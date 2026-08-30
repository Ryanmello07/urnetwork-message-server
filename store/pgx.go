package store

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/urnetwork/connect/protocol"
)

// What a statement in this file needs of whatever it is running on: the pool, for the read paths
// §5.1.1 forbids a transaction to, and the transaction, for everything §6.1 puts inside one.
//
// It exists so that the refusal paths of §6.1 can be written once and reached from both sides of
// the row lock. It is NOT an invitation to run a submit's statements on the pool: a query that
// takes a connection while [PgxStore.transact] holds one is a pool deadlock at exactly the
// concurrency §6.1 is about.
type queryer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, arguments ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, arguments ...any) pgx.Row
}

// The Postgres [Store] of spec B §2.1: §3.2's tables, §3.3's query plans, and the transaction
// of §6.1.
//
// It answers the same contract the memory implementation does — [RunContract] runs against both
// unchanged — and the two are deliberately not layered on one another. What is shared is what
// belongs to the interface rather than to either of them: §3.1's exact-length shapes
// ([validateRecord]), §5.1 check 3's attachment rules ([wellFormedEpochAttachment]), §7.1's
// prune arithmetic ([pruneAfter]) and §7.3's clamp ([Limits.apply]). A second copy of any of
// those here would be a second copy to drift.
//
// What is NOT here, and is a deviation rather than an omission: §6.4's `lock_timeout = 3s` and
// the `REASON_RATE_LIMITED{retry_after}` it answers on. It is the one refusal only this
// implementation can give, and naming it here would put it in the class
// [assertEveryRefusalIsExercised] derives from this type — which demands a contract scenario for
// it, which [RunContract] would then run against the memory implementation too, which §6.4 says
// cannot answer it because there is no connection to hold. A submitter therefore waits on the
// row lock here for as long as the lock is held, rather than being refused at three seconds.
type PgxStore struct {
	pool   *pgxpool.Pool
	limits Limits
	keys   *KekRing
}

var _ Store = (*PgxStore)(nil)

// A KEK id in a `write_key_wrapped` that this process was not given a key for. §5.5 makes the
// loss of a KEK unrecoverable and fleet-wide, so this is an operator condition — a rotation that
// retired a key still in use, or an escrow that was never tested — and never a client's answer.
var errKekUnknown = errors.New("store: no KEK loaded for the kek_id in a stored key")

// A stored key that is not 61 bytes, or that does not open. §3.2 CHECKs the length in the
// column, so reaching this means the row was written by something that is not this package.
var errKekCorrupt = errors.New("store: a stored epoch key is not a well-formed wrap")

// §5.5's wrap: `u8(kek_id) ‖ nonce(12) ‖ ct(32) ‖ tag(16)` = 61 bytes, AES-256-GCM under a KEK
// loaded from the vault resource `message_fleet.yml` (§10.2) and never written to the database.
//
// These are `Size` and not `Bytes` on purpose, and it is not a style preference. A constant in
// this package whose name ends in `Bytes` is an exact-length shape of §3.1 — a length a CALLER
// hands the store a value for — and [assertEveryDeclaredShapeIsDamaged] derives its class from
// exactly that suffix and demands a scenario that hands the store a wrong-length one. None of
// these is a caller's value: they are the internal layout of a column this package writes and
// reads, and no caller can hand a wrong-length one over. Naming them `Bytes` would put them in a
// class they are not in, and the honest answer to that gate is not an exemption in its table.
// The one length check they do carry — a stored wrap that is not 61 bytes — has its own scenario
// in TestTheEpochKeyWrapIsSpecB55s.
const (
	kekIdSize    = 1
	kekNonceSize = 12
	kekTagSize   = 16
	wrapSize     = kekIdSize + kekNonceSize + EpochKeyBytes + kekTagSize
)

// Which of an epoch's two keys a wrap holds. §5.3 gives them different lifetimes and §3.2 gives
// them different columns so a change to one cannot silently move the other; binding the label
// into the wrap's AAD carries the same separation into the ciphertext, so a `read_key_wrapped`
// moved into the `write_key_wrapped` column does not open.
const (
	wrapWriteKey uint8 = 0
	wrapReadKey  uint8 = 1
)

// The KEKs this process holds, keyed by the `kek_id` that leads every wrap.
//
// It is a ring rather than a key because §5.5's rotation needs a window: both KEKs are loaded,
// every row is unwrapped under the id it carries, and the old id is retired only once no row
// holds it. A single-key type would make that window a migration on the table that gates every
// submit, which is the defect the `kek_id` byte exists to prevent.
type KekRing struct {
	current uint8
	keys    map[uint8]cipher.AEAD
}

// A ring holding one KEK, which is what a deployment that has never rotated has. Add the
// second with [KekRing.Add] for the duration of a §5.5 rollover.
func NewKekRing(id uint8, kek []byte) (*KekRing, error) {
	ring := &KekRing{current: id, keys: map[uint8]cipher.AEAD{}}
	if err := ring.Add(id, kek); err != nil {
		return nil, err
	}
	return ring, nil
}

// Load another KEK, under the id its wraps carry. New wraps still go under the ring's current
// id; this is the half that lets the old id still be read.
func (self *KekRing) Add(id uint8, kek []byte) error {
	if len(kek) != 32 {
		return errKekCorrupt
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	self.keys[id] = aead
	return nil
}

// §5.5's 61 bytes, under the ring's current id.
func (self *KekRing) wrap(key []byte, label uint8, groupId []byte, epoch uint64) ([]byte, error) {
	if err := checkLength(key, EpochKeyBytes); err != nil {
		return nil, err
	}
	aead, held := self.keys[self.current]
	if !held {
		return nil, errKekUnknown
	}
	wrapped := make([]byte, kekIdSize+kekNonceSize, wrapSize)
	wrapped[0] = self.current
	if _, err := rand.Read(wrapped[kekIdSize:]); err != nil {
		return nil, err
	}
	return aead.Seal(wrapped, wrapped[kekIdSize:], key, kekAad(self.current, label, groupId, epoch)), nil
}

// The other direction, under whichever id the row carries.
func (self *KekRing) unwrap(wrapped []byte, label uint8, groupId []byte, epoch uint64) ([]byte, error) {
	if len(wrapped) != wrapSize {
		return nil, errKekCorrupt
	}
	id := wrapped[0]
	aead, held := self.keys[id]
	if !held {
		return nil, errKekUnknown
	}
	key, err := aead.Open(nil, wrapped[kekIdSize:kekIdSize+kekNonceSize], wrapped[kekIdSize+kekNonceSize:], kekAad(id, label, groupId, epoch))
	if err != nil {
		return nil, errKekCorrupt
	}
	return key, nil
}

// What a wrap is bound to besides the KEK: the id that selects the key, which of the epoch's two
// keys this is, and the (group, epoch) whose row it belongs in.
//
// §5.5 fixes the 61 bytes and says nothing about associated data, and this adds none to them —
// the AAD is re-supplied at unwrap and is not stored. What it buys is that a wrap is only ever
// readable in the row it was written for. §5.1.1 is explicit that the server "selects exactly
// one key and never trials a set", and a wrap that opened wherever it was pasted would let
// anybody who can write the database serve one epoch's reads under another epoch's key, which
// is the oracle §5.1.1 closes from the other end.
func kekAad(id uint8, label uint8, groupId []byte, epoch uint64) []byte {
	aad := []byte("URmessage/v1/kek")
	aad = append(aad, id, label)
	aad = append(aad, groupId...)
	return binary.BigEndian.AppendUint64(aad, epoch)
}

// A pool for this store, with the one runtime parameter §3.1 makes normative.
//
// §3.1: the cluster MUST be `timezone = 'UTC'` and the pool MUST set it explicitly, because
// `now()` returns `timestamptz` and assigning it to a `timestamp` column casts through the
// session's TimeZone. Retention is split across a Go clock (§7.1 computes `prune_after` from
// `time.Now().UTC()`) and a database clock (§7.4 sweeps `WHERE prune_after <= now()`), so a
// session in the wrong zone prunes user data hours early, fleet-wide and silently. Early
// pruning destroys user data, which is why this is not left to whatever the cluster was
// configured with.
//
// The sizing of §10.2's `db.yml` is not a parameter here because it does not need to be:
// pgxpool reads `pool_max_conns`, `pool_min_conns`, `pool_max_conn_lifetime`,
// `pool_max_conn_idle_time` and `pool_health_check_period` out of the connection string itself.
// A sizing argument beside a DSN that can already carry sizing is two places for one number to
// come from, and the loser is whichever one the caller did not think about.
func NewPgxPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	config.ConnConfig.RuntimeParams["timezone"] = "UTC"
	return pgxpool.NewWithConfig(ctx, config)
}

// The database clock reads UTC and agrees with this process, which is §3.1's `/readyz`
// assertion in one query.
//
// It converts a silent multi-hour retention error into a startup failure. Without it the only
// symptom of a mis-set session or cluster timezone is media disappearing early — months later,
// on somebody else's deployment, with nothing in the logs.
func CheckClock(ctx context.Context, pool *pgxpool.Pool, slack time.Duration) error {
	var stamp time.Time
	if err := pool.QueryRow(ctx, `SELECT now()::timestamp`).Scan(&stamp); err != nil {
		return err
	}
	drift := stamp.Sub(time.Now().UTC())
	if drift < -slack || slack < drift {
		return errClockNotUtc
	}
	return nil
}

var errClockNotUtc = errors.New("store: the database clock is not UTC, and §7.4 would prune against it")

// A store over the pool, with the limits of §7.3 to evaluate step (6) against and the KEKs of
// §5.5 to wrap epoch keys under.
func NewPgxStore(pool *pgxpool.Pool, limits Limits, keys *KekRing) *PgxStore {
	return &PgxStore{pool: pool, limits: limits, keys: keys}
}

// ── the read paths, §5.1.1: no transaction, no allocation ────────────────────────────────

// Step (1)'s read without step (1)'s lock (§4.3.10, Q2's read half).
//
// `AND NOT closed` is in the WHERE clause and not in a branch after it, so an unknown group and
// a closed one are the same zero rows and reach the same `return`. §4.5 refuses to distinguish
// them, and a store that read the row and then decided would have the answer in hand at the
// moment it chose what to say — which is exactly the shape a later refactor turns into an
// oracle for group existence.
func (self *PgxStore) GroupState(ctx context.Context, groupId []byte) (*GroupState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(groupId, GroupIdBytes); err != nil {
		return nil, err
	}

	var currentEpoch, nextRecordId int64
	var mediaTtl, policyVersion int32
	var durableTtl *int32
	state := &GroupState{}
	err := self.pool.QueryRow(ctx, `
        SELECT current_epoch, next_record_id, media_ttl_seconds, durable_ttl_seconds,
               policy_version, epoch_complete, group_context_hash
          FROM message_group
         WHERE group_id = $1 AND NOT closed`, groupId).
		Scan(&currentEpoch, &nextRecordId, &mediaTtl, &durableTtl,
			&policyVersion, &state.EpochComplete, &state.GroupContextHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGroupUnavailable
	}
	if err != nil {
		return nil, err
	}
	state.CurrentEpoch = uint64(currentEpoch)
	state.NextRecordId = uint64(nextRecordId)
	state.MediaTtlSeconds = uint32(mediaTtl)
	state.PolicyVersion = uint32(policyVersion)
	if durableTtl != nil {
		state.DurableTtlSeconds = ptr(uint32(*durableTtl))
	}
	return state, nil
}

// §5.1 check 6 on the submit path and §5.1.1's read-key lookup on the read path (Q9, Q15): a
// primary-key lookup on the epoch the caller named, and never a scan over the ones it did not.
//
// Three different histories reach the one `ErrEpochKeyUnknown` here — an epoch that never
// existed, one whose write key the 60-second tidy took and whose read key aged out, and a group
// that does not exist at all — and §5.1.1 is why they are not told apart. A row that has been
// emptied of both keys is not a row this method has anything to return: its `alg_id` and
// `opened_by_record` would confirm that the epoch once existed, which is the fact the caller
// holding no key is not entitled to.
func (self *PgxStore) EpochKeys(ctx context.Context, groupId []byte, epoch uint64) (*EpochKeys, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(groupId, GroupIdBytes); err != nil {
		return nil, err
	}

	var stored int64
	var writeWrapped, readWrapped []byte
	var readKeyInstall, retireTime *time.Time
	var algId int32
	var openedByRecord *int64
	var acceptTime time.Time
	err := self.pool.QueryRow(ctx, `
        SELECT epoch, write_key_wrapped, read_key_wrapped, read_key_install,
               alg_id, opened_by_record, accept_time, retire_time
          FROM message_epoch
         WHERE group_id = $1 AND epoch = $2`, groupId, int64(epoch)).
		Scan(&stored, &writeWrapped, &readWrapped, &readKeyInstall,
			&algId, &openedByRecord, &acceptTime, &retireTime)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEpochKeyUnknown
	}
	if err != nil {
		return nil, err
	}
	if writeWrapped == nil && readWrapped == nil {
		return nil, ErrEpochKeyUnknown
	}

	keys := &EpochKeys{
		Epoch:      uint64(stored),
		AlgId:      uint32(algId),
		AcceptTime: acceptTime,
	}
	if writeWrapped != nil {
		if keys.WriteKey, err = self.keys.unwrap(writeWrapped, wrapWriteKey, groupId, keys.Epoch); err != nil {
			return nil, err
		}
	}
	if readWrapped != nil {
		if keys.ReadKey, err = self.keys.unwrap(readWrapped, wrapReadKey, groupId, keys.Epoch); err != nil {
			return nil, err
		}
	}
	if readKeyInstall != nil {
		keys.ReadKeyInstall = *readKeyInstall
	}
	if openedByRecord != nil {
		keys.OpenedByRecord = uint64(*openedByRecord)
	}
	if retireTime != nil {
		keys.RetireTime = *retireTime
	}
	return keys, nil
}

// §4.3.4 over §5.1.1's read path: one statement, no transaction, no allocation.
//
// ONE statement is the load-bearing word, and it is why the group's row and the page of records
// are joined here rather than read one after the other. §5.1.1 forbids opening a transaction, so
// two statements are two READ COMMITTED snapshots, and a submit that commits between them is
// seen by half of this answer: `high_water_record_id` would come from a `next_record_id` the
// writer has already advanced while the record row it advanced for is not yet in the page. What
// the client is handed is then a gap at the top of the id sequence, which §4.3.4 sells as the
// withholding detector and §12.2 C-4 tells it to treat as a fault. A single statement has one
// snapshot, so the group's counter and the rows it counted are always the same transaction's.
//
// The read key does NOT gate which records come back, and that is a decision rather than an
// omission. §5.1.1's check 6 is a lookup on `(group_id, read_epoch)` — one epoch, named by the
// request and inside the `req_auth` MAC — and what it authorizes is the REQUEST;
// [PgxStore.EpochKeys] is where it is answered and `api.checkReadKey` is what calls it, before
// this method is reached at all. A store that additionally dropped records whose own epoch no
// longer retains a key would manufacture exactly the holes §4.3.4's gapless sequence exists to
// make meaningful, in every group older than the ninety-day window of §5.3.
func (self *PgxStore) Fetch(ctx context.Context, request *FetchRequest) (*FetchResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(request.GroupId, GroupIdBytes); err != nil {
		return nil, err
	}

	// one row more than was asked for, so that `complete` distinguishes a page the limit
	// truncated from one that happened to end on it. §4.3.4 leaves that boundary open and
	// `LIMIT $n` with `complete = rows < n` would be legal; it would also answer false for a page
	// that withheld nothing, where the memory implementation answers true — and a difference
	// between two implementations of one interface is worth one extra row
	var limit *int64
	if request.Limit != 0 {
		limit = ptr(int64(request.Limit) + 1)
	}
	// §4.3.4's cursor is a u64 off the wire and §3.2's `record_id` is a signed bigint, so the
	// conversion has a value the wire can carry and the column cannot. It is CLAMPED and not
	// cast: `int64(1 << 63)` is negative, `$2 < record_id` is then true of every row, and a
	// client that sent one would be handed the group's whole history under a cursor that never
	// advances — on every poll, forever. A group's allocator cannot reach 2^63, so clamping to
	// the largest id the column can hold answers the empty page the request actually asked for.
	since := request.SinceRecordId
	if since > math.MaxInt64 {
		since = math.MaxInt64
	}
	rows, err := self.pool.Query(ctx, fetchQuery(request.HeadsOnly), request.GroupId,
		int64(since), limit, int64(request.ClassMask))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &FetchResult{NextRecordId: request.SinceRecordId, Complete: true}
	found := false
	for rows.Next() {
		var nextRecordId int64
		row := &storedRecord{}
		if err := rows.Scan(append([]any{&nextRecordId}, row.targets()...)...); err != nil {
			return nil, err
		}
		found = true
		result.HighWaterRecordId = uint64(nextRecordId) - 1
		if row.recordId == nil {
			// the group's row with no page beside it: the left join's answer for a cursor that
			// is already caught up, or for a class mask nothing in the group carries
			continue
		}
		record, err := self.recordOf(request.GroupId, row)
		if err != nil {
			return nil, err
		}
		result.Records = append(result.Records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !found {
		// zero rows is the GROUP row missing, which is an unknown group and a closed one alike
		// (§4.5, §7.5); the page is left joined onto it and cannot be the half that is absent
		return nil, ErrGroupUnavailable
	}

	if request.Limit != 0 && uint32(len(result.Records)) > request.Limit {
		// truncated by the limit, which §4.3.4 calls normal rather than an error
		result.Records = result.Records[:request.Limit]
		result.Complete = false
	}
	if count := len(result.Records); count != 0 {
		result.NextRecordId = result.Records[count-1].RecordId
	}
	return result, nil
}

// §3.3's Q3 and Q11, with the group row joined on so that both halves of the answer come out of
// one snapshot. `state` is the inner source and `page` is left joined onto it, so a group that is
// unknown or closed produces no row at all, while a page that found nothing still produces one
// carrying the high water.
func fetchQuery(headsOnly bool) string {
	return `
        WITH state AS (
            SELECT next_record_id FROM message_group WHERE group_id = $1 AND NOT closed
        ), page AS (
            SELECT ` + recordColumns(headsOnly) + `
              ` + recordSource + `
             WHERE r.group_id = $1
               AND $2 < r.record_id
               AND ($4 = 0 OR ($4 & (1::bigint << r.retention_class::int)) <> 0)
             ORDER BY r.record_id
             LIMIT $3
        )
        SELECT state.next_record_id, page.*
          FROM state LEFT JOIN page ON true
         ORDER BY page.record_id`
}

// Every column of §3.2's `message_record` this package writes, and the `message_epoch` row an
// `EpochAttachment` keeps its two keys in.
//
// heads_only drops the body IN the statement rather than after it: §4.3.4 uses the flag for fast
// catch-up and for hole scans, and a body read out of the database and discarded in Go is exactly
// the bandwidth the flag exists in order not to spend.
func recordColumns(headsOnly bool) string {
	body := "r.ct_body AS ct_body"
	if headsOnly {
		body = "NULL::bytea AS ct_body"
	}
	return `r.record_id, r.sender_handle, r.epoch, r.stream_index, r.is_commit,
                   r.retention_class, r.size_bucket, r.expire_at, r.prune_after,
                   r.body_hash, r.ct_head, ` + body + `, r.blob_id, r.server_attachment,
                   r.recovery_handle, r.wrap_target_handle,
                   r.attachment_kind, r.attachment_epoch, r.attachment_alg_id,
                   r.attachment_media_ttl_seconds, r.attachment_durable_ttl_seconds,
                   r.attachment_group_context_hash, r.attachment_expected_wrap_count,
                   r.attachment_leaf_index, r.attachment_verify_pub, r.attachment_wrap_count,
                   e.write_key_wrapped, e.read_key_wrapped`
}

const recordSource = `FROM message_record r
              LEFT JOIN message_epoch e
                     ON e.group_id = r.group_id AND e.epoch = r.attachment_epoch`

// One row of [recordColumns], scanned.
//
// Every column is a pointer, including the ones §3.2 declares NOT NULL, because [fetchQuery]
// left joins this onto the group's row: a page that returned nothing still answers one row, and
// every record column in it is NULL. `recordId == nil` is that row, and is the only test for it.
type storedRecord struct {
	recordId         *int64
	senderHandle     []byte
	epoch            *int64
	streamIndex      *int64
	isCommit         *bool
	retentionClass   *int16
	sizeBucket       *int16
	expireAt         *time.Time
	pruneAfter       *time.Time
	bodyHash         []byte
	ctHead           []byte
	ctBody           []byte
	blobId           []byte
	serverAttachment []byte
	recoveryHandle   []byte
	wrapTarget       []byte

	kind              *int16
	attachmentEpoch   *int64
	algId             *int64
	mediaTtl          *int64
	durableTtl        *int64
	groupContextHash  []byte
	expectedWrapCount *int64
	leafIndex         *int64
	verifyPub         []byte
	wrapCount         *int64

	writeWrapped []byte
	readWrapped  []byte
}

// The scan targets, in [recordColumns]'s order. The two are one list written twice and there is
// no third place to forget a column from: a column added to one and not to the other is a scan
// arity error on the first row rather than a silently shifted decode.
func (self *storedRecord) targets() []any {
	return []any{
		&self.recordId, &self.senderHandle, &self.epoch, &self.streamIndex, &self.isCommit,
		&self.retentionClass, &self.sizeBucket, &self.expireAt, &self.pruneAfter,
		&self.bodyHash, &self.ctHead, &self.ctBody, &self.blobId, &self.serverAttachment,
		&self.recoveryHandle, &self.wrapTarget,
		&self.kind, &self.attachmentEpoch, &self.algId,
		&self.mediaTtl, &self.durableTtl,
		&self.groupContextHash, &self.expectedWrapCount,
		&self.leafIndex, &self.verifyPub, &self.wrapCount,
		&self.writeWrapped, &self.readWrapped,
	}
}

// A row back into the [Record] its submitter handed over.
//
// `expire_at` is reconstructed from the `timestamp` column rather than stored a second time as
// milliseconds, because §3.1 makes that column a lossy projection with no authority and a second
// copy of a value §4.3.3 makes `record_bytes` authoritative for is a second copy to disagree
// with. The loss is below one millisecond, which is finer than the unit the wire carries.
func (self *PgxStore) recordOf(groupId []byte, row *storedRecord) (*Record, error) {
	record := &Record{
		SenderHandle:     row.senderHandle,
		Epoch:            uint64(*row.epoch),
		StreamIndex:      uint64(*row.streamIndex),
		IsCommit:         *row.isCommit,
		RetentionClass:   uint8(*row.retentionClass),
		SizeBucket:       uint8(*row.sizeBucket),
		BodyHash:         row.bodyHash,
		CtHead:           row.ctHead,
		CtBody:           row.ctBody,
		BlobId:           row.blobId,
		ServerAttachment: row.serverAttachment,
		RecordId:         uint64(*row.recordId),
		PruneAfter:       row.pruneAfter,
	}
	if row.expireAt != nil {
		record.ExpireAtMs = uint64(row.expireAt.UnixMilli())
	}
	attachment, err := self.attachmentOf(groupId, row)
	if err != nil {
		return nil, err
	}
	record.Attachment = attachment
	return record, nil
}

// §5.4's attachment, out of the projection columns of migration 005c and — for the two keys an
// `EpochAttachment` carries — out of `message_epoch`, which §5.3 makes their only home.
//
// A commit whose epoch has since been superseded far enough for §6.1 step (6)'s
// `epoch < current_epoch` to have taken its write key comes back with a nil `WriteKey`. That is
// §5.3 rather than a loss: the server "retains the current epoch's key plus one briefly-retired
// predecessor, and nothing older", and a store that could still answer with an older one would
// be a store that had kept it.
func (self *PgxStore) attachmentOf(groupId []byte, row *storedRecord) (*Attachment, error) {
	if row.kind == nil {
		return nil, nil
	}
	kind := AttachmentKind(*row.kind)
	switch kind {
	case AttachmentEpoch:
		epoch := &EpochAttachment{GroupContextHash: row.groupContextHash}
		if row.attachmentEpoch != nil {
			epoch.Epoch = uint64(*row.attachmentEpoch)
		}
		if row.algId != nil {
			epoch.AlgId = uint32(*row.algId)
		}
		if row.mediaTtl != nil {
			epoch.MediaTtlSeconds = uint32(*row.mediaTtl)
		}
		if row.durableTtl != nil {
			epoch.DurableTtlSeconds = uint32(*row.durableTtl)
		}
		if row.expectedWrapCount != nil {
			epoch.ExpectedWrapCount = uint32(*row.expectedWrapCount)
		}
		var err error
		if row.writeWrapped != nil {
			if epoch.WriteKey, err = self.keys.unwrap(row.writeWrapped, wrapWriteKey, groupId, epoch.Epoch); err != nil {
				return nil, err
			}
		}
		if row.readWrapped != nil {
			if epoch.ReadKey, err = self.keys.unwrap(row.readWrapped, wrapReadKey, groupId, epoch.Epoch); err != nil {
				return nil, err
			}
		}
		return &Attachment{Kind: kind, Epoch: epoch}, nil
	case AttachmentWrap:
		wrap := &WrapTag{TargetHandle: row.wrapTarget}
		if row.leafIndex != nil {
			wrap.LeafIndex = uint32(*row.leafIndex)
		}
		return &Attachment{Kind: kind, Wrap: wrap}, nil
	case AttachmentRecovery:
		tag := &RecoveryTag{Handle: row.recoveryHandle, VerifyPub: row.verifyPub}
		if row.algId != nil {
			tag.AlgId = uint32(*row.algId)
		}
		return &Attachment{Kind: kind, Recovery: tag}, nil
	case AttachmentEpochComplete:
		marker := &EpochCompleteTag{}
		if row.attachmentEpoch != nil {
			marker.Epoch = uint64(*row.attachmentEpoch)
		}
		if row.wrapCount != nil {
			marker.WrapCount = uint32(*row.wrapCount)
		}
		return &Attachment{Kind: kind, EpochComplete: marker}, nil
	default:
		// AttachmentNone: a record that carried no attachment at all. It is a nil pointer and
		// not an empty one, because a nil is what its submitter handed over
		return nil, nil
	}
}

// §7.5. `AND NOT closed` is what makes closing a group twice the same answer an unknown group
// gives, and it is in the statement rather than in a read-then-write for the reason §6.1 gives
// everywhere else: two operators closing one group at the same moment would otherwise both read
// `closed = false`, and the second would stamp a `close_time` over the first, moving the start of
// the `group_reclaim_seconds` window the sweep deletes the group's ciphertext at.
func (self *PgxStore) CloseGroup(ctx context.Context, groupId []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkLength(groupId, GroupIdBytes); err != nil {
		return err
	}
	tag, err := self.pool.Exec(ctx, `
        UPDATE message_group SET closed = true, close_time = $2
         WHERE group_id = $1 AND NOT closed`, groupId, time.Now().UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupUnavailable
	}
	return nil
}

// ── §4.3.2 CreateGroup ───────────────────────────────────────────────────────────────────

// §6.1's "CreateGroup, written out", in one transaction.
//
// Two things about the refusals, both of which §4.5 decides and neither of which is free here.
//
// A `group_id` that already exists is REASON_REJECTED and is deliberately not distinguished
// from a bad MAC. That is why the group row goes in with `ON CONFLICT (group_id) DO NOTHING
// RETURNING`: the collision is a row count, so it leaves through the same `return` a malformed
// attachment does. An INSERT without the clause would raise `23505 unique_violation`, and this
// method would then answer an ERROR — with the constraint's name, the table's name and often the
// key's value in its text — to a party who has just learned, from the difference, that the group
// exists. Every field of the result is the same for both refusals too, and not merely the reason
// code: a result carrying `current_epoch` from the row it found would say the group exists and
// how far along it is while claiming to say nothing.
//
// And the founding commit is checked in full before any of it. §5.1's carve-out evaluates
// `epoch == current_epoch + 1` as `epoch == 1`, because there is no group row and therefore no
// current epoch; everything else about the attachment is checked exactly as a steady-state
// commit's is. This is the one commit no later commit can rescue — an accepted commit carrying a
// malformed attachment opens an epoch with no verifiable write key and bricks the group
// permanently — so the shape checks run before the transaction is opened at all.
func (self *PgxStore) CreateGroup(ctx context.Context, request *CreateGroupRequest) (*CreateGroupResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(request.GroupId, GroupIdBytes); err != nil {
		return nil, err
	}
	if err := checkLength(request.BootstrapWriteKey, EpochKeyBytes); err != nil {
		return nil, err
	}
	if request.InitialCommit == nil {
		return nil, ErrEmptyBatch
	}
	if err := validateRecord(request.InitialCommit); err != nil {
		return nil, err
	}
	if !request.InitialCommit.IsCommit || request.InitialCommit.Epoch != 0 ||
		!wellFormedEpochAttachment(request.InitialCommit, 1) {
		return &CreateGroupResult{Reason: protocol.Reason_REASON_REJECTED}, nil
	}

	attachment := request.InitialCommit.Attachment.Epoch
	media, durable, applied := self.limits.apply(attachment)
	// §7.1 computes prune_after in Go, from the class and the policy this commit just set. The
	// founding commit is PERMANENT in every client this specification describes, and that is
	// the one class the arithmetic answers nil for — but it is computed rather than assumed,
	// because "the founding commit is always PERMANENT" is a property of a client and this is
	// the server.
	now := time.Now().UTC()
	record := cloneRecord(request.InitialCommit)
	record.RecordId = firstRecordId

	transaction, err := self.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer transaction.Rollback(context.WithoutCancel(ctx))

	var created bool
	err = transaction.QueryRow(ctx, `
        INSERT INTO message_group (group_id, create_time, current_epoch, next_record_id,
                                   media_ttl_seconds, durable_ttl_seconds, group_context_hash,
                                   policy_version, epoch_complete, closed, close_time)
             VALUES ($1, $2, 1, $3, $4, $5, $6, 1, false, false, NULL)
        ON CONFLICT (group_id) DO NOTHING
          RETURNING true`,
		request.GroupId, now, int64(firstRecordId)+1, int32(media), durableColumn(durable),
		attachment.GroupContextHash).Scan(&created)
	if errors.Is(err, pgx.ErrNoRows) {
		return &CreateGroupResult{Reason: protocol.Reason_REASON_REJECTED}, nil
	}
	if err != nil {
		return nil, err
	}

	// epoch 0 holds write_key[0] and nothing else: it is the one key in this design the server
	// was handed outside a commit, it verified the founding commit under §5.1's carve-out, and
	// it is retired on sight because current_epoch is already 1. It has no read key, because a
	// read key on it would authorize reads under a key no commit ever published.
	bootstrap, err := self.keys.wrap(request.BootstrapWriteKey, wrapWriteKey, request.GroupId, 0)
	if err != nil {
		return nil, err
	}
	if _, err := transaction.Exec(ctx, `
        INSERT INTO message_epoch (group_id, epoch, write_key_wrapped, read_key_wrapped,
                                   read_key_install, alg_id, opened_by_record, accept_time,
                                   retire_time, expected_wrap_count)
             VALUES ($1, 0, $2, NULL, NULL, 0, NULL, $3, $3, 0)`,
		request.GroupId, bootstrap, now); err != nil {
		return nil, err
	}

	writeKey, err := self.keys.wrap(attachment.WriteKey, wrapWriteKey, request.GroupId, 1)
	if err != nil {
		return nil, err
	}
	readKey, err := self.keys.wrap(attachment.ReadKey, wrapReadKey, request.GroupId, 1)
	if err != nil {
		return nil, err
	}
	// expected_wrap_count comes from the founding attachment exactly as a steady-state commit's
	// does: it is the number §6.1 step (6b) holds this epoch's marker to, and [openGroup] in the
	// contract is a group that cannot leave readable-but-not-writable without it
	if _, err := transaction.Exec(ctx, `
        INSERT INTO message_epoch (group_id, epoch, write_key_wrapped, read_key_wrapped,
                                   read_key_install, alg_id, opened_by_record, accept_time,
                                   retire_time, expected_wrap_count)
             VALUES ($1, 1, $2, $3, $4, $5, $6, $4, NULL, $7)`,
		request.GroupId, writeKey, readKey, now, int32(attachment.AlgId),
		int64(record.RecordId), int64(attachment.ExpectedWrapCount)); err != nil {
		return nil, err
	}

	if err := insertRecord(ctx, transaction, request.GroupId, record, now,
		pruneAfter(now, record.RetentionClass, media, durable), 1); err != nil {
		return nil, err
	}

	// the claim, which is the uniqueness authority and the idempotency probe of §6.3. Without
	// it the creator's own retry of this commit reaches the gates as a fresh record.
	if _, err := transaction.Exec(ctx, `
        INSERT INTO message_stream_claim (group_id, sender_handle, stream_index, record_id,
                                          body_hash, head_hash, create_time)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		request.GroupId, record.SenderHandle, int64(record.StreamIndex), int64(record.RecordId),
		record.BodyHash, headHash(record.CtHead), now); err != nil {
		return nil, err
	}

	// the CAS row for epoch 0, which the founding commit has just consumed. Without it a second
	// commit at epoch 0 would be measured against the epoch instead and answered EPOCH_STALE,
	// which §6.4 says a losing committer is never given.
	if _, err := transaction.Exec(ctx, `
        INSERT INTO message_commit (group_id, epoch, record_id) VALUES ($1, $2, $3)`,
		request.GroupId, int64(record.Epoch), int64(record.RecordId)); err != nil {
		return nil, err
	}

	if _, err := transaction.Exec(ctx, `
        INSERT INTO message_sender (group_id, sender_handle, last_stream_index, record_count,
                                    byte_count, last_time)
             VALUES ($1, $2, $3, 1, $4, $5)`,
		request.GroupId, record.SenderHandle, int64(record.StreamIndex),
		recordBytes(record), now); err != nil {
		return nil, err
	}

	// and "a message_recovery row if the initial commit carries a RecoveryTag" (§6.1, CreateGroup
	// written out). No founding commit this specification describes carries one — its attachment
	// is the EpochAttachment §5.1's carve-out checks — but the row is written from the same
	// function the submit path uses rather than from an argument about what clients send
	if tag := recoveryTagOf(record); tag != nil {
		if _, err := pinRecoveryHandle(ctx, transaction, request.GroupId, tag, now); err != nil {
			return nil, err
		}
	}

	if err := transaction.Commit(ctx); err != nil {
		return nil, err
	}
	return &CreateGroupResult{
		// §7.3 applies to the founding commit exactly as it does to every later one, and this
		// is the policy the group lives under until it commits again
		Reason:       acceptanceReason(applied),
		CurrentEpoch: 1,
		RecordId:     record.RecordId,
		Applied:      applied,
	}, nil
}

// ── §6.1, the transaction ────────────────────────────────────────────────────────────────

// Steps (0) through (7), in that order, for the whole batch.
//
// The shape is the specification. Everything up to [PgxStore.write] READS; nothing above it
// writes, so "a refusal allocates nothing" is a property of where the statements are rather than
// a claim about what a rollback would have undone. §5.1's headline is that a party with no
// write_key cannot force a row lock, an index write or a WAL byte, and step (3b)'s batch barrier
// is the same sentence one level down: every per-record check runs for EVERY record before the
// allocator moves at all, so a batch that is going to be refused never reaches the UPDATE.
//
// A refusal is a [protocol.Reason] on a [SubmitResult]; the errors here are the other class of
// §4.5 — the caller handed this package something no client could have produced — and every one
// of them is answered before the transaction is opened.
func (self *PgxStore) Submit(ctx context.Context, request *SubmitRequest) (*SubmitResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(request.GroupId, GroupIdBytes); err != nil {
		return nil, err
	}
	if len(request.Records) == 0 {
		return nil, ErrEmptyBatch
	}
	commits := 0
	for _, record := range request.Records {
		if err := validateRecord(record); err != nil {
			return nil, err
		}
		if record.IsCommit {
			commits++
		}
	}
	// §4.3.3: mixing a commit with ordinary records would make partial-failure semantics
	// ambiguous during an epoch change, and a commit is one record by construction
	if commits != 0 && len(request.Records) != 1 {
		return nil, ErrCommitBatch
	}

	batch := make([]*pending, len(request.Records))
	for index, record := range request.Records {
		batch[index] = &pending{record: record, result: &SubmitResult{}}
	}

	// (0) IDEMPOTENCY PROBE, before any gate, before any allocation, and — the half that only
	// shows under contention — before the row lock of step (1). It is a plain read on the pool
	// and not the transaction's first statement, because a retry that blocked behind the very
	// transaction it is retrying would be a different protocol
	if err := self.probe(ctx, request.GroupId, batch); err != nil {
		return nil, err
	}
	for _, current := range batch {
		if current.probe == probeDiffers {
			// same index, different content: a client bug or an attack. §6.1 returns here, so
			// the batch takes no lock at all and writes nothing
			return self.refuse(ctx, self.pool, request.GroupId, batch, current,
				protocol.Reason_REASON_STREAM_INDEX_REUSED, 0)
		}
	}
	remaining := 0
	for _, current := range batch {
		if current.probe == probeIdentical {
			current.settled = true
			continue
		}
		remaining++
	}
	if remaining == 0 {
		// every record already landed. §6.1 answers REASON_OK{record_id} with no allocation and
		// there is nothing left for the gates to gate
		if err := self.fill(ctx, self.pool, request.GroupId, batch, 0); err != nil {
			return nil, err
		}
		return &SubmitResponse{Results: resultsOf(batch)}, nil
	}
	return self.transact(ctx, request.GroupId, batch)
}

// Steps (1) through (7), under one transaction and one row lock.
//
// Every query below runs on `transaction`, and none of them reaches back into the pool. That is
// not tidiness: a connection held by an open transaction that then waits for a second connection
// is a pool deadlock at exactly the concurrency §6.1 is about, and the refusal paths — which are
// the ones that want to read a winning commit or a current epoch — are precisely where the
// second acquire would be reached for.
func (self *PgxStore) transact(ctx context.Context, groupId []byte, batch []*pending) (*SubmitResponse, error) {
	transaction, err := self.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	// context.WithoutCancel so that a cancelled request still releases the row lock here rather
	// than leaving it to the connection's own teardown
	defer transaction.Rollback(context.WithoutCancel(ctx))

	// (1) Lock the group. Read state; DO NOT allocate ids yet. `AND NOT closed` and `FOR UPDATE`
	// are one statement, so an unknown group and a closed one are the same zero rows (§4.5)
	state := &GroupState{}
	var currentEpoch, nextRecordId int64
	var mediaTtl, policyVersion int32
	var durableTtl *int32
	err = transaction.QueryRow(ctx, `
        SELECT current_epoch, next_record_id, media_ttl_seconds, durable_ttl_seconds,
               policy_version, epoch_complete, group_context_hash
          FROM message_group
         WHERE group_id = $1 AND NOT closed
           FOR UPDATE`, groupId).
		Scan(&currentEpoch, &nextRecordId, &mediaTtl, &durableTtl,
			&policyVersion, &state.EpochComplete, &state.GroupContextHash)
	if errors.Is(err, pgx.ErrNoRows) {
		// 0 rows -> REASON_REJECTED (unknown or closed; indistinguishable, §4.5). NOTHING else
		// is filled in: a result carrying this group's current_epoch would tell a party holding
		// no write_key both that the group exists and how far along it is
		return refuseUnavailable(batch), nil
	}
	if err != nil {
		return nil, err
	}
	state.CurrentEpoch = uint64(currentEpoch)
	state.NextRecordId = uint64(nextRecordId)
	state.MediaTtlSeconds = uint32(mediaTtl)
	state.PolicyVersion = uint32(policyVersion)
	if durableTtl != nil {
		state.DurableTtlSeconds = ptr(uint32(*durableTtl))
	}
	// §4.3.3 sets current_epoch on EVERY result, so a stale client resynchronises in one round
	// trip. It is set here, once, for the accepted and the refused alike
	for _, current := range batch {
		current.result.CurrentEpoch = state.CurrentEpoch
	}

	// (3b) THE BATCH BARRIER. Steps (2), (2b) and (3) run for every record before the allocator
	// is touched, and the two reads they need are taken once for the whole batch rather than once
	// per record — a per-record round trip inside the row lock is the lock held for the length of
	// the batch. An allocated block larger than the rows written gives the group a permanent
	// record_id gap, which is the property decision B4 exists to create and the one §12.2 C-4
	// tells clients to treat as a fault.
	highWater, err := senderHighWater(ctx, transaction, groupId, batch)
	if err != nil {
		return nil, err
	}
	pinned, err := pinnedRecoveryKeys(ctx, transaction, groupId, batch)
	if err != nil {
		return nil, err
	}
	for _, current := range batch {
		if current.settled {
			continue
		}
		refusal, err := gate(ctx, transaction, groupId, state, current.record, highWater, pinned)
		if err != nil {
			return nil, err
		}
		if refusal != protocol.Reason_REASON_OK {
			return self.refuse(ctx, transaction, groupId, batch, current, refusal, state.CurrentEpoch)
		}
		// the batch's own high water, which the sender row will not carry until step (7): two
		// records of one sender at one index are otherwise both accepted, and only one of them
		// is named by a claim
		highWater[string(current.record.SenderHandle)] = current.record.StreamIndex
	}

	return self.write(ctx, transaction, groupId, state, batch)
}

// Step (0), against `message_stream_claim` and never against `message_record`: §7.2 zeroes an
// expired ephemeral record's sender_handle and erases its head, so the record cannot answer this
// question and never could for that class.
//
// One statement for the whole batch. `max_records_per_submit` is 256, so the per-record shape is
// 256 round trips ahead of the gates for every submission, on the path §5.1 spends its whole
// ordering argument keeping cheap.
//
// Both hashes are compared. Two records can legitimately share a body hash — an empty body —
// while differing in the head, and a probe on body_hash alone would call the second a retry of
// the first and hand back a record id for somebody else's row.
func (self *PgxStore) probe(ctx context.Context, groupId []byte, batch []*pending) error {
	handles := make([][]byte, len(batch))
	indexes := make([]int64, len(batch))
	for index, current := range batch {
		handles[index] = current.record.SenderHandle
		indexes[index] = int64(current.record.StreamIndex)
	}
	rows, err := self.pool.Query(ctx, `
        SELECT asked.position, claim.record_id, claim.body_hash, claim.head_hash
          FROM unnest($2::bytea[], $3::bigint[])
               WITH ORDINALITY AS asked(sender_handle, stream_index, position)
          JOIN message_stream_claim claim
            ON claim.group_id = $1
           AND claim.sender_handle = asked.sender_handle
           AND claim.stream_index = asked.stream_index`, groupId, handles, indexes)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var position, recordId int64
		var bodyHash, headDigest []byte
		if err := rows.Scan(&position, &recordId, &bodyHash, &headDigest); err != nil {
			return err
		}
		current := batch[position-1]
		if bytes.Equal(bodyHash, current.record.BodyHash) &&
			bytes.Equal(headDigest, headHash(current.record.CtHead)) {
			current.probe = probeIdentical
			current.result.Reason = protocol.Reason_REASON_OK
			current.result.RecordId = uint64(recordId)
			continue
		}
		current.probe = probeDiffers
	}
	return rows.Err()
}

// Step (3)'s read, for every sender the batch names, in one statement.
//
// Presence in the map is what "this sender has a high water" means, so a sender whose stored
// last_stream_index is 0 is not confused with one that has never written — the difference decides
// whether a record at index 0 is accepted or REASON_STREAM_INDEX_REGRESSED.
func senderHighWater(ctx context.Context, q queryer, groupId []byte, batch []*pending) (map[string]uint64, error) {
	handles := make([][]byte, 0, len(batch))
	for _, current := range batch {
		handles = append(handles, current.record.SenderHandle)
	}
	rows, err := q.Query(ctx, `
        SELECT sender_handle, last_stream_index
          FROM message_sender
         WHERE group_id = $1 AND sender_handle = ANY($2::bytea[])`, groupId, handles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]uint64{}
	for rows.Next() {
		var handle []byte
		var last int64
		if err := rows.Scan(&handle, &last); err != nil {
			return nil, err
		}
		found[string(handle)] = uint64(last)
	}
	return found, rows.Err()
}

// Step (6c)'s read: the verify_pub already pinned for every recovery handle the batch names.
//
// The query is skipped entirely when no record carries a `RecoveryTag`, which is every batch in
// steady state — §5.1's ordering argument is that nothing costing a read happens for a submission
// that does not need it.
func pinnedRecoveryKeys(ctx context.Context, q queryer, groupId []byte, batch []*pending) (map[string][]byte, error) {
	handles := [][]byte{}
	for _, current := range batch {
		if tag := recoveryTagOf(current.record); tag != nil {
			handles = append(handles, tag.Handle)
		}
	}
	pinned := map[string][]byte{}
	if len(handles) == 0 {
		return pinned, nil
	}
	rows, err := q.Query(ctx, `
        SELECT recovery_handle, verify_pub
          FROM message_recovery
         WHERE group_id = $1 AND recovery_handle = ANY($2::bytea[])`, groupId, handles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var handle, pub []byte
		if err := rows.Scan(&handle, &pub); err != nil {
			return nil, err
		}
		pinned[string(handle)] = pub
	}
	return pinned, rows.Err()
}

// Steps (2), (2b) and (3) for one record. REASON_OK means every gate passed.
func gate(ctx context.Context, q queryer, groupId []byte, state *GroupState, record *Record,
	highWater map[string]uint64, pinned map[string][]byte) (protocol.Reason, error) {

	// (2) EPOCH GATE, commit-aware. The message_commit check comes FIRST and stays first: the
	// row lock serialises committers, so a loser acquires the lock only after the winner
	// advanced the epoch, and an epoch-first gate therefore answers EPOCH_STALE and §6.2's
	// mandatory loser protocol — the one carrying the hard MUST NOT on pq_secret reuse — never
	// fires at all. Regardless of how far current_epoch has advanced
	if record.IsCommit {
		var lost bool
		err := q.QueryRow(ctx, `
            SELECT true FROM message_commit
             WHERE group_id = $1 AND epoch = $2`, groupId, int64(record.Epoch)).Scan(&lost)
		if err == nil {
			return protocol.Reason_REASON_COMMIT_LOST, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return protocol.Reason_REASON_OK, err
		}
	}
	if record.Epoch != state.CurrentEpoch {
		return protocol.Reason_REASON_EPOCH_STALE, nil
	}
	// readable-but-not-writable until the epoch's wrap fan-out closes with its marker
	if !state.EpochComplete && !exemptFromEpochComplete(record) {
		return protocol.Reason_REASON_EPOCH_INCOMPLETE, nil
	}

	// (2b) Attachment well-formedness, after the epoch gate and before the CAS, which is where
	// §6.1 puts it and where it has to stay in both directions. Before the CAS, because an
	// accepted commit carrying a malformed attachment opens an epoch with no verifiable write
	// key and bricks the group permanently. After the commit-lost check, because a loser's
	// attachment names epoch n+1 while current_epoch is already n+1 — well-formed when it was
	// built, and `epoch == current_epoch + 1` now false — so an attachment check in front of the
	// CAS check would answer REASON_REJECTED to every loser and §6.2's protocol would never see
	// the winner it is required to apply
	if record.IsCommit != (attachmentKindOf(record) == AttachmentEpoch) {
		return protocol.Reason_REASON_REJECTED, nil
	}
	if record.IsCommit && !wellFormedEpochAttachment(record, state.CurrentEpoch+1) {
		return protocol.Reason_REASON_REJECTED, nil
	}

	// (3) Stream monotonicity, per (group_id, sender_handle). Monotonic, NOT contiguous: a
	// refused write, a crash between reserve and send, or a lost commit leaves a legal gap, and
	// a contiguity check would refuse every one of them forever
	if last, seen := highWater[string(record.SenderHandle)]; seen && record.StreamIndex <= last {
		return protocol.Reason_REASON_STREAM_INDEX_REGRESSED, nil
	}

	// (6c) as a gate rather than as a write. §6.1 writes the recovery row after allocation and
	// rolls the batch back on a mismatch, which writes nothing either way; checking it here keeps
	// "a refusal allocates nothing" a property of the code path and not of an unwind
	if tag := recoveryTagOf(record); tag != nil {
		if known, found := pinned[string(tag.Handle)]; found && !bytes.Equal(known, tag.VerifyPub) {
			return protocol.Reason_REASON_REJECTED, nil
		}
	}
	return protocol.Reason_REASON_OK, nil
}

// Steps (4) through (7), applied together. Everything above this point read; nothing above it
// wrote.
func (self *PgxStore) write(ctx context.Context, transaction pgx.Tx, groupId []byte,
	state *GroupState, batch []*pending) (*SubmitResponse, error) {

	now := time.Now().UTC()
	accepted := []*pending{}
	for _, current := range batch {
		if !current.settled {
			accepted = append(accepted, current)
		}
	}

	// (4) Allocate exactly k ids, where k is the VERIFIED ACCEPTED COUNT and not the batch
	// length — a record step (0) answered already has an id and is not in the block. Only now,
	// under the row lock step (1) already holds, and deliberately not from a SEQUENCE:
	// nextval() is non-transactional, so every refusal in §6.1 would leave a permanent hole in
	// the id space and break the gapless property §4.3.4 sells to clients
	var first int64
	if err := transaction.QueryRow(ctx, `
        UPDATE message_group SET next_record_id = next_record_id + $2
         WHERE group_id = $1
        RETURNING next_record_id - $2`, groupId, int64(len(accepted))).Scan(&first); err != nil {
		return nil, err
	}

	currentEpoch := state.CurrentEpoch
	for index, current := range accepted {
		record := cloneRecord(current.record)
		record.RecordId = uint64(first) + uint64(index)
		record.PruneAfter = nil

		mediaTtl, durableTtl := state.MediaTtlSeconds, state.DurableTtlSeconds
		policy := state.PolicyVersion
		if record.IsCommit {
			// (5b) THE CAS, as a one-row insert against a full primary key. Under the row lock
			// the gate above has already answered this, and it is still here because §6.1 keeps
			// both mechanisms deliberately: the lock makes the losing path deterministic and
			// lets the winner be read in the same round trip, and the primary key holds the
			// invariant even if some future path forgets the lock
			var won bool
			err := transaction.QueryRow(ctx, `
                INSERT INTO message_commit (group_id, epoch, record_id) VALUES ($1, $2, $3)
                ON CONFLICT (group_id, epoch) DO NOTHING
                  RETURNING true`, groupId, int64(record.Epoch), int64(record.RecordId)).Scan(&won)
			if errors.Is(err, pgx.ErrNoRows) {
				return self.refuse(ctx, transaction, groupId, batch, current,
					protocol.Reason_REASON_COMMIT_LOST, state.CurrentEpoch)
			}
			if err != nil {
				return nil, err
			}

			// (6) On a won commit, and only then: open the next epoch, retire the old key
			opened, applied, err := self.openEpoch(ctx, transaction, groupId, state, record, now)
			if err != nil {
				return nil, err
			}
			currentEpoch = state.CurrentEpoch + 1
			mediaTtl, durableTtl = opened.media, opened.durable
			policy = state.PolicyVersion + 1
			current.result.Applied = applied
			current.result.CurrentEpoch = currentEpoch
		}

		// (6b) the marker that closes the fan-out. Only a wrap_count equal to the epoch's own
		// expected_wrap_count opens the group for ordinary writes; §5.1 check 3 refuses a
		// mismatch before it ever reaches here, and a mismatch that did reach here leaves the
		// group where it was rather than opening it on a number nobody agreed
		if marker := epochCompleteTagOf(record); marker != nil {
			if err := closeFanOut(ctx, transaction, groupId, currentEpoch, marker); err != nil {
				return nil, err
			}
		}

		// (5a) Claim first, then the row, both ON CONFLICT (§11.2 item 4). The claim is the
		// uniqueness authority; the record carries no unique index on (sender_handle,
		// stream_index) at all, because §7.2 zeroes that column on expiry and two senders may
		// legitimately hold the same index
		if _, err := transaction.Exec(ctx, `
            INSERT INTO message_stream_claim (group_id, sender_handle, stream_index, record_id,
                                              body_hash, head_hash, create_time)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (group_id, sender_handle, stream_index) DO NOTHING`,
			groupId, record.SenderHandle, int64(record.StreamIndex), int64(record.RecordId),
			record.BodyHash, headHash(record.CtHead), now); err != nil {
			return nil, err
		}
		if err := insertRecord(ctx, transaction, groupId, record, now,
			pruneAfter(now, record.RetentionClass, mediaTtl, durableTtl), policy); err != nil {
			return nil, err
		}

		// (6c) TOFU, scoped to this group: insert, then verify what is stored is the tag's.
		// The gate refused a differing pub already, and this is the half that also answers a
		// batch which claims a handle and rebinds it in the same transaction — the gate read
		// its pins before either record was written and cannot see the first one
		if tag := recoveryTagOf(record); tag != nil {
			rebound, err := pinRecoveryHandle(ctx, transaction, groupId, tag, now)
			if err != nil {
				return nil, err
			}
			if rebound {
				return self.refuse(ctx, transaction, groupId, batch, current,
					protocol.Reason_REASON_REJECTED, state.CurrentEpoch)
			}
		}

		// (7) Sender high-water and accounting
		if _, err := transaction.Exec(ctx, `
            INSERT INTO message_sender (group_id, sender_handle, last_stream_index, record_count,
                                        byte_count, last_time)
                 VALUES ($1, $2, $3, 1, $4, $5)
            ON CONFLICT (group_id, sender_handle) DO UPDATE
               SET last_stream_index = EXCLUDED.last_stream_index,
                   record_count = message_sender.record_count + 1,
                   byte_count   = message_sender.byte_count + EXCLUDED.byte_count,
                   last_time    = EXCLUDED.last_time`,
			groupId, record.SenderHandle, int64(record.StreamIndex), recordBytes(record),
			now); err != nil {
			return nil, err
		}

		// REASON_OK, or §7.3's REASON_RETENTION_CLAMPED when step (6) clamped the policy down or
		// floored it up. Both are acceptances: the record has an id and the commit opened its
		// epoch, and the difference is only what the client is told to render
		current.result.Reason = acceptanceReason(current.result.Applied)
		current.result.RecordId = record.RecordId
	}

	for _, current := range batch {
		if current.result.CurrentEpoch == 0 {
			current.result.CurrentEpoch = currentEpoch
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, err
	}
	return &SubmitResponse{Results: resultsOf(batch)}, nil
}

// What step (6) wrote into the group row, so that the commit's own record prunes against the
// policy it just published rather than against the one it replaced.
type openedEpoch struct {
	media   uint32
	durable *uint32
}

// §6.1 step (6): the next epoch's keys installed, the superseded one stamped for the tidy loop,
// everything strictly older emptied, and the group row moved.
func (self *PgxStore) openEpoch(ctx context.Context, transaction pgx.Tx, groupId []byte,
	state *GroupState, record *Record, now time.Time) (openedEpoch, *RetentionApplied, error) {

	attachment := record.Attachment.Epoch
	opens := state.CurrentEpoch + 1
	media, durable, applied := self.limits.apply(attachment)

	writeKey, err := self.keys.wrap(attachment.WriteKey, wrapWriteKey, groupId, opens)
	if err != nil {
		return openedEpoch{}, nil, err
	}
	// the read key of the epoch this commit OPENS. Different every epoch, retained for the
	// ninety-day window, and never taken by the sixty-second write-key tidy (§5.3)
	readKey, err := self.keys.wrap(attachment.ReadKey, wrapReadKey, groupId, opens)
	if err != nil {
		return openedEpoch{}, nil, err
	}
	if _, err := transaction.Exec(ctx, `
        INSERT INTO message_epoch (group_id, epoch, write_key_wrapped, read_key_wrapped,
                                   read_key_install, alg_id, opened_by_record, accept_time,
                                   retire_time, expected_wrap_count)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $5, NULL, $8)`,
		groupId, int64(opens), writeKey, readKey, now, int32(attachment.AlgId),
		int64(record.RecordId), int64(attachment.ExpectedWrapCount)); err != nil {
		return openedEpoch{}, nil, err
	}
	if _, err := transaction.Exec(ctx, `
        UPDATE message_epoch SET retire_time = $3
         WHERE group_id = $1 AND epoch = $2 AND write_key_wrapped IS NOT NULL`,
		groupId, int64(state.CurrentEpoch), now); err != nil {
		return openedEpoch{}, nil, err
	}
	// the predicate is LOAD-BEARING (§3.3 Q12): strictly older than the epoch being superseded,
	// so the one briefly-retired predecessor §5.3 keeps stays verifiable
	if _, err := transaction.Exec(ctx, `
        UPDATE message_epoch SET write_key_wrapped = NULL
         WHERE group_id = $1 AND epoch < $2 AND write_key_wrapped IS NOT NULL`,
		groupId, int64(state.CurrentEpoch)); err != nil {
		return openedEpoch{}, nil, err
	}
	if _, err := transaction.Exec(ctx, `
        UPDATE message_group
           SET current_epoch = $2, epoch_complete = false, media_ttl_seconds = $3,
               durable_ttl_seconds = $4, group_context_hash = $5,
               policy_version = policy_version + 1
         WHERE group_id = $1`,
		groupId, int64(opens), int32(media), durableColumn(durable),
		attachment.GroupContextHash); err != nil {
		return openedEpoch{}, nil, err
	}
	return openedEpoch{media: media, durable: durable}, applied, nil
}

// §6.1 step (6b). The condition has two halves and both are load-bearing: the marker names THIS
// epoch, and its wrap_count is the number THAT epoch's commit announced. A group opened on a
// count nobody agreed is a group whose members with no wrap cannot read what is written into the
// window the marker opened, and §6.1's epoch publication step 4 has each of them surface a
// `no_wrap` gap against a fan-out the server called complete.
func closeFanOut(ctx context.Context, transaction pgx.Tx, groupId []byte, currentEpoch uint64,
	marker *EpochCompleteTag) error {

	if marker.Epoch != currentEpoch {
		return nil
	}
	var expected int64
	err := transaction.QueryRow(ctx, `
        SELECT expected_wrap_count FROM message_epoch
         WHERE group_id = $1 AND epoch = $2`, groupId, int64(currentEpoch)).Scan(&expected)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if uint64(expected) != uint64(marker.WrapCount) {
		return nil
	}
	_, err = transaction.Exec(ctx, `
        UPDATE message_group SET epoch_complete = true WHERE group_id = $1`, groupId)
	return err
}

// §6.1 step (6c), written out: `INSERT … ON CONFLICT DO NOTHING, then verify the stored
// verify_pub equals the tag's`. Answers whether the handle is already pinned to a DIFFERENT key,
// which is §4.3.7's rebinding attack and rolls the batch back.
func pinRecoveryHandle(ctx context.Context, transaction pgx.Tx, groupId []byte, tag *RecoveryTag,
	now time.Time) (bool, error) {

	tagged, err := transaction.Exec(ctx, `
        INSERT INTO message_recovery (group_id, recovery_handle, verify_pub, alg_id, first_seen)
             VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (group_id, recovery_handle) DO NOTHING`,
		groupId, tag.Handle, tag.VerifyPub, int32(tag.AlgId), now)
	if err != nil {
		return false, err
	}
	if tagged.RowsAffected() != 0 {
		return false, nil
	}
	var pinned []byte
	if err := transaction.QueryRow(ctx, `
        SELECT verify_pub FROM message_recovery
         WHERE group_id = $1 AND recovery_handle = $2`, groupId, tag.Handle).Scan(&pinned); err != nil {
		return false, err
	}
	return !bytes.Equal(pinned, tag.VerifyPub), nil
}

// A batch that wrote nothing, with a reason on every result: §6.1 step (3b).
//
// The offender carries the specific refusal and every other record carries the deliberately
// non-specific REASON_REJECTED of §4.5, because the others were not themselves refused for
// anything and inventing a per-record reason for them would say something untrue. A record step
// (0) already answered keeps its REASON_OK: it names a row that landed in an earlier
// transaction, and no rollback of this one can unland it.
func (self *PgxStore) refuse(ctx context.Context, q queryer, groupId []byte, batch []*pending,
	offender *pending, reason protocol.Reason, currentEpoch uint64) (*SubmitResponse, error) {

	for _, current := range batch {
		if current.probe == probeIdentical {
			continue
		}
		if offender == nil || current == offender {
			current.result.Reason = reason
			continue
		}
		current.result.Reason = protocol.Reason_REASON_REJECTED
	}
	if err := self.fill(ctx, q, groupId, batch, currentEpoch); err != nil {
		return nil, err
	}
	return &SubmitResponse{Results: resultsOf(batch)}, nil
}

// The refusal of §6.1 step (1), which says nothing at all beyond the code.
//
// A group that is unknown and one that is closed reach this together (§4.5, §7.5), and neither
// gets a current_epoch or a winning_commit — both would be answers about a group the caller has
// just been told nothing about, and the difference between the two fields being filled and empty
// is itself the existence oracle §4.5 spends a paragraph closing.
func refuseUnavailable(batch []*pending) *SubmitResponse {
	for _, current := range batch {
		if current.probe == probeIdentical {
			continue
		}
		current.result.Reason = protocol.Reason_REASON_REJECTED
	}
	return &SubmitResponse{Results: resultsOf(batch)}
}

// current_epoch on every result, and the winner on every rejection of a commit.
//
// §6.2: the loser protocol binds to ANY rejection of a commit submission, not to
// REASON_COMMIT_LOST alone, so winning_commit is attached here by the shape of the result rather
// than by its reason code. Binding it to one code left step 2 — the hard MUST NOT on pq_secret
// reuse — unreachable in the path the design actually produces.
//
// `currentEpoch` is passed in when the caller read it under the row lock, and is looked up here
// only on the paths that never took one. A group that is not available answers nothing.
func (self *PgxStore) fill(ctx context.Context, q queryer, groupId []byte, batch []*pending,
	currentEpoch uint64) error {

	if currentEpoch == 0 {
		var epoch int64
		err := q.QueryRow(ctx, `
            SELECT current_epoch FROM message_group
             WHERE group_id = $1 AND NOT closed`, groupId).Scan(&epoch)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		currentEpoch = uint64(epoch)
	}
	for _, current := range batch {
		if current.result.CurrentEpoch == 0 {
			current.result.CurrentEpoch = currentEpoch
		}
		if !current.record.IsCommit || accepted(current.result.Reason) {
			continue
		}
		winner, err := self.winningCommit(ctx, q, groupId, current.record.Epoch)
		if err != nil {
			return err
		}
		current.result.WinningCommit = winner
	}
	return nil
}

// The record that consumed an epoch's one commit slot, as §6.2 hands it to a loser: the winner's
// exact bytes, so that step 3's "apply the winning commit, verifying it through MLS exactly as if
// it had arrived by fetch" has something to apply.
func (self *PgxStore) winningCommit(ctx context.Context, q queryer, groupId []byte, epoch uint64) (*Record, error) {
	row := &storedRecord{}
	err := q.QueryRow(ctx, `
        SELECT `+recordColumns(false)+`
          `+recordSource+`
          JOIN message_commit winner
            ON winner.group_id = r.group_id AND winner.record_id = r.record_id
         WHERE winner.group_id = $1 AND winner.epoch = $2`,
		groupId, int64(epoch)).Scan(row.targets()...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return self.recordOf(groupId, row)
}

// ── the row writers §6.1 shares with §4.3.2 ──────────────────────────────────────────────

// One row of §3.2's `message_record`.
//
// It is a function rather than a statement inside CreateGroup because §6.1 step (5a) writes the
// identical row for every accepted record of a batch, and the column that goes missing in a
// second copy of a thirty-column INSERT is `server_attachment` — the authenticated bytes §5.1
// check 3 re-verifies every projection against, which nothing downstream can reconstruct.
//
// `ON CONFLICT (group_id, record_id) DO NOTHING` is §6.1 step (5a)'s own, and §11.2 item 4's
// "never a bare INSERT". Under the row lock and a gapless allocator the conflict cannot happen;
// what the clause buys is that a path which someday forgets the lock retries into the row it
// already wrote instead of raising a unique violation out of the middle of a transaction.
func insertRecord(ctx context.Context, transaction pgx.Tx, groupId []byte, record *Record,
	now time.Time, prune *time.Time, policyVersion uint32) error {
	attachment := projectAttachment(record)
	_, err := transaction.Exec(ctx, `
        INSERT INTO message_record (group_id, record_id, sender_handle, epoch, stream_index,
                                    is_commit, retention_class, size_bucket, expire_at,
                                    prune_after, pruned, policy_version, body_hash, ct_head,
                                    ct_body, blob_id, server_attachment, recovery_handle,
                                    wrap_target_handle, create_time,
                                    attachment_kind, attachment_epoch, attachment_alg_id,
                                    attachment_media_ttl_seconds, attachment_durable_ttl_seconds,
                                    attachment_group_context_hash, attachment_expected_wrap_count,
                                    attachment_leaf_index, attachment_verify_pub,
                                    attachment_wrap_count)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false, $11, $12, $13, $14, $15,
                     $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)
        ON CONFLICT (group_id, record_id) DO NOTHING`,
		groupId, int64(record.RecordId), record.SenderHandle, int64(record.Epoch),
		int64(record.StreamIndex), record.IsCommit, int16(record.RetentionClass),
		int16(record.SizeBucket), expireAt(record.ExpireAtMs), prune, int32(policyVersion),
		record.BodyHash, record.CtHead, record.CtBody, record.BlobId, record.ServerAttachment,
		attachment.recoveryHandle, attachment.wrapTarget, now,
		attachment.kind, attachment.epoch, attachment.algId,
		attachment.mediaTtl, attachment.durableTtl,
		attachment.groupContextHash, attachment.expectedWrapCount,
		attachment.leafIndex, attachment.verifyPub, attachment.wrapCount)
	return err
}

// §5.4's attachment, decomposed into the projection columns of §3.2 and migration 005c.
//
// The bytes stay authoritative and these are what the server indexes and acts on, which is why
// §5.1 check 3 re-verifies one against the other before either is believed. Two of these columns
// are §3.2's own because they are the ones it INDEXES (Q6 and Q10); the rest are here because
// §6.1 steps (6), (6b) and (6c) act on them and [Store.Fetch] hands the parsed attachment back.
//
// The `EpochAttachment`'s two keys are absent on purpose: §5.3 keeps them wrapped on
// `message_epoch` and retains the current epoch's write key plus one briefly-retired predecessor
// and nothing older, so an unwrapped copy on every commit record would defeat both halves of
// that. [PgxStore.attachmentOf] reads them back from the epoch the attachment names.
type attachmentColumns struct {
	kind              int16
	epoch             *int64
	algId             *int64
	mediaTtl          *int64
	durableTtl        *int64
	groupContextHash  []byte
	expectedWrapCount *int64
	leafIndex         *int64
	verifyPub         []byte
	wrapCount         *int64
	recoveryHandle    []byte
	wrapTarget        []byte
}

func projectAttachment(record *Record) attachmentColumns {
	columns := attachmentColumns{kind: int16(attachmentKindOf(record))}
	if record.Attachment == nil {
		return columns
	}
	switch record.Attachment.Kind {
	case AttachmentEpoch:
		if epoch := record.Attachment.Epoch; epoch != nil {
			columns.epoch = ptr(int64(epoch.Epoch))
			columns.algId = ptr(int64(epoch.AlgId))
			columns.mediaTtl = ptr(int64(epoch.MediaTtlSeconds))
			columns.durableTtl = ptr(int64(epoch.DurableTtlSeconds))
			columns.groupContextHash = epoch.GroupContextHash
			columns.expectedWrapCount = ptr(int64(epoch.ExpectedWrapCount))
		}
	case AttachmentWrap:
		if wrap := record.Attachment.Wrap; wrap != nil {
			columns.wrapTarget = wrap.TargetHandle
			columns.leafIndex = ptr(int64(wrap.LeafIndex))
		}
	case AttachmentRecovery:
		if tag := record.Attachment.Recovery; tag != nil {
			columns.recoveryHandle = tag.Handle
			columns.verifyPub = tag.VerifyPub
			columns.algId = ptr(int64(tag.AlgId))
		}
	case AttachmentEpochComplete:
		if marker := record.Attachment.EpochComplete; marker != nil {
			columns.epoch = ptr(int64(marker.Epoch))
			columns.wrapCount = ptr(int64(marker.WrapCount))
		}
	}
	return columns
}

// §3.1's `expire_at`: unix milliseconds on the wire and in both preimages, and a `timestamp`
// column that is a lossy projection of it with no authority. Zero is not an instant in 1970 —
// it is a record that named no expiry — and it is stored as the NULL that says so.
func expireAt(milliseconds uint64) *time.Time {
	if milliseconds == 0 {
		return nil
	}
	return ptr(time.UnixMilli(int64(milliseconds)).UTC())
}

// §3.2's `durable_ttl_seconds`: NULL is indefinite, and the column is `int`.
func durableColumn(seconds *uint32) *int32 {
	if seconds == nil {
		return nil
	}
	return ptr(int32(*seconds))
}
