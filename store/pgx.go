package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/urnetwork/connect/protocol"
)

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
// [PgxStore.Submit] and [PgxStore.Fetch] are not written yet; both answer
// [errPgxNotImplemented]. Everything the two of them would write is nevertheless in the schema
// and in CreateGroup already, because the founding transaction of §4.3.2 writes one row of
// almost every table §6.1 later appends to.
type PgxStore struct {
	pool   *pgxpool.Pool
	limits Limits
	keys   *KekRing
}

var _ Store = (*PgxStore)(nil)

// The half of the store this agent did not write. It is declared HERE rather than beside the
// [Store] interface on purpose: a sentinel declared with the interface is one every
// implementation of it owes a contract scenario for, and "the pgx half is unfinished" is a fact
// about this file and not a condition any implementation of [Store] answers.
var errPgxNotImplemented = errors.New("store: the pgx Submit and Fetch are not implemented yet")

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

func (self *PgxStore) Fetch(ctx context.Context, request *FetchRequest) (*FetchResult, error) {
	return nil, errPgxNotImplemented
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
                                   retire_time)
             VALUES ($1, 0, $2, NULL, NULL, 0, NULL, $3, $3)`,
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
	if _, err := transaction.Exec(ctx, `
        INSERT INTO message_epoch (group_id, epoch, write_key_wrapped, read_key_wrapped,
                                   read_key_install, alg_id, opened_by_record, accept_time,
                                   retire_time)
             VALUES ($1, 1, $2, $3, $4, $5, $6, $4, NULL)`,
		request.GroupId, writeKey, readKey, now, int32(attachment.AlgId),
		int64(record.RecordId)); err != nil {
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

func (self *PgxStore) Submit(ctx context.Context, request *SubmitRequest) (*SubmitResponse, error) {
	return nil, errPgxNotImplemented
}

// ── the row writers §6.1 shares with §4.3.2 ──────────────────────────────────────────────

// One row of §3.2's `message_record`.
//
// It is a function rather than a statement inside CreateGroup because §6.1 step (5a) writes the
// identical row for every accepted record of a batch, and the column that goes missing in a
// second copy of a twenty-column INSERT is `server_attachment` — the authenticated bytes §5.1
// check 3 re-verifies every projection against, which nothing downstream can reconstruct.
func insertRecord(ctx context.Context, transaction pgx.Tx, groupId []byte, record *Record,
	now time.Time, prune *time.Time, policyVersion uint32) error {
	recoveryHandle, wrapTarget := attachmentProjections(record)
	_, err := transaction.Exec(ctx, `
        INSERT INTO message_record (group_id, record_id, sender_handle, epoch, stream_index,
                                    is_commit, retention_class, size_bucket, expire_at,
                                    prune_after, pruned, policy_version, body_hash, ct_head,
                                    ct_body, blob_id, server_attachment, recovery_handle,
                                    wrap_target_handle, create_time)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false, $11, $12, $13, $14, $15,
                     $16, $17, $18, $19)`,
		groupId, int64(record.RecordId), record.SenderHandle, int64(record.Epoch),
		int64(record.StreamIndex), record.IsCommit, int16(record.RetentionClass),
		int16(record.SizeBucket), expireAt(record.ExpireAtMs), prune, int32(policyVersion),
		record.BodyHash, record.CtHead, record.CtBody, record.BlobId, record.ServerAttachment,
		recoveryHandle, wrapTarget, now)
	return err
}

// §3.2's two extracted projections of `server_attachment`. The bytes stay authoritative and
// these are what the server indexes and acts on, which is why §5.1 check 3 re-verifies one
// against the other before either is believed.
func attachmentProjections(record *Record) (recoveryHandle []byte, wrapTarget []byte) {
	if tag := recoveryTagOf(record); tag != nil {
		recoveryHandle = tag.Handle
	}
	if attachmentKindOf(record) == AttachmentWrap && record.Attachment.Wrap != nil {
		wrapTarget = record.Attachment.Wrap.TargetHandle
	}
	return recoveryHandle, wrapTarget
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
