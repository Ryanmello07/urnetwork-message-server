package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/urnetwork/connect/protocol"
)

// The in-memory [Store]. Every row of §3.2 this transaction touches, held in maps, with the
// order of §6.1 and with nothing else borrowed from Go that Postgres would not have given.
//
// Two locks per group, and which mechanism each one stands in for is the whole argument that
// this implementation is a model rather than a convenience:
//
//   - row is `SELECT … FOR UPDATE` at step (1). It is taken when step (1) is reached — never
//     before, because §6.1 puts the idempotency probe of step (0) ahead of it and a retry that
//     blocked behind the transaction it is retrying would be a different protocol — and it is
//     held to the commit point. It is per group because the row lock is per group: a
//     store-wide lock would serialise submitters to different groups, which no database does,
//     and would hide every ordering defect that only appears under contention.
//
//   - data is READ COMMITTED visibility. Writers buffer everything and apply it in one
//     critical section, so a concurrent reader sees a whole transaction or none of it, which
//     is what a reader of Postgres gets and what a reader of a half-updated map does not.
//     Readers take it shared and never take row, so a probe, a fetch or a status read is never
//     serialised behind a submit — again matching the database, where a SELECT does not queue
//     behind a row lock it does not want.
//
// What this cannot model is a lock timeout: §6.4 answers `REASON_RATE_LIMITED{retry_after}` on
// `lock_timeout = 3s` rather than holding the connection, and there is no connection here to
// hold. That refusal belongs to the pgx implementation and is deliberately absent from this
// one and from the contract, because a contract test for it could only pass against a fake.
type MemoryStore struct {
	limits Limits
	now    func() time.Time

	mutex  sync.RWMutex
	groups map[string]*memoryGroup
}

var _ Store = (*MemoryStore)(nil)

// A store holding nothing, with the limits of §7.3 to evaluate step (6) against.
func NewMemoryStore(limits Limits) *MemoryStore {
	return &MemoryStore{
		limits: limits,
		now:    func() time.Time { return time.Now().UTC() },
		groups: map[string]*memoryGroup{},
	}
}

// A clock for tests that need `prune_after` and `retire_time` to be something they chose. The
// store's own default is time.Now().UTC(), and the UTC is not decoration: §3.1 splits
// retention across a Go clock and a database clock and a non-UTC one prunes user data early.
func (self *MemoryStore) SetClock(now func() time.Time) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.now = now
}

func (self *MemoryStore) clock() func() time.Time {
	self.mutex.RLock()
	defer self.mutex.RUnlock()
	return self.now
}

// One row of `message_group` and every row of §3.2 that hangs off it.
type memoryGroup struct {
	row  sync.Mutex
	data sync.RWMutex

	groupId    []byte
	createTime time.Time

	currentEpoch      uint64
	nextRecordId      uint64
	mediaTtlSeconds   uint32
	durableTtlSeconds *uint32
	policyVersion     uint32
	epochComplete     bool
	groupContextHash  []byte
	closed            bool
	closeTime         time.Time

	// message_record, indexed by record_id - 1. Gapless and 1-based is what makes the slice
	// index arithmetic legal, and is the property §4.3.4 sells to clients.
	records []*recordRow
	claims  map[claimKey]*claimRow
	commits map[uint64]*commitRow
	senders map[string]*senderRow
	epochs  map[uint64]*epochRow
	// message_recovery, TOFU scoped to this group (§3.2, §5.4)
	recovery map[string]*recoveryRow
}

type recordRow struct {
	record     *Record
	pruneAfter *time.Time
	pruned     bool
	createTime time.Time
	policy     uint32
}

type claimKey struct {
	sender      string
	streamIndex uint64
}

type claimRow struct {
	recordId   uint64
	bodyHash   []byte
	headHash   []byte
	createTime time.Time
}

type commitRow struct {
	epoch    uint64
	recordId uint64
}

type senderRow struct {
	lastStreamIndex uint64
	recordCount     int64
	byteCount       int64
	lastTime        time.Time
}

type epochRow struct {
	epoch             uint64
	writeKey          []byte
	readKey           []byte
	readKeyInstall    time.Time
	algId             uint32
	expectedWrapCount uint32
	openedByRecord    uint64
	acceptTime        time.Time
	retireTime        time.Time
}

type recoveryRow struct {
	verifyPub []byte
	algId     uint32
	firstSeen time.Time
}

// ── the read paths, §5.1.1: no transaction, no allocation ────────────────────────────────

func (self *MemoryStore) GroupState(ctx context.Context, groupId []byte) (*GroupState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(groupId, GroupIdBytes); err != nil {
		return nil, err
	}
	group := self.group(groupId)
	if group == nil {
		return nil, ErrGroupUnavailable
	}
	group.data.RLock()
	defer group.data.RUnlock()
	if group.closed {
		return nil, ErrGroupUnavailable
	}
	return group.state(), nil
}

func (self *MemoryStore) EpochKeys(ctx context.Context, groupId []byte, epoch uint64) (*EpochKeys, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(groupId, GroupIdBytes); err != nil {
		return nil, err
	}
	group := self.group(groupId)
	if group == nil {
		return nil, ErrEpochKeyUnknown
	}
	group.data.RLock()
	defer group.data.RUnlock()
	row, found := group.epochs[epoch]
	// an epoch that never existed and one whose keys have both been discarded answer
	// identically, which is §5.1.1 refusing to be an oracle for either
	if !found || (row.writeKey == nil && row.readKey == nil) {
		return nil, ErrEpochKeyUnknown
	}
	return &EpochKeys{
		Epoch:          row.epoch,
		WriteKey:       bytes.Clone(row.writeKey),
		ReadKey:        bytes.Clone(row.readKey),
		ReadKeyInstall: row.readKeyInstall,
		AlgId:          row.algId,
		OpenedByRecord: row.openedByRecord,
		AcceptTime:     row.acceptTime,
		RetireTime:     row.retireTime,
	}, nil
}

func (self *MemoryStore) Fetch(ctx context.Context, request *FetchRequest) (*FetchResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkLength(request.GroupId, GroupIdBytes); err != nil {
		return nil, err
	}
	group := self.group(request.GroupId)
	if group == nil {
		return nil, ErrGroupUnavailable
	}
	group.data.RLock()
	defer group.data.RUnlock()
	if group.closed {
		return nil, ErrGroupUnavailable
	}

	result := &FetchResult{
		NextRecordId:      request.SinceRecordId,
		HighWaterRecordId: group.nextRecordId - 1,
		Complete:          true,
	}
	for _, row := range group.records {
		if row.record.RecordId <= request.SinceRecordId {
			continue
		}
		if !classIncluded(request.ClassMask, row.record.RetentionClass) {
			continue
		}
		if request.Limit != 0 && uint32(len(result.Records)) == request.Limit {
			// truncated by the limit, which §4.3.4 calls normal rather than an error
			result.Complete = false
			break
		}
		result.Records = append(result.Records, row.read(request.HeadsOnly))
		result.NextRecordId = row.record.RecordId
	}
	return result, nil
}

// The class filter of §4.3.4, a bit per retention-class wire byte of §3.1. Zero is every class,
// which is the request's own documented default and not an empty set.
func classIncluded(mask uint32, class uint8) bool {
	if mask == 0 {
		return true
	}
	return mask&(uint32(1)<<class) != 0
}

func (self *MemoryStore) CloseGroup(ctx context.Context, groupId []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkLength(groupId, GroupIdBytes); err != nil {
		return err
	}
	group := self.group(groupId)
	if group == nil {
		return ErrGroupUnavailable
	}
	group.row.Lock()
	defer group.row.Unlock()
	group.data.Lock()
	defer group.data.Unlock()
	if group.closed {
		return ErrGroupUnavailable
	}
	group.closed = true
	group.closeTime = self.clock()()
	return nil
}

// ── §4.3.2 CreateGroup ───────────────────────────────────────────────────────────────────

func (self *MemoryStore) CreateGroup(ctx context.Context, request *CreateGroupRequest) (*CreateGroupResult, error) {
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

	// §5.1's carve-out: there is no message_group row and therefore no current_epoch, so the
	// EpochAttachment rule `epoch == current_epoch + 1` is evaluated as `epoch == 1`. The
	// initial commit sits at epoch 0 and its attachment opens epoch 1. Everything else about
	// the attachment is checked exactly as a steady-state commit's is, because an accepted
	// commit with a malformed attachment bricks the group and this is the only commit no
	// later commit can rescue.
	if !request.InitialCommit.IsCommit || request.InitialCommit.Epoch != 0 ||
		!wellFormedEpochAttachment(request.InitialCommit, 1) {
		return &CreateGroupResult{Reason: protocol.Reason_REASON_REJECTED}, nil
	}

	now := self.clock()()
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if _, taken := self.groups[string(request.GroupId)]; taken {
		// §4.3.2: an existing group_id is REASON_REJECTED and the creator retries with a fresh
		// one. §4.5 is why this is not distinguished from a bad MAC
		return &CreateGroupResult{Reason: protocol.Reason_REASON_REJECTED}, nil
	}

	attachment := request.InitialCommit.Attachment.Epoch
	media, durable, applied := self.limits.apply(attachment)
	record := cloneRecord(request.InitialCommit)
	record.RecordId = firstRecordId

	group := &memoryGroup{
		groupId:           bytes.Clone(request.GroupId),
		createTime:        now,
		currentEpoch:      1,
		nextRecordId:      firstRecordId + 1,
		mediaTtlSeconds:   media,
		durableTtlSeconds: durable,
		policyVersion:     1,
		epochComplete:     false,
		groupContextHash:  bytes.Clone(attachment.GroupContextHash),
		claims:            map[claimKey]*claimRow{},
		commits:           map[uint64]*commitRow{},
		senders:           map[string]*senderRow{},
		epochs:            map[uint64]*epochRow{},
		recovery:          map[string]*recoveryRow{},
	}

	// epoch 0 holds write_key[0], which verified this commit and nothing else; it is retired
	// on sight because current_epoch is already 1, and the tidy loop of §7.4 takes the key 60
	// seconds later exactly as it would for any superseded epoch (§5.3)
	group.epochs[0] = &epochRow{
		epoch:      0,
		writeKey:   bytes.Clone(request.BootstrapWriteKey),
		acceptTime: now,
		retireTime: now,
	}
	group.epochs[1] = &epochRow{
		epoch:             1,
		writeKey:          bytes.Clone(attachment.WriteKey),
		readKey:           bytes.Clone(attachment.ReadKey),
		readKeyInstall:    now,
		algId:             attachment.AlgId,
		expectedWrapCount: attachment.ExpectedWrapCount,
		openedByRecord:    record.RecordId,
		acceptTime:        now,
	}

	group.records = append(group.records, &recordRow{
		record:     record,
		pruneAfter: pruneAfter(now, record.RetentionClass, media, durable),
		createTime: now,
		policy:     group.policyVersion,
	})
	group.claims[claimKey{sender: string(record.SenderHandle), streamIndex: record.StreamIndex}] = &claimRow{
		recordId:   record.RecordId,
		bodyHash:   bytes.Clone(record.BodyHash),
		headHash:   headHash(record.CtHead),
		createTime: now,
	}
	group.commits[record.Epoch] = &commitRow{epoch: record.Epoch, recordId: record.RecordId}
	group.senders[string(record.SenderHandle)] = &senderRow{
		lastStreamIndex: record.StreamIndex,
		recordCount:     1,
		byteCount:       recordBytes(record),
		lastTime:        now,
	}
	if tag := recoveryTagOf(record); tag != nil {
		group.recovery[string(tag.Handle)] = &recoveryRow{
			verifyPub: bytes.Clone(tag.VerifyPub),
			algId:     tag.AlgId,
			firstSeen: now,
		}
	}

	self.groups[string(group.groupId)] = group
	return &CreateGroupResult{
		Reason:       protocol.Reason_REASON_OK,
		CurrentEpoch: group.currentEpoch,
		RecordId:     record.RecordId,
		Applied:      applied,
	}, nil
}

// ── §6.1, the transaction ────────────────────────────────────────────────────────────────

// What step (0) found for one record of the batch.
type probeOutcome uint8

const (
	probeAbsent probeOutcome = iota
	probeIdentical
	probeDiffers
)

// One record's place in the batch as the checks run.
type pending struct {
	record  *Record
	result  *SubmitResult
	probe   probeOutcome
	settled bool // step (0) answered it, or a gate refused it; either way it allocates nothing
}

func (self *MemoryStore) Submit(ctx context.Context, request *SubmitRequest) (*SubmitResponse, error) {
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
	group := self.group(request.GroupId)

	// (0) IDEMPOTENCY PROBE, before any gate, before any allocation, and — the half a
	// single-threaded reading loses — before the row lock of step (1). A genuine retry is by
	// definition at an already-consumed index and often at an epoch that has since advanced,
	// so a probe behind the gates rejects every one of them, and a probe behind the lock makes
	// a retry queue behind the very transaction it is retrying.
	self.probe(group, batch)
	for _, current := range batch {
		if current.probe == probeDiffers {
			// same index, different content: a client bug or an attack, and §6.1 returns
			// before the lock, so the batch writes nothing and takes no lock at all
			return self.refuseBatch(group, batch, current, protocol.Reason_REASON_STREAM_INDEX_REUSED), nil
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
		// every record already landed. §6.1 returns REASON_OK{record_id} with no allocation,
		// and there is nothing left for the gates to gate
		self.fillCurrentEpoch(group, batch)
		return &SubmitResponse{Results: resultsOf(batch)}, nil
	}

	if group == nil {
		return self.refuseBatch(group, batch, nil, protocol.Reason_REASON_REJECTED), nil
	}

	// (1) Lock the group. Read state; DO NOT allocate ids yet.
	group.row.Lock()
	defer group.row.Unlock()

	group.data.RLock()
	closed := group.closed
	state := group.state()
	group.data.RUnlock()

	// 0 rows -> REASON_REJECTED (unknown or closed; indistinguishable, §4.5)
	if closed {
		return self.refuseBatch(group, batch, nil, protocol.Reason_REASON_REJECTED), nil
	}
	for _, current := range batch {
		current.result.CurrentEpoch = state.CurrentEpoch
	}

	// (2), (2b) and (3), for every record, before a single id is allocated. Step (3b) is why
	// the loop is separated from the writes: an allocated block larger than the rows written
	// gives the group a permanent record_id gap, which destroys the property decision B4
	// exists to create and which §12.2 C-4 tells clients to treat as a fault.
	highWater := map[string]uint64{}
	for _, current := range batch {
		if current.settled {
			continue
		}
		if refusal := self.gate(group, state, current.record, highWater); refusal != protocol.Reason_REASON_OK {
			return self.refuseBatch(group, batch, current, refusal), nil
		}
		highWater[string(current.record.SenderHandle)] = current.record.StreamIndex
	}

	return self.commit(group, state, batch), nil
}

// Step (0), against `message_stream_claim` and never against `message_record`: §7.2 zeroes an
// expired ephemeral record's sender_handle and erases its head, so the record cannot answer
// this question and never could for that class.
//
// Both hashes are compared. Two records can legitimately share a body hash — an empty body —
// while differing in the head, and a probe on body_hash alone would call the second one a
// retry of the first.
func (self *MemoryStore) probe(group *memoryGroup, batch []*pending) {
	if group == nil {
		return
	}
	group.data.RLock()
	defer group.data.RUnlock()
	for _, current := range batch {
		record := current.record
		claim, found := group.claims[claimKey{sender: string(record.SenderHandle), streamIndex: record.StreamIndex}]
		if !found {
			continue
		}
		if bytes.Equal(claim.bodyHash, record.BodyHash) && bytes.Equal(claim.headHash, headHash(record.CtHead)) {
			current.probe = probeIdentical
			current.result.Reason = protocol.Reason_REASON_OK
			current.result.RecordId = claim.recordId
			continue
		}
		current.probe = probeDiffers
	}
}

// Steps (2), (2b) and (3) for one record. REASON_OK means every gate passed.
func (self *MemoryStore) gate(group *memoryGroup, state *GroupState, record *Record, highWater map[string]uint64) protocol.Reason {
	group.data.RLock()
	defer group.data.RUnlock()

	// (2) EPOCH GATE, commit-aware. The message_commit check comes FIRST and stays first: the
	// row lock serialises committers, so a loser acquires the lock only after the winner
	// advanced the epoch, and an epoch-first gate therefore answers EPOCH_STALE and §6.2's
	// mandatory loser protocol never fires. Regardless of how far current_epoch has advanced.
	if record.IsCommit {
		if _, lost := group.commits[record.Epoch]; lost {
			return protocol.Reason_REASON_COMMIT_LOST
		}
	}
	if record.Epoch != state.CurrentEpoch {
		return protocol.Reason_REASON_EPOCH_STALE
	}
	// readable-but-not-writable until the epoch's wrap fan-out closes with its marker
	if !state.EpochComplete && !exemptFromEpochComplete(record) {
		return protocol.Reason_REASON_EPOCH_INCOMPLETE
	}

	// (2b) Attachment well-formedness, after the epoch gate and before the CAS, which is where
	// §6.1 puts it and where it has to stay in both directions. Before the CAS, because an
	// accepted commit carrying a malformed attachment opens an epoch with no verifiable write
	// key and bricks the group permanently. After the commit-lost check, because a loser's
	// attachment names epoch n+1 while current_epoch is already n+1 — perfectly well-formed
	// when it was built, and `epoch == current_epoch + 1` now false — so an attachment check
	// in front of the CAS check would answer REASON_REJECTED to every loser and §6.2's loser
	// protocol would never see the winner it is required to apply.
	if record.IsCommit != (attachmentKindOf(record) == AttachmentEpoch) {
		return protocol.Reason_REASON_REJECTED
	}
	if record.IsCommit && !wellFormedEpochAttachment(record, state.CurrentEpoch+1) {
		return protocol.Reason_REASON_REJECTED
	}

	// (3) Stream monotonicity, per (group_id, sender_handle). Monotonic, NOT contiguous: a
	// refused write, a crash between reserve and send, or a lost commit leaves a legal gap,
	// and a contiguity check would refuse every one of them forever.
	last, seen := highWater[string(record.SenderHandle)]
	if !seen {
		if sender, found := group.senders[string(record.SenderHandle)]; found {
			last, seen = sender.lastStreamIndex, true
		}
	}
	if seen && record.StreamIndex <= last {
		return protocol.Reason_REASON_STREAM_INDEX_REGRESSED
	}

	// (6c) as a gate rather than as a write. §6.1 writes the recovery row after allocation and
	// rolls the batch back on a mismatch, which writes nothing either way; checking it here
	// keeps "a refusal allocates nothing" a property of the code path and not of an unwind.
	if tag := recoveryTagOf(record); tag != nil {
		if known, found := group.recovery[string(tag.Handle)]; found && !bytes.Equal(known.verifyPub, tag.VerifyPub) {
			return protocol.Reason_REASON_REJECTED
		}
	}
	return protocol.Reason_REASON_OK
}

// Steps (4) through (7), applied together. Everything above this point read; nothing above it
// wrote, which is what makes "a refused submit allocates nothing" a property of the shape of
// this function rather than a claim about it.
func (self *MemoryStore) commit(group *memoryGroup, state *GroupState, batch []*pending) *SubmitResponse {
	now := self.clock()()

	group.data.Lock()

	// (5b) THE CAS, as a one-row insert against a full primary key. Under the row lock the
	// gate above has already answered this, and it is still here because §6.1 keeps both
	// mechanisms deliberately: the lock makes the losing path deterministic and lets the
	// winner be read in the same round trip, and the primary key holds the invariant even if
	// some future path forgets the lock. The invariant is worth two mechanisms.
	for _, current := range batch {
		if current.settled || !current.record.IsCommit {
			continue
		}
		if _, lost := group.commits[current.record.Epoch]; lost {
			group.data.Unlock()
			return self.refuseBatch(group, batch, current, protocol.Reason_REASON_COMMIT_LOST)
		}
	}

	// (4) Allocate exactly k ids, where k is the verified accepted count. Only now.
	accepted := []*pending{}
	for _, current := range batch {
		if !current.settled {
			accepted = append(accepted, current)
		}
	}
	first := group.nextRecordId
	group.nextRecordId += uint64(len(accepted))

	for index, current := range accepted {
		record := cloneRecord(current.record)
		record.RecordId = first + uint64(index)

		mediaTtl, durableTtl := group.mediaTtlSeconds, group.durableTtlSeconds
		if record.IsCommit {
			// (6) On a won commit, and only then: open the next epoch, retire the old key.
			attachment := record.Attachment.Epoch
			media, durable, applied := self.limits.apply(attachment)
			group.epochs[state.CurrentEpoch+1] = &epochRow{
				epoch:             state.CurrentEpoch + 1,
				writeKey:          bytes.Clone(attachment.WriteKey),
				readKey:           bytes.Clone(attachment.ReadKey),
				readKeyInstall:    now,
				algId:             attachment.AlgId,
				expectedWrapCount: attachment.ExpectedWrapCount,
				openedByRecord:    record.RecordId,
				acceptTime:        now,
			}
			if superseded, found := group.epochs[state.CurrentEpoch]; found && superseded.writeKey != nil {
				superseded.retireTime = now
			}
			// the predicate is LOAD-BEARING (§3.3 Q12): strictly older than the epoch being
			// superseded, so the one briefly-retired predecessor §5.3 keeps stays verifiable
			for epoch, row := range group.epochs {
				if epoch < state.CurrentEpoch && row.writeKey != nil {
					row.writeKey = nil
				}
			}
			group.currentEpoch = state.CurrentEpoch + 1
			group.epochComplete = false
			group.mediaTtlSeconds = media
			group.durableTtlSeconds = durable
			group.groupContextHash = bytes.Clone(attachment.GroupContextHash)
			group.policyVersion++
			mediaTtl, durableTtl = media, durable
			current.result.Applied = applied
			current.result.CurrentEpoch = group.currentEpoch

			// (5b) the commit row itself
			group.commits[record.Epoch] = &commitRow{epoch: record.Epoch, recordId: record.RecordId}
		}

		// (6b) the marker that closes the fan-out. Only a wrap_count equal to the epoch's
		// expected_wrap_count opens the group for ordinary writes; §5.1 check 3 refuses a
		// mismatch before it ever reaches here, and a mismatch that did reach here leaves the
		// group where it was rather than opening it on a number nobody agreed
		if marker := epochCompleteTagOf(record); marker != nil {
			if row, found := group.epochs[group.currentEpoch]; found &&
				marker.Epoch == group.currentEpoch && marker.WrapCount == row.expectedWrapCount {
				group.epochComplete = true
			}
		}

		// (5a) Claim first, then the row. The claim is the uniqueness authority; the record
		// carries no unique index on (sender_handle, stream_index) at all, because §7.2 zeroes
		// that column on expiry and two senders may legitimately hold the same index.
		group.claims[claimKey{sender: string(record.SenderHandle), streamIndex: record.StreamIndex}] = &claimRow{
			recordId:   record.RecordId,
			bodyHash:   bytes.Clone(record.BodyHash),
			headHash:   headHash(record.CtHead),
			createTime: now,
		}
		group.records = append(group.records, &recordRow{
			record:     record,
			pruneAfter: pruneAfter(now, record.RetentionClass, mediaTtl, durableTtl),
			createTime: now,
			policy:     group.policyVersion,
		})

		// (6c) TOFU, scoped to this group. The gate refused a differing pub already; this is
		// the ON CONFLICT DO NOTHING half
		if tag := recoveryTagOf(record); tag != nil {
			if _, found := group.recovery[string(tag.Handle)]; !found {
				group.recovery[string(tag.Handle)] = &recoveryRow{
					verifyPub: bytes.Clone(tag.VerifyPub),
					algId:     tag.AlgId,
					firstSeen: now,
				}
			}
		}

		// (7) Sender high-water and accounting.
		sender, found := group.senders[string(record.SenderHandle)]
		if !found {
			sender = &senderRow{}
			group.senders[string(record.SenderHandle)] = sender
		}
		sender.lastStreamIndex = record.StreamIndex
		sender.recordCount++
		sender.byteCount += recordBytes(record)
		sender.lastTime = now

		current.result.Reason = protocol.Reason_REASON_OK
		current.result.RecordId = record.RecordId
	}
	currentEpoch := group.currentEpoch
	group.data.Unlock()

	for _, current := range batch {
		if current.result.CurrentEpoch == 0 {
			current.result.CurrentEpoch = currentEpoch
		}
	}
	return &SubmitResponse{Results: resultsOf(batch)}
}

// A batch that wrote nothing, with a reason on every result: §6.1 step (3b).
//
// The offender carries the specific refusal and every other record carries the deliberately
// non-specific REASON_REJECTED of §4.5, because the others were not themselves refused for
// anything and inventing a per-record reason for them would say something untrue. A record
// step (0) already answered keeps its REASON_OK: it names a row that landed in an earlier
// transaction, and no rollback of this one can unland it.
func (self *MemoryStore) refuseBatch(group *memoryGroup, batch []*pending, offender *pending, reason protocol.Reason) *SubmitResponse {
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
	self.fillCurrentEpoch(group, batch)
	return &SubmitResponse{Results: resultsOf(batch)}
}

// current_epoch on every result, and the winner on every rejection of a commit.
//
// §6.2: the loser protocol binds to ANY rejection of a commit submission, not to
// REASON_COMMIT_LOST alone, so winning_commit is attached here by the shape of the result
// rather than by its reason code. Binding it to one code left step 2 — the hard MUST NOT on
// pq_secret reuse — unreachable in the path the design actually produces.
func (self *MemoryStore) fillCurrentEpoch(group *memoryGroup, batch []*pending) {
	if group == nil {
		return
	}
	group.data.RLock()
	defer group.data.RUnlock()
	for _, current := range batch {
		if current.result.CurrentEpoch == 0 {
			current.result.CurrentEpoch = group.currentEpoch
		}
		if !current.record.IsCommit || current.result.Reason == protocol.Reason_REASON_OK {
			continue
		}
		if winner, found := group.commits[current.record.Epoch]; found {
			current.result.WinningCommit = cloneRecord(group.records[winner.recordId-1].record)
		}
	}
}

func resultsOf(batch []*pending) []*SubmitResult {
	results := make([]*SubmitResult, len(batch))
	for index, current := range batch {
		results[index] = current.result
	}
	return results
}

func (self *MemoryStore) group(groupId []byte) *memoryGroup {
	self.mutex.RLock()
	defer self.mutex.RUnlock()
	return self.groups[string(groupId)]
}

// ── row helpers ──────────────────────────────────────────────────────────────────────────

// Held under data.
func (self *memoryGroup) state() *GroupState {
	state := &GroupState{
		CurrentEpoch:     self.currentEpoch,
		NextRecordId:     self.nextRecordId,
		MediaTtlSeconds:  self.mediaTtlSeconds,
		PolicyVersion:    self.policyVersion,
		EpochComplete:    self.epochComplete,
		GroupContextHash: bytes.Clone(self.groupContextHash),
	}
	if self.durableTtlSeconds != nil {
		state.DurableTtlSeconds = ptr(*self.durableTtlSeconds)
	}
	return state
}

// A record on the way out, re-encoded by the caller. heads_only drops the body, which §4.3.4
// uses for fast catch-up and for hole scans; an erased body is already nil and reads the same.
func (self *recordRow) read(headsOnly bool) *Record {
	record := cloneRecord(self.record)
	if headsOnly {
		record.CtBody = nil
	}
	return record
}

// §7.1 computes prune_after in Go, from the class and the group's policy. PERMANENT never
// prunes, and DURABLE with an indefinite policy is the one other row with no prune time at all.
func pruneAfter(now time.Time, class uint8, mediaTtl uint32, durableTtl *uint32) *time.Time {
	switch {
	case class == ClassPermanent:
		return nil
	case class == ClassDurable:
		if durableTtl == nil {
			return nil
		}
		return ptr(now.Add(time.Duration(*durableTtl) * time.Second))
	case class == ClassMedia:
		return ptr(now.Add(time.Duration(mediaTtl) * time.Second))
	default:
		bucket := class - ClassEphBase
		return ptr(now.Add(time.Duration(ephBucketSeconds[bucket]) * time.Second))
	}
}

// H(ct_head), which is what the claim stores. §6.3: the record's head is erased when an
// ephemeral record expires, so a probe that recomputed it from the record would start calling
// a legitimate retry REASON_STREAM_INDEX_REUSED an hour after the fact.
func headHash(head []byte) []byte {
	sum := sha256.Sum256(head)
	return sum[:]
}

func recordBytes(record *Record) int64 {
	return int64(len(record.CtHead) + len(record.CtBody))
}

func attachmentKindOf(record *Record) AttachmentKind {
	if record.Attachment == nil {
		return AttachmentNone
	}
	return record.Attachment.Kind
}

func recoveryTagOf(record *Record) *RecoveryTag {
	if attachmentKindOf(record) != AttachmentRecovery {
		return nil
	}
	return record.Attachment.Recovery
}

func epochCompleteTagOf(record *Record) *EpochCompleteTag {
	if attachmentKindOf(record) != AttachmentEpochComplete {
		return nil
	}
	return record.Attachment.EpochComplete
}

// Step (2)'s exemption, in §6.1's own words: a wrap, a snapshot, or an EpochComplete marker
// for this epoch. A snapshot is a WrapTag at [SnapshotLeafIndex], so the wrap case covers it.
func exemptFromEpochComplete(record *Record) bool {
	switch attachmentKindOf(record) {
	case AttachmentWrap, AttachmentEpochComplete:
		return true
	default:
		return false
	}
}

// The commit attachment checks §5.1 check 3 lists, evaluated against the epoch this commit
// would open. Everything here is a shape or an arithmetic relation; `alg_id` is deliberately
// not on the list, because the set of known algorithms is message.ParseServerAttachment's and
// a second copy of it here would be a second copy to drift.
func wellFormedEpochAttachment(record *Record, opens uint64) bool {
	if attachmentKindOf(record) != AttachmentEpoch || record.Attachment.Epoch == nil {
		return false
	}
	attachment := record.Attachment.Epoch
	switch {
	case attachment.Epoch != opens:
		return false
	case len(attachment.WriteKey) != EpochKeyBytes:
		return false
	case len(attachment.ReadKey) != EpochKeyBytes:
		return false
	case attachment.ExpectedWrapCount == 0:
		return false
	case attachment.GroupContextHash != nil && len(attachment.GroupContextHash) != GroupContextHashBytes:
		return false
	}
	return true
}

// §3.1's exact lengths and §3.2's CHECKs, which the memory implementation has no constraints
// of its own to raise.
func validateRecord(record *Record) error {
	if err := checkLength(record.SenderHandle, SenderHandleBytes); err != nil {
		return err
	}
	if err := checkLength(record.BodyHash, BodyHashBytes); err != nil {
		return err
	}
	if len(record.CtHead) == 0 {
		return ErrIdentifierShape
	}
	if record.SizeBucket > 5 {
		return ErrSizeBucket
	}
	switch {
	case record.RetentionClass <= ClassMedia:
	case ClassEphBase <= record.RetentionClass && record.RetentionClass <= ClassEphMax:
	default:
		return ErrRetentionClass
	}
	// §7.6, normative: an EPH(0) transient is never persisted, so it has no row here to be
	// stored in and no record_id to be given. Reaching this package with one is an API-layer
	// defect rather than anything a client did
	if record.RetentionClass == ClassEphBase {
		return ErrTransientRecord
	}
	// inline XOR blob, never both (§3.2)
	if record.CtBody != nil && record.BlobId != nil {
		return ErrSizeBucket
	}
	if record.BlobId != nil {
		if err := checkLength(record.BlobId, BlobIdBytes); err != nil {
			return err
		}
	}
	switch attachmentKindOf(record) {
	case AttachmentWrap:
		if record.Attachment.Wrap == nil {
			return ErrIdentifierShape
		}
		if err := checkLength(record.Attachment.Wrap.TargetHandle, WrapTargetHandleBytes); err != nil {
			return err
		}
	case AttachmentRecovery:
		if record.Attachment.Recovery == nil {
			return ErrIdentifierShape
		}
		if err := checkLength(record.Attachment.Recovery.Handle, RecoveryHandleBytes); err != nil {
			return err
		}
		if err := checkLength(record.Attachment.Recovery.VerifyPub, VerifyPubBytes); err != nil {
			return err
		}
	case AttachmentEpochComplete:
		if record.Attachment.EpochComplete == nil {
			return ErrIdentifierShape
		}
	case AttachmentEpoch:
		if record.Attachment.Epoch == nil {
			return ErrIdentifierShape
		}
	}
	return nil
}

func checkLength(value []byte, want int) error {
	if len(value) != want {
		return ErrIdentifierShape
	}
	return nil
}

// Records cross this boundary by value, in both directions. A store that handed out the slice
// it holds would let a caller rewrite a stored body_hash from outside the transaction, which
// is not something the pgx implementation could do even by accident.
func cloneRecord(record *Record) *Record {
	if record == nil {
		return nil
	}
	copied := *record
	copied.SenderHandle = bytes.Clone(record.SenderHandle)
	copied.BodyHash = bytes.Clone(record.BodyHash)
	copied.CtHead = bytes.Clone(record.CtHead)
	copied.CtBody = bytes.Clone(record.CtBody)
	copied.BlobId = bytes.Clone(record.BlobId)
	copied.ServerAttachment = bytes.Clone(record.ServerAttachment)
	copied.Attachment = cloneAttachment(record.Attachment)
	return &copied
}

func cloneAttachment(attachment *Attachment) *Attachment {
	if attachment == nil {
		return nil
	}
	copied := &Attachment{Kind: attachment.Kind}
	if attachment.Epoch != nil {
		epoch := *attachment.Epoch
		epoch.WriteKey = bytes.Clone(attachment.Epoch.WriteKey)
		epoch.ReadKey = bytes.Clone(attachment.Epoch.ReadKey)
		epoch.GroupContextHash = bytes.Clone(attachment.Epoch.GroupContextHash)
		copied.Epoch = &epoch
	}
	if attachment.Wrap != nil {
		wrap := *attachment.Wrap
		wrap.TargetHandle = bytes.Clone(attachment.Wrap.TargetHandle)
		copied.Wrap = &wrap
	}
	if attachment.Recovery != nil {
		recovery := *attachment.Recovery
		recovery.Handle = bytes.Clone(attachment.Recovery.Handle)
		recovery.VerifyPub = bytes.Clone(attachment.Recovery.VerifyPub)
		copied.Recovery = &recovery
	}
	if attachment.EpochComplete != nil {
		marker := *attachment.EpochComplete
		copied.EpochComplete = &marker
	}
	return copied
}
