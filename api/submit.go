package api

import (
	"bytes"
	"context"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/blobd"
	"github.com/urnetwork/message-server/store"
	"google.golang.org/protobuf/proto"
)

// What one record of a submission has been shown to be, as the checks of §5.1 run over it.
//
// The parse is taken once and every later check reads it. §4.3.3 makes `record_bytes`
// authoritative and the projection a copy the server verifies and then never consults again, so
// a second parse — or a check that reached for the projection because it was nearer — is the
// divergence check 3 exists to prevent.
type recordPass struct {
	// The request's own copy, kept only so that check 3 can compare it with the parse.
	projection *protocol.Record

	parsed     *message.Record
	attachment *message.ServerAttachment

	// §5.1 check 6's answer for this record's epoch, and check 7's key.
	writeKey []byte
}

// One submission as it moves down §5.1's checks.
type submitPass struct {
	conn    *Connection
	groupId []byte
	records []*recordPass

	// §4.3.3's `epoch_keys` exactly as the request carried it, and the ONE delivery §4.3.3
	// admits, resolved out of it by [epochKeyAlignment] at check 3.
	//
	// `keys` is nil for every submission but a kind `0x0005` commit, which is every submission
	// this server has ever seen up to the day §5.4's acceptance window opens. It is carried on
	// the pass rather than re-derived at the transaction because the alignment refusals are
	// check 3's, and check 3 is in front of the key lookup, the MAC and the transaction — an
	// alignment fault must not be able to cost a database read.
	deliveries []*protocol.EpochKeyDelivery
	keys       *protocol.EpochKeyDelivery

	// Which named clause of check 3's `0x0005` arm refused this submission, when one did.
	//
	// It never reaches the wire — §4.5 merges every client-caused refusal into
	// `REASON_REJECTED` and a distinguishable refusal here would be an oracle over a value the
	// MAC covers — and it is not a log line either, because nothing in this build logs yet. It
	// is here so that the six clauses of [epochKeyAlignment] and the digest comparison are
	// SEPARABLE by this server's own tests: a gate whose clauses all answer one opaque code is
	// a gate whose clauses can be deleted one at a time with every test still green.
	alignment error

	// Set by the last stage, which is the only one that opens a transaction.
	response *protocol.SubmitResponse
}

// Which record a check refused, and with what. `index` is [wholeSubmission] when the refusal is
// the submission's rather than one record's — an unknown group is not the third record's fault.
type refusal struct {
	reason protocol.Reason
	index  int
}

const wholeSubmission = -1

var passed = refusal{reason: protocol.Reason_REASON_OK, index: wholeSubmission}

func refuse(reason protocol.Reason, index int) refusal {
	return refusal{reason: reason, index: index}
}

// One numbered check of §5.1, as the pipeline actually runs it.
//
// The number is here so that the order is a value the tests can read rather than a claim about
// the order of some statements. §5.1's order is normative for denial of service — "nothing that
// costs a database read happens before something that costs a hash" — and an ordering property
// nothing can observe is one the next refactor reorders for free.
type stage struct {
	number int
	name   string
	run    func(ctx context.Context, pass *submitPass) refusal
}

// §5.1's check order for the submit path, as one ordered value.
//
// [Handler.Submit] iterates exactly this slice, so the order under test is the order that runs.
// Checks 1, 2 and 4 are not here: they belong to [FrontChecks] and run in front of the whole
// pipeline, which is where §5.1 puts them and where their absence is declared.
func (self *Handler) submitStages() []stage {
	return []stage{
		{number: 3, name: "static shape, and every projection against the parse", run: self.checkStaticShape},
		{number: 5, name: "the known-group filter, with no database read on a hit", run: self.checkKnownGroup},
		{number: 6, name: "the epoch key lookup", run: self.checkEpochKey},
		{number: 7, name: "write_auth", run: self.checkWriteAuth},
		{number: 8, name: "body_hash against the body", run: self.checkBodyHash},
		{number: 9, name: "the §6.1 transaction", run: self.runTransaction},
	}
}

// §4.3.3, through §5.1's checks and then §6.1's transaction.
//
// The envelope reason is REASON_OK whenever there is a body to return, including a body whose
// every result is a refusal: §4.3.3 aligns SubmitResult positionally with the request, and a
// per-record answer cannot travel on the envelope. The envelope carries the reason only when
// there is no body at all — checks 1, 2 and 4, which refuse the request before it has records.
func (self *Handler) Submit(ctx context.Context, conn *Connection, request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error) {
	started := self.now()
	if conn == nil {
		return protocol.Reason_REASON_INTERNAL, nil, ErrNoConnection
	}
	if request == nil {
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	op, err := opOf(request)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason := self.frontChecks(ctx, conn, op); reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}

	pass := &submitPass{conn: conn, groupId: request.GetGroupId(), deliveries: request.GetEpochKeys()}
	for _, record := range request.GetRecords() {
		pass.records = append(pass.records, &recordPass{projection: record})
	}
	for _, current := range self.submitStages() {
		refused := current.run(ctx, pass)
		if refused.reason == protocol.Reason_REASON_OK {
			continue
		}
		self.pad(started)
		if len(pass.records) == 0 {
			// nothing to align a result with, so the refusal has only the envelope to travel on
			return refused.reason, nil, nil
		}
		return protocol.Reason_REASON_OK, refuseBatch(pass, refused), nil
	}
	if pass.response == nil {
		// the last stage is the transaction and it always answers; a nil here is this package's
		// own defect and never a client's
		return protocol.Reason_REASON_INTERNAL, nil, ErrNoStore
	}
	if !everyResultAccepted(pass.response) {
		self.pad(started)
	}
	return protocol.Reason_REASON_OK, pass.response, nil
}

// §4.3.2 and §6.1's "CreateGroup, written out", under §5.1's carve-out.
//
// The carve-out is three deviations and no more: check 5 is skipped because the group is what
// this request creates, check 6 is skipped because no epoch key and no read key are installed
// yet, and check 7 verifies against `bootstrap_write_key` from the request itself. That last one
// is self-certification and it is protected by the 20/day per-`client_id` limit of §4.7 and by
// nothing else, which §4.3.2 says in as many words rather than leaving to be inferred — and
// which is check 4, one of the three this build does not run.
func (self *Handler) CreateGroup(ctx context.Context, conn *Connection, request *protocol.CreateGroupRequest) (protocol.Reason, *protocol.CreateGroupResponse, error) {
	started := self.now()
	if conn == nil {
		return protocol.Reason_REASON_INTERNAL, nil, ErrNoConnection
	}
	if request == nil {
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	op, err := opOf(request)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason := self.frontChecks(ctx, conn, op); reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}

	pass := &recordPass{projection: request.GetInitialCommit()}
	groupId := request.GetGroupId()
	reject := func() (protocol.Reason, *protocol.CreateGroupResponse, error) {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}

	// check 3, with the initial commit's own two rules folded in: §6.1 evaluates
	// `epoch == current_epoch + 1` as `epoch == 1`, because there is no message_group row and
	// therefore no current_epoch to compare against.
	if len(request.GetBootstrapWriteKey()) != store.EpochKeyBytes {
		return reject()
	}
	if reason := self.staticShape(groupId, pass); reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}
	if !pass.parsed.Header.IsCommit || pass.parsed.Header.Epoch != 0 {
		return reject()
	}
	// the founding attachment, under EITHER kind. It read `!= message.AttachmentEpoch` until
	// ruling 27, which is the founding-commit copy of the same defect the steady-state clause
	// has: an iff written on one of two epoch kinds. `opensEpochOf` answers the epoch the
	// attachment opens from whichever kind carries it, and false for every other kind, so the
	// two questions this line asks are one call
	opens, isEpochAttachment := opensEpochOf(pass.attachment)
	if !isEpochAttachment || opens != 1 {
		return reject()
	}
	// §4.3.2's `epoch_keys`, through the SAME alignment rule `Submit` runs — one record, one
	// singular delivery — so the kind-keyed presence rule of §5.4's acceptance window is stated
	// in one place and cannot come to differ between the two submit call sites. §4.3.2's one
	// record is always a commit, so the "no commit" arm of that rule is unreachable here and is
	// not restated
	deliveries := []*protocol.EpochKeyDelivery{request.GetEpochKeys()}
	keys, _, alignmentErr := epochKeyAlignment([]*recordPass{pass}, deliveries)
	if alignmentErr != nil {
		return reject()
	}
	if keys != nil {
		// check 3's digest clause. It runs here exactly as it runs on `Submit`, and under
		// §5.1's carve-out it is a comparison against a value `bootstrap_write_key` will
		// authenticate at check 7 by way of LP(H(server_attachment)) — so it inherits this
		// arm's self-certification and adds no new trust
		if err := checkEpochKeysDigest(groupId, pass.attachment, keys); err != nil {
			return reject()
		}
	}

	// check 7, against the key the request supplied. Checks 5 and 6 are the carve-out.
	if !message.VerifyWriteAuth(request.GetBootstrapWriteKey(), conn.ServerNonce, pass.parsed) {
		return reject()
	}
	// check 8
	if reason := self.bodyHash(pass); reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}
	if reason := self.recordKindIsBuilt(pass); reason != protocol.Reason_REASON_OK {
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}

	columns, err := columnsOf(pass)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	result, err := self.store.CreateGroup(ctx, &store.CreateGroupRequest{
		GroupId:           groupId,
		InitialCommit:     columns,
		BootstrapWriteKey: request.GetBootstrapWriteKey(),
		// ruling 33, and the second of the two submit call sites. Under kind `0x0005` the
		// founding commit's attachment has no keys and these are what epoch 1 opens with
		EpochKeys: deliveryOf(keys),
	})
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if !acceptance(result.Reason) {
		// §4.3.2: an existing group_id answers exactly what a bad MAC answers, and the creator
		// retries with a fresh one
		self.pad(started)
		return result.Reason, nil, nil
	}

	// §5.1's insert path, in its own words: "the creating instance inserts locally before
	// responding". Without it, create-a-group then reconnect then send fails REASON_REJECTED,
	// which §4.5 makes indistinguishable from a bad MAC — so the user sees "message failed"
	// with nothing diagnosable behind it and the operator's own counter looks at the other
	// direction. The Redis publish that tells the other instances is peer's and is not built.
	self.knownGroups.Insert(groupId)

	return result.Reason, &protocol.CreateGroupResponse{
		CurrentEpoch: result.CurrentEpoch,
		RecordId:     result.RecordId,
		Applied:      appliedOf(result.Applied),
	}, nil
}

// §5.1 checks 1, 2 and 4, in order, in front of every operation.
func (self *Handler) frontChecks(ctx context.Context, conn *Connection, op uint8) protocol.Reason {
	if reason := self.front.FrameWithinLimits(ctx, conn); reason != protocol.Reason_REASON_OK {
		return reason
	}
	if reason := self.front.ConnectionAuthenticated(ctx, conn); reason != protocol.Reason_REASON_OK {
		return reason
	}
	return self.front.WithinRateLimits(ctx, conn, op)
}

// ── §5.1 check 3 ─────────────────────────────────────────────────────────────────────────

// Check 3 over the whole submission: the batch's own shape first, then every record's.
func (self *Handler) checkStaticShape(ctx context.Context, pass *submitPass) refusal {
	if len(pass.groupId) != store.GroupIdBytes {
		return refuse(protocol.Reason_REASON_REJECTED, wholeSubmission)
	}
	if len(pass.records) == 0 {
		return refuse(protocol.Reason_REASON_REJECTED, wholeSubmission)
	}
	if self.maxRecordsPerSubmit < len(pass.records) {
		return refuse(protocol.Reason_REASON_OVERSIZE, wholeSubmission)
	}
	for index, record := range pass.records {
		if reason := self.staticShape(pass.groupId, record); reason != protocol.Reason_REASON_OK {
			return refuse(reason, index)
		}
	}
	// §4.3.3: a batch containing a commit contains exactly one record, because partial-failure
	// semantics during an epoch change would otherwise be ambiguous. It is asked of the parse
	// and not of the projection, like everything else the server acts on.
	commits := 0
	for _, record := range pass.records {
		if record.parsed.Header.IsCommit {
			commits++
		}
	}
	if commits != 0 && len(pass.records) != 1 {
		return refuse(protocol.Reason_REASON_REJECTED, wholeSubmission)
	}
	return self.checkEpochKeys(pass)
}

// Check 3's `0x0005` clauses over the whole submission: §4.3.3's alignment rule, then the
// digest the attachment carries against the keys the request carried beside it.
//
// IT RUNS INSIDE CHECK 3 AND NOT LATER, and §5.1's ordering argument is why. Everything here is
// CPU over values the request already carries — a length, a boolean check 3 has already
// verified against the parse, two widths and one SHA-256 — so it costs no database read, and
// §5.1 is explicit that nothing costing a read happens before something costing a hash. Putting
// the digest comparison at the transaction instead would let a party holding no `write_key`
// force a row lock with a commit whose keys do not match.
//
// THE REFUSAL IS §4.5's MERGED `REASON_REJECTED` AND THE CAUSE IS NOT ON THE WIRE. Which of the
// six clauses fired is a named error for this server's own tests and log; a client that could
// tell "your keys are missing" from "your keys do not match the digest" would hold an oracle
// over a value the MAC covers.
func (self *Handler) checkEpochKeys(pass *submitPass) refusal {
	keys, index, err := epochKeyAlignment(pass.records, pass.deliveries)
	if err != nil {
		pass.alignment = err
		return refuse(protocol.Reason_REASON_REJECTED, index)
	}
	pass.keys = keys
	if keys == nil {
		// no commit, or a kind `0x0001` commit whose keys are in its own attachment. There is
		// no digest to compare and §5.4's acceptance window says so
		return passed
	}
	if err := checkEpochKeysDigest(pass.groupId, pass.records[index].attachment, keys); err != nil {
		pass.alignment = err
		return refuse(protocol.Reason_REASON_REJECTED, index)
	}
	return passed
}

// Check 3 for one record: the parse, the shape rules the parse does not already hold, the
// attachment, and every projection field against the parse.
func (self *Handler) staticShape(groupId []byte, pass *recordPass) protocol.Reason {
	if pass.projection == nil {
		return protocol.Reason_REASON_REJECTED
	}
	parsed, err := message.ParseRecord(pass.projection.GetRecordBytes())
	if err != nil {
		// the parser already holds the format version, is_commit as a genuine boolean, the
		// retention class byte, the size bucket against the ladder, blob_id's presence in both
		// directions, and full consumption of the input
		return protocol.Reason_REASON_REJECTED
	}
	pass.parsed = parsed
	header := &parsed.Header

	// The record names the group it is authenticated for and the request names the group the row
	// goes in. §4.3.3's projection list does not carry group_id — it is a field of the request
	// rather than of Record — so nothing below compares them, and a record whose header names
	// another group would be stored under this one with a MAC that covers the other. The MAC
	// would fail check 7 under this group's key; this refuses it three checks earlier and for
	// the right reason.
	if !bytes.Equal(header.GroupId[:], groupId) {
		return protocol.Reason_REASON_REJECTED
	}

	// `ct_head` ≤ head cap, and a head at all: §3.2 makes the column NOT NULL and §6.3 hashes it
	// into the claim, so a record with no head has nothing for a later retry to be compared with.
	if len(parsed.CtHead) == 0 {
		return protocol.Reason_REASON_REJECTED
	}
	if self.maxCtHeadBytes < len(parsed.CtHead) {
		return protocol.Reason_REASON_OVERSIZE
	}

	// `octet_length(ct_body)` is EXACTLY `size_bucket_bytes[b] + 16`. An equality, not a range,
	// because §9.5 pads bodies into buckets and a body that is not exactly its rung leaks its
	// real length. message.ParseRecord is deliberately more permissive — it also parses the
	// records this server rebuilds with an erased body on the read path, where ct_body is absent
	// — so the submit-only half is enforced here, through the exported ladder rather than
	// through a length written down twice.
	if header.SizeBucket != message.SizeBucketBlob {
		want := message.SizeBucketCtBodyBytes(header.SizeBucket)
		if want < 0 || len(parsed.CtBody) != want {
			return protocol.Reason_REASON_REJECTED
		}
	}

	// `eph_window` is zero off the windowed classes and within one window of arrival on them.
	if reason := self.ephWindow(header); reason != protocol.Reason_REASON_OK {
		return reason
	}

	// `server_attachment` parses and is well-formed for its record kind. The widths, the alg_ids
	// and `expected_wrap_count > 0` are message.ParseServerAttachment's, which is the one place
	// they are written; what belongs to the server is the relation to the record beside it.
	attachment, err := parseServerAttachment(header.ServerAttachment)
	if err != nil {
		return protocol.Reason_REASON_REJECTED
	}
	pass.attachment = attachment

	// An epoch attachment of EITHER kind iff is_commit. The other half of check 3's rule —
	// `epoch == current_epoch + 1`, and an EpochComplete marker's `wrap_count` against the
	// epoch's `expected_wrap_count` — is a relation to state this layer has not read and could
	// not hold still if it had: both are re-read by §6.1 under the group row lock, which is the
	// only place the value is stable, and reading them here would put a database read in front
	// of the hash of check 7 for exactly the attacker §5.1's order is written against.
	//
	// THE DISJUNCTION IS LOAD-BEARING AND WAS NOT ALWAYS HERE. Written as
	// `(attachment.Kind == message.AttachmentEpoch) != header.IsCommit` this clause looks like
	// an iff and stops being one the moment a second epoch kind exists: a kind `0x0005`
	// attachment on a NON-commit record gives `false != false`, which passes. Spec B §5.1
	// check 3 now states the disjunction for the same reason, and [isEpochAttachmentKind] is
	// the one place this build answers the question.
	if isEpochAttachmentKind(attachment.Kind) != header.IsCommit {
		return protocol.Reason_REASON_REJECTED
	}

	// Every projection field against the parse (§4.3.3, §5.1 check 3).
	//
	// One comparison of the whole message rather than eleven comparisons of named fields. A
	// field list here would be a list to forget a field from: a twelfth projection added to
	// Record tomorrow would be a field the client populates, the server indexes and nothing
	// checks, which is the exact shape check 3 exists to refuse. Comparing the messages makes
	// the class the descriptor's — a new field is unset in what the parse implies, set in what
	// the client sent, and the equality fails until somebody teaches projectionOf about it.
	sent, isRecord := proto.Clone(pass.projection).(*protocol.Record)
	if !isRecord {
		return protocol.Reason_REASON_INTERNAL
	}
	sent.RecordBytes = nil
	// server-assigned, and §4.3.3 says it is ignored on submit; a client that populated it is
	// not making a claim the server has to refuse
	sent.RecordId = 0
	if !proto.Equal(projectionOf(parsed, attachment), sent) {
		return protocol.Reason_REASON_REJECTED
	}
	return protocol.Reason_REASON_OK
}

// Check 3's `eph_window` clause, which is also §7.1's ±1 refusal and Spec A requirement S19.
//
// WHICH CLASSES CARRY A WINDOW IS ASKED OF [message.EphBucketSeconds] RATHER THAN OF A BYTE RANGE
// WRITTEN OUT HERE. §5.1 check 3 and §3.2's CHECK both phrase the half on the WIRE BYTE, 17..21.
// MASTER §8 gives that byte as `0x10 | bucket`, so 17..21 is buckets 1..5 and EPH(0), at
// `0x10` = 16, is OUTSIDE it — which is exactly where MASTER §8's presence rule puts EPH(0), in
// the must-be-zero half with PERMANENT, DURABLE and MEDIA. EphBucketSeconds answers a POSITIVE
// for precisely buckets 1..5, ZERO for bucket 0 (the transient rung's true window, not a marker
// for the absence of one) and a NEGATIVE off the ladder — the three-answer distinction ruled on
// 2026-09-13 for this caller — so `0 < seconds` IS the wire range, arithmetically, with no second
// copy of the table here and with no chance of the class-phrased reading that is wrong by one
// class.
//
// The two refusals this owes:
//
//   - a nonzero window on PERMANENT, DURABLE, MEDIA or EPH(0)  → REASON_REJECTED
//   - a window on EPH(1..5) more than one from the arrival one  → REASON_REJECTED, either
//     direction
//
// The submitted value is inside the `write_auth` preimage (MASTER §9.2), so this is a check on a
// value the MAC covers rather than on a field anyone in the path may rewrite — which is what
// makes it a check worth making in a server that reads nothing else about a record.
func (self *Handler) ephWindow(header *message.RecordHeader) protocol.Reason {
	seconds := message.EphBucketSeconds(header.EphBucket)
	if header.RetentionClass != message.RetentionEph || seconds <= 0 {
		if header.EphWindow != 0 {
			return protocol.Reason_REASON_REJECTED
		}
		return protocol.Reason_REASON_OK
	}

	// §7.1: `arrival_window = floor(create_time_ms / (eph_bucket_seconds[b] × 1000))`. The stamp
	// is this handler's clock rather than the row's `create_time`, because check 3 runs before
	// there is a transaction to have one. They differ by what the remaining checks and the
	// transaction take, which is orders below the shortest bucket's 3600 seconds; what that
	// difference can do is straddle a boundary, and ±1 is what absorbs it — the same skew §7.1's
	// one-hour `grace` already absorbs, expressed in this field's unit.
	millis := self.now().UnixMilli()
	if millis < 0 {
		// the formula's origin is the unix epoch and a clock before it has no window for the
		// submitted one to be within one of. REASON_INTERNAL and not REASON_REJECTED: nothing the
		// client sent is wrong, and §4.5's merged refusal is a statement about a party that holds
		// no key
		return protocol.Reason_REASON_INTERNAL
	}
	arrival := uint64(millis) / (uint64(seconds) * 1000)
	// the distance, taken so that it cannot underflow: both sides are u64 and the submitted value
	// is a client's, so `arrival - header.EphWindow` on a window one ahead is 2^64-1 and passes
	// every bound anyone would write against it
	distance := arrival - header.EphWindow
	if arrival < header.EphWindow {
		distance = header.EphWindow - arrival
	}
	if 1 < distance {
		return protocol.Reason_REASON_REJECTED
	}
	return protocol.Reason_REASON_OK
}

// The projection §4.3.3 says a record's bytes imply: every server-indexed field, read out of the
// parse and out of nothing else.
//
// `record_bytes` and `record_id` are left unset on purpose. The first is what this is a
// projection of, and the second is server-assigned and never authenticated.
func projectionOf(parsed *message.Record, attachment *message.ServerAttachment) *protocol.Record {
	header := &parsed.Header
	// the join of the class tag and the eph bucket happens in exactly one place in the system,
	// and it is not this one; an error here is a header the parser would not have produced
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return nil
	}
	projection := &protocol.Record{
		SenderHandle:   bytes.Clone(header.SenderHandle[:]),
		Epoch:          header.Epoch,
		StreamIndex:    header.StreamIndex,
		IsCommit:       header.IsCommit,
		RetentionClass: uint32(retentionWire),
		SizeBucket:     uint32(header.SizeBucket),
		ExpireAtMs:     header.ExpireAt,
		BodyHash:       bytes.Clone(header.BodyHash[:]),
		BlobId:         bytes.Clone(header.BlobId),
	}
	if attachment != nil && attachment.Wrap != nil {
		projection.WrapTargetHandle = bytes.Clone(attachment.Wrap.WrapTargetHandle)
	}
	if attachment != nil && attachment.Recovery != nil {
		projection.RecoveryHandle = bytes.Clone(attachment.Recovery.RecoveryHandle)
	}
	return projection
}

// ── §5.1 check 5 ─────────────────────────────────────────────────────────────────────────

// The known-group filter. A hit is answered from memory with no database read at all, which is
// what keeps a party holding no `write_key` from forcing a row lock, an index write or a WAL byte
// for a group that does not exist.
//
// **Three answers, not two.** §4.5 merges every client-caused refusal into REASON_REJECTED, and a
// filter that could not reach its own source of truth has produced no client-caused refusal at
// all: answering REASON_REJECTED there would tell a member of a real group, in the one code the
// spec deliberately refuses to explain, that their group does not exist — for as long as the
// database was unreachable, and with nothing in any log to say why. REASON_INTERNAL is the honest
// answer, and it is the one a client retries.
func (self *Handler) checkKnownGroup(ctx context.Context, pass *submitPass) refusal {
	known, err := self.knownGroups.Contains(ctx, pass.groupId)
	if err != nil {
		return refuse(protocol.Reason_REASON_INTERNAL, wholeSubmission)
	}
	if !known {
		return refuse(protocol.Reason_REASON_REJECTED, wholeSubmission)
	}
	return passed
}

// ── §5.1 check 6 ─────────────────────────────────────────────────────────────────────────

// The epoch key lookup: one read of message_epoch per epoch named, for a group that check 5 has
// already said exists.
//
// The record's epoch selects the key, so the server never trials a set. §5.3 keeps the current
// epoch's write key and one briefly-retired predecessor, so a record at `current_epoch - 1`
// resolves and one older does not — and both the never-existed epoch and the tidied one answer
// the same ErrEpochKeyUnknown, which §5.1.1 requires and §4.5 merges into REASON_REJECTED.
//
// The in-process LRU §5.1 specifies is not here. It changes how often this reads and never what
// it answers, and a cache in front of a store that has no latency would be a cache nothing could
// hold to its invalidation rules. The per-submission memo below is not that cache: it is one
// lookup per distinct epoch in one batch, which is what "reads message_epoch once" means for a
// batch that names one epoch 256 times.
func (self *Handler) checkEpochKey(ctx context.Context, pass *submitPass) refusal {
	// Only a resolved key is memoed, and there is no negative entry beside it. A lookup that
	// fails refuses the submission on the spot, so no second record ever asks about an epoch
	// this loop has already failed on, and an entry nothing can read back is a comment that
	// reads like a mechanism.
	seen := map[uint64][]byte{}
	for index, record := range pass.records {
		epoch := record.parsed.Header.Epoch
		if key, found := seen[epoch]; found {
			record.writeKey = key
			continue
		}
		keys, err := self.store.EpochKeys(ctx, pass.groupId, epoch)
		if err != nil || keys.WriteKey == nil {
			// an epoch that never existed, one whose write key the 60-second tidy has taken, and
			// a group the filter was wrong about are one answer here on purpose
			return refuse(protocol.Reason_REASON_REJECTED, index)
		}
		seen[epoch] = keys.WriteKey
		record.writeKey = keys.WriteKey
	}
	return passed
}

// ── §5.1 check 7 ─────────────────────────────────────────────────────────────────────────

// The MAC, recomputed byte-for-byte by connect/message's own builder and compared in constant
// time — never by a local reimplementation. §12.1 A-1 gives the reason in one sentence: two
// independent implementations of a MAC preimage diverge, and when they do the symptom is "some
// clients cannot send", intermittently, with a byte-order difference nobody can see behind it.
//
// It verifies the parsed record, which is the whole record: the preimage covers LP(H(ct_head))
// and LP(H(server_attachment)), and neither is a projection field, so a verifier handed the
// request's projection could not build the preimage at all.
func (self *Handler) checkWriteAuth(ctx context.Context, pass *submitPass) refusal {
	for index, record := range pass.records {
		if !message.VerifyWriteAuth(record.writeKey, pass.conn.ServerNonce, record.parsed) {
			return refuse(protocol.Reason_REASON_REJECTED, index)
		}
	}
	return passed
}

// ── §5.1 check 8 ─────────────────────────────────────────────────────────────────────────

// `body_hash == SHA-256(ct_body)` for inline bodies.
//
// It is an integrity check for recipients' benefit and not an authenticity check — the uploader
// and the record author are the same party (§5.2) — and it is here because the server already
// holds every byte, so the hash is free, while without it a truncated body is discovered only by
// a recipient after it has pulled the record over the mesh.
func (self *Handler) checkBodyHash(ctx context.Context, pass *submitPass) refusal {
	for index, record := range pass.records {
		if reason := self.bodyHash(record); reason != protocol.Reason_REASON_OK {
			return refuse(reason, index)
		}
	}
	return passed
}

func (self *Handler) bodyHash(pass *recordPass) protocol.Reason {
	if pass.parsed.Header.SizeBucket == message.SizeBucketBlob {
		// §5.1 check 8's other half: for a blob-backed record the same comparison is made at
		// bind time against message_blob.content_hash (§8.3), against bytes this process has not
		// been handed. [Handler.NotBuilt] carries the gap and runTransaction refuses the record.
		return protocol.Reason_REASON_OK
	}
	if blobd.ContentHash(pass.parsed.CtBody) != pass.parsed.Header.BodyHash {
		return protocol.Reason_REASON_REJECTED
	}
	return protocol.Reason_REASON_OK
}

// ── §5.1 check 9: only now, the transaction ──────────────────────────────────────────────

// §6.1, through the store, which owns every step of it. Nothing above this line has read the
// database except check 6's single key lookup, and nothing above this line has written anything
// at all.
func (self *Handler) runTransaction(ctx context.Context, pass *submitPass) refusal {
	records := make([]*store.Record, 0, len(pass.records))
	for index, record := range pass.records {
		if reason := self.recordKindIsBuilt(record); reason != protocol.Reason_REASON_OK {
			return refuse(reason, index)
		}
		columns, err := columnsOf(record)
		if err != nil {
			return refuse(protocol.Reason_REASON_INTERNAL, index)
		}
		records = append(records, columns)
	}
	response, err := self.store.Submit(ctx, &store.SubmitRequest{
		GroupId: pass.groupId,
		Records: records,
		// ruling 33: the keys the store installs come from HERE, the request, and never from
		// `records` — under kind `0x0005` no record in that slice has a key field at all.
		// [epochKeyAlignment] reduced §4.3.3's aligned list to this one delivery under named
		// refusals, so the store cannot be handed a misaligned one
		EpochKeys: deliveryOf(pass.keys),
	})
	if err != nil {
		// every refusal a client can cause is a Reason on a result; an error out of the store is
		// something this layer handed it that no client could have produced
		return refuse(protocol.Reason_REASON_INTERNAL, wholeSubmission)
	}
	pass.response = &protocol.SubmitResponse{Results: make([]*protocol.SubmitResult, 0, len(response.Results))}
	for _, result := range response.Results {
		pass.response.Results = append(pass.response.Results, resultOf(pass.groupId, result))
	}
	return passed
}

// The two record kinds this build refuses rather than half-serves, both named in
// [Handler.NotBuilt]: an EPH(0) transient, which §7.6 says is never persisted and which there is
// no channel to fan out to, and a blob-backed record, whose §8.3 bind check has no blob table to
// run against.
//
// REASON_INTERNAL and not REASON_REJECTED: the client did nothing wrong, and §4.5's merged
// refusal is a statement about a party that holds no key. Answering it here would tell a member
// in good standing that its group might not exist.
func (self *Handler) recordKindIsBuilt(pass *recordPass) protocol.Reason {
	header := &pass.parsed.Header
	if header.RetentionClass == message.RetentionEph && header.EphBucket == 0 {
		return protocol.Reason_REASON_INTERNAL
	}
	if header.SizeBucket == message.SizeBucketBlob {
		return protocol.Reason_REASON_INTERNAL
	}
	return protocol.Reason_REASON_OK
}

// The record decomposed into §3.2's columns, out of the parse and never out of the projection.
//
// This is the other half of §4.3.3's rule. Check 3 proves the projection agrees with the parse;
// this makes the agreement moot by never reading the projection again — including for the three
// things that are not projections at all, `ct_head`, `ct_body` and `server_attachment`, which
// are what a column set built from the request would silently be missing.
func columnsOf(pass *recordPass) (*store.Record, error) {
	header := &pass.parsed.Header
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return nil, err
	}
	return &store.Record{
		SenderHandle:     bytes.Clone(header.SenderHandle[:]),
		Epoch:            header.Epoch,
		StreamIndex:      header.StreamIndex,
		IsCommit:         header.IsCommit,
		RetentionClass:   retentionWire,
		EphWindow:        header.EphWindow,
		SizeBucket:       uint8(header.SizeBucket),
		ExpireAtMs:       header.ExpireAt,
		BodyHash:         bytes.Clone(header.BodyHash[:]),
		CtHead:           bytes.Clone(pass.parsed.CtHead),
		CtBody:           bytes.Clone(pass.parsed.CtBody),
		BlobId:           bytes.Clone(header.BlobId),
		ServerAttachment: bytes.Clone(header.ServerAttachment),
		Attachment:       attachmentOf(pass.attachment),
	}, nil
}

// connect/message's parsed attachment as the store's columns, which is a rename and a widening
// and nothing else.
func attachmentOf(attachment *message.ServerAttachment) *store.Attachment {
	if attachment == nil {
		return nil
	}
	switch attachment.Kind {
	case message.AttachmentEpoch:
		return &store.Attachment{
			Kind: store.AttachmentEpoch,
			Epoch: &store.EpochAttachment{
				Epoch:             attachment.Epoch.Epoch,
				WriteKey:          bytes.Clone(attachment.Epoch.WriteKey),
				ReadKey:           bytes.Clone(attachment.Epoch.ReadKey),
				AlgId:             uint32(attachment.Epoch.AlgId),
				MediaTtlSeconds:   attachment.Epoch.MediaTtlSeconds,
				DurableTtlSeconds: attachment.Epoch.DurableTtlSeconds,
				GroupContextHash:  bytes.Clone(attachment.Epoch.GroupContextHash),
				ExpectedWrapCount: attachment.Epoch.ExpectedWrapCount,
			},
		}
	case message.AttachmentWrap:
		// store.WrapTag carries a LeafIndex and connect/message's WrapTag carries an Epoch, so
		// there is no leaf index in an authenticated record to put in it. Nothing in the store
		// branches on the field; §6.1's snapshot-versus-device-wrap distinction is carried by
		// the record's retention class and by which epoch's fan-out it is in. Left zero rather
		// than invented, and named in the task's report.
		return &store.Attachment{
			Kind: store.AttachmentWrap,
			Wrap: &store.WrapTag{TargetHandle: bytes.Clone(attachment.Wrap.WrapTargetHandle)},
		}
	case message.AttachmentRecovery:
		return &store.Attachment{
			Kind: store.AttachmentRecovery,
			Recovery: &store.RecoveryTag{
				Handle:    bytes.Clone(attachment.Recovery.RecoveryHandle),
				VerifyPub: bytes.Clone(attachment.Recovery.RecoveryVerifyPub),
				AlgId:     uint32(attachment.Recovery.AlgId),
			},
		}
	case message.AttachmentComplete:
		return &store.Attachment{
			Kind: store.AttachmentEpochComplete,
			EpochComplete: &store.EpochCompleteTag{
				Epoch:     attachment.Complete.Epoch,
				WrapCount: attachment.Complete.WrapCount,
			},
		}
	case message.AttachmentEpochDigest:
		// ruling 27's sixth kind. Six public fields and a digest, and NO KEY — there is none in
		// this structure to copy. The store's own [store.openingOf] is where the two keys come
		// from, and under this kind they come from the request
		return &store.Attachment{
			Kind: store.AttachmentEpochDigest,
			EpochDigest: &store.EpochDigestAttachment{
				Epoch:             attachment.EpochDigest.Epoch,
				AlgId:             uint32(attachment.EpochDigest.AlgId),
				MediaTtlSeconds:   attachment.EpochDigest.MediaTtlSeconds,
				DurableTtlSeconds: attachment.EpochDigest.DurableTtlSeconds,
				GroupContextHash:  bytes.Clone(attachment.EpochDigest.GroupContextHash),
				ExpectedWrapCount: attachment.EpochDigest.ExpectedWrapCount,
				EpochKeysDigest:   bytes.Clone(attachment.EpochDigest.EpochKeysDigest),
			},
		}
	}
	return nil
}

// ── the answers ──────────────────────────────────────────────────────────────────────────

// §6.1 step (3b): a rejection anywhere rolls the whole batch back with zero rows written and a
// reason on every SubmitResult.
//
// `current_epoch` is left unset on every one of them, and that is the §4.5 merge rather than an
// omission. §4.3.3 sets it on every result so that a stale client resynchronises in one round
// trip, but every refusal this function builds is a refusal from in front of check 7 — no
// `write_auth` has verified — and a current_epoch there would tell a party holding no key that
// the group exists, which is the oracle the merge closes. Past check 7 the store fills it in,
// and by then the caller has proved it holds a group secret.
func refuseBatch(pass *submitPass, refused refusal) *protocol.SubmitResponse {
	response := &protocol.SubmitResponse{Results: make([]*protocol.SubmitResult, 0, len(pass.records))}
	for index := range pass.records {
		reason := protocol.Reason_REASON_REJECTED
		if refused.index == wholeSubmission || refused.index == index {
			reason = refused.reason
		}
		response.Results = append(response.Results, &protocol.SubmitResult{Reason: reason})
	}
	return response
}

// The store's result on the wire, including §6.2's winner.
//
// `record_id` is copied only onto an acceptance, and that is a second enforcement of a rule the
// store already enforces in `resultsOf`. It is deliberate, and the reason it is safe to hold in
// two places is that it is BLANKET: §6.1 step (3b) makes "a refusal allocates nothing" normative
// and no reason code in §4.5 carries a record_id, so there is no judgement here to drift from
// the store's. [store.Store] is an exported interface, `resultsOf` is not, and a mock or a
// future implementation that stamped an id onto a refusal reaches the wire through this function
// and nothing else — the id being the group's own allocation counter, handed to a party
// REASON_REJECTED tells nothing apart from a bad MAC.
//
// `current_epoch` and `winning_commit` are deliberately NOT filtered the same way, and the
// difference is the point. §4.5 gives REASON_EPOCH_STALE a current_epoch and §6.2 gives any
// rejected commit its winning_commit, so whether a refusal owes either one is a JUDGEMENT about
// what the caller has already proved it holds — the store makes it, past check 7, and a second
// copy of a judgement is exactly how two halves of one rule drift apart. What arrives here
// unset stays unset: `api.refuseBatch` builds every refusal from in front of check 7 and fills
// in neither.
func resultOf(groupId []byte, result *store.SubmitResult) *protocol.SubmitResult {
	answer := &protocol.SubmitResult{
		Reason:       result.Reason,
		CurrentEpoch: result.CurrentEpoch,
		Applied:      appliedOf(result.Applied),
	}
	if store.Accepted(result.Reason) {
		answer.RecordId = result.RecordId
	}
	if result.WinningCommit != nil {
		// §6.2 binds the loser protocol to ANY rejection of a commit submission, so the winner
		// travels whenever the store attached one. A record that cannot be re-encoded is a
		// corrupted stored row rather than anything about this submission, and dropping the
		// winner is better than refusing a refusal that is otherwise correct.
		if winner, err := rebuildRecord(groupId, result.WinningCommit, false); err == nil {
			answer.WinningCommit = winner
		}
	}
	return answer
}

func appliedOf(applied *store.RetentionApplied) *protocol.RetentionApplied {
	if applied == nil {
		return nil
	}
	return &protocol.RetentionApplied{
		MediaTtlSeconds:            applied.MediaTtlSeconds,
		DurableTtlSeconds:          applied.DurableTtlSeconds,
		MediaClampedDown:           applied.MediaClampedDown,
		DurableFlooredUp:           applied.DurableFlooredUp,
		DurableClampedDown:         applied.DurableClampedDown,
		DurableDefaulted:           applied.DurableDefaulted,
		RequestedMediaTtlSeconds:   applied.RequestedMediaTtlSeconds,
		RequestedDurableTtlSeconds: applied.RequestedDurableTtlSeconds,
	}
}

// The two answers §6.1 gives a record that landed, for the reason store.go gives: a caller that
// tested REASON_OK alone would read §7.3's clamp — an acceptance carrying a notice, with a record
// id and an opened epoch behind it — as a rejection.
func acceptance(reason protocol.Reason) bool {
	return reason == protocol.Reason_REASON_OK || reason == protocol.Reason_REASON_RETENTION_CLAMPED
}

func everyResultAccepted(response *protocol.SubmitResponse) bool {
	for _, result := range response.GetResults() {
		if !acceptance(result.GetReason()) {
			return false
		}
	}
	return true
}
