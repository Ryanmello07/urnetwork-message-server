package store

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/connect/protocol"
)

// The exact-length identifier shapes of §3.1, which are `bytea` columns with a `CHECK` in
// §3.2. They are checked here as well as there because a store that hands Postgres a
// fifteen-byte sender_handle learns about it as a constraint violation in the middle of a
// transaction, and because the memory implementation has no constraints of its own at all.
const (
	GroupIdBytes          = 32
	SenderHandleBytes     = 16
	BodyHashBytes         = 32
	HeadHashBytes         = 32
	RecoveryHandleBytes   = 16
	WrapTargetHandleBytes = 16
	BlobIdBytes           = 32
	GroupContextHashBytes = 32
	VerifyPubBytes        = 32

	// §5.1 check 3 and §5.3: the epoch attachment carries both keys raw, exactly 32 bytes
	// each. What §3.2 stores is the 61-byte wrap of one, which is this package's business on
	// the way to the column and never the caller's.
	EpochKeyBytes = 32
)

// The first record id a group ever assigns. §3.2 makes the column `DEFAULT 1` and says why:
// Spec A §5.1 defines `since_record_id = 0` as the "from the beginning" exclusive cursor, so
// a group that allocated 0 would make its own founding commit permanently unfetchable by
// every client that did not create it. Gapless and 1-based are one property, not two.
const firstRecordId uint64 = 1

// The retention-class wire bytes of §3.1. The class and the bucket are joined and split in
// connect/message and nowhere else; what reaches this package is the byte.
const (
	ClassPermanent uint8 = 0x00
	ClassDurable   uint8 = 0x01
	ClassMedia     uint8 = 0x02
	ClassEphBase   uint8 = 0x10
	ClassEphMax    uint8 = 0x15

	// The top of §3.2's `eph_window bigint`, which is SIGNED, as an unsigned bound. It is here
	// rather than as a `math.MaxInt64` at each site so that neither implementation file has to
	// import math to state §3.2's `CHECK (0 <= eph_window)` — and so that the one place the
	// column's width is written down is the one place the wire field's width meets it.
	EphWindowMax uint64 = 1<<63 - 1
)

// eph bucket to seconds, §3.1. Bucket 0 is the transient that is never persisted, so it has no
// lifetime here at all; §7.6 fans it out through Redis without opening a transaction, and
// [ErrTransientRecord] is what this package answers if one arrives anyway.
var ephBucketSeconds = [6]uint32{0, 3600, 28800, 86400, 604800, 2419200}

// The `WrapTag.leaf_index` that means the ratchet-tree snapshot rather than a device wrap
// (§6.1, epoch publication step 2).
const SnapshotLeafIndex uint32 = 0xFFFFFFFF

// The two `durable_ttl_seconds` sentinels of §6.1 step (6). They are distinct on purpose: one
// sentinel could not express both "the group set nothing" and "the group asked for
// indefinite", and with one sentinel a stock server stored "forever" for every group that
// never opened a retention screen.
const (
	DurableUnset      uint32 = 0
	DurableIndefinite uint32 = 0xFFFFFFFF
)

// Refusals of a submission are [protocol.Reason] codes and travel in a [SubmitResult]; §4.5 is
// the vocabulary and the API layer has nothing to translate. These errors are the other
// class: a caller of this package that handed it something no client could have caused. They
// are never a client's answer.
var (
	// §6.1 step (1): zero rows, from a group that does not exist or from one that is closed.
	// One error for both, because §4.5 refuses to distinguish them — a submit path that did
	// would be an oracle for group existence to a party holding no write_key.
	ErrGroupUnavailable = errors.New("store: group unknown or closed")

	// §5.1 check 6 and §5.1.1: no epoch key retained for that (group, epoch), whether because
	// the epoch never existed, because the 60-second tidy took the write key, or because the
	// read key aged out of the 90-day window. One error for all of them, for §5.1.1's reason.
	ErrEpochKeyUnknown = errors.New("store: no key retained for that epoch")

	// A record whose class is EPH(0). §7.6 is normative that it never touches disk, so it has
	// no record id, no claim and no row; the API layer publishes it and drops it. Reaching
	// this package with one is an API-layer defect, not a client refusal.
	ErrTransientRecord = errors.New("store: an EPH(0) transient is never persisted")

	// §3.1's exact-length shapes, and §3.2's CHECKs on the class and bucket bytes.
	ErrIdentifierShape = errors.New("store: an identifier is not the exact length §3.1 gives it")
	ErrRetentionClass  = errors.New("store: not a retention-class wire byte of §3.1")
	ErrSizeBucket      = errors.New("store: size_bucket is outside 0..5")

	// §3.2's two CHECKs on `eph_window`, one sentinel each for the reason ErrInlineOrBlob has
	// its own: an operator meeting "size_bucket is outside 0..5" for a window fault is sent to
	// the wrong field of the wrong record.
	//
	// The class CHECK is `eph_window = 0 OR (17 <= retention_class AND retention_class <= 21)`,
	// and it is stated on the WIRE BYTE rather than on the class. That is not a paraphrase of
	// "an EPH class": MASTER §8 gives the byte as `0x10 | bucket`, so EPH(0) is `0x10` = 16,
	// which is OUTSIDE 17..21 — the CHECK therefore puts the transient rung in the must-be-zero
	// half beside PERMANENT, DURABLE and MEDIA, which is exactly where MASTER §8's presence rule
	// puts it. A class-phrased reading would be wrong by one class.
	ErrEphWindowClass = errors.New("store: eph_window is nonzero on a class whose §3.1 wire byte is not 17..21")

	// The range CHECK is `0 <= eph_window`, and it is not vacuous just because the Go field is
	// unsigned: the wire field is a `u64` and §3.2's column is a `bigint`, which is SIGNED. A
	// window above math.MaxInt64 has no representation in that column, and an implementation
	// that converted it anyway would offer Postgres a negative the CHECK refuses while a store
	// with no constraints of its own accepted it — the two implementations disagreeing on one
	// input, which is the whole thing [RunContract] exists to make impossible.
	ErrEphWindowRange = errors.New("store: eph_window does not fit §3.2's signed bigint column")

	// §3.2: a record's body is inline or it is a blob, never both. It has its own sentinel
	// because it used to answer ErrSizeBucket, and "size_bucket is outside 0..5" is an
	// operator log line that sends the reader to the wrong field of the wrong record.
	ErrInlineOrBlob = errors.New("store: a record carries an inline body or a blob_id, never both")

	// §4.3.3: a batch carrying a commit carries exactly one record, because partial-failure
	// semantics during an epoch change would otherwise be ambiguous.
	ErrCommitBatch = errors.New("store: a batch containing a commit contains exactly one record")

	// An empty batch, which has no result to align positionally with anything.
	ErrEmptyBatch = errors.New("store: a submission carries at least one record")
)

// A record decomposed into the columns of §3.2's `message_record`, plus the parsed projection
// of its `server_attachment`.
//
// The parsing is not done here. §4.3.3 makes `record_bytes` authoritative and connect/message
// its only parser and encoder; the API layer parses, checks every projection field against the
// parse, verifies write_auth, and hands the columns over. This package stores columns and
// re-encodes on the way out, which is why there is no `record_bytes` field: keeping one would
// give the store a second copy of the truth to disagree with.
type Record struct {
	SenderHandle   []byte
	Epoch          uint64
	StreamIndex    uint64
	IsCommit       bool
	RetentionClass uint8

	// §3.2's `eph_window bigint NOT NULL DEFAULT 0`: `t`, the time-slice of this record's own
	// `K_eph[n][b][t]` (MASTER §8), projected out of the plaintext header field like every other
	// column in this struct. The authoritative copy is inside `record_bytes` and inside the
	// `write_auth` preimage; this one is what §7.1's ±1 refusal reads and what §4.3.4 re-encodes.
	//
	// Zero on every class but `EPH(1..5)`. The constraint is §3.2's and is repeated here rather
	// than left to §5.1 alone so that a second writer cannot land a nonzero window on a DURABLE
	// row and have §7.1 read it.
	EphWindow uint64

	SizeBucket uint8
	ExpireAtMs uint64
	BodyHash   []byte
	CtHead     []byte
	CtBody     []byte
	BlobId     []byte

	// The authenticated attachment bytes as submitted, and the projection of them the API
	// layer verified against message.ParseServerAttachment. §3.2 keeps both: the bytes are
	// what was authenticated and the projections are what the server acts on, and §5.1 check
	// 3 re-verifies one against the other before either is believed.
	ServerAttachment []byte
	Attachment       *Attachment

	// Server-assigned, and never authenticated. Zero on the way in.
	RecordId uint64

	// §3.2's `prune_after`, which §7.1 computes in Go from the class and the group's policy at
	// the moment the row is written, and which §7.2's sweep acts on. Server-assigned like
	// RecordId, nil on the way in, and nil on the way out for the two classes that never prune:
	// PERMANENT, and DURABLE under an indefinite policy.
	//
	// It is on the way out because otherwise it is not on the way out anywhere: it is a column
	// of §3.2 that no interface method returned, so §7.1's whole arithmetic was unobservable
	// and could be replaced by a nil with every test still green. What the API layer does with
	// it is not send it — §4.3.3 makes record_bytes authoritative and this is not in it.
	PruneAfter *time.Time
}

// Which of §5.4's server-visible attachments a record carries. A record carries at most one.
type AttachmentKind uint8

const (
	AttachmentNone AttachmentKind = iota
	AttachmentEpoch
	AttachmentWrap
	AttachmentRecovery
	AttachmentEpochComplete
)

// The parsed `server_attachment` of §5.4, as the API layer read it.
type Attachment struct {
	Kind          AttachmentKind
	Epoch         *EpochAttachment
	Wrap          *WrapTag
	Recovery      *RecoveryTag
	EpochComplete *EpochCompleteTag
}

// A commit's `EpochAttachment`: the keys and the policy for the epoch this commit opens.
//
// Well-formedness is checked before the CAS and never after (§6.1, normative). An accepted
// commit carrying a malformed attachment opens an epoch with no verifiable write key and
// bricks the group permanently — no member can submit again and there is no epoch to commit
// from — which is the single most damaging thing a buggy client can do here.
type EpochAttachment struct {
	Epoch             uint64
	WriteKey          []byte
	ReadKey           []byte
	AlgId             uint32
	MediaTtlSeconds   uint32
	DurableTtlSeconds uint32
	GroupContextHash  []byte
	ExpectedWrapCount uint32
}

// A device wrap or, at [SnapshotLeafIndex], the ratchet-tree snapshot (§6.1, epoch publication).
type WrapTag struct {
	TargetHandle []byte
	LeafIndex    uint32
}

// A recovery wrap, indexed by handle for the seed-only restore of §4.3.7. The server keeps the
// first `verify_pub` it sees for a handle within one group and refuses a later differing one.
//
// LATER includes later in the same batch. §4.3.7 refuses "any later differing
// recovery_verify_pub for the same recovery_handle in the same group" and §6.1 step (6c) runs
// per record, so a submission carrying two records that claim one handle under two pubs is
// refused whole — the first record of it is the first sight, and the second is a rebinding. It
// is written here rather than only in the contract because the two implementations answered it
// differently until it was: one gated on the group's stored pins, read once for the batch, and
// so could not see the claim the batch itself was making.
type RecoveryTag struct {
	Handle    []byte
	VerifyPub []byte
	AlgId     uint32
}

// The marker that closes an epoch's wrap fan-out (§6.1, epoch publication step 3).
type EpochCompleteTag struct {
	Epoch     uint64
	WrapCount uint32
}

// The three advertised limits of §7.3 and the defaults around them, as one value, so that the
// retention arithmetic of §6.1 step (6) has a single input.
type Limits struct {
	MediaTtlMaxSeconds         uint32 // 0 = no cap
	MediaTtlDefaultSeconds     uint32
	DurableTtlMaxSeconds       uint32 // 0 = no maximum, §7.3
	DurableTtlDefaultSeconds   uint32
	DurableRetentionMinSeconds uint32 // 0 = no minimum, §7.3
}

// §7.3's defaults, verbatim.
func DefaultLimits() Limits {
	return Limits{
		MediaTtlMaxSeconds:         2592000,  // 30 days
		MediaTtlDefaultSeconds:     2592000,  // 30 days
		DurableTtlMaxSeconds:       0,        // no maximum
		DurableTtlDefaultSeconds:   31536000, // one year, not forever
		DurableRetentionMinSeconds: 0,        // no minimum
	}
}

// What the server actually stored, and which of §7.3's three cases produced it.
//
// The three cases are kept distinguishable because they are three different sentences to the
// user: this server's default is a year; you asked for forever and got a year; you asked for
// two years and got a year. A client that could only see the number would have to pick one of
// them and would be wrong twice.
type RetentionApplied struct {
	MediaTtlSeconds   uint32
	DurableTtlSeconds uint32 // 0xFFFFFFFF is indefinite; 0 never appears in an applied value

	MediaClampedDown   bool
	DurableFlooredUp   bool
	DurableClampedDown bool
	DurableDefaulted   bool

	RequestedMediaTtlSeconds   uint32
	RequestedDurableTtlSeconds uint32
}

// Whether §7.3's warn-and-proceed fired, in any of its three directions. It is derived from
// the flags rather than set beside them, because a fourth direction added to [Limits.apply]
// tomorrow would otherwise be a clamp the client is never told about.
//
// `DurableDefaulted` is deliberately not one of them: §7.3 is explicit that a group which sent
// the unset sentinel asked for nothing, so nothing was refused, and it is REASON_OK.
func (self *RetentionApplied) clamped() bool {
	return self.MediaClampedDown || self.DurableFlooredUp || self.DurableClampedDown
}

// §7.3's answer to a commit whose policy was clamped down or floored up: the commit is
// ACCEPTED — it has a record id and it opened its epoch — and the reason names the clamp so
// the client can render §12.2 C-2's one-time notice against the effective value. Refusing is
// not an option in any of the three cases, because an operator config change would otherwise
// stop a group committing at all.
func acceptanceReason(applied *RetentionApplied) protocol.Reason {
	if applied != nil && applied.clamped() {
		return protocol.Reason_REASON_RETENTION_CLAMPED
	}
	return protocol.Reason_REASON_OK
}

// The two answers §6.1 gives a record that landed. Everything else in §4.5 is a refusal, and a
// caller that tested for REASON_OK alone would read §7.3's clamp — an acceptance carrying a
// notice, with a record id and an opened epoch behind it — as a rejected commit.
func accepted(reason protocol.Reason) bool {
	return reason == protocol.Reason_REASON_OK || reason == protocol.Reason_REASON_RETENTION_CLAMPED
}

// [accepted], for the wire boundary, which is outside this package.
//
// §6.1's answer to "did this record land" has one implementation and the API layer holds the
// protocol message to it. A second copy of the list is how the two drift apart, and the way a
// copy of THIS list goes wrong is already known: written against REASON_OK alone it erases the
// record id of every commit §7.3 clamped, because a clamp is an acceptance carrying a notice.
func Accepted(reason protocol.Reason) bool {
	return accepted(reason)
}

// The group state §6.1 step (1) reads under the row lock, and the same values §4.3.10 serves
// without one.
type GroupState struct {
	CurrentEpoch      uint64
	NextRecordId      uint64
	MediaTtlSeconds   uint32
	DurableTtlSeconds *uint32 // nil is indefinite, the NULL of §3.2
	PolicyVersion     uint32
	EpochComplete     bool
	GroupContextHash  []byte
}

// One epoch's key custody, §5.3. The write key is the current epoch's plus one briefly-retired
// predecessor and nothing older; the read key is retained for `read_key_window_seconds` from
// its install. The two lifetimes are different on purpose and are separate fields so a change
// to one cannot silently move the other.
type EpochKeys struct {
	Epoch          uint64
	WriteKey       []byte // nil once the tidy loop of §7.4 has taken it
	ReadKey        []byte // nil once the 90-day window has closed
	ReadKeyInstall time.Time
	AlgId          uint32
	OpenedByRecord uint64
	AcceptTime     time.Time
	RetireTime     time.Time // zero while this is the current epoch
}

// §4.3.2 and §6.1's "CreateGroup, written out".
type CreateGroupRequest struct {
	GroupId       []byte
	InitialCommit *Record

	// write_key[0], exactly 32 bytes, used only to verify the initial commit and installed
	// against epoch 0. §5.1's carve-out: this is self-certification, protected by the 20/day
	// per-client_id rate limit and by nothing else, and that is stated rather than implied.
	BootstrapWriteKey []byte
}

type CreateGroupResult struct {
	Reason       protocol.Reason
	CurrentEpoch uint64 // always 1 on success
	RecordId     uint64 // always 1 on success
	Applied      *RetentionApplied
}

// §4.3.3. The records are positionally aligned with [SubmitResponse.Results].
type SubmitRequest struct {
	GroupId []byte
	Records []*Record
}

type SubmitResponse struct {
	Results []*SubmitResult
}

// §4.3.3's SubmitResult. `CurrentEpoch` is always set, so a stale client resynchronises in one
// round trip, and `WinningCommit` is set on any rejection of a submission whose record has
// is_commit = 1 — not on REASON_COMMIT_LOST alone, because §6.2's loser protocol binds to the
// rejection and binding it to one code left its hard MUST NOT on pq_secret reuse unreachable.
type SubmitResult struct {
	Reason        protocol.Reason
	RecordId      uint64
	CurrentEpoch  uint64
	WinningCommit *Record
	Applied       *RetentionApplied
}

// §4.3.4 and the read path of §5.1.1. No transaction is opened and no row is allocated.
type FetchRequest struct {
	GroupId       []byte
	SinceRecordId uint64 // exclusive; 0 is the well-defined "from the beginning" cursor
	Limit         uint32
	HeadsOnly     bool
	ClassMask     uint32 // bit per retention-class wire byte; 0 = all

	// THE EPOCH CEILING (ledger item 246, ruled 2026-09-22). A row is served only when
	// `record.Epoch <= ReadEpoch`, and that is the whole of the rule.
	//
	// It is the same `read_epoch` §4.3.8 puts inside `canonical_request_bytes` and therefore
	// inside the `req_auth` MAC, and §5.1.1 check 6 has already resolved exactly one read key
	// under it before a store ever sees this field. So the ceiling is a value the CLIENT
	// authenticated and the SERVER verified, and the record's epoch is a §3.2 column this
	// server wrote itself — I6 is clean, because neither side of the comparison is a claim
	// the server is taking somebody's word for.
	//
	// WHY IT IS REQUIRED AND NOT OPTIONAL, and why 0 cannot mean "no ceiling" the way
	// `ClassMask`'s 0 means "every class": epoch 0 is a real epoch — the founding commit sits
	// at it — so there is no spare value left to spell "unbounded" with. That is the good
	// outcome rather than a constraint worked around. Ledger item 244's refutation of fix F1
	// is that it repairs a SERVE PATH, which a later arm can forget; a required field on this
	// request cannot be forgotten by anything that builds it.
	//
	// WHICH ARMS THAT IS, CORRECTED. 810f80b's version of this paragraph named `Subscribe`,
	// `RecoveryFetch` and `WrapFetch` as the paths that must not forget the ceiling. TWO OF
	// THE THREE MUST NOT TAKE IT AT ALL, and Spec B §5.1.1 now says so by name:
	//
	//   - `Subscribe` inherits it. A subscription is a streaming Fetch (§4.3.5).
	//   - `WrapFetch` MUST NOT take it. §4.3.9's request carries its own `epoch`, "independent
	//     of `read_epoch`… which names the wrap wanted", and the ordinary case is a member at
	//     epoch n fetching the wrap that gets it to n+1 — a record ABOVE its own ceiling by
	//     construction. `wrap_target_handle` is what bounds that arm.
	//   - `RecoveryFetch` has no `read_epoch` to take. §4.3.7 authorizes it by an Ed25519
	//     recovery proof and a seed-only restorer holds no read key at all.
	//
	// WHAT IT BUYS. MASTER §9.2 and Spec B §5.3 used to promise that a member removed at epoch
	// n keeps metadata access "until epoch n's read key ages out, and no longer" — a window
	// resting on a 90-day sweep that does not exist (`sweep/doc.go` holds no code). The ceiling
	// delivers the strictly tighter "nothing above epoch n, ever", on the day it ships and with
	// no sweep. Ruling 30 is LANDED as of 2026-09-22: both documents now publish the ceiling and
	// keep the 90 days as the storage rule it always was.
	ReadEpoch uint64
}

// §4.3.4's answer, and the two fields of it the ceiling above turns from arithmetic into a
// decision — which ledger item 246 names "the one real design question, and it must be answered
// in the same change".
//
// # HighWaterRecordId IS CEILING-RELATIVE
//
// It is the largest `record_id` in the group whose own epoch is at or below the request's
// `ReadEpoch`, and 0 when the group holds none. It was `next_record_id - 1`, the group's
// absolute maximum, and leaving it there would have broken the client on its FIRST catch-up
// page rather than in some corner: `sdk/urmessage`'s page walk raises `ErrFetchOmitted`
// whenever a page it has been told is COMPLETE stops below the high water that same response
// names. A member three epochs behind is served everything up to its ceiling — complete,
// correct, nothing withheld — and an absolute high water would have had it accuse an honest
// server on every page of the walk. This field is the reader's ONLY omission detector, so a
// value it has to learn to ignore is worse than no value at all: it teaches the one check that
// can catch a withholding server to be disbelieved.
//
// It is NOT narrowed by `ClassMask` or by `SinceRecordId`. The ceiling is the only thing that
// moves it, because the ceiling is the only one of the three that is about what this reader may
// see rather than about what this page was asked to carry. Spec B §4.3.4 used to call it "the
// group's max at read time", which this made false; the specification now says "the group's max
// AT OR BELOW read_epoch" and §5.1.1 carries the rule normatively.
//
// # Complete IS FALSE FOR THE LIMIT AND NOT FOR THE CEILING
//
// A page the ceiling ends is COMPLETE. "Complete" means "this is all of what you asked for",
// and what a reader asked for is bounded by the epoch it authenticated. It does not mean "this
// is everything the group holds", which is the group's business and not this request's.
//
// The alternative — `complete = false` whenever rows above the ceiling exist — was considered
// and is wrong, in a way that is measurable rather than aesthetic. That flag is how the same
// page walk decides to ASK AGAIN from the cursor it already has. A reader that has ingested the
// commit at its ceiling and not yet moved its epoch would re-ask, be served nothing (its cursor
// is already past everything at or below the ceiling), and fail on `ErrFetchNoProgress` — a
// hard error raised at a server that did exactly what it was asked. It would fire for every
// OBSERVER that cannot follow a commit and for every client polling at an epoch it has
// finished.
//
// # THE CEILING CANNOT HIDE THAT THERE IS MORE, WHICH IS WHY NEITHER FIELD HAS TO SAY SO
//
// A record above epoch n exists only because some commit opened n+1, and a commit is SEALED AT
// the epoch it closes — its own `epoch` column is n, it is below the ceiling, and it is served.
// Walking to the ceiling therefore hands the reader, in that same page, the commit that tells
// it to move. That is the whole argument, and it leans on nothing else.
//
// IT DELIBERATELY DOES NOT LEAN ON §4.3.10's GroupStatus — which would answer `current_epoch`
// and the group's absolute high water under this same read key — BECAUSE THIS SERVER DOES NOT
// SERVE IT. Measured and not assumed, because an argument resting on it would be resting on
// nothing:
//
//	grep -rhno 'GroupStatusRequest\|GroupStatusResponse\|FetchRequest' --include=*.go .
//
// answers 101 `FetchRequest` — the positive control carried in the same query — against ONE
// `GroupStatusRequest` and ONE `GroupStatusResponse`, and both of those are the two words of
// this comment. The day that arm lands it becomes a second, independent way for a reader to
// learn it is behind. It is not one today, and Spec B §4.3.10 now carries ledger item 248 for
// what that arm owes the ceiling when it does.
//
// # THE COST, STATED — AND IT IS NOT WHAT THIS COMMENT FIRST SAID
//
// A server may claim a shorter ceiling than the request named and withhold everything above it.
// Two things this paragraph got wrong on 810f80b, both measured:
//
// FIRST, THE SIZE. It said "the tail of the reader's OWN EPOCH". It is the whole tail above
// whatever ceiling the server claims — every record at every epoch above it. Measured through
// §5.1.1's read path: a server clamping every reader to epoch 1, asked at `read_epoch = 3` with
// a valid `req_auth` under `read_key[3]`, answered a `FetchResponse` that `proto.Equal`s the
// honest `read_epoch = 1` answer. Seven of twelve records — TWO ENTIRE EPOCHS — withheld, with
// no error and no hole, and the receiver's omission predicate (`reached < high_water`) answering
// "nothing omitted", where the absolute high water it replaced answered "omitted".
//
// SECOND, THE MITIGATION, which was circular. It said the withholding "becomes a hole the moment
// the reader advances to n+1". It cannot: the commit that would advance that reader is sealed at
// an epoch ABOVE the claimed ceiling, so it is inside the tail being withheld. A reader the
// withholding is holding below the ceiling never advances, by construction.
//
// What is actually true: Spec B §4.3.4 already concedes the SHAPE — "a server can withhold a
// contiguous tail, and §12.3's honest limit stands" — so this is not a new class of
// undetectable. What makes the ceiling's instance of it attributable is §4.3.4's
// `FetchAttestation`, and `read_epoch` is INSIDE ITS PREIMAGE as of 2026-09-22 for exactly this
// reason: without it, the honest short answer and the withholding one are the same bytes under
// the same signature. The signature itself is unbuilt ([api.Handler.NotBuilt]).
type FetchResult struct {
	Records           []*Record
	NextRecordId      uint64
	HighWaterRecordId uint64
	Complete          bool
}

// The store of spec B §2.1, as an interface.
//
// The methods are §6.1's transaction and the paths that read what it wrote, not its steps. The
// steps are deliberately not separate calls: their order is the whole of §6.1 — the
// idempotency probe before every gate and before any allocation, the message_commit check
// before the epoch comparison, the allocation after all of them — and an interface that
// exposed them individually would move that order into the caller, where no implementation of
// this interface owes it and no contract test could hold anyone to it.
//
// Every method is safe for concurrent use. That is not a convenience: §6.1's interesting cases
// are all racy ones, and an implementation that needed external serialisation would be an
// implementation whose contract could not be stated.
type Store interface {
	// §4.3.2, atomically. A group_id that already exists is REASON_REJECTED, deliberately not
	// distinguished from a bad MAC (§4.5).
	CreateGroup(ctx context.Context, request *CreateGroupRequest) (*CreateGroupResult, error)

	// §6.1, steps (0) through (7), in that order, for the whole batch. Step (3b) is the batch
	// half of it: every per-record check runs for every record before a single id is
	// allocated, so a rejection anywhere rolls the whole batch back with zero rows written.
	//
	// A refusal is a [protocol.Reason] on a [SubmitResult] and never an error. An error means
	// the caller handed this package something no client could have produced.
	//
	// The id allocator is IN the transaction, and that rules out a Postgres SEQUENCE. §6.1
	// step (3b) makes "a refusal allocates nothing" normative, and `nextval()` is
	// non-transactional: it does not roll back, so every refusal in §6.1 would leave a
	// permanent hole in a sequence-allocated id space and break the gapless property §4.3.4
	// sells to clients and §12.2 C-4 tells them to treat a hole in as a fault. The pgx
	// implementation therefore allocates with an `UPDATE message_group SET next_record_id =
	// next_record_id + k RETURNING`, under the same row lock step (1) already holds. This is
	// written here rather than only asserted in the contract suite, because a constraint a
	// second implementation learns from a red test is a constraint it learns too late.
	Submit(ctx context.Context, request *SubmitRequest) (*SubmitResponse, error)

	// Step (1)'s read without step (1)'s lock: §4.3.10's group status. Answers
	// [ErrGroupUnavailable] for a group that is unknown and for one that is closed, which are
	// the same answer for the reason §4.5 gives.
	GroupState(ctx context.Context, groupId []byte) (*GroupState, error)

	// §5.1 check 6 on the submit path and §5.1.1's read-key lookup on the read path. Answers
	// [ErrEpochKeyUnknown] for an epoch that never existed and for one whose keys have been
	// discarded, identically (§5.1.1).
	EpochKeys(ctx context.Context, groupId []byte, epoch uint64) (*EpochKeys, error)

	// §4.3.4 over §5.1.1's read path.
	Fetch(ctx context.Context, request *FetchRequest) (*FetchResult, error)

	// §7.5. A closed group answers [ErrGroupUnavailable] everywhere afterwards, exactly as an
	// unknown one does.
	CloseGroup(ctx context.Context, groupId []byte) error
}

// The retention arithmetic of §6.1 step (6) and §7.3, as a function of the attachment and the
// limits and of nothing else.
//
// Refusing a commit is not an option in any of the three cases: an operator config change
// would otherwise stop a group committing at all. The policy the group put in its
// transcript-covered attachment is never rewritten, so a group that ever moves to a server
// with different limits gets its original policy back with no migration.
func (self Limits) apply(attachment *EpochAttachment) (uint32, *uint32, *RetentionApplied) {
	applied := &RetentionApplied{
		RequestedMediaTtlSeconds:   attachment.MediaTtlSeconds,
		RequestedDurableTtlSeconds: attachment.DurableTtlSeconds,
	}

	// media. §6.1's LEAST(attachment.media_ttl_seconds, $server_media_cap) has no branch for a
	// zero request, and a zero would land in a column §3.2 CHECKs as 0 < media_ttl_seconds. It
	// is read as the same "the group set nothing" §7.3 gives media a default for.
	media := attachment.MediaTtlSeconds
	if media == 0 {
		media = self.MediaTtlDefaultSeconds
	}
	requestedMedia := media
	if self.MediaTtlMaxSeconds != 0 && self.MediaTtlMaxSeconds < media {
		media = self.MediaTtlMaxSeconds
	}
	applied.MediaClampedDown = media < requestedMedia
	applied.MediaTtlSeconds = media

	// text, bounded on both sides, and the two sentinels resolved here rather than refused at
	// §5.1 check 3, where both are legal values.
	var durable *uint32
	switch attachment.DurableTtlSeconds {
	case DurableUnset:
		applied.DurableDefaulted = true
		switch {
		case self.DurableTtlDefaultSeconds == 0 && self.DurableTtlMaxSeconds == 0:
			durable = nil
		case self.DurableTtlDefaultSeconds == 0:
			durable = ptr(self.DurableTtlMaxSeconds)
		case self.DurableTtlMaxSeconds == 0:
			durable = ptr(self.DurableTtlDefaultSeconds)
		default:
			durable = ptr(min(self.DurableTtlDefaultSeconds, self.DurableTtlMaxSeconds))
		}
	case DurableIndefinite:
		if self.DurableTtlMaxSeconds == 0 {
			durable = nil
		} else {
			// a server advertising a cap and silently honouring "keep forever" would be lying
			// in its own capability document
			durable = ptr(self.DurableTtlMaxSeconds)
			applied.DurableClampedDown = true
		}
	default:
		value := attachment.DurableTtlSeconds
		if value < self.DurableRetentionMinSeconds {
			value = self.DurableRetentionMinSeconds
			applied.DurableFlooredUp = true
		}
		if self.DurableTtlMaxSeconds != 0 && self.DurableTtlMaxSeconds < value {
			value = self.DurableTtlMaxSeconds
			applied.DurableClampedDown = true
		}
		durable = ptr(value)
	}

	if durable == nil {
		applied.DurableTtlSeconds = DurableIndefinite
	} else {
		applied.DurableTtlSeconds = *durable
	}
	return media, durable, applied
}

func ptr[T any](value T) *T {
	return &value
}

// ── the batch machinery both implementations share ───────────────────────────────────────
//
// It sits beside the interface rather than inside either implementation, because every
// statement below is about what a [SubmitResponse] may contain and none of it is about how a
// store is built. Both implementations reach all three, and a third one will.

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

// The refusal of §6.1 step (1), which says nothing at all beyond the code.
//
// A group that is unknown and one that is closed reach this together (§4.5, §7.5), and neither
// gets a current_epoch or a winning_commit — both would be answers about a group the caller has
// just been told nothing about, and the difference between the two fields being filled and empty
// is itself the existence oracle §4.5 spends a paragraph closing.
//
// The WHOLE result is replaced rather than those two fields left unset, and that is the
// difference between this and the version it replaces. The field that leaked here was
// `current_epoch` and the field that leaked before it was `record_id`; both were fixed by naming
// the field, and the class is not a field — it is everything a result can carry. A result built
// from the zero value cannot acquire a fifth field tomorrow that this path forgets to clear.
//
// A record step (0) already answered keeps its REASON_OK and its id. It names a row that landed
// in an earlier transaction, against a group that was open when it did, and no later close
// unlands it.
func refuseUnavailable(batch []*pending) *SubmitResponse {
	for _, current := range batch {
		if current.probe == probeIdentical {
			continue
		}
		*current.result = SubmitResult{Reason: protocol.Reason_REASON_REJECTED}
	}
	return &SubmitResponse{Results: resultsOf(batch)}
}

// Every [SubmitResponse] either implementation returns is built here, which is why the
// invariant that a REFUSAL NAMES NO RECORD ID is enforced here rather than at each of the
// three places that refuse one.
//
// §6.1 step (3b) makes "a refusal allocates nothing" normative, and the two halves of that are
// not the same statement: the rollback undoes the row, and nothing undoes the id already
// stamped onto the result struct beside it. [PgxStore.write] stamps `result.RecordId` on every
// record as it writes it, and §6.1 step (6c) can refuse the batch after an earlier record of it
// was stamped — so the offender's neighbours went out carrying ids naming rows the rollback had
// just removed, and `api.resultOf` copied record_id onto the protocol message unconditionally.
// An id on a refusal is the group's own allocation counter handed to a party whose record was
// rejected, and REASON_REJECTED is what §4.5 gives an unknown group and a bad MAC alike: it is
// the enumeration answer §5.1 withholds, arriving by the one field nobody was watching.
//
// `api.resultOf` now applies the same condition again at the wire, and that duplication is
// deliberate: [Store] is exported and this function is not, so a mock or a third implementation
// crosses that boundary and never this one. It is safe to hold in two places only because it is
// blanket — no code in §4.5 carries a record_id on a refusal — which `current_epoch` and
// `winning_commit` are not, and which is why neither of those is copied there.
//
// The condition is [accepted] rather than a list of refusing codes, for the reason Rule 5 gives
// and for one more: §7.3's REASON_RETENTION_CLAMPED is an ACCEPTANCE carrying a notice, with a
// record id and an opened epoch behind it, and a check written against REASON_OK alone would
// erase the id of every clamped commit in the project.
func resultsOf(batch []*pending) []*SubmitResult {
	results := make([]*SubmitResult, len(batch))
	for index, current := range batch {
		if !accepted(current.result.Reason) {
			current.result.RecordId = 0
		}
		results[index] = current.result
	}
	return results
}
