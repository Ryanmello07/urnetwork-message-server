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
	SizeBucket     uint8
	ExpireAtMs     uint64
	BodyHash       []byte
	CtHead         []byte
	CtBody         []byte
	BlobId         []byte

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
}

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
