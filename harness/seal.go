package harness

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/blobd"
	"github.com/urnetwork/message-server/store"
)

// What a sender can get wrong about a record before there is a server to refuse it.
var (
	ErrNoWriteKey  = errors.New("harness: §5.4's write_auth is computed under the epoch's write key, and there is none here")
	ErrGroupWidth  = errors.New("harness: a record names its group in a fixed-width header field, and this group_id is not that width")
	ErrSenderWidth = errors.New("harness: a record names its sender in a fixed-width header field, and this sender_handle is not that width")
	ErrNoRung      = errors.New("harness: §9.5 pads a body to exactly the rung its size bucket names, and this body does not fit that rung")
	// MASTER §8's window has the unix epoch as its origin, so a reading before it has no window
	// at all. Refused rather than clamped to zero: zero is the answer the presence rule gives an
	// unwindowed class, and a clock fault that produced it would be indistinguishable from one.
	ErrEphWindowSentAt = errors.New("harness: a sent_at before the unix epoch has no eph window")
)

// One record to seal, in the terms a sender chooses them.
//
// `Head` and `Body` are opaque octets and stay opaque: nothing here encrypts them, the server
// cannot read them, and the MLS key schedule that would produce real content keys is plan p4 and
// is absent rather than stubbed. The body is *padded* to its rung, which is §9.5 and is not
// encryption — it is what keeps the rung from leaking the message's real length.
type Sealed struct {
	// §3.1's identifiers, at their own widths.
	GroupId []byte
	Sender  []byte

	Epoch       uint64
	StreamIndex uint64
	IsCommit    bool

	Class     message.RetentionClass
	EphBucket uint8
	Bucket    message.SizeBucket

	// MASTER §8's `t`: the time-slice of this record's own `K_eph[n][b][t]`, plaintext and on the
	// wire. ALWAYS ENCODED, and zero on PERMANENT, DURABLE, MEDIA and EPH(0) — the presence rule,
	// which §5.1 check 3 and §3.2's CHECK both state as "the wire byte is 17..21" and which puts
	// EPH(0), at 16, in the must-be-zero half.
	//
	// It is a field of this struct rather than something computed inside Seal because the sender
	// computes it ONCE, off the same clock reading it puts in `sent_at` — a reading this package
	// does not have — and because a test that cannot submit a window the server should refuse is
	// a test that cannot reach §7.1 at all. [EphWindowAt] is the value a conforming sender puts
	// here.
	EphWindow uint64

	// §5.1's advisory upper bound, Unix milliseconds. Zero is unset.
	ExpireAt uint64

	Head []byte
	Body []byte

	// §5.11's one server-visible structured field, nil for an ordinary record.
	Attachment *message.ServerAttachment

	// The epoch's write key, which is what §5.1 check 7 verifies the MAC under.
	WriteKey []byte

	// The `server_nonce` to compute `write_auth` over. Nil takes the one this connection's Hello
	// issued, which is what a client following spec A §5.7 does. It is settable because "a
	// record sealed against a nonce the server did not issue is refused" is a property of the
	// whole stack that a test has to be able to reach, and the only way to reach it is to seal
	// against a different one on purpose.
	Nonce []byte
}

// The whole of what a sender does, in spec A §5.2's construction order: the body is padded to its
// rung, `body_hash` is taken over it, the header is completed, and only then is there a preimage
// to MAC.
//
// The answer is §4.3.3's shape: `record_bytes` and beside it the projection fields a client
// populates. The projection is built here rather than taken from the server's own builder,
// because §5.1 check 3 compares the two and a check whose two sides come from one function is a
// check that cannot fail.
func (self *Client) Seal(spec Sealed) (*protocol.Record, error) {
	if len(spec.WriteKey) == 0 {
		return nil, ErrNoWriteKey
	}
	if len(spec.GroupId) != store.GroupIdBytes {
		return nil, fmt.Errorf("%w: %d octets, want %d", ErrGroupWidth, len(spec.GroupId), store.GroupIdBytes)
	}
	if len(spec.Sender) != store.SenderHandleBytes {
		return nil, fmt.Errorf("%w: %d octets, want %d", ErrSenderWidth, len(spec.Sender), store.SenderHandleBytes)
	}
	nonce := spec.Nonce
	if nonce == nil {
		nonce = self.Nonce()
	}
	if len(nonce) == 0 {
		return nil, ErrNoNonce
	}

	attachmentBytes, err := message.EncodeServerAttachment(spec.Attachment)
	if err != nil {
		return nil, err
	}
	body, err := padToRung(spec.Bucket, spec.Body)
	if err != nil {
		return nil, err
	}

	header := message.RecordHeader{
		Epoch:            spec.Epoch,
		StreamIndex:      spec.StreamIndex,
		IsCommit:         spec.IsCommit,
		RetentionClass:   spec.Class,
		EphBucket:        spec.EphBucket,
		EphWindow:        spec.EphWindow,
		SizeBucket:       spec.Bucket,
		ExpireAt:         spec.ExpireAt,
		BodyHash:         blobd.ContentHash(body),
		ServerAttachment: attachmentBytes,
	}
	copy(header.GroupId[:], spec.GroupId)
	copy(header.SenderHandle[:], spec.Sender)

	record := &message.Record{Header: header, CtHead: spec.Head, CtBody: body}
	record.WriteAuth = message.ComputeWriteAuth(spec.WriteKey, nonce, &header, spec.Head, attachmentBytes)
	recordBytes, err := message.EncodeRecord(record)
	if err != nil {
		return nil, err
	}

	projection, err := projectionOf(&header, spec.Attachment)
	if err != nil {
		return nil, err
	}
	projection.RecordBytes = recordBytes
	return projection, nil
}

// §9.5's padding: a body is exactly its rung's ciphertext length, and that length comes from the
// exported ladder rather than from a number written here.
//
// The blob rung has no inline body at all, so there is nothing to pad to and the answer is nil —
// §8.3 binds that body against an object rather than carrying it.
func padToRung(bucket message.SizeBucket, body []byte) ([]byte, error) {
	want := message.SizeBucketCtBodyBytes(bucket)
	if want < 0 {
		if len(body) != 0 {
			return nil, fmt.Errorf("%w: size bucket %d carries no inline body and %d octets were given", ErrNoRung, bucket, len(body))
		}
		return nil, nil
	}
	if want < len(body) {
		return nil, fmt.Errorf("%w: %d octets do not fit rung %d, which holds %d", ErrNoRung, len(body), bucket, want)
	}
	padded := make([]byte, want)
	copy(padded, body)
	for index := len(body); index < len(padded); index++ {
		padded[index] = byte(index * 31)
	}
	return padded, nil
}

// §4.3.3's projection fields, as a client populates them.
//
// The one thing not written out here is the join of the retention class and the eph bucket. That
// happens in exactly one place in the system, [message.RetentionClassWire], and a second copy of
// its table in a harness would be the divergence §12.1 A-1 is written against.
func projectionOf(header *message.RecordHeader, attachment *message.ServerAttachment) (*protocol.Record, error) {
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return nil, err
	}
	projection := &protocol.Record{
		SenderHandle:   append([]byte{}, header.SenderHandle[:]...),
		Epoch:          header.Epoch,
		StreamIndex:    header.StreamIndex,
		IsCommit:       header.IsCommit,
		RetentionClass: uint32(retentionWire),
		SizeBucket:     uint32(header.SizeBucket),
		ExpireAtMs:     header.ExpireAt,
		BodyHash:       append([]byte{}, header.BodyHash[:]...),
		BlobId:         append([]byte{}, header.BlobId...),
	}
	if attachment != nil && attachment.Wrap != nil {
		projection.WrapTargetHandle = append([]byte{}, attachment.Wrap.WrapTargetHandle...)
	}
	if attachment != nil && attachment.Recovery != nil {
		projection.RecoveryHandle = append([]byte{}, attachment.Recovery.RecoveryHandle...)
	}
	return projection, nil
}

// MASTER §8's `eph_window`, as a SENDER computes it: `floor(sent_at_ms / (eph_bucket_seconds[b]
// × 1000))`, origin the unix epoch, off the same wall-clock reading the sender puts in `sent_at`.
//
// It answers ZERO for every class that carries no window, and it reaches that answer by ARITHMETIC
// rather than by a branch on the class: [message.EphBucketSeconds] is zero for bucket 0 and
// negative off the ladder, and both are answered here as a window of zero. §5.1 check 3 and §3.2's
// CHECK phrase the windowed half as the wire byte 17..21, which — since MASTER §8 gives the byte as
// `0x10 | bucket` — is buckets 1..5 and excludes EPH(0) at 16. A caller sealing PERMANENT, DURABLE
// or MEDIA passes bucket 0 and gets the zero the presence rule requires.
//
// WHY THIS IS WRITTEN HERE AND NOT LINKED. `connect/messagegroup` publishes `EphWindowAt` with this
// arithmetic for the real sender, and Spec B §2.2 does not allow this module to import that package
// — §12.1's published surface for the server is `connect/message` and `connect/protocol` and
// nothing else. This is therefore a SECOND SITE of one formula by construction of the dependency
// rule, and the divergence risk is real and filed rather than absorbed.
//
// `sentAtMs` is a reading and not a source: a harness that read a clock in here would be a harness
// that could not seal the record §7.1 is supposed to refuse.
func EphWindowAt(bucket uint8, sentAtMs int64) (uint64, error) {
	if sentAtMs < 0 {
		return 0, fmt.Errorf("%w: %d is before the unix epoch, which is the window's origin", ErrEphWindowSentAt, sentAtMs)
	}
	seconds := message.EphBucketSeconds(bucket)
	if seconds <= 0 {
		return 0, nil
	}
	return uint64(sentAtMs) / (uint64(seconds) * 1000), nil
}
