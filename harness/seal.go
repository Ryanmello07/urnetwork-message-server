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
