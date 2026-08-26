package api

import (
	"bytes"
	"context"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
	"google.golang.org/protobuf/proto"
)

// One read request as it moves down §5.1.1's checks.
type fetchPass struct {
	conn    *Connection
	request *protocol.FetchRequest

	// §4.3.8's op byte, read out of the descriptor rather than written down, because it is a
	// MAC input.
	op uint8

	// §5.1.1's check 6: the key named by (group_id, read_epoch), and never one of a set.
	readKey []byte

	response *protocol.FetchResponse
}

// One numbered check of §5.1 on the read path of §5.1.1.
//
// The numbers are §5.1's own: checks 1, 2, 4 and 5 apply unchanged, check 6 becomes the read-key
// lookup on (group_id, read_epoch), and the req_auth MAC replaces check 7. Check 8 is a body
// hash on a body nobody submitted here, and check 9 is a transaction §5.1.1 forbids outright —
// "no transaction is opened and no row is allocated on the read path" — so neither is in this
// slice, and TestTheReadPathOpensNoTransaction is what holds the second half of that to more
// than a comment.
type readStage struct {
	number int
	name   string
	run    func(ctx context.Context, pass *fetchPass) protocol.Reason
}

func (self *Handler) fetchStages() []readStage {
	return []readStage{
		{number: 3, name: "static shape of the request's own fields", run: self.checkFetchShape},
		{number: 5, name: "the known-group filter, with no database read", run: self.checkFetchKnownGroup},
		{number: 6, name: "the read-key lookup on (group_id, read_epoch)", run: self.checkReadKey},
		{number: 7, name: "req_auth", run: self.checkRequestAuth},
	}
}

// §4.3.4 over §5.1.1's read path.
//
// Every refusal is the same non-specific REASON_REJECTED with the same padded latency as the
// submit path, including the one for an epoch whose read key has aged out of the ninety-day
// window: the client learns it is outside the window from GroupStatus, which is itself
// authorized, and never from a distinguishable refusal.
func (self *Handler) Fetch(ctx context.Context, conn *Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
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

	pass := &fetchPass{conn: conn, request: request, op: op}
	for _, current := range self.fetchStages() {
		if reason := current.run(ctx, pass); reason != protocol.Reason_REASON_OK {
			self.pad(started)
			return reason, nil, nil
		}
	}

	result, err := self.store.Fetch(ctx, &store.FetchRequest{
		GroupId:       request.GetGroupId(),
		SinceRecordId: request.GetSinceRecordId(),
		Limit:         self.fetchLimit(request.GetLimit()),
		HeadsOnly:     request.GetHeadsOnly(),
		ClassMask:     request.GetClassMask(),
	})
	if err != nil {
		// the filter said the group exists and the read key resolved under it, so a store that
		// now says otherwise is answering about a group that was closed between the two — and
		// §7.5 makes a closed group answer exactly what an unknown one does
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}

	response := &protocol.FetchResponse{
		NextRecordId:      result.NextRecordId,
		HighWaterRecordId: result.HighWaterRecordId,
		Complete:          result.Complete,
	}
	for _, record := range result.Records {
		rebuilt, err := rebuildRecord(request.GetGroupId(), record, request.GetHeadsOnly())
		if err != nil {
			// a stored row that will not re-encode is this server's own corruption, and serving
			// the rest of the page around it would hide it behind a hole a client is told to
			// treat as a withheld record
			return protocol.Reason_REASON_INTERNAL, nil, err
		}
		response.Records = append(response.Records, rebuilt)
	}
	// §4.3.4's FetchAttestation is absent, not empty: it is an Ed25519 signature by the fleet
	// key over nine response fields, and this process holds no fleet key. [Handler.NotBuilt]
	// carries the gap; `Capabilities.attestation_supported` is how a client is told.
	return protocol.Reason_REASON_OK, response, nil
}

// §4.3.1: a fetch is bounded by `max_records_per_fetch`, and a request that asks for more, or
// asks for nothing in particular, gets the advertised bound rather than the group.
func (self *Handler) fetchLimit(requested uint32) uint32 {
	if requested == 0 || uint32(self.maxRecordsPerFetch) < requested {
		return uint32(self.maxRecordsPerFetch)
	}
	return requested
}

// §5.1.1 does not restate check 3 for the read path and §5.1.2 does restate it for the
// rendezvous one, in the same words: a static shape check on the operation's own fields. An
// identifier of the wrong width has to be refused somewhere, and the alternative is a store that
// answers it with an error two layers below the client.
func (self *Handler) checkFetchShape(ctx context.Context, pass *fetchPass) protocol.Reason {
	if len(pass.request.GetGroupId()) != store.GroupIdBytes {
		return protocol.Reason_REASON_REJECTED
	}
	if len(pass.request.GetReqAuth()) == 0 {
		// §4.3.8 makes it REQUIRED on this arm. An absent authenticator is refused here rather
		// than by the constant-time comparison below, because the length of a tag is public and
		// answering on it early leaks nothing.
		return protocol.Reason_REASON_REJECTED
	}
	return protocol.Reason_REASON_OK
}

// Check 5, unchanged from the submit path: an unknown group is refused with no database read.
func (self *Handler) checkFetchKnownGroup(ctx context.Context, pass *fetchPass) protocol.Reason {
	if !self.knownGroups.Contains(pass.request.GetGroupId()) {
		return protocol.Reason_REASON_REJECTED
	}
	return protocol.Reason_REASON_OK
}

// Check 6 on the read path: a read-key lookup keyed on (group_id, read_epoch).
//
// The epoch is named by the request and is inside the MAC, so the server selects exactly one key
// and never trials a set. A lookup that finds no retained key for that epoch — because the epoch
// never existed, or because its read key aged out of the ninety-day window of §5.3 — fails
// identically, which is §5.1.1 in its own words.
func (self *Handler) checkReadKey(ctx context.Context, pass *fetchPass) protocol.Reason {
	keys, err := self.store.EpochKeys(ctx, pass.request.GetGroupId(), pass.request.GetReadEpoch())
	if err != nil || keys.ReadKey == nil {
		return protocol.Reason_REASON_REJECTED
	}
	pass.readKey = keys.ReadKey
	return protocol.Reason_REASON_OK
}

// Check 7 on the read path: §4.3.8's req_auth, recomputed by connect/message and compared in
// constant time.
//
// `canonical_request_bytes` is the deterministically-marshaled request body with its own
// `req_auth` field set to zero length — so `read_epoch` is inside the bytes and inside the MAC,
// which is what makes the key selection above an authenticated choice rather than a hint.
func (self *Handler) checkRequestAuth(ctx context.Context, pass *fetchPass) protocol.Reason {
	canonical, err := canonicalRequestBytes(pass.request)
	if err != nil {
		return protocol.Reason_REASON_REJECTED
	}
	if !message.VerifyRequestAuth(pass.readKey, pass.conn.ServerNonce, pass.op, canonical, pass.request.GetReqAuth()) {
		return protocol.Reason_REASON_REJECTED
	}
	return protocol.Reason_REASON_OK
}

// §4.3.8's `canonical_request_bytes`: the deterministically-marshaled request body with its own
// `req_auth` field set to zero length.
//
// The field is cleared by the name §4.3.8 gives it, looked up in the message's own descriptor,
// so this one function serves all five arms that carry an authenticator and a sixth added later
// needs no edit here. Clearing and zero length are the same bytes on the wire: proto3 emits
// neither an absent nor an empty `bytes` field.
func canonicalRequestBytes(request proto.Message) ([]byte, error) {
	clone := proto.Clone(request)
	reflected := clone.ProtoReflect()
	field := reflected.Descriptor().Fields().ByName("req_auth")
	if field == nil {
		return nil, ErrNoOpForBody
	}
	reflected.Clear(field)
	return proto.MarshalOptions{Deterministic: true}.Marshal(clone)
}

// §2.4 and §4.3.3's read half: the server rebuilds `record_bytes` by calling EncodeRecord over
// the stored columns, with `ct_body` nil when the body has been erased or when `heads_only` was
// set, and sets `record_id`.
//
// `write_auth` is zero, and it is zero by being left alone rather than by a branch: the stored
// columns cannot reproduce it — it is a MAC over the submitting connection's `server_nonce`,
// which no other party holds and which is gone with that connection — and no verifier for it
// exists, because by I5 record authenticity is MLS's and is checked at the client.
func rebuildRecord(groupId []byte, record *store.Record, headsOnly bool) (*protocol.Record, error) {
	class, ephBucket, err := message.RetentionClassOf(record.RetentionClass)
	if err != nil {
		return nil, err
	}
	rebuilt := &message.Record{
		Header: message.RecordHeader{
			Epoch:            record.Epoch,
			StreamIndex:      record.StreamIndex,
			IsCommit:         record.IsCommit,
			RetentionClass:   class,
			EphBucket:        ephBucket,
			SizeBucket:       message.SizeBucket(record.SizeBucket),
			ExpireAt:         record.ExpireAtMs,
			BlobId:           bytes.Clone(record.BlobId),
			ServerAttachment: bytes.Clone(record.ServerAttachment),
		},
		CtHead: bytes.Clone(record.CtHead),
		CtBody: bytes.Clone(record.CtBody),
	}
	if len(groupId) != store.GroupIdBytes || len(record.SenderHandle) != store.SenderHandleBytes ||
		len(record.BodyHash) != store.BodyHashBytes {
		// §3.1's widths are a CHECK on every one of these columns, so a row that reaches here
		// with another width is a row Postgres would not hold; copying it into a fixed array
		// would silently zero-pad it into a different record
		return nil, store.ErrIdentifierShape
	}
	copy(rebuilt.Header.GroupId[:], groupId)
	copy(rebuilt.Header.SenderHandle[:], record.SenderHandle)
	copy(rebuilt.Header.BodyHash[:], record.BodyHash)
	if headsOnly {
		// the store already drops the body for a heads_only read, and an erased body is already
		// nil. This is the same rule stated where the encoder is called, so that a store which
		// forgot it cannot put a body on the wire through this path
		rebuilt.CtBody = nil
	}

	recordBytes, err := message.EncodeRecord(rebuilt)
	if err != nil {
		return nil, err
	}
	attachment, err := message.ParseServerAttachment(rebuilt.Header.ServerAttachment)
	if err != nil {
		return nil, err
	}
	// the same projection the submit path verifies the client's against, out of the same
	// function: the fields a client reads back are the fields the server checked, by construction
	projection := projectionOf(rebuilt, attachment)
	if projection == nil {
		return nil, message.ErrRetentionClassUnknown
	}
	projection.RecordBytes = recordBytes
	projection.RecordId = record.RecordId
	return projection, nil
}
