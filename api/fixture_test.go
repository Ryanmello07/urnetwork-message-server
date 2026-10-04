package api

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/blobd"
	"github.com/urnetwork/message-server/store"
	"google.golang.org/protobuf/proto"
)

// The sender in this package's tests plays the client, which is the only party in the system
// that seals a record. It reaches for connect/message for every derivation, every preimage and
// every encoding, exactly as the sdk does — a test that hand-rolled any of them would be the
// second implementation §12.1 A-1 is written against, and it would be a second implementation
// inside the repository whose whole gate is that there is not one.

var (
	senderA = handle(0xA0)
	senderB = handle(0xB0)
)

func handle(seed byte) [store.SenderHandleBytes]byte {
	var value [store.SenderHandleBytes]byte
	for index := range value {
		value[index] = seed ^ byte(index)
	}
	return value
}

// A group's storage root for one epoch. Deterministic, distinct per epoch, and not secret: the
// keys under it are what the test needs, and where a real storage root comes from is the MLS key
// schedule of plan p4, which is absent rather than stubbed.
func storageRoot(epoch uint64) []byte {
	root := make([]byte, 32)
	for index := range root {
		root[index] = byte(index)*3 ^ byte(epoch*17+5)
	}
	return root
}

// Everything one test needs to be a client, a connection and a server at once.
type fixture struct {
	handler     *Handler
	store       *store.MemoryStore
	knownGroups KnownGroups
	conn        *Connection
	groupId     []byte
	sleeps      []time.Duration

	// the clock the handler was built with, so a test can read the same stamp §7.1's arrival
	// window is computed from rather than a second one that drifts from it
	now func() time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, Config{})
}

// The fixture with parts of the config overridden, for the tests that need to observe the pad or
// to count what reaches the store.
func newFixtureWith(t *testing.T, config Config) *fixture {
	t.Helper()
	current := &fixture{
		store:       store.NewMemoryStore(store.DefaultLimits()),
		knownGroups: NewMemoryKnownGroups(),
		groupId:     groupId(0x11),
		conn:        &Connection{ServerNonce: nonce(0x5E), ClientId: []byte("a client id the platform authenticated")},
	}
	if config.Store == nil {
		config.Store = current.store
	}
	if config.KnownGroups == nil {
		config.KnownGroups = current.knownGroups
	}
	if config.Front == nil {
		config.Front = ChecksNotImplemented{}
	}
	if config.Sleep == nil {
		config.Sleep = func(remaining time.Duration) { current.sleeps = append(current.sleeps, remaining) }
	}
	if config.Now == nil {
		// a clock that does not advance, so a pad's argument is the floor itself and the
		// assertion about it is an equality rather than a measurement that flakes
		frozen := time.Unix(1767225600, 0).UTC()
		config.Now = func() time.Time { return frozen }
	}
	handler, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	current.handler = handler
	current.now = config.Now
	return current
}

// MASTER §8's `eph_window`: `floor(sent_at_ms / (eph_bucket_seconds[b] × 1000))`, origin the unix
// epoch, as the SENDER computes it.
//
// Written out here rather than taken from the handler's own arithmetic, for the reason
// [clientProjection] is written out: a check whose two sides come from one function is a check
// that cannot fail. What is NOT written out is the ladder — the bucket's length comes from
// [message.EphBucketSeconds], so a bucket whose window moves is a bucket this moves with.
//
// The zero answer is arithmetic and not a special case for the TRANSIENT RUNG, and it is not the
// answer AT ALL off the ladder. [message.EphBucketSeconds] gives three answers and this gives
// three back, in its order: a negative is a bucket that names no rung and is refused BEFORE the
// reading is looked at; a zero is bucket 0, whose window is 0 by definition and which does not
// consult the reading; a positive divides, and only then is a pre-epoch reading refused.
//
// Until 2026-09-13 this read `if seconds <= 0 { return 0, nil }`, which gave the off-ladder
// bucket and the transient rung ONE answer -- the sentinel collision M1-27's second half was
// ruled to eliminate. That is the same defect [harness.EphWindowAt] carried, and it is why this
// arithmetic is now driven over the shared table rather than trusted: see
// TestTheFixturesCopyOfTheSenderFormulaAnswersTheSharedKAT in ephkat_test.go, and ledger item 193.
//
// It answers in the shared table's own vocabulary -- a window, or the NAME of a refusal -- rather
// than through a sentinel of its own. A test fixture that declared two error values would be
// declaring a third set of identities for one formula's two refusals, which is more of exactly
// what item 193 files.
func ephWindowAnswer(bucket uint8, sentAtMs int64) (uint64, string) {
	seconds := message.EphBucketSeconds(bucket)
	switch {
	case seconds < 0:
		return 0, katOffLadder
	case seconds == 0:
		return 0, ""
	}
	if sentAtMs < 0 {
		return 0, katSentAt
	}
	return uint64(sentAtMs) / (uint64(seconds) * 1000), ""
}

// [ephWindowAnswer] for a caller that has a *testing.T and no use for a window that does not
// exist.
func ephWindowAt(t *testing.T, bucket uint8, sentAtMs int64) uint64 {
	t.Helper()
	window, refused := ephWindowAnswer(bucket, sentAtMs)
	if refused != "" {
		t.Fatalf("no eph window exists for bucket %d at sent_at_ms %d: %s", bucket, sentAtMs, refused)
	}
	return window
}

// The window §7.1 computes from this record's own arrival stamp, which for a submission this
// fixture makes is the handler's clock.
func (self *fixture) arrivalWindow(t *testing.T, bucket uint8) uint64 {
	t.Helper()
	return ephWindowAt(t, bucket, self.now().UnixMilli())
}

func groupId(seed byte) []byte {
	value := make([]byte, store.GroupIdBytes)
	for index := range value {
		value[index] = seed ^ byte(index*7)
	}
	return value
}

// §3.1's `blob_id`, at its own width, for the blob rung of §8.3.
func blobId(seed byte) []byte {
	value := make([]byte, store.BlobIdBytes)
	for index := range value {
		value[index] = seed ^ byte(index*11)
	}
	return value
}

func nonce(seed byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = seed ^ byte(index*5)
	}
	return value
}

func (self *fixture) writeKey(epoch uint64) []byte {
	return message.WriteKey(storageRoot(epoch))
}

func (self *fixture) readKey(epoch uint64) []byte {
	return message.ReadKey(storageRoot(epoch))
}

// The EpochAttachment a commit carries for the epoch it opens: the two keys, the policy, and the
// wrap set the EpochComplete marker will have to match.
func (self *fixture) epochAttachment(opens uint64, wraps uint32) *message.ServerAttachment {
	contextHash := make([]byte, 32)
	for index := range contextHash {
		contextHash[index] = byte(index) ^ byte(opens)
	}
	return &message.ServerAttachment{
		Kind: message.AttachmentEpoch,
		Epoch: &message.EpochAttachment{
			Epoch:             opens,
			AlgId:             0x0031, // HKDF-SHA-256, which is what derived both keys
			WriteKey:          self.writeKey(opens),
			ReadKey:           self.readKey(opens),
			GroupContextHash:  contextHash,
			ExpectedWrapCount: wraps,
		},
	}
}

// The kind 0x0005 EpochDigest a commit carries under ruling 27: [fixture.epochAttachment]'s six
// PUBLIC fields, with the two keys replaced by one digest over them.
//
// It is built through `message.NewEpochDigestAttachment` and never field by field, because that
// constructor is what makes an attachment whose `epoch` and whose digest's `opens_epoch` disagree
// UNREPRESENTABLE: it reads the epoch once, out of the body it is building, and is given no
// second one to disagree with. A fixture that filled `EpochKeysDigest` itself would be a fixture
// able to build the very body the constructor exists to prevent, and every test downstream of it
// would be testing a record no conforming committer can produce.
//
// The six public fields are taken FROM [fixture.epochAttachment] rather than typed again, so the
// two kinds cannot drift into disagreeing about anything but the keys.
func (self *fixture) digestAttachment(t *testing.T, opens uint64, wraps uint32) *message.ServerAttachment {
	t.Helper()
	return self.digestAttachmentFor(t, self.groupId, opens, wraps, self.writeKey(opens), self.readKey(opens))
}

// The same, for a group and a key pair the caller names — which is what a test needs in order to
// build a digest over the WRONG epoch, the WRONG group or the WRONG keys and watch check 3 refuse
// it.
func (self *fixture) digestAttachmentFor(t *testing.T, group []byte, opens uint64, wraps uint32,
	writeKey []byte, readKey []byte) *message.ServerAttachment {

	t.Helper()
	public := self.epochAttachment(opens, wraps).Epoch
	body, err := message.NewEpochDigestAttachment(
		[store.GroupIdBytes]byte(group),
		message.EpochDigestAttachment{
			Epoch:             public.Epoch,
			AlgId:             public.AlgId,
			MediaTtlSeconds:   public.MediaTtlSeconds,
			DurableTtlSeconds: public.DurableTtlSeconds,
			GroupContextHash:  public.GroupContextHash,
			ExpectedWrapCount: public.ExpectedWrapCount,
		},
		writeKey, readKey)
	if err != nil {
		t.Fatalf("NewEpochDigestAttachment: %v", err)
	}
	return &message.ServerAttachment{Kind: message.AttachmentEpochDigest, EpochDigest: body}
}

// The delivery a kind 0x0005 commit's epoch opens with, as the request carries it.
func (self *fixture) epochKeys(opens uint64) *protocol.EpochKeyDelivery {
	return &protocol.EpochKeyDelivery{WriteKey: self.writeKey(opens), ReadKey: self.readKey(opens)}
}

// An attachment encoded at the door that serves its kind, which is the encode-side half of
// `api.parseServerAttachment`.
//
// `message.EncodeServerAttachment` REFUSES kind 0x0005 by name — the two doors are how
// `connect/message` keeps "which kinds does this build serve" one question per door — so a
// fixture that called it alone could not build a 0x0005 record at all.
func encodeAtItsDoor(t *testing.T, attachment *message.ServerAttachment) []byte {
	t.Helper()
	if attachment != nil && attachment.Kind == message.AttachmentEpochDigest {
		bs, err := message.EncodeEpochDigestAttachment(attachment.EpochDigest)
		if err != nil {
			t.Fatalf("EncodeEpochDigestAttachment: %v", err)
		}
		return bs
	}
	bs, err := message.EncodeServerAttachment(attachment)
	if err != nil {
		t.Fatalf("EncodeServerAttachment: %v", err)
	}
	return bs
}

func wrapAttachment(epoch uint64, target [store.WrapTargetHandleBytes]byte) *message.ServerAttachment {
	return &message.ServerAttachment{
		Kind: message.AttachmentWrap,
		Wrap: &message.WrapTag{WrapTargetHandle: target[:], Epoch: epoch},
	}
}

func completeAttachment(epoch uint64, wraps uint32) *message.ServerAttachment {
	return &message.ServerAttachment{
		Kind:     message.AttachmentComplete,
		Complete: &message.EpochComplete{Epoch: epoch, WrapCount: wraps},
	}
}

// One record to seal, in the terms the sender chooses them.
type sealed struct {
	sender      [store.SenderHandleBytes]byte
	epoch       uint64
	streamIndex uint64
	isCommit    bool
	class       message.RetentionClass
	ephBucket   uint8
	// MASTER §8's `t`. Always encoded; zero on PERMANENT, DURABLE, MEDIA and EPH(0), and on
	// EPH(1..5) the sender's own [ephWindowAt]. Settable rather than computed inside seal because
	// the whole of §7.1's refusal is about a value a sender got wrong, and a fixture that could
	// only produce the right one could not reach it.
	ephWindow  uint64
	bucket     message.SizeBucket
	expireAt   uint64
	head       []byte
	body       []byte
	attachment *message.ServerAttachment
	writeKey   []byte

	// §8.3's blob rung: the body lives in an object this names and `ct_body` is absent, which is
	// the one rung the server binds rather than stores. Set alongside bucket SizeBucketBlob; the
	// record layer refuses a blob id on any other rung and a blob rung without one.
	blobId []byte

	// Overrides, for the tests that need a record that disagrees with itself.
	groupId []byte
	// A record with no body at all, which the record layer accepts because it also parses what
	// the server rebuilds for a heads_only read, and which §5.1 check 3 refuses on submit.
	emptyBody bool
	// A body_hash taken over other bytes, for check 8.
	bodyHashOf []byte
}

// The whole of what a sender does, in Spec A §5.2's construction order: the body is padded to its
// rung, `body_hash` is taken over it, the header is completed, and only then is there a preimage
// to MAC.
//
// The body is padded and not encrypted. §9.5's padding is what keeps the rung from leaking a
// message's real length, and the rung is what §5.1 check 3 asserts an equality against; the AEAD
// that would seal these octets is plan p4 and is not here, so what travels is opaque and
// unencrypted and this package cannot tell the difference — which is exactly what it claims.
func (self *fixture) seal(t *testing.T, spec sealed) *protocol.Record {
	t.Helper()
	group := spec.groupId
	if group == nil {
		group = self.groupId
	}
	attachmentBytes := encodeAtItsDoor(t, spec.attachment)
	var body []byte
	if spec.bucket != message.SizeBucketBlob {
		// the blob rung has no inline body at all, so there is no rung to pad to
		body = padToRung(t, spec.bucket, spec.body)
	}
	if spec.emptyBody {
		body = nil
	}
	bodyHash := blobd.ContentHash(body)
	if spec.bodyHashOf != nil {
		bodyHash = blobd.ContentHash(padToRung(t, spec.bucket, spec.bodyHashOf))
	}
	header := message.RecordHeader{
		Epoch:            spec.epoch,
		StreamIndex:      spec.streamIndex,
		IsCommit:         spec.isCommit,
		RetentionClass:   spec.class,
		EphBucket:        spec.ephBucket,
		EphWindow:        spec.ephWindow,
		SizeBucket:       spec.bucket,
		ExpireAt:         spec.expireAt,
		BodyHash:         bodyHash,
		ServerAttachment: attachmentBytes,
	}
	if spec.blobId != nil {
		header.BlobId = append([]byte{}, spec.blobId...)
	}
	copy(header.GroupId[:], group)
	copy(header.SenderHandle[:], spec.sender[:])

	record := &message.Record{Header: header, CtHead: spec.head, CtBody: body}
	record.WriteAuth = message.ComputeWriteAuth(spec.writeKey, self.conn.ServerNonce, &header, spec.head, attachmentBytes)
	recordBytes, err := message.EncodeRecord(record)
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}

	projection := clientProjection(t, &header, spec.attachment)
	projection.RecordBytes = recordBytes
	return projection
}

// §9.5's padding: a body is exactly its rung's ciphertext length, and the rung's length comes
// from the ladder rather than from a number written here.
func padToRung(t *testing.T, bucket message.SizeBucket, body []byte) []byte {
	t.Helper()
	want := message.SizeBucketCtBodyBytes(bucket)
	if want < 0 {
		t.Fatalf("size bucket %d has no inline body to pad", bucket)
	}
	if want < len(body) {
		t.Fatalf("a %d octet body does not fit rung %d, which holds %d", len(body), bucket, want)
	}
	padded := make([]byte, want)
	copy(padded, body)
	for index := len(body); index < len(padded); index++ {
		padded[index] = byte(index * 31)
	}
	return padded
}

// §4.3.3's projection fields, as a client populates them.
//
// Written out here rather than taken from projectionOf, so that the server's projection builder
// is compared with something and not with itself. The one thing it does not write out is the
// join of the retention class and the eph bucket: that happens in exactly one place in the
// system, message.RetentionClassWire, and a second copy of the table in a test would be the
// divergence every other rule in this file exists to prevent.
func clientProjection(t *testing.T, header *message.RecordHeader, attachment *message.ServerAttachment) *protocol.Record {
	t.Helper()
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		t.Fatalf("RetentionClassWire: %v", err)
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
	return projection
}

func projectionsAgree(left *protocol.Record, right *protocol.Record) bool {
	return proto.Equal(left, right)
}

// A submission through the api layer, which must reach a body: a submit whose envelope refuses
// has answered checks 1, 2 or 4, and none of those is what any test in this package is about.
func (self *fixture) submit(t *testing.T, records ...*protocol.Record) []*protocol.SubmitResult {
	t.Helper()
	reason, response, err := self.handler.Submit(context.Background(), self.conn, &protocol.SubmitRequest{
		GroupId: self.groupId,
		Records: records,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the submit envelope answered %v, want REASON_OK with a body", reason)
	}
	if len(response.GetResults()) != len(records) {
		t.Fatalf("the submit answered %d results for %d records; §4.3.3 aligns them positionally",
			len(response.GetResults()), len(records))
	}
	return response.GetResults()
}

// A submission carrying §4.3.3's `epoch_keys` beside the records.
//
// It is a separate entry point rather than a variadic on [fixture.submit] so that every existing
// caller keeps sending NO deliveries, which is what makes "a kind 0x0001 commit is still accepted
// with nothing beside it" a property the whole existing suite holds rather than one test asserts.
func (self *fixture) submitWithKeys(t *testing.T, keys []*protocol.EpochKeyDelivery, records ...*protocol.Record) []*protocol.SubmitResult {
	t.Helper()
	reason, response, err := self.handler.Submit(context.Background(), self.conn, &protocol.SubmitRequest{
		GroupId:   self.groupId,
		Records:   records,
		EpochKeys: keys,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the submit envelope answered %v, want REASON_OK with a body", reason)
	}
	if len(response.GetResults()) != len(records) {
		t.Fatalf("the submit answered %d results for %d records; §4.3.3 aligns them positionally",
			len(response.GetResults()), len(records))
	}
	return response.GetResults()
}

// A submission to a group the caller names, for the tests that submit to one that does not exist.
func (self *fixture) submitTo(t *testing.T, group []byte, records ...*protocol.Record) []*protocol.SubmitResult {
	t.Helper()
	reason, response, err := self.handler.Submit(context.Background(), self.conn, &protocol.SubmitRequest{
		GroupId: group,
		Records: records,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the submit envelope answered %v, want REASON_OK with a body", reason)
	}
	return response.GetResults()
}

// A fetch of the whole group, authorized under the epoch's read key.
func (self *fixture) fetch(t *testing.T) *protocol.FetchResponse {
	t.Helper()
	reason, response, err := self.fetchFrom(t, &protocol.FetchRequest{GroupId: self.groupId, ReadEpoch: 1})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the fetch answered %v, want REASON_OK", reason)
	}
	return response
}

// A fetch of whatever the caller asks for, with §4.3.8's req_auth computed over it.
func (self *fixture) fetchFrom(t *testing.T, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
	t.Helper()
	self.authorize(t, request)
	return self.handler.Fetch(context.Background(), self.conn, request)
}

// §4.3.8's req_auth, computed the way the client computes it: over the deterministically
// marshaled body with its own req_auth field at zero length, under the read key of the epoch the
// request names, with the op byte read out of the descriptor.
func (self *fixture) authorize(t *testing.T, request *protocol.FetchRequest) {
	t.Helper()
	request.ReqAuth = nil
	op, err := opOf(request)
	if err != nil {
		t.Fatalf("opOf: %v", err)
	}
	canonical, err := canonicalRequestBytes(request)
	if err != nil {
		t.Fatalf("canonicalRequestBytes: %v", err)
	}
	auth := message.ComputeRequestAuth(self.readKey(request.GetReadEpoch()), self.conn.ServerNonce, op, canonical)
	request.ReqAuth = auth[:]
}

// A group with its founding commit already accepted, for the tests that are about what happens
// afterwards rather than about the creation itself.
func (self *fixture) createGroup(t *testing.T) *protocol.CreateGroupResponse {
	t.Helper()
	commit := self.seal(t, sealed{
		sender:     senderA,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("a founding commit"),
		body:       []byte("a founding commit"),
		attachment: self.epochAttachment(1, 1),
		writeKey:   self.writeKey(0),
	})
	reason, created, err := self.handler.CreateGroup(context.Background(), self.conn, &protocol.CreateGroupRequest{
		GroupId:           self.groupId,
		InitialCommit:     commit,
		BootstrapWriteKey: self.writeKey(0),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("CreateGroup answered %v, want REASON_OK", reason)
	}
	return created
}

// The group above, with its epoch's fan-out closed, so that an ordinary record is writable.
func (self *fixture) createOpenGroup(t *testing.T) {
	t.Helper()
	self.createGroup(t)
	wrap := self.seal(t, sealed{
		sender:     senderA,
		epoch:      1,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		head:       []byte("the epoch-1 snapshot"),
		body:       []byte("the epoch-1 snapshot"),
		attachment: wrapAttachment(1, senderA),
		writeKey:   self.writeKey(1),
		// stream index 1: the founding commit consumed 0 for this sender
		streamIndex: 1,
	})
	if results := self.submit(t, wrap); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the wrap was answered %v, want REASON_OK", results[0].GetReason())
	}
	marker := self.seal(t, sealed{
		sender:      senderA,
		epoch:       1,
		streamIndex: 2,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket256,
		head:        []byte("epoch 1 complete"),
		body:        []byte("epoch 1 complete"),
		attachment:  completeAttachment(1, 1),
		writeKey:    self.writeKey(1),
	})
	if results := self.submit(t, marker); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the marker was answered %v, want REASON_OK", results[0].GetReason())
	}
}
