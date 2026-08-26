package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/blobd"
	"github.com/urnetwork/message-server/peer"
	"github.com/urnetwork/message-server/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The whole stack in one process: two connect clients, peer's §4.2 frame dispatch, api's §5.1
// pipeline and the in-memory store.
//
// It lives here rather than in peer because peer's //urmsg:mayimport directive names api, redact
// and metrics and does not name store — and api.New cannot be built without a store.Store. That
// is the layering working rather than a gap in it: an entrypoint is the one package allowed to
// reach every other, so the test that wires all of them belongs to the entrypoint.
//
// What only this test can see is that peer's [peer.Checks] are the checks *api* runs. Everywhere
// else in peer's own suite the handler is a double that calls them in api's documented order; here
// the real *api.Handler calls them, so a change to api's front-check order or to which checks it
// runs shows up as a failure in this file instead of nowhere.
type stack struct {
	ctx    context.Context
	cancel context.CancelFunc

	serverClient *connect.Client
	clientClient *connect.Client

	store  *store.MemoryStore
	peer   *peer.Peer
	handle *api.Handler

	nextRequestId uint64

	// The client's own connection state: the nonce §4.3.1 issued, and the keys it seals under.
	nonce   []byte
	groupId []byte

	mutex     sync.Mutex
	waiting   map[uint64]chan *protocol.MessageServerResponse
	unmatched int

	// §4.6's reassembly, on the client side. A FetchResponse carrying four records is already
	// past the 2048 byte part size, so a client of this server that could not put fragments back
	// together would hang on its first fetch — which is exactly how this test failed before it
	// had one.
	parts map[uint64][]byte
}

const stackProtocolVersion = 1

func newStack(t *testing.T) *stack {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	settings := connect.DefaultClientSettings()
	serverClient := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), settings)
	clientClient := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), settings)

	toServer := make(connect.Route)
	toClient := make(connect.Route)
	clientClient.RouteManager().UpdateTransport(connect.NewSendGatewayTransport(), []connect.Route{toServer})
	clientClient.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransport(), []connect.Route{toClient})
	clientClient.ContractManager().AddNoContractPeer(serverClient.ClientId())
	serverClient.RouteManager().UpdateTransport(
		connect.NewSendClientTransport(connect.DestinationId(clientClient.ClientId())), []connect.Route{toClient})
	serverClient.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransport(), []connect.Route{toServer})
	serverClient.ContractManager().AddNoContractPeer(clientClient.ClientId())

	connections, err := peer.NewConnections(rand.Reader, time.Now, time.Hour)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	checks, err := peer.NewChecks(connections, peer.DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	memory := store.NewMemoryStore(store.DefaultLimits())
	handler, err := api.New(api.Config{
		Store:       memory,
		KnownGroups: api.NewMemoryKnownGroups(),
		Front:       checks,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	served, err := peer.New(peer.Config{
		Client:          serverClient,
		Handler:         handler,
		Connections:     connections,
		Checks:          checks,
		Capabilities:    &protocol.Capabilities{MaxRequestBytes: peer.DefaultMaxRequestBytes},
		ProtocolVersion: stackProtocolVersion,
		ServerId:        bytes.Repeat([]byte{0x5A}, 16),
	})
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}

	current := &stack{
		ctx:          ctx,
		cancel:       cancel,
		serverClient: serverClient,
		clientClient: clientClient,
		store:        memory,
		peer:         served,
		handle:       handler,
		groupId:      bytes.Repeat([]byte{0x71}, store.GroupIdBytes),
		waiting:      map[uint64]chan *protocol.MessageServerResponse{},
		parts:        map[uint64][]byte{},
	}
	unsubscribe := clientClient.AddReceiveCallback(current.receive)
	t.Cleanup(func() {
		unsubscribe()
		served.Close()
		clientClient.Close()
		serverClient.Close()
		cancel()
	})
	return current
}

func (self *stack) receive(source connect.TransferPath, frames []*protocol.Frame, from connect.Peer) {
	for _, frame := range frames {
		var assembled []byte
		switch frame.GetMessageType() {
		case protocol.MessageType_MessageMessageServerResponse:
			assembled = frame.GetMessageBytes()
		case protocol.MessageType_MessageMessageServerFragment:
			fragment := &protocol.MessageServerFragment{}
			if proto.Unmarshal(frame.GetMessageBytes(), fragment) != nil {
				continue
			}
			self.mutex.Lock()
			self.parts[fragment.GetRequestId()] = append(self.parts[fragment.GetRequestId()], fragment.GetPart()...)
			if fragment.GetIndex()+1 == fragment.GetCount() {
				assembled = self.parts[fragment.GetRequestId()]
				delete(self.parts, fragment.GetRequestId())
			}
			self.mutex.Unlock()
			if assembled == nil {
				continue
			}
		default:
			continue
		}
		response := &protocol.MessageServerResponse{}
		if proto.Unmarshal(assembled, response) != nil {
			continue
		}
		self.mutex.Lock()
		waiter, found := self.waiting[response.GetRequestId()]
		if found {
			delete(self.waiting, response.GetRequestId())
		} else {
			self.unmatched++
		}
		self.mutex.Unlock()
		if found {
			waiter <- response
		}
	}
}

func (self *stack) call(t *testing.T, body proto.Message) *protocol.MessageServerResponse {
	t.Helper()
	self.mutex.Lock()
	self.nextRequestId++
	request := &protocol.MessageServerRequest{RequestId: self.nextRequestId, ProtocolVersion: stackProtocolVersion}
	waiter := make(chan *protocol.MessageServerResponse, 1)
	self.waiting[request.GetRequestId()] = waiter
	self.mutex.Unlock()

	if err := setBody(request, body); err != nil {
		t.Fatalf("setBody: %v", err)
	}
	encoded, err := connect.ProtoMarshal(request)
	if err != nil {
		t.Fatalf("ProtoMarshal: %v", err)
	}
	frame := &protocol.Frame{MessageType: protocol.MessageType_MessageMessageServerRequest, MessageBytes: encoded}
	if !self.clientClient.Send(frame, connect.DestinationId(self.serverClient.ClientId()), nil) {
		connect.MessagePoolReturn(frame.MessageBytes)
		t.Fatal("the client's send did not take the request frame")
	}
	select {
	case response := <-waiter:
		if response.GetRequestId() != request.GetRequestId() {
			t.Fatalf("a response to request %d carries request_id %d", request.GetRequestId(), response.GetRequestId())
		}
		return response
	case <-time.After(30 * time.Second):
		t.Fatalf("no response to request %d within 30s", request.GetRequestId())
		return nil
	}
}

// The arm of a `body` oneof that holds this message's type, found in the descriptor.
func setBody(carrier proto.Message, body proto.Message) error {
	reflected := carrier.ProtoReflect()
	oneof := reflected.Descriptor().Oneofs().ByName("body")
	want := body.ProtoReflect().Descriptor().FullName()
	for index := 0; index < oneof.Fields().Len(); index++ {
		field := oneof.Fields().Get(index)
		if field.Kind() != protoreflect.MessageKind || field.Message().FullName() != want {
			continue
		}
		reflected.Set(field, protoreflect.ValueOfMessage(body.ProtoReflect()))
		return nil
	}
	return errNoArm
}

var errNoArm = errorString("this message is not an arm of that body oneof")

type errorString string

func (self errorString) Error() string { return string(self) }

// §4.3.8's `op`: the field number of the arm this request body travels in, read out of the
// descriptor rather than written down, because it is a MAC input.
func opOf(body proto.Message) uint8 {
	want := body.ProtoReflect().Descriptor().FullName()
	fields := (&protocol.MessageServerRequest{}).ProtoReflect().Descriptor().Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if field.ContainingOneof() == nil || field.Kind() != protoreflect.MessageKind {
			continue
		}
		if field.Message().FullName() == want {
			return uint8(field.Number())
		}
	}
	return 0
}

// ── the client's own sealing, all of it through connect/message ──────────────────────────

func storageRoot(epoch uint64) []byte {
	root := make([]byte, 32)
	for index := range root {
		root[index] = byte(index)*3 ^ byte(epoch*17+5)
	}
	return root
}

func handleOf(seed byte) [store.SenderHandleBytes]byte {
	var value [store.SenderHandleBytes]byte
	for index := range value {
		value[index] = seed ^ byte(index)
	}
	return value
}

type sealed struct {
	sender      [store.SenderHandleBytes]byte
	epoch       uint64
	streamIndex uint64
	isCommit    bool
	class       message.RetentionClass
	head        []byte
	body        []byte
	attachment  *message.ServerAttachment
	writeKey    []byte
}

// One record, sealed the way spec A §5.2 orders it: the body is padded to its rung, `body_hash`
// is taken over it, the header is completed, and only then is there a preimage to MAC.
//
// The body is padded and not encrypted. The AEAD that would seal these octets is plan p4 and is
// absent; what travels is opaque to the server either way, which is the whole of what §5.2 claims.
func (self *stack) seal(t *testing.T, spec sealed) *protocol.Record {
	t.Helper()
	attachmentBytes, err := message.EncodeServerAttachment(spec.attachment)
	if err != nil {
		t.Fatalf("EncodeServerAttachment: %v", err)
	}
	want := message.SizeBucketCtBodyBytes(message.SizeBucket256)
	body := make([]byte, want)
	copy(body, spec.body)
	for index := len(spec.body); index < want; index++ {
		body[index] = byte(index * 31)
	}

	header := message.RecordHeader{
		Epoch:            spec.epoch,
		StreamIndex:      spec.streamIndex,
		IsCommit:         spec.isCommit,
		RetentionClass:   spec.class,
		SizeBucket:       message.SizeBucket256,
		BodyHash:         blobd.ContentHash(body),
		ServerAttachment: attachmentBytes,
	}
	copy(header.GroupId[:], self.groupId)
	copy(header.SenderHandle[:], spec.sender[:])

	record := &message.Record{Header: header, CtHead: spec.head, CtBody: body}
	record.WriteAuth = message.ComputeWriteAuth(spec.writeKey, self.nonce, &header, spec.head, attachmentBytes)
	encoded, err := message.EncodeRecord(record)
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}

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
		BodyHash:       append([]byte{}, header.BodyHash[:]...),
		RecordBytes:    encoded,
	}
	if spec.attachment != nil && spec.attachment.Wrap != nil {
		projection.WrapTargetHandle = append([]byte{}, spec.attachment.Wrap.WrapTargetHandle...)
	}
	return projection
}

func (self *stack) epochAttachment(opens uint64, wraps uint32) *message.ServerAttachment {
	contextHash := make([]byte, 32)
	for index := range contextHash {
		contextHash[index] = byte(index) ^ byte(opens)
	}
	return &message.ServerAttachment{
		Kind: message.AttachmentEpoch,
		Epoch: &message.EpochAttachment{
			Epoch:             opens,
			AlgId:             0x0031,
			WriteKey:          message.WriteKey(storageRoot(opens)),
			ReadKey:           message.ReadKey(storageRoot(opens)),
			GroupContextHash:  contextHash,
			ExpectedWrapCount: wraps,
		},
	}
}

// ── the test ─────────────────────────────────────────────────────────────────────────────

// A group is created, a record is submitted, and the record comes back on a fetch — all of it
// over §4.2's frame path, through peer's dispatch and api's §5.1 pipeline.
//
// Every authenticator on the way is computed against the `server_nonce` this connection's Hello
// issued, and none of them is carried in a request. The last step is what closes the loop: the
// record the client sealed is the record that comes back, byte for byte.
func TestARecordTravelsTheWholeStackAndComesBack(t *testing.T) {
	stack := newStack(t)
	sender := handleOf(0xA0)

	hello := stack.call(t, &protocol.HelloRequest{SupportedVersions: []uint32{stackProtocolVersion}})
	if hello.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("Hello was answered %v", hello.GetReason())
	}
	stack.nonce = hello.GetHello().GetServerNonce()
	if len(stack.nonce) != peer.ServerNonceBytes {
		t.Fatalf("Hello issued a %d byte server_nonce", len(stack.nonce))
	}
	if got := hello.GetHello().GetCapabilities().GetMaxRequestBytes(); got != peer.DefaultMaxRequestBytes {
		t.Fatalf("Hello advertised max_request_bytes %d, want the value §5.1 check 1 enforces", got)
	}

	// §4.3.2's founding commit, self-certified against bootstrap_write_key
	commit := stack.seal(t, sealed{
		sender:     sender,
		isCommit:   true,
		class:      message.RetentionPermanent,
		head:       []byte("a founding commit"),
		body:       []byte("a founding commit"),
		attachment: stack.epochAttachment(1, 1),
		writeKey:   message.WriteKey(storageRoot(0)),
	})
	created := stack.call(t, &protocol.CreateGroupRequest{
		GroupId:           stack.groupId,
		InitialCommit:     commit,
		BootstrapWriteKey: message.WriteKey(storageRoot(0)),
	})
	if created.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("CreateGroup over the frame path was answered %v", created.GetReason())
	}
	if created.GetCreateGroup().GetCurrentEpoch() != 1 {
		t.Fatalf("CreateGroup answered epoch %d, want 1", created.GetCreateGroup().GetCurrentEpoch())
	}

	// §6.1's epoch publication: the wrap set, then the marker that closes it
	stack.submit(t, "the epoch-1 wrap", stack.seal(t, sealed{
		sender:      sender,
		epoch:       1,
		streamIndex: 1,
		class:       message.RetentionPermanent,
		head:        []byte("the epoch-1 snapshot"),
		body:        []byte("the epoch-1 snapshot"),
		attachment: &message.ServerAttachment{
			Kind: message.AttachmentWrap,
			Wrap: &message.WrapTag{WrapTargetHandle: sender[:], Epoch: 1},
		},
		writeKey: message.WriteKey(storageRoot(1)),
	}))
	stack.submit(t, "the epoch-1 marker", stack.seal(t, sealed{
		sender:      sender,
		epoch:       1,
		streamIndex: 2,
		class:       message.RetentionDurable,
		head:        []byte("epoch 1 complete"),
		body:        []byte("epoch 1 complete"),
		attachment: &message.ServerAttachment{
			Kind:     message.AttachmentComplete,
			Complete: &message.EpochComplete{Epoch: 1, WrapCount: 1},
		},
		writeKey: message.WriteKey(storageRoot(1)),
	}))

	// and an ordinary record, which is what any of this is for
	written := stack.seal(t, sealed{
		sender:      sender,
		epoch:       1,
		streamIndex: 3,
		class:       message.RetentionDurable,
		head:        []byte("a head"),
		body:        []byte("a body nobody here can read"),
		writeKey:    message.WriteKey(storageRoot(1)),
	})
	stack.submit(t, "an ordinary record", written)

	// §4.3.4, authorized by §4.3.8's req_auth under epoch 1's read key
	fetch := &protocol.FetchRequest{GroupId: stack.groupId, ReadEpoch: 1, SinceRecordId: 0}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(fetch)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	auth := message.ComputeRequestAuth(message.ReadKey(storageRoot(1)), stack.nonce, opOf(fetch), canonical)
	fetch.ReqAuth = auth[:]

	fetched := stack.call(t, fetch)
	if fetched.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("Fetch over the frame path was answered %v", fetched.GetReason())
	}
	records := fetched.GetFetch().GetRecords()
	if len(records) != 4 {
		t.Fatalf("the fetch answered %d records for a group with four in it", len(records))
	}
	last := records[len(records)-1]

	// the header and both ciphertexts come back as they were sealed; `write_auth` does not, and
	// cannot. §4.3.4 rebuilds record_bytes from the stored columns, and the MAC is over a
	// `server_nonce` that belonged to the submitting connection and is gone with it. That is not
	// a loss: by MASTER I5 a record's authenticity is MLS's and is checked at the client, and
	// write_auth was only ever the access control of §5.1 check 7
	sent, err := message.ParseRecord(written.GetRecordBytes())
	if err != nil {
		t.Fatalf("parsing the record the client sealed: %v", err)
	}
	returned, err := message.ParseRecord(last.GetRecordBytes())
	if err != nil {
		t.Fatalf("parsing the record that came back: %v", err)
	}
	if !reflect.DeepEqual(returned.Header, sent.Header) {
		t.Fatalf("the header that came back is not the header the client sealed: sent %+v, returned %+v", sent.Header, returned.Header)
	}
	if !bytes.Equal(returned.CtHead, sent.CtHead) || !bytes.Equal(returned.CtBody, sent.CtBody) {
		t.Fatal("the ciphertexts that came back are not the ciphertexts the client sealed")
	}
	if returned.WriteAuth != ([32]byte{}) {
		t.Fatal("the rebuilt record carries a write_auth; the server cannot reproduce one and must not appear to")
	}
	if last.GetRecordId() == 0 {
		t.Fatal("the record came back with no record_id; §4.3.4's cursor is what a client paginates on")
	}

	if stack.unmatched != 0 {
		t.Fatalf("%d responses arrived carrying a request_id no request used", stack.unmatched)
	}
}

func (self *stack) submit(t *testing.T, what string, record *protocol.Record) {
	t.Helper()
	response := self.call(t, &protocol.SubmitRequest{GroupId: self.groupId, Records: []*protocol.Record{record}})
	if response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("%s was refused on the envelope with %v", what, response.GetReason())
	}
	results := response.GetSubmit().GetResults()
	if len(results) != 1 {
		t.Fatalf("%s was answered %d results for one record", what, len(results))
	}
	if results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("%s was answered %v", what, results[0].GetReason())
	}
}

// A request that arrives before this connection said Hello is refused by check 2, inside api's
// own pipeline, and reaches no store at all.
//
// This is the one place the real *api.Handler runs peer's [peer.Checks]. peer's own suite runs
// them through a double that calls them in api's documented order; if api stopped calling them,
// or called them after the pipeline, only this fails.
func TestApisPipelineRunsPeersFrontChecks(t *testing.T) {
	stack := newStack(t)

	// no Hello: there is no connection, so check 2 has no nonce to look up
	response := stack.call(t, &protocol.SubmitRequest{GroupId: stack.groupId})
	if response.GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a submit on no connection was answered %v, want REASON_REJECTED", response.GetReason())
	}
	if response.GetSubmit() != nil {
		t.Fatal("a front-check refusal carried a body; the refusal has only the envelope to travel on")
	}
	if state, err := stack.store.GroupState(context.Background(), stack.groupId); err == nil {
		t.Fatalf("a refused submit reached the store, which answered %v", state)
	}

	// §5.1 check 1, through the same pipeline: a request past max_request_bytes
	hello := stack.call(t, &protocol.HelloRequest{SupportedVersions: []uint32{stackProtocolVersion}})
	if hello.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("Hello was answered %v", hello.GetReason())
	}
	oversize := stack.call(t, &protocol.FetchRequest{
		GroupId: stack.groupId,
		ReqAuth: bytes.Repeat([]byte{0x11}, peer.DefaultMaxRequestBytes+16),
	})
	if oversize.GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("a request past max_request_bytes was answered %v, want REASON_OVERSIZE", oversize.GetReason())
	}
}
