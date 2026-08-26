package peer

import (
	"context"
	"crypto/rand"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Two connect clients in one process, wired to each other through two plain channels, exactly
// the way connect's own ip_test.go does it (ip_test.go:211). No network space, no operator and
// no ByJwt: NewNoContractClientOob plus AddNoContractPeer is what removes the contract
// requirement, which is why connect's own data-path tests run offline and why this one can.
//
// The server half is the one under test. The client half is a client of it and nothing more: it
// marshals a MessageServerRequest into a §4.2 frame, sends it to the server's client_id, and
// correlates what comes back by `request_id` — which is the only thing it can correlate by, and
// the whole reason [Peer] has to carry it.
type fixture struct {
	ctx    context.Context
	cancel context.CancelFunc

	serverClient *connect.Client
	clientClient *connect.Client

	peer        *Peer
	handler     *recordingHandler
	connections *Connections
	checks      *Checks

	nextRequestId atomic.Uint64

	// The client's own copy of what the last HelloResponse issued. A test that seals under this
	// is a client following spec A §5.7's outbox rule; a test that seals under a saved older one
	// is the replay this design exists to refuse.
	nonce []byte

	mutex     sync.Mutex
	waiting   map[uint64]chan *protocol.MessageServerResponse
	unmatched []*protocol.MessageServerResponse

	// The response fragments of §4.6, as the client sees them before it reassembles anything.
	rawFrames  []*protocol.Frame
	reassembly *reassembly
}

const fixtureProtocolVersion = 1

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, Config{})
}

// The fixture with parts of the peer's configuration overridden, for the tests that are about a
// bound rather than about a request.
func newFixtureWith(t *testing.T, config Config) *fixture {
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

	current := &fixture{
		ctx:          ctx,
		cancel:       cancel,
		serverClient: serverClient,
		clientClient: clientClient,
		handler:      &recordingHandler{},
		waiting:      map[uint64]chan *protocol.MessageServerResponse{},
	}

	if config.Now == nil {
		config.Now = time.Now
	}
	random := io.Reader(rand.Reader)
	if config.Connections == nil {
		connections, err := NewConnections(random, config.Now, config.ConnectionIdle)
		if err != nil {
			t.Fatalf("NewConnections: %v", err)
		}
		config.Connections = connections
	}
	if config.Capabilities == nil {
		config.Capabilities = &protocol.Capabilities{
			MaxRecordsPerSubmit: api.DefaultMaxRecordsPerSubmit,
			MaxRecordsPerFetch:  api.DefaultMaxRecordsPerFetch,
		}
	}
	if config.Checks == nil {
		maxRequestBytes := int(config.Capabilities.GetMaxRequestBytes())
		if maxRequestBytes == 0 {
			maxRequestBytes = DefaultMaxRequestBytes
		}
		checks, err := NewChecks(config.Connections, maxRequestBytes)
		if err != nil {
			t.Fatalf("NewChecks: %v", err)
		}
		config.Checks = checks
	}
	if config.Handler == nil {
		config.Handler = current.handler
	}
	if config.Client == nil {
		config.Client = serverClient
	}
	if config.ProtocolVersion == 0 {
		config.ProtocolVersion = fixtureProtocolVersion
	}
	if config.ServerId == nil {
		config.ServerId = make([]byte, 16)
	}

	served, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	current.peer = served
	current.connections = config.Connections
	current.checks = config.Checks
	current.reassembly = newReassembly(config.Now, DefaultMaxResponseBytes, 64, DefaultReassemblyIdle)
	current.handler.notBuilt = config.Checks.NotBuilt()
	current.handler.front = config.Checks

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

// The client's receive callback: §4.2's two outbound message types, correlated by `request_id`.
//
// It keeps the raw frames as well as the decoded responses, because §4.6's fragmentation is a
// property of the frames and a test that only looked at what reassembled could not tell one
// frame from four.
func (self *fixture) receive(source connect.TransferPath, frames []*protocol.Frame, from connect.Peer) {
	for _, frame := range frames {
		self.mutex.Lock()
		self.rawFrames = append(self.rawFrames, &protocol.Frame{
			MessageType:  frame.GetMessageType(),
			MessageBytes: append([]byte(nil), frame.GetMessageBytes()...),
			Raw:          frame.GetRaw(),
		})
		self.mutex.Unlock()

		switch frame.GetMessageType() {
		case protocol.MessageType_MessageMessageServerResponse:
			response := &protocol.MessageServerResponse{}
			if proto.Unmarshal(frame.GetMessageBytes(), response) == nil {
				self.deliver(response)
			}
		case protocol.MessageType_MessageMessageServerFragment:
			fragment := &protocol.MessageServerFragment{}
			if proto.Unmarshal(frame.GetMessageBytes(), fragment) != nil {
				continue
			}
			assembled, complete, reason := self.reassembly.accept(source.SourceId, fragment)
			if reason != protocol.Reason_REASON_OK || !complete {
				continue
			}
			response := &protocol.MessageServerResponse{}
			if proto.Unmarshal(assembled, response) == nil {
				self.deliver(response)
			}
		}
	}
}

func (self *fixture) deliver(response *protocol.MessageServerResponse) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	waiter, found := self.waiting[response.GetRequestId()]
	if !found {
		self.unmatched = append(self.unmatched, response)
		return
	}
	delete(self.waiting, response.GetRequestId())
	waiter <- response
}

func (self *fixture) frames() []*protocol.Frame {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]*protocol.Frame{}, self.rawFrames...)
}

func (self *fixture) forgetFrames() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.rawFrames = nil
}

func (self *fixture) uncorrelated() []*protocol.MessageServerResponse {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]*protocol.MessageServerResponse{}, self.unmatched...)
}

// A request built around one arm of §4.3's oneof, with a fresh `request_id`.
func (self *fixture) request(body proto.Message) *protocol.MessageServerRequest {
	request := &protocol.MessageServerRequest{
		RequestId:       self.nextRequestId.Add(1),
		ProtocolVersion: fixtureProtocolVersion,
	}
	if err := setRequestBody(request, body); err != nil {
		panic(err)
	}
	return request
}

// Send, and answer a channel the response will arrive on. Registered before the send, because a
// response that arrives before its waiter does is a response the correlator files as unmatched —
// which is a correlation failure this fixture must not be able to invent for itself.
func (self *fixture) begin(t *testing.T, request *protocol.MessageServerRequest) chan *protocol.MessageServerResponse {
	t.Helper()
	waiter := make(chan *protocol.MessageServerResponse, 1)
	self.mutex.Lock()
	self.waiting[request.GetRequestId()] = waiter
	self.mutex.Unlock()
	self.sendRequest(t, request)
	return waiter
}

// A waiter for a `request_id` this fixture did not mint.
//
// [fixture.begin] registers one for a request it built; the fragment tests below build the frame
// themselves, and the request_id they have to correlate on is the one inside those bytes rather
// than the one a helper chose.
func (self *fixture) waitFor(requestId uint64) chan *protocol.MessageServerResponse {
	waiter := make(chan *protocol.MessageServerResponse, 1)
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.waiting[requestId] = waiter
	return waiter
}

func (self *fixture) sendRequest(t *testing.T, request *protocol.MessageServerRequest) {
	t.Helper()
	body, err := connect.ProtoMarshal(request)
	if err != nil {
		t.Fatalf("ProtoMarshal: %v", err)
	}
	self.sendFrame(t, &protocol.Frame{
		MessageType:  protocol.MessageType_MessageMessageServerRequest,
		MessageBytes: body,
	})
}

func (self *fixture) sendFrame(t *testing.T, frame *protocol.Frame) {
	t.Helper()
	if !self.clientClient.Send(frame, connect.DestinationId(self.serverClient.ClientId()), nil) {
		connect.MessagePoolReturn(frame.MessageBytes)
		t.Fatalf("the client's send did not take a frame of type %v", frame.GetMessageType())
	}
}

// One request, answered. The timeout is generous and is a test failure rather than a hang: a
// dispatcher that dropped `request_id` would otherwise leave this blocked forever.
func (self *fixture) await(t *testing.T, waiter chan *protocol.MessageServerResponse) *protocol.MessageServerResponse {
	t.Helper()
	select {
	case response := <-waiter:
		return response
	case <-time.After(30 * time.Second):
		t.Fatalf("no response arrived within 30s; %d responses arrived correlated to no request at all", len(self.uncorrelated()))
		return nil
	}
}

func (self *fixture) call(t *testing.T, body proto.Message) *protocol.MessageServerResponse {
	t.Helper()
	return self.await(t, self.begin(t, self.request(body)))
}

// §4.3.1, as a client performs it: say Hello, keep the nonce, and re-MAC everything against it.
func (self *fixture) hello(t *testing.T) *protocol.HelloResponse {
	t.Helper()
	response := self.call(t, &protocol.HelloRequest{SupportedVersions: []uint32{fixtureProtocolVersion}})
	if response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("Hello was answered %v, want REASON_OK", response.GetReason())
	}
	hello := response.GetHello()
	if hello == nil {
		t.Fatalf("Hello was answered REASON_OK with no HelloResponse in it")
	}
	self.nonce = hello.GetServerNonce()
	return hello
}

// The request-side counterpart of [setResponseBody], for the fixture only: a client that had to
// name the arm and the field number separately would be a client that could put a FetchRequest
// in the submit arm, which is the thing under test rather than a thing to help it along.
func setRequestBody(request *protocol.MessageServerRequest, body proto.Message) error {
	if body == nil {
		return nil
	}
	want := body.ProtoReflect().Descriptor().FullName()
	for _, field := range bodyArmsOf(request.ProtoReflect().Descriptor()) {
		if field.Message().FullName() != want {
			continue
		}
		request.ProtoReflect().Set(field, protoreflect.ValueOfMessage(body.ProtoReflect()))
		return nil
	}
	return ErrNoResponseArm
}

// ── the handler under the dispatcher ─────────────────────────────────────────────────────

// One call into the api layer, as the dispatcher made it.
type handlerCall struct {
	arm      string
	nonce    []byte
	clientId []byte

	// Whatever identifies this particular request, so that two calls into the same arm are two
	// entries here rather than one fact repeated.
	marker uint64
}

// A stand-in for *api.Handler that answers immediately and records what it was handed.
//
// It is a test double and not the real pipeline because peer's own layering forbids the import
// that would build one: peer may import api, and api.New needs a store.Store, which peer's
// //urmsg:mayimport directive does not permit even in a test. What is under test here is the
// dispatch and the connection, and the one thing this double must not fake is the `server_nonce`
// it is handed — every test below reads it back out of these records.
type recordingHandler struct {
	// §5.1's front checks, run in front of every operation in §5.1's order, because *api.Handler
	// runs them there and a double that skipped them would leave [Checks] called by nothing at
	// all in this package's own tests. The order is api's contract and api's own
	// TestEveryOperationRunsSpecB51sFrontChecksAndAnswersTheirRefusal is what pins it; this
	// mirrors it so that peer's checks are exercised through the frame path rather than only
	// through a direct call.
	front api.FrontChecks

	mutex sync.Mutex
	calls []handlerCall

	// What api.Handler.NotBuilt would carry: its own list plus the front checks'. The double
	// mirrors that rather than answering nothing, so [Peer.NotBuilt] is assembled here from the
	// same two sources it is assembled from in a real wiring.
	notBuilt []api.NotBuilt

	// Set by the tests that need a handler that blocks, refuses, or verifies a MAC.
	onSubmit      func(conn *api.Connection, request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error)
	onFetch       func(conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error)
	onCreateGroup func(conn *api.Connection, request *protocol.CreateGroupRequest) (protocol.Reason, *protocol.CreateGroupResponse, error)
}

var _ Handler = (*recordingHandler)(nil)

func (self *recordingHandler) record(arm string, conn *api.Connection, marker uint64) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	current := handlerCall{arm: arm, marker: marker}
	if conn != nil {
		current.nonce = append([]byte(nil), conn.ServerNonce...)
		current.clientId = append([]byte(nil), conn.ClientId...)
	}
	self.calls = append(self.calls, current)
}

func (self *recordingHandler) recorded() []handlerCall {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]handlerCall{}, self.calls...)
}

func (self *recordingHandler) forget() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.calls = nil
}

// §5.1 checks 1, 2 and 4, in order, in front of every operation — api/submit.go's frontChecks.
func (self *recordingHandler) frontChecks(ctx context.Context, conn *api.Connection, op uint8) protocol.Reason {
	if self.front == nil {
		return protocol.Reason_REASON_OK
	}
	if reason := self.front.FrameWithinLimits(ctx, conn); reason != protocol.Reason_REASON_OK {
		return reason
	}
	if reason := self.front.ConnectionAuthenticated(ctx, conn); reason != protocol.Reason_REASON_OK {
		return reason
	}
	return self.front.WithinRateLimits(ctx, conn, op)
}

func (self *recordingHandler) CreateGroup(ctx context.Context, conn *api.Connection, request *protocol.CreateGroupRequest) (protocol.Reason, *protocol.CreateGroupResponse, error) {
	if reason := self.frontChecks(ctx, conn, 11); reason != protocol.Reason_REASON_OK {
		return reason, nil, nil
	}
	self.record("create_group", conn, uint64(len(request.GetGroupId())))
	if self.onCreateGroup != nil {
		return self.onCreateGroup(conn, request)
	}
	return protocol.Reason_REASON_OK, &protocol.CreateGroupResponse{CurrentEpoch: 1, RecordId: 1}, nil
}

func (self *recordingHandler) Submit(ctx context.Context, conn *api.Connection, request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error) {
	if reason := self.frontChecks(ctx, conn, 12); reason != protocol.Reason_REASON_OK {
		return reason, nil, nil
	}
	self.record("submit", conn, uint64(len(request.GetRecords())))
	if self.onSubmit != nil {
		return self.onSubmit(conn, request)
	}
	results := []*protocol.SubmitResult{}
	for range request.GetRecords() {
		results = append(results, &protocol.SubmitResult{Reason: protocol.Reason_REASON_OK})
	}
	return protocol.Reason_REASON_OK, &protocol.SubmitResponse{Results: results}, nil
}

func (self *recordingHandler) Fetch(ctx context.Context, conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
	if reason := self.frontChecks(ctx, conn, 13); reason != protocol.Reason_REASON_OK {
		return reason, nil, nil
	}
	self.record("fetch", conn, request.GetSinceRecordId())
	if self.onFetch != nil {
		return self.onFetch(conn, request)
	}
	return protocol.Reason_REASON_OK, &protocol.FetchResponse{HighWaterRecordId: request.GetSinceRecordId()}, nil
}

func (self *recordingHandler) NotBuilt() []api.NotBuilt {
	return self.notBuilt
}

// Every response the client has received for one `request_id`, in the order its frames arrived,
// once at least `wanted` of them have.
//
// Read out of the raw frames rather than through [fixture.deliver], because the correlator keeps
// the first response for a request_id and files the rest as unmatched — and which one is first
// is exactly what a test about ordering has to look at.
func (self *fixture) responsesFor(t *testing.T, requestId uint64, wanted int) []*protocol.MessageServerResponse {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		found := []*protocol.MessageServerResponse{}
		for _, frame := range self.frames() {
			if frame.GetMessageType() != protocol.MessageType_MessageMessageServerResponse {
				continue
			}
			response := &protocol.MessageServerResponse{}
			if proto.Unmarshal(frame.GetMessageBytes(), response) != nil || response.GetRequestId() != requestId {
				continue
			}
			found = append(found, response)
		}
		if wanted <= len(found) {
			return found
		}
		if deadline.Before(time.Now()) {
			t.Fatalf("%d of %d responses for request_id %d arrived within 30s", len(found), wanted, requestId)
			return nil
		}
		time.Sleep(time.Millisecond)
	}
}
