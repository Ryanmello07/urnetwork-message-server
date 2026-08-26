package peer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The refusals this package answers with an error rather than with a [protocol.Reason], because
// no client could have caused them: a peer built without a collaborator, or a wiring in which
// two halves of §5.1 read different state.
var (
	ErrNoClient       = errors.New("peer: this package is the connect frame transport, and there is no connect client to transport frames on")
	ErrNoHandler      = errors.New("peer: a dispatcher with no handler answers §4.3 with nothing at all")
	ErrNoCapabilities = errors.New("peer: §4.3.1 makes Capabilities the whole of the server-advertised contract, and a Hello that advertised none would leave every client guessing at every limit")
	ErrNoResponseArm  = errors.New("peer: this response body is not an arm of MessageServerResponse.body, so §4.3 gives it nowhere to travel")
	ErrWrongArm       = errors.New("peer: the dispatch table's key and the body its handler asserts disagree, so this arm would be served by another arm's handler")
	ErrCapMismatch    = errors.New("peer: §5.1 check 1 enforces a bound and §4.3.1 advertises one, and this build would advertise a different number than it enforces")
)

// The api entry points this package dispatches into.
//
// An interface with one production implementation, for the reason [api.FrontChecks] is one: a
// test that wants to know which arm reached which handler needs something it can watch, and a
// concrete *api.Handler is something it can only watch through a store.
type Handler interface {
	CreateGroup(ctx context.Context, conn *api.Connection, request *protocol.CreateGroupRequest) (protocol.Reason, *protocol.CreateGroupResponse, error)
	Submit(ctx context.Context, conn *api.Connection, request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error)
	Fetch(ctx context.Context, conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error)
	NotBuilt() []api.NotBuilt
}

var _ Handler = (*api.Handler)(nil)

// A peer's collaborators. Everything whose zero value would be a silent hole is refused by [New].
type Config struct {
	Client      *connect.Client
	Handler     Handler
	Connections *Connections

	// The same value the handler was built with. [New] refuses a wiring where it is not: check 2
	// resolves a connection out of a registry, and a handler checking one registry while frames
	// arrive on another is a check that answers about connections nobody is using.
	Checks *Checks

	// §4.3.1's advertisement, and the source of the two bounds this package enforces.
	// `max_request_bytes` and `max_response_bytes` are read from here rather than configured
	// beside it, so that what a client is told and what it is held to are one number. Zero on
	// either takes §4.6's and §4.3.1's defaults, and the same default is written back into the
	// advertisement.
	Capabilities *protocol.Capabilities

	// §4.3.1's `server_id`: 16 bytes, stable per fleet.
	ServerId []byte

	// The version this server speaks. A Hello whose `supported_versions` does not carry it is
	// answered REASON_UNSUPPORTED_VERSION and opens no connection.
	ProtocolVersion uint32

	// §4.6's `part` size. Zero takes [DefaultFragmentPartBytes].
	FragmentPartBytes int

	// How many requests are served at once, and how many wait. Zero takes the defaults below.
	//
	// A pool rather than the receive callback itself, and this is the reason: connect invokes a
	// receive callback inline on the single loop that reads every peer's frames
	// (transfer.go:1334), so a handler run there would serialise the whole server behind one
	// group's transaction. A full queue still backpressures that loop, which is what connect
	// documents the callback for — the alternative is a refusal invented out of no §4.5 code.
	Workers    int
	QueueDepth int

	// The idle bound of §4.6's reassembly state, and the one [Connections] has no section for.
	// Zero on the first takes §4.6's 30 seconds; zero on the second disables the connection
	// sweep, which [Peer.NotBuilt] then declares.
	ReassemblyIdle time.Duration
	ConnectionIdle time.Duration

	// §4.6's per-client cap on concurrent reassemblies. Zero takes §4.6's 16.
	ReassembliesPerClient int

	Now func() time.Time
}

// The §4.2 frame binding: one connect client, one receive callback, and the dispatch of §4.3's
// oneof into api.
//
// Nothing here logs. §11.1 forbids identifiers in every sink it names, and the two values this
// layer has most of are a client_id and a request_id; counters are what an aggregate view is
// allowed to be made of, so counters are what [Peer.Stats] answers.
type Peer struct {
	client      *connect.Client
	handler     Handler
	connections *Connections
	checks      *Checks

	capabilities *protocol.Capabilities
	serverId     []byte

	protocolVersion   uint32
	maxRequestBytes   int
	maxResponseBytes  int
	fragmentPartBytes int

	now func() time.Time

	reassembly *reassembly

	// Built once in [New] and never written again, so the table a test reads is the table the
	// dispatcher runs.
	routes map[protoreflect.FullName]route

	ctx         context.Context
	cancel      context.CancelFunc
	unsubscribe func()
	jobs        chan job
	workers     sync.WaitGroup

	stats stats
}

// One arm of §4.3's request oneof that this build serves.
//
// A value rather than a switch, so that "which arms does this build serve" is something a gate
// can read out of the program instead of being told. The unserved arms are then the descriptor's
// arms minus this table's keys, which is a subtraction rather than a second list.
type route struct {
	name string

	// Whether §5.1's front checks run inside the api pipeline for this arm. They do for every
	// arm api owns, and they cannot for Hello: check 2 resolves a connection and Hello is where
	// a connection begins, so [Peer.hello] runs check 1 itself and there is no check 2 to run.
	// Left as one field rather than as a comment, because it decides where check 1 happens and
	// running it in both places would make the api pipeline's copy unreachable — which is
	// exactly the "called and passed is the same as never called" that FrontChecks exists over.
	pipeline bool

	run func(ctx context.Context, arrived *inbound, body proto.Message) (protocol.Reason, proto.Message, error)
}

type job struct {
	arrived *inbound
	request *protocol.MessageServerRequest
}

type stats struct {
	framesReceived  atomic.Uint64
	framesDropped   atomic.Uint64
	requestsServed  atomic.Uint64
	responsesSent   atomic.Uint64
	responsesFailed atomic.Uint64
}

// The aggregate counters of §11.3's shape: no identifier, no label, nothing a client chose.
type Stats struct {
	FramesReceived  uint64
	FramesDropped   uint64
	RequestsServed  uint64
	ResponsesSent   uint64
	ResponsesFailed uint64
}

func New(config Config) (*Peer, error) {
	if config.Client == nil {
		return nil, ErrNoClient
	}
	if config.Handler == nil {
		return nil, ErrNoHandler
	}
	if config.Connections == nil {
		return nil, ErrNoConnections
	}
	if config.Checks == nil {
		return nil, ErrNoChecks
	}
	if config.Checks.connections != config.Connections {
		return nil, ErrCheckedElsewhere
	}
	if config.Capabilities == nil {
		return nil, ErrNoCapabilities
	}

	capabilities, _ := proto.Clone(config.Capabilities).(*protocol.Capabilities)
	if capabilities.GetMaxRequestBytes() == 0 {
		capabilities.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if capabilities.GetMaxResponseBytes() == 0 {
		capabilities.MaxResponseBytes = DefaultMaxResponseBytes
	}
	// the number the client is told and the number check 1 holds it to are the same number, and
	// this is where that stops being a convention
	if int(capabilities.GetMaxRequestBytes()) != config.Checks.maxRequestBytes {
		return nil, fmt.Errorf("%w: Capabilities.max_request_bytes is %d and §5.1 check 1 enforces %d",
			ErrCapMismatch, capabilities.GetMaxRequestBytes(), config.Checks.maxRequestBytes)
	}

	self := &Peer{
		client:            config.Client,
		handler:           config.Handler,
		connections:       config.Connections,
		checks:            config.Checks,
		capabilities:      capabilities,
		serverId:          append([]byte(nil), config.ServerId...),
		protocolVersion:   config.ProtocolVersion,
		maxRequestBytes:   int(capabilities.GetMaxRequestBytes()),
		maxResponseBytes:  int(capabilities.GetMaxResponseBytes()),
		fragmentPartBytes: config.FragmentPartBytes,
		now:               config.Now,
	}
	if self.fragmentPartBytes <= 0 {
		self.fragmentPartBytes = DefaultFragmentPartBytes
	}
	if self.now == nil {
		self.now = time.Now
	}
	reassembliesPerClient := config.ReassembliesPerClient
	if reassembliesPerClient <= 0 {
		reassembliesPerClient = DefaultReassembliesPerClient
	}
	reassemblyIdle := config.ReassemblyIdle
	if reassemblyIdle == 0 {
		reassemblyIdle = DefaultReassemblyIdle
	}
	self.reassembly = newReassembly(self.now, self.maxRequestBytes, reassembliesPerClient, reassemblyIdle)
	self.routes = self.buildRoutes()

	workers := config.Workers
	if workers <= 0 {
		workers = 8
	}
	queueDepth := config.QueueDepth
	if queueDepth <= 0 {
		queueDepth = 64
	}
	self.jobs = make(chan job, queueDepth)
	self.ctx, self.cancel = context.WithCancel(config.Client.Ctx())
	for range workers {
		self.workers.Add(1)
		go self.work()
	}
	// registered last: a frame that arrives before the workers exist would block the receive
	// loop on a channel nobody is reading
	self.unsubscribe = config.Client.AddReceiveCallback(self.receive)
	return self, nil
}

// Stop dispatching. The connect client is the caller's and is not closed here.
func (self *Peer) Close() {
	self.unsubscribe()
	self.cancel()
	self.workers.Wait()
}

func (self *Peer) Stats() Stats {
	return Stats{
		FramesReceived:  self.stats.framesReceived.Load(),
		FramesDropped:   self.stats.framesDropped.Load(),
		RequestsServed:  self.stats.requestsServed.Load(),
		ResponsesSent:   self.stats.responsesSent.Load(),
		ResponsesFailed: self.stats.responsesFailed.Load(),
	}
}

// Everything §5.1, §4.3 or §4.3.1 specifies that this build does not do: the handler's own list,
// the arms of §4.3's oneof nothing here serves, and the two advertisements that would need a key
// this process does not hold.
func (self *Peer) NotBuilt() []api.NotBuilt {
	notBuilt := append([]api.NotBuilt{}, self.handler.NotBuilt()...)
	notBuilt = append(notBuilt, self.unservedArms()...)
	notBuilt = append(notBuilt, unsignedHello)
	if self.connections.idle == 0 {
		notBuilt = append(notBuilt, unsweptConnections)
	}
	return notBuilt
}

// The arms of §4.3's request oneof this build has no handler for.
//
// Derived by subtracting the dispatch table from the compiled descriptor, so an arm added to
// message.proto arrives here declared rather than arriving as a silent REASON_INTERNAL nobody
// wrote down. A list of the fourteen arms this build does not serve would be a list that is
// wrong the first time §4.3 grows a fifteenth.
func (self *Peer) unservedArms() []api.NotBuilt {
	notBuilt := []api.NotBuilt{}
	for _, field := range bodyArmsOf((&protocol.MessageServerRequest{}).ProtoReflect().Descriptor()) {
		if _, served := self.routes[field.Message().FullName()]; served {
			continue
		}
		notBuilt = append(notBuilt, api.NotBuilt{
			Section: "§4.3",
			What: fmt.Sprintf("the %s arm of MessageServerRequest.body, op %d: no handler in this build serves it, and a request naming it is answered REASON_INTERNAL",
				field.Name(), field.Number()),
			Owner: "api",
		})
	}
	return notBuilt
}

// §4.3.1's `server_keys` and `kt_gossip`, which need a key this process does not hold.
//
// §9.1 decision B13 is explicit that no replica holds the signing private key and no replica
// ever holds the root, so a HelloResponse from this build carries no key chain at all — which a
// client following §4.3.1 must refuse to connect on. It is declared for the same reason api
// declares FetchAttestation: an advertisement that is simply absent looks, from a green test,
// exactly like one that was verified.
var unsignedHello = api.NotBuilt{
	Section: "§4.3.1, §9.1, §9.4",
	What:    "HelloResponse.server_keys and HelloResponse.kt_gossip: the fleet key chain a client verifies against the compiled-in root, and the operator STH this server independently observed. This process holds no fleet key and observes no log",
	Owner:   "the key custody of §9.1, through kt",
}

// A connection registry with no idle bound.
//
// Two things are lost and neither is visible from a passing test. The live map holds one entry
// per client_id that ever said Hello and never shrinks, which is a memory bound chosen by anyone
// who can address a frame at this server. And a client that reconnects without saying Hello — a
// case §5.7's guarantee depends on and connect gives this server no way to detect — keeps its
// previous connection's nonce for as long as the entry lives, which with no bound is forever.
var unsweptConnections = api.NotBuilt{
	Section: "§5.7, §4.3.1",
	What:    "the connection idle bound: Config.ConnectionIdle is zero, so a connection is closed only by a later Hello from the same client_id, and a nonce outlives an unannounced reconnect without limit",
	Owner:   "the operator's configuration",
}

// ── the receive path ─────────────────────────────────────────────────────────────────────

// connect's receive callback: §4.2's two inbound message types and nothing else.
//
// Everything a frame carries was chosen by whoever addressed it, so nothing below panics on any
// of it. A frame this server cannot answer — one that does not decode, or one whose message
// bytes are marked raw when §4.2 says every frame of this binding is not — is dropped and
// counted, because a response has to carry a `request_id` and a frame that did not decode has
// not got one to carry.
//
// The frames and their bytes are borrowed for the duration of this call (transfer.go:146), so
// nothing here keeps a reference to either: the request is unmarshaled, which copies, and a
// fragment's `part` is appended into a buffer of our own.
func (self *Peer) receive(source connect.TransferPath, frames []*protocol.Frame, from connect.Peer) {
	for _, frame := range frames {
		switch frame.GetMessageType() {
		case protocol.MessageType_MessageMessageServerRequest:
			self.stats.framesReceived.Add(1)
			self.arrived(source.SourceId, frame)
		case protocol.MessageType_MessageMessageServerFragment:
			self.stats.framesReceived.Add(1)
			self.arrivedFragment(source.SourceId, frame)
		}
	}
}

// §5.1 check 1's first half for an unfragmented request: it decodes, or it does not.
//
// The size is measured and carried, and it is deliberately not refused here — check 1's bound is
// decided once, by [Checks.FrameWithinLimits], on the way through the pipeline. Refusing here
// too would leave the pipeline's copy of check 1 unreachable, and an unreachable check is one
// nobody notices the deletion of.
func (self *Peer) arrived(clientId connect.Id, frame *protocol.Frame) {
	arrived, request, decoded := decodeRequest(clientId, frame)
	if !decoded {
		self.stats.framesDropped.Add(1)
		return
	}
	self.enqueue(job{arrived: arrived, request: request})
}

// One request frame, decoded and measured, or nothing.
//
// Split out from [Peer.arrived] because it is the whole of what the fuzz target has to reach: a
// target that decoded the bytes itself would be fuzzing its own copy of this, and the interesting
// half is what the dispatcher does with what came out.
func decodeRequest(clientId connect.Id, frame *protocol.Frame) (*inbound, *protocol.MessageServerRequest, bool) {
	request := &protocol.MessageServerRequest{}
	if frame.GetRaw() || proto.Unmarshal(frame.GetMessageBytes(), request) != nil {
		return nil, nil, false
	}
	return &inbound{clientId: clientId, bytes: len(frame.GetMessageBytes()), fragments: 1}, request, true
}

// One fragment frame, decoded, or nothing.
func decodeFragment(frame *protocol.Frame) (*protocol.MessageServerFragment, bool) {
	fragment := &protocol.MessageServerFragment{}
	if frame.GetRaw() || proto.Unmarshal(frame.GetMessageBytes(), fragment) != nil {
		return nil, false
	}
	return fragment, true
}

// §4.6's reassembly, and check 1's other half.
//
// A fragment carries a `request_id` even when the request it belongs to never assembles, so
// unlike a malformed request frame every refusal on this path can be answered rather than
// dropped — which is what makes REASON_OVERSIZE reach the client that caused it.
func (self *Peer) arrivedFragment(clientId connect.Id, frame *protocol.Frame) {
	fragment, decoded := decodeFragment(frame)
	if !decoded {
		self.stats.framesDropped.Add(1)
		return
	}
	assembled, reason := self.reassembly.accept(clientId, fragment)
	if reason != protocol.Reason_REASON_OK {
		self.send(clientId, &protocol.MessageServerResponse{RequestId: fragment.GetRequestId(), Reason: reason})
		return
	}
	if assembled == nil {
		return
	}
	request := &protocol.MessageServerRequest{}
	if proto.Unmarshal(assembled, request) != nil {
		// the fragments arrived and the bytes they carried are not a request; §4.5's
		// non-specific refusal is the answer, and it has a request_id to travel on
		self.send(clientId, &protocol.MessageServerResponse{
			RequestId: fragment.GetRequestId(),
			Reason:    protocol.Reason_REASON_REJECTED,
		})
		return
	}
	self.enqueue(job{
		arrived: &inbound{clientId: clientId, bytes: len(assembled), fragments: int(fragment.GetCount())},
		request: request,
	})
}

// Hand the request to a worker, or backpressure the receive loop until one is free.
//
// Blocking is deliberate and it is connect's own documented mechanism: "A blocked callback
// intentionally backpressures that path and preserves frame lifetime/order" (transfer.go:146).
// The alternative would be to refuse a request for want of a worker, and §4.5 has no code for
// that — REASON_RATE_LIMITED would claim the limiter of §4.7 that §5.1 check 4 still declares
// absent.
func (self *Peer) enqueue(current job) {
	select {
	case self.jobs <- current:
	case <-self.ctx.Done():
	}
}

func (self *Peer) work() {
	defer self.workers.Done()
	for {
		select {
		case <-self.ctx.Done():
			return
		case current := <-self.jobs:
			self.stats.requestsServed.Add(1)
			self.send(current.arrived.clientId, self.answer(self.ctx, current.arrived, current.request))
		}
	}
}

// ── the dispatch ─────────────────────────────────────────────────────────────────────────

// One request, answered.
//
// Every path out of here returns a response and every response carries the request's own
// `request_id`, set in exactly one place. Responses are sent by whichever worker finished first,
// so two requests in flight on one connection can be answered out of order — which is what
// `request_id` is for, and why a dispatcher that dropped it would turn concurrency into a
// correlation bug rather than into a visible failure.
func (self *Peer) answer(ctx context.Context, arrived *inbound, request *protocol.MessageServerRequest) *protocol.MessageServerResponse {
	response := &protocol.MessageServerResponse{RequestId: request.GetRequestId()}

	field := request.ProtoReflect().WhichOneof(bodyOneofOf(request.ProtoReflect().Descriptor()))
	if field == nil {
		// no body at all, or an arm this build's descriptor does not know — the wire cannot tell
		// them apart and neither does this. §4.5's non-specific refusal
		response.Reason = protocol.Reason_REASON_REJECTED
		return response
	}
	body := request.ProtoReflect().Get(field).Message().Interface()
	current, served := self.routes[field.Message().FullName()]
	if !served {
		// an arm §4.3 defines and this build has no handler for. [Peer.unservedArms] declares
		// every one of them, so this is a gap with an address rather than a shrug
		response.Reason = protocol.Reason_REASON_INTERNAL
		return response
	}

	if !current.pipeline {
		// the arms api does not own run check 1 here, because there is nowhere else for it to
		// run. Hello is the only one, and check 2 cannot precede it: a connection is what Hello
		// creates
		if reason := withinLimits(arrived.bytes, self.maxRequestBytes); reason != protocol.Reason_REASON_OK {
			response.Reason = reason
			return response
		}
	} else {
		// §4.3.1 negotiates the version once, at Hello. A later request that names a different
		// one is answered rather than served under a version this server does not speak; zero is
		// a field the client did not set and is not a mismatch
		if version := request.GetProtocolVersion(); version != 0 && version != self.protocolVersion {
			response.Reason = protocol.Reason_REASON_UNSUPPORTED_VERSION
			return response
		}
		// §5.1 check 2's lookup: the connection is resolved from the platform-authenticated
		// source client_id, and from nothing the request carries
		connection, found := self.connections.Lookup(arrived.clientId)
		if !found {
			response.Reason = protocol.Reason_REASON_REJECTED
			return response
		}
		arrived.connection = connection
	}

	reason, answered, err := current.run(withInbound(ctx, arrived), arrived, body)
	if err != nil {
		// an error is this server's fault by construction — api answers a client's fault with a
		// Reason — so it is REASON_INTERNAL and the body it might have built does not travel
		response.Reason = protocol.Reason_REASON_INTERNAL
		return response
	}
	response.Reason = reason
	if err := setResponseBody(response, answered); err != nil {
		response.Reason = protocol.Reason_REASON_INTERNAL
		return response
	}
	return response
}

// The arms of §4.3's request oneof this build serves.
//
// Each entry asserts its own body type, and a mismatch between the key and that assertion is an
// error rather than a call into the wrong handler: two arms swapped in this table would then
// answer REASON_INTERNAL on both instead of quietly serving one arm's request with the other
// arm's handler, which is a bug that reads as a passing test.
func (self *Peer) buildRoutes() map[protoreflect.FullName]route {
	return map[protoreflect.FullName]route{
		nameOf(&protocol.HelloRequest{}): {
			name:     "hello",
			pipeline: false,
			run: func(ctx context.Context, arrived *inbound, body proto.Message) (protocol.Reason, proto.Message, error) {
				request, ok := body.(*protocol.HelloRequest)
				if !ok {
					return protocol.Reason_REASON_INTERNAL, nil, ErrWrongArm
				}
				reason, answered, err := self.hello(ctx, arrived, request)
				if answered == nil {
					return reason, nil, err
				}
				return reason, answered, err
			},
		},
		nameOf(&protocol.CreateGroupRequest{}): {
			name:     "create_group",
			pipeline: true,
			run: func(ctx context.Context, arrived *inbound, body proto.Message) (protocol.Reason, proto.Message, error) {
				request, ok := body.(*protocol.CreateGroupRequest)
				if !ok {
					return protocol.Reason_REASON_INTERNAL, nil, ErrWrongArm
				}
				reason, answered, err := self.handler.CreateGroup(ctx, arrived.connection.ApiConnection(), request)
				if answered == nil {
					return reason, nil, err
				}
				return reason, answered, err
			},
		},
		nameOf(&protocol.SubmitRequest{}): {
			name:     "submit",
			pipeline: true,
			run: func(ctx context.Context, arrived *inbound, body proto.Message) (protocol.Reason, proto.Message, error) {
				request, ok := body.(*protocol.SubmitRequest)
				if !ok {
					return protocol.Reason_REASON_INTERNAL, nil, ErrWrongArm
				}
				reason, answered, err := self.handler.Submit(ctx, arrived.connection.ApiConnection(), request)
				if answered == nil {
					return reason, nil, err
				}
				return reason, answered, err
			},
		},
		nameOf(&protocol.FetchRequest{}): {
			name:     "fetch",
			pipeline: true,
			run: func(ctx context.Context, arrived *inbound, body proto.Message) (protocol.Reason, proto.Message, error) {
				request, ok := body.(*protocol.FetchRequest)
				if !ok {
					return protocol.Reason_REASON_INTERNAL, nil, ErrWrongArm
				}
				reason, answered, err := self.handler.Fetch(ctx, arrived.connection.ApiConnection(), request)
				if answered == nil {
					return reason, nil, err
				}
				return reason, answered, err
			},
		},
	}
}

// ── the send path ────────────────────────────────────────────────────────────────────────

// One response, on its way back to the client that asked.
//
// §4.3.1's `max_response_bytes` binds here: a response past it is replaced by the refusal
// REASON_OVERSIZE carrying the same `request_id`, because a response the transport will not
// carry is a request the client never hears about at all.
func (self *Peer) send(clientId connect.Id, response *protocol.MessageServerResponse) {
	if self.maxResponseBytes < proto.Size(response) {
		response = &protocol.MessageServerResponse{
			RequestId: response.GetRequestId(),
			Reason:    protocol.Reason_REASON_OVERSIZE,
		}
	}
	frames, err := responseFrames(response, self.fragmentPartBytes)
	if err != nil {
		self.stats.responsesFailed.Add(1)
		return
	}
	destination := connect.DestinationId(clientId)
	for _, frame := range frames {
		if !self.client.Send(frame, destination, self.acked) {
			// the send did not take the frame, so no ack will ever fire and the bytes are ours
			// to give back
			connect.MessagePoolReturn(frame.MessageBytes)
			self.stats.responsesFailed.Add(1)
			continue
		}
		self.stats.responsesSent.Add(1)
	}
}

func (self *Peer) acked(err error) {
	if err != nil {
		self.stats.responsesFailed.Add(1)
	}
}

// ── the descriptor, read rather than written down ────────────────────────────────────────

func nameOf(message proto.Message) protoreflect.FullName {
	return message.ProtoReflect().Descriptor().FullName()
}

// The `body` oneof of a MessageServerRequest or a MessageServerResponse.
//
// Looked up by the name §4.3 gives it, once per call, rather than by index: an oneof added
// beside it would silently become "the first one" to a lookup by position.
func bodyOneofOf(descriptor protoreflect.MessageDescriptor) protoreflect.OneofDescriptor {
	return descriptor.Oneofs().ByName("body")
}

// Every message-typed arm of a message's `body` oneof.
func bodyArmsOf(descriptor protoreflect.MessageDescriptor) []protoreflect.FieldDescriptor {
	body := bodyOneofOf(descriptor)
	if body == nil {
		return nil
	}
	arms := []protoreflect.FieldDescriptor{}
	for index := 0; index < body.Fields().Len(); index++ {
		field := body.Fields().Get(index)
		if field.Kind() == protoreflect.MessageKind {
			arms = append(arms, field)
		}
	}
	return arms
}

// Place a handler's answer in the arm of `MessageServerResponse.body` that holds its type.
//
// The arm is found by matching the body's own message name against the descriptor, the way
// api.opOf finds §4.3.8's op byte, rather than by a switch listing fourteen typed wrappers. A
// switch is where a copy-paste puts a FetchResponse in the submit arm, and the wire is then a
// response the client parses as another operation's.
func setResponseBody(response *protocol.MessageServerResponse, body proto.Message) error {
	if body == nil {
		return nil
	}
	want := body.ProtoReflect().Descriptor().FullName()
	for _, field := range bodyArmsOf(response.ProtoReflect().Descriptor()) {
		if field.Message().FullName() != want {
			continue
		}
		response.ProtoReflect().Set(field, protoreflect.ValueOfMessage(body.ProtoReflect()))
		return nil
	}
	return fmt.Errorf("%w: %s", ErrNoResponseArm, want)
}
