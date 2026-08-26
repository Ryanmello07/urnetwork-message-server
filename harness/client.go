package harness

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The refusals a caller of this package can cause, as opposed to the ones the server answers. A
// server's answer is always a [protocol.Reason]; none of these ever is.
var (
	ErrNoConnectClient = errors.New("harness: a client of this server speaks over a connect client, and there is none here to speak over")
	ErrNoServer        = errors.New("harness: every frame is addressed to the server's client_id, and this one names no server")
	ErrNoArm           = errors.New("harness: this message is not an arm of that body oneof, so §4.3 gives it nowhere to travel")
	ErrSendRefused     = errors.New("harness: the connect client would not take the frame, so the request is on no wire at all")
	ErrNoResponse      = errors.New("harness: no response carrying this request_id arrived before the deadline")
	ErrWrongArm        = errors.New("harness: the server answered REASON_OK on an arm that is not the one this request travelled in")
	ErrNoNonce         = errors.New("harness: every authenticator of §5.4 and §4.3.8 is computed over the connection's server_nonce, and this client has not said Hello")
	ErrNoReadKey       = errors.New("harness: §4.3.8's req_auth is computed under the epoch's read key, and there is none here")
)

// How long a call waits for the frame that answers it. Generous, because what it protects against
// is a dispatcher that dropped `request_id` — which is a hang rather than a slow answer, and a
// test that hangs reports nothing at all.
const DefaultTimeout = 30 * time.Second

// This client's collaborators. Everything whose zero value would be a silent hole is refused by
// [New].
type Config struct {
	// The connect client this harness speaks over. It stays the caller's: [Client.Close]
	// unsubscribes and does not close it, the way [peer.Peer.Close] does not close the server's.
	Client *connect.Client

	// The server's client_id, which is the destination of every frame this client sends.
	Server connect.Id

	// The version this client offers at Hello and stamps on every later request. Zero sends no
	// version at all, which §4.3.1 treats as a client that did not negotiate.
	ProtocolVersion uint32

	// §4.6's part size for the requests this client fragments. Zero takes
	// [peer.DefaultFragmentPartBytes], which is §4.6's own ceiling — connect advertises no
	// per-peer frame budget for the min to be taken against, so the ceiling is the whole of it.
	PartBytes int

	// How long [Client.Call] waits. Zero takes [DefaultTimeout].
	Timeout time.Duration
}

// What crossed the wire, counted on this client's own side.
//
// It exists because "the record travelled over the transport" is not observable from the record
// coming back. A test that accidentally called the api layer directly would see the same record
// with the same bytes, and the difference between the two — the only difference, and the whole of
// this milestone — is that one of them put frames on a route. So the frames are counted here, the
// server counts its own in [peer.Stats], and a test asserts the two against each other.
type Counts struct {
	// §4.2 frames this client handed to connect: one per unfragmented request, and §4.6's
	// fragment count for a request too large for one frame.
	RequestFrames uint64

	// Response and fragment frames that arrived from the server. Frames of any other type are
	// not counted, because connect's own control traffic is not this binding's.
	ResponseFrames uint64

	// Responses that decoded and reached the request that was waiting for them.
	Responses uint64

	// Responses that decoded and carried a `request_id` no request of this client is waiting on.
	// It is the correlation failure a concurrent test is looking for, and it is counted rather
	// than dropped so that "every response matched its request" is a number rather than an
	// absence.
	Unmatched uint64

	// Inbound reassemblies this client abandoned: a fragment whose `index` was not the one the
	// buffer was waiting for, or whose `count` changed under it. §4.6 aborts rather than
	// buffering holes and so does this.
	Aborted uint64
}

// A client of the message server, over one connect client.
type Client struct {
	connect         *connect.Client
	server          connect.Id
	protocolVersion uint32
	partBytes       int
	timeout         time.Duration

	unsubscribe func()
	closed      sync.Once

	nextRequestId atomic.Uint64

	mutex   sync.Mutex
	waiting map[uint64]chan *protocol.MessageServerResponse
	partial map[uint64]*partial
	counts  Counts

	// This connection's own state, as §4.3.1 issued it. The nonce is what every authenticator
	// below is computed over, and it is replaced by each Hello — which is spec A §5.7's outbox
	// rule from the client's side: a record sealed against the previous one no longer verifies.
	nonce        []byte
	capabilities *protocol.Capabilities
}

// One inbound response being reassembled, per §4.6's (source, request_id) — the source being the
// one server this client talks to.
type partial struct {
	count uint32
	next  uint32
	bytes []byte
}

func New(config Config) (*Client, error) {
	if config.Client == nil {
		return nil, ErrNoConnectClient
	}
	if config.Server == (connect.Id{}) {
		return nil, ErrNoServer
	}
	self := &Client{
		connect:         config.Client,
		server:          config.Server,
		protocolVersion: config.ProtocolVersion,
		partBytes:       config.PartBytes,
		timeout:         config.Timeout,
		waiting:         map[uint64]chan *protocol.MessageServerResponse{},
		partial:         map[uint64]*partial{},
	}
	if self.partBytes <= 0 || peer.MaxFragmentPartBytes < self.partBytes {
		// §4.6's MUST NOT, applied to this side of the wire too: a client that could configure
		// its way past the ceiling would put fragments on the wire at a size a conforming
		// receiver is entitled to refuse
		self.partBytes = peer.DefaultFragmentPartBytes
	}
	if self.timeout <= 0 {
		self.timeout = DefaultTimeout
	}
	self.unsubscribe = config.Client.AddReceiveCallback(self.receive)
	return self, nil
}

// Stop receiving. The connect client is the caller's and is not closed here.
func (self *Client) Close() {
	self.closed.Do(func() { self.unsubscribe() })
}

func (self *Client) Counts() Counts {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.counts
}

// The `server_nonce` the last Hello issued, or nil.
//
// A copy, because it is the input to every MAC this client computes and a caller that could write
// through it could make a whole test seal against something the server never issued without any
// line of that test saying so.
func (self *Client) Nonce() []byte {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]byte(nil), self.nonce...)
}

// §4.3.1's advertisement from the last Hello, or nil. A clone, for [Client.Nonce]'s reason.
func (self *Client) Capabilities() *protocol.Capabilities {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.capabilities == nil {
		return nil
	}
	clone, _ := proto.Clone(self.capabilities).(*protocol.Capabilities)
	return clone
}

// ── the receive path ─────────────────────────────────────────────────────────────────────

// connect's receive callback: §4.2's two outbound message types, reassembled and correlated.
//
// The frames and their bytes are borrowed for the duration of this call, so nothing here keeps a
// reference to either — the response is unmarshaled, which copies, and a fragment's `part` is
// appended into a buffer of our own.
func (self *Client) receive(source connect.TransferPath, frames []*protocol.Frame, from connect.Peer) {
	for _, frame := range frames {
		switch frame.GetMessageType() {
		case protocol.MessageType_MessageMessageServerResponse:
			self.countResponseFrame()
			response := &protocol.MessageServerResponse{}
			if proto.Unmarshal(frame.GetMessageBytes(), response) == nil {
				self.deliver(response)
			}
		case protocol.MessageType_MessageMessageServerFragment:
			self.countResponseFrame()
			fragment := &protocol.MessageServerFragment{}
			if proto.Unmarshal(frame.GetMessageBytes(), fragment) != nil {
				continue
			}
			assembled, complete := self.accept(fragment)
			if !complete {
				continue
			}
			response := &protocol.MessageServerResponse{}
			if proto.Unmarshal(assembled, response) == nil {
				self.deliver(response)
			}
		}
	}
}

func (self *Client) countResponseFrame() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.counts.ResponseFrames++
}

// §4.6's reassembly, on the client's side: in order, or aborted.
//
// Deliberately this package's own and not peer's. peer's reassembler is the server's, and a
// client that reassembled with the server's code would be one implementation checking itself —
// the fragmentation this milestone claims is carried end to end would be carried by one function
// calling another, and a mistake in the cutting would be undone by the same mistake in the
// joining.
func (self *Client) accept(fragment *protocol.MessageServerFragment) ([]byte, bool) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	requestId := fragment.GetRequestId()
	current, open := self.partial[requestId]
	aborts := fragment.GetCount() <= fragment.GetIndex() ||
		(!open && fragment.GetIndex() != 0) ||
		(open && fragment.GetIndex() != current.next) ||
		(open && fragment.GetCount() != current.count)
	if aborts {
		delete(self.partial, requestId)
		self.counts.Aborted++
		return nil, false
	}
	if !open {
		current = &partial{count: fragment.GetCount()}
		self.partial[requestId] = current
	}
	current.bytes = append(current.bytes, fragment.GetPart()...)
	current.next++
	if current.next < current.count {
		return nil, false
	}
	delete(self.partial, requestId)
	return current.bytes, true
}

func (self *Client) deliver(response *protocol.MessageServerResponse) {
	self.mutex.Lock()
	waiter, found := self.waiting[response.GetRequestId()]
	if found {
		delete(self.waiting, response.GetRequestId())
		self.counts.Responses++
	} else {
		self.counts.Unmatched++
	}
	self.mutex.Unlock()
	if found {
		// buffered by one and removed from the map under the same lock, so this cannot block,
		// and no second response for this request_id can find a waiter to block on either
		waiter <- response
	}
}

// ── the send path ────────────────────────────────────────────────────────────────────────

// One request, sent and answered.
//
// The waiter is registered before the send, because a response that arrives before its waiter
// does is a response this client files as uncorrelated — a correlation failure the harness would
// have invented for itself, and the concurrent tests are looking for exactly that number.
func (self *Client) Call(ctx context.Context, body proto.Message) (*protocol.MessageServerResponse, error) {
	return self.call(ctx, body, self.partBytes)
}

// One request, sent as a single frame however large it is.
//
// §4.6's fragmentation is what a client does when a request exceeds the frame budget, and a
// client is not obliged to do it — connect will carry a larger frame, and this server has to
// answer one. It is also the only way to reach §5.1 check 1's copy *inside* the api pipeline: a
// request that never assembles is refused by the reassembler, one stage earlier, and the copy
// that a real *api.Handler runs is then never asked.
func (self *Client) CallWhole(ctx context.Context, body proto.Message) (*protocol.MessageServerResponse, error) {
	return self.call(ctx, body, 0)
}

func (self *Client) call(ctx context.Context, body proto.Message, partBytes int) (*protocol.MessageServerResponse, error) {
	request := &protocol.MessageServerRequest{
		RequestId:       self.nextRequestId.Add(1),
		ProtocolVersion: self.protocolVersion,
	}
	if err := setBody(request, body); err != nil {
		return nil, err
	}

	waiter := make(chan *protocol.MessageServerResponse, 1)
	self.mutex.Lock()
	self.waiting[request.GetRequestId()] = waiter
	self.mutex.Unlock()

	if err := self.send(request, partBytes); err != nil {
		self.forget(request.GetRequestId())
		return nil, err
	}

	timer := time.NewTimer(self.timeout)
	defer timer.Stop()
	select {
	case response := <-waiter:
		if response.GetRequestId() != request.GetRequestId() {
			// unreachable while the correlator keys on the id, and asserted anyway: it is the one
			// thing a client cannot check any other way
			return nil, fmt.Errorf("%w: request %d was answered under request_id %d",
				ErrNoResponse, request.GetRequestId(), response.GetRequestId())
		}
		return response, nil
	case <-ctx.Done():
		self.forget(request.GetRequestId())
		return nil, ctx.Err()
	case <-timer.C:
		self.forget(request.GetRequestId())
		return nil, fmt.Errorf("%w: request %d, after %v", ErrNoResponse, request.GetRequestId(), self.timeout)
	}
}

func (self *Client) forget(requestId uint64) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	delete(self.waiting, requestId)
}

// The request on the wire: one frame, or §4.6's fragments of it.
func (self *Client) send(request *protocol.MessageServerRequest, partBytes int) error {
	frames, err := requestFrames(request, partBytes)
	if err != nil {
		return err
	}
	for index, frame := range frames {
		if !self.connect.Send(frame, connect.DestinationId(self.server), nil) {
			returnFrames(frames[index:])
			return fmt.Errorf("%w: frame %d of %d", ErrSendRefused, index+1, len(frames))
		}
		self.mutex.Lock()
		self.counts.RequestFrames++
		self.mutex.Unlock()
	}
	return nil
}

// One request, cut into the §4.2 frames §4.6 carries it in.
//
// The whole request is one frame when it fits in a part, and `count` fragments of `partBytes`
// otherwise. §4.6 numbers them from zero and the receiver aborts on any index it was not waiting
// for, so they go on the wire in order and connect keeps them in it — "frames are received in
// order of send" is the guarantee transfer.go opens with.
//
// A part size of zero or less means this request is not fragmented at all, whatever its size.
// See [Client.CallWhole] for the one thing that is only reachable that way.
func requestFrames(request *protocol.MessageServerRequest, partBytes int) ([]*protocol.Frame, error) {
	body, err := connect.ProtoMarshal(request)
	if err != nil {
		return nil, err
	}
	if partBytes <= 0 || len(body) <= partBytes {
		return []*protocol.Frame{{
			MessageType:  protocol.MessageType_MessageMessageServerRequest,
			MessageBytes: body,
		}}, nil
	}
	count := (len(body) + partBytes - 1) / partBytes
	frames := make([]*protocol.Frame, 0, count)
	for index := 0; index < count; index++ {
		end := min((index+1)*partBytes, len(body))
		encoded, err := connect.ProtoMarshal(&protocol.MessageServerFragment{
			RequestId: request.GetRequestId(),
			Index:     uint32(index),
			Count:     uint32(count),
			Part:      body[index*partBytes : end],
		})
		if err != nil {
			returnFrames(frames)
			connect.MessagePoolReturn(body)
			return nil, err
		}
		frames = append(frames, &protocol.Frame{
			MessageType:  protocol.MessageType_MessageMessageServerFragment,
			MessageBytes: encoded,
		})
	}
	// the whole request now lives in the fragments, so the buffer it was marshaled into goes back
	// to the pool rather than to the collector
	connect.MessagePoolReturn(body)
	return frames, nil
}

func returnFrames(frames []*protocol.Frame) {
	for _, frame := range frames {
		connect.MessagePoolReturn(frame.MessageBytes)
	}
}

// ── the four operations ──────────────────────────────────────────────────────────────────

// §4.3.1, as a client performs it: negotiate a version, keep the nonce, and re-MAC everything
// against it from here on.
func (self *Client) Hello(ctx context.Context, versions ...uint32) (protocol.Reason, *protocol.HelloResponse, error) {
	if len(versions) == 0 {
		versions = []uint32{self.protocolVersion}
	}
	response, err := self.Call(ctx, &protocol.HelloRequest{SupportedVersions: versions})
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if response.GetReason() != protocol.Reason_REASON_OK {
		return response.GetReason(), nil, nil
	}
	hello := response.GetHello()
	if hello == nil {
		return response.GetReason(), nil, ErrWrongArm
	}
	self.mutex.Lock()
	self.nonce = append([]byte(nil), hello.GetServerNonce()...)
	self.capabilities, _ = proto.Clone(hello.GetCapabilities()).(*protocol.Capabilities)
	self.mutex.Unlock()
	return response.GetReason(), hello, nil
}

func (self *Client) CreateGroup(ctx context.Context, request *protocol.CreateGroupRequest) (protocol.Reason, *protocol.CreateGroupResponse, error) {
	response, err := self.Call(ctx, request)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if response.GetReason() != protocol.Reason_REASON_OK {
		return response.GetReason(), nil, nil
	}
	if response.GetCreateGroup() == nil {
		return response.GetReason(), nil, ErrWrongArm
	}
	return response.GetReason(), response.GetCreateGroup(), nil
}

func (self *Client) Submit(ctx context.Context, request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error) {
	response, err := self.Call(ctx, request)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if response.GetReason() != protocol.Reason_REASON_OK {
		return response.GetReason(), nil, nil
	}
	if response.GetSubmit() == nil {
		return response.GetReason(), nil, ErrWrongArm
	}
	return response.GetReason(), response.GetSubmit(), nil
}

// §4.3.4, authorized by §4.3.8's `req_auth` under the read key of the epoch the request names.
//
// The request is authorized here rather than by the caller because the authenticator is over the
// request's own canonical bytes: a caller that filled in `req_auth` and then changed a field
// would be sending a MAC over a request it did not send, which is a bug that reads as a server
// refusing a well-formed fetch.
func (self *Client) Fetch(ctx context.Context, request *protocol.FetchRequest, readKey []byte) (protocol.Reason, *protocol.FetchResponse, error) {
	if len(readKey) == 0 {
		return protocol.Reason_REASON_INTERNAL, nil, ErrNoReadKey
	}
	if err := self.authorize(request, readKey); err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	response, err := self.Call(ctx, request)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if response.GetReason() != protocol.Reason_REASON_OK {
		return response.GetReason(), nil, nil
	}
	if response.GetFetch() == nil {
		return response.GetReason(), nil, ErrWrongArm
	}
	return response.GetReason(), response.GetFetch(), nil
}

// §4.3.8's `req_auth`: over the deterministically marshaled body with its own `req_auth` field
// cleared, under the epoch's read key, over this connection's nonce, with the op byte read out of
// the descriptor.
func (self *Client) authorize(request *protocol.FetchRequest, readKey []byte) error {
	nonce := self.Nonce()
	if len(nonce) == 0 {
		return ErrNoNonce
	}
	op, err := opOf(request)
	if err != nil {
		return err
	}
	request.ReqAuth = nil
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return err
	}
	auth := message.ComputeRequestAuth(readKey, nonce, op, canonical)
	request.ReqAuth = auth[:]
	return nil
}

// ── the descriptor, read rather than written down ────────────────────────────────────────

// Place a body in the arm of `MessageServerRequest.body` that holds its type.
//
// Found by matching the message name against the descriptor rather than by a switch over fourteen
// typed wrappers, for the reason peer's own setResponseBody is: a switch is where a copy-paste
// puts a FetchRequest in the submit arm, and the server then answers an operation nobody asked
// for.
func setBody(request *protocol.MessageServerRequest, body proto.Message) error {
	if body == nil {
		return ErrNoArm
	}
	field, err := armOf(request.ProtoReflect().Descriptor(), body)
	if err != nil {
		return err
	}
	request.ProtoReflect().Set(field, protoreflect.ValueOfMessage(body.ProtoReflect()))
	return nil
}

// §4.3.8's `op`: the field number of the arm this body travels in.
//
// Read out of the compiled descriptor and never written down, because it is a MAC input — a
// constant here that disagreed with the arm would produce a refusal on exactly one operation,
// which §4.5 deliberately refuses to explain to the client.
func opOf(body proto.Message) (uint8, error) {
	field, err := armOf((&protocol.MessageServerRequest{}).ProtoReflect().Descriptor(), body)
	if err != nil {
		return 0, err
	}
	if field.Number() < 0 || 255 < field.Number() {
		return 0, fmt.Errorf("%w: %s is arm %d, which is not a u8", ErrNoArm, field.Message().FullName(), field.Number())
	}
	return uint8(field.Number()), nil
}

// The arm of a message's `body` oneof that carries this type.
func armOf(descriptor protoreflect.MessageDescriptor, body proto.Message) (protoreflect.FieldDescriptor, error) {
	oneof := descriptor.Oneofs().ByName("body")
	if oneof == nil {
		return nil, ErrNoArm
	}
	want := body.ProtoReflect().Descriptor().FullName()
	for index := 0; index < oneof.Fields().Len(); index++ {
		field := oneof.Fields().Get(index)
		if field.Kind() != protoreflect.MessageKind || field.Message().FullName() != want {
			continue
		}
		return field, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNoArm, want)
}
