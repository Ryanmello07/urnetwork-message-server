package peer

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"google.golang.org/protobuf/proto"
)

// §4.6, from the client's side: one request, cut into parts and sent as fragment frames.
func (self *fixture) sendFragments(t *testing.T, request *protocol.MessageServerRequest, partBytes int) {
	t.Helper()
	body, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	count := (len(body) + partBytes - 1) / partBytes
	for index := range count {
		self.sendFragment(t, &protocol.MessageServerFragment{
			RequestId: request.GetRequestId(),
			Index:     uint32(index),
			Count:     uint32(count),
			Part:      body[index*partBytes : min((index+1)*partBytes, len(body))],
		})
	}
}

func (self *fixture) sendFragment(t *testing.T, fragment *protocol.MessageServerFragment) {
	t.Helper()
	body, err := connect.ProtoMarshal(fragment)
	if err != nil {
		t.Fatalf("ProtoMarshal: %v", err)
	}
	self.sendFrame(t, &protocol.Frame{
		MessageType:  protocol.MessageType_MessageMessageServerFragment,
		MessageBytes: body,
	})
}

// A request body of about this many bytes, for the tests that are about a bound rather than
// about a field.
func filler(bytesWanted int) *protocol.FetchRequest {
	return &protocol.FetchRequest{
		GroupId: bytes.Repeat([]byte{0x44}, 32),
		ReqAuth: bytes.Repeat([]byte{0x55}, bytesWanted),
	}
}

// ── §5.1 check 1 ─────────────────────────────────────────────────────────────────────────

// A request past `max_request_bytes` is refused REASON_OVERSIZE and reaches no handler.
//
// The refusal comes back on the envelope with the request's own `request_id`, which is the whole
// reason check 1 is decided inside the pipeline rather than dropped at the frame: a client that
// sent something too large is told so, and told which request it was.
func TestARequestPastMaxRequestBytesIsRefusedAndNeverServed(t *testing.T) {
	fixture := newFixtureWith(t, Config{
		Capabilities: &protocol.Capabilities{MaxRequestBytes: 512},
	})
	fixture.hello(t)
	fixture.handler.forget()

	request := fixture.request(filler(1500))
	response := fixture.await(t, fixture.begin(t, request))
	if response.GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("a request of about 1500 bytes against a 512 byte cap was answered %v, want REASON_OVERSIZE", response.GetReason())
	}
	if response.GetRequestId() != request.GetRequestId() {
		t.Fatalf("the refusal came back on request_id %d, want %d", response.GetRequestId(), request.GetRequestId())
	}
	if calls := fixture.handler.recorded(); len(calls) != 0 {
		t.Fatalf("an oversize request reached the handler: %v", calls)
	}

	// and one inside the cap still goes through, so what refused was the size
	if inside := fixture.call(t, filler(64)); inside.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("a request inside the cap was answered %v", inside.GetReason())
	}
}

// Hello advertises the cap the server enforces, and [New] refuses a build where it does not.
//
// §4.3.1 calls Capabilities the whole of the server-advertised contract. A server advertising one
// number and enforcing another gives every client a size to fragment to that it will then be
// refused at, and §5.1 check 1 is the only place the client would find out.
func TestTheAdvertisedRequestCapIsTheOneCheckOneEnforces(t *testing.T) {
	fixture := newFixtureWith(t, Config{Capabilities: &protocol.Capabilities{MaxRequestBytes: 4096}})
	hello := fixture.hello(t)
	if int(hello.GetCapabilities().GetMaxRequestBytes()) != fixture.checks.maxRequestBytes {
		t.Fatalf("Hello advertises max_request_bytes %d and check 1 enforces %d",
			hello.GetCapabilities().GetMaxRequestBytes(), fixture.checks.maxRequestBytes)
	}
	if fixture.peer.maxRequestBytes != fixture.checks.maxRequestBytes {
		t.Fatalf("the frame layer bounds reassembly at %d and check 1 refuses at %d", fixture.peer.maxRequestBytes, fixture.checks.maxRequestBytes)
	}

	connections, err := NewConnections(bytes.NewReader(bytes.Repeat([]byte{1}, 1024)), time.Now, 0)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	checks, err := NewChecks(connections, 4096)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	_, err = New(Config{
		Client:       fixture.serverClient,
		Handler:      fixture.handler,
		Connections:  connections,
		Checks:       checks,
		Capabilities: &protocol.Capabilities{MaxRequestBytes: 8192},
	})
	if !errors.Is(err, ErrCapMismatch) {
		t.Fatalf("a peer advertising 8192 and enforcing 4096 was built with err %v", err)
	}
}

// A handler and a peer that read different connection registries is not a wiring [New] allows.
func TestAPeerAndItsHandlersChecksShareOneRegistry(t *testing.T) {
	fixture := newFixture(t)
	elsewhere, err := NewConnections(bytes.NewReader(bytes.Repeat([]byte{1}, 1024)), time.Now, 0)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	checks, err := NewChecks(elsewhere, DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	_, err = New(Config{
		Client:       fixture.serverClient,
		Handler:      fixture.handler,
		Connections:  fixture.connections,
		Checks:       checks,
		Capabilities: &protocol.Capabilities{},
	})
	if !errors.Is(err, ErrCheckedElsewhere) {
		t.Fatalf("a peer whose checks read another registry was built with err %v", err)
	}
}

// ── §4.6 reassembly ──────────────────────────────────────────────────────────────────────

// A request that does not fit one frame arrives whole.
func TestAFragmentedRequestIsReassembledAndServed(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)
	fixture.handler.forget()

	marker := uint64(4242)
	request := fixture.request(&protocol.FetchRequest{
		GroupId:       bytes.Repeat([]byte{0x66}, 32),
		SinceRecordId: marker,
		ReqAuth:       bytes.Repeat([]byte{0x77}, 6000),
	})
	waiter := make(chan *protocol.MessageServerResponse, 1)
	fixture.mutex.Lock()
	fixture.waiting[request.GetRequestId()] = waiter
	fixture.mutex.Unlock()

	fixture.sendFragments(t, request, DefaultFragmentPartBytes)
	response := fixture.await(t, waiter)
	if response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("a fragmented request was answered %v", response.GetReason())
	}
	if response.GetFetch().GetHighWaterRecordId() != marker {
		t.Fatalf("the reassembled request named record %d, want %d", response.GetFetch().GetHighWaterRecordId(), marker)
	}
	if left := fixture.peer.reassembly.inFlightCount(); left != 0 {
		t.Fatalf("%d reassemblies are still held after the request completed", left)
	}
}

// Reassembly past the cap is REASON_OVERSIZE, and the buffer goes immediately.
//
// §4.6 is explicit that the buffer is freed at that moment rather than at the end of the request:
// an unbounded reassembly buffer is a memory-exhaustion vector, and one freed a stage later is
// one an attacker holds open by never sending the last fragment.
func TestReassemblyPastTheCapIsRefusedAndTheBufferFreedAtOnce(t *testing.T) {
	fixture := newFixtureWith(t, Config{Capabilities: &protocol.Capabilities{MaxRequestBytes: 4096}})
	fixture.hello(t)
	fixture.handler.forget()

	request := fixture.request(filler(12000))
	waiter := make(chan *protocol.MessageServerResponse, 1)
	fixture.mutex.Lock()
	fixture.waiting[request.GetRequestId()] = waiter
	fixture.mutex.Unlock()

	fixture.sendFragments(t, request, 2048)
	response := fixture.await(t, waiter)
	if response.GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("a reassembly past a 4096 byte cap was answered %v, want REASON_OVERSIZE", response.GetReason())
	}
	if response.GetRequestId() != request.GetRequestId() {
		t.Fatalf("the refusal came back on request_id %d, want %d", response.GetRequestId(), request.GetRequestId())
	}
	if calls := fixture.handler.recorded(); len(calls) != 0 {
		t.Fatalf("an oversize reassembly reached the handler: %v", calls)
	}
	if left := fixture.peer.reassembly.inFlightCount(); left != 0 {
		t.Fatalf("%d reassembly buffers survive a refusal §4.6 says frees them immediately", left)
	}
}

// The four ways §4.6 says a reassembly aborts, each on its own.
//
// A unit test on the reassembler rather than four trips through the frame path, because three of
// the four are conditions a well-behaved connect client will not put on the wire in order and the
// fourth needs seventeen requests in flight at once.
func TestEveryWaySpecB46AbortsAReassembly(t *testing.T) {
	now := time.Unix(1767225600, 0).UTC()
	clock := func() time.Time { return now }
	clientId := connect.NewId()

	t.Run("a count of zero", func(t *testing.T) {
		buffers := newReassembly(clock, 4096, 16, DefaultReassemblyIdle)
		if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Count: 0}); reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("a fragment naming no fragments at all was answered %v", reason)
		}
	})

	t.Run("an index past the count", func(t *testing.T) {
		buffers := newReassembly(clock, 4096, 16, DefaultReassemblyIdle)
		if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 3, Count: 2}); reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("fragment 3 of 2 was answered %v", reason)
		}
	})

	t.Run("out of order, which aborts rather than buffering a hole", func(t *testing.T) {
		buffers := newReassembly(clock, 4096, 16, DefaultReassemblyIdle)
		if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 3, Part: []byte("a")}); reason != protocol.Reason_REASON_OK {
			t.Fatalf("the first fragment was answered %v", reason)
		}
		if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 2, Count: 3, Part: []byte("c")}); reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("fragment 2 arriving after fragment 0 was answered %v, want the request aborted", reason)
		}
		if left := buffers.inFlightCount(); left != 0 {
			t.Fatalf("%d buffers survive an out-of-order abort", left)
		}
	})

	t.Run("past the concurrent cap for one client", func(t *testing.T) {
		buffers := newReassembly(clock, 4096, 16, DefaultReassemblyIdle)
		for index := range 16 {
			if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: uint64(index), Index: 0, Count: 2, Part: []byte("x")}); reason != protocol.Reason_REASON_OK {
				t.Fatalf("in-flight reassembly %d was answered %v", index, reason)
			}
		}
		if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 99, Index: 0, Count: 2, Part: []byte("x")}); reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("the seventeenth concurrent reassembly was answered %v; §4.6 caps a client at sixteen", reason)
		}
		// another client is not affected by this one's cap
		if _, reason := buffers.accept(connect.NewId(), &protocol.MessageServerFragment{RequestId: 99, Index: 0, Count: 2, Part: []byte("x")}); reason != protocol.Reason_REASON_OK {
			t.Fatalf("a second client was refused for the first client's in-flight reassemblies")
		}
	})

	t.Run("past §4.6's thirty seconds", func(t *testing.T) {
		buffers := newReassembly(clock, 4096, 16, DefaultReassemblyIdle)
		if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("a")}); reason != protocol.Reason_REASON_OK {
			t.Fatalf("the first fragment was answered %v", reason)
		}
		now = now.Add(DefaultReassemblyIdle + time.Second)
		// the second fragment of an expired request opens a new reassembly, so it is refused as
		// a first fragment with a non-zero index rather than appended to a buffer that is gone
		if _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 1, Count: 2, Part: []byte("b")}); reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("a fragment arriving after the expiry was appended to the expired buffer: %v", reason)
		}
		if left := buffers.inFlightCount(); left != 0 {
			t.Fatalf("%d expired buffers are still held", left)
		}
	})
}

// Check 1 answers the same way whichever of its two call sites reaches it.
//
// The bound is one function for exactly this reason: the reassembler needs it as a memory bound
// that cannot wait for a pipeline stage, and the pipeline needs it as check 1's refusal. Two
// copies of `max < bytes` is a build that refuses a fragmented request at one size and an
// unfragmented one at another.
func TestCheckOneRefusesTheSameWayOnBothPathsItRunsOn(t *testing.T) {
	fixture := newFixtureWith(t, Config{Capabilities: &protocol.Capabilities{MaxRequestBytes: 2048}})
	fixture.hello(t)

	unfragmented := fixture.await(t, fixture.begin(t, fixture.request(filler(6000))))

	fragmented := fixture.request(filler(6000))
	waiter := make(chan *protocol.MessageServerResponse, 1)
	fixture.mutex.Lock()
	fixture.waiting[fragmented.GetRequestId()] = waiter
	fixture.mutex.Unlock()
	fixture.sendFragments(t, fragmented, 1024)
	reassembled := fixture.await(t, waiter)

	if unfragmented.GetReason() != reassembled.GetReason() {
		t.Fatalf("the same oversize request was answered %v unfragmented and %v fragmented", unfragmented.GetReason(), reassembled.GetReason())
	}
	if unfragmented.GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("both paths answered %v, want REASON_OVERSIZE", unfragmented.GetReason())
	}
}

// ── §4.6 outbound ────────────────────────────────────────────────────────────────────────

// A response too large for one frame travels as fragments that carry its `request_id`.
//
// The frames are asserted directly and not only through the client's reassembly: a client and a
// server that fragment symmetrically wrongly agree with each other perfectly, and a test that only
// read what came back out would not notice.
func TestAResponseTooLargeForOneFrameTravelsAsFragments(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)
	fixture.forgetFrames()

	fixture.handler.onFetch = func(conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
		return protocol.Reason_REASON_OK, &protocol.FetchResponse{
			HighWaterRecordId: request.GetSinceRecordId(),
			Records:           []*protocol.Record{{RecordBytes: bytes.Repeat([]byte{0x88}, 9000)}},
		}, nil
	}

	request := fixture.request(&protocol.FetchRequest{GroupId: bytes.Repeat([]byte{1}, 32), SinceRecordId: 31})
	response := fixture.await(t, fixture.begin(t, request))
	if response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("a large fetch was answered %v", response.GetReason())
	}
	if response.GetRequestId() != request.GetRequestId() {
		t.Fatalf("the reassembled response carries request_id %d, want %d", response.GetRequestId(), request.GetRequestId())
	}

	fragments := []*protocol.MessageServerFragment{}
	for _, frame := range fixture.frames() {
		if frame.GetMessageType() != protocol.MessageType_MessageMessageServerFragment {
			continue
		}
		fragment := &protocol.MessageServerFragment{}
		if err := proto.Unmarshal(frame.GetMessageBytes(), fragment); err != nil {
			t.Fatalf("a fragment frame did not decode: %v", err)
		}
		if frame.GetRaw() {
			t.Fatal("a fragment frame is marked raw; §4.2 says Frame.raw is always false for this binding")
		}
		fragments = append(fragments, fragment)
	}
	if len(fragments) < 2 {
		t.Fatalf("a response of about 9000 bytes travelled in %d fragments at a %d byte part size", len(fragments), DefaultFragmentPartBytes)
	}

	assembled := []byte{}
	for index, fragment := range fragments {
		if fragment.GetRequestId() != request.GetRequestId() {
			t.Fatalf("fragment %d carries request_id %d, want %d", index, fragment.GetRequestId(), request.GetRequestId())
		}
		if fragment.GetIndex() != uint32(index) || fragment.GetCount() != uint32(len(fragments)) {
			t.Fatalf("fragment %d of %d announces itself as %d of %d", index, len(fragments), fragment.GetIndex(), fragment.GetCount())
		}
		if DefaultFragmentPartBytes < len(fragment.GetPart()) {
			t.Fatalf("fragment %d carries %d bytes against §4.6's %d byte part size", index, len(fragment.GetPart()), DefaultFragmentPartBytes)
		}
		assembled = append(assembled, fragment.GetPart()...)
	}
	rebuilt := &protocol.MessageServerResponse{}
	if err := proto.Unmarshal(assembled, rebuilt); err != nil {
		t.Fatalf("the concatenated parts are not a MessageServerResponse: %v", err)
	}
	if !proto.Equal(rebuilt, response) {
		t.Fatal("the concatenated parts and the response the client reassembled are two different messages")
	}
}

// A response past `max_response_bytes` becomes a refusal that still names the request.
//
// The alternative is a response the transport will not carry, which is a request the client never
// hears about at all — and a client with no answer and no reason retries forever.
func TestAResponsePastMaxResponseBytesIsRefusedWithItsOwnRequestId(t *testing.T) {
	fixture := newFixtureWith(t, Config{
		Capabilities: &protocol.Capabilities{MaxResponseBytes: 4096},
	})
	fixture.hello(t)
	fixture.handler.onFetch = func(conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
		return protocol.Reason_REASON_OK, &protocol.FetchResponse{
			Records: []*protocol.Record{{RecordBytes: bytes.Repeat([]byte{0x99}, 20000)}},
		}, nil
	}

	request := fixture.request(&protocol.FetchRequest{GroupId: bytes.Repeat([]byte{2}, 32)})
	response := fixture.await(t, fixture.begin(t, request))
	if response.GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("a 20000 byte response against a 4096 byte cap was answered %v, want REASON_OVERSIZE", response.GetReason())
	}
	if response.GetRequestId() != request.GetRequestId() {
		t.Fatalf("the refusal carries request_id %d, want %d", response.GetRequestId(), request.GetRequestId())
	}
	if response.GetFetch() != nil {
		t.Fatal("the refusal carried the body it was refusing to carry")
	}
}
