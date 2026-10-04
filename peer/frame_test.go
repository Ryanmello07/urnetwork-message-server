package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
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
	if left := fixture.peer.reassembly.holding().reassemblies; left != 0 {
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
	if left := fixture.peer.reassembly.holding().reassemblies; left != 0 {
		t.Fatalf("%d reassembly buffers survive a refusal §4.6 says frees them immediately", left)
	}
}

// Every way §4.6 aborts a reassembly, taken from the enforcement rather than typed out beside it.
//
// The table this loops over is [reassemblyAborts], which is the same table [reassembly.accept]
// asks — so a rule added to the enforcement arrives here needing a case, and a case for a rule
// that no longer exists is a failure too. That is the whole reason the rules are values: the
// version of this test that listed "the four ways §4.6 says a reassembly aborts" was looking at
// five conditions' worth of code, and the one it left out — a `count` that changes mid-reassembly
// — could be deleted with every test in this repository still green. A list is a claim about a
// class, and on this project a hand-written one has understated the class thirteen times.
//
// Each case does two things. It shows the rule refusing, and then it shows the same fragment
// *not* refused by a reassembler built from the table with exactly that rule taken out — which is
// what makes the case a case about its own rule rather than about the rule beside it. Half of
// these conditions are refused by two rules at once if the fragment is chosen carelessly, and a
// case that is caught by a neighbour proves nothing about the rule it is filed under.
//
// A unit test on the reassembler rather than trips through the frame path, because most of these
// are conditions a well-behaved connect client will not put on the wire in order, and one of them
// needs seventeen requests in flight at once.
func TestEveryWaySpecB46AbortsAReassembly(t *testing.T) {
	now := time.Unix(1767225600, 0).UTC()
	clock := func() time.Time { return now }
	clientId := connect.NewId()
	stranger := connect.NewId()

	// what one rule's case needs: a reassembler configured so that this rule can fire, whatever
	// has to be in flight first, and the fragment the rule is expected to refuse
	type abortCase struct {
		build    func() *reassembly
		open     func(t *testing.T, buffers *reassembly)
		from     connect.Id
		fragment *protocol.MessageServerFragment
		reason   protocol.Reason
	}
	plain := func() *reassembly {
		return newReassembly(clock, 4096, 16, DefaultMaxReassemblies, DefaultReassemblyIdle)
	}
	first := func(fragment *protocol.MessageServerFragment) func(t *testing.T, buffers *reassembly) {
		return func(t *testing.T, buffers *reassembly) {
			t.Helper()
			if _, _, reason := buffers.accept(clientId, fragment); reason != protocol.Reason_REASON_OK {
				t.Fatalf("the fragment this case needs in flight was answered %v", reason)
			}
		}
	}

	cases := map[string]abortCase{
		// a count of zero, which is the only index this rule refuses that the out-of-order rule
		// does not also refuse: index 0 is the index a reassembly that does not exist is waiting
		// for, and zero of them is what the sender says there are
		"an index that is not below the fragment count": {
			build:    plain,
			from:     clientId,
			fragment: &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 0},
			reason:   protocol.Reason_REASON_REJECTED,
		},
		// §4.6 aborts rather than buffering a hole, and before the buffer exists that is the same
		// rule read as "a first fragment must be index 0"
		"an index that is not the one this reassembly is waiting for": {
			build:    plain,
			from:     clientId,
			fragment: &protocol.MessageServerFragment{RequestId: 1, Index: 1, Count: 3, Part: []byte("b")},
			reason:   protocol.Reason_REASON_REJECTED,
		},
		// the index is the one this buffer is waiting for and the count is not the one it was
		// opened with, so no other rule fires on it
		"a fragment count that changed mid-reassembly": {
			build:    plain,
			open:     first(&protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 3, Part: []byte("a")}),
			from:     clientId,
			fragment: &protocol.MessageServerFragment{RequestId: 1, Index: 1, Count: 5, Part: []byte("b")},
			reason:   protocol.Reason_REASON_REJECTED,
		},
		"§4.6's concurrent reassemblies for one client": {
			build: func() *reassembly {
				return newReassembly(clock, 4096, 1, DefaultMaxReassemblies, DefaultReassemblyIdle)
			},
			open:     first(&protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("a")}),
			from:     clientId,
			fragment: &protocol.MessageServerFragment{RequestId: 2, Index: 0, Count: 2, Part: []byte("a")},
			reason:   protocol.Reason_REASON_REJECTED,
		},
		// a second client, inside its own §4.6 cap and refused for what the first one holds:
		// the bound above the per-client one, which nothing but this rule can be refusing
		"the reassemblies this server holds for every client at once": {
			build: func() *reassembly {
				return newReassembly(clock, 4096, DefaultReassembliesPerClient, 1, DefaultReassemblyIdle)
			},
			open:     first(&protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("a")}),
			from:     stranger,
			fragment: &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("a")},
			reason:   protocol.Reason_REASON_REJECTED,
		},
		"§5.1 check 1's max_request_bytes over the whole reassembly": {
			build: func() *reassembly {
				return newReassembly(clock, 8, 16, DefaultMaxReassemblies, DefaultReassemblyIdle)
			},
			from:     clientId,
			fragment: &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("nine byte")},
			reason:   protocol.Reason_REASON_OVERSIZE,
		},
	}

	// the class comes out of the program: every rule the enforcement asks needs a case here, and
	// a case here that names no rule of the enforcement is a case about nothing
	for name := range cases {
		if !slices.ContainsFunc(reassemblyAborts, func(rule abortRule) bool { return rule.name == name }) {
			t.Fatalf("this test has a case for %q and §4.6's enforcement has no such rule; the case is testing a condition nothing applies", name)
		}
	}

	for _, rule := range reassemblyAborts {
		current, found := cases[rule.name]
		if !found {
			t.Fatalf("§4.6's enforcement aborts on %q and no case here provokes it; a rule nothing observes is a rule a later edit deletes invisibly", rule.name)
		}

		t.Run(rule.name, func(t *testing.T) {
			buffers := current.build()
			if current.open != nil {
				current.open(t, buffers)
			}
			before := buffers.holding()
			assembled, complete, reason := buffers.accept(current.from, current.fragment)
			if reason != current.reason {
				t.Fatalf("the fragment this rule refuses was answered %v, want %v", reason, current.reason)
			}
			if complete || assembled != nil {
				t.Fatalf("a refusal reported complete=%v with %d bytes for dispatch", complete, len(assembled))
			}
			// §4.6 frees the buffer at the refusal, so a refused fragment leaves the reassembler
			// holding no more than it held before — its own bytes least of all
			after := buffers.holding()
			if before.reassemblies < after.reassemblies || before.bytes < after.bytes {
				t.Fatalf("a refused fragment took the reassembler from %+v to %+v", before, after)
			}

			// and the same fragment against the same table with this one rule missing: if it is
			// still refused, then what refused it above was some other rule and this case says
			// nothing about the rule it is filed under
			without := current.build()
			without.aborts = slices.DeleteFunc(slices.Clone(reassemblyAborts), func(other abortRule) bool { return other.name == rule.name })
			if len(without.aborts) != len(reassemblyAborts)-1 {
				t.Fatalf("removing %q left %d of %d rules", rule.name, len(without.aborts), len(reassemblyAborts))
			}
			if current.open != nil {
				current.open(t, without)
			}
			if _, _, reason := without.accept(current.from, current.fragment); reason != protocol.Reason_REASON_OK {
				t.Fatalf("with %q taken out of §4.6's aborts the same fragment is still answered %v, so what refused it above was another rule and this case observes nothing about this one",
					rule.name, reason)
			}
		})
	}

	// the fifth way state ends is not a refusal and so is not one of the rules above: §4.6's
	// thirty seconds. [TestReassemblyStateExpiresAtSpecB46sBoundAndNotBefore] is where the bound
	// itself is asserted; what is here is that a fragment arriving after it continues nothing.
	t.Run("past §4.6's thirty seconds", func(t *testing.T) {
		buffers := plain()
		if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("a")}); reason != protocol.Reason_REASON_OK {
			t.Fatalf("the first fragment was answered %v", reason)
		}
		now = now.Add(DefaultReassemblyIdle + time.Second)
		defer func() { now = now.Add(-(DefaultReassemblyIdle + time.Second)) }()
		// the second fragment of an expired request opens a new reassembly, so it is refused as
		// a first fragment with a non-zero index rather than appended to a buffer that is gone
		if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 1, Count: 2, Part: []byte("b")}); reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("a fragment arriving after the expiry was appended to the expired buffer: %v", reason)
		}
		if left := buffers.holding().reassemblies; left != 0 {
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

// §5.1 check 1 refuses at exactly the number §4.3.1 advertises, and not at the one beside it.
//
// Every other test of check 1 is far from the bound — 1500 against 512, 12000 against 4096, 6000
// against 2048 — and a bound is not a size, it is a *boundary*. Both of its neighbours are one
// character in [withinLimits] and neither is visible from any of those sizes: `max <= bytes`
// refuses a request of exactly the number Capabilities advertises, which is the size a client
// that reads Capabilities cuts its largest request to, and anything looser serves a request past
// the number this server told every client it enforces. Both were applied to the shipped build
// and the whole suite stayed green.
//
// The number is read out of the HelloResponse rather than typed, because what is being asserted
// is that the advertised cap and the enforced cap are the same *number* — and a literal here
// would be a third number agreeing with neither.
func TestCheckOnesBoundIsExactlyTheNumberCapabilitiesAdvertises(t *testing.T) {
	t.Run("the bound itself, at the number and on both sides of it", func(t *testing.T) {
		for _, max := range []int{1, 512, 4096, DefaultMaxRequestBytes} {
			for _, current := range []struct {
				bytes int
				want  protocol.Reason
			}{
				{max - 1, protocol.Reason_REASON_OK},
				{max, protocol.Reason_REASON_OK},
				{max + 1, protocol.Reason_REASON_OVERSIZE},
			} {
				if got := withinLimits(current.bytes, max); got != current.want {
					t.Errorf("%d bytes against a bound of %d was answered %v, want %v; §5.1 check 1 bounds a request *at* max_request_bytes and refuses past it",
						current.bytes, max, got, current.want)
				}
			}
		}
	})

	t.Run("a request of exactly the advertised cap is served, and one byte more is refused", func(t *testing.T) {
		fixture := newFixtureWith(t, Config{Capabilities: &protocol.Capabilities{MaxRequestBytes: 4096}})
		hello := fixture.hello(t)
		cap := int(hello.GetCapabilities().GetMaxRequestBytes())
		fixture.handler.forget()

		atTheCap := requestOfExactly(t, fixture, cap)
		if response := fixture.await(t, fixture.begin(t, atTheCap)); response.GetReason() != protocol.Reason_REASON_OK {
			t.Fatalf("a request of exactly the advertised max_request_bytes (%d) was answered %v; a client that cuts its requests to the number in Capabilities would be refused at every one of them",
				cap, response.GetReason())
		}
		if calls := fixture.handler.recorded(); len(calls) != 1 {
			t.Fatalf("a request at the cap reached the handler %d times", len(calls))
		}

		fixture.handler.forget()
		pastTheCap := requestOfExactly(t, fixture, cap+1)
		if response := fixture.await(t, fixture.begin(t, pastTheCap)); response.GetReason() != protocol.Reason_REASON_OVERSIZE {
			t.Fatalf("a request of %d bytes against an advertised cap of %d was answered %v", cap+1, cap, response.GetReason())
		}
		if calls := fixture.handler.recorded(); len(calls) != 0 {
			t.Fatalf("a request one byte past the cap reached the handler: %v", calls)
		}
	})

	t.Run("a reassembly of exactly the cap completes, and one byte more is refused", func(t *testing.T) {
		const maxRequestBytes = 64
		clock := newTestClock()
		buffers := newReassembly(clock.time, maxRequestBytes, DefaultReassembliesPerClient, DefaultMaxReassemblies, DefaultReassemblyIdle)
		clientId := connect.NewId()

		assembled, complete, reason := replay(buffers, clientId, 1, bytes.Repeat([]byte{0x41}, maxRequestBytes), 16)
		if reason != protocol.Reason_REASON_OK || !complete || len(assembled) != maxRequestBytes {
			t.Fatalf("a reassembly of exactly the %d byte cap answered %v complete=%v with %d bytes", maxRequestBytes, reason, complete, len(assembled))
		}
		if _, _, reason := replay(buffers, clientId, 2, bytes.Repeat([]byte{0x42}, maxRequestBytes+1), 16); reason != protocol.Reason_REASON_OVERSIZE {
			t.Fatalf("a reassembly of one byte past the %d byte cap answered %v", maxRequestBytes, reason)
		}
		if holding := buffers.holding(); holding != (held{}) {
			t.Fatalf("the boundary left %+v behind", holding)
		}
	})
}

// A request whose §4.2 frame carries exactly this many bytes.
//
// Built by measuring and correcting rather than by adding a constant to a body size: what check 1
// bounds is the marshaled length of the whole MessageServerRequest, and the request_id and the
// protocol version inside it are varints whose own length depends on their value. A test that
// assumed "40 bytes of envelope" would be asserting the bound one byte to the side of where it
// is, which is the whole thing this helper exists to get right.
func requestOfExactly(t *testing.T, fixture *fixture, want int) *protocol.MessageServerRequest {
	t.Helper()
	request := fixture.request(filler(want))
	body := request.GetFetch()
	for range 8 {
		size := proto.Size(request)
		if size == want {
			return request
		}
		length := len(body.GetReqAuth()) + want - size
		if length < 0 {
			t.Fatalf("a request of %d bytes is smaller than this arm's own envelope", want)
		}
		body.ReqAuth = bytes.Repeat([]byte{0x55}, length)
	}
	t.Fatalf("no request of exactly %d bytes could be built; the boundary below would be asserted at a size that is not the bound", want)
	return nil
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

// A fragmented request that assembles to nothing is answered, and answered the same way the
// unfragmented one is.
//
// `proto.Marshal(&MessageServerRequest{})` is zero bytes, so an empty request is a well-formed
// thing a client can fragment without doing anything malformed at all. Reassembly used to report
// completion by handing back a non-nil slice, and an empty request assembles to a nil one: the
// reassembly *completed* — its state freed, its per-client count decremented — while answering
// the sentinel that means "more fragments are expected". The frame was received, never served,
// never answered and never counted as dropped, which is precisely what peer/doc.go says no path
// through this package does.
//
// The unfragmented control is what makes it a comparison rather than an expectation: the same
// zero bytes in a request frame decode and are refused REASON_REJECTED, and §4.6 is not entitled
// to a second opinion about what an empty request means.
func TestAFragmentedRequestThatAssemblesToNothingIsAnswered(t *testing.T) {
	fixture := newFixture(t)

	empty, err := proto.Marshal(&protocol.MessageServerRequest{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("an empty MessageServerRequest marshals to %d bytes, so nothing below is about the case this test is named for", len(empty))
	}

	// the control, unfragmented. request_id 0 is what those zero bytes decode to, and it is what
	// a response to them has to carry
	control := fixture.waitFor(0)
	fixture.sendFrame(t, &protocol.Frame{
		MessageType:  protocol.MessageType_MessageMessageServerRequest,
		MessageBytes: empty,
	})
	unfragmented := fixture.await(t, control)
	if unfragmented.GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("zero bytes in a request frame were answered %v; §4.5's non-specific refusal is what a request with no body arm gets", unfragmented.GetReason())
	}

	for _, count := range []uint32{1, 2} {
		before := fixture.peer.Stats()
		waiter := fixture.waitFor(0)
		for index := range count {
			fixture.sendFragment(t, &protocol.MessageServerFragment{RequestId: 0, Index: index, Count: count})
		}
		fragmented := fixture.await(t, waiter)

		if fragmented.GetReason() != unfragmented.GetReason() {
			t.Fatalf("%d empty fragments assembled to a request answered %v, and the same zero bytes unfragmented were answered %v",
				count, fragmented.GetReason(), unfragmented.GetReason())
		}
		after := fixture.peer.Stats()
		if after.RequestsServed != before.RequestsServed+1 {
			t.Fatalf("%d empty fragments assembled and %d requests were served; a completed reassembly is a request",
				count, after.RequestsServed-before.RequestsServed)
		}
		if after.FramesDropped != before.FramesDropped {
			t.Fatalf("%d empty fragments dropped %d frames; every one of them decoded, so nothing here is a frame this server could not read",
				count, after.FramesDropped-before.FramesDropped)
		}
	}
}

// §4.6's refusals are not sent on connect's receive loop.
//
// connect invokes the receive callback inline on the single loop that reads every peer's frames
// (transfer.go:1334), and [Peer.send] is a SendWithTimeout whose only bound is
// [Config.SendTimeout] — thirty seconds by default, and ended by the *remote* peer's read rate.
// A reassembly refusal sent from the callback therefore hands a client that reads nothing a
// thirty-second hold on every other client's frames, repeatedly, for the price of one 2 KB
// frame. [Config.Workers]' backpressure argument does not cover it: that argument is about a
// queue an internal component drains, and this is a network send a remote peer drains.
//
// It is measured rather than argued. connect takes about thirty frames into its own send buffer
// for a route nobody reads and then blocks for the whole timeout, so a callback that sent
// inline would spend tens of timeouts here and one that queues spends none.
//
// The batch is deliberately many times the refusal queue rather than a fraction of it. A queue in
// front of one consumer is a delay of QueueDepth frames and not a bound: [Peer.refuseLoop] is a
// single consumer by design and drains at one refusal per SendTimeout against a client that reads
// nothing, so past the depth every further fragment costs the whole server a timeout again. The
// version of this test that shipped sized the queue at four times the batch — the one arrangement
// in which the queue cannot fill — and passed against a build where 200 frames held the receive
// path for exactly 100 send timeouts. That the queue does fill here is asserted, so this cannot
// go back to passing vacuously.
func TestASpecB46RefusalIsNotSentOnConnectsReceiveLoop(t *testing.T) {
	const sendTimeout = 300 * time.Millisecond
	const queueDepth = 8
	const frameCount = 32 * queueDepth

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverClient := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), connect.DefaultClientSettings())
	t.Cleanup(serverClient.Close)

	// a client whose read side has stopped: its route exists and nothing ever drains it
	client := connect.NewId()
	serverClient.ContractManager().AddNoContractPeer(client)
	unread := make(connect.Route)
	serverClient.RouteManager().UpdateTransport(
		connect.NewSendClientTransport(connect.DestinationId(client)), []connect.Route{unread})

	connections, err := NewConnections(rand.Reader, time.Now, 0)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	checks, err := NewChecks(connections, DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	served, err := New(Config{
		Client:          serverClient,
		Handler:         &recordingHandler{},
		Connections:     connections,
		Checks:          checks,
		Capabilities:    &protocol.Capabilities{},
		ProtocolVersion: fixtureProtocolVersion,
		ServerId:        make([]byte, 16),
		SendTimeout:     sendTimeout,
		QueueDepth:      queueDepth,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(served.Close)

	// §4.6 aborts a reassembly whose `count` names no fragments at all, so every one of these
	// is a refusal carrying a request_id of its own
	frames := make([]*protocol.Frame, 0, frameCount)
	for index := range frameCount {
		body, err := connect.ProtoMarshal(&protocol.MessageServerFragment{RequestId: uint64(index) + 1})
		if err != nil {
			t.Fatalf("ProtoMarshal: %v", err)
		}
		frames = append(frames, &protocol.Frame{
			MessageType:  protocol.MessageType_MessageMessageServerFragment,
			MessageBytes: body,
		})
	}

	// what connect does with a batch: this call, on the loop, with the frames borrowed for its
	// duration (transfer.go:146). On its own goroutine so that a build which does hold the loop
	// fails at the budget rather than tens of timeouts later
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		served.receive(connect.TransferPath{SourceId: client}, frames, connect.Peer{})
		done <- time.Since(start)
	}()

	var elapsed time.Duration
	select {
	case elapsed = <-done:
	case <-time.After(sendTimeout):
		t.Fatalf("connect's receive loop has been inside one batch of %d malformed fragments for a whole SendTimeout (%v) and has not come out; every other peer's frames are behind it, and the batch cost this client %d bytes",
			frameCount, sendTimeout, frameCount*len(frames[0].GetMessageBytes()))
	}
	if sendTimeout <= elapsed {
		t.Fatalf("connect's receive loop spent %v on %d malformed fragments from a client that reads nothing; the loop must not wait on a send at all, and one whole SendTimeout (%v) is what waiting on one costs",
			elapsed, frameCount, sendTimeout)
	}

	if received := served.Stats().FramesReceived; received != frameCount {
		t.Fatalf("%d of %d fragment frames reached the receive path, so the timing above is about a shorter batch than this test sent", received, frameCount)
	}
	// the arrangement, asserted rather than assumed: unless the refusal queue actually filled,
	// this test is measuring the case where a bounded queue is enough and not the case where it
	// is only a delay
	dropped := served.Stats().RefusalsDropped
	if dropped == 0 {
		t.Fatalf("%d refusals were decided against a queue of %d drained by one consumer sending to a client that reads nothing, and none was dropped; the queue never filled, so nothing here observes what happens past it",
			frameCount, queueDepth)
	}
	t.Logf("%d fragment frames on the receive loop in %v: %d refusals queued, %d dropped for want of a queue slot", frameCount, elapsed, uint64(frameCount)-dropped, dropped)
}

// The refusals of one aborted reassembly reach the client in the order this server decided them.
//
// §4.6 abandons a reassembly the moment it would pass `max_request_bytes`, and every fragment of
// that request which arrives afterwards names a reassembly that is gone — so it is answered with
// §4.5's non-specific REASON_REJECTED, and all of them carry the request's own `request_id`. A
// client correlating by `request_id` keeps the first one it sees.
//
// So the specific refusal must not be overtaken by the generic ones behind it. That is what
// decides the shape of [Peer.refuseLoop]: one consumer of one FIFO, rather than the worker pool
// that answers requests, where sixty refusals would be sixty goroutines racing to the send path
// and the client would be told REASON_REJECTED for a request whose actual fault was a bound it
// could have read out of Capabilities.
func TestTheRefusalsOfOneAbortedReassemblyKeepTheirOrder(t *testing.T) {
	fixture := newFixtureWith(t, Config{Capabilities: &protocol.Capabilities{MaxRequestBytes: 2048}})
	fixture.hello(t)
	fixture.forgetFrames()

	// two fragments fit inside the cap, the third passes it and aborts, and every one after
	// that is refused for naming a reassembly that no longer exists
	request := fixture.request(filler(60000))
	waiter := fixture.waitFor(request.GetRequestId())
	fixture.sendFragments(t, request, 1024)

	if response := fixture.await(t, waiter); response.GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("the first refusal the client correlated was %v; the fragment that broke the cap is what the client has to be told about", response.GetReason())
	}

	responses := fixture.responsesFor(t, request.GetRequestId(), 32)
	if responses[0].GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("the first of %d responses for this request_id was %v; §4.6's specific refusal was overtaken by the generic ones behind it",
			len(responses), responses[0].GetReason())
	}
	for index, response := range responses[1:] {
		if response.GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("response %d of this aborted reassembly was %v; every fragment after the abort names a reassembly that is gone, and §4.5's non-specific refusal is what that gets",
				index+1, response.GetReason())
		}
	}
}
