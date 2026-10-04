package peer

import (
	"bytes"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ── the frame path exists ────────────────────────────────────────────────────────────────

// §4.2's binding, end to end: a request marshaled into a frame by one connect client is
// dispatched by another and answered on the same path.
//
// It is the first test in the file because everything below it is a claim about a path that has
// to exist first. A failure here is the wiring, not the dispatch.
func TestARequestTravelsTheFramePathAndIsAnswered(t *testing.T) {
	fixture := newFixture(t)

	hello := fixture.hello(t)
	if len(hello.GetServerNonce()) != ServerNonceBytes {
		t.Fatalf("HelloResponse issued a %d byte server_nonce; §4.3.1 and spec A §5.7 both say 32",
			len(hello.GetServerNonce()))
	}
	if hello.GetCapabilities() == nil {
		t.Fatal("HelloResponse carried no Capabilities; §4.3.1 calls it the whole of the server-advertised contract")
	}

	response := fixture.call(t, &protocol.SubmitRequest{GroupId: bytes.Repeat([]byte{1}, 32)})
	if response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the submit was answered %v, want REASON_OK", response.GetReason())
	}
	if response.GetSubmit() == nil {
		t.Fatal("the submit was answered REASON_OK with no SubmitResponse in it")
	}
}

// ── request_id ───────────────────────────────────────────────────────────────────────────

// Every response carries the `request_id` of the request it answers, under real concurrency.
//
// The concurrency is the test rather than decoration. Responses are sent by whichever worker
// finished first, so a dispatcher that took the request_id from anything but the request it is
// answering — a counter, the last one it saw, the connection — produces the right answer under a
// serial test and a correlation bug under load. Each request here names an arm and a marker only
// it uses, and the assertion is that every answer's body matches its own request rather than
// somebody else's.
func TestEveryResponseCarriesItsOwnRequestIdUnderConcurrency(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)

	// a handler that finishes in a deliberately scrambled order, so the responses cannot arrive
	// in the order the requests were sent and correlation is the only thing that can work
	fixture.handler.onFetch = func(conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
		time.Sleep(time.Duration(request.GetSinceRecordId()%7) * 3 * time.Millisecond)
		return protocol.Reason_REASON_OK, &protocol.FetchResponse{HighWaterRecordId: request.GetSinceRecordId()}, nil
	}

	const requests = 64
	waiters := map[uint64]chan *protocol.MessageServerResponse{}
	markers := map[uint64]uint64{}
	for index := range requests {
		// the marker is the fetch's own since_record_id, echoed by the handler into the
		// response body: a response landing on the wrong request_id shows up as a body that
		// belongs to another request rather than as a missing answer
		marker := uint64(1000 + index)
		request := fixture.request(&protocol.FetchRequest{GroupId: bytes.Repeat([]byte{2}, 32), SinceRecordId: marker})
		markers[request.GetRequestId()] = marker
		waiters[request.GetRequestId()] = fixture.begin(t, request)
	}

	group := sync.WaitGroup{}
	for requestId, waiter := range waiters {
		group.Add(1)
		go func() {
			defer group.Done()
			response := fixture.await(t, waiter)
			if response.GetRequestId() != requestId {
				t.Errorf("a response correlated to request %d carries request_id %d", requestId, response.GetRequestId())
				return
			}
			if response.GetFetch().GetHighWaterRecordId() != markers[requestId] {
				t.Errorf("request %d asked from record %d and was answered a body from record %d; the request_id and the body belong to two different requests",
					requestId, markers[requestId], response.GetFetch().GetHighWaterRecordId())
			}
		}()
	}
	group.Wait()

	if uncorrelated := fixture.uncorrelated(); len(uncorrelated) != 0 {
		t.Fatalf("%d responses arrived carrying a request_id no request used", len(uncorrelated))
	}
	if served := fixture.peer.Stats().RequestsServed; served != requests+1 {
		t.Fatalf("the peer served %d requests for %d sent plus one Hello", served, requests)
	}
}

// Two requests in flight at once are two requests, even when they are the same request twice.
//
// A dispatcher keyed on anything but `request_id` — the arm, the connection, the client — merges
// these into one, and the merge is invisible unless both are outstanding at the same moment.
func TestTwoIdenticalRequestsInFlightAreAnsweredTwice(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)

	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	fixture.handler.onFetch = func(conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
		entered <- struct{}{}
		<-release
		return protocol.Reason_REASON_OK, &protocol.FetchResponse{HighWaterRecordId: request.GetSinceRecordId()}, nil
	}

	body := &protocol.FetchRequest{GroupId: bytes.Repeat([]byte{3}, 32), SinceRecordId: 7}
	first := fixture.begin(t, fixture.request(proto.Clone(body)))
	second := fixture.begin(t, fixture.request(proto.Clone(body)))

	// both are inside the handler before either is allowed to answer, so the two responses
	// cannot be one response counted twice
	for range 2 {
		select {
		case <-entered:
		case <-time.After(30 * time.Second):
			t.Fatal("only one of two identical requests reached the handler; they were merged somewhere")
		}
	}
	close(release)

	one, two := fixture.await(t, first), fixture.await(t, second)
	if one.GetRequestId() == two.GetRequestId() {
		t.Fatalf("two requests were both answered with request_id %d", one.GetRequestId())
	}
	for _, response := range []*protocol.MessageServerResponse{one, two} {
		if response.GetFetch().GetHighWaterRecordId() != 7 {
			t.Fatalf("a response to a fetch from record 7 carries %d", response.GetFetch().GetHighWaterRecordId())
		}
	}
}

// ── the dispatch ─────────────────────────────────────────────────────────────────────────

// Each arm of §4.3's oneof reaches its own handler, and its answer comes back in its own arm.
//
// Two failures are in scope and one test cannot be split without losing the second. A table that
// sent every arm to one handler is caught by the recorded call names; a table with two arms
// swapped is caught by the same, because each arm's handler records a different name. The
// response side is checked at the same time: a body placed in the wrong arm of the response oneof
// is a response the client parses as another operation's answer.
func TestEachArmReachesItsOwnHandlerAndAnswersInItsOwnArm(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)
	fixture.handler.forget()

	for _, current := range []struct {
		arm      string
		body     proto.Message
		answered func(*protocol.MessageServerResponse) bool
	}{
		{
			arm:      "create_group",
			body:     &protocol.CreateGroupRequest{GroupId: bytes.Repeat([]byte{4}, 32)},
			answered: func(response *protocol.MessageServerResponse) bool { return response.GetCreateGroup() != nil },
		},
		{
			arm:      "submit",
			body:     &protocol.SubmitRequest{GroupId: bytes.Repeat([]byte{5}, 32)},
			answered: func(response *protocol.MessageServerResponse) bool { return response.GetSubmit() != nil },
		},
		{
			arm:      "fetch",
			body:     &protocol.FetchRequest{GroupId: bytes.Repeat([]byte{6}, 32), SinceRecordId: 11},
			answered: func(response *protocol.MessageServerResponse) bool { return response.GetFetch() != nil },
		},
	} {
		t.Run(current.arm, func(t *testing.T) {
			fixture.handler.forget()
			response := fixture.call(t, current.body)
			if response.GetReason() != protocol.Reason_REASON_OK {
				t.Fatalf("%s was answered %v", current.arm, response.GetReason())
			}
			calls := fixture.handler.recorded()
			if len(calls) != 1 || calls[0].arm != current.arm {
				t.Fatalf("a %s request reached %v; §4.3's arms are not interchangeable", current.arm, calls)
			}
			if !current.answered(response) {
				t.Fatalf("a %s request was answered with a body in another arm of MessageServerResponse.body: %v", current.arm, response)
			}
		})
	}
}

// Every arm §4.3 defines is either served by this build or declared unbuilt, and no arm is both.
//
// The class comes out of the compiled descriptor rather than out of a list here, which is the
// half of this that keeps working: a fifteenth arm added to message.proto is an arm this build
// would answer REASON_INTERNAL to, and a list in this file would still be green.
func TestEveryArmOfTheRequestOneofIsServedOrDeclared(t *testing.T) {
	fixture := newFixture(t)

	arms := bodyArmsOf((&protocol.MessageServerRequest{}).ProtoReflect().Descriptor())
	if len(arms) < 15 {
		t.Fatalf("MessageServerRequest.body was read as having %d arms; §4.3 declares fifteen, so the descriptor walk has stopped finding them", len(arms))
	}
	served := []string{}
	for _, current := range fixture.peer.routes {
		served = append(served, current.name)
	}
	slices.Sort(served)
	t.Logf("§4.3's request oneof has %d arms; this build serves %d: %v", len(arms), len(served), served)

	declared := []string{}
	for _, notBuilt := range fixture.peer.NotBuilt() {
		declared = append(declared, notBuilt.What)
	}
	for _, arm := range arms {
		_, served := fixture.peer.routes[arm.Message().FullName()]
		// the declaration opens by naming the arm, so the match is anchored rather than a
		// substring: "fetch" is inside "recovery_fetch" and "wrap_fetch", and a contains-match
		// would report the one arm this build does serve as declared unbuilt
		opening := "the " + string(arm.Name()) + " arm of MessageServerRequest.body"
		named := slices.ContainsFunc(declared, func(what string) bool { return strings.HasPrefix(what, opening) })
		switch {
		case served && named:
			t.Fatalf("the %s arm is both served and declared unbuilt, so one of the two is a lie", arm.Name())
		case !served && !named:
			t.Fatalf("the %s arm (op %d) is neither served nor declared unbuilt; an arm answered REASON_INTERNAL with nothing written down is a hole with no address",
				arm.Name(), arm.Number())
		}
	}
}

// ── refusals, never panics ───────────────────────────────────────────────────────────────

// An absent body, an unknown arm, a malformed frame and a raw frame are all refusals or drops.
//
// This is the outermost layer of a network service: every one of these is a frame anybody who can
// address one gets to send, and a panic on any of them is an availability bug reachable by
// everybody. The two that carry a `request_id` are answered; the two that do not are dropped and
// counted, because a response has to be correlated to something.
func TestMalformedInboundIsRefusedOrDroppedAndNeverPanics(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)

	t.Run("no body at all", func(t *testing.T) {
		response := fixture.await(t, fixture.begin(t, &protocol.MessageServerRequest{RequestId: 90001}))
		if response.GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("a request with no body was answered %v, want REASON_REJECTED", response.GetReason())
		}
	})

	t.Run("an arm this descriptor does not know", func(t *testing.T) {
		// field 60 is inside no arm of §4.3's oneof, so it lands in unknown fields and the
		// oneof is unset — which is the same thing on the wire as no body at all, and is
		// answered the same way
		request := &protocol.MessageServerRequest{RequestId: 90002}
		unknown := protowire.AppendTag(nil, 60, protowire.BytesType)
		unknown = protowire.AppendBytes(unknown, []byte{0x08, 0x01})
		request.ProtoReflect().SetUnknown(protoreflect.RawFields(unknown))
		response := fixture.await(t, fixture.begin(t, request))
		if response.GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("a request naming an unknown arm was answered %v, want REASON_REJECTED", response.GetReason())
		}
	})

	t.Run("bytes that are not a protobuf", func(t *testing.T) {
		before := fixture.peer.Stats()
		fixture.sendFrame(t, &protocol.Frame{
			MessageType:  protocol.MessageType_MessageMessageServerRequest,
			MessageBytes: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		})
		waitForDrop(t, fixture, before.FramesDropped+1)
	})

	t.Run("a raw frame, which §4.2 says this binding never sends", func(t *testing.T) {
		before := fixture.peer.Stats()
		body, err := connect.ProtoMarshal(&protocol.MessageServerRequest{RequestId: 90003})
		if err != nil {
			t.Fatalf("ProtoMarshal: %v", err)
		}
		fixture.sendFrame(t, &protocol.Frame{
			MessageType:  protocol.MessageType_MessageMessageServerRequest,
			MessageBytes: body,
			Raw:          true,
		})
		waitForDrop(t, fixture, before.FramesDropped+1)
	})

	// the server is still serving after all four
	if response := fixture.call(t, &protocol.FetchRequest{GroupId: bytes.Repeat([]byte{7}, 32)}); response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("after four malformed frames a good request was answered %v", response.GetReason())
	}
}

func waitForDrop(t *testing.T, fixture *fixture, want uint64) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if want <= fixture.peer.Stats().FramesDropped {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the peer dropped %d frames, want at least %d", fixture.peer.Stats().FramesDropped, want)
}

// ── the version gate ─────────────────────────────────────────────────────────────────────

// A Hello that does not name this server's version opens no connection.
//
// The second half is the one worth having: a refused Hello that had nonetheless minted a nonce
// would leave a connection live under a protocol neither side agreed on, and would let a client
// reach every other arm by saying Hello wrong.
func TestAHelloThatNamesNoSharedVersionIssuesNoNonce(t *testing.T) {
	fixture := newFixture(t)

	for _, versions := range [][]uint32{nil, {}, {fixtureProtocolVersion + 1}, {0}} {
		response := fixture.call(t, &protocol.HelloRequest{SupportedVersions: versions})
		if response.GetReason() != protocol.Reason_REASON_UNSUPPORTED_VERSION {
			t.Fatalf("a Hello naming versions %v was answered %v, want REASON_UNSUPPORTED_VERSION", versions, response.GetReason())
		}
		if response.GetHello() != nil {
			t.Fatalf("a refused Hello carried a HelloResponse: %v", response.GetHello())
		}
	}
	if count := fixture.connections.Count(); count != 0 {
		t.Fatalf("%d connections are live after four refused Hellos; a refused Hello issues no nonce", count)
	}

	// and a request on the connection that was never opened is refused rather than served
	response := fixture.call(t, &protocol.SubmitRequest{GroupId: bytes.Repeat([]byte{8}, 32)})
	if response.GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a submit with no connection was answered %v, want REASON_REJECTED", response.GetReason())
	}
	if calls := fixture.handler.recorded(); len(calls) != 0 {
		t.Fatalf("a submit with no connection reached the handler: %v", calls)
	}
}

// ── what this build does not do ──────────────────────────────────────────────────────────

// The two advertisements a Hello cannot carry are absent and declared, not quietly omitted.
func TestAHelloCarriesNoKeyChainAndSaysSo(t *testing.T) {
	fixture := newFixture(t)
	hello := fixture.hello(t)

	if len(hello.GetServerKeys()) != 0 || hello.GetKtGossip() != nil {
		t.Fatalf("this build advertised a key chain or a gossiped STH, and it holds neither key: %v", hello)
	}
	declared := false
	for _, notBuilt := range fixture.peer.NotBuilt() {
		if notBuilt.Section == unsignedHello.Section && notBuilt.What == unsignedHello.What {
			declared = true
		}
	}
	if !declared {
		t.Fatalf("HelloResponse carries no server_keys and nothing declares it; §10.1's readiness endpoint would read this build as complete: %v", fixture.peer.NotBuilt())
	}
}

// A peer with no connection idle bound declares the two things that costs.
//
// This test is about the declaration and only about the declaration. That a configured bound is
// a bound rather than a way to make the declaration go away is a separate claim, and it is
// asserted separately — see TestANonceDoesNotOutliveTheConnectionIdleBound and
// TestTheLiveConnectionMapIsBoundedByTheIdleBound. The two used to be one: this test passed on
// a build where Config.ConnectionIdle reached nothing but this branch, so setting it removed
// the warning without creating the bound the warning was about.
func TestAPeerWithNoConnectionIdleBoundDeclaresIt(t *testing.T) {
	fixture := newFixture(t)
	if !slices.ContainsFunc(fixture.peer.NotBuilt(), func(entry api.NotBuilt) bool { return entry.What == unsweptConnections.What }) {
		t.Fatalf("Config.ConnectionIdle is zero and nothing says so: %v", fixture.peer.NotBuilt())
	}

	bounded := newFixtureWith(t, Config{ConnectionIdle: time.Hour})
	if slices.ContainsFunc(bounded.peer.NotBuilt(), func(entry api.NotBuilt) bool { return entry.What == unsweptConnections.What }) {
		t.Fatalf("Config.ConnectionIdle is an hour and this build still declares the bound missing: %v", bounded.peer.NotBuilt())
	}
}

// §5.1 check 4 is still absent, and still says so.
//
// peer performs check 1 and half of check 2, and the risk in that is exactly that somebody
// tidies check 4's declaration away with them. It is answered by the type api named for what it
// does not do, and it is reachable from [Peer.NotBuilt] in a real wiring.
func TestTheRateLimitCheckIsStillDeclaredAbsent(t *testing.T) {
	fixture := newFixture(t)

	found := false
	for _, entry := range fixture.checks.NotBuilt() {
		if entry.Check == 4 {
			found = true
			t.Logf("§5.1 check 4: %s", entry)
		}
	}
	if !found {
		t.Fatalf("§5.1 check 4 is not declared unbuilt by this build's front checks: %v", fixture.checks.NotBuilt())
	}
	if reason := fixture.checks.WithinRateLimits(fixture.ctx, &api.Connection{}, 12); reason != protocol.Reason_REASON_OK {
		t.Fatalf("check 4 answered %v; the point of ChecksNotImplemented is that it passes and says so, not that it refuses", reason)
	}
}

// ── shutdown ─────────────────────────────────────────────────────────────────────────────

// Close returns with requests in flight, and nothing is dispatched after it.
//
// The hang this guards is specific. connect's Client.Send is SendWithTimeout(-1), which blocks
// until the *client's* context is done — and a peer does not own its client's context, so a
// worker parked in a send would still be parked when Close came to wait for it. What makes Close
// terminate is that the send is bounded and carries this peer's own context.
//
// The second half matters as much: a Close that returned while workers went on answering would be
// a drain of §2.3 that drained nothing.
func TestCloseReturnsWithRequestsInFlightAndDispatchesNothingAfter(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	fixture.handler.onFetch = func(conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return protocol.Reason_REASON_OK, &protocol.FetchResponse{HighWaterRecordId: request.GetSinceRecordId()}, nil
	}

	// more requests than there are workers, so the queue is occupied as well as the workers
	for index := range 32 {
		fixture.sendRequest(t, fixture.request(&protocol.FetchRequest{
			GroupId:       bytes.Repeat([]byte{0xC0}, 32),
			SinceRecordId: uint64(index),
		}))
	}
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("no request reached the handler")
	}

	done := make(chan struct{})
	go func() {
		close(release)
		fixture.peer.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Close did not return with requests in flight")
	}

	before := len(fixture.handler.recorded())
	fixture.sendRequest(t, fixture.request(&protocol.FetchRequest{GroupId: bytes.Repeat([]byte{0xC1}, 32)}))
	time.Sleep(250 * time.Millisecond)
	if after := len(fixture.handler.recorded()); after != before {
		t.Fatalf("%d requests were served after Close returned", after-before)
	}

	// and closing again is not a second shutdown, because a peer is closed by whichever of a
	// drain, a failed startup and a cleanup notices first
	fixture.peer.Close()
}

// ── §4.3.1's version, on every request that names one ────────────────────────────────────

// Every arm §5.1's pipeline owns refuses a request that names a protocol version this server
// does not speak, and serves one that names none.
//
// §4.3.1 negotiates the version once, at Hello, and `MessageServerRequest.protocol_version` is
// on every request after it. A build that carried the field and ignored it would be serving
// requests under a version neither side agreed on and answering them in a format the client is
// not reading — which is a wire-compatibility break that presents as data corruption rather than
// as a refusal.
//
// The class comes out of the dispatch table rather than out of a list here: which arms this gate
// covers is exactly which arms run inside the pipeline, and an arm added to that table tomorrow
// is covered by this loop the day it lands. Hello is deliberately outside it and is asserted
// outside it — a connection is what Hello creates, so §4.3.1 negotiates there through
// `supported_versions` instead, and the arm bodies are built from the descriptor so that adding
// one needs no edit here.
func TestEveryPipelineArmRefusesAProtocolVersionThisServerDoesNotSpeak(t *testing.T) {
	fixture := newFixture(t)
	fixture.hello(t)

	// an arm of §4.3's oneof, filled in through the descriptor rather than by naming its type
	inArm := func(arm protoreflect.FieldDescriptor, version uint32) *protocol.MessageServerRequest {
		request := &protocol.MessageServerRequest{
			RequestId:       fixture.nextRequestId.Add(1),
			ProtocolVersion: version,
		}
		request.ProtoReflect().Mutable(arm)
		return request
	}

	gated := 0
	for _, arm := range bodyArmsOf((&protocol.MessageServerRequest{}).ProtoReflect().Descriptor()) {
		current, served := fixture.peer.routes[arm.Message().FullName()]
		if !served || !current.pipeline {
			continue
		}
		gated++

		fixture.handler.forget()
		refused := fixture.await(t, fixture.begin(t, inArm(arm, fixtureProtocolVersion+1)))
		if refused.GetReason() != protocol.Reason_REASON_UNSUPPORTED_VERSION {
			t.Fatalf("a %s naming protocol version %d was answered %v; this server speaks %d and §4.3.1 negotiated that at Hello",
				arm.Name(), fixtureProtocolVersion+1, refused.GetReason(), fixtureProtocolVersion)
		}
		if calls := fixture.handler.recorded(); len(calls) != 0 {
			t.Fatalf("a %s naming a version this server does not speak reached the handler %d times", arm.Name(), len(calls))
		}

		// zero is a field the client did not set, and §4.3.1 does not require one on every
		// request. It is the control that says the refusal above is about the value and not
		// about the presence of the gate
		unset := fixture.await(t, fixture.begin(t, inArm(arm, 0)))
		if unset.GetReason() != protocol.Reason_REASON_OK {
			t.Fatalf("a %s that named no protocol version at all was answered %v; an unset field is not a mismatch", arm.Name(), unset.GetReason())
		}
		matched := fixture.await(t, fixture.begin(t, inArm(arm, fixtureProtocolVersion)))
		if matched.GetReason() != protocol.Reason_REASON_OK {
			t.Fatalf("a %s naming this server's own version was answered %v", arm.Name(), matched.GetReason())
		}
	}
	if gated == 0 {
		t.Fatal("no arm of §4.3's oneof runs inside the pipeline in this build, so the loop above asserted nothing")
	}
	t.Logf("§4.3.1's per-request version gate covers %d pipeline arms", gated)

	// and Hello, which is outside it: a connection is what Hello creates, so there is nothing for
	// check 2 to resolve and nothing for this gate to have been negotiated against yet. §4.3.1
	// negotiates there on supported_versions, which
	// TestAHelloThatNamesNoSharedVersionIssuesNoNonce is about
	hello := &protocol.MessageServerRequest{
		RequestId:       fixture.nextRequestId.Add(1),
		ProtocolVersion: fixtureProtocolVersion + 1,
	}
	if err := setRequestBody(hello, &protocol.HelloRequest{SupportedVersions: []uint32{fixtureProtocolVersion}}); err != nil {
		t.Fatalf("setRequestBody: %v", err)
	}
	if response := fixture.await(t, fixture.begin(t, hello)); response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("a Hello whose envelope named version %d and whose supported_versions named %d was answered %v; §4.3.1 negotiates on the list, and the envelope field is what the list has not agreed yet",
			fixtureProtocolVersion+1, fixtureProtocolVersion, response.GetReason())
	}
}

// The receive callback's backpressure ends when the peer does.
//
// [Peer.enqueue] blocks on a full queue on purpose — that is connect's own documented mechanism,
// and it is what keeps this server from inventing a refusal §4.5 has no code for. What makes it
// safe to block is that the wait also ends on this peer's context: without that escape the
// callback is parked on a channel whose readers have all returned, and connect's single receive
// loop — the one that reads every peer's frames — is wedged for the life of the process by a
// shutdown, which is the moment a drain of §2.3 is supposed to be finishing.
//
// One worker, a queue of one, and a handler that does not return: real goroutines, real channels,
// and the block is confirmed before Close is called, so a version of this that never blocked
// would fail here rather than pass vacuously.
func TestABlockedEnqueueIsReleasedWhenThePeerCloses(t *testing.T) {
	fixture := newFixtureWith(t, Config{Workers: 1, QueueDepth: 1})
	fixture.hello(t)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	fixture.handler.onSubmit = func(conn *api.Connection, request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return protocol.Reason_REASON_OK, &protocol.SubmitResponse{}, nil
	}

	// the one worker, occupied
	fixture.sendRequest(t, fixture.request(&protocol.SubmitRequest{GroupId: bytes.Repeat([]byte{0x21}, 32)}))
	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the only worker never reached the handler, so the queue below is not full")
	}

	waiting := job{arrived: &inbound{clientId: fixture.clientClient.ClientId()}, request: &protocol.MessageServerRequest{}}
	// the one queue slot, filled
	fixture.peer.enqueue(waiting)

	blocked := make(chan struct{})
	go func() {
		fixture.peer.enqueue(waiting)
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("an enqueue onto a full queue behind an occupied worker returned at once; nothing below is testing the escape from a wait that did not happen")
	case <-time.After(250 * time.Millisecond):
	}

	go fixture.peer.Close()
	select {
	case <-blocked:
	case <-time.After(30 * time.Second):
		t.Fatal("an enqueue blocked on a full queue never returned after Close; connect's receive loop is wedged there for the life of the process, and it is the loop that reads every peer's frames")
	}
	once.Do(func() { close(release) })
}
