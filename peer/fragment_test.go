package peer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"google.golang.org/protobuf/proto"
)

// ── what §4.6 is, as numbers ─────────────────────────────────────────────────────────────

// §4.6's bounds, transcribed from the spec in exactly one place.
//
// Every other test in this file derives its numbers from the configuration rather than typing
// them, which is what makes those tests follow a build that has been tuned. That leaves nobody
// asserting the defaults are §4.6's own, so this does — and it is the only place a literal from
// the spec appears.
func TestSpecB46sBoundsAreTheNumbersThisBuildHolds(t *testing.T) {
	for _, bound := range []struct {
		what string
		got  int
		want int
	}{
		{"§4.6's `part` size ceiling, the 2048 of min(peer_advertised_frame_budget, 2048)", MaxFragmentPartBytes, 2048},
		{"§4.6's concurrent reassemblies per client", DefaultReassembliesPerClient, 16},
		{"§4.6's working assumption for max_request_bytes, which is the reassembly cap", DefaultMaxRequestBytes, 131072},
		{"§4.3.1's max_response_bytes, the matching cap on the way out", DefaultMaxResponseBytes, 1048576},
	} {
		if bound.got != bound.want {
			t.Errorf("this build holds %d for %s; spec B says %d", bound.got, bound.what, bound.want)
		}
	}
	if DefaultReassemblyIdle != 30*time.Second {
		t.Errorf("reassembly state expires after %v; §4.6 says 30 s", DefaultReassemblyIdle)
	}
}

// ── the concurrency cap ──────────────────────────────────────────────────────────────────

// §4.6's per-client cap is the configured one, and the slot comes back when a reassembly ends.
//
// The cap is read back out of the reassembler rather than typed, and the table runs it at three
// values, because a test that says sixteen tests the number in the test: raise the configuration
// and a hand-written 16 keeps passing while sixteen more buffers per client go unchecked. Three
// values also mean the loop below cannot be a coincidence of one arrangement.
//
// A cap is only half of it. §4.6 caps *concurrent* reassemblies, so a build that refused the
// seventeenth forever — never giving the slot back when a request completed or aborted — would
// pass a test that only counted refusals, and would then refuse every fragmented request that
// client sent for the rest of its connection. Both directions are asserted here.
func TestTheConcurrentReassemblyCapIsTheConfiguredOneAndTheSlotComesBack(t *testing.T) {
	for _, configured := range []int{1, 3, DefaultReassembliesPerClient} {
		t.Run(fmt.Sprintf("%d per client", configured), func(t *testing.T) {
			clock := newTestClock()
			buffers := newReassembly(clock.time, 4096, configured, DefaultReassemblyIdle)
			bound := buffers.perClient
			if bound != configured {
				t.Fatalf("a reassembler configured for %d concurrent reassemblies holds %d", configured, bound)
			}
			clientId := connect.NewId()

			// every request here is two fragments long, so opening one leaves it in flight
			open := func(requestId uint64) protocol.Reason {
				_, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{
					RequestId: requestId, Index: 0, Count: 2, Part: []byte("ab"),
				})
				return reason
			}

			for index := range bound {
				if reason := open(uint64(index)); reason != protocol.Reason_REASON_OK {
					t.Fatalf("in-flight reassembly %d of %d was answered %v", index+1, bound, reason)
				}
			}
			full := buffers.holding()
			if full.reassemblies != bound || full.clients != 1 || full.bytes != 2*bound {
				t.Fatalf("with %d reassemblies open the reassembler holds %+v", bound, full)
			}

			// the one past the cap is refused, and it buffers nothing on its way to being
			// refused: a cap applied after the allocation is a cap on nothing that matters
			if reason := open(uint64(bound)); reason != protocol.Reason_REASON_REJECTED {
				t.Fatalf("reassembly %d against a cap of %d was answered %v", bound+1, bound, reason)
			}
			if after := buffers.holding(); after != full {
				t.Fatalf("the refused reassembly changed what is held from %+v to %+v", full, after)
			}

			// the cap is one client's and not this server's
			other := connect.NewId()
			if _, _, reason := buffers.accept(other, &protocol.MessageServerFragment{
				RequestId: 0, Index: 0, Count: 2, Part: []byte("ab"),
			}); reason != protocol.Reason_REASON_OK {
				t.Fatalf("a second client was answered %v for the first client's in-flight reassemblies", reason)
			}

			// a completed reassembly gives its slot and its bytes back
			_, complete, reason := buffers.accept(clientId, &protocol.MessageServerFragment{
				RequestId: 0, Index: 1, Count: 2, Part: []byte("cd"),
			})
			if !complete || reason != protocol.Reason_REASON_OK {
				t.Fatalf("the last fragment of an open request answered complete=%v %v", complete, reason)
			}
			if holding := buffers.holding(); holding.reassemblies != bound || holding.bytes != 2*bound {
				t.Fatalf("one of %d reassemblies completed and the reassembler still holds %+v; its slot and its four bytes should have gone", bound, holding)
			}
			if reason := open(uint64(bound)); reason != protocol.Reason_REASON_OK {
				t.Fatalf("the slot of a completed reassembly was not given back: a new request was answered %v", reason)
			}

			// and so does an aborted one — here by a repeat of index 0, which is §4.6's
			// out-of-order abort on a request whose next index is 1
			if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{
				RequestId: uint64(bound), Index: 0, Count: 2, Part: []byte("ab"),
			}); reason != protocol.Reason_REASON_REJECTED {
				t.Fatalf("a repeated index 0 was answered %v, want the request aborted", reason)
			}
			if reason := open(uint64(bound) + 1); reason != protocol.Reason_REASON_OK {
				t.Fatalf("the slot of an aborted reassembly was not given back: a new request was answered %v", reason)
			}

			// and nothing survives its own expiry, whatever it was doing when its client went
			// away: the memory comes back by completion, by abort, or by §4.6's thirty seconds
			clock.advance(buffers.idle + time.Nanosecond)
			buffers.sweep()
			if holding := buffers.holding(); holding != (held{}) {
				t.Fatalf("every reassembly expired and the reassembler still holds %+v", holding)
			}
		})
	}
}

// [New] wires the configured cap into the reassembler, so that the cap the test above reads back
// out of a reassembler is the one a peer built from a [Config] actually holds.
func TestAPeersReassemblyCapIsTheOneItsConfigNames(t *testing.T) {
	for _, configured := range []int{0, 2, 40} {
		fixture := newFixtureWith(t, Config{ReassembliesPerClient: configured})
		want := configured
		if want == 0 {
			want = DefaultReassembliesPerClient
		}
		if got := fixture.peer.reassembly.perClient; got != want {
			t.Fatalf("a peer configured with ReassembliesPerClient %d caps a client at %d, want %d", configured, got, want)
		}
	}
}

// ── the thirty seconds ───────────────────────────────────────────────────────────────────

// §4.6's expiry happens at the bound, and not before it.
//
// On an injected clock rather than by waiting: a test that slept for thirty seconds is a test
// somebody deletes the first time the suite gets slow, and one that slept for a *shortened*
// bound would be asserting a number the production build does not hold. That the clock is a
// parameter of the reassembler is what makes this possible, and it is a parameter for this
// reason.
//
// Both sides of the bound are asserted. A reassembler that expired everything on sight would
// satisfy "expires after 30 s" while aborting every fragmented request that took two round trips
// to arrive, and only the "and not before" half tells the two apart.
func TestReassemblyStateExpiresAtSpecB46sBoundAndNotBefore(t *testing.T) {
	clock := newTestClock()
	buffers := newReassembly(clock.time, 4096, DefaultReassembliesPerClient, DefaultReassemblyIdle)
	idle := buffers.idle
	clientId := connect.NewId()
	fragments := fragmentsOf(1, []byte("aaaabbbbcccc"), 4)

	if _, _, reason := buffers.accept(clientId, fragments[0]); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the first fragment was answered %v", reason)
	}
	// at exactly the bound the state is still there and still accepting: §4.6 expires *after*
	// 30 s, and a reassembly abandoned at 30.000 s aborts requests nobody was slow about
	clock.advance(idle)
	if _, _, reason := buffers.accept(clientId, fragments[1]); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the second fragment, arriving exactly %v after the first, was answered %v", idle, reason)
	}
	if holding := buffers.holding(); holding.reassemblies != 1 || holding.bytes != 8 {
		t.Fatalf("at exactly the bound the reassembler holds %+v, want the two fragments it accepted", holding)
	}

	// one tick past it the state is gone rather than continued — and because the bound is on
	// when the reassembly began, the fragment accepted at the bound did not renew it
	clock.advance(time.Nanosecond)
	if dropped := buffers.sweep(); dropped != 1 {
		t.Fatalf("the sweep past %v dropped %d reassemblies, want 1", idle, dropped)
	}
	if holding := buffers.holding(); holding != (held{}) {
		t.Fatalf("an expired reassembly left %+v behind", holding)
	}
	if _, _, reason := buffers.accept(clientId, fragments[2]); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a fragment arriving after the expiry was answered %v; there is no buffer left for it to continue", reason)
	}

	// the expiry is also what gives the per-client cap back on a client that opened reassemblies
	// and went quiet, so every one of them goes rather than just enough of them to make room
	for index := range buffers.perClient {
		if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{
			RequestId: uint64(100 + index), Index: 0, Count: 2, Part: []byte("ab"),
		}); reason != protocol.Reason_REASON_OK {
			t.Fatalf("reassembly %d was answered %v", index+1, reason)
		}
	}
	clock.advance(idle + time.Nanosecond)
	if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{
		RequestId: 999, Index: 0, Count: 2, Part: []byte("ab"),
	}); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a client whose %d expired reassemblies should have been collected was answered %v", buffers.perClient, reason)
	}
	if holding := buffers.holding(); holding.reassemblies != 1 {
		t.Fatalf("after the expiry the reassembler holds %+v, want only the reassembly opened after it", holding)
	}
}

// §4.6's thirty seconds pass whether or not the attacker sends anything else.
//
// The expiry inside [reassembly.accept] bounds a server that is being sent fragments. This is
// the other half: a client opens a reassembly, goes silent, and nothing else arrives at this
// server at all — and the buffer is released anyway, because it is released on a clock this
// process owns. Without [Peer.sweepLoop] that release waits on the attacker's next frame, and a
// bound the attacker chooses when to apply is not a bound on the attacker.
//
// A short bound rather than §4.6's thirty seconds, because what is under test here is that a
// clock of ours runs the expiry at all; [TestReassemblyStateExpiresAtSpecB46sBoundAndNotBefore]
// is where the number itself is asserted.
func TestReassemblyStateIsFreedWithNoFurtherFragmentToSweepIt(t *testing.T) {
	fixture := newFixtureWith(t, Config{ReassemblyIdle: 50 * time.Millisecond})

	// delivered by calling the receive callback the way connect calls it, so that the fragment
	// is buffered before the assertion below rather than in a race with it
	part := bytes.Repeat([]byte{0x33}, 512)
	body, err := connect.ProtoMarshal(&protocol.MessageServerFragment{RequestId: 77, Index: 0, Count: 4, Part: part})
	if err != nil {
		t.Fatalf("ProtoMarshal: %v", err)
	}
	fixture.peer.receive(
		connect.TransferPath{SourceId: connect.NewId()},
		[]*protocol.Frame{{MessageType: protocol.MessageType_MessageMessageServerFragment, MessageBytes: body}},
		connect.Peer{},
	)
	if holding := fixture.peer.reassembly.holding(); holding.bytes != len(part) {
		t.Fatalf("the fragment was buffered as %+v, want %d bytes; a release is not what the wait below would be observing", holding, len(part))
	}

	until(t, "§4.6's expiry with no further fragment sent", func() bool {
		return fixture.peer.reassembly.holding() == held{}
	})
}

// ── the buffer cap, and the freeing ──────────────────────────────────────────────────────

// REASON_OVERSIZE frees every buffered byte at the moment it refuses.
//
// §4.6 calls an unbounded reassembly buffer a trivial memory-exhaustion vector, and a receiver
// that refuses without freeing leaves that vector open exactly as wide: a client sends fragments
// up to the cap, is refused, and repeats — holding `max_request_bytes` per request_id for as
// long as the state lives. The refusal alone cannot tell the two builds apart, which is why the
// bytes are counted here rather than inferred from the reason code.
//
// The count *before* the refusal is asserted too. "The reassembler holds nothing" passes for
// free against a reassembler that never held anything, and this test would then be green whether
// or not the fragments it sent were ever buffered at all.
func TestAnOversizeReassemblyFreesEveryByteAtTheMomentItRefuses(t *testing.T) {
	const maxRequestBytes = 1024
	clock := newTestClock()
	buffers := newReassembly(clock.time, maxRequestBytes, DefaultReassembliesPerClient, DefaultReassemblyIdle)
	clientId := connect.NewId()

	fragments := fragmentsOf(1, bytes.Repeat([]byte{0x5a}, 4*maxRequestBytes), 256)
	buffered := 0
	refusedAt := -1
	for index, fragment := range fragments {
		assembled, complete, reason := buffers.accept(clientId, fragment)
		if reason == protocol.Reason_REASON_OVERSIZE {
			refusedAt = index
			if complete || assembled != nil {
				t.Fatalf("the refusal reported complete=%v and handed back %d bytes for dispatch", complete, len(assembled))
			}
			break
		}
		if reason != protocol.Reason_REASON_OK || complete {
			t.Fatalf("fragment %d of a request inside the cap was answered %v complete=%v", index, reason, complete)
		}
		buffered += len(fragment.GetPart())
		if holding := buffers.holding(); holding.bytes != buffered || holding.reassemblies != 1 || holding.clients != 1 {
			t.Fatalf("after %d buffered bytes the reassembler holds %+v", buffered, holding)
		}
	}
	if refusedAt < 0 {
		t.Fatalf("%d bytes of fragments against a %d byte cap were never refused", 4*maxRequestBytes, maxRequestBytes)
	}
	if buffered == 0 {
		t.Fatal("the cap refused before one byte was buffered, so the freeing asserted below has nothing to observe")
	}
	if holding := buffers.holding(); holding != (held{}) {
		t.Fatalf("REASON_OVERSIZE left %+v behind; §4.6 frees the buffer immediately, and a buffer freed one stage later is one an attacker holds open by never sending the last fragment", holding)
	}

	// the client is refused, not poisoned: the slot and the request_id are usable again, and
	// what assembles on them carries none of the aborted request's bytes
	wanted := []byte("a request that fits")
	assembled, complete, reason := replay(buffers, clientId, 1, wanted, 8)
	if !complete || reason != protocol.Reason_REASON_OK {
		t.Fatalf("a request inside the cap on the same request_id was answered %v complete=%v", reason, complete)
	}
	if !bytes.Equal(assembled, wanted) {
		t.Fatalf("the request after the abort assembled to %q", assembled)
	}
	if holding := buffers.holding(); holding != (held{}) {
		t.Fatalf("a completed request left %+v behind", holding)
	}
}

// ── in order, or not at all ──────────────────────────────────────────────────────────────

// An out-of-order index aborts the request, and no later fragment brings it back.
//
// §4.6 aborts "rather than buffering holes", and the difference between the two shows up on the
// fragment *after* the abort: a receiver that kept the buffer would accept the index it was
// still waiting for and assemble a request out of parts that arrived around a gap. So index 1 is
// sent after the abort, which is precisely the fragment a hole-buffering receiver wants next.
//
// The last step is what makes the abort a free rather than a rejection: the same request_id,
// sent again in order, assembles to exactly the bytes of the second attempt. A receiver that
// aborted the request while keeping its bytes would answer with the first attempt's part still
// on the front of it.
func TestAnOutOfOrderIndexAbortsAndNoLaterFragmentResurrectsIt(t *testing.T) {
	clock := newTestClock()
	buffers := newReassembly(clock.time, 4096, DefaultReassembliesPerClient, DefaultReassemblyIdle)
	clientId := connect.NewId()
	fragments := fragmentsOf(1, []byte("aaabbbccc"), 3)

	if _, _, reason := buffers.accept(clientId, fragments[0]); reason != protocol.Reason_REASON_OK {
		t.Fatalf("index 0 was answered %v", reason)
	}
	if holding := buffers.holding(); holding.bytes != 3 {
		t.Fatalf("after index 0 the reassembler holds %+v", holding)
	}
	if _, _, reason := buffers.accept(clientId, fragments[2]); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("index 2 arriving after index 0 was answered %v, want the request aborted", reason)
	}
	if holding := buffers.holding(); holding != (held{}) {
		t.Fatalf("an out-of-order index left %+v buffered; §4.6 aborts rather than buffering holes", holding)
	}
	if _, complete, reason := buffers.accept(clientId, fragments[1]); reason != protocol.Reason_REASON_REJECTED || complete {
		t.Fatalf("index 1, arriving after the abort, was answered %v complete=%v; it is the fragment a hole-buffering receiver would have been waiting for", reason, complete)
	}
	if holding := buffers.holding(); holding != (held{}) {
		t.Fatalf("the fragment after the abort left %+v behind", holding)
	}

	wanted := []byte("xxxyyyzzz")
	assembled, complete, reason := replay(buffers, clientId, 1, wanted, 3)
	if !complete || reason != protocol.Reason_REASON_OK {
		t.Fatalf("the same request_id sent again in order was answered %v complete=%v", reason, complete)
	}
	if !bytes.Equal(assembled, wanted) {
		t.Fatalf("the second attempt assembled to %q, want only its own bytes", assembled)
	}
}

// ── interleaving ─────────────────────────────────────────────────────────────────────────

// Two clients and two request_ids, all four reassembling at once, and none of them contaminated.
//
// Real goroutines against one reassembler, because the property is not that the arithmetic is
// right — it is that (source client_id, request_id) is what separates one buffer from another. A
// reassembler keyed on `request_id` alone passes every sequential test in this file: it is only
// when two clients hold the same request_id open at the same moment that the missing half of the
// key does anything at all. So both clients here use both request_ids.
//
// The assertions are invariants and not orderings. Which goroutine completes first is the
// scheduler's business; that each one gets back the bytes it sent, exactly once, is not.
func TestConcurrentReassembliesDoNotContaminateEachOther(t *testing.T) {
	clock := newTestClock()
	buffers := newReassembly(clock.time, DefaultMaxRequestBytes, DefaultReassembliesPerClient, DefaultReassemblyIdle)

	clients := []connect.Id{connect.NewId(), connect.NewId()}
	requestIds := []uint64{7, 9}

	type sender struct {
		client    int
		requestId uint64
		body      []byte
	}
	senders := []sender{}
	for index := range clients {
		for _, requestId := range requestIds {
			senders = append(senders, sender{client: index, requestId: requestId, body: payloadFor(index, requestId)})
		}
	}

	type outcome struct {
		sender      sender
		assembled   []byte
		reason      protocol.Reason
		completions int
	}
	outcomes := make(chan outcome, len(senders))
	start := make(chan struct{})
	running := sync.WaitGroup{}
	for _, current := range senders {
		running.Add(1)
		go func() {
			defer running.Done()
			// released together, so the fragments actually interleave rather than queueing up
			// behind whichever goroutine the scheduler happened to start first
			<-start
			found := outcome{sender: current, reason: protocol.Reason_REASON_OK}
			for _, fragment := range fragmentsOf(current.requestId, current.body, 64) {
				assembled, complete, reason := buffers.accept(clients[current.client], fragment)
				if reason != protocol.Reason_REASON_OK {
					found.reason = reason
					break
				}
				if complete {
					found.completions++
					found.assembled = assembled
				}
				runtime.Gosched()
			}
			outcomes <- found
		}()
	}
	close(start)
	running.Wait()
	close(outcomes)

	seen := 0
	for found := range outcomes {
		seen++
		what := fmt.Sprintf("client %d's request %d", found.sender.client, found.sender.requestId)
		switch {
		case found.reason != protocol.Reason_REASON_OK:
			t.Errorf("%s was answered %v while three other reassemblies were open", what, found.reason)
		case found.completions != 1:
			t.Errorf("%s completed %d times", what, found.completions)
		case !bytes.Equal(found.assembled, found.sender.body):
			t.Errorf("%s assembled %d bytes that are not the %d it sent: another reassembly's fragments reached this buffer",
				what, len(found.assembled), len(found.sender.body))
		}
	}
	if seen != len(senders) {
		t.Fatalf("%d of %d concurrent reassemblies reported an outcome", seen, len(senders))
	}
	if holding := buffers.holding(); holding != (held{}) {
		t.Fatalf("every concurrent reassembly completed and %+v is still held", holding)
	}
	if err := buffers.consistent(); err != nil {
		t.Fatal(err)
	}
}

// Two connect clients fragmenting one request_id at the same instant, through the frame path,
// are each answered their own request.
//
// Both use `request_id` 5150, which is legal — §4.6 keys on (source client_id, request_id), and
// a client_id is not a client's to choose — and which is the collision a server keyed on the
// request_id alone would serve as one request.
//
// The fragments are handed to the receive callback the way connect hands them, from two
// goroutines, a round at a time: both clients' fragment *i* are delivered before either client's
// fragment *i+1*. Sending them over the transport instead would leave the interleaving to
// connect's send buffers, and a run in which one client's six fragments happened to arrive
// before the other's is a sequential test wearing two goroutines — it would pass against a
// reassembler with no client_id in its key, which is the one thing this arrangement is for.
// Everything after the callback is untouched: the reassembler, the worker pool, and the send
// path back to two real connect clients over two real routes.
func TestTwoClientsFragmentingOneRequestIdAtOnceAreEachAnsweredTheirOwn(t *testing.T) {
	const shared = uint64(5150)
	const mineMarker = uint64(111)
	const theirsMarker = uint64(222)

	fixture := newFixture(t)
	fixture.hello(t)

	other, otherResponses := fixture.anotherClient(t)
	otherHello := &protocol.MessageServerRequest{RequestId: 1, ProtocolVersion: fixtureProtocolVersion}
	if err := setRequestBody(otherHello, &protocol.HelloRequest{SupportedVersions: []uint32{fixtureProtocolVersion}}); err != nil {
		t.Fatalf("setRequestBody: %v", err)
	}
	sendRequestFrom(t, other, fixture.serverClient, otherHello)
	if response := awaitOn(t, otherResponses, otherHello.GetRequestId()); response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the second client's Hello was answered %v", response.GetReason())
	}
	fixture.handler.forget()

	// two requests that differ in nothing this server can tell apart except the client they
	// arrive from and the marker each carries back
	requestOf := func(marker uint64) *protocol.MessageServerRequest {
		request := &protocol.MessageServerRequest{RequestId: shared, ProtocolVersion: fixtureProtocolVersion}
		if err := setRequestBody(request, &protocol.FetchRequest{
			GroupId:       bytes.Repeat([]byte{0x21}, 32),
			SinceRecordId: marker,
			ReqAuth:       bytes.Repeat([]byte{0x22}, 6000),
		}); err != nil {
			t.Fatalf("setRequestBody: %v", err)
		}
		return request
	}
	waiter := fixture.waitFor(shared)

	mineFragments := frameFragmentsOf(t, requestOf(mineMarker), 1024)
	theirsFragments := frameFragmentsOf(t, requestOf(theirsMarker), 1024)
	if len(mineFragments) < 2 || len(mineFragments) != len(theirsFragments) {
		t.Fatalf("the two requests fragmented into %d and %d frames; this test needs both fragmented and both the same length",
			len(mineFragments), len(theirsFragments))
	}
	for round := range mineFragments {
		delivering := sync.WaitGroup{}
		deliver := func(clientId connect.Id, frame *protocol.Frame) {
			defer delivering.Done()
			fixture.peer.receive(connect.TransferPath{SourceId: clientId}, []*protocol.Frame{frame}, connect.Peer{})
		}
		delivering.Add(2)
		go deliver(fixture.clientClient.ClientId(), mineFragments[round])
		go deliver(other.ClientId(), theirsFragments[round])
		delivering.Wait()
	}

	mine := fixture.await(t, waiter)
	theirs := awaitOn(t, otherResponses, shared)
	if mine.GetReason() != protocol.Reason_REASON_OK || theirs.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("two clients fragmenting at once were answered %v and %v", mine.GetReason(), theirs.GetReason())
	}
	if mine.GetFetch().GetHighWaterRecordId() != mineMarker {
		t.Fatalf("this client's request_id %d came back naming record %d, want %d", shared, mine.GetFetch().GetHighWaterRecordId(), mineMarker)
	}
	if theirs.GetFetch().GetHighWaterRecordId() != theirsMarker {
		t.Fatalf("the other client's request_id %d came back naming record %d, want %d", shared, theirs.GetFetch().GetHighWaterRecordId(), theirsMarker)
	}

	// and each reassembled request was dispatched on its own client's connection
	calls := fixture.handler.recorded()
	if len(calls) != 2 {
		t.Fatalf("two fragmented requests reached the handler as %d calls: %+v", len(calls), calls)
	}
	for _, call := range calls {
		want := fixture.clientClient.ClientId().Bytes()
		if call.marker == theirsMarker {
			want = other.ClientId().Bytes()
		}
		if !bytes.Equal(call.clientId, want) {
			t.Fatalf("the request marked %d was served on another client's connection", call.marker)
		}
	}
	if holding := fixture.peer.reassembly.holding(); holding != (held{}) {
		t.Fatalf("both requests were served and %+v is still held", holding)
	}
}

// ── the part size on the way out ─────────────────────────────────────────────────────────

// No fragment this server sends is larger than §4.6 allows, whatever the configuration says.
//
// §4.6's part size is `min(peer_advertised_frame_budget, 2048)` and the sender "MUST NOT exceed
// the negotiated budget". A min is a ceiling on both of its arguments, so a build configured with
// a larger number does not get larger fragments — it gets the ceiling. The alternative is a
// server that puts fragments on the wire at a size chosen by whoever wrote the yml, which every
// conforming receiver is entitled to refuse and which no test of this server's own reassembler
// would ever notice, both halves being wrong in the same direction.
func TestNoFragmentThisServerSendsExceedsSpecB46sPartSize(t *testing.T) {
	t.Run("a budget above the ceiling is clamped to it", func(t *testing.T) {
		fixture := newFixtureWith(t, Config{FragmentPartBytes: 60000})
		if fixture.peer.fragmentPartBytes != MaxFragmentPartBytes {
			t.Fatalf("a peer configured with a 60000 byte frame budget cuts %d byte parts, want §4.6's ceiling of %d",
				fixture.peer.fragmentPartBytes, MaxFragmentPartBytes)
		}
		parts := largeFetchParts(t, fixture)
		if len(parts) < 2 {
			t.Fatalf("a 9000 byte response travelled in %d fragments; a build that ignored §4.6's ceiling would send it in one frame", len(parts))
		}
		for index, part := range parts {
			if MaxFragmentPartBytes < part {
				t.Fatalf("fragment %d carries %d bytes, past §4.6's %d", index, part, MaxFragmentPartBytes)
			}
		}
	})

	t.Run("a budget below the ceiling is honoured, because the rule is a min", func(t *testing.T) {
		const budget = 512
		fixture := newFixtureWith(t, Config{FragmentPartBytes: budget})
		if fixture.peer.fragmentPartBytes != budget {
			t.Fatalf("a peer configured with a %d byte frame budget cuts %d byte parts", budget, fixture.peer.fragmentPartBytes)
		}
		parts := largeFetchParts(t, fixture)
		if len(parts) < 2 {
			t.Fatalf("a 9000 byte response travelled in %d fragments at a %d byte budget", len(parts), budget)
		}
		for index, part := range parts {
			if budget < part {
				t.Fatalf("fragment %d carries %d bytes against a negotiated budget of %d", index, part, budget)
			}
		}
	})
}

// ── the fuzz of the fragment path ────────────────────────────────────────────────────────

// One fragment, as a fuzz input: eight bytes naming every field a client controls.
//
// A packed script rather than four fuzzed arguments, because what is interesting on this path is
// a *sequence* — an out-of-order index means nothing without the fragment before it, and the
// per-client cap means nothing without enough requests to reach it. The mutator explores
// sequences by editing the script.
func fragmentOp(client byte, requestId byte, index uint16, count uint16, partLen byte, flags byte) []byte {
	op := []byte{client, requestId, 0, 0, 0, 0, partLen, flags}
	binary.BigEndian.PutUint16(op[2:4], index)
	binary.BigEndian.PutUint16(op[4:6], count)
	return op
}

func fragmentScript(ops ...[]byte) []byte {
	script := []byte{}
	for _, op := range ops {
		script = append(script, op...)
	}
	return script
}

// Arbitrary fragment sequences never panic, never exceed §4.6's bounds, and never leave state
// behind.
//
// The third is the one that needs a fuzz target rather than a case. Every abort §4.6 names is
// asserted by a test above, one at a time, on the sequence that provokes it — but a reassembler
// that leaks one entry per hostile request is the memory-exhaustion vector §4.6 is written
// against by a slower route, and what finds that is the sequence nobody thought of. So every
// iteration ends by expiring everything and asserting that the state map, the per-client count
// map and the buffered bytes are all empty; and after every single fragment, that the two maps
// still agree with each other.
//
// A deliberately small `max_request_bytes`, so that a hostile script reaches the cap rather than
// wandering about under it: a bound the fuzzer never touches is a bound the fuzzer is not
// testing.
func FuzzTheFragmentPathIsBoundedAndLeavesNothingBehind(f *testing.F) {
	f.Add(fragmentScript(
		fragmentOp(0, 0, 0, 3, 40, 0),
		fragmentOp(0, 0, 1, 3, 40, 0),
		fragmentOp(0, 0, 2, 3, 40, 0),
	), uint8(1))
	f.Add(fragmentScript(
		fragmentOp(0, 0, 0, 3, 40, 0),
		fragmentOp(0, 0, 2, 3, 40, 0),
		fragmentOp(0, 0, 1, 3, 40, 0),
	), uint8(1))
	f.Add(fragmentScript(
		fragmentOp(0, 1, 0, 2, 200, 0),
		fragmentOp(1, 1, 0, 2, 200, 0),
		fragmentOp(0, 1, 1, 2, 200, 0),
		fragmentOp(1, 1, 1, 2, 200, 0),
	), uint8(2))
	f.Add(fragmentScript(
		fragmentOp(0, 0, 0, 65535, 255, 0),
		fragmentOp(0, 1, 0, 65535, 255, 0),
		fragmentOp(0, 2, 0, 65535, 255, 0),
		fragmentOp(0, 3, 0, 65535, 255, 0),
		fragmentOp(0, 4, 0, 65535, 255, 0),
		fragmentOp(0, 0, 1, 65535, 255, 1),
	), uint8(1))
	f.Add(fragmentScript(fragmentOp(0, 0, 0, 0, 0, 0)), uint8(1))
	f.Add([]byte{}, uint8(0))
	f.Add([]byte{0xff, 0xff, 0xff}, uint8(255))

	f.Fuzz(func(t *testing.T, script []byte, clientCount uint8) {
		const maxRequestBytes = 512
		const perClient = 4
		clock := newTestClock()
		buffers := newReassembly(clock.time, maxRequestBytes, perClient, DefaultReassemblyIdle)

		clients := []connect.Id{}
		for range int(clientCount%4) + 1 {
			clients = append(clients, connect.NewId())
		}
		ceiling := held{
			reassemblies: perClient * len(clients),
			clients:      len(clients),
			bytes:        perClient * len(clients) * maxRequestBytes,
		}

		for len(script) >= 8 {
			op := script[:8]
			script = script[8:]
			if op[7]&1 != 0 {
				clock.advance(DefaultReassemblyIdle / 3)
			}
			assembled, complete, reason := buffers.accept(clients[int(op[0])%len(clients)], &protocol.MessageServerFragment{
				RequestId: uint64(op[1]),
				Index:     uint32(binary.BigEndian.Uint16(op[2:4])),
				Count:     uint32(binary.BigEndian.Uint16(op[4:6])),
				Part:      bytes.Repeat([]byte{op[6]}, int(op[6])),
			})

			if maxRequestBytes < len(assembled) {
				t.Fatalf("a reassembly answered %d bytes against a %d byte cap", len(assembled), maxRequestBytes)
			}
			if reason != protocol.Reason_REASON_OK && (complete || assembled != nil) {
				t.Fatalf("a refusal (%v) reported complete=%v with %d bytes for dispatch", reason, complete, len(assembled))
			}
			holding := buffers.holding()
			if ceiling.reassemblies < holding.reassemblies || ceiling.clients < holding.clients || ceiling.bytes < holding.bytes {
				t.Fatalf("the reassembler holds %+v, past the %+v that %d clients capped at %d reassemblies of %d bytes can hold",
					holding, ceiling, len(clients), perClient, maxRequestBytes)
			}
			if err := buffers.consistent(); err != nil {
				t.Fatal(err)
			}
		}

		clock.advance(DefaultReassemblyIdle + time.Nanosecond)
		buffers.sweep()
		if holding := buffers.holding(); holding != (held{}) {
			t.Fatalf("every reassembly this script opened has expired and %+v is still held; a reassembler that leaks one entry per hostile request is §4.6's memory-exhaustion vector by a slower route", holding)
		}
	})
}

// ── the helpers ──────────────────────────────────────────────────────────────────────────

// The two maps §4.6's state lives in, checked against each other.
//
// `counts` is what the per-client cap is enforced from and `inFlight` is what the memory is held
// in. A drop that forgot either one leaves the cap enforced against reassemblies that no longer
// exist, or memory held under a client the cap believes is idle — and neither shows up in any
// single accept's answer, which is why this is asserted after every one of them in the fuzz.
func (self *reassembly) consistent() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	counted := map[connect.Id]int{}
	for key := range self.inFlight {
		counted[key.clientId]++
	}
	if len(counted) != len(self.counts) {
		return fmt.Errorf("%d clients hold a buffer and the per-client count map has %d entries", len(counted), len(self.counts))
	}
	for clientId, count := range counted {
		if self.counts[clientId] != count {
			return fmt.Errorf("a client holds %d buffers and is counted against §4.6's cap as holding %d", count, self.counts[clientId])
		}
	}
	return nil
}

// One request's worth of fragments, as §4.6 says a sender cuts them.
func fragmentsOf(requestId uint64, body []byte, partBytes int) []*protocol.MessageServerFragment {
	count := max((len(body)+partBytes-1)/partBytes, 1)
	fragments := make([]*protocol.MessageServerFragment, 0, count)
	for index := range count {
		fragments = append(fragments, &protocol.MessageServerFragment{
			RequestId: requestId,
			Index:     uint32(index),
			Count:     uint32(count),
			Part:      body[min(index*partBytes, len(body)):min((index+1)*partBytes, len(body))],
		})
	}
	return fragments
}

// A whole request, fragmented and accepted in order, and whatever its last fragment answered.
func replay(buffers *reassembly, clientId connect.Id, requestId uint64, body []byte, partBytes int) ([]byte, bool, protocol.Reason) {
	var assembled []byte
	complete := false
	reason := protocol.Reason_REASON_OK
	for _, fragment := range fragmentsOf(requestId, body, partBytes) {
		assembled, complete, reason = buffers.accept(clientId, fragment)
		if reason != protocol.Reason_REASON_OK {
			return assembled, complete, reason
		}
	}
	return assembled, complete, reason
}

// A payload no other (client, request_id) pair produces, so that a contaminated reassembly is a
// mismatch rather than a coincidence. Every payload is the same length: two buffers that swapped
// their bytes would otherwise be caught by a length nobody had to compare.
func payloadFor(client int, requestId uint64) []byte {
	body := []byte{}
	for len(body) < 700 {
		body = binary.BigEndian.AppendUint64(append(body, byte(client)), requestId)
	}
	return body[:700]
}

// A fetch whose response is too large for one frame, and the sizes of the parts it travelled in.
func largeFetchParts(t *testing.T, fixture *fixture) []int {
	t.Helper()
	fixture.hello(t)
	fixture.forgetFrames()
	fixture.handler.onFetch = func(conn *api.Connection, request *protocol.FetchRequest) (protocol.Reason, *protocol.FetchResponse, error) {
		return protocol.Reason_REASON_OK, &protocol.FetchResponse{
			Records: []*protocol.Record{{RecordBytes: bytes.Repeat([]byte{0x77}, 9000)}},
		}, nil
	}
	if response := fixture.call(t, &protocol.FetchRequest{GroupId: bytes.Repeat([]byte{0x31}, 32)}); response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("a 9000 byte fetch was answered %v", response.GetReason())
	}
	parts := []int{}
	for _, frame := range fixture.frames() {
		if frame.GetMessageType() != protocol.MessageType_MessageMessageServerFragment {
			continue
		}
		fragment := &protocol.MessageServerFragment{}
		if err := proto.Unmarshal(frame.GetMessageBytes(), fragment); err != nil {
			t.Fatalf("a fragment frame did not decode: %v", err)
		}
		parts = append(parts, len(fragment.GetPart()))
	}
	return parts
}

// Poll until something is true, or fail. A deadline rather than a sleep of the length being
// waited for: what is under test is that the release happens at all, and a fixed sleep would be
// either a flake on a slow machine or a second of every run on a fast one.
func until(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !done() {
		if deadline.Before(time.Now()) {
			t.Fatalf("waited 30s for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// A second connect client on the same server, wired the way [newFixtureWith] wires the first.
//
// Two clients rather than two request_ids on one, because §4.6 keys reassembly on
// (source client_id, request_id) and one client cannot exercise the client_id half of that key
// at all.
func (self *fixture) anotherClient(t *testing.T) (*connect.Client, chan *protocol.MessageServerResponse) {
	t.Helper()
	other := connect.NewClient(self.ctx, connect.NewId(), connect.NewNoContractClientOob(), connect.DefaultClientSettings())
	toServer := make(connect.Route)
	toClient := make(connect.Route)
	other.RouteManager().UpdateTransport(connect.NewSendGatewayTransport(), []connect.Route{toServer})
	other.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransport(), []connect.Route{toClient})
	other.ContractManager().AddNoContractPeer(self.serverClient.ClientId())
	self.serverClient.RouteManager().UpdateTransport(
		connect.NewSendClientTransport(connect.DestinationId(other.ClientId())), []connect.Route{toClient})
	self.serverClient.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransport(), []connect.Route{toServer})
	self.serverClient.ContractManager().AddNoContractPeer(other.ClientId())

	responses := make(chan *protocol.MessageServerResponse, 64)
	unsubscribe := other.AddReceiveCallback(func(source connect.TransferPath, frames []*protocol.Frame, from connect.Peer) {
		for _, frame := range frames {
			if frame.GetMessageType() != protocol.MessageType_MessageMessageServerResponse {
				continue
			}
			response := &protocol.MessageServerResponse{}
			if proto.Unmarshal(frame.GetMessageBytes(), response) != nil {
				continue
			}
			select {
			case responses <- response:
			default:
			}
		}
	})
	t.Cleanup(func() {
		unsubscribe()
		other.Close()
	})
	return other, responses
}

// t.Errorf rather than t.Fatalf on the three below, because they are called from the goroutines
// of the interleaving test and only a test's own goroutine may end it.
func sendFrom(t *testing.T, from *connect.Client, to *connect.Client, frame *protocol.Frame) {
	if !from.Send(frame, connect.DestinationId(to.ClientId()), nil) {
		connect.MessagePoolReturn(frame.MessageBytes)
		t.Errorf("a client's send did not take a frame of type %v", frame.GetMessageType())
	}
}

func sendRequestFrom(t *testing.T, from *connect.Client, to *connect.Client, request *protocol.MessageServerRequest) {
	body, err := connect.ProtoMarshal(request)
	if err != nil {
		t.Errorf("ProtoMarshal: %v", err)
		return
	}
	sendFrom(t, from, to, &protocol.Frame{
		MessageType:  protocol.MessageType_MessageMessageServerRequest,
		MessageBytes: body,
	})
}

// One request, as the §4.2 frames §4.6 fragments it into.
func frameFragmentsOf(t *testing.T, request *protocol.MessageServerRequest, partBytes int) []*protocol.Frame {
	t.Helper()
	body, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	frames := []*protocol.Frame{}
	for _, fragment := range fragmentsOf(request.GetRequestId(), body, partBytes) {
		encoded, err := proto.Marshal(fragment)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		frames = append(frames, &protocol.Frame{
			MessageType:  protocol.MessageType_MessageMessageServerFragment,
			MessageBytes: encoded,
		})
	}
	return frames
}

// The response for one `request_id` on a client that keeps no correlator of its own.
func awaitOn(t *testing.T, responses chan *protocol.MessageServerResponse, requestId uint64) *protocol.MessageServerResponse {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case response := <-responses:
			if response.GetRequestId() == requestId {
				return response
			}
		case <-deadline:
			t.Fatalf("no response for request_id %d arrived within 30s", requestId)
			return nil
		}
	}
}
