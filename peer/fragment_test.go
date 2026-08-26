package peer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"slices"
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
			buffers := newReassembly(clock.time, 4096, configured, DefaultMaxReassemblies, DefaultReassemblyIdle)
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

// The reassemblies this server holds at once are bounded across clients, not only within one.
//
// §4.6's cap is per client, and the client_id it is per is the `source.SourceId` connect hands
// the receive callback — before §5.1 check 2 has resolved a connection, which happens one stage
// later inside the api pipeline. So a client_id that has never said Hello opens reassembly state
// here as readily as one that has, and sixteen buffers of `max_request_bytes` multiplied by as
// many client_ids as an attacker cares to mint is the memory-exhaustion vector §4.6 exists to
// close, reached around the cap rather than through it. Ten thousand strangers were measured
// holding ten thousand reassemblies and twenty megabytes with no refusal at all.
//
// Every client here is a stranger and every one of them is inside §4.6's own cap, so the per-
// client rule cannot be what refuses: what refuses is the bound above it. And because that bound
// is a number spec B does not give, this build declares it — a conforming client can be refused
// by it, and §4.6 gives a client no way to predict that from Capabilities.
func TestTheReassembliesThisServerHoldsAtOnceAreBoundedAcrossClients(t *testing.T) {
	const maxReassemblies = 8
	clock := newTestClock()
	buffers := newReassembly(clock.time, 4096, DefaultReassembliesPerClient, maxReassemblies, DefaultReassemblyIdle)

	opened := []connect.Id{}
	refusedAt := -1
	for index := range 4 * maxReassemblies {
		// a stranger apiece, each opening one reassembly and so inside §4.6's sixteen
		clientId := connect.NewId()
		_, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("ab")})
		if reason == protocol.Reason_REASON_REJECTED {
			refusedAt = index
			break
		}
		if reason != protocol.Reason_REASON_OK {
			t.Fatalf("stranger %d opening its first reassembly was answered %v", index, reason)
		}
		opened = append(opened, clientId)
	}
	if refusedAt != maxReassemblies {
		t.Fatalf("%d strangers each opened a reassembly inside §4.6's own per-client cap against a bound of %d, and the first refusal came at stranger %d (-1 being none at all); §4.6's cap multiplies by every client_id there is, so a bound above it is the only one that holds",
			len(opened), maxReassemblies, refusedAt)
	}
	if holding := buffers.holding(); holding.reassemblies != maxReassemblies || holding.clients != maxReassemblies {
		t.Fatalf("at the bound the reassembler holds %+v, want %d reassemblies under %d clients", holding, maxReassemblies, maxReassemblies)
	}

	// and the bound is on what is held rather than on what has ever arrived: a reassembly that
	// completes gives its slot back to whoever asks next
	if _, complete, reason := buffers.accept(opened[0], &protocol.MessageServerFragment{RequestId: 1, Index: 1, Count: 2, Part: []byte("cd")}); !complete || reason != protocol.Reason_REASON_OK {
		t.Fatalf("the last fragment of an open request answered complete=%v %v", complete, reason)
	}
	if _, _, reason := buffers.accept(connect.NewId(), &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: []byte("ab")}); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the slot of a completed reassembly was not given back: the next stranger was answered %v", reason)
	}

	// a peer holds the configured bound, and the default is a bound rather than none
	for _, configured := range []int{0, 3} {
		fixture := newFixtureWith(t, Config{MaxReassemblies: configured})
		want := configured
		if want == 0 {
			want = DefaultMaxReassemblies
		}
		if got := fixture.peer.reassembly.maxReassemblies; got != want {
			t.Fatalf("a peer configured with MaxReassemblies %d holds %d, want %d", configured, got, want)
		}
		// §4.6 names no bound here, so the one this build applies is declared rather than
		// presented as the spec's
		if !slices.ContainsFunc(fixture.peer.NotBuilt(), func(entry api.NotBuilt) bool { return entry.What == globalReassemblyBound.What }) {
			t.Fatalf("this build refuses a conforming client for a bound §4.6 does not give and nothing declares it; §10.1's readiness endpoint would read the refusal as the spec's: %v",
				fixture.peer.NotBuilt())
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
	buffers := newReassembly(clock.time, 4096, DefaultReassembliesPerClient, DefaultMaxReassemblies, DefaultReassemblyIdle)
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

// The sweep's period is half §4.6's bound, and a tick is what frees the buffer.
//
// [Peer.sweepLoop]'s comment argues that the period is *derived* from the bound rather than
// chosen beside it — "nothing outlives it by more than half of it" — and until this test nothing
// held it to that. The period could be made a hundred times the bound with the whole suite green,
// because the test that waits for the sweep polls for thirty seconds against a fifty-millisecond
// bound: it observes "eventually" and every period under thirty seconds satisfies it. At the
// production thirty seconds a hundredfold period leaves an abandoned buffer alive for fifty
// minutes, which is §4.6's bound exceeded a hundredfold with nothing red.
//
// So the period the loop asks for is read back out of the ticker it asked, and the relation is
// asserted against the bound rather than against a number. And the tick is delivered by the test
// rather than waited for, on a clock the test also moves — which is the same reason [Config.Now]
// exists: a bound a test can only observe by waiting for it is a bound the test has to shorten,
// and a shortened bound is not the one production holds.
func TestTheSweepPeriodIsHalfSpecB46sBoundAndATickIsWhatFreesTheBuffer(t *testing.T) {
	t.Run("the period a peer asks for is at most half the bound it was configured with", func(t *testing.T) {
		for _, idle := range []time.Duration{DefaultReassemblyIdle, time.Minute, time.Second, 50 * time.Millisecond, 4 * time.Millisecond} {
			ticker := newTestTicker()
			newFixtureWith(t, Config{ReassemblyIdle: idle, NewTicker: ticker.new})
			period := ticker.asked(t)
			if period <= 0 {
				t.Fatalf("a peer bounded at %v asked for a ticker of %v, which is not a period at all", idle, period)
			}
			if idle < 2*period {
				t.Fatalf("a peer bounded at %v sweeps every %v, so an abandoned buffer outlives §4.6's bound by up to %v; the period is derived from the bound precisely so that nothing outlives it by more than half of it",
					idle, period, period-idle/2)
			}
		}
	})

	t.Run("a bound too short to halve takes the floor rather than a ticker of zero", func(t *testing.T) {
		// time.NewTicker panics on a period of zero, and this is the only reason the derivation
		// has a floor at all — so the floor is asserted as a floor and not as a second opinion
		// about the bound
		ticker := newTestTicker()
		newFixtureWith(t, Config{ReassemblyIdle: time.Nanosecond, NewTicker: ticker.new})
		if period := ticker.asked(t); period <= 0 || time.Millisecond < period {
			t.Fatalf("a peer bounded at a nanosecond asked for a ticker of %v, want the floor of %v", period, time.Millisecond)
		}
	})

	t.Run("a tick is what frees an abandoned buffer, on a clock this test moves", func(t *testing.T) {
		clock := newTestClock()
		ticker := newTestTicker()
		fixture := newFixtureWith(t, Config{Now: clock.time, NewTicker: ticker.new})
		ticker.asked(t)

		// delivered by calling the receive callback the way connect calls it, so the fragment is
		// buffered before the assertions below rather than in a race with them
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
			t.Fatalf("the fragment was buffered as %+v, want %d bytes; a release is not what the tick below would be observing", holding, len(part))
		}

		// a tick before the bound frees nothing — otherwise "the sweep runs" would be
		// indistinguishable from a sweep that aborts every request that takes two round trips
		ticker.tick(t)
		if holding := fixture.peer.reassembly.holding(); holding.bytes != len(part) {
			t.Fatalf("a sweep with the clock still at the instant the fragment arrived left %+v; §4.6 expires state *after* thirty seconds, and a sweep that drops on sight aborts every request that takes two round trips", holding)
		}

		clock.advance(DefaultReassemblyIdle + time.Nanosecond)
		ticker.tick(t)
		until(t, "§4.6's expiry on a tick, with the clock past the bound and no further fragment sent", func() bool {
			return fixture.peer.reassembly.holding() == held{}
		})
	})
}

// The ticks [Peer.sweepLoop] runs on, and the period it asked for them at.
//
// Guarded for the reason [testClock] is: the period is written by the sweep goroutine as it
// starts and read by the test, and a seam that raced would turn every bound built on it into a
// test that fails somewhere else.
type testTicker struct {
	mutex   sync.Mutex
	periods []time.Duration
	ticks   chan time.Time
}

func newTestTicker() *testTicker {
	return &testTicker{ticks: make(chan time.Time, 1)}
}

func (self *testTicker) new(period time.Duration) (<-chan time.Time, func()) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.periods = append(self.periods, period)
	return self.ticks, func() {}
}

// The period the loop asked for, once it has asked. The goroutine starts inside [New] and this
// is read from the test's own goroutine, so the wait is for the start rather than for the bound.
func (self *testTicker) asked(t *testing.T) time.Duration {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		self.mutex.Lock()
		periods := append([]time.Duration{}, self.periods...)
		self.mutex.Unlock()
		if len(periods) == 1 {
			return periods[0]
		}
		if 1 < len(periods) {
			t.Fatalf("%d tickers were asked for; the sweep is one loop and a second one would sweep on a period nothing here asserts", len(periods))
		}
		if deadline.Before(time.Now()) {
			t.Fatal("the sweep loop never asked for a ticker")
		}
		time.Sleep(time.Millisecond)
	}
}

// One tick, delivered and taken. Delivery is not the sweep, so the tick is followed until the
// loop has taken it off the channel — which is what makes the assertion after it about the sweep
// rather than about the send.
func (self *testTicker) tick(t *testing.T) {
	t.Helper()
	select {
	case self.ticks <- time.Now():
	case <-time.After(30 * time.Second):
		t.Fatal("the sweep loop never took a tick")
	}
	deadline := time.Now().Add(30 * time.Second)
	for len(self.ticks) != 0 {
		if deadline.Before(time.Now()) {
			t.Fatal("the sweep loop never took a tick off the channel")
		}
		time.Sleep(time.Millisecond)
	}
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
	buffers := newReassembly(clock.time, maxRequestBytes, DefaultReassembliesPerClient, DefaultMaxReassemblies, DefaultReassemblyIdle)
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
	buffers := newReassembly(clock.time, 4096, DefaultReassembliesPerClient, DefaultMaxReassemblies, DefaultReassemblyIdle)
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
	buffers := newReassembly(clock.time, DefaultMaxRequestBytes, DefaultReassembliesPerClient, DefaultMaxReassemblies, DefaultReassemblyIdle)

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

// What §4.6's expiry costs does not grow with what is open.
//
// The expiry runs under the reassembler's mutex on every arriving fragment, which is the mutex
// every client's fragments queue behind. A version of it that scanned the whole in-flight map
// answered every refusal identically and cost 9 nanoseconds per open reassembly per fragment: at
// fifty thousand open — which is reachable, because the client_ids reassembly is keyed on are not
// this server's to count — every fragment frame from anybody cost 455µs of held mutex, and the
// server's whole fragment throughput was two thousand a second. Linear per fragment is quadratic
// in an attacker's total work, and it is §4.6's own enforcement paying it.
//
// Counted rather than timed. What is claimed is a complexity, a duration asserted on a shared
// machine is a flake, and the count is exact: the walk looks at the oldest reassembly, finds it
// inside the bound, and stops. Two orders of magnitude apart, so that "it did not grow" is a
// measurement rather than a hope.
func TestWhatSpecB46sExpiryCostsDoesNotGrowWithWhatIsOpen(t *testing.T) {
	measure := func(t *testing.T, open int) uint64 {
		t.Helper()
		clock := newTestClock()
		buffers := newReassembly(clock.time, 4096, open+1, open+1, DefaultReassemblyIdle)
		clientId := connect.NewId()
		for index := range open {
			if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{
				RequestId: uint64(index), Index: 0, Count: 2, Part: []byte("ab"),
			}); reason != protocol.Reason_REASON_OK {
				t.Fatalf("reassembly %d of %d was answered %v", index, open, reason)
			}
		}
		if holding := buffers.holding(); holding.reassemblies != open {
			t.Fatalf("%d reassemblies were opened and the reassembler holds %+v, so the cost below is about a smaller map than this test built", open, holding)
		}

		before := buffers.expiryReads()
		if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{
			RequestId: uint64(open), Index: 0, Count: 2, Part: []byte("ab"),
		}); reason != protocol.Reason_REASON_OK {
			t.Fatalf("the fragment being measured was answered %v", reason)
		}
		cost := buffers.expiryReads() - before

		// cheap because it walks the expired ones, and not because it stopped expiring: the
		// bound still ends everything that is open
		clock.advance(buffers.idle + time.Nanosecond)
		if dropped := buffers.sweep(); dropped != open+1 {
			t.Fatalf("the sweep past the bound dropped %d of %d reassemblies", dropped, open+1)
		}
		if holding := buffers.holding(); holding != (held{}) {
			t.Fatalf("an expiry that costs nothing left %+v behind", holding)
		}
		return cost
	}

	const few = 100
	const many = 100 * few
	small := measure(t, few)
	large := measure(t, many)
	t.Logf("one fragment against %d open reassemblies looked at %d of them; against %d it looked at %d", few, small, many, large)

	// the walk reads the oldest entry, finds it inside the bound and stops, so one is the answer
	// at every size; two is the slack for an implementation that also reads the entry it stops at
	const constant = 2
	if constant < small || constant < large {
		t.Fatalf("one fragment cost %d buffer reads against %d open and %d against %d; §4.6's expiry must cost what it drops rather than what is open, or every client's fragment pays for every other client's buffer",
			small, few, large, many)
	}
	if small < large {
		t.Fatalf("one fragment cost %d buffer reads against %d open and %d against %d, so the cost grows with what is open",
			small, few, large, many)
	}
}

// §4.6's part-size ceiling holds across the whole window either side of it, not at two points.
//
// [TestNoFragmentThisServerSendsExceedsSpecB46sPartSize] picks 60000 and 512, and a ceiling that
// had been doubled clamps the first and honours the second exactly as the real one does — so the
// window where the rule actually breaks, (2048, 4096], is the window neither case is in. That
// mutation was applied to the shipped build and the whole suite stayed green, and under it a peer
// configured with FragmentPartBytes 3000 puts 3000-byte parts on the wire: a MUST NOT of §4.6,
// which every conforming receiver is entitled to refuse.
//
// So the ceiling is asserted against §4.6's own formula — min(peer_advertised_frame_budget, 2048)
// — at every budget from nothing to twice the ceiling, rather than at sizes chosen to be
// obviously inside or obviously outside it.
func TestNoConfiguredBudgetPutsAPartPastSpecB46sCeiling(t *testing.T) {
	t.Run("the min itself, across the whole window", func(t *testing.T) {
		for budget := -MaxFragmentPartBytes; budget <= 2*MaxFragmentPartBytes; budget++ {
			// §4.6's rule as §4.6 writes it: the smaller of the negotiated budget and 2048, and
			// a budget of zero or less is no negotiation at all, so there is nothing to be the
			// smaller of
			want := min(budget, MaxFragmentPartBytes)
			if budget <= 0 {
				want = MaxFragmentPartBytes
			}
			if got := partSize(budget); got != want {
				t.Fatalf("a negotiated budget of %d cuts %d byte parts, want min(%d, %d) = %d",
					budget, got, budget, MaxFragmentPartBytes, want)
			}
		}
	})

	t.Run("a budget one byte past the ceiling is clamped on the wire", func(t *testing.T) {
		// one byte past, because that is the near edge of the window the two cases in the test
		// beside this one skip over
		fixture := newFixtureWith(t, Config{FragmentPartBytes: MaxFragmentPartBytes + 1})
		if fixture.peer.fragmentPartBytes != MaxFragmentPartBytes {
			t.Fatalf("a peer configured one byte past §4.6's ceiling cuts %d byte parts", fixture.peer.fragmentPartBytes)
		}
		parts := largeFetchParts(t, fixture)
		if len(parts) < 2 {
			t.Fatalf("a 9000 byte response travelled in %d fragments", len(parts))
		}
		for index, part := range parts {
			if MaxFragmentPartBytes < part {
				t.Fatalf("fragment %d carries %d bytes, past §4.6's %d", index, part, MaxFragmentPartBytes)
			}
		}
	})
}

// §4.6's part size is a rule this server obeys as a sender and does not enforce as a receiver.
//
// The position is recorded rather than left to be inferred from what no test looks at. §4.6 says
// "the sender chooses `part` size as min(peer_advertised_frame_budget, 2048)", and the bound it
// gives the *receiver* is `max_request_bytes` over the reassembled request — so an inbound part
// far past 2048 is accepted here as long as the reassembly stays inside that, and a part past
// `max_request_bytes` is refused REASON_OVERSIZE like any other reassembly that would exceed it.
//
// It is a reading rather than an oversight: the budget is negotiated per peer, this server
// advertises none, and a receiver that refused parts at its own sender ceiling would refuse
// conforming senders that negotiated a larger one. What makes it worth a test is that the
// alternative reading is equally defensible and nothing else in this package says which one is
// built.
func TestAnInboundPartPastSpecB46sSenderBudgetIsAcceptedAndTheReceiversOwnBoundIsNot(t *testing.T) {
	clock := newTestClock()
	buffers := newReassembly(clock.time, DefaultMaxRequestBytes, DefaultReassembliesPerClient, DefaultMaxReassemblies, DefaultReassemblyIdle)
	clientId := connect.NewId()

	past := bytes.Repeat([]byte{0x6c}, 32*MaxFragmentPartBytes)
	if len(past) <= MaxFragmentPartBytes || DefaultMaxRequestBytes < len(past) {
		t.Fatalf("a part of %d bytes is not past §4.6's %d and inside max_request_bytes %d", len(past), MaxFragmentPartBytes, DefaultMaxRequestBytes)
	}
	if _, _, reason := buffers.accept(clientId, &protocol.MessageServerFragment{RequestId: 1, Index: 0, Count: 2, Part: past}); reason != protocol.Reason_REASON_OK {
		t.Fatalf("an inbound part of %d bytes, past §4.6's sender ceiling of %d and inside max_request_bytes, was answered %v; this receiver polices the reassembly and not the sender's budget",
			len(past), MaxFragmentPartBytes, reason)
	}
	if holding := buffers.holding(); holding.bytes != len(past) {
		t.Fatalf("the oversized part was answered REASON_OK and buffered as %+v", holding)
	}

	// and the bound this receiver does hold refuses at its own number
	if _, _, reason := buffers.accept(connect.NewId(), &protocol.MessageServerFragment{
		RequestId: 1, Index: 0, Count: 2, Part: bytes.Repeat([]byte{0x6d}, DefaultMaxRequestBytes+1),
	}); reason != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("a part one byte past max_request_bytes was answered %v", reason)
	}
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

		clients := []connect.Id{}
		for range int(clientCount%4) + 1 {
			clients = append(clients, connect.NewId())
		}
		// tighter than the per-client caps add up to, so a script that spreads itself across
		// clients reaches the bound above §4.6's cap as well as §4.6's own — and so the ceiling
		// below is the smaller of the two rather than the one that is easier to satisfy
		maxReassemblies := max(perClient*len(clients)/2, 1)
		buffers := newReassembly(clock.time, maxRequestBytes, perClient, maxReassemblies, DefaultReassemblyIdle)
		ceiling := held{
			reassemblies: maxReassemblies,
			clients:      len(clients),
			bytes:        maxReassemblies * maxRequestBytes,
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

// The three structures §4.6's state lives in, checked against each other.
//
// `counts` is what the per-client cap is enforced from, `inFlight` is what the memory is held in,
// and `order` is what the expiry walks. A drop that forgot any one of them leaves the cap
// enforced against reassemblies that no longer exist, or memory held under a client the cap
// believes is idle, or an expiry that stops at a buffer nothing holds — and none of those shows
// up in any single accept's answer, which is why this is asserted after every one of them in the
// fuzz.
//
// The order's own invariant is the one [reassembly.expire] stops on: the queue is in the order
// the reassemblies began, so the first entry inside the bound ends the walk. That is only true
// while `started` is assigned at creation and never refreshed — the day a fragment renews it, the
// walk starts missing expired buffers behind the renewed one, and this is what says so.
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

	if self.order.Len() != len(self.inFlight) {
		return fmt.Errorf("%d reassemblies are open and the expiry order holds %d entries", len(self.inFlight), self.order.Len())
	}
	var previous time.Time
	for element := self.order.Front(); element != nil; element = element.Next() {
		key, _ := element.Value.(reassemblyKey)
		current, found := self.inFlight[key]
		if !found {
			return fmt.Errorf("the expiry order holds a reassembly that is not open, so the walk stops at a buffer nothing holds")
		}
		if current.element != element {
			return fmt.Errorf("an open reassembly points at an entry of the expiry order that is not the one holding it, so dropping it would leave the other behind")
		}
		if current.started.Before(previous) {
			return fmt.Errorf("the expiry order is not in the order the reassemblies began (%v after %v), so the walk stops before the expired ones behind it",
				current.started, previous)
		}
		previous = current.started
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
