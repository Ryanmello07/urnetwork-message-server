package main

import (
	"context"
	"crypto/rand"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/peer"
	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/protocol"
	"google.golang.org/protobuf/proto"
)

// §4.5's reject floor, as the peer serves it (LRI R75, T3).
//
// It lives here and not in peer for stack_test.go's reason: the property is about the peer serving
// the real *api.Handler, and peer's tests may not build one, since api.New takes a store.

// A stack over a handler that serves the rendezvous arms at `floor`, with the peer's default workers.
func newPaddedStack(t *testing.T, floor time.Duration) *stack {
	t.Helper()
	return newPaddedStackTuned(t, floor, nil)
}

// [newPaddedStack], with the peer's configuration handed to `tune` first.
func newPaddedStackTuned(t *testing.T, floor time.Duration, tune func(*peer.Config)) *stack {
	t.Helper()
	memory := store.NewMemoryStore(store.DefaultLimits())
	connections, err := peer.NewConnections(rand.Reader, time.Now, time.Hour)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	checks, err := peer.NewChecks(connections, peer.DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	subscriptions := api.NewSubscriptions()
	t.Cleanup(subscriptions.Close)
	handler, err := api.New(api.Config{
		Store:         memory,
		KnownGroups:   api.NewStoreKnownGroups(memory),
		Front:         checks,
		LinkBoxes:     memory,
		RejectFloor:   floor,
		Subscriptions: subscriptions,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	if !handler.RendezvousServed() {
		t.Fatal("a handler with a link box store and a floor does not serve the rendezvous arms")
	}
	return newStackOverTuned(t, memory, connections, checks, handler, tune)
}

// Once the peer has received `frames` frames, or a failure.
func (self *stack) receivedAtLeast(t *testing.T, frames uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for self.peer.Stats().FramesReceived < frames {
		if time.Now().After(deadline) {
			t.Fatalf("the peer received %d frames in 10 s, want %d", self.peer.Stats().FramesReceived, frames)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// One refused Open's answer, and how long after it was sent it came.
type refusedOpen struct {
	reason protocol.Reason
	took   time.Duration
	err    error
}

// `count` Opens at ids no box has, sent at once, each answered on the channel when it comes.
func (self *stack) refusedOpens(ctx context.Context, count int) chan refusedOpen {
	answers := make(chan refusedOpen, count)
	for index := range count {
		go func() {
			id := make([]byte, store.RendezvousIdBytes)
			id[0], id[1] = 0xA5, byte(index)
			sent := time.Now()
			response, err := self.client.Call(ctx, &protocol.RendezvousOpenRequest{RendezvousId: id})
			answers <- refusedOpen{reason: response.GetReason(), took: time.Since(sent), err: err}
		}()
	}
	return answers
}

// A PADDED REFUSAL HOLDS NO WORKER (LRI R75, T3; §4.5). The handler returns a padded refusal at once,
// with the rest of its floor, and the peer sends the answer from a timer off its worker pool. So a
// request that is not padded, sent behind more padded refusals than the peer has workers, is answered
// within a bound far short of the floor, where a pad slept on a worker answered it a floor later for
// each wave of eight. The bound stated: half the floor, at a floor of 500 ms, behind sixteen refusals,
// twice the default workers. The refusals keep their floor: each is answered REASON_CARD_RETIRED no
// sooner than the floor after it was sent, and the peer counts sixteen answers deferred.
//
// SLEEP-ON-WORKER, the pad slept on the worker as it was, is killed by the bound; PEER-SYNC, the
// deferral ignored and the answer sent at once, by the floor.
func TestAPaddedRefusalHoldsNoWorker(t *testing.T) {
	const (
		floor     = 500 * time.Millisecond
		refusals  = 16
		bound     = floor / 2
		handshake = 1
	)
	current := newPaddedStack(t, floor)
	current.hello(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	answers := current.refusedOpens(ctx, refusals)
	current.receivedAtLeast(t, handshake+refusals)

	sent := time.Now()
	response, err := current.client.Call(ctx, &protocol.UnsubscribeRequest{All: true})
	took := time.Since(sent)
	if err != nil || response.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("Unsubscribe behind the refusals answered %v (%v)", response.GetReason(), err)
	}
	if bound < took {
		t.Fatalf("an Unsubscribe sent behind %d padded refusals was answered after %v, beyond the bound of %v at a floor of %v: the refusals held the peer's workers",
			refusals, took, bound, floor)
	}

	for range refusals {
		answer := <-answers
		if answer.err != nil || answer.reason != protocol.Reason_REASON_CARD_RETIRED {
			t.Fatalf("a refused Open answered %v (%v), want REASON_CARD_RETIRED", answer.reason, answer.err)
		}
		if answer.took < floor {
			t.Fatalf("a refused Open was answered %v after it was sent, before the floor of %v", answer.took, floor)
		}
	}
	if deferred := current.peer.Stats().AnswersDeferred; deferred != refusals {
		t.Fatalf("the peer deferred %d answers, want the %d refusals'", deferred, refusals)
	}
	t.Logf("behind %d refusals at a floor of %v, the Unsubscribe was answered after %v; the refusals each waited out the floor", refusals, floor, took)
}

// A DEFERRED ANSWER DOES NOT HOLD THE PEER'S CLOSE (LRI R75, T3). Refusals waiting out a long floor are
// dropped when the peer closes, as a worker's sleeping one was, and Close returns at once rather than
// when the floor has passed: the waits are on timers, which Close ends, and not on workers' sleeps,
// which nothing ends. The control is the refusals' own count, which shows they were waiting.
func TestAPeerClosesWithoutWaitingOutADeferredAnswer(t *testing.T) {
	const floor = 20 * time.Second
	current := newPaddedStack(t, floor)
	current.hello(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	answers := current.refusedOpens(ctx, 4)
	deadline := time.Now().Add(10 * time.Second)
	for current.peer.Stats().AnswersDeferred < 4 {
		if time.Now().After(deadline) {
			t.Fatalf("the peer deferred %d answers in 10 s, want 4", current.peer.Stats().AnswersDeferred)
		}
		time.Sleep(2 * time.Millisecond)
	}
	started := time.Now()
	current.peer.Close()
	if took := time.Since(started); floor/4 < took {
		t.Fatalf("the peer took %v to close with four answers waiting out a floor of %v", took, floor)
	}
	cancel()
	var once sync.Once
	for range 4 {
		if answer := <-answers; answer.err == nil && answer.reason == protocol.Reason_REASON_CARD_RETIRED {
			once.Do(func() {
				t.Errorf("a refusal waiting out its floor was answered across the peer's Close, after %v", answer.took)
			})
		}
	}
}

// `refusals` Opens at ids no box has, sent at once to a peer that lets `slots` answers wait out their
// floor at a time, and how long each took, in the order the answers came.
//
// Each is answered REASON_CARD_RETIRED no sooner than the floor after it was sent. And past the bound,
// a worker waits for a waiting answer to be sent before it defers another, which then waits out its
// own rest from there: so the answers come `slots` at a time, a floor apart, and the k-th no sooner
// than ceil(k / slots) floors after it was sent. That is held with half a floor of slack, which an
// answer let past the bound early does not meet, and neither does one that never met a bound.
func (self *stack) refusalsWaitOutTheBound(t *testing.T, floor time.Duration, refusals int, slots int) []time.Duration {
	t.Helper()
	// every answer is due within refusals ÷ slots floors; this is many times that, and a refusal not
	// answered by it is one that waits for room that never comes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	answers := self.refusedOpens(ctx, refusals)
	took := []time.Duration{}
	for range refusals {
		answer := <-answers
		if answer.err != nil || answer.reason != protocol.Reason_REASON_CARD_RETIRED {
			t.Fatalf("a refused Open answered %v (%v), want REASON_CARD_RETIRED", answer.reason, answer.err)
		}
		took = append(took, answer.took)
	}
	slices.Sort(took)
	for index, after := range took {
		if after < floor {
			t.Fatalf("a refused Open was answered %v after it was sent, before the floor of %v; the answers took %v", after, floor, took)
		}
		waves := (index + slots) / slots
		if least := time.Duration(waves)*floor - floor/2; 1 < waves && after < least {
			t.Fatalf("answer %d of %d came %v after it was sent, where a bound of %d waiting at once makes it wait %d floors of %v: more answers waited at once than the bound lets wait; the answers took %v",
				index+1, refusals, after, slots, waves, floor, took)
		}
	}
	return took
}

// THE BOUND ON WAITING ANSWERS KEEPS THE FLOOR (LRI R78, N1). Past MaxDeferredAnswers a worker waits
// for a waiting answer to be sent before it defers another, and no answer is sent before its floor:
// eight refusals sent at once to a peer that lets two answers wait are each answered no sooner than the
// floor, two at a time, a floor apart, and all eight are counted deferred. BOUND-CUTS-FLOOR, which sends
// an answer past the bound at once, is killed by the floor; UNBOUNDED, which takes no slot at all, by
// the waves.
func TestRefusalsPastTheBoundOnWaitingAnswersKeepTheirFloor(t *testing.T) {
	const (
		floor    = 300 * time.Millisecond
		refusals = 8
		slots    = 2
	)
	current := newPaddedStackTuned(t, floor, func(config *peer.Config) { config.MaxDeferredAnswers = slots })
	current.hello(t)
	took := current.refusalsWaitOutTheBound(t, floor, refusals, slots)
	if deferred := current.peer.Stats().AnswersDeferred; deferred != refusals {
		t.Fatalf("the peer deferred %d answers, want the %d refusals'", deferred, refusals)
	}
	t.Logf("%d refusals at once, %d answers let wait at a time, at a floor of %v: answered after %v", refusals, slots, floor, took)
}

// THE BYTES OF WAITING ANSWERS ARE BOUNDED TOO, AND KEEP THE FLOOR (LRI R78, N5). Past MaxDeferredBytes,
// as past MaxDeferredAnswers, a worker waits for waiting answers to be sent before it defers another,
// and no answer is sent before its floor. A refused Open's answer is a request_id and a reason, a few
// octets; the peer here lets as many wait as fit in twice the size of one with a two-octet request_id,
// and one octet more, which is two of them and not three, whatever their request ids. Eight refusals
// sent at once, with the count left at its default, are then answered no sooner than the floor, two at
// a time, a floor apart. BYTES-CUTS-FLOOR, which sends an answer past the budget at once, is killed by
// the floor; BYTES-UNBOUNDED, which counts no bytes, by the waves.
func TestRefusalsPastTheByteBudgetOfWaitingAnswersKeepTheirFloor(t *testing.T) {
	const (
		floor    = 300 * time.Millisecond
		refusals = 8
		slots    = 2
	)
	one := proto.Size(&protocol.MessageServerResponse{RequestId: 1<<14 - 1, Reason: protocol.Reason_REASON_CARD_RETIRED})
	current := newPaddedStackTuned(t, floor, func(config *peer.Config) { config.MaxDeferredBytes = slots*one + 1 })
	current.hello(t)
	took := current.refusalsWaitOutTheBound(t, floor, refusals, slots)
	if deferred := current.peer.Stats().AnswersDeferred; deferred != refusals {
		t.Fatalf("the peer deferred %d answers, want the %d refusals'", deferred, refusals)
	}
	t.Logf("%d refusals at once, %d octets of answers let wait at a time, an answer at most %d, at a floor of %v: answered after %v", refusals, slots*one+1, one, floor, took)
}

// AN ANSWER LARGER THAN THE WHOLE BYTE BUDGET IS STILL SENT, ALONE (LRI R78, N5). An answer is counted
// at no more than the whole budget, so that one larger than it waits for the others to be sent and is
// then sent itself, rather than waiting for room that can never be made. A peer whose budget is one
// octet, smaller than any answer, answers four refusals sent at once one at a time, a floor apart, each
// no sooner than the floor. BYTES-UNCAPPED, which counts such an answer whole, is killed here: its
// answers wait for ever.
func TestAnAnswerLargerThanTheWholeByteBudgetIsStillSentAlone(t *testing.T) {
	const (
		floor    = 200 * time.Millisecond
		refusals = 4
	)
	current := newPaddedStackTuned(t, floor, func(config *peer.Config) { config.MaxDeferredBytes = 1 })
	current.hello(t)
	took := current.refusalsWaitOutTheBound(t, floor, refusals, 1)
	t.Logf("%d refusals at once, a byte budget of one octet, at a floor of %v: answered after %v", refusals, floor, took)
}
