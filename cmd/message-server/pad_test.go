package main

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/peer"
	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/protocol"
)

// §4.5's reject floor, as the peer serves it (LRI R75, T3).
//
// It lives here and not in peer for stack_test.go's reason: the property is about the peer serving
// the real *api.Handler, and peer's tests may not build one, since api.New takes a store.

// A stack over a handler that serves the rendezvous arms at `floor`, with the peer's default workers.
func newPaddedStack(t *testing.T, floor time.Duration) *stack {
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
	return newStackOver(t, memory, connections, checks, handler)
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
