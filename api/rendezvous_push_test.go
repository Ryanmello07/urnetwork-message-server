package api

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/protocol"
)

// A pusher that takes every push. The registry drops a subscription whose push is refused, on its
// own goroutine, and with no pusher at all every push is refused: the counts below would then
// race that goroutine rather than measure the calls they are about.
type acceptingPusher struct{}

func (acceptingPusher) Push([]byte, []byte, *protocol.MessageServerPush) bool { return true }

// THE RENDEZVOUS REGISTRY IS BOUNDED PER CONNECTION AND INDEXED BY BOX (LRI R75, S-1). A connection
// holds at most DefaultMaxRendezvousSubscriptionsPerConnection rendezvous subscriptions, the bound its
// group subscriptions have, and one more is refused, ErrRendezvousSubscriptionsFull, with nothing
// evicted; a repeat of a box it holds is the same subscription and is not refused at the bound; and a
// second connection of the same client, a re-Hello's, has a bound of its own.
//
// What each call touches is counted, in subscriptions visited, so that the index is a measurement and
// not a claim. A deposit into one box visits that box's subscribers and no others, a retire the same,
// a subscribe none at all, and a prune the subscribers of the boxes it drops, which are past their
// expiry, and none of a box still live. The reviewer's measure of the scan this replaces was 41 µs a
// subscribe at ten thousand subscriptions and 1.6 ms at eighty thousand, each under the one mutex
// Submit's publish takes.
func TestARendezvousRegistryIsBoundedPerConnectionAndTouchesOnlyTheBoxItIsTold(t *testing.T) {
	now := time.Unix(1767225600, 0).UTC()
	expire := now.Add(DefaultLinkBoxTtl)
	box := func(seed byte) []byte { return linkBytes(store.RendezvousIdBytes, seed) }
	client := []byte("a client id the platform authenticated")

	t.Run("TheBound", func(t *testing.T) {
		registry := NewSubscriptions()
		registry.SetPusher(acceptingPusher{})
		t.Cleanup(registry.Close)
		for index := range DefaultMaxRendezvousSubscriptionsPerConnection {
			_, added, err := registry.subscribeRendezvous(client, nonce(0x51), box(byte(index)), expire, now)
			if err != nil || !added {
				t.Fatalf("subscription %d of a connection's %d answered %v, %v", index+1, DefaultMaxRendezvousSubscriptionsPerConnection, added, err)
			}
		}
		_, added, err := registry.subscribeRendezvous(client, nonce(0x51), box(0xF0), expire, now)
		if !errors.Is(err, ErrRendezvousSubscriptionsFull) || added {
			t.Fatalf("a connection's subscription past its bound answered %v, %v; want ErrRendezvousSubscriptionsFull and nothing added", added, err)
		}
		if held := registry.RendezvousSubscriptions(); held != DefaultMaxRendezvousSubscriptionsPerConnection {
			t.Fatalf("the refused subscription left %d held, want %d: refused, and nothing evicted", held, DefaultMaxRendezvousSubscriptionsPerConnection)
		}
		// a repeat of a box it holds is the same subscription, and is answered at the bound
		if _, added, err := registry.subscribeRendezvous(client, nonce(0x51), box(0), expire, now); err != nil || added {
			t.Fatalf("a repeat of a held box at the bound answered %v, %v; want nothing added and no refusal", added, err)
		}
		// THE CONTROL: the same client on another connection has a bound of its own
		if _, added, err := registry.subscribeRendezvous(client, nonce(0x52), box(0xF0), expire, now); err != nil || !added {
			t.Fatalf("another connection's first subscription answered %v, %v", added, err)
		}
	})

	t.Run("WhatEachCallTouches", func(t *testing.T) {
		registry := NewSubscriptions()
		registry.SetPusher(acceptingPusher{})
		t.Cleanup(registry.Close)
		visited := func() uint64 {
			registry.mutex.Lock()
			defer registry.mutex.Unlock()
			count := registry.rendezvousVisited
			registry.rendezvousVisited = 0
			return count
		}
		subscribe := func(connection string, rendezvousId []byte, until time.Time) {
			t.Helper()
			if _, added, err := registry.subscribeRendezvous([]byte(connection), nonce(0x51), rendezvousId, until, now); err != nil || !added {
				t.Fatalf("subscribing %s answered %v, %v", connection, added, err)
			}
		}
		boxA, boxB, boxC, boxD := box(0xA0), box(0xB0), box(0xC0), box(0xD0)
		for index := range 3 {
			subscribe(fmt.Sprintf("a%d", index), boxA, expire)
		}
		for index := range 40 {
			subscribe(fmt.Sprintf("b%d", index), boxB, expire)
		}
		visited()

		registry.depositedRendezvous(boxA, 1, now)
		if got := visited(); got != 3 {
			t.Fatalf("a deposit into a box with 3 subscribers, beside one with 40, visited %d subscriptions, want 3", got)
		}
		registry.retiredRendezvous(boxB)
		if got := visited(); got != 40 {
			t.Fatalf("a retire of a box with 40 subscribers visited %d subscriptions, want 40", got)
		}
		if held := registry.RendezvousSubscriptions(); held != 3 {
			t.Fatalf("after the retire the registry holds %d subscriptions, want box A's 3", held)
		}
		subscribe("c", boxC, expire)
		if got := visited(); got != 0 {
			t.Fatalf("a subscribe visited %d subscriptions, want none", got)
		}

		// a prune drops what has expired, and visits that and nothing else: box D lapses a minute in
		for index := range 5 {
			subscribe(fmt.Sprintf("d%d", index), boxD, now.Add(time.Minute))
		}
		visited()
		registry.depositedRendezvous(boxA, 2, now.Add(2*time.Minute))
		if got := visited(); got != 5+3 {
			t.Fatalf("a deposit into box A, made after box D lapsed, visited %d subscriptions, want box D's 5 dropped and box A's 3 marked", got)
		}
		if held := registry.RendezvousSubscriptions(); held != 3+1 {
			t.Fatalf("after box D lapsed the registry holds %d subscriptions, want box A's 3 and box C's 1", held)
		}
	})
}

// A RENDEZVOUS SUBSCRIPTION IS OF ONE BOX, AND A COLLECT UNDOES ONLY ITS OWN CLAIM ON IT (LRI R78, N2
// and N3), held at the registry, where cmd/message-server's tests hold it through the arm.
//
// A box is its id and its expiry. A subscription for a box that expires before the one standing at
// its id is for a box that has gone: it is answered no subscription and no error, and the standing
// box's subscriber is untouched. One for a box that expires after it ends the standing one, which is
// the box that has gone.
//
// A Collect settles the claim it took. A subscription ends for a Collect whose write did not take
// only when no Collect kept it and none is still to settle; and a claim on a subscription that has
// ended since, and been made again by another Collect, settles nothing.
func TestARendezvousSubscriptionIsOfOneBoxAndACollectUndoesOnlyItsOwnClaim(t *testing.T) {
	now := time.Unix(1767225600, 0).UTC()
	earlier, later := now.Add(DefaultLinkBoxTtl), now.Add(DefaultLinkBoxTtl+time.Minute)
	id := linkBytes(store.RendezvousIdBytes, 0x70)
	holder, stale := []byte("the later box's collector"), []byte("a Collect verified against the earlier box")
	newRegistry := func(t *testing.T) *Subscriptions {
		registry := NewSubscriptions()
		registry.SetPusher(acceptingPusher{})
		t.Cleanup(registry.Close)
		return registry
	}
	holds := func(registry *Subscriptions, client []byte) bool {
		registry.mutex.Lock()
		defer registry.mutex.Unlock()
		box := registry.rendezvousBoxes[string(id)]
		return box != nil && box.subscribers[connectionKeyOf(client, nonce(0x51))] != nil
	}

	t.Run("AGoneBoxSubscribesNothing", func(t *testing.T) {
		registry := newRegistry(t)
		if _, added, err := registry.subscribeRendezvous(holder, nonce(0x51), id, later, now); err != nil || !added {
			t.Fatalf("the later box's subscription answered %v, %v", added, err)
		}
		claimed, added, err := registry.subscribeRendezvous(stale, nonce(0x51), id, earlier, now)
		if claimed != nil || added || err != nil {
			t.Fatalf("a subscription for the earlier box, the later standing at its id, answered %v, %v, %v; want nothing and no error", claimed != nil, added, err)
		}
		if !holds(registry, holder) || holds(registry, stale) || registry.RendezvousSubscriptions() != 1 {
			t.Fatalf("after it the registry holds %d subscriptions, the later box's collector's %v: want that one alone", registry.RendezvousSubscriptions(), holds(registry, holder))
		}
		// THE CONTROL: a box standing under the earlier expiry is the one gone, and is ended
		registry = newRegistry(t)
		registry.subscribeRendezvous(stale, nonce(0x51), id, earlier, now)
		if _, added, err := registry.subscribeRendezvous(holder, nonce(0x51), id, later, now); err != nil || !added {
			t.Fatalf("the later box's subscription, the earlier standing, answered %v, %v", added, err)
		}
		if !holds(registry, holder) || holds(registry, stale) || registry.RendezvousSubscriptions() != 1 {
			t.Fatalf("the earlier box's subscription outlasted the later box's: %d held", registry.RendezvousSubscriptions())
		}
	})

	t.Run("AnUndoIsOfItsOwnClaim", func(t *testing.T) {
		for _, order := range []struct {
			name     string
			settle   []bool // the first claim's settlement, then the second's
			reversed bool   // the second settles first
			holds    bool
		}{
			{"the first fails, the second takes", []bool{false, true}, false, true},
			{"the second takes, then the first fails", []bool{false, true}, true, true},
			{"the first takes, the second fails", []bool{true, false}, false, true},
			{"both fail", []bool{false, false}, false, false},
			{"both fail, the second first", []bool{false, false}, true, false},
		} {
			registry := newRegistry(t)
			first, added, _ := registry.subscribeRendezvous(holder, nonce(0x51), id, later, now)
			second, again, _ := registry.subscribeRendezvous(holder, nonce(0x51), id, later, now)
			if first == nil || !added || second != first || again {
				t.Fatalf("%s: two Collects with subscribe made %v and %v, want one subscription made and then found", order.name, added, again)
			}
			if order.reversed {
				registry.settleRendezvous(holder, nonce(0x51), id, second, order.settle[1])
				registry.settleRendezvous(holder, nonce(0x51), id, first, order.settle[0])
			} else {
				registry.settleRendezvous(holder, nonce(0x51), id, first, order.settle[0])
				registry.settleRendezvous(holder, nonce(0x51), id, second, order.settle[1])
			}
			if held := holds(registry, holder); held != order.holds {
				t.Fatalf("%s: the registry holds the subscription %v, want %v", order.name, held, order.holds)
			}
		}

		// a claim on a subscription ended since, and made again by another Collect, settles nothing
		registry := newRegistry(t)
		first, _, _ := registry.subscribeRendezvous(holder, nonce(0x51), id, later, now)
		registry.retiredRendezvous(id)
		second, added, _ := registry.subscribeRendezvous(holder, nonce(0x51), id, later, now)
		if second == nil || second == first || !added {
			t.Fatal("a subscription made again after a retire is not a subscription of its own")
		}
		registry.settleRendezvous(holder, nonce(0x51), id, first, false)
		if !holds(registry, holder) {
			t.Fatal("a failed Collect's claim on a subscription ended since undid the one made again by another Collect")
		}
	})
}
