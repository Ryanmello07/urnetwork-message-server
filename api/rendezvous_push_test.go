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
			added, err := registry.subscribeRendezvous(client, nonce(0x51), box(byte(index)), expire, now)
			if err != nil || !added {
				t.Fatalf("subscription %d of a connection's %d answered %v, %v", index+1, DefaultMaxRendezvousSubscriptionsPerConnection, added, err)
			}
		}
		added, err := registry.subscribeRendezvous(client, nonce(0x51), box(0xF0), expire, now)
		if !errors.Is(err, ErrRendezvousSubscriptionsFull) || added {
			t.Fatalf("a connection's subscription past its bound answered %v, %v; want ErrRendezvousSubscriptionsFull and nothing added", added, err)
		}
		if held := registry.RendezvousSubscriptions(); held != DefaultMaxRendezvousSubscriptionsPerConnection {
			t.Fatalf("the refused subscription left %d held, want %d: refused, and nothing evicted", held, DefaultMaxRendezvousSubscriptionsPerConnection)
		}
		// a repeat of a box it holds is the same subscription, and is answered at the bound
		if added, err := registry.subscribeRendezvous(client, nonce(0x51), box(0), expire, now); err != nil || added {
			t.Fatalf("a repeat of a held box at the bound answered %v, %v; want nothing added and no refusal", added, err)
		}
		// THE CONTROL: the same client on another connection has a bound of its own
		if added, err := registry.subscribeRendezvous(client, nonce(0x52), box(0xF0), expire, now); err != nil || !added {
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
			if added, err := registry.subscribeRendezvous([]byte(connection), nonce(0x51), rendezvousId, until, now); err != nil || !added {
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
