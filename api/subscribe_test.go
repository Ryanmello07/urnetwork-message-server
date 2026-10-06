package api

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message/protocol"
)

// The registry's own rules, below the handler: the epoch ceiling, dropping a connection that is
// gone, replace and unsubscribe, the cap, and coalescing. The end to end proof is
// sdk/cp3b/push_test.go.

type recordedPush struct {
	clientId  []byte
	groupId   []byte
	highWater uint64
}

type fakePusher struct {
	mutex   sync.Mutex
	pushes  chan recordedPush
	refuse  bool
	release chan struct{}
}

func newFakePusher() *fakePusher {
	return &fakePusher{pushes: make(chan recordedPush, 64)}
}

func (self *fakePusher) Push(clientId []byte, serverNonce []byte, push *protocol.MessageServerPush) bool {
	self.mutex.Lock()
	refuse, release := self.refuse, self.release
	self.mutex.Unlock()
	if release != nil {
		<-release
	}
	records := push.GetRecords()
	self.pushes <- recordedPush{clientId: clientId, groupId: records.GetGroupId(), highWater: records.GetHighWaterRecordId()}
	return !refuse
}

func (self *fakePusher) next(within time.Duration) (recordedPush, bool) {
	select {
	case push := <-self.pushes:
		return push, true
	case <-time.After(within):
		return recordedPush{}, false
	}
}

var (
	testClient = []byte("client-0000000001")
	testNonce  = []byte("nonce-0001")
	testGroup  = bytes.Repeat([]byte{0x47}, 32)
)

func TestAPushIsOwedOnlyForRecordsAtOrBelowTheSubscribersCeiling(t *testing.T) {
	subscriptions := NewSubscriptions()
	defer subscriptions.Close()
	pusher := newFakePusher()
	subscriptions.SetPusher(pusher)
	if err := subscriptions.subscribe(testClient, testNonce, testGroup, 1, 5, false); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// a record sealed ABOVE the ceiling the subscription was authorized at: no push, which is the
	// same high water a fetch at that read_epoch would be told
	subscriptions.published(testGroup, []publishedRecord{{recordId: 6, epoch: 2}})
	if push, pushed := pusher.next(300 * time.Millisecond); pushed {
		t.Fatalf("a record at epoch 2 was announced to a subscription at ceiling 1: %+v", push)
	}

	// the control: a record at the ceiling IS announced, at its own id
	subscriptions.published(testGroup, []publishedRecord{{recordId: 7, epoch: 1}})
	push, pushed := pusher.next(2 * time.Second)
	if !pushed {
		t.Fatal("a record at the subscription's own ceiling produced no push")
	}
	if !bytes.Equal(push.groupId, testGroup) || push.highWater != 7 {
		t.Fatalf("the push named group %x at high water %d, want %x at 7", push.groupId, push.highWater, testGroup)
	}

	// and another group's record reaches nobody here
	subscriptions.published(bytes.Repeat([]byte{0x48}, 32), []publishedRecord{{recordId: 9, epoch: 1}})
	if push, pushed := pusher.next(300 * time.Millisecond); pushed {
		t.Fatalf("a record of another group was announced: %+v", push)
	}
}

func TestAPushThatCannotBeDeliveredDropsItsSubscription(t *testing.T) {
	subscriptions := NewSubscriptions()
	defer subscriptions.Close()
	pusher := newFakePusher()
	pusher.refuse = true
	subscriptions.SetPusher(pusher)
	if err := subscriptions.subscribe(testClient, testNonce, testGroup, 1, 0, false); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	subscriptions.published(testGroup, []publishedRecord{{recordId: 1, epoch: 1}})
	if _, pushed := pusher.next(2 * time.Second); !pushed {
		t.Fatal("no push was attempted")
	}
	deadline := time.Now().Add(2 * time.Second)
	for subscriptions.Stats().Dropped == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("a refused push left its subscription in place: %+v", subscriptions.Stats())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if stats := subscriptions.Stats(); stats.Subscriptions != 0 || stats.Connections != 0 {
		t.Fatalf("after the drop the registry holds %+v", stats)
	}
	// and nothing is tried again for it
	subscriptions.published(testGroup, []publishedRecord{{recordId: 2, epoch: 1}})
	if push, pushed := pusher.next(300 * time.Millisecond); pushed {
		t.Fatalf("a dropped subscription was pushed again: %+v", push)
	}
}

func TestReplaceUnsubscribeAndTheCapAreOneConnectionsOwn(t *testing.T) {
	subscriptions := NewSubscriptions()
	defer subscriptions.Close()
	group := func(index int) []byte { return bytes.Repeat([]byte{byte(index)}, 32) }
	for index := 0; index < DefaultMaxSubscriptionsPerConnection; index++ {
		if err := subscriptions.subscribe(testClient, testNonce, group(index), 1, 0, false); err != nil {
			t.Fatalf("subscription %d of %d: %v", index+1, DefaultMaxSubscriptionsPerConnection, err)
		}
	}
	if err := subscriptions.subscribe(testClient, testNonce, group(200), 1, 0, false); !errors.Is(err, ErrSubscriptionsFull) {
		t.Fatalf("subscription %d answered %v, want ErrSubscriptionsFull", DefaultMaxSubscriptionsPerConnection+1, err)
	}
	// re-subscribing to a group already held is not a new one, so the cap does not refuse it
	if err := subscriptions.subscribe(testClient, testNonce, group(0), 2, 0, false); err != nil {
		t.Fatalf("re-subscribing a held group at the cap: %v", err)
	}
	// ANOTHER connection is not charged against this one's cap
	if err := subscriptions.subscribe([]byte("client-0000000002"), testNonce, group(200), 1, 0, false); err != nil {
		t.Fatalf("a second connection's first subscription: %v", err)
	}
	// replace is the complete set for THIS connection
	if err := subscriptions.subscribe(testClient, testNonce, group(7), 1, 0, true); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if stats := subscriptions.Stats(); stats.Subscriptions != 2 || stats.Connections != 2 {
		t.Fatalf("after replace the registry holds %+v, want one subscription on each of two connections", stats)
	}
	// unsubscribing what is not held is not an error and changes nothing
	subscriptions.unsubscribe(testClient, testNonce, [][]byte{group(99)}, false)
	subscriptions.unsubscribe(testClient, testNonce, nil, true)
	if stats := subscriptions.Stats(); stats.Subscriptions != 1 || stats.Connections != 1 {
		t.Fatalf("after unsubscribe-all the registry holds %+v, want only the other connection's", stats)
	}
	// a re-Hello is a new nonce, which is a new connection holding nothing
	subscriptions.unsubscribe([]byte("client-0000000002"), []byte("nonce-0002"), nil, true)
	if stats := subscriptions.Stats(); stats.Subscriptions != 1 {
		t.Fatalf("unsubscribing under another nonce cancelled %d subscriptions it did not make", 1-stats.Subscriptions)
	}
}

func TestPushesToABusyConnectionCoalesceToTheLatestHighWater(t *testing.T) {
	subscriptions := NewSubscriptions()
	defer subscriptions.Close()
	pusher := newFakePusher()
	pusher.release = make(chan struct{})
	subscriptions.SetPusher(pusher)
	if err := subscriptions.subscribe(testClient, testNonce, testGroup, 1, 0, false); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	// the first push is held on the wire while three more records land
	subscriptions.published(testGroup, []publishedRecord{{recordId: 1, epoch: 1}})
	time.Sleep(50 * time.Millisecond)
	for id := uint64(2); id <= 4; id++ {
		subscriptions.published(testGroup, []publishedRecord{{recordId: id, epoch: 1}})
	}
	close(pusher.release)
	var seen []uint64
	for {
		push, pushed := pusher.next(500 * time.Millisecond)
		if !pushed {
			break
		}
		seen = append(seen, push.highWater)
	}
	if len(seen) == 0 || seen[len(seen)-1] != 4 {
		t.Fatalf("the pushes named %v; the last must be the latest high water, 4", seen)
	}
	if 2 < len(seen) {
		t.Fatalf("four records to one busy connection produced %d pushes %v; they coalesce to at most two", len(seen), seen)
	}
	t.Log(fmt.Sprintf("four records, one busy connection: pushes %v", seen))
}
