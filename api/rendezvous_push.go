package api

import (
	"bytes"
	"container/heap"
	"errors"
	"time"

	"github.com/urnetwork/message/protocol"
)

// §4.3.11's PUSH: a collector that set `subscribe` on a Collect is told of every deposit into its
// box, for the life of its connection, by a RendezvousPush carrying the rendezvous id and the
// count waiting "and nothing else". It rides [Subscriptions]: the same per-connection keying, the
// same delivery goroutine, and a refused push drops the subscription, for the reason a refused
// RecordPush does. The collector's next Collect is the retry.
//
// A subscription ends with its box. A retire ends it at once; a box past its expiry, which no
// deposit can reach, is dropped by the next rendezvous call this registry is told of after it.
//
// BOUNDED PER CONNECTION, AND INDEXED BY BOX (LRI R75, S-1). A connection holds at most
// [DefaultMaxRendezvousSubscriptionsPerConnection] rendezvous subscriptions, the bound its group
// subscriptions have, and one more is refused, never made by evicting one: an eviction would be a
// silent stop. The subscriptions are kept by box, so that a deposit or a retire touches that box's
// subscribers and no others, and the boxes are kept in expiry order as well, so that dropping what
// has expired visits what it drops and nothing else. Before this, every subscribe, deposit and
// retire scanned every subscription under the one mutex Submit's publish takes, which one client
// could grow without bound; what bounds a client now is the cap on live boxes and each box's
// expiry, and none of the calls above costs more than its own box's subscribers.

// The rendezvous subscriptions one connection may hold: the bound a connection's group
// subscriptions have, so that a connection's two bounds are one number. A link session holds one
// box, so it is ample.
const DefaultMaxRendezvousSubscriptionsPerConnection = DefaultMaxSubscriptionsPerConnection

var ErrRendezvousSubscriptionsFull = errors.New("api: this connection holds as many rendezvous subscriptions as it may")

// One connection's subscription to one box, as the push loop is told it is owed a push.
type rendezvousKey struct {
	connection string
	box        string
}

type rendezvousSubscription struct {
	clientId     []byte
	serverNonce  []byte
	rendezvousId []byte
	// the count the next push carries
	pending uint32
	// THE COLLECTS THAT HOLD IT (LRI R78, N2). A Collect with subscribe makes the subscription, or finds
	// it made, before its write, and settles its claim once the write has answered
	// ([Subscriptions.settleRendezvous]): `claims` counts the Collects that have not settled yet, and
	// `kept` is whether the write of one of them answered REASON_OK. It is the write's answer, not the
	// Collect's: what the Collect then answers its client is not looked at here (LRI R82). It is ended
	// for a Collect whose write did not take only when no Collect kept it and none is still to settle,
	// so that a Collect whose write took does not lose it to another's failed write.
	claims int
	kept   bool
}

// One box's subscribers, by connection, and the box's expiry, fixed at its registration, after which
// nothing can be deposited into it.
type rendezvousBox struct {
	expireTime  time.Time
	subscribers map[string]*rendezvousSubscription
}

// The boxes in expiry order: a min-heap, read only by [Subscriptions.pruneRendezvous]. An entry
// outlives its box when a retire or a refused push ends the box first, and is dropped when it comes
// up: the box it names is gone, or is a later box at the same id, with an expiry of its own.
type rendezvousExpiry []rendezvousExpiryEntry

type rendezvousExpiryEntry struct {
	expireTime time.Time
	box        string
}

func (self rendezvousExpiry) Len() int { return len(self) }
func (self rendezvousExpiry) Less(i, j int) bool {
	return self[i].expireTime.Before(self[j].expireTime)
}
func (self rendezvousExpiry) Swap(i, j int)   { self[i], self[j] = self[j], self[i] }
func (self *rendezvousExpiry) Push(entry any) { *self = append(*self, entry.(rendezvousExpiryEntry)) }
func (self *rendezvousExpiry) Pop() any {
	old := *self
	last := old[len(old)-1]
	*self = old[:len(old)-1]
	return last
}

// subscribeRendezvous registers one connection for pushes on one box until the box's expiry, and
// answers the subscription, with a claim on it taken for the caller to settle
// ([Subscriptions.settleRendezvous]), and whether this call added it: a second Collect with subscribe
// set on the same connection is the same subscription, and adds nothing. A connection already
// holding its bound is refused, [ErrRendezvousSubscriptionsFull], and nothing is evicted. It visits
// no other subscription.
//
// A BOX IS ITS ID AND ITS EXPIRY (LRI R78, N3). A record standing at the id under an earlier expiry
// is a box that has gone, which a live box's Collect cannot be subscribing to, and it is ended here
// rather than joined. One standing under a LATER expiry is a box registered at the id after the box
// this call was verified against had gone: that box is the one gone, and this call subscribes
// nothing and ends nothing, answering no subscription and no error. Its write then finds the later
// box. Where that box is pinned under other keys than the ones this call was verified against, the
// write answers REASON_CARD_RETIRED. Where a client registered the same code with the same keys
// again after a sweep, the write is acted on, as a Collect of that box, with no subscription made
// by this call (LRI R82).
func (self *Subscriptions) subscribeRendezvous(clientId []byte, serverNonce []byte, rendezvousId []byte, expireTime time.Time, now time.Time) (*rendezvousSubscription, bool, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.pruneRendezvous(now)
	connection := connectionKeyOf(clientId, serverNonce)
	box := self.rendezvousBoxes[string(rendezvousId)]
	if box != nil && expireTime.Before(box.expireTime) {
		return nil, false, nil
	}
	if box != nil && box.expireTime.Before(expireTime) {
		self.dropRendezvousBox(string(rendezvousId))
		box = nil
	}
	if box != nil {
		if present := box.subscribers[connection]; present != nil {
			present.claims++
			return present, false, nil
		}
	}
	if self.maxRendezvousPerConnection <= self.rendezvousHeld[connection] {
		return nil, false, ErrRendezvousSubscriptionsFull
	}
	if box == nil {
		box = &rendezvousBox{expireTime: expireTime, subscribers: map[string]*rendezvousSubscription{}}
		self.rendezvousBoxes[string(rendezvousId)] = box
		heap.Push(&self.rendezvousExpiry, rendezvousExpiryEntry{expireTime: expireTime, box: string(rendezvousId)})
	}
	made := &rendezvousSubscription{
		clientId:     bytes.Clone(clientId),
		serverNonce:  bytes.Clone(serverNonce),
		rendezvousId: bytes.Clone(rendezvousId),
		claims:       1,
	}
	box.subscribers[connection] = made
	self.rendezvousHeld[connection]++
	self.rendezvousCount++
	return made, true, nil
}

// settleRendezvous settles the claim a Collect took on a subscription with
// [Subscriptions.subscribeRendezvous], once its write has answered: `taken` is whether it answered
// REASON_OK.
//
// THE UNDO IS OF WHAT THE CALL CLAIMED, COMPARED BY POINTER, as deliverRendezvous compares (LRI R78,
// N2). If the subscription standing for the connection on the box now is not the one claimed, a
// refused push, a retire, the box's expiry or another box at the id has ended that one since, and what
// stands is another Collect's: nothing is settled. Otherwise the claim ends. A Collect that took keeps
// the subscription; one that did not ends it only when no Collect kept it and none is still to settle,
// so that the subscription is undone when every Collect that made or found it failed, and never under
// a Collect whose write took. `taken` is the write's answer, not the Collect's (LRI R82).
func (self *Subscriptions) settleRendezvous(clientId []byte, serverNonce []byte, rendezvousId []byte, claimed *rendezvousSubscription, taken bool) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	connection := connectionKeyOf(clientId, serverNonce)
	box := self.rendezvousBoxes[string(rendezvousId)]
	if box == nil || box.subscribers[connection] != claimed {
		return
	}
	claimed.claims--
	if taken {
		claimed.kept = true
		return
	}
	if !claimed.kept && claimed.claims == 0 {
		self.removeRendezvous(string(rendezvousId), connection)
	}
}

// removeRendezvous ends one connection's subscription to one box. The caller holds the mutex.
func (self *Subscriptions) removeRendezvous(box string, connection string) {
	record := self.rendezvousBoxes[box]
	if record == nil {
		return
	}
	if _, present := record.subscribers[connection]; !present {
		return
	}
	delete(record.subscribers, connection)
	delete(self.rendezvousReady, rendezvousKey{connection: connection, box: box})
	self.releaseRendezvous(connection)
	if len(record.subscribers) == 0 {
		delete(self.rendezvousBoxes, box)
	}
}

// dropRendezvousBox ends every subscription to one box, visiting those. The caller holds the mutex.
func (self *Subscriptions) dropRendezvousBox(box string) {
	record := self.rendezvousBoxes[box]
	if record == nil {
		return
	}
	for connection := range record.subscribers {
		self.rendezvousVisited++
		delete(self.rendezvousReady, rendezvousKey{connection: connection, box: box})
		self.releaseRendezvous(connection)
	}
	delete(self.rendezvousBoxes, box)
}

// One subscription fewer, counted against its connection and in the whole. The caller holds the
// mutex.
func (self *Subscriptions) releaseRendezvous(connection string) {
	self.rendezvousCount--
	if self.rendezvousHeld[connection] <= 1 {
		delete(self.rendezvousHeld, connection)
		return
	}
	self.rendezvousHeld[connection]--
}

// pruneRendezvous drops the subscriptions of every box past its expiry at `now`, in expiry order,
// and visits those and no others. The caller holds the mutex.
func (self *Subscriptions) pruneRendezvous(now time.Time) {
	for self.rendezvousExpiry.Len() != 0 && !now.Before(self.rendezvousExpiry[0].expireTime) {
		entry := heap.Pop(&self.rendezvousExpiry).(rendezvousExpiryEntry)
		if record := self.rendezvousBoxes[entry.box]; record != nil && !now.Before(record.expireTime) {
			self.dropRendezvousBox(entry.box)
		}
	}
}

// depositedRendezvous marks every subscription to the box as owed a push of the box's new count,
// visiting that box's subscribers and no others.
func (self *Subscriptions) depositedRendezvous(rendezvousId []byte, pending uint32, now time.Time) {
	self.mutex.Lock()
	self.pruneRendezvous(now)
	marked := false
	if record := self.rendezvousBoxes[string(rendezvousId)]; record != nil {
		for connection, subscription := range record.subscribers {
			self.rendezvousVisited++
			subscription.pending = pending
			self.rendezvousReady[rendezvousKey{connection: connection, box: string(rendezvousId)}] = true
			marked = true
		}
	}
	self.mutex.Unlock()
	if marked {
		select {
		case self.signal <- struct{}{}:
		default:
		}
	}
}

// retiredRendezvous ends every subscription to a box that has been retired: there is nothing left
// to deposit into it.
func (self *Subscriptions) retiredRendezvous(rendezvousId []byte) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.dropRendezvousBox(string(rendezvousId))
}

// RendezvousSubscriptions is how many (connection, box) subscriptions are held: a count, never
// which.
func (self *Subscriptions) RendezvousSubscriptions() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.rendezvousCount
}

// The rendezvous half of [Subscriptions.deliver]: every push owed, one at a time, off the lock.
func (self *Subscriptions) deliverRendezvous() {
	for {
		self.mutex.Lock()
		pusher := self.pusher
		var key rendezvousKey
		var owed *rendezvousSubscription
		for candidate := range self.rendezvousReady {
			delete(self.rendezvousReady, candidate)
			if record := self.rendezvousBoxes[candidate.box]; record != nil {
				if current := record.subscribers[candidate.connection]; current != nil {
					key, owed = candidate, current
					break
				}
			}
		}
		if owed == nil {
			self.mutex.Unlock()
			return
		}
		clientId, serverNonce, rendezvousId, pending := owed.clientId, owed.serverNonce, owed.rendezvousId, owed.pending
		self.mutex.Unlock()

		delivered := false
		if pusher != nil {
			delivered = pusher.Push(clientId, serverNonce, &protocol.MessageServerPush{
				Body: &protocol.MessageServerPush_Rendezvous{Rendezvous: &protocol.RendezvousPush{
					RendezvousId: rendezvousId,
					PendingCount: pending,
				}},
			})
		}

		self.mutex.Lock()
		if record := self.rendezvousBoxes[key.box]; record != nil && record.subscribers[key.connection] == owed {
			if delivered {
				self.pushed += 1
			} else {
				self.removeRendezvous(key.box, key.connection)
				self.dropped += 1
			}
		}
		self.mutex.Unlock()
	}
}
