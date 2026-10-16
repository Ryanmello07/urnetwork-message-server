package api

import (
	"bytes"
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
// deposit can reach, is dropped by the next rendezvous subscription or deposit this registry is
// told of, so the registry holds no more than the boxes that were live at that call.

// One connection's subscription to one box.
type rendezvousKey struct {
	connection string
	box        string
}

type rendezvousSubscription struct {
	clientId     []byte
	serverNonce  []byte
	rendezvousId []byte
	// the box's expiry, fixed at its registration, after which nothing can be deposited into it
	expireTime time.Time
	// the count the next push carries
	pending uint32
}

// subscribeRendezvous registers one connection for pushes on one box, until the box's expiry. A
// second Collect with subscribe set on the same connection is the same subscription.
func (self *Subscriptions) subscribeRendezvous(clientId []byte, serverNonce []byte, rendezvousId []byte, expireTime time.Time, now time.Time) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.pruneRendezvous(now)
	key := rendezvousKey{connection: connectionKeyOf(clientId, serverNonce), box: string(rendezvousId)}
	if _, present := self.rendezvous[key]; present {
		return
	}
	self.rendezvous[key] = &rendezvousSubscription{
		clientId:     bytes.Clone(clientId),
		serverNonce:  bytes.Clone(serverNonce),
		rendezvousId: bytes.Clone(rendezvousId),
		expireTime:   expireTime,
	}
}

// pruneRendezvous drops every subscription whose box is past its expiry at `now`. The caller holds
// the mutex.
func (self *Subscriptions) pruneRendezvous(now time.Time) {
	for key, subscription := range self.rendezvous {
		if !now.Before(subscription.expireTime) {
			delete(self.rendezvous, key)
			delete(self.rendezvousReady, key)
		}
	}
}

// depositedRendezvous marks every subscription to the box as owed a push of the box's new count.
func (self *Subscriptions) depositedRendezvous(rendezvousId []byte, pending uint32, now time.Time) {
	self.mutex.Lock()
	self.pruneRendezvous(now)
	marked := false
	for key, subscription := range self.rendezvous {
		if key.box == string(rendezvousId) {
			subscription.pending = pending
			self.rendezvousReady[key] = true
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
	for key := range self.rendezvous {
		if key.box == string(rendezvousId) {
			delete(self.rendezvous, key)
			delete(self.rendezvousReady, key)
		}
	}
}

// RendezvousSubscriptions is how many (connection, box) subscriptions are held: a count, never
// which.
func (self *Subscriptions) RendezvousSubscriptions() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return len(self.rendezvous)
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
			if current := self.rendezvous[candidate]; current != nil {
				key, owed = candidate, current
				break
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
		if current := self.rendezvous[key]; current == owed {
			if delivered {
				self.pushed += 1
			} else {
				delete(self.rendezvous, key)
				self.dropped += 1
			}
		}
		self.mutex.Unlock()
	}
}
