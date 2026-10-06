package api

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/protocol"
)

// §4.3.5 SUBSCRIBE AND §4.4's PUSH, AS THIS BUILD SERVES THEM: A NOTIFICATION, NOT A RECORD STREAM.
//
// WHAT A PUSH CARRIES. A `RecordPush` here names the group and the new `high_water_record_id` and
// carries NO records. The client answers it with the Fetch it would have sent on its next poll,
// so fetch stays the one path a record is ever ingested by, with its ordering, its contiguity and
// its omission checks unchanged. §4.4's register-then-backfill race does not arise for a
// notification: the ack's `snapshot_record_id` tells the client whether to fetch at once, and
// every record committed after registration produces a push. Streaming the records themselves,
// and §4.4's buffered backfill, are the next step and are declared in [Handler.NotBuilt].
//
// WHAT AUTHORIZES IT. Exactly what authorizes a Fetch: §5.1 checks 1, 2, 4 and 5, the read-key
// lookup on (group_id, read_epoch), and §4.3.8's req_auth under that key, op 14. A subscription
// serves the ceiling it was authorized at and no higher, exactly as §5.1.1's epoch ceiling does
// for a fetch: a record sealed above the subscriber's `read_epoch` produces no push, so a client
// re-subscribes after it installs a new epoch.
//
// ONE GROUP PER REQUEST, and that is a spec gap rather than a choice. `SubscribeRequest` carries
// `repeated Subscription` beside ONE `read_epoch` and ONE `req_auth`, and §4.3.8 selects the key
// by (group_id, read_epoch), so a single MAC can authorize a single group. Two or more are
// refused with REASON_REJECTED. Ledger 269.
//
// PER CONNECTION, never per client. A subscription is keyed on the client id AND the server nonce
// of the connection that made it, so a re-Hello opens a connection with none, and the [Pusher]
// refuses any push whose nonce is no longer that connection's. A refused push drops the
// subscription; it is never retried, because the client's next fetch is the retry.

// Pusher delivers one push to one connection. False means that connection is gone or has been
// replaced, and the subscription that asked for the push is dropped.
type Pusher interface {
	Push(clientId []byte, serverNonce []byte, push *protocol.MessageServerPush) bool
}

// The subscriptions one connection may hold. A thirty-third is refused rather than evicting
// one, because an eviction would be a silent stop.
const DefaultMaxSubscriptionsPerConnection = 32

var ErrSubscriptionsFull = errors.New("api: this connection holds as many subscriptions as it may")

type subscriptionKey struct {
	connection string
	group      string
}

type subscription struct {
	clientId    []byte
	serverNonce []byte
	groupId     []byte
	readEpoch   uint64
	// the high water this subscription is owed, and the one last pushed to it
	owed     uint64
	notified uint64
}

// Subscriptions is §4.3.5's state, held in this process: a single replica's registry, because
// §2.4's Redis is not built and a second replica would share nothing.
type Subscriptions struct {
	maxPerConnection int

	mutex        sync.Mutex
	pusher       Pusher
	byKey        map[subscriptionKey]*subscription
	byConnection map[string]map[string]bool
	ready        map[subscriptionKey]bool
	signal       chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
	pushed       uint64
	dropped      uint64
}

func NewSubscriptions() *Subscriptions {
	self := &Subscriptions{
		maxPerConnection: DefaultMaxSubscriptionsPerConnection,
		byKey:            map[subscriptionKey]*subscription{},
		byConnection:     map[string]map[string]bool{},
		ready:            map[subscriptionKey]bool{},
		signal:           make(chan struct{}, 1),
		closed:           make(chan struct{}),
	}
	go self.deliver()
	return self
}

// SetPusher is called once the peer that can reach connections exists, which is after the
// handler that registers subscriptions has been built.
func (self *Subscriptions) SetPusher(pusher Pusher) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.pusher = pusher
}

func connectionKeyOf(clientId []byte, serverNonce []byte) string {
	return string(clientId) + "\x00" + string(serverNonce)
}

// subscribe registers one connection's subscription to one group, at one epoch ceiling.
func (self *Subscriptions) subscribe(clientId []byte, serverNonce []byte, groupId []byte,
	readEpoch uint64, snapshot uint64, replace bool) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	connection := connectionKeyOf(clientId, serverNonce)
	if replace {
		for group := range self.byConnection[connection] {
			delete(self.byKey, subscriptionKey{connection: connection, group: group})
		}
		delete(self.byConnection, connection)
	}
	key := subscriptionKey{connection: connection, group: string(groupId)}
	groups := self.byConnection[connection]
	if _, exists := self.byKey[key]; !exists && self.maxPerConnection <= len(groups) {
		return ErrSubscriptionsFull
	}
	if groups == nil {
		groups = map[string]bool{}
		self.byConnection[connection] = groups
	}
	groups[string(groupId)] = true
	self.byKey[key] = &subscription{
		clientId:    append([]byte(nil), clientId...),
		serverNonce: append([]byte(nil), serverNonce...),
		groupId:     append([]byte(nil), groupId...),
		readEpoch:   readEpoch,
		owed:        snapshot,
		notified:    snapshot,
	}
	return nil
}

// unsubscribe cancels this connection's subscriptions to the named groups, or all of them.
// Unknown ids are ignored: refusing them would make this an existence oracle.
func (self *Subscriptions) unsubscribe(clientId []byte, serverNonce []byte, groupIds [][]byte, all bool) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	connection := connectionKeyOf(clientId, serverNonce)
	groups := self.byConnection[connection]
	if all {
		for group := range groups {
			delete(self.byKey, subscriptionKey{connection: connection, group: group})
		}
		delete(self.byConnection, connection)
		return
	}
	for _, groupId := range groupIds {
		delete(self.byKey, subscriptionKey{connection: connection, group: string(groupId)})
		delete(groups, string(groupId))
	}
	if len(groups) == 0 {
		delete(self.byConnection, connection)
	}
}

type publishedRecord struct {
	recordId uint64
	epoch    uint64
}

// published is told every record a Submit stored. It never blocks on a connection: it marks what
// each subscriber is owed and wakes the one delivery goroutine, which coalesces.
func (self *Subscriptions) published(groupId []byte, records []publishedRecord) {
	if len(records) == 0 {
		return
	}
	self.mutex.Lock()
	woke := false
	for key, sub := range self.byKey {
		if key.group != string(groupId) {
			continue
		}
		for _, record := range records {
			if record.epoch <= sub.readEpoch && sub.owed < record.recordId {
				sub.owed = record.recordId
			}
		}
		if sub.notified < sub.owed {
			self.ready[key] = true
			woke = true
		}
	}
	self.mutex.Unlock()
	if woke {
		select {
		case self.signal <- struct{}{}:
		default:
		}
	}
}

func (self *Subscriptions) deliver() {
	for {
		select {
		case <-self.closed:
			return
		case <-self.signal:
		}
		for {
			self.mutex.Lock()
			pusher := self.pusher
			var key subscriptionKey
			var sub *subscription
			for candidate := range self.ready {
				delete(self.ready, candidate)
				// a subscription cancelled since it was marked is skipped, not the whole set
				if current := self.byKey[candidate]; current != nil {
					key, sub = candidate, current
					break
				}
			}
			if sub == nil {
				self.mutex.Unlock()
				break
			}
			owed := sub.owed
			clientId, serverNonce, groupId := sub.clientId, sub.serverNonce, sub.groupId
			self.mutex.Unlock()

			delivered := false
			if pusher != nil {
				delivered = pusher.Push(clientId, serverNonce, &protocol.MessageServerPush{
					Body: &protocol.MessageServerPush_Records{Records: &protocol.RecordPush{
						GroupId:           groupId,
						HighWaterRecordId: owed,
					}},
				})
			}

			self.mutex.Lock()
			if current := self.byKey[key]; current == sub {
				if delivered {
					if sub.notified < owed {
						sub.notified = owed
					}
					self.pushed += 1
					if sub.notified < sub.owed {
						// more arrived while this one was on the wire
						self.ready[key] = true
					}
				} else {
					delete(self.byKey, key)
					if groups := self.byConnection[key.connection]; groups != nil {
						delete(groups, key.group)
						if len(groups) == 0 {
							delete(self.byConnection, key.connection)
						}
					}
					self.dropped += 1
				}
			}
			self.mutex.Unlock()
		}
	}
}

// SubscriptionStats is what an operator can be told: counts, never which connection holds what.
type SubscriptionStats struct {
	Subscriptions uint64
	Connections   uint64
	Pushed        uint64
	Dropped       uint64
}

func (self *Subscriptions) Stats() SubscriptionStats {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return SubscriptionStats{
		Subscriptions: uint64(len(self.byKey)),
		Connections:   uint64(len(self.byConnection)),
		Pushed:        self.pushed,
		Dropped:       self.dropped,
	}
}

func (self *Subscriptions) Close() {
	self.closeOnce.Do(func() { close(self.closed) })
}

// ── the handlers ──────────────────────────────────────────────────────────────────────────────

// Subscribe is §4.3.5 over §5.1.1's read path. Every refusal is the merged REASON_REJECTED with
// the read path's padded latency, exactly as Fetch's are.
func (self *Handler) Subscribe(ctx context.Context, conn *Connection, request *protocol.SubscribeRequest) (protocol.Reason, *protocol.SubscribeResponse, error) {
	started := self.now()
	if conn == nil {
		return protocol.Reason_REASON_INTERNAL, nil, ErrNoConnection
	}
	if request == nil {
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	op, err := opOf(request)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason := self.frontChecks(ctx, conn, op); reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}
	if self.subscriptions == nil {
		// no registry configured: this replica serves no push, and says so in NotBuilt
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}
	reject := func() (protocol.Reason, *protocol.SubscribeResponse, error) {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	// one group, because one MAC: see the file header
	if len(request.GetSubscriptions()) != 1 {
		return reject()
	}
	wanted := request.GetSubscriptions()[0]
	groupId := wanted.GetGroupId()
	if len(groupId) != store.GroupIdBytes || len(request.GetReqAuth()) == 0 {
		return reject()
	}
	known, err := self.knownGroups.Contains(ctx, groupId)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}
	if !known {
		return reject()
	}
	keys, err := self.store.EpochKeys(ctx, groupId, request.GetReadEpoch())
	if err != nil || keys.ReadKey == nil {
		return reject()
	}
	canonical, err := canonicalRequestBytes(request)
	if err != nil {
		return reject()
	}
	if !message.VerifyRequestAuth(keys.ReadKey, conn.ServerNonce, op, canonical, request.GetReqAuth()) {
		return reject()
	}

	// the snapshot: the high water at the subscriber's own ceiling, read the way a fetch reads it
	result, err := self.store.Fetch(ctx, &store.FetchRequest{
		GroupId:       groupId,
		SinceRecordId: wanted.GetSinceRecordId(),
		Limit:         1,
		HeadsOnly:     true,
		ReadEpoch:     request.GetReadEpoch(),
	})
	if err != nil {
		return reject()
	}
	snapshot := result.HighWaterRecordId
	if err := self.subscriptions.subscribe(conn.ClientId, conn.ServerNonce, groupId,
		request.GetReadEpoch(), snapshot, request.GetReplace()); err != nil {
		return reject()
	}
	return protocol.Reason_REASON_OK, &protocol.SubscribeResponse{
		Acks: []*protocol.SubscriptionAck{{
			GroupId:          bytes.Clone(groupId),
			SnapshotRecordId: snapshot,
			Reason:           protocol.Reason_REASON_OK,
		}},
	}, nil
}

// Unsubscribe is §4.3.8's exempt arm: it reads no group state and cancels only the caller's own
// subscriptions on this connection. It answers with the envelope's reason alone; there is no
// response arm 15.
func (self *Handler) Unsubscribe(ctx context.Context, conn *Connection, request *protocol.UnsubscribeRequest) (protocol.Reason, error) {
	if conn == nil {
		return protocol.Reason_REASON_INTERNAL, ErrNoConnection
	}
	if request == nil {
		return protocol.Reason_REASON_REJECTED, nil
	}
	op, err := opOf(request)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, err
	}
	// §4.3.8 exempts this arm from req_auth and from nothing else: checks 1, 2 and 4 still run
	if reason := self.frontChecks(ctx, conn, op); reason != protocol.Reason_REASON_OK {
		return reason, nil
	}
	if self.subscriptions == nil {
		return protocol.Reason_REASON_INTERNAL, nil
	}
	if request.GetAll() && 0 < len(request.GetGroupIds()) {
		return protocol.Reason_REASON_REJECTED, nil
	}
	self.subscriptions.unsubscribe(conn.ClientId, conn.ServerNonce, request.GetGroupIds(), request.GetAll())
	return protocol.Reason_REASON_OK, nil
}

// publishAccepted tells the registry what a Submit stored: every accepted result that names a
// record, with the epoch its record was sealed at.
func (self *Handler) publishAccepted(pass *submitPass) {
	if self.subscriptions == nil || pass.response == nil {
		return
	}
	var stored []publishedRecord
	for index, result := range pass.response.GetResults() {
		if !acceptance(result.GetReason()) || result.GetRecordId() == 0 || len(pass.records) <= index {
			continue
		}
		parsed := pass.records[index].parsed
		if parsed == nil {
			continue
		}
		stored = append(stored, publishedRecord{recordId: result.GetRecordId(), epoch: parsed.Header.Epoch})
	}
	self.subscriptions.published(pass.groupId, stored)
}

// PushTimeout bounds how long a peer may spend handing one push to one connection. Pushes go out
// one at a time, so this is also the longest one dead connection can delay the rest.
const PushTimeout = 5 * time.Second
