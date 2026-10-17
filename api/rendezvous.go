package api

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/protocol"
)

// §4.3.11's KIND 4, THE LINK BOX, ON THE FIVE RENDEZVOUS ARMS (20 TO 24): Register, Open, Deposit,
// Collect and Retire, over [store.LinkBoxes]. The identity plan's Task 19.
//
// EACH ARM, IN §5.1.2's ORDER: checks 1, 2 and 4 in front; check 3, kind 4's static shape, every
// length an equality, and at Register no key the library would refuse; check 6, the Q17 read, with §4.3.11's one answer for every box no arm may use;
// check 7, the arm's signature, verified through the record layer's published surface (Spec A
// §12.1's A-1 rendezvous section, the library's Task 7b) and through nothing of this package's own;
// and only then the write. No transaction opens and no row is allocated before check 7 has passed.
// Register's signature is self-certified, under the collect key the request itself carries, so it
// is verified before the Q17 read, and Register's one rule comes ahead of the cap on live boxes,
// which fails closed. A deposit is pushed to a collector that subscribed.
//
// ONE PREDICATE DECIDES WHETHER THE ARMS ARE SERVED (R70's addendum): a link box store and a reject
// floor above zero. A server missing either answers every rendezvous arm as an unserved arm is
// answered, as Spec B §4.3.11 says a zero-floor server does, leaves kind 4 out of Capabilities 26
// and 29, and names what is missing among what its readiness lists as not built.

// §10.2's `link_box_ttl_seconds` and `link_box_live_cap` defaults (Spec B revision 25). A zero in
// [Config] takes these, as the other bounds there take theirs.
const (
	DefaultLinkBoxTtl     = 600 * time.Second
	DefaultLinkBoxLiveCap = 10000
)

// The two things the arms are served on, each named where an operator reads the rest.
var (
	rendezvousWithoutLinkBoxes = NotBuilt{
		Section: "§4.3.11",
		What:    "no link box store is configured, so none of the five rendezvous arms is routed, a rendezvous request is answered as an unserved arm, and kind 4 is left out of Capabilities 26 and 29",
		Owner:   "cmd/message-server",
	}
	rendezvousWithoutFloor = NotBuilt{
		Section: "§4.3.11, §4.5",
		What:    "reject_floor_ms is zero, and a server whose reject floor is zero serves no kind-4 arm: none is routed, a rendezvous request is answered as an unserved arm, and kind 4 is left out of Capabilities 26 and 29",
		Owner:   "the operator's configuration",
	}
)

// What the served arms run without, said only when they are served.
var (
	rendezvousFilterNotBuilt = NotBuilt{
		Section: "§5.1.2 check 5",
		What:    "the known-rendezvous cuckoo filter is not built, so a request naming a guessed rendezvous id costs a Q17 read rather than none",
		Owner:   "peer, over the Redis of §2.4",
	}
	rendezvousCacheNotBuilt = NotBuilt{
		Section: "§5.1.2 check 6",
		What:    "Q17's in-process LRU, with its 5-second negative cache, is not built, so every rendezvous request reads message_rendezvous",
		Owner:   "api",
	}
	rendezvousPushUnserved = NotBuilt{
		Section: "§4.3.11",
		What:    "no subscription registry is configured, so a Collect with subscribe set registers nothing and no deposit is pushed",
		Owner:   "cmd/message-server",
	}
)

// Whether the five arms are served: a link box store, and a reject floor above zero. The peer
// routes the arms on this and on nothing else.
func (self *Handler) RendezvousServed() bool {
	return len(self.unservedRendezvous()) == 0
}

// Why the arms are not served, one entry per missing thing, and none when they are.
func (self *Handler) unservedRendezvous() []NotBuilt {
	missing := []NotBuilt{}
	if self.linkBoxes == nil {
		missing = append(missing, rendezvousWithoutLinkBoxes)
	}
	if self.rejectFloor == 0 {
		missing = append(missing, rendezvousWithoutFloor)
	}
	return missing
}

// The rendezvous lines of [Handler.NotBuilt].
func (self *Handler) rendezvousNotBuilt() []NotBuilt {
	if missing := self.unservedRendezvous(); len(missing) != 0 {
		return missing
	}
	notBuilt := []NotBuilt{rendezvousFilterNotBuilt, rendezvousCacheNotBuilt}
	if self.subscriptions == nil {
		notBuilt = append(notBuilt, rendezvousPushUnserved)
	}
	return notBuilt
}

// §4.3.1's `rendezvous_kinds` (Capabilities 29): a bit per kind served, which in I1 is kind 4 alone,
// 16, and nothing at all while the arms are not served.
func (self *Handler) RendezvousKinds() uint32 {
	if !self.RendezvousServed() {
		return 0
	}
	return 1 << store.LinkBoxKind
}

// §4.3.1's `rendezvous_deposit_sizes` (Capabilities 26): every deposit size a served kind takes,
// which in I1 is kind 4's alone, and none while the arms are not served.
func (self *Handler) RendezvousDepositSizes() []uint32 {
	if !self.RendezvousServed() {
		return nil
	}
	return []uint32{store.LinkDepositBytes}
}

// §5.1.2 check 6: Q17, and §4.3.11's one answer on the four arms after Register for every box the
// caller may not use. An unknown id, a retired box and a box past its expiry are each
// REASON_CARD_RETIRED, decided by `expire_time` whether or not the sweep has run. The fourth case,
// a signature that does not verify, is check 7's, and each arm answers it the same.
func (self *Handler) liveLinkBox(ctx context.Context, rendezvousId []byte, now time.Time) (*store.LinkBox, protocol.Reason, error) {
	box, err := self.linkBoxes.LinkBox(ctx, rendezvousId)
	if errors.Is(err, store.ErrLinkBoxUnknown) {
		return nil, protocol.Reason_REASON_CARD_RETIRED, nil
	}
	if err != nil {
		return nil, protocol.Reason_REASON_INTERNAL, err
	}
	if !box.Live(now) {
		return nil, protocol.Reason_REASON_CARD_RETIRED, nil
	}
	return box, protocol.Reason_REASON_OK, nil
}

// §5.1.2 check 3 for kind 4's registration (§4.3.11): the kind is 4, the card's X-Wing key is
// absent, the alg_id is 0x0014, every length is an equality, and neither key is one a box may not
// be pinned under. Any other kind, the card's kind 0 among them, is refused here, since no build of
// I1 serves one.
//
// The alg_id is compared as the u32 the request carries. The preimage takes a u16, and a value
// above 0xFFFF is refused here rather than truncated on its way there, where 0x10014 would verify
// as 0x0014 (the library's RendezvousRegistration).
//
// The keys are held to the library's own rule, RendezvousKeyIsAcceptable, which refuses the seven
// small-order encodings (LRI R72, R73). Every verifier applies it before any signature, so a box
// pinned under such a key could never be opened, deposited into, collected or retired by its
// holders; refused here, no such box is stored. It is the library's rule and not one computed here:
// api's gate against a second implementation bars the cryptography it is made of.
func linkBoxRegistrationShaped(request *protocol.RendezvousRegisterRequest) bool {
	return request.GetKind() == store.LinkBoxKind &&
		len(request.GetCardXwingPub()) == 0 &&
		request.GetAlgId() == store.LinkBoxAlgId &&
		len(request.GetRendezvousId()) == store.RendezvousIdBytes &&
		len(request.GetDepositVerifyPub()) == store.VerifyPubBytes &&
		len(request.GetCollectVerifyPub()) == store.VerifyPubBytes &&
		len(request.GetPublicCt()) == store.LinkCardBytes &&
		message.RendezvousKeyIsAcceptable(request.GetDepositVerifyPub()) &&
		message.RendezvousKeyIsAcceptable(request.GetCollectVerifyPub())
}

// Register: check 3; check 7, self-certified; Register's one rule ahead of the cap on live boxes;
// then the insert.
func (self *Handler) RendezvousRegister(ctx context.Context, conn *Connection, request *protocol.RendezvousRegisterRequest) (protocol.Reason, *protocol.RendezvousRegisterResponse, error) {
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
	if !self.RendezvousServed() {
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}
	if !linkBoxRegistrationShaped(request) {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}

	// §5.1.2 check 7: register_auth, under the collect_verify_pub in the request itself. The alg_id
	// was held to 0x0014 as a u32 above, so this conversion truncates nothing
	registration := &message.RendezvousRegistration{
		RendezvousId:     request.GetRendezvousId(),
		DepositVerifyPub: request.GetDepositVerifyPub(),
		CollectVerifyPub: request.GetCollectVerifyPub(),
		CardXwingPub:     request.GetCardXwingPub(),
		AlgId:            uint16(request.GetAlgId()),
		Kind:             request.GetKind(),
		PublicCt:         request.GetPublicCt(),
	}
	if !message.VerifyRendezvousRegister(registration, conn.ServerNonce, request.GetRegisterAuth()) {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}

	now := self.now()
	// Register's one rule comes before the cap (§4.3.11): a row standing at the id answers by
	// itself, and only an id with no row is held to the cap
	_, err = self.linkBoxes.LinkBox(ctx, request.GetRendezvousId())
	switch {
	case err == nil:
	case errors.Is(err, store.ErrLinkBoxUnknown):
		// the cap fails closed: a count that cannot be read is a full cap (§3.3, Q20)
		live, err := self.linkBoxes.LiveLinkBoxes(ctx, now)
		if err != nil || self.linkBoxLiveCap <= live {
			self.pad(started)
			return protocol.Reason_REASON_CARD_RATE_LIMITED, nil, nil
		}
	default:
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	registered, err := self.linkBoxes.RegisterLinkBox(ctx, &store.LinkBoxRegistration{
		RendezvousId:     request.GetRendezvousId(),
		DepositVerifyPub: request.GetDepositVerifyPub(),
		CollectVerifyPub: request.GetCollectVerifyPub(),
		PublicCt:         request.GetPublicCt(),
	}, now, self.linkBoxTtl)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if registered.Reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return registered.Reason, nil, nil
	}
	return protocol.Reason_REASON_OK, &protocol.RendezvousRegisterResponse{
		ExpireTimeMs: uint64(registered.ExpireTime.UnixMilli()),
		MailboxDepth: registered.MailboxDepth,
	}, nil
}

// Open: check 3, check 6, check 7, and the box's sealed card.
func (self *Handler) RendezvousOpen(ctx context.Context, conn *Connection, request *protocol.RendezvousOpenRequest) (protocol.Reason, *protocol.RendezvousOpenResponse, error) {
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
	if !self.RendezvousServed() {
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}
	if len(request.GetRendezvousId()) != store.RendezvousIdBytes {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	box, reason, err := self.liveLinkBox(ctx, request.GetRendezvousId(), self.now())
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}
	// §5.1.2 check 7: open_auth, under the box's pinned deposit_verify_pub. Without it Open would be
	// an existence oracle over guessed ids (Spec B §4.3.11), so a signature that does not verify is
	// answered as an unknown box is
	if !message.VerifyRendezvousOpen(box.DepositVerifyPub, conn.ServerNonce, request.GetRendezvousId(), request.GetOpenAuth()) {
		self.pad(started)
		return protocol.Reason_REASON_CARD_RETIRED, nil, nil
	}
	return protocol.Reason_REASON_OK, &protocol.RendezvousOpenResponse{
		AlgId:        store.LinkBoxAlgId,
		DepositBytes: store.LinkDepositBytes,
		PublicCt:     box.PublicCt,
		DepositSizes: []uint32{store.LinkDepositBytes},
	}, nil
}

// Deposit: check 3, the length an equality; check 6; check 7; the write; and the push.
func (self *Handler) RendezvousDeposit(ctx context.Context, conn *Connection, request *protocol.RendezvousDepositRequest) (protocol.Reason, *protocol.RendezvousDepositResponse, error) {
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
	if !self.RendezvousServed() {
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}
	// the length is an EQUALITY, for §5.1 check 3's reason: a range would admit an unpadded
	// deposit, and its length would then say something about what is inside it
	if len(request.GetRendezvousId()) != store.RendezvousIdBytes || len(request.GetDepositCt()) != store.LinkDepositBytes {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	now := self.now()
	box, reason, err := self.liveLinkBox(ctx, request.GetRendezvousId(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}
	// §5.1.2 check 7: deposit_auth, under the box's pinned deposit_verify_pub, over the rendezvous id
	// and H(deposit_ct)
	if !message.VerifyRendezvousDeposit(box.DepositVerifyPub, conn.ServerNonce, request.GetRendezvousId(), request.GetDepositCt(), request.GetDepositAuth()) {
		self.pad(started)
		return protocol.Reason_REASON_CARD_RETIRED, nil, nil
	}

	deposited, err := self.linkBoxes.DepositLinkBox(ctx, request.GetRendezvousId(), request.GetDepositCt(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if deposited.Reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return deposited.Reason, nil, nil
	}
	if self.subscriptions != nil {
		self.subscriptions.depositedRendezvous(request.GetRendezvousId(), deposited.PendingCount, now)
	}
	return protocol.Reason_REASON_OK, &protocol.RendezvousDepositResponse{
		DepositId:   deposited.DepositId,
		DepositHash: deposited.DepositHash,
	}, nil
}

// Collect: check 3, check 6, check 7, the delete through the acknowledgement, and the subscription.
func (self *Handler) RendezvousCollect(ctx context.Context, conn *Connection, request *protocol.RendezvousCollectRequest) (protocol.Reason, *protocol.RendezvousCollectResponse, error) {
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
	if !self.RendezvousServed() {
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}
	if len(request.GetRendezvousId()) != store.RendezvousIdBytes {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	now := self.now()
	box, reason, err := self.liveLinkBox(ctx, request.GetRendezvousId(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}
	// §5.1.2 check 7: collect_auth, under the box's pinned collect_verify_pub, over the rendezvous
	// id, both cursors, the limit and subscribe
	if !message.VerifyRendezvousCollect(box.CollectVerifyPub, conn.ServerNonce, &message.RendezvousCollectParams{
		RendezvousId:        request.GetRendezvousId(),
		SinceDepositId:      request.GetSinceDepositId(),
		AckThroughDepositId: request.GetAckThroughDepositId(),
		Limit:               request.GetLimit(),
		Subscribe:           request.GetSubscribe(),
	}, request.GetCollectAuth()) {
		self.pad(started)
		return protocol.Reason_REASON_CARD_RETIRED, nil, nil
	}

	collected, err := self.linkBoxes.CollectLinkBox(ctx, &store.LinkBoxCollectRequest{
		RendezvousId:        request.GetRendezvousId(),
		SinceDepositId:      request.GetSinceDepositId(),
		AckThroughDepositId: request.GetAckThroughDepositId(),
		Limit:               request.GetLimit(),
	}, now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if collected.Reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return collected.Reason, nil, nil
	}
	if request.GetSubscribe() && self.subscriptions != nil {
		self.subscriptions.subscribeRendezvous(conn.ClientId, conn.ServerNonce, request.GetRendezvousId(), collected.ExpireTime, now)
	}
	response := &protocol.RendezvousCollectResponse{
		PendingCount: collected.PendingCount,
		RefusedCount: collected.RefusedCount,
		ExpireTimeMs: uint64(collected.ExpireTime.UnixMilli()),
		Complete:     collected.Complete,
	}
	for _, deposit := range collected.Deposits {
		response.Deposits = append(response.Deposits, &protocol.RendezvousDeposit{
			DepositId:    deposit.DepositId,
			DepositCt:    deposit.DepositCt,
			CreateTimeMs: uint64(deposit.CreateTime.UnixMilli()),
		})
	}
	return protocol.Reason_REASON_OK, response, nil
}

// Retire: check 3, check 6, check 7, every deposit deleted, and the tombstone.
func (self *Handler) RendezvousRetire(ctx context.Context, conn *Connection, request *protocol.RendezvousRetireRequest) (protocol.Reason, *protocol.RendezvousRetireResponse, error) {
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
	if !self.RendezvousServed() {
		return protocol.Reason_REASON_INTERNAL, nil, nil
	}
	if len(request.GetRendezvousId()) != store.RendezvousIdBytes {
		self.pad(started)
		return protocol.Reason_REASON_REJECTED, nil, nil
	}
	now := self.now()
	box, reason, err := self.liveLinkBox(ctx, request.GetRendezvousId(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}
	// §5.1.2 check 7: retire_auth, under the box's pinned collect_verify_pub
	if !message.VerifyRendezvousRetire(box.CollectVerifyPub, conn.ServerNonce, request.GetRendezvousId(), request.GetRetireAuth()) {
		self.pad(started)
		return protocol.Reason_REASON_CARD_RETIRED, nil, nil
	}

	retired, err := self.linkBoxes.RetireLinkBox(ctx, request.GetRendezvousId(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if retired.Reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return retired.Reason, nil, nil
	}
	if self.subscriptions != nil {
		self.subscriptions.retiredRendezvous(request.GetRendezvousId())
	}
	return protocol.Reason_REASON_OK, &protocol.RendezvousRetireResponse{DiscardedDeposits: retired.DiscardedDeposits}, nil
}
