package api

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/protocol"
)

// §4.3.11's KIND 4, THE LINK BOX, ON THE FIVE RENDEZVOUS ARMS (20 TO 24): Register, Open, Deposit,
// Collect and Retire, over [store.LinkBoxes]. The identity plan's Task 19.
//
// WHAT IS NOT HERE, AND WHY NO ARM IS SERVED. Every arm's signature is Spec A §5.14's and is
// verified through the record layer's published surface: §12.1's A-1 rendezvous section,
// VerifyRendezvousRegister and the four beside it. The library this build pins has none of them
// (the lead's ruling R70), so §5.1.2's check 7 is not in this file. The arms are therefore not
// served. [Handler.RendezvousServed] is false, the peer routes none of the five, so the peer's
// derived list of unserved arms answers each REASON_INTERNAL, Capabilities 26 and 29 leave kind 4
// out, and [Handler.NotBuilt] names what is missing. The commit that pins the library's verifiers
// adds check 7 to every arm, ahead of every write, at the five places marked below.
//
// WHAT IS HERE, and runs today only in this package's own tests: §5.1.2's checks 1, 2 and 4 in
// front of every arm; check 3, kind 4's static shape, every length an equality; check 6, the Q17
// read, with §4.3.11's one answer for every box no arm may use; Register's one rule ahead of the
// cap on live boxes, which fails closed; the writes; and the push on each deposit to a collector
// that subscribed.
//
// ONE PREDICATE DECIDES WHETHER THE ARMS ARE SERVED (R70's addendum): a link box store, the
// library's verifiers, and a reject floor above zero. A server missing any one of the three
// answers every rendezvous arm as an unserved arm is answered, exactly as Spec B §4.3.11 says a
// zero-floor server does, and as a handler with no subscription registry answers Subscribe. That
// is the one answer for every reason a box cannot be served, and the readiness list says which.

// §10.2's `link_box_ttl_seconds` and `link_box_live_cap` defaults (Spec B revision 25). A zero in
// [Config] takes these, as the other bounds there take theirs.
const (
	DefaultLinkBoxTtl     = 600 * time.Second
	DefaultLinkBoxLiveCap = 10000
)

// Whether the library this build pins publishes Spec A §5.14's five verifiers. It does not (LRI
// R70), and this is false until the commit that pins a library that does; that commit deletes it,
// with the field it initialises, and adds check 7. A test in this package sets the field to run the
// arms' other checks. Nothing else may.
const rendezvousVerifiersPinned = false

// The three things the arms are served on, each named where an operator reads the rest.
var (
	rendezvousWithoutLinkBoxes = NotBuilt{
		Section: "§4.3.11",
		What:    "no link box store is configured, so none of the five rendezvous arms is routed, a rendezvous request is answered as an unserved arm, and kind 4 is left out of Capabilities 26 and 29",
		Owner:   "cmd/message-server",
	}
	rendezvousWithoutVerifiers = NotBuilt{
		Section: "§4.3.11, §5.1.2 check 7, Spec A §5.14",
		What:    "the library this build pins publishes none of the five rendezvous verifiers of Spec A §12.1's A-1 surface, so no kind-4 arm can verify its signature: none is routed, a rendezvous request is answered as an unserved arm, and kind 4 is left out of Capabilities 26 and 29 (LRI R70)",
		Owner:   "the library's Task 7b, then api",
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

// Whether the five arms are served: a link box store, the library's verifiers, and a reject floor
// above zero. The peer routes the arms on this and on nothing else.
func (self *Handler) RendezvousServed() bool {
	return len(self.unservedRendezvous()) == 0
}

// Why the arms are not served, one entry per missing thing, and none when they are.
func (self *Handler) unservedRendezvous() []NotBuilt {
	missing := []NotBuilt{}
	if self.linkBoxes == nil {
		missing = append(missing, rendezvousWithoutLinkBoxes)
	}
	if !self.verifiersPinned {
		missing = append(missing, rendezvousWithoutVerifiers)
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
// a signature that does not verify, is check 7's, and answers the same.
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
// absent, the alg_id is 0x0014, and every length is an equality. Any other kind, the card's kind 0
// among them, is refused here, since no build of I1 serves one.
func linkBoxRegistrationShaped(request *protocol.RendezvousRegisterRequest) bool {
	return request.GetKind() == store.LinkBoxKind &&
		len(request.GetCardXwingPub()) == 0 &&
		request.GetAlgId() == store.LinkBoxAlgId &&
		len(request.GetRendezvousId()) == store.RendezvousIdBytes &&
		len(request.GetDepositVerifyPub()) == store.VerifyPubBytes &&
		len(request.GetCollectVerifyPub()) == store.VerifyPubBytes &&
		len(request.GetPublicCt()) == store.LinkCardBytes
}

// Register: check 3, then Register's one rule ahead of the cap on live boxes, then the insert.
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

	// §5.1.2 check 7 lands here: register_auth, verified against the collect_verify_pub in the
	// request, which is self-certification (LRI R70)

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

// Open: check 3, check 6, and the box's sealed card.
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

	// §5.1.2 check 7 lands here: open_auth, under the box's pinned deposit_verify_pub (LRI R70)

	return protocol.Reason_REASON_OK, &protocol.RendezvousOpenResponse{
		AlgId:        store.LinkBoxAlgId,
		DepositBytes: store.LinkDepositBytes,
		PublicCt:     box.PublicCt,
		DepositSizes: []uint32{store.LinkDepositBytes},
	}, nil
}

// Deposit: check 3, the length an equality; check 6; the write; and the push.
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
	_, reason, err := self.liveLinkBox(ctx, request.GetRendezvousId(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}

	// §5.1.2 check 7 lands here: deposit_auth, under the box's pinned deposit_verify_pub, over the
	// rendezvous id and H(deposit_ct) (LRI R70)

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

// Collect: check 3, check 6, the delete through the acknowledgement, and the subscription.
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
	_, reason, err := self.liveLinkBox(ctx, request.GetRendezvousId(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}

	// §5.1.2 check 7 lands here: collect_auth, under the box's pinned collect_verify_pub, over the
	// rendezvous id, both cursors, the limit and subscribe (LRI R70)

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

// Retire: check 3, check 6, every deposit deleted, and the tombstone.
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
	_, reason, err := self.liveLinkBox(ctx, request.GetRendezvousId(), now)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	if reason != protocol.Reason_REASON_OK {
		self.pad(started)
		return reason, nil, nil
	}

	// §5.1.2 check 7 lands here: retire_auth, under the box's pinned collect_verify_pub (LRI R70)

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
