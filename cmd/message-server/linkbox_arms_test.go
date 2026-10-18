package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/protocol"
)

// §4.3.11's five arms, as the slice review of Tasks 18 to 20 asked them to be held (LRI R75): what
// every unauthorized request changes, which is nothing (T1 and T2); where each refusal's envelope
// starts (T4); every field an arm answers (T5); the bound on a connection's subscriptions (S-1); a
// replay that pushes nothing (S-2); and a write that acts only on the box its signature was verified
// against (D3). Signed, as linkbox_test.go's are, and for its reason.

// The box as the store holds it, or a failure.
func (self *linkFixture) stored(t *testing.T, box *linkBox) *store.LinkBox {
	t.Helper()
	stored, err := self.boxes.LinkBox(context.Background(), box.id)
	if err != nil {
		t.Fatalf("LinkBox: %v", err)
	}
	return stored
}

// collect_auth over a Collect with a limit, which [linkFixture.collectOf] leaves at zero.
func (self *linkFixture) collectLimited(box *linkBox, since uint64, ack uint64, limit uint32, subscribe bool) *protocol.RendezvousCollectRequest {
	request := self.collectOf(box, since, ack, subscribe)
	request.Limit = limit
	request.CollectAuth = ed25519.Sign(box.collect, message.RendezvousCollectPreimage(self.conn.ServerNonce, &message.RendezvousCollectParams{
		RendezvousId:        box.id,
		SinceDepositId:      since,
		AckThroughDepositId: ack,
		Limit:               limit,
		Subscribe:           subscribe,
	}))
	return request
}

// A box's deposits, two of them and a third refused, so that what an unauthorized Collect could
// destroy is there to be destroyed: two deposits to delete through its acknowledgement, and a
// refused_count of one to zero.
func (self *linkFixture) fillBox(t *testing.T, box *linkBox, seed byte) [][]byte {
	t.Helper()
	taken := [][]byte{linkOctets(store.LinkDepositBytes, seed), linkOctets(store.LinkDepositBytes, seed+1)}
	for _, depositCt := range taken {
		if reason, _ := self.deposit(t, self.depositOf(box, depositCt)); reason != protocol.Reason_REASON_OK {
			t.Fatalf("a deposit into a live box answered %v", reason)
		}
	}
	if reason, _ := self.deposit(t, self.depositOf(box, linkOctets(store.LinkDepositBytes, seed+2))); reason != protocol.Reason_REASON_CARD_RATE_LIMITED {
		t.Fatalf("a third deposit answered %v, want REASON_CARD_RATE_LIMITED", reason)
	}
	self.pads()
	if stored := self.stored(t, box); stored.DepositCount != 2 || stored.RefusedCount != 1 {
		t.Fatalf("the box holds %d deposits and %d refused, want 2 and 1", stored.DepositCount, stored.RefusedCount)
	}
	return taken
}

// Without its signature, whichever arm it is.
func unsigned[R any](request R) R {
	switch typed := any(request).(type) {
	case *protocol.RendezvousRegisterRequest:
		typed.RegisterAuth = nil
	case *protocol.RendezvousOpenRequest:
		typed.OpenAuth = nil
	case *protocol.RendezvousDepositRequest:
		typed.DepositAuth = nil
	case *protocol.RendezvousCollectRequest:
		typed.CollectAuth = nil
	case *protocol.RendezvousRetireRequest:
		typed.RetireAuth = nil
	}
	return request
}

// EVERY UNAUTHORIZED REQUEST ON EVERY ARM CHANGES NOTHING (LRI R75, T1 and T2; Spec B §13's test 46;
// §5.1.2: "no transaction is opened and no row is allocated before check 7 has passed"). The box is
// live and holds what an unauthorized request could destroy: two deposits, and a third refused, so
// that its refused_count is 1. Against it each arm is sent requests whose signature does not hold:
// under keys the box never pinned, over another connection's nonce, unsigned, and with the box's two
// keys swapped. Collect is sent each of them twice, with subscribe false and true, acknowledging
// everything. Each is given §4.3.11's one answer, REASON_CARD_RETIRED with no body and one pad, and a
// registration at the box's id whose register_auth does not hold is REASON_REJECTED, padded. After
// all of them the box, its deposits, its refusal count, the subscription registry and the pushes are
// as they were; and then the holder's own Collect returns both deposits and the refusal count.
//
// BRANCH-COLLECT, which verified collect_auth only when subscribe was false, is killed by the Collects
// with subscribe set; ALIAS-COLLECT and PARAM-COLLECT, which deleted through the acknowledgement
// before check 7 through an alias of the store and through a helper, are killed by what the holder's
// own Collect finds left.
func TestEveryUnauthorizedRequestOnEveryArmChangesNothing(t *testing.T) {
	ctx := context.Background()
	fixture := newLinkFixture(t, nil)
	box := fixture.mustRegister(t, 0x60)
	taken := fixture.fillBox(t, box, 0x61)
	before := fixture.stored(t, box)
	pushes := len(fixture.pusher.rendezvousPushes(0))

	stranger := newLinkBox(0x60)
	stranger.deposit = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA1))
	stranger.collect = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA2))
	elsewhere := &linkFixture{conn: &api.Connection{ServerNonce: bytes.Repeat([]byte{0x6F}, 16), ClientId: fixture.conn.ClientId}}
	swapped := &linkBox{id: box.id, deposit: box.collect, collect: box.deposit, card: box.card}
	depositCt := linkOctets(store.LinkDepositBytes, 0x78)

	type requests struct {
		register *protocol.RendezvousRegisterRequest
		open     *protocol.RendezvousOpenRequest
		deposit  *protocol.RendezvousDepositRequest
		collect  func(subscribe bool) *protocol.RendezvousCollectRequest
		retire   *protocol.RendezvousRetireRequest
	}
	signedBy := func(signer *linkFixture, keys *linkBox) requests {
		registration := signer.registration(keys)
		// at the live box's own id and with its own card and keys, so that only the signature is wrong
		registration.RendezvousId = box.id
		registration.DepositVerifyPub = publicOf(box.deposit)
		registration.CollectVerifyPub = publicOf(box.collect)
		registration.PublicCt = box.card
		signRegister(registration, keys.collect, signer.conn.ServerNonce)
		return requests{
			register: registration,
			open:     signer.open(keys),
			deposit:  signer.depositOf(keys, depositCt),
			collect: func(subscribe bool) *protocol.RendezvousCollectRequest {
				return signer.collectOf(keys, 0, 9, subscribe)
			},
			retire: signer.retireOf(keys),
		}
	}
	// a stranger's registration signed by its own key is self-certified and is Register's one rule's
	// to refuse; the one here keeps the box's collect key and is signed by another, which check 7 refuses
	kinds := map[string]requests{
		"signed under keys the box never pinned": signedBy(fixture, stranger),
		"signed over another connection's nonce": signedBy(elsewhere, box),
		"with the box's two keys swapped":        signedBy(fixture, swapped),
	}
	bare := signedBy(fixture, box)
	kinds["unsigned"] = requests{
		register: unsigned(bare.register),
		open:     unsigned(bare.open),
		deposit:  unsigned(bare.deposit),
		collect: func(subscribe bool) *protocol.RendezvousCollectRequest {
			return unsigned(fixture.collectOf(box, 0, 9, subscribe))
		},
		retire: unsigned(bare.retire),
	}

	oneRejected := linkAnswer{reason: protocol.Reason_REASON_REJECTED, body: false, pads: []time.Duration{linkFloor}}
	for name, current := range kinds {
		fixture.pads()
		reason, response, err := fixture.handler.RendezvousRegister(ctx, fixture.conn, current.register)
		if err != nil {
			t.Fatalf("RendezvousRegister: %v", err)
		}
		if answer := (linkAnswer{reason, response != nil, fixture.pads()}); !reflect.DeepEqual(answer, oneRejected) {
			t.Fatalf("Register at the live box's id, %s, was answered %v with a body %v after pads %v; want REASON_REJECTED, no body, one pad",
				name, answer.reason, answer.body, answer.pads)
		}
		for _, subscribe := range []bool{false, true} {
			answers := fixture.answers(t, current.open, current.deposit, current.collect(subscribe), current.retire)
			for arm, answer := range answers {
				if !reflect.DeepEqual(answer, oneAnswer) {
					t.Fatalf("%s on a live box, %s, Collect's subscribe %v, was answered %v with a body %v after pads %v; want §4.3.11's one answer",
						arm, name, subscribe, answer.reason, answer.body, answer.pads)
				}
			}
		}
	}

	if after := fixture.stored(t, box); !reflect.DeepEqual(after, before) {
		t.Fatalf("unauthorized requests changed the box from %+v to %+v", before, after)
	}
	if held := fixture.subscriptions.RendezvousSubscriptions(); held != 0 {
		t.Fatalf("unauthorized Collects left %d subscriptions", held)
	}
	if now := len(fixture.pusher.rendezvousPushes(0)); now != pushes {
		t.Fatalf("unauthorized requests sent %d pushes", now-pushes)
	}

	// THE HOLDER'S OWN COLLECT still finds both deposits and the refusal
	reason, collected := fixture.collect(t, fixture.collectOf(box, 0, 0, false))
	if reason != protocol.Reason_REASON_OK || collected.GetRefusedCount() != 1 || collected.GetPendingCount() != 2 || len(collected.GetDeposits()) != 2 {
		t.Fatalf("the holder's Collect after the unauthorized ones answered %v: %d deposits, %d pending, %d refused; want both deposits and the one refusal",
			reason, len(collected.GetDeposits()), collected.GetPendingCount(), collected.GetRefusedCount())
	}
	for index, deposit := range collected.GetDeposits() {
		if deposit.GetDepositId() != uint64(index+1) || !bytes.Equal(deposit.GetDepositCt(), taken[index]) {
			t.Fatalf("the holder's Collect returned deposit %d as %d with other octets", index+1, deposit.GetDepositId())
		}
	}
}

// LinkBoxes whose Q17 takes `by` on the fixture's clock: what a read of a box costs, made a number a
// test can hold an envelope to.
type advancingLinkBoxes struct {
	store.LinkBoxes
	mutex sync.Mutex
	clock *linkClock
	by    time.Duration
}

func (self *advancingLinkBoxes) LinkBox(ctx context.Context, rendezvousId []byte) (*store.LinkBox, error) {
	self.mutex.Lock()
	clock := self.clock
	self.mutex.Unlock()
	if clock != nil {
		clock.advance(self.by)
	}
	return self.LinkBoxes.LinkBox(ctx, rendezvousId)
}

// EVERY REFUSAL ON THE FOUR ARMS ENDS ITS ENVELOPE AT THE FLOOR, TIMED FROM THE ARM'S OWN START (LRI
// R75, T4; Spec B §13's test 46: alike "in code, size and time"). Q17 takes a read's time on the
// clock, so a refusal that read the box pads the floor less that read, and its whole answer takes the
// floor exactly. An unknown id, a retired box, a box past its expiry, and a live box asked under keys
// it never pinned, on each of Open, Deposit, Collect (with subscribe and without) and Retire, each pad
// the floor less one read. STARTED-LATE, an arm that times its envelope from after the read, pads the
// whole floor there, so that a box that exists answers a read later than one that does not, and is
// killed here. The control is check 3's refusal, before any read, which pads the floor itself.
func TestEveryRefusalEndsItsEnvelopeAtTheFloorTimedFromTheArmsStart(t *testing.T) {
	const read = 3 * time.Millisecond
	advancing := &advancingLinkBoxes{by: read}
	fixture := newLinkFixture(t, func(config *api.Config) {
		advancing.LinkBoxes = config.LinkBoxes
		config.LinkBoxes = advancing
	})
	expired := fixture.mustRegister(t, 0x10)
	fixture.clock.advance(api.DefaultLinkBoxTtl)
	retired := fixture.mustRegister(t, 0x20)
	if reason := fixture.retire(t, fixture.retireOf(retired)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Retire: %v", reason)
	}
	live := fixture.mustRegister(t, 0x30)
	stranger := newLinkBox(0x30)
	stranger.deposit = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xB1))
	stranger.collect = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xB2))
	// the clock moves only inside Q17 from here
	advancing.mutex.Lock()
	advancing.clock = fixture.clock
	advancing.mutex.Unlock()

	want := []time.Duration{linkFloor - read}
	for name, box := range map[string]*linkBox{
		"an unknown id":                          newLinkBox(0xE0),
		"a retired box":                          retired,
		"a box past its expiry":                  expired,
		"a live box, under keys it never pinned": stranger,
	} {
		for _, subscribe := range []bool{false, true} {
			answers := fixture.answers(t, fixture.open(box), fixture.depositOf(box, linkOctets(store.LinkDepositBytes, 0x77)),
				fixture.collectOf(box, 0, 9, subscribe), fixture.retireOf(box))
			for arm, answer := range answers {
				if answer.reason != protocol.Reason_REASON_CARD_RETIRED || answer.body || !slices.Equal(answer.pads, want) {
					t.Fatalf("%s on %s, Collect's subscribe %v, was answered %v with a body %v and padded %v; want REASON_CARD_RETIRED, no body, and %v: the arm read for %v, and its envelope, timed from its start, ends at the floor",
						arm, name, subscribe, answer.reason, answer.body, answer.pads, want, read)
				}
			}
		}
	}
	_ = live

	// THE CONTROL: check 3 refuses before any read, and pads the whole floor
	before := fixture.clock.now()
	answers := fixture.answers(t, &protocol.RendezvousOpenRequest{RendezvousId: linkOctets(store.RendezvousIdBytes-1, 0x41)},
		&protocol.RendezvousDepositRequest{RendezvousId: live.id, DepositCt: linkOctets(store.LinkDepositBytes-1, 0x42)},
		&protocol.RendezvousCollectRequest{RendezvousId: linkOctets(store.RendezvousIdBytes+1, 0x43)},
		&protocol.RendezvousRetireRequest{RendezvousId: nil})
	for arm, answer := range answers {
		if answer.reason != protocol.Reason_REASON_REJECTED || !slices.Equal(answer.pads, []time.Duration{linkFloor}) {
			t.Fatalf("the control: %s refused by check 3 answered %v and padded %v, want REASON_REJECTED and the whole floor", arm, answer.reason, answer.pads)
		}
	}
	if !fixture.clock.now().Equal(before) {
		t.Fatal("the control's refusals read a box, so the floor they padded measures nothing")
	}
}

// A ROUND TRIP THROUGH THE ARMS ANSWERS EVERY FIELD (LRI R75, T5; §4.3.11's response messages). The
// fields the store hands back reach the client, each of them: Register's expire_time_ms and
// mailbox_depth; Open's public_ct, alg_id 0x0014, deposit_bytes 17,526 and deposit_sizes [17526],
// with no card X-Wing key; Deposit's deposit_id and deposit_hash; Collect's deposits, with their ids,
// octets and create times, its pending_count, refused_count, expire_time_ms and complete, whole and
// limited; and Retire's discarded_deposits. MAP-COLLECT, MAP-OPEN and MAP-REGISTER-RETIRE, which each
// dropped some of them, are killed here.
func TestARoundTripThroughTheArmsAnswersEveryField(t *testing.T) {
	ctx := context.Background()
	fixture := newLinkFixture(t, nil)
	box := newLinkBox(0x30)
	registeredAt := fixture.clock.now()
	expireMs := uint64(registeredAt.Add(api.DefaultLinkBoxTtl).UnixMilli())

	reason, registered := fixture.register(t, fixture.registration(box))
	if reason != protocol.Reason_REASON_OK || registered.GetExpireTimeMs() != expireMs || registered.GetMailboxDepth() != 0 {
		t.Fatalf("Register answered %v, expiry %d and depth %d; want REASON_OK, %d and 0", reason, registered.GetExpireTimeMs(), registered.GetMailboxDepth(), expireMs)
	}

	reason, opened, err := fixture.handler.RendezvousOpen(ctx, fixture.conn, fixture.open(box))
	if err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("Open answered %v (%v)", reason, err)
	}
	if want := (&protocol.RendezvousOpenResponse{
		PublicCt:     box.card,
		AlgId:        store.LinkBoxAlgId,
		DepositBytes: store.LinkDepositBytes,
		DepositSizes: []uint32{store.LinkDepositBytes},
	}); !bytes.Equal(opened.GetPublicCt(), want.GetPublicCt()) || opened.GetAlgId() != want.GetAlgId() ||
		opened.GetDepositBytes() != want.GetDepositBytes() || !slices.Equal(opened.GetDepositSizes(), want.GetDepositSizes()) ||
		len(opened.GetCardXwingPub()) != 0 {
		t.Fatalf("Open answered alg_id %#x, deposit_bytes %d, deposit_sizes %v, a card of %d octets and an X-Wing key of %d; want 0x0014, 17526, [17526], the box's card and none",
			opened.GetAlgId(), opened.GetDepositBytes(), opened.GetDepositSizes(), len(opened.GetPublicCt()), len(opened.GetCardXwingPub()))
	}

	// two deposits, a second apart, each answered with its id and its hash
	deposits := [][]byte{linkOctets(store.LinkDepositBytes, 0x31), linkOctets(store.LinkDepositBytes, 0x32)}
	createMs := []uint64{}
	for index, depositCt := range deposits {
		createMs = append(createMs, uint64(fixture.clock.now().UnixMilli()))
		reason, deposited := fixture.deposit(t, fixture.depositOf(box, depositCt))
		hash := sha256.Sum256(depositCt)
		if reason != protocol.Reason_REASON_OK || deposited.GetDepositId() != uint64(index+1) || !bytes.Equal(deposited.GetDepositHash(), hash[:]) {
			t.Fatalf("deposit %d answered %v, id %d and hash %x; want REASON_OK, %d and %x", index+1, reason, deposited.GetDepositId(), deposited.GetDepositHash(), index+1, hash)
		}
		fixture.clock.advance(time.Second)
	}

	// the registration's retry answers the depth now waiting, and the same fixed expiry
	if reason, again := fixture.register(t, fixture.registration(box)); reason != protocol.Reason_REASON_OK || again.GetMailboxDepth() != 2 || again.GetExpireTimeMs() != expireMs {
		t.Fatalf("Register's retry answered %v, depth %d and expiry %d; want REASON_OK, 2 and %d", reason, again.GetMailboxDepth(), again.GetExpireTimeMs(), expireMs)
	}

	// Collect: every deposit, whole
	wantDeposits := []*protocol.RendezvousDeposit{
		{DepositId: 1, DepositCt: deposits[0], CreateTimeMs: createMs[0]},
		{DepositId: 2, DepositCt: deposits[1], CreateTimeMs: createMs[1]},
	}
	reason, collected := fixture.collect(t, fixture.collectOf(box, 0, 0, false))
	if reason != protocol.Reason_REASON_OK || !depositsEqual(collected.GetDeposits(), wantDeposits) || collected.GetPendingCount() != 2 ||
		collected.GetRefusedCount() != 0 || collected.GetExpireTimeMs() != expireMs || !collected.GetComplete() {
		t.Fatalf("Collect answered %v: %d deposits, pending %d, refused %d, expiry %d, complete %v; want both deposits, 2, 0, %d and true",
			reason, len(collected.GetDeposits()), collected.GetPendingCount(), collected.GetRefusedCount(), collected.GetExpireTimeMs(), collected.GetComplete(), expireMs)
	}
	// and limited to one: the first, not complete
	reason, limited := fixture.collect(t, fixture.collectLimited(box, 0, 0, 1, false))
	if reason != protocol.Reason_REASON_OK || !depositsEqual(limited.GetDeposits(), wantDeposits[:1]) || limited.GetComplete() || limited.GetPendingCount() != 2 {
		t.Fatalf("Collect limited to one answered %v: %d deposits, complete %v, pending %d; want the first, false and 2",
			reason, len(limited.GetDeposits()), limited.GetComplete(), limited.GetPendingCount())
	}

	// a third deposit is refused, and the next collect reports it; acknowledging the first leaves the second
	if reason, _ := fixture.deposit(t, fixture.depositOf(box, linkOctets(store.LinkDepositBytes, 0x33))); reason != protocol.Reason_REASON_CARD_RATE_LIMITED {
		t.Fatalf("a third deposit answered %v", reason)
	}
	reason, acknowledged := fixture.collect(t, fixture.collectOf(box, 0, 1, false))
	if reason != protocol.Reason_REASON_OK || !depositsEqual(acknowledged.GetDeposits(), wantDeposits[1:]) || acknowledged.GetPendingCount() != 1 ||
		acknowledged.GetRefusedCount() != 1 || !acknowledged.GetComplete() {
		t.Fatalf("Collect acknowledging the first answered %v: %d deposits, pending %d, refused %d, complete %v; want the second, 1, 1 and true",
			reason, len(acknowledged.GetDeposits()), acknowledged.GetPendingCount(), acknowledged.GetRefusedCount(), acknowledged.GetComplete())
	}

	// Retire discards what is left: the second deposit
	reason, retired, err := fixture.handler.RendezvousRetire(ctx, fixture.conn, fixture.retireOf(box))
	if err != nil || reason != protocol.Reason_REASON_OK || retired.GetDiscardedDeposits() != 1 {
		t.Fatalf("Retire answered %v (%v) with %d discarded, want REASON_OK and the 1 left", reason, err, retired.GetDiscardedDeposits())
	}
}

func depositsEqual(got []*protocol.RendezvousDeposit, want []*protocol.RendezvousDeposit) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index].GetDepositId() != want[index].GetDepositId() || !bytes.Equal(got[index].GetDepositCt(), want[index].GetDepositCt()) ||
			got[index].GetCreateTimeMs() != want[index].GetCreateTimeMs() {
			return false
		}
	}
	return true
}

// A COLLECT PAST ITS CONNECTION'S BOUND IS REFUSED, AND CHANGES NOTHING (LRI R75, S-1). A connection
// subscribes, by Collect, to as many boxes as it may; a Collect with subscribe set on one more box
// answers REASON_CARD_RATE_LIMITED, padded, with no body, and changes nothing: its acknowledgement
// deletes no deposit and the box's refused_count is not zeroed, as a refusal made after the write
// would have done, and no subscription is added. The controls: the same Collect without subscribe is
// served, and returns the deposits and the refusal it would have destroyed; and a repeat Collect with
// subscribe on a box the connection holds is served at the bound.
func TestACollectPastItsConnectionsBoundIsRefusedAndChangesNothing(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	held := []*linkBox{}
	for index := range api.DefaultMaxRendezvousSubscriptionsPerConnection {
		box := fixture.mustRegister(t, byte(index))
		if reason, _ := fixture.collect(t, fixture.collectOf(box, 0, 0, true)); reason != protocol.Reason_REASON_OK {
			t.Fatalf("Collect with subscribe on box %d answered %v", index+1, reason)
		}
		held = append(held, box)
	}
	fixture.pads()
	if count := fixture.subscriptions.RendezvousSubscriptions(); count != api.DefaultMaxRendezvousSubscriptionsPerConnection {
		t.Fatalf("the connection holds %d subscriptions, want %d", count, api.DefaultMaxRendezvousSubscriptionsPerConnection)
	}

	past := fixture.mustRegister(t, 0xC0)
	taken := fixture.fillBox(t, past, 0xC1)
	before := fixture.stored(t, past)
	reason, response := fixture.collect(t, fixture.collectOf(past, 0, 9, true))
	if reason != protocol.Reason_REASON_CARD_RATE_LIMITED || response != nil {
		t.Fatalf("a Collect with subscribe past the connection's bound answered %v with a body %v, want REASON_CARD_RATE_LIMITED and none", reason, response != nil)
	}
	if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{linkFloor}) {
		t.Fatalf("the refusal at the bound padded %v, want one pad to the floor", pads)
	}
	if after := fixture.stored(t, past); !reflect.DeepEqual(after, before) {
		t.Fatalf("the refused Collect changed the box from %+v to %+v: its acknowledgement or the refusal count was applied", before, after)
	}
	if count := fixture.subscriptions.RendezvousSubscriptions(); count != api.DefaultMaxRendezvousSubscriptionsPerConnection {
		t.Fatalf("after the refusal the connection holds %d subscriptions, want %d", count, api.DefaultMaxRendezvousSubscriptionsPerConnection)
	}

	// THE CONTROLS
	reason, collected := fixture.collect(t, fixture.collectOf(past, 0, 0, false))
	if reason != protocol.Reason_REASON_OK || len(collected.GetDeposits()) != len(taken) || collected.GetRefusedCount() != 1 {
		t.Fatalf("the same box's Collect without subscribe answered %v with %d deposits and %d refused, want both and 1", reason, len(collected.GetDeposits()), collected.GetRefusedCount())
	}
	if reason, _ := fixture.collect(t, fixture.collectOf(held[0], 0, 0, true)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a repeat Collect with subscribe on a held box answered %v at the bound, want REASON_OK", reason)
	}
}

// A REPLAYED DEPOSIT PUSHES NOTHING (LRI R75, S-2). §4.3.11 pushes on a deposit, and the same octets
// again are the deposit already standing, answered with its id, and not a deposit: a holder of the
// code replaying its own deposit in a loop would otherwise wake the collector for nothing. A collector
// subscribes; a deposit is pushed with its count; three replays of it are each answered with its id
// and push nothing; and the control, a second deposit, is pushed, and is the only push after the
// first.
func TestAReplayedDepositPushesNothing(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	box := fixture.mustRegister(t, 0xB0)
	if reason, _ := fixture.collect(t, fixture.collectOf(box, 0, 0, true)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect with subscribe: %v", reason)
	}
	first := linkOctets(store.LinkDepositBytes, 0xB1)
	if reason, _ := fixture.deposit(t, fixture.depositOf(box, first)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Deposit: %v", reason)
	}
	if pushes := fixture.pusher.rendezvousPushes(1); len(pushes) != 1 || pushes[0].GetPendingCount() != 1 {
		t.Fatalf("the first deposit was pushed as %v, want one push of 1 pending", pushes)
	}
	for index := range 3 {
		reason, replayed := fixture.deposit(t, fixture.depositOf(box, first))
		if reason != protocol.Reason_REASON_OK || replayed.GetDepositId() != 1 {
			t.Fatalf("replay %d answered %v with deposit %d, want REASON_OK and deposit 1", index+1, reason, replayed.GetDepositId())
		}
	}
	// THE CONTROL: a second deposit is pushed, with the count of two
	if reason, _ := fixture.deposit(t, fixture.depositOf(box, linkOctets(store.LinkDepositBytes, 0xB2))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control's Deposit: %v", reason)
	}
	// the control's push is the one with two pending, waited for a second at most
	deadline := time.Now().Add(time.Second)
	pending := []uint32{}
	for !slices.Contains(pending, 2) && time.Now().Before(deadline) {
		pending = pending[:0]
		for _, push := range fixture.pusher.rendezvousPushes(0) {
			pending = append(pending, push.GetPendingCount())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !slices.Contains(pending, 2) {
		t.Fatalf("the control, a second deposit, was not pushed with 2 pending: the pushes carried %v", pending)
	}
	// and nothing came between: a push for a replay would have come before the control's
	if !slices.Equal(pending, []uint32{1, 2}) {
		t.Fatalf("a deposit, three replays of it and a second deposit sent %d pushes, with pending counts %v; want [1 2]: a replay is not a deposit", len(pending), pending)
	}
}

// LinkBoxes that, once armed, replace the box at an id inside Q17: the read answers the box that was
// there, and before the read returns that box passes its expiry, the sweep reclaims it, and another is
// registered at its id under other keys. The arm then verifies the request against the box it read,
// at a time before that box's expiry, and writes.
type swappingLinkBoxes struct {
	*store.MemoryStore
	mutex sync.Mutex
	swap  func()
}

func (self *swappingLinkBoxes) LinkBox(ctx context.Context, rendezvousId []byte) (*store.LinkBox, error) {
	box, err := self.MemoryStore.LinkBox(ctx, rendezvousId)
	self.mutex.Lock()
	swap := self.swap
	self.swap = nil
	self.mutex.Unlock()
	if swap != nil {
		swap()
	}
	return box, err
}

// A WRITE ACTS ONLY ON THE BOX ITS SIGNATURE WAS VERIFIED AGAINST (LRI R75, D3). Between an arm's Q17
// read and its write, the box it read is swept at its expiry and another is registered at its id under
// other keys; the arm verifies the request, which the first box's holder signed, against the box it
// read, at a time before that box's expiry, and hands the write the key it verified under. Deposit,
// Collect and Retire each answer REASON_CARD_RETIRED, and the box at the id, the second, is as it was:
// no deposit taken, none deleted, its refusal count kept, and not retired. The controls are the same
// three requests at a box no swap touches, which act.
func TestAWriteActsOnlyOnTheBoxItsSignatureWasVerifiedAgainst(t *testing.T) {
	ctx := context.Background()
	swapping := &swappingLinkBoxes{}
	fixture := newLinkFixture(t, func(config *api.Config) {
		swapping.MemoryStore = config.LinkBoxes.(*store.MemoryStore)
		config.LinkBoxes = swapping
	})
	firstExpiry := fixture.clock.now().Add(api.DefaultLinkBoxTtl)
	// the arms' clock stays before the first boxes' expiry, at which the second boxes read as live
	fixture.clock.advance(time.Minute)

	for index, arm := range []string{"Deposit", "Collect", "Retire"} {
		first := fixture.mustRegisterAt(t, byte(0x40+0x10*index), firstExpiry.Add(-api.DefaultLinkBoxTtl))
		second := newLinkBox(byte(0x40 + 0x10*index))
		second.deposit = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, byte(0xC1+index)))
		second.collect = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, byte(0xD1+index)))
		second.card = linkOctets(store.LinkCardBytes, byte(0xE1+index))
		var standing *store.LinkBox
		swapping.mutex.Lock()
		swapping.swap = func() {
			swept, err := swapping.MemoryStore.SweepLinkBoxes(ctx, firstExpiry, store.LinkBoxSweepBounds{})
			if err != nil || swept.Boxes == 0 {
				t.Errorf("the sweep at the first box's expiry answered %+v (%v)", swept, err)
				return
			}
			registration := fixture.registration(second)
			registered, err := swapping.MemoryStore.RegisterLinkBox(ctx, &store.LinkBoxRegistration{
				RendezvousId:     registration.GetRendezvousId(),
				DepositVerifyPub: registration.GetDepositVerifyPub(),
				CollectVerifyPub: registration.GetCollectVerifyPub(),
				PublicCt:         registration.GetPublicCt(),
			}, firstExpiry.Add(time.Second), api.DefaultLinkBoxTtl, api.DefaultLinkBoxLiveCap)
			if err != nil || registered.Reason != protocol.Reason_REASON_OK {
				t.Errorf("registering the second box answered %+v (%v)", registered, err)
				return
			}
			deposited, err := swapping.MemoryStore.DepositLinkBox(ctx, second.id, publicOf(second.deposit), linkOctets(store.LinkDepositBytes, 0x5A), firstExpiry.Add(time.Second))
			if err != nil || deposited.Reason != protocol.Reason_REASON_OK {
				t.Errorf("a deposit into the second box answered %+v (%v)", deposited, err)
				return
			}
			standing, _ = swapping.MemoryStore.LinkBox(ctx, second.id)
		}
		swapping.mutex.Unlock()

		var reason protocol.Reason
		switch arm {
		case "Deposit":
			reason, _ = fixture.deposit(t, fixture.depositOf(first, linkOctets(store.LinkDepositBytes, 0x5B)))
		case "Collect":
			reason, _ = fixture.collect(t, fixture.collectOf(first, 0, 9, false))
		case "Retire":
			reason = fixture.retire(t, fixture.retireOf(first))
		}
		if standing == nil {
			t.Fatalf("%s: the swap did not happen inside Q17, so this case measures nothing", arm)
		}
		if reason != protocol.Reason_REASON_CARD_RETIRED {
			t.Fatalf("%s verified against a box swept since its read answered %v, want REASON_CARD_RETIRED: the box at the id now is not the one verified", arm, reason)
		}
		if after := fixture.stored(t, second); !reflect.DeepEqual(after, standing) {
			t.Fatalf("%s verified against a swept box changed the box registered at its id since, from %+v to %+v", arm, standing, after)
		}
	}

	// THE CONTROLS: the same three requests at a box no swap touches
	control := fixture.mustRegister(t, 0x90)
	if reason, _ := fixture.deposit(t, fixture.depositOf(control, linkOctets(store.LinkDepositBytes, 0x91))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control's Deposit answered %v", reason)
	}
	if reason, collected := fixture.collect(t, fixture.collectOf(control, 0, 9, false)); reason != protocol.Reason_REASON_OK || len(collected.GetDeposits()) != 0 {
		t.Fatalf("the control's Collect answered %v", reason)
	}
	if reason := fixture.retire(t, fixture.retireOf(control)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control's Retire answered %v", reason)
	}
	if _, err := fixture.boxes.LinkBox(ctx, control.id); errors.Is(err, store.ErrLinkBoxUnknown) {
		t.Fatal("the control's box is gone, where a retire keeps its tombstone")
	}
}

// The box, registered by its holder at `at` on the fixture's clock, which then returns to where it was.
func (self *linkFixture) mustRegisterAt(t *testing.T, seed byte, at time.Time) *linkBox {
	t.Helper()
	self.clock.mutex.Lock()
	was := self.clock.at
	self.clock.at = at
	self.clock.mutex.Unlock()
	box := self.mustRegister(t, seed)
	self.clock.mutex.Lock()
	self.clock.at = was
	self.clock.mutex.Unlock()
	return box
}
