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
// THE HOLDER STAYS SUBSCRIBED (LRI R78, N4). A second box, whose holder has subscribed by its own
// Collect, takes the same requests. Its subscription outlasts them, and the deposit made after them is
// pushed to its holder: a change to the subscription registry made before check 7 would have ended
// it, and nothing in the box would show that it had.
//
// BRANCH-COLLECT, which verified collect_auth only when subscribe was false, is killed by the Collects
// with subscribe set; ALIAS-COLLECT and PARAM-COLLECT, which deleted through the acknowledgement
// before check 7 through an alias of the store and through a helper, are killed by what the holder's
// own Collect finds left; and FIELD-REGISTRY-2, which ended a box's subscriptions through the
// registry's fields before check 7, keeping its counts, by the holder's push.
func TestEveryUnauthorizedRequestOnEveryArmChangesNothing(t *testing.T) {
	ctx := context.Background()
	fixture := newLinkFixture(t, nil)
	box := fixture.mustRegister(t, 0x60)
	taken := fixture.fillBox(t, box, 0x61)
	before := fixture.stored(t, box)
	watched := fixture.mustRegister(t, 0x68)
	if reason, _ := fixture.collect(t, fixture.collectOf(watched, 0, 0, true)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the holder's Collect with subscribe on the second box answered %v", reason)
	}
	fixture.pads()
	pushes := len(fixture.pusher.rendezvousPushes(0))

	elsewhere := &linkFixture{conn: &api.Connection{ServerNonce: bytes.Repeat([]byte{0x6F}, 16), ClientId: fixture.conn.ClientId}}
	depositCt := linkOctets(store.LinkDepositBytes, 0x78)

	type requests struct {
		register *protocol.RendezvousRegisterRequest
		open     *protocol.RendezvousOpenRequest
		deposit  *protocol.RendezvousDepositRequest
		collect  func(subscribe bool) *protocol.RendezvousCollectRequest
		retire   *protocol.RendezvousRetireRequest
	}
	// the requests at `target` whose signature does not hold, of each kind
	unauthorized := func(target *linkBox) map[string]requests {
		stranger := &linkBox{
			id:      target.id,
			deposit: ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA1)),
			collect: ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA2)),
			card:    target.card,
		}
		swapped := &linkBox{id: target.id, deposit: target.collect, collect: target.deposit, card: target.card}
		signedBy := func(signer *linkFixture, keys *linkBox) requests {
			registration := signer.registration(keys)
			// at the live box's own id and with its own card and keys, so that only the signature is wrong
			registration.RendezvousId = target.id
			registration.DepositVerifyPub = publicOf(target.deposit)
			registration.CollectVerifyPub = publicOf(target.collect)
			registration.PublicCt = target.card
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
		// a stranger's registration signed by its own key is self-certified and is Register's one
		// rule's to refuse; the one here keeps the box's collect key and is signed by another, which
		// check 7 refuses
		kinds := map[string]requests{
			"signed under keys the box never pinned": signedBy(fixture, stranger),
			"signed over another connection's nonce": signedBy(elsewhere, target),
			"with the box's two keys swapped":        signedBy(fixture, swapped),
		}
		bare := signedBy(fixture, target)
		kinds["unsigned"] = requests{
			register: unsigned(bare.register),
			open:     unsigned(bare.open),
			deposit:  unsigned(bare.deposit),
			collect: func(subscribe bool) *protocol.RendezvousCollectRequest {
				return unsigned(fixture.collectOf(target, 0, 9, subscribe))
			},
			retire: unsigned(bare.retire),
		}
		return kinds
	}

	oneRejected := linkAnswer{reason: protocol.Reason_REASON_REJECTED, body: false, pads: []time.Duration{linkFloor}}
	for _, target := range []*linkBox{box, watched} {
		for name, current := range unauthorized(target) {
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
	}

	if after := fixture.stored(t, box); !reflect.DeepEqual(after, before) {
		t.Fatalf("unauthorized requests changed the box from %+v to %+v", before, after)
	}
	if held := fixture.subscriptions.RendezvousSubscriptions(); held != 1 {
		t.Fatalf("after the unauthorized requests the registry holds %d subscriptions, want the holder's one", held)
	}
	if now := len(fixture.pusher.rendezvousPushes(0)); now != pushes {
		t.Fatalf("unauthorized requests sent %d pushes", now-pushes)
	}

	// THE HOLDER'S SUBSCRIPTION stands: a deposit into the second box is pushed to it
	if reason, _ := fixture.deposit(t, fixture.depositOf(watched, linkOctets(store.LinkDepositBytes, 0x69))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a deposit into the second box answered %v", reason)
	}
	pushed := fixture.pusher.rendezvousPushes(pushes + 1)
	if len(pushed) != pushes+1 || !bytes.Equal(pushed[len(pushed)-1].GetRendezvousId(), watched.id) || pushed[len(pushed)-1].GetPendingCount() != 1 {
		t.Fatalf("a deposit into the second box after the unauthorized requests sent %d pushes, want one to its holder of 1 pending: the requests ended the holder's subscription", len(pushed)-pushes)
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

// ── a Collect's subscription, and its undo (LRI R78, N2 and N3) ───────────────────────────────

// LinkBoxes whose Collects each take the next gate, in the order they are made. A gate holds its
// Collect inside the write until it is released, and then fails it, as a store's transient failure
// would, if it says so. A Collect with no gate left goes straight through.
type gatedCollects struct {
	store.LinkBoxes
	mutex sync.Mutex
	gates []*collectGate
}

type collectGate struct {
	entered chan struct{}
	release chan struct{}
	fail    bool
}

func newCollectGate(fail bool) *collectGate {
	return &collectGate{entered: make(chan struct{}), release: make(chan struct{}), fail: fail}
}

var errCollectGateFailed = errors.New("a store failure, made by the test, in a Collect's write")

func (self *gatedCollects) CollectLinkBox(ctx context.Context, request *store.LinkBoxCollectRequest, now time.Time) (*store.LinkBoxCollected, error) {
	self.mutex.Lock()
	var gate *collectGate
	if len(self.gates) != 0 {
		gate, self.gates = self.gates[0], self.gates[1:]
	}
	self.mutex.Unlock()
	if gate != nil {
		close(gate.entered)
		<-gate.release
		if gate.fail {
			return nil, errCollectGateFailed
		}
	}
	return self.LinkBoxes.CollectLinkBox(ctx, request, now)
}

// A fixture whose Collects take `gates`, in order.
func newGatedLinkFixture(t *testing.T, gates ...*collectGate) *linkFixture {
	t.Helper()
	gated := &gatedCollects{gates: gates}
	return newLinkFixture(t, func(config *api.Config) {
		gated.LinkBoxes = config.LinkBoxes
		config.LinkBoxes = gated
	})
}

// The holder's Collect with subscribe on `box`, acknowledging nothing, on a goroutine of its own, its
// answer on the channel.
func (self *linkFixture) collectAsync(box *linkBox) chan protocol.Reason {
	answered := make(chan protocol.Reason, 1)
	go func() {
		reason, _, _ := self.handler.RendezvousCollect(context.Background(), self.conn, self.collectOf(box, 0, 0, true))
		answered <- reason
	}()
	return answered
}

// A deposit into `box`, and how many pushes it sent, waited for a second at most.
func (self *linkFixture) depositPushes(t *testing.T, box *linkBox, seed byte) int {
	t.Helper()
	before := len(self.pusher.rendezvousPushes(0))
	if reason, _ := self.deposit(t, self.depositOf(box, linkOctets(store.LinkDepositBytes, seed))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a deposit into the box answered %v", reason)
	}
	return len(self.pusher.rendezvousPushes(before+1)) - before
}

// A COLLECT WHOSE WRITE FAILS LEAVES NO SUBSCRIPTION (LRI R78, N2). A Collect with subscribe makes its
// subscription before its write, so that a connection at its bound is refused before any deposit is
// deleted, and undoes it when the write does not take. Here the write fails, as a store's transient
// failure would: the Collect answers REASON_INTERNAL, the registry holds nothing, and a deposit after it
// is pushed to nobody. UNDO-DROPPED, which never undoes, is killed here. The control is the same Collect
// with a write that takes, which holds its subscription and is pushed the deposit.
func TestACollectWhoseWriteFailsLeavesNoSubscription(t *testing.T) {
	for _, fail := range []bool{true, false} {
		gate := newCollectGate(fail)
		close(gate.release)
		fixture := newGatedLinkFixture(t, gate)
		box := fixture.mustRegister(t, 0x50)
		reason, _, err := fixture.handler.RendezvousCollect(context.Background(), fixture.conn, fixture.collectOf(box, 0, 0, true))
		held := fixture.subscriptions.RendezvousSubscriptions()
		pushes := fixture.depositPushes(t, box, 0x51)
		if fail && (reason != protocol.Reason_REASON_INTERNAL || !errors.Is(err, errCollectGateFailed) || held != 0 || pushes != 0) {
			t.Fatalf("a Collect with subscribe whose write failed answered %v (%v), left %d subscriptions, and a deposit after it sent %d pushes; want REASON_INTERNAL with the store's error, none and none",
				reason, err, held, pushes)
		}
		if !fail && (reason != protocol.Reason_REASON_OK || err != nil || held != 1 || pushes != 1) {
			t.Fatalf("the control: a Collect with subscribe whose write took answered %v (%v), left %d subscriptions, and a deposit after it sent %d pushes; want REASON_OK, one and one",
				reason, err, held, pushes)
		}
	}
}

// A SUBSCRIPTION A COLLECT WAS TOLD IT HOLDS OUTLASTS ANOTHER COLLECT'S FAILED WRITE (LRI R78, N2; the
// delta review's probe). Of two Collects with subscribe on one connection and one box, the first makes
// the subscription and is held inside its write; the second finds it made, is answered REASON_OK, and
// so is told it holds it; then the first's write fails. The first undoes only what it made, and what it
// made is now held by a Collect that took: the subscription stands, and a deposit is pushed to it.
// UNDO-IGNORES-CLAIMS, which undoes whatever the failing Collect made, is killed here. The control is the
// same two Collects with the first's write taking.
func TestASubscriptionACollectWasToldItHoldsOutlastsAnotherCollectsFailedWrite(t *testing.T) {
	for _, fail := range []bool{true, false} {
		first := newCollectGate(fail)
		fixture := newGatedLinkFixture(t, first)
		box := fixture.mustRegister(t, 0x52)
		firstAnswer := fixture.collectAsync(box)
		<-first.entered
		second, _ := fixture.collect(t, fixture.collectOf(box, 0, 0, true))
		close(first.release)
		firstReason := <-firstAnswer
		held := fixture.subscriptions.RendezvousSubscriptions()
		pushes := fixture.depositPushes(t, box, 0x53)
		want := protocol.Reason_REASON_OK
		if fail {
			want = protocol.Reason_REASON_INTERNAL
		}
		if firstReason != want || second != protocol.Reason_REASON_OK || held != 1 || pushes != 1 {
			t.Fatalf("with the first write failing %v: the first Collect answered %v and the second %v, and after them the registry holds %d subscriptions and a deposit sent %d pushes; want %v, REASON_OK, one and one: the second was told it holds the subscription",
				fail, firstReason, second, held, pushes, want)
		}
	}
}

// A COLLECT'S FAILED WRITE LEAVES A SUBSCRIPTION ANOTHER MADE SINCE (LRI R78, N2: compared by pointer,
// as deliverRendezvous compares). The first Collect with subscribe makes the subscription and is held
// inside its write. A deposit's push to it is refused, as one to a connection that has gone is, and that
// ends it. A second Collect on the same connection then makes a subscription of its own, and is held
// inside its write in turn. The first's write fails: the subscription standing is not the one it made,
// and its undo leaves it. The second's write takes, and the next deposit is pushed to it.
// UNDO-NOT-BY-POINTER, an undo of whatever subscription the connection holds on the box, is killed here.
func TestACollectsFailedWriteLeavesASubscriptionAnotherMadeSince(t *testing.T) {
	first, second := newCollectGate(true), newCollectGate(false)
	fixture := newGatedLinkFixture(t, first, second)
	box := fixture.mustRegister(t, 0x54)
	firstAnswer := fixture.collectAsync(box)
	<-first.entered
	if held := fixture.subscriptions.RendezvousSubscriptions(); held != 1 {
		t.Fatalf("the first Collect, inside its write, holds %d subscriptions, want the one it made", held)
	}

	// the deposit's push is refused, and that ends the first Collect's subscription
	fixture.pusher.refuseNext(1)
	if reason, _ := fixture.deposit(t, fixture.depositOf(box, linkOctets(store.LinkDepositBytes, 0x55))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Deposit: %v", reason)
	}
	deadline := time.Now().Add(5 * time.Second)
	for fixture.pusher.refusedCount() != 1 || fixture.subscriptions.RendezvousSubscriptions() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the refused push did not end the first Collect's subscription in 5 s: %d pushes refused, %d subscriptions held",
				fixture.pusher.refusedCount(), fixture.subscriptions.RendezvousSubscriptions())
		}
		time.Sleep(2 * time.Millisecond)
	}

	secondAnswer := fixture.collectAsync(box)
	<-second.entered
	if held := fixture.subscriptions.RendezvousSubscriptions(); held != 1 {
		t.Fatalf("the second Collect, inside its write, holds %d subscriptions, want the one it made", held)
	}
	close(first.release)
	if reason := <-firstAnswer; reason != protocol.Reason_REASON_INTERNAL {
		t.Fatalf("the first Collect, whose write failed, answered %v, want REASON_INTERNAL", reason)
	}
	close(second.release)
	if reason := <-secondAnswer; reason != protocol.Reason_REASON_OK {
		t.Fatalf("the second Collect answered %v, want REASON_OK", reason)
	}
	if held := fixture.subscriptions.RendezvousSubscriptions(); held != 1 {
		t.Fatalf("after the first Collect's failed write and the second's, the registry holds %d subscriptions, want the second's: the first undid a subscription it did not make", held)
	}
	if pushes := fixture.depositPushes(t, box, 0x56); pushes != 1 {
		t.Fatalf("a deposit after both Collects sent %d pushes, want one, to the second's subscription", pushes)
	}
}

// One run of [TestAStaleCollectLeavesTheSubscriptionsOfTheBoxAtItsIdNow]: what the second box's
// collector and the stale Collect were answered, the subscriptions held after both, and the pushes of a
// deposit into the second box after them.
func staleCollectRun(t *testing.T, stale bool) (protocol.Reason, protocol.Reason, int, int) {
	t.Helper()
	ctx := context.Background()
	swapping := &swappingLinkBoxes{}
	fixture := newLinkFixture(t, func(config *api.Config) {
		swapping.MemoryStore = config.LinkBoxes.(*store.MemoryStore)
		config.LinkBoxes = swapping
	})
	firstExpiry := fixture.clock.now().Add(api.DefaultLinkBoxTtl)
	// the arms' clock stays before the first box's expiry, at which the second box reads as live
	fixture.clock.advance(time.Minute)
	first := fixture.mustRegisterAt(t, 0x40, firstExpiry.Add(-api.DefaultLinkBoxTtl))
	second := newLinkBox(0x40)
	second.deposit = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xC1))
	second.collect = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xD1))
	second.card = linkOctets(store.LinkCardBytes, 0xE1)
	holder := &linkFixture{conn: &api.Connection{ServerNonce: bytes.Repeat([]byte{0x7A}, 16), ClientId: []byte("the second box's collector")}}

	// the first box is swept at its expiry, the second registered at its id, and the second's own
	// collector subscribes, signed under its key over its own nonce
	var holderReason protocol.Reason
	swap := func() {
		if _, err := swapping.MemoryStore.SweepLinkBoxes(ctx, firstExpiry, store.LinkBoxSweepBounds{}); err != nil {
			t.Errorf("the sweep at the first box's expiry: %v", err)
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
		reason, _, err := fixture.handler.RendezvousCollect(ctx, holder.conn, holder.collectOf(second, 0, 0, true))
		if err != nil {
			t.Errorf("the second box's collector's Collect: %v", err)
		}
		holderReason = reason
	}
	var staleReason protocol.Reason
	if stale {
		// inside the stale Collect's Q17
		swapping.mutex.Lock()
		swapping.swap = swap
		swapping.mutex.Unlock()
		staleReason, _ = fixture.collect(t, fixture.collectOf(first, 0, 0, true))
	} else {
		swap()
	}
	held := fixture.subscriptions.RendezvousSubscriptions()
	before := len(fixture.pusher.rendezvousPushes(0))
	reason, _, err := fixture.handler.RendezvousDeposit(ctx, holder.conn, holder.depositOf(second, linkOctets(store.LinkDepositBytes, 0x5C)))
	if err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("a deposit into the second box answered %v (%v)", reason, err)
	}
	pushes := len(fixture.pusher.rendezvousPushes(before+1)) - before
	return holderReason, staleReason, held, pushes
}

// A STALE COLLECT LEAVES THE SUBSCRIPTIONS OF THE BOX AT ITS ID NOW (LRI R78, N3; the delta review's
// probe). A Collect is verified against a box that, between its Q17 read and its subscription, passed
// its expiry, was swept, and had another box registered at its id, whose own collector has subscribed.
// The box standing at the id expires later than the one the Collect read, so the Collect's own box is
// gone: it subscribes nothing and ends nothing, and its write answers REASON_CARD_RETIRED. The second
// box's collector keeps its subscription, and a deposit after is pushed to it. STALE-REPLACES, the
// registry replacing a standing box whatever its expiry, ends that subscription and is killed here. The
// control is the same second box and collector, with no stale Collect.
func TestAStaleCollectLeavesTheSubscriptionsOfTheBoxAtItsIdNow(t *testing.T) {
	for _, stale := range []bool{true, false} {
		holder, staleReason, held, pushes := staleCollectRun(t, stale)
		if holder != protocol.Reason_REASON_OK || held != 1 || pushes != 1 || (stale && staleReason != protocol.Reason_REASON_CARD_RETIRED) {
			t.Fatalf("with a stale Collect %v: the second box's collector was answered %v and the stale Collect %v, and after them the registry holds %d subscriptions and a deposit into the second box sent %d pushes; want REASON_OK, REASON_CARD_RETIRED, one and one",
				stale, holder, staleReason, held, pushes)
		}
	}
}
