package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/protocol"
)

// §4.3.11's kind 4 on the five arms, signatures and all: the identity plan's Task 19 with its verify
// step (LRI R70), and Task 20's Property 1.
//
// WHY THESE ARE HERE AND NOT IN api. Every request below is signed, and api's tests cannot sign:
// Spec A §12.1's A-1 surface hands api the five verifiers and no signer, and api's
// second-implementation gate holds its tests to that surface as it holds its code. The client's half
// is made here, where every package of the module may be reached, and it is made over the preimage
// the library itself builds (message.Rendezvous*Preimage), so that this test and the server never
// hold two implementations of one preimage. What api's own tests keep is what needs no signature:
// the predicate the arms are served on, check 3's shape, and the gates over its source.

// The reject floor these tests serve on: §10.2's "25 [a] as the api tests use".
const linkFloor = 25 * time.Millisecond

// A clock a test moves, so that a box can pass its expiry without a test that sleeps.
type linkClock struct {
	mutex sync.Mutex
	at    time.Time
}

func (self *linkClock) now() time.Time {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.at
}

func (self *linkClock) advance(by time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.at = self.at.Add(by)
}

// A pusher that keeps every push.
type linkPusher struct {
	mutex  sync.Mutex
	pushes []*protocol.MessageServerPush
	signal chan struct{}
}

func (self *linkPusher) Push(clientId []byte, serverNonce []byte, push *protocol.MessageServerPush) bool {
	self.mutex.Lock()
	self.pushes = append(self.pushes, push)
	self.mutex.Unlock()
	select {
	case self.signal <- struct{}{}:
	default:
	}
	return true
}

// The rendezvous pushes received so far, waiting at most a second for `want` of them.
func (self *linkPusher) rendezvousPushes(want int) []*protocol.RendezvousPush {
	deadline := time.After(time.Second)
	for {
		self.mutex.Lock()
		found := []*protocol.RendezvousPush{}
		for _, push := range self.pushes {
			if rendezvous := push.GetRendezvous(); rendezvous != nil {
				found = append(found, rendezvous)
			}
		}
		self.mutex.Unlock()
		if len(found) >= want {
			return found
		}
		select {
		case <-self.signal:
		case <-deadline:
			return found
		}
	}
}

// Everything one test needs: a handler that serves the arms, its store, a connection, its clock, the
// pads it slept and the pushes it sent.
type linkFixture struct {
	handler       *api.Handler
	boxes         *store.MemoryStore
	conn          *api.Connection
	clock         *linkClock
	pusher        *linkPusher
	subscriptions *api.Subscriptions

	mutex  sync.Mutex
	sleeps []time.Duration
}

func newLinkFixture(t *testing.T, configure func(*api.Config)) *linkFixture {
	t.Helper()
	current := &linkFixture{
		boxes:  store.NewMemoryStore(store.DefaultLimits()),
		conn:   &api.Connection{ServerNonce: bytes.Repeat([]byte{0x5E}, 16), ClientId: []byte("a client id the platform authenticated")},
		clock:  &linkClock{at: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)},
		pusher: &linkPusher{signal: make(chan struct{}, 16)},
	}
	subscriptions := api.NewSubscriptions()
	subscriptions.SetPusher(current.pusher)
	t.Cleanup(subscriptions.Close)
	current.subscriptions = subscriptions
	config := api.Config{
		Store:         current.boxes,
		KnownGroups:   api.NewMemoryKnownGroups(),
		Front:         api.ChecksNotImplemented{},
		LinkBoxes:     current.boxes,
		RejectFloor:   linkFloor,
		Now:           current.clock.now,
		Sleep:         current.sleep,
		Subscriptions: subscriptions,
	}
	if configure != nil {
		configure(&config)
	}
	handler, err := api.New(config)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	if !handler.RendezvousServed() && config.LinkBoxes != nil && config.RejectFloor != 0 {
		t.Fatal("a handler with a link box store and a floor serves no rendezvous arm")
	}
	current.handler = handler
	return current
}

func (self *linkFixture) sleep(remaining time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.sleeps = append(self.sleeps, remaining)
}

// The pads slept since the last call, and the slate cleared.
func (self *linkFixture) pads() []time.Duration {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	slept := self.sleeps
	self.sleeps = nil
	return slept
}

func strideBytes(length int, seed byte, stride byte) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = seed + byte(index)*stride
	}
	return value
}

func linkOctets(length int, seed byte) []byte {
	return strideBytes(length, seed, 1)
}

// One link box as its two devices hold it: the id and the deposit key the code derives (any Ed25519
// key here, since the server derives nothing and is handed both), the new device's collect key, and
// the sealed card.
type linkBox struct {
	id      []byte
	deposit ed25519.PrivateKey
	collect ed25519.PrivateKey
	card    []byte
}

func newLinkBox(seed byte) *linkBox {
	return &linkBox{
		id:      linkOctets(store.RendezvousIdBytes, seed),
		deposit: ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, seed+1)),
		collect: ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, seed+2)),
		card:    linkOctets(store.LinkCardBytes, seed+3),
	}
}

func publicOf(key ed25519.PrivateKey) []byte {
	return []byte(key.Public().(ed25519.PublicKey))
}

// register_auth over the library's preimage for the request as it stands, under `key`. The preimage
// takes the alg_id as a u16, and this signs the request's own alg_id truncated to one: for a request
// above 0xFFFF that is the signature a truncating server would verify.
func signRegister(request *protocol.RendezvousRegisterRequest, key ed25519.PrivateKey, nonce []byte) {
	request.RegisterAuth = ed25519.Sign(key, message.RendezvousRegisterPreimage(nonce, &message.RendezvousRegistration{
		RendezvousId:     request.GetRendezvousId(),
		DepositVerifyPub: request.GetDepositVerifyPub(),
		CollectVerifyPub: request.GetCollectVerifyPub(),
		CardXwingPub:     request.GetCardXwingPub(),
		AlgId:            uint16(request.GetAlgId()),
		Kind:             request.GetKind(),
		PublicCt:         request.GetPublicCt(),
	}))
}

// The box's registration, signed by its own collect key over this fixture's connection.
func (self *linkFixture) registration(box *linkBox) *protocol.RendezvousRegisterRequest {
	request := &protocol.RendezvousRegisterRequest{
		RendezvousId:     box.id,
		DepositVerifyPub: publicOf(box.deposit),
		CollectVerifyPub: publicOf(box.collect),
		AlgId:            store.LinkBoxAlgId,
		Kind:             store.LinkBoxKind,
		PublicCt:         box.card,
	}
	signRegister(request, box.collect, self.conn.ServerNonce)
	return request
}

func (self *linkFixture) open(box *linkBox) *protocol.RendezvousOpenRequest {
	return &protocol.RendezvousOpenRequest{
		RendezvousId: box.id,
		OpenAuth:     ed25519.Sign(box.deposit, message.RendezvousOpenPreimage(self.conn.ServerNonce, box.id)),
	}
}

func (self *linkFixture) depositOf(box *linkBox, depositCt []byte) *protocol.RendezvousDepositRequest {
	return &protocol.RendezvousDepositRequest{
		RendezvousId: box.id,
		DepositCt:    depositCt,
		DepositAuth:  ed25519.Sign(box.deposit, message.RendezvousDepositPreimage(self.conn.ServerNonce, box.id, depositCt)),
	}
}

func (self *linkFixture) collectOf(box *linkBox, since uint64, ack uint64, subscribe bool) *protocol.RendezvousCollectRequest {
	return &protocol.RendezvousCollectRequest{
		RendezvousId:        box.id,
		SinceDepositId:      since,
		AckThroughDepositId: ack,
		Subscribe:           subscribe,
		CollectAuth: ed25519.Sign(box.collect, message.RendezvousCollectPreimage(self.conn.ServerNonce, &message.RendezvousCollectParams{
			RendezvousId:        box.id,
			SinceDepositId:      since,
			AckThroughDepositId: ack,
			Subscribe:           subscribe,
		})),
	}
}

func (self *linkFixture) retireOf(box *linkBox) *protocol.RendezvousRetireRequest {
	return &protocol.RendezvousRetireRequest{
		RendezvousId: box.id,
		RetireAuth:   ed25519.Sign(box.collect, message.RendezvousRetirePreimage(self.conn.ServerNonce, box.id)),
	}
}

func (self *linkFixture) register(t *testing.T, request *protocol.RendezvousRegisterRequest) (protocol.Reason, *protocol.RendezvousRegisterResponse) {
	t.Helper()
	reason, response, err := self.handler.RendezvousRegister(context.Background(), self.conn, request)
	if err != nil {
		t.Fatalf("RendezvousRegister: %v", err)
	}
	return reason, response
}

// The box, registered, with the pads of its registration cleared.
func (self *linkFixture) mustRegister(t *testing.T, seed byte) *linkBox {
	t.Helper()
	box := newLinkBox(seed)
	if reason, _ := self.register(t, self.registration(box)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("registering a fresh kind-4 box answered %v", reason)
	}
	self.pads()
	return box
}

func (self *linkFixture) deposit(t *testing.T, request *protocol.RendezvousDepositRequest) (protocol.Reason, *protocol.RendezvousDepositResponse) {
	t.Helper()
	reason, response, err := self.handler.RendezvousDeposit(context.Background(), self.conn, request)
	if err != nil {
		t.Fatalf("RendezvousDeposit: %v", err)
	}
	return reason, response
}

func (self *linkFixture) collect(t *testing.T, request *protocol.RendezvousCollectRequest) (protocol.Reason, *protocol.RendezvousCollectResponse) {
	t.Helper()
	reason, response, err := self.handler.RendezvousCollect(context.Background(), self.conn, request)
	if err != nil {
		t.Fatalf("RendezvousCollect: %v", err)
	}
	return reason, response
}

func (self *linkFixture) retire(t *testing.T, request *protocol.RendezvousRetireRequest) protocol.Reason {
	t.Helper()
	reason, _, err := self.handler.RendezvousRetire(context.Background(), self.conn, request)
	if err != nil {
		t.Fatalf("RendezvousRetire: %v", err)
	}
	return reason
}

// One answer from an arm: what it answered, whether it carried a body, and the pads it slept.
type linkAnswer struct {
	reason protocol.Reason
	body   bool
	pads   []time.Duration
}

// The answer of each arm after Register to the four requests given, one per arm.
func (self *linkFixture) answers(t *testing.T, open *protocol.RendezvousOpenRequest, deposit *protocol.RendezvousDepositRequest,
	collect *protocol.RendezvousCollectRequest, retire *protocol.RendezvousRetireRequest) map[string]linkAnswer {
	t.Helper()
	ctx := context.Background()
	answers := map[string]linkAnswer{}
	self.pads()
	{
		reason, response, err := self.handler.RendezvousOpen(ctx, self.conn, open)
		if err != nil {
			t.Fatalf("RendezvousOpen: %v", err)
		}
		answers["Open"] = linkAnswer{reason, response != nil, self.pads()}
	}
	{
		reason, response, err := self.handler.RendezvousDeposit(ctx, self.conn, deposit)
		if err != nil {
			t.Fatalf("RendezvousDeposit: %v", err)
		}
		answers["Deposit"] = linkAnswer{reason, response != nil, self.pads()}
	}
	{
		reason, response, err := self.handler.RendezvousCollect(ctx, self.conn, collect)
		if err != nil {
			t.Fatalf("RendezvousCollect: %v", err)
		}
		answers["Collect"] = linkAnswer{reason, response != nil, self.pads()}
	}
	{
		reason, response, err := self.handler.RendezvousRetire(ctx, self.conn, retire)
		if err != nil {
			t.Fatalf("RendezvousRetire: %v", err)
		}
		answers["Retire"] = linkAnswer{reason, response != nil, self.pads()}
	}
	return answers
}

// The four arms after Register, each with a request its holder signed.
func (self *linkFixture) signedAnswers(t *testing.T, box *linkBox) map[string]linkAnswer {
	t.Helper()
	return self.answers(t, self.open(box), self.depositOf(box, linkOctets(store.LinkDepositBytes, 0x77)),
		self.collectOf(box, 0, 9, false), self.retireOf(box))
}

// §4.3.11's one answer for every box no arm may use: REASON_CARD_RETIRED, no body, one pad.
var oneAnswer = linkAnswer{reason: protocol.Reason_REASON_CARD_RETIRED, body: false, pads: []time.Duration{linkFloor}}

// ── Property 1 ───────────────────────────────────────────────────────────────────────────────

// A LINK BOX DEPOSIT IS EXACTLY ITS SIZE (Spec B §13's test 45). A deposit one octet short, one
// long, empty or doubled is refused, signed or not, as an equality refuses it, and so is a card one
// octet off 4,124. Each refusal is padded to the floor and leaves nothing behind; a deposit of
// exactly the size, signed, is taken. MR4, a range check, is killed here.
func TestALinkBoxDepositIsExactlyItsSize(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	box := fixture.mustRegister(t, 0x10)

	for _, length := range []int{store.LinkDepositBytes - 1, store.LinkDepositBytes + 1, 0, 2 * store.LinkDepositBytes} {
		reason, response := fixture.deposit(t, fixture.depositOf(box, linkOctets(length, 0x20)))
		if reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a signed deposit of %d octets was answered %v with a body %v; §5.1.2 check 3 refuses every length but %d",
				length, reason, response != nil, store.LinkDepositBytes)
		}
		if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{linkFloor}) {
			t.Fatalf("the refusal of a %d-octet deposit slept %v, want one pad to the floor", length, pads)
		}
	}
	if stored, err := fixture.boxes.LinkBox(context.Background(), box.id); err != nil || stored.DepositsTaken != 0 {
		t.Fatalf("after four refused deposits the box reads %+v (%v), want none taken", stored, err)
	}
	reason, response := fixture.deposit(t, fixture.depositOf(box, linkOctets(store.LinkDepositBytes, 0x20)))
	if reason != protocol.Reason_REASON_OK || response.GetDepositId() != 1 || len(response.GetDepositHash()) != 32 {
		t.Fatalf("a signed deposit of exactly %d octets was answered %v and %+v, want REASON_OK, deposit 1 and its 32-octet hash",
			store.LinkDepositBytes, reason, response)
	}

	for _, length := range []int{store.LinkCardBytes - 1, store.LinkCardBytes + 1} {
		other := newLinkBox(0x40)
		other.card = linkOctets(length, 0x41)
		if reason, response := fixture.register(t, fixture.registration(other)); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a signed registration of a %d-octet card answered %v, want REASON_REJECTED with no body", length, reason)
		}
		if _, err := fixture.boxes.LinkBox(context.Background(), other.id); !errors.Is(err, store.ErrLinkBoxUnknown) {
			t.Fatalf("a refused registration of a %d-octet card left a row: %v", length, err)
		}
	}
}

// ── Property 2 ───────────────────────────────────────────────────────────────────────────────

// AN UNKNOWN, A RETIRED AND AN UNAUTHORIZED BOX ANSWER ALIKE (Spec B §13's test 46), on Open,
// Deposit, Collect and Retire: the same code, no body, one pad to the same floor. A box past its
// expiry answers so too, decided by its expiry and not by the sweep, and none of the four arms
// changes it. UNAUTHORIZED is a live box asked with a signature that does not hold: under another
// key, over another connection's nonce, or none at all; and Open answers nothing without a valid
// open_auth. The control is the same four arms, each signed by the box's holder, on the live box.
// MR5, an unknown id answered REASON_REJECTED, and MR6, Open without open_auth, are killed here.
func TestAnUnknownARetiredAndAnUnauthorizedBoxAnswerAlike(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	retired := fixture.mustRegister(t, 0x20)
	if reason := fixture.retire(t, fixture.retireOf(retired)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("retiring a live box answered %v", reason)
	}
	expired := fixture.mustRegister(t, 0x30)
	if reason, _ := fixture.deposit(t, fixture.depositOf(expired, linkOctets(store.LinkDepositBytes, 0x31))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a deposit into a live box answered %v", reason)
	}
	fixture.clock.advance(api.DefaultLinkBoxTtl)
	before, err := fixture.boxes.LinkBox(context.Background(), expired.id)
	if err != nil {
		t.Fatalf("LinkBox: %v", err)
	}
	// registered once the clock has moved, so live now
	live := fixture.mustRegister(t, 0x60)

	// THE CONTROL: the holder's own open_auth is taken, on the live box
	if reason, response, err := fixture.handler.RendezvousOpen(context.Background(), fixture.conn, fixture.open(live)); err != nil || reason != protocol.Reason_REASON_OK || !bytes.Equal(response.GetPublicCt(), live.card) {
		t.Fatalf("the control: Open on a live box, signed by its holder, answered %v (%v), want its card", reason, err)
	}
	fixture.pads()

	unknown := newLinkBox(0xE0)
	for name, box := range map[string]*linkBox{
		"an unknown id":         unknown,
		"a retired box":         retired,
		"a box past its expiry": expired,
	} {
		for arm, answer := range fixture.signedAnswers(t, box) {
			if !reflect.DeepEqual(answer, oneAnswer) {
				t.Fatalf("%s on %s, signed by its holder, was answered %v with a body %v after pads %v; §4.3.11 gives every box no arm may use one answer: %v, no body, one pad to %v",
					arm, name, answer.reason, answer.body, answer.pads, oneAnswer.reason, linkFloor)
			}
		}
	}
	if after, err := fixture.boxes.LinkBox(context.Background(), expired.id); err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("the four arms answered a box past its expiry and changed it: %+v, then %+v (%v)", before, after, err)
	}

	t.Run("AnUnauthorizedBox", func(t *testing.T) {
		stranger := newLinkBox(0x60) // the live box's id, under keys the box never pinned
		stranger.deposit = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA1))
		stranger.collect = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA2))
		elsewhere := &linkFixture{conn: &api.Connection{ServerNonce: bytes.Repeat([]byte{0x6F}, 16)}}
		depositCt := linkOctets(store.LinkDepositBytes, 0x78)

		unsigned := func(request any) any {
			switch typed := request.(type) {
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
		for name, requests := range map[string][4]any{
			"signed under keys the box never pinned": {
				fixture.open(stranger), fixture.depositOf(stranger, depositCt), fixture.collectOf(stranger, 0, 9, false), fixture.retireOf(stranger)},
			"signed over another connection's nonce": {
				elsewhere.open(live), elsewhere.depositOf(live, depositCt), elsewhere.collectOf(live, 0, 9, false), elsewhere.retireOf(live)},
			"unsigned": {
				unsigned(fixture.open(live)), unsigned(fixture.depositOf(live, depositCt)), unsigned(fixture.collectOf(live, 0, 9, false)), unsigned(fixture.retireOf(live))},
			"the deposit and the collect key swapped": {
				(&linkFixture{conn: fixture.conn}).open(&linkBox{id: live.id, deposit: live.collect}),
				(&linkFixture{conn: fixture.conn}).depositOf(&linkBox{id: live.id, deposit: live.collect}, depositCt),
				(&linkFixture{conn: fixture.conn}).collectOf(&linkBox{id: live.id, collect: live.deposit}, 0, 9, false),
				(&linkFixture{conn: fixture.conn}).retireOf(&linkBox{id: live.id, collect: live.deposit})},
		} {
			answers := fixture.answers(t, requests[0].(*protocol.RendezvousOpenRequest), requests[1].(*protocol.RendezvousDepositRequest),
				requests[2].(*protocol.RendezvousCollectRequest), requests[3].(*protocol.RendezvousRetireRequest))
			for arm, answer := range answers {
				if !reflect.DeepEqual(answer, oneAnswer) {
					t.Fatalf("%s on a live box, %s, was answered %v with a body %v after pads %v; a signature that does not verify is answered as an unknown box is",
						arm, name, answer.reason, answer.body, answer.pads)
				}
			}
		}
		// and the live box is as it was: nothing was deposited, collected or retired into it
		if stored, err := fixture.boxes.LinkBox(context.Background(), live.id); err != nil || stored.RetiredTime != nil || stored.DepositsTaken != 0 {
			t.Fatalf("unauthorized requests changed the live box: %+v (%v)", stored, err)
		}
	})
}

// ── Property 3 ───────────────────────────────────────────────────────────────────────────────

// A LIVE BOX KEEPS THE KEY IT WAS REGISTERED UNDER (Spec B §13's test 47). A registration at its id
// under another collect key, another deposit key or another card is refused, each signed by the key
// it names, as Register's self-certification takes it; so is one at a box past its expiry. The same
// three values answer REASON_OK and change nothing, the expiry included. A collect signed by any key
// but the pinned one is answered as an unknown box is. MR7, a registration that replaces the pinned
// key, is killed here.
func TestALiveBoxKeepsTheKeyItWasRegisteredUnder(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	box := newLinkBox(0x50)
	reason, first := fixture.register(t, fixture.registration(box))
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("a fresh registration answered %v", reason)
	}
	pinned, _ := fixture.boxes.LinkBox(context.Background(), box.id)
	fixture.pads()

	for name, change := range map[string]func(*linkBox){
		"another collect key": func(other *linkBox) { other.collect = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA0)) },
		"another deposit key": func(other *linkBox) { other.deposit = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA1)) },
		"another card":        func(other *linkBox) { other.card = linkOctets(store.LinkCardBytes, 0xA2) },
	} {
		other := newLinkBox(0x50)
		change(other)
		if reason, response := fixture.register(t, fixture.registration(other)); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a signed registration with %s at a live box's id answered %v, want REASON_REJECTED with no body", name, reason)
		}
		if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{linkFloor}) {
			t.Fatalf("the refused registration with %s slept %v, want one pad to the floor", name, pads)
		}
		if stored, _ := fixture.boxes.LinkBox(context.Background(), box.id); !reflect.DeepEqual(stored, pinned) {
			t.Fatalf("a refused registration with %s changed the box from %+v to %+v", name, pinned, stored)
		}
	}

	t.Run("ACollectUnderAnotherKey", func(t *testing.T) {
		other := newLinkBox(0x50)
		other.collect = ed25519.NewKeyFromSeed(linkOctets(ed25519.SeedSize, 0xA0))
		reason, response := fixture.collect(t, fixture.collectOf(other, 0, 0, false))
		if reason != protocol.Reason_REASON_CARD_RETIRED || response != nil {
			t.Fatalf("a collect signed by a key the box never pinned answered %v, want REASON_CARD_RETIRED with no body", reason)
		}
		fixture.pads()
		if reason, _ := fixture.collect(t, fixture.collectOf(box, 0, 0, false)); reason != protocol.Reason_REASON_OK {
			t.Fatalf("the control, a collect signed by the pinned key, answered %v", reason)
		}
		fixture.pads()
	})

	fixture.clock.advance(time.Minute)
	reason, again := fixture.register(t, fixture.registration(box))
	if reason != protocol.Reason_REASON_OK || again.GetExpireTimeMs() != first.GetExpireTimeMs() {
		t.Fatalf("the same registration a minute on answered %v with expiry %d, want REASON_OK and the first expiry %d: a link box is not kept alive",
			reason, again.GetExpireTimeMs(), first.GetExpireTimeMs())
	}

	fixture.clock.advance(api.DefaultLinkBoxTtl)
	if reason, _ := fixture.register(t, fixture.registration(box)); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("the same registration past the box's expiry answered %v, want REASON_REJECTED", reason)
	}
}

// REGISTER IS SELF-CERTIFIED (Spec B §4.3.11): register_auth must hold under the collect key the
// request itself carries. A registration signed by another key, over another connection's nonce, or
// not at all, is refused before anything is read or written; the control is the same registration
// signed by its own collect key.
func TestARegistrationMustBeSignedByTheCollectKeyItCarries(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	box := newLinkBox(0x70)
	for name, sign := range map[string]func(*protocol.RendezvousRegisterRequest){
		"signed by the deposit key": func(request *protocol.RendezvousRegisterRequest) {
			signRegister(request, box.deposit, fixture.conn.ServerNonce)
		},
		"signed over another connection's nonce": func(request *protocol.RendezvousRegisterRequest) {
			signRegister(request, box.collect, bytes.Repeat([]byte{0x6F}, 16))
		},
		"unsigned": func(request *protocol.RendezvousRegisterRequest) { request.RegisterAuth = nil },
	} {
		request := fixture.registration(box)
		sign(request)
		if reason, response := fixture.register(t, request); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a registration %s answered %v, want REASON_REJECTED with no body", name, reason)
		}
		if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{linkFloor}) {
			t.Fatalf("the refused registration %s slept %v, want one pad to the floor", name, pads)
		}
		if _, err := fixture.boxes.LinkBox(context.Background(), box.id); !errors.Is(err, store.ErrLinkBoxUnknown) {
			t.Fatalf("a registration %s left a row: %v", name, err)
		}
	}
	if reason, _ := fixture.register(t, fixture.registration(box)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control, the registration signed by its own collect key, answered %v", reason)
	}
}

// A BOX IS NEVER STORED UNDER A KEY OF SMALL ORDER (LRI R72, R73). crypto/ed25519 accepts the
// signature R = the identity, S = 0 under such a key, for every message, so a box pinned under one
// would answer anyone; the library's verifiers refuse every such key first, so it would answer no
// one. Register refuses either key of small order at check 3, REJECTED and padded, and stores
// nothing: a deposit key of small order with the registration signed by its collect key, and a
// collect key of small order with the signature crypto/ed25519 accepts from anyone under it. The
// control is the same registration under keys of full order, and the forgery's own control is that
// crypto/ed25519 does accept it. Register's small-order call dropped is killed here, by the deposit
// key: check 7 at Register reads the collect key alone.
func TestRegisterRefusesAKeyOfSmallOrderAndStoresNothing(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	identity := append([]byte{0x01}, make([]byte, 31)...)
	forged := append(append([]byte{0x01}, make([]byte, 31)...), make([]byte, 32)...)
	if !ed25519.Verify(identity, []byte("any message at all"), forged) {
		t.Fatal("crypto/ed25519 refuses R = the identity, S = 0 under the identity, so the collect-key case below would be refused for that and not for its order")
	}

	for name, current := range map[string]struct {
		seed    byte
		request func(*linkBox) *protocol.RendezvousRegisterRequest
	}{
		"a deposit key of small order": {0x80, func(box *linkBox) *protocol.RendezvousRegisterRequest {
			request := fixture.registration(box)
			request.DepositVerifyPub = identity
			signRegister(request, box.collect, fixture.conn.ServerNonce)
			return request
		}},
		"a collect key of small order": {0x88, func(box *linkBox) *protocol.RendezvousRegisterRequest {
			request := fixture.registration(box)
			request.CollectVerifyPub = identity
			request.RegisterAuth = forged
			return request
		}},
	} {
		box := newLinkBox(current.seed)
		if reason, response := fixture.register(t, current.request(box)); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a registration with %s answered %v, want REASON_REJECTED with no body", name, reason)
		}
		if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{linkFloor}) {
			t.Fatalf("the refused registration with %s slept %v, want one pad to the floor", name, pads)
		}
		if _, err := fixture.boxes.LinkBox(context.Background(), box.id); !errors.Is(err, store.ErrLinkBoxUnknown) {
			t.Fatalf("a registration with %s left a row: %v", name, err)
		}
	}
	if reason, _ := fixture.register(t, fixture.registration(newLinkBox(0x90))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control, a registration under keys of full order, answered %v", reason)
	}
}

// ── Property 4 ───────────────────────────────────────────────────────────────────────────────

// LinkBoxes whose live count cannot be read.
type unreadableLiveCount struct {
	store.LinkBoxes
}

var errTheCountIsNotThere = errors.New("linkbox_test: the live count did not answer")

func (self *unreadableLiveCount) LiveLinkBoxes(ctx context.Context, now time.Time) (uint64, error) {
	return 0, errTheCountIsNotThere
}

// THE LIVE BOX CAP FAILS CLOSED (Spec B §13's test 48). A registration is refused when the live
// boxes are at the cap, and when their count cannot be read; a retired or an expired box does not
// count; and Register's one rule comes before the cap, so a retry of a live box's own registration
// is answered at a full cap. MR8, an unreadable count taken as room, is killed here.
func TestTheLiveBoxCapFailsClosed(t *testing.T) {
	fixture := newLinkFixture(t, func(config *api.Config) { config.LinkBoxLiveCap = 2 })
	first := fixture.mustRegister(t, 0x60)
	fixture.mustRegister(t, 0x61)

	third := newLinkBox(0x62)
	if reason, response := fixture.register(t, fixture.registration(third)); reason != protocol.Reason_REASON_CARD_RATE_LIMITED || response != nil {
		t.Fatalf("a registration at a full cap answered %v, want REASON_CARD_RATE_LIMITED with no body", reason)
	}
	if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{linkFloor}) {
		t.Fatalf("the refusal at a full cap slept %v, want one pad to the floor", pads)
	}
	if _, err := fixture.boxes.LinkBox(context.Background(), third.id); !errors.Is(err, store.ErrLinkBoxUnknown) {
		t.Fatalf("a registration refused at the cap left a row: %v", err)
	}
	if reason, _ := fixture.register(t, fixture.registration(first)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a live box's own registration, repeated at a full cap, answered %v; the one rule comes before the cap", reason)
	}
	if reason := fixture.retire(t, fixture.retireOf(first)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Retire: %v", reason)
	}
	if reason, _ := fixture.register(t, fixture.registration(third)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("with one of two boxes retired, a registration answered %v; a retired box does not count", reason)
	}

	t.Run("AnUnreadableCount", func(t *testing.T) {
		broken := newLinkFixture(t, func(config *api.Config) {
			config.LinkBoxes = &unreadableLiveCount{LinkBoxes: config.LinkBoxes}
		})
		box := newLinkBox(0x70)
		if reason, response := broken.register(t, broken.registration(box)); reason != protocol.Reason_REASON_CARD_RATE_LIMITED || response != nil {
			t.Fatalf("a registration whose live count could not be read answered %v, want REASON_CARD_RATE_LIMITED: the cap fails closed", reason)
		}
		if _, err := broken.boxes.LinkBox(context.Background(), box.id); !errors.Is(err, store.ErrLinkBoxUnknown) {
			t.Fatalf("a registration refused on an unreadable count left a row: %v", err)
		}
		// the control: the same registration, on a store whose count answers
		control := newLinkFixture(t, nil)
		if reason, _ := control.register(t, control.registration(box)); reason != protocol.Reason_REASON_OK {
			t.Fatalf("the control, the same registration with a count that answers, was answered %v", reason)
		}
	})
}

// ── Property 5 ───────────────────────────────────────────────────────────────────────────────

// LinkBoxes that fail every call, for the error paths of the logging gate.
type failingLinkBoxes struct{}

var errTheStoreFailed = errors.New("linkbox_test: the link box store failed")

func (failingLinkBoxes) RegisterLinkBox(context.Context, *store.LinkBoxRegistration, time.Time, time.Duration, uint64) (*store.LinkBoxRegistered, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) LinkBox(context.Context, []byte) (*store.LinkBox, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) DepositLinkBox(context.Context, []byte, []byte, []byte, time.Time) (*store.LinkBoxDeposited, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) CollectLinkBox(context.Context, *store.LinkBoxCollectRequest, time.Time) (*store.LinkBoxCollected, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) RetireLinkBox(context.Context, []byte, []byte, time.Time) (*store.LinkBoxRetired, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) LiveLinkBoxes(context.Context, time.Time) (uint64, error) {
	return 0, errTheStoreFailed
}

type lockedWriter struct {
	buffer *bytes.Buffer
	mutex  *sync.Mutex
}

func (self lockedWriter) Write(data []byte) (int, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.buffer.Write(data)
}

// NOTHING NAMES A BOX (Spec B §13's test 49; §11.1): no log line, metric label or error the arms
// write carries a rendezvous id, a deposit hash or a key. Every arm is run on its served path, on
// its refusals, unsigned and signed, and on a store that fails, with planted values, while the
// process's slog default and the standard logger write into this test; then every line written,
// every error answered and every NotBuilt line is searched for each planted value raw, in lower hex
// and in upper hex. The control plants one line and must find it, by its value and no other. The
// api package keeps no metric with a label, and [api.Subscriptions.Stats] answers counts. MR9, a
// handler that logs the rendezvous id, is killed here.
func TestNoLogLineMetricLabelOrErrorCarriesARendezvousIdADepositHashOrAKey(t *testing.T) {
	captured := &bytes.Buffer{}
	var capturedMutex sync.Mutex
	writer := lockedWriter{buffer: captured, mutex: &capturedMutex}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug})))
	previousOutput := log.Writer()
	log.SetOutput(writer)
	defer func() {
		slog.SetDefault(previous)
		log.SetOutput(previousOutput)
	}()

	errorsAnswered := []string{}
	keep := func(err error) {
		if err != nil {
			errorsAnswered = append(errorsAnswered, err.Error())
		}
	}
	// each planted value on a stride of its own, so that no one of them is a run inside another
	planted := &linkBox{
		id:      strideBytes(store.RendezvousIdBytes, 0x13, 1),
		deposit: ed25519.NewKeyFromSeed(strideBytes(ed25519.SeedSize, 0x29, 3)),
		collect: ed25519.NewKeyFromSeed(strideBytes(ed25519.SeedSize, 0x47, 5)),
		card:    strideBytes(store.LinkCardBytes, 0x61, 7),
	}
	plantedCt := strideBytes(store.LinkDepositBytes, 0x83, 11)
	var plantedHash []byte

	ctx := context.Background()
	for name, fixture := range map[string]*linkFixture{
		"served":             newLinkFixture(t, nil),
		"a store that fails": newLinkFixture(t, func(config *api.Config) { config.LinkBoxes = failingLinkBoxes{} }),
	} {
		_, _, err := fixture.handler.RendezvousRegister(ctx, fixture.conn, fixture.registration(planted))
		keep(err)
		_, deposited, err := fixture.handler.RendezvousDeposit(ctx, fixture.conn, fixture.depositOf(planted, plantedCt))
		keep(err)
		if deposited != nil {
			plantedHash = deposited.GetDepositHash()
		}
		_, _, err = fixture.handler.RendezvousOpen(ctx, fixture.conn, fixture.open(planted))
		keep(err)
		_, _, err = fixture.handler.RendezvousCollect(ctx, fixture.conn, fixture.collectOf(planted, 0, 0, true))
		keep(err)
		_, _, err = fixture.handler.RendezvousRetire(ctx, fixture.conn, fixture.retireOf(planted))
		keep(err)
		if name == "served" {
			// every refusal once more on the served store, the box now retired, signed and not
			fixture.signedAnswers(t, planted)
			fixture.answers(t, &protocol.RendezvousOpenRequest{RendezvousId: planted.id},
				&protocol.RendezvousDepositRequest{RendezvousId: planted.id, DepositCt: plantedCt},
				&protocol.RendezvousCollectRequest{RendezvousId: planted.id}, &protocol.RendezvousRetireRequest{RendezvousId: planted.id})
		}
		for _, line := range fixture.handler.NotBuilt() {
			errorsAnswered = append(errorsAnswered, line.String())
		}
		t.Logf("%s: the arms ran", name)
	}
	if len(plantedHash) != 32 {
		t.Fatal("the served deposit answered no 32-octet hash, so the gate would search for nothing")
	}

	forms := func(value []byte) []string {
		return []string{string(value), fmt.Sprintf("%x", value), fmt.Sprintf("%X", value)}
	}
	values := map[string][]byte{
		"the rendezvous id":       planted.id,
		"the deposit key":         publicOf(planted.deposit),
		"the collect key":         publicOf(planted.collect),
		"the deposit hash":        plantedHash,
		"the card's first octets": planted.card[:16],
	}
	search := func(haystack string) []string {
		found := []string{}
		for name, value := range values {
			for _, form := range forms(value) {
				if strings.Contains(haystack, form) {
					found = append(found, name)
					break
				}
			}
		}
		slices.Sort(found)
		return found
	}
	// the self-check: each planted value is found in its own forms and in no other's
	for name, value := range values {
		for _, form := range forms(value) {
			if found := search(form); !slices.Equal(found, []string{name}) {
				t.Fatalf("the planted values overlap: a form of %s is found as %v, so a hit could not say what it found", name, found)
			}
		}
	}

	capturedMutex.Lock()
	written := captured.String()
	capturedMutex.Unlock()
	if found := search(written); len(found) != 0 {
		t.Fatalf("a log line names %v:\n%s", found, written)
	}
	if found := search(strings.Join(errorsAnswered, "\n")); len(found) != 0 {
		t.Fatalf("an error or a NotBuilt line names %v:\n%s", found, strings.Join(errorsAnswered, "\n"))
	}
	t.Logf("%d octets of log and %d errors and NotBuilt lines searched for five planted values, three forms each", len(written), len(errorsAnswered))

	// THE CONTROL, in the same capture: one planted line, which the search must find, by the value
	// it plants and by no other
	slog.Info("control", "rendezvous_id", fmt.Sprintf("%x", planted.id))
	capturedMutex.Lock()
	written = captured.String()
	capturedMutex.Unlock()
	if found := search(written); !slices.Equal(found, []string{"the rendezvous id"}) {
		t.Fatalf("the control planted the rendezvous id in one log line and the search found %v", found)
	}
}

// ── Property 6 ───────────────────────────────────────────────────────────────────────────────

// LinkBoxes that count every call, so that "no store call" is a measurement.
type countingLinkBoxes struct {
	store.LinkBoxes
	mutex sync.Mutex
	calls int
}

func (self *countingLinkBoxes) count() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.calls++
}
func (self *countingLinkBoxes) RegisterLinkBox(ctx context.Context, registration *store.LinkBoxRegistration, now time.Time, ttl time.Duration, liveCap uint64) (*store.LinkBoxRegistered, error) {
	self.count()
	return self.LinkBoxes.RegisterLinkBox(ctx, registration, now, ttl, liveCap)
}
func (self *countingLinkBoxes) LinkBox(ctx context.Context, rendezvousId []byte) (*store.LinkBox, error) {
	self.count()
	return self.LinkBoxes.LinkBox(ctx, rendezvousId)
}
func (self *countingLinkBoxes) DepositLinkBox(ctx context.Context, rendezvousId []byte, verifiedPub []byte, depositCt []byte, now time.Time) (*store.LinkBoxDeposited, error) {
	self.count()
	return self.LinkBoxes.DepositLinkBox(ctx, rendezvousId, verifiedPub, depositCt, now)
}
func (self *countingLinkBoxes) CollectLinkBox(ctx context.Context, request *store.LinkBoxCollectRequest, now time.Time) (*store.LinkBoxCollected, error) {
	self.count()
	return self.LinkBoxes.CollectLinkBox(ctx, request, now)
}
func (self *countingLinkBoxes) RetireLinkBox(ctx context.Context, rendezvousId []byte, verifiedPub []byte, now time.Time) (*store.LinkBoxRetired, error) {
	self.count()
	return self.LinkBoxes.RetireLinkBox(ctx, rendezvousId, verifiedPub, now)
}
func (self *countingLinkBoxes) LiveLinkBoxes(ctx context.Context, now time.Time) (uint64, error) {
	self.count()
	return self.LinkBoxes.LiveLinkBoxes(ctx, now)
}

// ONLY KIND FOUR IS SERVED, AND NOTHING WITH A ZERO FLOOR (Spec B §13's test 51; LRI R66). A
// registration of kind 0, the proto's default and the card's, or of any kind but 4, is refused,
// signed or not; and a handler whose reject floor is zero serves no kind-4 arm: every arm, signed,
// answers as an unserved arm, no call reaches the store, Capabilities 26 and 29 leave kind 4 out,
// and NotBuilt says why. The control is the same registration at kind 4, which is taken. MR12, the
// arms served at a zero floor, is killed here; MR11, the server's own kind check dropped, is killed
// by api's check-3 test, since the library's register verifier refuses every kind but 4 as well.
func TestOnlyKindFourIsServedAndNothingWithAZeroFloor(t *testing.T) {
	served := newLinkFixture(t, nil)
	for _, kind := range []uint32{0, 1, 2, 3, 5, 255} {
		box := newLinkBox(byte(0x10 + kind))
		request := served.registration(box)
		request.Kind = kind
		// signed as the kind-4 registration was: the library builds no preimage for another kind
		if reason, response := served.register(t, request); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a registration of kind %d answered %v, want REASON_REJECTED: no build of I1 serves any kind but 4", kind, reason)
		}
	}
	if reason, _ := served.register(t, served.registration(newLinkBox(0x90))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control, a registration of kind 4, answered %v", reason)
	}
	if kinds, sizes := served.handler.RendezvousKinds(), served.handler.RendezvousDepositSizes(); kinds != 16 || !slices.Equal(sizes, []uint32{store.LinkDepositBytes}) {
		t.Fatalf("a served handler advertises kinds %b and deposit sizes %v, want 10000 and [%d]", kinds, sizes, store.LinkDepositBytes)
	}

	counting := &countingLinkBoxes{}
	unpadded := newLinkFixture(t, func(config *api.Config) {
		counting.LinkBoxes = config.LinkBoxes
		config.LinkBoxes = counting
		config.RejectFloor = 0
	})
	if unpadded.handler.RendezvousServed() {
		t.Fatal("a handler whose reject floor is zero says it serves the rendezvous arms")
	}
	box := newLinkBox(0xA0)
	if reason, _ := unpadded.register(t, unpadded.registration(box)); reason != protocol.Reason_REASON_INTERNAL {
		t.Fatalf("Register at a zero floor answered %v, want REASON_INTERNAL, as an unserved arm is answered", reason)
	}
	for arm, answer := range unpadded.signedAnswers(t, box) {
		if answer.reason != protocol.Reason_REASON_INTERNAL {
			t.Fatalf("%s at a zero floor answered %v, want REASON_INTERNAL, as an unserved arm is answered", arm, answer.reason)
		}
	}
	if counting.calls != 0 {
		t.Fatalf("the arms of a handler with a zero floor reached the store %d times", counting.calls)
	}
	if kinds, sizes := unpadded.handler.RendezvousKinds(), unpadded.handler.RendezvousDepositSizes(); kinds != 0 || sizes != nil {
		t.Fatalf("a handler with a zero floor advertises kinds %b and deposit sizes %v, want none", kinds, sizes)
	}
	if !slices.ContainsFunc(unpadded.handler.NotBuilt(), func(line api.NotBuilt) bool { return strings.Contains(line.What, "reject_floor_ms is zero") }) {
		t.Fatalf("a handler with a zero floor does not say why it serves no kind-4 arm: %v", unpadded.handler.NotBuilt())
	}
}

// AN ALG_ID ABOVE 0xFFFF IS REFUSED, AND NEVER TRUNCATED (the library's RendezvousRegistration; the
// coordinator's note on Task 7b). The request carries alg_id as a u32 and the preimage takes a u16,
// so each registration below is signed exactly as a server that truncated would verify it: over
// 0x0014. Each is refused, padded, and leaves no row. The control is 0x0014 itself, signed the same
// way, which is taken. A mutant that truncates the alg_id instead of refusing it is killed here.
func TestAnAlgIdAboveTheU16IsRefusedAndNeverTruncated(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	for index, algId := range []uint32{0x00010014, 0x00FF0014, 0xFFFF0014} {
		box := newLinkBox(byte(0x30 + 0x10*index))
		request := fixture.registration(box)
		request.AlgId = algId
		signRegister(request, box.collect, fixture.conn.ServerNonce)
		if reason, response := fixture.register(t, request); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a registration with alg_id %#x, signed over its truncation 0x0014, answered %v; it is refused, never truncated", algId, reason)
		}
		if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{linkFloor}) {
			t.Fatalf("the refusal of alg_id %#x slept %v, want one pad to the floor", algId, pads)
		}
		if _, err := fixture.boxes.LinkBox(context.Background(), box.id); !errors.Is(err, store.ErrLinkBoxUnknown) {
			t.Fatalf("a registration with alg_id %#x left a row: %v", algId, err)
		}
	}
	if reason, _ := fixture.register(t, fixture.registration(newLinkBox(0xC0))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control, alg_id 0x0014 signed the same way, answered %v", reason)
	}
}

// ── the push ─────────────────────────────────────────────────────────────────────────────────

// A DEPOSIT IS PUSHED TO A COLLECTOR THAT SUBSCRIBED (§4.3.11), with the box's id and the count
// waiting and nothing else; a retire ends the subscription, and so does the box's expiry. The
// control is a collect that did not subscribe, after which a deposit pushes nothing.
func TestADepositIsPushedToACollectorThatSubscribed(t *testing.T) {
	fixture := newLinkFixture(t, nil)
	quiet := fixture.mustRegister(t, 0xD0)
	if reason, _ := fixture.collect(t, fixture.collectOf(quiet, 0, 0, false)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect: %v", reason)
	}
	if reason, _ := fixture.deposit(t, fixture.depositOf(quiet, linkOctets(store.LinkDepositBytes, 0xD1))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Deposit: %v", reason)
	}

	box := fixture.mustRegister(t, 0xE0)
	if reason, _ := fixture.collect(t, fixture.collectOf(box, 0, 0, true)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect with subscribe: %v", reason)
	}
	for index, want := range []uint32{1, 2} {
		if reason, _ := fixture.deposit(t, fixture.depositOf(box, linkOctets(store.LinkDepositBytes, byte(0xE1+index)))); reason != protocol.Reason_REASON_OK {
			t.Fatalf("Deposit %d: %v", index+1, reason)
		}
		pushes := fixture.pusher.rendezvousPushes(index + 1)
		if len(pushes) != index+1 {
			t.Fatalf("after %d deposits into a box with a subscribed collector, %d pushes arrived", index+1, len(pushes))
		}
		latest := pushes[len(pushes)-1]
		if !bytes.Equal(latest.GetRendezvousId(), box.id) || latest.GetPendingCount() != want {
			t.Fatalf("push %d named box %x with %d pending, want box %x with %d", index+1, latest.GetRendezvousId(), latest.GetPendingCount(), box.id, want)
		}
	}
	if reason := fixture.retire(t, fixture.retireOf(box)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Retire: %v", reason)
	}
	for _, push := range fixture.pusher.rendezvousPushes(2) {
		if bytes.Equal(push.GetRendezvousId(), quiet.id) {
			t.Fatal("a deposit into a box whose collector did not subscribe was pushed")
		}
	}
	subscriptions := func() int {
		return fixture.subscriptions.RendezvousSubscriptions()
	}
	if held := subscriptions(); held != 0 {
		t.Fatalf("a retired box keeps %d subscriptions", held)
	}

	// a subscription ends with its box's expiry as well: past it, the next subscription this
	// registry is told of drops it. The control is the count while the box is live
	lapsing := fixture.mustRegister(t, 0xF0)
	if reason, _ := fixture.collect(t, fixture.collectOf(lapsing, 0, 0, true)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect with subscribe: %v", reason)
	}
	if held := subscriptions(); held != 1 {
		t.Fatalf("the control: a live box with a subscribed collector holds %d subscriptions, want 1", held)
	}
	fixture.clock.advance(api.DefaultLinkBoxTtl)
	later := fixture.mustRegister(t, 0xF8)
	if reason, _ := fixture.collect(t, fixture.collectOf(later, 0, 0, true)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect with subscribe: %v", reason)
	}
	if held := subscriptions(); held != 1 {
		t.Fatalf("past one box's expiry and after a subscription to another, the registry holds %d subscriptions, want only the live box's", held)
	}
}

// ── Task 20: a box past its expiry, before the sweep and after it ───────────────────────────

// A BOX PAST ITS TTL OPENS, DEPOSITS AND COLLECTS AS AN UNKNOWN ONE WOULD, WHETHER OR NOT THE SWEEP
// HAS RUN (the identity plan's Task 20, Property 1; §4.3.11, §7.4). A box is registered, takes a
// deposit, and the clock moves to its expiry. Before the sweep its row still stands, and Open,
// Deposit, Collect and Retire, each signed by its holder, answer it exactly as they answer an id
// never registered; then Q19 runs at the same instant and reclaims it, and they answer it so again.
// Register is the one arm the sweep's timing reaches (§4.3.11): it refuses the id while the expired
// row stands, and registers a new box there once the sweep has reclaimed it. The control is the box
// while it is live, which Open answers with its card. MR10, expiry decided by the sweep alone, is
// killed by the case before the sweep.
func TestABoxPastItsTtlAnswersAsAnUnknownOneBeforeTheSweepAndAfterIt(t *testing.T) {
	ctx := context.Background()
	fixture := newLinkFixture(t, nil)
	expiring := fixture.mustRegister(t, 0x10)
	if reason, _ := fixture.deposit(t, fixture.depositOf(expiring, linkOctets(store.LinkDepositBytes, 0x11))); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a deposit into a live box answered %v", reason)
	}
	unknown := newLinkBox(0xEE)

	// THE CONTROL: live, the box is not answered as an unknown id is
	if reason, response, err := fixture.handler.RendezvousOpen(ctx, fixture.conn, fixture.open(expiring)); err != nil || reason != protocol.Reason_REASON_OK || response == nil {
		t.Fatalf("the control: Open on the live box answered %v (%v), want its card", reason, err)
	}
	fixture.pads()

	// to the microsecond of its expiry, which is past it: a box is live strictly before expire_time
	fixture.clock.advance(api.DefaultLinkBoxTtl)

	for _, stage := range []string{"before the sweep", "after the sweep"} {
		if stage == "after the sweep" {
			swept, err := fixture.boxes.SweepLinkBoxes(ctx, fixture.clock.now(), store.LinkBoxSweepBounds{})
			if err != nil || *swept != (store.LinkBoxesSwept{Deposits: 1, Boxes: 1}) {
				t.Fatalf("the sweep at the box's expiry answered %+v (%v), want its one deposit and the box", swept, err)
			}
			if _, err := fixture.boxes.LinkBox(ctx, expiring.id); !errors.Is(err, store.ErrLinkBoxUnknown) {
				t.Fatalf("after the sweep the box's row still stands: %v", err)
			}
		} else if _, err := fixture.boxes.LinkBox(ctx, expiring.id); err != nil {
			t.Fatalf("before the sweep the expired box's row must stand, or this case measures nothing: %v", err)
		}

		expired, never := fixture.signedAnswers(t, expiring), fixture.signedAnswers(t, unknown)
		if !reflect.DeepEqual(expired, never) {
			t.Fatalf("%s, a box past its expiry was answered %v, and an id never registered %v", stage, expired, never)
		}
		for arm, answer := range expired {
			if !reflect.DeepEqual(answer, oneAnswer) {
				t.Fatalf("%s, %s on a box past its expiry answered %v with a body %v, want REASON_CARD_RETIRED and none", stage, arm, answer.reason, answer.body)
			}
		}

		reason, _ := fixture.register(t, fixture.registration(expiring))
		fixture.pads()
		want := protocol.Reason_REASON_REJECTED
		if stage == "after the sweep" {
			want = protocol.Reason_REASON_OK
		}
		if reason != want {
			t.Fatalf("%s, a registration at the expired box's id answered %v, want %v: Register is the one arm the sweep's timing reaches", stage, reason, want)
		}
	}
}
