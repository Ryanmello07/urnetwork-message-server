package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/protocol"
)

// §4.3.11's kind 4 on the five arms, the identity plan's Task 19: its Properties 1 to 6, the shape
// R70's addendum gives an unserved arm, the push, and the holder gate over [store.LinkBoxes].
//
// WHAT THESE TESTS RUN WITHOUT, AND HOW. §5.1.2's check 7 is not in this build (rendezvous.go; LRI
// R70), so no arm is served in any wiring. A test here sets the handler's verifiersPinned to run
// every other check of the arms; the cases that need a signature, the unauthorized box of
// Property 2 and the collect under another key of Property 3, are subtests that say so and skip,
// and the commit that pins the library's verifiers fills them in, with MR6.

// The reject floor these tests serve on: §10.2's "25 [a] as the api tests use".
const rendezvousFloor = 25 * time.Millisecond

// A clock a test moves, so that a box can pass its expiry without a test that sleeps.
type rendezvousClock struct {
	mutex sync.Mutex
	at    time.Time
}

func (self *rendezvousClock) now() time.Time {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.at
}

func (self *rendezvousClock) advance(by time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.at = self.at.Add(by)
}

// A pusher that keeps every push, for the push's test and its control.
type recordingPusher struct {
	mutex  sync.Mutex
	pushes []*protocol.MessageServerPush
	signal chan struct{}
}

func (self *recordingPusher) Push(clientId []byte, serverNonce []byte, push *protocol.MessageServerPush) bool {
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
func (self *recordingPusher) rendezvousPushes(t *testing.T, want int) []*protocol.RendezvousPush {
	t.Helper()
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

// Everything one rendezvous test needs: a handler that serves the arms but for check 7, its store,
// a connection, its clock, the pads it slept and the pushes it sent.
type rendezvousFixture struct {
	handler *Handler
	boxes   *store.MemoryStore
	conn    *Connection
	clock   *rendezvousClock
	pusher  *recordingPusher

	// what New set verifiersPinned to, before this fixture set it
	pinnedAsBuilt bool

	mutex  sync.Mutex
	sleeps []time.Duration
}

func newRendezvousFixture(t *testing.T, configure func(*Config)) *rendezvousFixture {
	t.Helper()
	current := &rendezvousFixture{
		boxes:  store.NewMemoryStore(store.DefaultLimits()),
		conn:   &Connection{ServerNonce: nonce(0x5E), ClientId: []byte("a client id the platform authenticated")},
		clock:  &rendezvousClock{at: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)},
		pusher: &recordingPusher{signal: make(chan struct{}, 16)},
	}
	subscriptions := NewSubscriptions()
	subscriptions.SetPusher(current.pusher)
	t.Cleanup(subscriptions.Close)
	config := Config{
		Store:         current.boxes,
		KnownGroups:   NewMemoryKnownGroups(),
		Front:         ChecksNotImplemented{},
		LinkBoxes:     current.boxes,
		RejectFloor:   rendezvousFloor,
		Now:           current.clock.now,
		Sleep:         current.sleep,
		Subscriptions: subscriptions,
	}
	if configure != nil {
		configure(&config)
	}
	handler, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// every check of the arms but check 7, which lands with the library's verifiers (LRI R70)
	current.pinnedAsBuilt = handler.verifiersPinned
	handler.verifiersPinned = true
	current.handler = handler
	return current
}

func (self *rendezvousFixture) sleep(remaining time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.sleeps = append(self.sleeps, remaining)
}

// The pads slept since the last call, and the slate cleared.
func (self *rendezvousFixture) pads() []time.Duration {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	slept := self.sleeps
	self.sleeps = nil
	return slept
}

func linkBytes(length int, seed byte) []byte {
	return strideBytes(length, seed, 1)
}

func strideBytes(length int, seed byte, stride byte) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = seed + byte(index)*stride
	}
	return value
}

// A kind-4 registration whose values are distinct from every other seed's.
func linkRegister(seed byte) *protocol.RendezvousRegisterRequest {
	return &protocol.RendezvousRegisterRequest{
		RendezvousId:     linkBytes(store.RendezvousIdBytes, seed),
		DepositVerifyPub: linkBytes(store.VerifyPubBytes, seed+1),
		CollectVerifyPub: linkBytes(store.VerifyPubBytes, seed+2),
		AlgId:            store.LinkBoxAlgId,
		Kind:             store.LinkBoxKind,
		PublicCt:         linkBytes(store.LinkCardBytes, seed+3),
	}
}

func (self *rendezvousFixture) register(t *testing.T, request *protocol.RendezvousRegisterRequest) (protocol.Reason, *protocol.RendezvousRegisterResponse) {
	t.Helper()
	reason, response, err := self.handler.RendezvousRegister(context.Background(), self.conn, request)
	if err != nil {
		t.Fatalf("RendezvousRegister: %v", err)
	}
	return reason, response
}

func (self *rendezvousFixture) mustRegister(t *testing.T, seed byte) []byte {
	t.Helper()
	request := linkRegister(seed)
	if reason, _ := self.register(t, request); reason != protocol.Reason_REASON_OK {
		t.Fatalf("registering a fresh kind-4 box answered %v", reason)
	}
	self.pads()
	return request.GetRendezvousId()
}

func (self *rendezvousFixture) deposit(t *testing.T, rendezvousId []byte, depositCt []byte) (protocol.Reason, *protocol.RendezvousDepositResponse) {
	t.Helper()
	reason, response, err := self.handler.RendezvousDeposit(context.Background(), self.conn,
		&protocol.RendezvousDepositRequest{RendezvousId: rendezvousId, DepositCt: depositCt})
	if err != nil {
		t.Fatalf("RendezvousDeposit: %v", err)
	}
	return reason, response
}

// One answer from each of the four arms after Register, for a box: what it answered, the body it
// carried, and the pads it slept.
type rendezvousAnswer struct {
	reason protocol.Reason
	body   bool
	pads   []time.Duration
}

func (self *rendezvousFixture) answers(t *testing.T, rendezvousId []byte) map[string]rendezvousAnswer {
	t.Helper()
	ctx := context.Background()
	answers := map[string]rendezvousAnswer{}
	self.pads()
	{
		reason, response, err := self.handler.RendezvousOpen(ctx, self.conn, &protocol.RendezvousOpenRequest{RendezvousId: rendezvousId})
		if err != nil {
			t.Fatalf("RendezvousOpen: %v", err)
		}
		answers["Open"] = rendezvousAnswer{reason, response != nil, self.pads()}
	}
	{
		reason, response, err := self.handler.RendezvousDeposit(ctx, self.conn, &protocol.RendezvousDepositRequest{
			RendezvousId: rendezvousId, DepositCt: linkBytes(store.LinkDepositBytes, 0x77)})
		if err != nil {
			t.Fatalf("RendezvousDeposit: %v", err)
		}
		answers["Deposit"] = rendezvousAnswer{reason, response != nil, self.pads()}
	}
	{
		reason, response, err := self.handler.RendezvousCollect(ctx, self.conn, &protocol.RendezvousCollectRequest{
			RendezvousId: rendezvousId, AckThroughDepositId: 9})
		if err != nil {
			t.Fatalf("RendezvousCollect: %v", err)
		}
		answers["Collect"] = rendezvousAnswer{reason, response != nil, self.pads()}
	}
	{
		reason, response, err := self.handler.RendezvousRetire(ctx, self.conn, &protocol.RendezvousRetireRequest{RendezvousId: rendezvousId})
		if err != nil {
			t.Fatalf("RendezvousRetire: %v", err)
		}
		answers["Retire"] = rendezvousAnswer{reason, response != nil, self.pads()}
	}
	return answers
}

// ── Property 1 ───────────────────────────────────────────────────────────────────────────────

// A LINK BOX DEPOSIT IS EXACTLY ITS SIZE (Spec B §13's test 45). A deposit one octet short, one
// long, empty or doubled is refused, as an equality refuses it; so is a card one octet off 4,124.
// Each refusal is padded to the floor and leaves nothing behind. MR4, a range check, is killed here.
func TestALinkBoxDepositIsExactlyItsSize(t *testing.T) {
	fixture := newRendezvousFixture(t, nil)
	id := fixture.mustRegister(t, 0x10)

	for _, length := range []int{store.LinkDepositBytes - 1, store.LinkDepositBytes + 1, 0, 2 * store.LinkDepositBytes} {
		reason, response := fixture.deposit(t, id, linkBytes(length, 0x20))
		if reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a deposit of %d octets was answered %v with a body %v; §5.1.2 check 3 refuses every length but %d",
				length, reason, response != nil, store.LinkDepositBytes)
		}
		if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{rendezvousFloor}) {
			t.Fatalf("the refusal of a %d-octet deposit slept %v, want one pad to the floor", length, pads)
		}
	}
	if box, err := fixture.boxes.LinkBox(context.Background(), id); err != nil || box.DepositsTaken != 0 {
		t.Fatalf("after four refused deposits the box reads %+v (%v), want none taken", box, err)
	}
	reason, response := fixture.deposit(t, id, linkBytes(store.LinkDepositBytes, 0x20))
	if reason != protocol.Reason_REASON_OK || response.GetDepositId() != 1 || len(response.GetDepositHash()) != 32 {
		t.Fatalf("a deposit of exactly %d octets was answered %v and %+v, want REASON_OK, deposit 1 and its 32-octet hash",
			store.LinkDepositBytes, reason, response)
	}

	for _, length := range []int{store.LinkCardBytes - 1, store.LinkCardBytes + 1} {
		request := linkRegister(0x40)
		request.PublicCt = linkBytes(length, 0x41)
		if reason, response := fixture.register(t, request); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a card of %d octets was answered %v, want REASON_REJECTED with no body", length, reason)
		}
		if _, err := fixture.boxes.LinkBox(context.Background(), request.GetRendezvousId()); !errors.Is(err, store.ErrLinkBoxUnknown) {
			t.Fatalf("a refused registration of a %d-octet card left a row: %v", length, err)
		}
	}
}

// ── Property 2 ───────────────────────────────────────────────────────────────────────────────

// AN UNKNOWN, A RETIRED AND AN UNAUTHORIZED BOX ANSWER ALIKE (Spec B §13's test 46), on Open,
// Deposit, Collect and Retire: the same code, no body, one pad to the same floor; and a box past
// its expiry answers so too, decided by its expiry and not by the sweep. None of the four arms
// changes the expired box. MR5, an unknown id answered REASON_REJECTED, is killed here.
func TestAnUnknownARetiredAndAnUnauthorizedBoxAnswerAlike(t *testing.T) {
	fixture := newRendezvousFixture(t, nil)
	retired := fixture.mustRegister(t, 0x20)
	if reason, _, err := fixture.handler.RendezvousRetire(context.Background(), fixture.conn, &protocol.RendezvousRetireRequest{RendezvousId: retired}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("retiring a live box answered %v (%v)", reason, err)
	}
	expired := fixture.mustRegister(t, 0x30)
	if reason, _ := fixture.deposit(t, expired, linkBytes(store.LinkDepositBytes, 0x31)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a deposit into a live box answered %v", reason)
	}
	fixture.clock.advance(DefaultLinkBoxTtl)
	before, err := fixture.boxes.LinkBox(context.Background(), expired)
	if err != nil {
		t.Fatalf("LinkBox: %v", err)
	}

	want := rendezvousAnswer{reason: protocol.Reason_REASON_CARD_RETIRED, body: false, pads: []time.Duration{rendezvousFloor}}
	for name, id := range map[string][]byte{
		"an unknown id":         linkBytes(store.RendezvousIdBytes, 0xEE),
		"a retired box":         retired,
		"a box past its expiry": expired,
	} {
		for arm, answer := range fixture.answers(t, id) {
			if !reflect.DeepEqual(answer, want) {
				t.Fatalf("%s on %s was answered %v with a body %v after pads %v; §4.3.11 gives every box no arm may use one answer: %v, no body, one pad to %v",
					arm, name, answer.reason, answer.body, answer.pads, want.reason, rendezvousFloor)
			}
		}
	}
	if after, err := fixture.boxes.LinkBox(context.Background(), expired); err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("the four arms answered a box past its expiry and changed it: %+v, then %+v (%v)", before, after, err)
	}

	t.Run("AnUnauthorizedBox", func(t *testing.T) {
		t.Skip("§5.1.2 check 7 is not in this build: a signature that does not verify answers alike once the library's verifiers are pinned (LRI R70), and MR6 is killed then")
	})
}

// ── Property 3 ───────────────────────────────────────────────────────────────────────────────

// A LIVE BOX KEEPS THE KEY IT WAS REGISTERED UNDER (Spec B §13's test 47). A registration at its id
// under another collect key, another deposit key or another card is refused, as is one at a box
// past its expiry, while the same three values answer REASON_OK and change nothing, the expiry
// included. MR7, a registration that replaces the pinned key, is killed here.
func TestALiveBoxKeepsTheKeyItWasRegisteredUnder(t *testing.T) {
	fixture := newRendezvousFixture(t, nil)
	original := linkRegister(0x50)
	reason, first := fixture.register(t, original)
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("a fresh registration answered %v", reason)
	}
	id := original.GetRendezvousId()
	pinned, _ := fixture.boxes.LinkBox(context.Background(), id)
	fixture.pads()

	for name, change := range map[string]func(*protocol.RendezvousRegisterRequest){
		"another collect key": func(request *protocol.RendezvousRegisterRequest) { request.CollectVerifyPub = linkBytes(32, 0xA0) },
		"another deposit key": func(request *protocol.RendezvousRegisterRequest) { request.DepositVerifyPub = linkBytes(32, 0xA1) },
		"another card": func(request *protocol.RendezvousRegisterRequest) {
			request.PublicCt = linkBytes(store.LinkCardBytes, 0xA2)
		},
	} {
		other := linkRegister(0x50)
		change(other)
		if reason, response := fixture.register(t, other); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a registration with %s at a live box's id answered %v, want REASON_REJECTED with no body", name, reason)
		}
		if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{rendezvousFloor}) {
			t.Fatalf("the refused registration with %s slept %v, want one pad to the floor", name, pads)
		}
		if box, _ := fixture.boxes.LinkBox(context.Background(), id); !reflect.DeepEqual(box, pinned) {
			t.Fatalf("a refused registration with %s changed the box from %+v to %+v", name, pinned, box)
		}
	}

	fixture.clock.advance(time.Minute)
	reason, again := fixture.register(t, linkRegister(0x50))
	if reason != protocol.Reason_REASON_OK || again.GetExpireTimeMs() != first.GetExpireTimeMs() {
		t.Fatalf("the same registration a minute on answered %v with expiry %d, want REASON_OK and the first expiry %d: a link box is not kept alive",
			reason, again.GetExpireTimeMs(), first.GetExpireTimeMs())
	}

	fixture.clock.advance(DefaultLinkBoxTtl)
	if reason, _ := fixture.register(t, linkRegister(0x50)); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("the same registration past the box's expiry answered %v, want REASON_REJECTED", reason)
	}

	t.Run("ACollectUnderAnotherKey", func(t *testing.T) {
		t.Skip("§5.1.2 check 7 is not in this build: a collect_auth under any key but the pinned one answers REASON_CARD_RETIRED once the library's verifiers are pinned (LRI R70)")
	})
}

// ── Property 4 ───────────────────────────────────────────────────────────────────────────────

// LinkBoxes whose live count cannot be read.
type unreadableLiveCount struct {
	store.LinkBoxes
}

var errTheCountIsNotThere = errors.New("api_test: the live count did not answer")

func (self *unreadableLiveCount) LiveLinkBoxes(ctx context.Context, now time.Time) (uint64, error) {
	return 0, errTheCountIsNotThere
}

// THE LIVE BOX CAP FAILS CLOSED (Spec B §13's test 48). A registration is refused when the live
// boxes are at the cap, and when their count cannot be read; a retired or an expired box does not
// count; and Register's one rule comes before the cap, so a retry of a live box's own registration
// is answered at a full cap. MR8, an unreadable count taken as room, is killed here.
func TestTheLiveBoxCapFailsClosed(t *testing.T) {
	fixture := newRendezvousFixture(t, func(config *Config) { config.LinkBoxLiveCap = 2 })
	first := fixture.mustRegister(t, 0x60)
	fixture.mustRegister(t, 0x61)

	third := linkRegister(0x62)
	if reason, response := fixture.register(t, third); reason != protocol.Reason_REASON_CARD_RATE_LIMITED || response != nil {
		t.Fatalf("a registration at a full cap answered %v, want REASON_CARD_RATE_LIMITED with no body", reason)
	}
	if pads := fixture.pads(); !slices.Equal(pads, []time.Duration{rendezvousFloor}) {
		t.Fatalf("the refusal at a full cap slept %v, want one pad to the floor", pads)
	}
	if _, err := fixture.boxes.LinkBox(context.Background(), third.GetRendezvousId()); !errors.Is(err, store.ErrLinkBoxUnknown) {
		t.Fatalf("a registration refused at the cap left a row: %v", err)
	}
	if reason, _ := fixture.register(t, linkRegister(0x60)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a live box's own registration, repeated at a full cap, answered %v; the one rule comes before the cap", reason)
	}
	if reason, _, err := fixture.handler.RendezvousRetire(context.Background(), fixture.conn, &protocol.RendezvousRetireRequest{RendezvousId: first}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("Retire: %v (%v)", reason, err)
	}
	if reason, _ := fixture.register(t, third); reason != protocol.Reason_REASON_OK {
		t.Fatalf("with one of two boxes retired, a registration answered %v; a retired box does not count", reason)
	}

	t.Run("AnUnreadableCount", func(t *testing.T) {
		broken := newRendezvousFixture(t, func(config *Config) {
			config.LinkBoxes = &unreadableLiveCount{LinkBoxes: config.LinkBoxes}
		})
		request := linkRegister(0x70)
		if reason, response := broken.register(t, request); reason != protocol.Reason_REASON_CARD_RATE_LIMITED || response != nil {
			t.Fatalf("a registration whose live count could not be read answered %v, want REASON_CARD_RATE_LIMITED: the cap fails closed", reason)
		}
		if _, err := broken.boxes.LinkBox(context.Background(), request.GetRendezvousId()); !errors.Is(err, store.ErrLinkBoxUnknown) {
			t.Fatalf("a registration refused on an unreadable count left a row: %v", err)
		}
		// the control: the same request, on a store whose count answers
		if reason, _ := newRendezvousFixture(t, nil).register(t, linkRegister(0x70)); reason != protocol.Reason_REASON_OK {
			t.Fatalf("the control, the same registration with a count that answers, was answered %v", reason)
		}
	})
}

// ── Property 5 ───────────────────────────────────────────────────────────────────────────────

// LinkBoxes that fail every call, for the error paths of the logging gate.
type failingLinkBoxes struct{}

var errTheStoreFailed = errors.New("api_test: the link box store failed")

func (failingLinkBoxes) RegisterLinkBox(context.Context, *store.LinkBoxRegistration, time.Time, time.Duration) (*store.LinkBoxRegistered, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) LinkBox(context.Context, []byte) (*store.LinkBox, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) DepositLinkBox(context.Context, []byte, []byte, time.Time) (*store.LinkBoxDeposited, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) CollectLinkBox(context.Context, *store.LinkBoxCollectRequest, time.Time) (*store.LinkBoxCollected, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) RetireLinkBox(context.Context, []byte, time.Time) (*store.LinkBoxRetired, error) {
	return nil, errTheStoreFailed
}
func (failingLinkBoxes) LiveLinkBoxes(context.Context, time.Time) (uint64, error) {
	return 0, errTheStoreFailed
}

// NOTHING NAMES A BOX (Spec B §13's test 49; §11.1): no log line, metric label or error this
// package writes carries a rendezvous id, a deposit hash or a key. Every arm is run on its served
// path, on its refusals and on a store that fails, with planted values, while the process's slog
// default and the standard logger write into this test; then every line written, every error
// answered and every NotBuilt line is searched for each planted value raw, in lower hex and in
// upper hex. The control plants one line and must find it. This package keeps no metric with a
// label, and [Subscriptions.Stats] answers counts. MR9, a handler that logs the id, is killed here.
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

	ctx := context.Background()
	errorsAnswered := []string{}
	keep := func(err error) {
		if err != nil {
			errorsAnswered = append(errorsAnswered, err.Error())
		}
	}
	// each planted value on a stride of its own, so that no one of them is a run inside another:
	// the search must tell them apart, and the self-check below holds it to that
	planted := linkRegister(0xB0)
	planted.RendezvousId = strideBytes(store.RendezvousIdBytes, 0x13, 1)
	planted.DepositVerifyPub = strideBytes(store.VerifyPubBytes, 0x29, 3)
	planted.CollectVerifyPub = strideBytes(store.VerifyPubBytes, 0x47, 5)
	planted.PublicCt = strideBytes(store.LinkCardBytes, 0x61, 7)
	plantedCt := strideBytes(store.LinkDepositBytes, 0x83, 11)
	var plantedHash []byte

	for name, fixture := range map[string]*rendezvousFixture{
		"served":             newRendezvousFixture(t, nil),
		"a store that fails": newRendezvousFixture(t, func(config *Config) { config.LinkBoxes = failingLinkBoxes{} }),
	} {
		_, _, err := fixture.handler.RendezvousRegister(ctx, fixture.conn, planted)
		keep(err)
		_, deposited, err := fixture.handler.RendezvousDeposit(ctx, fixture.conn, &protocol.RendezvousDepositRequest{RendezvousId: planted.GetRendezvousId(), DepositCt: plantedCt})
		keep(err)
		if deposited != nil {
			plantedHash = deposited.GetDepositHash()
		}
		_, _, err = fixture.handler.RendezvousOpen(ctx, fixture.conn, &protocol.RendezvousOpenRequest{RendezvousId: planted.GetRendezvousId()})
		keep(err)
		_, _, err = fixture.handler.RendezvousCollect(ctx, fixture.conn, &protocol.RendezvousCollectRequest{RendezvousId: planted.GetRendezvousId(), Subscribe: true})
		keep(err)
		_, _, err = fixture.handler.RendezvousRetire(ctx, fixture.conn, &protocol.RendezvousRetireRequest{RendezvousId: planted.GetRendezvousId()})
		keep(err)
		// and every refusal once more on the served store, the box now retired; the failing store
		// answered every arm above with its error already
		if name == "served" {
			fixture.answers(t, planted.GetRendezvousId())
		}
		for _, line := range fixture.handler.NotBuilt() {
			errorsAnswered = append(errorsAnswered, line.String())
		}
		t.Logf("%s: the arms ran", name)
	}
	if len(plantedHash) != 32 {
		t.Fatalf("the served deposit answered no 32-octet hash, so the gate would search for nothing")
	}

	forms := func(value []byte) []string {
		return []string{string(value), fmt.Sprintf("%x", value), fmt.Sprintf("%X", value)}
	}
	values := map[string][]byte{
		"the rendezvous id":       planted.GetRendezvousId(),
		"the deposit key":         planted.GetDepositVerifyPub(),
		"the collect key":         planted.GetCollectVerifyPub(),
		"the deposit hash":        plantedHash,
		"the card's first octets": planted.GetPublicCt()[:16],
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

	// THE CONTROL, in the same capture: one planted line, which the search must find, by the
	// value it plants and by no other
	slog.Info("control", "rendezvous_id", fmt.Sprintf("%x", planted.GetRendezvousId()))
	capturedMutex.Lock()
	written = captured.String()
	capturedMutex.Unlock()
	if found := search(written); !slices.Equal(found, []string{"the rendezvous id"}) {
		t.Fatalf("the control planted the rendezvous id in one log line and the search found %v", found)
	}
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
func (self *countingLinkBoxes) RegisterLinkBox(ctx context.Context, registration *store.LinkBoxRegistration, now time.Time, ttl time.Duration) (*store.LinkBoxRegistered, error) {
	self.count()
	return self.LinkBoxes.RegisterLinkBox(ctx, registration, now, ttl)
}
func (self *countingLinkBoxes) LinkBox(ctx context.Context, rendezvousId []byte) (*store.LinkBox, error) {
	self.count()
	return self.LinkBoxes.LinkBox(ctx, rendezvousId)
}
func (self *countingLinkBoxes) DepositLinkBox(ctx context.Context, rendezvousId []byte, depositCt []byte, now time.Time) (*store.LinkBoxDeposited, error) {
	self.count()
	return self.LinkBoxes.DepositLinkBox(ctx, rendezvousId, depositCt, now)
}
func (self *countingLinkBoxes) CollectLinkBox(ctx context.Context, request *store.LinkBoxCollectRequest, now time.Time) (*store.LinkBoxCollected, error) {
	self.count()
	return self.LinkBoxes.CollectLinkBox(ctx, request, now)
}
func (self *countingLinkBoxes) RetireLinkBox(ctx context.Context, rendezvousId []byte, now time.Time) (*store.LinkBoxRetired, error) {
	self.count()
	return self.LinkBoxes.RetireLinkBox(ctx, rendezvousId, now)
}
func (self *countingLinkBoxes) LiveLinkBoxes(ctx context.Context, now time.Time) (uint64, error) {
	self.count()
	return self.LinkBoxes.LiveLinkBoxes(ctx, now)
}

// Every arm, with a well-formed request for the box at `seed`, and what each answered.
func (self *rendezvousFixture) everyArm(t *testing.T, seed byte) map[string]protocol.Reason {
	t.Helper()
	ctx := context.Background()
	register := linkRegister(seed)
	id := register.GetRendezvousId()
	answers := map[string]protocol.Reason{}
	reason, _, err := self.handler.RendezvousRegister(ctx, self.conn, register)
	answers["Register"] = reason
	keepNil(t, err)
	reason, _, err = self.handler.RendezvousOpen(ctx, self.conn, &protocol.RendezvousOpenRequest{RendezvousId: id})
	answers["Open"] = reason
	keepNil(t, err)
	reason, _, err = self.handler.RendezvousDeposit(ctx, self.conn, &protocol.RendezvousDepositRequest{RendezvousId: id, DepositCt: linkBytes(store.LinkDepositBytes, seed)})
	answers["Deposit"] = reason
	keepNil(t, err)
	reason, _, err = self.handler.RendezvousCollect(ctx, self.conn, &protocol.RendezvousCollectRequest{RendezvousId: id})
	answers["Collect"] = reason
	keepNil(t, err)
	reason, _, err = self.handler.RendezvousRetire(ctx, self.conn, &protocol.RendezvousRetireRequest{RendezvousId: id})
	answers["Retire"] = reason
	keepNil(t, err)
	return answers
}

func keepNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("an arm answered an error: %v", err)
	}
}

// ONLY KIND FOUR IS SERVED, AND NOTHING WITH A ZERO FLOOR (Spec B §13's test 51; LRI R66). A
// registration of kind 0, the proto's default and the card's, or of any kind but 4, is refused; and
// a handler whose reject floor is zero serves no kind-4 arm: every arm answers as an unserved arm,
// no call reaches the store, Capabilities 26 and 29 leave kind 4 out, and NotBuilt says why. MR11,
// the kind check dropped, and MR12, the arms served at a zero floor, are killed here.
func TestOnlyKindFourIsServedAndNothingWithAZeroFloor(t *testing.T) {
	served := newRendezvousFixture(t, nil)
	for _, kind := range []uint32{0, 1, 2, 3, 5, 255} {
		request := linkRegister(byte(0x10 + kind))
		request.Kind = kind
		if reason, response := served.register(t, request); reason != protocol.Reason_REASON_REJECTED || response != nil {
			t.Fatalf("a registration of kind %d answered %v, want REASON_REJECTED: no build of I1 serves any kind but 4", kind, reason)
		}
	}
	if reason, _ := served.register(t, linkRegister(0x90)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control, a registration of kind 4, answered %v", reason)
	}
	if kinds, sizes := served.handler.RendezvousKinds(), served.handler.RendezvousDepositSizes(); kinds != 16 || !slices.Equal(sizes, []uint32{store.LinkDepositBytes}) {
		t.Fatalf("a served handler advertises kinds %b and deposit sizes %v, want 10000 and [%d]", kinds, sizes, store.LinkDepositBytes)
	}

	counting := &countingLinkBoxes{}
	unpadded := newRendezvousFixture(t, func(config *Config) {
		counting.LinkBoxes = config.LinkBoxes
		config.LinkBoxes = counting
		config.RejectFloor = 0
	})
	if unpadded.handler.RendezvousServed() {
		t.Fatal("a handler whose reject floor is zero says it serves the rendezvous arms")
	}
	for arm, reason := range unpadded.everyArm(t, 0xA0) {
		if reason != protocol.Reason_REASON_INTERNAL {
			t.Fatalf("%s at a zero floor answered %v, want REASON_INTERNAL, as an unserved arm is answered", arm, reason)
		}
	}
	if counting.calls != 0 {
		t.Fatalf("the arms of a handler with a zero floor reached the store %d times", counting.calls)
	}
	if kinds, sizes := unpadded.handler.RendezvousKinds(), unpadded.handler.RendezvousDepositSizes(); kinds != 0 || sizes != nil {
		t.Fatalf("a handler with a zero floor advertises kinds %b and deposit sizes %v, want none", kinds, sizes)
	}
	if !slices.Contains(unpadded.handler.NotBuilt(), rendezvousWithoutFloor) {
		t.Fatalf("a handler with a zero floor does not say why it serves no kind-4 arm: %v", unpadded.handler.NotBuilt())
	}
}

// ── R70's addendum: one predicate, one unserved answer ───────────────────────────────────────

// THE ARMS ARE SERVED ON THREE THINGS, AND A HANDLER MISSING ANY ONE ANSWERS EVERY ARM AS UNSERVED.
// For each of the three, every arm answers REASON_INTERNAL with no call to the store, Capabilities 26
// and 29 leave kind 4 out, and NotBuilt names exactly what is missing. The control is the same
// request against a served handler whose store holds no box: REASON_CARD_RETIRED, after one call.
func TestARendezvousArmIsUnservedWhenAnyOfItsThreeIsMissing(t *testing.T) {
	for name, current := range map[string]struct {
		configure func(*Config, *countingLinkBoxes)
		pinned    bool // ignored when asBuilt
		asBuilt   bool // the flag as New set it, and no test's
		missing   NotBuilt
	}{
		"no link box store": {
			configure: func(config *Config, counting *countingLinkBoxes) { config.LinkBoxes = nil },
			pinned:    true,
			missing:   rendezvousWithoutLinkBoxes,
		},
		"no verifiers, as in every wiring of this build": {
			configure: func(config *Config, counting *countingLinkBoxes) {
				counting.LinkBoxes = config.LinkBoxes
				config.LinkBoxes = counting
			},
			asBuilt: true,
			missing: rendezvousWithoutVerifiers,
		},
		"a zero reject floor": {
			configure: func(config *Config, counting *countingLinkBoxes) {
				counting.LinkBoxes = config.LinkBoxes
				config.LinkBoxes = counting
				config.RejectFloor = 0
			},
			pinned:  true,
			missing: rendezvousWithoutFloor,
		},
	} {
		t.Run(name, func(t *testing.T) {
			counting := &countingLinkBoxes{}
			fixture := newRendezvousFixture(t, func(config *Config) { current.configure(config, counting) })
			fixture.handler.verifiersPinned = current.pinned
			if current.asBuilt {
				fixture.handler.verifiersPinned = fixture.pinnedAsBuilt
			}
			for arm, reason := range fixture.everyArm(t, 0xC0) {
				if reason != protocol.Reason_REASON_INTERNAL {
					t.Fatalf("%s with %s answered %v, want REASON_INTERNAL", arm, name, reason)
				}
			}
			if counting.calls != 0 {
				t.Fatalf("with %s the arms reached the store %d times", name, counting.calls)
			}
			if fixture.handler.RendezvousServed() || fixture.handler.RendezvousKinds() != 0 || fixture.handler.RendezvousDepositSizes() != nil {
				t.Fatalf("with %s the handler says it serves kind 4", name)
			}
			if missing := fixture.handler.unservedRendezvous(); !slices.Equal(missing, []NotBuilt{current.missing}) {
				t.Fatalf("with %s NotBuilt names %v, want exactly %v", name, missing, current.missing)
			}
			if !slices.Contains(fixture.handler.NotBuilt(), current.missing) {
				t.Fatalf("with %s the readiness list does not carry %v", name, current.missing)
			}
		})
	}

	t.Run("TheControlAServedHandlerWithAnEmptyStore", func(t *testing.T) {
		counting := &countingLinkBoxes{}
		fixture := newRendezvousFixture(t, func(config *Config) {
			counting.LinkBoxes = config.LinkBoxes
			config.LinkBoxes = counting
		})
		reason, response, err := fixture.handler.RendezvousOpen(context.Background(), fixture.conn,
			&protocol.RendezvousOpenRequest{RendezvousId: linkRegister(0xC0).GetRendezvousId()})
		if err != nil || reason != protocol.Reason_REASON_CARD_RETIRED || response != nil || counting.calls != 1 {
			t.Fatalf("Open on a served handler with an empty store answered %v (%v), a body %v, after %d store calls; want REASON_CARD_RETIRED, none, after one",
				reason, err, response != nil, counting.calls)
		}
	})
}

// ── the push ─────────────────────────────────────────────────────────────────────────────────

// A DEPOSIT IS PUSHED TO A COLLECTOR THAT SUBSCRIBED (§4.3.11), with the box's id and the count
// waiting and nothing else; a retire ends the subscription. The control is a collect that did not
// subscribe, after which a deposit pushes nothing.
func TestADepositIsPushedToACollectorThatSubscribed(t *testing.T) {
	ctx := context.Background()
	fixture := newRendezvousFixture(t, nil)
	quiet := fixture.mustRegister(t, 0xD0)
	if reason, _, err := fixture.handler.RendezvousCollect(ctx, fixture.conn, &protocol.RendezvousCollectRequest{RendezvousId: quiet}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect: %v (%v)", reason, err)
	}
	if reason, _ := fixture.deposit(t, quiet, linkBytes(store.LinkDepositBytes, 0xD1)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("Deposit: %v", reason)
	}

	id := fixture.mustRegister(t, 0xE0)
	if reason, _, err := fixture.handler.RendezvousCollect(ctx, fixture.conn, &protocol.RendezvousCollectRequest{RendezvousId: id, Subscribe: true}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect with subscribe: %v (%v)", reason, err)
	}
	for index, want := range []uint32{1, 2} {
		if reason, _ := fixture.deposit(t, id, linkBytes(store.LinkDepositBytes, byte(0xE1+index))); reason != protocol.Reason_REASON_OK {
			t.Fatalf("Deposit %d: %v", index+1, reason)
		}
		pushes := fixture.pusher.rendezvousPushes(t, index+1)
		if len(pushes) != index+1 {
			t.Fatalf("after %d deposits into a box with a subscribed collector, %d pushes arrived", index+1, len(pushes))
		}
		latest := pushes[len(pushes)-1]
		if !bytes.Equal(latest.GetRendezvousId(), id) || latest.GetPendingCount() != want {
			t.Fatalf("push %d named box %x with %d pending, want box %x with %d", index+1, latest.GetRendezvousId(), latest.GetPendingCount(), id, want)
		}
	}
	if reason, _, err := fixture.handler.RendezvousRetire(ctx, fixture.conn, &protocol.RendezvousRetireRequest{RendezvousId: id}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("Retire: %v (%v)", reason, err)
	}
	if held := fixture.handler.subscriptions.RendezvousSubscriptions(); held != 0 {
		t.Fatalf("a retired box keeps %d subscriptions", held)
	}
	for _, push := range fixture.pusher.rendezvousPushes(t, 2) {
		if bytes.Equal(push.GetRendezvousId(), quiet) {
			t.Fatal("a deposit into a box whose collector did not subscribe was pushed")
		}
	}

	// A subscription ends with its box's expiry as well: past it, the next subscription this
	// registry is told of drops it. The control is the count while the box is live.
	lapsing := fixture.mustRegister(t, 0xF0)
	if reason, _, err := fixture.handler.RendezvousCollect(ctx, fixture.conn, &protocol.RendezvousCollectRequest{RendezvousId: lapsing, Subscribe: true}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect with subscribe: %v (%v)", reason, err)
	}
	if held := fixture.handler.subscriptions.RendezvousSubscriptions(); held != 1 {
		t.Fatalf("the control: a live box with a subscribed collector holds %d subscriptions, want 1", held)
	}
	fixture.clock.advance(DefaultLinkBoxTtl)
	later := fixture.mustRegister(t, 0xF8)
	if reason, _, err := fixture.handler.RendezvousCollect(ctx, fixture.conn, &protocol.RendezvousCollectRequest{RendezvousId: later, Subscribe: true}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("Collect with subscribe: %v (%v)", reason, err)
	}
	fixture.handler.subscriptions.mutex.Lock()
	held := []string{}
	for key := range fixture.handler.subscriptions.rendezvous {
		held = append(held, fmt.Sprintf("%x", key.box))
	}
	fixture.handler.subscriptions.mutex.Unlock()
	if !slices.Equal(held, []string{fmt.Sprintf("%x", later)}) {
		t.Fatalf("past one box's expiry and after a subscription to another, the registry holds %v, want only the live box %x", held, later)
	}
}

// ── the holder gate, LinkBoxes as Store is held ──────────────────────────────────────────────

// The [store.LinkBoxes] methods that change a row, and the ones that do not. Written down with its
// reason, as storeMethodMutates is; what is derived is its completeness.
var linkBoxMethodMutates = map[string]bool{
	"RegisterLinkBox": true,  // §4.3.11's Register
	"DepositLinkBox":  true,  // Deposit
	"CollectLinkBox":  true,  // Collect deletes through its acknowledgement
	"RetireLinkBox":   true,  // Retire
	"LinkBox":         false, // Q17
	"LiveLinkBoxes":   false, // Q20
}

// The arm each write belongs to.
var linkBoxWriteArm = map[string]string{
	"RegisterLinkBox": "RendezvousRegister",
	"DepositLinkBox":  "RendezvousDeposit",
	"CollectLinkBox":  "RendezvousCollect",
	"RetireLinkBox":   "RendezvousRetire",
}

// EVERY LINK BOX WRITE THIS PACKAGE CAN MAKE IS MADE BY ITS OWN ARM, held as
// TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate holds [store.Store]. Both halves
// are derived: the holders are every struct field of type store.LinkBoxes, and the method set comes
// off the interface by reflection, so a method added to it fails here unclassified. A write is
// permitted in the one arm that owns it and nowhere else, and the methods this package never calls
// are printed. When check 7 lands, the gate the commit adds is that each of these calls follows it.
func TestEveryLinkBoxWriteThisPackageCanMakeIsMadeByItsOwnArm(t *testing.T) {
	interfaceType := reflect.TypeOf((*store.LinkBoxes)(nil)).Elem()
	declared := []string{}
	for index := range interfaceType.NumMethod() {
		name := interfaceType.Method(index).Name
		declared = append(declared, name)
		if _, classified := linkBoxMethodMutates[name]; !classified {
			t.Fatalf("store.LinkBoxes declares %s and linkBoxMethodMutates does not say whether it writes", name)
		}
	}
	for name := range linkBoxMethodMutates {
		if !slices.Contains(declared, name) {
			t.Fatalf("linkBoxMethodMutates classifies %s and store.LinkBoxes no longer declares it", name)
		}
	}

	files := token.NewFileSet()
	parsed, err := parser.ParseDir(files, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing this package: %v", err)
	}
	pkg, found := parsed["api"]
	if !found {
		t.Fatalf("this package did not parse as api")
	}
	holders := map[string]bool{}
	for _, file := range pkg.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok {
				return true
			}
			selector, ok := field.Type.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "LinkBoxes" {
				return true
			}
			if pkgName, ok := selector.X.(*ast.Ident); !ok || pkgName.Name != "store" {
				return true
			}
			for _, name := range field.Names {
				holders[name.Name] = true
			}
			return true
		})
	}
	if len(holders) == 0 {
		t.Fatal("no field of type store.LinkBoxes was found in this package, so the walk below inspects nothing")
	}

	// THE TWO HOLDER TESTS PARTITION THE STORE'S HOLDERS. Every struct field in this package whose
	// type comes from package store is a store.Store, held by
	// TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate, or a store.LinkBoxes, held
	// here; a field of any other type from store is held by neither, and fails by name until it is
	// classified. The fields found, by type, are printed.
	heldBy := map[string]string{
		"Store":     "TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate",
		"LinkBoxes": "TestEveryLinkBoxWriteThisPackageCanMakeIsMadeByItsOwnArm",
	}
	storeFields := map[string][]string{}
	for _, file := range pkg.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			structType, ok := node.(*ast.StructType)
			if !ok {
				return true
			}
			for _, field := range structType.Fields.List {
				fieldType := field.Type
				if star, ok := fieldType.(*ast.StarExpr); ok {
					fieldType = star.X
				}
				selector, ok := fieldType.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				if pkgName, ok := selector.X.(*ast.Ident); !ok || pkgName.Name != "store" {
					continue
				}
				for _, name := range field.Names {
					storeFields[selector.Sel.Name] = append(storeFields[selector.Sel.Name], name.Name)
				}
			}
			return true
		})
	}
	t.Logf("struct fields of a type from package store, by type: %v", storeFields)
	for typeName, fields := range storeFields {
		if _, held := heldBy[typeName]; !held {
			t.Fatalf("this package holds a store.%s in %v, and neither holder test holds that type", typeName, fields)
		}
	}
	for typeName, test := range heldBy {
		if len(storeFields[typeName]) == 0 {
			t.Fatalf("%s holds store.%s, and no struct field in this package is one", test, typeName)
		}
	}

	calls := map[string][]string{}
	for _, file := range pkg.Files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				receiver, ok := method.X.(*ast.SelectorExpr)
				if !ok || !holders[receiver.Sel.Name] {
					return true
				}
				calls[method.Sel.Name] = append(calls[method.Sel.Name], function.Name.Name)
				return true
			})
		}
	}

	unused := []string{}
	for _, name := range declared {
		callers := calls[name]
		if len(callers) == 0 {
			unused = append(unused, name)
			continue
		}
		if !linkBoxMethodMutates[name] {
			continue
		}
		for _, caller := range callers {
			if caller != linkBoxWriteArm[name] {
				t.Fatalf("store.LinkBoxes.%s is called from %s, and a link box write belongs to %s alone", name, caller, linkBoxWriteArm[name])
			}
		}
	}
	t.Logf("store.LinkBoxes holders in this package: %v", keysOf(holders))
	t.Logf("calls, by method: %v", calls)
	t.Logf("methods this package never calls: %v", unused)
	if len(unused) != 0 {
		t.Fatalf("store.LinkBoxes declares %v and this package never calls them", unused)
	}
}

// ── Task 20: a box past its expiry, before the sweep and after it ───────────────────────────

// A BOX PAST ITS TTL OPENS, DEPOSITS AND COLLECTS AS AN UNKNOWN ONE WOULD, WHETHER OR NOT THE SWEEP
// HAS RUN (the identity plan's Task 20, Property 1; §4.3.11, §7.4). A box is registered, takes a
// deposit, and the clock moves to its expiry. Before the sweep its row still stands, and Open,
// Deposit, Collect and Retire answer it exactly as they answer an id never registered; then Q19
// runs at the same instant and reclaims it, and they answer it so again. Register is the one arm the
// sweep's timing reaches (§4.3.11): it refuses the id while the expired row stands, and registers a
// new box there once the sweep has reclaimed it. The control is the box while it is live, which
// Open answers with its card. MR10, expiry decided by the sweep alone, is killed by the case before
// the sweep.
func TestABoxPastItsTtlAnswersAsAnUnknownOneBeforeTheSweepAndAfterIt(t *testing.T) {
	ctx := context.Background()
	fixture := newRendezvousFixture(t, nil)
	expiring := fixture.mustRegister(t, 0x10)
	if reason, _ := fixture.deposit(t, expiring, linkBytes(store.LinkDepositBytes, 0x11)); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a deposit into a live box answered %v", reason)
	}
	unknown := linkBytes(store.RendezvousIdBytes, 0xEE)

	// THE CONTROL: live, the box is not answered as an unknown id is
	if reason, response, err := fixture.handler.RendezvousOpen(ctx, fixture.conn, &protocol.RendezvousOpenRequest{RendezvousId: expiring}); err != nil || reason != protocol.Reason_REASON_OK || response == nil {
		t.Fatalf("the control: Open on the live box answered %v (%v), want its card", reason, err)
	}
	fixture.pads()

	// to the microsecond of its expiry, which is past it: a box is live strictly before expire_time
	fixture.clock.advance(DefaultLinkBoxTtl)

	for _, stage := range []string{"before the sweep", "after the sweep"} {
		if stage == "after the sweep" {
			swept, err := fixture.boxes.SweepLinkBoxes(ctx, fixture.clock.now(), store.LinkBoxSweepBounds{})
			if err != nil || *swept != (store.LinkBoxesSwept{Deposits: 1, Boxes: 1}) {
				t.Fatalf("the sweep at the box's expiry answered %+v (%v), want its one deposit and the box", swept, err)
			}
			if _, err := fixture.boxes.LinkBox(ctx, expiring); !errors.Is(err, store.ErrLinkBoxUnknown) {
				t.Fatalf("after the sweep the box's row still stands: %v", err)
			}
		} else if _, err := fixture.boxes.LinkBox(ctx, expiring); err != nil {
			t.Fatalf("before the sweep the expired box's row must stand, or this case measures nothing: %v", err)
		}

		expired, never := fixture.answers(t, expiring), fixture.answers(t, unknown)
		if !reflect.DeepEqual(expired, never) {
			t.Fatalf("%s, a box past its expiry was answered %v, and an id never registered %v", stage, expired, never)
		}
		for arm, answer := range expired {
			if answer.reason != protocol.Reason_REASON_CARD_RETIRED || answer.body {
				t.Fatalf("%s, %s on a box past its expiry answered %v with a body %v, want REASON_CARD_RETIRED and none", stage, arm, answer.reason, answer.body)
			}
		}

		reason, _ := fixture.register(t, linkRegister(0x10))
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
