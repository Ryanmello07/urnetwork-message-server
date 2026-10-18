package api

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/protocol"
)

// §4.3.11's kind 4 on the five arms, the identity plan's Task 19: what this package can test of it
// without a signature.
//
// WHERE THE REST IS. Every behaviour past §5.1.2's check 7 needs a request its holder signed, and
// this package's tests cannot sign: Spec A §12.1's A-1 surface gives api the five verifiers and no
// signer, and TestNothingThisPackageCanReachHoldsASecondImplementation holds this package's tests to
// that surface as it holds its code. The arms' properties, signed and unsigned, are therefore
// cmd/message-server's linkbox_test.go, where every package of the module may be reached. What stays
// here is what needs no signature: the predicate the arms are served on (R70's addendum), check 3's
// shape, and the gates over this package's own source, which hold every write to its arm and behind
// its arm's verifier.

// The reject floor these tests serve on: §10.2's "25 [a] as the api tests use".
const rendezvousFloor = 25 * time.Millisecond

// Everything one test here needs: a handler, its store and a connection.
type rendezvousFixture struct {
	handler *Handler
	boxes   *store.MemoryStore
	conn    *Connection

	mutex  sync.Mutex
	sleeps []time.Duration
}

func newRendezvousFixture(t *testing.T, configure func(*Config)) *rendezvousFixture {
	t.Helper()
	current := &rendezvousFixture{
		boxes: store.NewMemoryStore(store.DefaultLimits()),
		conn:  &Connection{ServerNonce: nonce(0x5E), ClientId: []byte("a client id the platform authenticated")},
	}
	config := Config{
		Store:       current.boxes,
		KnownGroups: NewMemoryKnownGroups(),
		Front:       ChecksNotImplemented{},
		LinkBoxes:   current.boxes,
		RejectFloor: rendezvousFloor,
		Sleep:       current.sleep,
	}
	if configure != nil {
		configure(&config)
	}
	handler, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	current.handler = handler
	return current
}

func (self *rendezvousFixture) sleep(remaining time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.sleeps = append(self.sleeps, remaining)
}

func linkBytes(length int, seed byte) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}

// A kind-4 registration in check 3's shape, unsigned.
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

// ── check 3 ──────────────────────────────────────────────────────────────────────────────────

// CHECK 3 HOLDS A REGISTRATION TO KIND 4's SHAPE (§5.1.2; §4.3.11): the kind is 4, the card's X-Wing
// key is absent, the alg_id is 0x0014 compared as the u32 the request carries, every length is an
// equality, and neither key is of small order. Each case changes one field of a registration in
// that shape, and the control is the shape itself. MR11, the kind check dropped, is killed here:
// the library's register verifier refuses every kind but 4 as well, so the arms' own test cannot
// see the server's check go. So is a check that truncates the alg_id to the preimage's u16 rather
// than refusing it above 0xFFFF, and so is Register's small-order call dropped.
func TestCheck3HoldsARegistrationToKindFoursShape(t *testing.T) {
	if !linkBoxRegistrationShaped(linkRegister(0x10)) {
		t.Fatal("the control, a registration in kind 4's shape, is refused by check 3")
	}
	for name, change := range map[string]func(*protocol.RendezvousRegisterRequest){
		"kind 0, the card's":              func(request *protocol.RendezvousRegisterRequest) { request.Kind = 0 },
		"kind 1":                          func(request *protocol.RendezvousRegisterRequest) { request.Kind = 1 },
		"kind 2":                          func(request *protocol.RendezvousRegisterRequest) { request.Kind = 2 },
		"kind 3":                          func(request *protocol.RendezvousRegisterRequest) { request.Kind = 3 },
		"kind 5":                          func(request *protocol.RendezvousRegisterRequest) { request.Kind = 5 },
		"a card X-Wing key":               func(request *protocol.RendezvousRegisterRequest) { request.CardXwingPub = linkBytes(1216, 0x70) },
		"alg_id 0x0013":                   func(request *protocol.RendezvousRegisterRequest) { request.AlgId = 0x0013 },
		"alg_id 0x10014, 0x0014 as a u16": func(request *protocol.RendezvousRegisterRequest) { request.AlgId = 0x00010014 },
		"alg_id 0xFFFF0014":               func(request *protocol.RendezvousRegisterRequest) { request.AlgId = 0xFFFF0014 },
		"an id of 31 octets":              func(request *protocol.RendezvousRegisterRequest) { request.RendezvousId = linkBytes(31, 0x71) },
		"an id of 33 octets":              func(request *protocol.RendezvousRegisterRequest) { request.RendezvousId = linkBytes(33, 0x71) },
		"a deposit key of 31 octets":      func(request *protocol.RendezvousRegisterRequest) { request.DepositVerifyPub = linkBytes(31, 0x72) },
		"a collect key of 33 octets":      func(request *protocol.RendezvousRegisterRequest) { request.CollectVerifyPub = linkBytes(33, 0x73) },
		"a card of 4,123 octets":          func(request *protocol.RendezvousRegisterRequest) { request.PublicCt = linkBytes(4123, 0x74) },
		"a card of 4,125 octets":          func(request *protocol.RendezvousRegisterRequest) { request.PublicCt = linkBytes(4125, 0x74) },
	} {
		request := linkRegister(0x10)
		change(request)
		if linkBoxRegistrationShaped(request) {
			t.Fatalf("check 3 takes a registration with %s", name)
		}
	}

	// THE KEYS: a deposit key or a collect key of small order is refused by the library's rule
	// (LRI R72, R73), whose list is the library's own and held to the curve there. Three of the
	// seven encodings, the identity among them, and one with its sign bit set, which the rule
	// clears before it compares
	smallOrder := map[string][]byte{
		"y = 0":                      make([]byte, 32),
		"the identity, y = 1":        append([]byte{0x01}, make([]byte, 31)...),
		"y = p - 1":                  append(append([]byte{0xec}, bytesOf(30, 0xff)...), 0x7f),
		"the identity, sign bit set": append(append([]byte{0x01}, make([]byte, 30)...), 0x80),
	}
	for name, key := range smallOrder {
		for field, change := range map[string]func(*protocol.RendezvousRegisterRequest){
			"deposit key": func(request *protocol.RendezvousRegisterRequest) { request.DepositVerifyPub = key },
			"collect key": func(request *protocol.RendezvousRegisterRequest) { request.CollectVerifyPub = key },
		} {
			request := linkRegister(0x10)
			change(request)
			if linkBoxRegistrationShaped(request) {
				t.Fatalf("check 3 takes a registration whose %s is the small-order encoding of %s", field, name)
			}
		}
	}
}

func bytesOf(length int, value byte) []byte {
	octets := make([]byte, length)
	for index := range octets {
		octets[index] = value
	}
	return octets
}

// ── R70's addendum: one predicate, one unserved answer ───────────────────────────────────────

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

// Every arm, with a well-formed and unsigned request for the box at `seed`, and what each answered.
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

// THE ARMS ARE SERVED ON TWO THINGS, AND A HANDLER MISSING EITHER ANSWERS EVERY ARM AS UNSERVED (R70's
// addendum; the library's verifiers are pinned since Task 7b). For each, every arm answers
// REASON_INTERNAL with no call to the store, Capabilities 26 and 29 leave kind 4 out, and NotBuilt
// names exactly what is missing. The control is the same request against a served handler whose
// store holds no box: REASON_CARD_RETIRED, after one call, at check 6. MR12, the arms served at a
// zero floor, is killed here.
func TestARendezvousArmIsUnservedWhenEitherOfItsTwoIsMissing(t *testing.T) {
	for name, current := range map[string]struct {
		configure func(*Config, *countingLinkBoxes)
		missing   NotBuilt
	}{
		"no link box store": {
			configure: func(config *Config, counting *countingLinkBoxes) { config.LinkBoxes = nil },
			missing:   rendezvousWithoutLinkBoxes,
		},
		"a zero reject floor": {
			configure: func(config *Config, counting *countingLinkBoxes) {
				counting.LinkBoxes = config.LinkBoxes
				config.LinkBoxes = counting
				config.RejectFloor = 0
			},
			missing: rendezvousWithoutFloor,
		},
	} {
		t.Run(name, func(t *testing.T) {
			counting := &countingLinkBoxes{}
			fixture := newRendezvousFixture(t, func(config *Config) { current.configure(config, counting) })
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
		if !fixture.handler.RendezvousServed() || fixture.handler.RendezvousKinds() != 16 {
			t.Fatal("a handler with a link box store and a floor does not serve kind 4")
		}
		reason, response, err := fixture.handler.RendezvousOpen(context.Background(), fixture.conn,
			&protocol.RendezvousOpenRequest{RendezvousId: linkRegister(0xC0).GetRendezvousId()})
		if err != nil || reason != protocol.Reason_REASON_CARD_RETIRED || response != nil || counting.calls != 1 {
			t.Fatalf("Open on a served handler with an empty store answered %v (%v), a body %v, after %d store calls; want REASON_CARD_RETIRED, none, after one",
				reason, err, response != nil, counting.calls)
		}
	})
}

// THE LINK BOX'S SIZES ARE THE LIBRARY'S (Spec A §5.14, frozen by ledger item 300): the card and the
// deposit lengths 013 and 014 CHECK, and check 3 asserts as equalities, are the ones the library
// publishes, so that the two cannot drift apart a byte at a time.
func TestTheLinkBoxSizesAreTheLibrarys(t *testing.T) {
	if store.LinkCardBytes != message.LinkCardBytes() || store.LinkDepositBytes != message.LinkDepositBytes() {
		t.Fatalf("the store holds a card to %d octets and a deposit to %d, and the library publishes %d and %d",
			store.LinkCardBytes, store.LinkDepositBytes, message.LinkCardBytes(), message.LinkDepositBytes())
	}
}
