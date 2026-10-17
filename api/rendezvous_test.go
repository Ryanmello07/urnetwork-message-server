package api

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"slices"
	"strings"
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

// ── the gates over this package's source ─────────────────────────────────────────────────────

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

// The package's own source, without its tests.
func parseThisPackage(t *testing.T) (*token.FileSet, *ast.Package) {
	t.Helper()
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
	return files, pkg
}

// Every struct field and parameter of type store.LinkBoxes in this package, by name.
func linkBoxHolders(t *testing.T, pkg *ast.Package) map[string]bool {
	t.Helper()
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
		t.Fatal("no field of type store.LinkBoxes was found in this package, so the walk inspects nothing")
	}
	return holders
}

// EVERY LINK BOX WRITE THIS PACKAGE CAN MAKE IS MADE BY ITS OWN ARM, held as
// TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate holds [store.Store]. Both halves
// are derived: the holders are every struct field of type store.LinkBoxes, and the method set comes
// off the interface by reflection, so a method added to it fails here unclassified. A write is
// permitted in the one arm that owns it and nowhere else, and the methods this package never calls
// are printed. TestEveryRendezvousArmVerifiesThroughTheLibraryBeforeItWrites holds each of these
// writes behind its arm's verifier.
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

	_, pkg := parseThisPackage(t)
	holders := linkBoxHolders(t, pkg)

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

// THE LIBRARY'S RENDEZVOUS SURFACE, AND WHAT OF IT THIS PACKAGE MAY CALL: an allowlist, one row per
// exported function of the record layer's rendezvous file, with its reason. The rows are held to
// that file in both directions, so a function the library adds fails here until it has a row, and
// a row the library dropped fails as stale. A row with no callers is one no function here may call.
var rendezvousSurface = map[string]struct {
	callers []string
	why     string
}{
	"VerifyRendezvousRegister": {[]string{"RendezvousRegister"}, "§5.1.2 check 7 on Register: register_auth under the collect key the request carries"},
	"VerifyRendezvousOpen":     {[]string{"RendezvousOpen"}, "check 7 on Open: open_auth under the pinned deposit key"},
	"VerifyRendezvousDeposit":  {[]string{"RendezvousDeposit"}, "check 7 on Deposit: deposit_auth under the pinned deposit key, over H(deposit_ct)"},
	"VerifyRendezvousCollect":  {[]string{"RendezvousCollect"}, "check 7 on Collect: collect_auth under the pinned collect key"},
	"VerifyRendezvousRetire":   {[]string{"RendezvousRetire"}, "check 7 on Retire: retire_auth under the pinned collect key"},
	"RendezvousKeyIsAcceptable": {[]string{"linkBoxRegistrationShaped"},
		"Register's check 3: the library's small-order rule, which every verifier applies first, so that no box is stored under a key nobody could use (LRI R72, R73); a new export beyond A-1's block"},
	"RendezvousRegisterPreimage": {nil, "the client's half, signed over; it panics on what it refuses, and the server builds no preimage"},
	"RendezvousOpenPreimage":     {nil, "the client's half"},
	"RendezvousDepositPreimage":  {nil, "the client's half"},
	"RendezvousCollectPreimage":  {nil, "the client's half"},
	"RendezvousRetirePreimage":   {nil, "the client's half"},
	"RendezvousId":               {nil, "the link code's derivation; the server holds no code and is handed the id"},
	"DepositVerifyKey":           {nil, "the link code's derivation; the server is handed the key at registration"},
	"LinkCardBytes":              {nil, "held equal to store.LinkCardBytes by TestTheLinkBoxSizesAreTheLibrarys"},
	"LinkDepositBytes":           {nil, "held equal to store.LinkDepositBytes by TestTheLinkBoxSizesAreTheLibrarys"},
}

// Each arm, and the one verifier of the library's it answers to.
var rendezvousArmVerifier = map[string]string{
	"RendezvousRegister": "VerifyRendezvousRegister",
	"RendezvousOpen":     "VerifyRendezvousOpen",
	"RendezvousDeposit":  "VerifyRendezvousDeposit",
	"RendezvousCollect":  "VerifyRendezvousCollect",
	"RendezvousRetire":   "VerifyRendezvousRetire",
}

// The exported functions of the record layer's rendezvous file: the file that declares the
// register verifier, read out of the library rather than named here.
func recordLayerRendezvousSurface(t *testing.T) map[string]bool {
	t.Helper()
	fileSet, libraryFiles := parseGoDir(t, recordLayerDir(t), false)
	surface := map[string]bool{}
	for _, file := range libraryFiles {
		declared, ours := []string{}, false
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !function.Name.IsExported() {
				continue
			}
			declared = append(declared, function.Name.Name)
			if function.Name.Name == "VerifyRendezvousRegister" {
				ours = true
			}
		}
		if ours {
			if len(surface) != 0 {
				t.Fatalf("two files of the record layer declare VerifyRendezvousRegister; the second is %s", fileSet.File(file.Pos()).Name())
			}
			for _, name := range declared {
				surface[name] = true
			}
		}
	}
	if len(surface) == 0 {
		t.Fatal("no file of the record layer declares VerifyRendezvousRegister, so this gate read no rendezvous surface")
	}
	return surface
}

// EVERY RENDEZVOUS ARM VERIFIES ITS SIGNATURE THROUGH THE LIBRARY BEFORE IT WRITES (§5.1.2: "no
// transaction is opened and no row is allocated before check 7 has passed"; Spec A §12.1's A-1),
// and nothing here calls the library's rendezvous surface outside the allowlist above. Each arm
// calls its own verifier once and no other's, as the whole condition of an if that returns on its
// false answer, and every link box write in it stands after that call in the source. Every call
// into the surface is made by a function its row names, and the calls found, by caller, are
// printed. MR6, Open without open_auth, fails here as well as in the arms' own test, whether its
// call is removed or kept and made to decide nothing, and so does Register's small-order call
// dropped.
func TestEveryRendezvousArmVerifiesThroughTheLibraryBeforeItWrites(t *testing.T) {
	surface := recordLayerRendezvousSurface(t)
	for name := range surface {
		if _, listed := rendezvousSurface[name]; !listed {
			t.Fatalf("the record layer's rendezvous file exports %s, and rendezvousSurface has no row saying whether this package may call it", name)
		}
	}
	for name := range rendezvousSurface {
		if !surface[name] {
			t.Fatalf("rendezvousSurface has a row for %s, and the record layer's rendezvous file no longer exports it", name)
		}
	}
	for arm, verifier := range rendezvousArmVerifier {
		if row := rendezvousSurface[verifier]; !slices.Equal(row.callers, []string{arm}) {
			t.Fatalf("%s answers to %s, and that verifier's row names %v", arm, verifier, row.callers)
		}
	}

	recordLayer := recordLayerImportPath(t)
	files, pkg := parseThisPackage(t)
	holders := linkBoxHolders(t, pkg)
	type call struct {
		name string
		at   token.Pos
	}
	reached, writes, decides := map[string][]call{}, map[string][]call{}, map[string][]token.Pos{}
	for _, file := range pkg.Files {
		names := localNames(file, recordLayer)
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				// a verifier that decides: the whole condition of an if is its negation, and the if
				// returns, so that a false answer ends the arm. A call that a condition merely
				// contains, `false && !…` among them, decides nothing
				if statement, ok := node.(*ast.IfStmt); ok {
					negation, ok := statement.Cond.(*ast.UnaryExpr)
					if !ok || negation.Op != token.NOT {
						return true
					}
					expression, ok := negation.X.(*ast.CallExpr)
					if !ok || len(statement.Body.List) == 0 {
						return true
					}
					if _, returns := statement.Body.List[len(statement.Body.List)-1].(*ast.ReturnStmt); returns {
						decides[function.Name.Name] = append(decides[function.Name.Name], expression.Pos())
					}
					return true
				}
				expression, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := expression.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch receiver := selector.X.(type) {
				case *ast.Ident:
					if names[receiver.Name] && surface[selector.Sel.Name] {
						reached[function.Name.Name] = append(reached[function.Name.Name], call{selector.Sel.Name, expression.Pos()})
					}
				case *ast.SelectorExpr:
					if holders[receiver.Sel.Name] && linkBoxMethodMutates[selector.Sel.Name] {
						writes[function.Name.Name] = append(writes[function.Name.Name], call{selector.Sel.Name, expression.Pos()})
					}
				}
				return true
			})
		}
	}
	t.Logf("calls into the library's rendezvous surface, by caller: %v", reached)

	called := map[string]bool{}
	for caller, calls := range reached {
		for _, current := range calls {
			called[current.name] = true
			if !slices.Contains(rendezvousSurface[current.name].callers, caller) {
				t.Fatalf("%s calls the library's %s at %s, and its row allows %v: %s",
					caller, current.name, files.Position(current.at), rendezvousSurface[current.name].callers, rendezvousSurface[current.name].why)
			}
		}
	}
	for name, row := range rendezvousSurface {
		if len(row.callers) != 0 && !called[name] {
			t.Fatalf("%s's row names %v as its callers, and nothing here calls it: %s", name, row.callers, row.why)
		}
	}
	for arm, verifier := range rendezvousArmVerifier {
		verified := []call{}
		for _, current := range reached[arm] {
			if strings.HasPrefix(current.name, "VerifyRendezvous") {
				verified = append(verified, current)
			}
		}
		if len(verified) != 1 || verified[0].name != verifier {
			t.Fatalf("%s calls the rendezvous verifiers %v, want %s once and no other", arm, verified, verifier)
		}
		if !slices.Contains(decides[arm], verified[0].at) {
			t.Fatalf("%s calls %s at %s, and not as the whole condition of an if that returns on its false answer: a call that decides nothing is no check 7",
				arm, verifier, files.Position(verified[0].at))
		}
		for _, write := range writes[arm] {
			if write.at < verified[0].at {
				t.Fatalf("%s calls %s at %s, before its verifier %s at %s: a row written before check 7 has passed",
					arm, write.name, files.Position(write.at), verifier, files.Position(verified[0].at))
			}
		}
		t.Logf("%s: %s, then %d link box write(s)", arm, verifier, len(writes[arm]))
	}
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
