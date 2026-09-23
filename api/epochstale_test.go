package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
)

// A WRITE AT ANY EPOCH BUT THE CURRENT ONE IS REFUSED, through §5.1's whole submit pipeline —
// ledger item 247's second half: "check that no path in `api/` accepts a write at a non-current
// epoch."
//
// [store.RunContract]'s AWriteAtAnyEpochButTheCurrentOneIsRefused holds every implementation of
// [store.Store] to the property. What it cannot see is this layer, which has three chances to
// get to a row before §6.1 step (2) ever runs: check 6 resolves the write key for the epoch the
// RECORD names, check 7 verifies a MAC under it, and only then is the batch handed down.
//
// THE ONE PROBE THAT MATTERS is the retired predecessor. Every other epoch here is stopped by
// key custody at check 6 and says nothing about the epoch gate — which would make a green run
// vacuous — but §5.3 retains "the current epoch's write key plus one briefly-retired
// predecessor", so a write at `current-1` under `write_key[current-1]` reaches §6.1 step (2)
// with a VALID MAC. That is exactly the forge ledger item 244 filed: a member removed at epoch n
// writing at n with the key it legitimately held. The assertion below is that it answers
// REASON_EPOCH_STALE, and the run fails as vacuous if no probe reached that far.
func TestNoPathInTheApiAcceptsAWriteAtANonCurrentEpoch(t *testing.T) {
	fixture := newFixture(t)
	threeEpochGroup(t, fixture) // senderA has spent stream indices 0..11; the group is at epoch 3

	// senderB has no stream-index history in this group, so stream index 0 is legal for every
	// probe below and no probe can be refused at §6.1 step (3) instead of step (2)
	probe := func(t *testing.T, epoch uint64, index uint64) protocol.Reason {
		t.Helper()
		record := fixture.seal(t, sealed{
			sender: senderB, epoch: epoch, streamIndex: index,
			class: message.RetentionDurable, bucket: message.SizeBucket256,
			head: []byte("a probe"), body: []byte("a probe"), writeKey: fixture.writeKey(epoch),
		})
		return fixture.submit(t, record)[0].GetReason()
	}

	answers := map[uint64]protocol.Reason{}
	index := uint64(0)
	for _, epoch := range []uint64{0, 1, 2, 4, 5, uint64(1) << 40} {
		answers[epoch] = probe(t, epoch, index)
		index++
		if store.Accepted(answers[epoch]) {
			t.Fatalf("a record at epoch %d was ACCEPTED through the api and the group is at epoch 3; ledger item 244's schedule rests on this being impossible",
				epoch)
		}
	}

	// THE VACUITY GUARD. If every probe above was stopped at check 6 for want of a retained
	// write key, this test has measured key custody and not the epoch gate — and it would stay
	// green with §6.1 step (2) deleted outright
	if answers[2] != protocol.Reason_REASON_EPOCH_STALE {
		t.Fatalf("the probe at epoch 2 — the retired predecessor, whose write key §5.3 says is still held — was answered %v, want REASON_EPOCH_STALE; if it did not reach §6.1 step (2) then nothing in this test did, and a green run here would mean key custody and not the epoch gate",
			answers[2])
	}
	// and the complement, so the reader can see which probes were stopped WHERE
	t.Logf("a group at epoch 3, through the api, answered by epoch: %v", answers)

	// THE CONTROL, in the same test, in the same group, by the same sender: the current epoch is
	// writable. Without it every assertion above passes for a server that refuses everything
	if reason := probe(t, 3, index); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control at the group's CURRENT epoch was answered %v; nothing above is a measurement if nothing can be accepted at all", reason)
	}
}

// The [store.Store] methods that create or change a row, and the ones that do not.
//
// This is the classification [TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate]
// holds the package to, and it is written down here with its reason rather than derived, because
// "does this method write" is not a thing an AST can be asked. What IS derived is its
// completeness: a method added to the interface and left out of this map fails that test by name.
var storeMethodMutates = map[string]bool{
	"CreateGroup": true,  // §4.3.2, and §6.1's epoch gate evaluated as `epoch == 1`
	"Submit":      true,  // §6.1 steps (0) through (7), the epoch gate at step (2)
	"CloseGroup":  true,  // §7.5; it writes no record and takes the group out of every path
	"GroupState":  false, // §4.3.10
	"EpochKeys":   false, // §5.1 check 6 and §5.1.1's read-key lookup
	"Fetch":       false, // §4.3.4
}

// EVERY WRITE THIS PACKAGE CAN MAKE GOES THROUGH §6.1's EPOCH GATE, as a property of the package
// rather than of the two call sites that exist today — ledger item 247.
//
// The behavioural test above proves the two arms that exist refuse a stale write. It cannot prove
// anything about the arm that does not exist yet, and item 247 is explicit that the thing to
// check is "no future `Subscribe` path accepts a write at a non-current epoch". A `Subscribe`,
// `RecoveryFetch` or `WrapFetch` arm is coming; what this asserts is that when one lands, it
// cannot reach a row except through a method whose first act is §6.1 step (2).
//
// It reads the package's own source, and BOTH halves of it are derived:
//
//   - the holders. Every struct field in this package whose type is [store.Store] is found in the
//     AST, so a second holder — `storeKnownGroups.records` is already one, beside
//     `Handler.store` — is covered without being named here.
//   - the interface. The method set comes off [store.Store] by reflection, so a method added to
//     it is a failure in [storeMethodMutates] rather than a silent hole.
//
// What is left over is printed. A gate whose narrowing is invisible is a gate nobody can audit,
// and the complement here — the Store methods this package never calls — is the list a reviewer
// actually needs.
func TestEveryWriteThisPackageCanMakeGoesThroughSection61sEpochGate(t *testing.T) {
	interfaceType := reflect.TypeOf((*store.Store)(nil)).Elem()
	declared := []string{}
	for index := range interfaceType.NumMethod() {
		name := interfaceType.Method(index).Name
		declared = append(declared, name)
		if _, classified := storeMethodMutates[name]; !classified {
			t.Fatalf("store.Store declares %s and storeMethodMutates does not say whether it writes; a method this test cannot classify is a method it cannot hold anybody to",
				name)
		}
	}
	for name := range storeMethodMutates {
		if !slices.Contains(declared, name) {
			t.Fatalf("storeMethodMutates classifies %s and store.Store no longer declares it; a stale entry here is a gate narrower than it reads",
				name)
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
		t.Fatalf("this package did not parse as `api`; it parsed as %v", keysOf(parsed))
	}

	// every field whose declared type is store.Store, by name
	holders := map[string]bool{}
	for _, file := range pkg.Files {
		ast.Inspect(file, func(node ast.Node) bool {
			field, ok := node.(*ast.Field)
			if !ok {
				return true
			}
			selector, ok := field.Type.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Store" {
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
		t.Fatal("no field of type store.Store was found in this package, so the walk below inspects nothing and would be green with every gate removed")
	}

	// every call this package makes on one of those holders
	calls := map[string][]string{}
	for path, file := range pkg.Files {
		ast.Inspect(file, func(node ast.Node) bool {
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
			at := path[strings.LastIndexByte(path, '/')+1:]
			calls[method.Sel.Name] = append(calls[method.Sel.Name], at)
			return true
		})
	}

	mutating, readOnly, unused := []string{}, []string{}, []string{}
	for _, name := range declared {
		switch {
		case len(calls[name]) == 0:
			unused = append(unused, name)
		case storeMethodMutates[name]:
			mutating = append(mutating, name)
		default:
			readOnly = append(readOnly, name)
		}
	}
	slices.Sort(mutating)

	// THE COMPLEMENT, PRINTED: what this gate narrowed away is the list a reviewer needs, and an
	// empty one would be the tell that the walk found nothing
	t.Logf("store.Store holders in this package: %v", keysOf(holders))
	t.Logf("mutating methods called: %v", mutating)
	t.Logf("read-only methods called: %v", readOnly)
	t.Logf("methods this package never calls: %v", unused)

	// §6.1 runs its epoch gate inside CreateGroup and inside Submit, and those are the only two
	// ways this package can put a row anywhere. A third that appeared here would be a write this
	// package makes on a path nothing in [store.RunContract] holds to step (2)
	want := []string{"CreateGroup", "Submit"}
	if !slices.Equal(mutating, want) {
		t.Fatalf("this package calls the mutating store methods %v, and §6.1's epoch gate is inside %v; a write on any other method is a write at whatever epoch its caller chose",
			mutating, want)
	}
	if len(calls["CloseGroup"]) != 0 {
		t.Fatalf("this package calls CloseGroup at %v, which §7.5 gives to the operator and not to a client request", calls["CloseGroup"])
	}
}

// The keys of a map, sorted, for the two places above that print one. Written out because a
// failure message whose order changes between runs is a failure message nobody can diff.
func keysOf[V any](from map[string]V) []string {
	names := make([]string, 0, len(from))
	for name := range from {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
