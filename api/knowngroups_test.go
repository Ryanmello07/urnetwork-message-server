package api

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
)

// ── §5.1 check 5's filter, and which fact it is about ────────────────────────────────────

// The store-backed filter answers about the DATABASE, and the memory one answers about this
// process's own history. Those are two different facts, and the difference is measured here.
//
// The measurement is the point. Both filters agree on every group the process that holds them
// created, which is every group any test in this package creates — so a suite built around one
// handler cannot tell them apart, and did not, for as long as the entrypoint wired the wrong one.
// The fact they disagree about is a group that exists in the store and was created by SOMEBODY
// ELSE: another replica, or the same replica before it restarted.
//
// The restart itself is not here. It is in cmd/message-server's
// TestAGroupCreatedBeforeARestartIsStillReachableAfterIt, which spawns two processes, because a
// process boundary is what the defect lived on and a second handler in one address space is not
// one. What this test holds is the mechanism that makes that test pass.
func TestTheStoreBackedFilterIsAFactAboutTheStoreAndTheMemoryOneIsNot(t *testing.T) {
	ctx := context.Background()
	records := store.NewMemoryStore(store.DefaultLimits())

	// somebody else's process created the group: this handler's filter is its own and is not
	// shared with either filter below
	elsewhere := newFixtureWith(t, Config{Store: records})
	elsewhere.createOpenGroup(t)

	backed := NewStoreKnownGroups(records)
	known, err := backed.Contains(ctx, elsewhere.groupId)
	if err != nil {
		t.Fatalf("the store-backed filter could not reach its store: %v", err)
	}
	if !known {
		t.Fatal("the store-backed filter says a group that is in the store does not exist; check 5 would answer REASON_REJECTED, which §4.5 makes indistinguishable from a bad MAC")
	}

	// the control, and the whole reason the wiring line matters: the same question, the same
	// store, the other implementation
	volatile := NewMemoryKnownGroups()
	stale, err := volatile.Contains(ctx, elsewhere.groupId)
	if err != nil {
		t.Fatalf("the memory filter answered an error, and it has no source of truth to fail to reach: %v", err)
	}
	if stale {
		t.Fatal("a freshly built memory filter says a group it was never told about exists; it has stopped being a per-process map and this test is no longer measuring the difference it exists to measure")
	}
}

// A miss is a question and not an answer: the filter does not remember that a group did not exist.
//
// A negative cache here would put the restart defect back one layer down and make it worse — the
// window would be however long the entry lived rather than however long the process ran, and it
// would open on a group_id a client asked about one millisecond before it was created, which is
// the ordinary race between two members of a group that is being founded.
func TestTheStoreBackedFilterDoesNotRememberThatAGroupDidNotExist(t *testing.T) {
	ctx := context.Background()
	records := store.NewMemoryStore(store.DefaultLimits())
	backed := NewStoreKnownGroups(records)

	creator := newFixtureWith(t, Config{Store: records})

	known, err := backed.Contains(ctx, creator.groupId)
	if err != nil {
		t.Fatalf("Contains before the group exists: %v", err)
	}
	if known {
		t.Fatal("the filter says a group that has never been created exists")
	}

	creator.createOpenGroup(t)

	known, err = backed.Contains(ctx, creator.groupId)
	if err != nil {
		t.Fatalf("Contains after the group exists: %v", err)
	}
	if !known {
		t.Fatal("the filter answered `no` before the group existed and is still answering `no` after it does, so it cached the negative")
	}
}

// What the substitution costs, as counted store calls rather than as a claim in a comment.
//
// [StoreKnownGroupsNotBuilt] tells an operator this build pays "one indexed row read per
// distinct unknown group_id" and none for a hit. Both halves are numbers, so both are counted:
// a hit after the first read is 0 reads, and two questions about the same unknown group are 2.
// The second number is the one that looks like a defect and is not — see the test above for why
// the cache that would make it 1 must not exist.
func TestTheStoreBackedFilterCostsOneReadPerDistinctUnknownGroupAndNoneForAHit(t *testing.T) {
	ctx := context.Background()
	counted := &countingStore{Store: store.NewMemoryStore(store.DefaultLimits())}
	backed := NewStoreKnownGroups(counted)

	creator := newFixtureWith(t, Config{Store: counted})
	creator.createOpenGroup(t)

	// the first question about a group that exists: one read
	counted.reset()
	if known, err := backed.Contains(ctx, creator.groupId); err != nil || !known {
		t.Fatalf("Contains on an existing group answered (%v, %v)", known, err)
	}
	if counted.groupState != 1 {
		t.Fatalf("the first hit cost %d GroupState reads, want 1: %s", counted.groupState, counted)
	}

	// and every question after it: none
	counted.reset()
	for index := 0; index < 8; index++ {
		if known, err := backed.Contains(ctx, creator.groupId); err != nil || !known {
			t.Fatalf("Contains #%d on an existing group answered (%v, %v)", index, known, err)
		}
	}
	if counted.reads() != 0 {
		t.Fatalf("eight hits after the first cost %d store calls, want 0; §5.1 check 5 exists so that a hit costs nothing: %s",
			counted.reads(), counted)
	}

	// an unknown group: one read every time, which is the declared price
	unknown := groupId(0x9D)
	counted.reset()
	for index := 0; index < 2; index++ {
		if known, err := backed.Contains(ctx, unknown); err != nil || known {
			t.Fatalf("Contains #%d on an unknown group answered (%v, %v)", index, known, err)
		}
	}
	if counted.groupState != 2 {
		t.Fatalf("two questions about the same unknown group cost %d GroupState reads, want 2: %s", counted.groupState, counted)
	}
	t.Logf("measured: hit #1 = 1 read, hits #2..#9 = 0 reads, two misses on one unknown group = 2 reads (%s)", counted)
}

// ── the third answer ─────────────────────────────────────────────────────────────────────

// A store that cannot be reached at all, so that the filter's miss path has nowhere to go.
type unreachableGroupState struct {
	store.Store
}

var errTheDatabaseIsNotThere = errors.New("api_test: the database did not answer")

func (self *unreachableGroupState) GroupState(ctx context.Context, groupId []byte) (*store.GroupState, error) {
	return nil, errTheDatabaseIsNotThere
}

// A filter that could not reach its own source of truth answers REASON_INTERNAL, on both paths.
//
// It is REASON_INTERNAL and not §4.5's merged REASON_REJECTED because the two say opposite things
// to the only party who can act on either. REASON_REJECTED is the answer to a party holding no
// key, and §4.5 deliberately makes it carry no information — so a member of a real group told
// REASON_REJECTED for the duration of a database outage sees exactly what they would see if their
// group had been deleted, with nothing in any log to separate the two. REASON_INTERNAL is the
// answer a client retries.
//
// Both halves of the assertion matter. The same request against a reachable store is the control:
// without it "REASON_INTERNAL" would also be the answer to a test whose record was malformed.
func TestAFilterThatCannotReachItsStoreAnswersInternalAndNotAMergedRefusal(t *testing.T) {
	records := store.NewMemoryStore(store.DefaultLimits())

	reachable := newFixtureWith(t, Config{Store: records, KnownGroups: NewStoreKnownGroups(records)})
	reachable.createOpenGroup(t)

	record := func(current *fixture) *protocol.Record {
		return current.seal(t, sealed{
			sender: senderA, epoch: 1, streamIndex: 3,
			class: message.RetentionDurable, bucket: message.SizeBucket256,
			head: []byte("a head"), body: []byte("a body"), writeKey: current.writeKey(1),
		})
	}

	// the control: everything about this request is well formed and the group is there
	if results := reachable.submit(t, record(reachable)); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the control submission was answered %v, want REASON_OK", results[0].GetReason())
	}
	if reason, _, err := reachable.fetchFrom(t, &protocol.FetchRequest{GroupId: reachable.groupId, ReadEpoch: 1}); err != nil || reason != protocol.Reason_REASON_OK {
		t.Fatalf("the control fetch was answered (%v, %v), want REASON_OK", reason, err)
	}

	// the same store, and a filter whose miss path cannot reach it
	blind := newFixtureWith(t, Config{
		Store:       records,
		KnownGroups: NewStoreKnownGroups(&unreachableGroupState{Store: records}),
	})

	results := blind.submit(t, record(blind))
	if results[0].GetReason() != protocol.Reason_REASON_INTERNAL {
		t.Fatalf("a submission whose filter could not reach the database was answered %v; REASON_REJECTED here tells a member of a real group, in the one code §4.5 refuses to explain, that their group does not exist",
			results[0].GetReason())
	}

	reason, _, err := blind.fetchFrom(t, &protocol.FetchRequest{GroupId: blind.groupId, ReadEpoch: 1})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if reason != protocol.Reason_REASON_INTERNAL {
		t.Fatalf("a fetch whose filter could not reach the database was answered %v, want REASON_INTERNAL", reason)
	}
}

// The filter is read and written from many goroutines at once, which is what a handler does.
//
// [store.Store] documents every method as safe for concurrent use and says why — "§6.1's
// interesting cases are all racy ones" — and this filter is the one collaborator in front of it
// that keeps mutable state of its own. Its read path is a double-checked map: an RLock, a release,
// a store read, and then a Lock to fill the cache, so two goroutines missing on the same group
// both write it. There is nothing subtle about the locking and that is exactly why it is worth
// running: this test is only an assertion at all under `-race`, which nothing in this repository
// had ever been run under before today.
//
// The ids overlap on purpose. A test whose goroutines each used a private group_id would exercise
// map growth and never the case the RWMutex is for.
func TestTheStoreBackedFilterIsSafeUnderConcurrentUse(t *testing.T) {
	ctx := context.Background()
	records := store.NewMemoryStore(store.DefaultLimits())
	creator := newFixtureWith(t, Config{Store: records})
	creator.createOpenGroup(t)

	backed := NewStoreKnownGroups(records)

	const goroutines = 16
	const rounds = 64
	var running sync.WaitGroup
	failures := make(chan string, goroutines)
	for worker := 0; worker < goroutines; worker++ {
		running.Add(1)
		go func(worker int) {
			defer running.Done()
			for round := 0; round < rounds; round++ {
				// the group that exists: every worker must see it, every time
				known, err := backed.Contains(ctx, creator.groupId)
				if err != nil || !known {
					failures <- "an existing group answered not-known under concurrent use"
					return
				}
				// a small shared set that does not exist, so the miss path runs concurrently too
				absent := groupId(byte(0xB0 + round%4))
				if known, err := backed.Contains(ctx, absent); err != nil || known {
					failures <- "a group that is in no table answered known"
					return
				}
				// and a writer, on ids several workers share
				backed.Insert(groupId(byte(0xE0 + worker%3)))
			}
		}(worker)
	}
	running.Wait()
	close(failures)
	for failure := range failures {
		t.Fatal(failure)
	}
}

// ── what each filter declares about itself ───────────────────────────────────────────────

// Every implementation of [KnownGroups] says what it is not, and a handler puts that on §10.1's
// endpoint.
//
// This is the half of F1 that was not a defect in the code at all. The per-process filter was
// wired for four passes, and `/readyz` printed twenty-one `not-built` lines while the ops document
// said "every one of these is printed by /readyz" — so a reader was entitled to conclude the list
// was complete, and the one absence that could lose every tester's history was on none of it.
// A list that claims completeness and is not complete is worse than no list.
//
// The tripwire is the last assertion: a build that goes back to the volatile filter does not go
// quiet, it prints the volatile filter's own sentence.
func TestEveryKnownGroupsImplementationSaysWhatItIsNot(t *testing.T) {
	records := store.NewMemoryStore(store.DefaultLimits())

	for _, current := range []struct {
		name   string
		filter KnownGroups
		says   string
	}{
		{name: "the per-process map", filter: NewMemoryKnownGroups(), says: "restart"},
		{name: "the store-backed filter", filter: NewStoreKnownGroups(records), says: "refresh"},
	} {
		t.Run(current.name, func(t *testing.T) {
			declared := current.filter.NotBuilt()
			if len(declared) == 0 {
				t.Fatal("this filter declares nothing at all, so §10.1's readiness endpoint reads it as §5.1's own machine")
			}
			said := false
			for _, entry := range declared {
				if entry.Check != 0 {
					t.Fatalf("this filter claims §5.1 check %d is not run, and check 5 IS run; TestEveryCheckOfSpecB51IsRunOrDeclared refuses a number that is both, correctly", entry.Check)
				}
				if strings.Contains(entry.What, current.says) {
					said = true
				}
			}
			if !said {
				t.Fatalf("this filter's declaration does not mention %q, which is the part of §5.1's design it does not have: %v", current.says, declared)
			}
		})
	}

	// and the handler carries it, which is what makes /readyz and --print-config able to say so
	volatile := newFixtureWith(t, Config{KnownGroups: NewMemoryKnownGroups()}).handler
	backed := newFixtureWith(t, Config{Store: records, KnownGroups: NewStoreKnownGroups(records)}).handler

	saysRestart := func(handler *Handler) bool {
		for _, entry := range handler.NotBuilt() {
			if entry.What == memoryUnbackedFilter.What {
				return true
			}
		}
		return false
	}
	if !saysRestart(volatile) {
		t.Fatalf("a handler built on the per-process filter does not declare it: %v", volatile.NotBuilt())
	}
	if saysRestart(backed) {
		t.Fatalf("a handler built on the store-backed filter declares the per-process filter's defect, so the declaration is not derived from the filter that is actually wired: %v", backed.NotBuilt())
	}
}
