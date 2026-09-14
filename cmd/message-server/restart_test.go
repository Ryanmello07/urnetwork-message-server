package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/harness"
	"github.com/urnetwork/message-server/store"
)

// A group created before a restart is still reachable after it, **and the restart is a real one**.
//
// This is §5.1 check 5's filter, and the reason this test spawns processes instead of building a
// second handler is that the property is about a PROCESS BOUNDARY and nothing else. Every part of
// this server was already correct when a group and the filter that knows about it were built in
// one address space: the group was created, the filter was told, and the fetch came back. What was
// broken was what a `map[string]bool` in that address space is worth once the address space is
// gone — and a test that rebuilds the pipeline in the same process has not crossed the boundary
// the defect lives on. It reconstructs the filter; an operator restarting a unit does not.
//
// So the two halves run in two OS processes, this test binary re-executed, and the ONLY thing they
// share is the PostgreSQL schema:
//
//	process 1   newServer -> CreateGroup -> a record submitted -> exit
//	process 2   newServer -> Fetch       -> the record must come back
//
// Each child builds its collaborators through [newServer], the same call `main` makes, and serves
// them through [newStackWith] with that server's OWN handler — not a copy of it. That is
// deliberate: the defect was a single line inside newServer, everything downstream of it was
// right, and a stack that built its own pipeline would have gone green over it.
//
// **What goes red without the fix.** With `api.NewMemoryKnownGroups()` back at that line, process
// 2 starts with an empty filter, check 5 misses, and the fetch is answered REASON_REJECTED —
// which §4.5 makes indistinguishable from a bad MAC — while every readiness precondition is met.
// Measured, not argued: see the edit log entry for this commit.
func TestAGroupCreatedBeforeARestartIsStillReachableAfterIt(t *testing.T) {
	if phase := os.Getenv(restartPhaseVariable); phase != "" {
		// this process IS one of the two halves; the parent below is what put it here
		runRestartPhase(t, phase)
		return
	}

	dsn := freshSchemaDsn(t)
	ctx := context.Background()

	pool, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatal("a pool for the migration job could not be created")
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrating the schema these two processes share: %v", err)
	}

	// ── process 1: the group is created, and then this process is gone ───────────────────
	runRestartChild(t, dsn, restartPhaseCreate)

	// The rows are in Postgres, read by a third party that is neither of the two children. This
	// is what makes the next assertion about REACHABILITY and not about data: if the fetch below
	// were to fail, it would fail over a group this line has just seen.
	records := store.NewPgxStore(pool, store.DefaultLimits(), nil)
	state, err := records.GroupState(ctx, restartGroupId())
	if err != nil {
		t.Fatalf("after the first process exited, the group it created is not in the database at all: %v", err)
	}
	if state.CurrentEpoch != 1 {
		t.Fatalf("the group is at epoch %d after its founding commit, want 1", state.CurrentEpoch)
	}
	if state.NextRecordId != 5 {
		t.Fatalf("the group allocated %d ids (next_record_id), want 5: a founding commit, a wrap, a marker and one ordinary record", state.NextRecordId-1)
	}

	// ── process 2: a different process, the same database ────────────────────────────────
	//
	// Nothing is handed over but the DSN. The filter in this process has never been told about
	// this group by a CreateGroup of its own, which is exactly the state a restarted replica is
	// in, and it is the state in which every group in the fleet used to become unreachable.
	runRestartChild(t, dsn, restartPhaseFetch)
}

// The two halves, and the environment that selects one.
//
// A phase rather than a second Test function, because a second Test function would have to skip
// itself in an ordinary run — and a suite that reports a skip nobody reads is how a test that
// never executes looks exactly like a test that passed.
const (
	restartPhaseVariable = "URMESSAGE_RESTART_PHASE"
	restartDsnVariable   = "URMESSAGE_RESTART_DSN"

	restartPhaseCreate = "create"
	restartPhaseFetch  = "fetch"
)

// The one record whose journey spans the restart. Its text is asserted on the far side, so that
// "the fetch was answered REASON_OK" cannot pass over an empty page.
const restartRecordHead = "a head written before the restart"

// The group both processes name. Deterministic, because the second process has to ask about a
// group it was never told about by anything but the database.
func restartGroupId() []byte {
	return stackGroupId()
}

// One half of the restart, in its own process.
//
// It re-executes THIS test binary with `-test.run` anchored to the one test above, so the child
// is the same code with the same build flags — including `-race`, when the parent was built with
// it — rather than a second program that might differ.
func runRestartChild(t *testing.T, dsn string, phase string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	child := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestAGroupCreatedBeforeARestartIsStillReachableAfterIt$",
		"-test.v",
		"-test.timeout=3m")
	child.Env = append(os.Environ(),
		restartPhaseVariable+"="+phase,
		restartDsnVariable+"="+dsn)
	output, err := child.CombinedOutput()

	// The DSN carries a password and the child's output is about to be printed. Nothing in this
	// binary puts a DSN in an error — that property has its own test — but this output also
	// carries whatever the Go runtime would say about a panic, and the environment is in a
	// process dump. Redacting here costs nothing and does not depend on that property holding.
	printable := strings.ReplaceAll(string(output), dsn, "<the test DSN>")
	if err != nil {
		t.Fatalf("the %s process failed (%v). §5.1 check 5's filter is what this is about: a group created in one process and refused in the next is REASON_REJECTED, which §4.5 makes indistinguishable from a bad MAC.\n%s",
			phase, err, printable)
	}
	if testing.Verbose() {
		t.Logf("the %s process:\n%s", phase, printable)
	}
}

// The child: build this process's server the way `main` does, serve it, and do one half.
func runRestartPhase(t *testing.T, phase string) {
	dsn := os.Getenv(restartDsnVariable)
	if dsn == "" {
		t.Fatalf("%s is set and %s is not, so this child has no database to be half of a restart against", restartPhaseVariable, restartDsnVariable)
	}

	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	loaded.hostingJurisdiction = "US"

	// The KEK is fixed rather than random, and that is load-bearing: §5.5 wraps every epoch key
	// under it, so a second process with a different KEK could not unwrap the read key the first
	// one installed — and the fetch would fail for a reason that has nothing to do with the
	// filter this test is about. Both children take the same one, which is what a fleet does.
	current, err := newServer(context.Background(), deployment{
		ordinal:       "0",
		healthAddress: "127.0.0.1:0",
		dsn:           dsn,
		kek:           make([]byte, kekBytes),
		serverId:      make([]byte, serverIdBytes),
	}, loaded, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newServer in the %s process: %v", phase, err)
	}
	defer current.Close()

	// this server's own handler, connection table and front checks — the values newServer wired
	stack := newStackWith(t, current.records, current)

	switch phase {
	case restartPhaseCreate:
		stack.openGroup(t)
		stack.submitAccepted(t, "the record written before the restart", stack.seal(t, harness.Sealed{
			Sender:      handleOf(0xA0),
			Epoch:       1,
			StreamIndex: 3,
			Class:       message.RetentionDurable,
			Bucket:      message.SizeBucket256,
			Head:        []byte(restartRecordHead),
			Body:        []byte("a body written before the restart"),
		}))

	case restartPhaseFetch:
		// The one thing this process has NOT done is create the group. Its filter has never been
		// told about it by anything but the database, which is what a restarted replica is.
		stack.hello(t)
		response := stack.fetch(t)
		found := false
		for _, record := range response.GetRecords() {
			parsed, err := message.ParseRecord(record.GetRecordBytes())
			if err != nil {
				t.Fatalf("a record fetched after the restart does not parse: %v", err)
			}
			if string(parsed.CtHead) == restartRecordHead {
				found = true
			}
		}
		if !found {
			t.Fatalf("the fetch after the restart was answered REASON_OK and returned %d records, and the record written before the restart is not among them",
				len(response.GetRecords()))
		}

		// ── the control, in the same process, over the same transport ────────────────
		//
		// Without it, "the group was found" is equally well explained by a filter that answers
		// true for everything — which is not check 5 at all, and which would leave every
		// assertion above green while every unknown group_id bought a full epoch-key lookup
		// and a MAC comparison. The id below is in no table, and the answer must be the other
		// one.
		unknown := make([]byte, store.GroupIdBytes)
		for index := range unknown {
			unknown[index] = 0xC3 ^ byte(index)
		}
		if _, err := current.records.GroupState(context.Background(), unknown); !errors.Is(err, store.ErrGroupUnavailable) {
			t.Fatalf("the group_id this control picked as absent is not absent: GroupState answered %v", err)
		}
		reason, _, err := stack.client.Fetch(stack.ctx,
			&protocol.FetchRequest{GroupId: unknown, ReadEpoch: 1, SinceRecordId: 0}, readKeyFor(1))
		if err != nil {
			t.Fatalf("the control fetch: %v", err)
		}
		if reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("a fetch of a group that is in no table was answered %v, want REASON_REJECTED: a filter that admits everything has stopped being §5.1 check 5", reason)
		}

	default:
		t.Fatalf("%s=%q is not a phase of this test", restartPhaseVariable, phase)
	}
}
