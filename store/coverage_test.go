package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Which implementations of [Store] this run actually held to [RunContract], printed after every
// run whether it passed or failed.
//
// This exists because of the one thing a `go test` run cannot say for itself. The pgx contract
// needs a database, and the honest way to handle a machine without one is to skip — but a
// skipped test contributes nothing to the `ok` line, so a run in which the entire second
// implementation never executed a statement is textually indistinguishable from a run in which
// both passed. That is the project's central failure mode wearing a different hat: a test that
// silently does not run is a test that cannot fail.
//
// So the outcome is stated in the same breath as the verdict, above the `ok`, in every mode —
// `-v` or not, filtered or not — and it names the implementations rather than counting them.
//
// The class is DERIVED and is never a list typed here. It is read out of this package's own
// source: every named type in it whose methods cover every method of `type Store interface`. A
// third implementation added tomorrow appears in this banner as "did not run" on the first run
// that forgets to hold it to the contract, which is exactly the day it matters.

// What happened to one implementation in this run.
type contractOutcome struct {
	ran    bool
	reason string
}

var (
	contractMutex    sync.Mutex
	contractOutcomes = map[string]contractOutcome{}
)

// [RunContract] against one implementation, recording that it ran.
//
// The name is not passed in: it is read off the first store the factory builds, with
// [implementationUnderTest], which is the same derivation the refusal gate inside RunContract
// uses for its own class. A wrapper that took the name as an argument would be a wrapper whose
// argument could disagree with the store it wrapped.
func heldToTheContract(t *testing.T, newStore func(Limits) Store) {
	t.Helper()
	RunContract(t, func(limits Limits) Store {
		store := newStore(limits)
		recordContractOutcome(t, store, contractOutcome{ran: true})
		return store
	})
}

// An implementation this run could not hold to the contract, and why. The prototype may be a
// typed nil — naming the implementation must not require the resources running it would.
func contractSkipped(t *testing.T, prototype Store, reason string) {
	t.Helper()
	recordContractOutcome(t, prototype, contractOutcome{reason: reason})
}

func recordContractOutcome(t *testing.T, store Store, outcome contractOutcome) {
	t.Helper()
	name := implementationUnderTest(t, store)
	contractMutex.Lock()
	defer contractMutex.Unlock()
	// a run that reached the contract beats a run that recorded a reason for not reaching it,
	// whichever order they land in
	if current, found := contractOutcomes[name]; found && current.ran {
		return
	}
	contractOutcomes[name] = outcome
}

// What a job sets to say that a partial run is a failure.
//
// The default is the other way round and stays that way: a developer with no PostgreSQL runs the
// suite, the pgx contract skips, and the run is green. What that developer must not be able to do
// is mistake it for a complete one, and the banner is what stops them — under `-v`, which this
// project's rules require and which CI passes, and on any failure.
//
// This exists because of the one invocation where the banner is not enough. Under a plain
// `go test ./store/` the go command prints exactly one line — `ok …/store 0.9s` — and DISCARDS
// everything the binary wrote, banner included. On that invocation the only signal `go test` will
// carry out of the package is the exit code, and this is how the exit code gets to say it. A job
// that means to cover both implementations sets this, and a DSN that went missing then turns the
// run red rather than green with a paragraph nobody printed.
const requireCoverageVariable = "URMESSAGE_REQUIRE_CONTRACT_COVERAGE"

func TestMain(m *testing.M) {
	code := m.Run()
	releasePgxHarness()
	report, complete := contractCoverage()
	fmt.Fprint(os.Stderr, report)
	if code == 0 && !complete && os.Getenv(requireCoverageVariable) != "" {
		fmt.Fprintf(os.Stderr, "%s is set and this run did not hold every implementation of Store to RunContract, so it is a failure rather than a pass. Unset it to run a filtered or database-less suite.\n",
			requireCoverageVariable)
		code = 1
	}
	os.Exit(code)
}

// The banner. It is a string rather than a print so that the test below can hold it to saying
// what it claims.
func contractCoverage() (string, bool) {
	implementations, err := storeImplementations(".")
	if err != nil {
		// a derivation that could not read the class has not established that anything was
		// covered, so it is not a complete run either
		return fmt.Sprintf("\nCONTRACT COVERAGE: unknown — %v\nthe class of Store implementations could not be read out of this package, so nothing below states what this run covered.\n\n", err), false
	}

	contractMutex.Lock()
	defer contractMutex.Unlock()
	return renderContractCoverage(implementations, contractOutcomes)
}

// The banner itself, as a function of a class and a set of outcomes rather than of whatever this
// process happened to record.
//
// It is separated for one reason, and the reason is a mutation that survived: the HEADLINE is the
// whole of what this banner is for — a reader scanning a log for whether the run covered anything
// reads one word — and while it could only be produced from the live map, no test could construct
// a partial run and a complete one and hold the two apart. "PARTIAL RUN" could be pinned to "FULL
// RUN" in one line, every run would then report a clean sweep, and the suite stayed green. Which
// is this project's own central failure applied to the thing that exists to announce it.
func renderContractCoverage(implementations []string, outcomes map[string]contractOutcome) (string, bool) {
	report := &strings.Builder{}
	ran := 0
	rows := []string{}
	for _, name := range implementations {
		outcome, found := outcomes[name]
		switch {
		case outcome.ran:
			ran++
			rows = append(rows, fmt.Sprintf("  %-14s ran the contract", name))
		case found:
			rows = append(rows, fmt.Sprintf("  %-14s DID NOT RUN — %s", name, outcome.reason))
		default:
			rows = append(rows, fmt.Sprintf("  %-14s DID NOT RUN — no test in this run held it to RunContract", name))
		}
	}
	headline := "PARTIAL RUN"
	if ran == len(implementations) {
		headline = "FULL RUN"
	}
	fmt.Fprintf(report, "\n%s: %d of %d implementations of Store were held to RunContract.\n", headline, ran, len(implementations))
	fmt.Fprintf(report, "%s\n", strings.Join(rows, "\n"))
	if ran != len(implementations) {
		report.WriteString("a passing result below covers only the implementations marked \"ran the contract\".\n")
	}
	report.WriteString("\n")
	return report.String(), ran == len(implementations)
}

// The banner's headline, in both of the sentences it can say.
//
// Held against outcome sets this test supplies rather than against the live map, because the live
// map says whatever this run happened to record — which is one of the two sentences, never both,
// and never the one that matters most on the run where it would have been wrong.
func TestTheBannerTellsAPartialRunFromACompleteOne(t *testing.T) {
	implementations, err := storeImplementations(".")
	if err != nil {
		t.Fatalf("the class of Store implementations: %v", err)
	}
	if len(implementations) < 2 {
		t.Fatal("the headline is being held against a package with fewer than two implementations, where partial and complete cannot be told apart")
	}

	every := map[string]contractOutcome{}
	for _, name := range implementations {
		every[name] = contractOutcome{ran: true}
	}
	complete, everyRan := renderContractCoverage(implementations, every)
	if !everyRan {
		t.Error("every implementation was recorded as having run the contract and the banner does not call the run complete")
	}
	if !strings.Contains(complete, "FULL RUN") || strings.Contains(complete, "PARTIAL RUN") {
		t.Errorf("every implementation ran the contract and the banner does not say FULL RUN:\n%s", complete)
	}
	if strings.Contains(complete, "DID NOT RUN") {
		t.Errorf("every implementation ran the contract and the banner names one that did not:\n%s", complete)
	}

	// one short of the class, which is exactly the shape of a run with no database: the pgx
	// contract skipped, the suite green, and this banner the only thing that says so
	short := map[string]contractOutcome{}
	for _, name := range implementations[1:] {
		short[name] = contractOutcome{ran: true}
	}
	partial, allRan := renderContractCoverage(implementations, short)
	// the boolean and the headline are the same fact, and they are asserted together because
	// TestMain acts on the boolean while a reader acts on the word: the two disagreeing is a job
	// that passes while its own banner says the run was partial
	if allRan {
		t.Errorf("%s was not held to the contract and the banner calls the run complete:\n%s", implementations[0], partial)
	}
	if !strings.Contains(partial, "PARTIAL RUN") || strings.Contains(partial, "FULL RUN") {
		t.Errorf("%s was not held to the contract and the banner does not say PARTIAL RUN:\n%s", implementations[0], partial)
	}
	if !strings.Contains(partial, implementations[0]+" ") || !strings.Contains(partial, "DID NOT RUN") {
		t.Errorf("the banner does not name %s as the implementation that did not run:\n%s", implementations[0], partial)
	}
	// the sentence that tells a reader what the `ok` line underneath it is worth
	if !strings.Contains(partial, "a passing result below covers only") {
		t.Errorf("a partial run's banner does not say what a passing result below it covers:\n%s", partial)
	}
	// and a run that recorded a REASON for not reaching an implementation says the reason rather
	// than the generic line, because "no test held it to RunContract" and "there was no database"
	// send an operator to two different places
	explained := map[string]contractOutcome{implementations[0]: {reason: "no URMESSAGE_TEST_DSN in the environment"}}
	for _, name := range implementations[1:] {
		explained[name] = contractOutcome{ran: true}
	}
	explanation, _ := renderContractCoverage(implementations, explained)
	if !strings.Contains(explanation, "no URMESSAGE_TEST_DSN in the environment") {
		t.Errorf("the banner dropped the reason the implementation could not be held to the contract:\n%s", explanation)
	}
}

// Every named type in this package whose method set covers every method of `type Store
// interface`, read out of the source rather than listed.
//
// Reflection cannot answer this — a Go program cannot enumerate the types of a package — so it
// is the AST, the same source the two gates inside [RunContract] read their own classes from.
// Test files are excluded: a fake declared in one is not an implementation this module ships.
func storeImplementations(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := []*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		text, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), name, text, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, parsed)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no non-test Go source was read from %s", directory)
	}

	wanted := storeInterfaceMethods(files)
	if len(wanted) == 0 {
		return nil, fmt.Errorf("no file under %s declares `type Store interface` with methods on it", directory)
	}
	declared := map[string]map[string]bool{}
	for _, file := range files {
		for _, declaration := range file.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction {
				continue
			}
			owner := receiverTypeOf(function)
			if owner == "" {
				continue
			}
			if declared[owner] == nil {
				declared[owner] = map[string]bool{}
			}
			declared[owner][function.Name.Name] = true
		}
	}

	found := []string{}
	for owner, methods := range declared {
		covers := true
		for _, method := range wanted {
			covers = covers && methods[method]
		}
		if covers {
			found = append(found, owner)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no type in %s has all of %v, so this derivation read the interface and matched nothing", directory, wanted)
	}
	slices.Sort(found)
	return found, nil
}

func storeInterfaceMethods(files []*ast.File) []string {
	methods := []string{}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			specification, isSpecification := node.(*ast.TypeSpec)
			if !isSpecification || specification.Name.Name != "Store" {
				return true
			}
			declaredInterface, isInterface := specification.Type.(*ast.InterfaceType)
			if !isInterface {
				return true
			}
			for _, method := range declaredInterface.Methods.List {
				for _, name := range method.Names {
					methods = append(methods, name.Name)
				}
			}
			return true
		})
	}
	slices.Sort(methods)
	return methods
}

// The derivation, and the banner over it, held against what this package actually contains.
//
// Without this the banner is a print statement nobody has read: a derivation that found nothing
// would report "0 of 0 implementations" and call it a FULL RUN, which is the same clean-looking
// output for the same absent coverage the banner exists to make visible.
func TestTheContractCoverageBannerReadsThisPackage(t *testing.T) {
	implementations, err := storeImplementations(".")
	if err != nil {
		t.Fatalf("the class of Store implementations: %v", err)
	}
	t.Logf("this package declares %d implementations of Store: %v", len(implementations), implementations)
	for _, wanted := range []string{"MemoryStore", "PgxStore"} {
		if !slices.Contains(implementations, wanted) {
			t.Errorf("%s implements every method of Store in this package and the derivation did not find it: %v", wanted, implementations)
		}
	}
	// and the direction that says the derivation is not simply naming every type it sees
	if slices.Contains(implementations, "Record") || slices.Contains(implementations, "Limits") {
		t.Errorf("a type that implements none of Store's methods is in the derived class: %v", implementations)
	}

	// the banner says PARTIAL whenever an implementation is unaccounted for, which is the whole
	// of what it is for. It is checked against a class of two or more, because with one
	// implementation "all of them ran" and "the one that ran" are the same sentence
	if len(implementations) < 2 {
		t.Fatal("the banner is being held against a package with fewer than two implementations, where partial and complete cannot be told apart")
	}
	coverage, _ := contractCoverage()
	if !strings.Contains(coverage, fmt.Sprintf("of %d implementations", len(implementations))) {
		t.Errorf("the banner does not count the derived class:\n%s", coverage)
	}
	for _, name := range implementations {
		if !strings.Contains(coverage, name) {
			t.Errorf("the banner does not name %s:\n%s", name, coverage)
		}
	}
}
