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

func TestMain(m *testing.M) {
	code := m.Run()
	releasePgxHarness()
	fmt.Fprint(os.Stderr, contractCoverage())
	os.Exit(code)
}

// The banner. It is a string rather than a print so that the test below can hold it to saying
// what it claims.
func contractCoverage() string {
	implementations, err := storeImplementations(".")
	if err != nil {
		return fmt.Sprintf("\nCONTRACT COVERAGE: unknown — %v\nthe class of Store implementations could not be read out of this package, so nothing below states what this run covered.\n\n", err)
	}

	contractMutex.Lock()
	defer contractMutex.Unlock()
	report := &strings.Builder{}
	ran := 0
	rows := []string{}
	for _, name := range implementations {
		outcome, found := contractOutcomes[name]
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
	return report.String()
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
	coverage := contractCoverage()
	if !strings.Contains(coverage, fmt.Sprintf("of %d implementations", len(implementations))) {
		t.Errorf("the banner does not count the derived class:\n%s", coverage)
	}
	for _, name := range implementations {
		if !strings.Contains(coverage, name) {
			t.Errorf("the banner does not name %s:\n%s", name, coverage)
		}
	}
}
