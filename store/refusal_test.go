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
	"testing"

	"github.com/urnetwork/connect/protocol"
)

// §6.1 step (3b), against [resultsOf] itself rather than against whichever implementation
// happens to reach it.
//
// This exists because of a dependency that was left in a concerns list. The invariant — a
// refusal names no record id — is enforced in one place, and the only scenario that could
// observe it doing anything was PgxStore's: §4.3.7's intra-batch rebind is refused there AFTER
// the write loop has stamped `result.RecordId` onto the offender's neighbours, while MemoryStore
// refuses the same batch at the gate and so never stamps anything. That asymmetry is deliberate
// — it keeps §6.1 step (6c)'s post-allocation verify reachable — but it left the invariant's
// only test a side effect of one implementation's internal ordering. Move the refusal forward in
// PgxStore for any good reason tomorrow and the `if !accepted` in [resultsOf] becomes dead code
// that could be deleted with the whole suite green.
//
// So the dependency is dissolved rather than pinned: the invariant is asserted where it lives,
// by a caller that stamps the id itself. What the implementations do above it is then free to
// change.
//
// The class is §4.5's whole vocabulary, read out of the generated enum. A list of refusal codes
// typed here would be the Rule 5 failure this invariant has already survived once — a version
// that tested REASON_REJECTED alone would pass while every other refusal in the protocol named
// a row.
func TestARefusalNamesNoRecordId(t *testing.T) {
	if len(protocol.Reason_name) == 0 {
		t.Fatal("protocol.Reason declares no values, so this gate read nothing at all")
	}
	acceptances, refusals := 0, 0
	for value, name := range protocol.Reason_name {
		reason := protocol.Reason(value)
		batch := []*pending{{
			record: &Record{},
			// stamped, exactly as [PgxStore.write] stamps a record it has just written and as
			// [MemoryStore.commit] stamps one it has just appended
			result: &SubmitResult{Reason: reason, RecordId: 41, CurrentEpoch: 7},
		}}
		results := resultsOf(batch)
		if len(results) != 1 {
			t.Fatalf("a batch of one produced %d results", len(results))
		}
		if accepted(reason) {
			acceptances++
			if results[0].RecordId != 41 {
				t.Errorf("%s is an acceptance and its record id was taken off; §7.3's clamp is an acceptance carrying a notice, with a record id and an opened epoch behind it, and a check written against REASON_OK alone erases the id of every clamped commit in the project", name)
			}
			continue
		}
		refusals++
		if results[0].RecordId != 0 {
			t.Errorf("a result refused with %s came back naming record %d; §6.1 step (3b) allocates nothing on a refusal so it has no id to name, and the id it named is the group's own allocation counter handed to a party §4.5 tells nothing apart from a bad MAC",
				name, results[0].RecordId)
		}
		// and the direction that is NOT a rule, asserted so that nobody generalises the one
		// above into it: §4.5 gives REASON_EPOCH_STALE a current_epoch and §6.2 gives any
		// rejected commit its winning_commit, both of them on refusals. A blanket clear here
		// would delete the field §6.2's loser protocol binds to
		if results[0].CurrentEpoch != 7 {
			t.Errorf("a result refused with %s lost its current_epoch; §4.3.3 sets it on EVERY result and §4.5 makes REASON_EPOCH_STALE the refusal that carries it, so this is not the record id's rule and must not acquire it",
				name)
		}
	}
	// a one-sided loop is a loop that proved one branch and reported both
	if acceptances == 0 || refusals == 0 {
		t.Fatalf("%d of §4.5's codes are acceptances and %d are refusals; a run that saw only one kind asserted nothing about the other", acceptances, refusals)
	}
	t.Logf("§4.5 declares %d codes: %d acceptances and %d refusals, each held to resultsOf", len(protocol.Reason_name), acceptances, refusals)
}

// The claim in [resultsOf]'s own doc comment — "every [SubmitResponse] either implementation
// returns is built here" — held to the source, because that claim is what makes one place the
// right number of places for the invariant above.
//
// The class is derived: every function in this package that ANSWERS with a *SubmitResponse, read
// off the signatures. A response assembled anywhere else is a response the record-id rule was
// never applied to, and it reaches the wire through `api.resultOf` looking exactly like one that
// had. A third implementation of [Store] is the case this is written for — it will write its own
// Submit, and nothing but this says where its response has to come from.
func TestEverySubmitResponseIsBuiltByResultsOf(t *testing.T) {
	builders, err := submitResponseBuilders(".")
	if err != nil {
		t.Fatalf("the class of functions answering with a *SubmitResponse: %v", err)
	}
	if len(builders) < 3 {
		t.Fatalf("this package answers with a *SubmitResponse from %d functions, which is too few for the derivation to have read the package rather than one file: %v",
			len(builders), sortedNames(builders))
	}
	t.Logf("%d functions in this package answer with a *SubmitResponse: %v", len(builders), sortedNames(builders))

	if stray := straysAmong(builders); len(stray) != 0 {
		t.Errorf("these functions answer with a *SubmitResponse and neither call resultsOf nor hand the whole answer to something that does:\n  %s\nresultsOf is where a refusal loses the record id it was stamped with, once, for both implementations and for whatever refuses next — a response assembled beside it is a response nothing took the id off",
			strings.Join(stray, "\n  "))
	}

	// and the extractor held against a source that violates the rule, so that a run in which it
	// silently matched nothing cannot read as a clean run of a complete gate
	synthetic, err := buildersIn(`package store

func (self *RogueStore) Submit(ctx context.Context, request *SubmitRequest) (*SubmitResponse, error) {
	return &SubmitResponse{Results: []*SubmitResult{{RecordId: 9}}}, nil
}

func (self *RogueStore) polite(batch []*pending) *SubmitResponse {
	return &SubmitResponse{Results: resultsOf(batch)}
}

func (self *RogueStore) passesItOn(batch []*pending) *SubmitResponse {
	return self.polite(batch)
}
`)
	if err != nil {
		t.Fatalf("the extractor's own fixture: %v", err)
	}
	caught := straysAmong(synthetic)
	if !slices.Contains(caught, "RogueStore.Submit") {
		t.Errorf("the extractor read a Submit that assembles its own response and did not report it: %v", caught)
	}
	if slices.Contains(caught, "RogueStore.polite") {
		t.Errorf("the extractor reported a function that calls resultsOf directly: %v", caught)
	}
	if slices.Contains(caught, "RogueStore.passesItOn") {
		t.Errorf("the extractor reported a function that hands the whole answer to one that calls resultsOf: %v", caught)
	}
}

// One function that answers with a *SubmitResponse, and the names its body calls.
type submitBuilder struct {
	name  string
	calls map[string]bool
}

// The name as a call site writes it: `self.transact(...)` and `refuseUnavailable(...)` both
// arrive here without their receiver.
func (self submitBuilder) shortName() string {
	if _, method, found := strings.Cut(self.name, "."); found {
		return method
	}
	return self.name
}

// The builders that reach [resultsOf] neither directly nor by handing the whole answer to
// another builder.
//
// The second half is what makes this a derivation rather than a grep: `PgxStore.Submit` returns
// `self.transact(...)` and never mentions resultsOf, and it is not a violation. Reachability is
// transitive because that chain is three deep.
func straysAmong(builders map[string]submitBuilder) []string {
	reaches := map[string]bool{}
	for name, builder := range builders {
		reaches[name] = builder.calls["resultsOf"]
	}
	// one pass per builder is enough to close a chain that is at most that long
	for range len(builders) {
		for name, builder := range builders {
			if reaches[name] {
				continue
			}
			for other, called := range builders {
				if reaches[other] && builder.calls[called.shortName()] {
					reaches[name] = true
					break
				}
			}
		}
	}
	stray := []string{}
	for name := range builders {
		if !reaches[name] {
			stray = append(stray, name)
		}
	}
	slices.Sort(stray)
	return stray
}

func sortedNames(builders map[string]submitBuilder) []string {
	names := []string{}
	for name := range builders {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Every function in the package at `directory` whose results include a *SubmitResponse, with the
// names its body calls. Test files are excluded: a fake declared in one is not something this
// module ships an answer from.
func submitResponseBuilders(directory string) (map[string]submitBuilder, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	found := map[string]submitBuilder{}
	read := 0
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
		read++
		for key, builder := range buildersOf(parsed) {
			found[key] = builder
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("no non-test Go source was read from %s", directory)
	}
	return found, nil
}

func buildersIn(source string) (map[string]submitBuilder, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	return buildersOf(parsed), nil
}

func buildersOf(file *ast.File) map[string]submitBuilder {
	found := map[string]submitBuilder{}
	for _, declaration := range file.Decls {
		function, isFunction := declaration.(*ast.FuncDecl)
		if !isFunction || function.Body == nil || !answersWithASubmitResponse(function) {
			continue
		}
		name := function.Name.Name
		if owner := receiverTypeOf(function); owner != "" {
			name = owner + "." + name
		}
		builder := submitBuilder{name: name, calls: map[string]bool{}}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				builder.calls[callee.Name] = true
			case *ast.SelectorExpr:
				builder.calls[callee.Sel.Name] = true
			}
			return true
		})
		found[name] = builder
	}
	return found
}

func answersWithASubmitResponse(function *ast.FuncDecl) bool {
	if function.Type.Results == nil {
		return false
	}
	for _, result := range function.Type.Results.List {
		star, isStar := result.Type.(*ast.StarExpr)
		if !isStar {
			continue
		}
		if identifier, isIdentifier := star.X.(*ast.Ident); isIdentifier && identifier.Name == "SubmitResponse" {
			return true
		}
	}
	return false
}
