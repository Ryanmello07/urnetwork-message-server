package api

import (
	"go/ast"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ── the second implementation, one package over ──────────────────────────────────────────

// The reach that laundering a MAC through a neighbouring package would take.
//
// TestNoFunctionInThisPackageBuildsAPreimageComputesAMacOrParsesARecord derives its class from
// connect/message's own imports, which is the half of a gate this project keeps getting wrong.
// Its scope was the other half and it was typed: the single directory ".". A second
// implementation of the MAC placed in a package api/doc.go's mayimport list already permits, and
// called from checkWriteAuth, passes that gate untouched — and this repository does not merely
// leave that path open, it uses it deliberately. blobd/doc.go argues in as many words that
// §8.3's content_hash lives in blobd *because* the api gate has no exemption in it. That
// argument is sound for one hash and it is a standing invitation for the next one.
//
// So the scope is derived too: every package of this module that api can reach, closed over the
// import graph, because a function api can call is a function that runs in api's process. What
// is written down here is not the ban — the ban is the whole derived class — but the exemptions,
// and that is the direction that cannot understate. A new reach into crypto or into the
// presentation-language codec anywhere in that closure fails this gate until somebody writes it
// down beside a reason, which is what would have happened to the laundered HMAC.
var secondImplementationExemptions = []struct {
	// module-relative, the way §2.2's own directive names a package
	directory string
	reaches   string
	why       string
}{
	{
		directory: "blobd",
		reaches:   "crypto/sha256",
		why: "§8.3's content_hash: SHA-256 over a body's ciphertext, taken whole, in the one place §5.1 check 8 " +
			"and §8.3's bind check both ask for it. It is a content hash and not an authenticator: it takes no key, " +
			"so there is nothing here for a preimage to diverge over",
	},
	{
		directory: "store",
		reaches:   "crypto/sha256",
		why: "§6.3's H(ct_head), which the idempotency claim of §6.1 step (0) stores instead of the head itself, " +
			"because an ephemeral record's head is erased at expiry and a probe that recomputed it would start " +
			"calling a legitimate retry REASON_STREAM_INDEX_REUSED. Keyless, like the hash above",
	},
}

// Nothing api can reach holds a second implementation of a preimage, a MAC or the record codec,
// except what is written down above.
func TestNothingThisPackageCanReachHoldsASecondImplementation(t *testing.T) {
	class := secondImplementationClass(t)
	packages := intraModulePackagesReachableFrom(t, ".")
	if len(packages) < 2 {
		t.Fatalf("this gate found %d packages of this module reachable from api (%v); api imports store and blobd, so the closure has stopped being computed",
			len(packages), packages)
	}
	t.Logf("%d packages of this module are reachable from api: %v", len(packages), sorted(mapKeys(packages)))

	used := map[string]bool{}
	findings := []string{}
	for _, directory := range sorted(mapKeys(packages)) {
		for _, path := range sorted(mapKeys(classReachesIn(t, packages[directory], class))) {
			exempt := false
			for _, exemption := range secondImplementationExemptions {
				if exemption.directory == directory && exemption.reaches == path {
					exempt, used[exemption.directory+" "+exemption.reaches] = true, true
				}
			}
			if !exempt {
				findings = append(findings, directory+" reaches "+path)
			}
		}
	}
	if len(findings) != 0 {
		t.Fatalf("%d package(s) api can call reach the record layer's own primitives, and a MAC one package over is a MAC in api's process:\n\t%s\n\nIf one of these is legitimate, it goes in secondImplementationExemptions with the section that puts it there — a reach nobody wrote down is the laundering this gate exists to refuse.",
			len(findings), strings.Join(findings, "\n\t"))
	}

	// a stale exemption is a hole that outlived its reason
	for _, exemption := range secondImplementationExemptions {
		if !used[exemption.directory+" "+exemption.reaches] {
			t.Fatalf("%s no longer reaches %s, so its exemption clears something that is not there any more: %s",
				exemption.directory, exemption.reaches, exemption.why)
		}
	}
}

// The positive control for the scope, in the direction the class already has one.
//
// Without it the test above passes on a closure that came back empty, on a walk that visited no
// file, and on a class that matched nothing — three ways to report a clean run having read
// nothing, which is this project's most expensive failure. The control fixture is not in the
// closure, so it is measured directly: the gate must find it, and it must find it in a directory
// that no exemption clears.
func TestTheSecondImplementationScopeFindsAPackageOutsideThisOne(t *testing.T) {
	class := secondImplementationClass(t)
	control := filepath.Join("testdata", "secondimplementation")
	reaches := classReachesIn(t, control, class)
	if len(reaches) < 3 {
		t.Fatalf("%s reaches %d members of the class (%v); it is written to reach a hash, a MAC and the codec, so fewer than three means the walk or the class has lost one",
			control, len(reaches), sorted(mapKeys(reaches)))
	}
	for _, exemption := range secondImplementationExemptions {
		if exemption.directory == filepath.ToSlash(control) {
			t.Fatalf("the control fixture is on the exemption list, so the gate above would clear it")
		}
	}
}

// ── §5.1 check 7, decided by connect/message and by nothing else ─────────────────────────

// The function that runs §5.1 check 7 on each path calls one of connect/message's verifiers.
//
// TestThisPackageDecidesEveryAuthenticatorThroughConnectMessage asserts that two distinct
// verifiers are reached *somewhere* in the package, and that is not the same claim: the
// CreateGroup carve-out's own call keeps the count at two while the submit pipeline's check 7
// compares a tag some other way. This binds the claim to the stage that makes the decision.
//
// Both ends are derived. Which check number is the MAC comes from §5.1's table — the row that
// says the preimage is recomputed with connect/message's encoder and "never a local
// reimplementation" — and which function runs it comes from the stage values the pipelines are
// built out of, so a renamed method or a reordered pipeline moves this gate with it.
func TestSpecB51sMacCheckIsDecidedByACallIntoConnectMessage(t *testing.T) {
	number := macCheckNumberOfSpecB51(t)
	verifiers := recordLayerVerifiers(t)
	fileSet, files := parseGoDir(t, ".", false)

	stages := stageFunctionsNumbered(t, files, number)
	if len(stages) < 2 {
		t.Fatalf("§5.1 check %d is run by %d stage function(s) (%v); the submit path and the read path each have one, so this walk has stopped finding them",
			number, len(stages), stages)
	}
	t.Logf("§5.1 check %d is run by %v", number, stages)

	for _, name := range stages {
		declared := functionNamed(files, name)
		if declared == nil {
			t.Fatalf("§5.1 check %d names the stage function %s and this package declares no such function", number, name)
		}
		reached := verifiersCalledIn(files, declared, verifiers, recordLayerImportPath(t))
		if len(reached) == 0 {
			t.Fatalf("%s runs §5.1 check %d and calls none of connect/message's verifiers (%v) at %s; check 7 is \"recompute the §5.4 preimage byte-for-byte using connect/message's encoder — never a local reimplementation\", and a comparison made any other way is the second implementation §12.1 A-1 is written against",
				name, number, verifiers, fileSet.Position(declared.Pos()))
		}
		t.Logf("%s decides check %d through %v", name, number, reached)
	}
}

// ── §4.3.3: the projection is verified once and then never consulted ─────────────────────

// Only the check that verifies the request's own projection ever reads it.
//
// §4.3.3 makes `record_bytes` authoritative and the projection a copy the server verifies and
// then acts on never again, and recordPass's own document says so. The first half is asserted by
// TestEveryProjectionFieldIsCheckedAgainstTheParse; this is the second, and nothing could
// observe it before — a later check that reached for the projection because it was nearer
// behaves identically for exactly as long as check 3 holds, which makes it a defect that appears
// only in combination with a second one.
//
// Both ends are derived. The field is whichever field of a struct in this package holds a
// *protocol.Record — that is what a request's own copy is — and the functions permitted to read
// it are those the check-3 stage reaches, closed over this package's own call graph.
func TestOnlyTheCheckThatVerifiesTheProjectionEverReadsIt(t *testing.T) {
	fileSet, files := parseGoDir(t, ".", false)
	fields := projectionFieldNames(t, files)
	t.Logf("the request's own projection is held in %v", fields)

	number := staticShapeCheckNumberOfSpecB51(t)
	stages := stageFunctionsNumbered(t, files, number)
	if len(stages) == 0 {
		t.Fatalf("no stage of any pipeline runs §5.1 check %d, so this gate has no function to close over", number)
	}
	allowed := functionsReachedFrom(files, stages)
	t.Logf("§5.1 check %d reaches %v", number, sorted(allowed))

	reads, findings := 0, []string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			declared, isFunction := decl.(*ast.FuncDecl)
			if !isFunction || declared.Body == nil {
				continue
			}
			ast.Inspect(declared.Body, func(node ast.Node) bool {
				selector, isSelector := node.(*ast.SelectorExpr)
				if !isSelector || !slices.Contains(fields, selector.Sel.Name) {
					return true
				}
				reads++
				if !allowed[declared.Name.Name] {
					findings = append(findings, declared.Name.Name+" reads ."+selector.Sel.Name+" at "+fileSet.Position(selector.Pos()).String())
				}
				return true
			})
		}
	}
	if reads == 0 {
		t.Fatalf("nothing in this package reads %v at all, so this gate read nothing and would report the same clean run for a check 3 that had stopped comparing", fields)
	}
	if len(findings) != 0 {
		t.Fatalf("%d place(s) outside §5.1 check %d read the request's own projection:\n\t%s\n\n§4.3.3 makes record_bytes authoritative; a check that reads the copy is correct only for as long as check 3 holds, and check 3 is a check somebody can delete.",
			len(findings), number, strings.Join(findings, "\n\t"))
	}
}

// ── the derivations ──────────────────────────────────────────────────────────────────────

// The §5.1 check that is the MAC, read out of §5.1's own table.
//
// The anchor is the instruction §12.1 A-1 and check 7 share — the preimage is recomputed with
// connect/message's encoder and "never a local reimplementation" — rather than the number 7,
// because the number is what a gate would still be asserting after §5.1 renumbered. A table with
// no such row, or with two, fails here rather than leaving the gate above to read nothing.
func macCheckNumberOfSpecB51(t *testing.T) int {
	t.Helper()
	return checkNumberOfSpecB51Row(t, "never a local reimplementation")
}

// The §5.1 check that is the static shape check, by the name §5.1's own row gives it.
func staticShapeCheckNumberOfSpecB51(t *testing.T) int {
	t.Helper()
	return checkNumberOfSpecB51Row(t, "**Static shape.**")
}

// The number of the one §5.1 row carrying a phrase.
func checkNumberOfSpecB51Row(t *testing.T, anchor string) int {
	t.Helper()
	name, document := specBDocument(t)
	lines := strings.Split(document, "\n")

	heading := -1
	for number, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "### 5.1 ") {
			heading = number
		}
	}
	if heading == -1 {
		t.Fatalf("%s carries no '### 5.1 ' heading", name)
	}
	found := []int{}
	for number := heading + 1; number < len(lines); number++ {
		line := strings.TrimSpace(lines[number])
		if strings.HasPrefix(line, "#") {
			break
		}
		if !strings.HasPrefix(line, "|") || !strings.Contains(line, anchor) {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		value, err := strconv.Atoi(strings.TrimSpace(cells[0]))
		if err != nil {
			continue
		}
		found = append(found, value)
	}
	if len(found) != 1 {
		t.Fatalf("%s §5.1 carries %d rows containing %q (%v); this gate reads its check number out of exactly one",
			name, len(found), anchor, found)
	}
	return found[0]
}

// The functions the pipelines name as the run of one numbered check.
//
// Read out of the stage values themselves — every composite literal in the package that carries
// both a `number` and a `run` — rather than out of a function name written here, because the
// pipelines are values so that the order and the wiring can be read rather than asserted about
// some statements.
func stageFunctionsNumbered(t *testing.T, files []*ast.File, want int) []string {
	t.Helper()
	found := []string{}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			literal, isLiteral := node.(*ast.CompositeLit)
			if !isLiteral {
				return true
			}
			number, run := 0, ""
			for _, element := range literal.Elts {
				pair, isPair := element.(*ast.KeyValueExpr)
				if !isPair {
					continue
				}
				key, isIdent := pair.Key.(*ast.Ident)
				if !isIdent {
					continue
				}
				switch key.Name {
				case "number":
					value, isBasic := pair.Value.(*ast.BasicLit)
					if !isBasic {
						continue
					}
					parsed, err := strconv.Atoi(value.Value)
					if err != nil {
						continue
					}
					number = parsed
				case "run":
					if selector, isSelector := pair.Value.(*ast.SelectorExpr); isSelector {
						run = selector.Sel.Name
					}
					if ident, isIdent := pair.Value.(*ast.Ident); isIdent {
						run = ident.Name
					}
				}
			}
			if number == want && run != "" && !slices.Contains(found, run) {
				found = append(found, run)
			}
			return true
		})
	}
	slices.Sort(found)
	return found
}

func functionNamed(files []*ast.File, name string) *ast.FuncDecl {
	for _, file := range files {
		for _, decl := range file.Decls {
			declared, isFunction := decl.(*ast.FuncDecl)
			if isFunction && declared.Name.Name == name {
				return declared
			}
		}
	}
	return nil
}

// The connect/message verifiers one function calls.
func verifiersCalledIn(files []*ast.File, declared *ast.FuncDecl, verifiers []string, path string) []string {
	local := map[string]bool{}
	for _, file := range files {
		for name := range localNames(file, path) {
			local[name] = true
		}
	}
	found := []string{}
	ast.Inspect(declared, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		qualifier, isIdent := selector.X.(*ast.Ident)
		if !isIdent || !local[qualifier.Name] {
			return true
		}
		if slices.Contains(verifiers, selector.Sel.Name) && !slices.Contains(found, selector.Sel.Name) {
			found = append(found, selector.Sel.Name)
		}
		return true
	})
	return found
}

// Every function of this package reachable from a set of entry points, closed over the calls
// written in their bodies.
//
// Calls through the receiver are followed by the receiver's own name rather than by a `self`
// written here, so a file that named its receiver something else would still be walked.
func functionsReachedFrom(files []*ast.File, entries []string) map[string]bool {
	calls := map[string][]string{}
	for _, file := range files {
		for _, decl := range file.Decls {
			declared, isFunction := decl.(*ast.FuncDecl)
			if !isFunction || declared.Body == nil {
				continue
			}
			receiver := ""
			if declared.Recv != nil && len(declared.Recv.List) == 1 && len(declared.Recv.List[0].Names) == 1 {
				receiver = declared.Recv.List[0].Names[0].Name
			}
			ast.Inspect(declared.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				switch target := call.Fun.(type) {
				case *ast.Ident:
					calls[declared.Name.Name] = append(calls[declared.Name.Name], target.Name)
				case *ast.SelectorExpr:
					if qualifier, isIdent := target.X.(*ast.Ident); isIdent && receiver != "" && qualifier.Name == receiver {
						calls[declared.Name.Name] = append(calls[declared.Name.Name], target.Sel.Name)
					}
				}
				return true
			})
		}
	}
	reached := map[string]bool{}
	pending := append([]string{}, entries...)
	for 0 < len(pending) {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if reached[name] {
			continue
		}
		reached[name] = true
		pending = append(pending, calls[name]...)
	}
	return reached
}

// The struct fields of this package that hold a request's own projection: a *protocol.Record.
func projectionFieldNames(t *testing.T, files []*ast.File) []string {
	t.Helper()
	found := []string{}
	for _, file := range files {
		qualifiers := localNames(file, wireImportPath(t))
		ast.Inspect(file, func(node ast.Node) bool {
			structType, isStruct := node.(*ast.StructType)
			if !isStruct || structType.Fields == nil {
				return true
			}
			for _, field := range structType.Fields.List {
				pointer, isPointer := field.Type.(*ast.StarExpr)
				if !isPointer {
					continue
				}
				selector, isSelector := pointer.X.(*ast.SelectorExpr)
				if !isSelector || selector.Sel.Name != "Record" {
					continue
				}
				qualifier, isIdent := selector.X.(*ast.Ident)
				if !isIdent || !qualifiers[qualifier.Name] {
					continue
				}
				for _, name := range field.Names {
					if !slices.Contains(found, name.Name) {
						found = append(found, name.Name)
					}
				}
			}
			return true
		})
	}
	if len(found) == 0 {
		t.Fatal("no struct in this package holds a *protocol.Record, so this gate found no projection to be about and every assertion under it would be vacuous")
	}
	slices.Sort(found)
	return found
}

// The import path this module names connect/protocol by, taken from this package's own imports.
func wireImportPath(t *testing.T) string {
	t.Helper()
	_, files := parseGoDir(t, ".", false)
	found := ""
	for _, file := range files {
		for _, imported := range file.Imports {
			path := importPath(t, imported)
			if strings.HasSuffix(path, "/protocol") {
				if found != "" && found != path {
					t.Fatalf("this package imports two wire protocols, %s and %s", found, path)
				}
				found = path
			}
		}
	}
	if found == "" {
		t.Fatal("this package imports no connect/protocol, so there is no wire Record for this gate to look for")
	}
	return found
}

// Every package of this module reachable from one directory, closed over the import graph, as
// module-relative directory to directory on disk.
func intraModulePackagesReachableFrom(t *testing.T, from string) map[string]string {
	t.Helper()
	root := moduleRoot(t)
	module := moduleImportPath(t)

	start, err := filepath.Abs(from)
	if err != nil {
		t.Fatalf("resolving %s: %v", from, err)
	}
	found := map[string]string{}
	pending := []string{start}
	for 0 < len(pending) {
		directory := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		relative, err := filepath.Rel(root, directory)
		if err != nil {
			t.Fatalf("%s is not under %s: %v", directory, root, err)
		}
		relative = filepath.ToSlash(relative)
		if _, seen := found[relative]; seen {
			continue
		}
		found[relative] = directory

		_, files := parseGoDir(t, directory, false)
		if len(files) == 0 {
			t.Fatalf("%s holds no non-test go file, so this closure read nothing about it", directory)
		}
		for _, file := range files {
			for _, imported := range file.Imports {
				path := importPath(t, imported)
				inside, within := strings.CutPrefix(path, module+"/")
				if !within {
					continue
				}
				pending = append(pending, filepath.Join(root, filepath.FromSlash(inside)))
			}
		}
	}
	return found
}

// This module's own import path, from its go.mod.
func moduleImportPath(t *testing.T) string {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
		if path, declared := strings.CutPrefix(strings.TrimSpace(line), "module "); declared {
			return strings.TrimSpace(path)
		}
	}
	t.Fatal("go.mod declares no module path, so nothing here can tell this module's own packages from anybody else's")
	return ""
}

// Every place in one directory that reaches a member of the class, keyed by the class member.
//
// The same walk TestNoFunctionInThisPackageBuildsAPreimageComputesAMacOrParsesARecord runs, with
// the class member kept rather than folded into a sentence, because the scope gate has to answer
// "which member" to check it against an exemption.
func classReachesIn(t *testing.T, dir string, class []string) map[string][]string {
	t.Helper()
	fileSet, files := parseGoDir(t, dir, true)
	if len(files) == 0 {
		t.Fatalf("%s holds no go file at all, so this walk read nothing", dir)
	}
	reaches := map[string][]string{}
	for _, file := range files {
		local := map[string]string{}
		for _, imported := range file.Imports {
			path := importPath(t, imported)
			if !slices.Contains(class, path) {
				continue
			}
			reaches[path] = append(reaches[path], "imported at "+fileSet.Position(imported.Pos()).String())
			local[localName(imported, path)] = path
		}
		if len(local) == 0 {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, isSelector := node.(*ast.SelectorExpr)
			if !isSelector {
				return true
			}
			qualifier, isIdent := selector.X.(*ast.Ident)
			if !isIdent {
				return true
			}
			path, named := local[qualifier.Name]
			if !named {
				return true
			}
			reaches[path] = append(reaches[path], selector.Sel.Name+" at "+fileSet.Position(selector.Pos()).String())
			return true
		})
	}
	return reaches
}

func mapKeys[Value any](values map[string]Value) map[string]bool {
	keys := map[string]bool{}
	for key := range values {
		keys[key] = true
	}
	return keys
}
