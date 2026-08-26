package api

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The gate §12.1 A-1 and §5.1 check 7 both ask for: no function in this package builds a
// preimage, computes a MAC, or parses a record itself.
//
// A-1's reason, in its own words: "Two independent implementations of a MAC preimage diverge.
// When they do, the symptom is 'some clients can't send,' intermittently, and the cause is a
// byte-order difference nobody can see." Check 7 says the same thing as an instruction —
// "recompute the §5.4 preimage byte-for-byte using connect/message's encoder — never a local
// reimplementation". The failure this prevents is not a wrong implementation; it is a second
// one that agrees today.
//
// **The class is derived and not typed, and it is derived from connect/message.** What the
// server must not do is what that package does, so the ban is read out of that package's own
// imports on every run: the cryptographic primitives it is built from, and the presentation
// language it frames bytes with. The two standard-library trees a preimage or an encoding can
// come out of at all — crypto/… and encoding/… — are in the class whether or not connect/message
// currently imports something from them, so the edit that adds crypto/sha3 or encoding/binary
// over there does not need a matching edit here. An enumeration would have held hmac and sha256
// and missed subtle, or held all three and missed the syntax codec, which is the specific shape
// of failure this project has walked past twelve times.
//
// **What it cannot see**, stated because a gate whose limits are unwritten gets trusted past
// them: a preimage hand-assembled with append and a tag compared with a hand-written loop names
// no package at all. What covers that is the other direction —
// TestThisPackageDecidesEveryAuthenticatorThroughConnectMessage asserts that the authenticator
// decisions here are calls into connect/message, so a hand-rolled comparison would have to
// replace one of those rather than sit beside it.
func TestNoFunctionInThisPackageBuildsAPreimageComputesAMacOrParsesARecord(t *testing.T) {
	class := secondImplementationClass(t)
	t.Logf("%d packages in the derived class: %v", len(class), class)

	findings := secondImplementationFindings(t, ".", class)
	if len(findings) != 0 {
		t.Fatalf("this package reaches for the record layer's own primitives in %d places, and §12.1 A-1 says it uses connect/message's published surface and nothing else:\n\t%s",
			len(findings), strings.Join(findings, "\n\t"))
	}
}

// The positive control. Without it the test above is a test that could pass by reading nothing:
// an empty class, a directory that yielded no files, or a walk that never visited a call would
// all report exactly the same clean run.
func TestTheSecondImplementationGateFlagsTheControlFixture(t *testing.T) {
	class := secondImplementationClass(t)
	control := filepath.Join("testdata", "secondimplementation")

	findings := secondImplementationFindings(t, control, class)
	if len(findings) == 0 {
		t.Fatalf("%s builds a preimage, takes an HMAC and parses a record with the syntax codec, and the gate reported nothing about it", control)
	}
	t.Logf("the control fixture trips the gate in %d places:\n\t%s", len(findings), strings.Join(findings, "\n\t"))

	// and it trips it on more than one member of the class, so that a class that had collapsed
	// to a single package would still be caught here
	tripped := map[string]bool{}
	for _, finding := range findings {
		for _, path := range class {
			if strings.Contains(finding, path) {
				tripped[path] = true
			}
		}
	}
	if len(tripped) < 3 {
		t.Fatalf("the control fixture trips %d members of the class (%v); it is written to trip a hash, a MAC and the codec, so fewer than three means the class or the walk has lost one",
			len(tripped), tripped)
	}
}

// The other direction: the authenticator decisions this package makes are calls into
// connect/message's verifiers, and not comparisons of its own.
//
// It is what keeps the ban above from being satisfied by deleting the verification instead of
// delegating it. The class is connect/message's own exported Verify* surface, read out of that
// package rather than named here.
func TestThisPackageDecidesEveryAuthenticatorThroughConnectMessage(t *testing.T) {
	verifiers := recordLayerVerifiers(t)
	if len(verifiers) < 2 {
		t.Fatalf("connect/message exports %d Verify* functions (%v); the write path and the read path each need one, so a class this small means the scan missed them",
			len(verifiers), verifiers)
	}

	fileSet, files := parseGoDir(t, ".", false)
	reached := map[string]bool{}
	for _, file := range files {
		local := localNames(file, recordLayerImportPath(t))
		ast.Inspect(file, func(node ast.Node) bool {
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
			if slices.Contains(verifiers, selector.Sel.Name) {
				reached[selector.Sel.Name] = true
				t.Logf("%s at %s", selector.Sel.Name, fileSet.Position(call.Pos()))
			}
			return true
		})
	}
	if len(reached) < 2 {
		t.Fatalf("this package reaches %d of connect/message's verifiers (%v), and §5.1 has two authenticated paths: write_auth on submit and req_auth on read",
			len(reached), reached)
	}
}

// ── the derivation ───────────────────────────────────────────────────────────────────────

// The import path this module names connect/message by, taken from this package's own imports.
func recordLayerImportPath(t *testing.T) string {
	t.Helper()
	_, files := parseGoDir(t, ".", false)
	found := ""
	for _, file := range files {
		for _, imported := range file.Imports {
			path := importPath(t, imported)
			if strings.HasSuffix(path, "/message") {
				if found != "" && found != path {
					t.Fatalf("this package imports two record layers, %s and %s", found, path)
				}
				found = path
			}
		}
	}
	if found == "" {
		t.Fatalf("this package imports no connect/message, so §12.1 A-1's surface is reached by nothing and this gate has nothing to derive a class from")
	}
	return found
}

// Where connect/message's source is, through this module's own replace directive rather than
// through a path written here: the workspace is sibling-checked-out and a developer who moved
// the checkout moved the replace with it.
func recordLayerDir(t *testing.T) string {
	t.Helper()
	root := moduleRoot(t)
	path := recordLayerImportPath(t)

	text, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	directory := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		// replace <module> => <dir>
		if len(fields) != 4 || fields[0] != "replace" || fields[2] != "=>" {
			continue
		}
		if !strings.HasPrefix(path, fields[1]+"/") {
			continue
		}
		directory = filepath.Join(root, filepath.FromSlash(fields[3]), filepath.FromSlash(strings.TrimPrefix(path, fields[1]+"/")))
	}
	if directory == "" {
		t.Fatalf("go.mod carries no replace covering %s, so this gate cannot read the package it derives its class from", path)
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("%s, where the replace for %s points, is not a directory", directory, path)
	}
	return directory
}

// The three names this gate is about, as a guard on the directory it read: a scan that landed
// somewhere else, or on a package that has been split, would otherwise derive an empty class and
// report a clean run.
var recordLayerLandmarks = []string{"EncodeRecord", "ParseRecord", "ComputeWriteAuth"}

// The packages a preimage, a MAC or a record encoding can be built out of.
//
// Two halves, both rules rather than lists. The first is what connect/message imports that is
// outside the standard library — the presentation language it frames every encoding with, and
// anything else it grows a dependency on. The second is the two standard-library trees the
// primitives live in, which is a fact about the standard library's layout and not about this
// package's current imports, so it holds for a primitive nothing has reached for yet.
func secondImplementationClass(t *testing.T) []string {
	t.Helper()
	dir := recordLayerDir(t)
	_, files := parseGoDir(t, dir, false)
	if len(files) == 0 {
		t.Fatalf("%s holds no non-test go file, so the class derived from it is empty and every call here is cleared", dir)
	}
	declared := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			if function, isFunction := decl.(*ast.FuncDecl); isFunction {
				declared[function.Name.Name] = true
			}
		}
	}
	for _, landmark := range recordLayerLandmarks {
		if !declared[landmark] {
			t.Fatalf("%s declares no %s, so it is not the record layer this gate derives its class from", dir, landmark)
		}
	}

	class := map[string]bool{}
	for _, file := range files {
		for _, imported := range file.Imports {
			path := importPath(t, imported)
			if classIncludesPath(path) {
				class[path] = true
			}
		}
	}
	if len(class) == 0 {
		t.Fatalf("%s imports nothing this gate would ban, so the class is empty and the clean run below would mean nothing", dir)
	}
	return sorted(class)
}

// Whether an import path is in the class: a standard-library primitive or encoding tree, or a
// package outside the standard library. The standard library is exactly the set of paths whose
// first segment carries no dot, which is the go command's own rule.
func classIncludesPath(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	if strings.Contains(first, ".") {
		return true
	}
	return first == "crypto" || first == "encoding"
}

// connect/message's exported verifiers, read out of its source.
func recordLayerVerifiers(t *testing.T) []string {
	t.Helper()
	_, files := parseGoDir(t, recordLayerDir(t), false)
	found := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			function, isFunction := decl.(*ast.FuncDecl)
			if !isFunction || function.Recv != nil {
				continue
			}
			if strings.HasPrefix(function.Name.Name, "Verify") {
				found[function.Name.Name] = true
			}
		}
	}
	return sorted(found)
}

// ── the walk ─────────────────────────────────────────────────────────────────────────────

// Every place in one directory that reaches a member of the class: the import that made it
// reachable, and every call written through it.
//
// Both, and not one or the other. The import alone is the total answer — nothing can be called
// without it — and the call sites are what a failure message has to name for the reader to see
// what was actually done.
func secondImplementationFindings(t *testing.T, dir string, class []string) []string {
	t.Helper()
	fileSet, files := parseGoDir(t, dir, true)
	if len(files) == 0 {
		t.Fatalf("%s holds no go file at all, so this walk read nothing", dir)
	}
	findings := []string{}
	for _, file := range files {
		local := map[string]string{}
		for _, imported := range file.Imports {
			path := importPath(t, imported)
			if !slices.Contains(class, path) {
				continue
			}
			findings = append(findings, "imports "+path+" at "+fileSet.Position(imported.Pos()).String())
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
			findings = append(findings, path+"."+selector.Sel.Name+" at "+fileSet.Position(selector.Pos()).String())
			return true
		})
	}
	slices.Sort(findings)
	return slices.Compact(findings)
}

// ── the plumbing ─────────────────────────────────────────────────────────────────────────

var errNoModuleRoot = errors.New("no go.mod above this package, so nothing here can find the workspace it is checked out in")

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving this package's directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal(errNoModuleRoot)
		}
		dir = parent
	}
}

// One directory's go files, with or without the tests beside them.
//
// The tests are included where this gate reads its own package, and that is deliberate: a
// preimage built in a test file is the same second implementation, and it would be the one a
// later reader copies into the package because it was already there.
func parseGoDir(t *testing.T, dir string, includeTests bool) (*token.FileSet, []*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fileSet := token.NewFileSet()
	files := []*ast.File{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", filepath.Join(dir, entry.Name()), err)
		}
		files = append(files, file)
	}
	return fileSet, files
}

func importPath(t *testing.T, imported *ast.ImportSpec) string {
	t.Helper()
	path, err := strconv.Unquote(imported.Path.Value)
	if err != nil {
		t.Fatalf("an import path that is not a quoted string: %s", imported.Path.Value)
	}
	return path
}

// The name an import is written under in one file: its alias, or the last segment of its path.
//
// The last segment is the go command's own default and is right for every package in the class
// here; a package whose declared name differs from its directory would need the type checker to
// resolve, and would be caught by the import finding above regardless.
func localName(imported *ast.ImportSpec, path string) string {
	if imported.Name != nil {
		return imported.Name.Name
	}
	_, last, found := strings.Cut(path, "/")
	if !found {
		return path
	}
	for {
		_, next, more := strings.Cut(last, "/")
		if !more {
			return last
		}
		last = next
	}
}

// Every local name one file binds to one import path.
func localNames(file *ast.File, path string) map[string]bool {
	names := map[string]bool{}
	for _, imported := range file.Imports {
		quoted, err := strconv.Unquote(imported.Path.Value)
		if err != nil || quoted != path {
			continue
		}
		names[localName(imported, path)] = true
	}
	return names
}

func sorted(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	slices.Sort(values)
	return values
}
