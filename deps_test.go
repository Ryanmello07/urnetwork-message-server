// The dependency rule of spec B §2.2, the layering the package documents of this module state,
// and the encoding line §13 item 28 names — as tests rather than as the CI shell lines the
// spec prints beside them.
//
// Why the dependency rule exists, in §2.2's own words: "the operator's model package *is* the
// account identity layer, and §4.2 forbids the message server from consulting it." §5.2 spells
// out the consequence — every check this server *can* perform it can also skip, so a server
// that can reach account identity eventually joins against it, and clients that come to depend
// on what it decided have made it a participant in a security argument it is not supposed to be
// in. The cost of the rule is stated in §2.2 as well: server/task is unavailable, which is why
// §7.4 specifies an in-process scheduler behind a Postgres advisory lock instead. A rule with
// its reason written beside it is a rule the next contributor argues with instead of deleting.
//
// Two reasons this is a test and not the shell line. A CI-only gate does not run before a
// developer pushes, so the first thing it can say is that the branch is already red. And the
// shell line is a grep over a hand-typed alternation:
//
//	go list -deps ./... | grep -E 'urnetwork/server/(model|session|task|controller|api)|urnetwork/sdk' && exit 1
//
// which is the shape this project has been walked past a dozen times. A typed list of what is
// banned understates the real class every time, and it does it silently — most recently a
// constant-time gate that banned six comparator names and missed bytes.HasPrefix. It also
// mismatches in the other direction: as a substring match it trips on
// urnetwork/server/modelling, and §13 item 8's companion line, go list -deps ./... | grep
// connect/mls, trips on github.com/urnetwork/connect/mls/syntax — the presentation-language
// codec that connect/message, a package §2.2 explicitly ALLOWS, is built on, and which is not
// an MLS implementation at all.
//
// So the direction is turned around, the way connect's own import gate does it (see
// TestTheCryptoIsBuiltFromExactlyThesePackages in connect/mls/crypto_test.go, whose comment
// argues it at length). What is written down here is the whole of what §2.2 permits, and
// everything else fails until somebody writes it down. That is the direction the shell line
// does not check at all: a dependency nobody thought to ban passes the grep every time.
//
// The forbidden list below is therefore not what decides the outcome — the allow list is,
// because a forbidden path is by construction not an allowed one. What the forbidden list buys
// is a failure message naming the section a reader has to go read, and a class to hold the
// positive control against; TestEverythingSpecB22ForbidsIsOnTheForbiddenList is what keeps it
// from decaying into decoration, by reading that section rather than trusting the copy.
//
// Four things this file learned the hard way, each of them a green run that had measured
// nothing:
//
//   - A closure is measured per build configuration. go list -deps ./... answers for whichever
//     GOOS, GOARCH, CGO_ENABLED and -tags the shell carried, so an import behind //go:build
//     linux is invisible on a Windows developer box and links perfectly well into the
//     StatefulSet of §2.3. The configurations come from release-platforms.txt, the same file
//     the release job builds from, and the host's own is measured beside them.
//   - A closure that was measured is not a closure that covers the module. Narrowing the
//     pattern from ./... to ./cmd/... leaves a green run reporting two of eleven packages, and
//     nothing here had an expectation to compare "two of this module" against. The package set
//     is derived from the tree, and every package in it must be reached.
//   - An import path is a claim about where code came from, and a replace directive can put
//     anything behind an allowed one without touching the path. The go command reports the
//     directory it actually read, and that directory's own go.mod has to agree.
//   - Inside the module the layering was prose only. Eight package documents state a "May
//     import:" contract, two of them structural halves of §11.1, and nothing read one.
package messageserver

import (
	"errors"
	"fmt"
	"go/build"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A rule over import paths: one path, matched exactly, or with everything beneath it when
// subtree is set. Prefixes are matched at the segment boundary, so .../server/model covers
// .../server/model/counters and does not cover .../server/modelling — the two things the
// substring grep of §2.2 gets respectively right by luck and wrong.
type rule struct {
	path    string
	subtree bool
}

func (self rule) covers(path string) bool {
	if path == self.path {
		return true
	}
	return self.subtree && strings.HasPrefix(path, self.path+"/")
}

// The whole of what spec B §2.2 ALLOWS, at the granularity §2.2 states it. The standard
// library and this module's own packages are not on the list because they are derived from
// what the go command reports rather than typed out here — see violations.
//
// Two of these are narrower than a module: §2.2 allows github.com/urnetwork/server at its root
// package only, and names three packages of connect rather than connect as a whole. The four
// third-party modules are as §2.2 writes them, and are listed even though nothing in this
// module imports one yet: this list is the policy, not the go.mod. Their own transitive
// modules are deliberately absent — the day pgx lands, its dependencies fail this gate until
// somebody looks at them and writes them down, which is the entire point.
//
// github.com/urnetwork/connect/mls/syntax is deliberately NOT here, and it is the entry the
// next contributor will want to add. connect/message imports it — aad.go, attachment.go,
// codec.go and writeauth.go all do — so the first package of this module that parses a record
// will fail this gate. That failure is correct and is not a defect in this file: §2.2 allows
// connect/message, while §5.3 and §13 item 8 say the binary must not link connect/mls and
// assert it with a grep that also matches connect/mls/syntax. The two cannot both hold as
// written. The resolution belongs in the spec — amend §13 item 8 to the package rather than
// the prefix, since a TLS presentation-language codec is not an MLS implementation — and then
// in this list, not in a quiet edit to whichever of the two is easier to change.
var allowedDependencies = []rule{
	{path: "github.com/urnetwork/server"},
	{path: "github.com/urnetwork/connect"},
	{path: "github.com/urnetwork/connect/protocol", subtree: true},
	{path: "github.com/urnetwork/connect/message", subtree: true},
	{path: "github.com/urnetwork/glog", subtree: true},
	{path: "github.com/jackc/pgx/v5", subtree: true},
	{path: "github.com/redis/go-redis/v9", subtree: true},
	{path: "github.com/minio/minio-go/v7", subtree: true},
	{path: "github.com/prometheus/client_golang", subtree: true},
}

// What §2.2 FORBIDS by name, plus the one §5.3 forbids by name. Redundant against the allow
// list on purpose: these produce a failure message that names the reason instead of the
// generic one, and they are the class the positive control is held against.
//
// The five operator packages are subtrees, because a package under server/model is the same
// account identity layer one directory down. connect/mls is exact, because its only child
// today is the presentation-language codec described above; any other child of it is caught by
// the allow list, which is the direction that cannot understate.
//
// None of this is policy retyped and then left to rot. TestEverythingSpecB22ForbidsIsOnThe-
// ForbiddenList parses §2.2's FORBIDDEN block out of the spec document and fails when an entry
// has gone missing from this list, which is what deleting five of these used to survive.
var forbiddenDependencies = []rule{
	{path: "github.com/urnetwork/server/model", subtree: true},
	{path: "github.com/urnetwork/server/session", subtree: true},
	{path: "github.com/urnetwork/server/task", subtree: true},
	{path: "github.com/urnetwork/server/controller", subtree: true},
	{path: "github.com/urnetwork/server/api", subtree: true},
	{path: "github.com/urnetwork/sdk", subtree: true},
	{path: "github.com/urnetwork/connect/mls"},
}

func isAllowed(path string) bool {
	return slices.ContainsFunc(allowedDependencies, func(allowed rule) bool { return allowed.covers(path) })
}

func isForbidden(path string) bool {
	return slices.ContainsFunc(forbiddenDependencies, func(banned rule) bool { return banned.covers(path) })
}

// ── what the go command is asked, and under which configuration ──────────────────────────

// One dependency as the go command reports it: the import path, whether this row is the
// package compiled for its own test, whether this toolchain counts it as part of the standard
// library, what it imports, the module it was resolved from, whether that module is this one,
// and the directory a replace directive pointed that module at.
type dependency struct {
	path       string
	variant    bool
	standard   bool
	imports    []string
	module     string
	main       bool
	replaceDir string
}

// The go list template the whole gate is parsed out of. Standard, Module.Main and Imports are
// asked of the go command rather than decided here, so "is this the standard library", "is
// this our own code" and "what does it reach" are answers from the thing that resolved the
// build, not a prefix match this file invented.
//
// Module.Replace.Dir is on the end because it is the only field that says where the code
// actually came from. Module.Path is the path the go.mod asked for, which a replace does not
// change; the directory is what a replace does change, and the two disagreeing is the one
// substitution a list of import paths cannot see.
const goListFormat = "{{.ImportPath}}\t{{.Standard}}\t{{join .Imports \",\"}}\t{{with .Module}}{{.Path}}\t{{.Main}}\t{{with .Replace}}{{.Dir}}{{end}}{{end}}"

// The manifest of what this module is released for. Read by this gate and by the release job
// in .github/workflows/gates.yml, so what ships and what is measured are one list rather than
// two that happen to agree today.
const releasePlatformsFile = "release-platforms.txt"

var (
	errPlatformShape  = errors.New("a platform line is <goos>/<goarch> followed by optional key=value settings")
	errUnknownSetting = errors.New("is not a setting this manifest defines, so the release build would apply something this gate does not")
)

// One configuration the go command resolves the module for.
//
// All four fields decide which files a build reads. GOOS and GOARCH decide it through build
// constraints, CGO_ENABLED decides it a second time for every package with a cgo half and a
// pure-Go half, and tags decide it a third. A gate that measures one of these has measured one
// of them, and says nothing whatever about the rest.
type buildConfiguration struct {
	goos   string
	goarch string
	cgo    string
	tags   string
	source string
}

func (self buildConfiguration) String() string {
	described := fmt.Sprintf("%s/%s cgo=%s", self.goos, self.goarch, self.cgo)
	if self.tags != "" {
		described += " tags=" + self.tags
	}
	return described + " [" + self.source + "]"
}

// The environment for one go command invocation, built rather than inherited.
//
// Every variable that decides which files the go command reads is stripped out of the shell's
// environment and written back from the configuration, so the answer belongs to the
// configuration and not to whatever the developer happened to export. GOFLAGS goes too and is
// never written back: it can carry -tags, and a build tag arriving through the environment is
// exactly the invisible configuration this loop exists to make visible.
func (self buildConfiguration) environment() []string {
	written := map[string]string{
		"GOOS":        self.goos,
		"GOARCH":      self.goarch,
		"CGO_ENABLED": self.cgo,
	}
	kept := []string{}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		// windows environment names are case-insensitive, so the comparison has to be too
		name = strings.ToUpper(name)
		if _, replaced := written[name]; replaced || name == "GOFLAGS" {
			continue
		}
		kept = append(kept, entry)
	}
	for name, value := range written {
		kept = append(kept, name+"="+value)
	}
	// deterministic, so two failure messages from two runs are comparable
	slices.Sort(kept)
	return kept
}

// The configurations this module is measured for: every one the release manifest names, and
// the one the developer running this test would get from a plain go build.
//
// The host is measured as well as the released set because the two catch different things. The
// manifest catches an import behind a constraint for the platform that ships and nothing else
// builds; the host catches the reverse, a package that does not compile at all for the person
// holding it. Neither substitutes for the other.
func measuredConfigurations(t *testing.T) []buildConfiguration {
	t.Helper()
	found := releasedConfigurations(t)
	host := hostConfiguration(t)
	for index, configuration := range found {
		if configuration.goos == host.goos && configuration.goarch == host.goarch &&
			configuration.cgo == host.cgo && configuration.tags == host.tags {
			found[index].source += " and " + host.source
			return found
		}
	}
	return append(found, host)
}

// The released set, from the manifest.
func releasedConfigurations(t *testing.T) []buildConfiguration {
	t.Helper()
	text, err := os.ReadFile(releasePlatformsFile)
	if err != nil {
		t.Fatalf("%s: %v; this gate does not fall back to the one platform it happens to be run on", releasePlatformsFile, err)
	}
	found := []buildConfiguration{}
	for number, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		configuration, err := parsePlatform(line)
		if err != nil {
			t.Fatalf("%s line %d: %v", releasePlatformsFile, number+1, err)
		}
		configuration.source = fmt.Sprintf("%s line %d", releasePlatformsFile, number+1)
		found = append(found, configuration)
	}
	if len(found) == 0 {
		t.Fatalf("%s names no platform, so this gate would measure only the host it is run on", releasePlatformsFile)
	}
	return found
}

func parsePlatform(line string) (buildConfiguration, error) {
	fields := strings.Fields(line)
	goos, goarch, split := strings.Cut(fields[0], "/")
	if !split || goos == "" || goarch == "" {
		return buildConfiguration{}, fmt.Errorf("%q: %w", fields[0], errPlatformShape)
	}
	// cgo is part of the configuration whether or not a line says so, and the default has to be
	// one of the two values rather than whatever the shell was carrying
	configuration := buildConfiguration{goos: goos, goarch: goarch, cgo: "0"}
	for _, setting := range fields[1:] {
		name, value, split := strings.Cut(setting, "=")
		if !split {
			return buildConfiguration{}, fmt.Errorf("%q: %w", setting, errPlatformShape)
		}
		switch name {
		case "cgo":
			configuration.cgo = value
		case "tags":
			configuration.tags = value
		default:
			return buildConfiguration{}, fmt.Errorf("%q %w", name, errUnknownSetting)
		}
	}
	return configuration, nil
}

// What a plain go build on this machine would target, asked of the go command rather than read
// off runtime.GOOS: a suite run from a cross-compiling shell is measuring that shell's target,
// and the measurement line should say which one it was.
func hostConfiguration(t *testing.T) buildConfiguration {
	t.Helper()
	answered := strings.Split(strings.ReplaceAll(goOutput(t, nil, "env", "GOOS", "GOARCH", "CGO_ENABLED"), "\r\n", "\n"), "\n")
	values := []string{}
	for _, line := range answered {
		if line = strings.TrimSpace(line); line != "" {
			values = append(values, line)
		}
	}
	if len(values) != 3 {
		t.Fatalf("go env GOOS GOARCH CGO_ENABLED answered %v, which is not the three values this gate asked for", values)
	}
	return buildConfiguration{goos: values[0], goarch: values[1], cgo: values[2], source: "this developer's own build"}
}

// The go command, found rather than assumed. The toolchain is on PATH in CI and on a developer
// box; the toolchain that compiled this test is the fallback, so a suite run from an editor
// that did not inherit a PATH still runs the gate. If neither is there the gate FAILS: a gate
// that skips is a gate that is off, and it reports the same green run as a gate that passed.
func goCommand(t *testing.T) string {
	t.Helper()
	if found, err := exec.LookPath("go"); err == nil {
		return found
	}
	fallback := filepath.Join(build.Default.GOROOT, "bin", "go")
	found, err := exec.LookPath(fallback)
	if err != nil {
		t.Fatalf("no go command on PATH and none at %s (%v); this gate does not skip", fallback, err)
	}
	return found
}

// One go command invocation. A nil environment means this process's own, which is used only
// for the question that asks what that environment is; everything else passes one built from a
// configuration.
//
// Every failure here is fatal for one reason: an invocation that returned nothing is
// indistinguishable, in the pass or fail the suite prints, from a module that depends on
// nothing forbidden.
func goOutput(t *testing.T, environment []string, arguments ...string) string {
	t.Helper()
	command := exec.Command(goCommand(t), arguments...)
	command.Env = environment
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(command.Args, " "), err, stderr.String())
	}
	return stdout.String()
}

// The dependency closure the go command reports for a set of patterns under one configuration.
func dependenciesOf(t *testing.T, configuration buildConfiguration, arguments ...string) []dependency {
	t.Helper()
	flags := []string{"list", "-deps", "-f", goListFormat}
	if configuration.tags != "" {
		flags = append(flags, "-tags", configuration.tags)
	}
	arguments = append(flags, arguments...)
	described := fmt.Sprintf("go %s under %s", strings.Join(arguments, " "), configuration)
	found := parseDependencies(t, described, goOutput(t, configuration.environment(), arguments...))
	if len(found) == 0 {
		t.Fatalf("%s listed no package at all, so this gate read nothing", described)
	}
	return found
}

// The dependencies in one block of go list output.
//
// Carriage returns are stripped before anything else. This repository is checked out on a
// platform where core.autocrlf is true at system scope, and a parser anchored on "\n" alone
// reads a CRLF block as one long malformed line — which is a gate reporting clean having read
// nothing, the exact inversion this file exists to prevent.
func parseDependencies(t *testing.T, source string, text string) []dependency {
	t.Helper()
	found := []dependency{}
	for number, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			t.Fatalf("%s line %d is not in the format this gate reads: %q", source, number+1, line)
		}
		// a test variant is reported as "<path> [<path>.test]"; the dependency is the package
		// on the left, and the variant marker would otherwise miss every rule below
		path, _, variant := strings.Cut(fields[0], " [")
		standard, err := parseBool(fields[1])
		if err != nil {
			t.Fatalf("%s line %d: %v", source, number+1, err)
		}
		imports := []string{}
		if fields[2] != "" {
			imports = strings.Split(fields[2], ",")
		}
		module := fieldAt(fields, 3)
		if !standard && module == "" {
			// every non-standard package the go command resolves belongs to some module, so a
			// row without one means the template and this parser have drifted apart and the
			// gate is about to decide where code came from without having been told
			t.Fatalf("%s line %d: %s is outside the standard library and the go command named no module for it", source, number+1, path)
		}
		found = append(found, dependency{
			path:       path,
			variant:    variant,
			standard:   standard,
			imports:    imports,
			module:     module,
			main:       fieldAt(fields, 4) == "true",
			replaceDir: fieldAt(fields, 5),
		})
	}
	return found
}

// A field the go template may not have emitted at all: a standard library package has no
// module, so those rows stop after the import list.
func fieldAt(fields []string, index int) string {
	if index < len(fields) {
		return fields[index]
	}
	return ""
}

// Strict rather than strconv.ParseBool, which also accepts "1", "t" and "T": the template
// writes exactly one of two words, and anything else means the format string and this parser
// have drifted apart.
func parseBool(field string) (bool, error) {
	switch field {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%q is neither true nor false", field)
}

// ── the rule itself ──────────────────────────────────────────────────────────────────────

// The dependencies of a set that the rule refuses, split by how they are refused.
//
// Allowedness decides. A path the allow list covers is not a violation whatever else it
// matches, which is why TestNoAllowedDependencyIsAlsoForbidden exists: widening the allow list
// is the one edit that can turn this gate off, so the two lists are checked against each other
// rather than trusted to stay disjoint.
//
// The standard library and this module's own packages are skipped, both of them from what the
// go command reported rather than from a prefix typed here. What that skip discards is every
// bit of intra-module structure, which is why the layering has a gate of its own below.
func violations(deps []dependency) (forbidden []string, unlisted []string) {
	for _, dep := range deps {
		if dep.standard || dep.main {
			continue
		}
		if isAllowed(dep.path) {
			continue
		}
		unlisted = append(unlisted, dep.path)
		if isForbidden(dep.path) {
			forbidden = append(forbidden, dep.path)
		}
	}
	slices.Sort(forbidden)
	slices.Sort(unlisted)
	return slices.Compact(forbidden), slices.Compact(unlisted)
}

// The dependencies whose path the allow list permits and whose code came from somewhere the
// allow list does not.
//
// An import path is a claim. A require for github.com/urnetwork/connect/message beside a
// replace of it to ../anything leaves the path exactly where §2.2 put it, and Module.Path still
// reports the path that was asked for, because a replace does not change it. What a replace
// changes is the directory, and the go command reports that, so the claim is checked against
// the module that directory's own go.mod declares.
//
// Only allowed paths are examined. An unlisted one is already being refused above, and naming
// it twice buries the interesting line under the obvious one.
//
// What this cannot see is a directory that declares itself to be the module it stands in for.
// At that point the lie is inside a go.mod rather than inside the import graph, and it belongs
// to go.sum and to a reviewer, not to a dependency gate.
func substitutions(t *testing.T, deps []dependency) []string {
	t.Helper()
	found := []string{}
	for _, dep := range deps {
		if dep.standard || dep.main || !isAllowed(dep.path) {
			continue
		}
		origin := dep.module
		if dep.replaceDir != "" {
			origin = modulePathDeclaredAt(t, dep.replaceDir)
		}
		if isAllowed(origin) {
			continue
		}
		found = append(found, fmt.Sprintf("%s, whose code the go command read from module %s", dep.path, origin))
	}
	slices.Sort(found)
	return slices.Compact(found)
}

var errNoModuleDirective = errors.New("has no module directive in it, so it declares no module path at all")

// The module path a replacement directory declares for itself.
func modulePathDeclaredAt(t *testing.T, directory string) string {
	t.Helper()
	name := filepath.Join(directory, "go.mod")
	text, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("a replace directive points at %s and this gate cannot read %s (%v), so it cannot say where that code came from", directory, name, err)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
		fields := strings.Fields(strings.TrimSuffix(line, "\r"))
		if len(fields) >= 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	t.Fatalf("%s %v", name, errNoModuleDirective)
	return ""
}

// ── what this module is, derived from the tree ───────────────────────────────────────────

// Every package directory of this module, as import path against directory.
//
// Derived by walking the tree, never listed. The point of the coverage check below is that the
// measured closure covers the module, and a check whose idea of "the module" is a list typed
// beside it agrees with any narrowing of the go list pattern that also narrows the list.
//
// What is skipped is the go command's own rule for what it will not walk into — a directory
// called testdata, and one whose name begins with a dot or an underscore — so the two agree by
// construction rather than by coincidence.
func packagesOfThisModule(t *testing.T) map[string]string {
	t.Helper()
	root := strings.TrimSpace(goOutput(t, nil, "list", "-m", "-f", "{{.Path}}"))
	if root == "" {
		t.Fatal("go list -m named no module, so this gate has no import path to build the package set from")
	}
	directories := map[string]string{}
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := entry.Name()
		if entry.IsDir() {
			if path == "." {
				return nil
			}
			if name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(name) != ".go" {
			return nil
		}
		directory := filepath.Dir(path)
		importPath := root
		if directory != "." {
			importPath = root + "/" + filepath.ToSlash(directory)
		}
		directories[importPath] = directory
		return nil
	})
	if err != nil {
		t.Fatalf("walking this module for its packages: %v", err)
	}
	if len(directories) == 0 {
		t.Fatal("this module holds no package directory at all, which is not a module this gate can check")
	}
	return directories
}

// The directive a package document carries saying what of this module that package may import.
//
// A directive rather than the prose beside it, because the prose cannot be parsed and must not
// be guessed at: store's own paragraph names redact twice, once as something it may import and
// once, three sentences later, inside the reason it may not import server/model. Go strips a
// //word:word line from rendered documentation, so the machine-readable half sits against the
// sentence it restates without appearing twice in godoc.
//
// The list names this module's own packages only. What a package may import from outside the
// module is §2.2's list and is checked above; this is the half §2.2 says nothing about, and
// which two package documents make a security argument out of — metrics must not be able to
// accept a redact type, and redact must reach nothing, because every package imports it.
const mayImportDirective = "//urmsg:mayimport"

// The one token that means an entrypoint: a process that cannot import a package cannot start
// it, so cmd/ declares breadth rather than a list that would be edited on every wiring change
// and reviewed on none.
const anyPackageOfThisModule = "*"

type layer struct {
	importPath string
	directory  string
	any        bool
	allowed    []string
}

// What every package of this module declares. Every package must declare something: a package
// with no directive is a package the layering says nothing about, and the whole failure being
// fixed here is a contract that was written down and never read.
func layersOfThisModule(t *testing.T, packages map[string]string) map[string]layer {
	t.Helper()
	layers := map[string]layer{}
	for importPath, directory := range packages {
		declared, count := declarationsIn(t, directory)
		if count == 0 {
			t.Fatalf("%s carries no %s directive, so nothing states what of this module it may import; every package of this module declares one, an entrypoint as %s %s",
				importPath, mayImportDirective, mayImportDirective, anyPackageOfThisModule)
		}
		if count > 1 {
			t.Fatalf("%s carries %d %s directives and this gate would have to choose between them", importPath, count, mayImportDirective)
		}
		current := layer{importPath: importPath, directory: directory}
		for _, token := range declared {
			if token == anyPackageOfThisModule {
				if len(declared) != 1 {
					t.Fatalf("%s declares %s alongside %v; breadth and a list are two different contracts", importPath, anyPackageOfThisModule, declared)
				}
				current.any = true
				continue
			}
			named := namedPackage(t, importPath, token, packages)
			if named == importPath {
				t.Fatalf("%s names itself in its %s directive", importPath, mayImportDirective)
			}
			if slices.Contains(current.allowed, named) {
				t.Fatalf("%s names %s twice in its %s directive", importPath, token, mayImportDirective)
			}
			current.allowed = append(current.allowed, named)
		}
		slices.Sort(current.allowed)
		layers[importPath] = current
	}
	return layers
}

// A directive token resolved to an import path. Module-relative, because a bare last element is
// ambiguous the day two directories share one, and this gate would then be matching on a name
// instead of on a package.
func namedPackage(t *testing.T, declaring string, token string, packages map[string]string) string {
	t.Helper()
	known := []string{}
	for importPath, directory := range packages {
		if filepath.ToSlash(directory) == token {
			return importPath
		}
		known = append(known, filepath.ToSlash(directory))
	}
	slices.Sort(known)
	t.Fatalf("%s names %q in its %s directive and this module has no such package; it holds %v", declaring, token, mayImportDirective, known)
	return ""
}

// The directive tokens in one package directory, and how many directives were found. Every .go
// file in the directory is read, tests included, so the directive cannot be hidden somewhere
// the package document is not.
func declarationsIn(t *testing.T, directory string) ([]string, int) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("reading %s: %v", directory, err)
	}
	declared, count := []string{}, 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
			continue
		}
		name := filepath.Join(directory, entry.Name())
		text, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			rest, found := strings.CutPrefix(line, mayImportDirective)
			if !found || (rest != "" && !strings.HasPrefix(rest, " ")) {
				continue
			}
			count++
			declared = append(declared, strings.Fields(rest)...)
		}
	}
	return declared, count
}

// ── the measurement ──────────────────────────────────────────────────────────────────────

// One closure, and what it turned out to be made of.
type measurement struct {
	configuration buildConfiguration
	what          string
	deps          []dependency
	own           int
	standard      int
	outside       int
}

func (self measurement) String() string {
	return fmt.Sprintf("%s, %s: %d packages in the closure — %d of this module, %d standard library, %d outside both",
		self.configuration, self.what, len(self.deps), self.own, self.standard, self.outside)
}

// Every closure this gate reads: each configuration crossed with each of the two patterns.
//
// Measured twice per configuration: the packages this module builds, which is what §2.2's own
// gate reads, and the same packages plus their tests, which it does not. A forbidden import in
// a _test.go file is a forbidden import — it links the operator's identity layer into a binary
// this repository builds, and a fixture is exactly where somebody reaches for one — and
// go list -deps ./... cannot see it.
func measureThisModule(t *testing.T) []measurement {
	t.Helper()
	measurements := []measurement{}
	for _, configuration := range measuredConfigurations(t) {
		assertTheConfigurationTook(t, configuration)
		for _, pattern := range []struct {
			what      string
			arguments []string
		}{
			{what: "the packages this module builds", arguments: []string{"./..."}},
			{what: "those packages and their tests", arguments: []string{"-test", "./..."}},
		} {
			current := measurement{
				configuration: configuration,
				what:          pattern.what,
				deps:          dependenciesOf(t, configuration, pattern.arguments...),
			}
			for _, dep := range current.deps {
				switch {
				case dep.standard:
					current.standard++
				case dep.main:
					current.own++
				default:
					current.outside++
				}
			}
			measurements = append(measurements, current)
		}
	}
	return measurements
}

// The go command answered for the configuration it was handed.
//
// Without this the loop above is a loop over labels. environment() could stop overriding
// anything at all — return the shell's own environment unchanged — and every closure would be
// the host's while six log lines named three configurations, which is a gate reporting one
// build as three and is worse than the single build it replaced. So the same environment that
// resolves the closure is asked what it resolved for, and the answer has to be the question.
func assertTheConfigurationTook(t *testing.T, configuration buildConfiguration) {
	t.Helper()
	answered := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(goOutput(t, configuration.environment(), "env", "GOOS", "GOARCH", "CGO_ENABLED"), "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			answered = append(answered, line)
		}
	}
	wanted := []string{configuration.goos, configuration.goarch, configuration.cgo}
	if !slices.Equal(answered, wanted) {
		t.Fatalf("this gate asked the go command for %v and it answered for %v, so %s was measured under a configuration it does not name", wanted, answered, configuration)
	}
}

// ── the controls ─────────────────────────────────────────────────────────────────────────

// A go list block in the exact format the gate reads, with violations planted in it, and
// beside it a block with none.
//
// Both halves are needed. A matcher that flags nothing passes the clean control, a matcher that
// flags everything passes the planted one, and either of them reports the green run of a
// working gate on the real module. Composed from escapes rather than written as a raw string
// literal, so the fixture is the same bytes whatever this file's line endings are.
//
// The last two rows of the hand-written half are the segment boundary, one on each side of it,
// and they are here because that boundary is the whole difference between this matcher and the
// grep §2.2 prints. server/modelling is not the account identity layer and must come back
// merely unlisted; connect/messagex is not connect/message and must not inherit its permission.
// A matcher that compared bare prefixes agrees with every other row in this block.
//
// Fields are: import path, standard, imports, module, main, replacement directory.
var handWrittenControlRows = []string{
	"fmt\ttrue\t\t\t\t",
	"github.com/urnetwork/message-server/api\tfalse\tgithub.com/urnetwork/message-server/store\tgithub.com/urnetwork/message-server\ttrue\t",
	"github.com/urnetwork/server\tfalse\t\tgithub.com/urnetwork/server\tfalse\t",
	"golang.org/x/crypto/chacha20poly1305\tfalse\t\tgolang.org/x/crypto\tfalse\t",
	"github.com/urnetwork/server/modelling\tfalse\t\tgithub.com/urnetwork/server\tfalse\t",
	"github.com/urnetwork/connect/messagex\tfalse\t\tgithub.com/urnetwork/connect\tfalse\t",
}

var handWrittenUnlisted = []string{
	"golang.org/x/crypto/chacha20poly1305",
	"github.com/urnetwork/server/modelling",
	"github.com/urnetwork/connect/messagex",
}

// One row per entry of forbiddenDependencies, and one for the package a directory below it,
// generated from that list rather than typed beside it.
//
// Generation buys coverage, not pinning. Every entry gets a round trip through the matcher, so
// an entry that could never match anything — a typo, a subtree flag the wrong way round — is
// exercised instead of decorating the list; and the flag is exercised in both directions, since
// a subtree entry must catch the package one directory below it and an exact entry must not.
// What generation cannot do is notice an entry deleted from the list it generates from, and
// five of these were once deleted with both tests still green. Pinning them is
// TestEverythingSpecB22ForbidsIsOnTheForbiddenList's job, and it reads the spec.
func generatedControlRows() (rows []string, forbidden []string, unlisted []string) {
	for _, banned := range forbiddenDependencies {
		below := banned.path + "/somewhere"
		for _, path := range []string{banned.path, below} {
			rows = append(rows, strings.Join([]string{path, "false", "", moduleRootOf(path), "false", ""}, "\t"))
			unlisted = append(unlisted, path)
		}
		forbidden = append(forbidden, banned.path)
		if banned.subtree {
			forbidden = append(forbidden, below)
		}
	}
	return rows, forbidden, unlisted
}

// The module a fixture path is pretended to have come from: host, owner, repository. Enough for
// a row the parser will accept, and derived from the path so that a new forbidden entry needs
// no second edit somewhere else.
func moduleRootOf(path string) string {
	segments := strings.Split(path, "/")
	if len(segments) < 3 {
		return path
	}
	return strings.Join(segments[:3], "/")
}

func plantedControl() (block string, forbidden []string, unlisted []string) {
	rows, forbidden, unlisted := generatedControlRows()
	rows = append(rows, handWrittenControlRows...)
	unlisted = append(unlisted, handWrittenUnlisted...)
	slices.Sort(forbidden)
	slices.Sort(unlisted)
	return strings.Join(rows, "\n"), slices.Compact(forbidden), slices.Compact(unlisted)
}

var cleanControl = strings.Join([]string{
	"fmt\ttrue\t\t\t\t",
	"github.com/urnetwork/message-server/api\tfalse\t\tgithub.com/urnetwork/message-server\ttrue\t",
	"github.com/urnetwork/server\tfalse\t\tgithub.com/urnetwork/server\tfalse\t",
	"github.com/urnetwork/connect/message\tfalse\t\tgithub.com/urnetwork/connect\tfalse\t",
}, "\n")

// The controls, also run before the module is measured, so that a matcher already proven broken
// cannot go on to report the module clean inside the same test that reports it.
func assertTheMatcherWorks(t *testing.T) {
	t.Helper()

	block, wantForbidden, wantUnlisted := plantedControl()

	forbidden, unlisted := violations(parseDependencies(t, "the planted control", block))
	if !slices.Equal(forbidden, wantForbidden) {
		t.Fatalf("the matcher called %v forbidden in the planted control, want %v", forbidden, wantForbidden)
	}
	if !slices.Equal(unlisted, wantUnlisted) {
		t.Fatalf("the matcher called %v unlisted in the planted control, want %v", unlisted, wantUnlisted)
	}

	// the same block with the line endings this platform's git hands a checkout. go list itself
	// writes "\n", but the day somebody moves these controls into a testdata file this is the
	// difference between a parser that reads every row and one that reads a single malformed
	// line and reports the module clean
	forbidden, unlisted = violations(parseDependencies(t, "the planted control in CRLF", strings.ReplaceAll(block, "\n", "\r\n")))
	if !slices.Equal(forbidden, wantForbidden) || !slices.Equal(unlisted, wantUnlisted) {
		t.Fatalf("the matcher called %v forbidden and %v unlisted in the CRLF rendering of the planted control, want %v and %v",
			forbidden, unlisted, wantForbidden, wantUnlisted)
	}

	forbidden, unlisted = violations(parseDependencies(t, "the clean control", cleanControl))
	if len(forbidden) != 0 || len(unlisted) != 0 {
		t.Fatalf("the matcher refused %v and %v in a control that holds only allowed dependencies", forbidden, unlisted)
	}
}

// The matcher refuses everything §2.2 forbids and permits everything it allows.
//
// A test of its own rather than only a helper the dependency test calls first. The control used
// to be reachable from exactly one call site, so replacing that call with an assignment to the
// blank identifier removed the whole of it with no compile error, no vet error and two passing
// tests. It is still called from there, for the reason above it, but it no longer depends on
// that call to run at all.
func TestTheMatcherRefusesWhatSpecB22Forbids(t *testing.T) {
	assertTheMatcherWorks(t)
}

// An allowed import path whose code came from somewhere else is refused.
//
// The control is a real directory with a real go.mod in it, because the check reads that file:
// a fixture that only pretended to have one would prove that a string comparison works and
// nothing at all about whether the gate can find the answer on disk.
func TestAnAllowedPathWhoseCodeCameFromElsewhereIsRefused(t *testing.T) {
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "go.mod"), []byte("module example.com/not-connect\n\ngo 1.26.5\n"), 0o600); err != nil {
		t.Fatalf("writing the impostor go.mod: %v", err)
	}
	sibling := t.TempDir()
	if err := os.WriteFile(filepath.Join(sibling, "go.mod"), []byte("module github.com/urnetwork/connect\n\ngo 1.26.5\n"), 0o600); err != nil {
		t.Fatalf("writing the sibling go.mod: %v", err)
	}

	row := func(directory string) string {
		return strings.Join([]string{
			"github.com/urnetwork/connect/message", "false", "", "github.com/urnetwork/connect", "false", directory,
		}, "\t")
	}

	// the path half of the rule permits every one of these rows, so nothing but the directory
	// decides — without this the check below could pass because the path had been refused
	if forbidden, unlisted := violations(parseDependencies(t, "the substituted control", row(elsewhere))); len(forbidden) != 0 || len(unlisted) != 0 {
		t.Fatalf("the path half of the rule refused %v and %v, so this control is not testing what it claims", forbidden, unlisted)
	}

	substituted := substitutions(t, parseDependencies(t, "the substituted control", row(elsewhere)))
	if len(substituted) != 1 {
		t.Fatalf("connect/message replaced by a directory declaring module example.com/not-connect was reported as %v, want exactly one refusal", substituted)
	}

	if clean := substitutions(t, parseDependencies(t, "the sibling control", row(sibling))); len(clean) != 0 {
		t.Fatalf("the sibling checkout §2.1's own workspace layout is built on was refused as %v", clean)
	}

	if clean := substitutions(t, parseDependencies(t, "the unreplaced control", row(""))); len(clean) != 0 {
		t.Fatalf("a dependency with no replace directive at all was refused as %v", clean)
	}
}

// ── the gates ────────────────────────────────────────────────────────────────────────────

// Every dependency of this module, in every configuration it is released for, is one spec B
// §2.2 allows — and the closure that was measured covers the module.
func TestEveryDependencyOfThisModuleIsOneSpecB22Allows(t *testing.T) {
	assertTheMatcherWorks(t)

	packages := packagesOfThisModule(t)
	measurements := measureThisModule(t)
	reached := map[string]bool{}

	for _, measured := range measurements {
		// what was measured, stated in the same breath as the verdict: a reader of a green run
		// can tell "found nothing" from "read nothing", and a reader of a red one knows which
		// configuration the answer is about
		t.Log(measured.String())
		if measured.own == 0 {
			t.Fatalf("%s, which includes no package of this module at all", measured)
		}
		if measured.standard == 0 {
			t.Fatalf("%s, and a closure with no standard library package in it means the template and the parser have drifted", measured)
		}

		for _, dep := range measured.deps {
			if dep.main {
				reached[dep.path] = true
			}
		}

		forbidden, unlisted := violations(measured.deps)
		if len(forbidden) != 0 {
			t.Errorf("%s.\nspec B §2.2 forbids these outright and this module reaches them:\n  %s\nthe operator's model package is the account identity layer and §4.2 forbids consulting it; connect/mls is forbidden by §5.3, because the moment an MLS parser is in this process \"just validate the commit\" is a one-line change",
				measured, strings.Join(forbidden, "\n  "))
		}
		if len(unlisted) != 0 {
			t.Errorf("%s.\nthese are not in spec B §2.2's allow list:\n  %s\neither the import is wrong, or §2.2 has grown and allowedDependencies in this file has not; write it down deliberately — this gate is the only place a new dependency of this module is looked at",
				measured, strings.Join(unlisted, "\n  "))
		}
		if substituted := substitutions(t, measured.deps); len(substituted) != 0 {
			t.Errorf("%s.\nthese carry an import path §2.2 allows and code from a module it does not:\n  %s\na replace directive does not change an import path, so the allow list above cannot see this; §2.1's workspace layout replaces a sibling with the module of the same name and with nothing else",
				measured, strings.Join(substituted, "\n  "))
		}
	}

	// the closure was measured; that it covers the module is a separate claim, and the counts
	// above cannot make it. Narrowing the pattern to ./cmd/... leaves every one of them healthy
	// and nine of this module's packages unread.
	missing := []string{}
	for importPath := range packages {
		if !reached[importPath] {
			missing = append(missing, importPath)
		}
	}
	slices.Sort(missing)
	if len(missing) != 0 {
		t.Errorf("%d closures were measured and none of them reached these %d packages of this module:\n  %s\nthe dependency rule says nothing whatever about a package no closure includes; either the go list pattern has stopped covering the module, or these files build under no configuration %s names",
			len(measurements), len(missing), strings.Join(missing, "\n  "), releasePlatformsFile)
	}
}

// Nothing on the allow list is forbidden, and nothing forbidden is allowed.
//
// violations lets allowedness decide, so the one edit that silently turns this gate off is a
// new entry on the allow list that covers a banned path — which is precisely the edit somebody
// makes at 3 a.m. to get a branch green. It fails here instead.
func TestNoAllowedDependencyIsAlsoForbidden(t *testing.T) {
	if len(allowedDependencies) == 0 || len(forbiddenDependencies) == 0 {
		t.Fatal("one of the two lists is empty, so this check compares nothing")
	}
	for _, allowed := range allowedDependencies {
		for _, banned := range forbiddenDependencies {
			if banned.covers(allowed.path) {
				t.Errorf("the allow list carries %q, which spec B §2.2 forbids through %q", allowed.path, banned.path)
			}
			if allowed.covers(banned.path) {
				t.Errorf("the allow list entry %q (subtree %v) covers the forbidden %q", allowed.path, allowed.subtree, banned.path)
			}
		}
	}
}

// Everything spec B §2.2 writes under FORBIDDEN is on the forbidden list in this file.
//
// Five of the seven entries used to be pinned by nothing at all: deleting server/session,
// server/task, server/controller, server/api and connect/mls left both tests green, because the
// allow list refuses those paths anyway and no expectation anywhere named them. What that
// deletion lost was not safety, it was that a reader who tripped the gate stopped being told
// which section they had walked into. What pins them is the section itself, parsed rather than
// retyped, so the list here and the normative text cannot drift apart in the direction that
// matters — the spec forbidding something this file has quietly stopped forbidding.
func TestEverythingSpecB22ForbidsIsOnTheForbiddenList(t *testing.T) {
	name, document := specBDocument(t)
	block := forbiddenBlockOfSpecB22(t, name, document)
	t.Logf("%s: §2.2's FORBIDDEN block names %d import paths, and this file carries %d entries", name, len(block), len(forbiddenDependencies))

	for _, path := range block {
		if !slices.ContainsFunc(forbiddenDependencies, func(banned rule) bool { return banned.path == path }) {
			t.Errorf("spec B §2.2 forbids %q and forbiddenDependencies in this file carries no entry for it, so tripping over it would produce the generic failure instead of §2.2's reason", path)
		}
	}

	// the reverse direction is weaker on purpose. connect/mls is the one entry §2.2's block does
	// not carry — it comes from §5.3, which writes it as connect/mls rather than as a full
	// import path — so what is asked of an entry outside the block is that the document names it
	// somewhere. That refuses a ban invented here with no section behind it, which is all this
	// direction is for.
	for _, banned := range forbiddenDependencies {
		if slices.Contains(block, banned.path) {
			continue
		}
		segments := strings.Split(banned.path, "/")
		if len(segments) < 2 {
			t.Errorf("the forbidden entry %q is not an import path this gate can look for in the spec", banned.path)
			continue
		}
		named := strings.Join(segments[len(segments)-2:], "/")
		if !strings.Contains(document, named) {
			t.Errorf("forbiddenDependencies carries %q, which is not in §2.2's FORBIDDEN block and which %s never mentions as %q", banned.path, name, named)
		}
	}
}

// No package of this module imports more of this module than its own package document says it
// may.
//
// Eight package documents state a "May import:" contract, and until this test nothing read one.
// Two of them are load-bearing rather than tidy: metrics says "Never this module's redact: the
// point of a label type that cannot be printed is lost the moment a collector can accept one,
// and a metric label is a sink §11.1 names explicitly", and redact says "the standard library,
// and nothing else ... every other package in this module imports it, so an import here is an
// import everywhere". §2.2's own gate can see neither, because violations skips every package
// the go command reports as belonging to the main module — by construction it discards all
// intra-module structure before any rule is applied to anything.
//
// The package compiled for its own test is held to the same contract as the package. An
// internal test file is in the package, and redact's argument is that an import in redact is an
// import everywhere; an external <name>_test package is not in it, and is not checked, because
// it is a separate package that ships nowhere.
func TestNoPackageOfThisModuleImportsMoreOfItThanItSaysItMay(t *testing.T) {
	packages := packagesOfThisModule(t)
	layers := layersOfThisModule(t, packages)

	declared := []string{}
	for importPath, current := range layers {
		if current.any {
			declared = append(declared, fmt.Sprintf("%s: any package of this module", importPath))
			continue
		}
		declared = append(declared, fmt.Sprintf("%s: %v", importPath, current.allowed))
	}
	slices.Sort(declared)
	t.Logf("%d packages of this module declare what they may import of it:\n  %s", len(declared), strings.Join(declared, "\n  "))

	checked := 0
	for _, measured := range measureThisModule(t) {
		for _, dep := range measured.deps {
			current, ours := layers[dep.path]
			if !ours || current.any {
				continue
			}
			checked++
			for _, imported := range dep.imports {
				if _, inThisModule := packages[imported]; !inThisModule {
					continue
				}
				if imported == dep.path || slices.Contains(current.allowed, imported) {
					continue
				}
				where := dep.path
				if dep.variant {
					where += " compiled for its own test"
				}
				t.Errorf("under %s, %s imports %s and its %s directive names %v; either the import is wrong or the package document that argues against it has changed its mind, and this is the one place that argument is written down",
					measured.configuration, where, imported, mayImportDirective, current.allowed)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no package of this module was checked against its own directive, so this gate read nothing")
	}
}

// The .gitattributes line spec B §13 item 28 names, read back out of item 28.
//
// Item 28 prints the required line verbatim, so the required line is taken from there rather
// than copied into this file: a gate carrying its own copy of what the spec demands passes
// whenever the copy and the spec agree with each other and both disagree with the repository.
//
// This is item 28's second half. The first — that no document carries the four byte runs
// double-encoded UTF-8 produces — is not implemented here, because four documents in
// docs/reviews already carry them and a gate that lands red is a gate somebody switches off.
// Fixing those documents and then writing that half is its own change.
func TestGitattributesCarriesTheLineSpecB13Item28Names(t *testing.T) {
	name, document := specBDocument(t)
	required := requiredGitattributesLine(t, name, document)
	t.Logf("%s item 28 requires the .gitattributes line %q", name, required)

	text, err := os.ReadFile(".gitattributes")
	if err != nil {
		t.Fatalf(".gitattributes: %v", err)
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(strings.TrimSuffix(line, "\r")) == required {
			return
		}
	}
	t.Errorf(".gitattributes does not carry the line %s item 28 requires:\n  %s\nwithout it a checkout is free to re-encode a document, and the mojibake the other half of item 28 hunts for is then produced by the checkout itself", name, required)
}

// ── reading the spec ─────────────────────────────────────────────────────────────────────

// The spec B document, found by shape rather than by name, so a rename fails loudly here
// instead of quietly turning two gates into no-ops.
func specBDocument(t *testing.T) (string, string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("docs", "specs", "*-spec-b-*.md"))
	if err != nil {
		t.Fatalf("looking for the spec B document: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("docs/specs holds %d documents matching *-spec-b-*.md (%v); this gate reads its rule out of exactly one", len(matches), matches)
	}
	text, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("%s: %v", matches[0], err)
	}
	return filepath.ToSlash(matches[0]), strings.ReplaceAll(string(text), "\r\n", "\n")
}

var errBlockNotFound = errors.New("holds no line beginning FORBIDDEN:, so §2.2's block has moved or been reworded and this gate would have checked nothing at all")

// The import paths under §2.2's FORBIDDEN: marker.
//
// Deliberately unforgiving. A line inside the block that is not a single import path stops the
// gate rather than being skipped past: §2.2's ALLOWED half carries parenthesised annotations,
// and a parser that shrugs at one of those is a parser that will shrug at a path it failed to
// read and go on to report a shorter block than the spec wrote.
func forbiddenBlockOfSpecB22(t *testing.T, name string, document string) []string {
	t.Helper()
	lines := strings.Split(document, "\n")

	starts := []int{}
	for number, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "FORBIDDEN:") {
			starts = append(starts, number)
		}
	}
	if len(starts) == 0 {
		t.Fatalf("%s %v", name, errBlockNotFound)
	}
	if len(starts) > 1 {
		t.Fatalf("%s holds %d FORBIDDEN: blocks and this gate would have to choose between them", name, len(starts))
	}

	paths := []string{}
	for number := starts[0]; number < len(lines); number++ {
		text := strings.TrimSpace(lines[number])
		if number == starts[0] {
			text = strings.TrimSpace(strings.TrimPrefix(text, "FORBIDDEN:"))
		} else if strings.HasPrefix(text, "```") {
			break
		}
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 1 || !strings.Contains(fields[0], "/") {
			t.Fatalf("%s line %d is inside §2.2's FORBIDDEN block and is not a single import path: %q; this gate stopped rather than read past it", name, number+1, text)
		}
		paths = append(paths, fields[0])
	}
	if len(paths) == 0 {
		t.Fatalf("%s line %d begins a FORBIDDEN block with no import path under it", name, starts[0]+1)
	}
	return paths
}

var errItem28NotFound = errors.New("carries no §13 item naming the .gitattributes line it requires, in the words \"contains the line\" followed by that line in backticks")

// The .gitattributes line item 28 demands, taken from item 28's own sentence.
func requiredGitattributesLine(t *testing.T, name string, document string) string {
	t.Helper()
	found := []string{}
	for _, line := range strings.Split(document, "\n") {
		_, after, split := strings.Cut(line, "contains the line ")
		if !split || !strings.HasPrefix(after, "`") {
			continue
		}
		quoted, _, closed := strings.Cut(strings.TrimPrefix(after, "`"), "`")
		if !closed || quoted == "" {
			continue
		}
		found = append(found, quoted)
	}
	if len(found) == 0 {
		t.Fatalf("%s %v", name, errItem28NotFound)
	}
	if len(found) > 1 {
		t.Fatalf("%s names %d required .gitattributes lines (%v) and this gate would have to choose between them", name, len(found), found)
	}
	return found[0]
}
