// The dependency rule of spec B §2.2, as a test rather than as the CI shell line the spec
// prints beside it.
//
// Why the rule exists, in §2.2's own words: "the operator's model package *is* the account
// identity layer, and §4.2 forbids the message server from consulting it." §5.2 spells out the
// consequence — every check this server *can* perform it can also skip, so a server that can
// reach account identity eventually joins against it, and clients that come to depend on what
// it decided have made it a participant in a security argument it is not supposed to be in.
// The cost of the rule is stated in §2.2 as well: server/task is unavailable, which is why
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
// positive control against.
package messageserver

import (
	"fmt"
	"go/build"
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
var forbiddenDependencies = []rule{
	{path: "github.com/urnetwork/server/model", subtree: true},
	{path: "github.com/urnetwork/server/session", subtree: true},
	{path: "github.com/urnetwork/server/task", subtree: true},
	{path: "github.com/urnetwork/server/controller", subtree: true},
	{path: "github.com/urnetwork/server/api", subtree: true},
	{path: "github.com/urnetwork/sdk", subtree: true},
	{path: "github.com/urnetwork/connect/mls"},
}

// One dependency as the go command reports it: the import path, whether this toolchain counts
// it as part of the standard library, and the module it was resolved from.
type dependency struct {
	path     string
	standard bool
	module   string
	main     bool
}

// The go list template the whole gate is parsed out of. Standard and Module.Main are asked of
// the go command rather than decided here, so "is this the standard library" and "is this our
// own code" are answers from the thing that resolved the build, not a prefix match this file
// invented.
const goListFormat = "{{.ImportPath}}\t{{.Standard}}\t{{with .Module}}{{.Path}}\t{{.Main}}{{end}}"

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

// The dependency closure the go command reports for a set of patterns. Every failure here is
// fatal for one reason: an invocation that returned nothing is indistinguishable, in the
// pass or fail the suite prints, from a module that depends on nothing forbidden.
func dependenciesOf(t *testing.T, arguments ...string) []dependency {
	t.Helper()
	command := exec.Command(goCommand(t), append([]string{"list", "-deps", "-f", goListFormat}, arguments...)...)
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(command.Args, " "), err, stderr.String())
	}
	found := parseDependencies(t, strings.Join(command.Args, " "), stdout.String())
	if len(found) == 0 {
		t.Fatalf("%s listed no package at all, so this gate read nothing", strings.Join(command.Args, " "))
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
		if len(fields) < 2 {
			t.Fatalf("%s line %d is not in the format this gate reads: %q", source, number+1, line)
		}
		// a test variant is reported as "<path> [<path>.test]"; the dependency is the package
		// on the left, and the variant marker would otherwise miss every rule below
		path, _, _ := strings.Cut(fields[0], " [")
		standard, err := parseBool(fields[1])
		if err != nil {
			t.Fatalf("%s line %d: %v", source, number+1, err)
		}
		found = append(found, dependency{
			path:     path,
			standard: standard,
			module:   fieldAt(fields, 2),
			main:     fieldAt(fields, 3) == "true",
		})
	}
	return found
}

// A field the go template may not have emitted at all: a standard library package has no
// module, so those rows are two fields wide.
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

// The dependencies of a set that the rule refuses, split by how they are refused.
//
// Allowedness decides. A path the allow list covers is not a violation whatever else it
// matches, which is why TestNoAllowedDependencyIsAlsoForbidden exists: widening the allow list
// is the one edit that can turn this gate off, so the two lists are checked against each other
// rather than trusted to stay disjoint.
//
// The standard library and this module's own packages are skipped, both of them from what the
// go command reported rather than from a prefix typed here.
func violations(deps []dependency) (forbidden []string, unlisted []string) {
	for _, dep := range deps {
		if dep.standard || dep.main {
			continue
		}
		if slices.ContainsFunc(allowedDependencies, func(allowed rule) bool { return allowed.covers(dep.path) }) {
			continue
		}
		unlisted = append(unlisted, dep.path)
		if slices.ContainsFunc(forbiddenDependencies, func(banned rule) bool { return banned.covers(dep.path) }) {
			forbidden = append(forbidden, dep.path)
		}
	}
	slices.Sort(forbidden)
	slices.Sort(unlisted)
	return slices.Compact(forbidden), slices.Compact(unlisted)
}

// A go list block in the exact format the gate reads, with violations planted in it: one
// operator package a directory below a forbidden root, the sdk, and a dependency that is
// merely unlisted. Beside it, a block with none.
//
// Both halves are needed. A matcher that flags nothing passes the clean control, a matcher
// that flags everything passes the planted one, and either of them reports the green run of a
// working gate on the real module. Composed from escapes rather than written as a raw string
// literal, so the fixture is the same bytes whatever this file's line endings are.
var forbiddenControl = strings.Join([]string{
	"fmt\ttrue",
	"github.com/urnetwork/message-server/api\tfalse\tgithub.com/urnetwork/message-server\ttrue",
	"github.com/urnetwork/server\tfalse\tgithub.com/urnetwork/server\tfalse",
	"github.com/urnetwork/server/model/counters\tfalse\tgithub.com/urnetwork/server\tfalse",
	"github.com/urnetwork/sdk\tfalse\tgithub.com/urnetwork/sdk\tfalse",
	"golang.org/x/crypto/chacha20poly1305\tfalse\tgolang.org/x/crypto\tfalse",
}, "\n")

var cleanControl = strings.Join([]string{
	"fmt\ttrue",
	"github.com/urnetwork/message-server/api\tfalse\tgithub.com/urnetwork/message-server\ttrue",
	"github.com/urnetwork/server\tfalse\tgithub.com/urnetwork/server\tfalse",
	"github.com/urnetwork/connect/message\tfalse\tgithub.com/urnetwork/connect\tfalse",
}, "\n")

// The controls, run before the module is measured, so that a broken matcher cannot report the
// module clean.
func assertTheMatcherWorks(t *testing.T) {
	t.Helper()

	forbidden, unlisted := violations(parseDependencies(t, "the planted control", forbiddenControl))
	wantForbidden := []string{"github.com/urnetwork/sdk", "github.com/urnetwork/server/model/counters"}
	if !slices.Equal(forbidden, wantForbidden) {
		t.Fatalf("the matcher called %v forbidden in the planted control, want %v", forbidden, wantForbidden)
	}
	wantUnlisted := append(slices.Clone(wantForbidden), "golang.org/x/crypto/chacha20poly1305")
	slices.Sort(wantUnlisted)
	if !slices.Equal(unlisted, wantUnlisted) {
		t.Fatalf("the matcher called %v unlisted in the planted control, want %v", unlisted, wantUnlisted)
	}

	forbidden, unlisted = violations(parseDependencies(t, "the clean control", cleanControl))
	if len(forbidden) != 0 || len(unlisted) != 0 {
		t.Fatalf("the matcher refused %v and %v in a control that holds only allowed dependencies", forbidden, unlisted)
	}
}

// Every dependency of this module is one spec B §2.2 allows.
//
// Measured twice: the packages this module builds, which is what §2.2's own gate reads, and
// the same packages plus their tests, which it does not. A forbidden import in a _test.go file
// is a forbidden import — it links the operator's identity layer into a binary this repository
// builds, and a fixture is exactly where somebody reaches for one — and go list -deps ./...
// cannot see it.
func TestEveryDependencyOfThisModuleIsOneSpecB22Allows(t *testing.T) {
	assertTheMatcherWorks(t)

	for _, measured := range []struct {
		what      string
		arguments []string
	}{
		{what: "the packages this module builds", arguments: []string{"./..."}},
		{what: "those packages and their tests", arguments: []string{"-test", "./..."}},
	} {
		deps := dependenciesOf(t, measured.arguments...)
		own, standard, outside := 0, 0, 0
		for _, dep := range deps {
			switch {
			case dep.standard:
				standard++
			case dep.main:
				own++
			default:
				outside++
			}
		}
		// what was measured, stated in the same breath as the verdict: a reader of a green run
		// can tell "found nothing" from "read nothing", and a reader of a red one knows how
		// much of the module the answer covers
		measurement := fmt.Sprintf("%s: %d packages in the closure — %d of this module, %d standard library, %d outside both",
			measured.what, len(deps), own, standard, outside)
		t.Log(measurement)
		if own == 0 {
			t.Fatalf("%s, which includes no package of this module at all", measurement)
		}
		if standard == 0 {
			t.Fatalf("%s, and a closure with no standard library package in it means the template and the parser have drifted", measurement)
		}

		forbidden, unlisted := violations(deps)
		if len(forbidden) != 0 {
			t.Errorf("%s.\nspec B §2.2 forbids these outright and this module reaches them:\n  %s\nthe operator's model package is the account identity layer and §4.2 forbids consulting it; connect/mls is forbidden by §5.3, because the moment an MLS parser is in this process \"just validate the commit\" is a one-line change",
				measurement, strings.Join(forbidden, "\n  "))
		}
		if len(unlisted) != 0 {
			t.Errorf("%s.\nthese are not in spec B §2.2's allow list:\n  %s\neither the import is wrong, or §2.2 has grown and allowedDependencies in this file has not; write it down deliberately — this gate is the only place a new dependency of this module is looked at",
				measurement, strings.Join(unlisted, "\n  "))
		}
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
