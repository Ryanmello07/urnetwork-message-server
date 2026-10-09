package messageserver

import (
	"strings"
	"testing"
)

// The protobuf runtime that the schema's generated code is linked against.
const protobufRuntime = "google.golang.org/protobuf"

// This module resolves the protobuf runtime the message module resolves.
//
// message/protocol is protoc-gen-go output, and what this server signs and compares is a function
// of the runtime it is linked with as well as of the schema: §4.3.8's canonical_request_bytes is
// a deterministic marshal, and §4.3.8's op is read out of the compiled descriptor. The message
// repository proves its schema byte-compatible with connect's old copy, in its wire-golden corpus,
// under the runtime ITS go.mod resolves. This module links the same package under the runtime
// THIS go.mod resolves, and minimal version selection takes the higher of the two requirements,
// so a bump on either side alone moves this binary off the runtime that proof was made under, with
// every build green. Finding R3-F10 of the split's plan, answered with its version-equality
// option: one version, held on both sides.
//
// Both answers are the go command's: this module's build list, and the message module's own,
// asked in the directory this module's replace points at. A failure to ask is a failure, never a
// skip — deps_test.go makes the argument and goOutput carries it out.
func TestThisModuleResolvesTheProtobufRuntimeTheMessageModuleResolves(t *testing.T) {
	environment := hostConfiguration(t).environment()
	ours := strings.TrimSpace(goOutput(t, environment, "list", "-m", "-f", "{{.Version}}", protobufRuntime))
	directory := strings.TrimSpace(goOutput(t, environment, "list", "-m", "-f", "{{.Dir}}", messageModulePath))
	if ours == "" || directory == "" {
		t.Fatalf("the go command named no version of %s (%q) or no directory for %s (%q), so there is nothing to compare", protobufRuntime, ours, messageModulePath, directory)
	}
	theirs := strings.TrimSpace(goOutput(t, environment, "-C", directory, "list", "-m", "-f", "{{.Version}}", protobufRuntime))
	t.Logf("this module resolves %s %s; %s, read from %s, resolves %s", protobufRuntime, ours, messageModulePath, directory, theirs)
	if ours != theirs {
		t.Fatalf("this module resolves %s %s and %s resolves %s; the message repository's wire-golden proof holds for the runtime it resolves, so the two must name the same version",
			protobufRuntime, ours, messageModulePath, theirs)
	}
}
