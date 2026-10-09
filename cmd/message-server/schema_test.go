package main

import (
	"os"
	"reflect"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	connectprotocol "github.com/urnetwork/connect/protocol"
	messageprotocol "github.com/urnetwork/message/protocol"
)

// The package the messaging schema's generated Go lives in since ledger 284. It was
// connect/protocol until then, and connect's removal deletes that copy.
const messagingSchemaPackage = "github.com/urnetwork/message/protocol"

// The variable that relaxes protobuf's registration-conflict policy. Set to warn or ignore, it
// lets a second copy of a schema be dropped with at most a warning, and the binary starts: a
// binary that started under it proves nothing about how many copies it links.
const registrationConflictPolicy = "GOLANG_PROTOBUF_REGISTRATION_CONFLICT"

// The binary this repository deploys registers message.proto exactly once, and the copy it
// registers is the message module's.
//
// This is a binary that links both protocol packages: connect/protocol for the Frame a request
// rides in, and message/protocol for the request inside it, which until ledger 284 were one
// package. Built against a connect that still carries message.proto, it holds two files declaring
// the same names. Under protobuf's default policy that panics at init, before any test here runs,
// so `go test` fails the package; measured against connect 92a657fa, this package, peer's and
// harness's all do. Build and vet see none of it. Under a relaxed policy the binary starts with
// whichever copy registered first, so this test refuses to run under one rather than vouch for a
// binary it cannot see into. What it then asks the registry, at run time:
//
//   - message.proto is registered, and its go_package is message/protocol's;
//   - every message it declares resolves, by full name, to a Go type of that package;
//   - exactly one registered file declares any of those names.
//
// The control: connect's Frame, in the same proto package, resolves to connect's protocol
// package, so the Go-package reading can tell the two apart. The message repository's sdk holds
// its binaries to the same three, in TestOneCopyOfMessageProtoIsRegistered.
func TestTheMessagingSchemaIsRegisteredOnceAndFromTheMessageModule(t *testing.T) {
	if policy := os.Getenv(registrationConflictPolicy); policy != "" && policy != "panic" {
		t.Fatalf("%s=%s relaxes protobuf's registration-conflict policy, so this binary would start with a second copy of the schema linked; run the suite without it",
			registrationConflictPolicy, policy)
	}
	file := (&messageprotocol.MessageServerRequest{}).ProtoReflect().Descriptor().ParentFile()
	registered, err := protoregistry.GlobalFiles.FindFileByPath(file.Path())
	if err != nil {
		t.Fatalf("%s is not registered in this binary: %v", file.Path(), err)
	}
	options, _ := registered.Options().(*descriptorpb.FileOptions)
	if goPackage := options.GetGoPackage(); goPackage != messagingSchemaPackage {
		t.Fatalf("the registered %s declares go_package %q, want %q: this binary links a copy of the schema other than the message module's",
			registered.Path(), goPackage, messagingSchemaPackage)
	}
	if registered != file {
		t.Fatalf("the registry's %s is not the descriptor message/protocol declares", file.Path())
	}

	names := map[protoreflect.FullName]bool{}
	messages := file.Messages()
	for index := range messages.Len() {
		name := messages.Get(index).FullName()
		names[name] = true
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(name)
		if err != nil {
			t.Errorf("%s does not resolve in the registry: %v", name, err)
			continue
		}
		if got := reflect.TypeOf(messageType.Zero().Interface()).Elem().PkgPath(); got != messagingSchemaPackage {
			t.Errorf("%s resolves to a Go type of %s, want %s", name, got, messagingSchemaPackage)
		}
	}
	if len(names) == 0 {
		t.Fatalf("%s declares no message, so nothing above was asked", file.Path())
	}

	declaring := []string{}
	protoregistry.GlobalFiles.RangeFiles(func(other protoreflect.FileDescriptor) bool {
		others := other.Messages()
		for index := range others.Len() {
			if names[others.Get(index).FullName()] {
				declaring = append(declaring, other.Path())
				break
			}
		}
		return true
	})
	if len(declaring) != 1 {
		t.Fatalf("%d registered files declare %s's names: %v; this binary must hold exactly one", len(declaring), file.Path(), declaring)
	}

	// THE CONTROL: the same reading, on a name of connect's in the same proto package
	frame, err := protoregistry.GlobalTypes.FindMessageByName((&connectprotocol.Frame{}).ProtoReflect().Descriptor().FullName())
	if err != nil {
		t.Fatalf("CONTROL FAILED: connect's Frame does not resolve: %v", err)
	}
	if got := reflect.TypeOf(frame.Zero().Interface()).Elem().PkgPath(); got != "github.com/urnetwork/connect/protocol" {
		t.Fatalf("CONTROL FAILED: connect's Frame resolves to %s, so the Go-package reading cannot tell the two packages apart", got)
	}
	t.Logf("%s is registered once, from %s: %d messages, each resolving to it; connect's Frame resolves to connect's protocol package",
		file.Path(), messagingSchemaPackage, len(names))
}
