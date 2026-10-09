package main

import (
	"errors"
	"os"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// The test file every main package of this module needs, and messagectl's.
//
// It exists for what happens before its first test. `go build` and `go vet` link nothing that
// runs, so neither sees a panic at init, and the one this file is written against is a protobuf
// schema registered twice. `go test` links this package with everything it imports and runs
// their init functions before the first test, so with this file the job that runs `go test ./...`
// starts this binary. Without one, that job printed "[no test files]" for this directory and
// started nothing: finding R3-F7 of the repository split's plan (ledger 281).
//
// The schema moved. The split took message.proto from connect/protocol to
// github.com/urnetwork/message/protocol (ledger 283 and 284), and a binary that links both copies
// panics at init under protobuf's default registration-conflict policy. messagectl links one:
// store reaches message/protocol, and nothing messagectl links reaches connect/protocol. The
// binaries that link both are cmd/message-server's, peer's and harness's, and
// cmd/message-server/schema_test.go holds the one this repository deploys.

// The path the messaging schema registers under. The move changed the file's go_package and not
// its name, so the path holds on both sides of it.
const messagingSchema = "message.proto"

// The go_package the registered copy declares since the move: the message module's, and never
// connect's old copy, which a connect pinned from before its removal still carries.
const messagingSchemaPackage = "github.com/urnetwork/message/protocol"

// The variable that relaxes protobuf's registration-conflict policy. Set to warn or ignore, it
// lets a second copy of a schema be dropped with at most a warning, and the binary starts: a
// binary that started under it proves nothing about how many copies it links.
const conflictPolicyVariable = "GOLANG_PROTOBUF_REGISTRATION_CONFLICT"

// This binary starts with the messaging schema registered, under the policy that refuses a second
// copy.
//
// messagectl reaches the schema through store, which names spec B §4.5's Reason codes from it.
// Reaching this test means every init of that closure ran, so under the default policy no second
// copy is linked. The lookup is the positive control: the schema this guards is in the binary to
// be duplicated at all.
func TestThisBinaryStartsWithTheMessagingSchemaRegisteredOnce(t *testing.T) {
	if policy := os.Getenv(conflictPolicyVariable); policy != "" && policy != "panic" {
		t.Fatalf("%s=%s relaxes protobuf's registration-conflict policy, so this binary would start with a second copy of %s linked; run the suite without it",
			conflictPolicyVariable, policy, messagingSchema)
	}
	file, err := protoregistry.GlobalFiles.FindFileByPath(messagingSchema)
	if errors.Is(err, protoregistry.NotFound) {
		t.Fatalf("%s is not registered in this binary, so the import that carried it through store has gone, and this test's subject with it",
			messagingSchema)
	}
	if err != nil {
		t.Fatalf("%s: %v", messagingSchema, err)
	}
	options, _ := file.Options().(*descriptorpb.FileOptions)
	if goPackage := options.GetGoPackage(); goPackage != messagingSchemaPackage {
		t.Fatalf("%s is registered with go_package %q, want %q: store reaches a copy of the schema other than the message module's",
			messagingSchema, goPackage, messagingSchemaPackage)
	}
	t.Logf("%s is registered, as proto package %s from %s, and this binary started under the policy that panics on a second copy",
		file.Path(), file.Package(), messagingSchemaPackage)
}
