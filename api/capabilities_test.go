package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
)

// ── the two record kinds this build cannot serve ─────────────────────────────────────────

// An EPH(0) transient and a blob-backed record are refused, and refused before the transaction.
//
// Both are declared in [Handler.NotBuilt], and a declaration is not a gate: both carry Check 0,
// so TestEveryCheckOfSpecB51IsRunOrDeclared — which reads §5.1's nine numbered checks — holds
// neither of them to anything. What holds them is this.
//
// The refusal has to happen here and not in the store, and the two cases say why in opposite
// directions. §7.6 is normative that an EPH(0) transient is never persisted: the store answers
// ErrTransientRecord for one, which is an error rather than a client's answer, so a record that
// got that far would turn "this build has no transient channel" into a REASON_INTERNAL carrying
// a store error and a wasted transaction. A blob-backed record is worse — nothing below refuses
// it at all, so §8.3's bind against message_blob.content_hash would simply not happen and the
// row would be stored with a body nobody ever checked.
func TestTheRecordKindsThisBuildCannotServeAreRefusedRatherThanStored(t *testing.T) {
	for _, current := range []struct {
		name    string
		section string
		record  func(fixture *fixture, t *testing.T) *protocol.Record
	}{
		{
			name:    "an EPH(0) transient",
			section: "§7.6",
			record: func(fixture *fixture, t *testing.T) *protocol.Record {
				return fixture.seal(t, sealed{
					sender: senderA, epoch: 1, streamIndex: 500,
					class: message.RetentionEph, ephBucket: 0, bucket: message.SizeBucket256,
					head: []byte("a transient head"), body: []byte("a transient body"),
					writeKey: fixture.writeKey(1),
				})
			},
		},
		{
			name:    "a size_bucket 5 blob-backed record",
			section: "§8.3",
			record: func(fixture *fixture, t *testing.T) *protocol.Record {
				return fixture.seal(t, sealed{
					sender: senderA, epoch: 1, streamIndex: 501,
					class: message.RetentionMedia, bucket: message.SizeBucketBlob,
					head: []byte("a head naming a blob"), blobId: blobId(0x0B),
					writeKey: fixture.writeKey(1),
				})
			},
		},
	} {
		t.Run(current.name, func(t *testing.T) {
			counted := &countingStore{}
			fixture := newFixtureWith(t, Config{Store: counted})
			counted.Store = fixture.store
			fixture.createOpenGroup(t)
			before := len(fixture.fetch(t).GetRecords())

			declared := false
			for _, notBuilt := range fixture.handler.NotBuilt() {
				if strings.Contains(notBuilt.Section, current.section) {
					declared = true
				}
			}
			if !declared {
				t.Fatalf("%s is refused below but %s is on no NotBuilt entry, so §10.1's readiness endpoint cannot say the capability is missing",
					current.name, current.section)
			}

			counted.reset()
			results := fixture.submit(t, current.record(fixture, t))
			if results[0].GetReason() != protocol.Reason_REASON_INTERNAL {
				t.Fatalf("%s was answered %v, want REASON_INTERNAL: the client did nothing wrong and §4.5's merged refusal is a statement about a party holding no key",
					current.name, results[0].GetReason())
			}
			if results[0].GetRecordId() != 0 {
				t.Fatalf("%s was allocated record_id %d", current.name, results[0].GetRecordId())
			}
			if counted.submit != 0 {
				t.Fatalf("%s reached §6.1's transaction", current.name)
			}
			if after := len(fixture.fetch(t).GetRecords()); after != before {
				t.Fatalf("%s was stored: the group holds %d records and held %d", current.name, after, before)
			}
		})
	}
}

// The same refusal on the CreateGroup path, which runs the same check outside the pipeline.
func TestAFoundingCommitOnAnUnservableRungCreatesNothing(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store

	commit := fixture.seal(t, sealed{
		sender: senderA, isCommit: true,
		class: message.RetentionPermanent, bucket: message.SizeBucketBlob,
		head: []byte("a founding commit naming a blob"), blobId: blobId(0x0C),
		attachment: fixture.epochAttachment(1, 1), writeKey: fixture.writeKey(0),
	})
	counted.reset()
	reason, created, err := fixture.handler.CreateGroup(context.Background(), fixture.conn, &protocol.CreateGroupRequest{
		GroupId:           fixture.groupId,
		InitialCommit:     commit,
		BootstrapWriteKey: fixture.writeKey(0),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if reason != protocol.Reason_REASON_INTERNAL {
		t.Fatalf("a founding commit on the blob rung was answered %v, want REASON_INTERNAL", reason)
	}
	if created != nil {
		t.Fatalf("a refused CreateGroup answered a body: %+v", created)
	}
	if counted.createGroup != 0 {
		t.Fatal("a founding commit on the blob rung reached §6.1's transaction")
	}
	if fixture.knownGroups.Contains(fixture.groupId) {
		t.Fatal("a refused CreateGroup put the group into §5.1 check 5's filter")
	}
}

// ── §4.5's third property, when nobody configured it ─────────────────────────────────────

// A handler built without a reject floor says so, and one built with a floor does not.
//
// §4.5 names three things a merged REASON_REJECTED keeps identical. Two of them — the same code
// and the same response size — are properties of what this package builds and hold in every
// deployment. The third is the timing envelope, and it is the only one that depends on a number
// nobody wrote down: no section of the spec gives the floor a value, so [Config] cannot default
// it the way it defaults the three bounds §4.3.1 does name. What must not happen is that the
// difference is silent — a deployment that configured everything else loses one of §4.5's three
// required properties, and §10.1's readiness endpoint is the thing that should be able to say so.
func TestAHandlerWithNoRejectFloorDeclaresTheTimingEnvelopeUnbuilt(t *testing.T) {
	names := func(handler *Handler) []string {
		found := []string{}
		for _, notBuilt := range handler.NotBuilt() {
			if strings.Contains(notBuilt.What, "latency floor") {
				found = append(found, notBuilt.String())
			}
		}
		return found
	}

	unpadded := newFixture(t).handler
	if len(names(unpadded)) != 1 {
		t.Fatalf("a handler with no RejectFloor names the missing latency floor %d times in NotBuilt (%v), want exactly once",
			len(names(unpadded)), unpadded.NotBuilt())
	}

	padded := newFixtureWith(t, Config{RejectFloor: 25 * time.Millisecond}).handler
	if found := names(padded); len(found) != 0 {
		t.Fatalf("a handler with a RejectFloor of 25ms still declares the timing envelope unbuilt: %v", found)
	}

	// and the declaration is not one of §5.1's nine, so the check-coverage gate is unaffected by
	// a build that configures the floor and by one that does not
	for _, notBuilt := range unpadded.NotBuilt() {
		if strings.Contains(notBuilt.What, "latency floor") && notBuilt.Check != 0 {
			t.Fatalf("the missing latency floor claims §5.1 check %d, and §5.1 numbers no such check", notBuilt.Check)
		}
	}
}
