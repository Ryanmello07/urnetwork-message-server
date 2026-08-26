package api

import (
	"context"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
)

// ── §5.1 check 3: the record's group against the request's ───────────────────────────────

// A record whose header names one group may not be stored under another, and check 3 is what
// refuses it.
//
// §4.3.3's projection list does not carry `group_id` — it is a field of the request rather than
// of Record — so the whole-message comparison every other projection field is covered by says
// nothing about this one. The MAC is not a backstop either, and this test proves that rather
// than assuming it: `header.group_id` is inside the `write_auth` preimage, so a record sealed
// for another group under THIS group's epoch key verifies perfectly well under this group's key.
// The bytes below are checked against connect/message's own verifier before they are submitted,
// so a failure here cannot be read as "the forgery was malformed".
func TestARecordThatNamesAnotherGroupIsRefusedBeforeItIsStoredUnderThisOne(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store
	fixture.createOpenGroup(t)
	before := fixture.fetch(t)

	elsewhere := groupId(0x33)
	stranger := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 70, groupId: elsewhere,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head that names another group"), body: []byte("a body that names another group"),
		writeKey: fixture.writeKey(1),
	})
	parsed, err := message.ParseRecord(stranger.GetRecordBytes())
	if err != nil {
		t.Fatalf("the record this test sealed does not parse: %v", err)
	}
	if !message.VerifyWriteAuth(fixture.writeKey(1), fixture.conn.ServerNonce, parsed) {
		t.Fatal("the confused record's write_auth does not verify under this group's epoch key, so this test would be measuring check 7 rather than check 3")
	}

	counted.reset()
	results := fixture.submit(t, stranger)
	if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a record naming group %x submitted to group %x was answered %v, want REASON_REJECTED",
			elsewhere[:4], fixture.groupId[:4], results[0].GetReason())
	}
	if counted.reads() != 0 {
		t.Fatalf("a record naming another group cost %d store calls (%s); check 3 refuses it before check 6's lookup", counted.reads(), counted)
	}

	after := fixture.fetch(t)
	if len(after.GetRecords()) != len(before.GetRecords()) {
		t.Fatalf("the confused record was stored: the group holds %d records and held %d",
			len(after.GetRecords()), len(before.GetRecords()))
	}
	if after.GetHighWaterRecordId() != before.GetHighWaterRecordId() {
		t.Fatalf("the confused record moved the high water from %d to %d",
			before.GetHighWaterRecordId(), after.GetHighWaterRecordId())
	}
}

// The same rule on the CreateGroup path, which is where nothing can backstop it.
//
// §5.1's carve-out has check 7 verify against `bootstrap_write_key` from the request itself, so
// the submitter chooses the key and the MAC verifies over whatever `group_id` the header names.
// Check 3 is the only thing between a founding commit that names one group and a message_group
// row created for another.
func TestAFoundingCommitThatNamesAnotherGroupCreatesNothing(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store

	elsewhere := groupId(0x33)
	commit := fixture.seal(t, sealed{
		sender: senderA, groupId: elsewhere, isCommit: true,
		class: message.RetentionPermanent, bucket: message.SizeBucket256,
		head: []byte("a founding commit for another group"), body: []byte("a founding commit for another group"),
		attachment: fixture.epochAttachment(1, 1),
		writeKey:   fixture.writeKey(0),
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
	if reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a founding commit naming group %x under a request naming group %x was answered %v, want REASON_REJECTED",
			elsewhere[:4], fixture.groupId[:4], reason)
	}
	if created != nil {
		t.Fatalf("a refused CreateGroup answered a body: %+v", created)
	}
	if counted.createGroup != 0 {
		t.Fatal("the confused founding commit reached §6.1's transaction")
	}
	if fixture.knownGroups.Contains(fixture.groupId) {
		t.Fatal("the confused founding commit put the group into §5.1 check 5's filter")
	}
}

// ── §5.1 check 3: ct_head ────────────────────────────────────────────────────────────────

// A record carries a head, and the head is within the cap check 3 names.
//
// The floor and the ceiling are separate rules with separate reasons. §3.2 makes `ct_head` NOT
// NULL and §6.3 hashes it into the idempotency claim, so a record with no head has nothing a
// later retry can be compared against; the cap is check 3's own and is the only bound on the
// field anywhere in this process, because §5.1 check 1's `max_request_bytes` belongs to the
// frame decoder and is declared unbuilt. The number the cap defaults to is read off
// connect/message's size ladder rather than typed here, so a rung added above 64 KiB moves both
// together instead of leaving a head cap under a body the same server accepts.
func TestACtHeadIsRequiredAndBoundedByTheHeadCap(t *testing.T) {
	top := 0
	for bucket := message.SizeBucket(0); bucket <= message.SizeBucketBlob; bucket++ {
		if size := message.SizeBucketBytes(bucket); top < size {
			top = size
		}
	}
	if DefaultMaxCtHeadBytes != top {
		t.Fatalf("the default head cap is %d and the top of connect/message's inline ladder is %d; check 3's cap is read off the ladder so that the two cannot drift",
			DefaultMaxCtHeadBytes, top)
	}

	for _, current := range []struct {
		name     string
		cap      int
		head     []byte
		want     protocol.Reason
		accepted bool
	}{
		{"no head at all", 0, nil, protocol.Reason_REASON_REJECTED, false},
		{"a head of one octet", 0, make([]byte, 1), protocol.Reason_REASON_OK, true},
		{"a head of exactly the default cap", 0, make([]byte, DefaultMaxCtHeadBytes), protocol.Reason_REASON_OK, true},
		{"a head one octet over the default cap", 0, make([]byte, DefaultMaxCtHeadBytes+1), protocol.Reason_REASON_OVERSIZE, false},
		{"a head of exactly a configured cap", 64, make([]byte, 64), protocol.Reason_REASON_OK, true},
		{"a head one octet over a configured cap", 64, make([]byte, 65), protocol.Reason_REASON_OVERSIZE, false},
	} {
		t.Run(current.name, func(t *testing.T) {
			counted := &countingStore{}
			fixture := newFixtureWith(t, Config{Store: counted, MaxCtHeadBytes: current.cap})
			counted.Store = fixture.store
			fixture.createOpenGroup(t)
			before := len(fixture.fetch(t).GetRecords())

			record := fixture.seal(t, sealed{
				sender: senderA, epoch: 1, streamIndex: 80,
				class: message.RetentionDurable, bucket: message.SizeBucket256,
				head: current.head, body: []byte("a body"), writeKey: fixture.writeKey(1),
			})
			counted.reset()
			results := fixture.submit(t, record)
			if results[0].GetReason() != current.want {
				t.Fatalf("a ct_head of %d octets under a cap of %d was answered %v, want %v",
					len(current.head), fixture.handler.maxCtHeadBytes, results[0].GetReason(), current.want)
			}
			if !current.accepted && counted.submit != 0 {
				t.Fatalf("a ct_head of %d octets reached §6.1's transaction; check 3 refuses it six checks earlier", len(current.head))
			}
			after := len(fixture.fetch(t).GetRecords())
			if current.accepted && after != before+1 {
				t.Fatalf("an accepted record left the group holding %d records, and it held %d", after, before)
			}
			if !current.accepted && after != before {
				t.Fatalf("a refused ct_head of %d octets was stored: the group holds %d records and held %d",
					len(current.head), after, before)
			}
		})
	}
}

// ── §5.1 check 3: the attachment against the record beside it ────────────────────────────

// An EpochAttachment is carried by a commit and by nothing else, in both directions.
//
// The relation is the server's whole reason for reading the attachment at all: §6.1 takes the
// next epoch's `write_key` and the group's retention policy out of it, and it does that for a
// record whose `is_commit` bit said an epoch was changing. A commit with no attachment opens an
// epoch with no key, and an ordinary record carrying one hands the server a policy no epoch
// change authorized — and above check 3 there is nothing that would refuse either.
func TestAnEpochAttachmentIsCarriedByACommitAndByNothingElse(t *testing.T) {
	for _, current := range []struct {
		name     string
		isCommit bool
	}{
		{"an ordinary record carrying an epoch attachment", false},
		{"a commit carrying no attachment at all", true},
	} {
		t.Run(current.name, func(t *testing.T) {
			counted := &countingStore{}
			fixture := newFixtureWith(t, Config{Store: counted})
			counted.Store = fixture.store
			fixture.createOpenGroup(t)
			before := len(fixture.fetch(t).GetRecords())

			var attachment *message.ServerAttachment
			if !current.isCommit {
				attachment = fixture.epochAttachment(2, 1)
			}
			record := fixture.seal(t, sealed{
				sender: senderA, epoch: 1, streamIndex: 90, isCommit: current.isCommit,
				class: message.RetentionDurable, bucket: message.SizeBucket256,
				head: []byte("a head"), body: []byte("a body"),
				attachment: attachment, writeKey: fixture.writeKey(1),
			})
			counted.reset()
			results := fixture.submit(t, record)
			if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
				t.Fatalf("%s was answered %v, want REASON_REJECTED", current.name, results[0].GetReason())
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
