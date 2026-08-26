package api

import (
	"context"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
)

// ── §4.3.2 and §6.1's carve-out ──────────────────────────────────────────────────────────

// Every rule specific to the CreateGroup carve-out refuses before §6.1's transaction.
//
// The carve-out is where §5.1 has the least left: check 5 is skipped because the group is what
// this request creates, check 6 is skipped because no epoch key is installed yet, and check 7
// verifies against a key the request itself supplied. What remains in front of the transaction is
// check 3 and the initial commit's own three rules, and until this test each of them could be
// deleted with the whole suite green — because the store refuses the same shapes underneath, so
// the client's answer is REASON_REJECTED either way.
//
// The store is therefore what this measures. A rule that has moved into §6.1 is a rule an
// attacker pays a transaction to be told about, which is precisely the ordering §5.1 exists to
// impose, and it is the only difference between an enforced rule and a deleted one that a caller
// at this boundary can see.
func TestEveryRuleOfTheCreateGroupCarveOutRefusesBeforeTheTransaction(t *testing.T) {
	for _, current := range []struct {
		name      string
		bootstrap func(fixture *fixture) []byte
		commit    func(fixture *fixture, t *testing.T) *protocol.Record
	}{
		{
			name: "a bootstrap write key that is not §3.1's width",
			bootstrap: func(fixture *fixture) []byte {
				return fixture.writeKey(0)[:store.EpochKeyBytes-1]
			},
			commit: foundingCommit,
		},
		{
			name: "an initial commit that does not sit at epoch 0",
			commit: func(fixture *fixture, t *testing.T) *protocol.Record {
				return fixture.seal(t, sealed{
					sender: senderA, epoch: 1, isCommit: true,
					class: message.RetentionPermanent, bucket: message.SizeBucket256,
					head: []byte("a founding commit at epoch 1"), body: []byte("a founding commit at epoch 1"),
					attachment: fixture.epochAttachment(1, 1), writeKey: fixture.writeKey(0),
				})
			},
		},
		{
			name: "an initial commit that is not a commit at all",
			commit: func(fixture *fixture, t *testing.T) *protocol.Record {
				return fixture.seal(t, sealed{
					sender: senderA, class: message.RetentionPermanent, bucket: message.SizeBucket256,
					head: []byte("not a commit"), body: []byte("not a commit"),
					writeKey: fixture.writeKey(0),
				})
			},
		},
		{
			name: "an epoch attachment that opens an epoch other than 1",
			commit: func(fixture *fixture, t *testing.T) *protocol.Record {
				return fixture.seal(t, sealed{
					sender: senderA, isCommit: true,
					class: message.RetentionPermanent, bucket: message.SizeBucket256,
					head: []byte("a founding commit opening epoch 2"), body: []byte("a founding commit opening epoch 2"),
					attachment: fixture.epochAttachment(2, 1), writeKey: fixture.writeKey(0),
				})
			},
		},
		{
			name: "an initial commit carrying a wrap instead of an epoch attachment",
			commit: func(fixture *fixture, t *testing.T) *protocol.Record {
				return fixture.seal(t, sealed{
					sender: senderA, isCommit: true,
					class: message.RetentionPermanent, bucket: message.SizeBucket256,
					head: []byte("a founding commit with a wrap"), body: []byte("a founding commit with a wrap"),
					attachment: wrapAttachment(1, senderA), writeKey: fixture.writeKey(0),
				})
			},
		},
	} {
		t.Run(current.name, func(t *testing.T) {
			counted := &countingStore{}
			fixture := newFixtureWith(t, Config{Store: counted})
			counted.Store = fixture.store

			bootstrap := fixture.writeKey(0)
			if current.bootstrap != nil {
				bootstrap = current.bootstrap(fixture)
			}
			counted.reset()
			reason, created, err := fixture.handler.CreateGroup(context.Background(), fixture.conn, &protocol.CreateGroupRequest{
				GroupId:           fixture.groupId,
				InitialCommit:     current.commit(fixture, t),
				BootstrapWriteKey: bootstrap,
			})
			if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}
			if reason != protocol.Reason_REASON_REJECTED {
				t.Fatalf("%s was answered %v, want REASON_REJECTED", current.name, reason)
			}
			if created != nil {
				t.Fatalf("%s was refused and still answered a body: %+v", current.name, created)
			}
			if counted.createGroup != 0 {
				t.Fatalf("%s reached §6.1's transaction, where the store refuses it as an error rather than as a client's answer", current.name)
			}
			if fixture.knownGroups.Contains(fixture.groupId) {
				t.Fatalf("%s put the group into §5.1 check 5's filter", current.name)
			}
		})
	}
}

// A bootstrap write key of the wrong width is answered before the commit beside it is looked at,
// with §4.5's merged refusal and not with a more specific code.
//
// This is the one rule of the carve-out the store cannot stand in for and check 7 cannot either.
// connect/message refuses a MAC key that is not thirty-two octets, so a short key fails check 7
// no matter what — which makes "the length was checked" and "the length was not checked"
// identical on every request that is wrong in only that one way. A request that is wrong in two
// ways separates them: the head below is over the cap, so check 3 has a REASON_OVERSIZE ready,
// and what the caller gets tells you which rule answered.
func TestABootstrapWriteKeyOfTheWrongWidthIsAnsweredBeforeTheCommitBesideIt(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted, MaxCtHeadBytes: 64})
	counted.Store = fixture.store

	oversized := func(t *testing.T) *protocol.Record {
		return fixture.seal(t, sealed{
			sender: senderA, isCommit: true,
			class: message.RetentionPermanent, bucket: message.SizeBucket256,
			head: make([]byte, 65), body: []byte("a founding commit with too much head"),
			attachment: fixture.epochAttachment(1, 1), writeKey: fixture.writeKey(0),
		})
	}

	// the control: with a key of the right width, check 3 answers and its answer is specific
	reason, _, err := fixture.handler.CreateGroup(context.Background(), fixture.conn, &protocol.CreateGroupRequest{
		GroupId:           fixture.groupId,
		InitialCommit:     oversized(t),
		BootstrapWriteKey: fixture.writeKey(0),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if reason != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("a founding commit whose ct_head is over the cap was answered %v, want REASON_OVERSIZE; without it this test cannot tell the two rules apart", reason)
	}

	// and with a key of the wrong width, the key is what answers, and it answers the merged code
	for _, width := range []int{0, store.EpochKeyBytes - 1, store.EpochKeyBytes + 1} {
		bootstrap := make([]byte, width)
		copy(bootstrap, fixture.writeKey(0))
		counted.reset()
		reason, created, err := fixture.handler.CreateGroup(context.Background(), fixture.conn, &protocol.CreateGroupRequest{
			GroupId:           fixture.groupId,
			InitialCommit:     oversized(t),
			BootstrapWriteKey: bootstrap,
		})
		if err != nil {
			t.Fatalf("a %d octet bootstrap write key: %v", width, err)
		}
		if reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("a %d octet bootstrap write key beside an oversized ct_head was answered %v, want REASON_REJECTED: §3.1 gives the key exactly %d octets and the width is decided first",
				width, reason, store.EpochKeyBytes)
		}
		if created != nil {
			t.Fatalf("a %d octet bootstrap write key was refused and still answered a body", width)
		}
		if counted.createGroup != 0 {
			t.Fatalf("a %d octet bootstrap write key reached §6.1's transaction", width)
		}
	}
}

// The founding commit every case above deviates from in one way.
func foundingCommit(fixture *fixture, t *testing.T) *protocol.Record {
	t.Helper()
	return fixture.seal(t, sealed{
		sender: senderA, isCommit: true,
		class: message.RetentionPermanent, bucket: message.SizeBucket256,
		head: []byte("a founding commit"), body: []byte("a founding commit"),
		attachment: fixture.epochAttachment(1, 1), writeKey: fixture.writeKey(0),
	})
}
