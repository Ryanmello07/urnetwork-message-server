package api

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
	"google.golang.org/protobuf/proto"
)

// §5.1 check 3's kind `0x0005` arm, end to end through the handler: the digest comparison, the
// alignment rule of §4.3.3 and §4.3.2, both submit call sites, and item 244's property — that a
// fetch returns no epoch key material in any served byte — held with a control that says the
// search would find one if it were there.

// THE PROPERTY, with its control in the same test.
//
// A commit carrying a `0x0005` attachment whose digest matches the request's keys is ACCEPTED,
// and the epoch it opens is opened with THOSE keys — proved by a record at the new epoch MAC'd
// under the delivered write key being accepted, which is check 6 and check 7 answering about a
// key that can only have come from the request. The refusal case is the same submission with one
// octet of the delivered write key changed: refused, and refused BY THE NAMED CLAUSE.
func TestACommitWhoseDigestMatchesTheRequestKeysIsAcceptedAndOneThatDoesNotIsRefusedByName(t *testing.T) {
	t.Parallel()

	// ── the acceptance, which is the control for the refusal below ────────────────────────
	accepting := newFixture(t)
	accepting.createOpenGroup(t)
	commit := accepting.seal(t, sealed{
		sender:      senderB,
		epoch:       1,
		streamIndex: 0,
		class:       message.RetentionPermanent,
		bucket:      message.SizeBucket256,
		isCommit:    true,
		head:        []byte("a kind 0x0005 commit"),
		body:        []byte("a kind 0x0005 commit"),
		attachment:  accepting.digestAttachment(t, 2, 1),
		writeKey:    accepting.writeKey(1),
	})
	results := accepting.submitWithKeys(t, []*protocol.EpochKeyDelivery{accepting.epochKeys(2)}, commit)
	if results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("a kind 0x0005 commit whose digest matches its request's keys was answered %v, want REASON_OK", results[0].GetReason())
	}
	if results[0].GetCurrentEpoch() != 2 {
		t.Fatalf("the commit was accepted and the group is at epoch %d, want 2", results[0].GetCurrentEpoch())
	}

	// the epoch opened with the REQUEST's keys, and the proof is a record the server verifies
	// under one of them. Nothing in the record carried that key, so a server that installed
	// anything else refuses this.
	wrap := accepting.seal(t, sealed{
		sender:      senderB,
		epoch:       2,
		streamIndex: 1,
		class:       message.RetentionPermanent,
		bucket:      message.SizeBucket256,
		head:        []byte("the epoch-2 snapshot"),
		body:        []byte("the epoch-2 snapshot"),
		attachment:  wrapAttachment(2, senderB),
		writeKey:    accepting.writeKey(2),
	})
	if reason := accepting.submit(t, wrap)[0].GetReason(); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a record at the opened epoch, MAC'd under the DELIVERED write key, was answered %v; the epoch was opened with some other key", reason)
	}

	// ── the refusal, by name ──────────────────────────────────────────────────────────────
	refusing := newFixture(t)
	refusing.createOpenGroup(t)
	same := refusing.seal(t, sealed{
		sender:      senderB,
		epoch:       1,
		streamIndex: 0,
		class:       message.RetentionPermanent,
		bucket:      message.SizeBucket256,
		isCommit:    true,
		head:        []byte("a kind 0x0005 commit"),
		body:        []byte("a kind 0x0005 commit"),
		attachment:  refusing.digestAttachment(t, 2, 1),
		writeKey:    refusing.writeKey(1),
	})
	// ONE OCTET, and of the key rather than of the digest: altering the digest would fail
	// check 7 instead, because LP(H(server_attachment)) is inside the write_auth preimage —
	// which is a different clause answering, and a refusal from the wrong clause is what this
	// test exists to tell apart
	tampered := &protocol.EpochKeyDelivery{
		WriteKey: slices.Clone(refusing.writeKey(2)),
		ReadKey:  refusing.readKey(2),
	}
	tampered.WriteKey[7] ^= 0x01

	reason, response, err := refusing.handler.Submit(context.Background(), refusing.conn, &protocol.SubmitRequest{
		GroupId:   refusing.groupId,
		Records:   []*protocol.Record{same},
		EpochKeys: []*protocol.EpochKeyDelivery{tampered},
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the envelope answered %v, want REASON_OK with a body", reason)
	}
	if got := response.GetResults()[0].GetReason(); got != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a kind 0x0005 commit whose request keys do not match its digest was answered %v, want REASON_REJECTED", got)
	}
	// and the epoch did NOT open, which is the consequence the refusal exists to prevent
	if _, err := refusing.store.EpochKeys(context.Background(), refusing.groupId, 2); err == nil {
		t.Fatal("the mismatched commit was refused and epoch 2 exists anyway")
	}
}

// The digest clause refuses BY THE SENTINEL `connect/message` gives it, and not by some other
// clause of check 3 that happens to fire first.
//
// §4.5 merges every client-caused refusal into REASON_REJECTED, so the wire cannot tell this
// from a bad MAC and MUST NOT. What has to be able to tell them apart is this server's own
// tests: a suite that asserted only REASON_REJECTED would stay green with the digest comparison
// deleted, because the same submission is refused by nothing at all.
func TestTheDigestClauseRefusesUnderItsOwnSentinel(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.createOpenGroup(t)

	commit := fixture.seal(t, sealed{
		sender:     senderB,
		epoch:      1,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("a kind 0x0005 commit"),
		body:       []byte("a kind 0x0005 commit"),
		attachment: fixture.digestAttachment(t, 2, 1),
		writeKey:   fixture.writeKey(1),
	})
	pass := &recordPass{projection: commit}
	if reason := fixture.handler.staticShape(fixture.groupId, pass); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the commit failed check 3's per-record half with %v before the digest clause was reached", reason)
	}

	cases := map[string]struct {
		delivery *protocol.EpochKeyDelivery
		want     error
	}{
		// the matching pair, which is the inline control: the same call answers nil, so every
		// refusal below is about what was changed and not about the call
		"TheMatchingPair": {delivery: fixture.epochKeys(2), want: nil},
		"AWriteKeyOneOctetOff": {delivery: &protocol.EpochKeyDelivery{
			WriteKey: flipOctet(fixture.writeKey(2), 7),
			ReadKey:  fixture.readKey(2),
		}, want: message.ErrEpochKeysDigestMismatch},
		"AReadKeyOneOctetOff": {delivery: &protocol.EpochKeyDelivery{
			WriteKey: fixture.writeKey(2),
			ReadKey:  flipOctet(fixture.readKey(2), 31),
		}, want: message.ErrEpochKeysDigestMismatch},
		// the two keys swapped. It is its own case because a preimage that did not FRAME the
		// two keys would hash the same octets either way round
		"TheTwoKeysSwapped": {delivery: &protocol.EpochKeyDelivery{
			WriteKey: fixture.readKey(2),
			ReadKey:  fixture.writeKey(2),
		}, want: message.ErrEpochKeysDigestMismatch},
		// the NEXT epoch's pair, against a digest taken at epoch 2. This is the case that says
		// `opens_epoch` is really inside the preimage
		"TheKeysOfAnotherEpoch": {delivery: &protocol.EpochKeyDelivery{
			WriteKey: fixture.writeKey(3),
			ReadKey:  fixture.readKey(3),
		}, want: message.ErrEpochKeysDigestMismatch},
	}
	for name, current := range cases {
		t.Run(name, func(t *testing.T) {
			err := checkEpochKeysDigest(fixture.groupId, pass.attachment, current.delivery)
			if current.want == nil {
				if err != nil {
					t.Fatalf("the matching pair was refused with %v; every other case in this table is measured against this one answering nil", err)
				}
				return
			}
			if !errors.Is(err, current.want) {
				t.Fatalf("the digest clause answered %v, want %v", err, current.want)
			}
		})
	}
}

// The digest is taken over the GROUP as well as the epoch (ruling 34), and this is the case that
// says so: the same two keys and the same epoch, under a digest built for another group.
//
// Without `LP(group_id)` in the preimage the digest commits to an epoch INDEX and two keys, and
// epoch 2 of every group in the world is the same index — so the same digest would verify the
// same pair under any group_id a request cared to name.
func TestTheDigestIsOverTheGroupAndNotOnlyTheEpoch(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)

	mine := fixture.digestAttachment(t, 2, 1)
	theirs := fixture.digestAttachmentFor(t, groupId(0x22), 2, 1, fixture.writeKey(2), fixture.readKey(2))

	// the two digests differ, which is the measurement the assertion below rests on
	if slices.Equal(mine.EpochDigest.EpochKeysDigest, theirs.EpochDigest.EpochKeysDigest) {
		t.Fatal("two groups' digests over the same epoch and the same two keys are the same octets, so LP(group_id) is not in the preimage")
	}
	// mine verifies under my group, which is the control
	if err := checkEpochKeysDigest(fixture.groupId, mine, fixture.epochKeys(2)); err != nil {
		t.Fatalf("the digest built for this group did not verify under it: %v", err)
	}
	// and the other group's does not
	if err := checkEpochKeysDigest(fixture.groupId, theirs, fixture.epochKeys(2)); !errors.Is(err, message.ErrEpochKeysDigestMismatch) {
		t.Fatalf("a digest built for another group verified under this one with %v", err)
	}
}

// §4.3.3's alignment rule, every clause driven and every refusal named.
//
// THE PANIC IS THE POINT OF THE LENGTH CLAUSE. `deliveries[index]` with a list shorter than
// `records` is an index panic, which reaches a client as a 500 for a request it shaped. Each
// case below is a shape that a naive implementation indexes into.
func TestEveryAlignmentViolationIsRefusedByNameAndNotByAPanic(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.createOpenGroup(t)

	digestCommit := func(index uint64) *protocol.Record {
		return fixture.seal(t, sealed{
			sender:      senderB,
			epoch:       1,
			streamIndex: index,
			class:       message.RetentionPermanent,
			bucket:      message.SizeBucket256,
			isCommit:    true,
			head:        []byte("a kind 0x0005 commit"),
			body:        []byte("a kind 0x0005 commit"),
			attachment:  fixture.digestAttachment(t, 2, 1),
			writeKey:    fixture.writeKey(1),
		})
	}
	epochCommit := func(index uint64) *protocol.Record {
		return fixture.seal(t, sealed{
			sender:      senderB,
			epoch:       1,
			streamIndex: index,
			class:       message.RetentionPermanent,
			bucket:      message.SizeBucket256,
			isCommit:    true,
			head:        []byte("a kind 0x0001 commit"),
			body:        []byte("a kind 0x0001 commit"),
			attachment:  fixture.epochAttachment(2, 1),
			writeKey:    fixture.writeKey(1),
		})
	}
	ordinary := func(index uint64) *protocol.Record {
		return fixture.seal(t, sealed{
			sender:      senderB,
			epoch:       1,
			streamIndex: index,
			class:       message.RetentionDurable,
			bucket:      message.SizeBucket256,
			head:        []byte("an ordinary record"),
			body:        []byte("an ordinary record"),
			writeKey:    fixture.writeKey(1),
		})
	}

	cases := map[string]struct {
		records    []*protocol.Record
		deliveries []*protocol.EpochKeyDelivery
		want       error
	}{
		// the two shapes §4.3.3 admits, as the inline controls: one entry against one 0x0005
		// commit, and none at all against a batch with no commit in it
		"OneEntryAgainstOneDigestCommit": {
			records:    []*protocol.Record{digestCommit(0)},
			deliveries: []*protocol.EpochKeyDelivery{fixture.epochKeys(2)},
			want:       nil,
		},
		"NoEntriesAgainstOrdinaryRecords": {
			records:    []*protocol.Record{ordinary(0), ordinary(1)},
			deliveries: nil,
			want:       nil,
		},
		// "neither empty nor exactly as long as records" — the clause that has to run FIRST,
		// because every clause after it indexes
		"AListShorterThanRecords": {
			records:    []*protocol.Record{ordinary(0), ordinary(1)},
			deliveries: []*protocol.EpochKeyDelivery{fixture.epochKeys(2)},
			want:       ErrEpochKeysLength,
		},
		"AListLongerThanRecords": {
			records:    []*protocol.Record{digestCommit(0)},
			deliveries: []*protocol.EpochKeyDelivery{fixture.epochKeys(2), fixture.epochKeys(2)},
			want:       ErrEpochKeysLength,
		},
		// an entry sitting opposite a record with is_commit = 0
		"AnEntryOppositeAnOrdinaryRecord": {
			records:    []*protocol.Record{ordinary(0)},
			deliveries: []*protocol.EpochKeyDelivery{fixture.epochKeys(2)},
			want:       ErrEpochKeysOnNonCommit,
		},
		// a kind 0x0005 commit with no entry: an epoch the server would install without having
		// been handed what opens it
		"ADigestCommitWithNoEntry": {
			records:    []*protocol.Record{digestCommit(0)},
			deliveries: nil,
			want:       ErrEpochKeysMissing,
		},
		// §5.4's acceptance window read the other way: a kind 0x0001 commit WITH an entry
		"AnEpochCommitWithAnEntry": {
			records:    []*protocol.Record{epochCommit(0)},
			deliveries: []*protocol.EpochKeyDelivery{fixture.epochKeys(2)},
			want:       ErrEpochKeysUnwanted,
		},
		// and the control for that one: the same kind 0x0001 commit with NOTHING beside it,
		// which is every commit this server has ever accepted
		"AnEpochCommitWithNoEntry": {
			records:    []*protocol.Record{epochCommit(0)},
			deliveries: nil,
			want:       nil,
		},
		// a zero entry, which proto3 cannot tell from an absent one on a repeated field. It is
		// two EMPTY KEYS and never an absence
		"AZeroEntry": {
			records:    []*protocol.Record{digestCommit(0)},
			deliveries: []*protocol.EpochKeyDelivery{{}},
			want:       ErrEpochKeysEmptyEntry,
		},
		"AKeyOfTheWrongWidth": {
			records: []*protocol.Record{digestCommit(0)},
			deliveries: []*protocol.EpochKeyDelivery{{
				WriteKey: fixture.writeKey(2)[:store.EpochKeyBytes-1],
				ReadKey:  fixture.readKey(2),
			}},
			want: ErrEpochKeyWidth,
		},
	}

	for name, current := range cases {
		t.Run(name, func(t *testing.T) {
			passes := []*recordPass{}
			for _, record := range current.records {
				pass := &recordPass{projection: record}
				if reason := fixture.handler.staticShape(fixture.groupId, pass); reason != protocol.Reason_REASON_OK {
					t.Fatalf("a fixture record failed check 3's per-record half with %v", reason)
				}
				passes = append(passes, pass)
			}
			// no recover(): a panic here fails the test with its stack, which is what "and not
			// an index panic" has to be measured as
			_, index, err := epochKeyAlignment(passes, current.deliveries)
			if current.want == nil {
				if err != nil {
					t.Fatalf("a shape §4.3.3 admits was refused with %v", err)
				}
				return
			}
			if !errors.Is(err, current.want) {
				t.Fatalf("the alignment rule answered %v, want %v", err, current.want)
			}
			if index < wholeSubmission || len(current.records) <= index {
				t.Fatalf("the refusal named index %d for a batch of %d records; a refusal has to align with a result or with the whole submission",
					index, len(current.records))
			}
		})
	}
}

// Every alignment refusal reaches the wire as §4.5's merged REASON_REJECTED, at the right index,
// through the whole handler — and none of them costs a row.
func TestAnAlignmentViolationIsRejectedThroughTheHandlerAndAllocatesNothing(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.createOpenGroup(t)

	commit := fixture.seal(t, sealed{
		sender:     senderB,
		epoch:      1,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("a kind 0x0005 commit"),
		body:       []byte("a kind 0x0005 commit"),
		attachment: fixture.digestAttachment(t, 2, 1),
		writeKey:   fixture.writeKey(1),
	})
	results := fixture.submitWithKeys(t, nil, commit)
	if got := results[0].GetReason(); got != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a kind 0x0005 commit with no delivery was answered %v, want REASON_REJECTED", got)
	}
	if _, err := fixture.store.EpochKeys(context.Background(), fixture.groupId, 2); err == nil {
		t.Fatal("the refused commit opened epoch 2 anyway")
	}

	// THE CONTROL: the same commit with its delivery is accepted by the same handler
	if got := fixture.submitWithKeys(t, []*protocol.EpochKeyDelivery{fixture.epochKeys(2)}, commit)[0].GetReason(); got != protocol.Reason_REASON_OK {
		t.Fatalf("the same commit WITH its delivery was answered %v, want REASON_OK", got)
	}
}

// §6.3's idempotent retry over a kind `0x0005` commit: the same record submitted twice answers
// REASON_OK with the SAME record_id and opens the epoch exactly once.
func TestResubmittingAKind0x0005CommitIsIdempotent(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.createOpenGroup(t)

	commit := fixture.seal(t, sealed{
		sender:     senderB,
		epoch:      1,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("a kind 0x0005 commit"),
		body:       []byte("a kind 0x0005 commit"),
		attachment: fixture.digestAttachment(t, 2, 1),
		writeKey:   fixture.writeKey(1),
	})
	keys := []*protocol.EpochKeyDelivery{fixture.epochKeys(2)}

	first := fixture.submitWithKeys(t, keys, commit)
	if first[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the first submission answered %v", first[0].GetReason())
	}
	second := fixture.submitWithKeys(t, keys, commit)
	if second[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("§6.3's retry of an identical record answered %v, want REASON_OK", second[0].GetReason())
	}
	if first[0].GetRecordId() != second[0].GetRecordId() {
		t.Fatalf("the retry was given record_id %d and the original holds %d; §6.3 answers the id it already allocated",
			second[0].GetRecordId(), first[0].GetRecordId())
	}
	if epoch := second[0].GetCurrentEpoch(); epoch != 2 {
		t.Fatalf("after the retry the group is at epoch %d, want 2; a retry that re-opened the epoch would be at 3", epoch)
	}
	// and the keys installed against epoch 2 are still the ones the FIRST submission delivered
	opened, err := fixture.store.EpochKeys(context.Background(), fixture.groupId, 2)
	if err != nil {
		t.Fatalf("EpochKeys: %v", err)
	}
	if !slices.Equal(opened.WriteKey, fixture.writeKey(2)) {
		t.Errorf("epoch 2 holds write key %x after the retry, want the delivered %x", opened.WriteKey, fixture.writeKey(2))
	}
}

// ITEM 244's PROPERTY, at the layer that serves the bytes: a fetch returns NO epoch key material
// in any served byte of a kind `0x0005` commit — and the same search over a kind `0x0001` commit
// FINDS both keys, which is what says the search is one that could have failed.
//
// The search is over the whole served `Record` message, marshaled, and not over a field somebody
// remembered to look at. Item 244's leak was `record_bytes` rebuilt verbatim from a stored
// column, so a test that inspected the projection fields alone would have missed it entirely.
func TestAFetchServesNoEpochKeyMaterialForAKind0x0005Commit(t *testing.T) {
	t.Parallel()

	// ── the property ─────────────────────────────────────────────────────────────────────
	digest := newFixture(t)
	digest.createOpenGroup(t)
	digestCommit := digest.seal(t, sealed{
		sender:     senderB,
		epoch:      1,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("a kind 0x0005 commit"),
		body:       []byte("a kind 0x0005 commit"),
		attachment: digest.digestAttachment(t, 2, 1),
		writeKey:   digest.writeKey(1),
	})
	if reason := digest.submitWithKeys(t, []*protocol.EpochKeyDelivery{digest.epochKeys(2)}, digestCommit)[0].GetReason(); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the kind 0x0005 commit was answered %v", reason)
	}
	served := digest.fetch(t)
	if len(served.GetRecords()) == 0 {
		t.Fatal("the fetch returned no records at all, so the property below holds over nothing")
	}
	if found := servedBytesCarrying(t, served, digest.writeKey(2), digest.readKey(2)); len(found) != 0 {
		t.Errorf("a fetch served epoch 2's key material for a kind 0x0005 commit, in records %v; ledger item 244 is that the served commit hands a removed member the next epoch's read and write keys, forever", found)
	}

	// ── THE POSITIVE CONTROL, in the same test and through the same search ───────────────
	//
	// The identical scenario under kind 0x0001, where the two keys ARE in the served bytes.
	// Without it, "no bytes matched" is satisfied by a search that matches nothing.
	plain := newFixture(t)
	plain.createOpenGroup(t)
	plainCommit := plain.seal(t, sealed{
		sender:     senderB,
		epoch:      1,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("a kind 0x0001 commit"),
		body:       []byte("a kind 0x0001 commit"),
		attachment: plain.epochAttachment(2, 1),
		writeKey:   plain.writeKey(1),
	})
	if reason := plain.submit(t, plainCommit)[0].GetReason(); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the kind 0x0001 control commit was answered %v", reason)
	}
	control := plain.fetch(t)
	if found := servedBytesCarrying(t, control, plain.writeKey(2), plain.readKey(2)); len(found) == 0 {
		t.Fatal("the kind 0x0001 control's served bytes do NOT carry epoch 2's keys under this search, so the search is not one that would find them under kind 0x0005 either and the property above is vacuous")
	}
}

// §6.2's loser protocol over a kind `0x0005` commit: the losing committer is handed the WINNER's
// record, rebuilt from the stored row, and it still carries no key.
//
// IT IS ITS OWN TEST BECAUSE THIS SERVE PATH FAILS SILENTLY. `resultOf` drops a
// `winning_commit` that will not re-encode rather than refusing a refusal that is otherwise
// correct — so a `rebuildRecord` that could not parse a stored `0x0005` attachment would leave
// every loser with `winning_commit` UNSET and §6.2's mandatory protocol with nothing to apply,
// with no error anywhere. `Fetch` is the other serve path and has the same parse; this is the
// one whose failure is invisible.
func TestTheLoserOfAKind0x0005CommitIsHandedTheWinnersRecord(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.createOpenGroup(t)

	winner := fixture.seal(t, sealed{
		sender:     senderB,
		epoch:      1,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("the winning kind 0x0005 commit"),
		body:       []byte("the winning kind 0x0005 commit"),
		attachment: fixture.digestAttachment(t, 2, 1),
		writeKey:   fixture.writeKey(1),
	})
	if reason := fixture.submitWithKeys(t, []*protocol.EpochKeyDelivery{fixture.epochKeys(2)}, winner)[0].GetReason(); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the winning commit was answered %v", reason)
	}

	// a second committer at the same epoch, from another sender, which §6.2 makes a loser
	loser := fixture.seal(t, sealed{
		sender:      senderA,
		epoch:       1,
		streamIndex: 3,
		class:       message.RetentionPermanent,
		bucket:      message.SizeBucket256,
		isCommit:    true,
		head:        []byte("the losing kind 0x0005 commit"),
		body:        []byte("the losing kind 0x0005 commit"),
		attachment:  fixture.digestAttachment(t, 2, 1),
		writeKey:    fixture.writeKey(1),
	})
	result := fixture.submitWithKeys(t, []*protocol.EpochKeyDelivery{fixture.epochKeys(2)}, loser)[0]
	if result.GetReason() == protocol.Reason_REASON_OK {
		t.Fatalf("a second commit at epoch 1 was accepted; §6.1's CAS admits one per (group, epoch)")
	}
	if result.GetWinningCommit() == nil {
		t.Fatal("the losing committer was handed no winning_commit; §6.2 sets it on ANY rejection of a commit submission, and a rebuild that refused the stored kind 0x0005 attachment drops it silently")
	}
	// the winner is the winner. It is NOT proto.Equal to what was submitted and must not be:
	// §4.3.3's read half rebuilds `record_bytes` with `write_auth` ZERO, because the MAC is over
	// the submitting connection's server_nonce and no other party holds it. So the comparison is
	// over the projections, plus the one thing this test is really about — that the rebuilt
	// `record_bytes` still parse to a kind 0x0005 attachment
	served := result.GetWinningCommit()
	if !slices.Equal(served.GetSenderHandle(), winner.GetSenderHandle()) || served.GetEpoch() != winner.GetEpoch() ||
		served.GetStreamIndex() != winner.GetStreamIndex() || !slices.Equal(served.GetBodyHash(), winner.GetBodyHash()) {
		t.Errorf("the winning_commit handed back is not the record that won")
	}
	parsed, err := message.ParseRecord(served.GetRecordBytes())
	if err != nil {
		t.Fatalf("the winner's rebuilt record_bytes do not parse: %v", err)
	}
	attachment, err := parseServerAttachment(parsed.Header.ServerAttachment)
	if err != nil {
		t.Fatalf("the winner's rebuilt server_attachment does not parse at either door: %v", err)
	}
	if attachment.Kind != message.AttachmentEpochDigest {
		t.Fatalf("the winner came back carrying attachment kind 0x%04x, want the kind 0x0005 it was submitted with", uint16(attachment.Kind))
	}
	if found := servedBytesCarrying(t, &protocol.FetchResponse{Records: []*protocol.Record{result.GetWinningCommit()}},
		fixture.writeKey(2), fixture.readKey(2)); len(found) != 0 {
		t.Error("§6.2's winning_commit carries epoch 2's key material; it is one of the six serve paths ruling 33 names")
	}
}

// Both submit call sites. §4.3.2's `initial_commit` is the second one, and a rule implemented on
// `Submit` alone leaves the founding commit installing epoch 1 from an attachment that has no
// keys in it.
func TestCreateGroupTakesAKind0x0005FoundingCommit(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)

	founding := fixture.seal(t, sealed{
		sender:     senderA,
		class:      message.RetentionPermanent,
		bucket:     message.SizeBucket256,
		isCommit:   true,
		head:       []byte("a founding commit"),
		body:       []byte("a founding commit"),
		attachment: fixture.digestAttachment(t, 1, 1),
		writeKey:   fixture.writeKey(0),
	})
	reason, created, err := fixture.handler.CreateGroup(context.Background(), fixture.conn, &protocol.CreateGroupRequest{
		GroupId:           fixture.groupId,
		InitialCommit:     founding,
		BootstrapWriteKey: fixture.writeKey(0),
		EpochKeys:         fixture.epochKeys(1),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("a kind 0x0005 founding commit was answered %v, want REASON_OK", reason)
	}
	if created.GetCurrentEpoch() != 1 {
		t.Fatalf("the created group is at epoch %d, want 1", created.GetCurrentEpoch())
	}
	// epoch 1 opened with the REQUEST's keys, proved by a record at epoch 1 MAC'd under the
	// delivered write key
	wrap := fixture.seal(t, sealed{
		sender:      senderA,
		epoch:       1,
		streamIndex: 1,
		class:       message.RetentionPermanent,
		bucket:      message.SizeBucket256,
		head:        []byte("the epoch-1 snapshot"),
		body:        []byte("the epoch-1 snapshot"),
		attachment:  wrapAttachment(1, senderA),
		writeKey:    fixture.writeKey(1),
	})
	if got := fixture.submit(t, wrap)[0].GetReason(); got != protocol.Reason_REASON_OK {
		t.Fatalf("a record at epoch 1 under the DELIVERED write key was answered %v; the epoch was opened with some other key", got)
	}
}

// §4.3.2's presence rule, both directions, and the digest clause on the founding commit.
func TestCreateGroupRefusesAMisalignedOrMismatchedFoundingCommit(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		digestKind bool
		keys       func(f *fixture) *protocol.EpochKeyDelivery
		want       protocol.Reason
	}{
		// the two controls: each kind with the delivery its own arm requires
		"AKind0x0005FoundingCommitWithItsDelivery": {
			digestKind: true,
			keys:       func(f *fixture) *protocol.EpochKeyDelivery { return f.epochKeys(1) },
			want:       protocol.Reason_REASON_OK,
		},
		"AKind0x0001FoundingCommitWithNoDelivery": {
			digestKind: false,
			keys:       func(f *fixture) *protocol.EpochKeyDelivery { return nil },
			want:       protocol.Reason_REASON_OK,
		},
		"AKind0x0005FoundingCommitWithNoDelivery": {
			digestKind: true,
			keys:       func(f *fixture) *protocol.EpochKeyDelivery { return nil },
			want:       protocol.Reason_REASON_REJECTED,
		},
		"AKind0x0001FoundingCommitWithADelivery": {
			digestKind: false,
			keys:       func(f *fixture) *protocol.EpochKeyDelivery { return f.epochKeys(1) },
			want:       protocol.Reason_REASON_REJECTED,
		},
		"AKind0x0005FoundingCommitWhoseKeysDoNotMatchItsDigest": {
			digestKind: true,
			keys: func(f *fixture) *protocol.EpochKeyDelivery {
				return &protocol.EpochKeyDelivery{WriteKey: flipOctet(f.writeKey(1), 3), ReadKey: f.readKey(1)}
			},
			want: protocol.Reason_REASON_REJECTED,
		},
		"AKind0x0005FoundingCommitWithAZeroDelivery": {
			digestKind: true,
			keys:       func(f *fixture) *protocol.EpochKeyDelivery { return &protocol.EpochKeyDelivery{} },
			want:       protocol.Reason_REASON_REJECTED,
		},
	}
	for name, current := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newFixture(t)
			attachment := fixture.epochAttachment(1, 1)
			if current.digestKind {
				attachment = fixture.digestAttachment(t, 1, 1)
			}
			founding := fixture.seal(t, sealed{
				sender:     senderA,
				class:      message.RetentionPermanent,
				bucket:     message.SizeBucket256,
				isCommit:   true,
				head:       []byte("a founding commit"),
				body:       []byte("a founding commit"),
				attachment: attachment,
				writeKey:   fixture.writeKey(0),
			})
			reason, _, err := fixture.handler.CreateGroup(context.Background(), fixture.conn, &protocol.CreateGroupRequest{
				GroupId:           fixture.groupId,
				InitialCommit:     founding,
				BootstrapWriteKey: fixture.writeKey(0),
				EpochKeys:         current.keys(fixture),
			})
			if err != nil {
				t.Fatalf("CreateGroup: %v", err)
			}
			if reason != current.want {
				t.Fatalf("CreateGroup answered %v, want %v", reason, current.want)
			}
		})
	}
}

// §5.1 check 3's `iff is_commit`, over the kind the disjunction was written for.
//
// `(kind == message.AttachmentEpoch) != is_commit` ADMITS a kind 0x0005 attachment on an
// ORDINARY record — `false != false` passes — so this is the case that catches the clause that
// was never widened. The control is the same ordinary record with no attachment, accepted.
func TestAKind0x0005AttachmentOnAnOrdinaryRecordIsRefused(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.createOpenGroup(t)

	ordinary := fixture.seal(t, sealed{
		sender:      senderB,
		epoch:       1,
		streamIndex: 0,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket256,
		head:        []byte("an ordinary record wearing a commit's attachment"),
		body:        []byte("an ordinary record wearing a commit's attachment"),
		attachment:  fixture.digestAttachment(t, 2, 1),
		writeKey:    fixture.writeKey(1),
	})
	// THROUGH `staticShape` AND NOT ONLY THROUGH THE HANDLER, and the reason is a mutant this
	// test survived. The clause exists in THREE copies — here, and in each store — so a
	// submission that gets past this one is still refused by the store's, and a test that
	// asserted only the handler's answer stayed GREEN with this layer's clause reverted to
	// `kind == message.AttachmentEpoch`. Measured: `go test ./api/ -run
	// TestAKind0x0005AttachmentOnAnOrdinaryRecordIsRefused` was `ok` under that mutant. The
	// copies defend each other in production and that is worth having; what it costs is that
	// an end-to-end assertion cannot hold any ONE of them, so this line calls check 3 directly.
	direct := &recordPass{projection: ordinary}
	if reason := fixture.handler.staticShape(fixture.groupId, direct); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("check 3 answered %v for an ordinary record carrying a kind 0x0005 attachment, want REASON_REJECTED; this is the api layer's own copy of the iff and nothing below it is involved", reason)
	}
	if got := fixture.submitWithKeys(t, nil, ordinary)[0].GetReason(); got != protocol.Reason_REASON_REJECTED {
		t.Fatalf("an ordinary record carrying a kind 0x0005 attachment was answered %v, want REASON_REJECTED", got)
	}
	// and the same clause's other half, which was already held: a kind 0x0001 attachment on an
	// ordinary record
	plain := fixture.seal(t, sealed{
		sender:      senderB,
		epoch:       1,
		streamIndex: 1,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket256,
		head:        []byte("an ordinary record wearing a commit's attachment"),
		body:        []byte("an ordinary record wearing a commit's attachment"),
		attachment:  fixture.epochAttachment(2, 1),
		writeKey:    fixture.writeKey(1),
	})
	if got := fixture.submit(t, plain)[0].GetReason(); got != protocol.Reason_REASON_REJECTED {
		t.Fatalf("an ordinary record carrying a kind 0x0001 attachment was answered %v, want REASON_REJECTED", got)
	}

	// THE CONTROL: the same ordinary record with no attachment at all is accepted
	bare := fixture.seal(t, sealed{
		sender:      senderB,
		epoch:       1,
		streamIndex: 2,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket256,
		head:        []byte("an ordinary record"),
		body:        []byte("an ordinary record"),
		writeKey:    fixture.writeKey(1),
	})
	if got := fixture.submit(t, bare)[0].GetReason(); got != protocol.Reason_REASON_OK {
		t.Fatalf("an ordinary record with no attachment was answered %v, want REASON_OK", got)
	}
}

// A copy of a key with one octet flipped, which is the smallest change that can be made to it.
func flipOctet(key []byte, at int) []byte {
	altered := slices.Clone(key)
	altered[at] ^= 0x01
	return altered
}

// Which served records carry either key ANYWHERE in their marshaled bytes, by record_id.
//
// It marshals the whole `protocol.Record` rather than reading named fields, because item 244's
// leak was inside `record_bytes` — a column the server rebuilds verbatim — and a search over the
// projection fields alone would have found nothing while the keys went out on the wire.
func servedBytesCarrying(t *testing.T, response *protocol.FetchResponse, keys ...[]byte) []uint64 {
	t.Helper()
	found := []uint64{}
	for _, record := range response.GetRecords() {
		bs, err := proto.Marshal(record)
		if err != nil {
			t.Fatalf("marshaling a served record: %v", err)
		}
		for _, key := range keys {
			if len(key) != 0 && containsSubslice(bs, key) {
				found = append(found, record.GetRecordId())
				break
			}
		}
	}
	return found
}

func containsSubslice(haystack []byte, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for start := 0; start+len(needle) <= len(haystack); start++ {
		if slices.Equal(haystack[start:start+len(needle)], needle) {
			return true
		}
	}
	return false
}
