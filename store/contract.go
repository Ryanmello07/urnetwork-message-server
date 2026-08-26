package store

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect/protocol"
)

// RunContract is every behavioural test a [Store] owes, and it belongs to the interface rather
// than to any implementation of it. The memory implementation calls it; the pgx implementation
// calls it unchanged when it lands.
//
// This is the answer to the hazard the interface creates, and it is the reason it is written
// this way round. An in-memory store can hand out semantics Postgres will not — a map lookup
// is atomic where `SELECT … FOR UPDATE` is not, a Go mutex serialises what READ COMMITTED
// interleaves — so a suite written *for* the memory store would pass here and the deployment
// would fail there. The rule for what goes in: if a test could only pass against a map, it
// does not belong; if it belongs, both implementations owe it.
//
// The racy cases are the interesting ones, so they are run concurrently and for real, and they
// assert the invariant rather than a winner. "Exactly one of them wins and the others get the
// documented refusal" is the property. "The first one wins" is not a property of anything.
//
// It lives in a non-test file because an exported helper has to; that is the same trade
// net/http/httptest makes, and it is why the file imports testing.
func RunContract(t *testing.T, newStore func() Store) {
	t.Helper()

	// where the AST gate below reads its class from: this file's directory, and the directory
	// of whoever called RunContract, so an implementation living beside its own test is
	// covered without this file knowing anything about it
	_, here, _, _ := runtime.Caller(0)
	_, caller, _, _ := runtime.Caller(1)
	directories := []string{filepath.Dir(here)}
	if directory := filepath.Dir(caller); directory != directories[0] {
		directories = append(directories, directory)
	}

	seen := &recorder{reasons: map[protocol.Reason]int{}}
	// runs after every subtest below, parallel ones included
	t.Cleanup(func() { assertEveryRefusalIsExercised(t, directories, seen) })

	t.Run("TheIdempotencyProbeOfStep0", func(t *testing.T) { contractProbe(t, newStore, seen) })
	t.Run("RecordIdsAreGaplessAndOneBased", func(t *testing.T) { contractAllocation(t, newStore, seen) })
	t.Run("AStreamIndexIsMonotonicAndNotContiguous", func(t *testing.T) { contractStreamIndex(t, newStore, seen) })
	t.Run("TheEpochGateIsCommitAware", func(t *testing.T) { contractEpochGate(t, newStore, seen) })
	t.Run("AnUnavailableGroupIsOneAnswer", func(t *testing.T) { contractGroupAvailability(t, newStore, seen) })
	t.Run("ACommitAttachmentIsCheckedBeforeTheCas", func(t *testing.T) { contractAttachment(t, newStore, seen) })
	t.Run("ARejectionRollsTheWholeBatchBack", func(t *testing.T) { contractBatch(t, newStore, seen) })
	t.Run("RetentionIsResolvedAtStep6", func(t *testing.T) { contractRetention(t, newStore, seen) })
	t.Run("AWonCommitMovesEpochKeyCustody", func(t *testing.T) { contractEpochKeys(t, newStore, seen) })
	t.Run("TheReadPathAllocatesNothing", func(t *testing.T) { contractFetch(t, newStore, seen) })
	t.Run("ConcurrentSubmittersAtOneStreamIndex", func(t *testing.T) { contractConcurrentStreamIndex(t, newStore, seen) })
	t.Run("ConcurrentCommittersAtOneEpoch", func(t *testing.T) { contractConcurrentCommitters(t, newStore, seen) })
	t.Run("ARetryArrivingWhileTheOriginalIsInFlight", func(t *testing.T) { contractConcurrentRetry(t, newStore, seen) })
	t.Run("AnErrorIsForTheCallerAndNeverForTheClient", func(t *testing.T) { contractCallerErrors(t, newStore) })
}

// A refusal is a reason on a result; an error is the API layer having handed the store
// something no client could have produced. The two are not interchangeable, and each of these
// would otherwise arrive as a REASON_REJECTED that the operator could never tell from a bad MAC.
func contractCallerErrors(t *testing.T, newStore func() Store) {
	t.Parallel()
	ctx := context.Background()

	transient := ordinaryRecord(testHandle(0x21), 1, 0, 0x30)
	transient.RetentionClass = ClassEphBase // EPH(0)
	short := ordinaryRecord(testHandle(0x21), 1, 0, 0x30)
	short.SenderHandle = testBytes(SenderHandleBytes-1, 0x21)

	cases := []struct {
		name    string
		records []*Record
		want    error
	}{
		// §7.6 is normative that an EPH(0) transient never touches disk: it is published and
		// dropped, so it has no row here to be stored in and no record_id to be given
		{name: "AnEph0TransientNeverReachesTheStore", records: []*Record{transient}, want: ErrTransientRecord},
		{name: "AnEmptyBatchHasNoResultToAlignWith", records: []*Record{}, want: ErrEmptyBatch},
		{name: "AnIdentifierOfTheWrongLength", records: []*Record{short}, want: ErrIdentifierShape},
		// §4.3.3: mixing a commit with ordinary records makes partial-failure semantics
		// ambiguous during an epoch change, and a commit is one record by construction
		{name: "ACommitMixedIntoABatch", want: ErrCommitBatch, records: []*Record{
			commitRecord(testHandle(0x31), 1, 0, 2, 0x40),
			ordinaryRecord(testHandle(0x21), 1, 0, 0x30),
		}},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			t.Parallel()
			store, group := openGroup(t, newStore())
			before := nextRecordId(t, store, group)
			response, err := store.Submit(ctx, &SubmitRequest{GroupId: group, Records: current.records})
			if !errors.Is(err, current.want) {
				t.Fatalf("Submit answered (%v, %v), want the error %v", response, err, current.want)
			}
			if response != nil {
				t.Fatalf("Submit answered an error and a response; a caller that reads results on an error reads results nobody wrote")
			}
			if after := nextRecordId(t, store, group); after != before {
				t.Fatalf("a refused-at-the-door submission moved next_record_id from %d to %d", before, after)
			}
		})
	}
}

// ── step (0) ─────────────────────────────────────────────────────────────────────────────

func contractProbe(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()

	t.Run("AbsentContinuesToTheGates", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		results := submit(t, store, seen, group, ordinaryRecord(sender, 1, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_OK)
		if results[0].RecordId == 0 {
			t.Fatal("an accepted record was given record_id 0, which Spec A §5.1 reserves as the from-the-beginning cursor")
		}
	})

	t.Run("BothHashesMatchingIsIdempotentAndAllocatesNothing", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		record := ordinaryRecord(sender, 1, 7, 0x30)

		first := submit(t, store, seen, group, record)
		wantReason(t, first[0], protocol.Reason_REASON_OK)

		before := nextRecordId(t, store, group)
		second := submit(t, store, seen, group, ordinaryRecord(sender, 1, 7, 0x30))
		wantReason(t, second[0], protocol.Reason_REASON_OK)
		if second[0].RecordId != first[0].RecordId {
			t.Fatalf("a retry of an accepted record answered record_id %d and the original was %d; §6.3 returns the record that landed",
				second[0].RecordId, first[0].RecordId)
		}
		if after := nextRecordId(t, store, group); after != before {
			t.Fatalf("an idempotent retry moved next_record_id from %d to %d; §6.1 step (0) answers before any allocation", before, after)
		}
	})

	t.Run("ADifferingBodyIsStreamIndexReused", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		submit(t, store, seen, group, ordinaryRecord(sender, 1, 7, 0x30))

		differing := ordinaryRecord(sender, 1, 7, 0x30)
		differing.BodyHash = testBytes(BodyHashBytes, 0x99)
		results := submit(t, store, seen, group, differing)
		wantReason(t, results[0], protocol.Reason_REASON_STREAM_INDEX_REUSED)
	})

	t.Run("ADifferingHeadIsStreamIndexReused", func(t *testing.T) {
		t.Parallel()
		// §6.3 compares both hashes because two records can legitimately share a body hash —
		// an empty body — while differing in the head. A probe on body_hash alone calls the
		// second one a retry of the first and hands back a record_id for someone else's row.
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		first := ordinaryRecord(sender, 1, 7, 0x30)
		first.CtBody = nil
		first.BodyHash = testBytes(BodyHashBytes, 0x00)
		submit(t, store, seen, group, first)

		second := ordinaryRecord(sender, 1, 7, 0x30)
		second.CtBody = nil
		second.BodyHash = testBytes(BodyHashBytes, 0x00)
		second.CtHead = []byte("a different head entirely")
		results := submit(t, store, seen, group, second)
		wantReason(t, results[0], protocol.Reason_REASON_STREAM_INDEX_REUSED)
	})

	t.Run("AnIdenticalRetryAtAnAdvancedEpochIsStillOk", func(t *testing.T) {
		t.Parallel()
		// the probe is ahead of the epoch gate, and this is what that buys: a genuine retry is
		// by definition at an already-consumed index and often at an epoch that has since
		// advanced, so a probe behind the gates rejects every one of them
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		record := ordinaryRecord(sender, 1, 7, 0x30)
		first := submit(t, store, seen, group, record)
		wantReason(t, first[0], protocol.Reason_REASON_OK)

		advanceEpoch(t, store, seen, group, testHandle(0x22), 0)

		second := submit(t, store, seen, group, ordinaryRecord(sender, 1, 7, 0x30))
		wantReason(t, second[0], protocol.Reason_REASON_OK)
		if second[0].RecordId != first[0].RecordId {
			t.Fatalf("a retry across an epoch change answered record_id %d, want %d", second[0].RecordId, first[0].RecordId)
		}
	})

	t.Run("ForACommitTheProbeTakesPrecedenceOverTheCas", func(t *testing.T) {
		t.Parallel()
		// §6.3: getting this backwards makes every timeout look like a fork, sends the client
		// through the epoch-n+1 discard path, and burns a pq_secret it may never reuse
		store, group := openGroup(t, newStore())
		committer := testHandle(0x31)
		commit := commitRecord(committer, 1, 0, 2, 0x40)

		first := submit(t, store, seen, group, commit)
		wantReason(t, first[0], protocol.Reason_REASON_OK)

		before := nextRecordId(t, store, group)
		second := submit(t, store, seen, group, commitRecord(committer, 1, 0, 2, 0x40))
		wantReason(t, second[0], protocol.Reason_REASON_OK)
		if second[0].RecordId != first[0].RecordId {
			t.Fatalf("a retried identical commit answered record_id %d, want the one that landed, %d", second[0].RecordId, first[0].RecordId)
		}
		if after := nextRecordId(t, store, group); after != before {
			t.Fatalf("a retried identical commit moved next_record_id from %d to %d", before, after)
		}
	})

	t.Run("AnyRejectionOfACommitCarriesTheWinner", func(t *testing.T) {
		t.Parallel()
		// §6.2 binds the loser protocol to ANY rejection of a commit submission, not to
		// REASON_COMMIT_LOST alone. This one is refused at step (0), before a gate runs at all
		store, group := openGroup(t, newStore())
		committer := testHandle(0x31)
		winner := submit(t, store, seen, group, commitRecord(committer, 1, 0, 2, 0x40))
		wantReason(t, winner[0], protocol.Reason_REASON_OK)

		differing := commitRecord(committer, 1, 0, 2, 0x40)
		differing.BodyHash = testBytes(BodyHashBytes, 0x77)
		results := submit(t, store, seen, group, differing)
		wantReason(t, results[0], protocol.Reason_REASON_STREAM_INDEX_REUSED)
		if results[0].WinningCommit == nil {
			t.Fatal("a rejected commit submission carried no winning_commit; §6.2 sets it on every rejection, which is what makes its step 2 reachable")
		}
		if results[0].WinningCommit.RecordId != winner[0].RecordId {
			t.Fatalf("winning_commit named record %d, want %d", results[0].WinningCommit.RecordId, winner[0].RecordId)
		}
	})
}

// ── allocation ───────────────────────────────────────────────────────────────────────────

func contractAllocation(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	store := newStore()
	ctx := context.Background()

	group := testGroupId(0x11)
	creator := testHandle(0x21)
	created, err := store.CreateGroup(ctx, &CreateGroupRequest{
		GroupId:           group,
		InitialCommit:     commitRecord(creator, 0, 0, 1, 0x40),
		BootstrapWriteKey: testBytes(EpochKeyBytes, 0x50),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	seen.observe(created.Reason)
	if created.Reason != protocol.Reason_REASON_OK {
		t.Fatalf("CreateGroup answered %v", created.Reason)
	}
	// the literal 1, never the package's own constant: a contract that read the number out of
	// the implementation would agree with an implementation that had changed it, which is the
	// exact edit §3.2 spends a paragraph warning about
	if created.RecordId != 1 {
		t.Fatalf("the founding commit was given record_id %d, want 1; §3.2 is 1-based so that since_record_id = 0 can mean from the beginning",
			created.RecordId)
	}
	if created.CurrentEpoch != 1 {
		t.Fatalf("CreateGroup left current_epoch at %d, want 1", created.CurrentEpoch)
	}

	submit(t, store, seen, group, markerRecord(creator, 1, 1, 1))
	sender := testHandle(0x22)
	for index := range uint64(6) {
		results := submit(t, store, seen, group, ordinaryRecord(sender, 1, index, byte(0x60+index)))
		wantReason(t, results[0], protocol.Reason_REASON_OK)
	}

	// gapless, 1-based, and 0 never assigned — read back through the from-the-beginning cursor
	fetched, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(fetched.Records) != 8 {
		t.Fatalf("since_record_id = 0 returned %d records, want all 8; a 0-based allocator makes the founding commit unfetchable by everyone who did not create it", len(fetched.Records))
	}
	for index, record := range fetched.Records {
		if want := uint64(index) + 1; record.RecordId != want {
			t.Fatalf("record %d of the group has record_id %d, want %d; the id sequence is gapless and a hole in it is what §12.2 C-4 tells clients to treat as a fault",
				index, record.RecordId, want)
		}
	}
	if fetched.HighWaterRecordId != 8 {
		t.Fatalf("high_water_record_id is %d, want 8", fetched.HighWaterRecordId)
	}
}

// ── step (3) ─────────────────────────────────────────────────────────────────────────────

func contractStreamIndex(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()

	t.Run("AGapIsAccepted", func(t *testing.T) {
		t.Parallel()
		// a refused write, a crash between reserve and send, or a lost commit leaves a legal
		// gap, and §6.1 enforces monotonicity and not contiguity for exactly those three
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, 0, 0x30))[0], protocol.Reason_REASON_OK)
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, 1000, 0x31))[0], protocol.Reason_REASON_OK)
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, 1001, 0x32))[0], protocol.Reason_REASON_OK)
	})

	t.Run("ARegressionIsRefused", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		submit(t, store, seen, group, ordinaryRecord(sender, 1, 10, 0x30))
		results := submit(t, store, seen, group, ordinaryRecord(sender, 1, 7, 0x31))
		wantReason(t, results[0], protocol.Reason_REASON_STREAM_INDEX_REGRESSED)
	})

	t.Run("TheSameIndexIsRefusedNotRegressed", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		sender := testHandle(0x21)
		submit(t, store, seen, group, ordinaryRecord(sender, 1, 10, 0x30))
		results := submit(t, store, seen, group, ordinaryRecord(sender, 1, 10, 0x31))
		wantReason(t, results[0], protocol.Reason_REASON_STREAM_INDEX_REUSED)
	})

	t.Run("TheIndexIsScopedToOneSender", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 40, 0x30))
		results := submit(t, store, seen, group, ordinaryRecord(testHandle(0x22), 1, 0, 0x31))
		wantReason(t, results[0], protocol.Reason_REASON_OK)
	})
}

// ── step (2) ─────────────────────────────────────────────────────────────────────────────

func contractEpochGate(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()

	t.Run("ALosingCommitterIsToldItLostAndNotThatItIsStale", func(t *testing.T) {
		t.Parallel()
		// the row lock serialises committers, so a loser acquires it only AFTER the winner
		// advanced the epoch. An epoch-first gate therefore answers EPOCH_STALE to every loser
		// and §6.2's mandatory loser protocol — the one carrying the hard MUST NOT on
		// pq_secret reuse — never fires at all
		store, group := openGroup(t, newStore())
		winner := submit(t, store, seen, group, commitRecord(testHandle(0x31), 1, 0, 2, 0x40))
		wantReason(t, winner[0], protocol.Reason_REASON_OK)

		results := submit(t, store, seen, group, commitRecord(testHandle(0x32), 1, 0, 2, 0x41))
		wantReason(t, results[0], protocol.Reason_REASON_COMMIT_LOST)
		if results[0].CurrentEpoch != 2 {
			t.Fatalf("the loser was told current_epoch %d, want the epoch the winner opened, 2", results[0].CurrentEpoch)
		}
		if results[0].WinningCommit == nil || results[0].WinningCommit.RecordId != winner[0].RecordId {
			t.Fatal("the loser was not handed the winning commit, so it cannot apply it and §6.2 steps 3 to 5 are unreachable")
		}
	})

	t.Run("AnOrdinaryRecordAtAnOldEpochIsStale", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		advanceEpoch(t, store, seen, group, testHandle(0x31), 0)
		results := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_EPOCH_STALE)
		if results[0].CurrentEpoch != 2 {
			t.Fatalf("EPOCH_STALE carried current_epoch %d, want 2", results[0].CurrentEpoch)
		}
	})

	t.Run("TheGroupIsReadableButNotWritableUntilTheMarkerLands", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		committer := testHandle(0x31)
		wantReason(t, submit(t, store, seen, group, commitRecord(committer, 1, 0, 2, 0x40))[0], protocol.Reason_REASON_OK)

		ordinary := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 2, 0, 0x30))
		wantReason(t, ordinary[0], protocol.Reason_REASON_EPOCH_INCOMPLETE)

		// a wrap is exempt, which is what lets the fan-out of the epoch publication sequence
		// happen at all while the group is closed to ordinary writes
		wrap := submit(t, store, seen, group, wrapRecord(committer, 2, 1, testHandle(0x21)))
		wantReason(t, wrap[0], protocol.Reason_REASON_OK)

		marker := submit(t, store, seen, group, markerRecord(committer, 2, 2, 1))
		wantReason(t, marker[0], protocol.Reason_REASON_OK)

		reopened := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 2, 0, 0x30))
		wantReason(t, reopened[0], protocol.Reason_REASON_OK)
	})
}

// ── step (1) ─────────────────────────────────────────────────────────────────────────────

func contractGroupAvailability(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()

	t.Run("AnUnknownGroupIsRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		unknown := testGroupId(0xEE)
		results := submit(t, store, seen, unknown, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_REJECTED)

		if _, err := store.GroupState(ctx, unknown); !errors.Is(err, ErrGroupUnavailable) {
			t.Fatalf("GroupState on an unknown group answered %v, want ErrGroupUnavailable", err)
		}
	})

	t.Run("AClosedGroupIsTheSameAnswerAsAnUnknownOne", func(t *testing.T) {
		t.Parallel()
		// §4.5: distinguishing them would turn the submit path into an oracle for group
		// existence to a party holding no write_key
		store, group := openGroup(t, newStore())
		if err := store.CloseGroup(ctx, group); err != nil {
			t.Fatalf("CloseGroup: %v", err)
		}
		results := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_REJECTED)

		closed := errorOf(store.GroupState(ctx, group))
		unknown := errorOf(store.GroupState(ctx, testGroupId(0xEE)))
		if closed == nil || unknown == nil || !errors.Is(closed, unknown) {
			t.Fatalf("a closed group answered %v and an unknown one %v; §6.1 step (1) reads zero rows for both and §4.5 refuses to tell them apart", closed, unknown)
		}
		if _, err := store.Fetch(ctx, &FetchRequest{GroupId: group}); !errors.Is(err, ErrGroupUnavailable) {
			t.Fatalf("Fetch on a closed group answered %v, want ErrGroupUnavailable", err)
		}
	})

	t.Run("ASecondCreateOfTheSameIdIsRejected", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		before := nextRecordId(t, store, group)
		again, err := store.CreateGroup(ctx, &CreateGroupRequest{
			GroupId:           group,
			InitialCommit:     commitRecord(testHandle(0x29), 0, 0, 1, 0x44),
			BootstrapWriteKey: testBytes(EpochKeyBytes, 0x55),
		})
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		seen.observe(again.Reason)
		if again.Reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("CreateGroup on an existing id answered %v, want REASON_REJECTED", again.Reason)
		}
		if after := nextRecordId(t, store, group); after != before {
			t.Fatalf("a refused CreateGroup moved the existing group's next_record_id from %d to %d", before, after)
		}
	})
}

// ── the attachment, before the CAS ───────────────────────────────────────────────────────

func contractAttachment(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()

	// an accepted commit carrying a malformed attachment opens an epoch with no verifiable
	// write key and bricks the group permanently: no member can submit again and there is no
	// epoch to commit from. Every one of these is refused rather than accepted and repaired.
	malformed := map[string]func(*EpochAttachment){
		"AWriteKeyThatIsNot32Bytes": func(attachment *EpochAttachment) {
			attachment.WriteKey = testBytes(EpochKeyBytes-1, 0x40)
		},
		"AReadKeyThatIsNot32Bytes": func(attachment *EpochAttachment) {
			attachment.ReadKey = testBytes(EpochKeyBytes+1, 0x41)
		},
		"AnExpectedWrapCountOfZero": func(attachment *EpochAttachment) {
			attachment.ExpectedWrapCount = 0
		},
		"AnEpochThatIsNotTheNextOne": func(attachment *EpochAttachment) {
			attachment.Epoch = 9
		},
	}
	for name, damage := range malformed {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, group := openGroup(t, newStore())
			record := commitRecord(testHandle(0x31), 1, 0, 2, 0x40)
			damage(record.Attachment.Epoch)

			before := stateOf(t, store, group)
			results := submit(t, store, seen, group, record)
			wantReason(t, results[0], protocol.Reason_REASON_REJECTED)

			after := stateOf(t, store, group)
			if after.CurrentEpoch != before.CurrentEpoch {
				t.Fatalf("a commit refused for its attachment moved current_epoch from %d to %d; §6.4 leaves it untouched",
					before.CurrentEpoch, after.CurrentEpoch)
			}
			if after.PolicyVersion != before.PolicyVersion {
				t.Fatalf("a commit refused for its attachment moved policy_version from %d to %d", before.PolicyVersion, after.PolicyVersion)
			}
		})
	}

	t.Run("ACommitWithNoEpochAttachmentIsRejected", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore())
		record := ordinaryRecord(testHandle(0x31), 1, 0, 0x30)
		record.IsCommit = true
		results := submit(t, store, seen, group, record)
		wantReason(t, results[0], protocol.Reason_REASON_REJECTED)
	})

	t.Run("AnOrdinaryRecordWithAnEpochAttachmentIsRejected", func(t *testing.T) {
		t.Parallel()
		// EpochAttachment iff is_commit (§5.1 check 3). Without the iff, a member could set
		// the next epoch's write key without ever winning a CAS
		store, group := openGroup(t, newStore())
		record := commitRecord(testHandle(0x31), 1, 0, 2, 0x40)
		record.IsCommit = false
		results := submit(t, store, seen, group, record)
		wantReason(t, results[0], protocol.Reason_REASON_REJECTED)
	})
}

// ── step (3b) ────────────────────────────────────────────────────────────────────────────

func contractBatch(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	store, group := openGroup(t, newStore())
	sender := testHandle(0x21)
	submit(t, store, seen, group, ordinaryRecord(sender, 1, 5, 0x30))

	before := nextRecordId(t, store, group)
	results := submit(t, store, seen, group,
		ordinaryRecord(sender, 1, 6, 0x31),
		ordinaryRecord(sender, 1, 7, 0x32),
		ordinaryRecord(sender, 1, 2, 0x33), // regresses, and takes the batch with it
	)
	if len(results) != 3 {
		t.Fatalf("a batch of 3 answered %d results; they are positionally aligned with the request", len(results))
	}
	for index, result := range results {
		if result.Reason == protocol.Reason_REASON_OK {
			t.Fatalf("result %d of a refused batch is REASON_OK; §6.1 step (3b) rolls the WHOLE batch back with a reason on every result", index)
		}
	}
	wantReason(t, results[2], protocol.Reason_REASON_STREAM_INDEX_REGRESSED)
	if after := nextRecordId(t, store, group); after != before {
		t.Fatalf("a refused batch moved next_record_id from %d to %d; an allocated block larger than the rows written gives the group a permanent record_id gap",
			before, after)
	}

	// and the two innocent indexes are still free, because nothing was written
	accepted := submit(t, store, seen, group,
		ordinaryRecord(sender, 1, 6, 0x31),
		ordinaryRecord(sender, 1, 7, 0x32),
	)
	wantReason(t, accepted[0], protocol.Reason_REASON_OK)
	wantReason(t, accepted[1], protocol.Reason_REASON_OK)
}

// ── step (6) ─────────────────────────────────────────────────────────────────────────────

func contractRetention(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()

	// the three cases of §7.3 are three different sentences to the user, and a client that
	// could only see the number would have to pick one of them and would be wrong twice
	cases := []struct {
		name     string
		durable  uint32
		expected func(*testing.T, *RetentionApplied)
	}{
		{
			name:    "TheUnsetSentinelIsDefaultedAndNotClamped",
			durable: DurableUnset,
			expected: func(t *testing.T, applied *RetentionApplied) {
				if !applied.DurableDefaulted {
					t.Error("durable_defaulted is false for a group that sent the unset sentinel; it asked for nothing, so nothing was refused")
				}
				if applied.DurableClampedDown || applied.DurableFlooredUp {
					t.Error("a defaulted policy was reported as clamped")
				}
			},
		},
		{
			name:    "AnExplicitPolicyIsNeitherDefaultedNorClamped",
			durable: 1000,
			expected: func(t *testing.T, applied *RetentionApplied) {
				if applied.DurableDefaulted {
					t.Error("durable_defaulted is true for a group that named a value")
				}
				if applied.DurableTtlSeconds != 1000 {
					t.Errorf("an explicit 1000 was stored as %d", applied.DurableTtlSeconds)
				}
			},
		},
		{
			name:    "TheIndefiniteSentinelSurvivesOnAServerWithNoTextCap",
			durable: DurableIndefinite,
			expected: func(t *testing.T, applied *RetentionApplied) {
				if applied.DurableTtlSeconds != DurableIndefinite {
					t.Errorf("indefinite was stored as %d on a server advertising no text cap", applied.DurableTtlSeconds)
				}
				if applied.DurableClampedDown {
					t.Error("indefinite was reported as clamped by a server that advertises no cap to clamp to")
				}
			},
		},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			t.Parallel()
			store, group := openGroup(t, newStore())
			record := commitRecord(testHandle(0x31), 1, 0, 2, 0x40)
			record.Attachment.Epoch.DurableTtlSeconds = current.durable
			results := submit(t, store, seen, group, record)
			wantReason(t, results[0], protocol.Reason_REASON_OK)
			if results[0].Applied == nil {
				t.Fatal("an accepted commit carried no RetentionApplied, so the client cannot name the effective value")
			}
			if results[0].Applied.RequestedDurableTtlSeconds != current.durable {
				t.Fatalf("RetentionApplied reported the request as %d, want %d", results[0].Applied.RequestedDurableTtlSeconds, current.durable)
			}
			current.expected(t, results[0].Applied)

			state, err := store.GroupState(ctx, group)
			if err != nil {
				t.Fatalf("GroupState: %v", err)
			}
			if state.PolicyVersion == 0 {
				t.Fatal("policy_version was never advanced by an accepted commit")
			}
		})
	}
}

// ── §5.3 ─────────────────────────────────────────────────────────────────────────────────

func contractEpochKeys(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	store, group := openGroup(t, newStore())

	wantReason(t, submit(t, store, seen, group, commitRecord(testHandle(0x31), 1, 0, 2, 0x40))[0], protocol.Reason_REASON_OK)

	opened, err := store.EpochKeys(ctx, group, 2)
	if err != nil {
		t.Fatalf("no keys installed for the epoch the commit opened: %v", err)
	}
	if len(opened.WriteKey) != EpochKeyBytes || len(opened.ReadKey) != EpochKeyBytes {
		t.Fatalf("epoch 2 holds a %d-byte write key and a %d-byte read key, want %d of each",
			len(opened.WriteKey), len(opened.ReadKey), EpochKeyBytes)
	}
	if opened.ReadKeyInstall.IsZero() {
		t.Error("read_key_install was not stamped, so the 90-day window of §5.3 has no start")
	}

	// the briefly-retired predecessor: still verifiable, and marked for the tidy loop
	retired, err := store.EpochKeys(ctx, group, 1)
	if err != nil {
		t.Fatalf("the superseded epoch's keys are already gone: %v", err)
	}
	if retired.WriteKey == nil {
		t.Error("the superseded epoch's write key was discarded in the same transaction; decision B9 keeps one predecessor so a record in flight still verifies")
	}
	if retired.RetireTime.IsZero() {
		t.Error("the superseded epoch was not stamped with a retire_time, so the tidy loop has nothing to act on")
	}

	// and everything strictly older loses its write key, which is the load-bearing half of
	// §6.1's predicate: without the `epoch < current_epoch` the retired predecessor goes too
	older, err := store.EpochKeys(ctx, group, 0)
	if err == nil && older.WriteKey != nil {
		t.Error("an epoch two behind the current one still holds a write key; §5.3 retains the current epoch's and one predecessor, and nothing older")
	}
}

// ── §5.1.1 ───────────────────────────────────────────────────────────────────────────────

func contractFetch(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	store, group := openGroup(t, newStore())
	sender := testHandle(0x21)
	for index := range uint64(4) {
		submit(t, store, seen, group, ordinaryRecord(sender, 1, index, byte(0x60+index)))
	}

	before := nextRecordId(t, store, group)
	page, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0, Limit: 2})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(page.Records) != 2 || page.Complete {
		t.Fatalf("a limited page returned %d records with complete=%v, want 2 and false; §4.3.4 calls truncation normal", len(page.Records), page.Complete)
	}
	if after := nextRecordId(t, store, group); after != before {
		t.Fatalf("a fetch moved next_record_id from %d to %d; §5.1.1 opens no transaction and allocates no row", before, after)
	}

	rest, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: page.NextRecordId})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rest.Records) == 0 || rest.Records[0].RecordId != page.Records[1].RecordId+1 {
		t.Fatalf("the cursor from the first page did not resume where it left off")
	}

	heads, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0, HeadsOnly: true})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, record := range heads.Records {
		if record.CtBody != nil {
			t.Fatalf("heads_only returned a body for record %d", record.RecordId)
		}
	}

	permanent, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0, ClassMask: 1 << ClassPermanent})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, record := range permanent.Records {
		if record.RetentionClass != ClassPermanent {
			t.Fatalf("a PERMANENT-only fetch returned a record of class %d", record.RetentionClass)
		}
	}
}

// ── the racy half of §6.1 ────────────────────────────────────────────────────────────────

func contractConcurrentStreamIndex(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	// real contention on one (group, sender, stream_index), and the assertion is the invariant
	// rather than a winner: exactly one submission is accepted, every other is refused with a
	// documented stream-index refusal, and the group allocated exactly one id.
	const submitters = 8
	ctx := context.Background()
	store, group := openGroup(t, newStore())
	sender := testHandle(0x21)

	before := nextRecordId(t, store, group)
	results := race(submitters, func(index int) *SubmitResult {
		record := ordinaryRecord(sender, 1, 99, byte(0x70+index))
		response, err := store.Submit(ctx, &SubmitRequest{GroupId: group, Records: []*Record{record}})
		if err != nil {
			t.Errorf("Submit: %v", err)
			return nil
		}
		return response.Results[0]
	})

	accepted := 0
	for _, result := range results {
		if result == nil {
			continue
		}
		seen.observe(result.Reason)
		switch result.Reason {
		case protocol.Reason_REASON_OK:
			accepted++
		case protocol.Reason_REASON_STREAM_INDEX_REUSED, protocol.Reason_REASON_STREAM_INDEX_REGRESSED:
			// the two documented refusals a loser can get, and which one depends only on
			// whether its step (0) probe ran before or after the winner committed. Both mean
			// the same thing to the client and neither allocated anything
		default:
			t.Errorf("a loser at a contended stream_index was refused with %v, which is not one of the refusals §6.1 documents for it", result.Reason)
		}
	}
	if accepted != 1 {
		t.Fatalf("%d of %d submissions at one stream_index were accepted, want exactly 1", accepted, submitters)
	}
	if after := nextRecordId(t, store, group); after != before+1 {
		t.Fatalf("%d submitters at one stream_index moved next_record_id by %d, want 1", submitters, after-before)
	}
}

func contractConcurrentCommitters(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	const committers = 8
	ctx := context.Background()
	store, group := openGroup(t, newStore())

	before := nextRecordId(t, store, group)
	results := race(committers, func(index int) *SubmitResult {
		record := commitRecord(testHandle(byte(0x40+index)), 1, 0, 2, byte(0x80+index))
		response, err := store.Submit(ctx, &SubmitRequest{GroupId: group, Records: []*Record{record}})
		if err != nil {
			t.Errorf("Submit: %v", err)
			return nil
		}
		return response.Results[0]
	})

	winners, lost := 0, 0
	winningId := uint64(0)
	for _, result := range results {
		if result == nil {
			continue
		}
		seen.observe(result.Reason)
		switch result.Reason {
		case protocol.Reason_REASON_OK:
			winners++
			winningId = result.RecordId
		case protocol.Reason_REASON_COMMIT_LOST:
			lost++
			if result.WinningCommit == nil {
				t.Error("a losing committer was not handed the winner, so §6.2 steps 3 to 5 cannot run")
			}
			if result.CurrentEpoch != 2 {
				t.Errorf("a losing committer was told current_epoch %d, want 2", result.CurrentEpoch)
			}
		default:
			t.Errorf("a losing committer was refused with %v; §6.4 says never EPOCH_STALE, which is what the previous ordering produced", result.Reason)
		}
	}
	if winners != 1 || lost != committers-1 {
		t.Fatalf("%d committers at one epoch produced %d winners and %d losers, want 1 and %d", committers, winners, lost, committers-1)
	}
	for _, result := range results {
		if result != nil && result.WinningCommit != nil && result.WinningCommit.RecordId != winningId {
			t.Fatalf("a loser was handed record %d as the winner and the winner was %d", result.WinningCommit.RecordId, winningId)
		}
	}
	if after := nextRecordId(t, store, group); after != before+1 {
		t.Fatalf("%d committers at one epoch moved next_record_id by %d, want 1", committers, after-before)
	}
	state := stateOf(t, store, group)
	if state.CurrentEpoch != 2 {
		t.Fatalf("%d committers at one epoch left current_epoch at %d, want exactly one advance to 2", committers, state.CurrentEpoch)
	}
}

func contractConcurrentRetry(t *testing.T, newStore func() Store, seen *recorder) {
	t.Parallel()
	// the same submission, byte for byte, from several connections at once: a client that
	// timed out and retried while the original was still in flight. Whether a given retry sees
	// the claim or the sender high-water depends on where the original had got to, so the
	// property is not which answer it gets — it is that one row landed, that every acceptance
	// names that same row, and that no refusal is anything but a documented stream-index one.
	const attempts = 8
	ctx := context.Background()
	store, group := openGroup(t, newStore())
	sender := testHandle(0x21)

	before := nextRecordId(t, store, group)
	results := race(attempts, func(int) *SubmitResult {
		response, err := store.Submit(ctx, &SubmitRequest{
			GroupId: group,
			Records: []*Record{ordinaryRecord(sender, 1, 42, 0x30)},
		})
		if err != nil {
			t.Errorf("Submit: %v", err)
			return nil
		}
		return response.Results[0]
	})

	accepted := map[uint64]int{}
	for _, result := range results {
		if result == nil {
			continue
		}
		seen.observe(result.Reason)
		switch result.Reason {
		case protocol.Reason_REASON_OK:
			accepted[result.RecordId]++
		case protocol.Reason_REASON_STREAM_INDEX_REUSED, protocol.Reason_REASON_STREAM_INDEX_REGRESSED:
		default:
			t.Errorf("a concurrent identical retry was refused with %v", result.Reason)
		}
	}
	if len(accepted) != 1 {
		t.Fatalf("%d identical concurrent submissions named %d distinct record ids, want exactly 1", attempts, len(accepted))
	}
	if after := nextRecordId(t, store, group); after != before+1 {
		t.Fatalf("%d identical concurrent submissions moved next_record_id by %d, want 1", attempts, after-before)
	}
}

func race(count int, attempt func(int) *SubmitResult) []*SubmitResult {
	results := make([]*SubmitResult, count)
	start := make(chan struct{})
	group := sync.WaitGroup{}
	for index := range count {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results[index] = attempt(index)
		}()
	}
	close(start)
	group.Wait()
	return results
}

// ── the derived gate: every refusal this package can name is exercised here ──────────────

type recorder struct {
	mutex   sync.Mutex
	reasons map[protocol.Reason]int
}

func (self *recorder) observe(reason protocol.Reason) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.reasons[reason]++
}

func (self *recorder) exercised() map[protocol.Reason]int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	found := map[protocol.Reason]int{}
	for reason, count := range self.reasons {
		found[reason] = count
	}
	return found
}

// The class this gate holds the suite to is DERIVED, from the Go source of the package under
// test, and is never a list typed here.
//
// A typed list understates the class the moment somebody adds a refusal, and the test that
// would have caught the missing coverage is the test that stopped covering it. So the reasons
// are read out of the AST: every protocol.Reason_REASON_* the package names, in any file,
// implementation and suite alike. A new refusal that no scenario above produces fails here,
// and it fails naming itself.
func assertEveryRefusalIsExercised(t *testing.T, directories []string, seen *recorder) {
	t.Helper()
	assertTheExtractorWorks(t)

	named, files := reasonsNamedIn(t, directories)
	if files == 0 {
		t.Fatalf("no Go source was read from %v, so this gate read nothing at all", directories)
	}
	if len(named) == 0 {
		t.Fatalf("%d files under %v name no protocol.Reason at all; either the store has stopped using §4.5's vocabulary or this gate has stopped seeing it", files, directories)
	}
	exercised := seen.exercised()

	described := []string{}
	for reason := range named {
		described = append(described, fmt.Sprintf("%v x%d", reason, exercised[reason]))
	}
	slices.Sort(described)
	t.Logf("%d files under %v name %d of §4.5's reasons; the contract produced them %s", files, directories, len(named), strings.Join(described, ", "))

	missing := []string{}
	for reason := range named {
		if exercised[reason] == 0 {
			missing = append(missing, reason.String())
		}
	}
	slices.Sort(missing)
	if len(missing) != 0 {
		t.Errorf("the store names these reasons and no contract scenario produced one:\n  %s\nevery refusal this interface can give owes a scenario here, and the scenario is what asserts that the refusal allocated nothing — §5.1's headline property is that an attacker without a write_key cannot force a single row lock, a single index write, or a single WAL byte",
			strings.Join(missing, "\n  "))
	}
}

// Every protocol.Reason named in the Go source of these directories, and how many files were
// read to find them.
func reasonsNamedIn(t *testing.T, directories []string) (map[protocol.Reason]bool, int) {
	t.Helper()
	named, files := map[protocol.Reason]bool{}, 0
	for _, directory := range directories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("reading %s: %v", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".go" {
				continue
			}
			name := filepath.Join(directory, entry.Name())
			text, err := os.ReadFile(name)
			if err != nil {
				t.Fatalf("reading %s: %v", name, err)
			}
			files++
			for reason := range reasonsIn(t, name, string(text)) {
				named[reason] = true
			}
		}
	}
	return named, files
}

// The identifiers of one source file that name a §4.5 reason, resolved through the generated
// enum's own name table rather than through a mapping written here.
func reasonsIn(t *testing.T, name string, source string) map[protocol.Reason]bool {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), name, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	found := map[protocol.Reason]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		identifier, isIdentifier := node.(*ast.Ident)
		if !isIdentifier {
			return true
		}
		value, isReason := protocol.Reason_value[strings.TrimPrefix(identifier.Name, "Reason_")]
		if !isReason || !strings.HasPrefix(identifier.Name, "Reason_REASON_") {
			return true
		}
		found[protocol.Reason(value)] = true
		return true
	})
	return found
}

// The extractor, held against a planted source and a clean one.
//
// Without both halves this gate reports the green run of a complete gate having read nothing:
// an extractor that finds nothing passes the clean control and reports every reason as
// exercised, and an extractor that finds everything passes the planted one and reports reasons
// the store never names.
func assertTheExtractorWorks(t *testing.T) {
	t.Helper()
	// the planted reason is named through the generated enum's own name table rather than as
	// an identifier, because an identifier here would be an identifier in this file, and the
	// class this gate derives is "every reason this package's source names" — a control that
	// planted itself into the class would demand a scenario for a refusal nothing can return
	quota := protocol.Reason(protocol.Reason_value["REASON_QUOTA_EXCEEDED"])
	planted := reasonsIn(t, "planted.go", `package planted

import "github.com/urnetwork/connect/protocol"

func f() protocol.Reason { return protocol.Reason_REASON_QUOTA_EXCEEDED }
`)
	if len(planted) != 1 || !planted[quota] {
		t.Fatalf("a source naming exactly one reason was read as %v", planted)
	}
	clean := reasonsIn(t, "clean.go", `package clean

const ReasonablyNamed = "REASON_QUOTA_EXCEEDED"

func f() int { return 0 }
`)
	if len(clean) != 0 {
		t.Fatalf("a source naming no reason at all was read as %v; a string and a lookalike identifier are not a reason", clean)
	}
}

// ── the harness every scenario submits through ───────────────────────────────────────────

// One submission, with the invariants that hold for EVERY submission asserted on the way past.
//
// Three of them, and they are here rather than in one scenario each because they are true of
// every call and a property asserted in one place is a property the next scenario forgets:
//
//   - a batch carrying any refusal allocated nothing at all (§6.1 step 3b, §5.1);
//   - the ids handed to an accepted batch are exactly the block next_record_id moved by, in
//     order, so gapless and 1-based is checked on every accepted record in this file;
//   - an acceptance that allocated nothing is a step (0) idempotent hit and names a record id
//     the group had already assigned.
func submit(t *testing.T, store Store, seen *recorder, groupId []byte, records ...*Record) []*SubmitResult {
	t.Helper()
	ctx := context.Background()

	before, known := readNextRecordId(store, groupId)
	response, err := store.Submit(ctx, &SubmitRequest{GroupId: groupId, Records: records})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if len(response.Results) != len(records) {
		t.Fatalf("a batch of %d answered %d results; §4.3.3 aligns them positionally", len(records), len(response.Results))
	}
	after, _ := readNextRecordId(store, groupId)

	refused := false
	for _, result := range response.Results {
		seen.observe(result.Reason)
		if result.Reason != protocol.Reason_REASON_OK {
			refused = true
		}
		if result.Reason == protocol.Reason_REASON_OK && result.RecordId == 0 {
			t.Fatalf("an accepted record was given record_id 0, which Spec A §5.1 reserves as the from-the-beginning cursor")
		}
	}
	if !known {
		return response.Results
	}

	if refused && after != before {
		t.Fatalf("a submission carrying a refusal moved next_record_id from %d to %d; §5.1's headline property is that a refusal costs the group nothing — not a row lock, not an index write, not a WAL byte",
			before, after)
	}
	allocated := []uint64{}
	for _, result := range response.Results {
		if result.Reason == protocol.Reason_REASON_OK && result.RecordId >= before {
			allocated = append(allocated, result.RecordId)
		}
	}
	if uint64(len(allocated)) != after-before {
		t.Fatalf("next_record_id moved by %d and %d results named a newly allocated id; the allocated block and the rows written are the same k or the group's id sequence acquires a permanent gap",
			after-before, len(allocated))
	}
	for index, id := range allocated {
		if want := before + uint64(index); id != want {
			t.Fatalf("the %d-th newly allocated id is %d, want %d; §6.1 step (4) allocates one contiguous block", index, id, want)
		}
	}
	return response.Results
}

func wantReason(t *testing.T, result *SubmitResult, want protocol.Reason) {
	t.Helper()
	if result.Reason != want {
		t.Fatalf("the submission was answered %v, want %v", result.Reason, want)
	}
}

// A group that exists and is open for ordinary writes: created, and then its epoch-1 wrap
// fan-out closed with the marker §6.1's epoch publication step 3 requires. Without the marker
// the group is readable-but-not-writable and every ordinary submit is REASON_EPOCH_INCOMPLETE,
// which is correct and is not what most of these scenarios are about.
func openGroup(t *testing.T, store Store) (Store, []byte) {
	t.Helper()
	ctx := context.Background()
	groupId := testGroupId(0x11)
	creator := testHandle(0x20)

	created, err := store.CreateGroup(ctx, &CreateGroupRequest{
		GroupId:           groupId,
		InitialCommit:     commitRecord(creator, 0, 0, 1, 0x40),
		BootstrapWriteKey: testBytes(EpochKeyBytes, 0x50),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if created.Reason != protocol.Reason_REASON_OK {
		t.Fatalf("CreateGroup answered %v", created.Reason)
	}
	response, err := store.Submit(ctx, &SubmitRequest{
		GroupId: groupId,
		Records: []*Record{markerRecord(creator, 1, 1, 1)},
	})
	if err != nil {
		t.Fatalf("Submit(marker): %v", err)
	}
	if response.Results[0].Reason != protocol.Reason_REASON_OK {
		t.Fatalf("the epoch-1 marker was answered %v", response.Results[0].Reason)
	}
	return store, groupId
}

// A commit accepted, and its epoch's fan-out closed, so the group is writable again at the new
// epoch. Used by the scenarios whose subject is what an epoch change does to something else.
func advanceEpoch(t *testing.T, store Store, seen *recorder, groupId []byte, committer []byte, index uint64) {
	t.Helper()
	state := stateOf(t, store, groupId)
	commit := submit(t, store, seen, groupId, commitRecord(committer, state.CurrentEpoch, index, state.CurrentEpoch+1, 0x40))
	wantReason(t, commit[0], protocol.Reason_REASON_OK)
	marker := submit(t, store, seen, groupId, markerRecord(committer, state.CurrentEpoch+1, index+1, 1))
	wantReason(t, marker[0], protocol.Reason_REASON_OK)
}

func stateOf(t *testing.T, store Store, groupId []byte) *GroupState {
	t.Helper()
	state, err := store.GroupState(context.Background(), groupId)
	if err != nil {
		t.Fatalf("GroupState: %v", err)
	}
	return state
}

func nextRecordId(t *testing.T, store Store, groupId []byte) uint64 {
	t.Helper()
	return stateOf(t, store, groupId).NextRecordId
}

func readNextRecordId(store Store, groupId []byte) (uint64, bool) {
	state, err := store.GroupState(context.Background(), groupId)
	if err != nil {
		return 0, false
	}
	return state.NextRecordId, true
}

func errorOf[T any](_ T, err error) error {
	return err
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────

func testBytes(length int, seed byte) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}

func testGroupId(seed byte) []byte {
	return testBytes(GroupIdBytes, seed)
}

func testHandle(seed byte) []byte {
	return testBytes(SenderHandleBytes, seed)
}

func ordinaryRecord(sender []byte, epoch uint64, index uint64, seed byte) *Record {
	return &Record{
		SenderHandle:   sender,
		Epoch:          epoch,
		StreamIndex:    index,
		RetentionClass: ClassDurable,
		SizeBucket:     0,
		BodyHash:       testBytes(BodyHashBytes, seed),
		CtHead:         testBytes(48, seed),
		CtBody:         testBytes(272, seed),
	}
}

func commitRecord(sender []byte, epoch uint64, index uint64, opens uint64, seed byte) *Record {
	record := ordinaryRecord(sender, epoch, index, seed)
	record.IsCommit = true
	record.RetentionClass = ClassPermanent
	record.ServerAttachment = testBytes(64, seed)
	record.Attachment = &Attachment{
		Kind: AttachmentEpoch,
		Epoch: &EpochAttachment{
			Epoch:             opens,
			WriteKey:          testBytes(EpochKeyBytes, seed),
			ReadKey:           testBytes(EpochKeyBytes, seed+1),
			AlgId:             1,
			MediaTtlSeconds:   3600,
			DurableTtlSeconds: 86400,
			ExpectedWrapCount: 1,
		},
	}
	return record
}

func wrapRecord(sender []byte, epoch uint64, index uint64, target []byte) *Record {
	record := ordinaryRecord(sender, epoch, index, 0x90)
	record.RetentionClass = ClassPermanent
	record.ServerAttachment = testBytes(64, 0x90)
	record.Attachment = &Attachment{
		Kind: AttachmentWrap,
		Wrap: &WrapTag{TargetHandle: target, LeafIndex: 0},
	}
	return record
}

func markerRecord(sender []byte, epoch uint64, index uint64, wrapCount uint32) *Record {
	record := ordinaryRecord(sender, epoch, index, 0xA0)
	record.RetentionClass = ClassPermanent
	record.ServerAttachment = testBytes(64, 0xA0)
	record.Attachment = &Attachment{
		Kind:          AttachmentEpochComplete,
		EpochComplete: &EpochCompleteTag{Epoch: epoch, WrapCount: wrapCount},
	}
	return record
}
