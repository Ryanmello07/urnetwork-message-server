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
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
func RunContract(t *testing.T, newStore func(Limits) Store) {
	t.Helper()

	// where the AST gates below read their class from: this file's directory, and the
	// directory of whoever called RunContract, so an implementation living beside its own
	// test is covered without this file knowing anything about it
	_, here, _, _ := runtime.Caller(0)
	_, caller, _, _ := runtime.Caller(1)
	directories := []string{filepath.Dir(here)}
	if directory := filepath.Dir(caller); directory != directories[0] {
		directories = append(directories, directory)
	}
	// the concrete type under test, so the refusal gate's class is the implementation's own
	// and not the directory's. Two implementations of [Store] share a package here, and the
	// memory one is documented as unable to answer §6.4's REASON_RATE_LIMITED — there is no
	// connection to hold — so a class read from the directory turns the memory run red the
	// day the pgx one lands, and the response under time pressure is to weaken the gate
	under := implementationUnderTest(t, newStore(DefaultLimits()))

	seen := &recorder{reasons: map[protocol.Reason]int{}, sentinels: map[string]int{}}
	// runs after every subtest below, parallel ones included
	t.Cleanup(func() {
		assertEveryRefusalIsExercised(t, directories, under, seen)
		assertEverySentinelIsExercised(t, directories, seen)
	})

	t.Run("TheIdempotencyProbeOfStep0", func(t *testing.T) { contractProbe(t, newStore, seen) })
	t.Run("RecordIdsAreGaplessAndOneBased", func(t *testing.T) { contractAllocation(t, newStore, seen) })
	t.Run("AStreamIndexIsMonotonicAndNotContiguous", func(t *testing.T) { contractStreamIndex(t, newStore, seen) })
	t.Run("TheEpochGateIsCommitAware", func(t *testing.T) { contractEpochGate(t, newStore, seen) })
	t.Run("AnUnavailableGroupIsOneAnswer", func(t *testing.T) { contractGroupAvailability(t, newStore, seen) })
	t.Run("TheFoundingCommitIsCheckedBeforeTheGroupExists", func(t *testing.T) { contractCreateGroup(t, newStore, seen) })
	t.Run("ACommitAttachmentIsCheckedBeforeTheCas", func(t *testing.T) { contractAttachment(t, newStore, seen) })
	t.Run("ARejectionRollsTheWholeBatchBack", func(t *testing.T) { contractBatch(t, newStore, seen) })
	t.Run("RetentionIsResolvedAtStep6", func(t *testing.T) { contractRetention(t, newStore, seen) })
	t.Run("AWonCommitMovesEpochKeyCustody", func(t *testing.T) { contractEpochKeys(t, newStore, seen) })
	t.Run("ARecoveryHandleIsTrustedOnFirstUse", func(t *testing.T) { contractRecovery(t, newStore, seen) })
	t.Run("TheMarkerIsTheOnlyThingThatOpensAnEpoch", func(t *testing.T) { contractEpochComplete(t, newStore, seen) })
	t.Run("TheReadPathAllocatesNothing", func(t *testing.T) { contractFetch(t, newStore, seen) })
	t.Run("TheClassFilterReturnsExactlyTheClassesAsked", func(t *testing.T) { contractClassMask(t, newStore, seen) })
	t.Run("RecordsAreCopiedAtTheStoreBoundary", func(t *testing.T) { contractDefensiveCopy(t, newStore, seen) })
	t.Run("APruneTimeIsComputedFromTheClassAndThePolicy", func(t *testing.T) { contractPruneAfter(t, newStore, seen) })
	t.Run("ConcurrentSubmittersAtOneStreamIndex", func(t *testing.T) { contractConcurrentStreamIndex(t, newStore, seen) })
	t.Run("ConcurrentCommittersAtOneEpoch", func(t *testing.T) { contractConcurrentCommitters(t, newStore, seen) })
	t.Run("ACommitRacingOrdinaryWritesAtTheSameEpoch", func(t *testing.T) { contractConcurrentCommitAndWrite(t, newStore, seen) })
	t.Run("AReaderConcurrentWithAWriter", func(t *testing.T) { contractConcurrentReader(t, newStore, seen) })
	t.Run("ARetryArrivingWhileTheOriginalIsInFlight", func(t *testing.T) { contractConcurrentRetry(t, newStore, seen) })
	t.Run("AnErrorIsForTheCallerAndNeverForTheClient", func(t *testing.T) { contractCallerErrors(t, newStore, seen) })
}

// A refusal is a reason on a result; an error is the API layer having handed the store
// something no client could have produced. The two are not interchangeable, and each of these
// would otherwise arrive as a REASON_REJECTED that the operator could never tell from a bad MAC.
//
// Which errors owe a scenario is not decided here. [assertEverySentinelIsExercised] derives the
// class from the sentinels declared beside the Store interface and fails naming whichever one
// this table has stopped covering — this used to be a hand-typed list of four cases with no
// derivation behind it, which is Rule 5's failure mode applied to errors instead of to refusals,
// and three of the eight sentinels had no scenario at all while a fourth was being answered for
// the wrong condition.
func contractCallerErrors(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()

	damage := map[string]struct {
		want   error
		damage func(*Record)
	}{
		// §7.6 is normative that an EPH(0) transient never touches disk: it is published and
		// dropped, so it has no row here to be stored in and no record_id to be given
		"AnEph0TransientNeverReachesTheStore": {want: ErrTransientRecord, damage: func(record *Record) {
			record.RetentionClass = ClassEphBase
		}},
		"AnIdentifierOfTheWrongLength": {want: ErrIdentifierShape, damage: func(record *Record) {
			record.SenderHandle = testBytes(SenderHandleBytes-1, 0x21)
		}},
		"ABlobIdOfTheWrongLength": {want: ErrIdentifierShape, damage: func(record *Record) {
			record.CtBody = nil
			record.BlobId = testBytes(BlobIdBytes+1, 0x33)
		}},
		// §3.2's CHECK on the class byte: between MEDIA and the base of the eph ladder there is
		// nothing, and a byte that lands there has no retention arithmetic to be given
		"ARetentionClassBetweenTheLadders": {want: ErrRetentionClass, damage: func(record *Record) {
			record.RetentionClass = ClassMedia + 1
		}},
		"ARetentionClassAboveTheEphLadder": {want: ErrRetentionClass, damage: func(record *Record) {
			record.RetentionClass = ClassEphMax + 1
		}},
		"ASizeBucketOffTheLadder": {want: ErrSizeBucket, damage: func(record *Record) {
			record.SizeBucket = 6
		}},
		// inline XOR blob (§3.2). It answered ErrSizeBucket until this scenario existed, which
		// is an operator log line sending the reader to the wrong field of the wrong record
		"ABodyThatIsInlineAndABlobAtOnce": {want: ErrInlineOrBlob, damage: func(record *Record) {
			record.BlobId = testBytes(BlobIdBytes, 0x33)
		}},
	}

	for name, current := range damage {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			record := ordinaryRecord(testHandle(0x21), 1, 0, 0x30)
			current.damage(record)
			assertTheCallersError(t, newStore, seen, []*Record{record}, current.want)
		})
	}

	t.Run("AnEmptyBatchHasNoResultToAlignWith", func(t *testing.T) {
		t.Parallel()
		assertTheCallersError(t, newStore, seen, []*Record{}, ErrEmptyBatch)
	})

	t.Run("ACommitMixedIntoABatch", func(t *testing.T) {
		t.Parallel()
		// §4.3.3: mixing a commit with ordinary records makes partial-failure semantics
		// ambiguous during an epoch change, and a commit is one record by construction
		assertTheCallersError(t, newStore, seen, []*Record{
			commitRecord(testHandle(0x31), 1, 0, 2, 0x40),
			ordinaryRecord(testHandle(0x21), 1, 0, 0x30),
		}, ErrCommitBatch)
	})

	t.Run("AnEpochWithNoRetainedKey", func(t *testing.T) {
		t.Parallel()
		// §5.1 check 6 and §5.1.1: an epoch that never existed and one whose keys have both been
		// discarded answer identically, which is §5.1.1 refusing to be an oracle for either
		store, group := openGroup(t, newStore(DefaultLimits()))
		wantError(t, seen, errorOf(store.EpochKeys(ctx, group, 9)), ErrEpochKeyUnknown)
		wantError(t, seen, errorOf(store.EpochKeys(ctx, testGroupId(0xEE), 1)), ErrEpochKeyUnknown)
	})
}

func assertTheCallersError(t *testing.T, newStore func(Limits) Store, seen *recorder, records []*Record, want error) {
	t.Helper()
	store, group := openGroup(t, newStore(DefaultLimits()))
	before := nextRecordId(t, store, group)
	response, err := store.Submit(context.Background(), &SubmitRequest{GroupId: group, Records: records})
	wantError(t, seen, err, want)
	if response != nil {
		t.Fatal("Submit answered an error and a response; a caller that reads results on an error reads results nobody wrote")
	}
	if after := nextRecordId(t, store, group); after != before {
		t.Fatalf("a refused-at-the-door submission moved next_record_id from %d to %d", before, after)
	}
}

// ── step (0) ─────────────────────────────────────────────────────────────────────────────

func contractProbe(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()

	t.Run("AbsentContinuesToTheGates", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))
		sender := testHandle(0x21)
		results := submit(t, store, seen, group, ordinaryRecord(sender, 1, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_OK)
		if results[0].RecordId == 0 {
			t.Fatal("an accepted record was given record_id 0, which Spec A §5.1 reserves as the from-the-beginning cursor")
		}
	})

	t.Run("BothHashesMatchingIsIdempotentAndAllocatesNothing", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))
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
		store, group := openGroup(t, newStore(DefaultLimits()))
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
		store, group := openGroup(t, newStore(DefaultLimits()))
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
		store, group := openGroup(t, newStore(DefaultLimits()))
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
		store, group := openGroup(t, newStore(DefaultLimits()))
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
		store, group := openGroup(t, newStore(DefaultLimits()))
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

func contractAllocation(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	store := newStore(DefaultLimits())
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
	if !accepted(created.Reason) {
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

	// gapless, 1-based, and 0 never assigned — read back through the from-the-beginning cursor.
	//
	// FOR THE SECOND IMPLEMENTATION: this reads contiguity out of Fetch, which is only the same
	// property while no row has been pruned. §7.2 replaces an expired ephemeral row with a
	// placeholder rather than deleting it, exactly so that this stays true — a store that
	// deleted the row instead would leave a hole here, and §12.2 C-4 tells clients to treat a
	// hole as the server withholding. No scenario in this file ages a record out, so the day
	// one does, this assertion is the one that states what §7.2 owes.
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

func contractStreamIndex(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()

	t.Run("AGapIsAccepted", func(t *testing.T) {
		t.Parallel()
		// a refused write, a crash between reserve and send, or a lost commit leaves a legal
		// gap, and §6.1 enforces monotonicity and not contiguity for exactly those three
		store, group := openGroup(t, newStore(DefaultLimits()))
		sender := testHandle(0x21)
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, 0, 0x30))[0], protocol.Reason_REASON_OK)
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, 1000, 0x31))[0], protocol.Reason_REASON_OK)
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, 1001, 0x32))[0], protocol.Reason_REASON_OK)
	})

	t.Run("ARegressionIsRefused", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))
		sender := testHandle(0x21)
		submit(t, store, seen, group, ordinaryRecord(sender, 1, 10, 0x30))
		results := submit(t, store, seen, group, ordinaryRecord(sender, 1, 7, 0x31))
		wantReason(t, results[0], protocol.Reason_REASON_STREAM_INDEX_REGRESSED)
	})

	t.Run("TheSameIndexIsRefusedNotRegressed", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))
		sender := testHandle(0x21)
		submit(t, store, seen, group, ordinaryRecord(sender, 1, 10, 0x30))
		results := submit(t, store, seen, group, ordinaryRecord(sender, 1, 10, 0x31))
		wantReason(t, results[0], protocol.Reason_REASON_STREAM_INDEX_REUSED)
	})

	t.Run("TheIndexIsScopedToOneSender", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))
		submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 40, 0x30))
		results := submit(t, store, seen, group, ordinaryRecord(testHandle(0x22), 1, 0, 0x31))
		wantReason(t, results[0], protocol.Reason_REASON_OK)
	})

	// Monotonicity WITHIN one batch, which had no scenario at all. §6.1 step (3) runs the gate
	// for every record before a single id is allocated, so the high-water it compares against
	// has to include the records earlier in this same batch — the sender row has not been
	// written yet and will not be until step (7).
	//
	// The batch below is chosen so it can only be answered by the per-batch high-water: every
	// index in it is above the sender's stored high-water of 5, so a store comparing against the
	// row alone accepts both records, gives them both ids, and leaves one permanent record_id
	// that the single stream claim does not name. §6.1 step (5a)'s `ON CONFLICT DO NOTHING` has
	// no documented answer for its own 0-row case, and this is the shape of it.
	intraBatch := map[string][]uint64{
		"TwoRecordsAtOneIndexInOneBatch":                  {6, 6},
		"ARegressionAgainstAnEarlierRecordOfTheSameBatch": {6, 7, 6},
	}
	for name, indexes := range intraBatch {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, group := openGroup(t, newStore(DefaultLimits()))
			sender := testHandle(0x21)
			wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, 5, 0x30))[0], protocol.Reason_REASON_OK)

			batch := []*Record{}
			for offset, index := range indexes {
				batch = append(batch, ordinaryRecord(sender, 1, index, byte(0x40+offset)))
			}
			results := submit(t, store, seen, group, batch...)
			for offset, result := range results {
				if accepted(result.Reason) {
					t.Fatalf("record %d of a batch that regresses against itself was accepted; two records of one sender at the same stream_index both got a record id and only one of them is named by a claim", offset)
				}
			}
			wantReason(t, results[len(results)-1], protocol.Reason_REASON_STREAM_INDEX_REGRESSED)

			// and the indexes the batch touched are still free, because it wrote nothing
			for _, index := range indexes[:len(indexes)-1] {
				wantReason(t, submit(t, store, seen, group, ordinaryRecord(sender, 1, index, byte(0x50+index)))[0], protocol.Reason_REASON_OK)
			}
		})
	}
}

// ── step (2) ─────────────────────────────────────────────────────────────────────────────

func contractEpochGate(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()

	t.Run("ALosingCommitterIsToldItLostAndNotThatItIsStale", func(t *testing.T) {
		t.Parallel()
		// the row lock serialises committers, so a loser acquires it only AFTER the winner
		// advanced the epoch. An epoch-first gate therefore answers EPOCH_STALE to every loser
		// and §6.2's mandatory loser protocol — the one carrying the hard MUST NOT on
		// pq_secret reuse — never fires at all
		store, group := openGroup(t, newStore(DefaultLimits()))
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
		store, group := openGroup(t, newStore(DefaultLimits()))
		advanceEpoch(t, store, seen, group, testHandle(0x31), 0)
		results := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_EPOCH_STALE)
		if results[0].CurrentEpoch != 2 {
			t.Fatalf("EPOCH_STALE carried current_epoch %d, want 2", results[0].CurrentEpoch)
		}
	})

	t.Run("TheGroupIsReadableButNotWritableUntilTheMarkerLands", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))
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

func contractGroupAvailability(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()

	t.Run("AnUnknownGroupIsRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore(DefaultLimits())
		unknown := testGroupId(0xEE)
		results := submit(t, store, seen, unknown, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_REJECTED)

		wantError(t, seen, errorOf(store.GroupState(ctx, unknown)), ErrGroupUnavailable)
	})

	t.Run("AClosedGroupIsTheSameAnswerAsAnUnknownOne", func(t *testing.T) {
		t.Parallel()
		// §4.5: distinguishing them would turn the submit path into an oracle for group
		// existence to a party holding no write_key
		store, group := openGroup(t, newStore(DefaultLimits()))
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
		wantError(t, seen, errorOf(store.Fetch(ctx, &FetchRequest{GroupId: group})), ErrGroupUnavailable)
		// §7.5: a group closed twice is a group that is already unavailable, which is the same
		// answer an unknown one gives to everything else
		wantError(t, seen, store.CloseGroup(ctx, group), ErrGroupUnavailable)
	})

	t.Run("ASecondCreateOfTheSameIdIsRejected", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))
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

func contractAttachment(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()

	for name, damage := range malformedEpochAttachments {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, group := openGroup(t, newStore(DefaultLimits()))
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
		store, group := openGroup(t, newStore(DefaultLimits()))
		record := ordinaryRecord(testHandle(0x31), 1, 0, 0x30)
		record.IsCommit = true
		results := submit(t, store, seen, group, record)
		wantReason(t, results[0], protocol.Reason_REASON_REJECTED)
	})

	t.Run("AnOrdinaryRecordWithAnEpochAttachmentIsRejected", func(t *testing.T) {
		t.Parallel()
		// EpochAttachment iff is_commit (§5.1 check 3). Without the iff, a member could set
		// the next epoch's write key without ever winning a CAS
		store, group := openGroup(t, newStore(DefaultLimits()))
		record := commitRecord(testHandle(0x31), 1, 0, 2, 0x40)
		record.IsCommit = false
		results := submit(t, store, seen, group, record)
		wantReason(t, results[0], protocol.Reason_REASON_REJECTED)
	})
}

// ── step (3b) ────────────────────────────────────────────────────────────────────────────

func contractBatch(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	store, group := openGroup(t, newStore(DefaultLimits()))
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

func contractRetention(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()

	// §7.3's three cases are three different sentences to the user, and a client that could only
	// see the number would have to pick one of them and would be wrong twice.
	//
	// All three are reachable only because RunContract takes the limits. On DefaultLimits both
	// durable bounds are 0 and the media cap is far above anything a fixture asks for, so the
	// floor, the cap, every flag they set and REASON_RETENTION_CLAMPED itself were arithmetic no
	// scenario could reach: both bounds could be deleted outright and the suite stayed green.
	cases := []struct {
		name     string
		limits   Limits
		media    uint32
		durable  uint32
		reason   protocol.Reason
		expected func(*testing.T, *RetentionApplied, *GroupState)
	}{
		{
			name:    "TheUnsetSentinelIsDefaultedAndNotClamped",
			limits:  DefaultLimits(),
			media:   3600,
			durable: DurableUnset,
			reason:  protocol.Reason_REASON_OK,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if !applied.DurableDefaulted {
					t.Error("durable_defaulted is false for a group that sent the unset sentinel; it asked for nothing, so nothing was refused")
				}
				if applied.clamped() {
					t.Error("a defaulted policy was reported as clamped")
				}
				wantDurable(t, applied, state, 31536000)
			},
		},
		{
			name:    "AnExplicitPolicyIsNeitherDefaultedNorClamped",
			limits:  DefaultLimits(),
			media:   3600,
			durable: 1000,
			reason:  protocol.Reason_REASON_OK,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if applied.DurableDefaulted {
					t.Error("durable_defaulted is true for a group that named a value")
				}
				wantDurable(t, applied, state, 1000)
			},
		},
		{
			name:    "TheIndefiniteSentinelSurvivesOnAServerWithNoTextCap",
			limits:  DefaultLimits(),
			media:   3600,
			durable: DurableIndefinite,
			reason:  protocol.Reason_REASON_OK,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if applied.DurableTtlSeconds != DurableIndefinite {
					t.Errorf("indefinite was stored as %d on a server advertising no text cap", applied.DurableTtlSeconds)
				}
				if applied.DurableClampedDown {
					t.Error("indefinite was reported as clamped by a server that advertises no cap to clamp to")
				}
				if state.DurableTtlSeconds != nil {
					t.Errorf("the group row holds a text ttl of %d, and §3.2 writes indefinite as NULL", *state.DurableTtlSeconds)
				}
			},
		},
		{
			// §7.3 case 1, which is the only one of the three that touches media at all
			name:    "AMediaPolicyAboveTheCapIsClampedDownAndAccepted",
			limits:  Limits{MediaTtlMaxSeconds: 3600, MediaTtlDefaultSeconds: 3600, DurableTtlDefaultSeconds: 31536000},
			media:   86400,
			durable: 1000,
			reason:  protocol.Reason_REASON_RETENTION_CLAMPED,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if !applied.MediaClampedDown {
					t.Error("a media policy above the advertised cap was not reported as clamped, so the client renders the requested value and tells the user something untrue")
				}
				if applied.RequestedMediaTtlSeconds != 86400 {
					t.Errorf("RetentionApplied reported the media request as %d, want 86400", applied.RequestedMediaTtlSeconds)
				}
				wantMedia(t, applied, state, 3600)
			},
		},
		{
			// the other side of the same branch: a policy inside the cap is stored AS ASKED, and
			// without this the whole media branch can be replaced by the server's own default
			name:    "AMediaPolicyInsideTheCapIsStoredAsAsked",
			limits:  Limits{MediaTtlMaxSeconds: 86400, MediaTtlDefaultSeconds: 2592000, DurableTtlDefaultSeconds: 31536000},
			media:   3600,
			durable: 1000,
			reason:  protocol.Reason_REASON_OK,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if applied.MediaClampedDown {
					t.Error("a media policy inside the advertised cap was reported as clamped")
				}
				wantMedia(t, applied, state, 3600)
			},
		},
		{
			name:    "AMediaPolicyOfZeroTakesThisServersOwnDefault",
			limits:  Limits{MediaTtlDefaultSeconds: 777, DurableTtlDefaultSeconds: 4242},
			media:   0,
			durable: DurableUnset,
			reason:  protocol.Reason_REASON_OK,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if applied.MediaClampedDown {
					t.Error("a media policy that asked for nothing was reported as clamped")
				}
				wantMedia(t, applied, state, 777)
				wantDurable(t, applied, state, 4242)
			},
		},
		{
			// §7.3 case 2, the only direction that floors UP
			name:    "ATextPolicyBelowTheFloorIsFlooredUp",
			limits:  Limits{MediaTtlMaxSeconds: 2592000, MediaTtlDefaultSeconds: 2592000, DurableTtlDefaultSeconds: 31536000, DurableRetentionMinSeconds: 100000},
			media:   3600,
			durable: 1000,
			reason:  protocol.Reason_REASON_RETENTION_CLAMPED,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if !applied.DurableFlooredUp {
					t.Error("a text policy shorter than the advertised minimum was not reported as floored up; §7.3 warns and proceeds in this direction too, and the user is told a retention they did not ask for")
				}
				if applied.DurableClampedDown {
					t.Error("a floored policy was also reported as clamped down")
				}
				wantDurable(t, applied, state, 100000)
			},
		},
		{
			// §7.3 case 3
			name:    "ATextPolicyAboveTheCapIsClampedDown",
			limits:  Limits{MediaTtlMaxSeconds: 2592000, MediaTtlDefaultSeconds: 2592000, DurableTtlMaxSeconds: 1000, DurableTtlDefaultSeconds: 31536000},
			media:   3600,
			durable: 86400,
			reason:  protocol.Reason_REASON_RETENTION_CLAMPED,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if !applied.DurableClampedDown {
					t.Error("a text policy above the advertised cap was not reported as clamped")
				}
				wantDurable(t, applied, state, 1000)
			},
		},
		{
			// §7.3 case 3's second half: a server that advertises a cap and silently honoured
			// "keep forever" would be lying in its own capability document
			name:    "TheIndefiniteSentinelIsClampedOnAServerThatAdvertisesACap",
			limits:  Limits{MediaTtlMaxSeconds: 2592000, MediaTtlDefaultSeconds: 2592000, DurableTtlMaxSeconds: 1000, DurableTtlDefaultSeconds: 31536000},
			media:   3600,
			durable: DurableIndefinite,
			reason:  protocol.Reason_REASON_RETENTION_CLAMPED,
			expected: func(t *testing.T, applied *RetentionApplied, state *GroupState) {
				if !applied.DurableClampedDown {
					t.Error("the explicit-indefinite sentinel was honoured whole by a server advertising a text cap")
				}
				wantDurable(t, applied, state, 1000)
			},
		},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			t.Parallel()
			store, group := openGroup(t, newStore(current.limits))
			record := commitRecord(testHandle(0x31), 1, 0, 2, 0x40)
			record.Attachment.Epoch.MediaTtlSeconds = current.media
			record.Attachment.Epoch.DurableTtlSeconds = current.durable

			before := stateOf(t, store, group)
			results := submit(t, store, seen, group, record)
			wantReason(t, results[0], current.reason)
			if results[0].RecordId == 0 {
				t.Fatal("a clamped commit was not given a record id; §7.3 accepts the commit in all three cases, because an operator config change would otherwise stop a group committing at all")
			}
			if results[0].Applied == nil {
				t.Fatal("an accepted commit carried no RetentionApplied, so the client cannot name the effective value")
			}
			if results[0].Applied.RequestedDurableTtlSeconds != current.durable {
				t.Fatalf("RetentionApplied reported the text request as %d, want %d", results[0].Applied.RequestedDurableTtlSeconds, current.durable)
			}

			after := stateOf(t, store, group)
			current.expected(t, results[0].Applied, after)

			// §6.1 step (6) advances policy_version on every accepted commit, and the client
			// uses it to notice that the policy under it changed. Asserting it is non-zero
			// observes nothing: CreateGroup sets it to 1 before this commit runs
			if after.PolicyVersion != before.PolicyVersion+1 {
				t.Fatalf("an accepted commit moved policy_version from %d to %d, want exactly one advance", before.PolicyVersion, after.PolicyVersion)
			}
			if after.CurrentEpoch != before.CurrentEpoch+1 {
				t.Fatalf("an accepted commit moved current_epoch from %d to %d", before.CurrentEpoch, after.CurrentEpoch)
			}
		})
	}

	// §7.3 has no carve-out for the founding commit, and it is the commit whose policy the group
	// lives under until it commits again — so a store that clamped it silently would leave the
	// creator's client rendering a retention notice for a policy the group never had
	t.Run("TheFoundingCommitIsClampedTheSameWayAsAnyOther", func(t *testing.T) {
		t.Parallel()
		limits := Limits{MediaTtlMaxSeconds: 1800, MediaTtlDefaultSeconds: 1800, DurableTtlMaxSeconds: 1000, DurableTtlDefaultSeconds: 31536000}
		store := newStore(limits)
		groupId := testGroupId(0x11)
		created, err := store.CreateGroup(context.Background(), &CreateGroupRequest{
			GroupId:           groupId,
			InitialCommit:     commitRecord(testHandle(0x20), 0, 0, 1, 0x40),
			BootstrapWriteKey: testBytes(EpochKeyBytes, 0x50),
		})
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		seen.observe(created.Reason)
		if created.Reason != protocol.Reason_REASON_RETENTION_CLAMPED {
			t.Fatalf("CreateGroup answered %v for a founding commit whose media and text policies were both clamped down", created.Reason)
		}
		if created.Applied == nil {
			t.Fatal("a clamped CreateGroup carried no RetentionApplied, so the creator cannot name the effective value")
		}
		state := stateOf(t, store, groupId)
		wantMedia(t, created.Applied, state, 1800)
		wantDurable(t, created.Applied, state, 1000)
	})
}

// What the commit was told it got, and what the group row actually holds, are the same number.
// The pair is the point: a store that reported the effective value and stored something else
// would satisfy either assertion alone.
func wantMedia(t *testing.T, applied *RetentionApplied, state *GroupState, want uint32) {
	t.Helper()
	if applied.MediaTtlSeconds != want {
		t.Errorf("RetentionApplied names a media ttl of %d, want %d", applied.MediaTtlSeconds, want)
	}
	if state.MediaTtlSeconds != want {
		t.Errorf("the group row holds a media ttl of %d, want %d", state.MediaTtlSeconds, want)
	}
}

func wantDurable(t *testing.T, applied *RetentionApplied, state *GroupState, want uint32) {
	t.Helper()
	if applied.DurableTtlSeconds != want {
		t.Errorf("RetentionApplied names a text ttl of %d, want %d", applied.DurableTtlSeconds, want)
	}
	if state.DurableTtlSeconds == nil {
		t.Errorf("the group row holds an indefinite text ttl, want %d", want)
		return
	}
	if *state.DurableTtlSeconds != want {
		t.Errorf("the group row holds a text ttl of %d, want %d", *state.DurableTtlSeconds, want)
	}
}

// ── §5.3 ─────────────────────────────────────────────────────────────────────────────────

func contractEpochKeys(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))

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

	// the briefly-retired predecessor: still verifiable, and marked for the tidy loop.
	//
	// FOR THE SECOND IMPLEMENTATION: what is asserted below is that the retire_time is stamped
	// inside the commit, NOT that the key is gone. §5.3's 60-second tidy is a loop and §7.4 puts
	// it behind an advisory lock, so a store that takes the key later is still correct — the
	// contract holds it only to leaving the loop something to act on. The `epoch < current_epoch`
	// half further down is different: that one IS synchronous, because it is the predicate that
	// decides whether the one predecessor §5.3 keeps survives the transaction at all.
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

	// an epoch this group has never opened is the same answer as one whose keys are gone, which
	// is §5.1.1 refusing to be an oracle for either
	wantError(t, seen, errorOf(store.EpochKeys(ctx, group, 99)), ErrEpochKeyUnknown)
}

// ── §5.1.1 ───────────────────────────────────────────────────────────────────────────────

func contractFetch(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))
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

	// FOR THE SECOND IMPLEMENTATION: `since_record_id` is EXCLUSIVE and `next_record_id` on a
	// page is the id of its last record, so a client resumes by handing the previous page's
	// cursor straight back. §4.3.4 declares the cursor exclusive and never says which id the
	// response carries; this is the half it left open, and the resume below is what pins it.
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

	// the class filter has its own scenario: what a mask returns is a statement about WHICH
	// records came back, and "everything that came back is PERMANENT" is satisfied by an empty
	// answer, which is what an off-by-one in the mask produces for every class
}

// ── the racy half of §6.1 ────────────────────────────────────────────────────────────────

func contractConcurrentStreamIndex(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	// real contention on one (group, sender, stream_index), and the assertion is the invariant
	// rather than a winner: exactly one submission is accepted, every other is refused with a
	// documented stream-index refusal, and the group allocated exactly one id.
	//
	// It is run in rounds because one round is not an experiment. §6.1 step (1)'s row lock could
	// be deleted outright and a single round of eight caught it about one run in seven — green
	// ten times out of ten in the configuration CI runs, which is a test that reports the clean
	// run of a complete test having contended with nothing.
	const rounds = 24
	const submitters = 8
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))
	sender := testHandle(0x21)

	for round := range rounds {
		before := nextRecordId(t, store, group)
		index := uint64(100 + round)
		results := race(submitters, func(attempt int) *SubmitResult {
			record := ordinaryRecord(sender, 1, index, byte(0x70+attempt))
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
				// FOR THE SECOND IMPLEMENTATION: this arm DECIDES something §6.1 leaves open,
				// and it is written down here because a constraint a second implementation
				// learns from a red test is a constraint it learns too late. Step (5a)'s claim
				// insert is `ON CONFLICT (group_id, sender_handle, stream_index) DO NOTHING`
				// and the spec gives no answer for its 0-row case. A pgx store that surfaced
				// that case as REASON_REJECTED would fail here, and §6.1 does not say it is
				// wrong to — but the client cannot act on REASON_REJECTED, which §4.5 makes
				// deliberately non-specific, and both of the codes above tell it exactly what
				// happened. The 0-row case IS a reused index, so it is answered as one
				t.Errorf("a loser at a contended stream_index was refused with %v, which is not one of the refusals §6.1 documents for it", result.Reason)
			}
		}
		if accepted != 1 {
			t.Fatalf("round %d: %d of %d submissions at one stream_index were accepted, want exactly 1", round, accepted, submitters)
		}
		if after := nextRecordId(t, store, group); after != before+1 {
			t.Fatalf("round %d: %d submitters at one stream_index moved next_record_id by %d, want 1", round, submitters, after-before)
		}
	}
}

// §6.1 step (1)'s row lock, from the side that shows when it is missing.
//
// A committer and a crowd of ordinary writers at the same epoch. The lock serialises them
// against each other, and the consequence is sharp: the moment the commit lands, the epoch has
// moved and the new epoch's wrap fan-out has not closed, so an ordinary record has nowhere left
// to go — at the old epoch it is EPOCH_STALE and at the new one it is EPOCH_INCOMPLETE. The
// commit's own record id is therefore the LAST id the group hands out in that round.
//
// Without the lock, a writer that read the group's state before the commit still writes after
// it: the group ends up with an epoch-1 ordinary record sitting above the commit that closed
// epoch 1, which is a record no member of the new epoch has a key for and which the ordering
// argument of §6.1 says cannot exist.
func contractConcurrentCommitAndWrite(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	const rounds = 12
	const writers = 8
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))
	committer := testHandle(0x31)
	marker := testHandle(0x32)

	for round := range rounds {
		epoch := stateOf(t, store, group).CurrentEpoch
		index := uint64(round)
		results := race(writers+1, func(attempt int) *SubmitResult {
			record := ordinaryRecord(testHandle(byte(0x50+attempt)), epoch, index, byte(0x60+attempt))
			if attempt == 0 {
				record = commitRecord(committer, epoch, index, epoch+1, 0x40)
			}
			response, err := store.Submit(ctx, &SubmitRequest{GroupId: group, Records: []*Record{record}})
			if err != nil {
				t.Errorf("Submit: %v", err)
				return nil
			}
			return response.Results[0]
		})
		for _, result := range results {
			if result != nil {
				seen.observe(result.Reason)
			}
		}
		if results[0] == nil || !accepted(results[0].Reason) {
			t.Fatalf("round %d: the only committer was answered %v", round, results[0])
		}
		won := results[0].RecordId

		records := allRecords(t, store, group)
		highest := records[len(records)-1]
		if highest.RecordId != won {
			t.Fatalf("round %d: the commit that closed epoch %d has record id %d and the group's highest is %d, an %s record at epoch %d. §6.1 step (1)'s row lock is what stops a writer that read the group's state before the commit from writing after it, and a record above the commit that closed its epoch is one no member of the new epoch holds a key for",
				round, epoch, won, highest.RecordId, describeRecord(highest), highest.Epoch)
		}
		if after := stateOf(t, store, group); after.CurrentEpoch != epoch+1 {
			t.Fatalf("round %d: one accepted commit moved current_epoch from %d to %d", round, epoch, after.CurrentEpoch)
		}

		// reopen the new epoch for the next round
		wantReason(t, submit(t, store, seen, group, markerRecord(marker, epoch+1, index, 1))[0], protocol.Reason_REASON_OK)
	}
}

// The claim doc.go and memory.go both rest on, and which nothing tested: a concurrent reader
// sees a whole transaction or none of it. That is what makes the memory implementation a model
// of READ COMMITTED rather than a map, and every scenario above reads strictly before or
// strictly after a write — so a store that applied its claim row and its record row in two
// visible steps passed all of them.
//
// The assertion is inside ONE Fetch, so it is a statement about a single snapshot rather than
// about two calls that could straddle a commit. A complete page from the beginning holds every
// record id up to its own high water, contiguously. A reader that catches a transaction
// half-applied sees the id the group's row has already advanced to and a record row that is not
// there yet, which is exactly the withholding hole §12.2 C-4 tells clients to treat as a fault.
func contractConcurrentReader(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	const writers = 4
	const each = 40
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))

	writing := sync.WaitGroup{}
	done := make(chan struct{})
	start := make(chan struct{})
	for writer := range writers {
		writing.Add(1)
		go func() {
			defer writing.Done()
			sender := testHandle(byte(0x50 + writer))
			<-start
			for index := range uint64(each) {
				response, err := store.Submit(ctx, &SubmitRequest{
					GroupId: group,
					Records: []*Record{ordinaryRecord(sender, 1, index, byte(0x60+index))},
				})
				if err != nil {
					t.Errorf("Submit: %v", err)
					return
				}
				seen.observe(response.Results[0].Reason)
			}
		}()
	}
	go func() { writing.Wait(); close(done) }()
	close(start)

	// a failure is carried out of the loop rather than raised inside it: the writers are still
	// running, and a t.Fatal here would end the test underneath them and turn a clean assertion
	// failure into a log-after-test panic that says nothing about what was observed
	reads, torn := 0, ""
	for reading := true; reading && torn == ""; {
		select {
		case <-done:
			reading = false
		default:
		}
		page, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0})
		if err != nil {
			torn = fmt.Sprintf("Fetch: %v", err)
			break
		}
		reads++
		switch {
		case !page.Complete:
			torn = "an unlimited fetch answered complete=false"
		case !contiguousFromOne(page.Records):
			torn = fmt.Sprintf("one fetch returned record ids %v, which has a hole in it", recordIdsOf(page.Records))
		case uint64(len(page.Records)) != page.HighWaterRecordId:
			torn = fmt.Sprintf("one fetch answered %d records and a high water of %d; a reader caught a transaction half-applied — the group's row had already advanced past a record row that was not there yet — and §12.2 C-4 tells a client to treat that as the server withholding",
				len(page.Records), page.HighWaterRecordId)
		}
	}
	<-done
	if torn != "" {
		t.Fatal(torn)
	}
	if reads < 2 {
		t.Fatalf("the reader got %d fetches in while %d writers wrote %d records each, so it observed nothing concurrent", reads, writers, each)
	}
	t.Logf("%d concurrent reads against %d writers", reads, writers)
}

func contiguousFromOne(records []*Record) bool {
	for index, record := range records {
		if record.RecordId != uint64(index)+1 {
			return false
		}
	}
	return true
}

func describeRecord(record *Record) string {
	switch {
	case record.IsCommit:
		return "a commit"
	case record.Attachment == nil || record.Attachment.Kind == AttachmentNone:
		return "an ordinary"
	default:
		return "an attachment-carrying"
	}
}

func contractConcurrentCommitters(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	const committers = 8
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))

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

func contractConcurrentRetry(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	// the same submission, byte for byte, from several connections at once: a client that
	// timed out and retried while the original was still in flight. Whether a given retry sees
	// the claim or the sender high-water depends on where the original had got to, so the
	// property is not which answer it gets — it is that one row landed, that every acceptance
	// names that same row, and that no refusal is anything but a documented stream-index one.
	const attempts = 8
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))
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

// ── §4.3.2, the founding commit ──────────────────────────────────────────────────────────

// CreateGroup's own validation of the founding commit, which had no scenario at all: every
// check on it could be deleted and the suite stayed green, and the code path that then took a
// nil attachment one line later panicked.
//
// It is checked here rather than left to the submit path because memory.go's own comment on
// this branch says why: an accepted commit with a malformed attachment opens an epoch with no
// verifiable write key and bricks the group permanently, and this is the ONE commit no later
// commit can rescue — there is no epoch to commit from and no member who can submit.
func contractCreateGroup(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()

	// the record-shaped damage, and then §5.1 check 3's attachment damage from the same table
	// the submit path is held to, so neither path can be repaired without the other
	damaged := map[string]func(*Record){
		"ARecordThatIsNotACommit": func(record *Record) {
			record.IsCommit = false
		},
		"ACommitThatDoesNotSitAtEpoch0": func(record *Record) {
			// §5.1's carve-out evaluates `epoch == current_epoch + 1` as `epoch == 1` because
			// there is no group row yet; the commit itself sits at 0 and nowhere else
			record.Epoch = 1
		},
		"ACommitCarryingNoAttachmentAtAll": func(record *Record) {
			record.Attachment = nil
			record.ServerAttachment = nil
		},
		"ACommitCarryingAWrapInsteadOfAnEpoch": func(record *Record) {
			record.Attachment = &Attachment{
				Kind: AttachmentWrap,
				Wrap: &WrapTag{TargetHandle: testHandle(0x21), LeafIndex: 0},
			}
		},
	}
	for name, damage := range malformedEpochAttachments {
		damage := damage
		damaged[name] = func(record *Record) { damage(record.Attachment.Epoch) }
	}

	for name, damage := range damaged {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newStore(DefaultLimits())
			groupId := testGroupId(0x11)
			founding := commitRecord(testHandle(0x20), 0, 0, 1, 0x40)
			damage(founding)

			created, err := store.CreateGroup(ctx, &CreateGroupRequest{
				GroupId:           groupId,
				InitialCommit:     founding,
				BootstrapWriteKey: testBytes(EpochKeyBytes, 0x50),
			})
			if err != nil {
				t.Fatalf("CreateGroup answered the error %v; a founding commit a client could have built is refused with a reason, not with an error", err)
			}
			seen.observe(created.Reason)
			if created.Reason != protocol.Reason_REASON_REJECTED {
				t.Fatalf("CreateGroup answered %v to a malformed founding commit, want REASON_REJECTED; this is the one commit no later commit can rescue", created.Reason)
			}
			if created.RecordId != 0 {
				t.Fatalf("a refused CreateGroup handed out record_id %d", created.RecordId)
			}

			// and the group does not exist, so the id is still free for the retry §4.3.2 tells
			// the creator to make
			wantError(t, seen, errorOf(store.GroupState(ctx, groupId)), ErrGroupUnavailable)
			createGroup(t, store, groupId, testHandle(0x20))
		})
	}

	t.Run("ACreateWithNoInitialCommitIsTheCallersError", func(t *testing.T) {
		t.Parallel()
		store := newStore(DefaultLimits())
		created, err := store.CreateGroup(ctx, &CreateGroupRequest{
			GroupId:           testGroupId(0x11),
			BootstrapWriteKey: testBytes(EpochKeyBytes, 0x50),
		})
		wantError(t, seen, err, ErrEmptyBatch)
		if created != nil {
			t.Fatal("CreateGroup answered an error and a result; a caller that reads a reason on an error reads a reason nobody wrote")
		}
	})
}

// ── §6.1 step (6c), the recovery handle ──────────────────────────────────────────────────

// The trust-on-first-use gate of §5.4 and §4.3.7, which had no scenario at all: no test ever
// submitted a recovery record, so the check that stops an attacker rebinding somebody else's
// recovery handle to their own verify_pub could be deleted in silence.
//
// The two halves are asserted through the same pair. The gate is what refuses a differing pub;
// the write in step (6c) is what there is for the gate to compare against, and a store that
// only gated would accept the second pub because it never kept the first.
func contractRecovery(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	store, group := openGroup(t, newStore(DefaultLimits()))
	owner := testHandle(0x21)
	attacker := testHandle(0x22)
	handle := testBytes(RecoveryHandleBytes, 0x60)
	pub := testBytes(VerifyPubBytes, 0x70)
	other := testBytes(VerifyPubBytes, 0x80)

	first := submit(t, store, seen, group, recoveryRecord(owner, 1, 0, handle, pub))
	wantReason(t, first[0], protocol.Reason_REASON_OK)

	// the same handle under the same key is the owner writing its archive again
	again := submit(t, store, seen, group, recoveryRecord(owner, 1, 1, handle, pub))
	wantReason(t, again[0], protocol.Reason_REASON_OK)

	// and §4.3.7's attack: a differing verify_pub for a handle this group already knows. A
	// seed-only restore proves possession against the pub the server pinned, so rebinding the
	// handle would hand the restore to whoever rebound it
	rebind := submit(t, store, seen, group, recoveryRecord(attacker, 1, 0, handle, other))
	wantReason(t, rebind[0], protocol.Reason_REASON_REJECTED)

	// a handle nobody has claimed is not refused, so the gate is a gate and not a wall
	fresh := submit(t, store, seen, group, recoveryRecord(attacker, 1, 1, testBytes(RecoveryHandleBytes, 0x90), other))
	wantReason(t, fresh[0], protocol.Reason_REASON_OK)

	// §3.2 scopes the recovery row to one group, so the same handle in another group is another
	// row and takes its own first pub. A store that pinned handles globally would let one
	// group's archive decide another group's
	elsewhere := createGroup(t, store, testGroupId(0x12), testHandle(0x23))
	wantReason(t, submit(t, store, seen, elsewhere, markerRecord(testHandle(0x23), 1, 1, 1))[0], protocol.Reason_REASON_OK)
	wantReason(t, submit(t, store, seen, elsewhere, recoveryRecord(owner, 1, 0, handle, other))[0], protocol.Reason_REASON_OK)
}

// ── §6.1 step (2) and step (6b), the epoch-complete marker ───────────────────────────────

func contractEpochComplete(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()

	t.Run("ANewGroupIsReadableButNotWritableUntilItsFirstMarker", func(t *testing.T) {
		t.Parallel()
		// only the post-commit window was covered, and CreateGroup could set epoch_complete on
		// the group it was creating without a single test noticing. §3.2's DEFAULT and §4.3.2's
		// prose disagree about which side of this a new group starts on; this is the side the
		// implementation chose, held down so the choice cannot drift silently
		store := newStore(DefaultLimits())
		group := createGroup(t, store, testGroupId(0x11), testHandle(0x20))

		if stateOf(t, store, group).EpochComplete {
			t.Fatal("a group was open for ordinary writes the moment it was created, before its epoch-1 wrap fan-out had landed a single wrap; a member with no wrap cannot read what is written into that window")
		}
		if len(allRecords(t, store, group)) != 1 {
			t.Fatal("a new group did not read back its own founding commit; readable-but-not-writable is readable")
		}
		blocked := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
		wantReason(t, blocked[0], protocol.Reason_REASON_EPOCH_INCOMPLETE)

		wantReason(t, submit(t, store, seen, group, markerRecord(testHandle(0x20), 1, 1, 1))[0], protocol.Reason_REASON_OK)
		if !stateOf(t, store, group).EpochComplete {
			t.Fatal("the epoch-1 marker landed and the group is still not open")
		}
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))[0], protocol.Reason_REASON_OK)
	})

	mismatched := map[string]struct {
		epoch     uint64
		wrapCount uint32
	}{
		// §6.1 step (6b)'s only condition, in both of its halves. Neither had a scenario, so the
		// whole condition could be replaced by an unconditional open
		"AMarkerNamingAnotherEpoch":   {epoch: 7, wrapCount: 1},
		"AMarkerNamingAnotherWrapSet": {epoch: 1, wrapCount: 2},
	}
	for name, current := range mismatched {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newStore(DefaultLimits())
			group := createGroup(t, store, testGroupId(0x11), testHandle(0x20))

			// the record is accepted — §5.1 check 3 refuses a mismatch upstream and this
			// package is not a second copy of that check — but it opens nothing, because a
			// group opened on a wrap count nobody agreed is a group whose members cannot all
			// read it
			marker := markerRecord(testHandle(0x20), 1, 1, current.wrapCount)
			marker.Attachment.EpochComplete.Epoch = current.epoch
			wantReason(t, submit(t, store, seen, group, marker)[0], protocol.Reason_REASON_OK)

			if stateOf(t, store, group).EpochComplete {
				t.Fatalf("a marker naming epoch %d and wrap_count %d opened a group at epoch 1 expecting 1 wrap", current.epoch, current.wrapCount)
			}
			blocked := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
			wantReason(t, blocked[0], protocol.Reason_REASON_EPOCH_INCOMPLETE)

			// and the right marker still works afterwards, so the group is not bricked either
			wantReason(t, submit(t, store, seen, group, markerRecord(testHandle(0x20), 1, 2, 1))[0], protocol.Reason_REASON_OK)
			wantReason(t, submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))[0], protocol.Reason_REASON_OK)
		})
	}

	t.Run("OnlyTheExemptKindsPassTheGateWhileTheFanOutIsOpen", func(t *testing.T) {
		t.Parallel()
		// §6.1 step (2)'s exemption is a hand-written switch, and a hand-written switch with one
		// positive test per member and no test of its complement can be widened by one line —
		// adding AttachmentEpoch lets a commit through the gate and nothing says so. There is no
		// AST to derive the exemption itself from, because the class is §6.1's prose; what IS
		// derivable is the class it partitions, so the table below is held against every
		// AttachmentKind the package declares and a kind added tomorrow fails here by name.
		exemption := map[string]struct {
			exempt bool
			record func(sender []byte, epoch uint64, index uint64) *Record
		}{
			"AttachmentNone": {record: func(sender []byte, epoch uint64, index uint64) *Record {
				return ordinaryRecord(sender, epoch, index, 0x30)
			}},
			"AttachmentEpoch": {record: func(sender []byte, epoch uint64, index uint64) *Record {
				return commitRecord(sender, epoch, index, epoch+1, 0x41)
			}},
			"AttachmentWrap": {exempt: true, record: func(sender []byte, epoch uint64, index uint64) *Record {
				return wrapRecord(sender, epoch, index, testHandle(0x21))
			}},
			"AttachmentRecovery": {record: func(sender []byte, epoch uint64, index uint64) *Record {
				return recoveryRecord(sender, epoch, index, testBytes(RecoveryHandleBytes, 0x60), testBytes(VerifyPubBytes, 0x70))
			}},
			"AttachmentEpochComplete": {exempt: true, record: func(sender []byte, epoch uint64, index uint64) *Record {
				return markerRecord(sender, epoch, index, 1)
			}},
		}
		declared := attachmentKindsDeclared(t)
		if len(declared) == 0 {
			t.Fatal("no AttachmentKind constant was found in the package, so this table is being held against nothing at all")
		}
		for _, name := range declared {
			if _, covered := exemption[name]; !covered {
				t.Fatalf("%s is an AttachmentKind the package declares and this table has no scenario for it; §6.1 step (2)'s exemption is a class, and a class with an untested member is a class that can be widened by one line", name)
			}
		}
		if len(exemption) != len(declared) {
			t.Fatalf("this table names %d kinds and the package declares %d (%v); a scenario for a kind that no longer exists is a scenario that stopped meaning anything", len(exemption), len(declared), declared)
		}

		for _, name := range declared {
			current := exemption[name]
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				store := newStore(DefaultLimits())
				group := createGroup(t, store, testGroupId(0x11), testHandle(0x20))
				results := submit(t, store, seen, group, current.record(testHandle(0x22), 1, 3))
				if current.exempt {
					wantReason(t, results[0], protocol.Reason_REASON_OK)
					return
				}
				wantReason(t, results[0], protocol.Reason_REASON_EPOCH_INCOMPLETE)
			})
		}
	})
}

// Every AttachmentKind the package declares, by name, read out of its const block rather than
// typed into the scenario that partitions it.
func attachmentKindsDeclared(t *testing.T) []string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	names := []string{}
	for _, file := range parseDirectories(t, []string{filepath.Dir(here)}) {
		for _, declaration := range file.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.CONST {
				continue
			}
			// the type is written once, on the first spec of the block, and every spec after it
			// inherits — so it is carried forward rather than read again
			kind := ""
			for _, specification := range general.Specs {
				value, isValue := specification.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				if named, isNamed := value.Type.(*ast.Ident); isNamed {
					kind = named.Name
				}
				if kind != "AttachmentKind" {
					continue
				}
				for _, name := range value.Names {
					names = append(names, name.Name)
				}
			}
		}
	}
	slices.Sort(names)
	return names
}

// ── §4.3.4's class filter ────────────────────────────────────────────────────────────────

// Which records a class mask returns, and not merely what class the records it returned are.
//
// The difference is the whole finding: an assertion of the form "everything that came back is
// PERMANENT" is satisfied by an empty answer, and an off-by-one in the mask makes every class
// answer empty. So the expected id set is built from the store's own unmasked answer and the
// masked answers are held against it exactly.
func contractClassMask(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))
	sender := testHandle(0x21)

	// one record per persisted class of §3.1, walked from the package's own constants rather
	// than typed out, so a bucket added to the eph ladder is a bucket this scenario files and
	// filters on. EPH(0) is absent because §7.6 is normative that it never reaches a store
	classes := []uint8{ClassPermanent, ClassDurable, ClassMedia}
	for bucket := ClassEphBase + 1; bucket <= ClassEphMax; bucket++ {
		classes = append(classes, bucket)
	}
	for index, class := range classes {
		record := ordinaryRecord(sender, 1, uint64(index), byte(0x60+index))
		record.RetentionClass = class
		wantReason(t, submit(t, store, seen, group, record)[0], protocol.Reason_REASON_OK)
	}

	// mask 0 is every class, which is the request's documented default and not an empty set
	everything := allRecords(t, store, group)
	if uint64(len(everything)) != nextRecordId(t, store, group)-1 {
		t.Fatalf("an unmasked fetch returned %d of the group's %d records", len(everything), nextRecordId(t, store, group)-1)
	}
	expected := map[uint8][]uint64{}
	for _, record := range everything {
		expected[record.RetentionClass] = append(expected[record.RetentionClass], record.RecordId)
	}

	for _, class := range classes {
		if len(expected[class]) == 0 {
			t.Fatalf("no record of class %#x reached the group, so filtering on it asserts nothing", class)
		}
		fetched, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0, ClassMask: uint32(1) << class})
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if !slices.Equal(recordIdsOf(fetched.Records), expected[class]) {
			t.Fatalf("a class-%#x fetch returned records %v, want exactly %v; an assertion about the class of what came back is vacuous on an empty answer, and an off-by-one in the mask answers empty for every class",
				class, recordIdsOf(fetched.Records), expected[class])
		}
	}

	// and the mask is a set: two bits are the union of the two classes, in record-id order
	union := append(slices.Clone(expected[ClassDurable]), expected[ClassMedia]...)
	slices.Sort(union)
	both, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0, ClassMask: uint32(1)<<ClassDurable | uint32(1)<<ClassMedia})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !slices.Equal(recordIdsOf(both.Records), union) {
		t.Fatalf("a two-class fetch returned %v, want %v", recordIdsOf(both.Records), union)
	}
}

// ── the store boundary ───────────────────────────────────────────────────────────────────

// Records cross this interface by value, in both directions, and neither direction had a test.
//
// It is a contract property rather than an implementation detail: the pgx store copies through
// the wire by construction and a store holding Go slices does not, so an implementation that
// handed out the slice it holds would be one whose callers can rewrite stored rows from outside
// the transaction — and would pass every other scenario in this file.
func contractDefensiveCopy(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	store, group := openGroup(t, newStore(DefaultLimits()))

	record := ordinaryRecord(testHandle(0x21), 1, 0, 0x30)
	bodyHash := slices.Clone(record.BodyHash)
	body := slices.Clone(record.CtBody)
	head := slices.Clone(record.CtHead)
	results := submit(t, store, seen, group, record)
	wantReason(t, results[0], protocol.Reason_REASON_OK)
	id := results[0].RecordId

	// the caller still holds the slices it handed over, and rewriting them must not rewrite the
	// row. body_hash is the one that matters most: it is what §6.1 step (0) probes against, so a
	// caller that could rewrite it could turn somebody else's retry into a REASON_OK naming its
	// own record
	record.BodyHash[0] ^= 0xff
	record.CtBody[0] ^= 0xff
	record.CtHead[0] ^= 0xff
	stored := recordById(t, store, group, id)
	if !slices.Equal(stored.BodyHash, bodyHash) || !slices.Equal(stored.CtBody, body) || !slices.Equal(stored.CtHead, head) {
		t.Fatal("a caller rewrote a stored record by rewriting the slice it submitted; the store took the caller's memory rather than a copy of it, which is not something the pgx implementation could do even by accident")
	}

	// heads_only drops the body from what is RETURNED and not from what is stored. §4.3.4 uses
	// it for fast catch-up and for hole scans, over the same rows the next full read serves
	heads, err := store.Fetch(ctx, &FetchRequest{GroupId: group, SinceRecordId: 0, HeadsOnly: true})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for _, one := range heads.Records {
		if one.CtBody != nil {
			t.Fatalf("heads_only returned a body for record %d", one.RecordId)
		}
	}
	if after := recordById(t, store, group, id); !slices.Equal(after.CtBody, body) {
		t.Fatalf("after a heads_only fetch the full read returns a %d-byte body, want the %d bytes that were stored; one catch-up read had erased every body in the group",
			len(after.CtBody), len(body))
	}

	// and what Fetch hands out is the caller's to scribble on
	for _, one := range allRecords(t, store, group) {
		if len(one.CtBody) != 0 {
			one.CtBody[0] ^= 0xff
		}
		if len(one.BodyHash) != 0 {
			one.BodyHash[0] ^= 0xff
		}
	}
	if after := recordById(t, store, group, id); !slices.Equal(after.CtBody, body) || !slices.Equal(after.BodyHash, bodyHash) {
		t.Fatal("a reader rewrote a stored record by rewriting what Fetch handed it")
	}
}

func recordById(t *testing.T, store Store, groupId []byte, id uint64) *Record {
	t.Helper()
	for _, record := range allRecords(t, store, groupId) {
		if record.RecordId == id {
			return record
		}
	}
	t.Fatalf("record %d is not in the group", id)
	return nil
}

// ── §7.1 ─────────────────────────────────────────────────────────────────────────────────

// prune_after, which §7.1 computes in Go from the class and the group's policy at the moment
// the row is written, and which §7.2's sweep is the only consumer of.
//
// It had no test and could not have had one: §3.2 has the column, the store had the arithmetic,
// and no interface method handed it back — so the whole of it could be replaced by a nil and
// every scenario stayed green, and the pgx implementation would have got no help from the
// contract on the one calculation that decides when user data is destroyed.
//
// What is asserted is a relation and not an instant, because the contract cannot set anybody's
// clock and §3.1 splits retention across a Go clock and a database clock: the submission is
// bracketed by two wall-clock readings and the row's prune time has to land in that bracket
// plus the class's own lifetime. The slack is for the skew between this process and whichever
// clock the store used; it is far below the smallest gap in §3.1's ladder, so a prune time
// computed from the wrong lifetime cannot hide inside it.
func contractPruneAfter(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	const slack = 60 * time.Second

	t.Run("EveryClassPrunesOnItsOwnLadder", func(t *testing.T) {
		t.Parallel()
		// the group's own policy, which is what DURABLE and MEDIA prune against, and which is
		// deliberately not either default: a store reading its lifetimes out of the operator's
		// configuration instead of out of the group's row would pass on the defaults
		store, group := openGroup(t, newStore(Limits{
			MediaTtlMaxSeconds:       2000,
			MediaTtlDefaultSeconds:   2000,
			DurableTtlDefaultSeconds: 31536000,
		}))
		state := stateOf(t, store, group)
		if state.MediaTtlSeconds != 2000 || state.DurableTtlSeconds == nil {
			t.Fatalf("the group's policy is media %d and text %v, and this scenario prunes against it", state.MediaTtlSeconds, state.DurableTtlSeconds)
		}

		lifetimes := map[uint8]*uint32{
			// §7.1: PERMANENT never prunes, and it is the only class with no lifetime at all
			ClassPermanent: nil,
			ClassDurable:   state.DurableTtlSeconds,
			ClassMedia:     ptr(state.MediaTtlSeconds),
		}
		// the eph ladder from the package's own table rather than from five numbers typed here,
		// so a bucket whose lifetime moves is a bucket this scenario moves with it
		for bucket := ClassEphBase + 1; bucket <= ClassEphMax; bucket++ {
			lifetimes[bucket] = ptr(ephBucketSeconds[bucket-ClassEphBase])
		}

		index := uint64(0)
		submitted := map[uint8]uint64{}
		brackets := map[uint8][2]time.Time{}
		for class := range lifetimes {
			record := ordinaryRecord(testHandle(0x21), 1, index, byte(0x60+index))
			record.RetentionClass = class
			before := time.Now().UTC()
			results := submit(t, store, seen, group, record)
			wantReason(t, results[0], protocol.Reason_REASON_OK)
			brackets[class] = [2]time.Time{before, time.Now().UTC()}
			submitted[class] = results[0].RecordId
			index++
		}

		for class, lifetime := range lifetimes {
			stored := recordById(t, store, group, submitted[class])
			if lifetime == nil {
				if stored.PruneAfter != nil {
					t.Errorf("a class-%#x record was given a prune time of %v; §7.1 is that PERMANENT never prunes, and a prune time on it is user data with a deletion date nobody asked for",
						class, *stored.PruneAfter)
				}
				continue
			}
			if stored.PruneAfter == nil {
				t.Errorf("a class-%#x record with a lifetime of %ds was given no prune time at all; §7.2's sweep has nothing to act on and the row is kept forever", class, *lifetime)
				continue
			}
			window := time.Duration(*lifetime) * time.Second
			earliest := brackets[class][0].Add(window - slack)
			latest := brackets[class][1].Add(window + slack)
			if stored.PruneAfter.Before(earliest) || stored.PruneAfter.After(latest) {
				t.Errorf("a class-%#x record with a lifetime of %ds prunes at %v, want somewhere in [%v, %v]; §7.1 computes it from the class and the group's policy and from nothing else",
					class, *lifetime, stored.PruneAfter.UTC(), earliest, latest)
			}
		}
	})

	t.Run("AnIndefiniteTextPolicyIsTheOtherClassThatNeverPrunes", func(t *testing.T) {
		t.Parallel()
		// the second of §7.1's two no-prune cases, and the one that is a property of the GROUP
		// rather than of the record: DURABLE under a policy the server did not cap
		store, group := openGroup(t, newStore(DefaultLimits()))
		commit := commitRecord(testHandle(0x31), 1, 0, 2, 0x40)
		commit.Attachment.Epoch.DurableTtlSeconds = DurableIndefinite
		wantReason(t, submit(t, store, seen, group, commit)[0], protocol.Reason_REASON_OK)
		wantReason(t, submit(t, store, seen, group, markerRecord(testHandle(0x31), 2, 1, 1))[0], protocol.Reason_REASON_OK)
		if state := stateOf(t, store, group); state.DurableTtlSeconds != nil {
			t.Fatalf("the group's text policy is %d, and this scenario needs the indefinite one", *state.DurableTtlSeconds)
		}

		results := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 2, 0, 0x30))
		wantReason(t, results[0], protocol.Reason_REASON_OK)
		if stored := recordById(t, store, group, results[0].RecordId); stored.PruneAfter != nil {
			t.Errorf("a DURABLE record under an indefinite policy prunes at %v; the group asked for indefinite and the server agreed to it", *stored.PruneAfter)
		}
	})

	t.Run("APruneTimeIsFixedWhenTheRowIsWritten", func(t *testing.T) {
		t.Parallel()
		// §7.1 computes it against the policy in force AT WRITE TIME, so a later commit that
		// shortens the policy does not retroactively bring forward the deletion of rows written
		// under the old one. That is what recordRow.policy is for, and it is the difference
		// between a policy change and a policy change applied backwards over a group's history.
		store, group := openGroup(t, newStore(DefaultLimits()))
		first := submit(t, store, seen, group, ordinaryRecord(testHandle(0x21), 1, 0, 0x30))
		wantReason(t, first[0], protocol.Reason_REASON_OK)
		before := recordById(t, store, group, first[0].RecordId)
		if before.PruneAfter == nil {
			t.Fatal("a DURABLE record under a bounded policy was given no prune time")
		}
		was := *before.PruneAfter

		commit := commitRecord(testHandle(0x31), 1, 1, 2, 0x40)
		commit.Attachment.Epoch.DurableTtlSeconds = 60
		wantReason(t, submit(t, store, seen, group, commit)[0], protocol.Reason_REASON_OK)
		wantReason(t, submit(t, store, seen, group, markerRecord(testHandle(0x31), 2, 2, 1))[0], protocol.Reason_REASON_OK)

		after := recordById(t, store, group, first[0].RecordId)
		if after.PruneAfter == nil || !after.PruneAfter.Equal(was) {
			t.Errorf("a commit that shortened the text policy moved an already-written row's prune time from %v to %v; §7.1 fixes it at write time, and a policy applied backwards deletes history the group never agreed to lose",
				was, after.PruneAfter)
		}
	})
}

// ── the derived gate: every refusal this package can name is exercised here ──────────────

type recorder struct {
	mutex   sync.Mutex
	reasons map[protocol.Reason]int
	// keyed by the sentinel's own message text rather than by a name typed here: the text is
	// what the AST gate below reads out of the errors.New call, so the two sides of that gate
	// are the same string and there is no mapping between them to get wrong
	sentinels map[string]int
}

func (self *recorder) observe(reason protocol.Reason) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.reasons[reason]++
}

func (self *recorder) observeSentinel(sentinel error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.sentinels[sentinel.Error()]++
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

func (self *recorder) exercisedSentinels() map[string]int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	found := map[string]int{}
	for sentinel, count := range self.sentinels {
		found[sentinel] = count
	}
	return found
}

// The class these gates hold the suite to is DERIVED, from the Go source of the code under
// test, and is never a list typed here.
//
// A typed list understates the class the moment somebody adds a refusal, and the test that
// would have caught the missing coverage is the test that stopped covering it. So the reasons
// are read out of the AST: every protocol.Reason the implementation under test can name. A new
// refusal that no scenario above produces fails here, and it fails naming itself.
//
// WHAT the AST is read out of is the half this gate got wrong first. Reading every .go file in
// the directory makes the class the DIRECTORY's, and two implementations of [Store] share this
// one. The day the pgx implementation names §6.4's REASON_RATE_LIMITED, a directory-derived
// class demands a scenario for it from the MEMORY run — and §6.4 is explicit that the memory
// store cannot answer it, because there is no connection to hold. RunContract is one function,
// so the demanded scenario would run against both, and the only way out under time pressure is
// to weaken the gate, which is how derived gates die. The class is therefore the reasons named
// by the functions REACHABLE from the methods of the concrete type this run is exercising.
func assertEveryRefusalIsExercised(t *testing.T, directories []string, under string, seen *recorder) {
	t.Helper()
	assertTheExtractorWorks(t)

	files := parseDirectories(t, directories)
	named, walked := reachableReasons(files, under)
	if walked == 0 {
		t.Fatalf("no function of %s was found in %d files under %v, so this gate read nothing at all", under, len(files), directories)
	}
	if len(named) == 0 {
		t.Fatalf("the %d functions reachable from %s name no protocol.Reason at all; either the store has stopped using §4.5's vocabulary or this gate has stopped seeing it", walked, under)
	}
	exercised := seen.exercised()

	described := []string{}
	for reason := range named {
		described = append(described, fmt.Sprintf("%v x%d", reason, exercised[reason]))
	}
	slices.Sort(described)
	t.Logf("%d functions reachable from %s name %d of §4.5's reasons; the contract produced them %s", walked, under, len(named), strings.Join(described, ", "))

	missing := []string{}
	for reason := range named {
		if exercised[reason] == 0 {
			missing = append(missing, reason.String())
		}
	}
	slices.Sort(missing)
	if len(missing) != 0 {
		t.Errorf("%s names these reasons and no contract scenario produced one:\n  %s\nevery refusal this implementation can give owes a scenario here, and the scenario is what asserts that the refusal allocated nothing — §5.1's headline property is that an attacker without a write_key cannot force a single row lock, a single index write, or a single WAL byte",
			under, strings.Join(missing, "\n  "))
	}
}

// The second derived class: every error sentinel declared beside the [Store] interface owes a
// scenario too.
//
// §4.5 separates a refusal, which is a reason on a result and is a client's answer, from an
// error, which is the API layer having handed the store something no client could produce. The
// refusals had a gate and the errors had a hand-typed table of four, which is the Rule 5
// failure applied to the other half of the vocabulary — three sentinels had no scenario at all,
// and one of them was being answered for the wrong condition entirely.
//
// The class is the INTERFACE's rather than the package's or the implementation's: these are the
// errors every implementation of [Store] owes, so they are read out of the file that declares
// `type Store interface`. What is carried is the sentinel's MESSAGE and not its name, because
// the message is what a scenario asserting it can be observed to have asserted — the derived
// class and the exercised set are then the same strings, with no mapping between them to typo.
func assertEverySentinelIsExercised(t *testing.T, directories []string, seen *recorder) {
	t.Helper()
	assertTheSentinelExtractorWorks(t)

	files := parseDirectories(t, directories)
	declared, where := sentinelsDeclaredWithTheInterface(files)
	if where == "" {
		t.Fatalf("no file under %v declares `type Store interface`, so this gate read nothing at all", directories)
	}
	if len(declared) == 0 {
		t.Fatalf("%s declares the Store interface and no error sentinel beside it; either the interface has stopped having errors or this gate has stopped seeing them", where)
	}
	exercised := seen.exercisedSentinels()

	missing := []string{}
	for message, name := range declared {
		if exercised[message] == 0 {
			missing = append(missing, fmt.Sprintf("%s (%q)", name, message))
		}
	}
	slices.Sort(missing)
	t.Logf("%s declares %d error sentinels for the Store interface; the contract asserted %d of them", where, len(declared), len(declared)-len(missing))
	if len(missing) != 0 {
		t.Errorf("these sentinels are declared with the Store interface and no contract scenario asserted one:\n  %s\nan unexercised sentinel is a condition nobody has checked the store answers for, and the one that had no scenario here turned out to be answered for a different condition entirely",
			strings.Join(missing, "\n  "))
	}
}

// The concrete type behind the [Store] the caller handed us, as a name the AST can be searched
// for. It is read off the interface's dynamic type rather than written here, so the gate
// follows whichever implementation this run is exercising.
func implementationUnderTest(t *testing.T, store Store) string {
	t.Helper()
	kind := reflect.TypeOf(store)
	for kind != nil && kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if kind == nil || kind.Name() == "" {
		t.Fatalf("the store under test is %T, which has no named type for the refusal gate to read a class from", store)
	}
	return kind.Name()
}

// One parsed source file of the package under test.
type sourceFile struct {
	name   string
	parsed *ast.File
}

func parseDirectories(t *testing.T, directories []string) []sourceFile {
	t.Helper()
	files := []sourceFile{}
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
			files = append(files, sourceFile{name: name, parsed: parseSource(t, name, string(text))})
		}
	}
	if len(files) == 0 {
		t.Fatalf("no Go source was read from %v, so the gates read nothing at all", directories)
	}
	return files
}

func parseSource(t *testing.T, name string, source string) *ast.File {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), name, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return parsed
}

// A function of the package. A plain function has an empty receiver.
type functionKey struct {
	receiver string
	name     string
}

// Every protocol.Reason named by a function reachable from the methods of `receiver`, and how
// many functions the walk visited.
//
// The walk is the whole of what makes the class per-implementation. It follows a plain call by
// name, which is exact — Go allows one package-level function per name — and a call on the
// enclosing function's own receiver by that receiver's type, which is exact too and is every
// `self.x()` in a store written in this package's style. Anything else, a call through a field
// or on a value whose type this walk does not track, is followed to EVERY method of that name
// in the package. That direction is deliberate: a walk that guesses narrow understates its
// class and goes quiet, and one that guesses wide only ever demands coverage it did not
// strictly have to.
func reachableReasons(files []sourceFile, receiver string) (map[protocol.Reason]bool, int) {
	plain := map[string]*ast.FuncDecl{}
	methods := map[functionKey]*ast.FuncDecl{}
	byName := map[string][]functionKey{}
	queue := []functionKey{}
	for _, file := range files {
		for _, declaration := range file.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction || function.Body == nil {
				continue
			}
			owner := receiverTypeOf(function)
			if owner == "" {
				plain[function.Name.Name] = function
				continue
			}
			key := functionKey{receiver: owner, name: function.Name.Name}
			methods[key] = function
			byName[function.Name.Name] = append(byName[function.Name.Name], key)
			if owner == receiver {
				queue = append(queue, key)
			}
		}
	}

	visited := map[functionKey]bool{}
	found := map[protocol.Reason]bool{}
	walked := 0
	for len(queue) != 0 {
		key := queue[0]
		queue = queue[1:]
		if visited[key] {
			continue
		}
		visited[key] = true
		function := plain[key.name]
		if key.receiver != "" {
			function = methods[key]
		}
		if function == nil {
			continue
		}
		walked++
		for reason := range reasonsIn(function) {
			found[reason] = true
		}
		queue = append(queue, callsIn(function, key.receiver, plain, byName)...)
	}
	return found, walked
}

func receiverTypeOf(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return ""
	}
	kind := function.Recv.List[0].Type
	if star, isStar := kind.(*ast.StarExpr); isStar {
		kind = star.X
	}
	if identifier, isIdentifier := kind.(*ast.Ident); isIdentifier {
		return identifier.Name
	}
	return ""
}

func receiverNameOf(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 || len(function.Recv.List[0].Names) == 0 {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
}

func callsIn(function *ast.FuncDecl, owner string, plain map[string]*ast.FuncDecl, byName map[string][]functionKey) []functionKey {
	self := receiverNameOf(function)
	called := []functionKey{}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		switch target := call.Fun.(type) {
		case *ast.Ident:
			if _, found := plain[target.Name]; found {
				called = append(called, functionKey{name: target.Name})
			}
		case *ast.SelectorExpr:
			if base, isIdentifier := target.X.(*ast.Ident); isIdentifier && self != "" && base.Name == self {
				called = append(called, functionKey{receiver: owner, name: target.Sel.Name})
				return true
			}
			called = append(called, byName[target.Sel.Name]...)
		}
		return true
	})
	return called
}

// The identifiers under one node that name a §4.5 reason, resolved through the generated enum's
// own name table rather than through a mapping written here.
func reasonsIn(node ast.Node) map[protocol.Reason]bool {
	found := map[protocol.Reason]bool{}
	ast.Inspect(node, func(node ast.Node) bool {
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

// The error sentinels declared in the file that declares `type Store interface`, keyed by their
// message text, with that file's name.
func sentinelsDeclaredWithTheInterface(files []sourceFile) (map[string]string, string) {
	for _, file := range files {
		if !declaresTheStoreInterface(file.parsed) {
			continue
		}
		found := map[string]string{}
		for _, declaration := range file.parsed.Decls {
			general, isGeneral := declaration.(*ast.GenDecl)
			if !isGeneral || general.Tok != token.VAR {
				continue
			}
			for _, specification := range general.Specs {
				value, isValue := specification.(*ast.ValueSpec)
				if !isValue {
					continue
				}
				for index, name := range value.Names {
					if !strings.HasPrefix(name.Name, "Err") || index >= len(value.Values) {
						continue
					}
					if message, isSentinel := errorsNewMessage(value.Values[index]); isSentinel {
						found[message] = name.Name
					}
				}
			}
		}
		return found, filepath.Base(file.name)
	}
	return nil, ""
}

func declaresTheStoreInterface(file *ast.File) bool {
	declares := false
	ast.Inspect(file, func(node ast.Node) bool {
		specification, isSpecification := node.(*ast.TypeSpec)
		if !isSpecification || specification.Name.Name != "Store" {
			return true
		}
		if _, isInterface := specification.Type.(*ast.InterfaceType); isInterface {
			declares = true
		}
		return true
	})
	return declares
}

// The message of an `errors.New("…")`, and whether the expression was one at all. A sentinel
// built any other way is not read as one rather than being read as an empty message: an empty
// message would join the class silently and could never be exercised.
func errorsNewMessage(expression ast.Expr) (string, bool) {
	call, isCall := expression.(*ast.CallExpr)
	if !isCall || len(call.Args) != 1 {
		return "", false
	}
	target, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || target.Sel.Name != "New" {
		return "", false
	}
	if base, isIdentifier := target.X.(*ast.Ident); !isIdentifier || base.Name != "errors" {
		return "", false
	}
	literal, isLiteral := call.Args[0].(*ast.BasicLit)
	if !isLiteral || literal.Kind != token.STRING {
		return "", false
	}
	message, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return message, true
}

// The reason extractor and the reachability walk, held against planted sources and clean ones.
//
// Without both halves this gate reports the green run of a complete gate having read nothing:
// an extractor that finds nothing passes the clean control and reports every reason as
// exercised, and an extractor that finds everything passes the planted one and reports reasons
// the store never names. The walk needs the same treatment in its own axis — a walk that
// reached everything would put the whole directory back in the class, which is the defect this
// gate was rewritten to fix — so the planted package carries a sibling implementation and an
// unreached function, and neither of their reasons may appear.
func assertTheExtractorWorks(t *testing.T) {
	t.Helper()
	// the planted reason is named through the generated enum's own name table rather than as an
	// identifier, because an identifier here would be an identifier in this file, and a control
	// that planted itself into the class would demand a scenario for a refusal nothing returns
	quota := protocol.Reason(protocol.Reason_value["REASON_QUOTA_EXCEEDED"])
	planted := reasonsIn(parseSource(t, "planted.go", plantedReasonSource))
	if len(planted) != 1 || !planted[quota] {
		t.Fatalf("a source naming exactly one reason was read as %v", planted)
	}
	clean := reasonsIn(parseSource(t, "clean.go", cleanReasonSource))
	if len(clean) != 0 {
		t.Fatalf("a source naming no reason at all was read as %v; a string and a lookalike identifier are not a reason", clean)
	}

	// Under is the implementation under test and Other is the one sharing its package, which is
	// exactly the pgx-beside-memory arrangement this gate exists to survive. Under's class is
	// the three reasons it reaches and neither of the two it cannot.
	files := []sourceFile{{name: "under.go", parsed: parseSource(t, "under.go", plantedWalkSource)}}
	reached, walked := reachableReasons(files, "Under")
	if walked != 4 {
		t.Fatalf("the walk from Under visited %d functions, want the 4 it can reach", walked)
	}
	want := map[protocol.Reason]bool{
		protocol.Reason_REASON_OK:                                    true,
		protocol.Reason(protocol.Reason_value["REASON_EPOCH_STALE"]): true,
		protocol.Reason(protocol.Reason_value["REASON_OVERSIZE"]):    true,
	}
	for reason := range want {
		if !reached[reason] {
			t.Fatalf("the walk from Under missed %v, which it reaches; a walk that guesses narrow understates its class and goes quiet", reason)
		}
	}
	for reason := range reached {
		if !want[reason] {
			t.Fatalf("the walk from Under reached %v, which only a sibling implementation or an unreached function names; that is the directory-wide class this gate was rewritten to stop deriving", reason)
		}
	}
	if _, none := reachableReasons(files, "NoSuchTypeAtAll"); none != 0 {
		t.Fatalf("the walk from a type with no methods visited %d functions, so an empty class would read as a complete one", none)
	}
}

// The sentinel extractor, held against a planted source and a clean one in both of its axes:
// what counts as a sentinel, and which file it has to be declared in.
func assertTheSentinelExtractorWorks(t *testing.T) {
	t.Helper()
	files := []sourceFile{
		{name: "elsewhere.go", parsed: parseSource(t, "elsewhere.go", plantedForeignSentinelSource)},
		{name: "iface.go", parsed: parseSource(t, "iface.go", plantedSentinelSource)},
	}
	declared, where := sentinelsDeclaredWithTheInterface(files)
	if where != "iface.go" {
		t.Fatalf("the sentinels were read out of %q, want the file declaring the Store interface", where)
	}
	if len(declared) != 1 || declared["planted: a sentinel"] != "ErrPlanted" {
		t.Fatalf("a file declaring one sentinel beside the interface was read as %v; a sentinel declared elsewhere, one built by fmt.Errorf and a var not named Err are none of them the interface's errors", declared)
	}
}

// The planted and clean sources the two extractor controls above read. They are constants
// rather than literals inside the controls because a source that names a reason as an
// identifier, written inline, would be an identifier in THIS file, and this file is inside the
// class the reason gate derives — the control would then demand a scenario for a refusal
// nothing can return. Held out here they are string data and the AST walk over contract.go
// never sees an identifier at all.
const (
	plantedReasonSource = `package planted

import "github.com/urnetwork/connect/protocol"

func f() protocol.Reason { return protocol.Reason_REASON_QUOTA_EXCEEDED }
`

	cleanReasonSource = `package clean

const ReasonablyNamed = "REASON_QUOTA_EXCEEDED"

func f() int { return 0 }
`

	// Under reaches three reasons by the three call shapes the walk resolves: its own receiver,
	// a plain function, and a method through a field. Other and unreached name two more that no
	// walk from Under may pick up.
	plantedWalkSource = `package under

import "github.com/urnetwork/connect/protocol"

type Under struct{ helper *Helper }
type Helper struct{}
type Other struct{}

func (self *Under) Reachable() protocol.Reason {
	if self.helper.throughAField() == protocol.Reason_REASON_OK {
		return plain()
	}
	return self.throughItsOwnReceiver()
}

func (self *Under) throughItsOwnReceiver() protocol.Reason { return protocol.Reason_REASON_EPOCH_STALE }

func (self *Helper) throughAField() protocol.Reason { return protocol.Reason_REASON_OVERSIZE }

func plain() protocol.Reason { return protocol.Reason_REASON_OK }

func (self *Other) Elsewhere() protocol.Reason { return protocol.Reason_REASON_RATE_LIMITED }

func unreached() protocol.Reason { return protocol.Reason_REASON_QUOTA_EXCEEDED }
`

	plantedForeignSentinelSource = `package planted

import "errors"

var ErrDeclaredAwayFromTheInterface = errors.New("planted: not the interface's error")
`

	plantedSentinelSource = `package planted

import (
	"errors"
	"fmt"
)

type Store interface{ Do() error }

var (
	ErrPlanted   = errors.New("planted: a sentinel")
	ErrFormatted = fmt.Errorf("planted: not an errors.New")
	NotASentinel = errors.New("planted: not named Err")
)
`
)

// ── the harness every scenario submits through ───────────────────────────────────────────

// One submission, with the invariants that hold for EVERY submission asserted on the way past.
//
// Four of them, and they are here rather than in one scenario each because they are true of
// every call and a property asserted in one place is a property the next scenario forgets:
//
//   - a batch carrying any refusal allocated nothing at all (§6.1 step 3b, §5.1);
//   - the ids handed to an accepted batch are exactly the block next_record_id moved by, in
//     order, so gapless and 1-based is checked on every accepted record in this file;
//   - an acceptance that allocated nothing is a step (0) idempotent hit and names a record id
//     the group had already assigned;
//   - §4.3.3's `current_epoch` is always set, on every result, so a stale client resynchronises
//     in one round trip. It is asserted against the epoch the group is at after the call rather
//     than against a number written here, and that is only sound because every caller of this
//     helper is serial — the racing scenarios call Submit directly.
//
// "Accepted" is [accepted] and not REASON_OK: §7.3's REASON_RETENTION_CLAMPED is an acceptance
// carrying a notice, with a record id and an opened epoch behind it.
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
		if !accepted(result.Reason) {
			refused = true
		}
		if accepted(result.Reason) && result.RecordId == 0 {
			t.Fatalf("an accepted record was given record_id 0, which Spec A §5.1 reserves as the from-the-beginning cursor")
		}
	}
	if !known {
		return response.Results
	}

	epoch := stateOf(t, store, groupId).CurrentEpoch
	for index, result := range response.Results {
		if result.CurrentEpoch != epoch {
			t.Fatalf("result %d carried current_epoch %d and the group is at %d; §4.3.3 sets it on EVERY result so a stale client resynchronises in one round trip, and the common case — an accepted ordinary record — is the one that goes uncovered when only the refusals fill it",
				index, result.CurrentEpoch, epoch)
		}
	}

	if refused && after != before {
		t.Fatalf("a submission carrying a refusal moved next_record_id from %d to %d; §5.1's headline property is that a refusal costs the group nothing — not a row lock, not an index write, not a WAL byte",
			before, after)
	}
	allocated := []uint64{}
	for _, result := range response.Results {
		if accepted(result.Reason) && result.RecordId >= before {
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

// An error the store answered, held against the sentinel §4.5 separates from a refusal, and
// recorded so [assertEverySentinelIsExercised] can see that this sentinel has a scenario. Every
// assertion about an error goes through here, so a sentinel that loses its last scenario loses
// it loudly.
func wantError(t *testing.T, seen *recorder, got error, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("the store answered %v, want the sentinel %v", got, want)
	}
	seen.observeSentinel(want)
}

// A group that exists and is open for ordinary writes: created, and then its epoch-1 wrap
// fan-out closed with the marker §6.1's epoch publication step 3 requires. Without the marker
// the group is readable-but-not-writable and every ordinary submit is REASON_EPOCH_INCOMPLETE,
// which is correct and is not what most of these scenarios are about — the scenarios whose
// subject it IS use [createGroup] and take the group before the marker.
func openGroup(t *testing.T, store Store) (Store, []byte) {
	t.Helper()
	groupId := createGroup(t, store, testGroupId(0x11), testHandle(0x20))
	response, err := store.Submit(context.Background(), &SubmitRequest{
		GroupId: groupId,
		Records: []*Record{markerRecord(testHandle(0x20), 1, 1, 1)},
	})
	if err != nil {
		t.Fatalf("Submit(marker): %v", err)
	}
	if !accepted(response.Results[0].Reason) {
		t.Fatalf("the epoch-1 marker was answered %v", response.Results[0].Reason)
	}
	return store, groupId
}

// §4.3.2 and nothing after it: a group whose epoch-1 wrap fan-out has NOT landed, which is what
// CreateGroup leaves behind and is the state the group spends its first round trips in.
func createGroup(t *testing.T, store Store, groupId []byte, creator []byte) []byte {
	t.Helper()
	created, err := store.CreateGroup(context.Background(), &CreateGroupRequest{
		GroupId:           groupId,
		InitialCommit:     commitRecord(creator, 0, 0, 1, 0x40),
		BootstrapWriteKey: testBytes(EpochKeyBytes, 0x50),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if !accepted(created.Reason) {
		t.Fatalf("CreateGroup answered %v", created.Reason)
	}
	return groupId
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

// Every record the group holds, read back through the from-the-beginning cursor of §4.3.4.
func allRecords(t *testing.T, store Store, groupId []byte) []*Record {
	t.Helper()
	fetched, err := store.Fetch(context.Background(), &FetchRequest{GroupId: groupId, SinceRecordId: 0})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	return fetched.Records
}

func recordIdsOf(records []*Record) []uint64 {
	ids := []uint64{}
	for _, record := range records {
		ids = append(ids, record.RecordId)
	}
	return ids
}

func errorOf[T any](_ T, err error) error {
	return err
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────

// §5.1 check 3's attachment damage, as one table, because both paths that check a commit's
// attachment owe every case of it. CreateGroup's founding commit is the one commit no later
// commit can rescue, and it had no scenario at all while the submit path had four — so the
// table lives here and the two scenarios read it rather than each keeping a copy to diverge.
var malformedEpochAttachments = map[string]func(*EpochAttachment){
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

// §5.4's RecoveryTag: the seed-only restore of §4.3.7 finds its archive by handle, and the pub
// the server pinned for that handle is what a restore proves possession against.
func recoveryRecord(sender []byte, epoch uint64, index uint64, handle []byte, verifyPub []byte) *Record {
	record := ordinaryRecord(sender, epoch, index, 0xB0)
	record.RetentionClass = ClassPermanent
	record.ServerAttachment = testBytes(64, 0xB0)
	record.Attachment = &Attachment{
		Kind:     AttachmentRecovery,
		Recovery: &RecoveryTag{Handle: handle, VerifyPub: verifyPub, AlgId: 1},
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
