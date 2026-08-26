package api

import (
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
)

// ── §4.3.3's batch ───────────────────────────────────────────────────────────────────────

// Every batch in this file carries more than one record, and until it existed no test in this
// package did. A pipeline that only ever sees a batch of one cannot tell a per-record answer from
// a per-batch one, cannot tell one epoch-key lookup from N of them, and cannot tell a positional
// result list from a list of the same length by accident.

// A SubmitResult is aligned with the request positionally, and the refusing record's own reason
// lands on the refusing record's own index.
//
// §4.3.3 states the alignment and §6.1 step (3b) states what the other records get: the whole
// batch rolls back, so every index carries a refusal, but only the offender's carries the
// offender's reason. Merging the two — one result for the batch, or the offender's reason on
// every index — is how a client learns the wrong thing about which of its records it may retry.
func TestASubmitResultIsAlignedWithTheRequestPositionally(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted, MaxCtHeadBytes: 64})
	counted.Store = fixture.store
	fixture.createOpenGroup(t)
	before := len(fixture.fetch(t).GetRecords())

	records := []*protocol.Record{}
	for index := 0; index < 3; index++ {
		head := []byte("a head within the cap")
		if index == 1 {
			// over the configured cap, which is check 3's REASON_OVERSIZE and not its
			// REASON_REJECTED — so a result carrying the offender's reason is distinguishable
			// from one carrying the batch's
			head = make([]byte, 65)
		}
		records = append(records, fixture.seal(t, sealed{
			sender: senderA, epoch: 1, streamIndex: uint64(200 + index),
			class: message.RetentionDurable, bucket: message.SizeBucket256,
			head: head, body: []byte("a body"), writeKey: fixture.writeKey(1),
		}))
	}

	counted.reset()
	results := fixture.submit(t, records...)
	want := []protocol.Reason{
		protocol.Reason_REASON_REJECTED,
		protocol.Reason_REASON_OVERSIZE,
		protocol.Reason_REASON_REJECTED,
	}
	for index, result := range results {
		if result.GetReason() != want[index] {
			t.Fatalf("record %d of the batch was answered %v, want %v; §4.3.3 aligns results with the request and only the offender carries the offender's reason",
				index, result.GetReason(), want[index])
		}
		if result.GetRecordId() != 0 {
			t.Fatalf("record %d of a refused batch was allocated record_id %d", index, result.GetRecordId())
		}
	}
	if counted.submit != 0 {
		t.Fatal("a batch refused by check 3 reached §6.1's transaction")
	}
	if after := len(fixture.fetch(t).GetRecords()); after != before {
		t.Fatalf("a refused batch stored %d records", after-before)
	}
}

// A batch that names one epoch reads message_epoch once.
//
// §5.1 check 6 says "one lookup for a 256-record batch naming one epoch" and the memo in
// checkEpochKey is what makes it true. Nothing observed it while every test submitted one record,
// because one record and one lookup agree under every implementation.
func TestABatchNamingOneEpochPaysOneEpochKeyLookup(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store
	fixture.createOpenGroup(t)

	records := []*protocol.Record{}
	for index := 0; index < 5; index++ {
		records = append(records, fixture.seal(t, sealed{
			sender: senderA, epoch: 1, streamIndex: uint64(300 + index),
			class: message.RetentionDurable, bucket: message.SizeBucket256,
			head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
		}))
	}

	counted.reset()
	results := fixture.submit(t, records...)
	for index, result := range results {
		if result.GetReason() != protocol.Reason_REASON_OK {
			t.Fatalf("record %d of an accepted batch was answered %v", index, result.GetReason())
		}
	}
	if counted.epochKeys != 1 {
		t.Fatalf("a batch of %d records naming one epoch cost %d message_epoch lookups, want exactly one",
			len(records), counted.epochKeys)
	}
}

// §4.3.3: a batch containing a commit contains exactly one record.
//
// The reason is in §4.3.3's own words — partial-failure semantics during an epoch change would
// otherwise be ambiguous — and the rule is check 3's, which means it is answered before check 5's
// filter, before check 6's lookup and before the transaction. The store refuses the same shape
// with ErrCommitBatch, but that is an error and not a client's answer: reaching it would turn a
// client mistake into a REASON_INTERNAL and a database round trip.
func TestABatchContainingACommitContainsExactlyOneRecord(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store
	fixture.createOpenGroup(t)
	before := len(fixture.fetch(t).GetRecords())

	ordinary := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 400,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("an ordinary head"), body: []byte("an ordinary body"), writeKey: fixture.writeKey(1),
	})
	commit := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 401, isCommit: true,
		class: message.RetentionPermanent, bucket: message.SizeBucket256,
		head: []byte("a commit head"), body: []byte("a commit body"),
		attachment: fixture.epochAttachment(2, 1), writeKey: fixture.writeKey(1),
	})

	counted.reset()
	results := fixture.submit(t, ordinary, commit)
	for index, result := range results {
		if result.GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("record %d of a batch carrying a commit beside another record was answered %v, want REASON_REJECTED",
				index, result.GetReason())
		}
	}
	if counted.submit != 0 {
		t.Fatal("a batch carrying a commit beside another record reached §6.1's transaction, where ErrCommitBatch would have made a client's mistake a REASON_INTERNAL")
	}
	if after := len(fixture.fetch(t).GetRecords()); after != before {
		t.Fatalf("a refused commit batch stored %d records", after-before)
	}
}

// §4.3.1's `max_records_per_submit`, at a configured bound and at the documented default.
//
// The bound is advertised in Capabilities and enforced in exactly one place. Without it a single
// request decides how much work the process does, which is the denial of service §5.1's whole
// check order is written against — and it is check 3's, so an oversized batch costs no lookup and
// no transaction.
func TestMaxRecordsPerSubmitBoundsABatch(t *testing.T) {
	for _, current := range []struct {
		name  string
		limit int
	}{
		{"a configured bound", 2},
		{"the documented default", DefaultMaxRecordsPerSubmit},
	} {
		t.Run(current.name, func(t *testing.T) {
			configured := current.limit
			if configured == DefaultMaxRecordsPerSubmit {
				// zero takes the default, which is what this case is here to hold
				configured = 0
			}
			counted := &countingStore{}
			fixture := newFixtureWith(t, Config{Store: counted, MaxRecordsPerSubmit: configured})
			counted.Store = fixture.store
			fixture.createOpenGroup(t)
			before := len(fixture.fetch(t).GetRecords())

			batch := func(count int, base uint64) []*protocol.Record {
				records := []*protocol.Record{}
				for index := 0; index < count; index++ {
					records = append(records, fixture.seal(t, sealed{
						sender: senderA, epoch: 1, streamIndex: base + uint64(index),
						class: message.RetentionDurable, bucket: message.SizeBucket256,
						head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
					}))
				}
				return records
			}

			counted.reset()
			over := batch(current.limit+1, 1000)
			for index, result := range fixture.submit(t, over...) {
				if result.GetReason() != protocol.Reason_REASON_OVERSIZE {
					t.Fatalf("record %d of a %d-record batch under a bound of %d was answered %v, want REASON_OVERSIZE",
						index, len(over), current.limit, result.GetReason())
				}
			}
			if counted.submit != 0 {
				t.Fatalf("a %d-record batch over the bound of %d reached §6.1's transaction", len(over), current.limit)
			}
			if after := len(fixture.fetch(t).GetRecords()); after != before {
				t.Fatalf("an oversized batch stored %d records", after-before)
			}

			// and the bound itself is not off by one: exactly the bound is accepted
			at := batch(current.limit, 2000)
			for index, result := range fixture.submit(t, at...) {
				if result.GetReason() != protocol.Reason_REASON_OK {
					t.Fatalf("record %d of a batch of exactly the bound (%d) was answered %v, want REASON_OK",
						index, current.limit, result.GetReason())
				}
			}
			if after := len(fixture.fetch(t).GetRecords()); after != before+current.limit {
				t.Fatalf("a batch of exactly the bound stored %d records, want %d", after-before, current.limit)
			}
		})
	}
}
