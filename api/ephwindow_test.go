package api

import (
	"fmt"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"google.golang.org/protobuf/proto"
)

// ── §5.1 check 3's `eph_window` clause, which is §7.1 and Spec A requirement S19 ──────────

// `eph_window` is zero unless the record's retention-class wire byte is 17..21, and EPH(0) is on
// the zero side of that line.
//
// THE WIRE-BYTE PHRASING AND A CLASS-PHRASED ONE ARE NOT THE SAME RULE, AND THIS IS THE RECORD
// THEY DISAGREE ON. MASTER §8 gives the byte as `0x10 | bucket`, so EPH(0) is `0x10` = 16, which
// is OUTSIDE 17..21 — §5.1 check 3 and §3.2's CHECK therefore both put the transient rung in the
// must-be-zero half, agreeing exactly with MASTER §8's presence rule ("always present; 0 on
// PERMANENT, DURABLE, MEDIA and EPH(0)"). A server that read the same clause as "a non-EPH class"
// would be wrong by one class and would admit a window on EPH(0).
//
// The EPH(0) rows below are what make that difference observable rather than argued. §7.6 is why
// this build answers REASON_INTERNAL for an EPH(0) at all — it is published and dropped, and this
// build has no channel to publish it on — but that refusal is [Handler.recordKindIsBuilt]'s, six
// checks later. A window on one is REASON_REJECTED, from check 3, and the two are distinguishable.
//
// The store's own copy of the same CHECK cannot make this distinction and is not asked to: §7.6
// gives an EPH(0) no row at all, so the window constraint on it is unreachable there.
func TestAnEphWindowIsZeroUnlessTheWireByteIsSeventeenThroughTwentyOne(t *testing.T) {
	for _, current := range []struct {
		name      string
		class     message.RetentionClass
		ephBucket uint8
		// what this build answers when the window is the zero the presence rule requires
		zeroWindow protocol.Reason
	}{
		{"permanent", message.RetentionPermanent, 0, protocol.Reason_REASON_OK},
		{"durable", message.RetentionDurable, 0, protocol.Reason_REASON_OK},
		{"media", message.RetentionMedia, 0, protocol.Reason_REASON_OK},
		{"eph bucket 0", message.RetentionEph, 0, protocol.Reason_REASON_INTERNAL},
	} {
		t.Run(current.name, func(t *testing.T) {
			wire, err := message.RetentionClassWire(current.class, current.ephBucket)
			if err != nil {
				t.Fatalf("RetentionClassWire: %v", err)
			}
			if 17 <= wire && wire <= 21 {
				t.Fatalf("%s has wire byte %d, which is INSIDE 17..21, so this table has put a windowed class in the must-be-zero half",
					current.name, wire)
			}

			fixture := newFixture(t)
			fixture.createOpenGroup(t)
			before := len(fixture.fetch(t).GetRecords())

			zero := fixture.seal(t, sealed{
				sender: senderA, epoch: 1, streamIndex: 90, class: current.class,
				ephBucket: current.ephBucket, ephWindow: 0, bucket: message.SizeBucket256,
				head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
			})
			if reason := fixture.submit(t, zero)[0].GetReason(); reason != current.zeroWindow {
				t.Fatalf("%s carrying the zero window the presence rule requires was answered %v, want %v",
					current.name, reason, current.zeroWindow)
			}

			// one, and not the arrival window: the claim is that ANY nonzero value is refused
			// here, and a plausible value would leave a server that ran the ±1 arithmetic on an
			// unwindowed class indistinguishable from one that refused outright
			windowed := fixture.seal(t, sealed{
				sender: senderA, epoch: 1, streamIndex: 91, class: current.class,
				ephBucket: current.ephBucket, ephWindow: 1, bucket: message.SizeBucket256,
				head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
			})
			results := fixture.submit(t, windowed)
			if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
				t.Fatalf("%s (wire byte %d, outside 17..21) carrying eph_window 1 was answered %v, want REASON_REJECTED",
					current.name, wire, results[0].GetReason())
			}
			if results[0].GetRecordId() != 0 {
				t.Fatalf("%s carrying a window it may not carry was allocated record_id %d",
					current.name, results[0].GetRecordId())
			}

			accepted := 0
			if current.zeroWindow == protocol.Reason_REASON_OK {
				accepted = 1
			}
			if after := len(fixture.fetch(t).GetRecords()); after != before+accepted {
				t.Fatalf("%s: the group holds %d records after one %v and one refusal, and held %d",
					current.name, after, current.zeroWindow, before)
			}
		})
	}
}

// On EPH(1..5), the submitted window is within ONE of the window this record's own arrival stamp
// falls in, in either direction (§5.1 check 3, §7.1, Spec A requirement S19).
//
// ±1 AND NOT TIGHTER: the sender computes from `sent_at` and this server sees arrival, so a record
// that crossed a boundary in flight is a legitimate record one window behind. ±1 AND NOT LOOSER:
// under the 2026-09-13 ruling the window selects the record's own KEY, so a window ahead extends
// that key past its timer and no later sweep of this server's corrects it; two windows would
// double the shortest bucket's guarantee, which is the thing the rule protects.
//
// EVERY BUCKET, because the divisor is the bucket's own: a server that read one bucket's seconds
// for another would be within ±1 on the bucket it happened to read and on no other. And a window
// of ZERO is in the table for the presence rule's other half — MASTER §8 makes the field nonzero
// on EPH(1..5), and this clause is what refuses a zero, because zero is the whole distance from
// the unix epoch to now measured in this bucket's windows.
func TestAnEphWindowMoreThanOneFromTheArrivalWindowIsRefused(t *testing.T) {
	for bucket := uint8(1); bucket <= 5; bucket++ {
		seconds := message.EphBucketSeconds(bucket)
		if seconds <= 0 {
			t.Fatalf("eph bucket %d answers %d seconds, so this loop has walked off the windowed rungs",
				bucket, seconds)
		}
		t.Run(fmt.Sprintf("bucket%d", bucket), func(t *testing.T) {
			fixture := newFixture(t)
			fixture.createOpenGroup(t)
			arrival := fixture.arrivalWindow(t, bucket)
			if arrival < 3 {
				t.Fatalf("the arrival window for bucket %d is %d, which is too near the origin for this test to submit one two windows behind",
					bucket, arrival)
			}
			before := len(fixture.fetch(t).GetRecords())

			accepted := 0
			index := uint64(100)
			for _, offset := range []int64{-2, -1, 0, 1, 2} {
				window := uint64(int64(arrival) + offset)
				want := protocol.Reason_REASON_OK
				if offset < -1 || 1 < offset {
					want = protocol.Reason_REASON_REJECTED
				}
				index++
				record := fixture.seal(t, sealed{
					sender: senderA, epoch: 1, streamIndex: index, class: message.RetentionEph,
					ephBucket: bucket, ephWindow: window, bucket: message.SizeBucket256,
					head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
				})
				results := fixture.submit(t, record)
				if results[0].GetReason() != want {
					t.Fatalf("EPH(%d) at window %d, which is %+d from the arrival window %d, was answered %v, want %v",
						bucket, window, offset, arrival, results[0].GetReason(), want)
				}
				if want == protocol.Reason_REASON_OK {
					accepted++
					continue
				}
				if results[0].GetRecordId() != 0 {
					t.Fatalf("EPH(%d) at %+d from arrival was refused and allocated record_id %d",
						bucket, offset, results[0].GetRecordId())
				}
			}

			index++
			zero := fixture.seal(t, sealed{
				sender: senderA, epoch: 1, streamIndex: index, class: message.RetentionEph,
				ephBucket: bucket, ephWindow: 0, bucket: message.SizeBucket256,
				head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
			})
			if reason := fixture.submit(t, zero)[0].GetReason(); reason != protocol.Reason_REASON_REJECTED {
				t.Fatalf("EPH(%d) carrying eph_window 0, which MASTER §8's presence rule makes nonzero on this class and which is %d windows behind arrival, was answered %v, want REASON_REJECTED",
					bucket, arrival, reason)
			}

			if after := len(fixture.fetch(t).GetRecords()); after != before+accepted {
				t.Fatalf("bucket %d: the group holds %d records after %d acceptable windows and three refusals, and held %d",
					bucket, after, accepted, before)
			}
		})
	}
}

// The window this server refuses on is a value `write_auth` covers, which is what makes the
// refusal worth making in a server that reads nothing (MASTER §9.2, ruled 2026-09-13).
//
// The bytes are rewritten to a window check 3 ACCEPTS — one ahead of arrival — so the refusal
// below cannot be check 3's own clause answering for itself. What refuses it is check 7, over a
// preimage whose `u64(eph_window)` sits immediately after `u8(retention_class)`. The control is
// the same parse re-encoded untouched: it is accepted, so the refusal is the rewritten field and
// not the re-encoding.
func TestRewritingTheEphWindowBreaksTheMacThatCoversIt(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store
	fixture.createOpenGroup(t)
	arrival := fixture.arrivalWindow(t, 1)

	original := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 120, class: message.RetentionEph,
		ephBucket: 1, ephWindow: arrival, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})

	reencode := func(window uint64) *protocol.Record {
		t.Helper()
		parsed, err := message.ParseRecord(original.GetRecordBytes())
		if err != nil {
			t.Fatalf("the record this test sealed does not parse: %v", err)
		}
		parsed.Header.EphWindow = window
		recordBytes, err := message.EncodeRecord(parsed)
		if err != nil {
			t.Fatalf("EncodeRecord: %v", err)
		}
		again, isRecord := proto.Clone(original).(*protocol.Record)
		if !isRecord {
			t.Fatal("proto.Clone of a Record answered something else")
		}
		again.RecordBytes = recordBytes
		return again
	}

	counted.reset()
	results := fixture.submit(t, reencode(arrival+1))
	if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a record whose eph_window was rewritten from %d to %d under its original write_auth was answered %v, want REASON_REJECTED",
			arrival, arrival+1, results[0].GetReason())
	}
	if counted.submit != 0 {
		t.Fatal("the rewritten record reached §6.1's transaction; check 7 refuses it two checks earlier")
	}

	if reason := fixture.submit(t, reencode(arrival))[0].GetReason(); reason != protocol.Reason_REASON_OK {
		t.Fatalf("the same parse re-encoded with its own window was answered %v, so the refusal above is the re-encoding rather than the rewritten field",
			reason)
	}
}
