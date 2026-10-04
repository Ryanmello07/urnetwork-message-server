package api

import (
	"slices"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
)

// THE EPOCH CEILING of ledger item 246, through §5.1.1's whole read path rather than through the
// store: a real `req_auth` under a real read key, check 6's lookup on `(group_id, read_epoch)`,
// and the records that come back off the wire.
//
// The store contract holds both implementations to the rule ([RunContract]'s
// TheEpochCeilingServesNothingAboveTheAuthenticatedEpoch). What it cannot hold anybody to is the
// half that lives here: that the ceiling is the SAME number the MAC was computed over. A handler
// that passed the group's current epoch, or nothing, or a number off the connection would pass
// every assertion in the store suite and serve a removed member the whole group.

// The group this file builds, and the id/epoch table every expectation below is read off. The
// fixture's own `createOpenGroup` is records 1 through 3; each `advanceEpochTo` adds three more.
//
//	id  1  commit   epoch 0   opens 1     <- createGroup
//	id  2  wrap     epoch 1               <- createOpenGroup
//	id  3  marker   epoch 1
//	id  4  ordinary epoch 1
//	id  5  commit   epoch 1   opens 2     <- the ceiling for a reader at epoch 1
//	id  6  wrap     epoch 2
//	id  7  marker   epoch 2
//	id  8  ordinary epoch 2
//	id  9  commit   epoch 2   opens 3     <- the ceiling for a reader at epoch 2
//	id 10  wrap     epoch 3
//	id 11  marker   epoch 3
//	id 12  ordinary epoch 3
//
// The last record id each ceiling admits, written down rather than computed, so that a change to
// the fixture above shows up as a failure here and not as a silently different expectation.
var ceilingTops = map[uint64]uint64{1: 5, 2: 9, 3: 12}

// A fetch of the whole group under a named epoch, with its req_auth computed under that
// epoch's read key. [fixture.fetch] is the same thing pinned to epoch 1, which is every other
// test in this package and is the one reading a ceiling cannot be seen through.
func (self *fixture) fetchAt(t *testing.T, epoch uint64) *protocol.FetchResponse {
	t.Helper()
	reason, response, err := self.fetchFrom(t, &protocol.FetchRequest{GroupId: self.groupId, ReadEpoch: epoch})
	if err != nil {
		t.Fatalf("Fetch(read_epoch %d): %v", epoch, err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("Fetch(read_epoch %d) answered %v, want REASON_OK", epoch, reason)
	}
	return response
}

// A commit at `from` opening `from+1`, and the wrap and marker that close the new epoch's
// fan-out — which is exactly what `createOpenGroup` does for epoch 1, one epoch later.
//
// `index` is senderA's next free stream index; the three records consume it, +1 and +2.
func advanceEpochTo(t *testing.T, fixture *fixture, from uint64, index uint64) {
	t.Helper()
	commit := fixture.seal(t, sealed{
		sender: senderA, epoch: from, streamIndex: index, isCommit: true,
		class: message.RetentionPermanent, bucket: message.SizeBucket256,
		head: []byte("a commit"), body: []byte("a commit"),
		attachment: fixture.epochAttachment(from+1, 1), writeKey: fixture.writeKey(from),
	})
	if results := fixture.submit(t, commit); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the commit closing epoch %d was answered %v", from, results[0].GetReason())
	}
	wrap := fixture.seal(t, sealed{
		sender: senderA, epoch: from + 1, streamIndex: index + 1,
		class: message.RetentionPermanent, bucket: message.SizeBucket256,
		head: []byte("a wrap"), body: []byte("a wrap"),
		attachment: wrapAttachment(from+1, senderA), writeKey: fixture.writeKey(from + 1),
	})
	if results := fixture.submit(t, wrap); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the epoch-%d wrap was answered %v", from+1, results[0].GetReason())
	}
	marker := fixture.seal(t, sealed{
		sender: senderA, epoch: from + 1, streamIndex: index + 2,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("complete"), body: []byte("complete"),
		attachment: completeAttachment(from+1, 1), writeKey: fixture.writeKey(from + 1),
	})
	if results := fixture.submit(t, marker); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the epoch-%d marker was answered %v", from+1, results[0].GetReason())
	}
}

// One ordinary DURABLE record at `epoch`, so that each epoch has something in it that is not
// ceremony.
func ordinaryAt(t *testing.T, fixture *fixture, epoch uint64, index uint64) {
	t.Helper()
	record := fixture.seal(t, sealed{
		sender: senderA, epoch: epoch, streamIndex: index,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a message"), body: []byte("a message"), writeKey: fixture.writeKey(epoch),
	})
	if results := fixture.submit(t, record); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("an ordinary record at epoch %d was answered %v", epoch, results[0].GetReason())
	}
}

// The group of the table above: three epochs, each with one ordinary record, each closed by a
// commit that opens the next.
func threeEpochGroup(t *testing.T, fixture *fixture) {
	t.Helper()
	fixture.createOpenGroup(t) // records 1..3; senderA has spent stream indices 0,1,2
	ordinaryAt(t, fixture, 1, 3)
	advanceEpochTo(t, fixture, 1, 4) // records 5,6,7
	ordinaryAt(t, fixture, 2, 7)
	advanceEpochTo(t, fixture, 2, 8) // records 9,10,11
	ordinaryAt(t, fixture, 3, 11)
}

// The ceiling, served: a fetch authorized under `read_key[n]` comes back with nothing above
// epoch n, and the high water comes back as the top of what that ceiling admits.
//
// This is the measurement ledger item 244 made in the other direction. It reproduced a fetch
// authorized under `read_key[1]` serving eight records, four of them above epoch 1; the
// complement below is what makes a green run here the opposite claim rather than a fixture that
// happens to hold nothing interesting.
func TestAFetchIsServedNothingAboveTheEpochItsReqAuthWasComputedUnder(t *testing.T) {
	fixture := newFixture(t)
	threeEpochGroup(t, fixture)

	// the whole group, read at its own epoch. This is the positive control and the source of
	// every expectation below: if the ceiling were dropped, this is the page every reader would
	// get, and the complement at each ceiling is what tells the two apart
	whole := fixture.fetchAt(t, 3)
	if len(whole.GetRecords()) != 12 {
		t.Fatalf("the fixture built %d records and the table in this file is written for 12", len(whole.GetRecords()))
	}

	for ceiling := uint64(1); ceiling <= 3; ceiling++ {
		page := fixture.fetchAt(t, ceiling)
		served, withheld := []uint64{}, []uint64{}
		for _, record := range whole.GetRecords() {
			header, err := message.ParseRecordHeader(record.GetRecordBytes())
			if err != nil {
				t.Fatalf("parsing record %d: %v", record.GetRecordId(), err)
			}
			if header.Epoch <= ceiling {
				served = append(served, record.GetRecordId())
			} else {
				withheld = append(withheld, record.GetRecordId())
			}
		}
		got := []uint64{}
		for _, record := range page.GetRecords() {
			got = append(got, record.GetRecordId())
			header, err := message.ParseRecordHeader(record.GetRecordBytes())
			if err != nil {
				t.Fatalf("parsing record %d: %v", record.GetRecordId(), err)
			}
			// asserted against the SERVED BYTES and not against a column: the record a client
			// reads its own epoch out of is the one the handler rebuilt, and a ceiling applied
			// to a column the rebuild then contradicted would pass a test that read the column
			if ceiling < header.Epoch {
				t.Fatalf("a fetch authorized under read_key[%d] was served record %d, whose own header names epoch %d",
					ceiling, record.GetRecordId(), header.Epoch)
			}
		}
		if !slices.Equal(got, served) {
			t.Fatalf("a fetch authorized under read_key[%d] served %v; the records at or below epoch %d are %v", ceiling, got, ceiling, served)
		}
		// THE COMPLEMENT. A ceiling below the group's epoch that withheld nothing is the shape
		// a dropped ceiling arrives in, and every assertion above still passes in it
		if ceiling < 3 && len(withheld) == 0 {
			t.Fatalf("a ceiling of %d withheld no record at all; there is nothing here for it to be seen doing", ceiling)
		}
		if ceiling == 3 && len(withheld) != 0 {
			t.Fatalf("the ceiling at the group's own epoch withheld %v, and it is this test's positive control for a ceiling that filters nothing", withheld)
		}
		if page.GetHighWaterRecordId() != ceilingTops[ceiling] {
			t.Fatalf("a fetch authorized under read_key[%d] reported high water %d, want %d — the top of what its own ceiling admits, because that is the number sdk/urmessage reads as ErrFetchOmitted",
				ceiling, page.GetHighWaterRecordId(), ceilingTops[ceiling])
		}
		if !page.GetComplete() {
			t.Fatalf("a fetch authorized under read_key[%d] was handed everything its ceiling admits and told complete=false", ceiling)
		}
	}
}

// THE BEHIND-MEMBER CATCH-UP, END TO END, and it is the one thing that can sink F0.
//
// Ledger item 246: "a commit sealed at epoch E opens E+1, so it passes a ceiling of E, which is
// why catch-up should survive — but a behind-member catch-up was not driven end to end. If a
// member several epochs behind cannot walk forward one epoch per round trip under the ceiling,
// F0 is wrong."
//
// So this is a member holding only `read_key[1]`, walking to the present. Nothing here is told
// the group's epoch and nothing here is handed a key it has not earned: each round's read key is
// the one the PREVIOUS round's commit carried, parsed out of the `record_bytes` the server
// served, exactly as `sdk/urmessage`'s page walk does it.
func TestAMemberSeveralEpochsBehindWalksForwardOneEpochPerRoundTrip(t *testing.T) {
	fixture := newFixture(t)
	threeEpochGroup(t, fixture)

	reached, cursor, epoch, fetches := []uint64{}, uint64(0), uint64(1), 0
	for range 16 {
		request := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: epoch, SinceRecordId: cursor}
		reason, page, err := fixture.fetchFrom(t, request)
		fetches++
		if err != nil {
			t.Fatalf("catch-up at epoch %d from %d: %v", epoch, cursor, err)
		}
		// check 6 resolved a read key for this epoch and check 7 verified a MAC under it. A
		// REASON_REJECTED here is the walk being refused at an epoch it legitimately holds,
		// which is the ceiling cutting a member off by another route
		if reason != protocol.Reason_REASON_OK {
			t.Fatalf("catch-up at epoch %d was answered %v", epoch, reason)
		}
		if !page.GetComplete() {
			t.Fatalf("catch-up at epoch %d answered complete=false with no limit set; complete=false is how sdk/urmessage is told to re-ask from this same cursor, which at this ceiling answers nothing and fails on ErrFetchNoProgress",
				epoch)
		}

		opens := uint64(0)
		for _, record := range page.GetRecords() {
			reached = append(reached, record.GetRecordId())
			parsed, err := message.ParseRecord(record.GetRecordBytes())
			if err != nil {
				t.Fatalf("record %d does not parse: %v", record.GetRecordId(), err)
			}
			if !parsed.Header.IsCommit || parsed.Header.Epoch != epoch {
				continue
			}
			attachment, err := message.ParseServerAttachment(parsed.Header.ServerAttachment)
			if err != nil {
				t.Fatalf("the attachment of commit %d: %v", record.GetRecordId(), err)
			}
			if attachment.Epoch != nil {
				opens = attachment.Epoch.Epoch
			}
		}

		// sdk/urmessage's omission check, run here on every complete page. An absolute high
		// water fails it on every round of an honest walk, which is why the field moved
		if top := page.GetHighWaterRecordId(); len(reached) != 0 && reached[len(reached)-1] < top {
			t.Fatalf("catch-up at epoch %d reached record %d and was told the high water is %d; ErrFetchOmitted is what sdk/urmessage raises on exactly this",
				epoch, reached[len(reached)-1], top)
		}
		cursor = page.GetNextRecordId()
		if opens == 0 {
			break
		}
		if opens != epoch+1 {
			t.Fatalf("the commit at epoch %d opens epoch %d, and this walk advances one epoch per round trip", epoch, opens)
		}
		epoch = opens
	}

	if epoch != 3 {
		t.Fatalf("a member holding read_key[1] walked to epoch %d in %d round trips and the group is at 3; ledger item 246 says F0 is wrong if a behind member cannot walk forward under the ceiling",
			epoch, fetches)
	}
	want := []uint64{}
	for id := uint64(1); id <= 12; id++ {
		want = append(want, id)
	}
	if !slices.Equal(reached, want) {
		t.Fatalf("the walk arrived holding records %v and the group holds %v; a member that arrives short of the present has been cut off by the ceiling, however politely",
			reached, want)
	}
	// THREE ROUND TRIPS FOR THREE EPOCHS. Twelve records and three fetches: the walk is paced
	// by the epoch and not by the record, which is the cost F0 actually charges a behind member
	if fetches != 3 {
		t.Fatalf("the walk from epoch 1 to epoch 3 took %d round trips, want 3 — one per epoch", fetches)
	}
}
