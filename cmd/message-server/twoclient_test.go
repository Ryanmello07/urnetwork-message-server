package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/harness"
	"github.com/urnetwork/message-server/peer"
	"google.golang.org/protobuf/proto"
)

// CP3c: a record travels over the wire.
//
// The previous milestone proved a record survives submit and fetch through the api layer, and
// the one before it proved the same journey through peer's dispatch. What is new here is that
// every step is asserted to have *crossed a transport*: two real connect clients in one process,
// §4.2 frames on a route between them, and the frames counted at both ends. A test that
// accidentally called api directly would see the same record with the same bytes come back —
// that is exactly why [stack.assertCarried] exists, and why it is the assertion this file turns
// on rather than a decoration on the end of it.
//
// Nothing here encrypts. `ct_head` and `ct_body` are opaque octets to every layer under test —
// the server never opens them and cannot — and the MLS key schedule that produces real content
// keys is plan p4 and is absent rather than stubbed. What this asserts is authenticated,
// addressed, durable transport for opaque bytes, and no more than that.
func TestARecordTravelsOverTwoConnectClientsAndComesBack(t *testing.T) {
	stack := newStack(t)
	sender := handleOf(0xA0)
	journey := stack.carried()

	// ── the connection: a server_nonce this client did not choose ────────────────────────
	//
	// It cannot have chosen it: HelloRequest carries no nonce field, and §5.1 check 2 reads the
	// value from the connection and never from the request. What is observable here is the
	// width and that it is not the zero value a server with no CSPRNG would answer; that it is
	// *this connection's* rather than a constant is what
	// TestARecordSealedAgainstANonceTheServerDidNotIssueIsRefused asserts, where a second
	// connection makes the difference visible.
	hello := stack.hello(t)
	nonce := hello.GetServerNonce()
	if len(nonce) != peer.ServerNonceBytes {
		t.Fatalf("Hello issued a %d octet server_nonce, want §5.7's %d", len(nonce), peer.ServerNonceBytes)
	}
	if bytes.Equal(nonce, make([]byte, peer.ServerNonceBytes)) {
		t.Fatal("Hello issued a server_nonce of zeroes, which is a nonce every other connection also has")
	}
	if got := hello.GetCapabilities().GetMaxRequestBytes(); got != peer.DefaultMaxRequestBytes {
		t.Fatalf("Hello advertised max_request_bytes %d, want the number §5.1 check 1 enforces", got)
	}

	// ── the founding commit, sealed against the nonce the server issued ──────────────────
	//
	// §4.3.2: self-certified under `bootstrap_write_key`, which is the epoch-0 write key, and
	// MAC'd over this connection's nonce like every record after it.
	commit := stack.seal(t, harness.Sealed{
		Sender:     sender,
		IsCommit:   true,
		Class:      message.RetentionPermanent,
		Bucket:     message.SizeBucket256,
		Head:       []byte("the founding commit's opaque head"),
		Body:       []byte("the founding commit's opaque body"),
		Attachment: epochAttachment(1, 1),
		Nonce:      nonce,
	})
	reason, created, err := stack.client.CreateGroup(stack.ctx, &protocol.CreateGroupRequest{
		GroupId:           stack.groupId,
		InitialCommit:     commit,
		BootstrapWriteKey: writeKeyFor(0),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the founding commit was answered %v, want REASON_OK", reason)
	}
	if created.GetRecordId() != 1 {
		t.Fatalf("the founding commit was allocated record_id %d, want 1", created.GetRecordId())
	}
	if created.GetCurrentEpoch() != 1 {
		t.Fatalf("the group opened at epoch %d, want 1", created.GetCurrentEpoch())
	}

	// ── §6.1's epoch publication: the wrap set, then the marker that closes it ───────────
	stack.submitAccepted(t, "the epoch-1 wrap", stack.seal(t, harness.Sealed{
		Sender:      sender,
		Epoch:       1,
		StreamIndex: 1,
		Class:       message.RetentionPermanent,
		Bucket:      message.SizeBucket256,
		Head:        []byte("the epoch-1 snapshot head"),
		Body:        []byte("the epoch-1 snapshot body"),
		Attachment:  wrapAttachment(1, sender),
	}))
	stack.submitAccepted(t, "the epoch-1 marker", stack.seal(t, harness.Sealed{
		Sender:      sender,
		Epoch:       1,
		StreamIndex: 2,
		Class:       message.RetentionDurable,
		Bucket:      message.SizeBucket256,
		Head:        []byte("epoch 1 complete"),
		Body:        []byte("epoch 1 complete, one wrap"),
		Attachment:  completeAttachment(1, 1),
	}))

	// ── an ordinary record, submitted and fetched back ───────────────────────────────────
	//
	// The leg is watched on its own, because it is the one the milestone is about: these two
	// requests are the record going out and coming back, and the frames they took are counted
	// at both ends of the transport.
	carrying := stack.carried()
	ordinary := stack.seal(t, harness.Sealed{
		Sender:      sender,
		Epoch:       1,
		StreamIndex: 3,
		Class:       message.RetentionDurable,
		Bucket:      message.SizeBucket1K,
		Head:        []byte("an ordinary record's opaque head"),
		Body:        []byte("an ordinary record's opaque body"),
		// §5.1's advisory upper bound, non-zero on purpose: a header field that is zero on both
		// sides of a round trip is a field this test would report as having travelled without
		// having carried anything
		ExpireAt: 1798761600000,
	})
	result := stack.submitAccepted(t, "an ordinary record", ordinary)
	if result.GetRecordId() != 4 {
		t.Fatalf("the ordinary record was allocated record_id %d, want 4", result.GetRecordId())
	}

	fetched := stack.fetch(t)
	if len(fetched.GetRecords()) != 4 {
		t.Fatalf("the fetch answered %d records for a group with four in it", len(fetched.GetRecords()))
	}
	assertTravelled(t, commit, fetched.GetRecords()[0], 1)
	assertTravelled(t, ordinary, fetched.GetRecords()[3], 4)

	stack.assertCarried(t, carrying, 2, "the ordinary record's submit and the fetch that brought it back")
	// hello, create_group, the wrap, the marker, the ordinary record, the fetch
	stack.assertCarried(t, journey, 6, "the whole journey")
}

// §4.6's fragmentation, carrying one record end to end in both directions.
//
// Only a real transport can show this. The size is taken from the budget §4.3.1 advertised
// rather than from a constant here, because the two numbers a client has to reconcile — the
// request bound it is held to and the frame size it must cut to — are both the server's, and a
// test that hardcoded either would keep passing after the server changed it.
func TestARecordTooLargeForOneFrameTravelsInSpecB46sFragments(t *testing.T) {
	stack := newStack(t)
	stack.openGroup(t)

	budget := int(stack.client.Capabilities().GetMaxRequestBytes())
	if budget == 0 {
		t.Fatal("Hello advertised no max_request_bytes, so there is no budget to pick a size out of")
	}
	// a quarter of the advertised budget: comfortably inside §5.1 check 1's bound and inside
	// check 3's head cap, and many times §4.6's part size, so the request cannot reach the
	// server in one frame
	headBytes := budget / 4
	if headBytes <= peer.MaxFragmentPartBytes {
		t.Fatalf("a quarter of the advertised budget is %d octets, which fits in §4.6's %d octet part; this test would fragment nothing",
			headBytes, peer.MaxFragmentPartBytes)
	}
	head := make([]byte, headBytes)
	for index := range head {
		head[index] = byte(index * 7)
	}
	// what the client had to cut the request into, from the payload it is carrying: a client that
	// stopped fragmenting sends one frame, and one frame is below this
	wantFrames := uint64(headBytes / peer.MaxFragmentPartBytes)

	outbound := stack.carried()
	large := stack.seal(t, harness.Sealed{
		Sender:      handleOf(0xC0),
		Epoch:       1,
		StreamIndex: 0,
		Class:       message.RetentionDurable,
		Bucket:      message.SizeBucket1K,
		Head:        head,
		Body:        []byte("a body no larger than any other"),
	})
	result := stack.submitAccepted(t, "a record too large for one frame", large)
	submitted := stack.assertCarried(t, outbound, 1, "the submit of a record too large for one frame")
	if submitted.client.RequestFrames < wantFrames {
		t.Fatalf("a %d octet head reached the server in %d frames; §4.6 cuts %d octet parts, so it takes at least %d",
			headBytes, submitted.client.RequestFrames, peer.MaxFragmentPartBytes, wantFrames)
	}

	// and back the other way, where the server is the one doing the cutting
	inbound := stack.carried()
	fetched := stack.fetch(t)
	returned := stack.assertCarried(t, inbound, 1, "the fetch that brought the large record back")
	if returned.client.ResponseFrames < wantFrames {
		t.Fatalf("a response carrying a %d octet head arrived in %d frames, and §4.6's parts make that at least %d",
			headBytes, returned.client.ResponseFrames, wantFrames)
	}

	back := recordWithId(t, fetched, result.GetRecordId())
	assertTravelled(t, large, back, result.GetRecordId())
}

// A record sealed against a nonce this server did not issue is refused, and the same record
// re-MAC'd against the nonce it did issue is accepted.
//
// This is the cross-connection replay defence of spec A §5.7 working through the whole stack:
// peer mints the nonce at Hello and destroys the previous one, api reads it from the connection
// and never from the request, and connect/message verifies the MAC over it. It is the property
// most worth having an integration test for, because every layer holds one third of it.
//
// Three steps, and the third is not optional. Without the control, "refused" is equally
// consistent with a server that simply stopped accepting this record for some other reason —
// which is how a replay test passes while proving nothing.
func TestARecordSealedAgainstANonceTheServerDidNotIssueIsRefused(t *testing.T) {
	stack := newStack(t)
	stack.openGroup(t)
	issued := stack.client.Nonce()
	allocated := stack.nextRecordId(t)

	// one record, and the only thing that changes between the three attempts is the nonce its
	// MAC was computed over
	spec := harness.Sealed{
		Sender:      handleOf(0xD0),
		Epoch:       1,
		StreamIndex: 0,
		Class:       message.RetentionDurable,
		Bucket:      message.SizeBucket256,
		Head:        []byte("a head whose MAC is the only thing under test"),
		Body:        []byte("a body whose MAC is the only thing under test"),
	}

	// ── a nonce the server never issued to anybody ───────────────────────────────────────
	invented := make([]byte, peer.ServerNonceBytes)
	if _, err := rand.Read(invented); err != nil {
		t.Fatalf("reading a nonce for the attacker to seal against: %v", err)
	}
	if bytes.Equal(invented, issued) {
		t.Fatal("the invented nonce is the issued one, which would make this test assert nothing")
	}
	invented32 := spec
	invented32.Nonce = invented
	watching := stack.carried()
	results := stack.submit(t, stack.seal(t, invented32))
	if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a record sealed against a nonce the server never issued was answered %v, want REASON_REJECTED",
			results[0].GetReason())
	}
	if results[0].GetRecordId() != 0 {
		t.Fatalf("a record sealed against an invented nonce was allocated record_id %d, want none", results[0].GetRecordId())
	}
	stack.assertCarried(t, watching, 1, "the submit sealed against an invented nonce")
	if now := stack.nextRecordId(t); now != allocated {
		t.Fatalf("a refused record moved next_record_id from %d to %d", allocated, now)
	}

	// ── the previous connection's nonce, after this client said Hello again ──────────────
	//
	// §4.3.1 opens a connection and destroys the one before it, so this is the record that was
	// queued in spec A §5.7's outbox and sent after a reconnect without being re-MAC'd.
	rotated := stack.hello(t).GetServerNonce()
	if bytes.Equal(rotated, issued) {
		t.Fatal("two connections of one client_id were issued the same server_nonce, so a record sealed on the first still verifies on the second")
	}
	stale := spec
	stale.Nonce = issued
	watching = stack.carried()
	results = stack.submit(t, stack.seal(t, stale))
	if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a record sealed against the previous connection's nonce was answered %v, want REASON_REJECTED",
			results[0].GetReason())
	}
	if results[0].GetRecordId() != 0 {
		t.Fatalf("a replayed record was allocated record_id %d, want none", results[0].GetRecordId())
	}
	stack.assertCarried(t, watching, 1, "the submit sealed against the previous connection's nonce")
	if now := stack.nextRecordId(t); now != allocated {
		t.Fatalf("a replayed record moved next_record_id from %d to %d", allocated, now)
	}

	// ── the control: the same record, re-MAC'd against the nonce this connection was issued ─
	watching = stack.carried()
	result := stack.submitAccepted(t, "the same record re-MAC'd against the new connection's nonce", stack.seal(t, spec))
	if result.GetRecordId() != allocated {
		t.Fatalf("the accepted record was allocated record_id %d, want %d — the two refusals allocated one",
			result.GetRecordId(), allocated)
	}
	stack.assertCarried(t, watching, 1, "the submit re-MAC'd against the current nonce")
}

// Every response matched the request it answered, under load, with nothing to correlate by but
// `request_id`.
//
// Two requests in flight on one connection can be answered in either order — peer's workers are
// a pool and the response is sent by whichever finishes first — so `request_id` is the only
// thing a client can correlate by, and a dispatcher that dropped or reused it would turn
// concurrency into silently wrong answers rather than into a visible failure.
//
// Correlation is checked twice over, because the cheap half is not enough. That a response
// carrying the right `request_id` arrived is the harness's own bookkeeping; what makes the
// answer *this request's* answer is that the record the server says it stored under the id it
// reported is the record this request sent — sender handle, head, body and header, compared
// against the one this goroutine sealed. A dispatcher that swapped two in-flight responses
// passes the first check and fails the second.
func TestConcurrentSubmitsAreEachAnsweredUnderTheirOwnRequestId(t *testing.T) {
	// enough that one wrong pairing is not a coin toss, and every one of them a different
	// sender_handle: §6.1 step (3) is monotonic per (group_id, sender_handle), so one sender
	// submitting concurrently would have the losers refused for the ordering rather than for
	// anything this test is about
	const senders = 32

	stack := newStack(t)
	stack.openGroup(t)

	records := make([]*protocol.Record, senders)
	for index := range records {
		head := fmt.Appendf(nil, "the opaque head of concurrent sender %02d", index)
		records[index] = stack.seal(t, harness.Sealed{
			Sender:      handleOf(byte(0x40 + index)),
			Epoch:       1,
			StreamIndex: 0,
			Class:       message.RetentionDurable,
			Bucket:      message.SizeBucket256,
			Head:        head,
			Body:        head,
		})
	}

	// sealed before the burst starts, so what overlaps is the requests rather than the MACs
	results := make([]*protocol.SubmitResult, senders)
	failures := make([]error, senders)
	begin := make(chan struct{})
	sending := sync.WaitGroup{}
	watching := stack.carried()
	for index := range senders {
		sending.Add(1)
		go func() {
			defer sending.Done()
			// every goroutine parked on one channel, so the sends overlap rather than queue up
			// behind each other's setup
			<-begin
			reason, response, err := stack.client.Submit(stack.ctx, &protocol.SubmitRequest{
				GroupId: stack.groupId,
				Records: []*protocol.Record{records[index]},
			})
			switch {
			case err != nil:
				failures[index] = err
			case reason != protocol.Reason_REASON_OK:
				failures[index] = fmt.Errorf("the submit envelope was answered %v", reason)
			case len(response.GetResults()) != 1:
				failures[index] = fmt.Errorf("%d results came back for one record", len(response.GetResults()))
			default:
				results[index] = response.GetResults()[0]
			}
		}()
	}
	close(begin)
	sending.Wait()

	for index, failure := range failures {
		if failure != nil {
			t.Fatalf("concurrent sender %d: %v", index, failure)
		}
	}

	fetched := stack.fetch(t)
	stack.assertCarried(t, watching, senders+1, "the concurrent submits and the fetch that read them back")

	answered := map[uint64]int{}
	for index, result := range results {
		if result.GetReason() != protocol.Reason_REASON_OK {
			t.Fatalf("concurrent sender %d was answered %v", index, result.GetReason())
		}
		recordId := result.GetRecordId()
		if recordId == 0 {
			t.Fatalf("concurrent sender %d was accepted and allocated no record_id", index)
		}
		if previous, taken := answered[recordId]; taken {
			t.Fatalf("senders %d and %d were both answered record_id %d, so one of them was handed the other's answer",
				previous, index, recordId)
		}
		answered[recordId] = index
		// the answer is this request's answer: the record stored under the id it reported is the
		// record this goroutine sealed
		assertTravelled(t, records[index], recordWithId(t, fetched, recordId), recordId)
	}
}

// A record whose `write_auth` does not verify is refused, and allocates nothing.
//
// "Allocated nothing" is not observable from the refusal: a server that took an id and rolled the
// row back answers a client identically and answers a fetch identically. §3.2's `next_record_id`
// is what tells the two apart, the store's own contract exposes it, and the record after the
// forgery is the second half of the same statement — §6.1 step (3b) and decision B4 make the
// sequence gapless, so a forgery that consumed an id would show up as a gap the next record
// falls into.
func TestARecordWhoseWriteAuthDoesNotVerifyIsRefusedAndAllocatesNothing(t *testing.T) {
	stack := newStack(t)
	stack.openGroup(t)
	allocated := stack.nextRecordId(t)

	spec := harness.Sealed{
		Sender:      handleOf(0xE0),
		Epoch:       1,
		StreamIndex: 0,
		Class:       message.RetentionDurable,
		Bucket:      message.SizeBucket256,
		Head:        []byte("a head nobody will store"),
		Body:        []byte("a body nobody will store"),
	}
	forged := stack.seal(t, spec)
	// the tag is the record's last 32 octets; one flipped bit in it is the whole forgery, and
	// every other octet of the record is the one the control below submits
	forged.RecordBytes[len(forged.RecordBytes)-1] ^= 0x01

	watching := stack.carried()
	results := stack.submit(t, forged)
	if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a forged write_auth was answered %v, want REASON_REJECTED", results[0].GetReason())
	}
	if results[0].GetRecordId() != 0 {
		t.Fatalf("a forged write_auth was allocated record_id %d, want none", results[0].GetRecordId())
	}
	stack.assertCarried(t, watching, 1, "the forged record's submit")

	if now := stack.nextRecordId(t); now != allocated {
		t.Fatalf("a forged record moved next_record_id from %d to %d, so the refusal allocated one", allocated, now)
	}
	before := stack.fetch(t)
	if uint64(len(before.GetRecords()))+1 != allocated {
		t.Fatalf("the group holds %d records and next_record_id is %d; the forgery is in the store", len(before.GetRecords()), allocated)
	}

	// the id the forgery would have consumed is still the next one handed out
	result := stack.submitAccepted(t, "the record after the forgery", stack.seal(t, spec))
	if result.GetRecordId() != allocated {
		t.Fatalf("the record after the forgery was allocated record_id %d, want %d — the forgery allocated one",
			result.GetRecordId(), allocated)
	}
}

// ── what "the record travelled" means, in one place ──────────────────────────────────────

// What a fetched record has to be for the record to have travelled: the same header field for
// field, byte-identical ciphertexts, the server-assigned id, a `write_auth` of zero, and the
// projection the server rebuilt agreeing with the one the client sent.
func assertTravelled(t *testing.T, sent *protocol.Record, back *protocol.Record, recordId uint64) {
	t.Helper()
	if back.GetRecordId() != recordId {
		t.Fatalf("the record came back as record_id %d, want %d", back.GetRecordId(), recordId)
	}
	sealed, err := message.ParseRecord(sent.GetRecordBytes())
	if err != nil {
		t.Fatalf("the record this test sealed does not parse: %v", err)
	}
	returned, err := message.ParseRecord(back.GetRecordBytes())
	if err != nil {
		t.Fatalf("the record the server rebuilt does not parse: %v", err)
	}
	if !reflect.DeepEqual(sealed.Header, returned.Header) {
		t.Fatalf("the header came back different:\n sealed   %+v\n returned %+v", sealed.Header, returned.Header)
	}
	if !bytes.Equal(sealed.CtHead, returned.CtHead) {
		t.Fatalf("ct_head came back %d octets against the %d that were sealed, and not the same octets",
			len(returned.CtHead), len(sealed.CtHead))
	}
	if !bytes.Equal(sealed.CtBody, returned.CtBody) {
		t.Fatalf("ct_body came back %d octets against the %d that were sealed, and not the same octets",
			len(returned.CtBody), len(sealed.CtBody))
	}
	// §2.4: write_auth is zero on read. It is a MAC over the submitting connection's nonce, so
	// there is nothing to reconstruct it from and nobody who could verify it, and a client that
	// read the zero as evidence would be trusting the server to vouch for content.
	if returned.WriteAuth != ([32]byte{}) {
		t.Fatal("write_auth came back non-zero on a read; the server cannot reproduce one and must not appear to")
	}
	if !proto.Equal(withoutServerFields(sent), withoutServerFields(back)) {
		t.Fatalf("the projections came back different:\n sent %+v\n back %+v", withoutServerFields(sent), withoutServerFields(back))
	}
}

// One record's projection fields alone: the two the server assigns are dropped, because
// `record_bytes` is what the projection is of and `record_id` is not authenticated and is unset
// on the way in.
func withoutServerFields(record *protocol.Record) *protocol.Record {
	stripped, _ := proto.Clone(record).(*protocol.Record)
	stripped.RecordBytes = nil
	stripped.RecordId = 0
	return stripped
}

// The record a fetch answered under this id.
func recordWithId(t *testing.T, fetched *protocol.FetchResponse, recordId uint64) *protocol.Record {
	t.Helper()
	for _, record := range fetched.GetRecords() {
		if record.GetRecordId() == recordId {
			return record
		}
	}
	t.Fatalf("the fetch answered %d records and none of them is record_id %d", len(fetched.GetRecords()), recordId)
	return nil
}
