package api

import (
	"context"
	"reflect"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"google.golang.org/protobuf/proto"
)

// CP3a: a record travels.
//
// A sender seals a record, the api layer runs §5.1's checks over it and §6.1's transaction under
// it, and the same bytes come back out of a fetch. Nothing in this file encrypts. `ct_head` and
// `ct_body` are opaque octets to every layer under test — the server never opens them and cannot
// — and the MLS key schedule that produces the real content keys is plan p4 and is absent rather
// than stubbed. What this asserts is what CP3a claims and no more: an authenticated, addressed,
// durable transport for opaque bytes.
//
// **Where this deviates from the task's numbering, and why.** The milestone asks for a record
// allocated `record_id` 1 by a submit that follows a group creation. §6.1's CreateGroup writes
// `message_record{record_id = 1}` for the initial commit and leaves `next_record_id = 2`, so no
// later submit can be given 1 — the founding commit IS record 1, and the first record that
// travels through this layer is therefore the one CreateGroup carries. It is sealed exactly as
// the milestone describes: a RecordHeader, `write_auth` under `message.WriteKey(storageRoot)`,
// and `message.EncodeRecord`. The second sender then submits at its own `stream_index` through
// Submit, and both are fetched back in `record_id` order.
//
// The second sender's record is a wrap, and that is §6.1 rather than a convenience. CreateGroup
// leaves the group at epoch 1 with `epoch_complete = false`, which §6.1 step (2) makes
// readable-but-not-writable for everything except a wrap, a snapshot or the EpochComplete
// marker; the marker then closes the fan-out and the ordinary record at the end of this test is
// what proves the group became writable.
func TestARecordTravelsEndToEnd(t *testing.T) {
	ctx := context.Background()
	fixture := newFixture(t)

	// ── 1 and 2: a group, and a sealed initial commit ────────────────────────────────────
	commit := fixture.seal(t, sealed{
		sender:      senderA,
		epoch:       0,
		streamIndex: 0,
		isCommit:    true,
		class:       message.RetentionPermanent,
		bucket:      message.SizeBucket256,
		head:        []byte("the founding commit's opaque head"),
		body:        []byte("the founding commit's opaque body"),
		attachment:  fixture.epochAttachment(1, 1),
		writeKey:    fixture.writeKey(0),
	})

	// ── 3: submitted through the api layer, accepted, allocated record_id 1 ──────────────
	reason, created, err := fixture.handler.CreateGroup(ctx, fixture.conn, &protocol.CreateGroupRequest{
		GroupId:           fixture.groupId,
		InitialCommit:     commit,
		BootstrapWriteKey: fixture.writeKey(0),
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

	// ── 4: fetched back, and the bytes are the bytes that were sealed ────────────────────
	fetched := fixture.fetch(t)
	if len(fetched.GetRecords()) != 1 {
		t.Fatalf("the fetch answered %d records, want 1", len(fetched.GetRecords()))
	}
	assertTravelled(t, fixture, commit, fetched.GetRecords()[0], 1)

	// ── 5: a second sender, at its own stream_index ──────────────────────────────────────
	//
	// §6.1's epoch publication step 5 in miniature: the wrap set for the epoch the founding
	// commit opened, published by a member that is not the committer.
	wrap := fixture.seal(t, sealed{
		sender:      senderB,
		epoch:       1,
		streamIndex: 40,
		class:       message.RetentionPermanent,
		bucket:      message.SizeBucket256,
		head:        []byte("the epoch-1 snapshot head"),
		body:        []byte("the epoch-1 snapshot body"),
		attachment:  wrapAttachment(1, senderB),
		writeKey:    fixture.writeKey(1),
	})
	results := fixture.submit(t, wrap)
	if results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the second sender's wrap was answered %v, want REASON_OK", results[0].GetReason())
	}
	if results[0].GetRecordId() != 2 {
		t.Fatalf("the second sender's wrap was allocated record_id %d, want 2", results[0].GetRecordId())
	}

	fetched = fixture.fetch(t)
	if len(fetched.GetRecords()) != 2 {
		t.Fatalf("the fetch answered %d records, want 2", len(fetched.GetRecords()))
	}
	assertTravelled(t, fixture, commit, fetched.GetRecords()[0], 1)
	assertTravelled(t, fixture, wrap, fetched.GetRecords()[1], 2)

	// ── the fan-out closes, and the epoch becomes writable ───────────────────────────────
	marker := fixture.seal(t, sealed{
		sender:      senderA,
		epoch:       1,
		streamIndex: 1,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket256,
		head:        []byte("epoch 1 complete"),
		body:        []byte("epoch 1 complete, one wrap"),
		attachment:  completeAttachment(1, 1),
		writeKey:    fixture.writeKey(1),
	})
	if results := fixture.submit(t, marker); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the EpochComplete marker was answered %v, want REASON_OK", results[0].GetReason())
	}

	// an ordinary record, which is what the marker made possible: before it landed §6.1 step (2)
	// answered REASON_EPOCH_INCOMPLETE to exactly this submission
	ordinary := fixture.seal(t, sealed{
		sender:      senderA,
		epoch:       1,
		streamIndex: 2,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket1K,
		head:        []byte("an ordinary record's head"),
		body:        []byte("an ordinary record's body"),
		writeKey:    fixture.writeKey(1),
	})
	results = fixture.submit(t, ordinary)
	if results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the ordinary record was answered %v, want REASON_OK", results[0].GetReason())
	}
	if results[0].GetRecordId() != 4 {
		t.Fatalf("the ordinary record was allocated record_id %d, want 4", results[0].GetRecordId())
	}

	fetched = fixture.fetch(t)
	if len(fetched.GetRecords()) != 4 {
		t.Fatalf("the fetch answered %d records, want 4", len(fetched.GetRecords()))
	}
	for index, want := range []*protocol.Record{commit, wrap, marker, ordinary} {
		assertTravelled(t, fixture, want, fetched.GetRecords()[index], uint64(index+1))
	}

	// ── 6: a corrupted write_auth is refused, and allocates nothing ──────────────────────
	forged := fixture.seal(t, sealed{
		sender:      senderA,
		epoch:       1,
		streamIndex: 3,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket256,
		head:        []byte("a head nobody will store"),
		body:        []byte("a body nobody will store"),
		writeKey:    fixture.writeKey(1),
	})
	// the tag is the record's last 32 octets; one flipped bit in it is the whole forgery
	forged.RecordBytes[len(forged.RecordBytes)-1] ^= 0x01

	results = fixture.submit(t, forged)
	if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a forged write_auth was answered %v, want REASON_REJECTED", results[0].GetReason())
	}
	if results[0].GetRecordId() != 0 {
		t.Fatalf("a forged write_auth was allocated record_id %d, want none", results[0].GetRecordId())
	}

	after := fixture.fetch(t)
	if len(after.GetRecords()) != 4 {
		t.Fatalf("after the forgery the group holds %d records, want the same 4", len(after.GetRecords()))
	}
	if after.GetHighWaterRecordId() != 4 {
		t.Fatalf("after the forgery the high water is %d, want 4", after.GetHighWaterRecordId())
	}
	// the id the forgery would have consumed is still the next one to be handed out, which is
	// the property §6.1 step (3b) and decision B4 are both about: the sequence is gapless
	next := fixture.seal(t, sealed{
		sender:      senderA,
		epoch:       1,
		streamIndex: 4,
		class:       message.RetentionDurable,
		bucket:      message.SizeBucket256,
		head:        []byte("the record after the forgery"),
		body:        []byte("the record after the forgery"),
		writeKey:    fixture.writeKey(1),
	})
	results = fixture.submit(t, next)
	if results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the record after the forgery was answered %v, want REASON_OK", results[0].GetReason())
	}
	if results[0].GetRecordId() != 5 {
		t.Fatalf("the record after the forgery was allocated record_id %d, want 5 — the forgery allocated one", results[0].GetRecordId())
	}
}

// What a fetched record has to be for the record to have travelled: the same header, byte for
// byte the same two ciphertexts, the server-assigned id, and a `write_auth` of zero.
func assertTravelled(t *testing.T, fixture *fixture, sent *protocol.Record, back *protocol.Record, recordId uint64) {
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
	if !reflect.DeepEqual(sealed.CtHead, returned.CtHead) {
		t.Fatalf("ct_head came back %d octets, sealed %d, and not the same octets", len(returned.CtHead), len(sealed.CtHead))
	}
	if !reflect.DeepEqual(sealed.CtBody, returned.CtBody) {
		t.Fatalf("ct_body came back %d octets, sealed %d, and not the same octets", len(returned.CtBody), len(sealed.CtBody))
	}
	// §2.4: write_auth is zero on read. It is a MAC over the submitting connection's nonce, so
	// there is nothing to reconstruct it from and nobody who could verify it, and a client that
	// read the zero as evidence would be trusting the server to vouch for content.
	if returned.WriteAuth != ([32]byte{}) {
		t.Fatalf("write_auth came back non-zero on a read")
	}
	// and the projections the server sends are the ones it would verify
	sentProjection := withoutServerFields(sent)
	backProjection := withoutServerFields(back)
	if !projectionsAgree(sentProjection, backProjection) {
		t.Fatalf("the projections came back different:\n sent %+v\n back %+v", sentProjection, backProjection)
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
