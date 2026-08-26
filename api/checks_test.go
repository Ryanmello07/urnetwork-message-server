package api

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ── the check order itself ───────────────────────────────────────────────────────────────

// Every check §5.1 numbers is either run here or declared unrun, and no check is both.
//
// The class comes out of the spec document rather than out of a list in this file, because a
// list is the thing that goes stale silently: a tenth check added to §5.1 would be a check this
// package neither runs nor mentions, and every test in this file would still be green. What
// makes a skipped check visible is that the set has an outside source.
func TestEveryCheckOfSpecB51IsRunOrDeclared(t *testing.T) {
	specified := checkNumbersOfSpecB51(t)
	t.Logf("§5.1 numbers %d checks: %v", len(specified), specified)

	handler := newFixture(t).handler
	run := []int{}
	for _, stage := range handler.submitStages() {
		run = append(run, stage.number)
	}
	declared := []int{}
	for _, notBuilt := range handler.NotBuilt() {
		if notBuilt.Check != 0 {
			declared = append(declared, notBuilt.Check)
		}
	}

	for _, number := range specified {
		inRun := slices.Contains(run, number)
		inDeclared := slices.Contains(declared, number)
		switch {
		case inRun && inDeclared:
			t.Fatalf("§5.1 check %d is both run and declared unrun, so one of the two is a lie", number)
		case !inRun && !inDeclared:
			t.Fatalf("§5.1 check %d is neither run (%v) nor declared unrun (%v); a skipped check that looks like a passed check is how a pipeline ships with a hole", number, run, declared)
		}
	}
	for _, number := range append(append([]int{}, run...), declared...) {
		if !slices.Contains(specified, number) {
			t.Fatalf("this package claims a check %d that §5.1 does not number: %v", number, specified)
		}
	}
}

// The pipeline runs §5.1's checks in §5.1's order.
//
// "Order matters for denial of service, not just correctness. Nothing that costs a database read
// happens before something that costs a hash." An ordering that only the statements know is an
// ordering the next refactor reorders for free, so the numbers are a value and this reads them.
func TestTheSubmitPipelineRunsSpecB51sChecksInOrder(t *testing.T) {
	specified := checkNumbersOfSpecB51(t)
	stages := newFixture(t).handler.submitStages()
	if len(stages) == 0 {
		t.Fatal("the submit pipeline has no stages at all")
	}
	previous := 0
	for _, stage := range stages {
		if stage.number <= previous {
			t.Fatalf("check %d (%s) runs after check %d; §5.1's order is normative", stage.number, stage.name, previous)
		}
		if !slices.Contains(specified, stage.number) {
			t.Fatalf("check %d (%s) is not a check §5.1 numbers", stage.number, stage.name)
		}
		previous = stage.number
	}
	// the transaction is last, and it is the only stage that may write anything
	if stages[len(stages)-1].number != 9 {
		t.Fatalf("the pipeline ends at check %d; §5.1 check 9 is 'only now: open the transaction'", stages[len(stages)-1].number)
	}
}

// Steps 1 through 8 are lock-free and touch the database at most once, only for a group that
// actually exists.
//
// This is the property §5.1's whole order exists to create, stated as §5.1 states it: "An
// attacker without a write_key cannot force a single row lock, a single index write, or a single
// WAL byte." A record refused by the shape check or by the filter reaches the store zero times.
func TestNothingCostingADatabaseReadHappensBeforeTheChecksThatCostAHash(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store
	fixture.createOpenGroup(t)

	record := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 9,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})

	// refused by check 3: the projection disagrees with the parse
	broken, _ := proto.Clone(record).(*protocol.Record)
	broken.Epoch = 7
	counted.reset()
	if results := fixture.submit(t, broken); results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a projection that disagrees with the parse was answered %v", results[0].GetReason())
	}
	if counted.reads() != 0 {
		t.Fatalf("a record refused by check 3 cost %d store calls: %s", counted.reads(), counted)
	}

	// refused by check 5: the group is not in the filter, and no database read may happen at all
	elsewhere := groupId(0x77)
	stranger := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 9, groupId: elsewhere,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})
	counted.reset()
	if results := fixture.submitTo(t, elsewhere, stranger); results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a submission to an unknown group was answered %v", results[0].GetReason())
	}
	if counted.reads() != 0 {
		t.Fatalf("a submission to an unknown group cost %d store calls: %s", counted.reads(), counted)
	}

	// and a record whose write_auth is forged costs exactly the one key lookup check 6 pays for,
	// and never the transaction
	forged, _ := proto.Clone(record).(*protocol.Record)
	forged.RecordBytes = append([]byte{}, record.GetRecordBytes()...)
	forged.RecordBytes[len(forged.RecordBytes)-1] ^= 0x01
	counted.reset()
	if results := fixture.submit(t, forged); results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a forged write_auth was answered %v", results[0].GetReason())
	}
	if counted.submit != 0 || counted.createGroup != 0 {
		t.Fatalf("a forged write_auth reached the transaction: %s", counted)
	}
	if counted.epochKeys != 1 {
		t.Fatalf("a forged write_auth cost %d epoch key lookups, want exactly the one check 6 pays for", counted.epochKeys)
	}
}

// ── §5.1 check 3 ─────────────────────────────────────────────────────────────────────────

// Every projection field of the request's Record must equal the corresponding field of
// ParseRecord(record_bytes), and any difference is REASON_REJECTED.
//
// The field set is the descriptor's, walked, and not a list written here: §4.3.3's projection
// block is eleven fields today and the whole point of check 3 is that the server indexes nothing
// it has not verified, so a twelfth field added tomorrow has to arrive already covered. A
// mutator that does not know how to change a field's kind stops this test rather than skipping
// the field, because a skipped field is a field this test would report as covered.
func TestEveryProjectionFieldIsCheckedAgainstTheParse(t *testing.T) {
	fixture := newFixture(t)
	fixture.createOpenGroup(t)
	before := len(fixture.fetch(t).GetRecords())

	fields := (&protocol.Record{}).ProtoReflect().Descriptor().Fields()
	covered := 0
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		switch field.Name() {
		case "record_bytes":
			// what the projections are a projection of
			continue
		case "record_id":
			// server-assigned, never authenticated, and §4.3.3 says it is ignored on submit
			continue
		}
		covered++

		record := fixture.seal(t, sealed{
			sender: senderA, epoch: 1, streamIndex: uint64(100 + index),
			class: message.RetentionDurable, bucket: message.SizeBucket256,
			head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
		})
		mutateProjection(t, record, field)

		results := fixture.submit(t, record)
		if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("Record.%s disagreed with the parse and was answered %v, want REASON_REJECTED", field.Name(), results[0].GetReason())
		}
		if results[0].GetRecordId() != 0 {
			t.Fatalf("Record.%s disagreed with the parse and was allocated record_id %d", field.Name(), results[0].GetRecordId())
		}
	}
	if covered < 11 {
		t.Fatalf("this test mutated %d projection fields; §4.3.3 declares eleven, so the descriptor walk has lost some", covered)
	}
	if after := len(fixture.fetch(t).GetRecords()); after != before {
		t.Fatalf("the group holds %d records after %d refused submissions, and held %d before", after, covered, before)
	}
}

// On submit, `octet_length(ct_body)` is EXACTLY the rung's length. Not at most it.
//
// message.ParseRecord is deliberately more permissive — it accepts an absent body, because it
// also runs on the read path where §2.4 has the server rebuild a record with `ct_body` nil for an
// erased body or a heads_only fetch — so this equality is the server's own and there is nothing
// else in the process that would refuse a bodyless submission.
func TestASubmittedBodyIsExactlyItsRungAndNotMerelyWithinIt(t *testing.T) {
	fixture := newFixture(t)
	fixture.createOpenGroup(t)
	before := len(fixture.fetch(t).GetRecords())

	bodyless := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 20,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head with no body under it"), emptyBody: true,
		writeKey: fixture.writeKey(1),
	})
	// the record is well formed as far as the record layer is concerned, which is the whole
	// reason this check has to exist here
	if _, err := message.ParseRecord(bodyless.GetRecordBytes()); err != nil {
		t.Fatalf("the record layer refused the bodyless record itself (%v), so this test is not measuring the server's own equality", err)
	}
	results := fixture.submit(t, bodyless)
	if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a ct_body of 0 octets on a rung of %d was answered %v, want REASON_REJECTED",
			message.SizeBucketCtBodyBytes(message.SizeBucket256), results[0].GetReason())
	}
	if after := len(fixture.fetch(t).GetRecords()); after != before {
		t.Fatalf("a bodyless record was stored: the group holds %d records and held %d", after, before)
	}
}

// ── §4.5's merge ─────────────────────────────────────────────────────────────────────────

// REASON_REJECTED merges "unknown group", "write_auth did not verify" and "epoch key unknown",
// and the merge is a property of the response rather than of the code path.
//
// Distinguishing them turns submit into an existence oracle for `group_id`: a party holding no
// write key could enumerate ids and learn which exist. §4.5 names the three things that must
// match — the same code, the same response size, and the same timing envelope — and this asserts
// all three, on the marshaled bytes rather than on the fields, because a field added to
// SubmitResult on one path only is exactly the helpful error message this decays into.
func TestTheThreeCausesOfRejectedAreIndistinguishableInTheResponse(t *testing.T) {
	fixture := newFixtureWith(t, Config{RejectFloor: 25 * time.Millisecond})
	fixture.createOpenGroup(t)

	// (1) a group that does not exist
	elsewhere := groupId(0x99)
	unknownGroup := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 30, groupId: elsewhere,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})

	// (2) an epoch this group never opened, so no key is installed for it
	unknownEpoch := fixture.seal(t, sealed{
		sender: senderA, epoch: 9, streamIndex: 31,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(9),
	})

	// (3) a write_auth that does not verify
	forged := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 32,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})
	forged.RecordBytes[len(forged.RecordBytes)-1] ^= 0x01

	answers := map[string][]byte{}
	pads := map[string][]time.Duration{}
	for _, refusal := range []struct {
		name    string
		groupId []byte
		record  *protocol.Record
	}{
		{"an unknown group", elsewhere, unknownGroup},
		{"an unknown epoch key", fixture.groupId, unknownEpoch},
		{"a write_auth that did not verify", fixture.groupId, forged},
	} {
		fixture.sleeps = nil
		reason, response, err := fixture.handler.Submit(context.Background(), fixture.conn, &protocol.SubmitRequest{
			GroupId: refusal.groupId,
			Records: []*protocol.Record{refusal.record},
		})
		if err != nil {
			t.Fatalf("%s: %v", refusal.name, err)
		}
		if reason != protocol.Reason_REASON_OK {
			t.Fatalf("%s answered on the envelope with %v", refusal.name, reason)
		}
		if response.GetResults()[0].GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("%s was answered %v, want REASON_REJECTED", refusal.name, response.GetResults()[0].GetReason())
		}
		marshaled, err := proto.MarshalOptions{Deterministic: true}.Marshal(response)
		if err != nil {
			t.Fatalf("%s: marshaling the response: %v", refusal.name, err)
		}
		answers[refusal.name] = marshaled
		pads[refusal.name] = append([]time.Duration{}, fixture.sleeps...)
	}

	var first string
	for name := range answers {
		if first == "" || name < first {
			first = name
		}
	}
	for name, marshaled := range answers {
		if len(marshaled) != len(answers[first]) {
			t.Fatalf("%q answers %d octets and %q answers %d; §4.5 requires the same response size",
				name, len(marshaled), first, len(answers[first]))
		}
		if string(marshaled) != string(answers[first]) {
			t.Fatalf("%q and %q answer different bytes:\n %x\n %x", name, first, marshaled, answers[first])
		}
		if !slices.Equal(pads[name], pads[first]) {
			t.Fatalf("%q padded %v and %q padded %v; §4.5 requires the same timing envelope",
				name, pads[name], first, pads[first])
		}
	}
	if len(pads[first]) != 1 {
		t.Fatalf("a refusal padded %d times, want exactly one pad to the floor", len(pads[first]))
	}
}

// A refusal allocates nothing, whichever check refused it.
//
// §6.1 step (3b) makes it normative for the batch — "any rejection rolls the WHOLE batch back
// with zero rows written" — and decision B4 makes it visible: `record_id` is per-group and
// gapless, so an id consumed by a record that was never stored is a hole §12.2 C-4 instructs
// clients to treat as a fault.
func TestARefusedSubmitAllocatesNothing(t *testing.T) {
	fixture := newFixture(t)
	fixture.createOpenGroup(t)
	before := fixture.fetch(t)
	high := before.GetHighWaterRecordId()

	refusals := []*protocol.Record{}

	broken := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 50,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})
	broken.StreamIndex = 51 // check 3
	refusals = append(refusals, broken)

	staleEpoch := fixture.seal(t, sealed{
		sender: senderA, epoch: 9, streamIndex: 52,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(9),
	})
	refusals = append(refusals, staleEpoch) // check 6

	forged := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 53,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})
	forged.RecordBytes[len(forged.RecordBytes)-1] ^= 0x01
	refusals = append(refusals, forged) // check 7

	wrongBody := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 54,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
		bodyHashOf: []byte("a body that is not the body under it"),
	})
	refusals = append(refusals, wrongBody) // check 8

	for index, record := range refusals {
		results := fixture.submit(t, record)
		if results[0].GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("refusal %d was answered %v, want REASON_REJECTED", index, results[0].GetReason())
		}
		if results[0].GetRecordId() != 0 {
			t.Fatalf("refusal %d was allocated record_id %d", index, results[0].GetRecordId())
		}
	}

	after := fixture.fetch(t)
	if after.GetHighWaterRecordId() != high {
		t.Fatalf("%d refusals moved the high water from %d to %d", len(refusals), high, after.GetHighWaterRecordId())
	}
	if len(after.GetRecords()) != len(before.GetRecords()) {
		t.Fatalf("%d refusals stored %d records", len(refusals), len(after.GetRecords())-len(before.GetRecords()))
	}

	// and the next id is the one the refusals would have consumed
	next := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 60,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("the record after them"), body: []byte("the record after them"), writeKey: fixture.writeKey(1),
	})
	results := fixture.submit(t, next)
	if results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the record after the refusals was answered %v", results[0].GetReason())
	}
	if results[0].GetRecordId() != high+1 {
		t.Fatalf("the record after the refusals was allocated record_id %d, want %d; a refusal consumed one",
			results[0].GetRecordId(), high+1)
	}
}

// ── §5.1.1, the read path ────────────────────────────────────────────────────────────────

// No transaction is opened and no row is allocated on the read path, and a fetch that fails its
// authenticator reads nothing at all.
func TestTheReadPathOpensNoTransaction(t *testing.T) {
	counted := &countingStore{}
	fixture := newFixtureWith(t, Config{Store: counted})
	counted.Store = fixture.store
	fixture.createOpenGroup(t)

	counted.reset()
	fixture.fetch(t)
	if counted.submit != 0 || counted.createGroup != 0 {
		t.Fatalf("a fetch reached the transaction: %s", counted)
	}

	// a req_auth that does not verify reads no rows: check 7 refuses before the store is asked
	// for anything but the key check 6 selected
	request := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1}
	fixture.authorize(t, request)
	request.ReqAuth[0] ^= 0x01
	counted.reset()
	reason, _, err := fixture.handler.Fetch(context.Background(), fixture.conn, request)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a forged req_auth was answered %v, want REASON_REJECTED", reason)
	}
	if counted.fetch != 0 {
		t.Fatalf("a forged req_auth still read %d pages of records", counted.fetch)
	}
	if counted.submit != 0 || counted.createGroup != 0 {
		t.Fatalf("a forged req_auth reached the transaction: %s", counted)
	}
}

// A read whose epoch has no retained key and a read whose MAC does not verify fail identically,
// and so does a read of a group that does not exist.
func TestTheReadPathRefusesEveryCauseIdentically(t *testing.T) {
	fixture := newFixtureWith(t, Config{RejectFloor: 25 * time.Millisecond})
	fixture.createOpenGroup(t)

	unknownGroup := &protocol.FetchRequest{GroupId: groupId(0x44), ReadEpoch: 1}
	unknownEpoch := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 9}
	badAuth := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1}

	answers := []string{}
	pads := [][]time.Duration{}
	for index, request := range []*protocol.FetchRequest{unknownGroup, unknownEpoch, badAuth} {
		fixture.authorize(t, request)
		if index == 2 {
			request.ReqAuth[0] ^= 0x01
		}
		fixture.sleeps = nil
		reason, response, err := fixture.handler.Fetch(context.Background(), fixture.conn, request)
		if err != nil {
			t.Fatalf("fetch %d: %v", index, err)
		}
		if reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("fetch %d was answered %v, want REASON_REJECTED", index, reason)
		}
		if response != nil {
			t.Fatalf("fetch %d was refused and still carried a body", index)
		}
		answers = append(answers, reason.String())
		pads = append(pads, append([]time.Duration{}, fixture.sleeps...))
	}
	for index := range answers {
		if answers[index] != answers[0] {
			t.Fatalf("fetch %d answered %q and fetch 0 answered %q", index, answers[index], answers[0])
		}
		if !slices.Equal(pads[index], pads[0]) {
			t.Fatalf("fetch %d padded %v and fetch 0 padded %v", index, pads[index], pads[0])
		}
	}
	if len(pads[0]) != 1 {
		t.Fatalf("a refused read padded %d times, want exactly one", len(pads[0]))
	}
}

// §4.3.8's op byte comes from the compiled descriptor and is the arm number the spec gives.
func TestTheOpByteIsTheArmNumberOfTheRequest(t *testing.T) {
	op, err := opOf(&protocol.FetchRequest{})
	if err != nil {
		t.Fatalf("opOf: %v", err)
	}
	if op != 13 {
		t.Fatalf("FetchRequest is op %d; §4.3.8 names it 13, and the number is a MAC input", op)
	}
	if _, err := opOf(&protocol.Record{}); err == nil {
		t.Fatal("a message that is not an arm of MessageServerRequest.body was given an op byte")
	}
}

// ── the plumbing ─────────────────────────────────────────────────────────────────────────

// A store that counts what reaches it, so that "nothing that costs a database read happens
// before something that costs a hash" is a measurement rather than a reading of the source.
type countingStore struct {
	store.Store
	createGroup int
	submit      int
	fetch       int
	epochKeys   int
	groupState  int
}

func (self *countingStore) reset() {
	self.createGroup, self.submit, self.fetch, self.epochKeys, self.groupState = 0, 0, 0, 0, 0
}

func (self *countingStore) reads() int {
	return self.createGroup + self.submit + self.fetch + self.epochKeys + self.groupState
}

func (self *countingStore) String() string {
	return "create_group=" + strconv.Itoa(self.createGroup) +
		" submit=" + strconv.Itoa(self.submit) +
		" fetch=" + strconv.Itoa(self.fetch) +
		" epoch_keys=" + strconv.Itoa(self.epochKeys) +
		" group_state=" + strconv.Itoa(self.groupState)
}

func (self *countingStore) CreateGroup(ctx context.Context, request *store.CreateGroupRequest) (*store.CreateGroupResult, error) {
	self.createGroup++
	return self.Store.CreateGroup(ctx, request)
}

func (self *countingStore) Submit(ctx context.Context, request *store.SubmitRequest) (*store.SubmitResponse, error) {
	self.submit++
	return self.Store.Submit(ctx, request)
}

func (self *countingStore) Fetch(ctx context.Context, request *store.FetchRequest) (*store.FetchResult, error) {
	self.fetch++
	return self.Store.Fetch(ctx, request)
}

func (self *countingStore) EpochKeys(ctx context.Context, groupId []byte, epoch uint64) (*store.EpochKeys, error) {
	self.epochKeys++
	return self.Store.EpochKeys(ctx, groupId, epoch)
}

func (self *countingStore) GroupState(ctx context.Context, groupId []byte) (*store.GroupState, error) {
	self.groupState++
	return self.Store.GroupState(ctx, groupId)
}

// One projection field changed to something the parse does not say.
//
// A field kind with no case here stops the test. §4.3.3's projection block is a list of fields
// the server indexes, so a field this mutator quietly skipped would be a field check 3 could
// stop covering with every test still green.
func mutateProjection(t *testing.T, record *protocol.Record, field protoreflect.FieldDescriptor) {
	t.Helper()
	reflected := record.ProtoReflect()
	switch field.Kind() {
	case protoreflect.BytesKind:
		current := append([]byte{}, reflected.Get(field).Bytes()...)
		if len(current) == 0 {
			current = make([]byte, 16)
			current[0] = 1
		} else {
			current[0] ^= 0xFF
		}
		reflected.Set(field, protoreflect.ValueOfBytes(current))
	case protoreflect.BoolKind:
		reflected.Set(field, protoreflect.ValueOfBool(!reflected.Get(field).Bool()))
	case protoreflect.Uint64Kind:
		reflected.Set(field, protoreflect.ValueOfUint64(reflected.Get(field).Uint()+1))
	case protoreflect.Uint32Kind:
		reflected.Set(field, protoreflect.ValueOfUint32(uint32(reflected.Get(field).Uint())+1))
	default:
		t.Fatalf("Record.%s is a %s, and this mutator has no way to change one; a field it cannot change is a field this test reports as covered without covering it",
			field.Name(), field.Kind())
	}
}

// §5.1's nine numbered checks, read out of §5.1's own table.
func checkNumbersOfSpecB51(t *testing.T) []int {
	t.Helper()
	name, document := specBDocument(t)
	lines := strings.Split(document, "\n")

	heading := -1
	for number, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "### 5.1 ") {
			if heading != -1 {
				t.Fatalf("%s carries two §5.1 headings and this gate would have to choose between them", name)
			}
			heading = number
		}
	}
	if heading == -1 {
		t.Fatalf("%s carries no '### 5.1 ' heading, so §5.1's table has moved or been reworded and this gate would have read nothing", name)
	}

	numbers := []int{}
	started := false
	for number := heading + 1; number < len(lines); number++ {
		line := strings.TrimSpace(lines[number])
		if strings.HasPrefix(line, "#") {
			break
		}
		if !strings.HasPrefix(line, "|") {
			if started {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		value, err := strconv.Atoi(strings.TrimSpace(cells[0]))
		if err != nil {
			// the header row and the alignment row, which name no check
			continue
		}
		started = true
		numbers = append(numbers, value)
	}
	if len(numbers) < 9 {
		t.Fatalf("%s §5.1 yielded %d numbered checks (%v); the table names nine", name, len(numbers), numbers)
	}
	for index, value := range numbers {
		if value != index+1 {
			t.Fatalf("%s §5.1's numbering is %v, which is not 1..%d in order; this gate reads the order as well as the set", name, numbers, len(numbers))
		}
	}
	return numbers
}

// Spec B, from the tree this package is checked out in.
func specBDocument(t *testing.T) (string, string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(moduleRoot(t), "docs", "specs", "*-spec-b-*.md"))
	if err != nil {
		t.Fatalf("looking for the spec B document: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("docs/specs holds %d documents matching *-spec-b-*.md (%v); this gate reads its rule out of exactly one", len(matches), matches)
	}
	text, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("%s: %v", matches[0], err)
	}
	return filepath.ToSlash(matches[0]), strings.ReplaceAll(string(text), "\r\n", "\n")
}
