package api

import (
	"context"
	"reflect"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
)

// ── §4.3.4's parameters ──────────────────────────────────────────────────────────────────

// Every field of the store's FetchRequest comes from the field of the client's request that
// carries the same name.
//
// The field set is [store.FetchRequest]'s own, walked, and not a list written here — which is
// what makes this a gate rather than four assertions. A field added to the store's request with
// no source on the wire is a field the handler would be free to invent, and a field the handler
// quietly stopped passing on is a parameter the client asked for and did not get; §4.3.4 has four
// of them and every one was a pure passthrough that no test had ever sent a non-default value
// through.
//
// Every value below is deliberately not its zero value, and the walk asserts that too. A request
// of all defaults is a request every dropped field passes.
func TestEveryFieldOfTheStoresFetchRequestComesFromTheClientsOwn(t *testing.T) {
	recorder := &recordingStore{}
	fixture := newFixtureWith(t, Config{Store: recorder, MaxRecordsPerFetch: 64})
	recorder.Store = fixture.store
	fixture.createOpenGroup(t)

	request := &protocol.FetchRequest{
		GroupId:       fixture.groupId,
		ReadEpoch:     1,
		SinceRecordId: 1,
		Limit:         7,
		HeadsOnly:     true,
		ClassMask:     classMask(t, message.RetentionDurable, 0),
	}
	reason, _, err := fixture.fetchFrom(t, request)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the fetch answered %v, want REASON_OK", reason)
	}
	if recorder.lastFetch == nil {
		t.Fatal("the fetch never reached the store at all")
	}

	asked := reflect.ValueOf(*recorder.lastFetch)
	fields := asked.Type()
	sent := reflect.ValueOf(request)
	for index := 0; index < fields.NumField(); index++ {
		name := fields.Field(index).Name
		getter := sent.MethodByName("Get" + name)
		if !getter.IsValid() {
			t.Fatalf("store.FetchRequest.%s has no Get%s on protocol.FetchRequest, so nothing here can say where its value came from; a field with no source on the wire is a field this layer invents",
				name, name)
		}
		want := getter.Call(nil)[0]
		if want.IsZero() {
			t.Fatalf("this test sent %s at its zero value, so a handler that dropped it on the floor would pass", name)
		}
		if !reflect.DeepEqual(want.Interface(), asked.Field(index).Interface()) {
			t.Fatalf("the client asked for %s = %v and the store was asked for %v", name, want.Interface(), asked.Field(index).Interface())
		}
	}
}

// §4.3.1's `max_records_per_fetch` is a bound and not a suggestion, and it is the only place the
// advertised number is enforced.
//
// A request that asks for more than the bound gets the bound; a request that asks for nothing in
// particular gets the bound rather than the group. Both directions matter: the second is what
// keeps an unbounded page out of a response for a client that simply left the field unset.
func TestTheFetchLimitIsBoundedByMaxRecordsPerFetch(t *testing.T) {
	recorder := &recordingStore{}
	fixture := newFixtureWith(t, Config{Store: recorder, MaxRecordsPerFetch: 2})
	recorder.Store = fixture.store
	fixture.createOpenGroup(t)
	// asked of the store directly, because the handler's own bound is what is under test here
	// and a count taken through it could only ever answer the bound
	held, err := fixture.store.Fetch(context.Background(), &store.FetchRequest{GroupId: fixture.groupId})
	if err != nil {
		t.Fatalf("counting what the group holds: %v", err)
	}
	if len(held.Records) <= 2 {
		t.Fatalf("the group holds %d records and the bound under test is 2; a bound at or above what the group holds is a bound nothing can be seen to apply", len(held.Records))
	}

	for _, requested := range []uint32{0, 3, 512} {
		request := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1, Limit: requested}
		reason, response, err := fixture.fetchFrom(t, request)
		if err != nil {
			t.Fatalf("a fetch asking for %d: %v", requested, err)
		}
		if reason != protocol.Reason_REASON_OK {
			t.Fatalf("a fetch asking for %d was answered %v", requested, reason)
		}
		if recorder.lastFetch.Limit != 2 {
			t.Fatalf("a fetch asking for %d reached the store asking for %d, and max_records_per_fetch is 2",
				requested, recorder.lastFetch.Limit)
		}
		if len(response.GetRecords()) != 2 {
			t.Fatalf("a fetch asking for %d answered %d records under a bound of 2", requested, len(response.GetRecords()))
		}
		if response.GetComplete() {
			t.Fatalf("a fetch truncated by the bound answered complete = true, and §4.3.4 has the client resume from next_record_id")
		}
	}

	// and a request under the bound is answered at its own size rather than at the bound's
	request := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1, Limit: 1}
	if _, response, err := fixture.fetchFrom(t, request); err != nil {
		t.Fatalf("a fetch asking for 1: %v", err)
	} else if len(response.GetRecords()) != 1 {
		t.Fatalf("a fetch asking for 1 answered %d records", len(response.GetRecords()))
	}
	if recorder.lastFetch.Limit != 1 {
		t.Fatalf("a fetch asking for 1 reached the store asking for %d", recorder.lastFetch.Limit)
	}

	// the default is the documented one, and a handler that took it from nowhere would be
	// answering an unbounded page to a client that named no limit
	defaulted := newFixtureWith(t, Config{Store: recorder})
	recorder.Store = defaulted.store
	defaulted.createOpenGroup(t)
	if _, _, err := defaulted.fetchFrom(t, &protocol.FetchRequest{GroupId: defaulted.groupId, ReadEpoch: 1}); err != nil {
		t.Fatalf("a fetch under the default bound: %v", err)
	}
	if recorder.lastFetch.Limit != DefaultMaxRecordsPerFetch {
		t.Fatalf("a fetch naming no limit reached the store asking for %d, and §4.3.1's documented default is %d",
			recorder.lastFetch.Limit, DefaultMaxRecordsPerFetch)
	}
}

// `since_record_id` is exclusive, and `class_mask` selects exactly the classes it names.
//
// Both are §4.3.4's and both were passthroughs nothing sent a value through. The cursor is what
// every client's incremental sync is built on — a dropped one re-serves the whole group on every
// poll — and the mask is a bit per retention-class wire byte, which is the one place in this
// package where a class travels as a number rather than as a tag.
func TestSinceRecordIdAndClassMaskSelectWhatComesBack(t *testing.T) {
	fixture := newFixture(t)
	fixture.createOpenGroup(t)
	extra := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 600,
		class: message.RetentionMedia, bucket: message.SizeBucket256,
		head: []byte("a media head"), body: []byte("a media body"), writeKey: fixture.writeKey(1),
	})
	if results := fixture.submit(t, extra); results[0].GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("the media record was answered %v", results[0].GetReason())
	}

	whole := fixture.fetch(t)
	if len(whole.GetRecords()) < 3 {
		t.Fatalf("the group holds %d records and this test needs at least three to have anything to select from", len(whole.GetRecords()))
	}

	for _, since := range []uint64{0, 1, whole.GetHighWaterRecordId()} {
		request := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1, SinceRecordId: since}
		_, response, err := fixture.fetchFrom(t, request)
		if err != nil {
			t.Fatalf("a fetch since %d: %v", since, err)
		}
		want := []uint64{}
		for _, record := range whole.GetRecords() {
			if since < record.GetRecordId() {
				want = append(want, record.GetRecordId())
			}
		}
		got := []uint64{}
		for _, record := range response.GetRecords() {
			got = append(got, record.GetRecordId())
		}
		if len(got) != len(want) {
			t.Fatalf("a fetch since %d answered record ids %v, want %v; the cursor is exclusive", since, got, want)
		}
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("a fetch since %d answered record ids %v, want %v", since, got, want)
			}
		}
	}

	for _, class := range []message.RetentionClass{message.RetentionPermanent, message.RetentionDurable, message.RetentionMedia} {
		wire, err := message.RetentionClassWire(class, 0)
		if err != nil {
			t.Fatalf("RetentionClassWire: %v", err)
		}
		request := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1, ClassMask: classMask(t, class, 0)}
		_, response, err := fixture.fetchFrom(t, request)
		if err != nil {
			t.Fatalf("a fetch of class 0x%02x: %v", wire, err)
		}
		if len(response.GetRecords()) == 0 {
			t.Fatalf("a fetch of class 0x%02x answered nothing, and the group holds a record of every class this loop names", wire)
		}
		for _, record := range response.GetRecords() {
			if record.GetRetentionClass() != uint32(wire) {
				t.Fatalf("a fetch masked to class 0x%02x answered a record of class 0x%02x",
					wire, record.GetRetentionClass())
			}
		}
		if len(response.GetRecords()) == len(whole.GetRecords()) {
			t.Fatalf("a fetch masked to class 0x%02x answered all %d records the group holds, so the mask selected nothing",
				wire, len(whole.GetRecords()))
		}
	}
}

// A heads_only read withholds `ct_body`, even from a store that answered with one.
//
// rebuildRecord's own comment is the claim under test: the rule is stated where the encoder is
// called "so that a store which forgot it cannot put a body on the wire through this path". The
// memory store does not forget, which is exactly why observing this against it proves nothing —
// so the store below is the one that forgot, and the response still has to come back with no
// body at all.
func TestAHeadsOnlyFetchWithholdsTheBodyEvenFromAStoreThatKeptIt(t *testing.T) {
	forgetful := &bodyKeepingStore{}
	fixture := newFixtureWith(t, Config{Store: forgetful})
	forgetful.Store = fixture.store
	fixture.createOpenGroup(t)

	// the control: this store really does answer a heads_only read with bodies attached, so a
	// green run below is the handler's doing and not the store's
	answered, err := forgetful.Fetch(context.Background(), &store.FetchRequest{GroupId: fixture.groupId, HeadsOnly: true})
	if err != nil {
		t.Fatalf("the forgetful store: %v", err)
	}
	kept := 0
	for _, record := range answered.Records {
		if 0 < len(record.CtBody) {
			kept++
		}
	}
	if kept == 0 {
		t.Fatal("the store this test installed answers a heads_only read with no bodies, so it is not the store that forgot and this test measures nothing")
	}

	request := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1, HeadsOnly: true}
	reason, response, err := fixture.fetchFrom(t, request)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("a heads_only fetch was answered %v", reason)
	}
	if len(response.GetRecords()) == 0 {
		t.Fatal("a heads_only fetch answered no records at all")
	}
	for _, record := range response.GetRecords() {
		rebuilt, err := message.ParseRecord(record.GetRecordBytes())
		if err != nil {
			t.Fatalf("record %d does not parse: %v", record.GetRecordId(), err)
		}
		if 0 < len(rebuilt.CtBody) {
			t.Fatalf("record %d came back from a heads_only fetch carrying %d octets of ct_body",
				record.GetRecordId(), len(rebuilt.CtBody))
		}
		if len(rebuilt.CtHead) == 0 {
			t.Fatalf("record %d came back from a heads_only fetch with no head either", record.GetRecordId())
		}
	}

	// and the same fetch without heads_only does carry the bodies, so the assertion above is
	// about the flag rather than about a path that never has a body
	full := &protocol.FetchRequest{GroupId: fixture.groupId, ReadEpoch: 1}
	if _, response, err := fixture.fetchFrom(t, full); err != nil {
		t.Fatalf("Fetch: %v", err)
	} else {
		bodies := 0
		for _, record := range response.GetRecords() {
			rebuilt, err := message.ParseRecord(record.GetRecordBytes())
			if err != nil {
				t.Fatalf("record %d does not parse: %v", record.GetRecordId(), err)
			}
			if 0 < len(rebuilt.CtBody) {
				bodies++
			}
		}
		if bodies == 0 {
			t.Fatal("a fetch that did not ask for heads only came back with no bodies either")
		}
	}
}

// ── the doubles ──────────────────────────────────────────────────────────────────────────

// A store that keeps the last read it was asked for, so that "the client asked for this" and
// "the store was asked for this" are two facts rather than one.
type recordingStore struct {
	store.Store
	lastFetch *store.FetchRequest
}

func (self *recordingStore) Fetch(ctx context.Context, request *store.FetchRequest) (*store.FetchResult, error) {
	copied := *request
	self.lastFetch = &copied
	return self.Store.Fetch(ctx, request)
}

// The store rebuildRecord's comment names: one that forgot to drop the body for a heads_only
// read, and answers with it attached.
type bodyKeepingStore struct {
	store.Store
}

func (self *bodyKeepingStore) Fetch(ctx context.Context, request *store.FetchRequest) (*store.FetchResult, error) {
	forgetful := *request
	forgetful.HeadsOnly = false
	return self.Store.Fetch(ctx, &forgetful)
}

// §4.3.4's `class_mask`: a bit per retention-class wire byte of §3.1, with the wire byte taken
// from the one function in the system that joins a class with an eph bucket.
func classMask(t *testing.T, class message.RetentionClass, ephBucket uint8) uint32 {
	t.Helper()
	wire, err := message.RetentionClassWire(class, ephBucket)
	if err != nil {
		t.Fatalf("RetentionClassWire: %v", err)
	}
	return uint32(1) << wire
}
