package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The client half of spec A §5.7: a record, sealed under a `write_key` and a connection's nonce.
//
// Everything here is connect/message's — the key derivation, the preimage, the MAC and the
// codec. A test that hand-rolled any of them would be asserting that two copies of a preimage in
// this repository agree with each other, which is the one thing §12.1 A-1 says a test must never
// be, and would make the replay property below a property of the copy.
func sealRecord(t *testing.T, writeKey []byte, serverNonce []byte, streamIndex uint64) *protocol.Record {
	t.Helper()
	header := message.RecordHeader{
		Epoch:          1,
		StreamIndex:    streamIndex,
		RetentionClass: message.RetentionDurable,
		SizeBucket:     message.SizeBucket256,
	}
	copy(header.GroupId[:], bytes.Repeat([]byte{0x21}, 32))
	copy(header.SenderHandle[:], bytes.Repeat([]byte{0x33}, 16))
	for index := range header.BodyHash {
		header.BodyHash[index] = byte(index * 7)
	}
	head := []byte("a head this test does not read")
	body := make([]byte, message.SizeBucketCtBodyBytes(message.SizeBucket256))

	record := &message.Record{Header: header, CtHead: head, CtBody: body}
	record.WriteAuth = message.ComputeWriteAuth(writeKey, serverNonce, &header, head, nil)
	encoded, err := message.EncodeRecord(record)
	if err != nil {
		t.Fatalf("EncodeRecord: %v", err)
	}
	return &protocol.Record{RecordBytes: encoded}
}

// A group's `write_key`, from a storage root this test chose. Not secret and not derived from an
// MLS key schedule — plan p4 is absent rather than stubbed — but derived through the same
// function the sdk derives it through, which is what makes the MAC below the real one.
func testWriteKey() []byte {
	root := make([]byte, 32)
	for index := range root {
		root[index] = byte(index)*5 ^ 0x9c
	}
	return message.WriteKey(root)
}

// A handler that does the one thing §5.1 check 7 does: recompute the MAC with connect/message's
// own verifier, against the nonce the dispatcher handed it.
//
// It is the smallest handler that can tell a replay from a fresh record, and it is the whole of
// what the replay property needs: whether the server refuses a record sealed against a nonce it
// no longer holds is decided by which nonce reaches this call.
func verifyingSubmit(writeKey []byte) func(*api.Connection, *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error) {
	return func(conn *api.Connection, request *protocol.SubmitRequest) (protocol.Reason, *protocol.SubmitResponse, error) {
		results := []*protocol.SubmitResult{}
		for _, projection := range request.GetRecords() {
			reason := protocol.Reason_REASON_REJECTED
			if parsed, err := message.ParseRecord(projection.GetRecordBytes()); err == nil {
				if message.VerifyWriteAuth(writeKey, conn.ServerNonce, parsed) {
					reason = protocol.Reason_REASON_OK
				}
			}
			results = append(results, &protocol.SubmitResult{Reason: reason})
		}
		return protocol.Reason_REASON_OK, &protocol.SubmitResponse{Results: results}, nil
	}
}

// ── the property the design has to make true ─────────────────────────────────────────────

// A client that reconnects cannot replay a record sealed against the old connection's nonce.
//
// This is the whole argument for what a connection is in this package. connect gives the server
// no way to tell one session of a client_id from the next — see [Connections] — so a connection
// here is one Hello epoch, and a Hello destroys the previous nonce outright. What that buys is
// exactly this: a record that verified on connection one is refused on connection two, by the
// real MAC, with nothing changed but the connection.
//
// The third step is the control that makes the second mean anything. Without it, "the record was
// refused" is equally consistent with a server that refuses everything after a second Hello, and
// the test would pass on a peer that had simply broken.
func TestARecordSealedAgainstAClosedConnectionsNonceIsRefusedOnTheNext(t *testing.T) {
	fixture := newFixture(t)
	writeKey := testWriteKey()
	fixture.handler.onSubmit = verifyingSubmit(writeKey)

	first := fixture.hello(t)
	accepted := fixture.call(t, &protocol.SubmitRequest{
		GroupId: bytes.Repeat([]byte{0x21}, 32),
		Records: []*protocol.Record{sealRecord(t, writeKey, first.GetServerNonce(), 1)},
	})
	if reason := accepted.GetSubmit().GetResults()[0].GetReason(); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a record sealed against this connection's own nonce was answered %v", reason)
	}

	// sealed on connection one, and held back — the queued record of spec A §5.7's outbox rule
	held := sealRecord(t, writeKey, first.GetServerNonce(), 2)

	second := fixture.hello(t)
	if bytes.Equal(first.GetServerNonce(), second.GetServerNonce()) {
		t.Fatal("a second Hello issued the same server_nonce as the first; the nonce is not scoped to a connection at all")
	}

	replayed := fixture.call(t, &protocol.SubmitRequest{
		GroupId: bytes.Repeat([]byte{0x21}, 32),
		Records: []*protocol.Record{held},
	})
	if reason := replayed.GetSubmit().GetResults()[0].GetReason(); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a record sealed against the previous connection's nonce was answered %v on the next connection; §5.7's whole purpose is that this cannot verify", reason)
	}

	// the control: the same record, at the same stream index, re-MAC'd against the new
	// connection's nonce, is accepted. So what refused the replay was the nonce and not the
	// reconnect
	resealed := fixture.call(t, &protocol.SubmitRequest{
		GroupId: bytes.Repeat([]byte{0x21}, 32),
		Records: []*protocol.Record{sealRecord(t, writeKey, second.GetServerNonce(), 2)},
	})
	if reason := resealed.GetSubmit().GetResults()[0].GetReason(); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a record re-MAC'd against the new connection's nonce was answered %v; §5.7's outbox rule says this is the recovery, so the refusal above was not about the nonce", reason)
	}
}

// The old nonce is not merely superseded: it is gone.
//
// A grace window in which the previous connection's nonce still verified would satisfy the test
// above only by accident of ordering, and would be precisely the cross-connection replay window
// the nonce exists to close. There is no method on [Connections] that could answer with a retired
// nonce, and this asserts that there is no path to one either.
func TestAClosedConnectionsNonceIsHeldNowhere(t *testing.T) {
	fixture := newFixture(t)
	first := fixture.hello(t)

	clientId := fixture.clientClient.ClientId()
	before, found := fixture.connections.Lookup(clientId)
	if !found || !before.Holds(first.GetServerNonce()) {
		t.Fatal("the connection the first Hello opened does not hold the nonce that Hello issued")
	}

	second := fixture.hello(t)
	after, found := fixture.connections.Lookup(clientId)
	if !found {
		t.Fatal("a second Hello left the client with no connection at all")
	}
	if after.Generation() != before.Generation()+1 {
		t.Fatalf("two Hellos produced generations %d and %d; a connection is one Hello epoch", before.Generation(), after.Generation())
	}
	if after.Holds(first.GetServerNonce()) {
		t.Fatal("the live connection still holds the previous connection's nonce")
	}
	if !after.Holds(second.GetServerNonce()) {
		t.Fatal("the live connection does not hold the nonce its own Hello issued")
	}
	if count := fixture.connections.Count(); count != 1 {
		t.Fatalf("%d connections are live for one client_id; a second Hello replaces rather than adds", count)
	}
}

// A request whose connection was replaced while it was in flight is refused.
//
// The window is real: peer resolves the connection when it dispatches and §5.1's check 2 runs
// inside the pipeline, so a Hello arriving between the two leaves a request authenticated against
// a nonce that no longer exists. It is asserted directly rather than through a race, because a
// test that has to win a race to observe a refusal is a test that reports the refusal missing
// whenever it loses.
func TestARequestWhoseConnectionWasReplacedInFlightIsRefused(t *testing.T) {
	connections, err := NewConnections(rand.Reader, time.Now, 0)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	checks, err := NewChecks(connections, DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}

	clientId := connect.NewId()
	first, err := connections.Open(clientId)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	arrived := &inbound{clientId: clientId, connection: first, bytes: 64, fragments: 1}
	ctx := withInbound(context.Background(), arrived)

	if reason := checks.ConnectionAuthenticated(ctx, first.ApiConnection()); reason != protocol.Reason_REASON_OK {
		t.Fatalf("a request on the live connection was refused %v", reason)
	}
	if _, err := connections.Open(clientId); err != nil {
		t.Fatalf("the second Open: %v", err)
	}
	if reason := checks.ConnectionAuthenticated(ctx, first.ApiConnection()); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a request from a connection that has been replaced was answered %v, want REASON_REJECTED", reason)
	}
}

// The nonce a handler verifies against is the connection's, and nothing the client sent.
//
// §5.1 check 2 in its own words: "the server knows its own connection's nonce and looks it up
// from the connection, never from the request". Two halves are asserted. The schema half is
// derived from the compiled descriptor: no message reachable from `MessageServerRequest.body`
// declares a field a server could mistake for a nonce, so there is nothing in a request to read
// one out of. The behavioural half fills every field the client does control with a value the
// client chose, and reads back what the dispatcher handed the handler.
func TestTheNonceAHandlerVerifiesAgainstComesFromTheConnection(t *testing.T) {
	fixture := newFixture(t)

	request := (&protocol.MessageServerRequest{}).ProtoReflect().Descriptor()
	seen := map[protoreflect.FullName]bool{}
	for _, arm := range bodyArmsOf(request) {
		if field := nonceShapedFieldIn(arm.Message(), seen); field != "" {
			t.Fatalf("%s is reachable from MessageServerRequest.body and declares %s; §5.1 check 2 says the server never reads a nonce out of a request, and this build's own descriptor now offers it one",
				arm.Message().FullName(), field)
		}
	}

	chosen := bytes.Repeat([]byte{0xAB}, ServerNonceBytes)
	// every byte of this Hello the client controls, set to the value an attacker would pick
	response := fixture.call(t, &protocol.HelloRequest{
		SupportedVersions: []uint32{fixtureProtocolVersion},
		ClientEpochHint:   chosen,
	})
	issued := response.GetHello().GetServerNonce()
	if bytes.Equal(issued, chosen) {
		t.Fatal("the nonce issued to this connection is the value the client put in client_epoch_hint")
	}
	fixture.nonce = issued

	fixture.handler.forget()
	fixture.call(t, &protocol.SubmitRequest{GroupId: chosen, Records: []*protocol.Record{{RecordBytes: chosen, BodyHash: chosen}}})
	calls := fixture.handler.recorded()
	if len(calls) != 1 {
		t.Fatalf("the submit reached the handler %d times", len(calls))
	}
	if !bytes.Equal(calls[0].nonce, issued) {
		t.Fatalf("the handler was handed a server_nonce that is not this connection's own")
	}
	if !bytes.Equal(calls[0].clientId, fixture.clientClient.ClientId().Bytes()) {
		t.Fatalf("the handler was handed a client_id that is not the platform-authenticated source")
	}
}

// Any field of a message reachable from a request that a server could read a nonce out of.
//
// The class is every `bytes` field whose name carries "nonce", found by walking the descriptor
// graph rather than by listing the messages of §4.3 — the fifteen arms reach forty-odd messages
// between them, and a list would be a list that the next `oneof` arm is missing from.
func nonceShapedFieldIn(descriptor protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool) string {
	if seen[descriptor.FullName()] {
		return ""
	}
	seen[descriptor.FullName()] = true
	fields := descriptor.Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if strings.Contains(string(field.Name()), "nonce") {
			return string(field.FullName())
		}
		if field.Kind() == protoreflect.MessageKind {
			if found := nonceShapedFieldIn(field.Message(), seen); found != "" {
				return found
			}
		}
	}
	return ""
}

// One connection's nonce never changes under it, however many requests it serves.
//
// §5.7 says "valid for the life of that connection, and never rotated", and the failure this
// guards is the opposite of the one above: a server that reissued a nonce per request, or per
// some interval, would break every queued record a client holds and would do it intermittently.
func TestOneConnectionKeepsOneNonceAcrossEveryRequestOnIt(t *testing.T) {
	fixture := newFixture(t)
	hello := fixture.hello(t)
	fixture.handler.forget()

	for index := range 16 {
		fixture.call(t, &protocol.FetchRequest{GroupId: bytes.Repeat([]byte{9}, 32), SinceRecordId: uint64(index)})
	}
	calls := fixture.handler.recorded()
	if len(calls) != 16 {
		t.Fatalf("%d of 16 requests reached the handler", len(calls))
	}
	for _, current := range calls {
		if !bytes.Equal(current.nonce, hello.GetServerNonce()) {
			t.Fatalf("a request on one connection was served under a nonce that is not the one its Hello issued")
		}
	}
}

// Every connection gets its own 32 bytes, and no two are the same.
//
// A nonce derived from the client_id, from a counter, or from the clock would satisfy every other
// test in this file and would be enumerable by the party the nonce is supposed to bind.
func TestEveryConnectionIsIssuedItsOwnNonce(t *testing.T) {
	connections, err := NewConnections(rand.Reader, time.Now, 0)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	seen := map[string]bool{}
	for index := range 256 {
		// half of them from one client_id in a row, which is the reconnect case, and half from
		// distinct ones, which is the ordinary case
		clientId := connect.NewId()
		if index%2 == 0 {
			clientId = connect.Id{}
		}
		current, err := connections.Open(clientId)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		nonce := current.ServerNonce()
		if len(nonce) != ServerNonceBytes {
			t.Fatalf("a connection was issued a %d byte nonce", len(nonce))
		}
		if seen[string(nonce)] {
			t.Fatalf("two connections were issued the same nonce at open %d", index)
		}
		seen[string(nonce)] = true
	}
}

// A short random source is an error, never a short nonce.
func TestANonceIsNotIssuedFromASourceThatCannotFillIt(t *testing.T) {
	connections, err := NewConnections(bytes.NewReader(make([]byte, ServerNonceBytes-1)), time.Now, 0)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	if _, err := connections.Open(connect.NewId()); !errors.Is(err, ErrShortNonce) {
		t.Fatalf("a random source with 31 bytes in it answered %v, want ErrShortNonce", err)
	}
	if count := connections.Count(); count != 0 {
		t.Fatalf("%d connections are live after an Open that could not fill a nonce", count)
	}
}

// The sweep closes an idle connection, and closing it destroys its nonce.
//
// This is the only bound on how long a nonce outlives a session whose client stopped talking
// without saying so — the case connect gives this server no way to detect at all — so it is
// asserted rather than assumed, on an injected clock rather than by waiting.
func TestTheSweepClosesAnIdleConnectionAndItsNonce(t *testing.T) {
	now := time.Unix(1767225600, 0).UTC()
	clock := func() time.Time { return now }
	connections, err := NewConnections(rand.Reader, clock, time.Minute)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}

	clientId := connect.NewId()
	opened, err := connections.Open(clientId)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if closed := connections.Sweep(); closed != 0 {
		t.Fatalf("the sweep closed %d connections that had just been opened", closed)
	}

	now = now.Add(30 * time.Second)
	if _, found := connections.Lookup(clientId); !found {
		t.Fatal("a connection half a minute old was already gone")
	}
	now = now.Add(90 * time.Second)
	if closed := connections.Sweep(); closed != 1 {
		t.Fatalf("the sweep closed %d connections; one was two minutes past a one minute bound", closed)
	}
	if _, found := connections.Lookup(clientId); found {
		t.Fatal("a swept connection is still resolvable, so its nonce still verifies")
	}
	if connections.IsLive(opened) {
		t.Fatal("a swept connection still reports itself live")
	}
}
