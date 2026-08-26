package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/harness"
	"github.com/urnetwork/message-server/peer"
	"github.com/urnetwork/message-server/store"
)

// The whole stack in one process: two real connect clients, peer's §4.2 frame dispatch, api's
// §5.1 pipeline and the in-memory store.
//
// It lives here rather than in peer because peer's //urmsg:mayimport directive names api, redact
// and metrics and does not name store — and api.New cannot be built without a store.Store. That
// is the layering working rather than a gap in it: an entrypoint is the one package allowed to
// reach every other, so the test that wires all of them belongs to the entrypoint.
//
// What only this file can see is that peer's [peer.Checks] are the checks *api* runs. Everywhere
// else in peer's own suite the handler is a double that calls them in api's documented order;
// here the real *api.Handler calls them, so a change to api's front-check order or to which
// checks it runs shows up as a failure here instead of nowhere.
//
// The client half is [harness.Client] and is not written out here, for the reason its own
// document gives: a test that builds its own frames is a test whose client and server can drift
// apart one file at a time, and the one thing every test in this directory has to be able to ask
// afterwards is how many frames the journey took.
type stack struct {
	ctx    context.Context
	cancel context.CancelFunc

	serverClient *connect.Client
	clientClient *connect.Client

	store   *store.MemoryStore
	peer    *peer.Peer
	handler *api.Handler
	client  *harness.Client

	groupId []byte
}

const stackProtocolVersion = 1

// The two connect clients, wired to each other through two plain channels, exactly the way
// connect's own ip_test.go does it (ip_test.go:211).
//
// No network space, no operator and no ByJwt: NewNoContractClientOob plus AddNoContractPeer is
// what removes the contract requirement, which is why connect's own data-path tests run offline
// and why these do.
func newStack(t *testing.T) *stack {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	settings := connect.DefaultClientSettings()
	serverClient := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), settings)
	clientClient := connect.NewClient(ctx, connect.NewId(), connect.NewNoContractClientOob(), settings)

	toServer := make(connect.Route)
	toClient := make(connect.Route)
	clientClient.RouteManager().UpdateTransport(connect.NewSendGatewayTransport(), []connect.Route{toServer})
	clientClient.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransport(), []connect.Route{toClient})
	clientClient.ContractManager().AddNoContractPeer(serverClient.ClientId())
	serverClient.RouteManager().UpdateTransport(
		connect.NewSendClientTransport(connect.DestinationId(clientClient.ClientId())), []connect.Route{toClient})
	serverClient.RouteManager().UpdateTransport(connect.NewReceiveGatewayTransport(), []connect.Route{toServer})
	serverClient.ContractManager().AddNoContractPeer(clientClient.ClientId())

	connections, err := peer.NewConnections(rand.Reader, time.Now, time.Hour)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	checks, err := peer.NewChecks(connections, peer.DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	memory := store.NewMemoryStore(store.DefaultLimits())
	handler, err := api.New(api.Config{
		Store:       memory,
		KnownGroups: api.NewMemoryKnownGroups(),
		Front:       checks,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	served, err := peer.New(peer.Config{
		Client:          serverClient,
		Handler:         handler,
		Connections:     connections,
		Checks:          checks,
		Capabilities:    &protocol.Capabilities{MaxRequestBytes: peer.DefaultMaxRequestBytes},
		ProtocolVersion: stackProtocolVersion,
		ServerId:        bytes.Repeat([]byte{0x5A}, 16),
	})
	if err != nil {
		t.Fatalf("peer.New: %v", err)
	}
	client, err := harness.New(harness.Config{
		Client:          clientClient,
		Server:          serverClient.ClientId(),
		ProtocolVersion: stackProtocolVersion,
	})
	if err != nil {
		t.Fatalf("harness.New: %v", err)
	}

	current := &stack{
		ctx:          ctx,
		cancel:       cancel,
		serverClient: serverClient,
		clientClient: clientClient,
		store:        memory,
		peer:         served,
		handler:      handler,
		client:       client,
		groupId:      bytes.Repeat([]byte{0x71}, store.GroupIdBytes),
	}
	t.Cleanup(func() {
		client.Close()
		served.Close()
		clientClient.Close()
		serverClient.Close()
		cancel()
	})
	return current
}

// ── what the transport carried, from both ends ───────────────────────────────────────────

// The two ends' own counters at one instant.
//
// This is the measurement the whole milestone turns on. A record that survives submit and fetch
// through the api layer directly comes back with exactly the same bytes as one that crossed two
// connect clients, so "it came back" distinguishes nothing: the previous milestone already had
// that. What distinguishes them is that one of them put frames on a route, and the only way to
// assert it is to count the frames at both ends and hold the two counts to each other.
type carried struct {
	client harness.Counts
	server peer.Stats
}

func (self *stack) carried() carried {
	return carried{client: self.client.Counts(), server: self.peer.Stats()}
}

// Everything that crossed the wire since `before`, asserted from both ends.
//
// `requests` is how many requests the caller made, so that a journey which quietly stopped
// reaching the dispatcher is a failure here rather than a smaller number nobody compares.
//
// Every one of these is an equality between a number this client counted and a number the server
// counted, which is what makes the assertion unfakeable from either side alone: a test that
// called api directly would move neither, and a stubbed transport would have to move both in
// step to get past it.
func (self *stack) assertCarried(t *testing.T, before carried, requests uint64, what string) carried {
	t.Helper()

	// The server counts a response frame *after* connect's send has taken it, and connect may
	// hand that frame to this client before the count lands — so on the last frame of a journey
	// the two ends settle a few instructions apart. The equality is the claim; this waits for
	// the counter and never for the frame, and it fails rather than degrading into "at least
	// one".
	deadline := time.Now().Add(5 * time.Second)
	for {
		now := self.carried()
		if now.server.ResponsesSent-before.server.ResponsesSent == now.client.ResponseFrames-before.client.ResponseFrames {
			break
		}
		if deadline.Before(time.Now()) {
			t.Fatalf("%s: the server counted %d response frames sent and this client counted %d received, and they did not settle",
				what, now.server.ResponsesSent-before.server.ResponsesSent, now.client.ResponseFrames-before.client.ResponseFrames)
		}
		time.Sleep(time.Millisecond)
	}

	after := self.carried()
	delta := carried{
		client: harness.Counts{
			RequestFrames:  after.client.RequestFrames - before.client.RequestFrames,
			ResponseFrames: after.client.ResponseFrames - before.client.ResponseFrames,
			Responses:      after.client.Responses - before.client.Responses,
			Unmatched:      after.client.Unmatched - before.client.Unmatched,
			Aborted:        after.client.Aborted - before.client.Aborted,
		},
		server: peer.Stats{
			FramesReceived:  after.server.FramesReceived - before.server.FramesReceived,
			FramesDropped:   after.server.FramesDropped - before.server.FramesDropped,
			RequestsServed:  after.server.RequestsServed - before.server.RequestsServed,
			ResponsesSent:   after.server.ResponsesSent - before.server.ResponsesSent,
			ResponsesFailed: after.server.ResponsesFailed - before.server.ResponsesFailed,
			RefusalsDropped: after.server.RefusalsDropped - before.server.RefusalsDropped,
		},
	}

	if delta.client.RequestFrames == 0 {
		t.Fatalf("%s: this client put no frame on the transport at all, so whatever was observed did not travel over it", what)
	}
	if delta.client.ResponseFrames == 0 {
		t.Fatalf("%s: no frame came back over the transport, so whatever was observed did not travel over it", what)
	}
	if delta.server.FramesReceived != delta.client.RequestFrames {
		t.Fatalf("%s: this client sent %d request frames and the server's receive callback saw %d",
			what, delta.client.RequestFrames, delta.server.FramesReceived)
	}
	if delta.server.RequestsServed != requests {
		t.Fatalf("%s: %d requests were made and the server's dispatcher served %d", what, requests, delta.server.RequestsServed)
	}
	if delta.client.Responses != requests {
		t.Fatalf("%s: %d requests were made and %d responses reached a request that was waiting for one",
			what, requests, delta.client.Responses)
	}
	if delta.client.Unmatched != 0 {
		t.Fatalf("%s: %d responses arrived carrying a request_id no request of this client was waiting on",
			what, delta.client.Unmatched)
	}
	if delta.client.Aborted != 0 {
		t.Fatalf("%s: this client abandoned %d inbound reassemblies, so a fragmented response arrived out of order or changed its count",
			what, delta.client.Aborted)
	}
	if delta.server.FramesDropped != 0 {
		t.Fatalf("%s: the server dropped %d frames it could not decode", what, delta.server.FramesDropped)
	}
	if delta.server.ResponsesFailed != 0 || delta.server.RefusalsDropped != 0 {
		t.Fatalf("%s: the server failed %d sends and dropped %d refusals", what, delta.server.ResponsesFailed, delta.server.RefusalsDropped)
	}
	return delta
}

// ── the client's own keys and handles ────────────────────────────────────────────────────

// A group's storage root for one epoch. Deterministic, distinct per epoch, and not secret: the
// two keys under it are what a test needs, and where a real storage root comes from is the MLS
// key schedule of plan p4, which is absent rather than stubbed.
func storageRoot(epoch uint64) []byte {
	root := make([]byte, 32)
	for index := range root {
		root[index] = byte(index)*3 ^ byte(epoch*17+5)
	}
	return root
}

func writeKeyFor(epoch uint64) []byte {
	return message.WriteKey(storageRoot(epoch))
}

func readKeyFor(epoch uint64) []byte {
	return message.ReadKey(storageRoot(epoch))
}

// §3.1's `sender_handle`, at its own width, distinct per seed.
func handleOf(seed byte) []byte {
	value := make([]byte, store.SenderHandleBytes)
	for index := range value {
		value[index] = seed ^ byte(index)
	}
	return value
}

// The EpochAttachment a commit carries for the epoch it opens: the two keys, the alg id that
// derived them, and the wrap set the EpochComplete marker will have to match.
func epochAttachment(opens uint64, wraps uint32) *message.ServerAttachment {
	contextHash := make([]byte, 32)
	for index := range contextHash {
		contextHash[index] = byte(index) ^ byte(opens)
	}
	return &message.ServerAttachment{
		Kind: message.AttachmentEpoch,
		Epoch: &message.EpochAttachment{
			Epoch:             opens,
			AlgId:             0x0031, // HKDF-SHA-256, which is what derived both keys
			WriteKey:          writeKeyFor(opens),
			ReadKey:           readKeyFor(opens),
			GroupContextHash:  contextHash,
			ExpectedWrapCount: wraps,
		},
	}
}

func wrapAttachment(epoch uint64, target []byte) *message.ServerAttachment {
	return &message.ServerAttachment{
		Kind: message.AttachmentWrap,
		Wrap: &message.WrapTag{WrapTargetHandle: append([]byte{}, target...), Epoch: epoch},
	}
}

func completeAttachment(epoch uint64, wraps uint32) *message.ServerAttachment {
	return &message.ServerAttachment{
		Kind:     message.AttachmentComplete,
		Complete: &message.EpochComplete{Epoch: epoch, WrapCount: wraps},
	}
}

// ── the four operations, as this directory's tests use them ──────────────────────────────

// §4.3.1, and the nonce every authenticator below is computed against.
func (self *stack) hello(t *testing.T) *protocol.HelloResponse {
	t.Helper()
	reason, hello, err := self.client.Hello(self.ctx)
	if err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("Hello was answered %v, want REASON_OK", reason)
	}
	return hello
}

// One record, sealed against this connection's nonce.
//
// The group and the write key default rather than being repeated at every call site: a record's
// key is the write key of the epoch its header names, which for a founding commit is the
// bootstrap epoch 0 and for everything after it is the epoch it was published in. A test that
// means something else says so by setting the field.
func (self *stack) seal(t *testing.T, spec harness.Sealed) *protocol.Record {
	t.Helper()
	if spec.GroupId == nil {
		spec.GroupId = self.groupId
	}
	if spec.WriteKey == nil {
		spec.WriteKey = writeKeyFor(spec.Epoch)
	}
	record, err := self.client.Seal(spec)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return record
}

// A submission over the frame path, which must reach a body: an envelope refusal has answered
// checks 1, 2 or 4, and none of those is what a test that calls this is about.
func (self *stack) submit(t *testing.T, records ...*protocol.Record) []*protocol.SubmitResult {
	t.Helper()
	reason, response, err := self.client.Submit(self.ctx, &protocol.SubmitRequest{
		GroupId: self.groupId,
		Records: records,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the submit envelope was answered %v, want REASON_OK with a body", reason)
	}
	if len(response.GetResults()) != len(records) {
		t.Fatalf("the submit answered %d results for %d records; §4.3.3 aligns them positionally",
			len(response.GetResults()), len(records))
	}
	return response.GetResults()
}

// A submission that must be accepted, for the steps a test performs on its way to what it is
// actually about.
func (self *stack) submitAccepted(t *testing.T, what string, record *protocol.Record) *protocol.SubmitResult {
	t.Helper()
	result := self.submit(t, record)[0]
	if result.GetReason() != protocol.Reason_REASON_OK {
		t.Fatalf("%s was answered %v, want REASON_OK", what, result.GetReason())
	}
	return result
}

// A fetch of the whole group from the beginning, authorized under epoch 1's read key.
func (self *stack) fetch(t *testing.T) *protocol.FetchResponse {
	t.Helper()
	reason, response, err := self.client.Fetch(self.ctx,
		&protocol.FetchRequest{GroupId: self.groupId, ReadEpoch: 1, SinceRecordId: 0}, readKeyFor(1))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("the fetch was answered %v, want REASON_OK", reason)
	}
	return response
}

// The group of §6.1, opened and made writable: the founding commit, the epoch's wrap set, and the
// marker that closes the fan-out.
//
// Three records rather than one, and that is §6.1 rather than ceremony. CreateGroup leaves the
// group at epoch 1 with `epoch_complete = false`, which step (2) makes readable-but-not-writable
// for everything except a wrap, a snapshot or the EpochComplete marker — so an ordinary record
// before the marker lands is answered REASON_EPOCH_INCOMPLETE, and every test below that submits
// one needs this first.
func (self *stack) openGroup(t *testing.T) {
	t.Helper()
	self.hello(t)

	founder := handleOf(0xA0)
	commit := self.seal(t, harness.Sealed{
		Sender:     founder,
		IsCommit:   true,
		Class:      message.RetentionPermanent,
		Bucket:     message.SizeBucket256,
		Head:       []byte("a founding commit"),
		Body:       []byte("a founding commit"),
		Attachment: epochAttachment(1, 1),
	})
	reason, created, err := self.client.CreateGroup(self.ctx, &protocol.CreateGroupRequest{
		GroupId:           self.groupId,
		InitialCommit:     commit,
		BootstrapWriteKey: writeKeyFor(0),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if reason != protocol.Reason_REASON_OK {
		t.Fatalf("CreateGroup was answered %v, want REASON_OK", reason)
	}
	if created.GetCurrentEpoch() != 1 {
		t.Fatalf("CreateGroup answered epoch %d, want 1", created.GetCurrentEpoch())
	}

	self.submitAccepted(t, "the epoch-1 wrap", self.seal(t, harness.Sealed{
		Sender:      founder,
		Epoch:       1,
		StreamIndex: 1,
		Class:       message.RetentionPermanent,
		Bucket:      message.SizeBucket256,
		Head:        []byte("the epoch-1 snapshot"),
		Body:        []byte("the epoch-1 snapshot"),
		Attachment:  wrapAttachment(1, founder),
	}))
	self.submitAccepted(t, "the epoch-1 marker", self.seal(t, harness.Sealed{
		Sender:      founder,
		Epoch:       1,
		StreamIndex: 2,
		Class:       message.RetentionDurable,
		Bucket:      message.SizeBucket256,
		Head:        []byte("epoch 1 complete"),
		Body:        []byte("epoch 1 complete"),
		Attachment:  completeAttachment(1, 1),
	}))
}

// §3.2's `next_record_id` for this test's group, read out of the store the server writes to.
//
// The store's own contract exposes it, which is what makes "the refusal allocated nothing" an
// assertion rather than an inference from a record that did not come back: a server that
// allocated an id and then rolled the row back would answer a fetch identically.
func (self *stack) nextRecordId(t *testing.T) uint64 {
	t.Helper()
	state, err := self.store.GroupState(self.ctx, self.groupId)
	if err != nil {
		t.Fatalf("GroupState: %v", err)
	}
	return state.NextRecordId
}
