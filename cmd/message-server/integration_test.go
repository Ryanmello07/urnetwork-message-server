package main

import (
	"bytes"
	"testing"

	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/peer"
)

// A request that arrives before this connection said Hello is refused by check 2, inside api's
// own pipeline, and reaches no store at all.
//
// This is the one place the real *api.Handler runs peer's [peer.Checks]. peer's own suite runs
// them through a double that calls them in api's documented order; if api stopped calling them,
// or called them after the pipeline, only this fails.
//
// The journey this file used to open with — a record created, submitted and fetched back over the
// frame path — is now TestARecordTravelsOverTwoConnectClientsAndComesBack in twoclient_test.go,
// which is the same journey with the assertion this one did not have: that the frames it claims
// to have travelled on were counted at both ends of the transport.
func TestApisPipelineRunsPeersFrontChecks(t *testing.T) {
	stack := newStack(t)

	// no Hello: there is no connection, so check 2 has no nonce to look up
	response, err := stack.client.Call(stack.ctx, &protocol.SubmitRequest{GroupId: stack.groupId})
	if err != nil {
		t.Fatalf("the submit did not reach the server: %v", err)
	}
	if response.GetReason() != protocol.Reason_REASON_REJECTED {
		t.Fatalf("a submit on no connection was answered %v, want REASON_REJECTED", response.GetReason())
	}
	if response.GetSubmit() != nil {
		t.Fatal("a front-check refusal carried a body; the refusal has only the envelope to travel on")
	}
	if state, err := stack.store.GroupState(stack.ctx, stack.groupId); err == nil {
		t.Fatalf("a refused submit reached the store, which answered %v", state)
	}

	// §5.1 check 1, through the same pipeline: a request past max_request_bytes, sent whole.
	//
	// Whole rather than fragmented, and that is the point rather than a shortcut. A request this
	// size arrives in §4.6's fragments from any client that fragments, and the reassembler then
	// refuses it one stage before the pipeline — so check 1's copy inside api, which is the copy
	// this test is named for, would never be asked at all.
	stack.hello(t)
	oversize, err := stack.client.CallWhole(stack.ctx, &protocol.FetchRequest{
		GroupId: stack.groupId,
		ReqAuth: bytes.Repeat([]byte{0x11}, peer.DefaultMaxRequestBytes+16),
	})
	if err != nil {
		t.Fatalf("the oversize fetch did not reach the server: %v", err)
	}
	if oversize.GetReason() != protocol.Reason_REASON_OVERSIZE {
		t.Fatalf("a request past max_request_bytes was answered %v, want REASON_OVERSIZE", oversize.GetReason())
	}
}
