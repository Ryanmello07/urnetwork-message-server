package api

import (
	"testing"

	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
)

// §6.1 step (3b) at the wire boundary: whatever the store hands over, a refusal leaves this
// package naming no record.
//
// The store enforces this in `resultsOf`, the one place either of its implementations builds a
// SubmitResponse, and that was the whole of the enforcement. `store.Store` is an EXPORTED
// interface and `resultsOf` is not, so the rule held for the two implementations that happen to
// live in that package and for nothing else: a mock in a test, a third implementation, or a
// future one that stamps an id onto a refusal reaches the client through [resultOf] and through
// nothing else. The store cannot enforce a rule about a store it does not contain.
//
// It is duplicated here and not elsewhere because it is the only half of the invariant that is
// BLANKET. No code in §4.5 carries a record_id on a refusal, so there is no judgement in this
// copy to drift from the store's — where `current_epoch` and `winning_commit` are exactly that
// judgement (§4.5 gives REASON_EPOCH_STALE the first and §6.2 gives any rejected commit the
// second), and are left alone here for that reason. The assertion below covers both directions.
//
// The class is §4.5's whole vocabulary, read out of the generated enum rather than typed here.
func TestARefusalReachesTheWireNamingNoRecord(t *testing.T) {
	if len(protocol.Reason_name) == 0 {
		t.Fatal("protocol.Reason declares no values, so this gate read nothing at all")
	}
	groupId := make([]byte, store.GroupIdBytes)
	acceptances, refusals := 0, 0
	for value, name := range protocol.Reason_name {
		reason := protocol.Reason(value)
		// a store that ignores the rule, which is the case this exists for: `resultsOf` is
		// unexported and this is the boundary every implementation of the interface crosses
		answer := resultOf(groupId, &store.SubmitResult{
			Reason:       reason,
			RecordId:     41,
			CurrentEpoch: 7,
		})
		if answer.GetReason() != reason {
			t.Errorf("%s reached the wire as %v", name, answer.GetReason())
		}
		// §4.3.3 sets current_epoch on EVERY result so a stale client resynchronises in one
		// round trip, and §4.5's REASON_EPOCH_STALE is a refusal that carries it. Whether a
		// given refusal owes one is the store's judgement, made past check 7, and this function
		// transcribes it rather than second-guessing it
		if answer.GetCurrentEpoch() != 7 {
			t.Errorf("%s reached the wire with current_epoch %d and the store said 7; §4.3.3 sets it on every result and REASON_EPOCH_STALE is the refusal it exists for",
				name, answer.GetCurrentEpoch())
		}
		if store.Accepted(reason) {
			acceptances++
			if answer.GetRecordId() != 41 {
				t.Errorf("%s is an acceptance and its record_id did not reach the wire; §7.3's clamp is an acceptance carrying a notice, with a record id behind it, and a check written against REASON_OK alone drops the id of every clamped commit",
					name)
			}
			continue
		}
		refusals++
		if answer.GetRecordId() != 0 {
			t.Errorf("a refusal with %s reached the wire naming record %d; §6.1 step (3b) allocates nothing on a refusal, and the id it named is the group's own allocation counter handed to a party §4.5 tells nothing apart from a bad MAC",
				name, answer.GetRecordId())
		}
	}
	if acceptances == 0 || refusals == 0 {
		t.Fatalf("%d of §4.5's codes are acceptances and %d are refusals; a run that saw only one kind asserted nothing about the other", acceptances, refusals)
	}
	t.Logf("§4.5 declares %d codes: %d acceptances and %d refusals, each held to resultOf", len(protocol.Reason_name), acceptances, refusals)
}
