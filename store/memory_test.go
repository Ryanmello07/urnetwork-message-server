package store

import "testing"

// The memory implementation, against the contract every implementation of [Store] owes. There
// is nothing here but the call: a test the memory store had to itself would be a test the pgx
// store does not run, and the whole reason the contract is a function is that the second
// implementation runs the first one's tests unchanged.
//
// The factory takes the limits because §7.3's arithmetic is a function of them. On
// DefaultLimits both durable bounds are 0 and the media cap is above anything a fixture asks
// for, so a contract that could only build a store one way could not reach the clamp, the
// floor, or REASON_RETENTION_CLAMPED at all — the whole of §6.1 step (6) was arithmetic no
// scenario could observe.
//
// It goes through [heldToTheContract] rather than calling RunContract directly so that the
// banner in coverage_test.go can say which implementations this run covered. That is not
// bookkeeping for its own sake: the pgx contract skips without a database, a skip contributes
// nothing to the `ok` line, and without the banner a run that exercised one of the two
// implementations reads exactly like a run that exercised both.
func TestTheMemoryStoreMeetsTheContract(t *testing.T) {
	heldToTheContract(t, func(limits Limits) Store { return NewMemoryStore(limits) })
}
