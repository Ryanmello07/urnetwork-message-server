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
func TestTheMemoryStoreMeetsTheContract(t *testing.T) {
	RunContract(t, func(limits Limits) Store { return NewMemoryStore(limits) })
}
