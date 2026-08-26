package store

import "testing"

// The memory implementation, against the contract every implementation of [Store] owes. There
// is nothing here but the call: a test the memory store had to itself would be a test the pgx
// store does not run, and the whole reason the contract is a function is that the second
// implementation runs the first one's tests unchanged.
func TestTheMemoryStoreMeetsTheContract(t *testing.T) {
	RunContract(t, func() Store { return NewMemoryStore(DefaultLimits()) })
}
