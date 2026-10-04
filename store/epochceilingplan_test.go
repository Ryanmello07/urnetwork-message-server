package store

import (
	"context"
	"encoding/json"
	"testing"
)

// THE EPOCH CEILING'S BILL, held to a property rather than to a number.
//
// [PgxStore.Fetch]'s `ceiling` CTE is `max(record_id) WHERE group_id = $1 AND epoch <= $5`, and
// until migration 011 no index carried `epoch` that it could use: the planner took PRIMARY KEY
// (group_id, record_id) backwards and evaluated the ceiling row by row, so a reader far behind
// paid for every row ABOVE its ceiling — traffic it will never be served — on every fetch it
// makes, including the zero-row polls of a reader whose cursor is already caught up to its own
// epoch. The party best placed to repeat that cheaply is a removed member still holding
// `read_key[n]`, which is the exact party the ceiling exists to bound.
//
// The property is the one the index was added for: THE BEHIND READER'S CEILING DOES NOT GET
// MORE EXPENSIVE WHEN THE GROUP GETS BUSIER ABOVE IT. Ten times the traffic above the ceiling,
// the same buffers below it. A buffer count on its own would be a machine-specific number that
// nobody could tell a regression from; a ratio between two runs on one machine is neither.
//
// What it is NOT is a claim that the ceiling is free. The planner chooses between two shapes by
// selectivity — the pkey scan costs the rows above, this index costs the rows at or below — so
// the bill is about min(above, below), and with both sides large the planner takes the pkey path
// and pays it. [PgxStore.Fetch]'s comment carries that measurement and ledger item 249 carries
// the restructure that would close it.
func TestTheEpochCeilingDoesNotPayForTrafficAboveIt(t *testing.T) {
	store := pgxTestStore(t, DefaultLimits())
	group := testBytes(32, 0x11)

	// ten records at epoch 1 — everything a reader stuck at epoch 1 may ever be served — and
	// then two rounds of traffic at epoch 2 that it may not
	insertCeilingRows(t, store, group, 1, 1, 10)
	insertCeilingRows(t, store, group, 2, 11, 20010)
	analyzeRecords(t, store)
	first := ceilingBuffers(t, store, group, 1)
	firstAbove := rowsAboveCeiling(t, store, group, 1)

	insertCeilingRows(t, store, group, 2, 20011, 200010)
	analyzeRecords(t, store)
	second := ceilingBuffers(t, store, group, 1)
	secondAbove := rowsAboveCeiling(t, store, group, 1)

	// the vacuity guard, and it is not a formality: if the second round had not landed, or had
	// landed at or below the ceiling, the assertion below would hold for a store that does the
	// worst possible thing. The control is the count of rows this reader may NOT see, taken
	// from the table itself, and it must have grown by the 10× the test claims.
	if secondAbove < 10*firstAbove {
		t.Fatalf("the traffic above the ceiling went %d -> %d, which is not the 10x this test measures the response to; the buffer comparison below would be about nothing",
			firstAbove, secondAbove)
	}

	// the property. The slack is two buffers and not a percentage: an index-only scan over a set
	// that did not change reads the same pages, and anything proportional to the traffic above
	// the ceiling shows up here as thousands rather than as two.
	if second > first+2 {
		t.Fatalf("a reader at epoch 1 paid %d buffers for its ceiling with %d records above it and %d with %d above — the cost is tracking traffic this reader is never served, which is what the (group_id, epoch, record_id) index of migration 011 exists to stop",
			first, firstAbove, second, secondAbove)
	}
	t.Logf("the ceiling at epoch 1 cost %d buffers under %d records above it and %d buffers under %d",
		first, firstAbove, second, secondAbove)
}

// Rows straight into §3.2's table, because this test is about the plan the `ceiling` CTE gets
// and not about anything §6.1 does on the way in.
func insertCeilingRows(t *testing.T, store *PgxStore, group []byte, epoch int64, from int64, to int64) {
	t.Helper()
	_, err := store.pool.Exec(context.Background(), `INSERT INTO message_record
        (group_id, record_id, sender_handle, epoch, stream_index, is_commit,
         retention_class, size_bucket, body_hash, ct_head)
        SELECT $1, g, $2, $3, g, false, 0, 0, $4, $4
          FROM generate_series($5::bigint, $6::bigint) AS g`,
		group, testBytes(16, 0x22), epoch, testBytes(32, 0x33), from, to)
	if err != nil {
		t.Fatalf("inserting records %d..%d at epoch %d: %v", from, to, epoch, err)
	}
}

// VACUUM as well as ANALYZE: the visibility map is what lets an index-only scan skip the heap,
// and a table that has only ever been written to has none, so a run without this measures the
// first fetch after a bulk load rather than the steady state.
func analyzeRecords(t *testing.T, store *PgxStore) {
	t.Helper()
	if _, err := store.pool.Exec(context.Background(), `VACUUM ANALYZE message_record`); err != nil {
		t.Fatalf("VACUUM ANALYZE: %v", err)
	}
}

// The buffers one execution of the `ceiling` CTE actually touched, off EXPLAIN's own accounting
// rather than off a timing. Shared hits and shared reads together, because an index that has
// fallen out of cache is the same amount of work.
func ceilingBuffers(t *testing.T, store *PgxStore, group []byte, ceiling int64) int {
	t.Helper()
	var document []byte
	err := store.pool.QueryRow(context.Background(),
		`EXPLAIN (ANALYZE, BUFFERS, COSTS OFF, FORMAT JSON)
         SELECT max(r.record_id) FROM message_record r
          WHERE r.group_id = $1 AND r.epoch <= $2`, group, ceiling).Scan(&document)
	if err != nil {
		t.Fatalf("EXPLAIN at ceiling %d: %v", ceiling, err)
	}
	explained := []struct {
		Plan struct {
			SharedHitBlocks  int `json:"Shared Hit Blocks"`
			SharedReadBlocks int `json:"Shared Read Blocks"`
		} `json:"Plan"`
	}{}
	if err := json.Unmarshal(document, &explained); err != nil {
		t.Fatalf("EXPLAIN FORMAT JSON at ceiling %d: %v", ceiling, err)
	}
	if len(explained) != 1 {
		t.Fatalf("EXPLAIN answered %d plans and this reads one", len(explained))
	}
	return explained[0].Plan.SharedHitBlocks + explained[0].Plan.SharedReadBlocks
}

// The complement of what a reader at `ceiling` is served: the rows it may not see, which is the
// quantity the corrected comment on [PgxStore.Fetch] says the old plan was paying for.
func rowsAboveCeiling(t *testing.T, store *PgxStore, group []byte, ceiling int64) int64 {
	t.Helper()
	var above int64
	err := store.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM message_record r
          WHERE r.group_id = $1 AND r.epoch > $2`, group, ceiling).Scan(&above)
	if err != nil {
		t.Fatalf("the rows above ceiling %d: %v", ceiling, err)
	}
	return above
}
