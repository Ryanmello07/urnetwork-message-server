package store

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/message/protocol"
)

// The identity plan's Task 18, Properties 1 and 3, each by the name the plan gives its test, and
// each against both implementations: the memory store always, and the pgx store when
// URMESSAGE_TEST_DSN names a database, as TestThePgxStoreMeetsTheContract does. RunContract runs
// Property 3's scenario again inside the contract, where the refusal and sentinel gates count what
// it produced; these are the names a mutation's kill is read off.

// THE LINK BOX HOLDS NO DEPOSITOR (Property 1; Spec B §13's test 42, in the form of test 40): no
// row of either table holds a `client_id`, or anything made from one.
//
// The store is handed no client id at all, so the property is held where a depositor would have to
// be kept: in the rows. Two halves, in both stores:
//   - THE COLUMNS. 013's and 014's tables have exactly §3.2's columns, read from the catalog for
//     the pgx store and from the row types' tags for the memory store. A column added to keep a
//     depositor, by a migration or by a field, fails here by name.
//   - THE VALUES. A workload of every arm, then every row read back whole: each column holds the
//     value the workload handed in for it, or the store's own time or count, and nothing else. A
//     depositor kept in a column that already exists fails here.
//
// Each half has its control, run in the same test: the comparison is shown a dump with one column
// added and a dump with one value changed, and must report each.
func TestTheLinkBoxHoldsNoDepositor(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		store := NewMemoryStore(DefaultLimits())
		runLinkBoxWorkload(t, store)
		assertTheLinkBoxRowsAreTheWorkloads(t, memoryLinkBoxColumns(t), memoryLinkBoxDump(t, store))
	})
	t.Run("pgx", func(t *testing.T) {
		store := pgxTestStore(t, DefaultLimits())
		runLinkBoxWorkload(t, store)
		assertTheLinkBoxRowsAreTheWorkloads(t, pgxLinkBoxColumns(t, store), pgxLinkBoxDump(t, store))
	})
}

// COLLECT, RETIRE AND REPLAY (Property 3; Spec B §13's test 44).
func TestCollectDeletesThroughItsAcknowledgementAndRetireKeepsATombstone(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		contractLinkBoxCollectAndRetire(t, func(limits Limits) Store { return NewMemoryStore(limits) }, newRecorder())
	})
	t.Run("pgx", func(t *testing.T) {
		dsn := os.Getenv(pgxDsnVariable)
		if dsn == "" {
			t.Skipf("%s is unset, so the pgx store was NOT held to this property in this run", pgxDsnVariable)
		}
		contractLinkBoxCollectAndRetire(t, func(limits Limits) Store { return pgxSchemaStore(dsn, limits) }, newRecorder())
	})
}

func newRecorder() *recorder {
	return &recorder{reasons: map[protocol.Reason]int{}, sentinels: map[string]int{}}
}

// §3.2's 013 and 014, column for column, in the order the DDL gives them.
var linkBoxTableColumns = map[string][]string{
	"message_rendezvous": {"rendezvous_id", "kind", "deposit_verify_pub", "collect_verify_pub",
		"card_xwing_pub", "public_ct", "alg_id", "next_deposit_id", "deposit_count", "refused_count",
		"register_time", "refresh_time", "expire_time", "retired_time", "reclaim_after"},
	"message_rendezvous_deposit": {"rendezvous_id", "deposit_id", "deposit_hash", "deposit_ct",
		"create_time", "prune_after"},
}

// One row, column by column, each value as the comparison holds it: a []byte, an int64, a UTC
// time.Time, or nil for NULL.
type linkBoxRow map[string]any

// Every row of both tables, by table.
type linkBoxDump map[string][]linkBoxRow

// The workload: every arm, in an order that leaves something in every column.
//
//	box A at 0: deposits 1 at 10 and 2 at 20, a third refused at 30, a collect acknowledging 1 at
//	40, so that A holds deposit 2, has taken 2, waits on 1 and has its refusal zeroed;
//	box B at 50, retired at 60, with nothing in it.
func runLinkBoxWorkload(t *testing.T, store LinkBoxes) {
	t.Helper()
	seen := newRecorder()
	a := linkBoxRegistration(0x30)
	registerLinkBox(t, store, seen, a, linkBoxEpoch)
	depositLinkBox(t, store, seen, a.RendezvousId, 0x31, linkBoxAt(10))
	depositLinkBox(t, store, seen, a.RendezvousId, 0x32, linkBoxAt(20))
	if refused := depositLinkBox(t, store, seen, a.RendezvousId, 0x33, linkBoxAt(30)); refused.Reason != protocol.Reason_REASON_CARD_RATE_LIMITED {
		t.Fatalf("the workload's third deposit answered %v", refused.Reason)
	}
	collectLinkBox(t, store, seen, &LinkBoxCollectRequest{RendezvousId: a.RendezvousId, AckThroughDepositId: 1}, linkBoxAt(40))
	b := linkBoxRegistration(0x40)
	registerLinkBox(t, store, seen, b, linkBoxAt(50))
	retireLinkBox(t, store, seen, b.RendezvousId, linkBoxAt(60))
}

// What the workload must leave, and nothing else.
func expectedLinkBoxDump() linkBoxDump {
	a := linkBoxRegistration(0x30)
	b := linkBoxRegistration(0x40)
	second, secondHash := linkBoxDeposit(0x32)
	retired := linkBoxAt(60)
	return linkBoxDump{
		"message_rendezvous": {
			{"rendezvous_id": a.RendezvousId, "kind": int64(LinkBoxKind), "deposit_verify_pub": a.DepositVerifyPub,
				"collect_verify_pub": a.CollectVerifyPub, "card_xwing_pub": nil, "public_ct": a.PublicCt,
				"alg_id": int64(LinkBoxAlgId), "next_deposit_id": int64(3), "deposit_count": int64(1),
				"refused_count": int64(0), "register_time": linkBoxEpoch, "refresh_time": linkBoxEpoch,
				"expire_time": linkBoxAt(600), "retired_time": nil, "reclaim_after": linkBoxAt(600)},
			{"rendezvous_id": b.RendezvousId, "kind": int64(LinkBoxKind), "deposit_verify_pub": b.DepositVerifyPub,
				"collect_verify_pub": b.CollectVerifyPub, "card_xwing_pub": nil, "public_ct": b.PublicCt,
				"alg_id": int64(LinkBoxAlgId), "next_deposit_id": int64(1), "deposit_count": int64(0),
				"refused_count": int64(0), "register_time": linkBoxAt(50), "refresh_time": linkBoxAt(50),
				"expire_time": linkBoxAt(650), "retired_time": retired, "reclaim_after": linkBoxAt(650)},
		},
		"message_rendezvous_deposit": {
			{"rendezvous_id": a.RendezvousId, "deposit_id": int64(2), "deposit_hash": secondHash,
				"deposit_ct": second, "create_time": linkBoxAt(20), "prune_after": linkBoxAt(600)},
		},
	}
}

func assertTheLinkBoxRowsAreTheWorkloads(t *testing.T, columns map[string][]string, dump linkBoxDump) {
	t.Helper()
	// the columns, against §3.2's lists, and the comparison's control in the same breath
	if findings := linkBoxColumnFindings(columns); len(findings) != 0 {
		t.Fatalf("the tables are not §3.2's:\n  %s", strings.Join(findings, "\n  "))
	}
	planted := map[string][]string{}
	for table, names := range columns {
		planted[table] = slices.Clone(names)
	}
	planted["message_rendezvous_deposit"] = append(planted["message_rendezvous_deposit"], "client_id")
	if findings := linkBoxColumnFindings(planted); len(findings) != 1 || !strings.Contains(findings[0], "client_id") {
		t.Fatalf("the column comparison, shown a deposit table with a client_id column, reported %v; it cannot tell the property from its failure", findings)
	}

	// the values, against what the workload handed in, and their control
	want := expectedLinkBoxDump()
	if findings := linkBoxDumpFindings(dump, want); len(findings) != 0 {
		t.Fatalf("the rows hold something the workload did not hand in for them:\n  %s", strings.Join(findings, "\n  "))
	}
	tampered := linkBoxDump{}
	for table, rows := range dump {
		for _, row := range rows {
			copied := linkBoxRow{}
			for name, value := range row {
				copied[name] = value
			}
			tampered[table] = append(tampered[table], copied)
		}
	}
	tampered["message_rendezvous_deposit"][0]["deposit_ct"] = testBytes(LinkDepositBytes, 0xC1)
	if findings := linkBoxDumpFindings(tampered, want); len(findings) != 1 || !strings.Contains(findings[0], "deposit_ct") {
		t.Fatalf("the value comparison, shown a deposit whose octets were changed, reported %v; it cannot tell the property from its failure", findings)
	}
	t.Logf("%d rows of message_rendezvous and %d of message_rendezvous_deposit, every column the workload's",
		len(dump["message_rendezvous"]), len(dump["message_rendezvous_deposit"]))
}

func linkBoxColumnFindings(columns map[string][]string) []string {
	findings := []string{}
	for table, want := range linkBoxTableColumns {
		got := slices.Clone(columns[table])
		wantSorted := slices.Clone(want)
		slices.Sort(got)
		slices.Sort(wantSorted)
		for _, name := range got {
			if !slices.Contains(wantSorted, name) {
				findings = append(findings, fmt.Sprintf("%s has the column %s, which §3.2 does not give it", table, name))
			}
		}
		for _, name := range wantSorted {
			if !slices.Contains(got, name) {
				findings = append(findings, fmt.Sprintf("%s lacks §3.2's column %s", table, name))
			}
		}
	}
	for table := range columns {
		if _, known := linkBoxTableColumns[table]; !known {
			findings = append(findings, fmt.Sprintf("a table %s was read, which is neither 013's nor 014's", table))
		}
	}
	slices.Sort(findings)
	return findings
}

// Rows are matched by their key: the rendezvous id, and the deposit id beside it.
func linkBoxDumpFindings(got linkBoxDump, want linkBoxDump) []string {
	key := func(row linkBoxRow) string {
		return fmt.Sprintf("%x/%v", row["rendezvous_id"], row["deposit_id"])
	}
	findings := []string{}
	for table := range linkBoxTableColumns {
		wanted := map[string]linkBoxRow{}
		for _, row := range want[table] {
			wanted[key(row)] = row
		}
		found := map[string]bool{}
		for _, row := range got[table] {
			k := key(row)
			found[k] = true
			expected, known := wanted[k]
			if !known {
				findings = append(findings, fmt.Sprintf("%s holds a row %.8s that the workload did not make", table, k))
				continue
			}
			for name, value := range row {
				if !reflect.DeepEqual(value, expected[name]) {
					findings = append(findings, fmt.Sprintf("%s's row %.8s holds %s = %s, want %s", table, k, name, describeLinkBoxValue(value), describeLinkBoxValue(expected[name])))
				}
			}
			for name := range expected {
				if _, present := row[name]; !present {
					findings = append(findings, fmt.Sprintf("%s's row %.8s has no %s", table, k, name))
				}
			}
		}
		for k := range wanted {
			if !found[k] {
				findings = append(findings, fmt.Sprintf("%s lacks the row %.8s the workload made", table, k))
			}
		}
	}
	slices.Sort(findings)
	return findings
}

func describeLinkBoxValue(value any) string {
	switch typed := value.(type) {
	case []byte:
		return fmt.Sprintf("%d octets %.8x", len(typed), typed)
	case time.Time:
		return typed.Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

// A column's value as the comparison holds it.
func linkBoxValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case []byte:
		if typed == nil {
			return nil
		}
		return slices.Clone(typed)
	case int16:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case time.Time:
		return typed.UTC()
	case *time.Time:
		if typed == nil {
			return nil
		}
		return typed.UTC()
	default:
		return fmt.Sprintf("an unexpected %T", value)
	}
}

// ── the memory store's rows, read by reflection over the row types' tags ─────────────────────

func memoryLinkBoxColumns(t *testing.T) map[string][]string {
	t.Helper()
	return map[string][]string{
		"message_rendezvous":         taggedColumns(t, reflect.TypeOf(memoryLinkBoxRow{})),
		"message_rendezvous_deposit": taggedColumns(t, reflect.TypeOf(memoryLinkDepositRow{})),
	}
}

// Every field's `column` tag. A field with none is a finding of its own: the type would hold
// something no column names.
func taggedColumns(t *testing.T, kind reflect.Type) []string {
	t.Helper()
	names := []string{}
	for index := range kind.NumField() {
		field := kind.Field(index)
		name, tagged := field.Tag.Lookup("column")
		if !tagged {
			t.Fatalf("%s.%s carries no column tag, so it is a value the row holds that no column of §3.2 names", kind.Name(), field.Name)
		}
		names = append(names, name)
	}
	return names
}

func taggedRow(row any) linkBoxRow {
	value := reflect.ValueOf(row).Elem()
	kind := value.Type()
	out := linkBoxRow{}
	for index := range kind.NumField() {
		out[kind.Field(index).Tag.Get("column")] = linkBoxValue(value.Field(index).Interface())
	}
	return out
}

func memoryLinkBoxDump(t *testing.T, store *MemoryStore) linkBoxDump {
	t.Helper()
	store.boxMutex.Lock()
	defer store.boxMutex.Unlock()
	dump := linkBoxDump{}
	for _, row := range store.boxes {
		dump["message_rendezvous"] = append(dump["message_rendezvous"], taggedRow(row))
	}
	for _, deposits := range store.deposits {
		for _, row := range deposits {
			dump["message_rendezvous_deposit"] = append(dump["message_rendezvous_deposit"], taggedRow(row))
		}
	}
	return dump
}

// ── the pgx store's rows, read from the catalog and with SELECT * ────────────────────────────

func pgxLinkBoxColumns(t *testing.T, store *PgxStore) map[string][]string {
	t.Helper()
	columns := map[string][]string{}
	rows, err := store.pool.Query(context.Background(), `
        SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name IN ('message_rendezvous', 'message_rendezvous_deposit')`)
	if err != nil {
		t.Fatalf("information_schema.columns: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatalf("information_schema.columns: %v", err)
		}
		columns[table] = append(columns[table], column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("information_schema.columns: %v", err)
	}
	return columns
}

func pgxLinkBoxDump(t *testing.T, store *PgxStore) linkBoxDump {
	t.Helper()
	dump := linkBoxDump{}
	for table := range linkBoxTableColumns {
		rows, err := store.pool.Query(context.Background(), `SELECT * FROM `+table)
		if err != nil {
			t.Fatalf("SELECT * FROM %s: %v", table, err)
		}
		fields := rows.FieldDescriptions()
		for rows.Next() {
			values, err := rows.Values()
			if err != nil {
				rows.Close()
				t.Fatalf("SELECT * FROM %s: %v", table, err)
			}
			row := linkBoxRow{}
			for index, field := range fields {
				row[field.Name] = linkBoxValue(values[index])
			}
			dump[table] = append(dump[table], row)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("SELECT * FROM %s: %v", table, err)
		}
	}
	return dump
}

// §7.4's LOCK (the identity plan's Task 20): a batch that finds another sweeper holding the lock on
// its schema does nothing and answers Skipped, and the same batch once the lock is released sweeps.
// PostgreSQL only, since the memory store has no second sweeper to meet. The control is the batch
// after the release, which reclaims the box the skipped one left.
func TestASweepBatchSkipsWhileAnotherSweeperHoldsTheLock(t *testing.T) {
	store := pgxTestStore(t, DefaultLimits())
	ctx := context.Background()
	registration := linkBoxRegistration(0x10)
	if registered, err := store.RegisterLinkBox(ctx, registration, linkBoxAt(0), linkBoxTtl); err != nil || registered.Reason != protocol.Reason_REASON_OK {
		t.Fatalf("RegisterLinkBox: %v (%v)", registered, err)
	}

	holder, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer holder.Rollback(ctx)
	var held bool
	if err := holder.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1, hashtext(current_schema()))`,
		linkBoxSweepAdvisoryLock).Scan(&held); err != nil || !held {
		t.Fatalf("the other sweeper could not take the lock: %v, %v", held, err)
	}

	swept, err := store.SweepLinkBoxes(ctx, linkBoxAt(600), LinkBoxSweepBounds{})
	if err != nil || *swept != (LinkBoxesSwept{Skipped: true}) {
		t.Fatalf("a batch while another sweeper held the lock answered %+v (%v), want Skipped and nothing else", swept, err)
	}
	if _, err := store.LinkBox(ctx, registration.RendezvousId); err != nil {
		t.Fatalf("a skipped batch deleted the expired box: %v", err)
	}

	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	swept, err = store.SweepLinkBoxes(ctx, linkBoxAt(600), LinkBoxSweepBounds{})
	if err != nil || *swept != (LinkBoxesSwept{Boxes: 1}) {
		t.Fatalf("the control, the batch after the lock was released, answered %+v (%v), want the expired box", swept, err)
	}
}
