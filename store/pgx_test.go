package store

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/urnetwork/connect/protocol"
)

// The pgx implementation, against the contract every implementation of [Store] owes.
//
// There is nothing here but the call and the database it needs, for the reason memory_test.go
// gives: a test the pgx store had to itself would be a test the memory store does not run, and
// the whole reason the contract is a function is that the second implementation runs the first
// one's tests unchanged.
//
// # What a run without a database means
//
// This test needs PostgreSQL and skips without one. A skip contributes nothing to the `ok` line,
// so a run in which it skipped would otherwise look exactly like a run in which it passed —
// which is the project's own central failure, a test that cannot fail, arriving as a test that
// silently did not run. Two things answer it: the skip message below says what did not happen
// rather than what is missing, and the banner in coverage_test.go prints, after every run in
// every mode, which implementations of [Store] were held to [RunContract] and which were not.
//
// # Isolation
//
// Every store the contract builds gets its own schema with its own migrations, because the
// contract builds a store per scenario and its scenarios share group ids by construction —
// testGroupId(0x11) is the same 32 bytes in every one of them. The schemas are dropped in
// TestMain. One suite at a time per database: [reservePgxSchema] sweeps a previous run's
// leftovers, and it recognises a live run by its connections rather than by its name.
const pgxDsnVariable = "URMESSAGE_TEST_DSN"

// The pool sizing every contract store gets, as pgxpool's own connection-string keys.
//
// It is small, and the idle reaping is aggressive, because the contract builds a store per
// scenario and this harness has nowhere to close one: the factory RunContract calls is
// `func(Limits) Store` and a Store has no Close, so every pool stays open until TestMain. At
// pgxpool's defaults — max 4, idle 30 minutes, health check every minute — eighty scenarios hold
// eighty idle connections against a `max_connections` of 100, and the run dies with "sorry, too
// many clients already" somewhere in the middle. That is what this line is, and it is why the
// health check period is a second: MaxConnIdleTime is only acted on when the health check runs.
const pgxTestPoolSizing = "pool_max_conns=3&pool_min_conns=0&pool_max_conn_idle_time=1s&pool_health_check_period=1s"

func TestThePgxStoreMeetsTheContract(t *testing.T) {
	dsn := os.Getenv(pgxDsnVariable)
	if dsn == "" {
		contractSkipped(t, (*PgxStore)(nil), fmt.Sprintf("no %s in the environment, so §6.1's transaction was never executed against PostgreSQL", pgxDsnVariable))
		t.Skipf("%s is unset. The pgx store was NOT held to the contract in this run: no migration was applied, no transaction was opened, and nothing below says anything about it. Set %s to a PostgreSQL DSN this suite may create and drop schemas in.",
			pgxDsnVariable, pgxDsnVariable)
	}
	heldToTheContract(t, func(limits Limits) Store { return pgxSchemaStore(dsn, limits) })
}

// ── the two properties the interface's own comments decide, held while Submit is a stub ──

// §4.3.2 and §4.5: a `group_id` that already exists is REASON_REJECTED, and is deliberately not
// distinguished from a bad MAC.
//
// [RunContract] owns this property — TheFoundingCommitIsCheckedBeforeTheGroupExists and
// AnUnavailableGroupIsOneAnswer/ASecondCreateOfTheSameIdIsRejected are where it lives — and
// cannot reach it against this store yet, because both of those reach a second CreateGroup only
// after a Submit, and [PgxStore.Submit] is not written. So the property this half of the store
// is most able to get wrong is, for now, observed by nothing at all: a store that let the unique
// violation out as a `23505` error would be told by no test in this package. This is that test,
// and it comes out when the contract can run it.
func TestAPgxGroupIdThatAlreadyExistsIsRefusedTheWayABadMacIs(t *testing.T) {
	store := pgxTestStore(t, DefaultLimits())
	ctx := context.Background()
	group := testGroupId(0x11)
	createGroup(t, store, group, testHandle(0x20))

	again, err := store.CreateGroup(ctx, &CreateGroupRequest{
		GroupId:           group,
		InitialCommit:     commitRecord(testHandle(0x29), 0, 0, 1, 0x44),
		BootstrapWriteKey: testBytes(EpochKeyBytes, 0x55),
	})
	// the error is the whole point. `INSERT` without `ON CONFLICT DO NOTHING` answers here with
	// PostgreSQL's own text — the constraint's name, the table's name, and often the key's value
	// — to a party that has just learned from the difference that the group exists
	if err != nil {
		t.Fatalf("CreateGroup on an existing group_id answered the error %v; §4.5 makes this a refusal a client could have caused, and the driver's own message names the constraint that fired", err)
	}
	if again.Reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("CreateGroup on an existing id answered %v, want REASON_REJECTED", again.Reason)
	}

	// and the half the reason code alone does not hold: field for field the same result a group
	// that does not exist gets for a malformed founding commit
	malformed := commitRecord(testHandle(0x29), 0, 0, 1, 0x44)
	malformed.Attachment.Epoch.ExpectedWrapCount = 0
	badMac, err := store.CreateGroup(ctx, &CreateGroupRequest{
		GroupId:           testGroupId(0x77),
		InitialCommit:     malformed,
		BootstrapWriteKey: testBytes(EpochKeyBytes, 0x55),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if !reflect.DeepEqual(again, badMac) {
		t.Fatalf("a CreateGroup refused because the group already exists answered %+v and one refused for its own attachment answered %+v; every field that differs is a field an enumerator reads",
			again, badMac)
	}

	// the refused create wrote nothing: the existing group is where it was
	state := stateOf(t, store, group)
	if state.CurrentEpoch != 1 || state.NextRecordId != firstRecordId+1 {
		t.Fatalf("after a refused CreateGroup the group is at epoch %d and next_record_id %d, want 1 and %d", state.CurrentEpoch, state.NextRecordId, firstRecordId+1)
	}
}

// §7.5 and §4.5: a closed group answers exactly as an unknown one does, everywhere.
//
// [RunContract]'s AnUnavailableGroupIsOneAnswer owns this too, and cannot reach it here for the
// same reason — it opens its group with a Submit. What is held below is the part this half
// implements: [PgxStore.GroupState] and [PgxStore.CloseGroup]. Fetch is the other half's.
func TestAPgxGroupThatIsClosedAnswersLikeOneThatNeverExisted(t *testing.T) {
	store := pgxTestStore(t, DefaultLimits())
	ctx := context.Background()
	group := createGroup(t, store, testGroupId(0x11), testHandle(0x20))
	missing := testGroupId(0xEE)

	if err := store.CloseGroup(ctx, group); err != nil {
		t.Fatalf("CloseGroup: %v", err)
	}
	answers := map[string][2]error{
		"GroupState": {errorOf(store.GroupState(ctx, group)), errorOf(store.GroupState(ctx, missing))},
		// §7.5: a group closed twice is a group that is already unavailable, which is the same
		// answer an unknown one gives
		"CloseGroup": {store.CloseGroup(ctx, group), store.CloseGroup(ctx, missing)},
	}
	for method, pair := range answers {
		closed, unknown := pair[0], pair[1]
		if closed == nil || unknown == nil || !errors.Is(closed, unknown) {
			t.Errorf("%s answered %v for a closed group and %v for an unknown one; §6.1 step (1) reads zero rows for both and §4.5 refuses to tell them apart", method, closed, unknown)
		}
		if !errors.Is(closed, ErrGroupUnavailable) {
			t.Errorf("%s answered %v for a closed group, want %v", method, closed, ErrGroupUnavailable)
		}
	}
}

// ── the code this half adds that the contract does not own at all ────────────────────────

// §10.3's migration runner: it applies the list once, it is idempotent on a database already at
// head, and it refuses a list that has been edited under a version that already ran.
func TestThePgxMigrationsRunOnceAndAreAppendOnly(t *testing.T) {
	store := pgxTestStore(t, DefaultLimits())
	ctx := context.Background()

	// pgxTestStore migrated the schema on the way in; a second run is the deploy that reruns the
	// init job, and must write nothing
	if err := Migrate(ctx, store.pool); err != nil {
		t.Fatalf("a second Migrate on a database already at head: %v", err)
	}
	var applied int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM migration_audit`).Scan(&applied); err != nil {
		t.Fatalf("migration_audit: %v", err)
	}
	if applied != len(migrations) {
		t.Fatalf("migration_audit holds %d rows and the list has %d migrations; a runner that reapplied one would have failed on the CREATE TABLE, and one that skipped one leaves a table missing", applied, len(migrations))
	}

	// §10.3: "A landed migration is never edited, only superseded." The audit row is what holds
	// the list to it, so a version that ran under a different name is the edit being caught
	if _, err := store.pool.Exec(ctx, `UPDATE migration_audit SET name = $1 WHERE version = 1`, "001 something else entirely"); err != nil {
		t.Fatalf("migration_audit: %v", err)
	}
	if err := Migrate(ctx, store.pool); !errors.Is(err, errMigrationRewritten) {
		t.Fatalf("Migrate answered %v for a version that ran under a different name, want %v; without this an edited migration is silently skipped and the schema silently diverges from the list", err, errMigrationRewritten)
	}
}

// §5.5's wrap format, and what it is bound to.
//
// No database: this is arithmetic over bytes, and it is the one piece of this store a stolen
// database dump turns on. §5.3 is explicit that a dump alone must not yield write keys.
func TestTheEpochKeyWrapIsSpecB55s(t *testing.T) {
	ring, err := NewKekRing(7, testBytes(32, 0x01))
	if err != nil {
		t.Fatalf("NewKekRing: %v", err)
	}
	group := testGroupId(0x11)
	key := testBytes(EpochKeyBytes, 0x40)

	wrapped, err := ring.wrap(key, wrapWriteKey, group, 3)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	// §3.2 CHECKs this length in the column, so a wrap of any other size is a migration failure
	// at the first commit rather than here
	if len(wrapped) != wrapSize {
		t.Fatalf("a wrap is %d bytes and §5.5 fixes u8(kek_id) || nonce(12) || ct(32) || tag(16) at %d", len(wrapped), wrapSize)
	}
	if wrapped[0] != 7 {
		t.Errorf("the wrap leads with kek_id %d and the ring's current id is 7; §5.5's dual-KEK window is that byte and nothing else", wrapped[0])
	}
	// the key is not in the clear anywhere in it
	if strings.Contains(string(wrapped), string(key)) {
		t.Error("the wrapped key contains the key")
	}
	back, err := ring.unwrap(wrapped, wrapWriteKey, group, 3)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !reflect.DeepEqual(back, key) {
		t.Fatalf("unwrap returned %x for a wrap of %x", back, key)
	}

	// and what it is bound to. §5.1.1 selects exactly one key by epoch and never trials a set;
	// a wrap that opened wherever it was pasted would serve one epoch's reads under another's
	for name, opened := range map[string]func() ([]byte, error){
		"the same wrap read as the epoch's other key": func() ([]byte, error) {
			return ring.unwrap(wrapped, wrapReadKey, group, 3)
		},
		"the same wrap moved to another epoch": func() ([]byte, error) {
			return ring.unwrap(wrapped, wrapWriteKey, group, 4)
		},
		"the same wrap moved to another group": func() ([]byte, error) {
			return ring.unwrap(wrapped, wrapWriteKey, testGroupId(0x12), 3)
		},
		// the length check in unwrap, which is the one shape check this file carries and which
		// §3.1's own gate does not cover: no caller hands a wrap over, the database does
		"a stored wrap that is not 61 bytes": func() ([]byte, error) {
			return ring.unwrap(wrapped[:wrapSize-1], wrapWriteKey, group, 3)
		},
	} {
		if _, err := opened(); !errors.Is(err, errKekCorrupt) {
			t.Errorf("%s opened with %v, want %v", name, err, errKekCorrupt)
		}
	}

	// §5.5's rollover: a second KEK is loaded, the old id still unwraps, new wraps take the
	// current id. Retiring an id that a row still carries is what §5.5 says bricks every read
	rotated, err := NewKekRing(8, testBytes(32, 0x02))
	if err != nil {
		t.Fatalf("NewKekRing: %v", err)
	}
	if _, err := rotated.unwrap(wrapped, wrapWriteKey, group, 3); !errors.Is(err, errKekUnknown) {
		t.Errorf("a ring that does not hold kek_id 7 answered %v for a wrap under it, want %v", err, errKekUnknown)
	}
	if err := rotated.Add(7, testBytes(32, 0x01)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := rotated.unwrap(wrapped, wrapWriteKey, group, 3); err != nil {
		t.Errorf("with both KEKs loaded, a wrap under the old id answered %v", err)
	}
	fresh, err := rotated.wrap(key, wrapWriteKey, group, 3)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if fresh[0] != 8 {
		t.Errorf("a wrap made during the rollover window carries kek_id %d, want the ring's current 8", fresh[0])
	}
}

// ── the harness ──────────────────────────────────────────────────────────────────────────

// A store on its own schema, or a skip that says what did not run.
func pgxTestStore(t *testing.T, limits Limits) *PgxStore {
	t.Helper()
	dsn := os.Getenv(pgxDsnVariable)
	if dsn == "" {
		t.Skipf("%s is unset, so nothing in this test touched PostgreSQL", pgxDsnVariable)
	}
	return pgxSchemaStore(dsn, limits)
}

// The KEK this suite wraps under. §10.2 loads the real one from the vault resource
// `message_fleet.yml`; the id is deliberately neither 0 nor 1, so a wrap written with a
// hard-coded id fails to unwrap rather than passing by coincidence.
func testKekRing() *KekRing {
	ring, err := NewKekRing(7, testBytes(32, 0x5A))
	if err != nil {
		panic(err)
	}
	return ring
}

var (
	pgxMutex   sync.Mutex
	pgxSerial  int
	pgxAdmin   *pgxpool.Pool
	pgxPools   []*pgxpool.Pool
	pgxSchemas []string
)

// The prefix every schema and every connection of this run carries. The pid is in it so a run
// can recognise its own, and so the sweep can tell an abandoned schema from a live run's.
func pgxRunPrefix() string {
	return "urmsg_c" + strconv.Itoa(os.Getpid())
}

// A store of its own, migrated, on a schema of its own.
//
// A setup failure panics rather than failing a test: this is called from the contract's factory,
// which runs on whichever subtest goroutine asked for a store, and t.Fatal from the wrong
// goroutine reports nothing and stops nothing. A panic names the cause and takes the run down,
// which is the right outcome for a database that was configured and then could not be reached.
func pgxSchemaStore(dsn string, limits Limits) *PgxStore {
	ctx := context.Background()
	schema := reservePgxSchema(ctx, dsn)

	pool, err := NewPgxPool(ctx, pgxDsnFor(dsn, schema))
	if err != nil {
		panic(fmt.Errorf("a pool on schema %s: %w", schema, err))
	}
	// §3.1's own readiness check, on the pool this store is about to use. Without it the
	// RuntimeParams line in NewPgxPool is decoration: nothing else in this suite reads a
	// database clock, and a cluster in the wrong zone would be found by a user's media
	// disappearing hours early rather than here
	if err := CheckClock(ctx, pool, 30*time.Second); err != nil {
		panic(fmt.Errorf("the database clock on schema %s: %w", schema, err))
	}
	if err := Migrate(ctx, pool); err != nil {
		panic(fmt.Errorf("migrating schema %s: %w", schema, err))
	}

	pgxMutex.Lock()
	pgxPools = append(pgxPools, pool)
	pgxMutex.Unlock()
	return NewPgxStore(pool, limits, testKekRing())
}

// The DSN with a schema bound to it. `search_path` is not one of the keys pgconn reserves, so it
// arrives as a runtime parameter and every unqualified name in this package's SQL resolves in
// that schema — which is what lets the queries be written the way production runs them, with no
// schema in them at all.
func pgxDsnFor(dsn string, schema string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		panic(fmt.Errorf("%s: %w", pgxDsnVariable, err))
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	query.Set("application_name", pgxRunPrefix())
	for _, setting := range strings.Split(pgxTestPoolSizing, "&") {
		name, value, _ := strings.Cut(setting, "=")
		query.Set(name, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// A fresh schema, and on the first call the administrative pool and a sweep of whatever a
// previous run left behind.
func reservePgxSchema(ctx context.Context, dsn string) string {
	pgxMutex.Lock()
	defer pgxMutex.Unlock()
	if pgxAdmin == nil {
		admin, err := NewPgxPool(ctx, pgxDsnFor(dsn, "public"))
		if err != nil {
			panic(fmt.Errorf("%s: %w", pgxDsnVariable, err))
		}
		pgxAdmin = admin
		sweepAbandonedPgxSchemas(ctx, admin)
	}
	pgxSerial++
	schema := fmt.Sprintf("%s_%03d", pgxRunPrefix(), pgxSerial)
	if _, err := pgxAdmin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		panic(fmt.Errorf("creating schema %s: %w", schema, err))
	}
	pgxSchemas = append(pgxSchemas, schema)
	return schema
}

// Schemas from a run that did not get to drop its own — a killed process, a panic — carrying 594
// relations each. They are told from a live run's by its connections and not by its name: every
// pool this harness opens sets `application_name` to the run's prefix, so a prefix with no
// backend in `pg_stat_activity` is a run that is not there any more.
//
// The schema is <prefix>_<serial> and the connection carries <prefix>, so the run's identity is
// the name with its serial stripped. Comparing anything else here drops a LIVE run's schemas out
// from under it: split_part(nspname, '_', 2) is 'c26372' where the application_name is
// 'urmsg_c26372', which is a predicate that never matches and a sweep that is unconditional.
func sweepAbandonedPgxSchemas(ctx context.Context, admin *pgxpool.Pool) {
	rows, err := admin.Query(ctx, `
        SELECT nspname FROM pg_namespace
         WHERE nspname LIKE 'urmsg\_c%'
           AND regexp_replace(nspname, '_[0-9]+$', '') NOT IN (
               SELECT application_name FROM pg_stat_activity WHERE application_name LIKE 'urmsg\_c%')`)
	if err != nil {
		return
	}
	abandoned := []string{}
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err == nil {
			abandoned = append(abandoned, schema)
		}
	}
	rows.Close()
	for _, schema := range abandoned {
		admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
	}
	if len(abandoned) != 0 {
		fmt.Fprintf(os.Stderr, "dropped %d schemas left by a run that did not finish\n", len(abandoned))
	}
}

// Every pool closed and every schema dropped. Called from TestMain, so it runs whether the suite
// passed or failed — a red run that left its schemas behind would make the next run's sweep the
// only thing standing between this database and a pg_class holding tens of thousands of
// relations.
func releasePgxHarness() {
	pgxMutex.Lock()
	defer pgxMutex.Unlock()
	for _, pool := range pgxPools {
		pool.Close()
	}
	pgxPools = nil
	if pgxAdmin == nil {
		return
	}
	ctx := context.Background()
	for _, schema := range pgxSchemas {
		if _, err := pgxAdmin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			fmt.Fprintf(os.Stderr, "dropping schema %s: %v\n", schema, err)
		}
	}
	pgxSchemas = nil
	pgxAdmin.Close()
	pgxAdmin = nil
}
