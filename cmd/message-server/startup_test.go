package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/message-server/store"
)

// The first start on a bare box, which is what the VPS will do.
//
// This is the test the whole task turns on, and it is written as the sequence an operator
// actually performs rather than as a set of unit assertions: point the process at an EMPTY
// database, start it, watch `/readyz` refuse and say `migrations_at_head`, run the migration the
// way §10.3 says migrations are run, and watch that one precondition — and only that one — stop
// being named.
//
// What it does NOT assert, because it cannot and because pretending otherwise is the failure
// mode this repository has been bitten by: that a record can be submitted. That needs a
// `connect.Client` attached to an operator's platform, which needs a `network_client` credential
// an admin of that operator mints, and no test on this machine can produce one. The state this
// server is in at the end of this test is exactly the state a VPS is in after `apt install
// postgresql` and a `messagectl migrate`: healthy, migrated, and refusing readiness on the
// credential it has not been given. See transport.go.
func TestAFirstStartAgainstAnEmptyDatabaseServesHealthAndNamesWhatIsMissing(t *testing.T) {
	dsn := freshSchemaDsn(t)
	ctx := context.Background()

	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	loaded.hostingJurisdiction = "US"

	current, err := newServer(ctx, deployment{
		ordinal:       "0",
		healthAddress: "127.0.0.1:0",
		dsn:           dsn,
		kek:           make([]byte, kekBytes),
		serverId:      make([]byte, serverIdBytes),
		// no credential: this is the bare box, and §9.1's network_client has not been created
	}, loaded, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newServer against an empty database: %v", err)
	}
	defer current.Close()

	// the property transport.go argues for: with no credential there is no connect client and no
	// dispatcher, rather than a client that receives nothing while eight workers wait behind it
	if current.attachment != nil {
		t.Fatal("a deployment with no transport credential stood up a connect client anyway")
	}
	if current.dispatch != nil {
		t.Fatal("a deployment with no connect client stood up a frame dispatcher anyway; every counter behind it would read zero forever and look like a server nobody has messaged")
	}

	if err := current.listen(); err != nil {
		t.Fatalf("binding §10.1's private health port: %v", err)
	}
	address := current.healthAddress()
	if address == "" {
		t.Fatal("the health listener reports no address")
	}

	// §10.1: /healthz is "process alive" and answers even though nothing else is ready
	if status, body := get(t, address, "/healthz"); status != http.StatusOK || !strings.Contains(body, "alive") {
		t.Fatalf("/healthz answered %d %q on a process that is running", status, body)
	}

	// an empty database: migrations have not run, and that is what the endpoint must say
	status, body := get(t, address, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz answered %d against an empty database:\n%s", status, body)
	}
	beforeMigration := refusedNames(body)
	if !slices.Contains(beforeMigration, "migrations_at_head") {
		t.Fatalf("/readyz against an empty database did not refuse on migrations_at_head; it refused on %v", beforeMigration)
	}
	if slices.Contains(beforeMigration, "database_reachable") {
		t.Fatalf("/readyz says the database is unreachable, and this test just created a schema in it: %v", beforeMigration)
	}

	// §10.3: "a dedicated init job or `messagectl migrate`, never N replicas racing at startup".
	// This is that job, run against the same database the server has open.
	pool, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatalf("a pool for the migration job: %v", err)
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("the first migration against an empty database: %v", err)
	}

	status, body = get(t, address, "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz answered %d on a replica with no transport credential; §9.1 requires one per ordinal:\n%s", status, body)
	}
	afterMigration := refusedNames(body)
	if slices.Contains(afterMigration, "migrations_at_head") {
		t.Fatalf("the migration ran and /readyz still refuses on migrations_at_head: %v", afterMigration)
	}

	// exactly one precondition changed, and it is the one the migration is about. A readiness
	// that went from five refusals to one would also pass the line above
	removed, added := difference(beforeMigration, afterMigration)
	if !slices.Equal(removed, []string{"migrations_at_head"}) || 0 < len(added) {
		t.Fatalf("running the migration removed %v and added %v from the refusal set; it must remove exactly migrations_at_head",
			removed, added)
	}

	// what is left is the provisioning a bare box does not have, and nothing else
	if !slices.Equal(afterMigration, []string{"ordinal_credential", "connect_client_attached"}) {
		t.Fatalf("a migrated server with no credential refuses on %v; the only two things missing are §9.1's network_client and the attachment that needs it",
			afterMigration)
	}

	// the last precondition, reached: a pool that has been closed is a database that does not
	// answer. It is asserted through the precondition's own closure rather than through the
	// endpoint, because Close takes the endpoint down with the pool
	byName := map[string]precondition{}
	for _, item := range current.preconditions() {
		byName[item.name] = item
	}
	if err := byName["database_reachable"].met(ctx); err != nil {
		t.Fatalf("database_reachable refuses while the pool is open: %v", err)
	}

	// §13 item 21, reached: "/readyz fails on a cluster whose timezone is not UTC."
	//
	// The tolerance is narrowed rather than the cluster reconfigured, because this cluster IS
	// correct and reconfiguring PostgreSQL from a test is not something this suite may do. The
	// predicate is the same one a wrong timezone trips -- store.CheckClock compares
	// `SELECT now()::timestamp` against time.Now().UTC() and refuses outside the slack -- at a
	// nanosecond instead of at fourteen hours. Without this the precondition is one nothing in
	// this suite has ever seen refuse.
	if err := byName["clock_utc"].met(ctx); err != nil {
		t.Fatalf("clock_utc refuses against a cluster whose pool sets timezone=UTC: %v", err)
	}
	current.clockSlack = -1
	if err := byName["clock_utc"].met(ctx); err == nil {
		t.Fatal("clock_utc is met with a tolerance no clock can satisfy, so it is not comparing the database clock with anything")
	}
	current.clockSlack = clockSlack
	current.pool.Close()
	if err := byName["database_reachable"].met(ctx); err == nil {
		t.Fatal("database_reachable is met against a pool that has been closed, so nothing about the database is being asked")
	}
}

// §2.3's shutdown: the health port is released and the process can exit.
//
// A listener that outlives Close is a port a restarted replica cannot bind, which on a
// single-node deployment is a restart loop whose only symptom is "address already in use".
func TestShutdownReleasesTheHealthPort(t *testing.T) {
	dsn := freshSchemaDsn(t)
	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	loaded.hostingJurisdiction = "US"

	current, err := newServer(context.Background(), deployment{
		ordinal:       "0",
		healthAddress: "127.0.0.1:0",
		dsn:           dsn,
		kek:           make([]byte, kekBytes),
		serverId:      make([]byte, serverIdBytes),
	}, loaded, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if err := current.listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := current.healthAddress()
	if status, _ := get(t, address, "/healthz"); status != http.StatusOK {
		t.Fatalf("/healthz answered %d before shutdown", status)
	}

	current.Close()

	// readiness went false before anything was torn down, which is what a load balancer reads
	if !current.ready.draining.Load() {
		t.Fatal("Close did not mark this replica draining, so /readyz would have kept saying `ready` while the pool was closing")
	}
	// and the port is free: bind it again
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("the health port is still held after Close: %v", err)
	}
	listener.Close()
}

// ── the fixtures ─────────────────────────────────────────────────────────────────────────

// The DSN variable the store's own contract uses. The same one, deliberately: a developer who has
// set it for `store` has set it for this, and a CI job that sets one sets both.
const testDsnVariable = "URMESSAGE_TEST_DSN"

// A schema of this test's own, dropped afterwards, with a DSN bound to it.
//
// `search_path` rather than a database, because the migrations create 594 relations and a
// database per test is minutes of DDL; it is exactly what store's own pgx harness does and for
// the same reason.
func freshSchemaDsn(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(testDsnVariable)
	if dsn == "" {
		t.Skipf("%s is unset. NOTHING in this test ran: no database was opened, no migration was applied, and no readiness precondition that asks the database was evaluated. Set %s to a PostgreSQL DSN this suite may create and drop schemas in.",
			testDsnVariable, testDsnVariable)
	}

	ctx := context.Background()
	admin, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatalf("%s: a pool could not be created", testDsnVariable)
	}
	defer admin.Close()

	schema := fmt.Sprintf("urmsg_srv%d_%d", os.Getpid(), time.Now().UnixNano()%1000000)
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("creating schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		dropper, err := store.NewPgxPool(context.Background(), dsn)
		if err != nil {
			return
		}
		defer dropper.Close()
		dropper.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})

	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("%s does not parse as a URL", testDsnVariable)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	query.Set("pool_max_conns", strconv.Itoa(4))
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// One request against the health listener.
func get(t *testing.T, address string, path string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Get("http://" + address + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return response.StatusCode, string(body)
}

// The precondition names a `/readyz` body refused on, in the order it printed them.
func refusedNames(body string) []string {
	var names []string
	for _, line := range strings.Split(body, "\n") {
		rest, found := strings.CutPrefix(line, "not-ready ")
		if !found {
			continue
		}
		name, _, _ := strings.Cut(rest, ":")
		names = append(names, name)
	}
	return names
}

// What left one set and what joined it.
func difference(before []string, after []string) (removed []string, added []string) {
	for _, name := range before {
		if !slices.Contains(after, name) {
			removed = append(removed, name)
		}
	}
	for _, name := range after {
		if !slices.Contains(before, name) {
			added = append(added, name)
		}
	}
	return removed, added
}

// A database whose `migration_audit` exists and is missing a version is NOT at head.
//
// This test exists because a mutation survived without it, and the survivor is the interesting
// kind: [store.MigrationsAtHead] has two "not at head" branches, and only one of them had ever
// been reached. An empty database has no `migration_audit` at all and returns from the first
// branch; the loop's branch — the table is there and a version in the list is not in it — is the
// PARTIALLY MIGRATED state, and nothing created one.
//
// It is not a hypothetical state. [store.Migrate] runs each migration in its own transaction with
// its own audit row precisely so that "a failure leaves the database at the last migration that
// fully applied rather than half-way through one" — so a migration that fails on version N leaves
// exactly this shape, and it is the shape an operator is looking at when the init job goes red.
// A reader that answered "at head" for it would take traffic on a schema missing its last tables.
func TestADatabaseMissingOneMigrationIsNotAtHead(t *testing.T) {
	dsn := freshSchemaDsn(t)
	ctx := context.Background()

	pool, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatalf("a pool: %v", err)
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	head, _, err := store.MigrationsAtHead(ctx, pool)
	if err != nil || !head {
		t.Fatalf("a freshly migrated database is not at head: head=%v err=%v", head, err)
	}

	// the last migration's audit row, removed: the table is there, every earlier version is in it,
	// and the newest is not. That is a run that failed on the last one
	last := store.MigrationCount()
	if _, err := pool.Exec(ctx, `DELETE FROM migration_audit WHERE version = $1`, last); err != nil {
		t.Fatalf("removing the last audit row: %v", err)
	}
	head, missing, err := store.MigrationsAtHead(ctx, pool)
	if err != nil {
		t.Fatalf("MigrationsAtHead on a partially migrated database: %v", err)
	}
	if head {
		t.Fatal("a database whose migration_audit is missing its newest version reports at head; a replica would take traffic on a schema missing that migration's tables")
	}
	if missing != last {
		t.Fatalf("the missing version is reported as %d, want %d", missing, last)
	}

	// and a version in the MIDDLE, which is the run that failed early and is the one a reader that
	// only checked the count would answer wrongly for
	if _, err := pool.Exec(ctx, `INSERT INTO migration_audit (version, name) VALUES ($1, $2)`,
		last, "restored so the count is right again"); err != nil {
		t.Fatalf("restoring the last audit row: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM migration_audit WHERE version = 1`); err != nil {
		t.Fatalf("removing the first audit row: %v", err)
	}
	head, missing, err = store.MigrationsAtHead(ctx, pool)
	if err != nil {
		t.Fatalf("MigrationsAtHead with version 1 missing: %v", err)
	}
	if head {
		t.Fatal("a database missing migration 1 and holding every other version reports at head; the row count is right and the schema is not")
	}
	if missing != 1 {
		t.Fatalf("the missing version is reported as %d, want 1", missing)
	}
}

// §10.3's append-only rule is not suspended for a reader.
//
// > "**Append-only. A landed migration is never edited**, only superseded."
//
// [store.Migrate] refuses a version that ran under a different name, and so does
// [store.MigrationsAtHead] — and the second refusal is the one that matters at deploy time,
// because a replica reads rather than migrates. A reader that answered "at head" for a database
// whose audit disagrees with the binary's list would put a replica carrying one migration list on
// a schema built from another, which is the silent divergence §10.3's rule exists to prevent.
//
// This test exists because the clause survived a mutation without it: the refusal could be
// deleted from the read path and every suite stayed green.
func TestAMigrationThatRanUnderADifferentNameIsRefusedByTheReaderToo(t *testing.T) {
	dsn := freshSchemaDsn(t)
	ctx := context.Background()

	pool, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatalf("a pool: %v", err)
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	if _, err := pool.Exec(ctx, `UPDATE migration_audit SET name = $1 WHERE version = 1`,
		"001 something else entirely"); err != nil {
		t.Fatalf("rewriting an audit row: %v", err)
	}
	head, version, err := store.MigrationsAtHead(ctx, pool)
	if err == nil {
		t.Fatalf("MigrationsAtHead reported head=%v with no error for a database whose migration 1 ran under a different name; a replica would serve on a schema its own list does not describe", head)
	}
	if head {
		t.Fatal("MigrationsAtHead reported at head for a rewritten migration")
	}
	if version != 1 {
		t.Fatalf("the refusal names version %d, want the one that was rewritten (1)", version)
	}
}
