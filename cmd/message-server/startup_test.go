package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/message-server/api"
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

	// §10.1's endpoint names §5.1 check 5's filter for what it is.
	//
	// This is the half of F1 that was not a defect in the code: the per-process filter was wired
	// for four passes and appeared on no not-built list, while the ops document said the list was
	// complete. The entry now comes from the filter itself, so a build that rewires it says so.
	if !strings.Contains(body, api.StoreKnownGroupsNotBuilt.What) {
		t.Fatalf("/readyz does not name what §5.1 check 5's filter substitutes for:\n%s", body)
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

	// §3.1's two halves, and the correction that split them.
	//
	// This block used to assert one precondition and to say, in its own comment, that the
	// tolerance was narrowed rather than the cluster reconfigured "because this cluster IS
	// correct". The cluster this suite runs on is `America/Phoenix`, seven hours out, and the
	// precondition was met on every run: it asked `SELECT now()::timestamp` through a pool that
	// pins `timezone = UTC` on every connection, so it was comparing against the value it was
	// checking for. It was not lenient; it was blind, and the sentence claiming otherwise was
	// false about the machine it was written on.
	//
	// clock_utc now reads the cluster on a connection that does not force the parameter, and
	// [freshSchemaDsn] asks this test's own session for UTC, which is what §10.3 asks an operator
	// for. So it is met here --
	if err := byName["clock_utc"].met(ctx); err != nil {
		t.Fatalf("clock_utc refuses against a session this test asked for UTC: %v", err)
	}
	// -- and it is observed REFUSING, for the reason it is named for and at §10.1's endpoint, in
	// TestReadinessRefusesOnAClusterWhoseTimezoneIsNotUtc, which needs no narrowed tolerance
	// because a wrong zone is something a DSN can ask for.
	//
	// clock_skew is the half that still cannot be arranged by configuration -- it needs two
	// machines that disagree about the instant -- so the tolerance trick stays where it belongs,
	// on the check it was always actually exercising.
	if err := byName["clock_skew"].met(ctx); err != nil {
		t.Fatalf("clock_skew refuses between this process and the database it is talking to: %v", err)
	}
	current.clockSlack = -1
	if err := byName["clock_skew"].met(ctx); err == nil {
		t.Fatal("clock_skew is met with a tolerance no clock can satisfy, so it is not comparing the database clock with anything")
	}
	current.clockSlack = clockSlack
	current.pool.Close()
	if err := byName["database_reachable"].met(ctx); err == nil {
		t.Fatal("database_reachable is met against a pool that has been closed, so nothing about the database is being asked")
	}
}

// §13 item 21, at the endpoint: "`/readyz` fails on a cluster whose timezone is not UTC."
//
// Before this, that sentence was false about this build and nothing said so. `clock_utc` asked
// `SELECT now()::timestamp` through a pool that pins `timezone = UTC` on every connection it hands
// out, so the only thing it could measure was host-vs-database skew — and on a cluster set to
// `America/Phoenix` it answered `ready`, `messagectl status` printed `clock: UTC`, and the ops
// document said the process "refuses to start otherwise". Three published claims, none true.
//
// The test is arranged rather than skipped, and that is the difference the fix makes. A wrong
// timezone is now something a deployment can ASK for — this one asks for `America/Phoenix`
// through the DSN's `options`, which is what a `postgresql.conf` or an `ALTER DATABASE` produces
// — so the precondition can be watched refusing without touching a shared cluster and without a
// narrowed tolerance standing in for the real cause.
//
// The second half is the one that would have caught the original defect: `clock_skew` must NOT be
// named. The two are different faults with different repairs — a postgresql.conf and an NTP
// daemon — and a single precondition covering both is how one of them went unobserved.
func TestReadinessRefusesOnAClusterWhoseTimezoneIsNotUtc(t *testing.T) {
	dsn := freshSchemaDsn(t)
	ctx := context.Background()

	pool, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatal("a pool for the migration job could not be created")
	}
	defer pool.Close()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	loaded.hostingJurisdiction = "US"

	for _, current := range []struct {
		zone    string
		refuses bool
		why     string
	}{
		{zone: "UTC", refuses: false, why: "§3.1's requirement, met"},
		{zone: "America/Phoenix", refuses: true, why: "seven hours out, in every month of the year"},
		{zone: "Europe/London", refuses: true, why: "zero every January and one hour every July: the half-year fault a single reading passes"},
	} {
		t.Run(current.zone, func(t *testing.T) {
			replica, err := newServer(ctx, deployment{
				ordinal:       "0",
				healthAddress: "127.0.0.1:0",
				dsn:           withSessionTimezone(t, dsn, current.zone),
				kek:           make([]byte, kekBytes),
				serverId:      make([]byte, serverIdBytes),
			}, loaded, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatalf("newServer: %v", err)
			}
			defer replica.Close()
			if err := replica.listen(); err != nil {
				t.Fatalf("listen: %v", err)
			}

			status, body := get(t, replica.healthAddress(), "/readyz")
			if status != http.StatusServiceUnavailable {
				t.Fatalf("/readyz answered %d on a replica with no credential:\n%s", status, body)
			}
			refused := refusedNames(body)

			if slices.Contains(refused, "clock_utc") != current.refuses {
				t.Fatalf("a cluster in %s (%s): /readyz refused on %v, and clock_utc should have been named: %v",
					current.zone, current.why, refused, current.refuses)
			}
			// the other half of §3.1 is a different fault and must not be blamed for this one
			if slices.Contains(refused, "clock_skew") {
				t.Fatalf("a cluster in %s made clock_skew refuse as well; the two machines' wall clocks have not moved and an operator sent to NTP by a timezone fault has been sent to the wrong place: %v",
					current.zone, refused)
			}
			// and nothing else moved: a wrong zone is one precondition and not a cascade
			without := []string{}
			for _, name := range refused {
				if name != "clock_utc" {
					without = append(without, name)
				}
			}
			if !slices.Equal(without, []string{"ordinal_credential", "connect_client_attached"}) {
				t.Fatalf("a cluster in %s changed the refusal set beyond clock_utc: %v", current.zone, refused)
			}
		})
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

// `--print-config` runs on the box it is documented for: one with no database to point at.
//
// Its own doc comment calls it "the one mode an operator does first on a new box — confirm the
// process can see its configuration, BEFORE it has a database to point at", and the ops document
// makes it step 1 of the bring-up sequence. It could not do that: `run` called `loadDeployment`
// before it consulted `printOnly`, and a missing DSN was a hard startup failure, so the first
// command of the documented sequence failed on the first box state it is documented for.
//
// This is also the first test in this repository that calls [run] at all — the signal path, the
// lifetime split and this branch had never been executed by the suite.
//
// Three assertions, and the third is the one that keeps the fix from becoming a different defect:
// the mode must still report the absence in words, because it exits 0 and an operator who reads
// exit 0 as "this will start" has been misled by a command that knew better.
func TestPrintConfigRunsOnABoxThatHasNoDatabaseYet(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, messageResource),
		[]byte("operator_host: ur.network\nhosting_jurisdiction: US\n"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", messageResource, err)
	}
	t.Setenv(resourceDirVariable, directory)
	t.Setenv(dsnVariable, "")

	printed := captureStdout(t, func() {
		if err := run(true); err != nil {
			t.Errorf("--print-config on a box with no database answered %v, and that box is the one it exists for", err)
		}
	})

	if !strings.Contains(printed, pgResource) || !strings.Contains(printed, "ABSENT") {
		t.Fatalf("--print-config did not report %s as ABSENT:\n%s", pgResource, printed)
	}
	// every other resource was still read, so the answer is whole rather than truncated at the
	// first thing that was missing
	for _, name := range []string{fleetResource, messageServerResource, messageResource} {
		if !strings.Contains(printed, name) {
			t.Fatalf("--print-config stopped before it reached %s:\n%s", name, printed)
		}
	}
	if !strings.Contains(printed, "WILL NOT START") {
		t.Fatalf("--print-config exits 0 on a configuration that cannot start and does not say so:\n%s", printed)
	}
	// and the third not-built half, which this mode used to leave out while the ops document said
	// it printed all of them. It is a fact of the binary's wiring rather than of a running process,
	// so a mode that opens nothing has no excuse to be silent about it.
	if !strings.Contains(printed, api.StoreKnownGroupsNotBuilt.What) {
		t.Fatalf("--print-config does not name what §5.1 check 5's filter substitutes for, and the ops document says this mode prints every not-built entry:\n%s", printed)
	}

	// and the refusal is unchanged for the mode that would actually open the database
	if err := run(false); !errors.Is(err, errResourceMissing) {
		t.Fatalf("starting with no DSN answered %v, want %v: §2.3 makes Postgres authoritative", err, errResourceMissing)
	}
}

// A bind failure names no address, which is the rule [server.announce] already keeps.
//
// §11.1's MUST-NOT list says "any IP address" without qualifying whose, and this build reads that
// literally in the announcement and in `health.go`, where it costs a real diagnostic — a pgx dial
// error "goes nowhere at all" for exactly this reason. The bind failure printed
// `listen tcp 127.0.0.1:443: bind: ...` two functions away. A rule that holds where it is expensive
// and lapses where it is cheap is not a rule, and the cheap lapse is the one nobody notices.
//
// The three cases are the three shapes a listen error takes, and they are different code paths in
// `net`: a port that is held (`*os.SyscallError` under an `*net.OpError`, whose message carries no
// address of its own), an address that will not parse (`*net.AddrError`, whose message IS the
// address), and a host that is not this machine's (`*os.SyscallError` again, on a different
// errno). The assertion is the same for all three and it is derived from the configured value
// rather than from a list of phrases: neither the host nor the port may appear.
func TestABindFailureNamesNoAddressSpecB111Forbids(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("taking a port: %v", err)
	}
	defer held.Close()
	taken := held.Addr().String()

	for _, current := range []struct {
		name    string
		address string
	}{
		{name: "a port that is already held", address: taken},
		{name: "an address that does not parse", address: "this-is-not-an-address"},
		{name: "a host this machine does not have", address: "203.0.113.9:9099"},
	} {
		t.Run(current.name, func(t *testing.T) {
			replica := &server{deploy: deployment{healthAddress: current.address}}
			err := replica.listen()
			if err == nil {
				replica.listener.Close()
				t.Fatalf("binding %q succeeded, so this case is not a bind failure at all", current.address)
			}

			// stated here rather than by calling namesTheAddress, which is the predicate under
			// test: a test that asserts a function against itself asserts nothing, and this one
			// would also inherit that function's deliberately conservative treatment of an address
			// it cannot split.
			message := err.Error()
			if strings.Contains(message, current.address) {
				t.Fatalf("the bind failure repeats the configured address: %v", err)
			}
			if host, port, splitErr := net.SplitHostPort(current.address); splitErr == nil {
				if host != "" && strings.Contains(message, host) {
					t.Fatalf("the bind failure names the host §11.1 forbids: %v", err)
				}
				if port != "" && strings.Contains(message, port) {
					t.Fatalf("the bind failure names the port: %v", err)
				}
			}
			t.Logf("%s -> %v", current.name, err)
		})
	}

	// The negative control for the predicate the fix rests on: it has to be able to say YES, or
	// the assertions above are three ways of reading an answer that is always no.
	if !namesTheAddress("listen tcp "+taken+": bind: ...", taken) {
		t.Fatal("namesTheAddress does not recognise the whole address inside a message, so it would clear anything")
	}
	host, port, _ := net.SplitHostPort(taken)
	if !namesTheAddress("something about "+host, taken) || !namesTheAddress("something about port "+port, taken) {
		t.Fatal("namesTheAddress recognises the address only when host and port appear together, and *net.AddrError separates them")
	}
	if namesTheAddress("bind: Only one usage of each socket address is normally permitted.", taken) {
		t.Fatal("namesTheAddress finds the address in a message that does not contain it, so every bind failure would be replaced by the generic sentence and no cause would ever reach an operator")
	}
}

// ── the fixtures ─────────────────────────────────────────────────────────────────────────

// What a function wrote to os.Stdout while it ran.
//
// [printConfiguration] writes to os.Stdout directly, which is right — it is a command's output and
// not a log — and it is why nothing had ever asserted on it.
func captureStdout(t *testing.T, during func()) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("a pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = write

	collected := make(chan string, 1)
	go func() {
		captured, _ := io.ReadAll(read)
		collected <- string(captured)
	}()

	during()

	os.Stdout = saved
	write.Close()
	output := <-collected
	read.Close()
	return output
}

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
	// §3.1's requirement, asked of this test's own sessions.
	//
	// It is `options` and not the `timezone` runtime parameter, because the timezone parameter is
	// exactly what [store.CheckClusterTimezone] strips before it asks — that key is the one
	// [store.NewPgxPool] writes, and stripping it is the whole mechanism of the check. A zone
	// arriving through `options` is the cluster speaking as far as any connection can tell, which
	// is what a `postgresql.conf` or an `ALTER DATABASE` produces.
	//
	// Without it this suite asserts §3.1 against whatever zone the developer's cluster happens to
	// be in — which on the machine this was written on is `America/Phoenix`, and every readiness
	// test in this file would refuse on clock_utc for a reason that has nothing to do with what it
	// is testing. The check is exercised in the OTHER direction, deliberately and from both sides:
	// store's TestASessionThatIsNotUtcIsRefusedIncludingOneThatIsUtcHalfTheYear, and this
	// directory's TestReadinessRefusesOnAClusterWhoseTimezoneIsNotUtc.
	query.Set("options", "-c timezone=UTC")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// The same DSN with a session zone that is not UTC, which is what §3.1 forbids and §13 item 21
// says `/readyz` must refuse.
func withSessionTimezone(t *testing.T, dsn string, zone string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("the schema DSN does not parse as a URL")
	}
	query := parsed.Query()
	query.Set("options", "-c timezone="+zone)
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
