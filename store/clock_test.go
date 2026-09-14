package store

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// §3.1 is two requirements and this suite used to have one check for both of them, which could
// only ever answer one.
//
// [CheckClockSkew] asks the POOL, and every pooled connection carries `timezone = UTC` in its
// startup packet — so its comparison runs against the value it is checking for. It is met on a
// cluster in any zone at all, which this test demonstrates rather than asserts: the pool's own
// session zone is read back and must be UTC no matter what the cluster is set to.
//
// [CheckClusterTimezone] opens a connection that does not send the parameter, and answers about
// the cluster. On a correctly configured cluster the two agree; the whole point is that on a
// misconfigured one they do not, and only one of them notices.
func TestTheClusterTimezoneCheckReadsTheClusterAndThePoolCannot(t *testing.T) {
	dsn := os.Getenv(pgxDsnVariable)
	if dsn == "" {
		t.Skipf("%s is unset, so nothing in this test touched PostgreSQL", pgxDsnVariable)
	}
	ctx := context.Background()

	// what the cluster is, read the way a client with no opinion reads it
	bare, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("a plain connection could not be opened")
	}
	defer bare.Close(context.Background())

	var zone string
	var monthsAtZeroOffset int
	if err := bare.QueryRow(ctx, `
        SELECT current_setting('TimeZone'),
               count(*) FILTER (WHERE month::timestamp = (month AT TIME ZONE 'UTC'))
          FROM generate_series(date_trunc('year', now()),
                               date_trunc('year', now()) + interval '11 months',
                               interval '1 month') AS month`).
		Scan(&zone, &monthsAtZeroOffset); err != nil {
		t.Fatalf("reading the cluster's own timezone: %v", err)
	}
	clusterIsUtc := monthsAtZeroOffset == 12
	t.Logf("this cluster is %q: %d of 12 months of this year render at a zero offset", zone, monthsAtZeroOffset)

	// the check under test agrees with that measurement, in whichever direction it points
	err = CheckClusterTimezone(ctx, dsn)
	if clusterIsUtc && err != nil {
		t.Fatalf("the cluster renders UTC in all twelve months and CheckClusterTimezone refuses it: %v", err)
	}
	if !clusterIsUtc && err == nil {
		t.Fatalf("this cluster is %q and renders UTC in only %d of 12 months, and CheckClusterTimezone is met against it", zone, monthsAtZeroOffset)
	}

	// and the pool cannot see any of that, which is the defect this pair of checks replaces
	pool, err := NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatal("a pool could not be created")
	}
	defer pool.Close()

	var pooled string
	if err := pool.QueryRow(ctx, `SELECT current_setting('TimeZone')`).Scan(&pooled); err != nil {
		t.Fatalf("reading the pool's session timezone: %v", err)
	}
	if pooled != "UTC" {
		t.Fatalf("a pooled connection's session timezone is %q; NewPgxPool pins it to UTC, and if it no longer does then §7.1's Go clock and §7.4's SQL clock are no longer writing into the same zone", pooled)
	}
	if err := CheckClockSkew(ctx, pool, 30*time.Second); err != nil {
		t.Fatalf("the skew check refuses through a pool whose own session is UTC: %v", err)
	}
	if !clusterIsUtc {
		t.Logf("MEASURED: this cluster is %q, seven-ish hours from UTC. clock_skew is MET through the pool and clock_utc REFUSES. That pair is the whole of finding F2: a single check asked through the pool answered `UTC` about this cluster on every run of this suite.", zone)
	}
}

// A session that is not UTC is refused, including one that is UTC for part of the year.
//
// This is the environment-independent half: it does not depend on how the cluster under it
// happens to be configured, because it forces the session's zone through the connection string's
// `options`, which [CheckClusterTimezone] does not strip — it strips only the `timezone` runtime
// parameter, which is the one [NewPgxPool] adds.
//
// `Etc/UTC` and `Europe/London` are the two cases a name test would get wrong in both directions:
// a list of spellings would have to contain the first, and would accept the second, whose offset
// is zero every January and one hour every July. A fleet under it prunes correctly all winter and
// an hour early all summer, which is the silent multi-hour retention error §3.1 exists to stop.
func TestASessionThatIsNotUtcIsRefusedIncludingOneThatIsUtcHalfTheYear(t *testing.T) {
	dsn := os.Getenv(pgxDsnVariable)
	if dsn == "" {
		t.Skipf("%s is unset, so nothing in this test touched PostgreSQL", pgxDsnVariable)
	}
	ctx := context.Background()

	for _, current := range []struct {
		zone     string
		accepted bool
		why      string
	}{
		{zone: "UTC", accepted: true, why: "§3.1's own spelling"},
		{zone: "Etc/UTC", accepted: true, why: "a different name for the same offset: the predicate is an offset and not a name"},
		{zone: "America/Phoenix", accepted: false, why: "seven hours out, in every month"},
		{zone: "Europe/London", accepted: false, why: "zero in January and plus one in July: a half-year fault a name test and a single reading both miss"},
		{zone: "Atlantic/Azores", accepted: false, why: "minus one in January and zero in July: the other half-year, in the other direction"},
	} {
		t.Run(current.zone, func(t *testing.T) {
			err := CheckClusterTimezone(ctx, withSessionTimezone(t, dsn, current.zone))
			if current.accepted && err != nil {
				t.Fatalf("a session in %s (%s) was refused: %v", current.zone, current.why, err)
			}
			if !current.accepted && err == nil {
				t.Fatalf("a session in %s was accepted as UTC, and it is %s", current.zone, current.why)
			}
		})
	}
}

// The same forced session, through a pool, is invisible: the skew check is met against every one
// of the zones above.
//
// It is the negative control for the test above and it is the finding itself. Without it, "the
// cluster check refuses Phoenix" is equally well explained by a suite that would have refused it
// anywhere — and the claim that matters is that the OTHER check, the one this repository had, does
// not.
func TestTheSkewCheckIsMetThroughAPoolInEveryZoneTheClusterCheckRefuses(t *testing.T) {
	dsn := os.Getenv(pgxDsnVariable)
	if dsn == "" {
		t.Skipf("%s is unset, so nothing in this test touched PostgreSQL", pgxDsnVariable)
	}
	ctx := context.Background()

	for _, zone := range []string{"America/Phoenix", "Europe/London", "Atlantic/Azores"} {
		t.Run(zone, func(t *testing.T) {
			forced := withSessionTimezone(t, dsn, zone)
			if err := CheckClusterTimezone(ctx, forced); err == nil {
				t.Fatalf("this zone is supposed to be one the cluster check refuses, and it did not")
			}
			pool, err := NewPgxPool(ctx, forced)
			if err != nil {
				t.Fatal("a pool could not be created")
			}
			defer pool.Close()
			if err := CheckClockSkew(ctx, pool, 30*time.Second); err != nil {
				t.Fatalf("the skew check refused through a pool, which pins timezone=UTC over this session: %v", err)
			}
			t.Logf("a %s session: the cluster check refuses it and the skew check through the pool is met", zone)
		})
	}
}

// The check works on the DSN shape the ops document tells an operator to write: one carrying
// pgxpool's own `pool_*` sizing keys.
//
// It is a regression test for a defect this check shipped with in draft and did not survive. It
// parsed with `pgx.ParseConfig`, which does not know `pool_max_conns` — it forwards it to the
// server as a runtime parameter, and the connection dies with `unrecognized configuration
// parameter`. Every readiness probe on a fleet whose `pg.yml` sizes its pool would have refused
// clock_utc forever, for a reason that has nothing to do with a timezone, and the suite would not
// have caught it because test DSNs are written without sizing.
func TestTheClusterTimezoneCheckWorksOnADsnThatCarriesPoolSizing(t *testing.T) {
	dsn := os.Getenv(pgxDsnVariable)
	if dsn == "" {
		t.Skipf("%s is unset, so nothing in this test touched PostgreSQL", pgxDsnVariable)
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("%s does not parse as a URL", pgxDsnVariable)
	}
	query := parsed.Query()
	// exactly the line docs/ops prints in its example pg.yml, plus the rest of the set
	// NewPgxPool's comment says pgxpool reads out of the connection string
	query.Set("pool_max_conns", "16")
	query.Set("pool_min_conns", "1")
	query.Set("pool_max_conn_idle_time", "30s")
	query.Set("pool_health_check_period", "1m")
	query.Set("options", "-c timezone=UTC")
	parsed.RawQuery = query.Encode()

	if err := CheckClusterTimezone(context.Background(), parsed.String()); err != nil {
		t.Fatalf("the cluster check refused a UTC session over a DSN carrying pool sizing: %v", err)
	}
}

// A DSN whose session asks the server for a particular timezone, through the startup packet's
// `options` rather than through the `timezone` runtime parameter.
//
// The distinction is what makes this a test and not a tautology: [CheckClusterTimezone] deletes
// `RuntimeParams["timezone"]`, because that is the key [NewPgxPool] writes. A zone arriving by
// `options` is the cluster speaking, as far as the connection is concerned, and is exactly what a
// `postgresql.conf` or an `ALTER DATABASE` would produce.
func withSessionTimezone(t *testing.T, dsn string, zone string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("%s does not parse as a URL", pgxDsnVariable)
	}
	query := parsed.Query()
	query.Set("options", "-c timezone="+zone)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
