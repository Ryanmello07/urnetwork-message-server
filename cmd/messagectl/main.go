// The ops CLI of spec B §2.1: migrate, sweep-now, capability dump, key rotate.
//
// One of the four is implemented, and it is the one §10.3 makes structural rather than
// convenient: "Who executes migrations: a dedicated init job or `messagectl migrate`, **never** N
// replicas racing at startup, holding `pg_advisory_lock(<migration constant>)` for the duration.
// `/readyz` asserts 'migrations at head' and fails until the job has run." The message server
// therefore has no migration path at all — it reads whether the list has run and refuses
// readiness if it has not — and this is where a migration is run from.
//
// The other three say so per subcommand rather than printing a usage banner that reads like a
// working tool.
//
// May import: any package of this module, for the same reason as the server entrypoint — an
// ops CLI that cannot reach store cannot run a migration.
//
//urmsg:mayimport *
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/urnetwork/message-server/store"
)

// The subcommands §2.1 names, with the section each is built against.
var subcommands = []struct {
	name  string
	what  string
	run   func(ctx context.Context, arguments []string) error
	built bool
}{
	{"migrate", "apply the ordered migration list under pg_advisory_lock (§10.3)", migrate, true},
	{"status", "report whether this database is at the head of the migration list (§10.1)", status, true},
	{"sweep-now", "run the retention sweep once, --until-clean after a restore (§10.4 trap 1)", nil, false},
	{"capabilities", "dump the Capabilities this fleet advertises, and its capability_version (§10.2)", nil, false},
	{"rotate", "rotate a KEK or the fleet transport credential (§5.5, §10.5)", nil, false},
}

// Where the DSN comes from. The same two places the server reads it from, in the same order, so
// that "the migration ran against the database the server will open" is true by construction
// rather than by an operator typing the same string twice.
const (
	dsnVariable         = "URMESSAGE_PG_DSN"
	resourceDirVariable = "URMESSAGE_RESOURCE_DIR"
	pgResource          = "pg.yml"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stdout, "messagectl <subcommand>\n\n")
		for _, subcommand := range subcommands {
			built := ""
			if !subcommand.built {
				built = "   [not implemented in this build]"
			}
			fmt.Fprintf(os.Stdout, "  %-14s %s%s\n", subcommand.name, subcommand.what, built)
		}
		fmt.Fprintf(os.Stdout, "\nThe DSN is read from %s, or from `dsn` in %s/%s.\n",
			dsnVariable, resourceDirVariable, pgResource)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for _, subcommand := range subcommands {
		if subcommand.name != os.Args[1] {
			continue
		}
		if !subcommand.built {
			break
		}
		if err := subcommand.run(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "messagectl %s: %v\n", subcommand.name, err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "messagectl: %s is not implemented in this build\n", os.Args[1])
	os.Exit(1)
}

// §10.3's migration run: the whole ordered list, once, under the advisory lock
// [store.Migrate] takes for the duration.
//
// It is idempotent by construction — a version already in `migration_audit` is skipped — so
// running it against a database at head is the no-op an init job on every deploy needs it to be,
// and running it against an empty database is the first start the VPS will do.
func migrate(ctx context.Context, arguments []string) error {
	pool, err := open(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	before, missing, _ := store.MigrationsAtHead(ctx, pool)
	if before {
		fmt.Fprintf(os.Stdout, "already at head: %d migrations\n", store.MigrationCount())
		return nil
	}
	fmt.Fprintf(os.Stdout, "applying from migration %d of %d\n", missing, store.MigrationCount())
	if err := store.Migrate(ctx, pool); err != nil {
		return err
	}
	head, stillMissing, err := store.MigrationsAtHead(ctx, pool)
	if err != nil {
		return err
	}
	if !head {
		return fmt.Errorf("Migrate returned without an error and migration %d of %d has still not run",
			stillMissing, store.MigrationCount())
	}
	fmt.Fprintf(os.Stdout, "at head: %d migrations\n", store.MigrationCount())
	return nil
}

// The question §10.1's readiness endpoint asks, asked from a shell.
//
// It exists because the answer an operator needs during a deploy is "has the job run", and the
// only other way to get it is to read `/readyz` on a replica that may be refusing for four other
// reasons at the same time.
func status(ctx context.Context, arguments []string) error {
	dsn, pool, err := openWithDsn(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Two lines and not one, because they used to be one — and the one that was printed could not
	// fail for the reason it was named for. `clock: UTC` was printed against a cluster configured
	// `America/Phoenix`: every pooled connection pins `timezone = UTC` in its startup packet, so
	// the comparison ran against the value it was checking for. The zone is now read on a
	// connection that does not send that parameter, and the skew comparison keeps its own line
	// under its own name, because the two send an operator to different places — a postgresql.conf
	// and an NTP daemon.
	if err := store.CheckClusterTimezone(ctx, dsn); err != nil {
		fmt.Fprintf(os.Stdout, "timezone:   NOT UTC — §3.1 makes this normative and §7.4 would prune against it\n")
	} else {
		fmt.Fprintf(os.Stdout, "timezone:   UTC\n")
	}
	if err := store.CheckClockSkew(ctx, pool, 30*time.Second); err != nil {
		fmt.Fprintf(os.Stdout, "clock skew: the database's wall clock and this host's disagree by more than 30s; §7.1 reads one and §7.4 the other\n")
	} else {
		fmt.Fprintf(os.Stdout, "clock skew: within 30s\n")
	}
	head, missing, err := store.MigrationsAtHead(ctx, pool)
	if err != nil {
		return err
	}
	if head {
		fmt.Fprintf(os.Stdout, "migrations: at head, %d applied\n", store.MigrationCount())
		return nil
	}
	fmt.Fprintf(os.Stdout, "migrations: NOT at head — migration %d of %d has not run\n", missing, store.MigrationCount())
	os.Exit(2)
	return nil
}

// The pool, from the same DSN the server reads.
//
// The DSN is never in an error here. pgx puts it in its own, and it carries a password.
func open(ctx context.Context) (*pgxpool.Pool, error) {
	_, pool, err := openWithDsn(ctx)
	return pool, err
}

// The pool, and the DSN it was opened from.
//
// The DSN comes back because [store.CheckClusterTimezone] cannot be asked through the pool: every
// pooled connection carries `timezone = UTC` in its startup packet, which is exactly the value
// that check exists to read. Handling it is the caller's business, and the rule is the one the
// whole of this repository keeps — it is never printed and never put in an error.
func openWithDsn(ctx context.Context) (string, *pgxpool.Pool, error) {
	dsn := os.Getenv(dsnVariable)
	if dsn == "" {
		directory := os.Getenv(resourceDirVariable)
		if directory == "" {
			directory = "."
		}
		file, err := os.ReadFile(filepath.Join(directory, pgResource))
		if err != nil {
			return "", nil, fmt.Errorf("%w: %s is unset and %s/%s could not be read",
				errNoDsn, dsnVariable, directory, pgResource)
		}
		dsn = dsnFrom(string(file))
		if dsn == "" {
			return "", nil, fmt.Errorf("%w: %s/%s has no `dsn` line", errNoDsn, directory, pgResource)
		}
	}
	pool, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		return "", nil, errors.New("the pg.yml DSN did not parse, or a pool could not be created from it")
	}
	return dsn, pool, nil
}

var errNoDsn = errors.New("no DSN")

// The `dsn:` line of a §10.2 simple resource.
//
// A ten-line reader rather than the server's, and deliberately more permissive than it: the
// server refuses a `message.yml` it does not fully understand, because a key it skipped is a
// value an operator set and the server did not run on. This command runs one migration and reads
// one key, so a `pg.yml` carrying a key the server has not learned must not stop a migration —
// the failure mode that matters here is a schema that did not get applied.
func dsnFrom(contents string) string {
	for _, line := range strings.Split(contents, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		name, value, found := strings.Cut(trimmed, ":")
		if !found || strings.TrimSpace(name) != "dsn" {
			continue
		}
		value = strings.TrimSpace(value)
		if 2 <= len(value) && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		return value
	}
	return ""
}
