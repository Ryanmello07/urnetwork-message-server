package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The DDL of spec B §3.2, as the ordered migration list §10.3 asks for, with its own
// `migration_audit` table in its own database.
//
// # Which of §3.2's fourteen tables are here
//
// Seven: the ones a method of [Store] reads or writes. §3.2 also defines `message_blob`,
// `message_group_usage`, `message_kt_gossip`, `message_recovery`, `message_diagnostic_session`,
// `message_rendezvous` and `message_rendezvous_deposit`, and every one of them belongs to a
// subsystem this interface does not reach — the blob lifecycle of §8, the sweep's soft rollups
// of §7.4, the gossip cache of §9.5, the seed-only restore of §4.3.7, §11.5's diagnostic
// sessions and §4.3.11's rendezvous. Creating them now would ship schema that nothing in this
// module reads, writes or tests, and the list is append-only precisely so each one can arrive
// with the code that uses it.
//
// The one that will arrive soonest is `message_recovery`: §6.1 step (6c) writes it inside the
// submit transaction, so it lands with [Store.Submit] rather than with this half.
//
// # Append-only, and how that is held
//
// §10.3: "A landed migration is never edited, only superseded." The version a migration is
// recorded under is its POSITION in this slice, and `migration_audit` keeps the name beside it,
// so a migration edited into a different position, renamed, or deleted is caught on the next run
// by name rather than being silently skipped or silently re-applied. The labels are §3.2's own —
// 001, 002, 003, 003b, 004, 004b, 005 — and the gaps in them are the tables above.
type migration struct {
	name string
	sql  string
}

// §10.3's `newSqlMigration`. A `newCodeMigration` — a raw connection outside a transaction, for
// the `CREATE INDEX CONCURRENTLY` procedure §10.3 spells out over the 64 partitions — arrives
// with the first index added to a populated table, and not before: every index here is created
// with the table it is on, in the same transaction, on a relation that holds no rows.
func newSqlMigration(name string, sql string) migration {
	return migration{name: name, sql: sql}
}

// §3.4: `message_record` is PARTITION BY HASH (group_id) with 64 partitions created
// unconditionally, and `message_stream_claim` the same way and for the same reason. It is not a
// config switch because it cannot be one — converting a populated table is a full rewrite of the
// largest relation in the system with no online path — and a partitioned table with no
// partitions rejects every INSERT with "no partition of relation found for row".
const recordPartitions = 64

// The partitions of one hash-partitioned table, generated rather than written out.
//
// §3.2 prints `message_record_p00` and then "p01 through p63, identically". Sixty-four typed
// CREATE TABLE lines is sixty-four chances for a remainder to be wrong or missing, and a missing
// remainder is not a migration failure — it is one INSERT in sixty-four failing at runtime, on
// whichever groups happen to hash into it.
//
// `fillfactor = 100` is §3.4's, and it goes on the leaf partitions because PostgreSQL refuses a
// storage parameter on a partitioned parent ("cannot specify storage parameters for a
// partitioned table"). Records are write-once apart from the body erase and the `prune_after`
// NULLing, so there is no HOT-update workload to reserve free space for.
func partitionsOf(table string) string {
	statements := &strings.Builder{}
	for remainder := range recordPartitions {
		fmt.Fprintf(statements, "CREATE TABLE %s_p%02d PARTITION OF %s\n    FOR VALUES WITH (MODULUS %d, REMAINDER %d) WITH (fillfactor = 100);\n",
			table, remainder, table, recordPartitions, remainder)
	}
	return statements.String()
}

// The ordered list. Position is the version; the name is what `migration_audit` holds it to.
var migrations = []migration{
	// ── 001 ──────────────────────────────────────────────────────────────────────────
	//
	// `fillfactor = 70` is §3.4's, and it is the opposite of the record table's: this row is
	// updated on every submit — §6.1 step (4) allocates against `next_record_id` under the row
	// lock — so the free space is what keeps that update HOT and off the index.
	newSqlMigration("001 message_group", `
CREATE TABLE message_group (
    group_id            bytea       NOT NULL,
    create_time         timestamp   NOT NULL DEFAULT now(),
    current_epoch       bigint      NOT NULL,
    -- per-group gapless record id allocator (decision B4). 1-BASED: record_id = 0 is never
    -- assigned, so since_record_id = 0 is the well-defined "from the beginning" cursor.
    next_record_id      bigint      NOT NULL DEFAULT 1,
    media_ttl_seconds   int         NOT NULL,
    durable_ttl_seconds int         NULL,          -- NULL = indefinite
    group_context_hash  bytea       NULL,          -- echoed to clients; never interpreted
    policy_version      int         NOT NULL DEFAULT 0,
    -- false between an accepted commit and its EpochComplete marker (§6.1)
    epoch_complete      boolean     NOT NULL DEFAULT true,
    closed              boolean     NOT NULL DEFAULT false,
    close_time          timestamp   NULL,

    PRIMARY KEY (group_id),
    CHECK (octet_length(group_id) = 32),
    CHECK (0 <= current_epoch),
    CHECK (1 <= next_record_id),
    CHECK (0 < media_ttl_seconds),
    CHECK (durable_ttl_seconds IS NULL OR 0 < durable_ttl_seconds),
    CHECK (group_context_hash IS NULL OR octet_length(group_context_hash) = 32),
    CHECK (NOT closed OR close_time IS NOT NULL)
) WITH (fillfactor = 70);
`),

	// ── 002 ──────────────────────────────────────────────────────────────────────────
	newSqlMigration("002 message_epoch", `
CREATE TABLE message_epoch (
    group_id          bytea     NOT NULL,
    epoch             bigint    NOT NULL,
    -- u8(kek_id) || nonce(12) || ct(32) || tag(16) = 61 B (§5.5). The key id is what makes a
    -- dual-KEK rollover window possible without a migration on the table that gates every
    -- submit.
    write_key_wrapped bytea     NULL,
    -- the epoch's read key, same wrap format, RETAINED for read_key_window_seconds from
    -- read_key_install and not for the write key's sixty seconds (§5.3).
    read_key_wrapped  bytea     NULL,
    read_key_install  timestamp NULL,
    alg_id            int       NOT NULL,
    opened_by_record  bigint    NULL,
    accept_time       timestamp NOT NULL DEFAULT now(),
    retire_time       timestamp NULL,

    PRIMARY KEY (group_id, epoch),
    CHECK (octet_length(group_id) = 32),
    CHECK (write_key_wrapped IS NULL OR octet_length(write_key_wrapped) = 61),
    CHECK (read_key_wrapped IS NULL OR octet_length(read_key_wrapped) = 61),
    CHECK ((read_key_wrapped IS NULL) = (read_key_install IS NULL))
);

-- the read-key expiry worklist (Q16). Partial, and the tidy loop NULLs both columns after
-- acting, so the index holds exactly the outstanding work.
CREATE INDEX message_epoch_read_key_expiry
    ON message_epoch (read_key_install) WHERE read_key_wrapped IS NOT NULL;
`),

	// ── 003 ──────────────────────────────────────────────────────────────────────────
	newSqlMigration("003 message_record", `
CREATE TABLE message_record (
    group_id        bytea     NOT NULL,
    record_id       bigint    NOT NULL,   -- per-group, gapless, allocated in-tx
    sender_handle   bytea     NOT NULL,
    epoch           bigint    NOT NULL,
    stream_index    bigint    NOT NULL,
    is_commit       boolean   NOT NULL,
    retention_class smallint  NOT NULL,
    size_bucket     smallint  NOT NULL,

    expire_at       timestamp NULL,       -- lossy projection of the wire u64 milliseconds
    prune_after     timestamp NULL,       -- server-computed; NULLed once the sweep has acted
    pruned          boolean   NOT NULL DEFAULT false,
    policy_version  int       NOT NULL DEFAULT 0,

    body_hash       bytea     NOT NULL,   -- retained after ct_body is erased
    ct_head         bytea     NOT NULL,
    ct_body         bytea     NULL,       -- NULL when erased, or when the body is a blob
    blob_id         bytea     NULL,

    -- the authenticated attachment exactly as submitted; the two below are projections of it
    server_attachment  bytea  NULL,
    recovery_handle    bytea  NULL,
    wrap_target_handle bytea  NULL,

    create_time     timestamp NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, record_id),
    CHECK (octet_length(group_id) = 32),
    CHECK (octet_length(sender_handle) = 16),
    CHECK (octet_length(body_hash) = 32),
    CHECK (blob_id IS NULL OR octet_length(blob_id) = 32),
    CHECK (recovery_handle IS NULL OR octet_length(recovery_handle) = 16),
    CHECK (wrap_target_handle IS NULL OR octet_length(wrap_target_handle) = 16),
    CHECK (ct_body IS NULL OR blob_id IS NULL),          -- inline XOR blob, never both
    CHECK (0 <= stream_index),
    CHECK (retention_class IN (0,1,2) OR (16 <= retention_class AND retention_class <= 21)),
    CHECK (0 <= size_bucket AND size_bucket <= 5)
) PARTITION BY HASH (group_id);

`+partitionsOf("message_record")+`
-- §3.4: pglz cannot compress AEAD output, so EXTERNAL skips it and costs no CPU per write.
ALTER TABLE message_record ALTER COLUMN ct_head SET STORAGE EXTERNAL;
ALTER TABLE message_record ALTER COLUMN ct_body SET STORAGE EXTERNAL;
`),

	// ── 003b ─────────────────────────────────────────────────────────────────────────
	//
	// The claim carries the uniqueness on (group_id, sender_handle, stream_index) that
	// `message_record` deliberately does not: §7.2 zeroes `sender_handle` on an expired
	// ephemeral record, and two senders may legitimately hold the same stream_index, so an
	// index on the record would collide the moment the sweep zeroed one. It is also the honest
	// home for the idempotency probe of §6.3, which never needed the record's storage columns.
	newSqlMigration("003b message_stream_claim", `
CREATE TABLE message_stream_claim (
    group_id      bytea  NOT NULL,
    sender_handle bytea  NOT NULL,
    stream_index  bigint NOT NULL,
    record_id     bigint NOT NULL,
    body_hash     bytea  NOT NULL,
    head_hash     bytea  NOT NULL,   -- H(ct_head), so §6.3 compares both
    create_time   timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, sender_handle, stream_index),
    CHECK (octet_length(group_id) = 32),
    CHECK (octet_length(sender_handle) = 16),
    CHECK (octet_length(body_hash) = 32),
    CHECK (octet_length(head_hash) = 32)
) PARTITION BY HASH (group_id);

`+partitionsOf("message_stream_claim")),

	// ── 004  indexes ─────────────────────────────────────────────────────────────────
	//
	// There is deliberately no unique index on message_record (group_id, sender_handle,
	// stream_index) — 003b is the uniqueness authority — and deliberately no partial unique
	// index for the commit: PostgreSQL rejects one on a partitioned table, so that migration
	// would fail at deploy time. The CAS is 004b.
	newSqlMigration("004 message_record indexes", `
-- Q10: epoch wrap fan-out, indexed by target
CREATE INDEX message_record_wrap
    ON message_record (group_id, epoch, wrap_target_handle)
    WITH (fillfactor = 100)
    WHERE wrap_target_handle IS NOT NULL;

-- Q11: what makes FetchRequest.class_mask costed rather than a full group scan per page
CREATE INDEX message_record_class
    ON message_record (group_id, retention_class, record_id)
    WITH (fillfactor = 100);

-- Q5: the sweep worklist. Partial, and the sweep NULLs prune_after once it has acted, so the
-- index holds exactly the outstanding work and its size is the backlog, not the corpus.
CREATE INDEX message_record_prune
    ON message_record (prune_after)
    WITH (fillfactor = 100)
    WHERE prune_after IS NOT NULL;

-- Q6: seed-only restore
CREATE INDEX message_record_recovery
    ON message_record (recovery_handle, group_id, record_id)
    WITH (fillfactor = 100)
    WHERE recovery_handle IS NOT NULL;

-- blob back-reference, for binding and for GC
CREATE INDEX message_record_blob
    ON message_record (blob_id)
    WITH (fillfactor = 100)
    WHERE blob_id IS NOT NULL;
`),

	// ── 004b  the single-commit invariant ────────────────────────────────────────────
	//
	// THE CAS (Q14): a one-row insert against a full primary key, not a predicate index.
	newSqlMigration("004b message_commit", `
CREATE TABLE message_commit (
    group_id  bytea  NOT NULL,
    epoch     bigint NOT NULL,
    record_id bigint NOT NULL,
    PRIMARY KEY (group_id, epoch),
    CHECK (octet_length(group_id) = 32)
);
`),

	// ── 005 ──────────────────────────────────────────────────────────────────────────
	newSqlMigration("005 message_sender", `
CREATE TABLE message_sender (
    group_id          bytea     NOT NULL,
    sender_handle     bytea     NOT NULL,
    last_stream_index bigint    NOT NULL,
    record_count      bigint    NOT NULL DEFAULT 0,
    byte_count        bigint    NOT NULL DEFAULT 0,
    last_time         timestamp NOT NULL,

    PRIMARY KEY (group_id, sender_handle),
    CHECK (octet_length(group_id) = 32),
    CHECK (octet_length(sender_handle) = 16)
);
`),
}

// §10.3: migrations are executed by a dedicated init job or `messagectl migrate`, NEVER by N
// replicas racing at startup, and the runner holds `pg_advisory_lock` for the duration. The
// constant is the ASCII of "urmsg", so two message-server deployments sharing a cluster take the
// same lock and no other application takes it by accident.
const migrationAdvisoryLock int64 = 0x75726d7367

// §10.3's own audit table, in this module's own database. `version` is the migration's position
// in [migrations] and `name` is what holds the list to being append-only.
const migrationAuditDdl = `
CREATE TABLE IF NOT EXISTS migration_audit (
    version    int       NOT NULL,
    name       text      NOT NULL,
    apply_time timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (version)
);
`

// A landed migration was edited, renamed, reordered or removed. §10.3 makes the list
// append-only, and the failure this catches is the quiet one: a renumbered list re-applies a
// migration that already ran, or skips one that has not.
var errMigrationRewritten = errors.New("store: a landed migration is not the one recorded for its version")

// Bring the database this pool is connected to up to head.
//
// Every migration runs in its own transaction with its audit row, so a failure leaves the
// database at the last migration that fully applied rather than half-way through one. DDL is
// transactional in PostgreSQL, which is what makes that possible and is why §10.3's exception —
// `CREATE INDEX CONCURRENTLY`, which cannot run inside a transaction — is a code migration and
// not a SQL one.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer connection.Release()

	// held for the whole run, on this one connection: a session-level advisory lock taken on a
	// pooled connection and released from another is not a lock at all
	if _, err := connection.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLock); err != nil {
		return err
	}
	defer connection.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLock)

	if _, err := connection.Exec(ctx, migrationAuditDdl); err != nil {
		return err
	}
	applied, err := appliedMigrations(ctx, connection.Conn())
	if err != nil {
		return err
	}
	for index, current := range migrations {
		version := index + 1
		if name, found := applied[version]; found {
			if name != current.name {
				return fmt.Errorf("%w: version %d ran as %q and this list holds %q", errMigrationRewritten, version, name, current.name)
			}
			continue
		}
		transaction, err := connection.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := transaction.Exec(ctx, current.sql); err != nil {
			transaction.Rollback(ctx)
			return fmt.Errorf("migration %d %q: %w", version, current.name, err)
		}
		if _, err := transaction.Exec(ctx, `INSERT INTO migration_audit (version, name) VALUES ($1, $2)`, version, current.name); err != nil {
			transaction.Rollback(ctx)
			return err
		}
		if err := transaction.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// What `migration_audit` says has run, keyed by version.
func appliedMigrations(ctx context.Context, connection *pgx.Conn) (map[int]string, error) {
	rows, err := connection.Query(ctx, `SELECT version, name FROM migration_audit`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[int]string{}
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			return nil, err
		}
		found[version] = name
	}
	return found, rows.Err()
}
