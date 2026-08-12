# URmessage â€” Message Server and Operator Context

**Spec B of three.** Companion documents: spec A (`connect`/`sdk` protocol and client core) and spec C (Windows messaging client).
**Normative parent:** `docs/specs/2026-08-12-urmessage-protocol-design.md` (revision 5) â€” referred to below as *the master spec*, cited by section (e.g. Â§9.3).
**Decision record:** `SPEC-LEDGER.md`.
**Date:** 2026-08-12 Â· **Revision:** 1 Â· **Status:** Design, pending owner review

Notation follows the master spec: `LP(x)` = 32-bit length prefix then `x`; `â€–` = concatenation; `H` = SHA-256. All timestamps in Postgres are `timestamp` in UTC, never `timestamp with time zone`, matching the operator's convention.

---

## PLANNING LEDGER

### Current state

| Item | State |
|---|---|
| Master protocol design | Revision 5, awaiting owner review |
| This spec | Revision 1, first draft |
| Message server code | None |
| Repo | `Ryanmello07/urnetwork-message-server` (seeded: LICENSE, README, SPEC-LEDGER, docs) |
| Branch for protocol code | `beta/message` on the `connect` and `sdk` forks (not yet created) |
| Blocking on | Two write-authenticator amendments to master spec Â§9.2 â€” see *Open items* 1 and 2. Both are wire-format additions and **must land before slice 2 freezes the format** |

Verified against the checked-out trees at `C:\Users\ryanm\Downloads\claude_sandbox_message\{server,connect,sdk}`:

- `server/go.mod` is `github.com/urnetwork/server`, Go 1.26.5, with `jackc/pgx/v5 v5.10.0`, `redis/go-redis/v9 v9.22.0`, `minio/minio-go/v7 v7.2.1`, `prometheus/client_golang v1.24.1`.
- `server/db.go` exposes `Db`/`Tx`/`MaintenanceDb`/`MaintenanceTx`/`ReplicaDb`, `WithPgResult`, `RaisePgResult`, `BatchInTx`, and the `PgConn`/`PgTx`/`PgResult` aliases. Pools are configured from vault resource `pg.yml` and config resource `db.yml`.
- `server/db_migrations.go` is an ordered slice of `newSqlMigration(...)` / `newCodeMigration(...)`, versioned through a `migration_audit` table. 581 migrations today. It carries a standing `FIXME perf: CREATE INDEX should always use CONCURRENTLY`.
- `server/blob.go` defines a `BlobStore` interface (Put/Get/List/SetLifecycle/Bucket/Prefix/Authority) over MinIO or a local filesystem, configured from vault `minio.yml`. **It has no `Delete`, deliberately** â€” retention there is an ILM lifecycle rule.
- `server/redis.go` exposes `RedisClient = redis.UniversalClient` configured from vault + config `redis.yml`.
- `server/task` imports `server/session`, which imports `server/model`. Importing the task framework therefore drags in the operator's account model.
- `connect/protocol/frame.proto` defines `enum MessageType` densely populated 0â€“28, and `Frame{message_type, message_bytes, raw}`.
- `connect/transfer.go` exposes `Send`, `SendWithTimeout`, `SendMultiHopWithTimeout`, `AddReceiveCallback(ReceiveFunction)`; `ReceiveFunction = func(source TransferPath, frames []*protocol.Frame, peer Peer)`. `ClientSettings.MinimumMessageLenLimit()` returns **4 KiB**, and `sendPackBatchMaxMessageByteCount` is 3 KiB.
- `server/connect/transport.go:471-501` authenticates with `ParseByJwtForAudience` + `ValidateByJwtState` + `model.GetNetworkClientNetwork`. Bearer token, no challenge-response, as the master spec Â§4.3 records.

### Decisions specific to this component, and why

| # | Decision | Why |
|---|---|---|
| **B1** | The message server is its **own Go module and repo**, and imports **only the root `github.com/urnetwork/server` package** for infrastructure (`Db`/`Tx`, `Redis`, `Vault`/`Config`, `Id`, `BlobStore`). It **MUST NOT** import `server/model`, `server/session`, `server/task`, `server/controller`, or `server/api`. | Those packages carry the operator's account tables and would put the operator's identity model inside the process that holds ciphertext, contradicting Â§4.2. Verified: `server/task â†’ server/session â†’ server/model`, so the task framework is unusable here and the sweep scheduler is written in-process instead. Enforced in CI by a `go list -deps` deny-list. |
| **B2** | **Redis is required, but no correctness invariant may depend on it.** It carries cross-instance subscribe fan-out, rate-limit token buckets, presence, and the known-group filter refresh. Losing Redis degrades latency and push liveness; it never changes what is accepted or stored. | The commit CAS and stream monotonicity are durability invariants. Putting either in Redis makes a cache eviction a protocol violation. |
| **B3** | **No record ciphertext, no epoch write key, and no blob byte ever enters Redis.** Pub/sub payloads carry a masked group id and a record-id range only; the receiving instance re-reads Postgres. | Redis persistence (AOF/RDB) would write ciphertext to a second, usually less-hardened disk, and `MONITOR`/slowlog would print keys. |
| **B4** | `record_id` is a **per-group, gapless, monotonically allocated bigint**, not a global `bigserial`. Allocation is `UPDATE message_group SET next_record_id = next_record_id + n RETURNING`, in the submit transaction. | A global sequence allocates before commit, so a reader can observe id 10 before id 9 is visible and then never see 9. That silently breaks `fetch since record_id`, which is the single most-used query in the system. Per-group allocation also serialises the group's log, which is exactly what the Delivery Service role (Â§9.3) needs anyway, so the lock is not additional cost â€” it is the same lock. |
| **B5** | The retention sweep is driven by a **server-computed `prune_after`**, not by the client-declared `expire_at`. `expire_at` is stored and echoed to clients unchanged, as Â§8 specifies (advisory), but never consulted by the sweep. | Â§8 calls `expire_at` advisory. A sweep driven by it lets any member pin `MEDIA` forever by declaring `expire_at = 2999`, defeating Â§12.2's cap. |
| **B6** | **No client-initiated server-side erase in v1.** Bodies are removed by class expiry and by the sweep only. `TOMBSTONE` remains a purely client-side, MLS-authenticated construct. | `write_key` is group-wide (Â§9.2), so an erase request cannot be attributed to a device or to the original sender â€” any member could erase any body, a history-destroying DoS. Â§9.2 already defers per-device capabilities to V2 for precisely this reason, and Â§12.3 already tells users delete-for-everyone does not claw anything back. Early erase is therefore gated on the V2 per-device capability work. |
| **B7** | **Split transport: protobuf request/response over the connect frame path for the control plane; TLS/HTTP over the mesh for the bulk (blob) plane.** Argued in Â§4.1. | A 100 MB upload driven through a 3 KiB-batched, ack-windowed client sequence head-of-line-blocks every message in that sequence. Ranged and resumable semantics already exist in HTTP and in MinIO multipart. Meanwhile subscribe needs *server-initiated* push, which the frame path gives free and HTTP does not. |
| **B8** | **Two new `MessageType` enum values only** (`MessageServerRequest`, `MessageServerResponse`, plus `MessageServerPush`), reserved at **1000â€“1099**, with a `oneof` inside for every operation. | `frame.proto` is shared with `beta/algorithm-dpi` and `beta/custom-server`. Adding one enum value per operation guarantees a merge conflict on every branch every time we add an operation. A reserved high block plus an internal `oneof` reduces the shared-file diff to three lines, permanently. |
| **B9** | The server keeps **only the current epoch's `write_key`**, wrapped under a KEK loaded from the vault. Advancing an epoch NULLs every older key in the same transaction. | Â§9.3 already rejects records at a non-current epoch, so an old key has no verification use. Discarding it shrinks the blast radius of a database compromise to one key per group. |
| **B10** | The message server runs against a **separate Postgres cluster and separate credentials from the operator**, even though one organisation runs both. | Same operator, separate blast radius. An operator database compromise must not also yield message ciphertext and epoch write keys. Cheap; do it on day one, because retrofitting a database split after launch is not cheap. |
| **B11** | Forbidden identifiers are made **structurally unprintable** in Go â€” `GroupId`, `SenderHandle`, `BlobId`, `RecoveryHandle` are named types whose `String()`, `Format()`, `LogValue()`, and `MarshalJSON()` all return a redaction constant. | Â§9.7 is a normative requirement, and a rule that depends on every future developer remembering it will be violated. Making an accidental `%v` physically incapable of printing the value is the only enforcement that survives contact with a team. |
| **B12** | Bodies over the inline ladder go to the blob store; `ct_head` and `ct_body` use `STORAGE EXTERNAL` (no TOAST compression). | Ciphertext is incompressible; `pglz` would burn CPU on every write and every read for a ~0% ratio. |

### Interfaces to the other two components

| Direction | Summary | Detail |
|---|---|---|
| **Requires from spec A** | Byte-exact record header encoding; the `write_auth` preimage including the `server_attachment` amendment; the size-bucket and eph-bucket ladders; a shared Go package `connect/message` the server links so it never reimplements the parser; a shared interop vector file. | Â§12.1 |
| **Provides to spec A** | The reject-reason contract, the `COMMIT_LOST` retry contract, the capability document, and the exact idempotency semantics of a retried submit. | Â§12.1 |
| **Provides to spec C** | Everything C consumes goes through `sdk` â€” C never speaks to the message server directly. What C must surface in UI: blob cap before the file picker opens, retention notices, resumable-upload progress, attestation warnings, hole detection on the gapless `record_id`. | Â§12.2 |
| **Requires from the operator** | A network + client ids for the server fleet; a discovery endpoint listing the fleet; the KT log and its signed tree heads; a transport `FramerSettings.MaxMessageLen` measurement. | Â§9 |

### Open items

1. **`server_attachment` amendment to Â§9.2 (blocking, format-freezing).** Commit records must carry a server-visible epoch attachment (the next epoch's `write_key`, retention policy, group-context hash) and archive records must carry a server-visible `recovery_handle` (Â§5.4 seed-only restore is unservable without an index). Per **I6** and **I8** the server may not act on either unless it is authenticated. Proposal: append `â€– LP(H(server_attachment))` to the Â§9.2 `write_auth` preimage and to `AAD_head`, where `server_attachment` is a typed, extensible byte string, empty for ordinary records. One amendment covers both cases and every future one. **Owner ruling required.**
2. **Control-plane message size.** `ClientSettings.MinimumMessageLenLimit()` is 4 KiB and `sendPackBatchMaxMessageByteCount` is 3 KiB. A 64 KiB inline record does not fit one frame. This spec defines an application-level fragmentation wrapper (Â§4.6) so the protocol is transport-cap independent, but the platform's *actual* production `MaxMessageLen` must be measured before we size the inline ladder. **Assumption to confirm by measurement.**
3. **Retention floor negotiation** (ledger open item 1, master spec Â§15.1). Recommendation: **warn and proceed** â€” the server clamps to its advertised cap, returns `RETENTION_CLAMPED` on the commit that set the policy, and the client renders a one-time in-group notice. Refusing would let a server config change break a group outright. **Owner ruling required.**
4. **Blob padding ladder.** This spec assumes blob objects are padded to a multiple of 256 KiB (bounded overhead, removes fine-grained size fingerprinting). Spec A owns the ladder. **Assumption to confirm with spec A.**
5. **KT staging.** Â§10.1 requires a Merkle *prefix* tree (absence proofs), not just a log. This spec specifies both, and proposes shipping the append-only log with signed tree heads and two-path gossip first, with the VRF-indexed prefix tree required before any non-beta user. **Owner ruling required** â€” the master spec says "required, not optional," and staging it is a weakening if not explicitly time-boxed.
6. **Group-row lock throughput.** B4 serialises writes per group. Expected ceiling ~1â€“2k records/s/group; a 500-member group at peak is nowhere near that. **Assumption to confirm by benchmark in slice 3.**
7. **Push transport** (ledger open item 2). Out of scope for this spec beyond leaving `presence` in Redis and a `push_token` field reserved. WNS wiring is a later slice.

### Edit log

Append-only. Newest last. One entry per commit that changes this spec. Follow the ledger Â§6 change process: edit, subagent diff review, fix, commit with the ledger entry, append here.

---

*(no entries yet)*

---

## 1. Scope

**In scope.** The message server process: storage, ordering, single-commit agreement, `write_auth` verification, history serving, blob lifecycle, retention and pruning, capability advertisement, its own URnetwork account and transport wiring, deployment, configuration, migrations, backup, observability. Plus the operator-side surface the message server and clients depend on: the discovery directory and the key-transparency log.

**Out of scope.** MLS (spec A). The record format's cryptographic construction (master spec Â§8, implemented in spec A). Client state, local store, provisioning (spec A). Any UI (spec C).

**Non-goals, permanently.** The message server never decrypts, never parses an MLS structure, never holds an MLS implementation, and never adjudicates group membership or roles.

---

## 2. Service architecture

### 2.1 Repository and package layout

Module `github.com/urnetwork/message-server` (fork at `Ryanmello07/urnetwork-message-server`), sibling-checked-out alongside `connect`, `sdk`, and `server` with local `replace ../` directives, matching the workspace layout the rest of the URnetwork Go repos use.

```
message-server/
  cmd/message-server/       process entrypoint
  cmd/messagectl/           ops CLI (migrate, sweep-now, capability dump, key rotate)
  peer/                     connect client wiring, frame dispatch, fragmentation
  api/                      request handlers, one file per operation
  store/                    pgx queries; the only package that writes SQL
  store/migrations.go       ordered migration list + migration_audit
  blobd/                    HTTP bulk plane (upload/download), grant verification
  sweep/                    retention sweep, blob GC, orphan reaper
  kt/                       key-transparency gossip client (read-only)
  redact/                   unprintable identifier types (decision B11)
  metrics/                  Prometheus collectors
  docs/specs/               this document
```

### 2.2 Dependency rule (normative)

```
ALLOWED:  github.com/urnetwork/server            (root package only)
          github.com/urnetwork/connect           (beta/message)
          github.com/urnetwork/connect/protocol
          github.com/urnetwork/connect/message   (record parser, shared with spec A)
          github.com/urnetwork/glog
          jackc/pgx/v5, redis/go-redis/v9, minio/minio-go/v7,
          prometheus/client_golang

FORBIDDEN: github.com/urnetwork/server/model
           github.com/urnetwork/server/session
           github.com/urnetwork/server/task
           github.com/urnetwork/server/controller
           github.com/urnetwork/server/api
           github.com/urnetwork/sdk
```

CI gate:

```bash
go list -deps ./... | grep -E 'urnetwork/server/(model|session|task|controller|api)|urnetwork/sdk' && exit 1
exit 0
```

The rule exists because the operator's model package *is* the account identity layer, and Â§4.2 forbids the message server from consulting it. The cost is that `server/task` is unavailable, so Â§7.4 specifies an in-process scheduler behind a Postgres advisory lock instead.

### 2.3 Process model

| Property | Value |
|---|---|
| Instances | N stateless replicas, N â‰¥ 2 |
| URnetwork identity | One network for the fleet; **each instance holds its own `client_id`** and its own long-lived credential in the vault |
| Client affinity | A client resolves the fleet from discovery, picks one instance, and stays sticky for the session; on disconnect it re-picks |
| Cross-instance fan-out | Redis pub/sub (Â§2.4) |
| Shared state | Postgres (authoritative), object store (blobs), Redis (soft) |
| Graceful shutdown | Stop accepting new frames, drain in-flight transactions, unsubscribe from Redis, close the connect client, exit. No two-phase teardown â€” this is a normal user-mode service, unlike the VPN client's privileged service |

Per-instance `client_id` (rather than a shared one) is deliberate: the platform's resident routes a `client_id` to a single connection, so a shared id would pin the whole fleet to one replica.

### 2.4 Redis: what it is for, and what it is never for

| Use | Key shape | TTL | Loss behaviour |
|---|---|---|---|
| Subscribe fan-out | `urmsg:g:<mask>` pub/sub channel | â€” | Pushes stop; clients still poll on reconnect and lose nothing |
| Rate-limit token buckets | `urmsg:rl:c:<client_id_hash>`, `urmsg:rl:g:<mask>` | 60 s | Fail **closed** to a conservative in-process limiter |
| Presence (which instance holds which subscription) | `urmsg:pres:<client_id_hash>` | 90 s, refreshed | Push routing degrades to broadcast on the group channel |
| Known-group filter epoch | `urmsg:gf:epoch` | â€” | Filter refreshes from Postgres on a timer regardless |
| Idempotency hint cache | `urmsg:idem:<mask>:<handle>:<idx>` | 300 s | Falls through to the Postgres unique index, which is the authority |

`<mask>` is `hex(HMAC-SHA256(channel_key, group_id)[0:8])`, where `channel_key` is a server secret from the vault. **Raw `group_id` never appears in a Redis key**, because Redis keyspace notifications, `MONITOR`, and slowlog all print keys and Redis is routinely operated with looser controls than the database.

Pub/sub payload is exactly `{mask, group_id_enc, lo_record_id, hi_record_id}` where `group_id_enc` is the group id AEAD-encrypted under the same server secret so the receiving instance can resolve it without a lookup table. **No ciphertext, no write key, no blob byte crosses Redis** (decision B3).

Deployment requirement: `slowlog-log-slower-than -1`, `MONITOR` disabled by ACL, no AOF/RDB persistence for this instance's database.

**The commit CAS is not in Redis.** It is a Postgres transaction (Â§6). A Redis-based CAS would make a failover or an eviction into an MLS fork.

---

## 3. Data model

### 3.1 Conventions

- All ids are `bytea` with an exact-length `CHECK`. `group_id` is 32 B, `sender_handle` 16 B, `body_hash` 32 B, `recovery_handle` 16 B, `blob_id` 32 B. They are **not** `uuid` â€” `uuid` is 128-bit and would silently truncate a 256-bit group id.
- All timestamps are `timestamp` (UTC). Never `timestamp with time zone`, matching `server/db.go`'s standing note.
- `retention_class smallint`: `0` PERMANENT, `1` DURABLE, `2` MEDIA, `16 + b` EPH(bucket *b*).
- `size_bucket smallint`: `0` 256 B, `1` 1 KiB, `2` 4 KiB, `3` 16 KiB, `4` 64 KiB, `5` blob-ref. The stored `ct_body` length must be **exactly** the bucket size plus the AEAD tag; see Â§5.1 check 3.
- Eph buckets: `0` transient (receipts, typing â€” **never persisted**), `1` 1 h, `2` 8 h, `3` 1 d, `4` 1 w, `5` 4 w. Buckets 1â€“5 are the master spec Â§12.2 disappearing ladder.

### 3.2 DDL

Written in the operator's migration style â€” an ordered slice of `newSqlMigration(...)` in `store/migrations.go`, with its own `migration_audit` table in its own database.

```sql
-- â”€â”€ 001 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE message_group (
    group_id            bytea       NOT NULL,
    create_time         timestamp   NOT NULL DEFAULT now(),

    -- Delivery Service state (master spec Â§9.3)
    current_epoch       bigint      NOT NULL,

    -- per-group gapless record id allocator (decision B4)
    next_record_id      bigint      NOT NULL DEFAULT 0,

    -- retention policy, as published by the committer in the epoch attachment,
    -- already clamped to this server's advertised caps
    media_ttl_seconds   int         NOT NULL,
    durable_ttl_seconds int         NULL,          -- NULL = indefinite
    group_context_hash  bytea       NULL,          -- echoed to clients; never interpreted

    blob_quota_bytes    bigint      NOT NULL,
    closed              boolean     NOT NULL DEFAULT false,

    PRIMARY KEY (group_id),
    CHECK (octet_length(group_id) = 32),
    CHECK (0 <= current_epoch),
    CHECK (0 <= next_record_id),
    CHECK (0 < media_ttl_seconds),
    CHECK (durable_ttl_seconds IS NULL OR 0 < durable_ttl_seconds),
    CHECK (group_context_hash IS NULL OR octet_length(group_context_hash) = 32)
);

-- â”€â”€ 002 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE message_epoch (
    group_id          bytea     NOT NULL,
    epoch             bigint    NOT NULL,
    -- AES-256-GCM(KEK, write_key) as nonce(12) || ct(32) || tag(16) = 60 B.
    -- NULLed the moment the epoch is superseded (decision B9).
    write_key_wrapped bytea     NULL,
    alg_id            int       NOT NULL,
    opened_by_record  bigint    NULL,      -- record_id of the commit that opened this epoch
    accept_time       timestamp NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, epoch),
    CHECK (octet_length(group_id) = 32),
    CHECK (write_key_wrapped IS NULL OR octet_length(write_key_wrapped) = 60)
);

-- â”€â”€ 003 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE message_record (
    group_id        bytea     NOT NULL,
    record_id       bigint    NOT NULL,   -- per-group, gapless, allocated in-tx
    sender_handle   bytea     NOT NULL,
    epoch           bigint    NOT NULL,
    stream_index    bigint    NOT NULL,
    is_commit       boolean   NOT NULL,
    retention_class smallint  NOT NULL,
    size_bucket     smallint  NOT NULL,

    expire_at       timestamp NULL,       -- client-declared, advisory, echoed verbatim
    prune_after     timestamp NULL,       -- server-computed; NULLed once the sweep has acted

    body_hash       bytea     NOT NULL,   -- retained after ct_body is erased (Â§8)
    ct_head         bytea     NOT NULL,
    ct_body         bytea     NULL,       -- NULL when erased, or when the body is a blob
    blob_id         bytea     NULL,
    recovery_handle bytea     NULL,       -- set only on archive records (open item 1)
    create_time     timestamp NOT NULL DEFAULT now(),

    PRIMARY KEY (group_id, record_id),
    CHECK (octet_length(group_id) = 32),
    CHECK (octet_length(sender_handle) = 16),
    CHECK (octet_length(body_hash) = 32),
    CHECK (blob_id IS NULL OR octet_length(blob_id) = 32),
    CHECK (recovery_handle IS NULL OR octet_length(recovery_handle) = 16),
    CHECK (ct_body IS NULL OR blob_id IS NULL),          -- inline XOR blob, never both
    CHECK (0 <= stream_index),
    CHECK (retention_class IN (0,1,2) OR (16 <= retention_class AND retention_class <= 21)),
    CHECK (0 <= size_bucket AND size_bucket <= 5)
) PARTITION BY HASH (group_id);

-- 64 partitions. See Â§3.4 for when this is worth turning on.
-- CREATE TABLE message_record_p00 PARTITION OF message_record
--     FOR VALUES WITH (MODULUS 64, REMAINDER 0);  ... p63

ALTER TABLE message_record ALTER COLUMN ct_head SET STORAGE EXTERNAL;
ALTER TABLE message_record ALTER COLUMN ct_body SET STORAGE EXTERNAL;

-- â”€â”€ 004  indexes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
-- write-once stream index + idempotent retry key (Â§6.3)
CREATE UNIQUE INDEX message_record_stream
    ON message_record (group_id, sender_handle, stream_index);

-- the Delivery Service invariant, enforced by the database (Â§6.1)
CREATE UNIQUE INDEX message_record_commit
    ON message_record (group_id, epoch) WHERE is_commit;

-- the sweep worklist. Partial on prune_after IS NOT NULL, and the sweep NULLs
-- prune_after once it has acted, so this index contains exactly the outstanding
-- work and nothing else, forever. Index size is the backlog, not the corpus.
CREATE INDEX message_record_prune
    ON message_record (prune_after) WHERE prune_after IS NOT NULL;

-- seed-only restore (Â§5.4 of the master spec)
CREATE INDEX message_record_recovery
    ON message_record (recovery_handle, group_id, record_id)
    WHERE recovery_handle IS NOT NULL;

-- blob back-reference, for binding and for GC
CREATE INDEX message_record_blob
    ON message_record (blob_id) WHERE blob_id IS NOT NULL;

-- â”€â”€ 005 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

-- â”€â”€ 006 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE message_blob (
    blob_id         bytea     NOT NULL,
    group_id        bytea     NOT NULL,
    state           smallint  NOT NULL,   -- 0 GRANTED, 1 COMPLETE, 2 BOUND
    declared_bytes  bigint    NOT NULL,
    received_bytes  bigint    NOT NULL DEFAULT 0,
    chunk_bytes     int       NOT NULL,
    chunk_mask      bytea     NOT NULL,   -- 1 bit per chunk; resumable upload state
    retention_class smallint  NOT NULL,
    object_key      text      NOT NULL,   -- encodes the TTL ladder rung; see Â§8.3
    grant_expire    timestamp NOT NULL,
    prune_after     timestamp NULL,
    create_time     timestamp NOT NULL DEFAULT now(),

    PRIMARY KEY (blob_id),
    CHECK (octet_length(blob_id) = 32),
    CHECK (octet_length(group_id) = 32),
    CHECK (state IN (0,1,2)),
    CHECK (0 < declared_bytes),
    CHECK (0 <= received_bytes AND received_bytes <= declared_bytes)
);

CREATE INDEX message_blob_prune
    ON message_blob (prune_after) WHERE prune_after IS NOT NULL;
CREATE INDEX message_blob_expire_grant
    ON message_blob (grant_expire) WHERE state <> 2;
CREATE INDEX message_blob_group
    ON message_blob (group_id, create_time);

-- â”€â”€ 007  soft rollups (recomputed by the sweep, never in the write path) â”€â”€
CREATE TABLE message_group_usage (
    group_id      bytea     NOT NULL,
    record_count  bigint    NOT NULL,
    inline_bytes  bigint    NOT NULL,
    blob_bytes    bigint    NOT NULL,
    compute_time  timestamp NOT NULL,
    PRIMARY KEY (group_id)
);

-- â”€â”€ 008  key-transparency gossip cache (Â§9.5) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
CREATE TABLE message_kt_gossip (
    kt_epoch      bigint    NOT NULL,
    root_hash     bytea     NOT NULL,
    prev_root     bytea     NOT NULL,
    leaf_count    bigint    NOT NULL,
    sth_sig       bytea     NOT NULL,
    observed_time timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (kt_epoch)
);
```

### 3.3 Index rationale against the real query patterns

| # | Query | Frequency | Plan | Index |
|---|---|---|---|---|
| Q1 | `SELECT â€¦ WHERE group_id=$1 AND record_id > $2 ORDER BY record_id LIMIT $3` | Dominant read. Every fetch, every reconnect backfill, every subscribe catch-up | Index scan on the PK, forward, bounded by LIMIT | `PRIMARY KEY (group_id, record_id)` |
| Q2 | `UPDATE message_group SET next_record_id = next_record_id + $2 WHERE group_id=$1 AND NOT closed RETURNING current_epoch, next_record_id - $2` | Every submit | Single-row PK update; also the group lock | `PRIMARY KEY (group_id)` |
| Q3 | `INSERT INTO message_record â€¦ ON CONFLICT (group_id, sender_handle, stream_index) DO NOTHING` | Every submit | Unique-index probe | `message_record_stream` |
| Q4 | `INSERT â€¦ ON CONFLICT (group_id, epoch) WHERE is_commit DO NOTHING` | Every commit | Partial unique probe | `message_record_commit` |
| Q5 | `SELECT group_id, record_id, retention_class, blob_id FROM message_record WHERE prune_after <= now() ORDER BY prune_after FOR UPDATE SKIP LOCKED LIMIT 1000` | Sweep, every 60 s | Partial index scan over the backlog only | `message_record_prune` |
| Q6 | `SELECT â€¦ WHERE recovery_handle = $1 ORDER BY group_id, record_id` | Rare (seed-only restore) | Partial index scan | `message_record_recovery` |
| Q7 | `SELECT last_stream_index FROM message_sender WHERE group_id=$1 AND sender_handle=$2` | Every submit | PK lookup | `PRIMARY KEY (group_id, sender_handle)` |
| Q8 | `SELECT â€¦ FROM message_blob WHERE grant_expire <= now() AND state <> 2 LIMIT 500` | Orphan reaper, every 5 min | Partial index scan | `message_blob_expire_grant` |
| Q9 | `SELECT write_key_wrapped, alg_id FROM message_epoch WHERE group_id=$1 AND epoch=$2` | Every submit on cache miss | PK lookup, served from an in-process LRU >99% of the time | `PRIMARY KEY (group_id, epoch)` |

Two properties of `message_record_prune` are load-bearing and easy to lose in a refactor:

1. It is **partial** on `prune_after IS NOT NULL`, and
2. the sweep **sets `prune_after = NULL`** after acting.

Together, the index holds only outstanding work. A full index on `prune_after` would grow with the corpus and every sweep pass would scan past millions of already-pruned rows. If a future change makes the sweep leave `prune_after` populated, this index becomes the service's largest and least useful object. There is a CI assertion for this in Â§13.

`message_record_stream` and `message_record_commit` are `UNIQUE` and therefore include `group_id`, the partition key, as Postgres requires for a partitioned unique index. `message_record_prune` and `message_record_recovery` are non-unique and need not.

### 3.4 Partitioning, TOAST, and vacuum

**Partitioning.** `PARTITION BY HASH (group_id)` with 64 partitions is defined in the DDL and is a **config switch, default off for v1**. Turn it on when `message_record` passes roughly 10^8 rows or when a single index exceeds working memory. It helps because Q1 is partition-local and because the sweep can walk one partition at a time, keeping each pass's lock and I/O footprint small. It does **not** enable a drop-partition retention trick â€” a pruned `MEDIA` record keeps its head forever (Â§8), so no partition ever becomes fully droppable. Do not design around that.

**TOAST.** Bodies at buckets 3 and 4 (16 KiB, 64 KiB) exceed the ~2 KiB TOAST threshold and go out of line. `STORAGE EXTERNAL` skips `pglz`, which cannot compress AEAD output and would cost CPU on every write and read. When the sweep sets `ct_body = NULL`, the TOAST chunks become dead and are reclaimed by the next autovacuum of the TOAST table â€” not immediately. Media-heavy deployments must confirm autovacuum is reaching `pg_toast.pg_toast_<oid>`; a common failure is a tuned `autovacuum_vacuum_scale_factor` on the parent that leaves the TOAST table untouched, and the operator's disk fills with erased bodies that are already logically gone.

**Bloat.** Records are otherwise write-once: the only UPDATE is the body erase and the `prune_after` NULLing. Set `fillfactor = 100` on `message_record` and its indexes; there is no HOT-update workload to reserve space for. `message_group` is the opposite â€” it is updated on every submit â€” so set `fillfactor = 70` there so the allocator update stays HOT.

---

## 4. API surface

### 4.1 Transport choice, and the argument for it

The task invites an argument for REST-over-transport. The answer is a split, and the split falls on a real boundary.

**Control plane â€” protobuf request/response inside connect `Frame`s.** Reasons:

1. It inherits connect's existing reliability, ordering, per-peer hybrid-PQ session encryption (`transfer_encrypt.go:378` leads with `tls.X25519MLKEM768`), and contract accounting, with zero new transport code and zero new attack surface.
2. **Subscribe needs server-initiated push.** The frame path gives it directly: the server calls `Send` to the client's `client_id`. HTTP needs a second mechanism (SSE, long-poll, or a WebSocket) that would then need its own reconnect, its own auth, and its own idle handling.
3. Control messages are small and already protobuf-shaped; `connect/protocol` already owns the codegen (`protocol/Makefile`).
4. REST would put a URL path on the wire for every operation. Paths are the single most-logged artefact in every HTTP stack on earth, and Â§9.7 forbids exactly that. A `oneof` inside an encrypted frame has no path to leak.

**Bulk plane â€” TLS/HTTP to the message server's own endpoint, reached through a provider like any internet host.** Reasons:

1. A 100 MB object driven through a sequence whose batching constant is 3 KiB and whose window is sized for chat would head-of-line-block every message in that client's sequence for the duration of the upload.
2. Range requests, `Content-Range` resumption, and multipart assembly already exist in HTTP and in MinIO's API. Reimplementing them over the frame path is weeks of work to reach parity with a solved problem.
3. The bytes are already client-encrypted under the `MEDIA` class key. The HTTPS layer is defence in depth, not the security boundary, so using an ordinary TLS stack costs nothing in the threat model.
4. Authorization does not leak into the bulk plane: a `BlobGrant` minted on the control plane is a bearer capability scoped to one `blob_id`, one direction, one size, and a short expiry. **`write_auth` is verified only on the control plane.** The blob endpoint knows nothing about groups.

So: **request/response messages, not REST, for everything that touches group state; HTTP only for opaque bytes already authorized elsewhere.**

### 4.2 Frame binding

Three additions to `connect/protocol/frame.proto`, in a reserved block, per decision B8:

```proto
    // â”€â”€ URmessage (beta/message). Block 1000-1099 reserved so parallel
    // beta branches do not collide. Every operation lives in a oneof inside
    // MessageServerRequest/Response, NOT as its own MessageType.
    MessageServerRequest  = 1000;
    MessageServerResponse = 1001;
    MessageServerPush     = 1002;
```

Client â†’ server frames are addressed to the instance's `client_id` with `Send`/`SendWithTimeout`. Server â†’ client pushes use the same, reversed. `Frame.raw` is always false for these.

### 4.3 Control-plane messages

New file `connect/protocol/message.proto`, `package bringyour`, generated alongside the existing protos. Spec A owns this file; the server links the generated Go directly so there is exactly one definition.

```proto
message MessageServerRequest {
    uint64 request_id = 1;              // client-scoped, monotonic, correlates the response
    uint32 protocol_version = 2;
    oneof body {
        HelloRequest          hello           = 10;
        CreateGroupRequest    create_group    = 11;
        SubmitRequest         submit          = 12;
        FetchRequest          fetch           = 13;
        SubscribeRequest      subscribe       = 14;
        UnsubscribeRequest    unsubscribe     = 15;
        GroupStatusRequest    group_status    = 16;
        BlobGrantRequest      blob_grant      = 17;
        RecoveryFetchRequest  recovery_fetch  = 18;
    }
}

message MessageServerResponse {
    uint64 request_id = 1;
    Reason reason = 2;                  // REASON_OK on success
    oneof body {
        HelloResponse         hello           = 10;
        CreateGroupResponse   create_group    = 11;
        SubmitResponse        submit          = 12;
        FetchResponse         fetch           = 13;
        SubscribeResponse     subscribe       = 14;
        GroupStatusResponse   group_status    = 16;
        BlobGrantResponse     blob_grant      = 17;
        RecoveryFetchResponse recovery_fetch  = 18;
    }
}

message MessageServerPush {
    oneof body {
        RecordPush       records      = 1;
        TransientPush    transient    = 2;   // EPH(0): never persisted
        CapabilityChange capability   = 3;
        Backpressure     backpressure = 4;
    }
}
```

#### 4.3.1 Hello â€” capability advertisement and nonce issuance

```proto
message HelloRequest {
    repeated uint32 supported_versions = 1;
    bytes  client_epoch_hint = 2;        // opaque; lets the server pre-warm caches
}

message HelloResponse {
    uint32 protocol_version      = 1;
    bytes  server_id             = 2;    // 16 B, stable per fleet
    bytes  server_signing_pub    = 3;    // Ed25519, pinned by the client on first contact (Â§9.4 master)
    uint64 server_time_ms        = 4;

    // Â§9.2: server_nonce comes from the connection challenge. Issued here,
    // scoped to THIS connection, and required in every write_auth on it.
    bytes  server_nonce          = 5;    // 32 B

    Capabilities capabilities    = 6;
    BlobEndpoint blob_endpoint   = 7;
    KtGossip     kt_gossip       = 8;    // the operator STH this server independently observed
}

message Capabilities {
    uint64 max_blob_bytes                = 1;   // default 104857600 (100 MB), master spec Â§12.2
    uint32 max_request_bytes             = 2;   // control-plane, post-fragmentation reassembly
    uint32 max_records_per_submit        = 3;   // default 64
    uint32 max_records_per_fetch         = 4;   // default 512
    uint32 media_ttl_default_seconds     = 5;   // default 2592000 (30 days)
    uint32 media_ttl_max_seconds         = 6;   // the advertised cap; policy above it is clamped
    uint32 durable_retention_min_seconds = 7;   // the minimum this server promises to honour
    repeated uint32 eph_bucket_seconds   = 8;   // [0, 3600, 28800, 86400, 604800, 2419200]
    repeated uint32 size_bucket_bytes    = 9;   // [256, 1024, 4096, 16384, 65536]
    uint32 blob_chunk_bytes              = 10;  // default 262144
    uint32 blob_pad_multiple             = 11;  // open item 4
    bool   attestation_supported         = 12;
}

message BlobEndpoint {
    string host              = 1;
    uint32 port              = 2;
    bytes  tls_spki_sha256   = 3;   // pinned; the client MUST NOT fall back to a CA path
    string path_prefix       = 4;
}
```

`Capabilities` is the whole of the server-advertised contract. The client MUST fetch it before its first submit of a session and MUST re-read it on `CapabilityChange`. Spec C must surface `max_blob_bytes` **before** the file picker opens, not after the user has waited for a 400 MB read.

#### 4.3.2 Create group

```proto
message CreateGroupRequest {
    bytes  group_id          = 1;   // 32 B, CSPRNG, client-chosen
    Record initial_commit    = 2;   // is_commit = 1, epoch = 0
    EpochAttachment epoch0   = 3;   // carries write_key[0] and the initial policy
}
message CreateGroupResponse {
    uint64 current_epoch = 1;
    uint64 record_id     = 2;
    RetentionApplied applied = 3;   // what the server actually clamped to
}
```

Squatting: `group_id` is a 32-byte CSPRNG value chosen by the creator, so a targeted pre-registration requires guessing it. `CreateGroup` on an existing id returns `REASON_REJECTED` (see Â§4.5 on why it does not distinguish itself from a bad MAC) and the creator retries with a fresh id. Group creation is rate-limited per `client_id`.

#### 4.3.3 Submit

```proto
message SubmitRequest {
    bytes  group_id = 1;
    repeated Record records = 2;    // at most Capabilities.max_records_per_submit
}

message Record {
    bytes  sender_handle    = 1;   // 16 B
    uint64 epoch            = 2;
    uint64 stream_index     = 3;
    bool   is_commit        = 4;
    uint32 retention_class  = 5;
    uint32 size_bucket      = 6;
    uint64 expire_at_ms     = 7;   // advisory (master Â§8); stored, echoed, never swept on
    bytes  body_hash        = 8;   // 32 B, H(ct_body); retained after erasure
    bytes  ct_head          = 9;
    bytes  ct_body          = 10;  // absent when size_bucket = 5 (blob-ref)
    bytes  blob_id          = 11;  // present iff size_bucket = 5
    bytes  server_attachment = 12; // typed, extensible; empty for ordinary records (open item 1)
    bytes  write_auth       = 13;  // MAC per master Â§9.2, extended per open item 1
}

message SubmitResponse {
    repeated SubmitResult results = 1;   // positionally aligned with the request
}
message SubmitResult {
    Reason reason         = 1;
    uint64 record_id      = 2;   // set when accepted or idempotently re-accepted
    uint64 current_epoch  = 3;   // always set, so a stale client resynchronises in one round trip
    Record winning_commit = 4;   // set only on REASON_COMMIT_LOST (Â§6.2)
    RetentionApplied applied = 5;
}
```

**A batch containing a commit MUST contain exactly one record.** Mixing a commit with ordinary records in one batch would make partial-failure semantics ambiguous during an epoch change and buys nothing â€” a commit is one record by construction.

#### 4.3.4 Fetch

```proto
message FetchRequest {
    bytes  group_id        = 1;
    uint64 since_record_id = 2;   // exclusive
    uint32 limit           = 3;
    bool   heads_only      = 4;   // skip ct_body; used for fast catch-up and for hole scans
    uint32 class_mask      = 5;   // bitmask of retention_class values to include; 0 = all
}
message FetchResponse {
    repeated Record records       = 1;
    uint64 next_record_id         = 2;
    uint64 high_water_record_id   = 3;   // the group's max at read time
    bool   complete               = 4;   // false when truncated by limit
    FetchAttestation attestation  = 5;
}
message FetchAttestation {                // master Â§9.4
    bytes  group_id            = 1;
    uint64 since_record_id     = 2;
    uint64 until_record_id     = 3;
    repeated uint64 record_ids = 4;
    uint64 high_water_record_id = 5;
    uint64 server_time_ms      = 6;
    bytes  server_id           = 7;
    bytes  sig                 = 8;       // Ed25519 over the canonical encoding below
}
```

Attestation signature input:

```
"URmessage/v1/attest" â€– LP(server_id) â€– LP(group_id)
  â€– u64(since_record_id) â€– u64(until_record_id) â€– u64(high_water_record_id)
  â€– u32(count) â€– u64(record_id[0]) â€– â€¦ â€– u64(record_id[count-1])
  â€– u64(server_time_ms)
```

`high_water_record_id` is inside the signature deliberately: it is what makes "the server told me nothing newer existed" an attributable statement rather than an absence. Because `record_id` is per-group and gapless (decision B4), a client can detect a withheld record as a **hole in the id sequence** without any digest machinery â€” which is a real v1 improvement over the master spec's Â§12.3 admission that withholding is undetectable, though it does not close it (a server can withhold a contiguous tail, and Â§12.3's honest limit stands).

#### 4.3.5 Subscribe

```proto
message SubscribeRequest {
    repeated Subscription subscriptions = 1;
    bool replace = 2;                   // true = this is the complete set for this connection
}
message Subscription {
    bytes  group_id        = 1;
    uint64 since_record_id = 2;
}
message SubscribeResponse {
    repeated SubscriptionAck acks = 1;  // each carries snapshot_record_id (Â§4.4)
}
message RecordPush {
    bytes  group_id = 1;
    repeated Record records = 2;        // always contiguous in record_id
    uint64 high_water_record_id = 3;
}
message TransientPush {                 // EPH(0) â€” receipts, typing. Never touches disk.
    bytes  group_id = 1;
    repeated Record records = 2;
}
```

#### 4.3.6 Blob grant

```proto
message BlobGrantRequest {
    bytes  group_id        = 1;
    bytes  blob_id         = 2;   // 32 B, client-chosen (content-independent; see Â§8.1)
    Direction direction    = 3;   // UPLOAD | DOWNLOAD
    uint64 declared_bytes  = 4;   // upload only; already padded per Capabilities
    uint32 retention_class = 5;   // MEDIA, or the parent's EPH class (master Â§12.2)
    bytes  write_auth      = 6;   // proves group membership before any object-store work
}
message BlobGrantResponse {
    bytes  grant_token   = 1;   // opaque bearer capability; see Â§8.2
    uint64 expires_ms    = 2;
    uint32 chunk_bytes   = 3;
    bytes  chunk_mask    = 4;   // upload: chunks already received, for resume
    string path          = 5;   // path under BlobEndpoint.path_prefix
}
```

#### 4.3.7 Recovery fetch (seed-only restore, master Â§5.4)

```proto
message RecoveryFetchRequest {
    bytes  recovery_handle = 1;   // 16 B
    bytes  proof           = 2;   // MAC over the connection's server_nonce under a
                                  // recovery_root-derived key; proves possession, not identity
    uint64 cursor          = 3;
    uint32 limit           = 4;
}
message RecoveryFetchResponse {
    repeated GroupRecords groups = 1;
    uint64 next_cursor = 2;
}
```

This request is the one place a client asks for data across groups, and it is exactly the disclosure the master spec Â§5.4 already makes ("the server learns how many groups that handle participates in"). It is rate-limited hard (Â§4.7) because it is otherwise an oracle for handle existence.

### 4.4 The subscribe race, resolved

Naive subscribe has a well-known hole: register-then-backfill duplicates and misses, backfill-then-register loses everything written in between. The required sequence is:

1. On `SubscribeRequest`, the instance **registers the Redis subscription first** and begins **buffering** pushes for that group in memory, without sending them.
2. It then reads a backfill snapshot: `Q1` bounded by `LIMIT`, capturing `snapshot_record_id = high_water_record_id` at the moment of the read.
3. It returns `SubscriptionAck{snapshot_record_id}` and streams the backfill.
4. It then **flushes the buffer, discarding every buffered record with `record_id <= snapshot_record_id`**, and goes live.
5. If the buffer overflows (slow client, large group), the instance drops the buffer, sends `Backpressure{group_id, resume_from_record_id}`, and the client re-subscribes from its own high-water. **It never silently drops records** â€” a silent drop is indistinguishable from server withholding, which is precisely the thing clients are supposed to be able to notice.

Because `record_id` is gapless, the client can assert contiguity across the seam and treat any gap as a fault.

### 4.5 Reason codes, and what they may not distinguish

```proto
enum Reason {
    REASON_OK                       = 0;
    REASON_REJECTED                 = 1;  // deliberately non-specific; see below
    REASON_EPOCH_STALE              = 2;  // carries current_epoch
    REASON_COMMIT_LOST              = 3;  // carries the winning commit
    REASON_STREAM_INDEX_REUSED      = 4;  // same index, different content
    REASON_STREAM_INDEX_REGRESSED   = 5;  // index <= last accepted
    REASON_OVERSIZE                 = 6;
    REASON_QUOTA_EXCEEDED           = 7;
    REASON_RATE_LIMITED             = 8;  // carries retry_after_ms
    REASON_RETENTION_CLAMPED        = 9;  // accepted, policy reduced to the advertised cap
    REASON_BLOB_UNKNOWN             = 10;
    REASON_BLOB_INCOMPLETE          = 11;
    REASON_UNSUPPORTED_VERSION      = 12;
    REASON_INTERNAL                 = 13;
}
```

**`REASON_REJECTED` deliberately merges "unknown group", "write_auth did not verify", and "epoch key unknown".** Distinguishing them would turn the submit path into an oracle for group existence: a party who holds no `write_key` could enumerate `group_id`s and learn which exist. The reject is the same code, the same response size, and the same timing envelope (the handler pads its response latency to a fixed floor on the reject path).

`REASON_EPOCH_STALE` and `REASON_COMMIT_LOST` do reveal that the group exists â€” but they are only ever returned **after** a `write_auth` verified, so the caller already holds a group secret.

### 4.6 Fragmentation (open item 2)

`ClientSettings.MinimumMessageLenLimit()` is 4 KiB and `sendPackBatchMaxMessageByteCount` is 3 KiB. A 64 KiB inline record does not fit a frame, and we must not assume any particular production `MaxMessageLen`. Therefore the control plane carries its own fragmentation, transport-cap independent:

```proto
message MessageServerFragment {
    uint64 request_id = 1;
    uint32 index      = 2;
    uint32 count      = 3;
    bytes  part       = 4;
}
```

Rules:

- The sender chooses `part` size as `min(peer_advertised_frame_budget, 2048)` bytes and MUST NOT exceed the negotiated budget.
- The receiver reassembles into a buffer capped at `Capabilities.max_request_bytes`; exceeding it aborts the request with `REASON_OVERSIZE` and **frees the buffer immediately** â€” an unbounded reassembly buffer is a trivial memory-exhaustion vector.
- Reassembly state is per `(source client_id, request_id)`, expires after 30 s, and is capped at 16 concurrent in-flight reassemblies per client.
- Fragments MUST be delivered in order by the underlying sequence; out-of-order `index` aborts the request rather than buffering holes.

Until open item 2 is settled by measurement, the working assumption is `max_request_bytes = 131072` with fragmentation on.

### 4.7 Rate limits

| Limit | Default | Scope | Backing |
|---|---|---|---|
| Records/s | 20 sustained, 100 burst | `client_id` | Redis token bucket, in-process fallback |
| Bytes/s (control) | 512 KiB/s | `client_id` | Redis |
| Records/s | 200 sustained | `group_id` (masked) | Redis |
| Group creations | 20/day | `client_id` | Redis + Postgres counter |
| Blob grants | 60/hour | `client_id` | Redis |
| Blob bytes/day | 2 GiB | `client_id` | Redis |
| RecoveryFetch | 5/hour, 20/day | `recovery_handle` **and** `client_id` | Redis, both must pass |
| Fetch records/s | 5,000 | `client_id` | Redis |

On Redis unavailability, all limits fail **closed** to an in-process limiter at 25% of the configured rate. Availability is not worth an unmetered write path.

---

## 5. `write_auth` verification

### 5.1 The exact check order (normative)

Order matters for denial of service, not just correctness. Nothing that costs a database read happens before something that costs a hash.

| # | Check | Cost | On failure |
|---|---|---|---|
| 1 | Frame decodes; fragment reassembly within `max_request_bytes` | CPU, bounded | `REASON_OVERSIZE`, free buffer |
| 2 | Connection is authenticated at the connect layer (`ByJwt` validated by the platform; Â§4.3 master) and `request.server_nonce == this connection's issued nonce` | memory | `REASON_REJECTED` |
| 3 | **Static shape.** `octet_length(sender_handle)==16`, `body_hash`==32, `retention_class` and `size_bucket` in range, `expire_at` parses, `ct_head` â‰¤ head cap, and **`octet_length(ct_body)` is exactly `size_bucket_bytes[b] + 16`** (the AEAD tag) â€” equality, not a range, because Â§9.5 pads into buckets. `size_bucket == 5` requires `ct_body` absent and `blob_id` present. `server_attachment` well-formed for its record kind | CPU | `REASON_OVERSIZE` / `REASON_REJECTED` |
| 4 | **Rate limits** (Â§4.7) | Redis | `REASON_RATE_LIMITED` |
| 5 | **Known-group filter.** An in-memory cuckoo filter of every `group_id`, refreshed from Postgres on a timer. An unknown group is rejected here with **no database read** | memory | `REASON_REJECTED` |
| 6 | **Epoch key lookup.** In-process LRU keyed `(group_id, epoch)`; miss reads `message_epoch` once, unwraps under the KEK, caches. Negative results cached 5 s with jitter | memory / 1 read | `REASON_REJECTED` |
| 7 | **MAC.** Recompute the Â§9.2 preimage byte-for-byte using `connect/message`'s encoder â€” never a local reimplementation â€” and compare with `hmac.Equal` | CPU | `REASON_REJECTED` |
| 8 | `body_hash == SHA-256(ct_body)` for inline bodies | CPU | `REASON_REJECTED` |
| 9 | **Only now**: open the transaction and take the group row lock (Â§6.1) | DB | see Â§6 |

Steps 1â€“8 are lock-free and touch the database at most once, only for a group that actually exists. An attacker without a `write_key` cannot force a single row lock, a single index write, or a single WAL byte.

### 5.2 What the server explicitly does NOT check, and why

| Not checked | Why |
|---|---|
| Any plaintext, message type, or semantic content | It cannot decrypt, and adding a decryption capability would end the design |
| That the sender is a **particular** member | `write_key` is group-wide (Â§9.2). The server learns "a current member of this group" and no more. This is the accepted v1 cost of dropping per-device capabilities |
| MLS validity of anything: proposal legality, commit correctness, tree hash, transcript hash, `confirmation_tag`, leaf signatures, credentials, capability consistency, or any of the 43 ValSem codes | **I5.** Authentication is MLS's, end to end. The server does not link an MLS implementation, at all â€” see Â§5.3 |
| Roles: OWNER / ADMIN / MEMBER / OBSERVER | Â§11 of the master spec puts roles in the transcript-covered group-context extension, which the server cannot read. `OBSERVER` is UI- and MLS-enforced in v1 |
| Whether an accepted commit is *the right* commit | Â§9.3 requires only that it is *the first valid* one. "Right" is not a property the server can evaluate, and pretending otherwise would make the server an MLS participant |
| Deletion authority | Decision B6: there is no client-initiated erase in v1 |
| Whether a record duplicates an earlier one semantically | Only the `(group_id, sender_handle, stream_index)` uniqueness is enforced |

**Why authenticity is MLS's job and not the server's.** Two reasons, and the second is the one that matters.

The first is capability: the server holds no group leaf key, so it cannot tell a genuine sender from a member impersonating another member. Any check it invented would be weaker than the one the client already performs.

The second is trust structure. Every check the server *can* perform, the server can also *skip*. If clients came to depend on a server-side validity check, the server would have quietly become a participant in the security argument â€” and Â§4.2's entire point is that it is not one. A record forged by anyone without a group leaf key fails MLS verification at every client regardless of what the server accepted. `write_auth` therefore exists for exactly three purposes: **quota, spam control, and refusal.** It is an access-control token, never a proof, and no client may treat a server's acceptance as evidence of anything.

**Normative:** `FetchResponse` and `RecordPush` assert nothing about validity. A client MUST fully verify every record through MLS regardless of which server delivered it, regardless of `FetchAttestation`, and regardless of whether the record arrived over a subscription it opened itself.

### 5.3 Epoch key custody

`write_key[n] = HKDF-Expand(storage_root[n], "write/v1", 32)` is delivered to the server by the committer, in the commit record's `server_attachment`, over the connect session's own hybrid-PQ encryption.

The master spec Â§9.2 says the server "holds `H(write_key)`-derived verification state per epoch." **That phrasing is not realizable for a symmetric MAC**: verifying `MAC(write_key, â€¦)` requires `write_key` itself, and a hash of it verifies nothing. This spec therefore implements the only thing that works â€” the server holds the key â€” and records the consequences plainly:

- **A server holding `write_key` can forge `write_auth`.** This changes nothing in the threat model: the server is the party enforcing `write_auth`, so it could equally just accept an unauthenticated record. Any record it injects fails MLS at every client (**I5**).
- **A stolen database dump alone must not yield write keys.** Keys are stored wrapped: `AES-256-GCM(KEK, write_key)` with a random 12-byte nonce, KEK loaded from vault resource `message_server.yml` and never written to the database, never in a database backup, and rotated independently (Â§10.4).
- **Only the current epoch's key is retained** (decision B9). Advancing to epoch *n+1* NULLs `write_key_wrapped` for every epoch `< n+1` in the same transaction.
- **`write_key` derives nothing else.** It is a label-separated HKDF child of `storage_root[n]`, so holding it yields neither `storage_root` nor the sibling class keys `K_perm` / `K_durable` / `K_media` / `eph_root`. This property is why the server can hold it at all, and it MUST NOT be reused for any second purpose â€” a second use would compose two contexts under a key an untrusted party holds.

An asymmetric write proof (per-epoch Ed25519 derived from `storage_root`, server holds only the public half) would remove the forgery capability entirely at the cost of one signature per record. It is the right long-term shape and is recorded as a recommendation against master spec Â§9.2 in **open item 1**. It is not a v1 blocker because the forgery capability buys an attacker nothing that clients accept.

**Normative:** the message server binary MUST NOT link an MLS implementation. A CI check asserts `connect/mls` does not appear in `go list -deps`. This is not fussiness â€” the moment an MLS parser is in this process, the temptation to "just validate the commit" becomes a one-line change, and I5 dies quietly.

### 5.4 Required amendments to master spec Â§9.2 (open item 1)

Two server-visible fields have no home in the current preimage, and **I6** forbids the server from acting on anything it cannot verify:

1. **Epoch attachment.** A commit's `write_key[n+1]` and retention policy. Without it the server cannot verify the next epoch's records at all, and a forged attachment would let any member set the next epoch's write key or set `media_ttl` to one second.
2. **`recovery_handle`.** The server indexes and serves by it (Â§5.4 of the master spec). An unauthenticated handle would let a member tag another member's archive records into their own recovery index.

Single proposed amendment covering both, and every future server-visible field:

```
write_auth = MAC(write_key, "URmessage/v1/write" â€– LP(server_nonce) â€– LP(group_id)
                 â€– LP(sender_handle) â€– u64(epoch) â€– u64(stream_index) â€– u8(is_commit)
                 â€– u8(retention_class) â€– u8(size_bucket) â€– u64(expire_at)
                 â€– LP(H(ct_head)) â€– LP(body_hash)
                 â€– LP(H(server_attachment)))                        â† added

AAD_head  = â€¦ â€– LP(body_hash) â€– LP(H(server_attachment))            â† added
```

`server_attachment` is a typed, extensible byte string: empty for ordinary records, `EpochAttachment` for commits, `RecoveryTag` for archive records. This is a **wire-format addition and must land before slice 2 freezes the format.**

---

## 6. Single-commit agreement â€” the Delivery Service

The message server is the MLS Delivery Service of RFC 9750 Â§5.2.1, implementing the strongly-consistent design. Master spec Â§9.3 states the three requirements; this section specifies the mechanism.

### 6.1 The transaction

```sql
BEGIN ISOLATION LEVEL READ COMMITTED;

-- (1) Lock the group and allocate the record id block in one statement.
--     This row lock is simultaneously: the CAS serialiser, the record_id
--     allocator, and the epoch-advance mutex. One lock, three jobs.
UPDATE message_group
   SET next_record_id = next_record_id + $n
 WHERE group_id = $1 AND NOT closed
RETURNING current_epoch,
          next_record_id - $n AS first_record_id,
          media_ttl_seconds, durable_ttl_seconds;
--     0 rows  -> REASON_REJECTED (unknown or closed; indistinguishable, Â§4.5)

-- (2) Epoch gate. RFC 9750 Â§5.2.1: records at a non-current epoch are refused.
--     if record.epoch <> current_epoch:
--         ROLLBACK; return REASON_EPOCH_STALE{current_epoch}

-- (3) Stream monotonicity, per (group_id, sender_handle). Monotonic, NOT
--     contiguous â€” master spec Â§8: "a refused write does not brick the stream."
SELECT last_stream_index FROM message_sender
 WHERE group_id = $1 AND sender_handle = $2;
--     record.stream_index <= last  -> REASON_STREAM_INDEX_REGRESSED
--     (idempotent-retry handling in Â§6.3 runs first)

-- (4a) Ordinary record.
INSERT INTO message_record (...) VALUES (...);

-- (4b) Commit record. The partial unique index is the backstop; the row lock
--      above is the primary mechanism. Both, deliberately.
INSERT INTO message_record (..., is_commit) VALUES (..., true)
ON CONFLICT (group_id, epoch) WHERE is_commit DO NOTHING;
--     0 rows inserted -> the CAS was lost:
SELECT * FROM message_record
 WHERE group_id = $1 AND epoch = $2 AND is_commit;
--     ROLLBACK; return REASON_COMMIT_LOST{current_epoch, winning_commit}

-- (5) On a won commit, and only then: open the next epoch and retire the old key.
INSERT INTO message_epoch (group_id, epoch, write_key_wrapped, alg_id, opened_by_record)
     VALUES ($1, current_epoch + 1, wrap(attachment.write_key), attachment.alg_id, record_id);
UPDATE message_epoch SET write_key_wrapped = NULL
 WHERE group_id = $1 AND epoch <= current_epoch;
UPDATE message_group
   SET current_epoch      = current_epoch + 1,
       media_ttl_seconds  = LEAST(attachment.media_ttl_seconds,  $server_media_cap),
       durable_ttl_seconds = ...,
       group_context_hash = attachment.group_context_hash
 WHERE group_id = $1;

-- (6) Sender high-water and accounting.
INSERT INTO message_sender (...) VALUES (...)
ON CONFLICT (group_id, sender_handle) DO UPDATE
   SET last_stream_index = EXCLUDED.last_stream_index,
       record_count = message_sender.record_count + 1,
       byte_count   = message_sender.byte_count + EXCLUDED.byte_count,
       last_time    = EXCLUDED.last_time;

COMMIT;
-- (7) AFTER commit, never before: publish {mask, lo, hi} to Redis.
```

Why both the row lock and the unique index: the lock makes the losing path deterministic and lets the winner be read and returned in the same round trip; the index guarantees the invariant even if some future code path forgets the lock. The invariant is worth two mechanisms.

**Attachment validation precedes acceptance (normative).** A commit is validated for attachment well-formedness â€” `epoch == current_epoch + 1`, `write_key` exactly 32 bytes, `alg_id` known, retention fields in range â€” at step 3 of Â§5.1, *before* the CAS. An accepted commit carrying a malformed attachment would open an epoch with no verifiable write key and **brick the group permanently**: no member could ever submit again, and there is no epoch to commit from. This is the single most damaging failure available to a buggy client, and it is prevented by refusing the commit rather than by accepting and repairing.

### 6.2 What happens to a losing committer

The server returns:

```
SubmitResult{ reason = REASON_COMMIT_LOST,
              current_epoch = n+1,
              winning_commit = <the full accepted Record> }
```

The loser MUST, in order:

1. **Discard its provisional epoch-*n+1* state entirely** â€” the TreeKEM path secrets, the derived `storage_root[n+1]`, `write_key[n+1]`, and every X-Wing wrap it built.
2. **MUST NOT reuse the `pq_secret[n+1]` it sampled.** It was encapsulated to a ratchet tree that no longer exists; carrying it into the real epoch *n+1* would bind one PQ secret across two distinct epochs and break the Â§7 composition's per-epoch independence. Sample a fresh one. This is a hard MUST NOT, easy to violate as an "optimisation," and invisible in testing.
3. **Apply the winning commit** from `winning_commit`, verifying it through MLS exactly as if it had arrived by fetch. Server delivery grants it nothing.
4. **Recompute which of its own proposals remain unapplied.** RFC 9420 commits reference proposals by hash; the winner may already have included some or all of them. Blindly re-proposing produces duplicates that a correct implementation will then reject.
5. **Re-propose only the remainder**, and retry the commit at epoch *n+1*.
6. **Discard and re-encrypt any records it optimistically produced at epoch *n+1***. Their `stream_index` values were already consumed and MUST NOT be reused (master spec Â§8: a device durably records "index *k* consumed" *before* encrypting). The stream therefore acquires a gap â€” which is legal precisely because the server enforces monotonicity and not contiguity. This is the clause that makes the whole retry loop safe, and it exists for exactly this case.
7. **Back off before retrying**: full jitter, base 250 ms, cap 8 s, maximum 5 attempts, then surface a failure to the user. A 500-member group where an admin change triggers simultaneous commits is a thundering herd; without jitter it converges on livelock.

The server publishes `message_commit_cas_total{result="lost"}`. A sustained loss rate above ~1% means clients are thrashing and the backoff is mistuned; it is an alerting signal, not background noise.

### 6.3 Idempotent retry versus stream-index reuse

A client that times out and retries a submit that actually landed must not be told it lost. On a unique violation of `(group_id, sender_handle, stream_index)`:

```
load the existing row
if existing.body_hash == new.body_hash AND H(existing.ct_head) == H(new.ct_head):
        return REASON_OK { record_id = existing.record_id }     -- idempotent
else:
        return REASON_STREAM_INDEX_REUSED                        -- client bug or attack
```

Comparing both hashes, not just `body_hash`, matters: two records can legitimately share a body hash (an empty body) while differing in the head.

For a **commit** the same rule applies and takes precedence over the CAS check â€” a retried identical commit returns `REASON_OK`, not `REASON_COMMIT_LOST`. Getting this backwards makes every timeout look like a fork and sends the client through the epoch-*n+1* discard path unnecessarily, which is expensive and, per Â§6.2 step 2, burns a `pq_secret`.

### 6.4 Failure modes and their responses

| Failure | Behaviour |
|---|---|
| Instance dies mid-transaction | Postgres rolls back. Nothing partially applied. The client retries; Â§6.3 makes it idempotent |
| Two instances commit simultaneously | Both take the same row lock; one blocks; the second observes the advanced epoch and returns `EPOCH_STALE`, or loses the CAS and returns `COMMIT_LOST` |
| Redis publish fails after commit | The record is durable; only push is lost. The client's next fetch or reconnect backfill picks it up. **The publish is never inside the transaction** |
| Client submits at epoch *n* while a commit to *n+1* is landing | `EPOCH_STALE{n+1}`; client re-encrypts at *n+1*, consuming a new `stream_index` and leaving a gap |
| Group row lock contention | Bounded by `lock_timeout = 3s`; on timeout return `REASON_RATE_LIMITED{retry_after}` rather than holding the connection |
| Attachment malformed | Commit refused before the CAS (Â§6.1). The group's current epoch is untouched |

---

## 7. Retention and pruning

### 7.1 Pruning without knowing what anything is

The server knows six things about a record: its class, its size bucket, its group, its arrival time, its client-declared `expire_at`, and the group's retention policy as published in the last epoch attachment. It knows nothing about content, and it never needs to. Every retention decision is a function of those six.

At admission the server computes:

```
prune_after =
  PERMANENT (0)   -> NULL                                     -- never
  DURABLE   (1)   -> NULL, or create_time + group.durable_ttl_seconds when set,
                     floored at Capabilities.durable_retention_min_seconds
  MEDIA     (2)   -> create_time + LEAST(group.media_ttl_seconds,
                                         Capabilities.media_ttl_max_seconds)
  EPH(0)          -> never stored at all (Â§7.2)
  EPH(1..5)       -> create_time + eph_bucket_seconds[b] + grace
```

`grace` is 1 hour, absorbing client clock skew and delayed delivery. It is safe because expiry is enforced by key destruction, not by this row disappearing: after `eph_root[n]` is gone, a retained ciphertext is undecryptable by everyone including a seedphrase holder (master Â§8.1). The server's deletion is hygiene.

`expire_at` is stored and echoed verbatim, never consulted (decision B5).

### 7.2 What each class actually does at `prune_after`

| Class | Action | Head | Body | Blob | Row |
|---|---|---|---|---|---|
| `PERMANENT` | none | kept | kept | n/a | kept |
| `DURABLE` | none by default; if the group set a TTL, same as MEDIA | kept | erased | deleted | kept |
| `MEDIA` | `ct_body = NULL`, blob deleted | **kept** | erased | deleted | **kept** |
| `EPH(0)` | never persisted; fanned out through Redis to online subscribers and dropped | â€” | â€” | â€” | â€” |
| `EPH(1..5)` | whole row deleted, blob deleted | deleted | deleted | deleted | deleted |

`MEDIA` keeps its head and `body_hash` forever, per master spec Â§8 ("`body_hash` RETAINED when `ct_body` is erased"), which is what lets the client render "this attachment expired" in the right place in the timeline and keeps the record chain intact. Master spec Â§12.2's "attachment on an ephemeral parent inherits the parent's key class" is honoured by the client choosing `EPH(b)` rather than `MEDIA` for such a record â€” the server just applies the class it is given.

`EPH(0)` never touching disk is what makes master spec Â§12.2's "never persisted" true rather than aspirational. Receipts and typing indicators arrive, are published to the group's Redis channel, are delivered to whoever is currently subscribed, and are gone. There is no `INSERT`.

After acting, the sweep **sets `prune_after = NULL`**, removing the row from `message_record_prune`. See Â§3.3 â€” this is what keeps the sweep's cost proportional to the backlog rather than the corpus.

### 7.3 The advertised cap and minimum

Three numbers in `Capabilities`, all configuration:

| Field | Default | Meaning |
|---|---|---|
| `max_blob_bytes` | 100 MB | Master spec Â§12.2. Clients respect it; the server also enforces it at grant time and at assembly time |
| `media_ttl_max_seconds` | 30 days | The cap. A group policy above it is silently clamped and the commit returns `REASON_RETENTION_CLAMPED` |
| `durable_retention_min_seconds` | 0 (indefinite) | The minimum this server promises to honour for `DURABLE` |

**Open item 3 / ledger open item 1** â€” a group policy exceeding the advertised cap. Recommendation: **warn and proceed.** The server clamps, accepts the commit, and returns `REASON_RETENTION_CLAMPED{applied}`. The client renders a one-time in-group notice naming the applied value. The group's transcript-covered policy is unchanged, so if the group later moves to a server with a higher cap (V2), the original policy takes effect again with no migration. Refusing the commit instead would let an operator's configuration change block a group from committing at all, which is a worse failure than shorter media retention. **Owner ruling required.**

### 7.4 The sweep job

No `server/task` (decision B1), so an in-process scheduler:

- One goroutine per instance, ticking every 60 s.
- Mutual exclusion via `pg_try_advisory_lock(<constant>)` on a dedicated connection. Failure to acquire means another instance is sweeping; skip this tick. No leader election, no coordination service.
- Each pass, bounded:

```sql
SELECT group_id, record_id, retention_class, blob_id
  FROM message_record
 WHERE prune_after <= now()
 ORDER BY prune_after
   FOR UPDATE SKIP LOCKED
 LIMIT 1000;
```

- `SKIP LOCKED` means the sweep never queues behind a submit's group row lock, and never causes one to wait.
- Per batch: update or delete rows, commit, then delete the batch's blob objects. **Postgres first, object store second.** A crash between them leaves an orphaned object, which the orphan reaper and the ILM backstop both clean up. The reverse order would leave a row pointing at a deleted object, which is a user-visible fault.
- Between batches: 100 ms sleep. Per pass: max 50 batches or 20 s wall clock, whichever first. Steady state should keep `message_prune_lag_seconds` â€” `now() - min(prune_after)` over outstanding work â€” under an hour. That gauge is the retention SLO; alert above 6 h.
- A second, slower loop every 5 minutes: blob orphan reaping (`message_blob_expire_grant`), `message_group_usage` recomputation, and epoch-row tidying.
- `messagectl sweep-now --until-clean` runs the sweep to completion synchronously. It is required after every restore (Â§10.4).

---

## 8. Blob lifecycle

### 8.1 Identity and padding

`blob_id` is 32 bytes chosen by the client and **MUST NOT** be a hash of the plaintext or of the ciphertext. A content-derived id makes the object store a confirmation oracle: an adversary holding a candidate file could test whether it exists. Spec A supplies `blob_id` from the record's key material, so it is unlinkable across groups.

Object length is padded by the client to a multiple of `Capabilities.blob_pad_multiple` (default 256 KiB) before upload. Bounded overhead, removes fine-grained size fingerprinting. Ladder owned by spec A â€” **open item 4**.

Content type is always `application/octet-stream`. The server has never seen a media type and never will.

### 8.2 Grant tokens

A `BlobGrant` is minted on the control plane after `write_auth` verifies, so the bulk endpoint never sees a group id and never verifies group membership:

```
grant = base64url( nonce(12) â€– AES-256-GCM(grant_kek,
            u8(direction) â€– LP(blob_id) â€– u64(declared_bytes)
          â€– u32(chunk_bytes) â€– u64(expires_ms) â€– LP(client_id)) )
```

`grant_kek` is a server secret from the vault, shared across the fleet so any instance can serve any grant. The token is a bearer capability scoped to one `blob_id`, one direction, one size, and a 15-minute expiry (refreshable for long uploads). It carries `client_id` so a leaked token cannot be replayed from another session, and it contains no group id, so possession of a grant reveals nothing about membership.

### 8.3 Upload, download, storage

**Upload** â€” `PUT {path_prefix}/b/{blob_id}/{chunk_index}` with `Authorization: Bearer <grant>`:

1. The endpoint decrypts the grant, checks direction, expiry, `client_id`, and that `chunk_index * chunk_bytes < declared_bytes`.
2. Writes the chunk to the object store as `<object_key>/<chunk_index>`.
3. Sets the bit in `message_blob.chunk_mask` and advances `received_bytes`.
4. When the mask is full, assembles into `<object_key>` via MinIO multipart compose, sets `state = COMPLETE`, deletes the chunk objects.

Resume is `BlobGrantRequest` again: the response carries the current `chunk_mask` and the client uploads only the missing chunks. Idempotent â€” re-uploading a chunk is a no-op.

**Binding.** A blob becomes `BOUND` when a record with `size_bucket = 5` and that `blob_id` is accepted on the control plane. At that moment the server verifies `state == COMPLETE` (else `REASON_BLOB_INCOMPLETE`) and copies `prune_after` from the record. **An unbound blob is deleted at `grant_expire`**, so a client that uploads and never submits leaves nothing behind.

**Download** â€” `GET {path_prefix}/b/{blob_id}` with a download grant, supporting `Range`. The bytes are ciphertext; the endpoint streams them without touching Postgres beyond the grant check.

**Object keys encode the retention ladder rung**, so the ILM backstop works without per-object rules:

```
<prefix>/<env>/msg/media/ttl-30d/<hex(blob_id)>
<prefix>/<env>/msg/eph/ttl-1h/<hex(blob_id)>
```

Only a fixed ladder of TTLs is offered â€” `{1h, 8h, 1d, 7d, 30d, 90d, 180d, 365d}` â€” precisely so it maps to a bounded set of `BlobLifecycleRule{KeyPrefix, TTL}` entries via the existing `BlobStore.SetLifecycle`.

### 8.4 The `Delete` gap in `server/blob.go`

The operator's `BlobStore` interface has **no `Delete`**, deliberately: retention there is ILM-only. That is insufficient here, because a `MEDIA` body may need removal before its ladder TTL (a group shortens its policy; a blob is orphaned at grant expiry). The message server therefore defines its own interface:

```go
type MessageBlobStore interface {
    server.BlobStore                                    // Put/Get/List/SetLifecycle/Bucket/Prefix/Authority
    Delete(ctx context.Context, key string) error
    DeletePrefix(ctx context.Context, keyPrefix string) (int, error)
}
```

implemented over `minio-go`'s `RemoveObject`/`RemoveObjects` and over the local filesystem backend for dev. **Both mechanisms run: explicit `Delete` as the fast path, ILM as the floor.** If the sweep never runs for a month, media still expires. If ILM is misconfigured, the sweep still deletes. Neither is trusted alone.

---

## 9. Operator integration

### 9.1 The message server's own URnetwork account

Master spec Â§4.4: the message server holds its own account, and that credential is a server-side secret.

| Aspect | Design |
|---|---|
| Account | One network for the fleet, provisioned once by an operator admin |
| Client ids | One `network_client` per instance; `client_id` and its credential in vault `message_server.yml` |
| Session | Each instance runs a `connect.Client` against the platform transport exactly as any client does. `AddReceiveCallback` dispatches `MessageServerRequest` frames; responses go back through `Send` |
| Contracts | Long-lived per `(device, message server)`, provider-terminated (master Â§9.6) |
| Discovery | Clients resolve the fleet from the operator (Â§9.3), pin `server_signing_pub` on first contact, and pin `BlobEndpoint.tls_spki_sha256` |

### 9.2 What the operator does, and does not

**Does:** mints `ByJwt` for transport and billing; validates network membership; creates contracts and routes to providers; rate-limits and refuses service at the transport layer; runs the discovery directory; runs the key-transparency log; owns account lifecycle including the Â§5.5 identity reset; will own push (WNS) when it exists.

**Does not, normatively:** store message records; hold any `write_key` or any record ciphertext; learn group membership; get consulted on group admission; sign anything that satisfies an MLS proposal or commit validity condition; read blobs; hold the `recovery_handle` index, which exists on the message server alone.

Two rules that make this checkable rather than aspirational:

- **The message server MUST NOT call any operator API that would reveal group membership**, and MUST NOT report per-group or per-handle metrics to any operator-side sink. Metrics leaving the process are aggregate only (Â§11.2).
- **The operator MUST NOT be given read access to the message server's database.** Not "should not" â€” the credential separation in decision B10 is what makes that enforceable rather than a policy.

### 9.3 Discovery directory (operator side, master spec slice 9)

Two things share the name "discovery" and must not be conflated:

1. **Fleet discovery** â€” where the message server is. Unauthenticated, cacheable:
   `GET /message/servers` â†’ `[{server_id, client_id, signing_pub, blob_endpoint, capabilities, sig}]`, each entry signed by that server's own key so the operator cannot substitute an endpoint without detection. In v1 the list has one logical entry with N instances.

2. **Identity discovery** â€” `principal â†’ identity master key` (master Â§10.1), the thing the KT log makes auditable.

```sql
CREATE TABLE message_identity (
    principal_id   uuid      NOT NULL,   -- the operator's user/network principal
    identity_pub   bytea     NOT NULL,   -- Ed25519 master identity (master Â§5.2)
    alg_id         int       NOT NULL,
    version        int       NOT NULL,   -- increments on reset (master Â§5.5)
    discoverable   boolean   NOT NULL DEFAULT false,   -- opt-in to being findable
    kt_leaf_index  bigint    NULL,
    create_time    timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, version),
    CHECK (octet_length(identity_pub) = 32)
);
CREATE INDEX message_identity_current
    ON message_identity (principal_id, version DESC);
```

The searchable alias reuses the operator's existing `search` package (`NewSearchDb("urmessage", SearchTypePrefix)`) rather than a new index, so search behaviour, minimum alias length, and abuse controls match the rest of the platform. Publication is **opt-in** (`discoverable`); a user who does not publish is reachable only by direct key exchange, which is the SimpleX-adjacent behaviour the master spec Â§13 deliberately stops short of making the default.

Every write to `message_identity` â€” including a Â§5.5 reset â€” writes a KT leaf in the same transaction. A reset that does not appear in the log has been performed quietly, which Â§5.5 forbids.

### 9.4 Key-transparency log (operator side)

```sql
CREATE TABLE kt_leaf (
    leaf_index   bigserial NOT NULL,
    vrf_index    bytea     NOT NULL,   -- VRF(operator_vrf_sk, principal) â€” hides the principal
    commitment   bytea     NOT NULL,   -- H(principal â€– identity_pub â€– version â€– salt)
    kt_epoch     bigint    NOT NULL,
    create_time  timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (leaf_index),
    CHECK (octet_length(vrf_index) = 32),
    CHECK (octet_length(commitment) = 32)
);
CREATE UNIQUE INDEX kt_leaf_vrf_epoch ON kt_leaf (vrf_index, kt_epoch);

CREATE TABLE kt_epoch (
    kt_epoch    bigserial NOT NULL,
    root_hash   bytea     NOT NULL,
    prev_root   bytea     NOT NULL,
    leaf_count  bigint    NOT NULL,
    sth_sig     bytea     NOT NULL,   -- Ed25519 over the STH encoding
    sth_time    timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (kt_epoch)
);

-- Materialised sparse-Merkle nodes for the last K epochs, so an inclusion or
-- absence proof is a read rather than a full-tree recomputation.
CREATE TABLE kt_node (
    kt_epoch bigint NOT NULL,
    depth    int    NOT NULL,
    path     bytea  NOT NULL,
    hash     bytea  NOT NULL,
    PRIMARY KEY (kt_epoch, depth, path)
);
CREATE INDEX kt_node_epoch ON kt_node (kt_epoch);
```

Structure: a sparse Merkle **prefix tree** indexed by `VRF(operator_vrf_sk, principal)`, which is what yields *absence* proofs â€” "there is no other key for this principal" â€” and hides the principal set from anyone enumerating the tree. Inclusion alone does not prevent the operator from later adding a second key; absence proofs are the mechanism that does.

Cadence: a new epoch every 60 s, or on 1,000 pending updates, whichever comes first. `kt_node` is retained for K = 30 days of epochs; clients must audit within that window.

Client obligations (master Â§10.1): an inclusion proof for every resolution, and gossip of signed tree heads over **two independent paths**.

### 9.5 The message server as the second gossip path

The second path is this server, and the mechanism is deliberately narrow:

- The message server polls the operator's STH endpoint on its own schedule, verifies the signature and the consistency proof against the STH it last stored, and writes it to `message_kt_gossip`.
- It echoes the latest verified STH in `HelloResponse.kt_gossip`.
- **It MUST NOT accept an STH handed to it by a client**, and MUST NOT relay one client's STH to another. Doing either would collapse the two paths into one and hand an equivocating operator a way to launder its own fork.
- A client compares the STH it got directly from the operator against the one the message server observed. Divergence at the same `kt_epoch` is equivocation, and the client surfaces it as the blocking warning of master Â§10.2.

**Open item 5** stages the prefix tree behind the log. That is a weakening of master Â§10.1's "required, not optional" unless it is explicitly time-boxed, so it needs an owner ruling and a date, not a shrug.

---

## 10. Deployment, configuration, migrations, backup

### 10.1 Deployment

Container image built from a Dockerfile in the shape of the operator's. Ships:

| Component | Notes |
|---|---|
| `message-server` | N â‰¥ 2 replicas, stateless, each with its own `client_id` |
| PostgreSQL | **Separate cluster from the operator** (decision B10). Primary + streaming replica. WAL archiving on |
| Redis | Dedicated instance/database. No persistence. `MONITOR` disabled, slowlog off |
| Object store | MinIO bucket with ILM lifecycle rules per TTL prefix (Â§8.3) |
| Prometheus | Scrapes `/metrics` on a private port, never on the public interface |

Health endpoints on a private port: `/healthz` (process alive) and `/readyz` (database reachable, KEK loaded, connect client attached, migrations at head). Neither returns any identifier.

### 10.2 Configuration

Vault and config resources follow `server.Vault.RequireSimpleResource` / `server.Config.RequireSimpleResource` naming so ops and ansible keep the same shape:

| Resource | Kind | Contents |
|---|---|---|
| `pg.yml` | vault | Postgres connection (message-server cluster) |
| `db.yml` | config | pool sizing |
| `redis.yml` | vault + config | Redis connection and pool |
| `minio.yml` | vault | object store endpoint, credentials, prefix |
| `message_server.yml` | vault | per-instance `client_id` + credential; `write_key_kek`; `grant_kek`; `channel_key`; the Ed25519 attestation signing key |
| `message.yml` | config | `Capabilities` values, sweep tuning, rate limits, partition toggle |

**Every value in `Capabilities` is config, never a constant in code.** Changing the blob cap must not require a release, and `CapabilityChange` pushes the new values to connected clients.

### 10.3 Migrations

The operator's pattern, in its own database with its own `migration_audit`:

- `store/migrations.go` is an ordered slice of `newSqlMigration` / `newCodeMigration`. Numbering is independent of the operator's 581.
- **Append-only. A landed migration is never edited**, only superseded.
- Index creation on hot tables runs as a **code migration on a raw connection using `CREATE INDEX CONCURRENTLY`**, outside a transaction. This is the operator's standing `FIXME perf` in `db_migrations.go:144`; we are greenfield and should not inherit it.
- Every migration is tested against a database restored from the previous release's schema, in CI. A migration that has only ever run on an empty database has not been tested.
- Rollout order for an additive change: migrate, then deploy. For a destructive change: deploy the version that stops using the column, then migrate. There is no automatic down-migration; reversal is a new forward migration.

### 10.4 Backup, and the two traps

Base backup nightly, WAL archived continuously, PITR window 7 days. Object store: versioning **off** (contents are ciphertext; versioning would resurrect deleted media), cross-region replication optional.

**Trap 1 â€” a restore silently un-deletes.** A database restored to a point 3 days ago brings back every body the sweep erased in those 3 days and every `EPH` row it deleted. **Normative: after any restore, `messagectl sweep-now --until-clean` MUST run to completion before the service accepts traffic.** Startup refuses to serve if the restore marker file is present and the sweep has not run. Without this, disaster recovery quietly becomes a retention violation, and nobody notices because nothing fails.

**Trap 2 â€” the KEK must not be in the backup.** `write_key_kek` and `grant_kek` live in the vault, are never written to the database, and are backed up on a separate schedule with separate access control. A backup that contains both the wrapped keys and the KEK is equivalent to a backup of the unwrapped keys, and the whole point of decision B9 evaporates.

**Why backups do not break the disappearing-message guarantee.** A restored `EPH` body is still undecryptable: `eph_root[n]` was never wrapped to a recovery key, never in a provisioning bundle, and is destroyed on every device when its window closes (master Â§8.1). Master spec Â§12.1's guarantee is stated in terms of key destruction rather than server deletion **precisely so that it survives backups, replicas, forensic disk images, and operator error.** A deletion-based guarantee would be false the moment WAL archiving was switched on. This is the design's single most load-bearing choice on the storage side, and it should be quoted at anyone who proposes weakening it for convenience.

---

## 11. Observability and the MUST-NOT-LOG rule

### 11.1 The rule (normative, master spec Â§9.7)

> The message server MUST NOT create, store, or transmit logs of client commands, transport connections, or a history of deleted records in production.

Made operational:

**MUST NOT appear in any log line, metric label, trace span, error string, panic message, core dump, database log, object-store access log, or Redis slowlog:**

`group_id` Â· `sender_handle` Â· `record_id` Â· `stream_index` Â· `blob_id` Â· `recovery_handle` Â· `client_id` Â· `network_id` Â· any IP address Â· any `ByJwt` Â· `write_auth` Â· `write_key` (wrapped or not) Â· any KEK Â· any ciphertext or any prefix of it Â· any request or response body Â· any URL path containing a blob key Â· the fact that a particular client fetched a particular range Â· any record that a record once existed and was deleted.

**MAY appear:** process lifecycle events; migration start/finish and version; aggregate counters and histograms; error *classes* without identifiers; panic type and stack frames without argument values.

### 11.2 Enforcement, in descending order of reliability

1. **Structural (decision B11).** `GroupId`, `SenderHandle`, `BlobId`, `RecoveryHandle`, `ClientId` are named types in `redact/` whose `String()`, `Format(fmt.State, rune)`, `LogValue()`, `MarshalJSON()`, and `MarshalText()` all return `"<redacted>"`. Access to the bytes is through an explicit `.Unwrap()` used only by the store and crypto layers. **An accidental `%v` cannot leak, because there is nothing to print.** This is the only mechanism that survives a new team member on their first week.
2. **Compile-time.** A `go vet`-style analyser in CI fails the build on any format-verb application to a raw `[]byte` field of a record struct, and on any `glog`/`fmt` call taking a value from the store package's row types.
3. **Runtime.** The logging wrapper accepts only a fixed set of pre-approved field constructors. There is no `log.Any`.
4. **Infrastructure.** `log_statement = none`, `log_min_duration_statement = -1`, `auto_explain` off, on the message-server Postgres cluster. Object store access logging off. Redis `slowlog-log-slower-than -1`, `MONITOR` denied by ACL. `GOTRACEBACK=single` and `ulimit -c 0` so a panic does not dump buffers holding plaintext keys to disk.
5. **Test.** An acceptance test (Â§13) runs a full workload against the service with logs captured, then asserts that no captured byte sequence matches any identifier the test generated. It is the slice-3 acceptance criterion, per master spec Â§14.

### 11.3 Metrics

Prometheus via `client_golang`, matching the operator. **No metric may carry `group_id`, `sender_handle`, `client_id`, `network_id`, or `blob_id` as a label** â€” a metrics store with per-group series is a reconstructed membership graph with a nicer query language.

| Metric | Type | Labels |
|---|---|---|
| `message_submit_total` | counter | `result` (accepted, idempotent, rejected, epoch_stale, commit_lost, stream_reused, rate_limited, oversize) |
| `message_commit_cas_total` | counter | `result` (won, lost, idempotent) |
| `message_fetch_records` | histogram | `heads_only` |
| `message_fetch_latency_seconds` | histogram | â€” |
| `message_submit_latency_seconds` | histogram | â€” |
| `message_group_lock_wait_seconds` | histogram | â€” |
| `message_subscriptions_active` | gauge | â€” |
| `message_push_dropped_total` | counter | `cause` (backpressure, disconnect) |
| `message_prune_rows_total` | counter | `class`, `action` (erase, delete) |
| **`message_prune_lag_seconds`** | gauge | â€” |
| `message_prune_backlog_rows` | gauge | â€” |
| `message_blob_bytes_total` | counter | `direction` |
| `message_blob_orphans_reaped_total` | counter | â€” |
| `message_epoch_key_cache_total` | counter | `result` (hit, miss, negative) |
| `message_group_filter_false_positive_total` | counter | â€” |
| `message_kt_gossip_divergence_total` | counter | â€” |

SLOs: submit p99 < 150 ms; fetch p99 < 250 ms for 100 records; `message_prune_lag_seconds` < 3600 (page at 21600); `commit_lost / commit_total` < 1%; `message_kt_gossip_divergence_total` **> 0 pages immediately** â€” it means the operator equivocated.

---

## 12. Interfaces

### 12.1 What this component requires from spec A

| # | Item | Why it must come from A, not be reimplemented here |
|---|---|---|
| A-1 | **A shared Go package `connect/message`** exporting `ParseRecordHeader`, `WriteAuthPreimage(hdr) []byte`, `SizeBucketBytes(b) int`, `EphBucketSeconds(b) int`, `RetentionClassOf(u8)` | Two independent implementations of a MAC preimage diverge. When they do, the symptom is "some clients can't send," intermittently, and the cause is a byte-order difference nobody can see. One implementation, linked by both |
| A-2 | **The `server_attachment` amendment** (open item 1) â€” `EpochAttachment` and `RecoveryTag` encodings, and the amended Â§9.2 preimage | The server cannot verify the next epoch's write key or the recovery index without it. **Blocking, and format-freezing** |
| A-3 | Exact size-bucket byte lengths, including AEAD tag, so Â§5.1 check 3 can assert equality | Equality is what makes padding real; a range check silently permits an unpadded record |
| A-4 | The eph-bucket â†’ seconds table, with bucket 0 defined as transient | Â§7.2 depends on bucket 0 never being persisted |
| A-5 | `message.proto` in `connect/protocol`, generated by the existing Makefile | Shared codegen; the server links the generated Go |
| A-6 | The `COMMIT_LOST` client contract of Â§6.2, implemented in `sdk` â€” especially step 2 (never reuse `pq_secret`) and step 6 (never reuse a consumed `stream_index`) | Both are silent-corruption failures, invisible in functional tests |
| A-7 | Blob padding ladder and `blob_id` derivation (open item 4) | Â§8.1 |
| A-8 | **A shared interop vector file** `testdata/message-server-vectors.json`: N records with epoch keys, nonces, and the expected verdict for each (accept / reject with reason), plus a commit-race scenario with the expected winner | The single artefact that keeps client and server agreeing. Both suites run it in CI |
| A-9 | A measurement of the platform transport's production `FramerSettings.MaxMessageLen` (open item 2) | Sizes the inline ladder and the fragmentation budget |

### 12.2 What this component exposes to spec C (through `sdk`, never directly)

Spec C never opens a socket to the message server. Everything below reaches C through `URmessageSdk.dll`.

| # | Surface | What C must do with it |
|---|---|---|
| C-1 | `Capabilities.max_blob_bytes` | Show the cap and enforce it **before** the file picker, not after a 400 MB read |
| C-2 | `Capabilities.media_ttl_*` and `REASON_RETENTION_CLAMPED` | Render the one-time in-group notice when a policy is clamped (open item 3) |
| C-3 | Blob grant + resumable chunk upload | Progress UI that survives a disconnect and resumes; the mask makes this exact rather than approximate |
| C-4 | `FetchAttestation` and gapless `record_id` | Pin attestations covering the high-water range; warn when a later-learned record falls inside a covering attestation that omitted it (master Â§9.4); treat an id gap as a fault |
| C-5 | The `Reason` enum | Map to user-facing strings. `REASON_REJECTED` maps to a generic failure â€” C must not invent a more specific message, since the server deliberately did not distinguish (Â§4.5) |
| C-6 | `Backpressure` push | Re-subscribe from the client's own high-water. **Never** treat a drop as "nothing new" |
| C-7 | Reconnect semantics | Resubscribe with `since_record_id`; the server replays. There is no cross-connection subscription state |
| C-8 | Honest-limits copy | Master Â§12.3: a server that silently withholds a deletion is not detectable in v1. Â§12.4's required UI language is normative and must not be softened |
| C-9 | Server key pinning | `server_signing_pub` and `BlobEndpoint.tls_spki_sha256` are pinned on first contact; a change is a blocking warning, not a silent re-pin |

---

## 13. Test and acceptance criteria (slice 3)

Master spec Â§14 makes Â§9.7 an acceptance criterion for this slice. Concretely, slice 3 is done when all of the following pass in CI on every commit:

1. **Interop vectors.** `testdata/message-server-vectors.json` (A-8) passes in both directions: the server produces the expected verdict for every record, and the client produces records the server accepts.
2. **Commit-race property test.** *k* concurrent committers at the same epoch against a real Postgres: exactly one wins; every loser receives the winner's exact bytes; the group's `current_epoch` advances by exactly one; the losing epoch's `write_key` was never installed. Run at k âˆˆ {2, 8, 64} with randomized delays, 1,000 iterations.
3. **Idempotency.** Every submit replayed 3Ã— yields one row and `REASON_OK` each time; a differing record at the same `stream_index` yields `REASON_STREAM_INDEX_REUSED`.
4. **Prune index invariant.** After a full sweep, `SELECT count(*) FROM message_record WHERE prune_after IS NOT NULL AND prune_after <= now()` is 0, and `pg_relation_size('message_record_prune')` has not grown across a 100k-record fixture. Guards Â§3.3.
5. **Retention matrix.** One record per class; advance a fake clock; assert the Â§7.2 table exactly, including that `EPH(0)` never produced a row and that a pruned `MEDIA` retained its head and `body_hash`.
6. **Restore trap.** Restore a backup taken before a prune; assert the service refuses traffic until `sweep-now --until-clean` completes. Guards Â§10.4 trap 1.
7. **No-log acceptance.** Full workload with logs, metrics, traces, database log, Redis log, and object-store log captured; assert no generated identifier appears in any byte of any of them. Guards Â§9.7 and Â§11.
8. **No-MLS assertion.** `go list -deps ./... | grep connect/mls` is empty. Guards Â§5.3.
9. **Dependency deny-list.** Â§2.2's `go list -deps` gate.
10. **DoS ordering.** 10^5 submits with invalid `write_auth` against random group ids produce zero rows in `pg_stat_statements` beyond the epoch-key negative-cache reads. Guards Â§5.1's check order.
11. **Migration-on-populated-database.** Every migration applied to a database restored from the previous release's schema with representative data.

---

## 14. Deferred to V2, with the reason

| Item | Reason |
|---|---|
| Multi-server, read-through proxy | Master spec Â§2/T2. `server_id` fields are carried in `Capabilities` and `FetchAttestation` so it is not a format break |
| Group migration between hosts | Master spec T3. Consequence stated plainly in Â§13: lose the server, lose the groups |
| Client-initiated server-side erase | Decision B6 â€” gated on per-device write capabilities, which Â§9.2 already defers for the same reason |
| Per-device write capabilities | Master spec Â§9.2. Would also enable spam attribution to a device and own-stream erase |
| Stream digests (detectable withholding) | Master spec T8/Â§12.3. Partially mitigated in v1 by gapless `record_id` and `FetchAttestation`, not closed |
| Push (WNS/APNs/FCM) | Ledger open item 2. `presence` in Redis and a reserved `push_token` field are the only v1 hooks |
| Public groups, history export, editing, voice/video | Master spec Â§2 |
| Per-group storage quotas beyond a flat blob cap | Needs real usage data first; `message_group_usage` exists to collect it |
