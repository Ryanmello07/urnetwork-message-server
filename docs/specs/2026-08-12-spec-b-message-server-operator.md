# URmessage — Message Server and Operator Context

**Spec B of three.** Companion documents: spec A (`connect`/`sdk` protocol and client core) and spec C (Windows messaging client).
**Normative parent:** `docs/specs/2026-08-12-urmessage-protocol-design.md` (revision 7) — referred to below as *the master spec*, cited by section (e.g. §9.3).
**Decision record:** `SPEC-LEDGER.md`.
**Date:** 2026-08-12 · **Revision:** 4 · **Status:** Design, owner rulings applied

Notation follows the master spec: `LP(x)` = 32-bit **big-endian** length prefix then `x`; `u8/u16/u32/u64` = big-endian fixed width; `‖` = concatenation; `H` = SHA-256; HKDF is HKDF-SHA-256. All timestamps in Postgres are `timestamp` in UTC, never `timestamp with time zone`, matching the operator's convention.

---

## PLANNING LEDGER

### Current state

| Item | State |
|---|---|
| Master protocol design | Revision 7, owner rulings applied |
| This spec | Revision 4, R4 and R5 review plus the owner's product rulings applied |
| Message server code | None |
| Repo | `Ryanmello07/urnetwork-message-server` (seeded: LICENSE, README, SPEC-LEDGER, docs) |
| Branch for protocol code | `beta/message` on the `connect` and `sdk` forks (not yet created) |
| Blocking on | Nothing. The `server_attachment` amendment is **RULED and adopted** (§5.4) and is applied in MASTER §8/§8.3/§9.2 and Spec A §5.1/§5.11 |

Verified against the checked-out trees at `C:\Users\ryanm\Downloads\claude_sandbox_message\{server,connect,sdk}`:

- `server/go.mod` is `github.com/urnetwork/server`, Go 1.26.5, with `jackc/pgx/v5 v5.10.0`, `redis/go-redis/v9 v9.22.0`, `minio/minio-go/v7 v7.2.1`, `prometheus/client_golang v1.24.1`.
- `server/db.go` exposes `Db`/`Tx`/`MaintenanceDb`/`MaintenanceTx`/`ReplicaDb`, `WithPgResult`, `RaisePgResult`, `BatchInTx`, and the `PgConn`/`PgTx`/`PgResult` aliases. Pools are configured from vault resource `pg.yml` and config resource `db.yml`.
- `server/db_migrations.go` is an ordered slice of `newSqlMigration(...)` / `newCodeMigration(...)`, versioned through a `migration_audit` table. 581 migrations today. It carries a standing `FIXME perf: CREATE INDEX should always use CONCURRENTLY`.
- `server/blob.go` defines a `BlobStore` interface (Put/Get/List/SetLifecycle/Bucket/Prefix/Authority) over MinIO or a local filesystem, configured from vault `minio.yml`. **It has no `Delete`, deliberately** — retention there is an ILM lifecycle rule.
- `server/redis.go` exposes `RedisClient = redis.UniversalClient` configured from vault + config `redis.yml`.
- `server/task` imports `server/session`, which imports `server/model`. Importing the task framework therefore drags in the operator's account model.
- `connect/protocol/frame.proto` defines `enum MessageType` densely populated 0–28, and `Frame{message_type, message_bytes, raw}`.
- `connect/transfer.go` exposes `Send`, `SendWithTimeout`, `SendMultiHopWithTimeout`, `AddReceiveCallback(ReceiveFunction)`; `ReceiveFunction = func(source TransferPath, frames []*protocol.Frame, peer Peer)`. `ClientSettings.MinimumMessageLenLimit()` returns **4 KiB**, and `sendPackBatchMaxMessageByteCount` is 3 KiB.
- `server/connect/transport.go:471-501` authenticates with `ParseByJwtForAudience` + `ValidateByJwtState` + `model.GetNetworkClientNetwork`. Bearer token, no challenge-response, as the master spec §4.3 records.

### Decisions specific to this component, and why

| # | Decision | Why |
|---|---|---|
| **B1** | The message server is its **own Go module and repo**, and imports **only the root `github.com/urnetwork/server` package** for infrastructure (`Db`/`Tx`, `Redis`, `Vault`/`Config`, `Id`, `BlobStore`). It **MUST NOT** import `server/model`, `server/session`, `server/task`, `server/controller`, or `server/api`. | Those packages carry the operator's account tables and would put the operator's identity model inside the process that holds ciphertext, contradicting §4.2. Verified: `server/task → server/session → server/model`, so the task framework is unusable here and the sweep scheduler is written in-process instead. Enforced in CI by a `go list -deps` deny-list. |
| **B2** | **Redis is required, but no *durability or ordering* invariant may depend on it.** The commit CAS, stream monotonicity and `record_id` allocation are Postgres-only. It carries cross-instance subscribe fan-out, rate-limit token buckets, presence, the known-group filter add and refresh, and the §7.6 transient channel. Losing Redis degrades latency and push liveness. **It does change one thing, and only one: admission rate** — per §4.7 all limits fail closed to an in-process limiter at 25% of the configured rate. | The commit CAS and stream monotonicity are durability invariants; putting either in Redis makes a cache eviction a protocol violation. The admission-rate exception is stated here rather than left as a contradiction an engineer can cite in a future design argument. |
| **B3** | **No *persisted* record ciphertext, no epoch write key, and no blob byte ever enters Redis.** Pub/sub payloads carry a masked group id and a record-id range only; the receiving instance re-reads Postgres. The single carve-out is `EPH(0)`, which is never persisted anywhere and is fanned out as `AEAD(channel_key, transient_record_bytes)` on a dedicated channel — see §7.6. | Redis persistence (AOF/RDB) would write ciphertext to a second, usually less-hardened disk, and `MONITOR`/slowlog would print keys. The carve-out is bounded by construction to records that never touch disk, with §2.4's deployment requirements as the compensating control. |
| **B4** | `record_id` is a **per-group, gapless, monotonically allocated, 1-based bigint**, not a global `bigserial`. Allocation is `UPDATE message_group SET next_record_id = next_record_id + k RETURNING`, in the submit transaction, **after** every per-record check has passed (§6.1 step 4). `record_id = 0` is never assigned, so `since_record_id = 0` is the well-defined "from the beginning" cursor. | A global sequence allocates before commit, so a reader can observe id 10 before id 9 is visible and then never see 9. That silently breaks `fetch since record_id`, which is the single most-used query in the system. Per-group allocation also serialises the group's log, which is exactly what the Delivery Service role (§9.3) needs anyway, so the lock is not additional cost — it is the same lock. |
| **B5** | The retention sweep is driven by a server-computed `prune_after` = `LEAST(class_deadline, expire_at)`. **`expire_at` may only shorten retention, never extend it.** | That preserves the whole of B5's original reasoning — a member declaring `expire_at = 2999` cannot pin `MEDIA` forever — while satisfying MASTER §9.1 and Spec A S10, which both require pruning by class **and** `expire_at`. `expire_at` is inside `AAD_head` and the `write_auth` preimage, so **I6** is fully satisfied and there is no verification objection either. Discarding it entirely, as revision 1 did, silently ignored an authenticated, client-declared deletion time on every record. |
| **B6** | **No client-initiated server-side erase in v1.** Bodies are removed by class expiry and by the sweep only. `TOMBSTONE` remains a purely client-side, MLS-authenticated construct. | `write_key` is group-wide (§9.2), so an erase request cannot be attributed to a device or to the original sender — any member could erase any body, a history-destroying DoS. §9.2 already defers per-device capabilities to V2 for precisely this reason, and §12.3 already tells users delete-for-everyone does not claw anything back. Early erase is therefore gated on the V2 per-device capability work. |
| **B7** | **Split transport: protobuf request/response over the connect frame path for the control plane; TLS/HTTP over the mesh for the bulk (blob) plane.** Argued in §4.1. | A 100 MB upload driven through a 3 KiB-batched, ack-windowed client sequence head-of-line-blocks every message in that sequence. Ranged and resumable semantics already exist in HTTP and in MinIO multipart. Meanwhile subscribe needs *server-initiated* push, which the frame path gives free and HTTP does not. |
| **B8** | **Four `MessageType` enum values only** (`MessageServerRequest`, `MessageServerResponse`, `MessageServerPush`, `MessageServerFragment`), reserved at **1000–1099**, with a `oneof` inside for every operation. Spec A owns `connect/protocol/message.proto`; Spec B owns the `oneof` arms and their semantics (§4.2). | `frame.proto` is shared with `beta/algorithm-dpi` and `beta/custom-server`. Adding one enum value per operation guarantees a merge conflict on every branch every time we add an operation. A reserved high block plus an internal `oneof` reduces the shared-file diff to four lines, permanently. Spec A's `MessageEnvelope` / `MessageOp` alternative is deleted (§4.2). |
| **B9** | The server keeps the **current** epoch's `write_key` plus **one briefly-retired predecessor**, wrapped under a KEK loaded from the vault. Advancing an epoch sets `retire_time = now()` on the outgoing epoch instead of NULLing it; the 5-minute tidy loop (§7.4) NULLs `write_key_wrapped` where `retire_time < now() - interval '60 seconds'`. **This two-key window is why reads are not authenticated under an epoch *write* key**: `req_auth` uses the epoch's `read_key` instead (§5.3), which is retained for 90 days rather than 60 seconds, because a member offline across one commit would otherwise be locked out of every route back. | Destroying the superseded key immediately made `REASON_EPOCH_STALE` unreachable — check 6 would return the deliberately undiagnosable `REASON_REJECTED` for the single most common benign race in the system (a record submitted at epoch *n* while a commit to *n+1* lands), making `SubmitResult.current_epoch`'s "always set, so a stale client resynchronises in one round trip" a dead promise and §6.4's row for that race dead code. The blast-radius argument is unchanged at two keys. |
| **B10** | The message server runs against a **separate Postgres cluster and separate credentials from the operator**, even though one organisation runs both. | Same operator, separate blast radius. An operator database compromise must not also yield message ciphertext and epoch write keys. Cheap; do it on day one, because retrofitting a database split after launch is not cheap. |
| **B11** | Forbidden identifiers are made **structurally unprintable** in Go — `GroupId`, `SenderHandle`, `BlobId`, `RecoveryHandle`, `ClientId` are **opaque structs wrapping an unexported `[]byte`**, never named slice or array types, whose `String()`, `Format()`, `LogValue()`, `MarshalJSON()` and `MarshalText()` all return a redaction constant, with an explicit `.Unwrap()` at every store boundary. | §9.7 is a normative requirement, and a rule that depends on every future developer remembering it will be violated. Making an accidental `%v` physically incapable of printing the value is the only enforcement that survives contact with a team. The struct (rather than a named `[]byte`) is load-bearing: pgx v5 would otherwise encode such a type through its `TextMarshaler` and write the literal bytes `<redacted>` into a `bytea` column — see §11.2 item 1. |
| **B12** | Bodies over the inline ladder go to the blob store; `ct_head` and `ct_body` use `STORAGE EXTERNAL` (no TOAST compression). | Ciphertext is incompressible; `pglz` would burn CPU on every write and every read for a ~0% ratio. |
| **B13** | **The fleet's attestation signing private key lives in an HSM or a signing sidecar, never on a replica.** Replicas call it to sign; they never hold it. The fleet **root** key that certifies it is offline and is used only to certify a new signing key. | §9.1 accepted the opposite and stated the risk: the signing private half on every replica means one compromised replica compromises the fleet's pinned identity. With clients pinning a hardcoded root (Spec A §7.6), a compromised signing key is now revocable by certifying a successor from the offline root — but only if the root was never on a replica, and only if the signing key can be rotated without a replica ever having held it. Both properties have to exist on day one; neither can be retrofitted onto shipped installs. |
| **B14** | **The message server holds an account on exactly one operator, named in configuration.** Which operator is the administrator's choice among the operators this server is compatible with. Nothing in this module may assume the client is on the same operator, and no operator host may appear as a constant in code. | MASTER §2 and §4.1: operators are plural, two run today, and they are a different thing from message servers. A server that hardcodes one operator cannot be run by anyone else, and a check written as though one operator sees the whole system is wrong on the day the second one is used. |
| **B15** | **Placeholder rows for expired ephemeral records carry no `sender_handle`.** The stream-uniqueness and idempotency claim moves out of `message_record` into a dedicated `message_stream_claim` table so the handle column can be zeroed without colliding on a unique index. | MASTER §12.2. Keeping the row is justified by the gapless-`record_id` argument; keeping the sender in it is not, and left a permanent per-sender timestamped trail as the residue of the feature whose purpose is to leave none. The claim table is also the honest home for the idempotency probe, which was never about the record's content. |
| **B16** | **Aggregate-only logging with one opt-in, client-triggered exception**, replacing the absolute prohibition. | An absolute rule is met at 3 a.m. by an on-call engineer who quietly adds a log line. §11.5 specifies the bounded diagnostic session so that the supported answer to "we cannot debug this" exists and is the user's to grant. |

### Interfaces to the other two components

| Direction | Summary | Detail |
|---|---|---|
| **Requires from spec A** | Byte-exact record encoding, including `blob_id` as a header field; the `write_auth` and `req_auth` preimages including the `server_attachment` amendment; `req_auth` keyed on the epoch's `read_key`, with the epoch named by the request's `read_epoch` field and therefore inside the MAC; the recovery proof; the size-bucket and eph-bucket ladders; the blob id derivation and padding ladder; a shared Go package `connect/message` the server links so it never reimplements the parser or the encoder; a shared interop vector file. | §12.1 |
| **Provides to spec A** | The reject-reason contract, the losing-committer contract, the capability document, and the exact idempotency semantics of a retried submit. | §12.1 |
| **Provides to spec C** | Everything C consumes goes through `sdk` — C never speaks to the message server directly. What C must surface in UI: blob cap before the file picker opens, retention notices, resumable-upload progress, attestation warnings, hole detection on the gapless `record_id`. | §12.2 |
| **Requires from its operator** — the one named in `operator_host`, which is one of several and need not be the client's | A network + client ids for the server fleet; a discovery endpoint listing the fleet; that operator's KT log and its signed tree heads; a transport `FramerSettings.MaxMessageLen` measurement. | §9 |

### Open items

1. **`server_attachment` amendment to §9.2 — RULED, adopted. See §5.4.** Commit records carry a server-visible `EpochAttachment` (the next epoch's `write_key`, retention policy, group-context hash, `expected_wrap_count`), archive records a `RecoveryTag`, wrap records a `WrapTag`, and the fan-out marker an `EpochComplete`. `‖ LP(H(server_attachment))` is appended to the §9.2 `write_auth` preimage and to `AAD_head`. The encoding is owned by Spec A (`connect/message/attachment.go`) and consumed here. No longer blocking.
2. **Control-plane message size.** `ClientSettings.MinimumMessageLenLimit()` is 4 KiB and `sendPackBatchMaxMessageByteCount` is 3 KiB. A 64 KiB inline record does not fit one frame. This spec defines an application-level fragmentation wrapper (§4.6) so the protocol is transport-cap independent, but the platform's *actual* production `MaxMessageLen` must be measured before we size the inline ladder. **Assumption to confirm by measurement.**
3. **Retention negotiation — RULED, warn and proceed in every direction. See §7.3.** Longer than `media_ttl_max_seconds` clamps **down**; shorter than `durable_retention_min_seconds` floors **up**; longer than `durable_ttl_max_seconds`, including a request for indefinite text retention on a server that advertises a cap, clamps **down**. All three accept the commit and return `REASON_RETENTION_CLAMPED` with `RetentionApplied`. Refusal is not an option in any of them.
4. **Blob padding ladder — CLOSED.** Spec A §5.13 owns it: `blob_id = HKDF-Expand(record_key[i], "blob/v1", 32)`, padding to a **262144-byte (256 KiB)** multiple. `Capabilities.blob_pad_multiple` advertises the value and does not define it.
5. **KT staging — RULED, a release gate rather than a date.** §9.4 specifies the VRF suite, the tree arithmetic, the STH preimage, the history tree, the four client endpoints, the signing key and the monitor role. The ruling, matching MASTER §15 item 6: **the log is a general-availability gate.** Beta testers may run against a log that is not yet live, with every key-change row and every directory lookup rendering `kt_unavailable` explicitly; no non-beta user is served until the log, its four client endpoints and its monitor role are running. Closed.
6. **Group-row lock throughput.** B4 serialises writes per group. Expected ceiling ~1–2k records/s/group; a 500-member group at peak is nowhere near that. **Assumption to confirm by benchmark in slice 3.**
7. **Push transport — a general-availability gate, not a beta gate** (MASTER §15 item 2). Out of scope for this spec beyond leaving `presence` in Redis and a `push_token` field reserved, and the server-side channel registry, which lands with the client's push slice. The beta ships without push and says so in the client. A working **contentless** wake must exist before any non-beta user.
8. **Read-key retention window.** `read_key_window_seconds`, default **7776000** (90 days), is the single number that decides both how long an offline member may be away and how long a removed member keeps metadata access. It is configuration in `message.yml` and it is a **published** number, not a tuning knob: changing it changes a statement in MASTER §13.
9. **Backup, RPO and jurisdiction.** Nightly encrypted base backups, continuous WAL archiving, a **48-hour** point-in-time window, and a **named hosting jurisdiction** are required before any user beyond the two beta testers, and the jurisdiction is published rather than inferred from an IP address. §10.4.

### Edit log

Append-only. Newest last. One entry per commit that changes this spec. Follow the ledger §6 change process: edit, subagent diff review, fix, commit with the ledger entry, append here.

---

**Revision 2 — 2026-08-12 — R4 review applied (edits B-0 … B-24 of `research/r4-edit-plan.md`).**
File re-encoded from double-encoded UTF-8 to clean UTF-8, no BOM, LF (B-0). Wire binding adopted from this
spec with `MessageServerFragment = 1003`, and file ownership stated (B-5, B-8). `Record` replaced with
`record_bytes` plus verified server-indexed projections (B-6a). `req_auth` added to the read path with a new
§4.3.8 and §5.1.1 (B-6c, B-10). Recovery fetch moved to an Ed25519 TOFU proof with `message_recovery`
(B-6d, B-2). `CreateGroup` given `bootstrap_write_key` and a written-out transaction (B-6b, B-13). Epoch
publication, `wrap_target_handle`, `WrapFetch` and `EpochComplete` added (B-6i, B-11 sequence, B-13).
`message_record_commit` replaced by a `message_commit` table; 64 partitions created unconditionally (B-2,
B-4). Idempotency probe moved to step 0 and batch atomicity made normative (B-13). `H(write_key)` language
struck; two-key custody and a KEK lifecycle added as §5.5 (B-11). `expire_at` fixed at unix milliseconds and
allowed to shorten retention only (B-1, B-12, B-15). Retention negotiation RULED both directions; `EPH`
placeholder rows, group closure §7.5 and `EPH(0)` §7.6 added (B-15). Blob plane: `grant_ref` paths, 8 MiB
chunks, class and content-hash binding, and the `perm/` ILM rung (B-16). §9.1 lifecycle, discovery signature,
abuse response §9.6, and a fully specified KT log §9.4 (B-17, B-18). Drain, capability reload and fleet
convergence, migration ownership, backup trap 3 and rotation runbooks §10.5 (B-19). Postgres error-path
logging block and opaque redaction structs (B-20). §12 interfaces rebuilt around the single `connect/message`
export table (B-21). Fifteen new acceptance tests and five new V2 rows (B-22, B-24). Open items 1, 3 and 4
closed; item 5 reduced to "needs a date".

---

**Revision 3 — 2026-08-12 — R5 convergence pass.** `blob_id` became a header field and entered both
preimages; §5.1 check 3 acts on the parsed value. `req_auth` re-keyed from the epoch `write_key` to
the group's lifetime `read_key`, carried in `EpochAttachment`, stored on `message_group` and never
retired; §4.3.8 now names all five authorized reads with their op bytes and §5.1.1 agrees with it.
`durable_ttl_seconds = 0` explicitly maps to a `NULL` column and is never floored. `message_recovery`
re-keyed per group and §5.4 point 2 rewritten to state what `write_auth` does and does not prove.
`DURABLE` added to the blob-grant class list with its rung mapping. Epoch-bundle sizing recomputed
against the padded ladder (~6.9 MB per commit, ~2.5 GB/year). `CreateGroup` carve-out extended to
check 3. Open item 5 closed as a release gate. Tests 28–30 added. Every internal edit-plan label
replaced with a real section reference.

---

**Revision 4 — 2026-08-12 — the project owner's product rulings applied.** `read_key` re-keyed from a
group lifetime value to a **per-epoch** key stored on `message_epoch` with `read_key_install`,
retained for `read_key_window_seconds` (default 90 days) and NULLed by a second, independent tidy
statement; every authorized read gains a `read_epoch` field inside the MAC, `GroupStatusResponse`
gains `oldest_read_epoch`, check 3 stops comparing the attachment's read key against an installed
one, and the KEK rewrap pass is resized around ninety days of read keys (§3.2, §3.3, §4.3.8, §5.1,
§5.1.1, §5.3, §5.5, §6.1, §7.4, decision B9). Expired ephemeral placeholder rows now **zero
`sender_handle`**, which moved the stream-uniqueness and idempotency claim out of `message_record`
into a new `message_stream_claim` table (§3.2, §6.1, §6.3, §7.2, decision B15). Text retention gained
a **one-year default and a storage cap**, so the server advertises three limits — text cap, media
window, file size — and clamps text on both sides (§4.3.1, §6.1, §7.1, §7.3). Server key custody:
the attestation signing key moves to an HSM or signing sidecar, an offline fleet root certifies it
via `ServerKey.sig_by_root`, and a non-chaining key is refused outright rather than warned about
(§4.3.1, §9.1, §10.2, §10.5, §12.2, decision B13). **Operators are plural**: this server names its
own operator in `operator_host`, nothing may assume the client shares it, and §9.2 is restated per
operator (§4.3.1, §9.1, §9.2, §10.2, decision B14). Directory listing is opt-in and the opt-in is
what creates the row (§9.3). Logging becomes **aggregate-only** with one bounded, client-started
diagnostic session, backed by a new `message_diagnostic_session` table and a new §11.5 (§3.2, §11.1,
§11.5, decision B16). Backups: PITR cut from 7 days to **48 hours**, encrypted base backups, a stated
RPO and a named hosting jurisdiction (§10.4). Delivery receipts ship in v1 on the existing `EPH(0)`
path and leave the V2 list (§4.3.3, §14). Tests 29 and 30 rewritten; tests 31–36 added. Open item 7
restated as a general-availability gate; open items 8 and 9 added.

---

## 1. Scope

**In scope.** The message server process: storage, ordering, single-commit agreement, `write_auth` verification, history serving, blob lifecycle, retention and pruning, capability advertisement, its own URnetwork account and transport wiring, deployment, configuration, migrations, backup, observability. Plus the operator-side surface the message server and clients depend on: the discovery directory and the key-transparency log.

**Out of scope.** MLS (spec A). The record format's cryptographic construction (master spec §8, implemented in spec A). Client state, local store, provisioning (spec A). Any UI (spec C).

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

The rule exists because the operator's model package *is* the account identity layer, and §4.2 forbids the message server from consulting it. The cost is that `server/task` is unavailable, so §7.4 specifies an in-process scheduler behind a Postgres advisory lock instead.

### 2.3 Process model

| Property | Value |
|---|---|
| Instances | N replicas, N ≥ 2. Deployed as a **StatefulSet with stable ordinals**, because the per-instance transport credential is per-instance state — see §9.1 |
| URnetwork identity | One network for the fleet; **each instance holds its own `client_id`** and its own long-lived credential in the vault |
| Client affinity | A client resolves the fleet from discovery, picks one instance, and stays sticky for the session; on disconnect it re-picks |
| Cross-instance fan-out | Redis pub/sub (§2.4) |
| Shared state | Postgres (authoritative), object store (blobs), Redis (soft) |
| Graceful shutdown | Drain (below), then stop accepting new frames, drain in-flight transactions, unsubscribe from Redis, close the connect client, exit. No two-phase teardown — this is a normal user-mode service, unlike the VPN client's privileged service |

Per-instance `client_id` (rather than a shared one) is deliberate: the platform's resident routes a `client_id` to a single connection, so a shared id would pin the whole fleet to one replica.

**Drain.** On SIGTERM the instance sends `Drain{reconnect_after_ms}` to every attached client with a **jittered** value spread over a 60 s drain window, then continues serving until the window closes. Without it, at N = 2 a rolling deploy migrates the entire connected population twice in two synchronised waves, each producing a simultaneous backfill fetch from every client — combined with the response byte budget of §4.3.1, the most likely OOM the service will ever see, on every deploy. Export `message_drain_duration_seconds`.

### 2.4 Redis: what it is for, and what it is never for

| Use | Key shape | TTL | Loss behaviour |
|---|---|---|---|
| Subscribe fan-out | `urmsg:g:<mask>` pub/sub channel | — | Pushes stop; clients still poll on reconnect and lose nothing |
| Rate-limit token buckets | `urmsg:rl:c:<client_id_hash>`, `urmsg:rl:g:<mask>` | 60 s | Fail **closed** to a conservative in-process limiter |
| Presence (which instance holds which subscription) | `urmsg:pres:<client_id_hash>` | 90 s, refreshed | Push routing degrades to broadcast on the group channel |
| Known-group filter epoch | `urmsg:gf:epoch` | — | Filter refreshes from Postgres on a timer regardless |
| Idempotency hint cache | `urmsg:idem:<mask>:<handle>:<idx>` | 300 s | Falls through to `message_stream_claim`'s primary key, which is the authority |

`<mask>` is `hex(HMAC-SHA256(channel_key, group_id)[0:8])`, where `channel_key` is a server secret from the vault. **Raw `group_id` never appears in a Redis key**, because Redis keyspace notifications, `MONITOR`, and slowlog all print keys and Redis is routinely operated with looser controls than the database.

Pub/sub payload is exactly `{mask, group_id_enc, lo_record_id, hi_record_id}` where `group_id_enc` is the group id AEAD-encrypted under the same server secret so the receiving instance can resolve it without a lookup table. **No ciphertext, no write key, no blob byte crosses Redis** (decision B3).

Deployment requirement: `slowlog-log-slower-than -1`, `MONITOR` disabled by ACL, no AOF/RDB persistence for this instance's database.

**The commit CAS is not in Redis.** It is a Postgres transaction (§6). A Redis-based CAS would make a failover or an eviction into an MLS fork.

---

## 3. Data model

### 3.1 Conventions

- All ids are `bytea` with an exact-length `CHECK`. `group_id` is 32 B, `sender_handle` 16 B, `body_hash` 32 B, `recovery_handle` 16 B, `blob_id` 32 B. They are **not** `uuid` — `uuid` is 128-bit and would silently truncate a 256-bit group id.
- All timestamps are `timestamp` (UTC). **The cluster MUST be configured `timezone = 'UTC'`** in `postgresql.conf` on the primary, on every streaming replica, and on every restore or staging target, and the pgx pool MUST set it explicitly: `pool_config.ConnConfig.RuntimeParams["timezone"] = "UTC"`. This is not a convention — `now()` returns `timestamptz` and assigning it to a `timestamp` column casts through the session's `TimeZone`. Retention is split across two clocks (§7.1 computes `prune_after` in Go from `time.Now().UTC()`; §7.4 sweeps with `WHERE prune_after <= now()` in the database), so a non-UTC cluster prunes media up to 14 hours early or late, fleet-wide, silently. Early pruning destroys user data. `/readyz` asserts `SELECT now()::timestamp` against `time.Now().UTC()` within a few seconds and **refuses readiness on failure** — one query, converting a silent multi-hour retention error into a deploy-time failure.
- `expire_at` is unix **milliseconds** on the wire and in both preimages; see the `expire_at` units paragraph of §5.4. The `timestamp` column is a lossy projection with no authority.
- `sender_handle` is 16 bytes on every record. On an expired ephemeral record it is **sixteen zero bytes**: the row survives so `record_id` stays gapless, and the sender does not survive with it (§7.2). Sixteen zero bytes is a legal handle value that no `group_handle_key` derivation produces with any meaningful probability, and it is never treated as an identity.

The wire encoding is MASTER §8's and is restated here character-for-character because Spec A §5.1 restates the same table; a divergence makes every EPH record fail both AEAD and MAC:

```
retention_class wire byte:

  0x00  PERMANENT
  0x01  DURABLE
  0x02  MEDIA
  0x10 | bucket   EPH(bucket), bucket in 0..5  →  0x10, 0x11, 0x12, 0x13, 0x14, 0x15
                                                  (decimal 16, 17, 18, 19, 20, 21)

No other value is legal. RetentionClassOf() and RetentionClassWire() in connect/message are the ONLY
places the class and the bucket are joined or split.

eph bucket → seconds:  [0] transient (never persisted), [1] 3600, [2] 28800,
                       [3] 86400, [4] 604800, [5] 2419200

size_bucket:  0 = 256 B, 1 = 1024 B, 2 = 4096 B, 3 = 16384 B, 4 = 65536 B, 5 = blob-ref
              octet_length(ct_body) MUST equal size_bucket_bytes[b] + 16 exactly (the AEAD tag),
              for b in 0..4. For b = 5, ct_body is absent and blob_id is present.
```

### 3.2 DDL

Written in the operator's migration style — an ordered slice of `newSqlMigration(...)` in `store/migrations.go`, with its own `migration_audit` table in its own database.

```sql
-- ── 001 ───────────────────────────────────────────────────────────────────
CREATE TABLE message_group (
    group_id            bytea       NOT NULL,
    create_time         timestamp   NOT NULL DEFAULT now(),

    -- Delivery Service state (master spec §9.3)
    current_epoch       bigint      NOT NULL,

    -- per-group gapless record id allocator (decision B4). 1-BASED: record_id = 0 is
    -- never assigned, so since_record_id = 0 is the well-defined "from the beginning"
    -- exclusive cursor. At DEFAULT 0 the group's founding commit was
    -- permanently unfetchable by every client that did not create it.
    next_record_id      bigint      NOT NULL DEFAULT 1,

    -- retention policy, as published by the committer in the epoch attachment,
    -- already clamped to this server's advertised caps
    media_ttl_seconds   int         NOT NULL,
    durable_ttl_seconds int         NULL,          -- NULL = indefinite (wire sentinel 0; §5.4)

    -- read keys are per epoch and live on message_epoch, not here (§5.3).

    group_context_hash  bytea       NULL,          -- echoed to clients; never interpreted
    policy_version      int         NOT NULL DEFAULT 0,

    -- false between an accepted commit and its EpochComplete marker (§6.1, epoch
    -- publication step 3)
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
);
-- blob_quota_bytes is deliberately absent: it was NOT NULL with no default, no writer
-- and no reader, and §14 defers per-group quotas to V2 (§14).

-- ── 002 ───────────────────────────────────────────────────────────────────
CREATE TABLE message_epoch (
    group_id          bytea     NOT NULL,
    epoch             bigint    NOT NULL,
    -- u8(kek_id) || nonce(12) || ct(32) || tag(16) = 61 B. The key id is what makes a
    -- dual-KEK rollover window possible without a schema migration on the table that
    -- gates every submit (§5.5).
    write_key_wrapped bytea     NULL,

    -- the epoch's read key, from that epoch's EpochAttachment.read_key. Same wrap
    -- format as write_key_wrapped: u8(kek_id) || nonce(12) || ct(32) || tag(16).
    -- Installed when the epoch opens and RETAINED for read_key_window_seconds
    -- (default 7776000 = 90 days) from install_time, NOT 60 seconds (§5.3).
    read_key_wrapped  bytea     NULL,
    read_key_install  timestamp NULL,

    alg_id            int       NOT NULL,
    opened_by_record  bigint    NULL,      -- record_id of the commit that opened this epoch
    accept_time       timestamp NOT NULL DEFAULT now(),
    -- set when the epoch is superseded; the 5-minute tidy loop NULLs write_key_wrapped
    -- 60 s later, so the briefly-retired predecessor stays verifiable (decision B9).
    retire_time       timestamp NULL,

    PRIMARY KEY (group_id, epoch),
    CHECK (octet_length(group_id) = 32),
    CHECK (write_key_wrapped IS NULL OR octet_length(write_key_wrapped) = 61),
    CHECK (read_key_wrapped IS NULL OR octet_length(read_key_wrapped) = 61),
    CHECK ((read_key_wrapped IS NULL) = (read_key_install IS NULL))
);

-- the read-key expiry worklist. Partial, and the tidy loop NULLs both columns after
-- acting, so the index holds exactly the outstanding work — the same property
-- message_record_prune has, for the same reason (§3.3).
CREATE INDEX message_epoch_read_key_expiry
    ON message_epoch (read_key_install) WHERE read_key_wrapped IS NOT NULL;

-- ── 003 ───────────────────────────────────────────────────────────────────
CREATE TABLE message_record (
    group_id        bytea     NOT NULL,
    record_id       bigint    NOT NULL,   -- per-group, gapless, allocated in-tx
    sender_handle   bytea     NOT NULL,
    epoch           bigint    NOT NULL,
    stream_index    bigint    NOT NULL,
    is_commit       boolean   NOT NULL,
    retention_class smallint  NOT NULL,
    size_bucket     smallint  NOT NULL,

    expire_at       timestamp NULL,       -- lossy projection of the wire u64 milliseconds;
                                          -- no authority, never re-derived into a preimage
    prune_after     timestamp NULL,       -- server-computed; NULLed once the sweep has acted
    pruned          boolean   NOT NULL DEFAULT false,
    policy_version  int       NOT NULL DEFAULT 0,

    body_hash       bytea     NOT NULL,   -- retained after ct_body is erased (§8)
    ct_head         bytea     NOT NULL,
    ct_body         bytea     NULL,       -- NULL when erased, or when the body is a blob
    blob_id         bytea     NULL,

    -- the authenticated attachment exactly as submitted. The two columns below are
    -- extracted projections of it, and the server re-verifies them against
    -- message.ParseServerAttachment before acting (§5.1 check 3).
    server_attachment  bytea  NULL,
    recovery_handle    bytea  NULL,       -- from a RecoveryTag (§4.3.7)
    wrap_target_handle bytea  NULL,       -- from a WrapTag (§5.4; §6.1 epoch publication)

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
    -- the retention-class wire byte of §3.1: 0, 1, 2, or 16..21. No other value is legal.
    CHECK (retention_class IN (0,1,2) OR (16 <= retention_class AND retention_class <= 21)),
    CHECK (0 <= size_bucket AND size_bucket <= 5)
) PARTITION BY HASH (group_id);

-- All 64 partitions are created HERE, unconditionally, in this migration. A partitioned
-- table with no partitions rejects every INSERT with "no partition of relation found for
-- row", so a shipped schema without them could not store a record. See §3.4.
CREATE TABLE message_record_p00 PARTITION OF message_record
    FOR VALUES WITH (MODULUS 64, REMAINDER 0);
-- ... p01 through p63, identically, REMAINDER 1 .. 63.

ALTER TABLE message_record ALTER COLUMN ct_head SET STORAGE EXTERNAL;
ALTER TABLE message_record ALTER COLUMN ct_body SET STORAGE EXTERNAL;

-- ── 003b  stream claims: uniqueness and idempotency, separated from the record ──
-- This was a UNIQUE index on message_record (group_id, sender_handle, stream_index).
-- It cannot stay there: §7.2 zeroes sender_handle on an expired ephemeral record, and
-- two senders may legitimately hold the same stream_index, so zeroing would collide on
-- the index and the UPDATE would fail. The claim is also the honest home for the
-- idempotency probe of §6.3, which asks "did this exact submission already land" and
-- never needed the record's storage columns to answer.
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
-- 64 partitions, created unconditionally in this migration, exactly as for
-- message_record and for the same reason (§3.4).

-- ── 004  indexes ──────────────────────────────────────────────────────────
-- NOTE: there is deliberately no unique index on
-- message_record (group_id, sender_handle, stream_index). The claim table above is the
-- uniqueness authority, because §7.2 zeroes the handle column on expiry (§7.2, B15).
--
-- NOTE: there is deliberately no `message_record_commit ... WHERE is_commit`.
-- PostgreSQL rejects a PARTIAL UNIQUE index on a partitioned table, so that migration
-- would fail at deploy time. The Delivery Service invariant lives in the dedicated
-- message_commit table below, which is a better CAS anyway: a one-row insert against a
-- full primary key rather than a predicate index (§6.1).

-- epoch wrap fan-out, indexed by target (§6.1 epoch publication, Q10)
CREATE INDEX message_record_wrap
    ON message_record (group_id, epoch, wrap_target_handle)
    WHERE wrap_target_handle IS NOT NULL;

-- what makes FetchRequest.class_mask costed rather than a full group scan per page.
-- The class-filtered fetch is the join and seed-only-restore path, pulling PERMANENT
-- records out of a group holding a million DURABLE rows (Q11).
CREATE INDEX message_record_class
    ON message_record (group_id, retention_class, record_id);

-- the sweep worklist. Partial on prune_after IS NOT NULL, and the sweep NULLs
-- prune_after once it has acted, so this index contains exactly the outstanding
-- work and nothing else, forever. Index size is the backlog, not the corpus.
CREATE INDEX message_record_prune
    ON message_record (prune_after) WHERE prune_after IS NOT NULL;

-- seed-only restore (§5.4 of the master spec)
CREATE INDEX message_record_recovery
    ON message_record (recovery_handle, group_id, record_id)
    WHERE recovery_handle IS NOT NULL;

-- blob back-reference, for binding and for GC
CREATE INDEX message_record_blob
    ON message_record (blob_id) WHERE blob_id IS NOT NULL;

-- ── 004b  the single-commit invariant ──────────────────────────────────────────────
-- THE CAS. A one-row insert against a full primary key (§6.1 step 5b, Q14).
CREATE TABLE message_commit (
    group_id  bytea  NOT NULL,
    epoch     bigint NOT NULL,
    record_id bigint NOT NULL,
    PRIMARY KEY (group_id, epoch),
    CHECK (octet_length(group_id) = 32)
);

-- ── 005 ───────────────────────────────────────────────────────────────────
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

-- ── 006 ───────────────────────────────────────────────────────────────────
CREATE TABLE message_blob (
    blob_id         bytea     NOT NULL,
    group_id        bytea     NOT NULL,
    state           smallint  NOT NULL,   -- 0 GRANTED, 1 COMPLETE, 2 BOUND
    declared_bytes  bigint    NOT NULL,
    received_bytes  bigint    NOT NULL DEFAULT 0,
    chunk_bytes     int       NOT NULL,
    chunk_mask      bytea     NOT NULL,   -- 1 bit per chunk; DERIVED by listing the
                                          -- object store at grant/resume time (§8.3),
                                          -- not written per chunk
    content_hash    bytea     NULL,       -- computed during assembly; checked at bind
    grant_ref       bytea     NOT NULL,   -- 16 random bytes; THE path component (§8.2)
    retention_class smallint  NOT NULL,
    object_key      text      NOT NULL,   -- encodes the TTL ladder rung; see §8.3
    grant_expire    timestamp NOT NULL,
    prune_after     timestamp NULL,
    create_time     timestamp NOT NULL DEFAULT now(),

    PRIMARY KEY (blob_id),
    CHECK (octet_length(blob_id) = 32),
    CHECK (octet_length(group_id) = 32),
    CHECK (state IN (0,1,2)),
    CHECK (0 < declared_bytes),
    CHECK (0 <= received_bytes AND received_bytes <= declared_bytes),
    -- S3/MinIO server-side compose is multipart copy: every source part but the last
    -- must be >= 5 MiB, or ComposeObject fails with EntityTooSmall (§8.3)
    CHECK (chunk_bytes >= 5242880),
    CHECK (content_hash IS NULL OR octet_length(content_hash) = 32),
    CHECK (octet_length(grant_ref) = 16)
);

CREATE INDEX message_blob_prune
    ON message_blob (prune_after) WHERE prune_after IS NOT NULL;
CREATE INDEX message_blob_expire_grant
    ON message_blob (grant_expire) WHERE state <> 2;
CREATE INDEX message_blob_group
    ON message_blob (group_id, create_time);
CREATE UNIQUE INDEX message_blob_grant_ref
    ON message_blob (grant_ref);

-- ── 007  soft rollups (recomputed by the sweep, never in the write path) ──
CREATE TABLE message_group_usage (
    group_id      bytea     NOT NULL,
    record_count  bigint    NOT NULL,
    inline_bytes  bigint    NOT NULL,
    blob_bytes    bigint    NOT NULL,
    compute_time  timestamp NOT NULL,
    PRIMARY KEY (group_id)
);

-- ── 008  key-transparency gossip cache (§9.5) ─────────────────────────────
CREATE TABLE message_kt_gossip (
    kt_epoch      bigint    NOT NULL,
    root_hash     bytea     NOT NULL,
    prev_root     bytea     NOT NULL,
    leaf_count    bigint    NOT NULL,
    sth_sig       bytea     NOT NULL,
    observed_time timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (kt_epoch)
);

-- ── 009  recovery verification keys (§4.3.7) ─────────────────────────────────────
-- Keyed per group ON PURPOSE. A single global row would let one hostile first-sight write
-- deny seed-only restore to the handle's real owner in EVERY group, permanently. Per group,
-- a poisoning write is contained to the group whose members could already read the records
-- it concerns.
CREATE TABLE message_recovery (
    group_id        bytea NOT NULL,
    recovery_handle bytea NOT NULL,
    verify_pub      bytea NOT NULL,
    alg_id          int   NOT NULL,
    first_seen      timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, recovery_handle),
    CHECK (octet_length(group_id) = 32),
    CHECK (octet_length(recovery_handle) = 16),
    CHECK (octet_length(verify_pub) = 32)
);

-- ── 010  opt-in, client-triggered diagnostic sessions (§11.5, MASTER §9.7) ──
CREATE TABLE message_diagnostic_session (
    session_id   bytea     NOT NULL,   -- 16 B, minted by the server, presented by the client
    client_id    bytea     NOT NULL,
    start_time   timestamp NOT NULL DEFAULT now(),
    end_time     timestamp NOT NULL,   -- start + at most 1 hour, enforced
    PRIMARY KEY (session_id),
    CHECK (octet_length(session_id) = 16),
    CHECK (end_time > start_time),
    CHECK (end_time <= start_time + interval '1 hour')
);
CREATE INDEX message_diagnostic_active ON message_diagnostic_session (end_time);
```

Trust-on-first-use, **scoped to one group**: the server records `verify_pub` on first sight of a `RecoveryTag` in that group and **refuses any later differing pub for the same handle in the same group** — the same shape as the client's server-key pin.

### 3.3 Index rationale against the real query patterns

| # | Query | Frequency | Plan | Index |
|---|---|---|---|---|
| Q1 | `SELECT … WHERE group_id=$1 AND record_id > $2 ORDER BY record_id LIMIT $3` | Dominant read. Every fetch, every reconnect backfill, every subscribe catch-up | Index scan on the PK, forward, bounded by LIMIT | `PRIMARY KEY (group_id, record_id)` |
| Q2 | `SELECT current_epoch, next_record_id, … FROM message_group WHERE group_id=$1 AND NOT closed FOR UPDATE`, then, after every per-record check has passed, `UPDATE message_group SET next_record_id = next_record_id + $k WHERE group_id=$1 RETURNING next_record_id - $k` | Every submit | Single-row PK lock, then a single-row PK update; also the group lock | `PRIMARY KEY (group_id)` |
| Q3 | `INSERT INTO message_stream_claim … ON CONFLICT (group_id, sender_handle, stream_index) DO NOTHING` and the step-0 probe `SELECT record_id, body_hash, head_hash FROM message_stream_claim WHERE …` | Every submit | Unique-index probe, then a one-row PK insert | `PRIMARY KEY (group_id, sender_handle, stream_index)` on `message_stream_claim` |
| Q4 | *(withdrawn — the partial unique index on `message_record` is not creatable on a partitioned table. The CAS is Q14. The number is left reserved rather than renumbered.)* | — | — | — |
| Q5 | `SELECT group_id, record_id, retention_class, blob_id FROM message_record WHERE prune_after <= now() ORDER BY prune_after FOR UPDATE SKIP LOCKED LIMIT 1000` | Sweep, every 60 s | Partial index scan over the backlog only | `message_record_prune` |
| Q6 | `SELECT … WHERE recovery_handle = $1 ORDER BY group_id, record_id` | Rare (seed-only restore) | Partial index scan | `message_record_recovery` |
| Q7 | `SELECT last_stream_index FROM message_sender WHERE group_id=$1 AND sender_handle=$2` | Every submit | PK lookup | `PRIMARY KEY (group_id, sender_handle)` |
| Q8 | `SELECT … FROM message_blob WHERE grant_expire <= now() AND state <> 2 LIMIT 500` | Orphan reaper, every 5 min | Partial index scan | `message_blob_expire_grant` |
| Q9 | `SELECT write_key_wrapped, alg_id FROM message_epoch WHERE group_id=$1 AND epoch=$2` | Every submit on cache miss | PK lookup, served from an in-process LRU >99% of the time | `PRIMARY KEY (group_id, epoch)` |
| Q10 | `SELECT … WHERE group_id=$1 AND epoch=$2 AND wrap_target_handle=$3` | Every device join, every epoch catch-up | Partial index scan, one row | `message_record_wrap` |
| Q11 | `SELECT … WHERE group_id=$1 AND retention_class = ANY($2) AND record_id > $3 ORDER BY record_id LIMIT $4` | Join, seed-only restore, PERMANENT-only catch-up | Index scan | `message_record_class` |
| Q12 | `UPDATE message_epoch SET write_key_wrapped = NULL WHERE group_id=$1 AND epoch <= $2 AND write_key_wrapped IS NOT NULL` | Every commit | **The `IS NOT NULL` predicate is load-bearing** — it bounds the update to one or two rows. Without it a group at epoch 10,000 rewrites 10,000 already-NULL rows, with matching dead tuples and WAL, **inside the group row lock** that §6.7 already flags as the throughput ceiling | `PRIMARY KEY (group_id, epoch)` |
| Q13 | `SELECT blob_id, object_key FROM message_blob WHERE prune_after <= now() ORDER BY prune_after FOR UPDATE SKIP LOCKED LIMIT 500` | Blob GC, every 60 s | Partial index scan | `message_blob_prune` |
| Q14 | `INSERT INTO message_commit (group_id, epoch, record_id) VALUES (…) ON CONFLICT (group_id, epoch) DO NOTHING` | Every commit | One-row PK insert; **the** CAS | `PRIMARY KEY (group_id, epoch)` |
| Q15 | `SELECT read_key_wrapped FROM message_epoch WHERE group_id=$1 AND epoch=$2 AND read_key_wrapped IS NOT NULL` | Every authorized read, on cache miss | PK lookup, served from the same in-process LRU as Q9. Keyed by the request's authenticated `read_epoch`, so no scan and no key trial | `PRIMARY KEY (group_id, epoch)` |
| Q16 | `UPDATE message_epoch SET read_key_wrapped = NULL, read_key_install = NULL WHERE read_key_install < now() - $window AND read_key_wrapped IS NOT NULL` | Read-key tidy, every 5 min | Partial index scan over outstanding work only | `message_epoch_read_key_expiry` |

Two properties of `message_record_prune` are load-bearing and easy to lose in a refactor:

1. It is **partial** on `prune_after IS NOT NULL`, and
2. the sweep **sets `prune_after = NULL`** after acting.

Together, the index holds only outstanding work. A full index on `prune_after` would grow with the corpus and every sweep pass would scan past millions of already-pruned rows. If a future change makes the sweep leave `prune_after` populated, this index becomes the service's largest and least useful object. There is a CI assertion for this in §13.

Alongside it, a second CI assertion on Q12: **a commit at epoch 10,000 touches the same number of `message_epoch` rows as a commit at epoch 2** (§13 item 16).

`message_stream_claim`'s primary key leads with `group_id`, its own partition key, as Postgres requires for a unique constraint on a partitioned table. `message_record` now carries **no** unique index at all beyond its primary key: uniqueness on `(group_id, sender_handle, stream_index)` moved to the claim table precisely because §7.2 zeroes `sender_handle` on expiry (decision B15). `message_record_prune`, `message_record_recovery`, `message_record_wrap`, `message_record_class` and `message_record_blob` are non-unique. The single-commit invariant is not an index on `message_record` at all — see `message_commit` (§3.2) and §3.4.

### 3.4 Partitioning, TOAST, and vacuum

**Partitioning, from day one.** `message_record` is `PARTITION BY HASH (group_id)` with **64 partitions, all created unconditionally in migration 003**. There is no config switch and no partition toggle in `message.yml`.

It is not a switch because it cannot be one. Converting a populated non-partitioned table into a partitioned one in PostgreSQL is a full table rewrite — create the partitioned parent, create 64 partitions, copy 10^8 rows, rebuild five indexes, swap names — with no online path in core PostgreSQL, on the largest and busiest table in the system, at the moment it is largest and busiest. An operator reading the previous text would plan a maintenance-window-free capacity step that does not exist and discover it under load. On an empty table, 64 partitions cost essentially nothing.

`message_stream_claim` is partitioned the same way and for the same reason, and its primary key leads with `group_id`, the partition key, as PostgreSQL requires. The one thing partitioning forbids is a **partial** unique index, which is why the single-commit invariant is a dedicated `message_commit` table rather than `message_record_commit … WHERE is_commit` (§3.2) — and why the stream claim is a table rather than a partial unique index skipping expired rows (§7.2).

It does **not** enable a drop-partition retention trick: a pruned `MEDIA` record keeps its head forever (§7.2) and an expired `EPH` record keeps a placeholder row (§7.2), so **no partition ever becomes droppable**. Do not design around that.

**TOAST.** Bodies at buckets 3 and 4 (16 KiB, 64 KiB) exceed the ~2 KiB TOAST threshold and go out of line. `STORAGE EXTERNAL` skips `pglz`, which cannot compress AEAD output and would cost CPU on every write and read. When the sweep sets `ct_body = NULL`, the TOAST chunks become dead and are reclaimed by the next autovacuum of the TOAST table — not immediately. Media-heavy deployments must confirm autovacuum is reaching `pg_toast.pg_toast_<oid>`; a common failure is a tuned `autovacuum_vacuum_scale_factor` on the parent that leaves the TOAST table untouched, and the operator's disk fills with erased bodies that are already logically gone.

**Bloat.** Records are otherwise write-once: the only UPDATE is the body erase and the `prune_after` NULLing. Set `fillfactor = 100` on `message_record` and its indexes; there is no HOT-update workload to reserve space for. `message_group` is the opposite — it is updated on every submit — so set `fillfactor = 70` there so the allocator update stays HOT.

### 3.5 Storage model

| Class | Bytes/record (typical) | Prunable |
|---|---|---|
| `DURABLE` text | ~700 B inline + ~200 B row overhead | yes — **one year by default**, and only indefinite on a server that advertises no text cap (§7.3) |
| `MEDIA` head after prune | ~250 B, **forever** | body only |
| `PERMANENT` device wrap | ~4.6 KB (`ct_body` padded to exactly 4,112 B at `size_bucket 2`, plus head and columns) | **never** |
| `PERMANENT` recovery wrap | ~4.6 KB, padded identically | **never** |
| `PERMANENT` epoch snapshot | ~300 KB, blob | **never** |
| `EPH(1..5)` after expiry | ~60 B placeholder, **forever** | body only |

Per commit at 2 / 50 / 500 members: ~30 KB / ~700 KB / **~6.9 MB**. A 500-member group with one membership change per day accumulates roughly **2.5 GB/year of unprunable `PERMANENT` data**. State it plainly: **`PERMANENT`-class epoch-bundle data is the dominant unprunable term in this system**, by a wide margin, and §3.4's row counts do not express it. The padded ladder is what sets the number — a 1.2 KB wrap occupies a 4 KiB rung because the encoding admits no smaller one above 1 KiB — and an operator provisioning disk from row counts alone will under-provision by more than an order of magnitude. The only reclamation lever in v1 is group closure (§7.5); per-group quotas are V2.

---

## 4. API surface

### 4.1 Transport choice, and the argument for it

The task invites an argument for REST-over-transport. The answer is a split, and the split falls on a real boundary.

**Control plane — protobuf request/response inside connect `Frame`s.** Reasons:

1. It inherits connect's existing reliability, ordering, per-peer hybrid-PQ session encryption (`transfer_encrypt.go:378` leads with `tls.X25519MLKEM768`), and contract accounting, with zero new transport code and zero new attack surface.
2. **Subscribe needs server-initiated push.** The frame path gives it directly: the server calls `Send` to the client's `client_id`. HTTP needs a second mechanism (SSE, long-poll, or a WebSocket) that would then need its own reconnect, its own auth, and its own idle handling.
3. Control messages are small and already protobuf-shaped; `connect/protocol` already owns the codegen (`protocol/Makefile`).
4. REST would put a URL path on the wire for every operation. Paths are the single most-logged artefact in every HTTP stack on earth, and §9.7 forbids exactly that. A `oneof` inside an encrypted frame has no path to leak.

**Bulk plane — TLS/HTTP to the message server's own endpoint, reached through a provider like any internet host.** Reasons:

1. A 100 MB object driven through a sequence whose batching constant is 3 KiB and whose window is sized for chat would head-of-line-block every message in that client's sequence for the duration of the upload.
2. Range requests, `Content-Range` resumption, and multipart assembly already exist in HTTP and in MinIO's API. Reimplementing them over the frame path is weeks of work to reach parity with a solved problem.
3. The bytes are already client-encrypted under the `MEDIA` class key. The HTTPS layer is defence in depth, not the security boundary, so using an ordinary TLS stack costs nothing in the threat model.
4. Authorization does not leak into the bulk plane: a `BlobGrant` minted on the control plane is a bearer capability scoped to one `grant_ref`, one direction, one size, and a short expiry. **`write_auth` and `req_auth` are verified only on the control plane.** The blob endpoint knows nothing about groups.

So: **request/response messages, not REST, for everything that touches group state; HTTP only for opaque bytes already authorized elsewhere.**

### 4.2 Frame binding

Three additions to `connect/protocol/frame.proto`, in a reserved block, per decision B8:

```proto
    // ── URmessage (beta/message). Block 1000-1099 reserved so parallel beta
    // branches do not collide. Every operation lives in a oneof inside
    // MessageServerRequest/Response/Push, NOT as its own MessageType.
    MessageServerRequest  = 1000;
    MessageServerResponse = 1001;
    MessageServerPush     = 1002;
    MessageServerFragment = 1003;
```

> Spec A owns the file `connect/protocol/message.proto` and its codegen (it is generated by the existing
> `connect/protocol/Makefile` and linked by both the client and the server). Spec B owns the set of `oneof`
> arms and their semantics. A change to the file is an A commit; a change to an arm's meaning is a B
> decision recorded in `SPEC-LEDGER.md`.

There is no `MessageEnvelope`, no `MessageOp`, and no `MessageStreamAck`; Spec A §10.1 has been amended to delete them. Flow control is `Backpressure` (§4.4). The `server_nonce` is a property of the connection, not a field of the request (§5.1 check 2).

Client → server frames are addressed to the instance's `client_id` with `Send`/`SendWithTimeout`. Server → client pushes use the same, reversed. `Frame.raw` is always false for these.

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
        WrapFetchRequest      wrap_fetch      = 19;
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
        WrapFetchResponse     wrap_fetch      = 19;
    }
}

message MessageServerPush {
    oneof body {
        RecordPush       records      = 1;
        TransientPush    transient    = 2;   // EPH(0): never persisted
        CapabilityChange capability   = 3;
        Backpressure     backpressure = 4;
        Drain            drain        = 5;   // §2.3 graceful shutdown
    }
}
```

#### 4.3.1 Hello — capability advertisement and nonce issuance

```proto
message HelloRequest {
    repeated uint32 supported_versions = 1;
    bytes  client_epoch_hint = 2;        // opaque; lets the server pre-warm caches
}

message HelloResponse {
    uint32 protocol_version      = 1;
    bytes  server_id             = 2;    // 16 B, stable per fleet
    repeated ServerKey server_keys = 3;  // current, plus at most one announced successor
    uint64 server_time_ms        = 4;

    // Issued here, scoped to THIS connection, valid for the life of the connection,
    // never rotated, and NOT carried in requests (§5.1 check 2).
    bytes  server_nonce          = 5;    // 32 B

    Capabilities capabilities    = 6;
    BlobEndpoint blob_endpoint   = 7;
    KtGossip     kt_gossip       = 8;    // the operator STH this server independently observed
}

message ServerKey {
    bytes  pub             = 1;   // Ed25519, 32 B
    uint64 not_before_ms   = 2;
    uint64 not_after_ms    = 3;   // 0 = no announced end
    bytes  sig_by_previous = 4;   // Ed25519 by the outgoing key over
                                  // "URmessage/v1/serverkeyrot" ‖ LP(new_pub)
                                  //   ‖ u64(not_before_ms) ‖ u64(not_after_ms)
                                  // empty on a key certified directly by the root
    bytes  sig_by_root     = 5;   // Ed25519 by the FLEET ROOT key over
                                  // "URmessage/v1/serverkeyroot" ‖ LP(server_id)
                                  //   ‖ LP(pub) ‖ u64(not_before_ms) ‖ u64(not_after_ms)
                                  // REQUIRED on the first key a client ever sees from
                                  // this fleet; the client holds the root public key
                                  // compiled in and verifies against it (Spec A §7.6)
}

message Capabilities {
    uint64 max_blob_bytes                = 1;   // default 104857600 (100 MB), master spec §12.2
    uint32 max_request_bytes             = 2;   // control-plane, post-fragmentation reassembly
    uint32 max_records_per_submit        = 3;   // default 256
    uint32 max_records_per_fetch         = 4;   // default 512
    // ── the three advertised limits (MASTER §12.2). Every group operates inside
    //    all three, and the client reads them before it acts.
    uint32 media_ttl_default_seconds     = 5;   // media window default: 2592000 (30 days)
    uint32 media_ttl_max_seconds         = 6;   // media window cap; policy above it is clamped down
    uint32 durable_retention_min_seconds = 7;   // text minimum this server promises to honour
    uint32 durable_ttl_default_seconds   = 16;  // text default: 31536000 (1 year)
    uint32 durable_ttl_max_seconds       = 17;  // text storage cap; 0 = this server sets no maximum
    bool   group_durable_override        = 18;  // false = groups may not raise text retention here
    // max_blob_bytes (field 1) is the third limit: the file size limit.
    repeated uint32 eph_bucket_seconds   = 8;   // [0, 3600, 28800, 86400, 604800, 2419200]
    repeated uint32 size_bucket_bytes    = 9;   // [256, 1024, 4096, 16384, 65536]
    uint32 blob_chunk_bytes              = 10;  // default 8388608 (8 MiB); see §8.3
    uint32 blob_pad_multiple             = 11;  // 262144 (256 KiB), owned by Spec A §5.13
    bool   attestation_supported         = 12;
    uint32 max_submit_bytes              = 13;  // default 131072
    uint32 max_response_bytes            = 14;  // default 1048576
    uint64 capability_version            = 15;  // monotonic; see §10.2
    string operator_host                 = 19;  // the operator THIS SERVER holds its account
                                                // on, from message.yml. Not "the" operator:
                                                // the client's may differ (§9.1)
}

message BlobEndpoint {
    string host                     = 1;
    uint32 port                     = 2;
    repeated bytes tls_spki_sha256  = 3;   // current plus one announced successor; pinned,
                                           // and the client MUST NOT fall back to a CA path
    string path_prefix              = 4;
}
```

`Capabilities` is the whole of the server-advertised contract. The client MUST fetch it before its first submit of a session and MUST re-read it on `CapabilityChange`. Spec C must surface `max_blob_bytes` **before** the file picker opens, not after the user has waited for a 400 MB read.

`Capabilities` also names, in `HelloResponse`, **which operator this server holds its account on**, as `operator_host`. A client does not need to be on the same operator, and MUST NOT treat this value as naming *the* operator — it names *this server's*. The field exists so the client can render where its traffic is forwarded and so a future compatibility check has something to read.

**Both caps bind.** A submit MUST satisfy `max_records_per_submit` **and** `max_submit_bytes`; `max_submit_bytes` governs when they disagree. Sixty-four records at the top inline bucket is ~4 MiB against a 128 KiB reassembly budget, and §5.1 check 1 would reject it only after the client had fragmented and sent every byte.

**Responses are byte-bounded too.** The server truncates a `FetchResponse` on **whichever of `max_records_per_fetch` or `max_response_bytes` binds first**, always returning `complete = false` and a `next_record_id` the client resumes from. The store layer streams rows and stops at the byte budget rather than loading the batch and trimming, so the memory bound is real. Without this, 512 records at `size_bucket 4` is a ~32 MB response materialised per in-flight fetch — and N sticky clients all backfilling after a rolling restart is a straightforward OOM. `complete = false` is **normal** and MUST NOT be treated by the client as a hole (§12.2 C-4).

**Server key rotation, and why there is no longer a warning to click through.** Clients carry the **fleet root public key compiled into the SDK** (Spec A §7.6) and verify the first key they ever see from this fleet against it, which closes the only unauthenticated moment in the design and is impossible to retrofit onto installs that have already shipped. Thereafter:

- a rotation carrying a valid `sig_by_previous` chaining from a key the client already trusts, or a valid `sig_by_root`, is accepted **silently** and appended to the client's inspectable security log;
- a key that chains to neither is **refused outright**. The client does not connect and offers no way to accept it.

The previous design's "unsigned change is a blocking, app-wide warning" is deleted along with the modal that rendered it (Spec C §7.6). A warning whose only correct response is "do not proceed" is better expressed as not proceeding: the remediation for a compromise — rotating — is now silent and auditable, and the attack it was once indistinguishable from is now simply impossible to accept.

**Rotation therefore has a hard operational requirement**: the server MUST be able to present a successor certified by the root without any replica ever holding the root, and without any replica holding the signing private key at all (decision B13, §9.1).

#### 4.3.2 Create group

```proto
message CreateGroupRequest {
    bytes  group_id            = 1;   // 32 B, CSPRNG, client-chosen
    Record initial_commit      = 2;   // is_commit = 1, epoch = 0
    bytes  bootstrap_write_key = 3;   // write_key[0], EXACTLY 32 B. Used only to verify
                                      // initial_commit. This is self-certification: it is
                                      // protected solely by the 20/day per-client_id rate
                                      // limit, and nothing else. Stated plainly, not implied.
    // initial_commit's server_attachment is an EpochAttachment carrying write_key[1].
}
message CreateGroupResponse {
    uint64 current_epoch      = 1;    // always 1
    uint64 record_id          = 2;    // always 1
    RetentionApplied applied  = 3;
}
```

The transaction, the `§5.1` carve-out, and why the previous `epoch0`-only shape bricked or froze every group, are written out in §6.1.

Squatting: `group_id` is a 32-byte CSPRNG value chosen by the creator, so a targeted pre-registration requires guessing it. `CreateGroup` on an existing id returns `REASON_REJECTED` (see §4.5 on why it does not distinguish itself from a bad MAC) and the creator retries with a fresh id. Group creation is rate-limited per `client_id`.

#### 4.3.3 Submit

```proto
message SubmitRequest {
    bytes  group_id = 1;
    repeated Record records = 2;    // at most Capabilities.max_records_per_submit
}

message Record {
    // The canonical connect/message encoding of the whole record, produced by
    // EncodeRecord and parsed by ParseRecord. AUTHORITATIVE for every field below.
    // Carries ct_head, ct_body, server_attachment and write_auth.
    bytes  record_bytes       = 1;

    // Server-indexed projections of record_bytes. The server MUST verify that each
    // equals the corresponding field of ParseRecord(record_bytes) and MUST reject the
    // record with REASON_REJECTED if any differs. The client MUST populate all of them.
    bytes  sender_handle      = 2;   // 16 B
    uint64 epoch              = 3;
    uint64 stream_index       = 4;
    bool   is_commit          = 5;
    uint32 retention_class    = 6;   // the retention-class wire byte of §3.1: 0, 1, 2, or 16..21
    uint32 size_bucket        = 7;   // 0..5
    uint64 expire_at_ms       = 8;   // unix MILLISECONDS, 0 = unset
    bytes  body_hash          = 9;   // 32 B
    bytes  blob_id            = 10;  // 32 B, present iff size_bucket == 5
    bytes  wrap_target_handle = 11;  // 16 B, from server_attachment WrapTag; absent otherwise
    bytes  recovery_handle    = 12;  // 16 B, from server_attachment RecoveryTag; absent otherwise

    // Server-assigned. Ignored on submit, populated on read. Never authenticated.
    uint64 record_id          = 13;
}
```

> On **submit**, the server calls `message.ParseRecord(record_bytes)`, verifies every projection field
> equals the parsed value, verifies `write_auth`, and stores the record **decomposed** into columns.
> On **read**, the server rebuilds `record_bytes` by calling `message.EncodeRecord` over the stored
> columns — with `ct_body` nil when the body has been erased or when `heads_only` is set — and sets
> `record_id`. There is exactly one encoder and one parser in the system, and the server links the same
> Go code the client does.
>
> `write_auth` is **zero on read**. The stored columns cannot reproduce it — it is a MAC over the
> submitting connection's `server_nonce`, which no other party holds and which is gone with that
> connection — and no verifier exists for it: by **I5** record authenticity is MLS's, checked at the
> client. `message.EncodeRecord` accepts a zero `WriteAuth`, `message.ParseRecord` never rejects one,
> and the server retains no `write_auth` column because retaining it would serve nobody.

**Delivery receipts use this path unchanged.** A delivery receipt is an ordinary record of class `EPH(bucket 0)`: it is never persisted, never allocated a `record_id`, and fanned out on the transient channel of §7.6 exactly as a read receipt or a typing indicator is. The server does not know it is a delivery receipt, cannot distinguish it from any other transient, and gains no new capability from it — which is the point, because a delivery state the server manufactured would be a claim about someone else's device that no one could check (MASTER §9.5).

```proto
message SubmitResponse {
    repeated SubmitResult results = 1;   // positionally aligned with the request
}
message SubmitResult {
    Reason reason         = 1;
    uint64 record_id      = 2;   // set when accepted or idempotently re-accepted
    uint64 current_epoch  = 3;   // always set, so a stale client resynchronises in one round trip
    Record winning_commit = 4;   // set on ANY rejection of a submission whose record has
                                 // is_commit = 1, not only REASON_COMMIT_LOST (§6.2)
    RetentionApplied applied = 5;
}
```

**A batch containing a commit MUST contain exactly one record.** Mixing a commit with ordinary records in one batch would make partial-failure semantics ambiguous during an epoch change and buys nothing — a commit is one record by construction.

#### 4.3.4 Fetch

```proto
message FetchRequest {
    bytes  group_id        = 1;
    uint64 since_record_id = 2;   // exclusive; 0 = from the beginning (decision B4)
    uint32 limit           = 3;
    bool   heads_only      = 4;   // skip ct_body; used for fast catch-up and for hole scans
    uint32 class_mask      = 5;   // bitmask of retention_class values to include; 0 = all
    uint64 read_epoch      = 14;  // §4.3.8. The epoch whose read key computed req_auth.
                                  // Inside canonical_request_bytes, therefore inside the MAC.
    bytes  req_auth        = 15;  // §4.3.8. REQUIRED
}
message FetchResponse {
    repeated Record records       = 1;
    uint64 next_record_id         = 2;
    uint64 high_water_record_id   = 3;   // the group's max at read time
    bool   complete               = 4;   // false when truncated by limit OR by
                                         // max_response_bytes; both are NORMAL
    FetchAttestation attestation  = 5;
}
message FetchAttestation {
    bytes  group_id             = 1;
    uint64 since_record_id      = 2;
    uint64 until_record_id      = 3;
    repeated uint64 record_ids  = 4;
    uint64 high_water_record_id = 5;
    uint64 server_time_ms       = 6;
    bytes  server_id            = 7;
    uint32 class_mask           = 8;
    bool   heads_only           = 9;
    bytes  sig                  = 10;   // Ed25519 over the preimage below
}
```

```
"URmessage/v1/attest" ‖ LP(server_id) ‖ LP(group_id)
  ‖ u64(since_record_id) ‖ u64(until_record_id) ‖ u64(high_water_record_id)
  ‖ u32(class_mask) ‖ u8(heads_only)
  ‖ u32(count) ‖ u64(record_id[0]) ‖ … ‖ u64(record_id[count-1])
  ‖ u64(server_time_ms)
```

Clients compare attestations only within an identical `(class_mask, heads_only)` filter. `class_mask` and `heads_only` are inside the preimage so that a filtered fetch is not byte-indistinguishable from a withholding one; refusing to attest a filtered fetch was rejected, because the class-filtered fetch is the restore path and is exactly where an attestation is most wanted.

`high_water_record_id` is inside the signature deliberately: it is what makes "the server told me nothing newer existed" an attributable statement rather than an absence. Because `record_id` is per-group and gapless (decision B4), a client can detect a withheld record as a **hole in the id sequence** without any digest machinery — which is a real v1 improvement over the master spec's §12.3 admission that withholding is undetectable, though it does not close it (a server can withhold a contiguous tail, and §12.3's honest limit stands).

#### 4.3.5 Subscribe

```proto
message SubscribeRequest {
    repeated Subscription subscriptions = 1;
    bool replace = 2;                   // true = this is the complete set for this connection
    uint64 read_epoch = 14;             // §4.3.8. The epoch whose read key computed req_auth.
                                        // Inside canonical_request_bytes, therefore inside the MAC.
    bytes req_auth = 15;                // §4.3.8. REQUIRED
}
message Subscription {
    bytes  group_id        = 1;
    uint64 since_record_id = 2;
}
message SubscribeResponse {
    repeated SubscriptionAck acks = 1;  // each carries snapshot_record_id (§4.4)
}
message RecordPush {
    bytes  group_id = 1;
    repeated Record records = 2;        // always contiguous in record_id
    uint64 high_water_record_id = 3;
}
message TransientPush {                 // EPH(0) — receipts, typing. Never touches disk.
    bytes  group_id = 1;
    repeated Record records = 2;
}
```

#### 4.3.6 Blob grant

```proto
message BlobGrantRequest {
    bytes  group_id        = 1;
    bytes  blob_id         = 2;   // 32 B, from Spec A §5.13 (content-independent; see §8.1)
    Direction direction    = 3;   // DIRECTION_UPLOAD | DIRECTION_DOWNLOAD
    uint64 declared_bytes  = 4;   // upload only; already padded per Capabilities
    uint32 retention_class = 5;   // PERMANENT, DURABLE, MEDIA, or the parent's EPH class (§8.3)
    uint64 read_epoch      = 14;  // §4.3.8. The epoch whose read key computed req_auth.
                                  // Inside canonical_request_bytes, therefore inside the MAC.
    bytes  req_auth        = 15;  // §4.3.8. REQUIRED — this is a read-path authorization,
                                  // not a record, so it is req_auth and not write_auth
}
message BlobGrantResponse {
    bytes  grant_token   = 1;   // opaque bearer capability; see §8.2
    uint64 expires_ms    = 2;
    uint32 chunk_bytes   = 3;
    bytes  chunk_mask    = 4;   // upload: chunks already received, for resume
    string path          = 5;   // path under BlobEndpoint.path_prefix, keyed on grant_ref
}
```

#### 4.3.7 Recovery fetch (seed-only restore, master §5.4)

```proto
message RecoveryFetchRequest {
    bytes  recovery_handle = 1;   // 16 B
    bytes proof = 2;   // Ed25519 over "URmessage/v1/recovery" ‖ LP(server_nonce)
                       //   ‖ LP(recovery_handle), under recovery_sig_sk.
                       // Verified against message_recovery.verify_pub (TOFU).
    uint64 cursor          = 3;
    uint32 limit           = 4;
}
message RecoveryFetchResponse {
    repeated GroupRecords groups = 1;
    uint64 next_cursor = 2;
}
```

```
recovery_root      = HKDF-Expand(master_key, "recovery/v1", 32)              (unchanged)
recovery_handle    = HKDF-Expand(recovery_root, "idx/v1", 16)                (unchanged)
recovery_sig_seed  = HKDF-Expand(recovery_root, "idxsig/v1", 32)             (NEW)
recovery_sig_sk    = Ed25519 private key from recovery_sig_seed
recovery_verify_pub= Ed25519 public key of recovery_sig_sk                   (32 B)

recovery_proof = Ed25519(recovery_sig_sk,
                   "URmessage/v1/recovery" ‖ LP(server_nonce) ‖ LP(recovery_handle))

The archive record's server_attachment RecoveryTag (§5.4, kind 0x0002) carries
{recovery_handle, recovery_verify_pub, alg_id} and is covered by write_auth, so the
public half arrives authenticated as a member of the group.

The server stores the public half on first sight WITHIN THAT GROUP and REFUSES any later
differing recovery_verify_pub for the same recovery_handle in the same group
(trust-on-first-use, the same shape as the client's server-key pin).
RecoveryFetchRequest.proof is verified against it.
```

The proof is **asymmetric on purpose**. A symmetric MAC under a `recovery_root`-derived key is unverifiable by construction: the server holds only `recovery_handle` and MUST NOT hold `recovery_root` (a server holding it reads all durable history in every group), so it can derive no MAC key. As previously written this request was an **unauthenticated cross-group read keyed on a 16-byte handle** — which §4.3.7 itself concedes is a handle-existence oracle.

`RecoveryFetchRequest` is the one cross-group read. With `message_recovery` keyed per group, a handle may have a row in many groups; the server verifies the proof against **each candidate group's row** and returns only the groups whose stored `recovery_verify_pub` validates it. A group whose row was poisoned drops out of the result; every other group still restores. The disclosure is unchanged from master spec §5.4 — the server learns how many groups the handle participates in — and the request stays hard rate-limited (§4.7) because it is otherwise a handle-existence oracle.

#### 4.3.8 Request authentication

```
req_auth = MAC(read_key[e], "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op)
                            ‖ LP(canonical_request_bytes))

  read_key[e]             = the epoch's read key, HKDF-Expand(storage_root[e],
                            "read/v1", 32), installed from that epoch's
                            EpochAttachment.read_key and retained for
                            read_key_window_seconds (default 7776000 = 90 days)
                            from installation (§5.3).
  e                       = the request's read_epoch field. It is a field of the
                            request body, so it is inside canonical_request_bytes
                            and inside the MAC: the server selects a key by an
                            authenticated value and never trials keys.
  op                      = the field number of the selected `oneof body` arm in
                            MessageServerRequest, as a u8.
  canonical_request_bytes = the deterministically-marshaled request body message
                            (protobuf deterministic marshal, fields ascending) with its
                            own `req_auth` field set to zero length.

Required on, with their op bytes:  FetchRequest (13), SubscribeRequest (14),
                                   GroupStatusRequest (16), BlobGrantRequest (17),
                                   WrapFetchRequest (19).

Verified with §5.1 checks 1, 2, 4, 5 and the (group_id, read_epoch) read-key lookup, and
then this MAC, returning the same non-specific REASON_REJECTED on failure. A request
naming an epoch whose key has aged out returns the same REASON_REJECTED with the same
padded latency: the client learns it is outside the window from GroupStatus, which is
itself authorized, and never from a distinguishable refusal. No transaction is opened and
no row is allocated on the read path.
```

The arms that carry no `req_auth`, each for its own reason:

- `HelloRequest` (10) names no group, and its whole purpose is to obtain the `server_nonce` the MAC is computed over.
- `CreateGroupRequest` (11) is issued before the group exists, so there is no installed key to MAC under. It is self-certified against `bootstrap_write_key` and protected by the 20/day per-`client_id` rate limit and nothing else (§6.1).
- `SubmitRequest` (12) needs none: every record inside it carries its own `write_auth`.
- `UnsubscribeRequest` (15) reads no group state and cancels only the caller's own subscription.
- `RecoveryFetchRequest` (18) is issued by a seed-only restorer, which holds no group key at all; it is authorized by the Ed25519 recovery proof of §4.3.7 instead.

#### 4.3.9 Wrap fetch

```proto
        WrapFetchRequest      wrap_fetch      = 19;   // in MessageServerRequest.body
        WrapFetchResponse     wrap_fetch      = 19;   // in MessageServerResponse.body

message WrapFetchRequest {
    bytes  group_id           = 1;
    uint64 epoch              = 2;
    bytes  wrap_target_handle = 3;   // 16 B
    bool   want_snapshot      = 4;
    uint64 read_epoch         = 14;  // §4.3.8. The epoch whose read key computed req_auth.
                                     // Inside canonical_request_bytes, therefore inside the MAC.
                                     // Independent of `epoch` above, which names the wrap wanted.
    bytes  req_auth           = 15;
}
message WrapFetchResponse {
    repeated Record records = 1;     // the device wrap and, if requested, the snapshot ref
    bool   epoch_complete   = 2;
}
```

Served by `message_record_wrap` (§3.3 Q10). Without it every device add and every join pulls the whole ~6.9 MB epoch bundle through Q1 and discards 99.9% of it, at `max_records_per_fetch = 512`, over a 3 KiB-batched control plane — the exact failure MASTER §8.2's "the server MUST index wraps by target" exists to prevent. A request naming a target with no wrap at that epoch returns `REASON_WRAP_TARGET_UNKNOWN`.

#### 4.3.10 Supporting messages

Every message referenced above and not otherwise defined:

```proto
enum Direction { DIRECTION_UNSPECIFIED = 0; DIRECTION_UPLOAD = 1; DIRECTION_DOWNLOAD = 2; }

message GroupStatusRequest  { bytes group_id = 1; uint64 read_epoch = 14; bytes req_auth = 15; }
message GroupStatusResponse {
    uint64 current_epoch        = 1;
    uint64 high_water_record_id = 2;
    bool   epoch_complete       = 3;   // §6.1 epoch publication step 3
    bool   closed               = 4;
    RetentionApplied applied    = 5;
    uint64 oldest_read_epoch    = 6;   // the oldest epoch whose read key this server still
                                       // holds. A client whose newest key is older than this
                                       // is past the window and is told so rather than being
                                       // refused without explanation (§5.3).
}
message CapabilityChange { Capabilities capabilities = 1; uint64 capability_version = 2;
                           repeated ServerKey server_keys = 3; BlobEndpoint blob_endpoint = 4; }
message Backpressure     { bytes group_id = 1; uint64 resume_from_record_id = 2; }
message Drain            { uint32 reconnect_after_ms = 1; }
message GroupRecords     { bytes group_id = 1; repeated Record records = 2;
                           uint64 high_water_record_id = 3; bool complete = 4; }
message SubscriptionAck  { bytes group_id = 1; uint64 snapshot_record_id = 2; Reason reason = 3; }
message KtGossip         { uint64 kt_epoch = 1; bytes root_hash = 2; bytes prev_root = 3;
                           bytes history_root = 4; uint64 leaf_count = 5;
                           uint64 sth_time_ms = 6; bytes sth_sig = 7; }

message RetentionApplied {
    uint32 media_ttl_seconds        = 1;   // what the server actually stored
    uint32 durable_ttl_seconds      = 2;   // 0 = indefinite
    bool   media_clamped_down       = 3;
    bool   durable_floored_up       = 4;
    uint32 requested_media_ttl_seconds   = 5;
    uint32 requested_durable_ttl_seconds = 6;
    bool   durable_clamped_down          = 7;   // text clamped to durable_ttl_max_seconds
}
```

`sdk` surfaces this message field-for-field as `MessageRetentionApplied`, in **seconds**, differing only in Go casing (Spec A §7.7). Nothing on either side converts to milliseconds; `durable_ttl_seconds = 0` continues to mean indefinite all the way to the user-visible notice.

`EpochAttachment`, `RecoveryTag`, `WrapTag` and `EpochComplete` are **not** declared here. They are `connect/message` encodings owned by Spec A, restated in §5.4, and are carried opaquely inside `Record.record_bytes`; the server parses them with `message.ParseServerAttachment` and never reimplements them (§12.1 A-2).

### 4.4 The subscribe race, resolved

Naive subscribe has a well-known hole: register-then-backfill duplicates and misses, backfill-then-register loses everything written in between. The required sequence is:

1. On `SubscribeRequest`, the instance **registers the Redis subscription first** and begins **buffering** pushes for that group in memory, without sending them.
2. It then reads a backfill snapshot: `Q1` bounded by `LIMIT`, capturing `snapshot_record_id = high_water_record_id` at the moment of the read.
3. It returns `SubscriptionAck{snapshot_record_id}` and streams the backfill.
4. It then **flushes the buffer, discarding every buffered record with `record_id <= snapshot_record_id`**, and goes live.
5. If the buffer overflows (slow client, large group), the instance drops the buffer, sends `Backpressure{group_id, resume_from_record_id}`, and the client re-subscribes from its own high-water. **It never silently drops records** — a silent drop is indistinguishable from server withholding, which is precisely the thing clients are supposed to be able to notice.

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
    REASON_RETENTION_CLAMPED        = 9;  // accepted; policy clamped DOWN to the advertised
                                          // cap OR floored UP to the advertised minimum —
                                          // see §7.3 and RetentionApplied
    REASON_BLOB_UNKNOWN             = 10;
    REASON_BLOB_INCOMPLETE          = 11;
    REASON_UNSUPPORTED_VERSION      = 12;
    REASON_INTERNAL                 = 13;
    REASON_EPOCH_INCOMPLETE         = 14;  // the epoch's wrap set has not landed (§6.1, step 3 of
                                           // the epoch publication sequence)
    REASON_WRAP_TARGET_UNKNOWN      = 15;  // WrapFetch: no wrap for that target at that epoch
}
```

**`REASON_REJECTED` deliberately merges "unknown group", "write_auth did not verify", and "epoch key unknown".** Distinguishing them would turn the submit path into an oracle for group existence: a party who holds no `write_key` could enumerate `group_id`s and learn which exist. The reject is the same code, the same response size, and the same timing envelope (the handler pads its response latency to a fixed floor on the reject path). A failed `req_auth` on the read path returns the same code with the same envelope (§5.1.1).

`REASON_EPOCH_STALE` and `REASON_COMMIT_LOST` do reveal that the group exists — but they are only ever returned **after** a `write_auth` verified, so the caller already holds a group secret.

`REASON_COMMIT_LOST` is returned on **any** rejection of a commit submission, not only a lost CAS, and always carries `winning_commit` — see §6.2.

### 4.6 Fragmentation (open item 2)

`ClientSettings.MinimumMessageLenLimit()` is 4 KiB and `sendPackBatchMaxMessageByteCount` is 3 KiB. A 64 KiB inline record does not fit a frame, and we must not assume any particular production `MaxMessageLen`. Therefore the control plane carries its own fragmentation, transport-cap independent:

```proto
// MessageType 1003, from the reserved block of §4.2. It previously had no code point at all.
message MessageServerFragment {
    uint64 request_id = 1;
    uint32 index      = 2;
    uint32 count      = 3;
    bytes  part       = 4;
}
```

Rules:

- The sender chooses `part` size as `min(peer_advertised_frame_budget, 2048)` bytes and MUST NOT exceed the negotiated budget.
- The receiver reassembles into a buffer capped at `Capabilities.max_request_bytes`; exceeding it aborts the request with `REASON_OVERSIZE` and **frees the buffer immediately** — an unbounded reassembly buffer is a trivial memory-exhaustion vector.
- Reassembly state is per `(source client_id, request_id)`, expires after 30 s, and is capped at 16 concurrent in-flight reassemblies per client.
- Fragments MUST be delivered in order by the underlying sequence; out-of-order `index` aborts the request rather than buffering holes.

`max_request_bytes` remains the reassembly cap for requests; `max_response_bytes` (§4.3.1) is the matching cap for responses, which previously had none.

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
| Quarantine | see §9.6 | `client_id` | Postgres `message_quarantine`, checked at §5.1 check 4 |

On Redis unavailability, all limits fail **closed** to an in-process limiter at 25% of the configured rate. Availability is not worth an unmetered write path.

---

## 5. `write_auth` and `req_auth` verification

### 5.1 The exact check order (normative)

Order matters for denial of service, not just correctness. Nothing that costs a database read happens before something that costs a hash.

| # | Check | Cost | On failure |
|---|---|---|---|
| 1 | Frame decodes; fragment reassembly within `max_request_bytes` | CPU, bounded | `REASON_OVERSIZE`, free buffer |
| 2 | Connection is authenticated at the connect layer (`ByJwt` validated by the platform; §4.3 master). The `server_nonce` is **not** carried in the request — the server knows its own connection's nonce and looks it up from the connection, never from the request | memory | `REASON_REJECTED` |
| 3 | **Static shape.** `octet_length(sender_handle)==16`, `body_hash`==32, `retention_class` and `size_bucket` in range, `expire_at` parses, `ct_head` ≤ head cap, and **`octet_length(ct_body)` is exactly `size_bucket_bytes[b] + 16`** (the AEAD tag) — equality, not a range, because §9.5 pads into buckets. `size_bucket == 5` requires `ct_body` absent and a 32-byte `blob_id` present in the parsed header; any other `size_bucket` requires `blob_id` absent. Both are read from `message.ParseRecord`, never from the request's projection alone. And `server_attachment` parses via `message.ParseServerAttachment` and is well-formed for its record kind: `EpochAttachment` iff `is_commit`, with `epoch == current_epoch + 1`, `write_key` exactly 32 bytes, `read_key` exactly 32 bytes — **different in every epoch, and therefore never compared against a previously installed one** — known `alg_id`, retention fields in range and `expected_wrap_count > 0`; `RecoveryTag` with a 16-byte handle and a 32-byte Ed25519 pub; `WrapTag` with a 16-byte target; `EpochComplete` with a matching `wrap_count`. Every projection field of `Record` equals the corresponding field of `ParseRecord(record_bytes)` (§4.3.3) | CPU | `REASON_OVERSIZE` / `REASON_REJECTED` |
| 4 | **Rate limits** (§4.7), including the §9.6 quarantine check | Redis / DB | `REASON_RATE_LIMITED` |
| 5 | **Known-group filter.** An in-memory cuckoo filter of every `group_id`. An unknown group is rejected here with **no database read**. See the insert path below — the timer is a backstop only | memory | `REASON_REJECTED` |
| 6 | **Epoch key lookup.** In-process LRU keyed `(group_id, epoch)`; miss reads `message_epoch` once, unwraps under the `kek_id` in the row, caches. Negative results cached 5 s with jitter. The **current** epoch's key and one briefly-retired predecessor both resolve (§5.3) | memory / 1 read | `REASON_REJECTED` |
| 7 | **MAC.** Recompute the §5.4 preimage byte-for-byte using `connect/message`'s encoder — never a local reimplementation — and compare with `hmac.Equal` | CPU | `REASON_REJECTED` |
| 8 | `body_hash == SHA-256(ct_body)` for inline bodies; for blob-backed records the same comparison is made at **bind** time against `message_blob.content_hash`, computed by the server during assembly (§8.3). The server already streams every byte, so hashing is free, and without it a truncated or corrupt blob is discovered only by a recipient after downloading up to 100 MB over the mesh. This is an integrity check for recipients' benefit, not an authenticity check — the uploader and the record author are the same party (§5.2) | CPU | `REASON_REJECTED` |
| 9 | **Only now**: open the transaction and take the group row lock (§6.1) | DB | see §6 |

Steps 1–8 are lock-free and touch the database at most once, only for a group that actually exists. An attacker without a `write_key` cannot force a single row lock, a single index write, or a single WAL byte.

**Check 2, stated as a dependency rather than an assumption.** The message server relies on the platform to authenticate `source.SourceId` on every received frame and **cannot verify this independently** (decision B1 forbids importing `server/model` / `server/session`, where `ParseByJwtForAudience` and `ValidateByJwtState` live). Every rate limit in §4.7 and the grant binding in §8.2 rest on it. This is an explicit, named dependency on the operator transport, with an owner on the operator side — not an assumption.

**Check 5, the insert path.** The known-group cuckoo filter is refreshed from Postgres on a **60 s timer as a backstop only**. The primary path is an **add published over a dedicated Redis channel from the `CreateGroup` transaction's after-commit hook** (the §6.1 step (8) publish already exists as a pattern); every instance inserts on receipt, and the creating instance inserts locally before responding. Without an insert path, create-a-group → reconnect → send fails with `REASON_REJECTED`, which §4.5 deliberately makes indistinguishable from a bad MAC and which §12.2 C-5 requires the client to render as a generic failure — so the user sees "message failed" with no diagnosable cause and the operator sees nothing, because `message_group_filter_false_positive_total` counts the opposite direction. Add `message_group_filter_false_negative_total`, sourced from the periodic full refresh.

#### 5.1.1 The read path

`Fetch`, `Subscribe`, `GroupStatus`, `BlobGrant` and `WrapFetch` are authorized by `req_auth` (§4.3.8). Checks 1, 2, 4 and 5 apply unchanged; check 6 becomes a **read-key lookup keyed on `(group_id, read_epoch)`** — the epoch is named by the request and is inside the MAC, so the server selects exactly one key and never trials a set — and the `req_auth` MAC then replaces check 7. A lookup that finds no retained key for that epoch, whether because the epoch never existed or because its key aged out of the 90-day window, fails identically. **No transaction is opened and no row is allocated on the read path.** Failure returns the same non-specific `REASON_REJECTED` with the same padded latency floor as the submit path.

Before this, `FetchRequest` and `SubscribeRequest` carried no authenticator at all and §5 specified verification for submit only: any client holding a valid `ByJwt` that learned a 32-byte `group_id` could read a group's complete ciphertext history, every wrap and every attestation. That is a better enumeration and disclosure oracle than the submit path, which §4.5 goes to real trouble to close, and it makes MASTER §9.5's description of what the server sees ("your account, your group list") false.

`RecoveryFetch` is authorized by the Ed25519 recovery proof (§4.3.7) instead, because a seed-only restorer holds no `write_key`.

### 5.2 What the server explicitly does NOT check, and why

| Not checked | Why |
|---|---|
| Any plaintext, message type, or semantic content | It cannot decrypt, and adding a decryption capability would end the design |
| That the sender is a **particular** member | `write_key` is group-wide (§9.2). The server learns "a current member of this group" and no more. This is the accepted v1 cost of dropping per-device capabilities |
| MLS validity of anything: proposal legality, commit correctness, tree hash, transcript hash, `confirmation_tag`, leaf signatures, credentials, capability consistency, or any of the 43 ValSem codes | **I5.** Authentication is MLS's, end to end. The server does not link an MLS implementation, at all — see §5.3 |
| Roles: OWNER / ADMIN / MEMBER / OBSERVER | §11 of the master spec puts roles in the transcript-covered group-context extension, which the server cannot read. `OBSERVER` is UI- and MLS-enforced in v1 |
| Whether an accepted commit is *the right* commit | §9.3 requires only that it is *the first valid* one. "Right" is not a property the server can evaluate, and pretending otherwise would make the server an MLS participant |
| Deletion authority | Decision B6: there is no client-initiated erase in v1 |
| Whether a record duplicates an earlier one semantically | Only the `(group_id, sender_handle, stream_index)` uniqueness is enforced |

**Why authenticity is MLS's job and not the server's.** Two reasons, and the second is the one that matters.

The first is capability: the server holds no group leaf key, so it cannot tell a genuine sender from a member impersonating another member. Any check it invented would be weaker than the one the client already performs.

The second is trust structure. Every check the server *can* perform, the server can also *skip*. If clients came to depend on a server-side validity check, the server would have quietly become a participant in the security argument — and §4.2's entire point is that it is not one. A record forged by anyone without a group leaf key fails MLS verification at every client regardless of what the server accepted. `write_auth` therefore exists for exactly three purposes: **quota, spam control, and refusal.** It is an access-control token, never a proof, and no client may treat a server's acceptance as evidence of anything.

**Normative:** `FetchResponse` and `RecordPush` assert nothing about validity. A client MUST fully verify every record through MLS regardless of which server delivered it, regardless of `FetchAttestation`, and regardless of whether the record arrived over a subscription it opened itself.

### 5.3 Epoch key custody

`write_key[n] = HKDF-Expand(storage_root[n], "write/v1", 32)` is delivered to the server by the committer, in the commit record's `server_attachment`, over the connect session's own hybrid-PQ encryption.

MASTER §9.2 and Spec A §12.1 have both been amended to strike the `H(write_key)` language. The adopted text, identical in all three documents:

> The server holds `write_key[n]` itself. It is delivered to the server by the committer inside the commit
> record's `server_attachment` (`EpochAttachment.write_key`), over the connect session's own hybrid-PQ
> encryption, and is stored wrapped under a vault KEK. Three consequences, all accepted:
>
> 1. A server holding `write_key` **can forge `write_auth`**. This changes nothing: the server is the party
>    enforcing `write_auth`, so it could equally accept an unauthenticated record, and any record it injects
>    fails MLS verification at every client (**I5**).
> 2. `write_key` is a label-separated HKDF child of `storage_root[n]`, so holding it yields neither
>    `storage_root[n]` nor the sibling class keys `K_perm` / `K_durable` / `K_media` / `eph_root`. It MUST
>    NOT be reused for any second purpose beyond `write_auth`.
> 3. The server retains the **current** epoch's key plus **one** briefly-retired predecessor (60 s), and
>    nothing older.
>
> An asymmetric per-epoch write proof (Ed25519 derived from `storage_root`, server holds only the public
> half) removes the forgery capability at the cost of one signature per record. It is the right long-term
> shape and is a **V2** item, not v1 text.

One consequence of point 3 that the DDL carries: **a stolen database dump alone must not yield write keys.** Keys are stored wrapped as `u8(kek_id) ‖ nonce(12) ‖ ct(32) ‖ tag(16)` under a KEK loaded from vault resource `message_server.yml`, never written to the database, never in a database backup, and rotated on the schedule in §5.5.

**The read key is a separate key, per epoch, with a much longer lifetime than the write key.** `read_key[n] = HKDF-Expand(storage_root[n], "read/v1", 32)` arrives in the `EpochAttachment` of the commit that opens epoch *n*, and is stored on `message_epoch` wrapped in exactly the same format as that epoch's write key, under the same KEK, with `read_key_install` stamped. **It is retained for `read_key_window_seconds` — default 7776000, ninety days — and then NULLed by the tidy loop of §7.4.** Write keys are still retired after 60 seconds; the two lifetimes are different on purpose and the columns are separate so a future change to one cannot silently move the other.

This is not symmetry for its own sake. `req_auth` under an epoch *write* key would be unusable: decision B9 keeps one predecessor for 60 seconds, so a member offline across a single commit for longer than that holds a key this server cannot resolve — and it cannot call `GroupStatus` to discover the current epoch, cannot `Fetch` the commits that would let it derive the new key, and cannot `WrapFetch` its own wrap, because all three are reads. The read key removes the cycle, and the ninety-day window is what makes it survive a member who was away for a season.

**What the window costs and what it buys, both stated.**

- A member removed at epoch *n* keeps read authorization — the ability to fetch ciphertext it cannot decrypt, and the metadata around it — until epoch *n*'s read key ages out, and no longer. Under the previous design it kept that access **for the life of the group**, which is the defect the window closes.
- A member away for more than ninety days holds only keys this server has discarded and cannot read until it is re-admitted, links from another of its devices, or restores from its seedphrase, which is authorized by the Ed25519 recovery proof of §4.3.7 and never by a read key.
- `GroupStatusResponse.oldest_read_epoch` exists so the client can name that condition instead of showing a bare refusal.

The server never derives a read key. It receives one per epoch, installs it against that epoch, and serves reads authenticated under any it still retains. It no longer compares a commit's read key against a previously installed one — a differing value is now the normal case, once per epoch.

**Normative:** the message server binary MUST NOT link an MLS implementation. A CI check asserts `connect/mls` does not appear in `go list -deps`. This is not fussiness — the moment an MLS parser is in this process, the temptation to "just validate the commit" becomes a one-line change, and I5 dies quietly.

### 5.4 The `server_attachment` amendment to master spec §9.2 — RULED, adopted

Two server-visible fields have no home in the original preimage, and **I6** forbids the server from acting on anything it cannot verify:

1. **Epoch attachment.** A commit's `write_key[n+1]` and retention policy. Without it the server cannot verify the next epoch's records at all, and a forged attachment would let any member set the next epoch's write key or set `media_ttl` to one second.
2. **`recovery_handle`.** The server indexes and serves by it (master spec §5.4). It must be authenticated, because the server acts on it — but be exact about what the authentication proves. `write_auth` is group-wide, so it proves only that *a current member of this group* submitted the record. It does **not** prove that the submitting member owns the handle, and no server-side check can: the server holds no identity keys and by **I5** never verifies authorship. What binds a handle to an identity is the `RECOVERY_PUB` body signature under the publishing member's `identity` key (MASTER §5.3), which the **client** verifies before honouring any `RecoveryTag`. The server's job is narrower and is stated in full below: keep the first `recovery_verify_pub` it sees for a handle **within one group**, refuse a later differing one, and contain the damage of a bad first write to that group alone.

The adopted amendment covers both, and every future server-visible field. It is applied in MASTER §8, §8.3 and §9.2 and in Spec A §5.1 and §5.11:

```
write_auth = MAC(write_key, "URmessage/v1/write" ‖ LP(server_nonce) ‖ LP(group_id)
                 ‖ LP(sender_handle) ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit)
                 ‖ u8(retention_class) ‖ u8(size_bucket) ‖ u64(expire_at)
                 ‖ LP(H(ct_head)) ‖ LP(body_hash) ‖ LP(blob_id)
                 ‖ LP(H(server_attachment)))

AAD_head  = "URmessage/v1/aad/head" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
          ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit) ‖ u8(retention_class)
          ‖ u8(size_bucket) ‖ u64(expire_at) ‖ LP(body_hash) ‖ LP(blob_id)
          ‖ LP(H(server_attachment))
```

`LP(blob_id)` is a **zero-length** prefix on every record whose `size_bucket` is not 5. `blob_id` is now a header field of the record, parsed out of `record_bytes` by `message.ParseRecord` like every other projection — which is what makes §8.3's bind checks act on an authenticated value rather than on an unverifiable field of the request.

The encoding is `connect/message`'s (Spec A §5.11) and is restated here character-for-character:

```
server_attachment := u16(kind) ‖ LP(body)

  kind 0x0000  NONE            body is zero-length. Ordinary records carry a ZERO-LENGTH
                               server_attachment (the whole field is empty), NOT kind 0x0000.
  kind 0x0001  EpochAttachment carried by, and only by, a record with is_commit = 1
  kind 0x0002  RecoveryTag     carried by RECOVERY_PUB records and by recovery wrap records
  kind 0x0003  WrapTag         carried by per-device epoch wrap records and by the epoch snapshot
  kind 0x0004  EpochComplete   carried by the wrap-set-complete marker record

EpochAttachment {
    u64  epoch                  // the epoch this attachment OPENS. MUST equal current_epoch + 1
    u16  alg_id                 // 0x0031 (HKDF-SHA-256) in v1
    LP   write_key              // exactly 32 bytes: write_key[epoch]
    LP   read_key               // exactly 32 bytes: read_key[epoch] = HKDF-Expand(
                                //   storage_root[epoch], "read/v1", 32), for the epoch this
                                //   attachment OPENS. Different in every epoch; the server
                                //   installs it per epoch and retains it for 90 days (§5.3)
    u32  media_ttl_seconds
    u32  durable_ttl_seconds    // 0 = indefinite
    LP   group_context_hash     // exactly 32 bytes
    u32  expected_wrap_count    // device wraps + recovery wraps + 1 snapshot, for the epoch it opens
}

RecoveryTag {
    LP   recovery_handle        // exactly 16 bytes
    LP   recovery_verify_pub    // exactly 32 bytes, Ed25519
    u16  alg_id                 // 0x0001 (Ed25519)
}

WrapTag {
    LP   wrap_target_handle     // exactly 16 bytes
    u64  epoch                  // the epoch whose wrap or snapshot this record carries
}

EpochComplete {
    u64  epoch
    u32  wrap_count             // MUST equal that epoch's EpochAttachment.expected_wrap_count
}

wrap_target_handle = HKDF-Expand(group_handle_key, "wt/v1" ‖ u64(epoch) ‖ u32(leaf_index), 16)
                     // every member can compute it for every leaf; the server cannot invert it.
                     // The epoch snapshot record uses leaf_index = 0xFFFFFFFF.
```

`server_attachment` is **zero-length** for ordinary records, and a zero-length attachment and an `AttachmentNone` attachment MUST encode identically, or `H(server_attachment)` differs between client and server for every ordinary record.

**`durable_ttl_seconds = 0` means indefinite, on the wire and nowhere else.** The wire sentinel is `0`; the column's sentinel is `NULL`; §6.1 step (6) is the only place the two meet. An indefinite policy is **never floored**: it is already longer than any minimum this server could advertise, so `durable_floored_up` is false. It **is** clamped down where this server advertises a text storage cap: `durable_ttl_max_seconds` non-zero maps wire `0` to the cap, sets `durable_clamped_down`, and `RetentionApplied.durable_ttl_seconds` reports the cap rather than echoing `0`. Only a server advertising no cap stores `NULL` and echoes `0` back. Clamping down is honest — a server with a stated cap cannot honour "keep forever" — whereas flooring up would convert "keep forever" into a shorter finite TTL and then delete the history the group asked to keep.

**`expire_at` units.**

> `expire_at` is **unix milliseconds, `u64`, big-endian, `0` meaning unset**, on the wire, in `AAD_head`,
> and in the `write_auth` preimage. The `timestamp` column in Postgres is a lossy convenience projection
> with **no authority**: `write_auth` is computed and verified only over request bytes via
> `connect/message`'s encoder and is **never** re-derived from the database.
>
> `expire_at` **may only shorten retention, never extend it**:
> `prune_after = LEAST(class_deadline, expire_at)`, with `expire_at` ignored when NULL, 0, or later than
> the class deadline. This satisfies MASTER §9.1 and Spec A S10 while preserving the whole of decision B5's
> reasoning (a member cannot pin `MEDIA` forever by declaring `expire_at = 2999`).

### 5.5 KEK lifecycle

The KEK is the most consequential secret in the deployment and had no lifecycle at all: §5.3 forward-referenced a rotation procedure in §10.4 that does not exist, the 60-byte `CHECK` on `write_key_wrapped` left no room for a key identifier so a dual-KEK window was impossible without a migration on the table that gates every submit, and the loss mode was unstated.

**Format.** `write_key_wrapped = u8(kek_id) ‖ nonce(12) ‖ ct(32) ‖ tag(16)` = 61 bytes (§3.2). `message_epoch.read_key_wrapped` uses the identical format under the identical KEK (§5.3).

**Rotation (§10.5).** Load both KEKs. Unwrap under the `kek_id` in the row. A bounded background pass rewraps, under the new id, **every `message_epoch` row that holds either a `write_key_wrapped` at `epoch = current_epoch` or a non-NULL `read_key_wrapped`** — the second set is far larger, because read keys are retained for ninety days and write keys for sixty seconds, and sizing the rewrap pass off the write keys alone will underestimate it by orders of magnitude on an active fleet. Retire the old KEK only when both `SELECT count(*) FROM message_epoch WHERE substring(write_key_wrapped from 1 for 1) = old_id` and `SELECT count(*) FROM message_epoch WHERE substring(read_key_wrapped from 1 for 1) = old_id` are zero. Missing the second retires a KEK that is still the only way to unwrap ninety days of read keys, and every authorized read in the system fails at §5.1.1's key lookup. Export `message_kek_rewrap_pending` over the sum of both. Cadence: 180 days, or immediately on suspected exposure.

**Loss is unrecoverable, and must be stated.** If `write_key_kek` is lost, no `write_key_wrapped` can be unwrapped, §5.1 check 6 fails for every group, and every submit returns `REASON_REJECTED`. There is no path back: installing a new epoch key requires an accepted commit whose `write_auth` must verify under the epoch key that can no longer be unwrapped. **Every group on the server is permanently bricked.** The KEK MUST therefore be escrowed — Shamir *m*-of-*n* split, or an offline copy under separate access control — with a **documented, tested recovery drill**, and it MUST stay out of the database and off the database backup schedule (§10.4 trap 2). `grant_kek` and `channel_key` carry the same `kek_id` treatment; grants are 15-minute-lived so their rollover is trivial — say so rather than leaving it inferred.

---

## 6. Single-commit agreement — the Delivery Service

The message server is the MLS Delivery Service of RFC 9750 §5.2.1, implementing the strongly-consistent design. Master spec §9.3 states the three requirements; this section specifies the mechanism.

### 6.1 The transaction

The order is the entire point: an epoch-first, allocate-first order rejects every legitimate retry and never reaches the loser protocol.

```sql
BEGIN ISOLATION LEVEL READ COMMITTED;

-- (0) IDEMPOTENCY PROBE, before any gate and before any allocation.
--     A genuine retry is BY DEFINITION at an already-consumed index, and often at an
--     epoch that has since advanced, so running the gates first rejects every one of them.
--     The probe reads the CLAIM, not the record: §7.2 zeroes an expired ephemeral
--     record's sender_handle and erases its head, so the record cannot answer this
--     question and never could for that class.
SELECT record_id, body_hash, head_hash
  FROM message_stream_claim
 WHERE group_id = $1 AND sender_handle = $2 AND stream_index = $3;
--   present, body_hash AND head_hash both match -> REASON_OK{record_id}, no allocation
--   present, either differs                     -> REASON_STREAM_INDEX_REUSED
--   absent                                      -> continue
--   For a COMMIT this rule takes precedence over the CAS: a retried identical commit
--   returns REASON_OK, not REASON_COMMIT_LOST. Getting this backwards makes every
--   timeout look like a fork and burns a pq_secret (§6.2 step 2).

-- (1) Lock the group. Read state; DO NOT allocate ids yet.
SELECT current_epoch, next_record_id, media_ttl_seconds, durable_ttl_seconds,
       policy_version, epoch_complete
  FROM message_group
 WHERE group_id = $1 AND NOT closed
   FOR UPDATE;
--   0 rows -> REASON_REJECTED (unknown or closed; indistinguishable, §4.5)

-- (2) EPOCH GATE, commit-aware.
--   if record.is_commit AND a row exists in message_commit at (group_id, record.epoch):
--        ROLLBACK; return REASON_COMMIT_LOST{current_epoch, winning_commit}
--        -- REGARDLESS of how far current_epoch has advanced. The row lock serialises
--        -- committers, so a loser acquires the lock only AFTER the winner advanced the
--        -- epoch; an epoch-first gate therefore returned EPOCH_STALE and §6.2's
--        -- mandatory loser protocol never fired.
--   else if record.epoch <> current_epoch:
--        ROLLBACK; return REASON_EPOCH_STALE{current_epoch}
--        -- verified under the briefly-retired key when record.epoch == current_epoch - 1
--   if NOT epoch_complete AND the record is not a wrap / snapshot / EpochComplete
--   for this epoch:
--        ROLLBACK; return REASON_EPOCH_INCOMPLETE{current_epoch}

-- (3) Stream monotonicity, per (group_id, sender_handle). Monotonic, NOT contiguous.
SELECT last_stream_index FROM message_sender
 WHERE group_id = $1 AND sender_handle = $2;
--   record.stream_index <= last -> REASON_STREAM_INDEX_REGRESSED

-- (3b) BATCH ATOMICITY. Run every per-record check above for EVERY record in the batch
--      BEFORE allocating. Any rejection rolls the WHOLE batch back with zero rows
--      written and a reason on every SubmitResult. Otherwise the allocated id block
--      exceeds the rows written and the group's record_id sequence acquires a permanent
--      gap -- destroying the property decision B4 exists to create and that §12.2 C-4
--      instructs clients to treat as a fault.

-- (4) Allocate exactly k ids, where k is the verified accepted count.
UPDATE message_group SET next_record_id = next_record_id + $k
 WHERE group_id = $1
RETURNING next_record_id - $k AS first_record_id;

-- (5a) Ordinary records. Claim first, then the row. ON CONFLICT on both, never a bare
--      INSERT (§11.2 item 4). The claim is the uniqueness authority; the record row
--      carries no unique index on (sender_handle, stream_index) at all, because that
--      column is zeroed on expiry (§7.2).
INSERT INTO message_stream_claim (group_id, sender_handle, stream_index, record_id,
                                  body_hash, head_hash)
     VALUES (...)
ON CONFLICT (group_id, sender_handle, stream_index) DO NOTHING;
INSERT INTO message_record (...) VALUES (...)
ON CONFLICT (group_id, record_id) DO NOTHING;

-- (5b) Commit record: the CAS is a one-row insert against a full primary key.
INSERT INTO message_commit (group_id, epoch, record_id) VALUES ($1, $2, $r)
ON CONFLICT (group_id, epoch) DO NOTHING;
--   0 rows inserted -> SELECT the winner; ROLLBACK;
--                      return REASON_COMMIT_LOST{current_epoch, winning_commit}
INSERT INTO message_record (..., is_commit) VALUES (..., true);

-- (6) On a won commit, and only then: open the next epoch, retire the old key.
INSERT INTO message_epoch (group_id, epoch, write_key_wrapped, read_key_wrapped,
                           read_key_install, alg_id, opened_by_record)
     VALUES ($1, current_epoch + 1, wrap(attachment.write_key),
             wrap(attachment.read_key), now(), attachment.alg_id, $r);
-- the read key of the epoch this commit OPENS. Different every epoch, retained 90 days,
-- and never NULLed by the 60-second write-key tidy (§5.3).
UPDATE message_epoch SET retire_time = now()
 WHERE group_id = $1 AND epoch = current_epoch AND write_key_wrapped IS NOT NULL;
UPDATE message_epoch SET write_key_wrapped = NULL
 WHERE group_id = $1 AND epoch < current_epoch
   AND write_key_wrapped IS NOT NULL;        -- the predicate is LOAD-BEARING; §3.3 Q12
UPDATE message_group
   SET current_epoch       = current_epoch + 1,
       epoch_complete      = false,
       media_ttl_seconds   = LEAST(attachment.media_ttl_seconds,  $server_media_cap),
       -- Text retention is bounded on BOTH sides now: floored up to the advertised
       -- minimum and clamped down to the advertised cap. 0 means indefinite on the wire;
       -- it maps to NULL only when this server permits it, which is when
       -- durable_ttl_max_seconds is 0 (no maximum). Where a maximum is advertised,
       -- indefinite is clamped to it, because "keep forever" is not something a server
       -- with a stated cap can honour (§7.3).
       durable_ttl_seconds = CASE
           WHEN attachment.durable_ttl_seconds = 0 AND $server_durable_max = 0 THEN NULL
           WHEN attachment.durable_ttl_seconds = 0 THEN $server_durable_max
           ELSE LEAST(GREATEST(attachment.durable_ttl_seconds, $server_durable_min),
                      CASE WHEN $server_durable_max = 0
                           THEN attachment.durable_ttl_seconds
                           ELSE $server_durable_max END)
       END,
       group_context_hash  = attachment.group_context_hash,
       policy_version      = policy_version + 1
 WHERE group_id = $1;

-- (6b) On an accepted EpochComplete marker whose wrap_count equals that epoch's
--      expected_wrap_count: UPDATE message_group SET epoch_complete = true.

-- (6c) On any record carrying a RecoveryTag: INSERT INTO message_recovery ...
--      ON CONFLICT (group_id, recovery_handle) DO NOTHING, then verify the stored
--      verify_pub equals the tag's. A mismatch is REASON_REJECTED and rolls the batch
--      back (TOFU, scoped to this group, §4.3.7).

-- (7) Sender high-water and accounting.
INSERT INTO message_sender (...) VALUES (...)
ON CONFLICT (group_id, sender_handle) DO UPDATE
   SET last_stream_index = EXCLUDED.last_stream_index,
       record_count = message_sender.record_count + 1,
       byte_count   = message_sender.byte_count + EXCLUDED.byte_count,
       last_time    = EXCLUDED.last_time;

COMMIT;
-- (8) AFTER commit, never before: publish {mask, group_id_enc, lo, hi} to Redis.
```

Why both the row lock and the `message_commit` primary key: the lock makes the losing path deterministic and lets the winner be read and returned in the same round trip; the primary key guarantees the invariant even if some future code path forgets the lock. The invariant is worth two mechanisms.

**Attachment validation precedes acceptance (normative).** A commit is validated for attachment well-formedness — `epoch == current_epoch + 1`, `write_key` exactly 32 bytes, `read_key` exactly 32 bytes, `alg_id` known, retention fields in range, and `expected_wrap_count > 0` — at step 3 of §5.1, *before* the CAS. An accepted commit carrying a malformed attachment would open an epoch with no verifiable write key and **brick the group permanently**: no member could ever submit again, and there is no epoch to commit from. This is the single most damaging failure available to a buggy client, and it is prevented by refusing the commit rather than by accepting and repairing.

**CreateGroup, written out.**

```proto
message CreateGroupRequest {
    bytes  group_id            = 1;   // 32 B, CSPRNG, client-chosen
    Record initial_commit      = 2;   // is_commit = 1, epoch = 0
    bytes  bootstrap_write_key = 3;   // write_key[0], EXACTLY 32 B. Used only to verify
                                      // initial_commit. This is self-certification: it is
                                      // protected solely by the 20/day per-client_id rate
                                      // limit, and nothing else. Stated plainly, not implied.
    // initial_commit's server_attachment is an EpochAttachment carrying write_key[1].
}
message CreateGroupResponse {
    uint64 current_epoch      = 1;    // always 1
    uint64 record_id          = 2;    // always 1
    RetentionApplied applied  = 3;
}
```

> The `CreateGroup` transaction inserts, atomically: `message_group{current_epoch = 1, next_record_id = 2,
> epoch_complete = false}`; `message_epoch{epoch 0, wrap(write_key[0])}` and
> `message_epoch{epoch 1, wrap(write_key[1]), wrap(attachment.read_key), read_key_install = now()}`;
> `message_record{record_id = 1, epoch = 0, is_commit = true}` with its
> `message_stream_claim{stream_index, record_id 1, body_hash, head_hash}`;
> `message_commit{group_id, epoch 0, record_id 1}`; the creator's `message_sender` row; and a
> `message_recovery` row if the initial commit carries a `RecoveryTag`. The initial commit's attachment is
> mapped exactly as a steady-state commit's is, including the two-sided text-retention clamp of step (6).
>
> **§5.1 carve-out (normative):** `CreateGroup` skips check 5 (known-group filter) and check 6 (key
> lookup: there is neither an installed epoch key nor an installed read key yet) and verifies the MAC in
> check 7 against `bootstrap_write_key` from its own request. In check 3 the `EpochAttachment` rule
> `epoch == current_epoch + 1` is evaluated as `epoch == 1`, because there is no `message_group` row and
> therefore no `current_epoch` to compare against: the initial commit is at epoch 0 and its attachment
> opens epoch 1. The attachment's `read_key` is installed against epoch 1, exactly as a steady-state
> commit's is installed against the epoch it opens. Every other check applies unchanged.
>
> The previous design supplied only `epoch0` "carrying `write_key[0]`" plus an initial commit at epoch 0.
> Applying §6.1's steady-state rule to it gave either `current_epoch = 1` with no key installed for epoch 1
> — the permanent brick §6.1 claims to prevent — or `current_epoch = 0` with the epoch-0 commit slot already
> consumed, so the first real commit lost the CAS forever and the group could never leave epoch 0.

**Epoch publication.**

> **Epoch publication sequence.** A commit is submitted at `epoch == current_epoch = n`, MAC'd under
> `write_key[n]`, and carries an `EpochAttachment` for epoch `n+1`.
>
> 1. The server accepts at most one commit per `(group_id, epoch)`. On acceptance it sets
>    `current_epoch := n+1` and installs `write_key[n+1]` from the attachment, in the same transaction.
> 2. The committer then submits, **as ordinary records at epoch `n+1`, MAC'd under `write_key[n+1]`**: one
>    device wrap per active device leaf (`WrapTag`, indexed by `wrap_target_handle`), one recovery wrap per
>    member (`RecoveryTag`, indexed by `recovery_handle`), and the ratchet-tree snapshot (one
>    `PERMANENT`-class record, `WrapTag` with `leaf_index = 0xFFFFFFFF`).
> 3. The committer closes the fan-out with one `EpochComplete` marker record whose `wrap_count` MUST equal
>    the attachment's `expected_wrap_count`. Until that marker is accepted, the group is
>    **readable-but-not-writable**: the server returns `REASON_EPOCH_INCOMPLETE` to any non-wrap submit at
>    epoch `n+1`. Step (2) of the transaction already implements exactly this and exempts wrap, snapshot
>    and marker records for every submitter, so no change to the SQL is needed.
> 4. A member or device that finds no wrap for its target at epoch `n+1` after the marker has landed
>    surfaces a `gap` entry with reason `no_wrap`. It never fails silently.
> 5. If the committer dies mid-fan-out, the marker never lands, the group stays non-writable, and any
>    member may re-publish the missing wraps for epoch `n+1` (they are all derivable from the epoch state
>    every member holds) and submit the marker.
>
> **Sizing at the 500-member × 2-device design target.** Wraps pad to the ladder like everything else: a
> device wrap (~1,210 B) and a recovery wrap (~1,242 B) both land in `size_bucket 2`, a `ct_body` of
> exactly 4,112 bytes, about 4.6 KB on the wire each. One commit + 1,000 device wraps + 500 recovery
> wraps + 1 snapshot + 1 marker ≈ 1,503 records ≈ **6.9 MB**, plus a ~300 KB snapshot object on the bulk
> plane. Per-record size caps apply to individual wrap records, never to the commit as a whole.
> `max_records_per_submit` is 256 and `max_submit_bytes` is 131072; the byte cap binds first at about
> 28 wraps per submission, so a wrap-only batch takes **~55 round trips**.

**stream_index scope.**

> `stream_index` is a single `u64` counter per `(group_id, sender_handle)`, write-once, assigned locally.
> A device MUST durably record "index *k* consumed" **before** encrypting, and MUST NEVER encrypt a second
> record at a consumed index. The server enforces **monotonicity, not contiguity**, so a refused write, a
> crash between reserve and send, or a lost commit leaves a legal gap.
>
> `EPH(bucket 0)` transients **do** consume an index locally (so the counter is never rewound) and are
> **never** checked server-side, because the record is never stored and `message_sender.last_stream_index`
> is not advanced for them.

### 6.2 What happens to a losing committer

**The loser protocol binds to any rejection of a commit submission**, not to `REASON_COMMIT_LOST` alone. `SubmitResult.winning_commit` is set on **every** rejection of a submission whose record has `is_commit = 1`, so a loser always receives the winner's exact bytes and always knows that steps 1–7 apply. Binding it to one reason code left step 2 — the hard `MUST NOT` on `pq_secret[n+1]` reuse, which §12.1 A-6 itself calls a silent-corruption failure invisible in functional tests — unreachable in the path the design actually produces.

```
SubmitResult{ reason = REASON_COMMIT_LOST,
              current_epoch = n+1,
              winning_commit = <the full accepted Record> }
```

```
On any rejection of a commit submission, the committer MUST, in order:

1. Discard its provisional epoch-(n+1) state entirely — TreeKEM path secrets, storage_root[n+1],
   write_key[n+1], eph_root[n+1], and every X-Wing wrap it built.
2. MUST NOT reuse the pq_secret[n+1] it sampled. It was encapsulated to a ratchet tree that no
   longer exists; carrying it into the real epoch n+1 binds one PQ secret across two distinct
   epochs and breaks MASTER §7's per-epoch independence. Sample a fresh one.
3. Apply the winning commit from SubmitResult.winning_commit, verifying it through MLS exactly as
   if it had arrived by fetch. Server delivery grants it nothing.
4. Recompute which of its own proposals remain unapplied. The winner may already have included
   some; blindly re-proposing produces duplicates a correct implementation then rejects.
5. Re-propose only the remainder, and retry the commit at epoch n+1.
6. Discard and re-encrypt any records it optimistically produced at epoch n+1. Their stream_index
   values were already consumed and MUST NOT be reused; the stream acquires a legal gap.
7. Back off: full jitter, base 250 ms, cap 8 s, maximum 5 attempts, then surface a failure.
```

This block is byte-identical to Spec A §5.12. Step 2 is a hard `MUST NOT`, easy to violate as an "optimisation," and invisible in testing. Step 7's jitter matters because a 500-member group where an admin change triggers simultaneous commits is a thundering herd; without jitter it converges on livelock.

The server publishes `message_commit_cas_total{result="lost"}`. A sustained loss rate above ~1% means clients are thrashing and the backoff is mistuned; it is an alerting signal, not background noise.

### 6.3 Idempotent retry versus stream-index reuse

A client that times out and retries a submit that actually landed must not be told it lost. This is §6.1 **step (0)** — an explicit probe on `(group_id, sender_handle, stream_index)` that runs *before* the epoch gate and *before* any allocation, not a rescue from a unique violation, because a genuine retry is by definition at an already-consumed index and often at an epoch that has since advanced:

```
load the existing claim from message_stream_claim
if existing.body_hash == new.body_hash AND existing.head_hash == H(new.ct_head):
        return REASON_OK { record_id = existing.record_id }     -- idempotent
else:
        return REASON_STREAM_INDEX_REUSED                        -- client bug or attack
```

The claim stores `head_hash` rather than recomputing it from `ct_head`, because the record's head is erased when an ephemeral record expires (§7.2) and a probe that depended on it would start returning `REASON_STREAM_INDEX_REUSED` for a legitimate retry an hour after the fact.

Comparing both hashes, not just `body_hash`, matters: two records can legitimately share a body hash (an empty body) while differing in the head.

For a **commit** the same rule applies and takes precedence over the CAS check — a retried identical commit returns `REASON_OK`, not `REASON_COMMIT_LOST`. Getting this backwards makes every timeout look like a fork and sends the client through the epoch-*n+1* discard path unnecessarily, which is expensive and, per §6.2 step 2, burns a `pq_secret`.

### 6.4 Failure modes and their responses

| Failure | Behaviour |
|---|---|
| Instance dies mid-transaction | Postgres rolls back. Nothing partially applied. The client retries; §6.3 makes it idempotent |
| Two instances commit simultaneously | Both take the same row lock; one blocks; the second finds a `message_commit` row at its epoch and returns `COMMIT_LOST` with the winner — **never** `EPOCH_STALE`, which the previous ordering produced |
| Redis publish fails after commit | The record is durable; only push is lost. The client's next fetch or reconnect backfill picks it up. **The publish is never inside the transaction** |
| Client submits at epoch *n* while a commit to *n+1* is landing | `EPOCH_STALE{n+1}`, verified under the briefly-retired key (§5.3); the client re-encrypts at *n+1*, consuming a new `stream_index` and leaving a legal gap |
| Group row lock contention | Bounded by `lock_timeout = 3s`; on timeout return `REASON_RATE_LIMITED{retry_after}` rather than holding the connection |
| Attachment malformed | Commit refused before the CAS (§6.1). The group's current epoch is untouched |

---

## 7. Retention and pruning

### 7.1 Pruning without knowing what anything is

The server knows six things about a record: its class, its size bucket, its group, its arrival time, its client-declared `expire_at`, and the group's retention policy as published in the last epoch attachment. It knows nothing about content, and it never needs to. Every retention decision is a function of those six.

At admission the server computes:

```
prune_after = LEAST(class_deadline, expire_at_or_infinity), where:

  class_deadline =
    PERMANENT (0)   -> infinity                                 -- never
    DURABLE   (1)   -> create_time + group.durable_ttl_seconds, which §6.1 step (6) has
                       already FLOORED at Capabilities.durable_retention_min_seconds and
                       CLAMPED at Capabilities.durable_ttl_max_seconds.
                       durable_ttl_seconds IS NULL -> infinity. NULL is reachable only on
                       a server that advertises no text cap (durable_ttl_max_seconds = 0);
                       where a cap is advertised, "indefinite" was clamped to it at
                       admission and there is nothing to decide here.
    MEDIA     (2)   -> create_time + LEAST(group.media_ttl_seconds,
                                           Capabilities.media_ttl_max_seconds)
    EPH(0)          -> never stored at all (§7.6)
    EPH(1..5)       -> create_time + eph_bucket_seconds[b] + grace

  expire_at_or_infinity = infinity when expire_at is NULL or 0, else expire_at

A prune_after of infinity is stored as NULL.
```

`grace` is 1 hour, absorbing client clock skew and delayed delivery. It is safe because expiry is enforced by key destruction, not by this row disappearing: after `eph_root[n]` is gone, a retained ciphertext is undecryptable by everyone including a seedphrase holder (master §8.1). The server's deletion is hygiene.

> `expire_at` is **unix milliseconds, `u64`, big-endian, `0` meaning unset**, on the wire, in `AAD_head`,
> and in the `write_auth` preimage. The `timestamp` column in Postgres is a lossy convenience projection
> with **no authority**: `write_auth` is computed and verified only over request bytes via
> `connect/message`'s encoder and is **never** re-derived from the database.
>
> `expire_at` **may only shorten retention, never extend it**:
> `prune_after = LEAST(class_deadline, expire_at)`, with `expire_at` ignored when NULL, 0, or later than
> the class deadline. This satisfies MASTER §9.1 and Spec A S10 while preserving the whole of decision B5's
> reasoning (a member cannot pin `MEDIA` forever by declaring `expire_at = 2999`).

### 7.2 What each class actually does at `prune_after`

| Class | Action at `prune_after` | Head | Body | Blob | Row |
|---|---|---|---|---|---|
| `PERMANENT` | none | kept | kept | **kept** (`perm/` rung, no ILM rule) | kept |
| `DURABLE` | none by default; if the group set a TTL, same as `MEDIA` | kept | erased | deleted | kept |
| `MEDIA` | `ct_body = NULL`, `pruned = true`, blob deleted | **kept** | erased | deleted | **kept** |
| `EPH(0)` | never persisted; fanned out through Redis and dropped (§7.6) | — | — | — | — |
| `EPH(1..5)` | `ct_body = NULL`, `ct_head = NULL`, `body_hash` zeroed, **`sender_handle` overwritten with sixteen zero bytes**, blob deleted, `pruned = true`, and the row's `message_stream_claim` row **deleted** | cleared | erased | deleted | **kept as a ~60-byte placeholder** |

**The `EPH(1..5)` row survives, and this is not optional.** Deleting whole rows destroys the gapless `record_id` property that §4.3.4 sells ("a client can detect a withheld record as a hole in the id sequence"), that §14 lists as the v1 mitigation for T8, and that §12.2 C-4 makes normative for the client ("treat an id gap as a fault"). Disappearing messages are a shipped v1 feature, so the first client to set a one-hour timer would start manufacturing permanent, indistinguishable false withholding faults an hour later, forever. The placeholder keeps `record_id`, `size_bucket`, `retention_class` and `epoch` so the client renders the timeline correctly, and carries no key material, no ciphertext **and no sender**.

**The sender does not survive, and that is the whole point.** The gapless-`record_id` argument justifies keeping a row; it does not justify keeping the sender in it. A retained `sender_handle` on every expired record leaves a permanent, per-sender, timestamped metadata trail — precisely the artefact that disappearing messages exist to not create — and it survives on a server the user has been told the content is gone from. The sweep therefore overwrites the column with sixteen zero bytes in the same statement that erases the body and the head.

Two mechanical consequences, both handled rather than discovered:

1. **`message_record` carries no unique index on `(group_id, sender_handle, stream_index)`.** Two senders may hold the same `stream_index`, so zeroing would collide. The uniqueness and idempotency claim lives in `message_stream_claim` (§3.2), and the sweep deletes the claim row for an expired ephemeral record along with its content.
2. **Monotonicity is unaffected.** `message_sender.last_stream_index` is untouched by expiry, so a replay at an old index is still refused with `REASON_STREAM_INDEX_REGRESSED` after the claim is gone. What is lost is only the ability to answer "was this exact submission already accepted" for a record whose content the server erased hours earlier, which is not a question any correct client asks that late.

The required user-facing wording for this state is MASTER §12.4: *"The content disappears, the fact of the message does not."*

The `PERMANENT` blob row is kept for the same reason plus §8.3's `perm/` rung: the epoch snapshot is exactly what a seed-only restorer needs to verify signatures, and an ILM ladder would delete it a year after the epoch, long after anyone would connect the two events.

`MEDIA` keeps its head and `body_hash` forever, per master spec §8 ("`body_hash` RETAINED when `ct_body` is erased"), which is what lets the client render "this attachment expired" in the right place in the timeline and keeps the record chain intact. Master spec §12.2's "attachment on an ephemeral parent inherits the parent's key class" is honoured by the client choosing `EPH(b)` rather than `MEDIA` for such a record — the server just applies the class it is given.

`EPH(0)` never touching disk is what makes master spec §12.2's "never persisted" true rather than aspirational. Read receipts, delivery receipts and typing indicators arrive, are published to the group's Redis channel, are delivered to whoever is currently subscribed, and are gone. There is no `INSERT`. The server cannot tell the three apart and does not try (§4.3.3).

After acting, the sweep **sets `prune_after = NULL`**, removing the row from `message_record_prune`. See §3.3 — this is what keeps the sweep's cost proportional to the backlog rather than the corpus.

### 7.3 The three advertised limits

All configuration, all in `Capabilities`:

| Field | Default | Meaning |
|---|---|---|
| `max_blob_bytes` | 100 MB | **The file size limit.** Clients respect it; the server also enforces it at grant time and at assembly time |
| `media_ttl_max_seconds` | 30 days | **The media and file window.** A group policy above it is clamped down and the commit returns `REASON_RETENTION_CLAMPED` |
| `media_ttl_default_seconds` | 30 days | What a group gets for media if it sets nothing |
| `durable_ttl_max_seconds` | **0 (no maximum)** | **The text storage cap.** Non-zero clamps a group's text retention down, including a request for indefinite retention |
| `durable_ttl_default_seconds` | **31536000 (1 year)** | What a group gets for text if it sets nothing. Text retention defaults to a year, not to forever |
| `durable_retention_min_seconds` | **0 (no minimum)** | The minimum this server promises to honour for text |
| `group_durable_override` | **true** | When false, a group may not raise text retention above the default on this server, and the client says so rather than offering a control that does nothing |

These are **the three limits MASTER §12.2 requires a server to advertise** — text, media, file size — plus the defaults and the override rule that make them usable. A group operates inside all three, and every one of them reaches the user as a formatted value rather than a literal (Spec C §8.4).

**Retention negotiation — RULED, warn and proceed, in every direction** (closes open item 3 and ledger open item 1). MASTER open item 1's original wording ("a group's policy **exceeds** the server's advertised **minimum**") was incoherent — exceeding a minimum is not a conflict. The three real cases:

> **Case 1 — the group's policy is longer than the server's `media_ttl_max_seconds`.** The server clamps
> **down**, accepts the commit, and returns `REASON_RETENTION_CLAMPED` with `RetentionApplied`.
>
> **Case 2 — the group's policy is shorter than the server's `durable_retention_min_seconds`.** The server
> floors **up**, accepts the commit, and returns `REASON_RETENTION_CLAMPED` with `RetentionApplied`.
>
> **Case 3 — the group's text policy is longer than the server's `durable_ttl_max_seconds`, or asks for
> indefinite retention on a server that advertises a cap.** The server clamps **down**, accepts the
> commit, and returns `REASON_RETENTION_CLAMPED` with `RetentionApplied`. This is the same shape as case
> 1 and exists because text is now bounded on both sides: a server that advertises a one-year cap and
> silently honoured "keep forever" would be lying in its own capability document.
>
> In every case the group's transcript-covered policy is unchanged, so if the group ever moves to a server
> with different limits (V2) the original policy takes effect again with no migration. The client renders a
> one-time in-group notice naming the **effective** value from `RetentionApplied`, never the requested one.
> Refusing the commit is not an option in any of the three cases: an operator config change would otherwise
> block a group from committing at all.

```proto
message RetentionApplied {
    uint32 media_ttl_seconds        = 1;   // what the server actually stored
    uint32 durable_ttl_seconds      = 2;   // 0 = indefinite
    bool   media_clamped_down       = 3;
    bool   durable_floored_up       = 4;
    uint32 requested_media_ttl_seconds   = 5;
    uint32 requested_durable_ttl_seconds = 6;
    bool   durable_clamped_down          = 7;   // text clamped to durable_ttl_max_seconds
}
```

Clamping is evaluated against the **fleet** `capability_version`, not the local one (§10.2).

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
- Between batches: 100 ms sleep. Per pass: max 50 batches or 20 s wall clock, whichever first. Steady state should keep `message_prune_lag_seconds` — `now() - min(prune_after)` over outstanding work — under an hour. That gauge is the retention SLO; alert above 6 h.
- A second, slower loop every 5 minutes: blob orphan reaping (`message_blob_expire_grant`), `message_group_usage` recomputation, and epoch-row tidying, which is where **two independent expiries** run against `message_epoch`: `write_key_wrapped` is NULLed for rows whose `retire_time < now() - interval '60 seconds'`, and `read_key_wrapped` together with `read_key_install` is NULLed for rows whose `read_key_install < now() - read_key_window_seconds` (default 90 days). They are separate statements against separate predicates on purpose: collapsing them into one is how a maintenance change ends up destroying ninety days of read authorization in a single deploy (§5.3). Export `message_read_keys_retained` as a gauge and `message_read_key_expired_total` as a counter.
- `messagectl sweep-now --until-clean` runs the sweep to completion synchronously. It is required after every restore (§10.4).

Three further loops, all outside the commit transaction.

**1. The policy-change rework pass**, bounded:

```sql
UPDATE message_record
   SET prune_after = LEAST(create_time + $newttl * interval '1 second', expire_at),
       policy_version = $v
 WHERE group_id = $1 AND retention_class = 2
   AND policy_version < $v
 ORDER BY record_id
 LIMIT 1000
 FOR UPDATE SKIP LOCKED;
```

`prune_after` is computed once at admission, so before this pass a group that shortened `MEDIA` retention from 30 days to 1 day kept 29 days of media its members believed was gone. §8.4 already named the case ("a group shortens its policy") and had no mechanism. It MUST stay out of the commit transaction — an unbounded `UPDATE` under the group row lock stalls the group.

**2. The blob GC loop**, making `message_blob.prune_after` the authority and the queue:

```sql
-- the record sweep sets message_blob.prune_after = now() in the SAME transaction as the
-- record update, instead of deleting the object inline.
SELECT blob_id, object_key FROM message_blob
 WHERE prune_after <= now() ORDER BY prune_after
   FOR UPDATE SKIP LOCKED LIMIT 500;
-- delete the object, then delete the row. Crash-safe and idempotent: a retry re-deletes
-- an already-absent object.
```

Before this, `message_blob_prune` indexed a column no query ever selected on; the orphan reaper (`WHERE grant_expire <= now() AND state <> 2`) by definition never saw a bound blob; nothing ever deleted a `message_blob` row, so the table grew monotonically with every attachment ever sent; and §7.4's claim that "the orphan reaper and the ILM backstop both clean up" after a crash between the Postgres commit and the object delete was false for bound blobs.

**3. `messagectl reconcile-blobs`** — the post-restore reconciliation of §10.4 trap 3.

### 7.5 Closing a group

`message_group.closed` appears in the DDL and in §6.1's `WHERE … AND NOT closed` and is otherwise undefined — nobody sets it, nothing says what it means, and nothing says what happens to a closed group's storage. Define it:

- **Set by** `messagectl close-group --group <id> --reason <r>`, an operator action, and by an owner-issued close record (V2).
- **Means**: submits are rejected with `REASON_REJECTED`; fetch is still served, so members can read what they have.
- `close_time` is stamped. After `group_reclaim_seconds` (config, default 30 days) the sweep deletes the group's records, blobs, epochs, sender rows, stream claims, recovery rows and the group row itself — which is also what destroys the last of its stored ciphertext and any read keys still inside their ninety-day window (§5.3).

This is the **only** lever against the unprunable classes in v1. Text is bounded now — one year by default, and clamped by `durable_ttl_max_seconds` where the server advertises one (§7.3) — but `PERMANENT` is never pruned and is the dominant term (§3.5), so a group whose members have all left otherwise keeps its epoch bundles forever, and an operator watching the disk fill has only the two window settings, which affect the two classes that are already the shortest-lived. Add `message_group_closed_total` and `message_group_reclaimed_total`.

### 7.6 EPH(0) transients

**EPH(0) is an explicit carve-out from decision B3, not a contradiction of it.** B3 fixes the pub/sub payload as `{mask, group_id_enc, lo_record_id, hi_record_id}` whose entire mechanism is "the receiving instance re-reads Postgres". For EPH(0) there is nothing in Postgres to re-read, so with the required N ≥ 2 replicas, read receipts, delivery receipts and typing indicators — all **on by default** per MASTER §12.2 — reached only subscribers who happened to land on the same instance as the sender.

A second channel, `urmsg:t:<mask>`, carries `AEAD(channel_key, transient_record_bytes)`. The carve-out is bounded **by construction** to records that never touch disk, and §2.4's existing deployment requirements (no AOF/RDB persistence, `MONITOR` denied by ACL, `slowlog-log-slower-than -1`) are named as the compensating control. Decision B3's text is amended to "no **persisted** record ciphertext, no epoch write key, and no blob byte ever enters Redis", citing this section.

**The EPH(0) submit path, specified:** §5.1 checks 1–8 apply in full. No transaction is opened. No `record_id` is allocated. `message_sender` is **not** updated. `SubmitResult.record_id` is `0` and `SubmitResult.reason` is `REASON_OK`. The sender's local `stream_index` counter still advances (§6.1, *stream_index scope*), so the server's `last_stream_index` legitimately falls behind — which is fine, because it enforces monotonicity and not contiguity.

---

## 8. Blob lifecycle

### 8.1 Identity and padding

**Spec A §5.13 owns both, and closes open item 4.** `blob_id = HKDF-Expand(record_key[i], "blob/v1", 32)`: 32 bytes derived from the record's key material, so it is unlinkable across groups and is **never** a hash of the plaintext or of the ciphertext (a content-derived id makes the object store a confirmation oracle: an adversary holding a candidate file could test whether it exists). Object length is padded by the client to a multiple of **262144 bytes (256 KiB)** before upload — bounded overhead, removes fine-grained size fingerprinting. `Capabilities.blob_pad_multiple` advertises the value; it does not define it.

Content type is always `application/octet-stream`. The server has never seen a media type and never will.

### 8.2 Grant tokens

A `BlobGrant` is minted on the control plane after `req_auth` verifies, so the bulk endpoint never sees a group id and never verifies group membership:

```
grant = base64url( nonce(12) ‖ AES-256-GCM(grant_kek,
            u8(kek_id) ‖ u8(direction) ‖ LP(blob_id) ‖ LP(grant_ref)
          ‖ u64(declared_bytes) ‖ u32(chunk_bytes) ‖ u64(expires_ms)) )
```

`grant_kek` is a server secret from the vault, shared across the fleet so any instance can serve any grant. It contains no group id, so possession of a grant reveals nothing about membership.

> `grant_ref` is 16 random bytes minted per grant and stored in `message_blob`. **It, not `blob_id`, is the
> path component**, so a captured path is meaningless and unlinkable across grants — §4.1 argument 4 rejects
> REST precisely because paths are the most-logged artefact in every HTTP stack, and §11.1 forbids "any URL
> path containing a blob key" while §8.3 put `hex(blob_id)` in the path.
>
> **The grant is a bearer capability for 15 minutes, and nothing more.** The `client_id` claim is
> **deleted**: §4.1 reaches the blob endpoint "through a provider like any internet host" over ordinary TLS
> with no client authentication of any kind, so the endpoint cannot learn the caller's `client_id` and the
> field was decorative — the stated anti-replay property did not exist. Anyone who observes a grant within
> its window can upload or download that object. The bytes are client-encrypted ciphertext, the path is
> opaque, and the window is short; that is the accepted position, stated plainly rather than claimed away.
> A proof-of-possession binding is a V2 item (§14).

### 8.3 Upload, download, storage

**`blob_chunk_bytes` is 8 MiB**, with `CHECK (chunk_bytes >= 5242880)` on `message_blob`, because S3/MinIO server-side compose is multipart copy and **every source part except the last must be ≥ 5 MiB**: a 100 MB blob at the old 256 KiB default is 400 sources of 256 KiB, and `ComposeObject` fails with `EntityTooSmall` at the last step of every multi-chunk upload, after the client has already spent the bytes. At 8 MiB a 100 MB blob is 13 chunks and the `chunk_mask` is 2 bytes.

**Upload** — `PUT {path_prefix}/b/{grant_ref}/{chunk_index}` with `Authorization: Bearer <grant>`:

1. The endpoint decrypts the grant, checks direction, expiry, and that `chunk_index * chunk_bytes < declared_bytes`.
2. Writes the chunk to the object store as `<object_key>/<chunk_index>`.
3. Writes nothing to Postgres.
4. When every chunk is present, assembles into `<object_key>` via MinIO multipart compose, computes `content_hash` over the assembled ciphertext as it streams, sets `state = COMPLETE`, deletes the chunk objects.

Per-chunk state is **out of the write path**: `chunk_mask` is **derived by listing the object store's `<object_key>/` chunk prefix** at grant and resume time — the objects are the authoritative record of what arrived — and `message_blob` is written only on state transitions GRANTED → COMPLETE → BOUND. This restores the "the bulk plane does not touch Postgres" property §8.2 and §8.3 claim, and removes 400 UPDATEs to a single row per upload, each a new row version, each serialising concurrent chunk PUTs on that row: a client that parallelised its upload got no parallelism and a lock wait per chunk.

Resume is `BlobGrantRequest` again: the response carries the listed `chunk_mask` and the client uploads only the missing chunks. Idempotent — re-uploading a chunk is a no-op.

**Binding.** A blob becomes `BOUND` when a record with `size_bucket = 5` and that `blob_id` is accepted on the control plane. At that moment the server verifies, in order:

1. `state == COMPLETE`, else `REASON_BLOB_INCOMPLETE`;
2. `record.retention_class == blob.retention_class`, else `REASON_REJECTED`;
3. `message_blob.content_hash == record.body_hash`, else `REASON_REJECTED`;
4. the record's computed `prune_after` is no later than the object key's rung — else the server copies the object to the correct rung before setting `BOUND`.

Without the class check a client could grant at `eph/ttl-1h` and bind to a `MEDIA` or `PERMANENT` record, and ILM would delete the object an hour later while the row still referenced it — the exact "row pointing at a deleted object, which is a user-visible fault" that §7.4 orders its writes to avoid. **An unbound blob is deleted at `grant_expire`**, so a client that uploads and never submits leaves nothing behind.

**Download** — `GET {path_prefix}/b/{grant_ref}` with a download grant, supporting `Range`. The bytes are ciphertext; the endpoint streams them without touching Postgres beyond the grant check.

**Object keys encode the retention rung**, so the ILM backstop works without per-object rules:

```
Object keys encode the retention rung:

  <prefix>/<env>/msg/perm/<hex(grant_ref)>            NO lifecycle rule, ever
  <prefix>/<env>/msg/media/ttl-<rung>/<hex(grant_ref)>
  <prefix>/<env>/msg/eph/ttl-<rung>/<hex(grant_ref)>

Rungs: {1h, 8h, 1d, 7d, 28d, 30d, 90d, 180d, 365d}

Rounding rule (normative): an object is placed on the largest rung NOT EXCEEDING its record's
prune_after interval — never the nearest. ILM may therefore only delete early relative to the
sweep, never late. A record with no prune_after (PERMANENT, or DURABLE with no TTL) uses perm/.

BlobGrantRequest.retention_class MAY be PERMANENT, DURABLE, MEDIA, or the parent's EPH class.

DURABLE rung mapping: a DURABLE record with no TTL has no prune_after and uses perm/, exactly
as PERMANENT does. A DURABLE record whose group set a TTL uses media/ttl-<rung>, rounded DOWN
by the rule above like any other bounded record.

Normative: SetLifecycle MUST NOT install any rule whose prefix matches `<prefix>/<env>/msg/perm/`.
At startup the process reads back the bucket's ILM configuration and REFUSES READINESS if any rule
matches that prefix. The sweep and the orphan reaper both skip the perm/ prefix.
```

The fixed rung ladder exists precisely so it maps to a bounded set of `BlobLifecycleRule{KeyPrefix, TTL}` entries via the existing `BlobStore.SetLifecycle`. The `perm/` rung is what keeps the ~300 KB `PERMANENT` epoch snapshot — a blob-ref record above the 64 KiB inline ceiling — from being deleted a year after its epoch by a lifecycle rule nobody would connect to the failure.

### 8.4 The `Delete` gap in `server/blob.go`

The operator's `BlobStore` interface has **no `Delete`**, deliberately: retention there is ILM-only. That is insufficient here, because a `MEDIA` body may need removal before its ladder TTL (a group shortens its policy; a blob is orphaned at grant expiry). The message server therefore defines its own interface:

```go
type MessageBlobStore interface {
    server.BlobStore                                    // Put/Get/List/SetLifecycle/Bucket/Prefix/Authority
    Delete(ctx context.Context, key string) error
    DeletePrefix(ctx context.Context, keyPrefix string) (int, error)
    Stat(ctx context.Context, key string) (size int64, err error)   // the chunk-listing resume path
}
```

implemented over `minio-go`'s `RemoveObject`/`RemoveObjects` and over the local filesystem backend for dev. **Both mechanisms run: explicit `Delete` as the fast path, ILM as the floor.** If the sweep never runs for a month, media still expires. If ILM is misconfigured, the sweep still deletes. Neither is trusted alone.

---

## 9. Operator integration

### 9.1 The message server's own URnetwork account

Master spec §4.4: the message server holds its own account, and that credential is a server-side secret.

| Phase | Design |
|---|---|
| **Provision** | The message server holds its account on **one operator, named in configuration as `operator_host`** (`message.yml`, §10.2) and chosen by whoever administers this server from the operators it is compatible with — there is more than one, and two run today (MASTER §4.1). The account credential for that operator is the per-ordinal entry in `message_server.yml`. An admin **of that operator** creates the network once and one `network_client` per **ordinal**. The process reads `MESSAGE_SERVER_ORDINAL` from the environment and selects that keyed entry from `message_server.yml`. Deploy as a **StatefulSet with stable ordinals**, not a Deployment — a per-instance long-lived credential is per-instance state, so §2.3's and §10.1's "stateless replicas" was false and autoscaling was impossible as specified (scaling out requires an operator admin action plus a vault edit). `/readyz` fails if the ordinal has no credential. Bootstrapping order: operator admin action → vault write → deploy. |
| **Rotate** | Issue a second credential for the ordinal, restart the instance, retire the first after the connect session drains. Cadence: 90 days. |
| **Revoke** | The operator admin deletes the `network_client`; the instance's connect session drops; a new signed discovery entry omitting that `client_id` is published. Revocation takes effect only because discovery entries carry `not_after` (§9.3). |
| **Replace** | As Provision, reusing the ordinal. |

Each instance runs a `connect.Client` against the platform transport exactly as any client does: `AddReceiveCallback` dispatches `MessageServerRequest` frames and responses go back through `Send`. Contracts are long-lived per `(device, message server)`, provider-terminated (master §9.6). Clients resolve the fleet from their operator (§9.3), **verify the first `ServerKey.pub` they ever see against the fleet root public key compiled into the SDK** rather than trusting it on first use (§4.3.1), and pin `BlobEndpoint.tls_spki_sha256`.

**The attestation signing key is fleet-wide, not per instance.** `server_id` is stable per fleet and any replica must be able to sign any `FetchAttestation`, so the public `server_keys` set and the sidecar endpoint that signs on their behalf are **fleet-wide** configuration, not the per-instance `message_server.yml` entry. Only `client_id` and the transport credential are per instance. If the key were per instance, a client would see a different `ServerKey` on the first reconnect that landed on a different replica — and §4.3.1 now **refuses** a key that chains to neither a trusted predecessor nor the fleet root, so per-instance keys would not be a warning to click through but an outage.

**The signing private key is not on the replicas.** The fleet's attestation signing key lives in an **HSM or a signing sidecar**; a replica calls it to sign a `FetchAttestation` and never holds the private half. Above it sits the **fleet root key**, which is offline, is used only to certify a signing key (`ServerKey.sig_by_root`, §4.3.1), and whose public half is compiled into every client (Spec A §7.6). The consequences are what make this worth the operational cost:

- Compromising a replica no longer compromises the fleet's pinned identity, because the replica never had it to lose.
- A signing key that *is* compromised is revocable: the offline root certifies a successor, clients accept it silently because it chains, and the old key stops verifying. Under the previous design the only remediation was a rotation that every user saw as a warning byte-for-byte identical to the attack.
- Neither property can be added later. A root that has ever been on a replica is not a root, and a client that shipped without the root pinned cannot be given one retroactively.

The signing sidecar is a hard dependency of the attestation path: `/readyz` fails when it is unreachable, and a replica that cannot sign serves no `FetchAttestation` rather than serving an unsigned one. Rate-limit and audit the sidecar's signing calls; export `message_attestation_sign_failures_total`.

**Nothing in this module may assume one operator.** The client's operator and this server's operator are configured independently and need not be the same; `operator_host` is configuration, never a constant in code, and a CI check greps the module for hardcoded operator hostnames. Where this document says "the operator", it means the one this server holds its account on, and it never means the one a given client is using.

### 9.2 What the operator does, and does not

**An operator does:** mint `ByJwt` for transport and billing; validate network membership; create contracts and route to providers; **set the price of data on its own network**; rate-limit and refuse service at the transport layer; run **its own** discovery directory and **its own** key-transparency log; own account lifecycle including the identity reset of MASTER §5.5; and own push when it exists. There is more than one operator, each runs its own directory and log, and this server gossips the signed tree heads of the operator it holds its account on and of no other (§9.5).

**Does not, normatively:** store message records; hold any `write_key` or any record ciphertext; learn group membership; get consulted on group admission; sign anything that satisfies an MLS proposal or commit validity condition; read blobs; hold the `recovery_handle` index, which exists on the message server alone; nor learn which messaging identity belongs to which paying account, except for identities whose owners have explicitly opted into directory listing. The directory row **is** that link, and no row exists for an unlisted identity (§9.3). This is what makes MASTER §4.2's claim structural: without the row, a compromised operator holds a payment record and a traffic pattern, not a social graph.

Two rules that make this checkable rather than aspirational:

- **The message server MUST NOT call any operator API that would reveal group membership**, and MUST NOT report per-group or per-handle metrics to any operator-side sink. Metrics leaving the process are aggregate only (§11.2).
- **The operator MUST NOT be given read access to the message server's database.** Not "should not" — the credential separation in decision B10 is what makes that enforceable rather than a policy.

### 9.3 Discovery directory (operator side, master spec slice 9)

Two things share the name "discovery" and must not be conflated:

1. **Fleet discovery** — where the message server is. Cacheable:
   `GET /message/servers` → `[{server_id, client_id, signing_pub, blob_endpoint, capabilities, not_before_ms, not_after_ms, sig}]`, each entry signed by that server's own key so the operator cannot substitute an endpoint without detection. In v1 the list has one logical entry with N instances. The signature preimage is:

   ```
   "URmessage/v1/discovery" ‖ LP(server_id) ‖ LP(client_id) ‖ LP(signing_pub)
     ‖ LP(blob_host) ‖ u32(blob_port) ‖ LP(tls_spki_sha256)
     ‖ u64(not_before_ms) ‖ u64(not_after_ms)
   ```

   > Entries carry `not_after` of **at most one hour** and a client MUST refuse an expired entry — that is
   > what makes revocation take effect at all. Previously entries were "unauthenticated, cacheable" with no
   > TTL, no version and no revocation list, so a stale signed entry could be replayed indefinitely.
   >
   > **State plainly:** the entry is signed by the fleet's own `signing_pub`, and on **first** contact the
   > client has never seen that key before. What closes the gap is not this signature but the **fleet root
   > compiled into the SDK**: the client accepts the fleet's key only once it carries a `sig_by_root` that
   > verifies under the root it already holds (§4.3.1), so a substituted endpoint is refused rather than
   > trusted on first use. What remains unauthenticated on first contact is only the operator's *transport*
   > to this list — an operator that withholds the list denies service, which it can do anyway.

2. **Identity discovery** — `principal → identity master key` (master §10.1), the thing the KT log makes auditable.

```sql
CREATE TABLE message_identity (
    principal_id   uuid      NOT NULL,   -- the operator's user/network principal
    identity_pub   bytea     NOT NULL,   -- Ed25519 master identity (master §5.2)
    alg_id         int       NOT NULL,
    version        int       NOT NULL,   -- increments on reset (master §5.5)
    discoverable   boolean   NOT NULL DEFAULT true,    -- see below: a row exists ONLY for
                                                       -- an identity that opted in, so the
                                                       -- column records a later opt-out
                                                       -- rather than an initial state
    kt_leaf_index  bigint    NULL,
    create_time    timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, version),
    CHECK (octet_length(identity_pub) = 32)
);
CREATE INDEX message_identity_current
    ON message_identity (principal_id, version DESC);
```

The searchable alias reuses the operator's existing `search` package (`NewSearchDb("urmessage", SearchTypePrefix)`) rather than a new index, so search behaviour, minimum alias length, and abuse controls match the rest of the platform. **Publication is opt-in, and the opt-in is what creates the row.** No `message_identity` row and no key-transparency leaf is written for an identity until its owner turns listing on. This is stronger than a `discoverable = false` row, which would still be a stored mapping from a paying account to a messaging identity — exactly the link MASTER §4.2 says must not exist without consent. Turning listing off later sets `discoverable = false` and writes a KT leaf recording the change; it does not delete history, because an append-only log has none to delete.

An unlisted identity is reachable by **invite link or direct key exchange**, which always work (MASTER §10.1, Spec A §7.3a). The cost, stated rather than glossed: an unlisted identity has no log leaf, so a key change for it carries no transparency evidence and the client renders it as `kt_unavailable` — a true statement about what is known, not a degradation of a guarantee it never had.

Every write to `message_identity` — including a §5.5 reset — writes a KT leaf in the same transaction. A reset that does not appear in the log has been performed quietly, which §5.5 forbids.

### 9.4 Key-transparency log (operator side)

```sql
CREATE TABLE kt_leaf (
    leaf_index   bigserial NOT NULL,
    vrf_index    bytea     NOT NULL,   -- VRF(operator_vrf_sk, principal) — hides the principal
    vrf_proof    bytea     NOT NULL,   -- 80 B for the suite below; RETURNED in every resolution
    commitment   bytea     NOT NULL,   -- see (b) below
    kt_epoch     bigint    NOT NULL,
    create_time  timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (leaf_index),
    CHECK (octet_length(vrf_index) = 32),
    CHECK (octet_length(commitment) = 32)
);
CREATE UNIQUE INDEX kt_leaf_vrf_epoch ON kt_leaf (vrf_index, kt_epoch);

CREATE TABLE kt_epoch (
    kt_epoch     bigserial NOT NULL,
    root_hash    bytea     NOT NULL,   -- the sparse prefix tree
    prev_root    bytea     NOT NULL,
    history_root bytea     NOT NULL,   -- the CT-style history tree; see (d)
    leaf_count   bigint    NOT NULL,
    sth_sig      bytea     NOT NULL,   -- Ed25519 over the STH preimage in (c)
    sth_time     timestamp NOT NULL DEFAULT now(),
    PRIMARY KEY (kt_epoch)
);

-- (d) the append-only history tree, over the ORDERED sequence of leaf updates.
CREATE TABLE kt_history (
    seq        bigserial NOT NULL,
    kt_epoch   bigint    NOT NULL,
    leaf_index bigint    NOT NULL,
    leaf_hash  bytea     NOT NULL,
    PRIMARY KEY (seq)
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

Structure: a sparse Merkle **prefix tree** indexed by `VRF(operator_vrf_sk, principal)`, which is what yields *absence* proofs — "there is no other key for this principal" — and hides the principal set from anyone enumerating the tree. Inclusion alone does not prevent the operator from later adding a second key; absence proofs are the mechanism that does.

Cadence: a new epoch every 60 s, or on 1,000 pending updates, whichever comes first. `kt_node` is retained for K = 30 days of epochs; clients must audit within that window.

Client obligations (master §10.1): an inclusion proof for every resolution, and gossip of signed tree heads over **two independent paths**.

A schema is not key transparency. A team handed one builds a chain of Merkle roots in Postgres and calls it done. All seven items below are required, at §4.3.4's level of precision.

**(a) VRF.** Suite: **RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI**, suite string `0x04`. Input encoding: `"URmessage/v1/vrf" ‖ LP(principal_id_bytes)`. `kt_leaf.vrf_proof` (80 bytes for this suite) is **returned in every resolution**. Without the proof the client cannot verify that a principal maps to the index it was shown, the operator can place a leaf anywhere it likes, and every absence proof is worthless — which makes this section's own "absence proofs are the mechanism" false.

**(b) Tree arithmetic.** Fixed depth **256**. Path encoding: the `vrf_index` bits, most-significant first.

```
empty_subtree_hash[256] = SHA-256("URmessage/v1/kt/empty")
empty_subtree_hash[d]   = SHA-256(0x00 ‖ empty_subtree_hash[d+1] ‖ empty_subtree_hash[d+1])
leaf_hash               = SHA-256(0x01 ‖ LP(vrf_index) ‖ LP(commitment) ‖ u64(kt_epoch))
internal_hash           = SHA-256(0x00 ‖ LP(left) ‖ LP(right))
commitment              = SHA-256("URmessage/v1/kt/leaf" ‖ LP(principal_id_bytes)
                                  ‖ LP(identity_pub) ‖ u32(version) ‖ LP(salt))   -- salt 32 B
```

**(c) STH preimage**, byte for byte:

```
"URmessage/v1/sth" ‖ u64(kt_epoch) ‖ LP(root_hash) ‖ LP(prev_root)
  ‖ LP(history_root) ‖ u64(leaf_count) ‖ u64(sth_time_ms)
```

**(d) Append-only, which a prefix-tree root chain does not provide.** `kt_epoch` holds a prefix-tree `root_hash` plus `prev_root`; a hash chain of prefix-tree roots proves **continuity, not append-only-ness** — an operator can delete or overwrite a leaf and still emit a valid chain, so §9.5's "verify the consistency proof against the STH it last stored" verifies nothing useful. That is what the **CT-style Merkle history tree** over the ordered sequence of leaf updates (`kt_history`, `kt_epoch.history_root`) is for. **Consistency proofs are defined against `history_root` (RFC 6962 §2.1.2 semantics), not against `root_hash`.**

**(e) Client endpoints.** Four, on the operator; they are slice 9's deliverable:

```
GET /message/kt/sth                          -> the latest signed tree head
GET /message/kt/sth?epoch=<n>                -> a specific STH
GET /message/kt/proof?principal=<p>          -> {vrf_index, vrf_proof, commitment, salt,
                                                 inclusion_path[], kt_epoch, sth}
GET /message/kt/absence?principal=<p>        -> {vrf_index, vrf_proof, absence_path[], kt_epoch, sth}
GET /message/kt/consistency?from=<a>&to=<b>  -> {history_proof[], sth_from, sth_to}
```

Response encoding: protobuf, with the same length-prefix conventions as §4.3.

**(f) The STH signing key.** Named, held in the operator's vault as `kt_sth.yml`, **distinct** from the message server's `server_keys` — clients pin them separately, and conflating them would let a message-server compromise forge log heads.

**(g) Monitor role and incident response.** The auditor is run by the operator's platform on-call, plus a published third-party monitor endpoint before any non-beta user. It checks continuously that every STH is consistent with its predecessor over `history_root` and that no leaf disappears between epochs. When `message_kt_gossip_divergence_total > 0` it pages immediately, and the runbook is: assume operator equivocation, freeze KT-dependent resolutions, publish the two divergent STHs.

### 9.5 The message server as the second gossip path

The second path is this server, and the mechanism is deliberately narrow:

- The message server polls the STH endpoint of **the operator it holds its account on** — `operator_host`, §9.1 — on its own schedule, verifies the signature and the consistency proof against the STH it last stored, and writes it to `message_kt_gossip`. It gossips that operator's log and no other; one operator's signed tree head is never evidence about another's.
- It echoes the latest verified STH in `HelloResponse.kt_gossip`, alongside the `operator_host` it came from, so a client can tell whether it is the log its own resolutions came from. **A client whose operator differs from this server's gets no second path from here** and must find its second gossip path among peer clients; it MUST NOT compare tree heads across two different operators' logs, because divergence between them is the normal case and means nothing.
- **It MUST NOT accept an STH handed to it by a client**, and MUST NOT relay one client's STH to another. Doing either would collapse the two paths into one and hand an equivocating operator a way to launder its own fork.
- A client on the same operator compares the STH it got directly from that operator against the one the message server observed. Divergence at the same `kt_epoch`, **in the same operator's log**, is equivocation, and the client surfaces it as the blocking warning of master §10.2.

**Open item 5** stages the prefix tree behind the log. That is a weakening of master §10.1's "required, not optional" unless it is explicitly time-boxed. It is time-boxed by release rather than by calendar: see ledger open item 5, which makes the live log a gate on general availability.

### 9.6 Abuse response

The message server's only lever against a misbehaving client is a rate limit. It cannot ban: decision B1 forbids an account model, §5.2 means it cannot attribute a record to a device or member, and §9.2 forbids reporting per-group or per-handle information to the operator. The operator *can* refuse service at the transport layer, but only if told which `client_id` — and the only party that knows is normatively restricted to "aggregate only". A sustained campaign therefore had no runbook: the operator saw volume and no cause; the message server saw the cause and may not say. (Distinct from the content moderation deferred in MASTER §15 item 4; this is about keeping the service up.)

**The permitted channel, exactly:** the message server MAY report `client_id` — which the operator already knows, having minted the `ByJwt` and routed the connection — together with a coarse abuse class (`rate`, `storage`, `malformed`) and **nothing else**. No `group_id`, no `sender_handle`, no per-group counts. Everything on §11.1's list remains forbidden. Naming `client_id` as permitted makes the boundary a rule rather than an inference.

**Local lever:** `messagectl quarantine --client <id> --until <t>`, backed by `message_quarantine(client_id bytea PRIMARY KEY, until timestamp NOT NULL, class text NOT NULL)` in the **message-server** cluster, checked at §5.1 check 4. Metric `message_quarantine_active` (gauge).

---

## 10. Deployment, configuration, migrations, backup

### 10.1 Deployment

Container image built from a Dockerfile in the shape of the operator's. Ships:

| Component | Notes |
|---|---|
| `message-server` | N ≥ 2 replicas as a **StatefulSet with stable ordinals** (§9.1), each with its own `client_id`. `terminationGracePeriodSeconds = 90`, matched to the 60 s drain window (§2.3) |
| PostgreSQL | **Separate cluster from the operator** (decision B10). Primary + streaming replica. WAL archiving on |
| Redis | Dedicated instance/database. No persistence. `MONITOR` disabled, slowlog off |
| Object store | MinIO bucket with ILM lifecycle rules per TTL prefix (§8.3) |
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
| `message_server.yml` | vault | per-**ordinal** `client_id` + transport credential (§9.1) |
| `message_fleet.yml` | vault | fleet-wide secrets: `write_key_kek`, `grant_kek`, `channel_key`, **the signing-sidecar endpoint and credential**, and the **fleet root public key** for verification. The signing private key is **not here and not anywhere on a replica** (§9.1) |
| `message.yml` | config | `Capabilities` values, sweep tuning, rate limits, `group_reclaim_seconds`, `read_key_window_seconds` (default 7776000), `durable_ttl_default_seconds` (31536000), `durable_ttl_max_seconds` (0), `group_durable_override`, `operator_host`, `backup_jurisdiction`, and `diagnostic_session_max_minutes` (60) |

**Every value in `Capabilities` is config, never a constant in code.** Changing the blob cap must not require a release, and `CapabilityChange` pushes the new values to connected clients.

> **Reload.** `message.yml` is watched and reloaded atomically. Every reload bumps a monotonic `u64`
> `capability_version`, carried in `HelloResponse.capabilities` and in `CapabilityChange`. Without a reload
> mechanism, "changing the blob cap must not require a release" was false and `CapabilityChange` had no
> trigger.
>
> **Fleet convergence.** The active `capability_version` is stored in a `message_config` table. On load, an
> instance whose version is **lower** than the stored one **refuses readiness**; one whose version is higher
> writes it. A rolling change therefore converges forward and never splits. This matters because
> capabilities are per-replica but their effects are **durable and fleet-wide**: §6.1 step (6) writes
> `LEAST(attachment.media_ttl_seconds, $server_media_cap)` into a durable `message_group` row using *that
> replica's* config, so during any rolling change the retention a group ends up with depends on which
> replica the committer happened to be sticky to — and the client is told `REASON_RETENTION_CLAMPED` and
> renders a permanent notice, making the divergence user-visible. Export `message_capability_version` as a
> gauge and alert on `count(count by (capability_version) (message_capability_version)) > 1`. §7.3 clamping
> is evaluated against the **fleet** version, not the local one.

### 10.3 Migrations

The operator's pattern, in its own database with its own `migration_audit`:

- `store/migrations.go` is an ordered slice of `newSqlMigration` / `newCodeMigration`. Numbering is independent of the operator's 581.
- **Append-only. A landed migration is never edited**, only superseded.
- Index creation on hot tables runs as a **code migration on a raw connection using `CREATE INDEX CONCURRENTLY`**, outside a transaction. This is the operator's standing `FIXME perf` in `db_migrations.go:144`; we are greenfield and should not inherit it.
- Every migration is tested against a database restored from the previous release's schema, in CI. A migration that has only ever run on an empty database has not been tested.
- Rollout order for an additive change: migrate, then deploy. For a destructive change: deploy the version that stops using the column, then migrate. There is no automatic down-migration; reversal is a new forward migration.

> **Every DDL block in this document is labelled with its database.** §3.2 and §9.6 → the **message-server**
> cluster. §9.3 and §9.4 (`message_identity`, `kt_leaf`, `kt_epoch`, `kt_node`, `kt_history`) → the
> **operator** cluster, appended to `server/db_migrations.go`'s list (581 today), in a different repository,
> under a different review process and deploy cadence — the repository §2.2 forbids this module from
> importing at all.
>
> **Cross-repo release order for slice 9:** operator schema → operator STH and proof endpoints →
> message-server gossip client → client KT enforcement. The message server MUST **tolerate the operator
> schema's absence**: the gossip client is disabled, `message_kt_gossip_divergence_total` is not emitted,
> and `/readyz` is unaffected. Without that tolerance the wrong order pages immediately on a metric
> indistinguishable from "the endpoint is not deployed yet".
>
> **Who executes migrations:** a dedicated init job or `messagectl migrate`, **never** N replicas racing at
> startup, holding `pg_advisory_lock(<migration constant>)` for the duration. `/readyz` asserts "migrations
> at head" and fails until the job has run.
>
> **Partitioned-table index procedure:** `CREATE INDEX CONCURRENTLY` is **not supported on a partitioned
> parent**. The procedure is `CREATE INDEX CONCURRENTLY` on each of the 64 partitions, then
> `CREATE INDEX … ON ONLY parent`, then `ALTER INDEX … ATTACH PARTITION` for each — a materially different
> code path from the `newCodeMigration`-on-a-raw-connection form §10.3 previously specified.

### 10.4 Backup, and the three traps

**Nightly encrypted base backup, WAL archived continuously, PITR window 48 hours.** Object store: versioning **off** (contents are ciphertext; versioning would resurrect deleted media), cross-region replication optional.

Three things are required before any user beyond the two beta testers, and none of them is optional for a product that makes deletion claims:

1. **Backups are encrypted at rest**, under a key held in the vault and not in the database backup schedule, on the same footing as the KEK (trap 2).
2. **A stated recovery point objective.** The RPO is **24 hours for the object store** — its state is always "now", so a Postgres restore to T−*n* loses *n* of media regardless of what the database says — and **the WAL archive interval, five minutes, for Postgres**. Published, not inferred.
3. **A named hosting jurisdiction**, written down and surfaced in the client's About screen, because "where is this server" is a question with a legal answer and users are entitled to it before they choose to use it. It is `backup_jurisdiction` in `message.yml` (§10.2).

**The honest consequence, which belongs here and not beside it: a backup is a copy that outlives a delete.** For up to 48 hours after a record is deleted or pruned, the operator of this server can still produce its ciphertext from a point-in-time restore. That window is **the real upper bound on the deletion story** — a number for a transparency report, not a database parameter to tune quietly — and it is why it was cut from seven days to two. MASTER §12.3 and §13 state it to users. Expired disappearing messages are unaffected, for the reason given at the end of this section.

**Trap 1 — a restore silently un-deletes.** A database restored to a point 40 hours ago brings back every body the sweep erased in those 40 hours, every `sender_handle` it zeroed, and every `EPH` row it deleted. **Normative: after any restore, `messagectl sweep-now --until-clean` MUST run to completion before the service accepts traffic.** Startup refuses to serve if the restore marker file is present and the sweep has not run. Without this, disaster recovery quietly becomes a retention violation, and nobody notices because nothing fails.

**Trap 2 — the KEK must not be in the backup.** `write_key_kek` and `grant_kek` live in the vault, are never written to the database, and are backed up on a separate schedule with separate access control. A backup that contains both the wrapped keys and the KEK is equivalent to a backup of the unwrapped keys, and the whole point of decision B9 evaporates. KEK loss is unrecoverable and bricks every group on the server; the escrow requirement is §5.5.

> **Trap 3 — Postgres and the object store cannot be restored to a common point in time.** Postgres has PITR
> over 48 hours; MinIO versioning is (correctly) **off**. Restoring Postgres to T−36h against a live object
> store produces two failure classes `sweep-now --until-clean` does not touch: **dangling references** (rows
> restored from T−36h pointing at blobs the sweep has since deleted — exactly the "row pointing at a deleted
> object" fault §7.4 orders its writes to avoid, reintroduced at scale), and **permanent orphans** (blobs
> uploaded after T−36h with no row after the restore; the orphan reaper is driven by
> `message_blob_expire_grant` and cannot see what has no row).
>
> **Normative:** `messagectl reconcile-blobs` MUST run to completion after any restore, before the service
> accepts traffic, gated by the same restore-marker mechanism as trap 1. It walks the object-store prefix,
> deletes objects with no `message_blob` row, and for rows whose object is missing marks the record erased
> so the client renders "this attachment expired" rather than failing a download.
>
> **RPO, plainly:** object-store state is always "now", so a Postgres PITR to T−*n* loses *n* of media
> regardless of what the database says.
>
> **Drill:** quarterly, exercising restore → `sweep-now --until-clean` → `reconcile-blobs` → readiness, plus
> a KEK-escrow recovery drill (§5.5). A restore target inherits its **own** `postgresql.conf`, so §11.2's
> logging settings and §3.1's `timezone = 'UTC'` MUST be verified on it before it serves traffic. The drill
> also verifies that the restored target's PITR window is **48 hours and not the default seven**, since a
> restore target inherits its own configuration.

**Why backups do not break the disappearing-message guarantee.** A restored `EPH` body is still undecryptable: `eph_root[n]` was never wrapped to a recovery key, never in a provisioning bundle, and is destroyed on every device when its window closes (master §8.1). Master spec §12.1's guarantee is stated in terms of key destruction rather than server deletion **precisely so that it survives backups, replicas, forensic disk images, and operator error.** A deletion-based guarantee would be false the moment WAL archiving was switched on. This is the design's single most load-bearing choice on the storage side, and it should be quoted at anyone who proposes weakening it for convenience.

### 10.5 Rotation runbooks

| What | Procedure |
|---|---|
| **KEK** (`write_key_kek`) | The §5.5 procedure: load both KEKs, unwrap under the row's `kek_id`, bounded background rewrap of every `message_epoch` row holding **either** a `write_key_wrapped` at `epoch = current_epoch` **or** a non-NULL `read_key_wrapped` under the new id, retire the old id only when `message_kek_rewrap_pending` reaches zero. Size the pass off the read keys: ninety days of them dwarf sixty seconds of write keys. Cadence 180 days, or immediately on suspected exposure |
| **`server_keys`** | Mint the successor **in the HSM or signing sidecar**, so no replica ever holds it → sign it with the outgoing key (`ServerKey.sig_by_previous`) → publish both in `HelloResponse` and `CapabilityChange` for one full pin window → switch signing → retire the predecessor. If the outgoing key is compromised or unavailable, bring the **offline fleet root** out instead and certify the successor with `ServerKey.sig_by_root`; clients accept either chain silently and refuse anything that chains to neither (§4.3.1, §9.1) |
| **Instance credential** | §9.1 *Rotate*: second credential for the ordinal, restart, retire the first after the connect session drains. Cadence 90 days |
| **`grant_kek` / `channel_key`** | Same `kek_id` treatment; grants live 15 minutes, so the rollover window is one grant lifetime |

**Operations note: TLS certificate renewals MUST reuse the key pair** so `tls_spki_sha256` is stable and routine renewal does not present every user with a warning indistinguishable from an attack.

---

## 11. Observability and the MUST-NOT-LOG rule

### 11.1 The rule (normative, master spec §9.7)

> The message server MUST NOT create, store, or transmit **per-identity** records of client commands,
> transport connections, or deleted records in production. What it MAY record is **aggregate**:
> counters and histograms with no identifier labels, error *classes*, process lifecycle and
> migration state. A single exception exists, is opt-in, is started by the user, and is bounded:
> §11.5.

This replaces an absolute prohibition, deliberately. The absolute form was aspirational: an on-call engineer meets it during an outage at 3 a.m., cannot see why submits are failing for one customer, and quietly adds a log line that never comes out. A rule that states exactly what is permitted is one an engineer can follow under pressure, and is therefore the stronger privacy position in practice, not the weaker one. The enforcement below is unchanged and applies to the aggregate rule exactly as it applied to the absolute one.

Made operational:

**MUST NOT appear in any log line, metric label, trace span, error string, panic message, core dump, database log, object-store access log, or Redis slowlog:**

`group_id` · `sender_handle` · `record_id` · `stream_index` · `blob_id` · `grant_ref` · `recovery_handle` · `wrap_target_handle` · `client_id` · `network_id` · any IP address · any `ByJwt` · `write_auth` · `req_auth` · `write_key` or `read_key` (wrapped or not) · any KEK · any ciphertext or any prefix of it · any request or response body · any URL path containing a blob key · any `pgconn.PgError` `Detail`, `Hint` or `Where` field · the fact that a particular client fetched a particular range · any record that a record once existed and was deleted.

**MAY appear:** process lifecycle events; migration start/finish and version; aggregate counters and histograms; error *classes* without identifiers; panic type and stack frames. **Go's runtime always prints argument words in a traceback** — `GOTRACEBACK=single` reduces which goroutines print, not what each frame shows, and only `GOTRACEBACK=none` suppresses stacks, at the cost of all crash diagnostics. The mitigation is structural: the §11.2 redact types are opaque structs, so only a pointer and a length appear in registers.

### 11.2 Enforcement, in descending order of reliability

1. **Structural (decision B11).** `GroupId`, `SenderHandle`, `BlobId`, `RecoveryHandle`, `ClientId` in `redact/` are **opaque structs wrapping an unexported `[]byte`** — never a named slice type and never a named array type — whose `String()`, `Format(fmt.State, rune)`, `LogValue()`, `MarshalJSON()`, and `MarshalText()` all return `"<redacted>"`. Access to the bytes is through an explicit `.Unwrap()` used only by the store and crypto layers. **An accidental `%v` cannot leak, because there is nothing to print.**

   This matters beyond style: pgx v5's encode planner consults `driver.Valuer`, `json.Marshaler` and `encoding.TextMarshaler` when a value is not directly handled by the target codec, so a *named type over `[]byte`* passed to a `bytea` parameter can be encoded through its `TextMarshaler` and **write the literal bytes `<redacted>` into the primary key column** — loud on a length-`CHECK`ed column, silent on an unconstrained one. An opaque struct cannot be passed to pgx at all, so the compiler enforces `.Unwrap()` at every store boundary instead of the developer discipline decision B11 exists to eliminate. Add the `store` package to item 2's analyser scope.
2. **Compile-time.** A `go vet`-style analyser in CI fails the build on any format-verb application to a raw `[]byte` field of a record struct, and on any `glog`/`fmt` call taking a value from the store package's row types.
3. **Runtime.** The logging wrapper accepts only a fixed set of pre-approved field constructors. There is no `log.Any`.
4. **Infrastructure.** On the message-server Postgres cluster:

```
log_error_verbosity          = terse    # LOAD-BEARING: drops DETAIL/HINT/CONTEXT lines,
                                        # which is where every forbidden identifier lives
log_min_error_statement      = panic
log_min_messages             = fatal
log_statement                = none
log_min_duration_statement   = -1
log_connections              = off
log_disconnections           = off
log_lock_waits               = off
log_replication_commands     = off
log_parameter_max_length_on_error = 0
auto_explain                 = off      # not loaded
```

   > The four settings previously listed suppress only **successful and slow** statement logging and do
   > nothing to the error path, which is where the identifiers are. `log_min_messages` defaults to
   > `warning`, so every ERROR is written; `log_min_error_statement` defaults to `error`, so the offending
   > SQL goes with it. A unique violation logs
   > `DETAIL: Key (group_id, sender_handle, stream_index)=(\x…, \x…, 42) already exists.` — three forbidden
   > items in one line, on the **normal** idempotent-retry path of §6.3, not an exotic one. A CHECK
   > violation logs `DETAIL: Failing row contains (…)` — the entire row, including `ct_head` and `ct_body`,
   > and §3.2 defines fifteen CHECK constraints that can produce it. `log_connections` /
   > `log_disconnections` are on in most packaged and managed configurations and log the client IP;
   > `log_lock_waits` logs the full statement, and §6.4 *expects* lock contention with `lock_timeout = 3s`.
   >
   > **These MUST be applied identically to the primary, every streaming replica, and any restore or
   > staging target** — a PITR target restored from a base backup inherits its own `postgresql.conf`.
   >
   > **Application rule.** Every `INSERT` in `store/` MUST use `ON CONFLICT`, and every CHECK condition
   > MUST be validated in Go before the statement is issued, so a constraint never fires in production.
   > §6.1 step (5a) is corrected to §3.3 Q3's `ON CONFLICT … DO NOTHING` form; the two sections
   > contradicted each other and the §6.1 form was the one that leaked. The analyser fails the build on
   > `%+v` / `%#v` applied to any error value and on any pgx `tracelog` / `QueryTracer` construction,
   > because `pgconn.PgError` carries `Detail`, `Hint` and `Where` and any of those re-emits the same
   > values into the service's own log.

   Object store access logging off. Redis `slowlog-log-slower-than -1`, `MONITOR` denied by ACL. `GOTRACEBACK=single` and `ulimit -c 0` so a panic does not dump buffers holding plaintext keys to disk. `http.Server.ErrorLog` on `blobd` is set to a discarding logger — Go's default writes `http: TLS handshake error from <IP>:port` to stderr, and an IP address is on §11.1's list. No OpenTelemetry or `otelhttp` instrumentation on `blobd`; if tracing exists anywhere, an explicit span-attribute allow-list. MinIO audit webhook and server request logging **off**; `mc admin trace` is an incident-only action requiring two-person approval.
5. **Test.** An acceptance test (§13) runs a full workload against the service with logs captured, then asserts that no captured byte sequence matches any identifier the test generated. It is the slice-3 acceptance criterion, per master spec §14.

### 11.3 Metrics

Prometheus via `client_golang`, matching the operator. **No metric may carry `group_id`, `sender_handle`, `client_id`, `network_id`, or `blob_id` as a label** — a metrics store with per-group series is a reconstructed membership graph with a nicer query language.

| Metric | Type | Labels |
|---|---|---|
| `message_submit_total` | counter | `result` (accepted, idempotent, rejected, epoch_stale, commit_lost, stream_reused, rate_limited, oversize) |
| `message_commit_cas_total` | counter | `result` (won, lost, idempotent) |
| `message_fetch_records` | histogram | `heads_only` |
| `message_fetch_latency_seconds` | histogram | — |
| `message_submit_latency_seconds` | histogram | — |
| `message_group_lock_wait_seconds` | histogram | — |
| `message_subscriptions_active` | gauge | — |
| `message_push_dropped_total` | counter | `cause` (backpressure, disconnect) |
| `message_prune_rows_total` | counter | `class`, `action` (erase, delete) |
| **`message_prune_lag_seconds`** | gauge | — |
| `message_prune_backlog_rows` | gauge | — |
| `message_blob_bytes_total` | counter | `direction` |
| `message_blob_orphans_reaped_total` | counter | — |
| `message_epoch_key_cache_total` | counter | `result` (hit, miss, negative) |
| `message_group_filter_false_positive_total` | counter | — |
| `message_group_filter_false_negative_total` | counter | — |
| `message_kt_gossip_divergence_total` | counter | — |
| `message_reject_stage_total` | counter | `stage` (the §5.1 check number only, no identifiers) |
| `message_redis_up` | gauge | — |
| `message_ratelimit_failclosed_total` | counter | `limit` |
| `message_transport_attached` | gauge | — |
| `message_transport_reconnect_total` | counter | — |
| `message_contract_state` | gauge | `state` |
| `message_reassembly_inflight` | gauge | — |
| `message_reassembly_bytes` | gauge | — |
| `message_vault_load_failure_total` | counter | — |
| `message_blobstore_errors_total` | counter | `op` |
| `message_internal_total` | counter | — |
| `message_capability_version` | gauge | — |
| `message_kek_rewrap_pending` | gauge | — |
| `message_blob_rows` | gauge | — |
| `message_quarantine_active` | gauge | — |
| `message_drain_duration_seconds` | histogram | — |
| `message_group_closed_total` | counter | — |
| `message_group_reclaimed_total` | counter | — |
| `message_read_keys_retained` | gauge | — |
| `message_read_key_expired_total` | counter | — |
| `message_attestation_sign_failures_total` | counter | — |
| `message_diagnostic_sessions_active` | gauge | — |

`message_reject_stage_total` is deliberately more specific than the wire code: the server has no reason to merge the three causes §4.5 merges *for the client*, and without it an enumeration attack at check 5 is indistinguishable from a client bug at check 7 or a key-cache problem at check 6.

SLOs: submit p99 < 150 ms; fetch p99 < 250 ms for 100 records; `message_prune_lag_seconds` < 3600 (page at 21600); `commit_lost / commit_total` < 1%; `message_kt_gossip_divergence_total` **> 0 pages immediately** — it means the operator equivocated. Page after 5 minutes on `message_redis_up == 0`; page immediately on `message_transport_attached == 0` and on contract or balance exhaustion.

**Capacity and cost note for the message server's own URnetwork account:** if its balance or contract quota is exhausted, messaging stops fleet-wide and presents as a transport outage with no attributable metric. `message_contract_state` exists so that failure has a name before it happens.

### 11.4 Where logs and metrics go

A message-server-**local** sink with a stated retention of 7 days. The operator's central logging stack MUST NOT receive message-server logs. §9.2 forbids reporting per-group or per-handle information to any operator-side sink and was silent on whole-log shipping — which, given one organisation runs both, is exactly the question an ops team gets wrong. Metrics leaving the process are aggregate only and carry no identifier labels (§11.3).

### 11.5 The one exception: a diagnostic session the user starts

A user who is diagnosing a problem can grant this server permission to record detail about **their own** traffic, for a bounded time. Nothing about them is recorded without it.

- The client requests a session; the server mints a 16-byte `session_id`, records it in `message_diagnostic_session` against the caller's `client_id` with an end time of **at most one hour** (`diagnostic_session_max_minutes`, hard-capped in code, not only in config), and returns it.
- While a session is live, the server may retain per-request detail **for that `client_id` only** — check numbers, reason codes, sizes, timings — in a **separate store** with its own seven-day retention, never in the ordinary log sink, and never covering any other client.
- Even inside a session, the forbidden list of §11.1 holds for **content and keys**: no ciphertext, no authenticator, no wrapped or unwrapped key, no blob byte. What a session adds is the ability to attribute an error class to a request, which is exactly what is missing when a user reports "it fails sometimes".
- The session ends at its end time or when the client stops it, whichever is first. A session cannot be started by an operator, by an administrator, or by anyone but the client whose traffic it covers.
- The user can retrieve what was recorded, because a diagnostic record they cannot read is a log they were talked into rather than one they granted.

Metric: `message_diagnostic_sessions_active` (gauge). Acceptance test 31 (§13) asserts that with no session live, a full workload produces no per-identity byte in any sink, and that with one live, the detail appears **only** in the diagnostic store and **only** for the session's client.

---

## 12. Interfaces

### 12.1 What this component requires from spec A

| # | Item | Why it must come from A, not be reimplemented here |
|---|---|---|
| A-1 | **A shared Go package `connect/message`**, whose exported surface is the single table below — the server may use **only** that surface | Two independent implementations of a MAC preimage diverge. When they do, the symptom is "some clients can't send," intermittently, and the cause is a byte-order difference nobody can see. One implementation, linked by both |
| A-2 | **The `server_attachment` encoding** (`EpochAttachment`, `RecoveryTag`, `WrapTag`, `EpochComplete`) and the amended §9.2 preimage — **RULED and adopted**, see §5.4. This spec no longer defines those messages; they are `connect/message` encodings carried opaquely inside `Record.record_bytes` | The server cannot verify the next epoch's write key, the recovery index or the wrap index without it. Format-freezing |
| A-3 | Exact size-bucket byte lengths, including AEAD tag, so §5.1 check 3 can assert equality | Equality is what makes padding real; a range check silently permits an unpadded record |
| A-4 | The eph-bucket → seconds table, with bucket 0 defined as transient | §7.6 depends on bucket 0 never being persisted |
| A-5 | `message.proto` in `connect/protocol`, generated by the existing Makefile | Shared codegen; the server links the generated Go |
| A-6 | The losing-committer contract of §6.2, implemented in `sdk`, bound to **any rejection of a commit submission** and not to `REASON_COMMIT_LOST` alone — especially step 2 (never reuse `pq_secret`) and step 6 (never reuse a consumed `stream_index`) | Both are silent-corruption failures, invisible in functional tests |
| A-7 | Blob padding ladder and `blob_id` derivation — Spec A §5.13, which closes open item 4 | §8.1 |
| A-8 | **A shared interop vector file** `testdata/message-server-vectors.json`: N records with epoch keys, nonces, and the expected verdict for each (accept / reject with reason), plus a commit-race scenario with the expected winner | The single artefact that keeps client and server agreeing. A **blocking CI job in both repos** |
| A-9 | A measurement of the platform transport's production `FramerSettings.MaxMessageLen` (open item 2) | Sizes the inline ladder and the fragmentation budget |
| A-10 | `ComputeRequestAuth` / `VerifyRequestAuth` (§4.3.8), taking the **epoch's** `read_key` — with the epoch named by the request's `read_epoch` field, which is inside `canonical_request_bytes` and therefore inside the MAC — and `RecoveryProof` / `VerifyRecoveryProof` (§4.3.7) | The read path and the seed-only restore path have no authenticator without them. Keying reads to an epoch *write* key would lock out any member offline across a commit for more than sixty seconds; the read key's ninety-day window is what avoids that, and naming the epoch inside the MAC is what lets the server select one key rather than trial ninety days of them |
| A-11 | `expire_at` is unix **milliseconds**, `u64`, big-endian, `0` = unset, on the wire and in both preimages; the shared `connect/message` encoder is the **only** producer of the preimage on both sides and it is never re-derived from the database | A seconds/milliseconds mismatch passes for the common case (`expire_at` unset, value 0) and fails only for the minority that set it — A-1's exact warning, but intermittent |
| A-12 | `blob_id` as a header field of the record, present iff `size_bucket == 5`, inside `AAD_head` and the `write_auth` preimage | §8.3 binds blobs by it and §5.1 check 3 acts on it; **I6** forbids the server acting on an unauthenticated field |

The A-1 surface, in full:

```go
// ── records ────────────────────────────────────────────────────────────────
func ParseRecord(b []byte) (*Record, error)
func EncodeRecord(r *Record) ([]byte, error)
func ParseRecordHeader(b []byte) (*RecordHeader, error)

// ── authenticators ─────────────────────────────────────────────────────────
func WriteAuthPreimage(serverNonce []byte, h *RecordHeader, ctHead []byte,
                       serverAttachment []byte) []byte
func ComputeWriteAuth(writeKey []byte, serverNonce []byte, h *RecordHeader,
                      ctHead []byte, serverAttachment []byte) [32]byte
func VerifyWriteAuth(writeKey []byte, serverNonce []byte, r *Record) bool           // constant time

func RequestAuthPreimage(serverNonce []byte, op uint8, requestBytes []byte) []byte
func ComputeRequestAuth(readKey []byte, serverNonce []byte, op uint8,
                        requestBytes []byte) [32]byte
func VerifyRequestAuth(readKey []byte, serverNonce []byte, op uint8,
                       requestBytes []byte, auth []byte) bool                        // constant time

func RecoveryProof(recoveryRoot []byte, serverNonce []byte,
                   recoveryHandle []byte) ([]byte, error)                            // Ed25519 sig
func VerifyRecoveryProof(recoveryVerifyPub []byte, serverNonce []byte,
                         recoveryHandle []byte, sig []byte) bool

// ── ladders ────────────────────────────────────────────────────────────────
func SizeBucketBytes(b SizeBucket) int          // body bytes EXCLUDING the 16-byte AEAD tag
func SizeBucketCtBodyBytes(b SizeBucket) int    // = SizeBucketBytes(b) + 16
func EphBucketSeconds(bucket uint8) int
func RetentionClassOf(wire byte) (RetentionClass, uint8, error)   // -> class, ephBucket
func RetentionClassWire(c RetentionClass, ephBucket uint8) byte
func ClassIsPrunable(c RetentionClass) bool

// ── server attachment ──────────────────────────────────────────────────────
func ParseServerAttachment(b []byte) (*ServerAttachment, error)
func EncodeServerAttachment(a *ServerAttachment) ([]byte, error)

// ── exported types ─────────────────────────────────────────────────────────
type Record, RecordHeader, RetentionClass, SizeBucket,
     ServerAttachment, EpochAttachment, RecoveryTag, WrapTag, EpochComplete
```

The server may use **only** this surface. It gets no decryption function, no key-schedule function, and no MLS type. A test in the message-server repo asserts the allowlist.

### 12.2 What this component exposes to spec C (through `sdk`, never directly)

Spec C never opens a socket to the message server. Everything below reaches C through `URmessageSdk.dll`.

| # | Surface | What C must do with it |
|---|---|---|
| C-1 | `MaxBlobBytes` from A's `ServerInfo()` — C never speaks to B, so it never sees raw `Capabilities` | Show the cap and enforce it **before** the file picker, not after a 400 MB read |
| C-2 | The three advertised limits — `max_blob_bytes`, `media_ttl_*`, `durable_ttl_*` with `durable_retention_min_seconds` and `group_durable_override` — and `REASON_RETENTION_CLAMPED`, surfaced through `RetentionApplied` | Render the one-time in-group notice when a policy is clamped **down** *or* floored **up** (§7.3), naming the **effective** value, never the requested one. Where `group_durable_override` is false, say so rather than offering a text-retention control that does nothing |
| C-3 | Blob grant + resumable chunk upload | Progress UI that survives a disconnect and resumes; the mask makes this exact rather than approximate |
| C-4 | `FetchAttestation` and gapless `record_id` | Pin attestations covering the high-water range; warn when a later-learned record falls inside a covering attestation that omitted it (master §9.4); treat an id gap as a fault. A `complete = false` response is **normal** and MUST NOT be treated as a hole; compare attestations only within an identical `(class_mask, heads_only)` filter |
| C-5 | The `Reason` enum | Map to user-facing strings. `REASON_REJECTED` maps to a generic failure — C must not invent a more specific message, since the server deliberately did not distinguish (§4.5) |
| C-6 | `Backpressure` push | Re-subscribe from the client's own high-water. **Never** treat a drop as "nothing new" |
| C-7 | Reconnect semantics | Resubscribe with `since_record_id`; the server replays. There is no cross-connection subscription state |
| C-8 | Honest-limits copy | Master §12.3: a server that silently withholds a deletion is not detectable in v1. §12.4's required UI language is normative and must not be softened |
| C-9 | Server key verification | The **first** `ServerKey` this fleet ever presents is verified against the fleet root public key compiled into the SDK (`ServerKey.sig_by_root`), not trusted on first use. `BlobEndpoint.tls_spki_sha256` is still pinned on first contact |
| C-10 | `ServerKey` rotation | A change carrying a valid `sig_by_previous` chaining from a trusted key, or a valid `sig_by_root`, is accepted **silently** and written to the client's inspectable security log. A key chaining to neither is **refused** — the client does not connect and offers no way to accept it. There is no modal and no accept path (§4.3.1) |

---

## 13. Test and acceptance criteria (slice 3)

Master spec §14 makes §9.7 an acceptance criterion for this slice. Concretely, slice 3 is done when all of the following pass in CI on every commit:

1. **Interop vectors.** The shared file `testdata/message-server-vectors.json` (A-8) passes in both directions — the server produces the expected verdict for every record, and the client produces records the server accepts — as a **blocking CI job in both repos**, `connect` and `message-server`.
2. **Commit-race property test.** *k* concurrent committers at the same epoch against a real Postgres: exactly one wins; every loser receives the winner's exact bytes; the group's `current_epoch` advances by exactly one; the losing epoch's `write_key` was never installed. Run at k ∈ {2, 8, 64} with randomized delays, 1,000 iterations.
3. **Idempotency.** Every submit replayed 3× yields one row and `REASON_OK` each time; a differing record at the same `stream_index` yields `REASON_STREAM_INDEX_REUSED`.
4. **Prune index invariant.** After a full sweep, `SELECT count(*) FROM message_record WHERE prune_after IS NOT NULL AND prune_after <= now()` is 0, and `pg_relation_size('message_record_prune')` has not grown across a 100k-record fixture. Guards §3.3.
5. **Retention matrix.** One record per class; advance a fake clock; assert the §7.2 table exactly — including that `EPH(0)` never produced a row, that a pruned `MEDIA` retained its head and `body_hash`, that an expired `EPH(1..5)` left its ~60-byte placeholder row, and that the `PERMANENT` blob and its row both survive.
6. **Restore trap.** Restore a backup taken before a prune; assert the service refuses traffic until `sweep-now --until-clean` completes. Guards §10.4 trap 1.
7. **No-log acceptance.** Full workload with logs, metrics, traces, database log, Redis log, and object-store log captured; assert no generated identifier appears in any byte of any of them. Guards §9.7 and §11.
8. **No-MLS assertion.** `go list -deps ./... | grep connect/mls` is empty. Guards §5.3.
9. **Dependency deny-list.** §2.2's `go list -deps` gate.
10. **DoS ordering.** 10^5 submits with invalid `write_auth` against random group ids produce zero rows in `pg_stat_statements` beyond the epoch-key negative-cache reads. Guards §5.1's check order.
11. **Migration-on-populated-database.** Every migration applied to a database restored from the previous release's schema with representative data.
12. **`record_id` starts at 1.** Create a group, fetch with `since_record_id = 0`, assert the initial commit is returned, and assert a `CreateGroupRequest` whose initial commit carries an attachment for any epoch but 1 is refused.
13. **Batch atomicity.** A 5-record batch whose third record regresses its stream index leaves `next_record_id` unchanged and writes zero rows.
14. **Idempotent retry.** A submit that landed, replayed after a timeout at an epoch that has since advanced, returns `REASON_OK` — not `STREAM_INDEX_REGRESSED` and not `EPOCH_STALE`.
15. **EPH gaplessness.** After an `EPH` sweep, `count(*) WHERE group_id = $1` is unchanged and `max(record_id) - min(record_id) + 1 == count(*)`.
16. **Epoch-key update is bounded.** A commit at epoch 10,000 touches the same number of `message_epoch` rows as a commit at epoch 2.
17. **Blob class match and the permanent rung.** Bind an `eph/ttl-1h`-rung blob to a `MEDIA` record; assert rejection. Create one blob per class — including `DURABLE` in **both** variants, with and without a group TTL — assert the object key's rung for each, and assert **no ILM rule matches the `perm/` prefix**.
18. **Response byte bound.** Fetch 512 records at `size_bucket 4`; assert the response is byte-bounded, `complete = false`, and resumable from `next_record_id`.
19. **Redaction round-trip.** Insert and read back every identifier type through the real store layer; assert no column anywhere in the schema contains the byte sequence `<redacted>` and every length CHECK holds.
20. **Redaction under hostile logging.** Run the full workload with `log_min_messages = debug1` deliberately and assert the guarantee still holds at the application layer, so it does not rest solely on cluster config an ops change can silently revert.
21. **UTC assertion.** `/readyz` fails on a cluster whose `timezone` is not UTC.
22. **Restore reconcile.** Extend item 6 to cover `reconcile-blobs`, not only the sweep.
23. **Group-filter false negative.** Create a group on instance A, reconnect to instance B, submit; assert `REASON_OK` rather than the undiagnosable `REASON_REJECTED` the timer-only refresh produced.
24. **Unauthenticated read.** A `FetchRequest` against a known `group_id` with no `req_auth` returns `REASON_REJECTED`.
25. **Recovery proof.** A `RecoveryFetchRequest` whose proof is under a different `recovery_root` is refused; a second `RecoveryTag` presenting a different `verify_pub` for a known handle is refused.
26. **Epoch publication.** A commit followed by an incomplete wrap fan-out leaves `epoch_complete = false` and rejects an ordinary submit with `REASON_EPOCH_INCOMPLETE`; the `EpochComplete` marker clears it.
27. **`expire_at` units and direction.** The shared interop vector file carries at least one record with a **non-zero** `expire_at`, so a seconds/milliseconds mismatch cannot pass by defaulting to 0. Separately: a `DURABLE` record with `expire_at` one hour out is pruned at one hour, not at the class deadline; a `MEDIA` record with `expire_at = 2999` is pruned at the class deadline, not at `expire_at`.
28. **Encoding guard.** A blocking job fails the build on any occurrence, in `docs/**/*.md`, of the four byte runs that double-encoded UTF-8 produces — the sequences U+00E2 U+20AC, U+00C2 U+00A7, U+00C3 U+00A2 and U+00C3 U+201A — and asserts that `.gitattributes` contains the line `*.md text working-tree-encoding=UTF-8 eol=lf`. The check is expressed by codepoint, never as literal corrupted text, so it does not fail on its own source.
29. **Catch-up after missed epochs.** A client that has missed 5 epochs reconnects, calls `GroupStatus`, `Fetch` and `WrapFetch` with a `req_auth` computed under the read key of the newest epoch it holds and a matching `read_epoch`, and succeeds on all three. Assert also that a commit whose `EpochAttachment` carries a **different** `read_key` from the previous epoch's is **accepted** and installs that key against the epoch it opens — the previous behaviour, refusing a changed read key, is now exactly backwards.
30. **Every authorized read is authorized, and only inside the window.** For each of the five op bytes 13, 14, 16, 17 and 19: the request with a correct `req_auth` and matching `read_epoch` succeeds; the same request with the MAC computed under another group's read key, under an epoch `write_key`, under a different epoch's read key, or with the wrong op byte, is refused with `REASON_REJECTED` and the same padded latency. Then advance a fake clock past `read_key_window_seconds`, run the tidy loop, and assert the same request is now refused identically, and that `GroupStatus` under a still-retained epoch reports `oldest_read_epoch` correctly.
31. **Aggregate-only logging, with and without a diagnostic session.** The §11.1 workload assertion runs twice: with no session live, no generated identifier appears in any sink; with a session live for one client, per-request detail appears **only** in the diagnostic store, **only** for that `client_id`, and disappears from acceptance at the session's end time. Guards §11.5.
32. **Expired ephemerals keep no sender.** After an `EPH` sweep, every expired row has a `sender_handle` of sixteen zero bytes, its `message_stream_claim` row is gone, `record_id` remains gapless, and a replay at that `stream_index` is still refused with `REASON_STREAM_INDEX_REGRESSED`. Guards §7.2 and decision B15.
33. **Text retention is bounded on both sides.** With `durable_ttl_max_seconds` set, a group asking for indefinite text retention is clamped to the cap and told so via `RetentionApplied` with `durable_clamped_down` true; with the cap at 0, the same request stores `NULL`. Guards §7.3.
34. **Read keys expire and write keys still expire faster.** Assert the two tidy statements are independent: after 61 seconds a write key is NULL and its read key is not; after 90 days the read key is NULL. Guards §5.3 and §7.4.
35. **No signing key on a replica.** Assert the process holds no attestation signing private key in memory or configuration, that every signature is produced through the sidecar, and that `/readyz` fails when the sidecar is unreachable. Guards §9.1 and decision B13.
36. **PITR window is 48 hours.** Assert the configured and restored-target retention of the WAL archive is 48 hours, and that the restore drill's marker gate refuses traffic until both `sweep-now --until-clean` and `reconcile-blobs` have completed. Guards §10.4.

---

## 14. Deferred to V2, with the reason

| Item | Reason |
|---|---|
| Multi-server, read-through proxy | Master spec §2/T2. `server_id` fields are carried in `Capabilities` and `FetchAttestation` so it is not a format break |
| Group migration between hosts | Master spec T3. Consequence stated plainly in §13: lose the server, lose the groups |
| Client-initiated server-side erase | Decision B6 — gated on per-device write capabilities, which §9.2 already defers for the same reason |
| Per-device write capabilities | Master spec §9.2. Would also enable spam attribution to a device and own-stream erase |
| Stream digests (detectable withholding) | Master spec T8/§12.3. Partially mitigated in v1 by gapless `record_id` and `FetchAttestation`, not closed |
| Push (WNS/APNs/FCM) | Ledger open item 2. `presence` in Redis and a reserved `push_token` field are the only v1 hooks |
| Public groups, history export, editing, voice/video | Master spec §2 |
| Per-group storage quotas beyond a flat blob cap | Needs real usage data first; `message_group_usage` exists to collect it. The `blob_quota_bytes` column is dropped until then (§3.2) |
| Per-member delivery receipts **shipped in v1** | Removed from this list. A device emits an `EPH(0)` receipt when it decrypts; the server fans it out on the transient channel of §7.6 and stores nothing. The `delivered` state is Spec A §7.4 |
| Asymmetric per-epoch write proof | §5.3 — removes the server's forgery capability at one signature per record |
| Grant proof-of-possession | §8.2 — the v1 grant is bearer-only for 15 minutes and says so |
| Per-instance signing keys under a fleet root | Still V2. What v1 **does** ship is the fleet root itself, offline, with the signing key in an HSM or sidecar and never on a replica (§9.1, decision B13) — which is what makes per-instance keys an optimisation later rather than a prerequisite |
| A wrap-sized rung on the size ladder | Wraps are ~1.2 KB and pad to the 4 KiB rung, which is most of the 6.9 MB epoch bundle (§3.5). A new rung is a wire change to a ladder restated in three documents and enforced as an equality by §5.1 check 3 — worth doing deliberately in V2, not as a size optimisation in v1 |
