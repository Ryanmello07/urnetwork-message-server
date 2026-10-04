# URmessage spec review â€” consolidated edit list

Merged from 47 raw findings into 44 distinct edits. Every item is grouped by the document whose text must change. Items marked **CROSS** require simultaneous edits in two or more documents and are broken out in Â§4 â€” they are the ones that get half-fixed.

Nothing here is invented; every edit traces to a finding in the review.

---

## 1. BLOCKERS by spec

### Spec A â€” none standalone
Spec A has no blocker that can be fixed inside Spec A alone. Both A-side blockers are cross-cutting (Â§4, X-1 and X-2) and must be edited in the same commit as Spec B.

### MASTER â€” none standalone
MASTER's two defects (Â§9.2 `write_key` custody, Â§8.2 epoch-bundle storage) are cross-cutting (Â§4, X-2 and X-3).

### Spec B â€” 10 blockers

Fix in this order; B-1 and B-2 unblock the Â§6 rewrite that B-5 and B-6 also touch.

**B-1 â€” Epoch bootstrap is off by one; every group bricks or freezes at creation.**
Â§4.3.2, Â§6.1 steps 2/5. Â§4.3.2 supplies only `epoch0` carrying `write_key[0]` plus an `initial_commit` at epoch 0; Â§6.1's steady-state rule then yields either `current_epoch = 1` with no key installed, or a group that can never advance.
*Edit:* State normatively that `CreateGroupRequest` carries **both** `bootstrap_write_key = write_key[0]` (used only to verify `initial_commit` â€” self-certification, protected solely by the 20/day rate limit; say so in the text) **and** `epoch0` = an `EpochAttachment` carrying `write_key[1]`. The CreateGroup transaction inserts `message_group{current_epoch = 1, next_record_id = â€¦}` and both epoch rows.

**B-2 â€” Â§7.2's EPH(1..5) row deletion destroys the gapless `record_id` property.**
Contradicts Â§4.3.4's withholding-detection claim, Â§14's T8 mitigation, and C-4's normative "treat an id gap as a fault." Every expiring message manufactures a permanent false fault.
*Edit:* The sweep MUST NOT delete an EPH row. Change Â§7.2's EPH(1..5) action to: `ct_body = NULL`, blob deleted, `ct_head = NULL`, `body_hash` zeroed, new column `pruned boolean NOT NULL DEFAULT false` set true. The ~60-byte row survives as an id placeholder. Fetch returns placeholders with `size_bucket` intact so the client can distinguish pruned from withheld.

**B-3 â€” No authenticator exists for the read path; any `ByJwt` holder who learns a `group_id` reads the whole group.**
Â§4.3.4, Â§4.3.5, Â§4.3.6, Â§5. `FetchRequest` and `SubscribeRequest` carry no authenticator at all; Â§5 specifies verification for submit only.
*Edit:* Define `req_auth = MAC(write_key[current], "URmessage/v1/req" â€– LP(server_nonce) â€– u8(op) â€– LP(canonical_request_bytes))`. Add it to the request envelope; require it on Fetch, Subscribe, BlobGrant, GroupStatus and RecoveryFetch; extend Â§5.1 to cover the read path (checks 2, 4, 5, 6, 7). Land in the same amendment as open item 1.

**B-4 â€” The recovery-fetch proof is unverifiable by construction.**
Â§4.3.7. Specified as a MAC under a `recovery_root`-derived key; the server holds only `recovery_handle = HKDF-Expand(recovery_root, "idx/v1", 16)` and must never hold `recovery_root`.
*Edit:* Make it asymmetric. `recovery_sig_sk = HKDF-Expand(recovery_root, "idxsig/v1", 32)` â†’ Ed25519. The archive record's `RecoveryTag` (covered by `write_auth`) carries `{recovery_handle, recovery_verify_pub, alg_id}`. Add `message_recovery(recovery_handle bytea PRIMARY KEY, verify_pub bytea NOT NULL, â€¦)`; the proof becomes a signature over the connection's `server_nonce`.

**B-5 â€” The losing committer gets EPOCH_STALE, so Â§6.2's mandatory loser protocol never fires.**
Â§6.1 steps 1â€“2, Â§6.2, Â§6.4, Â§13 test 2. The step-(1) row lock serialises committers, so the loser hits the step-(2) epoch gate and rolls back before step (4b)'s `ON CONFLICT` can fire.
*Edit:* Make the epoch gate commit-aware. In Â§6.1 step (2): if `record.is_commit` and a commit row exists at `(group_id, record.epoch)`, return `REASON_COMMIT_LOST{current_epoch, winning_commit}` regardless of how far `current_epoch` has advanced; only a **non-commit** record at a stale epoch returns EPOCH_STALE. Set `winning_commit` on every rejection of a commit.

**B-6 â€” The idempotent-retry probe is ordered after the two gates that reject every retry.**
Â§6.1 steps 2â€“3, Â§6.3, Â§13 test 3. A genuine retry is by definition at a consumed `stream_index` and often at an advanced epoch, so it dies at step (2) or step (3) and never reaches step (4)'s unique violation.
*Edit:* Hoist the probe to the top of the transaction, before both gates: `SELECT record_id, body_hash, ct_head FROM message_record WHERE group_id=$1 AND sender_handle=$2 AND stream_index=$3`. Both `body_hash` and `H(ct_head)` match â†’ COMMIT with no allocation, return `REASON_OK{record_id}`; present and differing â†’ REASON_STREAM_REGRESSED. Delete the parenthetical in step (3).

**B-7 â€” The MUST-NOT-LOG rule is not implementable with the four Postgres settings listed.**
Â§11.2 item 4, with Â§6.1 step (4a) and Â§13 test 7. `log_statement=none`, `log_min_duration_statement=-1` and `auto_explain off` suppress only successful/slow statements. `log_min_messages` defaults to `warning` and `log_min_error_statement` to `error`, so every ERROR â€” including the unique-violation path that carries the failing row â€” is written with its identifiers.
*Edit:* Replace item 4's Postgres line with a normative settings block: `log_error_verbosity = terse` (load-bearing: drops DETAIL/HINT/CONTEXT), `log_min_error_statement = panic`, `log_min_messages = fatal`, `log_connections = off`, plus the existing four. Add the application rule that no pgx error may be logged verbatim â€” errors are mapped to a reason code before any log call â€” and make Â§13 test 7 assert against a real forced unique violation.

**B-8 â€” The key-transparency log is named and schema'd but not buildable.**
Â§9.4, Â§9.5. Missing: (a) VRF suite â€” `vrf_index bytea -- VRF(operator_vrf_sk, principal)` names no algorithm, no suite id, no input encoding; (b) the VRF proof is neither stored nor served; (c) no leaf/internal/empty-subtree hash definitions, depth, or path encoding; (d) no signed tree head format or gossip/consistency-proof procedure.
*Edit:* Expand Â§9.4 to Â§4.3.4's level of precision. Minimum: name RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI and add `vrf_proof bytea NOT NULL` to `kt_leaf`, returned on every resolution; define leaf-hash, internal-hash, empty-subtree-hash, depth and path encoding with explicit domain-separation labels; specify the signed tree head, the inclusion and consistency proof formats, and the gossip procedure.

**B-9 â€” The KEK has no lifecycle, and the schema forecloses rotation.**
Â§5.3 (forward-reference to a Â§10.4 procedure that does not exist), Â§10.4, migration 002. `write_key_wrapped` is `CHECK (octet_length(...) = 60)` with no key-id byte, so no row can indicate which KEK wrapped it.
*Edit:* (a) Change `write_key_wrapped` to `u8(kek_id) â€– nonce(12) â€– ct(32) â€– tag(16)` = 61 B and relax the CHECK â€” **before migration 002 lands**. (b) Write Â§10.5 "KEK rotation": load both KEKs; unwrap under the row's `kek_id`; rewrap all rows at `epoch = current_epoch` under the new id in a bounded background pass; retire the old KEK only when no row references it. (c) Keep Â§10.4's "KEK is not in the backup" rule and cross-reference it.

**B-10 â€” A PERMANENT-class blob cannot be stored, and a stored one is silently deleted by ILM; blob class is never reconciled at bind.**
Â§4.3.6, Â§8.3, Â§7.2. Â§3.1 caps inline bodies at 64 KiB, so MASTER Â§8.2's ~300 KB ratchet-tree snapshot â€” a PERMANENT record â€” must be a blob; Â§4.3.6 admits only MEDIA or the parent's EPH class. Separately, binding checks only `state == COMPLETE`, so a client may grant at `eph/ttl-1h` and bind to a MEDIA or PERMANENT record, and ILM deletes the object an hour later.
*Edit:* (a) Permit `PERMANENT` in `BlobGrantRequest.retention_class`. (b) Add a `perm/` object-key prefix carrying **no** lifecycle rule â€” `<prefix>/<env>/msg/perm/<hex(blob_id)>` â€” and state normatively that `SetLifecycle` MUST NOT install a rule matching it; add a startup assertion that reads back the bucket ILM config and refuses to serve if a matching rule exists. (c) At bind time require `record.retention_class == blob.retention_class`, else REASON_REJECTED; require the record's computed `prune_after` to be no later than the object key's rung, else server-side copy to the correct rung before `BOUND`. (d) Add both cases to Â§13's retention matrix.

---

## 2. MAJOR by spec

### Spec A â€” none standalone (see Â§4, X-2/X-3/X-4)

### Spec B â€” 25

**Concurrency / correctness**

1. **B9 destroys superseded `write_key`s, making REASON_EPOCH_STALE unreachable** (Â§5.1 check 6, B9/Â§5.3 vs Â§4.3.3, Â§6.1 step 2). The commonest benign race returns an undiagnosable REJECTED. *Edit:* add `retire_time timestamp NULL` to `message_epoch`; step (5) sets `retire_time = now()` instead of NULLing; NULL `write_key_wrapped WHERE retire_time < now() - interval '60 seconds'` in Â§7.4's existing 5-minute loop; verify a stale record's MAC under the retired key so the correct reason can be returned.
2. **Batch atomicity vs gapless `record_id` is unspecified** (Â§6.1 step 1, Â§4.3.3). Positional `SubmitResult` implies partial acceptance; the pre-allocated block then exceeds rows written and punches a permanent hole. *Edit:* make the batch all-or-nothing. Run every per-record check â€” including the hoisted probe from B-6 â€” before allocation; compute exact accepted count `k`; allocate `k`; insert. Any in-transaction rejection rolls the whole batch back with zero rows written.
3. **`Record` has no `record_id` field** (Â§4.3.3, Â§4.3.4, Â§4.3.5, Â§4.4). Hole detection, resume and `RecordPush` contiguity all have nothing to reference. *Edit:* add `uint64 record_id = 14` â€” server-assigned, ignored on submit, absent from the `write_auth` preimage and both AADs (already so per MASTER Â§8). Â§4.4 step 4, Â§4.3.5's contiguity claim and C-4 then become mechanical.
4. **`next_record_id DEFAULT 0` vs exclusive `since_record_id`** (migration 001 vs Â§4.3.4) â€” record 0, the initial commit, is permanently unfetchable by anyone who did not create the group, and the failure is silent. *Edit:* `next_record_id bigint NOT NULL DEFAULT 1` with `CHECK (1 <= next_record_id)`; add to Â§4.3.4: "`record_id` values begin at 1; `since_record_id = 0` returns the group from its first record"; add the cold-start case to Â§13's interop vectors. (Two findings merged.)
5. **`server_nonce` is never rotated** (Â§4.3.1, Â§5.1 check 2, vs A Â§12.1 S8/S9) â€” a static replay window for the whole session. *Edit:* add `uint32 server_nonce_lifetime_seconds` to `Capabilities`; deliver replacements on `CapabilityChange`; accept the current **and** immediately previous nonce for one further lifetime; add a Â§13 rotation case.
6. **The known-group cuckoo filter has no insert path** (Â§5.1 check 5, Â§2.4) â€” create-group â†’ reconnect â†’ send fails undiagnosably until an unstated timer fires. *Edit:* publish an add over a dedicated Redis channel from CreateGroup's after-commit hook (Â§6.1 step 7 is the existing pattern); every instance inserts on receipt; the creating instance inserts locally before responding; state the 60 s timer as a backstop only; add `message_group_filter_false_negative_total`.

**Schema / retention / performance**

7. **Â§6.1 step 5 rewrites every historical epoch row on every commit, inside the group's serialising lock.** *Edit:* append `AND write_key_wrapped IS NOT NULL`, bounding it to one row (two with the retirement grace). Add as Q10 in Â§3.3 flagged load-bearing; add a Â§13 assertion that a commit at epoch 10,000 touches the same number of rows as a commit at epoch 2.
8. **Partitioning is not a config switch and the shipped table is unusable.** (Â§3.2 003/004, Â§3.4, Â§10.3 â€” two findings merged.) Migration 003 declares `PARTITION BY HASH (group_id)` with every `PARTITION OF` commented out, so every INSERT fails; and converting a populated table later is a full offline rewrite of the largest table in the system. *Edit:* partition from day one â€” create all 64 partitions unconditionally in 003 (free on an empty table; both unique indexes already include `group_id`). Delete the "config switch, default off for v1" framing and the 10^8-row trigger.
9. **`class_mask` has no index and no Â§3.3 row** (Â§4.3.4, Â§3.3) â€” a joining device or seed-only restorer full-scans a million-row group per fetch page. *Edit:* `CREATE INDEX message_record_class ON message_record (group_id, retention_class, record_id)` plus a Q10 rationale row; if judged too expensive, delete `class_mask` from the API rather than shipping an uncosted plan.
10. **A retention-policy change never reaches stored records** (Â§7.1, Â§8.4, Â§6.1 step 5). *Edit:* add `policy_version int NOT NULL DEFAULT 0` to `message_group`, bump in step (5), stamp at admission; give Â§7.4's loop a bounded rework pass `UPDATE message_record SET prune_after = create_time + $newttl, policy_version = $v WHERE group_id=$1 AND retention_class=2 AND policy_version < $v â€¦`.
11. **`expire_at` is never swept, contradicting MASTER Â§9.1 and A Â§12.1 S10** (B5, Â§7.1). B5's justification argues only against *extending* retention. *Edit:* `prune_after = LEAST(class_deadline, expire_at)`, ignoring `expire_at` when NULL, zero, or later than the class deadline. Rewrite B5's text to the true invariant: "`expire_at` may only shorten retention, never extend it." Add a Â§13 retention-matrix case.
12. **`FetchResponse` has no byte budget** (Â§4.3.4, Â§4.3.1). 512 records Ã— 64 KiB â‰ˆ 32 MB against a 128 KiB reassembly budget. *Edit:* add `Capabilities.max_response_bytes` (suggest 1 MiB); truncate on whichever of count or bytes binds first, always returning `complete = false` and a resumable `next_record_id`; require the store layer to stream and stop at the budget rather than loading then trimming.
13. **`max_records_per_submit` and `max_request_bytes` are mutually inconsistent** (Â§4.3.1, Â§4.6) â€” 64 records Ã— 64 KiB â‰ˆ 4 MiB vs a 131072-byte working cap; a client obeying the advertised contract builds an unrejectable-until-late request. *Edit:* state normatively that a submit must satisfy **both** and that `max_request_bytes` governs; better, replace `max_records_per_submit` with `max_submit_bytes`. Propagate to Â§12.2 as a new C-item.
14. **`timestamp` columns store local time** (Â§3.1, Â§7.1, Â§7.4). `now()` is `timestamptz`; assigning to `timestamp` casts through the session `TimeZone`, and retention straddles two clocks. *Edit:* require `timezone = 'UTC'` in `postgresql.conf` on primary, replicas and every restore target; set `RuntimeParams["timezone"] = "UTC"` in the pgx pool config; add a `/readyz` startup assertion comparing `SELECT now()::timestamp` against UTC.
15. **`closed` and `blob_quota_bytes` are defined and never used** (Â§3.2, Â§7.2, Â§14) â€” no writer, no meaning, no enforcement, and `blob_quota_bytes` is NOT NULL with no DEFAULT so the CreateGroup INSERT has no value to supply. Together the operator has no lever over storage growth. *Edit:* define who sets `closed`, when, and what happens to a closed group's storage in Â§7.2; and either drop `blob_quota_bytes` until V2 (Â§14 already says `message_group_usage` collects the data first) or give it `NOT NULL DEFAULT 0 CHECK (0 <= blob_quota_bytes)` meaning "0 = server-wide default". (Two findings merged.)

**Blob plane**

16. **Chunk assembly cannot work at the specified chunk size** (Â§8.3 step 4, Â§4.3.1 `blob_chunk_bytes = 262144`). S3/MinIO compose is multipart copy; every source but the last must be â‰¥ 5 MiB, so a 100 MB blob at 256 KiB fails with EntityTooSmall â€” every multi-chunk attachment. *Edit:* preferred â€” drop object-per-chunk and use a real multipart upload (`NewMultipartUpload` at grant time, store the upload id, chunks become parts). Alternative â€” raise `blob_chunk_bytes` to â‰¥ 5 MiB and add `CHECK (chunk_bytes >= 5242880)` to `message_blob`.
17. **Blob GC for BOUND blobs is unreachable and the crash-safety argument is false** (migration 006, Â§7.2, Â§7.4, Â§8.3). `message_blob_prune` is never queried; the orphan reaper's `state <> 2` excludes every bound blob; and objects are deleted *after* the commit that NULLed `prune_after`, so a crash loses the only pointer. *Edit:* make `message_blob.prune_after` the authority and the queue â€” the record sweep sets it to `now()` in the same transaction instead of deleting inline; add a second loop `SELECT blob_id, object_key FROM message_blob WHERE prune_after <= now() ORDER BY prune_after FOR UPDATE SKIP LOCKED LIMIT 500`, delete objects, then delete rows.
18. **The grant token's `client_id` binding is unenforceable** (Â§8.2, Â§4.1) â€” the bulk endpoint is reached over ordinary TLS with `Authorization: Bearer <grant>` and no client authentication, so it cannot learn the caller's `client_id`; the stated anti-replay property does not exist. *Edit:* `grant_pop_key = HKDF-Expand(grant_kek, "pop/v1" â€– LP(blob_id) â€– LP(client_id), 32)`, returned over the authenticated control plane; require `X-URmsg-PoP: MAC(grant_pop_key, method â€– path â€– u32(chunk_index) â€– u64(unix_minute))` on every bulk request.
19. **`blob_id` in the URL path contradicts Â§4.1's own argument and Â§11.1's own rule** (Â§8.3, Â§10.1, Â§11.1). Paths are logged by every ingress, L7 LB and CDN. *Edit:* mint an opaque per-grant path component inside the grant AEAD â€” `{path_prefix}/b/{grant_ref}/{chunk_index}`, `grant_ref` = 16 random bytes â€” so a captured path is meaningless and unlinkable across grants. Add to Â§10.1: `blobd` terminates TLS itself, no L7 proxy or CDN in front.

**Protocol / evidence**

20. **The fetch attestation does not cover the filter** (Â§4.3.4). An attestation over a `class_mask = PERMANENT` fetch is byte-indistinguishable from one over an unfiltered range that omitted everything else â€” exactly the withholding C-4 exists to detect. *Edit:* append `â€– u32(class_mask) â€– u8(heads_only)` to the signature input and add both to `FetchAttestation`; C-4 compares attestations only within an identical filter. If judged too subtle, refuse to attest any fetch with `class_mask != 0` and return the field empty.
21. **EPH(0) fan-out directly contradicts decision B3** (Â§7.2, Â§4.3.5 vs B3, Â§2.4). B3 fixes the pub/sub payload as a record-id range whose entire mechanism is "re-read Postgres"; for EPH(0) there is nothing to re-read. *Edit:* carve EPH(0) out of B3 explicitly rather than leaving the contradiction â€” add channel `urmsg:t:<mask>` with payload `AEAD(channel_key, transient_record_bytes)`, naming Â§2.4's existing deployment requirements (no AOF/RDB, MONITOR denied by ACL, slowlog off) as the compensating control, and bound the carve-out to records that by construction are never persisted.

**Operations**

22. **The server's URnetwork account has no lifecycle and contradicts the deployment model** (Â§9.1, Â§2.3, Â§10.2). Provisioning is one sentence; rotation and revocation are absent; "one `network_client` per instance" contradicts "N stateless replicas". *Edit:* rewrite Â§9.1 as a four-row lifecycle table â€” **Provision:** one network, one `network_client` per ordinal; the process reads `MESSAGE_SERVER_ORDINAL` and selects `message_server.yml`'s keyed entry; deploy as a StatefulSet with stable ordinals; `/readyz` fails if the ordinal has no credential. **Rotate / Revoke / Decommission:** specify each.
23. **The fleet Ed25519 attestation key has no rollover and is copied to every replica** (Â§9.1, Â§4.3.1, Â§10.2, Â§12.2 C-9 â€” merged with the Â§4.3.1 pinning finding). C-9 makes routine TLS renewal or any key rotation a fleet-wide warning indistinguishable from an attack. *Edit:* make `HelloResponse` carry a key set â€” `repeated ServerKey {pub, not_before, not_after, sig_by_previous}` â€” so a planned rotation is a signed chain accepted silently while an unsigned change stays a blocking warning; likewise advertise `repeated bytes tls_spki_sha256` (current plus one announced successor); publish the fleet signing key into the operator's KT log; add an ops note requiring certificate renewals to reuse the key pair so the SPKI is stable; add the rotation case to Â§13.
24. **`Capabilities` is "config, never a constant" with no reload mechanism and no version** (Â§10.2, Â§4.3.1, Â§2.3, Â§6.1 step 5). *Edit:* watch `message.yml`, reload atomically, and bump a monotonic `capability_version` (u64) carried in `HelloResponse.capabilities` and `CapabilityChange`; store the fleet's active version in a `message_config` table so an instance loading a lower version can refuse or warn.
25. **Backup covers Postgres and not the object store; the two cannot be restored to a common point** (Â§10.4). MinIO versioning is off (correctly), so a Postgres restore to Tâˆ’3d yields dangling rows and orphaned objects that trap 1's `sweep-now --until-clean` does not touch. *Edit:* add `messagectl reconcile-blobs`, mandatory after any restore before serving traffic, gated by the same restore-marker mechanism: walk the object-store prefix, delete objects with no `message_blob` row, and for rows whose object is missing mark `ct_body`/`blob_id` state erased so the client reports it honestly.
26. **The `redact/` package is a silent data-corruption hazard as specified** (Â§11.2 item 1 / B11, Â§3.1, Â§13). `GroupId`, `SenderHandle`, `BlobId`, `RecoveryHandle`, `ClientId` are named slice types implementing `MarshalJSON`/`MarshalText`; pgx v5's encode planning consults `json.Marshaler` and `encoding.TextMarshaler`, so a redacted type passed as a query argument writes the literal `<redacted>`. *Edit:* make the redact types opaque structs wrapping an unexported `[]byte` â€” never a named slice or array â€” so they cannot reach pgx at all and the compiler forces `.Unwrap()` at every store boundary; register explicit pgx codecs or require that only `.Unwrap()` output reaches a query argument; add a store-package test asserting it.
27. **The metric set covers the protocol and not the failure surface** (Â§11.3). *Edit:* add `message_redis_up` (gauge), `message_ratelimit_failclosed_total{limit}`, `message_transport_attached` (gauge), `message_transport_reconnect_total`, `message_contract_state{state}` (gauge, with an alert on contract or balance exhaustion), `message_reassembly_inflight` / `message_reassembly_bytes` (gauges), `message_reject_stage_total{stage}`.

---

## 3. MINOR

- **Ten messages are referenced but never declared** (Â§4.3, Â§4.3.2, Â§6.1, Â§12.1 A-2): `GroupStatusRequest`/`Response`, `CapabilityChange`, `Backpressure` (fields only in Â§4.4 prose), `RetentionApplied`, `GroupRecords`, `SubscriptionAck`, `Direction`, `KtGossip`, `EpochAttachment`, `RecoveryTag`. `EpochAttachment` is consequential â€” Â§6.1 validates and installs from it. *Edit:* define `EpochAttachment{u64 epoch, bytes write_key, u16 alg_id, u32 media_ttl_seconds, u32 durable_ttl_seconds, bytes group_context_hash}` and `RecoveryTag{bytes recovery_handle, bytes recovery_verify_pub, u16 alg_id}` **in Spec B** (the server is their only consumer; Spec A needs only `LP(H(server_attachment))`), and declare the other eight.
- **`expire_at` has three representations and no stated conversion** (Â§4.3.3 `expire_at_ms`, Â§5.4 preimage `u64(expire_at)`, migration 003 `timestamp`). *Edit:* state in Â§5.4 that `expire_at` is milliseconds since the Unix epoch on the wire, in the preimage and in `AAD_head`; that `write_auth` is computed and verified **only** over request bytes via `connect/message`'s encoder and never re-derived from the database; and that the `timestamp` column is a lossy convenience projection with no authority.
- **Decision B2 contradicts Â§4.7.** B2: "no correctness invariant may depend on Redis â€¦ it never changes what is accepted." Â§4.7: on Redis loss, limits fail closed to 25% of configured rate. *Edit:* reword B2 to "no *durability or ordering* invariant may depend on Redis â€” the commit CAS, stream monotonicity and `record_id` allocation are Postgres-only," and add a sentence naming admission rate as the one thing a Redis outage does change.
- **`body_hash` is never verified for blob-backed records** (Â§5.1 check 8, Â§8.3). The server already streams every byte, so hashing is free. *Edit:* compute SHA-256 during assembly, store as `message_blob.content_hash bytea`, compare at bind time against the record's `body_hash`, REASON_REJECTED on mismatch. Note in Â§5.2 that this is integrity for recipients and DoS reduction â€” not authenticity, since uploader and author are the same party.

---

## 4. CROSS-CUTTING â€” must be edited in one commit across documents

These four are the half-fix risks. Each needs an owner who rules, and all named documents amended together.

**X-1 â€” Mutually exclusive wire bindings for the same shared file; each spec says the other owns it.** *(BLOCKER)*
Documents: **Spec A Â§10.1 + decision A10; Spec B Â§4.2, Â§4.3, decision B8, Â§5.1.**
A adds MessageType 29 (`MessageEnvelope{request_id, op uint32, payload bytes, server_nonce bytes}`) and 30 (`MessageStreamAck`) with an opaque op+payload envelope whose payload is "encoded by connect/message" and whose op codes are "Spec B's to define". B's decision B8 rejects exactly that approach and reserves 1000/1001/1002.
*Edit (recommended resolution):* keep A's envelope shape and code points â€” 29 `MessageEnvelope`, 30 `MessageStreamAck`, add 31 `MessageFragment`. Keep `server_nonce` in the envelope and **delete B Â§5.1's separate field comparison**. Make B's `oneof` bodies the payload encodings selected by `op`. Withdraw B8's 1000/1001/1002 reservation in the same commit.

**X-2 â€” Epoch wrap records have no home in the schema or the API; the epoch bundle is the dominant storage and fetch cost and is unmentioned.** *(BLOCKER â€” two findings merged)*
Documents: **MASTER Â§8.2; Spec A Â§12.1 S5/S6; Spec B Â§3.2 (003/004), Â§3.3, Â§3.4, Â§4.3, Â§4.3.4, Â§7.2, Â§8.3.**
A's S5 normatively requires the server to index device wraps by `wrap_target_handle` (16 B, from `group_handle_key`) and recovery wraps by `recovery_handle`, "so a device or restorer fetches its own wrap in O(1)". B's `message_record` has only `recovery_handle` â€” no `wrap_target_handle` column, no index, no wrap-fetch operation in the request `oneof`. MASTER Â§8.2 sizes a commit at the 500-member target at ~2.1 MB (1.21 MB device wraps + 0.62 MB recovery wraps + 0.30 MB snapshot), which B's data model, retention table and capacity section never account for.
*Edit, all in one commit:*
- Spec A: confirm `wrap_target` as a server-visible, `write_auth`-covered 16-byte opaque per-epoch tag â€” a **third `server_attachment` case**, folded into open item 1 rather than a second mechanism.
- Spec B Â§3.2: `wrap_target_handle bytea NULL CHECK (wrap_target_handle IS NULL OR octet_length(wrap_target_handle)=16)` on `message_record`, plus `CREATE INDEX message_record_wrap ON message_record (group_id, wrap_target_handle, epoch) WHERE wrap_target_handle IS NOT NULL`.
- Spec B Â§4.3: add `WrapFetchRequest{group_id, wrap_target_handle, epoch}` / `WrapFetchResponse{...}` to the request `oneof` (and require `req_auth` on it per B-3).
- Spec B Â§3.3, Â§3.4, Â§7.2: add the Q-row, the capacity line at the ~2.1 MB/commit figure, and the retention treatment for wrap and snapshot records; note the interaction with B-10's `perm/` rung for the ~300 KB snapshot blob.

**X-3 â€” Three documents disagree on whether the server holds `write_key`, and the two that are wrong are read first.** *(MAJOR)*
Documents: **MASTER Â§9.2; Spec A Â§12.1 (and A Â§5.7's signature); Spec B Â§5.3, decision B9, Â§12.1.**
MASTER Â§9.2 says the server "holds `H(write_key)`-derived verification state per epoch"; A Â§12.1 says "without learning `write_key`" â€” while A Â§5.7's own `VerifyWriteAuth(writeKey []byte, â€¦)` and B Â§5.3/B9 have the server holding the key.
*Edit:* in the same commit that lands the `server_attachment` amendment (open item 1), strike MASTER Â§9.2's "`H(write_key)`-derived verification state" sentence and Spec A Â§12.1's "without learning `write_key`" clause, replacing both with B Â§5.3's text and its three consequences (server can forge; keys are wrapped under the KEK; superseded keys are retired then destroyed). Record it in B Â§12.1 as A-10.

**X-4 â€” Three documents disagree on the uniqueness domain of `stream_index`.** *(MAJOR)*
Documents: **MASTER Â§8; Spec A Â§12.1 S2; Spec B migrations 004/005 (`message_record_stream`, `message_sender`).**
MASTER: "monotonic per (`sender_handle`)". A's S2: per `(group_id, sender_handle, retention_class)`. B: `UNIQUE (group_id, sender_handle, stream_index)` and `message_sender PRIMARY KEY (group_id, sender_handle)`, no class. A client following A keeps one counter per class and its first EPH record collides.
*Edit (recommended):* adopt MASTER's per-`sender_handle` domain â€” a single counter is what makes MASTER Â§8's durable "index k consumed" record one fsync per record rather than one per class, and it leaves B's index and `message_sender` unchanged. **Strike `retention_class` from A's S2.** Add a case to the shared interop vectors covering interleaved classes from one sender.

---

## 5. VERDICT

**No â€” not until the blockers land, and then yes with one caveat.** The ten Spec B blockers and the two cross-cutting blockers are handoff-blocking rather than merely severe: a team handed Spec B today would build a group that cannot bootstrap (B-1), a read path with no authentication (B-3), a recovery proof that cannot be verified by any party (B-4), a commit path whose loser protocol never fires (B-5/B-6), and a schema with nowhere to put the epoch bundle that dominates its own storage budget (X-2); once those and X-1's wire-binding conflict are resolved, the remaining MAJORs are ordinary pre-implementation cleanup that a team can absorb alongside the build.

**Review coverage:** Spec B is now adequately reviewed â€” this pass read it end to end (schema, protocol, commit path, blob plane, KT log, operations, logging, metrics) and the findings are distributed across all of it, so the prior pass's gap on B is closed. **Spec C is not reviewed and does not appear in this material at all** â€” no finding in this pass references a Spec C, so if a third spec exists it remains in exactly the unreviewed state the prior pass left it in and must be sent through a review of its own before any handoff.
