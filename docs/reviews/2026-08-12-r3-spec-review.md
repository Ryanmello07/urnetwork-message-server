# CONSOLIDATED EDIT LIST â€” URmessage spec review (5 reviewers, 41 raw findings â†’ 12 blockers / 15 majors / 10 minors)

Reviewer overlap was heavy: the PQ wrap targets were raised 4Ã—, the write capability 3Ã—, the record-key chain 2Ã—, concurrent-commit ordering 2Ã—. Merged below. Each item gives the sections to edit and the edit to make. Fix order matters â€” B-1 is the keystone; six other items are edits to structures it introduces.

---

## 1. BLOCKERS

### B-1 â€” Define the URmessage LeafNode extension; delete `pq_root`
**Sections:** Â§5.2 (key tree), Â§6 ("Extensions we require"), Â§7 Â¶2, Â§8.3 table row 1
**Raised by:** 4 reviewers (as UNIMPLEMENTABLE Ã—2, CRYPTO_DEFECT, CONTRADICTION)

The per-device PQ wrap target is undefined end to end. `pq_root = HKDF-Expand(master_key, "pq/v1", 32)` is seed-derived, which contradicts Â§5.2's own invariant ("`recovery_root` is the only master-derived group-usable secret" / "a device that could derive its own keys from the seed would hold the seed, and revocation would be meaningless") â€” `pq_root` is `device_root` renamed, i.e. the defect R2-B1 deleted. The `pq_root` branch also terminates in "â†’ see Â§7" and Â§7 gives no formula. Meanwhile an MLS leaf for ciphersuite 0x0003 carries exactly one X25519 `encryption_key` and no ML-KEM key, and Â§6 defines no LeafNode extension at all.

**Edit:**
1. Delete the `pq_root` branch from Â§5.2 entirely. The existing sentence about `recovery_root` then becomes true.
2. In Â§5.2's device paragraph, add to the on-device CSPRNG-generated set (sealed to the keystore, never seed-derived): `(dk_pq, ek_pq) = ML-KEM-1024`, `(sk_wx, pk_wx) = X25519`, plus the capability scalar of B-5.
3. Define **one** extension `urmessage_leaf_keys`, allocated a type value, listed in `required_capabilities.extension_types` â€” therefore covered by the LeafNode signature, the tree hash, and RFC 9420 Â§7.3 validation, and revoked by `Remove` like the rest of the leaf. Body: `{u16 alg_id, LP(device_x25519_pub), LP(device_mlkem_pub), LP(cap_leaf_pub), LP(delegation_pub)}`.
4. Rewrite Â§7 Â¶2 and Â§8.3 row 1 to name this extension as the sole wrap target for device leaves.

**Unblocks:** B-2, B-5, M-6, M-13.

### B-2 â€” Replace the `mls_secret` recovery wrap with an explicit epoch history archive
**Sections:** Â§8.3, Â§7, Â§5.3, Â§11 (history grants), Â§12.4, Â§13
**Raised by:** 2 reviewers (BLOCKER + BLOCKER/UNIMPLEMENTABLE on the indexing half)

Â§8.3 wraps the MLS-Exporter output and calls it "the anchor that makes seed-only restore work." It cannot be: per RFC 9420 Â§8.1, `exporter_secret`, `encryption_secret` and `sender_data_secret` are independent sibling `ExpandWithLabel(epoch_secret, â€¦)` derivations â€” the exporter output derives none of the others. Separately, the committer cannot *construct* the wrap: `rk_cls`/`rk_pq` derive from `recovery_root`, which only the member holds, and their public halves are published nowhere.

**Edit:**
1. Define `archive_secret[n] = sender_data_secret[n] â€– encryption_secret[n]` â€” prefer these two named secrets to `epoch_secret[n]`, which would also expose `confirmation_key` and `membership_key` â€” plus a snapshot of the epoch-n ratchet-tree public state and GroupContext needed for signature verification. Wrap **that**, not `mls_secret[n]`.
2. Publication: at join and on any `identity` key change, the member emits `RECOVERY_PUB { group_id, LP(rk_cls_pub), LP(rk_pq_pub), u16 alg_id }` signed under its `identity` key, carried as a member-level URmessage group-context entry or a `PERMANENT`-class record. This is what the committer wraps to.
3. Indexing: `recovery_handle` never enters group state. Only the member's own device writes the index record under it (see M-9).

### B-3 â€” Make the group host the Delivery Service; restore compare-and-swap
**Sections:** Â§9.3, Â§9.1, Â§6 table row "Ordering, fork detection", Â§8 header
**Raised by:** 2 reviewers

"Two concurrent commits for the same epoch are resolved by MLS's own rules" is false. RFC 9420 gives fork *detection* only; RFC 9750 Â§5.2 states the requirement ("the group must agree on a single MLS Commit message that ends each epoch") and offers exactly two satisfying designs. The conclusion drawn â€” that revision 2's server-side CAS is no longer needed â€” is the opposite of what is required, and it is a regression against revision 2.

**Edit:** Adopt strongly consistent / RFC 9750 Â§5.2.1 and write it normatively:
1. Add cleartext `is_commit u8` to the Â§8 RECORD header; include it in `AAD_head`, `AAD_body` and the `cap_auth` input.
2. Â§9.1: the host MUST accept at most one record with `is_commit=1` per `(group_id, epoch)` and at most one `EPOCH_WRITER_SET` per `(group_id, epoch)`, first-valid-wins, never replaced; MUST return the accepted set to any later submitter; MUST reject records whose `(epoch, writer_handle)` is not in the accepted set. A committer whose set is rejected re-derives against the winner and retries.
3. Rewrite Â§9.3 and the Â§6 table row to cite RFC 9750 Â§5.2.1, not "MLS's own rules."

### B-4 â€” Give `EPOCH_WRITER_SET` an authenticator the blind host can verify
**Sections:** Â§9.2, Â§9.1
**Raised by:** 1 reviewer as BLOCKER, reinforced by the MAJOR forgery finding (folded in as M-11)

`EPOCH_WRITER_SET` is "authenticated under `storage_root[n]`," and Â§9.2 states one sentence earlier that the server does not hold `storage_root[n]`. The server therefore cannot verify the one artifact it uses to decide whom to accept writes from; Â§9.1's first duty has no trustworthy source for `cap_pub`, `may_write`, or the handle list, and anyone who learns `group_id` can publish a set.

**Edit:** Sign the set for epoch n under a committer key that the host can chain to group registration: at group creation the founder registers `group_control_pub` with the host alongside `group_id`; the set for epoch n is signed under the epoch-n control key, whose public half is carried in the epoch-(nâˆ’1) set, rooted at `group_control_pub`. Combine with B-3's first-wins rule so the chain cannot be forked. Add the authenticator to the struct explicitly rather than leaving it prose.

### B-5 â€” Make the write capability per-device; keep `read_cap` group-symmetric
**Sections:** Â§9.2 (lines 400â€“406), Â§8.1, Â§11 OBSERVER row, Â§12.2
**Raised by:** 3 reviewers (2 BLOCKER, 1 MAJOR)

`cap = HKDF-Expand(storage_root[n], "cap/v1" â€– LP(leaf_index), 32)` with `storage_root[n]` group-wide and `leaf_index` public means every member can compute every other member's write capability. Â§9.2 presents this as a convenience; it is the vulnerability. The host-facing write authenticator proves only "some member of this group," so Â§11's OBSERVER role is unenforceable and no record is attributable.

**Edit:**
1. Keep `read_cap` derived from `storage_root[n]` â€” group-symmetric read authorization is correct.
2. Write capability: each device holds a long-term scalar `cap_leaf` (on-device CSPRNG), publishes `cap_leaf_pub` in the B-1 extension. Per epoch, blind it so the committer can still populate the set without any device secret: `b(n) = HKDF-Expand(storage_root[n], "capblind/v1" â€– LP(u32(leaf_index)), 64) mod L`; private `cap(n) = cap_leaf Â· b(n)`, public `cap_pub(n) = cap_leaf_pub Â· b(n)`.
3. `EPOCH_WRITER_SET` carries `{writer_handle, cap_pub(n), may_write}`.

### B-6 â€” Split the AAD in two; the record is currently unconstructible
**Sections:** Â§8, RECORD/AAD block (lines 307â€“318)

`body_hash = H(ct_body)`, one AAD is given for both ciphertexts, and it ends in `â€– LP(body_hash)` â€” so producing `ct_body` requires an AAD that requires `ct_body`. No order of operations terminates. The line-312 parenthetical also contradicts the block it annotates.

**Edit:**
```
AAD_body = "URmessage/v1/aad/body" â€– u16(alg_suite) â€– LP(group_id) â€– LP(writer_handle)
           â€– u64(epoch) â€– u64(stream_index) â€– LP(prev_record_hash)
           â€– u8(retention_class) â€– u8(size_bucket) â€– u8(is_commit) â€– u64(expire_at) â€– u64(t)
AAD_head = "URmessage/v1/aad/head" â€– (same fields) â€– LP(body_hash)
```
Order: encrypt body â†’ `body_hash = H(ct_body)` â†’ encrypt head â†’ compute `cap_auth`. Delete the contradictory parenthetical.

### B-7 â€” Delete the `record_key` chain; derive record keys positionally
**Sections:** Â§8.2 (lines 360â€“366), Â§8 `keys` block, Â§8.1 holes, Â§12.1
**Raised by:** 2 reviewers across 3 findings (unimplementable index, false FS claim, head/body chain contradiction) â€” one edit fixes all three

The ratchet index `i` is bound to no wire field and cannot be reconstructed: four class chains plus "`ct_head` is always durable-class" means nothing says whether a record advances the durable chain by one or two, nor how `stream_index` maps to a per-class counter. Two implementations will not interoperate. The FS claim is also false â€” `record_key[0]` derives from `class_key` â† `storage_root[n]`, which every member, every newly provisioned device and the recovery-key holder hold, so any chain is recomputable from index 0 forever for DURABLE/PERMANENT.

**Edit:**
1. Replace the chain with `record_key = HKDF-Expand(class_key, "rec/v1" â€– LP(leaf_index) â€– u64(stream_index), 32)`, where `class_key` = the record's own class key for the body and `K_durable[n]` for the head. Two explicitly named keys, both positional, both pure functions of header fields â€” holes, pruning and out-of-order arrival all become free.
2. Delete the skipped-key window entirely (it exists only to serve the chain).
3. Replace the FS paragraph with an honest statement: storage keys provide no forward secrecy within an epoch; every member can derive every record key of the epoch; forward secrecy across epochs comes from MLS and from EPH key destruction, nothing else. Correct Â§12.1's claim to match.

### B-8 â€” Specify the ephemeral key schedule with a per-bucket forward ratchet
**Sections:** Â§8.2 (line 358), Â§12.1
**Raised by:** 2 reviewers (BLOCKER/CRYPTO_DEFECT + MAJOR/UNIMPLEMENTABLE)

"`K_eph[n][b][t]` = time-sliced per bucket b, window t" is the entire specification of the hierarchy on which Â§12.1's strongest guarantee rests. It defines no derivation, no window origin, no destruction rule, no skew handling. The natural implementation â€” `HKDF-Expand(eph_root[n], "eph/v1" â€– u8(b) â€– u64(t), 32)` â€” retains `eph_root[n]`, so every past window is recomputable and the schedule is not forward-secure across windows, defeating the property Â§8.2 itself calls "the single most easily broken property in this document."

**Edit:**
```
S[n][b][0]     = HKDF-Expand(eph_root[n], "eph/v1" â€– u8(b), 32)   for every bucket b
K_eph[n][b][t] = HKDF-Expand(S[n][b][t], "key/v1", 32)
S[n][b][t+1]   = HKDF-Expand(S[n][b][t], "step/v1", 32)
```
Normative additions: a device MUST derive `S[n][b][0]` for all buckets on receipt of `eph_root[n]` and MUST destroy `eph_root[n]` immediately; MUST destroy `S[n][b][t]` on stepping to `t+1`. Define `t = floor((unix_seconds âˆ’ ORIGIN)/window(b))` with a fixed protocol ORIGIN. Resolve skew by making the sender authoritative: carry `u64(t)` in the header, cover it in `AAD_head`/`AAD_body` and `cap_auth`, receiver uses the carried `t` and rejects values more than a stated bound from local time.

### B-9 â€” Remove `server_nonce` from `cap_auth`
**Sections:** Â§8 (lines 320â€“322), Â§8.1 (337â€“339), Â§9.5, Â§9.2 (line 425)

`cap_auth` covers `LP(server_nonce)` and is verified by the *group* host, but Â§9.5 has the client talking only to its home server â€” so the nonce must round-trip from the foreign host before encryption. Combined with Â§8.1's "record 'index k consumed' before encrypting, and never encrypt a second record at a consumed index," the write path is non-retryable and cannot be used offline: any lost response burns an index permanently.

**Edit:** Drop `server_nonce` from the covered bytes. Replay protection is already the host's write-once enforcement of `(group_id, writer_handle, epoch, stream_index)` â€” a resubmission is a byte-identical duplicate at a consumed index and is idempotently rejected; cross-group replay is blocked by the covered `group_id`. Move liveness to a connection-level challenge-response outside the record.

### B-10 â€” Define `redacted_form` and replace implicit holes with `VOID` records
**Sections:** Â§8.1 (lines 337â€“348), Â§8 line 307

`redacted_form(...)` is the load-bearing term for the entire erasure-safety story and is defined nowhere â€” field set, canonical encoding, whether `record_id`/`cap_auth` are included, whether `ct_body` becomes `body_hash` or is omitted. Any two implementations disagree and every chain check fails. There is also no hole-declaration field, so a suppressing host and an abandoned index are indistinguishable.

**Edit:**
1. Write `redacted_form` out as an explicit field list with canonical encoding, `ct_body` replaced by `LP(body_hash)`, `cap_auth` excluded.
2. Define a `VOID` record: `retention_class = PERMANENT`, empty body, normal `stream_index`, `prev_record_hash` and `cap_auth`, emitted by the writer when it abandons an index. The host then enforces strict contiguity per `(writer_handle, epoch)` and any gap is unambiguously host suppression.

### B-11 â€” Define the device-binding certificate and make it the AS check
**Sections:** Â§6 (Credential), Â§11 (roles, self-service device management), Â§10.2

Â§6 has a `BasicCredential` carrying the member's `identity` public key with "each of their devices holds a separate leaf signed under it." RFC 9420 Â§7.3 LeafNode validation verifies the LeafNode signature under the LeafNode's **own** `signature_key` and enforces key uniqueness â€” it never checks any relation between `signature_key` and the credential identity. The implied check exists nowhere in the spec, so nothing binds a leaf to a member and every downstream "is this the owner?" test (roles, self-service device management) is unimplementable.

**Edit:** Device signature keys stay on-device per Â§5.2; the member's `identity` key signs
`DEVICE_BIND = Sign(identity_priv, "URmessage/v1/devbind" â€– u16(alg_id) â€– LP(identity_pub) â€– LP(device_signature_key) â€– LP(group_id) â€– u64(not_before))`.
Carry it in a registered custom Credential type listed in `required_capabilities.credential_types` (preferred), and state normatively that every member MUST verify DEVICE_BIND at LeafNode-validation time and reject leaves that fail. Reference this as *the* identity resolution used by M-1's role check.

### B-12 â€” State which epoch envelopes commit records and `EPOCH_WRITER_SET`
**Sections:** Â§8 RECORD header, Â§9.2, Â§8.1

The header carries one cleartext `epoch` and envelope keys come from `storage_root[n]`, but the spec never says which epoch's root envelopes (i) the commit record ending epoch n, or (ii) `EPOCH_WRITER_SET(n+1)`, which Â§9.2 requires be "authenticated under `storage_root[n]` â€” the new epoch's key." A device added at n+1 holds no `storage_root[n]`, so the wrong choice makes joins unreadable.

**Edit, normative:** a commit record is enveloped and `cap_auth`'d under the epoch it is **sent in** and carries `epoch = n`. `EPOCH_WRITER_SET(n+1)` is a separate record enveloped and authenticated under `storage_root[n+1]`, carrying `epoch = n+1` and `stream_index = 0` in the committer's new-epoch stream. A host MUST accept `EPOCH_WRITER_SET(n+1)` before any other epoch-(n+1) record.

---

## 2. MAJOR â€” ranked by rework prevented

Items M-1 through M-5 change the wire format that Â§14 slice 2 freezes. They must land **with** the blockers, not after.

**M-1 â€” `alg_suite` in the record header.** Â§8 header, AAD, `cap_auth`, `redacted_form`, `EPOCH_WRITER_SET`. Â§7.1 requires every authenticator and ciphertext to carry `alg_id` inside signed bytes; the record violates it on both counts. Add `alg_suite u16` as the first field after `group_id`, identifying the (AEAD, KDF, capability-authenticator) triple as **one registered suite** â€” independent negotiation of the three is a downgrade surface. Host rejects records whose suite is not the set's. *Cheapest edit here, highest cost if deferred past the freeze.*

**M-2 â€” `epoch` is u64, not u32.** Â§8 header, AAD, `cap_auth`, Â§7 wrap `info`. `GroupContext.epoch` is `uint64` (RFC 9420 Â§8.1). A truncating cast would be baked in at the exact point where epoch is the anti-replay binding for both the AEAD and the capability authenticator. (Raised as MINOR; promoted because slice 2 freezes it.)

**M-3 â€” Roles into Â§6's extension body, plus a client-side commit-authorization rule.** Â§11, Â§6, Â§15.4. Â§11 says "Roles live in the URmessage group-context extension" but Â§6's normative body is `{host_server_id, retention_policy, disappearing_buckets}` â€” roles are absent. Worse, MLS has no authorization model: per RFC 9420 Â§12.1.7 any member may send `GroupContextExtensions` and any member may commit, so the protocol accepts a role change from an ordinary member. Add `owner_identity_key` plus `roles[{identity_key_hash, role}]` to the extension body, and a normative deterministic rule every member applies before accepting a commit: reject any commit containing a `GroupContextExtensions` proposal that changes `roles`, `owner_identity_key` or `host_server_id` unless the committer's leaf resolves via B-11's DEVICE_BIND to the owner or an admin.

**M-4 â€” Split `ct_head`.** Â§8.2, Â§8 record layout, Â§12.5, Â§13. `ct_head` is DURABLE-class and always retained, and Â§8.3 hands the recovery key the material from which `K_durable[n]` follows â€” so a seedphrase holder reaches a permanent structured record (type, `sent_at`, sender) of every expired disappearing message, contradicting Â§8.2's own consequence paragraph and Â§12.5's required UI language. Split into `ct_head_chain` (`handle_link` only, DURABLE, always retained â€” preserves everything Â§8.1/Â§12.2 rely on) and `ct_head_meta` (MLS PrivateMessage header, `type`, `sent_at`), encrypted under the record's own class so EPH metadata dies with the EPH key.

**M-5 â€” Replace the application-layer combiner with an MLS PSK.** Â§7. The salt/ikm ordering in `storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n])` is sound and should be said so â€” but "following draft-ietf-mls-combiner" and "an adversary must break both" overclaim. Inject `pq_secret[n]` into the MLS key schedule as a `PreSharedKey` proposal with `psk_type = application` (RFC 9420 Â§8.4) in the same Commit that establishes epoch n, with `pq_psk_id = HKDF-Expand(pq_secret[n], "URmessage/v1/pq-psk-id" â€– LP(group_id) â€– u64(epoch), â€¦)`. This uses the mechanism the RFC already provides, binds PQ material into the transcript, and lets Â§7 shrink.

**M-6 â€” Make Â§7 the single normative wrap definition; Â§8.3's table becomes a pointer.** Â§7 Â¶2 vs Â§8.3 table. They disagree on payload (Â§7: `pq_secret[n]` to both targets; Â§8.3: `pq_secret[n]`+`eph_root[n]` to devices, `pq_secret[n]`+`mls_secret[n]` to recovery) and on addressing (`wrap_key` info uses `LP(leaf_index)`, which does not address a recovery key). After M-5 and B-2 the surviving set is small: `{pq_secret[n] â†’ device leaves}` and `{pq_secret[n], archive_secret[n] â†’ member recovery key}`, with `eph_root[n]` delivered over the MLS application channel. Replace `LP(leaf_index)` in `info` with `u8(target_type) â€– LP(target_id)`.

**M-7 â€” Decouple PQ rotation from the MLS epoch (PQ *era*).** Â§7 Â¶2 vs Â§6's 500-member target and Â§8.3. Each hybrid wrap is ~1.65 KB; at 500 members Ã— 2 devices, Â§8.3 requires ~3000 wraps â‰ˆ 5 MB per epoch, reintroducing exactly the linear per-epoch cost adopting MLS was meant to eliminate â€” TreeKEM's O(log n) is irrelevant if a linear layer sits beside it. Rotate `pq_secret` per era: advance on any Commit containing a `Remove`, on member-key rotation, or on a wall-clock bound (propose 7 days), whichever comes first; additive Commits and Updates inherit the current era. Bind the era into the transcript so it cannot be silently stretched.

**M-8 â€” Epoch retirement for removed writers.** Â§9.1/Â§9.2 acceptance rules, Â§8.1. MLS removal takes effect only from the new epoch and the storage layer defines no retirement, so a member removed by the commit creating n+1 still holds `storage_root[n]` and `cap[n]` and can submit fresh epoch-n records weeks later. (a) Make `prev_high_water_index` a ceiling as well as a floor: once a writer publishes `handle_link` for n+1 declaring `prev_high_water_index = k`, clients MUST reject epoch-n records from that writer above index k. (b) For writers with no successor handle â€” i.e. removed members â€” the host stamps a retirement time when it accepts `EPOCH_WRITER_SET(n+1)` and refuses later epoch-n records from them.

**M-9 â€” Sign the retained header facts.** Â§8 `ct_head`, Â§8 line 332, Â§8.1 `handle_link`. Â§8 states "Sender authentication is MLS's, inside `ct_body`. The storage layer adds no second signature" â€” so `type`, `sent_at` and `handle_link` are protected only by an AEAD under group-shared `K_durable[n]`, and any member can forge another member's tombstones and chain links, which is precisely the material that survives erasure and drives rendering. Add `Sign(leaf_sig_key, "URmessage/v1/head" â€– LP(group_id) â€– u64(epoch) â€– u64(stream_index) â€– u8(type) â€– u64(sent_at) â€– LP(handle_link) â€– LP(body_hash))` inside `ct_head_chain`. Note explicitly that MLS's `authenticated_data` is not sufficient, because verifying `FramedContentTBS` requires the application data that erasure destroys.

**M-10 â€” `recovery_handle` is a lifetime cross-group pseudonym.** Â§5.2, Â§5.3, Â§9.6, Â§13. It is keyed on `(member, server)` and nothing else â€” not group, not epoch â€” and Â§5.2 says the seed cannot be rotated, so neither can the handle. Â§5.3's disclosure ("handles are per-server, so no global identifier exists") understates it: it is a stable identifier linking all of that member's groups on that server for the life of the seed, which contradicts Â§9.6's "Foreign host: â€¦ Not identity." Fix structurally via B-2 (handle appears only in a record the member's own device writes) and rewrite the Â§5.3 and Â§13 disclosures to state the residual linkage plainly.

**M-11 â€” `EPOCH_WRITER_SET` forgery by current members.** Â§9.2. The stated claim is correct as far as it goes â€” a member removed at n cannot forge the set â€” but any *current* member can, because the authenticator is a symmetric key every member holds; flipping `may_write=false` denies a victim writes for the whole epoch. Largely absorbed by B-4 and B-5; the residual edits are (1) add the authenticator to the struct explicitly, (2) require clients to recompute `may_write` from the M-3 roles and treat mismatch as equivocation, (3) first-wins per `(group_id, epoch)`, never replaced.

**M-12 â€” Permute `entries[]`.** Â§9.2 line 410 vs Â§9.6. MLS leaf indices are stable across epochs, so serialising entries in leaf order â€” the obvious implementation and the only one the struct implies â€” lets the host correlate entry #k at n with entry #k at n+1 and recover a stable per-member pseudonym, converting Â§9.6's per-epoch `writer_handle` rotation into a complete activity graph. Require a per-epoch pseudorandom order, e.g. sort by `HKDF-Expand(storage_root[n], "wsorder/v1" â€– LP(writer_handle), 16)`. Members already recompute every handle, so verification is free and the host learns nothing. Normative MUST plus a test vector.

**M-13 â€” Time-scope `READ_DELEGATION`.** Â§9.2, Â§9.5. Epoch-scoping breaks the caching the delegation exists to enable: epochs advance on every Add/Remove/Update â€” many times a day at 500 members â€” so a client offline at a commit leaves its home server unable to prefetch, exactly when prefetch matters. Change to `{group_id, home_server_id, not_before, not_after, auth}`, authenticated under the `delegation_pub` in the B-1 LeafNode extension so it survives epoch changes and is revoked by `Remove`. Cap `not_after âˆ’ not_before` normatively.

**M-14 â€” Complete the test-vector list.** Â§6, Â§14 slice 1. The vectors are the acceptance criterion for slice 1 and Â§0 makes that the decisive argument for the whole revision, but the list omits `passive-client-welcome`, `passive-client-handling-commit`, `passive-client-random`, `tree-operations` and `deserialization` â€” the passive-client vectors being exactly the ones that catch the joining/epoch-handling errors this spec is most exposed to. Add all five to both sections. Add one non-vector acceptance item, since no vector covers it: two independent instances running a 3-member group through a concurrent-commit collision and demonstrating the B-3 CAS outcome.

**M-15 â€” Fix the wrap KDF block.** Â§7 `wrap_key`/`hybrid_ct` vs Â§7.1. The core is right â€” `ss_x25519 â€– ss_mlkem` as IKM with both ciphertexts bound into `info` is the standard split-key-PRF pattern and matches draft-ounsworth-cfrg-kem-combiners-05 â€” but no AEAD nonce is derived and `alg_id` is absent from `info`, violating Â§7.1's own anti-downgrade rule. Rewrite:
```
prk = HKDF-Extract(salt = "URmessage/v1/wrap-salt", ikm = ss_x25519 â€– ss_mlkem)
wrap_key â€– wrap_nonce = HKDF-Expand(prk, info, 56)     // 32 B key â€– 24 B nonce
info = "URmessage/v1/wrap" â€– LP(group_id) â€– u64(epoch)
       â€– u8(target_type) â€– LP(target_id) â€– u8(payload_type)
       â€– u16(alg_id) â€– LP(pk_x25519) â€– LP(ek_mlkem) â€– LP(ct_x25519) â€– LP(ct_mlkem)
```
(Raised as MINOR; promoted because it is a wire-format freeze item and it merges with M-6.)

---

## 3. MINOR

1. **Â§6 / Â§11 name the wrong binding mechanism.** `confirmed_transcript_hash` covers `FramedContent` of Commits (RFC 9420 Â§8.2); GroupContext extensions are not in it. Reword to: "carried in the GroupContext `extensions` field, which is bound into the epoch key schedule and therefore into `confirmation_tag`, and into `FramedContentTBS` for every member-sent message â€” a server that alters them produces a group state whose confirmation tag no member can verify." Correct the Â§8.1 citation to Â§8.2.
2. **Â§7 exporter context is empty.** Use `MLS-Exporter("URmessage/v1/storage", LP(group_id) â€– u64(epoch), 32)`, match RFC 9420 Â§8.5's function name and argument order, and add a sentence reserving that label for this single purpose. Not a defect â€” label, length and per-epoch freshness are correct â€” but it wastes the field that makes the binding explicit.
3. **Â§11 self-service device management overstates what MLS allows.** RFC 9420 Â§12.4 forbids a Commit that removes the committer, so removal of leaf L MUST be committed from a different leaf of the same member. Define the uncovered cases: a member with no remaining device is removed by the OWNER or an ADMIN; a member leaving voluntarily sends a self-Remove that another member commits. Reflect in the stolen-laptop rationale that self-service revocation presupposes a second device.
4. **New devices cannot read live disappearing messages.** Correct behaviour, invisible in the document. Add to Â§5.3 step 3: "Consequently a newly provisioned device cannot read disappearing messages sent before it was added, even ones that have not yet expired; they render as gaps on that device only." Add the Â§12.5 string and the Â§13 line.
5. **History grants convey what?** Add to Â§11: "A history grant conveys `storage_root[m..n]` and nothing else. It never conveys `eph_root` for any epoch, so granted history contains no disappearing messages, live or expired. The grant banner MUST say so." Add "or a history grant" as a fourth item to Â§8.2's exclusion list.
6. **Padding is not normative.** Â§9.6's "control messages are padded into the same size buckets as content" is vacuous while `size_bucket` is a client-declared byte and the host sees true length. Add to Â§8: `len(ct_head) + len(ct_body)` MUST equal the declared bucket boundary exactly, padding applied inside `ct_body` before encryption using a length-prefixed plaintext; host MUST reject mismatches. Same MUST for `COVER` records.
7. **`PERMANENT` settable by clients or not?** Â§12.3 ("Set by: protocol") and Â§9.6 ("`PERMANENT` is available to content") give opposite answers. Take Â§9.6's reading and bound it: client-settable for content, subject to a per-writer per-epoch `PERMANENT` byte quota advertised alongside the Â§12.3 size cap. Update the "Set by" cell.
8. **`expire_at` annotation is over-broad.** "Advisory; keys are authoritative" holds only for EPH. Change to: "advisory. For `EPH` the key is authoritative and destruction is guaranteed (Â§8.2). For `MEDIA` and `DURABLE` expiry is enforced only by host pruning and is detectable-but-not-compellable (Â§12.4)." Extend Â§12.5's UI language to cover media expiry with the same honesty as the durable-default string.

---

## 4. MLS ADOPTION ASSESSMENT

**Direct answer: delegation worked for the problem it was aimed at, and relocated the rest. It resolved group key agreement and moved every prior blocker into the layer RFC 9420 does not cover â€” where three of them came back in worse form, because the spec now assumes MLS handles things it does not.**

Of the 12 merged blockers, **zero** are defects in group key agreement itself â€” the tree, the epoch schedule, membership changes and fork *detection* are genuinely off the table now, and no reviewer raised a single finding against them. That is real.

But the blockers sort into two piles, neither of which delegation touched:

- **9 of 12 live in the URmessage-specific layer MLS never covered** â€” storage record construction (B-6, B-7, B-10, B-12), the PQ layer (B-1, B-2), capabilities and host acceptance (B-4, B-5, B-9). These are the same *class* of problem as the prior revision's, re-expressed against a new substrate.
- **3 of 12 are new, and are caused by adopting MLS while misreading its contract** (B-3 ordering, B-11 credential/device binding, plus the exporter misuse in B-2). These did not exist before. Â§9.3 asserts a resolution rule RFC 9420 does not contain, Â§6 asserts a credential check RFC 9420 Â§7.3 does not perform, and Â§8.3 assumes an exporter output can regenerate its sibling secrets, which RFC 9420 Â§8.1 forbids.

**Regressions specifically attributable to the adoption: 2.** (i) `pq_root` re-creates the seed-derived device-key defect that R2-B1 deleted, under a new name, and directly contradicts Â§5.2's own invariant one line below it. (ii) Â§9.3 *removes* revision 2's server-side compare-and-swap on the strength of a false claim about MLS, discarding a correct mechanism the design needs â€” RFC 9750 Â§5.2 assigns that job to the Delivery Service, i.e. back to the host.

**Explicitly carried-forward-unresolved: 2** (both tagged UNRESOLVED_PRIOR by reviewers) â€” the incomplete IETF vector list that Â§0 rests its entire argument on, and the undefined per-device PQ wrap target.

The honest scoreboard: **1 problem class resolved (group key agreement), 9 relocated, 3 newly introduced, 2 regressed.** The adoption was the right call and should stand â€” but Â§0's framing, that delegating to RFC 9420 resolves the prior blockers, is not supported by this review and should be rewritten to say what is actually true: it resolves the key-agreement blockers and narrows the remaining work to a smaller, better-bounded custom layer that is still entirely unbuilt.

---

## 5. VERDICT

**No â€” not after the BLOCKERs alone.**

Five of the MAJORs (M-1 `alg_suite`, M-2 u64 epoch, M-3 roles in the group-context extension, M-4 the `ct_head` split, M-5 the PSK combiner) change structures that Â§14 slice 2 explicitly freezes, so shipping the blocker fixes without them buys a second wire-format break that the plan says cannot happen. And the blocker fixes are not independent patches â€” B-1's LeafNode extension is a prerequisite for B-2, B-5, M-6 and M-13, so Â§Â§5â€“9 are being rewritten as one interlocking pass; the owner should review that pass whole, once, rather than review a document whose Â§5.2 invariant, Â§7 wrap targets and Â§8.3 table still disagree with each other.
