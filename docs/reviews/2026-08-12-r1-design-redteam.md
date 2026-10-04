# URmessage v2 â€” REVISED ARCHITECTURE (spec payload)

---

## 1. VERDICT ON V1 â€” TWO-PLANE LOG

**Verdict: SURVIVES ONLY IN AMENDED FORM. The claim as written is false and must be struck from the spec.**

V1 claimed the split "preserves MLS-grade tamper-evidence for membership while letting messages be deleted." Two halves, both wrong:

- MLS tamper-evidence comes from *every member processing the same commit sequence and detecting divergence*, not from a hash chain. V1 keeps the chain and discards the detection. Under V2's single copy there is no second view in which a fork could surface. A hash chain is tamper-evident, never fork-evident or completeness-evident.
- The premise "we cannot chain content because we must prune it" is simply false. Matrix solved this in 2015: hash over the *redacted form*, so stripping the payload preserves the event's identity and position. The content plane was un-chained for no reason and paid for it with a censor's alibi that D3-REVISED then made unattributable.

The split survives as a **client-side namespace**, not as a server-visible plane. Required amendments:

**A1 â€” ONE RECORD FORMAT.** Control and content records are byte-shaped identically on the wire and at rest. Event type, plane, sender identity, and epoch semantics live *inside* the ciphertext. The server sees only what it must to operate: `group_id`, `record_id`, `writer_handle`, `stream_index`, `prev_record_hash`, `retention_class`, `size_bucket`, `expire_at`, and a write-capability authenticator. This is Session's storage-namespace pattern (proven in production) rather than a server-enforced plane split.

**A2 â€” EVERY RECORD IS CHAINED, IN BOTH PLANES.** Per-writer chains, not a global chain: each record carries `(writer_handle, stream_index, prev_record_hash)` where `prev_record_hash` is over the *redacted form* (header only) of that writer's previous record. Gapless `stream_index` is enforced by the server on write and verified by every client on read. This costs 40 bytes and requires no global ordering, so it is compatible with V2's single-host model and with arbitrary pruning. Receiving index 12 without 11 is unforgeable evidence of a hole.

**A3 â€” EPOCH-HEAD BINDING ON EVERY RECORD.** Every record â€” content included â€” carries `(epoch, control_seq, control_head_hash)` of the sender's view inside the signed, encrypted envelope. A receiver whose own control log cannot reach that head hard-fails and refetches; a receiver at a *higher* `control_seq` than a sender who must have seen the commit raises a fork alarm and blocks sending. This is the mechanism that makes epoch-stall and equivocation cost the server a *total blackout of every up-to-date sender*, which is user-visible. Signal has the weaker version of this (group revision on every message); we need it strictly because we retain durable ciphertext.

**A4 â€” CHAIN THE HEADERS, ERASE THE PAYLOADS.** Control event = `header{prev_hash, seq, epoch, H(payload), signer, sig}` + `payload{type, member ids, device keys, wrapped key material}`. The chain covers headers only. Erasing a payload leaves a verifiable hole ("an authorized event occurred here, content erased") instead of breaking the chain. This is the only thing that makes GDPR-style erasure and any form of compaction possible at all, and it is Matrix's redaction trick applied to the plane Matrix could never apply it to.

**A5 â€” CONTROL PLANE IS COMPACTABLE VIA SIGNED CHECKPOINTS.** "Tiny, permanent, never pruned" is false on all three counts and must be deleted. Replace with: at every epoch commit boundary (or every M commits), k-of-n admins sign a `MEMBERSHIP_CHECKPOINT` that is a self-contained attestation of the member set, device set, roles, admin policy, host chain, head hash, and â€” critically â€” a per-epoch `authorized_writer_digest` for every epoch since the last checkpoint. Pre-checkpoint payloads become prunable by clients and servers without producing decryptable-but-unattributable history, because the checkpoint still proves who was authorized to write at epoch 7 even after the epoch-7 ADD/REMOVE payloads are gone.

**A6 â€” RETENTION CLASS IS A KEY-SCHEDULE PROPERTY, NOT A FLAG.** Two key classes per epoch: `K_durable`, and `K_eph(bucket)` for each configured disappearing window. `K_eph` is forward-ratcheted with old states deleted on schedule, is **never** included in the D5 at-rest wrap, and is **never** included in a device-provisioning bundle. A retained ciphertext in an expired bucket is undecryptable by every device in the world, including a newly provisioned one. Without this, "disappearing" is a UI animation.

**A7 â€” NO RETROACTIVE ACCESS BY DEFAULT.** A member or device added at epoch N receives key material from epoch N forward only. Protocol default, not a client setting. Retroactive access exists only as `HISTORY_GRANT` (Â§6), an explicit, epoch-range-bounded, k-of-n-gated, permanently-headered, UI-surfaced event. This is what separates legitimate device provisioning from a compromised admin exfiltrating three years of history as a routine `ADD_MEMBER`.

**A8 â€” RESIDUAL LEAK, STATED NOT DENIED.** After A1, the server still sees `retention_class` and `size_bucket`, because it must to prune. It therefore still sees "a PERMANENT-class record was written at time T" and can correlate that with a content-volume spike. Mitigations: control events are padded into the same size buckets as content; PERMANENT class is available to content (pinned messages); clients emit `COVER` records. This reduces the leak to a rate signal, not an event feed. It does not eliminate it, and Â§7 says so to users.

---

## 2. VERDICT ON V2 â€” ONE SERVER PER GROUP, NO REPLICATION

**Verdict: SURVIVES as the ordering and admission model. The user-facing claim ("each USER chooses their message server") is closer to false than true and must be re-worded. "Better than Matrix" holds on three axes, fails on two, and must be stated that way.**

The core of V2 is right and is externally validated: SimpleX, the most privacy-maximalist mainstream messenger, spent four years shipping fully-connected mesh groups and is now replacing them with dedicated super-peer relays â€” convergent evolution onto exactly V2. O(1) egress per message and a single authority on ordering are real, defensible wins over both Matrix and SimpleX. Keep them.

What fails is everything *else* Matrix's replication buys, which V2 discarded without replacement:

| Property | Matrix | V2 as proposed | V2 amended |
|---|---|---|---|
| Group scaling / egress | poor (per-server fanout, state res) | **better** | **better** |
| State resolution complexity | severe | **absent** | **absent** |
| Client-side indirection | yes (you speak only to your homeserver) | **lost** | restored (B2) |
| Availability when host dies | room survives elsewhere | **total loss** | partial (B3) |
| Second copy â†’ fork detection | yes | **lost** | partial (A3 + B4) |

### Required amendments

**B1 â€” UNWELD THE GROUP FROM ITS HOST.** `group_id = H(GENESIS)` where GENESIS carries a random 32-byte `group_nonce` and the founding admin set. **`server_id` is removed from the group_id preimage.** The host is a mutable, signed, chained field. Add `SERVER_MIGRATE{new_server_id, effective_epoch, prev_host_head_hash, reason}` requiring the same k-of-n admin quorum as membership changes (this is SimpleX's QADD/QKEY/QUSE queue rotation, lifted to group scope). Add `HOST_SUCCESSION_SET{standby_server_ids[], activation_rule}` so succession is pre-authorized before the host dies rather than after. Without B1, a group that detects its host misbehaving cannot leave, and the trust in the host is unbounded in scope and time.

**B2 â€” READ-THROUGH PROXY MODE, MANDATORY IN THE CLIENT.** Jane never speaks to a foreign host. She subscribes at her home server SrvB; SrvB maintains one long-poll subscription per (home server, foreign group), fetches ciphertext from SrvA, caches a rolling window, and serves her. SrvA remains the sole authority on ordering and admission â€” there is nothing to merge, no DAG, no state resolution. This is a CDN, not a replica.

- *Restores*: client-side indirection (the foreign host sees a server, not Jane's client, and never her ByJwt); offline read; local echo; a genuinely user-chosen server that actually carries her traffic.
- *Cost*: one subscription + a byte cache per (home server, foreign group); +1 RTT on cold reads, eliminated by pre-fetch on subscription; egress on the hostâ†’home hop is amortized across every member sharing that home server, so for any clustering at all it is **net cheaper** than N direct fetches. Estimated at ~5% of Matrix's federation complexity because none of the hard part (conflict resolution) is present.
- *New exposure, stated*: the home server learns the set of foreign groups its user participates in. It already learns she exists and when she is active. This is a strictly smaller disclosure than the status quo, where five foreign hosts each learn her identity directly.

**B3 â€” AVAILABILITY: CHECKPOINTS + MANDATORY CLIENT RETENTION + SUCCESSION.** Host death must degrade, not destroy.
- Every client MUST retain the full control **header** chain (A4) plus the latest `MEMBERSHIP_CHECKPOINT`. Sizing: ~100 bytes/header, compacted at checkpoints; a 200-member group at 2.5 devices/member with 500 epochs is ~50 KB of headers plus a one-time ~800 KB checkpoint (500 devices Ã— 32 B Ed25519 + 1568 B ML-KEM-1024 encaps key + 32 B). Fetched once, refreshed at checkpoints. This is trivially affordable and it means group identity, membership, epoch state, and the revocation record survive the host's death on every member's device.
- Home-server caches (B2) already hold a recent ciphertext window, so recent content survives too.
- On host loss, k-of-n admins activate a standby per `HOST_SUCCESSION_SET`, publish `SERVER_MIGRATE` binding `prev_host_head_hash`, and the group resumes from the newest checkpoint. Content older than the retained window is lost â€” **accept this**; D3-REVISED already made content deletable, so its loss is a degradation, not a violation.
- *Honest residual*: this is weaker than Matrix. Matrix's room survives because every participating homeserver holds a full replica. We survive because members hold the control chain and home servers hold a cache. State it plainly (Â§7).

**B4 â€” DECOUPLE CONTROL-PLANE DELIVERY FROM THE HOST.** Control events are self-authenticating under V4 â€” signed, position-bound, chained â€” so they need no trusted transport. Any member device MAY relay any control event to any other member directly over the URnetwork connect transport, or via that member's own home server. The host retains ordering authority (it assigns `record_id` and enforces gaplessness) but loses its **veto**. Without B4, a host suppressing writes from enough admins to keep the count below k freezes membership forever, deniably, and the stronger the k-of-n policy the cheaper the jam.

**B5 â€” WELCOME QUORUM.** A hash chain proves internal consistency, never completeness; a first-time joiner holds no independent anchor and will happily verify a truncated-and-re-rooted chain in which a revoked admin was never revoked. Therefore: a client accepts a join only if the control head is countersigned by the **inviter plus at least one other current member device**, obtained independently of the host. The inviter's countersignature rides inside the invite blob, which already exists as a server-side encrypted container (short links, Â§6), so it costs nothing.

**B6 â€” FETCH ATTESTATION.** On every fetch, the server returns a signed statement `{group_id, requested_range, record_ids_returned, server_time, sig}`. The server is not trusted; the point is that selective omission stops being deniable. A client that later learns of a record the attestation omitted holds a durable, publishable artifact. This converts "flaky mobile networking" into evidence and is roughly 200 lines of work.

**B7 â€” CONTRACT SHAPE (metadata, and this one is URnetwork-specific).** `transfer_contract` stores `source_network_id, source_id, destination_network_id, destination_id, transfer_byte_count, create_time, close_time` (`server/db_migrations.go:683-698`), indexed both directions (`:700-705`), retained 7 days past payout with a 90-day hard ceiling (`server/model/subscription_model.go:42-48`). With V2 as proposed, `SELECT DISTINCT source_network_id ... WHERE destination_id = <SrvB>` is the membership roster of every group SrvB hosts, complete with per-user volume and timing, in the operator's Postgres, requiring no plaintext and no misbehavior. Required:
- B2 alone collapses 42 member rows into ~11 home-server rows. That is the single largest win available.
- Additionally: terminate the user's contract at a URnetwork **provider hop** so the ledger records `Janeâ†”provider` and `SrvAâ†”provider`, never `Janeâ†”SrvA` â€” the same double-blind shape the VPN egress path already uses.
- Additionally: one long-lived contract per (device, home server) covering a billing window, rather than per-fetch contracts, so polling cadence stops being a timing feed.
- In the design's favor and worth recording: raw IPs are not stored, only peppered /29 and /56 hashes (`server/ip.go:40-66`), and `audit_contract_event` is now a daily aggregate with zeroed party ids (`server/model/audit_provider_sweep_model.go:972-1076`). The 7-to-90-day `transfer_contract` feed is the exposure.

### Re-worded product claim

Not "you choose your message server." Say: **"You choose the server your client talks to. Groups are hosted on one server chosen by whoever created them, and your client reaches it through yours."** That is true after B2, and it is the claim that survives contact with a user who joins six groups she did not create.

---

## 3. VERDICT ON V3 â€” TRUSTED OPERATOR

**Verdict: SURVIVES only if one sentence is deleted. "Message servers may accept operator assertions about identity linkage" is the single clause that collapses the entire trust boundary and must be struck.**

If SrvB admits a device because the operator vouched, the operator's signing key **is** a group-membership key, and membership is decryption. No amount of V4 crypto saves this: per-group KEM keys, injected commit secrets, and confirmation tags all faithfully wrap the new epoch secret to whatever the control plane says is a member. The operator does not break anything â€” it uses the authorization power the design granted it.

### The exact boundary

**Operator MAY:**
- Mint ByJwt for transport reachability and billing/contract creation. Nothing else.
- Route: create transfer contracts, provide connectivity between clients and message servers.
- Rate-limit, abuse-manage, and refuse service.
- Hold SSO linkage records and operate a **discovery directory** mapping `principal â†’ identity master key`, for social discovery only (D1's stated purpose).
- Publish that directory into a key-transparency log.

**Operator MUST NOT â€” structurally, not as policy:**
- **The control-plane event grammar MUST contain no event type whose validity can be satisfied by an operator signature.** `DEVICE_ADD` is valid only when signed by an already-authorized device of the same member, or by k-of-n admins under the D4/V4 policy. `MEMBER_ADD` is valid only under k-of-n. An operator assertion is never a substitute for either, and there is no field in any event where one could be placed.
- Message servers MUST NOT consult operator assertions when deciding group admission or key-wrap recipients. Operator assertions enter the system **only** as advisory UI hints in the discovery path, and are rendered as such.

### The mechanisms that bound it â€” named specifically

**M1 â€” KEY TRANSPARENCY (CONIKS/Signal-KT style).** The operator's `principal â†’ identity master key` directory is published as an append-only log over a Merkle prefix tree. Clients require an inclusion proof for every resolution and gossip signed tree heads (via message servers and via other members' clients, which are already talking to each other under B4). Consistency proofs make a rewrite detectable; inclusion proofs make an equivocating directory detectable. This converts "the operator vouches" from a trust grant into an **auditable public statement**. This is the primary bound and it is non-optional: without it, D1+D4's SSO vouching is unmitigated key substitution, and note the trust root isn't even the operator â€” `auth_model.go:125-153, :260-329` associates a new SSO auth onto an existing user when the `user_auth` string matches, so control of the Google or Apple account is control of the URnetwork identity. The operator can be perfectly honest and assert a true fact about its own database while the human behind the key has changed.

**M2 â€” CROSS-SIGNING (Matrix-style, adapted).** Each member has a master identity key (Ed25519, long-lived, in the KT log), a self-signing key that signs their own device keys, and a user-signing key that signs other members' master keys after out-of-band verification. `DEVICE_ADD` requires a self-signing-key signature from an already-authorized device of the same member, or k-of-n admins. This is precisely Session Protocol V2's device-group model â€” a team that shipped shared-identity-key multi-device, lived with it, and reversed. Strongest external validation available.

**M3 â€” SAFETY NUMBERS (Signal).** A comparable out-of-band fingerprint over the pair's master identity keys, per contact and per group. **TOFU pin outranks the operator**: once pinned, an operator assertion of a different key is never silently applied. It renders as a blocking warning and is written as a permanent `KEY_CHANGE_NOTICE` header in every shared group, marked with its evidence class ("vouched by Operator; not signed by Jane's prior key"). This is the negative signal V3 currently lacks. **A "verified" badge with no counterpart warning is a downgrade from Signal's silence**, and shipping the badge without M3 makes the product worse than Signal on the one axis users actually look at.

**M4 â€” PROOF OF POSSESSION AT THE MESSAGE SERVER.** This is what makes "not trusted with plaintext" a *property* rather than a *promise*. Today `server/connect/transport.go:471-501` authenticates a connect session with `ParseByJwtForAudience` + `ValidateByJwtState` + a network-membership lookup, and a grep for `ed25519|nonce|challenge|proof-of-possession` across `server/connect` returns zero. ByJwt is a pure bearer token; `by_jwt.go:399-420` lets the operator mint one with any NetworkId/UserId/DeviceId/ClientId it likes, and every state check reads rows in a database the operator owns. `registerConnection` allocates a fresh connectionId per connection, so a concurrent second session on the same client_id is ordinary, not anomalous.

Therefore: **a group subscription or write on a message server MUST additionally complete a challenge-response against the per-group write/read capability key**, whose authorizing chain terminates in a device key present in the group's control plane. Server sends a nonce; client returns a signature (or the deniable NaCl-box authenticator, below) over `nonce || group_id || epoch || purpose`. A minted ByJwt now gets the operator *transport reachability* and nothing else. One key theft is no longer a permanent global impersonation capability against groups.

**M5 â€” CAPABILITY-BASED WRITE AUTH (SimpleX SKEY, adapted).** The key the message server verifies is a **per-group, per-device, per-epoch capability key**, derived `HKDF(device_cap_root, "urmessage/cap/v2" || group_id || epoch)` â€” unrelated to and unlinkable from the member's identity key, and different in every group. The server authorizes writes without ever learning who is writing. Revocation is by epoch rotation, which the design already performs. Combine with the **deniable authenticator** (SimpleX's NaCl crypto_box variant) on the server-facing hop only: a seized or subpoenaed message server then holds **no transferable cryptographic proof** that a given member sent a given record. The end-to-end signature inside the ciphertext is unaffected and still gives members full sender authentication.

**M6 â€” NOTIFICATION CREDENTIAL SEPARATION (SimpleX NKEY/NID).** Each device gets a per-group notification credential distinct from its read and write credentials, so the push path cannot be joined to the fetch path. **Reject** SimpleX's refusal of platform push â€” we ship APNs/FCM (note: no push system exists in the server today; this is greenfield). The separation is cheap; the abstinence is not worth it at this product target.

**M7 â€” NORMATIVE MUST-NOT-LOG (SMP spec pattern).** The spec places prohibitions on the *implementation*, not on a policy page: message servers MUST NOT create, store, or transmit logs of client commands, transport connections, or a history of deleted records in production. Free to write, and once D4 makes "which server should I trust" a real user-facing question, it is the only thing a server operator can be held to.

---

## 4. DELETION SEMANTICS

Separate the three things that D3-REVISED currently conflates.

### 4.1 What is cryptographically guaranteed

**G1 â€” A deletion cannot be forged.** A `TOMBSTONE` is signed by the original sender's device, position-bound, and occupies a slot in that device's own stream. No server can manufacture one.

**G2 â€” A withheld deletion is detectable.** Because the tombstone occupies `stream_index` in the sender's gapless chain (A2), suppressing it creates a visible hole. Additionally, every device publishes a periodic signed `STREAM_DIGEST` â€” `{device_id, epoch, high_water_index, live_index_set, head_hash}` â€” at every epoch change and at most every N hours. **This is the load-bearing mechanism**: it models retraction as authenticated *state*, not as an event, so a client comparing the digest against what the server served detects a withheld tombstone directly. Without STREAM_DIGEST, a hostile host holds a free, permanent, undetectable veto on every deletion in the system, which is the single worst outcome available for a product whose headline privacy control is deletion.

**G3 â€” An expired disappearing message is undecryptable by everyone.** Under A6, messages in bucket B are encrypted under `K_eph(B)`, forward-ratcheted, deleted on schedule, excluded from the D5 at-rest wrap and from every provisioning bundle. Retained server ciphertext, seized devices, and freshly provisioned devices all fail to decrypt. **This is a genuine cryptographic guarantee and it is stronger than Signal's**, which relies on client cooperation only.

**G4 â€” Suppression is distinguishable from deletion.** A missing `stream_index` renders as a permanent, visually distinct "message from Jane unavailable" placeholder â€” not as a tombstone, and not as nothing. Users see the difference between "she deleted it" and "someone removed it."

**G5 â€” Retention floor is enforced by keys, not by server promise.** Server pruning policy is advisory. The key schedule is authoritative. A server that keeps everything gains nothing on ephemeral content.

### 4.2 What is NOT guaranteed

- **Delete-for-everyone cannot be enforced against a recipient who already decrypted.** Screenshot, archive, patched client. Same as Signal, same as every messenger. Not fixable.
- **Durable-class messages remain recoverable while epoch keys survive.** Durable is the default (D3-REVISED). A durable message deleted by its sender is removed from every honest server and every honest client, but a hostile server that retained the ciphertext and a party that later obtains the epoch key can read it. This is strictly weaker than Signal, whose server holds ciphertext only until delivery. It is the price of durable multi-device history and it is the correct trade for this product â€” but it must be stated, not buried.
- **The fact that a deletion occurred is not hidden.** The tombstone occupies a slot; the server sees a PERMANENT-class record from a writer handle. Padding and cover records blur the rate, not the fact.
- **Server-side prune is best-effort.** We can detect a lying server (G2, B6) after the fact. We cannot compel an honest one.

### 4.3 Required UI language (exact)

- Disappearing messages: **"After the timer, this message can no longer be read by anyone â€” the key is destroyed on every device and on the server."** (True under A6. Do not ship the feature without A6.)
- Delete for everyone: **"Removed from this conversation on every device that is online and honest. Anyone who already read it may have kept a copy, and we cannot detect that."**
- Default durable: **"Messages are kept so your new devices can see your history. That means the server holds a copy until it's deleted or expires."**
- Never say "gone forever" for the durable class. Never render a suppressed message as a tombstone.

---

## 5. REMAINING MUST-FIX (merged, deduplicated)

| # | Fix | Kills |
|---|---|---|
| **F1** | Per-writer gapless `stream_index` + `prev_record_hash` on **all** records, in AAD and under the position-bound signature | Silent drop/reorder; censorship-as-deletion; undetectable tombstone suppression |
| **F2** | `(epoch, control_seq, control_head_hash)` in every record's signed envelope; hard-fail and refetch on unknown head; fork alarm on backwards head | Epoch stall; server equivocation; revocation-by-silence |
| **F3** | `STREAM_DIGEST` published per device per epoch (retraction as signed state) | Withheld tombstones; the host's deletion veto |
| **F4** | Control chain covers **headers only**; payloads erasable | GDPR-impossible chain; forced group destruction to comply |
| **F5** | `MEMBERSHIP_CHECKPOINT` with per-epoch `authorized_writer_digest`; control plane is compactable, not "permanent" | Unbounded control growth; decryptable-but-unattributable history after compaction |
| **F6** | Welcome quorum: inviter + one other member device countersign the head, delivered out of band of the host | Truncate-and-re-root against a first-time joiner |
| **F7** | No retroactive key access by default; `HISTORY_GRANT` as an explicit, epoch-ranged, k-of-n, permanently-headered, UI-surfaced event | Compromised admin exfiltrating full history as a routine ADD_MEMBER |
| **F8** | Two key classes per epoch, `K_durable` / `K_eph(bucket)`; `K_eph` excluded from at-rest wrap and provisioning bundles | Resurrection of "disappeared" messages via device provisioning |
| **F9** | Remove `server_id` from the `group_id` preimage; `SERVER_MIGRATE` + `HOST_SUCCESSION_SET` under k-of-n | Group welded to a dead or hostile host; migration impossible |
| **F10** | Control events relayable by any member device, peer-to-peer or via own home server | Host veto over the k-of-n admin quorum |
| **F11** | Mandatory read-through proxy at the user's home server | Lost client indirection; 5 foreign hosts learning Jane's ByJwt; per-member contract rows against the host |
| **F12** | Contract shaping: provider-terminated hop + one long-lived contract per (device, home server) | `transfer_contract` as a subpoena-able membership graph |
| **F13** | Delete "Message servers may accept operator assertions about identity linkage" from V3; no control event satisfiable by an operator signature | Operator-as-membership-key; total collapse of the trust boundary |
| **F14** | Key transparency for the operator directory; cross-signing for devices; safety numbers with TOFU pin outranking the operator; `KEY_CHANGE_NOTICE` as a blocking, permanent event | Undetectable key substitution; SSO-account-takeover as identity takeover; a verified badge with no negative signal |
| **F15** | Proof-of-possession for group subscription/write against the per-group capability key; ByJwt authorizes transport and billing only | Operator minting a token and speaking as any member on any message server |
| **F16** | Per-group derived KEM key: `seed = HKDF(device_kem_root, "urmessage/kem/v2" \|\| group_id)` â†’ `mlkem.NewDecapsulationKey1024(seed)` (deterministic derivation confirmed present in go1.26.5), hybrid with per-group X25519 | Global device KEM key linking a device across every group |
| **F17** | Per-group per-epoch **capability** key for server-facing auth (SKEY pattern), deniable NaCl-box authenticator on the server hop | Message server learning identity keys; server holding transferable proof of authorship |
| **F18** | Unified record format; plane, type, and sender inside the ciphertext; bucketed padding (not flat 16 KB); `COVER` records | The two-plane split as a permanent server-side event feed |
| **F19** | Separate notification credential per (device, group), distinct from read/write | Push path joinable to fetch path |
| **F20** | Signed fetch attestation per response | Deniable selective omission |
| **F21** | `ADMIN_REDACT` distinct from user `TOMBSTONE`; suppressed records render as a distinct placeholder | Moderation masquerading as user deletion, and vice versa |
| **F22** | Spec-level normative MUST-NOT-LOG on server implementations | Nothing to hold a self-selected D4 operator to |

---

## 6. THE v2 EVENT MODEL

### 6.0 Common record structure

```
RECORD (server-visible header â€” cleartext to the hosting/home server)
  record_id          : opaque, server-assigned, fetch pagination only
  group_id           : 32B  = H(canonical(GENESIS))          [no server_id in preimage â€” F9]
  writer_handle      : 16B  per-group, per-epoch pseudonymous writer id
  epoch_hint         : u32  (epoch the writer_handle belongs to; enables per-epoch gapless enforcement)
  stream_index       : u64  gapless per (writer_handle, epoch_hint), server-enforced   [F1]
  prev_record_hash   : 32B  H(redacted form of this writer's previous record)          [F1]
  retention_class    : PERMANENT | DURABLE | EPH(bucket_id)                            [A6]
  size_bucket        : u8   (256B / 1K / 4K / 16K / 64K / blob-ref)                    [F18]
  expire_at          : u64  (advisory; keys are authoritative)
  cap_auth           : capability-key signature OR deniable NaCl-box authenticator     [F17]
                       over (group_id â€– writer_handle â€– epoch_hint â€– stream_index â€– prev_record_hash â€– H(ct))
  ct                 : padded ciphertext

INNER (AEAD under K_durable(epoch) or K_eph(epoch,bucket); AAD = full header above)
  plane              : CONTROL | CONTENT           [client-only distinction â€” F18]
  type               : event type (below)
  epoch              : u32
  control_seq        : u64                          [F2]
  control_head_hash  : 32B                          [F2]
  sender             : {member_id, device_id}
  sent_at            : u64
  payload            : type-specific
  sig                : Ed25519 by device key over
                       group_id â€– epoch â€– control_head_hash â€– control_seq â€– plane â€– type
                       â€– writer_handle â€– epoch_hint â€– stream_index â€– prev_record_hash â€– H(payload)
                       [position-bound â€” V4]
```

Control records additionally split `payload` into an erasable body with only `H(payload)` chained (F4). Writer-handle continuity across epoch rotation is asserted inside the ciphertext, never to the server.

### 6.1 CONTROL PLANE event types

**`GENESIS`** â€” `{version, group_nonce:32B random, founding_members[{member_id, master_key_ed25519}], admin_policy{k, n, roster[member_id]}, cipher_suite{kem: X25519+ML-KEM-1024, sig: Ed25519, aead, kdf}, initial_host{server_id} (SIGNED FIELD, NOT IN group_id PREIMAGE), retention_defaults{durable, eph_buckets[]}, cap_derivation_params}`. `group_id = H(canonical(GENESIS))`.

**`EPOCH_COMMIT`** â€” `{epoch_new, prev_epoch_head_hash, proposals[refs], commit_secret_wraps[{device_id, hybrid_ct(X25519 â€– ML-KEM-1024)}], transcript_hash, confirmation_tag (MAC over transcript under the epoch confirmation key), signer}`. Injected `commit_secret` per V4. Wraps live in the erasable payload. Emitted mandatorily after every MEMBER_REMOVE / DEVICE_REVOKE / ROLE_SET-to-OBSERVER.

**`MEMBER_ADD`** â€” `{member_id, master_key_ed25519, kt_inclusion_proof (ADVISORY ONLY), role, history_scope = FROM_EPOCH(current) [F7], admin_sigs[k-of-n]}`. No operator signature is a valid authorizer â€” there is no field for one. [F13]

**`MEMBER_REMOVE`** â€” `{member_id, reason_code, admin_sigs[k-of-n]}`.

**`DEVICE_ADD`** â€” `{member_id, device_id, device_ed25519_pub, device_kem_pub{x25519, mlkem1024} (per-group derived, F16), cap_pub_epoch, notif_cred_pub (F19), authorizer âˆˆ {self_signing_sig by an already-authorized device of the SAME member | admin_sigs[k-of-n]}}`. [M2/F14]

**`DEVICE_REVOKE`** â€” `{member_id, device_id, reason, authorizer âˆˆ {other device of same member | admin_sigs[k-of-n]}}`. Forces EPOCH_COMMIT.

**`ADMIN_POLICY_UPDATE`** â€” `{new_k, new_n, new_roster, effective_epoch, admin_sigs[current k-of-n]}`.

**`ROLE_SET`** â€” `{member_id, role âˆˆ {OWNER, ADMIN, MEMBER, OBSERVER}, sigs per hierarchy}`. OBSERVER = decryption rights, no write capability; the server refuses writes from an observer's `writer_handle`, so it is enforced at both layers.

**`HISTORY_GRANT`** â€” `{target{member_id, device_id}, epoch_range{from, to}, expiry, justification_code, admin_sigs[k-of-n], epoch_secret_wraps[]}`. Non-erasable header. MUST render as a persistent banner in every member's UI. Absent by default. [F7]

**`SERVER_MIGRATE`** â€” `{new_server_id, effective_epoch, prev_host_head_hash, reason, admin_sigs[k-of-n]}`. [F9]

**`HOST_SUCCESSION_SET`** â€” `{standby_server_ids[], activation_rule{unreachable_for, quorum}, admin_sigs[k-of-n]}`. [F9/B3]

**`MEMBERSHIP_CHECKPOINT`** â€” `{epoch, control_seq, control_head_hash, members[{member_id, master_key, role, devices[{device_id, ed25519, kem_pub}]}], admin_policy, host_chain[{server_id, from_epoch}], authorized_writer_digest[epoch â†’ H(authorized device set)] since last checkpoint, admin_sigs[k-of-n]}`. Enables compaction, joiner validation, and host-death survival. [F5/B3/B5]

**`RETENTION_POLICY_SET`** â€” `{durable_default, eph_buckets[{bucket_id, window}], server_min_retention (advisory), admin_sigs[k-of-n]}`.

**`KEY_CHANGE_NOTICE`** â€” `{member_id, old_master_key, new_master_key, evidence_class âˆˆ {SIGNED_BY_PRIOR_KEY, ADMIN_ATTESTED, OPERATOR_ASSERTED_ADVISORY}, kt_proof}`. Non-erasable. `OPERATOR_ASSERTED_ADVISORY` renders as a blocking warning and never auto-applies over a TOFU pin. [F14/M3]

**`GROUP_META`** â€” `{name, avatar_ref, description, conversation_prefs}`, admin-signed, small.

**`WELCOME`** *(delivered to the joiner out of band; not appended to the chain)* â€” `{MEMBERSHIP_CHECKPOINT, control_head, inviter_countersig, second_member_countersig [F6], epoch_secret_wraps from history_scope forward, host{server_id}, short_link_binding}`.

**Invites (COPY â€” SimpleX short links).** An invite is a <80-char short link resolving to a **server-side encrypted container** holding the full blob: group_id, host server_id, PQ key material, group profile, conversation preferences, and the welcome-quorum countersignatures. One-time invitations and reusable publishable addresses are distinct objects; revoking a published address does not disturb existing connections. Highest value-per-complexity mechanism in the reference corpus and directly aligned with the product target.

### 6.2 CONTENT PLANE event types

**`MESSAGE`** â€” `{body{text | attachment_refs[] | reply_to{device_id, stream_index}}, retention_class, mentions[]}`.

**`ATTACHMENT_BLOB`** â€” separately fetched, own content key, inherits the parent's retention class and key class.

**`EDIT`** â€” `{target{device_id, stream_index}, new_body}`. Signed by the original sender's device. Occupies a new slot.

**`REACTION`** â€” `{target{device_id, stream_index}, emoji}`. Inherits target retention class.

**`TOMBSTONE`** *(user delete)* â€” `{target{device_id, stream_index}, scope âˆˆ {SELF, EVERYONE}}`. Signed by the original sender's device. Occupies a slot in the deleter's own stream. [F1/F3]

**`ADMIN_REDACT`** *(moderation â€” distinct type, distinct UI)* â€” `{target{device_id, stream_index}, admin_sigs per policy, reason_code}`. [F21]

**`STREAM_DIGEST`** â€” `{device_id, epoch, high_water_index, live_index_ranges (compressed), head_hash, sig}`. Published at every epoch change and at most every N hours. **The mechanism that makes deletion verifiable-delivery.** [F3]

**`RECEIPT`** â€” `{delivered_up_to | read_up_to}`, batched, disableable, EPH class.

**`PRESENCE` / `TYPING`** â€” EPH bucket 0, never persisted.

**`COVER`** â€” padding record, indistinguishable in class and size bucket, discarded by clients. Blurs the PERMANENT-class rate signal. [F18/A8]

### 6.3 Explicitly rejected (record the rejections in the spec so they are not re-litigated)

- Onion routing inside URmessage â€” connect already provides multi-hop with X25519MLKEM768.
- Flat 16 KB padding â€” bucketed only; our egress is O(1) per message, so length-hiding is cheap but flat blocks are not worth 1.6 MB per one-character group message.
- Per-pairwise double ratchet as the group layer â€” O(NÂ²) state, no shared group secret. The ratchet is fine; per-pair application is the problem.
- Swarm replication / deterministic node assignment â€” incompatible with D4's user-chosen server.
- Identifier-free resource addressing â€” ruled out by the product target; it is the root cause of every SimpleX usability complaint.
- Shared group signing key â€” destroys in-group sender authentication.
- Database-as-identity with no recovery â€” V4 already rejects it; device provisioning replaces it.
- Signature algorithm: Ed25519 with an algorithm-agility field. ML-DSA is `crypto/internal` only in go1.26.5, so no public API. Signal and Apple are in the same position; this is mainstream, not a compromise.

---

## 7. HONEST-LIMITS â€” what to tell the user plainly

Calibrated to "slightly better than Signal, not as insane as SimpleX."

**Where we are better than Signal**
1. You choose the server your client talks to. Signal has one.
2. Disappearing messages are enforced by key destruction, not by client cooperation. When the timer expires, no device and no server can read it â€” including a device you set up tomorrow.
3. Post-quantum protection for stored messages, not just for the connection: hybrid X25519 + ML-KEM-1024 wrapping.
4. Your history follows you to a new device without anyone mailing a private key around, and without a new device being able to reach back past the day it was added.
5. Missing messages are visible. If a server drops one, you see a gap, not silence.

**Where we are the same as Signal**
6. Nobody can read your messages but the group. Servers hold ciphertext.
7. "Delete for everyone" cannot claw back what someone already read, screenshotted, or archived. No messenger can.

**Where we are honestly worse than Signal, and why**
8. **The server that hosts a group knows who is in it.** Signal hides group membership from its own server using anonymous credentials; we do not. This is the price of one host per group, which is also what makes our groups scale.
9. **We keep messages by default.** Signal's server forgets a message once it is delivered. We store it so your other devices and your next phone can see your history. A hostile host that ignores its own deletion policy keeps a copy it may be able to read later. Turn on disappearing messages for anything you would not want stored.
10. **The URnetwork operator can see that your device talks to a given message server, and how much.** It cannot read anything. Billing records this pairing for up to 90 days. We reduce it by routing through your own server and through a provider hop, but we do not eliminate it.
11. **You do not choose the server for groups you did not create.** The person who created the group chose it. Your client reaches it through your own server, so it does not learn who you are â€” but it does host your group's messages.

**Where we are better than Matrix**
12. One message costs one upload regardless of group size, so large groups work on a phone.
13. There is no conflicting-history problem to resolve, because each group has exactly one authority on ordering.
14. Membership records can be erased on request. Matrix's cannot.

**Where we are honestly worse than Matrix**
15. **If a group's host server disappears permanently, recent messages can be lost.** Membership, admin history, and group identity survive on every member's device, and the group can be moved to a new server by its admins â€” but Matrix's rooms survive on every participating server, and ours do not. This is a deliberate trade for the two wins above.

**Where we deliberately did not go as far as SimpleX**
16. We use durable identities and a searchable directory, so you can be found, re-added, and recovered. SimpleX refuses all three. That refusal buys metadata resistance we decided is not worth the product it produces.
17. Servers can see *that* you are active in a group and roughly how much, even though they cannot see what you say or, with the capability system, prove who said it.

**The one thing users must be told about verification**
18. **A "verified" badge from the operator is a convenience, not a proof.** If someone takes over the email or Apple/Google account behind an identity, the operator will honestly vouch for a key belonging to the wrong person. Compare safety numbers in person or over a call for anything that matters. We will always show you a blocking warning when a contact's key changes, we will never silently accept a change over a key you have already pinned, and every such change is written permanently into the group's record.
