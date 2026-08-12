# URmessage — Protocol Design

**Date:** 2026-08-12
**Revision:** 5 — single-server v1; storage layer simplified; MLS contract corrected; X-Wing adopted
**Status:** Design, pending approval

Notation: `LP(x)` = 32-bit length prefix then `x`. `u8/u32/u64` = big-endian fixed width. `‖` =
concatenation. `H` = SHA-256. HKDF is HKDF-SHA-256.

---

## 0. Revision history and what it cost

**Revisions 1–2** specified a bespoke group key agreement layer. Two independent reviews found 10
then 12 blocking cryptographic defects in it.

**Revision 3** deleted that layer and adopted **MLS (RFC 9420)**, implemented in-house. The review of
revision 3 found **zero** defects in group key agreement — the tree, epoch schedule, membership
changes, and fork detection drew no findings at all. That category is closed.

It also found that revision 3 **overclaimed** what delegation achieved. Adopting MLS did not resolve
the earlier blockers; it narrowed the remaining work to a smaller custom layer, where nine of them
reappeared re-expressed, and three new ones were introduced by misreading MLS's contract:

- §9.3 claimed MLS resolves concurrent commits. It does not — RFC 9420 provides fork *detection*;
  RFC 9750 §5.2 assigns single-commit agreement to the Delivery Service. Corrected in §9.3.
- §8.3 assumed an MLS exporter output could regenerate sibling secrets. RFC 9420 §8.1 makes them
  independent derivations. Corrected in §8.3.
- §6 asserted a credential check RFC 9420 §7.3 does not perform. Corrected in §6.

**Revision 4** narrows v1 to **one operator, one message server, many providers**, which removes the
read-through proxy, per-epoch handle rotation, and per-device capability blinding — the three
mechanisms responsible for most of the remaining blockers. It also adds §3, an explicit invariant
list, because two revision-3 defects were contradictions of an invariant stated a line away.

**Revision 5** replaces the hand-rolled hybrid-KEM combiner with **X-Wing**, and makes
[OpenMLS](https://github.com/openmls/openmls) the reference oracle in place of a 24-star Go
repository. Both changes came from the project owner finding OpenMLS. The combiner was the last
hand-rolled cryptographic composition in the document and had drawn a finding in every review round;
it is now a construction with a published security proof. The cost is ML-KEM-768 rather than 1024,
taken deliberately — see §7.

## 1. Purpose and product target

URmessage is a private messenger built on the URnetwork mesh. It reuses URnetwork's transport and
provider relaying, and adds what transport cannot provide: **durable offline delivery** and **group
cryptography**.

> "Slightly better than Signal, not as insane as SimpleX. Kinda like Matrix but better."

A weakness Signal also has is acceptable; being worse than Signal is not. Metadata resistance that
costs usability is rejected.

## 2. Scope

**v1 topology:** one operator, one message server, many providers carrying traffic. Multi-server is
V2 — the wire format keeps `server_id` fields so it is not a format break, but no code implements it.

**v1 ships:** text messaging (DMs and groups), full multi-device, disappearing messages, safety
numbers with key-change warnings, reactions, read receipts and typing indicators, attachments and
images, and a WinUI 3 Windows client reusing the VPN app's shell and branding.

**Deferred to V2+, type codes reserved so none is a format break:** message editing, multi-server and
read-through proxy, group migration between hosts, stream digests, per-device write capabilities,
voice and video (relayed through providers, not peer-to-peer), public groups, history export, mobile
clients.

**Cross-platform:** `connect` and `sdk` changes must build for all supported platforms from the
start. Windows is implemented first; platform notes are written as Windows development surfaces them.

**Permanent non-goals:** anonymity against a global passive adversary; deniability of authorship to
other group members; protection against a recipient who screenshots or archives.

## 3. Invariants

Every other section MUST satisfy these. A section that appears to contradict one is wrong, not an
exception.

- **I1.** The URnetwork operator never receives plaintext, never stores message records, and no MLS
  proposal or commit is valid on an operator signature.
- **I2.** No device-held group secret is derivable from the seedphrase. Device keys are generated
  on-device from a local CSPRNG and sealed to the platform keystore. A device that could derive its
  keys from the seed would hold the seed, and revocation would mean nothing.
- **I3.** `recovery_root` (§5.2) is the **only** master-derived group-usable secret.
- **I4.** Ephemeral-class key material is never wrapped to a recovery key, never included in a
  provisioning bundle, and never derivable from any durable secret.
- **I5.** Sender authentication is MLS's, end-to-end. The storage layer adds no second signature over
  content, and the server's checks are access control only — never authenticity.
- **I6.** Anything the server acts on is covered by an authenticator the server can verify. Anything
  the server cannot verify, it MUST NOT act on.
- **I7.** No AEAD key or nonce is ever used twice, and no AAD is computed from a value that depends on
  the ciphertext it protects.
- **I8.** Any field a client validates is either inside the MLS-authenticated payload or covered by
  `write_auth`. Nothing load-bearing is unauthenticated cleartext.

## 4. Trust model

### 4.1 Actors

| Actor | Role |
|---|---|
| **Client** | Holds the seedphrase and all keys. The only place plaintext exists. |
| **Message server** | Stores ciphertext, orders records, serves history, prunes. One in v1. Holds its own URnetwork account for routing. |
| **Operator** | URnetwork platform. Authorizes transport, mints contracts, routes to providers, runs the discovery directory and key-transparency log. **Forwards traffic; never stores message records.** |
| **Provider** | URnetwork relay. Sees ciphertext in transit only. |

### 4.2 The operator boundary

**MAY:** mint `ByJwt` for transport and billing; create contracts and route; rate-limit and refuse
service; run a discovery directory mapping `principal → identity master key`; publish it to a
key-transparency log.

**MUST NOT:** store message records; satisfy any MLS proposal or commit's validity condition; be
consulted by the message server on group admission. Operator assertions are advisory UI hints in
discovery only.

If the server admitted a device because the operator vouched, the operator's signing key would *be* a
group-membership key, and membership is decryption.

### 4.3 Transport identity cannot be reused

`server/connect/transport.go:471-501` authenticates a connect session by parsing a `ByJwt`,
validating its state, and checking network membership — no challenge-response; a grep for
`ed25519|nonce|challenge|proof-of-possession` across `server/connect` returns nothing. `ByJwt` is a
bearer token and every check reads a database the operator owns.

Correct for a VPN transport; unusable as messaging authorization. Group writes carry `write_auth`
(§9.2). `ByJwt` authorizes transport and billing only.

Note this is defence in depth, not the primary protection: by **I5**, a record forged by anyone
without a group leaf key fails MLS verification at every client regardless of what the server accepts.

### 4.4 A URnetwork account is required

`ContractManager.CreateContract` (`transfer_contract_manager.go:1278-1305`) obtains a contract by
sending a control frame to `ControlId` — the platform — which requires a `ByJwt`. URmessage cannot
operate without a URnetwork account. What is optional is *linking* the messaging identity to a
human-identifiable SSO account. The message server likewise holds its own account; that credential is
a server-side secret.

## 5. Identity and key custody

### 5.1 The seedphrase is new and client-generated

URnetwork already has a seedphrase (`sdk/api.go:2284`). **It must not be reused.**
`model/auth_model.go:42` defines `AuthTypeSeedphrase` as a login type and `:168-169` passes the
plaintext phrase from the request body into `LoginWithSeedphrase`, so the operator receives it on
every login. Deriving message keys from it would hand the operator every private key.

URmessage generates its own BIP39 24-word mnemonic on-device, never transmitted. The two secrets are
never derivable from each other.

### 5.2 What the seed derives — and what it does not

Per **I2** and **I3**:

```
BIP39 24-word mnemonic  →  PBKDF2-HMAC-SHA512, 2048 rounds  →  64-byte seed
master_key = HKDF-Extract(salt = "URmessage/v1", ikm = seed)                  [32 B]

master_key
├─ identity      = HKDF-Expand(master_key, "identity/v1", 32)  → Ed25519 master identity
│                    (the MLS credential subject; published in the KT log)
└─ recovery_root = HKDF-Expand(master_key, "recovery/v1", 32)
     ├─ per group g:  rk_xwing = XWing.KeyGen(
     │                    HKDF-Expand(recovery_root, "rk/v1" ‖ LP(g), 96))            [96 B]
     └─ recovery_handle = HKDF-Expand(recovery_root, "idx/v1", 16)
```

X-Wing key generation is deterministic from a seed — `crypto/mlkem`'s `NewDecapsulationKey768(seed)`
plus a derived X25519 scalar — so the recovery key is reconstructible from the mnemonic alone, which
is what makes seed-only restore work.

**Generated on-device, never seed-derived**, sealed to the platform keystore (DPAPI on Windows):

```
device_sig      Ed25519    the MLS leaf signature key
device_xwing    X-Wing     hybrid KEM wrap target (X25519 + ML-KEM-768)
```

There is no `pq_root`. A seed-derived per-device key would violate I2 and make `Remove` meaningless.

### 5.3 Publishing device and recovery public keys

Device public keys travel in an MLS LeafNode extension so they are covered by the LeafNode signature
and the tree hash, validated per RFC 9420 §7.3, and removed by `Remove` along with the rest of the
leaf:

```
extension urmessage_leaf_keys {
    u16  alg_id
    LP   device_xwing_pub
}
```

Listed in `required_capabilities.extension_types`.

Recovery public keys are **member**-scoped, not device-scoped, so they cannot live in a leaf. A
member publishes them once at join and again on any identity change:

```
RECOVERY_PUB { group_id, LP(rk_xwing_pub), u16 alg_id }   signed under `identity`
```

carried as a `PERMANENT`-class record. Without this the committer cannot construct a recovery wrap at
all, because `recovery_root` is known only to its owner.

### 5.4 Device provisioning

1. Existing device shows a QR with an ephemeral X25519 public key and a nonce.
2. New device performs an authenticated handshake over connect; both users compare a short
   authentication string.
3. Existing device sends the group list and **durable-class** archive material. Ephemeral-class
   material is never included (**I4**).
4. Existing device issues an MLS `Add` for the new device's leaf and commits it.

**Seed-only restore** is the documented last resort: a bare seed derives `recovery_handle` and asks
the server for the archive records indexed under it. The server learns how many groups that handle
participates in — and in a single-server v1 it already knows the user's full group list, so this adds
nothing it did not have. Disclosed in §13.

### 5.5 Identity reset after seedphrase loss

Seed-only restore (§5.4) covers a user who still holds the mnemonic. A user who has **lost** it has no
recovery path for their existing identity — by design, since `identity` derives from the seed and
nothing else does.

The operator may reset the account's *linkage*, which issues the user a **new** master identity. This
is a rotation of the published identity key, and §13's "cannot be rotated" refers to recovering the
old one: the old key and everything encrypted to it are permanently gone.

Consequences, all mandatory:

- All history under the old identity is unrecoverable. No archive wrap targets the new key.
- The new identity is **not** automatically admitted to any group. Admins must re-add it via
  `Add`, exactly as for a new member. Automatic re-admission would be the key-substitution attack of
  §10.2 performed by the operator.
- Every contact holding a pin on the old key sees the blocking `KEY_CHANGE_NOTICE` warning of §10.2,
  with `evidence_class` recording that the operator asserted it and no prior key signed it.
- The reset is written to the key-transparency log (§10.1), so it is publicly auditable and cannot be
  performed quietly.

Reset is rate-limited with a cooldown measured in days. The existing operator precedent
(`model/account_action_rate_limit.go`, 5 per day for seedphrase regeneration) is far too permissive
for an end-to-end-encrypted identity.

## 6. Group layer — MLS (RFC 9420)

All group key agreement is MLS. This document records only the choices we make within it.

**A DM is a group with exactly two members.** There is no separate pairwise path, no second
encryption codepath, and no distinct wire format — a DM differs from a group only in member count and
in how the client renders it. Group creation, epochs, and membership changes are identical.

| Concern | Handled by |
|---|---|
| Group creation, epochs, key schedule | RFC 9420 §8 |
| Membership changes | `Add` / `Remove` / `Update` proposals + `Commit`, §12 |
| Devices | One MLS **leaf per device**; revoking a device is a `Remove` |
| Per-sender message keys and nonces | Secret tree, §9 |
| Fork **detection** | `confirmed_transcript_hash` + `confirmation_tag`, §8.1 |
| Single-commit **agreement** | The Delivery Service — our message server, §9.3 |
| Joining | `Welcome`, §12.4.3 |

**Ciphersuite:** `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003). ChaCha20 rather than
AES-GCM, to match the stack and avoid AES-NI assumptions on ARM64.

**Credential:** `BasicCredential` carrying the member's `identity` public key. RFC 9420 §7.3 does
**not** verify that a credential corresponds to any external identity — it validates signature and
capability consistency only. Binding `identity` to a human is entirely our job, and is done by the KT
log plus local pinning (§10). The spec must not assume MLS checks this.

**Extensions:** `required_capabilities`; `urmessage_leaf_keys` (§5.3); and a group-context extension
carrying `{roles, retention_policy, disappearing_buckets, server_id}`, so those are covered by the
transcript hash and no server can alter them.

**Test vectors:** slice 1 MUST pass the RFC 9420 vectors for tree-math, crypto-basics, secret-tree,
key-schedule, psk_secret, transcript-hashes, welcome, tree-validation, treekem, message-protection,
and messages. **[OpenMLS](https://github.com/openmls/openmls) is the reference oracle** — read and
tested against, never shipped. It is maintained by Phoenix R&D (Raphael Robert co-authored RFC 9420)
and CE Labs, with 1.0k stars and 170 forks, which makes it far better provenance than any Go
implementation available. It is Rust, so it is a cross-check, not a dependency: a pure-Go MLS builds
everywhere gomobile already goes — Windows, macOS, Linux, iOS, Android — with no Rust toolchain in CI
and no per-platform static-library cross-build.

**This is the acceptance criterion for slice 1** — not "it works," but "the vectors pass."

**Group size:** design target 500. TreeKEM is O(log n); the practical limit is Welcome size and client
memory, not the ratchet.

## 7. Post-quantum composition

MLS post-quantum ciphersuites remain an Internet-Draft
([draft-ietf-mls-pq-ciphersuites-01](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/),
Nov 2025), so our ciphersuite is classical and post-quantum protection is added at the **storage**
layer, following [draft-ietf-mls-combiner](https://datatracker.ietf.org/doc/html/draft-ietf-mls-combiner-02)
rather than an invented composition. Signal uses the same shape in both PQXDH and SPQR: combine the
classical and post-quantum secrets so an adversary must break **both**.

There are two distinct compositions here, and only one of them is ours.

**The hybrid KEM — not ours.** Use **X-Wing**
([draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)),
which combines X25519 with ML-KEM-768 in a construction carrying a published security proof. This is
the same KEM OpenMLS adopted for its post-quantum ciphersuite, built on Cryspen's formally verified
libcrux primitives. It replaces the hand-rolled `ss_x25519 ‖ ss_mlkem` combiner of earlier revisions,
which was the most dangerous composition in this document.

**The MLS/PQ secret combination — ours, but standard.** Combining an MLS-derived secret with an
externally delivered post-quantum secret is the pattern of
[draft-ietf-mls-combiner](https://datatracker.ietf.org/doc/html/draft-ietf-mls-combiner-02), and the
dual-PRF `HKDF-Extract(salt = A, ikm = B)` shape is the same one Signal uses in PQXDH and SPQR.

At each epoch the committer samples `pq_secret[n]` (32 B CSPRNG) and X-Wing-encapsulates it to every
active device leaf's `urmessage_leaf_keys` and to every member's `RECOVERY_PUB`:

```
mls_secret[n]   = MLS-Exporter("URmessage/v1/storage", "", 32)          RFC 9420 §8.5
storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n])

(ct_xwing, ss)  = XWing.Encapsulate(target_xwing_pub)
wrap_key        = HKDF-Expand(ss, "URmessage/v1/wrap" ‖ LP(group_id) ‖ u64(epoch)
                                 ‖ LP(target_id), 32)
hybrid_ct       = u16(alg_id) ‖ LP(ct_xwing) ‖ LP(aead_ct)
```

`urmessage_leaf_keys` therefore publishes a single X-Wing public key rather than separate X25519 and
ML-KEM halves; §5.2 and §5.3 read accordingly.

Harvesting today's classical MLS handshake is insufficient, because `pq_secret` arrived under X-Wing.
Transit is already hybrid — `connect/transfer_encrypt.go:378` leads with `X25519MLKEM768`.

**Parameter note.** X-Wing is fixed at ML-KEM-768 (NIST Level 3), not the ML-KEM-1024 chosen earlier.
This is a deliberate trade: the combiner was the risk, not the parameter, and a construction with a
security proof at Level 3 beats a hand-rolled one at Level 5. Level 5 is revisited when
draft-ietf-mls-pq-ciphersuites becomes an RFC and offers a standardized option.

**Caveat.** X-Wing has no IANA MLS code point yet, so it is a documented draft rather than a ratified
standard, and interoperability with other MLS deployments is not guaranteed. Acceptable here because
we use it in our own storage layer, not in the MLS ciphersuite itself.

**Migration:** when the PQ ciphersuites become an RFC we adopt one and `pq_secret` becomes redundant.
The algorithm identifiers below make that a ciphersuite change, not a format break.

### 7.1 Algorithm agility

Every signature, authenticator, hybrid ciphertext, and published public key carries `alg_id` (u16),
inside the signed bytes so it cannot be stripped or downgraded.

| `alg_id` | Meaning |
|---|---|
| `0x0001` | Ed25519 |
| `0x0011` | X25519 |
| `0x0014` | **X-Wing (X25519 + ML-KEM-768)** — v1 wrap KEM |
| `0x0021` | XChaCha20-Poly1305 |
| `0x0031` | HKDF-SHA-256 |

Reserved, not implemented in v1: `0x0002` ML-DSA-87; `0x0012` ML-KEM-1024; `0x0013` hybrid
X25519 + ML-KEM-1024, for the Level 5 revisit described above.

### 7.2 Implementation guardrails

All X25519 operations MUST use `crypto/ecdh` or `curve25519.X25519` and MUST treat a returned error
as a hard validation failure. `sdk.GenerateSharedSecret` (`sdk/sdk.go:804-817` — length-checks only,
reaches deprecated `ScalarMult` via `box.Precompute`, yields an all-zero shared secret on a low-order
point), `box.Precompute`, and `curve25519.ScalarMult` MUST NOT be used. Any key-agreement or
signature mismatch MUST return an error; logging and continuing is prohibited.

`crypto/mlkem` is in the Go 1.26.5 standard library, verified by running `go doc crypto/mlkem`
against the pinned toolchain: it provides both `DecapsulationKey768` and `DecapsulationKey1024`, each
with seed-based construction, and its own documentation states *"Most applications should use the
ML-KEM-768 parameter set."* X-Wing is therefore implementable on stdlib primitives alone —
`crypto/mlkem` for ML-KEM-768, `crypto/ecdh` for X25519, plus the X-Wing combiner KDF — with no
external dependency. Slice 1 pins the Go version and includes a compile assertion on
`mlkem.NewDecapsulationKey768`.

X-Wing MUST be implemented exactly as specified in the draft, including its domain-separation label
and the ordering of inputs to the combiner. It MUST be validated against the draft's test vectors
before use; a "roughly equivalent" combiner forfeits the security proof that is the entire reason for
choosing it.

## 8. Storage layer

MLS produces `PrivateMessage` objects. This layer is the envelope that stores them durably, lets them
be deleted, and lets the server order and prune without decrypting.

```
RECORD
  record_id        server-assigned AFTER acceptance; pagination only; never authenticated
  group_id         32B
  sender_handle    16B  = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)
                         stable per group; every member computes it; the server cannot invert it
  epoch            u64
  stream_index     u64  monotonic per (sender_handle); write-once
  is_commit        u8   1 on an MLS Commit record — the server acts on this, so it is authenticated
  retention_class  u8   PERMANENT | DURABLE | MEDIA | EPH(bucket)
  size_bucket      u8   256B / 1K / 4K / 16K / 64K / blob-ref
  expire_at        u64  advisory; keys are authoritative
  body_hash        32B  H(ct_body); RETAINED when ct_body is erased
  ct_head          AEAD, always retained; MLS PrivateMessage header, type, sent_at
  ct_body          AEAD, erasable; the MLS PrivateMessage payload
  write_auth       MAC, computed last; see §9.2
```

Per **I7**, the two ciphertexts use **distinct keys and distinct AADs**, and `body_hash` appears only
in the head's AAD — never in the body's, which would be circular:

```
AAD_body = "URmessage/v1/aad/body" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
         ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(retention_class)

AAD_head = "URmessage/v1/aad/head" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
         ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit) ‖ u8(retention_class)
         ‖ u8(size_bucket) ‖ u64(expire_at) ‖ LP(body_hash)

key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)
key_body ‖ nonce_body = HKDF-Expand(record_key[i], "rec/v1/body", 56)
```

Construction order: encrypt `ct_body` → compute `body_hash` → encrypt `ct_head` → compute
`write_auth`. Every dependency is acyclic.

Per **I5**, this layer adds no signature. Sender authentication is MLS's, inside the ciphertext.

`stream_index` is assigned write-once and locally: a device MUST durably record "index k consumed"
*before* encrypting, and MUST NEVER encrypt a second record at a consumed index. The server enforces
monotonicity, not strict contiguity, so a refused write does not brick the stream.

`sender_handle` is stable per group rather than rotating per epoch. Per-epoch rotation existed to stop
*foreign* hosts linking a member across epochs; with one server that the client authenticates to, it
bought nothing and cost three defects. `group_handle_key = HKDF-Expand(storage_root[0], "gh/v1", 32)`
— fixed at group creation so the handle survives epoch changes.

### 8.1 Retention classes and their keys

```
storage_root[n]
├─ K_perm[n]    = HKDF-Expand(storage_root[n], "perm/v1", 32)
├─ K_durable[n] = HKDF-Expand(storage_root[n], "durable/v1", 32)
├─ K_media[n]   = HKDF-Expand(storage_root[n], "media/v1", 32)
└─ eph_root[n]  = 32 B fresh CSPRNG at commit  ← NOT derived from storage_root (I4)
     └─ K_eph[n][b][t] = HKDF-Expand(eph_root[n], "eph/v1" ‖ u8(b) ‖ u64(t), 32)

record_key[0]   = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)
record_key[i+1] = HKDF-Expand(record_key[i], "ratchet/v1", 32)
```

A real forward ratchet: the sender overwrites `record_key[i]` after use, keeping a bounded skipped-key
window for out-of-order receipt. `ct_head` is always under the **durable** class, since it is always
retained.

`eph_root[n]` is independently sampled, time-sliced by window `t`, never wrapped to a recovery key,
never in a provisioning bundle, deleted when its window closes. **After the timer, retained server
ciphertext, a seized device, a newly provisioned device, and a seedphrase holder all fail to
decrypt.** This is the most easily broken property here — deriving `eph_root` from `storage_root`
would compile, pass tests, and silently make every expired message recoverable forever.

### 8.2 Archive and recovery wraps

| Target | Receives |
|---|---|
| Active device leaves | `pq_secret[n]` **and** `eph_root[n]` |
| Member `RECOVERY_PUB` | `pq_secret[n]` **and** `archive_secret[n]` |

```
archive_secret[n] = sender_data_secret[n] ‖ encryption_secret[n]     RFC 9420 §8.1
```

Those two named secrets — **not** the exporter output, which cannot regenerate its siblings, and
**not** `epoch_secret`, which would also expose `confirmation_key` and `membership_key`. The wrap also
carries a snapshot of the epoch's ratchet-tree public state and GroupContext, which a restoring device
needs to verify signatures.

## 9. Message server

### 9.1 Responsibilities

Accept records whose `write_auth` verifies. Enforce monotonic `stream_index` per `sender_handle`.
Enforce single-commit agreement (§9.3). Serve history. Prune by retention class and `expire_at`.
Never decrypt.

### 9.2 Write authorisation

```
write_key = HKDF-Expand(storage_root[n], "write/v1", 32)          group-wide
write_auth = MAC(write_key, "URmessage/v1/write" ‖ LP(server_nonce) ‖ LP(group_id)
                 ‖ LP(sender_handle) ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit)
                 ‖ u8(retention_class) ‖ u8(size_bucket) ‖ u64(expire_at)
                 ‖ LP(H(ct_head)) ‖ LP(body_hash))
```

One group-wide key, so the server learns only "a current member of this group" — which is all it needs
for quota and spam control. Per **I5**, authenticity is MLS's job, and a forged record fails at every
client no matter what the server accepts. Per **I6**, `write_auth` covers every header field the
server acts on.

The server holds `H(write_key)`-derived verification state per epoch, published by the committer as
part of the commit record's cleartext. Revocation is by epoch rotation, which MLS already performs on
every `Remove`.

`server_nonce` comes from the connection challenge (§4.3) and prevents cross-connection replay.

**What this gives up versus per-device capabilities:** the server cannot attribute a record to a
device, so `OBSERVER` is enforced in the UI and by MLS proposal rules rather than at the server, and
spam is attributable only to a group. Accepted for v1; per-device capabilities are reserved for V2.

### 9.3 Single-commit agreement — the server is the Delivery Service

RFC 9420 provides fork **detection**, not resolution. RFC 9750 §5.2 requires that the group agree on a
single Commit ending each epoch, and assigns that to the Delivery Service. Our message server is the
Delivery Service, and implements the strongly-consistent design of RFC 9750 §5.2.1:

- The server MUST accept at most one record with `is_commit = 1` per `(group_id, epoch)`, first valid
  wins, never replaced.
- It MUST return the accepted commit to any later submitter, which re-derives against the winner and
  retries.
- It MUST reject records whose `epoch` is not the current accepted epoch.

`is_commit` is cleartext because the server acts on it, and is covered by `AAD_head` and `write_auth`
per **I8**, so it cannot be flipped in transit.

### 9.4 Fetch attestation

`FETCH_ATTESTATION{group_id, requested_range, record_ids_returned[], server_time, server_id, sig}`,
signed by the server's long-term Ed25519 key, pinned by clients on first contact. Clients retain
attestations covering their high-water range and warn when a later-learned record falls inside a
covering attestation that omitted it.

### 9.5 What the server sees

Your account, your group list, `sender_handle` per group, record sizes by bucket, timing, retention
class. **Not** content, and not which member a handle belongs to.

In a single-server v1 this is broadly Signal's position: one server that knows who you are and who you
talk to, and cannot read anything. §13 says so rather than claiming otherwise.

Mitigations: records are padded into size buckets; `PERMANENT` is available to content so class does
not imply type; clients may emit `COVER` records — built into the format, exposed as a user setting,
**off by default**, since it costs constant background bandwidth and battery and must run on a
schedule independent of real sending or it leaks anyway.

### 9.6 Contract shaping

Transfer contracts are created per `(device, message server)`, long-lived, with a provider-terminated
hop, so `transfer_contract` rows do not become a subpoena-able membership graph held by the operator.

### 9.7 Normative logging prohibition

The message server MUST NOT create, store, or transmit logs of client commands, transport
connections, or a history of deleted records in production. A requirement on implementations, not a
policy page.

## 10. Identity verification

### 10.1 Key transparency

The operator's `principal → identity master key` directory is published as an append-only log over a
Merkle prefix tree. Clients require an inclusion proof for every resolution and gossip signed tree
heads over two paths — the message server and peer clients — since an equivocating operator otherwise
only has to fool one.

Required rather than optional because `model/auth_model.go:125-153` associates a new SSO auth onto an
existing user when `user_auth` matches. Control of the Google or Apple account is control of the
URnetwork identity, and the operator would be *honestly* vouching for a key belonging to the wrong
person.

### 10.2 Verification is local, SSH-style

Everyone is **unverified by default**. There is no verified badge.

The client pins each contact's identity key on first use. If a later resolution differs from the pin,
the client raises a **blocking warning** — the shape of SSH's changed-host-key prompt — naming what
changed and when, and requires explicit approval. A user who has never contacted someone sees no
warning, because there is no pin to contradict.

Safety numbers are an out-of-band fingerprint over the pair's identity keys for deliberate
verification. A key change is also written permanently into every group the pair shares.

Deliberately weaker than a verified-badge UX and deliberately stronger than silence: the operator can
assert a key, but never *quietly* replace one you have already seen.

## 11. Roles and administration

| Role | Count | May do |
|---|---|---|
| **OWNER** | exactly 1 | Everything. Sole authority for history grants, admin-set changes, ownership transfer |
| **ADMIN** | 0..n, delegated by owner | Add/remove members, set MEMBER/OBSERVER, retention policy, group metadata, commit epochs |
| **MEMBER** | — | Send, read |
| **OBSERVER** | — | Read only. UI- and MLS-enforced in v1; not server-enforced (§9.2) |

No quorum for any normal operation. **Owner succession is the single exception**, and it is a
deliberate one — see below. Roles live in the group-context extension (§6), so they are covered by
the MLS transcript hash and no server can alter them.

**Self-service device management.** A member may add or remove **their own** device leaves and commit
that change. Otherwise revoking a stolen laptop would block on an admin.

**Owner succession.** The owner may issue `OWNER_SUCCESSOR_SET` naming a successor. Promotion requires
the successor to claim it **and** a majority of current admins to countersign that the owner is
unreachable, after a 30-day floor. Without it, owner seed loss freezes the admin set permanently.

**History grants.** Owner-only, non-erasable, rendered as a persistent banner for the life of the
group naming grantee, epoch range, and granting owner. New members receive keys from their join epoch
forward by default.

## 12. Deletion and retention

### 12.1 Guaranteed

- **A deletion cannot be forged.** A `TOMBSTONE` is an MLS-authenticated message from the original
  sender.
- **An expired disappearing message is undecryptable by everyone**, including a device provisioned
  tomorrow and a seedphrase holder (§8.1).

### 12.2 Retention classes

| Class | Default | Set by |
|---|---|---|
| `PERMANENT` | never pruned | protocol (`RECOVERY_PUB`, key-change records) |
| `DURABLE` | long-lived; text default | group admin; server publishes a minimum it honours |
| `MEDIA` | **1 month** | group admin, bounded by the server's advertised cap |
| `EPH(bucket)` | off by default; 1h / 8h / 1d / 1w / 4w | per conversation; admin-settable for groups |

Media is a distinct class rather than inheriting its parent's, because it is most of the storage and
little of the value after a month. An attachment on an *ephemeral* parent inherits the parent's key
class — it must not outlive the timer — and otherwise uses `MEDIA`.

The server advertises a per-attachment size cap; clients respect it. Default **100 MB**.

Read receipts and typing indicators are **on by default**, `EPH(bucket 0)`, never persisted, batched,
individually disableable.

### 12.3 Not guaranteed

- Delete-for-everyone cannot claw back what a recipient already decrypted.
- Durable-class messages remain recoverable while epoch keys survive.
- **A server that silently withholds a deletion is not detectable in v1.** Stream digests are deferred
  to V2. In v1 the server is operated by the same party as the operator, so this is a trust
  assumption, and §13 says so.
- Server-side pruning is best-effort.

### 12.4 Required UI language

- Disappearing: *"After the timer, this message can no longer be read by anyone — the key is destroyed
  on every device and on the server."*
- Delete for everyone: *"Removed from this conversation on every device that is online and honest.
  Anyone who already read it may have kept a copy, and we cannot detect that."*
- Durable default: *"Messages are kept so your new devices can see your history. That means the server
  holds a copy until it's deleted or expires."*

Never say "gone forever" for the durable class.

## 13. Honest limits

**Better than Signal.** Disappearing messages are enforced by key destruction, not client cooperation
— including against a device set up tomorrow and against a seedphrase holder. Post-quantum protection
for stored messages, not just the connection. History follows you to a new device without it reaching
back past the day it was added.

**Same as Signal.** The server holds ciphertext only and cannot read anything. "Delete for everyone"
cannot claw back what someone already read. **And in v1, one server that knows your account, your
groups, and your activity** — server choice is a V2 feature, so this line is parity, not an advantage.

**Worse than Signal, and why.** The server knows group membership; Signal hides it with anonymous
credentials. We keep messages by default so your other devices can see history. The operator can see
that your device talks to the message server and how much. **A server that ignores its own deletion
policy is not detectable in v1.** And **the 24-word phrase is a master key: it cannot be rotated, and
whoever holds it reads all durable history past and future in every group and can act as you.**
Expired disappearing messages are the one thing it does not unlock.

**Better than Matrix.** One message costs one upload regardless of group size. No conflicting-history
problem. Membership payloads can be erased on request.

**Worse than Matrix.** One server, no replication, no migration in v1: if it is lost, the groups are
lost. Deliberate, and revisited in V2.

**Deliberately short of SimpleX.** Durable identities and a searchable directory, so you can be found,
re-added, and recovered.

**On verification.** Nobody is verified by default and there is no badge. You are warned loudly when a
contact's key changes from one you have seen before, and never silently switched.

## 14. Implementation slices

| # | Slice | Contains |
|---|---|---|
| 1 | `connect/mls/` | RFC 9420. **Acceptance: the IETF test vectors pass**, cross-checked against OpenMLS. |
| 2 | `connect/message/` | Storage records, retention classes, ratchet, PQ composition, `write_auth`, padding, `COVER`. Freezes the wire format. |
| 3 | `message-server` | Store, ordering, single-commit agreement, `write_auth` verification, retention, fetch attestation. §9.7 is an acceptance criterion. |
| 4 | Client core in `sdk` | Group state, local store, KT client, provisioning. |
| 5 | `message-windows` text | Send, receive, groups, TOFU warnings, reactions, receipts. **First testable build.** |
| 6 | Disappearing messages | `eph_root`, buckets, tombstones. |
| 7 | Multi-device | Provisioning UI, device management, revocation. |
| 8 | Attachments | Blob store, `MEDIA` class, thumbnails, resumable upload. |
| 9 | `/server` operator | Discovery directory, KT log. |

Slice 1 is the schedule risk and is first because it has an objective completion test. Slices 1–5
produce something two people can text on.

## 15. Open items

1. **Retention floor negotiation** — behaviour when a group's policy exceeds the server's advertised
   minimum: warn and proceed, or refuse?
2. **Push transport** — WNS for Windows; APNs/FCM when mobile lands. No push exists in the operator
   today.
3. **Owner succession residual risk** — a colluding admin majority can displace an owner who is merely
   offline. The 30-day floor bounds but does not eliminate this.
4. **`OWNER_SUCCESSOR_SET` placement** — group-context extension is likely right, since it should be
   transcript-covered.
5. **Moderation recourse** deferred by decision — revisit with legal counsel before any public launch.
