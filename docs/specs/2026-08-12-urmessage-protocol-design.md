# URmessage — Protocol Design

**Date:** 2026-08-12
**Revision:** 6 — R4 and R5 review applied: `server_attachment` (§8.3), `blob_id` in the record header
and both preimages, `req_auth` under a group-lifetime `read_key` (§9.2), asymmetric recovery proof bound
to `RECOVERY_PUB`, epoch publication sequence, wire encodings fixed
**Status:** Design, pending approval

Notation: `LP(x)` = 32-bit **big-endian** length prefix then `x`; `u8/u16/u32/u64` = big-endian
fixed width; `‖` = concatenation; `H` = SHA-256. HKDF is HKDF-SHA-256.

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

**Revision 6** applies the R4 review (148 findings) and the R5 convergence review across this document
and the three implementation specs. Nothing in the cryptographic core changed; what changed is that the
server-facing surface is now fully authenticated and fully specified, where revision 5 left four things
implied:

- **§8.3, the `server_attachment`.** Three values the server must act on — the next epoch's `write_key`
  and retention policy, the `recovery_handle` index, and the `wrap_target_handle` index — had no home in
  the record header and were therefore either unauthenticated or undefined, in contradiction of **I6**.
  They now travel in one typed, extensible field hashed into both `AAD_head` and the `write_auth`
  preimage.
- **Reads were unauthenticated.** `Fetch`, `Subscribe`, `GroupStatus`, `BlobGrant` and `WrapFetch` now
  carry `req_auth` (§9.2). An unauthenticated read was a full metadata dump and a group-existence oracle.
- **The `H(write_key)` claim was false.** A hash of a MAC key verifies nothing. The server holds
  `write_key[n]` itself, delivered in the commit's `server_attachment`, and §9.2 now states the three
  consequences plainly instead of implying a property the construction never had.
- **The recovery-fetch proof is asymmetric** (§5.2). The server holds only `recovery_handle` and must
  never hold `recovery_root`, so a symmetric proof was unverifiable by construction.
- **Encodings that two documents had to agree on are now stated once**: the `retention_class` and
  `size_bucket` wire bytes (§8), `expire_at` in milliseconds and shortening-only (§8, §9.1), `record_id`
  as a 1-based per-group counter (§8), `stream_index` scoped per `(group_id, sender_handle)` (§8), the
  epoch publication sequence with its `EpochComplete` marker (§8.2), and the `FetchAttestation` preimage
  (§9.4).
- **Open item 1 is ruled** (§15): retention negotiation is warn-and-proceed in both directions.
- **Reads are authenticated under a key an offline member still holds.** `req_auth` is MAC'd under
  `read_key`, fixed at group creation, not under the current epoch's `write_key` — which the server
  discards a minute after the epoch changes and which a client cannot re-derive without first reading.
  `blob_id` joined the record header and both preimages, because the server binds blobs by it and
  **I6** forbids acting on anything unauthenticated.

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
     │                    HKDF-Expand(recovery_root, "rk/v1" ‖ LP(g), 32))            [32 B seed]
     ├─ recovery_handle    = HKDF-Expand(recovery_root, "idx/v1", 16)
     └─ recovery_sig_seed  = HKDF-Expand(recovery_root, "idxsig/v1", 32)  → Ed25519
```

A seed-only restorer proves possession of `recovery_root` to the server without revealing it:

```
recovery_root      = HKDF-Expand(master_key, "recovery/v1", 32)              (unchanged)
recovery_handle    = HKDF-Expand(recovery_root, "idx/v1", 16)                (unchanged)
recovery_sig_seed  = HKDF-Expand(recovery_root, "idxsig/v1", 32)             (NEW)
recovery_sig_sk    = Ed25519 private key from recovery_sig_seed
recovery_verify_pub= Ed25519 public key of recovery_sig_sk                   (32 B)

recovery_proof = Ed25519(recovery_sig_sk,
                   "URmessage/v1/recovery" ‖ LP(server_nonce) ‖ LP(recovery_handle))

The archive record's server_attachment RecoveryTag (§8.3, kind 0x0002) carries
{recovery_handle, recovery_verify_pub, alg_id} and is covered by write_auth, so the
public half arrives authenticated as a member of the group.

The server stores the public half on first sight and REFUSES any later differing
recovery_verify_pub for the same recovery_handle WITHIN THAT GROUP (trust-on-first-use,
the same shape as the client's server-key pin, kept per group so one bad first write
cannot deny restore everywhere — Spec B §5.4). RecoveryFetchRequest.proof is verified
against each candidate group's stored key.
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
RECOVERY_PUB { group_id, LP(rk_xwing_pub), u16 alg_id,
               LP(recovery_handle), LP(recovery_verify_pub) }   signed under `identity`
```

carried as a `PERMANENT`-class record whose `server_attachment` is the matching `RecoveryTag`
(§8.3, kind 0x0002). Without this the committer cannot construct a recovery wrap at all, because
`recovery_root` is known only to its owner.

The signature over the whole body is what binds the handle to an identity. `write_auth` proves only
that *a current member of this group* submitted the record — it is group-wide — so it cannot
distinguish a member publishing its own handle from a member claiming someone else's. **A client
MUST NOT honour a `RecoveryTag` on any record whose `RECOVERY_PUB` body signature it has not
verified under the publishing member's `identity` key.** The server cannot perform that check: it
holds no identity keys, and by **I5** it never verifies authorship. Its own protection is narrower
and is described in Spec B §5.4.

### 5.4 Device provisioning

1. Existing device shows a QR with an ephemeral X25519 public key and a nonce.
2. New device performs an authenticated handshake over connect; both users compare a short
   authentication string.
3. Existing device sends the group list and **durable-class** archive material. Ephemeral-class
   material is never included (**I4**).
4. Existing device issues an MLS `Add` for the new device's leaf and commits it.

**Seed-only restore** is the documented last resort: a bare seed derives `recovery_handle`, proves
possession of `recovery_root` with the §5.2 `recovery_proof`, and asks the server for the archive
records indexed under that handle. The server learns how many groups that handle
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
  with `evidence_class = "operator_reset"` and `signed_by_old_key = false`. The closed set of evidence
  classes is Spec A's (`kt_inclusion`, `operator_assertion`, `operator_reset`, `kt_unavailable`,
  `unknown`). **In v1 the identity key changes only by this path**: `identity` is derived from the
  seedphrase and nothing else, so a reinstall or a new computer from the same phrase produces the same
  key and raises no warning at all. A self-signed rotation is a V2 mechanism and is never emitted in v1.
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
  record_id          u64  per-group, gapless, 1-based; server-assigned AFTER acceptance;
                          pagination and hole detection only; NEVER authenticated
  group_id           32B
  sender_handle      16B  = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)
                          stable per group; every member computes it; the server cannot invert it
  epoch              u64
  stream_index       u64  monotonic per (group_id, sender_handle); write-once
  is_commit          u8   1 on an MLS Commit record — the server acts on this, so it is authenticated
  retention_class    u8   see the encoding table below
  size_bucket        u8   256B / 1K / 4K / 16K / 64K / blob-ref
  expire_at          u64  unix MILLISECONDS, big-endian, 0 = unset; advisory upper bound only —
                          it may SHORTEN retention, never extend it
  body_hash          32B  H(ct_body); RETAINED when ct_body is erased
  blob_id            32B  present iff size_bucket == 5, absent otherwise; the object the body
                          lives in when the body is not inline. Derived from the record's key
                          material, never from content — see Spec A §5.13
  server_attachment  opaque, typed, extensible; ZERO-LENGTH for ordinary records. The only
                          server-visible structured field. See §8.3.
  ct_head            AEAD, always retained; MLS PrivateMessage header, type, sent_at
  ct_body            AEAD, erasable; the MLS PrivateMessage payload
  write_auth         MAC, computed last; see §9.2
```

The `retention_class` and `size_bucket` bytes have exactly one encoding:

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

Per **I7**, the two ciphertexts use **distinct keys and distinct AADs**, and `body_hash` appears only
in the head's AAD — never in the body's, which would be circular:

```
AAD_body = "URmessage/v1/aad/body" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
         ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(retention_class)

AAD_head = "URmessage/v1/aad/head" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
         ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit) ‖ u8(retention_class)
         ‖ u8(size_bucket) ‖ u64(expire_at) ‖ LP(body_hash) ‖ LP(blob_id)
         ‖ LP(H(server_attachment))

key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)
key_body ‖ nonce_body = HKDF-Expand(record_key[i], "rec/v1/body", 56)
```

`LP(blob_id)` is a **zero-length** prefix on every record whose `size_bucket` is not 5, so the
preimage is defined for ordinary records without a special case. `blob_id` is absent from `AAD_body`,
because the body it names is the thing being encrypted.

Construction order: build `server_attachment` → encrypt `ct_body` → compute `body_hash` → encrypt
`ct_head` → compute `write_auth`. Every dependency is acyclic.

Per **I5**, this layer adds no signature. Sender authentication is MLS's, inside the ciphertext.

`stream_index` is a single `u64` counter per `(group_id, sender_handle)`, write-once, assigned locally.
A device MUST durably record "index *k* consumed" **before** encrypting, and MUST NEVER encrypt a second
record at a consumed index. The server enforces **monotonicity, not contiguity**, so a refused write, a
crash between reserve and send, or a lost commit leaves a legal gap.

`EPH(bucket 0)` transients **do** consume an index locally (so the counter is never rewound) and are
**never** checked server-side, because the record is never stored and `message_sender.last_stream_index`
is not advanced for them.

`sender_handle` is stable per group rather than rotating per epoch. Per-epoch rotation existed to stop
*foreign* hosts linking a member across epochs; with one server that the client authenticates to, it
bought nothing and cost three defects.

A group has exactly two lifetime values, both fixed at creation and neither ever rotated:

```
group_handle_key = HKDF-Expand(storage_root[0], "gh/v1",   32)
read_key         = HKDF-Expand(storage_root[0], "read/v1", 32)
```

`group_handle_key` is what makes `sender_handle` and `wrap_target_handle` survive an epoch change.
`read_key` is what makes read authorization survive one (§9.2). **Both are delivered to a joining
member in its `Welcome`, alongside the group-context extension**, and neither is derivable from any
later epoch's `storage_root`. A member that does not hold `group_handle_key` cannot compute its own
handle and therefore cannot write; a member that does not hold `read_key` cannot authenticate a
single read, including the read that would fetch the commit that admitted it.

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
| Member `RECOVERY_PUB` | **`storage_root[n]`** **and** `archive_secret[n]` |

```
archive_secret[n] = sender_data_secret[n] ‖ encryption_secret[n]     RFC 9420 §8.1
```

Those two named secrets — **not** the exporter output, which cannot regenerate its siblings, and
**not** `epoch_secret`, which would also expose `confirmation_key` and `membership_key`.

**Why the recovery wrap carries `storage_root[n]` and not `pq_secret[n]`.** `storage_root =
HKDF-Extract(mls_secret, pq_secret)` requires `mls_secret`, which comes from `MLS-Exporter` and
therefore requires live MLS epoch state. A seed-only restorer (§5.4) has none by definition, so a wrap
carrying `pq_secret` would leave it able to derive no class key and open nothing — while holding an
`archive_secret` that would decrypt the MLS payload inside. Seed-only restore would not work at all.

This does not weaken the post-quantum property. The PQ layer exists against an adversary who harvested
the classical MLS handshake and later gains a quantum computer; that adversary derives `mls_secret`
from the harvested handshake regardless, so `pq_secret` and `storage_root` are equivalent to them —
both protected solely by X-Wing, which is what §7 intends. Against a classical adversary the only way
into the recovery wrap is the recovery X-Wing private key, derived from the seed, and a seed holder
already reads everything (§13). No adversary class gains anything.

**The epoch snapshot is a record, not part of the wrap.** A restoring device also needs the epoch's
ratchet-tree public state and GroupContext to verify signatures. That snapshot is roughly 300 KB at
the 500-member design target; carried inside each member's wrap it would make a single commit emit
~150 MB. It is instead **one `PERMANENT`-class record per epoch**, encrypted under
`K_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 32)` — which the restorer can open precisely
because `storage_root[n]` is in its wrap.

**Epoch publication sequence.** A commit is submitted at `epoch == current_epoch = n`, MAC'd under
`write_key[n]`, and carries an `EpochAttachment` for epoch `n+1`.

1. The server accepts at most one commit per `(group_id, epoch)`. On acceptance it sets
   `current_epoch := n+1` and installs `write_key[n+1]` from the attachment, in the same transaction.
2. The committer then submits, **as ordinary records at epoch `n+1`, MAC'd under `write_key[n+1]`**: one
   device wrap per active device leaf (`WrapTag`, indexed by `wrap_target_handle`), one recovery wrap per
   member (`RecoveryTag`, indexed by `recovery_handle`), and the ratchet-tree snapshot (one
   `PERMANENT`-class record, `WrapTag` with `leaf_index = 0xFFFFFFFF`).
3. The committer closes the fan-out with one `EpochComplete` marker record whose `wrap_count` MUST equal
   the attachment's `expected_wrap_count`. Until that marker is accepted, the group is
   **readable-but-not-writable**: the server returns `REASON_EPOCH_INCOMPLETE` to any non-wrap submit
   at epoch `n+1`.
4. A member or device that finds no wrap for its target at epoch `n+1` after the marker has landed
   surfaces a `gap` entry with reason `no_wrap`. It never fails silently.
5. If the committer dies mid-fan-out, the marker never lands, the group stays non-writable, and any
   member may re-publish the missing wraps for epoch `n+1` (they are all derivable from the epoch state
   every member holds) and submit the marker.

**Sizing at the 500-member × 2-device design target.** Every wrap is padded to the ladder like any
other record: a device wrap (~1,210 B of plaintext) and a recovery wrap (~1,242 B) both land in
`size_bucket 2`, so each is a `ct_body` of exactly 4,112 bytes plus its head and header, about
**4.6 KB on the wire**. One commit + 1,000 device wraps + 500 recovery wraps + 1 snapshot record +
1 marker is ≈ 1,503 records ≈ **6.9 MB**, plus the ~300 KB snapshot object on the bulk plane.
Per-record size caps apply to individual wrap records, never to the commit as a whole.
`max_records_per_submit` is 256 and `max_submit_bytes` is 131072; the byte cap binds first at about
28 wraps per submission, so a wrap-only batch takes **~55 round trips**.

Padding is what makes those numbers what they are. A wrap-sized rung on the ladder would cut the
bundle to roughly 2.6 MB, and it is deliberately not added in v1: the ladder is restated in three
documents and enforced as an equality by the server, and renumbering it to save bytes on the one
operation that is already the largest in the system is a wire break bought for a bounded case.

The snapshot exceeds the 64 KiB inline ceiling and is therefore written as a **blob-ref record**
(`size_bucket = 5`) of class `PERMANENT`. The server MUST offer a non-expiring object rung for it — see
Spec B §8.3 — and MUST NOT place it on any TTL ladder.

The server MUST index wraps by target: device wraps and the snapshot by `wrap_target_handle`, recovery
wraps by `recovery_handle`, both delivered inside the authenticated `server_attachment` (§8.3). Without
this a 500-member group makes every join a 6.9 MB download.

### 8.3 The server attachment

Anything the server acts on is covered by an authenticator the server can verify (**I6**). Three fields
the server must act on — the next epoch's `write_key` and retention policy, the `recovery_handle` index,
and the `wrap_target_handle` index — have no home in the record header. They travel in one typed,
extensible field, `server_attachment`, hashed into both `AAD_head` and the `write_auth` preimage. The
encoding is owned by `connect/message` (Spec A) and consumed by the message server (Spec B).

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
    LP   read_key               // exactly 32 bytes: read_key = HKDF-Expand(storage_root[0],
                                //   "read/v1", 32). Identical in every epoch of this group;
                                //   the server refuses a commit that changes it (§9.2)
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

## 9. Message server

### 9.1 Responsibilities

Accept records whose `write_auth` verifies. **Authorize reads: `Fetch`, `Subscribe`, `GroupStatus`,
`BlobGrant` and `WrapFetch` MUST carry `req_auth` (§9.2) and MUST be refused without it — an
unauthenticated read is a full metadata dump and a group-existence oracle.** Enforce monotonic
`stream_index` per `(group_id, sender_handle)`. Enforce single-commit agreement (§9.3). Serve history.
Prune by retention class **and `expire_at`, where `expire_at` may only shorten retention, never extend
it**. Never decrypt.

### 9.2 Write authorisation

```
write_key = HKDF-Expand(storage_root[n], "write/v1", 32)          group-wide, per epoch

write_auth = MAC(write_key, "URmessage/v1/write" ‖ LP(server_nonce) ‖ LP(group_id)
                 ‖ LP(sender_handle) ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit)
                 ‖ u8(retention_class) ‖ u8(size_bucket) ‖ u64(expire_at)
                 ‖ LP(H(ct_head)) ‖ LP(body_hash) ‖ LP(blob_id)
                 ‖ LP(H(server_attachment)))
```

One group-wide key, so the server learns only "a current member of this group" — which is all it needs
for quota and spam control. Per **I5**, authenticity is MLS's job, and a forged record fails at every
client no matter what the server accepts. Per **I6**, `write_auth` covers every header field the
server acts on.

The server holds `write_key[n]` itself. It is delivered to the server by the committer inside the commit
record's `server_attachment` (`EpochAttachment.write_key`), over the connect session's own hybrid-PQ
encryption, and is stored wrapped under a vault KEK. Three consequences, all accepted:

1. A server holding `write_key` **can forge `write_auth`**. This changes nothing: the server is the party
   enforcing `write_auth`, so it could equally accept an unauthenticated record, and any record it injects
   fails MLS verification at every client (**I5**).
2. `write_key` is a label-separated HKDF child of `storage_root[n]`, so holding it yields neither
   `storage_root[n]` nor the sibling class keys `K_perm` / `K_durable` / `K_media` / `eph_root`. It MUST
   NOT be reused for any second purpose beyond `write_auth`.
3. The server retains the **current** epoch's key plus **one** briefly-retired predecessor (60 s), and
   nothing older.

An asymmetric per-epoch write proof (Ed25519 derived from `storage_root`, server holds only the public
half) removes the forgery capability at the cost of one signature per record. It is the right long-term
shape and is a **V2** item, not v1 text.

Revocation is by epoch rotation, which MLS already performs on every `Remove`.

Reads are authorized by a second authenticator, under the group's lifetime `read_key` (§8) and a
distinct domain label:

```
req_auth = MAC(read_key, "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op)
                         ‖ LP(canonical_request_bytes))

  op                      = the field number of the selected `oneof body` arm in
                            MessageServerRequest, as a u8.
  canonical_request_bytes = the deterministically-marshaled request body message
                            (protobuf deterministic marshal, fields ascending) with its
                            own `req_auth` field set to zero length.

Required on, with their op bytes:  FetchRequest (13), SubscribeRequest (14),
                                   GroupStatusRequest (16), BlobGrantRequest (17),
                                   WrapFetchRequest (19).

NOT used on: HelloRequest (names no group, and is where server_nonce is issued),
             CreateGroupRequest (the group does not exist yet; the initial commit is
               self-certified against bootstrap_write_key — Spec B §6.1),
             UnsubscribeRequest (cancels only the caller's own subscription and reads
               no group state),
             SubmitRequest (every record in it carries its own write_auth),
             RecoveryFetchRequest (a seed-only restorer holds no group key; it is
               authorized by the asymmetric Ed25519 recovery proof of §5.2).

Verified on the server with Spec B §5.1 checks 1, 2, 4, 5 and the group read-key lookup,
and then this MAC, returning Spec B's deliberately non-specific REASON_REJECTED on
failure. No transaction is opened and no row is allocated on the read path.
```

**Why the read key is not the epoch key.** The server keeps only the current epoch's `write_key` and
one briefly-retired predecessor, so a member that was offline across a single commit for more than a
minute holds a `write_key` the server can no longer resolve. If reads were authenticated under that
key, such a member could not call `GroupStatus` to learn the current epoch, could not `Fetch` the
commits that would let it derive the current `storage_root`, and could not `WrapFetch` its own wrap —
every path out of the condition is itself a read. The result would be permanent lockout after any
membership change, for every client that was not online for it. `read_key` is fixed at group
creation, so a member holds it however long it has been away, and catch-up always works.

**How the server gets it.** Every commit's `EpochAttachment` carries `read_key`, byte-identical in
every epoch of the group. The server installs it on first sight, stores it wrapped under the same
vault KEK as the epoch write keys, and REFUSES any later commit whose attachment carries a different
value. Because it travels inside `server_attachment` it is covered by `write_auth`, so **I6** holds:
the server acts only on a value it can verify.

**What this costs, stated plainly.** A removed member keeps read authorization for the life of the
group. Epoch rotation on `Remove` denies it every key from that epoch forward, so what it retains is
the ability to fetch ciphertext it cannot decrypt and the metadata around it — record ids, sizes,
timings, `sender_handle`s. There is no v1 mechanism that withdraws read authorization from a former
member; the operator's levers are rate limiting and group closure. A per-epoch or per-device read
capability is the right long-term shape and is reserved for **V2**, alongside the per-device write
capabilities this section already defers.

`server_nonce` is 32 bytes, issued by the message server at session start in `HelloResponse`, scoped
to **that connection**, valid for the life of that connection, and never rotated. It prevents
cross-connection replay. It is **not** carried in requests — the server knows its own connection's
nonce and looks it up from the connection, never from the request.

**Outbox rule (normative, client side).** On reconnect, every queued record MUST be re-MAC'd against
the new connection's nonce before submission. On `REASON_EPOCH_STALE`, a queued record MUST be
discarded and re-sealed at the new epoch, consuming a **fresh** `stream_index`.

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

On every history fetch the server returns a `FetchAttestation`, signed by the fleet's long-term Ed25519
key, pinned by clients on first contact. The normative field list and signing preimage are Spec B
§4.3.4, restated here so the two implementations sign the same bytes:

```proto
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

Clients retain attestations covering their high-water range and warn when a later-learned record falls
inside a covering attestation that omitted it. Clients compare attestations only within an identical
`(class_mask, heads_only)` filter.

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

**In a DM with the changed contact:** blocking modal, outbound sending to that conversation disabled until
resolved.

**In a group containing them:** a permanent, non-dismissible in-thread record plus a non-blocking bar.
**Sending stays enabled**, because the changed key is not in the group's ratchet tree and cannot read
anything sent there.

**New blocking condition:** an `Add` committing a member whose identity key differs from a pin the user
holds. This is blocking for that group, with its own permanent record, and its own copy:
*"Bo was added to this group with a different safety number than the one you have seen."*

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
| 2 | `connect/message/` | Storage records, retention classes, ratchet, PQ composition, `write_auth`, padding, `COVER`. `server_attachment`, `req_auth`, recovery proof. Freezes the wire format — §8, §8.3 and §9.2 must be final before this slice starts. |
| 3 | `message-server` | Store, ordering, single-commit agreement, `write_auth` verification, retention, fetch attestation. §9.7 is an acceptance criterion. |
| 4 | Client core in `sdk` | Group state, local store, KT client, provisioning. |
| 5 | `message-windows` text | Send, receive, groups, TOFU warnings, reactions, receipts. **First testable build.** |
| 6 | Disappearing messages | `eph_root`, buckets, tombstones. |
| 7 | Multi-device | Provisioning UI, device management, revocation. |
| 8 | Attachments | Blob store, `MEDIA` class, thumbnails, resumable upload. |
| 9 | `/server` operator | Discovery directory, KT log. Includes the VRF-indexed prefix tree, the history tree, and the four client endpoints of Spec B §9.4 — not the log alone. |

Slice 1 is the schedule risk and is first because it has an objective completion test. Slices 1–5
produce something two people can text on.

## 15. Open items

1. **Retention negotiation — RULED, warn and proceed.** Two distinct cases, previously conflated as
   "policy exceeds the server's advertised minimum," which is incoherent:
   - a group policy **longer** than the server's `media_ttl_max_seconds` → the server clamps **down**;
   - a group policy **shorter** than the server's `durable_retention_min_seconds` → the server floors
     **up**.

   In both cases the server accepts the commit and returns `REASON_RETENTION_CLAMPED` with the applied
   values; the client renders a one-time in-group notice naming the **effective** policy. The group's
   transcript-covered policy is unchanged. Refusal is not an option in either direction.
2. **Push transport** — WNS for Windows; APNs/FCM when mobile lands. No push exists in the operator
   today. Owned jointly by Spec A (`RegisterPushChannel`), Spec B (server-side channel registry) and
   Spec C (§10.2, and the Azure AD application registration, which needs a named owner).
3. **Owner succession residual risk** — a colluding admin majority can displace an owner who is merely
   offline. The 30-day floor bounds but does not eliminate this.
4. **`OWNER_SUCCESSOR_SET` placement** — group-context extension is likely right, since it should be
   transcript-covered.
5. **Moderation recourse** deferred by decision — revisit with legal counsel before any public launch.
6. **Key-transparency log — RULED, a release gate rather than a date.** Spec B §9.4 specifies the
   VRF suite, the tree arithmetic, the STH preimage, the history tree, the four client endpoints, the
   signing key and the monitor role. §10.1 makes the log required rather than optional, and this item
   asked for a completion date. The ruling: **the log is a general-availability gate.** URmessage may
   be distributed to beta testers while every key-change row and every directory lookup renders
   `kt_unavailable` explicitly, and it MUST NOT be offered to any non-beta user until the log, its
   four client endpoints and its monitor role are live. This is the same shape as the funded external
   audit that gates the MLS implementation, and it is checkable on the day of a release rather than on
   a calendar. The item is closed.
