# URmessage — Protocol Design

**Date:** 2026-08-12
**Revision:** 9 — the out-of-band contact card gets the transport it was specified without: a
group-less contact rendezvous with its own asymmetric authenticators, a per-card capability
generation derived from the seedphrase, and a bounded, short-lived deposit the server cannot read
(§5.2, §9.8, §10.1, §11, §14); the metadata cost of first contact is stated where the other costs
are (§9.5, §9.7, §13); rotation is named as the v1 substitute for blocking (§13, §15)
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

**Revision 4** narrows v1 to **one message server and many providers carrying traffic**, which removes
the read-through proxy, per-epoch handle rotation, and per-device capability blinding — the three
mechanisms responsible for most of the remaining blockers. It also adds §3, an explicit invariant
list, because two revision-3 defects were contradictions of an invariant stated a line away.
Revisions 4–6 also wrote "one operator" alongside it, which was never true of the platform; revision
7 corrects it (§2).

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
  `read_key`, not under the current epoch's `write_key` — which the server discards a minute after
  the epoch changes and which a client cannot re-derive without first reading. Revision 6 fixed that
  key for the life of the group; revision 7 makes it per-epoch with a 90-day server-side window,
  which keeps the property and expires a removed member's metadata access (§8, §9.2).
  `blob_id` joined the record header and both preimages, because the server binds blobs by it and
  **I6** forbids acting on anything unauthenticated.

**Revision 7** applies the project owner's product rulings. Nothing in the cryptographic core
changed. What changed is ownership of decisions that earlier revisions had taken as engineer
defaults, and four places where the document contradicted itself or an implementation spec:

- **Operators are plural.** Revisions 1–6 read "the operator" as a single party throughout. Two
  operator servers exist today, they are separate from message servers, and a message server holds
  an account on whichever compatible operator its administrator chooses. v1 still ships **one
  message server**; nothing hardcodes one operator. §2, §4.1, §4.2, §4.4 and §13 are rewritten.
- **`read_key` is per epoch, not per group lifetime**, with a 90-day server-side acceptance
  window. A removed member's metadata access now expires. §8, §8.3, §9.1 and §9.2 are rewritten.
- **Delivery receipts ship in v1.** A device emits an ephemeral record when it decrypts. This is a
  wire-format addition and lands with the storage layer, not after it. §2, §12.2 and §13.
- **Owner succession ships**, at a raised bar: supermajority of admins, a 90-day floor, escalating
  warnings on every owner device, and an owner opt-out. Spec A's parse-refusal of the successor
  extension is lifted. §11, and open items 3 and 4 close.
- **Retention has a default and three server-advertised limits.** Text keeps for one year rather
  than indefinitely; the message server advertises a text-storage cap, a media window and a file
  size limit, and groups operate inside all three. §12.2.
- **Logging is aggregate-only rather than absolutely prohibited.** §9.7 states what may be
  recorded, which is enforceable, instead of a rule that an on-call engineer meets at 3 a.m. and
  quietly breaks.

**Revision 8** applies the project owner's second batch of product rulings, and corrects three places
where a ruling already taken had reached some documents and not others. Nothing in the cryptographic
core changed.

- **Operators are plural in every document, not only in this one.** Revision 7 rewrote §2 and §4
  here and left the implementation specs reading "the operator": the client SDK exposed no operator
  value at all, and the Windows client compiled its network space host in as a build-time constant,
  which is the one-operator assumption surviving as a build instruction. Every operator-facing value
  is configuration with a build-time default, a message server advertises the operator it holds its
  account on, and every key-transparency artefact is scoped to the operator it came from — one
  operator's signed tree head is never evidence about another's. §2, §4.1, §4.2 and §10.1.
- **A directory lookup made when no transparency log is reachable proceeds, and says so.** §15 item
  6 permits a beta in which every key-change row **and every directory lookup** renders
  `kt_unavailable`; key changes were given that treatment and lookups were left failing closed,
  which would have left the beta with no way to start a conversation at all. A resolution answered
  **with** a proof that does not verify still fails closed, because that is the event the machinery
  exists to catch. §10.1.
- **An out-of-band contact card ships in v1.** Directory listing is opt-in and off by default, and
  an invite link needs someone who is already inside a group, so two people who have never met had
  no way to reach each other at all. A contact card is a QR code or a copyable link its owner hands
  over directly; it carries a capability rather than a membership, and the capability is rotatable.
  §2, §10.1 and §11.
- **A reaction carries any emoji rather than one of eight.** The reaction body becomes a
  length-prefixed UTF-8 string on the wire, which makes it a format change that lands with the
  storage layer rather than with the client work that renders it. Four consequences are stated here
  rather than discovered later: font coverage, joined sequences, normalisation, and a reaction
  becoming user-authored content and therefore a moderation surface the project has deliberately
  deferred. §2, §12.2, §13 and §14.
- **Read receipts and typing indicators are reciprocal.** Turning yours off also hides everyone
  else's from you. Without that, the setting is a one-way observation tool in which the most
  privacy-conscious person in a conversation learns the most about everyone else. Delivery receipts
  are not covered by the rule and remain independently disableable. §12.2.
- **The succession supermajority is one arithmetic rule, and the owner warning is a client
  obligation rather than a validity condition.** Two rules written in prose disagreed for a group
  with one admin, where one clause allowed a single signature to take a group and the other forbade
  it. And no receiving client can observe what was displayed on the owner's devices, so warning
  delivery cannot be a condition on a commit's validity — a validity condition nobody can check is a
  condition that is silently skipped. §11.
- **Text retention has two wire sentinels rather than one.** "The group set nothing" and "the group
  asked for forever" are different requests, and one value cannot carry both: with a single sentinel
  a stock server stored forever for every group that never opened a retention screen, which made the
  one-year default a promise about client behaviour rather than a property of the system. §8.3 and
  §12.2.

**Revision 9** gives the contact card a transport. Revision 8 ruled that an out-of-band card ships
in v1 and specified it in the client and the SDK, where the redeemer "presents a key package at the
rendezvous the token names" — and no document defined that rendezvous, no server component had any
group-less ingress, and the one surface the beta cannot start a conversation without was the one
surface no component owned. Nothing in the cryptographic core changed.

- **A contact rendezvous is a group-less mailbox at the message server** (§9.8). It is keyed by
  `rendezvous_id = H("URmessage/v1/rendezvous" ‖ token)`, registered and retired by the card's owner
  under a key only the owner holds, and deposited into by any card holder under a key derived from
  the token itself. Every value the server acts on is inside a signature preimage it verifies, so
  **I6** holds on a path where no group key exists.
- **The card is a capability generation, derived from the seedphrase** (§5.2). Rotation is an
  increment of a counter, so every device of an identity derives every generation with no new sync
  channel, and a seed-only restore recovers a card that is already printed on paper.
- **The deposit is sealed to the card and is opaque to the server.** The server stores a
  fixed-length blob, learns no identity key, no display name and no key package, and verifies a
  token-derived signature that proves possession of the card and deliberately proves nothing about
  who is holding it.
- **The metadata cost is stated rather than implied** (§9.5, §13): the server learns that a client
  sent a contact request to the owner of some rendezvous, at a time. That is a social-graph edge, it
  is the first one in the design, and it exists for first contact only.
- **Rotation is named as what v1 offers in place of blocking** (§13, §15 item 4). It withdraws the
  capability from everyone holding it, which is a real remedy and a blunt one, and saying so is
  better than letting a user discover the bluntness.

## 1. Purpose and product target

URmessage is a private messenger built on the URnetwork mesh. It reuses URnetwork's transport and
provider relaying, and adds what transport cannot provide: **durable offline delivery** and **group
cryptography**.

> "Slightly better than Signal, not as insane as SimpleX. Kinda like Matrix but better."

A weakness Signal also has is acceptable; being worse than Signal is not. Metadata resistance that
costs usability is rejected.

## 2. Scope

**v1 topology:** one message server, many providers carrying traffic, and **more than one
operator**. Operators and message servers are different things: an operator is the URnetwork
platform that authorizes transport, mints contracts and routes to providers; a message server
stores ciphertext and orders records. Two operator servers run today. A message server holds an
account on one compatible operator, chosen by whoever administers that server, and forwards its
traffic through it. A client reaches its message server through its own operator. Multi-*server* is
V2 — the wire format keeps `server_id` fields so it is not a format break, but no code implements
it. **Nothing in v1 may hardcode a single operator**: every operator-facing value is
configuration, and a build that compiles one operator's host into a constant is a defect.

**v1 ships:** text messaging (DMs and groups), full multi-device, disappearing messages, safety
numbers with key-change warnings, reactions with any emoji, read receipts, delivery receipts and
typing indicators, attachments and images, invite links, contact cards, balance-code redemption,
owner succession, and a WinUI 3 Windows client reusing the VPN app's shell and branding.

**Deferred to V2+, type codes reserved so none is a format break:** message editing, multi-server and
read-through proxy, group migration between hosts, stream digests, per-device write capabilities,
voice and video (relayed through providers, not peer-to-peer), public groups, history export, mobile
clients, and **very large groups**, which get their own Community Server system rather than a larger
ordinary group. That is a distinct design with its own admission, storage and moderation shape,
well beyond V2. Nothing in the v1 wire format forecloses it: group size is bounded by policy and by
the client, never by a format field.

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
| **Message server** | Stores ciphertext, orders records, serves history, prunes. One in v1. Holds an account on **one** operator — chosen by its administrator from the operators it is compatible with — and forwards its traffic through it. |
| **Operator** | A URnetwork platform instance. **There is more than one; two run today.** Authorizes transport, mints contracts, routes to providers, sets data pricing, and runs its own discovery directory and key-transparency log. **Forwards traffic; never stores message records.** A client uses the operator its account is on; that need not be the one its message server uses. |
| **Provider** | URnetwork relay. Sees ciphertext in transit only. |

### 4.2 The operator boundary

**An operator MAY:** mint `ByJwt` for transport and billing; create contracts and route;
rate-limit and refuse service; set the price of data on its own network; run a discovery directory
mapping `principal → identity master key` **for the identities that have opted into being
listed**; publish that directory to its own key-transparency log. Each operator runs its own
directory and its own log; a client verifies against the log of the operator it resolved a
principal from, and never treats one operator's signed tree head as evidence about another's.

**The messaging identity and the paying URnetwork account are cryptographically unlinked.** The
master identity of §5.2 is generated on-device from a phrase the operator never sees, and no
operator-held record binds it to an account unless the user explicitly opts into directory listing.
This is what makes "the operator cannot read your messages" structural rather than a policy
statement: without the join, a compromised operator holds a payment record and a traffic pattern,
not a social graph. The accepted cost is stated in §13 — there is no cross-boundary abuse tooling,
and support cannot answer "which account is this".

**MUST NOT:** store message records; satisfy any MLS proposal or commit's validity condition; be
consulted by the message server on group admission. Operator assertions are advisory UI hints in
discovery only. No operator may be assumed to be *the* operator: a client, a message server and a
contact may each be on a different one, and any check written as though one operator sees the whole
system is wrong.

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
human-identifiable SSO account, which §4.2 makes an explicit opt-in. The message server likewise
holds an account — on the operator its administrator selected — and that credential is a
server-side secret. The client's operator and the message server's operator are configuration on
both sides and are not required to be the same.

### 4.5 Who pays for the data

**Operators set data pricing; nobody else does.** A message server does not price data and does not
fund its members' traffic. Messaging consumes the **user's own URnetwork allowance** on the user's
own operator, exactly as any other traffic on that account does — currently 40 GB per day free,
which is ample for text, receipts and ordinary attachments.

Message servers operated for the beta are given free data credit by the operator that hosts them.
That is an arrangement between an operator and a server administrator; it is not a protocol
feature and no client behaviour depends on it.

**When an account runs out of credit, messaging stops and the client says so.** The failure is
reported in the app with the reason named, and the user is directed to the URnetwork website, app
or VPN client to add credit — URmessage does not sell data and contains no purchase flow. It does
contain a redemption flow for **balance codes**: a code issued by an operator that grants credit
against the user's account. Beta testers receive credit this way. The redemption surface is Spec A
§7.9 and its screen is Spec C §12.4.

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
├─ recovery_root = HKDF-Expand(master_key, "recovery/v1", 32)
│    ├─ per group g:  rk_xwing = XWing.KeyGen(
│    │                    HKDF-Expand(recovery_root, "rk/v1" ‖ LP(g), 32))            [32 B seed]
│    ├─ recovery_handle    = HKDF-Expand(recovery_root, "idx/v1", 16)
│    └─ recovery_sig_seed  = HKDF-Expand(recovery_root, "idxsig/v1", 32)  → Ed25519
└─ card_root     = HKDF-Expand(master_key, "card/v1", 32)
     └─ card_seed[k] = HKDF-Expand(card_root, "cardgen/v1" ‖ u32(k), 32)   one per card generation
```

`card_root` derives the contact card of §10.1 and its rendezvous, one generation at a time, and
rotating the card is incrementing *k*. Deriving it from the master key rather than from a device is
what makes the card work across an identity's devices with no channel to synchronise it and what
makes a seed-only restore recover a card that is already printed on paper. It is **not** an
exception to **I3**: `card_root` opens no group, decrypts no message body and appears in no wrap,
so it is not a group-usable secret. Its whole power is to accept first-contact requests, which a
seedphrase holder can already do by being you. The generation's own derivations are §9.8.

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
  `out_of_band`, `unknown`), where `out_of_band` is a key that came from its owner directly rather
  than from any directory (§10.1). **In v1 the identity key changes only by this path**: `identity` is derived from the
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
AES-GCM, to match the stack and avoid AES-NI assumptions on ARM64. A **second ciphersuite,
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001), is registered and implemented** alongside
it. v1 groups are still created at 0x0003 and the group policy refuses anything else, so this
changes no group on the wire. It exists because a registry with one entry is indistinguishable from
a hardcoded constant, and the post-quantum MLS ciphersuites are still a draft we expect to adopt:
the part that breaks later is the assumption of a singleton, and it is cheap to disprove now and
expensive to disprove after the fact. `ReInit` remains unimplemented — registering a suite and
migrating a live group are different problems, and only the first is v1.

**Credential:** `BasicCredential` carrying the member's `identity` public key. RFC 9420 §7.3 does
**not** verify that a credential corresponds to any external identity — it validates signature and
capability consistency only. Binding `identity` to a human is entirely our job, and is done by the KT
log plus local pinning (§10). The spec must not assume MLS checks this.

**Extensions:** `required_capabilities`; `urmessage_leaf_keys` (§5.3); a group-context extension
carrying `{roles, retention_policy, disappearing_buckets, server_id}`; and a second group-context
extension carrying the owner-succession nomination of §11 — so all of those are covered by the
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

**Group size: 500 members, enforced.** TreeKEM is O(log n) and the ratchet is not the constraint;
Welcome size, epoch-bundle size and client memory are, and 500 is where they are still comfortable.
A commit that would carry the group past 500 members is refused by the committing client and
rejected by every receiving client, so the cap does not depend on one well-behaved participant.
**Ten devices per identity**, enforced the same way. Both numbers are shown in the UI rather than
discovered by hitting them (Spec C §12.5). Groups that genuinely need more than 500 people are the
Community Server case named in §2, not a larger group.

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

A group has exactly one lifetime value, fixed at creation and never rotated, and one per-epoch read
authorizer:

```
group_handle_key = HKDF-Expand(storage_root[0], "gh/v1",   32)     fixed for the life of the group
read_key[n]      = HKDF-Expand(storage_root[n], "read/v1", 32)     one per epoch
```

`group_handle_key` is what makes `sender_handle` and `wrap_target_handle` survive an epoch change.
It is delivered to a joining member in its `Welcome` alongside the group-context extension, and is
not derivable from any later epoch's `storage_root`. A member that does not hold it cannot compute
its own handle and therefore cannot write.

`read_key[n]` is what authorizes reads (§9.2). Every member derives it from the epoch state it
already holds, so it needs no separate delivery except at join, where the `Welcome` carries the
joining epoch's key. Each commit's `EpochAttachment` delivers to the server the read key of the
epoch that commit opens. **The server retains every read key it has installed for 90 days from
installation** and accepts a read authenticated under any retained key, so a member that was
offline across many commits still authenticates with the newest key it holds and catches up. A
member removed at epoch *n* keeps metadata access only until epoch *n*'s key falls out of that
window. §9.2 states the consequences of the window in both directions.

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
    LP   read_key               // exactly 32 bytes: read_key[epoch] = HKDF-Expand(
                                //   storage_root[epoch], "read/v1", 32), for the epoch this
                                //   attachment OPENS. Different in every epoch; the server
                                //   installs it per epoch and retains it for 90 days (§9.2)
    u32  media_ttl_seconds
    u32  durable_ttl_seconds    // 0          = the group set nothing; the server applies its own
                                //              advertised text default
                                // 0xFFFFFFFF = the group asked for indefinite retention, which a
                                //              server advertising a text cap clamps down to that cap
                                // any other value = the group's requested retention in seconds,
                                //              floored up to the server's advertised minimum and
                                //              clamped down to its advertised cap
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

**On `EpochAttachment.durable_ttl_seconds`:** two sentinels rather than one, because "the group set
nothing" and "the group asked for forever" are different requests and a single value cannot carry
both. A server that advertises a one-year text default and receives an unset value stores one year. A
server that advertises a cap and receives a request for indefinite retention stores the cap and
reports what it applied. Neither case refuses the commit. The server-side arithmetic is Spec B §6.1
and Spec B §7.3.

## 9. Message server

### 9.1 Responsibilities

Accept records whose `write_auth` verifies. **Authorize reads: `Fetch`, `Subscribe`, `GroupStatus`,
`BlobGrant` and `WrapFetch` MUST carry `req_auth` and the epoch of the read key that computed it
(§9.2), and MUST be refused without both — an unauthenticated read is a full metadata dump and a
group-existence oracle.** Retain each group's read keys for 90 days from installation and refuse a
request naming an epoch whose key has aged out. Enforce monotonic
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

Consequence 1 is not buried here: §13 states it in the honest-limits list, because a reader who
discovers it later will otherwise assume it is worse than it is.

An asymmetric per-epoch write proof (Ed25519 derived from `storage_root`, server holds only the public
half) removes the forgery capability at the cost of one signature per record. It is the right long-term
shape and is a **V2** item, not v1 text.

Revocation is by epoch rotation, which MLS already performs on every `Remove`.

Reads are authorized by a second authenticator, under the epoch's `read_key` and a distinct domain
label:

```
req_auth = MAC(read_key[e], "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op)
                            ‖ LP(canonical_request_bytes))

  e                       = the epoch named by the request's read_epoch field. The client uses
                            the newest epoch whose state it holds.
  op                      = the field number of the selected `oneof body` arm in
                            MessageServerRequest, as a u8.
  canonical_request_bytes = the deterministically-marshaled request body message
                            (protobuf deterministic marshal, fields ascending) with its
                            own `req_auth` field set to zero length. read_epoch is one of
                            those fields, so the epoch the server selects a key by is inside
                            the MAC and cannot be altered in transit.

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

Verified on the server with Spec B §5.1 checks 1, 2, 4, 5 and the group read-key lookup
for the named epoch, and then this MAC, returning Spec B's deliberately non-specific
REASON_REJECTED on failure. No transaction is opened and no row is allocated on the read
path.
```

**Why the read key is not the epoch's write key.** The server keeps only the current epoch's
`write_key` and one briefly-retired predecessor, so a member that was offline across a single
commit for more than a minute holds a `write_key` the server can no longer resolve. If reads were
authenticated under that key, such a member could not call `GroupStatus` to learn the current
epoch, could not `Fetch` the commits that would let it derive the current `storage_root`, and could
not `WrapFetch` its own wrap — every path out of the condition is itself a read. The read key
exists to break that cycle, and its retention window is measured in months rather than seconds for
exactly that reason.

**How the server gets it.** Every commit's `EpochAttachment` carries the read key of the epoch that
commit opens. The server installs it against that epoch, stores it wrapped under the same vault KEK
as the epoch write keys, and stamps the installation time. Because it travels inside
`server_attachment` it is covered by `write_auth`, so **I6** holds: the server acts only on a value
it can verify. Unlike the write key it is **not** discarded when the epoch advances.

**The 90-day window, stated in both directions.** The server retains each installed read key for 90
days and accepts a read authenticated under any retained key.

- A member that returns within 90 days authenticates under the newest read key it holds and
  catches up normally, however many commits it missed.
- A member **removed** at epoch *n* keeps the ability to fetch ciphertext it cannot decrypt, and
  the metadata around it — record ids, sizes, timings, `sender_handle`s — until epoch *n*'s key
  ages out. After that the server refuses it. This is the property the window exists to create:
  before it, a removed member kept a live metadata feed for the life of the group.
- A member that is offline for **longer** than 90 days holds only keys the server has discarded and
  cannot read until it is re-admitted, links from another of its devices, or restores from its
  seedphrase — seed-only restore is authorized by the §5.2 recovery proof and never by a read key,
  so it always remains available. The client names this state rather than presenting it as a
  generic failure (Spec C §9.8).

Epoch rotation on `Remove` already denies a removed member every decryption key from that epoch
forward; the window is what finally denies it the metadata as well.

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

Delivery receipts add one thing to that list: because a device emits an ephemeral record when it
decrypts, the server sees **when a device of that group was online and processing**, at
`sender_handle` granularity. Read receipts alone did not disclose that, since a user may leave a
conversation unread for days. The trade was made deliberately — a delivery state that is a real
signal from a real device is worth more than a server guess, and a server guess is the only other
way to have one — and §13 records it.

The contact rendezvous adds the first social-graph edge in this design, and it is named here rather
than left to be inferred. The server sees that a rendezvous with a given 32-byte id exists, which
`client_id` registered it, which `client_id`s collect from it — which groups those clients as
devices of one identity — and the count and arrival times of fixed-size deposits at it, each
carrying the `client_id` that delivered it. In other words it sees **that some client sent a contact
request to the owner of some card, at a time.** It does not see either party's identity key, either
party's principal, the display name, the key package, whether the request was accepted, or the group
that results. The edge is bounded three ways: it names nobody, it survives only the deposit's
seven-day life, and it covers first contact only — the conversation that follows is an ordinary
group and discloses exactly what §9.5's first paragraph says a group discloses. §13 states it to
users.

In a single-server v1 this is broadly Signal's position: one server that knows who you are and who you
talk to, and cannot read anything. §13 says so rather than claiming otherwise.

Mitigations: records are padded into size buckets; `PERMANENT` is available to content so class does
not imply type; clients may emit `COVER` records — built into the format, exposed as a user setting,
**off by default**, since it costs constant background bandwidth and battery and must run on a
schedule independent of real sending or it leaks anyway.

### 9.6 Contract shaping

Transfer contracts are created per `(device, message server)`, long-lived, with a provider-terminated
hop, so `transfer_contract` rows do not become a subpoena-able membership graph held by the operator.

### 9.7 Normative logging rule

The message server MUST NOT create, store, or transmit **per-identity** records of client commands,
transport connections, or deleted records in production. Concretely, no log line, metric label,
trace span, error string, database log or object-store access log may contain a `group_id`,
`sender_handle`, `record_id`, `stream_index`, `blob_id`, `recovery_handle`, `wrap_target_handle`,
`rendezvous_id`, `deposit_id`, `client_id`, network id, IP address, authenticator, key or
ciphertext, nor the fact that a particular client fetched a particular range or deposited at a
particular rendezvous.

**What it MAY record is aggregate:** counters and histograms with no identifier labels, error
*classes*, process lifecycle, and migration state. This is a carve-out, stated deliberately, and it
replaces an absolute prohibition that was aspirational: an on-call engineer meets an absolute rule
at 3 a.m. during an outage and quietly adds a log line. A rule that says exactly what is allowed is
one an engineer can follow under pressure, and is therefore the stronger privacy position in
practice. Spec B §11 makes it operational and testable.

**One narrow exception, opt-in and client-triggered.** A user who is diagnosing a problem may start
a **diagnostic session** from the client. The client presents a short-lived token the server
records against, and for the life of that session — bounded, and never longer than one hour — the
server may retain per-request detail for **that client only**, in a separate store with its own
retention, surfaced back to the user. No session, no per-identity record. The mechanism is Spec B
§11.5 and the control is Spec C §12.

### 9.8 The contact rendezvous

A contact card (§10.1) is handed to someone who is in none of your groups and may be in no
directory. There is no group key between you, so there is no `write_auth` and no `req_auth`, and
the only third party either of you shares is the message server. The rendezvous is the smallest
mailbox that lets that first message land while satisfying **I6**.

Every generation of a card derives one:

```
card_seed[k]         = HKDF-Expand(card_root, "cardgen/v1" ‖ u32(k), 32)
token[k]             = HKDF-Expand(card_seed[k], "token/v1", 16)     ← the card's only secret
card_xwing[k]        = XWing.KeyGen(HKDF-Expand(card_seed[k], "cardkem/v1", 32))
collect_sig_seed[k]  = HKDF-Expand(card_seed[k], "colsig/v1", 32)   → collect_sig_sk

rendezvous_id[k]     = H("URmessage/v1/rendezvous" ‖ token[k])                        [32 B]
deposit_sig_seed[k]  = HKDF-Expand(HKDF-Extract("URmessage/v1/rendezvous", token[k]),
                                   "depsig/v1", 32)                 → deposit_sig_sk
```

`rendezvous_id` and `deposit_sig_sk` follow from `token` alone, so every card holder derives them.
`collect_sig_sk` and the private half of `card_xwing` follow only from `card_root`, so only the
identity's own devices derive them. Successive `rendezvous_id`s are independent HKDF outputs, so
the server cannot link one generation to the next and the holder of a retired token cannot compute
the live one.

The owner **registers** `{rendezvous_id, deposit_verify_pub, collect_verify_pub, card_xwing_pub}`
under a signature by `collect_sig_sk`. The registration is self-certified — the server verifies it
against the key the request carries and then pins that key — which is the same shape as
`CreateGroupRequest`'s `bootstrap_write_key`, protected by a per-client rate limit and by 128 bits
of unguessability in the token and by nothing else. Every later collect and the retirement verify
against the pinned key. A card holder **opens** the rendezvous to fetch `card_xwing_pub`, proving
possession of the token first, then **deposits** a fixed-length ciphertext sealed to that key under
a signature by `deposit_sig_sk`. The owner **collects** and **retires**. The wire messages, the
five preimages and the server's checks are Spec B §4.3.11; the encodings are Spec A §5.14.

**Three properties, all deliberate.** The server holds only public halves, so unlike `write_key` it
**cannot forge** any authenticator on this path. The deposit signature proves **possession of the
card and nothing else**, because it is derived from the token and is therefore the same key for
every holder — the server can separate card holders from everyone else and can separate nothing
finer. And what binds the key package inside a deposit to the identity whose safety digits the
owner is shown is an inner signature under the requester's `identity` key, verified by the
**owner's client**, never by the server, exactly as §5.3 requires for a `RecoveryTag`. The server
does the narrow check it can do, the client does the one that binds a key to a person, and neither
pretends to do the other's.

The mailbox is bounded rather than throttled: sixteen uncollected deposits per rendezvous, seven
days each, one exact size. A card that is being sprayed fills up for a week; it does not grow a
spool. What the server learns from all of this is §9.5.

## 10. Identity verification

### 10.1 Key transparency

An operator's `principal → identity master key` directory is published as an append-only log over a
Merkle prefix tree. Each operator runs its own directory and its own log. Clients gossip signed tree
heads over two paths — the message server and peer clients — since an equivocating operator
otherwise only has to fool one, and each client compares heads only within the log of the operator
it resolved from. A resolution answered **with** a proof that does not verify is refused outright:
the log spoke and the proof was wrong, which is the exact event this mechanism exists to catch. A
resolution made when **no log is reachable at all** proceeds, and everything derived from it — the
contact, the conversation, the key-change history — is marked as resting on no transparency
evidence, in the same words and the same rows a key change with no log evidence gets. §15 item 6
permits beta testers to run in that state and makes the live log a general-availability gate; a
lookup that fails closed before the log exists would leave the beta with no way to start a
conversation at all.

**Listing is opt-in and off by default.** No directory entry and no log leaf exists for an identity
until its owner turns listing on, which is also the only act that creates a link between a
messaging identity and a paying account (§4.2). An unlisted identity is reachable two ways, both of
which work with no directory at all and neither of which needs the log to be live: a group invite
link made by a member who is already inside, and a **contact card** — a QR code or a copyable link
the identity's owner hands to someone directly, carrying the display name, the identity key and a
capability that lets the holder open a direct conversation. The card is what makes the product
usable before anyone is listed and before the log exists. What carries it is a **contact
rendezvous** (§9.8): a group-less, size-bounded, short-lived mailbox at the message server,
addressed by an id derived from the card's own token, into which a card holder deposits one sealed
contact request and from which the card's owner collects. The capability the card carries is
rotatable, and rotating it retires the rendezvous — §11 specifies what that costs and what it does
not. The metadata price of the mechanism is one line and is not buried: the message server learns
that a contact request for some rendezvous id arrived from some client at some time, and learns
nothing about either party from it (§9.5). The cost of being unlisted is that key changes for that
identity carry no log evidence and are attested by local pinning alone, which the client renders as
an explicit "not in a transparency log" state rather than as silence (Spec A §7.6).

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

This split is deliberate and is not to be widened. A blocking prompt in a 40-member group fires for
people the user cannot verify and has no way to act on, and the only thing it reliably teaches is
that these prompts are dismissed. The two places it blocks are the two places the user can do
something: a two-party conversation, and the moment a key the user has seen before is committed
into a group by someone else.

Safety numbers are an out-of-band fingerprint over the pair's identity keys for deliberate
verification. A key change is also written permanently into every group the pair shares.

Deliberately weaker than a verified-badge UX and deliberately stronger than silence: the operator can
assert a key, but never *quietly* replace one you have already seen.

## 11. Roles and administration

| Role | Count | May do |
|---|---|---|
| **OWNER** | exactly 1 | Everything. Sole authority for history grants, admin-set changes, ownership transfer |
| **ADMIN** | 0..n, delegated by owner | Add members, **remove MEMBERs and OBSERVERs only**, set MEMBER/OBSERVER, retention policy, group metadata, commit epochs |
| **MEMBER** | — | Send, read |
| **OBSERVER** | — | Read only. UI- and MLS-enforced in v1; not server-enforced (§9.2) |

**Only the OWNER may remove an ADMIN.** An admin may remove members and observers; a commit in
which a non-owner removes an admin is invalid, is refused by the committing client, and is rejected
by every receiving client on validation. This is two lines of rule and an unfixable incident
without it: one compromised admin could otherwise strip the entire admin set including the owner in
a single commit, and the removed owner's keys are gone from the very next epoch, so there is no
undo by construction.

No quorum for any normal operation. **Owner succession is the single exception**, and it is a
deliberate one — see below. Roles live in the group-context extension (§6), so they are covered by
the MLS transcript hash and no server can alter them.

**Self-service device management.** A member may add or remove **their own** device leaves and commit
that change. Otherwise revoking a stolen laptop would block on an admin. An identity may hold at
most **ten device leaves**, and a group at most **500 members** (§6). Both caps are enforced by the
committing client and by every receiving client on validation, and both are shown in the UI before
they are hit.

**A DM's policy is jointly controlled.** A DM is a two-member group and uses no second code path,
but the member who created it does not get to decide alone how long the other's messages survive.
Either party may **shorten** retention or the disappearing timer, and the change applies at once.
Neither may **lengthen** either unilaterally: a lengthening change is recorded as a pending request
and takes effect only when the other party sets the same value, expiring after seven days if they
do not. Every change and every pending request is announced in the thread, so nothing about how
long this conversation persists is decided silently.

**Two ways into a conversation, and one of them is withdrawable.** A group **invite link** is issued
by a member who is already inside the group and admits its holder to that group, bounded by the
group's admission policy and by whoever issued it. A **contact card** (§10.1) is issued by an
identity for itself and admits nobody to anything: it carries a capability token that lets its
holder ask that identity for a two-member group, and nothing else. Because the card is a capability
rather than a membership, it is rotatable: its owner mints the next generation at any time, which
registers a fresh rendezvous and retires the current one, so a redemption of the retired link is
refused while **every conversation already started is untouched**. Rotating costs printed cards and
old screenshots and never a conversation, which is what makes it a control people use rather than
avoid. It costs one thing more, and the client says so before it acts: a request that had been
deposited at the old rendezvous and not yet collected is discarded with it, because that request was
made under the capability being withdrawn. A client therefore collects everything outstanding at the
current generation **before** it retires it, and a rotation interrupted between minting and retiring
leaves both live and is completed on the next run rather than being restarted. The calls are Spec A
§7.3b and the screen is Spec C §12.7.

**An owner must hand the group over before leaving.** The leave action is refused for an OWNER
until ownership has been transferred to a current member; the client offers the transfer in the
same flow rather than reporting a bare failure. A group can therefore never reach the
unadministrable state through an ordinary, deliberate departure. This does not replace succession,
which covers the different case of an owner who simply stops using the app.

**Owner succession.** The group-context extension may carry a successor nomination: the member
nominated, the time of nomination, and whether succession is enabled at all. Promotion requires
**all** of the following, and the absence of any one of them makes a promotion commit invalid at
every receiving client:

1. Succession is **enabled** for the group. An owner may switch it off, and a group with it off has
   no succession path at all — that is the owner's choice to make, and the UI states its
   consequence.
2. The nominated successor claims the role.
3. **A supermajority of current admins countersign** that the owner is unreachable: countersignatures
   from at least `max(2, ceil(2 × admins / 3))` current admins, counted at the epoch the promotion
   commits from. A group with fewer than two admins therefore has no reachable succession path at
   all, and the client states that as the consequence of having no admins rather than presenting
   succession as available. One arithmetic rule, because two rules written in prose disagreed for a
   group with one admin — where one clause allowed a single signature to take a group and the other
   forbade it.
4. **Ninety days** have elapsed since the last record authored by any of the owner's device leaves
   was accepted in this group.
5. The nomination's floor is **at least ninety days**. A nomination carrying a shorter floor is
   invalid, so a group cannot shorten its own succession delay after the fact.

**The owner is warned, and that is a client obligation rather than a validity condition.** Every
client that holds the owner's identity MUST warn the owner on **every one of its devices** at 30,
60, 75 and 85 days since the last record any of the owner's device leaves authored in the group,
with escalating prominence, and any single record the owner authors resets the clock. This is
written as an obligation on clients rather than as a condition on the commit because no receiving
client can verify that a warning was shown on someone else's machine, and a validity condition
nobody can check is a condition that is silently skipped. The warning surfaces are Spec C §5.1 and
Spec C §9.10; the state that drives them is Spec A's `MessageSuccessionState`.

The earlier design — a majority of admins after 30 days — was a governance coup mechanism wearing a
recovery mechanism's clothes. Ninety days with escalating warnings still rescues a dead owner while
making the displacement of a live one effectively impossible: the live owner has four warnings on
four occasions and needs to send one message to stop it.

**History grants.** Owner-only, non-erasable, rendered as a persistent banner for the life of the
group naming grantee, epoch range, and granting owner. New members receive keys from their join epoch
forward by default.

## 12. Deletion and retention

### 12.1 Guaranteed

- **A deletion cannot be forged.** A `TOMBSTONE` is an MLS-authenticated message from the original
  sender.
- **An expired disappearing message is undecryptable by everyone**, including a device provisioned
  tomorrow and a seedphrase holder (§8.1).
- **Delete for everyone is bounded to 24 hours from sending**, and leaves a visible "message
  deleted" placeholder in the thread. A retraction request outside that window is refused by the
  sending client and ignored by receiving clients. An unbounded silent retraction would let someone
  rewrite a years-old shared conversation undetectably, which is a worse property than the one it
  buys.

### 12.2 Retention classes

| Class | Default | Set by |
|---|---|---|
| `PERMANENT` | never pruned | protocol (`RECOVERY_PUB`, key-change records) |
| `DURABLE` | **1 year**; text default | group admin, bounded by the server's advertised text-storage cap and minimum |
| `MEDIA` | **1 month** | group admin, bounded by the server's advertised media window |
| `EPH(bucket)` | off by default; 1h / 8h / 1d / 1w / 4w | per conversation; admin-settable for groups |

A group that never opens a retention screen sends no value, and the message server applies its own
advertised text default — one year on a stock server. Indefinite text retention is still reachable,
but only by asking for it explicitly and only on a server that advertises no text cap; on a server
that advertises one, the request is stored as that cap. This is what makes the one-year default a
property of the system rather than a promise about how clients behave.

Media is a distinct class rather than inheriting its parent's, because it is most of the storage and
little of the value after a month. An attachment on an *ephemeral* parent inherits the parent's key
class — it must not outlive the timer — and otherwise uses `MEDIA`.

**A disappearing-timer change is forward-only.** It applies to messages sent after it; messages
already sent keep the class they were sealed under. The cryptography forces this — a durable message
is encrypted under the durable class key, and re-classing it after the fact would be a promise about
client cooperation rather than a guarantee. So when either party to a DM shortens the timer (§11),
what takes effect at once is the class of the next message, not the fate of the previous one.

**The message server advertises three limits, and every group operates inside all three:**

1. a **text storage cap** — the longest `DURABLE` retention it will hold, alongside the minimum it
   promises to honour;
2. a **media and file window** — the longest `MEDIA` retention it will hold;
3. a **file size limit** — the largest single attachment it will accept. Default **100 MB**.

A group policy outside any of them is clamped or floored by the server, which accepts the commit
and reports what it applied (§15 item 1); the group's transcript-covered policy is unchanged, so a
move to a server with different limits restores the original intent. **A group may raise its own
text retention above the server's default only if the server permits group overrides**, which it
advertises alongside the three limits; where it does not, every group on that server keeps text for
the server's configured period and the UI says so.

Text retention defaults to one year rather than to forever. "Forever" is not a default anyone
chose; it is what happens when nobody sets a number, and it makes the honest-limits statement in
§13 worse for every user who never opened a settings screen.

**What an expired disappearing message leaves behind.** The record's row survives, because the
per-group `record_id` sequence is gapless and a client detects a withheld record as a hole in it —
deleting rows would make every disappearing message manufacture a false withholding warning. The
row keeps its `record_id`, `epoch`, `retention_class` and `size_bucket`, and **its `sender_handle`
is overwritten with sixteen zero bytes**. Keeping a row is justified by the gapless-id argument;
keeping the sender in it is not, and would leave a permanent, per-sender, timestamped metadata
trail as the residue of the feature whose entire purpose is to leave none. The server-side
mechanism is Spec B §7.2.

Read receipts and typing indicators are **on by default**, `EPH(bucket 0)`, never persisted, batched,
individually disableable. **They are also reciprocal: turning yours off hides everyone else's from
you.** With read receipts off, a message you send stops at delivered and never reaches read, and no
read state from anyone else reaches you; with typing indicators off, nobody else's appears. Without
that rule the setting is a one-way observation tool, in which the most privacy-conscious person in a
conversation is the one who learns the most about everyone else — the opposite of what someone
reaching for the switch is asking for. Signal, WhatsApp and iMessage all resolve it the same way,
and the rule is enforced below the UI (Spec A §7.2) so a screen that forgot it could not leak
anything.

**Delivery receipts are on by default and are the same class of record**: a device emits one
`EPH(bucket 0)` receipt when it decrypts a message, so "delivered" is a statement by a device that
actually decrypted rather than an inference by a server that cannot. They are batched, never
persisted, and individually disableable, and their metadata cost is disclosed in §9.5 and §13. They
are **not** reciprocal: a delivery receipt is a statement about a device being online rather than
about a person having read something, and the two are not the same disclosure.

**A reaction carries any emoji.** The reaction field is not a fixed list. A reactor picks from the
full emoji set their system offers, and the reaction travels as a length-prefixed UTF-8 string
inside the encrypted body like any other message content. Four consequences follow, and all four are
stated here rather than discovered later.

**Font coverage.** Emoji are added to Unicode every year and no shipped font has all of them, so a
reaction that renders as a picture on one device can render as a replacement box on another. A
client shows what it received — the box, with the codepoint sequence available on inspection — and
never substitutes a different emoji, drops the reaction, or hides the count. A missing glyph is a
fact about the reader's fonts, and quietly rewriting someone's reaction to something the reader can
see would be a worse property than showing a box.

**Sequences.** Many emoji are several codepoints joined with zero-width joiners, and a client whose
text shaper does not know a particular sequence renders its parts instead of the whole. A reaction is
therefore bounded to exactly one extended grapheme cluster, so a sequence is one reaction and never
becomes several, and the wire encoding is validated on both send and receipt against a Unicode
version this project pins and updates deliberately. Two clients on different Unicode versions must
agree on what is legal, and the only way to have that is to name the version.

**Normalisation.** Reactions group into counts, and grouping fragments the moment two byte sequences
that look identical are treated as different. The grouping key is the reaction in Normalisation Form
C with skin-tone modifiers and variation selectors removed; the original bytes are kept for display.
Skin tone is stripped rather than preserved because a reaction is a one-tap gesture and a skin tone
attached to it says something about the person reacting that they did not choose to say, while a
thumbs-up is a thumbs-up regardless of the tone the sender's keyboard defaults to.

**A reaction is content, so reactions are a moderation surface.** With a fixed list, the worst a
reaction could carry was one of eight approved meanings. With the full set, a reaction is something a
person wrote, and it can be used to harass. There is no reporting route behind it, because
moderation recourse is deferred (§15 item 4); what exists is muting, leaving, and removal by whoever
administers the group. This is a cost accepted knowingly in exchange for the feature every user
expects, and §13 states it to users in those terms.

### 12.3 Not guaranteed

- Delete-for-everyone cannot claw back what a recipient already decrypted.
- Durable-class messages remain recoverable while epoch keys survive.
- **A server that silently withholds a deletion is not detectable in v1.** Stream digests are deferred
  to V2, and there is one message server with no second party auditing its pruning, so this is a
  trust assumption in whoever administers it, and §13 says so.
- Server-side pruning is best-effort.
- **A backup is a copy that outlives a delete.** The message server takes nightly encrypted backups
  and archives write-ahead logs continuously, and its point-in-time recovery window is **48 hours**.
  Until a deletion falls out of that window, the operator of the message server can still produce
  the ciphertext of a record you deleted. This qualifies the deletion story rather than sitting
  beside it, and 48 hours is a number to publish in a transparency report rather than a database
  parameter to tune quietly. Expired disappearing messages are the exception and are unaffected:
  their guarantee is key destruction, not row deletion, which is precisely why it survives backups.
- A group whose members have all left is reclaimed 30 days after it is closed, which is when the
  last of its stored ciphertext and its retained read keys are destroyed.

### 12.4 Required UI language

- Disappearing: *"After the timer, this message can no longer be read by anyone — the key is destroyed
  on every device and on the server."*
- Delete for everyone: *"Removed from this conversation on every device that is online and honest.
  Anyone who already read it may have kept a copy, and we cannot detect that."*
- Durable default: *"Messages are kept so your new devices can see your history. That means the server
  holds a copy until it's deleted or expires."*
- Delete for everyone, outside the window: *"Messages can only be removed for everyone within 24
  hours of sending."*
- Expired disappearing message: *"The content disappears, the fact of the message does not."*

Never say "gone forever" for the durable class.

## 13. Honest limits

**Better than Signal.** Disappearing messages are enforced by key destruction, not client cooperation
— including against a device set up tomorrow and against a seedphrase holder. Post-quantum protection
for stored messages, not just the connection. History follows you to a new device without it reaching
back past the day it was added.

**Same as Signal.** The server holds ciphertext only and cannot read anything. "Delete for
everyone" cannot claw back what someone already read, and it is bounded to 24 hours. **And in v1,
one message server that knows your account, your groups, and your activity** — server choice is a
V2 feature, so this line is parity, not an advantage.

**Worse than Signal, and why.** The server knows group membership; Signal hides it with anonymous
credentials. We keep messages by default — one year for text, one month for media — so your other
devices can see history. Your operator can see that your device talks to a message server and how
much. **A server that ignores its own deletion policy is not detectable in v1.** **The message
server holds each epoch's `write_key`, so it can forge the access-control tag on a record it
injects** — such a record fails MLS verification at every client, so this is a denial-of-service and
noise vector rather than an authenticity break, and it is written here so nobody discovers it and
assumes it is worse than it is. **Delivery receipts tell the server when a device of yours was
online and decrypting**, which read receipts alone do not. **Backups outlive deletions for up to 48
hours** (§12.3). And **the 24-word phrase is a master key: it cannot be rotated, and whoever holds
it reads all durable history past and future in every group and can act as you.** Expired
disappearing messages are the one thing it does not unlock. **A contact card leaves the server a
first-contact edge:** it learns that a client sent a contact request to the owner of a card, and
when, though it learns neither party's identity from it and the record is gone in a week (§9.5).
**And rotating a card is the only block we ship**: with per-contact blocking deferred, the way to
stop unwanted contact requests is to mint a new card, which cuts off the person who is abusing you
and everyone else you handed the old one to, at the same moment.

**Better than Matrix.** One message costs one upload regardless of group size. No conflicting-history
problem. Membership payloads can be erased on request.

**Worse than Matrix.** One server, no replication, no migration in v1: if it is lost, the groups are
lost. Deliberate, and revisited in V2.

**Deliberately short of SimpleX.** Durable identities and a searchable directory, so you can be found,
re-added, and recovered.

**On verification.** Nobody is verified by default and there is no badge. You are warned loudly when a
contact's key changes from one you have seen before, and never silently switched.

**On metadata after removal.** A member you remove loses every decryption key from that epoch
forward immediately, and loses the ability to read the group's metadata from the message server 90
days later (§9.2). It is not instant, and 90 days is the price of letting a member who closed their
laptop for a season come back and catch up.

**On what is written down.** The message server records aggregate counters and error classes and
nothing per identity (§9.7). It is not a claim that nothing is ever logged: it is a claim about what
may be logged, which is a rule an engineer can follow at three in the morning. If you ask for help
with a problem, you can turn on a bounded diagnostic session yourself, and nothing is recorded about
you unless you do.

**On the two identities.** Your messaging identity and the URnetwork account that pays for the
traffic are not linked unless you turn on directory listing. The cost of that is ours to state:
there is no cross-boundary abuse tooling, and support cannot answer "which account is this" — if you
write to us about an account, we cannot tell you anything about the messages on it, and if someone
is abusing you from an identity you cannot name, we cannot connect it to an account either.

**On reactions.** A reaction can be any emoji, so a reaction is something a person wrote rather than
a choice from a list we approved. That makes it the same kind of surface as a message: it can be
used to say something unwelcome, and there is no reporting route behind it, because moderation
recourse is deferred (§15 item 4). What you have instead is muting the conversation, leaving it, or
removing the person if you administer the group.

## 14. Implementation slices

| # | Slice | Contains |
|---|---|---|
| 1 | `connect/mls/` | RFC 9420. **Acceptance: the IETF test vectors pass**, cross-checked against OpenMLS. |
| 2 | `connect/message/` | Storage records, retention classes, ratchet, PQ composition, `write_auth`, padding, `COVER`. `server_attachment`, `req_auth`, recovery proof, **the `EPH(0)` delivery-receipt record**, **the reaction body as a length-prefixed UTF-8 string**, **the two-sentinel `durable_ttl_seconds` encoding**, and **the contact-card encoding, the rendezvous derivations and the five rendezvous signature preimages**. Freezes the wire format — §8, §8.3 and §9.2 must be final before this slice starts, and the additions named in bold must land here rather than with the client work that renders them. |
| 3 | `message-server` | Store, ordering, single-commit agreement, `write_auth` verification, retention, fetch attestation, **the contact rendezvous of §9.8**. §9.7 is an acceptance criterion. |
| 4 | Client core in `sdk` | Group state, local store, KT client, provisioning. |
| 5 | `message-windows` text | Send, receive, groups, TOFU warnings, reactions, **rendering** read and delivery receipts. **First testable build — internal only.** |
| 6 | Disappearing messages | `eph_root`, buckets, tombstones. |
| 7 | Multi-device | Provisioning UI, device management, revocation. **The public beta starts here.** |
| 8 | Attachments | Blob store, `MEDIA` class, thumbnails, resumable upload. |
| 9 | `/server` operator | Discovery directory, KT log. Includes the VRF-indexed prefix tree, the history tree, and the four client endpoints of Spec B §9.4 — not the log alone. |

The rendezvous is split across those two slices on purpose: its encodings are wire format and freeze
with everything else in slice 2, and its endpoint is server work in slice 3, so slice 5 — whose
first acceptance criterion is two strangers exchanging cards — has both halves before it starts.

Slice 1 is the schedule risk and is first because it has an objective completion test. Slices 1–5
produce something two people can text on.

**What "beta" means, and when it starts.** Slice 5 is an **internal-only** build. It is text-only,
single-device and unnotified, and calling that a beta externally sets an expectation that is hard to
walk back. **The public beta starts when slice 7 is complete** — text, disappearing messages and
**multi-device**. Multi-device is deliberately ahead of attachments in the order above: it is the
thing this product has that Signal Desktop does not, whereas attachments are table stakes that
nobody switches for.

**Three things gate general availability rather than the beta**, and each is checkable on the day of
a release rather than on a calendar:

- the key-transparency log, its four client endpoints and its monitor role (§15 item 6);
- a working contentless push wake, so the product can notify a user while it is not running
  (§15 item 2);
- code signing for the shipped Windows binaries. The beta ships unsigned, with the cost accepted and
  stated in Spec C §2.7.

**The external cryptographic audit is a decision taken at slice 5**, when there is working code to
scope a quote against, rather than a commitment made now against a design. The risk is worth
restating rather than filing: audit firms book months out, so if the answer at slice 5 is yes, the
lead time lands on the critical path to general availability instead of running alongside the build.

## 15. Open items

1. **Retention negotiation — RULED, warn and proceed.** Two distinct cases, previously conflated as
   "policy exceeds the server's advertised minimum," which is incoherent:
   - a group policy **longer** than the server's `media_ttl_max_seconds` → the server clamps **down**;
   - a group policy **shorter** than the server's `durable_retention_min_seconds` → the server floors
     **up**.

   In both cases the server accepts the commit and returns `REASON_RETENTION_CLAMPED` with the applied
   values; the client renders a one-time in-group notice naming the **effective** policy. The group's
   transcript-covered policy is unchanged. Refusal is not an option in either direction.
2. **Push transport — RULED, a general-availability gate.** WNS for Windows; APNs and FCM when
   mobile lands. No push exists in any operator today. **The beta ships without push**, and Spec C's
   copy stands as written: "URmessage can only notify you while it's running." A working
   **contentless** wake — one that carries no sender, no preview and no plaintext group id — MUST be
   live before any non-beta user, alongside the key-transparency log. Owned jointly by Spec A
   (`RegisterPushChannel`), Spec B (server-side channel registry) and Spec C (§10.2). **The Azure AD
   application registration the Windows path needs still has no named owner, and that is the long
   pole on this item.**
3. **Owner succession — RULED and specified in §11.** The nomination lives in the group-context
   extension, so it is transcript-covered and no server can alter it. The residual risk that a
   colluding admin majority displaces a merely-offline owner is bounded by four things rather than
   one: a supermajority rather than a majority, a 90-day floor rather than 30, escalating warnings on
   every owner device, and an owner opt-out that disables the mechanism entirely. A live owner stops
   a displacement by sending one message. The item is closed.
4. **Moderation recourse** deferred by decision — revisit with legal counsel before any public
   launch. **Reporting a user is deferred with it**: a report route without a moderation process
   behind it is a form that goes nowhere. What v1 ships instead is **mute and leave**, which is
   sufficient because directory listing is opt-in (§10.1) and therefore most unsolicited contact
   never starts. Blocking a contact is also deferred, for the same reason and because its
   cross-device carrier is unscoped. Blocking's absence has one concrete substitute and it is stated
   rather than implied: rotating a contact card withdraws the capability from every holder at once
   (§11). It is a real remedy for unwanted first contact and a blunt one, and it does nothing at all
   about someone already inside a conversation, for whom v1 offers mute, leave, and removal by
   whoever administers the group.
5. *(folded into item 4.)*
6. **Key-transparency log — RULED, a release gate rather than a date.** Spec B §9.4 specifies the
   VRF suite, the tree arithmetic, the STH preimage, the history tree, the four client endpoints, the
   signing key and the monitor role. §10.1 makes the log required rather than optional, and this item
   asked for a completion date. The ruling: **the log is a general-availability gate.** URmessage may
   be distributed to beta testers while every key-change row and every directory lookup renders
   `kt_unavailable` explicitly, and it MUST NOT be offered to any non-beta user until the log, its
   four client endpoints and its monitor role are live. This is the same shape as the external
   cryptographic audit of item 7 — a condition checkable on the day of a release rather than a date on
   a calendar. The item is closed. Confirmed by the project owner: this is the ruling, not a proposal,
   and the log's absence blocks general availability rather than the beta.
7. **External cryptographic audit — RULED, decided at slice 5.** Whether to commission a funded
   external audit of the MLS implementation and the storage layer is decided when slice 5 exists and
   a firm can be given working code to quote against. Spec A's audit gate is written accordingly: it
   blocks general availability **if** an audit is commissioned, and the decision itself is scheduled
   rather than assumed. The accepted risk, restated so it is not rediscovered: audit firms book
   months out, so a "yes" at slice 5 puts the lead time on the critical path to general availability
   rather than in parallel with the build.
