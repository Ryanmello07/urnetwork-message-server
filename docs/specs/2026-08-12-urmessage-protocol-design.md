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

**Amendment to revision 9 — 2026-08-25 — §8, `record_id`.** Not a new revision: no rule changed, and
every document that names this one as its normative parent still names revision 9. §8's `RECORD` block
listed `record_id` as its first field beside fourteen fields that are all inside `record_bytes`, while
Spec B §4.3.3 carries it as a **sibling** of `record_bytes` — field 13 of the enclosing protobuf,
ignored on submit and populated on read. The MASTER-wins rule made that a real conflict rather than a
detail, and it resolves the way Spec B and the shipped codec already had it, because the block's own
annotation settles it: an id assigned **after** acceptance is assigned after `write_auth` has been
computed and verified, so an id inside those bytes would be a value the MAC covers, which is exactly
what "NEVER authenticated" denies, and would make the id unassignable without invalidating the record.
§8 now says so where a reader building a codec from that block would see it. Found by implementing the
codec, not by re-reading the spec.

**Amendment to revision 9 — 2026-08-25 — §8, the record AADs' `alg_id`.** Not a new revision: no rule
changed, a value that was only inferable is now written down. §7.1 requires every AEAD to carry its
algorithm identifier inside the authenticated bytes and §8 writes `u16(alg_id)` into both AAD blocks,
but nothing said which of §7.1's identifiers a record's AADs carry. Both preimage builders take it as
a parameter, so the divergence is not one either side's tests can see: two implementations that each
read this document and chose differently would agree on the format, agree on the keys, and fail the
AEAD on every record. §8's own key derivation settles it — a 24-octet nonce is XChaCha20-Poly1305's —
so the answer was always `0x0021`, and §8 now says so rather than leaving it to be inferred from a
nonce length. Found by building the two preimages, before the sealer that would have chosen.

**Amendment to revision 9 — 2026-09-17 — §8.4: `aad_mls` goes to v2, and the three half-adopted items
are ruled.** **This one changes a rule and it changes a preimage**, which is the first amendment since
§8's `eph_window` to do the second. The owner ruled that MLS is adopted **fully** rather than
partially, on the finding that half-adopting it is what left the holes below.

*(1)* **§8.4.2 now carries v2.** `aad_mls = H("URmessage/v2/aad/mls" ‖ AAD_body ‖ u32(generation) ‖
head_commit)`, 160 octets of preimage, still a 32-octet digest. Two things v1 left outside the
signature are now inside it. **The MLS generation:** RFC 9420's `FramedContentTBS` covers the group
id, the epoch, the sender, the `authenticated_data`, the content type and the content — **and no
generation** — while the generation sits in `SenderData` under a **group-shared** secret and every
leaf's ratchet is derivable from a **group-shared** `encryption_secret`. So a member could open
another member's frame, keep its `FramedContent` and its signature octets byte for byte, and re-seal
them at a generation of its own choosing; the receiver obeyed it, and the true sender's own frame at
that generation was then dead for ever. **The head plaintext:** `ct_head` is sealed under the same
`record_key[i]` every member derives and no field of the frame covered it, so a member could re-issue
another member's genuine body at the same position under a head — and therefore a `sent_at` — of its
own writing. `head_commit` is **keyed**, `HMAC-SHA-256` under
`HKDF-Expand(record_key[i], "rec/v1/head-bind", 32)`, because `aad_mls` travels in the clear and an
unkeyed hash of a public preimage and a millisecond timestamp is a few million guesses for the
**server**.

*(2)* **The two land as ONE version, one flag day, one live re-run**, because two wire changes would
cost two of each and the second would re-measure the first. **And the wire cost is zero:** `aad_mls`
is a digest at both versions, so `authenticated_data` stays 32 octets, `octet_length(ct_body)` is
unchanged at every rung, no rung moves, the message server is not edited and Spec B is not revised.

*(3)* **§8.4.3 gains a third refusal, and it is about ORDER rather than about a value.** R1 and R2
must be decided on a reading that steps no ratchet and erases no key. Under v1 that ordering was a
defence against a denial channel; under v2 it is the refusal itself, because opening a frame is what
commits the generation the frame names. The pre-ratchet reading must therefore answer the sender
leaf, the `authenticated_data` **and the generation** — all three out of one `SenderData` open — and
a reading that answers the first two only does not satisfy R3.

*(4)* **§8.4.4 is CORRECTED: the frame's overhead step function has four steps and this document
published three.** Two varints widen, not one, and the band `16,300 ≤ P < 16,384` costs 196 octets
and was named nowhere. The ladder columns are unaffected, which is why it survived — the ladder was
measured by walking and the step function beside it was derived — and it becomes load-bearing at
§8.4.6, which is arithmetic over exactly this function.

*(5)* **§8.4.6 rules the size ceiling** (ledger **203**'s defect half): the early size refusal runs on
the **framed** length, not the caller's, so a body of 65,335 to 65,532 octets no longer reserves a
stream index and spends an MLS generation on its way to a refusal that was certain. It is
implementable because §8.4.4 measures that the frame's length is a function of the plaintext's length
alone.

*(6)* **§8.4.7 rules the three half-adopted items.** A member cannot open its own application record,
that is MLS, and a device renders its own sent lines from a copy it kept — **ratifying what `sdk` had
already built and holds in 37 `cp3b` cases**, and recording that it was built ahead of the ruling. A
ceremony record's `sender_handle` is **routing and not attribution**, full adoption does not reach
that arm, and the one row that admits an authentication is the commit row, where the epoch machinery
owes it. And `ReceiverKey` is **unexported**: measured at **zero** production callers across all
three repositories, it commits a ratchet with no authentication and nothing bounds repetition.

*(7)* **What this ruling CLOSES and what it does not.** It closes `connect` open items **MG-6** and
**MG-4**, records **MG-5**, and closes ledger item **204** — `sent_at` was the largest forgeable field
in the system and is now covered by the sender's signature. It does **not** close ledger item **199**:
`is_commit`, `size_bucket`, `expire_at`, `blob_id` and `H(server_attachment)` are still outside every
signature and still cannot be brought inside one, and the first of them is the one the server acts on.
Item 199's list loses its sixth entry and keeps its five.

**Amendment to revision 9 — 2026-09-18 — §7, §8.1, §8.2, §8.3: three owner rulings transcribed, and
one red-team finding adopted four weeks late.** **Unlike the two amendments above, this one does change
rules** — and it is filed as an amendment rather than as revision 10 because the rules changed when the
owner ruled them on 2026-09-13 and when M-15 was adopted, not here: this document was simply the last
of four to be told. Whether that warrants a revision bump is **not decided here**, because a bump moves
the parent pin and the baseline row of both Spec A and Spec B and no ruling covers that; it is recorded
in `SPEC-LEDGER.md` as a residual for the owner.

- **The three rulings of 2026-09-13 (§8.1, §8.2, §8.3).** Recovery wraps land **after** the
  `EpochComplete` marker, as ordinary records of the now-open epoch; the device wrap is sealed under an
  **MLS-exporter envelope**, `env_key[k]`, with the recovery wrap KEM-sealed as a consequence and the
  past-epoch caching obligation live; and the device wrap becomes **two records**, a `PERMANENT` one
  carrying `pq_secret` and an `EPH` one carrying `eph_root`, so `expected_wrap_count` is
  `2 × device_leaves + 1`. This document had carried the pre-ruling fan-out order, the single-record
  device wrap and the pre-split sizing since 2026-09-13, against Spec A and Spec B which had all three.
  **The accepted cost of the first ruling travels with it**, and is now stated in §8.2 rather than only
  in the ledger: `expected_wrap_count` is **decorative for the recovery arm**, and **nothing detects a
  missing recovery wrap** — not the count, not the `no_wrap` gap, not a live member, not the server.
  Ledger item **141**, which filed the divergence rather than hiding it, closes here.
- **§7's wrap KDF adopts red-team finding M-15**, raised on 2026-08-12 and carrying **no disposition of
  any kind** for four weeks — no ledger item, no owner decision, no spec revision, adopted nor
  rejected. `wrap_key` now derives its own 24-octet AEAD nonce and binds `alg_id`, the target's X-Wing
  public key and the ciphertext into `info`, over an Extract-then-Expand under a named salt. It costs
  **zero wire bytes** and migrates no code. §7 states what each added element buys, and names the one
  substitution the adoption required: M-15's block was written against the pre-X-Wing combiner revision
  5 deleted, so its four separate X25519/ML-KEM values become the two X-Wing ones. Ledger item **144**
  closes with it.
- **What it does NOT settle, named so no implementer concludes it did.** `target_id`, `target_type` and
  `payload_type` are inputs to §7's `info` that this document does not define — the first was already
  undefined before the amendment and the other two arrive with M-15. §7 carries them as inherited gaps.
  Ledger items **132**, **133**, **134**, **142** and **143** stay filed and unruled, and §8.1 and §8.2
  name **143** and **142** where a reader of the construction will meet them.

**Amendment to revision 9 — 2026-09-19 — §7, §8, §8.2: M-15's SECOND instance, which the sweep that
closed the first did not report, and the one contradiction the transcription left standing.** The
2026-09-18 amendment ran M-15's class across this document and reported the §7 `wrap_key` instance and
one sibling out of scope (Spec A §5.14's rendezvous deposit, ledger item **145**). It missed a member
of that class **in the section it was already editing**.

- **§8.2's epoch snapshot was the second instance.** `K_snapshot[n] = HKDF-Expand(storage_root[n],
  "snap/v1", 32)` was a 32-octet AEAD key with **no nonce, no `alg_id` and no AAD anywhere in the
  corpus** — M-15's defect, in M-15's own document, one section from where M-15 was adopted. It now
  expands **56** octets to `K_snapshot[n] ‖ nonce_snapshot[n]` and states an `AAD_snap` binding
  `alg_id`, the group and the epoch. `K_snapshot[n]`'s **value is unchanged** — HKDF-Expand's prefix
  property, measured over 1,000 roots rather than asserted — so it costs zero wire bytes and no code,
  and §5.11 correction **E2**'s quotation of the key stays true. What the derived nonce does **not**
  buy is stated beside it: both halves are functions of the epoch alone, so a second snapshot sealed
  at one epoch by step 6's republish path reuses the pair. New ledger item **148** files that.
- **§8's *"this layer adds no signature"*** was the **seventh** location the three rulings of
  2026-09-13 invalidate and the only one the 2026-09-18 transcription left standing: §8.2 now makes a
  body signature a **MUST** on all three wrap record kinds. **I5 is not amended** — it says *"no
  second signature over **content**"* and a wrap body is not content; §8's sentence had dropped the
  qualifier.
- **§7's `info` table and its gap list read against each other**, and now do not: the table
  enumerates `target_type`'s **domain**, the gap list says no document gives its **encoding**, and
  both are true at once. The gap is unchanged and still unruled.

**Why the sweep missed it is recorded, because that is worth more than the fix.** New ledger item
**147** carries it: the 2026-09-18 sweep was run as a search for the *construction* M-15 named — a KEM
seal, `HKDF-Expand(ss, …)`, `hybrid_ct` — and the snapshot is not a KEM seal, so it fell outside the
query while being inside the class. The class M-15 actually names is **every AEAD key in this corpus
derived by a bare 32-octet expand**, and that class is greppable.

**Amendment to revision 9 — 2026-09-09 — §7 and §8.2: the wrap body's grammar, its signature preimage
and its padding, ruled as composite `C3`. This one changes rules.** m1 open items `M1-1` and `M1-7`
were **ruled together** on that date and this document is where the shape lives; Spec A §5.11 keeps
the measurements and the residuals. **What is now normative:** an 11-octet
`u8(wrap_format_version) ‖ u8(target_type) ‖ u8(payload_type) ‖ u64(content_epoch)` envelope **outside**
`hybrid_ct` in every wrap body, with **no `publisher_leaf_index`**; `aead_ct`'s plaintext as
`secret ‖ LP(identity_pub) ‖ sig`; a written-out signature preimage carrying **`LP(wrap_envelope)`**
ahead of `LP(ct_xwing)`; and one padding rule — `LP32(len) ‖ body ‖ zeros` with an accumulating,
position-free refusal of a non-zero tail — over **all three** wrap bodies, the recovery wrap included.
**Zero wire octets:** `ct_body` stays 4,112 on both wrap kinds, the records stay 4,398 and 4,428, and
the epoch fan-out stays ≈ 11.5 MB.

- **Two of the four terms are repairs the three independent option sets did not contain**, and they
  are the reason this is worth an amendment rather than a transcription. `LP(wrap_envelope)` closes a
  signature that otherwise covers the record header, the KEM transcript and the secret and **not one
  octet of the envelope this ruling adds** — a defect three independent analyses missed, because a
  sealer and an opener agree about a field neither is asked to defend and **no round-trip test can
  see it**. The `LP32` prefix over the recovery wrap collapses two body grammars into one, so a parser
  no longer needs the server attachment's kind to decide whether the body's first four octets are a
  length. Ledger items **176** and **177** close with this amendment.
- **What was ruled against, and it was a choice.** Putting the signature in the server attachment
  would let any party, the operator included, refuse an unsigned wrap on the wire bytes alone; its
  price is +68/+104 octets a record, ~+170 KB an epoch, a Spec B §5.1 check-3 change, and publicly
  verifiable per-epoch attribution of the committer across all 2,501 wrap records — §4.2's own
  boundary. **The two cannot both be had**; the privacy was taken, and §8.2 says so where a reader of
  the *"MUST NOT honour"* sentence will meet it.
- **What it does NOT settle, named so no implementer concludes it did.** `target_type` and
  `payload_type` still have **no code point** — this ruling puts them on the wire and does not say
  which octet each class takes, so §7's `wrap_key` stays underivable by a second implementation.
  `aead_ct` still has **no stated AAD**, and this ruling puts a signature and a public key inside it.
  Whether `LP(identity_pub)` joins the preimage's own `LP(payload)` term is stated nowhere, so the
  preimage is 1,320 octets or 1,356 and a builder must be told which. And **`target_id` is still
  undefined.** Ledger items **132**, **133**, **134**, **142**, **148**, **152** and **178** stay
  filed and unruled; **176**, **177** and **179** no longer do.

**Amendment to revision 9 — 2026-09-07 — §8.1's ledger pointer, and nothing else. Not a new revision:
no rule in this document changed.** Ledger items **143** and **169** were **ruled** that day, together,
as shape **A1** — the `stream_index` counter is one per `(group_id, sender_handle)` and carries no
retention class, and `i = stream_index` in every ladder including the device wrap's. §8.1 pointed a
reader at 143 *"which is filed and not ruled"* at exactly the place the construction produces the
hazard, and that pointer now carries the ruling. **What this document declares is unchanged**, and that
is the ruling's own argument rather than an accident: A1 was chosen because it is the counter §9's
`message_sender` and the shipped message server already key on, so the client moved and the schema, the
server and every construction here stayed still. The position rule itself lives in Spec A §5.3 and
§5.6 (revision A-21), because it is about ladders and this document is about the constructions under
them. Ledger items **132**, **133**, **134**, **142** and **148** stay filed and unruled; **143** and
**169** no longer do.

**Amendment to revision 9 — 2026-09-11 — §8 and §8.1: the `EPH` carve-out this document stated
nowhere. A RULE IN THIS DOCUMENT CHANGES, and that is said first because the two amendments before it
opened by saying the opposite.** The rule *"`ct_head` is always under the **durable** class, since it
is always retained"* was stated here **unqualified**, at §8's record listing and at §8.1's ratchet
paragraph, with no `EPH` annotation at either — while Spec A §5.3, which owns the construction, has
stated the rule **and excluded `EPH` in the same section** since revision A-20, and
`messagegroup.SealRecord` has refused every non-`DURABLE` class since m1 wave 1. *(**This sentence
read "in the same paragraph" and that is FALSE. Corrected in place 2026-09-11**, the same day, and in
place rather than by erasure because the next reader will check it: §5.3 states the rule in prose at
**`§5.3:1248-1257`** and again in its Go block at **`:1225-1231`**, and carries the `EPH` exclusion at
**`§5.3:1290-1299`** — **47 lines below the rule paragraph's own statement of it at `:1250`, 49 below
that paragraph's first line, and 70 below the Go comment** — with five paragraphs between them. The amendment below is **strengthened** by the correction rather than
weakened: a Spec A reader who stops at the rule does not reach the carve-out either, so the exclusion
was not where a builder meets the rule in **either** document.)* **The harm was never
the rule; it was that a second implementer building from the top document would seal an `EPH` head
under `K_durable` and nothing in the corpus or the tree would stop them** — widening the shipped
refusal to admit `PERMANENT` reddens **2 of 208** `messagegroup` tests and both are the blanket
refusal gates themselves, so the divergence between the documents is caught by no test at all. §8 and
§8.1 now carry the exclusion in this document's own voice. **This inverts revision A-20**, which ruled
*"MASTER §8.1 stands as written and Spec A §5.3 is the document that changes"* (`SPEC-LEDGER.md`
item 128): MASTER §8.1 is now the document that changes and Spec A §5.3 is unedited. It also spends
the argument revision **A-21** called *"the ruling's own strongest argument"* — *"no MASTER rule
change"* — which is why the inversion is named here rather than absorbed. **Ledger item 152 is NOT
ruled by this amendment:** what class an `EPH` head is keyed under stays open, and it must be ruled in
one sitting with ledger open item **M1-27**, because `K_eph[n][b][t]`'s window `t` has no unit, no
origin and no clock in any document — so no `EPH` head has a computable key today whatever class it is
assigned. Ledger items **132**, **133**, **134**, **142**, **148**, **152** and **178** stay filed and
unruled.

**Amendment to revision 9 — 2026-09-11 (second pass of that date) — §8's `body_hash` line: the same
premise, six lines above the line the amendment above corrected and inside the same fence. A RULE IN
THIS DOCUMENT CHANGES, and it is the rule the note above was written to fix.** §8's record listing
carried *"`body_hash` 32B H(ct_body); RETAINED when `ct_body` is erased"* — unqualified, in the same
column-aligned field listing, **six lines above** the `ct_head` line the note above amended. It is
false for the same one class and for the same reason: Spec B §7.2 **zeroes `body_hash`** for
`EPH(1..5)` in the one statement that sets `ct_head = NULL`. The line now carries the scope. **What
this says about the note above is worth more than the line itself:** that pass derived its class from
two regular expressions, printed the complement, and *still* reached only the sites its own regexes
named — this line matched neither, so the shape of the defect survived inside the correction. The
class for **this** pass was derived by reading §8, §8.1, §9.1 and §12.2 end to end and by reading
Spec A §5.1 and §7 and Spec B §3.2 and §7.2 the same way; what reading cannot see is stated in
`SPEC-LEDGER.md` beside the result. **Three sites outside this document are closed in the same
commit**, all of them found by reading and none by the earlier queries: Spec A §7's server-conformance
row **S10**, which stated both clauses unqualified and — after the amendment above — contradicted
MASTER §8 and §12.2, the two sections it cites as its own authority; and Spec A §5.1's two Go struct
comments, one of which was this document's **pre-amendment wording, verbatim**. **`EPH(0)` is not in
scope anywhere here:** it is never persisted, so it has no `body_hash` on disk to retain or zero.
**Nothing is ruled by this amendment.** Ledger item **152** is still open, still to be ruled in one
sitting with **M1-27** — `K_eph[n][b][t]` has no computable `t` and `message.EphBucketSeconds(0)`
answers `-1` — and ledger items **132**, **133**, **134**, **142**, **148**, **152**, **178** and the
new **181** stay filed and unruled.

> **ITEM 152 AND M1-27 WERE BOTH RULED ON 2026-09-13, IN ONE SITTING, AND THE FIRST OF THE TWO
> RULINGS REVERSES A STANDING ONE. The note above is dated and stands as written; this is the
> forward pointer it owes, placed here because this is where a reader of that note stops.** See the
> ninth amendment below.

**NINTH AMENDMENT — 2026-09-13. `ct_head` IS KEYED UNDER THE RECORD'S OWN CLASS KEY, WHICH REVERSES
THE RULING OF 2026-09-07; AND `record_bytes` GAINS A FIELD, WHICH REOPENS A SECTION §14 FROZE. Both
halves are the owner's, both are ruled, and the second is the price of the first.**

**What was ruled on 2026-09-07 and is now reversed.** *"`ct_head` is always sealed under the DURABLE
class ratchet, whatever the record's own retention class"* (ledger item **128**; Spec A revision
**A-20**), on the reason *"the head is always retained, so it is keyed by the class that is always
retained."* **Why it was wrong:** the premise is false for exactly one class and it is the class the
question was about — Spec B §7.2 sets `ct_head = NULL` for `EPH(1..5)` at `prune_after`, so an `EPH`
head is not always retained. And it was ruled on item 128's own narrower terms, a two-ratchet
bookkeeping contradiction, **without ledger item 152 beside it although 152 had asked in those very
terms that it be** — 152 carried the confidentiality consequence, 128 never named it. **What replaces
it:** `ct_head` takes the record's **own** class key, so head and body take one ladder at one
position; `PERMANENT`, `DURABLE` and `MEDIA` are unchanged in effect, and an `EPH(1..5)` record's
metadata dies with `K_eph` rather than under a key every seedphrase holder holds forever. §8's record
listing and §8.1 carry it; ledger item **128 closes with it** and item **152** closes with it.

**The consequence that is the point of the ruling.** Before it, the only thing stopping an `EPH` head
outliving its timer was **a cooperating server** — Spec B §7.2's sweep, an *operational* erasure,
against the adversary §8.1 names as *"retained server ciphertext"*: a backup, a replica that missed
the sweep, a legal hold, a seized snapshot. **The guarantee is now cryptographic rather than
behavioural**, which is the conversion ruling 3 of 2026-09-13 made for `eph_root[n]` and left the
head out of — **against the three adversaries listed in the second-pass note below, and NOT yet
against a seized member device**, which is ledger open item **186** and is qualified there rather than
claimed here.

**What the reopening costs, stated rather than absorbed.** `K_eph[n][b][t]` had no computable `t` —
m1 open item **M1-27** — so the window is now a **new plaintext `u64` field, `eph_window`**, in
`record_bytes`, authenticated by `write_auth` and carried in both AADs. §14's slice-2 row says §8,
§8.3 and §9.2 *"must be final before this slice starts"*; slice 2 is `connect/message` and it has
shipped. **This is a break of that rule.** What it means concretely: the `record_bytes` layout is
`connect/message`'s and carries a `u8 format_version` as its first octet, which is the hook this
change uses — it becomes **`0x02`**, and a decoder meeting `0x01` refuses rather than mis-parsing.
**Nothing already encoded is migrated, because nothing already encoded is retained**: no client
ships messaging code, no server holds production records, and every m1 wave-1 path stops at a
`*message.Record` in memory. The cost is a recompile, a re-derivation of every record AEAD and MAC
vector, and a second implementation to bring along — not a data migration. **It is not pretended the
field was always there.** Two further additions land with it: §8's bucket table now requires
`EphBucketSeconds` to answer bucket 0 and an off-ladder bucket **differently** (M1-27's second half),
and §9.2's outbox rule now requires a stale-window `EPH` record to be **re-sealed** rather than
re-MAC'd, which is what makes the server's window check satisfiable by a correct client.

**SECOND PASS, SAME DATE — four corrections to the amendment above, and the largest of them narrows
what it claims.** *(1)* **The conversion to cryptographic is real and is narrower than the first pass
wrote it.** It holds against **retained server ciphertext**, a **newly provisioned device** and a
**seedphrase holder** — the three adversaries §8.1 now names. It does **not** yet hold against a
**seized member device**, because `eph_root[n]` is one per-epoch value with `t` as an HKDF `info` term,
so a device holding that epoch's state recomputes every window's key and reads `t` off the record this
ruling put in the clear. No document schedules the destruction of `eph_root[n]` or `K_eph[n][b][t]`,
and §12.4's required UI string promises one. **Ledger open item 186**, filed and not ruled; §8.1 and
§12.4 carry it at the sentences that make the claim. *(2)* **The `eph_root` device wrap is an `EPH(5)`
record and no document says what `eph_window` it carries**, while the server refuses an implausible
one — a builder MUST NOT publish it until that is ruled (**ledger open item 185**, §8.2). *(3)* §8.1's
`ct_head` rule sentence enumerates four class keys and reads as exhaustive; the device wrap takes
none of them, and the carve-out is now named at the rule rather than only at the far end of §8.1. *(4)*
§8's bucket-0 sentinel paragraph reached this document and Spec B §3.1 on the first pass and Spec A
§5.1 not at all, and the two copies that existed did not match each other — the three copies are now
one text (ledger item **141**'s class, caught by reading rather than by any query).

**Amendment to revision 9 — 2026-09-15 — §8's `ct_body` line and `I5` paragraph, and a new §8.4: the
owner's two rulings, taken together because they are one question asked twice.** Not a new revision,
and **this is the first amendment whose larger half REMOVES A DIVERGENCE rather than changing a rule**.
*(1)* **`ct_body` becomes what this document has said it is since revision 4.** The block has read
*"the MLS PrivateMessage payload"* throughout, and the `I5` paragraph has read *"Sender authentication
is MLS's, inside the ciphertext"* throughout; the shipped build did neither. It padded the application
plaintext and sealed it under a record key, using MLS as a key schedule and skipping the part of MLS
that authenticates senders. **Not one line of this document had to change for that to be wrong**, which
is why no review round and no grep over this corpus found it: the documents were right and the code was
not, and the divergence was declared in no erratum, no open item and no `NotBuilt` entry. The measured
consequence, which is what forced the expensive option: `record_key[0]` derives from the **class key
every member holds** plus a **leaf number**, `sender_handle` is the same shape, `write_auth` is a MAC
under a group-wide key, and `messagegroup/seal.go` contains no signature at all — so **any member can
seal a record attributed to any other member and every member opens it**, which `connect`'s own
`TestAnyMemberCanWriteARecordAttributedToAnotherLeaf` asserts as a standing property of the shipped
tree. §8.4.1 states the scope, which is the **body only**, and §8.4.4 measures the bill, which lands
almost entirely on the 256-octet rung: **252 usable octets become 59**. *(2)* **§8.4.2 writes the rule
where the document was silent**: the inner frame's AAD is `H("URmessage/v1/aad/mls" ‖ AAD_body)`, a
digest rather than the preimage because the preimage's 104 octets would leave the 256-octet rung
carrying **nothing at all**. *(3)* **§8.4.3 states two refusals an opener owes**, and neither implies
the other — the sender binding is what turns *"someone in this group"* into *"Alice"*, and the position
binding is what stops a signed frame being re-enveloped into another stream position or another
retention class. *(4)* **§8.4.5 defines `message_id`**, which this corpus has referenced as the referent
of a reaction, a reply, a tombstone, a read cursor, a local-store row key and a pagination cursor since
revision 9 while **defining it nowhere**. It derives from `(group_id, sender_handle, stream_index)` —
the triple MLS now signs, by way of the AAD in (2) — keyed under `group_handle_key` so the server
cannot compute it. **No wire field changes, `format_version` stays `0x02`, no preimage in this document
moves an octet, and Spec B is untouched.** The content **KIND** is deliberately NOT ruled here and is
the next ruling; ledger open item **198** carries it, and items **199**–**207** carry the rest of what
this leaves open.

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
prk             = HKDF-Extract(salt = "URmessage/v1/wrap-salt", ikm = ss)
wrap_key ‖ wrap_nonce
                = HKDF-Expand(prk, info, 56)          // 32 B key ‖ 24 B nonce
info            = "URmessage/v1/wrap" ‖ LP(group_id) ‖ u64(epoch)
                  ‖ u8(target_type) ‖ LP(target_id) ‖ u8(payload_type)
                  ‖ u16(alg_id) ‖ LP(target_xwing_pub) ‖ LP(ct_xwing)
hybrid_ct       = u16(alg_id) ‖ LP(ct_xwing) ‖ LP(aead_ct)
```

`urmessage_leaf_keys` therefore publishes a single X-Wing public key rather than separate X25519 and
ML-KEM halves; §5.2 and §5.3 read accordingly.

**The wrap body: what is around `hybrid_ct`, what is inside `aead_ct`, and what the signature covers.
RULED 2026-09-09, as composite `C3`.** `hybrid_ct` is the middle of a wrap body and not the whole of
it. **All three wrap bodies take one grammar** — the `pq_secret` device wrap, the `eph_root` device
wrap and the recovery wrap, with no exception for any of them:

```
wrap_envelope = u8(wrap_format_version = 0x01) ‖ u8(target_type) ‖ u8(payload_type)
                ‖ u64(content_epoch)                                        // 11 octets
wrap_body     = wrap_envelope ‖ hybrid_ct
ct_body_plain = LP32(len(wrap_body)) ‖ wrap_body ‖ 0x00 × (rung − 4 − len(wrap_body))

aead_ct       = AEAD(wrap_key, wrap_nonce, secret ‖ LP(identity_pub) ‖ sig)
sig           = Sign(identity_priv, wrapsig_preimage)          // under the publisher's identity key
wrapsig_preimage
              = "URmessage/v1/wrapsig" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
                ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit) ‖ u8(retention_class_wire)
                ‖ u8(size_bucket) ‖ u64(expire_at) ‖ LP(blob_id) ‖ LP(H(server_attachment))
                ‖ LP(wrap_envelope) ‖ LP(ct_xwing) ‖ LP(payload)
```

**Every step of the walk is a fixed width or a length prefix, and no step needs a key, a payload type
or the record's class.** Four octets of `LP32` give the body's exact extent; eleven fixed octets give
the version, the two type bytes and the content epoch; `hybrid_ct` is self-delimiting by the line
above it; the remainder to the rung is a tail that MUST be all zero and whose refusal is stated in
§8.2. **`u16(alg_id)` in the preimage is `hybrid_ct`'s own KEM identifier as written above; whether
§7.1's *"every signature carries `alg_id` inside the signed bytes"* is thereby satisfied for the
SIGNATURE's suite, or whether a second identifier is owed, is not ruled — Spec A §5.11 files it.**

**Which rung, and it differs by wrap kind for a reason that is not this ruling's.** The two
device-wrap bodies are AEAD plaintexts, so they pad to `SizeBucketBytes(b)` — **4,096** at bucket 2 —
and the record AEAD's 16-octet tag makes `ct_body` 4,112. The recovery wrap's `ct_body` is under **no**
record AEAD, so the padded body **is** `ct_body` and its rung is **4,112**. One grammar, two
denominators, and the difference is the outer seal rather than the body.

**What each part is there for, and the two terms that are repairs rather than adoptions.**

- **The version octet is first**, for the reason every offset below it is meaningful only under that
  version. It is what makes a second body field later a negotiation rather than a flag day.
- **`u8(target_type)` and `u8(payload_type)` travel in the body as well as inside `info`.** They are
  bound into `wrap_key` above, so a receiver that derives the key **from the envelope's own values**
  and finds `aead_ct` does not open has detected the disagreement fail-closed. Their **encoding** is
  still undefined — see the gap list below, which this ruling does not fill.
- **`u32(publisher_leaf_index)` is deliberately NOT carried.** `sender_handle` is already in
  `record_bytes` in the clear, so a member can resolve the publisher without it; a seed-only restorer
  cannot resolve a bare leaf index at all, holding no ratchet tree; and on the recovery wrap, whose
  body is under no record AEAD, four cleartext octets would convert a per-leaf pseudonym the server
  already sees into a **tree position**.
- **`LP(identity_pub)` is inside `aead_ct` and not in the cleartext body**, because the party that
  needs it is the one that opens `aead_ct`: a seed-only restorer holds no MLS state and no
  `group_handle_key`, so without a carried key a recovery wrap's signature is unverifiable by the only
  reader it exists for. **What this ruling does not state is that the carried key must be anchored in
  the KT log (§10.1)**, and a carried key is one the wrap's own sealer chose.
- **`LP(wrap_envelope)` in the preimage is the first repair, and it is the term that makes the rest of
  the ruling worth anything.** Without it the signature reaches the record header, the KEM transcript
  and the secret, and reaches **not one octet of the envelope** — because the envelope is outside
  `hybrid_ct`, the signature is inside `aead_ct`, and `LP(ct_xwing)` lies between them. It costs
  **zero body octets and zero wire octets**, and it is acyclic: the envelope is plaintext the sealer
  fixes before it encapsulates.
- **The `LP32` prefix over all three bodies is the second repair.** Without it on the recovery wrap a
  parser cannot decide whether the body's first four octets are a length or
  `version ‖ target_type ‖ payload_type` until it has read the server attachment's kind — a
  target-type-dependent body encoding, which is the defect class the kind-`0x0000` ruling was written
  against.

**What this ruling deliberately did NOT take, recorded because it is a trade and not an oversight.**
The alternative shape put `LP(sig) ‖ LP(identity_pub)` into the **server attachment**, where any
party — the message server included — could refuse an unsigned or wrongly-signed wrap from the wire
bytes alone. Its price was **+68 / +104 octets per record**, about **+170 KB per epoch fan-out**, a
Spec B §5.1 check-3 change, and a **publicly verifiable signature under a key §5.2 publishes in the KT
log on all 2,501 wrap records of every epoch** — per-epoch attribution of the committer, to the
operator, which cuts against §4.2. **The two properties cannot both be had.** The privacy was taken,
and the cost is that *"a client MUST NOT honour an unverified wrap"* is enforceable by the
decapsulating target and by nobody else.

**One term of the preimage is under-determined and a builder must have it ruled before it signs.**
`LP(payload)` was measured over a 32-octet secret. Whether `payload` now means the secret alone or
`secret ‖ LP(identity_pub)` is stated by no document; the preimage is 1,320 octets under the first
reading and 1,356 under the second. Spec A §5.11 carries the measurement and files the residual.

**The wrap KDF derives its own AEAD nonce and binds `alg_id`. ADOPTED 2026-09-18 from red-team finding
M-15.** Until this amendment `wrap_key` was a bare `HKDF-Expand(ss, …, 32)` over a four-element
`info`, and that had two defects which the review of 2026-08-12 found in one line
(`docs/reviews/2026-08-12-r3-spec-review.md`, **M-15**): **it expanded thirty-two octets, a key and no
nonce**, so no document in this corpus said what nonce `aead_ct` was sealed under; and **`alg_id` was
absent from `info`**, so the identifier travelled on the wire inside `hybrid_ct` while being bound into
no key at all — which is exactly the downgrade §7.1's own rule exists to prevent. The finding carried
**no disposition of any kind for four weeks** — no ledger item, no owner decision, no spec revision —
and its first half was then rediscovered independently, by a different chain of reasoning, as ledger
item **144**. Both halves close here.

`aead_ct` is sealed under `(wrap_key, wrap_nonce)`. Twenty-four octets is XChaCha20-Poly1305's nonce
and no other v1 suite's, which is the same argument §8 uses to settle its own record AADs, and
56 = 32 ‖ 24 is the split `key_head ‖ nonce_head` already uses in §8. **Nothing new goes on the wire:**
`wrap_nonce` is derived independently by both sides and `hybrid_ct` is unchanged, so this costs zero
wire bytes. It also migrates no code — measured 2026-09-18, a grep for `wrap_key`, `WrapKey` and
`wraphead` across every `*.go` file in `msgrepo` and in `connect` returns three hits and all three are
in `connect/mls/leaf_keys_test.go`, referring to the leaf's wrap KEM **public key** in the
`urmessage_leaf_keys` extension, which is a different thing.

**What each element of `info` is there for**, so that a reader can see the list was adopted
deliberately rather than pasted:

| Element | | What it buys |
|---|---|---|
| `"URmessage/v1/wrap"` | kept | domain separation from every other HKDF label in this document |
| `LP(group_id)` | kept | a wrap of one group never opens under another group's key |
| `u64(epoch)` | kept | the epoch whose secrets the wrap carries — Spec A §5.11 calls it the **content** epoch, and it is deliberately not the record's own `epoch` field |
| `u8(target_type)` | **new** | separates target *classes* under one key schedule. This design has exactly two — an active device leaf, and a member's `RECOVERY_PUB` — and naming them is **not** assigning them octets; which byte each takes is one of the three gaps below |
| `LP(target_id)` | kept | the recipient; one member's wrap never opens under another's key |
| `u8(payload_type)` | **new** | separates payload *kinds* sent to one target at one epoch — which ruling 3 of 2026-09-13 turns into a live case rather than a hypothetical, because a device leaf now receives **two** wrap records at one epoch |
| `u16(alg_id)` | **new** | M-15's anti-downgrade half. The same two octets `hybrid_ct` carries are now inside the key, so flipping them on the wire yields a different `wrap_key` and the AEAD fails, instead of the field being one that nothing checks |
| `LP(target_xwing_pub)` | **new** | binds the encapsulation to the public key it was made to |
| `LP(ct_xwing)` | **new** | binds the transcript: the key depends on the ciphertext that carried it. This is the split-key-PRF shape M-15 cited, and the pattern of draft-ounsworth-cfrg-kem-combiners |
| `HKDF-Extract` under a named salt | **new** | Extract-then-Expand in place of a bare Expand off a raw shared secret, under a salt no other construction here uses. X-Wing's `ss` is already a uniform 32-octet KDF output, so this buys **domain separation and not entropy extraction**, and it is written that way rather than claimed as more |

**One substitution was necessary, and it is stated rather than made quietly. M-15's block cannot be
adopted verbatim, because it was written against a construction revision 5 deleted.** The r3 review
read a pre-X-Wing revision — its keystone finding B-1 still names `device_x25519_pub` and
`device_mlkem_pub` as two separate leaf values — so its block takes `ikm = ss_x25519 ‖ ss_mlkem` and
binds `LP(pk_x25519) ‖ LP(ek_mlkem) ‖ LP(ct_x25519) ‖ LP(ct_mlkem)`. **Those six identifiers exist
nowhere in this design.** Measured 2026-09-18: across every document in this repository they occur
**only** inside r3's own review file, and in this section's own sentence recording their deletion —
*"It replaces the hand-rolled `ss_x25519 ‖ ss_mlkem` combiner of earlier revisions, which was the
most dangerous composition in this document"*, which is the citation because the line number is
advisory. Pasting M-15's IKM literally would reinstate exactly that combiner: a revert of revision
5, not an adoption of M-15.
So two X-Wing values stand in for the four: `LP(target_xwing_pub) ‖ LP(ct_xwing)` covers the same
material in X-Wing's own ordering — an X-Wing public key is the ML-KEM encapsulation key followed by
the X25519 public key, and an X-Wing ciphertext is the ML-KEM ciphertext followed by the X25519 one —
under two length prefixes rather than four. Every substantive claim of M-15 survives the substitution;
only the names change, and this paragraph is the record that they did.

**Three inputs this block names and this document does not define. They are INHERITED rather than
introduced, and they are named here rather than filled, because filling any one of them is a wire
ruling and this amendment makes none.**

- **`target_id`.** Already the fourth input to the pre-amendment `wrap_key`, and defined nowhere in the
  corpus. Spec A §5.11 (5) lists it as unstated and gives four candidates that are four different byte
  strings — `recovery_handle`, the epoch-scoped `wrap_target_handle`, a leaf index, a member id. A
  publisher and a restorer that choose differently produce a wrap nobody can open, with no error
  anywhere.
- **`target_type` and `payload_type`.** Both arrive with M-15, and neither has a **code point**
  anywhere: no document maps a target class or a payload kind to an octet, and nothing stops two
  implementations choosing opposite assignments. Measured 2026-09-18: both identifiers occur only
  inside r3's review file and in the 2026-09-12 red team's reference back to it.
  *(**Clarified 2026-09-19, and the gap is NOT closed by the clarification.** This bullet read
  — *"neither has a code point, a value table or a definition anywhere"* — while the `info` table
  three paragraphs above enumerates `target_type`'s two classes in the same block, so the two read
  against each other and a reader could take either for the mistake. Neither is. What the table gives
  is the **domain**, which this document does fix, because §8.2's payload table fixes it. What no
  document gives is the **encoding** — which octet each class takes — and the encoding is what a
  publisher and a restorer must agree on, which is what makes this a gap rather than a note. **The
  domain is not the encoding.** Unruled before this sentence and unruled after it; only the wording
  changed.)*
- **Which `alg_id`.** §7.1 lists `0x0014` as *"the v1 wrap KEM"* and requires every *"hybrid
  ciphertext"* to carry an identifier, so `hybrid_ct`'s is not seriously in doubt — but no line says so
  in as many words, and the record AADs needed an amendment on 2026-08-25 to settle exactly this
  question for themselves. It does **not** block M-15: what makes the binding anti-downgrade is that
  `info` carries **the same two octets `hybrid_ct` carries**, whichever they turn out to be, and the
  block above says that rather than picking a number.

**So the block is normative modulo those three**, and a second implementation cannot build a wrap from
it alone. What it does settle is the shape — Extract-then-Expand, 56 octets, **nine** elements — so
that when the three are ruled the derivation does not move underneath them.

**Nine and not eleven, and the arithmetic is the substitution above.** M-15's `info` lists eleven
elements; four of them are the separate X25519 and ML-KEM public keys and ciphertexts, and two
X-Wing values carry the same material, so the adopted list is nine. MASTER's pre-amendment `info`
had four. The five that are new are the ones the table marks so.

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
                          pagination and hole detection only; NEVER authenticated.
                          NOT inside record_bytes — it travels beside it. See below.
  group_id           32B
  sender_handle      16B  = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)
                          stable per group; every member computes it; the server cannot invert it
  epoch              u64
  stream_index       u64  monotonic per (group_id, sender_handle); write-once
  is_commit          u8   1 on an MLS Commit record — the server acts on this, so it is authenticated
  retention_class    u8   see the encoding table below
  eph_window         u64  PLAINTEXT. The time-slice t of the record's own K_eph[n][b][t]
                          (§8.1). Always present; 0 on PERMANENT, DURABLE, MEDIA and
                          EPH(0). Sender-computed from its own sent_at; the opener uses
                          the wire value and never recomputes it. RULED 2026-09-13; see
                          §8.1 and ledger item 152 / m1 open item M1-27. This field is
                          an ADDITION to a section §14 froze, and §0 carries what that cost.
  size_bucket        u8   256B / 1K / 4K / 16K / 64K / blob-ref
  expire_at          u64  unix MILLISECONDS, big-endian, 0 = unset; advisory upper bound only —
                          it may SHORTEN retention, never extend it
  body_hash          32B  H(ct_body); RETAINED when ct_body is erased for PERMANENT,
                          DURABLE and MEDIA. NOT retained for EPH(1..5) — Spec B §7.2
                          ZEROES it at prune_after, in the one statement that also sets
                          ct_head = NULL. (Amended 2026-09-11, second pass of that date;
                          this line read "RETAINED when ct_body is erased" with no
                          exception in it, six lines above the ct_head line the first
                          pass corrected and inside the same fence.)
  blob_id            32B  present iff size_bucket == 5, absent otherwise; the object the body
                          lives in when the body is not inline. Derived from the record's key
                          material, never from content — see Spec A §5.13
  server_attachment  opaque, typed, extensible; ZERO-LENGTH for ordinary records. The only
                          server-visible structured field. See §8.3.
  ct_head            AEAD; MLS PrivateMessage header, type, sent_at. RETAINED for
                          PERMANENT, DURABLE and MEDIA. NOT retained for EPH(1..5) — Spec B
                          §7.2 sets ct_head = NULL at prune_after. KEYED UNDER THE RECORD'S
                          OWN CLASS KEY, whatever that class is — RULED 2026-09-13, which
                          REVERSES the 2026-09-07 durable-head rule. See §8.1 and ledger
                          item 152, which this closes. (Amended 2026-09-11; this line read
                          "AEAD, always retained" with no exception in it. Amended again
                          2026-09-13; it then read "so §8.1's durable-class rule excludes
                          EPH, and the class an EPH head is keyed under is unruled".)
  ct_body            AEAD, erasable; the MLS PrivateMessage payload. THE SHIPPED BUILD DID
                     NOT DO THIS AND THE DIVERGENCE WAS DECLARED NOWHERE; see §8.4, RULED
                     2026-09-15, which states WHICH records carry an MLS frame, what its
                     AAD is, the two refusals an opener owes, and what the rung costs.
                     This line is UNCHANGED in meaning and always was the rule.
  write_auth         MAC, computed last; see §9.2
```

**`record_id` is a field of the record and not a field of `record_bytes`** (amended 2026-08-25,
found by implementing the codec). The fifteen fields below it — **every line of the `RECORD` block
except `record_id` itself**, which is the rule rather than the number, so the next field added to that
block moves the count and a reader who counts the block is the check — are the ones `connect/message`
serialises; `record_id` is not one of them and never can be. *(**Amended 2026-09-13, second pass of
that date.** This read *"The fourteen fields below it"* and was exactly right until that same date's
first pass inserted `eph_window` into the block 35 lines above and did not touch the word. No regex
over `ct_head`, `durable` or `eph_window` reaches the word "fourteen": it is reachable only by reading
the paragraph under the block you have just edited, which is what this document's own `body_hash` note
and ledger item **141** each already record against it.)* It is assigned by the server *after*
acceptance, which is after `write_auth` has been computed and verified, so a `record_id` inside those
bytes would be a value the MAC covers — which is exactly what the line above says it is not, and
would make the id unassignable without invalidating the record. It appears in neither AAD and in
neither preimage for the same reason. Spec B §4.3.3 carries it as **field 13 of the enclosing
protobuf, a sibling of `record_bytes`** — ignored on submit, populated on read — and Spec A §2.4 has
the server call `EncodeRecord` and then set the id separately. `EncodeRecord` ignores `Record.RecordId`
and `ParseRecord` always answers zero for it, so encoding a record, assigning it an id, and encoding it
again produces identical bytes. A reader who took this block as the layout of `record_bytes` would build
a codec that disagrees with the shipped one on every record; the block is a field listing, and the wire
layout is `connect/message`'s, stated in `codec.go`. **The block's ORDER is nevertheless normative and
the layout follows it** — the codec's field order *is* this listing's, which is what fixes the wire
position of any field added to the block, `eph_window` included (stated here 2026-09-13, second pass of
that date: until then the only sentence saying so sat far below this one, under the AADs, while this
one reads as an instruction to ignore the block — the distance is not restated as a line count,
because a line count is the thing this corpus has had go stale most often). What the block does **not** give is
each field's *encoding*. That rule — **fixed-width Go fields encode raw at their natural width,
variable-length fields as `LP(x)`** — and the resulting octet list are **owner decision 60**
(`docs/reviews/2026-08-25-owner-decisions-59-63.md`), which is the only normative statement of the
`record_bytes` octet layout in this repository and which the 2026-09-13 ruling amends in two places:
`u64 eph_window` immediately after `u8 retention_class_wire`, and `format_version` to `0x02`.

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

  The bucket-0 answer and the off-ladder answer MUST DIFFER. RULED 2026-09-13, M1-27.
  EphBucketSeconds MUST answer 0 for bucket 0 — the true retention window of a rung that
  is never stored — and a NEGATIVE for 6..255, which is not a bucket at all. It answers
  -1 for both today, so a caller cannot ask it which of the two it met. The code change
  is connect's.

size_bucket:  0 = 256 B, 1 = 1024 B, 2 = 4096 B, 3 = 16384 B, 4 = 65536 B, 5 = blob-ref
              octet_length(ct_body) MUST equal size_bucket_bytes[b] + 16 exactly (the AEAD tag),
              for b in 0..4. For b = 5, ct_body is absent and blob_id is present.
```

**The bucket-0 sentinel paragraph inside the block above is restated character-for-character in Spec A
§5.1 and Spec B §3.1, and this document's commentary on it is kept OUT of the block for exactly that
reason.** *(Amended 2026-09-13, second pass of that date. On the first pass the paragraph was written
into this document and into Spec B §3.1, into Spec A §5.1 **not at all**, and the two copies that did
exist did not match each other — three fences, three texts, in the one block whose whole contract is
that all three are identical. That is ledger item **141**'s class, which Spec A §5.11 calls the worst
kind because a wire-block annotation is the form a second implementation transcribes rather than
reads.)* The negative for `6..255` is **unreachable through a parsed record** — `RetentionClassOf`
refuses every wire byte outside `0x10..0x15` — so it is a programmer-error sentinel rather than a
value a record can carry, while `0` for bucket 0 is a real retention window a caller may act on. That
asymmetry is the whole of why the two must not share one answer.

Per **I7**, the two ciphertexts use **distinct keys and distinct AADs**, and `body_hash` appears only
in the head's AAD — never in the body's, which would be circular:

```
AAD_body = "URmessage/v1/aad/body" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
         ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(retention_class) ‖ u64(eph_window)

AAD_head = "URmessage/v1/aad/head" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle)
         ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit) ‖ u8(retention_class)
         ‖ u64(eph_window) ‖ u8(size_bucket) ‖ u64(expire_at) ‖ LP(body_hash)
         ‖ LP(blob_id) ‖ LP(H(server_attachment))

key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)
key_body ‖ nonce_body = HKDF-Expand(record_key[i], "rec/v1/body", 56)
```

**`alg_id` in both record AADs is `0x0021`, XChaCha20-Poly1305** (amended 2026-08-25, found by
building the preimages). §7.1 puts the identifier inside the authenticated bytes so it cannot be
stripped or downgraded, and both blocks above write `u16(alg_id)` — but no line said *which*
identifier a record's AADs carry, and a builder that takes it as a parameter cannot infer one. It is
the record AEAD's own identifier and never the KDF's. The derivation above settles which: it hands out
`key_head ‖ nonce_head` as 56 octets, a 32-octet key and a **24-octet nonce**, and a 24-octet nonce is
XChaCha20-Poly1305's and no other v1 suite's. `0x0031` (HKDF-SHA-256) names the function that produced
that key, not the one that consumes it, and a client that wrote it here would build a preimage that
round-trips against itself and fails the AEAD against every other implementation, on every record it
sends. Where a later ciphersuite changes the record AEAD this field carries that suite's AEAD
identifier from §7.1's table, which is the agility the field is in the preimage for.

`LP(blob_id)` is a **zero-length** prefix on every record whose `size_bucket` is not 5, so the
preimage is defined for ordinary records without a special case. `blob_id` is absent from `AAD_body`,
because the body it names is the thing being encrypted.

**`u64(eph_window)` sits immediately after `u8(retention_class)` in both AADs and in §9.2's
`write_auth` preimage, and it is ALWAYS present — zero on every class but `EPH(1..5)`. RULED
2026-09-13.** Immediately after `retention_class` because it is the field that qualifies it and
because the codec's field order is this listing's. Always present rather than *present iff the class
is `EPH`* because that is what `LP(blob_id)` actually does: `blob_id` is absent from the **record**
and present as a **zero-length term** in the preimage, so *"the preimage is defined for ordinary
records without a special case"* — the sentence directly above. The fixed-width analogue of a
zero-length term is a zero-valued one, and taking the surface reading of the `blob_id` precedent
instead would put a conditional in the one preimage builder this design has kept free of them. It
leaks nothing either way: `retention_class` is plaintext, so a server that can read the class can
already compute the bucket, and it already stamps arrival time — §7.1's `prune_after` arithmetic is
that computation. **What each of the three placements buys, because they are not the same thing.**
The **key derivation** is what stops a bucket or window downgrade: `K_eph[n][b][t]` takes both `b`
and `t`, so an altered window yields a key nobody holds and the record does not open — the AAD is
not what does that work and no reader should conclude it is. The **`write_auth`** term is the
load-bearing one: it is what makes §9's server-side window check a check on a value the MAC covers
rather than on a field anyone in the path may rewrite. The **AAD** terms cost zero wire octets and
are defence in depth of exactly the kind §8.2's `AAD_snap` paragraph argues for, and they are what
binds the zero on a non-`EPH` record, so a header cannot be spliced across classes.

Construction order: build `server_attachment` → encrypt `ct_body` → compute `body_hash` → encrypt
`ct_head` → compute `write_auth`. Every dependency is acyclic.

Per **I5**, this layer adds no signature **over content**. Sender authentication is MLS's, inside the
ciphertext.

**AND THAT SENTENCE WAS ASPIRATIONAL UNTIL 2026-09-15, WHICH IS THE SECOND THING THIS PARAGRAPH GOT
WRONG AND THE LARGER ONE.** *"Sender authentication is MLS's, inside the ciphertext"* was true of this
document and false of the shipped build, which put no MLS frame inside `ct_body` for an application
record at all — so there was no inner signature for I5 to defer to, and what the layer actually
offered was a group-wide AEAD proving *"someone in this group wrote this"* and nothing more. §8.4 is
the ruling that makes the sentence TRUE rather than a change to it. **I5 itself is untouched and needs
no amendment**, for the same reason its wrap exception needed none: its wording is *"no second
signature over content"*, and a layer that had no FIRST one was not violating it — it was failing to
earn the deference the sentence above extends to MLS.

**The wrap is the exception, and this sentence used to omit it. Corrected 2026-09-19.** It read *"this
layer adds no signature"* flat, which §8.2's *"Every wrap body is signed under the publisher's
`identity` key, and a client MUST NOT honour an unverified one"* — **RULED 2026-09-13**, transcribed
into this document on 2026-09-18 — makes false for all three wrap record kinds. It is the **seventh**
location here that the three rulings of 2026-09-13 invalidate, after the six ledger item **141** closed
on, and the only one that pass left standing; the query that finds all seven is published with item
141. **I5 itself is untouched and needs no amendment**: its own wording is *"no second signature over
content"*, and a wrap body is not content — a wrap carries **no MLS frame at all**, so there is no
inner signature for I5 to defer to, and §8.2's is the first and only signature over that record class
rather than a second one over anything. The epoch snapshot is not among the three: it is a blob-ref
record with **no `ct_body`**, so it has no wrap body to sign.

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

           t = eph_window, the record's own plaintext field (§8). RULED 2026-09-13.
               t = floor(sent_at_ms / (eph_bucket_seconds[b] × 1000)) for b in 1..5,
               computed by the SENDER from the same wall-clock reading it puts in
               sent_at; origin is the Unix epoch, 1970-01-01T00:00:00Z; unit is a
               count of whole buckets since that origin. For b = 0, t = 0 BY
               DEFINITION and is never computed — bucket 0 is never persisted, so it
               has one window for the life of eph_root[n] and there is no division.

record_key[0]   = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)
record_key[i+1] = HKDF-Expand(record_key[i], "ratchet/v1", 32)
```

A real forward ratchet: the sender overwrites `record_key[i]` after use, keeping a bounded skipped-key
window for out-of-order receipt. **`ct_head` is keyed under the record's OWN class key — `K_perm`,
`K_durable`, `K_media` or `K_eph[n][b][t]` — exactly as `ct_body` is. RULED 2026-09-13, and it
REVERSES the ruling of 2026-09-07.** **THAT ENUMERATION IS NOT EXHAUSTIVE, and this clause is here so
that nobody reads it as though it were** (added 2026-09-13, second pass of that date): **the device
wrap takes no class key at all** — its ladder is rooted at `env_key[k]`, stated in full at the end of
this section and in §8.2. It is named *here*, at the rule, because the rule is the sentence an
implementer transcribes and the carve-out is at the far end of this section, and because the
`eph_root` device
wrap is an **`EPH(5)`** record: a builder applying the rule literally would key the record that
*delivers* `eph_root[k]` under a key derived *from* `eph_root[k]`, which is the same circularity that
disqualified `sent_at` as the carrier of `t`, one level in.

**Head and body therefore take ONE ladder, at one position.** `key_head` and `key_body` are separated
by their HKDF labels — `"rec/v1/head"` and `"rec/v1/body"` off the same `record_key[i]` — which is
what **I7**'s *"distinct keys and distinct AADs"* has always meant and is why one position is safe.
The two-ratchet reading the replaced rule created, in which one record's single `stream_index` covered
two ladder positions, is gone with it; the class-blind counter ruled 2026-09-07 as shape **A1**
(ledger **143** and **169**) is untouched and still says `i = stream_index` in every ladder, and the
device wrap's own two-records-on-one-root instance is a different instance and is unaffected.

**What was ruled on 2026-09-07, why it was wrong, and what replaces it.** The 2026-09-07 ruling was
*"`ct_head` is always sealed under the DURABLE class ratchet, whatever the record's own retention
class"*, on the reason *"the head is always retained, so it is keyed by the class that is always
retained."* **The premise is false for exactly one class, and it is the class the whole question was
about:** Spec B §7.2 sets `ct_head = NULL` for `EPH(1..5)` at `prune_after`, so an `EPH` head is not
always retained, and the failure the rule existed to prevent — a retained header going unopenable at
the moment its body vanishes — is a failure only where the head outlives the body, which for
`EPH(1..5)` it does not. It was ruled on ledger item **128**'s narrower terms, a bookkeeping
contradiction, **without ledger item 152 beside it although 152 had asked in those very terms that it
be**; 152 carried the confidentiality consequence and 128 did not name it. It is replaced by the rule
in the first paragraph above. Item **128** closes with this ruling and its text is kept whole in the
ledger with the reversal annotated at the sentence a reader lands on.

**PERMANENT, DURABLE and MEDIA are unchanged in effect.** `K_perm[n]`, `K_durable[n]` and `K_media[n]`
all descend from `storage_root[n]` and none is ever destroyed, so for those three the repair costs
nothing and changes no guarantee. **The whole of what moves is `EPH`.** An `EPH(1..5)` record's
metadata — the MLS `PrivateMessage` header, `type` and `sent_at` — now dies with `K_eph[n][b][t]`
instead of living under a key every member, every future device and every seedphrase holder holds
forever. `K_durable[n]` descends from `storage_root[n]`, is destroyed nowhere, and rides every
member's recovery wrap for the life of the group; an `EPH` head sealed under it would have survived
the timer, a seized device, a device provisioned tomorrow and a seedphrase holder, falsifying the next
paragraph's own sentence, §12.4's required UI string and §13.

**AND THIS IS THE PRIZE, STATED HERE BECAUSE IT IS WHAT THE RULING BOUGHT.** Before today the only
thing stopping an `EPH` head outliving its timer was **a cooperating server**: Spec B §7.2's
`ct_head = NULL` sweep. That is an **operational** erasure, and the adversary the next paragraph names
is *"retained server ciphertext"* — a backup, a replica that missed the sweep, a legal hold, a seized
snapshot — which is precisely the case an erasure does not cover. **This ruling converts that
guarantee from behavioural to cryptographic** *(for retained server ciphertext, a newly provisioned
device and a seedphrase holder — and **not** for a seized member device, which is ledger open item
**186** and is stated in full two paragraphs below; qualification added 2026-09-13, second pass of
that date)*, which is the same conversion ruling 3 of 2026-09-13
made for `eph_root[n]` itself. The head was the half that ruling left behind; it is not left behind
now. One consequence worth naming rather than leaving to be found: Spec B §7.2's sweep is no longer
what the guarantee **rests on**, and ledger item **181** is re-examined in that light and answered
there.

**What it costs, and it is not nothing.** `K_eph[n][b][t]` needs a computable `t`, which no document
gave it — ledger open item **M1-27** — so this ruling is made in one sitting with the ruling that
supplies one, `eph_window` in §8 above. That field is an **addition to a frozen wire format**: §14
requires §8, §8.3 and §9.2 to be final before slice 2 starts, and slice 2 is `connect/message`, which
has shipped. §0 carries the revision and what reopening it means.

`eph_root[n]` is independently sampled, never wrapped to a recovery key and never in a provisioning
bundle. **After the timer, retained server ciphertext, a newly provisioned device and a seedphrase
holder all fail to decrypt.** This is the most easily broken property here — deriving `eph_root` from
`storage_root` would compile, pass tests, and silently make every expired message recoverable forever.

*(**Amended 2026-09-13, second pass of that date, and the amendment NARROWS this sentence rather than
extending it.** It read: *"`eph_root[n]` is independently sampled, **time-sliced by window `t`**, never
wrapped to a recovery key, never in a provisioning bundle, **deleted when its window closes**. After
the timer, retained server ciphertext, **a seized device**, a newly provisioned device, and a
seedphrase holder all fail to decrypt."* **Ruling 2 of the same date puts `t` at the DERIVED key and
not at the root**, and the tree at the head of this section is explicit about what that leaves:
`eph_root[n]` is **one** 32-octet CSPRNG value per epoch and `t` is an HKDF `info` term, so anyone
holding `eph_root[n]` recomputes **every** window's key for **every** bucket — and ruling 2 now prints
`t` in the clear on the record, so there is nothing left to search for. Spec A §5.3 states this
directly, as the reason for the opener's ahead-refusal: *"the opener can derive **any** window's key
from `eph_root[n]`."* The root therefore has **no window of its own to close**, and **a seized member
device is not covered by anything this document states**: it holds `eph_root[n]` for as long as it
retains epoch `n`'s state, and the only deletion the corpus names anywhere is epoch-scoped — Spec A
§3.5's `DeleteGroupStateBefore` with `PastEpochWindow = 32`, and epochs advance on commits rather than
on clocks, so in a quiet group that is indefinite. **What is owed is a destruction schedule for
`K_eph[n][b][t]` and for `eph_root[n]`, in the unit ruling 2 has just defined** — §12.4's required UI
string already promises it (*"the key is destroyed on every device"*) and no section of any document
schedules it. **Ledger open item 186**, filed and not ruled. The three adversaries left in the
sentence above ARE established and none of them depends on that schedule: the message server never
holds `eph_root` at all, and **I4** with §5.4 keep it out of every recovery wrap and every provisioning
bundle. §12.1's own statement of this guarantee never claimed the seized device, and is unchanged.)*

**Ruling 3 of 2026-09-13 is what makes the paragraph above cryptographic rather than behavioural.**
`eph_root[n]` now travels in its own `EPH(5)` device-wrap record, on the four-week rung the server
actually prunes, instead of sharing a `PERMANENT` record with `pq_secret[n]` — a record prunable
**never**, encapsulated to a device key that never rotates, and therefore one whose single compromise
opened every `K_eph` that ever existed. §8.2 carries the split and its three accepted costs.

**One record class does not take a `class_key` at that root, and it is the device wrap. RULED
2026-09-13** (§8.2): a device-wrap record's ladder head is
`record_key[0] = HKDF-Expand(env_key[k], "sender/v1" ‖ LP(leaf_index), 32)`, where `env_key[k]` is
the MLS-exporter envelope §8.2 defines. **No new ladder is introduced and no label below the root
changes.** `env_key[k]` has **no retention class in it**, and ruling 3 then puts two records of two
different classes on that one root; the concrete way an implementer reaches a repeated
`(key, nonce)` from that is ledger item **143**. **RULED 2026-09-07** with ledger item **169** as shape
**A1**: `i = stream_index` in every ladder, over a `stream_index` counter that is **class-blind** — one
per `(group_id, sender_handle)`, which is the counter §9's `message_sender` and the message server
already keep. So the two device-wrap records for one leaf are two allocations out of one counter, take
two different positions on this shared root, and separate both AEADs. **No rule in this document
changes for it**; the position rule is Spec A §5.3's and §5.6's, and Spec A §5.11 carries the
instantiation.

### 8.2 Archive and recovery wraps

| Target | Record | Class | Receives |
|---|---|---|---|
| Active device leaves | the `pq_secret` device wrap | `PERMANENT` | `pq_secret[n]`, 32 octets |
| Active device leaves | the `eph_root` device wrap | `EPH(5)`, the four-week rung | `eph_root[n]`, 32 octets |
| Member `RECOVERY_PUB` | the recovery wrap | `PERMANENT` | **`storage_root[n]`** **and** `archive_secret[n]` |

**The device wrap is TWO records. RULED 2026-09-13** — it was one record carrying both secrets until
then, and this table's first row read *"`pq_secret[n]` **and** `eph_root[n]`"*. Both records carry a
`WrapTag`, both are sealed as *The outer seal* below says, both are signed, and both are indexed by
the **same** `wrap_target_handle`, because that derivation (§8.3) is unchanged and no ruling of
2026-09-13 changes a derivation. **Two records at one handle is therefore the normal case**: a
`WrapFetch` by target returns both, and a client separates them by the retention class the record
header already carries. The reason for the split is §8.1's disappearing-message promise, and Spec A
§5.11 carries the three accepted costs — the doubled device-wrap count, the interaction with the
wrap-index uniqueness repair ledger open item **132** reaches for, and the `EPH` wrap's expiry being
measured from its publication rather than from its epoch's end.

**WHAT `eph_window` THE `eph_root` DEVICE WRAP CARRIES IS NOT RULED, AND A BUILDER MUST NOT PUBLISH
THAT RECORD UNTIL IT IS. FILED 2026-09-13, second pass of that date — ledger open item 185.** The
record is `EPH(5)`, so its retention-class wire byte is `0x15`, §8's presence rule makes `eph_window`
**non-zero** on it, and §9.2's server check together with Spec A requirement **S19** refuses any
`EPH(1..5)` record whose window is more than one from its arrival window — **none of the three carries
a carve-out for a wrap**. But the field's own formula is `floor(sent_at_ms / …)`, and Spec A §5.11 (5)
states in terms that **what a wrap head's plaintext holds is not stated**, because a wrap is the one
record class carrying no MLS frame and therefore no `sent_at`. A builder that reasons *"this record's
key does not come from `K_eph`, so it has no window"* writes `0` and is refused by the server, which
stops the epoch fan-out and leaves no device able to obtain `eph_root[k]`; a builder that computes a
window from its own clock at publication is equally conforming on the text as it stands. **Two
implementers, two answers, one of them fatal, and no document between them** — so the refusal stands
until the owner rules which, and whether S19 applies to a record whose `eph_window` selects no key.
It does **not** touch the `pq_secret` device wrap, which is `PERMANENT` and whose `eph_window` is `0`
by §8's presence rule.

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
~150 MB. It is instead **one `PERMANENT`-class record per epoch**, encrypted under `K_snapshot[n]` —
which the restorer can open precisely because `storage_root[n]` is in its wrap.

**The snapshot's AEAD derives its own nonce and binds `alg_id`. AMENDED 2026-09-19, and it is M-15's
class rather than a new shape.** Until this amendment the line above read `K_snapshot[n] =
HKDF-Expand(storage_root[n], "snap/v1", 32)` — **thirty-two octets, a key and no nonce**, with no
`alg_id` bound and no AAD stated anywhere in the corpus. That is defect for defect what r3's **M-15**
raised against §7's `wrap_key` and what §7 adopted on 2026-09-18, one section away and in this same
document. Measured 2026-09-19 at `be7154d`, the commit before this amendment: `snap/v1` occurred
**five** times across this repository and a snapshot nonce occurred **zero** times.

```
K_snapshot[n] ‖ nonce_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 56)  // 32 B key ‖ 24 B nonce

AAD_snap = "URmessage/v1/aad/snap" ‖ u16(alg_id) ‖ LP(group_id) ‖ u64(n)
```

**What each element buys, stated on the same terms §7's own table states its.**

- **The 56.** `32 ‖ 24` is the split `key_head ‖ nonce_head` already uses in §8 and `wrap_key ‖
  wrap_nonce` uses in §7, and a 24-octet nonce is XChaCha20-Poly1305's and no other v1 suite's — the
  same argument §8 used on 2026-08-25 to settle which `alg_id` its own record AADs carry. So `alg_id`
  here is `0x0021`, by that argument rather than by a fresh assertion.
- **`K_snapshot[n]` does not change value, so nothing quoting it goes stale.** HKDF-Expand's output is
  a prefix of any longer expand under the same PRK and the same `info`, so the first 32 octets of the
  56 are exactly the octets the pre-amendment line produced. Measured rather than assumed:
  `Expand(root, "snap/v1", 32) == Expand(root, "snap/v1", 56)[:32]` over 1,000 random roots, every
  one. **Zero wire bytes** — `nonce_snapshot[n]` is derived independently by both sides and the blob
  object's length is unchanged — and **no code**: a grep for `K_snapshot`, `KSnapshot` and `snap/v1`
  across every `*.go` file in `msgrepo` and in `connect` returns **zero** hits.
- **What the AAD buys.** `storage_root[n]` already binds the group and the epoch, so `LP(group_id)`
  and `u64(n)` are defence in depth of exactly the kind §8's `AAD_body` already carries for exactly
  that reason. `u16(alg_id)` is the element that is **not** redundant: it is M-15's anti-downgrade
  half, and without it the suite identifier is a value nothing binds.

**What the nonce does NOT buy, because the honest half is the useful half.** Both `K_snapshot[n]` and
`nonce_snapshot[n]` are functions of the epoch alone, so **two snapshot objects sealed at one epoch
reuse the pair exactly**. The derived nonce does not rescue that case and no reader should conclude it
does. It is not hypothetical: step 6 below lets **any member** re-publish the missing wraps of an
interrupted fan-out, the snapshot is one of the records `expected_wrap_count` names, and the wrap index
is deliberately not unique (ledger open item **132**). It is safe only while every conforming publisher
seals a **byte-identical** plaintext — which the ratchet-tree public state and GroupContext at one
epoch are by MLS agreement, but which **no line of this corpus requires of the serialiser**. Two
publishers whose encodings differ by one byte hand the message server a two-time pad over the epoch's
ratchet tree, plus the Poly1305 one-time key. Ledger open item **148** files it, and it is **not ruled
here**: both repairs are rulings this amendment is not scoped to make — a canonical-serialisation MUST,
or a publisher-separated nonce, which either changes `K_snapshot[n]`'s value or adds a second expand
beside it.

**The outer seal. RULED 2026-09-13, and the two wrap kinds take opposite answers because they have
opposite readers.** A wrap is an ordinary record, and an ordinary record's `ct_body` is AEAD'd under a
`record_key` descending from `storage_root[n]` (§8.1) — which is the value the wrap exists to deliver.
That circularity is broken once per kind, and the break for the device wrap is one new exporter label:

```
env_key[k] = MLS-Exporter("URmessage/v1/envelope", "", 32)          RFC 9420 §8.5, at epoch k
```

- **The device-wrap records ride that envelope.** `env_key[k]` takes the place of the class key at the
  head of §8.1's **existing** ladder, for a device-wrap record and for nothing else:
  `record_key[0] = HKDF-Expand(env_key[k], "sender/v1" ‖ LP(leaf_index), 32)`. No new ladder, and no
  label below the root changes. It is not circular — `env_key[k]` descends from the MLS key schedule
  and from no `storage_root` — and it is chosen for the one property nothing else has: it is the only
  outer key that **neither the message server nor a member removed by the commit that opened epoch
  `k`** can derive, while a member the commit *added* holds it the moment it joins.
- **The recovery wrap cannot use the envelope, and is KEM-sealed as a CONSEQUENCE rather than as a
  second ruling.** Its only intended reader is a seed-only restorer (§5.4), which has no MLS state by
  definition — therefore no `mls_secret[k]`, therefore no `env_key[k]` — and no `storage_root` of any
  epoch. Any outer key derived from either makes this record unopenable by the one party it is for. So
  its `ct_body` is the wrap body under **no record AEAD** — *(**amended 2026-09-09**: this clause read
  *"its `ct_body` **is** `hybrid_ct`, padded to its rung"*, and the `C3` ruling makes that false in two
  places. The body is `wrap_envelope ‖ hybrid_ct` under §7's grammar, and it carries the same `LP32`
  length prefix the two device-wrap bodies do — one grammar for all three, which is the whole of the
  ruling's second repair)* — and its `ct_head` is a real AEAD keyed
  `key_head ‖ nonce_head = HKDF-Expand(wrap_key, "wraphead/v1", 56)`. The head is not optional: the
  shipped server refuses a zero-length `ct_head` at four independent points, which Spec A §5.11
  measures. Keying it off `wrap_key` is not circular, because `wrap_key` comes from decapsulation.
- **The epoch snapshot is not in the wrap-body class at all.** It is ruled under `K_snapshot[n]` above
  and is a blob-ref record with no `ct_body`; nothing in this paragraph touches it.

**The envelope's accepted cost is a caching obligation, and it is live.** `env_key[k]` is computable
only while the group is **at** epoch `k`: an MLS exporter reads the current epoch's schedule, and no
published API reaches a past epoch's exporter. So on every transition into an epoch — its own merged
commit, or a peer's processed during catch-up — and **before merging any further commit**, a client
MUST export `env_key[k]` and retain it durably across a restart, until it has opened its own
device-wrap records for epoch `k` and derived `storage_root[k]`, at which point it zeroizes it. A
client that misses the window **cannot recover `storage_root[k]`**, and with it loses every class key
of epoch `k`, every record sealed under them, and that epoch's snapshot. It is **not** locked out of
the group — `read_key[k]` and `write_key[k]` arrive in the clear in the commit's `EpochAttachment` —
and it MUST surface the epoch as a visible failure rather than failing silently or retrying forever.
Spec A §5.11 carries the measurements behind this paragraph and the residuals it leaves open.

**Every wrap body is signed under the publisher's `identity` key, and a client MUST NOT honour an
unverified one.** For the recovery wrap this is §5.3's existing rule applied where it already applied.
For the two device-wrap records it is **new normative policy, RULED 2026-09-13**: they carry a
`WrapTag` and no `RecoveryTag`, so §5.3's sentence had never reached them and no document required a
signature over them before. It is required because the wrap is the only record class carrying **no MLS
frame** — so without it every field a client validates on a wrap is authenticated by nothing, and
§9.2's stated mitigation for server injection, *"any record it injects fails MLS verification at every
client (I5)"*, has no referent for a wrap. 64 octets fit inside the rung with room to spare.

**Where the signature sits and which octets it covers — RULED 2026-09-09.** The signature is the last
field of `aead_ct`'s plaintext, with `LP(identity_pub)` beside it, and its preimage is written out in
§7. It therefore lives **inside** the KEM seal: no party but the decapsulating target can locate it,
and no party but the decapsulating target can tell a signed wrap from an unsigned one. That is the
accepted cost of keeping the committer unattributable to the operator, and it is stated here rather
than left to be discovered, because the *"MUST NOT honour"* sentence above reads as though anyone
could apply it. **The order in which a target opens, verifies and honours a wrap — and therefore what
*"honour"* means — is not ruled here** and is filed in Spec A §5.11.

**How every wrap body is padded — RULED 2026-09-09, and it is one scheme over all three.** A wrap body
is `LP32(len) ‖ body ‖ zeros` to its rung, and **a non-zero tail is a typed refusal**: the check
accumulates over the whole tail and **names no position**, because anything that reports where the
first non-zero octet lay is a padding oracle. The refusal is not optional and it is not decoration: a
device wrap's tail sits inside the record body AEAD, whose key descends from `env_key[k]` — which
**every member of the epoch holds** — so an unchecked tail is a ~2.8 KB member-writable channel inside
every wrap that the body signature does not cover. **Three things this rule still owes a document**
and Spec A §5.11 files them: the fill octet is zero; the true inline ceiling is **65,532** rather than
the *"64 KiB"* this document publishes below; and whether the same tail refusal reaches the **ordinary
record body**, whose unpadder is the same function.

**Epoch publication sequence.** A commit is submitted at `epoch == current_epoch = n`, MAC'd under
`write_key[n]`, and carries an `EpochAttachment` for epoch `n+1`.

**RULED 2026-09-13 — the recovery wraps land AFTER the marker, and the reason is the shipped server.**
The pre-ruling sequence published one recovery wrap per member *before* the marker, and **no conforming
fan-out executed against the shipped server at all**: the epoch-complete gate exempts exactly the
`WrapTag` and `EpochComplete` attachment kinds, so a `RecoveryTag` record submitted while the fan-out is
open is refused `REASON_EPOCH_INCOMPLETE` — and that refusal is asserted by name, against **both** store
implementations, by a contract test that derives the exempt class from the declared attachment kinds in
**both directions**. Nothing in the server changes and that test stays green as written; what changes is
that a conforming client no longer submits a recovery wrap at that moment. Spec A §5.11 and Spec B §6.1
carry the measurements.

1. The server accepts at most one commit per `(group_id, epoch)`. On acceptance it sets
   `current_epoch := n+1` and installs `write_key[n+1]` from the attachment, in the same transaction.
2. The committer then submits, **as ordinary records at epoch `n+1`, MAC'd under `write_key[n+1]`**:
   **two** device-wrap records per active device leaf (`WrapTag`, both indexed by that leaf's
   `wrap_target_handle`), and the ratchet-tree snapshot (one `PERMANENT`-class record, `WrapTag` with
   `leaf_index = 0xFFFFFFFF`). **No recovery wrap is published in this step.**
3. The committer closes the fan-out with one `EpochComplete` marker record whose `wrap_count` MUST equal
   the attachment's `expected_wrap_count`. Until that marker is accepted, the group is
   **readable-but-not-writable**: the server returns `REASON_EPOCH_INCOMPLETE` to any submit at epoch
   `n+1` that carries neither a `WrapTag` nor an `EpochComplete`.
4. **Then**, as ordinary records of the now-open epoch `n+1`, the committer publishes one recovery wrap
   per member (`RecoveryTag`, indexed by `recovery_handle`). They are ordinary in every sense: the
   epoch-complete gate is satisfied, nothing exempts them, and they hold no privilege the epoch's other
   records do not.
5. A member or device that finds no **device** wrap for its target at epoch `n+1` after the marker has
   landed surfaces a `gap` entry with reason `no_wrap`. It never fails silently. This detector covers
   the device arm and the snapshot and **not** the recovery arm; *What `expected_wrap_count` counts*
   below says why, and says what covers the recovery arm instead.
6. If the committer dies mid-fan-out, the marker never lands, the group stays non-writable, and any
   member may re-publish the missing wraps for epoch `n+1` (*"they are all derivable from the epoch
   state every member holds"* — **that parenthesis is false as it stands and is deliberately not
   repaired here**: `pq_secret[n+1]` is a fresh CSPRNG draw delivered only inside the wrap, so a fan-out
   interrupted before the first device wrap lands is derivable by nobody at all. Ledger open item **134**
   files it, and its other two copies are marked in place the same way in Spec A §5.11 and Spec B §6.1)
   and submit the marker.
7. **A committer that dies after the marker and before the recovery wraps leaves a fully writable group
   with a short recovery arm, and no party detects it.** This failure mode is new with the resequence
   and is the first of its two accepted costs. It is **not** confined to a committer that dies — see the
   next paragraph, which is the half of the cost most easily missed.

**The window the resequence opened, and it is not only a dead committer's problem — the second accepted
cost.** Step 3's marker is what makes the group **fully writable**, and step 4 then runs *inside* that
writable window. So any member's commit accepted during step 4 sets `current_epoch := n+2`, and every
recovery wrap still in flight is refused **`REASON_EPOCH_STALE`**: the server refuses any record whose
epoch is not the current one, and that check sits **in front of** the epoch-complete gate, so nothing
about the fan-out's state changes the answer. **The refusal is permanent.** Therefore an ordinary,
conforming, **live** committer loses the tail of its recovery arm to somebody else's perfectly legal
commit — no crash required, at whatever rate the group commits. The window is the recovery arm's own
length, about eighteen round trips at the design target; the sizing paragraph below carries the
arithmetic. Whether a stranded recovery wrap may be republished at a later epoch is **ledger open item
142 and is not ruled**: Spec A §5.11 prices it and shows that the obvious retry — rebuilding the record
around a `ct_xwing` the outbox kept — is an XChaCha20-Poly1305 nonce reuse rather than a repair.

**What `expected_wrap_count` counts, and what it cannot see.**

```
expected_wrap_count = 2 × (active device leaves) + 1        // the + 1 is the epoch snapshot
```

It counts **both** device-wrap record kinds and the snapshot, and it counts **no** recovery wrap. At the
design target that is 2 × 1,000 + 1 = **2,001**, and the marker's `wrap_count` must equal it.

**And for the recovery arm it is decorative, by construction.** The count names a set that closes when
the marker lands, and under the resequence the recovery wraps are published after that moment — so the
count cannot name them, and the omission detector cannot see a missing recovery wrap.

**"Decorative" is scoped to the recovery arm, and it does not mean "advisory".** For what the count does
name — the two device-wrap record kinds and the snapshot — it is **exact**, and its equality against the
marker's `wrap_count` is normative and is the only thing that opens an epoch. A server or client that
read the word as licence to stop enforcing that equality would reintroduce the permanent brick the gate
exists to prevent.

**So what does detect a missing recovery wrap? Nothing does.** Written plainly, because the honest
answer is the useful one:

- **`expected_wrap_count` cannot.** It closed before the recovery wraps were due.
- **Step 5's `no_wrap` gap cannot.** It is keyed on *"after the marker has landed"*, and after the
  marker has landed an absent recovery wrap is indistinguishable from one not yet published.
- **No live member notices**, because no live member reads its own recovery wrap on any normal path.
  Its reader is a seed-only restorer, which is by definition not present when the wrap is due.
- **The server cannot.** It never counts a wrap record, `expected_wrap_count` has no upper bound, and
  the wrap index is deliberately not unique — ledger open item **132**.

**A missing recovery wrap is therefore discovered at restore time, by the party least able to do
anything about it, potentially years later** — and by then that epoch's `storage_root` is unrecoverable
for that member. It is the accepted cost of the resequence, recorded here rather than only in the
ledger, and there are **two** ways to get one rather than one: a committer that dies after the marker
(step 7), and a live committer that loses the rest of its arm under `REASON_EPOCH_STALE`.

**Sizing at the 500-member × 2-device design target, after the 2026-09-13 device-wrap split.** Every
wrap is padded to the ladder like any other record, and the arithmetic is §7's framing with `LP` = 4
octets, an X-Wing ciphertext of 1120 and a 16-octet AEAD tag. A device-wrap record carrying **one**
32-octet secret is `2 + (4+1120) + (4+32+16)` = **1,178 B** of plaintext (the pre-split two-secret wrap
was 1,210 B); a recovery wrap carrying `storage_root` (32) and `archive_secret` (64) is
`2 + (4+1120) + (4+96+16)` = **1,242 B**; and the body signature adds 64 octets to each. **The
2026-09-09 ruling adds three more terms and no wire octet:** `LP(identity_pub)` costs 36 inside
`aead_ct`, the wrap envelope 11 outside `hybrid_ct`, and the `LP32` body prefix 4 — so the ruled
device-wrap body occupies **1,293** of the 4,096 rung with a **2,803**-octet zero tail, and the ruled
recovery wrap's `ct_body` occupies **1,357** of 4,112 with a **2,755**-octet tail. Every one of
them still lands in `size_bucket 2`, so each is a `ct_body` of exactly 4,112 bytes plus its head and
header, about **4.6 KB on the wire**, with roughly 2.8 KB of the rung unused — so the signature, the
identity key, the envelope and the prefix together cost nothing on the wire. One commit + 2,000 device-wrap records + 1 snapshot record + 1 marker + 500
recovery wraps is ≈ **2,503 records ≈ 11.5 MB**, plus the ~300 KB snapshot object on the bulk plane
(≈ 1,503 records and ≈ 6.9 MB before the split). Per-record size caps apply to individual wrap records,
never to the commit as a whole. `max_records_per_submit` is 256 and `max_submit_bytes` is 131072; the
byte cap binds first at about 28 wraps per submission, so the wrap traffic takes **~90 round trips**,
now split either side of the marker: **~72** for the device arm and the snapshot, then the marker, then
**~18** for the recovery arm — and that last figure is the length of the window above.

Padding is what makes those numbers what they are. A wrap-sized rung on the ladder would have cut the
**pre-split** bundle from 6.9 MB to roughly 2.6 MB; the ratio is unchanged by the split, and the
post-split absolute is deliberately **not** restated here, because no ruled document carries one and
this amendment computes no new figure. Either way the rung is not added in v1: the ladder is restated
in three documents and enforced as an equality by the server, and renumbering it to save bytes on the
one operation that is already the largest in the system is a wire break bought for a bounded case.

The snapshot exceeds the 64 KiB inline ceiling and is therefore written as a **blob-ref record**
(`size_bucket = 5`) of class `PERMANENT`. The server MUST offer a non-expiring object rung for it — see
Spec B §8.3 — and MUST NOT place it on any TTL ladder.

The server MUST index wraps by target: device wraps and the snapshot by `wrap_target_handle`, recovery
wraps by `recovery_handle`, both delivered inside the authenticated `server_attachment` (§8.3). Without
this a 500-member group makes every join an 11.5 MB download.

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
    u32  expected_wrap_count    // RULED 2026-09-13: the device-wrap RECORDS plus the one snapshot,
                                //   for the epoch this attachment opens -- two device-wrap records
                                //   per active device leaf, so 2 x device_leaves + 1. Recovery wraps
                                //   are NOT counted: they land AFTER the marker. See "What
                                //   expected_wrap_count counts, and what it cannot see" in 8.2,
                                //   which also says what detects a missing recovery wrap (nothing
                                //   does).
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

### 8.4 The inner MLS frame, its AAD, and `message_id`

**RULED 2026-09-15 — BOTH HALVES IN ONE SITTING, because they are one question asked twice.** The
first half is *what is inside `ct_body`*; the second is *what names a message*. The second is only
answerable because of the first: the identifier this section defines is a triple MLS signs, and
before the first half it was a triple only the group's own shared key covered.

#### 8.4.1 The body is a real MLS frame, and this REMOVES A DIVERGENCE rather than adding a rule

**§8's record block has said `ct_body` is *"the MLS PrivateMessage payload"* since revision 4, and
§8's `I5` paragraph has said *"Sender authentication is MLS's, inside the ciphertext"* for as long.
Neither sentence changes here.** What changes is that the shipped build did not do it — it padded the
application plaintext and sealed it under a record key, using MLS as a key schedule and skipping the
part of MLS that authenticates senders — and **that divergence was declared nowhere**: not as an
erratum, not as an open item, not as a `NotBuilt` entry. It is declared now, and the rule this
document already carried is made satisfiable by reading this document alone.

**WHAT FORCED IT, measured rather than argued.** §8.1's `record_key[0] = HKDF-Expand(class_key,
"sender/v1" ‖ LP(leaf_index), 32)` takes the **class key every member of the group holds** and a
**leaf number**, and a leaf number is an INPUT rather than a credential. `sender_handle` is the same shape. `write_auth` is a
MAC under a group-wide key. So **any member can derive any other member's record key at any position
and seal a record the whole group opens as that member's.** The record layer's AEAD proves *"someone
in this group wrote this"*; it has never proved *"Alice wrote this"*, and nothing in the record layer
can, because every input to it is group-shared by construction. A real `PrivateMessage` closes it
because MLS signs every application message under the sender's own credential, which is the one
secret in the system that is not group-shared.

**Scope, and it is held.** The **body only**. The record layer, the retention classes, the size
ladder, the blob path, `ct_head`, `write_auth`, the codec, `format_version`, every server-side check
and every line of Spec B stand exactly as they are. **No wire field is added, removed, widened or
reordered, and no octet of the record's encoding moves.** What changes is the plaintext *inside* one
AEAD the server cannot read. The outer AEAD keeps doing what it does for the server — erasure,
retention class, ordering, position; the inner frame does what it does for members — authentication
and per-message forward secrecy.

`ct_body`'s plaintext, before padding, is `LP(inner) ‖ 0*` to the rung — **unchanged**, the padder is
untouched — where `inner` is one marshalled MLS `MLSMessage`. **Which records carry which `inner` is
derived from two values the sealer already holds**, never from a new parameter:

```
is_commit   server_attachment.kind   inner
----------------------------------------------------------------------------------
    1       any                      the MLS COMMIT this record announces. ALREADY an
                                     MLSMessage today; nothing about a commit record changes.
    0       NONE                     an MLS APPLICATION message, ContentTypeApplication,
                                     produced by Protect. THIS ROW IS THE WHOLE OF THE CHANGE.
    0       WRAP | EPOCH | COMPLETE  NO MLS FRAME AT ALL. ct_body carries that record kind's
            | any other              own body, exactly as it does today.
```

A record in the middle row is an **application record**. The predicate is `is_commit == 0 &&
kind == NONE`, stated once and computed once. Row 3 is not a carve-out invented here: §8.2 and Spec A
§5.11 (5) already say a wrap *"carries no MLS frame at all"*, which is why a wrap head has no
`sent_at` and why ledger item **185** exists. Row 1 is not a change either: a commit record's
`ct_body` has always held an `MLSMessage`, so **MASTER §8's sentence was already true for commit
records and false only for application records** — which is the precise shape of the divergence and
the reason no reader caught it by grepping this document.

**An application record is therefore DOUBLE-SEALED, and the two seals answer different questions.**
The inner seal answers *who wrote this, and in what position*, to members. The outer seal answers
*which class, which window, which stream position, and may this be erased*, to the server. Neither
substitutes for the other, and **I7**'s *"distinct keys and distinct AADs"* now spans three AEADs
rather than two.

#### 8.4.2 `aad_mls` v2 — what the inner frame authenticates, and what that defends

**RULED 2026-09-17. THIS SECTION CARRIED v1 UNTIL THIS RULING AND CARRIES v2 FROM IT. ONE VERSION,
ONE FLAG DAY, ONE LIVE RE-RUN.** v1 bound six header fields and nothing else, and the two things it
left outside are each a standing forgery with a measured reproduction: the MLS **generation**
(reproduced below) and the **head plaintext** (ledger **MG-6**). They land together because two wire
changes would cost two flag days and two live re-runs of every number this project holds, and
because the second of them would re-measure the first.

MLS's `authenticated_data` is covered by the `PrivateMessage`'s own two AEADs **and by the sender's
signature**, so it is the place a record binds itself to the credential that wrote it. v2 puts three
things there rather than one, and the digest stays 32 octets, so **no wire field moves and no rung
moves**.

```
aad_mls = H("URmessage/v2/aad/mls" ‖ AAD_body ‖ u32(generation) ‖ head_commit)      32 octets

  The preimage is 160 octets and has exactly four terms, concatenated in this order with no
  separator, no padding and no framing of any kind:

  (1) the label        20 octets   "URmessage/v2/aad/mls", US-ASCII, raw. No length prefix, no
                                   NUL terminator, no version octet beside it. The label is the
                                   version: a v1 opener handed a v2 frame rebuilds v1's preimage,
                                   gets a different digest and refuses at R2, which is the
                                   fail-closed direction.
  (2) AAD_body        104 octets   §8's, VERBATIM AND UNCHANGED, and its own label stays at v1:
                                   "URmessage/v1/aad/body" ‖ u16(alg_id) ‖ LP(group_id)
                                   ‖ LP(sender_handle) ‖ u64(epoch) ‖ u64(stream_index)
                                   ‖ u8(retention_class) ‖ u64(eph_window)
                                   104 octets for v1's fixed 32-octet group_id and 16-octet
                                   sender_handle; alg_id is 0x0021. The term is AAD_body's OWN
                                   OCTETS, taken from the one builder that produces them, and
                                   never a second assembly of its fields here.
  (3) u32(generation)   4 octets   BIG-ENDIAN, four octets, most significant first. It is RFC 9420
                                   §6.3.2's SenderData.generation of THIS frame — the generation of
                                   the sender's own application ratchet that this frame's content
                                   is sealed under. u32 and not u64 because u32 is the width RFC
                                   9420 gives the field, and a second width here is a preimage no
                                   MLS implementation reproduces.
  (4) head_commit      32 octets   RAW, no length prefix, the full 32-octet HMAC output:

                                     head_bind_key = HKDF-Expand(record_key[i],
                                                                 "rec/v1/head-bind", 32)
                                     head_commit   = HMAC-SHA-256(head_bind_key, head_plain)

                                   record_key[i] is §8.1's ladder rung at i = stream_index — the
                                   SAME rung key_head ‖ nonce_head and key_body ‖ nonce_body come
                                   off, reached by no new ladder and no new walk. The info string
                                   is the raw ASCII "rec/v1/head-bind", 16 octets, length-prefixed
                                   by nothing, which is exactly what "rec/v1/head" and
                                   "rec/v1/body" already are; it stays at v1 because it names a
                                   derivation off the v1 record ladder. head_plain is the head
                                   PLAINTEXT octets exactly as they are sealed into ct_head — the
                                   same array, of whatever length including zero, with no length
                                   prefix, no padding, no re-encoding and no canonicalisation.

H is SHA-256 and HKDF is HKDF-SHA-256, as §0's notation fixes them. The output is 32 octets and
`aad_mls` IS those 32 octets. **Two implementers building from this block alone produce the same 32
octets.**
```

**WHICH RECORDS THIS REACHES, and it is not "every record".** Exactly §8.4.1's middle row: an
**application record**, the predicate `is_commit == 0 && server_attachment is empty`, computed once
and read identically by the sealer and the opener. Row 1 (a commit record) and row 3 (a wrap, an
epoch fan-out, a completion marker) carry **no `aad_mls` at all** and nothing in this section reaches
them; §8.4.7 says what does and does not authenticate those.

**`AAD_body` IS STILL THE SECOND TERM AND IS STILL NOT RE-ASSEMBLED HERE**, for v1's reasons, which
this ruling does not disturb: it already carries exactly the six fields that fix a record's identity
and position, one preimage builder cannot drift from itself, and a field added to `AAD_body` later is
bound here automatically rather than by a second edit somebody forgets. **It is still HASHED and not
carried verbatim**: `AAD_body` is 104 octets and those octets come out of the size rung — verbatim,
the 256-octet rung carries **no application body at all** (measured, §8.4.4). v2 adds 36 octets to
the **preimage** and **zero to the wire**, because the digest's width is what travels.

**WHY THE GENERATION, stated as the attack it stops, and it is not the attack v1 stopped.** The
generation is **not in the signature preimage**: RFC 9420 §6.1's `FramedContentTBS` is
`ProtocolVersion ‖ WireFormat ‖ FramedContent ‖ GroupContext`, and `FramedContent` carries the group
id, the epoch, the sender, the `authenticated_data`, the content type and the content — and no
generation. The generation lives in `SenderData`, sealed under the epoch's **group-shared**
`sender_data_secret`, so every member can write one. And every member can seal *at* one: RFC 9420 §9
derives every leaf's ratchet from the epoch's `encryption_secret`, which is group-shared by
construction, so a member holds any other member's message key at any generation it likes.

So a member who cannot forge Alice's signature can **open Alice's frame, keep her `FramedContent` and
her signature octets unchanged, and re-seal them at a generation of its own choosing.** Under v1 that
record passes R1 (the frame really is Alice's) and R2 (the position really is that record's), and the
receiver obeys the generation the attacker wrote. What it buys is a **deletion the attacker aims**:
an accepted frame commits its generation at that receiver, and Alice's own later frame at that
generation is then refused for ever with *"ratchet generation already consumed"*. Aimed one at a
time, or a few at a time past the retained-key bound, it takes the lot. **Measured, and the two
shapes differ — §8.4.4 publishes the numbers and the query.**

With the generation inside `aad_mls`, that record is one whose inner AAD names a generation it is not
at, and §8.4.3's R2 catches it — **before any ratchet moves**, which is R3.

**WHAT TERM (3) OBLIGES A SEALER TO DO, because the obvious reading of it is impossible.** MLS's
`Protect(aad, plaintext)` takes the AAD as an **input** and chooses the generation **inside**, from
the sender ratchet, so the generation cannot be in the AAD before `Protect` is called. Term (3) is
therefore not a value a caller looks up and passes; it is a value the seal must **agree with itself
about**. The rule:

```
S1  The sealer MUST build aad_mls from the generation the frame is ACTUALLY sealed under.
S2  The reservation of that generation and the construction of aad_mls MUST be ATOMIC with
    respect to every other seal on this group's own sender ratchets.
S3  If the generation consumed is ever not the one aad_mls names, the seal MUST REFUSE and
    emit NOTHING. It MUST NOT return a frame whose AAD names a generation the frame is not at.
```

**The shape this document rules, and why it cannot emit a divergence.** The seal takes an **AAD
builder** rather than an AAD — `f(generation) → aad` — and reads the next generation, calls the
builder, signs and seals under **one** hold of the lock that already serialises this group's seals.
Four parts, and the fourth is the one that makes S1 a rule rather than an argument. *(i)* **One
consumer**: a leaf's *application* ratchet is advanced by the application seal and by nothing else —
a proposal and a commit draw from the **handshake** ratchet, which is a different ratchet of the same
leaf. *(ii)* **No external door**: the secret tree is not reachable from outside the MLS
implementation, so nothing can step that ratchet behind the seal's back. *(iii)* **One lock hold**
spans read, build, sign and seal, so no other seal on this group can interleave between the read and
the consume. *(iv)* **S3 is the pin.** If (i) to (iii) are ever wrong, the result is one local
refusal costing one generation — an ordinary gap, exactly like a refused submit — instead of a sender
**every one of whose messages is refused by its own peers** for a reason it cannot see. That
asymmetry is why S3 is a MUST: a wrong atomicity argument must be loud at the sender rather than
silent everywhere else.

**Three shapes are refused and the reasons are recorded so they are not re-proposed.** *Expose the
next generation and require the seal to use exactly that one*: two calls, two lock acquisitions, a
window between them, and no place for S3 to live — nothing in the seal's signature says which
generation the caller assumed. *Return the generation and let the caller rebuild the AAD*: impossible,
because the AAD is an input to the **signature**. *Reserve the generation, then seal against it*:
splits reservation from consumption and makes an unconsumed reservation a new durable state that
`§8.4`'s persist rule would have to carry.

**And the property to mutation-test, which is not the same as S1.** *Every frame a sealer emits names,
in its AAD, the generation it is sealed under.* **Falsifiable:** hand the seal a key source that skips
one generation and require the call to refuse rather than return octets. A build that returns them is
one whose every message is refused by its own peers, and the case that catches it is the only thing
between that and a silent outage.

**WHY THE HEAD, and why the bind is KEYED.** `ct_head` is sealed under the same `record_key[i]` every
member derives, and under v1 **no field of the inner frame covered the head plaintext**. So a member
could take another member's genuine body — frame, signature and all — and re-issue it at the **same
position** under a head of its own writing: R1 passed, R2 passed, and the record opened to the true
sender's plaintext under an attacker's head. The head is not decoration: it carries `sent_at`, which
is what a conversation is ordered by and what §12.1's delete-for-everyone window is measured from.
And the substitute is *accepted*, so it spends the rung and the genuine record at that index then
cannot open at all. That is ledger **MG-6** and ledger open item **204**, and `head_commit` closes
both.

**It is `HMAC-SHA-256` under a key and never a bare `H(head_plain)`**, and the reason is a leak rather
than a preference: `AAD_body` is public to the server, and `aad_mls` travels **in the clear** as the
frame's `authenticated_data`. An unkeyed commitment to a nine-octet head whose only variable is a
millisecond timestamp is a few million guesses, which would hand the server a confirmable
`sent_at` — the one clock value the record layer deliberately keeps inside an AEAD.
`record_key[i]` is the key because both sides hold it at the right moment and no non-member ever
does.

**AND IT IS NOT CIRCULAR, which is the whole reason this one can be bound and `AAD_head` cannot.**
The order is a fact about the construction and is stated here so an implementer does not have to
rediscover it. The **sealer** is handed `head_plain` as an argument and frames the body *after* the
stream index is reserved and *before* `ct_head` is sealed, so every input to `head_commit` — the
rung key and the head octets — exists at the moment `aad_mls` is built. The **opener** opens
`ct_head` *above* the point where it unframes the body, so it holds `head_plain` before it needs
`aad_mls`. Contrast `AAD_head`, which contains `body_hash = H(ct_body)` and `ct_body` is sealed over
the very frame the AAD would sit in: that one cannot be bound in either form, in principle and not
merely in this build.

**WHAT v2 STILL DOES NOT BIND, printed rather than described, because the complement is the part a
reader has to be told.** `AAD_head` carries five fields `AAD_body` does not — `is_commit`,
`size_bucket`, `expire_at`, `blob_id`, `H(server_attachment)` — and v2 reaches **none of them**.
They stay authenticated by the group-wide `write_auth` MAC and the group-wide head AEAD, that is, by
*"someone in this group"*. `is_commit` is the one the **server** acts on. Ledger open item **199**
carries all five and is **not** closed by this ruling; what is removed from its list is the sixth
entry, the head plaintext, which was the only one with a live consumer.

**AND ONE THING v2 MAKES TRUE THAT WAS FALSE, stated because a ruling that only adds is a ruling
nobody checks.** `head_commit` covers the head plaintext and therefore covers `sent_at`. A `sent_at`
a member other than the sender wrote now produces a record that refuses at R2, so ledger open item
**204** — *"`sent_at` is the largest forgeable field in the system and it is the one the UI
renders"* — is **CLOSED by this ruling**, and item **211**'s third clock candidate becomes usable for
the first time.

#### 8.4.3 The refusals an opener owes: two on values, one on ORDER, and none implies another

A record layer that computes `aad_mls` and never checks it has bought nothing: MLS verifies that *the
sender signed whatever AAD is in the frame*, and only the record layer can say whether that AAD is
**this record's**. Likewise MLS reports which leaf signed, and only the record layer knows which
handle the record claims.

```
R1  (sender binding)      REFUSE unless
      sender_handle(group_handle_key, inner.sender_leaf) == record.sender_handle

R2  (position binding)    REFUSE unless
      inner.authenticated_data == H("URmessage/v2/aad/mls"
                                    ‖ AAD_body(alg_id, record.header)
                                    ‖ u32(inner.sender_data.generation)
                                    ‖ HMAC-SHA-256(HKDF-Expand(record_key[i],
                                                               "rec/v1/head-bind", 32),
                                                   head_plain))
      where i = record.stream_index and head_plain is what THIS record's ct_head opened to.

R3  (order)               R1 and R2 MUST be decided on a reading that steps no ratchet and
                          erases no key, and the record MUST be refused before either happens.
```

**R1 is the one that converts *"someone in this group"* into *"Alice"*.** R2 does not imply it: a
member at leaf B can perfectly well call `Protect` with an `aad_mls` naming leaf A's handle — R2
passes, the signature is B's, and the record then claims A while the frame says B. An opener without
R1 has two answers to *who wrote this* and no rule for choosing, which is a forgery with extra steps.

**R2 is the one that makes the AAD load-bearing rather than decorative**, and R1 does not imply it:
R1 pins the writer and says nothing about the position, the class, the window, the generation or the
head the writer's frame was put into.

**R3 IS NOT A RESTATEMENT OF EITHER AND IS THE ONE v2 MAKES NON-OPTIONAL.** Under v1 the ordering was
a defence against a denial channel and a correct opener could be written without it. Under v2 it is
the refusal itself: the **generation** is the value being bound, and opening a frame is what commits
its generation at this receiver. A refusal taken after the open has already spent the ratchet
position the attacker named — which is the whole of the attack — so an opener that checks R2 late has
implemented the check and kept the vulnerability. Stated as a property: **a record that this opener
refuses leaves every ratchet of this receiver exactly where it was.**

**R3 is satisfiable, and this is the one paragraph an implementer needs.** All three inputs R1 and R2
require are readable *before* any ratchet is touched: the sender leaf, the `authenticated_data` and
the **generation** all come out of **one** open of the frame's `SenderData` under the epoch's
`sender_data_secret` — a value every member already holds — plus the cleartext `authenticated_data`
header field; and `head_plain` comes from `ct_head`, which the opener has already opened, above the
frame, in order to have a head at all. **No ratchet is reached by any of it**, because a ratchet is
keyed on the leaf and the generation that reading *produces*. A reading that answers the leaf and the
AAD but **not** the generation does not satisfy R3, and that is the surface change v2 forces: the
pre-ratchet reading MUST answer all three.

**THE PRE-RATCHET READING AUTHENTICATES NOTHING, AND IT DOES NOT HAVE TO.** Every value it reads is
sealed under a group-shared secret or is a cleartext header field, so a member chooses all of them.
A refusal on them is honest — a refusal needs no authentication — while an **acceptance** on them is
an acceptance of an attacker's claim. So the three values are the opener's **pre-filter** and never
its answer: the opener takes R1 and R2 **again** on what the open has authenticated, and that second
reading is the one that decides.

**AND ONE HALF OF THAT SECOND READING IS PREDICTED TO DEFEND NOTHING. It is named here rather than
left to be discovered.** For the leaf and the AAD the second reading is load-bearing in the ordinary
way. For the **generation** it is not, and the reason is mechanical: the content AEAD's key is
derived from the generation the sender data named, so a frame that OPENS AT ALL opened under exactly
the generation the pre-reading read, and a disagreement between the two readings is unreachable
through any octets. **The clause is still written**, because the alternative to writing it is an
argument a reader has to reconstruct rather than a rule, and because the argument's premise — one
`SenderData` open feeding both the pre-reading and the key derivation — is a property of the
implementation rather than of this document. **What is owed:** the pass that implements it MUST
delete the generation half of the second reading, run `connect`'s `mls` and `messagegroup` suites,
and **say by name** whether anything went red. If nothing does, that is the expected answer and it is
reported rather than hidden.

All three are refusals of the **whole record**. A record failing any is not rendered as a message
from anybody — not as a gap attributed to a sender, and not as *"malformed"* under Spec A §7.4, which
is a different condition about a body that opened.

**What to mutation-test, one mutation per clause, each stated so it can be run without re-deriving
it.** *(a)* Drop term (3) from the preimage on **both** sides: a substitute frame re-sealed at
another generation must go from refused to accepted. *(b)* Drop term (4) on both sides: a genuine
body re-issued under another member's head at the same position must go from refused to accepted.
*(c)* Change the label's `v2` to `v1` on the **opener** only: every genuine record must stop opening.
*(d)* Encode term (3) little-endian on the sealer only: every genuine record must stop opening at
every peer. *(e)* Take R2 **after** the open rather than before: the substitute must still be refused
and the victim's genuine frame at the named generation must go from openable to dead — the refusal
survives and the denial appears, which is the mutation that separates R3 from R2. *(f)* Replace
`HMAC-SHA-256(head_bind_key, ·)` with `SHA-256(·)`: no refusal changes and **nothing goes red**, which
is the point — that clause defends a confidentiality property no refusal can see, and it must be
held by a stated rule rather than by a case.

#### 8.4.4 What it costs: the size ladder, measured

Every number below is `len(Protect(aad, plaintext))` on the shipped `connect/mls` at `27c50c2`, over a
two-member group with a 32-octet `group_id` and ciphersuite **C5**. **Query:** a temporary
`mls`-package case that Protects at each length and walks the largest plaintext whose protected form
fits `rung − 4`; it was run, read, and deleted, and `connect` is unmodified. The frame's overhead is a
step function of the plaintext length, because RFC 9420's varint prefix widens at 64 and at 16,384:

**CORRECTED 2026-09-17: THE STEP FUNCTION HAS FOUR STEPS AND THIS SECTION PUBLISHED THREE.** The
sentence above says the varint *"widens at 64 and at 16,384"* and names two boundaries. There are
**three**, because **two different varints** widen: `varint(P)` inside the ciphertext, at 64 and at
16,384, and `varint(C)` around it, where `C ≈ P + 82`, at `C = 16,384` and therefore at `P = 16,300`.
Swept rather than reasoned:

```
overhead = len(frame) − len(plaintext), 32-octet aad, two-member group, 32-octet group_id

  193   for      0 ≤ P <     64
  194   for     64 ≤ P < 16,300
  196   for 16,300 ≤ P < 16,384      ← the band this section and connect/messagegroup both omitted
  198   for 16,384 ≤ P
```

**Query, re-measured 2026-09-17 against `connect` `d368fea`:** a probe module **outside all three
repositories** that imports `connect` read-only, seals at every `P` from 0 to 66,000 and prints
`len(frame) − P` at each change of value; `connect`'s `git status` was empty before and after.
Ciphersuite `0x0003` (X25519 / ChaCha20-Poly1305 / SHA-256 / Ed25519). **The rung column below is
unaffected** — 16,186 is below 16,300, so no rung boundary falls in the missing band — which is
exactly why the error survived: the ladder was measured by *walking*, and the step function beside it
was *derived*, and only the derived one is wrong. **It is load-bearing now** because §8.4.6's early
size refusal is arithmetic over this function, and an implementer who takes the three-step form
refuses a legal 16,300-to-16,383-octet body, or admits one it must then refuse late.

**AND THE OVERHEAD DEPENDS ON THE PLAINTEXT LENGTH ALONE, WHICH IS WHAT MAKES §8.4.6 POSSIBLE.**
Measured in the same run at twelve lengths against three different 32-octet `aad_mls` values
(all-zero, all-`0xff`, and random): the frame length was **identical** at every length. It cannot
depend on the AAD's *value* because the AAD is sealed under no length-varying encoding, and it does
not depend on the AAD's *length* here because `aad_mls` is a 32-octet digest at v1 and at v2 alike.
So `len(frame)` is a pure function of `len(bodyPlain)` for a given epoch — computable **before** a
stream index is reserved or a generation is spent.

```
MLSMessage wrapper           4      version u16, wire_format u16
group_id                    33      varint(32)=1 + 32
epoch, content_type          9      u64 + u8
authenticated_data     1 + |aad|    varint(32)=1 + 32   for aad_mls, at v1 and at v2 alike
encrypted_sender_data       29      varint(28)=1 + (leaf u32 + generation u32 + reuse_guard[4] + tag 16)
ciphertext          varint(C) + C   C = varint(P) + P + varint(64)=2 + signature 64 + tag 16
```

**v2 COSTS ZERO WIRE OCTETS AGAINST v1, AND THE WHOLE TABLE BELOW STANDS UNCHANGED.** `aad_mls` is a
SHA-256 digest at both versions, so `authenticated_data` is 32 octets at both, so `len(frame)` is
identical at every `P`, so `octet_length(ct_body)` is identical at every rung, so no rung moves, no
`size_bucket` distribution changes, and no operator capacity number is re-taken. The 36 octets v2
adds are added to a **preimage**, and a preimage has no width on any wire. **Re-derived rather than
assumed:** the ladder below — 59 / 826 / 3,898 / 16,186 / 65,334 — was re-measured by the same
2026-09-17 probe, by binary search for the largest `P` with `len(frame) + 4 ≤ rung`, and reproduces
exactly.

| rung | `ct_body` octets | body today | body with `aad_mls` (32 B) | lost | with `AAD_body` verbatim (104 B) |
|---|---|---|---|---|---|
| 0 — 256 B | 272 | **252** | **59** | 193 | **0 — the rung carries nothing** |
| 1 — 1 KiB | 1,040 | 1,020 | **826** | 194 | 753 |
| 2 — 4 KiB | 4,112 | 4,092 | **3,898** | 194 | 3,825 |
| 3 — 16 KiB | 16,400 | 16,380 | **16,186** | 194 | 16,113 |
| 4 — 64 KiB | 65,552 | 65,532 | **65,334** | 198 | 65,261 |

**The 256-octet rung is where the whole bill lands, and it is the rung the next ruling's features live
on.** A reaction, a receipt and a typing indicator are all tens of octets; a text message of more than
**59** octets — about 59 ASCII characters, or 15 to 20 CJK or emoji — now pays the 1 KiB rung, which
is `1040` stored octets where it used to pay `272`. That is **3.8x** for a large fraction of real
traffic, and it is the reason `aad_mls` is a digest: the verbatim column kills the rung outright, and
a rung that carries nothing turns every reaction into a 1 KiB record.

**The 64 KiB ceiling moves by 198 octets, and §8.4.6 now rules what a sealer does about it.** A body
of 65,335 to 65,532 octets fitted before §8.4 and does not fit after it; the only place it can go is
the blob rung, and the blob plane is **not built** (ledger open item **203**). What was unruled until
2026-09-17 was not *whether* such a body is refused — it always was — but *what it costs to refuse
it*, and the answer was a stream index and an MLS generation. §8.4.6 rules that.

**What v2 does not cost, beside what §8.4 did not cost.** No wire field, no `format_version` bump, no
schema change, no `CHECK`, no reason code, no Spec B revision, no change to `octet_length(ct_body)`
at any rung, and no re-derivation of `AAD_body`, `AAD_head`, `write_auth`, `key_head ‖ nonce_head`,
`key_body ‖ nonce_body`, `record_key[i]`, `sender_handle`, `message_id` or any other preimage in §8:
every one of them is byte-identical before and after. **The message server is not edited and is not
redeployed for this ruling** — it checks `octet_length(ct_body) == size_bucket_bytes[b] + 16`, and
that arithmetic is untouched. What v2 adds is one HKDF expansion and one HMAC per application record
at each end, over a ladder rung both ends already hold.

#### 8.4.5 `message_id`

**RULED 2026-09-15. The identifier is not invented, and it is not `record_id`.**

The corpus has used `message_id` as the referent of a reaction, a reply, a tombstone, a read cursor,
the local store's per-row key and the C ABI's pagination cursor since revision 9, and **no document
has ever defined it**. It cannot be `record_id`: the server assigns that *after* acceptance, so a
client would have nothing to quote in the record it is sealing, and §8's own block rules `record_id`
out of every preimage for exactly that reason.

```
message_id = HKDF-Expand(group_handle_key,
                         "mid/v1" ‖ LP(group_id) ‖ LP(sender_handle) ‖ u64(stream_index),
                         32)
```

Every term is in this document's own notation: `LP(x)` is the 32-bit big-endian length prefix then
`x`; `u64` is eight big-endian octets; HKDF is HKDF-SHA-256. The `info` string is therefore
`6 + 4+32 + 4+16 + 8 = 70` octets and the output is 32. **Two implementers building from this block
alone produce the same 32 octets.**

**Why this triple.** `(group_id, sender_handle, stream_index)` is unique per message **by a rule this
document already enforces**: §8 makes `stream_index` write-once per `(group_id, sender_handle)`, a
device MUST durably record *"index k consumed"* before encrypting, and the server enforces
monotonicity. It is known to the **sender before it sends**, because the index is reserved before
anything is sealed — so a reply can name its own parent and a send can be quoted optimistically. It
is readable by a **receiver without opening the body**, because all three fields are plaintext record
fields — so an id still keys the row of an `EPH` record whose body has been erased and whose
placeholder must still render in order. **And, since §8.4.1, it is authenticated by MLS**: the triple
is inside `AAD_body`, `AAD_body` is inside `aad_mls`, and `aad_mls` is inside the bytes the sender's
own credential signed. **The id is the sender's claim, not the group's** — and that sentence is false
without the first half of this ruling, which is why the two were ruled together.

**It is KEYED, and `group_handle_key` is the key.** All three inputs are visible to the message
server, so an unkeyed id would be computable by the server for every record it stores, handing it a
join key between any id that ever appears anywhere and the record it names. `group_handle_key` is the
group's one lifetime value: §8 fixes it at creation, never rotates it, and delivers it in the
`Welcome`, so **every member already holds it and no new distribution is needed** — and a member who
does not hold it *"cannot compute its own handle and therefore cannot write"*, so it was already the
floor for participation. Using it rather than `storage_root[n]` is what makes an id **stable across
epochs**, which a reply to a message from four commits ago requires.

**Why NOT the MLS generation, which is the other triple MLS authenticates.** Measured against
`connect` at `27c50c2`:

1. **It is not on the surface.** `mls.ApplicationMessage` (`mls/group.go:3665`) has three fields —
   `SenderLeaf`, `AuthenticatedData`, `Plaintext` — and the generation is not one; the storage
   layer's own seam, `messagegroup.GroupHandle.Unprotect` (`messagegroup/engine.go:122`), returns
   four values and the generation is not one either. Surfacing it changes two published surfaces, one
   of them the RFC-validated `mls` package, for a value nothing else wants.
2. **It is inside the ENCRYPTED `SenderData`** (`mls/framing.go:802`), under a key derived from the
   content ciphertext. So it is computable only by a party that can open the frame — and an id that
   requires opening the body **cannot key a row that outlives the body**. Spec B §7.2 erases
   `ct_body` and `ct_head` for `EPH(1..5)` at `prune_after` while the row stays for gap detection. An
   id that dies with the body cannot name the record that survives it. **This is decisive, and it is
   a property of this system rather than of MLS.**
3. **It resets at every epoch**: the generation is per `(leaf, epoch, content_type)`. So the unique
   tuple is a four-tuple including `epoch`, not a triple, and one of its four members is the one in
   (2).
4. **The sender cannot cheaply compute it either.** `Group.Protect` (`mls/group.go:4332`) returns one
   `[]byte`, and reading the generation off the ratchet before the call means reaching past the one
   seam the storage layer keeps narrow.

**AMENDED 2026-09-17. TWO OF THOSE FOUR REASONS ARE NOW FALSE AND `message_id` DOES NOT CHANGE.**
§8.4.2 v2 puts `u32(generation)` inside the frame's AAD, so the generation **is** on the surface now —
the pre-ratchet reading answers it and the sealer computes it before it seals — and reasons **(1)**
and **(4)** above are spent. They are kept above, struck through by this paragraph rather than
deleted, because a reason that stops being true is the shape this corpus has most often lost track
of. **Reasons (2) and (3) are untouched and each is independently decisive**, which is why the
identifier stands exactly as ruled: the generation is inside the **encrypted** `SenderData`, so an id
built from it could not key a row whose body has been erased and whose placeholder must still render
in order — and it **resets at every epoch**, so the unique tuple would be a four-tuple one of whose
members is the first problem. `message_id` remains
`HKDF-Expand(group_handle_key, "mid/v1" ‖ LP(group_id) ‖ LP(sender_handle) ‖ u64(stream_index), 32)`,
unchanged, and **no octet of it moves under v2**.

**Spelling.** The 32 octets are the identifier. Spec A §7.1 types it `string` on the SDK surface; that
string is the **lowercase hex** of those octets, 64 characters from `[0-9a-f]`, with no prefix and no
separator. Where a preimage takes `LP(message_id)` — Spec A §8.3a's local-store row key is the only
one today — it takes **the 32 octets and not the 64-character spelling**. Stated here because nothing
stated it, and it is free to state now: no local store exists yet, so this is a definition rather than
a migration.

**Every record has one.** The derivation reads only header fields, so a commit record, a wrap and an
`EPH(0)` transient each have a well-defined `message_id`; what differs is whether the product ever
surfaces it. Ledger open item **202** carries the transient, which consumes an index locally, is never
stored, and therefore has an id nothing can fetch.

#### 8.4.6 The size ceiling: the early refusal runs on the FRAMED length

**RULED 2026-09-17. Ledger open item 203's defect half. The product half — where a body above the
ceiling goes — stays open and stays with the blob plane.**

A sealer refuses a body no rung can hold. **The rule is which length it refuses on**, and until this
ruling it refused on the wrong one:

```
An application record's early size refusal is taken over  framed_length(len(bodyPlain)),
and for every other record over  len(bodyPlain).

framed_length(P) is the length of the marshalled MLSMessage the sealer will produce for an
application plaintext of P octets in this epoch. It is a function of P alone (§8.4.4), so it is
computable with no key material, no signature, no ratchet step and no reserved index.

The refusal MUST be taken BEFORE the stream index is reserved and BEFORE the generation is spent.
```

**What the old rule cost.** The early check ran over the caller's `len(bodyPlain)` against the rung
ladder, which is **necessary and not sufficient**: the octets actually sealed are 193 to 198 longer.
A body of 65,335 to 65,532 octets passes that check, **reserves a stream index**, **spends an MLS
generation**, builds the frame, and is only then refused — so a call that always fails costs the
sender one write-once index and one write-once generation per attempt, both of them gaps every
receiver must then absorb, and a caller in a retry loop walks its own ratchet toward
`MaxGenerationSkip` on a request that can never succeed. That is ledger open item **201**'s hazard
reached by a cause that is pure waste.

**Why it is implementable, in one sentence, because that was the open question.** §8.4.4 measures
that the frame's length depends on the plaintext's length and **not** on the AAD's value, and
`aad_mls` is a 32-octet digest at v1 and v2 alike, so `framed_length` is a pure function the sealer
can evaluate in front of both reservations.

**It is DERIVED and MUST NOT be a table of constants.** An implementation MUST compute
`framed_length` from the epoch's ciphersuite, the group id's width, the signature's width and the
32-octet `aad_mls`, by the same construction that produces the frame — never by hard-coding 193,
194, 196 and 198. Those four numbers are this document's **expected answer** for a second
implementation to check itself against at ciphersuite `0x0003` with a 32-octet group id, and a
builder that transcribes them instead of deriving them has built a client that silently mis-sizes on
the first suite, group-id width or signature algorithm that differs — and §8.4.4 records that this
document itself published three of the four correctly and the fourth not at all for two days.

**The derived ceiling, which is what a caller above the record layer must enforce.** The largest
application body an inline rung can carry is **65,334** octets. A caller that offers more is refused
before anything is spent. `sdk` already enforces exactly this at its own door — `MaxTextOctets =
65334`, refused ahead of the seal — and **that enforcement is ratified here rather than introduced**;
what this section adds is that the record layer owes the same refusal at *its* door, because
`SealRecord` is a published surface with callers `sdk`'s door does not front.

**Property, and it presupposes no unruled sentence:** *for every body length, a `SealRecord` call
that will be refused for length reserves no stream index and spends no MLS generation.* **Falsifiable
by an incorrect implementation:** seal a 65,400-octet body twice, then seal a legal one, and read the
legal record's `stream_index` — under the old rule it is 2, under this rule it is 0. **What to
mutation-test:** put the early check back on `len(bodyPlain)` and require a named assertion on that
index to go red; and, separately, hard-code the three-step overhead function of §8.4.4's old text and
require a 16,350-octet body to go from sealed to refused.

#### 8.4.7 What full adoption means for the three things half-adopted

**RULED 2026-09-17, in the same sitting as §8.4.2, because each of the three is a question the
2026-09-15 ruling opened and left open.**

**(1) A MEMBER CANNOT OPEN ITS OWN APPLICATION RECORD. That is MLS, it is accepted, and the product's
answer is the copy the sender kept.** `Protect` consumes a generation of **this leaf's own sending
ratchet**, and MLS derives no *receiving* ratchet for a member's own leaf — a member never receives
its own messages. So `OpenRecord` of a record this same device sealed answers *"ratchet generation
already consumed"*, and before 2026-09-15 it opened. **Ratified: a device renders its own sent lines
from a copy it kept and never by decrypting the record it wrote**, and a record of its own it holds
no copy of is **authenticated by that very refusal**, counted, and is not a failure.

Four things this silently broke and the ruling therefore has to name: a restarted device rebuilding
its own half of a conversation, a record whose submit answer was lost, the clone check's evidence,
and a restored group that could never `Send` again. All four are the same missing sentence — *where
does a device read its own messages from* — and the answer above is that sentence.

**IT WAS BUILT BEFORE IT WAS RULED, AND THAT IS RECORDED RATHER THAN SMOOTHED OVER.** `sdk` chose this
option, implemented it, and holds it in 37 `cp3b` cases while this document still said the opposite;
the ruling ratifies work that was already load-bearing rather than commissioning it. The two other
options are recorded as **refused**: answering the sealer its own plaintext beside the record changes
a published signature for a value the caller already has, and exempting a record at this member's own
`sender_handle` from the inner open **re-opens exactly the forgery §8.4 closed**, narrowed to
self-attribution — any member could seal a record attributed to Alice and Alice's own device would
render it. That third option is written down here so it is refused rather than rediscovered.

**Spec A §5.2's sentence *"it does not make a working call stop working"* is FALSE of this and is
corrected there.** Its measurement was a *second* `OpenRecord` of one record, which already refused
at the record layer's skipped-key window; a **first** `OpenRecord` of one's own record was a working
call and it has stopped working.

**(2) THE CEREMONY ARM CARRIES NO SIGNATURE, ITS `sender_handle` IS ROUTING AND NOT ATTRIBUTION, AND
FULL ADOPTION DOES NOT CHANGE THAT.** §8.4.1 row 3 — a wrap, an epoch fan-out, a completion marker —
carries no MLS frame at all, so §8.4.3's refusals do not apply to it and **no member's credential
signs it**. Every key those records use is group-shared, so any member can write one at any other
member's `sender_handle`. Adopting MLS *fully* does not reach them: a wrap is HPKE addressed to a
device and an epoch marker is a counter, and neither is a thing a `PrivateMessage` could carry
without changing what it is.

So the ruling is what the shape already forces, said out loud in three parts. *(a)* **A ceremony
record's `sender_handle` is a routing label and MUST NOT be rendered, attributed, or used as
evidence that a particular member wrote anything.** *(b)* **A door named for opening a message MUST
refuse the ceremony arm**, so a member's choice of arm is a choice between being checked and being
refused rather than a way around the check. *(c)* **An acceptance on the ceremony arm MUST spend
nothing** — no receiver ratchet rung, no index — because an acceptance taken on an unauthenticated
claim costs the victim while a refusal taken on one costs the attacker. (b) and (c) are already
built; (a) is the sentence that was missing.

**And the one row that DOES admit an authentication is the commit row, which is not this door's.**
A commit record's body *is* an `MLSMessage` and *is* signed. What authenticates it is **processing
the commit**, which belongs to the epoch machinery: that machinery MUST require the commit to be one
MLS accepts **and** to have been signed by the leaf the record's `sender_handle` names, and MUST drop
a record failing either rather than ceremonially applying it. A check taken at the record door on the
frame's *peeked* sender leaf would be **worse than none**, because that leaf comes out of sender data
sealed under a group-shared secret and would read as authentication while authenticating nothing.

**What stays open after this, and it is item 199's list.** `is_commit` and `H(server_attachment)` —
the two fields that *choose* which row of §8.4.1 a record takes — are in `AAD_head` and therefore
outside every signature, and cannot be brought inside one while `AAD_head` contains
`body_hash = H(ct_body)`. So the arm is chosen by something no member signs. That is not closed here
and is not closable by any content kind; it is ledger open item **199**.

**(3) `ReceiverKey` IS UNEXPORTED.** The raw secret-tree door `ReceiverKey(leaf, kind, generation)`
commits a ratchet with **no authentication of any kind**, and it is the one place where the framing
path's whole argument — *"the party choosing this generation opened an AEAD under the epoch's
sender_data_secret, so it is a member of this group"* — comes apart, because a caller handing it a
leaf, a kind and a generation taken off the wire has skipped that AEAD. What one unauthenticated
header then buys is: the victim leaf's node secret taken out of the tree and **both** of that leaf's
ratchets materialised destructively, plus up to `MaxGenerationSkip` = 1,024 ratchet steps and the
retention that goes with them, **with nothing bounding repetition**.

**Measured, with the query beside it, before deciding:** `grep -rn "\.ReceiverKey(" --include=*.go
connect sdk msgrepo` → **42 lines in exactly two files**, `connect/mls/secret_tree_test.go` and
`connect/mls/secret_tree_kat_test.go`, **both `package mls`**, and **zero** production call sites in
any of the three repositories. So unexporting it is a pure in-package rename that breaks no caller
that exists, and the two legitimate needs — look a generation up, then commit it — are already the
`MessageKeySource` pair `MessageKey` / `CommitMessageKey`, which sit **behind** the sender-data open
in the framing path and are where a receive path belongs.

**The reason it is unexported rather than kept with a caveat.** A door whose own documentation has to
say *"it bypasses sender data authentication"* and whose safety rests on *"there is no caller to have
learned it from"* is held by an absence, and an absence is not a rule: the next caller is the defect,
and nothing in the type system or the test suite is looking for it. **Property:** *no package outside
`mls` can reach a ratchet commit that is not behind the sender-data AEAD.* **Falsifiable:** write a
caller in `messagegroup` and require it not to compile. **What must be run in `connect`:** the `mls`
suite, for the gates keyed on this package's exported surface — this document does not claim they are
green, and the pass that lands the rename owes that number with its query.

**This is `connect`'s change and not this repository's**, and no line of it is implemented here.

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
                 ‖ u8(retention_class) ‖ u64(eph_window) ‖ u8(size_bucket)
                 ‖ u64(expire_at) ‖ LP(H(ct_head)) ‖ LP(body_hash) ‖ LP(blob_id)
                 ‖ LP(H(server_attachment)))
```

One group-wide key, so the server learns only "a current member of this group" — which is all it needs
for quota and spam control. Per **I5**, authenticity is MLS's job, and a forged record fails at every
client no matter what the server accepts. Per **I6**, `write_auth` covers every header field the
server acts on.

**`u64(eph_window)` is in the preimage because the server ACTS on it, which is what I6 requires. RULED
2026-09-13.** The server MUST refuse an `EPH(1..5)` record whose `eph_window` is more than **one
window** away from the window its own arrival stamp falls in, in either direction, and the refusal is
Spec B §5.1's and §7's to write. It can make the check with what it already holds: `retention_class`
is plaintext, so it has the bucket; §7.1 already stamps `create_time` and already computes a class
deadline from it. **A window far in the future is the case that matters** — it is a request that an
`EPH` record's key outlive its timer, made by a sender, and under the ruling above it is the key
itself that is being extended rather than a row's lifetime, so no later sweep corrects it. **±1 window
and not tighter**, because the sender computes from `sent_at` and the server sees arrival, and that is
the same skew §7.1's one-hour `grace` already absorbs, expressed in this field's unit. **±1 window and
not looser**, because two windows is a doubling of the shortest bucket's guarantee.

**And that check is satisfiable only with one client-side rule, so the rule is made here.** A queued
`EPH(1..5)` record whose window has closed before it is submitted MUST be **discarded and re-sealed**
at the current window, consuming a **fresh `stream_index`** — not merely re-MAC'd. This is exactly the
shape of the outbox rule below for `REASON_EPOCH_STALE`, and without it a client that reconnects after
a long offline stretch would re-MAC a record the server is now required to refuse. A client that
re-MACs without re-sealing is the falsifying implementation.

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
discarded and re-sealed at the new epoch, consuming a **fresh** `stream_index`. **And a queued
`EPH(1..5)` record whose `eph_window` is no longer the current window MUST be discarded and re-sealed
the same way, for the same reason and at the same cost (added 2026-09-13 with `eph_window`).**
Re-MAC'ing it would submit a record the message server is **required to refuse** under the ±1 check
below, carrying a window a conforming recipient has already left. *(This clause read *"Its old window's
key is being destroyed on schedule, so re-MAC'ing it would submit a record the server is required to
refuse and that no recipient could open."* **Amended 2026-09-13, second pass of that date: there is no
schedule** — ledger open item **186** — and this rule never needed one. The server's refusal is the
whole of the reason and it holds on the text as it stands.)*

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

**A member the policy does not name is a MEMBER** (ruled 2026-09-21, ledger item 242). An Add commit
names nobody — a role is a later, separate policy commit — so every joiner is unnamed until an
admin or the owner says otherwise, and the default must be the role that lets them send. An
implementation whose lookup answers OBSERVER for an unnamed identity is the falsifying one.

**Authority is the committer's.** Every proposal a commit carries, by value or by reference, is
judged against the role of the **authenticated committer** and never against its proposer; a
by-reference proposal is therefore never more permissive than the same proposal by value. An Add is
an ADMIN's or the OWNER's to commit (the table above); a member of any role may remove its **own**
leaf; an identity already in the group may be given a further leaf only by a commit that identity
itself makes, and a leaf's identity does not change across an Update or the committer's own path —
without those two rules a credential that merely *claims* an existing identity would inherit its
role. Ownership transfers only to a current member, and the outgoing owner becomes an ADMIN. A
commit that breaks any rule here is refused before it is built and rejected by every receiver on
validation; because the server has already advanced the epoch by then, honest receivers stop at the
epoch before it — a hostile committer can halt a group and cannot take it.

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
  on every device and on the server."* **This string is a promise about key destruction and is the only
  place the corpus states that promise to a user, so what discharges it matters: "on the server" is
  discharged (the message server never holds `eph_root[n]` at all), and "on every device" is NOT
  scheduled anywhere — ledger open item 186, filed 2026-09-13 (second pass) and not ruled. The string
  is NOT changed, because it states the requirement correctly; what is missing is the mechanism, and
  §8.1 carries the same note at the sentence that makes the same claim.**
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
| 2 | `connect/message/` | Storage records, retention classes, ratchet, PQ composition, `write_auth`, padding, `COVER`. `server_attachment`, `req_auth`, recovery proof, **the `EPH(0)` delivery-receipt record**, **the reaction body as a length-prefixed UTF-8 string**, **the two-sentinel `durable_ttl_seconds` encoding**, and **the contact-card encoding, the rendezvous derivations and the five rendezvous signature preimages**. Freezes the wire format — §8, §8.3 and §9.2 must be final before this slice starts, and the additions named in bold must land here rather than with the client work that renders them. **§8 and §9.2 WERE REOPENED on 2026-09-13, after this slice shipped, to add `eph_window` — see §0 and §8.1. That is a break of this row's own rule, taken knowingly and recorded rather than absorbed.** |
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
