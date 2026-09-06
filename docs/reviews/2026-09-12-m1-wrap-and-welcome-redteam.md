# M1-1 and M1-2: the device wrap's seal and the Welcome's carrier

Written 2026-09-12. **This is a decision document. Nothing in it edits a spec, and nothing in it is
ruled.** It exists because two holes block CP3b, six option write-ups were produced against them, and
three adversarial reviews were run over those write-ups. What follows is what survived.

**Read this if you are ruling.** The five parts answer, in order: what is genuinely undecided; what
the ground under the decision turned out to be; which options are still standing and which attack
killed the rest; what the recommendation costs; and what the evidence does **not** resolve, with what
would have to be measured or built to resolve it. This project has twice had an implementer discover
that a document had silently chosen. Where the honest answer is *the owner must pick*, this document
says so and does not pick.

**Provenance and standard of evidence.** Every code and spec claim below was re-verified in this
session against `connect` at `beta/message` `1307f15` (`go build ./mls/... ./message/...
./messagegroup/...` green) and against `msgrepo` at HEAD. Where a red-team lens made a claim this
document repeats, the claim was checked; where a lens was wrong, or right for a different reason than
it gave, that is said. **Three of the decisive findings are corrections to the red team itself**, and
one — the false sentence at §5.11 step 5 — is duplicated in **three** documents rather than the two
every lens reported.

---

## Part 1 — what is actually undecided

### M1-1 — the device wrap

**The question is not what a wrap contains.** That is pinned, and the arithmetic proves it. MASTER §7
(`2026-08-12-urmessage-protocol-design.md:578-581`) fixes the inner construction verbatim —
`(ct_xwing, ss) = XWing.Encapsulate(target_xwing_pub)`, `wrap_key = HKDF-Expand(ss,
"URmessage/v1/wrap" ‖ LP(group_id) ‖ u64(epoch) ‖ LP(target_id), 32)`, `hybrid_ct = u16(alg_id) ‖
LP(ct_xwing) ‖ LP(aead_ct)`. MASTER §8.2's payload table fixes what rides inside. Spec A §5.11's
published sizes (`spec-a:1666-1671`) reproduce exactly from those two: with `LP` = 4 octets,
`XwingCiphertextSize` = 1120 and a 16-octet tag, a device wrap carrying two 32-octet secrets is
`2 + (4+1120) + (4+64+16)` = **1,210** and a recovery wrap carrying 32 + 64 is **1,242**. Both are the
published figures. So M1-1's own filing — *"no stated seal, anywhere"* — is **wrong about the inner
seal**. It is right about everything else. (The same arithmetic proves the device wrap carries **two**
secrets: a one-secret wrap would be 1,178.)

**The question is the OUTER seal**, and it is circular as filed: §5.11 makes the wrap an ordinary
record, an ordinary record's `ct_body` is AEAD'd under a `record_key` descending from
`storage_root[n]`, and `storage_root[n]` is what the wrap delivers.

Five constraints bound the answer, and **three of them were not in the filing**:

1. **The fan-out is three record shapes, not one.** A device wrap (`WrapTag`, `size_bucket 2`,
   `ct_body` 4,112), a recovery wrap (`RecoveryTag`, same rung), and **the epoch snapshot** — which
   `spec-a:1673` makes a **blob-ref record at `size_bucket = 5`, where `ct_body` is absent
   entirely**, and which correction **E2** (`spec-a:1566`) already pins under `K_snapshot[n] =
   HKDF-Expand(storage_root[n], "snap/v1", 32)`. All three M1-1 options wrote as though the fan-out
   were one or two shapes. A ruling must answer for all three, and for one of them the answer is
   *already ruled — do not overwrite it*.
2. **The recovery wrap's only intended reader holds nothing.** MASTER:818, in as many words: *"A
   seed-only restorer (§5.4) has none by definition."* Correction **E1** (`spec-a:1565`) exists for
   precisely this. Any outer key derived from MLS state or from any `storage_root` makes that record
   unopenable by the party it is for.
3. **`ct_head` cannot be zero-length.** Refused at `api/submit.go:301`, again at
   `store/memory.go:979`; the column is `NOT NULL` (`store/migrations.go:160`); and
   `store/contract.go:145` asserts the refusal against **both** store implementations.
4. The inner X-Wing construction is untouched by all three options, so none of them changes MASTER
   §7's post-quantum claim at the layer that claim is about.
5. Whatever is ruled must not require the opener to hold a key it cannot have **at the moment it
   opens** — a stronger constraint than "at some point in the group's life", because
   `PastEpochWindow` is 32 and older MLS state is zeroized (Part 3).

### M1-2 — the Welcome

**The question is not whether a carrier is needed. It is which value needs one, because the two values
have opposite requirements and gluing them into one sentence hides that.**

`read_key[n]` is handed to the server **in the clear** in every commit — `EpochAttachment.ReadKey`,
`connect/message/attachment.go:160-163`, whose own comment reads *"the server installs it against this
epoch and retains it for ninety days."* It needs integrity and availability at the joiner and
**confidentiality from nobody**.

`group_handle_key` is the opposite in every respect. Its entire job is that *"the server cannot invert
it"* (`spec-a:1641`). It is `HKDF-Expand(storage_root[0], "gh/v1", 32)` and **fixed for the life of the
group** (MASTER:760) — never rotated, no revocation path, and none constructible without breaking every
historical handle. It feeds `sender_handle` (MASTER:650), which is inside every AAD and every
`write_auth` preimage. And `storage_root[0]` requires epoch **zero's** `pq_secret`:
`CreateGroupResponse.current_epoch` is *"always 1"* (`connect/protocol/message.proto:212`), so there has
never been an epoch-0 wrap set, and after group creation the value exists **on the founder's device and
nowhere else, for the life of the group**.

Four constraints bound it:

1. **A Welcome is classical-only.** v1 pins ciphersuite `0x0003`, `MLS_128_DHKEMX25519_...`
   (`connect/mls/suite.go`), and `connect/mls/hpke.go` is DHKEM(X25519). Every octet of secret placed in
   a Welcome is protected by X25519 alone — against MASTER:584's own premise, *"Harvesting today's
   classical MLS handshake is insufficient, because `pq_secret` arrived under X-Wing."*
2. **No joiner can validate `group_handle_key`'s VALUE under any option**, because checking it requires
   `storage_root[0]`. Every option's Property-3 obligation therefore reduces to a width refusal plus a
   behavioural cross-check, and if the ruling does not say so the property passes vacuously.
3. **An absent carrier must be a typed refusal.** `ReadExtensions` carries unregistered types and
   `FindExtensionEntry` answers `found == false` rather than refusing, so the natural implementation
   proceeds with `group_handle_key = 0^32` — which is not a *wrong* key but a **globally known** one,
   making every `sender_handle` and `wrap_target_handle` in the group a constant any attacker can
   tabulate.
4. **The minimum content is decided by M1-1, not by M1-2** — unless M1-1 is ruled in a way that
   decouples them. A joiner at epoch *n* holds `mls_secret[n]` and nothing else.

---

## Part 2 — the ground under the decision, which is not what the options assumed

Six findings. **All six are option-independent** — true whichever way M1-1 and M1-2 are ruled — and
every one was verified in this session rather than argued. They are here, before the options, because
several change what the options are being chosen *between*.

### A. No conforming fan-out executes against the shipped server today

`exemptFromEpochComplete` (`store/memory.go:937-944`) exempts exactly `AttachmentWrap` and
`AttachmentEpochComplete`. §5.11 step 2 requires **one recovery wrap per member** as an ordinary record
at epoch *n+1*, before the marker; `AttachmentRecovery` is not exempt, so every one is refused
`REASON_EPOCH_INCOMPLETE` at `memory.go:581`. This is not a gap awaiting a one-line addition:
`store/contract.go:2555`, `OnlyTheExemptKindsPassTheGateWhileTheFanOutIsOpen`, runs its table against
**both** stores, derives it from the declared `AttachmentKind` constants **in both directions**, and
asserts the refusal by name. Spec B §6.1 asserts the opposite and is wrong.

### B. The server never counts wraps, so every option's omission detector checks a number against itself

`store/memory.go:720-724` opens the group for ordinary writes when `marker.WrapCount` equals
`row.expectedWrapCount` — a **client-declared number compared against another client-declared number**.
No wrap record is ever counted, in either store. `wellFormedEpochAttachment` (`memory.go:962`) bounds
`expected_wrap_count` only at non-zero; there is **no upper bound**. The wrap index is deliberately **not
unique** (`store/migrations.go:222-226`), and **nothing anywhere binds `sender_handle` to the party that
submitted the record** — `SenderHandle` appears in `api/submit.go` only as a copy and in
`store/memory.go` only as a map key.

Three consequences, all reachable by any member holding `write_key[n+1]`, which is every member, because
it is plaintext in the commit's `EpochAttachment`:

- The shared spine's justification for uniform wrapping — *"expected_wrap_count is a pure function of
  the epoch's tree, so every member sees a low one immediately"* — detects only a committer that
  declares a **low** number, which is the one shape a malicious committer would never choose.
- One record closes a fan-out that never happened, forcing a permanent `no_wrap` gap on every member
  simultaneously (§5.11 step 4 keys the gap on *"after the marker has landed"*).
- A committer declaring `expected_wrap_count = 0xFFFFFFFF` freezes a group readable-but-not-writable
  **permanently**, and by finding E the only exit is a marker that lies.

### C. The wrap is the only record class carrying no MLS frame, and I8 does not hold for a single field of one

MASTER **I5** (`:248`): sender authentication is MLS's; *"the storage layer adds no second signature over
content."* MASTER **I8** (`:254`): *"Any field a client validates is either inside the MLS-authenticated
payload or covered by write_auth."* Spec A §2.4 (`:300-303`) empties the second arm on the read path:
`write_auth` is **zero on read** and *"A client MUST NOT verify write_auth on a fetched record."*

A wrap's body is `hybrid_ct`. There is no MLS frame in it under any option. So the wrap's epoch,
`sender_handle`, `stream_index`, retention class, size bucket and `wrap_target_handle` — every field a
client validates and acts on — are authenticated by **nothing MLS**. Options 1 and 2 substitute a
group-wide symmetric key, which proves *some member* and is exactly the granularity I5 says this layer
does not provide; Option 3 substitutes nothing.

**The corpus already contains the fix and no M1-1 option applies it.** MASTER §5.3 (`:441-443`): *"A
client MUST NOT honour a RecoveryTag on any record whose RECOVERY_PUB body signature it has not verified
under the publishing member's identity key."* A recovery **wrap** carries a `RecoveryTag`. Under all
three options it carries no signature to verify. Every option therefore publishes ~500 records per epoch
that §5.3, in its own words, says a client MUST NOT honour.

### D. Removal revokes nothing at the server layer

`EpochAttachment.WriteKey` and `.ReadKey` are plaintext fields of every commit record. `Fetch` runs
exactly four stages (`api/fetch.go`, `fetchStages`) — request shape, known-group, read-key lookup on
`(group_id, read_epoch)`, `req_auth` — and **none scopes the returned records to an epoch**;
`MemoryStore.Fetch` (`store/memory.go:217-255`) filters on `record_id` and the class mask and nothing
else. So a member removed at epoch *n* fetches the commit that removed it under `read_key[n]`, reads
`read_key[n+1]` and `write_key[n+1]` out of its cleartext attachment, and chains forward indefinitely
with a fresh ninety-day window each time.

With `sender_handle` derivable by any holder of `group_handle_key` and monotonicity unbounded on the jump
(`memory.go:609-611`, no reset path in any spec), ~500 records at the maximum stream index permanently
silence the entire membership. MASTER §8's *"A member removed at epoch n keeps metadata access only until
epoch n's key falls out of that window"* is false.

**This decides one option comparison and should be noted where it does.** M1-1 Option 2's stated privacy
cost — *"a removed member can still enumerate and read the outer layer of the fan-out that excluded it"*
— is not a discriminator, because the capability an ex-member retains is far larger than reading and
every option grants it.

### E. The dead-committer case is worse than M1-22 filed it, and a conforming client can cause it

M1-22 files a fan-out interrupted before the first wrap as unrecoverable. It is worse than that:
**readable-but-not-writable is not a resting state, it is terminal.**

- No member can write: `memory.go:581`, `REASON_EPOCH_INCOMPLETE`.
- No member can commit out: a commit carries `AttachmentEpoch`, which the exemption set does not contain.
- Past that gate it still fails: `memory.go:578` refuses any record whose epoch is not the current one
  with `REASON_EPOCH_STALE`, so the escape commit must be submitted **at epoch n+1** and sealed under the
  class keys of the `storage_root` that was lost.

And it is reachable **without a crash**. Spec A §5.12 and guardrail G10 mandate destroying
`pq_secret[n+1]` on *any rejection* of a commit submission, while Spec B `:2234` makes a retried
identical commit return `REASON_OK`. A timeout on a commit that actually landed therefore drives a
**conforming** client to burn the secret for an epoch that is already open. The corpus notices the
adjacent hazard — that same sentence's tail says getting idempotency backwards *"burns a pq_secret"* —
and has not noticed that burning it **after acceptance** is unrecoverable rather than merely expensive.

**The false sentence is in three documents, not two.** *"they are all derivable from the epoch state
every member holds"* appears at `spec-a:1662`, `spec-b:2164` **and** MASTER:852. Every option agreed it
must be rewritten and every lens reported two copies.

### F. eph_root's disappearing-message guarantee is a property of behaviour, not of cryptography

MASTER §8.1 promises that after the timer *"retained server ciphertext, a seized device, a newly
provisioned device, and a seedphrase holder all fail to decrypt"*, and calls it *"the most easily broken
property here."* All three M1-1 options put `eph_root[n]` in the **device wrap** — the sizing arithmetic
proves it. The device wrap is `PERMANENT` and prunable **never** (`spec-b:907`). And the key it is
encapsulated to never rotates: `ProposeUpdate`'s own header (`connect/mls/group.go:1613`) states that
*"The device wrap key is read off the leaf being REPLACED and re-encoded, so an update publishes the same
urmessage_leaf_keys the group already wraps to."*

So one device X-Wing key, obtained once at any point in a device's life, opens every retained device wrap
for every epoch, hence every `K_eph[n][b][t]` that ever existed. The promise holds only while every party
that ever held an EPH ciphertext actually deleted it. Option 1's failure list names the tension and offers
the fix — split the device wrap into a `PERMANENT` record carrying `pq_secret` and an `EPH(5)` record
carrying `eph_root` — and leaves it **unchosen**. It cannot be deferred past this ruling, because it
doubles the device-wrap count and therefore changes `expected_wrap_count`'s shape.

---

## Part 3 — the surviving options, and the attacks that killed the rest

### M1-1 Option 1 — the MLS-exporter envelope — KILLED for two of the three record shapes; survives for the device wrap

The construction: a second RFC 9420 §8.5 exporter label at the wrap's **own** epoch, `env_key[n] =
MLS-Exporter("URmessage/v1/envelope", "", 32)`, with the record ladder beneath it. It does not descend
from any `storage_root`, so it is genuinely not circular, and a member the commit **added** holds it the
moment `JoinFromWelcome` returns. That much is sound and was not broken.

**Attack 1 — fatal, the recovery wrap.** Option 1's own wire block puts `RecoveryTag` in the envelope
class. A seed-only restorer has no MLS state **by definition** — MASTER:818, stated for exactly this
record — so it cannot derive `env_key[n]`, cannot compute `key_body`, and cannot reach the `hybrid_ct`
it holds the X-Wing private half for. §5.4's *"documented last resort"* becomes a no-op for every group.
This is correction **E1** reintroduced one layer up, and **none of Option 1's nine stated failure modes
mentions it**; its "WHO CAN READ" paragraph silently assumes the reader is an MLS member.

**Attack 2 — fatal, the snapshot.** Option 1 lists the snapshot in the envelope class too. Correction
**E2** (`spec-a:1566`) already pins it under `K_snapshot[n]`, *"which the restorer can open precisely"*
(MASTER:833). Option 1 never says which key wins. Separately, the snapshot is a **blob-ref record with
no ct_body at all** (`spec-a:1673`), so "ct_body is an AEAD under key_body" is not a statement about it
in the first place.

**Attack 3 — unfiled by the proposal, and it falsifies its headline cost.** Option 1a's central claim is
*"connect/mls needs NO change at all"*, because `(*Group).Export` exists. Measured:
`connect/mls/group.go:821` reads `self.schedule` — the **current** epoch's schedule. There is no
`ExportAt`. `PastEpochWindow` is 32 (`errors_lifecycle.go:19-22`), `DeleteGroupStateBefore(epoch -
PastEpochWindow)` runs on every merged commit (`group.go:2587`), and `group.go:2488` calls that delete
*"A SECURITY REQUIREMENT AND NOT HOUSEKEEPING"*. So `env_key[k]` is computable **only while the group is
at epoch k**. A member walking 40 commits of catch-up and opening wraps afterwards — the natural
implementation, and the very path Option 1 claims as its best case — can never open any of those 40
wraps. The option imposes an unstated obligation on every client to call `Export` at every intermediate
epoch of every catch-up walk and cache the result forever.

**What survives, and it is real.** For the **device wrap at the live epoch**, `env_key[n+1]` is the only
outer key in the whole option set that **neither the message server nor a member removed by the commit
that opened the epoch** can derive. Those are two genuine properties no other option has.

### M1-1 Option 1b — extending the envelope to the commit and the marker — KILLED outright

1b's sole distinguishing benefit over 1a is the healing commit: a group whose fan-out died commits again
under `env_key[n+1]`, which every member holds.

**The attack is one line of the shipped server.** A commit carries `AttachmentEpoch`.
`exemptFromEpochComplete` (`memory.go:937-944`) exempts only `AttachmentWrap` and
`AttachmentEpochComplete`. A group whose fan-out died has `epochComplete == false` **by construction —
that is the definition of the failure being healed** — so the healing commit is refused
`REASON_EPOCH_INCOMPLETE`, every time. The only route to it is first landing an `EpochComplete` marker
that **lies** about the wrap count, i.e. requiring every honest client to execute finding B's attack.

And the alternative — exempting commits from the gate — is precisely the change `store/contract.go:2555`
was written to prevent. Its own comment: *"a hand-written switch with one positive test per member and no
test of its complement can be widened by one line — adding AttachmentEpoch lets a commit through the gate
and nothing says so."* 1b asks for exactly that line. The proposal cites `memory.go:939` by line number
for its recovery-wrap prerequisite and never runs the same function against its own escape hatch.

**1a is unaffected by this and should be ruled on its own merits.**

### M1-1 Option 2 — the backward seal under the closing epoch — KILLED twice, independently

**Attack 1 — the chain has no base case.** A seed-only restorer at epoch *n+1* needs `storage_root[n]` to
open the recovery wrap that delivers `storage_root[n+1]`. Induct down. The recursion bottoms out at
`storage_root[0]` — and by Option 2's **own** M1-2 text, `CreateGroupResponse.current_epoch` is always 1,
there is never an epoch-0 wrap set, and `storage_root[0]` *"after group creation exists on exactly one
device for the life of the group."* There is no sequence of fetches by which any restorer, in any group,
ever, reaches any class key. Option 2's stated reader set — *"Every member that was in the group at epoch
n"* — silently excludes the only party the recovery wrap exists for.

**Attack 2 — one dropped wrap is permanent ejection, not one lost epoch.** Option 2's failure-mode text
says a dropped wrap at epoch *k* *"BLOCKS every later epoch for the affected member"* and does not follow
it to the conclusion, because the repair window is bounded by two shipped behaviours the option does not
know about: `memory.go:578` refuses any record whose epoch is not the current one (`REASON_EPOCH_STALE` —
the wrap exemption is from the epoch-**complete** gate, never the epoch-**equality** gate), and
`memory.go:691-696` NULLs the superseded epoch's write key on advance. So the victim's repair window
closes at the next commit and the key needed to MAC the replacement is gone sixty seconds later. The
victim is a full MLS member every other member believes is present, permanently unable to read, write or
fetch, with no signal to anyone.

**One correction in Option 2's favour, recorded because a rejected option should be rejected for true
reasons.** Its headline cost — *"N SEQUENTIAL, DEPENDENT WrapFetch round trips"* — is **overstated**.
Every `wrap_target_handle` is locally computable from `group_handle_key` at every epoch (`spec-a:1641`),
so all N fetches can be issued concurrently and only the **decryption** is serial. The latency argument
against Option 2 is weaker than every write-up states. It does not save the option; the two attacks above
are structural.

### M1-1 Option 3 — the X-Wing ciphertext is the seal — KILLED as written; repairable, but the repair does not buy what the option claims

**Attack 1 — kills it as written.** The premise is a zero-length `ct_head`, and the option calls this
load-bearing: *"the only way this option's premise holds end to end."* Measured: refused at
`api/submit.go:301`, refused again at `store/memory.go:979`, the column is `NOT NULL`
(`migrations.go:160`), and `store/contract.go:145`'s `ARecordWithNoHeadAtAll` asserts the refusal against
**both** stores with the reason written out — §6.3's idempotency probe would hash the empty string into
every headless record's claim. **Every wrap of every kind is rejected.** The option's cost line — *"no SQL
change, no proto change, no server change beyond the shared recovery-wrap exemption"* — is false, and its
supporting citation (*"codec.go accepts it"*) is about `connect`'s codec, which is not the party that
refuses it.

**The repair is one line and costs the option nothing**: give the wrap a real head, keyed
`HKDF-Expand(wrap_key, "wraphead/v1", 56)`. `wrap_key` comes from decapsulation, so it is not circular,
and it preserves the option's actual property — that the only key opening a wrap is the target's own.

**Attack 2 — survives the repair, and this is the decisive one.** A malicious message server holds
`write_key[n+1]` in the clear from the commit attachment — `connect/message/attachment.go:155-157` says
so outright, *"The server holds it and can therefore forge write_auth, which spec B section 5.3 states as
an accepted consequence rather than a defect"* — and it holds the target's device X-Wing public key, from
the key-package store **it operates** under ledger 69. So it encapsulates, derives `wrap_key`, seals head
and body, and hands the target an attacker-chosen `pq_secret` and `eph_root` with **no cryptographic
failure anywhere in the pipeline**. Under Options 1 and 2 the same forgery is blocked by `env_key[n+1]`
or `K_perm[n]`, neither of which the server holds. MASTER §9.2's stated mitigation for server injection —
*"any record it injects fails MLS verification at every client (I5)"* — **has no referent for a wrap**.

That acceptance in Spec B §5.3 was made when every record body was independently sealed under a key the
server does not hold. Option 3 removes that premise for the one record kind whose integrity decides
whether a member keeps its group.

**Attack 3 — unnamed anywhere.** Option 3 branches on attachment kind to decide whether `ct_body` is an
AEAD output. The **snapshot** carries a `WrapTag` and has no `ct_body` at all. The branch misfires on it.

**What survives, and it is also real.** Option 3 is the **only** rule whose opener key every recovery path
can actually produce, including the seed-only one. It consumes no ratchet position and needs no
`sender_handle` to `leaf_index` inversion and no stream-index-to-ratchet-position mapping for 1,501
records per commit. It has the widest repair set. And a dropped wrap costs one epoch, not the group.

---

### M1-2 Option 1 — GroupInfo extension 0xF004 carrying group_handle_key — CONTENTS killed; the MECHANISM survives

**Attack 1 — the filed cost, and it is correctly filed.** Placing a **group-lifetime, never-rotated**
value inside `encrypted_group_info` protects it with X25519 alone. One retained Welcome plus a future
CRQC inverts every `sender_handle` and every `wrap_target_handle` the group ever wrote, in both
directions, permanently — the exact unlinkability MASTER §8:764-766 says the key exists to provide,
against MASTER:584's own premise. MASTER:760 fixes the key at creation, so no rotation recovers it.

**Attack 2 — unfiled, live today, no quantum computer required, and strictly worse.** Ledger 69 puts the
key-package store on the message server with *"the handle derived from the identity KEY"*. **Nothing in
that ruling requires the committer to verify that a package served under an identity-derived handle
carries that identity's signature key**, and nothing in `msgrepo` checks anything about a served package
— `grep -rn 'KeyPackage|key_package' msgrepo --include=*.go` returns **zero**. So a hostile store answers
a lookup for Bob with a package whose `init_key` is its own, opens the resulting Welcome under its own
key, and reads `0xF004`. `connect/mls/welcome.go`'s own header concedes the symmetry: *"anybody at all
holding that key package can build a Welcome addressed to it"* — and whoever supplied the package can
open one.

**Attack 3 — by the option's own admission.** The `K_wrap[n] = HKDF-Expand(group_handle_key,
"wraprec/v1" ‖ u64(epoch), 32)` ruling this option requires makes a restorer unable to open its own
recovery wrap, *"strictly worse than the status quo"* in its own words. Under a key-separation lens it is
worse still: it gives a never-rotating **public-index** key a second, secret, **confidentiality** role
whose reader set is *everyone who has ever been a member* — a set that only grows and can never shrink.

**What survives.** `0xF004` in `GroupInfo.Extensions` is the only authenticated, joiner-encrypted slot in
the v1 profile, and its cost is measured: `Extensions` is left nil at **all four** construction sites
(`connect/mls/group.go:643, 2238, 2860, 4137` — each sets `GroupContext`, `ConfirmationTag` and `Signer`
and nothing else), `CommitOptions` exports only `Force` and `ExtraProposals` (`commit.go:49-77`), `Group`
retains no `GroupInfo` so `JoinFromWelcome` cannot hand one back, and a `groupExtensionProfile` row is
required or the derived registry test fails. Four changes, two to exported surface.

### M1-2 Option 2 — re-root group_handle_key into the wrap — CARRIER survives and is the best in the set; the RE-ROOTING is contested and the evidence does not settle it

**The carrier half is the strongest result in the M1-2 set.** Carrying only `read_key[join_epoch]` and
the joiner's **own** `wrap_target_handle` discloses **nothing the server does not already hold**:
`read_key` arrives in the clear in every commit (`attachment.go:160-163`) and `wrap_target_handle` is a
server-indexed projection (`message.proto:243`). Under that content, both attacks that kill Option 1's
contents — the harvest and the key-package substitution — yield **zero**. That property is unique to it.

**The re-rooting half is where the lenses split, and each is right about something different.**

- *For:* it is the only closure that fixes seed-only restore — a hole nobody had filed. A restorer gets
  `storage_root[n]` from its recovery wrap and **still cannot compute `sender_handle` or reach the epoch
  snapshot**, because both need `group_handle_key`, which needs `storage_root[0]`. §5.4 today restores
  read access and nothing else, permanently. Only this option changes that.
- *Against:* it converts a one-shot, join-time, committer-only substitution into a **per-epoch,
  any-member, any-target** identity flip, and it deletes the derivation, so there is **no correct value
  to recompute from**. A founder-chosen 32-byte CSPRNG draw is a value **no member can ever audit, in
  principle rather than in practice** — a backdoored founder can hand a colluding server a key it inverts
  from creation onward, forever, with no key compromise and no quantum computer.

Both readings are correct. **The evidence does not choose between them** — see Part 5 item 1.

Two costs on top, both real: it moves ~1.1 KB per wrap into `server_attachment`, which is hashed into
`AAD_head` and the `write_auth` preimage, making the wrap plane's largest field the one the server parses
before authentication; and it is a **flag day** whose window closes the moment the first real group
exists.

### M1-2 Option 3 — the X-Wing sidecar — KILLED as a PRODUCTION carrier; its CP3b form is fine and already blessed

**The attack.** The sidecar carries **no authenticator**. Encapsulation targets a public key from a store
the message server operates, and its AAD binds the hash of `encrypted_group_info` — a hash of transmitted
bytes, computable by any party that relays or stores the Welcome. So the store operator builds its own
sidecar to the joiner's real public key carrying a `group_handle_key` **it chose**, defeating the key's
sole documented purpose for every new member. The option's load-bearing sentence — *"the AAD binding
proves 'whoever built this Welcome built this sidecar'"* — is false, and the RFC 9420 analogy it rests on
is false with it: RFC 9420's `GroupSecrets` binding works because the joiner then verifies
`confirmation_tag` against the derived key schedule, and the sidecar has no key-schedule anchor for its
contents.

Worse, its headline safety property — that a wrong `pq_secret` fails *"LOUD, IMMEDIATE, AT THE SERVER, AND
TYPED"* against the server's own installed `write_key[n]` — **names the adversary as the detector**. A
design whose safety check is performed by the party it is defending against is not weak; it is not a
check.

**It is salvageable exactly as its own text offers and does not take**: an Ed25519 signature over the
sidecar under the committer's `identity` key, verified by the joiner in the RECOVERY_PUB pattern (MASTER
§5.3). With that signature it is arguably the **strongest** M1-2 answer, because it is the only carrier
that keeps the join inside X-Wing and the only one indifferent to M1-1's ruling.

**Its CP3b form is a different thing and must be named as different.** Ledger item 44a already blesses
*"a named, gated test-only hand-off — of a public KeyPackage and a Welcome already sealed to the joiner's
init key — under the same absent-not-placeholder rule that made CP3a's key source safe."* That channel
does not cross the message server, so none of the above applies to it. The option is written so the CP3b
shape and the production shape are the same construction on a different channel; **the ruling must say
they are not the same ruling.**

---

## Part 4 — the recommendation, and what it costs

### M1-1: three record kinds, three rules, and one signature that is not optional

**(1) Device wrap — Option 1a's envelope.** `env_key[n+1] = MLS-Exporter("URmessage/v1/envelope", "",
32)` at the wrap's own epoch, with the record ladder beneath it. Chosen for the one property nothing else
has: it is the only outer key the **message server** cannot derive and the only one a **member removed by
the commit that opened the epoch** cannot derive.

**(2) Recovery wrap — Option 3's rule, with Option 3's ct_head defect repaired.** `ct_body` is
`hybrid_ct` followed by zeros, with the tail zero-assertion as a **named typed refusal**, and `ct_head` a
real AEAD keyed `HKDF-Expand(wrap_key, "wraphead/v1", 56)` so the shipped server accepts it. No group key
of any epoch is consulted, because the intended reader holds none **by definition** (MASTER:818). This is
not a compromise between the two options: it is the only shape in which the recovery wrap means anything.

**(3) Epoch snapshot — unchanged.** Correction **E2** already rules it under `K_snapshot[n]`, and it is a
blob-ref record with no `ct_body`. The ruling should say **explicitly** that the snapshot is not in the
wrap-body class at all, because two of the three options quietly put it there and a reader of either would
conclude otherwise. Its `ct_head` is governed by **M1-6**, not by this ruling.

**(4) A signature over every wrap body under the publisher's identity key, verified before the wrap is
honoured.** This is not new policy — MASTER §5.3:441 already mandates it for the `RecoveryTag`, which
every recovery wrap carries — it is that rule applied where it already applies and extended to the device
wrap. 64 octets in 2,886 octets of existing slack. It is the highest-value item in this document: without
it, finding C stands under **every** option, the duplicate-wrap disambiguation rule (finding B) has
nothing to be written against, and *"record authenticity is MLS's"* is a sentence with no referent for the
one record class carrying no MLS frame.

**(5) Drop 1b.** Its only benefit is refused by the shipped server, and the change that would admit it is
the one a green derived contract test exists to prevent.

**(6) Rewrite §5.11 step 5 in all three documents** — `spec-a:1662`, `spec-b:2164`, MASTER:852. The
correct wording is *"derivable by any member that has already opened its own wrap for epoch n+1"*, and
the ruling must also say that a repairer publishes under its **own** `sender_handle` and stream index, so
openers must not assume the committer wrote every wrap.

#### Residual risk of this recommendation, stated plainly

1. **It is a target-type-dependent body encoding.** The device wrap and the recovery wrap are read
   differently, decided by the attachment kind. That is the defect class the 2026-08-26 kind-`0x0000`
   ruling was written against, one level up. It is confined to a distinction `wrap_aad`'s
   `u8(target_type)` already carries, but it **is** the cost and should not be described as free.
2. **The device wrap still owes a normative stream-index-to-ratchet-position mapping**, and the failure
   mode of getting it wrong is not a decryption error. The record nonce is **derived from the record
   key** (`key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)`, MASTER §8.1), so
   key-nonce uniqueness is exactly `i` uniqueness — and a repeated pair under XChaCha20-Poly1305 leaks the
   Poly1305 one-time key, which is header **forgery**, not a plaintext XOR. Pin `i = stream_index` in
   every ladder, so the invariant follows from §5.12 step 6's existing "MUST NOT be reused" rule rather
   than from a second, unwritten discipline. Gaps are normatively legal (MASTER §8: *"The server enforces
   monotonicity, not contiguity"*), and one rate-limited submit mid-fan-out is the trigger.
3. **The env_key past-epoch problem is not solved, only bounded.** Attack 3 against Option 1 stands for
   the device wrap: a client must call `Export` at every intermediate epoch of a catch-up walk and cache
   the result, or lose that epoch's storage root permanently. **This is the strongest single argument for
   ruling Option 3 for the device wrap as well**, and Part 5 item 2 says what would decide it. It is
   stated here rather than buried, because the recommendation is not clean on this axis.
4. **The signature does not close findings B, D or E.** Those are server-side and are not m1's.
5. **The eph_root split (finding F) is left unchosen by this recommendation and must be ruled alongside
   it**, because it changes `expected_wrap_count`'s shape.

### M1-2: Option 1's mechanism, Option 2's carrier contents, and group_handle_key deliberately not ruled here

**Carrier:** extension `0xF004` in `GroupInfo.Extensions`, carrying `u16 version`, `u64 join_epoch`,
`opaque read_key<V>` (exactly 32) and `opaque wrap_target_handle<V>` (exactly 16) — Option 1's slot with
Option 2's contents. Nothing in it decrypts anything and nothing in it is unknown to the server, so a
captured Welcome and a substituted key package both cost **zero**. Absent extension, wrong width, or an
all-zero value MUST be a **typed refusal**, named in the ruling, or Task 16's Property 3 and its
mutations pass vacuously and the natural implementation derives every handle in the group from a globally
known key.

**Where group_handle_key lives is not ruled here.** See Part 5 item 1.

**CP3b is not blocked by that deferral**, and this is the single most schedule-relevant fact in this
document. Ledger 44a already blesses a gated, test-only hand-off of a public `KeyPackage` and a sealed
`Welcome` for the CP3b path. Extending that same hand-off to carry `group_handle_key` — under the same
absent-not-placeholder rule — closes Task 16 for CP3b **without ruling the production carrier**, and
without putting a group-lifetime secret anywhere it would live in production. The ruling must state that
the CP3b hand-off is **not** the production carrier, in the hand-off's own doc comment, or the next reader
will find one construction and assume it is both.

#### Residual risk

- The joiner cannot validate the **value** of `group_handle_key` under any carrier, ever. The only
  available check is behavioural: compute an existing member's `sender_handle` from the delivered key and
  confirm it matches a record already fetched. **That must be written into the ruling as a requirement**,
  not left as an implementation note.
- Deferring the production carrier means the group-lifetime key's real home is decided later, when the
  first real group may already exist. Option 2's flag-day window is exactly what this deferral spends.
  That is a genuine cost of the deferral and it argues for ruling Part 5 item 1 **soon**, even though it
  cannot be ruled from this document.

---

## Part 5 — what cannot be decided yet, and what would decide it

### 1. Where group_handle_key lives — the owner must pick, and this document cannot pick for them

Three shapes, each with a cost the evidence weighs but does not rank:

| Shape | What it costs |
|---|---|
| In the Welcome (`0xF004`) | Forfeits the PQ property of a group-lifetime value **permanently and retroactively**; and is live-attackable today via key-package substitution, no CRQC needed |
| In every device and recovery wrap (M1-2 Opt 2) | Per-epoch, any-member, any-target identity flip; deletes the derivation, so the value becomes **unauditable in principle**; flag day |
| In a signed sidecar (M1-2 Opt 3 plus the signature) | Needs the identity signature it offers and does not take, **and** a concrete channel ruling that ledger 69 has not yet made |

**What would decide it, and none of it exists yet:**

- **(a) Whether the key-package store authenticates a served package against the claimed identity's
  signature key.** Ledger 69 requires the handle be derived from the identity key and says nothing about
  verifying the package. Measured: `grep -rn 'KeyPackage|key_package' msgrepo --include=*.go` returns
  **zero** — nothing is implemented, so this is a spec question, not a code one. **If the answer is "it
  does not", the Welcome carrier is dead for a reason that has nothing to do with quantum computers**,
  and the choice narrows to two. This is the cheapest determination available and should be made first.
- **(b) Whether a first-write cross-check is actually implementable.** It requires the joiner to observe a
  handle it can **independently attribute** to a known leaf. Nobody has shown it can. If it cannot, then
  no carrier validates the value and the ranking must be made on blast radius alone.
- **(c) Whether the founder-chosen CSPRNG variant can be given any audit path at all.** If it can, the
  strongest objection to Option 2's re-rooting falls and it is probably the answer, because it is also the
  only fix for seed-only restore. If it cannot, that is a permanent, unauditable trust concentration in
  the founder and should be ruled as such rather than discovered later.

### 2. Whether the device wrap rides the envelope or the KEM

The recommendation says envelope. It is not a settled call, and the deciding fact is **measurable and has
not been measured**:

A provisioned live device holds the master key (§5.4's provisioning bundle) and therefore `recovery_root`
and the recovery X-Wing private key. **If that is true, a live device with a missing or corrupt device
wrap at epoch k can open its own RECOVERY wrap at epoch k and obtain `storage_root[k]` outright**,
skipping `pq_secret[k]` entirely — under the recommendation, with no MLS state needed at all. If so:

- the device wrap's only irreplaceable payload is `eph_root[k]`;
- residual risk 3 above shrinks from "lose that epoch's storage root permanently" to "lose that epoch's
  ephemeral messages";
- and finding F's split becomes considerably more attractive, because it separates the replaceable
  payload from the irreplaceable one.

**What to build or determine:** confirm from §5.4's provisioning-bundle contents whether a linked device
actually receives the master key, then state the recovery-wrap-as-fallback path normatively or refute it.
Nothing in the corpus states it either way today, and every option write-up missed it. This one
determination changes the M1-1 device-wrap answer, the size of residual risk 3, and the case for the
`eph_root` split — three things at once, for the cost of reading one section and writing one sentence.

### 3. The eph_root split (finding F)

Splitting the device wrap into a `PERMANENT` record carrying `pq_secret` and an `EPH(5)` record carrying
`eph_root` is the only construction offered anywhere that makes MASTER §8.1's promise cryptographic rather
than behavioural. It doubles the device-wrap count — 2,000 rather than 1,000 at the design target — and
changes `expected_wrap_count`'s shape, so it interacts with item 4 and cannot be ruled independently of
it. **It is a sizing decision the owner owns**; the cryptographic case for it is unambiguous and the cost
case is not.

### 4. The server-side items, none of which is m1's to rule

Findings B, D and E are Spec B changes. They should be filed as ledger open items rather than resolved
here:

- **Count landed wraps** at distinct handles before honouring an `EpochComplete` marker, and bound
  `expected_wrap_count` against the epoch's own tree. Today `memory.go:722` checks a number against itself
  and `memory.go:962` bounds it only at non-zero.
- **A uniqueness constraint on (group_id, epoch, wrap_target_handle)**, plus a disambiguation rule for
  what a client does with two wraps at one handle. With the recommendation's signature the rule writes
  itself — *the one signed by a member of the epoch's tree*; without it there is no rule to write.
- **The marker's authority.** Anyone holding `write_key` can close a fan-out with one record.
- **The repair window.** The wrap exemption covers the epoch-**complete** gate and not the
  epoch-**equality** gate, so the wrap plane has a one-epoch repair window that shuts at the next commit.
  Option 1's own proposed repair for the omission attack is refused by it. Widening it lets a holder of a
  retained key write into closed epochs, so it is a real trade and not an oversight to correct.
- **Whether removal revokes anything.** Finding D falsifies two published claims. Fixing it is a design
  change, not an edit.

### 5. How the recovery-wrap refusal (finding A) is fixed

Two answers and neither is obviously right:

- **Exempt `AttachmentRecovery`** from the epoch-complete gate — which reverses a green, derived, two-store
  contract assertion, and widens the set of records that can land while a group is not writable.
- **Resequence the fan-out** so recovery wraps are published after the marker — which makes
  `expected_wrap_count` decorative by construction, since the count would then name records that had not
  landed when it was checked.

This blocks every option equally and must be ruled before any of them means anything.

---

## What this document deliberately does not do

It does not rule M1-1 or M1-2. It does not resolve **M1-6**, which sits under every record the fan-out
writes and which the recommendation touches at exactly one point — the snapshot's `ct_head`. It does not
close **M1-22**: no option offered closes it, and finding E shows it is worse than filed and reachable by
a conforming client. And it does not rank the three homes for `group_handle_key`, because the
determination that would rank them (Part 5 item 1a) has not been made and is cheap to make.
