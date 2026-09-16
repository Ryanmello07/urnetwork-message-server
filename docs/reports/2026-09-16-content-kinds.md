# Content kinds: an encoding for every feature the owner asked for

**2026-09-16. A DESIGN WITH A RECOMMENDATION. NOTHING HERE IS RULED.** This is ledger item **198**,
*"the content KIND has no encoding"*. It answers the owner's list against MASTER §8.4, the two rulings
of 2026-09-15. The list is read / sent / delivered receipts, emoji reactions, GIFs, images, video,
reply, delete, edit, and *"anything else that makes a messenger great"*.

> ## ⚠ READ §11 FIRST — ERRATA, 2026-09-17
>
> `aad_mls` v2 landed **one commit after this document was audited** and closed two open items it
> leans on. **Three of §3's four reasons for where the kind lives are dead**, including the one §3
> calls decisive, and **§8 choice 5 is not a choice** — item 204 is closed and went the other way.
> **Do not build §3 as written; the placement is being re-ruled.**
>
> What survives unchanged: **§1's answer, and the whole budget.** The rungs re-measure at exactly
> 59 / 826 / 3898 / 16186 / 65334, so **no row of §4.2's registry table moves**. §11 lists every
> correction, including four to this document's own claims.

Audited against `connect` **d368fea** and `sdk` **cfe3ce4** (both `beta/message`, both read only),
and `msgrepo` **4b465ae** (`main`). Every claim carries one of three marks:

- **measured**: reproduced by running something, with the query beside it;
- **read**: established by reading source at a named line;
- **not reproduced**: a claim handed to this pass that did not survive checking.

---

## 1. The answer

**Every kind the owner asked for can be encoded under the measured constraints. None needs a wire
field, a `format_version` change or any server change. Three still cannot ship, and the encoding
is not what blocks any of them.**

| Asked for | Encoding (octets of application plaintext) | Rung | What stands between it and shipping |
|---|---|---|---|
| text | `1 + t` | 256 B while `t ≤ 58` | sdk work only |
| reply | `33 + t` | 256 B while `t ≤ 26` | sdk work only |
| reaction, any emoji | `33 + e` | 256 B while `e ≤ 26`: **3,748 of 3,944** Emoji 17.0 sequences (95.0%) | sdk work for a DURABLE conversation; D2 and D3 otherwise |
| delete for everyone | `33` | 256 B always | sdk work, plus the clock choice in §5.4 |
| delete for me | local only | none | the local store |
| sent state | local only | none | the local store |
| delivered receipt | `1 + 32n` | 256 B at `n = 1`; 1 KiB to `n = 25` | **D1 (M1-25, measured worse than filed) and D8 (no EPH(0) path exists)** |
| read receipt | `33` | 256 B always | **D1 and D8** |
| typing | `1` | 256 B always | **D1 and D8** |
| image / GIF / file that fits inline | descriptor, plus body up to about **65,270** octets | 1 KiB to 64 KiB | sdk has no MEDIA writer (0 hits); D3 |
| image / GIF / video / file above that | descriptor encodes; the bytes do not | 1 KiB and up | **the blob plane (not built) and D6** |
| thumbnail | an inline field of the descriptor | adds to the descriptor's rung | with attachments |
| edit | a reserved code, and nothing else | none | **ruled out of v1**; §5.10 is what makes it additive later |
| system entries | not a wire kind | none | synthesized locally from what MLS authenticates (§5.9) |

### The three that cannot ship

1. **Receipts and typing.** They encode in 33 and 1 octets. **No production path can seal one**
   (`InstallEphRoot` has zero non-test call sites) and **the server refuses one**
   (`msgrepo/api/submit.go:610`). **They are also not safe to ship until M1-25 is ruled, and M1-25 is
   worse than filed.** §2.3 has the measurements. Consider 1,025 transients between two stored
   records on one ladder. They do not destroy the next durable message: they destroy **every later
   one**. In the probe that was all 2,004 later records it offered, against 0 of 2,004 one transient
   short of the wall. **A receiver that was online and opened every transient refuses the same way:
   2 of 2 later records offered.** And M1-25's own "option A" no longer closes it after 2026-09-15.
   That option is *"a separate counter for transients: nothing server-side checks them, so nothing
   breaks"*. But a transient is now an MLS application message, so it consumes a generation of the
   same sender ratchet. A receiver that misses 1,025 of them refused all 3 later messages offered, at
   the MLS layer, with the record layer satisfied. `mls/secret_tree.go:875-880` says that refusal
   lasts until the epoch's next commit (read; no commit was driven).
2. **Media above the inline ceiling.** The descriptor encodes. The bytes need the blob plane, and a
   blob-ref record has no answer under MASTER §8.4.1. A `size_bucket = 5` record satisfies the
   application predicate (`is_commit == 0 && kind == NONE`), yet it has no `ct_body` to carry a
   frame in, and `OpenRecord` refuses it outright (`connect/messagegroup/seal.go:751`,
   `ErrBlobRecordUnsupported`).
3. **Editing.** It is ruled out in four documents. This design reserves its code and defines what a
   v1 receiver does on meeting one, which is the part that makes it additive. That discharges
   MASTER §2:479's *"type codes reserved so none is a format break"*. The feature audit §7(c) found
   that sentence safe by assertion only.

### Three claims handed to this pass that do not reproduce (nothing below is built on them)

- **"The reaction set is contradictory in the specs."** Not reproduced. Spec C revision 5
  (`spec-c:104`) reverses revision 3 (`spec-c:102`) in as many words. Owner decision 49
  (`docs/reviews/2026-08-12-owner-decisions-46-49.md:50`) is the ruling. MASTER §0:124, MASTER
  §12.2:2639, Spec A §7.4a and Spec C §5.2a all say any emoji. Details and the live residue are in
  §5.3.
- **"1,025 typing indicators permanently destroy the next durable message."** This reproduces, and
  it **understates**. Every later durable message is destroyed too, and an online receiver loses them
  as well (§2.3, S1 and S1b).
- **"`sdk/urmessage` routes every record through [`Protect`]: founding, wraps, markers, text."**
  True of `SealRecord`: all four call it (`group.go:514, :559, :573, :649`, read). **Not true of
  `Protect`.** Only the text record is framed. The founding record has `is_commit = 1`, and the wraps
  and the marker carry server attachments, so `isApplicationRecord` answers false for all three
  (`connect/messagegroup/mlsframe.go:161`, read).
  `TestWhichRecordsCarryAnInnerFrameIsMasterSection841sTable` → **PASS** (run).

---

## 2. The measured ground

### 2.1 The budget

**Rung capacity, application plaintext handed to `Protect`**. Measured:
`go test ./messagegroup/ -count=1 -v -run '^TestTheSizeLadderCostOfTheInnerFrameIsMeasuredHere$'`
at `connect` d368fea → **PASS**, logging:

| rung | `ct_body` octets | usable before 2026-09-15 | usable now | lost |
|---|---|---|---|---|
| 0: 256 B | 272 | 252 | **59** | 193 |
| 1: 1 KiB | 1,040 | 1,020 | **826** | 194 |
| 2: 4 KiB | 4,112 | 4,092 | **3,898** | 194 |
| 3: 16 KiB | 16,400 | 16,380 | **16,186** | 194 |
| 4: 64 KiB | 65,552 | 65,532 | **65,334** | 198 |

**The same boundaries through the whole seal path, not through `Protect` alone.** Measured with the
probe described in §2.3, at the `SealRecord` level on a real two-member group:

- A DURABLE body of 59 octets lands on `size_bucket 0`, and 60 lands on `size_bucket 1`.
- 826 lands on bucket 1 and 827 on bucket 2.
- 3,898 lands on 2 and 3,899 on 3.
- 16,186 lands on 3 and 16,187 on 4.
- 65,334 lands on 4, and 65,335 is refused: *"a record body is longer than the largest rung of the
  size ladder: 65533 octets plus a 4 octet length prefix"*.
- An `EPH(0)` body of 59 octets lands on bucket 0 and 60 on bucket 1.

**The opener returns exactly the octets sealed**, so a design's last variable-length field needs no
length prefix. Measured with the same probe: bodies of 0, 1, 33, 58, 59, 60, 826 and 827 octets, the
last octet of each set to `0x00` (the padder's own fill value). Each opened at the same length and
byte-identical.

### 2.2 The head is not the sender's

**Measured:**
`go test ./messagegroup/ -count=1 -v -run '^TestTheHeadPlaintextIsNotBoundByTheFrame$'` → **PASS**,
logging *"RESIDUAL OPEN (MG-6): a record another member built opened with head="A HEAD THE ATTACKER
CHOSE" body="the body the sender really wrote" at the true sender's own handle and stream index"*.
So a member can re-issue another member's genuine, signed body under a head of its own writing
(`connect/messagegroup/OPENITEMS.md` MG-6). Reachability depends on log ordering and **is not
established** (MG-6 says so itself).

**The head's length is also server-visible.** `ct_head` travels as `LP(ct_head)`
(`connect/message/codec.go:155`, read). Spec B §5.1 check 3 bounds it as *"`ct_head` ≤ head cap"*, a
cap and not a rung (`spec-b:2090`, read). A kind-dependent head length would therefore tell the
server which kind a record is.

**MG-4, also measured:**
`go test ./messagegroup/ -count=1 -run '^TestASessionCannotOpenItsOwnApplicationRecordAndThatIsMls$'`
→ **PASS**. A sender cannot open its own application record.

### 2.3 The windows a kind's retention class lands on

**The probe.** It is a scratch Go module outside all three repositories. It imports `connect` at
d368fea through a `replace` directive and uses exported API only. It rebuilds `messagegroup`'s
two-member fixture exactly as `newTwoEngineChainAtClock` does:

1. two engines over in-memory stores, each with a real signer, a real identity key and an X-Wing leaf
   key;
2. `CreateGroup`, then `NewKeyPackage`, `ProposeAdd`, `Commit`, `MergePendingCommit` and
   `JoinFromWelcome`;
3. `NewGroupSession` on both sides, with the epoch-zero `group_handle_key` and a reserver that
   allocates from 1, as the fixture's does;
4. `InstallEphRoot` on both sides.

Member A seals. Each record round-trips through `EncodeRecord`/`ParseRecord`, and member B opens it.
**It is not committed anywhere, and `git status` in `connect` was empty after every run.**

| # | Arrangement | n | Result |
|---|---|---|---|
| S1 | A: one DURABLE (B opens it), then `n` EPH(0) records B never receives, then DURABLE r1, r2, r3, then 2,000 more DURABLE and a final one, each offered to B | 1,024 | all 2,004 later records open; 0 refused |
| S1 | same | **1,025** | r1 at index 1027 refused: *"index 1027 is 1025 ahead of head 2, and the window is 1024"*. r2 and r3 refused, **2,000 of 2,000** of the next refused, and the final one at index 3,030 refused: *"3028 ahead of head 2"*. **2,004 of 2,004** |
| S1b | same as S1, but B is **online** and opens every transient on its own EPH(0) ladder | 1,024 | 1,024 transients opened; r1 and r2 open |
| S1b | same | **1,025** | 1,025 transients opened, 0 refused. **r1 and r2 refused**, with the same sentence as S1 |
| S2 | A: one DURABLE (B opens it), then `n` direct `GroupHandle.Protect` calls that reserve **no stream index**, which is what a separate transient counter does after MASTER §8.4. Then DURABLE r1, r2, r3 at indices 2, 3, 4 | 1,024 | all open |
| S2 | same | **1,025** | r1, r2 and r3 refused: *"an application record's inner MLS frame did not open: mls: ratchet generation too far ahead: generation 1026, head 1, bound 1024"* |
| S5 | five rounds of (1,000 EPH(0) records B never sees, then one stored DURABLE record B opens), then an ordinary DURABLE | none | 0 of the 5 stored records refused; the final record at index 5,007 **opens** |
| S5-mutant | the same, with round 3's stored record skipped | none | **2 of the remaining stored records refused**, and the final record at 5,006 refused: *"3002 ahead of head 2004"* |
| S3 | A: 1,030 DURABLE (B opens all), then one MEDIA record; B tracks the MEDIA ladder at head **0**, as `sdk/urmessage/group.go:1504` does | none | refused: *"index 1031 is 1031 ahead of head 0"* |
| S3-control | same, with B tracking MEDIA at head 1031 (the highest index B authenticated, plus 1) | none | opens |
| S4 | A: 1,030 DURABLE (B opens all), then one EPH(1) record; B tracks that window's ladder at head 0 | none | refused: *"index 1031 is 1031 ahead of head 0"* |
| S6 | A: one MEDIA, then `n` DURABLE (**B opens every one**), then a second MEDIA | 1,024 | the second MEDIA opens |
| S6 | same | **1,025** | the second MEDIA refused: *"1025 ahead of head 2"* |
| S6-retrack | the same B then re-tracks the MEDIA ladder at head 1027 (the highest index authenticated, plus 1) | none | the second MEDIA opens |

**Read beside it.** Four sources explain these results:

- The record-layer refusal is by distance, not by retained count (`ratchet.go:578`).
- `OpenRecord` peeks before it commits, so a refusal moves nothing (`seal.go:795`).
- The MLS refusal (`mls/secret_tree.go:562`) moves no head, by the declaration at
  `mls/secret_tree.go:857-887`: *"stays refused for every later generation that sender reaches in
  this epoch"*.
- That declaration says the arrangement *"is reached by a RESTORE and not by ordinary delivery"*.
  **A transient is ordinary delivery that is never stored**, so a member offline when it was pushed
  can never receive it. That premise fails for transients.

**Named tests, run.**

- `TestTransientsOnTheSharedCounterStarveADurableReceiverWindow` → **PASS**. It reserves indices
  directly against the reserver (`ratchetrepairs_test.go:464, :481`) and asserts only the first
  record after the wall.
- `TestAReceiverPastTheSkipBoundStaysWhereItIs` and
  `TestARestoredMemberIsDeafToAPeerThatMovedPastTheSkipBound` (`connect/mls`) → **PASS**.

**No `messagegroup` case observes the MLS half.** Query:
`grep -rn 'too far ahead\|ErrRatchetGenerationTooFarAhead' --include=*_test.go messagegroup` → **0**.

### 2.4 How long an emoji is

**Measured:**

- **Source:** `emoji-test.txt` from `https://unicode.org/Public/emoji/latest/` (`# Version: 17.0`,
  sha256 `1d8a944f88d7952f7ef7c5167fef3c67995bcae24543949710231b03a201acda`).
- **Filter:** `fully-qualified` rows only.
- **Length:** the UTF-8 octet length of each code point sequence.
- **Count:** 3,944 sequences.

| fits in ≤ | sequences | share |
|---|---|---|
| 8 octets | 2,327 | 59.0% |
| 17 | 3,405 | 86.3% |
| 18 | 3,420 | 86.7% |
| 22 | 3,458 | 87.7% |
| 25 | 3,513 | 89.1% |
| **26** | **3,748** | **95.0%** |
| 28 or 34 | 3,849 | 97.6% |
| 35 (the longest) | 3,944 | 100% |

The longest are the 95 two-person kiss and couple sequences with two skin tones, at 35 octets.
**These are counts of sequences, not of use.** No usage data was measured. Separately, and computed
rather than measured: 👍 is 4 octets, ❤️ is 6 and 👍🏽 is 8. Emoji 16.0 has 3,781 sequences under the
same query.

### 2.5 What exists to carry a kind today

| Query | Result |
|---|---|
| `grep -rn '\.InstallEphRoot(' --include=*.go connect sdk msgrepo \| grep -v _test.go` | **0** (positive control, test files only: 4) |
| `msgrepo/api/submit.go:610, :613` (read) | an EPH(0) transient and a `size_bucket 5` record are refused before the transaction |
| `grep -rn 'RetentionMedia\|MediaTtl' --include=*.go sdk/` | **0**, so no MEDIA writer exists |
| `sdk/urmessage/group.go:1341` (read) | every non-DURABLE record is skipped on receive |
| `sdk/urmessage/group.go:1504` (read) | every first-seen `(leaf, class, window)` ladder is tracked at head 0 |
| `connect/messagegroup/seal.go:751` (read) | `OpenRecord` refuses any `size_bucket 5` record |

---

## 3. Where the kind lives

**Recommendation: the kind is the first octet of the application plaintext handed to `Protect`.**
That puts it inside the sender's signature (MASTER §8.4.3, refusals R1 and R2) and inside the rung.

Four reasons put it there and not in `ct_head`. The first is measured and decides it alone.

1. **The head is not covered by the sender's signature** (§2.2, MG-6). A kind in the head could be
   rewritten by any member while the body stays genuine, and the rewrite would change what a signed
   body *means*. Alice's text could be relabelled as a tombstone, or her reaction as a text. The
   body would still be Alice's, and R1 and R2 would still pass.
2. **The head's length is server-visible** (§2.2). Unless every head were padded to one length, the
   kind would leak to the server by size, and padding the head spends octets the head does not
   budget today.
3. **Spec B §7.2 erases `ct_head` and `ct_body` together for `EPH(1..5)`.** A kind in the head
   therefore survives no longer than a kind in the body, for the one class where survival was the
   argument for the head (feature audit §5.1, option A).
4. **Item 204** already proposes moving `sent_at` *out* of the head for reason 1. Moving the kind
   *into* the head would take the opposite direction.

### 3.1 The head's version byte: used for what it was built for, not as the body's grammar

`sdk/urmessage/record.go:124-129` (read): *"It exists so that the day this package puts a second
field in the head -- a reply-to, a content type -- a record written by the older build is refused
with a sentence rather than parsed as something it is not."*

**Use it for exactly that.** The change that introduces kinds should bump the head from `0x01` to
`0x02`. Then an sdk at cfe3ce4, which casts every body to text (`group.go:1375`), refuses a kinded
record with `ErrHeadFormat` instead of rendering `0x05 ‖ <32 octets> ‖ 👍` as a text message.

**Do not use it to choose how the body is parsed.** The head is unbound (§2.2), so a member who can
rewrite it could make a genuine body parse under a different grammar. The rule this implies is
**K1** (§9): *the grammar a body is parsed under is a function only of octets inside the sender's
signature.* Two corollaries follow:

- **A kinded build keeps no raw-text parser for head `0x01`.** It refuses `0x01` rather than
  reading the body as text, so no body is interpretable under two grammars. **The cost:** any
  record an sdk at cfe3ce4 sealed under the new framing becomes unreadable to a kinded build.
  Records sealed before MASTER §8.4 carry no inner frame, so `OpenRecord` already refuses them at
  `peekInnerFrameSender` (`mlsframe.go:285`, read; not run against a pre-§8.4 record). There is no
  local store, and history is a re-fetch (feature audit §4.2), so nothing on a device holds a copy
  either. Whether any such record matters is the owner's decision.
- **There is no separate body version octet.** The kind code *is* the version of that kind's
  grammar. An incompatible change to a kind takes a new code, not a version bump. That costs nothing
  on the 59-octet rung, whereas a version octet costs one octet of every record.

---

## 4. The envelope

### 4.1 Encoding rules

1. `plaintext := u8 kind ‖ body(kind)`.
2. **Fixed-width fields are raw at their natural width. Variable-length fields are `LP(x)`, except
   the last variable-length field of a fixed layout, which is a tail running to the end of the
   plaintext.** The first half is owner decision 60's rule for `record_bytes`
   (`docs/reviews/2026-08-25-owner-decisions-59-63.md:14`), applied here to bodies. The tail is safe
   because the opener returns exactly the octets sealed (§2.1).
3. **A reference to another message is its raw 32-octet `message_id`** (MASTER §8.4.5), not
   `LP(message_id)`. The id is fixed-width, so rule 2 applies, and it saves 4 octets on the rung where
   4 octets matter.
4. **Every kind body has exactly one encoding.** A body is refused as malformed (Spec A §7.4's
   `"malformed"` gap) when:
   - it is too short for its layout;
   - it carries trailing octets after a layout with no tail;
   - its tail is empty where one is required;
   - its TLVs are out of order or repeated;
   - or its kind is `0x00`.
5. **`0x00` is reserved and refused**, mirroring `ContentTypeApplication`'s refusal of MLS's zero
   (`connect/mls/framing.go:55-63`). **`0xFF` is reserved as an escape**: a later ruling may define
   it as "a second octet extends the code". v1 treats it as an unknown kind.

### 4.2 The registry

**Code ranges.** A code's range fixes which retention classes it is legal on.

- `0x01`–`0x3F`: **stored** kinds. **Refused on `EPH(0)`.**
- `0x40`–`0x7F`: **transient** kinds. **Legal on `EPH(0)` only.**
- `0x80`–`0xFE`: reserved.

| Code | Kind | Body | Octets | Largest on the 256 B rung | Goes to 1 KiB at | `MessageEntry` effect (Spec A §7.4) |
|---|---|---|---|---|---|---|
| `0x01` | TEXT | `utf8 text` (tail, ≥ 1) | `1 + t` | `t = 58` | `t = 59` | new entry, `Kind "text"` |
| `0x02` | REPLY | `reply_to[32] ‖ utf8 text` (tail, ≥ 1) | `33 + t` | `t = 26` | `t = 27` | new entry, `Kind "text"`, `ReplyToId` |
| `0x03` | ATTACHMENT | TLV descriptor (§5.8) | 105 for the smallest blob descriptor (9-octet MIME); 34 + body inline (10-octet MIME) | never | always | new entry, `Kind "attachment"` |
| `0x04` | TOMBSTONE | `target[32]` | `33` | always | never | target becomes `Kind "tombstone"`; no entry of its own |
| `0x05` | REACTION_ADD | `target[32] ‖ emoji` (tail, 1..64) | `33 + e` | `e = 26` | `e = 27` | target's `Reactions`; `"reactions_changed"` |
| `0x06` | REACTION_REMOVE | `target[32] ‖ emoji` (tail, 1..64) | `33 + e` | `e = 26` | `e = 27` | same |
| `0x07` | COVER | empty | `1` | always | never | nothing: discarded, never receipted (§5.7) |
| `0x08` | *EDIT, reserved* | *not specified in v1* | none | none | none | a v1 receiver applies the unknown-kind rule (§4.3) |
| `0x09` | ATTACHMENT_BODY | `media octets` (tail) | `1 + m` | `m = 58` | `m = 59` | none; referenced by an ATTACHMENT (§5.8) |
| `0x40` | DELIVERED | `id[32] × n` (tail, `n ≥ 1`, length ≡ 0 mod 32) | `1 + 32n` | `n = 1` | `n = 2`; up to `n = 25` on 1 KiB, `121` on 4 KiB | target's `DeliveredTo`; `"delivered_changed"` |
| `0x41` | READ_THROUGH | `id[32]` | `33` | always | never | `ReadBy` up to that id in server order; `"read_changed"` |
| `0x42` | TYPING_START | empty | `1` | always | never | `TypingIds`; `"typing_changed"` |
| `0x43` | TYPING_STOP | empty | `1` | always | never | same |

The rung arithmetic is `59 − fixed octets`, against the measured 59 (§2.1). The code *values* are a
recommendation. The ranges, the rules in §4.1 and §4.3, and the byte layouts are the design.

### 4.3 A kind this build does not know

- **On a stored class:** the record keeps its position and its `message_id`. The walk continues:
  it is **not** a `fail()`, so it does not count toward `ErrRecordAbandoned`. It renders as one
  closed placeholder, and it is never parsed as any known kind. **Spec A has no value for this
  today.** `"malformed"` is wrong, because a future kind is not malformed. So a `Kind "unsupported"`
  or a `GapReason "unsupported"` is owed. That is a closed-set change to Spec A §7.4 and to Spec C
  §16.1 gate 8, and it is **owner choice 11** (§8).
- **On `EPH(0)`:** dropped silently. Nothing was persisted, so there is no history to be
  incomplete, and MASTER §12.2's never-persisted rule is served by dropping.
- **The range rule comes first, for known and unknown codes alike.** A `0x40`–`0x7F` code on a
  stored class is refused as `"malformed"`, because the sender broke a rule the code alone decides.
  A `0x01`–`0x3F` code on `EPH(0)` is dropped. Only a code on a class its range allows reaches the
  two rules above, and for `0x80`–`0xFE` the class alone decides.

**This rule is what makes editing, and every later kind, additive rather than a format break.**

---

## 5. Kind by kind

### 5.1 TEXT (`0x01`)

The UTF-8 is the tail. It must be valid UTF-8, and at least one octet. A text of 59 or more octets
goes to the 1 KiB rung, and MASTER §8.4.4 already prices that at 1,040 stored octets where it used to
be 272. Nothing about the kind changes that price: the kind octet costs one octet, which moves the
boundary from 59 to 58.

### 5.2 REPLY (`0x02`)

`reply_to` is the parent's `message_id`, and the reply renders by live lookup (Spec C §5.2a:415). The
quoted text never travels on the wire, which is also what Spec A §7.4's ephemeral-containment rule
requires for a reply to an ephemeral message (`spec-a:4269`). **A reply longer than 26 octets goes to
1 KiB.** A reply is a new message, so it takes the conversation's current class (§6). Its referent may
be gone, and the lookup then renders the parent as unavailable.

**A reply may not name a transient** (**K5**, §9; this is item 202's answer for this kind).

### 5.3 REACTION (`0x05`, `0x06`)

**The set: already ruled, and the contradiction does not reproduce.** Query:
`grep -n 'eight emoji\|closed at eight' docs/specs/2026-08-12-spec-c-windows-client-ui.md` → **one hit,
line 102**, which is revision 3's changelog row. Line 104, revision 5, reads *"**Reactions take any
emoji**: §5.2a replaces the eight-emoji table with the full picker"*. The owner's ruling is decision
49: *"Full emoji picker for reactions — NOT the eight fixed emoji. Owner overrode the
recommendation."* MASTER §0:124 and §12.2:2639, Spec A §7.4a:4215, and Spec C §5.2a:423 (*"There is
no approved list and no fallback list"*) all agree. **So nothing is recommended about the set. It
is decided.**

**What is live instead, and it is three things:**

1. **The superseded row is still readable, and a reader lands on it.** This pass's brief did, and so
   did the feature audit's (§7(d)). Whether to annotate superseded changelog rows is the owner's
   decision.
2. **The pinned Unicode version is still unnamed** (feature audit §5.5; M1-41 is the segmentation
   dependency). This pass measured against Emoji **17.0**, the version `latest/` served on this date.
   Naming it is **owner choice 4**.
3. **The byte cap against the rung.** Spec A's cap is 64 octets. The longest fully-qualified
   sequence in 17.0 is 35 octets, so the cap rejects no RGI emoji, and the rung is what decides cost.

**The layout, and why the op folds into the kind.** Spec A §5.1's
`REACTION { u8 op, LP(target_message_id), LP(emoji_utf8) }` has no discriminator. Its `op` tells
adding from removing, not a reaction from a text. Every layout below is measured against §2.4:

| Layout | Fixed octets | `e` that fits 256 B | Sequences that fit (of 3,944) |
|---|---|---|---|
| Spec A §5.1 verbatim, with no kind octet: **not viable**, because nothing tells a reader it is a reaction | 41 | 18 | 3,420 (86.7%) |
| Spec A §5.1 verbatim, behind a kind octet | 42 | 17 | 3,405 (86.3%) |
| kind, `op`, raw id, tail emoji | 34 | 25 | 3,513 (89.1%) |
| kind that folds `op`, raw id, `LP(emoji)` | 37 | 22 | 3,458 (87.7%) |
| **kind that folds `op`, raw id, tail emoji (recommended)** | **33** | **26** | **3,748 (95.0%)** |
| the recommended layout, plus `sent_at` in the body (item 204) | 41 | 18 | 3,420 (86.7%) |
| kind, then `sender_handle[16] ‖ u64 stream_index` in place of the id | 25 | 34 | 3,849 (97.6%) |

**The last row is noted and not recommended.** `(sender_handle, stream_index)` is `message_id`'s
preimage minus `group_id`. Every member can compute the id from it, and it saves 7 octets. But the
owner ruled `message_id` as *the* referent, and two referent spellings in one registry would be two
places for a builder to diverge.

**Validation stays exactly Spec A §7.4a**: valid UTF-8 of 1 to 64 octets, exactly one extended
grapheme cluster, checked on send and on receipt. The tail is the raw bytes the reactor picked. The
grouping key (NFC, with skin-tone modifiers and variation selectors removed) is computed by the
receiver and never sent. A REMOVE carries the raw form, and the receiver folds it to the key.

**Who may remove what.** A REMOVE cancels an ADD with the same `(reactor, target, grouping key)`, and
records are ordered by server order (`record_id`). What "the same reactor" means across one person's
devices is **D7**. Until an identity system exists, it is `sender_handle`, that is, the leaf.

### 5.4 TOMBSTONE (`0x04`), delete for everyone

**`target[32]`, 33 octets, always the 256 B rung.** Four receipt-side rules, each with a named
refusal:

- **T-a:** the target must be a stored content kind: TEXT, REPLY or ATTACHMENT. A tombstone naming a
  reaction, a tombstone, a COVER or an id nothing stored carries is ignored.
- **T-b, same sender (K6):** a tombstone applies only if its `sender_handle` equals the target's.
  This is what MASTER §12.1 *"A deletion cannot be forged"* needs beyond R1. Without it, R1 proves
  who wrote the tombstone and nothing proves they wrote the target. A tombstone whose target has not
  arrived is **held**, not dropped, because `message_id` is a keyed PRF and the target's sender
  cannot be read off the id.
- **T-c, the class rule (K7):** a tombstone takes **exactly the target's class**. If it were
  shorter-lived, a device fetching after the tombstone's prune would resurrect the target. If it were
  longer-lived, it would leave a residue past the target's timer.
- **T-d, the 24-hour window (ledger item 211):** MASTER §12.1:2564 and Spec A §7.4:4143. **No
  document says which clock measures it, and the choice is not cosmetic.** Every clock reading in a record is its sender's
  claim, so:
  - **(i) Measure it on sender claims** (the target's and the tombstone's `sent_at`). This is
    enforceable against third parties and honest-but-late senders. **It is not enforceable against
    the original sender**, who wrote both claims, and no design in which time is a sender claim can
    change that. Spec A §7.4's *"otherwise the bound would be a client-side courtesy that any modified
    client could ignore"* is therefore true of third parties and false of the original sender. That
    is worth one sentence in the spec.
  - **(ii) Measure it on the receiver's own first-stored time of the target.** The sender cannot move
    that clock. But devices diverge: one offline for three days applies a tombstone that an online
    device ignores.
  - **(iii) Measure it on the head's `sent_at`, as shipped.** Any member can move that (§2.2). So a
    third member who re-issues Alice's genuine body under a 25-hour-old head makes Alice's own
    tombstone be ignored, **if** MG-6 is reachable, which is not established.

  **Recommended: (i), with `sent_at` moved into the body (item 204), and the limit stated plainly.**
  That is **owner choice 6**.

**The alternative encoding, noted:** the tombstone names the sender's own `stream_index` (a u64, 9
octets). Same-leaf sender identity then holds **by construction**, with no check to mutate away. The
cost is that it cannot express a delete from another device of the same person (D7) without a new
kind. **The `message_id` form is recommended** because it survives the D7 ruling without a format
change. The check it depends on is named in §9 with its mutation.

**A tombstone of an attachment** deletes local bytes only. The server's copy is not erased, per Spec B
B6 (*"No client-initiated server-side erase in v1"*).

### 5.5 Receipts: DELIVERED (`0x40`) and READ_THROUGH (`0x41`)

**The policy is decided and is not reopened:** MASTER §12.2:2622-2637, Spec A §7.2's closed
preference keys (`spec-a:3300`), reciprocity for read receipts, and none for delivery receipts. What
this section adds is the body, and what a receipt may name.

- **DELIVERED** is `id[32] × n`. It names records **this device opened**, which is Spec A §7.4:4197's
  *"a statement by a device that actually decrypted"*.
- **READ_THROUGH** is one `id[32]`: *"read everything up to and including this message, in
  `record_id` order"*. That is `MarkRead(throughMessageId)` (`spec-a:4020`). One id covers any number
  of messages, so a read receipt is **always 33 octets and always the 256 B rung**. A receiver that
  does not yet hold that id holds the receipt.
- **What a receipt may name (K9):** TEXT, REPLY and ATTACHMENT, and nothing else. Never a reaction,
  a tombstone, a COVER or a transient.
- **Item 202's answer, recommended:** a transient's `message_id` **is never surfaced by the SDK**, and
  a call naming an id that is not a stored record in the local store is a call error that emits no
  record (**K5**). The derivation still defines an id for every record, as MASTER §8.4.5 says. The
  product simply never hands one out.
- **The receipt time** is the receiver's arrival time and costs no octets. A timestamp inside the
  receipt would be a claim by the emitter, and nothing needs one.

**Batching, the number MASTER §12.2 says "batched" about and never gives.** Here is what the batch
size `n` costs, computed from §2.1's capacities:

| DELIVERED batch `n` | Rung | `ct_body` octets per message receipted | Positions consumed per message received |
|---|---|---|---|
| 1 | 256 B | 272 | 1 |
| 25 | 1 KiB | 41.6 | 0.04 |
| 121 | 4 KiB | 34.0 | 0.008 |

The last column is the one D1 is about. **Before D1 is ruled:** a member who reads a busy group and
never sends a stored record crosses the S1b wall after 1,025 receipt records. At `n = 1` that is
1,025 received messages. At `n = 25` it is 25,625. **Batch size is therefore a data-loss parameter
until D1 is ruled**, not only a traffic-shape one. That is **owner choice 7**.

**A tension to name, not solve:** Spec A slice A6 lists COVER records as traffic cover. If a device
emits DELIVERED receipts for texts and never for COVERs, a server that correlates a fetch with the
receipt that follows learns which stored records were cover. Batching blurs the correlation, and
nothing removes it.

### 5.6 TYPING (`0x42`, `0x43`)

Both bodies are empty, one octet each, always the 256 B rung. There is no target and no timestamp.
Spec C §5.8:542 drops an id not re-listed within **10 seconds**, which places the repeat cadence under
10 s. **The cadence itself is unruled** (feature audit §5.6(d)). At a 5-second repeat, one minute of
composing consumes 12 stream positions and 12 MLS generations. **Nothing about typing is safe to
build before D1**, and the measurement in §2.3 is why.

### 5.7 COVER (`0x07`)

Spec A names COVER three times and specifies it nowhere: the `pad.go` and `reaction.go` rows of §2.2
(`spec-a:198, :222`) and slice A6 (`spec-a:5876`). **This gives it a body: the kind octet and nothing
else.** The rung hides the length, so a one-octet COVER is indistinguishable by size from a 59-octet
text. Receivers discard it, emit no receipt for it (K9) and create no entry.

**It is also the anchor D1's recommended option uses**: a stored record that re-anchors every
receiver's ladder and MLS head. S5 measures that the shape holds, and that skipping one anchor fails.

### 5.8 ATTACHMENT (`0x03`) and ATTACHMENT_BODY (`0x09`)

**A descriptor is a TLV list.** Each field is `u8 tag ‖ LP(value)`, with tags strictly ascending and
none repeated. **A tag with its high bit set is critical**: a build that does not know a critical tag
renders the whole record under §4.3. An unknown tag without that bit is ignored. The five octets per
field are a deliberate cost, because a descriptor never fits the 256 B rung anyway.

| Tag | Field | Value | Required |
|---|---|---|---|
| `0x01` | FILENAME | UTF-8, ≤ 255 octets | no |
| `0x02` | DIMENSIONS | `u32 width ‖ u32 height`, pixels | no (images, video) |
| `0x03` | DURATION | `u64` milliseconds | no (video, audio) |
| `0x04` | CAPTION | UTF-8 | no |
| `0x05` | REPLY_TO | `[32]` | no |
| `0x06` | THUMBNAIL | image octets (format is owner choice 9) | no |
| `0x07` | PLAYBACK | `u8`: bit 0 loop, bit 1 autoplay muted, others zero | no (GIF-like video) |
| `0x81` | MIME | UTF-8, ≤ 255 octets, from Spec A §5.13's content sniff | **yes** |
| `0x82` | SIZE | `u64`, plaintext octets | **yes** |
| `0x83` | INLINE | the media octets | exactly one of `0x83`, `0x84`, `0x85` |
| `0x84` | BODY_REF | `u64 stream_index` of this sender's own ATTACHMENT_BODY record | exactly one of `0x83`, `0x84`, `0x85` |
| `0x85` | BLOB_REF | `u64 stream_index` of this sender's own `size_bucket 5` record ‖ `media_key[32]` ‖ `sha256(ciphertext)[32]` | exactly one of `0x83`, `0x84`, `0x85` |

**Worked sizes**, computed from the table and §2.1:

- **Inline JPEG** (`image/jpeg`, `IMG_0042.jpg`, size, dimensions): kind `1`, FILENAME `5 + 12`,
  DIMENSIONS `5 + 8`, MIME `5 + 10`, SIZE `5 + 8`, and INLINE's own `5` = **64 octets** of
  descriptor. That leaves **65,270** octets of image on the 64 KiB rung, or **65,287** without the
  filename. A split ATTACHMENT_BODY record carries up to **65,333**.
- **A blob descriptor for a video** (`video/mp4`, size, dimensions, duration, a 12-octet filename):
  `1 + 17 + 13 + 13 + 14 + 13 + 77` = **148 octets**, which is the 1 KiB rung. A thumbnail then has
  **673** octets on 1 KiB, **3,745** on 4 KiB and **16,033** on 16 KiB. **Thumbnail sizes were not
  measured**, so which rung a real poster frame needs is not established here.

**Inline or split: owner choice 9, and the recommendation is to split.**

- **One record (`INLINE`):** the simplest option, and it works on today's transport (§2.1). But
  MASTER §12.2:2586 puts attachments in `MEDIA` (one month) unless the parent is ephemeral. A single
  MEDIA record loses its filename and caption along with its bytes, so Spec A's
  `MessageAttachment.State "pruned"` cannot say *what* was pruned. Spec A §7.4:4176 argues that
  distinction is exactly what the state exists for.
- **Split (`BODY_REF`):** the descriptor sits in the conversation's class, and a separate
  ATTACHMENT_BODY record sits in MEDIA. The filename and caption survive the bytes. The body record is
  an application record, so it is signed (R1) and bound to its position (R2). A body at the sender's
  referenced index that the sender did not write does not open. **No digest is needed for this form.**
  The cost is one more record and one more position. And **D3 applies to the MEDIA ladder, measured**
  (S6): 1,025 other records between two photos lose the second photo.

**The blob form (`BLOB_REF`) is what media above about 65 KB needs, and it waits on two things.**
First, the blob plane (Spec B §8; not built; the server refuses `size_bucket 5` at
`submit.go:613`). Second, **D6**: under MASTER §8.4.1's predicate a `size_bucket 5` record is an
application record with no `ct_body`. Protecting the whole object as one MLS message would mean:

- no descriptor before download, which is the auto-download hold Spec A §7.4:4149 depends on;
- no `Range` read, which Spec B §8.3 supports;
- the whole file in one AEAD and one signature.

**Recommended, and a MASTER §8.4.1 change: a `size_bucket 5` record carries no MLS frame.** Its
integrity comes from the signed descriptor's `sha256(ciphertext)`, and its confidentiality from
`media_key`. Spec B §8.3's binding rules still match `content_hash` against `body_hash`. The
descriptor names the sender's own stream index, so a blob at another member's handle is inert: it
opens nothing and is referenced by nothing that verifies (**K11**). A random `media_key` needs no new
key-schedule label. A key derived from `record_key[k]` would save 32 octets and needs one: owner
choice 10.

**GIFs and video, which no spec considered** (feature audit §5.8):

- A GIF is `image/gif`, inline while it fits.
- Video is `video/*` with DURATION, DIMENSIONS and a THUMBNAIL poster frame, blob-borne above the
  inline ceiling.
- Whether a GIF is transcoded to `video/mp4` with `PLAYBACK = loop | autoplay-muted` is owner choice
  9. The tag exists so either answer encodes.

**Decoder exposure (K12).** Spec A §7.4:4149 holds attachment bodies from unknown senders to close
*"unsolicited-attachment decoder exposure"*. **An inline THUMBNAIL reopens exactly that** unless the
hold covers it: a client must not decode a thumbnail or an inline body whenever `AutoDownloadHeld`
would be true. Whether a held bubble then shows a file card, or a decoder-free placeholder, is owner
choice 9.

### 5.9 System entries and gaps: not wire kinds

- **`Kind "gap"`** is what the receiver synthesizes for a hole (Spec A §7.4:4167).
- **`Kind "system"`** entries come from sources MLS already authenticates: membership changes, key
  changes, timer changes (`GroupPolicyExtension.DisappearingBuckets` inside a processed commit). A
  wire SYSTEM kind would be a second, weaker source for facts the commit already carries, so **none
  is recommended.**
- **A group's name has no carrier at all** (feature audit §5.9). If the owner puts it in an
  application record, the `0x20`–`0x3F` range is where it would go, with the sender's role read from
  the group context of the sending epoch. A group-context extension is the alternative that comes
  with commit authentication.
- **Item 198(b) is not closable by a content kind, and it is named here so no one expects it to be.**
  The epoch-complete marker, wraps and fan-outs carry a server attachment. `isApplicationRecord` is
  therefore false for them, they carry no frame, and no kind octet exists inside them to bind. That
  question belongs to MG-5 and item 199.

### 5.10 Editing: reserved, and additive by §4.3

`0x08` is reserved. **No body is specified**, because editing is ruled out of v1: MASTER §2:479,
SPEC-LEDGER T8, Spec B, Spec C §15, and Spec A's `Edited bool // reserved; always false in v1`
(`spec-a:4074`). A v1 receiver meeting `0x08` on a stored class applies §4.3: a placeholder in
position, the original message untouched, and no "edited" state. A later ruling can define `0x08` as
`target[32] ‖ replacement` with the sender check of T-b. **Nothing a v1 build parses or stores
changes when it does.**

### 5.11 "Anything else", placed rather than designed

| Feature | Where it would go | Note |
|---|---|---|
| mentions | a new stored kind, or a TLV of a rich-text kind, at about `16` octets per mentioned handle | not in any spec |
| link previews | an ATTACHMENT-shaped descriptor, fetched by the **sender** | absent from the corpus entirely (feature audit §9); *who fetches* is a privacy ruling |
| voice notes | ATTACHMENT, `audio/*`, DURATION | *voice calling* is excluded (MASTER §2); voice *files* were never considered |
| stickers | ATTACHMENT, inline image | none |
| sharing a contact card | a stored kind carrying Spec A §5.14's 131-octet card, 132 octets, 1 KiB rung | none |
| location, polls, view-once | new stored kinds under §4.3 | none designed; view-once cannot be enforced against a recipient (MASTER §2's non-goals) |
| forwarding, starring, pinning, editing, history export | ruled **out** of v1 by Spec C §15 | not placed |

---

## 6. Retention class per kind

| Kind | Class | Why |
|---|---|---|
| TEXT, REPLY, ATTACHMENT descriptor | the conversation's current content class at send | a new message |
| ATTACHMENT_BODY, or the `size_bucket 5` record | `MEDIA`, or the descriptor's `EPH` class | MASTER §12.2:2586 |
| REACTION_ADD | the **shorter-lived** of the target's class and the current class, under the group's applied policy | never outlives the thing it is about |
| REACTION_REMOVE | **exactly** the class of the ADD it cancels (**K8**) | if shorter, a later-fetching device resurrects the reaction |
| TOMBSTONE | **exactly** the target's class (**K7**) | §5.4, T-c |
| COVER | the ladder it anchors | D1 |
| DELIVERED, READ_THROUGH, TYPING_* | `EPH(0)` only (**K3**) | MASTER §12.2 |

**Any class other than the conversation's own content class puts a record on a different ladder, and
D2 and D3 then apply** (§7). For DURABLE-only conversations with inline attachments, every kind
above except the MEDIA body lands on one ladder. That is the configuration in which reactions,
replies and tombstones are safe to build first.

---

## 7. Dependencies the kinds cannot route around

**D1: M1-25, now in two halves, and measured. Filed as ledger item 208.** Blocks receipts, typing,
and COVER-as-anchor.

- **The record half:** S1 and S1b. 1,025 positions consumed between two records on one ladder
  lost every later record the probe offered on that ladder (2,004 of 2,004), and **an online
  receiver lost them too** (2 of 2 offered).
- **The MLS half, new since 2026-09-15:** S2. After 1,025 application messages a receiver never
  processed, every later message offered from that sender was refused (3 of 3).
  `mls/secret_tree.go:875-880` states the refusal lasts until the epoch's next commit (read). Transients are
  application messages under MASTER §8.4.1's predicate, which ignores the retention class
  (`mlsframe.go:161-163`, read).

The options, stated plainly:

- **(a) A budget with a stored COVER anchor. Recommended.** A sender emits a stored COVER on the
  conversation's ladder before it has consumed 1,024 positions since its last stored record on that
  ladder. **S5 measures it holding** for 5,000 transients, and failing when one anchor is skipped.
  The costs: one 272-octet stored record per anchor, and M1-25's first cost (one fsync per transient)
  unchanged. **It covers the MLS half only for receivers that process the anchor.** In a disappearing
  conversation, an offline member may never fetch an `EPH(1..5)` anchor before it is pruned. *That
  last sentence is derived from S2's mechanism and Spec B §7.2's pruning. It was not measured end to
  end.*
- **(b) A separate transient counter, and transients carry no MLS frame.** This closes both halves.
  The costs: any member can forge *"Alice read this"* and *"Alice is typing"*, and MASTER §8.4.1's
  table gains a row. And with a separate counter a transient and a stored record can share
  `(group_id, sender_handle, stream_index)`, so **they share a `message_id`**. That is only safe with
  K5 (transients never referenceable).
- **(c) A separate transient counter with the frame kept.** **This does not close it. Measured, S2.**
- **(d) Accept it.** Stored messages are lost to receipts and typing, at every receiver, for as long
  as the probe kept offering them (**measured, S1 and S1b**). Whether the loss outlives an epoch
  change was not measured.

**D2: a first-seen ladder is tracked at head 0. Ledger item 209, with D3.**
`sdk/urmessage/group.go:1504`, read. It is
unreachable today only because `group.go:1341` skips every non-DURABLE record. **Once any kind uses
MEDIA or an `EPH(1..5)` window, the first such record past the sender's index 1,024 is refused:
measured, S3 and S4.** An `EPH(1..5)` ladder is per window (`session.go:571`, read), so **every new
window is a first-seen ladder.** That makes this a disappearing-messages defect, not only a kinds
one.

**The change, reported and not made: `sdk` is Track A's.** `headIndex` must come from this device's
own authenticated state for that sender, never from 0 and never from a header. The candidate value
measured in S3-control (the highest index authenticated from that sender, plus 1) opens the record.
**It is not safe as written**, though. A record of the new class that arrives after a later record
of another class would land below the head. So the value is a ruling, not a one-line patch.

**D3: a stored-class ladder is starved by other classes.** S6: 1,025 DURABLE records between two
MEDIA records lose the second, **at a receiver that opened every one**. This is M1-25's shape without
a transient in it, and the concrete loss behind item 200's *"`1024/k`"*. **Re-tracking at
authenticated state heals the measured case (S6-retrack).** It also discards the ladder's retained
skipped keys, and whether that is acceptable is unruled.

**D4: MG-4.** A sender cannot open its own application records (§2.2). **Every kind a device sent**,
its own reactions, tombstones, receipts and texts, **comes from its local store or not at all.** A
device rebuilt from the server alone recovers none of them. This matters for the owner's live check
*"a device killed mid-conversation that rebuilt its history"*, which ran under the old framing.
**That check was not re-run here.**

**D5: MG-6 and item 204.** The head is unbound (§2.2), and `sent_at` lives in it. Moving `sent_at`
into the body costs **8 octets on every stored kind**: text to 50 on the 256 B rung, reply to 18, a
reaction's emoji to 18, which fits **3,420 of 3,944** sequences (86.7%). Tombstones and receipts
still fit. Transients need no timestamp. **Owner choice 5.**

**D6: the blob plane, and `size_bucket 5` under MASTER §8.4.1** (§5.8). Ledger item 210.

**D7: identity.** Deleting and un-reacting from another device of the same person needs a mapping
from leaf to person, and the sdk has no identity system (feature audit §2, not re-read here). v1 can
key both on `sender_handle` without a format change (§5.3, §5.4).

**D8: the `EPH(0)` path.** No production `InstallEphRoot` call site, the server refusing `EPH(0)`
(§2.5), and no Subscribe or push (feature audit §2). Receipts and typing cannot cross until all three
land.

---

## 8. The owner's choices, stated simply

Each line gives the recommendation first, then what it costs.

1. **Where the kind lives.** *In the first octet of the signed application plaintext.* Costs one
   octet per record. The head was rejected on the MG-6 measurement.
2. **A body version octet.** *None: the kind code is the version.* Bump the head byte to `0x02` so
   an old build refuses kinded records with a sentence. Costs nothing on the rung.
3. **How a message is referenced.** *The raw 32-octet `message_id`.* Costs 4 fewer octets than Spec
   A §5.1's `LP` form, which is itself an amendment to Spec A §5.1's REACTION block.
4. **Reactions.** The set is already ruled (any emoji). *Name the pinned version (measured against
   Emoji 17.0), and fold add and remove into the kind.* The reaction then stays on the 256 B rung for
   **95.0%** of sequences, against 86.3% for Spec A's layout behind a kind octet.
5. **`sent_at` into the body (item 204).** *Yes.* Costs 8 octets on every stored kind (D5).
6. **The tombstone.** *A `message_id` referent, a same-leaf check now, and the 24-hour window
   measured on sender claims, with its limit against the original sender stated in Spec A §7.4.*
7. **Delivery-receipt batch size.** *Whatever D1's ruling allows.* Before D1, it sets how many
   messages a silent member can read before losing its own next message (§5.5).
8. **M1-25 (D1).** *A budget with a stored COVER anchor.* Its alternatives and their measured
   failures are in §7.
9. **Attachments.** *Split the descriptor from the body. Thumbnails inline, and under the
   auto-download hold. Transcoding GIFs is your call.*
10. **Blob-ref records (D6).** *No MLS frame on `size_bucket 5`; integrity from the signed descriptor;
    a random `media_key`.* A MASTER §8.4.1 amendment.
11. **An unknown kind.** *A new closed value, `"unsupported"`*, in `Kind` or in `GapReason`. It
    touches Spec A §7.4 and Spec C gate 8.
12. **Item 202.** *Transients are never referenceable (K5).*
13. **Spec A's `Kind "reaction"`.** Under this design no record produces a *reaction entry*: Spec C
    renders a strip on the target. *Keep it only if a reaction is ever meant to render as a row.*

---

## 9. Properties, the refusal each owes, and what to mutation-test

**No test code is supplied.** Each property is satisfiable by a correct implementation and
falsifiable by an incorrect one. None presupposes an unruled sentence: where a property depends on a
choice in §8, it is stated so that every option satisfies or falsifies it on its own terms.

| ID | Property | Refusal owed | Mutation that must turn a named assertion red |
|---|---|---|---|
| **K1** | The grammar a body is parsed under is a function only of octets inside the sender's signature | none new | select the body grammar from the head's version byte. MG-6's substitution then changes how a genuine body is read |
| **K2** | Every kind body has one encoding | `"malformed"` on trailing octets, a short body, TLV disorder or repetition, or kind `0x00` | accept one trailing octet on a TOMBSTONE, so two encodings of one deletion both apply |
| **K3** | A stored kind is refused on `EPH(0)`; a transient kind is refused on every stored class | refuse the record | delete either half: a DELIVERED stored for a year, or a TEXT that is never stored |
| **K4** | An unknown kind on a stored class keeps its position and id, does not count toward `ErrRecordAbandoned`, and is never parsed as a known kind. On `EPH(0)` it is dropped | none: a placeholder | route an unknown kind through `fail()`, so three deliveries abandon the record |
| **K5** | No API surface returns a transient's `message_id`, and naming an id that is not a stored record is a call error that emits no record | call error | surface the id of a TYPING record, then REPLY to it |
| **K6** | A tombstone applies only when its `sender_handle` equals its target's | ignore | delete the comparison, so one member deletes another's message |
| **K7** | A tombstone's class equals its target's | refuse at send | seal it one class shorter, so a device fetching after the tombstone's prune shows the target |
| **K8** | A REACTION_REMOVE's class equals its ADD's | refuse at send | the same mutation, on the reaction |
| **K9** | A receipt names only stored TEXT, REPLY and ATTACHMENT records this device opened | refuse at send | emit a DELIVERED for a COVER |
| **K10** | Reaction validation holds on send and on receipt (Spec A §7.4a, unchanged) | `"malformed"` | validate on send only |
| **K11** | Attachment bytes render only through a descriptor that opened, whose referenced body sits at the same sender's position and, for a blob, matches `sha256(ciphertext)` | refuse the bytes | skip the digest comparison |
| **K12** | No thumbnail or inline body is decoded while `AutoDownloadHeld` would be true | none: a placeholder | decode the thumbnail before the hold check |
| **T1** | A sender's transients never make any of its stored records unopenable at a receiver that processes every stored record | none: this is a sender obligation | **measured red already**: S1, S1b and S2 falsify it today; S5 satisfies it; S5-mutant (one anchor skipped) is red |
| **T2** | A receiver opens the first record of a ladder it has not tracked, at any index within the window of the last record it authenticated from that sender | none | **measured red already**: S3 and S4 |
| **T3** | Stored records of other classes between two records of one class never lose the second | none | **measured red already**: S6 |
| **T4** | No two records a member can reference share a `message_id` | none | give transients their own counter without K5 |

---

## 10. What this cannot see, and what the clauses defend

- **The live deployment.** No access. Every live result the brief cites ran under the pre-§8.4
  framing, and none was re-run.
- **Usage frequencies.** §2.4 counts sequences, and nothing measured which emoji people use.
- **Thumbnail sizes.** They were not measured, so §5.8's rungs for a real poster frame are unknown.
- **Unicode segmentation (M1-41).** The one-cluster rule was not exercised.
- **The MLS half in disappearing conversations (D1).** Derived, not measured end to end.
- **Re-tracking (D3, S6-retrack).** One case healed. Whether it is safe was not examined: retained
  keys, out-of-order records, and the attacker's ability to influence an authenticated high-water
  mark.
- **Whether S1's loss outlives an epoch change.** The probe never committed a second epoch.
- **Identity (D7)** and **the `EPH(0)` delivery path (D8)** were placed, not audited.
- **Uncommitted `sdk` work.** During this pass `sdk` held uncommitted changes from Track A, its only
  writer: 19 paths, including `urmessage/group.go` (+292/−42 against cfe3ce4) and two new `cp3b`
  cases. **Every `sdk` line cited here was re-checked against the committed cfe3ce4 blob with
  `git show`, and matches.** Whether that work changes D2, D4 or the receive path's class skip is
  not known here, and none of it was read.
- **Nothing in any repository reads this document or the ledger items it files. That was measured,
  not assumed.** Every added clause (this file, the new ledger items, the item-198 note and the edit
  log entry) was removed from the tree. The removal wrote `git show HEAD:SPEC-LEDGER.md` into place
  and moved the report out; it did not use `git checkout`, so the index was never touched. `go test
  ./... -count=1 -timeout 900s -json` was then re-run in `msgrepo`. The results before and after are
  in the ledger entry. **They are identical, so these clauses defend nothing mechanically**, and they
  are named rather than implied. `api/checks_test.go:698`, `deps_test.go:1556` and
  `peer/checks_test.go:229` each read Spec B only. `planlint_test.go` reads `SPEC-LEDGER.md` only for
  items a plan cites (`:102`), and no plan cites 198 or 208–211. What would defend this design is
  code that does not exist yet: `connect/messagegroup/reaction.go` and `tombstone.go`, both named in
  Spec A §2.2 and absent from the tree, and the §9 cases beside them.

---

## 11. ERRATA, added 2026-09-17 after a five-agent re-survey of the tree

**This document was audited against `msgrepo 4b465ae`, `connect d368fea`, `sdk cfe3ce4`. All three
have moved.** `aad_mls` v2 landed one commit after the audit and closed two open items this document
leans on. Nothing below changes the document's §1 answer — every kind the owner asked for still
encodes, and the budget is unchanged — but **§3's stated reasoning no longer holds, and §8 choice 5
is not a choice.** Corrections are listed against the section that needs them.

### 11.1 The budget is CONFIRMED, and unchanged

Re-measured at `connect 4a70be8` by the tree's own bisection over real `Protect` calls
(`TestTheSizeLadderCostOfTheInnerFrameIsMeasuredHere`, PASS):

```
256 B rung -> 59 usable    1 KiB -> 826    4 KiB -> 3898    16 KiB -> 16186    64 KiB -> 65334
```

**Identical to §2.1. No row of §4.2's registry table changes.** TEXT `t = 58`, REPLY `t = 26`,
REACTION `e = 26`, TOMBSTONE always fits. The reason is structural rather than luck: v2 changed the
digest's **preimage**, not its **width**. `aadMls` returns `[32]byte` at v1 and v2 alike
(`connect/messagegroup/mlsframe.go:185`, `:206`), and only the aad's *length* enters the frame
(`const aadMlsBytes = sha256.Size`, `:115`).

### 11.2 §3's four reasons: three are dead

| | Reason | Status |
|---|---|---|
| 1 | "The head is not covered by the sender's signature" | **DEAD.** v2's fourth term binds the head. `mlsframe.go:166-169`: *"the complement is FIVE things. IT WAS SIX UNTIL 2026-09-17 and the sixth was the head plaintext, which v2's fourth term binds; open item MG-6 and ledger item 204 are CLOSED by that term."* |
| 2 | "The head's length is server-visible" | **DEAD, by live measurement.** `ct_head` is **25 octets on all 3,758 rows** of the production server's `message_record` table. It is already one fixed width and does not vary with content, so a further octet keeps it fixed-width and leaks nothing per-message. |
| 3 | "Spec B §7.2 erases `ct_head` and `ct_body` together" | **Alive**, but it is a *no-worse-than*, not a discriminator between head and body. |
| 4 | "Item 204 moves `sent_at` *out* of the head for reason 1" | **DEAD.** `SPEC-LEDGER.md:7915` records item 204 **CLOSED 2026-09-17 by `aad_mls` v2**, and the ledger states the repair this document recommends *"is NOT what was done"*. |

**§3's conclusion may still be correct — but not for the reasons printed there, and "The first is
measured and decides it alone" is false at HEAD.** The placement is being re-ruled on the current
tree. Until that ruling lands, **do not build §3 as written.**

The live stakes, which §3 could not have weighed because it believed reason 2: `ct_head` is **not**
rung-quantised and `ct_body` **is**, so a kind octet in the head would buy back one octet of the
59 — TEXT to 59, REPLY to 27, REACTION emoji to 27.

### 11.3 §2.2's measurement no longer reproduces

`TestTheHeadPlaintextIsNotBoundByTheFrame` **no longer exists** in `connect/messagegroup`; only a
comment at `mlsframe_test.go:1842` mentions it. Its inverse,
`TestASubstitutedHeadIsRefusedAndTheGenuineRecordStillOpens`, **PASSes and logs "MG-6 CLOSED"**.
Everything built on that measurement — §3's reason 1, K1's mutation, and D5 — needs re-deriving
rather than carrying forward.

### 11.4 §8 choice 5 is not an open choice, and its cost is not being paid

Choice 5 was *"move `sent_at` into the body: Yes"*, costed at **8 octets on every stored kind**
(text to 50, reply to 18, reaction emoji to 18, fitting 3,420 of 3,944 sequences). **Item 204 is
closed and went the other way.** That cost is not being paid by anyone. The 59-octet budget and the
95.0% emoji figure in §2.4 stand as printed.

### 11.5 §4.2's ATTACHMENT row is wrong in one cell

The `0x03` row prints "never" under *Largest on the 256 B rung*. That is right for the 105-octet
BLOB_REF descriptor, which is the only form §4.2 costed. It is **wrong for the split/BODY_REF
descriptor this document itself recommends**: its minimum is `1 + (5 + mime) + 13 + 13 = 32 + mime`,
i.e. **42 octets for `image/jpeg`**, which fits the 256 B rung for any MIME type of 27 octets or
fewer.

### 11.6 §5.5's quotation is not in Spec A

§5.5 attributes *"a statement by a device that actually decrypted"* to Spec A §7.4. **That string
appears nowhere in Spec A**, at the audited commit or at HEAD. The nearest real text is
`spec-a:4258` (HEAD), *"a statement by a device that decrypted the record, never an inference by the
server"*, and it sits in the `MessageEntry.State` closed-set block, not at the line cited. **The
substance is right; the quotation marks are not.**

### 11.7 Anchors: this document is accurate about the tree it read, and stale against the tree you
would build from

Every `file:line` in this document resolves at `4b465ae` / `d368fea` / `cfe3ce4` and **only** there.
Re-resolved at HEAD: `spec-a:4143` → **4214**, `:4074` → **4145**, `:4020` → **4091**, `:4269` →
**4340**; MASTER §2:479 → **539**; `connect .../seal.go:751` → **780**; `sdk .../group.go:1341` →
**1554**, `:1504` → **1953**. The "34 `urnet_message_*` exports" of §2.5 is **38** at `sdk eebd50c`
(it was exactly 34 at `cfe3ce4`, so the figure is stale, not wrong).

### 11.8 Two notes this document does not contain, recorded so a builder does not re-derive them

- **The framing overhead is a FOUR-step function, not three**: 193 for `0 ≤ P < 64`, 194 for
  `64 ≤ P < 16300`, 196 for `16300 ≤ P < 16384`, 198 for `P ≥ 16384`
  (`TestTheDerivedFramedLengthIsTheLengthTheSealEmits`, PASS). Two nested varints widen, not one:
  `varint(P)` at 64 and 16,384, and `varint(C)` where `C ≈ P + 82` at `P = 16,300`. **It moves no
  rung capacity** (16384−4−194 = 16186 and 65536−4−198 = 65334 either way); a three-step builder
  merely refuses legal bodies of 16,300..16,383 octets bound for the 64 KiB rung.
- **`S2-24` does not resolve.** The substance reproduces — own-message content **is** plaintext on
  disk, measured as a canary string at offset 111 of a 186-octet file — but the identifier collides:
  `SPEC-LEDGER.md:13423` is item S2-24 and is about a torn-tail repair in §8.2, unrelated. Cite
  `sdk/urmessage/statestore_durable.go:26-48` and the measurement, not S2-24.

### 11.9 A defect in Spec A found while checking this document, filed separately

**Spec A names a test that does not exist, in two places.** §2.3 (`spec-a:277`) says the forbidden
import edges are *"each asserted by a test in `connect/layering_test.go` and `sdk/layering_test.go`"*,
and the compliance table at `spec-a:5551` lists both files against "the forbidden import edges of
§2.3". **`sdk/layering_test.go` does not exist, and no test file in `sdk` mentions layering at all**
(`ls sdk/*layering*` → no such file; `grep -rln 'layering\|must not import' --include=*_test.go sdk/`
→ 0 files). The edges are therefore asserted from the **connect side only**
(`connect/layering_test.go:153-176`), and Spec A's compliance table claims coverage the tree does not
have. This is a specification defect, not a content-kinds one.
