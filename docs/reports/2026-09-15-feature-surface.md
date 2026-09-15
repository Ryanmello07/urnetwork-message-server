# Feature surface: can the protocol carry a messenger, and what can the Windows app be wired to?

**2026-09-15.** Written to answer one question the owner asked — *"Read, sent, delivered, emojis,
gifs, media images / videos and others… also edit and delete and reply, and anything else you can
think of. Verify the protocol can handle all of this then we start building on the actual windows
app demo."*

Audited against the tree at `connect` **27c50c2** (`beta/message`), `msgrepo` **6dd3464** (`main`),
`sdk` **fd44c73** (`beta/message`). Every number below carries the query that produced it. Claims
are marked **measured** (reproduced by running something), **read** (established by reading the
source at a named line), or **not reproduced** (a claim I was handed that did not survive checking).

I ruled nothing and filed nothing. Where two documents disagree I say so and leave it.

---

## 1. The honest answer

**The record layer can carry all of it, and none of it works.** Those are not in tension, and the
distinction is the whole report.

What is proven is a byte transport for opaque octets: a record is sealed, padded to one of five
rungs, authenticated in two preimages, ordered by the server without decryption, and pruned by
class. That layer is real and it is finished — I re-measured its ceiling rather than reading it
(`TestASealedRecordIsExactlyItsRungAndIsOneTheCodecAccepts` → PASS; the inline body ceiling is
**65,532 octets**, `connect/messagegroup/seal.go:770` `want := bodyLength + lpPrefixBytes` against
the 65,536 rung with a 4-octet u32 length prefix). So *"can the bytes cross"* is answered yes, and
the live 1,271-assertion run is a true result about that layer.

But **every feature the owner named is a statement *about* a message**, not a message. A reaction
says *"this emoji, on that message."* A delete says *"retract that message."* A reply says *"in
answer to that message."* A read receipt says *"I read that message."* An image says *"these bytes
are a PNG named cat.png."* Each of those needs two primitives, and **the system has neither**:

1. **A way for a body to say what it is.** There is no content envelope anywhere — not in the code,
   not in the specs. The send path seals `[]byte(text)` verbatim and the receive path casts it back
   with no branch. §3 below.
2. **A stable name for the message being referred to.** The specs call it `message_id`, use it as
   the referent for reactions, replies, tombstones, read-through cursors and every row key in the
   local store — and **never define it anywhere**. §5.2 below.

Both are unmade design decisions rather than unwritten code. Nothing cryptographic, no server
change, no protocol arm and no schema migration stands in the way of either. That is the good news
and it is also the bad news: they will not close by anyone writing code this week.

**What this means for the Windows app:** it can start today, but not on the content features, and
its *first* blocker is not the envelope. There is no C ABI, no DLL and no binding of any kind
between the Windows client and `sdk/urmessage` — §4 has the numbers. Build order in §6.

---

## 2. The table

`D` = designed, `W` = on the wire, `I` = implemented. A **yes** carries its evidence; a **no** says
what is missing.

| Feature | D | W | I | Blocked on |
|---|---|---|---|---|
| **Plain text send/receive** | yes — Spec A §7.1 `SendText` | yes — the record codec, `connect/message/codec.go:11-26`, 16 fields | **yes** — `sdk/urmessage/group.go:625` `Send(ctx, text)`, `:929` `Receive`; measured PASS | nothing. This is the one shipped feature |
| **Sent state** | yes — Spec A §7.4:4067, closed six-value set | n/a — a local state | **partial** — exists only as "`Send` returned no error". `Message` (group.go:58-75) has 5 fields, no `State` | the local entry store (§6 step 2) |
| **Delivered receipts** | yes, thoroughly — MASTER §12.2:2341, Spec A §7.4:4083 "a record, not a server signal" | **carrier only** — EPH(0) wire byte `0x10` (`connect/message/record.go:244`), `TransientPush` (message.proto:325). The *receipt* has no encoding | **no** — 0 hits, §7 | content envelope → M1-25 → eph_root wiring → server EPH(0) accept → Subscribe → SDK surface. Five steps |
| **Read receipts** | yes — same, plus reciprocity Spec A §7.2:3194 | same carrier, same absence | **no** — 0 hits | the same five steps |
| **Typing indicators** | yes — Spec C §5.8:528, MASTER §12.2 | same carrier | **no** — 0 hits | the same five, **plus open item M1-25**, a measured hazard rather than a to-do (§5.3) |
| **Emoji reactions** | yes, best-in-corpus — Spec A §5.1:1182 `REACTION { u8 op, LP(target_message_id), LP(emoji_utf8) }`, §7.4a validation, `Emoji`/`EmojiRaw` split | **no** — 0 hits for `Reaction` in `connect/protocol/` | **no** — `grep -rni 'emoji'` over all three repos → **0**; `connect/messagegroup/reaction.go` does not exist | content envelope; **`message_id`**; the pinned Unicode version (never named); M1-41 (Go has no UAX-29) |
| **Replies / quoting** | yes — `SendText(…replyToId…)` Spec A §7.1:3887, live-lookup render Spec C §5.2a:415 | **no** — `grep -rn 'reply_to\|ReplyToId'` → **0** | **no** — same 0 | content envelope; **`message_id`** |
| **Delete for me** | yes — Spec C §8.2:893, `DeleteLocal` | n/a, local only | **no** — 0 hits | the local entry store. There is no row to delete |
| **Delete for everyone** | yes, four docs agree — Spec A §7.4:4029, bounded 24 h, ignored on receipt outside it | **correctly none** — ruled: Spec B B6:46 "No client-initiated server-side erase in v1" | **no** — `grep -rn 'DeleteForEveryone\|DeleteLocal\|delete_window'` → **0**; `tombstone.go` does not exist | content envelope; **`message_id`**. **No server work at all** |
| **Editing** | **deliberately out of v1**, four docs — MASTER §2:448, Spec C §15, Spec A §7.1:3959 `Edited bool // reserved; always false in v1` | none, correctly | **no**, correctly — `grep -rn 'Edited\b'` → 0 | nothing. But see §7(c) on the undischarged "type codes reserved" claim |
| **Images / files (inline)** | partially — no content descriptor designed | **yes** — 5 rungs, ≤ 65,532 octets, measured | **transport yes, feature no** — PNG bytes cross byte-identical and render as text. `Send`'s parameter is `text string` | content envelope. MIME, filename and caption have nowhere to live |
| **Images / files (blob plane)** | yes, unusual detail — Spec A §5.13, Spec B §8.1-8.3 | **yes and complete** — `size_bucket 5`, `blob_id` in both preimages (`aad.go:268`, `writeauth.go:296`), presence enforced both ways (`codec.go:313-318`), `blob_grant` op 17, `BlobEndpoint`, 3 capabilities, 2 REASON codes | **no, on every side** — `"blob/v1"` → **0** Go hits; `BlobGrant` → **0**; `blobd/` is doc.go + one hash; client ladder excludes rung 5 (`seal.go:772`); server refuses with REASON_INTERNAL (**measured**) | the whole blob plane. **Not deferrable** — the epoch snapshot is a blob-ref record (§5.4) |
| **Video / GIF** | **no** — not designed anywhere | inherits blob | **no** | an owner decision. Spec C's bubble table has only "Inline image" and "File card" |
| **Thumbnails / previews** | **no** — Spec C renders 320×320 DIP from `MessageAttachment`, which has no thumbnail, width, height or duration field | — | **no** | an owner decision: second blob, inline field, or client decode |
| **Push / notify while closed** | yes, **ruled a GA gate** — MASTER §15 item 2:2536 | declared, unserved — `SubscribeRequest`(14), `RecordPush`, `TransientPush`, `MessageServerPush` all in message.proto | **no** — no Redis (`config.go:221`), no push path (`config.go:220`), 4 of 15 arms served | Redis; Subscribe handlers; and for a real wake, **an Azure AD registration with no named owner** |
| **Starting a conversation (cards / rendezvous)** | yes, to the byte — Spec A §5.14, 131-byte card, 5238-byte deposit, 5 preimages | declared, unserved — 5 arms (20-24), 2 tables named at `store/migrations.go:20` | **no, either side** | server work + **an identity system that does not exist** (`sdk/urmessage/device.go:279`) |
| **A group larger than two** | yes — Spec A §7.3, MASTER §11 | **no new wire needed** — the epoch ceremony is the same three records, and the server's epoch advance is **built and tested past epoch 2** (`store/contract.go:1481`) | **MLS half built** (`ProposeRemove`, 4 roles, 3 ValSems); **client orchestration absent** — `ErrAlphaOneAdd` refuses a second add by name; the fetch loop drops every commit (`group.go:1323`) | client orchestration in `sdk/urmessage` + one named connect gap, `GroupEngine.LoadGroup` (J1-8) |
| **A group having a name** | **no — undesigned** | none — `GroupPolicyExtension` is `{Roles, RetentionPolicy, DisappearingBuckets, ServerId}` | **no** | an owner decision. Naming has no carrier, so renaming is not the gap |
| **Local history / search** | yes — Spec A §8.1, 18 row classes; Spec C §15 puts local search **in v1** | n/a | **no** — `grep -rni sqlite --include=*.go` over all three repos → **1**, and it is a comment. The conversation is `self.log []*Message` in RAM | nothing but work, plus one already-taken decision (modernc.org/sqlite, Spec A rev A-4) |
| **MEDIA retention class** | yes | **yes** — wire byte `0x02`, derived key, TTL fields, `media_ttl_seconds` column with CHECK, ~10-case contract test | **half** — server arithmetic real; **no writer** (`grep -rn 'RetentionMedia\|MediaTtl' --include=*.go sdk/` → **0**) and **no reaper** (`msgrepo/sweep/` is doc.go only) | a writer in the SDK and a sweep. `prune_after` is computed, stored, and read by nothing |

---

## 3. The content envelope

### 3.1 What exists

**One plaintext envelope exists in the workspace, it is nine octets, and it is not in `connect`.**

`sdk/urmessage/record.go:129-155` — **read**:

```go
const headVersion byte = 0x01
const headBytes = 1 + 8            // version, then sent_at as unix ms, big endian
```

`encodeHead` writes version ‖ u64 BE; `decodeHead` refuses any other length or version with
`ErrHeadFormat`. It ships and is on the live path — sealed at `group.go:649`, read back at `:1361`.

Its own comment at `record.go:124-127` names the missing field:

> *"It exists so that the day this package puts a second field in the head -- a reply-to, a content
> type -- a record written by the older build is refused with a sentence rather than parsed as
> something it is not."*

So the extension point is **already built and already version-guarded**. This matters for cost. The
framing survey this audit was handed said *"there is NO plaintext content envelope in any repo."*
That is **half wrong, in the cheap direction**. The half that is right is the half that gates
everything.

### 3.2 What is missing

**The body has no envelope at all.**

- Send — `sdk/urmessage/group.go:649`: `SealRecord(message.RetentionDurable, 0, false,
  encodeHead(sentAtMs), []byte(text), 0, nil)`. The body **is** the UTF-8.
- Receive — `group.go:1375`: `Text: string(bodyPlain)`. An unconditional cast, no branch.
- The only receipt-side discrimination is by **plaintext header fields the server reads**:
  `group.go:1322` (`IsCommit`, `ServerAttachment`) and `group.go:1341` (`RetentionClass`). That
  works only because there is exactly one kind of user content, and it is on the wrong side of the
  encryption boundary to extend — extending it would tell the server which record is a reaction.
- The two control record kinds are told apart by **comparing the body to English sentences**:
  `group.go:39`, `alphaWrapBody = "urmessage/v1 alpha epoch wrap: no key material, the epoch secret
  travels in the mls welcome"`. Written at `:559` and `:573`; read nowhere.

**And it is missing from the specs, not only from the code.** Query:
`grep -nE "application_data|content_type|ContentType" msgrepo/docs/specs/*.md` → **ZERO hits across
all four specs** (**measured**). Spec A §5.1:1178 states the intent directly:

> *"Most application records carry an opaque body inside `ct_body` and this layer never looks at it.
> The reaction is the exception, because its body is validated on both sides."*

Exactly one leaf body shape is specified — `REACTION { u8 op, LP(target_message_id),
LP(emoji_utf8) }` — and **nothing anywhere says how a reader knows a body is one**. Its `u8 op` is
`0x01 = add / 0x02 = remove`: it distinguishes reacting from un-reacting, never a reaction from a
text. A skimmer will read it as a discriminator. It is not one.

### 3.3 What `type` in `ct_head` is, and whether it is implemented

MASTER §8's record table, `2026-08-12-urmessage-protocol-design.md:1078` — **read**:

```
ct_head            AEAD; MLS PrivateMessage header, type, sent_at.
```

That word `type` is the only appearance of a content discriminator in the design corpus. It has no
width, no enum and no value list. Query: `grep -rn "type, sent_at" msgrepo/docs/specs/` → **2 hits**,
that table line and one Spec A citation of it.

**It is MLS's `ContentType`, not an application kind.** MASTER:1042 fixes the reading — *"MLS
produces `PrivateMessage` objects. This layer is the envelope that stores them durably."* The table
is RFC 9420's. And it **is implemented**: `connect/mls/framing.go:55-63`, `ContentTypeApplication =
1`, `ContentTypeProposal = 2`, `ContentTypeCommit = 3`, with a refusal on the reserved zero.

So both readings of MASTER §8's `type` are wrong. It is not missing, and it is not the thing anyone
wants: **a text, a reaction, an image and a tombstone are all `ContentTypeApplication`.**

**Worse, it is not even present in a real message's head.** Query:
`grep -rn "ContentTypeApplication|ApplicationData" --include=*.go sdk/urmessage connect/messagegroup`
→ **0 hits**, against a positive control of `SealRecord` → **128 hits** over the same tree, so the
search genuinely read it (**measured**). The shipped build never constructs an MLS `PrivateMessage`
for an application message at all, so `ct_body` is not *"the MLS PrivateMessage payload"* that
MASTER:1087 defines it as. **This divergence is declared nowhere** — not a NotBuilt entry, not a
ledger open item. §7(a).

### 3.4 What the consumers already assume

Spec A §7.1:3946 publishes a **closed** vocabulary on `MessageEntry`:

```go
Kind string   // "text"|"attachment"|"reaction"|"tombstone"|"system"|"gap"
```

and Spec C §16.1 gate 8 **CI-asserts set equality** on it against the Windows UI. A build gate stands
over a field no record can carry, and it passes green today because it compares spec to spec.
`grep -rn "MessageEntry|type MessageClient" --include=*.go connect sdk msgrepo` → **0** (**measured**).

Six of the files Spec A §5 assigns this work to do not exist: `reaction.go`, `tombstone.go`,
`card.go`, `rendezvous.go`, `wrap.go`, `pad.go`.

**I did not design the envelope and am not proposing a layout.** The decision is §5.1.

---

## 4. What the Windows app can be wired to today

This is the decision the report exists to inform, so it gets its own numbers.

### 4.1 The blocker nobody named: there is no binding

`grep -rn "^//export" --include=*.go sdk/` → **622** exports, all in `sdk/cgo/`. Every one is the VPN
SDK's `urnet_*` ABI. Filtered to messaging: **1**, and it is
`urnet_set_message_pool_memory_targets` — a memory pool, not messaging.
`grep -rn "urmessage" --include=*.go sdk/cgo/` → **0** (**measured**).

`sdk/urmessage` has exactly **two** non-test consumers in the whole sandbox: `sdk/liveprobe/main.go`
and the `sdk/cp3b` test suite. Query: `grep -rn 'sdk/urmessage"' --include=*.go . | grep -v
'^./sdk/urmessage/'` → 10 lines, 9 of them tests.

Spec A §9 designs the C ABI in detail — `urmsg_client_send_text`, `urmsg_client_history`, a whole
memory-ownership table at §9.4. None of it exists. **So the Windows app's step 0 is a binding, and
that is true regardless of how the envelope is ruled.**

### 4.2 What is real behind that binding, today

- One UTF-8 string per record, **≤ 65,532 octets**, class DURABLE (`Group.Send`).
- Receive by **poll** (`Group.Receive`). `sdk/message_transport.go:34-43` states the verification in
  its own voice: *"There is no server push, and the receive path is a poll… fetching is the only
  receive there is."* Confirmed independently: `msgrepo/peer/peer.go:790,805,820,835` — `buildRoutes`
  serves **4** of the **15** arms declared at `connect/protocol/message.proto:38-52`.
- Per message: `RecordId`, `SenderHandle` (16 opaque octets, **not a name** — there is no identity
  system), `Mine`, `Text`, `SentAtMs`.
- A group of **exactly two**, created by `CreateGroup` → `AddMember` → `Open`, joined with an
  `Invite` that is **secret in full** and must be hand-carried.
- History on restart = a **re-fetch from the server**, not a restore from disk.

That is the entire product surface: `NewDevice`, `Connect`, `KeyPackage`, `Groups`, `Close`,
`CreateGroup`, `Join`, `Restore`, `AddMember`, `Open`, `Send`, `Receive`, and 8 accessors. Spec A §7
declares roughly ninety methods.

### 4.3 What would be a stub

Everything else in §2's table. Wiring any of these now means wiring to a fixture: delivery / read /
typing state, reactions, replies, delete, attachments of any kind, group names, contact discovery,
a third member, notifications while closed, and local history or search.

**The demo already proves how convincing a fixture looks.**
`message-windows/.claude/worktrees/demo-ui/app/src/App/Demo/DemoWorld.h:23` declares `enum class
DeliveryState { Pending, Sent, Delivered, Read, Failed, Expired }` — Spec A's exact six — and
`DemoAutoplay.cpp:29` drives a live typing indicator from `constexpr std::array<int64_t, 4>
kTypingMs{3200, 5400, 4100, 5900}`. A screenshot of that build shows a fully working
receipts-and-typing messenger. It is a table.

---

## 5. What only the owner can decide

Each with the options and what each costs. I am not proposing shapes and I ruled none of these.

### 5.1 The content envelope — the one that unblocks the most

**The decision:** whether a plaintext body declares its type, where that declaration lives, and what
the values are.

- **Option A — in `ct_head`, beside `sent_at`.** Cheapest: the version byte already exists to refuse
  an older build (`record.go:129`), and `ct_head` is never read by the server, so it needs no
  `format_version` bump. **Cost:** Spec B §7.2 sets `ct_head = NULL` at `prune_after` for EPH(1..5),
  so a type stored there dies with the record.
- **Option B — a leading field of `ct_body`.** Survives pruning of the head. **Cost:** it is inside
  the erasable half, and it consumes bytes on the padding ladder — a short text near a rung boundary
  pays a whole rung.
- **Option C — honour MASTER §8 as written:** make `ct_body` a real MLS `PrivateMessage` payload with
  the application content inside it. **Cost:** the largest change. But the alternative is that the
  shipped build's non-MLS framing silently becomes the design, which is an undeclared divergence from
  MASTER:1087 today (§7a).

**What it unblocks, together:** reactions, replies, tombstones and delete-for-everyone, all three
receipt classes, typing, attachment descriptors (MIME, filename, caption), system records, and the
six values of `MessageEntry.Kind` that Spec C's gate 8 already asserts. **This is why ruling it once
beats ruling five features separately.**

### 5.2 `message_id` — the primitive nobody has filed

**The decision:** what a message's stable identifier is, who assigns it, and whether it exists before
the server answers.

The corpus uses it as the referent for a reaction (`LP(target_message_id)`, Spec A §5.1:1182), a
reply (`ReplyToId`, §7.1:3950), a tombstone, a read cursor (`MarkRead(…throughMessageId)`,
§7.1:3909), the local store's per-row key (`HKDF-Expand(local_store_key, "entry/v1" ‖ LP(group_id) ‖
LP(message_id), 44)`, §8.3a:4936) and the C ABI's pagination cursor (§9:5159).

**No document defines it.** Queries (**measured**): Spec A → 5 substantive uses, none a definition;
MASTER → `grep -c "message_id"` = **0**; Spec B → **0** relevant (its hits are the unrelated
`message_identity` table).

It is **provably not `record_id`**: §8.3a:4942 lists `group_id`, `message_id`, `record_id` as three
separate plaintext columns, and `connect/message/codec.go:47-56` rules `record_id` out of the
authenticated encoding in four ways precisely because the server assigns it *after* acceptance. So
the question *"what does a client quote before the server has answered?"* has no answer in the
corpus, and **one missing primitive blocks four features at once**.

**It is not on any open-item list** — no ledger item, no review finding. Rule it in the same sitting
as 5.1: the referent and the identifier are the same question asked twice.

### 5.3 M1-25 — what a typing indicator costs

**Filed and unruled**, `msgrepo/docs/plans/2026-09-04-slice1-m1-message-crypto.md:6192-6196`
(**read**).

Under ruling A1 every retention class shares one stream-index counter per (group, sender_handle), so
an EPH(0) transient consumes an index. Two costs:

- Every typing indicator is a **synchronous durable flush** — the transient send rate becomes the
  fsync rate.
- **1,025 transients between two durable records permanently gap the second one**, against the
  1,024-wide receiver window at `connect/mls/secret_tree.go:856`.

**Measured, not read:** `go test ./messagegroup/ -run
TestTransientsOnTheSharedCounterStarveADurableReceiverWindow` → **PASS**.

- **Option A — a separate counter for transients.** The plan notes nothing server-side checks them,
  so nothing breaks. **Cost:** a second counter and its persistence.
- **Option B — state the cost and accept it.** **Cost:** a real message is losable by a typing
  indicator.

**Nothing about typing indicators is safe to build before this is ruled.**

### 5.4 The blob plane's schedule — it is not an attachments feature

MASTER:1698 (**read**): the epoch snapshot *"exceeds the 64 KiB inline ceiling and is therefore
written as a **blob-ref record** (`size_bucket = 5`) of class `PERMANENT`"*, with the reason at
:1703 — *"Without this a 500-member group makes every join an 11.5 MB download."* Spec B §8.3's
non-expiring `perm/` object rung exists for it.

**So blobs sit on the archive and join critical path, not behind the media slice.** The current build
sidesteps it with the `alphaWrapBody` placeholder string and produces no snapshot
(`ExpectedWrapCount` has no `+1` for one).

**The decision:** schedule the blob plane with the group-growth work, or accept the 11.5 MB join.

### 5.5 The pinned Unicode version for reactions

Spec A §7.4a:4126 requires sender and receiver to validate against the same vendored tables, warns
exactly what happens otherwise (*"a sender on a newer version emits something a receiver refuses, and
the reaction disappears with no explanation on either side"*), calls updating it *"a deliberate
change with its own test vectors, not a dependency bump"* — **and names no version.**

Query (**measured**): `grep -rnE "Unicode [0-9]|Unicode-[0-9]|UAX ?#?29|Emoji_Presentation|
Extended_Pictographic|RGI_Emoji" msgrepo/docs/specs/*.md` → **ZERO hits across all four specs.**

The rule cannot be implemented as written, and **A-16 sits on the A6 wire-freeze gate depending on
it** (spec-a:5691). Paired with it: **M1-41**, the dependency decision — Go's stdlib has no UAX #29
segmentation, so a new module or a hand-rolled subset plus vendored tables. This project vendors
aggressively; it is a real decision, not a `go get`.

### 5.6 Receipt privacy defaults

Already **decided and written**, and worth naming so nobody re-opens it: MASTER §12.2:2331 — read
receipts and typing are on by default, EPH(0), never persisted, batched, individually disableable,
and **reciprocal**; delivery receipts are the same record class, on by default, and **not**
reciprocal. Spec A §7.2:3194 puts enforcement below the UI so a screen that forgot it cannot leak.

**What is genuinely unruled is smaller and specific:** (a) the receipt body — §7.4:4084 says it names
*"the record and nothing else"* and never says how; (b) the client-side discriminator between
delivery receipt, read receipt and typing indicator — the server's inability to tell them apart is
deliberate (Spec B §7.6:2764), but no document says how the *client* does; (c) the batching interval
— *"batched"* appears twice with no number, no cap, no algorithm; (d) the typing repeat cadence.
(a) and (b) are 5.1 in another costume.

### 5.7 Editing in v1

**Already ruled out**, in four documents — MASTER §2:448, SPEC-LEDGER T8:114, Spec B:3737, Spec C §15
(*"The context menu has Delete, not Edit"*) — with the field reserved at Spec A §7.1:3959
(`Edited bool // reserved; always false in v1`) and correctly zero code.

**The live question is not whether to ship it. It is whether its deferral is safe.** See §7(c).

### 5.8 Thumbnails, video and GIF

**Undesigned, not unbuilt** — no amount of implementation work closes either.

- **Thumbnails:** Spec C §5.2a renders a 320×320 DIP thumbnail from `MessageAttachment`, which has
  **no** thumbnail field, no width, no height, no duration (Spec A:3983). The decision is whether a
  thumbnail is a second blob, an inline field, or a client-side decode.
- **Video and GIF:** `grep -niE "\bgif\b|video|voice note|audio"` across MASTER, Spec A and Spec C →
  **2 hits, both exclusions, and both about voice/video *calling***. Sending a video file is absent
  from every spec — no duration, poster frame, autoplay, loop, transcode policy or per-type cap. Spec
  C's bubble table offers only "Inline image" and "File card", so **a GIF and an MP4 both land as
  file cards.** Someone reading *"video deferred to V2"* would conclude video files were considered
  and excluded; they were **not considered**.

### 5.9 A group's name

`GroupPolicyExtension` is `{Roles, RetentionPolicy, DisappearingBuckets, ServerId}`
(`connect/mls/group_policy.go:130-135`) — no name field. The `Invite` carries five key-material
fields and no name. Spec A publishes `MessageGroup.Name` and `CreateGroup(name string, …)` with no
stated source, and `grep -rn "SetGroupName|RenameGroup" msgrepo/docs/specs/*.md` finds nothing.

**Renaming is not unbuilt: naming has no carrier.** Say where a group's name lives before anyone
writes a rename.

---

## 6. Build order

Ordered by what unblocks the most. Steps 1-3 are independent of each other and can run in parallel.

**0. Rule §5.1 and §5.2 together, in one sitting**, before A6 freezes the wire. One decision, five
features, and the extension point is pre-built. Nothing below unblocks the content features without
it. *This is a meeting, not a task.*

**1. A binding: `sdk/urmessage` → Windows.** The Windows app cannot touch real data at all without
one, and this is true whatever §5.1 decides. Spec A §9 designs it. Today: 622 `urnet_*` exports, zero
for urmessage. **Start here** — everything the Windows team does this week runs through it.

**2. The local message store.** Spec A §8.1 / §8.3a against `modernc.org/sqlite` (already accepted,
Spec A rev A-4), starting with two tables — the plaintext metadata index and `entry.body_sealed`
under `local_store_key` — and have `Group.Receive` write through it instead of appending to
`self.log`. **Needs no ruling and no other team.** It does **not** need the envelope: a `Kind` column
can read `"text"` on every row until §5.1 lands. It converts search (which Spec C rules **in** v1),
unread counts, drafts, history paging, `MessageEntry.State` and delete-for-me from *not built* to
*wire it up* — and it stops a server-side retention prune from erasing the client's only copy.

**3. Group orchestration past epoch 1.** The MLS half and the server half are **built**
(`ProposeRemove`, four roles, three ValSems; `store/contract.go:1481` asserts the epoch advance and
:1959-1990 drives it over rounds). What is absent is client orchestration: generalise `Group.Open`'s
three-record ceremony into an epoch-change routine, and **stop dropping every commit at
`group.go:1323`**. Needs one owner ruling first — `GroupEngine.LoadGroup` (J1-8), a Spec A §6
amendment and therefore Gate 5.

**4. Then, after step 0 lands:** the head v2 (or body v1) encoding and one parser, both client-side,
in a single new file behind the existing version byte; `group.go:1375`'s unconditional cast becomes a
switch. Then reactions (`connect/messagegroup/reaction.go`, which Spec A:221 names and which does not
exist), tombstones with the 24-hour constant and its receipt-side refusal, replies, and the
attachment descriptor — each small, each sequential, **and none of them needing server work** except
attachments.

**5. Subscribe, and then push.** Stand up Redis and serve Subscribe/Unsubscribe — **that alone turns
a poller into a live client and is worth doing before push.** Then the EPH(0) accept-and-drop path
replacing `submit.go:610`'s REASON_INTERNAL, then receipts and typing (after §5.3 is ruled). A real
wake is a GA gate that will not move until somebody owns the Azure AD registration; **naming that
owner is a person, not a commit.**

**6. The blob plane.** Four declared gaps — the `message_blob` table and the four-step bind, blobd's
PUT/GET with grant decrypt, the `blob_grant` op-17 handler, and `grant_kek` from `message_fleet.yml`
— plus one **undeclared** gap: `capabilities()` (`cmd/message-server/server.go:240-258`) advertises
`max_blob_bytes`, `blob_chunk_bytes` and `blob_pad_multiple` as **zero** and `HelloResponse` carries
no `BlobEndpoint`, so a spec-conformant client doing Spec C §5.4's pre-send cap check sees zero with
no NotBuilt line explaining why. See §5.4 on why this is not last.

**7. Contact cards and the rendezvous.** Fully specified, entirely unbuilt on both sides, gated on an
identity system that does not exist. This is what makes the product usable by two strangers.

---

## 7. Contradictions found, and claims that did not reproduce

Reported rather than resolved. I ruled on none of these.

**(a) The shipped build diverges from MASTER §8 and nothing declares it.** MASTER:1087 defines
`ct_body` as *"the MLS PrivateMessage payload"*. The shipped seal path never constructs an MLS frame
for an application message: `grep -rn "ContentTypeApplication|ApplicationData" --include=*.go
sdk/urmessage connect/messagegroup` → **0**, positive control `SealRecord` → **128** (**measured**).
Not a NotBuilt entry, not a ledger open item.

**(b) Spec A disagrees with itself about whether bodies have types.** §5.1:1178 declares them opaque
with the reaction as the sole exception; §7.1:3946 publishes a closed six-value `Kind`, and Spec C
§16.1 gate 8 CI-asserts set equality on it. Both are current text in the same document set.

**(c) The editing deferral's safety claim is not discharged.** MASTER §2:448 and SPEC-LEDGER T8:114
both say *"type codes reserved so none is a format break."* **There is no type-code registry** in any
spec or any Go file. Spec A §5.1's "Record types" heading enumerates retention classes and size
buckets. MASTER §8's `ct_head` `type` is MLS's `ContentType` and cannot carry an application kind
(§3.3). A6 freezes the wire; today the deferral is **safe by assertion**.

**(d) The reaction-set contradiction I was asked to flag does not reproduce as a live disagreement.**
The brief named Spec A A-5 (*arbitrary emoji against a pinned Unicode version*) against Spec C
revision 3 (*closed at eight emoji, by codepoint*). **Spec C's revision table is append-only, newest
last, and runs to rev 6.** Rev 5 (`2026-08-12-spec-c-windows-client-ui.md:104`) reverses rev 3 in as
many words: *"**Reactions take any emoji**: §5.2a replaces the eight-emoji table with the full
picker."* Spec C §5.2a's body at :424 now reads *"There is no approved list and no fallback list."*
MASTER §12.2 agrees: *"**A reaction carries any emoji.** The reaction field is not a fixed list."*
Queries: `sed -n '96,112p'` on Spec C, and `grep -n "eight emoji\|closed at eight"` → **1 hit**,
line 102, the stale rev-3 changelog row. The only other mention is `grep -n "eight"` → :435, *"With a
fixed set the worst a reaction could carry **was** one of eight approved meanings"* — past tense,
arguing *for* the new rule. Both are non-normative.

So the three specs agree. **What remains is that the superseded row is still readable in the document
and a reader will land on it** — as this audit's brief did. Whether to annotate superseded changelog
rows is the owner's call; I am not making it.

**(e) The test count in the brief does not reproduce under my queries.** I was told the suite is
*"353 without PostgreSQL, 479 with."* My measurements at `6dd3464` are in §9. I publish my queries
rather than reconcile to a number I cannot derive.

**(f) Two false friends that will fool the next grep.** `sdk/urmessage/group.go:199-201` has a field
literally named `delivered map[uint64]bool`. It is **not** a delivery receipt — it is the set of
record ids already in the local log, used to dedupe a rewound fetch. And
`connect/message/attachment.go` is 520 lines about the **server** attachment (the epoch-rekey
ceremony), not media; it is one of the most finished files in the area and has nothing to do with
attachments in the product sense. Both will report features that do not exist.

### The queries behind §2's zeros

All run over `connect sdk msgrepo` with `--include=*.go` unless noted (**measured**):

| Query | Result |
|---|---|
| `grep -rni 'emoji'` | **0** |
| `grep -rn 'REACTION'` | **0** |
| `grep -rni 'reaction'` | **5**, all `dialFailureAction` in `connect/ip.go:5048-5085` |
| `grep -rn 'reply_to\|ReplyToId\|replyToId'` | **0** |
| `grep -rn 'DeleteForEveryone\|DeleteLocal\|delete_window'` | **0** |
| `grep -rn 'MessageEntry\|type MessageClient'` | **0** |
| `grep -rn 'Edited\b'` | **0** (correct — reserved, not built) |
| `grep -rn 'TransientPush' \| grep -v protocol/message.pb.go` | **0** |
| `grep -rn '"blob/v1"'` | **0** |
| `grep -rn 'BlobGrant' \| grep -v '\.pb\.go'` (msgrepo, sdk) | **0** |
| `grep -rn 'RetentionMedia\|MediaTtl'` in `sdk/` | **0** |
| `grep -rn '\.InstallEphRoot('` non-test | **0** call sites |
| `grep -rni 'sqlite'` | **1**, a comment in `connect/messagegroup/streamindex.go:32` |
| `grep -rn 'NotBuilt{'` non-test in `msgrepo/` | **19** declarations |
| `grep -n 'nameOf(&protocol' msgrepo/peer/peer.go` | **4** served arms, of 15 declared |

---

## 8. Two things that are more built than anyone would guess

Stated loudly, because an inventory that reports them red would cost real schedule.

**The receipt record class's crypto is finished.** `SealRecord` / `OpenRecord` handle EPH(0) today.
**Measured:** `go test ./messagegroup/ -run
TestAnEphRecordIsSealedUnderItsOwnWindowsKeyAndUnderNoOther` → **PASS**, logging *"bucket 0: window 0
is the record's own"* (`ephkey_test.go:2063`) and *"6 of 6 eph buckets rebuilt from the outside"*.
The blanket refusal of non-DURABLE classes was lifted on 2026-09-13 (ledger 152). It is unreachable
only because `InstallEphRoot` has **zero production call sites**, so no live session holds an
`eph_root` and no live session can seal any EPH record.

**The server is the most honest party in the project, and I confirmed it rather than catching it.**
It refuses what it cannot serve rather than half-serving it, and publishes the refusals.
**Measured:** `go test ./api/ -run
'TestAnEphWindowIsZeroUnlessTheWireByteIsSeventeenThroughTwentyOne/eph_bucket_0|
TestTheRecordKindsThisBuildCannotServeAreRefusedRatherThanStored'` → **PASS**, including subtests
`an_EPH(0)_transient` and `a_size_bucket_5_blob-backed_record`. `msgrepo/api/submit.go:608-616`
returns `REASON_INTERNAL` for both, before the transaction. 19 NotBuilt declarations; `peer.go:371`
**derives** the unserved-arm list from the compiled descriptor rather than curating it.

**But that inventory is structurally blind to this report's central gap.** Every declaration is
server-side, and Spec B §2.2 forbids the server from linking an MLS parser at all. A missing
*client-side plaintext encoding* cannot appear on `/readyz`. **That is how the gap survived to a
live, end-to-end-verified deployment.**

---

## 9. What this audit did not look at

Named rather than implied.

- **The live deployment.** I have no access and did not SSH anywhere. I can neither confirm nor
  contradict the 1,271-assertion result from these three repos. Related: `sdk/urmessage/doc.go:46-52`
  says the shipped wiring has *"no account, no JWT and no platform"*, and `grep -rn "ByJwt"
  sdk/urmessage/ sdk/cp3b/ msgrepo/harness/` → **5 lines in 2 files, every one a comment**
  (`sdk/urmessage/doc.go:21,36,37`, `sdk/cp3b/world_test.go:27,146`) — no code path builds or carries
  one. **If a real operator credential was minted for the live run, minting it is itself an unnamed
  per-user v1 requirement.**
- **PostgreSQL-backed behaviour.** 14 tests skipped for want of `URMESSAGE_TEST_DSN` (§10).
- **Disappearing messages.** Placed, not audited: `GroupPolicyExtension.DisappearingBuckets`
  round-trips through its codec and has **no writer** (`device.go:530` writes Roles only); every
  `SealRecord` call in the alpha passes `expireAt = 0`.
- **Multi-device.** Designed in full at Spec A §7.5 (pairing codes, SAS digits, a ten-leaf cap); what
  ships is `ErrIdentityInUse`, a clone detector that refuses the second copy. MASTER:2507 ranks it
  **ahead of attachments**. I placed it and stopped.
- **History for a late joiner** (`GrantHistory` / `HistoryGrants`), **per-conversation mute**,
  **unread counts**, **key transparency**, **recovery and the seedphrase**, **the PIN and auto-lock**.
  Read far enough to place; not audited.
- **Spec C's remaining screens and its other build gates.** I read §15's not-in-v1 table and gate 8,
  and nothing else in §16.
- **`connect`'s and `sdk`'s own test suites beyond the five tests I ran by name**, and the whole of
  `connect` outside `message`, `messagegroup`, `mls` and `protocol`.
- **Link previews.** `grep -ric "link preview" msgrepo/docs/specs/*.md` → **0 everywhere.** Absent
  from the corpus entirely — neither designed nor ruled out.
- **Anything in `message-windows` beyond the four greps in §4.3.**

**And one boundary worth stating positively:** Spec C §15 rules forwarding, starring, pinning, drafts
sync, voice and video, avatar upload, blocking, reporting, message editing, history export and
managed deployment **out** of v1 — *absent, not disabled*, each with a reason — and rules **local
search in**. An auditor who counts those as gaps will over-report. I did not audit them individually.

---

## 10. Verification

**Run in `msgrepo` at `6dd3464`**, Go 1.26.5, **without** PostgreSQL (`URMESSAGE_TEST_DSN` unset):

```
go build ./...                    → BUILD_OK
go test ./... -timeout 900s       → exit 0, 0 FAIL, 6 ok, 6 [no test files]
```

Counts, with the query beside each — the brief's *"353 without PostgreSQL, 479 with"* does **not**
reproduce under any of them, so I publish mine rather than reconcile:

| Query (over the `-v` log) | Count |
|---|---|
| `grep -c '^=== RUN'` (tests + subtests) | **485** |
| `grep -c -- '--- PASS:'` (all depths) | **471** |
| `grep -c '^--- PASS:'` (top level only) | **179** |
| `grep -c -- '--- SKIP:'` | **14**, every one `URMESSAGE_TEST_DSN is unset` |
| `grep -c -- '--- FAIL:'` | **0** |
| `grep -rhn '^func Test' --include=*_test.go . \| wc -l` | **191** |
| `grep -rhn '^func Fuzz' --include=*_test.go . \| wc -l` | **3** |

Tests run by name in the read-only repos, to check claims rather than read them — all **PASS**:

- `connect`: `TestASealedRecordIsExactlyItsRungAndIsOneTheCodecAccepts`,
  `TestAnEphRecordIsSealedUnderItsOwnWindowsKeyAndUnderNoOther`,
  `TestTransientsOnTheSharedCounterStarveADurableReceiverWindow`
- `msgrepo`: `TestTheRecordKindsThisBuildCannotServeAreRefusedRatherThanStored` (both subtests),
  `TestAnEphWindowIsZeroUnlessTheWireByteIsSeventeenThroughTwentyOne/eph_bucket_0`

**Tree integrity before commit:** `git ls-files` = `git ls-tree -r HEAD --name-only` = **129**.
