# The CP3b chain, and three amendment proposals

Written 2026-09-02. Commissioned by the reviewer's finding against the s1 plan: *"The plan does not
trace a chain to CP3b and does not answer the sequencing question that commissioned it."*

Two things are in here and they are different kinds of thing:

- **Part 1 answers the sequencing question.** It is a measurement and a schedule. It is not a
  decision and needs no ruling.
- **Parts 2 and 3 are proposals for the owner.** Three gaps and two filed conflicts, each written up
  as options with a recommendation. **Nothing here is decided.** This project has twice had an
  implementer discover that a plan resolved an ambiguity the spec never settled, so every position
  below is labelled as a position and every rejected alternative is named.

Nothing in this document edits a spec.

---

## Part 1 — the shortest chain from here to CP3b

### What CP3b is, restated from the source

`PROGRESS.md` splits the original CP3 in two:

- **CP3a — a message travels.** Record → submit → accept → fan out → fetch → parse, authenticated end
  to end by real `write_auth` / `req_auth`, **with the AEAD under a test-only key source**. Reached
  2026-08-26.
- **CP3b — a message is private.** The same path **with the real MLS key schedule underneath**.
  *"This is the original CP3, and it is the bar for anything a human is invited to send a real
  message through."*

CP3 itself is *"two clients, one group, one message through the server."*

So CP3b is a two-client, one-message, one-group test in which every key is real: `storage_root` from
`HKDF-Extract(mls_secret, pq_secret)`, class keys and a record-key ratchet under it, and no test-only
key source anywhere on the path. The person comes after; the last leg of this document says how much
further that is.

### Current state, and how each line was established

| Component | State | Established by |
|---|---|---|
| `connect/mls` p1–p6 | complete except p6 Task 20 | the brief; p6 Task 20 read and confirmed to be p8's forge seams |
| `connect/mls` p7 | Tasks 1–6 done, plus Task 14 pulled forward (ledger 43) | the brief; `group_context_verified.go`, `group_policy.go`, `owner_successor.go`, `leaf_keys.go`, `proposal_list.go` present |
| `connect/mls` p2 | owes X-Wing | verified: `grep` for `Encapsulate\|Decapsulate\|mlkem` over `mls/` and `message/` non-test source returns **one** hit, a comment. `AlgIdXwing` and `XwingPublicKeyLen` exist in `extension.go`; the KEM does not exist |
| `connect/mls` p8 | not started | the brief |
| `connect/message` | record, codec, AAD, `write_auth`/`req_auth`, server attachment | seven non-test `.go` files (`aad`, `attachment`, `codec`, `doc`, `errors`, `record`, `writeauth`). **No key schedule, no AEAD, no ratchet, no X-Wing, no wraps** — `grep -r 'func StorageRoot' --include=*.go` over the tree returns **0**, and `message/doc.go` says in its own words *"The key schedule lands beside them"*, future tense |
| `message-server` (`msgrepo`) | store passes the hardened contract against real PostgreSQL, both implementations | ledger item 33; `store/pgx.go`, `store/memory.go`, `store/contract.go` |
| `message-server` served operations | `Hello`, `CreateGroup`, `Submit`, `Fetch` | `api/` holds `submit.go` and `fetch.go` and nothing else; `Store` declares six methods and none of them is `Subscribe` or `WrapFetch` |
| `sdk` | no code; plan s1 written, 16 tasks, declarations only | `docs/plans/2026-08-30-slice2-s1-sdk-surface.md`; its own goal line says *"Nothing in this plan sends a message, opens a store, or touches MLS"* |

**One thing the brief did not say, and it is the largest fact in this document.** The re-orientation
of 2026-08-29 named three unplanned workstreams: the sdk, server persistence, and Windows wiring.
There is a **fourth**, and it is on the critical path in front of two of those three: **the
`connect/message` plan does not exist.** The s1 plan already names it — it calls it **m1**, cites it
as the producer of `StorageRoot` and of the 24-hour delete-for-everyone constant, and records both as
*pending pins with no producer*. `docs/plans/` holds p1–p8 (all `connect/mls`) and s1 (`sdk`).
Nothing owns `connect/message`'s second half, which is §5.2, §5.3, §5.5 and the client half of
§5.11 — and that is precisely the half CP3b is defined by.

### The chain

Four legs. Legs 1 and 3 are parallel to each other; leg 2 needs leg 1; leg 4 needs legs 1–3.

#### Leg 1 — `connect/mls`: p2's X-Wing tail, then p7's lifecycle spine

| Task | Plan | The dependency that forces its position |
|---|---|---|
| Task 19 — X-Wing sizes, seed expansion, key generation | p2 | Nothing downstream can encapsulate to a leaf until a key pair exists. `urmessage_leaf_keys` already publishes a 1216-byte X-Wing public key and nothing can produce or consume one |
| Task 20 — encapsulation, decapsulation, the draft vector gate | p2 | **This is the hinge of the whole chain.** MASTER §7: the committer samples `pq_secret[n]` and X-Wing-encapsulates it to every active device leaf. No encapsulation means no `pq_secret` delivery; no `pq_secret` means no `storage_root`; no `storage_root` means no class keys, no record key, no AEAD — which is the exact difference between CP3a and CP3b |
| Task 7 — proposal-list validation, ValSem101–113 | p7 | Task 13 cannot generate a commit over a list nothing validates, and Task 18 cannot process one |
| Task 8 — applying a proposal list | p7 | Task 13 and Task 18 both apply before they seal or verify |
| Task 9 — the path-required rule | p7 | An `Add` commit's update path is required or forbidden by this rule; Task 13 chooses wrongly without it |
| Task 10 — commit validation, ValSem200–209 and the two errata | p7 | Task 18 is the receiving half and has nothing to check with |
| Task 11 — group creation, `NewGroup` | p7 | There is no group otherwise. Also produces `StateStore`, which Task 19's epoch advance persists through |
| Task 12 — proposal generation | p7 | The second client is admitted by an `Add`. The v1 profile parse-refuses external commits (§3.1), so there is no other door into a group |
| Task 13 — commit generation | p7 | The `Add` has to be committed. `CreateGroupRequest.initial_commit` is `is_commit = 1, epoch = 0` carrying the `EpochAttachment` for epoch 1, so the *founding* wire message already is a commit |
| Task 14 — signing and verifying a `GroupInfo` | p7 | **Done.** Pulled forward because ledger 43 found the proposal cache's provenance question unanswerable without it |
| Task 15 — `Welcome` generation | p7 | The joiner's only entry. `CommitResult` carries `Welcome` and `RatchetTree`, the latter annotated *"for out-of-band Welcome delivery"* — see the hole below |
| Task 16 — `JoinFromWelcome` | p7 | The second client's side of the same |
| Task 18 — commit processing | p7 | Both clients advance an epoch: the founder's own commit and the joiner's first received one |
| Task 19 — the epoch advance, persistence and the past-epoch window | p7 | `storage_root` is per epoch and the record layer reads epoch state. The server's §6.1 step (2) verifies a record *"under the briefly-retired key when record.epoch == current_epoch - 1"*, which is the past-epoch window seen from the other end |
| Task 22 — round-trip group tests | p7 | This plan's gate, and the cheapest evidence that the lifecycle is real rather than green |

**Not on the path, and why each is safe to defer.** p7 Task 17 and 17a (vector families 8 and 9) and
Task 23 (families 13–15, passive client) — interop gates; two of our own clients need not agree with
OpenMLS to prove a message arrives, which is the re-orientation's argument for deferring p8 and it
applies to these three tasks by the same reasoning. Task 20 (membership caps and removal authority) —
a two-member group refuses nobody; note that s1's registry carries `mls.CheckGroupSize` and
`mls.CheckDeviceCount` as pending pins against this task, so deferring it leaves those pins pending,
which is what pending pins are for. Task 21 (owner succession) — no owner is unreachable in a test.
p6 Task 20 — read and confirmed: it produces `sealFramedContentForTest` for p8's ValSem002–011 forge,
and its own text says *"This task's tests are the ten ValSem002–011 tests in the validation plan."*
p8 in its entirety. p2 Task 21 (fuzz target and the layering assertion) is deferrable; p2 Task 22
(pin `message.XwingPublicKeySize` against `mls.XwingPublicKeyLen`) is forced to land **with** leg 2,
because the constant it pins does not exist until `connect/message` declares it — `extension.go` says
so in its own comment: *"That copy has NOT landed."*

**Two things on this leg that are not tasks.** Ledger 40/40a: a labelled-preimage panic reachable
through `VerifyWithLabel`, *"before any application-level check a caller could make"*, on *"the path
every incoming signed message crosses"*. A friendly two-client test will not hit it, and CP3b is
defined as *the bar for anything a human is invited to send a real message through*. A remote crash
any group member can fire is a bar failure, not a backlog item, and it is on this leg because
`VerifyWithLabel` is on it. Ledger 41/42 (the cache ceilings) are availability rather than crash and
can follow.

#### Leg 2 — `connect/message`: the plan called m1, which does not exist

This is a plan-writing task before it is an implementation task. Contents forced by CP3b, and only
those:

| Piece | Spec | Why CP3b cannot skip it |
|---|---|---|
| `StorageRoot`, `DeriveClassKeys`, `RecordKeyZero`, `RecordKeyNext`, `RecordAeadHead`, `RecordAeadBody`, `GroupHandleKey`, `SenderHandle` | §5.3 | This *is* "the real MLS key schedule underneath". Guardrail G1 — `hkdf.Extract` takes ikm first and the spec writes salt first — is on this function and is the single easiest silent defect in the project |
| The record seal and open | §5.2, §5.1 | CP3a's harness says it plainly: *"It does not encrypt. `ct_head` and `ct_body` are opaque octets the caller hands in and the caller gets back."* This is the whole delta |
| The epoch wrap set: the X-Wing wrap of `pq_secret[n]` to each device leaf, the `WrapTag` records, the `EpochComplete` marker | §5.11 | The server already enforces the publication sequence — `store/contract.go`'s `TheMarkerIsTheOnlyThingThatOpensAnEpoch`, and `REASON_EPOCH_INCOMPLETE` to any non-wrap submit until the marker lands. A client that does not publish wraps cannot send a second record |
| `record_key[0]` and one ratchet step | §5.5 | One message needs `record_key[0]`; the skipped-key window is only needed once messages can be missed |

**Deferrable inside m1, and each deferral must be named rather than silent.** Recovery wraps
(`RecoveryTag`, `storage_root ‖ archive_secret` to `RECOVERY_PUB`) — seed-only restore is slice A9.
The epoch snapshot — it exists so a restoring device can verify signatures, and both CP3b clients are
live. `eph_root` and the EPH ladder, tombstones, COVER, blobs (§5.13), receipts, reactions. The
contact-card encoding and rendezvous preimages of §5.14 — unless the owner rules Part 2 proposal 1 in
the direction that puts them on the path.

**A trap in those two deferrals.** §5.11 defines `expected_wrap_count` as *"device wraps + recovery
wraps + 1 snapshot"*, and the server checks only that the marker's `wrap_count` equals the
attachment's `expected_wrap_count` — it has no idea what the right number is. So a client that omits
recovery wraps and the snapshot will pass the server while diverging from the spec's definition of
the field. That is exactly the shape of defect this project keeps paying for: a deferral the system
cannot detect. It must be a gated, named deferral in m1, not a number an implementer picks.

#### Leg 3 — the message server: nothing new is required

Verified against the tree. `Store` declares `CreateGroup`, `Submit`, `GroupState`, `EpochKeys`,
`Fetch`, `CloseGroup`; the api layer serves `Hello`, `CreateGroup`, `Submit`, `Fetch`; and ledger
item 33 records the hardened contract green against real PostgreSQL for both implementations.

- **`Subscribe` is not on the CP3b path.** A client can poll `Fetch`. It is on the product path.
- **`WrapFetch` is not on the CP3b path.** Wraps are ordinary records at epoch *n+1* and come back
  through `Fetch`; a member computes `wrap_target_handle` for its own leaf and picks its wrap out of
  the page. Spec B S5's O(1)-by-target index is an optimisation, and Spec A's `WrapFetch` op byte 19
  is how the product avoids downloading everyone's wraps. Neither changes what is decryptable.
- **The retired-write-key behaviour is already load-bearing and already pinned** (ledger 36), which
  matters here because leg 2's wrap records are submitted at the new epoch under the new write key.

This is the one leg with no work on it, and it is the leg the re-orientation said to start early.
That call was right.

#### Leg 4 — the `sdk`: s1, and the plans that do not exist

s1 is 16 tasks and produces **declarations only**. After it, CP3b needs behaviour: an identity, group
state, the engine seam, the transport binding, a send path and a receive path. Those are s2–s10, and
**none of them is written**. So the honest chain says: s1, then between two and four plans that have
to be written first, and the size of those is currently a guess in exactly the way the sdk's own size
was a guess before s1 was written.

What CP3b needs from s1's own output: the value structs and lists it declares, the listener
interfaces, and Task 16's registry. What it does not need: Task 15 (CI) and Tasks 12–14 (the
`sdk/surface` gates) are quality machinery rather than path — though they are cheap, and the plan
lands as one commit set by design.

**The engine seam is the piece to name.** §4.5 Gate 5 puts MLS behind a narrow swappable interface;
s1 records that the single legitimate production edge `sdk → connect/mls` is s5's
`NewConnectMlsEngineFactory`, and that `message.GroupEngine` / `message.GroupHandle` are pending pins
with **s5** as producer and `connect/message/engine.go` absent. So the sdk's dependency on leg 2 is
not only the key schedule; it is a file nobody has written, in a plan nobody has written.

### What CP3b does **not** need from Spec A §7

This is the half of the question that matters most, because "the sdk is done" and "two people can
talk" are separated by most of §7.

**Measurement, with its method stated so it is not confused with the plan's.** s1 counts **212 pinned
declarations over 1,675 lines**, counting nested types and constants. Counting only top-level `func`
lines and top-level `type X struct|interface` lines between `### 7.1` and `## 8.`, measured
2026-09-02, §7 holds **191**. The two numbers count different things and neither contradicts the
other; the per-subsection split below is on the second rule.

| Subsection | funcs | types | CP3b needs |
|---|---|---|---|
| 7.2 Lifecycle and identity | 45 | 7 | **~12**: `NewMessageClient`, `Close`, `MessageClientSettings`, `SetByJwt`, `ByJwtState`, `GenerateMessageSeedphrase`, `ValidateMessageSeedphrase`, `HasIdentity`, `CreateIdentity`, `IdentityPublicKey`, `Start`, `ServerInfo` |
| 7.2.1 Seedphrase custody | 1 | 0 | none |
| 7.3 Groups | 27 | 2 | **~5**: `CreateGroup`, `Groups`, `Group`, `Members`, `AddGroupListener` |
| 7.3a Invite links and join requests | 8 | 4 | **none** — and blocked anyway; see proposal 2 |
| 7.3b Contact cards | 8 | 3 | **none**, unless the owner rules proposal 1 toward the deposit-only option |
| 7.4 Messaging | 20 | 9 | **~4**: `SendText`, `AddMessageListener`, `History`, `Entry` |
| 7.4a Reactions | 0 | 0 | none |
| 7.5 Devices | 13 | 3 | **none.** Multi-device is slice A9 |
| 7.6 Verification, directory, KT | 10 | 7 | **none.** TOFU pinning, safety numbers and `LookupPrincipal` are product, not privacy-of-this-message |
| 7.7 Listeners | 0 | 18 | **~5 interfaces**, plus their payload structs |
| 7.9 Balance | 3 | 3 | **none** |

**Roughly 21 functions and a dozen types — call it 15 to 18 per cent of §7.** The rest is the product.
Stated as a sentence: **CP3b needs identity, one group, one send, one receive, and the engine seam.
It needs no PIN, no lock, no cover traffic, no user preferences, no diagnostics, no push, no policy,
no roles, no leave, no ownership transfer, no succession, no history grants, no invites, no invite
links, no contact cards, no reactions, no receipts, no typing, no attachments, no search, no
backfill, no devices, no verification, no directory, no key transparency, no balance, and no cgo
ABI.**

Two of those absences are worth their own line, because they read like omissions and are not:

- **No `MessagePin` and no TOFU.** §7.6 is how a *user* knows who they are talking to. CP3b is two
  clients we own, and the claim it makes is that the ciphertext is real, not that the peer is
  authenticated to a human. Putting TOFU on the CP3b path would make CP3b a product milestone, which
  it is not.
- **No cgo ABI, no header, no baseline.** §9 exists so Spec C can build. CP3b is Go calling Go.

### The hole in the middle of the chain, which no filed item covers

CP3b needs the second client to be admitted to the group. That requires two transfers the protocol
has no channel for:

1. **The founder needs the joiner's MLS KeyPackage** before it can propose the `Add`. This is Part 2
   proposal 1, and it is filed.
2. **The joiner needs the `Welcome`.** This is *not* filed anywhere. Spec A annotates
   `CommitResult.RatchetTree` *"for out-of-band Welcome delivery"* and then names no band. Every
   server operation in the protocol is keyed by `group_id` and gated on possession of that group's
   epoch key — which a joiner does not have, by definition. The only identity-adjacent channel in the
   whole protocol is §5.14's rendezvous, and it is addressed by a **card token**, not by an identity,
   and its only body is `CONTACT_REQUEST`. §7.3's `PendingInvites()` / `AcceptInvite()` are declared
   over this same absent channel.

So the same missing mechanism blocks three declared surfaces and the CP3b chain. Proposal 1 below is
written to close both directions, and that is the main reason its recommendation lands where it does.

**For CP3b specifically there is a legitimate short circuit**, and it should be taken deliberately and
gated: the two clients are ours and run in one test, so the KeyPackage and the `Welcome` can be handed
over **in process**, by a named test-only path with a gate asserting it is unreachable from any
non-test build — the identical discipline that made CP3a's absent-not-placeholder key source safe. The
rule that made that work is worth repeating verbatim: *"a missing key schedule fails closed and looks
like what it is; a placeholder one fails open and looks like a working messenger."* A test-only
KeyPackage hand-off has the same property, because it transports a **public** value and a `Welcome`
that is already sealed to the joiner's init key. It weakens nothing about the key schedule, which is
what CP3b is about. **It is a deferral of first contact, not of privacy, and it must be named as such
or CP3b will be mistaken for a product.**

### The chain in one line, with counts

**p2 Tasks 19–20 (2) → p7 Tasks 7–13, 15, 16, 18, 19, 22 (12) → m1, a plan that does not exist,
scoped to §5.2, §5.3, §5.5 and §5.11's client half → s1 (16) → two to four sdk plans that do not
exist → CP3b.** Plus ledger 40/40a closed on the way, and the first-contact short circuit named and
gated.

Everything else in p2, p6, p7 and p8 — and about 85 per cent of Spec A §7 — is off it.

### And how much further is a person

The task framing says *a message typed on one client and read on another*. CP3b as `PROGRESS.md`
defines it is a two-client test, not a person. The additional legs to a human are, in order: **s10**
(`sdk/cgo-message`, the generator, the header, the ABI baseline — which s1 deliberately does not
freeze), then **Spec C's wiring** of a shell untouched since 2026-08-13, then a **deployed server**,
which is the item the re-orientation called the one whose risk is deployment rather than design. None
of those three is on the CP3b chain, and all three are between CP3b and a person. Saying so is the
point: CP3b is the *privacy* bar, not the *product* bar, and the sdk's remaining 85 per cent is where
the product is.

---

## Part 2 — three amendment proposals

**These are proposals. None is a decision.** Each states what Spec A promises, what exists, what is
missing, two or three options with their trade-offs, a recommendation labelled as one, and what stays
blocked until it is ruled.

### Proposal 1 — there is no way to fetch a key package for a principal

Filed as ledger open item 44.

#### What the spec promises

Four declarations take a **principal** and produce a group the named party is a member of:

```go
func (self *MessageClient) CreateGroupWithMembers(name string, principals *StringList,
    policy *MessageGroupPolicy, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) CreateDirect(principal string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) InviteMember(groupId string, principal string,
    callback GroupCallback) *MessageSendTicket
func (self *MessageClient) AcceptJoinRequest(groupId string, requestId string,
    callback GroupCallback) *MessageSendTicket
```

Every one of them must issue an MLS `Add`, and an `Add` proposal carries a **KeyPackage**. §7.3's own
comment on `CreateGroupWithMembers` makes the atomicity explicit: *"one MLS commit covering N Add
proposals plus the policy."* N key packages, before the commit, in one shot.

#### What exists

- **`connect/protocol/message.proto` contains zero occurrences of `key_package`.** Verified
  independently of the owner's check: a case-insensitive grep for `key_package` and `keypackage` over
  all seven `.proto` files in `connect/protocol/` returns nothing.
- **The directory maps `principal → identity master key`.** §12.3 says exactly that and no more, and
  it is out of scope for all three specs — it is MASTER slice 9, which has no plan and no schedule.
  `LookupPrincipal` returns `MessageDirectoryResult{Principal, DisplayName, IdentityKeyFingerprint,
  ProofState, OperatorHost}`: a fingerprint, not a key package.
- **Directory listing is off by default.** §7.6: *"An identity that has never called it has no
  directory entry and no key-transparency leaf."* So even if the directory served key packages, it
  would serve them for opted-in identities only.
- **One path does exist, and it runs the other way.** §5.14's sealed contact-request deposit carries
  `LP key_package` — *"the MLS KeyPackage the card's owner will Add"*. The **requester** supplies its
  own key package to the **card owner**.

#### What that path can and cannot do, precisely

**It can** serve `AcceptContactRequest` and `StartDirectFromCard` completely: the redeemer of a card
deposits its own key package, the owner collects, verifies the inner `request_sig` under the
`identity_pub` inside it, and Adds. That is a whole first-contact flow and it is fully specified.

**It cannot** serve any of the four declarations above, and the reason is directional rather than
incidental. The deposit path requires the party being added to **act first**, and to act at a
rendezvous **the party being added chose** — a card generation of *its own* identity, addressed by a
token only that card's owner can mint. All four declarations require the **inviter** to act first,
against a party that may be offline and that has handed out nothing.

The four split 3+1:

- `CreateDirect`, `CreateGroupWithMembers`, `InviteMember` — **nothing serves them.** There is no
  request that says "give me a key package for this principal", no store that holds one, and no
  channel to ask over.
- `AcceptJoinRequest` — **conditionally serves itself.** `MessageJoinRequest` carries `Principal`,
  `DisplayName`, `KeyFingerprint`, `ViaLinkId` and **no key package**. If §7.3a's join-request deposit
  is specified to carry one, the way `CONTACT_REQUEST` does, then this declaration is served by
  proposal 2 and needs nothing from this one. That interlock is the reason these two proposals should
  be ruled together.

**And the same hole blocks the reverse direction**, which nothing has filed: once the founder holds a
key package and commits the `Add`, the `Welcome` has to reach the joiner, and there is no channel for
that either. See Part 1's "hole in the middle of the chain", and ledger 44a.

#### Options

**Option A — the operator's directory serves key packages.** Extend slice 9's directory from
`principal → identity master key` to `principal → {identity key, key packages}`. A client publishes a
pool; a lookup consumes one.

- *For:* fits `LookupPrincipal`'s existing shape; the KT log already covers the identity key that
  **signs** every key package, so inclusion proofs extend to key packages for free; no new
  message-server state and no new record class.
- *Against:* **it works only for listed identities**, and listing is off by default — so
  `InviteMember(principal)` fails for the default user, which is most users, which makes the feature a
  trap rather than a limitation. The operator learns "A asked for B", a social graph at the party
  MASTER §4.2 deliberately unlinks from messaging. And it is blocked on a slice with no plan and no
  schedule, so it cannot be on the CP3b chain at all.

**Option B — a key-package store on the message server, addressed by an identity handle.** New Spec B
operations, e.g. `KeyPackagePublish` and `KeyPackageClaim`, keyed by
`kp_handle = H("URmessage/v1/kph" ‖ identity_pub)`. A claim consumes one one-time package; an
exhausted pool answers with a **last-resort** package, explicitly labelled as such.

- *For:* works for **unlisted** identities and for **offline** invitees, which is the case the product
  needs. Needs no operator work and no slice 9. It is Signal's prekey model, and locked decision P1
  makes *"a weakness Signal also has is acceptable"* the governing rule. Addressing by a handle
  derived from the identity public key — which the fetcher must already possess, from a card, a
  directory answer, or a shared group — means the **server never sees a principal**, so it is not the
  disclosure option A is. And **the same op family can carry the `Welcome`**: a second body type at
  the same handle closes the unfiled hole above and gives §7.3's `PendingInvites` something to be
  built from.
- *Against:* it gives the message server its **first identity-adjacent index.** Today the server holds
  no identity at all — sender handles are per-group and unlinkable by construction. It would learn the
  claim graph over handles, and correlating a claim with the `CreateGroup` that follows it yields "the
  holder of handle H was added to group G". That is a **new disclosure class** and it must be recorded
  as a locked trade-off with its reasoning, not absorbed quietly. One-time packages also bring the
  exhaustion problem: an attacker can drain a target's pool, so the last-resort package is not
  optional — and a reused last-resort key is a weaker initial secret for exactly the joins that happen
  under attack.

**Option C — deposit-only: change the surface instead of the mechanism.** v1 admits a member only when
that member has already deposited a key package — through §5.14's card, or through §7.3a's join
request. `CreateDirect`, `InviteMember` and `CreateGroupWithMembers` are redefined to take a contact
the caller **already holds a key package for**, rather than a principal.

- *For:* zero new mechanism, zero new metadata, nothing new to freeze, and every mechanism it uses is
  already specified and already scheduled in A6. It is the SimpleX-shaped answer and it is honest.
- *Against:* it is a **product change, not a spec clarification.** "Add someone from the directory"
  becomes impossible; Spec C's add-member screens change; `LookupPrincipal` becomes a way to see
  someone and not a way to reach them. And **it does not close the `Welcome` direction**, so it is not
  a complete answer on its own.

#### Recommendation, offered as a recommendation

**Option B, with A rejected for v1 and C's discipline kept as the fallback** when a claim finds no
package at all. Three reasons, in order of weight:

1. It is the only option that serves the default user — unlisted, offline.
2. It is the only option that also closes the `Welcome` hole, which is on the CP3b chain and which
   nothing else in this document or the ledger closes.
3. P1 is a locked decision and it settles the privacy argument in B's favour: this is precisely the
   weakness Signal has.

With it, three things the amendment must state explicitly rather than leave to an implementer: the
handle derivation (from the identity **key**, never the principal); the last-resort package's
existence and its labelling, so a client can tell a user which kind of key their first message went
under; and the new disclosure class, as a **locked trade-off in §3 of this ledger**, so nobody has to
rediscover why the message server has an identity-adjacent index.

#### What stays blocked until it is ruled

`CreateDirect`, `CreateGroupWithMembers`, `InviteMember`, and — unless proposal 2 rules the other way —
`AcceptJoinRequest`, in s5/s7 or wherever the group flows land. Spec B's schema. Spec C's add-member
screens. **Not blocked:** s1, which is declaration-only, and m1's record-format freeze, because a
key-package channel is control-plane protobuf and not a record.

---

### Proposal 2 — §7.3a invite links have no wire, no derivation and no server operation

Filed as ledger open item 45.

#### What the spec promises

§7.3a declares eight functions and four types: `CreateInviteLink`, `InviteLinks`, `RevokeInviteLink`,
`RedeemInviteLink`, `JoinRequests`, `AcceptJoinRequest`, `DeclineJoinRequest`,
`AddJoinRequestListener`, plus `MessageInviteLink`, `MessageJoinRequest` and two callbacks. Two kinds:
a **one-time link** (the default) and a **reusable published address** that *"any ADMIN or the OWNER
accepts or declines"*, and whose revocation *"disturbs no existing member"*. The link *"carries the
group id, the rendezvous id, the inviting member's identity fingerprint, and the capability"*.

#### What exists

- **The rendezvous transport, and it is derivation-agnostic.** `RendezvousRegisterRequest` carries
  `rendezvous_id`, `deposit_verify_pub`, `collect_verify_pub`, `card_xwing_pub`, `alg_id` and
  `register_auth`. The server checks signatures against the keys **it was handed at registration**. It
  never checks where they came from. The same is true of Open, Deposit, Collect and Retire.
- **§5.14's five preimages are group-agnostic**: each binds `server_nonce` and `rendezvous_id`, and
  nothing about a card.
- **§5.14's derivations are per identity, and only per identity**:
  `card_root = HKDF-Expand(master_key, "card/v1", 32)`, then `card_seed[k]`, `token[k]`,
  `rendezvous_id[k]`, `collect_sig_seed[k]`, `deposit_sig_seed[k]`.
- **`RendezvousRetire`, authorized by `collect_sig_sk`, is exactly the revoke operation §7.3a needs**,
  and it already exists on the wire.

#### What is missing

Four things, and only the first is arguable:

1. **A derivation for a per-link rendezvous.** `card_root` is per identity. A group invite link needs
   a rendezvous per **link**, with a `collect_verify_pub` per link — and, for a reusable published
   address, a collect key that **any admin** can hold. A group has no shared secret of that shape. It
   has `group_handle_key`, which is *fixed at group creation* and which **every member** can compute,
   including members who have since been removed.
2. **A link encoding.** §5.14 specifies the *card*: `u8 version = 0x01 ‖ u16 alg_id ‖ LP(identity_pub)
   ‖ LP(token) ‖ LP(display_name) ‖ u32 checksum`. A link carries a group id, a rendezvous id, an
   inviting member's fingerprint, a capability, an expiry and a one-time/reusable flag. No document
   gives its bytes, and `MessageInviteLink.Url` is only *"the urmessage:// form Spec C renders and
   shares"*.
3. **A deposit body for a join request.** The only body §5.14 defines is `CONTACT_REQUEST`, padded to
   exactly 4096 and sealed to exactly 5238 bytes — *"an equality the server asserts"*. A join request
   has different contents, and it must carry a key package or proposal 1's hole reopens here.
4. **The server-side authorization model for a reusable address**, which is the substance of (1).

#### §13's sentence is false, and saying so is part of this proposal

§13 schedules §7.3a into A7 on this reasoning:

> Invite links and join requests (§7.3a), contact cards and their rotation (§7.3b), ownership transfer
> and succession (§7.3), and balance-code redemption (§7.9) land in **A7** with the rest of the client
> core: **each is an `sdk`-level flow over mechanisms A6 already froze.**

**That is false for §7.3a.** A6's contents are enumerated in the same table, and the relevant entry is
*"the contact-card encoding and the rendezvous preimages of §5.14"*. Measured against the four items
above: A6 freezes the **transport** and the **five preimages**, both of which are genuinely
group-agnostic and genuinely reusable. It freezes **no** derivation for a per-link rendezvous, **no**
link encoding, **no** join-request deposit body, and **no** authorization model for a reusable
address. Three of the four things §7.3a needs are not among the frozen mechanisms, and the fourth —
the transport — is the one nobody was worried about.

The sentence is true of §7.3b, which is what it was almost certainly written for: contact cards are
exactly an sdk-level flow over §5.14. It was extended to §7.3a without the check, and the consequence
is that §7.3a is scheduled into a slice whose prerequisites do not include what it needs. **A7 cannot
deliver §7.3a as the table stands.**

#### Options

**Option A — a per-link seed, carried in the link.** `link_seed` is 32 bytes of CSPRNG at creation,
derived from nothing. Everything else derives from it exactly as §5.14 derives from `token[k]`:
`rendezvous_id`, `deposit_sig_seed`, `collect_sig_seed`, and the link's X-Wing key. The creating
member holds `link_seed`; the link carries only what yields **deposit** authority, which is precisely
the split §5.14 already engineered (`TestDepositSigProvesOnlyTokenPossession`,
`TestCollectKeyIsNotDerivableFromToken`).

- *For:* for a **one-time link** — §7.3a's default — this is complete and costs nothing new
  server-side. It reuses the five frozen preimages verbatim. Only the derivation and the link encoding
  are new, and both are small.
- *Against:* for a **reusable published address**, `link_seed` must reach every admin, so it needs a
  distribution channel inside the group — a new record kind wrapped under the epoch's class keys.
  Every **member** can read that, not only admins, so §7.3a's "any ADMIN or the OWNER accepts" becomes
  an advisory client-side rule rather than a cryptographic one.

**Option B — derive the link from group material.**
`link_root = HKDF-Expand(group_handle_key, "invite/v1" ‖ LP(link_id), 32)`. Every member computes it;
nothing needs distributing; it survives epoch changes, which a durable published address needs.

- *For:* no new distribution, no new record, no new secret.
- *Against:* **this is the obvious design and it is wrong.** §5.3: `group_handle_key` is derived from
  `storage_root[0]` and is *"FIXED at group creation"*, never rotated. So a **removed** member retains
  the ability to compute every link's collect key forever — it can collect the join requests of
  strangers trying to join a group it was thrown out of, and it can retire the group's published
  address. That is a live security defect rather than a trade-off, and it is recorded here so the
  option is rejected once rather than re-invented.

**Option C — authorize the reusable address at the server, under the group's read key.** The link's
server operations carry `req_auth` under `read_key[epoch]` — the existing §5.7 authorizer — so
authority means "a current member at a live epoch", which lapses for a removed member at the next
epoch without anyone doing anything.

- *For:* it is the only option whose revocation is tied to membership, which is what a durable
  published address actually needs. It reuses an existing authenticator.
- *Against:* the server learns **link → group**, so it can count how many strangers ask to join group
  G and when. Today a rendezvous is unlinked from any group by design, and this would be the first
  place the message server relates a rendezvous to group state. It also needs a new operation family
  rather than the five frozen preimages.

#### Recommendation, offered as a recommendation

**A for one-time links, C for reusable published addresses, and B rejected on the removed-member
argument.** The one-time link is §7.3a's stated default and the common case, and A serves it with a
new *derivation* and a new *encoding* only — no new server operation at all. The reusable address is
the case that genuinely needs revocation bound to membership, and only C gives it. Splitting them is
not a fudge: §7.3a already describes them as two different things with two different approval models,
and the two halves have genuinely different requirements.

One detail worth keeping whichever way it goes: the server asserts the deposit is **exactly**
`rendezvous_deposit_bytes`. If the join-request body pads to the same total as `CONTACT_REQUEST`, then
a contact request and a join request are **indistinguishable by length** on the wire — a property
worth having on purpose rather than by accident.

#### What stays blocked until it is ruled

All eight §7.3a declarations — s1 already places them in Task 11's blocked set. `AcceptJoinRequest`'s
key-package source, which is the interlock with proposal 1. §13's A7 row, which currently promises
something A6 does not deliver. And Spec C's join-request screens.

---

### Proposal 3 — `GrantHistory` has no mechanism anywhere

Filed as ledger open item 46.

#### What the spec promises

- MASTER §11: *"History grants. Owner-only, non-erasable, rendered as a persistent banner for the life
  of the group naming grantee, epoch range, and granting owner. New members receive keys from their
  join epoch forward by default."*
- Spec A §7.3: `GrantHistory(groupId, memberId, fromEpoch, callback)` and `HistoryGrants(groupId)`,
  with the comment *"A grant is a group record, so it is a commit and returns a ticket."*
- Spec A §7.7: `GroupEvent.Kind`'s closed set contains `"history_granted"`.
- Spec A §7.7: `MessageHistoryGrant{GrantId, GranteeMemberId, GranteePrincipal, GranteeDisplayName,
  GrantedByMemberId, GrantedByDisplayName, FromEpoch, FromMs, GrantedAtMs}`.
- Spec C §12: screen 15 renders the banner from `HistoryGrants(groupId)`, with **no dismiss
  affordance**, because *"a banner the user can close is an erasure with extra steps."*

#### What exists

**Nothing.** §5.11 wraps the **current** epoch to **current** members: the device wrap carries
`pq_secret[n]` and `eph_root[n]` to each active device leaf; the recovery wrap carries
`storage_root[n]` and `archive_secret[n]` to each member's `RECOVERY_PUB`. Both are produced by the
committer, at commit time, for the epoch the commit opens. There is **no wrap-to-past-epochs
primitive**, no record class for a grant, no server operation, and no group-context extension — v1's
`RequiredCapabilities` is fixed to `[0xF001, 0xF002]`. The s1 plan already records exactly this, in
its Task 11 blocked set: *"`GrantHistory` (no extension — v1 `RequiredCapabilities` is fixed to
`[0xF001, 0xF002]` — no record class, no server op, no wrap-to-past-epochs primitive)"*.

**The gap is load-bearing in three places**, which is why it cannot be deferred silently:
`GrantHistory` and `HistoryGrants` in §7.3; `"history_granted"` in a **closed** vocabulary that
nothing can ever emit, which is precisely the reachability half of s1 Task 9 Property 2 already
carried as an accepted survivor; and Spec C screen 15, which is unbuildable.

**And a review already found this, and its fix was never applied.**
`docs/reviews/2026-08-12-r3-spec-review.md` finding 5 says: *"A history grant conveys
`storage_root[m..n]` and nothing else. It never conveys `eph_root` for any epoch, so granted history
contains no disappearing messages, live or expired. The grant banner MUST say so."* — plus *"Add 'or a
history grant' as a fourth item to §8.2's exclusion list."* Neither sentence is in any spec today:
`grep -n "conveys" docs/specs/*.md` returns nothing, and MASTER's `eph_root` exclusion list still
reads *"never wrapped to a recovery key, never in a provisioning bundle, deleted when its window
closes"* — three items, not four.

#### One fact that makes this cheaper than it looks

Conveying `storage_root[m]` conveys the class keys, `read_key[m]` **and** `write_key[m]`, because
`WriteKey` and `ReadKey` are both HKDF expansions of the same root
(`connect/message/writeauth.go`). That looks like it hands a grantee forgery authority at epoch *m*,
and it does not: §6.1 step (6) empties the write key of every epoch strictly older than the superseded
one, so a retired write key authorizes nothing at the server. Worth stating in the amendment, because
the first reviewer to notice it will otherwise treat it as a blocker.

And `eph_root` is safe by construction rather than by discipline: it is *"32 B fresh CSPRNG at commit,
never derived from `storage_root`"*, so a grant of `storage_root[m..n]` **cannot** convey a
disappearing message even if someone wanted it to. `TestEphRootHasNoDurableInput` already holds that.

#### Options

**Option A — a grant record carrying an X-Wing wrap of `storage_root[m..n]` to the grantee's device
leaves.** A fifth `server_attachment` kind beside the four in §5.11, indexed by `wrap_target_handle`
exactly as a device wrap is, so `WrapFetch` serves it with no new server operation. The payload is the
contiguous range as one value — 32 bytes per epoch — carried as a blob-ref record of class
`PERMANENT`, which is the shape the epoch snapshot already uses for the same reason.

- *For:* it is the existing mechanism with a different label and a different target set. Same X-Wing,
  same wrap-key derivation shape, same indexing, same record plumbing. `PERMANENT` class is what makes
  "non-erasable" true on the wire rather than only in a UI. One record per grant, not one per epoch.
- *Against:* it is a **format addition**, so it must land before A6 freezes the wire or it is a format
  break. The payload grows linearly in the epoch range — a group at epoch 5,000 granted from 0 is
  160 KB, which is why it is blob-backed rather than inline, and the bound should be stated rather
  than discovered.

**Option B — a chained history secret, so one value opens a range.** Maintain a per-epoch value from
which all earlier ones derive, and grant the single value at epoch *n*.

- *For:* a constant-size grant.
- *Against:* **reject.** It is a new hand-rolled construction, and this ledger's own revision history
  records that *"every hand-rolled cryptographic construction in this project drew a finding in every
  review round it existed."* Worse, it inverts the default: any holder of epoch *n*'s value opens every
  earlier epoch, so a member **added** at epoch *n* would receive all prior history by construction —
  the exact opposite of MASTER §11's *"New members receive keys from their join epoch forward by
  default"*, and silently.

**Option C — grant nothing; re-encrypt.** The granting owner re-sends the history as new records at
the current epoch.

- *For:* no format change at all.
- *Against:* **reject, but state it**, because it is what an implementer reaches for when nothing is
  specified. It forges authorship — a record's sender handle and its MLS authentication belong to the
  original sender, and re-sending under the owner's handle makes the owner appear to have said what
  someone else said. It multiplies storage for the one class that is never pruned. And it breaks the
  record ids everyone else's clients cite.

#### Recommendation, offered as a recommendation

**Option A**, with three things the amendment must state that no document states today:

1. **What a grant conveys, verbatim:** `storage_root[m..n]` and nothing else; never `eph_root` for any
   epoch, so granted history contains no disappearing messages, live or expired; and the banner must
   say so. This is r3 finding 5, accepted in review on 2026-08-12 and never applied.
2. **MASTER's `eph_root` exclusion list gains a fourth item** — "never in a history grant" — which is
   the other half of the same finding, and is also unapplied.
3. **What makes it non-erasable on the wire**, not only in a UI: the grant record is class
   `PERMANENT`, so the retention sweep never prunes it, and `HistoryGrants` is projected from the
   record set rather than from a local flag. Spec C forbids a dismiss affordance; nothing today makes
   the underlying record undeletable, and a rule enforced only in a renderer is a sentence.

#### What stays blocked until it is ruled

`GrantHistory` and `HistoryGrants`. `"history_granted"` remains a closed-vocabulary value no producer
can emit. Spec C screen 15. And the format freeze: this is a `server_attachment` kind, so ruling it
**after** A6 freezes the wire makes it a format break rather than an addition. **That is the reason
this one is more urgent than its feature priority suggests.**

---

## Part 3 — the two conflicts already filed

Ledger items 38 and 39, both found 2026-08-30 by the closed-group reviewer, both unresolved. They look
like two questions and they are one, so they get one principle and two consequences. **These are
readings I would take, offered with their reasons. Neither is a decision, and neither spec is edited.**

### The principle

**`closed` withdraws the ability to write new content. It does not withdraw a member's ability to
learn what is already there.**

That single rule answers both items, and the fact that it answers both is the main argument for it:
two independent rulings on the same boolean is how a field-scoped fix leaves the next field along
broken, which is what items 34, 35 and 37 each were.

### Item 38 — §7.5 says a closed group still serves `Fetch`; the build refuses it everywhere

**The conflict.** §7.5: *"submits are rejected with `REASON_REJECTED`; fetch is still served, so
members can read what they have."* `store/store.go`'s interface doc: *"a closed group answers
`ErrGroupUnavailable` everywhere afterwards, exactly as an unknown one does."* Both implementations
refuse, `contract.go` asserts that they do, and item 37's fix extended the same refusal to
`EpochKeys`.

**The reading I would take: §7.5 is right, and the interface's sentence should go.** Four reasons.

1. **§4.5's indistinguishability protects an outsider, and a fetcher is not an outsider.** The reason
   closed and unknown answer identically is to deny an existence oracle for group ids. But on the
   read path §5.1.1 makes check 6 a read-key lookup on `(group_id, read_epoch)` and check 7 the
   `req_auth` MAC under that key, and **both run before the group's closed state is consulted at
   all** — so the only party that can observe a difference between closed and unknown has already
   proved possession of that epoch's read key. Existence is answered earlier and by something else
   entirely: §5.1 check 5's known-group cuckoo filter refuses an unknown id **with no database
   read**, and closing does not remove an id from it. Merging the two answers for a key-holding
   member therefore protects nobody and costs them their history. Item 37 said the same thing about
   its own finding in as many words: *"a state disclosure, **not** an existence oracle to an
   outsider."*
2. **§7.5's clause has a stated product reason and the interface's sentence does not.** *"so members
   can read what they have"* is a promise. The interface's rule is a simplification no requirement
   produced — and this project's own §6 change process exists because that is how "§X changed and §Y
   did not" happens.
3. **Closing is not deletion, and the spec is explicit about the gap.** `close_time` is stamped and
   the sweep deletes everything after `group_reclaim_seconds`, default **30 days**. If closing blinds
   members instantly, the 30-day window buys the operator an undo and buys the user nothing, and
   closing becomes indistinguishable from deletion from where the user stands.
4. **The incoherent state is the one that shipped, and item 38 says so.** Refusing `Fetch` while
   serving the read key that authorizes it *"serves a key for a page nothing will return."* Whichever
   way this goes, the pair has to move together.

**What adopting it costs, stated so it is not discovered later.**

- **`EpochKeys` must serve a closed group** on the read path, which partly reverses item 37's fix. It
  does **not** need to know which path is asking: on the submit path, check 6 passes and §6.1 step (1)
  then refuses at `WHERE … AND NOT closed`, so the answer is unchanged. The join item 37 added stays;
  its predicate loosens from "not closed" to "exists".
- **§4.5's indistinguishability has to be restated per method**, and per **rule 5** that restatement
  must be a **derived class and not a list**: the read methods answer a closed group as they answer an
  open one; the write methods answer it as they answer an unknown one. `contract.go`'s gate already
  derives its class from `type Store interface` at run time (item 37's fix), so it can derive this
  partition too. A hand-written list of read methods is the failure mode this repository has recorded
  fourteen times.
- It reverses shipped, pinned behaviour. That is a cost, and it is **not** an argument: "the strict
  reading is already implemented" is exactly the reasoning that lets a plan settle what a spec never
  did.

**If the owner rules the other way**, the amendment is small and should be equally explicit: strike
*"fetch is still served, so members can read what they have"* from §7.5, and say that closing is a
**withdrawal** with a 30-day operator undo. What must not survive is the current position, where one
document promises reads and the other refuses them.

### Item 39 — §6.1's step (0) answers a closed group's retry with `REASON_OK`

**The conflict.** §6.1's idempotency probe is *"before any gate, before any allocation, and before the
row lock of step (1)"*, and reads `message_stream_claim` without joining the group row. So a record
that landed before the close is answered `REASON_OK{record_id}` on retry, and a stream index reused
with different content is answered `REASON_STREAM_INDEX_REUSED` — where §7.5 says a closed group's
submits are rejected with `REASON_REJECTED`. Both implementations agree, so this is a spec conflict
and not a divergence.

**The reading I would take: §6.1's step order outranks §7.5's sentence, and §7.5 should say so.**
Three reasons, and the second is decisive on its own.

1. **Step (0) is not a submit in the sense §7.5 means.** It allocates nothing, writes nothing and
   creates no state. It answers "did this exact record already land?" — and the honest answer is yes.
   §7.5's rejection is about **new content**, which is the principle above.
2. **Answering `REASON_REJECTED` to a retried commit fires the loser protocol, and that is a
   documented corruption path.** `REASON_REJECTED` has a normative client response, and Spec B binds
   the loser contract to *"any rejection of a commit submission"* — whose step 2 is the hard
   `MUST NOT` on reusing `pq_secret[n+1]`, which §12.1 A-6 calls a silent-corruption failure invisible
   in functional tests. Spec B says it in its own words: getting the retry rule backwards *"makes
   every timeout look like a fork and burns a pq_secret."* So making a closed group reject retries
   would drive clients into the exact expensive path the probe was put in front of the lock to avoid.
3. **Nobody learns anything they did not already know.** Reaching step (0) means passing §5.1 checks
   1–8, and check 7 is the `write_auth` MAC — so the party being answered holds that epoch's **write
   key**, and it is a member retrying a record it already sent. (The read key is the read path's
   authenticator, not the submit path's; it is not required here.)

**What I would keep as it is.** `REASON_STREAM_INDEX_REUSED` for a different body at a consumed index,
for the same reason: it is a refusal that writes nothing, and it is more useful than `REASON_REJECTED`
to the only party that can reach it. And both answers already carry **no** `current_epoch`, which is
item 37's rule reaching the two paths a fix scoped to step (1) does not — that stays.

**The dependency between the two items, which is the reason to rule them together.** These two
readings are consistent because they come from one principle. If the owner instead takes the
**strict** reading on 38 — a closed group is gone — then 39 must flip with it, or the build ends up
saying "this group does not exist" to a `Fetch` and "here is your record id" to a `Submit` retry,
which is worse than either position on its own. Item 39 already prices that flip: an `EXISTS` on
`message_group` inside step (0)'s statement, not a second round trip. **Ruling one of these without
the other is the thing to avoid.**
