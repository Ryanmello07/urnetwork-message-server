# [The Session Seam — the two epoch keys `sdk` may hold, and the nonce that moves under a live session] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the two `connect`-side blockers on the CP3b path that need no owner ruling —
**S2-1**, *"the epoch keys are not reachable from `sdk`, and the only workaround is a second copy of
the one derivation the record layer is proved against"*, and **S2-2**, *"`server_nonce` is captured
once at construction and cannot be rebound, so the first reconnect invalidates every record sealed
after it."* When this plan lands, a `sdk` client can obtain `read_key[e]` and `write_key[e]` for a
live session without spelling an exporter label, and can carry out spec A §5.7's normative outbox
rule — *"on reconnect, every queued record MUST be re-MAC'd against the new connection's nonce
before submission"* — without rebuilding the session and without holding a second nonce. It lands
entirely in `connect/messagegroup` on `beta/message`. It adds no production file outside that
package, no module dependency, and no import.

**And it does not reach CP3b, which is the first paragraph rather than a footnote, because plans on
this project have been read as milestones before.** CP3b is *"two clients, one group, one DURABLE
text message, every key real, no test-only key source anywhere on the path."* Two of the four
blockers the `s2` plan filed against that sentence are closed here. **S2-3** is not: `pq_secret` has
a sampler and no delivery channel, its delivery is m1 Task 14's, and m1 Task 14 is blocked on ledger
item 152 — **which is the owner's and which this plan does not touch, propose a reading of, or
pre-empt**. **S2-4** was closed on `connect` `0c14aa0` and is named here only so the count of what
remains is right. A plan that ships every task below and reports CP3b has met a bar it cannot have
met.

**The largest single act of this plan is a refusal, and it is stated before the design rather than
inside it.** The naive close of S2-1 is an accessor for `storage_root`, because `storage_root` is
the one value everything `sdk` asks for hangs off and one accessor answers every ask at once. That
accessor is not built here. `message.WriteKey`, `message.ReadKey`, `DeriveClassKeys` and
`GroupHandleKey` are all **exported**, so a consumer holding the root holds every class key, both
auth keys and the routing identifier of that epoch — the whole key schedule below `mls_secret` — and
a record layer whose proof is *"every keyed octet descends from one exporter output and two injected
values"* would have published, in one method, the value that proof is a statement about. **What
ships instead is the two TERMINAL keys and nothing else**, and the six things that are not on the
door are printed below rather than left to be inferred.

**Architecture:** One package and two doors, both on `GroupSession`, both posted to the command loop
spec A §3.6 requires. **S2-1** is a new value type in a new file, `epochkeys.go` — `EpochKeys`,
carrying the epoch, `read_key[e]` and `write_key[e]` as copies, with a `Destroy` that erases them —
and one session method that answers it. It is `ProvisionalEpoch`'s shape, deliberately, because that
type already exists in this package and answers the same question for epoch *n+1*; what differs is
that `ProvisionalEpoch` hands out **live** arrays and this hands out **copies**, for a reason derived
from the concurrency contract rather than from taste (below). **S2-2** is a setter with **no getter**
— `RebindServerNonce` — and one re-authenticator, `ReauthRecord`, which recomputes the single field
of `message.Record` that the nonce binds and refuses every record it may not recompute. Nothing else
in the package changes shape, and `keysource_test.go` is not edited.

**Tech Stack:** Go 1.26.5, standard library only. **No new module dependency and no new import in
`connect/messagegroup`** — `messagegroup/imports_test.go` pins that package's production import set
as a whole, and `connect/message` (which declares `WriteKey`, `ReadKey`, `ComputeWriteAuth` and
`Record`) is already inside it.

---

## Global Constraints

### The rules this plan is written under

These are the project's, inherited from the ten plans before this one and from `connect/mls`'s
`GATES.md`. They are restated because they change how every task below is meant to be read, and two
of them are restated in the sharper form the last two repairs produced.

**R1 — this plan supplies no test code, and neither may a task.** Roughly **thirty** plan-supplied
tests across p1–p8 could not fail; nine consecutive p1 tasks each carried one. Every task below
states **the property**, **the refusal that property owes**, and **the mutation set the implementer
must run**. The implementer derives the test. A plan that hands over a test hands over the illusion
of coverage.

**R2 — every signature in this document is illustrative of shape and not of spelling, and every one
was read from source before it was written here.** Every declaration quoted below was read at
`connect` `beta/message` `0c14aa0` out of the file that owns it, with the file and line given so a
reader can check rather than trust: `messagegroup/session.go:105-118` (the field block), `:156`
(`NewGroupSession`), `:168` (the nonce refusal), `:189` (the nonce copy), `:260` (`Close`), `:288`
(`Epoch`), `:304` (`SenderHandle`), `:335` (`AdvanceEpoch`), `:368` (`TrackSender`), `:428`
(`installEpochOnLoop`), `:480-481` (the two auth keys derived), `:553` (`zeroizeOnLoop`), `:582-583`
(`mlsSecretLabel`, `mlsSecretBytes`); `messagegroup/seal.go:88` (`SealRecord`), `:326` (the one
`ComputeWriteAuth` call), `:347` (`OpenRecord`); `messagegroup/epoch.go:125` (`ProvisionalEpoch`),
`:211-259` (its six accessors), `:329` (`Destroy`), `:362` (`unusable`);
`messagegroup/errors.go:209` (`ErrSessionServerNonce`), `:213` (`ErrSessionClosed`);
`message/record.go:105-116` (`Record`); `message/writeauth.go:158` (`WriteKey`), `:172` (`ReadKey`),
`:227` (`WriteAuthPreimage`), `:298` (`ComputeWriteAuth`), `:319` (`VerifyWriteAuth`);
`message/aad.go:164` (`AADBody`), `:205` (`AADHead`). **Read the declaration again before writing a
call.** Ledger **25** is why: `FindExtension` changed shape and seven plan call sites still spelled
the old one.

**R3 — a rule is stated in as many conditions as its source states it, and a gate's scope is derived
separately from its class.** Where a task below names a derived class, it states how many members
that class has **at that task**, so a reader can tell a gate that fatals on arrival from one that
passes vacuously.

**R4 — every property must be satisfiable by a correct implementation, falsifiable by an incorrect
one, and OBSERVABLE from the task that states it.** The third clause is this project's newest rule
and it was added because a property stated an observation route that could not see its own principal
clause. **The mechanical form: beside every property, name the ROUTE the observation takes — the
call, the decode and the FIELD — and check that every name on that route is in the task's own
`Consumes` block.** The clause has two edges and both are stated, because applying only the first is
how the pass that introduced it over-corrected: **a property must not assert what the task cannot
read, AND a property must not defer what it can.**

**This plan has one property where R4's third clause is the whole design argument, and it is said
here rather than buried in Task 4.** A rebound `server_nonce` changes exactly one octet string of
one record. Two records sealed in sequence differ in that octet string anyway, because
`stream_index` moves between them — so *"seal, rebind, seal again, observe that `write_auth` moved"*
observes a difference it cannot attribute. **The only route on which the nonce is the sole free
variable is re-authenticating THE SAME record**, which is why `ReauthRecord` is in this plan and not
deferred to `sdk`: without it S2-2's close is unobservable in the package that makes it.

**R5 — a narrowing must print its complement, and an empty complement is the dangerous reading.**
Nine rounds on this project were spent on one class: a narrowing whose complement is unprinted, or
whose justification names something in the tree today. **The mechanical form, because "derive it
from the property" failed five times as a slogan: PRINT what the narrowing REMOVED.** Every
narrowing below — the door's key set, the re-auth's field set, the ban's file set — prints the set it
excluded and the size of that set. An empty complement is the tell that the narrowing is not a
narrowing.

**R6 — a class is a QUERY and a count is not a class, and the same reading applies to a complement.**
Beside every class and beside every complement this document states, the QUERY that produces it and
the number that query returns at `0c14aa0` are printed. **Clause (a): a query is checked for what it
CONTAINS and not only for what it counts** — a stated size a query does not return is one defect, and
a query whose output does not contain the class is the worse one, because the number can be right by
coincidence while the derivation reaches nothing. **Clause (b): the sweep's own SCOPE is a query and
not a reading** — every place this document publishes a number a query could produce is in R6's
scope, not only the places written as a property.

**R7 — a secret array whose erase obligation is somebody else's is a property about that somebody,
and some task must hold it.** Arm (i), the ALIAS arm: an array a body does not own, put into a
structure that declares a `Zeroize`. Arm (ii), the ORPHAN arm: a secret array no `Zeroize` will ever
reach. **This plan creates exactly one arm-(ii) site and it is the reason `EpochKeys` is a type
rather than two return values**: a method answering `(readKey []byte, writeKey []byte, err error)`
hands a caller two live secrets with no name to erase them under, which is the orphan arm by
construction. Task 1 Property 4 holds the erase; **K1-5** is the residual the language leaves.

### Repository, branch, toolchain

| | |
|---|---|
| repository | `C:/Users/ryanm/Downloads/claude_sandbox_message/connect` |
| branch | `beta/message` |
| base commit every measurement in this document was taken at | `0c14aa0` |
| toolchain | Go 1.26.5, `GOROOT=C:/Users/ryanm/Downloads/claude_sandbox_message/toolchain/go` |
| package | `connect/messagegroup`, and nothing else |
| plan document | this file, in `msgrepo`, which is a different repository and a different writer |

**Every query in this document was run against the COMMIT and not against the working tree, with
`git grep <pattern> 0c14aa0 -- <path>` and `git show 0c14aa0:<path>`, and the reason is not
fastidiousness.** At the hour this plan was written the `connect` working tree carried an
uncommitted `messagegroup/engine.go` and an untracked `messagegroup/zzscratch_test.go` belonging to
another writer. Reading the tree would have measured somebody else's unfinished edit and published
it as a fact about `0c14aa0`. **None of the numbers below comes from `engine.go`**, and that is
itself measured rather than asserted: `git grep -c 'func (self \*GroupSession)' 0c14aa0 --
'messagegroup/engine.go'` returns nothing, so that file declares no member of any class this plan
derives.

### The measurements this plan rests on, with the query beside each number

**R6, applied to this document's own numbers.** Every number below is one a reader can reproduce in
one command at `0c14aa0`.

**M1 — `GroupSession`'s exported method set is SEVEN, and none of the seven answers a key.**

```
git grep -n 'func (self \*GroupSession) [A-Z]' 0c14aa0 -- 'messagegroup/*.go' | grep -v _test
```

Returns 7 lines: `SealRecord` and `OpenRecord` (`seal.go:88`, `:347`), and `Close`, `Epoch`,
`SenderHandle`, `AdvanceEpoch`, `TrackSender` (`session.go:260`, `:288`, `:304`, `:335`, `:368`).
**R6 clause (a):** piping the same query through `grep -c 'SenderHandle'` returns 1, so the answer
contains the class rather than merely counting to it.

**M2 — the whole method set of `*GroupSession` is SEVENTEEN, which is the class the landed loop gate
derives over.**

```
git grep -c 'func (self \*GroupSession)' 0c14aa0 -- 'messagegroup/*.go' | grep -v _test
```

Returns `seal.go:5` and `session.go:12`. This is the denominator
`TestEveryMethodOfAGroupSessionReachesItsStateOnlyOnTheLoop` (`session_test.go:39`) reads off the
syntax tree; this plan adds three members to it and the gate covers all three with no edit.

**M3 — `server_nonce`'s whole production footprint in `messagegroup` is FIVE lines, and one of them
is a read.**

```
git grep -n 'serverNonce' 0c14aa0 -- 'messagegroup/*.go' | grep -v _test
```

Returns `session.go:111` (the field), `:157` (the parameter), `:168` (the emptiness refusal), `:189`
(the copy the constructor takes) and `seal.go:326` (the one read). **There is no sixth line, and
that is S2-2 stated as a measurement rather than as a claim**: a value with one writer, which is the
constructor, and no setter.

**M4 — `read_key` has ZERO production readers, and this plan gives it its first.**

```
git grep -n 'readKey' 0c14aa0 -- 'messagegroup/*.go' | grep -v _test
```

Returns 5 lines — `session.go:110` (the field), `:475` and `:563` (two erases), `:481` (the
derivation `message.ReadKey(root)`), `:569` (the nil after the second erase). **Not one of the five
is a read.** The session has derived `read_key[e]` at every epoch since the field landed, erased it
at every rotation, and nothing has ever asked for it. **R6 clause (a):** piping through
`grep -c ':481'` returns 1.

**M5 — `ComputeWriteAuth` is called ONCE in this package, and the query returns two lines of which
one is a comment.**

```
git grep -n 'ComputeWriteAuth' 0c14aa0 -- 'messagegroup/*.go' | grep -v _test
```

Returns `seal.go:40` (prose in the file header) and `seal.go:326` (the call). **The class is the
call sites and it has ONE member; the answer has two lines.** This is exactly R6 clause (a)'s
subject: a reader who counted the lines would publish two and be wrong about a class of one. Piping
through `grep -c 'record.WriteAuth = '` returns 1.

**M6 — `server_nonce` reaches exactly ONE production file of `connect/message`.**

```
git grep -c 'serverNonce' 0c14aa0 -- 'message/*.go' | grep -v _test
```

Returns `message/writeauth.go:18` and **nothing else** — not `aad.go`, not `record.go`, not
`codec.go`. `AADHead` (`aad.go:205`) and `AADBody` (`aad.go:164`) do not take a nonce and do not
mention one. **This is the whole blast radius of S2-2 in one line: neither AEAD preimage binds the
nonce, so no ciphertext of any record is a function of it.**

**M7 — `message.Record` has FIVE fields and the nonce binds ONE.**

```
git show 0c14aa0:message/record.go | sed -n '/^type Record struct/,/^}/p'
```

Returns `RecordId`, `Header`, `CtHead`, `CtBody`, `WriteAuth`. Combined with M6: `WriteAuth` is the
only one of the five whose value is a function of `server_nonce`. **The complement is FOUR and it is
printed**: `RecordId` is server-assigned and authenticated by nothing; `Header`, `CtHead` and
`CtBody` are sealed under `record_key[i]` against two aads that carry no nonce.

**M8 — the session's erase class is EIGHT sites, and this plan's door carries TWO of them.**

```
git show 0c14aa0:messagegroup/session.go \
  | sed -n '/func (self \*GroupSession) zeroizeOnLoop/,/^}/p' \
  | grep -nE 'zeroize\(self\.|\.Zeroize\(\)'
```

Returns 8 lines: the sender ratchets, `receivers`, `classKeys`, `storageRoot`, `writeKey`,
`readKey`, `groupHandleKey`, `pqSecret`. This is the class the narrowing below is stated over, and
`zeroizeOnLoop` is the right derivation for it because its own comment says why every field is named
there rather than delegated.

**M9 — `messagegroup` has TWENTY test files, and the ban in Task 3 covers TWO of them.**

```
git ls-tree -r 0c14aa0 --name-only messagegroup/ | grep -c '_test.go$'
```

Returns 20.

**M10 — `keysource_test.go` declares FIVE tests, not the three its own header's phrase "all three
tests" names.**

```
git grep -n '^func Test' 0c14aa0 -- 'messagegroup/keysource_test.go'
```

Returns `TestEveryKeyedOctetOfARecordIsReproducibleFromTheExporterAndTheTwoInjectedValuesAlone`
(`:576`), `TestFlippingAnyBitOfTheExporterOutputChangesEveryKeyedOctetOfARecord` (`:642`),
`TestTheTranscribedRetentionAndSizeAgreeWithThePackage` (`:689`),
`TestNothingOnTheReproductionsSideOfTheComparisonComesFromTheModule` (`:1420`) and
`TestTheFixtureCanHandTheReproductionNothingItCouldSealWith` (`:1615`). **The header's "three"
counts the record-level tests and the two gates are the other two** — which is not a defect in that
file, since its own prose distinguishes them, but a plan that said "the three tests" and meant the
file would be wrong by two.

### S2-1, measured: what is actually missing, and what a second copy would have been

The `s2` plan's filed cause is right and its consequence is right. What is worth stating precisely
is **which** derivation would have been copied, because the answer is narrower than the item's own
sentence suggests and it is what makes the narrowing below possible.

`message.WriteKey` and `message.ReadKey` are **exported** (`message/writeauth.go:158`, `:172`), and
`connect/message` is a package `sdk` may import. So the missing thing is not the two expansions. The
missing thing is their **argument**: `storage_root[e]`, which is `StorageRoot(mls_secret, pq_secret)`
over `mls_secret = handle.Export("URmessage/v1/storage", nil, 32)` — and `mlsSecretLabel` and
`mlsSecretBytes` are **unexported constants of `session.go`** (`:582-583`). A `sdk` that wanted the
keys would have had to spell that label and that length itself, which is a second statement of the
one value every key of the epoch hangs off. `session.go`'s own comment on those two constants says
why that is fatal rather than untidy: *"two callers exporting under two labels would be two members
of one group who agree about nothing."*

**So the ask is a reachable `write_key[e]` and `read_key[e]`, and the naive close is a reachable
`storage_root[e]`. They are not the same door and the difference is one-way.** Both expansions are
`HKDF-Expand` under a label, so a holder of either key cannot recover the root; a holder of the root
derives both keys, all three class keys (`DeriveClassKeys`), `group_handle_key` (`GroupHandleKey`)
and therefore every record key of the epoch. **The door is the keys.**

**The narrowing, and its complement, printed.** The class is the session's own key material, derived
over `zeroizeOnLoop`'s erase sites rather than listed (M8): **EIGHT**. The door carries **TWO**.
**The complement is SIX**, and here it is:

| not on the door | why, and what would have to change to put it there |
|---|---|
| `storageRoot` | every other row hangs off it, and `message.WriteKey`, `message.ReadKey`, `DeriveClassKeys` and `GroupHandleKey` are all exported — so this accessor is the whole epoch key schedule published as one method. Its only consumer is spec A §5.3's restart, and **J1-9** ruled the restart off the CP3b prefix. **K1-1** |
| `groupHandleKey` | the routing identifier, and the value §5.3 and MASTER §8 disagree about which of the two a device persists. That disagreement is **M1-4**, and shipping an accessor for either half would settle it by shipping. **K1-1** |
| `classKeys` | the three retention-class ladder roots. Every consumer of one goes through `SealRecord` or `OpenRecord`, which is where the ladder and its window live; a caller holding a class key holds every record key of that class at that epoch |
| `pqSecret` | MASTER §7's per-epoch PQ independence. Its delivery is **S2-3** and m1 Task 14's, and that is blocked on ledger item 152, which this plan does not touch |
| the sender ratchets | `record_key[i]` for this device's own ladder — the octets forward secrecy is about, and the reason `AdvanceEpoch` drops every one of them |
| `receivers` | the same thing for every tracked peer, plus the skipped-key window |

**And what this derivation CANNOT see, stated rather than implied: `mls_secret` is not a field.** It
is a local in `installEpochOnLoop` (`session.go:429`) with a `defer zeroize` on it, so a class
derived over the session's fields does not contain it and cannot ban it. It is named here as the
seventh excluded value, and the thing that keeps it off the door is that no task below writes an
accessor for it — which is an argument about this diff and not a gate.

Guardrail **G6** is the neighbouring rule and it is quoted rather than paraphrased, because the
paraphrase is wrong in a way that matters. G6's row in spec A §5.9 reads *"`epoch_secret` exported
instead of the two named secrets"*, defended by *"§3.3: `EpochSecretName` is a closed two-value
enum"*. Its subject is `mls.Group.EpochSecret` and the MLS `epoch_secret`, from which §3.3 notes
`confirmation_key` and `membership_key` would also fall out. **Neither `read_key[e]` nor
`write_key[e]` is `epoch_secret`, and neither is reachable from one**: `mls_secret` is an RFC 9420
§8.5 exporter output, the root is an `HKDF-Extract` over it, and both keys are one-way expansions
off the root. **G6 is not touched by this plan, and the door that would have come nearest to it — an
accessor for `mls_secret` or for the root — is the one this plan refuses to build.**

### S2-2, measured: the blast radius, field by field

The `s2` item asks three questions. Each is answered here with the query that answers it.

**Which sealed values bind the nonce.** **Exactly one field of `message.Record`: `WriteAuth`.** M6
and M7 together are the whole derivation: `serverNonce` appears in exactly one production file of
`connect/message` (`writeauth.go`), so no other preimage in that package takes one; `AADHead` and
`AADBody` have no nonce parameter and no nonce mention; and `Record` has five fields. **The
complement is FOUR and it is printed above.** A reader who expected the nonce to be inside the aads
— which is where a reader's instinct puts a connection-scoped anti-replay value — can check it in one
command.

**What a rebind must invalidate or recompute.** **`record.WriteAuth`, and nothing else.** Every
input `ComputeWriteAuth` takes other than the key and the nonce is already on the record:
`WriteAuthPreimage(serverNonce, h *RecordHeader, ctHead []byte, serverAttachment []byte)`
(`writeauth.go:227`). So a rebind is one `HMAC-SHA-256` over a preimage rebuilt from the record in
hand. **It is NOT a re-seal**: no AEAD runs, no `record_key` rung is consumed, the sender ratchet
does not move, and no `stream_index` is reserved. That is what makes `ReauthRecord` a legal
operation at all, and it is why spec A §5.7's outbox rule can say *"re-MAC'd"* for the nonce case
and *"discarded and re-sealed at the new epoch, consuming a fresh `stream_index`"* for the epoch
case. **Two different words for two different costs, and this plan implements the first and refuses
the second.**

**Whether anything already sealed becomes unopenable. NO — and this is the finding most likely to be
got wrong, so it is stated with its query.** `OpenRecord` never reads `WriteAuth` and never reads a
nonce: M3 shows the only read of `serverNonce` in the package is `seal.go:326`, which is on
`SealRecord`'s path, and M5 shows `WriteAuth` has exactly one producer and no consumer in this
package. Confidentiality is under `record_key[i]`, which the nonce does not reach. **What a stale
nonce costs is SERVER ACCEPTANCE, not readability**: the refusal happens on the server's side of the
wire, at `VerifyWriteAuth` against that connection's own nonce (`msgrepo/api/submit.go:458`). A
record that was accepted before the reconnect stays readable forever — spec A §2.4 has the server
rebuild `record_bytes` on the read path with `write_auth` left **zero**, precisely because the mac
cannot be reconstructed at all. **So S2-2 is a liveness defect and not a confidentiality or
durability one**, and the `s2` item's *"invalidates every record sealed after it"* is exactly right
about submission and must not be read as being about the records.

**And the rotation is per Hello rather than per transport connection, which is why "the first
reconnect" is the right phrase.** Spec A §5.7, as ruled on 2026-08-26, defines a connection as
*"one `Hello` epoch of a `client_id`"*: *"every `Hello` mints a fresh nonce and destroys the previous
one outright, with no history and no grace window."* The shipped server agrees —
`msgrepo/peer/hello.go:57` calls `connections.Open(arrived.clientId)`, which replaces
unconditionally, and `msgrepo/peer/connection.go:138` draws 32 fresh octets for the new one. **The
residual §5.7 names is the other direction**: a client that reconnects *without* saying `Hello`
keeps its nonce and the server cannot tell — which is why §5.7 makes the outbox rule **normative for
the guarantee** rather than merely for correctness, and is the sentence this plan's two doors exist
to make satisfiable.

### What this plan does to `keysource_test.go`'s property

CP3b's definition is held as a standing test in one file, and a plan that adds doors to the type
that file is written about owes an account of what it did to it. This is that account, in one place,
and every task below restates the part of it that task owns.

**(1) The file is not edited. That is a check and not an intention.** No task's `Files` block names
`messagegroup/keysource_test.go`, and the definition of done requires `git diff --stat` over the
plan's whole range to show it absent. A plan that had to retune the proof of the bar in order to
close a blocker would be reporting that the blocker was closed and the bar was moved.

**(2) The three record-level tests stay green because NO OCTET MOVES.** The property is *"the whole
sealed record is rebuilt, byte for byte, from three values and nothing else"* — `mls_secret` off the
real group, the injected `pq_secret`, the injected `server_nonce`. `EpochKeys` derives nothing: it
**copies** two fields the session already holds, and both were already derived by
`installEpochOnLoop` at every epoch. `RebindServerNonce` writes a field the fixture never calls it
on. `ReauthRecord` is not on `SealRecord`'s or `OpenRecord`'s path. **Neither door adds a key source,
because neither door produces a key.**

**(3) One sentence of the file's header becomes conditional, and that is the whole of the damage.**
The header names its three values, and of the third it says *"`server_nonce` — the value the
constructor was injected with."* Before this plan that sentence is unconditional, because there is no
setter. After it the sentence is *"the value the constructor was injected with, unless something
rebound it"*, and the fixture is what makes the condition true. **The close is a property and not a
promise: Task 3 Property 5 bans `RebindServerNonce` from `keysource_test.go` and from
`sessionfixture_test.go`, derived over the package's test source, with the complement — the other
eighteen test files, which may call it freely — printed.**

**(4) The gate that protects the reproduction widens on its own, and the plan MEASURES that rather
than asserting it.** `TestNothingOnTheReproductionsSideOfTheComparisonComesFromTheModule`
(`keysource_test.go:1420`) derives its banned class as *"every name the MODULE declares"*, read off
`go.mod` and the import graph — *"a package the next import adds is in it with no edit here.
`message.WriteKey` is a member. So is a constant nobody has written yet."* **`EpochKeys` and its four
methods are members of that class on the commit that declares them.** So the one thing this plan
makes newly attractive — *"the reproduction could just ask the session for `write_key` instead of
expanding `write/v1`"* — is refused by a gate that needs no edit. Task 5 Property 2 holds that as a
mutation rather than as a sentence.

**(5) And the two gates fire in a known order, which is stated because the obvious mutation cannot
reach the second one first.** The reproduction has no session in scope: what crosses to it is
`keySourceSealed`, and `TestTheFixtureCanHandTheReproductionNothingItCouldSealWith`
(`keysource_test.go:1615`) judges that boundary **by the type reached**, admitting exactly one —
`message.Record`, reached directly. So a mutant that put an `*EpochKeys` on the boundary fails at the
**boundary** gate, before the module gate ever sees a call. Task 5's mutation set carries both forms
and names which fires for each. **A plan that claimed the module gate as the first line of defence
here would be wrong about its own tree.**

### What `keysource_test.go` still cannot see after this plan

R5 applied to the proof itself. The file already prints six things it cannot see; this plan adds
three, and they are printed here because an unprinted complement is the dangerous reading.

**(a) A no-op `RebindServerNonce`.** The reproduction's nonce is the injected one and the fixture
never rebinds, so a setter that dropped its argument on the floor moves no octet of any record that
file builds and **all five of its tests stay green**. *CP3b's defining test cannot see S2-2's defect,
in either direction.* What sees it is Task 3 Property 2 and Task 4 Property 1, and nothing else in
the tree.

**(b) A `ReauthRecord` that macs under the wrong key of the right epoch.** `read_key[e]` and
`write_key[e]` are both 32 octets off the same root; a re-auth under the wrong one produces a
well-formed tag that no server verifies. No record on `keysource_test.go`'s path is ever re-authed,
so that file is silent about it. Task 4 Property 3 is where it is caught, and mutation 8 is what
proves the catch works.

**(c) `EpochKeys` answering the right key of the wrong epoch.** A door that cached its answer across
an `AdvanceEpoch` would hand out a superseded `write_key` with a current epoch number on it.
`keysource_test.go` asserts its fixture is at epoch 0 and reproduces nothing at epoch > 0 — its own
exclusion (3) — so it cannot see this at all. Task 2 Property 3 holds it.

### The landed gates this plan's code must satisfy from its first commit

Additive to an exported surface is not additive to a package whose gates derive their classes off
it. **FIVE landed gates read the class this plan adds members to, and not one of them needs an
edit** — which is the argument for adding members in the shapes below rather than in convenient
ones.

| gate | where | what it holds about this plan's code |
|---|---|---|
| `TestEveryMethodOfAGroupSessionReachesItsStateOnlyOnTheLoop` | `session_test.go:39` | all three new session methods must post through `do`. A `RebindServerNonce` that wrote `self.serverNonce` directly goes RED here, because `serverNonce` is a loop-owned field by that gate's own derivation |
| `TestAGroupSessionHoldsNoLock` | `session_test.go:94` | no mutex may be added to make the setter safe |
| `TestCloseIsIdempotentStopsTheLoopAndErasesEveryKey` | `session_test.go:370` | this plan adds no session field, so the erase class does not move; a door that cached a copy on the session would move it and go RED here |
| `TestNothingOnTheReproductionsSideOfTheComparisonComesFromTheModule` | `keysource_test.go:1420` | the four new exported names join its banned class with no edit |
| `TestTheFixtureCanHandTheReproductionNothingItCouldSealWith` | `keysource_test.go:1615` | `*EpochKeys` may not cross the fixture boundary |

**The complement, printed: the gates in this package that this plan does NOT move.**
`imports_test.go`'s production-import pin (no import is added), `entropy_test.go`,
`zeroize_test.go`'s `noinline` class (the new erase bodies join it and must carry the pragma —
that is a member, not an exemption), and every `_test.go` file under `message/` and `mls/`. The set
is not empty, which is the point of printing it.

### House style

Receiver is `self`. Refusals are typed sentinels in `errors.go` with `%w`. Every erase goes through
`zeroize` and every body that erases a field it then overwrites carries `//go:noinline`, per that
file's own class. No `unsafe`. No new import.

---

## Interfaces consumed from other plans

Everything below exists and compiles at `0c14aa0`. Shapes are described so the plan is readable;
**their spellings are not normative (R2)** and every one must be read out of the file that declares
it before a call is written.

```go
// connect/messagegroup/session.go — the type this whole plan hangs two doors off.
// Seven exported methods at 0c14aa0 and none answers a key (M1). Its state is
// reached from the loop goroutine ONLY, through do().
type GroupSession struct{ /* 17 unexported fields; see :105-118 */ }
func (self *GroupSession) do(action func()) error        // :241, unexported
func (self *GroupSession) Epoch() (uint64, error)        // :288
func (self *GroupSession) AdvanceEpoch(pqSecret []byte) error  // :335
func (self *GroupSession) SealRecord(class message.RetentionClass, ephBucket uint8,
    isCommit bool, headPlain []byte, bodyPlain []byte, expireAt uint64,
    serverAttachment *message.ServerAttachment) (*message.Record, error)   // seal.go:88
func (self *GroupSession) OpenRecord(record *message.Record) ([]byte, []byte, error) // seal.go:347
```

```go
// connect/messagegroup/epoch.go — the SHAPE this plan copies, for epoch n+1.
// Six accessors, each closed off a destroyed flag through one door check, and
// a Destroy that erases every secret and is safe on the zero value.
type ProvisionalEpoch struct{ /* ... */ }
func (self *ProvisionalEpoch) StorageRoot() ([]byte, error)   // :219, LIVE not copied
func (self *ProvisionalEpoch) WriteKey() ([]byte, error)      // :227
func (self *ProvisionalEpoch) Destroy()                       // :329
func (self *ProvisionalEpoch) unusable(what string) error     // :362, unexported
```

**`ProvisionalEpoch` has no `ReadKey`, and that is measured rather than assumed**:
`git grep -c 'func (self \*ProvisionalEpoch) [A-Z]' 0c14aa0 -- 'messagegroup/epoch.go'` returns
**9**, and the nine are `Epoch`, `StorageRoot`, `WriteKey`, `EphRoot`, `PqSecret`, `Wraps`,
`InstallWraps`, `Destroyed` and `Destroy`. **R6 clause (a):** piping the unqualified form through
`grep -c ReadKey` returns 0, which is the tell rather than the count. This plan does not add one — **K1-6** is why, and epoch
*n+1*'s read key is not on the CP3b prefix.

```go
// connect/message/writeauth.go — the two derivations and the one mac. All exported,
// all reachable from sdk today, all taking their argument by value.
func WriteKey(storageRoot []byte) []byte        // :158, HKDF-Expand(root, "write/v1", 32)
func ReadKey(storageRootEpoch []byte) []byte    // :172
func WriteAuthPreimage(serverNonce []byte, h *RecordHeader, ctHead []byte,
    serverAttachment []byte) []byte             // :227, PANICS on an empty nonce or a short key
func ComputeWriteAuth(writeKey []byte, serverNonce []byte, h *RecordHeader,
    ctHead []byte, serverAttachment []byte) [32]byte   // :298
func VerifyWriteAuth(writeKey []byte, serverNonce []byte, r *Record) bool  // :319, server side
```

**The panic/answer-false split is the file's own and it is load-bearing for Task 4.**
`writeauth.go:60-76` argues it: the computing half panics with the sentinel as the panic value
because an empty nonce there *"is a lifecycle bug in the caller and cannot arrive from the
network"*; the verifying half answers false because it *"is remotely reachable and a panic there
would be a client that can stop the process."* **`ReauthRecord` is on the computing side**, so every
refusal it owes must be taken **before** `ComputeWriteAuth` is reached, and a refusal that arrives as
a recovered panic is not a refusal.

```go
// connect/message/record.go — five fields, and the nonce binds one (M7).
type Record struct {
    RecordId  uint64
    Header    RecordHeader
    CtHead    []byte
    CtBody    []byte
    WriteAuth [32]byte
}
var ErrRecordNil error   // message/errors.go
```

```go
// connect/messagegroup/errors.go — the sentinels this plan reuses rather than twins.
var ErrSessionServerNonce error  // :209, "requires the submitting connection's server nonce"
var ErrSessionClosed error       // :213
var ErrRecordNotForThisSession error  // the group-id / epoch refusal OpenRecord already makes
```

---

## Interfaces produced by this plan

Every later plan writes its `Consumes` block against these. Each is restated inside the task that
creates it. Shapes, not spellings (R2).

```go
// connect/messagegroup/epochkeys.go — Task 1. The S2-1 door's value.
// It carries COPIES and owns their erase; the session's own arrays are not aliased.
type EpochKeys struct {
    epoch     uint64
    readKey   []byte
    writeKey  []byte
    destroyed bool
}
func (self *EpochKeys) Epoch() (uint64, error)
func (self *EpochKeys) ReadKey() ([]byte, error)
func (self *EpochKeys) WriteKey() ([]byte, error)
func (self *EpochKeys) Destroy()
```

```go
// connect/messagegroup/errors.go — Task 1.
var ErrEpochKeysDestroyed error  // an accessor on a destroyed or zero-valued EpochKeys
```

```go
// connect/messagegroup/session.go — Tasks 2 and 3. Two of the three new session methods.
// There is NO ServerNonce getter and Task 3 Property 4 is what keeps it that way.
func (self *GroupSession) EpochKeys() (*EpochKeys, error)
func (self *GroupSession) RebindServerNonce(serverNonce []byte) error
```

```go
// connect/messagegroup/seal.go — Task 4. The third, and the only route on which a
// rebind is observable with the nonce as the sole free variable.
func (self *GroupSession) ReauthRecord(record *message.Record) error
```

**`GroupSession` is not in this list and neither is any field of it.** This plan adds three methods
to a landed type and zero fields, which is what keeps `TestCloseIsIdempotentStopsTheLoopAndErases
EveryKey`'s erase class where it is.

---

## File Structure

Every file created or modified by this plan, and its single responsibility.

| File | Responsibility |
|---|---|
| `connect/messagegroup/epochkeys.go` | **create:** Task 1. `EpochKeys`, its three accessors, its `Destroy`, and the one door check both are closed off — `ProvisionalEpoch`'s shape, with the copy-versus-live divergence argued in the file header rather than left for a reader to notice |
| `connect/messagegroup/errors.go` | **modify:** Task 1. `ErrEpochKeysDestroyed` in. Nothing comes out |
| `connect/messagegroup/session.go` | **modify:** Tasks 2 and 3. `EpochKeys()` and `RebindServerNonce()`, both posting through `do`. **No field is added and no field is removed**, which the `Close` erase gate reads |
| `connect/messagegroup/seal.go` | **modify:** Task 4. `ReauthRecord` and its `reauthRecordOnLoop` body, beside the one landed `ComputeWriteAuth` call at `:326` so the two macs of this package sit in one file and a reader comparing them does not have to open two |
| `connect/messagegroup/epochkeys_test.go` | **create:** Tasks 1 and 2. The value's refusals, the copy discipline, the erase, and the door's epoch agreement |
| `connect/messagegroup/noncerebind_test.go` | **create:** Tasks 3, 4 and 5. The rebind, the re-auth, the field-scope class, the no-getter class and the two-file ban. **Named for the subject and not for the file it tests**, because `session_test.go` and `seal_test.go` both already exist and a task that appended to either would put a new derived class inside a file whose gates derive their own |
| `connect/messagegroup/doc.go` | **modify:** Task 6. The package's honest-inventory paragraph, which names what this package cannot do; two of its sentences stop being true on Task 4's commit |
| `msgrepo/docs/plans/2026-08-12-slice1-interface-registry.md` | **modify:** Task 6. The registry entry for what this plan produced |

**`connect/messagegroup/keysource_test.go` is deliberately absent from this table**, and its absence
is checked rather than intended — see the definition of done.

---

## How to read a task

Each task has **Files**, an **Interfaces** block naming exactly what it consumes and what it
produces, and numbered steps. The steps are always the same six, and steps 1 and 5 are where the
work is.

1. **Derive the property and write the failing test.** The task states the property, the refusal
   that property owes, and — separately, per R3 — the scope the gate must derive. It does **not**
   state the test. Read every signature you call out of source (R2).
2. **Run it and watch it fail for the stated reason.** A test that fails to compile has not yet
   failed for the stated reason.
3. **Write the minimal implementation.**
4. **Run it and watch it pass.**
5. **Mutation-test.** Apply each numbered mutation, run the targeted `-run` first, and record the
   result. Any mutation that survives the targeted run is re-run against the full package. **A
   surviving mutation is a defect in the test, not a curiosity**: fix the test and re-run the whole
   set. Record survivors and their reason in the commit message.
6. **Commit.**

**On counting tests while doing this:** `-run 'Test'` filters subtests too, and Go splits the pattern
on `/` at every nesting level, so a targeted run discards roughly two thirds of the entries over
these trees. Use a targeted regex for the mutation loop and an **unfiltered** run for any number that
goes into a commit message.

---

## Wave 1 — S2-1, the two keys and the door that answers them (Tasks 1–2)

**This wave needs no other work and no ruling.** It is additive to `connect/messagegroup`, touches
no wire byte, moves no octet of any record, and is independent of Wave 2 — the two waves share no
file except `session.go` and no symbol at all.

### Task 1: `EpochKeys` — two keys, six refusals, and the copy that is not an alias

**Files:**
- Create: `connect/messagegroup/epochkeys.go`
- Modify: `connect/messagegroup/errors.go` (`ErrEpochKeysDestroyed` in)
- Test: `connect/messagegroup/epochkeys_test.go`

**Interfaces:**
- Consumes: nothing of this plan. From the landed tree: `zeroize` (`zeroize.go:55`), which is this
  package's one erase and the reason `Destroy`'s body carries `//go:noinline`; and
  `ProvisionalEpoch`'s door-check shape (`epoch.go:362`) as a **pattern read from source**, not as a
  call — `unusable` is unexported and belongs to that type.
  **And the instruments the properties beneath this line are OBSERVED through (R4's third clause):**
  a second `[]byte` header over the same backing array, which is how `zeroize_test.go` already
  observes an erase without letting a reslice satisfy it, and which is the only route Property 4's
  principal clause has.
- Produces: `EpochKeys`, its `Epoch`, `ReadKey`, `WriteKey` and `Destroy`, and `ErrEpochKeysDestroyed`.

**Why this is a type and not two return values, stated before the properties because it is the
decision the properties are written around.** A method answering `(readKey, writeKey []byte, err
error)` hands a caller two live secrets under no name, which is R7 arm (ii) — the orphan arm — by
construction: nothing will ever erase them and nothing can be asked to. A type carries the erase
obligation as a method a caller can defer, which is the same answer `ProvisionalEpoch` gives for the
same question one epoch over.

**Why COPIES here where `ProvisionalEpoch` hands out LIVE arrays, which is a divergence from the
sibling type and therefore owes a reason.** `ProvisionalEpoch` is built by one goroutine and read by
that goroutine; nothing else owns its arrays, so a live answer costs nothing. `GroupSession`'s
`writeKey` and `readKey` are written **and erased** by the loop goroutine — `installEpochOnLoop`
zeroizes both before overwriting them at every `AdvanceEpoch` (`session.go:474-475`), and
`zeroizeOnLoop` zeroizes both at `Close` (`:562-563`). A live answer would hand a caller a window
onto a field another goroutine writes, with no happens-before between the read and the write: a data
race in the exact place spec A §3.6 built a command loop to make impossible. **So the copy is
derived from the concurrency contract and not from taste, and the consequence is real and is filed:
a copy outlives the epoch it came from (K1-5).**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — an `EpochKeys` answers exactly three values, and each is the one the session held
  for that epoch.** `Epoch()` is the epoch number the door was opened at; `ReadKey()` is
  `message.ReadKey(storage_root[e])`; `WriteKey()` is `message.WriteKey(storage_root[e])`. Each is 32
  octets.
  *Refusal owed:* none on this path.
  *Route:* construct the value directly in-package with known octets, call the three accessors, read
  the returned slices. The comparison is against the octets that went in, not against a re-derivation
  — Task 2 is where the values are tied to a real session.

  **Property 2 — a destroyed `EpochKeys` answers a typed refusal on every accessor, and the zero
  value answers the same one.** Both are *"this value has nothing to tell you"*, and one sentinel
  covers them because a caller's question is the same in both cases and it matches it with one
  `errors.Is`. This is `ProvisionalEpoch`'s reasoning (`epoch.go:362-377`) applied to the sibling
  type rather than restated as a new decision.
  *Refusal owed:* `ErrEpochKeysDestroyed`, wrapped with `%w` and naming which door was tried, on
  `Epoch`, `ReadKey` and `WriteKey`.
  *Route:* call each accessor twice — once on a `Destroy`ed value and once on `var keys EpochKeys` —
  and match with `errors.Is`. **Both arms are the property; a test that ran only the destroyed arm
  would leave the zero value answering nil keys and no error**, which is the exact shape
  `ErrProvisionalEpochDestroyed`'s own doc comment names.
  *Scope to derive, separately from the class (R3):* the class is **every exported method of
  `EpochKeys` that answers a value**, derived off the type's own method set rather than listed, and
  at this task **that class is three members** — `Epoch`, `ReadKey`, `WriteKey`. `Destroy` is not a
  member: it answers nothing and must be safe on both. The query is
  `git grep -n 'func (self \*EpochKeys)' -- 'messagegroup/epochkeys.go'`, which returns four lines at
  this task's commit, of which three are the class. **The complement is ONE and it is `Destroy`.**

  **Property 3 — `Destroy` is idempotent and safe on the zero value.** A destructor is the one method
  a caller writes in a `defer` above the construction it is destroying, so a destructor that panicked
  there would take the process down on the cleanup path of the failure it was cleaning up.
  *Refusal owed:* none; `Destroy` answers nothing in either case.
  *Route:* `Destroy` twice on a live value and once on `var keys EpochKeys`; the observation is that
  neither panics and that the accessors afterwards answer Property 2's sentinel.

  **Property 4 — `Destroy` erases the octets and not just the slice headers, and the erase is
  observable on the backing array.** The property's subject is the ARRAY, because a body that set
  `self.readKey = nil` and nothing else leaves 32 octets of key material on the heap under a header
  the caller may still hold.
  *Refusal owed:* none.
  *Route:* take a second `[]byte` header over the same backing array **before** `Destroy`, call
  `Destroy`, read the second header — `zeroize_test.go`'s own shape, and the only route that cannot
  be satisfied by a reslice. **This is the clause R4's third edge is about: a property that observed
  the value the accessor returned afterwards would be observing a refusal, not an erase.**
  *And the pragma is part of the property, not of the style:* `Destroy`'s body hands arrays that
  outlive the call to `zeroize`, so it joins this package's `//go:noinline` erase class. A body
  without it is a body the compiler may prove dead.

  **Property 5 — the value holds no alias of anything it did not make.** Every array `EpochKeys`
  holds was copied into it; nothing it holds is a slice header some other structure also holds.
  *Refusal owed:* none; this is a property about the constructor and Task 2's caller, and it is
  stated here because the type is where it must be true.
  *Route:* the source of `epochkeys.go`, read for the absence of any assignment of a parameter slice
  to a field without a copy. **Stated as an observation over ONE file rather than over the package,
  because at this task the caller does not exist yet — Task 2 Property 4 is where it becomes a
  property about a live session, and this half is what that half is checked against.** That class is
  **one** member at this task — `epochkeys.go` — and the complement is every other production file of
  the package, which holds no `EpochKeys` and cannot construct one.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Have `ReadKey` answer the `writeKey` field. **Property 1 must fail**, and the failure must name
     which accessor answered which key rather than only that 32 octets disagreed.
  2. Drop the door check from `WriteKey` alone. **Property 2 must fail** on one of its three class
     members, and the gate's message must name the member — a failure that said "an accessor" would
     leave an implementer guessing which.
  3. Make the door check test `destroyed` and not the zero value. **Property 2 must fail** on the
     zero-value arm while the destroyed arm stays green. This is the mutant that survives a test
     written with one arm.
  4. Make `Destroy` return early on the second call **before** setting `destroyed`. **Property 3 must
     fail.**
  5. Have `Destroy` set the three fields to nil without calling `zeroize`. **Property 4 must fail**
     on the second header, and **Property 2 must still pass** — which is what proves Property 4 is
     observing the array rather than the accessor.
  6. Remove `//go:noinline` from `Destroy`. **Property 4 must fail** under an optimising build. Record
     the result honestly: if it survives at this toolchain version, say so in the commit message and
     leave the pragma in — the class it belongs to is this package's, and a pragma kept because the
     class requires it is not the same as a pragma kept because a mutant died.
  7. Have the constructor assign a parameter slice to `self.writeKey` without copying. **Property 5
     must fail**, and Task 2 Property 4 must fail on the commit after next — the two halves of one
     defect, and mutation 7 is the one that shows they are one.

- [ ] **Step 6: Commit**

### Task 2: `GroupSession.EpochKeys()` — the door, on the loop, and `read_key`'s first reader

**Files:**
- Modify: `connect/messagegroup/session.go` (the new method; **no field added**)
- Test: `connect/messagegroup/epochkeys_test.go`

**Interfaces:**
- Consumes: Task 1's `EpochKeys`, `EpochKeys.Epoch`, `EpochKeys.ReadKey`, `EpochKeys.WriteKey` and
  `EpochKeys.Destroy`. From the landed tree: `GroupSession.do` (`session.go:241`), which every method
  that touches session state posts through; `GroupSession.Epoch` (`:288`) and
  `GroupSession.AdvanceEpoch` (`:335`), which are the two halves of Property 3's route;
  `message.WriteKey` and `message.ReadKey` (`writeauth.go:158`, `:172`), which are how the property's
  comparison is computed independently of the session.
  **And the instrument the properties are OBSERVED through (R4's third clause):** `newTestSession`
  (`sessionfixture_test.go:440`) over a real `mls` group, plus `testPqSecret` and the fixture's own
  handle — without which *"the key the session held"* has no referent. It is a landed test
  instrument of this package and is not new work.
- Produces: the session method `EpochKeys`, answering `*EpochKeys` and an `error`, posted through the
  command loop. **The receiver type is deliberately not backticked here**: it is landed, this plan
  does not produce it, and a `Consumes` block elsewhere that names a method off it is naming
  somebody else's declaration.

**`read_key` gets its first production reader on this commit (M4).** At `0c14aa0` the session derives
it at every epoch, erases it at every rotation, and nothing reads it. That is worth stating because
it changes what a reviewer should look for: **a defect in `message.ReadKey`'s argument has never been
observable from this package**, and this task is the first thing that could see one.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the door answers the two keys of the epoch the session is at, and a caller can
  check that for itself.** The value's `Epoch()` equals the session's `Epoch()` at the moment the
  door was opened; its `WriteKey()` equals `message.WriteKey(root)` and its `ReadKey()` equals
  `message.ReadKey(root)` for that epoch's root.
  *Refusal owed:* none on this path.
  *Route:* open a session over a real group through `newTestSession`; call `EpochKeys()`; compare
  against `message.WriteKey` / `message.ReadKey` computed in the test over a root the test derives
  from the same handle's `Export` and the same injected `pq_secret`. **The comparison is deliberately
  against a re-derivation and not against the session's own fields**, because a test that read
  `self.writeKey` would be comparing the door to the field the door copies and would pass under a
  door that copied the wrong field of the right type.

  **Property 2 — a closed session refuses, and refuses with the sentinel every other door uses.**
  *Refusal owed:* `ErrSessionClosed`, from inside the posted command, in the shape `Epoch` and
  `SenderHandle` already use — `err = ErrSessionClosed` under `if self.closing`, and the post's own
  error carried out separately.
  *Route:* `Close()` then `EpochKeys()`; match with `errors.Is`.

  **Property 3 — the door reads the epoch it is called at and never a cached one.** After
  `AdvanceEpoch`, a freshly opened `EpochKeys` carries the new epoch number and two keys that differ
  from the ones the previous door answered; and **the previously opened value is unaffected**, because
  it holds copies.
  *Refusal owed:* none.
  *Route:* open door A; `AdvanceEpoch(NewPqSecret())`; open door B; compare `Epoch()`, `WriteKey()`
  and `ReadKey()` across the two. **Both clauses are the property.** The first catches a door that
  cached; the second catches a door that aliased, and it is the only place in this plan where the
  alias defect is visible as a *value* rather than as a source read — after `AdvanceEpoch` the
  session's arrays have been zeroized, so an aliased door A answers 32 zero octets and no error,
  which is exactly the shape this project's rule about placeholders forbids.

  **Property 4 — the value holds no window onto the session, and the observation is the erase.**
  After `Close()`, a value opened before it still answers its two keys unchanged.
  *Refusal owed:* none — and the absence is the point: a caller that closed a session and then read a
  key it had already been handed gets the key, not a refusal and not zeros.
  *Route:* open the door; `Close()`; read `WriteKey()` and `ReadKey()` and compare against what they
  answered before. **This is Task 1 Property 5's other half**, stated over a live session: mutation 7
  of Task 1 makes both fail.

  **Property 5 — the door is on the loop, and the class that holds it is derived rather than
  listed.** `EpochKeys` reads `self.epoch`, `self.writeKey` and `self.readKey`, all three of which are
  loop-owned by `TestEveryMethodOfAGroupSessionReachesItsStateOnlyOnTheLoop`'s own derivation, so a
  body that read them without posting goes RED in a landed gate.
  *Refusal owed:* none.
  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the scope is this
  package's production source; the class is every method on `*GroupSession` read off the syntax tree.
  That class is **seventeen** members at `0c14aa0` (M2) and **eighteen** on this task's commit. The query
  is `git grep -c 'func (self \*GroupSession)' -- 'messagegroup/*.go' | grep -v _test`, and **R6
  clause (a)**: piping it through `grep -c 'session.go'` must return 1, and the per-file number for
  `session.go` must read 13 rather than 12 after this task. **The complement of "every method" is the
  two the gate excludes — `do` and `run` — which are the mechanism the property is stated over rather
  than an exemption by name.**

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Copy `self.readKey` into both fields of the answered value. **Property 1 must fail** on the
     write-key clause alone, and the failure must name which clause — a message that said "a key
     disagreed" would not distinguish this mutant from mutation 7.
  2. Copy `self.storageRoot` into a third field of `EpochKeys` and answer it from a new accessor.
     **Task 5 Property 1 must fail** — the narrowing gate — and every property of this task must stay
     green, which is what proves the narrowing is held somewhere other than here.
  3. Read `self.writeKey` outside the `do` closure. **Property 5 must fail** in
     `TestEveryMethodOfAGroupSessionReachesItsStateOnlyOnTheLoop`, naming `writeKey`.
  4. Return the live `self.writeKey` slice instead of a copy. **Property 4 must fail** after `Close`,
     and **Property 3's second clause must fail** after `AdvanceEpoch`. Two properties, one mutant,
     and if only one of them goes red the other is not observing what it claims.
  5. Cache the `*EpochKeys` on the session and answer the same pointer every time. **Property 3's
     first clause must fail**, and `TestCloseIsIdempotentStopsTheLoopAndErasesEveryKey` must go red on
     the new field — the landed gate catching what this task's own properties would have let through.
  6. Drop the `self.closing` check. **Property 2 must fail.**
  7. Have the door answer `self.epoch + 1`. **Property 1 must fail** on the epoch clause while both
     key clauses stay green, which is what keeps the epoch from being decoration on a value whose
     whole use is telling two epochs apart.

- [ ] **Step 6: Commit**

---

## Wave 2 — S2-2, the nonce that moves and the one field it moves (Tasks 3–4)

**This wave is independent of Wave 1 and may be dispatched in parallel with it.** They share
`session.go` and no symbol. Task 4 depends on Task 3 and not the reverse: the re-auth is what makes
the rebind observable, and the rebind is what gives the re-auth something to do.

### Task 3: `RebindServerNonce` — a setter, no getter, and the two files that may not call it

**Files:**
- Modify: `connect/messagegroup/session.go` (the new method; **no field added**)
- Test: `connect/messagegroup/noncerebind_test.go`

**Interfaces:**
- Consumes: from the landed tree, `GroupSession.do` (`session.go:241`); `ErrSessionServerNonce`
  (`errors.go:209`) and `ErrSessionClosed` (`:213`), both reused rather than twinned; `zeroize`
  (`zeroize.go:55`), because the superseded nonce is erased before it is overwritten in the shape
  `AdvanceEpoch` already uses for `pq_secret` (`session.go:350-354`).
  **And the instruments the properties are OBSERVED through (R4's third clause):** `newTestSession`
  and `testServerNonce` (`sessionfixture_test.go`), which is where the injected nonce comes from;
  Task 4's `ReauthRecord`, which is the only route on which Property 2's principal clause can be seen
  — **stated here and not hidden, because it means Property 2 cannot be closed until Task 4 lands and
  this task's own commit may not claim it**; and `messagegroupProductionSources` (`recordaead_test.go:39`)
  plus a parse of the package's `_test.go` files, which is Property 5's route.
- Produces: the session method `RebindServerNonce`, taking a `[]byte` and answering an `error`.
  **And no getter**, which is Property 4's whole subject.

**The nonce is not a key, and the setter is written as though it might be anyway.** The fixture's own
header draws the distinction — *"none of the four is a KEY, which is the distinction CP3b's 'no
test-only key source anywhere on the path' draws"* — and it is right: the nonce is a value the
submitting connection chooses, carried in `HelloResponse`, public to the server by construction. The
superseded value is nevertheless erased before it is overwritten, for the same reason
`AdvanceEpoch` erases `pq_secret` before overwriting it: a field of this type that is dropped
unerased is a drop site, and the discipline is the file's rather than the value's.

**Why there is no getter, and the complement of that narrowing.** A `sdk` that rebinds already holds
the nonce — it came out of `HelloResponse` in the same call that prompted the rebind — so a getter
answers a question nobody asks. What it would cost is precise: the reproduction in
`keysource_test.go` is handed the nonce **the test injected**, and a getter is the one thing that
would let a fixture hand it the nonce **the session holds** instead, at which point the third of the
three values stops being an independent input and becomes the subject agreeing with itself. **The
complement, printed: after this plan the session's exported surface is NINE methods (M1 plus three);
the two that answer a value the session holds are `Epoch` and `SenderHandle`; neither is a nonce and
neither is a key.** The set is not empty, which is what makes this a narrowing rather than a
tautology.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the setter replaces the session's nonce and refuses what the constructor refuses,
  with the constructor's own sentinel.** An empty nonce is refused with `ErrSessionServerNonce`, which
  is the sentinel `NewGroupSession` already uses at `session.go:168`. **The two doors onto one field
  agree**, and that is the property rather than a convenience: two doors with two refusals is two
  rules, and a reader would have to derive which one applied.
  *Refusal owed:* `ErrSessionServerNonce` on an empty or nil nonce, before the field is touched.
  *Route:* call with nil and with an empty slice; match with `errors.Is`; then call with a good value
  and observe through Task 4's `ReauthRecord`.
  **What this property deliberately does NOT do is refuse a nonce that is not 32 octets**, even though
  spec A §5.7 and requirement S9 both fix the width at 32. The constructor refuses only emptiness, and
  making the setter stricter than the constructor is exactly the two-rules defect the first clause
  forbids. **The disagreement between the spec's width and the package's check is real, is not this
  plan's to rule, and is filed as K1-2.**

  **Property 2 — a rebind moves `write_auth` and moves nothing else, and the observation is a
  re-authentication of THE SAME record.** Seal a record; keep its `WriteAuth`; rebind to a different
  nonce; `ReauthRecord` that record; the tag differs, and every other field of the record is
  byte-identical.
  *Refusal owed:* none on this path.
  *Route:* `SealRecord` → read `record.WriteAuth` → `RebindServerNonce` → Task 4's `ReauthRecord` →
  read `record.WriteAuth` again, and the other four fields of `message.Record`. **The route runs
  through Task 4 and this is stated rather than deferred (R4's second edge): there is no route on
  which the nonce is the sole free variable that does not re-auth one record.** Sealing a second
  record instead moves `stream_index`, which moves `record_key[i]`, which moves both ciphertexts and
  the handle — a difference no assertion can attribute to the nonce.
  *And the control that makes the observation mean anything:* `ReauthRecord` **without** an
  intervening rebind must leave `WriteAuth` byte-identical. Without that control, "the tag changed"
  is consistent with a re-auth that is simply nondeterministic.

  **Property 3 — a closed session refuses the rebind.**
  *Refusal owed:* `ErrSessionClosed`, from inside the posted command, in every other door's shape.
  *Route:* `Close()` then `RebindServerNonce`; `errors.Is`.

  **Property 4 — no exported method of `GroupSession` answers the nonce, and the class is derived off
  the syntax tree rather than promised.** The class is every exported method of `*GroupSession` whose
  results include a `[]byte` or a `[N]byte` that the method body reads from `self.serverNonce`.
  *Refusal owed:* none; the observation is a source read in the shape this package's existing AST
  gates use.
  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the scope is this
  package's production source. The enclosing class is every exported method of `*GroupSession`, and
  that class is **nine** members on this task's commit — M1's seven plus `EpochKeys` and
  `RebindServerNonce`. **The nonce-answering SUBSET of it must be empty, and this is the one place in
  this document where an emptiness is the property rather than a defect in it** — which is why the
  gate must fatal on an empty *enclosing* class: a gate that derived no exported method at all would
  report the same clean run over a subset that had grown to nine. The query is
  `git grep -n 'func (self \*GroupSession) [A-Z]' -- 'messagegroup/*.go' | grep -v _test`, which must
  return **9** on this commit, and **R6 clause (a)**: piping it through `grep -c 'RebindServerNonce'`
  must return 1.

  **Property 5 — `RebindServerNonce` is not called from the two test files whose own correctness
  depends on the nonce being the injected one, and the ban's complement is printed.** The two are
  `keysource_test.go`, whose reproduction is handed `server_nonce` as one of its three values, and
  `sessionfixture_test.go`, which is the constructor every session in this package is built through.
  *Refusal owed:* none; this is a source property, held mechanically.
  *Route:* parse the package's `_test.go` files and collect every call site of `RebindServerNonce`;
  the two banned names must not appear among their files.
  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the scope is the
  package's test source — **twenty files at `0c14aa0`** (M9), twenty-two after this plan's two new
  ones. That class is **two** members; **the complement is TWENTY and it is printed by the gate
  itself**, as the list of test files that may call the setter freely. **An empty complement would
  mean the ban had grown to cover the package, and the gate must say which reading it is looking at
  rather than leaving a reader to infer it.** The query is
  `git grep -ln 'RebindServerNonce' -- 'messagegroup/*_test.go'`, whose answer must contain
  `noncerebind_test.go` and must not contain either banned name.
  **And what this property protects, said plainly: it is the close of the one sentence of
  `keysource_test.go`'s header that this plan makes conditional.** Before this task that file's
  *"`server_nonce` — the value the constructor was injected with"* is true because no setter exists.
  After it, it is true because of this gate.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Make the setter a no-op that validates and returns nil. **Property 2 must fail.** *And record
     what else does not:* all five tests of `keysource_test.go` stay green, which is the measured
     form of *"CP3b's defining test cannot see S2-2's defect"* and belongs in the commit message
     rather than in a reviewer's head.
  2. Refuse a nonce that is not 32 octets. **Property 1's second clause must fail**, because the
     constructor accepts one and the two doors have stopped agreeing. This mutant is the K1-2 hazard
     made visible rather than ruled.
  3. Accept an empty nonce. **Property 1 must fail** — and note that without the refusal
     `ComputeWriteAuth` panics at `writeauth.go:298` on the next seal, so the alternative to this
     refusal is a panic on a later goroutine and not a bad mac.
  4. Drop the `self.closing` check from the setter's posted body. **Property 3 must fail** — and note
     what a rebind on a closed session would otherwise do: `zeroizeOnLoop` has already erased
     `writeKey`, so the next `ReauthRecord` would reach `ComputeWriteAuth` with a zero-length key and
     **panic** rather than refuse (`writeauth.go:60-76`), on whichever goroutine posted it.
  5. Write `self.serverNonce` outside the `do` closure. **Property 4's enclosing gate must still
     pass** and `TestEveryMethodOfAGroupSessionReachesItsStateOnlyOnTheLoop` must go RED, naming
     `serverNonce`. Two gates, and the landed one is the one that catches it.
  6. Retain the caller's slice instead of copying it. **Property 2 must fail** when the test mutates
     its own argument after the call — a caller's buffer is a caller's, and a session that aliased
     one would seal under whatever that buffer became.
  7. Drop the `zeroize` of the superseded nonce. **Nothing in this task fails**, and that is the
     honest result: the nonce is not a key and no property here observes its erase. Record the
     survivor and its reason in the commit message rather than inventing a property to kill it —
     `zeroize_test.go`'s `noinline` class is where that discipline lives.
  8. Add a `ServerNonce() []byte` accessor. **Property 4 must fail**, and the gate must name the
     method it found rather than reporting that the class is non-empty.
  9. Call `RebindServerNonce` inside `newTestSession`. **Property 5 must fail**, and — run it
     unfiltered — `TestEveryKeyedOctetOfARecordIsReproducibleFromTheExporterAndTheTwoInjectedValues
     Alone` must fail too, on the `write_auth` comparison alone and on no other. **Two failures, and
     the second is what shows the ban is guarding a real sentence rather than a stylistic one.**

- [ ] **Step 6: Commit**

### Task 4: `ReauthRecord` — one field, four refusals, and the epoch case the spec sends elsewhere

**Files:**
- Modify: `connect/messagegroup/seal.go` (`ReauthRecord` and its on-loop body)
- Test: `connect/messagegroup/noncerebind_test.go`

**Interfaces:**
- Consumes: Task 3's `RebindServerNonce`. From the landed tree: `GroupSession.do`
  (`session.go:241`); `message.ComputeWriteAuth` (`writeauth.go:298`), which is the one derivation
  this method performs and which this package already calls exactly once (M5);
  `ErrRecordNotForThisSession` and `ErrSessionClosed` (`errors.go`); `message.ErrRecordNil`;
  `subtle.ConstantTimeCompare`, because guardrail **G8**'s mechanical half is a ban on `bytes.Equal`
  and this package's own comparisons of octets go one way whether or not the octets are secret.
  **And the instruments the properties are OBSERVED through (R4's third clause):** `newTestSession`
  and `testServerNonce`; `GroupSession.SealRecord` (`seal.go:88`), which is where the record under
  test comes from; `GroupSession.OpenRecord` (`seal.go:347`), which is the route of Property 5's
  principal clause; `GroupSession.AdvanceEpoch` (`session.go:335`), which is Property 4's; and Task
  2's `GroupSession.EpochKeys` and `EpochKeys.WriteKey`, which is how the test recomputes the
  expected tag **independently of the session's own field**.
- Produces: the session method `ReauthRecord`, taking a `*message.Record` and answering an `error`,
  mutating the one field of that record the nonce binds.

**What it is, in one sentence, because the name invites a larger reading: it recomputes
`record.WriteAuth` under this session's current `write_key` and current `server_nonce`, and it
touches nothing else.** Every other input `ComputeWriteAuth` takes is already on the record. It is
spec A §5.7's *"every queued record MUST be re-MAC'd against the new connection's nonce before
submission"*, and nothing more.

**And what it refuses, because the same section rules the neighbouring case differently.** §5.7's
outbox rule has two clauses and they prescribe two different costs: the nonce case is *re-MAC'd*; the
epoch case — `REASON_EPOCH_STALE` — is *"discarded and re-sealed at the new epoch, consuming a fresh
`stream_index`"*. **A re-MAC of a record whose epoch has passed is well-formed, cheap, and wrong**:
the tag would be taken under `write_key[n+1]` over a header naming epoch *n*, which no server
verifies and which no test in this package would notice, because the record round-trips against
itself perfectly. So `ReauthRecord` refuses it. **The refusal is the whole of what this plan does
about the epoch case; the re-seal needs a `stream_index` the durable reserver allocates and an outbox
nothing in `connect` owns, and that is K1-3.**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the re-auth answers the mac the server would verify, and the test computes the
  expected tag without asking the method that produced it.** After a rebind, `record.WriteAuth` equals
  `message.ComputeWriteAuth(writeKey, newNonce, &record.Header, record.CtHead,
  record.Header.ServerAttachment)` where `writeKey` came out of Task 2's door.
  *Refusal owed:* none on this path.
  *Route:* `EpochKeys()` → `WriteKey()` → `message.ComputeWriteAuth` in the test → compare against
  `record.WriteAuth`. **Computing the expected tag from the session's own `SealRecord` instead would
  be comparing the method to itself**, which is the tautology `keysource_test.go`'s whole gate
  apparatus exists to prevent one level up. This is the only place in the plan where Task 2's door is
  consumed by a test rather than by a caller, and it is why Wave 1 lands first.

  **Property 2 — exactly one field of the record moves, and the class is the record's field set
  rather than a list.** `RecordId`, `Header` (every field of it), `CtHead` and `CtBody` are
  byte-identical across the call; `WriteAuth` is not.
  *Refusal owed:* none.
  *Route:* a deep copy of the record before the call, compared field by field after it.
  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the class is
  every field of `message.Record`, read off `message/record.go` rather than listed, and **that class
  is five members** (M7). **One member moves; the complement is FOUR and the gate prints it.** The
  query is `git show 0c14aa0:message/record.go | sed -n '/^type Record struct/,/^}/p'`, and **R6
  clause (a)**: piping it through `grep -c 'WriteAuth'` returns 1. **This is the blast-radius
  measurement of S2-2 held as a standing property rather than written down once in a plan** — a sixth
  field added to `Record` next month is in the class with no edit here, and the gate says which side
  of the line it landed on.

  **Property 3 — the tag is taken under the WRITE key and never under the read key.** The two are
  both 32 octets off the same root and a mac under the wrong one is well-formed.
  *Refusal owed:* none; the observation is the comparison of Property 1, which fails under the wrong
  key.
  *Route:* Property 1's route, with the expected tag computed under `EpochKeys().WriteKey()`. **Stated
  as its own property rather than folded into Property 1 because it names the mutant (8) that
  Property 1's comparison catches and a reader would otherwise have to find**, and because
  `keysource_test.go` explicitly cannot see it — its exclusion (5) puts `message.ReadKey` outside the
  reproduction entirely.

  **Property 4 — every refusal is taken before the mac, and on a refusal the caller's record is
  unchanged.** Four refusals: a nil record; a record whose `Header.GroupId` is not this session's; a
  record whose `Header.Epoch` is not this session's; and a closed session. On each, `record.WriteAuth`
  is exactly what it was.
  *Refusal owed:* `message.ErrRecordNil`; `ErrRecordNotForThisSession` for both the group-id and the
  epoch arm, which is the sentinel `openRecordOnLoop` already uses for the same pair
  (`seal.go:385`); `ErrSessionClosed`.
  *Route:* keep the tag, call, match with `errors.Is`, read the tag again.
  **The "unchanged on refusal" clause is not tidiness**: `OpenRecord`'s own comment states the same
  rule one level over — *"a partial plaintext is never returned beside an error"* — and a
  half-applied re-auth hands an outbox a record it believes is fresh. **And it is why the epoch check
  must precede the `ComputeWriteAuth` call rather than wrap it:** that function **panics** on a short
  key or an empty nonce (`writeauth.go:60-76`), so a refusal that arrived as a recovered panic would
  be a refusal taken after the damage.

  **Property 5 — a rebind and a re-auth change nothing about opening.** `OpenRecord` on the same
  record answers the same head and body plaintexts it answered before the rebind.
  *Refusal owed:* none.
  *Route:* `OpenRecord` before the rebind, `OpenRecord` after the re-auth, compare both plaintexts by
  their octets. **This is the "nothing already sealed becomes unopenable" finding held as a property
  instead of asserted in prose**, and it is the clause that makes the blast-radius claim checkable by
  someone who does not believe the greps.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Re-auth under the nonce the session was **constructed** with rather than its current one.
     **Property 1 must fail**, and Task 3 Property 2 must fail with it.
  2. Also recompute `Header.BodyHash` inside the re-auth. **Property 2 must fail**, naming
     `Header` — the gate must say which of the five members moved, not that one did.
  3. Re-seal `CtHead` instead of re-macing. **Property 2 must fail on `CtHead`** and **Property 5 must
     fail**, because a second seal on the same rung is nonce reuse under `record_key[i]` and the
     record stops opening. Two failures; if only Property 2 goes red, Property 5's route is not
     reaching the record it thinks it is.
  4. Drop the epoch check. **Property 4 must fail**, and the re-auth of an epoch-stale record must be
     shown to succeed and produce a tag — the mutant must be demonstrated to be *silent*, not merely
     to be accepted, because that silence is the reason the refusal is in this plan.
  5. Drop the group-id check. **Property 4 must fail** on that arm alone.
  6. Assign `record.WriteAuth` before the refusals. **Property 4's unchanged-on-refusal clause must
     fail**, and the three refusal arms must still return their sentinels — a mutant that returned the
     right error and mutated the record anyway is the one this clause exists for.
  7. Compare the group id with `bytes.Equal`. **Guardrail G8's landed gate must go RED**; record which
     gate caught it, because it is not one of this plan's.
  8. Take the mac under `EpochKeys().ReadKey()`. **Property 3 must fail** and **Property 1 must fail**;
     **Property 2 must still pass**, which is what shows Property 2 is about which field moved and not
     about what it moved to.
  9. Answer a fresh `*message.Record` instead of mutating in place. **Property 2 must fail**, because
     the caller's record did not move at all — and the failure must name the caller's record rather
     than reporting equality, which is the shape that reads as a pass.

- [ ] **Step 6: Commit**

---

## Wave 3 — the narrowing, held as a standing gate (Task 5)

### Task 5: What may leave a live session — the derived class, its complement, and the two gates that already hold it

**Files:**
- Modify: `connect/messagegroup/noncerebind_test.go` (the narrowing gate)
- Test: `connect/messagegroup/noncerebind_test.go`

**Interfaces:**
- Consumes: Tasks 1, 2, 3 and 4 — `EpochKeys`, `GroupSession.EpochKeys`,
  `GroupSession.RebindServerNonce` and `GroupSession.ReauthRecord`, which are the four names the class
  below must contain.
  **And the instruments the properties are OBSERVED through (R4's third clause):**
  `messagegroupProductionSources` (`recordaead_test.go:39`), the AST read of this package's
  production files that `engine_test.go` already uses in ten places and that is the route of Property
  1; and, for Property 2, the two landed gates in `keysource_test.go` — which are **run** rather than
  read, because a mutation is what observes them.
- Produces: no declaration. The standing form of the narrowing this plan's Global Constraints
  argue in prose.

**Why this is a task and not a paragraph.** The narrowing that makes S2-1 safe — *"the two terminal
keys and not the root"* — is a decision in a plan, and a decision in a plan is one commit away from
being undone by somebody who reads the door and not the document. The gate is what turns it into a
property of the tree. **It is also the only place in this plan where R5's mechanical form is
executed by a machine rather than by prose: the gate PRINTS the complement, and its own failure mode
is an empty one.**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — no exported method of this package answers `storage_root`, `group_handle_key`, a
  class key, `pq_secret`, a record key or `mls_secret`, and the class is derived off the production
  source rather than listed.** The gate reads the package's production files, collects every exported
  method of `*GroupSession` and of `*EpochKeys`, and, for each, the session or value fields its body
  reads into a result.
  *Refusal owed:* none; the observation is a source read.
  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the scope is this
  package's production source. **The class is the session's key material, derived over
  `zeroizeOnLoop`'s erase sites; that class is EIGHT members** (M8). **TWO are answerable —
  `writeKey` and `readKey` — and the complement is SIX, which the gate prints by name on every run.**
  The query is the M8 command. **R6 clause (a):** piping it through `grep -c 'storageRoot'` returns 1,
  so the answer contains the complement's largest member rather than merely counting to eight.
  **And the gate's own failure mode is stated, because an unprinted complement is the dangerous
  reading: it fatals on an empty derived class, on an empty answerable set, AND on an empty
  complement** — the third because a complement that had shrunk to nothing is a door that had grown
  to everything, reported by a gate that would otherwise say "no findings".
  *And what this gate cannot see, printed rather than implied:* `mls_secret`, which is a local in
  `installEpochOnLoop` and not a field, so a field-derived class does not contain it; and any value
  a method computes rather than reads, since the reach is a field read and not a dataflow.

  **Property 2 — the reproduction in `keysource_test.go` cannot reach this plan's doors, and the two
  gates that stop it fire in a known order.** The boundary gate refuses an `*EpochKeys` on
  `keySourceSealed`; the module gate refuses a call to any name this module declares from the
  reproduction's side.
  *Refusal owed:* none; both gates are landed and this property is a claim about **which** of them
  fires.
  *Route:* the mutation set below. **This property is observed only through mutation, and that is
  stated rather than dressed up**: there is nothing to assert on a clean tree, because on a clean
  tree the reproduction does not reach the doors and no gate says so. A property written as an
  assertion here would be green in every world.
  *Scope to derive, separately from the class (R3):* the scope is `keysource_test.go`'s own five
  tests (M10). That class is **two** members, named because they are the subject rather than because
  a list was convenient — `TestTheFixtureCanHandTheReproductionNothingItCouldSealWith` and
  `TestNothingOnTheReproductionsSideOfTheComparisonComesFromTheModule`. **The complement is the other
  THREE tests of that file**, which observe octets rather than reach, and which mutations 3 and 4
  must leave green.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add a `StorageRoot()` accessor to `EpochKeys` answering a copied root. **Property 1 must fail**,
     naming `storageRoot` and printing the complement it has just shrunk to five.
  2. Narrow the gate's class to the two answerable fields. **Property 1 must fail on its own
     empty-complement check**, which is the mutant that proves R5's mechanical form is held by the
     gate and not only by this document.
  3. Put an `*EpochKeys` field on `keySourceSealed`. **`TestTheFixtureCanHandTheReproduction
     NothingItCouldSealWith` must fail**, naming the field and the type it reaches — and the module
     gate must NOT be what fails first, which is Property 2's principal clause. Revert immediately:
     this mutant edits the file this plan otherwise does not touch.
  4. With mutation 3 in place, have `reproduceRecordFromTheExporterOutput` read `write_key` off that
     field instead of expanding `"write/v1"`. **`TestNothingOnTheReproductionsSideOfTheComparison
     ComesFromTheModule` must fail**, naming `WriteKey`, **and the three record-level tests of that
     file must stay GREEN** — which is the whole point: the reproduction agrees with the sealer
     because it has become the sealer, and only the gate can tell. Revert immediately.
  5. Rename `EpochKeys.WriteKey` to something the module class would not contain — it cannot be done,
     and recording *why* is the exercise: the class is every name the module declares, so there is no
     spelling that escapes it. **Property 2 must be satisfiable by this reasoning and the commit
     message must say so**, because a mutation that cannot be written is evidence only if somebody
     tried.

- [ ] **Step 6: Commit**

---

## Wave 4 — off the CP3b prefix (Task 6)

### Task 6: The package's inventory, and the registry entry

**Files:**
- Modify: `connect/messagegroup/doc.go` (the honest-inventory paragraph),
  `msgrepo/docs/plans/2026-08-12-slice1-interface-registry.md`
- Test: `connect/messagegroup/noncerebind_test.go`

**Interfaces:**
- Consumes: Tasks 2, 3 and 4 — the three new session methods, whose existence is what makes two
  sentences of `doc.go` untrue.
  **And the instrument the property is OBSERVED through (R4's third clause):**
  `messagegroupProductionSources` (`recordaead_test.go:39`), which is how `engine_test.go:101`
  already reads this package's doc comments and is the route of the property below.
- Produces: no declaration.

**This task is off the CP3b prefix and is stated as such.** Nothing below changes behaviour. It is
here because a package whose doc comment says it cannot do a thing it now does is a package the next
reader will not believe about anything else — the same reason the join plan inverted a refusal test
rather than deleting it.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — no production sentence in this package says the epoch keys are unreachable or that
  the nonce cannot be rebound, and the class is derived off the package's own source.**
  *Refusal owed:* none; the observation is a source read in the shape this package's existing AST
  gates use.
  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the scope is this
  package's production source. The class is **every production sentence naming `server_nonce`
  alongside "cannot", "no setter" or "construction", or naming the epoch keys alongside
  "unreachable"**. The query is
  `git grep -rn 'no setter\|cannot be rebound\|not reachable' -- 'messagegroup/*.go' | grep -v _test`.
  **At `0c14aa0` that class is TWO members**, both in `session.go`'s own header block, and both in a
  file Tasks 2 and 3 already edit — **so the work was scheduled and only the sentence was left**,
  which is the failure mode this project's count-without-a-query class names. The gate prints the
  members, so a third written next month fails on the commit that adds it. **The complement, printed:
  the `_test.go` references to the same phrases, which move with the gates that hold them and are not
  this class's.**

  **Property 2 — the registry entry names what this plan produced, and names what it did not.** The
  four new exported names; and, beside them, that `storage_root`, `group_handle_key` and the class
  keys are deliberately absent and why.
  *Refusal owed:* none. This is a documentation property, held by review rather than by a gate,
  because the registry lives in a different repository from the code and no test in `connect` can
  read it. **That is stated rather than papered over: it is the one property in this plan with no
  mechanical observer**, and K1-7 is the residual.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Restore one of the two sentences in `session.go`. **Property 1 must fail**, naming the line.
  2. Add a third sentence of the same shape to `seal.go`. **Property 1 must fail** on a class of one
     where it should be zero — the gate must derive the new member rather than checking the two it
     knew about.
  3. Narrow the query to `session.go`. **Property 1 must fail** on its own scope check, because a
     gate whose scope is the file the defect was first seen in is the defect this project has paid
     for three times.
  4. Write the registry entry naming only what this plan produced. **Property 2 must fail** at
     review — and record that no test caught it, which is the measurement K1-7 is filed on.

- [ ] **Step 6: Commit**

---

## Execution order

1. **Task 1** and **Task 3** may be dispatched in parallel. They share no file.
2. **Task 2** after Task 1. The door needs the value.
3. **Task 4** after Tasks 2 and 3. It consumes the setter, and its Property 1 computes its expected
   tag through Task 2's door.
4. **Task 5** after Tasks 1–4. Its class must contain all four new names.
5. **Task 6** last, and it is off the CP3b prefix.

**Task 3's Property 2 cannot be closed at Task 3's commit** and the task says so in its own
`Consumes` block: its observation route runs through Task 4's `ReauthRecord`. An implementer who
dispatches Tasks 3 and 4 to two workers must give the second one Property 2, and the first one's
commit message must say the property is open. **This is the one cross-task residual in the plan and
it is named rather than hidden, because the alternative — writing Property 2 as though a second seal
could observe it — is exactly the unobservable property R4's third clause was added for.**

## Definition of done

- `go build ./...` and `go vet ./...` clean in `connect`.
- `go test ./messagegroup/ -count=1` green, **unfiltered**, with the test count recorded in the
  commit message and compared against the count at `0c14aa0`.
- `go test ./... -count=1` green in `connect`, unfiltered.
- **`git diff --stat 0c14aa0..HEAD -- messagegroup/keysource_test.go` is EMPTY.** This is the check
  behind *"the file is not edited"*, and it is a command rather than an intention.
- `git diff --stat 0c14aa0..HEAD` names no file outside `connect/messagegroup/`.
- The nine-method exported surface is measured and printed:
  `git grep -c 'func (self \*GroupSession) [A-Z]' HEAD -- 'messagegroup/*.go' | grep -v _test`
  returns 9, and `grep -c 'RebindServerNonce'` over the same answer returns 1.
- Every mutation in every task has been run and its result recorded, **survivors included**. Task 3
  mutation 6 and Task 6 mutation 4 are expected survivors and their reasons are written down; a
  survivor that is not one of those two is a defect in a test.
- `go test ./ -run TestThePlanLinter` green in `msgrepo`, with every reporting count compared across
  the diff rather than read off a single run.

## What this plan does not close

- **S2-3.** `pq_secret` has no delivery channel. Its delivery is m1 Task 14's and that is blocked on
  **ledger item 152**, which is the owner's and which this plan does not touch, read, propose a
  reading of, or work around. **Every task above runs on a session constructed with an injected
  `pq_secret`, exactly as the landed fixture does**, so nothing here makes the bar's *"no test-only
  key source"* clause any nearer or any further.
- **CP3b.** Two of the four filed blockers close here. One remains, and it is S2-3.
- **The width disagreement** between spec A §5.7's 32 octets and `NewGroupSession`'s emptiness check.
  **K1-2.**
- **The outbox itself.** §5.7's rule is normative and client-side; this plan supplies the two
  operations it names and owns neither the queue nor the policy. **K1-3.**
- **The `s2` plan's own text.** S2-1 and S2-2 are not edited there, and their *"Position taken"*
  paragraphs — the injected `StorageRootZero`, and `s2` Task 10 Property 4's local refusal — still
  stand as written. **A plan that rewrote another plan's open items on the strength of a plan is claiming a
  landing that has not happened.** When this plan's code lands, that is the commit that earns the
  edit.

## Open items

Each is a spec or ownership problem in this plan's area, with what it blocks. **None is resolved
silently.** Where this plan took a position because something had to compile, the position is
labelled as a position and the rejected alternative is named.

**K1-1 — the value a device must persist across a restart is still unreachable, and which value it
is remains unruled.** Spec A §5.3 says a session past epoch zero must have persisted
`storage_root[0]`; `session.go`'s own header says MASTER §8 requires only `group_handle_key` and
persists that instead, and **M1-4** carries the divergence. **This plan's door carries neither**, so
a device that must survive a process boundary still has no exported route to the value its own
document tells it to keep. *Position taken:* none — and that is the item. Shipping an accessor for
either half would settle M1-4 by shipping, which is the one thing a plan may not do to an open
ruling. *Rejected:* a `StorageRoot()` on `EpochKeys`, for the reason the narrowing table gives.
**Blocks:** a restart. **It does not block CP3b**: **J1-9** ruled the restart off that prefix, and
**S2-14** — no production `mls.StateStore` in any tree — is upstream of it anyway. **Owner:** m1,
through M1-4.

**K1-2 — `server_nonce`'s width is 32 in the spec and unchecked in the package, and this plan's
setter inherits the unchecked rule deliberately.** Spec A §5.7 says *"32 bytes"* and requirement S9
repeats it; `NewGroupSession` (`session.go:168`) refuses only an **empty** nonce; the shipped server
draws exactly 32 (`msgrepo/peer/connection.go:138`). *Position taken:* `RebindServerNonce` refuses
exactly what the constructor refuses, because two doors onto one field with two refusals is two
rules and a reader would have to derive which applied. *Rejected:* making the setter stricter, which
would leave the looser door open and the stricter one looking like the rule. *Not resolved:* whether
**both** doors should refuse a nonce that is not 32 octets. That is a change to a landed refusal and
needs whoever owns `NewGroupSession`'s contract. **Blocks:** nothing today; it is a latent
disagreement between a normative width and a shipped check, and Task 3 mutation 2 is where it is
visible.

**K1-3 — the epoch-stale half of the outbox rule has no owner and no mechanism.** §5.7 rules it
plainly — *"on `REASON_EPOCH_STALE`, a queued record MUST be discarded and re-sealed at the new
epoch, consuming a fresh `stream_index`"* — and `ReauthRecord` refuses such a record rather than
re-macing it, which is the correct half of the rule and is all `connect` can do. The other half needs
a `stream_index` from the durable reserver (`s2` Wave 1, Tasks 1–4), an outbox to hold the record,
and a policy for the plaintext that must be re-sealed. **Nothing in `connect` owns any of the
three.** *Position taken:* refuse, with `ErrRecordNotForThisSession`, and say so. *Rejected:*
re-macing it anyway, which is silent and wrong, and re-sealing inside `ReauthRecord`, which would put
a `stream_index` reservation inside a method whose whole claim is that it reserves none. **Blocks:**
any real client that advances an epoch with records queued. **Owner:** `sdk`, through `s2`.

**K1-4 — nothing observes that a rebind happened before the next seal, and inventing a signal that
would is not this plan's to do.** A session that is never rebound goes on sealing under a superseded
nonce, and the failure surfaces as a server refusal rather than as a local one — which is precisely
what `s2` Task 10 Property 4 chose to refuse locally instead. Whether the session should refuse to
seal after some liveness signal (*"the connection this nonce came from is gone"*) is a design
question **no document asks**, and `connect` has no connection identity to hang it on — §5.7's
2026-08-26 ruling says so in as many words and calls removing that residual an owner decision about
a repository this work does not own. *Position taken:* none. *Not resolved:* deliberately. **Blocks:**
nothing. It bounds what S2-2's close buys: the operations exist, the obligation to use them is the
caller's, and the residual §5.7 already names is unchanged by this plan.

**K1-5 — an `EpochKeys` copy outlives the epoch it came from, and nothing in the language makes a
caller destroy it.** The copy is derived from the concurrency contract — a live array would be a read
off the loop against the loop's own erase — and its cost is that `AdvanceEpoch` no longer erases every
copy of the epoch's auth keys, only the session's. `ProvisionalEpoch` has the same shape and the same
residual, so this is a property of the pattern rather than of this instance. *Position taken:* a type
with a `Destroy`, so the obligation has a name a caller can `defer`. *Rejected:* returning two bare
slices, which is R7 arm (ii) by construction; and handing out live arrays, which is the race.
**Blocks:** nothing. It is the price of the door, stated so the next reader of `epochkeys.go` does not
have to rediscover it.

**K1-6 — `read_key`'s lifetime is described two ways in one document, and this plan reads it the way
the code does.** Spec A's revision A-3 calls `read_key` *"a group-lifetime `read_key`"*; §5.7 says
*"every later epoch's key is derived locally from that epoch's `storage_root`"* and
`message.ReadKey`'s parameter is literally named `storageRootEpoch`. **The code and §5.7 agree and
A-3's adjective is the odd one out** — which is a reading, not a ruling, and it is filed rather than
applied: `EpochKeys.ReadKey` answers the key of the epoch the door was opened at, and a consumer that
needs a superseded epoch's read key has nowhere to get one. *Not resolved:* whether a client should
retain read keys across epochs to reach the server's `read_key_window_seconds`, which §5.7 describes
from the server's side and leaves silent on the client's. **Blocks:** the read-key window edge
`s2` Task 11 has to detect. **Owner:** whoever rules the §5.7 client half.

**K1-7 — one property in this plan has no mechanical observer, and it is named rather than dropped.**
Task 6 Property 2 is about the interface registry, which lives in `msgrepo` while the code lives in
`connect`; no test in either tree reads the other. *Position taken:* state it as held by review and
say so in the property, rather than writing a gate in `connect` that reads a file in another
repository or quietly demoting the property to a checklist line. **Blocks:** nothing. It is the one
place in this document where R4's third clause is satisfied by a person.

## Open asks on other plans

- **To `s2`:** when the code of this plan lands, S2-1 and S2-2 become closable, and the two
  *"Position taken"* paragraphs under them — the injected `messageClientConfig.StorageRootZero`,
  and `s2` Task 10 Property 4's local refusal — are the two places it will want to re-read. **`StorageRootZero`
  is the one this plan expects to change shape**: `sdk` needs `write_key[0]` for
  `CreateGroupRequest.bootstrap_write_key` and `read_key[e]` for every Fetch, and after Task 2 both
  are reachable from the session, so injecting a root becomes injecting more than the leg needs.
  **This plan does not make that edit.**
- **To m1:** `ProvisionalEpoch` has `WriteKey()` and no `ReadKey()`, so epoch *n+1*'s
  `EpochAttachment.read_key` has no source today. That is m1's type and m1's attachment; **K1-6** is
  the reading this plan took and did not apply.
- **To the owner:** ledger item **152** is the only remaining ruling on the CP3b path, and this plan
  is written so that nothing in it depends on which way it goes.
