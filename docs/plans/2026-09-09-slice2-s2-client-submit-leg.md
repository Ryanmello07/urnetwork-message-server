# [The `sdk` Client Submit Leg and the Durable Stream Reserver] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the two CP3b legs the owner assigned to `s2` on 2026-09-06 — **leg 4**, the
`connect.Client` binding of Spec A §10 with a send path that calls
`messagegroup.GroupSession.SealRecord` and submits the `*message.Record` it returns and a receive
path that fetches and calls `OpenRecord`; and **leg 5**, a durable `StreamIndexReserver` for the
interface m1 Task 6 declares and deliberately does not implement. Both land in `sdk`, on
`beta/message`, against a message server that needs nothing new.

**And CP3b is not reachable by this plan alone. That is the first paragraph rather than a footnote,
because plans on this project have been read as milestones before.** CP3b is *"two clients, one
group, one DURABLE text message, every key real, no test-only key source anywhere on the path."*
Four things stand between a finished `s2` and that sentence. All four are in `connect`, all four are
upstream of every task below, and **not one of them is named in leg 4 or leg 5**: the epoch read and
write keys are not reachable from `sdk` without a second copy of an unexported exporter label
(**S2-1**); `server_nonce` is captured once at `NewGroupSession` and cannot be rebound, so the first
reconnect of a real `connect.Client` invalidates every record sealed after it (**S2-2**); `pq_secret`
has a sampler in flight and **no delivery channel**, so the only thing that makes two clients agree
on a storage root today is a test constant, which is exactly what the bar forbids (**S2-3**); and
`GroupEngine.JoinFromWelcome` is an unconditional refusal, so there is no exported path by which two
clients share one group at all (**S2-4**). A plan that ships every task below and reports CP3b has
met a bar it cannot have met. What this plan produces is *one client seals a real durable record
under real keys over a durable reserver, submits it to a real server over a real `connect.Client`,
fetches it back and opens it* — six of CP3b's words short of CP3b, and every one of the six is
somebody else's commit.

**Architecture:** Four layers, and the split is what makes the wave order safe. **The reserver**
(Tasks 1–4) is a file-backed durable store plus the adapter that presents it as
`messagegroup.StreamIndexReserver`. It imports `connect/messagegroup` for two type names and
otherwise nothing but the standard library; it needs no transport, no `MessageClient`, no s1 symbol
and no new module dependency, and it gates every seal by construction, because `NewGroupSession`
refuses a nil reserver. **The transport** (Tasks 5–7) is a request/response binding over the
existing `connect.Client`: frames at the four §10.1 code points, `request_id` correlation, §4.6
fragmentation in both directions, and Hello. **The paths** (Tasks 8–12) are seal → project → submit,
and fetch → parse → open. **The gates** (Tasks 13–15) are the layering test `sdk` has never had, the
CI `sdk` has never had, and the registry entry that tells the next plan what this one produced.

**Tech Stack:** Go 1.26.5; `github.com/urnetwork/connect` (already a `replace` in `sdk/go.mod`);
stdlib `os`, `encoding/binary`, `crypto/sha256`, `sync`, `testing`; `google.golang.org/protobuf`,
already in the graph. **No new module dependency, and specifically not `modernc.org/sqlite`** — see
*Dependency policy*.

---

## Global Constraints

### The five rules this plan is written under

These come from this project's own ledger, from the nine plans before it, and — R5 — from this
plan's own first review. They are stated first because they change how every task below is meant to
be read.

**R1 — this plan supplies no test code, and neither may a task.** Roughly **thirty** plan-supplied
tests across p1–p8 could not fail: nine consecutive p1 tasks each carried one, and a `GroupContext`
round-trip test passed against a codec with `epoch` deleted from both halves, because it generated
its seeds with the same marshaller it then checked. Each task below states **the property**, **the
refusal that property owes**, and **the mutation set the implementer must run**. The implementer
derives the test. A plan that hands over a test hands over the illusion of coverage.

**R2 — every signature is read from source, never from this plan; and on this leg the SOURCE COMMENT
is the stale one.** Ledger 25: `FindExtension` changed shape and seven plan call sites still spelled
the old one. Every Go fragment in this document is **illustrative of shape, not of spelling**. There
is a live inversion of the usual rule on exactly this plan's subject.
`connect/messagegroup/streamindex.go` quotes Spec A §8.2 as declaring
`ReserveStreamIndex(groupId []byte, index uint64) error` and `StreamHighWater(groupId []byte)
(uint64, error)` — the **pre-A1** shape. Spec A §8.2 was amended on 2026-09-07 and today reads
`ReserveStreamIndex(groupId, senderHandle []byte) (uint64, error)` and
`StreamHighWater(groupId, senderHandle []byte) (uint64, error)`. The shipped Go interface is a third
thing again: `Reserve(stream StreamKey) (uint64, error)` and `HighWater(stream StreamKey) (uint64,
error)`. **Read all three before Task 3.** Filed as **S2-15**.

**R3 — every gate derives its class AND its scope, and states them separately.** Ledger 21: five
times on this project a gate derived its class correctly and then wrote its scope down beside it —
one file name where the subject was a package, two error spellings where the package had five. The
fix each time was a wider derivation, never a longer list. Every task below that builds a gate
answers the scope question separately from the class question, **in the gate's own header comment**.

**R4 — derive from the PROPERTY, never from the INSTANCE.** This has bitten four times at four
altitudes here: a class dispositioned by a count instead of a grep; a location query built from the
numbers a ruling changed instead of the claims it falsified; a class swept by the construction a
finding was raised against instead of the property it names; and a gate whose class was a
*directory* rather than *"code that produces the record's keyed octets"*. On this plan the live
instance is Task 8: the projection's class is **what the message descriptor declares as
server-indexed**, not the eleven field names anybody can type, and a gate written over the names
passes on the day a twelfth field is added and the client stops populating it.

**R5 — a property must be SATISFIABLE by a correct implementation and FALSIFIABLE by an incorrect
one, and both halves are checked by running the derivation the property mandates.** The s1 plan
shipped four properties no correct implementation could satisfy, and the first draft of this plan
shipped nine more of the same class plus four whose mutation could not be applied at all. They are
listed here rather than only repaired, because the list is what a later pass checks a new property
against:

| Where | Which half failed | Why |
|---|---|---|
| Task 13 Properties 1 and 3, and two Definition-of-done rows | unsatisfiable | the scope was the transitive dependency set, which necessarily contains `connect/mls` and `connect/mls/syntax` — Wave 1's own required edges — and the grep string matched the second as a substring of the first |
| Task 2 Property 1 | unsatisfiable | a two-member sync class on a platform whose directory-handle `Sync()` returns *"Access is denied."* |
| Task 3 Property 1 | unsatisfiable | a class pinned to one member that a correct inlined implementation makes two |
| Task 4 Property 2 and Task 9 Property 2 | unsatisfiable | a class of "one member" over a `GroupSession` construction the plan never made, i.e. zero |
| Task 6 Property 3 with mutation 8 | unfalsifiable | a class of integer **literals** cannot see `1 << 11` |
| Task 11 Property 2 | unsatisfiable | the oneof descriptor the property reads has fifteen arms and the property stated four |
| Task 11 Property 3 | undecidable | *"an epoch this client cannot key"* against a signature carrying a bare `[]byte` and no epoch |
| Task 10 Property 4 | unfalsifiable | the seal-time nonce epoch it compares against was recorded nowhere, so a correct-looking path compares a number with itself |
| Task 10 Property 5 with mutation 7 | unfalsifiable | `protocol.SubmitRequest` has no `req_auth` field, so the mutation does not compile |
| Task 7 mutation 6 | inapplicable | nothing in `msgrepo` constructs a `CapabilityChange` or emits `MessageMessageServerPush` |
| Task 1 mutation 3 | unkillable | the version tag was not required to be readable independently of the identity |
| Task 8 mutation 5 | survivable | the prose pointed the mutation set at the three classes where the tag and the wire byte are numerically identical |

**And the 2026-09-09 repair pass shipped SEVEN more of the same class while fixing the ones above,
which is why they are in the same table and not in a footnote.** A repair is as capable of
introducing this class as a first draft is, and the two above it that came from one pass are the
argument for sweeping every pair rather than fixing the pair somebody reported.

| Where | Which half failed | Why |
|---|---|---|
| Task 1 Property 2 against Task 2a's guard placement | unsatisfiable **as a pair** | one pass put an OS-held guard file *inside* `dir` and, in the same pass, made "a file in `dir` that is not a row is `ErrStreamStoreState`" categorical. A correct Task 2a made every later `StreamHighWater` refuse, and Task 2a lands **with** Task 2, so Wave 1 was red on the commit that completed it |
| Task 1 Property 4 with mutation 7, against Task 2 mutation 10 | contradictory | the same truncation had to be `ErrStreamStoreState` at Task 1 and a **discarded torn tail** at Task 2. Task 1 lands first, so an implementer dispatched on it alone writes the store Task 2's own mutation then fails |
| Task 2 mutation 10's second clause | unsatisfiable, unbounded | *"Property 4 must fail if it answers `(0, nil)` for a key whose row is present"*, applied to a row of one record, convicts the correct answer |
| Task 2 Property 1's second reported number | unsatisfiable | *"the allocation path performs no directory-entry mutation at all"* on a store whose **first** allocation for a key must create that key's row, having had no key set at open time to pre-create from |
| Task 8a Property 4 | unsatisfiable | a class of *"two members … in whatever stands the client up"* over `OpenStreamStore` / `OpenReceiveState` **call expressions in production files**, in a plan where both stores arrive injected and nothing stands the client up. The class is zero |
| Task 10 Property 5 | unsatisfiable at its own commit | a class of *"one member — Task 11's `Fetch`"* at a task whose landing order is `9, 10, 11`. Zero at Task 10 |
| Task 13 Property 4 | unsatisfiable | *"beyond the two this plan promotes"* against its own measurement of 8 direct → 9 direct, which is **one** |

**The class, not the list, is the rule**: run the derivation the property states, on this tree, with
this toolchain, on the platform the plan tells the implementer to use — and check that the number
that comes back is the number the property states, and that the stated mutation compiles. **And run
it over PAIRS, not properties**: five of the seven above are individually readable and only fail
against a second sentence somewhere else in the document. The derivation that finds them is
mechanical — index every constraint site in every task by the objects it names (backticked
identifiers plus the document's own uncoded nouns: the row, the guard, the allocation path, the
torn tail, the directory entry), then read every object **two or more CONSTRAINT SITES** name. Doing
it over Property blocks alone is **not** the derivation and misses the first row of this table
outright, because Task 2a states its guard placement in task prose and not inside a Property.

**And the unit is the constraint site, not the task — a correction the 2026-09-09 defence pass had to
make to this very paragraph, having been caught by it.** Until that pass this sentence read *"every
object two or more **TASKS** constrain"*. Both findings that prompted the sweep happened to be
cross-task, so **the scope reproduced the shape of its two instances rather than the property it was
defending**, which is *two sentences in this document that cannot both be satisfied* — a property
that is silent about how many tasks they sit in. The bound was not merely loose: it structurally
could not see a contradiction confined to one task, and the pass that wrote it walked past one in the
task it was repairing (Task 1 Property 4 case 2 against Task 1 mutation 7 against Task 1 mutation 9).
A scope derived from the instances is not a derivation. The constraint sites are: every clause of a
Property, every *Refusal owed* line, every numbered mutation, and every sentence of task prose that
states an obligation.

**AND THE SECOND AXIS, which is where both of the surviving instances actually lived: a constraint
whose two sides are EQUAL under everything the deciding party can read.** This is not a
contradiction between two demands that could each be met separately. It is a demand for a function
that does not exist, and it is the strictly worse failure, because re-aiming one of the two sentences
does not remove it — a later pass simply re-derives the same demand somewhere else. **The
derivation, and it is as mechanical as the first.** For every constraint site that names a **cause, a
history or an intent** rather than an observable — *truncated*, *crashed*, *interrupted*, *a
committer that lied*, *the caller passed*, *was ever handed out*, *this build produced*, *an omitted
wrap is visible* — write down two things: **(a)** the exact set of values the deciding party can read
at the moment it must answer, and **(b)** the set of causes that map to one value of (a). If two
causes in (b) are given different answers anywhere in the corpus, the pair is **unsatisfiable**, and
the repair is not to move one demand: it is to restate the constraint over (a), or to rule that both
causes take the same answer and say so. A third of (b) is party-shaped rather than byte-shaped — the
same record is visible to its target and invisible to the server — and a constraint that names no
party is a constraint with no (a) at all.

**What the corrected sweep found on 2026-09-09, run over both live plans.** Three instances, none of
them reachable by the task-scoped derivation above, plus one under-determination. The scope it read
is published beside the count so the query can be re-run: every Property clause and every numbered
mutation of the 15 tasks in this document and the 24 in `m1`, indexed by backticked identifier and
by the uncoded nouns listed above.

| Where | Which half failed | Why, and what it took |
|---|---|---|
| Task 1 Property 4 case 2, with Task 1 mutations 7 and 9 (and Task 2 mutation 10) | **unsatisfiable — no discriminator exists** | a 3-record row truncated to half and a 2-record row whose second append flushed halfway are **byte-identical**; mutation 9 required the second discarded and mutation 7 required the first refused. Resolved at Task 1 Property 4 by ruling that the two are indistinguishable and take one answer, with the classification restated as a decision procedure over `(L, W, checksums)`; mutation 7 re-aimed onto **corruption**, which is the only operation that can reach case 3, and mutations 11 and 12 added as the controls |
| `m1` Task 14 Property 7's ordering clause | **unsatisfiable — the demand precedes its own precondition** | *"refuse before reading the epoch"* against a signature that lives inside `aead_ct`, whose key `wrap_key` takes the envelope's epoch and both type octets as inputs. A receiver that has not read the epoch cannot reach the signature at all. Repaired to the observable half — refuse before **installing** — with the ruling itself untouched and the sentence still owed as `m1`'s **M1-51** |
| `m1` Task 14 Property 5's headline | **unsatisfiable over an unnamed party** | *"an omitted wrap is visible"* is true at the omitted member, false at the server, which sees a matching `expected_wrap_count`, and false at every other member. The property now names the party and asserts the **invisibility** at the other two, which is M1-22's finding made testable rather than merely filed |
| Task 1 Property 2 and Task 12 Property 7, each against its own categorical rule | **under-determined, and one reading breaks the wave's most important mutation** | *"an entry … that is not a row of **either tag**"* has an undefined antecedent. Read as "the two tags the codebase knows about", mutation 3's planted pre-A1 row is not a row of either and answers `ErrStreamStoreState` where the mutation demands `ErrStreamKeySpace`. Both properties now state the three-way partition over the name's own shape |

**What it found clean, published because a sweep that reports only its hits is a sweep nobody can
size.** The other objects named by two or more constraint sites inside one task are consistent:
Task 2a Property 4's two crash points differ in whether a flushed record is present, so they are
separable in the bytes; Task 2a Property 2's live-versus-dead holder is separable because the
exclusion is OS-held rather than a pid file, which is what mutation 3 exists to pin; Task 12's
`ErrOutOfWindow` / `ErrNoWrap` pair are two different absences with two different observables; and
`m1` Task 15's *"omit the recovery leg entirely"* is already carried as a **named, deliberately
unrefuted** mutation rather than as a demand nothing can meet, which is the shape this axis asks
for.

### Repository, branch, toolchain

- Work happens in `sdk`. `connect` is on `beta/message`; `msgrepo` is on `main`. **This plan changes
  no file in `connect`, and no file in `msgrepo` except its own registry entry (Task 15).**
- Go 1.26.5, pinned. `actions/setup-go@v5` with `go-version: '1.26.5'` in every workflow.
- The `urnetwork-workspace` skill governs how these repos are built and tested together. `test.sh`
  is zsh and `-timeout 0 -race`; on Windows run `go test` directly and say so in the commit message.

**Three preconditions, all measured 2026-09-09, and all three unmet.** No task below starts until
each is closed. They are **S2-13**.

1. **`../goidenticons` is not checked out.** `sdk/go.mod` carries
   `replace github.com/urnetwork/goidenticons => ../goidenticons` and that directory does not exist.
   `go build ./...` in `sdk` fails with `reading ..\goidenticons\go.mod: The system cannot find the
   path specified.` s1 recorded this on 2026-08-30 as *"currently unmet"*; it is still unmet ten
   days later. **No s2 task can compile, test or mutation-test until it is fixed, and editing
   `go.mod` is not the workaround** — the replace is load-bearing for the mobile artifacts.
2. **`sdk` has no `beta/message` branch.** `git branch -a` shows `main` plus fourteen remotes, none
   of them `beta/message`. The branch this plan and s1 are both written against does not exist yet.
3. **`sdk` has no CI.** There is no `.github` directory at all. s1 Task 15 creates the first
   workflow; if s1 is deferred, Task 14 below inherits that job, and it is written to be inheritable.

### Where the CP3b line falls, said plainly

**Tasks 1–12, including 2a and 8a, are the CP3b prefix. Tasks 13–15 are not.** The prefix is not a
guess about effort; it is the set of things without which the run cannot happen at all.

- **Tasks 1–4, and 2a** — without a durable reserver, `NewGroupSession` will not construct: it
  refuses a nil one. Task 2a is on the prefix and not beside it: two openers of one directory
  allocate the same index, and §5.6 calls a reused `stream_index` under a reused `record_key` *"a
  total break of both AEADs for that record"*. A run over m1 Task 6's test fake proves the record layer and not the client. §5.6's reasoning
  is that a reused `stream_index` is a reused nonce under a reused `record_key`, *"a total break of
  both AEADs for that record"*.
- **Tasks 5–7** — without the binding there is no way to reach the server, and without Hello there
  is no `server_nonce`, so there is no `write_auth` and no `req_auth`.
- **Tasks 8–10, and 8a** — without the projection every submit is refused by §5.1 check 3; without
  the group-opening ceremony every ordinary submit is refused with `REASON_EPOCH_INCOMPLETE`. Task 8a
  is the seam: it is the only place a `GroupSession` is constructed, so without it the reserver of
  Wave 1 is never wired to the send path and leg 4's defining sentence is produced by nothing.
- **Tasks 11–12** — *"a person reading a message"* is the bar, and reading is Fetch plus
  `OpenRecord` plus the receiver bookkeeping `OpenRecord` refuses without.

**Tasks 13–15 are off the prefix and are not optional.** A layering gate, a workflow and a registry
entry are how the next plan finds out what this one did. None of them is between a `*Record` in
memory and a person reading a message, and saying so is what keeps the prefix honest.

**And CP3b's one text message is the FOURTH thing this client submits, not the first.** This is the
largest cost hidden by leg 4's one-sentence description, and every fact in it was read from `msgrepo`
source rather than from a document. `api/submit.go`'s `CreateGroup` refuses unless the initial commit
is `IsCommit` with header `Epoch == 0` and carries a `ServerAttachment` whose `Kind` is
`AttachmentEpoch` and whose `Epoch.Epoch == 1`. `store/memory.go`'s `wellFormedEpochAttachment` then
refuses that attachment unless `WriteKey` and `ReadKey` are exactly 32 octets **and
`ExpectedWrapCount != 0`** — so group creation *promises* a wrap fan-out. The store then refuses
every ordinary submit with `REASON_EPOCH_INCOMPLETE` until the fan-out closes, exempting only
`AttachmentWrap` and `AttachmentEpochComplete`. So the real leg-4 send sequence is **CreateGroup →
the wraps → the `EpochComplete` marker → the text message**, and Task 9 is that sequence.

### What this plan REUSES rather than rebuilds

This project has already paid for a second implementation of one preimage. The list below is what
`s2` links; a task that re-specifies any of it is a defect in the task.

| Reused, whole | Where it lives | What `s2` therefore does not write |
|---|---|---|
| The record layer: seal, open, both ratchets, the key schedule, the class keys, the handles | `connect/messagegroup` | **No crypto.** `s2` calls `SealRecord` and `OpenRecord` and derives no record key, no nonce and no AEAD input |
| The codec and every wire authenticator: `EncodeRecord`, `ParseRecord`, `ComputeWriteAuth`, `ComputeRequestAuth`, `WriteKey`, `ReadKey`, `RetentionClassWire`, `EncodeServerAttachment`, the size-bucket ladders | `connect/message` | **No preimage, no MAC, no codec.** §12.1 A-1 exists so there is one implementation of each; a second in `sdk` is the A-1 defect by definition |
| The whole wire vocabulary — `MessageServerRequest`, `Record`, `CreateGroupRequest`, `SubmitRequest`, `FetchRequest`, `Capabilities`, `Reason`, and the four `MessageType` code points | `connect/protocol` | **No `.proto` edit and no generated code.** `sdk/go.mod` already carries `replace github.com/urnetwork/connect => ../connect`, so this costs no new module dependency |
| The transport: `Client.Send`, `Client.SendWithTimeout`, `Client.AddReceiveCallback`, `TransferPath`, `Id` | `connect` | **No transport.** `s2` writes a *binding* — correlation, fragmentation, timeouts — on top of a shipped one |
| The server: `Submit`, `CreateGroup`, `Fetch`, Hello, the epoch gate, the monotonicity check, both stores | `msgrepo` | **Nothing at all.** Verified rather than taken from a document: `msgrepo` builds clean and its suite is green, CP3c's tests pass, and `api/`, `peer/` and `store/` already carry every check leg 4 must satisfy |
| The reserver's five contract clauses, its two sentinels, and its mutation set | m1 Task 6 | **No new properties for leg 5.** Tasks 1–4 inherit m1 Task 6's five properties whole, `TestStreamIndexNeverReused` included, and add only what a *durable* implementation owes that an interface cannot state |
| `Sub`, `exportedList`, and `LocalState`'s storage-directory convention | `sdk` | The list machinery and where a file goes |

**And one reference that must be read and must not be imported.** `msgrepo/harness/client.go` is a
working client for every wire move Tasks 5–11 make — `request_id` correlation, §4.6 fragmentation
both ways with its own reassembler, per-connection `server_nonce` capture, `req_auth` over canonical
bytes, and the op byte read off the compiled descriptor. **Read it.** It cannot be imported: it is in
module `github.com/urnetwork/message-server`, which `sdk/go.mod` neither requires nor replaces, and
it is additionally gated test-only by `msgrepo/deps_test.go`'s own import-graph test. It also carries
one active decoy — its `padToRung` pads with a byte derived from the index and writes no length
prefix, while `messagegroup`'s `padBody` writes a syntax length prefix and a zero tail. **`s2` seals
through `SealRecord` and writes no padder at all**, so the messagegroup scheme is the one on the wire
and the harness's is not a model.

### Where the owner's premise holds and where it does not

The 2026-09-06 ruling assigned both legs to `s2` on the reasoning that *"`sdk` already owns transport
and storage."* Half of that is true, and the half that fails is the load-bearing half. Measured in
`sdk` at `432986f`:

- **Transport — true of the VPN, not of messaging.** There are **two** production `connect.Client`
  constructions in `sdk`, not one: `device_local_provider.go:109`, owned by `deviceLocalProvider`,
  i.e. by the VPN device; and `sim_device.go:115`, `client := connect.NewClient(cancelCtx,
  config.ClientId, clientOob, clientSettings)` (a commented-out third is at `device_local.go:3238`).
  `sim_device.go` is `package sdk` with **no build tag** and builds its own `ApiOutOfBandControl`
  from `config.ByJwt` and `config.ApiUrl` — so the standalone authenticated client **S2-7** says has
  no precedent does have one, in the simulation surface, and S2-7 records that below. What is true
  and load-bearing is the rest: there is no request/response correlator, no fragmenter, and no
  message-server binding of any kind, and `grep -ril 'urmessage|messagegroup|MessageStore'` over
  `sdk` returns **zero files**.
- **Storage — false in the one respect leg 5 needs.** `sdk`'s storage is `LocalState`: one JSON or
  raw value per file under its storage home, written with `os.WriteFile`. There is no database, no
  transaction, no atomic rename, and a grep for `.Sync()` over `sdk` production code returns one hit,
  in generated cgo exports, unrelated. Contract clause 1 — *"`Reserve` returns only after the
  reservation survives a process death"* — has **no precedent in this tree to copy**, and clause 1's
  own warning is that a `Reserve` returning before the flush *"is a nonce reuse machine that passes
  every round trip test there is"*.

This is why Task 2 is written as a durability task and not as a file-format task, and why `sdk`'s
existing storage helper is named in the reuse table for its **directory convention only**.

### Does s1 have to land first? No — and this is the most valuable scheduling fact in the document

s1 is sixteen tasks and is **written and unexecuted**: `sdk` contains none of its declarations.
s1's own open items say **S1-9** *"blocks s2 entirely"*, and **S1-4** and **S1-8** *"blocks s2's
schema"*. Measured against the actual dependency, all three claims are narrower than they read.

- **Legs 4 and 5 name no s1 symbol.** The reserver's subject is `messagegroup.StreamIndexReserver`
  and `messagegroup.StreamKey`. The transport's subjects are `connect`, `connect/protocol`,
  `connect/message` and `connect/messagegroup`. s1's own File Structure does not list
  `message_store.go` at all.
- **S1-9 blocks only the ENTRY half of §8.2.** `StoredEntry` is named in exactly **four** of §8.2's
  fourteen methods — `PutEntries`, `EntriesBefore`, `EntryById`, `SearchEntries` — and **none of the
  four is a stream method**. Tasks 1–4 need `ReserveStreamIndex` and `StreamHighWater` and nothing
  else from that interface.
- **S1-4 and S1-8 block the `pin` and entry schemas**, which are not in this plan's prefix at all.

**The ruling this plan takes, and it is a position rather than a reading.** Tasks 1–12 land under
**package-internal declarations plus the two §8.2 stream methods**, with no dependency on any s1
type. What genuinely waits for s1 is **surfacing** — exposing any of this as a method on
`MessageClient`, which is s1's declaration to make. That surfacing is not in this plan; it is named
in *What this plan does not close*.

**And one thing this plan deliberately does NOT declare: the `MessageStore` interface itself.**
Declaring a *partial* `MessageStore` would put §8.2's name on a different method set, and A8 makes
the fourteen-method bound the point of the interface. So Task 3 declares the **concrete store type**
with the two stream methods spelled exactly as §8.2 spells them — so that the day `StoredEntry` is
ruled the type already satisfies the interface — and declares no interface under that name. Filed as
**S2-12**.

### Dependency policy

- **New MODULES in the root `sdk` module: none. One require-block line, and it is scheduled rather
  than discovered.** Everything Tasks 1–15 need is the standard library plus
  `github.com/urnetwork/connect`, already replaced to `../connect` — **with one exception the earlier
  draft's blanket sentence hid**. Task 5's `Call` takes a `proto.Message`, so
  `google.golang.org/protobuf` becomes a **direct** requirement; it sits in `sdk/go.mod`'s second
  require block today as `// indirect` (`v1.36.11`, measured 2026-09-09), so this is a `go.mod` edit
  and **not a fetch**. `sdk/go.mod` is therefore in Task 5's Files list, and Task 13 Property 4 gates
  the require blocks so a second promotion is visible on the commit that makes it. Task 2a's
  per-`GOOS` exclusion adds nothing: `syscall` is the standard library.
- **`modernc.org/sqlite` is deliberately kept OFF the CP3b prefix**, and this is a position rather
  than an omission. Spec A A8 / A-ASSUME-1 calls it *"CONFIRMED, not an assumption"* and cites a
  gomobile `android/arm` CI gate as having settled it. Measured 2026-09-09: the module is **not in
  the module cache**, so adopting it is a network fetch of a large transitive tree into the one
  module that feeds the AAR, the Apple framework and the DLL — and `sdk` has **no `.github`
  directory**, so the gate said to have settled it **cannot have run**. The reserver needs an fsync,
  not a query planner: one row per `StreamKey`, created once and thereafter written in place and
  flushed — see Task 2 for why the rename an earlier draft prescribed is off the allocation path. §8.1's own table
  marks the `stream` high-water rows *"no"* for encryption, so the CP3b half of `s2` needs no
  `Sealer` and no DPAPI either. Filed as **S2-11**. SQLite remains A8's choice for the **entry and
  search** store, which is off this prefix entirely.

### Layering

- Spec A §2.3: `sdk` → `connect/messagegroup` → `connect/message` → `connect/mls` →
  `connect/mls/syntax`. This plan creates the **first production `sdk` → `connect/messagegroup` and
  `sdk` → `connect/message` edges in the tree**, and both are legal.
- **`sdk` must not import `connect/mls` from any production file.** Gate 5 (§4.5) is the whole reason
  the engine seam exists, and `NewConnectMlsEngine`'s five parameters are all `connect/mls` types.
  **`s2` therefore never constructs a `GroupEngine` or a `GroupHandle`; it takes one as an injected
  value.** The single legitimate production edge is s5's engine factory and it is s5's to introduce.
  Task 13 is the gate, written against the **non-test** dependency set (`go list -deps`, not
  `-deps -test`) for the reason s1's open item S1-13 records.
- **`sdk` must not import `github.com/urnetwork/message-server`.** Task 13 gates that too.

### House style

`connect/CODESTYLE.md` is the house style for both repos; `sdk` has no copy and follows it anyway.
`self` receivers; `stateLock` for guarded state; explicit field names at every initialisation; a doc
comment on every file, type and function. Tests are top-level `func TestXxx(t *testing.T)`; positive
tests do not use `t.Run`. `gofmt`. Binary constants as products of decimals, never shifts.

---

## Interfaces consumed from other plans

Everything below already exists and compiles. Shapes are described so the plan is readable; **their
spellings are not normative (R2)** and every one must be read out of the file that declares it before
a call is written. Measured at `connect` `beta/message` `33932e0`, where
`go build ./message/... ./messagegroup/... ./protocol/...` exits 0.

```go
// connect/messagegroup/streamindex.go — leg 5's whole subject. Reserve ALLOCATES
// and returns the index; it does not take one. Post-A1 the key is CLASS-BLIND.
type StreamIndexReserver interface {
    Reserve(stream StreamKey) (uint64, error)
    HighWater(stream StreamKey) (uint64, error)
}
type StreamKey struct {
    GroupId      [32]byte
    SenderHandle [16]byte
}
```

```go
// connect/messagegroup/session.go and seal.go — the COMPLETE exported method set of
// *GroupSession is these seven. There is NO key accessor, NO group_handle_key
// accessor and NO server-nonce setter; that absence is S2-1 and S2-2.
func NewGroupSession(handle GroupHandle, pqSecret []byte, groupHandleKeyEpoch0 []byte,
    reserver StreamIndexReserver, nowMs func() int64, serverNonce []byte) (*GroupSession, error)
func (self *GroupSession) SealRecord(class message.RetentionClass, ephBucket uint8, isCommit bool,
    headPlain []byte, bodyPlain []byte, expireAt uint64,
    serverAttachment *message.ServerAttachment) (*message.Record, error)
func (self *GroupSession) OpenRecord(record *message.Record) ([]byte, []byte, error)
func (self *GroupSession) Close() error
func (self *GroupSession) Epoch() (uint64, error)
func (self *GroupSession) SenderHandle() ([16]byte, error)
func (self *GroupSession) AdvanceEpoch(pqSecret []byte) error
func (self *GroupSession) TrackSender(leaf uint32, class message.RetentionClass,
    ephBucket uint8, headIndex uint64) error
```

```go
// connect/messagegroup — the key-schedule and handle primitives s2 may call.
// GroupHandle.Export is the ONLY door to mls_secret, and the label and length it
// takes are UNEXPORTED constants inside the package. That is S2-1.
func StorageRoot(mlsSecret []byte, pqSecret []byte) []byte
func GroupHandleKey(storageRootEpoch0 []byte) []byte     // PANICS on a non-32-octet root
func SenderHandle(groupHandleKey []byte, leaf uint32) [16]byte  // PANICS on a short key
func WrapTargetHandle(groupHandleKey []byte, contentEpoch uint64, leafIndex uint32) [16]byte
// GroupHandle is TWENTY-THREE methods, counted off the syntax tree rather than
// by eye: GroupId, Epoch, OwnLeafIndex, MemberCount, MemberAt, Export,
// SenderDataSecret, EncryptionSecret, EpochAuthenticator, RatchetTreeSnapshot,
// GroupContextBytes, ProposeAdd, ProposeRemove, ProposeUpdate,
// ProposeGroupPolicy, Commit, MergePendingCommit, ClearPendingCommit, Process,
// ApplyCommit, Protect, Unprotect, Close. The number is written down here with
// its derivation attached because four independent reads of this interface
// during this plan's preparation returned 18, 22, 24 and 26 — every one of them
// a hand count, and every one of them wrong. Count it, do not read it.
type GroupHandle interface { /* the 23 above — read engine.go */ }
```

```go
// connect/message — the codec and every authenticator. s2 links these and writes
// no second implementation of any of them (§12.1 A-1).
func EncodeRecord(r *Record) ([]byte, error)
func ParseRecord(b []byte) (*Record, error)
func WriteKey(storageRoot []byte) []byte
func ReadKey(storageRootEpoch []byte) []byte
func ComputeWriteAuth(writeKey []byte, serverNonce []byte, h *RecordHeader,
    ctHead []byte, serverAttachment []byte) [32]byte
func ComputeRequestAuth(readKey []byte, serverNonce []byte, op uint8, requestBytes []byte) [32]byte
func RetentionClassWire(class RetentionClass, ephBucket uint8) (byte, error)
func EncodeServerAttachment(a *ServerAttachment) ([]byte, error)
type Record struct{ RecordId uint64; Header RecordHeader; CtHead, CtBody []byte; WriteAuth [32]byte }
type ServerAttachment struct{ Kind ServerAttachmentKind; Epoch *EpochAttachment
    Recovery *RecoveryTag; Wrap *WrapTag; Complete *EpochComplete }
```

```go
// connect — the shipped transport. transfer.go's normative note on ReceiveFunction
// is load-bearing for Task 5: frames and their message bytes are BORROWED and valid
// only until the callback returns, and the callback is an inline backpressure
// boundary. Never hand a borrowed Frame to a goroutine or a channel.
func (self *Client) Send(frame *protocol.Frame, destination TransferPath, ackCallback AckFunction) bool
func (self *Client) SendWithTimeout(frame *protocol.Frame, destination TransferPath,
    ackCallback AckFunction, timeout time.Duration, opts ...any) bool
func (self *Client) AddReceiveCallback(receiveCallback ReceiveFunction) func()
type ReceiveFunction = func(source TransferPath, frames []*protocol.Frame, peer Peer)
func DestinationId(destinationId Id) TransferPath
```

```go
// connect/protocol — the wire. The Go spellings carry a DOUBLED prefix; a spelling
// copied from an older spec revision is a compile error, not a silent break.
MessageType_MessageMessageServerRequest  = 1000
MessageType_MessageMessageServerResponse = 1001
MessageType_MessageMessageServerPush     = 1002
MessageType_MessageMessageServerFragment = 1003
type Record struct{ RecordBytes []byte; SenderHandle []byte; Epoch, StreamIndex uint64
    IsCommit bool; RetentionClass, SizeBucket uint32; ExpireAtMs uint64
    BodyHash, BlobId, WrapTargetHandle, RecoveryHandle []byte; RecordId uint64 }
type CreateGroupRequest struct{ GroupId []byte; InitialCommit *Record; BootstrapWriteKey []byte }
type FetchRequest struct{ GroupId []byte; SinceRecordId uint64; Limit uint32; HeadsOnly bool
    ClassMask uint32; ReadEpoch uint64; ReqAuth []byte }
```

**Consumed from m1, as properties rather than as code.** m1 Task 6's five contract clauses and its
seven mutations are inherited whole by Tasks 1–4. m1 Task 6 states them; this plan does not restate
them as if they were new, and a task below that appears to add one is adding what a *durable*
implementation owes beyond what an interface can state.

**Pending pins — cross-plan symbols this plan names that do NOT exist yet.** Task 15's registry entry
must carry these, so that on the day the producer lands the gate fails and asks for the pin rather
than leaving a stale reference for the next reader.

| Symbol | Producer | Consumed by | State on 2026-09-09 |
|---|---|---|---|
| a reachable `read_key[e]` / `write_key[e]` for a live session | `connect` — unowned | Tasks 9, 10, 11 | **absent.** `GroupSession` has seven exported methods and none returns a key. **S2-1** |
| a `server_nonce` rebind on a live `GroupSession` | `connect` — unowned | Task 7 | **absent.** No setter exists. **S2-2** |
| a `pq_secret` DELIVERY channel (the device wrap) | m1 Task 14 | Tasks 8a and 9 | **blocked** on ledger item 152 **alone, since 2026-09-09** — `M1-1`'s remainder and `M1-7` were ruled that day as composite `C3`, so Task 14's field list, signature preimage and padding are settled and its only remaining blocker is the landed `EPH` seal refusal. The SAMPLER landed while this plan was being reviewed — `messagegroup/epoch.go` is tracked at `connect` `7868d65` and declares `NewPqSecret` — and the delivery did not: there is no `wrap*.go` in `messagegroup`, and `XwingEncapsulate` / `XwingDecapsulate` still have **zero production callers outside `xwing.go`**, re-measured at `7868d65`. **S2-3** |
| a working `GroupEngine.JoinFromWelcome` | m1 Task 16, and `connect/mls` upstream of it | any two-client run | **absent.** An unconditional refusal on every input. **S2-4** |
| an injected `GroupEngine` / `GroupHandle` factory | s5 | Tasks 9–12 | absent; Gate 5 forbids `s2` from constructing one |
| a production `mls.StateStore` | s5, or unowned | any run across a process boundary | **absent.** The interface has eight methods and zero production implementations in any tree. **S2-14** |
| `MessageClient` and its method set | s1 | the surfacing this plan does not do | absent; s1 is written and unexecuted |
| `StoredEntry` | s1 open item S1-9 | the ten §8.2 methods this plan does not declare | undefined in every document. **S2-12** |

---

## Interfaces produced by this plan

Every later slice-2 plan writes its `Consumes` block against these. Each is restated inside the task
that creates it. Shapes, not spellings (R2).

```go
// sdk/message_stream_store.go — leg 5. The durable reserver, in §8.2's own
// spelling so that the day StoredEntry is ruled this type already satisfies
// MessageStore's two stream methods without an edit.
package sdk

type StreamStore struct{ /* unexported */ }

func OpenStreamStore(dir string) (*StreamStore, error)
func (self *StreamStore) Close() error
func (self *StreamStore) ReserveStreamIndex(groupId, senderHandle []byte) (uint64, error)
func (self *StreamStore) StreamHighWater(groupId, senderHandle []byte) (uint64, error)
```

```go
// sdk/message_stream_adapter.go — the flattening §8.2 assigns to the implementer,
// in ONE place. It is the only code in sdk that converts between a StreamKey and
// the two []byte parameters, and the only code that maps a store failure onto
// messagegroup's sentinels.
type streamReserver struct{ /* unexported */ }

func NewStreamIndexReserver(store *StreamStore) messagegroup.StreamIndexReserver
```

```go
// sdk/message_transport.go — leg 4a. The message-server binding over the existing
// connect.Client. Unexported construction: nothing here is on the ABI, and the
// surfacing onto MessageClient is s1's declaration and not this plan's.
type messageTransport struct{ /* unexported */ }

type messageTransportConfig struct {
    Client          *connect.Client
    Server          connect.Id
    ProtocolVersion uint32
    PartBytes       int
    Timeout         time.Duration
}

type messageTransportCounts struct{ /* unexported */ }

func newMessageTransport(config *messageTransportConfig) (*messageTransport, error)
func (self *messageTransport) Close()
func (self *messageTransport) Call(ctx context.Context, body proto.Message) (*protocol.MessageServerResponse, error)
func (self *messageTransport) Hello(ctx context.Context, versions ...uint32) (protocol.Reason, *protocol.HelloResponse, error)
func (self *messageTransport) Nonce() []byte
func (self *messageTransport) NonceEpoch() uint64
func (self *messageTransport) Capabilities() *protocol.Capabilities
func (self *messageTransport) Counts() messageTransportCounts
```

```go
// sdk/message_stream_exclusion_*.go — leg 5's single writer. One declaration
// per GOOS; the fallback file's body is a refusal, not a no-op.
var ErrStreamStoreLocked error

func acquireStreamStoreExclusion(dir string) (io.Closer, error)
```

```go
// sdk/message_client.go — the seam. The ONLY place package sdk constructs a
// GroupSession, and the declaration of the two halves every later Produces
// block writes a method on. Package-internal: the surfacing onto s1's
// MessageClient is s1's declaration and not this plan's (S2-19).
type messageClientConfig struct{ /* Transport, Handle, PqSecretZero, StorageRootZero,
    Streams, Receive, NowMs, GroupId */ }
type messageClient struct{ /* unexported */ }
type messageSender struct{ /* unexported */ }
type messageReceiver struct{ /* unexported */ }

type sealedRecord struct {
    Record     *message.Record
    Attachment *message.ServerAttachment
    NonceEpoch uint64
}

func newMessageClient(config *messageClientConfig) (*messageClient, error)
func (self *messageClient) Sender() *messageSender
func (self *messageClient) Receiver() *messageReceiver
func (self *messageClient) Close() error
func (self *messageSender) Seal(class message.RetentionClass, ephBucket uint8, isCommit bool,
    headPlain []byte, bodyPlain []byte, expireAt uint64,
    attachment *message.ServerAttachment) (*sealedRecord, error)
```

```go
// sdk/message_projection.go — the §4.3.3 projection. Written in sdk on purpose;
// see S2-9 for why this is the one deliberate second implementation on the leg
// and why it is not an instance of the defect the reuse table forbids.
func recordProjection(record *message.Record, attachment *message.ServerAttachment) (*protocol.Record, error)
```

```go
// sdk/message_send.go and sdk/message_group_open.go — the send path and the
// group-opening ceremony the server's epoch gate requires before it.
func (self *messageSender) OpenGroup(ctx context.Context, spec *groupOpenSpec) error
func (self *messageSender) SubmitRecord(ctx context.Context,
    sealed *sealedRecord) (*protocol.SubmitResult, error)
```

```go
// sdk/message_fetch.go and sdk/message_receive_state.go — the receive path and
// the second durable store nobody had been given: the per-peer head index that
// TrackSender takes and that a record header must never supply.
type readKeyRef struct {
    Epoch uint64
    Key   []byte
}

func (self *messageReceiver) Fetch(ctx context.Context, request *protocol.FetchRequest,
    readKey *readKeyRef) (*protocol.FetchResponse, error)

type ReceiveState struct{ /* unexported */ }

func OpenReceiveState(dir string) (*ReceiveState, error)
func (self *ReceiveState) HeadIndex(groupId []byte, leaf uint32, retentionWire byte) (uint64, error)
func (self *ReceiveState) AdvanceHeadIndex(groupId []byte, leaf uint32, retentionWire byte, index uint64) error
func (self *ReceiveState) Close() error
```

---

## File Structure

Every file created or modified by this plan, and its single responsibility.

| File | Responsibility |
|---|---|
| `sdk/message.go` | Package-level doc for the messaging client; the R2 statement, in the source, that every signature on this leg is read from the file that declares it — and the three-way divergence S2-15 records |
| `sdk/message_stream_store.go` | `StreamStore`: the on-disk row, the key-space version tag, the width refusals, `OpenStreamStore`, `Close`, `ReserveStreamIndex`, `StreamHighWater`, and the fsync boundary |
| `sdk/message_stream_exclusion_windows.go`, `sdk/message_stream_exclusion_unix.go`, `sdk/message_stream_exclusion_other.go` | Task 2a. The single-writer exclusion, one declaration per `GOOS`, held by the operating system. The `other` file's body is `ErrStreamStoreLocked`: a platform this store cannot make safe is one it refuses to open on |
| `sdk/message_stream_adapter.go` | The `StreamKey` flattening and the sentinel mapping, in exactly one place |
| `sdk/message_errors.go` | The typed refusals this plan owns, each usable with `errors.Is` |
| `sdk/message_transport.go` | The `connect.Client` binding: frame build, `AddReceiveCallback` demux, `request_id` correlation, timeouts, counters |
| `sdk/message_transport_fragment.go` | §4.6 fragmentation and reassembly, both directions, and the one home for the part-size bound |
| `sdk/message_transport_hello.go` | Hello, the per-connection `server_nonce`, and the `Capabilities` cache |
| `sdk/message_projection.go` | The `*message.Record` → `*protocol.Record` projection |
| `sdk/message_client.go` | Task 8a. The seam: the one `NewGroupSession` call in `package sdk`, the one `SealRecord` call site, the `messageSender` and `messageReceiver` declarations, and the sealed record that carries its own nonce epoch |
| `sdk/message_group_open.go` | The ceremony: `CreateGroupRequest`, the `EpochAttachment`, the wraps, the `EpochComplete` marker |
| `sdk/message_send.go` | Seal → project → `SubmitRequest` → `SubmitResult` disposition |
| `sdk/message_fetch.go` | `FetchRequest` with `read_epoch` and `req_auth`, and `ParseRecord` on the way back |
| `sdk/message_receive_state.go` | `ReceiveState`, the durable per-peer head index, and the `sender_handle` → leaf map |
| `sdk/message_stream_store_test.go` | Tasks 1, 2, 2a and 4's gates, including the crash-restart harness, the two-process exclusion gate, and the torn-tail gate |
| `sdk/message_stream_adapter_test.go` | Task 3's gates |
| `sdk/message_transport_test.go`, `sdk/message_transport_fragment_test.go`, `sdk/message_transport_hello_test.go` | Tasks 5, 6 and 7's gates |
| `sdk/message_projection_test.go` | Task 8's descriptor-derived gate |
| `sdk/message_client_test.go` | Task 8a's gates: the construction count, the seal-site count, and the G11 lost-commit re-seal |
| `sdk/message_group_open_test.go`, `sdk/message_send_test.go` | Tasks 9 and 10's gates |
| `sdk/message_fetch_test.go`, `sdk/message_receive_state_test.go` | Tasks 11 and 12's gates |
| `sdk/message_layering_test.go` | Task 13: the production dependency set of `sdk`, and the two edges it must not contain |
| `sdk/.github/workflows/messaging-client.yml` | Task 14. The repository has **no** `.github` directory today |
| `sdk/.gitattributes` | Task 14: `eol=lf` for Go and module files. `sdk` has none, and this project has already lost 84 source anchors to a carriage return |
| `sdk/go.mod` | **modify:** Task 5 promotes `google.golang.org/protobuf` from the indirect require block to the direct one. No fetch; see *Dependency policy* |
| `msgrepo/docs/plans/2026-08-12-slice1-interface-registry.md` | **modify:** Task 15 adds `s2`'s produced surface and its pending pins |

---

## How to read a task

Each task has **Files**, an **Interfaces** block naming exactly what it consumes and what it
produces, and numbered steps. The steps are always the same six, and steps 1 and 5 are where the work
is.

1. **Derive the property and write the failing test.** The task states the property, the refusal that
   property owes, and — separately, per R3 — the scope the gate must derive. It does **not** state
   the test. Read every signature you call out of source (R2).
2. **Run it and watch it fail for the stated reason.** A test that fails to compile has not yet
   failed for the stated reason.
3. **Write the minimal implementation.**
4. **Run it and watch it pass.**
5. **Mutation-test.** Apply each numbered mutation, run the targeted `-run` first, and record the
   result. Any mutation that survives the targeted run is re-run against the full package. **A
   surviving mutation is a defect in the test, not a curiosity**: fix the test and re-run the whole
   set. Record survivors and their reason in the commit message.
6. **Commit.**

---

## Wave 1 — leg 5, the durable reserver (Tasks 1–4)

**This wave needs nothing.** No transport, no s1 symbol, no `GroupHandle`, no new dependency, and no
ruling from anybody except the one Task 1 asks for. It should land first and alone. It is also the
one wave whose defect is silent: a reserver that returns before its flush passes every round-trip
test there is, because the reused index is still well formed and the record still opens against
itself.

### Task 1: The row, its identity, and the transition rule ledger item 170 asks for

**Files:**
- Create: `sdk/message.go`, `sdk/message_stream_store.go`, `sdk/message_errors.go`
- Test: `sdk/message_stream_store_test.go`

**Interfaces:**
- Consumes: `messagegroup.StreamKey` (`GroupId [32]byte`, `SenderHandle [16]byte`) — the type whose
  field set **is** the row identity. Nothing from any plan's task.
- Produces:
```go
// the row identity and the refusals that make ledger item 170's hazard
// structurally unreachable rather than merely unlikely.
type StreamStore struct{ /* unexported */ }

func OpenStreamStore(dir string) (*StreamStore, error)
func (self *StreamStore) Close() error

var ErrStreamKeyWidth   error  // a groupId or senderHandle of the wrong width
var ErrStreamKeySpace   error  // a row written under a key derivation this build does not produce
var ErrStreamStoreState error  // a row that is present and unreadable, never a silent zero
```

**Why ledger item 170 gets a mechanism here and not a migration.** Item 170 says a store holding
pre-A1 rows answers `HighWater` **0** for an A1 key, because contract clause 4 makes *"never seen"* a
silent, error-free zero; the ladder then resumes at position 1 and `Next` hands out `record_key[1]`
under a class key that has not moved, which is a repeated `(key, nonce)` on **both** AEADs. The item
proposes a one-sentence ruling in this plan: *rows written under a `StreamKey` carrying a retention
byte are migrated by taking the maximum over the classes of one `(group_id, sender_handle)`, or the
whole key space is versioned and refused.*

**This plan requires the second, and it requires it as a mechanism rather than as a sentence.**
Two reasons, and the second is the one that matters.

1. **The migration half is vacuous here and saying so is load-bearing.** `s2` is the **first** durable
   reserver in any tree — verified 2026-09-09: `grep -rn 'StreamIndexReserver\|ReserveStreamIndex'
   --include=*.go` over `connect` and `sdk` finds the interface, the ratchet, the session and the
   test fakes only. A store that has never existed cannot hold a pre-A1 row, so a migration written
   for one is dead code on the day it ships, and dead code on a safety path is worse than no code.
2. **A versioned key space closes the hazard's PROPERTY, not its instance (R4).** The property is
   *"a row this build cannot key is answered as a silent zero"*. Pre-A1 rows are one instance of it;
   a future ruling on **M1-5** that changes row identity again is another; a partially written file
   from a killed process is a third. A version tag in the key derivation refuses all three
   identically. **The plan therefore does not need M1-5 ruled in order to be safe** — it still asks
   for the ruling, and **S2-5** says what the ruling blocks.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — a row is identified by exactly the fields the RESERVATION is keyed by, and the
  identity is derived from `StreamKey`'s own field set rather than spelled.** m1 Task 6's test fake
  already derives its row string by reflecting over `StreamKey`, which is what makes row identity the
  field set *by construction*; this store owes the same derivation for the same reason. Every field
  of that derived class is two members at this task — `GroupId` and `SenderHandle` — and the gate must
  report the number it read, so a field added or removed in `connect` fails here rather than silently
  re-keying every row.
  *Refusal owed:* none — this is a derivation, and its failure mode is a wrong count, not an error
  value.
  *Scope to derive, separately from the class (R3):* the scope is **the type `StreamKey` as
  `connect/messagegroup` declares it today**, read through reflection at test time, and not a copy of
  its field names in `sdk`. A gate that lists `GroupId` and `SenderHandle` survives the day a third
  field returns and is therefore not this gate.

  **Property 2 — a row whose key space this build did not produce is REFUSED, never answered zero.**
  The row's on-disk name carries a version tag derived from the same field set Property 1 derives.
  A row bearing any other tag is `ErrStreamKeySpace`.
  *And the names in the row directory partition three ways, over the name's own shape and never over
  intent, because "either tag" below is otherwise an undefined antecedent and one of its two readings
  breaks mutation 3.* **(a)** a name that parses as `tag ‖ identity` under **this build's** tag — an
  ordinary row; **(b)** a name that parses as `tag ‖ identity` under a fixed-width tag that is **not**
  this build's, whatever its value — `ErrStreamKeySpace`, which is the answer mutation 3's planted
  pre-A1 row must get; **(c)** anything else in the row directory — `ErrStreamStoreState`. Read as
  *"the two tags the codebase knows about"*, the categorical rule below would send mutation 3's row
  to (c), and **the mutation this task calls the single most important in the wave would demand an
  error the store does not produce**. The tag is fixed-width and self-delimiting, so (b) and (c) are
  separated by the name alone and by nothing a build has to remember.
  *Refusal owed:* `ErrStreamKeySpace`, a typed fatal error per §5.9 G7 — never a bool, never a log
  line, and specifically **never `(0, nil)`**, which is the answer contract clause 4 gives an unseen
  stream and which is exactly what makes item 170's hazard silent.
  *And the mechanism has a precondition the property is useless without.* The tag must be
  **separable**: a fixed-width, self-delimiting field readable off the row's name **independently of
  the identity**, and `StreamHighWater` must **enumerate the row directory** rather than stat one
  path. If the tag is folded into the derived identity hash, a foreign-key-space row is simply a file
  whose name this build never computes — an absent row — `HighWater` answers `(0, nil)`, and
  mutation 3 below, which this task calls the single most important mutation in the wave, **cannot be
  killed at all**. What that costs is one directory read per call, and it is priced here rather than
  discovered.
  *And the enumerated directory is not `dir`.* `dir` is this store's own directory, never `sdk`'s
  shared `LocalState` home, and `OpenStreamStore` creates **two** things inside it: a **row
  directory**, which holds rows and nothing else and is the only thing the enumeration ever reads;
  and, beside it and never inside it, whatever single entry Task 2a's exclusion is held on. This plan
  spells the row directory `dir/rows` for readability and the spelling is not normative; **what is
  normative is that the enumerated directory holds rows and nothing else, by construction**. Then
  the rule this property rests on can be categorical without an exception in it: **an entry in the
  row directory that is not a row under any tag — partition (c) above — is `ErrStreamStoreState`.**
  *Why two levels rather than one directory and an exempted name, because this is the collision the
  2026-09-09 repair introduced and this pass removes.* That repair put Task 2a's OS-held exclusion on
  a guard file **inside `dir`** and, in the same pass, wrote the categorical rule above over `dir` —
  so a correct implementation of Task 2a made every `StreamHighWater` after it refuse, and Wave 1 was
  red on the commit that completed it (Task 2a lands with Task 2). Two repairs were available and
  only one of them is a construction. *Rejected:* exempting the guard **by name** from the
  enumeration, which is an ignore-list — the ledger-21 defect in one line, and it goes on silently
  ignoring the second non-row somebody writes there tomorrow. *Rejected:* a guard **outside `dir`**,
  which puts this store's lock in a directory the store does not own — `sdk`'s shared home — where
  two stores' guards collide by name and the exclusion no longer sits on the tree it protects.
  *Taken:* the enumerated object and the excluded object are **different directories**, one nested in
  the other, so nothing has to be excluded from the enumeration at all and the refusal above gets
  **stronger** rather than weaker: nothing legitimate is ever written into the row directory, so
  anything found there is a real finding. Task 2a Property 1 names this back.

  **Property 3 — a key of the wrong width is refused at the boundary, before anything derives from
  it.** §8.2's parameters are `[]byte` and declare no length rule; `StreamKey`'s fields are
  `[32]byte` and `[16]byte` and are total. The flattening between them is where a 17-octet group id
  becomes either a panic or a silent truncation, and truncation collides two streams onto one row.
  *Refusal owed:* `ErrStreamKeyWidth`, naming which parameter and what width it had.
  *And this is not only hygiene:* `messagegroup.GroupHandleKey` and `messagegroup.SenderHandle`
  **panic** rather than return an error on a wrong-width input, defended by the argument that
  *"nothing here is reachable from the network: the key is this member's own persisted derivation."*
  This task is the thing that makes that value a row read off a disk. The width check here is what
  keeps that argument true; the panic is not a substitute for it. **S2-8**.

  **Property 4 — a present-but-unreadable row is an error, it is a DIFFERENT error from an absent
  one, and a TORN TAIL is neither.** Clause 4's error-free zero is correct for a stream never seen
  and catastrophic for a stream whose row cannot be read, and the two are one `os.IsNotExist` apart.
  The third case is the one an earlier draft of this property did not have, and it is not a
  refinement: under the row format step 3 mandates — fixed-width checksummed records, appended one
  per allocation — a trailing record that does not verify is the **ordinary** outcome of a crash
  mid-append, and answering it with an error is a store no later process can open.
  **The three cases, and the discriminator is POSITION and SIZE, not content.**
  1. **Absent row.** `(0, nil)`. This is clause 4's answer for a stream never seen.
  2. **Torn tail.** A failing **suffix** — trailing bytes that are not a whole record, and/or a
     final whole record whose checksum does not verify — with **no verifying record after it**, and
     no larger than **one record plus a partial**. Discard it and answer the last record that does
     verify; if none does, answer `(0, nil)`, because a row carrying no verifying record is the state
     `OpenStreamStore` creates a row in **before** it hands out an index for that key, and that is the
     same state a stream never seen is in. No error in either sub-case.
  3. **Corrupt body.** A record that fails to verify with a **verifying record after it**, or a
     failing suffix **larger than one record plus a partial**, or a row whose name parses but whose
     records are not a whole number of record widths in a way case 2 cannot explain.
     `ErrStreamStoreState` — never `(0, nil)`, and never the last surviving record's value.
  **AND THE ONE THING THE THREE CASES DO NOT SETTLE ON THEIR OWN: a truncated row and an interrupted
  append are the SAME BYTES, and the store answers them the same way.** A three-record row truncated
  to half its length is `R1` followed by half of `R2`. A two-record row whose second append flushed
  halfway is `R1` followed by half of `R2`. **They are byte-identical**, and the format admits no
  third input: no header, no record count, no external length authority, and — by Task 2 Property 1 —
  exactly **one** forced flush on the allocation path, so there is no second durable object that
  could hold a count even if one were wanted. The only inputs any rule here has are the row's length,
  the record width and the per-record checksum verdicts, and the two rows are equal under all three.
  **No function of those inputs can answer them differently, so this plan does not ask for one.**
  Both are case 2: discard the failing suffix and answer the last record that verifies. *This is the
  resolution of the contradiction the 2026-09-09 repair pass relocated rather than removed, and it is
  a stronger statement than re-aiming a mutation:* re-aiming moves the demand, while this says the
  demand was for a discriminator that does not exist. **A rule that claims to detect truncation on
  this format is a rule that has invented an input.**

  **The classification as a decision procedure, because three cases in prose are a partition and an
  implementer needs the function.** Let `W` be the record width and `L` the row's length; let
  `k = L div W` and `r = L mod W`, so the row is records `R_1 … R_k` at offsets `0, W, …, (k−1)·W`,
  followed by an `r`-octet partial when `r > 0`.

  1. The row is **absent** → case 1, `(0, nil)`. A row that is **present and zero-length** is not
     case 1; it is case 2's no-verifying-record sub-case, and it takes the same `(0, nil)` for the
     reason case 2 already gives.
  2. Let `f` be the least `j` whose `R_j` fails its checksum, or `k+1` if every record verifies.
     **If any `R_j` with `j > f` verifies → case 3.**
  3. Otherwise the failing suffix is `R_f … R_k` plus the partial: `k − f + 1` whole records and `r`
     octets. **If `k − f + 1 ≥ 2` → case 3**, a failing suffix larger than one record plus a partial.
  4. Otherwise (`k − f + 1 ≤ 1`) → **case 2**: discard from offset `(f−1)·W` to the end and answer
     `R_{f−1}`'s value; if `f = 1`, answer `(0, nil)`.

  **The procedure is total, and it is the whole of the rule.** Case 3's third clause — *"a row whose
  name parses but whose records are not a whole number of record widths in a way case 2 cannot
  explain"* — names no row step 3 does not already reach: `r > 0` on its own is always explained by
  case 2's partial, and `r > 0` beside two or more failing records is already case 3 by step 3. The
  clause is kept as prose and it **adds no case**. A reading under which it adds one is a reading in
  which the rule is not a function of the row's bytes, which is the defect this paragraph removes.

  **What the ruling costs, said here because it is a price and not a gap.** An out-of-band truncation
  that removes whole **flushed** records is undetectable, and it rewinds the high water silently.
  Task 2 Property 2's `ErrStreamStoreRewound` catches it only while the process that handed out the
  higher index is still alive; across a restart there is nothing left to compare against. **S2-23.**

  **The bound in case 2 is derived, not chosen.** The allocation path appends **one** record and
  flushes, so at most one record can be un-flushed when a process dies; a failing suffix bigger than
  that cannot be an interrupted append and is therefore corruption. That derivation is what makes
  the discard safe, and Task 2 states its other half: a `Reserve` whose flush had not returned had
  not returned an index, so discarding a torn tail discards nothing that was ever handed out.
  **The bound is also the thing a later change breaks silently** — a batched allocation that appended
  two records per flush would invalidate it without touching a line of this property. That is
  **S2-22**.
  *Refusal owed:* `ErrStreamStoreState` for case 3, naming which of the three shapes it found;
  `(0, nil)` for case 1 and for case 2's no-verifying-record sub-case; and **never**
  `ErrStreamStoreState` for a torn tail, which is the half Task 2's own design requires and this
  property now carries. Task 2 Property 2 and Task 2a Property 4 both read this answer.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**

  `sdk/message.go` carries the package doc and, **in the source rather than only in this plan**, the
  R2 statement and the three-way §8.2 divergence of **S2-15**, so the next reader finds it before
  writing a call rather than after.

  The row is one file per `StreamKey` **in the row directory** — the subdirectory of `dir` that
  Property 2 requires hold rows and nothing else — named by the version tag and the derived identity
  — **in that order**, so the tag is readable off the name without computing the identity, which is
  what Property 2's refusal rests on. One file per key rather than one file for all keys is not a
  performance choice: it makes the flush of Task 2 a single-file flush, and it makes a corrupt row
  cost one stream instead of every stream. Nothing but a row is ever written into that directory,
  and Task 2a's guard entry sits beside it in `dir` for exactly that reason.

  **The row has two lifecycle events and only one of them recurs.** It is *created* — a directory
  entry, inside the row directory — the first time the store touches that key, **before any index for
  it has been handed out**; it is *appended to and flushed in place* on every allocation after that.
  Task 2 Property 1 is why: no allocation against a row that already exists mutates a directory
  entry, because the one platform this plan tells the implementer to work on cannot force a directory
  entry's durability at all. The row's format therefore carries its own integrity — fixed-width,
  checksummed records, and a rule that discards a tail whose checksum does not verify — rather than
  relying on an atomic replacement it no longer performs. **The create is inside the first
  `ReserveStreamIndex` for that key** and is the one directory-entry mutation the design admits,
  exactly once per key; Task 2 Property 1's second number is written over the steady-state path for
  that reason, and S2-16 is the residual it leaves.

- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add a third field to a local copy of `StreamKey` and key rows off the copy. Property 1 must
     fail on the count, not on a comparison of names.
  2. Hard-code the two field names into the row derivation. Property 1 must fail when the reflected
     field set and the spelled one disagree — and a gate that passes here is the ledger-21 defect.
  3. Plant a row under a pre-A1 key derivation (the three-field one) and read it with an A1 key.
     Property 2 must fail with `ErrStreamKeySpace`. **A `(0, nil)` here is ledger item 170 reproduced
     in `sdk`, and it is the single most important mutation in this wave.**
  4. Drop the version tag from the row name. Property 2 must fail.
  5. Pass a 17-octet `groupId`. Property 3 must fail with `ErrStreamKeyWidth`.
  6. Pass a 31-octet `groupId` and let it be zero-padded to 32. Property 3 must fail — a silent pad
     collides two streams onto one row, which is Property 3's whole point and is invisible to a test
     that only checks lengths that are too long.
  7. **Corrupt** the last **two** whole records of a row carrying at least three — overwrite their
     octets in place, leaving the row's length unchanged, so two whole records fail their checksums
     with no verifying record after them. Property 4 must fail with `ErrStreamStoreState`, and it
     must not answer the last verifying record's value and must not answer zero. The failing suffix
     is two whole records, which step 3 of the decision procedure sends to case 3.
     **Re-aimed twice, and the second time for a reason worth keeping in the document.** The first
     version truncated a row *"to half its length"* with no bound and demanded `ErrStreamStoreState`
     for exactly the cut Task 2 mutation 10 requires the store to **discard**. The 2026-09-09 repair
     added the three-record bound and left the truncation in place, which moved the contradiction
     **inside this task** rather than removing it: at N=3 the cut leaves `R1` plus a half-record
     partial, which Property 4 case 2 answers with `R1` and no error, and at N=4 it leaves two whole
     verifying records and no failing suffix at all. **It may not be a truncation, and that is a fact
     about the format rather than about the wording.** Truncation is a byte-prefix operation: every
     whole record left in the prefix verifies and at most one partial trails it, so a truncated row
     is always case 2 by construction and **can never reach case 3**. A mutation demanding
     `ErrStreamStoreState` for a truncation is unsatisfiable by any implementation, for every N it
     could name.
  8. Corrupt one record in the middle of a row and leave every record after it verifying. Property 4
     must fail with `ErrStreamStoreState` — a failure with a verifying record after it is case 3 no
     matter how small it is.
  9. Answer `ErrStreamStoreState` for a torn tail rather than discarding it. Property 4 must fail,
     and Task 2 Property 1 and Task 2a Property 4 must fail with it. **This is the control that
     separates a corrupt body from an interrupted append**: a store that refuses a torn tail is a
     store no process can open after any crash mid-append, which is a permanent wedge on the exact
     path Task 2a Property 4 exists to make survivable, and a suite that cannot fail here has written
     the refusal Task 1 mutation 7 used to demand.
  10. Return `(0, nil)` for a row whose body is corrupt in the sense of case 3. Property 4 must fail.
  11. Classify by the row's **length alone** — refuse any row whose length is not a whole multiple of
      the record width. Property 4 must fail on a three-record row truncated to half its length,
      which the procedure sends to case 2 and which answers `R1` with no error; mutation 9 must fail
      with it, and so must Task 2 mutation 10's fixture. **This is the store that "detects
      truncation"**, and it is here because Property 4 now rules that it cannot: the same bytes are
      an interrupted append, and refusing them wedges every open after any crash mid-append.
  12. Take case 2's bound as *"a failing suffix no larger than `2W`"* rather than *"at most one whole
      record plus a partial"*. Property 4 must fail on a row whose last **two** whole records fail
      with no partial after them: the failing suffix is exactly `2W`, which the mutant admits to
      case 2 and answers `R_{k−2}` for, and which step 3 sends to case 3. This is the off-by-one the
      prose invites and the procedure removes, and it is what separates a suite that read the
      procedure from one that read the paragraph above it.

- [ ] **Step 6: Commit**

---

### Task 2: `Reserve`, `HighWater`, the fsync boundary, and the two sentinels

**Files:**
- Modify: `sdk/message_stream_store.go`, `sdk/message_errors.go`
- Test: `sdk/message_stream_store_test.go`

**Interfaces:**
- Consumes: Task 1's `StreamStore`, its row identity and its four refusals. **Nothing from
  `connect/messagegroup`, deliberately** — see the sentinel note below.
- Produces:
```go
// §8.2's two stream methods, spelled as §8.2 spells them. ALLOCATION, not
// assertion: Reserve takes no index and returns one.
func (self *StreamStore) ReserveStreamIndex(groupId, senderHandle []byte) (uint64, error)
func (self *StreamStore) StreamHighWater(groupId, senderHandle []byte) (uint64, error)

// the two CONDITIONS this task owes, as sdk's own typed errors. The NAMES
// messagegroup branches on are Task 3's and are reached by wrapping these.
var ErrStreamStoreRewound  error // persisted state behind an index already handed out
var ErrStreamStoreConsumed error // the store can never allocate for this key again
```

**Why this task owes the CONDITION and not `messagegroup`'s NAME.** Task 3 Property 1 declares the
adapter *"the only code that maps a store failure onto `messagegroup`'s sentinels"*, and this task's
Consumes block names nothing from `messagegroup`. Both are deliberate and the earlier draft broke
them: it made Property 2 owe `messagegroup.ErrStreamIndexRewound` directly, which an implementer
dispatched on Task 2 alone can satisfy only by importing `messagegroup` here (contradicting Task 3's
uniqueness) or by declaring a shadow sentinel in `sdk` (after which `errors.Is` against
`messagegroup`'s fails at the adapter). The source settles which half is which:
`connect/messagegroup/streamindex.go`'s contract clause 2 says *"A persisted state behind an index
already handed out is `ErrStreamIndexRewound`"* — a statement about the **composite** a caller sees,
which is store-plus-adapter. `ratchet.go` reads only one of the two sentinels off the reserver
(`errors.Is(err, ErrStreamIndexConsumed)` at `Next`; it raises `ErrStreamIndexRewound` itself at
`ratchet.go:318` from `index < self.position`), so the rewind name matters to a human reader and the
consumed name matters to a branch. The store owes both conditions; the adapter owes both names.

**This task implements m1 Task 6's five clauses and states no new ones.** m1 Task 6 declares the
contract and holds a file-backed fake to it; what a *durable production* implementation owes beyond
what an interface can state is the fsync boundary and the crash window, and those are Properties 1
and 2 below. The other three are m1 Task 6's, restated only because a mutation set needs a subject.

**The fsync obligation, and why "durable" here is not the retention class.** Clause 1 is *"`Reserve`
returns only after the reservation SURVIVES A PROCESS DEATH. Not after the write is issued, not after
it is buffered: after it is durable."* `sdk` has no precedent for any of this; its entire storage is
`os.WriteFile` with no flush anywhere in production code.

**And the recipe an earlier draft of this task gave — temp file, `Sync()` the file, rename, `Sync()`
the DIRECTORY — cannot be run on the platform this plan tells the implementer to work on.** Measured
2026-09-09 on this machine with the project toolchain (Go 1.26.5, `GOROOT` at
`claude_sandbox_message/toolchain/go`, Windows 11, NTFS): a program that does
`os.Create` / `Write` / `Sync` / `Rename` and then opens the containing directory prints

```
file Sync: <nil>
rename: <nil>
open dir: <nil>
dir Sync: sync C:\Users\...\Temp\dsync1057162880: Access is denied.
```

and `os.OpenFile(dir, os.O_RDONLY, 0)` gives the same handle and the same refusal. **A correct
implementation on Windows can perform exactly one forced flush on the allocation path, so a class
stated as two members fails for the correct implementation and mutation 2 cannot discriminate.**
There is no user-space lever for the other half: `FlushFileBuffers` on a volume handle needs
administrator privilege and flushes the whole volume, which is not something a client SDK may do.

**So the plan constrains the DESIGN rather than the platform, and prices what that costs.** An
allocation against a key whose row already exists performs **no directory-entry mutation at all** —
no create, no rename, no remove — and every such allocation is an in-place durable write of a file
that already exists. The one exception is **exactly once per key and is the create itself**: a row
file's directory entry is established when the store first touches that key, inside that key's first
`ReserveStreamIndex`, at a point where **no index has been handed out for it**. Saying *"the
allocation path performs no directory-entry mutation at all"* without that clause — which is how an
earlier version of this paragraph read — states a property no correct implementation can satisfy,
because the store has no key set at open time to pre-create from and S2-16 rejects requiring one. The
one flush on the allocation path is then a *file contents* flush, which `os.File.Sync` forces on
every platform this plan ships to, and the create is the one durability boundary Windows will not
force — S2-16.

**What that costs, stated rather than absorbed.** Three things. (1) There is no atomic replacement on
the allocation path any more, so a torn write must be survivable by the row's own format — a
fixed-width, checksummed record and a rule that discards a tail whose checksum does not verify. That
rule is safe for exactly one reason and the reason must be written into the implementation's comment:
a torn tail can only be a write whose flush had not returned, and a `Reserve` whose flush had not
returned had not returned an index, so discarding it discards nothing that was handed out. (2) Task 1
Property 4's *present-but-unreadable* refusal has to distinguish a torn **tail** (discard, answer the
last good record) from a corrupt **body** (`ErrStreamStoreState`), and those are different conditions
in the same file. **That obligation is DISCHARGED, and stating it here without discharging it is what
left Task 1 mutation 7 and this task's mutation 10 demanding opposite answers to one truncation for a
day.** It is discharged at **Task 1 Property 4**, which states the three cases and the size-and-
position discriminator between them, and at Task 1 mutations 7, 8, 9 and 10, which exercise both
sides of it — mutation 9 being the control that a torn tail must NOT be refused. (3) The FIRST
allocation against a never-before-seen stream still rests on a directory entry whose durability
Windows will not force, and it is also the one directory-entry mutation this design admits: it
happens inside that key's first `ReserveStreamIndex`, before any index for the key has been handed
out, which is why Property 1's second number below is written over the steady-state path. That
residual is real, it is not closed by anything in this plan, and it is **S2-16**.

**And the crash-recovery rule, stated as a rule rather than as a procedure.** On open, the store
answers `StreamHighWater` from **persisted state only**, never from a recomputed value and never from
anything a ratchet remembers. `NewSenderRatchet` reads `HighWater` in its **constructor** and walks
`highWater + 1` rungs, so a store that answered a recomputed number would place a live ladder under a
counter nothing has recorded. A crash between `Reserve` returning and the record reaching the wire
leaves a **gap**, and a gap is legal: the server enforces monotonicity, **not contiguity**, precisely
so a refused write or a crash between reserve and send is not a permanent wedge.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `Reserve` returns only after the reservation is on stable storage by a mechanism
  this platform can force.** The test needs an **injected failure point between the write and the
  flush**, not a `time.Sleep`: the observable difference between a durable and a buffered write is
  only visible if the process can be stopped between them.
  *Refusal owed:* a flush error is returned, never swallowed. A `Reserve` that returns `(n, nil)`
  after a failed flush has handed out an index it cannot prove it recorded.
  *Scope to derive, separately from the class (R3):* the class is **every forced flush on the
  allocation path**, and that class is **one** member at this task — the row file's contents —
  because an allocation against a row that already exists is required to mutate no directory entry,
  so there is no second durability boundary for any platform to differ about. The gate reports **two**
  numbers: the number of forced flushes it observed on the path, and the number of directory-entry
  mutations it observed on the path. The scope is the whole allocation path and everything it calls,
  not the row write alone; a gate that reads the `Reserve` body and not what the body calls has read
  half of it. The second number is what makes the property platform-independent, and a gate that
  reports only the first is the gate the earlier draft asked for.
  *And the second number is stated over TWO cases, not one, because a correct implementation cannot
  make it zero in both.* The row for a never-before-seen key does not exist until the store creates
  it, and the store has no key set at open time to pre-create from (S2-16 rejects requiring one), so
  the **first** allocation against a key necessarily creates a directory entry. The gate therefore
  runs the path twice and reports both readings: **first allocation for a key — one create, one
  forced flush; every allocation after it — zero creates, one forced flush.** A property that
  demanded zero creates on both readings is one no correct implementation can satisfy, which is the
  class R5 exists to catch, and it is what the earlier draft's single-number-zero phrasing asked for.

  **Property 2 — `StreamHighWater` is answered from persisted state and never rewinds.** After a
  restart it is at least what it was, for every key, under every interleaving the test can produce.
  *Refusal owed:* `ErrStreamStoreRewound`, matched by `errors.Is`, when the persisted state is behind
  an index already handed out. Task 3 is what makes that findable as
  `messagegroup.ErrStreamIndexRewound`; this task owes the condition and the `sdk` name.

  **Property 3 — no index is ever handed out twice, for the life of the stream and across every
  restart.** Under the allocation shape the caller has nothing to repeat, so the obligation lands on
  the counter.
  *Refusal owed:* `ErrStreamStoreConsumed`, matched by `errors.Is`, for the store's **permanent**
  refusal to allocate — the next position is one it has already handed out and it has no way past it.
  A typed fatal error per §5.9 G7, never a bool and never a log line. The mapping onto
  `messagegroup.ErrStreamIndexConsumed` is Task 3's; this task owes the condition and the `sdk`
  name, and Task 3 Property 3 is what makes `SenderRatchet.Next` able to branch on it.

  **Property 4 — the store is total over its key space.** A stream never seen answers `HighWater` 0
  **with no error**, so the first allocation is 1.
  *Refusal owed:* none, and that is the point — the absence of an error here is what clause 4
  requires, and Task 1 Property 4 is what keeps it from swallowing a real failure.

  **Property 5 — `Reserve` is not idempotent, and under allocation that is structural.** Two calls
  are two indices. There is no call that answers an index a previous call answered.
  *Refusal owed:* none; a test that asks for one has misread the shape.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Return from `Reserve` before the flush. Property 1 must fail. **This is the mutation the whole
     wave exists for**, and a suite that cannot kill it has tested a file format.
  2. Create, rename or remove a directory entry on the allocation path **for a key whose row already
     exists** — write the new high water to a temporary file and rename it over the row, which is what
     the earlier draft of this task prescribed. Property 1 must fail on its **second** reported number
     for the steady-state reading, on every platform. It must **not** be expected to fail on the
     first: on Windows the mutant and the correct implementation both force exactly one flush, and a
     gate that tried to tell them apart by counting flushes would be red at baseline there. **Nor may
     it be expected to fail on the first-allocation reading**, where the correct implementation
     creates one entry too — a mutation applied without the "already exists" bound convicts the
     implementation the plan mandates.
  3. Swallow the flush error and return `nil`. Property 1 must fail.
  4. Answer `StreamHighWater` from an in-memory cache that survives the injected crash. Property 2
     must fail — the cache is exactly the recomputed value the rule forbids.
  5. Resume at `HighWater()` rather than `HighWater() + 1`. Property 2 must fail, and note that this
     mutation is invisible without the restart.
  6. Let a rewound persisted state answer normally. Property 2 must fail with
     `ErrStreamStoreRewound`.
  7. Return a bare filesystem error where the store is permanently unable to allocate. Property 3
     must fail: `errors.Is(err, ErrStreamStoreConsumed)` must find the sentinel.
  8. Return `ErrStreamStoreState` for a stream never seen. Property 4 must fail.
  9. Make `Reserve` answer the same index twice for the same key. Property 3 and Property 5 must
     both fail.
  10. Truncate the row's last record to half a record's width and reopen, **on a row carrying at
     least two records**. Property 2 must fail if the store answers a high water **above** the last
     record whose checksum verifies, and Property 4 must fail if it answers `(0, nil)` for a row that
     still carries a verifying record. A torn tail is discarded; a torn tail read as data is a high
     water nothing recorded. **The two-record bound is load-bearing and was added on 2026-09-09**:
     on a row carrying exactly one record the same cut leaves no verifying record at all, `(0, nil)`
     is then the correct answer — Task 1 Property 4's case 2 — and a mutation applied without the
     bound convicts a correct implementation on its own second clause.
     **And it was the correct half of the 2026-09-09 pair, which is why it is unchanged here.** Task 1
     mutation 7 was the half demanding an answer no implementation could give. This mutation asks for
     case 2's answer for a cut that **is** case 2, it agrees with Task 1 Property 4's decision
     procedure step 4, and Task 1 mutation 11 is now the control that keeps a store from refusing it.

- [ ] **Step 6: Commit**

---

### Task 2a: The single writer, and what a second opener must do

**Files:**
- Modify: `sdk/message_stream_store.go`, `sdk/message_errors.go`
- Create: `sdk/message_stream_exclusion_windows.go`, `sdk/message_stream_exclusion_unix.go`,
  `sdk/message_stream_exclusion_other.go`
- Test: `sdk/message_stream_store_test.go` (extend)

**Interfaces:**
- Consumes: Task 1's `StreamStore` and `OpenStreamStore`, and **Task 1 Property 2's two-level
  directory construction** — the row directory the enumeration reads, and `dir` itself, which is where
  this task's guard entry goes and where it may not be; Task 2's allocation path. Nothing from
  `connect/messagegroup`.
- Produces:
```go
// the exclusion, and the refusal a second opener gets. One declaration per
// GOOS, and the fallback file is a REFUSAL rather than a no-op.
var ErrStreamStoreLocked error // another StreamStore holds this directory

func acquireStreamStoreExclusion(dir string) (io.Closer, error)
```

**THIS TASK EXISTS BECAUSE THE HAZARD THE WHOLE LEG WAS COMMISSIONED TO PREVENT HAD NO PROPERTY.**
An earlier draft of Tasks 1–4 stated **sixteen** properties and **twenty-nine** mutations — 4/8,
5/9, 4/7 and 3/5, counted off that draft rather than taken from the review that found this gap, which
put the mutation total at twenty-two — and not one of them was about a second writer. Measured over
that draft: a grep for `lock`, `mutex`, `concurren`, `single.writer`, `exclusive`, `two processes`,
`second process`, `flock` and `O_EXCL` returned zero hits on any of those terms across its
2,032 lines. Task 2 Property 3's scope was *"the life of the stream
and across every restart"* — restarts, never concurrent openers — and Task 4's crash-restart gate is
sequential by construction.

**What that leaves open, in the words of the spec the leg cites.** Two `StreamStore` instances over
one directory — two processes, or two `OpenStreamStore` calls in one process — each read the same
persisted high water and each allocate **the same next index**. §5.6 says what that is: a reused
`stream_index` is a reused nonce under a reused `record_key`, *"a total break of both AEADs for that
record."* The exposure is not hypothetical under ruling A1: `connect/messagegroup/ratchet.go` puts
every retention class of one sender on **one** `StreamKey`, and `NewSenderRatchet` takes the reserver
per ladder, so several ladders already call `Reserve` on the same stream inside one session. And the
durable write recipe Task 2 gives is a read-modify-write of one row, which is not atomic against a
second writer no matter how many times it is flushed.

**`streamindex.go` names the shape of the answer without naming the mechanism**, and it is quoted
here rather than paraphrased because the sentence is the argument: the session-owns-the-counter shape
was rejected in part because *"the store that owes the persistence cannot implement it atomically: a
read, then a caller's decision, then a write with an fsync in it is a window that an allocation done
in one statement does not have."* An allocation done in one statement is what this task makes true,
and §8.2 says nothing at all about concurrent openers — that silence is **S2-17**.

**Position taken: the exclusion is held by the OPERATING SYSTEM, never by a lock file with contents.**
On Windows, an exclusive `syscall.CreateFile` on a guard entry with `dwShareMode = 0`; on Unix,
`syscall.Flock` with `LOCK_EX|LOCK_NB` on the same entry. Both are in the standard library's
`syscall` package on their own `GOOS`, so this costs **no module dependency** — see *Dependency
policy*. A `GOOS` with neither primitive gets a third file whose body is `ErrStreamStoreLocked`
unconditionally: **a platform this store cannot make safe is a platform it refuses to open on**, and
a build tag that quietly compiled to a no-op is the single-writer property deleted by a build
constraint. *Rejected:* a lock file carrying a pid and a timestamp, because it has no liveness oracle
— it either survives a crash and wedges every later open of that directory, or it is stolen from a
live writer on a heuristic, and the SDK cannot tell those apart.

**WHERE the guard entry sits, because an earlier version of this paragraph put it somewhere that made
Task 1 unsatisfiable.** It sits **in `dir`, beside the row directory and never inside it**. Task 1
Property 2 requires `StreamHighWater` to **enumerate** the directory that holds rows and states, as a
categorical rule with no exception in it, that an entry there which is not a row under any tag is
`ErrStreamStoreState`. A guard entry inside the enumerated directory therefore *is* a finding: the
store reads its own lock as data, every `StreamHighWater` after `OpenStreamStore` refuses, and — since
this task lands **with** Task 2 rather than after it — Wave 1 is red on the commit that completes it.
Both halves of that collision were written in one repair pass on 2026-09-09 and it is removed here by
**construction rather than by exception**: the enumerated object and the excluded object are
different directories, one nested inside the other, so no task has to exempt anything, no reader has
to know the guard's name, and the categorical rule gets stronger rather than weaker. Task 1
Property 2 states the same shape from the row's side and names this task back.

**WHICH `GOOS` gets which file, measured rather than asserted — and the `unix` build term is the
wrong constituency.** Compile-probed 2026-09-09 with the project toolchain (Go 1.26.5,
`CGO_ENABLED=0`), building the three-file split exactly as this task's Files block names it, with the
Unix file carrying `//go:build unix` and the fallback carrying `//go:build !unix && !windows`:

```
OK    windows/amd64  linux/amd64  darwin/arm64  android/arm64  ios/arm64
OK    freebsd/amd64  openbsd/amd64  netbsd/amd64  dragonfly/amd64  illumos/amd64
OK    js/wasm  wasip1/wasm  plan9/amd64          (the fallback file: a refusal, as intended)
FAIL  solaris/amd64  aix/ppc64   x_unix.go: undefined: syscall.Flock
```

`solaris` and `aix` **satisfy the `unix` term** — `go/build`'s `unix` covers aix, android, darwin,
dragonfly, freebsd, hurd, illumos, ios, linux, netbsd, openbsd and solaris — and `syscall.Flock` is
**not declared on either**. So the split as named does not compile there at all: a platform the
fail-closed file was written to *refuse* on becomes a **build break** instead, and the property's own
gate never runs to say so. *Position taken:* the Unix file's constraint is **the `GOOS` set on which
`syscall.Flock` is declared**, spelled as an explicit term list (or `unix && !solaris && !aix`), and
the fallback's is its complement — derived from the primitive, per R4, and not from the `unix` term
which is an instance of it. **The fallback's real constituency is then `js/wasm`, `wasip1/wasm`,
`plan9`, `solaris` and `aix`** — and `js/wasm` is a target **this module already builds for**:
measured 2026-09-09 over `sdk`'s 57 root production files, `device_rpc_platform_js.go` carries
`//go:build js` and `device_rpc_platform_native.go` carries `//go:build !js`. So the priced
consequence, stated rather than discovered, is that **the message store refuses to open on the wasm
artifact, and `NewGroupSession` refuses a nil reserver, so that artifact has no messaging** until
somebody supplies an exclusion for it. Whether it should is **S2-20**.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — at most one `StreamStore` allocates against one directory at a time, and a second
  opener is REFUSED rather than admitted.** The refusal is what a second opener must do with it:
  surface it. A retry loop here is a busy-wait against a live process, and a retry that eventually
  succeeds because the first store closed is a store that started allocating against state it never
  read.
  *Refusal owed:* `ErrStreamStoreLocked`, matched by `errors.Is`, naming the directory and — where
  the platform can tell — whether the holder is this process or another. `OpenStreamStore` refuses;
  it does not open a store that cannot allocate.
  *Scope to derive, separately from the class (R3):* the class is **every path by which a second
  allocator over one directory can come to exist**, and that class is **two** members at this task —
  a second `OpenStreamStore` call inside this process, and a second process opening the same
  directory — with the gate reporting the number of paths it exercised. The scope is **the
  directory**, not the process: a gate that only holds the in-process case is measuring a mutex, and
  a mutex is invisible to the second process, which is the case CP3b's two clients actually create.
  *And a fifth thing the gate must report, because it is what keeps this task from breaking Task 1:*
  **where the guard entry sits.** It is in `dir`, beside the row directory and never inside it, and
  the gate reports the path it acquired the exclusion on together with the path it enumerates, so a
  guard that moved into the enumerated directory is visible as a number a reader can compare rather
  than as a `StreamHighWater` refusing three tasks later. **Task 1 Property 2** states the same
  construction from the row's side.

  **Property 2 — the exclusion is released by the death of the process that held it, and by nothing
  else.** A store whose process died without calling `Close` leaves a directory a later process can
  open; a store whose process is alive leaves one no other process can.
  *Refusal owed:* none for the release. The finding is a **stale-lock heuristic**: any code that
  decides whether the holder is alive by reading a pid, a timestamp or a file's age.

  **Property 3 — `Reserve` is atomic against every other call on this store, across the read, the
  increment AND the flush.** Two goroutines calling `Reserve` on one `StreamStore` for one key get
  two different indices, and no `StreamHighWater` observes the incremented value before the flush
  that made it durable returned.
  *Refusal owed:* none; the failure is a duplicate index or a high water above what is on disk, and
  the gate runs under `-race` as well as under a plain run because only one of the two shows a torn
  guard.

  **Property 4 — a crash between the flush and `Reserve`'s return burns the index and never reuses
  it; a crash before the flush burns nothing.** The next opener's `StreamHighWater` is the flushed
  value in the first case and the previous value in the second, and it never rewinds below either.
  A burned index is a legal gap: the server enforces monotonicity, not contiguity.
  *Refusal owed:* none; this is the crash-mid-allocation answer Task 2's Property 1 makes possible
  and this task states.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Drop the exclusion entirely and open the directory twice, then `Reserve` on both for one key.
     Property 1 must fail on two equal indices. **This is the mutation the task exists for**, and
     no mutation in Tasks 1, 2, 3 or 4 reaches it.
  2. Hold the exclusion with a package-level `sync.Mutex` only. Property 1 must fail on its second
     path — the second process — and a gate that only exercises the first will pass this mutant.
  3. Hold it with a lock file whose contents are a pid and a timestamp, and treat a file older than
     a threshold as stale. Property 2 must fail, and the failure must name which of the two
     directions the mutant chose: a wedge after a crash, or a live holder's lock stolen.
  4. Release the exclusion at the end of `ReserveStreamIndex` rather than at `Close`. Property 1
     must fail.
  5. Compile the fallback `GOOS` file as a no-op that returns a `nil` closer and a `nil` error.
     Property 1 must fail on that build — the fail-closed file is a property, not a placeholder.
  6. Take the guard across the read and the increment but release it before the flush. Property 3
     must fail.
  7. Let `StreamHighWater` read the in-memory counter rather than the flushed row while a `Reserve`
     is in flight. Property 3 must fail, and Task 2 Property 2 must fail with it.
  8. Crash after the flush and before `Reserve` returns, then reopen. Property 4 must fail if the
     reopened store answers a high water **below** the flushed index.
  9. Crash before the flush, then reopen. Property 4 must fail if the reopened store answers a high
     water **at or above** the unflushed index, and it must fail if the reopen **errors** — the
     unflushed record is a torn tail and Task 1 Property 4 case 2 requires it discarded, not refused.
  10. Acquire the exclusion on a guard entry **inside the row directory** — the directory Task 1
     Property 2's enumeration reads — rather than beside it in `dir`. **Task 1 Property 2 must fail
     with `ErrStreamStoreState` on the first `StreamHighWater` after a successful `OpenStreamStore`**,
     and this task's Property 1 must not: the exclusion still holds, and that is the point. **This is
     the mutation that reproduces the collision the 2026-09-09 repair introduced** — a guard file
     inside `dir` against a categorical rule that every entry there is a row — and until it was
     written nothing in Tasks 1, 2, 2a, 3, 4 or 12 exercised it, which is why two properties written
     in one pass could be mutually unsatisfiable and every gate stay green.
  11. Constrain the Unix file with the `unix` build term rather than with the measured `GOOS` set on
     which `syscall.Flock` is declared. The **build** must fail on `solaris` and `aix` with
     `undefined: syscall.Flock`, and the Definition of done's cross-compile row is what makes it
     visible: a platform the fail-closed file was written to refuse on becomes a compile error
     instead, and Property 1's gate never runs there to say so.

- [ ] **Step 6: Commit**

---

### Task 3: The `StreamKey` flattening, and the sentinel mapping `SenderRatchet.Next` branches on

**Files:**
- Create: `sdk/message_stream_adapter.go`
- Test: `sdk/message_stream_adapter_test.go`

**Interfaces:**
- Consumes: Task 2's `StreamStore.ReserveStreamIndex` and `StreamStore.StreamHighWater`;
  `messagegroup.StreamIndexReserver`, `messagegroup.StreamKey`,
  `messagegroup.ErrStreamIndexConsumed`, `messagegroup.ErrStreamIndexRewound`.
- Produces:
```go
// the ONE place in sdk where a StreamKey becomes two []byte parameters, and the
// one place where a store failure becomes a messagegroup sentinel.
func NewStreamIndexReserver(store *StreamStore) messagegroup.StreamIndexReserver
```

**Why an adapter is mandatory, and why this is a fact rather than an open question.** The m1 plan
says §8.2's `MessageStore` is `messagegroup.StreamIndexReserver` *"method for method and now
parameter for parameter too"*. Spec A §8.2 itself says otherwise, in the paragraph the A1 amendment
added: *"`messagegroup.StreamIndexReserver` is this pair method for method, and the flattening from
these two `[]byte` parameters to its comparable `StreamKey` is the implementer's."* Read against the
source, the spec is right and the plan sentence is stale in two ways at once:

- **the method NAMES differ** — `ReserveStreamIndex` / `StreamHighWater` against `Reserve` /
  `HighWater`; and
- **the parameter shapes differ** — `(groupId, senderHandle []byte)` against `(stream StreamKey)`.

A `*StreamStore` therefore cannot be handed to `NewGroupSession` and a task dispatched on the plan's
wording would not compile. **What is method for method is the DIRECTION and the KEY**: two methods,
one allocating and returning a `uint64`, one querying, both class-blind. That correspondence is real
and it is what A1 bought.

**And the flattening silently drops two properties `streamindex.go` calls deliberate.** `StreamKey`
is comparable *"deliberately twice over: a stream key can be a map key without a second encoding, and
a group id that moved under a ratchet cannot reserve indices against one row and use them against
another."* §8.2's `[]byte` pair is neither comparable nor immutable — a caller may mutate the backing
array after the call returns. **The adapter copies at the boundary**, and no document asks it to.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every flattening in `sdk` is inside the adapter type.** Anything else that converts
  between a `StreamKey` and a `(groupId, senderHandle)` pair is a second implementation of one
  mapping, which is the §12.1 A-1 shape.
  *Refusal owed:* none — this is a gate, and its finding is a call site outside the adapter.
  *Scope to derive, separately from the class (R3):* the class is **every production declaration in
  `sdk` whose body reads both `StreamKey.GroupId` and `StreamKey.SenderHandle`**, read off the syntax
  tree rather than off a file name; the scope is **the whole of `package sdk`'s production files**,
  not the two files this task creates. That class is **one** member at this task if the flattening is
  written once as a helper and **two** if it is written into each of `Reserve` and `HighWater`, and
  **both are correct implementations** — so the count is not the finding. The gate reports the
  number it read and fails on a member whose enclosing declaration is not a method of the adapter
  type, which is the question the property actually asks. A gate that pinned the count to one would
  convict the inlined implementation, which is the defect class R4 exists to catch: it would derive
  from an instance of the design rather than from the property.

  **Property 2 — the adapter copies the key at the boundary, in both directions.** A caller that
  mutates the slice it passed, or that keeps the slice the adapter passed on, must not be able to
  move a row.
  *Refusal owed:* none; the failure is observable as a reservation landing on the wrong row.

  **Property 3 — a permanent refusal is findable by `errors.Is` as
  `messagegroup.ErrStreamIndexConsumed`, and a rewind as `messagegroup.ErrStreamIndexRewound`.** This
  is not tidiness. `SenderRatchet.Next` branches on `errors.Is(err, ErrStreamIndexConsumed)` to decide
  between a **permanent wedge** and a **retryable failure**. A store that returns its own error there
  is classified retryable, so the caller retries forever and **each retry pays a durable write**. A
  §8.2-conformant store that skips this mapping is a defective `StreamIndexReserver`, and §8.2
  declares neither sentinel.
  *Refusal owed:* both sentinels, wrapped so the store's own message survives underneath.

  **Property 4 — a wrong-width `StreamKey` cannot exist, and a wrong-width `[]byte` cannot pass.**
  The `StreamKey` direction is total by construction, which is what the array types buy; the `[]byte`
  direction is Task 1 Property 3's refusal, re-checked here so the adapter is safe when it is the
  entry point rather than the exit.
  *Refusal owed:* `ErrStreamKeyWidth`.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add a second flattening in another `sdk` file. Property 1 must fail and must name the new call
     site.
  2. Move the flattening into the transport and leave the adapter calling it. Property 1 must still
     fail — the gate's subject is the count of flattenings, not the file the adapter lives in.
  3. Pass the caller's slice through without copying, then mutate it after the call. Property 2 must
     fail.
  4. Return the store's own error unwrapped on a permanent refusal. Property 3 must fail on
     `errors.Is`.
  5. Map a **retryable** failure onto `ErrStreamIndexConsumed`. Property 3 must fail — the mapping
     must be exact in both directions, and a mapping that only over-reports wedges a healthy ladder
     permanently.
  6. Map a rewind onto `ErrStreamIndexConsumed`. Property 3 must fail; the two sentinels name
     different conditions and ledger item 171 turns on the difference.
  7. Accept a 16-octet `groupId` at the adapter and let Task 1's check catch it later. Property 4
     must fail at the adapter.

- [ ] **Step 6: Commit**

---

### Task 4: The crash-restart gate — `TestStreamIndexNeverReused` over the production store

**Files:**
- Test: `sdk/message_stream_store_test.go` (extend)

**Interfaces:**
- Consumes: Tasks 1, 2, 2a and 3's whole surface.
- Produces: no declaration. This task produces the one **named** test on this leg. §5.9 G5 and G11
  name it, which is why it is spelled here at all — R1 forbids naming a test, and a test the spec
  names by name is the stated exception rather than a lapse.

**§5.6 states its shape and this task does not invent one:** *"runs 10,000 seal operations with an
injected crash after `Reserve` and before the AEAD, restarts the session from the persisted state,
and asserts no `index` is ever produced twice."*

**What this task discharges of that sentence, and what it does not — because the two halves are in
different waves and an earlier draft claimed both.** §5.6's shape has three subjects: a SEAL, a
SESSION and a STORE. This task's Files list is one test file, its Consumes list is Tasks 1, 2, 2a
and 3, and Wave 1's own header says the wave needs *"no `GroupHandle`"* — so the seal and the session
are not reachable here, and a task that said it ran 10,000 *seal* operations and restarted a
*session* would be describing work no wave-1 task can do. What lands here is the **store half**: ten
thousand allocations with an injected crash after `Reserve` and before the value is used, and a
reopen of the persisted directory. That is the half that can fail, because a non-durable `Reserve` is
distinguishable from a durable one only in that window.

**The session half lands at Task 8a**, which is the one place a `GroupSession` is constructed and
therefore the first place a seal exists to crash inside. §5.9 **G11**'s own extension — *"an
injected commit loss between reserve and re-seal"* — needs a commit and so needs a session; it is
Task 8a Property 5's and is named there rather than left cited and unstepped. **The name
`TestStreamIndexNeverReused` stays on this task** because §5.9 G5 names it and R1's exception is for
a test the spec names; Task 8a's half extends the same name rather than starting a second one, and
the Definition of done's row runs both.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — ten thousand allocations with an injected crash after `Reserve` and before the AEAD
  produce no index twice.** The crash point is **after the store returned and before the caller used
  the value**, which is the only window in which a non-durable `Reserve` is distinguishable from a
  durable one.
  *Refusal owed:* none; a duplicate is a test failure and the failure message must print the index
  and both allocation ordinals, because a run that says only *"duplicate found"* costs an afternoon.

  **Property 2 — the gate's subject is the PRODUCTION store, not a fake.** m1 Task 6 already holds
  its file-backed fake to the same property; a `sdk` gate that ran over another fake would prove the
  contract twice and the implementation never.
  *Refusal owed:* none.
  *Scope to derive, separately from the class (R3):* the class is **every
  `messagegroup.StreamIndexReserver` implementation declared in `package sdk`'s production files**,
  read off the syntax tree; that class is **one** member at this task — `streamReserver`, the type
  Task 3 produces — and the gate reports the number it read. The scope is the package's production
  files, not the test file, and the store must be obtained the way the production caller obtains it:
  through `OpenStreamStore` and `NewStreamIndexReserver`, never as a struct literal assembled in the
  test. A gate that constructs the store differently from the production caller is testing a
  configuration nothing ships. **This class is deliberately NOT stated as "every reserver a
  `GroupSession` in `package sdk` can be constructed with"**, which is what an earlier draft said:
  Wave 1 constructs no `GroupSession` at all, so that class has no member here and the gate would be
  the empty gate this plan's own Definition of done calls broken. The `GroupSession` half — that the
  one production construction is handed this reserver and no other — is Task 8a Property 1's.

  **Property 3 — the restart is a real restart of the store, not a reset of a variable.** The
  persisted directory is reopened; nothing in memory crosses the boundary.
  *Refusal owed:* none.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**

  There is nothing to implement. If this task requires an implementation change, Task 2 was
  incomplete and the change belongs there with its own mutation run.

- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Return from `Reserve` before the flush. Property 1 must fail. This is Task 2's mutation 1 seen
     from the milestone, and it must be killed here too.
  2. Carry the in-memory high water across the simulated restart. Properties 1 and 3 must fail.
  3. Reduce the run to 100 allocations. Property 1 must still fail under mutation 1 — if it does
     not, the run length was doing the work the crash injection was supposed to do, and the gate is
     a stress test wearing a property's name.
  4. Reopen the store without re-reading the rows. Property 3 must fail.
  5. Run the gate against a hand-built fake instead of the production store. Property 2 must fail.

- [ ] **Step 6: Commit**

---

## Wave 2 — leg 4a, the transport binding (Tasks 5–7)

**This wave needs no key, no group and no session.** It can be built and tested against the message
server with opaque bytes, which is precisely what CP3c already proved end to end over two real
`connect.Client`s. It has no dependency on Wave 1 and may be built in parallel with it.

### Task 5: The message-server binding — frames, correlation, and the borrow rule

**Files:**
- Create: `sdk/message_transport.go`
- Modify: `sdk/go.mod` — `google.golang.org/protobuf` moves from the indirect require block to the
  direct one, because `Call` takes a `proto.Message`. No fetch; see *Dependency policy*.
- Test: `sdk/message_transport_test.go`

**Interfaces:**
- Consumes: `connect.Client.Send`, `connect.Client.SendWithTimeout`,
  `connect.Client.AddReceiveCallback`, `connect.DestinationId`, `connect.TransferPath`,
  `connect.Id`; `protocol.MessageServerRequest`, `protocol.MessageServerResponse`, and the four
  `MessageType` code points. Nothing from any plan's task.
- Produces:
```go
type messageTransport struct{ /* unexported */ }
type messageTransportConfig struct{ /* Client, Server, ProtocolVersion, PartBytes, Timeout */ }

// the counters Properties 2 and 3 make readable. Declared HERE, with the
// transport that owns them: an earlier draft named this type in a return
// signature and declared it in no task.
type messageTransportCounts struct{ /* unexported */ }

func newMessageTransport(config *messageTransportConfig) (*messageTransport, error)
func (self *messageTransport) Close()
func (self *messageTransport) Call(ctx context.Context, body proto.Message) (*protocol.MessageServerResponse, error)
func (self *messageTransport) Counts() messageTransportCounts
```

**The one rule in `connect` that is normative for this file**, quoted rather than paraphrased,
because paraphrasing it is how it gets broken: *"The frames, frame objects, and their message bytes
are borrowed and valid only until the callback returns. Decode, copy, or `MessagePoolShareReadOnly`
any data that must outlive the callback; never hand a borrowed Frame to an asynchronous send,
goroutine, or channel."* And: *"`ReceiveFunction` is invoked inline by the receive path. A blocked
callback intentionally backpressures that path."* Both halves bind this task: the first says what may
cross the callback boundary, and the second says the callback may not block on a waiter.

**There is no server push, and the receive path is a poll.** Verified against `msgrepo/peer`: the
dispatch table serves exactly four arms — Hello, `CreateGroup`, `Submit`, `Fetch`.
`Subscribe`, `Unsubscribe`, `GroupStatus`, `BlobGrant`, `RecoveryFetch`, `WrapFetch` and the
rendezvous arms exist in the proto and have **no server handler**;
`MessageMessageServerPush` is a code point nothing emits. A binding that assumes a subscription is
wrong today, and Task 11's fetch loop is the only receive path there is.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — nothing borrowed outlives the receive callback.** Every byte the binding keeps is
  copied inside the callback, and no `*protocol.Frame` reaches a goroutine, a channel or a map.
  *Refusal owed:* none; the failure is corruption under load, which is why this is a gate over the
  code and not only a behaviour test.
  *Scope to derive, separately from the class (R3):* the class is **every value that reaches the
  binding through the receive callback's parameters**, read off `ReceiveFunction`'s own signature
  rather than listed; that class is **three** members at this task — the `TransferPath`, the
  `[]*protocol.Frame` slice with every frame and byte inside it, and the `Peer` — and the gate must
  report the number it read, so a parameter added to `ReceiveFunction` upstream fails here. The scope
  is the callback's whole dynamic extent, not the callback body's lexical block. A gate that checks
  the body and not what the body calls has read half of it.

  **Property 2 — a response is delivered to the waiter that asked for it, or to nobody.** Correlation
  is by `request_id`; an unmatched response is **counted and dropped**, never delivered to the wrong
  waiter and never silently discarded.
  *Refusal owed:* a counter that a test can read, so *"nothing arrived"* and *"something arrived for
  nobody"* are distinguishable.

  **Property 3 — a response arriving after its waiter timed out leaks nothing.** No goroutine, no map
  entry, no channel.
  *Refusal owed:* the late response increments the unmatched counter; the timed-out `Call` returns a
  typed timeout, never a nil response with a nil error.

  **Property 4 — the callback never blocks on a waiter.** Delivery is non-blocking; a waiter that has
  gone away costs the receive path nothing.
  *Refusal owed:* none; the failure mode is a stalled transport, which the property is written to
  make observable rather than to describe.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Store the received `*protocol.Frame` in the correlation map and read its bytes after the
     callback returns. Property 1 must fail.
  2. Keep the frame's byte slice without copying. Property 1 must fail. A test that only exercises
     one in-flight request will not see this; the mutation is the reason the gate is over the code.
  3. Hand the borrowed slice to a goroutine that copies it *promptly*. Property 1 must still fail —
     promptness is not the rule, and a gate that passes here has measured a race it happened to win.
  4. Deliver a response whose `request_id` matches nothing to the oldest waiter. Property 2 must
     fail.
  5. Drop an unmatched response without counting it. Property 2 must fail.
  6. Leave the map entry behind on timeout. Property 3 must fail.
  7. Send on an unbuffered channel with no default. Property 4 must fail.
  8. Return `(nil, nil)` on timeout. Property 3 must fail.

- [ ] **Step 6: Commit**

---

### Task 6: §4.6 fragmentation, both directions, and the one home for the part size

**Files:**
- Create: `sdk/message_transport_fragment.go`
- Test: `sdk/message_transport_fragment_test.go`

**Interfaces:**
- Consumes: Task 5's `messageTransport`; `protocol.MessageServerFragment` and the
  `MessageMessageServerFragment` code point.
- Produces:
```go
// the cut and the reassembly. The part size is a wire bound and it gets ONE
// declaration in sdk; see S2-9 for why it is not shared with the server's.
const messageFragmentPartBytes = 2048

func (self *messageTransport) fragments(request *protocol.MessageServerRequest) ([]*protocol.Frame, error)
```

**Where the number comes from, and why `sdk` gets its own copy.** `MaxFragmentPartBytes = 2048` and
`DefaultFragmentPartBytes` live in `msgrepo/peer/frame.go` — the **server** module, which `sdk`
cannot import. `connect` holds **no fragmenter at all**, and the query is published beside the claim:
`grep -rn MessageServerFragment --include=*.go connect/`, with generated files excluded, returns
exactly one hit at `33932e0` — a name-to-number mapping entry in `protocol/message_wire_test.go` —
and no cut, no reassembler and no part-size constant. So `sdk` writes the third fragmenter in the
workspace and the second copy of the bound. **That is a real cost and it is filed as S2-9, not absorbed.** The
constant's doc comment must name §4.6, name `msgrepo/peer/frame.go` as the other copy, and say that
the two are held together by nothing but this comment until one of them moves into `connect`.

**Off the CP3b prefix, and deliberately built anyway.** One durable text message at size bucket 0–2
is far under 2048 octets, so the fragmenter is never entered on the CP3b path. It is here because
`CreateGroupRequest` carries a whole record and an `EpochAttachment` and is the first request that
plausibly crosses the bound, and because a reassembler written later is a reassembler written under
deadline.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — a request cut into parts reassembles to the same bytes.** For every request size
  from below one part to several parts, including the exact multiples of the part size, where an
  off-by-one produces an empty final part.
  *Refusal owed:* none for the round trip; a reassembly that cannot complete returns a typed error.

  **Property 2 — an out-of-order, duplicated, or short-counted fragment ABORTS the reassembly.** It
  does not buffer, it does not wait, and it does not produce a partial message.
  *Refusal owed:* a typed abort, counted, so the transport's own counters distinguish an abort from a
  timeout.

  **Property 3 — the part size has exactly one declaration in `sdk`.**
  *Refusal owed:* none; the finding is a second literal.
  *Scope to derive, separately from the class (R3):* the class is **every constant EXPRESSION in
  `package sdk`'s production files whose evaluated value equals the part size**, read off the
  type-checked syntax tree — `go/types`' `Info.Types[expr].Value` — and never off the literal text;
  the scope is the whole package, not this file. That class is **one** member at this task, and the
  gate reports the number it read. Two things turn on the word *expression*: a gate scoped to this
  file passes on the day somebody writes the number into the send path, which is the divergence the
  property exists to prevent; and a gate that scans **literals** cannot see `1 << 11`, which contains
  no literal equal to 2048, so mutation 8 below would survive a gate written to the earlier draft's
  own words.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Cut at `partBytes + 1`. Property 1 must fail.
  2. Emit a final empty part for an exact multiple. Property 1 must fail.
  3. Reassemble by appending in arrival order rather than by index. Property 2 must fail.
  4. Accept a duplicate index and overwrite. Property 2 must fail.
  5. Accept a fragment whose `count` disagrees with the first fragment's. Property 2 must fail.
  6. Deliver a partial reassembly when a fragment never arrives. Property 2 must fail.
  7. Write `2048` a second time in the send path. Property 3 must fail.
  8. Write the part size as a shift rather than a decimal product. Property 3 must still fail on the
     count — the class is the value, not the spelling.

- [ ] **Step 6: Commit**

---

### Task 7: Hello, the per-connection `server_nonce`, and the `Capabilities` cache

**Files:**
- Create: `sdk/message_transport_hello.go`
- Test: `sdk/message_transport_hello_test.go`

**Interfaces:**
- Consumes: Task 5's `messageTransport.Call`; `protocol.HelloRequest`, `protocol.HelloResponse`,
  `protocol.Capabilities`.
- Produces:
```go
func (self *messageTransport) Hello(ctx context.Context, versions ...uint32) (protocol.Reason, *protocol.HelloResponse, error)
func (self *messageTransport) Nonce() []byte              // the CURRENT connection's, copied
func (self *messageTransport) Capabilities() *protocol.Capabilities
func (self *messageTransport) NonceEpoch() uint64         // increments on every Hello
```

**`server_nonce` is a property of the CONNECTION and this is where the leg's second blocker becomes
concrete.** The server draws a fresh 32-octet nonce per connection and replaces it unconditionally at
every Hello. `NewGroupSession` copies the nonce **once**, at construction, and `GroupSession` has no
setter — verified by grepping every production reference. So after any reconnect, every record the
session seals carries a `write_auth` over a nonce the server no longer holds, and every submit is
refused. CP3c already proves the server does exactly that.

**What this plan does about it, stated as a position with its cost.** *Position taken:* the transport
exposes `NonceEpoch()`, and the send path (Task 10) **refuses to submit a record sealed under a
superseded nonce** rather than submitting it and reading the refusal off the wire. The session
rebuild that would actually recover is **not** in this plan, because its cost has never been priced:
rebuilding drops every sender and receiver ratchet, re-walks each ladder from the store's high water,
and is **refused outright** above `maxLadderWalk` — and `NewSenderRatchet` refuses that resume for
**every class of that sender**, because the counter they share is what crossed the bound. *Rejected:*
tearing down and rebuilding the `GroupSession` inside `s2` on every reconnect, because it silently
imports that cost into a plan that cannot pay it and because it needs `pq_secret` and
`groupHandleKeyEpoch0` back in hand. **S2-2**, and it needs a `connect` change nobody owns.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — no request that requires an authenticator precedes Hello on that connection.** The
  `server_nonce` comes only from `HelloResponse`, and both `write_auth` and `req_auth` are MACs over
  it.
  *Refusal owed:* a typed refusal naming Hello, raised locally, never a request put on the wire to be
  refused there.

  **Property 2 — the nonce a caller reads is the CURRENT connection's, and a nonce from a superseded
  connection is never handed out.** `NonceEpoch()` increments on every Hello, and a caller that read
  a nonce at epoch *n* can tell that it is stale at epoch *n+1*.
  *Refusal owed:* `Nonce()` returns a **copy**; a caller that mutates what it got cannot move the
  transport's own state.

  **Property 3 — `Capabilities` is read before the first submit of a session and bounds every later
  request.** A request exceeding an advertised bound is refused locally.
  *Refusal owed:* a typed refusal naming the capability and both numbers. §4.3.1 makes this the
  server's whole advertised contract, and a client that discovers a bound by being refused has spent
  a round trip to read a field it already had.

  **Property 4 — the first request of a connection uses a compiled-in part budget, because Hello
  itself has no advertised one.** This is the ordering hole in §4.3.1 that a plan can either state or
  discover: Hello must be sent before `Capabilities` exists.
  *Refusal owed:* none; the compiled-in value is Task 6's constant and must be the same one.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Submit before Hello. Property 1 must fail locally, not on the wire.
  2. Cache the nonce across a reconnect. Property 2 must fail.
  3. Return the internal nonce slice rather than a copy, then mutate it. Property 2 must fail.
  4. Leave `NonceEpoch()` unchanged across a Hello. Property 2 must fail — and note that this
     mutation is the one that makes Task 10's refusal unreachable, which is why it is here and not
     only there.
  5. Skip the `Capabilities` read and submit anyway. Property 3 must fail.
  6. Enforce a stale `Capabilities` after a second Hello that advertised a **smaller** bound.
     Property 3 must fail. An earlier draft wrote this mutation as *"enforce a stale `Capabilities`
     after a `CapabilityChange`"*, which cannot be applied: measured 2026-09-09,
     `grep -rn 'CapabilityChange' --include=*.go` over `msgrepo` returns **nothing** and so does
     `grep -rn 'MessageMessageServerPush'` — no emitter, no handler — and Task 5 above establishes
     that the push code point is dead. A re-Hello is the only path on which the advertised bounds
     actually move, and it is a path a real `connect.Client` takes on every reconnect.
  7. Use a part budget for Hello that differs from Task 6's constant. Property 4 must fail, and
     Task 6 Property 3 must fail with it.

- [ ] **Step 6: Commit**

---

## Wave 3 — the seam and the send path (Tasks 8, 8a, 9, 10)

**This wave is where the upstream blockers bite.** Tasks 9 and 10 cannot be completed against a real
server without a reachable `write_key[0]` and the epoch keys (**S2-1**). They are written so that the
half that does not need them — the projection, the ordering, the result disposition — lands and is
gated now, and the key access is a single injected parameter rather than a re-derivation scattered
through the path.

**And Task 8a is in this wave rather than beside it, even though it lands after Wave 4.** It is the
seam: the one place `package sdk` constructs a `GroupSession`, the one call site of `SealRecord`, and
the declaration of the `messageSender` and `messageReceiver` that Tasks 9, 10 and 11 write methods
on. Its position in the **landing order** is not its position in this wave, and the Execution order
table states both.

### Task 8: The §4.3.3 projection, derived from the descriptor rather than from a field list

**Files:**
- Create: `sdk/message_projection.go`
- Test: `sdk/message_projection_test.go`

**Interfaces:**
- Consumes: `message.Record`, `message.RecordHeader`, `message.ServerAttachment`,
  `message.EncodeRecord`, `message.RetentionClassWire`; `protocol.Record`. Nothing from any plan's
  task.
- Produces:
```go
func recordProjection(record *message.Record, attachment *message.ServerAttachment) (*protocol.Record, error)
```

**What the server does with this, read from `msgrepo/api/submit.go` rather than from §4.3.3.** The
server re-projects `ParseRecord(record_bytes)` itself and compares the **whole message** with
`proto.Equal`, having cleared `record_bytes` and zeroed `record_id` on the client's copy. Its own
comment says why it compares messages rather than fields: *"A field list here would be a list to
forget a field from: a twelfth projection added to `Record` tomorrow would be a field the client
populates, the server indexes and nothing checks."* **That argument binds this task identically**,
and it is R4 in one sentence: derive from the descriptor, not from the eleven names.

**Two traps, both of which produce `REASON_REJECTED` with no diagnostic.**

- **`retention_class` carries the WIRE byte, not the enum value — and the divergence is narrower
  and nastier than it sounds.** The server projects
  `uint32(RetentionClassWire(header.RetentionClass, header.EphBucket))`. Measured in
  `connect/message/record.go` on 2026-09-09: the tags are `RetentionPermanent = 0`,
  `RetentionDurable = 1`, `RetentionMedia = 2`, `RetentionEph = 3`, and the wire bytes are
  `0x00`, `0x01`, `0x02` and `0x10 | bucket`. So `uint32(header.RetentionClass)` agrees with the
  wire byte for **all three** non-EPH classes — `nonEphWireBytes` maps each to its own numeric value
  and the file's own comment says *"the tag values and the wire values happen to agree for these
  three today, and a conversion would silently make that coincidence the encoding"* — and diverges
  **only** for EPH. An earlier draft of this task said it agreed for `DURABLE` *"by coincidence"* and
  diverged *"for every other class"*, which points a mutation set at `PERMANENT` and `MEDIA`, the two
  classes M1-6 lifted, where the mutant is indistinguishable from the correct implementation. **The
  only killing case is an EPH record**, and `SealRecord` refuses that class, so the gate must call
  the projection with a hand-built `message.RecordHeader` rather than with a sealed record.
  `RetentionClassWire` is the one place the class and the bucket join, and a second copy of that
  join is the §12.1 A-1 divergence.
- **`record_id` is server-assigned and must be left unset.** The server zeroes it before comparing,
  so populating it is not refused — it is *ignored*, which means a client that populates it wrongly
  learns nothing until something else reads it.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every server-indexed field the message descriptor declares is populated, and the
  gate's class is the descriptor's.** A field added to `protocol.Record` tomorrow must fail this gate
  until the projection is taught about it.
  *Refusal owed:* an error naming the field, not a silent zero.
  *Scope to derive, separately from the class (R3):* the class is **the field set of
  `protocol.Record` minus `record_bytes` and `record_id`**, read off the compiled descriptor at test
  time. Today that class is **eleven** members and the gate must report the number it read; a gate
  that spells the eleven names is the ledger-21 defect and passes on the day a twelfth arrives. The
  **scope** is a different question and is answered separately: it is every field of the descriptor,
  including ones this plan believes are always empty, because *"always empty"* is a claim about the
  CP3b path and not about the message.

  **Property 2 — `retention_class` is the wire byte produced by `message.RetentionClassWire`, and
  `sdk` contains no second computation of it.**
  *Refusal owed:* the error `RetentionClassWire` itself returns, propagated, never swallowed into a
  zero.

  **Property 3 — the projection round-trips against an independent parse.** For a record built by
  `SealRecord`, projecting the `*message.Record` and projecting `ParseRecord(EncodeRecord(r))` agree
  field for field. This is the client-side half of the check the server performs, and it is what
  turns a `REASON_REJECTED` with no diagnostic into a local failure with one.
  *Refusal owed:* none; the failure names the field that differs.

  **Property 4 — `record_id` is never populated and `record_bytes` is always the output of
  `EncodeRecord`.**
  *Refusal owed:* none.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add a field to a local copy of the descriptor and leave the projection unchanged. Property 1
     must fail on the count.
  2. Spell the eleven field names in the gate. Property 1 must fail when the descriptor and the
     spelled list disagree.
  3. Drop `blob_id` from the projection. Property 1 must fail — and note it is empty on the CP3b
     path, which is why the scope is the descriptor and not the path.
  4. Drop `wrap_target_handle`. Property 1 must fail, for the same reason and on the record class
     Task 9 actually sends.
  5. Write `uint32(header.RetentionClass)` into `retention_class`. Property 2 must fail — and it can
     fail **only** on an EPH record, because the tag and the wire byte are numerically identical for
     `PERMANENT` (0/`0x00`), `DURABLE` (1/`0x01`) and `MEDIA` (2/`0x02`). A suite that exercises any
     or all of those three will not see it. `SealRecord` refuses every class but `DURABLE`, so the
     gate reaches EPH through a hand-built header rather than through a seal.
  6. Re-implement the class-and-bucket join locally. Property 2 must fail on the second
     implementation, not on the answer.
  7. Populate `record_id` with the record's own field. Property 4 must fail.
  8. Project from the header before `SealRecord` set `stream_index`. Property 3 must fail.

- [ ] **Step 6: Commit**

---

### Task 8a: The seam — the session, the two halves, and the record that carries its own nonce epoch

**Files:**
- Create: `sdk/message_client.go`
- Test: `sdk/message_client_test.go`

**Interfaces:**
- Consumes: Task 2a's `StreamStore` under its exclusion, Task 3's `NewStreamIndexReserver`,
  Task 5's `messageTransport`, Task 7's `Nonce` and `NonceEpoch`, Task 12's `OpenReceiveState`;
  `messagegroup.NewGroupSession`, `messagegroup.GroupSession.SealRecord`,
  `messagegroup.GroupHandleKey`, `messagegroup.StorageRoot`; `message.Record`. Consumes an
  **injected** `GroupHandle` — never a constructed one (Gate 5).
- Produces:
```go
// the seam. Package-internal on purpose: the surfacing onto s1's MessageClient
// is s1's declaration and not this plan's (S2-19).
type messageClientConfig struct {
    Transport       *messageTransport
    Handle          messagegroup.GroupHandle // injected; Gate 5 forbids constructing one
    PqSecretZero    []byte                   // injected; S2-3
    StorageRootZero []byte                   // injected; S2-1
    Streams         *StreamStore
    Receive         *ReceiveState
    NowMs           func() int64
    GroupId         [32]byte
}

type messageClient struct{ /* unexported */ }
type messageSender struct{ /* unexported */ }
type messageReceiver struct{ /* unexported */ }

func newMessageClient(config *messageClientConfig) (*messageClient, error)
func (self *messageClient) Sender() *messageSender
func (self *messageClient) Receiver() *messageReceiver
func (self *messageClient) Close() error

// a sealed record and the nonce epoch it was sealed under, together, because
// Task 10 Property 4 cannot be decided from a *message.Record alone.
type sealedRecord struct {
    Record     *message.Record
    Attachment *message.ServerAttachment
    NonceEpoch uint64
}

func (self *messageSender) Seal(class message.RetentionClass, ephBucket uint8, isCommit bool,
    headPlain []byte, bodyPlain []byte, expireAt uint64,
    attachment *message.ServerAttachment) (*sealedRecord, error)
```

**THIS TASK EXISTS BECAUSE THE PLAN'S PARTS EACH COMPILED AND NEVER MET.** An earlier draft wrote
`messageSender` and `messageReceiver` as method receivers in three `Produces` blocks — Tasks 9, 10
and 11 — and **declared neither type in any task**, listed neither in File Structure, and named
neither in any `Consumes` entry. It called `NewGroupSession` nowhere, so leg 4's defining sentence
— *"a send path that calls `SealRecord` and submits the `*message.Record` it returns"* — was
produced by nothing, Wave 1's reserver was never wired to Wave 3, and two derived-class gates
(Task 4 Property 2 and Task 9 Property 2) each declared a class of one member over a construction
the plan never made, which is a class of **zero** and which this plan's own Definition of done calls
a broken gate rather than a clean one. A plan whose parts each compile and never meet is a plan that
discovers its own gap at the last task.

**Where it sits and why.** First in Wave 3 after the projection, because Task 9's ceremony and
Task 10's send are both methods on `messageSender` and Task 11's fetch is a method on
`messageReceiver`; all three need the type declared before they can be dispatched. It needs Waves 1
and 2 whole — it is the first task that does — and Task 12's `OpenReceiveState`, which is why the
Execution order table now sequences Wave 4 before this task rather than after it.

**And this is where the one-way door of `NewGroupSession` is closed once rather than at every caller.**
The constructor says a session opened at MLS epoch 0 *"may leave `groupHandleKeyEpoch0` nil, because
the current root IS the epoch zero root and the constructor expands it"*, and there is no accessor
that hands the value back — the seven exported methods again. This task passes it, never nil, and
Task 9 Property 2's gate is over this call site.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `package sdk` constructs a `GroupSession` in exactly one place, and that place is
  handed the reserver Task 3 produces and a non-nil `groupHandleKeyEpoch0`.**
  *Refusal owed:* `newMessageClient` refuses — typed, naming which of the two it lacked — rather than
  constructing a session with a nil reserver (which `NewGroupSession` refuses anyway) or a nil epoch
  zero handle key (which it accepts, and which bricks the group at the next restart).
  *Scope to derive, separately from the class (R3):* the class is **every `NewGroupSession` call
  expression in `package sdk`'s production files**, read off the syntax tree; the scope is the whole
  package, not this file, because the second call site is the one that will take the convenience.
  That class is **one** member at this task, and **this task is what makes it one rather than none**:
  before this task, nothing in `package sdk` constructs a session at all, so every gate written over
  that construction reads nothing and reports clean. Task 4 Property 2 and Task 9 Property 2 derive
  over the same construction from two other angles and both name this property.

  **Property 2 — the seam is the only caller of `SealRecord` in `package sdk`.** Every record the
  send path submits and every record the ceremony sends came out of one call site, and no
  `message.Record` is assembled by hand anywhere in the package.
  *Refusal owed:* none for the count; the finding is a second call site or a `message.Record`
  composite literal in production code.
  *Scope to derive, separately from the class (R3):* the class is **every call to
  `(*messagegroup.GroupSession).SealRecord` in `package sdk`'s production files**, resolved through
  the type checker rather than matched on the method name, so a wrapper that renames it is still a
  member; the scope is the whole package's production files. That class is **one** member at this
  task and stays one at Tasks 9 and 10, because both route through `Seal`. The gate reports the
  number it read.

  **Property 3 — a record carries the nonce epoch it was sealed under, and nothing recomputes it.**
  `Seal` records `Transport.NonceEpoch()` at the moment it seals; `SubmitRecord` compares that
  recorded number with the epoch at submit time.
  *Refusal owed:* a typed refusal when a `*message.Record` reaches the submit path without a
  recorded seal-time epoch, naming the record's stream index — because the alternative is submitting
  it under the *current* epoch, which makes Task 10 Property 4 true by construction and therefore
  unfalsifiable. This is the half Task 10 Property 4 compares against and an earlier draft recorded
  nowhere.

  **Property 4 — the send half and the receive half share one session, one transport and one pair of
  stores.** Two `messageSender`s over one directory would be Task 2a Property 1's refusal reached
  from inside `sdk` itself.
  *Refusal owed:* `newMessageClient` refuses a config whose `Streams` or `Receive` is nil, rather than
  opening its own.
  *Scope to derive, separately from the class (R3):* the class is **the durable-store fields of
  `messageClientConfig`**, read off the struct's own field set rather than spelled; that class is
  **two** members at this task — `Streams` and `Receive` — and the gate reports the number it read,
  so a third durable store added to the config tomorrow fails here until this property is taught
  about it. The **scope** is a different question and is answered separately: it is every production
  file of `package sdk`, walked for `OpenStreamStore` and `OpenReceiveState` **call expressions**, of
  which the gate reports the number it found **and the number of production files it walked** — a
  walk of zero files is the broken gate, a count of zero call expressions is the correct reading, and
  the finding is any call expression at all.
  *The count of call expressions is ZERO at this task and that is deliberate, not an oversight — an
  earlier draft of this scope said "two members … in whatever stands the client up", and no task in
  this plan stands the client up.* Every declaration here is package-internal, both stores arrive on
  the config **injected**, and the surfacing that would open them is s1's (**S2-19**). So a gate
  written to expect two call expressions reads zero and is red at its own commit, which is the same
  empty-class defect this plan's Task 8a was created to close, one altitude up. The property that
  survives is the **prohibition** — the seam opens no store — and it is falsified by mutation 9,
  which puts a member there.

  **Property 5 — §5.9 G11: a commit lost between reserve and re-seal never re-uses the index.** The
  session re-seals after a lost commit and the second seal takes a **new** allocation, not the one
  the lost commit burned.
  *Refusal owed:* none; a duplicate index is the failure, and the message must print the index and
  both seal ordinals. This is the session half of the shape §5.6 describes; Task 4 Property 1 holds
  the store half, and the two together are what §5.9 G5 and G11 name.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Construct a second `GroupSession` in another `sdk` production file. Property 1 must fail on the
     count and name both call sites.
  2. Delete the seam's construction so the package constructs none. Property 1 must fail on a class
     of zero — **not pass** — which is the control that separates this gate from the vacuous one an
     earlier draft of Task 4 and Task 9 wrote.
  3. Pass nil as `groupHandleKeyEpoch0`. Property 1 must fail at the call site, before any restart.
  4. Call `SealRecord` directly from the send path, bypassing `Seal`. Property 2 must fail on the
     count.
  5. Wrap `SealRecord` in a renamed helper and call the helper. Property 2 must still fail — the
     class is resolved through the type checker, not matched on a name.
  6. Build a `message.Record` as a composite literal in production code. Property 2 must fail.
  7. Read `NonceEpoch()` at submit time and use it for both sides of the comparison. Property 3 must
     fail, and Task 10 Property 4 must fail with it: a comparison of a number with itself is the
     unfalsifiable shape this property exists to prevent.
  8. Drop the seal-time epoch and submit the bare `*message.Record`. Property 3 must fail with the
     typed refusal, not by succeeding.
  9. Open a second `StreamStore` inside the receiver. Property 4 must fail on the count, and Task 2a
     Property 1 must fail with it.
  10. Re-seal after a lost commit at the index the lost commit reserved. Property 5 must fail with a
     duplicate, and Task 4 Property 1 must not — the store handed out two numbers and the session
     used one twice, which is the half a store gate cannot see.

- [ ] **Step 6: Commit**

---

### Task 9: The group-opening ceremony the server's epoch gate requires

**Files:**
- Create: `sdk/message_group_open.go`
- Test: `sdk/message_group_open_test.go`

**Interfaces:**
- Consumes: Task 5's `messageTransport.Call`, Task 7's `Nonce`, Task 8's `recordProjection`,
  **Task 8a's `messageSender` and its `Seal`** — which is where the `GroupHandle`, the
  `StorageRootZero`, the `PqSecretZero` and the one `GroupSession` already are;
  `messagegroup.GroupHandleKey`, `messagegroup.StorageRoot`, `messagegroup.WrapTargetHandle`,
  `message.WriteKey`, `message.ReadKey`, `message.EpochAttachment`, `message.WrapTag`,
  `message.EpochComplete`; `protocol.CreateGroupRequest`. The `GroupHandle` is **injected** and
  never constructed (Gate 5), and it is injected once, at Task 8a, rather than again here.
- Produces:
```go
// what the ceremony needs BEYOND the seam. The handle, the storage root and
// the pq_secret are Task 8a's config and are deliberately not repeated here:
// two structs carrying the same injected key is two places to inject it
// differently.
type groupOpenSpec struct {
    ExpectedWraps uint32
    WrapBodies    [][]byte // one per expected wrap; S2-3 is what supplies them
}

func (self *messageSender) OpenGroup(ctx context.Context, spec *groupOpenSpec) error
```

**The ordering is the task, and every step of it was read from `msgrepo` source.**

1. **`CreateGroup`** carrying an `initial_commit` that is `IsCommit` with header `Epoch == 0` and a
   `ServerAttachment` of kind `AttachmentEpoch` whose `Epoch.Epoch == 1`, plus a
   `bootstrap_write_key` of exactly 32 octets. The server verifies the record's `write_auth` under
   that supplied key. The attachment must carry `WriteKey` and `ReadKey` of exactly 32 octets each
   and an `ExpectedWrapCount` that is **not zero**.
2. **The wraps** — `ExpectedWrapCount` records carrying `AttachmentWrap`, addressed by
   `WrapTargetHandle`. These and the marker are the only records exempt from the epoch gate.
3. **The `EpochComplete` marker**, whose `WrapCount` must equal the epoch's `ExpectedWrapCount`; only
   then does the store open the group for ordinary writes.
4. **Only then** the first ordinary `DURABLE` record — which is CP3b's one text message and is
   Task 10's.

**The trap that bricks the group at first restart, and it reads as a convenience.**
`NewGroupSession` says a session opened at MLS epoch 0 *"may leave `groupHandleKeyEpoch0` nil,
because the current root IS the epoch zero root and the constructor expands it."* That is true, and
there is **no accessor that hands the value back** — the seven exported methods again. So a caller
that takes the nil path never learns the value it is required to persist; at the next restart the
session opens above epoch 0 and is refused with `ErrEpochZeroHandleKeyMissing`, and by then
`mls_secret[0]` is unrecoverable because `Export` answers an erased-epoch error. **This plan
therefore never passes nil.** `OpenGroup` computes
`GroupHandleKey(StorageRoot(mls_secret[0], pq_secret[0]))` itself and persists it before the group's
first commit. Both functions are exported, so this is workable; the documented convenience is a
one-way door.

**And this is where S2-1 stops being abstract.** `bootstrap_write_key` is `write_key[0]`, and the
attachment's keys are `write_key[1]` and `read_key[1]`. The only derivation is
`message.WriteKey(StorageRoot(handle.Export(<label>, nil, 32), pqSecret))`, and the label and length
are **unexported constants** in `messagegroup`. `GroupHandle.Export` is exported and takes the label
as a parameter, so `sdk` *can* spell it — and that is a second copy of the one derivation the m1
standing test proves the entire record layer against. *Position taken:* `groupOpenSpec` takes
`StorageRootZero` as an **injected parameter**, so the derivation happens in exactly one place
outside this plan and `s2` contains no copy of the label at all. *Rejected:* spelling
`"URmessage/v1/storage"` in `sdk`. **S2-1** is the ask, and until it is answered the injection point
is where the answer lands.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the four steps happen in that order, and an ordinary record submitted before the
  marker is refused LOCALLY.** The server refuses it with `REASON_EPOCH_INCOMPLETE`; a client that
  learns the ordering from the wire has spent a round trip on a rule it holds.
  *Refusal owed:* a typed refusal naming the step that has not happened.

  **Property 2 — `group_handle_key[0]` is computed and persisted BEFORE the group's first commit, and
  the nil path is unreachable from this plan.** After the group leaves epoch 0 the value cannot be
  reconstructed by anything.
  *Refusal owed:* `OpenGroup` refuses to proceed if the persist failed, rather than continuing with a
  value only memory holds.
  *Scope to derive, separately from the class (R3):* the class is **every `NewGroupSession` call
  expression in `package sdk`'s production files**, read off the syntax tree, and the gate requires a
  non-nil third argument at every one. That class is **one** member at this task — Task 8a's, which
  is the construction that gives this gate something to read; until Task 8a lands, nothing in
  `package sdk` constructs a session and this gate reads nothing while reporting clean. The gate
  reports the number it read, and a count of zero is the broken gate the Definition of done names. The scope is the package, not this file, because the second call site
  is the one that will take the convenience. Task 8a Property 1 is the same construction seen from
  the seam's side and names this property back.

  **Property 3 — `ExpectedWrapCount` is a promise the client keeps.** The marker's `WrapCount` equals
  the number of wrap records this client actually submitted, and both equal the count the attachment
  declared.
  *Refusal owed:* a local refusal to send the marker when the counts disagree.
  *And this property is stricter than the server.* The store sets `epochComplete` when the marker's
  own declared `WrapCount` equals the row's `expectedWrapCount`; **it never counts the wrap records
  it received**. So a client could declare one, send the marker declaring one, and send no wrap at
  all, and the server would open the group. That is a weak gate on the server, and it is exactly the
  path on which a CP3b run would exercise **no `pq_secret` delivery at all** while appearing to pass.
  This property is what keeps `s2` off it.

  **Property 4 — every record in the ceremony is sealed through Task 8a's one `SealRecord` call and
  none is assembled by hand.** Including the initial commit and the marker.
  *Refusal owed:* none; the finding is a `message.Record` literal in production code, or a second
  `SealRecord` call site, which is Task 8a Property 2's count.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Submit an ordinary record before the marker. Property 1 must fail locally.
  2. Send the marker before the wraps. Property 1 must fail.
  3. Pass nil as `groupHandleKeyEpoch0`. Property 2 must fail — this is the mutation that reproduces
     the one-way door, and a suite that never restarts the session will not see it, so the gate must
     be over the call site.
  4. Persist `group_handle_key` after the first commit instead of before. Property 2 must fail.
  5. Declare `ExpectedWrapCount` as 1 and send no wrap, then send the marker with `WrapCount` 1.
     Property 3 must fail **in `sdk`**, even though the server accepts it.
  6. Send a marker whose `WrapCount` differs from the attachment's `ExpectedWrapCount`. Property 3
     must fail.
  7. Set `ExpectedWrapCount` to zero. The server refuses the attachment; Property 3 must fail first,
     locally.
  8. Build the `EpochComplete` record as a `message.Record` literal. Property 4 must fail.

- [ ] **Step 6: Commit**

---

### Task 10: Submit, and the `SubmitResult` vocabulary

**Files:**
- Create: `sdk/message_send.go`
- Test: `sdk/message_send_test.go`

**Interfaces:**
- Consumes: Task 3's `NewStreamIndexReserver`, Task 5's `Call`, Task 7's `Nonce` and `NonceEpoch`,
  Task 8's `recordProjection`, Task 8a's `messageSender`, `Seal` and `sealedRecord`, Task 9's
  `OpenGroup`; `protocol.SubmitRequest`, `protocol.SubmitResult`, `protocol.Reason`.
- Produces:
```go
// takes the SEALED record, not a bare *message.Record: the nonce epoch the
// record was sealed under travels with it, because Property 4 below cannot be
// decided from the record alone (Task 8a Property 3).
func (self *messageSender) SubmitRecord(ctx context.Context,
    sealed *sealedRecord) (*protocol.SubmitResult, error)
```

**`SubmitRequest` is the one authenticated arm that carries NO `req_auth`.** §4.3.8 requires an
authenticator on Fetch, Subscribe, GroupStatus, BlobGrant and WrapFetch and **exempts Submit**,
because every record carries its own `write_auth`. `connect/protocol`'s own test holds that set
executable. A send path that computes a `req_auth` for Submit is not merely wasteful — it is a claim
about the protocol that the protocol does not make.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — a batch containing a commit contains exactly one record.** §4.3.3 states it and the
  server enforces it.
  *Refusal owed:* a local refusal naming the batch size.

  **Property 2 — every `Reason` the server can answer is dispositioned, and an unrecognised one is a
  refusal rather than a success.**
  *Refusal owed:* a typed refusal carrying the reason.
  *Scope to derive, separately from the class (R3):* the class is **the `protocol.Reason` enum's
  value set**, read off the compiled descriptor; that class is **eighteen** members at this task
  (`REASON_OK` through `REASON_CARD_RATE_LIMITED`, values 0–17, measured 2026-09-09) and the gate
  reports the number it read, so a nineteenth added upstream fails here. The scope is *every* value,
  not the subset the CP3b path can provoke: a gate scoped to the reachable subset grows a hole every
  time the server learns a new refusal.

  **Property 3 — `winning_commit` is surfaced on ANY commit rejection**, not only on the one reason a
  reader expects. §6.2 and A-6 make it the loser's only route back to the current epoch.
  *Refusal owed:* the refusal carries it; dropping it strands the caller.

  **Property 4 — a record sealed under a superseded `server_nonce` is not submitted.** The nonce
  epoch **recorded at seal time by Task 8a Property 3** is compared with the nonce epoch read at
  submit time. The two numbers must have different provenance: a path that reads `NonceEpoch()` twice
  compares a number with itself and the property becomes true by construction, which is the
  unfalsifiable shape R1 exists to prevent.
  *Refusal owed:* a typed refusal naming both epochs, so the caller can tell this from a server
  rejection; and a second typed refusal for a record that arrives with no recorded seal-time epoch,
  because submitting it under the current epoch is the same defect wearing a success. This is the
  local half of **S2-2**; the recovery is not this plan's.

  **Property 5 — no `req_auth` is COMPUTED on the submit path.** §4.3.8 exempts Submit, and the
  earlier draft of this property said *"`Submit` carries no `req_auth`; the finding is a populated
  field"* — which cannot fail and whose mutation cannot be applied: measured 2026-09-09,
  `protocol.SubmitRequest` declares `group_id` and `records` and **nothing else**, the envelope
  `MessageServerRequest` carries no `req_auth` either, and an `awk` pass over `message.proto` finds
  the field only on `BlobGrantRequest`, `FetchRequest`, `GroupStatusRequest`, `RetentionApplied`,
  `SubscribeRequest`, `TransientPush` and `WrapFetchRequest`. There is no field to populate, so
  *"the finding is a populated field"* names a finding no incorrect implementation can produce and
  a mutation that does not compile. What CAN be wrong is the computation, and it is worth catching:
  a `req_auth` computed for Submit is a claim about the protocol that the protocol does not make,
  and it burns a MAC under `read_key[e]` over bytes nobody verifies.
  *Refusal owed:* none; the finding is a reachable call.
  *Scope to derive, separately from the class (R3):* the class is **every call to
  `message.ComputeRequestAuth` in `package sdk`'s production files, with the exported entry points
  each is reachable from**, read off the call graph rather than off the file it sits in. **That class
  has no member at this task**, and saying so is the repair rather than the defect: Task 11's `Fetch`
  is the one legitimate call this plan ever makes, the landing order is `9, 10, 11`, and a gate
  written here to expect one member reports a count it cannot read on its own commit — the empty
  derived class this plan's Task 8a exists to have closed. The count half **lands at Task 11
  Property 1**, which is where that one call comes into existence; what this task holds is the
  **prohibition**, and its gate reports **the number of call-graph nodes it walked from
  `SubmitRecord`** rather than the class size, so a walk of zero nodes is the broken gate and a class
  of zero here is the correct reading. The mutations are what put a member in the class: 7 writes one
  into `SubmitRecord` and 8 writes one into a helper both halves call. The scope is the whole
  package's call graph, not the send path's own file, because the defect is a helper called from both
  halves rather than a line written into `SubmitRecord`.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Put a commit and an ordinary record in one batch. Property 1 must fail locally.
  2. Treat an unrecognised `Reason` as success. Property 2 must fail.
  3. Enumerate only the reasons the CP3b path provokes. Property 2 must fail on the count.
  4. Drop `winning_commit` on every reason but one. Property 3 must fail.
  5. Submit a record sealed before a reconnect. Property 4 must fail locally, not on the wire.
  6. Compare nonce **bytes** instead of nonce epoch. Property 4 must still fail — two connections can
     in principle draw the same nonce, and a gate that compares the value is a gate that tests the
     CSPRNG.
  7. Compute a `req_auth` inside `SubmitRecord` and discard the result. Property 5 must fail on
     **reachability**, not on a wire field — there is no wire field to fail on.
  8. Move the `req_auth` computation into a helper that both `Fetch` and `SubmitRecord` call.
     Property 5 must still fail, on the call graph rather than on the call site.

- [ ] **Step 6: Commit**

---

## Wave 4 — the receive path (Tasks 11–12)

**Task 12's store half lands BEFORE Task 8a and its call-site half lands after it**, and saying so is
what keeps the two from being dispatched as one unit that cannot compile. `OpenReceiveState` and its
row (Properties 5, 6 and 7) need nothing from the seam and are a dependency of Task 8a's config;
Properties 1 to 4 are gates over argument expressions and call orderings inside the receiver, which
is a type Task 8a declares. Task 11's `Fetch` is a method on that same type and lands after it
whole.

### Task 11: Fetch, `req_auth`, and the op byte that is read rather than written down

**Files:**
- Create: `sdk/message_fetch.go`
- Test: `sdk/message_fetch_test.go`

**Interfaces:**
- Consumes: Task 5's `Call`, Task 7's `Nonce`, Task 8a's `messageReceiver`;
  `message.ComputeRequestAuth`, `message.ParseRecord`; `protocol.FetchRequest`,
  `protocol.FetchResponse`.
- Produces:
```go
// the key travels WITH the epoch it belongs to. A bare []byte cannot answer
// "is this the key for read_epoch?", so Property 3 below would be undecidable
// at this signature -- which is what an earlier draft asked for.
type readKeyRef struct {
    Epoch uint64
    Key   []byte
}

func (self *messageReceiver) Fetch(ctx context.Context, request *protocol.FetchRequest,
    readKey *readKeyRef) (*protocol.FetchResponse, error)
```

**The recipe, from §4.3.8 and from `msgrepo/api/fetch.go`'s verifier rather than from memory.**
`req_auth = MAC(read_key[e], "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op) ‖ LP(canonical_request_bytes))`,
where `op` is **the oneof arm's field number** and `canonical_request_bytes` is the protobuf
deterministic marshal of the request body **with its own `req_auth` cleared**. `read_epoch` is inside
those bytes and therefore inside the MAC, which is what makes the server's key selection an
authenticated choice rather than a hint. The server refuses an absent `req_auth` outright, before the
comparison, because the length of a tag is public.

**The read key is an explicit parameter, and that is a finding rather than a style choice — but it
carries its EPOCH, which the earlier draft's bare `[]byte` did not.** `msgrepo/harness/client.go`'s
own `Fetch` takes `readKey []byte` for exactly the first reason: it has no session to ask. `s2`
**will** have a session, and the session will not tell it — `GroupSession` holds the read key
privately and exposes none of its seven methods to reach it. Making the parameter explicit keeps the
gap visible at every call site instead of burying a re-derivation inside the fetch path. **S2-1.**
Making it a `readKeyRef` rather than a `[]byte` is Property 3's precondition: a bare slice cannot
answer *"is this the key for `read_epoch`?"*, so the local refusal that property owes would be
undecidable at the signature and the property unfalsifiable.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the MAC is computed over the canonical bytes with `req_auth` cleared, under
  `read_key[read_epoch]`.** A MAC computed over the request as sent, with the field already
  populated, verifies against nothing.
  *Refusal owed:* none locally; the observable failure is `REASON_REJECTED`, which is why the
  property is asserted against `message.ComputeRequestAuth`'s own output and not against a server.
  *And this is the one `message.ComputeRequestAuth` call `package sdk` ever makes.* It is where
  **Task 10 Property 5**'s empty class first has a member: at Task 10's own commit that class is
  zero, because Task 11 lands after Task 10, and from **this** commit onward it is one. **Task 10
  Property 5** is unchanged by that — its finding is a call reachable from `SubmitRecord`, and this
  one must not be. The two properties are the same subject seen from the two halves of §4.3.8, which
  requires the authenticator on Fetch and exempts Submit.

  **Property 2 — the op byte is read off the compiled descriptor, never written down.** It is the
  oneof arm's field number and `connect/protocol` already holds a test that pins the correspondence.
  *Refusal owed:* an error for a body that is not a known arm, never a default of zero.
  *Scope to derive, separately from the class (R3):* the class is **every arm of
  `MessageServerRequest`'s `body` oneof**, read off the compiled descriptor rather than listed; that
  class is **fifteen** members at this task — `hello` = 10 through `rendezvous_retire` = 24, counted
  off `connect/protocol/message.proto` on 2026-09-09 — and the gate reports the number it read, so a
  sixteenth arm added upstream fails here. The scope is the descriptor's whole arm set, because an
  arm added tomorrow gets an op byte whether or not this plan sends it.
  **The four arms this binding SENDS are a different, smaller statement and must not be conflated
  with the class.** An earlier draft said the descriptor-derived class *"is four members — Hello,
  `CreateGroup`, `Submit` and `Fetch`, which are also the only four arms `msgrepo/peer` dispatches"*.
  The four is right about `peer` and wrong about the descriptor: `peer/peer.go` registers exactly
  those four handlers, but that is the **server's dispatch table**, and a gate that does what the
  sentence says — read the class off the oneof descriptor — reports 15 and fails the stated count on
  its first run. `sdk` cannot import `peer` (Task 13 Property 2), so the four are a documented subset
  with their own, separate refusal: `Call` refuses a body outside those four with a typed error
  naming the arm and its op byte, rather than sending a request no handler serves.

  **Property 3 — a `FetchRequest` whose `read_epoch` is not the epoch of the key supplied is refused
  locally, before the MAC is computed**, rather than sent to be refused.
  *Refusal owed:* a typed refusal naming **both** epochs — the request's and the key's. The earlier
  draft said *"an epoch this client cannot key"*, which is not decidable at this signature: a bare
  `readKey []byte` carries no epoch, so nothing in the produced surface could tell a key for epoch 3
  from a key for epoch 4 and the property could neither be satisfied deliberately nor failed by a
  wrong implementation. `readKeyRef` carries the epoch beside the key for exactly this reason, and
  the key is still injected because — S2-1 — the session does not hand one back.

  **Property 4 — `since_record_id` is EXCLUSIVE and 0 means from the beginning**, and the paging loop
  never re-requests a record it has already seen nor skips one.
  *Refusal owed:* none; the failure is a gap or a repeat, and the property is what makes both
  observable.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Compute the MAC over the request with `req_auth` already populated. Property 1 must fail.
  2. Use a non-deterministic marshal. Property 1 must fail — and note this may pass by luck on a
     single-field request, so the gate must use a request with several fields set.
  3. Clear a different field. Property 1 must fail.
  4. Hard-code the op byte. Property 2 must fail when the descriptor and the constant disagree.
  5. Default an unknown arm's op byte to zero. Property 2 must fail.
  6. Send with an empty `req_auth`. Property 1 must fail locally; the server refuses it outright and
     a client that relies on that has moved its own check onto somebody else's machine.
  7. Set `read_epoch` to a value that is not the supplied `readKeyRef.Epoch`. Property 3 must fail
     locally, and it must fail before the MAC is computed — a MAC under the wrong epoch's key is
     still a MAC, and a path that computes one has turned a local mismatch into a wire refusal.
  8. Supply a `readKeyRef` with a nil or zero-length `Key`. Property 3 must fail locally, for the
     same reason and before the MAC — a MAC under a zero-length key is still a MAC.
  9. Treat `since_record_id` as inclusive. Property 4 must fail with a duplicate.
  10. Page with `since_record_id = last + 1`. Property 4 must fail with a skip — off-by-one in the
     other direction, and it is the one that loses a message rather than repeating one.

- [ ] **Step 6: Commit**

---

### Task 12: `TrackSender`'s head index, and the `sender_handle` → leaf map nothing declares

**Files:**
- Create: `sdk/message_receive_state.go`
- Test: `sdk/message_receive_state_test.go`

**Interfaces:**
- Consumes: Task 11's `Fetch`, Task 1's row identity and its three refusals, Task 2a's exclusion;
  `messagegroup.GroupSession.TrackSender`, `messagegroup.GroupSession.OpenRecord`,
  `messagegroup.SenderHandle`, `messagegroup.ReceiverRatchetKey`, `messagegroup.ErrOutOfWindow`,
  `messagegroup.ErrNoWrap`, `messagegroup.ErrNoReceiverRatchet`; `message.RetentionClassWire`;
  `GroupHandle.MemberCount` and `GroupHandle.MemberAt`, off an injected handle.
- Produces:
```go
// keyed by the retention WIRE byte, which is what the ratchet this row feeds is
// keyed by. NOT by message.RetentionClass -- see below.
type ReceiveState struct{ /* unexported */ }

func OpenReceiveState(dir string) (*ReceiveState, error)
func (self *ReceiveState) HeadIndex(groupId []byte, leaf uint32, retentionWire byte) (uint64, error)
func (self *ReceiveState) AdvanceHeadIndex(groupId []byte, leaf uint32, retentionWire byte, index uint64) error
func (self *ReceiveState) Close() error

var ErrReceiveStateKeySpace error // a row written under a key derivation this build does not produce
var ErrReceiveStateWidth    error // a groupId of the wrong width, or a wire byte no join produces
var ErrReceiveStateState    error // a row that is present and unreadable, never a silent zero
```

**THE KEY IS THE RATCHET'S KEY, AND AN EARLIER DRAFT GOT IT WRONG IN THE SAME WAY LEDGER ITEM 170
DESCRIBES.** That draft keyed the row by `(groupId, leaf, class message.RetentionClass)`. The ratchet
the row feeds is keyed by the retention **wire** byte: `connect/messagegroup/session.go`'s
`trackSenderOnLoop` computes `retentionWire, err := message.RetentionClassWire(class, ephBucket)` and
tracks under `ReceiverRatchetKey{SenderHandle: SenderHandle(groupHandleKey, leaf), RetentionWire:
retentionWire}` — a two-field comparable struct whose second field carries the bucket. `RetentionEph`
is **one** class value (3) spanning buckets 0..5 at wire `0x10|bucket`, so a row keyed by the class
collapses **all six EPH buckets of one sender onto one persisted head index**.

**Why this is not a latent tidiness problem.** A wrong head index on receive is **silent message
loss, not a stall**: `NewReceiverRatchet(classKey, leaf, headIndex, windowSize)` walks `headIndex`
rungs before it returns, so everything below the number it was given falls outside the skipped-key
window and can never be opened. Nothing is broken today only because `SealRecord` refuses every class
but `DURABLE` (`seal.go`: `if class != message.RetentionDurable { return nil, ...
ErrRetentionClassUnruled }`) — which is precisely the argument ledger item 170 makes about a store
that has no rows yet, one layer down. **So this store gets Task 1's mechanism too**, and the earlier
draft gave it none: a version tag in the row name derived from the same field set the identity is
derived from, a key-space refusal, and a width refusal. A row this build cannot key is
`ErrReceiveStateKeySpace` and never `(0, nil)`.

The row identity's field set has an authority and it is not this plan: **`ReceiverRatchetKey` as
`connect/messagegroup` declares it**, plus the group. Whether §8.2 should say so is **S2-18**.

**This is a SECOND durable store, and no leg was given it.** `TrackSender`'s doc is explicit that
`headIndex` *"is the CALLER'S state, never a number read off a record header"*, and the reason is
adversarial rather than stylistic: `NewReceiverRatchet` walks one expansion per index below the
number it is given, so a peer that could choose the number could choose how much work this session
does. §8.2's `MessageStore` carries `ReserveStreamIndex` and `StreamHighWater` and **nothing at all
for the receive side**. So leg 5 as the plan states it is only the **sender** half of the durability
CP3b needs, and this task is the other half. **S2-6.**

**And the ceiling this store must be designed against is 2^20, not 2^64.** `maxLadderWalk` is
`1 << 20`, unexported, and it bounds a receiver's `headIndex` as well as a sender's resume. It is a
**wall, not a wrap**: a stream that has genuinely passed that many records cannot be resumed at all,
and under A1's shared counter every transient of that sender spends the same budget. A store designed
as if `u64` were the budget is designed against the wrong number. **S2-10.**

**The map nothing declares.** `OpenRecord` needs a receiver ratchet, which only `TrackSender(leaf,
...)` installs; a fetched record names only its `sender_handle`. `SenderHandle(groupHandleKey, leaf)`
is one-way and there is **no inverse anywhere in the tree**. So the receiver must enumerate the
group's members through `MemberCount` / `MemberAt` and precompute the map. Nothing in any document
says so.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `headIndex` comes from this store and never from a record header.** Across a
  restart, the number handed to `TrackSender` is the persisted one.
  *Refusal owed:* none; the finding is a read of `record.Header.StreamIndex` on the path to
  `TrackSender`.
  *Scope to derive, separately from the class (R3):* the class is **every argument expression that
  reaches `TrackSender`'s `headIndex` parameter in `package sdk`'s production files**, read off the
  syntax tree; the scope is the package, not this file. That class is one member at this task and the
  gate reports the number it read. A gate that greps for `TrackSender` and reads the line finds a
  call that spans four lines and reports clean.

  **Property 2 — the `sender_handle` → leaf map is TOTAL over the group's members**, derived from
  `MemberCount` and `MemberAt` rather than from the senders seen so far.
  *Refusal owed:* a record whose `sender_handle` is in no member's image is refused with a typed
  error naming the handle — never opened, and never silently skipped.

  **Property 3 — `ErrOutOfWindow` and `ErrNoWrap` are OUTCOMES, not failures.** Both are matched with
  `errors.Is` and reported as themselves; neither is an error the caller should retry.
  *Refusal owed:* the receive loop continues; a record that is out of window does not stop the fetch.

  **Property 4 — `TrackSender` precedes the first `OpenRecord` of that peer's records.** Otherwise
  `OpenRecord` answers `ErrNoReceiverRatchet`, because ratchets are tracked and never auto-created.
  *Refusal owed:* a local refusal naming the untracked leaf, so an untracked peer is distinguishable
  from a corrupt record.

  **Property 5 — a persisted head index above `maxLadderWalk` is refused at the store**, with an
  error that names the bound, rather than handed to `NewReceiverRatchet` to be refused there.
  *Refusal owed:* a typed refusal. The bound is unexported, so `sdk` holds its own copy and its doc
  comment must say that it is a copy and where the original is — the same obligation Task 6 carries
  for the part size, and **S2-9** covers both.

  **Property 6 — a row is identified by exactly the fields the RATCHET is keyed by, and the identity
  is derived from `messagegroup.ReceiverRatchetKey`'s own field set rather than spelled.** The wire
  byte the row is keyed by must be the one `message.RetentionClassWire(class, ephBucket)` produces
  and never a second computation of the class-and-bucket join — the same §12.1 A-1 rule Task 8
  Property 2 holds on the send side.
  *Refusal owed:* `ErrReceiveStateWidth` for a `groupId` of the wrong width or a wire byte
  `RetentionClassWire` does not produce, naming which and what it was. A wire byte accepted without
  that check is how bucket 3 and bucket 4 land on one row.
  *Scope to derive, separately from the class (R3):* the class is **the type
  `messagegroup.ReceiverRatchetKey` as `connect/messagegroup` declares it today**, read through
  reflection at test time and not copied into `sdk`; that class is **two** members at this task —
  `SenderHandle` and `RetentionWire` — and the gate reports the number it read, so a field added or
  removed in `connect` fails here rather than silently re-keying every row. The scope is the type,
  not the row's file name: a gate that listed the two field names survives the day a third returns
  and is therefore not this gate. The group is carried by `SenderHandle`'s own derivation
  (`SenderHandle(groupHandleKey, leaf)`), and the row still names `groupId` explicitly so that a
  store shared by two groups cannot collide on a truncated handle.

  **Property 7 — a row whose key space this build did not produce is REFUSED, never answered zero.**
  The row's on-disk name carries a version tag, readable off the name independently of the identity,
  derived from the same field set Property 6 derives.
  *Refusal owed:* `ErrReceiveStateKeySpace`, a typed fatal error per §5.9 G7 — never a bool, never a
  log line, and specifically **never `(0, nil)`**. This is Task 1 Property 2's mechanism applied to
  the second durable store, and the reason it is owed here rather than assumed is that the failure is
  worse on this side: on the send side a silent zero re-allocates an index, which the server refuses
  with `REASON_STREAM_INDEX_REGRESSED`; on the receive side a silent zero walks a ratchet to the
  wrong head and every record below it becomes permanently unopenable with no error anywhere.
  *And it inherits Task 1 Property 2's DIRECTORY SHAPE as well as its tag, because the collision that
  property removes reaches this store through this task's own `Consumes` block.* This task consumes
  both *"Task 1's row identity and its three refusals"* — of which `ErrReceiveStateState` is the
  analogue — and *"Task 2a's exclusion"*, so a guard entry inside the enumerated directory would make
  every `HeadIndex` after `OpenReceiveState` refuse, exactly as it would have on the send side. So
  `OpenReceiveState` creates the same two levels: a **row directory** under its `dir` that holds rows
  and nothing else and is the only thing the enumeration reads, and, beside it and never inside it,
  whatever single entry its exclusion is held on. **An entry in that row directory which is not a row
  under any tag — Task 1 Property 2's partition (c) — is `ErrReceiveStateState`**, and a name that
  parses as `tag ‖ identity` under a tag this build does not produce is partition (b) and is
  `ErrReceiveStateKeySpace`, which is the answer mutation 13 demands.
  *What this does NOT rule, and it is filed rather than decided:* whether `StreamStore` and
  `ReceiveState` may be handed the **same** `dir`, and whether `OpenReceiveState` acquires its own
  exclusion over its own directory or shares the one `OpenStreamStore` holds. This task's `Consumes`
  block names *"Task 2a's exclusion"* and does not say which, Task 8a's config carries the two stores
  as separate injected values and says nothing about their directories, and no document rules it.
  **S2-21.**

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Pass `record.Header.StreamIndex` to `TrackSender`. Property 1 must fail at the call site, not by
     behaviour.
  2. Wrap the header read in a helper and pass the helper's result. Property 1 must still fail — the
     class is the argument's provenance, not its spelling.
  3. Reset the head index to 0 on restart. Property 1 must fail.
  4. Build the map from senders already seen. Property 2 must fail for a member that has not yet
     sent.
  5. Skip a record whose `sender_handle` is unknown. Property 2 must fail — a silent skip and a
     refusal are one line apart and only one of them is safe.
  6. Treat `ErrOutOfWindow` as a fatal error. Property 3 must fail.
  7. Treat `ErrNoWrap` as a successful open with empty plaintext. Property 3 must fail.
  8. Call `OpenRecord` before `TrackSender`. Property 4 must fail with the local refusal, not with
     `ErrNoReceiverRatchet` from inside the session.
  9. Persist a head index of `maxLadderWalk + 1` and reopen. Property 5 must fail at the store.
  10. Key the row by `message.RetentionClass` rather than by the retention wire byte. Property 6 must
     fail, and it must fail on an **EPH** pair — buckets 3 and 4 of one sender — because the two
     keyings agree for `PERMANENT`, `DURABLE` and `MEDIA` and a gate that only exercises `DURABLE`
     passes this mutant. `SealRecord` refuses every class but `DURABLE`, so the gate reaches EPH by
     calling the store directly rather than through a seal.
  11. Add a third field to a local copy of `ReceiverRatchetKey` and key rows off the copy.
     Property 6 must fail on the count, not on a comparison of names.
  12. Compute the class-and-bucket join locally instead of calling `message.RetentionClassWire`.
     Property 6 must fail on the second implementation, not on the answer.
  13. Plant a row under a key derivation this build does not produce and read it. Property 7 must
     fail with `ErrReceiveStateKeySpace`. **A `(0, nil)` here is ledger item 170 reproduced on the
     receive side, where it costs messages rather than a server refusal.**
  14. Fold the version tag into the derived identity hash so it cannot be read off the name.
     Property 7 must fail — a foreign-tag row is then an absent file and the store answers zero.
  15. Acquire this store's exclusion on a guard entry **inside its row directory**. Property 7 must
     fail with `ErrReceiveStateState` on the first `HeadIndex` after a successful `OpenReceiveState`.
     This is Task 2a mutation 10 on the receive side, and it is here because this task consumes both
     halves of the collision that mutation reproduces.

- [ ] **Step 6: Commit**

---

## Wave 5 — the gates (Tasks 13–15), off the CP3b prefix

### Task 13: `sdk/layering_test.go` — the two edges this plan must not create

**Files:**
- Create: `sdk/message_layering_test.go`
- Test: the file is the test.

**Interfaces:**
- Consumes: nothing. It reads the module's own dependency graph.
- Produces: no declaration. It produces the gate s1 assigned to s5 and that `s2` is the first plan
  able to violate.

**Why it is here and not in s5.** s1's open item S1-13 records that `sdk/layering_test.go` does not
exist and that s1 creates the first **test-only** `sdk` → `connect/mls` edge, so the gate must be
written against the **non-test** import set. `s2` is the first plan that would introduce a wrong
**production** edge — to `connect/mls`, or to the message-server module — so the gate belongs with the
plan that could break it, not with the plan that will eventually own the engine factory.

**THE FIRST VERSION OF THIS GATE CONVICTED THE PLAN'S OWN REQUIRED EDGES, AND THE REPAIR IS A
RE-DERIVATION RATHER THAN AN EXEMPTION.** It is written out here because the s1 plan shipped four
properties no correct implementation could satisfy and the brief that commissioned this one named
that failure mode specifically. The first version scoped Property 1 to *"the whole non-test
dependency set — `go list -deps` … every package in that set, transitively"*, and its
Definition-of-done row was `go list -deps ./... | grep connect/mls` → no matches. Measured on this
tree 2026-09-09, at `connect` `7868d65` with Go 1.26.5:

- `grep -rn 'urnetwork/connect/mls' connect/messagegroup/*.go | grep -v _test` returns **eight import
  lines in seven production files** — `engine.go:38` and `:39`, `epoch.go:56`, `handle.go:55`,
  `keyschedule.go:52`, `ratchet.go:80`, `seal.go:77`, `xwing.go:36`. Five are `connect/mls`; three
  are `connect/mls/syntax`.
- `go list -deps ./message` alone prints `github.com/urnetwork/connect/mls/syntax`, and
  `go list -deps ./messagegroup` prints `github.com/urnetwork/connect/mls` as well.
- The grep string `connect/mls` matches `connect/mls/syntax` **as a substring**, so even an
  `sdk` that touched neither package but reached `connect/message` would fail that row.

Task 1 Consumes `messagegroup.StreamKey` and Task 8 Consumes `connect/message`, so **both** edges
are on the CP3b prefix from Task 1 onward. A transitive-set gate is therefore red before a single
mutation, and every Task 13 mutation would have run against a red baseline.

**What the gate actually needs to defend, re-derived from Gate 5 rather than from the old scope.**
§4.5's engine seam exists so that no `connect/mls` **type** appears in an `sdk` declaration and no
`sdk` file can construct a `GroupEngine`; `NewConnectMlsEngine`'s five parameters are all
`connect/mls` types, and that is the edge s5 owns. Nothing in §4.5 or §2.3 is a claim about the
*transitive closure* — `sdk` → `connect/messagegroup` → `connect/mls` is §2.3's own layering, drawn
in §2.3's own arrow order, and a gate that forbids it forbids the layering it cites. The decidable
property is the **direct import set of `package sdk`'s own files**.

**And what is no longer defended, said plainly rather than dropped.** The transitive scope would
have caught a **new module** arriving through a transitive path — a dependency `sdk` never names and
that appears anyway. A direct-import gate cannot see that. Property 4 below replaces exactly that
half, over the module's own `require` block, which is where a new module actually becomes visible
and is a smaller and decidable class. Nothing else the old scope covered is lost, because nothing
else it covered was satisfiable.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — no production file of `package sdk` DIRECTLY imports `connect/mls` or
  `connect/mls/syntax`.** Gate 5 (§4.5) permits exactly one such edge and it is s5's engine factory,
  which this plan does not write.
  *Refusal owed:* a failure naming the importing file and the imported path, and — because the two
  paths are one a substring of the other — matching them **anchored**, never by `strings.Contains`.
  *Scope to derive, separately from the class (R3):* the class is **the import paths §2.3 and Gate 5
  forbid an `sdk` FILE from spelling**, which those two rules fix rather than this gate; that class
  is **three** members at this task — `github.com/urnetwork/connect/mls`,
  `github.com/urnetwork/connect/mls/syntax` and `github.com/urnetwork/message-server` — and the gate
  reports the number of forbidden paths it was given, because a gate that was given none reports
  clean over everything. The **scope** is the **import specs of `package sdk`'s own non-test files**,
  read off the **syntax tree over every `.go` file in the package directory, unfiltered by any build
  context** — **never** `go list -deps`, whose answer over the four packages this plan links is 414
  packages across 30 module prefixes and necessarily contains both `mls` packages. The gate reports
  **two** numbers: the number of production files it read, and the number of production `.go` files
  the directory holds. **They must be equal**, and a read of zero files is a broken gate rather than
  a clean one.
  *And `go list -f '{{range .Imports}}'` is NOT an interchangeable reading of that scope, which is
  what an earlier version of this sentence offered.* `go list` answers for **one** build context and
  reports only the files that satisfy the runner's `GOOS`/`GOARCH`. Reproduced 2026-09-09 with the
  project toolchain in a scratch module holding `a.go` (imports `fmt`) and `b_unix.go`
  (`//go:build unix`, imports `crypto/sha256`): on `windows/amd64`,
  `go list -f '{{range .Imports}}{{println .}}{{end}}' .` prints `fmt` alone and
  `go list -f '{{.GoFiles}} {{.IgnoredGoFiles}}'` prints `[a.go] [b_unix.go]`; with `GOOS=linux` it
  prints `crypto/sha256` and `fmt`. Measured on the subject itself with `go/build`'s own `MatchFile`
  — the evaluator `go list` uses — over `sdk` at `432986f`: of **57** `package sdk` root production
  files a `windows/amd64` context reads **51** and skips **six** — `device_local_ioloop.go`
  (`!windows`), `device_rpc_platform_js.go` (`js`), `glog_android.go`, `glog_ios.go`,
  `glog_macos.go`, `stderr_mobile.go`. **Task 2a's own Files block adds two more a Windows runner
  never reads** — `message_stream_exclusion_unix.go` and `message_stream_exclusion_other.go` — and
  this plan directs Windows runs. A gate that cannot see a file cannot fail on what that file
  imports, which is why the two numbers above are reported side by side: the file-set reading is the
  property, and the equality of the two numbers is the check that the reading was not filtered.
  Property 3 below reads the same unfiltered file set for the same reason.

  **Property 2 — `sdk` does not import `github.com/urnetwork/message-server` at all**, in production
  or in test. `msgrepo/harness` is the reference for Tasks 5–11 and is read, never linked; it is also
  gated test-only on its own side, so an import here would fail there.
  *Refusal owed:* a failure naming the path. This is the one forbidden path whose scope IS the whole
  graph — `go list -deps -test` — because the module is not in `sdk`'s graph at all, so a walk that
  finds it has found a real arrival rather than a legal layer.

  **Property 3 — the `github.com/urnetwork/*` paths `package sdk`'s production files spell directly
  are exactly the ones this plan and the tree already declare.**
  *Refusal owed:* a failure naming the undeclared path and the file that spells it.
  *Scope to derive, separately from the class (R3):* the class is **every `github.com/urnetwork/*`
  import path appearing in an import spec of a `package sdk` production file**, read off the syntax
  tree; that class is **six** members at this task — `connect`, `connect/protocol`, `glog` and
  `goidenticons`, which the tree already spells (measured 2026-09-09 over `sdk`'s production files:
  37 sites, 6, 3 and 1 respectively), plus `connect/message` and `connect/messagegroup`, which this
  plan adds — and the gate reports the number it read. The scope is every production file of the
  package, not the files this plan creates, because an `sdk` file that already existed is as able to
  spell a new path as a new one is.

  **Property 4 — the module gains no new require-block entry beyond the ONE this plan promotes from
  indirect to direct, and no new module at all.** This is the half Property 1's old transitive scope
  was reaching for and could not decidably hold. *The number is one, and it read "two" until
  2026-09-09* — while this property's own measurement says 8 direct and 28 indirect before and 9 and
  27 after, the *Dependency policy* says *"One require-block line"*, and the Definition of done's row
  says *"one line"*. Re-measured 2026-09-09 in `sdk` at `432986f`: **36** require lines, **8** direct,
  **28** indirect, and `google.golang.org/protobuf v1.36.11 // indirect` at `go.mod:42`. A gate
  written to the header's "two" is red on the commit that makes the one promotion, which is the same
  unsatisfiable shape one countable line lower down.
  *Refusal owed:* a failure naming the module path and whether it arrived as direct or indirect.
  *Scope to derive, separately from the class (R3):* the class is **every module path in
  `sdk/go.mod`'s require blocks**, read off the parsed file rather than grepped; that class is
  **36** members at this task — 8 direct and 28 `// indirect`, counted 2026-09-09 — and the
  gate reports the number it read and the number in each block, so a module added or a module
  promoted both move a number a reader can see. The scope is both require blocks, direct and
  indirect, because a module that arrives indirect today is a module that can be spelled tomorrow.
  After this plan it is 36 still, at 9 direct and 27 indirect. The one promotion this plan makes is `google.golang.org/protobuf`, because Task 5's
  `Call` takes a `proto.Message`; it is in the graph today as `// indirect`, so this is **a `go.mod`
  line and not a fetch** — see *Dependency policy*. Task 2a's per-`GOOS` exclusion adds nothing at
  all: `syscall` is the standard library.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Import `connect/mls` from `sdk/message_group_open.go`. Property 1 must fail.
  2. Import it from a `_test.go` file. Property 1 must **pass** — a gate that fails here has the
     wrong scope and would convict s1's Task 3.
  3. Import `msgrepo/harness`. Property 2 must fail.
  4. Import an undeclared `github.com/urnetwork/*` path from a production file. Property 3 must fail.
  5. Reach `connect/mls` transitively through `connect/messagegroup` — which is what every task from
     Task 1 does. Property 1 must **PASS**. This is the mutation the first version of this gate got
     backwards: the transitive edge is §2.3's own layering and is required by Wave 1, and a gate that
     fails here is red at baseline, so every other mutation in this set would have run against a red
     gate.
  6. Match the forbidden paths with `strings.Contains` rather than an anchored comparison. Property 1
     must fail, on `connect/mls/syntax` reported as `connect/mls`, so the gate's own matcher is held
     to the distinction the two properties turn on.
  7. Add a module to `sdk/go.mod`'s indirect require block. Property 4 must fail.
  8. Promote a **second** module from indirect to direct. Property 4 must fail on the count that
     moved — one promotion is this plan's whole budget, so the second is the finding.
  9. Import `connect/mls` from a production file **this runner's build context excludes** — on a
     Windows runner, `sdk/message_stream_exclusion_unix.go`, which Task 2a creates and which a
     Windows `go list` never reads. Property 1 must fail, on Windows and on Linux alike. **A gate
     built on `go list -f '{{range .Imports}}'` passes this mutant on Windows and kills it on
     Linux**, which is the build-context filtering the scope above exists to avoid, and this plan
     directs Windows runs.
  10. Read the file set from `go list`'s `GoFiles` rather than from the directory. Property 1 must
     fail on the **second** reported number — files read against files on disk — because `GoFiles`
     is the filtered set and the equality is the whole check.

- [ ] **Step 6: Commit**

---

### Task 14: CI, and the line endings this project has already paid for

**Files:**
- Create: `sdk/.github/workflows/messaging-client.yml`, `sdk/.gitattributes`

**Interfaces:**
- Consumes: every gate Tasks 1–13 produce.
- Produces: no Go declaration.

**`sdk` has no `.github` directory at all.** s1 Task 15 creates the first workflow; whichever of the
two lands first creates it and the other adds a job. This task is written to be inheritable either
way: it declares the jobs, not the file's sole ownership.

**And the `.gitattributes` is not housekeeping.** `core.autocrlf` is true at system scope on the
machines this project is developed on, and this project has already had **84 source anchors pass
vacuously** because a matcher did not strip a carriage return. `sdk` has no `.gitattributes` today.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every gate this plan produces runs in CI**, and the workflow's job list is derived
  from the test files this plan creates rather than typed.
  *Refusal owed:* a red build.
  *Scope to derive, separately from the class (R3):* the class is **the test files this plan's File
  Structure declares**, and that class is **twelve** members at this task — the eleven
  `message_*_test.go` files of Tasks 1–12, including Task 8a's `message_client_test.go` (Task 2a
  extends `message_stream_store_test.go` and adds none), plus Task 13's layering test. The scope is
  the whole `sdk` root module, because a gate that runs only the files this plan names stops covering
  the package the moment another plan adds one.

  **Property 2 — the crash-restart gate runs in CI and its run length is not silently reduced there.**
  Ten thousand allocations with an injected crash is the one gate on this leg with a runtime cost,
  and it is the one that must not be trimmed to keep a build fast.
  *Refusal owed:* the run reports the number of allocations it performed.

  **Property 3 — Go files and module files are `eol=lf`.**
  *Refusal owed:* a failure naming the file.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Remove a test file from the workflow's invocation. Property 1 must fail.
  2. Add a test file the workflow does not run. Property 1 must fail on the derivation.
  3. Reduce the crash-restart run to 100 in CI only. Property 2 must fail, and the reported count is
     what makes it visible.
  4. Commit a Go file with CRLF endings. Property 3 must fail.

- [ ] **Step 6: Commit**

---

### Task 15: The registry entry, and the pending pins that must fail when their producer lands

**Files:**
- Modify: `msgrepo/docs/plans/2026-08-12-slice1-interface-registry.md`

**Interfaces:**
- Consumes: every `Produces` block in this plan.
- Produces: the registry rows for `s2`'s surface, and the pending-pin rows for the eight symbols in
  *Interfaces consumed from other plans*.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every symbol this plan produces has a registry row**, derived from this document's
  `Produces` blocks rather than transcribed.
  *Refusal owed:* a missing row is a finding naming the symbol.
  *Scope to derive, separately from the class (R3):* the class is **the `Produces` blocks of
  Tasks 1–12 that declare a symbol**, which is where every exported and package-internal declaration
  this plan makes is stated; that class is **thirteen** members at this task — Tasks 1, 2, 2a, 3, 5,
  6, 7, 8, 8a, 9, 10, 11 and 12, i.e. every task from 1 to 12 except Task 4, whose `Produces` block
  deliberately declares nothing. The scope is this document, not the `sdk` tree, because a registry
  that reads the tree records what was built and a registry that reads the plan records what was
  promised, and the gap between them is the finding.

  **Property 2 — every pending pin fails when its producer lands.** A pin that stays green after the
  symbol exists is a stale reference the next reader will trust.
  *Refusal owed:* the gate fails and names the symbol and its producer.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Remove a row for a symbol this plan produces. Property 1 must fail.
  2. Add a row for a symbol no `Produces` block declares. Property 1 must fail in the other
     direction.
  3. Declare a pending-pin symbol in `sdk` and leave the pin. Property 2 must fail.

- [ ] **Step 6: Commit**

---

## Execution order

| Wave | Tasks | Why here |
|---|---|---|
| 1 | 1, 2, 2a, 3, 4 | The durable reserver. Needs nothing — no transport, no s1 symbol, no `GroupHandle`, no new dependency — and gates every seal by construction, because `NewGroupSession` refuses a nil reserver. It should land **first and alone**. Task 1 must be committed **before any row exists on disk**, because the key-space version tag is what makes ledger item 170's hazard unreachable and adding it afterwards is the migration nobody can perform by recomputation. **Task 2a lands with Task 2, not after it**: a store that ships without the exclusion ships the hazard the leg exists to prevent, and a directory that has been allocated against by two openers cannot be repaired by adding a lock later |
| 2 | 5, 6, 7 | The transport. Independent of Wave 1 and buildable in parallel: CP3c already proved this shape end to end over opaque bytes with no key schedule at all |
| 3 | 8, 8a, 9, 10 | The seam and the send path. Task 8 needs neither wave. **Task 8a needs both waves whole and Task 12's `OpenReceiveState`**, which is why the landing order below puts part of Wave 4 in front of it; it constructs the one `GroupSession`, wires Wave 1's reserver to it, and declares the two halves Tasks 9, 10 and 11 write methods on. Tasks 9 and 10 are those methods, and Task 9 needs Task 7's nonce before it can seal anything the server will accept |
| 4 | 11, 12 | The receive path. Task 12's **store** half is a dependency of Task 8a's config and lands before it; Task 12's **call-site** half and the whole of Task 11 are gates over a type Task 8a declares and land after it |
| 5 | 13, 14, 15 | The gates. Task 13 goes as early as it can be made to pass — it is cheap and it is the only thing preventing the forbidden edge — but it is listed here because it is off the CP3b prefix |

**The landing order is not the wave order on this plan, and both are stated because the difference is
where a dispatched task fails to compile:**

```
1, 2, 2a, 3, 4        (wave 1, first and alone)
5, 6, 7               (wave 2, may run in parallel with wave 1)
8                     (needs neither)
12 steps 1-4          (OpenReceiveState, the row, Properties 5, 6, 7)
8a                    (the seam: needs waves 1 and 2 whole, and OpenReceiveState)
9, 10, 11             (methods on the types 8a declares)
12 steps 5-6          (Properties 1-4: the call-site gates over the receiver)
13, 14, 15            (the gates, off the prefix)
```

**Waves 1 and 2 may be worked in parallel by two implementers.** They share no file, no type and no
property. Everything from Task 8a onward is sequential with both. **An implementer dispatched on
Task 9, 10 or 11 before Task 8a has landed cannot compile**, because all three declare methods on a
receiver type Task 8a declares — and an earlier draft of this plan had no task declaring it at all,
which is the defect Task 8a exists to close.

**And one ordering that is invisible in the leg's description:** `group_handle_key[0]` must be
computed and persisted at group creation, **before the group's first commit**. After the group leaves
epoch 0, `mls_secret[0]` is unrecoverable, so the value can never be reconstructed. Task 9 Property 2
holds it.

---

## Definition of done

Complete when all of the following are true, each verified by **running the command**, not by
inspection. Every command runs from the `sdk` checkout with `GOROOT` and `PATH` set as the workspace
requires.

**Preconditions, and all three are unmet as of 2026-09-09 (S2-13):** `../goidenticons` checked out
beside `sdk`; a `beta/message` branch in `sdk`; and a decision on whether Task 14 or s1 Task 15
creates the first workflow. Nothing below can be run until the first is closed.

| Gate | Command | Expected |
|---|---|---|
| The module builds | `go build ./...` | ok |
| Every task's tests pass | `go test . -count=1` | ok |
| Race-clean | `go test . -race -count=1` | ok |
| The reserver never reuses an index | `go test . -run TestStreamIndexNeverReused -v` | PASS, and the run reports the number of allocations and the number of restarts it performed. A run that does not print both has not said whether it tested anything |
| Every derived-class gate reports its class size AND the scope it walked | `go test . -v` | every gate in Tasks 1, 2, 2a, 3, 4, 5, 6, 8, 8a, 10, 11, 12, 13, 14 and 15 prints the number of members it read **and the size of the scope it read them out of**. **A gate that READ NOTHING is broken, not clean** — zero files walked, zero call-graph nodes, zero descriptor fields. A class that is legitimately **empty over a scope the gate did walk** is a different thing and is not broken: Task 10 Property 5's prohibition is empty at its own commit by construction, says so, and relocates its count half to Task 11 Property 1. **The two were one sentence until 2026-09-09, and conflating them is what turns an honest prohibition into a row nothing can satisfy** |
| The single writer holds against a second PROCESS | `go test . -run TestStreamStoreSingleWriter -v` | PASS, and the run reports which of the two paths it exercised. A run that exercised only the in-process path has measured a mutex |
| No `sdk` FILE spells `connect/mls` — **normative row** | `go test . -run TestSdkLayering -v` | PASS, and the run prints **the number of production files it read and the number the directory holds, equal**, plus the three forbidden paths it was given. This is the row, not the `go list` one below it: the gate reads the file set off the directory, unfiltered by a build context |
| The same question asked from a shell, corroboration only | `for goos in windows linux darwin ios android js; do GOOS=$goos go list -f '{{range .Imports}}{{println .}}{{end}}' . ; done \| sort -u \| grep -xE 'github.com/urnetwork/connect/mls(/syntax)?'` | no matches. **Two things are the row.** `-x` and the group: unanchored, `connect/mls` matches `connect/mls/syntax`, and `-deps` in place of `-f` makes it red at baseline — `go list -deps` over the four packages this plan links prints both `mls` paths among 414. And the `GOOS` loop: a single `go list -f` answers for the runner's build context only — measured 2026-09-09, a `windows/amd64` context reads 51 of `sdk`'s 57 root production files, and Task 2a's `message_stream_exclusion_unix.go` is one of the files it cannot see. Even swept, this row misses any file no listed `GOOS` reads, which is why the gate above is the normative one |
| Task 2a's three files compile everywhere the module ships, and REFUSE where they cannot be safe | `for t in windows/amd64 linux/amd64 darwin/arm64 ios/arm64 android/arm64 freebsd/amd64 openbsd/amd64 netbsd/amd64 dragonfly/amd64 illumos/amd64 solaris/amd64 aix/ppc64 js/wasm wasip1/wasm plan9/amd64; do CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build ./... ; done` | exit 0 on **every** one. Measured 2026-09-09 with the `unix` build term in the Unix file, `solaris/amd64` and `aix/ppc64` fail with `undefined: syscall.Flock` — they satisfy `unix` and lack the primitive — so this row is what keeps the fail-closed file a refusal rather than a compile error |
| The transitive edge that IS legal is still there | `go list -deps . \| grep -c 'connect/mls'` | **2**, not 0. `sdk` → `connect/messagegroup` → `connect/mls` and `sdk` → `connect/message` → `connect/mls/syntax` are §2.3's own layering and Wave 1 requires the first. A run that reports 0 here means the reserver is not linked |
| No edge to the message server | `go list -deps -test ./... \| grep message-server` | no matches |
| The require blocks moved by one line and no more | `git diff --stat -- go.mod` | one line, `google.golang.org/protobuf` from indirect to direct |
| Vet and format | `go vet ./... && gofmt -l message*.go` | no output |
| CI is green | the `messaging-client` workflow on the pushed branch | green, and its log shows the crash-restart gate's reported allocation count |
| The plan linter is green in `msgrepo` | `go test ./ -run TestThePlanLinter` | ok |

**The gate that is not a command.** Each task records its mutation results in its commit message: the
mutation number, targeted or full run, killed or survived. A survivor with no recorded reason is an
incomplete task. This project has thirty plan-supplied tests that could not fail; the mutation record
is the only thing that distinguishes a test from a test-shaped object.

**And the claim this Definition of done does NOT authorise — which an earlier draft overstated in a
way its own open items contradict.** Completing every row above does **not** mean CP3b. CP3b needs
S2-1, S2-2, S2-3 and S2-4 closed, and all four are somebody else's commits in `connect`.

**It does not mean a run against a server either, and that is a smaller and more easily missed
claim.** Every row above is a unit invocation. **No row runs against a message server, no task in
this plan stands up a client that could reach one, and S2-7 leaves it unresolved whether CP3b runs
over two loopback clients or two authenticated ones.** S2-1 blocks Tasks 9, 10 and 11 against a real
server independently. So the earlier draft's closing sentence — *"one client, one group, one real
durable record, sealed and submitted and fetched and opened"* — describes an end-to-end run that no
row here performs and no task here builds the fixture for.

**The honest statement at the end of this plan is what its tasks actually produce:** *a durable
stream reserver under a single writer, with a crash-restart gate over the production store; a
message-server binding that speaks the four arms `msgrepo/peer` serves, with fragmentation and a
per-connection nonce; a projection the server's own re-projection would accept; a durable
receive-side head index keyed the way the ratchet is keyed; and one seam that constructs one
`GroupSession`, seals through it and would submit what it sealed — with no run against a server in
any row, and the fixture that would perform one filed as S2-7.*

---

## What this plan does not close

- **CP3b.** Four upstream blockers, S2-1 through S2-4, and none of them is `sdk` work. This is the
  first entry rather than the last because it is the one a reader is most likely to assume away.
- **The surfacing onto `MessageClient`.** Every declaration this plan produces is package-internal or
  is the store type §8.2 names. Turning any of it into a method on s1's `MessageClient` is s1's
  declaration plus a later task, and it is what actually waits for s1.
- **Twelve of §8.2's fourteen methods**, the whole of `StoredEntry`, `Sealer`, §8.3's DPAPI path, and
  the SQLite schema behind them. The record cache (`PutRecords` / `RecordsAfter` / `DeleteRecords`),
  the six entry methods and `Vacuum` are the display layer, not the message path.
- **`Subscribe`, `Unsubscribe`, `RecordPush`, `TransientPush`, `Backpressure`, `Drain`,
  `GroupStatus`, `BlobGrant`, `RecoveryFetch`, `WrapFetch` and the rendezvous arms.** None is
  implemented server-side; the receive path is a poll of Fetch and nothing else.
- **`FetchAttestation` verification, key-transparency gossip, `ServerKey` rotation and fleet-root
  pinning.** Two server-side absences this plan inherits and must not claim around, stated
  about the SERVER rather than about the message, because the two differ and this plan's own repair
  turned on exactly that distinction elsewhere: `protocol.HelloResponse` **declares** `server_keys`
  (field 3) and `kt_gossip` (field 8) and `msgrepo` **populates neither** — `peer/hello.go:68` says
  so in a comment and `peer/peer_test.go:355` pins it as a test — so a client cannot verify a fleet
  key chain against a compiled-in root; and Hello replaces a connection keyed on the source id unconditionally, so unless
  the platform authenticates that identifier a Hello naming another client destroys that client's
  nonce.
- **Every EPH, MEDIA and PERMANENT path**, including M1-25's transient/window interaction.
  `SealRecord` refuses every class but `DURABLE` today, so none of it is reachable and a test
  asserting any of it cannot pass. Note that Spec A §5.3 records M1-6 as lifting the refusal for
  PERMANENT and MEDIA on 2026-09-07 and **the code at `33932e0` still refuses them**, with two tests
  pinning the stale refusal. That divergence is `connect`'s; it becomes this plan's the day §5.11's
  snapshot has to be sealed as a PERMANENT record.
- **A second `connect.Client` for messaging with its own auth.** §9.3's `settings_json` carries no
  `ByJwt` and no device handle, and `sdk`'s only production client is the VPN's. Whether CP3b runs
  over two loopback clients the way `msgrepo`'s own fixture does, or over two authenticated ones, is
  **S2-7**.
- **The reconnect recovery.** Task 7 refuses to submit under a superseded nonce; it does not recover.
  The recovery is a session rebuild whose cost nothing has priced.

---

## Open items

Each is a spec or ownership problem in this plan's area, with what it blocks. **None is resolved
silently.** Where this plan took a position because something had to compile, the position is
labelled as a position and the rejected alternative is named.

**S2-1 — the epoch keys are not reachable from `sdk`, and the only workaround is a second copy of the
one derivation the record layer is proved against.** `GroupSession`'s complete exported method set is
seven methods — `Close`, `Epoch`, `SenderHandle`, `AdvanceEpoch`, `TrackSender`, `SealRecord`,
`OpenRecord` — and none returns `storage_root`, `read_key`, `write_key` or `group_handle_key`. But
leg 4 needs `read_key[e]` for **every** Fetch (§4.3.8 makes `req_auth` REQUIRED and the server refuses
an absent one outright), `write_key[0]` for `CreateGroupRequest.bootstrap_write_key`, and both keys of
epoch *n+1* for the `EpochAttachment` every commit carries. The only derivation runs through
`GroupHandle.Export(<label>, nil, 32)`, and the label and the length are **unexported constants**
inside `messagegroup`. Corroborating evidence that this is a real gap and not a misreading:
`msgrepo/harness`'s `Fetch` takes `readKey []byte` as an explicit parameter *precisely because it has
no session to ask*. Re-measured 2026-09-09 after this plan's review: the `messagegroup/epoch.go` that
was an untracked working-tree file when this plan was written **has since landed**, at `connect`
`7868d65`, and is tracked. It declares a `ProvisionalEpoch` with `StorageRoot()`, `WriteKey()`,
`EphRoot()`, `PqSecret()` and `Wraps()` accessors — but `NewProvisionalEpoch` **takes `storageRoot`
as a constructor parameter**, so it does not derive it either, and it covers the provisional epoch
*n+1* rather than the live one. **The landing does not close this item**, and the plan's earlier
"uncommitted, reported as measured" framing is corrected to "landed, and still not an answer". **And the finding
survives it:** re-measured against that working tree rather than only against the commit,
`grep 'func (self \*GroupSession) [A-Z]'` still returns the same **seven** methods and still returns
no accessor for `readKey`, `writeKey`, `storageRoot` or `groupHandleKey`. This is a gap in the
interface, not an artefact of reading an old commit. *Position taken:* every key crosses this plan's
boundary as an **injected parameter** — `messageClientConfig.StorageRootZero` and
`messageClientConfig.PqSecretZero` at the seam (Task 8a), and `Fetch`'s `readKeyRef`, which carries
the epoch the key is for — so `s2` contains no copy of the label and the gap stays visible at every
call site. The injection point is **one struct** rather than one per task, which is the repair the
review forced: two structs carrying the same injected key are two places to inject it differently. *Rejected:* spelling the
exporter label in `sdk`, which is the §12.1 A-1 defect by construction and defeats the session's own
zeroize discipline. **Blocks:** Tasks 9, 10 and 11 against a real server; CP3b. **Owner:** `connect`,
and nobody has it.

**S2-2 — `server_nonce` is captured once at construction and cannot be rebound, so the first
reconnect invalidates every record sealed after it.** `NewGroupSession` copies the nonce at
construction; there is no setter — a grep over production files finds the field, the parameter, the
emptiness check, the copy and one read in `seal.go`. Meanwhile the server draws a fresh 32-octet nonce
per connection and replaces it at **every** Hello, and CP3c already proves a record sealed under a
superseded nonce is refused. Over a real `connect.Client`, which reconnects, every submit after the
first reconnect is refused. *Position taken:* Task 10 Property 4 refuses locally rather than
submitting to be refused. *Rejected:* rebuilding the `GroupSession` per reconnect inside `s2`, because
that drops every sender and receiver ratchet, re-walks each ladder from the store's high water, is
**refused outright** above `maxLadderWalk` for every class of that sender, and needs `pq_secret` and
`groupHandleKeyEpoch0` back in hand — a cost nothing has priced and neither leg 4 nor leg 5 mentions.
**Blocks:** any session that outlives one connection; CP3b on a real network. **Owner:** `connect`.

**S2-3 — `pq_secret` has a sampler in flight and no delivery channel, and an `s2`-invented value is a
bar violation rather than a shortcut.** `NewGroupSession` refuses an empty `pq_secret` and so does
`AdvanceEpoch`, so `s2` cannot construct a session without one. The X-Wing primitives exist and have
**no production caller**, and the query is published beside the claim: over the non-test production
files of `connect/messagegroup` at `33932e0`, the only file matching
`XwingEncapsulate|XwingDecapsulate` is `xwing.go`, which **declares** them. m1 Task 13 supplies the sampler and **has landed** — `NewPqSecret` is
tracked at `connect` `7868d65`, which corrects this plan's earlier "in the working tree, uncommitted"
reading; m1 Task 14 supplies the device wrap that **delivers** it, has not landed, and is blocked on
ledger item 152 — **and, since 2026-09-09, on nothing else**: the owner ruled `M1-1`'s remainder and
`M1-7` together that day as composite `C3`, so what stands in front of Task 14 is the landed
non-`DURABLE` seal refusal at `seal.go:119`/`:387` and not an unruled field list. Re-measured at `7868d65`: no `wrap*.go` in `messagegroup`, and
`XwingEncapsulate` and `XwingDecapsulate` have no production caller outside `xwing.go`, which
declares them. Until delivery exists, the only thing making two
sessions agree on a storage root is a test constant — which is exactly the *"no test-only key source
anywhere on the path"* the bar forbids. **Blocks:** CP3b, unconditionally, no matter how well `s2` is
built. **Owner:** m1.

**S2-4 — there is no exported path by which two clients share one group.**
`GroupEngine.JoinFromWelcome` is an unconditional refusal on every input, because `connect/mls` keeps
a minted key package's signature private half on an unexported field and `StateStore.TakeKeyPackage`
does not carry it, so no caller outside `package mls` can assemble the join material a Welcome takes.
The only other door to a `GroupHandle` is `CreateGroup`, which makes a group of one. CP3b is *"two
clients, one group"*. The engine's own comment says this blocks m1 Task 16; **it blocks CP3b too**,
which no document says. **Blocks:** CP3b. **Owner:** `connect/mls`, upstream of m1 Task 16.

**S2-5 — M1-5 and ledger item 170 are unruled, and `s2` is the first store that can have rows.**
M1-5 rules which fields a durable store **row** is identified by; A1 ruled which stream a
**reservation** belongs to; the two have been confused once already. Item 170's own proposed ruling
is one sentence in this plan. *Position taken:* Task 1 makes the hazard structurally unreachable with
a versioned key space, so the plan is safe **whichever way M1-5 is ruled** — which is deliberately
stronger than waiting for the ruling, because the property is *"a row this build cannot key is
answered as a silent zero"* and pre-A1 rows are only one instance of it. *Not resolved:* the ruling
itself, which is still owed and still free today. **Blocks:** nothing in this plan; it blocks any
later change to row identity, which after Task 1 ships is a migration nobody can perform by
recomputation.

**S2-6 — the receive-side head-index store has no owner and no spec.** `TrackSender`'s `headIndex` is
documented as the caller's own state that must never be read off a record header, and §8.2's
`MessageStore` declares nothing for the receive side. Leg 5 as stated is only the sender half of the
durability CP3b needs. *Position taken:* Task 12 builds it as `ReceiveState`, separate from
`StreamStore`, because the two have different keys and different failure modes — and, after this
plan's review, keyed by the retention **wire** byte rather than by `message.RetentionClass`, with
Task 1's version-tag mechanism applied to it. What the key must be is **S2-18**. **Blocks:** a
restarted client that must not re-walk from zero. **Owed:** a §8.2 amendment naming it.

**S2-7 — how a client reaches the message server is specified nowhere in this plan's span.** §4.2 says
frames are addressed to the instance's `client_id`; no discovery, no settings field and no directory
lookup is specified. §9.3's `settings_json` carries `storage_dir`, `network_space_host` and
`message_server_id` and deliberately **no** `ByJwt`, while §10.2's own table says contracts need one.
**And the "no precedent" half of this item was wrong and is corrected here rather than left:**
measured 2026-09-09, `sdk` has **two** production `connect.NewClient` sites, not one —
`device_local_provider.go:109` (the VPN device) and `sim_device.go:115`, which is `package sdk` with
no build tag and stands up its own `ApiOutOfBandControl` from `config.ByJwt` and `config.ApiUrl`. So
a standalone authenticated client in this module is not unprecedented; it is unspecified for
messaging. `s2` either stands up a second authenticated client on that pattern or CP3b runs over two
loopback clients the way `msgrepo`'s own fixture does, with no network space and no operator. The
second is far cheaper and is what CP3c actually did. **Not resolved.** **Blocks:** Task 5's
construction on a real network; the end-to-end row the Definition of done deliberately does not
have; not the gates.

**S2-8 — §8.2 declares no length rule for its `[]byte` key, and `messagegroup` panics on one.**
`[32]byte` and `[16]byte` are total; `[]byte` is not, and clause 4 makes an unrecognised key an
**error-free zero** — the same silent-restart shape as item 170. Meanwhile `GroupHandleKey` and
`SenderHandle` **panic** rather than return an error on a wrong width, defended by *"nothing here is
reachable from the network: the key is this member's own persisted derivation"* — an argument that
holds only while the persisted value is trustworthy, and `s2` is the thing that makes it a value read
off a disk. *Position taken:* Tasks 1 and 3 refuse at the boundary with `ErrStreamKeyWidth`. *Not
resolved:* whether §8.2 should declare the refusal, which is a spec edit.

**S2-9 — FOUR wire-shaped values have no shared home and `s2` writes the second or third copy of
each.** The §4.3.3 **projection** exists in `msgrepo/api/submit.go` (server, authoritative) and
`msgrepo/harness/seal.go` (test-only) and **nowhere in `connect`**; §4.6's **part size** exists only
in `msgrepo/peer/frame.go`, the server module; **`maxLadderWalk`** is unexported in `messagegroup`;
and the fourth, which an earlier draft of this item omitted while Task 11 required `s2` to
reimplement it, is the **op-byte derivation**. The authoritative implementation is
`msgrepo/api/api.go:339`, `func opOf(body proto.Message) (uint8, error)`, which walks
`MessageServerRequest`'s fields, filters on `field.ContainingOneof() != nil`, bounds the number to a
`u8` and returns `uint8(field.Number())`. `sdk` cannot import module
`github.com/urnetwork/message-server` (Task 13 Property 2), so Task 11 Property 2 writes a second
one, and this item's own framing applies to it identically. Two readings of the projection are both defensible and this plan does **not** choose
between them: promoting one builder into `connect/message` makes §5.1 check 3 verify that
encode-then-parse round-trips (a real property, differently shaped), while keeping two independent
builders makes it verify that the client's projection agrees with the server's parse (which is what
the check's own comment describes). *Position taken:* write it in `sdk`, because `s2` may not change
`connect` and because extending §12.1 A-1's published surface is `connect`'s decision, not this
plan's. **Blocks:** nothing; it accrues. **Owed:** a ruling on where each of the three lives.

**S2-10 — `maxLadderWalk` is 2^20, unexported, permanent, and shared across classes.** It bounds a
sender's resume (refused, not truncated), an allocated index too far ahead of the ladder (which
**wedges** the ratchet permanently), and a receiver's `headIndex`. A stream that has genuinely passed
~1.05 million records cannot be resumed at all, and under A1's shared counter every EPH bucket-0
transient of that sender spends the same budget — so the transient send rate is also the wall's
approach rate. **The store must not be designed as if `u64` were the budget.** A real ceiling is
deferred to M1-12. **Blocks:** nothing today; it is a design constraint on Tasks 2 and 12 and it is
why both name it.

**S2-11 — A8's `modernc.org/sqlite` is called CONFIRMED on a gate that cannot have run.** §11.4 cites
a gomobile `android/arm` CI gate as settling it; `sdk` has no `.github` directory, so no such gate has
ever run, and the module is not in the module cache. *Position taken:* keep it off the CP3b prefix
entirely; the reserver needs an fsync, not a query planner, and §8.1's own table exempts the stream
rows from encryption so the CP3b half needs no `Sealer` either. *Not resolved:* whether SQLite is the
right answer for the entry and search store, which is a separate and larger decision. **Blocks:**
nothing here.

**S2-12 — `MessageStore` cannot be declared, and this plan declines to declare a partial one.**
`StoredEntry` is named in four of §8.2's fourteen methods and has **no field declared in any
document** (s1's S1-9). A8 makes the fourteen-method bound the point of the interface, so a partial
declaration under that name is a divergence rather than a subset. *Position taken:* declare the
concrete `StreamStore` with the two stream methods spelled exactly as §8.2 spells them, and no
interface. *Rejected:* declaring a ten-method `MessageStore`. **Blocks:** nothing in this plan.
**Owed:** `StoredEntry`, and then whoever assembles the interface.

**S2-13 — `sdk` has no `beta/message` branch, does not build, and has no CI.** All three measured
2026-09-09; the first was recorded by s1 on 2026-08-30 as *"currently unmet"* and is still unmet.
**Blocks:** every task in this plan, at step 2 of task 1.

**S2-14 — `mls.StateStore` has eight methods and zero production implementations in any tree.** The
only two are in-memory maps in `_test.go` files. §8.1 lists `mls_state`, `mls_private` and
`mls_keypackage` as SQLite tables and §8.2's fourteen methods declare none of them, so this is either
a fifteenth-through-twenty-second method or a second, unnamed interface. It also holds a plaintext
epoch secret and a leaf private key that the group erases the instant `PutGroupState` returns.
**Not `s2`'s**, because Gate 5 keeps `s2` out of `connect/mls` entirely. **Blocks:** any group two
real clients can both open across a process boundary. **Owner:** s5, or unassigned.

**S2-15 — three documents state §8.2's correspondence three different ways, and one of them is the
source comment.** `connect/messagegroup/streamindex.go` quotes the **pre-A1** §8.2; Spec A §8.2 today
carries the amended pair and says explicitly that *"the flattening from these two `[]byte` parameters
to its comparable `StreamKey` is the implementer's"*; and the m1 plan says the correspondence *"is now
parameter for parameter too"*, which is not true of either. Reading the source comment as normative
here produces the **assert** shape, which `streamindex.go` itself says wedges permanently under A1.
*Resolved by measurement rather than by ruling:* Spec A §8.2 is current and correct, an adapter is
mandatory, and Task 3 is it. **Owed:** a one-line correction to the `connect` comment and to the m1
sentence, neither of which this plan may make.

---

**S2-16 — Windows cannot force the durability of a directory entry, so the FIRST allocation against a
never-before-seen stream has a crash window no user-space code closes.** Measured 2026-09-09 on this
machine with the project toolchain: `os.Open(dir)` and `os.OpenFile(dir, os.O_RDONLY, 0)` both
succeed and both give a handle whose `Sync()` returns `Access is denied.` The only other lever,
`FlushFileBuffers` on a volume handle, needs administrator privilege and flushes the whole volume,
which a client SDK may not do. *Position taken:* Task 2 removes every directory-entry mutation from
the allocation path, so the one durability boundary there is a file-contents flush, which
`os.File.Sync` forces on every platform; a row's directory entry is established when the store first
touches the key, **before any index for it has been handed out**. *What that leaves:* if a crash
loses that entry after indices were served under it, the next open sees no row, answers `HighWater`
0 and re-allocates from 1 — the item-170 shape, reached through the filesystem rather than through a
key derivation. On NTFS the entry is metadata-journaled and lands within seconds, which is a strong
practical argument and **not a guarantee**, and this plan does not claim it as one. *Rejected:*
declaring the store Windows-unsafe, which would make CP3b unreachable on the platform the plan is
written for; and requiring the caller to pre-create every row, which needs a key set nobody has at
open time. **Blocks:** nothing in this plan; it is the residual under Task 2 Property 1 and the one
durability claim `s2` cannot make. **Owed:** a ruling on whether the SDK may hold an
already-fsynced spare row per group, which trades disk for the window.

**S2-17 — §8.2 says nothing about concurrent openers, and a `StreamIndexReserver`'s five contract
clauses say nothing either.** Clause 1 is about a process death, clause 3 about the life of the
stream and every restart; neither is about two live allocators. `streamindex.go` gets close — it
rejects the session-owns-the-counter shape partly because *"a read, then a caller's decision, then a
write with an fsync in it is a window that an allocation done in one statement does not have"* — but
it states no exclusion and §8.2 declares none. *Position taken:* Task 2a holds the exclusion in the
operating system, per `GOOS`, with a fail-closed fallback, and a second opener is refused rather than
queued. *Not resolved:* whether §8.2 should declare a sixth contract clause, and whether the
exclusion is per **directory** (this plan's choice) or per **stream** (which would let two processes
share one store and is a larger design). **Blocks:** nothing in this plan. **Owed:** a §8.2 amendment,
or a written statement that the exclusion is the implementer's.

**S2-18 — nothing rules what field set a RECEIVE-side row is keyed by, and the two candidates differ
by six.** M1-5 rules the send-side row; §8.2 declares nothing for the receive side at all (S2-6). The
ratchet the row feeds is keyed by `ReceiverRatchetKey{SenderHandle, RetentionWire}`, and
`RetentionEph` is one class value spanning six buckets — so a row keyed by `message.RetentionClass`
collapses all six EPH buckets of one sender onto one head index, which is ledger item **170**'s
defect class reproduced on the side where a wrong answer is silent message loss rather than a server
refusal. *Position taken:* Task 12 keys by the retention **wire** byte, derived through
`message.RetentionClassWire` and never by a second copy of the join, because that is the key the
consumer of the row already uses. *Not resolved:* whether §8.2 should declare the receive-side row at
all, and whether a future transient counter (item 152, M1-25) would re-key it again — which is the
same question M1-5 asks on the send side and has the same answer shape: a versioned key space, which
Task 12 Property 7 now carries. **Blocks:** nothing in this plan. **Owed:** a §8.2 amendment and a
ruling alongside M1-5.

**S2-19 — no document says which object owns the `GroupSession`, the transport and the two stores,
and the first draft of this plan therefore owned them nowhere.** §8.2 declares a store, §10 declares
a transport, and `messagegroup` declares a session; nothing declares the thing that holds all three,
and s1's `MessageClient` — the natural owner — is written and unexecuted. *Position taken:* Task 8a
declares a package-internal `messageClient` with `messageSender` and `messageReceiver` halves, so the
seam exists and is gated, and the **surfacing** onto `MessageClient` stays s1's declaration to make.
*Rejected:* declaring a partial `MessageClient` here, for the same reason S2-12 declines to declare a
partial `MessageStore`. **Blocks:** nothing in this plan; it is why the plan produces no exported
messaging surface. **Owed:** s1's `MessageClient`, and then one task that is not in this plan.

**S2-20 — the fail-closed exclusion file's real constituency includes `js/wasm`, a target this module
already builds for, and `solaris`/`aix`, where the `unix` build term does not compile at all.**
Compile-probed 2026-09-09 with the project toolchain, `CGO_ENABLED=0`, over the three-file split
exactly as Task 2a's Files block names it: `syscall.Flock` is declared on linux, darwin, ios,
android, freebsd, openbsd, netbsd, dragonfly and illumos, and **not** on solaris, aix, js/wasm,
wasip1/wasm or plan9 — while `go/build`'s `unix` term **includes solaris and aix**, so a Unix file
constrained with `unix` fails to build on both with `undefined: syscall.Flock`. *Position taken:*
Task 2a constrains the Unix file by **the `GOOS` set on which the primitive is declared**, not by the
`unix` term, and the Definition of done carries a cross-compile row so the distinction is a command
rather than a comment. *What that leaves, priced rather than absorbed:* the fallback's real
constituency is js/wasm, wasip1/wasm, plan9, solaris and aix, and **js/wasm is a target the root
`sdk` module already builds for** — measured over its 57 root production files,
`device_rpc_platform_js.go` carries `//go:build js` and `device_rpc_platform_native.go` carries
`//go:build !js`. So the wasm artifact gets a store that refuses to open, and `NewGroupSession`
refuses a nil reserver, so it gets no messaging. *Not resolved:* whether messaging is in scope for
the wasm artifact at all, and if it is, what its single-writer story is — a browser tab has neither
`Flock` nor `CreateFile` and the answer is probably not a file at all. **Blocks:** nothing in this
plan; the refusal is correct and this item is the thing it costs. **Owed:** a ruling from whoever
owns the `js` target.

**S2-21 — nothing rules whether the two durable stores may share a directory, or whose exclusion
covers which.** Task 12's `Consumes` block takes *"Task 2a's exclusion"* without saying whether
`OpenReceiveState` acquires its own over its own directory or shares the one `OpenStreamStore`
holds; Task 8a's config carries `Streams` and `Receive` as two separate injected values and says
nothing about their `dir`s; §8.2 declares the receive-side store not at all (S2-6). Both readings
have a failure mode: two stores over one directory collide on the row directory and on the guard,
and two exclusions over two directories leave a caller free to point them at the same one anyway.
*Position taken:* each store creates its own two-level layout — a row directory holding rows and
nothing else, and a guard entry beside it — so that whichever way this is ruled, a shared directory
is **refused at open** by the other store's exclusion rather than silently interleaved. *Not
resolved:* whether the two `dir`s must be distinct, and whether that is a precondition the
constructor checks or a caller's obligation. **Blocks:** nothing in this plan. **Owed:** a ruling
alongside S2-6's §8.2 amendment.

**S2-22 — the torn-tail discard rule's bound is derived from a write discipline no document states
as a contract.** Task 1 Property 4 separates a torn **tail** from a corrupt **body** by size and
position: a failing suffix no larger than one record plus a partial, with no verifying record after
it, is an interrupted append and is discarded; anything larger is corruption. That bound is correct
**because the allocation path appends one record and flushes** — one record is the most that can be
un-flushed when a process dies. Nothing declares that as a contract: not §8.2, not
`streamindex.go`'s five clauses, not this plan outside Task 2's own prose. A later change that
batched two allocations into one flush would invalidate the discriminator **without touching a line
of Task 1 Property 4**, and the failure mode is a two-record loss read as a torn tail and silently
discarded — a high water below what was handed out, which is the item-170 shape reached through the
row format instead of through the key derivation. *Position taken:* Task 1 Property 4 states the
derivation beside the rule so the coupling is visible, and Task 2's implementation comment must carry
it. *Not resolved:* whether the one-record-per-flush discipline belongs in §8.2 as a sixth contract
clause, beside the concurrent-opener clause S2-17 asks for. **Blocks:** nothing today. **Owed:** a
§8.2 amendment, or a written statement that the row format's integrity rule is the implementer's.

**S2-23 — a truncation that removes whole flushed records is undetectable, and it rewinds the high
water silently.** This is the residual of Task 1 Property 4's ruling that a truncated row and an
interrupted append are the same bytes, and it is filed rather than closed because the ruling is
correct and the cost is real. Within one process lifetime Task 2 Property 2's `ErrStreamStoreRewound`
catches it: the store has handed out an index and the persisted state is behind it. **Across a
restart there is nothing left to compare against** — the row *is* the persisted state, and a shorter
row is indistinguishable from a row that was never longer. Detecting it needs a length authority
outside the appended data, which is a record count in a header or a second file, and either one puts
a **second durable object** on the allocation path — exactly the boundary Task 2 Property 1 measures
at **one**, and the one whose durability S2-16 says this platform will not force for a directory
entry. *Position taken:* the store does not pretend to detect it, and Task 1 mutation 11 makes a
store that tries **red**, because a store that refuses a truncated row also refuses every ordinary
crash mid-append and wedges permanently. *Not resolved:* whether the row should carry a monotone
per-record sequence number, which would not close this (the surviving prefix is identical under it
too) but would make an out-of-order splice detectable, and whether that is worth a widened record.
**Blocks:** nothing. **Owed:** a sentence in §8.2 stating that the row format detects a torn tail and
not a truncated history, beside the one S2-22 asks for.

## Open asks on other plans

- **To `connect`, unowned:** a reachable `read_key[e]` and `write_key[e]` for a live `GroupSession`,
  or an agreed alternative (S2-1). Without it leg 4's fetch half is unwritable except by copying the
  exporter label into `sdk`.
- **To `connect`, unowned:** a `server_nonce` rebind on a live session, or a written statement that
  the rebuild is the answer together with its measured cost (S2-2).
- **To m1:** Task 14's device wrap, which is the delivery channel for `pq_secret` (S2-3); and a note
  in m1's own leg-4 and leg-5 text that the epoch fan-out is part of leg 4, because today the
  one-sentence description hides it.
- **To `connect/mls`, upstream of m1 Task 16:** publish the joiner's signature private key so
  `JoinFromWelcome` can work (S2-4).
- **To the owner:** rule M1-5 and ledger item 170 (S2-5); rule where the projection, the §4.6 part
  size, `maxLadderWalk` and the op-byte derivation live (S2-9); rule whether CP3b runs over two
  loopback clients or two authenticated ones (S2-7); and rule the receive-side row's key alongside
  M1-5 (S2-18).
- **To whoever owns §8.2:** declare the single-writer exclusion, or state that it is the
  implementer's (S2-17); and declare the receive-side store, which §8.2 does not mention at all
  (S2-6, S2-18).
- **To nobody, and it stays open:** the Windows directory-entry window under a store's first
  allocation for a stream (S2-16). It is named here because a plan that did not name it would have
  been read as having closed it.
- **To s1:** nothing blocking. S1-9 blocks the four `StoredEntry` methods and not this plan's prefix,
  and that is the scheduling fact this document most wants read.
