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

### The four rules this plan is written under

These come from this project's own ledger and from the nine plans before it. They are stated first
because they change how every task below is meant to be read.

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

**Tasks 1–12 are the CP3b prefix. Tasks 13–15 are not.** The prefix is not a guess about effort; it
is the set of things without which the run cannot happen at all.

- **Tasks 1–4** — without a durable reserver, `NewGroupSession` will not construct: it refuses a nil
  one. A run over m1 Task 6's test fake proves the record layer and not the client. §5.6's reasoning
  is that a reused `stream_index` is a reused nonce under a reused `record_key`, *"a total break of
  both AEADs for that record"*.
- **Tasks 5–7** — without the binding there is no way to reach the server, and without Hello there
  is no `server_nonce`, so there is no `write_auth` and no `req_auth`.
- **Tasks 8–10** — without the projection every submit is refused by §5.1 check 3; without the
  group-opening ceremony every ordinary submit is refused with `REASON_EPOCH_INCOMPLETE`.
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

- **Transport — true of the VPN, not of messaging.** There is exactly one production `connect.Client`
  in `sdk`, constructed in `device_local_provider.go` and owned by `deviceLocalProvider`, i.e. by the
  VPN device. There is no request/response correlator, no fragmenter, and no message-server binding
  of any kind. `grep -ril 'urmessage|messagegroup|MessageStore'` over `sdk` returns **zero files**.
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

- **New dependencies in the root `sdk` module: none.** Everything Tasks 1–15 need is the standard
  library plus `github.com/urnetwork/connect`, already replaced to `../connect`.
- **`modernc.org/sqlite` is deliberately kept OFF the CP3b prefix**, and this is a position rather
  than an omission. Spec A A8 / A-ASSUME-1 calls it *"CONFIRMED, not an assumption"* and cites a
  gomobile `android/arm` CI gate as having settled it. Measured 2026-09-09: the module is **not in
  the module cache**, so adopting it is a network fetch of a large transitive tree into the one
  module that feeds the AAR, the Apple framework and the DLL — and `sdk` has **no `.github`
  directory**, so the gate said to have settled it **cannot have run**. The reserver needs an fsync,
  not a query planner: one row per `StreamKey`, written and flushed and renamed. §8.1's own table
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
| a `pq_secret` DELIVERY channel (the device wrap) | m1 Task 14 | Task 9 | **blocked** on M1-1's remainder and ledger item 152. The sampler is m1 Task 13 and was in flight, uncommitted, in the `connect` working tree on 2026-09-09. **S2-3** |
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

func newMessageTransport(config *messageTransportConfig) (*messageTransport, error)
func (self *messageTransport) Close()
func (self *messageTransport) Call(ctx context.Context, body proto.Message) (*protocol.MessageServerResponse, error)
func (self *messageTransport) Hello(ctx context.Context, versions ...uint32) (protocol.Reason, *protocol.HelloResponse, error)
func (self *messageTransport) Nonce() []byte
func (self *messageTransport) Capabilities() *protocol.Capabilities
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
func (self *messageSender) SubmitRecord(ctx context.Context, record *message.Record,
    attachment *message.ServerAttachment) (*protocol.SubmitResult, error)
```

```go
// sdk/message_fetch.go and sdk/message_receive_state.go — the receive path and
// the second durable store nobody had been given: the per-peer head index that
// TrackSender takes and that a record header must never supply.
func (self *messageReceiver) Fetch(ctx context.Context, request *protocol.FetchRequest,
    readKey []byte) (*protocol.FetchResponse, error)

type ReceiveState struct{ /* unexported */ }

func OpenReceiveState(dir string) (*ReceiveState, error)
func (self *ReceiveState) HeadIndex(groupId []byte, leaf uint32, class message.RetentionClass) (uint64, error)
func (self *ReceiveState) AdvanceHeadIndex(groupId []byte, leaf uint32, class message.RetentionClass, index uint64) error
func (self *ReceiveState) Close() error
```

---

## File Structure

Every file created or modified by this plan, and its single responsibility.

| File | Responsibility |
|---|---|
| `sdk/message.go` | Package-level doc for the messaging client; the R2 statement, in the source, that every signature on this leg is read from the file that declares it — and the three-way divergence S2-15 records |
| `sdk/message_stream_store.go` | `StreamStore`: the on-disk row, the key-space version tag, the width refusals, `OpenStreamStore`, `Close`, `ReserveStreamIndex`, `StreamHighWater`, and the fsync boundary |
| `sdk/message_stream_adapter.go` | The `StreamKey` flattening and the sentinel mapping, in exactly one place |
| `sdk/message_errors.go` | The typed refusals this plan owns, each usable with `errors.Is` |
| `sdk/message_transport.go` | The `connect.Client` binding: frame build, `AddReceiveCallback` demux, `request_id` correlation, timeouts, counters |
| `sdk/message_transport_fragment.go` | §4.6 fragmentation and reassembly, both directions, and the one home for the part-size bound |
| `sdk/message_transport_hello.go` | Hello, the per-connection `server_nonce`, and the `Capabilities` cache |
| `sdk/message_projection.go` | The `*message.Record` → `*protocol.Record` projection |
| `sdk/message_group_open.go` | The ceremony: `CreateGroupRequest`, the `EpochAttachment`, the wraps, the `EpochComplete` marker |
| `sdk/message_send.go` | Seal → project → `SubmitRequest` → `SubmitResult` disposition |
| `sdk/message_fetch.go` | `FetchRequest` with `read_epoch` and `req_auth`, and `ParseRecord` on the way back |
| `sdk/message_receive_state.go` | `ReceiveState`, the durable per-peer head index, and the `sender_handle` → leaf map |
| `sdk/message_stream_store_test.go` | Tasks 1, 2 and 4's gates, including the crash-restart harness |
| `sdk/message_stream_adapter_test.go` | Task 3's gates |
| `sdk/message_transport_test.go`, `sdk/message_transport_fragment_test.go`, `sdk/message_transport_hello_test.go` | Tasks 5, 6 and 7's gates |
| `sdk/message_projection_test.go` | Task 8's descriptor-derived gate |
| `sdk/message_group_open_test.go`, `sdk/message_send_test.go` | Tasks 9 and 10's gates |
| `sdk/message_fetch_test.go`, `sdk/message_receive_state_test.go` | Tasks 11 and 12's gates |
| `sdk/message_layering_test.go` | Task 13: the production dependency set of `sdk`, and the two edges it must not contain |
| `sdk/.github/workflows/messaging-client.yml` | Task 14. The repository has **no** `.github` directory today |
| `sdk/.gitattributes` | Task 14: `eol=lf` for Go and module files. `sdk` has none, and this project has already lost 84 source anchors to a carriage return |
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
  *Refusal owed:* `ErrStreamKeySpace`, a typed fatal error per §5.9 G7 — never a bool, never a log
  line, and specifically **never `(0, nil)`**, which is the answer contract clause 4 gives an unseen
  stream and which is exactly what makes item 170's hazard silent.

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

  **Property 4 — a present-but-unreadable row is an error, and it is a DIFFERENT error from an absent
  one.** Clause 4's error-free zero is correct for a stream never seen and catastrophic for a stream
  whose row cannot be read, and the two are one `os.IsNotExist` apart.
  *Refusal owed:* `ErrStreamStoreState` for a row that exists and does not parse; `(0, nil)` only for
  a row that is genuinely absent.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**

  `sdk/message.go` carries the package doc and, **in the source rather than only in this plan**, the
  R2 statement and the three-way §8.2 divergence of **S2-15**, so the next reader finds it before
  writing a call rather than after.

  The row is one file per `StreamKey` under `dir`, named by the derived identity plus the version
  tag. One file per key rather than one file for all keys is not a performance choice: it makes the
  fsync of Task 2 a single-file fsync with no read-modify-write window, and it makes a corrupt row
  cost one stream instead of every stream.

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
  7. Truncate a row file to half its length. Property 4 must fail with `ErrStreamStoreState` and
     must **not** answer zero.
  8. Return `(0, nil)` for a row whose file exists but cannot be parsed. Property 4 must fail.

- [ ] **Step 6: Commit**

---

### Task 2: `Reserve`, `HighWater`, the fsync boundary, and the two sentinels

**Files:**
- Modify: `sdk/message_stream_store.go`, `sdk/message_errors.go`
- Test: `sdk/message_stream_store_test.go`

**Interfaces:**
- Consumes: Task 1's `StreamStore`, its row identity and its four refusals.
- Produces:
```go
// §8.2's two stream methods, spelled as §8.2 spells them. ALLOCATION, not
// assertion: Reserve takes no index and returns one.
func (self *StreamStore) ReserveStreamIndex(groupId, senderHandle []byte) (uint64, error)
func (self *StreamStore) StreamHighWater(groupId, senderHandle []byte) (uint64, error)
```

**This task implements m1 Task 6's five clauses and states no new ones.** m1 Task 6 declares the
contract and holds a file-backed fake to it; what a *durable production* implementation owes beyond
what an interface can state is the fsync boundary and the crash window, and those are Properties 1
and 2 below. The other three are m1 Task 6's, restated only because a mutation set needs a subject.

**The fsync obligation, and why "durable" here is not the retention class.** Clause 1 is *"`Reserve`
returns only after the reservation SURVIVES A PROCESS DEATH. Not after the write is issued, not after
it is buffered: after it is durable."* In this tree that means: write the new high water to a
temporary file in the same directory, `Sync()` **the file**, rename it over the row, and `Sync()`
**the directory** — a rename is not durable until the directory entry is. `sdk` has no precedent for
any of this; its entire storage is `os.WriteFile` with no flush anywhere in production code.

**And the crash-recovery rule, stated as a rule rather than as a procedure.** On open, the store
answers `StreamHighWater` from **persisted state only**, never from a recomputed value and never from
anything a ratchet remembers. `NewSenderRatchet` reads `HighWater` in its **constructor** and walks
`highWater + 1` rungs, so a store that answered a recomputed number would place a live ladder under a
counter nothing has recorded. A crash between `Reserve` returning and the record reaching the wire
leaves a **gap**, and a gap is legal: the server enforces monotonicity, **not contiguity**, precisely
so a refused write or a crash between reserve and send is not a permanent wedge.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `Reserve` returns only after the reservation survives a process death.** The test
  needs an **injected failure point between the write and the flush**, not a `time.Sleep`: the
  observable difference between a durable and a buffered write is only visible if the process can be
  stopped between them.
  *Refusal owed:* a flush error is returned, never swallowed. A `Reserve` that returns `(n, nil)`
  after a failed flush has handed out an index it cannot prove it recorded.
  *Scope to derive, separately from the class (R3):* the class is **every durable write on the
  allocation path**, and that class is **two** members at this task — the row file's contents and the
  directory entry the rename creates — with the gate reporting the number of syncs it observed. The
  scope is the whole allocation path, not the row write alone. A gate that syncs the file and not the
  directory passes on a filesystem that happens to order them and fails on one that does not, which
  is a gate that measures the filesystem rather than the store.

  **Property 2 — `StreamHighWater` is answered from persisted state and never rewinds.** After a
  restart it is at least what it was, for every key, under every interleaving the test can produce.
  *Refusal owed:* `ErrStreamIndexRewound`, matched by `errors.Is`, when the persisted state is behind
  an index already handed out.

  **Property 3 — no index is ever handed out twice, for the life of the stream and across every
  restart.** Under the allocation shape the caller has nothing to repeat, so the obligation lands on
  the counter.
  *Refusal owed:* `ErrStreamIndexConsumed`, matched by `errors.Is`, for the store's **permanent**
  refusal to allocate — the next position is one it has already handed out and it has no way past it.
  A typed fatal error per §5.9 G7, never a bool and never a log line. The mapping onto that sentinel
  is Task 3's; this task owes the condition.

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
  2. Sync the row file and not the directory. Property 1 must fail on its **scope**, not on its
     class.
  3. Swallow the flush error and return `nil`. Property 1 must fail.
  4. Answer `StreamHighWater` from an in-memory cache that survives the injected crash. Property 2
     must fail — the cache is exactly the recomputed value the rule forbids.
  5. Resume at `HighWater()` rather than `HighWater() + 1`. Property 2 must fail, and note that this
     mutation is invisible without the restart.
  6. Let a rewound persisted state answer normally. Property 2 must fail with
     `ErrStreamIndexRewound`.
  7. Return a bare filesystem error where the store is permanently unable to allocate. Property 3
     must fail: `errors.Is(err, ErrStreamIndexConsumed)` must find the sentinel.
  8. Return `ErrStreamStoreState` for a stream never seen. Property 4 must fail.
  9. Make `Reserve` answer the same index twice for the same key. Property 3 and Property 5 must
     both fail.

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

  **Property 1 — the adapter is the only flattening in `sdk`.** Anything else that converts between a
  `StreamKey` and a `(groupId, senderHandle)` pair is a second implementation of one mapping, which
  is the §12.1 A-1 shape.
  *Refusal owed:* none — this is a gate, and its finding is a call site.
  *Scope to derive, separately from the class (R3):* the class is **every production function in
  `sdk` that reads both `StreamKey.GroupId` and `StreamKey.SenderHandle`**, read off the syntax tree
  rather than off a file name; the scope is **the whole of `package sdk`'s production files**, not
  the two files this task creates. That class is **one** member at this task, and the gate must
  report the number it read, because a derived-class gate that fatals on an empty class and a gate
  that passes vacuously over one look identical in a log that prints neither.

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
- Consumes: Tasks 1, 2 and 3's whole surface.
- Produces: no declaration. This task produces the one **named** test on this leg. §5.9 G5 and G11
  name it, which is why it is spelled here at all — R1 forbids naming a test, and a test the spec
  names by name is the stated exception rather than a lapse.

**§5.6 states its shape and this task does not invent one:** *"runs 10,000 seal operations with an
injected crash after `Reserve` and before the AEAD, restarts the session from the persisted state,
and asserts no `index` is ever produced twice."*

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
  *Scope to derive, separately from the class (R3):* the class is **every reserver a `GroupSession`
  in `package sdk` can be constructed with**, and that class is **one** member at this task — the
  type Task 2 produces, reached through Task 3's constructor. The scope is the construction path, not
  the test file: the store must be obtained the way the production caller obtains it, never as a
  struct literal assembled in the test. A gate that constructs the store differently from the
  production caller is testing a configuration nothing ships.

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
  *Scope to derive, separately from the class (R3):* the class is **every integer literal in
  `package sdk`'s production files that equals the part size**, read off the syntax tree; the scope
  is the whole package, not this file. That class is one member at this task, and the gate reports
  the number it read. A gate scoped to this file passes on the day somebody writes the number into
  the send path, which is exactly the divergence the property exists to prevent.

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
  6. Enforce a stale `Capabilities` after a `CapabilityChange`. Property 3 must fail.
  7. Use a part budget for Hello that differs from Task 6's constant. Property 4 must fail, and
     Task 6 Property 3 must fail with it.

- [ ] **Step 6: Commit**

---

## Wave 3 — the send path (Tasks 8–10)

**This wave is where the upstream blockers bite.** Tasks 9 and 10 cannot be completed against a real
server without a reachable `write_key[0]` and the epoch keys (**S2-1**). They are written so that the
half that does not need them — the projection, the ordering, the result disposition — lands and is
gated now, and the key access is a single injected parameter rather than a re-derivation scattered
through the path.

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

- **`retention_class` carries the WIRE byte, not the enum value.** The server projects
  `uint32(RetentionClassWire(header.RetentionClass, header.EphBucket))`. A client that writes
  `uint32(header.RetentionClass)` agrees for `DURABLE` **by coincidence** and diverges for every
  other class. `RetentionClassWire` is the one place the class and the bucket join, and a second copy
  of that join is the §12.1 A-1 divergence.
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
  5. Write `uint32(header.RetentionClass)` into `retention_class`. Property 2 must fail. A suite that
     only exercises `DURABLE` will not see it, so the gate must cover the class ladder even though
     `SealRecord` refuses the rest.
  6. Re-implement the class-and-bucket join locally. Property 2 must fail on the second
     implementation, not on the answer.
  7. Populate `record_id` with the record's own field. Property 4 must fail.
  8. Project from the header before `SealRecord` set `stream_index`. Property 3 must fail.

- [ ] **Step 6: Commit**

---

### Task 9: The group-opening ceremony the server's epoch gate requires

**Files:**
- Create: `sdk/message_group_open.go`
- Test: `sdk/message_group_open_test.go`

**Interfaces:**
- Consumes: Task 5's `messageTransport.Call`, Task 7's `Nonce`, Task 8's `recordProjection`;
  `messagegroup.GroupSession.SealRecord`, `messagegroup.GroupHandleKey`,
  `messagegroup.StorageRoot`, `messagegroup.WrapTargetHandle`, `message.WriteKey`,
  `message.ReadKey`, `message.EpochAttachment`, `message.WrapTag`, `message.EpochComplete`;
  `protocol.CreateGroupRequest`. Consumes an **injected** `GroupHandle` — never a constructed one
  (Gate 5).
- Produces:
```go
type groupOpenSpec struct {
    Handle          messagegroup.GroupHandle
    StorageRootZero []byte   // injected; see S2-1
    PqSecretZero    []byte   // injected; see S2-3
    ExpectedWraps   uint32
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
  *Scope to derive, separately from the class (R3):* the class is **every `NewGroupSession` call in
  `package sdk`'s production files**, read off the syntax tree, and the gate requires a non-nil third
  argument at every one. That class is one member at this task, and the gate reports the number it
  read. The scope is the package, not this file, because the second call site is the one that will
  take the convenience.

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

  **Property 4 — every record in the ceremony is sealed by `SealRecord` and none is assembled by
  hand.** Including the initial commit and the marker.
  *Refusal owed:* none; the finding is a `message.Record` literal in production code.

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
  Task 8's `recordProjection`, Task 9's `OpenGroup`; `messagegroup.GroupSession.SealRecord`;
  `protocol.SubmitRequest`, `protocol.SubmitResult`, `protocol.Reason`.
- Produces:
```go
func (self *messageSender) SubmitRecord(ctx context.Context, record *message.Record,
    attachment *message.ServerAttachment) (*protocol.SubmitResult, error)
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
  epoch at seal time is compared with the nonce epoch at submit time.
  *Refusal owed:* a typed refusal naming both epochs, so the caller can tell this from a server
  rejection. This is the local half of **S2-2**; the recovery is not this plan's.

  **Property 5 — `Submit` carries no `req_auth`.**
  *Refusal owed:* none; the finding is a populated field.

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
  7. Populate `req_auth` on `SubmitRequest`. Property 5 must fail.

- [ ] **Step 6: Commit**

---

## Wave 4 — the receive path (Tasks 11–12)

### Task 11: Fetch, `req_auth`, and the op byte that is read rather than written down

**Files:**
- Create: `sdk/message_fetch.go`
- Test: `sdk/message_fetch_test.go`

**Interfaces:**
- Consumes: Task 5's `Call`, Task 7's `Nonce`; `message.ComputeRequestAuth`, `message.ParseRecord`;
  `protocol.FetchRequest`, `protocol.FetchResponse`.
- Produces:
```go
func (self *messageReceiver) Fetch(ctx context.Context, request *protocol.FetchRequest,
    readKey []byte) (*protocol.FetchResponse, error)
```

**The recipe, from §4.3.8 and from `msgrepo/api/fetch.go`'s verifier rather than from memory.**
`req_auth = MAC(read_key[e], "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op) ‖ LP(canonical_request_bytes))`,
where `op` is **the oneof arm's field number** and `canonical_request_bytes` is the protobuf
deterministic marshal of the request body **with its own `req_auth` cleared**. `read_epoch` is inside
those bytes and therefore inside the MAC, which is what makes the server's key selection an
authenticated choice rather than a hint. The server refuses an absent `req_auth` outright, before the
comparison, because the length of a tag is public.

**`readKey` is an explicit parameter, and that is a finding rather than a style choice.**
`msgrepo/harness/client.go`'s own `Fetch` takes `readKey []byte` for exactly this reason: it has no
session to ask. `s2` **will** have a session, and the session will not tell it — `GroupSession` holds
`readKey` privately and exposes none of its seven methods to reach it. Making the parameter explicit
keeps the gap visible at every call site instead of burying a re-derivation inside the fetch path.
**S2-1.**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the MAC is computed over the canonical bytes with `req_auth` cleared, under
  `read_key[read_epoch]`.** A MAC computed over the request as sent, with the field already
  populated, verifies against nothing.
  *Refusal owed:* none locally; the observable failure is `REASON_REJECTED`, which is why the
  property is asserted against `message.ComputeRequestAuth`'s own output and not against a server.

  **Property 2 — the op byte is read off the compiled descriptor, never written down.** It is the
  oneof arm's field number and `connect/protocol` already holds a test that pins the correspondence.
  *Refusal owed:* an error for a body that is not a known arm, never a default of zero.
  *Scope to derive, separately from the class (R3):* the class is **every request body type this
  binding can send**, read off the request message's oneof descriptor rather than listed; that class
  is **four** members at this task — Hello, `CreateGroup`, `Submit` and `Fetch`, which are also the
  only four arms `msgrepo/peer` dispatches — and the gate reports the number it read. The scope is
  the descriptor's whole arm set, because an arm added tomorrow gets an op byte whether or not this
  plan sends it.

  **Property 3 — a `FetchRequest` whose `read_epoch` names an epoch this client cannot key is refused
  locally**, rather than sent to be refused.
  *Refusal owed:* a typed refusal naming the epoch.

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
  7. Send a `read_epoch` naming an epoch this client holds no key for. Property 3 must fail locally,
     and it must fail before the MAC is computed — a MAC under a zero-length key is still a MAC, and
     a path that computes one has turned a missing key into a wire refusal.
  8. Treat `since_record_id` as inclusive. Property 4 must fail with a duplicate.
  9. Page with `since_record_id = last + 1`. Property 4 must fail with a skip — off-by-one in the
     other direction, and it is the one that loses a message rather than repeating one.

- [ ] **Step 6: Commit**

---

### Task 12: `TrackSender`'s head index, and the `sender_handle` → leaf map nothing declares

**Files:**
- Create: `sdk/message_receive_state.go`
- Test: `sdk/message_receive_state_test.go`

**Interfaces:**
- Consumes: Task 11's `Fetch`; `messagegroup.GroupSession.TrackSender`,
  `messagegroup.GroupSession.OpenRecord`, `messagegroup.SenderHandle`,
  `messagegroup.ErrOutOfWindow`, `messagegroup.ErrNoWrap`, `messagegroup.ErrNoReceiverRatchet`;
  `GroupHandle.MemberCount` and `GroupHandle.MemberAt`, off an injected handle.
- Produces:
```go
type ReceiveState struct{ /* unexported */ }

func OpenReceiveState(dir string) (*ReceiveState, error)
func (self *ReceiveState) HeadIndex(groupId []byte, leaf uint32, class message.RetentionClass) (uint64, error)
func (self *ReceiveState) AdvanceHeadIndex(groupId []byte, leaf uint32, class message.RetentionClass, index uint64) error
func (self *ReceiveState) Close() error
```

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
written against the **non-test** dependency set. `s2` is the first plan that would introduce a wrong
**production** edge — to `connect/mls`, or to the message-server module — so the gate belongs with the
plan that could break it, not with the plan that will eventually own the engine factory.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — no production file in `sdk` imports `connect/mls`.** Gate 5 (§4.5) permits exactly
  one such edge and it is s5's engine factory, which this plan does not write.
  *Refusal owed:* a failure naming the importing file and the imported path.
  *Scope to derive, separately from the class (R3):* the class is **the import paths §2.3 and Gate 5
  forbid `sdk`**, which those two rules fix rather than this gate; that class is **two** members at
  this task — `connect/mls` and `github.com/urnetwork/message-server` — and the gate reports the
  number of forbidden paths it was given, because a gate that was given none reports clean over
  everything. The **scope** is the whole **non-test** dependency set — `go list -deps`, never
  `-deps -test` — for the reason S1-13 states: s1's agreement check is a legitimate test-only edge
  and a gate over the test graph convicts it. The scope is every package in that set, transitively,
  and never a list of the ones this plan imports; the gate reports the number of packages it walked,
  and a walk of zero is a broken gate rather than a clean one.

  **Property 2 — `sdk` does not import `github.com/urnetwork/message-server` at all**, in production
  or in test. `msgrepo/harness` is the reference for Tasks 5–11 and is read, never linked; it is also
  gated test-only on its own side, so an import here would fail there.
  *Refusal owed:* a failure naming the path.

  **Property 3 — the production edges this plan DOES create are exactly the ones it declares.**
  `connect`, `connect/message`, `connect/messagegroup`, `connect/protocol`, and the standard library.
  *Refusal owed:* a failure naming an undeclared edge, so a dependency arriving through a transitive
  path is visible on the commit that adds it rather than at the next audit.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Import `connect/mls` from `sdk/message_group_open.go`. Property 1 must fail.
  2. Import it from a `_test.go` file. Property 1 must **pass** — a gate that fails here has the
     wrong scope and would convict s1's Task 3.
  3. Import `msgrepo/harness`. Property 2 must fail.
  4. Add an undeclared third-party dependency. Property 3 must fail.
  5. Reach `connect/mls` transitively through a new package rather than directly. Property 1 must
     still fail — the class is the dependency set, not the import block.

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
  Structure declares**, and that class is **eleven** members at this task — the ten `message_*_test.go`
  files of Tasks 1–12 plus Task 13's layering test. The scope is the whole `sdk` root module, because
  a gate that runs only the files this plan names stops covering the package the moment another plan
  adds one.

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
  this plan makes is stated; that class is **eleven** members at this task — every task from 1 to 12
  except Task 4, whose `Produces` block deliberately declares nothing. The scope is this document,
  not the `sdk` tree, because a registry that reads the tree records what was built and a registry
  that reads the plan records what was promised, and the gap between them is the finding.

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
| 1 | 1, 2, 3, 4 | The durable reserver. Needs nothing — no transport, no s1 symbol, no `GroupHandle`, no new dependency — and gates every seal by construction, because `NewGroupSession` refuses a nil reserver. It should land **first and alone**. Task 1 must be committed **before any row exists on disk**, because the key-space version tag is what makes ledger item 170's hazard unreachable and adding it afterwards is the migration nobody can perform by recomputation |
| 2 | 5, 6, 7 | The transport. Independent of Wave 1 and buildable in parallel: CP3c already proved this shape end to end over opaque bytes with no key schedule at all |
| 3 | 8, 9, 10 | The send path. Task 8 needs neither wave; Tasks 9 and 10 need both, and Task 9 needs Task 7's nonce before it can seal anything the server will accept |
| 4 | 11, 12 | The receive path. Nothing in the send path depends on it, which is why it is last on the prefix |
| 5 | 13, 14, 15 | The gates. Task 13 goes as early as it can be made to pass — it is cheap and it is the only thing preventing the forbidden edge — but it is listed here because it is off the CP3b prefix |

**Waves 1 and 2 may be worked in parallel by two implementers.** They share no file, no type and no
property. Waves 3 and 4 are sequential with each other and with both.

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
| Every derived-class gate reports its class size | `go test . -v` | every gate in Tasks 1, 3, 6, 8, 10, 11, 12, 13 and 15 prints the number of members it read. **A class size of zero is a broken gate, not a clean one** |
| No production edge to `connect/mls` | `go list -deps ./... \| grep connect/mls` | no matches |
| No edge to the message server | `go list -deps -test ./... \| grep message-server` | no matches |
| Vet and format | `go vet ./... && gofmt -l message*.go` | no output |
| CI is green | the `messaging-client` workflow on the pushed branch | green, and its log shows the crash-restart gate's reported allocation count |
| The plan linter is green in `msgrepo` | `go test ./ -run TestThePlanLinter` | ok |

**The gate that is not a command.** Each task records its mutation results in its commit message: the
mutation number, targeted or full run, killed or survived. A survivor with no recorded reason is an
incomplete task. This project has thirty plan-supplied tests that could not fail; the mutation record
is the only thing that distinguishes a test from a test-shaped object.

**And the claim this Definition of done does NOT authorise.** Completing every row above does **not**
mean CP3b. CP3b needs S2-1, S2-2, S2-3 and S2-4 closed, and all four are somebody else's commits in
`connect`. The honest statement at the end of this plan is *"one client, one group, one real durable
record, sealed and submitted and fetched and opened, over a durable reserver"*.

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
  pinning.** Two server-side absences this plan inherits and must not claim around: `HelloResponse`
  carries no `server_keys` and no `kt_gossip`, so a client cannot verify a fleet key chain against a
  compiled-in root; and Hello replaces a connection keyed on the source id unconditionally, so unless
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
no session to ask*. Measured 2026-09-09: an untracked `messagegroup/epoch.go` in the `connect` working
tree declares a `ProvisionalEpoch` with `StorageRoot()`, `WriteKey()` and `PqSecret()` accessors — but
it **takes `storageRoot` as a constructor parameter**, so it does not derive it either, and it covers
the provisional epoch *n+1* rather than the live one. That work was **uncommitted and actively
changing** while this plan was written; it is reported as measured, not as landed. **And the finding
survives it:** re-measured against that working tree rather than only against the commit,
`grep 'func (self \*GroupSession) [A-Z]'` still returns the same **seven** methods and still returns
no accessor for `readKey`, `writeKey`, `storageRoot` or `groupHandleKey`. This is a gap in the
interface, not an artefact of reading an old commit. *Position taken:* every key crosses this plan's
boundary as an **injected parameter** (`groupOpenSpec.StorageRootZero`, `Fetch`'s `readKey`), so `s2`
contains no copy of the label and the gap stays visible at every call site. *Rejected:* spelling the
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
`XwingEncapsulate|XwingDecapsulate` is `xwing.go`, which **declares** them. m1 Task 13 supplies the sampler and was in the `connect`
working tree uncommitted on 2026-09-09; m1 Task 14 supplies the device wrap that **delivers** it and
is blocked on M1-1's remainder and ledger item 152. Until delivery exists, the only thing making two
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
`StreamStore`, because the two have different keys and different failure modes. **Blocks:** a
restarted client that must not re-walk from zero. **Owed:** a §8.2 amendment naming it.

**S2-7 — how a client reaches the message server is specified nowhere in this plan's span.** §4.2 says
frames are addressed to the instance's `client_id`; no discovery, no settings field and no directory
lookup is specified. §9.3's `settings_json` carries `storage_dir`, `network_space_host` and
`message_server_id` and deliberately **no** `ByJwt`, while §10.2's own table says contracts need one —
and `sdk`'s only production `connect.Client` is the VPN's, inside `deviceLocalProvider`. So `s2`
either stands up a second authenticated client or CP3b runs over two loopback clients the way
`msgrepo`'s own fixture does, with no network space and no operator. The second is far cheaper and is
what CP3c actually did. **Not resolved.** **Blocks:** Task 5's construction on a real network; not the
gates.

**S2-8 — §8.2 declares no length rule for its `[]byte` key, and `messagegroup` panics on one.**
`[32]byte` and `[16]byte` are total; `[]byte` is not, and clause 4 makes an unrecognised key an
**error-free zero** — the same silent-restart shape as item 170. Meanwhile `GroupHandleKey` and
`SenderHandle` **panic** rather than return an error on a wrong width, defended by *"nothing here is
reachable from the network: the key is this member's own persisted derivation"* — an argument that
holds only while the persisted value is trustworthy, and `s2` is the thing that makes it a value read
off a disk. *Position taken:* Tasks 1 and 3 refuse at the boundary with `ErrStreamKeyWidth`. *Not
resolved:* whether §8.2 should declare the refusal, which is a spec edit.

**S2-9 — three wire-shaped values have no shared home and `s2` writes the second or third copy of
each.** The §4.3.3 **projection** exists in `msgrepo/api/submit.go` (server, authoritative) and
`msgrepo/harness/seal.go` (test-only) and **nowhere in `connect`**; §4.6's **part size** exists only
in `msgrepo/peer/frame.go`, the server module; and **`maxLadderWalk`** is unexported in
`messagegroup`. Two readings of the projection are both defensible and this plan does **not** choose
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
  size and `maxLadderWalk` live (S2-9); and rule whether CP3b runs over two loopback clients or two
  authenticated ones (S2-7).
- **To s1:** nothing blocking. S1-9 blocks the four `StoredEntry` methods and not this plan's prefix,
  and that is the scheduling fact this document most wants read.
