# [The `sdk` Messaging Surface and Its Shape] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Declare the whole of Spec A §7 — 212 pinned declarations over 1,675 lines — as compiling,
gomobile-legal, ABI-legal Go in `sdk`, in one wave, so that every other plan in slice 2 has a type
graph to compile against. Nothing in this plan sends a message, opens a store, or touches MLS. It
produces the shape that s2 through s10 fill in.

**Architecture:** Three layers, and the split is what makes the wave safe. **Declarations** — value
structs, `*List` wrappers, listener interfaces, the three behavioural handles — live in `package sdk`
and depend on nothing outside it. **The closed vocabularies** live beside them as validated constants
with a classification covering every string field on the surface, so a new reason value is a
compile-and-test event rather than a string somebody typed. **The gates** live in a new nested module
`sdk/surface`, which *loads* `github.com/urnetwork/sdk` with `golang.org/x/tools/go/packages` rather
than importing it, so the exportability walk can exist without `sdk` importing its own subpackage and
without `golang.org/x/tools` entering the root module's dependency graph or the mobile artifacts.

**Tech Stack:** Go 1.26.5, stdlib `testing` + `encoding/json` + `go/ast` + `go/types`;
`golang.org/x/tools/go/packages` confined to the `sdk/surface` module; GitHub Actions.

---

## Global Constraints

### The three rules this plan is written under

These come from this project's own ledger. They are stated first because they change how every task
below is meant to be read.

**R1 — this plan supplies no test code, and neither may a task.** Across p1 to p7 the implementers
found roughly **thirty** plan-supplied tests that could not fail: nine consecutive p1 tasks each
carried one; three `CheckRoundTrip` tests all passed against a version that did the work, evaluated
the comparison, discarded the result and returned `nil`; p6 Task 23's five plan tests **as a set**
could not fail against 16 of 26 mutations. Each task below therefore states **the property**, **the
refusal that property owes**, and **the mutation set the implementer must run**. The implementer
derives the test. A plan that hands over a test hands over the illusion of coverage; a plan that
states a property makes the implementer earn it.

**R2 — signatures are read from source, never from this plan.** Ledger 25: `FindExtension` changed
shape and seven plan call sites still spell the old one; ten references in p7, nine in p5, three each
in the registry and p8, seven of them written against a signature that no longer compiles. Every Go
fragment in this document is **illustrative of shape, not of spelling**. Before writing a call, read
the declaration out of the file that owns it. This applies with particular force to
`connect.CallbackList`, `sdk.Sub`, `sdk.newSub`, `sdk.exportedList`, and everything in
`sdk/cgo/gen/gen.go`, all of which this plan describes and none of which it quotes normatively.

**R3 — every gate derives its class AND its scope.** Ledger 21: five times on this project a gate
derived its class correctly and then wrote its scope down beside it — one file name where the subject
was a package, one root where the table was keyed for two, two error spellings where the package had
five — once inside the very commit fixing the previous instance. The fix for each was a wider
derivation, never a longer list. **Every task below that builds a gate must answer the scope question
separately from the class question, in the gate's own header comment**, and a reviewer must ask them
separately. This plan contains a live example of the failure: the brief that produced it said the
surface carries "16 closed vocabularies", and §9.5 rule 7 names seventeen. Measured against the spec
text, there are at least **eighteen more**. A class typed out rather than derived understates itself.

### Repository, branch, toolchain

- Work happens in `sdk`, branch `beta/message`, cut from `main` (196 tracked files at the time of
  writing). `connect` is on `beta/message`; `msgrepo` is on `main`.
- Go 1.26.5, pinned. `actions/setup-go@v5` with `go-version: '1.26.5'` in every workflow.
- **Environment precondition, verified 2026-08-30 and currently unmet.** The root `sdk` module does
  not build as checked out. `go build ./...` fails with
  `github.com/urnetwork/goidenticons@... (replaced by ../goidenticons): reading ../goidenticons/go.mod:
  The system cannot find the path specified.` `sdk/go.mod` carries
  `replace github.com/urnetwork/goidenticons => ../goidenticons` and that checkout is absent, as is
  any copy in the module cache. **Task 1 does not start until `go build ./...` succeeds in `sdk`.**
  Do not work around it by editing `go.mod`; the replace is load-bearing for the mobile artifacts.
- `connect` and `glog` are present as sibling checkouts and their replaces resolve.
- The `urnetwork-workspace` skill governs how these repos are built and tested together. `./test.sh`
  is zsh and `-timeout 0 -race`; on Windows run `go test` directly and say so in the commit message.

### Dependency policy

- **New dependencies permitted in the root `sdk` module on `beta/message`: none.** Spec A §2.4
  permits `modernc.org/sqlite`, and that is s2's, behind a build tag or subpackage. This plan adds
  nothing to `sdk/go.mod`.
- `golang.org/x/tools` is required by the new `sdk/surface` module and by nothing else. It is already
  at `v0.47.0` in `sdk/cgo/go.mod`; use the same version, so the two walks compile against the same
  `go/packages`.
- `sdk/surface` is a **nested module**, following the `build`, `cgo` and `js` precedent, for the
  reason those three exist: an artifact-adjacent dependency must not enter the graph
  `gomobile bind` resolves. The alternative — a test-only `golang.org/x/tools` in the root `go.mod` —
  was rejected because Go's module graph does not distinguish test-only requirements and the mobile
  builds would resolve it anyway.

### Layering

- Spec A §2.3: `sdk` → `connect/message` → `connect/mls` → `connect/mls/syntax`. `connect/message`
  must never import `sdk`.
- **`sdk` must not import `connect/mls` from any non-test file.** Gate 5 (§4.5) is the whole reason
  the engine seam exists; the single legitimate production edge is s5's `NewConnectMlsEngineFactory`,
  and it is s5's to introduce. This plan creates the **first test-only** edge (Task 3's
  `MessageProtocolLimits` agreement check), which means the eventual `sdk/layering_test.go` must be
  written against the **non-test** dependency set — `go list -deps`, not `go list -deps -test`. That
  is a scope decision, and it is recorded here so it is taken once rather than inferred later. See
  Open item S1-13.
- **`sdk` must not import `sdk/surface`.** `connect/CODESTYLE.md`'s package-layering rule forbids a
  parent importing its own child, and `internal/` does not exempt it — `internal/` controls
  visibility, not direction. The walk therefore lives in the child, *loads* the parent, and the
  child's test may import the parent (child → parent is explicitly allowed).

### House style

`connect/CODESTYLE.md` is the house style for both repos; `sdk` has no copy of its own and follows it
anyway. The rules this plan leans on:

- `self` receivers; `stateLock` for guarded state; explicit struct field names at every
  initialisation; a doc comment on every file, type and function; comments do not repeat the declared
  name.
- Tests are top-level `func TestXxx(t *testing.T)`. Positive tests do **not** use `t.Run`; a
  homogeneous set is a plain table loop reporting with `t.Errorf`. `t.Run` is for the case where the
  subtest boundary itself is the point — a subtest deliberately expected to fail, captured by its
  parent.
- `gofmt`. Binary size constants as products of decimals (`1024 * 1024`), never shifts.

### Surface rules that hold for every task

- **gomobile (§7.8).** Exported functions and methods may use `bool`, `int`, `int8/16/32/64`,
  `float32/64`, `string`, `[]byte`, and named types defined in `sdk`. No maps. No slices of anything
  but `byte`. No generics in exported signatures. Multiple returns only as `(T, error)`. Struct
  fields must themselves be exportable. `time.Time` never crosses — `int64` unix milliseconds, named
  `...Ms`.
- **`Sub` is returned by value.** `sdk/sub.go` declares `type Sub interface{ Close() }`. Measured
  2026-08-30: **every** `Add*Listener` in the existing `sdk` returns `Sub`, and `) *Sub` occurs
  **zero** times in the tree. §7 spells `*Sub` on **10** declarations, all of them `Add*Listener` on
  `MessageClient`. A pointer to an interface is neither gomobile-bindable nor idiomatic Go, and
  §7.1's own object-model table says `Sub` with no star. **This plan declares `Sub`, by value, in all
  ten places**, and Task 10 owns the gate. `Sub` is also §9.2's **fourth** messaging behavioural
  type and §7.1's — a handle this plan does not declare and cannot mark, which is why Task 14's
  handle set is "marker-derived, plus one gated exception" rather than "whatever carries the
  marker". The cgo generator will not catch the error: `classify`
  unwraps `*types.Pointer` to the named `Sub`, `Sub` is in `gen.go`'s hand-maintained
  `behavioralTypes` allowlist, and the pointer classifies as a handle. Verified by reading
  `sdk/cgo/gen/gen.go` lines 330–411.
- **Behavioural handles cross the ABI as `uint64_t`; everything else crosses as JSON.** A named
  struct that is *not* in `behavioralTypes` reaches `gen.go`'s struct branch and is classified
  `kindJson` — so a `MessageClient` with no entry crosses as a JSON blob rather than as an opaque
  handle. Verified at `gen.go:406`.
- **Every value struct on this surface must marshal to JSON and survive a round trip.** Three
  behaviours of the existing `exportedList` pattern were **measured** rather than assumed, and all
  three are load-bearing for Spec C (Task 8):
  1. a `nil *List` field marshals as `null`;
  2. an **empty but non-nil** `*List` field also marshals as `null`, because `exportedList.values` is
     a nil slice and `json.Marshal` of a nil slice is `null`;
  3. a `*List` held as a **value** rather than a pointer marshals as `{}`, because the promoted
     `MarshalJSON` has a pointer receiver and is not in the value's method set.
- **No timing-sensitive tests.** Nothing in this plan needs a clock. A later plan that does takes an
  injected `nowMs func() int64`.
- **Mutation testing is two-phase** (ledger 12b). A targeted `-run` costs ~1.8 s against a full
  package run's ~57 s. Run the targeted form for every mutation; run the full package only for a
  mutation that survives the targeted run. Twenty mutations is then about three minutes, not twenty.

---

## Interfaces consumed from other plans

**None.** That is the point of this plan's position in the wave. Everything s1 needs already exists
in `sdk` on `main` or in the standard library.

Read the following out of source before using them. Their shapes are described here so the plan is
readable; their spellings are not normative (R2).

```go
// sdk/sub.go — the existing subscription handle. Returned BY VALUE by every
// Add*Listener in the tree. newSub is unexported and takes the unsubscribe func.
type Sub interface{ Close() }
func newSub(unsubFn func()) Sub
```

```go
// sdk/gomobile.go — the existing list machinery. Unexported and generic, embedded
// by value in each exported wrapper; the wrapper is what crosses gomobile, because
// gomobile exports neither generics nor []T. Its MarshalJSON/UnmarshalJSON have
// POINTER receivers — see the third measured behaviour above.
type exportedList[T any] struct{ /* unexported */ }
func newExportedList[T any]() *exportedList[T]
// promoted methods: Len, Get, Add, Contains, MarshalJSON, UnmarshalJSON
type StringList struct{ exportedList[string] }
func NewStringList() *StringList
```

```go
// connect/util.go — the listener registry every existing view controller uses.
// Add returns a callback id; Remove takes it. This is what an Add*Listener body is
// built from, paired with newSub.
type CallbackList[T any] struct{ /* unexported */ }
func NewCallbackList[T any]() *CallbackList[T]
```

```go
// connect/mls/errors_lifecycle.go — the membership caps, which already exist.
// Task 3 asserts agreement with these from a TEST file only; sdk must not gain a
// production import edge to connect/mls (Gate 5).
const MaxGroupMembers = 500
const MaxDeviceLeavesPerIdentity = 10
```

**Pending pins** — cross-plan symbols this plan names that do **not** exist yet. Task 16's registry
gate must list them, so that the day the producer lands, the gate fails and asks for the pin rather
than leaving a stale reference for the next reader.

| Symbol | Producer | Consumed by | State on 2026-08-30 |
|---|---|---|---|
| the 24-hour delete-for-everyone window, as a constant | m1 (the `TOMBSTONE` body table) | `MessageProtocolLimits.DeleteForEveryoneWindowMs` | **absent.** `connect/message` holds no such constant |
| `message.GroupEngine`, `message.GroupHandle` | s5 | `MlsEngineFactory` | absent; `connect/message/engine.go` does not exist |
| `StoredEntry` | s2 | s9's projection into `MessageEntry` | undefined in the spec — Open item S1-9 |
| `mls.CheckGroupSize`, `mls.CheckDeviceCount` | p7 Task 20 | Task 3's agreement check | absent; the two **constants** exist, the two checks do not |

---

## Interfaces produced by this plan

Every other slice-2 plan writes its `Consumes` block against these. They are restated inside the task
that creates each one. Shapes, not spellings (R2).

```go
// sdk/message_client.go — the root handle. One per device per account, safe for
// concurrent use. This plan produces the shell: construction, close, the settings
// struct, and the accessors that read nothing but their own fields.
package sdk

type MessageClient struct{ /* unexported */ }
type MessageClientSettings struct{ /* the five §9.3 keys */ }

func NewMessageClient(settings *MessageClientSettings) (*MessageClient, error)
func (self *MessageClient) Close()
```

```go
// sdk/message_handles.go — the two other behavioural handles. Declared here so the
// 38 declarations returning a ticket and the 3 returning a link session have a type
// to name. Their behaviour is s9's and A9's respectively.
type MessageSendTicket struct{ /* unexported */ }
type MessageDeviceLinkSession struct{ /* unexported */ }
```

```go
// sdk/message_vocab.go — the closed vocabularies as validated constants, plus the
// classification of every string field on the surface. The registry is what
// TestVocabulariesAreClosed derives its scope from; the classification is what makes
// an unclassified new string field a failure rather than a silence.
func MessageVocabularies() *StringList                     // sorted vocabulary names
func MessageVocabularyValues(name string) *StringList        // sorted; nil if unknown
func MessageVocabularyContains(name string, value string) bool
```

```go
// sdk/message_lists.go — the 16 *List wrappers over the existing exportedList.
// MEASURED from §7, not counted from prose: MessageGroupList, MessageMemberList,
// MessageEntryList, MessageAttachmentList, MessageReactionList, MessageReceiptList,
// MessageDeviceList, MessagePinList, MessageInviteList, MessageInviteLinkList,
// MessageJoinRequestList, MessageContactRequestList, MessageHistoryGrantList,
// MessageSecurityLogEntryList, MessageSearchResultList, MessageDirectoryResultList.
// StringList already exists and is reused, never re-declared.
```

```go
// sdk/surface — a NESTED MODULE. The exportability walk, importable by
// sdk/cgo-message/gen (s10) so there is one classification model and not two.
package surface

type Kind int   // handle | callback | json | bytes | string | int | bool | float | id | time | bad

type Info struct {
    Kind   Kind
    Reason string   // set iff Kind is bad
}

func BehavioralTypes() []string                      // §9.2's four; s10's generator reads it
func MarkerDerivedHandles() []string                 // the three this plan declares, from the marker
func Classify(t types.Type) Info
func WalkReachable(pkg *packages.Package, roots []string) ([]Finding, error)
```

---

## File Structure

Every file created or modified by this plan, and its single responsibility.

| File | Responsibility |
|---|---|
| `sdk/message.go` | Package-level doc for the messaging surface; the R2 statement, in the source, that signatures are read from source |
| `sdk/message_client.go` | `MessageClient` shell, `MessageClientSettings`, `NewMessageClient`, `Close`, the settings parse and its defaults |
| `sdk/message_handles.go` | `MessageSendTicket`, `MessageDeviceLinkSession` |
| `sdk/message_errors.go` | The typed error set the shell and the stubs refuse with |
| `sdk/message_types_session.go` | `SyncState`, `MessageHealthEvent`, `MessageServerInfo`, `MessageSendability`, `MessageProtocolLimits`, `SyncResult` |
| `sdk/message_types_group.go` | `MessageGroup`, `MessageMember`, `MessageGroupPolicy`, `MessagePendingPolicy`, `MessageRetentionApplied`, `MessageSuccessionState`, `MessageHistoryGrant`, `MessageInvite`, `GroupResult`, `GroupEvent` |
| `sdk/message_types_entry.go` | `MessageEntry`, `MessageEntryDetail`, `MessageHistoryState`, `MessageAttachment`, `MessageReaction`, `MessageReceipt`, `MessageSearchResult`, `MessageEvent`, `RecordLifecycleEvent`, `UploadProgress`, `DownloadProgress`, `SendResult` |
| `sdk/message_types_trust.go` | `MessagePin`, `KeyChangeWarning`, `MessageDirectoryResult`, `IntegrityEvent`, `MessageSecurityLogEntry`, `MessageDevice`, `DeviceLinkState`, `DeviceRemovalProgress`, `MessageContactCard`, `MessageContactRequest`, `MessageInviteLink`, `MessageJoinRequest`, `MessageBalance`, `BalanceRedeemResult`, `RestoreProgress` |
| `sdk/message_lists.go` | The 16 `*List` wrappers and their constructors |
| `sdk/message_vocab.go` | The closed vocabularies, their values, and the string-field classification |
| `sdk/message_listeners.go` | The 21 listener/callback interfaces and the 10 `Add*Listener` declarations |
| `sdk/message_stubs.go` | The ABI-stable typed refusals for every call this slice does not implement |
| `sdk/message_lists_test.go` | The `*List` derivation and its JSON shape |
| `sdk/message_json_test.go` | JSON naming totality, round trip, and the three measured `*List` behaviours |
| `sdk/message_vocab_test.go` | `TestVocabulariesAreClosed` and the classification's totality |
| `sdk/message_listeners_test.go` | One-method closure; `Sub` by value; the listener/payload pairing |
| `sdk/message_stubs_test.go` | Every stub refuses, and refuses the same way twice |
| `sdk/message_client_test.go` | Settings parse, defaults, and the refusals `NewMessageClient` owes |
| `sdk/message_limits_test.go` | The agreement between `MessageProtocolLimits` and `connect/mls` — the only test-only import edge |
| `sdk/dependency_graph_test.go` | **modify:** add `surface/go.mod` to the artifact-module list |
| `sdk/surface/go.mod`, `go.sum` | The nested module; `golang.org/x/tools` lives here and nowhere else |
| `sdk/surface/behavioral.go` | `MarkerDerivedHandles()` — the three handles this plan declares, derived; and `BehavioralTypes()`, which adds §9.2's fourth, `Sub`, as the one gated exception |
| `sdk/surface/surface.go` | `Kind`, `Info`, `Classify`, `WalkReachable` |
| `sdk/surface/surface_test.go` | The walk's own properties, against fixtures inside the module |
| `sdk/surface/message_surface_test.go` | `TestMessageSurfaceIsExportable` |
| `sdk/surface/generator_drift_test.go` | The AST gate holding `surface` and `sdk/cgo/gen/gen.go` together |
| `sdk/.gitattributes` | `eol=lf` for Go and module files; the `working-tree-encoding` line for `.md` |
| `sdk/.github/workflows/messaging-surface.yml` | The jobs that run this plan's gates; the repo has **no** `.github` directory today |
| `msgrepo/docs/plans/2026-08-30-slice2-interface-registry.md` | The slice-2 cross-plan registry and its pending-pin gate |

---
## How to read a task

Each task has **Files**, an **Interfaces** block naming exactly what it consumes and what it
produces, and numbered steps. The steps are always the same six, and step 1 and step 5 are where the
work is:

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
   set. Record survivors and their reason in the commit message if any are accepted.
6. **Commit.**

---

## Phase A — the declarations (nothing here depends on anything outside `sdk`)

### Task 1: The three behavioural handles, and the marker that makes the handle set derivable

**Files:**
- Create: `sdk/message.go`, `sdk/message_handles.go`, `sdk/message_errors.go`
- Test: `sdk/message_handles_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
```go
// the three behavioural handles of §7.1. MessageClient's own construction is Task 2;
// this task declares the types and the property that makes them handles.
type MessageClient struct{ /* unexported */ }
type MessageSendTicket struct{ /* unexported */ }
type MessageDeviceLinkSession struct{ /* unexported */ }

// the marker. Unexported, so it crosses neither gomobile nor the ABI, and present on
// exactly the types THIS PLAN declares that must cross as opaque uint64_t handles.
// This is what lets Task 14 DERIVE the behavioural-type set instead of maintaining a
// second allowlist beside gen.go's.
//
// it reaches THREE of the FOUR handles 9.2 names. the fourth is Sub, which is an
// INTERFACE declared in sdk/sub.go and already in sdk/cgo/gen/gen.go's behavioralTypes
// -- so a marker on it would be a method added to a shipped interface's method set,
// breaking every implementor and moving the VPN ABI. Sub is a declared, size-gated
// exception in Task 14 Property 1, never a marker-carrier and never an omission.
func (self *MessageClient) messageBehavioralHandle()
func (self *MessageSendTicket) messageBehavioralHandle()
func (self *MessageDeviceLinkSession) messageBehavioralHandle()

func (self *MessageSendTicket) Cancel()
func (self *MessageDeviceLinkSession) SessionId() string
func (self *MessageDeviceLinkSession) OfferPayload() string
func (self *MessageDeviceLinkSession) AuthString() string
func (self *MessageDeviceLinkSession) PairingCode() string
func (self *MessageDeviceLinkSession) SasDigits() string
func (self *MessageDeviceLinkSession) Confirm(matches bool) error
func (self *MessageDeviceLinkSession) Cancel()
```

**Ownership note — `Await` is deliberately not declared.** §7.4 says `MessageSendTicket` "has
`Cancel()` and `Await()`; `Await` is not exposed over the ABI". `Await`'s return type is stated
nowhere in 4,510 lines of spec, and the two readings are both defects: returning nothing makes it
unable to report an outcome, and blocking makes it a UI-thread deadlock on every platform. Worse,
"not exposed over the ABI" needs an explicit `skipMethods["MessageSendTicket.Await"]` entry in s10's
generator, which nothing specifies, while **gomobile has no such exclusion list at all** and will
bind a blocking `Await` into the AAR and the Apple framework. Declaring it now is therefore an
irreversible product hazard on two platforms; not declaring it is additive to undo. This task
declares `Cancel()` only, writes the reason into the type's doc comment, and pins the method set so
the day somebody adds `Await` the gate fails and asks for the ruling. **Open item S1-1.**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — a behavioural handle is opaque.** No handle type may carry an exported field. A
  handle crosses the ABI as a `uint64_t` into a registry and crosses gomobile as an object
  reference; an exported field is data neither binding carries, and it is the exact shape that turns
  a handle into a JSON blob the moment somebody removes its classification entry.
  *Refusal owed:* a handle type with any exported field, of any type, fails — including a field
  whose own type is legal.
  *Scope to derive, separately from the class:* not "these three type names". The scope is **every
  named type in `package sdk` that carries the marker method**, obtained from the type graph. A
  fourth handle added later is inside the gate by existing, which is the whole point of the marker.
  *And the scope is not the whole of §9.2's handle set.* §9.2 names four messaging behavioural types
  and the fourth is `Sub`, which is an interface and cannot carry the marker (Task 14 Property 1).
  This property is about **opacity**, and an interface has no fields to expose, so `Sub` being
  outside this gate costs nothing here. State that in the header rather than leaving a reader to
  discover that "every handle" means three; the two gates that *do* need all four — Task 13's drift
  check and Task 14's walk — say so at their own headers.

  **Property 2 — the method set of each handle is exactly what is declared, and nothing else.**
  This gate exists to make an addition visible, not to prove the methods work. Its header must say
  so, and must name `Await` as the thing it is waiting for.
  *Refusal owed:* adding `Await()` — in any signature — fails, and the failure message names Open
  item S1-1 rather than saying "unexpected method".

  **Property 3 — every handle method is gomobile-legal.** Parameters and results drawn only from the
  §7.8 set. `Confirm(matches bool) error` is the only one taking an argument.
  *Refusal owed:* a method taking or returning a map, a non-`byte` slice, a generic, or more than
  `(T, error)`, fails.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**

  `sdk/message.go` carries the package-level doc for the messaging surface and — in the source, not
  only in this plan — the R2 statement: *every signature on this surface is read from the file that
  declares it; a call written from a document is a call that does not compile.*

  `sdk/message_errors.go` declares the typed error set. Two of them are needed by Task 2 and Task 11
  and are declared here so there is one declaration site:
  `ErrMessageSettingsInvalid`, `ErrMessageNotImplemented`. Each is a sentinel usable with
  `errors.Is`; the wrapping message names the field or the call.

- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add an exported field of type `string` to `MessageSendTicket`. Property 1 must fail.
  2. Add an exported field whose type is itself legal (`*MessageEntry`) to `MessageClient`. Property
     1 must still fail — a legal field type is not an excuse.
  3. Remove the marker method from `MessageDeviceLinkSession`. Property 1's **scope** must shrink and
     the gate must report that it saw two handles where the plan declares three. A gate that
     hardcoded the three names survives this; that survival is the ledger-21 defect and the test is
     wrong if it does not fail here.
  4. Declare `func (self *MessageSendTicket) Await()`. Property 2 must fail and must name S1-1.
  5. Declare `func (self *MessageSendTicket) Await() error`. Property 2 must fail identically —
     the gate must be over the method *set*, not over one spelling.
  6. Change `Confirm(matches bool) error` to `Confirm(matches bool)`. Property 2 must fail.
  7. Change `SasDigits() string` to `SasDigits() []string`. Property 3 must fail.
  8. Make `Cancel()` take a `map[string]string`. Property 3 must fail.
  9. Rename the marker method to something else on all three types at once. The gate must report
     zero handles and fail; a gate that treats an empty scope as a pass is the vacuous-gate class
     this project has already paid for.

- [ ] **Step 6: Commit**

---

### Task 2: `MessageClientSettings`, the §9.3 `settings_json` schema, and construction

**Files:**
- Create: `sdk/message_client.go`
- Test: `sdk/message_client_test.go`

**Interfaces:**
- Consumes: `MessageClient` (Task 1); `ErrMessageSettingsInvalid` (Task 1).
- Produces:
```go
type MessageClientSettings struct {
    StorageDir       string
    NetworkSpaceHost string
    MessageServerId  string
    EnableCover      bool
    MediaCacheBytes  int64
}

func NewMessageClient(settings *MessageClientSettings) (*MessageClient, error)
func (self *MessageClient) Close()
```

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the Go struct and the `settings_json` document are one schema, not two.** §7.2 and
  §9.3 print the same object twice, and s10's `urmsg_client_open(settings_json, out_error)` parses
  it. The five keys are `storage_dir`, `network_space_host`, `message_server_id`, `enable_cover`
  (optional, default false) and `media_cache_bytes` (optional, default 1 GiB). A Go field with no
  JSON key, or a JSON key with no Go field, is a call `urmsg_client_open` rejects at runtime with no
  compile-time warning anywhere.
  *Refusal owed:* a settings JSON carrying an unknown key is refused with
  `ErrMessageSettingsInvalid` naming the key — not ignored.
  **This is a forward-compatibility decision and the spec does not take it.** §9.3 says exactly one
  thing about the key set — *"All keys required unless marked optional"* — and says nothing about a
  key it does not know. Rejecting is the position this plan takes, because an unknown key is far more
  likely to be a caller's typo for a required one than a forward-compatible extension, and silently
  ignoring it means the client runs with the default for the key the caller thought they set. What
  it costs is stated rather than hidden: the DLL and the host application are separately versioned
  binaries (§9.6 ships the DLL; Spec C is its own build), so a newer host passing a key an older DLL
  does not know fails to open the client **at all** rather than degrading. *Rejected alternative:*
  ignore-and-log, which makes every typo a silent misconfiguration. Filed as **Open item S1-18**;
  the gate records the position taken, so a reversal is one edit to a rule.
  *Scope to derive:* every exported field of `MessageClientSettings`, from the type, paired against
  every key in the schema. Not a list of five.

  **Property 2 — the three required keys are required, and each names itself when missing.**
  `StorageDir`, `NetworkSpaceHost`, `MessageServerId`.
  *Refusal owed:* an empty required key fails construction with an error that names that key. Three
  separate failures, not one "invalid settings".

  **Property 3 — `network_space_host` is a required settings key in `sdk`, and the build-time
  default the spec sanctions belongs to the host application, not to this package.** Read the spec
  text before writing this gate, because the obvious phrasing forbids the exact construct the spec
  permits. §7.2 and §9.3 both say the key comes *"from the host application's per-user
  configuration, with a build-time value used only when nothing is configured. Never a compile-time
  constant **as its only source**"*, and decision A13 says *"A CI grep asserts that no operator
  hostname literal appears **outside the default-value declaration**"*. So a build-time default is
  **sanctioned**; what A13 and MASTER §2 forbid is a compiled-in constant that is the *only* source.
  A gate written as "no literal may be used as a default for this field" bans what A13 requires.
  The distinction that makes both true at once, and it is the whole content of this property: in
  `sdk` the key is **required** — §9.3 marks only `enable_cover` and `media_cache_bytes` optional,
  and Property 2 already refuses an empty one by name — so within `package sdk` there is no
  sanctioned default at all, and A13's "default-value declaration" is the **host application's**,
  which §7.2 and §9.3 both place there in the same sentence. §9.3 puts `message_server_id` in the
  same shape: its value comes *"from the build-time constant `kMessageServerClientId`"*, and that
  constant is likewise the caller's, not this package's.
  *Refusal owed:* an operator hostname literal in any **non-test** file of `package sdk` that can
  reach `NetworkSpaceHost` fails. Derive the class — *a value reaching `NetworkSpaceHost` by a path
  the settings key cannot override* — rather than banning a spelling like `"ur.network"`, which a
  rename defeats.
  *What the gate must NOT refuse, stated because a gate that overreaches here contradicts a locked
  decision:* a host supplied **through** the settings, at any value; `MessageServerInfo.OperatorHost`
  carrying a hostname at runtime; and a literal in a test. This gate is scoped to `package sdk` and
  must not be exported to Spec C's side, where the build-time default is **required**.

  **Property 4 — the two optional keys default, and the defaults are the spec's.** `enable_cover`
  false; `media_cache_bytes` 1 GiB, written `1024 * 1024 * 1024` per CODESTYLE, never `1 << 30`.
  *Refusal owed:* an explicit `0` for `media_cache_bytes` must be distinguishable from an absent
  key, or "no media cache" is unrequestable. Decide and assert which; if the spec does not settle it,
  it is Open item S1-14 and the gate records the position taken.

  **Property 5 — `Close` is idempotent and safe from any goroutine.** §7.1 says the client is safe
  for concurrent use. A second `Close` must not panic.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation.** The shell holds a `stateLock`, the settings, and
  a `closed` flag, and nothing else. It starts no goroutine, opens no file, and reaches no network:
  everything else on `MessageClient` is a later plan's.
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Delete the `media_cache_bytes` JSON key from the schema while keeping the Go field. Property 1
     must fail.
  2. Rename the Go field `StorageDir` to `Storage`. Property 1 must fail on the pairing, not on a
     hardcoded name.
  3. Add a sixth Go field with a JSON key. Property 1 must fail — the pairing is total in both
     directions.
  4. Accept an unknown JSON key silently. Property 1's refusal must fail.
  5. Make a missing `MessageServerId` fall back to the empty string and construct successfully.
     Property 2 must fail.
  6. Collapse the three required-key errors into one shared message. Property 2 must fail — it
     asserts each names itself.
  7. Introduce a package-level `const defaultNetworkSpaceHost = "ur.network"` and use it when the
     settings value is empty. Property 3 must fail.
  8. Do the same but read the literal from a differently named constant in a second file. Property 3
     must still fail; if it does not, the gate enumerated a name instead of deriving the class.
  8a. Supply `"ur.network"` as the settings **value** from a test. Property 3 must **pass** — this is
     the path §7.2 and A13 sanction, and a gate that bans the string has banned configuration. Run
     this one; it is the cheapest check that the gate derived the class rather than the spelling.
  9. Change the media cache default to `1 << 30`. The value is identical, so a value assertion
     passes: this mutation exists to check the CODESTYLE gate, not the arithmetic. If nothing fails,
     record that the style rule is unenforced rather than pretending it is covered.
  10. Make `Close` panic on second call. Property 5 must fail.

- [ ] **Step 6: Commit**

---

### Task 3: The session value structs, and the one agreement with `connect/mls`

**Files:**
- Create: `sdk/message_types_session.go`
- Test: `sdk/message_types_session_test.go`, `sdk/message_limits_test.go`

**Interfaces:**
- Consumes: `StringList` (existing, `sdk/gomobile.go`).
- Produces: `SyncState`, `MessageHealthEvent`, `MessageServerInfo`, `MessageSendability`,
  `MessageProtocolLimits`, `SyncResult`, and `func MessageProtocolLimitsValues() *MessageProtocolLimits`.

**The field manifest.** Every struct task in this plan produces a committed **field manifest** — the
field name, its Go type and its JSON key, transcribed from the spec section that declares it — and a
gate that compares the manifest with the type by reflection. The manifest is the *content* being
asserted; the gate's *scope* is derived from the type graph, so a struct added to the file without a
manifest entry fails. This is the same shape as p8's errata transcription guard, and it exists
because the alternative is a hundred structs whose only check is that they compile.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the manifest and the type agree, in both directions, for every struct in the
  surface set.** A field in the type with no manifest entry fails; a manifest entry with no field
  fails; a type mismatch fails.
  *Refusal owed:* an `int32` widened to `int64` fails. Width is not cosmetic here: gomobile binds
  `int32` to Java `int` and `int64` to Java `long`, and the cgo generator emits the C width from it,
  so a width change is an ABI break that compiles cleanly on both sides in Go.
  *Scope to derive:* every named struct type declared in the `message_types_*.go` files, obtained
  from the package, not a list of six names. The gate must fail if a struct in one of those files is
  absent from the manifest.

  **Property 2 — every time-valued field is `int64` unix milliseconds and is named `...Ms`.** §7.8
  forbids `time.Time` crossing, and §7.2 makes the millisecond convention total.
  *Refusal owed:* a field named `SentAt` of type `int64` fails; a field of type `*Time` or
  `time.Time` fails; a field named `TimeoutMs` of type `int32` fails.
  *Scope:* every field of every struct on the surface, derived — not the ones this task happens to
  declare. State that scope in the gate's header, because this is the property most likely to be
  scoped to one file and then quietly bypassed by the next task's file.

  **Property 3 — the suffix names the unit, field by field, and `MessageServerInfo` carries both
  units.** §7.2 says of `MessageServerInfo` that *"`MediaTtlMaxMs`, `MediaTtlDefaultMs`,
  `DurableTtlMaxMs`, `DurableTtlDefaultMs` and `DurableRetentionMinMs` are milliseconds because every
  other duration on this API surface is milliseconds"* and that `sdk` *"converts them from the
  server's seconds once, on receipt of `Capabilities`"* (that conversion is s4's); and that
  *"`MessageRetentionApplied` does **not** convert — it is a mirror of a wire message and stays in
  seconds."*
  **Do not read that as "every duration on `MessageServerInfo` ends `Ms`", because the struct itself
  contradicts it.** Measured against §7.2's declaration on 2026-09-02, `MessageServerInfo` carries
  **two** duration fields spelled `Seconds` — `RendezvousTtlSeconds` and `RendezvousDepositTtlSeconds`,
  both `int64`, both added by revision A-6 together with §7.3b — alongside `ReadKeyWindowMs`,
  `KeyVerifiedAtMs` and the five retention fields. A property written as "every duration on this
  struct ends `Ms`" is red against a correct transcription, and an implementer's likely resolution is
  renaming the two rendezvous fields, which silently changes the unit of a value §7.3b's rate-limit
  paragraph reads straight out of `ServerInfo()` and formats for the user.
  So the rule the gate carries is **transcription, not normalisation**: for every duration field on
  either struct, the suffix in the type matches the suffix in the manifest, and the manifest is
  transcribed from the §7 line that declares the field. `MessageRetentionApplied` is `Seconds`
  throughout, field for field.
  *Refusal owed:* a `MediaTtlMaxSeconds` on `MessageServerInfo` fails, because §7.2 declares that
  field `MediaTtlMaxMs`; a `RendezvousTtlMs` fails, because §7.2 declares it `RendezvousTtlSeconds`;
  a `DurableTtlMs` on `MessageRetentionApplied` fails. It is a naming gate and not a units gate —
  the units gate is s4's, at the one conversion site.
  *Residual, and it is a spec defect rather than a transcription question:* §7.2's clause *"because
  every other duration on this API surface is milliseconds"* is false of the very struct it appears
  in, because A-6 added the two rendezvous seconds fields to that struct afterwards. Transcribe what
  is declared and file **Open item S1-19**; do not reconcile the sentence by renaming a field.

  **Property 4 — `MessageProtocolLimitsValues()` agrees with `connect/mls` and does not restate
  it.** `mls.MaxGroupMembers` is 500 and `mls.MaxDeviceLeavesPerIdentity` is 10 today, in
  `connect/mls/errors_lifecycle.go`. §7.2 says these are protocol constants enforced by
  `connect/mls`, not server-advertised values.
  *Refusal owed:* changing `mls.MaxGroupMembers` to 400 without changing the sdk constant fails the
  build's test run. The check lives in `sdk/message_limits_test.go`, which is the **only** file in
  `package sdk` permitted to import `connect/mls`, and its header must say why: a production import
  would give `sdk` a compile-time edge to the MLS implementation and Gate 5 exists to prove there
  is none.
  *Pending pin:* `DeleteForEveryoneWindowMs` has **no producer** — `connect/message` declares no
  such constant. Declare the sdk value, mark it pinned-to-nothing in the Task 16 registry, and let
  the registry gate fail when m1 lands so the pin is taken rather than forgotten.

  **Property 5 — `Advertised == false` is honoured from the first declaration.** §7.2 requires that
  `OperatorHost`, `HostingJurisdiction`, `ReadKeyWindowMs` and the three limits render as "not known
  yet" until the first `HelloResponse`, and forbids a fabricated default. The behaviour is s4's; the
  *declaration* obligation is here, and it is that `MessageServerInfo` must carry no field
  initialised to a non-zero literal at construction. A default value invented at declaration time is
  a claim about where a user's ciphertext sits, made before the server has said anything.
  *Refusal owed:* a constructor or a `var` that gives `ReadKeyWindowMs` a 90-day default fails.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Widen `MessageSendability.RetryAfterMs` from `int64` to... it is already `int64`; instead
     narrow `MessageServerInfo.MaxRecordsPerFetch` from `int32` to `int16`. Property 1 must fail.
  2. Widen `SyncState.ConsecutiveFetchFailures` from `int32` to `int64`. Property 1 must fail.
  3. Delete `SyncState.EvaluatedAtMs` from the type, leaving the manifest. Property 1 must fail.
  4. Delete the same field from the manifest as well, so the two agree. Property 1 now passes — and
     that is correct: the manifest is the transcription, and this mutation is the reason a manifest
     is reviewed against the spec by a human at commit time. Record it as an accepted survivor with
     that reason; do not invent a gate that pretends to read the spec.
  5. Add a struct to `message_types_session.go` with no manifest entry. Property 1 must fail on
     scope. A gate keyed to six names survives this.
  6. Rename `SyncState.LastRecordReceivedMs` to `LastRecordReceived`. Property 2 must fail.
  7. Change `MessageHealthEvent.Seq` to `float64`. Property 1 must fail.
  8. Add `MessageServerInfo.MediaTtlMaxSeconds` beside the `Ms` field. Property 3 must fail.
  8a. Rename `MessageServerInfo.RendezvousTtlSeconds` to `RendezvousTtlMs`. Property 3 must fail —
     the rule is transcription, and a gate that normalised every duration on this struct to `Ms`
     passes this mutation while being red against the unmutated tree. Run this one before writing the
     implementation; it is what distinguishes the property from the version it replaced.
  9. Change the sdk `MaxGroupMembers` value to 501. Property 4 must fail.
  10. Change `mls.MaxGroupMembers` to 501 instead. Property 4 must fail in the same test — the
      agreement is symmetric.
  11. Replace the agreement check with a literal `if 500 != 500`. Property 4 must fail to fail —
      i.e. this mutation must be caught by review, not by a test, and the reason is that a test that
      restates a constant cannot check agreement with it. Note it in the gate's header.
  12. Give `MessageServerInfo.ReadKeyWindowMs` a package-level default of 90 days. Property 5 must
      fail.

- [ ] **Step 6: Commit**

---
### Task 4: The group value structs

**Files:**
- Create: `sdk/message_types_group.go`
- Test: `sdk/message_types_group_test.go`

**Interfaces:**
- Consumes: the manifest machinery and Properties 1–2 of Task 3; `StringList`.
- Produces: `MessageGroup`, `MessageMember`, `MessageGroupPolicy`, `MessagePendingPolicy`,
  `MessageRetentionApplied`, `MessageSuccessionState`, `MessageHistoryGrant`, `MessageInvite`,
  `GroupResult`, `GroupEvent`.

- [ ] **Step 1: Derive the property and write the failing test**

  Tasks 3's Properties 1 and 2 apply here unchanged and their **scope already covers these
  structs**, because the scope was derived over the files rather than over six names. Confirm that
  by running Task 3's gate before writing anything: if it does not already fail on the new file, its
  scope was enumerated and it must be widened before this task proceeds. This check is the cheapest
  place on the whole plan to catch a ledger-21 gate, and it costs one command.

  **Property 1 — `MessageRetentionApplied` is seconds, field for field, and says so.** It mirrors
  the message server's `RetentionApplied`; every retention value in the system is seconds
  (`media_ttl_seconds`, `durable_ttl_seconds`, `media_ttl_max_seconds`,
  `durable_retention_min_seconds`), and the two differ only in Go casing. `DurableTtlSeconds`
  carries `4294967295` for indefinite; `0` never appears in an applied value, because "unset" is a
  request and not an outcome.
  *Refusal owed:* a field on this struct ending `Ms` fails. So does an applied value of 0 reaching
  a consumer — but that assertion belongs to s8, and this task's header must say so rather than
  implying it is covered here.

  **Property 2 — `MessageGroupPolicy.DisappearingBucket` and the wire EPH class are different
  namespaces, and the declaration must carry the note.** Here `0` means disappearing is **off**;
  on the wire `EPH(bucket 0)` is the transient class carrying receipts and typing. Spec C's open
  item C-8 is closed by citing this. The only thing a gate can assert at declaration time is that
  the note exists at the field; assert that, and say in the header that the behaviour is s8's.

  **Property 3 — `MessageSuccessionState.CountersignsRequired` must eventually CALL
  `mls.SuccessionQuorum(adminCount)`, never reimplement `max(2, ceil(2*admins/3))`.** p7 Task 21
  produces `SuccessionQuorum`; it does not exist today.
  *Refusal owed:* none yet — there is nothing to call. **Pending pin:** record it in Task 16's
  registry against p7 Task 21, so the day it lands the registry gate fails and asks for the call
  site. A quorum formula that exists twice is a quorum formula that disagrees with itself exactly
  once, at the moment it matters.

  **Property 4 — `GroupResult.Reason` is its own closed vocabulary and is not §7.2's.** §7.7 says
  so explicitly — *"`GroupResult.Reason` is CLOSED and is its own vocabulary, separate from §7.2's
  three"* — and then lists the values. **§7.7 states no count.** Counted from that block on
  2026-09-02 the set has **22** members: `ok`, `not_permitted`, `owner_must_transfer`,
  `admin_removal_is_owner_only`, `awaiting_other_party`, `durable_override_not_permitted`,
  `group_size_exceeded`, `device_limit_exceeded`, `succession_disabled`, `succession_not_nominee`,
  `succession_quorum`, `succession_floor`, `succession_floor_too_short`, `link_expired`,
  `link_revoked`, `link_already_redeemed`, `card_retired`, `card_rate_limited`, `card_not_live`,
  `rate_limited`, `offline`, `internal`. That number is **this plan's measurement, not the spec's**,
  and no gate may take it as an input: the vocabulary is derived from the constants, and 22 is a
  tripwire that moves only with a §7.7 citation beside it. Filed as **Open item S1-20**, because a
  closed vocabulary whose size the spec never states is one a reader can undercount without any
  document contradicting them — which is what produced the "21" this repair replaced. The vocabulary
  itself is Task 9's;
  what belongs here is that `GroupResult.Reason` and `MessageSendability.Reason` must not be typed
  as the same named type, and neither may be an `int` enum — §7.3's reason for strings is that
  gomobile enums are nameless ints in Java and Swift and a mis-set role is a security-relevant bug.
  *Refusal owed:* declaring either as a named string type shared with the other fails.

  **Property 5 — `GroupEvent` carries `Seq` and `Dropped`; `MessageInvite`, `MessageHistoryGrant`
  and `MessageGroupPolicy` do not.** This is transcription, and it is contradicted by §7.4a rule 1,
  which claims both appear on *every* event payload. Measured across §7: **seven** structs carry
  both (`GroupEvent`, `IntegrityEvent`, `KeyChangeWarning`, `MessageEntry`, `MessageEvent`,
  `MessageHealthEvent`, `RecordLifecycleEvent`), `SyncState` carries `Dropped` alone, and three
  listener payloads carry neither. **Do not resolve this by adding the fields.** Transcribe what §7
  declares, record the contradiction as Open item S1-5, and let the manifest make the eventual
  ruling a visible diff.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Rename `MessageRetentionApplied.MediaTtlSeconds` to `MediaTtlMs`. Property 1 must fail.
  2. Delete the namespace note from `DisappearingBucket`. Property 2 must fail.
  3. Declare `type MessageReason string` and type both `GroupResult.Reason` and
     `MessageSendability.Reason` as it. Property 4 must fail.
  4. Declare `GroupResult.Reason` as `int32`. Property 4 must fail.
  5. Add `Seq int64` and `Dropped int64` to `MessageInvite`. Property 5 must fail — the manifest is
     the transcription and a helpful addition is still a change.
  6. Remove `Dropped` from `GroupEvent`. Property 5 must fail.
  7. Add a struct to this file with no manifest entry. Task 3 Property 1's scope must fail here; if
     it does not, the scope was enumerated.
  8. Change `MessageSuccessionState.FloorMs` to `FloorDays int32`. Task 3 Property 2 must fail on
     both the name and the width.
  9. Change `MessageGroup.MemberCount` from `int32` to `int`. Property 1 of Task 3 must fail: `int`
     is 64-bit on every target this ships to and binds differently.

- [ ] **Step 6: Commit**

---

### Task 5: The messaging value structs

**Files:**
- Create: `sdk/message_types_entry.go`
- Test: `sdk/message_types_entry_test.go`

**Interfaces:**
- Consumes: Task 3's manifest machinery; `StringList`; the 16 `*List` types are Task 7's and this
  task's fields **name** three of them across four field slots (`*MessageAttachmentList`,
  `*MessageReactionList`, `*MessageReceiptList` twice), so Task 7 may be done first or the two
  committed together.
- Produces: `MessageEntry`, `MessageEntryDetail`, `MessageHistoryState`, `MessageAttachment`,
  `MessageReaction`, `MessageReceipt`, `MessageSearchResult`, `MessageEvent`,
  `RecordLifecycleEvent`, `UploadProgress`, `DownloadProgress`, `SendResult`.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `MessageEntry.SenderRoleAtSend` is read from the sending epoch's group context and
  never from current membership, and the declaration must carry that and one more thing the spec
  does not say.** MLS state is retained for **32 epochs** (`PastEpochWindow`), and `History` is
  unbounded. A role read at render time from retained MLS state is therefore unreadable for any
  message older than 32 epochs, so the value must be **denormalised into the entry row at receipt**.
  The spec never says this. It is s2's schema and s9's projection; what belongs here is the doc
  comment stating the obligation, so neither plan discovers it late.
  *Refusal owed:* none mechanical. Record it as Open item S1-8 and in the registry, assigned to s2
  and s9 jointly.

  **Property 2 — `MessageEntry.Edited` is reserved and always false in v1.** A reserved field that
  something sets is a field that has quietly acquired a meaning.
  *Refusal owed:* a gate asserting no non-test file in `package sdk` assigns `true` to it. Derive
  the class — "an assignment reaching this field" — over the package's AST, not over one file.

  **Property 3 — the four `*List` fields are pointers, and the reason is measured, not stylistic.**
  A `*List` held as a **value** marshals as `{}` rather than as an array, because the promoted
  `MarshalJSON` has a pointer receiver and is not in the value's method set. Measured 2026-08-30.
  *Refusal owed:* a `*List`-typed field declared as a value fails.
  *Scope:* every field on the whole surface whose type is one of the list wrappers, derived from the
  type graph — not the four fields on `MessageEntry`.

  **Property 4 — `MessageEntry.Kind == "gap"` and `GapReason` are paired, and the two vocabularies
  overlap on exactly one value.** `GapReason` is set **iff** `Kind == "gap"`. §7.4 then makes a
  narrower claim than it looks: *"Attachment outcomes are **not** gap reasons — a pruned or failed
  attachment is an `AttachmentState`, so the client can tell 'kept for a month and then pruned' from
  'the download failed', which are different sentences to a user."* It names two outcomes. **It does
  not claim the two sets are disjoint, and they are not.**
  Measured against §7 on 2026-09-02: `MessageAttachment.State` is
  `"available" | "not_downloaded" | "downloading" | "pruned" | "expired" | "failed"`, and `GapReason`
  is `"expired" | "out_of_window" | "not_a_member_yet" | "withheld" | "no_wrap" | "malformed"`.
  **Both contain `"expired"`.** A property demanding they share no value is red against a correct
  transcription, and the resolution an implementer reaches for is deleting `"expired"` from one
  side — which loses either the expired-record gap or the expired-attachment state, and freezes that
  loss into s10's ABI baseline. Neither is available to delete: an expired **record** is one the
  server no longer holds past its retention window, and an expired **attachment** is a body past its
  media TTL under an entry that is still there. They are different sentences to a user, which is
  §7.4's own test.
  *Refusal owed, and it is an exact-set assertion rather than a disjointness one:* the intersection of
  the two declared value sets is exactly `{"expired"}`. That refuses in both directions — adding
  `"pruned"` or `"failed"` to `GapReason` fails (which is §7.4's actual claim), and **deleting**
  `"expired"` from either side fails too, which a disjointness property would have rewarded. The
  overlap is declared once, in a comment at both declaration sites, naming what the value means at
  each. It is checkable now and it is the thing that stops the two collapsing later.
  *Residual:* §7.4's sentence reads as set disjointness while the block eleven lines above it and
  the block sixty lines below it share a value. Transcribe both, assert the intersection, and file
  **Open item S1-21**; a spec correction narrowing §7.4's sentence to the attachment-only values is
  owed. The field-level invariant — `GapReason` set iff `Kind == "gap"` — is s9's to enforce at
  construction, and this task's header must say so rather than implying it is covered here.

  **Property 5 — `MessageEntry.RetryAfterMs` is a typed `int64` field on both `MessageEntry` and
  `MessageSendability`, and appears in no `ReasonDetail`.** §7.2 corrected an earlier revision that
  put it in `ReasonDetail`, which cannot work: `ReasonDetail` is free text that is explicitly never
  parsed, so Spec C's `{RetryAfterMs}` interpolation had nothing to read.
  *Refusal owed:* a `ReasonDetail` field declared as anything but a plain `string`, or a
  `RetryAfterMs` of any width but `int64`, fails. The width is `int64` rather than the wire's
  `uint32` because gomobile does not bind unsigned types.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Declare `MessageEntry.Attachments` as `MessageAttachmentList` (value, not pointer). Property 3
     must fail.
  2. Declare a *different* struct's list field as a value — e.g. `GroupEvent` gaining a value-typed
     list. Property 3 must still fail; if it does not, the scope was the four fields.
  3. Assign `Edited = true` in a non-test file. Property 2 must fail.
  4. Assign it through a local alias variable instead of directly. Property 2 must still fail; a gate
     matching the literal field access survives this, and that is the ledger-21 shape again.
  5. Add `"pruned"` to `GapReason`'s value set. Property 4 must fail — the intersection is then
     `{"expired", "pruned"}` and §7.4's claim about attachment outcomes is what breaks.
  5a. Delete `"expired"` from `MessageAttachment.State`. Property 4 must **also** fail: the
     intersection shrinks to the empty set. This is the mutation that separates the exact-set
     assertion from the disjointness one it replaced — a disjointness property passes this mutation
     while being red on the unmutated tree, which is the wrong outcome in both directions.
  5b. Delete `"expired"` from `GapReason` instead. Property 4 must fail identically.
  6. Change `RetryAfterMs` to `int32`. Property 5 must fail.
  7. Change `ReasonDetail` to a named string type. Property 5 must fail.
  8. Delete the `SenderRoleAtSend` doc comment. Property 1 must fail — the comment is the whole
     deliverable of that property and a gate that does not read it is a gate that asserts nothing.
  9. Change `MessageEntry.Seq` to `int32`. Task 3 Property 1 must fail.
  10. Rename `ExpiresAtMs` to `ExpiresAt`. Task 3 Property 2 must fail from a different file than
      the one it was written in.

- [ ] **Step 6: Commit**

---

### Task 6: The identity, trust, device, card and balance value structs

**Files:**
- Create: `sdk/message_types_trust.go`
- Test: `sdk/message_types_trust_test.go`

**Interfaces:**
- Consumes: Task 3's manifest machinery; `StringList`.
- Produces: `MessagePin`, `KeyChangeWarning`, `MessageDirectoryResult`, `IntegrityEvent`,
  `MessageSecurityLogEntry`, `MessageDevice`, `DeviceLinkState`, `DeviceRemovalProgress`,
  `MessageContactCard`, `MessageContactRequest`, `MessageInviteLink`, `MessageJoinRequest`,
  `MessageBalance`, `BalanceRedeemResult`, `RestoreProgress`.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `MessagePin.EvidenceClass` and `KeyChangeWarning.EvidenceClass` are one
  vocabulary at two sites.** Six values plus one reserved-and-never-emitted (`self_signed_rotation`).
  *Refusal owed:* two vocabulary entries with the same value set but different names fail. This is
  the property that stops a second copy drifting, and its scope is every closed vocabulary on the
  surface, not this pair.

  **Property 2 — `MessagePin.OperatorHost` is empty for a card-provided key, and that is exactly
  where the pin's primary key collapses.** §8.1 keys `pin` by `(principal, operator_host)`; §7.3b
  says a card-added contact's `Principal` is empty unless directory listing is on; §7.6 says
  `OperatorHost` is empty for a key from a contact card. Two card-added contacts therefore share the
  key `("", "")` and the second silently overwrites the first's pin — **which is precisely the state
  in which no `KeyChangeWarning` fires**. No alternate key is specified. This is a schema decision
  and it must be ruled before s2 writes a table; ruling it after rows exist is a migration.
  *Refusal owed:* none here — s1 declares a struct, not a table. **Do not resolve it by inventing a
  key.** Record it as Open item S1-4, blocking s2's schema and s6's pin store, and write it into the
  field's doc comment so the next reader of the struct meets it.

  **Property 3 — `MessageContactRequest.RefusedSinceLastCollect` is a property of the card, not of
  the request.** It carries the same value on every request in one collection.
  *Refusal owed:* none mechanical at declaration; the doc comment must state it, because a field
  that looks per-request and is per-card is a field a UI will sum.

  **Property 4 — `MessageMember.IdentityPublicKey` is `[]byte` and is what Spec C §11.5 derives the
  identicon from.** `[]byte` is the one slice type §7.8 permits, and it crosses the ABI by the
  buffer-out pattern rather than as JSON — so s10 will need a manual export for any *method*
  returning one. As a struct **field** it marshals as base64 JSON, which is a different crossing
  from `IdentityPublicKey()`'s. Say so in the doc comment; the two are easy to conflate and s10 has
  to treat them differently.
  *Refusal owed:* declaring it as `string` fails.

  **Property 5 — the four listener payloads that carry no `Seq`/`Dropped` are transcribed as
  declared.** `MessageJoinRequest`, `MessageContactRequest` and `MessageBalance` carry neither,
  though each is the payload of a persistent `Add*Listener`; `SyncState` (Task 3) carries `Dropped`
  without `Seq`. §9.5 rule 6 and §7.4a rule 1 both say both fields appear on every event payload.
  **Do not add them.** Open item S1-5; the manifest makes the ruling a visible diff.

  **Property 6 — no struct on this surface carries a `Verified` badge semantic.**
  `MessagePin.Verified` exists and §7.6 says there is **no verified badge in v1**; it is for a
  future release and for a "you verified this on 3 March" line. Stated here because it is the kind
  of decision a UI ticket quietly reverses.
  *Refusal owed:* the doc comment must carry the prohibition. Nothing mechanical; Spec C owns the
  rendering.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Rename `KeyChangeWarning.EvidenceClass`'s vocabulary to a second name with the same values.
     Property 1 must fail.
  2. Drop `"out_of_band"` from one of the two sites. Property 1 must fail.
  3. Declare `MessageMember.IdentityPublicKey` as `string`. Property 4 must fail.
  4. Declare it as `[]string`. Task 12's exportability walk must fail; if this task's gate also
     fails, good, but the walk is the one that must.
  5. Add `Seq`/`Dropped` to `MessageBalance`. Property 5 must fail.
  6. Delete the `OperatorHost` doc comment naming S1-4. Property 2 must fail.
  7. Change `MessageContactCard.Generation` from `int32` to `int64`. Task 3 Property 1 must fail.
  8. Rename `MessageDevice.LastSeenMs` to `LastSeen`. Task 3 Property 2 must fail.
  9. Add a `Badge bool` field to `MessagePin`. Task 3 Property 1 must fail on the manifest, and the
     review must catch the intent.

- [ ] **Step 6: Commit**

---

### Task 7: The 16 `*List` wrappers, and the one that must never emit `null`

**Files:**
- Create: `sdk/message_lists.go`
- Test: `sdk/message_lists_test.go`

**Interfaces:**
- Consumes: `exportedList[T]` (existing, `sdk/gomobile.go`); the element structs of Tasks 3–6.
- Produces: `MessageGroupList`, `MessageMemberList`, `MessageEntryList`, `MessageAttachmentList`,
  `MessageReactionList`, `MessageReceiptList`, `MessageDeviceList`, `MessagePinList`,
  `MessageInviteList`, `MessageInviteLinkList`, `MessageJoinRequestList`,
  `MessageContactRequestList`, `MessageHistoryGrantList`, `MessageSecurityLogEntryList`,
  `MessageSearchResultList`, `MessageDirectoryResultList`.

**`StringList` already exists and is reused.** It is the element type of `GroupResult.PartialInvites`,
`KeyChangeWarning.SharedGroupIds`, `MessageEvent.TypingIds`, `MessageReaction.MemberIds` and
`CreateGroupWithMembers`'s `principals` parameter. Do not declare a second one.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the set of declared `*List` types equals the set the surface names.** Derive it:
  every type name of the form `X` such that `*XList` appears as a result type or a field type
  anywhere in the exported surface must have a declaration, and every declared `*List` must be
  named somewhere. A list declared and never used is dead ABI; a list used and never declared does
  not compile, which the build already catches — but the gate is written in both directions anyway,
  because the compiler only catches one of them and the plan must not rely on that asymmetry.
  *Refusal owed:* declaring `MessageFooList` that nothing names fails.
  *Scope:* the whole exported surface reachable from `MessageClient`, from the type graph. Sixteen
  is the measured count today, not the gate's input.

  **Property 2 — every `*List` embeds the existing `exportedList[T]` and adds no state.** The
  wrapper exists because gomobile exports neither generics nor `[]T`, not because a list needs
  behaviour.
  *Refusal owed:* a `*List` with a second field fails; a `*List` implemented over a bare slice
  fails.

  **Property 3 — an empty `*List` marshals as `[]`, never as `null`.** Measured 2026-08-30 on the
  existing pattern: `exportedList.MarshalJSON` calls `json.Marshal(self.values)`, `values` is a nil
  slice until something is added, and `json.Marshal` of a nil slice is `null`. So even a freshly
  constructed, non-nil list emits `null`.
  **The Go half of that is measured; the consumer half is a premise, and the spec is silent on it.**
  The premise is that Spec C parses these with nlohmann and that reading `null` as an array throws
  there. Nothing in Spec A or Spec C states what a `*List` valued `null` does on the C++ side: Spec A
  §9.2 says only *"Data structs, lists and maps cross as JSON strings"*, and Spec C's one mention of
  the library is a note about a UTF-8 `dump()` throw path. This premise is load-bearing for sixteen
  shadowing `MarshalJSON` methods, so it is named as a premise and filed as **Open item S1-22**
  rather than cited as a reading. It is also the premise Task 11's `*List` refusal must not
  contradict — see Property 4 and Task 11's Property 2, which this plan previously allowed to
  disagree.
  Whatever the C++ side does with `null`, the empty-list case is worth fixing on its own: an empty
  list is a real and common answer — every screen hits it on first run — and `[]` is what it means.
  The fix is a `MarshalJSON` **on each wrapper**, shadowing the promoted one, over a shared
  unexported generic helper. Verified 2026-08-30 that the shadow wins, that an empty list then emits
  `[]`, and that a populated list round-trips byte-identically.
  **`exportedList.MarshalJSON` itself is deliberately not changed**: it is shared with the VPN
  surface, whose `URnetworkSdk.dll` is a shipped, signed artifact with an ABI baseline, and turning
  its `null`s into `[]`s is an observable change to that product's JSON. That is not s1's call to
  make. Say so in the file header.
  *Refusal owed:* a wrapper without its own `MarshalJSON` fails; a wrapper whose `MarshalJSON`
  returns `null` for an empty list fails.
  *Scope:* every declared `*List` on the messaging surface, derived — and explicitly **not** the
  pre-existing VPN lists, which the gate must exclude by derivation (element type declared in a
  `message_*.go` file) rather than by name.

  **Property 4 — a nil `*List` still emits `null`, in a field and in a return, and s1 cannot fix
  either here.** The shadow only helps a non-nil list. Two cases, and the plan previously answered
  them inconsistently:
  - *As a field.* The rule — *no surface struct is handed to a caller with a nil `*List` field* — is
    a construction obligation on every plan that builds one. Declare it in the registry (Task 16)
    with the gate assigned to s9, which writes the first projection.
  - *As a return.* §7 declares **twelve** methods on `MessageClient` returning a `*List`
    (`Groups`, `Members`, `HistoryGrants`, `PendingInvites`, `InviteLinks`, `JoinRequests`,
    `ContactRequests`, `History`, `Search`, `Devices`, `Pins`, `SecurityLog`) and **not one of them
    has an error return**. So a call that cannot answer has three available answers and the spec
    rules out two of them: `[]` is refused by §8.2 — *"`Groups()` and `History()` MUST NOT return
    empty in this condition — Spec C would then render 'No conversations yet' to a user whose entire
    history is intact on the server"* — and `null` is refused by Property 3's own premise, which says
    the consumer throws on it. The third, an error, the signature cannot express.
  *Refusal owed in s1:* none, and **recording either case as covered would be the exact failure this
  plan exists to avoid.** What s1 owes instead is that Task 11 does not claim to have solved the
  return case by picking `null` — see Task 11 Property 1's third bucket. Filed as **Open item S1-23**:
  §8.2 states a requirement that the signatures it names cannot express, and either those twelve
  declarations gain an error channel or Spec C's wrapper is specified to tolerate `null`. One of
  those two must be ruled before s10 freezes the baseline.

  **Property 5 — exported constructors exist for exactly the lists that are input parameters, and
  today that is none.** `NewStringList` already covers the only list-typed parameter on the surface
  (`CreateGroupWithMembers`). The generator skips `^New[A-Za-z0-9]*List$` by pattern — verified
  2026-09-02 at `sdk/cgo/gen/gen.go:107`, in **`skipFuncPatterns`**, which is why Task 13's drift
  gate reads that table and an earlier revision of Task 13 that omitted it left this reasoning
  ungated — so a constructor is invisible to the ABI and exists only for gomobile callers building
  an input.
  *Refusal owed:* if a later plan makes one of these a parameter type, the gate must fail and ask
  for the constructor. Write the gate so that happens; a gate asserting "zero constructors" is a
  gate that will be deleted the first time one is needed.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Delete `MessageReceiptList`. Property 1 must fail (it is named twice on `MessageEntry`).
  2. Declare `MessageBalanceList`, which nothing names. Property 1 must fail.
  3. Add a `total int32` field to `MessageEntryList`. Property 2 must fail.
  4. Delete one wrapper's `MarshalJSON`. Property 3 must fail for that wrapper.
  5. Delete *all* the wrappers' `MarshalJSON`. Property 3 must fail sixteen times, not once — a gate
     that stops at the first is a gate that hides the other fifteen.
  6. Change the shared helper to return `null` for an empty list. Property 3 must fail.
  7. Change the shared helper to return `[]` for a **populated** list. A test that only asserts the
     empty case survives this; if it survives, the test asserts the fix and not the behaviour.
  8. Change `exportedList.MarshalJSON` in `gomobile.go` to emit `[]`. Property 3 now passes with the
     shadows deleted — which is the mutation that proves the shadows are load-bearing only while
     that file is unchanged. Record it, revert it, and note in the header that a future change there
     makes the shadows redundant rather than wrong.
  9. Give `MessageGroupList` an exported `NewMessageGroupList`. Property 5 must fail while no
     parameter names it.
  10. Add an exported method taking a `*MessageGroupList` parameter. Property 5 must now demand the
      constructor and fail without it.

- [ ] **Step 6: Commit**

---
### Task 8: JSON field naming for the whole surface, and the rule that keeps it total

**Files:**
- Create: `sdk/message_json_test.go`
- Modify: every `sdk/message_types_*.go` and `sdk/message_lists.go` (tags)

**Interfaces:**
- Consumes: every value struct of Tasks 3–6; the wrappers of Task 7.
- Produces: no new symbol. It produces a **rule**, and the gate that makes the rule total.

**This resolves nothing the spec settled, because the spec settles nothing here.** No JSON field
naming is specified anywhere in Spec A, while every value struct crosses the ABI as JSON, Spec C
parses it with nlohmann, and §9.3's `settings_json` documents **snake_case** keys. §7's structs carry
zero `json:` tags. The existing `sdk` is split: api-mirroring structs like `ConnectLocation` carry
snake_case tags with `omitempty`; non-api value structs like `ProviderGridPoint` carry none at all,
and would emit PascalCase. So with no tags, `urmsg_client_open` would reject every key §9.3
documents, and Spec C would parse `MessageId` where its header says `message_id`.

**The position this plan takes, and it is a position rather than a reading:** snake_case tags on
every exported field of every struct on the messaging surface, no `omitempty` anywhere, and one
gate that makes both total. It is filed as **Open item S1-7** and needs ratification. What matters
more than which convention wins is that changing it later is one edit to a rule, not a hundred
edits to a hundred structs — which is what the gate below buys.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every exported field on the surface carries a `json:` tag whose key is the
  snake_case of the field name.** No exceptions without an entry in a declared exception table, and
  an unused exception entry fails too.
  *Refusal owed:* a field with no tag fails; a tag whose key is not the derived snake_case fails.
  *Scope to derive:* every exported field of every named struct **reachable from `MessageClient`**,
  walked over the type graph — not "the structs in `message_types_*.go`". Those two sets are the same
  today and will not be after s2 adds `StoredEntry`'s projection or s9 adds anything. State the
  scope in the gate's header, in the reachability form, and say why it is not the file form.

  **Property 2 — `omitempty` appears nowhere on the messaging surface.** Spec C parses a fixed
  schema; an absent key is an exception in nlohmann, not a default. Concretely,
  `MessageServerInfo.Advertised` is `false` before the first `HelloResponse` and Spec C must render
  "not known yet" from it — with `omitempty` the key vanishes and "false" becomes indistinguishable
  from "the DLL did not send it".
  *Refusal owed:* any `omitempty` on a messaging struct fails.
  *Scope:* explicitly **not** the whole `sdk` package. The pre-existing VPN structs use `omitempty`
  and are a shipped ABI. Derive the exclusion — a struct whose declaration is reachable from
  `MessageClient` — rather than excluding by file name, because a messaging struct declared in an
  older file must still be caught.

  **Property 3 — every struct on the surface round-trips.** Marshal a value with **every** field set
  to a distinguishable non-zero value, unmarshal, re-marshal: byte-identical, and the unmarshalled
  value equal to the original.
  *Refusal owed:* a field with no tag, an unexported field carrying data, or a duplicate JSON key
  fails. Duplicate keys are the failure this catches that nothing else does: two fields snake-casing
  to the same key marshal fine and unmarshal into one of them.
  *Derivation, not literals:* the fixture value must be built by **reflection over the type**, so a
  field added tomorrow is covered by existing. A hand-written fixture per struct is 44 fixtures that
  will each be one field behind, which is the vacuous-coverage shape this plan is written against.
  *And the obvious way to build it does not work — verified by running it, 2026-09-02.* A reflective
  builder that walks fields and sets them cannot populate a `*List`. The wrappers embed
  `exportedList[T]` **by value** and its only state is the unexported `values` field, so
  `reflect.Value.Set` on it panics with *"reflect: reflect.Value.Set using value obtained using
  unexported field"*, and a builder that skips what it cannot set leaves every list empty or nil.
  That is not a cosmetic gap: it makes Property 4's three assertions vacuous, because a fixture whose
  lists are all empty never exercises the populated case at all.
  The mechanism that does work, verified in the same run: reach the list through its **promoted
  exported method set**. `reflect.Value.MethodByName("Add")` is valid on an addressable
  `*MessageAttachmentList`, `Add` takes the element type, and the element is built by the same
  recursive builder. So the rule is: **set what is settable, and call `Add` for what is not.** State
  it in the gate's header, because the next person to write this reaches for `Set` first.
  The equality half is unaffected — `reflect.DeepEqual` reads unexported state fine, which is why
  Property 3's "an unexported field carrying data fails" refusal still holds even though the builder
  cannot construct that case; the case is constructed by the mutation, not by the fixture.

  **Property 4 — the three measured `*List` behaviours hold end to end.** With Task 7's shadows in
  place: an empty non-nil list field emits `[]`; a populated one emits an array; a nil field emits
  `null` and that is the residual s9 must not produce. Assert all three, and name the third as the
  known gap rather than asserting the absence of a case the type cannot prevent.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation** — the tags, and nothing else.
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Delete one field's tag. Property 1 must fail and must name the field.
  2. Change one tag from `sent_at_ms` to `sentAtMs`. Property 1 must fail.
  3. Add `,omitempty` to `MessageServerInfo.Advertised`. Property 2 must fail.
  4. Add `,omitempty` to a VPN struct. Property 2 must **pass** — the exclusion is deliberate and
     the gate must not claim a scope it was not given.
  5. Declare a messaging struct in `sdk/sdk.go` with no tags. Property 1 must fail; if it does not,
     the scope was the file set rather than reachability.
  6. Give two fields tags that collide (`sent_at_ms` on two fields). Property 3 must fail.
  7. Add an unexported field holding data that the JSON does not carry. Property 3 must fail on the
     equality half; a test asserting only byte-identity of re-marshal survives this.
  8. Replace the reflective fixture with a hand-written one for `MessageEntry`. Add a new field.
     Property 3 must fail; if it passes, the fixture is not derived.
  8a. Make the fixture builder skip any field it cannot `Set` — which is every `*List`, per the note
     above. Property 4 must fail: with every list left empty, the populated-array assertion has
     nothing to assert. If Property 4 passes, the fixture never reached a list and the three
     measured behaviours are being claimed rather than checked.
  9. Delete `MessageEntryList.MarshalJSON`. Property 4 must fail.

- [ ] **Step 6: Commit**

---

## Phase B — the closed vocabularies

### Task 9: The vocabularies, derived rather than counted, and `TestVocabulariesAreClosed`

**Files:**
- Create: `sdk/message_vocab.go`, `sdk/message_vocab_test.go`
- Test: the same

**Interfaces:**
- Consumes: every struct of Tasks 3–6.
- Produces:
```go
func MessageVocabularies() *StringList                      // sorted vocabulary names
func MessageVocabularyValues(name string) *StringList        // sorted; nil if unknown
func MessageVocabularyContains(name string, value string) bool
```

**The count is not the deliverable; the derivation is.** §9.5 rule 7 names **seventeen** closed
vocabularies. Measured against §7's own declarations, that is an undercount: this plan found **36
distinct value sets across more than 40 field sites**, and treats both numbers as a floor. Among the
nineteen §9.5 does not name are `MessageEntry.State`, `MessageEntry.Kind`,
`MessageEntry.RetentionClass`, `MessageEvent.Kind`, `GroupEvent.Kind`, `MessagePin.EvidenceClass`,
`MessageContactCard.State`, `MessageContactRequest.State`, `MessageInvite.State`,
`RecordLifecycleEvent.Kind`, `MessageEntryDetail.AttestationState`, `MessageGroup.PreviewClass`,
`MessageGroup.NotificationMode`, the four role fields, `RestoreProgress.Outcome`,
`DeviceRemovalProgress.State`, `SyncState.Transport`, `SyncState.StoreState`,
`SyncState.TokenState` (which is also `ByJwtState()`'s return), the user-preference key set, and the
value sets of `"attachment_auto_download"` and `"contact_card_auto_accept"`. **Do not copy that
list.** It is offered as evidence that copying is what produced §9.5's seventeen. Derive.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every string-typed field on the surface is classified, and there are exactly three
  classes.** `closed(vocabularyName)`, `free` (display only, explicitly never parsed), and
  `identifier` (an opaque id, a host, a path, a fingerprint). A fourth outcome — *unclassified* — is
  a **failure**, not a default.
  *Refusal owed:* a string field added tomorrow with no classification fails the build's test run,
  naming the field.
  *Scope to derive:* every `string`-typed exported field of every struct reachable from
  `MessageClient`, plus the string **return values** of exported methods that §7 declares closed —
  `ByJwtState()` is one and it is on no struct at all. A gate scoped to struct fields misses it, and
  that omission is exactly the class this project has paid for fourteen times.

  **Property 2 — a closed vocabulary is closed in both directions.** Every declared value is
  reachable from the surface, and no value outside the declared set may be written to a field
  classified `closed`. The second half is the one that gets forgotten. The spec makes three
  **negative** claims that must be asserted as absences, because a value quietly re-added is
  invisible otherwise:
  - vocabulary 1 has **no** `"fork_detected"` — a transcript-hash divergence triggers an automatic
    resync and only surfaces as `"fork_unresolved"`;
  - vocabulary 3's reasons have **no** `"server_key_change_unresolved"` — a server key that does not
    chain to the pinned fleet root is refused outright and reported `"server_key_untrusted"`;
  - vocabulary 2 has **no** `"commit_lost"` and no `"retention_refused"`.
  *Refusal owed:* adding any of those five values fails.

  **Property 3 — vocabulary 2 is a superset of vocabulary 1.** §7.2 defines the send-failure set as
  "every value of vocabulary 1, plus" seven more. That relation is checkable and it is the thing
  that stops the two drifting.
  *Refusal owed:* removing a value from vocabulary 1 without removing it from vocabulary 2 fails, and
  vice versa.

  **Property 4 — vocabulary 3 is ten states, and the two that are neither transport nor store
  conditions are named.** `locked` and `out_of_credit` are evaluated **before** the transport
  states, because a locked store or an exhausted allowance makes every other state meaningless. The
  ordering is s4's to implement; the count and the membership are checkable now.

  **Property 5 — one value set, one name.** `MessagePin.EvidenceClass` and
  `KeyChangeWarning.EvidenceClass` are the same vocabulary; `MessageServerInfo.KeyState` and
  `SyncState.ServerKeyState` are the same vocabulary; `MessageEntry.State` and `SendResult.State`
  are the same vocabulary; the four role fields are one vocabulary.
  *Refusal owed:* two vocabulary entries with identical value sets under different names fail.

  **Property 6 — a `free` field is never compared against a vocabulary anywhere in `sdk`.**
  `ReasonDetail`, `Detail` and `MessageSecurityLogEntry.Detail` are display only and explicitly never
  parsed. §9.5 rule 7 makes the same point about `out_error`.
  *Refusal owed:* a comparison of a `free`-classified field against a vocabulary value, anywhere in a
  non-test file, fails. Derive the class over the AST — *an expression comparing a free field to a
  string constant* — rather than banning a spelling.

  **Property 7 — `RestoreProgress.Phase` is declared closed by nobody.** It is a `string` on a
  callback payload with no stated value set. Under Property 1 it must be classified, and there is no
  honest classification: it is not free text (Spec C switches on it to render a progress phase) and
  it is not an identifier. Classify it `closed` with an **empty** value set and let Property 2 fail
  it, or classify it and record the values you invented. **Do not invent them silently.** Open item
  S1-11.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation.** The values are Go constants, grouped by
  vocabulary, each with the §7 line that declares it in a comment. `TestVocabulariesAreClosed` is
  the name §11.2 pins; use it.
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add `"fork_detected"` to vocabulary 1. Property 2 must fail.
  2. Add `"server_key_change_unresolved"` to vocabulary 3's reasons. Property 2 must fail.
  3. Add a new string field to `MessageGroup` with no classification. Property 1 must fail.
  4. Add a new exported method returning a closed string — a second `ByJwtState`-shaped one — with
     no classification. Property 1 must fail; if it passes, the scope was struct fields.
  5. Remove `"offline"` from vocabulary 1 but leave it in vocabulary 2. Property 3 must fail.
  6. Remove it from both. Property 3 passes, and Property 1's reachability half must fail because
     `MessageSendability.Reason` can still be `"offline"`… and it cannot, at declaration time,
     because nothing writes it yet. **Record this as an accepted survivor with its reason:** the
     reachability half of Property 2 is unenforceable until s4 writes the first producer, and it is
     assigned there in Task 16's registry. Claiming it is covered here would be the defect.
  7. Delete one health state so vocabulary 3 has nine. Property 4 must fail.
  8. Rename the `evidence_class` vocabulary at one of its two sites. Property 5 must fail.
  9. Compare `MessageSendability.ReasonDetail` against `"rate_limited"` in a non-test file. Property
     6 must fail.
  10. Do the same through a helper function taking the field as a parameter. Property 6 must still
      fail; if it does not, the gate matched a field access rather than deriving the class.
  11. Give `RestoreProgress.Phase` an invented four-value set with no spec citation. Property 7 must
      fail — the citation is part of the declaration.

- [ ] **Step 6: Commit**

---

## Phase C — the callable shape

### Task 10: The 21 listener interfaces, and `Sub` by value in all ten places

**Files:**
- Create: `sdk/message_listeners.go`, `sdk/message_listeners_test.go`

**Interfaces:**
- Consumes: `Sub`, `newSub` (existing, `sdk/sub.go`); `connect.CallbackList` (existing,
  `connect/util.go`); the payload structs of Tasks 3–6; `MessageClient` (Task 1).
- Produces: the 21 interfaces, and the 10 `Add*Listener` declarations on `MessageClient`.

**The 21, measured from §7.7:** `SyncListener`, `HealthListener`, `GroupListener`, `MessageListener`,
`KeyChangeListener`, `IntegrityListener`, `RecordLifecycleListener`, `SendCallback`, `UploadCallback`,
`GroupCallback`, `RestoreCallback`, `DownloadCallback`, `DeviceLinkCallback`,
`DeviceRemovalCallback`, `SyncCallback`, `DirectoryCallback`, `InviteLinkCallback`,
`JoinRequestListener`, `ContactRequestListener`, `BalanceListener`, `BalanceRedeemCallback`.

**The 10 `Add*Listener` declarations, measured from §7:** `AddSyncListener`, `AddHealthListener`,
`AddGroupListener`, `AddJoinRequestListener`, `AddContactRequestListener`, `AddMessageListener`,
`AddRecordLifecycleListener`, `AddKeyChangeListener`, `AddIntegrityListener`, `AddBalanceListener`.
§7 spells every one of them `*Sub`. **All ten are declared `Sub`.**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `Sub` is returned by value.** `sdk/sub.go` declares `type Sub interface{ Close() }`;
  a pointer to an interface is neither gomobile-bindable nor idiomatic; §7.1's own object-model table
  says `Sub` with no star; and **measured 2026-08-30, `) *Sub` occurs zero times in the existing
  `sdk` while every `Add*Listener` returns `Sub`**. The cgo generator will not catch a `*Sub`:
  `classify` unwraps the pointer to the named `Sub`, `Sub` is in `gen.go`'s `behavioralTypes`
  allowlist, and the pointer classifies as a handle — so the ABI gate passes and the AAR build is the
  first thing that fails, on someone else's machine.
  *Refusal owed:* any exported declaration in `package sdk` returning a pointer to an interface
  fails.
  *Scope to derive:* **every** exported function and method in the package, from the type graph —
  not the ten `Add*Listener` names, and not "results whose type is `*Sub`". Derive the class as
  *pointer to an interface type*, so a `*GroupListener` return is caught by the same gate.

  **Property 2 — every listener and callback interface has exactly one method.** §7.7 says
  one-method interfaces are what let the cgo generator map each to a single C function pointer, and
  `classify` sends any non-behavioural `sdk` interface down the callback path. Two methods is two
  function pointers per listener, which is an ABI shape change.
  *Refusal owed:* an interface on this surface with two methods fails.
  *The contradiction, unresolved:* §7.2 says `GroupListener` "additionally delivers
  `SendabilityChanged(groupId string, s *MessageSendability)`", while §7.7 declares it one-method
  under exactly that heading. `GroupEvent.Kind` already carries `"sendability_changed"` and
  `GroupEvent` already has a `Sendability` field, so the event route exists and the second method
  reads as a leftover. **This plan declares one method and files Open item S1-3.** Do not add the
  second on the strength of one sentence in a different section.

  **Property 3 — every payload type a listener method names is declared on this surface.** §7.7 says
  it plainly: a callback payload that is named but not defined is what makes Spec C unbuildable.
  *Refusal owed:* an interface whose method takes an undeclared type fails to compile, which is the
  build. The gate that earns its keep is the other direction: a **declared** payload struct that no
  listener, callback or accessor reaches is dead surface, and it fails.
  *Scope:* reachability from `MessageClient`, derived.

  **Property 4 — a callback carries `(payload, err error)`; a listener carries `(payload)` alone.**
  Measured from §7.7's declaration block on 2026-09-02: **ten** `*Listener` types take one argument
  (`SyncListener`, `HealthListener`, `GroupListener`, `MessageListener`, `KeyChangeListener`,
  `IntegrityListener`, `RecordLifecycleListener`, `JoinRequestListener`, `ContactRequestListener`,
  `BalanceListener`) and **eleven** `*Callback` types take two, the second an `error`
  (`SendCallback`, `UploadCallback`, `GroupCallback`, `RestoreCallback`, `DownloadCallback`,
  `DeviceLinkCallback`, `DeviceRemovalCallback`, `SyncCallback`, `DirectoryCallback`,
  `InviteLinkCallback`, `BalanceRedeemCallback`) — 10 + 11 = the 21 above, and the split is 10/11 and
  not the 7/14 an earlier revision of this plan carried. Like every other count in this plan the two
  numbers are measurements and not gate inputs; the gate derives the partition from the suffix. That
  is not a naming coincidence — it is what makes a stub in Task 11 able to refuse through a ticket at
  all.
  *Refusal owed:* a `*Callback` with no error parameter fails; a `*Listener` with one fails.
  *Scope:* derive from the suffix **and** assert the partition is total — every interface on the
  surface is one or the other, and a third naming ends the run.

  **Property 5 — `Close` on a returned `Sub` is idempotent, and a second `Close` after the client is
  closed does not panic.** The synchronous-and-final unregister of §9.5 rule 4 is s4's and s10's;
  what s1 owes is that the shell's `Sub` does not become a crash when the plan that implements the
  bus arrives.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation.** Registration goes through `connect.CallbackList`
  paired with `newSub`, exactly as every existing view controller does — read one of them before
  writing this. The listeners are registered and never invoked; delivery is s4's.
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Change `AddSyncListener` to return `*Sub`. Property 1 must fail.
  2. Change a **different** exported method to return `*GroupListener`. Property 1 must still fail;
     if it does not, the gate matched the type name `Sub` instead of deriving *pointer to interface*.
  3. Add `SendabilityChanged` to `GroupListener`. Property 2 must fail and must name S1-3.
  4. Add a second method to `SendCallback` instead. Property 2 must fail — the scope is every
     interface on the surface, not the seven listeners.
  5. Declare `MessagePendingPolicy` and reach it from nothing. Property 3 must fail. (It is reached
     from `GroupEvent`, so remove that field for the mutation.)
  6. Drop the `err error` parameter from `GroupCallback`. Property 4 must fail.
  7. Add an `err error` parameter to `SyncListener`. Property 4 must fail.
  8. Rename `BalanceRedeemCallback` to `BalanceRedeemHandler`. Property 4's totality must fail —
     a third naming must end the run rather than be skipped.
  9. Make `Sub.Close` panic on second call. Property 5 must fail.
  10. Register the same listener twice and close one `Sub`. The other must still be registered; a
      gate keyed on "the list is empty" survives a `Remove` that clears everything.

- [ ] **Step 6: Commit**

---

### Task 11: The ABI-stable typed refusals

**Files:**
- Create: `sdk/message_stubs.go`, `sdk/message_stubs_test.go`
- Modify: `sdk/message_errors.go`

**Interfaces:**
- Consumes: `ErrMessageNotImplemented` (Task 1); the callbacks of Task 10; the handles of Task 1;
  the lists of Task 7.
- Produces: a declaration for every §7 method on `MessageClient` that no slice-2 plan implements
  before CP3b, at its final signature.

**Why they exist.** §7 is 135 function and method declarations. Spec C builds against the header s10
generates from them, and §9.2's ABI baseline fails on any symbol change. A call that appears in
release *n+1* is a new symbol; a call that appears in release *n* as a refusal and works in *n+1* is
not. The stubs are what make "the surface is frozen" true before the surface is implemented.

The blocked set includes `RegisterPushChannel` / `UnregisterPushChannel` (§14 item 9; slice A12),
`DirectoryListed` / `SetDirectoryListed` and `LookupPrincipal` (the operator directory is out of
scope per §12.3, and Spec B §9.4 defines only KT proof endpoints, not a name search),
`SetCoverTraffic` (there is no COVER generator in `connect/message`), `StartDiagnosticSession` /
`StopDiagnosticSession` / `DiagnosticSessionEndsAtMs` (no proto arm), `GrantHistory` (no extension —
v1 `RequiredCapabilities` is fixed to `[0xF001, 0xF002]` — no record class, no server op, no
wrap-to-past-epochs primitive), all eight declarations of §7.3a, and the whole §7.5 device-link
surface.

**`HistoryGrants` is blocked for the same reason and is nonetheless NOT in this set**, because it
returns a `*MessageHistoryGrantList` and Property 1's third bucket takes every `*List`-returning
declaration: there is no answer it can give that this plan is willing to write down. It is listed in
Task 16's registry against s6 with Open item S1-23, and Task 11 declares nothing for it. The same
applies to the eleven other `*List` returns of §7, whichever plan owns them.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every §7 declaration on `MessageClient` falls in exactly one of three buckets, and
  the partition is total.** Two buckets are the obvious ones — *implemented by a named plan* and
  *stubbed here*. The third exists because the first draft of this task did not have it and answered
  a question the spec never settled in order to avoid it:
  - **Cannot be refused honestly.** A declaration whose signature has no error channel and whose two
    available answers are both wrong. Concretely, the twelve `*List`-returning methods of §7 (Task 7
    Property 4 lists them; not one has an error return): `[]` is the answer §8.2 forbids — *"Spec C
    would then render 'No conversations yet' to a user whose entire history is intact on the
    server"* — and `null` is the answer Task 7 Property 3's own premise says the consumer throws on.
    **A member of this bucket is not stubbed.** It is listed in Task 16's registry with the plan that
    implements it and with Open item S1-23 against it, and Task 11 declares nothing for it. Picking
    one of the two wrong answers and calling it "the honest answer to 'this build cannot tell you'"
    is what this bucket replaces.
  *Refusal owed:* a §7 method in none of the three buckets fails — and, crucially, so does one in
  **two**. A method in the third bucket that acquires a stub fails, which is what stops the bucket
  from quietly emptying itself back into bucket two.
  *Scope to derive:* the method set of `MessageClient` from the type graph, partitioned against the
  ownership table in Task 16's registry. This is the loop that closes: the registry is the scope
  source, so a method nobody claimed cannot be silently absent. A gate reading a list in this file
  instead is the ledger-21 shape and must be rejected in review.

  **Property 2 — a stub refuses; it never succeeds emptily.** §8.2 already states the principle for
  a different case: `Groups()` and `History()` **must not** return empty when the store could not be
  opened, because Spec C would then render "No conversations yet" to a user whose entire history is
  intact on the server. The same reasoning applies to a call this build cannot make.
  *The refusal each signature shape owes:*
  - returns `error` → `ErrMessageNotImplemented`, wrapped with the call's own name.
  - returns `(T, error)` → the zero `T` and the same error.
  - returns `*MessageSendTicket` → a ticket that completes by invoking the supplied callback with a
    nil payload and `err = ErrMessageNotImplemented`. Every `*Callback` interface carries an `error`
    second parameter (Task 10, Property 4), so this needs no new vocabulary value and tells no lie.
    **The delivery happens on a goroutine, and that is required rather than tolerated.** §9.5 rule 2
    is *"Callbacks arrive on an arbitrary Go goroutine, never the UI thread"*; a stub that invokes
    the callback inline delivers it on the caller's thread, which through the C ABI is the thread
    that called `urmsg_client_*` — the UI thread on Windows. So the inline form is not the safe
    version of this stub, it is the one that violates §9.5. Property 4 carves the goroutine out
    explicitly and bounds it; read the two together, because as first written they contradicted each
    other and the only reading that satisfied both broke rule 2.
  - returns a `*List` → **no stub at all.** This is Property 1's third bucket, and the reason is
    that the plan cannot have both halves of what it previously asserted. Task 7 Property 3 justifies
    sixteen shadowing `MarshalJSON` methods on the premise that the consumer **throws** when it reads
    `null` as an array; a `*List` stub returning nil marshals to exactly that `null`. `null` is
    therefore not "the honest answer to 'this build cannot tell you'" — under this plan's own premise
    it is a crash — and `[]` is the lie §8.2 names. §7 gives these twelve declarations no third
    answer, and **the spec is silent on which of the two it wants**: §9.2 says only that lists cross
    as JSON strings, and neither Spec A nor Spec C says what `null` does on the C++ side. Open item
    S1-23. Do not resolve it by picking one and writing it down as a reading.
  - returns `bool` → `false` **only where `false` is a true statement**. `DirectoryListed()` is:
    nothing is listed. `HasIdentity()` is not this task's.
  - returns `string` → the empty string is a lie for `ThisDeviceId()`, and there is no channel to say
    so. Record it rather than dressing it up; see Open item S1-6.

  **Property 3 — a stub's signature is the final signature.** Byte-for-byte what the implementing
  plan will declare, so replacing the body is not an ABI change.
  *Refusal owed:* a stub returning `error` where §7 declares `*MessageSendTicket` fails.

  **Property 4 — a stub refuses the same way twice, and never partially.** Calling a stub must not
  mutate any state that outlives the call or is observable to another call, must not register
  anything, and must be safe concurrently.
  *The class, derived:* **state reachable after the call returns.** Package-level variables, fields
  on the receiver, an entry in a `CallbackList`, an open file or socket, a retained reference to the
  caller's callback. Derive it over the AST — *a stub body writing to package or receiver state, or
  retaining a reference beyond the call* — rather than reading the bodies.
  *The one carve-out, and it is required rather than tolerated:* **the single delivery goroutine of
  Property 2's ticket refusal.** §9.5 rule 2 forbids delivering a callback on the caller's thread, so
  a ticket stub that refuses inline is the version that breaks the spec; the goroutine is what makes
  it legal. As first written this property banned every goroutine and Property 2 required one, and
  the only construct satisfying both — inline delivery — violates §9.5 rule 2. The carve-out is
  bounded so it cannot become a loophole: **exactly one** goroutine per call, which performs one
  callback invocation and exits, retains no reference to the client, is reachable from no field on
  the client or the ticket, and holds no lock. A gate asserting "no goroutine" is wrong; a gate
  asserting "no *retained* state" is the one that catches both a counter and a leaked worker.
  *Residual:* §9.5 rule 4 makes unregister synchronous and final for a `Sub` — *"`urmsg_release(sub)`
  does not return until no callback is executing and none will start"* — and says nothing about
  releasing a `*MessageSendTicket` whose refusal is in flight, though §9.2 makes the ticket a handle
  released by the same `urmsg_release`. Filed as **Open item S1-24**, assigned to s10, which writes
  the release path. In s1 the window is one callback long and touches no shared state, which is why
  the plan can proceed without ruling it; it will not stay that way once s9 sends anything.

  **Property 5 — the closed vocabularies have no value for "this build does not implement this".**
  `GroupResult.Reason`'s 22 values — counted from §7.7's block, which states no count (Task 4
  Property 4) — include `"internal"`, and answering `"internal"` to `CreateInviteLink` is a false
  statement about what happened. This is the same gap Spec B has at
  §4.5 (ledger open item 8), and it has the same two wrong candidates. **Do not add a value.**
  Because Property 2 routes every ticket refusal through the callback's `err` rather than through a
  `GroupResult`, no stub needs the missing value today — but the moment a real implementation must
  say "not on this server" it will. Open item S1-6.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Delete one stub. Property 1 must fail, naming the method.
  2. Add a stub for a method the registry says s4 implements. Property 1 must fail on the "both"
     half; a gate checking only "every method has an owner" survives this.
  3. Give `HistoryGrants` a stub of any shape. Property 1 must fail on the third bucket: a
     `*List`-returning declaration is listed as unrefusable and a stub for it is the "in two buckets"
     half of the refusal. A gate that only asks "is every method owned or stubbed" survives this.
  3a. Make that stub return an empty `*MessageHistoryGrantList`. Property 1 must still fail, and for
     the same reason — the point is that neither answer is available, not that one of them is worse.
  4. Make `RegisterPushChannel` return `nil`. Property 2 must fail.
  5. Make `CreateInviteLink` return a nil ticket without invoking the callback. Property 2 must
     fail — a caller waiting on a callback that never fires is worse than an error.
  6. Make it invoke the callback with a non-nil `GroupResult{Reason: "internal"}` and a nil error.
     Property 2 must fail; this is the mutation Property 5 exists to make visible.
  7. Change `RevokeInviteLink`'s return from `error` to `bool`. Property 3 must fail.
  8. Have a stub record its call count in a package variable. Property 4 must fail.
  9. Have it record the count on the receiver instead. Property 4 must still fail; if it does not,
     the class was "package state" and the scope should have been "any state".
  9a. Make the ticket stub invoke the callback **inline** instead of on the delivery goroutine.
     Property 2 must fail, naming §9.5 rule 2. A gate written as "a stub starts no goroutine" rewards
     this mutation, which is why Property 4's class is retained state and not goroutines.
  9b. Have the delivery goroutine park instead of exiting, or store the ticket on the client so it
     outlives the call. Property 4 must fail — the carve-out is one goroutine, one delivery, no
     retained reference, and a gate that exempts "goroutines" wholesale passes both of these.
  10. Call every stub twice concurrently under `-race`. No stub may report a race or differ between
      the two calls.

- [ ] **Step 6: Commit**

---
## Phase D — the gates

### Task 12: `sdk/surface` — the nested module and the classification model

**Files:**
- Create: `sdk/surface/go.mod`, `sdk/surface/go.sum`, `sdk/surface/surface.go`,
  `sdk/surface/surface_test.go`
- Modify: `sdk/dependency_graph_test.go`

**Interfaces:**
- Consumes: `golang.org/x/tools/go/packages` (in this module only); `go/types`.
- Produces:
```go
package surface   // module github.com/urnetwork/sdk/surface

type Kind int
type Info struct{ Kind Kind; Reason string }
type Finding struct{ Path string; Detail string }   // Path names how the type was reached

func Classify(t types.Type) Info
func WalkReachable(pkg *packages.Package, roots []string) ([]Finding, error)
```

**Why a module and why a child.** `connect/CODESTYLE.md` forbids a package importing its own
subpackage, and `internal/` does not exempt it: `internal/` controls visibility, not direction. So
`sdk` cannot import `sdk/surface`. The walk therefore lives in the child and *loads* the parent with
`go/packages` — loading is not importing and produces no edge in `go list -deps`. And it is a
separate module because `golang.org/x/tools` must not enter the root module's graph, which is the
graph `gomobile bind` resolves for the AAR and the Apple framework. `build`, `cgo` and `js` exist for
exactly that reason and this is the fourth of the same kind.

**Three traps, all verified by reading the code — the first two on 2026-08-30, the third on
2026-09-02.**

1. `sdk/dependency_graph_test.go` holds a **hardcoded** list of artifact modules —
   `build/go.mod`, `cgo/go.mod`, `js/go.mod` — and `TestSdkArtifactModulePionVersionsMatchRoot`
   silently excludes anything not in it. `surface/go.mod` must join that list **in the same commit
   that creates it**, or the new module's dependency graph is unchecked from birth.
2. The same test's helper `t.Fatal`s on a `go.mod` that contains **no** `github.com/pion/` lines
   ("contains no Pion module versions"). `cgo`, `build` and `js` each carry 16 pion lines, and they
   carry them because each requires `github.com/urnetwork/sdk`, whose graph drags them in as
   indirects. A `surface/go.mod` requiring only `golang.org/x/tools` has zero and would fail the
   moment it joined the list. So `surface` must `require github.com/urnetwork/sdk v0.0.0`, and that
   requirement must be **anchored by a real import** or `go mod tidy` drops it. The anchor is the
   walk's test importing `github.com/urnetwork/sdk` — child importing parent, which CODESTYLE
   explicitly allows.
3. **The nested module needs four `replace` directives, not one.** A `replace` applies only from the
   main module; a nested module inherits none of its parent's. `sdk/go.mod` carries three sibling
   replaces — `connect`, `glog`, `goidenticons` — so a `surface/go.mod` that replaces only
   `github.com/urnetwork/sdk` cannot resolve the parent's own requirements and does not build.
   Verified 2026-09-02 by reading all three existing nested modules: `cgo/go.mod`, `build/go.mod` and
   `js/go.mod` each carry the identical four, spelled

   ```
   replace github.com/urnetwork/sdk => ..
   replace github.com/urnetwork/connect => ../../connect
   replace github.com/urnetwork/glog => ../../glog
   replace github.com/urnetwork/goidenticons => ../../goidenticons
   ```

   Copy that block. Note the parent is `..` and not `../`; match the three siblings rather than
   inventing a fourth spelling, because `dependency_graph_test.go` compares these modules to each
   other.

`sdk/test.sh` picks the module up with no change: its submodule loop is
`find . -mindepth 2 -maxdepth 2 -name go.mod` over modules containing `_test.go`. Verified by
reading it.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `Classify` is total.** Every `types.Type` it is handed produces a `Kind`, and the
  only way to produce "unmappable" is the explicit bad kind with a non-empty `Reason`. A zero-value
  `Kind` returned for an unrecognised type is the vacuous-gate shape: an unmappable type would
  classify as whatever `Kind(0)` happens to be.
  *Refusal owed:* a type the model does not recognise must produce bad-with-a-reason, and the reason
  must name the type.

  **Property 2 — the walk's reachability is derived, and so is its root set.** §9.2's table says
  the messaging generator walks "only types reachable from `MessageClient` (an explicit allowlist in
  `gen.go`)". An explicit allowlist is a list, and a list of reachable types is a list that will be
  one type behind. Everything below a root is **reached**: through method parameters and results,
  through struct fields, through `*List` element types, and through the method signatures of listener
  interfaces.
  **The roots are derived too, and the first draft of this plan is the reason.** That draft
  enumerated four — `MessageClient`, `NewMessageClient`, `GenerateMessageSeedphrase`,
  `ValidateMessageSeedphrase`, `MessageProtocolLimitsValues` — and **omitted the three exported free
  functions this very plan creates in `sdk/message_vocab.go`**: `MessageVocabularies`,
  `MessageVocabularyValues` and `MessageVocabularyContains`. All three cross gomobile and the ABI,
  all three return or take `*StringList`, and under the enumerated root set all three fall outside
  the plan's own exportability walk. That is ledger 21 committed inside the task written to prevent
  it, and the fix is the one the ledger gives every time: a wider derivation, not a longer list.
  *The derivation:* a root is `MessageClient`, **plus every exported package-level function declared
  by a `message_*.go` file in `package sdk`**, obtained from the loaded package. A free function
  added by a later task is a root by existing. Measured on this plan's own output that set is eight —
  the five above plus the three vocabulary functions — and eight is the count the gate reports, never
  the count it is given.
  *Scope, stated separately per R3:* the derivation rule is the scope; the eight names are the
  content, and they are committed as a root manifest so an addition is a visible diff, exactly as
  Task 3's field manifest is. The gate fails if the derived set and the manifest disagree in either
  direction.
  *Refusal owed:* a struct reachable only as a field of a field of a root must be walked. A walk that
  stops at depth one passes a surface with a `map[string]string` two levels down.
  *Scope, stated separately:* the roots are enumerated (that is the content); the reachable set is
  derived (that is the scope). Say which is which in the header.

  **Property 3 — the walk reports every finding and fails once.** §7.8 says the test "fails on the
  first unmappable type". A gate that stops at the first hides the rest, and this surface has 44
  structs: one fix per CI round is a week of rounds. **This plan disagrees with §7.8's wording
  deliberately** and says so in the gate's header: collect all findings, report all, fail once.

  **Property 4 — `golang.org/x/tools` is absent from the root module's graph.** `go list -m all` from
  `sdk` must not name it.
  *Refusal owed:* adding it to `sdk/go.mod` fails.

  **Property 5 — `surface/go.mod` is in the artifact-module list and its pion versions match root.**
  The existing `TestSdkArtifactModulePionVersionsMatchRoot`, extended.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Return `Kind(0)` for an unrecognised type instead of bad. Property 1 must fail.
  2. Return bad with an empty `Reason`. Property 1 must fail — an unmappable type with no reason is
     a coverage report entry with no reason, which §9.2 calls a generator error.
  3. Stop the walk at depth 1. Property 2 must fail on a type reachable only at depth 3.
  4. Stop the walk at struct fields but not at interface method signatures. Property 2 must fail.
  5. Remove `MessageProtocolLimitsValues` from the roots. Property 2 must fail — `MessageProtocolLimits`
     is reachable from nothing else.
  5a. Add a new exported free function to `sdk/message_vocab.go` and leave the root manifest alone.
     Property 2 must fail on the derivation half. A gate whose roots are enumerated survives this,
     and surviving it is how the three vocabulary functions fell outside this plan's own walk.
  5b. Delete `MessageVocabularyValues` from the root manifest while leaving the function. Property 2
     must fail on the other direction.
  6. Return after the first finding. Property 3 must fail.
  7. Delete `surface/go.mod` from `dependency_graph_test.go`'s list. Property 5 must fail. **If it
     passes, that is the trap:** the test's own shape is to iterate a list, so a missing entry is
     invisible unless the gate also asserts the list's membership. Write it so it does.
  8. Change one pion version in `surface/go.mod`. Property 5 must fail.
  9. Remove `require github.com/urnetwork/sdk` from `surface/go.mod` and run `go mod tidy`. Property
     5 must fail with "contains no Pion module versions" — and the failure message must be
     recognisable as this trap rather than as a broken test.
  10. Add `golang.org/x/tools` to `sdk/go.mod`. Property 4 must fail.
  11. Delete `replace github.com/urnetwork/goidenticons => ../../goidenticons` from
      `surface/go.mod`. The module must fail to build, and the failure must be recognisable as the
      missing replace rather than as a broken gate — this is trap 3, and it is the same error the
      root module currently produces for the same reason.

- [ ] **Step 6: Commit**

---

### Task 13: The drift gate — `sdk/surface` and `sdk/cgo/gen` cannot silently disagree

**Files:**
- Create: `sdk/surface/generator_drift_test.go`

**Interfaces:**
- Consumes: `Classify` (Task 12); `go/ast`, `go/parser`.
- Produces: no symbol. It produces the honesty of Task 14's claim.

**§7.8's claim cannot be met literally, and the plan says so rather than pretending.** §7.8 says
`TestMessageSurfaceIsExportable` "runs the same walk the generator does". It cannot: the walk lives
in `sdk/cgo/gen`, which is `package main` in the separate module `github.com/urnetwork/sdk/cgo`. A
`package main` cannot be imported at all, and the root module importing the `cgo` module would
invert the dependency besides. So `sdk/surface` is a **re-derivation** of the generator's mapping
model, and this task is the gate that keeps the two from drifting. What it can prove and what it
cannot are both stated in its header.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the gate reads a real table, and proves it.** Parse `sdk/cgo/gen/gen.go` with
  `go/ast` and extract **seven** tables: `behavioralTypes`, `skipTypes`, `skipTypePatterns`,
  `keepTypes`, `skipFuncs`, `skipFuncPatterns` and `skipMethods`. An earlier revision of this task
  named six and omitted **`skipFuncPatterns`**, which is the one table Task 7 Property 5's reasoning
  actually rests on: the `^New[A-Za-z0-9]*List$` pattern that makes a list constructor invisible to
  the ABI lives there and nowhere else (verified 2026-09-02 at `gen.go:107`). Two of the seven are
  `[]*regexp.Regexp` and not `map[string]…`, so the gate must handle both composite-literal shapes;
  a gate that only knows the map shape reads zero from those two and, under the refusal below,
  reports it as a defect in the generator rather than in itself.
  *Refusal owed — and it is "did not find", not "found nothing".* An earlier revision of this task
  demanded that reading **zero** entries from any named table fail. That property is **red against
  the unmutated tree**: `keepTypes` is declared `var keepTypes = map[string]bool{}` at `gen.go:92`
  and is legitimately empty — it exists to carve names out of `skipTypePatterns` and nothing has
  needed carving yet. A gate red on arrival is not a strict gate; it is a gate that gets deleted or
  loosened in its first hour, and loosening it to "stop looking" is how the vacuous version arrives.
  The property that is true of an empty table and false of a truncated one:
  1. **Every one of the seven declarations is located in the AST**, by name, in the file Property 2
     found. A named table the gate cannot locate fails, and that is the failure that catches a
     rename, a move, and a text-matching gate that read nothing.
  2. **The gate reports the size it read for each**, and the aggregate across the seven is non-zero.
     Zero aggregate means it parsed nothing at all.
  3. **A table's emptiness is a fact it reports, not a verdict it passes.** `keepTypes` reads 0
     today; that is recorded in the gate's header with the date it was measured, so an entry
     appearing there is a visible diff rather than a silent change to what `skipTypePatterns` covers.
  Truncation is caught where truncation matters — Property 3, which asserts the comparison it ran was
  non-vacuous. This is the most important paragraph in the task. This project has already had 84
  source anchors pass vacuously on Windows because `core.autocrlf=true` made every text match miss,
  and the ledger's words for it are worth repeating: *that is not a gate failing; it is a gate
  reporting the clean run of a complete gate having read nothing.* `sdk` has no `.gitattributes`
  today (Task 15 adds one) and the same system-scope autocrlf applies to it.

  **Property 2 — the gate finds the generator by shape, not by path.** Locate the file by searching
  for the Go source that declares `behavioralTypes`, so a rename or a move fails loudly instead of
  reading nothing.
  *Refusal owed:* moving `gen.go` must fail the gate, not skip it.

  **Property 3 — the two models agree for every name both know, and the comparison proves it was not
  empty.** For every type name in `behavioralTypes`, `surface.Classify` must produce the handle kind;
  for every name in `skipTypes`, bad. And every **marker-derived** messaging behavioural type
  (Task 14) must appear in `sdk/cgo-message`'s `behavioralTypes` once s10 exists, and must **not**
  appear in `sdk/cgo`'s copy, which is the VPN generator and whose ABI baseline must not move.
  *Refusal owed:* a marker-derived messaging name appearing in `sdk/cgo/gen/gen.go`'s
  `behavioralTypes` fails — that would put a messaging export in `URnetworkSdk.dll`, which §9.1
  exists to prevent.
  **`Sub` is the exception, and it must be spelled out or this property is red today.** §9.2's table
  gives the messaging generator four behavioural types — `MessageClient`, `MessageSendTicket`,
  `MessageDeviceLinkSession`, `Sub` — and §7.1's object-model table lists `Sub` as a behavioural
  handle, *"existing sdk type; returned by every `Add*Listener`"*. `Sub` is therefore a messaging
  behavioural type **and** already present in `sdk/cgo/gen/gen.go`'s `behavioralTypes` (verified
  2026-09-02 at `gen.go:50`), because it is shared with the VPN surface. Written as "no messaging
  name may appear in the VPN table", this refusal fails on `Sub` against an unmutated tree. Scoping
  it to the **marker-derived** set is what makes it true, and it is true for a reason rather than by
  construction: `Sub` cannot carry the marker at all (Task 14 Property 1), so the two sets differ by
  exactly `Sub` and the gate asserts that difference rather than assuming it.
  *Anti-vacuity, and this is where truncation is caught:* the gate must assert that the number of
  names it compared equals the sizes Property 1 read, and that `"Sub"` is among them. Emptying
  `behavioralTypes` then fails here — a comparison over zero names is a clean run of a gate that
  checked nothing, which is the shape Property 1 declines to catch by banning empty tables.

  **Property 4 — what this gate does not prove is written down.** An AST comparison of the
  generator's **tables** does not prove its **logic** agrees: `classifyNamed`'s branch order, the
  `Id`/`Time` special cases and the `jsonable` recursion are re-derived and unchecked. Name the
  residual in the header. A gate that overstates its reach is worse than one that states its limit,
  because the limit is what the next reader plans around.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Point the gate at a file that does not exist. Property 1 must fail; it must not pass with an
     empty table.
  2. Point it at a file with an **empty** `behavioralTypes` map. **Property 1 must pass** — the
     declaration is present and its size is 0, which is a fact and not a verdict — and **Property 3
     must fail** on anti-vacuity, because it compared zero names and `"Sub"` was not among them.
     Run this one and check both halves; getting only the second is the point of the split.
  2a. Delete the `keepTypes` declaration from the file entirely. Property 1 must fail on "did not
     find". Leave it declared and empty, as it is today, and Property 1 must pass. These two
     mutations together are what distinguish the repaired property from the one that was red on
     arrival, so run them adjacently.
  2b. Delete `skipFuncPatterns`. Property 1 must fail. It is in the seven because Task 7 Property 5
     depends on it, and a six-table gate reports clean while the pattern it reasons from is gone.
  3. Rename `gen.go` to `generate.go`. Property 2 must fail, not skip.
  4. Convert `gen.go` to CRLF line endings. Property 1 must still pass if the gate is AST-based, and
     must fail if it was written with `strings.Contains`. Run this one; it is the cheapest possible
     check that the gate is not text-matching.
  5. Remove `"Sub"` from `behavioralTypes`. Property 3 must fail.
  6. Add `"MessageClient"` to `sdk/cgo/gen/gen.go`'s `behavioralTypes`. Property 3 must fail.
  7. Change `surface.Classify` to return json for a name in `behavioralTypes`. Property 3 must fail.

- [ ] **Step 6: Commit**

---

### Task 14: `TestMessageSurfaceIsExportable`, and why it is stronger than the generator

**Files:**
- Create: `sdk/surface/behavioral.go`, `sdk/surface/message_surface_test.go`

**Interfaces:**
- Consumes: `WalkReachable`, `Classify` (Task 12); the marker method (Task 1).
- Produces:
```go
// the three marker-derived handles, plus Sub, which cannot carry the marker.
func BehavioralTypes() []string       // the full §9.2 set: MarkerDerivedHandles() + subExceptions
func MarkerDerivedHandles() []string  // DERIVED from the marker method, not maintained
```

**Three reasons this test must be stronger than the generator, all verified in source.**

1. **The generator does not walk struct fields.** `gen.go:406` returns `kindJson` for any named
   struct the moment it sees one. A field holding a handle type, a func type or a map therefore
   passes the generator and fails at JSON time, at runtime, in Spec C. §7.8's claim that the test
   "runs the same walk" would make the test *weaker* than advertised, and a vacuous gate on this
   project has already cost real work.
2. **The generator will not catch `*Sub`.** `classify` unwraps `*types.Pointer` to the named `Sub`,
   `Sub` is in the hand-maintained `behavioralTypes` allowlist, and the pointer classifies as a
   handle. Pointer-to-interface is not gomobile-bindable, so the ABI gate passes and the AAR build is
   what breaks.
3. **The gomobile validation cannot run at PR time.** It is a `grep -Ri '// skipped'` over the
   sources jar produced *inside* `build_android` in `sdk/build/Makefile`, which needs an Android NDK,
   `gomobile`, `jar`, `unzip` and `checksec`. Verified by reading the Makefile. §11.5 calls it a
   CI gate; on this project's machines it is not one. **This Go-level walk is the only enforcement
   that actually runs**, and the header must say so, because a reader who believes §11.5 will assume
   this test is a convenience.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the handle set is marker-derived, plus exactly one name that cannot be.** Ask the
  loaded package which named types declare the unexported marker method of Task 1; that is
  `MarkerDerivedHandles()`, and it is three.
  **§9.2's messaging handle set is four, and the fourth is `Sub`.** §9.2's table names
  `MessageClient`, `MessageSendTicket`, `MessageDeviceLinkSession`, `Sub`; §7.1's object-model table
  lists `Sub` as a behavioural handle, *"existing sdk type; returned by every `Add*Listener`"*.
  **`Sub` cannot carry Task 1's marker**, and the reason is not stylistic: `sdk/sub.go` declares
  `type Sub interface{ Close() }`, so a marker on `Sub` is a method added to an **interface's** method
  set, not to a struct. That breaks every existing implementor — `simpleSub` in the same file, and
  whatever the VPN view controllers return — and it changes the shape of a type that is already in
  `sdk/cgo/gen/gen.go`'s `behavioralTypes` and therefore already in `URnetworkSdk.dll`'s shipped ABI.
  The marker is the mechanism for *this plan's new* handles; it was never available for the one that
  predates it.
  So `BehavioralTypes()` is `MarkerDerivedHandles()` plus a declared exception set, and the exception
  set is gated rather than trusted: it has **exactly one** member, that member is `"Sub"`, the reason
  is written beside it in source, and the type it names must exist in the loaded package and be an
  interface. A second hand-maintained entry fails, which is what stops the exception becoming the
  second allowlist the marker exists to abolish.
  *Refusal owed:* a fourth *struct* handle added without the marker is absent from the set and every
  gate that depends on it fails. A fifth added *with* the marker is present by existing, and no list
  needs editing. That asymmetry is the whole reason for the marker — and `Sub` is the standing
  reminder that the asymmetry has one exception, which is why the exception is counted rather than
  assumed.
  *Scope:* the package, from the type graph, for the derived part; a one-member declared set, gated
  on its size and its contents, for the exception. Say which is which in the header, per R3.

  **Property 2 — every type reachable from the roots is mappable, and struct fields are walked.**
  A field whose type is a handle, a func, a map, or a slice of anything but `byte` fails, at any
  depth.
  *Refusal owed:* `MessageEntry` gaining a `map[string]string` fails; gaining a `*MessageClient`
  fails; gaining a `func()` fails.

  **Property 3 — no exported declaration returns a pointer to an interface.** Task 10's Property 1
  states it for the ten `Add*Listener`s; here it is stated over the reachable surface, because the
  generator cannot see it and gomobile cannot run.
  *Refusal owed:* `*Sub`, `*GroupListener`, `*error` — all fail, by class rather than by name.

  **Property 4 — every finding is reported.** Task 12's Property 3, exercised here at the surface's
  real size. A CI round that names one of forty problems is thirty-nine rounds away from green.

  **Property 5 — the walk is not vacuous.** Assert that the loaded package produced a non-trivial
  reachable set before judging it. A `packages.Load` that fails to type-check returns a package with
  no types and no error worth noticing, and every "is this mappable" question then answers yes.
  *Refusal owed:* a run that reaches fewer types than the surface obviously has must fail as a
  broken gate, not pass as a clean one.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add `Extra map[string]string` to `MessageEntry`. Property 2 must fail.
  2. Add `Owner *MessageClient` to `MessageGroup`. Property 2 must fail — a handle inside a JSON
     struct is the exact case `gen.go:406` waves through.
  3. Add `OnDone func()` to `SendResult`. Property 2 must fail.
  4. Add `Tags []string` to `MessageMember`. Property 2 must fail; `[]byte` is the only permitted
     slice.
  5. Add the same `map` field to a struct reachable only at depth three. Property 2 must still fail.
  6. Change `AddSyncListener` to return `*Sub`. Property 3 must fail here as well as in Task 10 —
     two independent gates over the same rule is deliberate, because Task 10's is scoped to `sdk`
     and this one is scoped to reachability, and neither subsumes the other.
  6a. Add `"Sub"` a second time to the exception set, or add a second name to it. Property 1 must
     fail on the exception set's size. An exception set that can grow is the hand-maintained
     allowlist the marker was introduced to replace.
  6b. Add the marker method to the `Sub` **interface**. The package must fail to compile, or
     Property 1 must fail — either outcome is acceptable and both must be recorded, because this is
     the mutation that shows why `Sub` is an exception rather than an omission.
  7. Remove the marker from `MessageSendTicket`. Property 1 must fail, and Property 2 must then
     *also* fail because the ticket is now a struct with unexported fields reachable from
     `MessageClient` — check that the second failure is reported and not masked by the first.
  8. Break `packages.Load` (point it at a nonexistent package). Property 5 must fail as a broken
     gate. This is the most valuable mutation in the plan: it is the one that distinguishes "the
     surface is clean" from "the gate read nothing".
  9. Make the walk return after the first finding. Property 4 must fail.

- [ ] **Step 6: Commit**

---

### Task 15: CI — the `sdk` repository has no workflows at all

**Files:**
- Create: `sdk/.gitattributes`, `sdk/.github/workflows/messaging-surface.yml`

**Interfaces:**
- Consumes: every gate of Tasks 1–14.
- Produces: the first `.github` directory this repository has ever had.

**Verified 2026-08-30: `sdk` has no `.github`, no `.gitattributes`, and no CI of any kind.**
`connect` has all three. Every gate above is worth exactly as much as the thing that runs it.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `.gitattributes` pins line endings and the working-tree encoding.**
  `core.autocrlf=true` is set at system scope on the Windows boxes this project is developed on. Two
  things break quietly: `gofmt -l` reports every file as unformatted, so it stops distinguishing a
  real formatting error from a fresh clone; and any gate that matches on source text matches nothing.
  This has already happened on this project, to 84 source anchors. `connect/.gitattributes` and
  `msgrepo/.gitattributes` both exist for this reason; `sdk` needs the same treatment for `*.go`,
  `go.mod`, `go.sum`, `*.yml` and — carrying §11.4's `encoding-guard` line verbatim —
  `*.md text working-tree-encoding=UTF-8 eol=lf`.
  *Refusal owed:* the encoding-guard job must fail if that line is absent, and must fail on any
  occurrence in `**/*.md` of the four byte runs double-encoded UTF-8 produces (U+00E2 U+20AC,
  U+00C2 U+00A7, U+00C3 U+00A2, U+00C3 U+201A). Written against codepoints, never against literal
  corrupted text, so the check's own source does not trip it.

  **Property 2 — the workspace is checked out before anything is built, and the checkout names a
  repository AND a ref for each sibling.** `sdk`'s `go.mod` carries three `replace ../` directives —
  `connect`, `glog`, `goidenticons` — and **verified 2026-08-30 the build fails without them**:
  `reading ../goidenticons/go.mod: The system cannot find the path specified`. A workflow that checks
  out only `sdk` is a workflow that is red for a reason unrelated to any change. `sdk/surface` needs
  the same three at `../../` (Task 12, trap 3).
  **The ref is not optional, and an earlier revision of this task omitted it.** Everything this plan
  builds against in `connect` — `connect/mls`, which Task 3's limits agreement imports, and
  `connect/message`, which Task 16's pending pins probe — exists **only on `connect`'s
  `beta/message` branch**. Measured 2026-09-02: `connect` at `origin/main` holds **0** files under
  `mls/` and **0** under `message/`; at `beta/message` it holds **636** and **74**. So an
  `actions/checkout` of `urnetwork/connect` at its default branch produces a tree in which
  `connect/mls/errors_lifecycle.go` does not exist, and the job fails on a missing package rather
  than on anything a contributor changed. Every sibling checkout step therefore names
  `repository:` and `ref:` explicitly, and `connect`'s `ref:` is `beta/message`.
  *Refusal owed:* a missing sibling fails with a message naming **which** sibling and **which ref**
  it expected, not with a raw module or import error.
  *This is a pin, and it expires.* `beta/message` is a moving branch and the day `connect`'s
  messaging work reaches `main` the pin is wrong rather than merely stale. Record it as a row in
  `sdk/slice2-pending-pins.txt` (Task 16) so the gate asks for it to be re-taken, and record it in
  the registry beside the other cross-repository assumptions.

  **Property 3 — the jobs run the gates this plan built, in both modules.** The root module's
  messaging tests, and `sdk/surface`'s. Plus `go vet` and `gofmt -l` over the messaging files.
  Race detector on, matching `sdk/test.sh`.

  **Property 4 — what is not covered is named in the workflow file itself.** §11.4 lists nine
  blocking `sdk` jobs and this plan owns two of them. Unowned, and each must be written into the
  workflow's header comment with its owner: `unit` (the full suite, which needs the
  `urnetwork-workspace` treatment for its timing-sensitive groups), `layering`
  (`sdk/layering_test.go` does not exist — see Open item S1-13; assigned to s5, which introduces the
  one legitimate `sdk` → `connect/mls` edge), `forbidden-crypto` (assigned to s3, which is the first
  plan to touch key material), `gomobile-validate` (Property 3 of Task 14 — it cannot run at PR time
  and someone must own deciding whether it ever will), `abi-baseline` + `smoke` + `smoke_hpp` +
  `build-matrix` (all s10), and `e2e` (s9, and it needs Spec B's server binary). A list of unowned
  gates in a comment is not a gate; it is the thing that stops the next reader assuming they are
  covered.

- [ ] **Step 2: Run to verify it fails** — push the branch and watch the workflow go red for the
  stated reason. A workflow verified only by reading it is a workflow that has not run.
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Delete the `*.md` line from `.gitattributes`. Property 1 must fail.
  2. Introduce one double-encoded sequence into a markdown file. Property 1 must fail.
  3. Remove the `goidenticons` checkout step. Property 2 must fail with a message naming it.
  3a. Change `connect`'s `ref:` from `beta/message` to its default branch. Property 2 must fail with
     a message naming the branch, not with `package github.com/urnetwork/connect/mls is not in std`.
     This is the mutation that proves the ref is pinned rather than defaulted, and it is the one an
     earlier revision of this task could not have failed, because it named no ref at all.
  4. Break one messaging test. Property 3 must fail — confirm the job actually runs the root module
     and not only `surface`.
  5. Break a test in `sdk/surface` only. Property 3 must fail; a job that runs `go test ./...` from
     the repository root does **not** enter nested modules, and this mutation is what proves the
     workflow does.
  6. Delete the unowned-gates comment. Property 4 must fail — assert its presence, because the
     comment is the deliverable.

- [ ] **Step 6: Commit**

---

## Phase E — the cross-plan contract

### Task 16: The slice-2 interface registry, and the pending-pin gate

**Files:**
- Create: `msgrepo/docs/plans/2026-08-30-slice2-interface-registry.md`
- Create: `sdk/slice2-pending-pins.txt`, `sdk/message_registry_test.go`

**Interfaces:**
- Consumes: everything this plan produced.
- Produces: the ownership map that Task 11's Property 1 derives its scope from, and the pending-pin
  gate.

**Why this is in this plan and not after it.** `docs/plans/2026-08-12-slice1-interface-registry.md`
is 2,169 lines and normative — *where this file and a plan disagree, this file wins and the plan is
amended* — and it is what let eight plans compile against each other for months. Slice 2 has twelve
plans and no registry. Writing it after s1 means eleven plans are drafted against eleven readings of
§7.

**Where the pending-pin table lives, and why it is not in the registry.** A markdown table in
`msgrepo` and a Go gate in `sdk` that must "agree" is an ungated agreement claim, and this project
already carries one: ledger open item 7 records that §12.1 says "a test in the message-server repo
asserts the allowlist" and no such test exists. So the machine-readable table is
`sdk/slice2-pending-pins.txt`, that file is the **source**, and the registry cites it by path
instead of restating it. One copy, one gate, nothing to drift.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the registry's ownership map is total over §7.** Every one of §7's 135 function and
  method declarations, and every one of its 77 type declarations, has exactly one owning plan or is
  listed as deferred with the reason. Measured: 212 declarations.
  *Refusal owed:* Task 11's Property 1 derives its scope from this map, so a declaration with no
  owner and no stub already fails there. What this task adds is the other direction — a map entry
  naming a declaration §7 does not contain fails.

  **Property 2 — every pending pin is still pending, and the gate says so by looking.** For each row
  in `sdk/slice2-pending-pins.txt`, the named symbol must be **absent** from the named package.
  One row is not a symbol: **`connect` is pinned to its `beta/message` branch** (Task 15 Property 2),
  because `connect/mls` and `connect/message` exist on no other ref — measured 2026-09-02, 636 and 74
  files there against 0 and 0 on `main`. That row's condition is the inverse of the others: it is
  still pending while `mls/` is **absent** from `connect`'s default branch, and it expires — asking
  for the CI ref and this plan's cross-repository assumptions to be re-taken — the day it is not.
  When m1 lands `StorageRoot`, or p7 Task 21 lands `SuccessionQuorum`, the gate **fails** and asks
  for the pin to be taken. That is the point: a pin that expires silently is a stale reference for
  the next reader.
  *Refusal owed:* a row whose symbol has appeared fails, naming the row and the consuming plan.
  *Anti-vacuity, and this is not optional:* the gate must assert it parsed a **non-empty** table with
  the expected column count before judging anything, and must fail if the file is missing, empty, or
  parses to zero rows. A gate that reads nothing and reports clean is the failure mode this project
  has paid for more than once.

  **Property 3 — the rules s1 declares are written down once, in the registry, and every consuming
  plan inherits them.** They are:
  - `Sub` is returned by value; a pointer to an interface never crosses this surface.
  - Every value struct carries snake_case `json:` tags and no `omitempty` (Open item S1-7).
  - No surface struct is handed to a caller with a **nil** `*List` field. The wrappers guarantee
    `[]` for an empty list; they cannot guarantee anything for a nil one. **Gate assigned to s9**,
    which writes the first projection.
  - A `free`-classified string field is never parsed or compared against a vocabulary.
  - A closed vocabulary has one name and one value set, however many fields carry it.
  - Signatures are read from source (R2), and every plan in slice 2 repeats that line in its own
    Global Constraints.

  **Property 4 — the registry records what s1 chose where the spec was silent, marked as choices.**
  Not as readings. Each of Open items S1-1, S1-6, S1-7, S1-11, S1-14, S1-18, S1-21 and S1-23 is a
  position this plan took
  because something had to compile, and each is listed with the alternative it rejected. Twice on
  this project an implementer has discovered that a plan resolved an ambiguity the spec never
  settled; the difference between that and this is that these are labelled.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the registry and the gate**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Empty `sdk/slice2-pending-pins.txt`. Property 2 must fail as a broken gate, not pass as clean.
  2. Delete the file. Property 2 must fail.
  3. Corrupt one row's column count. Property 2 must fail rather than skip the row.
  4. Add `func StorageRoot(mlsSecret, pqSecret []byte) []byte` to `connect/message`. Property 2 must
     fail, naming m1 and the consuming plan.
  5. Add a map entry for a method §7 does not declare. Property 1 must fail.
  6. Remove one §7 method from the map. Task 11's Property 1 must fail; confirm the two gates
     compose rather than both being satisfied by the same list.
  7. Convert the pins file to CRLF. The gate must still parse it — or `.gitattributes` must pin it,
     and Task 15's Property 1 must cover the extension. Check which; do not assume.

- [ ] **Step 6: Commit**

---
## Execution order

All sixteen tasks are in **wave 0**. Nothing in this plan depends on anything outside `sdk`, which
is why it precedes every other slice-2 plan. The order below is the dependency order inside the
plan; it is not a suggestion, because a half-declared type graph fails to compile for reasons that
look like unrelated breakage.

| Order | Tasks | Why here |
|---|---|---|
| 1 | 1, 2 | The three handles and the shell. Every other declaration hangs off `MessageClient`. |
| 2 | 3, 4, 5, 6 | The 44 value structs. Task 3 builds the manifest machinery the other three inherit; running Task 3's gate before Task 4 writes a line is the cheapest ledger-21 check on the plan. |
| 3 | 7 | The 16 `*List` wrappers. Task 5's four fields name three of them, so 5 and 7 may be committed together. |
| 4 | 8, 9 | JSON tags and the vocabularies, both of which walk the finished struct set. |
| 5 | 10, 11 | The interfaces and the refusals, which name the payloads and the lists. |
| 6 | 12, 13, 14 | The `surface` module, the drift gate, the exportability walk. |
| 7 | 15 | CI. It runs everything above, so it goes last and is verified by pushing, not by reading. |
| 8 | 16 | The registry, whose ownership map Task 11's scope derives from — so 11 lands with a provisional map and 16 makes it normative. |

**This plan lands as one commit set on one branch.** §7.8's gate operates over the whole type graph;
a half-declared graph fails for reasons that look like unrelated breakage, and a reviewer chasing
those spends the review on the wrong thing.

---

## Definition of done

Complete when all of the following are true, each verified by **running the command**, not by
inspection. Every command runs from the `sdk` checkout with `GOROOT` and `PATH` set as the workspace
requires.

**Precondition, and it is currently unmet:** `../goidenticons` must be checked out beside `sdk`.
Verified 2026-08-30 that it is absent and that `go build ./...` fails because of it. Nothing below
can be run until it is there.

| Gate | Command | Expected |
|---|---|---|
| The package builds | `go build ./...` | ok |
| Every task's tests pass | `go test . -count=1` | ok |
| Race-clean | `go test . -race -count=1` | ok |
| The `surface` module's tests pass | `cd surface && go test ./... -race -count=1` | ok |
| The surface is exportable | `cd surface && go test ./... -run TestMessageSurfaceIsExportable -v` | PASS, and the run reports the number of types it reached |
| The vocabularies are closed | `go test . -run TestVocabulariesAreClosed -v` | PASS — this name and `TestMessageSurfaceIsExportable` are the two §11.2 pins; every other gate above is named by its task, because naming a test is the plan supplying one (R1) |
| The JSON surface is total | Task 8's gate, by whatever name the implementer gave it | PASS |
| No pointer-to-interface crosses the surface | Task 10's and Task 14's gates | PASS in both; and `grep -rn ') \*Sub' *.go` returns no matches |
| Every §7 method is owned, stubbed, or declared unrefusable | Task 11's gate | PASS, and the run reports the size of each of the three buckets — a third bucket that has silently emptied into the second is the failure this reports rather than the total being right |
| The pending pins are still pending | Task 16's gate | PASS, and the run reports the row count it parsed |
| The generator has not drifted | Task 13's gate | PASS, and the run reports the table sizes it read |
| The artifact modules agree | `go test . -run TestSdkArtifactModulePionVersionsMatchRoot -v` | PASS, with `surface/go.mod` among the four checked |
| `x/tools` is not in the root graph | `go list -m all \| grep golang.org/x/tools` | no matches |
| The VPN ABI baseline is untouched | `cd cgo/gen && go test ./... -count=1` | ok — this plan must not move it |
| Vet and format | `go vet ./... && gofmt -l message*.go surface/` | no output |
| CI is green | the `messaging-surface` workflow on the pushed branch | green, and its log shows the `surface` module's tests running |

**The gate that is not a command.** Each of the sixteen tasks records its mutation results in its
commit message: the mutation number, targeted or full run, killed or survived. A survivor with no
recorded reason is an incomplete task. This project has thirty plan-supplied tests that could not
fail; the mutation record is the only thing that distinguishes a test from a test-shaped object.

---

## What this plan does not close

- **No behaviour.** Nothing here opens a store, reaches a network, derives a key, or delivers an
  event. `MessageClient` is a shell with a `stateLock` and a `closed` flag.
- **The event bus.** `Seq` and `Dropped` are declared as fields; the bounded 256-event queue, the
  drop accounting and the synchronous-and-final unregister of §9.5 rules 4 and 6 are s4's, and §9.5
  rules 4 and 6 are **new machinery, not a port** — the existing `sdk/cgo` adapters invoke the C
  callback inline on the calling goroutine with no queue, no `WaitGroup` and no closed flag.
- **`sdk/layering_test.go`.** It does not exist; §11.4 lists it as blocking. Assigned to s5. This
  plan creates the first test-only `sdk` → `connect/mls` edge and records the scope decision that
  gate must be written against (Open item S1-13).
- **`gomobile-validate`.** It cannot run at PR time on this project's machines (Task 14). Deciding
  whether it ever will is unowned.
- **The ABI.** `sdk/cgo-message` does not exist; `include/urmessage_sdk.h` does not exist; no
  baseline is committed. All s10, deliberately phased so the baseline is not frozen before the
  surface is.

---

## Open items

Each is a spec problem in this plan's area, with what it blocks. **None is resolved silently.**
Where this plan took a position because something had to compile, the position is labelled as a
position, the rejected alternative is named, and Task 16's registry records it as a choice rather
than as a reading.

**S1-1 — `MessageSendTicket` has no type definition anywhere in 4,510 lines.** It is the return type
of **38** declarations (measured), §7.1 calls it a behavioural handle, §9.2 lists it as one of four
handle types, and the only statement of its shape is one sentence: *"has `Cancel()` and `Await()`;
`Await` is not exposed over the ABI."* `Await`'s return type is unspecified — returning nothing makes
it unable to report an outcome, blocking makes it a UI-thread deadlock — and "not exposed over the
ABI" needs a `skipMethods["MessageSendTicket.Await"]` entry that nothing specifies, while **gomobile
has no exclusion list at all** and will bind a blocking `Await` into the AAR and the Apple framework.
*Position taken:* declare `Cancel()` only, pin the method set, and let the gate fail the day
somebody adds `Await`. *Rejected:* declaring `Await() error` now, because it is irreversible on two
platforms. **Blocks:** Task 1 fully; s9's send path partially (it uses callbacks, not `Await`).

**S1-2 — `*Sub` on ten declarations.** §7 spells `*Sub` on all ten `Add*Listener` methods; §7.1's own
table says `Sub`; the existing `sdk` returns `Sub` by value in every case and `) *Sub` occurs zero
times in the tree. A pointer to an interface is not gomobile-bindable. The cgo generator will not
catch it (`Sub` is in `behavioralTypes`, so the pointer classifies as a handle). *Position taken:*
declare `Sub` by value in all ten places and gate it by class. **Blocks:** nothing, now. **Owed:** a
one-token correction to §7 in ten places, so the spec and the code stop disagreeing.

**S1-3 — `GroupListener` is given a second method in prose.** §7.2 says it "additionally delivers
`SendabilityChanged(groupId string, s *MessageSendability)`"; §7.7 declares it one-method under the
heading that one-method interfaces are what let the generator map each to a single C function
pointer. `GroupEvent.Kind` already carries `"sendability_changed"` and `GroupEvent` already has a
`Sendability` field, so the event route exists and the second method reads as a leftover. Two C
function pointers per listener is an ABI change. *Position taken:* one method; gate the addition.
**Blocks:** Task 10; s8's sendability delivery; s10's callback typedefs.

**S1-4 — the pin primary key collapses.** §8.1 keys `pin` by `(principal, operator_host)`; §7.3b says
a card-added contact's `Principal` is empty unless directory listing is on; §7.6 says
`MessagePin.OperatorHost` is empty for a key from a contact card. Two card-added contacts therefore
share the key `("", "")` and the second silently overwrites the first's pin — **which is exactly the
state in which no `KeyChangeWarning` fires**. No alternate key (the identity public key) is
specified. *Not resolved here, and it must not be:* this is a schema decision, and ruling it after
rows exist is a migration. **Blocks:** s2's schema, s6's pin store, s7's `AddContactByCard`.

**S1-5 — `Seq` and `Dropped` are claimed to be universal and are not.** §9.5 rule 6 and §7.4a rule 1
both say both fields appear on **every** event payload. Measured across §7: **seven** structs carry
both, `SyncState` carries `Dropped` without `Seq`, and `MessageJoinRequest`, `MessageContactRequest`
and `MessageBalance` carry neither — each of them the payload of a persistent `Add*Listener`. Either
add both to all four or narrow the rule to name which payloads carry them. *Position taken:*
transcribe what §7 declares; do not add fields. **Blocks:** Tasks 3, 4 and 6's manifests; s4's bus.

**S1-6 — no closed vocabulary has a value for "this build does not implement this operation", and
none has one for "that URL was not something I can parse".** `GroupResult.Reason`'s 22 values (S1-20)
include
`"internal"`, and answering `"internal"` to `CreateInviteLink` — or to `AddContactByCard` handed a
malformed URL — is a false statement about what happened. Compare `REASON_UNSUPPORTED_VERSION`, which
Spec B's proto does have, and ledger open item 8, which is the identical gap on the server side.
*Position taken:* Task 11's ticket-shaped stubs refuse through the callback's `err` parameter, so no
stub needs the missing value today. **Blocks:** the honesty of any real implementation that must say
"not on this server"; s7's URL handling. **Related:** §7.9's `BalanceRedeemResult.Reason` is a closed
six-value set that cannot be produced from the operator's `RedeemBalanceCodeError{Message string}` —
either the operator API gains an error code or the vocabulary collapses to
`ok`/`rate_limited`/`offline`/`internal`. That one blocks s4.

**S1-7 — no JSON field naming is specified anywhere.** Every value struct crosses the ABI as JSON,
Spec C parses it with nlohmann, §9.3's `settings_json` documents snake_case, and §7's hundred-plus
structs carry zero `json:` tags. The existing `sdk` is split — api mirrors carry snake_case with
`omitempty`, non-api value structs carry nothing and would emit PascalCase. *Position taken:*
snake_case on every field, `omitempty` nowhere, one total gate so a reversal is one edit to a rule.
*Rejected:* PascalCase (contradicts §9.3), and per-struct discretion (guarantees drift). **Blocks:**
Task 8; s10's ABI baseline, which must not be frozen against the wrong convention.

**S1-8 — sender identity does not collapse across device leaves, and `SenderRoleAtSend` cannot be
read when it is needed.** `sender_handle` is derived per leaf, so one identity with ten devices
produces ten handles, while `MessageEntry.SenderId` is "stable per group; maps to a
`MessageMember`", `MessageMember` carries a single `LeafIndex`, and `MessageReceipt` is "MemberId +
the earliest receipt time" — all three presuppose a handle→identity collapse defined nowhere.
`connect/mls` already gives the right anchor: `GroupPolicyExtension.RoleOf`'s `MemberId` is the
Ed25519 identity public key, documented in-source as stable across device leaves. Separately,
`SenderRoleAtSend` must be read from the **sending epoch's** group context, MLS state is retained for
32 epochs, and `History` is unbounded — so it must be denormalised into the entry row at receipt,
which the spec never says. *Position taken:* write both obligations into the field doc comments and
the registry. **Blocks:** s2's schema, s9's projection.

**S1-9 — `StoredEntry` is undefined and §8.2's bound is wrong.** Named in four of `MessageStore`'s
fourteen methods with not one field declared; and "fourteen methods, that bound is the point" omits
every table §8.1 itself lists — `pin`, `kt_head`, the security log, `device`, `attestation`,
`read_key`, `server_info`, `mls_state`, `mls_private`, `mls_keypackage`. Five of those are read
directly by §7 declarations. Either the bound is wrong or a second store interface has an owner the
spec never names. **Blocks:** s2 entirely; s9 Phase A's projection.

**S1-10 — `TestMessageSurfaceIsExportable` as specified cannot exist, and would be weaker than
advertised if it did.** §7.8 says it "runs the same walk the generator does"; the walk lives in
`sdk/cgo/gen`, which is `package main` in a separate module and cannot be imported. And the generator
does **not** walk struct fields — `gen.go:406` returns json for any named struct immediately — so a
field holding a handle type or a func passes the generator and fails at JSON time. §7.8's sentence
therefore describes a test that is either impossible or vacuous for field types. *Position taken:*
Tasks 12–14 build a re-derivation that is **stronger** than the generator, plus a drift gate, and say
so in their headers. **Owed:** a correction to §7.8's wording.

**S1-11 — `RestoreProgress.Phase` has no declared value set.** It is a `string` on a callback payload
that Spec C must switch on to render a progress phase, and it is neither declared closed nor declared
free. *Not resolved here.* **Blocks:** Task 9's classification totality; s3's `RestoreIdentity`.

**S1-12 — three `urmessage://` entry points and no way to tell them apart.** `RedeemInviteLink(url)`,
`AddContactByCard(url)` and `StartDirectFromCard(url)` are three separate calls;
`MessageInviteLink.Url` and `MessageContactCard.Url` share the scheme; a Windows client registering a
protocol handler receives one URL from the OS with nothing telling it which to call. Needs a
classifier declaration (a `ParseMessageUrl` returning a closed kind) or two distinct schemes. *This
plan declares neither*, because inventing a surface call is not a transcription. **Blocks:** s7;
Spec C's protocol-handler registration.

**S1-13 — `sdk/layering_test.go` does not exist**, though §11.4 lists `layering` as a blocking `sdk`
job. This plan introduces the first test-only `sdk` → `connect/mls` edge (Task 3's limits
agreement), so whoever writes that gate must scope it to the **non-test** dependency set —
`go list -deps`, not `go list -deps -test` — or it will refuse a legitimate test. Recorded here so
the scope is decided once. **Blocks:** nothing now; **assigned to** s5.

**S1-14 — `media_cache_bytes` cannot express "no media cache".** The key is optional with a 1 GiB
default, and an explicit `0` is indistinguishable from an absent key in a plain JSON unmarshal, so
either zero is unrequestable or the default is unreachable. *Position taken:* Task 2 decides and
asserts which, and records the decision. **Blocks:** Task 2's Property 4 only.

**S1-15 — `MessageSendTicket` has no accessor for the local `MessageId`.** A caller cannot correlate
the ticket with the pending entry before `SendCallback` fires, which is exactly the window in which a
UI must render an optimistic row. *This plan declares no accessor*, for the same reason as S1-12.
**Blocks:** s9 Phase C's optimistic send rendering.

**S1-16 — three structs render "the same 12 groups of 5 digits" and no derivation exists.**
`MessageContactCard.SafetyDigits`, `MessageContactRequest.SafetyDigits` and
`IdentitySafetyDigits()` are declared here as fields and methods; §7.6 pins only the format, MASTER
§10.2 says only "an out-of-band fingerprint over the pair's identity keys", and the two readings
disagree about whether the value is pair-scoped or single-key. Two clients that produce different
digits make the phone-call verification ritual noise. **Blocks:** s3, which must write exactly one
implementation, and s6, which calls it.

**S1-17 — no key-package distribution mechanism exists anywhere in the system.**
`CreateGroupWithMembers`, `InviteMember`, `CreateDirect` and `AcceptJoinRequest` each need a
`KeyPackage` for a named principal, and `key_package` appears on a wire in exactly one place in Spec
A: `LP key_package` inside §5.14's contact-request deposit. `connect/protocol/message.proto` has 15
request arms and none publishes or fetches one. This plan declares the four calls (they are §7
declarations) and Task 11 stubs none of them, because s7 and s8 own them. **Blocks:** those four
declarations; CP3b routes around it through s7's contact-card path.

**S1-18 — §9.3 does not say what an unknown `settings_json` key does.** The schema's only statement
about its key set is *"All keys required unless marked optional"*. Rejecting an unknown key and
ignoring it are both defensible and they fail differently: rejecting turns a newer host application's
extra key into a client that will not open at all, against a DLL that ships and versions separately
(§9.6); ignoring turns every caller typo into a silent misconfiguration, running with the default for
the key the caller believed they set. *Position taken:* Task 2 Property 1 refuses, naming the key.
*Rejected:* ignore-and-log. **Blocks:** Task 2 only, and s10's header documentation of
`urmsg_client_open`, which must state whichever rule stands.

**S1-19 — §7.2 says `MessageServerInfo` is all milliseconds and the struct is not.** The sentence
*"…are milliseconds because every other duration on this API surface is milliseconds"* appears
immediately below a declaration that carries `RendezvousTtlSeconds` and
`RendezvousDepositTtlSeconds`, both declared `int64` seconds in that struct by revision A-6 with a
`(§7.3b, §5.14)` citation, and both read out of `ServerInfo()` by §7.3b's rate-limit paragraph.
Anything written to the sentence rather than to the declaration is red against a
correct transcription and invites a rename that silently changes a unit. *Position taken:* Task 3
Property 3 transcribes the declaration field by field and asserts the suffix, not the sentence.
**Owed:** a correction to §7.2's clause naming the two exceptions. **Blocks:** nothing; it is a
transcription trap rather than a missing decision.

**S1-20 — §7.7 declares `GroupResult.Reason`'s value set and states no count.** Counted from the
block on 2026-09-02 it has **22** members. An earlier revision of this plan said 21 in three places
and attributed the number to the spec, which cannot be right, because the spec gives none. A closed
vocabulary whose size no document states is one a reader can undercount with nothing to contradict
them, and the undercount then propagates into every plan that quotes this one. *Position taken:* the
number is carried as this plan's measurement with its date, no gate takes it as an input, and the
vocabulary is derived from the constants. **Owed:** §7.7 stating the count beside the block, so the
next reader has something to check against. **Blocks:** nothing; it is a citation defect with a
propagation cost.

**S1-21 — §7.4's "attachment outcomes are not gap reasons" reads as disjointness and is not.**
`MessageAttachment.State` and `GapReason` both contain `"expired"`, and both need it: an expired
record is one past the server's retention window, an expired attachment is a body past its media
TTL under an entry still present. §7.4's sentence names `pruned` and `failed` and generalises in a
way its own declarations do not support. Written as disjointness the property is red against any
correct transcription, and the resolution an implementer reaches for — deleting `"expired"` from one
side — loses a real state and freezes the loss into s10's baseline. *Position taken:* Task 5
Property 4 asserts the intersection is exactly `{"expired"}`, which refuses in both directions.
**Owed:** a correction narrowing §7.4's sentence to the attachment-only values. **Blocks:** nothing;
Task 5 proceeds on the transcription.

**S1-22 — the `null`-versus-`[]` premise is the plan's, not the spec's.** Sixteen shadowing
`MarshalJSON` methods (Task 7) rest on the claim that Spec C's nlohmann parse throws when it reads
`null` as an array. The Go half is measured; the C++ half is asserted. Spec A §9.2 says only *"Data
structs, lists and maps cross as JSON strings"*, and neither Spec A nor Spec C says what a `null`
does on the consumer side. **Owed:** either a measurement against Spec C's wrapper or a sentence in
§9.2 or Spec C pinning the behaviour. **Blocks:** the justification for Task 7's shadows, and — with
S1-23 — the answer a `*List`-returning call gives when it cannot answer.

**S1-23 — twelve `*List`-returning declarations have no error channel, and both available answers
are refused.** §7 declares `Groups`, `Members`, `HistoryGrants`, `PendingInvites`, `InviteLinks`,
`JoinRequests`, `ContactRequests`, `History`, `Search`, `Devices`, `Pins` and `SecurityLog` returning
a `*List` and nothing else. §8.2 forbids the empty answer in the failure case — *"Spec C would then
render 'No conversations yet' to a user whose entire history is intact on the server"* — and S1-22's
premise makes `null` a consumer crash. §8.2 therefore states a requirement the signatures it names
cannot express. *Position taken:* Task 11 Property 1 gives these a third bucket and stubs none of
them; s1 declares no answer rather than picking a wrong one. *Rejected:* returning nil and calling
`null` "the honest answer", which an earlier revision of this plan did while Task 7 was simultaneously
calling `null` unparseable. **Blocks:** Task 11's coverage of those twelve; s9's and s6's first real
implementations; s10's baseline, which must not be frozen before the answer exists. **Needs:** either
an error channel on those declarations or a specified `null` tolerance in Spec C's wrapper.

**S1-24 — §9.5 rule 4 covers releasing a `Sub` and not a ticket.** *"`urmsg_release(sub)` does not
return until no callback is executing and none will start"* is stated for subscriptions; §9.2 makes
`MessageSendTicket` a handle released by the same `urmsg_release`, and nothing says what happens when
it is released while its callback is in flight. In s1 the window is one callback long over no shared
state (Task 11 Property 4), which is why this plan proceeds without a ruling. It stops being harmless
the moment s9 sends anything real. **Assigned to:** s10, which writes the release path. **Blocks:**
nothing in s1.

---

## Open asks on other plans

Nothing in this plan calls another plan's symbol, which is what makes it wave 0. The list below is
what this plan **hands over**, and what the receiving plan owes back.

| Ask | Plan | Why |
|---|---|---|
| A gate that no surface struct is handed out with a **nil** `*List` field | s9 | Task 7 Property 4: the wrappers guarantee `[]` for an empty list and can guarantee nothing for a nil one. s9 writes the first projection. |
| `sdk/layering_test.go`, scoped to the non-test dependency set | s5 | Open item S1-13; s5 introduces the one legitimate production edge to `connect/mls`. |
| The reachability half of the vocabulary closure — every declared value is written by something | s4 | Task 9 Property 2's accepted survivor. Unenforceable until a producer exists. |
| A `forbidden-crypto` gate over `sdk` | s3 | §11.4 lists it as blocking; s3 is the first plan to touch key material. |
| `skipMethods["MessageSendTicket.Await"]`, if and when S1-1 is ruled | s10 | The spec requires the exclusion and specifies nothing that implements it. |
| `MessageProtocolLimits.DeleteForEveryoneWindowMs`'s producer | m1 | Recorded as a pending pin with no producer; `connect/message` declares no such constant. |
| `SuccessionQuorum(adminCount)` called, never reimplemented, by `MessageSuccessionState.CountersignsRequired` | p7 Task 21 + s8 | A quorum formula that exists twice disagrees with itself exactly once, at the moment it matters. |
| Ratification of S1-7's snake_case-and-no-`omitempty` position before the ABI baseline is committed | s10 | Freezing the baseline against the wrong convention makes every later correction a baseline-break ceremony. |
| An answer for the twelve `*List`-returning declarations that have no error channel | s9, s6, s10 | Open item S1-23. `[]` is refused by §8.2 and `null` by S1-22's premise; s1 leaves them unstubbed rather than picking one. Whoever implements each owes the ruling, and s10 must not freeze the baseline before it. |
| A measurement of what Spec C's nlohmann wrapper does with a JSON `null` where an array is expected | s10 | Open item S1-22. Sixteen shadowing `MarshalJSON` methods and the whole of S1-23 rest on it, and it is the one load-bearing claim in this plan that was asserted rather than run. |
| Release semantics for a `*MessageSendTicket` whose callback is in flight | s10 | Open item S1-24. §9.5 rule 4 states it for `Sub` and §9.2 makes the ticket the same kind of handle. |
| Re-taking `connect`'s `beta/message` pin when the messaging work reaches `main` | s10, and whoever merges `connect` | Task 15 Property 2 and the pending-pin row. `connect/mls` and `connect/message` exist on no other ref today; the CI ref and this plan's cross-repository claims both move when that changes. |
