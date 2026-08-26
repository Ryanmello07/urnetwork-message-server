# URmessage — build progress

Append-only. Newest section last. One entry per completed unit of work, with the evidence
that it is actually done rather than reported done.

Detail lives in the per-plan SDD ledgers (`connect/.superpowers/sdd/<plan>/progress.md`),
which are not committed. This file is the durable summary.

---

## Tracks

Three tracks run in parallel because they are **separate repositories**, which is what makes
parallelism safe here — a single checkout cannot take concurrent agents without the git index
colliding, and that has cost this project real work before.

| Track | Repo | State |
|---|---|---|
| **A — protocol core** | `Ryanmello07/connect`, branch `beta/message` | p1 complete and green in CI; p2 started |
| **B — Windows client** | `Ryanmello07/urmessage-windows` (private) | CP1 shipped — builds, launches, renders |
| **C — message server** | `Ryanmello07/urnetwork-message-server` | greenfield; specs written, no code yet |

Brand source for track B is `Ryanmello07/urnetwork-windows` at branch `beta/algorithm-dpi`, read-only.

## Checkpoints

The owner's goal is a testable build at each step, ending at "able to send messages".

- **CP1 — the app you can look at.** WinUI 3 client with the VPN app's brand, theme and shell.
  Real and safe to run: it is a UI shell, not a messenger yet.
- **CP2 — the protocol core.** MLS (RFC 9420) in pure Go: p2–p7.
- **CP3 — first message end to end.** Two clients, one group, one message through the server.
- **CP4 — the feature set** from Spec C.

**Deliberate sequencing note:** CP3 comes *after* the real MLS core, not before it. A quicker
vertical slice with placeholder crypto would reach "a message appeared on the other screen"
sooner, and was rejected: in a privacy product a build that sends unprotected traffic is a
hazard the moment it exists, because it looks exactly like the real thing to anyone testing it.
The early visible checkpoint is CP1, which is honest — it is a shell and cannot be mistaken for
a working messenger.

**Amended 2026-08-25**, after the owner reprioritised: *"Get everything mostly ready enough to
communicate with basic tests. A full working messager/group chats can be worked on along side.
I want to make sure messages work first."*

That reads at first like the vertical slice the note above rejects. It is not, and the difference
is worth stating precisely so nobody has to re-litigate it later.

The message path splits into two halves, and only one of them needs MLS:

- **Everything up to the AEAD** — the record wire format, `write_auth`, `req_auth`, the protobuf
  control plane, the server's accept-and-fan-out pipeline, the client transport. None of it takes a
  group secret as input. All of it is real code that ships unchanged, and it is what "messages
  travel" actually means.
- **The AEAD keys themselves** — `storage_root`, the class keys, the record-key ratchet. These come
  from the MLS key schedule, which is p4.

So the reprioritisation is satisfied by building the first half **now and for real**, and it does
not require faking the second. The rule that keeps this honest: **the key schedule is absent, not
placeholder.** A test-only key source exists for the end-to-end test, it is named so nobody can
mistake it for anything else, and a gate asserts it is unreachable from any non-test build. A
missing key schedule fails closed and looks like what it is; a placeholder one fails open and looks
like a working messenger, which is exactly the hazard the original note names.

CP3 therefore splits:

- **CP3a — a message travels.** Record → submit → accept → fan out → fetch → parse, authenticated
  end to end by real `write_auth`/`req_auth`, with the AEAD under a test-only key source. Runs
  in-process; needs no VPS. This is the owner's "make sure messages work first".
- **CP3b — a message is private.** The same path with the real MLS key schedule underneath. This is
  the original CP3, and it is the bar for anything a human is invited to send a real message through.

Nothing is invited to CP3a but us.

---

## 2026-08-13 — Plan p1 complete: the TLS presentation-language codec

`connect/mls/syntax`, 19 planned tasks plus one follow-up, **23 commits, 135 tests**, pushed to
`beta/message` at `6b7e440`. Every task: fresh implementer, adversarial review, fixes, ledger entry.

Shipped: RFC 9420 §2.1.2 varints (canonical, reserved and non-minimal forms rejected), `opaque<V>`,
`LP(x)` for record framing, capacity-clipped sub-readers, `optional<T>` with a strict presence
octet, byte-counted vectors, `Marshal`/`Unmarshal` with full-consumption enforcement,
`CheckRoundTrip`, a hand-derived golden table, allocation bounds, a structured generator, three
fuzz targets and a CI gate.

**Nine consecutive tasks found a test in the plan that could not fail.** The one that mattered
most: all three of the plan's `CheckRoundTrip` tests passed against a version that did all the
work, evaluated the comparison, discarded the result and returned `nil` — and since all nine of
p8's fuzz targets call it, that would have made every one of them vacuous while reporting green.
The habit that caught these was mutation testing every claim: patch the version you rejected in
an isolated copy, and confirm the test actually fails on it.

**Four API gaps closed that the plan did not have**, each with a silent failure mode:
`CheckRoundTripLimit` (without it a ratchet tree returns `nil` unchecked and cannot be fuzzed at
all), `ReadNested` and `WriteNested` (nesting silently accepted trailing bytes in one direction
and silently capped a nested field at the wrong limit in the other). All four are in the interface
registry, so p5–p8 inherit them rather than rediscovering them.

**Measured, and it changed p8's design:** uniform random bytes reach the round-trip property
**14 times in 4096 — 0.34%** — against the *simplest possible* type, while the structured
generator reaches it 4096/4096. So p8's seed corpus is load-bearing rather than an optimisation,
and every fuzz target must now count what it actually decoded and fail at zero reachability.

## 2026-08-13 — connect CI restored, and a silently disabled safety net repaired

`connect` had run **no CI at all since 2026-08-04**, on `main` included: merge `35ceb0f0`
resolved to the parent that had no `.github` directory. Verified it was a coherent merge
resolution rather than index corruption — exactly six files, all from one work stream.

- `test.yml` restored and now on **both** `main` (`7167f3d`) and `beta/message`. Two changes from
  the restored file: the trigger covers `main` and `beta/**` (the original fired on
  `beta/custom-server` alone, which is *why* its loss went unnoticed for nine days), and the
  toolchain is read from `go.mod` rather than `stable`.
- `provider-release.yml` restored retargeted, tag renamed `beta-message-latest` — leaving the old
  name would have force-pushed over the existing provider beta release the first time it ran.

**The find underneath it.** Nine root-package tests were failing. A nine-agent diagnosis (one per
test, each required to rule out the alternatives with cited evidence) returned **zero real
regressions** — two environmental causes, both Windows-only:

- Six anchor tests: `core.autocrlf=true` at *system* scope. `functionBody` delimits a function
  with a bare `"\n}\n"`, which occurs **zero** times in a CRLF checkout against 286 of the CRLF
  form, so it fell through to returning the whole rest of the file.
- Three queue tests: Windows advances `time.Now()` only every **~500µs** (measured), so thousands
  of `pumpQueue` adds share a timestamp and a strict `Before` leaves ties unordered.

The important part was not the nine failures. Because `functionBody` widened silently instead of
erroring, the failure was **asymmetric**: 6 anchors written as `strings.Count` failed loudly,
while **84 written as `strings.Contains` passed vacuously**, matching text from elsewhere in the
file. These anchors exist precisely because seam wiring turned out to be deletable with zero
behavioural test failures — so on Windows the net was not protecting anything. Fixed in `42c9035`
(and cherry-picked to `main`); 17 anchor tests pass afterwards, so nothing was hiding behind the
vacuous passes.

Second time `core.autocrlf` has bitten this project — it also smudged the 16 vendored IETF vector
files during p1, which would have invalidated the entire "our codec passes the IETF vectors"
argument.

## 2026-08-13 — CHECKPOINT 1: the Windows client builds, launches and renders

`Ryanmello07/urmessage-windows`, **private**, 61 files, 3 commits. WinUI 3 / C++/WinRT, x64 Release
clean in 41s with 0 errors. Opens at 480×760 DIPs; a second launch redirects under its own key
`URmessage.Desktop` rather than into the VPN client's window.

Brand, palette and pane model lifted from the VPN app: `#101010` page, `#151515` header strips, PP
NeueBit wordmark, ABC Gravity for page titles, and the conversation list built from the VPN's own
`kit::MakePaneTwoLineRowButton` + `MakePaneSearchRow` — no rounded islands, hairline separation,
uniform row heights. The pane model rather than the card model, per the owner's "less random sized
modules and more fit in".

**The repo is private because it carries the four commercial font binaries** (ABC Gravity from
Dinamo; PP Neue Montreal and PP NeueBit from Pangram Pangram), whose licence says they ship inside
the app and must not be redistributed on their own. Whether that licence covers a second product is
an open owner question. **Related and pre-existing: `Ryanmello07/urnetwork-windows` is public and
contains the same four files.**

Two corrections the scaffolder found in the brief, both worth keeping:

- **The identity list was incomplete.** Beyond the five constants in `Ids.h`, three more `URnetwork`
  values are hard-coded in files the survey called copy-clean — including
  `HKCU\Software\URnetwork\Window`, whose placement blob carries a magic and version, so URmessage
  would have *accepted the VPN app's saved window geometry*. Also the storage root and the log
  filename. All now route through `Ids.h`.
- **The font check cannot be done by eye, and the agent's first read of it was wrong.** It judged the
  wordmark a fallback because it did not look pixelated, then measured: rendered ink 111×19 at a 30px
  em, against PP NeueBit 114×19, Montreal 164×27, ABC Gravity 219×28, Segoe UI 160×28. A wrong font
  family name produces **no error**, only silent fallback, so measurement is the only check that
  works. Method recorded in the repo's `Assets/README.md`.

Honest gaps: **ARM64 does not build here** (`MSB8020` — this box's VS18 Build Tools has x64 cross
tools only; environment gap, unverified rather than known-good). Data is stubbed — ten sample rows,
search filters nothing, rows have no click handler, no tray icon, placement is never saved. The app
icon is still the VPN's globe.

## 2026-08-13 — connect CI is green, and the data path picked up two real fixes

All workflows pass on `beta/message` at `18e6bd7` and on `main` at `7167f3d`. `main` has had working
CI for the first time since 2026-08-04.

The `Test — connect` run passing on Linux with the same code that fails nine tests on this Windows
box **demonstrates** the environmental diagnosis that was previously only argued.

Four commits, two of them beyond what was briefed, each isolated so either can be dropped:

- **My diagnosis of the extender failure was wrong**, and acting on it would have turned CI red. I
  attributed it to the 1s listener race; the implementer pulled logs from four CI runs and found the
  failure lands 0.15–0.27s *after* the sleep expired, with `listen tcp 1442` already up. The real
  cause is the content server binding `:443` **inside** `ListenAndServeTLS` on a goroutine, which
  discards the bind error. Fixed with a checked ephemeral port; the destination travels in the
  extender header, so no production code changed. Now demonstrated by CI passing with extender
  folded into the gate and `continue-on-error` removed.
- **The `pumpQueue` tiebreak cannot fix two of the three trim tests**, because `combineQueue` has no
  `pumpItem` and no `seq`, and `RemoveOlder` never reads `seq`. Their cause is the strict `Before`
  cutoff: both queues stamp `updateTime` from the same coarse clock the caller samples the cutoff
  from, so an item stamped just before the cutoff is never *older* than it. Measured: of 4096 adds,
  1433 carried the cutoff's own timestamp and exactly 1433 were left behind. Fixed by making the
  boundary inclusive. Each fix verified independently load-bearing by reverting only that change.

## Deployment targets available — owner, 2026-08-14

The owner has: a **VPS** to host a Message Server, a **test Operator server** to assist, and this
box for the **Windows client**. Their instruction: raise it when the time is right, not before.

So the trigger needs to be stated rather than felt. There are two distinct "ready" moments and it
is worth not confusing them.

**Ready A — server infrastructure, honest and much closer.** Stand the message server on the VPS
and have a harness exchange **opaque records** with it: authentication, the `write_auth` preimage,
group rows, fan-out, retention clamping, capabilities advertisement. This is infrastructure
testing, not a messenger — no real conversation exists, so nothing can be mistaken for a working
private messenger. It de-risks the VPS, the operator integration and the record layer early, which
is exactly what should not be discovered late.

Needs: `connect/message` (the record layer, currently a doc stub) and the Spec B server skeleton.
**Does not need the MLS core finished.**

**Ready B — the real end-to-end test.** Windows client ↔ server ↔ Windows client, real MLS, a
message typed on one and read on the other. Needs p2 through p7 complete.

The sequencing rule from the checkpoint section still holds: **CP3 comes after the real MLS core**,
and Ready A does not violate it precisely because it carries no message content. A build that
looks like a messenger but is not protected is the thing being avoided; a server exchanging opaque
bytes with a test harness is not that.

**Current distance to Ready A:** p1 complete; p2 at 5 of 23; p3 at 2 of 14; `connect/message` is a
doc stub; the server repo is greenfield. The record layer is the near-term unlock and does not
depend on p2-p7 finishing.

**Updated 2026-08-25.** Ready A is the same thing this document now calls **CP3a**; the two names
describe one milestone and CP3a is the one to use. Distance now: p1 complete, p2 at 16 of 23, p3 at
13 of 14, the record layer and the wire protocol both in flight.

**One architectural fact that changes what "host it on the VPS" means.** Spec B §4.1 puts the
control plane *inside connect frames*, not on HTTP: requests reach the message server addressed to
its `client_id` via `Send`/`SendWithTimeout`, and server-initiated pushes go back the same way
reversed. Only the bulk plane — blobs — is TLS/HTTP, and it is deliberately ignorant of groups.

So the message server is **a connect client that happens to be a server**, and standing it up needs
a URnetwork client identity registered with the test Operator, not an open port and a DNS name. Two
consequences worth having in advance rather than discovering on the VPS:

1. **CP3a needs no VPS at all.** Two connect clients in one process exercise the entire path. The
   VPS becomes a test of deployment and the Operator integration, which is a separate and later
   thing from a test of whether messages work.
2. The provider/Operator wiring is a real dependency with its own failure modes, and it is now on
   the critical path for the VPS step rather than for the messaging step. Better to find that out
   here than at the point of asking the owner for the VPS.

## 2026-08-14 — p2 through Task 6, p3 through Task 3, every task reviewed

Both protocol tracks run in their own worktree of `connect`, so their git indexes cannot collide:
p2 on `beta/message`, p3 on `beta/message-p3`. Each task now runs implement → adversarial review →
fix, at the owner's instruction.

**p2 crypto primitives — Tasks 1-6 done.** `b0142dd`, 55 tests. Package skeleton, the
forbidden-primitive gate, the two-entry ciphersuite registry, the single X25519 call site, HPKE
suite ids and the labelled KDF, and DHKEM X25519 derive/encap/decap.

**p3 tree math — Tasks 1-3 done.** `27b070b`, 25 tests, every function in `tree_math.go` at 100%
coverage. Vector loader and corpus tripwire, index types and node level, full-tree sizing,
extension and truncation.

### What the review pass keeps finding

Every task in both plans has turned up a test that could not fail. The count is now well past the
nine p1 produced. The sharpest of this batch:

- **p2 Task 6: the plan's four tests could not fail on nine of the ten implementations they exist
  to reject** — transposed `kem_context` on both sides, ephemeral key in the static slot, labels
  respelled, `shared_secret` dropped, the raw DH returned **unhashed**. Only one asymmetric
  transposition failed, and only because the round trip stopped round-tripping. That is the general
  lesson for a KEM: *a round-trip test proves your encap agrees with your decap, not that either
  matches the RFC.* Two implementations wrong in the same way agree perfectly.
  `TestHpkeEncapDeterministicMatchesEncap` never called `hpkeEncap` at all.
- **p2 Task 5: a test named `…Kat` asserted only a length**, over an ikm appearing nowhere in
  RFC 9180, and its ceiling constant was asserted only against itself — so a value 255× too tight
  passed the whole package.
- **p3 Task 2: the plan's table stopped short of the range**, so three clamped implementations
  passed. It also stopped short of the *middle*: levels 10-30 of `Level()` were asserted nowhere in
  the entire plan.
- **p3 Task 3: the plan's own test contradicted the plan's own implementation** on
  `TreeDepth(MaxLeafCount+1)`. The implementation won, because 31 is only producible by clamping and
  32 makes every downstream `1 << TreeDepth(n)` fail closed.

### Vector provenance, checked rather than assumed

A known-answer test derived from our own implementation is self-consistent and proves nothing. The
HPKE vectors now arrive by three independent routes that agree: Task 5 hand-transcribed them from
the RFC text, Task 6 read them from `GOROOT/src/crypto/hpke/testdata/rfc9180.json` (Go's own
vendored CFRG corpus), and the controller grepped them straight out of RFC 9180. `skEm` is absent
from Go's corpus, so it reaches the table only via Task 5's transcription — genuinely a third route.

Separately, **all 16 vendored IETF vector files were re-vendored** (`aecb087`): they had been stored
CRLF-smudged, with the manifest computed over the damage, so it verified 16/16 against bytes
upstream never published. Content was always correct; only the provenance claim was broken.

### One hazard converted into a compile error, one class closed by measurement

`HpkeKdfHkdfSha256` and `HpkeAeadAes128Gcm` are both `0x0001` from different IANA registries, so a
transposed registry declaration used to compile and pass every value assertion. Distinct named types
made it a compile error for twelve lines and zero test changes. It closes the *declaration* hole,
not the *encoder* hole — `AppendUint16` still needs an explicit conversion — and that limit is
recorded rather than papered over.

The related length-field hazard shows what the three-stage pattern is worth. Seven `SuiteParams`
length fields are 32 in both registered suites, so every interchange among them is invisible. The
implementer flagged one instance and called it unfixable, on the premise that a separating suite
would have to be registered. The reviewer disproved the premise — no KEM function consults the
registry, so a test can pass a bare literal — and put the class at eight. The fixer built the
exhaustive catalogue and measured the class at **forty**, then closed all of it. Survivors: 40 at
the implementer's commit, 18 under the reviewer's proposed fix, **0** as shipped.

## 2026-08-25 — the branch is current, and the message path is under construction

Three things the owner asked about, answered with measurements rather than impressions, plus the
start of the work that makes a message travel.

### The staleness question, and the fork question

The owner noticed `beta/message` was stale against a `connect` that the VPN project develops daily,
and asked whether the URmessage systems should split to a fork.

Measured before answering. `beta/message` was 16 commits behind `origin/main` on a base 19 days old.
The two change sets barely intersect: ours is 66 files under `mls/` plus one under `message/`;
`main`'s is entirely the root data path. **Overlap: three files**, and `main` had touched neither
`mls/` nor `message/` at all. The merge took one conflict — `test.yml`, add/add, resolved to ours
because ours was strictly newer — and `beta/message` is now **zero commits behind `origin/main`**,
verified green in CI at 9m39s rather than only locally.

That measurement also answers the fork question, recorded as **decision 59: do not fork.** The gap
to true upstream is larger — `origin/main` is **110 commits behind `upstream/main`**, 282 files,
+109,453/−26,209 — and it is *entirely* the VPN data path. Zero of those 282 files are under `mls/`
or `message/`. The workstreams are already disjoint in the file system, so a fork would buy
isolation the directory layout provides for free and charge a permanent merge burden for it. The
revisit trigger is mechanical rather than a feeling: **the first merge that conflicts in a file
neither side considers theirs.**

Two things fell out of that comparison that belong to the VPN side rather than to us:

- **Upstream independently made the same extender CI fix we did** — bind an ephemeral port up front
  with the error checked, instead of `ListenAndServeTLS` on a goroutine discarding a privileged
  `:443` bind — and went further with a new `extender_seam_test.go`. Our fix is therefore not a
  unique contribution, and forward-porting it to `main` would only create a conflict at the next
  sync. Not doing it.
- `origin/main`'s restored `test.yml` still runs extender in a `continue-on-error` step. Its last
  green run carries a swallowed `exit code 1` annotation from exactly that step: a step that cannot
  fail the job is a note, not a gate.

### A red release run that is not ours

`Provider Beta Release` went red on `beta/message` for the first time. It is not caused by messenger
work, and the workflow's own restoration comment predicted it: it fires only on a `go.mod`/`go.sum`
change, and the merge changed both. Every one of those changes is a **version bump that arrived from
`origin/main`** — pion, quic-go, x/crypto, x/net, x/sys, gvisor, tlshacks. `connect` on
`beta/message` still adds **zero** new module dependencies, which is what Spec A §2.1 requires.

It failed because `sn`'s `beta/custom-server` needs `go mod tidy` against the newer pins. That is
pre-existing `sn` ↔ `connect` drift the merge surfaced rather than created, and the fix belongs in
`sn`. Recorded as decision 63.

### The protobuf toolchain, verified rather than assumed

`protoc` was not on this box, which blocked the wire protocol. It now lives at
`toolchain/protoc35/bin` alongside a `protoc-gen-go` built from the module's own
`google.golang.org/protobuf v1.36.11`.

Version 35.1 specifically, and the reason is worth recording: regenerating all six committed protos
with it reproduces their `.pb.go` files **byte for byte, version stamp included**. protoc 29.3
produces identical code but stamps a different version, which would show up as a spurious one-line
diff in every regenerated file forever. Because 35.1 round-trips exactly, a diff in a regenerated
file from here on means *someone changed something* — never that the toolchain drifted. That is the
difference between a generated file you can review and one you have to trust.

### What is being built now

Two tracks, in separate worktrees so their git indexes cannot collide, each task gated by an
adversarial reviewer whose primary output is a list of mutations that survived:

- **The record layer**, `connect/message` — types and ladders, the wire codec, the AAD preimages,
  `write_auth` and `req_auth`. Four tasks. This is the half of the message path that does not need
  MLS.
- **The wire protocol**, `connect/protocol/message.proto` — Spec B §4.3 transcribed, generated, and
  gated.

The second one carries a hazard sharp enough to name here. Spec A §5.7 defines `req_auth` as a MAC
over `u8(op)`, where **`op` is the protobuf field number of the selected `oneof` arm**. So the field
numbers are not an implementation detail; they are protocol constants inside a MAC. Transpose two and
nothing fails to compile, nothing fails to parse, and nothing looks wrong — one operation returns
the deliberately non-specific `REASON_REJECTED`, against one implementation, forever. The gate for it
is a `protoreflect` walk of the compiled descriptor rather than a hand-typed table, and it asserts
that the arm set **equals** the set with a declared auth status, so an arm added later without that
decision fails the test instead of shipping.

## 2026-08-25 — CP3a's first half: a record can be built, framed, authenticated and parsed

`connect/message` went from a doc stub to the whole pre-AEAD half of the message path, and
`connect/protocol/message.proto` from nothing to the full control plane. Both are merged into
`beta/message` at `197af90` and pushed: **2,521 assertions across the two packages, 0 failing**,
`go vet` clean, index 440/440.

| Landed | What |
|---|---|
| `message/record.go` | the types, the retention wire byte, the two ladders, and the one place class and bucket may be joined |
| `message/codec.go` | `EncodeRecord` / `ParseRecord` / `ParseRecordHeader` over p1's `LP(x)` framing |
| `message/aad.go` | `AAD_head` and `AAD_body`, with G4 enforced by a signature rather than by discipline |
| `message/writeauth.go` | `write_auth` and `req_auth`, both key derivations, all three verifiers |
| `protocol/message.proto` | Spec B §4.2–§4.6, 603 lines, generated and gated |

p3 also closed at 14 of 14, so **tree math is done**: 5,981 assertions.

### What the review gate actually cost, and what it bought

Five reviewers returned **REJECT, REJECT, ACCEPT_WITH_FIXES, REJECT, ACCEPT** and **22 surviving
mutants** between them. Three of the five rejected work that was green — which is the point: every
one of those 22 is a change to production code that the implementer's own tests could not see.

The single worst was in the authenticators. Deleting two `if err != nil` blocks so
`tag, _ := authTag(...)` discards its error is a **total authentication bypass**: a wrong-length key
makes `authTag` return the zero tag, and Spec A §2.4 makes an all-zero `write_auth` the *normal*
state of every record on the read path. So every fetched record would have verified. **2,428 tests
passed with that in place.**

The most instructive was subtler. A variable-time fast path written as
`bytes.HasPrefix(...) && subtle.ConstantTimeCompare(...)` is behaviourally identical, so no
behavioural test can ever see it — and it passed the constant-time gate too, because that gate banned
**six enumerated names** and `HasPrefix` was not one of them. The gate is now a walk of the package's
imports that **derives** the comparator class: it finds **18**, `bytes.HasPrefix` and `hmac.Equal` and
`fmt.Sscanf` among them. That is the eleventh and twelfth time on this project that a hand-written
list understated the class it was standing in for.

The same defect had a twin in `record.go`'s join gate, which exempted the one file allowed to join the
class and the bucket **by base name** — so `connect/mls/record.go` could contain `class<<4 | bucket`
and the gate waved it through — and whose matcher covered no table-indexed join
(`table[class] + bucket`) and no split shape at all. Both closed; the gate now covers three roots and
prints what it measured: *184 files under the gate, map[.:11 ../../sdk:132 ../mls:41]*.

### Verified rather than reported

The workflow's own reports are not evidence, so **13 of the 22 survivors were re-run by hand** against
the shipped code — the two self-consistent table permutations, the size-bucket constants pointing at
each other's rungs, the wiped file walk, both gate evasions, the discarded writer error, the truncated
attachment hash, the masked size bucket, and five against the verifiers including truncating the tag
comparison to one byte. All 13 now fail as they should, and the tree was clean afterwards.

One survivor had had **no fix pass at all**, because its reviewer returned ACCEPT: `LeafIndex.NodeIndex`
could be replaced with a `0xFFFFFFFF` sentinel and the whole `mls` package — 5,725 tests — still passed,
even though the method's own doc comment is careful to say it wraps and that a zero from it is *not* an
error signal. Closed in `c6ff660`, with the check multiplying in 64 bits and reducing afterwards rather
than recomputing `2*uint32(self)`, which is the implementation's own expression and would pass for any
mutation that kept the line.

**A trap worth recording, because it inverts this project's main instrument.** One of those 13 first
came back as *still surviving*. It had not survived: the mutation was applied with an exact-string
replace whose search text was LF, against a file that is CRLF on this box, so nothing was edited at
all. **A mutation that fails to apply is indistinguishable from a mutation that survived**, and both
look like information. `sed -i` applied the same change and the test failed immediately. Confirming
the edit landed — `git diff --numstat` on the mutated file — is now part of the loop.

### Open, and small

- `ClassIsPrunable` is exported and the server prunes, so it belongs in Spec A §12.1's published
  surface and is not there yet.
- The absent-attachment ruling — an ordinary record contributes `LP(SHA-256(""))`, 36 bytes, not four
  zero octets — is pinned by a KAT and is **the first number to compare against the server team**. If
  they implement the other reading, every ordinary record fails AEAD and no test on either side fails.
- `AADBody` takes a `BodyBinding` rather than a `*RecordHeader`, which is what makes G4 structural
  instead of advisory, but it is exported surface that appears in no spec.

## 2026-08-26 — CP3a reached: a record travels end to end

`TestARecordTravelsEndToEnd` passes. A group is created from a founding commit, the commit is
allocated `record_id` 1, a second sender's wrap lands at 2, an `EpochComplete` marker closes the
fan-out, and an ordinary record — which `REASON_EPOCH_INCOMPLETE` would have refused a moment
earlier — lands at 4. All four fetch back and are asserted **byte-identical**: both ciphertexts
compared octet for octet, the whole header compared after a real `ParseRecord`, `write_auth`
confirmed zero on read per §2.4, and the projections compared field by field.

The message server is a Go module for the first time: `github.com/urnetwork/message-server`,
**155 assertions, 0 failing**, `go vet` clean, index 69/69. `connect` is at **5,135**.

| Landed | What |
|---|---|
| `connect/message/attachment.go` | the `server_attachment` codec §5.1 check 3 calls on every submit |
| `msgrepo/deps_test.go` | §2.2's dependency rule, as a test rather than a shell line |
| `msgrepo/store/` | the interface, a memory implementation, and a contract suite |
| `msgrepo/api/` | §5.1's check order, §6.1's submit, and the record that travels |

**What is honestly not here.** Nothing is encrypted. `ct_head` and `ct_body` are opaque bytes to
every layer built so far, the server cannot open them and never will, and the MLS key schedule that
produces real content keys is p4 and remains **absent rather than stubbed**. This is an
authenticated, addressed, durable transport for opaque bytes. That is exactly what CP3a claims and
no more, and the brief for it forbade adding a placeholder cipher to make the milestone test look
more like a messenger.

### The dependency rule was a sentence; it is a check now

Spec B §2.2 gave its rule as a shell grep. Three things were wrong with it and the implementation
found all three. It is a substring match, so it also matches `urnetwork/server/modelling`. It only
**bans**, never checking that what you *do* depend on was ever written down. And it measures **one
build configuration** — whatever `GOOS` the developer's shell carries — so an import behind
`//go:build linux` for the deployment platform is invisible on a Windows box. That last one was
demonstrated, not argued: a forbidden import behind a linux constraint left the host closure clean.

The gate now runs the closure per platform from `release-platforms.txt`, checks the **subset**
direction so an unlisted dependency fails until somebody writes it down, and fails rather than skips
when `go list` cannot run.

It also found a contradiction the specs could not both satisfy. §2.2 **allows** `connect/message`;
`connect/message` frames every record with `connect/mls/syntax`; and §13 item 8 asserted
`grep connect/mls` finds nothing — a prefix that matches the codec. **The first build that satisfied
§5.1 check 7 made §13 item 8 fail.** Spec B revisions 10 and 11 narrow the assertion from the prefix
to the exact package, with the argument for why a length-prefix reader is not an MLS implementation.

### Four spec amendments, and one deliberate non-amendment

Building the attachment codec found four things in Spec A §5.11 and §12.1 — recorded as A-10 and
Spec B revision 12, none of them changing a wire byte:

- §12.1 lists the sentinels the server may reach and had none of the six `ParseServerAttachment`
  can return.
- §12.1 omitted `ServerAttachmentKind` and its five constants, so a server held to the published
  surface could discriminate an `EpochAttachment` from a `RecoveryTag` only by testing four body
  pointers for nil — while check 3 requires exactly that discrimination on every submit.
- §5.11 declared `ServerAttachment`'s Go field types and **none of the four bodies'**. A second
  implementation could reasonably read the wire table's "exactly 32 bytes" as `[32]byte`, at which
  point check 3's "`write_key` exactly 32 bytes" is a question it can neither ask nor fail.
- **Kind `0x0000` on parse is now ruled: refuse it.** The table forbade *emitting* one and said
  nothing about *receiving* one. Accepting it gives one logical attachment two encodings with two
  different `H(server_attachment)` — which is inside `AAD_head` and the `write_auth` preimage — so
  two peers choosing differently disagree on the AEAD of every ordinary record and neither side's
  tests fail.

One flagged gap was **not** fixed, and the ledger says why: §5.4 was reported as dropping two
sentences about `durable_ttl` clamping, and both are already stated in its own prose. A report is a
claim, not a finding.

### Verified rather than reported, again

Five reviewers, **44 surviving mutants** between them. The sharpest were re-run by hand against the
shipped code: check 3's `group_id` binding, the memory store's write lock, a second MAC
implementation dropped into a *sibling* package (the no-reimplementation gate had hand-written its
scope as one directory), the attachment multi-body refusal, `VerifyWriteAuth` on the submit path,
projection equality, and the `ct_body` length rule. All now fail as they should.

**One survivor was found by the controller rather than by any reviewer.** Replacing check 7's call
in `CreateGroup` with `if false` left every test in the package passing — so a group could be created
whose founding commit does not verify under the key installed as epoch 0's, born inconsistent and
discovered only by whoever fetched it. The test that should have caught it is named
`TestEveryRuleOfTheCreateGroupCarveOutRefusesBeforeTheTransaction`; its table was five rules of six,
hand-written, and the one it omitted was the MAC. That is the thirteenth time on this project that a
class typed out rather than derived has understated itself.

## CP3b — the frame transport, and the connection that had to be invented

`peer` is the message server's connect client: §4.2's frame binding, §4.3's request oneof dispatched
into api, §4.3.1's Hello, §4.6's fragmentation in both directions, and §5.1's check 1. A record now
travels from one connect client through the dispatch, through §5.1's nine checks and §6.1's
transaction, and comes back on a fetch — all of it in one process, with no Postgres, no Redis and no
network space.

### The design question, and what the platform turned out not to have

Spec A §5.7 requires the `server_nonce` to be "scoped to that connection, valid for the life of that
connection, and never rotated". **`connect` has no connection to scope it to.** The receive callback
is handed a `SourceMask` whose `StreamId` is always zero for a client-addressed frame, a
`connect.Peer` built from the contract rather than the session, and no sequence id at all; the
per-peer encryption sessions have an event stream with no session identifier, no closed event, and a
supported mode in which they do not exist. Every one of those was read out of `transfer.go` and
`transfer_encrypt.go` rather than assumed.

So a connection here is **one `Hello` epoch of a `client_id`**, and a Hello destroys the previous
nonce outright. The property that buys is the one the task demanded and it is asserted with
`connect/message`'s own `VerifyWriteAuth`: a record sealed on connection one is refused on connection
two, and the same record re-MAC'd against the new nonce is accepted — the third step being the
control, without which "refused" is equally consistent with a peer that simply broke.

The half that is **not** true is written into the code and into the ledger: a client that reconnects
without saying Hello keeps its nonce, and nothing `connect` exposes changes across a reconnect. That
is a property of the platform, not of this package, and it is bounded by a configurable idle sweep
whose absence the build declares out loud.

### Checks 1 and 2, and the one that is still missing

Check 1 is one function with two callers, because the reassembler needs it as a memory bound §4.6
requires freed immediately and the pipeline needs it as the refusal that carries a `request_id` back
to the client. It answers `REASON_INTERNAL` — never `REASON_OK` — when the request carries no
measurement, because "not called" and "called and passed" are the same green test and a check that
cannot see its input must not report a pass.

Check 2 splits. The nonce half runs here; the `ByJwt` half is decision B1's named dependency and
cannot run in this process, so check 2 stays **declared** with its text rewritten to say which half
is which. **Check 4 is untouched**: still answered by the type api named for what it does not do,
still on the list §10.1's readiness endpoint reads.

### Verified rather than reported

Ten mutations, each confirmed applied with `git diff --numstat` before its result was believed, each
reverted after. Dropping `request_id`, one handler for every arm, a nonce read out of the request, a
nonce reused across two connections, a panic on an unknown arm, two arms swapped in the dispatch
table, check 1 always passing, check 2 always passing, the unserved arms undeclared, and a `Close`
that does not cancel. All ten failed the suite.

3.4 million fuzz executions over the inbound frame surface — request frames, raw frames and fragment
frames — found no panic, and every request that decodes is answered under its own `request_id`.

Two of the ten found a defect rather than confirming a test. The nonce-from-the-request mutation made
the replay test *panic* on an empty result slice instead of failing on the reason, because a
front-check refusal carries no body at all; a test that panics reports its own bug instead of the one
it found. And reviewing the send path found that `connect.Client.Send` is `SendWithTimeout(-1)`,
which blocks until the **client's** context is done — a context this package does not own — so
`Close` could hang until somebody closed the client.

## CP3b review — the bounds that were arguments, and the queue that was only a delay

A review of the above found one denial of service and four §4.6 bounds that could be moved, doubled
or deleted with the whole suite green. Every one of them is now held by a test that fails when the
bound moves, and each of those tests was confirmed by applying the mutation, watching it fail, and
reverting — `git diff --numstat` before every result was believed.

**The refusal path could hold `connect`'s receive loop for 240 bytes.** `Peer.refuse` blocked on a
bounded channel, and it runs on the receive callback, which `connect` invokes inline on the single
loop that reads *every* peer's frames. `refuseLoop` is one consumer by design — the ordering argument
for it is real, and it is what keeps §4.6's specific `REASON_OVERSIZE` from being overtaken by the
generic refusals behind it — so it drains at one refusal per `SendTimeout` against a client that reads
nothing. A queue in front of one such consumer is a delay of `QueueDepth` frames and not a bound:
measured, 200 fragment frames at the default depth held the receive path for exactly 100 send
timeouts, and 21 of 120 *single-frame* batches held it for a timeout apiece. At the default
`SendTimeout` those 240 bytes are ten and a half minutes of the whole server's receive loop.

A refusal that cannot be queued is now dropped and counted (`Stats.RefusalsDropped`) rather than
waited for. What that costs is the courtesy of §4.5's refusal to a client whose own refusals are
already backed up, and the newest is what goes — so the specific refusal, decided first, is the one
that survives. The test named for this DoS had sized its queue at four times its batch, which is the
one arrangement in which the queue cannot fill; it now sends thirty-two times the queue and asserts
that the queue did fill, so it cannot go back to passing vacuously.

**The enforcement of §4.6's own bound cost the attacker's own work.** `expire` scanned the whole
in-flight map on every arriving fragment, under the mutex every client's fragments queue behind: 9 ns
per open reassembly per fragment, linear per fragment and therefore quadratic in an attacker's total
work. At fifty thousand open, every fragment frame from anybody cost 455 µs of held mutex. Reassembly
state expires on when it *began* and no fragment refreshes it, so the reassemblies expire in the order
they were opened — they are now kept in that order and the walk stops at the first one inside the
bound. Asserted by counting what the expiry looked at rather than by timing it: one buffer read
against a hundred open, and one against ten thousand.

**Three more bounds, and the two spec gaps they exposed.** There was no bound above §4.6's per-client
cap and the `client_id` it is per is not this server's to count, so ten thousand strangers held ten
thousand reassemblies with no refusal — `Config.MaxReassemblies` now bounds it, and because §4.6 gives
no such number, `NotBuilt` declares it. `Peer.sweepLoop`'s period could be made a hundred times §4.6's
bound with everything green, because the test that waited for the sweep polled for "eventually";
`Config.NewTicker` makes the ticker a seam, so the period is read back out of it and the relation to
the bound is asserted, and the tick is delivered by the test with the clock moved past the bound
rather than waited for. And §5.1 check 1's comparison could be moved in either direction — a request
of exactly the number `Capabilities` advertises refused, or one past it served — because every
behavioural test was far from the boundary; it is now asserted at the number, on both call sites.

**The abort conditions are a table the enforcement reads.** The test named for "every way §4.6 aborts
a reassembly" listed four of five, and the one it left out — a `count` that changes mid-reassembly —
could be deleted with every test in the repository green. That is the fourteenth time on this project
that a class typed out rather than derived has understated itself. The rules are now values that
`reassembly.accept` asks in order, the test iterates them, and each case proves it belongs to its own
rule by rebuilding the reassembler with exactly that rule removed and watching the refusal disappear —
because half of these conditions are caught by a neighbour if the fragment is chosen carelessly.

**What is still open, and written into the code rather than left as an argument.** A worker's response
send is bounded only by `Config.SendTimeout`, so a client that sends real requests and reads nothing
can park every worker in a send and the receive loop then waits on the job queue. It is the same shape
as the refusal path and eight times milder — eight workers rather than one consumer — and closing it
means dropping responses a client is not reading, which is a decision about §4.3 rather than about a
queue. `-race` is still unavailable on this box: the toolchain has no cgo and the box has no C
compiler, so the concurrency claims are held by `-count=2` and by the fuzz rather than by the detector.
## CP3c — over the wire, and the assertion that it was

A record now travels from a client to the message server and back over **two real
`connect.Client`s** in one process: `harness` speaks §4.3's four operations over one of them, `peer`
dispatches §4.2's frames on the other, `api` runs §5.1's checks and §6.1's transaction, and the
memory store holds the rows. No Postgres, no Redis, no network space, no operator and no `ByJwt` —
`NewNoContractClientOob` plus `AddNoContractPeer` is what removes the contract requirement, which is
why `connect`'s own data-path tests run offline and why these do.

### The assertion the milestone actually turns on

A record that never left the process comes back with **exactly the same bytes** as one that crossed
two connect clients. So "it came back" distinguishes this milestone from the previous one not at
all, and every assertion about headers, ciphertexts and `write_auth` would pass on a test that
called `api` directly. What distinguishes them is that one of them put frames on a route.

So every journey is measured at both ends: the frames the client handed to `connect`, against
`peer.Stats`'s own `frames_received`; the response frames that arrived, against the server's
`responses_sent`; the requests made, against the dispatcher's `requests_served`. The equality is
what makes it unfakeable from either side alone. It was confirmed by building a *successful* bypass
— a second `api.Handler` over the same store, submitting the same record, with the fetch still over
the transport — where every record-level assertion in the test passed and the only thing that failed
was the witness: "2 requests were made and the server's dispatcher served 1".

Two things fell out of writing that bypass. The api layer **cannot** be called successfully from
outside the frame path in this wiring: check 1 reads the frame's byte measurement out of a context
only `peer`'s dispatcher populates, and answers `REASON_INTERNAL` rather than `REASON_OK` when it is
missing — so a careless bypass is refused rather than quietly served. And check 1's copy *inside*
the api pipeline is reachable only from a request that arrives whole: any client that fragments has
its bound enforced by the reassembler one stage earlier, so the test that is named for api running
peer's front checks now sends its oversize request unfragmented on purpose.

### The client is a harness, and that is a gate

The two tests already in `cmd/message-server` were building §4.2 frames by hand, which is a client
and a server that drift apart one file at a time. `harness` is now a package: Hello, CreateGroup,
Submit, Fetch, §4.6's fragmentation in both directions, §4.3.8's `req_auth`, spec A §5.2's sealing
order, and `request_id` correlation. It is **not** the sdk's `MessageClient` — no MLS, no key
schedule, no cipher, no keys of its own, and no import of `testing`, so it cannot end a test from a
goroutine the concurrency test owns. Its own reassembler is deliberately not `peer`'s: a client that
reassembled with the server's code would be one implementation checking itself, and a mistake in the
cutting would be undone by the same mistake in the joining.

That it is test-only is a gate rather than a sentence in its document.
`TestTheHarnessIsReachedOnlyFromTests` reads the module's own import graph under all three measured
build configurations and fails on any importer that is not a test binary, with the importer count
asserted so it cannot pass by reading nothing.

### What only a real transport could show

**Fragmentation, both ways.** A record whose head is a quarter of the budget `Capabilities`
advertised — derived from the server's own number, not a constant — reaches the server in at least
sixteen §4.6 fragments and comes back in at least sixteen more.

**A wrong nonce, refused, twice, with a control.** Once against a nonce the server never issued, and
once against the *previous connection's* nonce after a second Hello proved the two connections were
issued different ones. Then the same record, re-MAC'd against the current nonce, accepted — without
which "refused" is equally consistent with a server that simply broke.

**Thirty-two concurrent submits, correlated twice over.** That a response carrying the right
`request_id` arrived is the harness's own bookkeeping; what makes it *this request's* answer is that
the record stored under the id it reported is the record this goroutine sealed. A dispatcher that
swapped two in-flight responses passes the first check and fails the second. Each sender is its own
`sender_handle`, because §6.1 step (3) is monotonic per `(group_id, sender_handle)` and one sender
submitting concurrently would have the losers refused for the ordering rather than for anything the
test is about.

**A forged `write_auth` that allocates nothing.** Not observable from the refusal — a server that
took an id and rolled the row back answers a client identically and answers a fetch identically. §3.2's
`next_record_id` is what tells them apart, and the gapless record after the forgery is the second
half of the same statement.

### Verified rather than reported

Seven mutations, each confirmed applied with `git diff --numstat` before its result was believed and
reverted after. A nonce that is the same on every connection; a client that truncates instead of
fragmenting; a client that never fragments at all, so that only the frame count can notice; a
dispatcher that answers under its neighbour's `request_id` when another job is queued behind it; the
concurrent pairing itself, broken on purpose; check 7 that passes whatever the MAC says; an id
allocated with no row behind it; and the successful api bypass above. Every one failed, and each
named the assertion it was aimed at.

`-race` is still unavailable on this box — no cgo, no C compiler — so the concurrency claims are
held by `-count=2` (558 passes, exactly double the 279 at `-count=1`, so nothing is order- or
state-dependent) rather than by the detector.
