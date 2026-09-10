# [The Join — One Device, One Signing Key, and the First Group Two Clients Share] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close **S2-4** — *"there is no exported path by which two clients share one group"* — which
`PROGRESS.md`, this repository's ledger and the `s2` plan all name as the thing that blocks **CP3b**
outright. When this plan lands, `connect/messagegroup` can drive a real two-device group: engine A
founds it, engine B publishes a key package, A adds and commits, and B joins from the Welcome and the
ratchet tree. It lands entirely in `connect` on `beta/message`. It builds no durable store, needs no
`sdk` branch, and reaches no message server.

**And it does not reach CP3b, which is the first paragraph rather than a footnote, because plans on
this project have been read as milestones before.** CP3b is *"two clients, one group, one DURABLE
text message, every key real, no test-only key source anywhere on the path."* This plan buys the
**first six words** of that sentence and nothing after them. Three further blockers sit between a
finished join and the bar, all three already filed and none of them this plan's: **S2-1**, **S2-2**
and **S2-3**. A plan that ships every task below and reports CP3b has met a bar it cannot have met.

**The filed cause of S2-4 is a true sentence that points at the wrong fix, and this plan's largest
single act is to say so with measurements rather than to inherit it.** The refusal at
`connect/messagegroup/engine.go:314`, its sentinel at `errors.go:135`, the inventory paragraph at
`doc.go:47-56`, S2-4's own text and the `s2` plan's open ask all pin the blockage on
`mls.StateStore.TakeKeyPackage` not carrying a fourth value. Measured at `connect` `beta/message`
`a1f8025`, `TakeKeyPackage` has **no caller anywhere in the tree** — production or test — and
`PutKeyPackage`'s only caller is the adapter itself. The value that is missing is not a value the
store lost; it is a value nothing ever had. `mls.NewKeyPackage` (`mls/key_package.go:271`) **draws its
own signature key pair** at `:289` and puts the private half on an unexported field, while
`connectMlsEngine.CreateGroup` signs its founding leaf with `self.signer` — so one device mints leaves
under **two different identities depending on which door it came through**, and MASTER §5.2 line 516
rules that there is one: `device_sig`, *"the MLS leaf signature key"*. The fix is a `connect/mls`
constructor that mints a key package against a **caller-supplied** signing key, exactly as
`mls.NewGroup(cfg, signer, cred)` already does. `mls.StateStore` does not move, and neither do its
five test doubles or the reflective gate over them.

**Architecture:** Two packages and one direction. **`connect/mls` gains one exported constructor**
(`key_package.go`) that binds a key package's leaf key, its leaf signature, its `KeyPackageTBS`
signature and its retained seed to a signer the caller already holds — all four in one statement list,
so the partial-rebind defect `lifecycle_fixtures_test.go:206-217` names by hand is unreachable rather
than avoided. **`connect/messagegroup` gains a real join** (`engine.go`): mint under `self.signer`,
recover the addressed key package by parsing the Welcome, assemble `mls.JoinKeyMaterial`, call
`mls.JoinFromWelcome`, wrap the group. Nothing else in either package changes shape. The `mls` half
must land before the `messagegroup` half; the reverse order dispatches a task that cannot compile.

**Tech Stack:** Go 1.26.5, standard library only. **No new module dependency, no new import in either
package, and no new production file in `connect/messagegroup`** — `messagegroup/imports_test.go` pins
that package's production import set as a whole, and every type this plan calls is already inside it.

---

## Global Constraints

### The five rules this plan is written under

These come from this project's ledger and from the ten plans before it. They change how every task
below is meant to be read.

**R1 — this plan supplies no test code, and neither may a task.** Roughly **thirty** plan-supplied
tests across p1–p8 could not fail; nine consecutive p1 tasks each carried one. Every task below
states **the property**, **the refusal that property owes**, and **the mutation set the implementer
must run**. The implementer derives the test. A plan that hands over a test hands over the illusion
of coverage.

**R2 — every signature in this document is illustrative of shape and not of spelling, and every one
was read from source before it was written here.** Every declaration quoted below was read at
`connect` `beta/message` `a1f8025` out of the file that owns it, and the file and line are given so a
reader can check rather than trust: `mls/group.go:303` (`StateStore`), `mls/group.go:321`
(`GroupConfig`), `mls/group.go:469` (`NewGroup`), `mls/group.go:2915` (`JoinKeyMaterial`),
`mls/group.go:2947` (`Zeroize`), `mls/group.go:3033` (`JoinFromWelcome`), `mls/key_package.go:49`
(`KeyPackage`), `mls/key_package.go:64` (`signPriv`), `mls/key_package.go:75`
(`keyPackageSignatureLabel`), `mls/key_package.go:236` (`signedPreimage`), `mls/key_package.go:271`
(`NewKeyPackage`), `mls/key_package.go:349` (`Ref`), `mls/leaf_node.go:410` (`LeafNode.Sign`),
`mls/leaf_node.go:483` (`NewLeafNode`), `mls/crypto.go:76` (`SignatureKeyPair`),
`mls/crypto_labels.go:528` (`signaturePublicKeyOf`), `mls/hpke.go:192` (`hpkePublicKeyOf`),
`mls/tree.go:480` (`FindLeafBySignatureKey`), `mls/framing.go:890` and `:1079` (`MLSMessage`,
`ParseMLSMessage`), `mls/welcome_wire.go:256` and `:296` (`EncryptedGroupSecrets`, `Welcome`),
`messagegroup/engine.go:50`, `:66`, `:157`, `:177`, `:236`, `:270`, `:308`,
`messagegroup/errors.go:135`, `messagegroup/session.go:156` and `:428`. **Read the declaration again
before writing a call.** Ledger **25** is why: `FindExtension` changed shape and seven plan call sites
still spelled the old one.

**R3 — a rule is stated in as many conditions as its source states it, and a gate's scope is derived
separately from its class.** p5's plan stated RFC 9420 §7.9.2's **three**-condition parent-hash rule
as **one**, twice, and the omitted condition admitted a forged-subtree splice. Where a task below
names a derived class, it states how many members that class has **at that task**, so a reader can
tell a gate that fatals on arrival from one that passes vacuously.

**R4 — every property must be satisfiable by a correct implementation, falsifiable by an incorrect
one, and OBSERVABLE from the task that states it; and a property resting on a sentence no document
rules is deferred rather than defended.** The s1 plan shipped four properties no correct
transcription could satisfy — red before a single mutation. Where a property below depends on an
unruled sentence, the sentence is named as a **J1-n** item **before** the property that rests on it,
and the property is written over the part that is ruled.

**The third clause is new in this repair, and it is the one this project had not yet paid for.** This
document has now repaired unsatisfiable properties (s1's four, and Task 4 Property 4's own
contradiction) and undefended ones (R7's two); the verification of the repair found the first
**unobservable** one — Task 4 Property 1's widened class of four, whose added members name a leaf
that cannot be read from `package messagegroup` with anything the task consumes. A property that
cannot be observed is not a property: it is satisfiable and falsifiable in the abstract and green in
every world, which is indistinguishable from the vacuous pass R3 exists to catch.

**The mechanical form, so this is checkable rather than a slogan: beside every property, name the
ROUTE the observation takes — the call, the decode and the FIELD — and check that every name on that
route is in the task's own `Consumes` block.** A route that reaches through a value the seam does not
answer, or through a value the task's fixture does not build, is an unobservable property, and it
must either move to the task that can observe it or be printed as an UNOBSERVED member with its
reason, in `mls/UNOBSERVED.md`'s own shape. **The tell is an observation sentence that names a METHOD
where the property names a FIELD:** Task 4 Property 1 named `MemberAt` as the route to a founding
leaf's signature key, and `MemberAt` (`messagegroup/engine.go:396`) answers
`(leafIndex, identityPub, leafKeys, err)` — it drops `mls.Member.SignatureKey`
(`mls/group.go:779-781`) at the seam.

**R5 — a narrowing must print its complement.** Nine rounds on this project were spent on one class:
a narrowing whose complement is unprinted, or whose justification names something in the tree today.
The criterion, and it is bounded: **is the literal at a level where being wrong is visible, and does
it fail closed and print its complement?** `connect/mls/GATES.md` carries the argument. Every gate
below that excludes something says what it excluded and prints the excluded set's size; an empty
complement is the tell that the narrowing is not a narrowing.

**R6 — a class is a QUERY and a count is not a class, and the same reading applies to a
complement.** `connect/mls/GATES.md`'s first of the nine is *"a class dispositioned by a COUNT
instead of a grep. The number of members stood in for the members. A count cannot have a complement,
which is why nothing could be read off it."* That is a gate's defect in the tree and a plan's defect
here, and the review of this document found **four** instances of it in seven tasks. The mechanical
form, which is what makes it checkable rather than a slogan: **beside every class and beside every
complement this document states, print the QUERY that produces it and the number that query returns
at `a1f8025`.** A size with no query beside it is the defect whether the size is right or wrong; a
size with a query beside it is checkable by anyone in one command. *"The sweep for R6's class"* below
is R6 applied to every class-deriving property in this plan, printed row by row rather than
summarised — because a sweep whose own output is a count is an instance of what it swept for.

**R6's second clause, and it comes from running R6 over R6.** The first sweep repaired five rows and
three defects of its own survived it, all three the same shape one level up. The repair is two
mechanical additions rather than three more corrections:

**(a) A query is checked for what it CONTAINS, and not only for what it counts.** Task 1 Property 4
published `grep -rn "^func .*\*KeyPackage" --include=*.go mls/ | grep -v _test` beside a class of
one-going-on-two, and that query returns **7 lines containing ZERO members of the class** —
`NewKeyPackage`'s declaration wraps, `*KeyPackage` sits on the continuation line 272, and no line of
the answer both starts with `func` and names it. A stated size a query does not return is R6's first
clause; a query whose OUTPUT does not contain the class is this one, and it is the worse of the two,
because the number can be right by coincidence while the derivation reaches nothing. **So every
class-deriving row below prints the query, the number it returns, and — where the class is a subset
of that answer — how many members of the class appear IN the answer. Zero is the tell**, and it is
one command: pipe the published query through `grep -c` for a member's spelling.

**(b) The sweep's own SCOPE is a query, and not a reading.** The first sweep opened *"Eight
properties in this document derive a class"*, which is a list somebody wrote by hand — R6's own
defect, at the level of the sweep. Two of the three surviving defects were outside that scope and
could not have been found by it: the gate table's *"Three of the ten rows"* is a count in a table
that is not a property at all, and Task 1 Property 3 derives a class in substance while not being
written as class-deriving, which is why `planlint`'s check 2a cannot see it either. **The scope is
therefore stated as a predicate over the DOCUMENT rather than over its properties: every place this
document publishes a number a query could produce — a property, a table row, a headline, a Files
block — is in R6's scope. `go test ./ -run TestThePlanLinter`'s check 2a reads only the subset
spelled as a property (the class-deriving property class is 65 references, and 18 of them never
state their membership), so the rest is swept by hand here and printed row by row.**

**And the third surviving defect is what makes (a) and (b) worth writing down rather than fixing five
rows a fourth time: the repair's own concern said its new gate rows *"overstate what is owed — they
never understate it"*. Measured, they understate it by six gates.** That sentence is exactly the
shape of the sentence it replaced.

**R7 — a secret array whose erase obligation is somebody else's is a property about that somebody,
and some task must hold it. It has TWO arms, and the predicate is stated in both because the first
reading stated one and the table under it already carried the other.** Arm (i), the ALIAS arm:
wherever a task's body puts an array it does not own — a field of `self`, or an array another
component handed back — into a structure whose type declares a `Zeroize`, a property must (a) name
which array that erase destroys, (b) observe the **OWNER** after the call rather than the value the
call answered, and (c) carry a mutation that removes the copy. Arm (ii), the ORPHAN arm: wherever a
task's body holds a secret array that no `Zeroize` will ever reach — a local it drew, or a private
half a callee answered and the body then drops — a property must name it and require the erase, and
carry a mutation that removes it.

**The two arms are not a widening for tidiness; the table below already had an arm-(ii) row and the
predicate did not describe it.** Row 2 — Task 2's own drawn seed, handed to the delegate and dropped
— is *"a LOCAL, not a field"* and goes into no `Zeroize`-declaring structure at all, and the table
gives it Task 2 Property 4 while the predicate excludes it. **A sweep whose predicate does not admit
its own table's rows has not been run over itself**, and running it over itself is what found the two
sites the row below adds. *"The sweep for R7's class"* is that rule applied to every site in this
plan. **The class is SIX sites and its complement is one**; **four of the six were undefended before
this repair**, and one of the four — Task 5's `SignPrivate` — had both halves of a key-destroying
defect stated in this document and neither of them held by a property.

### Repository, branch, toolchain

| | |
|---|---|
| Repository | `C:/Users/ryanm/Downloads/claude_sandbox_message/connect` |
| Branch | `beta/message` |
| Baseline commit | `a1f8025` — 1,110 tracked files, 7,665 tests, worktree clean |
| Toolchain | Go 1.26.5 at `C:/Users/ryanm/Downloads/claude_sandbox_message/toolchain/go`, **not on `PATH`**; export `GOROOT` and prepend `$GOROOT/bin` in every shell |
| Shell | Git Bash, not PowerShell |
| Packages touched | `connect/mls` (Tasks 1–3), `connect/messagegroup` (Tasks 4–6). Nothing else in `connect` |
| This repository | `msgrepo` `main`, one file: Task 7's registry entry |

**Baseline measured this session, not assumed.** `go build ./...` exits 0; `go vet ./mls/...
./messagegroup/...` is clean; `go test ./mls/ ./messagegroup/ -count=1` is `ok mls 159.4s` /
`ok messagegroup 13.5s`. **`./mls/` takes about three minutes.** Budget for it; do not reach for a
`-short` flag that does not exist, and do not kill a run by process name — every task below can be
scoped with `-run`, and the full-package run belongs at step 5.

### Where the CP3b line falls, said plainly

CP3b is **two clients, one group, one DURABLE text message, every key real, no test-only key source
anywhere on the path**. `PROGRESS.md:73-77` is the definition this plan reads: CP3a is the same path
*"with the AEAD under a test-only key source"* and CP3b is *"the same path with the real MLS key
schedule underneath."*

**ON this plan's prefix, and it is the whole plan:**

| | |
|---|---|
| Tasks 1–3 | a `connect/mls` key package minted against a caller's signing key, and the in-package proof that such a key package is joinable |
| Tasks 4–6 | the engine mints under `self.signer`, the join body, and the two-engine `Export` equality that is the first thing in either tree able to assert *"two clients, one group"* |

**And what CP3b means after the 2026-09-10 ruling, stated here because this is the paragraph a
milestone report is written from: CP3b means *"the protocol works end to end"*. It does not mean
*"a person may use this"*.** The owner ruled J1-9 by reading *"no test-only key SOURCE anywhere on the
path"* literally — key SOURCE, not test-only CODE — so the in-memory `StateStore` already in the tree
satisfies the bar and **S2-14 came off the prefix**. **The cost the owner accepted, and it must be
reported rather than glossed: the first end-to-end run WILL NOT SURVIVE A RESTART.** Every future
report of this milestone says so. The ruling, its evidence and what it re-ordered are in
*"The J1-9 ruling"* below.

**OFF this plan's prefix, stated explicitly rather than left to be inferred:**

| Not here | Why, measured |
|---|---|
| **The Welcome's delivery channel** (ledger **44** and **44a**: key-package fetch by principal, invite links, the rendezvous) | Ledger **44a** already short-circuits it for CP3b with *"a named, gated test-only hand-off — of a public KeyPackage and a `Welcome` already sealed to the joiner's init key."* Task 6 is that hand-off: two engines in one process, the Welcome passed as a value. The production channel is nobody's in this plan |
| **A production `mls.StateStore`** (**S2-14**) | The two-engine join runs on the in-memory store already in the tree, and `mls.JoinFromWelcome` accepts any `StateStore`. The section *"The production `StateStore`"* below states what it owes and why it cannot live in `connect` at all. **RULED 2026-09-10 — J1-9 is closed and S2-14 is OFF the CP3b prefix**: CP3b's *"no test-only key SOURCE"* is read literally, as key SOURCE and not test-only CODE, so an in-memory `StateStore` satisfies it. **The accepted cost is written into the milestone rather than left to be inferred: the first end-to-end run will not survive a restart.** See *"The J1-9 ruling"* below |
| **Re-join, rejoin-after-removal, external commits, multi-device** | None is reachable from `GroupEngine`'s four methods (`messagegroup/engine.go:50`), and none is needed for one group of two |
| **A reopen path** — `mls.LoadGroup` has **zero** callers outside `mls`'s own tests, workspace-wide, and `GroupEngine` has no method that opens a persisted group | It is a Spec A §6 amendment, therefore Gate 5's swap surface and an owner ruling. **J1-8** |
| **`group_handle_key` and `pq_secret` delivery to the joiner** | **M1-2** (deferred 2026-09-13) and **S2-3**. A joined `GroupHandle` is not a `GroupSession`: `NewGroupSession` (`session.go:156`) refuses an empty `pq_secret`, and `installEpochOnLoop` (`session.go:459`) refuses a joiner at epoch > 0 that was handed no `group_handle_key`. **Task 6 Property 5 requires the test to say so in its own comment** |
| **Everything after the join** — submit, fetch, the epoch-key ceremony | the `s2` legs, with **S2-1** and **S2-2** in front of them |

**The one scheduling fact this document most wants read: S2-4 does not wait on S2-14.** Tasks 1–6
land in one repository, on one branch, against stores that already exist. Nothing here is blocked on
`sdk` having a branch, on a SQLite schema, or on a durability ruling.

### The measurements this plan rests on, with the query beside each number

Every one was run this session at `connect` `beta/message` `a1f8025` from
`C:/Users/ryanm/Downloads/claude_sandbox_message/connect`. A finding is a claim; these are the
queries that make them checkable.

| Claim | Query | Answer |
|---|---|---|
| `TakeKeyPackage` has no caller | `grep -rn "TakeKeyPackage(" --include=*.go .` | **five lines: one interface declaration, three implementations, one wrapper delegating to its own inner store. Zero call sites that drive it** |
| `PutKeyPackage` has one caller | `grep -rn "PutKeyPackage(" --include=*.go .` → **6** | **one call from production code**, `messagegroup/engine.go:258`. The complement, printed: one wrapper delegating to its own inner store (`caller_arrays_test.go:2119`), one interface declaration (`group.go:312`), three implementations (`sessionfixture_test.go:101`, `caller_arrays_test.go:2117`, `group_test.go:116`). **The 6 → 1 narrowing is printed here and was not before this repair — a third instance of the `signPriv` row's shape in this one table, found by running R6 over the TABLE rather than over the properties, which is R6 clause (b)** |
| The join never reads the unexported field | `grep -rn "SignPrivate:" --include=*.go .` | **13** sites, every one a `testMember.SigPriv` minted before the key package existed; **zero** read `kp.signPriv` |
| `signPriv` is written by exactly two sites | `grep -rn "signPriv" --include=*.go .` → **42**; narrowed to writes by `grep -rn "signPriv = \|signPriv:" --include=*.go .` → **12**; narrowed to `KeyPackage.signPriv` by dropping the 10 that write `joinTestWelcomeSpec.signPriv`, a TEST STRUCT's field of the same name (`welcome_test.go` × 9, `extension_lookup_test.go:397`) | **2** — `key_package.go:314` (`NewKeyPackage`) and `lifecycle_fixtures_test.go:233` (the fixture); the field is declared once, at `key_package.go:64`. **Both narrowings are printed rather than performed silently: 42 → 12 → 2. They were not, before this repair, and the claim was right — which is the point: R6's defect is the unprinted step, not the wrong number** |
| `StateStore` has no production implementation | `grep -rn ") PutGroupState(" --include=*.go .` | **five**, every one in a `_test.go` file |
| One key-package constructor exists | `grep -rn "^func New" --include=*.go mls/ \| grep -v _test \| grep -i keypackage` | exactly one, `key_package.go:271` |
| Its blast radius | `grep -rn "NewKeyPackage(" --include=*.go . \| grep -v "func "` | **20 lines, of which 16 are calls to `mls.NewKeyPackage`**: one production (`messagegroup/engine.go:245`) and 15 across **8** `mls` test files. **The four the query returns and the class excludes are printed rather than hand-dropped (R6):** `messagegroup/engine.go:52` (the `GroupEngine` interface method), `messagegroup/engine_test.go:961` (`fixture.engine.NewKeyPackage()`), `mls/key_package_test.go:1177` (a comment) and `mls/lifecycle_fixtures_test.go:227` (a `t.Fatalf` format string). **An earlier reading of this row said 17 across ten files** — the query's line count with three of those four hand-removed and no complement printed, which is R6's defect in this document's own headline number |
| `crypto.SignatureKeyPair()` production callers | `grep -rn "SignatureKeyPair()" --include=*.go . \| grep -v _test` | the interface line, the implementation, and **one** caller: `key_package.go:289` |
| No test in `messagegroup` has ever produced a Welcome | `grep -rn "\.Commit(" --include=*_test.go messagegroup/` | six lines; every `GroupHandle.Commit` call discards `welcome` and `ratchetTree` into `_` |
| No *recorded prose reasoning* constrains this | `grep -c "NewKeyPackage\|signPriv\|JoinKeyMaterial" mls/GATES.md mls/UNOBSERVED.md mls/ERRATA.md` | **0, 0, 0** — and that is the whole of what this query answers. **The conclusion an earlier reading drew from it — *"no gate it must not disturb"* — is drawn wider than the query, which reaches three markdown files and no `_test.go` file at all.** Measured against the tree instead, by BUILDING Task 1 in a throwaway copy of `connect` outside both checkouts and running `go test ./mls/ -count=1` **unfiltered**: **NINE gates go RED on Task 1's commit**, and after the three rows Task 1's Files block schedules, **SIX are still red**. All nine are rows of the gate table below. This row is kept, with its scope narrowed to what it measured, as the instance of R6's *"a conclusion drawn wider than the query that supports it"* that this document shipped — **and the number that replaced it, three, was the same defect a second time in the same row, which is why R6 now has a second clause and why this row's answer is a COMMAND rather than a grep** |

**And three probes, run against a throwaway module outside both checkouts with `replace
github.com/urnetwork/connect => ../connect`, then deleted. None modified `connect`; the worktree was
clean before and after.**

*Probe 1 — the identity split is real, and it is larger than the item S2-4 files.* Build a
`connectMlsEngine` the way `messagegroup/sessionfixture_test.go:143` builds one, publish a key
package, decode it, and print what the leaf names:

```
device signer public half        : ec494c50...81b8fda8
credential identity              : ec494c50...81b8fda8
published KP leaf SignatureKey   : f3130dca...c87c1794
published KP leaf cred identity  : ec494c50...81b8fda8
KP leaf key == device signer pub : false
founding member identity_pub     : ec494c50...81b8fda8   (CreateGroup, same device)
```

**The device publishes key packages naming a signature key it does not hold**, while the group it
founds names one it does. Nothing in non-test `mls` binds `LeafNode.SignatureKey` to
`Credential.Identity`, group policy roles key on `Credential.Identity` (`mls/group.go:787`), and
`Member.IdentityPub` is read off the credential (`mls/group.go:779`) — so the protocol will never
report it, and the whole 7,665-test suite is green with it in place.

*Probe 2 — the store already carries enough, and the refusal that comes back names the split.*
Assemble `mls.JoinKeyMaterial` out of what `PutKeyPackage` stored plus the engine's own signer, and
hand it to `mls.JoinFromWelcome` with a deliberately invalid Welcome. The caller-material gate at
`mls/group.go:3066` runs **before one octet the sender chose is judged**, so what comes back is about
the caller and not about the message:

```
mls.JoinFromWelcome w/ signer    : mls: this joiner's signing key is not the signature key its key package published
mls.JoinFromWelcome w/ nil sign  : mls: signature key length does not match the ciphersuite
```

*Probe 3 — where the package wall actually is, and it is not where the refusal says.* Attempt the
fixture's rebind from outside `package mls`:

```
rebind.go:13:5:  kp.SignPriv undefined (type *mls.KeyPackage has no field or method SignPriv,
                 but does have unexported field signPriv)
rebind.go:14:21: kp.SignedPreimage undefined (type *mls.KeyPackage has no field or method
                 SignedPreimage, but does have unexported method signedPreimage)
```

`kp.LeafNode.SignatureKey = pub` and `kp.LeafNode.Sign(crypto, priv, nil, 0)` **compile across the
package boundary**, and so does `crypto.SignWithLabel(priv, "KeyPackageTBS", content)` with the label
spelled as a literal. **So the wall is two identifiers, and one of the two ways over it is not a
compile error at all — it is a second spelling of `keyPackageSignatureLabel`.** That is the defect
class `messagegroup/engine.go:300` already names and refuses to take, and it is the reason the fix
belongs inside `connect/mls` rather than beside it.

### The ruling this plan takes a position on, and the sentence nobody wrote

**Position taken: the leaf of every key package this device publishes names `device_sig`, the same
key its founding leaves name. The rejected alternative is named, and so is its cost.**

The evidence, read from the specs in this repository:

- **MASTER §5.2 line 516**, under the heading *"Generated on-device, never seed-derived"*:
  `device_sig  Ed25519  the MLS leaf signature key`. The definite article, in a table of **per-device**
  keys.
- **Spec A §8.1 line 4625** puts `device_sig` in the **keyfile**. **Line 4628** puts *"Pending
  KeyPackages + their private halves"* in `mls_keypackage` — and §5.2 has already said which halves
  those are, because it names three device keys and only two of them are a key package's. **The sign
  private was never store-shaped.**
- `mls.NewGroup(cfg, signer, cred)` (`mls/group.go:469`) already takes a caller signer and hands it
  straight to `NewLeafNode` at `:525`. `mls.NewKeyPackage` is the only constructor in the package that
  mints an MLS leaf **without** one. That asymmetry is the whole of S2-4.
- `mls/group.go:2909-2912`, the `JoinKeyMaterial` header, already describes this design from the
  other end: *"`TakeKeyPackage` hands back the encoding and the two private keys it stored beside it,
  **and the signing key is the device's own**."* The source S2-4 quotes and the source that
  contradicts it are eleven hundred lines apart in one file.

**The rejected alternative, and the only real argument for it.** *Option A* is a fifth value on
`PutKeyPackage` and a fourth result on `TakeKeyPackage`, reproducing the fixture's field write. It
buys one thing the position gives up: under Option A every key package carries a **fresh, unlinkable**
signature key, so the delivery service cannot tell two of this device's key packages apart.
**Measured, that unlinkability does not exist in this tree and Option A would not create it.**
`connectMlsEngine.NewKeyPackage` puts `self.leafKeys` — the encoded `urmessage_leaf_keys` body
carrying this device's **one** `device_xwing` public half, per MASTER §5.2 — into the leaf of **every**
key package it publishes (`messagegroup/engine.go:236-247`), and `NewConnectMlsEngine` refuses a
device that has none (`engine.go:189`). Two key packages from one device are already publicly linkable
by a field that is there by design. Option A pays the full cost of a wider exported interface for a
property a landed extension has already spent.

**And the sentence no document writes, filed rather than ruled: J1-1.** MASTER §5.2 says `device_sig`
is *"the MLS leaf signature key"*. It does not say, in as many words, that **every** leaf this device
publishes — including a KeyPackage's, which RFC 9420 permits to carry a fresh key per advertisement —
names it. The position above reads the definite article and the per-device table as ruling it; a
reader could read §5.2 as scoped to the leaf of a group the device is already a member of. **This plan
is written so that reading it the other way costs one commit rather than a rewrite:** the constructor
Task 1 adds is additive, `mls.NewKeyPackage` keeps its exact signature and its exact behaviour, and
the only edit an Option A ruling would force is at `messagegroup/engine.go` plus the interface
widening Option A was always going to cost.

### What changes in `mls.StateStore`: nothing, and what that saves

`mls.StateStore` (`mls/group.go:303`) declares **eight** methods — confirmed by `reflect` in the gate
at `mls/caller_arrays_test.go:2181`, not read off a comment. **This plan changes none of them, adds
none, and moves no argument.** This section is here because S2-4's own text asks for the opposite and
because the cost of the opposite is measurable.

**Why a fourth return value on `TakeKeyPackage` is not the answer, in the order the objections
actually bite:**

1. **It closes nothing on its own.** `PutKeyPackage`'s caller would have to have obtained the sign
   private from somewhere first, and no exported surface of `connect/mls` answers it — compile-probed
   above. A fifth argument to `PutKeyPackage` and a fourth result on `TakeKeyPackage` still leave
   `messagegroup` with no value to put in them. **The constructor is required either way; the
   interface change is what is optional.**
2. **It widens a method with no caller.** `TakeKeyPackage` has zero call sites in the tree. Adding a
   result to a method nothing calls, to carry a value nothing can produce, is the shape of a change
   that cannot be wrong yet and cannot be right later.
3. **It contradicts Spec A §8.1 line 4625**, which puts `device_sig` in the keyfile and not in
   `mls_keypackage`, and it hands whoever writes S2-14 a third sealed column to design around.
4. **It costs six files and one reflective gate, in one commit or not at all.** Under Option A these
   move together, because the gate derives its class from `reflect.TypeOf((*StateStore)(nil)).Elem()`
   and compares recorded byte-storage routes against declared ones; its own comment says *"a tenth
   method, or a parameter added to one of the nine, fails here on the commit that adds it"*:

   | What moves under Option A | File:line |
   |---|---|
   | the interface | `mls/group.go:312-313` |
   | `recordingStore`, the reflect gate's own double | `mls/caller_arrays_test.go:2117`, `:2122` |
   | `testStore` | `mls/group_test.go:116`, `:121` |
   | `windowStore` | `mls/group_test.go:2612` — embeds a store; check what it promotes |
   | `refusingPutStore` | `mls/group_test.go:3221` — embeds a store; check what it promotes |
   | `memoryStateStore` | `messagegroup/sessionfixture_test.go:101`, `:110` |
   | Spec A §3.5's code block, character-identical to the landed interface | `docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md:588-604` |

   **Under the position this plan takes, every row of that table is untouched, and the eight-method
   interface Spec A §3.5 publishes stays the interface `sdk` will implement.** That is the saving, and
   it is why the constructor decision is Task 1 rather than Task 4.

**One thing about `TakeKeyPackage` this plan does have to answer, because Task 5 becomes its first
caller anywhere: it is destructive, and the header at `mls/group.go:287-302` does not say what that
costs.** See Task 5, and **J1-3**.

### The J1-9 ruling, 2026-09-10: CP3b's *"key source"* is read literally, and what that costs

**The ruling.** CP3b is *"two clients, one group, one DURABLE text message, every key real, no
test-only key source anywhere on the path."* The owner rules that **"key SOURCE" is read literally
and is not "test-only CODE"**. An in-memory `StateStore` is test-only code; it is not a key source.
Every key on the path still comes from the real MLS key schedule and the real crypto provider, and it
is the store's job to hold them, not to make them.

**The evidence the ruling rests on, and it is a landed byte-for-byte reproduction rather than an
argument.** `connect/messagegroup/keysource_test.go` holds CP3b's defining property as a STANDING
test, with its class derived rather than listed: **the whole sealed record is rebuilt, byte for byte,
from three values and nothing else** — `mls_secret`, which is the REAL group's
`Export("URmessage/v1/storage", nil, 32)` taken off the same `mls.Group` the session holds; and
`pq_secret` and `server_nonce`, neither of which is a key. Nothing on the reproduction's side comes
from the module under test: RFC 5869 is written out from the RFC, and the AEAD and MAC come from
`chacha20poly1305.NewX`, `crypto/hmac` and `crypto/sha256`.
`TestEveryKeyedOctetOfARecordIsReproducibleFromTheExporterAndTheTwoInjectedValuesAlone` and
`TestFlippingAnyBitOfTheExporterOutputChangesEveryKeyedOctetOfARecord` are the two that carry it.
**A `StateStore` appears nowhere in that reproduction, in either direction** — which is precisely the
point: the store holds state the key schedule produced, and an octet drawn from anywhere the
reproduction is not given moves `ct_body`, `ct_head`, `sender_handle` or `write_auth` and turns one of
the comparisons red. `PROGRESS.md:73-77` reads the same way from the definition's own contrast: CP3a
is the path *"with the AEAD under a test-only key source"* and CP3b is *"the same path with the real
MLS key schedule underneath"* — a sentence about where keys COME FROM.

**THE COST THE OWNER ACCEPTED, WRITTEN DOWN RATHER THAN GLOSSED.** The first end-to-end run
**will not survive a restart**. It proves the protocol; it does not prove the product. **Every future
report of this milestone must say so.** CP3b means *"the protocol works end to end"* and it does not
mean *"a person may use this"*. A report that says *"CP3b reached"* without the restart sentence has
overstated the milestone in the same way a plan that shipped every task and reported CP3b would have
— which is the failure mode this document's own first paragraph exists to prevent, one level up.

**What the ruling re-ordered.** **S2-14 comes OFF the CP3b prefix and becomes DURABILITY work.** It
is no longer a bar-gating item; it is the item between *"the protocol works"* and *"a person may use
this"*, and the five obligations below are what it owes when somebody picks it up. Nothing in this
plan moved: Tasks 1–6 were never blocked on it, `mls.JoinFromWelcome` accepts any `StateStore`, and
the two-engine join runs on the in-memory store already in the tree. **The `s2` plan's S2-14 item
carries this ruling too**, since `s2` is the plan that filed it. **The ruling does NOT name an owner
for S2-14 — that is J1-10, and it stays the owner's.**

**What the ruling does not do, so it is not read wider than it is:** it says nothing about **J1-8**
(the reopen path), **J1-11** (send-path durability), **J1-12**, **J1-13** or **J1-14**. Every one of
those is a durability question, and moving S2-14 off the prefix moves all five off it with S2-14
rather than closing any of them.

### The production `StateStore`, which this plan does not build

S2-14 is confirmed and understated: `grep -rn ") PutGroupState(" --include=*.go .` returns **five**
implementations and every one is in a `_test.go` file. Nothing in `connect`, `msgrepo`, `sdk` or
`server` implements `mls.StateStore` in production code. **After the 2026-09-10 ruling this is
DURABILITY work rather than CP3b work** — the five obligations below are unchanged, and what changed
is when they are owed.

**It cannot live in `connect` at all, and that is a gate rather than a preference.**
`messagegroup/imports_test.go` pins that package's production import set as a **whole** and names
`"os"`, `"bufio"`, `"path/filepath"` and `"syscall"` in the with-a-reason list; `connect/mls` holds
the equivalent property over its own scan roots. Spec A §8.1 assigns the three tables — `mls_state`,
`mls_private`, `mls_keypackage` — to `sdk`'s sealed local store. So the owner is `sdk`, gated on
**S2-13** (`sdk` has no `beta/message` branch and no CI), and this plan neither builds it nor waits
for it.

**What it owes, stated here because it persists private keys.** Every item is read off the interface's
own header or off a measured call site, and each is filed below with what it blocks.

1. **Durability on the send path, per message — not per epoch.** `PutGroupState` is called from
   `(*Group).sealAndRecordLocked` (`mls/group.go:1018`, persisting at `:1024`) **before** the
   ciphertext is handed to the caller, as well as from `NewGroup`, `MergePendingCommit` and
   `JoinFromWelcome`. `group.go`'s own comment there says a send that did not write back *"has gone
   out under one (key, base nonce) pair for this leaf and generation"*, with a 32-bit `reuse_guard`
   between that and a nonce collision. **So the write must be durable before the call returns.**
   Neither Spec A §3.5 nor §8.1 says this; §8.1 reserves `PRAGMA synchronous=FULL` for the `stream`
   table alone. **J1-11.**
2. **A crash between a put and a take, in both directions.** *Between `PutKeyPackage` and the
   Welcome:* the device published a key package whose private halves were never made durable, so
   every Welcome addressed to it is unopenable and the device must publish a fresh one and be
   re-added — a recoverable liveness cost, and the reason `PutKeyPackage` must be durable **before**
   `NewKeyPackage` returns the encoding that gets published. *Between `TakeKeyPackage` and a completed
   join:* item 3.
3. **`TakeKeyPackage`'s *take* semantics, and what they mean for a retry.** The name is the contract
   and the only implementation deletes before returning (`messagegroup/sessionfixture_test.go:117`).
   `mls.JoinFromWelcome`'s own header spends fifteen lines establishing that **a Welcome authenticates
   nobody** — anybody holding the published key package can seal a well-formed one to it — and the
   join then runs roughly fifteen checks (`mls/group.go:3066-3429`), any of which can refuse. A joiner
   that takes and then fails has consumed the device's only copy: the legitimate Welcome can never be
   opened. **The interface cannot express take-on-success**: it has one method that reads and deletes
   in one call, and there is no `GetKeyPackage` and no `DeleteKeyPackage`. Task 5 takes a position
   that works on the eight-method interface — take, and **put back on any failure** — and prints the
   one window it does not close: a crash between the take and the put-back loses the key package
   permanently. **J1-3** is the ruling owed, and it is a `Get`/`Delete` split or a normative sentence,
   not an implementer's choice.
4. **Whether any key material survives in a place nothing erases — the one that has bitten this
   project.** Three answers, and only the first is clean today. *(a)* `PutGroupState`'s `state` is a
   plaintext epoch secret and a leaf private key; the group erases the buffer the instant the call
   returns (`mls/group.go:969-980`, `zeroizeSecret(state)` on **both** the success and the error
   path), so a store that retains the caller's slice keeps a secret in an array nobody will ever wipe,
   and a store that copies owes the copy an erase of its own. The interface header rules this for
   `Put` and `Get` and says **nothing about `Take`**, which is the direction Task 5 walks into — see
   Task 5 Property 3 and **J1-5**. *(b)* `DeletePrivateKey` has **zero** production callers anywhere;
   `mls/group.go:4195` says so in as many words, deferring the delete to an epoch-boundary task that
   landed without it, so `mls_private` grows one sealed row per `ProposeUpdate` forever and Spec A
   §8.1's *"key superseded or leaf removed"* has no code that performs it. **J1-12.** *(c)* Spec A
   §8.1's second deletion trigger for `mls_keypackage`, *"30-day lifetime expiry"*, has no mechanism:
   the interface has no enumeration, no sweep and no lifetime accessor, and `TakeKeyPackage` needs a
   ref. **J1-13.**
5. **An error taxonomy, which the interface does not have.** `GetGroupState`, `GetPrivateKey` and
   `TakeKeyPackage` each return a bare `error`, and `LoadGroup` (`mls/group.go:2634`) propagates it
   verbatim. Spec A §8.2 makes the opposite rule normative for `MessageStore` — *"Store-open failure
   is an explicit value, never an empty result"* — and §3.5 says nothing. **A restart that meets a
   disk error is indistinguishable from a group that was never joined.** Task 5 Property 4 is where
   this stops being abstract, because the join loops over candidate refs and cannot tell *"not mine"*
   from *"the store is broken"*. **J1-4.**

### The sweep for R6's class: every NUMBER this plan publishes that a query could produce, beside the query

**The scope of this sweep is a predicate over the document and not a reading of its properties, and
that is the repair the verification forced (R6 clause b).** The first version of this table opened
*"Eight properties in this document derive a class"* — a list written by hand, which is R6's own
defect at the level of the sweep, and two of the three defects that survived it were outside that
scope and could not have been found by it. **The predicate now: every place this document publishes a
number a query could produce is in scope — a stated property, a table row, a section headline, a
Files block — whether or not it is written as class-deriving.** `go test ./ -run TestThePlanLinter`'s
check 2a reads only the subset spelled as a property, so the rest is swept by hand here and printed
row by row.

**Each row answers two questions and not one (R6 clause a): does the published query RETURN the
stated number, and does its output CONTAIN the class?** The second is the one Task 1 Property 4
failed at every commit while the first looked repaired. Every query was re-run this session at
`connect` `beta/message` `a1f8025`; the three built rows were measured by building the task in a
throwaway copy of `connect` outside both checkouts.

| Property | The query that derives the class | Stated | Returned at `a1f8025` | Verdict |
|---|---|---|---|---|
| **Task 1 Property 4**, first reading | `grep -rn "^func .*\*KeyPackage" --include=*.go mls/ \| grep -v _test`, split on whether the declaration ANSWERS one | class **2**, complement `UnmarshalMLS`'s receiver and the `MLSMessage.KeyPackage` arm | **7 lines**. `MLSMessage.KeyPackage` (`framing.go:897`) is a struct FIELD and is in no function class at all | **class right; complement wrong, and under the predicate mutation 10 fixes it is EMPTY** — `GATES.md`'s own dangerous reading. Repaired at the property |
| **Task 1 Property 4**, the repair's own reading — **and this is the row R6 was derived from, failing R6 a second time** | the same line grep, universe stated as **8**, complement stated as **7** | universe **8**, class **1**→2, complement **7** | the query returns **7 lines**, and `\| grep -c NewKeyPackage` returns **0** — the 7 lines it returns ARE the complement, and the class is not in the output at all, at `a1f8025` or with the sibling present. The universe of 8 is right and unreachable from the command printed beside it, because `NewKeyPackage`'s declaration wraps at `key_package.go:271-272` | **the number was right and the derivation reached nothing.** This is R6 clause (a)'s whole content. Repaired at the property: the universe is derived through `declaredFunctionsOf` (`crypto_test.go:7263`), the gate prints both sets, and mutation 10 now requires the third constructor to WRAP |
| **Task 1 Property 3** — **not in the first sweep's scope at all**, because Property 3 is not written as class-deriving | `providerStreamDraws` (`crypto_test.go:8191`), keyed off `providerOperations(t)` | a NEW gate over separate entropy | the tree **already derives this class and already states this property as a NUMBER**, in `providerStreamDraws`'s own comment for `NewKeyPackage`. Measured in the throwaway build: with the row Task 1 owes anyway, mutation 7 makes the LANDED gate red on its own — `NewKeyPackageWithSigner drew 32 bytes of the source, want 64` at both suites | **a second derivation of a landed derived class — the identical defect Task 2 Property 3 was repaired for, one property over.** Repaired at the property as clause A (the landed row) plus clause B (the answer comparison a count cannot see; measured, that mutant produces no `drew N bytes` line) |
| **The gate table's headline** — **not a property, therefore not in the first sweep's scope** | none published; the number was a reading | *"Three of the ten rows below go RED on Task 1's commit"* | **NINE**, measured by building Task 1 in a throwaway copy of `connect` and running `go test ./mls/ -count=1` unfiltered; **SIX still red** after the three rows the Files block scheduled | **a count with no query at all, in the row the review had ALREADY corrected once from zero to three.** Repaired at the gate table: the answer is now a COMMAND, all nine are rows, and Task 1's Files block names five test files |
| **The measurements table's `PutKeyPackage` row** — not a property | `grep -rn "PutKeyPackage(" --include=*.go .` | *"one, `messagegroup/engine.go:258`"* | **6 lines** — 1 production call, 1 delegating wrapper, 1 interface declaration, 3 implementations | **the 6 →1 narrowing was unprinted**, the same shape as the `signPriv` row's 42→2 that the verification named. **Found by running R6 over the TABLE rather than over the properties.** Repaired at the row |
| **Task 2 Property 3** | `grep -rn "keyPackageSignatureLabel" --include=*.go mls/` | class **1**, complement **2** test references, one of them at `lifecycle_fixtures_test.go:240` | **11 lines: 3 production** (`key_package.go:75` the declaration, `:320` the sign, `:399` the verify) **and 8 test across 5 files**; the fixture's call is at `:238` | **class wrong under its own predicate, complement wrong by 4x, one line number off by two — and the class is ALREADY derived in the tree.** Replaced at the property |
| **Task 3 Property 3** | `grep -rn "testKeyPackage(" --include=*.go mls/ \| grep -v "func testKeyPackage"` | class **112** | **112** | **class right; the complement's SIZE is unprinted**, which R5 forbids and which is why no mutation could name it. Repaired at the property |
| **Task 4 Property 1**, the class | `grep -rn "NewLeafNode(\|\.Sign(crypto" --include=*.go mls/ \| grep -v _test` → **8 sites**, read back to the section 6 method that reaches each → **5 doors** | class **2**, complement **1** | **8 sites → 5 doors: 4 in the class** (`NewKeyPackage`, `CreateGroup`, `GroupHandle.ProposeUpdate`, `GroupHandle.Commit`) **and 1 in the complement** (`GroupEngine.JoinFromWelcome`) | **class right after the repair, and the 8 → 5 step was unprinted** — the column printed 4 and 1 and never printed the 8 the query returns. Repaired at the row and at the property |
| **Task 4 Property 1**, the OBSERVATION — a question R6 does not ask and R4's new third clause does | for each door: the call, the decode and the FIELD, checked against the task's `Consumes` block | *"prints all four with the key each leaf named"*, and *"the last two are green today and must be printed as green"* | **ONE of the four is observable from `package messagegroup` at Task 4.** `MemberAt` — the route the property NAMES — answers `(leafIndex, identityPub, leafKeys, err)` and drops `mls.Member.SignatureKey`, so even door 2 is unreadable through it | **the first UNOBSERVABLE property this project has found**, and the reason R4 now has a third clause. Repaired at the property: each door carries its route, doors 3 and 4 move to the task that can observe them, and door 3 is printed as UNOBSERVED with its reason |
| **Task 5 Property 1** | every entry of `Welcome.Secrets`, read off the parsed message | **2** in the gate this task builds | reproduced: two `ProposeAdd`s and one `Commit(nil)` answer a `Welcome.Secrets` of 2, `NewMember` refs equal to each store's key | **right** |
| **Task 5 Property 5** | `sed -n '3033,3440p' mls/group.go \| grep -o 'cfg\.[A-Za-z]*' \| sort -u`, against `GroupConfig`'s eight declared fields | class **4**, complement **4** | class **4** — `Crypto`, `GroupId`, `Profile`, `Store`; complement **4** — `Suite`, `Extensions`, `RequiredCaps`, `LeafKeys`; and 4 + 4 is the type's whole field set | **right, and it is the CONTROL**: the one property here whose class and complement both reproduce and whose two sets exhaust a universe the compiler can name. It is the shape the four defective rows are repaired into |
| **Task 6 Property 4** | `grep -rn "TakeKeyPackage\|ErrEngineJoinUnavailable" --include=*.go messagegroup/ \| grep -v _test.go` | class **3** | **6** — `doc.go:50`, `engine.go:297`, `:314`, `:315`, `errors.go:130`, `:135` | **class wrong by 2x.** Every one of the six is in a file some task of this plan already edits, so the WORK was scheduled and only the number was wrong — which is exactly how a count that is not a query fails. Repaired at the property |
| **Task 7 Property 2** | `grep -n "nine" mls/caller_arrays_test.go` | class **1** | **3 lines**: `:2176` and `:2180` are about `StateStore`'s method set, `:45` is about a different subject (nine constructions, not nine methods) | **class wrong, and its complement is the third line — also not found by the review.** Repaired at the property |

**What the defective rows have in common, stated as a predicate rather than as a list of
corrections, because that is what R6 is for — and the predicate has now been widened TWICE by its own
output.** In the first generation, the plan wrote the class's members down by hand, counted the list
it had written, and published the count as the derivation's answer; the right number appears only
where the query and the number sit side by side. **In the second generation, the query was there and
was never run against the class it claimed to derive** — Task 1 Property 4's seven lines contain zero
members of the class, and the gate table's *"three"* had no query at all in a row the review had
already corrected once. **The complement is still the half that fails first**, and the new tell sits
beside it: **an empty INTERSECTION between a published query's output and the class it derives.**
Both are one command each — `grep -c` the class member's spelling in the query's own output; print
what the narrowing removed. **Task 5 Property 5 remains the control**: its class and its complement
both reproduce, they exhaust a universe the compiler can name, and 4 + 4 is `GroupConfig`'s whole
field set. It is the shape every repaired row above is written into.

### The sweep for R7's class: every value this plan assembles over an array something else owns

**The class is four sites and the complement is one.** Two of the four were held before this repair
and two were not; the second of the two is the defect this repair exists for.

| Site | The array it aliases | Who erases it | Held by |
|---|---|---|---|
| Task 4: `NewKeyPackageWithSigner(..., self.signer, ...)` writing `kp.signPriv` | the engine's `device_sig` | `(*KeyPackage).Zeroize` (`key_package.go:212`) | **held** — **Task 1 Property 2** (the constructor must CLONE) and **Task 4 Property 2** (the engine erases the minted value and `self.signer` survives it) |
| Task 2: the wrapper's own drawn seed, handed to the delegate and dropped | a LOCAL, not a field — but the seed's only other holder is the delegate's clone | nothing, once the delegate clones | **NOT held before this repair.** `mls/staged_erase_test.go` holds struct fields and this is an array on the stack. **Now Task 2 Property 4** |
| Task 5: `JoinKeyMaterial.InitPrivate` / `.EncryptPrivate` over what `TakeKeyPackage` answered | the STORE's own arrays | `(*JoinKeyMaterial).Zeroize` (`group.go:2947`) | **held** — **Task 5 Property 3** (assemble over copies, so the put-back restores octets rather than zeros) |
| Task 5: `JoinKeyMaterial.SignPrivate` | the engine's `device_sig` — **the same array as row 1** | `(*JoinKeyMaterial).Zeroize`, which erases `SignPrivate` by name | **NOT held before this repair, and this one destroys the device's identity.** Task 4 Property 2 holds the aliasing on the mint path and Task 5 states the assembly; the document stated both halves and held neither. **Now Task 5 Property 6** |
| **Task 4: `initPrivate`, the init private half `NewKeyPackageWithSigner` answers** — arm (ii) | a local the constructor drew and handed back; the STORE gets a copy (`sessionfixture_test.go:101-108` appends) and the engine's local is dropped | **nothing.** Task 4 Property 2's `defer keyPackage.Zeroize()` reaches `key_package.go:213`, which is `zeroizeSecret(self.signPriv)` and nothing else | **NOT held, and it is pre-existing at `a1f8025`** — `mls.NewKeyPackage`'s three existing callers drop it the same way. `JoinKeyMaterial.Zeroize`'s header, the authority this plan quotes twice as the reason `SignPrivate` must be erased, names this array FIRST: *"the init key opens every Welcome addressed to this key package"*. **Now Task 4 Property 5** |
| **Task 4: `encryptPrivate`, the leaf encryption private half** — arm (ii) | the same shape, one value over | **nothing**, for the same reason | **NOT held, pre-existing at `a1f8025`.** Same header, next clause: *"the encryption key is this member's leaf key for as long as it holds that leaf"*. Task 5 Property 3 holds both of these at JOIN time, one task later, and nothing holds them at MINT time. **Now Task 4 Property 5** |

**The complement, printed: one site.** Task 5's `mls.GroupConfig{Crypto: self.crypto, Store:
self.store}` aliases neither array — both are interfaces, `mls/group.go:3407` keeps `cfg.Store`
deliberately, and nothing erases an interface. It is named and excluded rather than omitted, for
`caller_arrays_test.go:35-50`'s own reason: *"an interface parameter hands over an OBJECT and not a
buffer"*, and a sweep that dropped it silently could not be told from one that never looked at the
config.

**The predicate, so the next plan can run this without an instance to copy, and stated in the two
arms the table actually has:** a site is in R7's class when a task's body handles a secret array
whose erase is somebody else's obligation — **arm (i)**, it puts an array it does not own (a field of
`self`, or an array another component handed back) into a structure whose type declares a `Zeroize`;
or **arm (ii)**, it holds a secret array that no `Zeroize` will reach, because the array is a local
it drew or a private half a callee answered and the body then drops. The engine has exactly one
arm-(i) field (`self.signer`), `connect/mls` has exactly two such types on this path (`KeyPackage`
and `JoinKeyMaterial`), and the arm-(ii) sites are read off the RESULT LISTS of the constructors each
task calls — which is the mechanical form, because a result list is enumerable and a body's locals
are not: **`NewKeyPackageWithSigner` answers four values, one of them an error and three of them
secret, and Task 4's body erases exactly one of the three.**

**Why the two new rows are printed as class members rather than filed away as pre-existing.** They
are the shape of the complement R5 forbids: the first reading of this sweep printed a complement of
exactly ONE while claiming to cover *"every value this plan assembles over an array something else
owns"*, and the two arrays `JoinKeyMaterial`'s own header names FIRST were outside it. **A complement
of one, beside a class of four, over a rule this wide, is the tell** — and it was found by asking
what the table's own arm-(ii) row implied rather than by re-reading the four. The DEFECT is
pre-existing at `a1f8025`; the OMISSION was this document's.

### The gates already in the tree, which this plan's code must satisfy from its first commit

**NINE of the sixteen rows below go RED on Task 1's commit, measured by building Task 1 and running
the package, and the number is a COMMAND rather than a reading (R6 clause b).** The command, run in a
throwaway copy of `connect` outside both checkouts with `NewKeyPackageWithSigner` declared and
undriven and Task 2 NOT applied:

```
go test ./mls/ -count=1        # unfiltered; ~120s.  9 top-level FAILs, every one naming
                               # NewKeyPackageWithSigner
```

**Then add the three rows Task 1's Files block schedules — `providerConstructionValues`,
`labelledCompositionClass`, the `covered` case in `key_schedule_test.go` — and re-run the same
command: those three go green and SIX remain red.** So Task 1 cannot be a green commit with the three
edits this plan used to schedule, and that is a dispatch-time fact rather than a review comment: an
implementer meets it at step 2 of Task 1, before anything of the property has been written.

**Every one of the nine derives its class off `connect/mls`'s own parse tree**, through one of four
landed helpers — `declaredFunctionsOf(t, cryptoOwnRoot)` (`crypto_test.go:7263`),
`packageLevelFunctionsTaking(t, providerInterfaceName)` (`:2723`),
`packageLevelFunctionsTakingCallerBytes(t)` (`:2805`) and `providerOperations(t)` (`:4619`, which is
`providerInterfaceMethods` concatenated with `providerConstructions`). **That is the QUERY behind the
number, and it is why the class was never three:** the constructor's SIGNATURE alone joins it to
every one of them — it is package-level, it takes a `CryptoProvider`, it takes a caller byte run
(`signer SignaturePrivateKey`), it reaches `marshalBytes`, and it answers byte runs. None of the nine
is an artefact of a particular body.

```
grep -rn "declaredFunctionsOf(t\|packageLevelFunctionsTaking(t\|packageLevelFunctionsTakingCallerBytes(t\|providerOperations(t\|providerConstructions(t" --include=*_test.go mls/
```

**Two of the six that stay red live in test files this plan named nowhere — `mls/crypto_labels_test.go`
and `mls/extension_test.go` — and one of them wants a WRITTEN DESIGN ARGUMENT rather than a row.**
Task 1's Files block now carries five test files, and the earlier reading of this section, which
asserted there was *"no gate it must not disturb"*, was a conclusion drawn from a three-markdown-file
grep; the measurements table above carries it with its scope narrowed to what it measured. **The
replacement it was given, three, was the same defect a second time** — see R6's second clause.

| Gate | Where | What it does to this plan |
|---|---|---|
| `TestEveryDeclarationHandedANilProviderRefusesRatherThanDereferencingIt` | `mls/provider_nil_test.go:321`, fatalling through `providerConstructions` at `mls/crypto_test.go:4591` | **RED on Task 1's commit, and FATAL rather than reporting.** Its class is every package-level construction taking a `CryptoProvider`, read off the parse tree; the new constructor is one, and `providerConstructionValues` (`crypto_test.go:4443`) holds no value for it, so the gate cannot call it and stops. **Owed in Task 1's commit: one row in that map.** This is not bookkeeping — it is the gate that holds Task 1 Property 5's nil-provider refusal, so the row is what makes Task 1 mutation 13 red |
| `TestEveryCompositionEnteringALabelledConstructionIsBoundedBeforeItGetsThere` | `mls/labelled_composition_test.go:1859`, class literal at `:1841-1857` | **RED on Task 1's commit.** It derives every composition entering a labelled construction off the parse tree and compares with `slices.Equal`; `key_package.go NewKeyPackageWithSigner: signedPreimage -> *suiteCryptoProvider.SignWithLabel content` arrives outside its known set. **Owed in Task 1's commit: one row added at `:1849`'s neighbour. And it moves a SECOND time, in Task 2's commit, when the `NewKeyPackage` row comes back out** — that two-rows-to-one movement is what Task 2 Property 3 is now written over, instead of a second gate deriving the same class |
| `TestEveryConstructionHandedAProviderReadsKdfNhFromIt` | `mls/key_schedule_test.go:4793`, erroring at `:5441-5444` | **RED on Task 1's commit.** Its `covered` table is compared against `packageLevelFunctionsTaking(t, providerInterfaceName)`, which reads every non-test file of the package (`crypto_test.go:2723`, held by `TestThePackageLevelFunctionScanReadsEveryNonTestFile`). **Owed in Task 1's commit: a row in `covered`, or an entry in `constructionsWhoseAnswerOnlyCoincidesWithKdfNh` with the reason** |
| `TestTheEngineInterfacesAreExactlySectionSixsBlock` | `messagegroup/engine_test.go:137`, table at `:39` | `GroupEngine`'s four signatures are pinned string-for-string to Spec A §6. **This plan changes none of them** — the join body changes, the signature does not |
| `TestOnlyOneProductionFileOfThisPackageNamesMlsGroup` | `messagegroup/engine_test.go:254` | exactly **one** production file may name `mls.Group`, matched by scanned path ending `/engine.go`, and the count is asserted. The join body lives in `engine.go` |
| the complete production import set | `messagegroup/imports_test.go:34` | pinned as a whole. `mls`, `mls/syntax`, `fmt` and `errors` are already in it; **this plan adds no import** |
| `TestTheRecordingStoreReadsEveryArgumentItsInterfaceDeclares` | `mls/caller_arrays_test.go:2181` | reflect-driven over `StateStore`'s whole method set. Untouched, because the interface does not move |
| `TestNewKeyPackageKeepsTheSigningSeedOffTheWireAndBesideItsOwnLeaf` | `mls/key_package_test.go:471` | holds `signaturePublicKeyOf(kp.signPriv) == kp.LeafNode.SignatureKey`. **GREEN on Task 1's commit with the new constructor present and undriven — measured, not predicted** — because its class is one hand-named constructor. That is Task 1 Property 4's whole diagnosis, and it is the one row here whose passing is the finding |
| `TestJoinFromWelcomeRefusesAndSaysWhatIsMissing` | `messagegroup/engine_test.go:823` | asserts the refusal. **It goes red on the commit that closes S2-4, by design; that is the gate working.** Task 6 inverts it |
| `TestNoOctetAGroupHandsOutwardIsStorageItKeeps` | `mls/caller_arrays_test.go:2214` | the array-ownership direction Task 5 Property 3 works inside |
| `TestEveryConstructionHandedAProviderRoutesThroughIt` | `mls/crypto_labels_test.go:2354`, class at `:2345` | **RED on Task 1's commit and STILL RED after the three rows above.** `covered` is compared against `packageLevelFunctionsTaking(t, "CryptoProvider")` minus `labelConstructionsOverAnyProvider`. **Owed: a call closure case beside `NewKeyPackage`'s at `:2212`, whose answer over the tagging provider must be a REFUSAL for `NewLeafNode`'s stated reason** — or an entry in the excusal map with its reason. **This file appears nowhere else in this plan** |
| `TestEveryConstructionInThisPackageLeavesItsInputAlone` | `mls/crypto_test.go:4117`, class at `:4108` and `:4132` | **RED on Task 1's commit and STILL RED after the three rows above.** Its class is `packageLevelFunctionsTakingCallerBytes` concatenated with `packageLevelFunctionsTaking(providerInterfaceName)`, and the new constructor joins by taking `signer SignaturePrivateKey` — a caller byte run — as well as a provider. **Owed: one case in that gate's `covered` list**, and the case is the one that would have caught Task 1 mutation 5 from a second direction |
| `TestProviderHasNoRemainingStubs` | `mls/crypto_test.go:5709`, reporting at `:5743`, `:5746`, `:5931` | **RED on Task 1's commit and STILL RED after the three rows above**, with THREE separate messages. Measured: `NewKeyPackageWithSigner answered result 0 field 4 is empty, which is what a stub answers` — that field is the leaf's `parent_hash`, empty for exactly the reason `NewKeyPackage`'s and `NewLeafNode`'s are. **Owed: an entry in `providerConstructionsWithUndefinedResults` (`:5563`), an entry in `providerConstructionsAnsweringOffTheWallClock` (`:5617`) because the leaf carries a wall-clock `Lifetime`, and a row in `providerStreamDependentOperations` (`:5482`)** |
| `TestNoProviderOperationFallsBackWhenItsSourceRunsDry` | `mls/crypto_test.go:7888`, reporting at `:7916` | **RED on Task 1's commit and STILL RED after the three rows above.** It compares what refused an exhausted source against `providerStreamDependentOperations`; the constructor draws twice, so it refuses and the two lists disagree. **Owed: the same `providerStreamDependentOperations` row**, whose comment must say what this construction draws and why — two entropy draws and NO signature key pair, which is the one line where the difference from `NewKeyPackage` is a number |
| `TestEveryProviderOperationDrawsExactlyWhatItUses` | `mls/crypto_test.go:8237`, reporting at `:8259` and `:8273` | **RED on Task 1's commit and STILL RED after the three rows above.** Measured: `NewKeyPackageWithSigner drew 64 bytes of the source, want 0`. **Owed: a row in `providerStreamDraws` (`:8191`) answering `2 * params.Nh`** — against `NewKeyPackage`'s `NsigPriv + 2*params.Nh`, and **that row IS Task 1 Property 3**, which is why Property 3 is now written as a reuse rather than as a new gate |
| `TestNoExportedSymbolOfThisPackageAssemblesAnExtensionBodyThroughItsOwnEncoder` | `mls/extension_test.go:3505` and `:3512` | **RED on Task 1's commit and STILL RED after the three rows above**, and it is the one that cannot be closed by a row. Measured, in the gate's own words: *"key_package.go exports NewKeyPackageWithSigner, which reaches [marshalBytes marshalRatchetTree] and answers a byte run; an extension body handed out loose is a tag choice handed to the caller, and 0xF001 rather than 0xF002 encodes, signs and travels."* **Owed: an entry in `extensionBodyByteRunsThatAreNotBodies` (`:2770`) carrying a WRITTEN DESIGN REASON**, in the shape `NewKeyPackage`'s own entry already has — the two HPKE private halves are keys and not bodies. `TestEveryExtensionBodyByteRunExemptionIsStillReported` expires an entry neither rule reports any more, so the entry cannot outlive the declaration. **This file appears nowhere else in this plan** |

### House style

Receivers are `self`. Errors are sentinels wrapped with `fmt.Errorf("%w: detail", sentinel, ...)` so
`errors.Is` still matches and the detail carries the counts a caller needs. Comments say why, not
what. Nothing in `connect` is modified outside the two packages named above.

---

## Interfaces consumed from other plans

Everything below exists and compiles at `a1f8025`. Shapes are described so the plan is readable;
**their spellings are not normative (R2)** and every one must be read out of the file that declares it
before a call is written.

```go
// connect/mls/group.go — the join, and the material it takes. COMPLETE and correct:
// 144 references across 13 mls test files, multi-member round trips green.
// This plan calls it and does not touch it.
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte,
    keys *JoinKeyMaterial) (*Group, error)

type JoinKeyMaterial struct {
    KeyPackage     KeyPackage
    InitPrivate    HpkePrivateKey
    EncryptPrivate HpkePrivateKey
    SignPrivate    SignaturePrivateKey
}
func (self *JoinKeyMaterial) Zeroize() // erases the three privates AND KeyPackage.signPriv
```

**The fields of `GroupConfig` that `JoinFromWelcome` actually reads, derived from its body rather than
from its doc comment** (`sed -n '3033,3440p' mls/group.go | grep -n 'cfg\.'`): `Crypto` (refused if
nil), `Store` (refused if nil), `Profile` (defaulted if nil), and `GroupId` — **only when the caller
sets it**, as an intent match, at `mls/group.go:3255`. `Suite`, `Extensions`, `RequiredCaps` and
`LeafKeys` are **not read**; required capabilities come off the Welcome's `GroupInfo`.

```go
// connect/mls — the door a joiner outside package mls already has to a Welcome's
// addressing. Every one of these is exported; no helper is needed and none exists.
func ParseMLSMessage(data []byte) (*MLSMessage, error)   // framing.go:1079
type MLSMessage struct{ /* ... */ Welcome *Welcome /* ... */ }   // framing.go:890
type Welcome struct {
    CipherSuite        CipherSuite
    Secrets            []EncryptedGroupSecrets
    EncryptedGroupInfo []byte
}                                                        // welcome_wire.go:296
type EncryptedGroupSecrets struct {
    NewMember             []byte    // THE KeyPackageRef this entry is addressed to
    EncryptedGroupSecrets HpkeCiphertext
}                                                        // welcome_wire.go:256
```

```go
// connect/mls/key_package.go — what exists, and the one thing it does not offer.
// It draws its OWN signature key pair at :289 and parks the private half on the
// unexported signPriv at :314. There is no parameter for a caller's signer.
func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,
    caps Capabilities, exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
    encPriv HpkePrivateKey, err error)
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error)
func (self *KeyPackage) Validate(crypto CryptoProvider, suite CipherSuite, now time.Time) error
func (self *KeyPackage) Zeroize()   // erases signPriv and nothing else

// and the two package-level derivations deliberately OUTSIDE CryptoProvider,
// which JoinFromWelcome's caller-material gate runs on:
func signaturePublicKeyOf(priv SignaturePrivateKey) (SignaturePublicKey, error) // crypto_labels.go:528
func hpkePublicKeyOf(priv HpkePrivateKey) (HpkePublicKey, error)                // hpke.go:192
```

`SignaturePrivateKey` is an **ed25519 seed**: `signaturePublicKeyOf` length-checks against
`ed25519.SeedSize` and expands with `ed25519.NewKeyFromSeed`, and the public half is **copied** out of
the expanded key rather than sliced from it, so a window onto the expanded key cannot reach the seed.
Task 1's constructor inherits that reasoning; it does not restate the primitive.

```go
// connect/mls/leaf_node.go — both EXPORTED, both taking a caller's signer.
// This is the asymmetry: a leaf can be built against a caller's key from
// outside the package, and the KeyPackage signature over it cannot.
func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey, ...) error
func NewLeafNode(crypto CryptoProvider, signer SignaturePrivateKey, cred Credential, ...) (*LeafNode, error)
```

```go
// connect/messagegroup/engine.go — section 6's factory, pinned string-for-string
// by engine_test.go:39. THIS PLAN CHANGES NO SIGNATURE ON IT.
type GroupEngine interface {
    Suite() uint16
    NewKeyPackage() (keyPackage []byte, err error)
    CreateGroup(groupId []byte, policy []byte, leafKeys []byte) (GroupHandle, error)
    JoinFromWelcome(welcome []byte, ratchetTree []byte) (GroupHandle, error)
}

// the engine ALREADY holds every input the join needs but one, and the one it
// is missing is a binding rather than a value.
type connectMlsEngine struct {
    crypto   mls.CryptoProvider
    store    mls.StateStore
    signer   mls.SignaturePrivateKey   // a real device signing key, refused if empty at :186
    cred     mls.Credential
    leafKeys []byte                    // the encoded urmessage_leaf_keys body
}
```

**From `GroupHandle` (`messagegroup/engine.go:66`), the methods Task 6 drives:** `GroupId`, `Epoch`,
`OwnLeafIndex`, `MemberCount`, `MemberAt`, `Export`, `ProposeAdd`, `Commit`, `MergePendingCommit`,
`Close`. **`Commit(nil)` commits every cached proposal** — `CreateCommit`'s nil arm at
`mls/group.go:1980` appends `self.proposals.Pending(...)` and `ProposeAdd` caches locally — so no new
seam method is needed for the founder to produce a Welcome. **An empty non-nil vector commits
nothing**; that overload is **J1-7**.

---

## Interfaces produced by this plan

Every later plan writes its `Consumes` block against these. Each is restated inside the task that
creates it. Shapes, not spellings (R2).

```go
// connect/mls/key_package.go — Task 1. The ONE addition to connect/mls.
// It draws the two HPKE pairs and NO signature key; the leaf's signature key,
// the leaf signature, the KeyPackageTBS signature and the retained seed are all
// the caller's signer, bound in one statement list.
func NewKeyPackageWithSigner(crypto CryptoProvider, suite CipherSuite,
    signer SignaturePrivateKey, cred Credential, caps Capabilities,
    exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
    encPriv HpkePrivateKey, err error)
```

```go
// connect/messagegroup/errors.go — Task 5. The refusals that REPLACE
// ErrEngineJoinUnavailable, and which name runtime conditions rather than a gap
// in another package's exported surface.
var ErrEngineNoKeyPackageForWelcome error // no key package this store holds is addressed by this welcome
var ErrEngineWelcomeShape error           // the octets are not an MLSMessage carrying a Welcome
```

**`mls.StateStore` is NOT in this list, and that is the point of the section above.** Its eight
methods and their four `PutKeyPackage` arguments are exactly what they were at `a1f8025`.

---

## File Structure

Every file created or modified by this plan, and its single responsibility.

| File | Responsibility |
|---|---|
| `connect/mls/key_package.go` | **modify:** Tasks 1 and 2. `NewKeyPackageWithSigner`, and `NewKeyPackage` re-expressed as the one-draw wrapper over it so exactly one body assembles a `KeyPackageTBS`. Also the two comments at `:58-63` and `:257-261` that describe a mechanism no code uses |
| `connect/mls/key_package_test.go` | **modify:** Tasks 1 and 2. The binding gate, the clone gate, the derived constructor class, and the determinism pair |
| `connect/mls/group.go` | **modify:** Task 1, comment only. `JoinKeyMaterial`'s header at `:2935-2941` says `signPriv` is set by `NewKeyPackage`; after Task 1 two constructors set it |
| `connect/mls/staged_erase_test.go` | **modify:** Task 1, one excuse string. `:1313` says `signPriv` is *"written only by NewKeyPackage"* |
| `connect/mls/welcome_test.go` | **modify:** Task 3. The in-package round trip that proves a Task 1 key package is joinable |
| `connect/messagegroup/engine.go` | **modify:** Tasks 4 and 5. `NewKeyPackage` mints under `self.signer`; `JoinFromWelcome` gets a body. Both stay in this one file — it is the only production file the `mls.Group` gate permits, and a second file is one edit away from naming the group |
| `connect/messagegroup/errors.go` | **modify:** Task 5. `ErrEngineNoKeyPackageForWelcome` and `ErrEngineWelcomeShape` in; `ErrEngineJoinUnavailable` out |
| `connect/messagegroup/doc.go` | **modify:** Task 6. The honest-inventory paragraph at `:47-56` says *"It cannot join a group"* and gives the reason S2-4 gives |
| `connect/messagegroup/sessionfixture_test.go` | **modify:** Task 4, two changes and the row states the CHANGE rather than the defect. **(1)** `buildTestEngine` (`:143`) must draw the credential identity **independently** of the signer; today `:148` draws `signer, identityPub` from one `crypto.SignatureKeyPair()` and `:165` passes `mls.BasicCredential(identityPub)`, so the assertion *"the leaf names the device signer"* and the assertion *"the leaf names the credential"* are the same program. **(2)** `testEngine` (`:122`) must gain a `signerPub` field: it retains `identityPub` and neither the signer nor its public half, so Task 4 Property 1's comparison has nothing to read. Blast radius measured and re-measured: `grep -rn "identityPub" --include=*_test.go messagegroup/` is 14 lines, the only one comparing the two is `engine_test.go:722` (which reads `Credential.Identity` at `mls/group.go:779` and stays true), and the split plus the field was applied and 185 of 186 tests still pass |
| `connect/messagegroup/engine_test.go` | **modify:** Tasks 4, 5 and 6. The mint gate, the join-refusal gates, and the inversion of `TestJoinFromWelcomeRefusesAndSaysWhatIsMissing` |
| `connect/messagegroup/enginejoin_test.go` | **create:** Task 6. The two-engine join. **Named `enginejoin_test.go` and not `join_test.go` on purpose:** m1 Task 16's Files block already claims `connect/messagegroup/join_test.go`, and two plans creating one file is how a dispatched task discovers a merge |
| `connect/mls/caller_arrays_test.go` | **modify:** Task 7, one word. `:2176` says *"a hand written double is nine wrappers"* and `StateStore` declares eight |
| `msgrepo/docs/plans/2026-08-12-slice1-interface-registry.md` | **modify:** Task 7. The registry entry for what this plan produced |

---

## How to read a task

Each task has **Files**, an **Interfaces** block naming exactly what it consumes and what it produces,
and numbered steps. The steps are always the same six, and steps 1 and 5 are where the work is.

1. **Derive the property and write the failing test.** The task states the property, the refusal that
   property owes, and — separately, per R3 — the scope the gate must derive. It does **not** state the
   test. Read every signature you call out of source (R2).
2. **Run it and watch it fail for the stated reason.** A test that fails to compile has not yet failed
   for the stated reason.
3. **Write the minimal implementation.**
4. **Run it and watch it pass.**
5. **Mutation-test.** Apply each numbered mutation, run the targeted `-run` first, and record the
   result. Any mutation that survives the targeted run is re-run against the full package. **A
   surviving mutation is a defect in the test, not a curiosity**: fix the test and re-run the whole
   set. Record survivors and their reason in the commit message.
6. **Commit.**

---
## Wave 1 — `connect/mls`: a key package bound to a caller's signing key (Tasks 1–3)

**This wave needs no other work and no ruling. It is not, however, free of the tree.** No
`messagegroup` change, no store change, no ruling from anybody; `mls.NewKeyPackage` keeps its
signature, its behaviour and its 16 call sites, and `mls.StateStore` is untouched. **But additive to
an exported package is not additive to a package whose gates derive their classes off it: NINE landed
gates in `connect/mls` go RED on Task 1's commit, measured unfiltered, and six of the nine are still
red after the three table rows this plan used to schedule.** All nine are named in the gate table
above with what each is owed, and Task 1's Files block carries the FIVE test files they live in. An
implementer who reads *"additive"* as *"nothing else moves"* stops at step 2 of Task 1 — and one who
reads the earlier *"three"* stops there too, three edits later, which is the whole reason the number
is now a command. **This wave
must land before Wave 2**, because
`connect/messagegroup` imports `connect/mls` and the engine's join cannot be written against a surface
that does not exist.

### Task 1: `NewKeyPackageWithSigner` — the four bindings, and the clone that keeps the caller's key

**Files:**
- Modify: `connect/mls/key_package.go`, `connect/mls/group.go` (the `JoinKeyMaterial` header comment
  at `:2935-2941` only)
- Test: `connect/mls/key_package_test.go` (extend), `connect/mls/staged_erase_test.go` (one excuse
  string at `:1313`)
- **Test, and this commit does not compile-and-pass without every one of them** — the NINE derived
  gates the section *"The gates already in the tree"* now names, each RED on this commit because its
  class is the package's own parse tree and the new constructor joins it undriven. **Measured by
  building Task 1 and running `go test ./mls/ -count=1` unfiltered: nine red; three of the nine go
  green on the first three files below and SIX stay red**, so an implementer who stops after those
  three has a red commit. In five files:
  - `connect/mls/crypto_test.go` — **six separate edits, not one.** One `providerConstructionValues`
    row at `:4443` (or `TestEveryDeclarationHandedANilProviderRefusesRatherThanDereferencingIt`
    **fatals**); one `covered` case in `TestEveryConstructionInThisPackageLeavesItsInputAlone`
    (`:4108`); one entry in `providerConstructionsWithUndefinedResults` (`:5563`) for the leaf's empty
    `parent_hash`; one entry in `providerConstructionsAnsweringOffTheWallClock` (`:5617`) for the
    leaf's `Lifetime`; one name in `providerStreamDependentOperations` (`:5482`); one row in
    `providerStreamDraws` (`:8191`) answering `2 * params.Nh` — **and that last row is Task 1
    Property 3**
  - `connect/mls/labelled_composition_test.go` — one `labelledCompositionClass` row beside `:1849`
  - `connect/mls/key_schedule_test.go` — one `covered` row, or an excused entry with its reason, at
    `:5441-5444`
  - `connect/mls/crypto_labels_test.go` — one call closure case beside `NewKeyPackage`'s at `:2212`,
    answering a REFUSAL over the tagging provider for `NewLeafNode`'s stated reason; or an entry in
    `labelConstructionsOverAnyProvider` with its reason. **Named in no earlier reading of this plan**
  - `connect/mls/extension_test.go` — one entry in `extensionBodyByteRunsThatAreNotBodies` (`:2770`)
    carrying a **written design reason**, in the shape `NewKeyPackage`'s own entry already has.
    **Named in no earlier reading of this plan, and it is the one that cannot be closed by a row**

**Interfaces:**
- Consumes: from `connect/mls` itself and from nothing else — `NewLeafNode`, `LeafNode.Sign`,
  `signaturePublicKeyOf`, `keyPackageSignatureLabel`, `(*KeyPackage).signedPreimage`,
  `CryptoProvider.DeriveKeyPair`, `CryptoProvider.Random`, `CryptoProvider.SignWithLabel`,
  `CryptoProvider.Suite`. Nothing from any other plan's task.
- Produces:
```go
// key_package.go — the sibling constructor. It draws the two HPKE pairs and NO
// signature key: the leaf's signature_key, the leaf signature, the KeyPackageTBS
// signature and the retained seed are all one caller-supplied key.
func NewKeyPackageWithSigner(crypto CryptoProvider, suite CipherSuite,
    signer SignaturePrivateKey, cred Credential, caps Capabilities,
    exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
    encPriv HpkePrivateKey, err error)
```

**Why this and not an accessor on `KeyPackage`.** The obvious smaller change is to export the seed —
`func (self *KeyPackage) SignPrivate() SignaturePrivateKey` — and let the caller persist it through
`PutPrivateKey`. It closes S2-4 with a one-line addition, and it is rejected here for a reason that is
a measurement rather than taste: **it preserves the identity split probe 1 found.** A device that can
read the seed of a key it did not choose still publishes a leaf naming a key that is not `device_sig`,
still founds groups under a different one, and still has nothing anywhere that would report it. An
accessor makes the split persistable; a signer parameter makes it impossible. **The complement is
printed rather than implied: the set of defects an accessor closes is exactly one — "the joiner cannot
reach the seed" — and the set this constructor closes is that one plus "the device has two
identities".**

**And why a sibling rather than a signature change to `NewKeyPackage`.** Measured:
`grep -rn "NewKeyPackage(" --include=*.go . | grep -v "func "` answers **20 lines**, of which **16
are calls to `mls.NewKeyPackage`** — one production and 15 across 8 `mls` test files; the four the
query returns and the class excludes are printed in the measurements table above rather than
hand-dropped here (R6). A signature change is **16 edits across 9 files** in one commit, for a
constructor whose
existing behaviour — draw a fresh key, keep it beside the leaf — is a correct thing to offer and is
what `mls`'s own suite exercises. **Task 2 removes the duplication the sibling would otherwise
create**, which is the half that actually matters.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the four bindings agree, and a key package this constructor answers is one every
  verifier in the package accepts.** All four of: `kp.LeafNode.SignatureKey` is the public half of
  `signer`; `kp.LeafNode`'s own signature verifies under that key; `kp.Signature` verifies as a
  `KeyPackageTBS` signature under that key; and `signaturePublicKeyOf(kp.signPriv)` equals
  `kp.LeafNode.SignatureKey`. **Four and not fewer, and the count is the property.**
  `lifecycle_fixtures_test.go:206-217` is the argument, in the tree, in its own words: rebinding the
  leaf alone *"leaves `kp.Signature` over the old leaf, which `KeyPackage.Validate` refuses with
  `errKeyPackageBadSignature`, and leaves `kp.signPriv` holding a private key whose public half the
  leaf no longer names, which nothing refuses at all — it is read, used to sign a joiner's first
  message, and rejected by every peer."* One of the four failures is loud and one is silent, and the
  silent one is why this is a property with four clauses rather than a call to `Validate`.
  *Refusal owed:* none on the success path. `(*KeyPackage).Validate(crypto, suite, now)` must return
  nil, and the leaf's own `VerifySignature` must return nil, over a key package minted here.

  **Property 2 — `kp.signPriv` is a COPY of the caller's signer, and `(*KeyPackage).Zeroize` erases
  the copy and leaves the caller's array intact.** This is the clause that makes the whole design
  safe and it does not exist in `NewKeyPackage`, because there the seed has no other owner. Here the
  seed **is `device_sig`**: an implementation that stores the caller's slice hands `(*KeyPackage).Zeroize`
  — and therefore `(*JoinKeyMaterial).Zeroize`, which calls it at `mls/group.go:2951` — a licence to
  erase the device's long-term signing key out from under the engine that owns it. The engine in Task 4
  is required to erase the minted value, so this is not a hypothetical caller.
  *Refusal owed:* none; the failure is silent by construction, which is why the gate must read the
  caller's array **after** `Zeroize` and assert it is unchanged, rather than reading the key package.

  **Property 3 — the init key pair and the leaf encryption key pair are still drawn from separate
  entropy, and neither is derived from `signer`. HALF OF THIS IS ALREADY DERIVED IN THE TREE AS A
  NUMBER, so this property REUSES that gate and states only the half it cannot see.** This is the
  same repair Task 2 Property 3 received one property over, and it was missed by the first R6 sweep
  because Property 3 is not written as class-deriving — which is why R6 now scopes itself over the
  document rather than over its properties (R6 clause b).

  **Clause A — the count, and the tree already derives it. The class this clause reuses is the
  operations of this package that draw from the provider's stream; that class is EIGHT members at
  `a1f8025` and nine at this task**, read off `providerStreamDraws` (`crypto_test.go:8191`) and
  cross-checked against `providerStreamDependentOperations` (`:5482`), which is **nine at `a1f8025`
  and ten at this task** because it carries `Random` and the draws map does not. Both are derived
  against `providerOperations(t)` rather than written down: an entry naming something that is not an
  operation of this surface fails, and an operation the map does not name is asserted to draw zero.
  `providerStreamDraws` is a map from construction name to bytes drawn, and its `NewKeyPackage`
  comment states this property in its own words:
  *"a constructor that derived the init pair and the encryption pair from ONE seed draws KDF.Nh fewer
  bytes and answers a key package that encodes, signs, refs and validates, so this is the one place
  in the package where that substitution is a NUMBER rather than a property somebody has to think to
  compare."* **The row Task 1's commit owes anyway — `"NewKeyPackageWithSigner": 2 * params.Nh` — IS
  clause A.** Measured, in the throwaway build: with the row added and the body correct, the count
  check at `crypto_test.go:8259` is silent; with **mutation 7** applied the LANDED gate goes red on
  its own, `NewKeyPackageWithSigner drew 32 bytes of the source, want 64`, at both registered suites.
  **Mutation 8 collapses to the same single draw and is caught the same way.** So clause A owes no
  new gate, and a second gate deriving the same class here would be the defect Task 2 Property 3 was
  repaired for.

  **Clause B — the half a count cannot see, and its complement is not empty.** A body that draws
  TWICE and derives both pairs from the FIRST draw answers `2 * params.Nh` and passes clause A
  exactly. **Measured, in the throwaway build: that mutant produces no `drew N bytes` line at all —
  the count gate does not see it.** What sees it is the ANSWER comparison, which the tree holds only
  for `NewKeyPackage` and only by hand: `TestNewKeyPackageDrawsTheInitAndEncryptionKeysFromSeparateEntropy`
  (`key_package_test.go:419`) runs over `newTestKeyPackage(t)`, a hand-named constructor — the same
  shape as `TestNewKeyPackageKeepsTheSigningSeedOffTheWireAndBesideItsOwnLeaf`, which is Property 4's
  whole diagnosis. **Clause B is therefore the one this task must write, and it is written over the
  answers rather than over the draws.**
  *Refusal owed:* none; the observation is that a message sealed to the leaf's `encryption_key` does
  not open under `initPriv`, and vice versa — and, separately, that `initPriv != encPriv` and
  `kp.InitKey != kp.LeafNode.EncryptionKey`.
  *The observation ROUTE (R4's third clause):* `crypto.HpkeSeal` / `crypto.HpkeOpen` over the
  constructor's own two answered privates and the key package's two published publics. Every name on
  it is in this task's Consumes block and every value is answered by the constructor under test.
  *This project has measured that exact substitution surviving a whole green suite one plan ago.*

  **Property 4 — the seed-and-leaf agreement gate's class is DERIVED from the package's own
  declarations rather than named, and every member of it is driven.** The gate that holds Property 1's
  fourth clause today is `TestNewKeyPackageKeepsTheSigningSeedOffTheWireAndBesideItsOwnLeaf`
  (`key_package_test.go:471`), and it drives **one hand-named constructor**. A sibling added beside a
  hand-named gate is a second minting door outside it, which is this project's most expensive shape —
  and **measured, that gate PASSES with `NewKeyPackageWithSigner` present and undriven.** That passing
  run is this property's diagnosis and it is a measurement, not a prediction.

  **The universe, the class and the complement, each beside the query that produces it (R6) — and the
  query re-derived, because the one this property published RETURNS THE COMPLEMENT AND NOTHING ELSE.**

  **The defect, printed rather than quietly corrected, because this is the exact row R6 was derived
  from and R6 did not catch its own row.** The query this property carried was
  `grep -rn "^func .*\*KeyPackage" --include=*.go mls/ | grep -v _test`, stated as returning a
  universe of **eight**. Measured at `a1f8025` it returns **SEVEN**, and
  `... | grep -c NewKeyPackage` is **ZERO**: `NewKeyPackage`'s declaration WRAPS — line 271 is
  `func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,` and `*KeyPackage`
  sits on the continuation line 272, which does not begin with `func`. **The seven lines it returns
  are exactly the seven this property printed as the COMPLEMENT.** So the class the property exists
  to derive was entirely outside the command printed beside it, at every commit; measured again in
  the throwaway build with `NewKeyPackageWithSigner` present, the answer is still 7 and the `grep -c`
  is still 0, because this plan's own `Produces` block spells the sibling across four lines too.
  **This is R6's second clause, clause (a), and it is the row that produced it: a query is checked
  for what it CONTAINS, not only for what it counts.**

  **The universe** is every function declaration of non-test `mls` whose signature mentions
  `*KeyPackage` in any position — **and it is an AST question, not a grep question**, because Go
  permits a declaration to wrap anywhere and this package's own style wraps every constructor in it.
  No line-oriented command can answer it: `grep -A1` widens the answer to every line after a `func`,
  and `go doc` reads the exported half only. **The gate therefore derives the universe the way this
  package's other derived gates already do** — `declaredFunctionsOf(t, cryptoOwnRoot)`
  (`crypto_test.go:7263`), which parses the package's non-test files and answers each declaration's
  name, receiver and parameter and result types. The universe is the declarations whose signature
  mentions `*KeyPackage` in ANY position; the class is those that ANSWER one; the complement is the
  rest. **A reader checks the number in one command by running the gate, and the gate PRINTS both
  sets** — which is a stronger check than a grep and is the only one that is right.

  **The numbers, measured through that derivation:** the universe is **eight** declarations at
  `a1f8025` and **nine** after this task; the class is **one** member at `a1f8025` (`NewKeyPackage`,
  `key_package.go:271`) and **two** at this task (`NewKeyPackageWithSigner`); the complement, printed,
  is **the other seven** — `marshalCore` (`:127`), `MarshalMLS` (`:137`), `UnmarshalMLS` (`:156`),
  `Zeroize` (`:212`), `signedPreimage` (`:236`), `Ref` (`:349`) and `Validate` (`:376`), every one a
  method taking a `*KeyPackage` as its receiver and answering something else. **8 = 1 + 7 and
  9 = 2 + 7, and both sums are printed on every run**, so a third constructor added next month is a
  number that changed rather than a door nobody drove. **The line grep is kept in this document only
  as the printed record of what it returns — 7 lines, 0 members of the class — so that the next
  reader does not re-derive it.**

  **Why the universe is stated and not only the class, and it is R5 read back to this document.** The
  narrower predicate — *"functions whose RESULT is a `*KeyPackage`"*, which is the predicate mutation
  10 requires — has an **EMPTY complement at every commit of this plan**, and `mls/GATES.md`'s table
  calls an empty complement the dangerous reading: *"the narrowing was written for members that do not
  exist."* Widening to the whole `*KeyPackage` signature universe and splitting it on *answers one*
  gives the same class, a complement of seven, and a predicate a reader checks in one command.
  **And it corrects what an earlier reading of this property printed as its complement:**
  `(*KeyPackage).UnmarshalMLS` (`key_package.go:156`) is in the complement but answers `error`, not a
  `KeyPackage`; and `MLSMessage.KeyPackage` (`framing.go:897`) is a **struct field**, not a function,
  so it is in neither set and in no function class at all. A complement whose two printed members were
  not in the predicate's domain is a complement that was never derived.
  *Refusal owed:* the gate fails closed on an underived member — a construction in the class that no
  case drove is a `t.Errorf` naming it, never a `continue`, which is `GATES.md`'s rule for the empty
  row of its own table.

  **Property 5 — the constructor's refusals are exactly `NewKeyPackage`'s refusals, minus the one it
  cannot have, plus the one it must.** *Minus:* `NewKeyPackage` can fail inside
  `crypto.SignatureKeyPair()`; this one never calls it, so that error path does not exist and the gate
  must say so rather than leave a reader to wonder. *Plus:* a `signer` that is not a valid signature
  private key. **The length check is not open-coded here**: `signaturePublicKeyOf` already checks
  against `ed25519.SeedSize` and answers `ErrBadSignatureKey`, and a second length literal in this
  file is a second place the constant can be wrong. *Kept:* nil `crypto`, refused **before any
  argument is judged** so a caller that passed none does not take the process rather than the call;
  and `crypto.Suite() != suite`, refused **before anything is drawn**, so a caller's mistake costs no
  entropy — both in `NewKeyPackage`'s order, both for `NewKeyPackage`'s stated reasons.
  *Refusal owed:* `ErrNilCryptoProvider` wrapped with what it was needed for; `errKeyPackageProviderSuite`
  carrying both code points; `ErrBadSignatureKey` for the signer.

  **The comment corrections this task owes, because it is the commit that makes them false.** All
  three are sentences a later reader would trust and re-derive the wrong fix from:
  `key_package.go:62-63` — *"read directly by the group lifecycle plan when it assembles
  `JoinKeyMaterial`"*; `key_package.go:257-261` — *"the signature seed rides on the unexported field
  instead, because … the group lifecycle plan reads it off the value when it assembles
  `JoinKeyMaterial`"*; and `staged_erase_test.go:1313` — `signPriv` is *"written only by
  `NewKeyPackage`"*. The first two are false **today**, before this task: measured,
  `grep -rn "SignPrivate:"` is 13 sites and **zero** of them read `kp.signPriv`. The third becomes
  false on this commit. `group.go:2935-2941` says the same thing from the other end and moves with
  them.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Set `kp.LeafNode.SignatureKey` from `signer` but sign the leaf with a freshly drawn key.
     **Property 1 must fail** on the leaf's own `VerifySignature`.
  2. Sign the leaf with `signer` but leave `kp.Signature` over a preimage taken before the leaf was
     rebound. **Property 1 must fail** with `errKeyPackageBadSignature` out of `Validate`.
  3. Set every binding from `signer` except `kp.signPriv`, which is left as a freshly drawn key.
     **Property 1 must fail** on its fourth clause, and **this is the mutation the fixture's own
     header says nothing refuses** — if it survives, the gate is reading `Validate` and calling that
     the property.
  4. Set `kp.signPriv` from `signer` and leave the leaf naming a freshly drawn public half.
     **Property 1 must fail**, in the direction opposite to mutation 3.
  5. Assign `signer` into `signPriv` directly instead of cloning it. **Property 2 must fail**: the
     caller's array is zeroed after `Zeroize`. A gate that reads only the key package passes this
     mutant, which is the whole reason Property 2 reads the caller's array.
  6. Clone `signer` into `signPriv` but have `Zeroize` erase nothing. **Property 2 must fail** on the
     key package's own copy still holding the seed.
  7. Derive both HPKE pairs from a single `crypto.Random` draw. **Property 3 must fail.**
  8. Derive `initPriv` from `signer` — the shape a constructor that "already has a key" invites.
     **Property 3 must fail.**
  9. Delete `NewKeyPackageWithSigner` from the derived class by naming the class as a literal list
     containing only `NewKeyPackage`. **Property 4 must fail**, and it must fail by reporting a class
     size of one against a package that declares two.
  10. Add a third, unexported constructor answering a `*KeyPackage` that binds only three of the four,
     **spelled in this package's own multi-line style so that its declaration WRAPS**. **Property 4
     must fail** by reporting a universe of ten, a class of three and a member the gate did not drive
     — which is the shape the sibling itself would have had without this property. **And the
     complement must still print seven**, which is what distinguishes this mutant from one that
     widened the predicate instead of adding a constructor. **The wrapping is the point of this
     mutation now, and it is what makes it reachable: against the line grep this property used to
     publish, a wrapped third constructor leaves the answer at 7 and this mutation SURVIVES.** A
     surviving mutation is a defect in the gate, so a gate that reads lines rather than declarations
     fails this mutation by construction.
  11. Move the suite check after the two `DeriveKeyPair` calls. **Property 5 must fail** on the
     stated ordering: a caller's mistake must cost no entropy.
  12. Open-code a `len(signer) != 32` check in `key_package.go` instead of letting
     `signaturePublicKeyOf` answer. **Property 5 must fail** on the refusal's identity — the sentinel
     a caller matches with `errors.Is` must be `ErrBadSignatureKey` and not a second local error.
  13. Refuse a nil `crypto` **after** dereferencing it for `crypto.Suite()`. **Property 5 must fail**
     with a panic rather than a refusal.

- [ ] **Step 6: Commit**

---

### Task 2: One minting body — `NewKeyPackage` re-expressed over Task 1

**Files:**
- Modify: `connect/mls/key_package.go`
- Test: `connect/mls/key_package_test.go` (extend)

**Interfaces:**
- Consumes: Task 1's `NewKeyPackageWithSigner`. Nothing else.
- Produces: no new declaration, and the signature below is restated only so a reader can see that
  nothing about it moves. Its body becomes one signature draw followed by a delegation to Task 1.
```go
// key_package.go — UNCHANGED in signature and in behaviour. 16 call sites
// across 9 files, one of them production, and none of them edited by this plan.
func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,
    caps Capabilities, exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
    encPriv HpkePrivateKey, err error)
```

**Why this is a task and not a line of Task 1.** The two ways over the package wall probe 3 found are
*a second assembly of `KeyPackageTBS`* and *a second spelling of `keyPackageSignatureLabel`*, and
`messagegroup/engine.go:300` already names both as defect classes this tree has paid for. A sibling
constructor with its own preimage assembly and its own `SignWithLabel` call **is** the first of them,
inside the package this time. After this task there is exactly one body that assembles a
`KeyPackageTBS` and exactly one call site of the label.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — for one signer and one entropy stream, the two constructors answer byte-identical
  key packages and byte-identical private halves.** `NewCryptoProviderWithRandom(suite, random)`
  (`mls/crypto.go:113`) makes this observable: run `NewKeyPackage` over a provider seeded with a
  recorded stream, recover the signature key it drew, then run `NewKeyPackageWithSigner` with that key
  over a provider seeded with the same stream **advanced past the signature draw**, and compare the
  two encodings octet for octet along with `initPriv` and `encPriv`.
  *Refusal owed:* none; the failure is an inequality, and the gate must report the first differing
  offset rather than a boolean, because a difference in the leaf and a difference in the signature are
  two different defects.

  **Property 2 — the draw ORDER `NewKeyPackage` had is the draw order it has.** Signature key, then
  init pair, then encryption pair. A wrapper that draws its signature key after delegating, or that
  lets the delegate draw first, changes what every deterministic-provider test in the package
  observes.
  *Refusal owed:* none; the observation is Property 1's equality holding **only** under the advanced
  stream and failing under the unadvanced one, which is what makes the ordering claim falsifiable
  rather than decorative.

  **Property 4 — the wrapper's own copy of the seed it drew does not outlive the call.** Before this
  task the freshly drawn signature seed has exactly **one** holder and `(*KeyPackage).Zeroize`
  (`key_package.go:212-216`) reaches it. After it there are **two**: `crypto.SignatureKeyPair()` hands
  back the seed buffer itself (`crypto_labels.go:492-498`), the wrapper passes it to the delegate, and
  Task 1 Property 2 requires the delegate to CLONE it — so the wrapper is left holding an array only
  it can reach and nothing erases. **This is R7's class arriving inside `mls`**, and it is the one
  place in this plan where the aliased array's owner is a local rather than a field, which is why the
  package's own field-by-field erase gate (`mls/staged_erase_test.go`) cannot see it: that gate holds
  struct fields. Task 2 mutation 5 already forbids erasing BEFORE the delegate runs; this property is
  the other end, and without it the re-expression trades one holder for two.
  *Refusal owed:* none; the observation is that the wrapper's array is zero after the call returns,
  taken on the error paths as well as the success path.

  **Property 3, clause A — after this task exactly one function of `package mls` assembles a
  `KeyPackageTBS` and hands it to a labelled construction, and the gate that says so is the one
  ALREADY IN THE TREE.** `mls/labelled_composition_test.go:1859`,
  `TestEveryCompositionEnteringALabelledConstructionIsBoundedBeforeItGetsThere`, already derives every
  composition entering a labelled construction **off the parse tree** and compares the derived set
  against `labelledCompositionClass` (`:1841-1857`) with `slices.Equal`; its row for this one is
  `key_package.go NewKeyPackage: signedPreimage -> *suiteCryptoProvider.SignWithLabel content` at
  `:1849`. **So this class is landed and derived, and building a second gate over it is the defect
  this project has already paid for once — a second assembly of one class.** Task 1 adds a
  `NewKeyPackageWithSigner` row to that gate's table; **this task takes the `NewKeyPackage` row back
  out**, and clause A is that the landed gate's table moves from two rows to one in this commit. **No
  new gate. The property is over a table that already exists, and the diff to it is the assertion.**
  *Refusal owed:* none of this task's own. The refusal is the landed gate's `t.Errorf`, which prints
  the derived set and the known set side by side on every run.

  **Property 3, clause B — the label is NAMED and not spelled, and this half the landed gate cannot
  see.** `labelled_composition_test.go` keys on the `SignWithLabel` CALL, not on how its label
  argument was written, so a delegate spelling `"KeyPackageTBS"` as a string literal keeps its row and
  the gate stays green. That is the second of the two ways over the package wall probe 3 found, and it
  is the reason this property has a clause the tree does not already derive: **exactly one production
  reference to the identifier `keyPackageSignatureLabel` is an argument to a signing call**, read off
  the parse tree of `key_package.go` rather than grepped.
  *Refusal owed:* none; the failure is a count that moved.

  **The class, its query and its complement (R6), because the earlier reading of this property got all
  three wrong.** The query is `grep -rn "keyPackageSignatureLabel" --include=*.go mls/`, and at
  `a1f8025` it answers **11 lines**. **Three are production:** `key_package.go:75` (the constant's own
  declaration), `:320` (the one `SignWithLabel`) and `:399` (the `VerifyWithLabel` inside `Validate`).
  **Clause B's class is the production signing sites, and that class is one member after
  this task; its complement INSIDE production is the other two, printed:** a constant cannot sign and a verifier is the reader
  rather than the writer, and a class that swallowed them silently could not tell a second signer from
  a second verifier. **The complement OUTSIDE production, printed: 8 test references across 5 files** —
  `caller_arrays_test.go:1349`, `group_test.go:1239`, `key_package_test.go:76`, `:374`, `:376`, `:393`,
  `lifecycle_fixtures_test.go:238` and `welcome_test.go:733` — of which **4 are `SignWithLabel` sites**
  and the rest read the constant to compare it. **An earlier reading of this property printed that
  complement as two references and put one of them at `lifecycle_fixtures_test.go:240`; the call is at
  `:238` and the set is four times larger.** It also called the production class *"every reference in
  the production source"* and then counted it as one, when that predicate returns three — which is why
  clause B now names the predicate *"an argument to a signing call"* and prints what that removed.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Leave the two bodies duplicated — the state Task 1 alone would ship — and change one octet of the
     preimage in the delegate only. **Property 1 must fail**, and **Property 3 clause A must fail** by
     the landed gate's derived set still carrying both `key_package.go` rows against a known set of
     one.
  2. In the wrapper, draw the signature key **after** delegating the HPKE draws. **Property 2 must
     fail** on the stream position.
  3. In the wrapper, pass the drawn public half rather than the private half. **Property 1 must fail**
     — and if it does not, the gate is comparing encodings without comparing the private halves.
  4. Spell the label as a literal `"KeyPackageTBS"` in the delegate instead of naming the constant.
     **Property 3 clause B must fail**, and **clause A must NOT** — the landed composition gate keys on
     the `SignWithLabel` call and keeps its row either way. **If clause A goes red here, clause B has
     been written as a second derivation of the landed class after all**, which is the outcome this
     property was rewritten to avoid; if NEITHER goes red, the task has reused a gate that cannot see
     the half it was reused for.
  5. Have the wrapper zeroize the key it drew before delegating. **Property 1 must fail** on
     `signPriv`.
  6. Have `NewKeyPackage` answer `initPriv` and `encPriv` in the opposite order. **Property 1 must
     fail** on the private halves even though the encodings still match — which is the assertion pair
     that keeps this property from being an encoding comparison wearing a constructor's name.
  7. In the wrapper, drop the drawn signature seed after delegating without erasing it. **Property 4
     must fail**, and no gate in `mls/staged_erase_test.go` may go red with it — that file holds
     struct fields, and this array is a local.

- [ ] **Step 6: Commit**

---

### Task 3: The in-package round trip — a Task 1 key package is joinable

**Files:**
- Modify: `connect/mls/welcome_test.go` (extend)
- Test: same file

**Interfaces:**
- Consumes: Task 1's `NewKeyPackageWithSigner`; `NewGroup`, `ProposeAdd`, `CreateCommit`,
  `MergePendingCommit`, `JoinFromWelcome`, `JoinKeyMaterial`, `Group.Export`, `Group.Epoch` — all
  landed. Nothing from any other plan's task.
- Produces: no declaration. A standing proof, inside `package mls`, that the constructor Task 1 adds
  answers a key package a Welcome join accepts — which is the thing `messagegroup` will depend on and
  cannot observe from outside.

**Why it is here and not folded into Wave 2.** `mls.JoinFromWelcome` is complete and exercised — 144
references across 13 test files — but **every one of those references reaches it through
`lifecycle_fixtures_test.go:218`**, a fixture that writes an unexported field and re-signs with an
unexported label. The join is therefore proved only over a path no package outside `mls` can take,
which is exactly what `engine.go:308` says. This task adds the first join in the tree whose material
came out of an **exported** constructor. If it fails, Wave 2 cannot be written; if Wave 2 fails
instead, this task says which side of the seam is wrong.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — a group founded under signer A admits a key package minted by Task 1 under signer B,
  and B joins the resulting Welcome with `SignPrivate` = B.** End state: two groups at the same epoch,
  the same group id, two members, and `Export` over one label and length answering the same octets on
  both sides. The exporter equality is the clause that matters: group id and epoch agree between a
  joiner that succeeded and a joiner that half-succeeded, and the exported secret does not.
  *Refusal owed:* none on this path.

  **Property 2 — the same material with any other value in `SignPrivate` is refused at the
  caller-material gate, before one octet of the Welcome is judged.** Three inputs, three refusals,
  and the gate must assert **which**: a different valid signer answers `errJoinerSignatureKeyNotTheLeafs`;
  a nil signer answers the ciphersuite-length refusal out of `signaturePublicKeyOf`; a signer that is
  the right length and not a valid seed answers the same. **The ordering is the property, not the
  refusal:** `mls/group.go:3066` runs this before `ParseMLSMessage`, so a corrupt Welcome handed in
  beside a wrong signer must still answer the signer's refusal. That ordering is what tells a caller
  whose keyring has parted company with its stored key package apart from a caller who was handed a
  tampered message.

  **Property 3 — the substitution is total, and it is total because `testKeyPackage`'s BODY moves
  rather than because 112 call sites were each checked.** The old statement of this property asked a
  gate to report 112 and to assert the equivalence "at the ones this task exercises", which — as the
  review of this document found — is satisfiable by any implementation and falsifiable by none: no
  mutation of this task could make it red, and this plan's own step 5 rule is *"a surviving mutation
  is a defect in the test"*. Restated so that a mutation can reach it: **after this task
  `testKeyPackage` (`lifecycle_fixtures_test.go:218`) contains no write to `kp.signPriv` and no second
  spelling of `keyPackageSignatureLabel`**, read off that function's own parse tree — and the 112 call
  sites move with it by construction rather than by inspection.
  *Refusal owed:* none; the observation is a source read of one function plus the package staying
  green, and 185 of the package's tests reach that function.

  **The class, its query and its complement (R6).** The class is derived off the package rather than
  listed: it is **every call site of `testKeyPackage` in `package mls`'s tests** — `grep -rn "testKeyPackage(" --include=*.go mls/ | grep -v "func
  testKeyPackage"` — and **that class is 112 members at this task, measured**, which the gate reports
  so that a 113th added next month is a number that changed. **The complement, printed with its size,
  which the earlier reading of this property left unstated and which R5 forbids: three** — the
  `SignWithLabel` sites in `mls`'s tests that are NOT `testKeyPackage`'s own and therefore do not move
  when its body does: `caller_arrays_test.go:1349` (a standalone hand assembly),
  `group_test.go:1239` (inside `testKeyPackagePublishing` at `:1226`, which delegates to
  `testKeyPackage` for the mint and then re-signs a planted encryption key by hand) and
  `key_package_test.go:76` (which re-signs using the key package's own `signPriv`). **The plan prints
  the three and rules none of them**: whether a site is a negative fixture that must keep its mismatch
  is a reading of the case around it, and an implementer who converts one without reading it deletes a
  negative case that holds Property 2 — which is mutation 7.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Join with a `JoinKeyMaterial` whose `SignPrivate` is a second valid signer. **Property 2 must
     fail** if anything other than `errJoinerSignatureKeyNotTheLeafs` comes back.
  2. Join with `SignPrivate` nil. **Property 2 must fail** unless the refusal is the length one.
  3. Corrupt the Welcome's first octet **and** pass a wrong signer. **Property 2 must fail** if the
     refusal names the message rather than the caller — this is the ordering clause, and a gate that
     only ever passes a well-formed Welcome cannot see it.
  4. Mint B's key package with `NewKeyPackage` (no signer) and join with the key the engine holds.
     **Property 1 must fail** at the caller-material gate. **This is the mutant that reproduces the
     tree as it stands at `a1f8025`**, and if it survives, this task is not testing what it claims.
  5. Skip `MergePendingCommit` on the founder before comparing exporters. **Property 1 must fail** on
     the `Export` equality while group id and epoch still look plausible on one side — which is the
     case that shows why the exporter clause is in the property.
  6. Compare only group id, epoch and member count. **Property 1 must fail** to detect mutant 5,
     which is the control on the assertion set rather than on the implementation.
  7. Convert one of the three complement sites Property 3 prints to the new constructor without
     reading the case around it. **Property 2 must fail**, because a case that was minting a
     mismatched key package now mints a matched one and its refusal disappears.
  8. Re-express `testKeyPackage` over `NewKeyPackageWithSigner` and leave the `kp.signPriv = m.SigPriv`
     write in place beneath it. **Property 3 must fail** on the function's own parse tree, and
     **nothing else in this task may go red** — the fixture still answers a correct key package, which
     is exactly why the old statement of this property could not be refuted by any mutation.
  9. Re-express `testKeyPackage` and leave its own `crypto.SignWithLabel(m.SigPriv,
     keyPackageSignatureLabel, ...)` in place after the delegate. **Property 3 must fail**, and **Task
     2 Property 3 clause B must fail with it** by reporting a second signing reference — which is the
     cross-check that says this property and that one are reading the same package.

- [ ] **Step 6: Commit**

---
## Wave 2 — `connect/messagegroup`: the engine that mints what it can join (Tasks 4–6)

**This wave needs Wave 1 whole.** Every task below calls a constructor Task 1 declares. It adds no
production file, no import and no interface method: `GroupEngine`'s four signatures are pinned
string-for-string to Spec A §6 by `engine_test.go:39` and none of them moves.

**And the two engine methods must agree about where the signature key comes from, which is why Task 4
comes before Task 5 rather than beside it.** A join body landed before the mint is fixed refuses at
`mls/group.go:3070` on every key package the old code minted — a task that looks green in isolation
and fails only end to end.

### Task 4: The engine mints under its own signer, and the fixture stops hiding the split

**Files:**
- Modify: `connect/messagegroup/engine.go` (`NewKeyPackage`'s body at `:236-262` and its doc paragraph
  at `:225-235`), `connect/messagegroup/sessionfixture_test.go` (`buildTestEngine` at `:143`)
- Test: `connect/messagegroup/engine_test.go` (extend)

**Interfaces:**
- Consumes: Task 1's `NewKeyPackageWithSigner`; the engine's own `self.signer`, `self.cred`,
  `self.crypto`, `self.leafKeys` (`messagegroup/engine.go:157`); `mls.ParseLeafKeysExtension`,
  `mls.Extension`, `syntax.Marshal`, `KeyPackage.Ref`, `StateStore.PutKeyPackage` — all landed.
  **And the observation route Property 1 needs, which an earlier reading of this task did not
  consume and could not therefore observe (R4's third clause):** `GroupHandle.RatchetTreeSnapshot`
  (`messagegroup/engine.go:80`), `mls.UnmarshalRatchetTree` (`mls/tree.go:1003`) and
  `(*RatchetTree).Leaf` (`mls/tree.go:312`), which together are the ONLY route from
  `package messagegroup` to a founding leaf's `SignatureKey`. **`MemberAt` is not that route** —
  `messagegroup/engine.go:396` answers `(leafIndex, identityPub, leafKeys, err)` and drops
  `mls.Member.SignatureKey`, which `mls/group.go:781` does populate. All three are landed and
  exported; nothing here is new work.
- Produces: no new declaration. Section 6's NewKeyPackage method keeps its signature and its
  return value; what changes is which key the leaf it publishes names, and that the minted value
  is erased before the method returns.

**What the store receives does not change, and the complement is printed.** `PutKeyPackage(ref,
encoded, initPrivate, encryptPrivate)` stays four arguments. The value that used to be dropped on the
floor is not persisted here either — it is `device_sig`, Spec A §8.1 line 4625 puts it in the keyfile,
and this task adds no row and no column to anything. **The set of things this task persists that it
did not persist before is empty, deliberately, and that is the sentence a reader should check the diff
against.**

**Why the shared fixture moves, and it is the smaller half of the task that matters most.**
`buildTestEngine` (`sessionfixture_test.go:143-148`) draws `signer, identityPub` from **one**
`crypto.SignatureKeyPair()` call and passes `mls.BasicCredential(identityPub)` as the credential —
so the device's credential identity **is** its signer's public half. Probe 1 shows the consequence:
`credential identity` and `device signer public half` printed the same 32 octets, and under that
fixture the assertion *"the leaf names the device signer"* and the assertion *"the leaf names the
credential"* are the same program. **A gate written over that fixture cannot fail for the reason this
task exists.** The fixture must draw the credential identity independently. Measured blast radius:
`grep -rn "identityPub" --include=*_test.go messagegroup/` is 14 lines, and the only one that compares
the two is `engine_test.go:722`, which compares `MemberAt(0)`'s identity against `fixture.identityPub`
— read off `Credential.Identity` at `mls/group.go:779`, so it stays true. **Run the whole
`./messagegroup/` package at step 5, not a `-run` subset; a shared fixture is a shared blast radius.**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the leaf signature key of every key package this engine publishes is a key this
  engine can sign with (clause A), and it is the same key its founding leaves name (clause B).**

  **Clause A rests on nothing anybody has to rule.** It is `mls.JoinFromWelcome`'s own caller-material
  gate read backwards: `mls/group.go:3066-3071` compares `signaturePublicKeyOf(keys.SignPrivate)`
  against `keys.KeyPackage.LeafNode.SignatureKey` before one octet of the Welcome is judged, so a key
  package whose leaf names a key the device cannot sign with is a key package no Welcome addressed to
  it can ever be opened with. Clause A is the whole of what Tasks 5 and 6 need.

  **Clause B rests on J1-1, which this document files as unruled, and is stated here as the position's
  cost rather than as a defended sentence (R4).** *"The same key its founding leaves name"* is
  verbatim what J1-1 says MASTER §5.2 line 516 does not write in as many words. The plan takes the
  wide reading with its evidence printed in *"The ruling this plan takes a position on"*; **what falls
  if the owner rules the other way is larger than the reversal price stated there and is written out
  here so the owner prices it once:** clause B itself, Task 4 Property 4 (which exists only because
  `ValSem101` now sees a duplicate signature key), Task 4's shared-fixture change, and Task 5's
  `SignPrivate: self.signer` — and under the narrow reading `mls.NewKeyPackageWithSigner` is left with
  no production caller at all. Clause A survives every reading, which is why it is stated first.

  **The observation** available inside `package messagegroup` is the public half the fixture holds
  beside the signer it injected, compared against the leaf `SignatureKey` each door publishes.
  **The fixture must be given that public half: `testEngine` (`sessionfixture_test.go:122`) retains
  `identityPub` and neither the signer nor its public half, so a `signerPub` field is required by this
  property and named nowhere else in this plan.**
  *Refusal owed:* none on the success path; a mint that cannot bind refuses out of Task 1's
  constructor and the engine wraps it.

  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the scope is
  **every door this engine has to an MLS leaf**, not "the key package". The query is the
  `NewLeafNode` and `LeafNode.Sign` sites of non-test `mls` — `grep -rn "NewLeafNode(\|\.Sign(crypto"
  --include=*.go mls/ | grep -v _test` — which returns **8 sites**, read back to the section 6 method
  that reaches each, which is **5 doors**. **That class is FOUR members at this task** — the four
  doors whose leaf comes out of this device — **and its complement is one**, and an earlier reading of
  this property named two. **The 8 → 5 step is printed because an earlier reading printed 4 and 1 and
  never printed the 8 the query returns** (R6 clause a).

  **And each door now carries its OBSERVATION ROUTE, which is R4's third clause and the reason this
  table is not the same table it was.** The repair before this one widened the class from two doors to
  four and required the gate to *"print all four with the key each leaf named"* — and then did not ask
  whether that key can be read. **Measured: exactly ONE of the four can be read from `package
  messagegroup` at Task 4.**

  | Door | reaches | at | the route to its leaf's `SignatureKey`, from `package messagegroup` | held at |
  |---|---|---|---|---|
  | `GroupEngine.NewKeyPackage` | `mls.NewKeyPackage` → `NewLeafNode` | `key_package.go:304` | **OBSERVABLE at Task 4.** The method answers the encoding; `syntax.Unmarshal` into an `mls.KeyPackage` and read `kp.LeafNode.SignatureKey`, an exported field of an exported type | **Task 4**, clause A |
  | `GroupEngine.CreateGroup` | `mls.NewGroup` → `NewLeafNode` | `group.go:525` | **OBSERVABLE at Task 4, but NOT by the route this property used to name.** `MemberAt` answers `identityPub` off `Credential.Identity` (`mls/group.go:779`) and DROPS `Member.SignatureKey` (`:781`) at the seam — and after this task's own fixture change the credential identity is drawn independently of the signer, so `MemberAt` compares two values that are unequal by construction. The route is `RatchetTreeSnapshot()` → `mls.UnmarshalRatchetTree` → `rt.Leaf(0).SignatureKey`, all three now in Consumes | **Task 4**, clause B |
  | `GroupHandle.ProposeUpdate` | `(*Group).ProposeUpdate` → `leaf.Sign` | `group.go:1683` | **NOT OBSERVABLE, at this task or any task in this plan.** The method answers a serialized `MLSMessage` carrying an RFC 9420 section 6.3 **PrivateMessage** — `mls/extension_test.go:2770`'s own exemption entry says so in the tree's words, and it measures 1,575 octets with `PrivateMessage=true`. The leaf is inside the AEAD. Nor can the proposer commit its own update to get the leaf into a tree: `(*Group).CreateCommit` refuses with `ErrSelfUpdateInCommit` (`mls/errors_proposal_validation.go:95`), *"mls: the committer covered its own update proposal"* | **PRINTED AS UNOBSERVED**, below |
  | `GroupHandle.Commit` | `(*Group).CreateCommit` → `CreateUpdatePathSecrets` → `leaf.Sign` | `treekem.go:463` | **NOT OBSERVABLE AT TASK 4; observable at Task 6.** Same route as `CreateGroup`, but the leaf only carries a fresh signature after a commit that MERGES, which needs a SECOND member's key package added first. Task 4 has one engine | **Task 6 Property 1** |

  **So this property holds doors 1 and 2, prints their routes, and hands door 4 to Task 6 — which is
  where the second engine is.** A property stated over a value the task cannot read is green in every
  world, including the one where the value is wrong; that is the same vacuous pass R3 exists to catch,
  one level in.

  **Door 3, printed as UNOBSERVED rather than asserted, in `mls/UNOBSERVED.md`'s own shape.**
  `GroupHandle.ProposeUpdate`'s leaf signature key is not readable through this seam by any route this
  plan has or could add without changing Spec A §6: the only octets the method answers are ciphertext,
  and the only tree the leaf reaches is one a DIFFERENT member commits. **What is known about it
  without observing it, and it is not nothing:** the leaf is signed with the GROUP's `signer`, which
  `NewGroup` (`mls/group.go:525`) and `JoinFromWelcome` (`:3413`) each CLONE off the caller — so this
  door keeps working after the engine's own key is destroyed, which is exactly why the erase Task 5
  Property 6 holds is invisible from a handle and had to be caught on the engine. **That is an
  argument and not an observation, and it is labelled as one.** *Owed:* an entry in
  `connect/mls/UNOBSERVED.md`, or a Spec A §6 amendment that lets a caller read its own leaf.

  **The complement, printed:** the one door of the five whose leaf does not come out of this device —
  `GroupEngine.JoinFromWelcome`, whose leaf comes off a peer's tree — named and excluded with that
  reason, and Task 6 Property 1 is where it is covered.

  **Property 2 — the value the constructor answered is erased before `NewKeyPackage` returns, and
  erasing it does not disturb `self.signer`. This is the MINT half of one aliasing; Task 5 Property 6
  is the JOIN half, and the pair is R7's class on this path.** Under Task 1 the minted key package holds a **copy** of
  `device_sig` on `signPriv`; a method that returns the encoding and drops the value leaves the
  device's long-term signing key in the heap for the collector to move around, and a method that
  erases a value aliasing `self.signer` destroys the engine. **The two halves are one property because
  either alone is a defect and the pair is the only safe state.**
  *Refusal owed:* none; the observation is that a second `NewKeyPackage` on the same engine still
  answers a key package whose leaf names the same key, which is false the moment `self.signer` has
  been zeroed.

  **Property 3 — what reaches the store is unchanged in arity and in content: the ref, the encoding,
  the init private and the encryption private, and nothing else.** The gate reads the four arguments
  the store received and asserts the encoding is the octets the method returned and the ref is
  `KeyPackage.Ref` over them.
  *Refusal owed:* the existing `ErrEngineLeafKeys` path is unchanged; a device with no leaf keys is
  still refused before anything is drawn.

  **Property 4 — a key package this engine publishes is one `connect/mls` still admits into ANOTHER
  device's group, and a self-add is refused for a reason this task creates.** Two assertions over two
  different groups; they are not one assertion in two moods, and an earlier reading of this property
  stated them as one and was therefore unsatisfiable — it required
  `TestNewKeyPackageAnswersOneConnectMlsWillAdmit` (`engine_test.go:959`) to *keep* asserting that a
  self-add succeeds and, two sentences later, required a self-add to be refused.

  *The admit.* That test asserts today that `handle.ProposeAdd(encoded)` succeeds over a group **the
  same engine founded**. **Measured, that assertion goes RED under this task, and it is the only
  existing test in `./messagegroup/` that does — 185 of 186 pass.** It must be **re-pointed at a group
  founded by a different engine**, where it keeps meaning what it was written to mean: the encoding is
  one `ProposeAdd` takes rather than merely some octets.

  *The refusal.* The self-add it used to perform becomes its own case. **Measured with the mint
  pointed at `self.signer`**, `ProposeAdd` over the engine's own key package into its own group
  answers `mls: an added key package publishes a signature key the group or another add already
  publishes: adds[0] publishes d1b2b710…`, and **it fires at `ProposeAdd`, not at `Commit`**, because
  `(*Group).propose` (`mls/group.go:1853`) runs `ValidateProposalList` including
  `ValSem101UniqueSignatureKey` (`mls/validate_proposals.go:362`) over its own pre-commit tree. That
  is correct behaviour which would otherwise read as a regression, and it exists only under J1-1's
  wide reading (see clause B above).
  *Refusal owed:* the self-add must be refused **at `ProposeAdd`**, and the gate must assert the
  refusal names the duplicate signature key rather than passing on any error — a gate that accepted
  "some error" here would also pass on a device with no leaf keys.

  **Property 5 — the two HPKE private halves the constructor answered are erased before
  `NewKeyPackage` returns, and erasing them does not disturb what the store holds. This is R7's arm
  (ii) on this path, and it is the row the first R7 sweep printed a complement of one over.**
  `NewKeyPackageWithSigner` answers `(kp, initPriv, encPriv, err)`. Property 2 requires exactly ONE of
  the three secrets to be erased — `defer keyPackage.Zeroize()` reaches `key_package.go:213`, which is
  `zeroizeSecret(self.signPriv)` and nothing else. The other two are handed to `PutKeyPackage`, which
  **copies** in the only store that exists (`sessionfixture_test.go:101-108` appends into a fresh
  array), and the engine's own locals are then dropped un-erased. **`JoinKeyMaterial.Zeroize`'s header
  — the authority this plan quotes twice as the reason `SignPrivate` must be erased — names these two
  FIRST:** *"the init key opens every Welcome addressed to this key package, the encryption key is
  this member's leaf key for as long as it holds that leaf, and the signing key is its identity."*
  Task 5 Property 3 holds both of these at JOIN time, one task later; nothing holds them at MINT time.
  **The defect is pre-existing at `a1f8025`** — `mls.NewKeyPackage`'s existing caller drops them the
  same way — **and this is the task whose body already touches the site, so this is where it is
  held.**
  *Refusal owed:* none; the failure is silent by construction, which is why the observation is made on
  the STORE and on the arrays rather than on the method's answer.
  *The observation ROUTE (R4's third clause):* the store's own `keyPackages` map, read back after
  `NewKeyPackage` returns — the fixture's `memoryStateStore` is in this package and the field is
  reachable from a test in it — compared against the arrays the engine held. Every name on the route
  is in this task's Consumes block. **What must NOT be read is the value the method answered**, for
  Property 2's stated reason.
  *And the ordering that makes it a property rather than a comment:* the erase must happen AFTER
  `PutKeyPackage` returns, because the store copies and an erase before the call stores zeros. A gate
  that only checked "the local is zeroed at return" passes a body that zeroed too early and persisted
  32 zero octets, which is a key package no Welcome can ever be opened with — and nothing in the tree
  refuses it.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Call `mls.NewKeyPackage` instead of the signer-taking constructor. **Property 1 must fail.**
     **This is the tree as it stands at `a1f8025`**, and it is the mutation the whole 7,665-test suite
     is currently green against.
  2. Mint with a signer drawn inside `NewKeyPackage`'s body rather than `self.signer`. **Property 1
     must fail** on both clauses, and the failure must name which of the two keys it compared.
  3. Leave `buildTestEngine` drawing the credential identity from the signer's public half.
     **Property 1 must not be able to fail** — the gate must report that its two compared values are
     equal by construction and refuse to run. A gate that passes here is measuring nothing, and this
     mutant is the control on the fixture rather than on the engine.
  4. Assign `self.signer` into the constructor without Task 1's clone, then erase the minted value.
     **Property 2 must fail** on the second `NewKeyPackage` call, and Task 1 Property 2 must fail with
     it.
  5. Return the encoding without erasing the minted value. **Property 2 must fail** on the heap
     residue clause.
  6. Persist a fifth value beside the four. **Property 3 must fail**, and it must fail by arity rather
     than by content — this is the mutant that reproduces Option A arriving by the back door.
  7. Store the ref computed over the leaf rather than over the whole key package. **Property 3 must
     fail**, and Task 5 Property 1 must fail with it because the Welcome names the whole-package ref.
  8. Add this engine's own key package to its own group and assert only that some error came back.
     **Property 4's refusal half must fail**, because the assertion no longer distinguishes
     `ValSem101`'s duplicate from `ErrEngineLeafKeys` — and re-point the admit half at the same
     engine's own group: **Property 4's admit half must fail** too, which is the pair that keeps the
     two assertions from collapsing back into one.
  9. Keep `engine.go:225-235`'s doc paragraph, which states the refusal's cause, unchanged.
     **Property 1 must fail** — not as a compile error but as a documentation assertion the gate makes
     over the package's own source, in the shape `messagegroup`'s existing AST gates already use:
     the paragraph names `StateStore.TakeKeyPackage` as the reason a join is impossible, and after
     this task that sentence is false in the file that publishes it.
  10. Drop `initPrivate` and `encryptPrivate` without erasing them — **the tree as it stands at
     `a1f8025`**. **Property 5 must fail**, on both arrays and naming which of the two it read.
  11. Erase the two BEFORE `PutKeyPackage` rather than after. **Property 5 must fail** on the store's
     side of the observation: the store now holds 32 zero octets where the init private belongs, and
     the whole suite is otherwise green over it, because nothing joins in this task.
  12. Erase `initPrivate` and leave `encryptPrivate`. **Property 5 must fail**, and it must name the
     ONE array it found rather than reporting that "an erase is missing" — a gate that collapses the
     two into one reading passes mutation 11 in one direction.
  13. Read Property 1's founding-leaf comparison through `MemberAt`'s `identityPub` instead of
     through `RatchetTreeSnapshot` → `mls.UnmarshalRatchetTree` → `rt.Leaf(0).SignatureKey`.
     **Property 1 clause B must fail**, and it must fail by reporting that the two values it compared
     are the CREDENTIAL identity and the signer's public half — two independent draws after this
     task's fixture change — rather than by reporting a key mismatch. **This is the control on R4's
     third clause**: it is the mutation that distinguishes a property that observes the leaf from one
     that observes a value the seam happens to answer.

- [ ] **Step 6: Commit**

---

### Task 5: The Welcome's refs, the take, and the put-back

**Files:**
- Modify: `connect/messagegroup/engine.go` (`JoinFromWelcome`'s body at `:308-316`),
  `connect/messagegroup/errors.go`
- Test: `connect/messagegroup/engine_test.go` (extend)

**Interfaces:**
- Consumes: Task 4's mint, because the material this body assembles is only joinable if the leaf names
  `self.signer`; `mls.ParseMLSMessage`, `mls.MLSMessage.Welcome`, `mls.Welcome.Secrets`,
  `mls.EncryptedGroupSecrets.NewMember`, `syntax.Unmarshal`, `mls.KeyPackage`, `mls.JoinKeyMaterial`,
  `mls.GroupConfig`, `mls.JoinFromWelcome`, `StateStore.TakeKeyPackage`, `StateStore.PutKeyPackage` —
  all landed and all exported. **And, for the properties' own fixtures rather than for the body:**
  `GroupEngine.CreateGroup`, `GroupEngine.NewKeyPackage`, `GroupHandle.ProposeAdd` and
  `GroupHandle.Commit` (`messagegroup/engine.go:66`), without which Property 1's two-entry Welcome
  cannot be produced at all, and a **call-recording store double**, which `memoryStateStore`
  (`sessionfixture_test.go:101`) is not — it holds a map and records nothing, so Property 2's
  before-and-after and Property 4's store-failure injection each need one this task builds. Property 5
  additionally needs an **AST read of `../mls/group.go`**, which no gate in `messagegroup` performs
  today (`engine_test.go:254` scans this package's own files only); the alternative that needs no new
  scan root is to hold Property 5 over the CONFIG this method builds rather than over
  `JoinFromWelcome`'s read-set, and that choice is the implementer's — both are stated because a task
  whose Files block does not provide for its own property is a task that discovers the gap at step 2.
- Produces:
```go
// errors.go — the refusals that replace ErrEngineJoinUnavailable. Both name a
// RUNTIME condition; neither names a gap in another package's exported surface.
var ErrEngineWelcomeShape error           // not an MLSMessage carrying a Welcome
var ErrEngineNoKeyPackageForWelcome error // no key package this store holds is addressed here
```

**Where the ref comes from, because §6's signature does not carry one.** `JoinFromWelcome(welcome,
ratchetTree)` names no key package, `NewKeyPackage` returns no ref, and `TakeKeyPackage(ref)` demands
one. The Welcome itself carries them: `Welcome.Secrets[i].NewMember` **is** the `KeyPackageRef` each
entry is addressed to, and every type on that path is exported. **So no new `mls` surface is needed
and none is added** — no `WelcomeKeyPackageRefs` helper, no `ListKeyPackages` on the store, no third
parameter on §6's method. *Rejected:* the engine remembering the refs it minted, because that state
does not survive a restart and would be a second, divergent copy of what the store already holds.

**And the ownership rule this task works under, because `JoinKeyMaterial` erases what it is handed
and one of the four things it is handed is the device's identity.** Every field of the
`mls.JoinKeyMaterial` this body assembles is a **copy this method made** — the two HPKE privates
because `TakeKeyPackage` answered the store's own arrays (Property 3), and `SignPrivate` because
`self.signer` is `device_sig` and `(*JoinKeyMaterial).Zeroize` erases `SignPrivate` by name at
`mls/group.go:2947`. **A join assembled directly over `self.signer` destroys the device's long-term
signing key on the first successful join, and nothing anywhere refuses afterwards.** Property 6 states
it, mutation 13 is the mutant, and **J1-16** files the header sentence the two readings of this rest
on. The rule generalises past this method and is worth reading as one line: *`JoinKeyMaterial` owns
every array it carries, so a caller assembles it only over arrays it is willing to have destroyed.*

**And the position this task takes on the destructive take, with the window it does not close.**
`TakeKeyPackage` reads and deletes in one call and there is no non-destructive read. A Welcome
authenticates nobody — `mls/group.go:3038-3050` spends fifteen lines on it — so anybody holding this
device's published key package can seal a well-formed Welcome to it. *Position taken:* the engine
takes the one ref the Welcome names that this store holds, and **puts it back on every failure path
after the take**, so a bogus Welcome costs a store round trip and not the device's only copy.
*Rejected:* taking only after a successful join, which the interface cannot express, because
`JoinFromWelcome` needs the material to decide. **The window this leaves and does not close: a crash
between the take and the put-back loses the key package permanently, and the device must publish a
fresh one and be re-added.** That is **J1-3**, it is the store's to close and not this method's, and
the put-back is what makes the loss require a crash rather than a message.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the engine finds its own key package by reading the Welcome, and takes exactly the
  one ref the Welcome names that this store holds.** Not the first ref, not every ref: the refs a
  Welcome names are addressed to different joiners, and a device that took on a ref it does not hold
  is asking a question, while a device that took on every ref is destroying other entries' addressing
  for no reason.
  *Refusal owed:* `ErrEngineWelcomeShape` when the octets do not parse as an `MLSMessage` carrying a
  `Welcome`, wrapped with the octet count. `ErrEngineNoKeyPackageForWelcome` when no ref the Welcome
  names is held, wrapped with **how many refs the Welcome named** and **how many the store refused**.
  *Scope to derive, separately from the class (R3):* the class is **every entry of
  `Welcome.Secrets`**, read off the parsed message rather than assumed to be one. **That class is two
  members in the gate this task must build** — a Welcome addressed to this device and one other joiner
  — because a one-entry Welcome cannot distinguish "found mine" from "took the first".

  **Property 2 — a join that FAILS restores the key package it took, and the store is byte-identical
  to what it was before the attempt.** Every failure path after the take: a Welcome that parses and
  whose group secrets do not open, a ratchet tree that does not verify, a confirmation tag that does
  not match, a `cfg` the caller built wrong. The observation is the store's own contents before and
  after, and then a **second** join attempt with a good Welcome over the same ref succeeding.
  *Refusal owed:* the underlying `mls` refusal, wrapped and not swallowed — the caller must be able to
  `errors.Is` its way to `errJoinerSignatureKeyNotTheLeafs` or to whatever `mls` answered, because
  "this join failed" and "your keyring is wrong" are different problems for the operator.
  **This property rests on nothing undecided:** it is a statement about this method's own behaviour,
  and J1-3's ruling changes how it is implemented rather than whether it holds.

  **Property 3 — the arrays the store handed back are not the arrays `JoinKeyMaterial.Zeroize`
  erases.** `TakeKeyPackage` answers the store's own arrays; `(*JoinKeyMaterial).Zeroize`
  (`mls/group.go:2947`) erases `InitPrivate`, `EncryptPrivate`, `SignPrivate` **and**
  `KeyPackage.signPriv`. A join that assembled the material directly over the store's arrays and then
  erased it puts zeroed octets back on the put-back path. The interface header at `mls/group.go:287-302`
  rules this for `Put` and for `Get` and **says nothing about `Take`** — that silence is **J1-5**, and
  this property is what stops it costing anything here.
  *Refusal owed:* none; the observation is the restored entry's octets equalling what was stored.

  **Property 4 — the refusal says what the interface cannot: a store failure and "not addressed to
  this device" are indistinguishable, and the message carries both readings.**
  `StateStore.TakeKeyPackage` returns a bare `error` with no declared not-found value, so a loop that
  treats every error as "not mine" reports a broken disk as an unaddressed Welcome.
  `ErrEngineNoKeyPackageForWelcome` must therefore carry the ref count, the refusal count and the
  **last store error verbatim**, so an operator reading the message can tell the two apart even though
  a caller matching on the type cannot. **This is deferred, not defended:** the taxonomy that would
  let the type tell them apart is **J1-4** and is owed by whoever owns Spec A §3.5.

  **Property 5 — the `mls.GroupConfig` this method builds carries exactly the fields
  `JoinFromWelcome` reads, and leaves `GroupId` unset.** The class is **every field of `GroupConfig`
  that `JoinFromWelcome`'s body reads**, derived from `mls/group.go:3033-3440` rather than from this
  plan or from the type's doc comment; **that class is four members** — `Crypto`, `Store`, `Profile`,
  `GroupId` — and the gate prints them. `GroupId` is left nil because §6's signature gives the engine
  no group id to intend, so the intent match `mls` offers is unreachable through this seam (**J1-6**),
  and a config that guessed one would refuse every legitimate Welcome.
  **The complement, printed:** the four `GroupConfig` fields `CreateGroup` sets and this method must
  not — `Suite`, `Extensions`, `RequiredCaps`, `LeafKeys` — which are unread on the join path because
  required capabilities come off the Welcome's own `GroupInfo`. A gate that did not print them would
  be a gate nobody can tell from one that checked nothing.

  **Property 6 — `JoinKeyMaterial` owns every array it carries, so this method assembles it only over
  arrays IT made, and `self.signer` is not one of them.** This is the property the earlier reading of
  this task did not have, and its absence is the one defect in this document that destroys a key.

  **The ownership rule, stated once for all four fields.** `(*JoinKeyMaterial).Zeroize`
  (`mls/group.go:2947`) erases `InitPrivate`, `EncryptPrivate`, `SignPrivate` **and**
  `KeyPackage.signPriv`, and this method must call it — the two HPKE privates open every Welcome
  addressed to this key package and the signing key is the device's identity, which is that type's own
  header at `:2925-2932`. **So the material is assembled over four copies this method made, and the
  erase destroys copies.** Property 3 already says exactly this about the two arrays `TakeKeyPackage`
  handed back; Property 6 says the same sentence about the third, and the third is the one that costs
  the device its identity rather than a store entry.

  **Position taken: a defensive copy of `self.signer` at the assembly site.** It adds no new
  discipline, only a fourth instance of one already spelled three times on this exact path — Task 1
  Property 2 requires the constructor to CLONE the caller's seed into `kp.signPriv`,
  `mls/group.go:3413` clones `keys.SignPrivate` into the joined group's `signer`, and `NewGroup` does
  the same for the founder. *Rejected: narrowing `(*JoinKeyMaterial).Zeroize` so it leaves
  `SignPrivate` alone* — that removes a real erase from the type that declares this material for
  **every** caller, and measured, `grep -rn "SignPrivate:" --include=*.go .` is 13 sites and **all
  13** pass a per-member `testMember.SigPriv` minted before the key package existed and wiped by
  nothing else; it also contradicts the type's own header,
  which is a `connect/mls` amendment rather than this method's call. *Rejected: not calling `Zeroize`
  at all* — the two arrays Property 3 exists for then stay in the heap, which trades this defect for
  **J1-5**'s and buys nothing.

  **What the erase costs when it is not held, measured rather than reasoned.** `zeroizeSecret`
  (`mls/secret_zeroize.go:42`) writes zeros through the slice, so a `SignPrivate` aliasing
  `self.signer` leaves the engine holding a 32-octet all-zero seed. **Nothing refuses it.**
  `signaturePublicKeyOf` accepts an all-zero seed, `NewKeyPackage` and `CreateGroup` both go on
  succeeding, and every leaf the device publishes afterwards names
  `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29` — the ed25519 public key of the
  all-zero seed, derivable by anyone — while `Credential.Identity` still names the real device.
  **The joined handle keeps working**, because `mls/group.go:3413` clones `SignPrivate` into the group
  before the erase, so `Commit`, `ProposeUpdate` and `Protect` on the handle this call answered are
  all green. **That is why nothing in Tasks 1–7 as written caught it, and it is why this property is
  about the ENGINE and not about the handle.**

  **The observation, and the observations that are NOT admissible.** The property is taken on **both
  exits** — after a join that succeeded and after a join that failed after the take — and the
  admissible observation is a door of Task 4 Property 1's class driven a **second** time: a second
  `NewKeyPackage()` whose leaf names the same signature key as the pre-join one, and a `CreateGroup`
  on the same engine whose leaf 0 names it. **Not admissible, and each is a green reading over a
  destroyed device:** `MemberAt(0)`'s `identityPub`, which reads `Credential.Identity`
  (`mls/group.go:779`) and the erase does not touch; anything read off the handle this call answered,
  for the clone above; and Task 6 Property 1's whole chain, which never drives engine B again after
  its join and passes green with engine B destroyed.
  *Refusal owed:* **none, and that is the finding** — the failure is silent by construction, which is
  why the gate reads the engine rather than the return value. Task 4 Property 2 holds the mint half of
  this same aliasing and names Task 5 Property 6 as the join half; neither alone covers the pair.
  *Scope to derive, separately from the property (R3):* the scope is R7's class over this whole plan —
  every value a task assembles over an array something longer-lived owns — derived in *"The sweep for
  R7's class"* above rather than listed here. **That class is four members** and its complement is
  one; two of the four were held before this repair, Task 2 Property 4 is the third, and this property
  is the fourth — the only one of the four whose array is the device's long-term identity rather than
  a store entry or a stack local.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Take on the **first** ref the Welcome names rather than on the one this store holds. **Property 1
     must fail** on a Welcome whose first entry is another joiner's — and a gate built over a
     one-entry Welcome passes this mutant, which is why Property 1's class is two.
  2. Take on **every** ref the Welcome names. **Property 1 must fail** by the store having lost an
     entry it should still hold.
  3. Swallow the parse error and fall through to the ref loop. **Property 1 must fail** on
     `ErrEngineWelcomeShape` never being answerable.
  4. Skip the put-back on the failure path. **Property 2 must fail** on the second attempt with a good
     Welcome. **This is the mutation the task exists for**, and nothing in Tasks 1–4 or 6 reaches it.
  5. Put back only when `mls.JoinFromWelcome` returns a specific error, rather than on every failure
     after the take. **Property 2 must fail** on any other refusal — an allow-list of failure reasons
     is the shape that fails open the day `mls` adds a check.
  6. Assemble `JoinKeyMaterial` directly over the arrays `TakeKeyPackage` answered and erase it before
     the put-back. **Property 3 must fail** on the restored entry being zeroed. If Property 2's gate
     compares only presence and not octets, this mutant survives — which is the control on Property 2.
  7. Answer `ErrEngineNoKeyPackageForWelcome` with no counts and no wrapped store error. **Property 4
     must fail.**
  8. Make the store return an I/O failure for the ref this device holds. **Property 4 must fail** if
     the message is indistinguishable from the unaddressed case.
  9. Set `cfg.GroupId` to the group id recovered from the parsed Welcome. **Property 5 must fail** —
     it turns an intent match into a tautology, which is worse than leaving it unset because it reads
     like a check.
  10. Set `cfg.RequiredCaps` from `engineRequiredCapabilities()`. **Property 5 must fail** on the
     printed complement, and the gate must say the field is unread rather than "the join still
     worked".
  11. Return the joined `*mls.Group` without wrapping it in `connectMlsHandle`. The build must fail,
     and if it does not, `TestOnlyOneProductionFileOfThisPackageNamesMlsGroup` must fail — the seam is
     a seam because the group does not leave this file.
  12. Keep `ErrEngineJoinUnavailable` declared and unused. **Property 1 must fail** on the package's
     own honesty gate: a sentinel naming an impossibility that is no longer impossible is the same
     defect class as the doc paragraph in Task 4 mutation 9.
  13. Assemble `SignPrivate: self.signer` directly — no copy — with `defer keys.Zeroize()`.
     **Property 6 must fail on BOTH exits**, and it must fail by naming the signature key the engine's
     NEXT leaf published rather than by reporting that the join failed. **This is the mutation the
     property exists for**, and it is the shape the plan and `mls`'s own header jointly read as
     correct before this repair.
  14. Assemble over a copy and erase only on the success return. **Property 6 must fail on the failure
     exit.**
  15. Assemble over a copy and erase only on the failure/put-back path. **Property 6 must fail on the
     success exit.** Mutations 14 and 15 are a pair on purpose: an implementation that erases on
     exactly one exit is caught by neither half alone, and 14 is the shape a `defer` refactor produces
     by accident.
  16. Take Property 6's observation from `MemberAt(0)`'s `identityPub` instead of from a leaf's
     signature key. **Property 6 must fail to detect mutation 13** — the control on the assertion set
     rather than on the implementation, and the exact reading under which the whole 7,665-test suite
     is green with the device destroyed.
  17. Drop `keys.Zeroize()` entirely — the "documented non-erase" this property rejects. **Property 3
     must fail** on the two arrays it holds, and **Property 6 must not pass by that route**: a gate
     that reads only `self.signer` calls an un-erased heap safe, which is how a fix for one half of an
     ownership rule ships the other half broken.

- [ ] **Step 6: Commit**

---

### Task 6: Two engines, one group — the `Export` equality that is the whole claim

**Files:**
- Create: `connect/messagegroup/enginejoin_test.go`
- Modify: `connect/messagegroup/doc.go` (the inventory paragraph at `:47-56`),
  `connect/messagegroup/engine_test.go` (`TestJoinFromWelcomeRefusesAndSaysWhatIsMissing` at `:823`)
- Test: `connect/messagegroup/enginejoin_test.go`

**Interfaces:**
- Consumes: Task 4's mint and Task 5's join body; `GroupEngine.CreateGroup`,
  `GroupEngine.NewKeyPackage`, `GroupEngine.JoinFromWelcome`; `GroupHandle.ProposeAdd`,
  `GroupHandle.Commit`, `GroupHandle.MergePendingCommit`, `GroupHandle.GroupId`, `GroupHandle.Epoch`,
  `GroupHandle.MemberCount`, `GroupHandle.MemberAt`, `GroupHandle.Export`, `GroupHandle.Close` — all
  landed at `messagegroup/engine.go:66`.
- Produces: no declaration. The first standing proof in either tree of *"two clients, one group"*, and
  the deletion of three statements that say it is impossible.

**Nothing in this package has ever produced a Welcome.** Measured:
`grep -rn "\.Commit(" --include=*_test.go messagegroup/` is six lines and every `GroupHandle.Commit`
call discards `welcome` and `ratchetTree` into `_`; `engine_test.go:913`, `:934` and `:948` all commit
a **one-member group with no proposals**, which is the only kind that group can make. So the producer
half of the Welcome is as unexercised at this seam as the consumer half, and this task is the first
thing to drive either.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — two independent engines end up in one group at one epoch, and their exporters agree.**
  The chain: A `CreateGroup`; B `NewKeyPackage`; A `ProposeAdd(kpB)`; A `Commit(nil)` answering a
  **non-empty** commit, welcome and ratchet tree; A `MergePendingCommit`; B
  `JoinFromWelcome(welcome, ratchetTree)`. End state, all five clauses: the same `GroupId`; the same
  `Epoch`; `MemberCount() == 2` on both; each `MemberAt` finding the other's `identityPub`; and
  `Export("URmessage/v1/storage", nil, 32)` **byte-equal** on both handles.
  **The exporter clause is the property and the other four are its preconditions.** Group id, epoch
  and member count agree between a joiner that really joined and a joiner that built plausible state
  out of a Welcome it mis-derived; the exported secret does not, and it is the exact value
  `GroupSession.installEpochOnLoop` reads at `session.go:429` to build every key of the record layer.
  *Refusal owed:* none on this path.

  **Property 2 — the two engines share no state, and the gate proves it rather than arranging it.**
  Two `mls.CryptoProvider`s, two `mls.StateStore`s, two signers, two credentials, two leaf-keys
  bodies. A shared store would let B's join succeed by reading A's group state and would make the
  exporter equality a tautology.
  *Refusal owed:* none; the observation is that B's store holds no group state before the join and
  exactly one after, and that A's store is unchanged by B's join.

  **Property 3 — the founder half answers a real Welcome through the seam.** `Commit(nil)` after a
  `ProposeAdd` answers a non-empty `welcome` and a non-empty `ratchetTree`; `Commit(nil)` with no
  pending proposal answers a **nil** welcome, which is `CommitResult`'s documented shape and the
  control that keeps the first clause from passing on any non-nil byte slice.
  *Refusal owed:* none. **The related overload this task does NOT rely on and does not fix:**
  `Commit([][]byte{})` — an empty non-nil vector — commits nothing and silently answers an empty
  commit with a nil Welcome, and `ProposeAdd` returns the encoded proposal **message** rather than a
  ref, so there is no way through this seam to obtain a value for `byReference` at all. That is
  **J1-7**, and this task uses the nil arm and says why.

  **Property 4 — every statement in this package that says a join is impossible is gone on this
  commit, and the gate is the package's own source.** Three: `doc.go:47-56`'s *"It cannot join a
  group"* paragraph and the reason under it; `ErrEngineJoinUnavailable` at `errors.go:135`; and
  `TestJoinFromWelcomeRefusesAndSaysWhatIsMissing` at `engine_test.go:823`, which is inverted into a
  positive join rather than deleted, because the shapes its comment rejects — *"a join that answered a
  handle built on a signature key this device does not hold"* — are exactly what Task 4 Property 1 and
  Task 5 Property 2 now hold.
  *Refusal owed:* none; the observation is a source read, in the shape `messagegroup`'s existing AST
  gates already use.
  *Scope to derive, separately from the class (R3), with the query beside it (R6):* the class is
  **every production sentence in this package that names `TakeKeyPackage` or
  `ErrEngineJoinUnavailable`**, derived over the package's production source rather than listed. The
  query is `grep -rn "TakeKeyPackage\|ErrEngineJoinUnavailable" --include=*.go messagegroup/ | grep
  -v _test.go`, and at `a1f8025` **that class is SIX members, not the three an earlier reading of this
  property named**:

  | line | what it is | which task removes it |
  |---|---|---|
  | `doc.go:50` | the honest-inventory sentence's reason | Task 6 (this task already edits `:47-56`) |
  | `engine.go:297` | `NewKeyPackage`'s doc paragraph | Task 4 |
  | `engine.go:314` | the refusal's format string | Task 5 |
  | `engine.go:315` | the sentinel argument to it | Task 5 |
  | `errors.go:130` | the comment block above the sentinel | Task 5 (it edits the declaration below it) |
  | `errors.go:135` | the sentinel itself | Task 5 |

  **Every one of the six is in a file some task of this plan already edits, so the WORK was scheduled
  and only the NUMBER was wrong — which is exactly how a count that is not a query fails, and why R6
  requires the query beside the size.** A gate that derives its class, as this property requires,
  would have printed six and failed against a plan that said three. The gate prints them, so a seventh
  written next month fails on the commit that adds it. **The complement, printed:** the references in
  `_test.go` files, which are the assertions that the sentinel and the refusal exist and which move
  with the gates that hold them rather than with this class; at `a1f8025` the same query without the
  `grep -v` returns the six above plus the test references, and Task 5's own edits carry those.

  **Property 5 — what this test does NOT establish is stated in its own comment, in the test file, and
  the gate asserts the comment is there.** Three sentences, and each names its item: **no record
  crosses between these two engines**, because `NewGroupSession` (`session.go:156`) refuses an empty
  `pq_secret` and there is no delivery channel for one (**S2-3**); **the joiner cannot compute a
  `sender_handle`**, because `installEpochOnLoop` (`session.go:459`) refuses a handle at epoch > 0
  that was given no `group_handle_key` and the carrier is deliberately deferred (**M1-2**); and **the
  Welcome here is handed over as a value in one process**, which is ledger **44a**'s named, gated,
  test-only hand-off and not a delivery channel. **CP3b is not reached by this task.** A file that
  proves two clients share a group and does not say those three things is a file the next reader will
  cite as the milestone.
  *Refusal owed:* none. This is a documentation property, held mechanically, for the reason ledger
  **44a**'s own rule gives: an absence that is named is safe and an absence that looks like a
  placeholder is not.

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Give both engines one shared `memoryStateStore`. **Property 2 must fail.** *And its rationale is
     corrected, because the earlier one was wrong:* a shared store does **not** make the exporter
     equality a tautology. `connectMlsHandle.Export` (`messagegroup/engine.go:417`) delegates to
     `(*mls.Group).Export`, which derives from the epoch key schedule held **in memory** by two
     distinct `*mls.Group` values; `StateStore` is written by `persist()` (`mls/group.go:681`,
     `:1024`, `:2579`, `:3429`) and read only by `LoadGroup` (`:2618`), which this plan measures as
     having zero callers outside `mls`'s tests. **So Property 1 going on passing under a shared store
     proves nothing about the exporter clause**, and the mutant is sound for the other reason:
     Property 2's own observation — that B's store holds no group state before the join and A's is
     unchanged by it — is false under one store.
  2. Skip `A.MergePendingCommit()`. **Property 1 must fail** on the exporter equality while group id
     and epoch still look right on B's side.
  3. Compare only `GroupId`, `Epoch` and `MemberCount`. **Property 1 must fail** to detect mutant 2 —
     the control on the assertion set rather than on the implementation.
  4. Hand B a `ratchetTree` from a different commit. **Property 1 must fail**, and Task 5 Property 2's
     put-back must hold: B's store still has its key package afterwards.
  5. Have B mint its key package with `mls.NewKeyPackage` — the tree at `a1f8025`. **Property 1 must
     fail** at `mls/group.go:3070`, and the failure must name the caller's material rather than the
     Welcome.
  6. `Commit([][]byte{})` instead of `Commit(nil)` after the `ProposeAdd`. **Property 3 must fail** on
     a nil welcome, which is J1-7's hazard made visible rather than ruled.
  7. Assert only that `welcome` is non-nil, dropping the no-proposal control. **Property 3 must fail**
     to distinguish a real Welcome from any non-empty slice.
  8. Restore `doc.go`'s *"It cannot join a group"* paragraph. **Property 4 must fail.**
  9. Keep `ErrEngineJoinUnavailable` declared. **Property 4 must fail** on a class of one where it
     should be zero, and the gate must print the sentence it found.
  10. Delete the three-sentence comment Property 5 requires. **Property 5 must fail**, and the failure
     must name which of the three is missing rather than reporting the comment absent.
  11. Construct a `GroupSession` over B's joined handle inside this test. **Property 5 must fail** —
     it cannot be constructed, and a test that reached for one has stopped saying what it does not
     establish and started trying to establish it.

- [ ] **Step 6: Commit**

---
## Wave 3 — off the CP3b prefix (Task 7)

### Task 7: The registry entry, and the count a gate's own comment gets wrong

**Files:**
- Modify: `msgrepo/docs/plans/2026-08-12-slice1-interface-registry.md`,
  `connect/mls/caller_arrays_test.go` (one word at `:2176`)
- Test: `msgrepo` — `go test ./ -run TestThePlanLinter`

**Interfaces:**
- Consumes: Tasks 1 and 5's Produces blocks, verbatim. Nothing else.
- Produces: no code. The registry rows that let the next plan write a `Consumes` block against this
  one without reading the source first.

**Why the one-word edit is here and not in Wave 1.** `caller_arrays_test.go:2176` says *"a hand
written double is nine wrappers"* and `mls.StateStore` declares **eight** — confirmed by the gate
three lines below it, which derives the number from `reflect` and is correct. The comment is wrong
today and stays wrong under this plan, because the interface does not move. It is worth a line
because it is **the sentence an implementer reads to decide how many wrappers to update**, and it sits
in the file whose gate would fail them.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the registry names what this plan produced, and every pending pin that was resolved
  by it is marked resolved rather than left pending.** The two produced names are
  `mls.NewKeyPackageWithSigner` and `messagegroup`'s two new sentinels; the resolved pin is the one
  m1 Task 16's Consumes block rests on — `GroupEngine.JoinFromWelcome` answering a handle rather than
  a refusal.
  *Refusal owed:* none; the gate is `go test ./ -run TestThePlanLinter` in `msgrepo`, whose check 4a
  is fatal on a `Consumes` entry naming a task that does not exist and whose check 3b is fatal on an
  open-item reference that resolves to nothing.

  **Property 2 — the stale count is corrected against the number the gate derives, not against this
  plan.** The class is **every prose count in `mls/caller_arrays_test.go` about `StateStore`'s method
  set**, and the query is `grep -n "nine" mls/caller_arrays_test.go`. **That class is TWO members at
  this task, not the one an earlier reading of this property named:** `:2176` — *"a hand written
  double is nine wrappers"* — and `:2180` — *"a tenth method, or a parameter added to one of the
  nine"* — both in the same comment block above the gate, and both wrong for the same reason, since
  `StateStore` declares **eight**. A correction that moved one and left the other is the defect this
  task exists to remove, sitting two lines below itself. The correction reads the number off
  `reflect.TypeOf((*StateStore)(nil)).Elem().NumMethod()` in the comment's own words, so a ninth
  method lands as a number that changed. **The complement, printed with its size: one** — `:45`, *"It
  is nine constructions today"*, which is the same digit about a different subject (the class of
  constructions handed a caller's bytes, not `StateStore`'s methods) and is **correct**. This task
  must not touch it, and the edit's diff must show it untouched. **A complement of one that the diff
  proves untouched is what stops this correction from being the third instance of its own class.**

- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run to verify it passes**
- [ ] **Step 5: Mutation-test**

  1. Add a registry row naming a task this plan does not declare. **Property 1 must fail** on the
     linter's check 4a.
  2. Cite an open item id no plan in the corpus defines. **Property 1 must fail** on check 3b.
  3. Correct the comment to "eight" by hand without reading the derived number. **Property 2 must
     fail** the day a ninth method lands — the correction has to name where the number comes from, or
     it is the same defect with a different digit.
  4. Correct `:2176` and leave `:2180` saying "one of the nine". **Property 2 must fail** on a class
     of two with one member uncorrected — which is the mutant an earlier reading of this property,
     with its class of one, could not have caught.
  5. Correct `:45` as well, on the reading that "nine" is one number in one file. **Property 2 must
     fail** on its printed complement: the third line is about a different class and is right.

- [ ] **Step 6: Commit**

---

## Execution order

| Wave | Tasks | Why here |
|---|---|---|
| 1 | 1, 2, 3 | `connect/mls`. Needs nothing and blocks everything. Task 1 is the root of the whole chain; Task 2 removes the duplicate minting body the sibling would otherwise leave; Task 3 is the first join in the tree whose material came out of an exported constructor, and it is what tells a failing Wave 2 which side of the seam is wrong |
| 2 | 4, 5, 6 | `connect/messagegroup`. Needs Wave 1 whole. Task 4 before Task 5 is not a preference: a join body landed against the old mint refuses at `mls/group.go:3070` on every key package the engine ever published, and the task looks green in isolation |
| 3 | 7 | The registry and one stale count. Off the CP3b prefix; land it last or land it any time after Task 5 |

**The landing order is the wave order on this plan, and the one thing worth stating separately is
where an implementer will otherwise fail to compile:**

```
1               (mls: the constructor)
2               (mls: one minting body — may be worked with 1, must land with or after it)
3               (mls: the round trip)
4               (messagegroup: the mint — needs 1)
5               (messagegroup: the join body — needs 4, and 4's mint, not just 4's commit)
6               (messagegroup: the two-engine join — needs 4 and 5)
7               (msgrepo + one comment — needs 1 and 5's Produces blocks)
```

**Tasks 1 and 2 may be worked by one implementer as one unit of thought and must land as two
commits**, because Task 2's Property 1 is an equality between two bodies and it is not observable
until both exist.

**No task in this plan may be worked in parallel with another by a second implementer.** Every one of
the seven touches a file an earlier one touches, and this project has already paid for two agents
committing to one repository.

**An implementer dispatched on Task 5 before Task 4 has landed cannot pass**, because
`mls.JoinFromWelcome`'s caller-material gate refuses the material the engine can assemble out of a key
package the old mint produced. That is Task 5 mutation 5 stated as a schedule.

---

## Definition of done

**In `connect`, on `beta/message`:**

1. `go build ./...` exits 0.
2. `go vet ./mls/... ./messagegroup/...` is clean.
2a. **The three gates the gate table now names are green, and they were RED before Task 1's
   implementation landed.** `go test ./mls/ -run 'TestEveryDeclarationHandedANilProviderRefusesRatherThanDereferencingIt|TestEveryCompositionEnteringALabelledConstructionIsBoundedBeforeItGetsThere|TestEveryConstructionHandedAProviderReadsKdfNhFromIt' -count=1`. **A green run of these three on the commit that adds the constructor and does not update them is impossible**, so a green run recorded without a red one before it means the `-run` pattern selected nothing — this project has shipped that exact failure and the linter's own header is the record of it.
2b. **`TestNewKeyPackageKeepsTheSigningSeedOffTheWireAndBesideItsOwnLeaf` derives its class rather
   than naming one.** It PASSES at `a1f8025` with the constructor present and undriven; after Task 1
   Property 4 it must print a universe of nine, a class of two and a complement of seven.
3. `go test ./mls/ ./messagegroup/ -count=1` is green. **Budget three minutes for `./mls/`.** The
   baseline to compare against is `ok mls 159.4s` / `ok messagegroup 13.5s` at `a1f8025`; a run that
   got dramatically faster is a run that stopped running something.
4. The test count has gone **up** and no test has been deleted. `TestJoinFromWelcomeRefusesAndSaysWhatIsMissing`
   is **inverted**, not removed, and the commit message says so.
5. `git ls-files | wc -l` equals `git ls-tree -r HEAD --name-only | wc -l`, checked **before** the
   commit and again after. On this machine the index has vanished mid-session before and a commit
   that silently truncated the tree is the failure mode.
6. The nine-platform `CGO_ENABLED=0` cross build is green. This plan adds no build tag and no
   platform-specific call, so a failure here is a surprise and must be read as one.
7. `grep -rn "ErrEngineJoinUnavailable" --include=*.go .` returns **nothing**.
8. `grep -rn "TakeKeyPackage(" --include=*.go .` returns the five lines it returned at `a1f8025`
   **plus** the engine's one new call site, and `PutKeyPackage`'s arity is still four.
9. Probe 1 re-run answers `KP leaf key == device signer pub : true`.
10. **The device survives its own join, which is the check this plan did not have.** After Task 6's
   two-engine chain, engine **B** mints a second key package and founds a second group, and both name
   the same signature key its pre-join key package named. **The failing value to look for is
   `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29`** — the ed25519 public key of
   the all-zero seed — and `grep -rn "SignPrivate: *self\.signer" --include=*.go messagegroup/`
   returns **nothing**: the field is assembled over a copy (Task 5 Property 6).

**In `msgrepo`, on `main`:**

11. `go build ./...` and `go test ./...` green.
12. `go test ./ -run TestThePlanLinter` ok, with the four fatal checks (2b, 3b, 3d, 4a) clean and the
    reporting counts recorded in the commit message on both sides of the diff.
13. `git ls-files | wc -l` equals `git ls-tree -r HEAD --name-only | wc -l`.

**And the sentence that is NOT in this list, deliberately: CP3b is not reached.** The Definition of
done for this plan is a joined group, not a delivered message. See *What this plan does not close*.

---

## What this plan does not close

- **CP3b.** Three filed blockers stand after this plan and none is its: **S2-1** (no reachable
  `read_key`/`write_key` on a live `GroupSession`), **S2-2** (`server_nonce` is captured once at
  construction and cannot be rebound), **S2-3** (`pq_secret` has a sampler and no delivery channel).
  Two clients that share a group still cannot agree on a `storage_root` without S2-3.
- **`group_handle_key` reaching the joiner.** **M1-2**, deliberately deferred 2026-09-13, with ledger
  **44a**'s gated hand-off blessed for CP3b. Task 6 does not build that hand-off; it does not need
  one, because it constructs no `GroupSession`.
- **A production `mls.StateStore`.** **S2-14**. The section above states what it owes. **J1-9 was
  RULED 2026-09-10 and S2-14 is OFF the CP3b prefix**: it is durability work, and the accepted cost
  is that the first end-to-end run does not survive a restart. **It is still unclosed and still has
  no owner (J1-10).**
- **A reopen path.** **J1-8**. `mls.LoadGroup` stays with zero callers outside `mls`'s own tests.
- **The Welcome's production delivery channel.** Ledger **44** and **44a**.
- **Re-join, external commits, external joins, multi-device.** Spec A §3.2 and §7.5.
- **The `mls_private` and `mls_keypackage` lifetimes.** **J1-12** and **J1-13**.
- **The receiver ratchet's persisted position.** **J1-14**. No `StateStore` implementation can repair
  it, because the field does not exist.

---

## Open items

Each is a spec, ownership or interface problem in this plan's area, with what it blocks. **None is
resolved silently.** Where this plan took a position because something had to compile, the position is
labelled as a position and the rejected alternative is named.

**J1-1 — MASTER §5.2 says `device_sig` is *"the MLS leaf signature key"* and does not say, in as many
words, that every leaf this device publishes names it.** A KeyPackage carries a LeafNode, and RFC 9420
permits a fresh signature key per advertisement — which is what `mls.NewKeyPackage` implements today.
§5.2's definite article and its per-device table are what this plan reads as ruling it; the narrower
reading scopes the sentence to the leaf of a group the device is a member of. *Position taken:* the
wide reading, with the evidence printed in *"The ruling this plan takes a position on"* and with the
plan built so the other reading costs one commit — `mls.NewKeyPackage` is untouched and additive is
reversible. *Not resolved:* the sentence itself. **Blocks:** nothing in this plan; it blocks anybody
who later wants per-key-package unlinkability, which `device_xwing` in the leaf-keys extension has
already spent. **Owed:** one sentence in MASTER §5.2 or Spec A §3.5.

**J1-2 — three landed comments in `connect/mls` describe a mechanism no code uses, and they are the
comments a planner would trust.** `key_package.go:62-63` and `:257-261` both say the group lifecycle
plan reads `signPriv` off the value when it assembles `JoinKeyMaterial`; `group.go:2935-2941` says the
same from the other end. Measured at `a1f8025`: `grep -rn "SignPrivate:"` is **13** sites and **zero**
read `kp.signPriv`; the only non-assertion reader of the field anywhere is `key_package_test.go:76`.
**These three sentences are why S2-4's filed cause, `messagegroup/engine.go:314`'s refusal text,
`errors.go:135`'s sentinel and `doc.go:50`'s inventory all frame the blockage as *"the field is
unexported"* rather than *"the constructor takes no signer"*.** Task 1 corrects them.
**Blocks:** nothing, now that it is written down. **Owed:** nothing; this item is the record of why a
correct-looking cause was wrong, kept so the next reader does not re-derive it.

**J1-3 — `TakeKeyPackage` is destructive, there is no non-destructive read, and nothing specifies what
a failed join costs.** The name is the contract and the only implementation deletes before returning.
`mls.JoinFromWelcome`'s own header establishes at length that **a Welcome authenticates nobody**, so
anybody holding this device's published key package can send one that fails any of roughly fifteen
checks after the take. The interface cannot express take-on-success: one method reads and deletes,
and there is no `GetKeyPackage` and no `DeleteKeyPackage`. *Position taken:* Task 5 takes and **puts
back on every failure after the take**, which works on the eight-method interface and reduces the loss
from *"an attacker's message"* to *"a crash in a millisecond-wide window"*. *Rejected:* a ninth and
tenth method, because it is a Spec A §3.5 amendment and the reflective gate at
`caller_arrays_test.go:2181` makes it a six-file commit — see *What changes in `mls.StateStore`*.
*Not resolved:* whether consume-on-attempt is intended, or whether §3.5 should be split into a `Get`
and a `Delete`. **Blocks:** any retry story, and offline or duplicate Welcome delivery. **Owed:** a
normative sentence in Spec A §3.5, and it lands on whoever writes S2-14.

**J1-4 — `mls.StateStore` has no error taxonomy, and the join is the first caller that needs one.**
`GetGroupState`, `GetPrivateKey` and `TakeKeyPackage` each return a bare `error` with no declared
not-found value, and `LoadGroup` (`mls/group.go:2634`) propagates it verbatim. Spec A §8.2 makes the
opposite rule normative for `MessageStore` — *"Store-open failure is an explicit value, never an empty
result"* — and §3.5 says nothing. Task 5's join loops over the refs a Welcome names and cannot tell
*"this ref is not mine"* from *"the disk is broken"*. *Position taken:* Task 5 Property 4 makes the
refusal carry both readings in its message, which is honest and is not a fix — a caller matching on
the type still cannot branch. **Blocks:** a restarted client deciding whether to re-join or to retry.
**Owed:** a sentinel in Spec A §3.5, in §8.2's own shape.

**J1-5 — the array-ownership contract is stated for `Put` and `Get` and is silent about `Take`, and
the silence is a live contradiction.** `mls/group.go:287-302` says a store must not retain a caller's
slice, and that what `GetGroupState` answers is the **store's** array which the group must not wipe.
`(*JoinKeyMaterial).Zeroize` (`:2947`) erases `InitPrivate`, `EncryptPrivate`, `SignPrivate` and
`KeyPackage.signPriv` — which are exactly the arrays `TakeKeyPackage` handed back. `memoryStateStore`
survives it only because it deletes the map entry first. **A production store that returns a retained
array without deleting has its octets wiped by a correct caller.** Task 5 Property 3 makes this cost
nothing at the one call site that exists, by copying before assembling. *Not resolved:* the header
sentence. **Blocks:** nothing today; it lands on whoever writes S2-14. **Owed:** one clause in
`StateStore`'s header and in Spec A §3.5.

**J1-6 — Spec A §6's `JoinFromWelcome(welcome, ratchetTree)` carries no intended group id, so the
intent match `mls.JoinFromWelcome` offers is unreachable through the seam.** `mls/group.go:3255`
checks `cfg.GroupId` against the group the Welcome describes *when the caller sets it*, and its own
comment is careful that this *"is an intent match and not authentication"* — what it buys is that a
caller which said which group it meant to join is not silently placed in another one. §6's method has
nowhere to say it. *Position taken:* Task 5 leaves `cfg.GroupId` nil and says so, because a guessed id
refuses every legitimate Welcome. **Blocks:** nothing for CP3b; it means a caller handed a Welcome for
group Y while expecting group X is placed in Y without a word. **Owed:** a §6 amendment — Gate 5's
swap surface, therefore an owner ruling.

**J1-7 — `GroupHandle.Commit(byReference [][]byte)` overloads nil and empty with opposite meanings,
and `ProposeAdd` gives a caller nothing to put in the parameter.** `mls/group.go:1980`: a **nil**
vector commits every cached proposal; an **empty non-nil** vector commits none and answers a
well-formed commit with a nil Welcome. Neither Spec A §6 nor `engine.go`'s doc names the distinction.
Compounding it, `ProposeAdd` returns the encoded proposal **message**, not a ref, so there is no way
through this seam to obtain a value for `byReference` at all — the nil arm is the only usable one and
the parameter is dead surface today. *Position taken:* Task 6 uses the nil arm, says why, and makes
mutation 6 the demonstration. **Blocks:** a founder that builds its ref vector in a loop that adds
nothing gets a green commit adding nobody. **Owed:** a sentence in §6, or a ref on `ProposeAdd`.

**J1-8 — `GroupEngine` has four methods and none of them opens a persisted group, so a durable store
would write rows nothing reads.** `mls.LoadGroup(cfg, epoch, signer)` (`mls/group.go:2618`) is a
complete restore including the TreeKEM ladder and the own-leaf sender ratchets, and measured, it has
**zero** callers anywhere outside `mls`'s own tests. CP3b's own word is *"DURABLE"*. And a reopen needs
one thing more the interface cannot answer: **which epoch**, since `LoadGroup` takes it as a
parameter and nothing enumerates it. **Blocks:** every restart story, and it makes S2-14 write-only
until it is closed. **Owed:** a fifth `GroupEngine` method and a latest-epoch answer — a Spec A §6
amendment, therefore Gate 5 and an owner ruling.

**J1-9 — RULED by the owner, 2026-09-10. CP3b's *"no test-only key SOURCE anywhere on the path"* is
read LITERALLY: key SOURCE, not test-only CODE. S2-14 comes OFF the CP3b prefix.**

*The question, kept because the reading is what was ruled and not the conclusion:* `mls.JoinFromWelcome`
calls `group.persist()` → `store.PutGroupState` at `mls/group.go:3429`, so a join always writes
through a `StateStore`, and the only implementations are five in-memory maps in `_test.go` files. An
in-memory map is test-only **code**; it is not a key **source** — it stores keys the real provider
drew.

*The ruling, in the owner's terms:* an in-memory `StateStore` satisfies CP3b, **because every key on
the path still comes from the real MLS key schedule and the real crypto provider**. That is not an
assertion this plan has to defend: `connect/messagegroup/keysource_test.go` already proves it
independently and byte for byte, rebuilding the whole sealed record from the real group's
`Export("URmessage/v1/storage", nil, 32)` plus two injected values that are not keys, with nothing on
the reproduction's side coming from the module under test. A `StateStore` appears nowhere in that
reproduction. `PROGRESS.md:73-77`'s own contrast reads the same way — CP3a is the path *"with the AEAD
under a test-only key source"*, CP3b *"the same path with the real MLS key schedule underneath"*.

***THE COST THE OWNER ACCEPTED, AND IT IS PART OF THE RULING RATHER THAN A FOOTNOTE TO IT: the first
end-to-end run WILL NOT SURVIVE A RESTART. It proves the protocol, not the product. Every future
report of this milestone must say so — CP3b means "the protocol works end to end", and it does not
mean "a person may use this".*** A report that omits the restart sentence has overstated the
milestone.

*What it changed:* **S2-14 moved off the CP3b prefix and became durability work**; this plan's
*"Where the CP3b line falls"*, its *"OFF this plan's prefix"* table, its *"What this plan does not
close"* list and the section now titled *"The J1-9 ruling"* all carry it, and the `s2` plan's S2-14
item carries it too. **Nothing in Tasks 1–7 moved**, because nothing in them was ever sequenced behind
S2-14. *What it did NOT change:* **J1-8**, **J1-11**, **J1-12**, **J1-13** and **J1-14** are each a
durability question and each moved off the prefix WITH S2-14 rather than being closed.
**Blocks:** nothing. **Owed:** nothing — except that **S2-14 still has no owner, which is J1-10 and
is still the owner's.**

**J1-10 — neither S2-4 nor S2-14 has an owner, and the plan that filed them is barred from both.** The
`s2` plan files S2-4 with *"Owner: `connect/mls`, upstream of m1 Task 16"* and S2-14 with *"Not
`s2`'s, because Gate 5 keeps `s2` out of `connect/mls` entirely"*. `connect/mls` is a package, not an
owner. **This plan takes S2-4 and does not take S2-14.** **Blocks:** S2-14 has nobody. **Owed:** an
owner for S2-14, which is `sdk`-shaped and gated on **S2-13**.

**J1-11 — `PutGroupState` is on the send path, once per sealed message, and no document says it must
be durable before it returns.** `(*Group).sealAndRecordLocked` (`mls/group.go:1018`) persists at
`:1024`, **before** the ciphertext is handed to the caller, and `group.go`'s comment there says a send
that did not write back *"has gone out under one (key, base nonce) pair for this leaf and
generation"*, with a 32-bit `reuse_guard` between that and a nonce collision. Spec A §8.1 reserves
`PRAGMA synchronous=FULL` for the `stream` table alone and §3.5 says nothing. **Blocks:** nothing in
this plan; it is a correctness requirement on S2-14 and is the same class as **S2-16**. **Owed:** a
clause in Spec A §3.5 or §8.1.

**J1-12 — `DeletePrivateKey` has zero production callers and `mls_private` grows forever.**
`PutPrivateKey` is called on every `ProposeUpdate` (`mls/group.go:1697`); `mls/group.go:4195` says in
as many words that deleting it belongs to *"(StateStore).DeletePrivateKey's, on the epoch boundary
task 19 owns"*, and that task landed `LoadGroup` without the delete. Spec A §8.1's *"key superseded or
leaf removed"* has no code that performs it. **Blocks:** nothing before CP3b; it is unbounded growth
of sealed private-key rows. **Owed:** a caller, and a sentence saying where it belongs.

**J1-13 — `mls_keypackage`'s second deletion trigger has no mechanism.** Spec A §8.1 line 4628 says
pending key packages are deleted on *"Welcome consumed, or 30-day lifetime expiry"*. The interface has
no enumeration, no sweep and no lifetime accessor, and `TakeKeyPackage` needs a ref, so nothing can
implement the second half. **Blocks:** nothing before CP3b. **Owed:** either a method, or a statement
that expiry is the local store's own business and not `mls.StateStore`'s.

**J1-14 — the persisted epoch blob carries the sender's ratchet position and nothing for the receive
side, and no store implementation can repair it.** `groupStateBlob` (`mls/group.go:1220`) declares
`SenderRatchets` and no receiver field; `LoadGroup` restores the own leaf's ratchets only; and
`(*Group).Unprotect` **never persists** — measured, the four `persist()` call sites in `group.go` are
`:681`, `:1024`, `:2579` and `:3429`, and none is on the receive path. So after a restart every peer's
receiver ratchet restarts at generation 0 and messages already consumed become acceptable again at the
MLS layer; `ErrRatchetGenerationConsumed` is in-memory only. **Stated with its caveat rather than
claimed as an exploit:** the record layer above may mask it by deduplicating on record id, and this
plan has not measured that it does. **Blocks:** the second run of a restarted client, not the first
message. **Owed:** a ruling on whether receiver position is in scope for the epoch blob. It is not the
store's to fix, because the field does not exist.

**J1-15 — this plan is the only document in the corpus that declares tasks and carries no linter
token, so a later plan's qualified `j1 Task N` reference cannot resolve.** `planlint_test.go:158`
derives a document's token with `planTokenRe = regexp.MustCompile("-((?:p|s|m)[0-9]+)-")` and
`:200` leaves `doc.token` empty when nothing matches; `2026-09-09-slice1-j1-the-join.md` matches
none of `p`, `s` or `m`. Of the 13 plan documents in `docs/plans/`, the only other token-less one is
`2026-08-12-slice1-interface-registry.md`, **which declares no tasks** — so this is the first
document where the gap can cost a resolution. `go test ./ -run TestThePlanLinter` is ok today, and
that is the point: the linter cannot see this, because a document with no token is not checked
against the token pattern rather than failing it. *Three ways to close it and this plan rules none:*
rename the file to a `-j1-` token the pattern accepts, widen the pattern, or rule that plan tokens
are `p`/`s`/`m` and this document must be renamed into one of those series. **Blocks:** any later
plan writing `j1 Task 5` in a `Consumes` block and expecting check 4a to resolve it. **Owed:** one
decision from whoever owns the corpus's naming, and it is free today.

**J1-16 — `JoinKeyMaterial`'s header says the caller goes on owning every array it passed and owes
each of them the erase, and the erase it names destroys them; for `SignPrivate` those two sentences
are opposite and no document says which array a caller may pass.** `mls/group.go:2925-2932`:
*"a caller goes on owning every array it passed and owes each of them the erase below"* —
and `Zeroize` at `:2947` wipes `SignPrivate` in place, so a caller that owns `device_sig` and passes
it owes an erase that destroys it. This is **J1-5**'s silence about `Take` seen from the other end:
J1-5 is about the arrays the STORE owns, this is about the array the CALLER owns and cannot afford
to lose. *Position taken:* Task 5 Property 6 assembles over a copy, which is correct under **both**
readings — if the header means "pass arrays you are willing to lose", a copy is one; if it means
"the erase is the caller's obligation and not this type's", a copy still satisfies it. **The position
is deliberately the one that does not need the ruling**, which is R4's shape rather than a
workaround. *Not resolved:* the header sentence, and whether a type that declares an erase over a
field it did not allocate is the right shape at all. **Blocks:** nothing in this plan. **Owed:** one
clause in `JoinKeyMaterial`'s header, and it lands beside **J1-5**'s on whoever writes S2-14.

---

## Open asks on other plans

- **To the owner:** rule **J1-1** — whether MASTER §5.2's `device_sig` binds every leaf this device
  publishes, including a KeyPackage's. This plan takes the wide reading with its evidence printed and
  is built so the narrow reading costs one commit. It is free today and expensive at Task 5.
- ~~**To the owner:** rule **J1-9**~~ — **ANSWERED 2026-09-10.** CP3b's *"no test-only key source"*
  is read literally as key SOURCE and not test-only CODE; S2-14 is off the prefix and is durability
  work; **the accepted cost is that the first end-to-end run does not survive a restart, and every
  report of this milestone says so.**
- **To the owner, and STILL OPEN:** name an owner for **S2-14** (**J1-10**). The J1-9 ruling moved
  S2-14 off the prefix; it did not give it a name, and an unowned durability item with no bar in
  front of it is the shape of work that never gets picked up. Also still open: rule **J1-8** —
  whether §6 grows a reopen method — since a durable store with no reader is a store nobody can
  justify, and J1-9 moved that question off the prefix rather than answering it.
- **To whoever owns Spec A §3.5:** **J1-3** (what a failed join costs, and whether `Take` splits into
  `Get` and `Delete`), **J1-4** (an error taxonomy), **J1-5** (the array-ownership clause for `Take`),
  **J1-11** (send-path durability), **J1-12** and **J1-13** (the two lifetimes with no mechanism). All
  six land on whoever writes S2-14 and all six are cheaper now than they will be nine tasks into that plan.
- **To whoever owns Spec A §6:** **J1-6** (the joiner has nowhere to say which group it meant) and
  **J1-7** (`Commit`'s nil-versus-empty overload, and `ProposeAdd` answering no ref). Both are Gate 5's
  swap surface.
- **To m1:** m1 Task 16's Files block lists *"Modify: `session.go`, `wrap.go`, `doc.go`"*. Measured at
  `a1f8025`, `wrap.go` does not exist, `session.go` needs **no** change for a joining member — the
  non-nil arm of `installEpochOnLoop` (`session.go:445`) already serves a handle at epoch > 0 — and
  the file that must change is `engine.go`, which is not listed. m1 Task 16's own measurement,
  *"`grep -rn 'group_handle_key|GroupHandleKey'` over `connect` returns 0"*, is stale: it returns 19
  production hits at `a1f8025`. The derivation, the width refusal and the `SenderHandle` binding all
  landed; only the carrier is absent. Also: this plan creates
  `connect/messagegroup/enginejoin_test.go` and deliberately does **not** create `join_test.go`, which
  m1 Task 16's Files block claims.
- **To `s2`:** S2-4's cause line — *"because `connect/mls` keeps a minted key package's signature
  private half on an unexported field and `StateStore.TakeKeyPackage` does not carry it"* — should be
  corrected to name the constructor, with **J1-2** as the reason it read that way; and the open ask
  *"publish the joiner's signature private key so `JoinFromWelcome` can work"* should become *"mint
  the key package against the device's own signer"*. The blocker itself is real, is unchanged, and is
  what this plan closes.
- **To whoever owns the corpus's plan naming:** **J1-15**, that this document has tasks and no linter
  token. Three ways to close it are named and none is taken here, because the choice decides how every
  future non-`p`/`s`/`m` plan is named and that is not one plan's to settle.
- **To whoever owns Spec A §3.5, added:** **J1-16**, `JoinKeyMaterial`'s ownership sentence against its
  own erase. It rides with **J1-5** and costs one clause.
- **To nobody, and it stays open:** **J1-14**, the receiver ratchet's persisted position. It is named
  here because a plan that did not name it would be read as having closed it.
