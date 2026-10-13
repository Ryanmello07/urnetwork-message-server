# Hardening: the adversary harness RED first, the held-group gate, then the sealed join

The execution plan for steps S0 and S1 of the hardening program, written by the lead's planner on
2026-10-09 from a lab that built and ran every commit it describes, and REVISED the same day to the
lead's rulings R6 to R14 after two independent checks of it (`LEAD-RULINGS-2026-10-09.md`,
`_finalcheck_fidelity.md` and `_finalcheck_grounding.md`, beside this file; the plan as it stood
is `2026-10-09-S0-T1-plan.before-revision.md`). It was checked again on 2026-10-12, against
`main` `0bb2128f` under go1.27.2 (`_revcheck2_report.md`), and amended to the lead's rulings R15
to R18 (`LEAD-RULINGS-2026-10-12.md`; the plan before that is
`2026-10-09-S0-T1-plan.before-revcheck2.md`). In this plan the join seal track is called **T1**
and its fast-tracked held-group gate **T1a**, as its design does; the program calls the same track
S1. "The identity track" is the program's S2 (safety numbers) and "the healing track" its S3.

| | |
|---|---|
| Repository | `github.com/urnetwork/message`. ONE PULL REQUEST PER PHASE: S0, T1a, T1. Each phase branch is CUT FROM `urnetwork/message` `main` and pushed to the owner's fork `Ryanmello07/urmessage`; it is never cut from the fork's own `main`, which carries a workflow file the upstream repository does not use and lacks upstream's last commits. |
| Order (R6) | The phases merge after, in this order: the import (merged as `07704991`), its follow-up (merged as `a0d47bef`), the pins switch (urnetwork/message#3, merged as `cc5efcc2`) and the toolchain move (urnetwork/message#4, merged as `0bb2128f`). ALL FOUR HAVE LANDED, so S0 is cut from a `main` that has them. Then S0, T1a and T1, ONE AT A TIME: each phase branch is cut from `main` after the phase before it has merged (R18). When `main` moves under a phase branch, `main` is merged into the branch, and the branch is never rebased. |
| Base | `urnetwork/message` `main` on the day a phase is cut: `0bb2128fdf14` on 2026-10-12. The lab was built on `4d365abfdb1a`, the pushed head of the import, which is an ancestor of it. The second check applied the lab's 21 commits to `0bb2128f` with `git am --keep-cr`: 20 apply strictly, and the scan's commit (Task 29) stops on hunk 1 of `test.sh`, whose context the toolchain move rewrapped; `--3way` merges it with the same added lines and no fuzz. The applied trees are S0 `515afbe2`, T1a `f6a717b1` and T1 `8ce27292`, before R16's change to Task 29's script, and they differ from the lab's trees only in files `main` changed. Task 29's diffs are cut against `0bb2128f`. Every path below is a path in that repository. |
| Compiler | The pin is go1.27.2: the toolchain move landed as `0bb2128f`. The lab's numbers were measured under go1.26.5, the pin at the lab's base, and the second check measured every phase end again on `0bb2128f` under go1.27.2: every count equals the lab's. EVERY NUMBER IN A PHASE REPORT IS STILL MEASURED AGAIN ON THE DAY, on the branch, under the compiler of the day. The lab's numbers are this plan's evidence that the design works; a count that differs on the day is a finding. |
| Designs | `hardening-designs/T4-testing-FINAL.md` (the harness, the quick fixes, the vectors) and `hardening-designs/T1-join-seal-FINAL.md` (T1a, T1), both in the session scratchpad |
| Variant | RESET, and it is the only variant. The owner, 2026-10-09: "So far the alpha message-server we have up can be classified as disposible as we are in development". Invite version 3 only: no version 2 reader, no mixed-version rules, no rekey sweep, no rollback runbook. ONE rollback rule is kept, and Task 55 step 4 states it. What the variant drops is Appendix A, as a record. |
| Lab | `hardening-plans/lab-s0t1plan/base/w`, a git repository in the session scratchpad: an export of the lab's base with its siblings at their pins, and ONE COMMIT PER TASK THAT CHANGES THE TREE. Every diff below is that commit's own. The chain as it stood before this revision is the branch `before-revision` of that repository. THE LAB'S COMMITS ARE NEVER PUSHED: its base is a Windows export, which records `test.sh` without its executable bit, and a phase's commits are made on a branch of `main` from the diffs printed here. |
| Tasks | S0: 31. T1a: 9. T1: 19. Three of them are the message-server writer's and two are the message-windows writer's, and each says so in its title; every other task is this repository's. The task numbers of phases T1a and T1 moved with this revision: "Review dispositions" has the table. |

## Goal

Make the join path's known weaknesses fail a test today, close the one that lets an invitation
replace a group a device holds as a member, then stop sending the join secrets in the clear.

- **S0** adds an adversary simulation harness to `sdk/cp3b`. On today's code 17 of its
  22 scenarios report a gap that is open, with the exact thing the adversary got. It
  also lands two quick fixes and installs one unused vector family.
- **T1a** closes 8 of those 17: an invitation can no longer replace a group the
  device holds as a member, and a refused invitation no longer spends the joiner's one-use join
  code. It changes no format. It ships first, on the mainline.
- **T1** closes 6 more: an invitation carries no secret in the clear. Three stay open
  and pinned: join-code substitution and the removed-group case (both the identity track's), and
  keys at rest (the healing track's).

## The architecture in three sentences

1. An invitation carries no secret in the clear: the two values a joiner needs (the join epoch's
   post-quantum secret and the group's handle key) travel sealed to the X-Wing key that the
   joiner's own device published in its join code, the way Matrix sends room keys encrypted to a
   device's published keys.
2. A MAC under a key only members of the joined epoch can derive ties that seal to this welcome,
   this tree and this leaf; the joiner verifies it, opens the seal and checks it before anything
   reaches its store, so a refused invitation costs nothing, and an invitation into a group the
   device holds as a member is refused before any of that.
3. Who the adder is stays outside this change, as device verification is its own layer in Matrix:
   that is the identity track, and the harness keeps its two gaps pinned open until that track
   closes them.

## What the lead has ruled

The first form of this plan asked the lead five things. All five are ruled (R6 to R10), and four
more rulings (R11 to R14) answer the final check of the plan. The rulings are
`LEAD-RULINGS-2026-10-09.md` and, for R15 to R18, which answer the second check of the revised plan,
`LEAD-RULINGS-2026-10-12.md`, beside this file. They are the lead's, not the owner's, and the owner
may flip any. Each is stated here where it changes what an implementer does, and each task that
applies one cites it by its id. READ BOTH FILES BEFORE YOU START A TASK, AND AGAIN BEFORE YOU FINISH.

- **R6. The toolchain pin moved, in its own reviewed change, before S0: urnetwork/message#4,
  merged as `0bb2128f`.**
  - *The finding* is this plan's own scan (Task 29, the base tree, the database of
    2026-10-08): under the pinned go1.26.5, standard-library advisories reach the four `sdk`
    modules (`net/http`, `net/textproto`, `net/url`, `crypto/tls`, `os`, `encoding/asn1`; fixed in
    go1.26.6 and go1.26.9), and five are also reported in `golang.org/x/net`, fixed in v0.60.0.
    The root module and the wire corpus reach none.
  - *The ruling.* ONE reviewed change of its own, as `scripts/toolchain.sh` requires: `go.mod`'s
    line and `mls/pins_test.go`'s literal together, target **go1.27.2**, with `golang.org/x/net`
    at v0.60.0 or newer wherever a module requires it. It is three pull requests in three
    repositories, one writer each, and IT IS NOT A TASK OF THIS PLAN. Its gate (the scan of
    Task 29 under the candidate), its fallback (go1.26.9) and what it must show under the
    new compiler, a cross-compiler run among them, are in the rulings file and are that change's.
  - *What this plan takes from it:* the ORDER in the "Order" row above; that a phase branch is
    never rebased; that every number of a phase report is measured on the day under the compiler
    of the day; and the scan's gate. THE MOVE HAS LANDED, so `MESSAGE_TEST_VULNCHECK=1` IS EXPECTED
    TO PASS from S0 on, with the tool R16 names (`govulncheck` v1.9.0: v1.1.4 cannot read go1.27's
    standard library), and a red scan is a finding for the lead. No task here changes a `go.mod`,
    a pin line or `mls/pins_test.go`: Task 28 edits the pin FILE's prose and none of its four
    `key=` lines.
  - *The live alpha server* holds only ciphertext and is disposable (the owner, 2026-10-09).
    Since 2026-10-12 it runs a server built under the new pin (urnetwork/message-server#5's
    branch), and a live probe held against it.
- **R7. One message-server writer** does Task 1, Task 32 and Task 41, and
  the three ledger entries the phase closes ask for. Each is ITS OWN SMALL PULL REQUEST to
  urnetwork/message-server, paired with the phase it covers, and the owner is told to merge the
  message-server one first. The writer starts after urnetwork/message-server#3 has merged, which
  it has (merged 2026-10-09 at 12:22 UTC).
- **R8, as R15 words it (2026-10-12). The full run at each phase close**, before the phase's pull
  request is opened: `./test.sh` whole, unmodified, under the pin, on linux with gcc (the host
  `alt-2`) and on Windows, and the fork's `fork-ci.yml` on the branch head with ALL FOUR LEGS. The
  pull request cites the runs.
  - THE WINDOWS RUN IS THAT WORKFLOW'S `windows` LEG: a `core.autocrlf=true` clone on GitHub's
    Windows runner, with MinGW-w64 gcc on `PATH`. No Windows host of the lead's has a C
    compiler, and nothing is installed on the owner's machine.
  - `test.sh` names what each host cannot run, and each run must print the verdict `test.sh`
    gives that host, AND NOTHING WIDER. On `alt-2`, `linux` and `linux-newer-go` that is
    `VERDICT: PASS, narrower than the full run (above)`, with EXACTLY ONE narrowing: the
    loopback library's C consumer, which is a Windows program. On `windows` it is
    `VERDICT: PASS`, or the narrowed verdict with EXACTLY ONE narrowing: the C consumer's second
    pass against a `-race` build of the loopback library, which ThreadSanitizer could not map
    into the dll.
  - Any other narrowing, a second one, or a FAIL stops the close. A run on a host with no C
    compiler ends `VERDICT: FAIL` by design (the README says so) and is not the phase's run.
  - The narrowings are held both ways: the close's record prints every line each run lists
    under `NARROWER THAN THE FULL RUN:`, and the set must EQUAL the allowed one.
  - The lab never ran the race detector or `sdk/cgo`: its host has no C compiler. T1a adds two
    mutexes to the join path, so A RACE REPORT AT T1a'S CLOSE IS A FINDING, NOT NOISE.
- **R11. The fourth leg is the provenance leg, in this form.** The import's proof is held at ONE
  recorded tip, the head of the pins switch, and `docs/HISTORY.md` says so. At a later tip, which
  is every tip of this plan, the leg checks that the recorded tip is an ancestor (nothing was
  rewritten) and that the proof still passes AT the recorded tip. **THIS PLAN ADDS NO ROW TO THE
  IMPORT'S MANIFEST** (`docs/history/adaptations.tsv`) and changes no file under `docs/history`.
  The changes to the leg and to `docs/history/carried.py`, which is to take the two removals'
  ranges as recorded commits and not as merge bases with a moving `main`, are the pins-switch
  pull request's (wave 6 of that work, items 8 and 11 of the wave; R11 names them by their own
  ids, which are not spelled here because the plan linter of `message-server` reads such a token
  as an open item of its own corpus). The fork's `fork-ci.yml` follows them, and that workflow is
  fork-only: it is part of no upstream pull request. Measured by the final
  check, before this ruling: as the leg stood it failed at every phase head by this plan's own
  changes (15 failures at the end of S0, 33 at T1a, 236 at T1), and on `main` itself since
  urnetwork/sdk#158 merged. **THE CHANGE HAS LANDED** (2026-10-12): the pins switch merged as
  `cc5efcc2` with the recorded tip `7a33917306ae` in `docs/history/recorded-tip.txt`, and the
  fork's `fork-ci.yml` (at `9ea66f34`) runs that tip's own proof from outside the checkout. The
  leg is green on `0bb2128f` (fork run 38290870884) and on the second check's T1 tree.
- **R9. The two choices this plan made are both confirmed.**
  - A group founded before T1 is REFUSED at `Restore` and at `Join` (`ErrGroupPredatesJoinSeal`,
    Task 47). Nothing is carried for compatibility. Two duties follow: the T1 report tells
    the owner in plain words that test conversations made before this package stop opening and
    that the folders are started fresh; and the Windows app says so in a sentence and does not
    show the raw error (Task 58).
  - `ForgetGroup` of a group that did not restore leaves WITHOUT the owner's question: there is no
    live roster to ask it of.
  - Both stay on the list of the pre-merge review (Task 57).
- **R10 and R14. The defect found while planning is filed by the T1a pull request, not fixed.** A
  device that was removed and added back reads what is sent after the re-add, and its first
  `Receive` ALSO answers "a record ciphertext did not authenticate" for history it cannot open.
  An authentication failure is the signal for tampering, and it must not also be the answer for
  history that is unreadable by design. Task 37 files it as open item MG-8 of
  `messagegroup/OPENITEMS.md`, with the one line of production prose that cites it and the
  planner's probe as a named test. The healing track's plan takes it.
- **R12. One group record that does not read must not wedge the device.** As this plan stood, the
  held-group gate asked the store for EVERY group record, so one record that did not read stopped
  the device joining, founding or leaving anything, and no call cleared it. All of the following
  is in Task 33 and its tests:
  - the gate and `recordOnDisk` ask about ONE group id, so a record that does not read refuses
    only an invitation into its own group;
  - the listing tolerates a record that does not read and reports it as damaged. R12 adds "with
    its group id where the store's own naming gives one", and THIS STORE'S NAMING GIVES NONE: it
    names a group's directory by a hash of its id. The report names the directory. It is the one
    clause not met as worded, and "Review dispositions" says what that costs and what it does not;
  - `Restore` goes on past such a record: it restores the others and reports the damaged one.
    THIS CHANGES BEHAVIOUR THAT WAS THERE BEFORE THE PLAN, ON PURPOSE: one damaged file must not
    cost a person every conversation on the device;
  - `ForgetGroup` leaves a group whose record does not read, and the refusal's sentence names
    `ForgetGroup`;
  - a control scenario beside `S7-c1`, with its mutants, two of them the ones the final check
    found alive; and one forced-order test each for `Restore` and `CreateGroup` under the
    admission mutex, each with the mutant that takes the lock away.
- **R13. The app's half of a refusal ships with the refusal.**
  - No app package is built on a T1a library until the Windows app can offer to leave a group
    that did not restore: Task 39, and Task 40 says so. `message-windows` pins
    its `message` commit by hand, so nothing reaches the app before that pin moves.
  - An invitation whose join code is already gone gets its own sentence, without the prefix that
    says the join code is not spent (Task 36), and its row in the app's table
    (Task 58).
- **R16. The scan's tool is `govulncheck` v1.9.0** (2026-10-12; it amends R6). v1.1.4, which the
  lab ran, panics inside its own `go/ssa` when it reads go1.27's standard library for linux, and
  `scripts/vulncheck.sh` then says, correctly, that the tool gave no verdict. Task 29's script
  defaults to v1.9.0, the scan's runs this plan records are made on `alt-2`, and its releasing
  note names the `toolchain` line of the root `go.mod`, the only one there is.
- **R17. The text follows urnetwork/message#3 and #4, and the second check's minors**
  (2026-10-12): the Order, Base and Compiler rows; R6, R8 and R11 above; Task 29's ruling
  paragraph and, cut by the S0 writer from its own commit, its code blocks; Step 1 and Step 2 of
  Tasks 31, 40 and 59; Task 59 Step 4; Task 58's row for an invitation no readable join code
  matches; and question (f) of Task 57.
- **R18. Execution** (2026-10-12). One phase at a time, each cut from `main` after the one
  before it has merged, with one writer on this repository. The S0 branch is built and verified
  on the owner's fork before Task 1 lands, and NO PHASE PULL REQUEST IS OPENED BEFORE TASK 1'S
  COMMIT IS ON `message-server`'s `main`. Task 1 waits for urnetwork/message-server#5, which adds
  the ledger's entry for the toolchain move, and it files this plan with the S0 writer's Task 29
  blocks in it.
- **Not ruled, and open for the pre-merge review** (Task 57): the read path during a
  join's window, and the erase after a failed record write. Both are questions of that task.

## How this plan is laid out

It is in the plan shape `message-server/docs/plans` holds its plans to, and `planlint_test.go` reads
it: each task states what it Consumes and Produces, the Properties its tests hold, and the
mutations that were measured to refute each property. Task 1 files it there.

- A task that changes the tree is ONE COMMIT, and the diff it prints is that commit's diff in the
  lab. The exceptions are stated where they occur: the harness's four files are one commit made by
  Task 2 to Task 27, and tasks that only run, review or report commit nothing.
- A step is a checkbox. "Tests first" steps print what the test printed in the lab on the tree
  BEFORE the change (`lab-s0t1plan/out2/red/`); "see it pass" steps print what it printed after.
- A mutation restores a rejected design with one edit. Every one was applied alone to the lab's
  tree and run against `messagegroup`, `sdk/urmessage` and the whole of `sdk/cp3b`. Appendix B
  prints each as a diff, with the command, so that none depends on the lab surviving.

## Test commands

`./test.sh` is the whole run. `urnetwork/message` has no CI service (its header says so); the
owner's fork runs `fork-ci.yml` on request. A phase's pull request is green when `./test.sh`
prints, on `alt-2` and on Windows, the verdict R8 allows that host (as R15 words it: narrowed by
exactly what `test.sh` names for that host, and by nothing else), and when the fork's
`fork-ci.yml` has run ALL FOUR LEGS on the branch head; the pull request cites that run. The fourth leg is the provenance leg in
R11's form: the recorded tip of the import's proof is an ancestor, and the proof passes at that
tip. What `test.sh` runs per module, by the wiring `scripts/module-census.sh` gives each:

```bash
export GOWORK=off
export GOTOOLCHAIN=$(bash scripts/toolchain.sh)                 # the pin, read off go.mod: go1.27.2 since 0bb2128f (go1.26.5 in the lab)
go mod verify && go mod tidy -diff && go build ./... && go vet ./...
URMESSAGE_REQUIRE_CORE_SDK_ROOT=1 URMESSAGE_REQUIRE_CONNECT_ROOT=1 \
  go test -count=1 -race -timeout 3h ./...                      # root: mls messagegroup message protocol syntax internal
go -C sdk           test -count=1 -race -timeout 3h ./...       # sdk, sdk/urmessage
go -C sdk/cp3b      test -count=1 -race -timeout 3h ./...       # the two-party suite, and the harness
go -C sdk/livepeer  test -count=1 -race -timeout 3h ./...
go -C sdk/liveprobe test -count=1 -race -timeout 3h ./...
go -C protocol/testdata/wiregolden test -count=1 -tags orig .   # the wire corpus builds under exactly one of two tags;
go -C protocol/testdata/wiregolden test -count=1 -tags new .    # with no tag it does not compile
bash sdk/cgo/compose.sh && go -C sdk/cgo test -count=1 -race -timeout 3h ./... ; bash sdk/cgo/compose.sh --clean
```

- **`-race` needs a C compiler.** `test.sh` adds it only when one is present; without one the go
  command answers "-race requires cgo". The lab's host has none, so every lab run below is without
  the race detector. R8 puts that leg on `alt-2`, at each phase close.
- **`sdk/cgo` is a composed module.** Its package main is the core SDK's, laid beside this
  repository's half by `compose.sh`; uncomposed, or with no C compiler, it has no Go file to test.
  It was not run in the lab.
- **The compiler.** Every lab run below is under go1.26.5, the pin at the lab's base. The pin is
  go1.27.2 since `0bb2128f`, and the second check ran every phase end again under it with the same
  counts. A phase's own runs are under the pin of the day, and the numbers a phase reports are
  those runs' numbers.
- **Since urnetwork/message#3 and #4**, `test.sh` builds `protoc-gen-go` under the pin, into a
  cache named for the pin, and refuses one built under another toolchain; and on a host with no C
  compiler it skips the native library, the composed package and the loopback library by name,
  and the census then fails the run for what was not built.
- `test.sh` also runs `gofmt`, the platform builds, 60 s of each `syntax` fuzz target, the protoc
  regeneration check, the module census, and (only with `MESSAGE_TEST_VULNCHECK=1`, from
  Task 29 on) the vulnerability scan. No task here changes a `go.mod`, a `.proto` file or an exported C
  symbol.

The harness has two modes:

```bash
go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./...                  # normal: a known gap passes
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./...  # strict: every open gap FAILS (the RED report)
```

## What was verified, how, and what was assumed

**Verified by running, in the lab.** The lab is `git archive 4d365abfdb1a` of the read-only checkout,
committed as the first commit of a git repository (`lab-s0t1plan/base/w`), with `connect`, `sdk`,
`message-server`, `glog`, `gvisor` and `goidenticons` exported beside it at the commits
`scripts/siblings.txt` pins, built with `GOWORK=off GOTOOLCHAIN=go1.26.5 GOPROXY=off
GOFLAGS=-mod=readonly`. Nothing was built or edited in the shared checkout. EVERYTHING BELOW WAS
RUN AGAIN FOR THIS REVISION, on the revised chain: no result of the chain as it stood at the final
check is quoted for a commit that changed.

- **One commit per task that changes the tree**, 21 in all. Each was checked out into a
  fresh worktree and gofmt, build, vet, the layering gate, `messagegroup`, the whole of `sdk` and of
  `sdk/cp3b`, the two probes' own tests and the harness in strict mode were run on it; the whole
  root module with `mls` was run on five of them (the base, the end of S0, the end of T1a, the
  capability commit and the last code commit). "Measured results" is that run.
- **The revision was made as commits, not as a patch on the end.** The held-group commit and the
  two-phase-join commit were changed in place, one commit was added at the end of T1a, and the
  twelve T1 commits were applied again behind them, with no conflict. One of the twelve was then
  changed as well: the first run of the revised chain found the every-octet case of Task 48
  failing against R13's new sentence, on that commit and the five after it, and it was fixed in
  the commit that owns it. Every commit builds and passes; the table shows each.
- **The revised chain applied to `main` as it stood on 2026-10-09** (`a0d47bef42c1`): the 21 commits of the lab's chain were applied to today's `main` for this revision (`git am --keep-cr`, no `--3way`): 21 of 21 apply with no conflict, and one hunk sits at an offset, in `test.sh`, because the import's last commits changed that file too. The three phase ends were then run again on the applied trees, with the same runner: every number equals the lab's. **On `0bb2128f` (2026-10-12)** the second check found 20 of the 21 applying strictly and the scan's commit needing `--3way` on one hunk of `test.sh`; the Base row says what that changes.
- **Tests first, measured.** For every task with a test, the test files of its commit were laid
  over the tree of the commit before and run; what each task prints under "see them fail" is that
  output (`lab-s0t1plan/out2/red/`, `v2/red_first.py`). Two tasks are measured their own way and
  say so: the family-16 shim, and the open item.
- **83 mutants**, each restoring a rejected design with one edit, each applied alone in a
  fresh worktree and each killed by the test its task names: 8 of the harness's own
  instruments, 35 for T1a (run on the T1a tree and again on the T1 tree) and 40 for
  T1.
- **Every `ADVSIM` line quoted** was printed by the commit it is quoted for. Two batch runs back
  the scenarios' own mutations: every registry line set to disagree with its scenario
  (`out2/registry-disagree-*.txt`), and each closing commit run with the registry of the commit
  before (`out2/registry-closing-*.txt`).
- **The vulnerability scan** was run once, on the base tree, with the network
  (`out2/vulncheck-base.txt`). It is the finding R6 rules on.
- **This document was run through `message-server`'s plan linter** in an export of that repository
  at its pin; Task 1 prints the result.
- **No result is older than its commit.** The revision changed commits in place, so a file of
  results can outlive the commit it measured. The script that wrote this file holds every
  measured output it reads, 331 files, to the commit time of the tree it was run on, and
  writes no plan otherwise. A trial run of it found one: the reading of the chain on `main` was
  older than two commits that were changed after it. That reading was taken again.
- **Every code block is cut from a commit** by the script that wrote this file
  (`lab-s0t1plan/gen2/main.py`): a new Go file whole, anything else as that commit's diff. The
  harness's scenario file is cut into consecutive pieces that are asserted to concatenate to it.

**Not run.**

- `./test.sh` itself, the race detector, `sdk/cgo` and the composed native library, the platform
  builds, the fuzz and protoc legs. The lab's host has no C compiler. R8 puts all of it on `alt-2`
  and on Windows at each phase close.
- Anything under go1.27.2, in the lab: every number here is under go1.26.5, the pin at the lab's
  base. The second check (2026-10-12) ran the phase ends, the new mutants and `./test.sh` on
  `alt-2` under go1.27.2 on `0bb2128f`, and every count equals these.
- The fork's `fork-ci.yml`, in the lab. The provenance leg in R11's form exists since the pins
  switch, and the second check ran its step on the T1 tree: it passes.
- The live probe, and anything against the alpha server. No VPS access was used.
- The scan over the native library (no C compiler), and over any tree but the base.
- `message-windows`. Its part is two tasks for its own writer.

**Read, not run.** `message-server`'s edit-log gate (it needs that repository's git history);
`TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario` against an empty registry; and the three
questions the final check left for the pre-merge review (Task 57, step 6, (a) to (c)).

**Assumed, and what is no longer assumed.**

- It WAS assumed that the import pull request would merge without changing a file this plan
  touches. That is now a fact with ONE EXCEPTION: `main` moved 13 files past the lab's base, and
  one of them, `test.sh`, is a file Task 29 changes. The only effect is the one-line offset
  above. If `main` differs again when a phase is cut, re-run Task 27 first. `main` did move again,
  by urnetwork/message#3 and #4: the Base row says what applies.
- That the pins switch and the toolchain move land as R6 orders them: THEY HAVE (`cc5efcc2`,
  `0bb2128f`), and the second check built and ran the chain against them.
- That the server's reset and the client directories are handled as Task 55 lists. The code no
  longer assumes it: a group from before T1 is refused by name.
- The testing design's owner questions are not answered yet; S0 depends on none of them.

## Rules for every task

- A task that changes the tree is one commit, on a branch CUT FROM `urnetwork/message` `main` and
  pushed to the owner's fork; one pull request per phase to `main`; merge commits only; never
  force-push (`README.md`, Contributing). When `main` moves, merge `main` into the branch (R6).
- A registry edit goes in the same commit as the change that moves the gap. The harness enforces
  it: a scenario whose gap closed while its entry still says `open` FAILS and names the edit.
- Tests first. For a scenario, "failing" means its strict-mode line is RED for the stated reason.
- One writer per repository. This plan's implementer writes `urnetwork/message`. Three tasks are
  the `message-server` writer's (R7) and two the `message-windows` writer's; none of them starts a
  second writer in a repository that has one.
- NO TASK ADDS A ROW TO THE IMPORT'S MANIFEST (`docs/history/adaptations.tsv`) OR CHANGES A FILE
  UNDER `docs/history` (R11). The import's proof is held at its recorded tip, not at this plan's.
- No task changes a `go.mod`, a pin line of `scripts/siblings.txt` or `mls/pins_test.go`. The
  toolchain move is R6's own change.
- A phase's numbers are measured on the phase's branch, on the day, under the compiler of the
  day. The lab's numbers are evidence for the design, and are not what a report quotes.
- No secret is printed, logged or committed. The probe's three credentials are read from paths.
- READ `LEAD-RULINGS-2026-10-09.md` AND `LEAD-RULINGS-2026-10-12.md` BEFORE YOU START A TASK, AND
  AGAIN BEFORE YOU FINISH.

---

# Phase S0: the harness, RED on today's code

### Task 1: File this plan in `message-server`, with its ledger entry (message-server writer)

- Consumes: this document; the hardening program plan in `message-server/docs/plans` and its gates 1, 3 and 4
- Produces: the plan at `docs/plans/2026-10-09-hardening-harness-and-join-seal.md`, and a SPEC-LEDGER entry, made by its section 6 change process, that records the rulings it rests on

**Why this is a task.** The program's first gate is that a track's plan is written in
`message-server/docs/plans`, in that repository's plan shape, reviewed, and landed with a ledger
entry BEFORE any code of the track is written; its third is that every plan change carries a
ledger entry in the same commit, which `editlog_test.go` holds. This repository holds no plans.

**Whose it is, and how it lands (R7).** The message-server writer's: ITS OWN SMALL PULL REQUEST to
urnetwork/message-server, paired with phase S0, and the owner is told to merge it first. The same
writer does Task 32 and Task 41, and the ledger entries the three phase closes ask for. The writer starts
after urnetwork/message-server#3 has merged, which it did on 2026-10-09.

- [ ] **Step 1: the file name.** `docs/plans/2026-10-09-hardening-harness-and-join-seal.md`. The
  program's naming rule forbids a `-s<n>-`, `-p<n>-` or `-m<n>-` segment, because the linter reads
  one out of a file name as the plan's token; this name has none.
- [ ] **Step 2: run the linter over it.**

```bash
go test -count=1 -run TestThePlanLinter -v ./ 2>&1 | grep -E 'hardening-harness|reference\(s\) read|^(--- |ok|FAIL)'
```

  Measured in the lab, with this file copied into an export of `message-server` at the commit
  `scripts/siblings.txt` pins: `ok`. With this file in place the linter's own counts move by what it reads here: properties 302 to 371; tasks that supply a Go test, each with a stated mutation 189 to 227; task references 2646 to 3274; open-item references 944 to 955; plan-token references 2213 to 2220; ledger citations 257 to 263; Consumes entries 261 to 320. No check, fatal or reporting, prints a finding against this file. (`lab-s0t1plan/out2/planlint-with-plan.txt`.)

  **On the day.** Measured in `message-server` at `83d746b529c1`, the commit this file is filed on, under go1.27.2: `ok`, and all seven of the linter's tests pass. With this file in place the linter's own counts move by what it reads here: properties 302 to 371; tasks that supply a Go test, each with a stated mutation 189 to 227; task references 2646 to 3304; open-item references 944 to 955; plan-token references 2213 to 2220; ledger citations 257 to 263; Consumes entries 261 to 320. No check, fatal or reporting, prints a finding against this file.
- [ ] **Step 3: the ledger entry**, in the same commit, by SPEC-LEDGER's section 6 change process:
  a dated entry in its section 7 edit log, and an item where one is owed. It records, as rulings
  and with their dates:
  - the owner's directive of 2026-10-05 and steer ("goal is to keep it simple and similar to
    matrix"), and the owner's statement of 2026-10-09 that the alpha server is disposable while in
    development, so that the reset variant is the only variant;
  - the lead's rulings of 2026-10-09: the `GroupEngine` interface gains a sixth method in T1a and
    three `messagegroup` gates are amended for it; the staging store lives in `sdk/urmessage` and
    not in `messagegroup`; the capability is unconditional; the sealed digest is kept; the code
    points `0x03` (target JOINER), `0x04` (payload JOIN_SECRETS_V1), `0xF004` (the capability) and
    `0x0041` (HMAC-SHA-256) stand; the vulnerability scan is an opt-in step of `test.sh`;
  - the lead's rulings R6 to R14 of 2026-10-09 (`LEAD-RULINGS-2026-10-09.md`), each by its id:
    the order of merges and the toolchain move to go1.27.2 (R6); the one message-server writer
    (R7); the full run and its four legs at each phase close (R8), the fourth being the
    provenance leg held at a recorded tip (R11); the two confirmed choices (R9); the re-added
    device's defect, filed as an open item and not fixed (R10, R14); one group record that does
    not read must not wedge the device (R12); and the app's half of a refusal ships with the
    refusal (R13);
  - the lead's rulings R15 to R18 of 2026-10-12 (`LEAD-RULINGS-2026-10-12.md`), each by its id:
    the verdict each host's full run must print (R15, R8 as worded since); the scan's tool,
    `govulncheck` v1.9.0 (R16); the text brought up to urnetwork/message#3 and #4 (R17); and the
    order of execution (R18); with the second check of the revised plan they answer
    (`_revcheck2_report.md`), and where each of its findings went: "Review dispositions";
  - the two independent checks of this plan those rulings answer (`_finalcheck_fidelity.md`,
    `_finalcheck_grounding.md`), and where each of their findings went: "Review dispositions";
  - what this plan adds to the design and why: "Where the design and the moved code disagree",
    below, item by item;
  - the round-1 red team record of the join seal design, and that its round 2 was NOT run: its
    prompts 3 to 7 are Task 57 of this plan;
  - the lab's measured runs, by the commands this plan prints.
- [ ] **Step 4: a subagent diff review** of that commit, as the program's gate 1 asks, then commit.

No task of this repository starts before that commit is on `message-server`'s main.

### Task 2: The registry and the verdict rules

- Consumes: `sdk/cp3b`'s existing world (`world_test.go`); nothing of this plan
- Produces: `advJudge`, `advVerdict`, `advHarness`, the registry file `known-gaps.json`, `TestAdvSimVerdictRules` and `TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario`

**Behaviour.** Every scenario hands what its adversary observed to one function, which judges
it against a registry entry. An `open` entry passes only while the adversary observes exactly what
the entry says; if it observes the goal instead, the test FAILS and names the registry edit;
anything else FAILS as "moved". `closed`, `control` and `residual` entries must match exactly. With
`ADVSIM_STRICT=1` an open entry FAILS: that run is the RED report.

The harness lives in `sdk/cp3b`, beside the two-party suite, because that module already runs real
devices against the real server in process. Its layering row forbids `syntax` and `x/crypto`, so
the adversary reads the invitation and the key package by offsets written from their grammar,
which is also what the testing design asks of its oracle: it shares no decoder with the code under
test.

**Property 1.** The verdict function passes an open entry only while the adversary observes exactly what the entry records, fails it when the adversary observes the goal, and fails it in strict mode; a closed, control or residual entry passes only on an exact match.

**Property 2.** Every registry entry is judged by exactly one scenario, and an empty registry is refused.

- [ ] **Step 1: the registry file.** Create `sdk/cp3b/testdata/advsim/known-gaps.json`. It starts empty, and each scenario task adds its one line:

```json
{
  "format": "advsim-known-gaps/1",
  "entries": [
  ]
}
```

- [ ] **Step 2: the rules and their own test.**

`sdk/cp3b/advsim_registry_test.go` (new file, 213 lines):

```go
package cp3b

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// THE ADVERSARY SIMULATION'S REGISTRY: what each scenario is EXPECTED to observe, written down
// before the scenario runs.
//
// A scenario drives an adversary over the real server and the real client, collects what the
// adversary got (its OBSERVATION, a sorted set of short facts such as "epoch:1"), and hands it to
// [advJudge]. The registry entry for that scenario says what the observation must be:
//
//   - "open": a known gap. The entry's `expect` is the gap's exact shape today and `goal` is what
//     the observation must become. It PASSES, as a known gap, only while the observation equals
//     `expect` exactly. An observation equal to `goal` FAILS with the instruction to flip the
//     entry in the commit that closed the gap; any other observation FAILS as a gap that moved.
//     So a gap cannot close, widen or change shape without an edit to this file.
//   - "closed", "control" and "residual": the observation must equal `expect` exactly. The three
//     differ only in what they say: a closed gap, a control that proves the harness can see, and
//     a breach that is documented and deliberately not closed.
//
// ADVSIM_STRICT=1 fails every open entry. That run is the RED report: it lists each gap that is
// still open with what the adversary got.
const (
	advRegistryFormat = "advsim-known-gaps/1"
	advRegistryPath   = "testdata/advsim/known-gaps.json"
)

type advEntry struct {
	Id       string   `json:"id"`
	State    string   `json:"state"`
	Expect   []string `json:"expect"`
	Goal     []string `json:"goal"`
	ClosedBy string   `json:"closed_by"`
	Reads    string   `json:"reads"`
}

type advRegistryFile struct {
	Format  string     `json:"format"`
	Entries []advEntry `json:"entries"`
}

func advLoadRegistry(t *testing.T) map[string]advEntry {
	t.Helper()
	body, err := os.ReadFile(filepath.FromSlash(advRegistryPath))
	if err != nil {
		t.Fatalf("FAIL(HARNESS): the registry %s could not be read: %v", advRegistryPath, err)
	}
	file := advRegistryFile{}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatalf("FAIL(HARNESS): the registry %s does not decode: %v", advRegistryPath, err)
	}
	if file.Format != advRegistryFormat {
		t.Fatalf("FAIL(HARNESS): the registry names format %q, want %q", file.Format, advRegistryFormat)
	}
	entries := map[string]advEntry{}
	for _, entry := range file.Entries {
		if _, twice := entries[entry.Id]; twice {
			t.Fatalf("FAIL(HARNESS): the registry names %q twice", entry.Id)
		}
		entries[entry.Id] = entry
	}
	if len(entries) == 0 {
		t.Fatalf("FAIL(HARNESS): the registry holds no entry, so every scenario would be judged against nothing")
	}
	return entries
}

// advSet is an observation in its one canonical form: sorted, without repeats, never nil.
func advSet(facts []string) []string {
	set := append([]string{}, facts...)
	slices.Sort(set)
	return slices.Compact(set)
}

// advVerdict is the whole of the rule, as a function of its three inputs and nothing else, so that
// [TestAdvSimVerdictRules] can drive every arm of it without a scenario.
func advVerdict(entry advEntry, observed []string, strict bool) (bool, string) {
	observed = advSet(observed)
	expect := advSet(entry.Expect)
	goal := advSet(entry.Goal)
	switch entry.State {
	case "closed", "control", "residual":
		if slices.Equal(observed, expect) {
			return true, strings.ToUpper(entry.State)
		}
		return false, fmt.Sprintf("FAIL (%s): observed %v, and this entry holds exactly %v", entry.State, observed, expect)
	case "open":
		switch {
		case slices.Equal(observed, expect) && strict:
			return false, fmt.Sprintf("RED: the gap is open, closed by %s: the adversary observed %v, and the goal is %v", entry.ClosedBy, observed, goal)
		case slices.Equal(observed, expect):
			return true, fmt.Sprintf("KNOWN GAP (closed by %s)", entry.ClosedBy)
		case slices.Equal(observed, goal):
			return false, fmt.Sprintf("FAIL: the gap has CLOSED: observed %v is the goal. Set this entry's state to \"closed\" and its expect to %v in the commit that closed it", observed, goal)
		default:
			return false, fmt.Sprintf("FAIL: the gap MOVED: observed %v, the registry models %v and the goal is %v. This is a regression, or a registry edit that needs a ledger entry", observed, expect, goal)
		}
	}
	return false, fmt.Sprintf("FAIL(HARNESS): state %q is not one of open, closed, control, residual", entry.State)
}

// advJudge holds one scenario's observation against its registry entry and prints the row.
func advJudge(t *testing.T, id string, observed []string) {
	t.Helper()
	entry, registered := advLoadRegistry(t)[id]
	if !registered {
		t.Fatalf("FAIL(HARNESS): scenario %q has no registry entry; every scenario's expected observation is written down first", id)
	}
	strict := os.Getenv("ADVSIM_STRICT") == "1"
	passed, verdict := advVerdict(entry, observed, strict)
	line := fmt.Sprintf("ADVSIM %-30s state=%-8s expect=%v observed=%v :: %s", id, entry.State, advSet(entry.Expect), advSet(observed), verdict)
	fmt.Println(line)
	if !passed {
		t.Fatalf("%s\n    the scenario: %s", line, entry.Reads)
	}
}

// advHarness fails a scenario whose own preconditions did not hold. It is a different verdict from
// a gap: a harness that could not set its scene up has measured nothing, in either direction.
func advHarness(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf("FAIL(HARNESS): "+format, args...)
}

func TestAdvSimVerdictRules(t *testing.T) {
	open := advEntry{Id: "x", State: "open", Expect: []string{"epoch:1"}, Goal: []string{}, ClosedBy: "T1"}
	closed := advEntry{Id: "y", State: "closed", Expect: []string{}}
	control := advEntry{Id: "z", State: "control", Expect: []string{"epoch:1"}}
	for _, one := range []struct {
		name     string
		entry    advEntry
		observed []string
		strict   bool
		pass     bool
		says     string
	}{
		{"an open gap observed exactly as modelled passes as a known gap", open, []string{"epoch:1"}, false, true, "KNOWN GAP"},
		{"the same gap is RED under ADVSIM_STRICT", open, []string{"epoch:1"}, true, false, "RED"},
		{"an open gap that reached its goal fails until the registry is flipped", open, nil, false, false, "CLOSED"},
		{"an open gap that reached its goal fails under strict too, and says the same", open, nil, true, false, "CLOSED"},
		{"an open gap wider than its model fails", open, []string{"epoch:1", "epoch:2"}, false, false, "MOVED"},
		{"an open gap of another shape fails", open, []string{"epoch:2"}, false, false, "MOVED"},
		{"a closed entry passes on its exact set", closed, nil, false, true, "CLOSED"},
		{"a closed entry fails on anything else", closed, []string{"epoch:1"}, false, false, "FAIL"},
		{"a control passes on its exact set", control, []string{"epoch:1"}, true, true, "CONTROL"},
		{"a control that saw nothing fails: the harness went blind", control, nil, false, false, "FAIL"},
		{"an unknown state fails", advEntry{State: "advisory"}, nil, false, false, "FAIL(HARNESS)"},
	} {
		passed, verdict := advVerdict(one.entry, one.observed, one.strict)
		if passed != one.pass || !strings.Contains(verdict, one.says) {
			t.Errorf("%s: passed=%v verdict=%q, want passed=%v and a verdict naming %q", one.name, passed, verdict, one.pass, one.says)
		}
	}
}

// Every entry is well formed, and every entry is named by exactly one scenario in this package.
//
// The second half is a census over the SOURCE of the advsim files: each registry id occurs exactly
// once as a quoted literal. An entry no scenario names is a property nothing measures, which reads
// as a closed gap; an id named twice is two scenarios whose verdicts one entry cannot both hold.
// The other direction, a scenario naming an id the registry lacks, is [advJudge]'s own refusal.
func TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario(t *testing.T) {
	entries := advLoadRegistry(t)
	sources, err := filepath.Glob("advsim_*_test.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no advsim source file was found (%v), so the census below read nothing", err)
	}
	text := ""
	for _, source := range sources {
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		text += string(body)
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		entry := entries[id]
		switch entry.State {
		case "open":
			if entry.ClosedBy == "" || entry.ClosedBy == "none" {
				t.Errorf("%s is open and names no track that closes it", id)
			}
			if slices.Equal(advSet(entry.Expect), advSet(entry.Goal)) {
				t.Errorf("%s is open and its model equals its goal, so it could never be told from a closed gap", id)
			}
		case "closed", "control", "residual":
		default:
			t.Errorf("%s has state %q", id, entry.State)
		}
		if entry.Reads == "" {
			t.Errorf("%s does not say what its adversary does", id)
		}
		if named := strings.Count(text, `"`+id+`"`); named != 1 {
			t.Errorf("%s is named %d times as a literal in %v, want exactly once", id, named, sources)
		}
	}
	t.Logf("%d registry entries, each named by exactly one scenario in %v", len(ids), sources)
}
```

- [ ] **Step 3: run it.**

```bash
go -C sdk/cp3b test -count=1 -run 'TestAdvSimVerdictRules' -v ./...
```

Measured on the harness commit: `--- PASS: TestAdvSimVerdictRules`. `TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario` refuses the empty registry by design ("the registry holds no entry, so every scenario would be judged against nothing"; read off the loader, not run in that state) and passes from the first scenario on.

- [ ] **Step 4: the mutations.** Each is one edit of the harness, applied alone to the S0 tree.

1. `HV1`: an open entry whose adversary observes the goal passes: a gap that closed stays recorded as open. Property 1 must fail. Measured: killed by `TestAdvSimVerdictRules`.
2. `HV2`: a closed entry passes whatever its adversary observes. Property 1 must fail. Measured: killed by `TestAdvSimVerdictRules`.
3. `HV3`: strict mode passes an open gap: the RED report is green. Property 1 must fail. Measured: killed by `TestAdvSimVerdictRules`.
4. `HV4`: the registry carries an entry no scenario judges. Property 2 must fail. Measured: killed by `TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 3: The adversary's tools: the paste channel, the quantum grant, the scrape, the read

- Consumes: `advHarness` (Task 2); `sdk/cp3b`'s `world`, `persona`, `copyAppData` and `wireTap`
- Produces: `advPaste`, `advShor`, `advShadow`, `advScrape`, `advScrapeHandleKey`, `advScrapePqSecret`, `advRead`, `advCanary`, `advInviteFields`, `advEncodeInvite`, `advKeyPackageInitKey`, `advGroupFiles`, `advRemoveEpochStates`, and `TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf`

**Behaviour.**

- `advPaste` is the out-of-band channel; everything carried over it is what a recorder keeps.
- `advShor` is the quantum grant. Rule: a quantum computer inverts a classical public key it
  holds, so the joiner's classical private keys are granted if and only if the join code's init
  key occurs in the captured octets. The X-Wing seed is withheld by overwriting it with random
  octets before anything reads the copy.
- `advScrape` slides a 32-octet window over what was captured and confirms a candidate by what
  only that secret does: a `pq_secret` reproduces the epoch digest the server holds, and a
  `group_handle_key` expands to a sender handle the server holds a row under.
- `advRead` opens the submitted records through the production opener and answers one
  `epoch:N` fact per canary it recovered. An adversary has read an epoch only if it produces a
  canary sealed there.

**Property 1.** Octets 5 to 37 of a join code are the X25519 public half of the init private key the joiner's store holds for it, so the grant looks for the key the Welcome is sealed to.

- [ ] **Step 1: the file.**

`sdk/cp3b/advsim_oracle_test.go` (new file, 472 lines):

```go
package cp3b

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
)

// THE ADVERSARY'S OWN TOOLS. Nothing in this file is the code under test's reading of its own
// formats: the invite and the key package are read here by offsets written from their grammar, so
// an adversary that finds a secret finds it in the OCTETS and not in a field the production
// decoder chose to hand over.

// ── the paste channel ────────────────────────────────────────────────────────────────────────

// advPaste is the out-of-band channel two people move a join code and an invitation over. Every
// artefact a scenario moves goes through carry, which is what a recorder on that channel keeps.
type advPaste struct {
	captured [][]byte
}

func (self *advPaste) carry(octets []byte) []byte {
	self.captured = append(self.captured, append([]byte(nil), octets...))
	return append([]byte(nil), octets...)
}

// haystack is everything the recorder kept, end to end: what a scrape reads.
func (self *advPaste) haystack() []byte {
	return bytes.Join(self.captured, nil)
}

// advCanary is a text no other source produces: "cnry-" and 32 hex digits.
func advCanary(t *testing.T) string {
	t.Helper()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("drawing a canary: %v", err)
	}
	return "cnry-" + hex.EncodeToString(random)
}

// ── the invite and the join code, read by their grammar ──────────────────────────────────────

// advInviteFields reads an encoded invite as what it is on the wire: a u16 version, fields each
// under a u32 length, and the SHA-256 of everything before it. It asserts the checksum, so a
// caller that re-encodes one knows the original was whole.
func advInviteFields(t *testing.T, encoded []byte) (uint16, [][]byte) {
	t.Helper()
	if len(encoded) < 2+sha256.Size {
		advHarness(t, "an invite of %d octets is shorter than a version and a checksum", len(encoded))
	}
	body := encoded[:len(encoded)-sha256.Size]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], encoded[len(encoded)-sha256.Size:]) {
		advHarness(t, "the invite's last 32 octets are not the SHA-256 of the octets before them")
	}
	version := binary.BigEndian.Uint16(body[:2])
	fields := [][]byte{}
	at := 2
	for at < len(body) {
		if len(body)-at < 4 {
			advHarness(t, "the invite ends inside a length prefix at octet %d", at)
		}
		length := int(binary.BigEndian.Uint32(body[at : at+4]))
		at += 4
		if len(body)-at < length {
			advHarness(t, "the invite's field at octet %d claims %d octets and %d remain", at, length, len(body)-at)
		}
		fields = append(fields, append([]byte(nil), body[at:at+length]...))
		at += length
	}
	return version, fields
}

// advEncodeInvite is the active attacker's tool: the same grammar written back, with the checksum
// recomputed. The checksum is not an authentication, and this is the function that shows it.
func advEncodeInvite(version uint16, fields [][]byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	for _, field := range fields {
		body = binary.BigEndian.AppendUint32(body, uint32(len(field)))
		body = append(body, field...)
	}
	sum := sha256.Sum256(body)
	return append(body, sum[:]...)
}

// advKeyPackageInitKey reads the HPKE init public key out of an encoded RFC 9420 KeyPackage:
// u16 version (mls10 = 1), u16 cipher suite (3), then init_key<V>, whose 32 octets stand under a
// one-octet variable-length prefix.
func advKeyPackageInitKey(t *testing.T, keyPackage []byte) []byte {
	t.Helper()
	if len(keyPackage) < 37 || keyPackage[0] != 0x00 || keyPackage[1] != 0x01 ||
		keyPackage[2] != 0x00 || keyPackage[3] != 0x03 || keyPackage[4] != 0x20 {
		advHarness(t, "these %d octets do not begin as an mls10 key package at suite 0x0003 with a 32 octet init key", len(keyPackage))
	}
	return append([]byte(nil), keyPackage[5:37]...)
}

// ── the Shor oracle ──────────────────────────────────────────────────────────────────────────

// advShadow is what a recorder with a quantum computer holds of one join: the MLS group state of
// the epoch the Welcome admitted the joiner at, rebuilt from the joiner's CLASSICAL private keys.
type advShadow struct {
	handle   messagegroup.GroupHandle
	exporter []byte
	epoch    uint64
	ownLeaf  uint32
}

// advShor is the grant rule and the grant.
//
// THE RULE: a quantum computer inverts a classical public key it HOLDS. The Welcome is sealed to
// the HPKE init key of one key package, and that key is published in the join code and nowhere
// else, so the oracle grants the joiner's classical private keys if and only if the init key
// occurs in the octets the recorder captured. An invitation alone grants nothing.
//
// THE GRANT: a copy of the joiner's state directory taken BEFORE the join, opened as a store, and
// the production engine joining the recorded Welcome over it. Every key that join uses is
// classical: the init key, the leaf's X25519 key and the Ed25519 signer.
//
// WHAT IS WITHHELD: the X-Wing seed. ML-KEM-768 is what the quantum computer does not break, so
// the seed in the copy is OVERWRITTEN with 32 random octets before anything else reads the store.
// A shadow that reached for the seed would open nothing with it.
func advShor(t *testing.T, captured [][]byte, joinCode []byte, preJoinStateDir string,
	welcome []byte, ratchetTree []byte) (*advShadow, bool) {

	t.Helper()
	initKey := advKeyPackageInitKey(t, joinCode)
	if !bytes.Contains(bytes.Join(captured, nil), initKey) {
		return nil, false
	}
	shadowDir := filepath.Join(t.TempDir(), "shadow")
	copyAppData(t, preJoinStateDir, shadowDir)
	store, err := urmessage.OpenDurableStateStore(shadowDir)
	if err != nil {
		advHarness(t, "the shadow's copy of the joiner's store does not open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	signerPub, signerPriv, leafKeys, seed, err := store.GetDeviceIdentity()
	if err != nil {
		advHarness(t, "the shadow's copy holds no device identity: %v", err)
	}
	if len(seed) != messagegroup.XwingSeedSize {
		advHarness(t, "the joiner's store holds a %d octet x-wing seed, so there was nothing to withhold", len(seed))
	}
	if _, err := rand.Read(seed); err != nil {
		advHarness(t, "drawing the replacement seed: %v", err)
	}
	if err := store.PutDeviceIdentity(signerPub, signerPriv, leafKeys, seed); err != nil {
		advHarness(t, "withholding the x-wing seed from the shadow: %v", err)
	}
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		advHarness(t, "the crypto provider: %v", err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(crypto, store, mls.SignaturePrivateKey(signerPriv),
		mls.BasicCredential(signerPub), leafKeys)
	if err != nil {
		advHarness(t, "the shadow's engine: %v", err)
	}
	handle, err := engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		advHarness(t, "the shadow holds the joiner's classical keys and the recorded Welcome did not open: %v", err)
	}
	exporter, err := handle.Export("URmessage/v1/storage", nil, 32)
	if err != nil {
		advHarness(t, "the shadow's exporter: %v", err)
	}
	return &advShadow{handle: handle, exporter: exporter, epoch: handle.Epoch(), ownLeaf: handle.OwnLeafIndex()}, true
}

// THE INIT KEY READER'S OWN CONTROL. The grant rule turns on thirty-two octets read by offset, so
// they are held against the one thing that cannot be argued with: the private half the store keeps
// for that key package, pushed through X25519 by the standard library.
func TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf(t *testing.T) {
	world := newWorld(t)
	bob := world.newPersona(t, "bob")
	joinCode, err := bob.device.KeyPackage()
	if err != nil {
		t.Fatalf("bob's KeyPackage: %v", err)
	}
	initKey := advKeyPackageInitKey(t, joinCode)
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("the crypto provider: %v", err)
	}
	ref, err := mls.MakeKeyPackageRef(crypto, joinCode)
	if err != nil {
		t.Fatalf("the key package's reference: %v", err)
	}
	// a copy, because the take is destructive and bob's own store must keep its key package
	copyDir := filepath.Join(t.TempDir(), "copy")
	copyAppData(t, bob.stateDir, copyDir)
	store, err := urmessage.OpenDurableStateStore(copyDir)
	if err != nil {
		t.Fatalf("opening the copy: %v", err)
	}
	defer store.Close()
	_, initPrivate, _, err := store.TakeKeyPackage(ref)
	if err != nil {
		t.Fatalf("the copy holds no key package under the join code's reference: %v", err)
	}
	private, err := ecdh.X25519().NewPrivateKey(initPrivate)
	if err != nil {
		t.Fatalf("the stored init private key is not an X25519 scalar: %v", err)
	}
	if !bytes.Equal(private.PublicKey().Bytes(), initKey) {
		t.Fatalf("octets 5..37 of the join code are %x, and the init private key the store holds has public half %x",
			initKey, private.PublicKey().Bytes())
	}
	// and the two places the grant rule reads: in the join code, never in an invitation built from it
	if !bytes.Contains(joinCode, initKey) {
		t.Fatal("the init key is not in the join code it was read from")
	}
}

// ── what the server holds ────────────────────────────────────────────────────────────────────

// advPublishedDigest is H(epoch_keys) of the commit that opened one epoch, read off the server's
// own rows: the value every reader of the group is served, and the one a candidate secret is
// confirmed against.
func advPublishedDigest(t *testing.T, world *world, groupId []byte, epoch uint64) []byte {
	t.Helper()
	for _, row := range world.allRows(t, groupId) {
		if !row.IsCommit || len(row.ServerAttachment) == 0 {
			continue
		}
		attachment, err := message.ParseServerAttachment(row.ServerAttachment)
		if err != nil || attachment.Kind != message.AttachmentEpochDigest || attachment.EpochDigest == nil {
			continue
		}
		if attachment.EpochDigest.Epoch == epoch {
			return append([]byte(nil), attachment.EpochDigest.EpochKeysDigest...)
		}
	}
	advHarness(t, "the server holds no commit whose kind 0x0005 attachment opens epoch %d, so no candidate secret can be confirmed", epoch)
	return nil
}

// advServerHandles is every sender_handle the server holds a row under.
func advServerHandles(t *testing.T, world *world, groupId []byte) map[[16]byte]bool {
	t.Helper()
	handles := map[[16]byte]bool{}
	for _, row := range world.allRows(t, groupId) {
		if len(row.SenderHandle) == 16 {
			handles[[16]byte(row.SenderHandle)] = true
		}
	}
	if len(handles) == 0 {
		advHarness(t, "the server holds no sender_handle for this group, so no handle key can be confirmed")
	}
	return handles
}

// ── the scrape ───────────────────────────────────────────────────────────────────────────────

type advScraped struct {
	pqSecret       []byte
	pqAt           int
	groupHandleKey []byte
	ghkAt          int
}

// advScrapeHandleKey slides a 32 octet window over the haystack and confirms a group_handle_key
// by what only that key does: it expands to a sender_handle the server holds a row under. It needs
// no MLS secret, which is why a classical observer can run it.
func advScrapeHandleKey(t *testing.T, world *world, groupId []byte, haystack []byte) ([]byte, int) {
	t.Helper()
	handles := advServerHandles(t, world, groupId)
	for at := 0; at+32 <= len(haystack); at += 1 {
		window := haystack[at : at+32]
		for leaf := uint32(0); leaf < 16; leaf += 1 {
			if handles[messagegroup.SenderHandle(window, leaf)] {
				return append([]byte(nil), window...), at
			}
		}
	}
	return nil, -1
}

// advScrapePqSecret slides the same window and confirms a pq_secret against the epoch's published
// digest: storage_root = Extract(exporter, window), the two server keys off that root, and
// H(epoch_keys) over them. A hit is the adversary holding storage_root of that epoch.
func advScrapePqSecret(t *testing.T, world *world, groupId []byte, shadow *advShadow, haystack []byte) ([]byte, int) {
	t.Helper()
	published := advPublishedDigest(t, world, groupId, shadow.epoch)
	group := [32]byte(groupId)
	for at := 0; at+32 <= len(haystack); at += 1 {
		window := haystack[at : at+32]
		root := messagegroup.StorageRoot(shadow.exporter, window)
		digest, err := message.EpochKeysDigest(group, shadow.epoch, message.WriteKey(root), message.ReadKey(root))
		if err != nil {
			advHarness(t, "H(epoch_keys) over a candidate: %v", err)
		}
		if bytes.Equal(digest, published) {
			return append([]byte(nil), window...), at
		}
	}
	return nil, -1
}

// advScrape runs both, and says where each was found.
func advScrape(t *testing.T, world *world, groupId []byte, shadow *advShadow, haystack []byte) advScraped {
	t.Helper()
	scraped := advScraped{pqAt: -1, ghkAt: -1}
	scraped.pqSecret, scraped.pqAt = advScrapePqSecret(t, world, groupId, shadow, haystack)
	scraped.groupHandleKey, scraped.ghkAt = advScrapeHandleKey(t, world, groupId, haystack)
	t.Logf("scraped %d octets (%d windows): pq_secret at %d, group_handle_key at %d",
		len(haystack), max(len(haystack)-31, 0), scraped.pqAt, scraped.ghkAt)
	return scraped
}

// ── reading ──────────────────────────────────────────────────────────────────────────────────

// advRead opens the group's application records of the shadow's epoch through the PRODUCTION
// opener, with the two secrets the adversary recovered, and answers one "epoch:N" fact per canary
// it recovered. An adversary has read an epoch if and only if it produces a canary sealed there.
//
// The records are the ones the clients submitted, off the wire tap: the octets a recorder of the
// server's rows holds. The shadow stands at the joiner's leaf, and a member cannot open its own
// frames, so the joiner's own records are skipped; the founder's are what it reads.
func advRead(t *testing.T, world *world, shadow *advShadow, pqSecret []byte, groupHandleKey []byte,
	canaries map[string]uint64) []string {

	t.Helper()
	if world.wire == nil {
		advHarness(t, "this world records no wire, so there is no submitted record to open")
	}
	streamStore, err := sdk.OpenStreamStore(t.TempDir())
	if err != nil {
		advHarness(t, "the shadow's stream store: %v", err)
	}
	t.Cleanup(func() { streamStore.Close() })
	session, err := messagegroup.NewGroupSession(shadow.handle, pqSecret, groupHandleKey,
		sdk.NewStreamIndexReserver(streamStore), func() int64 { return time.Now().UnixMilli() },
		[]byte("the shadow never writes, so this nonce authenticates nothing"))
	if err != nil {
		advHarness(t, "the shadow's session over the recovered secrets: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	own := messagegroup.SenderHandle(groupHandleKey, shadow.ownLeaf)
	tracked := map[string]bool{}
	read := []string{}
	opened, refused := 0, 0
	for _, octets := range advSubmittedRecords(world.wire) {
		parsed, err := message.ParseRecord(octets)
		if err != nil {
			continue
		}
		header := &parsed.Header
		if header.Epoch != shadow.epoch || header.IsCommit || len(header.ServerAttachment) != 0 {
			continue
		}
		if header.SenderHandle == own {
			continue
		}
		leaf, found := uint32(0), false
		for candidate := uint32(0); candidate < 16; candidate += 1 {
			if messagegroup.SenderHandle(groupHandleKey, candidate) == header.SenderHandle {
				leaf, found = candidate, true
				break
			}
		}
		if !found {
			continue
		}
		ladder := fmt.Sprintf("%d/%d/%d/%d", leaf, header.RetentionClass, header.EphBucket, header.EphWindow)
		if !tracked[ladder] {
			if err := session.TrackSender(leaf, header.RetentionClass, header.EphBucket, header.EphWindow, 0); err != nil {
				advHarness(t, "tracking leaf %d: %v", leaf, err)
			}
			tracked[ladder] = true
		}
		_, body, err := session.OpenRecord(parsed)
		if err != nil {
			refused += 1
			continue
		}
		opened += 1
		for canary, epoch := range canaries {
			if bytes.Contains(body, []byte(canary)) {
				read = append(read, fmt.Sprintf("epoch:%d", epoch))
			}
		}
	}
	t.Logf("the shadow opened %d application record(s) of epoch %d and was refused %d", opened, shadow.epoch, refused)
	return advSet(read)
}

// advSubmittedRecords is the octets of every record a client submitted through the tap, in order.
func advSubmittedRecords(tap *wireTap) [][]byte {
	tap.mutex.Lock()
	defer tap.mutex.Unlock()
	records := [][]byte{}
	for _, request := range tap.submits {
		for _, record := range request.GetRecords() {
			records = append(records, append([]byte(nil), record.GetRecordBytes()...))
		}
	}
	return records
}

// ── what a device holds of one group, as files ───────────────────────────────────────────────

// advGroupFiles is every file a durable store holds for one group, by its path under the group's
// directory. The directory is named by the SHA-256 of the group id, which is all this reads of the
// store's layout.
func advGroupFiles(t *testing.T, stateDir string, groupId []byte) map[string][]byte {
	t.Helper()
	sum := sha256.Sum256(groupId)
	name := hex.EncodeToString(sum[:])
	files := map[string][]byte{}
	err := filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(stateDir, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		marker := "/" + name + "/"
		at := bytes.Index([]byte(relative), []byte(marker))
		if at < 0 {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[relative[at+len(marker):]] = content
		return nil
	})
	if err != nil {
		advHarness(t, "reading the group's files under %s: %v", stateDir, err)
	}
	return files
}

// advRemoveEpochStates removes every epoch state a durable store holds for one group, and leaves
// its record: what "the group's MLS state did not survive" is on the disk.
func advRemoveEpochStates(stateDir string, groupId []byte) error {
	sum := sha256.Sum256(groupId)
	marker := "/" + hex.EncodeToString(sum[:]) + "/epoch/"
	return filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if bytes.Contains([]byte(filepath.ToSlash(path)), []byte(marker)) {
			return os.Remove(path)
		}
		return nil
	})
}
```

- [ ] **Step 2: run its control.** The init-key reader is held against the private half the store keeps:

```bash
go -C sdk/cp3b test -count=1 -run 'TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf' -v ./...
```

Measured on the harness commit: `--- PASS`.

- [ ] **Step 3: the mutations.** One edit of the harness, applied alone to the S0 tree.

1. `HV5`: the grant reads the init key one octet off: the octets it looks for are not the key the Welcome is sealed to. Property 1 must fail. Measured: killed by `TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf`.

- [ ] **Step 4: no commit yet.** The harness is one commit, made in Task 27.

### Task 4: The scene: one founding join, with everything a recorder kept

- Consumes: the tools (Task 3) and `advJudge` (Task 2); `sdk/cp3b`'s `newWorld`, `openPair`, `gcReceiveText`
- Produces: `advJoin`, `advFounding`, `advSettle`, `advHarvest`, and the head of `advsim_join_test.go`

**Behaviour.** `advFounding` founds a group, adds a second member over the paste channel and
opens it; with `join` set, the joiner reads a canary the founder sealed and answers with its own,
so each honest member has read what the adversary is about to be measured against. A scenario that
cannot establish that calls `advHarness`, which FAILS as a harness fault and never as a verdict.
`advHarvest` is the recorder's whole attack: the grant, the scrape and the read. Half a recovery
(the storage root without the handle key) is reported as `storage-root:N`, never as nothing.

This task states no property and supplies no test of its own: every scenario below is a test of
these helpers, and a helper that cannot establish its scene fails the scenario as a harness fault.

- [ ] **Step 1: the head of the file.** Create `sdk/cp3b/advsim_join_test.go` with this head. THE IMPORT BLOCK SHOWN IS THE FINISHED FILE'S: the head itself uses `bytes`, `context`, `fmt`, `path/filepath`, `testing`, `github.com/urnetwork/message/sdk/urmessage`, and each scenario task below names the import it is the first to use. The file compiles once the last scenario is in; to run one scenario earlier, keep only the imports used so far.

```go
package cp3b

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/sdk/urmessage"
)

// THE JOIN PATH UNDER ITS ADVERSARIES. Every scenario here drives real devices against the real
// server, lets an adversary do what its definition allows, and hands what it got to [advJudge].

// advJoin is one founding join, with everything a recorder on its paste channel kept.
type advJoin struct {
	world   *world
	ctx     context.Context
	paste   *advPaste
	groupId []byte

	alice      *persona
	bob        *persona
	aliceGroup *urmessage.Group
	bobGroup   *urmessage.Group

	// the two artefacts as they crossed the paste channel
	joinCode []byte
	invite   []byte
	// a copy of bob's state directory taken after he minted the join code and before he joined
	bobBeforeJoin string
	// every canary sealed so far, with the epoch it was sealed at
	canaries map[string]uint64
}

// advFounding founds a group on alice, adds bob through the paste channel and opens it. With
// join set, bob joins, reads a canary alice sealed in the join epoch and answers with his own, so
// that the epoch holds a canary from each honest member and each was read by the other.
func advFounding(t *testing.T, join bool) *advJoin {
	t.Helper()
	world := newWorldWith(t, worldOptions{recordWire: true})
	ctx := context.Background()
	scene := &advJoin{world: world, ctx: ctx, paste: &advPaste{}, groupId: newGroupId(t), canaries: map[string]uint64{}}
	scene.alice = world.newPersona(t, "alice")
	scene.bob = world.newPersona(t, "bob")
	for _, who := range []*persona{scene.alice, scene.bob} {
		if err := who.device.Connect(ctx); err != nil {
			advHarness(t, "%s's Connect: %v", who.name, err)
		}
	}
	aliceGroup, err := scene.alice.device.CreateGroup(ctx, scene.groupId)
	if err != nil {
		advHarness(t, "alice's CreateGroup: %v", err)
	}
	scene.aliceGroup = aliceGroup
	joinCode, err := scene.bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's KeyPackage: %v", err)
	}
	scene.joinCode = scene.paste.carry(joinCode)
	scene.bobBeforeJoin = filepath.Join(t.TempDir(), "bob-before-the-join")
	copyAppData(t, scene.bob.stateDir, scene.bobBeforeJoin)
	invite, err := aliceGroup.AddMember(scene.joinCode)
	if err != nil {
		advHarness(t, "alice's AddMember: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	scene.invite = scene.paste.carry(encoded)
	if err := aliceGroup.Open(ctx); err != nil {
		advHarness(t, "alice's Open: %v", err)
	}
	scene.say(t, "alice", aliceGroup)
	if !join {
		return scene
	}
	carried, err := urmessage.ParseInvite(scene.invite)
	if err != nil {
		advHarness(t, "parsing the honest invite: %v", err)
	}
	bobGroup, err := scene.bob.device.Join(ctx, carried)
	if err != nil {
		advHarness(t, "bob's Join over the honest invite: %v", err)
	}
	scene.bobGroup = bobGroup
	scene.hear(t, "bob", bobGroup)
	scene.say(t, "bob", bobGroup)
	scene.hear(t, "alice", aliceGroup)
	return scene
}

// say seals one fresh canary in a group and files it under the epoch the group stands at.
func (self *advJoin) say(t *testing.T, who string, group *urmessage.Group) string {
	t.Helper()
	canary := advCanary(t)
	if _, err := group.Send(self.ctx, canary); err != nil {
		advHarness(t, "%s's Send of a canary: %v", who, err)
	}
	self.canaries[canary] = group.Epoch()
	return canary
}

// hear is one Receive that must hand back at least one canary: the precondition that an honest
// member READ what the adversary is about to be measured against.
func (self *advJoin) hear(t *testing.T, who string, group *urmessage.Group) {
	t.Helper()
	received, err := group.Receive(self.ctx)
	if err != nil {
		advHarness(t, "%s's Receive: %v", who, err)
	}
	for _, one := range received {
		if _, isCanary := self.canaries[one.Text]; isCanary && one.Gap == "" {
			return
		}
	}
	advHarness(t, "%s received %d message(s) and none is a canary, so no honest member read what the adversary is measured against", who, len(received))
}

// advSettle fetches on one group until it stands at the epoch the scene needs. A walk crosses the
// commits it is served and no more, so one Receive is not "caught up"; and a group that does not
// get there is a harness fault, never a verdict.
func advSettle(t *testing.T, ctx context.Context, who string, group *urmessage.Group, epoch uint64) {
	t.Helper()
	for round := 0; round < 16 && group.Epoch() < epoch; round += 1 {
		if _, err := group.Receive(ctx); err != nil {
			advHarness(t, "%s's Receive on the way to epoch %d: %v", who, epoch, err)
		}
	}
	if got := group.Epoch(); got != epoch {
		advHarness(t, "%s stands at epoch %d after its walks, want %d", who, got, epoch)
	}
}

// recordOf is the durable record one persona holds for the scene's group.
func (self *advJoin) recordOf(t *testing.T, who *persona) *urmessage.GroupRecord {
	t.Helper()
	records, err := who.stateStore.GroupRecords()
	if err != nil {
		advHarness(t, "%s's GroupRecords: %v", who.name, err)
	}
	for _, record := range records {
		if bytes.Equal(record.GroupId, self.groupId) {
			return record
		}
	}
	return nil
}

// advHarvest is the recorder's whole attack on one join: the Shor grant over what was captured,
// the scrape of the haystack, and the read. It answers the epochs it read.
func advHarvest(t *testing.T, world *world, groupId []byte, captured [][]byte, haystack []byte,
	joinCode []byte, beforeJoin string, invite []byte, canaries map[string]uint64) []string {

	t.Helper()
	version, fields := advInviteFields(t, invite)
	if len(fields) < 3 {
		advHarness(t, "an invite at version %#04x with %d fields carries no welcome and tree to join from", version, len(fields))
	}
	shadow, granted := advShor(t, captured, joinCode, beforeJoin, fields[1], fields[2])
	if !granted {
		t.Logf("the recorder captured no init key, so the CRQC inverts nothing and the shadow does not exist")
		return []string{}
	}
	scraped := advScrape(t, world, groupId, shadow, haystack)
	if scraped.pqSecret == nil {
		shadow.handle.Close()
		return []string{}
	}
	if scraped.groupHandleKey == nil {
		// HALF A RECOVERY IS REPORTED AS WHAT IT IS, NEVER AS NOTHING. The recorder holds the storage
		// root of the join epoch, confirmed against the server's own digest, and lacks only the key
		// the production opener maps a sender handle to a leaf with.
		shadow.handle.Close()
		return []string{fmt.Sprintf("storage-root:%d", shadow.epoch)}
	}
	return advRead(t, world, shadow, scraped.pqSecret, scraped.groupHandleKey, canaries)
}
```

- [ ] **Step 2: no commit yet.** The harness is one commit, made in Task 27.

### Task 5: Scenario `P1-hndl-founding`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch`, and the registry line `P1-hndl-founding`

**Serves.** T4 P1; T1 6.2 S1, the founding pair.

**Why it is RED today.** Today's invitation carries `pq_secret` and `group_handle_key` as two length-prefixed fields in the clear. The recorder holds both codes, the grant gives it the classical join, the scrape finds both secrets, and it reads the founder's canary of epoch 1.

**Property 1.** On the base tree the adversary of `P1-hndl-founding` observes exactly `[epoch:1]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "P1-hndl-founding", "state": "open", "expect": ["epoch:1"], "goal": [], "closed_by": "T1", "reads": "a recorder of both pasted codes and the server's rows, with a later CRQC, reads the epoch a founding add admitted the joiner at"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// ── P1: harvest now, decrypt later ───────────────────────────────────────────────────────────

func TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch(t *testing.T) {
	scene := advFounding(t, true)
	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, scene.paste.haystack(),
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-hndl-founding", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM P1-hndl-founding state=open     expect=[epoch:1] observed=[epoch:1] :: KNOWN GAP (closed by T1)
strict: ADVSIM P1-hndl-founding state=open     expect=[epoch:1] observed=[epoch:1] :: RED: the gap is open, closed by T1: the adversary observed [epoch:1], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch:1], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit that needs`.
2. The change of Task 46, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 6: Scenario `P1-hndl-live-add`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch`, and the registry line `P1-hndl-live-add`

**Serves.** T1 6.2 S1, a live add at epoch 2 (the world the stale-secret mutants need).

**Why it is RED today.** The same, through the other adder road: `AddMemberAndPublish` rotates `pq_secret` and pastes the rotated value in the clear. The recorder reads epoch 2.

**Property 1.** On the base tree the adversary of `P1-hndl-live-add` observes exactly `[epoch:2]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "P1-hndl-live-add", "state": "open", "expect": ["epoch:2"], "goal": [], "closed_by": "T1", "reads": "the same recorder reads the epoch a live add (a rotated pq_secret) admitted the joiner at"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// advLiveAdd is one LIVE add with everything a recorder kept of it: the group is open, the founder
// adds a third device over the paste channel, the add's commit rotates pq_secret, and the joiner
// reads a canary the founder seals at the epoch it was admitted at.
type advLiveAdd struct {
	scene      *advJoin
	paste      *advPaste
	joinCode   []byte
	beforeJoin string
	invite     []byte
	canaries   map[string]uint64
}

func advLiveAddScene(t *testing.T) *advLiveAdd {
	t.Helper()
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	if err := carol.device.Connect(scene.ctx); err != nil {
		advHarness(t, "carol's Connect: %v", err)
	}
	paste := &advPaste{}
	joinCode, err := carol.device.KeyPackage()
	if err != nil {
		advHarness(t, "carol's KeyPackage: %v", err)
	}
	joinCode = paste.carry(joinCode)
	beforeJoin := filepath.Join(t.TempDir(), "carol-before-the-join")
	copyAppData(t, carol.stateDir, beforeJoin)
	invite, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "alice's AddMemberAndPublish: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	encoded = paste.carry(encoded)
	if epoch := scene.aliceGroup.Epoch(); epoch != 2 {
		advHarness(t, "the live add left the group at epoch %d, want 2", epoch)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		advHarness(t, "parsing the invite: %v", err)
	}
	carolGroup, err := carol.device.Join(scene.ctx, carried)
	if err != nil {
		advHarness(t, "carol's Join: %v", err)
	}
	canaries := map[string]uint64{}
	canary := advCanary(t)
	if _, err := scene.aliceGroup.Send(scene.ctx, canary); err != nil {
		advHarness(t, "alice's Send at epoch 2: %v", err)
	}
	canaries[canary] = scene.aliceGroup.Epoch()
	gcReceiveText(t, scene.ctx, "carol", carolGroup, canary)
	return &advLiveAdd{scene: scene, paste: paste, joinCode: joinCode, beforeJoin: beforeJoin, invite: encoded, canaries: canaries}
}

// The same recorder against a LIVE add: the group is open, the add's commit rotates pq_secret, and
// the invitation must deliver the rotated value. It is a second scenario because it is a second
// code path on the adder (AddMemberAndPublish and the staged rotation) and a second secret.
func TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch(t *testing.T) {
	live := advLiveAddScene(t)
	observed := advHarvest(t, live.scene.world, live.scene.groupId, live.paste.captured, live.paste.haystack(),
		live.joinCode, live.beforeJoin, live.invite, live.canaries)
	advJudge(t, "P1-hndl-live-add", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM P1-hndl-live-add state=open     expect=[epoch:2] observed=[epoch:2] :: KNOWN GAP (closed by T1)
strict: ADVSIM P1-hndl-live-add state=open     expect=[epoch:2] observed=[epoch:2] :: RED: the gap is open, closed by T1: the adversary observed [epoch:2], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch:2], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit that needs`.
2. The change of Task 46, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 7: Scenario `P1-hndl-admin-add`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimHarvestNowDecryptLaterReadsAnAdminsAddEpoch`, and the registry line `P1-hndl-admin-add`

**Serves.** T1 6.2 S1, four parties with an admin adding.

**Why it is RED today.** The one world in which the adder hands on secrets it was itself handed: its handle key arrived in its own invitation and its `pq_secret` in a device wrap. The recorder reads epoch 4.

**Property 1.** On the base tree the adversary of `P1-hndl-admin-add` observes exactly `[epoch:4]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "P1-hndl-admin-add", "state": "open", "expect": ["epoch:4"], "goal": [], "closed_by": "T1", "reads": "the same recorder reads the epoch an admin's add admitted the joiner at, in a group of four: the adder hands on secrets it was itself handed"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// The same recorder against an add made by an ADMIN who is not the founder, in a group of four. It
// is a scenario of its own because it is the one world in which the adder hands on secrets it was
// itself handed: its group_handle_key arrived in its own invitation, and its pq_secret of the epoch
// it adds at arrived in a device wrap.
func TestAdvSimHarvestNowDecryptLaterReadsAnAdminsAddEpoch(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	if err := scene.aliceGroup.SetRole(scene.ctx, rolesIdentityOf(t, scene.bobGroup), "admin"); err != nil {
		advHarness(t, "alice's SetRole(bob, admin): %v", err)
	}
	// bob and carol follow the two commits: an admin commits from the epoch the group stands at
	advSettle(t, scene.ctx, "bob", scene.bobGroup, 3)
	advSettle(t, scene.ctx, "carol", carolGroup, 3)
	dave := scene.world.newPersona(t, "dave")
	if err := dave.device.Connect(scene.ctx); err != nil {
		advHarness(t, "dave's Connect: %v", err)
	}
	paste := &advPaste{}
	joinCode, err := dave.device.KeyPackage()
	if err != nil {
		advHarness(t, "dave's KeyPackage: %v", err)
	}
	joinCode = paste.carry(joinCode)
	beforeJoin := filepath.Join(t.TempDir(), "dave-before-the-join")
	copyAppData(t, dave.stateDir, beforeJoin)
	invite, err := scene.bobGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "the admin's AddMemberAndPublish: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	encoded = paste.carry(encoded)
	if epoch := scene.bobGroup.Epoch(); epoch != 4 {
		advHarness(t, "the admin's add left the group at epoch %d, want 4", epoch)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		advHarness(t, "parsing the invite: %v", err)
	}
	daveGroup, err := dave.device.Join(scene.ctx, carried)
	if err != nil {
		advHarness(t, "dave's Join: %v", err)
	}
	canaries := map[string]uint64{}
	canary := advCanary(t)
	if _, err := scene.bobGroup.Send(scene.ctx, canary); err != nil {
		advHarness(t, "the admin's Send at epoch 4: %v", err)
	}
	canaries[canary] = scene.bobGroup.Epoch()
	gcReceiveText(t, scene.ctx, "dave", daveGroup, canary)

	observed := advHarvest(t, scene.world, scene.groupId, paste.captured, paste.haystack(),
		joinCode, beforeJoin, encoded, canaries)
	advJudge(t, "P1-hndl-admin-add", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimHarvestNowDecryptLaterReadsAnAdminsAddEpoch$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimHarvestNowDecryptLaterReadsAnAdminsAddEpoch$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM P1-hndl-admin-add state=open     expect=[epoch:4] observed=[epoch:4] :: KNOWN GAP (closed by T1)
strict: ADVSIM P1-hndl-admin-add state=open     expect=[epoch:4] observed=[epoch:4] :: RED: the gap is open, closed by T1: the adversary observed [epoch:4], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch:4], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit that needs`.
2. The change of Task 46, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 8: Scenario `P1-second-device-invitation`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets`, and the registry line `P1-second-device-invitation`

**Serves.** T1 6.2 S1, an identity's second device.

**Why it is RED today.** A plain member adds its own second device. The sdk mints one identity per state store, so the second device is a seam member; it has no device store for the quantum grant to work from, so this scenario measures the half of the recorder that needs none: handed the exporter of the classical join, it finds the epoch's secret and the handle key in the pasted invitation. It reads no canary, and its registry line says so.

**Property 1.** On the base tree the adversary of `P1-second-device-invitation` observes exactly `[ghk storage-root:2]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "P1-second-device-invitation", "state": "open", "expect": ["ghk", "storage-root:2"], "goal": [], "closed_by": "T1", "reads": "a recorder of a second device's pasted codes, handed the exporter of the classical join, finds the join epoch's secret and the group's handle key in the invitation; the device is added by a plain member that holds the identity, and no canary is read"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// The fourth world: A SECOND DEVICE OF ONE IDENTITY, added by the member that holds the identity,
// who here is neither the founder nor an admin. An urmessage.Device mints one identity per state
// store, so the second device is a seam member whose credential claims the first's identity. It
// has no device store for the quantum grant to be worked from, so this scenario measures the half
// of the recorder that needs none. The grant is the classical join itself: the exporter of the join
// epoch, which a quantum computer rebuilds from the join code's init key, read here off the second
// device's own joined state and granted only if that init key was captured. With it the recorder
// scrapes the pasted invitation for the epoch's secret and for the group's handle key.
//
// IT DOES NOT READ A CANARY, and its registry line says so. "storage-root:N" is the storage root
// of epoch N, confirmed against the digest the server holds: the root every record of that epoch
// is sealed under.
func TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets(t *testing.T) {
	scene := advFounding(t, true)
	laptop := scene.world.seamMemberClaiming(t, scene.ctx, "bob-laptop", rolesIdentityOf(t, scene.bobGroup))
	paste := &advPaste{}
	joinCode := paste.carry(laptop.keyPackage(t))
	invite, err := scene.bobGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "bob's AddMemberAndPublish of his own second device: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	encoded = paste.carry(encoded)
	if epoch := scene.bobGroup.Epoch(); epoch != 2 {
		advHarness(t, "the second device's add left the group at epoch %d, want 2", epoch)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		advHarness(t, "parsing the invite: %v", err)
	}
	laptop.join(t, carried)

	// THE GRANT RULE, as [advShor] states it: the init key is among the captured octets
	if !bytes.Contains(paste.haystack(), advKeyPackageInitKey(t, joinCode)) {
		advHarness(t, "the recorder holds both pasted codes and the join code's init key is not among their octets")
	}
	exporter, err := laptop.handle.Export("URmessage/v1/storage", nil, 32)
	if err != nil {
		advHarness(t, "the exporter of the epoch the second device joined: %v", err)
	}
	shadow := &advShadow{exporter: exporter, epoch: laptop.handle.Epoch(), ownLeaf: laptop.handle.OwnLeafIndex()}
	observed := []string{}
	scraped := advScrape(t, scene.world, scene.groupId, shadow, encoded)
	if scraped.groupHandleKey != nil {
		observed = append(observed, "ghk")
	}
	if scraped.pqSecret != nil {
		observed = append(observed, fmt.Sprintf("storage-root:%d", shadow.epoch))
	}
	// THE CONTROL, IN THE SAME QUERY: the same scrape over the same invitation with the two true
	// values planted after its last octet. A scrape that went blind finds nothing here either, and
	// that is a harness fault and not a closed gap.
	record := scene.recordOf(t, scene.bob)
	if record == nil || len(record.PqSecret) != 32 || len(record.GroupHandleKey) != 32 {
		advHarness(t, "the adder's durable record does not hold the two values to plant")
	}
	planted := append(append(append([]byte(nil), encoded...), record.PqSecret...), record.GroupHandleKey...)
	control := advScrape(t, scene.world, scene.groupId, shadow, planted)
	if !bytes.Equal(control.pqSecret, record.PqSecret) || !bytes.Equal(control.groupHandleKey, record.GroupHandleKey) {
		advHarness(t, "the scrape did not find the two true values planted after the invitation, so a verdict of nothing found would be a scrape that cannot see")
	}
	advJudge(t, "P1-second-device-invitation", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM P1-second-device-invitation state=open     expect=[ghk storage-root:2] observed=[ghk storage-root:2] :: KNOWN GAP (closed by T1)
strict: ADVSIM P1-second-device-invitation state=open     expect=[ghk storage-root:2] observed=[ghk storage-root:2] :: RED: the gap is open, closed by T1: the adversary observed [ghk storage-root:2], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [ghk storage-root:2], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit`.
2. The change of Task 46, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.
3. `HV7`: the scrape for pq_secret confirms nothing: it has gone blind. Property 1 must fail. Measured: killed by `TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 9: Scenario `P1-c1-invite-alone`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimTheInvitationAloneReadsNothing`, and the registry line `P1-c1-invite-alone`

**Serves.** T4 control: the grant rule.

**What it pins.** CONTROL, not a gap. The init key is in the join code and nowhere else, so a recorder that missed the join code is granted nothing. It would fail if an invitation ever carried the init key.

**Property 1.** On the base tree the adversary of `P1-c1-invite-alone` observes exactly `[]`, which the registry holds as a control: the run passes in both modes only while it observes exactly that.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "P1-c1-invite-alone", "state": "control", "expect": [], "goal": [], "closed_by": "none", "reads": "the recorder holds the invitation and not the join code, so the CRQC has no init key to invert and reads nothing"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// CONTROL: the invitation alone. The init key is in the join code and nowhere else, so a recorder
// that missed the join code has no public key to invert. This can fail: an invitation that ever
// carried the init key would be granted.
func TestAdvSimTheInvitationAloneReadsNothing(t *testing.T) {
	scene := advFounding(t, true)
	observed := advHarvest(t, scene.world, scene.groupId, [][]byte{scene.invite}, scene.invite,
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-c1-invite-alone", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimTheInvitationAloneReadsNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimTheInvitationAloneReadsNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM P1-c1-invite-alone state=control  expect=[] observed=[] :: CONTROL
strict: ADVSIM P1-c1-invite-alone state=control  expect=[] observed=[] :: CONTROL
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL (control): observed [], and this entry holds exactly [zz-not-observed]`.
2. `HV6`: the grant ignores its rule: the joiner's classical keys are granted whether or not the init key was captured. Property 1 must fail. Measured: killed by `TestAdvSimTheInvitationAloneReadsNothing`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 10: Scenario `P1-c2-replaced-pq`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAReplacedPqSecretReadsNothing`, and the registry line `P1-c2-replaced-pq`

**Serves.** T4 control: the read is causal.

**What it pins.** CONTROL. The recorded invitation with its secret replaced by random octets reads nothing: the read goes through that one value.

**Property 1.** On the base tree the adversary of `P1-c2-replaced-pq` observes exactly `[]`, which the registry holds as a control: the run passes in both modes only while it observes exactly that.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "P1-c2-replaced-pq", "state": "control", "expect": [], "goal": [], "closed_by": "none", "reads": "both codes, with random octets where the pq_secret would be: the read goes through that one value and nothing else"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`. It is the first piece of this file to use `crypto/rand`: add it to the import block.

```go

// CONTROL: both codes, with the pq_secret field of the RECORDED invitation replaced by random
// octets. The honest joiner still joined on the real one. The read is causal in that field.
func TestAdvSimAReplacedPqSecretReadsNothing(t *testing.T) {
	scene := advFounding(t, true)
	version, fields := advInviteFields(t, scene.invite)
	if len(fields) < 4 {
		advHarness(t, "the invite carries %d fields, so there is no fourth to replace", len(fields))
	}
	replaced := make([]byte, len(fields[3]))
	if _, err := rand.Read(replaced); err != nil {
		advHarness(t, "drawing the replacement: %v", err)
	}
	fields[3] = replaced
	recorded := advEncodeInvite(version, fields)
	haystack := append(append([]byte(nil), scene.joinCode...), recorded...)
	observed := advHarvest(t, scene.world, scene.groupId, [][]byte{scene.joinCode, recorded}, haystack,
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-c2-replaced-pq", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAReplacedPqSecretReadsNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAReplacedPqSecretReadsNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM P1-c2-replaced-pq state=control  expect=[] observed=[] :: CONTROL
strict: ADVSIM P1-c2-replaced-pq state=control  expect=[] observed=[] :: CONTROL
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL (control): observed [], and this entry holds exactly [zz-not-observed]`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 11: Scenario `P1-c3-injected-secrets`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimInjectedSecretsReadExactlyTheJoinEpoch`, and the registry line `P1-c3-injected-secrets`

**Serves.** T4 positive control; it replaces the design's "version 2 arm that must breach", which no build can keep once nothing reads version 2.

**What it pins.** CONTROL. Handed the two true secrets, the pipeline reads exactly the join epoch. After T1 this is what shows that the read still works.

**Property 1.** On the base tree the adversary of `P1-c3-injected-secrets` observes exactly `[epoch:1]`, which the registry holds as a control: the run passes in both modes only while it observes exactly that.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "P1-c3-injected-secrets", "state": "control", "expect": ["epoch:1"], "goal": [], "closed_by": "none", "reads": "both codes plus the true pq_secret and group_handle_key handed to the recorder: the pipeline reads exactly the join epoch"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// CONTROL: both codes, and the two true secrets handed to the recorder, read off the founder's own
// durable record. The pipeline then reads exactly the join epoch. Once the invitation carries no
// secret in the clear, this is what says the scrape and the read still work.
func TestAdvSimInjectedSecretsReadExactlyTheJoinEpoch(t *testing.T) {
	scene := advFounding(t, true)
	record := scene.recordOf(t, scene.alice)
	if record == nil || len(record.PqSecret) != 32 || len(record.GroupHandleKey) != 32 {
		advHarness(t, "the founder's durable record does not hold the two secrets to inject")
	}
	haystack := append(scene.paste.haystack(), record.PqSecret...)
	haystack = append(haystack, record.GroupHandleKey...)
	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, haystack,
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-c3-injected-secrets", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimInjectedSecretsReadExactlyTheJoinEpoch$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimInjectedSecretsReadExactlyTheJoinEpoch$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM P1-c3-injected-secrets state=control  expect=[epoch:1] observed=[epoch:1] :: CONTROL
strict: ADVSIM P1-c3-injected-secrets state=control  expect=[epoch:1] observed=[epoch:1] :: CONTROL
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL (control): observed [epoch:1], and this entry holds exactly [zz-not-observed]`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 12: Scenario `S2a-ghk-paste-observer`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAPasteObserverRecoversTheGroupHandleKey`, and the registry line `S2a-ghk-paste-observer`

**Serves.** T1 6.2 S2 (a).

**Why it is RED today.** A classical observer of one pasted invitation, holding the server's rows and no MLS secret, finds `group_handle_key` in the clear and confirms it against a sender handle. The same scrape is run a second time over the invitation with the true key planted after its last octet, so that "nothing found" is never a scrape that cannot see.

**Property 1.** On the base tree the adversary of `S2a-ghk-paste-observer` observes exactly `[ghk]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S2a-ghk-paste-observer", "state": "open", "expect": ["ghk"], "goal": [], "closed_by": "T1", "reads": "a classical observer of one pasted invitation plus the server's rows recovers group_handle_key, which maps every sender_handle to a leaf for the group's life"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// ── S2: sender anonymity against a paste observer ────────────────────────────────────────────

// (a) A CLASSICAL observer of one pasted invitation, holding the server's rows and no MLS secret.
func TestAdvSimAPasteObserverRecoversTheGroupHandleKey(t *testing.T) {
	scene := advFounding(t, true)
	observed := []string{}
	if key, at := advScrapeHandleKey(t, scene.world, scene.groupId, scene.invite); key != nil {
		t.Logf("group_handle_key recovered at octet %d of a %d octet invitation", at, len(scene.invite))
		observed = append(observed, "ghk")
	}
	// THE CONTROL, IN THE SAME QUERY: the same scrape over the same invitation with the group's
	// true handle key planted after its last octet. A scrape that went blind finds nothing here
	// either, and that is a harness fault and not a closed gap.
	record := scene.recordOf(t, scene.alice)
	if record == nil || len(record.GroupHandleKey) != 32 {
		advHarness(t, "the founder's durable record does not hold the group_handle_key to plant")
	}
	planted := append(append([]byte(nil), scene.invite...), record.GroupHandleKey...)
	key, at := advScrapeHandleKey(t, scene.world, scene.groupId, planted)
	if !bytes.Equal(key, record.GroupHandleKey) {
		advHarness(t, "the scrape did not find the true group_handle_key planted at octet %d, so a verdict of nothing found would be a scrape that cannot see", len(scene.invite))
	}
	t.Logf("%d windows of the invitation read; the planted control was found at octet %d of %d",
		len(scene.invite)-31, at, len(planted))
	advJudge(t, "S2a-ghk-paste-observer", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAPasteObserverRecoversTheGroupHandleKey$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAPasteObserverRecoversTheGroupHandleKey$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S2a-ghk-paste-observer state=open     expect=[ghk] observed=[ghk] :: KNOWN GAP (closed by T1)
strict: ADVSIM S2a-ghk-paste-observer state=open     expect=[ghk] observed=[ghk] :: RED: the gap is open, closed by T1: the adversary observed [ghk], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [ghk], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit that needs a l`.
2. The change of Task 46, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.
3. `HV8`: the scrape for the group handle key confirms nothing: it has gone blind. Property 1 must fail. Measured: killed by `TestAdvSimAPasteObserverRecoversTheGroupHandleKey`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 13: Scenario `S2b-first-appearance-link`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimFirstAppearanceLinksThisPastesMembersToTheirHandles`, and the registry line `S2b-first-appearance-link`

**Serves.** T1 6.2 S2 (b), the documented breach.

**What it pins.** RESIDUAL, pinned on purpose. With no key at all, the order handles first appear in the server's rows links both members to their handles. Sealing the secrets does not change it.

**Property 1.** On the base tree the adversary of `S2b-first-appearance-link` observes exactly `[linked:2/2]`, which the registry holds as a residual: the run passes in both modes only while it observes exactly that.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S2b-first-appearance-link", "state": "residual", "expect": ["linked:2/2"], "goal": [], "closed_by": "none", "reads": "with no key at all, the order sender handles first appear in the server's rows links the founder and this paste's joiner to their handles; sealing the secrets does not change it"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// (b) THE DOCUMENTED BREACH. With no key at all, the same observer links the founder and this
// paste's joiner to their handles by the order the handles first appear in the server's rows: the
// founding commit is the first row and is the founder's, and the next new handle is the joiner's.
// Sealing the secrets does not change this. It is pinned so that only a deliberate fix moves it.
func TestAdvSimFirstAppearanceLinksThisPastesMembersToTheirHandles(t *testing.T) {
	scene := advFounding(t, true)
	order := [][]byte{}
	for _, row := range scene.world.allRows(t, scene.groupId) {
		seen := false
		for _, earlier := range order {
			seen = seen || bytes.Equal(earlier, row.SenderHandle)
		}
		if !seen {
			order = append(order, append([]byte(nil), row.SenderHandle...))
		}
	}
	if len(order) != 2 {
		advHarness(t, "the server holds rows under %d handles for a two member group", len(order))
	}
	// the truth, read off what each device opened of the other's
	founder := senderHandleOf(t, scene.bobGroup)
	joiner := senderHandleOf(t, scene.aliceGroup)
	linked := 0
	if bytes.Equal(order[0], founder) {
		linked += 1
	}
	if bytes.Equal(order[1], joiner) {
		linked += 1
	}
	advJudge(t, "S2b-first-appearance-link", []string{fmt.Sprintf("linked:%d/2", linked)})
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimFirstAppearanceLinksThisPastesMembersToTheirHandles$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimFirstAppearanceLinksThisPastesMembersToTheirHandles$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S2b-first-appearance-link state=residual expect=[linked:2/2] observed=[linked:2/2] :: RESIDUAL
strict: ADVSIM S2b-first-appearance-link state=residual expect=[linked:2/2] observed=[linked:2/2] :: RESIDUAL
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL (residual): observed [linked:2/2], and this entry holds exactly [zz-not-observed]`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 14: Scenario `S3-chosen-secret`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAnAttackerChosenSecretIsNotInstalled`, and the registry line `S3-chosen-secret`

**Serves.** T1 6.2 S3: a re-encoded invitation with chosen secrets.

**Why it is RED today.** The checksum is not an authentication. The attacker rewrites the two secret fields, recomputes the SHA-256, and the joiner installs the attacker's values.

**Property 1.** On the base tree the adversary of `S3-chosen-secret` observes exactly `[installed:attacker-secret]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S3-chosen-secret", "state": "open", "expect": ["installed:attacker-secret"], "goal": [], "closed_by": "T1", "reads": "an attacker on the paste channel rewrites the invitation so that it carries secrets the attacker chose, and the joiner installs them"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// ── S3: an active attacker on the paste channel ──────────────────────────────────────────────

// The attacker rewrites the invitation in flight into the plaintext format, carrying a pq_secret
// and a group_handle_key IT chose, and recomputes the checksum.
func TestAdvSimAnAttackerChosenSecretIsNotInstalled(t *testing.T) {
	scene := advFounding(t, false)
	_, fields := advInviteFields(t, scene.invite)
	chosenPq := bytes.Repeat([]byte{0xA7}, 32)
	chosenGhk := bytes.Repeat([]byte{0x5E}, 32)
	forged := advEncodeInvite(0x0002, [][]byte{fields[0], fields[1], fields[2], chosenPq, chosenGhk})

	observed := []string{}
	parsed, err := urmessage.ParseInvite(forged)
	if err == nil {
		_, err = scene.bob.device.Join(scene.ctx, parsed)
	}
	t.Logf("the forged invitation was answered: %v", err)
	if record := scene.recordOf(t, scene.bob); record != nil {
		if bytes.Equal(record.PqSecret, chosenPq) || bytes.Equal(record.GroupHandleKey, chosenGhk) {
			observed = append(observed, "installed:attacker-secret")
		} else {
			observed = append(observed, "installed:something")
		}
	}
	advJudge(t, "S3-chosen-secret", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnAttackerChosenSecretIsNotInstalled$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnAttackerChosenSecretIsNotInstalled$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S3-chosen-secret state=open     expect=[installed:attacker-secret] observed=[installed:attacker-secret] :: KNOWN GAP (closed by T1)
strict: ADVSIM S3-chosen-secret state=open     expect=[installed:attacker-secret] observed=[installed:attacker-secret] :: RED: the gap is open, closed by T1: the adversary observed [installed:attacker-secret], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [installed:attacker-secret], the registry models [zz-not-observed] and the goal is []. This is a regression, or a regist`.
2. The change of Task 46, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 15: Scenario `S3-refusal-spends-join-code`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimARefusedInvitationDoesNotSpendTheJoinCode`, and the registry line `S3-refusal-spends-join-code`

**Serves.** T1 6.2 S3: key-package survival.

**Why it is RED today.** The engine consumes the join code before it learns the welcome is for another group. The honest invitation that follows fails: "none of them is in this store".

**Property 1.** On the base tree the adversary of `S3-refusal-spends-join-code` observes exactly `[join-code-spent]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S3-refusal-spends-join-code", "state": "open", "expect": ["join-code-spent"], "goal": [], "closed_by": "T1a", "reads": "an invitation refused for naming another group costs the joiner its one-use join code, so the honest invitation that follows cannot be joined"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// An invitation that is refused must not cost the joiner its join code. The attacker changes the
// group id the invitation names and recomputes the checksum; the honest invitation follows.
func TestAdvSimARefusedInvitationDoesNotSpendTheJoinCode(t *testing.T) {
	scene := advFounding(t, false)
	version, fields := advInviteFields(t, scene.invite)
	fields[0] = newGroupId(t)
	bent, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err != nil {
		advHarness(t, "the bent invitation does not parse, so the join was never reached: %v", err)
	}
	if _, err := scene.bob.device.Join(scene.ctx, bent); err == nil {
		advHarness(t, "an invitation naming one group and carrying another's welcome was accepted")
	} else {
		t.Logf("the bent invitation was refused: %v", err)
	}
	observed := []string{}
	honest, err := urmessage.ParseInvite(scene.invite)
	if err != nil {
		advHarness(t, "parsing the honest invite: %v", err)
	}
	bobGroup, err := scene.bob.device.Join(scene.ctx, honest)
	if err != nil {
		t.Logf("the honest invitation after the refused one: %v", err)
		observed = append(observed, "join-code-spent")
	} else {
		scene.bobGroup = bobGroup
		scene.hear(t, "bob", bobGroup)
	}
	advJudge(t, "S3-refusal-spends-join-code", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimARefusedInvitationDoesNotSpendTheJoinCode$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimARefusedInvitationDoesNotSpendTheJoinCode$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S3-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[join-code-spent] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S3-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[join-code-spent] :: RED: the gap is open, closed by T1a: the adversary observed [join-code-spent], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [join-code-spent], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit th`.
2. The change of Task 35, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 16: Scenario `S3-late-refusal-spends-join-code`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode`, and the registry line `S3-late-refusal-spends-join-code`

**Serves.** T1 6.2 S3: a garbled invitation, then the honest re-paste.

**Why it is RED today.** A refusal made after the engine has joined leaves the join code consumed and the joined state on the disk.

**Property 1.** On the base tree the adversary of `S3-late-refusal-spends-join-code` observes exactly `[join-code-spent]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S3-late-refusal-spends-join-code", "state": "open", "expect": ["join-code-spent"], "goal": [], "closed_by": "T1a", "reads": "an invitation refused after the engine has joined costs the joiner its join code and leaves state behind"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// The same property as the refused invitation above, at the OTHER place a refusal is made: after
// the engine has joined. The attacker shortens the fourth field by one octet and recomputes the
// checksum, the welcome is the right group's, and the refusal is this package's own.
func TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode(t *testing.T) {
	scene := advFounding(t, false)
	version, fields := advInviteFields(t, scene.invite)
	if len(fields) < 4 {
		advHarness(t, "the invite carries %d fields, so there is no fourth to shorten", len(fields))
	}
	fields[3] = fields[3][:len(fields[3])-1]
	observed := []string{}
	bent, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err == nil {
		_, err = scene.bob.device.Join(scene.ctx, bent)
	}
	if err == nil {
		advHarness(t, "an invitation with a shortened fourth field was accepted")
	}
	t.Logf("the shortened invitation was refused: %v", err)
	honest, err := urmessage.ParseInvite(scene.invite)
	if err != nil {
		advHarness(t, "parsing the honest invite: %v", err)
	}
	bobGroup, err := scene.bob.device.Join(scene.ctx, honest)
	if err != nil {
		t.Logf("the honest invitation after the refused one: %v", err)
		observed = append(observed, "join-code-spent")
	} else {
		scene.bobGroup = bobGroup
		scene.hear(t, "bob", bobGroup)
	}
	advJudge(t, "S3-late-refusal-spends-join-code", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S3-late-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[join-code-spent] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S3-late-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[join-code-spent] :: RED: the gap is open, closed by T1a: the adversary observed [join-code-spent], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [join-code-spent], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit th`.
2. The change of Task 36, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 17: Scenario `S3-mg1-join-code-substitution`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimASubstitutedJoinCodeAdmitsTheSwapper`, and the registry line `S3-mg1-join-code-substitution`

**Serves.** T1 6.2 S3: MG-1; T4 P2c.

**Why it is RED today.** OPEN UNTIL THE IDENTITY TRACK. Whoever controls the paste channel substitutes its own join code; the founder adds the swapper and nothing says so. Sealing seals to the swapper.

**Property 1.** On the base tree the adversary of `S3-mg1-join-code-substitution` observes exactly `[swapper-read:1]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S3-mg1-join-code-substitution", "state": "open", "expect": ["swapper-read:1"], "goal": [], "closed_by": "T2", "reads": "a swapper substitutes its own join code; the founder adds the swapper believing it is the victim, and the swapper reads what the founder sends"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// MG-1, pinned: a swapper substitutes its own join code for the victim's. The founder adds the
// swapper believing it is the victim, nothing anywhere says so, and the swapper reads what the
// founder sends. Sealing the join secret seals it TO THE SWAPPER. The identity layer closes this.
func TestAdvSimASubstitutedJoinCodeAdmitsTheSwapper(t *testing.T) {
	world := newWorldWith(t, worldOptions{recordWire: true})
	ctx := context.Background()
	alice := world.newPersona(t, "alice")
	mallory := world.newPersona(t, "mallory")
	for _, who := range []*persona{alice, mallory} {
		if err := who.device.Connect(ctx); err != nil {
			advHarness(t, "%s's Connect: %v", who.name, err)
		}
	}
	aliceGroup, err := alice.device.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		advHarness(t, "alice's CreateGroup: %v", err)
	}
	// the victim's join code never arrives: this is the one alice is handed in its place
	swapped, err := mallory.device.KeyPackage()
	if err != nil {
		advHarness(t, "mallory's KeyPackage: %v", err)
	}
	invite, err := aliceGroup.AddMember(swapped)
	if err != nil {
		advHarness(t, "alice's AddMember of the join code she was handed: %v", err)
	}
	if err := aliceGroup.Open(ctx); err != nil {
		advHarness(t, "alice's Open: %v", err)
	}
	canary := advCanary(t)
	if _, err := aliceGroup.Send(ctx, canary); err != nil {
		advHarness(t, "alice's Send: %v", err)
	}
	observed := []string{}
	malloryGroup, err := mallory.device.Join(ctx, gcReencodeInvite(t, invite))
	if err == nil {
		received, err := malloryGroup.Receive(ctx)
		if err != nil {
			advHarness(t, "mallory's Receive: %v", err)
		}
		for _, one := range received {
			if one.Text == canary {
				observed = append(observed, fmt.Sprintf("swapper-read:%d", aliceGroup.Epoch()))
			}
		}
	}
	advJudge(t, "S3-mg1-join-code-substitution", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimASubstitutedJoinCodeAdmitsTheSwapper$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimASubstitutedJoinCodeAdmitsTheSwapper$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S3-mg1-join-code-substitution state=open     expect=[swapper-read:1] observed=[swapper-read:1] :: KNOWN GAP (closed by T2)
strict: ADVSIM S3-mg1-join-code-substitution state=open     expect=[swapper-read:1] observed=[swapper-read:1] :: RED: the gap is open, closed by T2: the adversary observed [swapper-read:1], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [swapper-read:1], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit tha`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 18: Scenario `S4-state-thief`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimACopiedStateDirectoryReadsTheJoinEpoch`, and the registry line `S4-state-thief`

**Serves.** T4 P4: keys at rest.

**Why it is RED today.** OPEN UNTIL THE HEALING TRACK. A copy of the joiner's state directory reads the group record in the clear and opens what the founder seals next. It is also the positive control for the read.

**Property 1.** On the base tree the adversary of `S4-state-thief` observes exactly `[epoch:1]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S4-state-thief", "state": "open", "expect": ["epoch:1"], "goal": [], "closed_by": "T3", "reads": "a copy of the joiner's state directory taken after the join reads the join epoch: keys at rest are plaintext"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`. It is the first piece of this file to use `github.com/urnetwork/message/messagegroup` and `github.com/urnetwork/message/mls`: add them to the import block.

```go

// ── S4: a copied device ──────────────────────────────────────────────────────────────────────

// A copy of the joiner's whole state directory, taken after the join. It reads the group record
// in the clear (keys at rest are plaintext) and opens what the founder seals next. This is the
// positive control for the read: it does not depend on what an invitation carries.
func TestAdvSimACopiedStateDirectoryReadsTheJoinEpoch(t *testing.T) {
	scene := advFounding(t, true)
	thiefDir := filepath.Join(t.TempDir(), "thief")
	copyAppData(t, scene.bob.stateDir, thiefDir)
	// sealed AFTER the copy: the copy holds the founder's ratchet where bob left it
	scene.say(t, "alice", scene.aliceGroup)

	store, err := urmessage.OpenDurableStateStore(thiefDir)
	if err != nil {
		advHarness(t, "the thief's copy does not open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	signerPub, signerPriv, leafKeys, _, err := store.GetDeviceIdentity()
	if err != nil {
		advHarness(t, "the thief's copy holds no identity: %v", err)
	}
	records, err := store.GroupRecords()
	if err != nil || len(records) != 1 {
		advHarness(t, "the thief's copy holds %d group record(s): %v", len(records), err)
	}
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		advHarness(t, "the crypto provider: %v", err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(crypto, store, mls.SignaturePrivateKey(signerPriv),
		mls.BasicCredential(signerPub), leafKeys)
	if err != nil {
		advHarness(t, "the thief's engine: %v", err)
	}
	handle, err := engine.LoadGroup(records[0].GroupId, records[0].Epoch)
	if err != nil {
		advHarness(t, "the thief's LoadGroup: %v", err)
	}
	shadow := &advShadow{handle: handle, epoch: handle.Epoch(), ownLeaf: handle.OwnLeafIndex()}
	observed := advRead(t, scene.world, shadow, records[0].PqSecret, records[0].GroupHandleKey, scene.canaries)
	advJudge(t, "S4-state-thief", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimACopiedStateDirectoryReadsTheJoinEpoch$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimACopiedStateDirectoryReadsTheJoinEpoch$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S4-state-thief state=open     expect=[epoch:1] observed=[epoch:1] :: KNOWN GAP (closed by T3)
strict: ADVSIM S4-state-thief state=open     expect=[epoch:1] observed=[epoch:1] :: RED: the gap is open, closed by T3: the adversary observed [epoch:1], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch:1], the registry models [zz-not-observed] and the goal is []. This is a regression, or a registry edit that needs`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 19: Scenario `S7a-held-id-valid-invite`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAValidInvitationUnderAHeldGroupIdReplacesNothing`, and the registry line `S7a-held-id-valid-invite`

**Serves.** T1 6.2 S7: a valid invitation under a held group id.

**Why it is RED today.** Anyone can found a group under an id the victim holds and address an invitation to one of its join codes. `Join` overwrites the victim's record and its epoch state; after a restart the group is gone.

**Property 1.** On the base tree the adversary of `S7a-held-id-valid-invite` observes exactly `[epoch-state-replaced record-replaced restore-lost]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7a-held-id-valid-invite", "state": "open", "expect": ["epoch-state-replaced", "record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "a valid invitation into an attacker's group founded under a group id the victim holds replaces the victim's group"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`. It is the first piece of this file to use `strings`: add it to the import block.

```go

// ── S7: an invitation over a group the device already holds ──────────────────────────────────

// advHostile is an attacker's own group founded under the SAME group id the victim holds, with an
// invitation into it addressed to a join code the victim published. CreateGroup takes the id from
// its caller and AddMember reaches no server, so this costs the attacker nothing but that id and
// one of the victim's join codes.
func advHostile(t *testing.T, scene *advJoin, victim *urmessage.Device) []byte {
	t.Helper()
	mallory := scene.world.newPersona(t, "mallory")
	if err := mallory.device.Connect(scene.ctx); err != nil {
		advHarness(t, "mallory's Connect: %v", err)
	}
	hostile, err := mallory.device.CreateGroup(scene.ctx, scene.groupId)
	if err != nil {
		advHarness(t, "mallory's CreateGroup under the held id: %v", err)
	}
	joinCode, err := victim.KeyPackage()
	if err != nil {
		advHarness(t, "the victim's second KeyPackage: %v", err)
	}
	invite, err := hostile.AddMember(joinCode)
	if err != nil {
		advHarness(t, "mallory's AddMember of the victim's join code: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the hostile invite: %v", err)
	}
	return encoded
}

// advHeldGroupOutcome is what an invitation did to a group the victim held: which of its files
// changed, and whether the group still comes back and reads the real founder after a restart.
func advHeldGroupOutcome(t *testing.T, scene *advJoin, before map[string][]byte) []string {
	t.Helper()
	if len(before) == 0 {
		advHarness(t, "the victim held no file for this group before the invitation, so nothing could have been replaced")
	}
	after := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	observed := []string{}
	for name, content := range before {
		changed := !bytes.Equal(after[name], content)
		switch {
		case changed && name == "meta":
			observed = append(observed, "record-replaced")
		case changed && strings.HasPrefix(name, "epoch/"):
			observed = append(observed, "epoch-state-replaced")
		case changed:
			observed = append(observed, "changed:"+name)
		}
	}
	// and the property itself: the group restores, and reads what the REAL founder seals next
	canary := scene.say(t, "alice", scene.aliceGroup)
	scene.bob = scene.world.restart(t, scene.bob)
	lost := func(why string, err error) []string {
		t.Logf("the held group did not come back: %s: %v", why, err)
		return advSet(append(observed, "restore-lost"))
	}
	if err := scene.bob.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted victim's Connect: %v", err)
	}
	restored, err := scene.bob.device.Restore(scene.ctx)
	if err != nil || len(restored) != 1 {
		return lost(fmt.Sprintf("Restore answered %d group(s)", len(restored)), err)
	}
	received, err := restored[0].Receive(scene.ctx)
	if err != nil {
		return lost("Receive", err)
	}
	for _, one := range received {
		if one.Text == canary && one.Gap == "" {
			return advSet(observed)
		}
	}
	return lost("the founder's canary was not among what it read", nil)
}

func TestAdvSimAValidInvitationUnderAHeldGroupIdReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	hostile := advHostile(t, scene, scene.bob.device)
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = scene.bob.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7a-held-id-valid-invite", advHeldGroupOutcome(t, scene, before))
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAValidInvitationUnderAHeldGroupIdReplacesNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAValidInvitationUnderAHeldGroupIdReplacesNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7a-held-id-valid-invite state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[epoch-state-replaced record-replaced restore-lost] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S7a-held-id-valid-invite state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[epoch-state-replaced record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced record-replaced restore-lost], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch-state-replaced record-replaced restore-lost], the registry models [zz-not-observed] and the goal is []. This is a`.
2. The change of Task 33, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 20: Scenario `S7b-held-id-refused-late`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAnInvitationRefusedLateUnderAHeldGroupIdReplacesNothing`, and the registry line `S7b-held-id-refused-late`

**Serves.** T1 6.2 S7: a refused invitation under a held id.

**Why it is RED today.** The same invitation bent so that it is refused after the engine joined. The refusal comes too late: the epoch state is already replaced.

**Property 1.** On the base tree the adversary of `S7b-held-id-refused-late` observes exactly `[epoch-state-replaced restore-lost]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7b-held-id-refused-late", "state": "open", "expect": ["epoch-state-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "the same invitation, bent so that it is refused after the engine has joined, still replaces the held group's epoch state"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// The same invitation carrying a pq_secret one octet short: the session refuses it, which is a
// refusal that arrives AFTER the engine has joined.
func TestAdvSimAnInvitationRefusedLateUnderAHeldGroupIdReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	version, fields := advInviteFields(t, advHostile(t, scene, scene.bob.device))
	if len(fields) < 4 {
		advHarness(t, "the hostile invite carries %d fields", len(fields))
	}
	fields[3] = fields[3][:len(fields[3])-1]
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err == nil {
		_, err = scene.bob.device.Join(scene.ctx, parsed)
	}
	if err == nil {
		advHarness(t, "an invitation with a truncated fourth field was accepted")
	}
	t.Logf("the truncated invitation was answered: %v", err)
	advJudge(t, "S7b-held-id-refused-late", advHeldGroupOutcome(t, scene, before))
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationRefusedLateUnderAHeldGroupIdReplacesNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationRefusedLateUnderAHeldGroupIdReplacesNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7b-held-id-refused-late state=open     expect=[epoch-state-replaced restore-lost] observed=[epoch-state-replaced restore-lost] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S7b-held-id-refused-late state=open     expect=[epoch-state-replaced restore-lost] observed=[epoch-state-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced restore-lost], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch-state-replaced restore-lost], the registry models [zz-not-observed] and the goal is []. This is a regression, or`.
2. The change of Task 33, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 21: Scenario `S7c-fresh-id-held-welcome`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing`, and the registry line `S7c-fresh-id-held-welcome`

**Serves.** T1 6.2 S7: a fresh id in the invitation.

**Why it is RED today.** The invitation names a fresh id and carries a welcome for the held group. The engine joins the group the WELCOME names, so a check on the invitation's id sees nothing.

**Property 1.** On the base tree the adversary of `S7c-fresh-id-held-welcome` observes exactly `[epoch-state-replaced restore-lost]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7c-fresh-id-held-welcome", "state": "open", "expect": ["epoch-state-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "an invitation that names a fresh group id and carries a welcome for the held group replaces the held group's epoch state"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// The invitation NAMES a fresh group id and CARRIES the hostile welcome for the held one.
func TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	version, fields := advInviteFields(t, advHostile(t, scene, scene.bob.device))
	fields[0] = newGroupId(t)
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err == nil {
		_, err = scene.bob.device.Join(scene.ctx, parsed)
	}
	if err == nil {
		advHarness(t, "an invitation naming one group and carrying another's welcome was accepted")
	}
	t.Logf("the invitation under a fresh id was answered: %v", err)
	advJudge(t, "S7c-fresh-id-held-welcome", advHeldGroupOutcome(t, scene, before))
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7c-fresh-id-held-welcome state=open     expect=[epoch-state-replaced restore-lost] observed=[epoch-state-replaced restore-lost] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S7c-fresh-id-held-welcome state=open     expect=[epoch-state-replaced restore-lost] observed=[epoch-state-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced restore-lost], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch-state-replaced restore-lost], the registry models [zz-not-observed] and the goal is []. This is a regression, or`.
2. The change of Task 35, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 22: Scenario `S7d-held-on-disk-only`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAnInvitationOverAGroupHeldOnlyOnDiskReplacesNothing`, and the registry line `S7d-held-on-disk-only`

**Serves.** T1 6.2 S7: held on disk, not in memory.

**Why it is RED today.** After a restart and before a restore the device's map is empty and the group is on its disk. The invitation replaces it.

**Property 1.** On the base tree the adversary of `S7d-held-on-disk-only` observes exactly `[epoch-state-replaced record-replaced restore-lost]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7d-held-on-disk-only", "state": "open", "expect": ["epoch-state-replaced", "record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "the victim has restarted and not restored: the group is on its disk and not in its memory, and the invitation replaces it"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// The victim has restarted and has NOT restored: the group is on its disk and not in its memory.
func TestAdvSimAnInvitationOverAGroupHeldOnlyOnDiskReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	scene.bob = scene.world.restart(t, scene.bob)
	if err := scene.bob.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted victim's Connect: %v", err)
	}
	if held := len(scene.bob.device.Groups()); held != 0 {
		advHarness(t, "the restarted victim holds %d group(s) in memory before any Restore", held)
	}
	hostile := advHostile(t, scene, scene.bob.device)
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = scene.bob.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7d-held-on-disk-only", advHeldGroupOutcome(t, scene, before))
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationOverAGroupHeldOnlyOnDiskReplacesNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationOverAGroupHeldOnlyOnDiskReplacesNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7d-held-on-disk-only state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[epoch-state-replaced record-replaced restore-lost] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S7d-held-on-disk-only state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[epoch-state-replaced record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced record-replaced restore-lost], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [epoch-state-replaced record-replaced restore-lost], the registry models [zz-not-observed] and the goal is []. This is a`.
2. The change of Task 33, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 23: Scenario `S7e-held-id-unheld-epoch`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing`, and the registry line `S7e-held-id-unheld-epoch`

**Serves.** added by the lab.

**Why it is RED today.** The victim joined at epoch 2, so the hostile welcome (epoch 1) collides with no state on its disk. Its record is replaced. Only the gate itself stops this one.

**Property 1.** On the base tree the adversary of `S7e-held-id-unheld-epoch` observes exactly `[record-replaced restore-lost]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7e-held-id-unheld-epoch", "state": "open", "expect": ["record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "the victim joined above epoch one, so the hostile welcome stands at an epoch it holds no state for: only the held-group gate itself is in the way"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// The victim joined ABOVE epoch one, so it holds no epoch state at the epoch the hostile welcome
// stands at. Nothing about the state on its disk is in the way of this one; it is the scenario
// only the held-group gate itself closes.
func TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	if epoch := carolGroup.Epoch(); epoch != 2 {
		advHarness(t, "the victim joined at epoch %d, want 2", epoch)
	}
	scene.say(t, "alice", scene.aliceGroup)
	scene.hear(t, "carol", carolGroup)
	// from here the victim is carol
	scene.bob = carol
	hostile := advHostile(t, scene, carol.device)
	before := advGroupFiles(t, carol.stateDir, scene.groupId)
	if _, held := before["epoch/0000000000000001"]; held {
		advHarness(t, "the victim holds a state at epoch 1, so this is the same-epoch scenario again")
	}
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = carol.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7e-held-id-unheld-epoch", advHeldGroupOutcome(t, scene, before))
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7e-held-id-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[record-replaced restore-lost] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S7e-held-id-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [record-replaced restore-lost], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [record-replaced restore-lost], the registry models [zz-not-observed] and the goal is []. This is a regression, or a reg`.
2. The change of Task 33, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 24: Scenario `S7f-on-disk-unheld-epoch`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing`, and the registry line `S7f-on-disk-unheld-epoch`

**Serves.** added by the lab.

**Why it is RED today.** Both at once: on disk only, at an epoch with no state. Only the gate's reading of the records on the disk stops it.

**Property 1.** On the base tree the adversary of `S7f-on-disk-unheld-epoch` observes exactly `[record-replaced restore-lost]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7f-on-disk-unheld-epoch", "state": "open", "expect": ["record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "both at once: on disk and not in memory, at an epoch the victim holds no state for; only the gate's reading of the records on the disk is in the way"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// Both at once: the victim joined above epoch one, has restarted and has not restored. The group is
// on its disk and not in its memory, and it holds no state at the hostile welcome's epoch, so
// neither the device's map nor the state already on the disk is in the way. Only the gate's reading
// of the RECORDS on the disk is.
func TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	scene.say(t, "alice", scene.aliceGroup)
	scene.hear(t, "carol", carolGroup)
	carol = scene.world.restart(t, carol)
	if err := carol.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted victim's Connect: %v", err)
	}
	if held := len(carol.device.Groups()); held != 0 {
		advHarness(t, "the restarted victim holds %d group(s) in memory before any Restore", held)
	}
	scene.bob = carol
	hostile := advHostile(t, scene, carol.device)
	before := advGroupFiles(t, carol.stateDir, scene.groupId)
	if _, held := before["epoch/0000000000000001"]; held {
		advHarness(t, "the victim holds a state at epoch 1, so this is the same-epoch scenario again")
	}
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = carol.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7f-on-disk-unheld-epoch", advHeldGroupOutcome(t, scene, before))
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7f-on-disk-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[record-replaced restore-lost] :: KNOWN GAP (closed by T1a)
strict: ADVSIM S7f-on-disk-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [record-replaced restore-lost], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [record-replaced restore-lost], the registry models [zz-not-observed] and the goal is []. This is a regression, or a reg`.
2. The change of Task 33, with this registry line left as it is. Property 1 must fail. Measured at that commit: the scenario FAILS with "the gap has CLOSED" and names the registry edit.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 25: Scenario `S7g-removed-group-second-founder`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimASecondFoundersInvitationOverAGroupTheDeviceWasRemovedFrom`, and the registry line `S7g-removed-group-second-founder`

**Serves.** T1 design 7.3, round-2 prompt 3; the security review of this plan.

**Why it is RED today.** OPEN UNTIL THE IDENTITY TRACK. A group a commit removed this device from is still a group it holds: its record is on the disk and its history reads. Being added back is a join over a held id and is honoured; an invitation authenticates nobody, so a SECOND founder's invitation, standing above the epoch of the removal, is honoured too. The record is replaced and the device no longer reads as removed. The held-group gate does not close this, and this plan does not claim it does.

**Property 1.** On the base tree the adversary of `S7g-removed-group-second-founder` observes exactly `[record-replaced removal-forgotten]`, which the registry records as an open gap: the run passes in normal mode and FAILS in strict mode, for that reason.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7g-removed-group-second-founder", "state": "open", "expect": ["record-replaced", "removal-forgotten"], "goal": [], "closed_by": "T2", "reads": "a second founder's invitation, standing above the epoch of the removal, into a group of its own under the id of a group this device was removed from: the record is replaced and the device no longer reads as removed"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`. It is the first piece of this file to use `errors`: add it to the import block.

```go

// A GROUP A COMMIT REMOVED THIS DEVICE FROM IS STILL A GROUP IT HOLDS: its record is on the disk,
// its history still opens, and it reads as removed. This is what an invitation from a SECOND
// FOUNDER does to it, into a group of its own under the same group id. The second founder runs
// against a server of its own, so that its group stands ABOVE the epoch of the removal; an
// invitation is octets and crosses between the two.
//
// OPEN UNTIL THE IDENTITY LAYER. Being added back is a join over a held id and is the repair the
// removal itself names, so it is honoured; and an invitation authenticates nobody, so nothing in
// a join can tell the group that removed this device from another founder's.
func TestAdvSimASecondFoundersInvitationOverAGroupTheDeviceWasRemovedFrom(t *testing.T) {
	scene := advFounding(t, true)
	if err := scene.aliceGroup.RemoveMember(scene.ctx, rolesIdentityOf(t, scene.bobGroup)); err != nil {
		advHarness(t, "alice's RemoveMember of bob: %v", err)
	}
	if _, err := scene.bobGroup.Receive(scene.ctx); !errors.Is(err, urmessage.ErrRemovedFromGroup) {
		advHarness(t, "the removed device's Receive answered %v, want ErrRemovedFromGroup", err)
	}
	removedAt, removal := scene.bobGroup.Removal()
	if removal == nil {
		advHarness(t, "bob does not read as removed, so there is no removed group to measure")
	}
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	if len(before["meta"]) == 0 {
		advHarness(t, "the removed group has no record on bob's disk, so it is not a group he holds")
	}

	other := newWorld(t)
	mallory := other.newPersona(t, "mallory")
	helper := other.newPersona(t, "helper")
	for _, who := range []*persona{mallory, helper} {
		if err := who.device.Connect(scene.ctx); err != nil {
			advHarness(t, "%s's Connect: %v", who.name, err)
		}
	}
	hostileGroup, _ := openPair(t, scene.ctx, mallory, helper, scene.groupId)
	joinCode, err := scene.bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's KeyPackage: %v", err)
	}
	invite, err := hostileGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "the second founder's AddMemberAndPublish: %v", err)
	}
	if epoch := hostileGroup.Epoch(); epoch <= removedAt {
		advHarness(t, "the second founder's group stands at epoch %d and bob was removed at %d, so this is the stale re-add and not this scenario", epoch, removedAt)
	}
	_, err = scene.bob.device.Join(scene.ctx, gcReencodeInvite(t, invite))
	t.Logf("the second founder's invitation over the removed group was answered: %v", err)

	observed := []string{}
	if after := advGroupFiles(t, scene.bob.stateDir, scene.groupId); !bytes.Equal(after["meta"], before["meta"]) {
		observed = append(observed, "record-replaced")
	}
	held := scene.bob.device.Groups()
	if len(held) != 1 || !bytes.Equal(held[0].Id(), scene.groupId) {
		advHarness(t, "bob holds %d group(s) after the invitation, want the one under this id", len(held))
	}
	if _, removal := held[0].Removal(); removal == nil {
		observed = append(observed, "removal-forgotten")
	}
	advJudge(t, "S7g-removed-group-second-founder", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimASecondFoundersInvitationOverAGroupTheDeviceWasRemovedFrom$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimASecondFoundersInvitationOverAGroupTheDeviceWasRemovedFrom$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7g-removed-group-second-founder state=open     expect=[record-replaced removal-forgotten] observed=[record-replaced removal-forgotten] :: KNOWN GAP (closed by T2)
strict: ADVSIM S7g-removed-group-second-founder state=open     expect=[record-replaced removal-forgotten] observed=[record-replaced removal-forgotten] :: RED: the gap is open, closed by T2: the adversary observed [record-replaced removal-forgotten], and the goal is []
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL: the gap MOVED: observed [record-replaced removal-forgotten], the registry models [zz-not-observed] and the goal is []. This is a regression, or`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 26: Scenario `S7-c1-unrestorable-rejoins`

- Consumes: the registry and `advJudge` (Task 2), the adversary's tools (Task 3), the scene (Task 4)
- Produces: `TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain`, and the registry line `S7-c1-unrestorable-rejoins`

**Serves.** the security review of this plan.

**What it pins.** CONTROL. A group whose record is on the disk and whose epoch states are gone does not restore; it is left, the founder removes the stranded leaf and adds a fresh join code, and the device joins again. It holds today, because today nothing refuses a join over a held group. It is here so that the gate which does refuse one cannot leave this state with no way out.

**Property 1.** On the base tree the adversary of `S7-c1-unrestorable-rejoins` observes exactly `[rejoined]`, which the registry holds as a control: the run passes in both modes only while it observes exactly that.

- [ ] **Step 1: the registry line.** Add to `sdk/cp3b/testdata/advsim/known-gaps.json`:

```json
{"id": "S7-c1-unrestorable-rejoins", "state": "control", "expect": ["rejoined"], "goal": [], "closed_by": "none", "reads": "a group whose record is on the disk and whose epoch states are gone does not restore; it is left with ForgetGroup, the founder removes the stranded leaf and adds a fresh join code, and the device joins again"}
```

- [ ] **Step 2: the scenario.** Append to `sdk/cp3b/advsim_join_test.go`.

```go

// CONTROL: A GROUP WHOSE RECORD IS ON THE DISK AND WHICH DOES NOT RESTORE CAN STILL BE LEFT AND
// JOINED AGAIN. The damage is every epoch state the device holds for the group, removed from its
// disk while it is stopped; its record stays. The three verbs a person has over such a group are
// then driven in order: Restore, ForgetGroup, and the founder's repair (the stranded leaf out, a
// fresh join code in, Join).
//
// It is a control and not a gap: it holds today, because today nothing refuses a join over a held
// group. It is here so that the gate which does refuse one cannot leave this state with no way out.
func TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain(t *testing.T) {
	scene := advFounding(t, true)
	bobId := rolesIdentityOf(t, scene.bobGroup)
	scene.bob.kill()
	removed := 0
	for name := range advGroupFiles(t, scene.bob.stateDir, scene.groupId) {
		if strings.HasPrefix(name, "epoch/") {
			removed += 1
		}
	}
	if err := advRemoveEpochStates(scene.bob.stateDir, scene.groupId); err != nil || removed == 0 {
		advHarness(t, "removing bob's %d epoch state(s): %v", removed, err)
	}
	if record := advGroupFiles(t, scene.bob.stateDir, scene.groupId)["meta"]; len(record) == 0 {
		advHarness(t, "bob's record of the group is not on the disk, so this is not a group he holds")
	}
	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
	if err := bob.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted bob's Connect: %v", err)
	}
	restored, restoreErr := bob.device.Restore(scene.ctx)
	if len(restored) != 0 || restoreErr == nil {
		advHarness(t, "the damaged group restored (%d group(s), %v), so this is not a group that does not restore", len(restored), restoreErr)
	}
	t.Logf("Restore: %v", restoreErr)
	forgetErr := bob.device.ForgetGroup(scene.groupId)
	t.Logf("ForgetGroup: %v", forgetErr)

	if err := scene.aliceGroup.RemoveMember(scene.ctx, bobId); err != nil {
		advHarness(t, "alice's RemoveMember of the stranded leaf: %v", err)
	}
	joinCode, err := bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's fresh KeyPackage: %v", err)
	}
	invite, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "alice's AddMemberAndPublish of the fresh join code: %v", err)
	}
	observed := []string{}
	rejoined, joinErr := bob.device.Join(scene.ctx, gcReencodeInvite(t, invite))
	t.Logf("Join over the founder's fresh invitation: %v", joinErr)
	if joinErr != nil {
		observed = append(observed, "wedged")
	} else {
		scene.bob, scene.bobGroup = bob, rejoined
		scene.say(t, "alice", scene.aliceGroup)
		scene.hear(t, "bob", rejoined)
		observed = append(observed, "rejoined")
	}
	advJudge(t, "S7-c1-unrestorable-rejoins", observed)
}
```

- [ ] **Step 3: run it in both modes.**

```bash
go -C sdk/cp3b test -count=1 -run '^TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain$' -v ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run '^TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain$' -v ./...
```

Measured on the harness commit:

```
normal: ADVSIM S7-c1-unrestorable-rejoins state=control  expect=[rejoined] observed=[rejoined] :: CONTROL
strict: ADVSIM S7-c1-unrestorable-rejoins state=control  expect=[rejoined] observed=[rejoined] :: CONTROL
```

- [ ] **Step 4: the mutations.** Each was applied alone and the scenario run.

1. The registry line's `expect` replaced by a value no adversary observes. Property 1 must fail. Measured: `FAIL (control): observed [rejoined], and this entry holds exactly [zz-not-observed]`.

- [ ] **Step 5: no commit yet.** The harness is one commit, made in Task 27.

### Task 27: The RED report, and the harness's one commit

- Consumes: every scenario task above, Task 5 to Task 26
- Produces: the harness commit, and the RED lines the owner is shown

This task states no property: it runs what the tasks above built.

- [ ] **Step 1: assembled, the file is the lab's.** The pieces printed in Task 4 and in the 22 scenario tasks, in order, are `sdk/cp3b/advsim_join_test.go` byte for byte: the generator of this plan cuts them from that file and asserts that they concatenate to it (1009 lines).

- [ ] **Step 2: run the whole harness in both modes.**

```bash
go -C sdk/cp3b vet ./...
go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./... | grep -E '^ADVSIM|^--- FAIL|^ok|^FAIL'
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./... | grep -E '^ADVSIM|^--- FAIL|^ok|^FAIL'
```

Measured on the harness commit. `vet` is clean. Normal mode: `ok`, 25 `TestAdvSim` tests pass (22 scenarios and the harness's own 3). Strict mode: 17 FAIL and 8 PASS. The 17 RED lines:

```
ADVSIM P1-hndl-founding state=open     expect=[epoch:1] observed=[epoch:1] :: RED: the gap is open, closed by T1: the adversary observed [epoch:1], and the goal is []
ADVSIM P1-hndl-live-add state=open     expect=[epoch:2] observed=[epoch:2] :: RED: the gap is open, closed by T1: the adversary observed [epoch:2], and the goal is []
ADVSIM P1-hndl-admin-add state=open     expect=[epoch:4] observed=[epoch:4] :: RED: the gap is open, closed by T1: the adversary observed [epoch:4], and the goal is []
ADVSIM P1-second-device-invitation state=open     expect=[ghk storage-root:2] observed=[ghk storage-root:2] :: RED: the gap is open, closed by T1: the adversary observed [ghk storage-root:2], and the goal is []
ADVSIM S2a-ghk-paste-observer state=open     expect=[ghk] observed=[ghk] :: RED: the gap is open, closed by T1: the adversary observed [ghk], and the goal is []
ADVSIM S3-chosen-secret state=open     expect=[installed:attacker-secret] observed=[installed:attacker-secret] :: RED: the gap is open, closed by T1: the adversary observed [installed:attacker-secret], and the goal is []
ADVSIM S3-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[join-code-spent] :: RED: the gap is open, closed by T1a: the adversary observed [join-code-spent], and the goal is []
ADVSIM S3-late-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[join-code-spent] :: RED: the gap is open, closed by T1a: the adversary observed [join-code-spent], and the goal is []
ADVSIM S3-mg1-join-code-substitution state=open     expect=[swapper-read:1] observed=[swapper-read:1] :: RED: the gap is open, closed by T2: the adversary observed [swapper-read:1], and the goal is []
ADVSIM S4-state-thief state=open     expect=[epoch:1] observed=[epoch:1] :: RED: the gap is open, closed by T3: the adversary observed [epoch:1], and the goal is []
ADVSIM S7a-held-id-valid-invite state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[epoch-state-replaced record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced record-replaced restore-lost], and the goal is []
ADVSIM S7b-held-id-refused-late state=open     expect=[epoch-state-replaced restore-lost] observed=[epoch-state-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced restore-lost], and the goal is []
ADVSIM S7c-fresh-id-held-welcome state=open     expect=[epoch-state-replaced restore-lost] observed=[epoch-state-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced restore-lost], and the goal is []
ADVSIM S7d-held-on-disk-only state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[epoch-state-replaced record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [epoch-state-replaced record-replaced restore-lost], and the goal is []
ADVSIM S7e-held-id-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [record-replaced restore-lost], and the goal is []
ADVSIM S7f-on-disk-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[record-replaced restore-lost] :: RED: the gap is open, closed by T1a: the adversary observed [record-replaced restore-lost], and the goal is []
ADVSIM S7g-removed-group-second-founder state=open     expect=[record-replaced removal-forgotten] observed=[record-replaced removal-forgotten] :: RED: the gap is open, closed by T2: the adversary observed [record-replaced removal-forgotten], and the goal is []
```

- [ ] **Step 3: commit.**

```bash
git add sdk/cp3b/advsim_registry_test.go sdk/cp3b/advsim_oracle_test.go sdk/cp3b/advsim_join_test.go sdk/cp3b/testdata/advsim/known-gaps.json
git commit -m "advsim: the adversary harness, 22 scenarios, RED on 17 open gaps"
```

### Task 28: Quick fix: the pin file says only what exists

- Consumes: `mls/interop/PINS.md` and `mls/vectors_test.go`'s `expectedPendingFamilies`, as they are at the base
- Produces: `TestThePinFileNamesNothingThatDoesNotExist`

**Serves.** The testing design, 2.5.4 and 2.2.2 ("Retired: lines 21-23's placeholders; line 27's job that does not exist").

**Behaviour.** `mls/interop/PINS.md` names three peer images under digests nobody computed, a
weekly job that exists nowhere, a CI service this repository does not have, and its own path in the
repository it left. Two of its octets (offsets 8389 and 8508 at the base) are Windows-1252 dashes,
so the file is not UTF-8. After the fix it says what is true: `test.sh` hash-checks all sixteen
vendored vector files and verifies the families the manifest installs, and the families with no
runner are the ones `expectedPendingFamilies` lists.

**Property 1.** The pin file is UTF-8, names no digest nobody computed, no job, service or matrix that does not exist, and no path of the repository it left; it says on one line of each peer that the peer is NOT BUILT; and it names `expectedPendingFamilies`.

- [ ] **Step 1: the test first.**

`mls/pins_truth_test.go` (new file, 67 lines):

```go
package mls

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// THE PIN FILE SAYS ONLY WHAT EXISTS.
//
// interop/PINS.md is read by people deciding what this package has been held against, and until
// this test it named three peer images under digests nobody had computed, a weekly job that exists
// nowhere, a CI service this repository does not have and its own path in a repository it has
// left; and two of its octets were Windows-1252 dashes, so the file was not UTF-8. None of that
// was checked by anything, which is how it stayed.
//
// WHAT WOULD GO RED: any of the six retired phrases coming back; a peer that is not built being
// described as anything else; one of the four machine-readable pins losing its `key=<40 hex>`
// shape, which other tests in this package grep.
func TestThePinFileNamesNothingThatDoesNotExist(t *testing.T) {
	raw, err := os.ReadFile("interop/PINS.md")
	if err != nil {
		t.Fatalf("reading the pin file: %v", err)
	}
	if !utf8.Valid(raw) {
		t.Errorf("the pin file is not UTF-8: it holds an octet that is a dash in Windows-1252 and nothing in UTF-8")
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if len(text) < 1000 {
		t.Fatalf("the pin file is %d octets, so every absence below would be over nothing", len(text))
	}
	for _, retired := range []struct{ phrase, why string }{
		{"sha256:<...>", "a digest nobody has computed is not a pin"},
		{"peer-image-bump", "no such job exists, here or in any sibling repository"},
		{"CI never compiles", "this repository has no CI service: test.sh is the whole run"},
		{"green interop matrix", "there is no interop matrix"},
		{"connect/mls/interop/PINS.md", "this file's own path, before the package moved"},
		{"runs every vector family", "six of the sixteen families have no runner; the pending list in vectors_test.go says which"},
	} {
		if strings.Contains(text, retired.phrase) {
			t.Errorf("the pin file still says %q: %s", retired.phrase, retired.why)
		}
	}
	for _, peer := range []string{"openmls peer", "mlspp", "mls-rs"} {
		named := false
		for _, line := range strings.Split(text, "\n") {
			named = named || (strings.Contains(line, peer) && strings.Contains(line, "NOT BUILT"))
		}
		if !named {
			t.Errorf("the pin file does not say on one line that the %s is NOT BUILT", peer)
		}
	}
	// THE SENTENCE ABOUT WHAT RUNS POINTS AT THE LIST THAT IS HELD, and carries no count of its own:
	// vectors_test.go's expectedPendingFamilies is compared with the manifest on every run, and a
	// number written here would be a second copy nothing compares.
	if !strings.Contains(text, "`expectedPendingFamilies`") {
		t.Errorf("the pin file does not name expectedPendingFamilies, the one held list of the families with no runner")
	}
	for _, key := range []string{"mlswg", "openmls", "hpke", "xwing"} {
		pin := regexp.MustCompile(`(?m)^` + key + `=[0-9a-f]{40}$`)
		if found := len(pin.FindAllString(text, -1)); found != 1 {
			t.Errorf("the pin file holds %d line(s) of the shape %s=<40 hex>, want exactly 1", found, key)
		}
	}
}
```

- [ ] **Step 2: run it and see it fail.** On the base file. Measured:

```
$ go test -count=1 -run ^(TestThePinFileNamesNothingThatDoesNotExist) ./mls/
exit status 1
--- FAIL: TestThePinFileNamesNothingThatDoesNotExist (0.01s)
    pins_truth_test.go:28: the pin file is not UTF-8: it holds an octet that is a dash in Windows-1252 and nothing in UTF-8
    pins_truth_test.go:43: the pin file still says "sha256:<...>": a digest nobody has computed is not a pin
    pins_truth_test.go:43: the pin file still says "peer-image-bump": no such job exists, here or in any sibling repository
    pins_truth_test.go:43: the pin file still says "CI never compiles": this repository has no CI service: test.sh is the whole run
    pins_truth_test.go:43: the pin file still says "green interop matrix": there is no interop matrix
    pins_truth_test.go:43: the pin file still says "connect/mls/interop/PINS.md": this file's own path, before the package moved
    pins_truth_test.go:52: the pin file does not say on one line that the openmls peer is NOT BUILT
    pins_truth_test.go:52: the pin file does not say on one line that the mlspp is NOT BUILT
    pins_truth_test.go:52: the pin file does not say on one line that the mls-rs is NOT BUILT
    pins_truth_test.go:59: the pin file does not name expectedPendingFamilies, the one held list of the families with no runner
FAIL
...
```

- [ ] **Step 3: the change.** The file holds octets that are not UTF-8, so edit it byte for byte. This plan is UTF-8, so the diff below shows each of the two stray octets as `<0x97>`; the lab's commit holds the octets themselves. The four `key=<40 hex>` lines are untouched; other tests grep them. THIS IS THE PIN FILE'S PROSE AND NOT A PIN: no `go.mod` line, no `key=` line and no literal of `mls/pins_test.go` changes, so this task is inside what R6 lets be written before the toolchain move lands.

`mls/interop/PINS.md`:

```diff
--- a/mls/interop/PINS.md
+++ b/mls/interop/PINS.md
@@ -1,8 +1,11 @@
-<!-- connect/mls/interop/PINS.md -->
+<!-- mls/interop/PINS.md -->
 # Pinned external references
 
 This is the one pin file for the whole slice. Bumping any line here is a pull request that must show
-a green interop matrix and a green `vectors` job. Nothing in this file enters `go.mod`.
+`./test.sh` green. Its `mls` leg checks each of the 16 vendored vector files against the digest in
+`testdata/vectors/VECTORS.sha256`, and verifies every family that has a runner installed in the
+manifest of `vectors_test.go`. The families with no runner yet are the ones that file lists as
+`expectedPendingFamilies`: they are pinned and not yet run. Nothing in this file enters `go.mod`.
 
 The commit lines are machine-readable and are grepped by other plans' tasks; keep the
 `key=<40-char sha>` shape exactly.
@@ -16,16 +19,16 @@ xwing=9b6ce9e614811dba8d46841052f3883cbc4c1a65
 
 | What | Pin | Why |
 |---|---|---|
-| mlswg/mls-implementations | the `mlswg=` line above | the 16 vector families **and** the gRPC test runner, pinned together so the runner and the vectors never disagree |
-| openmls/openmls | the `openmls=` line above | the differential oracle and the 9 fuzz targets; built out of process in CI, never linked |
-| `ghcr.io/urnetwork/mls-peer-openmls` | digest `sha256:<...>` | interop peer |
-| `ghcr.io/urnetwork/mls-peer-mlspp` | digest `sha256:<...>` | interop peer |
-| `ghcr.io/urnetwork/mls-peer-mls-rs` | digest `sha256:<...>` | interop peer |
+| mlswg/mls-implementations | the `mlswg=` line above | the 16 vector families. The gRPC test runner at the same commit is NOT USED: nothing here runs it |
+| openmls/openmls | the `openmls=` line above | the differential oracle this package is to be held against. Nothing builds or links OpenMLS today |
+| the openmls peer | none | NOT BUILT. No image and no digest exists; it is planned as a binary built from the `openmls=` pin |
+| the mlspp peer | none | NOT BUILT, deferred |
+| the mls-rs peer | none | NOT BUILT, deferred |
 | `testdata/vectors/rfc/hpke-rfc9180-x25519.json` | the `hpke=` line above, filtered; sha256 `3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a` | the RFC 9180 base-mode known answers that hold the HPKE instantiation to the RFC rather than to itself; see the section below |
 | `../../messagegroup/testdata/vectors/rfc/xwing-draft10.json` | the `xwing=` line above, whole; sha256 `409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d` | the three draft-connolly-cfrg-xwing-kem known answers that hold the X-Wing combiner, its label position and the seed expansion to the draft rather than to themselves; see the section below |
 
-Peer images are prebuilt and pushed to GHCR by the weekly `peer-image-bump` job, which opens a
-digest-bump PR. CI never compiles Rust or C++ on a per-commit path.
+No interop peer is built, by anything, on any schedule. This repository has no CI service:
+`./test.sh` is the whole run, and it compiles Go only.
 
 ## testdata/vectors/rfc/hpke-rfc9180-x25519.json
 
@@ -121,8 +124,8 @@ the smudge. `TestXwingVectorFileWasNotSmudgedOnTheWayIn` refuses a carriage retu
 all, and `TestXwingVectorDirectoryDisablesGitsTextConversion` reads the attributes file itself so the rule
 going missing fails on the commit that removes it rather than on the next person's fresh clone.
 
-Every value above is pinned a second time in `messagegroup/xwing_vectors_test.go` <0x97> the vendored digest as
-`xwingVectorSha256`, the repository, commit, path and vector count as the constants beside it <0x97> and
+Every value above is pinned a second time in `messagegroup/xwing_vectors_test.go` -- the vendored digest as
+`xwingVectorSha256`, the repository, commit, path and vector count as the constants beside it -- and
 `TestXwingVectorProvenanceIsRecordedInThePinFile` compares the two copies field by field, parsing this
 section's table rather than grepping the file, for the reason the section above records: the commit appears
 in the fence, in the table and in the fetch url, so a `strings.Contains` over the whole file is answered by
```

- [ ] **Step 4: run it and see it pass.**

```bash
go test -count=1 -run 'TestThePinFileNamesNothingThatDoesNotExist|Pin|TestVectorFolder|Upstream' ./mls/
```

Measured: `ok github.com/urnetwork/message/mls`; the whole root module at the end of S0 is in the close task's table.

- [ ] **Step 5: the mutations.**

1. Restore any one of the five retired sentences to the file, or one of its two stray octets. Property 1 must fail. Measured: each is a line of the failure above, which is this test on the file as it stands at the base.

- [ ] **Step 6: commit.**

```bash
git add mls/pins_truth_test.go mls/interop/PINS.md
git commit -m "mls/interop: the pin file names nothing that does not exist"
```

### Task 29: Quick fix: a vulnerability scan over every module, as an opt-in step of `test.sh`

- Consumes: `scripts/module-census.sh`'s wirings, `scripts/toolchain.sh`, `sdk/cgo/compose.sh`, `test.sh`
- Produces: `scripts/vulncheck.sh`, the `MESSAGE_TEST_VULNCHECK` step of `test.sh`, and a section of `docs/RELEASING.md`

**Serves.** The testing design, 2.5.5. It asks for a `govulncheck.yml` workflow per repository.
This repository has no workflows and its maintainers do not use them (`test.sh`, header), so the
scan is a script. The lead's ruling of 2026-10-09: it is an OPT-IN step of `test.sh`, off by
default, and it is run by hand before a release.

**Behaviour.** `scripts/vulncheck.sh` runs a pinned `govulncheck` over every module file git
tracks, EACH LOADED THE WAY `test.sh` BUILDS IT: plain for the root, `sdk`, `sdk/livepeer` and
`sdk/liveprobe`; with the tool's `-test` flag for `sdk/cp3b`, whose every Go file is a test; under
`-tags new` for the wire corpus, which does not compile with no tag; composed by
`sdk/cgo/compose.sh` for the native library, and a FAILURE on linux with no C compiler; and the
loopback modfile named in the verdict as not scanned, with its reason. It counts the packages and
the Go files it will read before each scan and fails on zero, holds its rows both ways against the
module files git tracks, and reads the tool's exit status: 3 is a finding, anything else that is
not 0 is "the scan did not run". It prints the tree's commit and the database's own modified time.

It is off by default because its verdict moves when the database does, with no commit here, and
every other step of `test.sh` is a statement about the tree.

This task supplies no Go test and states no property. Its check is the first run.

- [ ] **Step 1: the script.**

`scripts/vulncheck.sh` (new file, 179 lines), as a diff:

```diff
--- /dev/null
+++ b/scripts/vulncheck.sh
@@ -0,0 +1,179 @@
+#!/usr/bin/env bash
+# scripts/vulncheck.sh: govulncheck over every module of this repository, each loaded the way
+# test.sh builds it, under the pinned toolchain.
+#
+# IT IS A STEP OF test.sh ONLY WHEN ASKED FOR (MESSAGE_TEST_VULNCHECK=1), and that is deliberate.
+# It reads the Go vulnerability database over the network, so its verdict changes when the
+# database does, with no commit here; test.sh's verdict is a statement about a tree. A red run of
+# this script is therefore attributable to one of two things, and it prints both: the tree's
+# commit and the database's own modified time. It is run by hand before a release
+# (docs/RELEASING.md).
+#
+# EVERY MODULE FILE HAS A ROW SAYING HOW IT IS LOADED, and the rows are held both ways against the
+# files git tracks, as scripts/module-census.sh holds its own: a module file with no row fails, and
+# so does a row whose file is gone. The wirings are the census's. They are written out here because
+# a scan that loads a module some other way than test.sh builds it reads some other program:
+#
+#   plain       go.mod, sdk, sdk/livepeer, sdk/liveprobe: ./... as it stands.
+#   tests       sdk/cp3b, the acceptance suite. Every Go file in it is a test, so it is scanned with
+#               the tool's -test flag: without it the tool is handed one package holding no file.
+#   tags:new    protocol/testdata/wiregolden. It builds under exactly one of two tags (test.sh runs
+#               both); `new` is this repository's schema. With no tag it does not compile.
+#   composed    sdk/cgo, the native library. Its package main is the core SDK's, laid beside this
+#               repository's half by sdk/cgo/compose.sh, and it is cgo: with no C compiler the
+#               package has no Go file at all and a scan of it would be a scan of nothing. On linux
+#               that is a failure, as it is for test.sh; on any other host it is named in the
+#               verdict as not scanned.
+#   not-scanned sdk/cgo/loopback.go.mod, with its reason below, named in the verdict on every run.
+#
+# A MODULE THAT HANDS THE TOOL NO GO FILE FAILS. The packages and the files the scan will read are
+# counted and printed before each scan, so a walk that found nothing, a tag that excluded
+# everything, or a module of tests scanned without its tests cannot read as a clean answer.
+#
+# THE TOOL'S OWN EXIT STATUS IS READ, AND ITS TWO FAILURES ARE NOT ONE: 3 is "a vulnerability
+# reaches this module's code", and anything else that is not 0 is "the scan did not run".
+#
+# Usage:  bash scripts/vulncheck.sh
+#         MESSAGE_TEST_VULNCHECK=1 ./test.sh               the whole run, with this as its last step
+#         GOVULNCHECK=v1.9.0 bash scripts/vulncheck.sh     another version of the tool
+#
+# The siblings must be on disk at their pins, exactly as for test.sh (scripts/siblings.sh).
+# The tool is built into a temporary directory with `go install <module>@<version>`, under the
+# pinned toolchain, and never enters a go.mod of this repository. It is run as that binary and not
+# through `go run`, which answers 1 whatever the program it ran answered.
+set -euo pipefail
+cd "$(dirname "$0")/.."
+export GOWORK=off
+GOTOOLCHAIN=$(bash scripts/toolchain.sh)
+export GOTOOLCHAIN
+# v1.9.0: v1.1.4 cannot read go1.27's standard library, and its go/ssa panics on a linux build.
+tool="golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK:-v1.9.0}"
+
+declare -A how=(
+  [go.mod]="plain"
+  [sdk/go.mod]="plain"
+  [sdk/cp3b/go.mod]="tests"
+  [sdk/livepeer/go.mod]="plain"
+  [sdk/liveprobe/go.mod]="plain"
+  [protocol/testdata/wiregolden/go.mod]="tags:new"
+  [sdk/cgo/go.mod]="composed"
+  [sdk/cgo/loopback.go.mod]="not-scanned"
+)
+loopback_reason="the loopback harness's modfile: the composed module plus the message server it runs in process, and nothing built from it ships"
+
+bin=$(mktemp -d)
+trap 'rm -rf "$bin"' EXIT
+GOBIN="$bin" go install "$tool"
+govulncheck=$(ls "$bin"/govulncheck*)
+
+echo "tree:     $(git rev-parse HEAD)"
+echo "tool:     $tool under $GOTOOLCHAIN"
+echo "database: $(curl -fsS https://vuln.go.dev/index/db.json || echo 'UNREADABLE')"
+
+scanned=0
+affected=()
+unscanned=()
+narrowings=()
+
+# scan <module file> <dir> <files template> [flags the go command and the tool both take]: the
+# packages the module loads and the Go files the tool will read, counted first, and then the tool
+# over the same pattern with the same flags
+scan() {
+  local modfile=$1 dir=$2 template=$3 counts packages files code
+  shift 3
+  local list_flags=() tool_flags=()
+  for flag in "$@"; do
+    tool_flags+=("$flag")
+    if [ "$flag" != -test ]; then list_flags+=("$flag"); fi
+  done
+  if ! counts=$(go -C "$dir" list "${list_flags[@]}" -f "$template" ./...); then
+    echo "    FAIL: go list could not load this module"
+    unscanned+=("$modfile")
+    return
+  fi
+  packages=$(echo "$counts" | grep -c . || true)
+  files=$(echo "$counts" | awk '{ for (i = 1; i <= NF; i++) total += $i } END { print total + 0 }')
+  echo "    packages loaded: $packages, Go files the scan reads: $files"
+  if [ "$files" = 0 ]; then
+    echo "    FAIL: the scan would read no Go file, so a clean answer would be an answer about nothing"
+    unscanned+=("$modfile")
+    return
+  fi
+  code=0
+  (cd "$dir" && "$govulncheck" "${tool_flags[@]}" ./...) || code=$?
+  case "$code" in
+    0) scanned=$((scanned + 1)) ;;
+    3) scanned=$((scanned + 1)); affected+=("$modfile") ;;
+    *) echo "    FAIL: the tool exited $code, which is not a verdict"; unscanned+=("$modfile") ;;
+  esac
+}
+code_files='{{len .GoFiles}} {{len .CgoFiles}}'
+test_files='{{len .GoFiles}} {{len .CgoFiles}} {{len .TestGoFiles}} {{len .XTestGoFiles}}'
+
+seen=()
+while IFS= read -r modfile; do
+  seen+=("$modfile")
+  dir=$(dirname "$modfile")
+  wiring=${how[$modfile]:-}
+  echo "=== $modfile ($wiring)"
+  case "$wiring" in
+    plain)
+      scan "$modfile" "$dir" "$code_files"
+      ;;
+    tests)
+      scan "$modfile" "$dir" "$test_files" -test
+      ;;
+    tags:*)
+      scan "$modfile" "$dir" "$code_files" -tags "${wiring#tags:}"
+      ;;
+    composed)
+      if [ "$(go env CGO_ENABLED)" != 1 ] || ! command -v "$(go env CC)" > /dev/null 2>&1; then
+        if [ "$(go env GOOS)" = linux ]; then
+          echo "    FAIL: linux with no C compiler or CGO_ENABLED=0: the native library is cgo, and the full scan needs gcc"
+          unscanned+=("$modfile")
+        else
+          echo "    NOT SCANNED: no C compiler on this $(go env GOOS) host, and the native library is cgo"
+          narrowings+=("$modfile: no C compiler on this $(go env GOOS) host")
+        fi
+        continue
+      fi
+      bash sdk/cgo/compose.sh
+      scan "$modfile" "$dir" "$code_files"
+      bash sdk/cgo/compose.sh --clean
+      ;;
+    not-scanned)
+      echo "    NOT SCANNED: $loopback_reason"
+      narrowings+=("$modfile: $loopback_reason")
+      ;;
+    *)
+      echo "    FAIL: this module file has no row in scripts/vulncheck.sh saying how it is loaded"
+      unscanned+=("$modfile")
+      ;;
+  esac
+done < <(git ls-files -- 'go.mod' '*/go.mod' '*.go.mod' | tr -d '\r' | sort)
+
+for modfile in "${!how[@]}"; do
+  found=0
+  for one in "${seen[@]:-}"; do
+    if [ "$one" = "$modfile" ]; then found=1; fi
+  done
+  if [ "$found" = 0 ]; then
+    echo "=== $modfile"
+    echo "    FAIL: scripts/vulncheck.sh has a row for this module file and git tracks no such file"
+    unscanned+=("$modfile")
+  fi
+done
+
+if [ "${#seen[@]}" = 0 ]; then
+  echo "VERDICT: FAIL (the walk found no module, so nothing was scanned)"
+  exit 1
+fi
+narrowed=""
+if [ "${#narrowings[@]}" != 0 ]; then
+  narrowed=", NARROWED: $(printf '%s; ' "${narrowings[@]}" | sed 's/; $//')"
+fi
+if [ "${#unscanned[@]}" != 0 ] || [ "${#affected[@]}" != 0 ]; then
+  echo "VERDICT: FAIL ($scanned of ${#seen[@]} modules scanned; with a finding: ${affected[*]:-none}; could not be scanned: ${unscanned[*]:-none}$narrowed)"
+  exit 1
+fi
+echo "VERDICT: PASS ($scanned of ${#seen[@]} modules scanned, no finding$narrowed)"
```

- [ ] **Step 2: the opt-in step and the releasing note.**

`test.sh`:

```diff
--- a/test.sh
+++ b/test.sh
@@ -33,7 +33,10 @@
 #   5. protocol/message.pb.go regenerated with the pinned protoc 35.1 and protoc-gen-go v1.36.11, the
 #      generator built under the pinned toolchain;
 #   6. the codec's fuzz targets, 60 s each (a done-when of spec A section 13);
-#   7. the census over what ran: every row's receipts that this host owes.
+#   7. the census over what ran: every row's receipts that this host owes;
+#   8. ONLY WHEN ASKED FOR (MESSAGE_TEST_VULNCHECK=1): govulncheck over every module
+#      (scripts/vulncheck.sh). It is off by default because its verdict moves when the vulnerability
+#      database does, with no commit here, and every step above is a statement about the tree.
 #
 # THE WHOLE RUN IS UNDER THE PINNED TOOLCHAIN, whatever go command the host has. The cryptographic
 # code is reviewed under one compiler, the `toolchain` line of go.mod (mls/pins_test.go holds every
@@ -58,6 +61,8 @@
 #                          Each worker is a process of its own: a 24-core Windows host whose page
 #                          file could not grow ran out of commit memory in a fuzz leg
 #   MESSAGE_TEST_TIMEOUT   per go test invocation (default 3h)
+#   MESSAGE_TEST_VULNCHECK 1 runs step 8, the vulnerability scan; it needs the network. It is run by
+#                          hand before a release (docs/RELEASING.md)
 #   PROTOC                 a protoc 35.1 binary, when none is on PATH (linux and Windows on x86-64
 #                          fetch the pinned release by digest themselves)
 #   WARP_VERSION           the SDK version the native library reports (default 0.0.0-test)
@@ -542,6 +547,11 @@ native
 # ---------------------------------------------------------------- 7. the census over what ran
 run "module census: every row's receipts" bash scripts/module-census.sh --receipts "$receipts"
 
+# ---------------------------------------------------------------- 8. opt-in: the vulnerability scan
+if [ "${MESSAGE_TEST_VULNCHECK:-}" = 1 ]; then
+  run "the vulnerability scan (scripts/vulncheck.sh, asked for by MESSAGE_TEST_VULNCHECK=1)" bash scripts/vulncheck.sh
+fi
+
 # ---------------------------------------------------------------- the verdict
 echo
 echo "================================================================ summary"
```

`docs/RELEASING.md`:

```diff
--- a/docs/RELEASING.md
+++ b/docs/RELEASING.md
@@ -57,3 +57,19 @@ the history with one more merge:
 
 A rebase merge also leaves rewritten copies of the commits on `main`. They stay:
 removing them would need a force push.
+
+## Before a release: the vulnerability scan
+
+`./test.sh` does not read the Go vulnerability database. Its verdict is a
+statement about a tree, and the database moves with no commit here. Before a
+tag, run the scan by hand, on linux with gcc so that the native library is
+scanned as well:
+
+    MESSAGE_TEST_VULNCHECK=1 ./test.sh    # the whole run, the scan last
+    bash scripts/vulncheck.sh             # the scan alone
+
+It prints the tree's commit and the database's own modified time, counts the Go
+files it reads in every module before it reads them, and fails if a module hands
+it none. A finding in the standard library is closed by moving the pinned
+toolchain, the `toolchain` line of the root `go.mod`, with `mls/pins_test.go`'s literal, which is a reviewed change of
+its own: the cryptographic code is reviewed under one compiler.
```

- [ ] **Step 3: check the scripts and the repository's own gates.**

```bash
bash -n scripts/vulncheck.sh && bash -n test.sh
go test -count=1 ./internal/...
```

Measured: both parse, and `internal/layering` and `internal/repository` are `ok`.

- [ ] **Step 4: run the scan once.** It needs the module proxy and vuln.go.dev.

```bash
bash scripts/vulncheck.sh
```

**On the day (R16).** The S0 writer runs this step on `alt-2`, under go1.27.2 and `govulncheck`
v1.9.0, over the S0 tree, and prints that run here, above the lab's. The lab's run below is the
finding R6 ruled on.

Measured on `alt-2`, linux with gcc 13.3.0, on 2026-10-12, over the S0 tree (`393e864b1e19`, the head of the S0 branch on the owner's fork):

```
tree:     393e864b1e1947efc577d1085104cb968ce004d0
tool:     golang.org/x/vuln/cmd/govulncheck@v1.9.0 under go1.27.2
database: {"modified":"2026-10-08T22:31:09Z"}
...
VERDICT: PASS (7 of 8 modules scanned, no finding, NARROWED: sdk/cgo/loopback.go.mod: the loopback harness's modfile: the composed module plus the message server it runs in process, and nothing built from it ships)
```

Measured in the lab on 2026-10-08, on a Windows host with no C compiler, over the base tree
(`lab-s0t1plan/out2/vulncheck-base.txt`):

```
tree:     b41ac05eee4847fb07b90918900ff58e135ee80f
tool:     golang.org/x/vuln/cmd/govulncheck@v1.1.4 under go1.26.5
database: {"modified":"2026-10-08T22:31:09Z"}
...
VERDICT: FAIL (6 of 8 modules scanned; with a finding: sdk/cp3b/go.mod sdk/go.mod sdk/livepeer/go.mod sdk/liveprobe/go.mod; could not be scanned: none, NARROWED: sdk/cgo/go.mod: no C compiler on this windows host; sdk/cgo/loopback.go.mod: the loopback harness's modfile: the composed module plus the message server it runs in process, and nothing built from it ships)
```

**What it found, and it is a finding for the lead and not for this task.** Four `sdk` modules
are reported as affected: 15 vulnerabilities reach `sdk/cp3b`'s tests and 14 reach each of `sdk`,
`sdk/livepeer` and `sdk/liveprobe`, all of them FROM THE STANDARD LIBRARY OF THE PINNED go1.26.5
(for `sdk`: `net/http` eight times, `crypto/tls` twice, `net/textproto`, `net/url`, `os`,
`encoding/asn1`), fixed in go1.26.6 and go1.26.9. Five of them are reported in `golang.org/x/net`
as well, fixed in v0.60.0. The root module and the wire corpus report none: the five foundational
packages reach no affected symbol. The
native library was NOT scanned on that host and the verdict says so. So the scan's first run is
red, for a reason that is real and that this script exists to say: the fix is the toolchain pin.

**Ruled: R6, and R16.** The pin moved to go1.27.2, with `golang.org/x/net` at v0.61.0, in one
reviewed change of its own: urnetwork/message#4, merged as `0bb2128f` before S0. It was not a
task of this plan. THIS SCRIPT'S TOOL IS `govulncheck` v1.9.0 (R16): v1.1.4, the version the lab
ran, panics inside its own `go/ssa` when it reads go1.27's standard library for linux, and the
script then says, correctly, "the tool exited 2, which is not a verdict". On a windows build the
same v1.1.4 ran clean, which is why the scan's runs this plan records are made on `alt-2`. Under
v1.9.0 the second check's scan of the T1 tree passed: 7 of 8 modules scanned and no finding, the
loopback modfile not scanned, by design. So from S0 on `MESSAGE_TEST_VULNCHECK=1` IS EXPECTED TO
PASS, and a red scan is a finding for the lead. The scan is run again at the close of T1
(Task 59), where it must pass.

- [ ] **Step 5: commit.**

```bash
git add scripts/vulncheck.sh test.sh docs/RELEASING.md
git commit -m "scripts: govulncheck over every module, an opt-in step of test.sh"
```

### Task 30: Vector family 16 (deserialization) is installed in the manifest

- Consumes: `mls`'s vector manifest (`RegisterVectorFamily`, `newVectorRunTally`, `assertRun`, `assertVectorFamilyIsInstalled`, `assertInstalledVerifierRefusesAWrongCase`) and package `syntax`'s verifier of the 14 published cases
- Produces: `TestDeserializationKat`, and a manifest whose pending list is `[2 8 9 13 14 15]`

**Serves.** The testing design, 2.1.1, family 16: "a manifest row only".

**Behaviour.** Package `syntax` has verified the 14 cases since it landed, and `mls`'s manifest,
which is the one place that says which of the sixteen families run, did not know. The shim
registers that verifier under number 16 and owes the manifest's accounting.

**Property 1.** The manifest installs family 16: its verifier runs under the manifest's loop, compares every published case and refuses a wrong one, and 16 is not on the pending list.

- [ ] **Step 1: the test first: take 16 off the pending list.**

`mls/vectors_test.go`:

```diff
--- a/mls/vectors_test.go
+++ b/mls/vectors_test.go
@@ -92,22 +92,22 @@ var vectorManifest = baseVectorManifest()
 // 5 and 6 because p4 tasks 17 and 16 register them from key_schedule_kat_test.go,
 // 10 and 11 because p5 tasks 24 and 25 register them from tree_kat_test.go,
 // 7 because p4 task 20 registers it from transcript_kat_test.go, and 3 because p4 task 25
-// registers it from secret_tree_kat_test.go. 16 is still
-// here even though package syntax ships a working runner for it: that runner is not
-// installed in this manifest, and a family verified somewhere this registry cannot see is,
-// as far as this gate is concerned, a family nothing runs. p8 task 8 is the shim.
+// registers it from secret_tree_kat_test.go. 16 left this list when deserialization_kat_test.go
+// installed package syntax's runner in this manifest: until then that runner ran, and a family
+// verified somewhere this registry cannot see is, as far as this gate is concerned, a family
+// nothing runs.
 //
 // 1 left this list when tree_math_kat_test.go landed, and the reason it was still HERE is
 // worth recording, because it is the failure mode this gate has: p3's tree math shipped onto
 // this branch with its corpus vendored and pinned and nothing running it, and this list --
 // written when that code was elsewhere -- reported the family as pending and passed. A family
 // whose implementation has landed is not pending, it is uncovered, and the two are
-// indistinguishable from here. Families 2 and 16 are in that position today: crypto-basics
-// covers RefHash, ExpandWithLabel, DeriveSecret, DeriveTreeSecret, SignWithLabel and
-// EncryptWithLabel, all of which this package declares, and 16's runner exists in package
-// syntax and is not installed here. Both are owned by tasks that are not this one, and both
-// are named here so that "pending" cannot go on meaning two different things silently.
-var expectedPendingFamilies = []int{2, 8, 9, 13, 14, 15, 16}
+// indistinguishable from here. Family 2 is in that position today: crypto-basics covers
+// RefHash, ExpandWithLabel, DeriveSecret, DeriveTreeSecret, SignWithLabel and
+// EncryptWithLabel, all of which this package declares. It is owned by a task that is not
+// this one, and it is named here so that "pending" cannot go on meaning two different things
+// silently.
+var expectedPendingFamilies = []int{2, 8, 9, 13, 14, 15}
 
 // RegisterVectorFamily installs a family runner. Registering a number twice, or a number
 // outside 1 to 16, is a programming error rather than a condition to report: both mean the
```

- [ ] **Step 2: run it and see it fail.** On the tree before the shim: ONLY the pending list is changed, and the manifest's own completeness test is run. The shim is a `_test.go` file too, and it is the CHANGE of this task and not its test; laid over with the test, this step printed a pass. Measured:

```
$ go test -count=1 -run ^TestVectorManifestIsComplete$ ./mls/
exit status 1
--- FAIL: TestVectorManifestIsComplete (0.00s)
    vectors_test.go:262: pending families [2 8 9 13 14 15 16], expected [2 8 9 13 14 15]; update expectedPendingFamilies in the same commit that lands or drops a runner
FAIL
FAIL	github.com/urnetwork/message/mls	0.881s
FAIL
```

- [ ] **Step 3: the change.**

`mls/deserialization_kat_test.go` (new file, 61 lines):

```go
package mls

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/urnetwork/message/syntax"
)

// FAMILY 16, DESERIALIZATION, INSTALLED IN THIS PACKAGE'S MANIFEST.
//
// The comparison is package syntax's, and has been since that package landed:
// [syntax.VerifyDeserializationVector] decodes each published header to the published length with
// the header fully consumed, and encodes the published length back to the published header. What
// was missing is that nothing HERE ran it. This registry is the one place that says which of the
// sixteen families run, and a family verified somewhere the registry cannot see is, as far as gate
// 1 is concerned, a family nothing runs.
//
// So this file is a shim and says so: it registers package syntax's verifier under number 16, and
// it owes the same accounting every other family here owes.
//
// Generate is nil. A header is a function of a length and nothing else, so a generator would be
// the encoder the verify direction already drives.
const deserializationKatFile = "deserialization.json"

// Family 16 is installed here, and 16 is deleted from expectedPendingFamilies in the same commit.
func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   16,
		Verify:   syntax.VerifyDeserializationVector,
		Generate: nil,
	})
}

// deserializationCase is the two published answers of one case, read out of the corpus text by
// this file and not by the verifier it installs.
type deserializationCase struct {
	VlbytesHeader string `json:"vlbytes_header"`
	Length        uint64 `json:"length"`
}

// THE FAMILY'S ACCOUNTING. The corpus publishes no cipher suite, so every case is covered; each
// case is two comparisons, one per direction, against two published answers; and the fourteen
// headers and fourteen lengths are twenty-eight different texts.
func TestDeserializationKat(t *testing.T) {
	tally, entries := newVectorRunTally(t, deserializationKatFile)
	for index, raw := range entries {
		published := deserializationCase{}
		if err := json.Unmarshal(raw, &published); err != nil {
			t.Fatalf("%s case %d does not parse: %v", deserializationKatFile, index, err)
		}
		tally.cover(t)
		syntax.VerifyDeserializationVector(t, raw)
		tally.answer(published.VlbytesHeader)
		tally.answer(strconv.FormatUint(published.Length, 10))
	}
	tally.assertRun(t, 14, 0, 28, 28)
	assertVectorFamilyIsInstalled(t, 16, deserializationKatFile, syntax.VerifyDeserializationVector, nil)
	assertInstalledVerifierRefusesAWrongCase(t, 16, vectorManifest[16])
}
```

- [ ] **Step 4: run it and see it pass.**

```bash
go test -count=1 -run 'TestVectorManifestIsComplete|TestVectorFamiliesVerify|TestDeserializationKat|TestNoVectorRunnerCanSkip' -v ./mls/
```

Measured: `deserialization.json: covered 14 cases at [], skipped 0 at unimplemented suites, 28 comparisons against 28 distinct published answers`, and `10 families verified`. The whole root module with `mls`, on this commit:

```
messagegroup   exit=0 pass=359 fail=0
sdk            exit=0 pass=308 fail=0
cp3b           exit=0 pass=106 fail=0
advsim-strict  exit=1 pass=8 fail=17
root with mls  exit=0 pass=2522 fail=0
```

- [ ] **Step 5: the mutations.**

1. Put `16` back in `expectedPendingFamilies` with the shim in place. Property 1 must fail. Measured: `TestVectorManifestIsComplete` fails, since the list and the manifest disagree in the other direction; it is the same comparison that fails in step 2.
2. Hand the installed verifier a published case with one octet changed. Property 1 must fail. It is what `assertInstalledVerifierRefusesAWrongCase` does on every run of the shim, so a verifier that compares nothing does not pass.

- [ ] **Step 6: commit.**

```bash
git add mls/deserialization_kat_test.go mls/vectors_test.go
git commit -m "mls: vector family 16 is installed in the manifest"
```

### Task 31: Close S0: the full run on both hosts, the ledger, the report, the pull request

- Consumes: every S0 task, Task 2 to Task 30
- Produces: the S0 pull request, a ledger entry and a status row in `message-server`, and the owner's first report

This task changes no file of this repository and states no property.

- [ ] **Step 1: the full run, on both hosts (R8).** On linux with gcc, on the host `alt-2` (the race detector, the composed native library and `sdk/cgo`, `nm`, the pinned protoc), and on Windows from a clone made with `core.autocrlf=true`. Neither was run in the lab, which has no C compiler. The verdicts are R8's, as R15 words them. `alt-2` prints `VERDICT: PASS, narrower than the full run (above)` with exactly one narrowing, the loopback library's C consumer, which is a Windows program. The Windows run is the `windows` leg of Step 2 (a `core.autocrlf=true` clone on GitHub's Windows runner, MinGW-w64 gcc on `PATH`), and it prints `VERDICT: PASS`, or the narrowed verdict with exactly one narrowing, the C consumer's second pass under ThreadSanitizer. Any other narrowing, or a second one, stops the close; a run on a host with no C compiler ends `VERDICT: FAIL` by design and is not this run. Print every narrowing line each run lists, and hold the set to the allowed one both ways. Both runs are under the toolchain pin of the day (R6), and the numbers this phase reports are these runs' numbers.

```bash
./test.sh
```

- [ ] **Step 2: the fork's workflow, all four legs (R8, R11).** Run `fork-ci.yml` on the branch head, on the owner's fork, with all four legs, and wait for four green legs. The fourth is the provenance leg in R11's form: the recorded tip of the import's proof (the head of the pins switch) is an ancestor of this branch, and the proof passes AT that tip. THIS PHASE ADDS NO ROW TO `docs/history/adaptations.tsv` AND CHANGES NO FILE UNDER `docs/history`. The leg's change landed with the pins switch: it holds the recorded tip `7a33917306ae` (`docs/history/recorded-tip.txt`) and runs that tip's own proof, and it is green on `0bb2128f` (fork run 38290870884). If it is red on a phase head, that is a finding for the lead, and no row is improvised to make it pass. The workflow file is fork-only and is in no upstream pull request.

- [ ] **Step 3: the pull request.** From a branch CUT FROM `urnetwork/message` `main`, pushed to the fork, to `urnetwork/message` main: merge commit only, never force-pushed (`README.md`, Contributing). When `main` moves, `main` is merged into the branch. Its description carries the two verdict lines, the id of the fork's run with its four legs, and the RED report of Task 27 as the branch printed it.

- [ ] **Step 4: the ledger and the status row (message-server writer, R7).** The same writer as Task 1, in its own small pull request to urnetwork/message-server, paired with this phase; the owner is told to merge that one first. A ledger entry for the close, and the program plan's status table: S0.2 (the harness) is "landed for the join path", with the list under "Not in S0" as what its own plan still owes; S0.3 is "pin file and scan landed; document fixes owed"; S0.4 is "family 16 installed".

- [ ] **Step 5: the report.** Send "At the end of S0" from the section "Reports to the owner", with the numbers of the runs made on the branch, under the compiler of the day, in place of the lab's.

**Not in S0, and where each lives.** This phase is the JOIN-PATH part of the testing design's
harness and the part of its quick fixes that has a home in this repository. The rest is deferred
by name:

| Testing design item | Where it lives | Status here |
|---|---|---|
| Vector families 2, 9 and 8 | `mls/`, the testing track's own state-machine-vectors plan | NOT IN THIS PLAN (the lead's ruling). Each is a real runner, not a shim: family 1's is 724 lines, and family 8 needs an independent oracle that does not exist yet. |
| Families 13, 14, 15 | `mls/` | need a production change (`joinRelaxations`), the testing design's owner question 1 and a red team before code |
| The harness's other properties: P2a and P2b (the swapper claiming an identity), P2-c1, P2-c2, P3a and P3b (a snapshot after a self-update), P5, P6, P7, P9, P10, the six random schedules, the archive handler | `sdk/cp3b`, the testing track's own harness plan | not written here. The program asks the first harness to be red for all three protocol tracks. It is red here for the join seal (14 scenarios), for the identity track (`S3-mg1-join-code-substitution`, `S7g-removed-group-second-founder`) and, at rest only, for the healing track (`S4-state-thief`). A snapshot that reads after the next commit is NOT here: it needs the self-update hook the healing track builds. |
| A direct case for the quantum grant's rule (an invitation alone is answered "not granted") | `sdk/cp3b`, the testing track's own harness plan | one test. Without it the harness mutant `HV6` is killed on the S0 tree and SURVIVES on the T1 tree; "Mutation proofs" says why |
| 2.5.1 the X-Wing pin text, 2.5.2 MASTER section 7, 2.5.3 the public statement, 2.5.4 MASTER and Spec A text | `message-server`, `docs/specs/` and `docs/SECURITY-POSTURE.md` | LISTED ONLY (the lead's ruling): a separate small task for the message-server writer. This repository's README gains a link once that document exists. |
| 2.5.5 `govulncheck.yml`, 2.5.6 `dependabot.yml`, the fuzz workflows, the nightly jobs | a CI service | `urnetwork/message` has none; the owner's fork runs `fork-ci.yml` on request, and that workflow is fork-only (R8, R11). Task 29 is the part that survives. Dependabot needs a repository admin. |
| 2.3 the `req_auth` known-answer file | `protocol/` here and the server | independent of the join path; the testing track's own task |
| The testing design's owner questions 1 to 11 | the testing track's plan | not answered here, and S0 depends on none of them |

---

# Phase T1a: an invitation cannot replace a group the device holds as a member, and a refusal costs nothing

T1a changes no format and no wire octet. It is four changes because the lab measured four
separate effects, and a fifth commit that files a defect and changes no behaviour (R10, R14). One
of its tasks is the app's, and comes before any app package is built on a T1a library (R13). The
first of the four changes was reworked for this revision (R12): as it stood at the final check, one
group record that did not read stopped the device joining, founding or leaving anything.

The design's Q9 says the held-group gate "is sdk-only". Measured: the sdk-only
gate closes five scenarios and leaves `S7c` open, because the engine joins the group the WELCOME
names. Closing `S7c` needs the join bound to the invitation's group id inside the engine.

**What T1a does not close, and says so.** A group a commit REMOVED this device from may be joined
again, because being added back is the repair a removal names. An invitation does not say who made
it, so a second founder's invitation above the removal's epoch is honoured too
(`S7g-removed-group-second-founder`, open until the identity track). "An invitation cannot replace
a held group" is true of a group the device holds AS A MEMBER, and of no other.

### Task 32: Amend Spec A section 6 for the engine's bound door (message-server writer)

- Consumes: Spec A section 6's `GroupEngine` block, which `TestTheEngineInterfacesAreExactlySectionSixsBlock` says it transcribes; the lead's ruling that the interface change is acceptable in T1a
- Produces: a section 6 that declares `JoinFromWelcomeInto`, its ledger entry, and the spec's own edit-log row

**Why this is a task, and why it is first.** Task 34 adds a sixth method to an interface Spec A
defines. The program's third gate is a diff review and a ledger entry for every spec change, in the
same commit, and the spec moves before the code it is the authority for.

**Whose it is, and how it lands (R7).** The message-server writer's, the same one as Task 1: its own
small pull request to urnetwork/message-server, paired with phase T1a, and the owner is told to
merge it first.

- [ ] **Step 1: the edit.** In `docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md`, section 6,
  the `GroupEngine` block gains:
  `JoinFromWelcomeInto(welcome []byte, ratchetTree []byte, groupId []byte) (GroupHandle, error)`,
  with one paragraph: it is `JoinFromWelcome` with the group id its caller means to join, matched
  inside `mls` ahead of the persist; an empty id is refused (`ErrEngineJoinGroupId`); it
  authenticates nobody, exactly as the first door (MG-1). The block's count goes from five methods
  to six; the handle's 35 are untouched.
- [ ] **Step 2: the edit-log row and the ledger entry**, in the same commit, as `editlog_test.go`
  holds.
- [ ] **Step 3: a subagent diff review**, then commit.

### Task 33: The held-group gate, under one admission mutex; a group that does not restore can be left; and one record that does not read costs its own group and no other

- Consumes: the scenarios of Task 19, Task 20, Task 22, Task 23, Task 24 and the control of Task 26; `Device.finishLeaveBefore`, `DeviceStore.GroupRecords`, `DeviceStore.GroupsBeingForgotten`, `Group.Removal`
- Produces: `ErrGroupAlreadyHeld`, `ErrReaddStale`, `ErrGroupNotRestored`, `ErrGroupRecordDamaged`, `joinOverHeldGroup`, `foundOverHeldGroup`, `heldUnread`, `hold`, `holdReplacing`, `admitMutex`, `noteUnrestored`, `didNotRestore`, `forgetUnrestored`, `recordOnDisk`, the one-id read `GroupRecord` on the interface of the device store, `groupRecordInLocked`, the scenario `S7-c2-unreadable-record-costs-one-group`, and the test helpers `newAnsweringDeviceOver`, `advDamageRecord`, `advHeard` and `overlapping`

**Behaviour.** Before the join code is touched, `Join` asks whether the device holds the group
the invitation names: in memory, and on its disk. If it does, the invitation is refused with
`ErrGroupAlreadyHeld`. One exception: a group a commit REMOVED this device from may be joined
again, and then only at an epoch above the removal (`ErrReaddStale`).

**The question and the hold that answers it are ONE critical section** (the security review's
first finding, measured: with the gate asked above the join's lock, two overlapping joins into one
group id both read "not held", and the second replaced the first). `Device.admitMutex` is held by
`Join`, `CreateGroup` and `Restore` from the question to the map entry. `holdReplacing` replaces
exactly the group the gate judged and nothing else, and `hold` never replaces; `CreateGroup` asks
the same question with no exception, before `mls` writes an epoch zero under the id. THE LOCK IS
HELD BY A TEST ON EACH OF THE THREE CALLS (R12, the final check's F5): the order is forced by a
store that says when an admission reads the disk, and each call has the mutant that takes its lock
away.

**A refusal names a remedy that exists** (the review's second finding, measured: a group whose
record is on the disk and whose state does not load could be neither restored, left nor joined
again, because `ForgetGroup` refused a group that is not in memory). `Restore` remembers the
groups it could not bring back, and `ForgetGroup` leaves one of those: the mark, then the erase.
The owner's refusal is not asked of it, because the roster is read off a live group and this one
has none (confirmed: R9). A group on the disk that no `Restore` has tried answers
`ErrGroupNotRestored`, so that a restart is not a way round the owner's refusal.

**ONE GROUP RECORD THAT DOES NOT READ COSTS ITS OWN GROUP AND NO OTHER (R12).** As this plan stood
at its final check, the gate, a founding and `ForgetGroup` each asked the store for EVERY group
record, and the store answered an error and no list when any one record failed its checksum. One
damaged file then stopped the device joining, founding or leaving anything, and no call cleared it
(measured by the final check: the base tree still joined and founded; the T1a tree did not). This
task is the repair, and it is five things:

- **The store answers about ONE group.** `DeviceStore` gains `GroupRecord(groupId)`: the record;
  `ErrStateNotFound` when the store holds none, or the group is being left; an error carrying
  `ErrGroupRecordDamaged` when a record is there and does not read; and any other error when the
  store could not answer at all. The gate, a founding and `recordOnDisk` ask that, so a record
  that does not read refuses only an invitation into its own group.
- **The list tolerates a record that does not read**, and reports it BESIDE the records that do:
  the shape `GroupsBeingForgotten` already has. The list and the one-id read go through one
  function, and a record is answered only from the directory it names, so the two cannot disagree
  about a group.
- **`Restore` goes on past such a record.** It restores the others, and the damaged record is its
  first failure, inside `ErrRestore`. THIS CHANGES BEHAVIOUR THAT WAS THERE BEFORE THE PLAN, ON
  PURPOSE: before, `Restore` returned on the list's error with no group at all.
- **`ForgetGroup` leaves a group whose record does not read**, with no `Restore` having to try
  first: the read it makes of that one record is the attempt, a record that does not read never
  restores, and there is no roster to ask the owner's question of. The gate's refusal of an
  invitation into such a group is `ErrGroupAlreadyHeld`, whose own sentence names `ForgetGroup`,
  carrying `ErrGroupRecordDamaged`, whose sentence names it again.
- **A record that does not read is a HELD group, and a store that cannot answer is a refusal.**
  Neither is "not held", which is the one answer that lets a join or a founding write (the final
  check's F6: two mutants that read them as "not held" survived every suite).

**What R12 asks that this store cannot give, said plainly.** R12 has the listing report a damaged
record "with its group id where the store's own naming gives one". `DurableStateStore` names a
group's directory by the SHA-256 of its id (`stateNameOf`), which cannot be turned back into an
id, and the id inside a record that does not read is not one to believe. So the list names a
damaged record BY ITS DIRECTORY, `Restore` reports it by that name, and nothing is added to the
device's memory of groups that did not restore. It costs nothing a caller needs: `ForgetGroup` and
the gate reach the group by the id the caller holds, which for a person is the id in the
invitation they were refused over.

**Property 1.** An invitation into a group this device holds as a member, in memory or as a record on its disk, is refused with `ErrGroupAlreadyHeld` before the join code is touched, and nothing of the held group changes.

**Property 2.** Two joins into one group id that overlap admit exactly one: the second finds the group held.

**Property 3.** A map entry is replaced only by the join that judged it, and a group is founded only under an id the device holds nothing for.

**Property 4.** A re-add at or below the epoch of the removal is refused with `ErrReaddStale`, and the founder's own later re-add still joins.

**Property 5.** A group `Restore` could not bring back is left by `ForgetGroup` and can then be joined again; a group no `Restore` has tried is not left that way.

**Property 6.** One group record that does not read costs its own group and no other: every other group restores and the damage is reported; an invitation into another group joins and a fresh id founds; a founding under the damaged group's id and an invitation into it are refused while the record stands; and `ForgetGroup` leaves that group, and that group alone, after which the same invitation joins.

**Property 7.** A store that cannot answer for a group refuses the join and the founding of that group and of no other; and the store answers a record only from the directory it names, in its list and by one id alike.

**Property 8.** A `Restore` and a founding that start while a join is inside the gate wait for it: the admission mutex is held by all three calls.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/heldgroup_test.go` (new file, 148 lines):

```go
package urmessage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	messageprotocol "github.com/urnetwork/message/protocol"
)

// THE HELD-GROUP GATE, at the device: an invite into a group this device holds is refused before
// the join code is touched, whoever built it, and the group it holds is the same object afterwards.
func TestAnInviteIntoAGroupThisDeviceHoldsIsRefused(t *testing.T) {
	ctx := context.Background()
	alice, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
	mallory, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("mallory's nonce"))
	for _, device := range []*Device{alice, bob, mallory} {
		if err := device.Connect(ctx); err != nil {
			t.Fatalf("Connect: %v", err)
		}
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	add := func(founder *Device) *Invite {
		group, err := founder.CreateGroup(ctx, groupId)
		if err != nil {
			t.Fatalf("CreateGroup: %v", err)
		}
		joinCode, err := bob.KeyPackage()
		if err != nil {
			t.Fatalf("bob's KeyPackage: %v", err)
		}
		invite, err := group.AddMember(joinCode)
		if err != nil {
			t.Fatalf("AddMember: %v", err)
		}
		return invite
	}
	honest := add(alice)
	held, err := bob.Join(ctx, honest)
	if err != nil {
		t.Fatalf("bob's Join over the honest invite: %v", err)
	}

	// the same invite again, and then a hostile founder's invite under the same group id
	if _, err := bob.Join(ctx, honest); !errors.Is(err, ErrGroupAlreadyHeld) {
		t.Errorf("the same invite a second time answered %v, want ErrGroupAlreadyHeld", err)
	}
	if _, err := bob.Join(ctx, add(mallory)); !errors.Is(err, ErrGroupAlreadyHeld) {
		t.Errorf("a second founder's invite under a held group id answered %v, want ErrGroupAlreadyHeld", err)
	}
	groups := bob.Groups()
	if len(groups) != 1 || groups[0] != held {
		t.Fatalf("bob holds %d group(s) after two refused invites, and the one it joined is no longer among them", len(groups))
	}
	if epoch := held.Epoch(); epoch != 1 {
		t.Errorf("the held group stands at epoch %d after two refused invites, want 1", epoch)
	}
}

// A MAP ENTRY IS REPLACED ONLY BY THE JOIN THAT JUDGED IT. hold never replaces, and holdReplacing
// replaces the one group it is told the gate judged and no other. Both are the second line behind
// the admission mutex: what they refuse cannot happen while every admission is inside that mutex,
// and this is the case that says they do refuse it.
//
// WHAT WOULD GO RED: let either write the map without looking, which is what both did before, and
// a group nobody judged takes the place of a live one.
func TestAMapEntryIsReplacedOnlyByTheJoinThatJudgedIt(t *testing.T) {
	ctx := context.Background()
	device, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("a nonce"))
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	held, err := device.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	incoming := &Group{id: bytes.Clone(groupId)}
	bystander := &Group{id: bytes.Clone(groupId)}
	for _, one := range []struct {
		name string
		file func() error
	}{
		{"hold, over a live group", func() error { return device.hold(incoming) }},
		{"holdReplacing, judged against no group", func() error { return device.holdReplacing(incoming, nil) }},
		{"holdReplacing, judged against some other group", func() error { return device.holdReplacing(incoming, bystander) }},
	} {
		if err := one.file(); !errors.Is(err, ErrGroupAlreadyHeld) {
			t.Errorf("%s answered %v, want ErrGroupAlreadyHeld", one.name, err)
		}
		if groups := device.Groups(); len(groups) != 1 || groups[0] != held {
			t.Fatalf("%s: the device no longer holds the group it held", one.name)
		}
	}

	// THE CONTROL: judged against the group that IS there, it replaces it and closes it.
	if err := device.holdReplacing(incoming, held); err != nil {
		t.Fatalf("CONTROL FAILED: holdReplacing judged against the held group answered %v", err)
	}
	if groups := device.Groups(); len(groups) != 1 || groups[0] != incoming {
		t.Fatalf("CONTROL FAILED: the device does not hold the group that replaced the held one")
	}
	held.mutex.Lock()
	closed := held.closed
	held.mutex.Unlock()
	if !closed {
		t.Errorf("the replaced group was left open: its session and its epoch's secrets are still live")
	}
	// the stand-in has no session to close, so it leaves the map before the device closes
	device.drop(groupId, incoming)
}

// NOTHING IS FOUNDED UNDER AN ID THIS DEVICE HOLDS. Founding writes an epoch-zero state under the
// id and files a group in the map, so a second founding under one id is the first group replaced.
func TestNoGroupIsFoundedUnderAnIdThisDeviceHolds(t *testing.T) {
	ctx := context.Background()
	device, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("a nonce"))
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	held, err := device.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	before, err := device.stateStore.GetGroupState(groupId, 0)
	if err != nil || len(before) == 0 {
		t.Fatalf("CONTROL FAILED: the store holds no epoch-zero state for the group just founded: %v", err)
	}
	before = bytes.Clone(before)
	if _, err := device.CreateGroup(ctx, groupId); !errors.Is(err, ErrGroupAlreadyHeld) {
		t.Fatalf("a second founding under a held id answered %v, want ErrGroupAlreadyHeld", err)
	}
	if groups := device.Groups(); len(groups) != 1 || groups[0] != held {
		t.Fatalf("the device no longer holds the group it founded first")
	}
	// REFUSED BEFORE THE MLS GROUP WAS MADE, which is the half the map cannot show: a founding
	// refused only at the hold has already written a second group's epoch zero over the first's.
	if after, err := device.stateStore.GetGroupState(groupId, 0); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("the refused founding replaced the held group's epoch-zero state in the store (%v)", err)
	}
	// THE CONTROL: any other id founds
	if _, err := device.CreateGroup(ctx, bytes.Repeat([]byte{0x48}, GroupIdBytes)); err != nil {
		t.Fatalf("CONTROL FAILED: founding under an id the device does not hold answered %v", err)
	}
}
```

`sdk/urmessage/heldrecord_test.go` (new file, 245 lines):

```go
package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/message/mls"
	messageprotocol "github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk"
)

// THE HELD-GROUP GATE AND THE DISK: what the device asks its store about ONE group, and what it
// does with each of the three things a store can answer that are not a record: "I hold none", "the
// record I hold does not read", and no answer at all.

// ONE RECORD THAT DOES NOT READ IS ONE GROUP'S, AT THE STORE. Three groups are on the disk and one
// record is cut to half its length. The list still answers the other two, and reports the third
// beside them by its directory; the one-id read answers "does not read" for that group and for no
// other. Then the states that are NOT damage, and one more that is: a group that was never there,
// a group being left, a record that reads and names another group, and a store that cannot answer.
//
// WHAT WOULD GO RED: answer an error and no list over one record that does not read, and a device
// loses every group it holds at its next Restore; hold a record under a directory it does not
// name, and the list holds a group the one-id read answers "not held" for.
func TestOneRecordThatDoesNotReadIsReportedByTheListAndAnsweredOnlyForItsOwnGroup(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	whole := bytes.Repeat([]byte{0x41}, GroupIdBytes)
	damaged := bytes.Repeat([]byte{0x42}, GroupIdBytes)
	other := bytes.Repeat([]byte{0x43}, GroupIdBytes)
	for _, groupId := range [][]byte{whole, damaged, other} {
		if err := store.PutGroupRecord(&GroupRecord{
			GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
		}); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
	}
	if records, err := store.GroupRecords(); err != nil || len(records) != 3 {
		t.Fatalf("CONTROL FAILED: before any damage the list answers %d record(s), %v", len(records), err)
	}
	path := store.groupRecordPath(damaged)
	octets, err := os.ReadFile(path)
	if err != nil || len(octets) < 2 {
		t.Fatalf("reading the record about to be damaged: %d octets, %v", len(octets), err)
	}
	if err := os.WriteFile(path, octets[:len(octets)/2], 0o600); err != nil {
		t.Fatalf("cutting the record to half its length: %v", err)
	}
	idsOf := func(records []*GroupRecord) string {
		ids := []string{}
		for _, record := range records {
			ids = append(ids, string(record.GroupId[:1]))
		}
		return strings.Join(ids, "")
	}

	// THE LIST: the two that read, and the third reported beside them by its directory
	records, err := store.GroupRecords()
	if !errors.Is(err, ErrGroupRecordDamaged) {
		t.Fatalf("the list over one record that does not read answered %v, want an error carrying ErrGroupRecordDamaged", err)
	}
	if got := idsOf(records); got != "AC" && got != "CA" {
		t.Fatalf("the list answered the records of %q beside its report, want the two that read", got)
	}
	if !strings.Contains(err.Error(), stateNameOf(damaged)) || strings.Contains(err.Error(), stateNameOf(whole)) ||
		strings.Contains(err.Error(), stateNameOf(other)) {
		t.Errorf("the report does not name the directory of the record that does not read, and that one alone: %v", err)
	}

	// THE ONE-ID READ: "does not read" for that group, the record for the others, "none" for a fourth
	if _, err := store.GroupRecord(damaged); !errors.Is(err, ErrGroupRecordDamaged) || errors.Is(err, ErrStateNotFound) {
		t.Errorf("the one-id read of the damaged group answered %v, want ErrGroupRecordDamaged", err)
	}
	for _, groupId := range [][]byte{whole, other} {
		if record, err := store.GroupRecord(groupId); err != nil || !bytes.Equal(record.GroupId, groupId) {
			t.Errorf("the one-id read of a group whose record reads answered %v, beside another group's damage", err)
		}
	}
	if _, err := store.GroupRecord(bytes.Repeat([]byte{0x44}, GroupIdBytes)); !errors.Is(err, ErrStateNotFound) || errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the one-id read of a group this store never held answered %v, want ErrStateNotFound", err)
	}

	// A GROUP BEING LEFT is not one this store holds a record for, by its id or in the list
	if err := store.MarkGroupForgetting(other); err != nil {
		t.Fatalf("MarkGroupForgetting: %v", err)
	}
	if _, err := store.GroupRecord(other); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the one-id read of a group being left answered %v, want ErrStateNotFound", err)
	}
	if records, _ := store.GroupRecords(); idsOf(records) != "A" {
		t.Errorf("the list answers the records of %q with one group being left and one damaged, want the one that is neither", idsOf(records))
	}

	// A RECORD THAT READS AND NAMES ANOTHER GROUP IS DAMAGE TOO. The whole group's record is copied
	// into the damaged group's directory. Answered by the list, it would be a second record of the
	// whole group, in a directory the one-id read reaches by another id.
	copied, err := os.ReadFile(store.groupRecordPath(whole))
	if err != nil {
		t.Fatalf("reading the whole group's record: %v", err)
	}
	if err := os.WriteFile(path, copied, 0o600); err != nil {
		t.Fatalf("copying it into the other group's directory: %v", err)
	}
	if _, err := store.GroupRecord(damaged); !errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the one-id read of a directory holding another group's record answered %v, want ErrGroupRecordDamaged", err)
	}
	if records, err := store.GroupRecords(); !errors.Is(err, ErrGroupRecordDamaged) || idsOf(records) != "A" {
		t.Errorf("the list over a directory holding another group's record answered the records of %q and %v, want one record and the damage reported", idsOf(records), err)
	}

	// AND A STORE THAT CANNOT ANSWER says neither "none" nor "does not read"
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := store.GroupRecord(whole); !errors.Is(err, ErrStateStoreState) || errors.Is(err, ErrStateNotFound) || errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the one-id read on a closed store answered %v, want ErrStateStoreState and neither of the two answers a caller acts on", err)
	}
}

// newAnsweringDeviceOver is [newAnsweringDevice] over a state store of the caller's, connected.
func newAnsweringDeviceOver(t *testing.T, store mls.StateStore, nonce []byte) *Device {
	t.Helper()
	client := &answeringClient{reason: messageprotocol.Reason_REASON_OK, nonce: nonce}
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          client,
		Server:          connect.NewId(),
		ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("sdk.NewMessageTransport: %v", err)
	}
	t.Cleanup(transport.Close)
	streamStore, err := sdk.OpenStreamStore(t.TempDir())
	if err != nil {
		t.Fatalf("sdk.OpenStreamStore: %v", err)
	}
	t.Cleanup(func() { streamStore.Close() })
	device, err := NewDevice(DeviceConfig{
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: store,
		Connect: ConnectPolicy{
			Budget:         30 * time.Second,
			AttemptTimeout: 2 * time.Second,
			FirstBackoff:   200 * time.Millisecond,
			MaxBackoff:     200 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	t.Cleanup(func() { device.Close() })
	if err := device.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return device
}

// deafStore is a durable store that cannot answer for ONE group id: its one-id read fails there,
// as a disk that will not be read does, and is the store's own for every other id.
type deafStore struct {
	*DurableStateStore
	deafTo []byte
}

func (self *deafStore) GroupRecord(groupId []byte) (*GroupRecord, error) {
	if bytes.Equal(groupId, self.deafTo) {
		return nil, errors.New("the store this test sits on cannot answer for this group")
	}
	return self.DurableStateStore.GroupRecord(groupId)
}

// A STORE THAT CANNOT ANSWER IS A REFUSAL, FOR THAT GROUP AND FOR NO OTHER. "Not held" is the one
// answer that lets a join or a founding write, so a store that fails to answer must never be read
// as it. An honest invite into the group the store cannot answer for is refused before the join
// code is touched; a founding under its id is refused before mls writes an epoch zero; and the
// same device, over the same store, joins another group and founds under a third id.
//
// WHAT WOULD GO RED: read any answer but a record as "not held", in the gate or in the founding's
// question, and a group held only on the disk is written over whenever the read of it fails.
func TestAStoreThatCannotAnswerRefusesTheJoinAndTheFoundingOfThatGroupAndOfNoOther(t *testing.T) {
	ctx := context.Background()
	durable := openTestStore(t, t.TempDir())
	store := &deafStore{DurableStateStore: durable}
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	inviteInto := func(groupId []byte) *Invite {
		founder, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("a founder's nonce"))
		if err := founder.Connect(ctx); err != nil {
			t.Fatalf("a founder's Connect: %v", err)
		}
		group, err := founder.CreateGroup(ctx, groupId)
		if err != nil {
			t.Fatalf("a founder's CreateGroup: %v", err)
		}
		joinCode, err := device.KeyPackage()
		if err != nil {
			t.Fatalf("the device's KeyPackage: %v", err)
		}
		invite, err := group.AddMember(joinCode)
		if err != nil {
			t.Fatalf("a founder's AddMember: %v", err)
		}
		return invite
	}
	deaf := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	store.deafTo = deaf
	honest := inviteInto(deaf)

	// THE JOIN: refused as a store that could not answer, and nothing of the group was written
	_, err := device.Join(ctx, honest)
	if err == nil || errors.Is(err, ErrGroupAlreadyHeld) || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("an invite into a group the store cannot answer for answered %v, want a refusal that says it could not be read and does not say the group is held", err)
	}
	if held := len(device.Groups()); held != 0 {
		t.Errorf("the refused join left the device holding %d group(s)", held)
	}
	if _, err := durable.GetGroupState(deaf, 1); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the refused join left an epoch state on the disk for the group it refused: %v", err)
	}
	// THE FOUNDING: refused, and before mls wrote an epoch zero under the id
	if _, err := device.CreateGroup(ctx, deaf); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("a founding under an id the store cannot answer for answered %v, want a refusal that says it could not be read", err)
	}
	if _, err := durable.GetGroupState(deaf, 0); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the refused founding left an epoch-zero state on the disk: %v", err)
	}

	// THE CONTROL, which is also the other half of the property: no other group is refused by it
	if _, err := device.Join(ctx, inviteInto(bytes.Repeat([]byte{0x48}, GroupIdBytes))); err != nil {
		t.Fatalf("CONTROL FAILED: an invite into another group, over the same store, answered %v", err)
	}
	if _, err := device.CreateGroup(ctx, bytes.Repeat([]byte{0x49}, GroupIdBytes)); err != nil {
		t.Fatalf("CONTROL FAILED: a founding under another id, over the same store, answered %v", err)
	}
	// AND THE REFUSAL COST NOTHING: once the store answers, the same invite joins
	store.deafTo = nil
	if _, err := device.Join(ctx, honest); err != nil {
		t.Errorf("the same invite, once the store answers for its group, answered %v: the refusal spent the join code", err)
	}
}
```

`sdk/cp3b/heldgroup_test.go` (new file, 442 lines):

```go
package cp3b

import (
	"bytes"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
)

// THE HELD-GROUP GATE AGAINST THE REAL SERVER: the cases the adversary scenarios cannot hold,
// because each needs something a scenario does not have. Two admissions that overlap need a store
// that says where each of them is; the stale re-add needs a removal at one epoch and an invitation
// below it; and the group that does not restore, and the one whose record does not read, need
// each of ForgetGroup's answers read.

// gateWatch is a durable store that says when an ADMISSION reads the disk, and holds that read
// where it stands until it is let go. Two reads are watched, and every other method is the
// store's own: the one-id read the held-group gate and a founding make, and the first read a
// Restore makes, which is for the leaves it has to finish. It is how a case puts one join INSIDE
// the gate and then starts a second admission, with no sleep deciding who got where.
type gateWatch struct {
	*urmessage.DurableStateStore
	armed   atomic.Bool
	asked   chan struct{}
	release chan struct{}
}

func (self *gateWatch) hold() {
	if self.armed.Load() {
		self.asked <- struct{}{}
		<-self.release
	}
}

func (self *gateWatch) GroupRecord(groupId []byte) (*urmessage.GroupRecord, error) {
	self.hold()
	return self.DurableStateStore.GroupRecord(groupId)
}

func (self *gateWatch) GroupsBeingForgotten() ([][]byte, error) {
	self.hold()
	return self.DurableStateStore.GroupsBeingForgotten()
}

// watchedDevice is a device over a gateWatch, against the world's real server.
func watchedDevice(t *testing.T, world *world, name string) (*urmessage.Device, *gateWatch) {
	t.Helper()
	root := t.TempDir()
	client := world.connectClient(t)
	transport := world.transport(t, client)
	streamStore, err := sdk.OpenStreamStore(filepath.Join(root, name, "stream"))
	if err != nil {
		t.Fatalf("%s: sdk.OpenStreamStore: %v", name, err)
	}
	inner, err := urmessage.OpenDurableStateStore(filepath.Join(root, name, "state"))
	if err != nil {
		t.Fatalf("%s: urmessage.OpenDurableStateStore: %v", name, err)
	}
	watch := &gateWatch{DurableStateStore: inner, asked: make(chan struct{}, 8), release: make(chan struct{})}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: watch,
	})
	if err != nil {
		t.Fatalf("%s: urmessage.NewDevice: %v", name, err)
	}
	t.Cleanup(func() {
		device.Close()
		inner.Close()
		streamStore.Close()
		transport.Close()
		client.Close()
	})
	return device, watch
}

// TWO JOINS INTO ONE GROUP ID THAT OVERLAP ADMIT EXACTLY ONE. The honest invitation is a live add,
// at epoch 2; the other is a second founder's group under the same id, at epoch 1. They stand at
// two epochs on purpose: the create-only commit refuses a second join only at an epoch the first
// already wrote, so at two epochs the gate is the only thing in the way.
//
// THE ORDER IS FORCED AND NOT TIMED. The first join is stopped inside the gate, at its reading of
// the disk. The second is then started. If it too reaches the gate while the first is still in it,
// both have read "not held" and the case fails there, by name. If it does not, it is waiting for
// the first, which is let go; the second then finds the group held.
//
// WHAT WOULD GO RED: ask the gate above the admission mutex, and both joins are in the gate at
// once; whichever writes its record second writes over the first.
func TestTwoJoinsIntoOneGroupIdThatOverlapAdmitExactlyOne(t *testing.T) {
	scene := advFounding(t, true)
	dave, watch := watchedDevice(t, scene.world, "dave")
	if err := dave.Connect(scene.ctx); err != nil {
		t.Fatalf("dave's Connect: %v", err)
	}
	joinCode, err := dave.KeyPackage()
	if err != nil {
		t.Fatalf("dave's KeyPackage: %v", err)
	}
	added, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		t.Fatalf("alice's AddMemberAndPublish: %v", err)
	}
	honest := gcReencodeInvite(t, added)
	hostile, err := urmessage.ParseInvite(advHostile(t, scene, dave))
	if err != nil {
		t.Fatalf("the second founder's invite does not parse: %v", err)
	}

	type answer struct {
		group *urmessage.Group
		err   error
	}
	first, second := make(chan answer, 1), make(chan answer, 1)
	watch.armed.Store(true)
	go func() {
		group, err := dave.Join(scene.ctx, honest)
		first <- answer{group, err}
	}()
	select {
	case <-watch.asked:
	case <-time.After(10 * time.Second):
		t.Fatal("the first join never reached the gate's reading of the disk, so nothing below is about two joins")
	}
	go func() {
		group, err := dave.Join(scene.ctx, hostile)
		second <- answer{group, err}
	}()
	select {
	case <-watch.asked:
		t.Errorf("the second join reached the held-group gate while the first was still inside it: both have read \"not held\"")
	case <-time.After(500 * time.Millisecond):
		// the second join is waiting for the first, which is the property
	}
	watch.armed.Store(false)
	close(watch.release)
	honestAnswer, hostileAnswer := <-first, <-second

	if honestAnswer.err != nil {
		t.Fatalf("the honest invite, which was first, answered %v", honestAnswer.err)
	}
	if !errors.Is(hostileAnswer.err, urmessage.ErrGroupAlreadyHeld) {
		t.Errorf("the second founder's invite, which overlapped the first, answered %v, want ErrGroupAlreadyHeld", hostileAnswer.err)
	}
	if held := dave.Groups(); len(held) != 1 || held[0] != honestAnswer.group {
		t.Fatalf("dave holds %d group(s) and the one the honest invite joined is not the one he holds", len(held))
	}
	// THE DISK, which is where the second join's damage would be: one record, at the honest epoch
	records, err := watch.DurableStateStore.GroupRecords()
	if err != nil || len(records) != 1 {
		t.Fatalf("dave's store holds %d record(s): %v", len(records), err)
	}
	if !bytes.Equal(records[0].GroupId, scene.groupId) || records[0].Epoch != 2 {
		t.Fatalf("dave's record names epoch %d, and the honest invite joined epoch 2: the second join wrote its record over the first's", records[0].Epoch)
	}
	// and the group he holds is the real one: it reads what the real founder seals next
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", honestAnswer.group, canary)
}

// overlapping puts one join INSIDE the held-group gate and then starts a second admission. Dave is
// added to the scene's group by a live add; his join of that invitation is started and is stopped
// at the gate's reading of the disk, where it holds the admission mutex; `second` is then started.
// It answers whether the second admission ALSO reached a reading of the disk while the join was
// still inside, which is two admissions in one critical section. Both are then let go, and it
// returns when both have returned, with the join's own answer.
func overlapping(t *testing.T, scene *advJoin, second func(dave *urmessage.Device)) (dave *urmessage.Device, joined *urmessage.Group, joinErr error, overlapped bool) {
	t.Helper()
	dave, watch := watchedDevice(t, scene.world, "dave")
	if err := dave.Connect(scene.ctx); err != nil {
		t.Fatalf("dave's Connect: %v", err)
	}
	joinCode, err := dave.KeyPackage()
	if err != nil {
		t.Fatalf("dave's KeyPackage: %v", err)
	}
	added, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		t.Fatalf("alice's AddMemberAndPublish: %v", err)
	}
	honest := gcReencodeInvite(t, added)
	done := make(chan struct{}, 2)
	watch.armed.Store(true)
	go func() {
		joined, joinErr = dave.Join(scene.ctx, honest)
		done <- struct{}{}
	}()
	select {
	case <-watch.asked:
	case <-time.After(10 * time.Second):
		t.Fatal("the join never reached the gate's reading of the disk, so nothing below is about two admissions")
	}
	go func() {
		second(dave)
		done <- struct{}{}
	}()
	select {
	case <-watch.asked:
		overlapped = true
	case <-time.After(500 * time.Millisecond):
		// the second admission is waiting for the join, which is the property
	}
	watch.armed.Store(false)
	close(watch.release)
	<-done
	<-done
	return dave, joined, joinErr, overlapped
}

// A RESTORE THAT STARTS WHILE A JOIN IS INSIDE THE GATE WAITS FOR IT. Restore puts groups onto the
// device as a join does, so it is an admission and takes the same mutex. Outside it, a join judged
// against "not held" can meet a group Restore filed meanwhile, and is then refused at the hold,
// AFTER its state and its record were written.
//
// THE ORDER IS FORCED, as in the case above. The join is stopped inside the gate, and Restore is
// then started; the first thing it does under the mutex is read the disk for leaves to finish,
// which the same store watches.
//
// WHAT WOULD GO RED: take the admission mutex away from Restore, and it reads the disk while the
// join is still between its question and its hold.
func TestARestoreThatOverlapsAJoinWaitsForIt(t *testing.T) {
	scene := advFounding(t, true)
	var restored []*urmessage.Group
	var restoreErr error
	dave, joined, joinErr, overlapped := overlapping(t, scene, func(dave *urmessage.Device) {
		restored, restoreErr = dave.Restore(scene.ctx)
	})
	if overlapped {
		t.Fatalf("Restore read the disk while a join was still inside the held-group gate: two admissions are in one critical section")
	}
	if joinErr != nil {
		t.Fatalf("the join, which was first, answered %v", joinErr)
	}
	// IT WAITED, SO IT SAW WHAT THE JOIN LEFT: the group is held, and there is nothing to restore
	if restoreErr != nil || len(restored) != 0 {
		t.Errorf("the Restore that waited answered %d group(s) and %v, want none and no error: the join had filed the group before it looked", len(restored), restoreErr)
	}
	if held := dave.Groups(); len(held) != 1 || held[0] != joined {
		t.Fatalf("dave holds %d group(s) and the one the join filed is not the one he holds", len(held))
	}
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", joined, canary)
}

// A FOUNDING THAT STARTS WHILE A JOIN IS INSIDE THE GATE WAITS FOR IT, AND THEN FINDS THE GROUP
// HELD. The founding is under the id the join is admitting, which is the case the mutex is for:
// outside it both read "not held", and the founding's epoch zero is written under an id a join
// is staging.
//
// WHAT WOULD GO RED: take the admission mutex away from CreateGroup, and its question reaches the
// disk while the join is still between its own question and its hold.
func TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld(t *testing.T) {
	scene := advFounding(t, true)
	var foundErr error
	dave, joined, joinErr, overlapped := overlapping(t, scene, func(dave *urmessage.Device) {
		_, foundErr = dave.CreateGroup(scene.ctx, scene.groupId)
	})
	if overlapped {
		t.Fatalf("a founding asked the disk about its group id while a join into that id was still inside the held-group gate: both have read \"not held\"")
	}
	if joinErr != nil {
		t.Fatalf("the join, which was first, answered %v", joinErr)
	}
	if !errors.Is(foundErr, urmessage.ErrGroupAlreadyHeld) {
		t.Errorf("the founding that waited answered %v, want ErrGroupAlreadyHeld: the join had filed the group before it asked", foundErr)
	}
	if held := dave.Groups(); len(held) != 1 || held[0] != joined {
		t.Fatalf("dave holds %d group(s) and the one the join filed is not the one he holds", len(held))
	}
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", joined, canary)
}

// A RE-ADD AT OR BELOW THE EPOCH OF THE REMOVAL IS REFUSED, AND THE REAL RE-ADD STILL JOINS. The
// victim joined at epoch 2 and was removed there, so a second founder's invitation at epoch 1
// stands BELOW the removal and at an epoch the victim holds no state for: nothing on its disk is
// in the way of it, and this rule is the only thing that refuses it.
//
// WHAT WOULD GO RED: drop the comparison of the joined epoch with the removal's, and the stale
// invitation joins and replaces the removed group.
func TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	if err := scene.aliceGroup.RemoveMember(scene.ctx, rolesIdentityOf(t, carolGroup)); err != nil {
		t.Fatalf("alice's RemoveMember of carol: %v", err)
	}
	if _, err := carolGroup.Receive(scene.ctx); !errors.Is(err, urmessage.ErrRemovedFromGroup) {
		t.Fatalf("CONTROL FAILED: the removed device's Receive answered %v, want ErrRemovedFromGroup", err)
	}
	removedAt, removal := carolGroup.Removal()
	if removal == nil || removedAt != 2 {
		t.Fatalf("CONTROL FAILED: carol reads (%d, %v) from Removal, want (2, non-nil)", removedAt, removal)
	}

	stale, err := urmessage.ParseInvite(advHostile(t, scene, carol.device))
	if err != nil {
		t.Fatalf("the second founder's invite does not parse: %v", err)
	}
	before := advGroupFiles(t, carol.stateDir, scene.groupId)
	if _, held := before["epoch/0000000000000001"]; held {
		t.Fatalf("CONTROL FAILED: carol holds a state at epoch 1, so something other than the re-add rule could refuse this")
	}
	if _, err := carol.device.Join(scene.ctx, stale); !errors.Is(err, urmessage.ErrReaddStale) {
		t.Fatalf("an invitation at epoch 1 over a group carol was removed from at epoch %d answered %v, want ErrReaddStale", removedAt, err)
	}
	after := advGroupFiles(t, carol.stateDir, scene.groupId)
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Errorf("the refused invitation changed %s of the removed group", name)
		}
	}
	held := carol.device.Groups()
	if len(held) != 1 || held[0] != carolGroup {
		t.Fatalf("carol holds %d group(s) after the refused invitation, and the removed group is not the one she holds", len(held))
	}
	if _, removal := carolGroup.Removal(); removal == nil {
		t.Fatalf("the removed group no longer reads as removed after an invitation that was refused")
	}

	// THE CONTROL, and the other half of the rule: the founder's own re-add, a later commit, joins.
	rejoined := removalAdd(t, scene.ctx, "alice", scene.aliceGroup, carol.device, "carol")
	if epoch := rejoined.Epoch(); epoch <= removedAt {
		t.Fatalf("the re-added group stands at epoch %d and the removal was at %d", epoch, removedAt)
	}
	if _, removal := rejoined.Removal(); removal != nil {
		t.Fatalf("the re-added group still reads as removed: %v", removal)
	}
}

// FORGETGROUP OVER A GROUP THAT IS ON THE DISK AND NOT IN MEMORY ANSWERS BY WHAT RESTORE SAID. A
// group no Restore has tried is not left: the owner's question is asked of a live group, and a
// device that has merely restarted is not let past it. A group Restore could not bring back is
// left, record and all, and after that the device holds nothing under the id.
//
// WHAT WOULD GO RED: refuse the group that did not restore, and a record is on the disk for good,
// refusing every invitation into it; or leave any group that is on the disk, and a restart is a
// way round the owner's refusal.
func TestForgetGroupOverAGroupOnTheDiskAnswersByWhatRestoreSaid(t *testing.T) {
	scene := advFounding(t, true)
	scene.bob.kill()
	if err := advRemoveEpochStates(scene.bob.stateDir, scene.groupId); err != nil {
		t.Fatalf("removing bob's epoch states: %v", err)
	}
	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
	if err := bob.device.Connect(scene.ctx); err != nil {
		t.Fatalf("the restarted bob's Connect: %v", err)
	}

	// BEFORE ANY RESTORE: on the disk, and not left
	if err := bob.device.ForgetGroup(scene.groupId); !errors.Is(err, urmessage.ErrGroupNotRestored) {
		t.Fatalf("ForgetGroup of a group no Restore has tried answered %v, want ErrGroupNotRestored", err)
	}
	if record := advGroupFiles(t, bob.stateDir, scene.groupId)["meta"]; len(record) == 0 {
		t.Fatalf("a ForgetGroup that was refused erased the group's record")
	}

	// AFTER A RESTORE THAT COULD NOT BRING IT BACK: left, and nothing of it stays
	restored, err := bob.device.Restore(scene.ctx)
	if len(restored) != 0 || !errors.Is(err, urmessage.ErrRestore) {
		t.Fatalf("CONTROL FAILED: Restore answered %d group(s) and %v, want none and ErrRestore", len(restored), err)
	}
	if err := bob.device.ForgetGroup(scene.groupId); err != nil {
		t.Fatalf("ForgetGroup of a group Restore could not bring back: %v", err)
	}
	if files := advGroupFiles(t, bob.stateDir, scene.groupId); len(files) != 0 {
		t.Fatalf("the group still has %d file(s) on the disk after it was left", len(files))
	}

	// AND AFTER THAT: nothing is held under the id
	if err := bob.device.ForgetGroup(scene.groupId); !errors.Is(err, urmessage.ErrGroupNotHeld) {
		t.Fatalf("ForgetGroup of a group already left answered %v, want ErrGroupNotHeld", err)
	}
}

// FORGETGROUP LEAVES A GROUP WHOSE RECORD DOES NOT READ, AND THAT GROUP ALONE. No Restore has to
// try first: the read ForgetGroup makes of that one record is the attempt, a record that does not
// read never restores, and there is no roster to ask the owner's question of. It is the remedy the
// gate's refusal of an invitation into such a group names, so it has to work when nothing else
// about the group does.
//
// AND IT IS ONE GROUP'S ANSWER. Bob holds a second group whose record reads. With the first
// group's record damaged beside it, that second group is still a group no Restore has tried, and
// is not left.
//
// WHAT WOULD GO RED: refuse the damaged group, and it can be neither restored, left nor joined
// again; or ask the store for every record to answer about one, and the damaged record of one
// group is the answer for the other.
func TestForgetGroupLeavesAGroupWhoseRecordDoesNotReadAndThatGroupAlone(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	if err := carol.device.Connect(scene.ctx); err != nil {
		t.Fatalf("carol's Connect: %v", err)
	}
	otherId := newGroupId(t)
	openPair(t, scene.ctx, carol, scene.bob, otherId)
	scene.bob.kill()
	advDamageRecord(t, scene.bob.stateDir, scene.groupId)
	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
	if err := bob.device.Connect(scene.ctx); err != nil {
		t.Fatalf("the restarted bob's Connect: %v", err)
	}
	if _, err := bob.stateStore.GroupRecord(scene.groupId); !errors.Is(err, urmessage.ErrGroupRecordDamaged) {
		t.Fatalf("CONTROL FAILED: bob's record of the first group answers %v, so this is not a record that does not read", err)
	}
	if _, err := bob.stateStore.GroupRecord(otherId); err != nil {
		t.Fatalf("CONTROL FAILED: bob's record of the second group answers %v, and it is the one that reads", err)
	}
	if len(advGroupFiles(t, bob.stateDir, scene.groupId)) < 2 {
		t.Fatalf("CONTROL FAILED: the damaged group has nothing on the disk but its record, so the erase below would be of one file")
	}

	// THE OTHER GROUP FIRST: its record reads and no Restore has tried it, so it is not left
	whole := advGroupFiles(t, bob.stateDir, otherId)
	if err := bob.device.ForgetGroup(otherId); !errors.Is(err, urmessage.ErrGroupNotRestored) {
		t.Fatalf("ForgetGroup of a group whose record reads, beside another group's damaged record, answered %v, want ErrGroupNotRestored", err)
	}
	if after := advGroupFiles(t, bob.stateDir, otherId); len(after) != len(whole) {
		t.Fatalf("a ForgetGroup that was refused left %d of the group's %d file(s)", len(after), len(whole))
	}

	// THE DAMAGED GROUP, BEFORE ANY RESTORE: left, and nothing of it stays
	if err := bob.device.ForgetGroup(scene.groupId); err != nil {
		t.Fatalf("ForgetGroup of a group whose record does not read, before any Restore: %v", err)
	}
	if files := advGroupFiles(t, bob.stateDir, scene.groupId); len(files) != 0 {
		t.Fatalf("the damaged group still has %d file(s) on the disk after it was left", len(files))
	}
	if err := bob.device.ForgetGroup(scene.groupId); !errors.Is(err, urmessage.ErrGroupNotHeld) {
		t.Fatalf("ForgetGroup of a group already left answered %v, want ErrGroupNotHeld", err)
	}
	// and the Restore that follows brings the other group back and has nothing to report
	restored, err := bob.device.Restore(scene.ctx)
	if err != nil || len(restored) != 1 || !bytes.Equal(restored[0].Id(), otherId) {
		t.Fatalf("Restore after the damaged group was left answered %d group(s) and %v, want the other group and no error", len(restored), err)
	}
}
```

`sdk/cp3b/advsim_join_test.go`:

```diff
--- a/sdk/cp3b/advsim_join_test.go
+++ b/sdk/cp3b/advsim_join_test.go
@@ -1007,3 +1007,149 @@ func TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain(t *testing.T) {
 	}
 	advJudge(t, "S7-c1-unrestorable-rejoins", observed)
 }
+
+// advHeard is one Receive that answers whether a canary came back opened. It fails nothing: in a
+// scenario whose subject is what still works, what a group read is a fact for the verdict.
+func advHeard(ctx context.Context, group *urmessage.Group, canary string) bool {
+	received, err := group.Receive(ctx)
+	if err != nil {
+		return false
+	}
+	for _, one := range received {
+		if one.Gap == "" && one.Text == canary {
+			return true
+		}
+	}
+	return false
+}
+
+// CONTROL: ONE RECORD THAT DOES NOT READ COSTS ITS OWN GROUP AND NO OTHER. Bob holds two groups,
+// the scene's and one of carol's founding. He is stopped, the scene's record on his disk is cut
+// to half its length, and he is started again. Then everything a person can do is driven in
+// order: Restore; an invitation into a third group; a founding under a fresh id; the two calls
+// that must be REFUSED while the damaged record stands (a founding under its group's id, and the
+// founder's own fresh invitation into its group); ForgetGroup; and that same invitation again.
+//
+// It is a control and not a gap. It is here because the held-group gate reads the disk: asked for
+// every record the store holds instead of for the one group, a single record that did not read
+// refused every invitation, every founding and every leave on the device, and no call cleared it.
+func TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther(t *testing.T) {
+	scene := advFounding(t, true)
+	ctx := scene.ctx
+	bobId := rolesIdentityOf(t, scene.bobGroup)
+	carol := scene.world.newPersona(t, "carol")
+	if err := carol.device.Connect(ctx); err != nil {
+		advHarness(t, "carol's Connect: %v", err)
+	}
+	otherId := newGroupId(t)
+	carolGroup, _ := openPair(t, ctx, carol, scene.bob, otherId)
+
+	scene.bob.kill()
+	advDamageRecord(t, scene.bob.stateDir, scene.groupId)
+	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
+	if err := bob.device.Connect(ctx); err != nil {
+		advHarness(t, "the restarted bob's Connect: %v", err)
+	}
+	if _, err := bob.stateStore.GroupRecord(scene.groupId); !errors.Is(err, urmessage.ErrGroupRecordDamaged) {
+		advHarness(t, "bob's record of the scene's group answers %v, so this is not a record that does not read", err)
+	}
+	observed := []string{}
+
+	// RESTORE: the other group comes back and reads, and the damage is reported
+	restored, restoreErr := bob.device.Restore(ctx)
+	t.Logf("Restore: %d group(s), %v", len(restored), restoreErr)
+	if len(restored) == 1 && bytes.Equal(restored[0].Id(), otherId) {
+		canary := advCanary(t)
+		if _, err := carolGroup.Send(ctx, canary); err != nil {
+			advHarness(t, "carol's Send: %v", err)
+		}
+		if advHeard(ctx, restored[0], canary) {
+			observed = append(observed, "others-restored")
+		}
+	}
+	if errors.Is(restoreErr, urmessage.ErrRestore) && errors.Is(restoreErr, urmessage.ErrGroupRecordDamaged) {
+		observed = append(observed, "damage-reported")
+	}
+
+	// ANOTHER GROUP STILL JOINS, and a fresh id still founds
+	dave := scene.world.newPersona(t, "dave")
+	if err := dave.device.Connect(ctx); err != nil {
+		advHarness(t, "dave's Connect: %v", err)
+	}
+	daveGroup, err := dave.device.CreateGroup(ctx, newGroupId(t))
+	if err != nil {
+		advHarness(t, "dave's CreateGroup: %v", err)
+	}
+	joinCode, err := bob.device.KeyPackage()
+	if err != nil {
+		advHarness(t, "bob's KeyPackage for the third group: %v", err)
+	}
+	third, err := daveGroup.AddMember(joinCode)
+	if err != nil {
+		advHarness(t, "dave's AddMember: %v", err)
+	}
+	if err := daveGroup.Open(ctx); err != nil {
+		advHarness(t, "dave's Open: %v", err)
+	}
+	joinedThird, err := bob.device.Join(ctx, gcReencodeInvite(t, third))
+	t.Logf("Join of a third group, with the damaged record standing: %v", err)
+	if err == nil {
+		canary := advCanary(t)
+		if _, err := daveGroup.Send(ctx, canary); err != nil {
+			advHarness(t, "dave's Send: %v", err)
+		}
+		if advHeard(ctx, joinedThird, canary) {
+			observed = append(observed, "other-group-joined")
+		}
+	}
+	_, err = bob.device.CreateGroup(ctx, newGroupId(t))
+	t.Logf("CreateGroup under a fresh id, with the damaged record standing: %v", err)
+	if err == nil {
+		observed = append(observed, "fresh-id-founded")
+	}
+
+	// WHILE THE DAMAGED RECORD STANDS, ITS OWN GROUP ID IS REFUSED: a founding under it, and the
+	// founder's fresh invitation into it. Neither may read a record that does not read as "not held".
+	_, err = bob.device.CreateGroup(ctx, scene.groupId)
+	t.Logf("CreateGroup under the damaged group's id: %v", err)
+	switch {
+	case errors.Is(err, urmessage.ErrGroupAlreadyHeld):
+		observed = append(observed, "damaged-id-not-founded")
+	case err == nil:
+		observed = append(observed, "founded-over-the-damaged-record")
+	}
+	if err := scene.aliceGroup.RemoveMember(ctx, bobId); err != nil {
+		advHarness(t, "alice's RemoveMember of the stranded leaf: %v", err)
+	}
+	joinCode, err = bob.device.KeyPackage()
+	if err != nil {
+		advHarness(t, "bob's fresh KeyPackage: %v", err)
+	}
+	fresh, err := scene.aliceGroup.AddMemberAndPublish(ctx, joinCode)
+	if err != nil {
+		advHarness(t, "alice's AddMemberAndPublish of the fresh join code: %v", err)
+	}
+	_, err = bob.device.Join(ctx, gcReencodeInvite(t, fresh))
+	t.Logf("Join over the founder's fresh invitation, with the damaged record standing: %v", err)
+	switch {
+	case errors.Is(err, urmessage.ErrGroupAlreadyHeld):
+		observed = append(observed, "damaged-invite-refused")
+	case err == nil:
+		observed = append(observed, "joined-over-the-damaged-record")
+	}
+
+	// THE REMEDY THAT REFUSAL NAMES, and then the same invitation again: the refusal cost nothing
+	forgetErr := bob.device.ForgetGroup(scene.groupId)
+	t.Logf("ForgetGroup of the damaged group: %v", forgetErr)
+	rejoined, joinErr := bob.device.Join(ctx, gcReencodeInvite(t, fresh))
+	t.Logf("Join over the same invitation after ForgetGroup: %v", joinErr)
+	if joinErr != nil {
+		observed = append(observed, "wedged")
+	} else {
+		scene.bob, scene.bobGroup = bob, rejoined
+		scene.say(t, "alice", scene.aliceGroup)
+		scene.hear(t, "bob", rejoined)
+		observed = append(observed, "rejoined")
+	}
+	advJudge(t, "S7-c2-unreadable-record-costs-one-group", observed)
+}
```

`sdk/cp3b/advsim_oracle_test.go`:

```diff
--- a/sdk/cp3b/advsim_oracle_test.go
+++ b/sdk/cp3b/advsim_oracle_test.go
@@ -470,3 +470,27 @@ func advRemoveEpochStates(stateDir string, groupId []byte) error {
 		return nil
 	})
 }
+
+// advDamageRecord cuts the record a durable store holds for one group to half its length, and
+// leaves everything else of the group: what "one file on the disk does not read" is. The device
+// must be stopped first, because its store holds the directory while it runs.
+func advDamageRecord(t *testing.T, stateDir string, groupId []byte) {
+	t.Helper()
+	sum := sha256.Sum256(groupId)
+	marker := "/" + hex.EncodeToString(sum[:]) + "/meta"
+	cut := 0
+	err := filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
+		if err != nil || entry.IsDir() || !bytes.HasSuffix([]byte(filepath.ToSlash(path)), []byte(marker)) {
+			return err
+		}
+		record, err := os.ReadFile(path)
+		if err != nil {
+			return err
+		}
+		cut += 1
+		return os.WriteFile(path, record[:len(record)/2], 0o600)
+	})
+	if err != nil || cut != 1 {
+		advHarness(t, "cutting the group's record under %s to half its length: %d file(s) cut, %v", stateDir, cut, err)
+	}
+}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk/cp3b test -count=1 -run ^(TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld|TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins|TestARestoreThatOverlapsAJoinWaitsForIt|TestAdvSim|TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther|TestForgetGroupLeavesAGroupWhoseRecordDoesNotReadAndThatGroupAlone|TestForgetGroupOverAGroupOnTheDiskAnswersByWhatRestoreSaid|Tes
exit status 1
FAIL	github.com/urnetwork/message/sdk/cp3b [build failed]
FAIL
 # github.com/urnetwork/message/sdk/cp3b [github.com/urnetwork/message/sdk/cp3b.test]
.\advsim_join_test.go:1053:30: bob.stateStore.GroupRecord undefined (type *urmessage.DurableStateStore has no field or method GroupRecord)
.\advsim_join_test.go:1053:84: undefined: urmessage.ErrGroupRecordDamaged
.\advsim_join_test.go:1070:84: undefined: urmessage.ErrGroupRecordDamaged
.\advsim_join_test.go:1116:32: undefined: urmessage.ErrGroupAlreadyHeld
.\advsim_join_test.go:1135:32: undefined: urmessage.ErrGroupAlreadyHeld
.\heldgroup_test.go:42:32: self.DurableStateStore.GroupRecord undefined (type *urmessage.DurableStateStore has no field or method GroupRecord)
.\heldgroup_test.go:147:45: undefined: urmessage.ErrGroupAlreadyHeld
...
$ go -C sdk test -count=1 -run ^(TestAMapEntryIsReplacedOnlyByTheJoinThatJudgedIt|TestAStoreThatCannotAnswerRefusesTheJoinAndTheFoundingOfThatGroupAndOfNoOther|TestAnInviteIntoAGroupThisDeviceHoldsIsRefused|TestNoGroupIsFoundedUnderAnIdThisDeviceHolds|TestOneRecordThatDoesNotReadIsReportedByTheListAndAnsweredOnlyForItsOwnGroup) ./urmessage/
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\heldgroup_test.go:47:54: undefined: ErrGroupAlreadyHeld
urmessage\heldgroup_test.go:50:60: undefined: ErrGroupAlreadyHeld
urmessage\heldgroup_test.go:86:53: device.hold(incoming) (no value) used as value
urmessage\heldgroup_test.go:87:75: device.holdReplacing undefined (type *Device has no field or method holdReplacing)
urmessage\heldgroup_test.go:88:83: device.holdReplacing undefined (type *Device has no field or method holdReplacing)
urmessage\heldgroup_test.go:90:41: undefined: ErrGroupAlreadyHeld
urmessage\heldgroup_test.go:99:19: device.holdReplacing undefined (type *Device has no field or method holdReplacing)
...
```

- [ ] **Step 3: the change.**

`sdk/urmessage/heldgroup.go` (new file, 164 lines):

```go
package urmessage

import (
	"errors"
	"fmt"
)

// joinOverHeldGroup is the held-group gate of [Device.Join]: it answers whether an invite into
// groupId may be joined at all, and for the one case that may, the group the join replaces and the
// epoch it has to exceed.
//
// A DEVICE HOLDS A GROUP when it has a live [Group] for it in memory, or a record of it on its
// disk. Either is refused with [ErrGroupAlreadyHeld], before the join code is touched and before
// anything is written. The disk is asked as well as the map because a device that has restarted
// and not yet restored holds every one of its groups on the disk and none of them in memory.
//
// THE ONE EXCEPTION is a group a commit REMOVED this device from: being added back is a join over
// a held id, and it is the repair [ErrRemovedFromGroup] itself names. It is honoured only above the
// epoch the device was removed at, which the caller holds the joined epoch against.
//
// THE EXCEPTION AUTHENTICATES NOBODY. An invite does not say who made it, so this gate cannot tell
// the group that removed this device from another founder's group under the same id that stands
// at a later epoch: that invite is honoured too, and it replaces the removed group's record. That
// is measured and pinned open in sdk/cp3b (S7g) until a join names its inviter.
//
// IT IS ASKED UNDER [Device.admitMutex], AND ITS ANSWER HOLDS UNTIL THE HOLD. Asked outside it,
// two joins into one group id that overlap both read "not held"; the second then wrote its record
// over the first's. Measured in sdk/cp3b, with the two invites at two epochs, before the mutex
// stood above this call.
//
// EPOCH STATES WITH NO RECORD ARE NOT A HELD GROUP. A founder that died before Open, or a join
// whose record did not persist, leaves them, and refusing here would refuse the join that repairs
// it. The engine's create-only commit is what protects those: it never writes over a state that is
// already there.
//
// THE DISK IS ASKED ABOUT THIS ONE GROUP, AND ABOUT NO OTHER ([DeviceStore.GroupRecord]). It used
// to be asked for every record it holds, and one record of ANOTHER group that did not read then
// refused every invite on the device, with no call that cleared it. Measured, before this was one
// read: a device with one damaged record joined nothing, founded nothing and left nothing.
//
// A RECORD THAT DOES NOT READ IS A HELD GROUP, and a store that cannot answer is a refusal: neither
// is "not held", which is the one answer that lets a join write. The first is refused as held
// ([ErrGroupAlreadyHeld], carrying [ErrGroupRecordDamaged]), because the remedy is the same and it
// exists: [Device.ForgetGroup] leaves a group whose record does not read.
func (self *Device) joinOverHeldGroup(groupId []byte) (replaces *Group, readd bool, removedEpoch uint64, err error) {
	self.mutex.Lock()
	live := self.groups[string(groupId)]
	self.mutex.Unlock()
	if live != nil {
		epoch, removal := live.Removal()
		if removal == nil {
			return nil, false, 0, fmt.Errorf("%w: group %x is live on this device", ErrGroupAlreadyHeld, groupId)
		}
		replaces, readd, removedEpoch = live, true, epoch
	}
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return replaces, readd, removedEpoch, nil
	}
	record, err := store.GroupRecord(groupId)
	if errors.Is(err, ErrStateNotFound) {
		return replaces, readd, removedEpoch, nil
	}
	if err != nil {
		return nil, false, 0, heldUnread(groupId, err, "the invite into it is refused")
	}
	if record.RemovedKind == removedNone {
		return nil, false, 0, fmt.Errorf("%w: group %x has a record on this device's disk", ErrGroupAlreadyHeld, groupId)
	}
	readd = true
	if removedEpoch < record.RemovedEpoch {
		removedEpoch = record.RemovedEpoch
	}
	return replaces, readd, removedEpoch, nil
}

// heldUnread is what the gate and a founding answer when the store said anything about a group but
// "here is its record" or "I hold none". A record that does not read is a group this device holds,
// refused as one, with the remedy [ErrGroupAlreadyHeld]'s own sentence names. A store that could
// not answer is refused as that, and names no remedy, because it has none to name.
func heldUnread(groupId []byte, err error, refused string) error {
	if errors.Is(err, ErrGroupRecordDamaged) {
		return fmt.Errorf("%w: group %x has a record on this device's disk that does not read: %w", ErrGroupAlreadyHeld, groupId, err)
	}
	return fmt.Errorf("urmessage: whether this device already holds group %x could not be read, so %s: %w", groupId, refused, err)
}

// foundOverHeldGroup is the same question for [Device.CreateGroup], and it has no exception: a
// group is founded under an id this device holds nothing for, removed or not. An id is 32 random
// octets of the caller's, so this refuses a caller's mistake and never an honest founding. It asks
// the disk about that one id, as the gate does and for the gate's reason: a record of another
// group that does not read is no reason to refuse a founding under a fresh id.
func (self *Device) foundOverHeldGroup(groupId []byte) error {
	if self.holdsGroup(groupId) {
		return fmt.Errorf("%w: group %x is live on this device", ErrGroupAlreadyHeld, groupId)
	}
	store, durable := self.stateStore.(DeviceStore)
	if !durable {
		return nil
	}
	_, err := store.GroupRecord(groupId)
	if errors.Is(err, ErrStateNotFound) {
		return nil
	}
	if err != nil {
		return heldUnread(groupId, err, "no group is founded under it")
	}
	return fmt.Errorf("%w: group %x has a record on this device's disk", ErrGroupAlreadyHeld, groupId)
}

// hold files a group on this device that is NEW TO ITS MAP: one founded here, or one restored off
// the disk. It never replaces. An id that is already in the map is refused, because the group
// sitting there is live, with a session and an epoch's secrets, and nothing asked whether it may
// go. The callers are under [Device.admitMutex] and have asked first, so this refusal is the
// second line and not the gate.
func (self *Device) hold(group *Group) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if held := self.groups[string(group.id)]; held != nil && held != group {
		return fmt.Errorf("%w: group %x is live on this device", ErrGroupAlreadyHeld, group.id)
	}
	self.groups[string(group.id)] = group
	delete(self.unrestored, string(group.id))
	return nil
}

// holdReplacing files a JOINED group on this device, in place of exactly the group the gate judged
// and of nothing else. judged is what [Device.joinOverHeldGroup] answered: nil when the device
// held no live group under the id, and otherwise the group a commit removed this device from. That
// group is closed here, because its session and its MLS handle are still open: left alone they are
// a loop and an epoch's secrets nothing will ever close.
//
// A MAP ENTRY THAT IS NOT THE ONE THE GATE JUDGED IS REFUSED. Under [Device.admitMutex] it cannot
// happen, which is the point of the mutex; an admission that ever runs outside it fails here,
// loudly, and does not replace a group nobody judged.
func (self *Device) holdReplacing(group *Group, judged *Group) error {
	self.mutex.Lock()
	if held := self.groups[string(group.id)]; held != judged {
		self.mutex.Unlock()
		return fmt.Errorf("%w: the group this device holds under %x is not the one this join was judged against", ErrGroupAlreadyHeld, group.id)
	}
	self.groups[string(group.id)] = group
	delete(self.unrestored, string(group.id))
	self.mutex.Unlock()
	if judged != nil {
		judged.Close()
	}
	return nil
}

// noteUnrestored records that [Device.Restore] could not bring one group back, and didNotRestore
// answers it. It is what lets [Device.ForgetGroup] leave such a group: a record on the disk whose
// state does not load is a group this device can neither use nor, without this, be rid of.
func (self *Device) noteUnrestored(groupId []byte) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.unrestored[string(groupId)] = true
}

func (self *Device) didNotRestore(groupId []byte) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.unrestored[string(groupId)]
}
```

`sdk/urmessage/errors.go`:

```diff
--- a/sdk/urmessage/errors.go
+++ b/sdk/urmessage/errors.go
@@ -728,6 +728,22 @@ var (
 	// already left, or closed under it.
 	ErrGroupNotHeld = errors.New("urmessage: this device holds no such group")
 
+	// [Device.ForgetGroup] was asked to leave a group that is on this device's disk and that no
+	// [Device.Restore] has tried to bring back since this process started. Restore first: a group
+	// that comes back is left like any other, the owner's refusal included, and one that does not
+	// come back is left by calling ForgetGroup again.
+	ErrGroupNotRestored = errors.New("urmessage: this group is on this device's disk and has not been restored; call Restore, and if it does not come back, ForgetGroup leaves it")
+
+	// A group's record is on this device's disk and DOES NOT READ: its checksum does not hold, it
+	// does not decode, it names another group, or the file under its name cannot be had. It is
+	// ONE GROUP'S damage and never the device's. [DeviceStore.GroupRecord] answers it for that one
+	// group; [DeviceStore.GroupRecords] answers it BESIDE the list of every record that does read,
+	// so [Device.Restore] brings the others back and reports this one; and an invite into any
+	// other group joins. A record that does not read can never be restored, so
+	// [Device.ForgetGroup] leaves its group without a Restore having tried, and without the
+	// owner's question, which is asked of a roster this group no longer has.
+	ErrGroupRecordDamaged = errors.New("urmessage: a group record on this device's disk does not read, so that group cannot be restored; ForgetGroup leaves it, and it can then be joined again")
+
 	// [Device.ForgetGroup] LEFT the group -- it is closed, its keys are gone from memory, and this
 	// device no longer holds it -- but the erase of its copy on the disk did not finish. The leave
 	// mark stands, so the next [Device.Restore] finishes the erase, and so does ForgetGroup again.
@@ -741,4 +757,20 @@ var (
 	// or added back. MASTER §11: "the leave action is refused for an OWNER until ownership has been
 	// transferred". Nothing changed: the group is open, and every file of it is still on the disk.
 	ErrOwnerMustTransfer = errors.New("urmessage: you own this group and somebody else is in it, so hand it over first with TransferOwnership; leaving now would leave them with an owner nobody can remove")
+
+	// [Device.Join] was handed an invite into a group this device ALREADY HOLDS, live in memory or
+	// as a record on its disk, and that group is not one a commit removed this device from. A join
+	// writes an epoch state, a record and a map entry under the group's id, so a join over a held
+	// group is that group replaced by whatever the invite carries, and an invite authenticates
+	// nobody. Nothing was written and the join code is not spent. The one join over a held id that
+	// is honoured is the re-add of a device a commit removed. A group that went dark or halted, one
+	// a restore could not bring back, and one whose record does not read ([ErrGroupRecordDamaged],
+	// which this then carries as well) is joined again by leaving it first, with
+	// [Device.ForgetGroup]. [Device.CreateGroup] answers it too, for an id this device holds
+	// anything under.
+	ErrGroupAlreadyHeld = errors.New("urmessage: this device already holds this group, so an invite into it is refused; leave it first with ForgetGroup to join it again")
+
+	// The re-add of a device a commit removed named an epoch at or below the one it was removed at.
+	// A real re-add is a later commit, so its Welcome stands above that epoch.
+	ErrReaddStale = errors.New("urmessage: this invite adds this device back at an epoch at or below the one it was removed at")
 )
```

`sdk/urmessage/device.go`:

```diff
--- a/sdk/urmessage/device.go
+++ b/sdk/urmessage/device.go
@@ -282,6 +282,16 @@ type Device struct {
 	mutex  sync.Mutex
 	groups map[string]*Group
 
+	// admitMutex is held by every call that puts a group onto this device -- [Device.Join],
+	// [Device.CreateGroup] and [Device.Restore] -- from the question "does this device hold that
+	// group" to the hold that answers it. Without it two admissions of one group id overlap, both
+	// read "not held", and the second replaces the first. It is taken before [Device.mutex] and
+	// never while that one is held.
+	admitMutex sync.Mutex
+	// unrestored is the groups the last [Device.Restore] found on the disk and could not bring
+	// back, by id. Guarded by mutex. It is what [Device.ForgetGroup] reads to leave one of them.
+	unrestored map[string]bool
+
 	// §4.3.5's pushes and the replaced-session flag: see [pushInbox], which is what the transport's
 	// callbacks hold instead of this device.
 	inbox *pushInbox
@@ -450,6 +460,7 @@ func NewDevice(config DeviceConfig) (*Device, error) {
 		random:           random,
 		commitAuthorizer: config.CommitAuthorizer,
 		groups:           map[string]*Group{},
+		unrestored:       map[string]bool{},
 		inbox:            inbox,
 	}, nil
 }
@@ -903,9 +914,3 @@ func (self *Device) createMlsGroup(groupId []byte) (messagegroup.GroupHandle, er
 	}
 	return handle, nil
 }
-
-func (self *Device) hold(group *Group) {
-	self.mutex.Lock()
-	defer self.mutex.Unlock()
-	self.groups[string(group.id)] = group
-}
```

`sdk/urmessage/group.go`:

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1294,9 +1294,17 @@ func (self *Device) CreateGroup(ctx context.Context, groupId []byte) (*Group, er
 	if len(groupId) != GroupIdBytes {
 		return nil, fmt.Errorf("urmessage: a group id is %d octets and this one is %d", GroupIdBytes, len(groupId))
 	}
+	// ONE ADMISSION AT A TIME, from the question below to the hold: see [Device.admitMutex].
+	self.admitMutex.Lock()
+	defer self.admitMutex.Unlock()
 	if err := self.finishLeaveBefore(groupId); err != nil {
 		return nil, err
 	}
+	// NOTHING IS FOUNDED UNDER AN ID THIS DEVICE HOLDS: see [Device.foundOverHeldGroup]. It is asked
+	// before the MLS group is made, because making it writes an epoch-zero state under that id.
+	if err := self.foundOverHeldGroup(groupId); err != nil {
+		return nil, err
+	}
 	nonce, nonceEpoch, err := self.nonce()
 	if err != nil {
 		return nil, err
@@ -1353,7 +1361,10 @@ func (self *Device) CreateGroup(ctx context.Context, groupId []byte) (*Group, er
 		ownFloorHeld: true,
 	}
 	group.initTables()
-	self.hold(group)
+	if err := self.hold(group); err != nil {
+		group.Close()
+		return nil, err
+	}
 	// NOTHING IS PERSISTED HERE AND THAT IS DELIBERATE. A group at epoch zero with no second
 	// member cannot be restored into anything a caller can use -- [Group.AddMember] needs the
 	// founding session, which is not persisted, and [Group.Open] needs the commit AddMember
@@ -1377,6 +1388,11 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
 	if err := invite.check(); err != nil {
 		return nil, err
 	}
+	// ONE ADMISSION AT A TIME, FROM THE HELD-GROUP GATE TO THE HOLD: see [Device.admitMutex]. The
+	// gate's answer is only worth the time it stays true for, so everything from the question to
+	// the map entry is one critical section.
+	self.admitMutex.Lock()
+	defer self.admitMutex.Unlock()
 	if err := self.finishLeaveBefore(invite.GroupId); err != nil {
 		return nil, err
 	}
@@ -1384,6 +1400,11 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
 	if err != nil {
 		return nil, err
 	}
+	// THE HELD-GROUP GATE, before the join code is touched: see [Device.joinOverHeldGroup].
+	replaces, readd, removedEpoch, err := self.joinOverHeldGroup(invite.GroupId)
+	if err != nil {
+		return nil, err
+	}
 	handle, err := self.engine.JoinFromWelcome(invite.Welcome, invite.RatchetTree)
 	if err != nil {
 		return nil, fmt.Errorf("urmessage: JoinFromWelcome: %w", err)
@@ -1393,6 +1414,11 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
 		return nil, fmt.Errorf("urmessage: the welcome joined group %x and the invite names %x",
 			handle.GroupId(), invite.GroupId)
 	}
+	if readd && handle.Epoch() <= removedEpoch {
+		handle.Close()
+		return nil, fmt.Errorf("%w: the welcome stands at epoch %d and this device was removed at epoch %d",
+			ErrReaddStale, handle.Epoch(), removedEpoch)
+	}
 	session, err := messagegroup.NewGroupSession(handle, invite.PqSecret, invite.GroupHandleKey,
 		self.reserver, self.nowMs, nonce)
 	if err != nil {
@@ -1459,7 +1485,11 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
 		return nil, fmt.Errorf(
 			"urmessage: this group joined and its record could not be persisted, so a restart would not come back into it: %w", err)
 	}
-	self.hold(group)
+	if err := self.holdReplacing(group, replaces); err != nil {
+		session.Close()
+		handle.Close()
+		return nil, err
+	}
 	return group, nil
 }
 
```

`sdk/urmessage/forget.go`:

```diff
--- a/sdk/urmessage/forget.go
+++ b/sdk/urmessage/forget.go
@@ -2,6 +2,7 @@ package urmessage
 
 import (
 	"bytes"
+	"errors"
 	"fmt"
 
 	"github.com/urnetwork/message/mls"
@@ -47,6 +48,22 @@ import (
 // owner alone, or one with another device of its own still in the group, strands nobody and may go.
 // A refusal changes nothing: no mark, no close, no file.
 //
+// A GROUP THE LAST RESTORE COULD NOT BRING BACK IS LEFT TOO, and it is the one group this call
+// leaves without holding it. Its record is on the disk, so [Device.Join] refuses an invite into it
+// ([ErrGroupAlreadyHeld], whose own sentence sends the caller here); its state does not load, so
+// it can never be held; and until this paragraph such a group could be neither restored, left nor
+// joined again. It is marked and erased like any other. THE OWNER'S REFUSAL IS NOT ASKED OF IT,
+// because it cannot be: the roster is read off a live group and this one has none, and a device
+// that cannot load a group's state strands nobody by erasing it that it had not already. A group
+// on the disk that no Restore has tried is NOT left this way: it answers [ErrGroupNotRestored],
+// so that a device that has merely restarted is asked the owner's question like any other.
+//
+// AND SO IS A GROUP WHOSE RECORD DOES NOT READ ([ErrGroupRecordDamaged]), with no Restore having
+// to try first: the read this call makes of that one record IS the attempt, a record that does
+// not read never restores, and the reasoning above holds of it word for word. Without this, the
+// gate's refusal of an invite into such a group named a remedy that failed for the gate's own
+// reason, and the group could be neither restored, left nor joined again.
+//
 // ONE CALLER AT A TIME PER GROUP. A [Device.Restore] or [Device.Join] of the same group on another
 // goroutine, between the map drop and the erase, is not guarded against: Restore skips a marked
 // group, but a Join would build a group the erase then deletes under it. Every caller this package
@@ -77,6 +94,18 @@ func (self *Device) ForgetGroup(groupId []byte) error {
 		}
 	}
 	if !held {
+		if durable {
+			onDisk, reads, err := recordOnDisk(store, groupId)
+			if err != nil {
+				return err
+			}
+			if onDisk && (!reads || self.didNotRestore(groupId)) {
+				return self.forgetUnrestored(store, groupId)
+			}
+			if onDisk {
+				return fmt.Errorf("%w: %x", ErrGroupNotRestored, groupId)
+			}
+		}
 		return fmt.Errorf("%w: %x", ErrGroupNotHeld, groupId)
 	}
 
@@ -111,6 +140,48 @@ func (self *Device) ForgetGroup(groupId []byte) error {
 	return nil
 }
 
+// recordOnDisk asks the store about ONE group: whether it holds a record for it, and whether that
+// record reads. A group being left is not on the disk for this purpose:
+// [DurableStateStore.GroupRecord] answers it as not found, and ForgetGroup has finished that one
+// before it asks this.
+//
+// IT ASKS ABOUT THE ONE GROUP AND NOT FOR THE LIST. It used to ask for every record the store
+// holds, so a record of another group that did not read made this an error, and ForgetGroup, the
+// remedy every held-group refusal names, failed for the reason the refusal was given.
+func recordOnDisk(store DeviceStore, groupId []byte) (onDisk bool, reads bool, err error) {
+	_, err = store.GroupRecord(groupId)
+	switch {
+	case err == nil:
+		return true, true, nil
+	case errors.Is(err, ErrStateNotFound):
+		return false, false, nil
+	case errors.Is(err, ErrGroupRecordDamaged):
+		return true, false, nil
+	}
+	return false, false, fmt.Errorf("urmessage: whether this device holds group %x on its disk could not be read, so nothing was left: %w", groupId, err)
+}
+
+// forgetUnrestored leaves a group that is on the disk and that will not come back, because the
+// last Restore could not bring it back or because its record does not read: the mark, then the
+// erase, as for a live group, with nothing to close.
+func (self *Device) forgetUnrestored(store DeviceStore, groupId []byte) error {
+	if err := store.MarkGroupForgetting(groupId); err != nil {
+		// the same rule as [Group.closeToForget]'s: a mark that stands although its write
+		// reported a failure is an instruction to erase, so the leave goes on
+		marked, readErr := store.GroupBeingForgotten(groupId)
+		if readErr != nil || !marked {
+			return fmt.Errorf("urmessage: the leave could not be recorded on the disk, so nothing was left: %w", err)
+		}
+	}
+	if err := store.DeleteGroupRecord(groupId); err != nil {
+		return fmt.Errorf("%w: %w", ErrForgetUnfinished, err)
+	}
+	self.mutex.Lock()
+	delete(self.unrestored, string(groupId))
+	self.mutex.Unlock()
+	return nil
+}
+
 // finishLeaveBefore is what [Device.Join] and [Device.CreateGroup] owe a leave of the same group
 // id that has not finished erasing (msgrepo ledger §7, 2026-10-03, re-check R1). The mark is the
 // erase's own instruction, so state written beside it is erased with it at the next Restore: a
```

`sdk/urmessage/restore.go`:

```diff
--- a/sdk/urmessage/restore.go
+++ b/sdk/urmessage/restore.go
@@ -3,6 +3,7 @@ package urmessage
 import (
 	"context"
 	"crypto/sha256"
+	"errors"
 	"fmt"
 
 	"github.com/urnetwork/message/messagegroup"
@@ -206,6 +207,10 @@ func (self *Device) Restore(ctx context.Context) ([]*Group, error) {
 	if !durable {
 		return nil, ErrNoDeviceStore
 	}
+	// ONE ADMISSION AT A TIME: a Join or a CreateGroup of a group this call is about to restore
+	// waits for it and reads the answer it leaves. See [Device.admitMutex].
+	self.admitMutex.Lock()
+	defer self.admitMutex.Unlock()
 	// A LEAVE THAT DID NOT FINISH ERASING IS FINISHED FIRST, and before the nonce is asked for: it
 	// needs no connection, and a device that cannot connect should still not keep a group it left
 	// on the disk. A group being left is never restored ([DurableStateStore.GroupRecords] skips
@@ -224,18 +229,39 @@ func (self *Device) Restore(ctx context.Context) ([]*Group, error) {
 	if err != nil {
 		return nil, err
 	}
+	// ONE RECORD THAT DOES NOT READ DOES NOT COST THE OTHERS. The list answers every record that
+	// reads, and reports the ones that do not beside it ([ErrGroupRecordDamaged]). This call used
+	// to return on that report, before its loop, so one damaged file left a device with none of
+	// its groups. It goes on now: the others are restored, and the damaged record is this call's
+	// first failure, answered inside [ErrRestore] like any other group that did not come back.
+	// It is named by the store's name for it and not by a group id, which the store cannot give
+	// (see [DurableStateStore.GroupRecords]); [Device.ForgetGroup] leaves it by its id.
 	records, err := store.GroupRecords()
-	if err != nil {
+	if err != nil && !errors.Is(err, ErrGroupRecordDamaged) {
 		return nil, err
 	}
 	restored := []*Group{}
 	var firstFailure error
+	if err != nil {
+		firstFailure = fmt.Errorf("%w: %w", ErrRestore, err)
+	}
 	for _, record := range records {
 		if self.holdsGroup(record.GroupId) {
 			continue
 		}
 		group, err := self.restoreOne(store, record, nonce, nonceEpoch)
+		if err == nil {
+			// THE HOLD IS HERE AND NOT IN restoreOne: this loop is the admission, under the mutex
+			// and after the question, and restoreOne only rebuilds.
+			if err = self.hold(group); err != nil {
+				group.Close()
+				err = fmt.Errorf("%w: group %x: %w", ErrRestore, record.GroupId, err)
+			}
+		}
 		if err != nil {
+			// REMEMBERED, so that [Device.ForgetGroup] can leave a group that will not come back:
+			// its record is still on the disk, and a join into it is refused while it is.
+			self.noteUnrestored(record.GroupId)
 			if firstFailure == nil {
 				firstFailure = err
 			}
@@ -473,7 +499,6 @@ func (self *Device) restoreOne(store DeviceStore, record *GroupRecord, nonce []b
 			restored.peerHeads[ladder] = head.Head
 		}
 	}
-	self.hold(restored)
 	return restored, nil
 }
 
```

`sdk/urmessage/statestore_durable.go`:

```diff
--- a/sdk/urmessage/statestore_durable.go
+++ b/sdk/urmessage/statestore_durable.go
@@ -163,9 +163,23 @@ type DeviceStore interface {
 	// package's rather than MLS's, and that a restore cannot be performed without.
 	PutGroupRecord(record *GroupRecord) error
 
-	// GroupRecords is every group this store holds a record for, in no particular order.
+	// GroupRecords is every group this store holds a record for THAT READS, in no particular order.
+	//
+	// A RECORD THAT DOES NOT READ IS REPORTED AND IS NOT THE LIST'S REFUSAL. The list holds every
+	// other record, and the error beside it wraps [ErrGroupRecordDamaged] and names each record it
+	// skipped by the store's own name for it. That is [DeviceStore.GroupsBeingForgotten]'s shape
+	// and its reason: one file that does not read must not cost a device every other group on its
+	// disk. Any other error is the store failing to answer, and comes with no list.
 	GroupRecords() ([]*GroupRecord, error)
 
+	// GroupRecord is the ONE record this store holds for groupId, and it is what a caller with a
+	// group id in its hand asks, so that another group's record is never its answer. It answers
+	// [ErrStateNotFound] when the store holds none (a group being left is none, as in the list),
+	// an error wrapping [ErrGroupRecordDamaged] when a record is there and does not read, and any
+	// other error when the store could not answer. It agrees with the list: both read a group's
+	// record by one function.
+	GroupRecord(groupId []byte) (*GroupRecord, error)
+
 	// DeleteGroupRecord removes one group's record AND every MLS epoch state beside it AND every
 	// copy of a record this device sent in it. It is how a device leaves a group without leaving
 	// its keys, or what it said, on the disk.
@@ -1812,13 +1826,21 @@ func decodeRemoval(part []byte) (uint8, uint64, error) {
 	return part[0], binary.BigEndian.Uint64(part[1:]), nil
 }
 
-// GroupRecords walks the group directory and answers every record it holds.
+// GroupRecords walks the group directory and answers every record it holds that reads.
 //
 // A DIRECTORY WITH NO meta IN IT IS SKIPPED AND NOT A REFUSAL, because that is a real state and
 // not a corruption: mls writes an epoch state at NewGroup, before this package has a pq_secret to
 // write beside it, so a crash between the two leaves exactly that. What it is NOT is a restorable
 // group -- and a group with no record is one this device has to be re-invited to, which is what a
 // missing pq_secret means whatever the MLS state says.
+//
+// A RECORD THAT DOES NOT READ IS REPORTED AND SKIPPED, AND THE OTHERS ARE STILL ANSWERED. It used
+// to be this call's whole answer: one meta that failed its checksum returned an error and no list,
+// so one damaged file cost a device every group on its disk at [Device.Restore]. The error beside
+// the list wraps [ErrGroupRecordDamaged], counts the records skipped and names each BY ITS
+// DIRECTORY. It cannot name them by group id: a directory's name is the SHA-256 of the id
+// ([stateNameOf]) and cannot be turned back into one, and the id inside a record that does not
+// read is not one to believe. A caller that holds an id asks [DurableStateStore.GroupRecord].
 func (self *DurableStateStore) GroupRecords() ([]*GroupRecord, error) {
 	self.lock.Lock()
 	defer self.lock.Unlock()
@@ -1841,28 +1863,78 @@ func (self *DurableStateStore) GroupRecords() ([]*GroupRecord, error) {
 	}
 	sort.Strings(names)
 	records := []*GroupRecord{}
+	damaged := []string{}
+	var firstDamage error
 	for _, name := range names {
-		// A GROUP BEING LEFT IS NOT A GROUP TO RESTORE: its epoch states may already be gone, and a
-		// restore of it would fail at every launch. [Device.Restore] finishes its erase instead.
-		if _, err := os.Stat(filepath.Join(root, name, "forgetting")); err == nil {
-			continue
-		}
-		parts, err := self.readRecord(filepath.Join(root, name, "meta"), stateKindGroupRecord)
+		record, err := self.groupRecordInLocked(name)
 		if err != nil {
 			if errors.Is(err, ErrStateNotFound) {
 				continue
 			}
-			return nil, err
-		}
-		record, err := groupRecordOf(name, parts)
-		if err != nil {
-			return nil, err
+			damaged = append(damaged, name)
+			if firstDamage == nil {
+				firstDamage = err
+			}
+			continue
 		}
 		records = append(records, record)
 	}
+	if firstDamage != nil {
+		return records, fmt.Errorf("%w (in all, %d of the %d group directories on this disk: %s)",
+			firstDamage, len(damaged), len(names), strings.Join(damaged, ", "))
+	}
 	return records, nil
 }
 
+// GroupRecord answers the one record this store holds for groupId: see [DeviceStore.GroupRecord].
+//
+// IT READS ONE DIRECTORY AND NO OTHER, which is the point of it. The held-group gate, a founding
+// and [Device.ForgetGroup] each hold one group id, and each used to ask the whole list, so a
+// record of ANOTHER group that did not read answered every one of them: the device could then
+// join nothing, found nothing and leave nothing, and no call cleared it.
+func (self *DurableStateStore) GroupRecord(groupId []byte) (*GroupRecord, error) {
+	self.lock.Lock()
+	defer self.lock.Unlock()
+	if err := self.refuseIfClosed(); err != nil {
+		return nil, err
+	}
+	return self.groupRecordInLocked(stateNameOf(groupId))
+}
+
+// groupRecordInLocked reads the record in one group directory, for the list and for the one-id
+// read alike, so that the two cannot answer differently about one group. It answers the record;
+// [ErrStateNotFound] when the directory holds none or the group is being left; and an error
+// wrapping [ErrGroupRecordDamaged] when a record is there and does not read.
+//
+// THE RECORD MUST NAME THE DIRECTORY IT SITS IN, which is [DurableStateStore.GroupsBeingForgotten]'s
+// rule for a leave mark and is here for the reason the one-id read exists: the directory is found
+// by the id, so a record that named another group would be held by the list under an id the
+// one-id read answers "not held" for.
+func (self *DurableStateStore) groupRecordInLocked(name string) (*GroupRecord, error) {
+	dir := filepath.Join(self.dataDir, "group", name)
+	// A GROUP BEING LEFT IS NOT A GROUP TO RESTORE: its epoch states may already be gone, and a
+	// restore of it would fail at every launch. [Device.Restore] finishes its erase instead.
+	if _, err := os.Stat(filepath.Join(dir, "forgetting")); err == nil {
+		return nil, fmt.Errorf("%w: the group in %s is being left", ErrStateNotFound, name)
+	}
+	parts, err := self.readRecord(filepath.Join(dir, "meta"), stateKindGroupRecord)
+	if err != nil {
+		if errors.Is(err, ErrStateNotFound) {
+			return nil, err
+		}
+		return nil, fmt.Errorf("%w: the record in %s: %w", ErrGroupRecordDamaged, name, err)
+	}
+	record, err := groupRecordOf(name, parts)
+	if err != nil {
+		return nil, fmt.Errorf("%w: %w", ErrGroupRecordDamaged, err)
+	}
+	if stateNameOf(record.GroupId) != name {
+		return nil, fmt.Errorf("%w: %w: the record in %s does not name its own group",
+			ErrGroupRecordDamaged, ErrStateStoreFormat, name)
+	}
+	return record, nil
+}
+
 // groupRecordOf is one durable group record's parts as a [GroupRecord], and the arity switch that
 // lets a store written before the pq_secret table still be read.
 //
@@ -1878,8 +1950,9 @@ func (self *DurableStateStore) GroupRecords() ([]*GroupRecord, error) {
 // bug with the compatibility path. [Device.restoreOne] is the one place that distinction is acted
 // on.
 //
-// IT IS A FUNCTION RATHER THAN THE BODY OF THAT LOOP BECAUSE OF A MEASUREMENT, which is the part
-// worth keeping. Inside [DurableStateStore.GroupRecords] the record's parts are a LOCAL called
+// IT IS A FUNCTION RATHER THAN PART OF THE READ THAT CALLS IT BECAUSE OF A MEASUREMENT, which is
+// the part worth keeping. Inside that read ([DurableStateStore.groupRecordInLocked], which the list
+// and the one-id read share) the record's parts are a LOCAL called
 // `parts` -- a generic record off a generic read -- and no census in this package could taint it:
 // pqsecretgate_test.go's walk seeds a PARAMETER, and wrapseedgate_test.go's `parts` entry seeds
 // the WRITE path's three functions and not this one. Mutant pq-M2 measured it: a `%x` of
```

- [ ] **Step 4: the gates this moves.** The pq_secret census names the function a joined group is filed through, so its entries for `hold` are respelled in the same commit. No census entry moves for the store's new read: both key-material gates pass on it as it is.

`sdk/urmessage/pqsecretgate_test.go`:

```diff
--- a/sdk/urmessage/pqsecretgate_test.go
+++ b/sdk/urmessage/pqsecretgate_test.go
@@ -321,9 +321,10 @@ var pqSecretSinks = map[string]pqSecretSink{
 		carries: []string{"invite.PqSecret"},
 		why:     "the joiner's session, built over the secret of the epoch it is admitted at.",
 	},
-	"Join|call self.hold": {
+	"Join|call self.holdReplacing": {
 		carries: []string{"group"},
-		why:     "the group going onto the device.",
+		why: "the group going onto the device, in place of the one a commit removed this device from " +
+			"when the join is a re-add. The replaced group is closed, which erases its own table.",
 	},
 	"Join|call self.persistGroup": {
 		carries: []string{"group"},
@@ -854,10 +855,6 @@ var pqSecretSinks = map[string]pqSecretSink{
 		why: "the restored table going to the one question a restarted device can answer about it: are " +
 			"there two different values in it.",
 	},
-	"restoreOne|call self.hold": {
-		carries: []string{"restored"},
-		why:     "the restored group going onto the device.",
-	},
 	"restoreOne|call session.InstallPqSecret": {
 		carries: []string{"row", "row.secret"},
 		why: "EACH PAST EPOCH GOING BACK INTO CONNECT'S TABLE. It carries the row's epoch and the " +
@@ -1030,7 +1027,7 @@ var pqSecretAccumulatorSites = map[string]string{
 	"Encode|accumulate writer.WriteOpaqueLP": "THE INVITE'S BUFFER. The secret goes into the syntax writer and the walk does not follow " +
 		"it into that object; it comes back out as the encoded invite, which is the out-of-band " +
 		"value by design.",
-	"Join|accumulate self.hold": "the same, for a joiner.",
+	"Join|accumulate self.holdReplacing": "the same, for a joiner.",
 	"Join|accumulate self.persistGroup": "THE DISK, one frame out. [Device.persistGroup] hands the record to the store, whose own " +
 		"write path IS censused -- PutGroupRecord, and the two calls under it -- so the blindness " +
 		"here is bounded by one function body.",
@@ -1058,7 +1055,6 @@ var pqSecretAccumulatorSites = map[string]string{
 		"keeps nothing and it derives nothing; its whole body is a ConstantTimeCompare of the " +
 		"candidate against rows of a table this census already covers, and what it answers is an " +
 		"epoch number and a bool. Its header carries why the subject is the whole table.",
-	"restoreOne|accumulate self.hold":                        "the same, for a restored group.",
 	"sealEpochWrapLocked|accumulate self.session.SealRecord": "the session's sealer, taking the wrap body that is already a ciphertext of the secret.",
 	"writeRecord|accumulate temp.Write": "THE DISK. What happens to those octets after this call is the filesystem's and not a " +
 		"value any walk over this package's names can follow. It is the honest end of this census " +
```

- [ ] **Step 5: the registry.** Five entries close, and one control is added, `S7-c2-unreadable-record-costs-one-group`: the scenario R12 words, beside `S7-c1`.

`sdk/cp3b/testdata/advsim/known-gaps.json`:

```diff
--- a/sdk/cp3b/testdata/advsim/known-gaps.json
+++ b/sdk/cp3b/testdata/advsim/known-gaps.json
@@ -15,13 +15,14 @@
     {"id": "S3-late-refusal-spends-join-code", "state": "open", "expect": ["join-code-spent"], "goal": [], "closed_by": "T1a", "reads": "an invitation refused after the engine has joined costs the joiner its join code and leaves state behind"},
     {"id": "S3-mg1-join-code-substitution", "state": "open", "expect": ["swapper-read:1"], "goal": [], "closed_by": "T2", "reads": "a swapper substitutes its own join code; the founder adds the swapper believing it is the victim, and the swapper reads what the founder sends"},
     {"id": "S4-state-thief", "state": "open", "expect": ["epoch:1"], "goal": [], "closed_by": "T3", "reads": "a copy of the joiner's state directory taken after the join reads the join epoch: keys at rest are plaintext"},
-    {"id": "S7a-held-id-valid-invite", "state": "open", "expect": ["epoch-state-replaced", "record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "a valid invitation into an attacker's group founded under a group id the victim holds replaces the victim's group"},
-    {"id": "S7b-held-id-refused-late", "state": "open", "expect": ["epoch-state-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "the same invitation, bent so that it is refused after the engine has joined, still replaces the held group's epoch state"},
+    {"id": "S7a-held-id-valid-invite", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "a valid invitation into an attacker's group founded under a group id the victim holds replaces the victim's group"},
+    {"id": "S7b-held-id-refused-late", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "the same invitation, bent so that it is refused after the engine has joined, still replaces the held group's epoch state"},
     {"id": "S7c-fresh-id-held-welcome", "state": "open", "expect": ["epoch-state-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "an invitation that names a fresh group id and carries a welcome for the held group replaces the held group's epoch state"},
-    {"id": "S7d-held-on-disk-only", "state": "open", "expect": ["epoch-state-replaced", "record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "the victim has restarted and not restored: the group is on its disk and not in its memory, and the invitation replaces it"},
-    {"id": "S7e-held-id-unheld-epoch", "state": "open", "expect": ["record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "the victim joined above epoch one, so the hostile welcome stands at an epoch it holds no state for: only the held-group gate itself is in the way"},
-    {"id": "S7f-on-disk-unheld-epoch", "state": "open", "expect": ["record-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "both at once: on disk and not in memory, at an epoch the victim holds no state for; only the gate's reading of the records on the disk is in the way"},
+    {"id": "S7d-held-on-disk-only", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "the victim has restarted and not restored: the group is on its disk and not in its memory, and the invitation replaces it"},
+    {"id": "S7e-held-id-unheld-epoch", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "the victim joined above epoch one, so the hostile welcome stands at an epoch it holds no state for: only the held-group gate itself is in the way"},
+    {"id": "S7f-on-disk-unheld-epoch", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "both at once: on disk and not in memory, at an epoch the victim holds no state for; only the gate's reading of the records on the disk is in the way"},
     {"id": "S7g-removed-group-second-founder", "state": "open", "expect": ["record-replaced", "removal-forgotten"], "goal": [], "closed_by": "T2", "reads": "a second founder's invitation, standing above the epoch of the removal, into a group of its own under the id of a group this device was removed from: the record is replaced and the device no longer reads as removed"},
-    {"id": "S7-c1-unrestorable-rejoins", "state": "control", "expect": ["rejoined"], "goal": [], "closed_by": "none", "reads": "a group whose record is on the disk and whose epoch states are gone does not restore; it is left with ForgetGroup, the founder removes the stranded leaf and adds a fresh join code, and the device joins again"}
+    {"id": "S7-c1-unrestorable-rejoins", "state": "control", "expect": ["rejoined"], "goal": [], "closed_by": "none", "reads": "a group whose record is on the disk and whose epoch states are gone does not restore; it is left with ForgetGroup, the founder removes the stranded leaf and adds a fresh join code, and the device joins again"},
+    {"id": "S7-c2-unreadable-record-costs-one-group", "state": "control", "expect": ["damage-reported", "damaged-id-not-founded", "damaged-invite-refused", "fresh-id-founded", "other-group-joined", "others-restored", "rejoined"], "goal": [], "closed_by": "none", "reads": "one group record on the device's disk does not read: every other group restores and the damage is reported, another group still joins, a fresh id still founds, a founding under the damaged group's id and an invitation into it are refused while the record stands, and the group is left with ForgetGroup and joined again over the same invitation"}
   ]
 }
```

Measured at this commit with the registry of the commit before: each of these FAILS and names the edit.

```
ADVSIM S7a-held-id-valid-invite state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in
ADVSIM S7b-held-id-refused-late state=open     expect=[epoch-state-replaced restore-lost] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that
ADVSIM S7d-held-on-disk-only state=open     expect=[epoch-state-replaced record-replaced restore-lost] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in th
ADVSIM S7e-held-id-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that clos
ADVSIM S7f-on-disk-unheld-epoch state=open     expect=[record-replaced restore-lost] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that clos
```

- [ ] **Step 6: run it and see it pass.**

```bash
go -C sdk test -count=1 ./urmessage/
go -C sdk/cp3b test -count=1 ./...
go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./... | grep -E '^ADVSIM S7|^ok|^FAIL'
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run): Strict mode has 12 FAIL: `S7a`, `S7b`, `S7d`, `S7e` and `S7f` print `:: CLOSED`, **`S7c` still prints `KNOWN GAP (closed by T1a)`**, and so do the two join-code scenarios. The new control prints `:: CONTROL`.

```
messagegroup   exit=0 pass=359 fail=0
sdk            exit=0 pass=313 fail=0
cp3b           exit=0 pass=113 fail=0
advsim-strict  exit=1 pass=14 fail=12
```

- [ ] **Step 7: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ25`: the held-group gate removed: nothing asks whether the device holds the group. Property 1 must fail. Measured: killed by `TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing`, and 12 other tests.
2. `MJ25b`: the gate asks the device's memory and not its disk. Property 1 must fail. Measured: killed by `TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing`, and 5 other tests.
3. `MJ35`: the gate is asked ABOVE the admission mutex (the first revision of this plan): two joins that overlap both read "not held". Property 2 must fail. Measured: killed by `TestTwoJoinsIntoOneGroupIdThatOverlapAdmitExactlyOne`, and 2 other tests.
4. `MJ38`: the map is written without looking: hold and holdReplacing replace whatever is there. Property 3 must fail. Measured: killed by `TestAMapEntryIsReplacedOnlyByTheJoinThatJudgedIt`.
5. `MJ42`: a founding asks nothing first: the second group under one id is refused only at the hold, after mls wrote its epoch zero. Property 3 must fail. Measured: killed by `TestNoGroupIsFoundedUnderAnIdThisDeviceHolds`, and 2 other tests.
6. `MJ37`: the re-add rule removed: an invitation at or below the epoch of the removal is honoured. Property 4 must fail. Measured: killed by `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins`.
7. `MJ25c`: the removed-group exception removed: a re-add is refused like any held group. Property 4 must fail. Measured: killed by `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins`, and 3 other tests.
8. `MJ36`: ForgetGroup refuses a group Restore could not bring back (the first revision of this plan): such a group can be neither restored, left nor joined again. Property 5 must fail. Measured: killed by `TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain`, and 2 other tests.
9. `MJ36b`: ForgetGroup leaves ANY group that is on the disk and not in memory: a restart is a way round the owner's refusal. Property 5 must fail. Measured: killed by `TestForgetGroupOverAGroupOnTheDiskAnswersByWhatRestoreSaid`, and 1 other test.
10. `MJ53`: the held-group gate asks the store for EVERY record (this plan as it stood at its final check): one record that does not read refuses every invitation on the device. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`, and 4 other tests.
11. `MJ53b`: a founding asks the store for every record: one record that does not read refuses a founding under any id. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`, and 1 other test.
12. `MJ53c`: ForgetGroup asks the store for every record: the damaged record of one group is the answer for another. Property 6 must fail. Measured: killed by `TestForgetGroupLeavesAGroupWhoseRecordDoesNotReadAndThatGroupAlone`.
13. `MJ54`: the gate reads any answer but a record as "not held": a store that cannot answer, and a record that does not read, let the join write. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`, and 1 other test.
14. `MJ54b`: a founding that finds the disk unreadable founds anyway. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`, and 1 other test.
15. `MJ55`: the list answers an error and no list over one record that does not read (the store as it was): Restore brings back nothing. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`, and 1 other test.
16. `MJ55b`: Restore returns on the list's report, before its loop (the device as it was): one damaged file costs every group on the device. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.
17. `MJ55c`: Restore goes on past a record that does not read and says nothing of it. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.
18. `MJ56`: ForgetGroup refuses a group whose record does not read (this plan as it stood at its final check): it can be neither restored, left nor joined again. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`, and 1 other test.
19. `MJ66`: a record that does not read is refused as "could not be read", which names no remedy (this plan as it stood at its final check): the person is not sent to ForgetGroup. Property 6 must fail. Measured: killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.
20. `MJ54`: the gate reads any answer but a record as "not held": a store that cannot answer, and a record that does not read, let the join write. Property 7 must fail. Measured: killed by `TestAStoreThatCannotAnswerRefusesTheJoinAndTheFoundingOfThatGroupAndOfNoOther`, and 1 other test.
21. `MJ54b`: a founding that finds the disk unreadable founds anyway. Property 7 must fail. Measured: killed by `TestAStoreThatCannotAnswerRefusesTheJoinAndTheFoundingOfThatGroupAndOfNoOther`, and 1 other test.
22. `MJ59`: a record is answered from a directory it does not name: the list holds a group the one-id read answers "not held" for. Property 7 must fail. Measured: killed by `TestOneRecordThatDoesNotReadIsReportedByTheListAndAnsweredOnlyForItsOwnGroup`.
23. `MJ57`: Restore is outside the admission mutex: it files groups while a join is between its question and its hold. Property 8 must fail. Measured: killed by `TestARestoreThatOverlapsAJoinWaitsForIt`.
24. `MJ58`: CreateGroup is outside the admission mutex: a founding asks whether its id is held while a join into that id is between its question and its hold. Property 8 must fail. Measured: killed by `TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld`.

- [ ] **Step 8: commit.**

```bash
git add sdk/urmessage/heldgroup_test.go sdk/urmessage/heldrecord_test.go sdk/cp3b/heldgroup_test.go sdk/cp3b/advsim_join_test.go sdk/cp3b/advsim_oracle_test.go sdk/urmessage/heldgroup.go sdk/urmessage/errors.go sdk/urmessage/device.go sdk/urmessage/group.go sdk/urmessage/forget.go sdk/urmessage/restore.go sdk/urmessage/statestore_durable.go sdk/urmessage/pqsecretgate_test.go sdk/cp3b/testdata/advsim/known-gaps.json
git commit -m "urmessage: an invite into a group this device holds is refused, under one admission mutex, and one record that does not read costs one group"
```

The new control on this commit, as it printed:

```
ADVSIM S7-c2-unreadable-record-costs-one-group state=control  expect=[damage-reported damaged-id-not-founded damaged-invite-refused fresh-id-founded other-group-joined others-restored rejoined] observed=[damage-reported damaged-id-not-founded damaged-invite-refused fresh-id-founded other-group-joined others-restored rejoined] :: CONTROL
```

And with the registry of the commit before, which has no line for it, the same scenario is a harness fault and not a verdict, so the line goes in with the scenario:

```
FAIL(HARNESS): scenario "S7-c2-unreadable-record-costs-one-group" has no registry entry; every scenario's expected observation is written down first
```

### Task 34: The engine's bound door: `JoinFromWelcomeInto`

- Consumes: the amended Spec A section 6 (Task 32); `mls`'s intent match on `GroupConfig.GroupId`, ahead of its persist
- Produces: `JoinFromWelcomeInto` on `GroupEngine`, `ErrEngineJoinGroupId`, and a section of `messagegroup/OPENITEMS.md` under MG-1

**Behaviour.** A sixth method on `messagegroup.GroupEngine`. It joins a welcome only if the
welcome describes the group the caller names; otherwise `mls`'s own intent check refuses before any
state is written, and the engine's existing loop puts the join code back. An empty id is refused
with `ErrEngineJoinGroupId`. `JoinFromWelcome` keeps its meaning. It authenticates nobody, exactly
as the first door, and the open items file says so under MG-1.

**Gates this moves, in the same commit.** Three gates of `messagegroup` pin the engine's shape,
and each is amended for a stated reason rather than loosened:

- `TestTheEngineInterfacesAreExactlySectionSixsBlock`: `GroupEngine` has 6 methods and
  `GroupHandle` 35, 41 in all. The sentences of `engine.go` and `engine_test.go` that said five,
  and 40, are corrected with it.
- `TestTheJoinConfigCarriesExactlyTheFieldsTheJoinReads`: REVERSED. It used to require that the
  join's `GroupConfig` leave `GroupId` unset; it now requires that it is set, from the bare
  parameter `groupId`, in the one function that calls `mls.JoinFromWelcome`.
- `TestNoProductionSentenceOfThisPackageSaysAJoinIsImpossible`: the second seam method is named,
  and one disposition is added.

**Property 1.** `JoinFromWelcomeInto` refuses a welcome for any group but the one its caller names, before anything is written, and the join code it took is back in the store.

**Property 2.** `JoinFromWelcomeInto` refuses an empty group id.

- [ ] **Step 1: the tests first.**

`messagegroup/enginejoininto_test.go` (new file, 66 lines):

```go
package messagegroup

import (
	"bytes"
	"fmt"
	"testing"
)

// JoinFromWelcomeInto is JoinFromWelcome with the caller's group id matched inside connect/mls,
// AHEAD of the persist. The property is what a refused Welcome leaves behind: no epoch state, and
// the key package still in the store.
//
// WHAT WOULD GO RED: build the join's mls.GroupConfig without GroupId and the first call below
// joins and writes a state under the Welcome's own id, which is the defect this door closes.
func TestJoinFromWelcomeIntoRefusesAWelcomeForAnotherGroupBeforeAnythingIsWritten(t *testing.T) {
	fixture := newEngineJoinFixture(t, "the-bound-join", true)
	real := fixture.handle.GroupId()
	statesBefore := len(fixture.joiner.store.groupStates)
	asked := bytes.Repeat([]byte{0x5D}, len(real))

	refused, err := fixture.joiner.engine.JoinFromWelcomeInto(fixture.welcome, fixture.ratchetTree, asked)
	if err == nil {
		t.Fatal("a welcome describing one group joined under another group's id")
	}
	if refused != nil {
		t.Error("the refused join answered a handle beside its error")
	}
	if got := len(fixture.joiner.store.groupStates); got != statesBefore {
		t.Errorf("the refused join left %d group state(s) in the store and there were %d before it", got, statesBefore)
	}
	if _, held := fixture.joiner.store.keyPackages[fmt.Sprintf("%x", fixture.joinerRef)]; !held {
		t.Fatalf("the joiner's key package is gone after a refused join, so the honest welcome can never be opened")
	}

	// THE CONTROL, and the other half of the property: the same welcome under the id it does
	// describe joins, over the key package the refusal put back.
	joined, err := fixture.joiner.engine.JoinFromWelcomeInto(fixture.welcome, fixture.ratchetTree, real)
	if err != nil {
		t.Fatalf("the welcome under its own group id: %v", err)
	}
	defer joined.Close()
	if !bytes.Equal(joined.GroupId(), real) {
		t.Errorf("the bound join answered group %x and was asked for %x", joined.GroupId(), real)
	}
	if got := len(fixture.joiner.store.groupStates); got != statesBefore+1 {
		t.Errorf("the join left %d group state(s) in the store, want the %d before it and one more", got, statesBefore)
	}
}

// An empty id is refused by name before the key package is touched: it is the one value that would
// turn the intent match off and make this door the unbound one.
func TestJoinFromWelcomeIntoRefusesAnEmptyGroupId(t *testing.T) {
	fixture := newEngineJoinFixture(t, "the-bound-join-empty-id", true)
	for _, empty := range [][]byte{nil, {}} {
		refused, err := fixture.joiner.engine.JoinFromWelcomeInto(fixture.welcome, fixture.ratchetTree, empty)
		if !errorIs(err, ErrEngineJoinGroupId) {
			t.Errorf("an empty group id answered %v, want ErrEngineJoinGroupId", err)
		}
		if refused != nil {
			t.Error("the refused join answered a handle beside its error")
		}
	}
	if _, held := fixture.joiner.store.keyPackages[fmt.Sprintf("%x", fixture.joinerRef)]; !held {
		t.Fatal("the joiner's key package was taken by a join that was refused for its arguments")
	}
}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go test -count=1 -run ^(TestJoinFromWelcomeIntoRefusesAWelcomeForAnotherGroupBeforeAnythingIsWritten|TestJoinFromWelcomeIntoRefusesAnEmptyGroupId) ./messagegroup/
exit status 1
FAIL	github.com/urnetwork/message/messagegroup [build failed]
FAIL
 # github.com/urnetwork/message/messagegroup [github.com/urnetwork/message/messagegroup.test]
messagegroup\enginejoininto_test.go:21:40: fixture.joiner.engine.JoinFromWelcomeInto undefined (type GroupEngine has no field or method JoinFromWelcomeInto)
messagegroup\enginejoininto_test.go:37:39: fixture.joiner.engine.JoinFromWelcomeInto undefined (type GroupEngine has no field or method JoinFromWelcomeInto)
messagegroup\enginejoininto_test.go:55:41: fixture.joiner.engine.JoinFromWelcomeInto undefined (type GroupEngine has no field or method JoinFromWelcomeInto)
messagegroup\enginejoininto_test.go:56:20: undefined: ErrEngineJoinGroupId
```

- [ ] **Step 3: the change.**

`messagegroup/engine.go`:

```diff
--- a/messagegroup/engine.go
+++ b/messagegroup/engine.go
@@ -42,8 +42,9 @@ import (
 // GroupEngine is the factory half of section 6: everything a caller needs in order to obtain a
 // GroupHandle, and nothing about a group it already holds.
 //
-// Five methods. Four are transcribed from section 6's block and the fifth is LoadGroup, which is a
-// section 6 AMENDMENT and is documented as one at its declaration below. JoinFromWelcome is HERE
+// Six methods. Four are transcribed from section 6's block; the fifth is LoadGroup and the sixth
+// is JoinFromWelcomeInto, and each of those two is a section 6 AMENDMENT, documented as one at its
+// declaration below. JoinFromWelcome is HERE
 // and not on GroupHandle, which is worth stating because the other factories are obviously
 // factories and this one reads like a group operation: a member joining from a Welcome has no
 // handle yet, and putting it on the handle would require one to exist before the join that
@@ -104,6 +105,24 @@ type GroupEngine interface {
 	LoadGroup(groupId []byte, epoch uint64) (GroupHandle, error)
 
 	JoinFromWelcome(welcome []byte, ratchetTree []byte) (GroupHandle, error)
+
+	// JoinFromWelcomeInto is JoinFromWelcome for a caller that KNOWS WHICH GROUP IT MEANS TO JOIN.
+	// IT IS THE SIXTH METHOD, an amendment made for the hardening program's held-group gate, and
+	// the one thing it adds is the group id.
+	//
+	// THE GROUP ID IS THE CALLER'S AND IS MATCHED BEFORE THE JOINED EPOCH IS PERSISTED.
+	// JoinFromWelcome leaves connect/mls's intent match off, because section 6 gave it no group id
+	// to intend. Its caller in the sdk compared the id AFTERWARDS, which was after mls had
+	// persisted the joined epoch under the id THE WELCOME named: an invite naming one group and
+	// carrying a Welcome for a group the device already held replaced that group's epoch state and
+	// was only then refused. Measured, in sdk/cp3b, before this method existed. Through this door a
+	// Welcome describing any group but groupId is refused inside mls, ahead of its persist, and the
+	// key package goes back as it does on every other refusal.
+	//
+	// IT AUTHENTICATES NOBODY, exactly as JoinFromWelcome: a group id is public, and a forged
+	// Welcome naming the id its target expects passes the match. What the match buys is that the
+	// id a caller judged -- is this a group I already hold? -- is the id that gets written.
+	JoinFromWelcomeInto(welcome []byte, ratchetTree []byte, groupId []byte) (GroupHandle, error)
 }
 
 // GroupHandle is the entire MLS surface the storage layer is allowed to see.
@@ -611,7 +630,7 @@ func NewConnectMlsEngine(crypto mls.CryptoProvider, store mls.StateStore,
 // Zeroize erases the identity signing key this engine holds a copy of.
 //
 // NOTHING IN THIS PACKAGE CALLS IT, and that is a gap in section 6 rather than an oversight here:
-// GroupEngine has five methods and none of them is a lifecycle method, so an engine has no
+// GroupEngine has six methods and none of them is a lifecycle method, so an engine has no
 // documented end. mls.Group clones the same signer into every group this device founds and erases
 // its own copy at Close; this copy has no Close to be erased at. The erase is declared so the
 // obligation sits on the type that holds the octets -- which is where connect/mls's erase reading
@@ -811,6 +830,21 @@ func (self *connectMlsEngine) LoadGroup(groupId []byte, epoch uint64) (GroupHand
 // two apart even though a caller matching on the type cannot. The taxonomy that would let the type
 // tell them apart is owed by whoever owns the store interface.
 func (self *connectMlsEngine) JoinFromWelcome(welcome []byte, ratchetTree []byte) (GroupHandle, error) {
+	return self.joinFromWelcome(welcome, ratchetTree, nil)
+}
+
+// JoinFromWelcomeInto is JoinFromWelcome with connect/mls's intent match on: see the interface.
+func (self *connectMlsEngine) JoinFromWelcomeInto(welcome []byte, ratchetTree []byte, groupId []byte) (GroupHandle, error) {
+	if len(groupId) == 0 {
+		return nil, ErrEngineJoinGroupId
+	}
+	return self.joinFromWelcome(welcome, ratchetTree, groupId)
+}
+
+// joinFromWelcome is the body both doors share: the key package refs a Welcome names, the take,
+// the join over the one taken entry, and the put-back on every failure after the take. groupId is
+// nil through JoinFromWelcome and the caller's own through JoinFromWelcomeInto.
+func (self *connectMlsEngine) joinFromWelcome(welcome []byte, ratchetTree []byte, groupId []byte) (GroupHandle, error) {
 	parsed, err := mls.ParseMLSMessage(welcome)
 	if err != nil {
 		return nil, fmt.Errorf("%w: %d octets do not decode as an MLSMessage: %w",
@@ -830,7 +864,7 @@ func (self *connectMlsEngine) JoinFromWelcome(welcome []byte, ratchetTree []byte
 			continue
 		}
 		handle, joinErr := self.joinWithTakenKeyPackage(welcome, ratchetTree, encoded,
-			initPrivate, encryptPrivate)
+			initPrivate, encryptPrivate, groupId)
 		if joinErr != nil {
 			// the put-back, on EVERY failure after the take rather than on a named list of
 			// them: an allow-list of failure reasons is the shape that fails open the day
@@ -877,7 +911,7 @@ func (self *connectMlsEngine) JoinFromWelcome(welcome []byte, ratchetTree []byte
 // header. Rejected: not calling Zeroize at all, which leaves the two HPKE halves in the heap and
 // buys nothing.
 func (self *connectMlsEngine) joinWithTakenKeyPackage(welcome []byte, ratchetTree []byte,
-	encoded []byte, initPrivate []byte, encryptPrivate []byte) (GroupHandle, error) {
+	encoded []byte, initPrivate []byte, encryptPrivate []byte, groupId []byte) (GroupHandle, error) {
 
 	var keyPackage mls.KeyPackage
 	if err := syntax.Unmarshal(encoded, &keyPackage); err != nil {
@@ -895,16 +929,21 @@ func (self *connectMlsEngine) joinWithTakenKeyPackage(welcome []byte, ratchetTre
 	defer keys.Zeroize()
 	// THE CONFIG CARRIES ONLY WHAT THE JOIN READS. mls.JoinFromWelcome's body reads Crypto,
 	// Store, Profile -- defaulted if nil -- and GroupId, and GroupId ONLY as an intent match the
-	// caller opts into. Section 6's signature gives this engine no group id to intend, so it is
-	// left unset: a config that guessed one would refuse every legitimate Welcome, and a config
-	// that recovered one from the message it is about to judge would turn an intent match into a
-	// tautology, which is worse than leaving it unset because it reads like a check. Suite,
-	// Extensions, RequiredCaps and LeafKeys are the four CreateGroup sets and this must not --
-	// they are unread on this path, because required capabilities come off the Welcome's own
-	// GroupInfo.
+	// caller opts into. Suite, Extensions, RequiredCaps and LeafKeys are the four CreateGroup sets
+	// and this must not -- they are unread on this path, because required capabilities come off
+	// the Welcome's own GroupInfo.
+	//
+	// THE GROUP ID IS THE CALLER'S OR IT IS ABSENT, AND IT IS NEVER THIS ENGINE'S GUESS. Through
+	// JoinFromWelcome it is nil, section 6's signature having given that door no group id to
+	// intend, and mls reads an empty one as "no intent stated". Through JoinFromWelcomeInto it is
+	// the id the caller was told it is joining -- for the sdk, the one an invite names beside its
+	// Welcome -- so the match is between two things the caller was handed. A config that guessed
+	// one would refuse every legitimate Welcome, and one that recovered it from the Welcome it is
+	// about to judge would turn the intent match into a tautology that reads like a check.
 	group, err := mls.JoinFromWelcome(&mls.GroupConfig{
-		Crypto: self.crypto,
-		Store:  self.store,
+		Crypto:  self.crypto,
+		Store:   self.store,
+		GroupId: groupId,
 	}, welcome, ratchetTree, keys)
 	if err != nil {
 		return nil, err
```

`messagegroup/errors.go`:

```diff
--- a/messagegroup/errors.go
+++ b/messagegroup/errors.go
@@ -177,6 +177,10 @@ var (
 	// on the type, and the only place the difference can survive is the message. The taxonomy
 	// that would let the type tell them apart is owed by whoever owns the store interface.
 	ErrEngineNoKeyPackageForWelcome = errors.New("messagegroup: no key package this store holds is addressed by this welcome")
+	// Fires when JoinFromWelcomeInto is handed an empty group id. That door is for a caller that
+	// knows which group it means to join, and an empty id is the one value that turns the intent
+	// match off inside connect/mls and makes this door JoinFromWelcome under another name.
+	ErrEngineJoinGroupId = errors.New("messagegroup: JoinFromWelcomeInto names the group it joins, and the group id it was given is empty")
 	// Fires when MemberAt is asked for an ordinal the membership does not have. It is a
 	// refusal and not a zero member because the two are told apart by nothing downstream: a
 	// projection that dropped mls.MemberAt's second result would turn a missing member into
```

`messagegroup/OPENITEMS.md`:

```diff
--- a/messagegroup/OPENITEMS.md
+++ b/messagegroup/OPENITEMS.md
@@ -89,6 +89,15 @@ Nothing below is decided and this package must not decide it.
 4. **Whose obligation it is**, and this item takes no position: the ruling may put it on `sdk`,
    on the application, or on a new method of section 6.
 
+### The second door carries the same obligation
+
+`GroupEngine.JoinFromWelcomeInto` is the sixth engine method, added by the hardening program's
+held-group gate. It is `JoinFromWelcome` with the group id its caller means to join, matched
+inside `mls` ahead of the persist, so that the id a caller judged ("do I already hold this group?")
+is the id that gets written. **It authenticates nobody, exactly as the first door**: a group id is
+public, and a forged Welcome naming the id its target expects passes the match. Everything this
+item says of `JoinFromWelcome` is said of both, and a ruling that closes it closes it at both.
+
 ### Why it is not closed here
 
 An anchoring mechanism chosen in an adapter is a security argument taken by the layer with the
```

- [ ] **Step 4: the gates this moves.** The three gates named above.

`messagegroup/engine_test.go`:

```diff
--- a/messagegroup/engine_test.go
+++ b/messagegroup/engine_test.go
@@ -50,6 +50,11 @@ var sectionSixGroupEngine = map[string]string{
 	// unexported. A restored group therefore could not ingest a commit. That was open item J1-8 and
 	// LoadGroup is the change it named.
 	"LoadGroup": "func(groupId []byte, epoch uint64) (GroupHandle, error)",
+	// THE SIXTH, AMENDED FOR THE HARDENING PROGRAM'S HELD-GROUP GATE. JoinFromWelcome's signature
+	// carries no group id, so connect/mls's intent match was off and the sdk compared the id after
+	// mls had persisted the joined epoch under the id the Welcome named. This door carries the id
+	// in, which is the whole of what it adds.
+	"JoinFromWelcomeInto": "func(welcome []byte, ratchetTree []byte, groupId []byte) (GroupHandle, error)",
 }
 
 var sectionSixGroupHandle = map[string]string{
@@ -288,8 +293,17 @@ func TestTheEngineInterfacesAreExactlySectionSixsBlock(t *testing.T) {
 	// removal's post-commit policy is. And ZERO methods for the removed-leaf set the same ruling
 	// derives, which is the other half of it: that read went on the PendingEpoch value this
 	// interface already answers, so the seam grew a field rather than a thirty-sixth method.
-	if len(sectionSixGroupEngine) != 5 || len(sectionSixGroupHandle) != 35 {
-		t.Errorf("section 6's block is transcribed as %d and %d methods; it was measured at 5 and 35, and a change to either is a change to the seam",
+	//
+	// AND IT IS 6 AND 35 FROM THE HARDENING PROGRAM'S HELD-GROUP GATE: the ENGINE half gains
+	// JoinFromWelcomeInto, ONE method, which is JoinFromWelcome carrying the group id its caller
+	// means to join. Without it connect/mls's intent match cannot be turned on from outside this
+	// package, and an invite naming one group while carrying a Welcome for a group the device
+	// already holds writes that group's epoch state before anything refuses it. One method and
+	// not a third parameter on JoinFromWelcome: that door's call sites, in three packages
+	// (`git grep -E '\.JoinFromWelcome\(' -- '*.go'`), state no intent, and a nil they would all
+	// have to pass is the unbound join spelled once per call.
+	if len(sectionSixGroupEngine) != 6 || len(sectionSixGroupHandle) != 35 {
+		t.Errorf("section 6's block is transcribed as %d and %d methods; it was measured at 6 and 35, and a change to either is a change to the seam",
 			len(sectionSixGroupEngine), len(sectionSixGroupHandle))
 	}
 }
@@ -307,8 +321,8 @@ func TestTheEngineInterfacesAreExactlySectionSixsBlock(t *testing.T) {
 // a type change rather than a factory change.
 //
 // The scope question (R3a) is answered separately from the class question: the CLASS is the
-// method set of both interfaces read off the syntax tree, which is 40 members at this commit --
-// 5 and 35, and the figure written here was the HANDLE half alone until 2026-09-25, which is a
+// method set of both interfaces read off the syntax tree, which is 41 members at this commit --
+// 6 and 35, and the figure written here was the HANDLE half alone until 2026-09-25, which is a
 // count its own sentence does not describe -- and is never a list; the SCOPE is engine.go,
 // because that is the file section 2.2's tree puts the
 // interface in and an interface declared anywhere else would fail
@@ -1909,11 +1923,17 @@ func TestTheJoinRefusalTellsAStoreFailureFromAWelcomeAddressedElsewhere(t *testi
 //
 // THE CLASS is the GroupConfig fields mls.JoinFromWelcome reads, and it is FOUR: Crypto, Store,
 // Profile -- defaulted if nil -- and GroupId, which it reads ONLY as an intent match the caller
-// opts into. GroupId is left unset because section 6's signature gives this engine no group id to
-// intend. THE COMPLEMENT IS PRINTED and is the four fields CreateGroup sets and this must not:
+// opts into. THE COMPLEMENT IS PRINTED and is the four fields CreateGroup sets and this must not:
 // Suite, Extensions, RequiredCaps and LeafKeys, all unread on the join path because required
 // capabilities come off the Welcome's own GroupInfo. A gate that did not print them would be one
 // nobody can tell from a gate that checked nothing.
+//
+// GroupId IS SET, AND ONLY FROM THE PARAMETER OF THAT NAME. Until the hardening program's
+// held-group gate this clause read the other way: section 6 gave the engine no group id to intend,
+// so the field stayed unset. JoinFromWelcomeInto now carries the caller's id down, and what this
+// gate holds instead is where the value comes from: the expression is the bare identifier groupId,
+// which is the join body's own parameter. A guess, or an id read back out of the Welcome being
+// judged, is some other expression and fails here.
 func TestTheJoinConfigCarriesExactlyTheFieldsTheJoinReads(t *testing.T) {
 	read := []string{"Crypto", "Store", "Profile", "GroupId"}
 	complement := []string{"Suite", "Extensions", "RequiredCaps", "LeafKeys"}
@@ -1925,8 +1945,11 @@ func TestTheJoinConfigCarriesExactlyTheFieldsTheJoinReads(t *testing.T) {
 	if len(set) == 0 {
 		t.Fatal("no mls.GroupConfig literal was found on this engine's join path, so this gate read nothing")
 	}
-	if slices.Contains(set, "GroupId") {
-		t.Error("the join path sets GroupId. Section 6 gives this engine no group id to intend, so a value here is either a guess that refuses every legitimate welcome or a group id recovered from the message about to be judged -- which turns an intent match into a tautology, and reads like a check")
+	if !slices.Contains(set, "GroupId") {
+		t.Error("the join path does not set GroupId, so connect/mls's intent match is off through both doors and JoinFromWelcomeInto binds nothing")
+	}
+	if source := engineJoinConfigGroupIdSource(t); source != "groupId" {
+		t.Errorf("the join path sets GroupId from %q. It is the caller's own id or it is absent: the one expression this gate admits is the parameter groupId, which JoinFromWelcome passes nil and JoinFromWelcomeInto passes its caller's. An id recovered from the welcome about to be judged turns the intent match into a tautology, and reads like a check", source)
 	}
 	for _, unread := range complement {
 		if slices.Contains(set, unread) {
@@ -2003,6 +2026,84 @@ func engineGroupConfigFieldsSetOnTheJoinPath(t *testing.T) []string {
 	return slices.Compact(named)
 }
 
+// engineJoinConfigGroupIdSource is the source text of the expression the JOIN PATH's
+// mls.GroupConfig literal sets GroupId from, scoped as engineGroupConfigFieldsSetOnTheJoinPath is:
+// the literal inside the production function whose body calls mls.JoinFromWelcome.
+//
+// IT ALSO HOLDS THAT THE NAME IS THAT FUNCTION'S PARAMETER AND IS NEVER ASSIGNED IN ITS BODY. The
+// text "groupId" alone would be satisfied by a local of that name filled from the Welcome, which
+// is the tautology the gate exists to refuse.
+func engineJoinConfigGroupIdSource(t *testing.T) string {
+	t.Helper()
+	fileSet, sources := messagegroupProductionSources(t)
+	found := []string{}
+	for _, source := range sources {
+		for _, declaration := range source.parsed.Decls {
+			function, isFunction := declaration.(*ast.FuncDecl)
+			if !isFunction || function.Body == nil {
+				continue
+			}
+			joins := false
+			ast.Inspect(function.Body, func(node ast.Node) bool {
+				selector, isSelector := node.(*ast.SelectorExpr)
+				if !isSelector || selector.Sel.Name != "JoinFromWelcome" {
+					return true
+				}
+				if qualifier, isIdentifier := selector.X.(*ast.Ident); isIdentifier && qualifier.Name == "mls" {
+					joins = true
+				}
+				return true
+			})
+			if !joins {
+				continue
+			}
+			isParameter := false
+			for _, field := range function.Type.Params.List {
+				for _, name := range field.Names {
+					isParameter = isParameter || name.Name == "groupId"
+				}
+			}
+			ast.Inspect(function.Body, func(node ast.Node) bool {
+				switch typed := node.(type) {
+				case *ast.AssignStmt:
+					for _, left := range typed.Lhs {
+						if name, isName := left.(*ast.Ident); isName && name.Name == "groupId" {
+							t.Errorf("%s assigns groupId in its body; the id the join intends is the caller's, handed down unchanged", function.Name.Name)
+						}
+					}
+				case *ast.CompositeLit:
+					selector, isSelector := typed.Type.(*ast.SelectorExpr)
+					if !isSelector || selector.Sel.Name != "GroupConfig" {
+						return true
+					}
+					for _, element := range typed.Elts {
+						pair, isPair := element.(*ast.KeyValueExpr)
+						if !isPair {
+							continue
+						}
+						if key, isKey := pair.Key.(*ast.Ident); !isKey || key.Name != "GroupId" {
+							continue
+						}
+						rendered := &bytes.Buffer{}
+						if err := printer.Fprint(rendered, fileSet, pair.Value); err != nil {
+							t.Fatalf("render the GroupId expression: %v", err)
+						}
+						if rendered.String() == "groupId" && !isParameter {
+							t.Errorf("%s sets GroupId from a groupId that is not one of its parameters", function.Name.Name)
+						}
+						found = append(found, rendered.String())
+					}
+				}
+				return true
+			})
+		}
+	}
+	if len(found) != 1 {
+		t.Fatalf("the join path sets GroupId in %d place(s) %v, want exactly one", len(found), found)
+	}
+	return found[0]
+}
+
 // TestTheDeviceSurvivesItsOwnJoin is j1 task 5's sixth property, and it is the one whose absence
 // destroys a key.
 //
```

`messagegroup/enginejoin_test.go`:

```diff
--- a/messagegroup/enginejoin_test.go
+++ b/messagegroup/enginejoin_test.go
@@ -372,6 +372,8 @@ var engineJoinDispositions = map[string]string{
 
 	"engine.go JoinFromWelcome": "where the ref comes from (section 6's signature carries none), why exactly one ref is taken and not the first or all, why the take is destructive and puts back, and what the store interface's bare error cannot express. Every one is a statement about a CONSTRAINT the join works within, and the body below them joins",
 
+	"engine.go joinFromWelcome": "the body both doors share since JoinFromWelcomeInto arrived, moved out of JoinFromWelcome with its sentences: the refusal of a message that decodes and carries no welcome arm. That is a MALFORMED input, and the loop below it joins",
+
 	"engine.go joinWithTakenKeyPackage": "the ownership rule: nothing refuses a device whose signing key was erased by its own join, and mls.JoinFromWelcome exits at some fifteen places so the erase is deferred. Both are reasons the join is written the way it is",
 
 	"errors.go ErrEngineWelcomeShape": "the sentinel for octets that are not an MLSMessage carrying a Welcome. It is a refusal of a MALFORMED input and fires on nothing a real Welcome produces",
@@ -428,12 +430,12 @@ func engineJoinPath(t *testing.T) (names map[string]bool, onlyTheJoinCalls []str
 	if seed == "" {
 		t.Fatal("no production declaration of this package calls mls.JoinFromWelcome, so this gate derived its class off nothing and would report clean having read nothing")
 	}
-	names = map[string]bool{seed: true, engineJoinSeamMethod: true}
+	names = map[string]bool{seed: true, engineJoinSeamMethod: true, engineJoinBoundSeamMethod: true}
 	// the seam method is in the frontier as well as in the set. It was in the set only, once, and
 	// the bug that produced is the one this whole block exists about: its body names
 	// ErrEngineNoKeyPackageForWelcome, so leaving it unwalked dropped "welcome" out of the derived
 	// vocabulary and left the class one word wide.
-	frontier := []string{seed, engineJoinSeamMethod}
+	frontier := []string{seed, engineJoinSeamMethod, engineJoinBoundSeamMethod}
 	for _, function := range bodies {
 		if function.Body == nil {
 			continue
@@ -549,6 +551,14 @@ func engineJoinExclusiveNames(t *testing.T) []string {
 // and engineJoinPath fatals rather than deriving a smaller class.
 const engineJoinSeamMethod = "JoinFromWelcome"
 
+// The SECOND seam method, since the hardening program's held-group gate: JoinFromWelcome carrying
+// the group id its caller means to join. It is the join as much as the first is, and it is named
+// here for the reason the first is kept whatever else names it: left out, its own name puts "join"
+// and "welcome" among the words the REST of the package spells, the derived vocabulary loses both,
+// and the gate goes on reporting over a class that has stopped being about the join. Measured
+// before this constant existed: the vocabulary fell from [join welcome] to [zeroize].
+const engineJoinBoundSeamMethod = "JoinFromWelcomeInto"
+
 // engineJoinVocabulary answers the words a sentence about the join is recognised by, and PRINTS
 // what each of its two narrowings removed.
 //
```

- [ ] **Step 5: run it and see it pass.**

```bash
go test -count=1 ./messagegroup/ ./internal/layering/
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run): The harness is unchanged: the sdk does not call the new door yet.

```
messagegroup   exit=0 pass=361 fail=0
sdk            exit=0 pass=313 fail=0
cp3b           exit=0 pass=113 fail=0
advsim-strict  exit=1 pass=14 fail=12
```

- [ ] **Step 6: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ26`: the engine does not hand mls the group id: the intent match is off through both doors. Property 1 must fail. Measured: killed by `TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing`, and 5 other tests.
2. `MJ26c`: the bound door takes an empty group id, which turns the intent match off and makes it the unbound door under another name. Property 2 must fail. Measured: killed by `TestJoinFromWelcomeIntoRefusesAnEmptyGroupId`.

- [ ] **Step 7: commit.**

```bash
git add messagegroup/enginejoininto_test.go messagegroup/engine.go messagegroup/errors.go messagegroup/OPENITEMS.md messagegroup/engine_test.go messagegroup/enginejoin_test.go
git commit -m "messagegroup: JoinFromWelcomeInto joins a welcome only into the group the caller names"
```

### Task 35: The sdk joins through the bound door, and only through it

- Consumes: `JoinFromWelcomeInto` (Task 34); the scenarios of Task 21 and Task 15
- Produces: `TestProductionJoinsOnlyThroughTheBoundDoor`

**Behaviour.** `Join` passes the invitation's group id to the engine. A welcome for any other
group is refused inside the engine before a state is written, and the join code survives. A source
gate reads every production file of `sdk/urmessage` and holds that the bound door is called exactly
once, from `Join`, and the unbound one never: the unbound door stays on the interface for tests,
and a production call of it would be a join that states no group id.

**Property 1.** Production code of `sdk/urmessage` calls `JoinFromWelcomeInto` exactly once, from `Join`, and never calls the unbound `JoinFromWelcome`.

**Property 2.** An invitation that names a fresh group id and carries a welcome for a held group replaces nothing, and an invitation refused for naming another group does not spend the join code.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/heldgroup_test.go`:

```diff
--- a/sdk/urmessage/heldgroup_test.go
+++ b/sdk/urmessage/heldgroup_test.go
@@ -4,6 +4,9 @@ import (
 	"bytes"
 	"context"
 	"errors"
+	"go/ast"
+	"go/parser"
+	"go/token"
 	"testing"
 
 	messageprotocol "github.com/urnetwork/message/protocol"
@@ -146,3 +149,50 @@ func TestNoGroupIsFoundedUnderAnIdThisDeviceHolds(t *testing.T) {
 		t.Fatalf("CONTROL FAILED: founding under an id the device does not hold answered %v", err)
 	}
 }
+
+// PRODUCTION JOINS ONLY THROUGH THE BOUND DOOR. [messagegroup.GroupEngine] keeps JoinFromWelcome,
+// which states no group id and so cannot refuse a Welcome for another group before mls has written
+// its state; the tests of three packages join through it, and may. No production file of this
+// package does.
+//
+// THE SUBJECT is every call in this package's production sources whose selector is one of the
+// engine's two joining doors, read off the syntax tree. THE OTHER HALF IS ASSERTED AND NOT ONLY
+// PRINTED: the bound door is called exactly once, so a gate that had stopped seeing calls at all
+// fails on its control and does not pass on nothing.
+//
+// WHAT WOULD GO RED: have Join call JoinFromWelcome again and compare the group id afterwards,
+// which is the join this package made until the held-group gate.
+func TestProductionJoinsOnlyThroughTheBoundDoor(t *testing.T) {
+	files := token.NewFileSet()
+	unbound, bound := []string{}, []string{}
+	for _, name := range stateTestProductionSources(t) {
+		parsed, err := parser.ParseFile(files, name, nil, 0)
+		if err != nil {
+			t.Fatalf("parsing %s: %v", name, err)
+		}
+		ast.Inspect(parsed, func(node ast.Node) bool {
+			call, isCall := node.(*ast.CallExpr)
+			if !isCall {
+				return true
+			}
+			selector, isSelector := call.Fun.(*ast.SelectorExpr)
+			if !isSelector {
+				return true
+			}
+			switch selector.Sel.Name {
+			case "JoinFromWelcome":
+				unbound = append(unbound, files.Position(call.Pos()).String())
+			case "JoinFromWelcomeInto":
+				bound = append(bound, files.Position(call.Pos()).String())
+			}
+			return true
+		})
+	}
+	t.Logf("calls of JoinFromWelcomeInto in production: %v; calls of JoinFromWelcome: %v", bound, unbound)
+	if len(bound) != 1 {
+		t.Errorf("production calls the bound door %d time(s) %v, want exactly once, from Join: a count of none is this gate reading nothing", len(bound), bound)
+	}
+	if len(unbound) != 0 {
+		t.Errorf("production calls the unbound JoinFromWelcome at %v: a join that states no group id is refused, if at all, after mls has written the joined state", unbound)
+	}
+}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk test -count=1 -run ^(TestProductionJoinsOnlyThroughTheBoundDoor) ./urmessage/
exit status 1
--- FAIL: TestProductionJoinsOnlyThroughTheBoundDoor (0.01s)
    heldgroup_test.go:191: calls of JoinFromWelcomeInto in production: []; calls of JoinFromWelcome: [group.go:1408:17]
    heldgroup_test.go:193: production calls the bound door 0 time(s) [], want exactly once, from Join: a count of none is this gate reading nothing
    heldgroup_test.go:196: production calls the unbound JoinFromWelcome at [group.go:1408:17]: a join that states no group id is refused, if at all, after mls has written the joined state
FAIL
FAIL	github.com/urnetwork/message/sdk/urmessage	0.992s
FAIL
$ go -C sdk/cp3b test -count=1 -run ^(TestAdvSim) ./...
exit status 1
--- FAIL: TestAdvSimARefusedInvitationDoesNotSpendTheJoinCode (0.06s)
    advsim_join_test.go:534: the bent invitation was refused: urmessage: the welcome joined group 206c808248ec6c9c74f1193c9d1218fac73f75adaf53b96d1901d0fc0f1d4f84 and the invite names 7f4a0c8ca9bd63b63f18d461e40c52b9b1e56d9e82244ff8fa227e6472682128
    advsim_join_test.go:543: the honest invitation after the refused one: urmessage: JoinFromWelcome: messagegroup: no key package this store holds is addressed by this welcome: the welcome names 1 key package refs, this store refused 1 of them, and the last refusal it answered was urmessage: this s
    advsim_join_test.go:549: ADVSIM S3-refusal-spends-join-code    state=closed   expect=[] observed=[join-code-spent] :: FAIL (closed): observed [join-code-spent], and this entry holds exactly []
--- FAIL: TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing (0.16s)
    advsim_join_test.go:802: the invitation under a fresh id was answered: urmessage: the welcome joined group 1f8a056592894b51ba7fa58e3cb87a39b1acabccbdb676f2dbb04704acd6900c and the invite names 52881bcdf31750fcccd5ef3d90393fae56d8361305340629a429b39a7dc6cb54
    advsim_join_test.go:733: the held group did not come back: Receive: urmessage: the message server refused this fetch: REASON_REJECTED
    advsim_join_test.go:803: ADVSIM S7c-fresh-id-held-welcome      state=closed   expect=[] observed=[epoch-state-replaced restore-lost] :: FAIL (closed): observed [epoch-state-replaced restore-lost], and this entry holds exactly []
FAIL
FAIL	github.com/urnetwork/message/sdk/cp3b	5.238s
...
```

- [ ] **Step 3: the change.**

`sdk/urmessage/group.go`:

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1405,9 +1405,11 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
 	if err != nil {
 		return nil, err
 	}
-	handle, err := self.engine.JoinFromWelcome(invite.Welcome, invite.RatchetTree)
+	// THE JOIN IS BOUND TO THE GROUP THE INVITE NAMES. A Welcome for any other group is refused
+	// inside the engine, before a state is written, and the join code is put back.
+	handle, err := self.engine.JoinFromWelcomeInto(invite.Welcome, invite.RatchetTree, invite.GroupId)
 	if err != nil {
-		return nil, fmt.Errorf("urmessage: JoinFromWelcome: %w", err)
+		return nil, fmt.Errorf("urmessage: JoinFromWelcomeInto: %w", err)
 	}
 	if !bytes.Equal(handle.GroupId(), invite.GroupId) {
 		handle.Close()
```

- [ ] **Step 4: the registry.** The scenarios this closes now observe the goal, so their entries flip in this commit.

`sdk/cp3b/testdata/advsim/known-gaps.json`:

```diff
--- a/sdk/cp3b/testdata/advsim/known-gaps.json
+++ b/sdk/cp3b/testdata/advsim/known-gaps.json
@@ -11,13 +11,13 @@
     {"id": "S2a-ghk-paste-observer", "state": "open", "expect": ["ghk"], "goal": [], "closed_by": "T1", "reads": "a classical observer of one pasted invitation plus the server's rows recovers group_handle_key, which maps every sender_handle to a leaf for the group's life"},
     {"id": "S2b-first-appearance-link", "state": "residual", "expect": ["linked:2/2"], "goal": [], "closed_by": "none", "reads": "with no key at all, the order sender handles first appear in the server's rows links the founder and this paste's joiner to their handles; sealing the secrets does not change it"},
     {"id": "S3-chosen-secret", "state": "open", "expect": ["installed:attacker-secret"], "goal": [], "closed_by": "T1", "reads": "an attacker on the paste channel rewrites the invitation so that it carries secrets the attacker chose, and the joiner installs them"},
-    {"id": "S3-refusal-spends-join-code", "state": "open", "expect": ["join-code-spent"], "goal": [], "closed_by": "T1a", "reads": "an invitation refused for naming another group costs the joiner its one-use join code, so the honest invitation that follows cannot be joined"},
+    {"id": "S3-refusal-spends-join-code", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "an invitation refused for naming another group costs the joiner its one-use join code, so the honest invitation that follows cannot be joined"},
     {"id": "S3-late-refusal-spends-join-code", "state": "open", "expect": ["join-code-spent"], "goal": [], "closed_by": "T1a", "reads": "an invitation refused after the engine has joined costs the joiner its join code and leaves state behind"},
     {"id": "S3-mg1-join-code-substitution", "state": "open", "expect": ["swapper-read:1"], "goal": [], "closed_by": "T2", "reads": "a swapper substitutes its own join code; the founder adds the swapper believing it is the victim, and the swapper reads what the founder sends"},
     {"id": "S4-state-thief", "state": "open", "expect": ["epoch:1"], "goal": [], "closed_by": "T3", "reads": "a copy of the joiner's state directory taken after the join reads the join epoch: keys at rest are plaintext"},
     {"id": "S7a-held-id-valid-invite", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "a valid invitation into an attacker's group founded under a group id the victim holds replaces the victim's group"},
     {"id": "S7b-held-id-refused-late", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "the same invitation, bent so that it is refused after the engine has joined, still replaces the held group's epoch state"},
-    {"id": "S7c-fresh-id-held-welcome", "state": "open", "expect": ["epoch-state-replaced", "restore-lost"], "goal": [], "closed_by": "T1a", "reads": "an invitation that names a fresh group id and carries a welcome for the held group replaces the held group's epoch state"},
+    {"id": "S7c-fresh-id-held-welcome", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "an invitation that names a fresh group id and carries a welcome for the held group replaces the held group's epoch state"},
     {"id": "S7d-held-on-disk-only", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "the victim has restarted and not restored: the group is on its disk and not in its memory, and the invitation replaces it"},
     {"id": "S7e-held-id-unheld-epoch", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "the victim joined above epoch one, so the hostile welcome stands at an epoch it holds no state for: only the held-group gate itself is in the way"},
     {"id": "S7f-on-disk-unheld-epoch", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "both at once: on disk and not in memory, at an epoch the victim holds no state for; only the gate's reading of the records on the disk is in the way"},
```

Measured at this commit with the registry of the commit before: each of these FAILS and names the edit.

```
ADVSIM S3-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
ADVSIM S7c-fresh-id-held-welcome state=open     expect=[epoch-state-replaced restore-lost] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit tha
```

- [ ] **Step 5: run it and see it pass.**

```bash
go -C sdk test -count=1 ./urmessage/
go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./... | grep -E '^ADVSIM S7c|^ADVSIM S3-refusal|^ADVSIM S3-late|^ok|^FAIL'
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run): `S7c` and `S3-refusal` print `:: CLOSED`. `S3-late-refusal-spends-join-code` still prints `KNOWN GAP (closed by T1a)`: the next task closes it.

```
messagegroup   exit=0 pass=361 fail=0
sdk            exit=0 pass=314 fail=0
cp3b           exit=0 pass=113 fail=0
advsim-strict  exit=1 pass=16 fail=10
```

- [ ] **Step 6: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ26b`: the sdk joins through the unbound door and compares the group id afterwards. Property 1 must fail. Measured: killed by `TestProductionJoinsOnlyThroughTheBoundDoor`, and 4 other tests.
2. `MJ26b`: the sdk joins through the unbound door and compares the group id afterwards. Property 2 must fail. Measured: killed by `TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing`, and 4 other tests.

- [ ] **Step 7: commit.**

```bash
git add sdk/urmessage/heldgroup_test.go sdk/urmessage/group.go sdk/cp3b/testdata/advsim/known-gaps.json
git commit -m "urmessage: the join is bound to the group the invite names"
```

### Task 36: The two-phase join: nothing reaches the store until every check has passed, and every refusal says what it cost

- Consumes: the admission mutex and `holdReplacing` (Task 33); the bound door (Task 35); the scenario of Task 16
- Produces: `joinStage`, `newJoinStage`, `ErrJoinRefused`, `ErrJoinCodeSpent`, `ErrJoinWouldOverwrite`, `ErrNoJoinCodeForInvite`

**Behaviour.** The device's engine is built over `joinStage`, an `mls.StateStore` that passes
everything through except during a join. During a join it holds the joined state in memory and
remembers the key package the engine took. `commit` writes the state create-only: it probes the
store first and refuses with `ErrJoinWouldOverwrite` if a state is already there; only
`ErrStateNotFound` means absent, any other answer refuses; the probe's answer is never erased.
`abort` erases the staged state and puts the join code back.

**The window has one exit.** `Join` runs gate, begin, engine join, checks, commit, record, hold.
Every return between begin and commit is a refusal written as a plain return of its cause, and ONE
deferred call closes what was built, erases what was staged, puts the join code back and gives
the cause the one sentence every refusal inside the window begins with, `ErrJoinRefused`: "this
invite was refused before anything was written, and the join code is not spent". The native bridge carries sentences and
not types, so an app tells "your join code is still good" from "it is spent" by that prefix alone.
`ErrJoinCodeSpent` is the two cases where the code is lost, and neither carries the prefix: the
put-back itself failed, or the joined state was committed and the record then could not be
written.

**One refusal inside the window does not carry the sentence, and must not (R13, the final check's
F7).** A refusal says what it cost, truthfully. An invitation that no join code of this device was
made for, which is what the SAME invitation is once its join code has gone, answers
`ErrNoJoinCodeForInvite`: "this device holds no join code this invitation was made for; make a new
join code". Measured by the final check, before this: after a join that answered
`ErrJoinCodeSpent` (either way), the same honest invitation pasted again answered the window's
prefix, "the join code is not spent", over the engine's "no key package this store holds is
addressed by this welcome"; the same holds after a crash inside the window, where nobody was told.
An app turns that prefix into "your join code is still good: ask for the invitation to be sent
again", which can never work. The app's row for the new sentence is in Task 58.

*What this sentence cannot tell apart, and says so in its own header.* The engine has ONE refusal
for "no key package this store holds is addressed by this Welcome", and its header says a caller
matching on the type cannot tell a Welcome addressed to nobody here from a store that would not
read the join code it holds. The new sentence is chosen by that one refusal, so it is also what a
store that failed to read answers, and what an invitation made for another device answers; the
cause it carries has the store's last refusal verbatim. The sentence ("this device holds no join
code this invitation was made for") is true of a join code that is gone and of an invitation made
for another device, and it claims nothing about a join code having been used. OF A STORE THAT
FAILED TO READ IT IS NOT TRUE AS WORDED: that device holds the join code, and its store would not
hand it over. The store's refusal is still in the cause, so the fact is not lost; what a person
reads is wrong for that one case. Whether that stands, or the store's not-found needs a type the
engine can pass on, is question (d) of Task 57.

**Where the stage lives.** The design places it in `messagegroup`. Measured on the first
revision: there it drags the session's internals into the join-sentence gate (80 sentences become
279 to 383, and the derived vocabulary collapses to `[zeroize]`). In the sdk it costs one renamed
field: `TestEveryAssignmentToGroupEpochIsInsideTheOneDoor` reads every assignment to a field named
`epoch`, whoever declares it, so the stage's field is `stagedEpoch`. The lead confirmed the
departure.

**Property 1.** A staged join reaches the store only at commit, and never over a state that is already there; a store that cannot answer the probe is a refusal; and the probe leaves the store's own array as it was.

**Property 2.** An aborted join puts the join code back.

**Property 3.** Every refusal made inside the join's window but one begins with the window's one sentence, does not say the join code is spent, leaves no state and no group, and the honest invitation then joins over the same join code.

**Property 4.** A refusal whose put-back fails, and a join whose record cannot be written, each say the join code is spent and do not say it is not.

**Property 5.** An invitation whose join code is already gone, by either of the two ways a join code goes, answers `ErrNoJoinCodeForInvite`: it begins with that sentence, does not say the join code is not spent, does not say this join spent it, and leaves no group.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/joinstage_test.go` (new file, 170 lines):

```go
package urmessage

import (
	"bytes"
	"errors"
	"testing"
)

// A staged join reaches the store only at its commit, and the commit never writes over a state
// that is already there.
//
// WHAT WOULD GO RED: forward PutGroupState during a join and the first assertion fails; drop the
// probe from commit and the hostile state replaces the first; zeroize the probe's answer and the
// first state reads back as zeros.
func TestAStagedJoinReachesTheStoreOnlyAtCommitAndNeverOverAStateAlreadyThere(t *testing.T) {
	store := NewMemoryStateStore()
	stage := newJoinStage(store)
	joined := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	bystander := bytes.Repeat([]byte{0x72}, GroupIdBytes)
	first := []byte("the epoch state the first join wrote")

	if err := stage.begin(joined); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 3, first); err != nil {
		t.Fatalf("PutGroupState during the join: %v", err)
	}
	if _, err := store.GetGroupState(joined, 3); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("the store answered %v for the joined group before the commit, want ErrStateNotFound: the join wrote through", err)
	}
	// the engine's own view of what it just wrote
	if staged, err := stage.GetGroupState(joined, 3); err != nil || !bytes.Equal(staged, first) {
		t.Fatalf("the stage answered %q, %v for the state it holds", staged, err)
	}
	// another group's write during the join is that group's own, and goes straight through
	if err := stage.PutGroupState(bystander, 9, []byte("a live group sealing")); err != nil {
		t.Fatalf("a bystander's PutGroupState: %v", err)
	}
	if _, err := store.GetGroupState(bystander, 9); err != nil {
		t.Fatalf("a bystander's write did not reach the store during a join: %v", err)
	}
	if err := stage.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if written, err := store.GetGroupState(joined, 3); err != nil || !bytes.Equal(written, first) {
		t.Fatalf("after the commit the store holds %q, %v", written, err)
	}

	// A SECOND JOIN INTO THE SAME GROUP AND EPOCH: refused, and the first state is intact.
	if err := stage.begin(joined); err != nil {
		t.Fatalf("the second begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 3, []byte("a hostile welcome's epoch state")); err != nil {
		t.Fatalf("the second PutGroupState: %v", err)
	}
	if err := stage.commit(); !errors.Is(err, ErrJoinWouldOverwrite) {
		t.Fatalf("a commit over a held state answered %v, want ErrJoinWouldOverwrite", err)
	}
	if err := stage.abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if kept, err := store.GetGroupState(joined, 3); err != nil || !bytes.Equal(kept, first) {
		t.Fatalf("after the refused commit the store holds %q, %v; the held state was replaced or erased", kept, err)
	}
	// and the stage is a plain forward again
	if err := stage.PutGroupState(joined, 4, []byte("the group's own next epoch")); err != nil {
		t.Fatalf("PutGroupState after the join: %v", err)
	}
	if _, err := store.GetGroupState(joined, 4); err != nil {
		t.Fatalf("a write after the join did not reach the store: %v", err)
	}
}

// A join that is refused after the engine took the join code puts it back, byte for byte.
func TestAnAbortedJoinPutsTheJoinCodeBack(t *testing.T) {
	store := NewMemoryStateStore()
	stage := newJoinStage(store)
	ref := []byte("the key package's reference")
	if err := store.PutKeyPackage(ref, []byte("kp"), []byte("init private"), []byte("leaf private")); err != nil {
		t.Fatalf("PutKeyPackage: %v", err)
	}
	if err := stage.begin(bytes.Repeat([]byte{0x71}, GroupIdBytes)); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, _, _, err := stage.TakeKeyPackage(ref); err != nil {
		t.Fatalf("TakeKeyPackage through the stage: %v", err)
	}
	if _, _, _, err := store.TakeKeyPackage(ref); err == nil {
		t.Fatal("CONTROL FAILED: the store still holds the key package after the take, so the put-back below proves nothing")
	}
	if err := stage.abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	kp, initPrivate, leafPrivate, err := store.TakeKeyPackage(ref)
	if err != nil {
		t.Fatalf("the join code is gone after an aborted join: %v", err)
	}
	if string(kp) != "kp" || string(initPrivate) != "init private" || string(leafPrivate) != "leaf private" {
		t.Fatalf("the join code came back as %q %q %q", kp, initPrivate, leafPrivate)
	}
}

// unreadableStore answers a failed read, which is neither "held" nor "not held".
type unreadableStore struct {
	*MemoryStateStore
	puts int
}

func (self *unreadableStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	return nil, errors.New("the disk this store sits on answered EIO")
}

func (self *unreadableStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.puts += 1
	return self.MemoryStateStore.PutGroupState(groupId, epoch, state)
}

// Only ErrStateNotFound means "nothing is there". A store that cannot say is not written over.
func TestACommitOverAStoreThatCannotAnswerIsRefused(t *testing.T) {
	store := &unreadableStore{MemoryStateStore: NewMemoryStateStore()}
	stage := newJoinStage(store)
	joined := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	if err := stage.begin(joined); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 1, []byte("staged")); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	if err := stage.commit(); !errors.Is(err, ErrJoinWouldOverwrite) {
		t.Fatalf("a commit over an unreadable store answered %v, want ErrJoinWouldOverwrite", err)
	}
	if store.puts != 0 {
		t.Fatalf("the refused commit wrote %d state(s) into a store that could not say what it held", store.puts)
	}
}

// ownArrayStore answers GetGroupState with ITS OWN ARRAY, which is what [mls.StateStore] permits a
// store to do and what the stores this package ships happen not to.
type ownArrayStore struct {
	*MemoryStateStore
	state []byte
}

func (self *ownArrayStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	return self.state, nil
}

// The create-only probe reads whether the store ANSWERED and nothing else. An erase of what it
// answered would be an erase of the held group's state, through the store's own array.
func TestTheCreateOnlyProbeLeavesTheStoresOwnArrayAlone(t *testing.T) {
	held := []byte("the held group's epoch state")
	store := &ownArrayStore{MemoryStateStore: NewMemoryStateStore(), state: bytes.Clone(held)}
	stage := newJoinStage(store)
	joined := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	if err := stage.begin(joined); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 1, []byte("a hostile welcome's epoch state")); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	if err := stage.commit(); !errors.Is(err, ErrJoinWouldOverwrite) {
		t.Fatalf("a commit over a held state answered %v, want ErrJoinWouldOverwrite", err)
	}
	if err := stage.abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if !bytes.Equal(store.state, held) {
		t.Fatalf("the store's own array reads %q after the probe and held %q before it", store.state, held)
	}
}
```

`sdk/urmessage/joinwindow_test.go` (new file, 293 lines):

```go
package urmessage

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	messageprotocol "github.com/urnetwork/message/protocol"
)

// THE JOIN'S WINDOW, FROM OUTSIDE: what each refusal says, and what it costs. The staging store
// has its own cases in joinstage_test.go; these drive [Device.Join] itself, over stores that
// misbehave at one named call.

// windowInvite founds a group on a device of its own and adds joiner's join code: the honest
// invite, and the group id it is for.
func windowInvite(t *testing.T, joiner *Device) (*Invite, []byte) {
	t.Helper()
	ctx := context.Background()
	founder, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("the founder's nonce"))
	if err := founder.Connect(ctx); err != nil {
		t.Fatalf("the founder's Connect: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	group, err := founder.CreateGroup(ctx, groupId)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	joinCode, err := joiner.KeyPackage()
	if err != nil {
		t.Fatalf("the joiner's KeyPackage: %v", err)
	}
	invite, err := group.AddMember(joinCode)
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	return invite, groupId
}

// bentInvite is a copy of an invite with one thing changed.
func bentInvite(invite *Invite, change func(*Invite)) *Invite {
	bent := &Invite{
		GroupId:        bytes.Clone(invite.GroupId),
		Welcome:        bytes.Clone(invite.Welcome),
		RatchetTree:    bytes.Clone(invite.RatchetTree),
		PqSecret:       bytes.Clone(invite.PqSecret),
		GroupHandleKey: bytes.Clone(invite.GroupHandleKey),
	}
	change(bent)
	return bent
}

// EVERY REFUSAL INSIDE THE JOIN'S WINDOW BEGINS WITH ONE SENTENCE, AND COSTS NOTHING. Three
// refusals, made at the three places the window can refuse: the engine (a Welcome for another
// group), this package's own checks (a secret the session will not take), and the create-only
// commit (a state already held at the joined epoch). Each answers [ErrJoinRefused] and begins with
// its sentence; none answers [ErrJoinCodeSpent]; the device holds no group; and the honest invite
// then joins OVER THE SAME JOIN CODE, which is what "not spent" means.
//
// ONE REFUSAL INSIDE THE WINDOW DOES NOT CARRY THE SENTENCE, AND MUST NOT: an invite whose join
// code is ALREADY GONE. It is driven both ways a join code goes with no group to show for it (a
// join whose record could not be written, and a refusal whose put-back failed), each of which said
// [ErrJoinCodeSpent] once; the SAME honest invite pasted again then answers
// [ErrNoJoinCodeForInvite], which does not say the join code is not spent, because it is.
//
// THE CONTROL is a refusal made BEFORE the window, which must not carry the sentence: a sentence
// every refusal carried would say nothing about where the join code is.
//
// WHAT WOULD GO RED: return a cause from inside the window without the deferred exit, or hand the
// engine the store and not the stage, and a row's honest invite no longer joins; or give the
// window's sentence to an invite whose join code is gone, and an app tells a person to ask for an
// invitation again that can never be joined.
func TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent(t *testing.T) {
	ctx := context.Background()
	orphan := []byte("an epoch state with no record: a join whose record did not persist")
	for _, one := range []struct {
		name   string
		bend   func(*Invite)
		plant  bool
		within error
	}{
		{"a welcome for another group, refused by the engine",
			func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }, false, nil},
		{"a pq_secret one octet short, refused by this package",
			func(invite *Invite) { invite.PqSecret = invite.PqSecret[:len(invite.PqSecret)-1] }, false, nil},
		{"a state already held at the joined epoch, refused by the commit",
			func(invite *Invite) {}, true, ErrJoinWouldOverwrite},
	} {
		store := NewMemoryStateStore()
		joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
		honest, groupId := windowInvite(t, joiner)
		if one.plant {
			if err := store.PutGroupState(groupId, 1, orphan); err != nil {
				t.Fatalf("%s: planting the orphan state: %v", one.name, err)
			}
		}
		_, err := joiner.Join(ctx, bentInvite(honest, one.bend))
		if !errors.Is(err, ErrJoinRefused) {
			t.Errorf("%s answered %v, want ErrJoinRefused", one.name, err)
			continue
		}
		if !strings.HasPrefix(err.Error(), ErrJoinRefused.Error()+": ") {
			t.Errorf("%s answered %q, which does not BEGIN with the window's sentence", one.name, err)
		}
		if errors.Is(err, ErrJoinCodeSpent) {
			t.Errorf("%s also answers ErrJoinCodeSpent: %v", one.name, err)
		}
		if one.within != nil && !errors.Is(err, one.within) {
			t.Errorf("%s answered %v, which does not carry its cause %v", one.name, err, one.within)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("%s left the joiner holding %d group(s)", one.name, held)
		}
		kept, stateErr := store.GetGroupState(groupId, 1)
		switch {
		case one.plant && !bytes.Equal(kept, orphan):
			t.Errorf("%s: the state the store already held reads %q, %v after the refusal", one.name, kept, stateErr)
		case !one.plant && !errors.Is(stateErr, ErrStateNotFound):
			t.Errorf("%s left a state in the store for the group it refused: %v", one.name, stateErr)
		}
		// THE JOIN CODE IS NOT SPENT: the honest invite joins over the same one
		if one.plant {
			if err := store.DeleteGroupStateBefore(groupId, 2); err != nil {
				t.Fatalf("%s: removing the orphan state: %v", one.name, err)
			}
		}
		if _, err := joiner.Join(ctx, honest); err != nil {
			t.Errorf("%s: the honest invite after the refusal answered %v, so the refusal spent the join code", one.name, err)
		}
	}

	// THE ROW THAT IS NOT LIKE THE OTHERS: an invite whose join code is already gone
	for _, one := range []struct {
		name  string
		spend func(t *testing.T) (*Device, *Invite, func())
	}{
		{"after a join whose record could not be written", func(t *testing.T) (*Device, *Invite, func()) {
			durable, err := OpenDurableStateStore(t.TempDir())
			if err != nil {
				t.Fatalf("OpenDurableStateStore: %v", err)
			}
			t.Cleanup(func() { durable.Close() })
			store := &recordSink{DurableStateStore: durable}
			joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
			honest, _ := windowInvite(t, joiner)
			store.armed = true
			_, err = joiner.Join(ctx, honest)
			if !errors.Is(err, ErrJoinCodeSpent) {
				t.Fatalf("CONTROL FAILED: the join whose record could not be written answered %v, want ErrJoinCodeSpent", err)
			}
			return joiner, honest, func() { store.armed = false }
		}},
		{"after a refusal whose put-back failed", func(t *testing.T) (*Device, *Invite, func()) {
			store := &keyPackageSink{MemoryStateStore: NewMemoryStateStore()}
			joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
			honest, _ := windowInvite(t, joiner)
			store.armed = true
			_, err := joiner.Join(ctx, bentInvite(honest, func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }))
			if !errors.Is(err, ErrJoinCodeSpent) {
				t.Fatalf("CONTROL FAILED: the refusal whose put-back failed answered %v, want ErrJoinCodeSpent", err)
			}
			return joiner, honest, func() { store.armed = false }
		}},
	} {
		joiner, honest, heal := one.spend(t)
		heal()
		_, err := joiner.Join(ctx, honest)
		if !errors.Is(err, ErrNoJoinCodeForInvite) {
			t.Errorf("the same invite again, %s, answered %v, want ErrNoJoinCodeForInvite", one.name, err)
			continue
		}
		if errors.Is(err, ErrJoinRefused) || strings.Contains(err.Error(), "the join code is not spent") {
			t.Errorf("the same invite again, %s, says the join code is not spent, and it is gone: %v", one.name, err)
		}
		if !strings.HasPrefix(err.Error(), ErrNoJoinCodeForInvite.Error()+": ") {
			t.Errorf("the same invite again, %s, answered %q, which does not BEGIN with the sentence an app reads", one.name, err)
		}
		if errors.Is(err, ErrJoinCodeSpent) {
			t.Errorf("the same invite again, %s, says THIS join spent the join code, and it was gone before it: %v", one.name, err)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("the same invite again, %s, left the joiner holding %d group(s)", one.name, held)
		}
	}

	// THE CONTROL: a refusal made before the window does not carry the window's sentence
	joiner := newAnsweringDeviceOver(t, NewMemoryStateStore(), []byte("the joiner's nonce"))
	honest, _ := windowInvite(t, joiner)
	if _, err := joiner.Join(ctx, honest); err != nil {
		t.Fatalf("CONTROL: the honest invite: %v", err)
	}
	if _, err := joiner.Join(ctx, honest); !errors.Is(err, ErrGroupAlreadyHeld) || errors.Is(err, ErrJoinRefused) {
		t.Errorf("CONTROL FAILED: an invite into a held group answered %v, want ErrGroupAlreadyHeld and not the window's sentence", err)
	}
}

// keyPackageSink is a memory store that will not take a key package back once it is armed.
type keyPackageSink struct {
	*MemoryStateStore
	armed bool
}

func (self *keyPackageSink) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	if self.armed {
		return errors.New("the store this test sits on will not take a key package")
	}
	return self.MemoryStateStore.PutKeyPackage(ref, kp, initPriv, encPriv)
}

// A REFUSAL WHOSE PUT-BACK FAILS SAYS THE JOIN CODE IS SPENT, AND DOES NOT SAY IT IS NOT. It is the
// first of the two ways a join costs its join code, and both of the roads to it are driven: a
// refusal this package makes, and a refusal the engine makes, whose own put-back fails first.
//
// WHAT WOULD GO RED: discard the abort's error, and a join code the store did not take back is
// reported as one that is still good.
func TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent(t *testing.T) {
	ctx := context.Background()
	for _, one := range []struct {
		name string
		bend func(*Invite)
	}{
		{"this package's refusal", func(invite *Invite) { invite.PqSecret = invite.PqSecret[:len(invite.PqSecret)-1] }},
		{"the engine's refusal", func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }},
	} {
		store := &keyPackageSink{MemoryStateStore: NewMemoryStateStore()}
		joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
		honest, _ := windowInvite(t, joiner)
		store.armed = true
		_, err := joiner.Join(ctx, bentInvite(honest, one.bend))
		if !errors.Is(err, ErrJoinCodeSpent) {
			t.Errorf("%s, with a store that takes no key package back, answered %v, want ErrJoinCodeSpent", one.name, err)
		}
		if errors.Is(err, ErrJoinRefused) {
			t.Errorf("%s says the join code is not spent although it could not be put back: %v", one.name, err)
		}
		if held := len(joiner.Groups()); held != 0 {
			t.Errorf("%s left the joiner holding %d group(s)", one.name, held)
		}
		// THE CONTROL: it IS spent. With the store working again the honest invite does not join.
		store.armed = false
		if _, err := joiner.Join(ctx, honest); err == nil {
			t.Errorf("CONTROL FAILED: %s: the honest invite joined afterwards, so the join code was never lost and nothing above is about a failed put-back", one.name)
		}
	}
}

// recordSink is a durable store that will not write a group record once it is armed.
type recordSink struct {
	*DurableStateStore
	armed bool
}

func (self *recordSink) PutGroupRecord(record *GroupRecord) error {
	if self.armed {
		return errors.New("the store this test sits on will not write a group record")
	}
	return self.DurableStateStore.PutGroupRecord(record)
}

// A JOIN WHOSE RECORD CANNOT BE WRITTEN SAYS THE JOIN CODE IS SPENT. It is the second way, and the
// only one that is past the window: every check passed, the joined state was committed, and the
// record that a restart would come back through then could not be written.
//
// WHAT WOULD GO RED: answer that failure without [ErrJoinCodeSpent], and an app tells a person
// whose join code is gone to paste the same invitation again.
func TestAJoinWhoseRecordCannotBeWrittenSaysTheJoinCodeIsSpent(t *testing.T) {
	ctx := context.Background()
	durable, err := OpenDurableStateStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDurableStateStore: %v", err)
	}
	t.Cleanup(func() { durable.Close() })
	store := &recordSink{DurableStateStore: durable}
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	honest, groupId := windowInvite(t, joiner)
	store.armed = true
	_, err = joiner.Join(ctx, honest)
	if !errors.Is(err, ErrJoinCodeSpent) {
		t.Fatalf("a join whose record could not be written answered %v, want ErrJoinCodeSpent", err)
	}
	if errors.Is(err, ErrJoinRefused) {
		t.Errorf("it also says the join code is not spent: %v", err)
	}
	if held := len(joiner.Groups()); held != 0 {
		t.Errorf("the device holds %d group(s) after a join that did not complete", held)
	}
	// what "past the window" means: the joined state did reach the store
	if _, err := durable.GetGroupState(groupId, 1); err != nil {
		t.Errorf("CONTROL FAILED: the store holds no state for the joined epoch (%v), so this failure was inside the window and not after it", err)
	}
}
```

`sdk/cp3b/heldgroup_test.go`:

```diff
--- a/sdk/cp3b/heldgroup_test.go
+++ b/sdk/cp3b/heldgroup_test.go
@@ -282,7 +282,8 @@ func TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld(t *testing.T)
 // in the way of it, and this rule is the only thing that refuses it.
 //
 // WHAT WOULD GO RED: drop the comparison of the joined epoch with the removal's, and the stale
-// invitation joins and replaces the removed group.
+// invitation joins and replaces the removed group; or join in one phase, and the refused
+// invitation leaves an epoch state behind that the re-added device then reads history with.
 func TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins(t *testing.T) {
 	scene := advFounding(t, true)
 	carol := scene.world.newPersona(t, "carol")
@@ -315,6 +316,12 @@ func TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins(t *testing.T) {
 			t.Errorf("the refused invitation changed %s of the removed group", name)
 		}
 	}
+	// AND IT LEFT NOTHING BEHIND. Until the join was staged, this refusal came after the engine had
+	// written the second founder's epoch-1 state beside the removed group's own, and the real
+	// re-add below then opened the real group's epoch-1 records with it and failed to.
+	if len(after) != len(before) {
+		t.Errorf("the refused invitation left %d file(s) under the group where there were %d", len(after), len(before))
+	}
 	held := carol.device.Groups()
 	if len(held) != 1 || held[0] != carolGroup {
 		t.Fatalf("carol holds %d group(s) after the refused invitation, and the removed group is not the one she holds", len(held))
@@ -331,6 +338,8 @@ func TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins(t *testing.T) {
 	if _, removal := rejoined.Removal(); removal != nil {
 		t.Fatalf("the re-added group still reads as removed: %v", removal)
 	}
+	canary := scene.say(t, "alice", scene.aliceGroup)
+	gcReceiveText(t, scene.ctx, "carol", rejoined, canary)
 }
 
 // FORGETGROUP OVER A GROUP THAT IS ON THE DISK AND NOT IN MEMORY ANSWERS BY WHAT RESTORE SAID. A
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk/cp3b test -count=1 -run ^(TestAdvSim) ./...
exit status 1
--- FAIL: TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode (0.23s)
    advsim_join_test.go:570: the shortened invitation was refused: urmessage: the session at epoch 1: messagegroup: a pq_secret is not the thirty two octets MASTER section 7 fixes: 31 octets, and it is the ikm of every storage_root this session extracts
    advsim_join_test.go:577: the honest invitation after the refused one: urmessage: JoinFromWelcomeInto: messagegroup: no key package this store holds is addressed by this welcome: the welcome names 1 key package refs, this store refused 1 of them, and the last refusal it answered was urmessage: th
    advsim_join_test.go:583: ADVSIM S3-late-refusal-spends-join-code state=closed   expect=[] observed=[join-code-spent] :: FAIL (closed): observed [join-code-spent], and this entry holds exactly []
FAIL
FAIL	github.com/urnetwork/message/sdk/cp3b	7.096s
FAIL
$ go -C sdk test -count=1 -run ^(TestACommitOverAStoreThatCannotAnswerIsRefused|TestAJoinWhoseRecordCannotBeWrittenSaysTheJoinCodeIsSpent|TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent|TestAStagedJoinReachesTheStoreOnlyAtCommitAndNeverOverAStateAlreadyThere|TestAnAbortedJoinPutsTheJoinCodeBack|TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent|TestTheCreateOnlyProbeLeavesTheStores
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\joinstage_test.go:17:11: undefined: newJoinStage
urmessage\joinstage_test.go:56:44: undefined: ErrJoinWouldOverwrite
urmessage\joinstage_test.go:77:11: undefined: newJoinStage
urmessage\joinstage_test.go:121:11: undefined: newJoinStage
urmessage\joinstage_test.go:129:44: undefined: ErrJoinWouldOverwrite
urmessage\joinstage_test.go:153:11: undefined: newJoinStage
urmessage\joinstage_test.go:161:44: undefined: ErrJoinWouldOverwrite
...
```

- [ ] **Step 3: the change.**

`sdk/urmessage/joinstage.go` (new file, 218 lines):

```go
package urmessage

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/message/mls"
)

// joinStage is the [mls.StateStore] a device's engine is built over: the device's own store, with
// ONE JOIN AT A TIME held in memory until this package has finished judging it.
//
// WHY A JOIN IS STAGED. mls persists the epoch it joined as the last statement of the join, and
// the engine takes the join code's private halves out of the store before that, so by the time
// [Device.Join] holds a group to judge, the state is on the disk and the join code is spent. Two
// defects followed, both measured in sdk/cp3b before this file existed. An invite refused after
// that point had cost the device its join code, and the honest invite that followed could not be
// opened. And an invite into a group the device ALREADY HELD had replaced that group's epoch state
// before anything could refuse it.
//
// WHAT IT DOES. Between begin and commit, the epoch state the engine writes for the group being
// joined is kept here and does not reach the store, and the key package the engine took is
// remembered. commit writes the state CREATE-ONLY: a store that already holds a state for that
// group and epoch is left as it is, and the commit is refused. abort erases the staged state and
// puts the key package back, so a refused join leaves the store exactly as it was. Outside a join,
// and for every other group during one, every method is the device's store, call for call.
//
// THE GROUP ID IS THE ONE [Device.Join] WAS HANDED IN THE INVITE, and the engine's
// JoinFromWelcomeInto has already refused a Welcome that describes any other group, so a write for
// this id during the join is the join's own: the device holds no live group under it (the
// held-group gate), and a group a commit removed it from is closed and writes nothing.
type joinStage struct {
	store mls.StateStore

	mutex   sync.Mutex
	joining bool
	groupId []byte

	held        bool
	stagedEpoch uint64
	state       []byte

	taken        bool
	takenRef     []byte
	takenPackage []byte
	takenInit    []byte
	takenEncrypt []byte
}

var _ mls.StateStore = (*joinStage)(nil)

func newJoinStage(store mls.StateStore) *joinStage {
	return &joinStage{store: store}
}

// begin opens the stage for one join. A second begin before the first has committed or aborted is
// refused: [Device.Join] holds [Device.admitMutex] across the whole of a join, so a second one is a
// caller that is not inside it.
func (self *joinStage) begin(groupId []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.joining {
		return fmt.Errorf("urmessage: a join into group %x is still staged, and a device stages one join at a time", self.groupId)
	}
	self.joining = true
	self.groupId = append([]byte(nil), groupId...)
	return nil
}

// commit writes the staged epoch state into the device's store, CREATE-ONLY, and closes the stage.
//
// THE PROBE READS NOTHING AND ERASES NOTHING. What GetGroupState answers is the STORE'S OWN ARRAY,
// which is [mls.StateStore]'s contract, so the answer is dropped unread: a probe that wiped it
// would destroy the held group's state in the act of deciding to leave it alone.
//
// ONLY [ErrStateNotFound] IS READ AS "NOTHING THERE". Every store this package ships answers that
// sentinel for an absent state, and the walk already depends on it. Any other answer, a state or a
// failed read alike, refuses the commit: a store that cannot say whether it holds this group is
// not written over.
func (self *joinStage) commit() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if !self.joining || !self.held {
		return fmt.Errorf("urmessage: no join is staged, or the engine wrote no epoch state for it")
	}
	_, err := self.store.GetGroupState(self.groupId, self.stagedEpoch)
	if err == nil {
		return fmt.Errorf("%w: group %x epoch %d", ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch)
	}
	if !errors.Is(err, ErrStateNotFound) {
		return fmt.Errorf("%w: whether group %x epoch %d is already held could not be read: %w",
			ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch, err)
	}
	if err := self.store.PutGroupState(self.groupId, self.stagedEpoch, self.state); err != nil {
		return err
	}
	self.closeLocked()
	return nil
}

// abort erases the staged state, puts back the key package the engine took, and closes the stage.
// It is safe after a commit and after an engine refusal, where it finds nothing to do: the engine
// puts the key package back itself on its own refusals, and PutKeyPackage below sees that.
func (self *joinStage) abort() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if !self.joining {
		return nil
	}
	var err error
	if self.taken {
		err = self.store.PutKeyPackage(self.takenRef, self.takenPackage, self.takenInit, self.takenEncrypt)
	}
	self.closeLocked()
	return err
}

// closeLocked erases everything the stage holds and ends the join.
func (self *joinStage) closeLocked() {
	zeroizeState(self.state)
	zeroizeState(self.takenInit)
	zeroizeState(self.takenEncrypt)
	self.state, self.groupId = nil, nil
	self.takenRef, self.takenPackage, self.takenInit, self.takenEncrypt = nil, nil, nil, nil
	self.joining, self.held, self.taken = false, false, false
}

// staging reports whether a write for this group belongs to the join in progress.
func (self *joinStage) stagingLocked(groupId []byte) bool {
	return self.joining && bytes.Equal(groupId, self.groupId)
}

func (self *joinStage) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if !self.stagingLocked(groupId) {
		return self.store.PutGroupState(groupId, epoch, state)
	}
	if self.held && epoch != self.stagedEpoch {
		return fmt.Errorf("urmessage: the join into group %x staged epoch %d and then wrote epoch %d", groupId, self.stagedEpoch, epoch)
	}
	// COPIED: mls erases the buffer it handed over as soon as this returns
	zeroizeState(self.state)
	self.state = append([]byte(nil), state...)
	self.stagedEpoch = epoch
	self.held = true
	return nil
}

func (self *joinStage) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.stagingLocked(groupId) && self.held && epoch == self.stagedEpoch {
		return append([]byte(nil), self.state...), nil
	}
	return self.store.GetGroupState(groupId, epoch)
}

// DeleteGroupStateBefore does nothing for the group being joined: nothing of the join is in the
// store yet, and what IS there under that id is not the join's to delete.
func (self *joinStage) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.stagingLocked(groupId) {
		return nil
	}
	return self.store.DeleteGroupStateBefore(groupId, epoch)
}

func (self *joinStage) PutPrivateKey(pub []byte, priv []byte) error {
	return self.store.PutPrivateKey(pub, priv)
}

func (self *joinStage) GetPrivateKey(pub []byte) ([]byte, error) {
	return self.store.GetPrivateKey(pub)
}

func (self *joinStage) DeletePrivateKey(pub []byte) error {
	return self.store.DeletePrivateKey(pub)
}

// PutKeyPackage forwards, and forgets the key package this join took when it is the one being put
// back: the engine does that itself on every refusal of its own.
func (self *joinStage) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.store.PutKeyPackage(ref, kp, initPriv, encPriv); err != nil {
		return err
	}
	if self.joining && self.taken && bytes.Equal(ref, self.takenRef) {
		zeroizeState(self.takenInit)
		zeroizeState(self.takenEncrypt)
		self.takenRef, self.takenPackage, self.takenInit, self.takenEncrypt = nil, nil, nil, nil
		self.taken = false
	}
	return nil
}

// TakeKeyPackage forwards, and during a join REMEMBERS what was taken, as copies, so that a refusal
// this package makes after the engine has joined can put the join code back.
func (self *joinStage) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	kp, initPriv, encPriv, err := self.store.TakeKeyPackage(ref)
	if err != nil || !self.joining {
		return kp, initPriv, encPriv, err
	}
	zeroizeState(self.takenInit)
	zeroizeState(self.takenEncrypt)
	self.takenRef = append([]byte(nil), ref...)
	self.takenPackage = append([]byte(nil), kp...)
	self.takenInit = append([]byte(nil), initPriv...)
	self.takenEncrypt = append([]byte(nil), encPriv...)
	self.taken = true
	return kp, initPriv, encPriv, nil
}
```

`sdk/urmessage/device.go`:

```diff
--- a/sdk/urmessage/device.go
+++ b/sdk/urmessage/device.go
@@ -292,6 +292,12 @@ type Device struct {
 	// back, by id. Guarded by mutex. It is what [Device.ForgetGroup] reads to leave one of them.
 	unrestored map[string]bool
 
+	// joinStage is the store the engine was built over: [Device.stateStore] with one join at a time
+	// staged in memory until [Device.Join] has finished judging it. A join holds admitMutex from
+	// before it begins the stage to after it closes it, so there is never a second one to stage.
+	// See [joinStage].
+	joinStage *joinStage
+
 	// §4.3.5's pushes and the replaced-session flag: see [pushInbox], which is what the transport's
 	// callbacks hold instead of this device.
 	inbox *pushInbox
@@ -437,7 +443,11 @@ func NewDevice(config DeviceConfig) (*Device, error) {
 	// What a member reads off MemberAt is therefore exactly "the leaf that signs", and MG-1's
 	// obligation -- that a joiner must decide whether it expected THAT identity -- is the
 	// caller's and is not met here.
-	engine, err := messagegroup.NewConnectMlsEngine(crypto, stateStore, signer,
+	// THE ENGINE IS BUILT OVER THE JOIN STAGE AND NOT OVER THE STORE. Everything the engine reads
+	// and writes still reaches stateStore, call for call; what the stage adds is that a join's
+	// first epoch state waits in memory until [Device.Join] commits it. See [joinStage].
+	stage := newJoinStage(stateStore)
+	engine, err := messagegroup.NewConnectMlsEngine(crypto, stage, signer,
 		mls.BasicCredential(signerPub), leafKeys)
 	if err != nil {
 		return nil, fmt.Errorf("urmessage: the mls engine: %w", err)
@@ -461,6 +471,7 @@ func NewDevice(config DeviceConfig) (*Device, error) {
 		commitAuthorizer: config.CommitAuthorizer,
 		groups:           map[string]*Group{},
 		unrestored:       map[string]bool{},
+		joinStage:        stage,
 		inbox:            inbox,
 	}, nil
 }
```

`sdk/urmessage/errors.go`:

```diff
--- a/sdk/urmessage/errors.go
+++ b/sdk/urmessage/errors.go
@@ -773,4 +773,43 @@ var (
 	// The re-add of a device a commit removed named an epoch at or below the one it was removed at.
 	// A real re-add is a later commit, so its Welcome stands above that epoch.
 	ErrReaddStale = errors.New("urmessage: this invite adds this device back at an epoch at or below the one it was removed at")
+
+	// [Device.Join] would have written the epoch state of a group and epoch this device's store
+	// already holds a state for, or could not read whether it does. A join creates a group's state
+	// and leaves one that is already there alone. The store is as it was and the join code is not
+	// spent.
+	ErrJoinWouldOverwrite = errors.New("urmessage: this device's store already holds a state for the group and epoch this invite joins, so the invite is refused and the store is left as it was")
+
+	// EVERY REFUSAL [Device.Join] MAKES INSIDE ITS WINDOW BEGINS WITH THIS SENTENCE, whatever the
+	// cause it wraps: the invite was judged after the engine took the join code and before
+	// anything reached the store, and it was refused there, so nothing was written and the join
+	// code went back. It is one fixed sentence because the C ABI carries sentences and not types:
+	// an app tells "your join code is still good" from [ErrJoinCodeSpent] by this prefix alone, and
+	// does not have to know every cause. ONE REFUSAL INSIDE THE WINDOW DOES NOT CARRY IT, because
+	// of it this sentence would be false: [ErrNoJoinCodeForInvite].
+	ErrJoinRefused = errors.New("urmessage: this invite was refused before anything was written, and the join code is not spent")
+
+	// [Device.Join] was handed an invite that NO JOIN CODE THIS DEVICE HOLDS WAS MADE FOR: the
+	// engine found no key package in this device's store that the Welcome is addressed to. The
+	// commonest cause is a join code that is ALREADY GONE. An earlier join of this same invite
+	// spent it ([ErrJoinCodeSpent], which was said once, to that call), or the process died inside
+	// a join's window, where nobody was told. An invite made for another device answers it too.
+	//
+	// IT IS REFUSED INSIDE THE WINDOW AND NOTHING WAS WRITTEN, AND IT DOES NOT BEGIN WITH
+	// [ErrJoinRefused]'s SENTENCE. That sentence says the join code is not spent, and an app turns
+	// it into "your join code is still good: ask for the invitation to be sent again". Here there
+	// is no join code for that to be true of, and pasting the same invite again can never work. A
+	// refusal says what it cost; this one says what is missing, and the remedy.
+	//
+	// WHAT IT CANNOT TELL APART is the engine's to tell and the engine says it cannot: its refusal
+	// is the same one for a Welcome addressed to nobody here and for a store that would not read
+	// the join code it holds (messagegroup.ErrEngineNoKeyPackageForWelcome, whose message carries
+	// the store's last refusal verbatim, as this one does behind it).
+	ErrNoJoinCodeForInvite = errors.New("urmessage: this device holds no join code this invitation was made for; make a new join code")
+
+	// THE ONE REFUSAL OF [Device.Join] THAT COSTS THE JOIN CODE. Every check a join makes runs
+	// before the joined state reaches the store, and a refusal there puts the join code back. This
+	// is what is left: the store would not take the join code back, or the joined state was
+	// written and the group's record then could not be. Make a new join code and be added again.
+	ErrJoinCodeSpent = errors.New("urmessage: this join did not complete and its join code is spent; make a new join code and ask to be added again")
 )
```

`sdk/urmessage/group.go`:

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1381,7 +1381,15 @@ func (self *Device) CreateGroup(ctx context.Context, groupId []byte) (*Group, er
 // Welcome names a group and a membership, JoinFromWelcome joins it, and the identity a caller would
 // read off the membership afterwards is whatever the Welcome's author put there. Deciding that is
 // the contact card's job and contact cards are out of scope.
-func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
+//
+// WHAT A REFUSAL COSTS, WHICH IS NOTHING BUT ONCE. Before the window nothing has been touched. A
+// refusal inside the window answers [ErrJoinRefused] wrapping its cause: nothing was written and
+// the join code is not spent, so the honest invite, pasted again, still joins. The one refusal that
+// costs the join code is [ErrJoinCodeSpent]. And an invite that no join code of this device was
+// made for, which is what the same invite is once its join code has gone, answers
+// [ErrNoJoinCodeForInvite] and not the window's sentence: nothing was written, and there is no
+// join code for "not spent" to be true of.
+func (self *Device) Join(ctx context.Context, invite *Invite) (joined *Group, err error) {
 	if invite == nil {
 		return nil, fmt.Errorf("urmessage: no invite")
 	}
@@ -1405,35 +1413,80 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
 	if err != nil {
 		return nil, err
 	}
-	// THE JOIN IS BOUND TO THE GROUP THE INVITE NAMES. A Welcome for any other group is refused
-	// inside the engine, before a state is written, and the join code is put back.
-	handle, err := self.engine.JoinFromWelcomeInto(invite.Welcome, invite.RatchetTree, invite.GroupId)
+
+	// ── THE WINDOW ─────────────────────────────────────────────────────────────────────────────
+	// From here to the commit below, the joined epoch state is STAGED in memory and the join code
+	// the engine took is remembered, so every refusal in between leaves the store as it was and
+	// the join code unspent. See [joinStage].
+	if err := self.joinStage.begin(invite.GroupId); err != nil {
+		return nil, err
+	}
+	var handle messagegroup.GroupHandle
+	var session *messagegroup.GroupSession
+	committed := false
+	// THE WINDOW HAS ONE EXIT, AND IT IS THIS DEFERRED CALL. Every return below this line and above
+	// the commit is a refusal, written as a plain return of its cause; this is where the group it
+	// built is closed, what was staged is erased, the join code goes back, and the cause is given
+	// the one sentence every refusal inside the window begins with (all but one: see below). A
+	// refusal added tomorrow is
+	// therefore closed and worded like every other, because there is nothing for it to forget.
+	// After the commit the stage is already closed and this does nothing.
+	defer func() {
+		abortErr := self.joinStage.abort()
+		if committed {
+			return
+		}
+		// the session owns the handle once it exists
+		if session != nil {
+			session.Close()
+		} else if handle != nil {
+			handle.Close()
+		}
+		if abortErr != nil {
+			joined, err = nil, fmt.Errorf("%w: %w, and the join code could not be put back: %w", ErrJoinCodeSpent, err, abortErr)
+			return
+		}
+		// THE ONE REFUSAL IN HERE THAT DOES NOT CARRY THE WINDOW'S SENTENCE: the engine found no
+		// join code of this device that the invite was made for. "The join code is not spent" is
+		// not true of a join code that is not there. See [ErrNoJoinCodeForInvite].
+		if errors.Is(err, messagegroup.ErrEngineNoKeyPackageForWelcome) {
+			joined, err = nil, fmt.Errorf("%w: %w", ErrNoJoinCodeForInvite, err)
+			return
+		}
+		joined, err = nil, fmt.Errorf("%w: %w", ErrJoinRefused, err)
+	}()
+	// BOUND TO THE GROUP THE INVITE NAMES. A Welcome that describes any other group is refused
+	// inside mls, ahead of its persist, and the engine puts the join code back itself.
+	handle, err = self.engine.JoinFromWelcomeInto(invite.Welcome, invite.RatchetTree, invite.GroupId)
 	if err != nil {
 		return nil, fmt.Errorf("urmessage: JoinFromWelcomeInto: %w", err)
 	}
 	if !bytes.Equal(handle.GroupId(), invite.GroupId) {
-		handle.Close()
-		return nil, fmt.Errorf("urmessage: the welcome joined group %x and the invite names %x",
-			handle.GroupId(), invite.GroupId)
+		return nil, fmt.Errorf("%w: the welcome joined group %x and the invite names %x",
+			ErrInviteDamaged, handle.GroupId(), invite.GroupId)
 	}
 	if readd && handle.Epoch() <= removedEpoch {
-		handle.Close()
 		return nil, fmt.Errorf("%w: the welcome stands at epoch %d and this device was removed at epoch %d",
 			ErrReaddStale, handle.Epoch(), removedEpoch)
 	}
-	session, err := messagegroup.NewGroupSession(handle, invite.PqSecret, invite.GroupHandleKey,
+	session, err = messagegroup.NewGroupSession(handle, invite.PqSecret, invite.GroupHandleKey,
 		self.reserver, self.nowMs, nonce)
 	if err != nil {
-		handle.Close()
 		return nil, fmt.Errorf("urmessage: the session at epoch %d: %w", handle.Epoch(), err)
 	}
 	// the door to prior epochs, ledger item 241. A member admitted here holds state from its
 	// admission on, so every epoch before it answers not-found through this door and renders as
 	// a gap; that is MLS's own answer for a later member and item 241 rules it stays that way.
 	if err := session.InstallPastEpochLoader(self.pastEpochLoader(invite.GroupId)); err != nil {
-		session.Close()
 		return nil, fmt.Errorf("urmessage: the past epoch loader: %w", err)
 	}
+	// THE COMMIT, CREATE-ONLY: the joined state reaches the store only if the store holds none for
+	// this group and epoch. It is the last thing that can refuse without costing the join code.
+	if err := self.joinStage.commit(); err != nil {
+		return nil, err
+	}
+	committed = true
+	// ── THE WINDOW IS CLOSED ───────────────────────────────────────────────────────────────────
 	group := &Group{
 		device:         self,
 		id:             append([]byte(nil), invite.GroupId...),
@@ -1485,7 +1538,7 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
 		session.Close()
 		handle.Close()
 		return nil, fmt.Errorf(
-			"urmessage: this group joined and its record could not be persisted, so a restart would not come back into it: %w", err)
+			"%w: this group joined and its record could not be persisted, so a restart would not come back into it: %w", ErrJoinCodeSpent, err)
 	}
 	if err := self.holdReplacing(group, replaces); err != nil {
 		session.Close()
```

- [ ] **Step 4: the registry.** The scenarios this closes now observe the goal, so their entries flip in this commit.

`sdk/cp3b/testdata/advsim/known-gaps.json`:

```diff
--- a/sdk/cp3b/testdata/advsim/known-gaps.json
+++ b/sdk/cp3b/testdata/advsim/known-gaps.json
@@ -12,7 +12,7 @@
     {"id": "S2b-first-appearance-link", "state": "residual", "expect": ["linked:2/2"], "goal": [], "closed_by": "none", "reads": "with no key at all, the order sender handles first appear in the server's rows links the founder and this paste's joiner to their handles; sealing the secrets does not change it"},
     {"id": "S3-chosen-secret", "state": "open", "expect": ["installed:attacker-secret"], "goal": [], "closed_by": "T1", "reads": "an attacker on the paste channel rewrites the invitation so that it carries secrets the attacker chose, and the joiner installs them"},
     {"id": "S3-refusal-spends-join-code", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "an invitation refused for naming another group costs the joiner its one-use join code, so the honest invitation that follows cannot be joined"},
-    {"id": "S3-late-refusal-spends-join-code", "state": "open", "expect": ["join-code-spent"], "goal": [], "closed_by": "T1a", "reads": "an invitation refused after the engine has joined costs the joiner its join code and leaves state behind"},
+    {"id": "S3-late-refusal-spends-join-code", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "an invitation refused after the engine has joined costs the joiner its join code and leaves state behind"},
     {"id": "S3-mg1-join-code-substitution", "state": "open", "expect": ["swapper-read:1"], "goal": [], "closed_by": "T2", "reads": "a swapper substitutes its own join code; the founder adds the swapper believing it is the victim, and the swapper reads what the founder sends"},
     {"id": "S4-state-thief", "state": "open", "expect": ["epoch:1"], "goal": [], "closed_by": "T3", "reads": "a copy of the joiner's state directory taken after the join reads the join epoch: keys at rest are plaintext"},
     {"id": "S7a-held-id-valid-invite", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "a valid invitation into an attacker's group founded under a group id the victim holds replaces the victim's group"},
```

Measured at this commit with the registry of the commit before: each of these FAILS and names the edit.

```
ADVSIM S3-late-refusal-spends-join-code state=open     expect=[join-code-spent] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
```

- [ ] **Step 5: run it and see it pass.**

```bash
go -C sdk test -count=1 ./...
go -C sdk/cp3b test -count=1 ./...
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./... | grep -c '^--- FAIL'
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run): Strict mode has 9 FAIL: the six T1 gaps, the two of the identity track and the one of the healing track. The existing re-add test `TestADeviceAddedBackThroughARealJoinReadsNoRemovalAndTheDiskAgreesAfterARestart` still passes.

```
messagegroup   exit=0 pass=361 fail=0
sdk            exit=0 pass=321 fail=0
cp3b           exit=0 pass=113 fail=0
advsim-strict  exit=1 pass=17 fail=9
```

- [ ] **Step 6: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ27`: the create-only probe removed: the commit writes over a state that is already there. Property 1 must fail. Measured: killed by `TestAStagedJoinReachesTheStoreOnlyAtCommitAndNeverOverAStateAlreadyThere`, and 2 other tests.
2. `MJ27b`: a store that fails to answer is read as "nothing there". Property 1 must fail. Measured: killed by `TestACommitOverAStoreThatCannotAnswerIsRefused`.
3. `MJ31`: the probe erases what the store answered, which is the store's own array. Property 1 must fail. Measured: killed by `TestTheCreateOnlyProbeLeavesTheStoresOwnArrayAlone`.
4. `MJ28b`: a refused join does not put the join code back. Property 2 must fail. Measured: killed by `TestAnAbortedJoinPutsTheJoinCodeBack`, and 9 other tests.
5. `MJ28`: the one-phase join: the stage never stages, and the joined state is written as the engine joins. Property 3 must fail. Measured: killed by `TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode`, and 13 other tests.
6. `MJ39`: a refusal inside the window answers its bare cause: nothing says the join code is not spent. Property 3 must fail. Measured: killed by `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent`, and 4 other tests.
7. `MJ40`: the put-back's failure is discarded (the first revision of this plan, on the engine's refusal): a join code the store did not take back is reported as still good. Property 4 must fail. Measured: killed by `TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent`, and 1 other test.
8. `MJ41`: a join whose record could not be written does not say its join code is spent. Property 4 must fail. Measured: killed by `TestAJoinWhoseRecordCannotBeWrittenSaysTheJoinCodeIsSpent`, and 1 other test.
9. `MJ60`: an invitation whose join code is already gone is answered with the window's sentence: it says the join code is not spent, and it is gone. Property 5 must fail. Measured: killed by `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent`, and 1 other test.

- [ ] **Step 7: commit.**

```bash
git add sdk/urmessage/joinstage_test.go sdk/urmessage/joinwindow_test.go sdk/cp3b/heldgroup_test.go sdk/urmessage/joinstage.go sdk/urmessage/device.go sdk/urmessage/errors.go sdk/urmessage/group.go sdk/cp3b/testdata/advsim/known-gaps.json
git commit -m "urmessage: a join reaches the store only after every check, and a refusal puts the join code back"
```

### Task 37: The open item for a re-added device's first `Receive`: filed, cited and reproduced, and not fixed

- Consumes: `messagegroup/OPENITEMS.md` and its two rules for a row; the gate `TestTheOpenItemThisPackageCitesIsFiledWhereItSaysItIs`; `messagegroup.ErrRecordAeadOpen` and `ErrRecordOpen`; the harness's scene (Task 4) and `removalAdd`; `Device.ForgetGroup`; the lead's rulings R10 and R14
- Produces: the row `MG-8` of `messagegroup/OPENITEMS.md`, the line of `messagegroup/errors.go` that cites it, and `TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen`

**Why this is a task (R10, R14; the final check's F3 and grounding MAJOR 2).** While planning,
the lab found a defect this plan neither causes nor changes: a device that was removed and added
back reads what is sent after the re-add, and its first `Receive` ALSO answers "a record ciphertext
did not authenticate" for history it cannot open. An authentication failure is the signal for
tampering, and it must not also be the answer for history that is unreadable by design. THIS PLAN
DOES NOT FIX IT: the healing track's plan takes it. The lead's ruling is that the T1a pull request
FILES it, and a filing in this repository is three things at once, because a gate holds the file
both ways: a row that no production prose cites fails the gate, and so does a citation with no row.

**What was measured, and it is all the row says.** On the tree of Task 36, with real devices
against the real server in one process (`lab-s0t1plan/rev/probes/`, and the planner's first probes
in `lab-s0t1plan/v2/probes/`):

| The re-added device | Its first `Receive` after the re-add |
|---|---|
| joined at the founding, and still holds its files of that first membership | the founder's new line, AND `urmessage.ErrRecordOpen` carrying `messagegroup.ErrRecordAeadOpen`, for a record the founder sealed before its removal |
| the same device, having left the group with `ForgetGroup` before it was added back | the founder's new line, the earlier history as 2 gaps, and no error |
| the same device, with ONLY the epoch states of its first membership removed from its disk | the founder's new line, the earlier history as 2 gaps, and no error |
| the same device, with only the copy of a line it sent removed, or only its head table | as the first row: the failure is as it was |
| a device that joined by a later add, and never held the founding epoch | the founder's new line, the earlier history as 2 gaps, and no error |

On the first row the same error came back on the second `Receive`, the third answered
`urmessage.ErrRecordAbandoned`, and from the fourth on `Receive` answered nothing; the history was
never read. So the precondition is on the device's own disk, and it is exactly this: an epoch
state of the FIRST membership, still there beside the state the re-add writes. The final check
reproduced the first row on the S0, T1a and T1 trees.

**The tree already holds part of this, as a COST and not as a defect, and the row says so.** The
header of `urmessage.ErrRemovedFromGroup` prices the one repair a removal names, being added back,
and `TestTheOnlyRepairTheRemovedSentinelNamesIsBeingAddedBackAndItCostsThreeWalksAndTheHistory`
holds it: a re-added device's own earlier lines cost `maxRecordAttempts` failed walks each and are
then lost. What the lead's ruling and this lab add: the answer on those walks is the signal for
tampering; it is not only the device's own lines; and the failed walks come from what the first
membership left on the disk, since with its epoch states gone there are none. A ruling on MG-8
therefore changes that header and that case, and the row lists both among what it has to choose.

**The named test HOLDS THE DEFECT AS IT IS; it does not approve it.** Its first half fails, by
name, on the day the defect is repaired ("OPEN ITEM MG-8 HAS CLOSED"), and on the day it changes
shape ("HAS MOVED"). Its other two halves are the controls, which are rows two and three of the
table: the same history as gaps, with no error.

**Property 1.** A device that joined at the founding, was removed and is added back, and still holds its files of the first membership, reads what the founder sends after the re-add, and its first `Receive` also answers `urmessage.ErrRecordOpen` carrying `messagegroup.ErrRecordAeadOpen`; the same device with those files gone, or with only the epoch states of the first membership gone, reads that history as gaps and answers no error.

**Property 2.** The open item is filed where the code cites it: `messagegroup/OPENITEMS.md` has a row `MG-8`, and production prose of `messagegroup` names it.

- [ ] **Step 1: the row first.** Append to `messagegroup/OPENITEMS.md`, in the file's own shape: the property, the reproduction, what a ruling has to choose, and what is owed elsewhere.

`messagegroup/OPENITEMS.md`:

```diff
--- a/messagegroup/OPENITEMS.md
+++ b/messagegroup/OPENITEMS.md
@@ -864,3 +864,100 @@ device wrap and did not reach any of the three code points; ruling 36's own sent
 post-quantum gate cannot be discharged by a carrier whose confidentiality rests on the MLS exporter*
 — is what makes this door load-bearing rather than optional, so the encodings it needs are now on
 the critical path of the removal track rather than of a later slice.
+
+---
+
+## MG-8 — a device added back after a removal answers "a record ciphertext did not authenticate" for history it cannot open by design
+
+**Status: OPEN. Filed 2026-10-09 by the hardening program's held-group gate, which measured it and
+does not change it. The mechanism is the healing track's to rule and to build.**
+
+### The property
+
+`ErrRecordAeadOpen` is this package's one answer for a record whose ciphertext does not
+authenticate under the key, the nonce and the aad it was opened with. Whoever is handed it has one
+reading: the record was altered, or it was sealed by somebody who does not hold the key. **It must
+not also be the answer for history a device cannot open by design.** A signal that fires on an
+honest group says nothing on the day it matters.
+
+A device that is removed from a group and added back joins at the epoch of the re-add. What was
+sealed before that epoch is history. It either renders as a gap, which is the answer for any epoch
+a member holds no state for, or it opens, if the device kept what opens it. Measured, it does
+neither.
+
+### What this tree already says about it, and what is new
+
+Part of this is already measured, as a COST and not as a defect. The header of
+`urmessage.ErrRemovedFromGroup` prices the one repair a removal names, which is being added back,
+and `urmessage.TestTheOnlyRepairTheRemovedSentinelNamesIsBeingAddedBackAndItCostsThreeWalksAndTheHistory`
+holds it: a re-added device's OWN lines from before the removal cost `maxRecordAttempts` failed
+walks each and are then lost, because the device "holds state from its admission on".
+
+Three things are added here.
+
+1. **A reading of that cost.** The answer on those walks is `ErrRecordAeadOpen`, and it reaches
+   the caller of `Receive`. That is the signal for tampering, given on an honest group.
+2. **It is not only the device's own lines** (measured, and not in that case). A record of ANOTHER
+   member, sealed before the removal, answers it too.
+3. **The failed walks come from what the first membership left on the disk** (measured, and not in
+   that case). With the epoch states of the first membership gone, the same history comes back as
+   gaps and `Receive` answers no error: no failed walk, and nothing abandoned. The history is lost
+   either way. The failed walks and the wrong answer are not owed.
+
+### The reproduction
+
+`TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen`, in
+`sdk/cp3b/readdhistory_test.go`: real devices against the real server, in one process. A device
+joins at the founding and sends there; a second member is added; the founder removes the first
+device, adds it back, and sends one line.
+
+- The re-added device's first `Receive` hands back the founder's new line. **It also answers
+  `urmessage.ErrRecordOpen` carrying `ErrRecordAeadOpen`**, for a record the FOUNDER sealed before
+  the removal.
+- **The control, in the same case:** the same device, having left the group with `ForgetGroup`
+  before it was added back, so that nothing of its first membership is on its disk. The same
+  history comes back as gaps and `Receive` answers no error.
+- **The narrower control, in the same case:** ONLY the epoch states of the first membership are
+  removed from its disk before the re-add; its record and everything else of it stay. Again gaps,
+  and no error.
+
+So the precondition is on the device's own disk, and it is exactly this: an epoch state of the
+FIRST membership, still there beside the state the re-add writes.
+
+Measured once more in the lab on 2026-10-09 and NOT held by the case: with only the copy of a line
+the device sent removed, or only its head table, the failure is as it was; the same error comes
+back on the second `Receive`, the third answers `urmessage.ErrRecordAbandoned`, and from the fourth
+on `Receive` answers nothing; and a device that joined by a later add, and never held the founding
+epoch, read the same history as gaps with no error.
+
+It is in the tree as it stood before the held-group gate and is the same after it. The gate
+honours a re-add, which is the repair `ErrRemovedFromGroup` itself names, and writes nothing a
+join did not write before.
+
+### What a ruling has to choose
+
+Nothing below is decided, and this package must not decide it.
+
+1. **Whether a re-added device reads the history of its first membership at all.** It held those
+   epochs once, and the removal was a decision to cut it off. MLS's own answer for a member
+   admitted later is a gap.
+2. **If it does not, what makes that history a gap.** Either the re-add discards the epoch states
+   the first membership left, which the narrower control shows is enough and which `ForgetGroup`
+   does among other things, or the walk tells an epoch from before this membership from an epoch
+   of it before any key is tried.
+3. **If it does, what it opens that history with.** The record a re-add writes carries the secrets
+   of the epoch it joined at and of no epoch before it.
+4. **What must not change, whichever way it is ruled.** A record of a current epoch that does not
+   authenticate goes on answering `ErrRecordAeadOpen`, and so does a record of a past epoch the
+   device does hold the keys for. "Answer a gap for anything old that does not open" is not the
+   repair: it is the tampering signal switched off for every past epoch, and the case that
+   reproduces this item is written to fail on it by name.
+5. **What the tree's own sentences say afterwards.** `ErrRemovedFromGroup`'s header and the case
+   it names price failed walks as the cost of being added back. A ruling here changes that price,
+   and both move with it.
+
+### What is owed elsewhere
+
+The healing track of the hardening program, whose plan takes this item, and a `SPEC-LEDGER.md`
+number from whoever owns that register. Until one exists, `errors.go` cites this row beside the
+sentence it is about.
```

- [ ] **Step 2: the test.** It needs the harness of phase S0 (`advFounding`), so it lives in `sdk/cp3b`.

`sdk/cp3b/readdhistory_test.go` (new file, 117 lines):

```go
package cp3b

import (
	"errors"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/sdk/urmessage"
)

// OPEN ITEM MG-8, REPRODUCED. A device that is removed from a group and added back reads what is
// sent after the re-add, and its first Receive ALSO answers an authentication failure for history
// it cannot open by design.
//
// The device joined at the founding and sent there. A second member was added, the founder removed
// the first device and added it back, and the founder sent one line. The device still holds its
// files of the first membership. Its first Receive after the re-add hands back the founder's new
// line, and it also answers [urmessage.ErrRecordOpen] carrying [messagegroup.ErrRecordAeadOpen],
// "a record ciphertext did not authenticate", for a record sealed before the removal. That
// sentence is the signal for tampering, and nothing here was tampered with.
//
// THIS CASE HOLDS THE DEFECT AS IT IS, so that it cannot change shape unseen. It does not approve
// it: messagegroup/OPENITEMS.md files it as MG-8, and the healing track's plan takes it. WHEN IT
// IS REPAIRED THIS CASE FAILS, by name. It is then rewritten to hold the repair, and the row and
// the line of messagegroup/errors.go that cites it are deleted in the same commit.
//
// PART OF IT IS ALREADY HELD ONE MODULE OVER, AS A COST:
// urmessage.TestTheOnlyRepairTheRemovedSentinelNamesIsBeingAddedBackAndItCostsThreeWalksAndTheHistory
// holds that a re-added device's own earlier lines cost failed walks and are then lost. What this
// case adds is the two controls, which say where that cost comes from.
//
// THE CONTROLS are the same device with less of its first membership on its disk. In the first it
// left the group with ForgetGroup before it was added back, so nothing of the first membership is
// there. In the second, narrower one, ONLY the epoch states of the first membership are gone, and
// its record and everything else of it stay. In both the same history comes back as gaps and
// Receive answers no error. So the failure is not about a re-add as such, and it is not about the
// epoch: it is about an epoch state of the first membership found beside the re-add's own.
//
// WHAT WOULD GO RED: hand a record of an earlier epoch that does not authenticate back as a gap,
// and the first half reads "MG-8 has closed". That is the repair NOT to make: it is the tampering
// signal switched off for every past epoch.
func TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen(t *testing.T) {
	for _, one := range []struct {
		name    string
		control string
	}{
		{"with its files of the first membership still on its disk", ""},
		{"THE CONTROL: having left the group with ForgetGroup before it was added back", "forgot"},
		{"THE NARROWER CONTROL: with only the epoch states of the first membership removed from its disk", "epochs"},
	} {
		scene := advFounding(t, true)
		carol := scene.world.newPersona(t, "carol")
		hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
		if err := scene.aliceGroup.RemoveMember(scene.ctx, rolesIdentityOf(t, scene.bobGroup)); err != nil {
			t.Fatalf("%s: alice's RemoveMember of bob: %v", one.name, err)
		}
		var err error
		for round := 0; round < 6; round += 1 {
			if _, err = scene.bobGroup.Receive(scene.ctx); errors.Is(err, urmessage.ErrRemovedFromGroup) {
				break
			}
		}
		removedAt, removal := scene.bobGroup.Removal()
		if removal == nil {
			t.Fatalf("%s: CONTROL FAILED: bob does not read as removed (his last Receive answered %v), so nothing below is about a re-add", one.name, err)
		}
		before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
		if _, held := before["epoch/0000000000000001"]; !held {
			t.Fatalf("%s: CONTROL FAILED: bob holds no state of the founding epoch, so he is not a device that held earlier epochs", one.name)
		}
		switch one.control {
		case "forgot":
			if err := scene.bob.device.ForgetGroup(scene.groupId); err != nil {
				t.Fatalf("%s: bob's ForgetGroup of the group he was removed from: %v", one.name, err)
			}
		case "epochs":
			if err := advRemoveEpochStates(scene.bob.stateDir, scene.groupId); err != nil {
				t.Fatalf("%s: removing the epoch states of the first membership: %v", one.name, err)
			}
			after := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
			if len(after["meta"]) == 0 || len(after) >= len(before) {
				t.Fatalf("%s: CONTROL FAILED: %d file(s) before and %d after, and the record must be one of those left: this is not \"only the epoch states\"", one.name, len(before), len(after))
			}
		}
		rejoined := removalAdd(t, scene.ctx, "alice", scene.aliceGroup, scene.bob.device, "bob")
		if epoch := rejoined.Epoch(); epoch <= removedAt {
			t.Fatalf("%s: CONTROL FAILED: the re-add stands at epoch %d and the removal was at %d", one.name, epoch, removedAt)
		}
		canary := scene.say(t, "alice", scene.aliceGroup)
		received, err := rejoined.Receive(scene.ctx)
		read, gaps := false, 0
		for _, message := range received {
			switch {
			case message.Gap != "":
				gaps += 1
			case message.Text == canary:
				read = true
			}
		}
		t.Logf("%s: the first Receive after the re-add: %d message(s), %d of them gaps, the founder's new line read=%v, and %v", one.name, len(received), gaps, read, err)
		if !read {
			t.Fatalf("%s: the re-added device did not read what the founder sent after the re-add, which is not this open item: it is a re-add that does not work", one.name)
		}
		if one.control != "" {
			if err != nil || gaps == 0 {
				t.Fatalf("%s: Receive answered %d gap(s) and %v, want the history as gaps and no error", one.name, gaps, err)
			}
			continue
		}
		switch {
		case err == nil:
			t.Fatalf("OPEN ITEM MG-8 HAS CLOSED: the re-added device's first Receive answered no error (%d gap(s)). Rewrite this case to hold the repair, and delete the MG-8 row of messagegroup/OPENITEMS.md and the line of messagegroup/errors.go that cites it, in the same commit", gaps)
		case !errors.Is(err, urmessage.ErrRecordOpen) || !errors.Is(err, messagegroup.ErrRecordAeadOpen):
			t.Fatalf("OPEN ITEM MG-8 HAS MOVED: the re-added device's first Receive answered %v, and the row records urmessage.ErrRecordOpen carrying messagegroup.ErrRecordAeadOpen. Say what it is now in messagegroup/OPENITEMS.md", err)
		}
	}
}
```

- [ ] **Step 3: run them and see the gate fail.** On the tree before this commit, with the row and the test laid over it and NO line of production prose citing the row yet. The gate is red, and names what is missing. The named test PASSES there, and that is the point of it: the defect it holds is in the tree before this commit. Measured:

```
$ go test -count=1 -run ^TestTheOpenItemThisPackageCitesIsFiledWhereItSaysItIs$ ./messagegroup/
exit status 1
--- FAIL: TestTheOpenItemThisPackageCitesIsFiledWhereItSaysItIs (0.02s)
    enginejoin_test.go:1874: register: 8 row(s) [MG-1 MG-2 MG-3 MG-4 MG-5 MG-6 MG-7 MG-8]; production source cites 7 [MG-1 MG-2 MG-3 MG-4 MG-5 MG-6 MG-7]
    enginejoin_test.go:1875: complement: 1 filed row(s) that no production file cites, [MG-8]
    enginejoin_test.go:1877: no production prose of this package cites MG-8, which OPENITEMS.md files. The obligation belongs at the surface a caller uses, and a register nothing points at is a register nobody reads
FAIL
FAIL	github.com/urnetwork/message/messagegroup	0.604s
FAIL
$ go -C sdk/cp3b test -count=1 -run ^TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen$ ./...
exit status 0
ok  	github.com/urnetwork/message/sdk/cp3b	1.985s
```

- [ ] **Step 4: the one line of production prose that cites it.** Beside the sentence the item is about.

`messagegroup/errors.go`:

```diff
--- a/messagegroup/errors.go
+++ b/messagegroup/errors.go
@@ -35,6 +35,7 @@ var (
 	// Fires when a record ciphertext does not authenticate under the key, the nonce and the
 	// aad it was opened with. It carries no plaintext with it and never a partial one: the
 	// only thing an unauthenticated ciphertext yields is the refusal.
+	// Open item MG-8: a device added back after a removal also reaches this, for history.
 	ErrRecordAeadOpen = errors.New("messagegroup: a record ciphertext did not authenticate")
 	// Fires when a group handle key is not the thirty two octets HKDF-Expand(storage_root[0],
 	// "gh/v1", 32) produces. A handle derived from a truncated key is a well formed handle,
```

- [ ] **Step 5: run it and see it pass.**

```bash
go test -count=1 -run 'TestTheOpenItemThisPackageCitesIsFiledWhereItSaysItIs' -v ./messagegroup/ | grep -E 'register:|complement:|^--- |^ok|^FAIL'
go test -count=1 ./messagegroup/
go -C sdk/cp3b test -count=1 -run 'TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen' -v ./...
```

Measured on this commit. The gate, and then the three halves of the named test:

```
register: 8 row(s) [MG-1 MG-2 MG-3 MG-4 MG-5 MG-6 MG-7 MG-8]; production source cites 8 [MG-1 MG-2 MG-3 MG-4 MG-5 MG-6 MG-7 MG-8]
complement: 0 filed row(s) that no production file cites, []
with its files of the first membership still on its disk: the first Receive after the re-add: 1 message(s), 0 of them gaps, the founder's new line read=true, and urmessage: a record from a member of this group did not open: record 5 from leaf 0: messagegroup: a record ciphertext did not authenticate: 25 octets of ciphertext
THE CONTROL: having left the group with ForgetGroup before it was added back: the first Receive after the re-add: 3 message(s), 2 of them gaps, the founder's new line read=true, and <nil>
THE NARROWER CONTROL: with only the epoch states of the first membership removed from its disk: the first Receive after the re-add: 3 message(s), 2 of them gaps, the founder's new line read=true, and <nil>
```

And the suites (`lab-s0t1plan/out2/verify/`):

```
messagegroup   exit=0 pass=361 fail=0
sdk            exit=0 pass=321 fail=0
cp3b           exit=0 pass=114 fail=0
advsim-strict  exit=1 pass=17 fail=9
root with mls  exit=0 pass=2524 fail=0
```

- [ ] **Step 6: the mutations.** One edit of production code, applied alone, and one of the file. Appendix B prints the first.

1. `MJ61`: a record of an earlier epoch that does not authenticate is handed back as a gap: the symptom of MG-8 goes away, and with it the tampering signal for every past epoch. Property 1 must fail. Measured: killed by `TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen`, and 1 other test.
2. The row with the citing line of `messagegroup/errors.go` left out. Property 2 must fail. Measured: it is this task's tests-first run, where `TestTheOpenItemThisPackageCitesIsFiledWhereItSaysItIs` fails with "no production prose of this package cites MG-8".

`MJ61` is THE REPAIR NOT TO MAKE, and the row says so: "answer a gap for anything old that does
not open" makes this symptom go away and switches the tampering signal off for every past epoch.
The test is written to fail on it by name, so that whoever repairs the item meets the sentence.

- [ ] **Step 7: commit.**

```bash
git add messagegroup/OPENITEMS.md messagegroup/errors.go sdk/cp3b/readdhistory_test.go
git commit -m "messagegroup, cp3b: open item MG-8, a re-added device answers an authentication failure for history it cannot open"
```

### Task 38: Run every T1a mutant

- Consumes: the mutations stated in Task 33, Task 34, Task 35, Task 36 and Task 37; Appendix B
- Produces: a table of kills made on the branch, to stand beside the lab's

This task changes no file and states no property. Apply each of the 35 T1a mutants of Appendix B
alone to the tree of Task 37, run `messagegroup`, `sdk/urmessage` and the whole of `sdk/cp3b`, and
restore the tree. Every one must be killed by the test its task names. The lab's run of the same
35 is the first table of "Mutation proofs".

### Task 39: The app can leave a group that did not restore, before any app package is built on a T1a library (message-windows writer)

- Consumes: `ErrGroupAlreadyHeld`, `ErrGroupRecordDamaged`, `ErrGroupNotRestored` and `ForgetGroup`'s leave of a group that did not restore or whose record does not read (Task 33); the native bridge's `urnet_message_device_forget_group`, which takes a group id and needs no live group; the lead's ruling R13
- Produces: in `message-windows`: a leave action for a group that is not live, offered on the held-group refusal; its sentence; and the screenshots of both

**Why this is a task, and why it is HERE and not at the end of T1 (R13; the final check's F4).**
The app's half of a refusal ships with the refusal. T1a closes the join that used to repair a group
which does not restore: an invitation into it is now refused with `ErrGroupAlreadyHeld`, and the
remedy that sentence names is `ForgetGroup`. Read in the app by the final check (`message-windows`
at `0b08178`, `app/src/App/Live/LiveMesh.cpp`): after a restore that brings back no group it waits
for an invitation, and its leave action needs a live group. So an app built on a T1a library,
before this task, tells a person to leave a group first and gives them no way to. This task changes
no file of this repository and states no property.

**The rule that makes the order safe.** `message-windows` pins its `message` commit by hand, so
nothing of T1a reaches the app before that pin moves. THE PIN DOES NOT MOVE TO A T1a COMMIT, AND NO
APP PACKAGE IS BUILT ON A T1a LIBRARY, BEFORE THIS TASK IS DONE. Task 40 says so again, and its
report says whether it is done.

| The sdk answers | The app says, and does |
|---|---|
| `ErrGroupAlreadyHeld`, for a group that is live in the app | "You are already in this group on this device." |
| `ErrGroupAlreadyHeld`, for a group that is not live: it did not restore, or its record does not read (the sentence then also carries `ErrGroupRecordDamaged`'s) | "This device still holds an old copy of this group that it cannot open. Leave it, and then use this invitation again." It OFFERS THE LEAVE, and the leave is `urnet_message_device_forget_group` with the group id OF THE INVITATION the person was refused over. The same invitation is then joined again: the refusal did not spend the join code. |
| `ErrGroupNotRestored`, from that leave | the app runs its restore first, and offers the leave again if the group did not come back |

**Where the app gets that group id, and one gap in the bridge that is said and not fixed.** A group
that is not live has no handle, and the bridge has NO ACCESSOR FOR AN INVITATION'S GROUP ID:
`urnet_message_group_id` reads a group. Two places hold the id today, and both were read off the
lab's tree: it is the FIRST FIELD of an encoded invitation, 32 octets behind the two version
octets and a four-octet length, at invite version 2 and at version 3 alike; and the refusal's own
sentence carries it in hex ("group <64 hex> has a record on this device's disk"). The app's writer
takes it from the invitation's octets. An accessor would be the cleaner door, and it is NOT added
here: it is an exported symbol and a change to the C header, and this plan makes neither. If the
app's writer wants it, it is a ruling for the lead and a small pull request of its own.

- [ ] **Step 1: the leave action for a group that is not live**, reached from the refusal above.
  It needs no roster and asks no owner's question, as `ForgetGroup` itself does not for such a
  group (R9).
- [ ] **Step 2: the two sentences**, each screenshotted from the running app with a state
  directory damaged for the purpose: one whose epoch states are gone, and one whose group record
  is cut short. A green build is not a check of what a person sees.
- [ ] **Step 3: the pin.** Only now may `message-windows` move its `message` pin to a T1a commit.

The other sentences T1a adds (the window's prefix, `ErrJoinCodeSpent`, `ErrNoJoinCodeForInvite`,
`ErrReaddStale`) have their rows in Task 58, with the app's other copy. Until then the app
shows them as it shows any error today, and none of them names an action the app lacks.

### Task 40: Close T1a: the full run on both hosts, the ledger, the report, the pull request

- Consumes: every T1a task, Task 32 to Task 39
- Produces: the T1a pull request, a ledger entry in `message-server`, and the owner's second report

This task changes no file of this repository and states no property.

**No app package is built on a T1a library before Task 39 is done (R13).** T1a merges to
`urnetwork/message` when this task's steps are green; what waits for the app's leave action is
the `message` pin of `message-windows`, which is moved by hand and by nobody else.

**T1a's own mechanisms are reviewed AFTER they merge, and this entry says so (the final check's
F15).** The pre-merge review of the join seal design's round-2 prompts is Task 57, at the end of T1, by
the lead's ruling. The removed-group exception, the admission mutex and `ForgetGroup` without the
owner's question are inside that review and are on `main` before it. The ledger entry and the
report of this close name the three, so that nobody reads "merged" as "reviewed".

- [ ] **Step 1: the full run, on both hosts (R8).** On linux with gcc, on the host `alt-2` (the race detector, the composed native library and `sdk/cgo`, `nm`, the pinned protoc), and on Windows from a clone made with `core.autocrlf=true`. Neither was run in the lab, which has no C compiler. The verdicts are R8's, as R15 words them. `alt-2` prints `VERDICT: PASS, narrower than the full run (above)` with exactly one narrowing, the loopback library's C consumer, which is a Windows program. The Windows run is the `windows` leg of Step 2 (a `core.autocrlf=true` clone on GitHub's Windows runner, MinGW-w64 gcc on `PATH`), and it prints `VERDICT: PASS`, or the narrowed verdict with exactly one narrowing, the C consumer's second pass under ThreadSanitizer. Any other narrowing, or a second one, stops the close; a run on a host with no C compiler ends `VERDICT: FAIL` by design and is not this run. Print every narrowing line each run lists, and hold the set to the allowed one both ways. Both runs are under the toolchain pin of the day (R6), and the numbers this phase reports are these runs' numbers. T1a puts a mutex on the join path (`Device.admitMutex`) and one inside the stage, and the race detector has not seen either: the lab's host has no C compiler. A RACE REPORT HERE IS A FINDING, NOT NOISE (R8): it stops the pull request until it is read.

```bash
./test.sh
```

- [ ] **Step 2: the fork's workflow, all four legs (R8, R11).** Run `fork-ci.yml` on the branch head, on the owner's fork, with all four legs, and wait for four green legs. The fourth is the provenance leg in R11's form: the recorded tip of the import's proof (the head of the pins switch) is an ancestor of this branch, and the proof passes AT that tip. THIS PHASE ADDS NO ROW TO `docs/history/adaptations.tsv` AND CHANGES NO FILE UNDER `docs/history`. The leg's change landed with the pins switch: it holds the recorded tip `7a33917306ae` (`docs/history/recorded-tip.txt`) and runs that tip's own proof, and it is green on `0bb2128f` (fork run 38290870884). If it is red on a phase head, that is a finding for the lead, and no row is improvised to make it pass. The workflow file is fork-only and is in no upstream pull request.

- [ ] **Step 3: the pull request.** From a branch CUT FROM `urnetwork/message` `main`, pushed to the fork, to `urnetwork/message` main: merge commit only, never force-pushed (`README.md`, Contributing). When `main` moves, `main` is merged into the branch. It ships on the mainline FIRST, ahead of the format change, because it closes a defect today's build has. Its description carries the two verdict lines, the id of the fork's run with its four legs, the kills of Task 38, and the open item it files (Task 37).

- [ ] **Step 4: the ledger entry (message-server writer, R7).** The same writer as Task 1, in its own small pull request to urnetwork/message-server, paired with this phase and merged first. It records: the close; the 35 kills of Task 38; the residual T1a leaves by name, `S7g-removed-group-second-founder`; THE OPEN ITEM IT FILES, `MG-8` of `messagegroup/OPENITEMS.md` (Task 37), with the note that the healing track's plan takes it; rulings R12 and R13 as applied; and that T1a's mechanisms are reviewed at Task 57, after this merge.

- [ ] **Step 5: the report.** Send "At the end of T1a" from "Reports to the owner", with the numbers of the runs made on the branch, under the compiler of the day. It says whether Task 39 is done.

---

# Phase T1: the invitation carries no secret in the clear

**Version table.** One row is all the reset variant keeps:

| | A version 2 invitation | A version 3 invitation |
|---|---|---|
| This build reads | refused: `ErrInviteVersion` | joined, after verify, open, check |
| This build writes | never | always |
| A join code without capability `0xF004` | | refused by the adder before anything is staged: `ErrJoinerCannotOpenSealedInvite` |
| A group whose context does not require `0xF004` | | not joined and not restored: `ErrGroupPredatesJoinSeal` |

**Formats** (all in `sdk/urmessage/joinseal.go`):

```
join_secrets_v1 = pq_secret[e] (32) | group_handle_key (32) | epoch_keys_digest[e] (32)        96 octets
join_seal       = wrap body over join_secrets_v1, through messagegroup.SealWrapBody, envelope
                  u8(0x01) | u8(target 0x03 JOINER) | u8(payload 0x04) | u64(content epoch 0),
                  target_id = u32(joiner_leaf)                                            1,253 octets
join_key        = MLS-Exporter("URmessage/v1/joinkey", u32(joiner_leaf), 32) at epoch e
join_auth       = HMAC-SHA-256(join_key, preimage)                                           32 octets
preimage        = "URmessage/v1/joinauth" | u16(0x0041) | u16(0x0003) | LP(group_id) | u64(e)
                  | u32(joiner_leaf) | LP(H(welcome)) | LP(H(ratchet_tree)) | LP(H(join_seal))  181 octets
invite v3       = u16(0x0003) | LP(group_id) | LP(welcome) | LP(ratchet_tree) | LP(join_seal)
                  | LP(join_auth) | SHA-256(everything before)
```

The four code points (`0x03`, `0x04`, `0xF004`, `0x0041`) stand, by the lead's ruling of
2026-10-09. `0xF004` names exactly this: invite version 3 with `join_secrets_v1`. Any change to the
seal, the payload or the authenticator takes a new invite version and a new capability, and goes
back through a red team first; the sealed digest is part of it and is kept.

**The joiner's checks, in order.** Nothing is written before the last row, and every refusal from
row 4 on is made inside the join's window: it puts the join code back, and it begins with the
window's sentence (Task 36). The one exception is in row 4: an invitation no join code of this
device was made for, where there is no join code for "not spent" to be true of.

| # | Check | Refusal | Where |
|---|---|---|---|
| 1 | version is `0x0003`; the checksum; five fields and nothing after | `ErrInviteVersion`, `ErrInviteDamaged`, or the framing's own sentence | `ParseInvite` |
| 2 | group id 32 octets; welcome and tree present; seal exactly 1,253; authenticator exactly 32; the envelope's four constants | `ErrJoinSealShape` | `Invite.check`, at the paste |
| 3 | the device does not hold this group as a member (memory and disk); a record of it that does not read is a held group, and a store that cannot answer for it is a refusal | `ErrGroupAlreadyHeld` | Task 33 |
| 4 | the welcome is for a join code this device holds, and describes the group the invitation names | `ErrNoJoinCodeForInvite` for the first, which is the one refusal from here on that does not begin with the window's sentence (R13); the engine's refusal for the second | Task 34, Task 35, Task 36 |
| 5 | a re-add stands above the epoch of the removal | `ErrReaddStale` | Task 33 |
| 6 | the group requires the join seal | `ErrGroupPredatesJoinSeal` | Task 47 |
| 7 | VERIFY `join_auth`, under this epoch's own exporter, over the received octets | `ErrJoinSealUnauthenticated` | `openJoinSeal` |
| 8 | OPEN the seal to this device's own X-Wing key | `ErrJoinSealUnreadable` | `openJoinSeal` |
| 9 | CHECK the payload: 96 octets, no all-zero secret, and the secret reproduces the sealed digest at this epoch | `ErrJoinSealUnreadable`, `ErrJoinSealWrongEpoch` | `openJoinSeal` |
| 10 | commit the staged state create-only, write the record, hold the group | `ErrJoinWouldOverwrite`, `ErrJoinCodeSpent` | Task 36 |

**T1 is twelve commits and not four.** Each task's diff is its own commit in the lab, built and
tested there, and each was cut from the commit before it. The flip of the format is one commit
because the adder that writes an invitation and the joiner that reads it cannot change in two
green commits; everything that can land ahead of it or after it does.

### Task 41: The sealed invite in MASTER and Spec A, reset-variant form (message-server writer)

- Consumes: the join seal design's section 4, less every compatibility part Appendix A lists; the formats and the table above; the lead's ruling that the four code points stand
- Produces: MASTER section 7.3 and the Spec A edits below, their edit-log rows, and one new ledger item

**Why this is a task, and why it is first.** T1 adds a third wrap target where MASTER says
"exactly two", a payload type, an algorithm id and a capability; the program's gates put the spec
edit ahead of the simulation step and require its ledger entry in the same commit. `messagegroup`
and `sdk/urmessage` are held to those documents by citation gates.

**Whose it is, and how it lands (R7).** The message-server writer's, the same one as Task 1 and
Task 32: its own small pull request to urnetwork/message-server, paired with phase T1, and the
owner is told to merge it first.

- [ ] **Step 1: MASTER** (`docs/specs/2026-08-12-urmessage-protocol-design.md`).
  - A new section 7.3, "The join delivery: a sealed invite": the formats above, with
    `join_secrets_v1` as a NAMED EXCEPTION to the wrap payload grammar (no `identity_pub`, no
    signature: `join_auth` stands in); the joiner's ten checks; the capability and the rule that
    every group requires it; why confidentiality rests on X-Wing alone and the exporter keys
    `join_auth` and nothing else; the residuals.
  - Section 7's target table: three `target_type` values and not two; `target_id = u32(leaf)` for
    the joiner; the code points `0x03` and `0x04`, with `0x02` and payload `0x03` left for the
    recovery wrap.
  - The sentence that says `pq_secret` "arrived under X-Wing": true of every epoch from this
    version on, the join epoch included; its history kept.
  - Section 7.1: HMAC-SHA-256 registered as `0x0041`, with the note that the three existing MACs
    carry no `alg_id`.
  - Section 8: the handle key and the join secret reach a joiner in `join_seal`, not in its
    Welcome.
  - Section 13's caveats: the seal is to a static key (a thief of the joiner's seed who also
    recorded the paste reads the join epoch); an invitation still shows the group's id and who is
    in it, so sender anonymity against a paste observer is NARROWED, not closed; a join
    authenticates nobody.
  - Section 15, open items: rotation of the handle key; sealing the welcome and the tree as well;
    a one-time X-Wing key per join code.
- [ ] **Step 2: Spec A** (`docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md`).
  - Section 3.1's table: a row for `0xF004`, capability only, refused as a group-context
    extension.
  - Section 5.7: how a joiner comes by the read key and the handle key.
  - Section 5.11, a new clause: the signature rule of its clause (4) is scoped to records;
    open item M1-54 is ruled for the join seal alone (version `0x01` only, refused at the paste,
    authenticated by `join_auth`); open item M1-55 is met, because every expectation is the
    joiner's own; and the order is verify, open, honour, which is stricter than a device wrap's
    because this MAC sits outside the seal.
  - Section 7: invite version 3; the errors this plan adds; the refusal of a join code from a
    device with no wrap seed; the held-group gate and its one exception; that one group record
    which does not read costs its own group and no other, and is left with `ForgetGroup` (R12);
    the one refusal inside the join's window that does not say the join code is not spent (R13);
    and the rule that only a group requiring the join seal is joined or restored.
  - Section 7.3a: every path that produces a Welcome delivers the seal and `join_auth`, made
    before anything of the epoch is submitted.
- [ ] **Step 3: the ledger item**, the next free number, by the section 6 change process: the
  rulings; the round-1 red-team record and that round 2 is Task 57 of this plan; the lab's
  measured runs with their commands; ledger item 266's post-quantum paragraph closed for joins
  from this version on; sender anonymity against a paste observer filed as narrowed; open item
  M1-20 gains `join_key` and the payload; MG-7 gains two code points; and the constraint this
  hands ledger item 185: the seal never carries ephemeral material.
- [ ] **Step 4: Spec C** (`docs/specs/2026-08-12-spec-c-windows-client-ui.md`) IS A FILE OF
  `message-server`, so its text is this writer's too, and one writer per repository holds. It is
  written from the copy the app's writer produces: the sentences and the screenshots of
  Task 39 (with phase T1a) and of Task 58 (with this phase). The app's writer writes the
  app; this writer writes the spec. It is a commit of its own, made when the app's writer hands
  over, and unlike steps 1 to 3 it does not have to land before T1's code.
- [ ] **Step 5: a subagent diff review**, then one commit, with each document's edit-log row.

### Task 42: The capability: every leaf lists `0xF004`, every group requires it, and a device that cannot open a seal publishes no join code

- Consumes: the spec text of Task 41; `mls`'s code-point registry, `groupExtensionProfile`, `v1Capabilities` and `engineRequiredCapabilities`; `Device.KeyPackage`
- Produces: `ExtensionTypeUrmessageJoinSeal`

**Behaviour.** `ExtensionTypeUrmessageJoinSeal = 0xF004` is a leaf capability and never a group
context extension. A key package that lists it says "my build opens a sealed invitation", and every
group this build founds requires it of every member, so `mls` itself refuses a join code without
it at the commit. It is unconditional: the design's `EngineOptions{JoinSeal}` existed to survive a
mis-paired `connect` and `sdk`, and both are one repository now (the lead confirmed the departure).

**The promise is kept or not made.** A store written before the X-Wing seed was kept restores
without one, and a join code from that device would list a capability it cannot honour: every add
of it would leave a leaf nobody can hand a working invitation to. `KeyPackage()` refuses, by the
name the missing seed already has (`ErrNoDeviceWrapKey`).

**Property 1.** `0xF004` is a registered private-use code point that a leaf lists as a capability and that is refused as a group-context extension.

**Property 2.** Every group the engine founds requires the join seal of its members, and a commit that adds a key package which does not list it is refused with nothing staged.

**Property 3.** A device with no X-Wing seed publishes no join code.

- [ ] **Step 1: the tests first.**

`mls/extension_test.go`:

```diff
--- a/mls/extension_test.go
+++ b/mls/extension_test.go
@@ -1511,6 +1511,7 @@ var registryCodePoints = map[string]map[string]uint64{
 		"ExtensionTypeUrmessageGroupPolicy":    0xF001,
 		"ExtensionTypeUrmessageLeafKeys":       0xF002,
 		"ExtensionTypeUrmessageOwnerSuccessor": 0xF003,
+		"ExtensionTypeUrmessageJoinSeal":       0xF004,
 	},
 }
 
```

`messagegroup/enginejoinseal_test.go` (new file, 94 lines):

```go
package messagegroup

import (
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// EVERY GROUP THIS ENGINE FOUNDS REQUIRES THE JOIN SEAL, AND ADMITS NO KEY PACKAGE WITHOUT IT. The
// capability is two things and both are held here: a leaf that lists it, which says its device
// opens a sealed invite, and a group that REQUIRES it, which is what makes connect/mls itself
// refuse a join code from a build that cannot. Only the first is visible in a join that works, so
// a founder that stopped requiring it would pass every suite that only joins.
//
// THE REQUIREMENT IS READ OFF THE GROUP'S OWN CONTEXT, and the refusal is driven with a real key
// package of a real device signer that carries its leaf keys and lists everything but 0xF004, so
// the only thing mls can refuse it for is the capability. THE CONTROL is the same construction
// with the capability listed, admitted by the same call.
//
// WHAT WOULD GO RED: take 0xF004 out of engineRequiredCapabilities and both halves fail; take it
// out of engineCapabilities alone and the control fails, because this engine's own key packages
// would no longer be admitted to its own groups.
func TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt(t *testing.T) {
	chain := newCommitAddChain(t, "the-join-seal-is-required")
	contextBytes, err := chain.founded.GroupContextBytes()
	if err != nil {
		t.Fatalf("GroupContextBytes: %v", err)
	}
	context := &mls.GroupContext{}
	if err := syntax.Unmarshal(contextBytes, context); err != nil {
		t.Fatalf("decoding the founded group's context: %v", err)
	}
	body, found, err := mls.FindExtension(context.Extensions, mls.ExtensionTypeRequiredCapabilities)
	if err != nil || !found {
		t.Fatalf("the founded group's context carries no required_capabilities (found %v, %v), so it requires nothing of a joiner", found, err)
	}
	required := mls.RequiredCapabilities{}
	if err := syntax.Unmarshal(body, &required); err != nil {
		t.Fatalf("decoding required_capabilities: %v", err)
	}
	if !slices.Contains(required.ExtensionTypes, mls.ExtensionTypeUrmessageJoinSeal) {
		t.Fatalf("a group this engine founded requires %v of a joiner, and the join seal capability %#04x is not among them",
			required.ExtensionTypes, uint16(mls.ExtensionTypeUrmessageJoinSeal))
	}

	third := newTestEngine(t)
	listing := func(extensions []mls.ExtensionType) []byte {
		leafKeys, err := mls.ParseLeafKeysExtension(third.leafKeys)
		if err != nil {
			t.Fatalf("the device's leaf keys body: %v", err)
		}
		leafKeysExtension, err := leafKeys.Encode()
		if err != nil {
			t.Fatalf("the leaf keys extension: %v", err)
		}
		capabilities := engineCapabilities()
		capabilities.Extensions = extensions
		keyPackage, initPrivate, encryptPrivate, err := mls.NewKeyPackageWithSigner(third.crypto,
			third.crypto.Suite(), third.signer, mls.BasicCredential(third.identityPub),
			capabilities, []mls.Extension{leafKeysExtension})
		if err != nil {
			t.Fatalf("a key package listing %v: %v", extensions, err)
		}
		defer keyPackage.Zeroize()
		defer zeroize(initPrivate)
		defer zeroize(encryptPrivate)
		encoded, err := syntax.Marshal(keyPackage)
		if err != nil {
			t.Fatalf("encode it: %v", err)
		}
		return encoded
	}
	without := listing([]mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys})
	_, _, _, err = chain.founded.CommitAdd([][]byte{without})
	if err == nil {
		t.Fatalf("a key package that does not list the join seal capability was admitted to a group that requires it")
	}
	if !strings.Contains(err.Error(), "required capability: extension type 0xf004") {
		t.Errorf("the refusal does not name the capability it was made for: %v", err)
	}
	if _, pendingErr := chain.founded.PendingEpoch(); pendingErr == nil {
		t.Fatalf("the refused add left a commit staged on the founder")
	}

	// THE CONTROL: the same key package with the capability listed is admitted by the same call.
	with := listing([]mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys, mls.ExtensionTypeUrmessageJoinSeal})
	if _, _, _, err := chain.founded.CommitAdd([][]byte{with}); err != nil {
		t.Fatalf("CONTROL FAILED: the same key package listing the capability answered %v", err)
	}
	chain.founded.ClearPendingCommit()
}
```

`sdk/urmessage/devicewrapkey_test.go`:

```diff
--- a/sdk/urmessage/devicewrapkey_test.go
+++ b/sdk/urmessage/devicewrapkey_test.go
@@ -35,6 +35,8 @@ import (
 
 	"github.com/urnetwork/message/messagegroup"
 	"github.com/urnetwork/message/mls"
+	messageprotocol "github.com/urnetwork/message/protocol"
+	"github.com/urnetwork/message/syntax"
 )
 
 // mintLeafKeys is one X-Wing key pair, as `deviceIdentity` mints one: the encoded leaf keys body
@@ -375,3 +377,32 @@ func TestNoFieldInThisPackageHoldsAnUnerasableXwingPrivateKey(t *testing.T) {
 	}
 	t.Logf("read %d struct fields of package urmessage's production source", fieldsRead)
 }
+
+// A DEVICE WITH NO X-WING SEED PUBLISHES NO JOIN CODE. The join code lists the join seal
+// capability, which asks for an invite sealed to the leaf's X-Wing key; a device that holds no
+// seed for that key would be asking for something it cannot open.
+//
+// THE CONTROL is a device that does hold its seed: it mints a join code, and that join code lists
+// the capability, which is the reason the refusal exists.
+//
+// WHAT WOULD GO RED: mint without asking, and the seedless device publishes a join code like any
+// other.
+func TestADeviceWithNoWrapSeedPublishesNoJoinCode(t *testing.T) {
+	dark := &Device{groups: map[string]*Group{}}
+	if _, err := dark.KeyPackage(); !errors.Is(err, ErrNoDeviceWrapKey) {
+		t.Fatalf("a device that holds no x-wing seed answered %v from KeyPackage, want ErrNoDeviceWrapKey", err)
+	}
+
+	lit, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("a nonce"))
+	joinCode, err := lit.KeyPackage()
+	if err != nil {
+		t.Fatalf("CONTROL FAILED: a device that holds its seed answered %v from KeyPackage", err)
+	}
+	decoded := &mls.KeyPackage{}
+	if err := syntax.Unmarshal(joinCode, decoded); err != nil {
+		t.Fatalf("CONTROL FAILED: the join code does not decode: %v", err)
+	}
+	if !decoded.LeafNode.Capabilities.SupportsExtension(mls.ExtensionTypeUrmessageJoinSeal) {
+		t.Fatalf("CONTROL FAILED: the join code does not list the join seal capability, so a seedless device publishing one would promise nothing")
+	}
+}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go test -count=1 -run ^(TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt) ./messagegroup/
exit status 1
FAIL	github.com/urnetwork/message/messagegroup [build failed]
FAIL
 # github.com/urnetwork/message/messagegroup [github.com/urnetwork/message/messagegroup.test]
messagegroup\enginejoinseal_test.go:44:51: undefined: mls.ExtensionTypeUrmessageJoinSeal
messagegroup\enginejoinseal_test.go:46:40: undefined: mls.ExtensionTypeUrmessageJoinSeal
messagegroup\enginejoinseal_test.go:89:117: undefined: mls.ExtensionTypeUrmessageJoinSeal
$ go test -count=1 ./mls/
exit status 1
--- FAIL: TestEveryRegistryDeclaredHereHoldsTheCodePointsTheRfcAssigns (0.12s)
    extension_test.go:1674: ExtensionType declares
FAIL
FAIL	github.com/urnetwork/message/mls	145.041s
FAIL
$ go -C sdk test -count=1 -run ^(TestADeviceWithNoWrapSeedPublishesNoJoinCode) ./urmessage/
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\devicewrapkey_test.go:405:58: undefined: mls.ExtensionTypeUrmessageJoinSeal
urmessage\rolesingest_test.go:901:8: undefined: mls.ExtensionTypeUrmessageJoinSeal
```

- [ ] **Step 3: the change.**

`mls/extension.go`:

```diff
--- a/mls/extension.go
+++ b/mls/extension.go
@@ -86,6 +86,12 @@ const (
 	ExtensionTypeUrmessageGroupPolicy    ExtensionType = 0xF001
 	ExtensionTypeUrmessageLeafKeys       ExtensionType = 0xF002
 	ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003
+	// urmessage_join_seal is CAPABILITY-ONLY: no extension of this type is ever carried, in a
+	// leaf or in a group context. A key package that lists it says its device opens invite
+	// version 3, whose join secrets arrive sealed to the leaf's urmessage_leaf_keys key, and a
+	// group that requires it admits no device that cannot. It names exactly that one format: a
+	// change to the seal, its payload or its authenticator takes a new code point.
+	ExtensionTypeUrmessageJoinSeal ExtensionType = 0xF004
 )
 
 // Extension is one entry of an extensions vector: a registry code point and an
```

`mls/validate_commit.go`:

```diff
--- a/mls/validate_commit.go
+++ b/mls/validate_commit.go
@@ -195,6 +195,7 @@ var groupExtensionProfile = map[ExtensionType]error{
 	ExtensionTypeUrmessageGroupPolicy:    nil,
 	ExtensionTypeUrmessageLeafKeys:       errProfileGroupExtension,
 	ExtensionTypeUrmessageOwnerSuccessor: nil,
+	ExtensionTypeUrmessageJoinSeal:       errProfileGroupExtension,
 }
 
 // checkGroupExtension is the one refusal surface for a group context extension type, standing in
```

`mls/group.go`:

```diff
--- a/mls/group.go
+++ b/mls/group.go
@@ -723,6 +723,7 @@ func v1Capabilities() Capabilities {
 			ExtensionTypeUrmessageGroupPolicy,
 			ExtensionTypeUrmessageLeafKeys,
 			ExtensionTypeUrmessageOwnerSuccessor,
+			ExtensionTypeUrmessageJoinSeal,
 		},
 		Proposals:   []ProposalType{},
 		Credentials: []CredentialType{CredentialTypeBasic},
```

`messagegroup/engine.go`:

```diff
--- a/messagegroup/engine.go
+++ b/messagegroup/engine.go
@@ -968,6 +968,7 @@ func engineCapabilities() mls.Capabilities {
 		Extensions: []mls.ExtensionType{
 			mls.ExtensionTypeUrmessageGroupPolicy,
 			mls.ExtensionTypeUrmessageLeafKeys,
+			mls.ExtensionTypeUrmessageJoinSeal,
 		},
 		Proposals:   []mls.ProposalType{},
 		Credentials: []mls.CredentialType{mls.CredentialTypeBasic},
@@ -981,6 +982,7 @@ func engineRequiredCapabilities() mls.RequiredCapabilities {
 		ExtensionTypes: []mls.ExtensionType{
 			mls.ExtensionTypeUrmessageGroupPolicy,
 			mls.ExtensionTypeUrmessageLeafKeys,
+			mls.ExtensionTypeUrmessageJoinSeal,
 		},
 	}
 }
```

`sdk/urmessage/device.go`:

```diff
--- a/sdk/urmessage/device.go
+++ b/sdk/urmessage/device.go
@@ -729,7 +729,20 @@ func (self *Device) rebindAll() error {
 //
 // IT IS SINGLE USE AND THE STORE ENFORCES THAT: the private halves are taken destructively at the
 // join, so two joins off one published package is not something this device can do.
+//
+// A DEVICE WITH NO X-WING SEED PUBLISHES NO JOIN CODE. Every join code this build mints lists the
+// join seal capability, and that is a promise: seal the join secrets to my leaf's X-Wing key and I
+// will open them. A store written before the seed was kept restores without one
+// ([DurableStateStore.GetDeviceIdentity]), and a join code from that device would be a promise it
+// cannot keep: every add of it would leave a leaf in somebody's group that nobody can hand a
+// working invite to. It is refused here, by the name the missing seed already has.
 func (self *Device) KeyPackage() ([]byte, error) {
+	self.mutex.Lock()
+	seedless := len(self.wrapSeed) == 0
+	self.mutex.Unlock()
+	if seedless {
+		return nil, fmt.Errorf("%w, and so it publishes no join code: an invite to one is sealed to that leaf", ErrNoDeviceWrapKey)
+	}
 	keyPackage, err := self.engine.NewKeyPackage()
 	if err != nil {
 		return nil, fmt.Errorf("urmessage: this device's key package: %w", err)
```

- [ ] **Step 4: regenerate the seed corpus.** The fuzz corpus is generated from the registry, so two `mls` gates (`TestTheCommittedSeedCorpusIsExactlyTheGeneratedCorpus`, `TestTheCommittedSeedCorpusCoversEveryRegistryCodePoint`) fail until it is regenerated. Measured: 176 files change, all under `mls/testdata/corpus/` (135 in `FuzzGroupContextRoundTrip`, 35 in `FuzzRatchetTreeDecode`, 6 in `FuzzUpdatePathDecode`); the file count per target does not change. They are not printed here: the first command writes them.

```bash
URMSG_MLS_WRITE_CORPUS=1 go test -count=1 -run 'TestTheCommittedSeedCorpusIsExactlyTheGeneratedCorpus' ./mls/
go test -count=1 -run 'TestTheCommittedSeedCorpus' ./mls/
```

The first run rewrites the corpus and itself reports FAIL; the second is `ok`.

- [ ] **Step 5: the gates this moves.** One fixture in the sdk spells "the engine's capability list" by hand, and a group now requires the new one; and the wrap-seed census gains the read `KeyPackage()` makes of the seed.

`sdk/urmessage/rolesingest_test.go`:

```diff
--- a/sdk/urmessage/rolesingest_test.go
+++ b/sdk/urmessage/rolesingest_test.go
@@ -898,6 +898,7 @@ func keylessKeyPackage(t *testing.T, dev *crossProcessDevice) []byte {
 		Extensions: []mls.ExtensionType{
 			mls.ExtensionTypeUrmessageGroupPolicy,
 			mls.ExtensionTypeUrmessageLeafKeys,
+			mls.ExtensionTypeUrmessageJoinSeal,
 		},
 		Proposals:   []mls.ProposalType{},
 		Credentials: []mls.CredentialType{mls.CredentialTypeBasic},
```

`sdk/urmessage/wrapseedgate_test.go`:

```diff
--- a/sdk/urmessage/wrapseedgate_test.go
+++ b/sdk/urmessage/wrapseedgate_test.go
@@ -152,6 +152,9 @@ var wrapSeedProducerSites = map[string]string{
 		"function whose loop touches the seed's own array one part at a time.",
 	"DecapsulateToOwnLeaf|self.wrapSeed": "the field read, under [Device.mutex], on the one path " +
 		"that uses the seed for what it is for.",
+	"KeyPackage|self.wrapSeed": "the field read, under the same mutex, by the door that publishes " +
+		"a join code, and only for its LENGTH: a device that holds no seed publishes none. Nothing " +
+		"of the seed leaves the comparison.",
 	"openWrapToOwnLeaf|self.wrapSeed": "the field read, under the same mutex, on the SECOND path " +
 		"that uses it for what it is for: opening a device wrap addressed to this leaf, which is " +
 		"ledger item 243's receive leg. Two paths and not one because the wrap door needs the " +
@@ -510,6 +513,10 @@ var wrapSeedCountedNotCarriedSites = map[string]string{
 	"DecapsulateToOwnLeaf|len self.wrapSeed": "the EMPTY-seed guard, which is a store written " +
 		"before the seed was retained or a device that has been Closed. It refuses by name " +
 		"([ErrNoDeviceWrapKey]) rather than expanding zero octets into a valid-looking key.",
+	"KeyPackage|len self.wrapSeed": "the SAME empty-seed guard on the door that publishes a join " +
+		"code. A join code lists the join seal capability, which asks for an invite sealed to this " +
+		"leaf's X-Wing key, so a device holding no seed for that key publishes none. It refuses by " +
+		"the same name, and what is read is the seed's length and never the seed.",
 	"openWrapToOwnLeaf|len self.wrapSeed": "the SAME empty-seed guard on the wrap door, and it is " +
 		"a site of its own rather than a shared one because this census keys on the enclosing " +
 		"function: a door that stopped making the check would leave the other door's entry still " +
```

- [ ] **Step 6: run it and see it pass.**

```bash
go test -count=1 ./mls/ ./messagegroup/
go -C sdk test -count=1 ./...
go -C sdk/cp3b test -count=1 ./...
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run): The whole root module with `mls` was run on this commit. `MJ63` is the one mutant of this plan whose kill is in `./mls/`: run that package for it.

```
messagegroup   exit=0 pass=362 fail=0
sdk            exit=0 pass=322 fail=0
cp3b           exit=0 pass=114 fail=0
advsim-strict  exit=1 pass=17 fail=9
root with mls  exit=0 pass=2525 fail=0
```

- [ ] **Step 7: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ63`: the profile row for 0xF004 removed: the join seal's code point is no longer refused as a group-context extension. Property 1 must fail. Measured: killed by `TestTheV1ProfileClassifiesEveryRegisteredExtensionTypeAsAGroupContextExtension`.
2. `MJ50`: a group this build founds does not require the join seal of its members. Property 2 must fail. Measured: killed by `TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt`, and 140 other tests.
3. `MJ64`: no leaf this build makes lists the capability its own groups require. Property 2 must fail. Measured: killed by `TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt`, and 314 other tests.
4. `MJ18`: a device with no X-Wing seed publishes a join code it can never open an invitation for. Property 3 must fail. Measured: killed by `TestADeviceWithNoWrapSeedPublishesNoJoinCode`.

- [ ] **Step 8: commit.**

```bash
git add mls/extension_test.go messagegroup/enginejoinseal_test.go sdk/urmessage/devicewrapkey_test.go mls/extension.go mls/validate_commit.go mls/group.go messagegroup/engine.go sdk/urmessage/device.go sdk/urmessage/rolesingest_test.go sdk/urmessage/wrapseedgate_test.go mls/testdata/corpus/
git commit -m "mls, messagegroup, urmessage: the join seal capability 0xF004, listed by every leaf and required by every group"
```

That `git add` names every file of the lab's commit: 186 in all, 176 of them under `mls/testdata/corpus/`.

The first form of this task listed a third mutation, "remove the constant and keep its row",
which is a build failure and not a rejected design. The final check ran the two real ones and both
were killed by gates that were already there; they are `MJ63` and `MJ64` above, run again here.
The first form's `git add` also left out the regenerated corpus, so the commit it made lacked 176
of this commit's files while the working tree passed; the line above names the directory.

### Task 43: The formats: the payload, the preimage and the digest a joiner recomputes

- Consumes: `messagegroup.StorageRoot`, `message.EpochKeysDigest`, `message.ReadKey`, `message.WriteKey`, `syntax.NewWriter`; the formats block above
- Produces: `joinAuthPreimage`, `encodeJoinSecrets`, `decodeJoinSecrets`, `epochKeysDigestOver`, `sameDigest`, `joinerLeafId`, `joinAuthInviteVersion`, `ErrJoinSealUnreadable`, and the join seal's constants

**Behaviour.** Pure functions and constants, with no caller yet. `join_secrets_v1` is three
32-octet values in one order; an opener refuses any other length and an all-zero secret. The
preimage is 181 octets, written out in the test field by field and pinned by its SHA-256.

**The preimage names its invite version by a constant of its own**, `joinAuthInviteVersion =
0x0003`, and does not read the codec's `InviteVersion` (the grounding review's first finding,
measured: read off the codec, the preimage carried `00 02` until the flip and this task's test
failed for three commits). The flip holds the two equal.

**Property 1.** The `join_auth` preimage for fixed inputs is exactly the 181 octets written out in the test, whose SHA-256 is pinned beside them.

**Property 2.** `join_secrets_v1` is three 32-octet values in one order, and nothing else opens: another length and an all-zero secret are refused.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/joinseal_test.go` (new file, 87 lines):

```go
package urmessage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// THE JOIN SEAL'S FORMATS, as octets a second implementation can check, and the seal itself from
// the task that makes it on.

// THE PREIMAGE, AS OCTETS A SECOND IMPLEMENTATION CAN CHECK. Every input is fixed, the expected
// preimage is written out field by field here rather than produced by the function under test, and
// its SHA-256 is pinned beside it.
func TestTheJoinAuthPreimageIsThese181Octets(t *testing.T) {
	groupId := bytes.Repeat([]byte{0xA0}, GroupIdBytes)
	welcome := []byte("the welcome")
	ratchetTree := []byte("the ratchet tree")
	joinSeal := []byte("the join seal")
	got, err := joinAuthPreimage(groupId, 7, 3, welcome, ratchetTree, joinSeal)
	if err != nil {
		t.Fatalf("joinAuthPreimage: %v", err)
	}

	hashOf := func(octets []byte) []byte {
		sum := sha256.Sum256(octets)
		return sum[:]
	}
	lengthOf32 := []byte{0x00, 0x00, 0x00, 0x20}
	want := []byte("URmessage/v1/joinauth")
	want = append(want, 0x00, 0x41)                                    // alg_id: HMAC-SHA-256
	want = append(want, 0x00, 0x03)                                    // invite_version
	want = append(append(want, lengthOf32...), groupId...)             // LP(group_id)
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 7)                        // u64(epoch)
	want = append(want, 0, 0, 0, 3)                                    // u32(joiner_leaf)
	want = append(append(want, lengthOf32...), hashOf(welcome)...)     // LP(H(welcome))
	want = append(append(want, lengthOf32...), hashOf(ratchetTree)...) // LP(H(ratchet_tree))
	want = append(append(want, lengthOf32...), hashOf(joinSeal)...)    // LP(H(join_seal))
	if len(want) != 181 {
		t.Fatalf("the preimage written out here is %d octets and the format fixes 181", len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("joinAuthPreimage answered\n %x\nand the format is\n %x", got, want)
	}
	const pinned = "a3e0125abc4ebf9e58b08469a2553db6aa3ef5145a217fe406424f673678dc56"
	if sum := sha256.Sum256(got); hex.EncodeToString(sum[:]) != pinned {
		t.Fatalf("the preimage hashes to %x and %s is pinned", sum, pinned)
	}
}

// join_secrets_v1 is three 32 octet values in one order, and an opener refuses any other length
// and an all-zero secret.
func TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens(t *testing.T) {
	pqSecret := bytes.Repeat([]byte{0x11}, 32)
	groupHandleKey := bytes.Repeat([]byte{0x22}, 32)
	digest := bytes.Repeat([]byte{0x33}, 32)
	payload, err := encodeJoinSecrets(pqSecret, groupHandleKey, digest)
	if err != nil {
		t.Fatalf("encodeJoinSecrets: %v", err)
	}
	if want := append(append(append([]byte{}, pqSecret...), groupHandleKey...), digest...); !bytes.Equal(payload, want) {
		t.Fatalf("join_secrets_v1 is %x, want pq_secret | group_handle_key | epoch_keys_digest", payload)
	}
	gotPq, gotGhk, gotDigest, err := decodeJoinSecrets(payload)
	if err != nil || !bytes.Equal(gotPq, pqSecret) || !bytes.Equal(gotGhk, groupHandleKey) || !bytes.Equal(gotDigest, digest) {
		t.Fatalf("decodeJoinSecrets answered %x %x %x, %v", gotPq, gotGhk, gotDigest, err)
	}
	for _, one := range []struct {
		name    string
		payload []byte
	}{
		{"one octet short", payload[:95]},
		{"one octet long", append(append([]byte{}, payload...), 0x00)},
		{"a bare pq_secret, which is what a device wrap carries", pqSecret},
		{"an all-zero pq_secret", append(make([]byte, 32), payload[32:]...)},
		{"an all-zero group_handle_key", append(append(append([]byte{}, pqSecret...), make([]byte, 32)...), digest...)},
	} {
		if _, _, _, err := decodeJoinSecrets(one.payload); !errors.Is(err, ErrJoinSealUnreadable) {
			t.Errorf("%s answered %v, want ErrJoinSealUnreadable", one.name, err)
		}
	}
	if _, err := encodeJoinSecrets(pqSecret[:31], groupHandleKey, digest); err == nil {
		t.Error("a 31 octet pq_secret was sealed")
	}
}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk test -count=1 ./
exit status 1
--- FAIL: TestThisModulesProductionCryptoImportsAreTheDeclaredOnes (1.03s)
    message_crypto_scope_test.go:293:   cgo/ctest/testdata/loopback_test_world.go [crypto/rand]
    message_crypto_scope_test.go:293:   livepeer/main.go                   [crypto/rand]
    message_crypto_scope_test.go:293:   liveprobe/main.go                  [crypto/rand]
    message_crypto_scope_test.go:293:   message_route.go                   [crypto/sha256 crypto/subtle crypto/tls]
    message_crypto_scope_test.go:293:   message_stream_store.go            [crypto/sha256]
    message_crypto_scope_test.go:293:   urmessage/device.go                [crypto/rand]
    message_crypto_scope_test.go:293:   urmessage/group.go                 [crypto/sha256]
    message_crypto_scope_test.go:293:   urmessage/invite.go                [crypto/sha256]
    message_crypto_scope_test.go:293:   urmessage/pqepoch.go               [crypto/sha256 crypto/subtle]
...
$ go -C sdk test -count=1 -run ^(TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens|TestTheJoinAuthPreimageIsThese181Octets) ./urmessage/
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\joinseal_test.go:22:14: undefined: joinAuthPreimage
urmessage\joinseal_test.go:59:18: undefined: encodeJoinSecrets
urmessage\joinseal_test.go:66:35: undefined: decodeJoinSecrets
urmessage\joinseal_test.go:80:22: undefined: decodeJoinSecrets
urmessage\joinseal_test.go:80:70: undefined: ErrJoinSealUnreadable
urmessage\joinseal_test.go:84:15: undefined: encodeJoinSecrets
```

- [ ] **Step 3: the change.**

`sdk/urmessage/joinseal.go` (new file, 162 lines):

```go
package urmessage

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"

	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/syntax"
)

// THE JOIN SEAL: how the two secrets a joiner needs reach it, since invite version 3.
//
// WHAT IT REPLACES. Until version 3 an [Invite] carried pq_secret and group_handle_key as two
// length-prefixed fields IN THE CLEAR, beside a Welcome whose own protection is classical X25519.
// A recorder of both pasted codes with a later quantum computer therefore read the epoch a member
// joined at, and in a two-person chat that never commits again that epoch is the whole chat. A
// classical observer of one pasted invite recovered group_handle_key, which maps every
// sender_handle to a leaf for the life of the group. Both were measured in sdk/cp3b.
//
// WHAT IT IS. The adder seals the two secrets to the X-Wing key the JOINER'S OWN LEAF publishes,
// through the wrap door every later epoch's delivery already uses, and authenticates the result
// with a MAC only a member of the join epoch can make:
//
//	join_secrets_v1 = pq_secret[e] (32) | group_handle_key (32) | epoch_keys_digest[e] (32)
//	join_seal       = wrap_body over join_secrets_v1, with the envelope
//	                  u8(0x01) | u8(target_type 0x03 JOINER) | u8(payload_type 0x04) | u64(0)
//	                  and target_id = u32(joiner_leaf)                          -- 1,253 octets
//	join_key        = MLS-Exporter("URmessage/v1/joinkey", u32(joiner_leaf), 32)  at epoch e
//	join_auth       = HMAC-SHA-256(join_key, preimage)                          -- 32 octets
//	preimage        = "URmessage/v1/joinauth" | u16(alg_id 0x0041) | u16(invite_version 0x0003)
//	                  | LP(group_id) | u64(e) | u32(joiner_leaf) | LP(H(welcome))
//	                  | LP(H(ratchet_tree)) | LP(H(join_seal))                  -- 181 octets
//
// CONFIDENTIALITY RESTS ON X-WING ALONE. The exporter keys join_auth and nothing else, so breaking
// the classical Welcome yields the MAC key and not the secrets.
//
// THE CONTENT EPOCH IN THE ENVELOPE IS ZERO, A CONSTANT, so the epoch a member joined at is not in
// the clear. The epoch is bound where it cannot be read: join_key is that epoch's exporter, the
// preimage carries it, and the sealed digest is over it.
//
// WHAT join_auth SAYS AND DOES NOT SAY. It says a member of the epoch this Welcome opened made
// this seal for this leaf, this Welcome and this tree. It does not say WHO: a Welcome authenticates
// nobody, and an adder the user did not mean to talk to makes a perfectly valid one (MG-1).
const (
	// The three MASTER section 7 octets of a join seal. The device wrap takes target 0x01 and
	// payloads 0x01 and 0x02 (pqepoch.go); target 0x02 and payload 0x03 are left for the recovery
	// wrap. Like those, these are provisional until MG-7 is ruled.
	wrapTargetTypeJoiner       uint8 = 0x03
	wrapPayloadTypeJoinSecrets uint8 = 0x04

	joinSecretsBytes = messagegroup.PqSecretBytes + groupHandleKeyBytes + sha256.Size
	// envelope | u16(alg_id) | LP(ct_xwing) | LP(aead_ct), the AEAD adding its 16 octet tag
	joinSealBytes = messagegroup.WrapEnvelopeBytes + 2 + 4 + messagegroup.XwingCiphertextSize + 4 + joinSecretsBytes + 16
	joinAuthBytes = sha256.Size

	// HMAC-SHA-256, as MASTER section 7.1 would register it. Proposed, with the code points above.
	joinAuthAlgId uint16 = 0x0041

	// THE INVITE VERSION join_auth IS OVER, AND IT IS THIS FORMAT'S OWN CONSTANT. The preimage
	// names the one invite version these 181 octets belong to, so it is written here and is not
	// read off [InviteVersion]: a build whose invites were at another version would otherwise
	// authenticate a different preimage with nothing saying so. The codec holds the two equal.
	joinAuthInviteVersion uint16 = 0x0003

	joinKeyExporterLabel = "URmessage/v1/joinkey"
	joinKeyBytes         = 32
	joinAuthLabel        = "URmessage/v1/joinauth"

	groupHandleKeyBytes = 32
)

// joinerLeafId is u32(joiner_leaf): the wrap's target_id and the join key's exporter context.
func joinerLeafId(leaf uint32) []byte {
	return []byte{byte(leaf >> 24), byte(leaf >> 16), byte(leaf >> 8), byte(leaf)}
}

// encodeJoinSecrets is join_secrets_v1, exactly 96 octets.
func encodeJoinSecrets(pqSecret []byte, groupHandleKey []byte, epochKeysDigest []byte) ([]byte, error) {
	if len(pqSecret) != messagegroup.PqSecretBytes || len(groupHandleKey) != groupHandleKeyBytes ||
		len(epochKeysDigest) != sha256.Size {
		return nil, fmt.Errorf("urmessage: join_secrets_v1 is three 32 octet values, and these are %d, %d and %d",
			len(pqSecret), len(groupHandleKey), len(epochKeysDigest))
	}
	payload := make([]byte, 0, joinSecretsBytes)
	payload = append(payload, pqSecret...)
	payload = append(payload, groupHandleKey...)
	payload = append(payload, epochKeysDigest...)
	return payload, nil
}

// decodeJoinSecrets cuts an opened payload into its three values, as copies, and refuses any other
// length and an all-zero secret. An all-zero value is not what any adder draws, and it is exactly
// what a buffer that was erased before it was sealed looks like.
func decodeJoinSecrets(payload []byte) (pqSecret []byte, groupHandleKey []byte, epochKeysDigest []byte, err error) {
	if len(payload) != joinSecretsBytes {
		return nil, nil, nil, fmt.Errorf("%w: the seal opened to %d octets and join_secrets_v1 is %d",
			ErrJoinSealUnreadable, len(payload), joinSecretsBytes)
	}
	zero := make([]byte, messagegroup.PqSecretBytes)
	pqSecret = append([]byte(nil), payload[:messagegroup.PqSecretBytes]...)
	groupHandleKey = append([]byte(nil), payload[messagegroup.PqSecretBytes:messagegroup.PqSecretBytes+groupHandleKeyBytes]...)
	epochKeysDigest = append([]byte(nil), payload[messagegroup.PqSecretBytes+groupHandleKeyBytes:]...)
	if subtle.ConstantTimeCompare(pqSecret, zero) == 1 || subtle.ConstantTimeCompare(groupHandleKey, zero) == 1 {
		zeroizeState(pqSecret)
		zeroizeState(groupHandleKey)
		return nil, nil, nil, fmt.Errorf("%w: the seal opened to an all-zero secret", ErrJoinSealUnreadable)
	}
	return pqSecret, groupHandleKey, epochKeysDigest, nil
}

// joinAuthPreimage is the 181 octets join_auth is a MAC over. Every value in it is the CALLER'S
// OWN: an adder passes what it built, and a joiner passes what its own joined group answers and
// the octets it received, never a value read back out of the seal.
func joinAuthPreimage(groupId []byte, epoch uint64, leaf uint32, welcome []byte, ratchetTree []byte,
	joinSeal []byte) ([]byte, error) {

	welcomeHash := sha256.Sum256(welcome)
	treeHash := sha256.Sum256(ratchetTree)
	sealHash := sha256.Sum256(joinSeal)
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte(joinAuthLabel))
	writer.WriteUint16(joinAuthAlgId)
	writer.WriteUint16(joinAuthInviteVersion)
	writer.WriteOpaqueLP(groupId)
	writer.WriteUint64(epoch)
	writer.WriteUint32(leaf)
	writer.WriteOpaqueLP(welcomeHash[:])
	writer.WriteOpaqueLP(treeHash[:])
	writer.WriteOpaqueLP(sealHash[:])
	preimage, err := writer.Bytes()
	if err != nil {
		return nil, fmt.Errorf("urmessage: the join_auth preimage: %w", err)
	}
	return preimage, nil
}

// epochKeysDigestOver is H(epoch_keys) of one epoch as a holder of that epoch's exporter and a
// candidate pq_secret computes it: the storage root, the two server keys off it, and the digest
// the commit that opened the epoch publishes. Every intermediate is erased here.
func epochKeysDigestOver(groupId []byte, epoch uint64, mlsSecret []byte, pqSecret []byte) ([]byte, error) {
	group, err := epochDigestGroupId(groupId)
	if err != nil {
		return nil, err
	}
	root := messagegroup.StorageRoot(mlsSecret, pqSecret)
	writeKey := message.WriteKey(root)
	readKey := message.ReadKey(root)
	zeroizeState(root)
	digest, err := message.EpochKeysDigest(group, epoch, writeKey, readKey)
	zeroizeState(writeKey)
	zeroizeState(readKey)
	return digest, err
}

// sameDigest compares two H(epoch_keys) values, and answers false for one that is absent. The
// values are published, so nothing here is secret; it goes through subtle because every comparison
// of key-derived octets in this package does.
func sameDigest(sealed []byte, published []byte) bool {
	return len(sealed) == sha256.Size && subtle.ConstantTimeCompare(sealed, published) == 1
}
```

`sdk/urmessage/errors.go`:

```diff
--- a/sdk/urmessage/errors.go
+++ b/sdk/urmessage/errors.go
@@ -48,6 +48,14 @@ var (
 	// told, and never at the join or at the first Receive after it.
 	ErrInviteDamaged = errors.New("urmessage: this invite is damaged: it is not the octets the founder encoded")
 
+	// THE REFUSALS OF THE JOIN SEAL INSIDE THE JOIN. Each is made before the joined state reaches
+	// the store, so the store is as it was and the join code is not spent: the honest invite,
+	// pasted again, still joins.
+	//
+	// Unreadable: the seal is authenticated and does not open to this device's leaf key, or opens
+	// to something that is not join_secrets_v1.
+	ErrJoinSealUnreadable = errors.New("urmessage: this invite's join seal does not open to this device")
+
 	// A record came back that a key should have opened and did not.
 	ErrRecordOpen = errors.New("urmessage: a record from a member of this group did not open")
 
```

- [ ] **Step 4: the gates this moves.** The sdk declares every crypto import per file, and the two key-material censuses of `sdk/urmessage` name every site they do not know: each new site has an entry with a reason.

`sdk/message_crypto_scope_test.go`:

```diff
--- a/sdk/message_crypto_scope_test.go
+++ b/sdk/message_crypto_scope_test.go
@@ -77,6 +77,8 @@ var sdkCryptoImports = map[string]sdkCryptoImport{
 		"the device's randomness when the caller hands it none"},
 	"urmessage/group.go": {[]string{"crypto/sha256"},
 		"pq secret witnesses, group-context hashes and a sealed body's hash check"},
+	"urmessage/joinseal.go": {[]string{"crypto/sha256", "crypto/subtle"},
+		"the three hashes join_auth's preimage is over and the width of the sealed digest; and the constant-time comparison of that digest and of an all-zero secret"},
 	"urmessage/invite.go": {[]string{"crypto/sha256"},
 		"an invite's checksum"},
 	"urmessage/pqepoch.go": {[]string{"crypto/sha256", "crypto/subtle"},
```

`sdk/urmessage/pqsecretgate_test.go`:

```diff
--- a/sdk/urmessage/pqsecretgate_test.go
+++ b/sdk/urmessage/pqsecretgate_test.go
@@ -90,6 +90,7 @@ import (
 //     inside the group record's own decode, survived the whole suite while that decode was the
 //     body of a loop and its record had no name a walk could seed.
 var pqSecretProducerNames = map[string]bool{
+	"decodeJoinSecrets":     true,
 	"NewPqSecret":           true,
 	"OpenWrapBody":          true,
 	"openWrapToOwnLeaf":     true,
@@ -124,6 +125,12 @@ type pqSecretSink struct {
 }
 
 var pqSecretProducerSites = map[string]string{
+	"epochKeysDigestOver|parameter pqSecret":   "the candidate a joiner, or the founder, recomputes H(epoch_keys) from.",
+	"encodeJoinSecrets|parameter pqSecret":     "the secret of the epoch an add opens, arriving at the payload's encoder.",
+	"decodeJoinSecrets|result epochKeysDigest": "the last third, which is the PUBLIC digest. It is in this census because the net takes every result of a producer.",
+	"decodeJoinSecrets|result groupHandleKey":  "the second third: the group's handle key, which is secret, and is held to the same dispositions as the secret beside it.",
+	"decodeJoinSecrets|result pqSecret":        "the first third of the payload: the secret of the epoch the joiner is admitted at.",
+	"decodeJoinSecrets|parameter pqSecret":     "the named result the first third of an opened join_secrets_v1 is answered through.",
 	"AddMemberAndPublish|self.pqSecretLocked": "the same read after the rotation has run, so the invite carries pq_secret[n+1] and not " +
 		"the secret the group is standing on.",
 	"AddMember|self.pqSecretLocked": "THE FOUNDING EPOCH'S SECRET READ BACK FOR THE WELCOME. Epoch one's secret travels in " +
@@ -240,6 +247,50 @@ var pqSecretProducerSites = map[string]string{
 }
 
 var pqSecretSinks = map[string]pqSecretSink{
+	"epochKeysDigestOver|return": {
+		carries: []string{"digest"},
+		why:     "H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes. It is not a key.",
+	},
+	"epochKeysDigestOver|call message.EpochKeysDigest": {
+		carries: []string{"readKey", "writeKey"},
+		why:     "the pair, into the digest.",
+	},
+	"epochKeysDigestOver|call zeroizeState": {
+		carries: []string{"readKey", "root", "writeKey"},
+		why:     "the erase of the root and of both keys, before the digest is answered.",
+	},
+	"epochKeysDigestOver|call message.ReadKey": {
+		carries: []string{"root"},
+		why:     "the read key off that root, to be digested.",
+	},
+	"epochKeysDigestOver|call message.WriteKey": {
+		carries: []string{"root"},
+		why:     "the write key off that root, to be digested.",
+	},
+	"epochKeysDigestOver|call messagegroup.StorageRoot": {
+		carries: []string{"pqSecret"},
+		why:     "the storage root of the epoch, from the exporter and the candidate secret.",
+	},
+	"decodeJoinSecrets|return": {
+		carries: []string{"epochKeysDigest", "groupHandleKey", "pqSecret"},
+		why:     "the three values, as copies, to the joiner's half.",
+	},
+	"decodeJoinSecrets|call zeroizeState": {
+		carries: []string{"groupHandleKey", "pqSecret"},
+		why:     "the erase of both copies on that refusal.",
+	},
+	"decodeJoinSecrets|call subtle.ConstantTimeCompare": {
+		carries: []string{"groupHandleKey", "pqSecret"},
+		why:     "the refusal of an all-zero secret, in constant time. It answers an int.",
+	},
+	"encodeJoinSecrets|return": {
+		carries: []string{"payload"},
+		why:     "join_secrets_v1, to its one caller, which seals it and erases it.",
+	},
+	"encodeJoinSecrets|call append": {
+		carries: []string{"payload", "pqSecret"},
+		why:     "the payload's assembly, into a buffer of exactly its length.",
+	},
 	"AddMemberAndPublish|call append": {
 		carries: []string{"self.pqSecretLocked"},
 		why:     "the same copy after the rotation.",
@@ -973,6 +1024,7 @@ var pqSecretSinks = map[string]pqSecretSink{
 }
 
 var pqSecretCountedNotCarriedSites = map[string]string{
+	"encodeJoinSecrets|len pqSecret":     "the encoder's width check and its refusal text: three 32 octet values or nothing.",
 	"PutGroupRecord|len record.PqSecret": "the durable writer's 'this record carries neither' refusal.",
 	"PutGroupRecord|len rows":            "the arity of the table about to be written.",
 	"check|len self.PqSecret":            "the invite's own emptiness check, and its refusal text.",
```

`sdk/urmessage/epochkeygate_test.go`:

```diff
--- a/sdk/urmessage/epochkeygate_test.go
+++ b/sdk/urmessage/epochkeygate_test.go
@@ -87,6 +87,8 @@ var epochKeyProducerSelectors = map[string]bool{
 // carry it. Measured: green, with the census printing `publishCommitLocked|message.WriteKey`, the
 // EpochAttachment.WriteKey literal and the epochKeysFor call, all three unchanged.
 var epochKeyProducerSites = map[string]string{
+	"epochKeysDigestOver|message.ReadKey":  "the read key of the same epoch, for the same digest.",
+	"epochKeysDigestOver|message.WriteKey": "the write key of the epoch a join seal is judged at, derived only to be digested and erased before the function answers.",
 	"Open|keys.WriteKey":                   "epoch 1's write key, off the session the founding commit opens",
 	"Open|keys.ReadKey":                    "epoch 1's read key, the same",
 	"Open|bootstrap.WriteKey":              "write_key[0], §4.3.2's bootstrap key, which certifies the founding commit and is NOT what it opens",
@@ -132,6 +134,18 @@ type epochKeySink struct {
 // measurement that says why they cannot move yet -- and because the map is held BOTH ways, the day
 // they do move this file goes red until somebody deletes the entry and the sentence with it.
 var epochKeySinks = map[string]epochKeySink{
+	"epochKeysDigestOver|return": {
+		carries: []string{"digest"},
+		why:     "H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes. It is not a key.",
+	},
+	"epochKeysDigestOver|call zeroizeState": {
+		carries: []string{"readKey", "writeKey"},
+		why:     "the erase of both, before the digest is answered.",
+	},
+	"epochKeysDigestOver|call message.EpochKeysDigest": {
+		carries: []string{"readKey", "writeKey"},
+		why:     "the pair, into the digest. What comes back is the digest and neither key.",
+	},
 	"Open|call epochKeysFor": {
 		carries: []string{"founding", "readKey", "writeKey"},
 		why: "RULING 33's ROAD, and the DECISION that gates it. epochKeysFor " +
```

- [ ] **Step 5: run it and see it pass.**

```bash
go -C sdk test -count=1 ./...
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run):

```
sdk            exit=0 pass=324 fail=0
advsim-strict  exit=1 pass=17 fail=9
```

- [ ] **Step 6: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ6`: the preimage does not cover the seal. Property 1 must fail. Measured: killed by `TestTheJoinAuthPreimageIsThese181Octets`, and 5 other tests.
2. `MJ7`: the preimage does not carry the epoch. Property 1 must fail. Measured: killed by `TestTheJoinAuthPreimageIsThese181Octets`, and 1 other test.
3. `MJ14`: the payload's length is not held to exactly 96. Property 2 must fail. Measured: killed by `TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens`.
4. `MJ14b`: an all-zero secret is accepted. Property 2 must fail. Measured: killed by `TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens`, and 1 other test.

- [ ] **Step 7: commit.**

```bash
git add sdk/urmessage/joinseal_test.go sdk/urmessage/joinseal.go sdk/urmessage/errors.go sdk/message_crypto_scope_test.go sdk/urmessage/pqsecretgate_test.go sdk/urmessage/epochkeygate_test.go
git commit -m "urmessage: join_secrets_v1, the join_auth preimage and the digest a joiner recomputes"
```

### Task 44: The key schedule: the epoch's digest is built ahead of the wraps, and a hook runs before anything is submitted

- Consumes: `Group.publishCommitLocked`, `stageEpochRotationLocked`, `submitLocked`; the fake server of `sdk/urmessage`'s tests
- Produces: the `beforeSubmit` parameter of `publishCommitLocked`

**Behaviour.** A live add rotates `pq_secret`, and the rotated value cannot reach a leaf that
does not exist yet through a wrap. So `publishCommitLocked` gains a `beforeSubmit` hook, called
once the epoch is fully decided and before any submit, and it is handed the rotated secret and the
digest the commit record is about to carry. The digest moves above the wraps so that one value
serves the hook and the record. A hook that refuses clears the staged commit. This task passes
`nil` at every call site: behaviour is unchanged.

**Two tests, because the source gate cannot see everything** (the security review, measured: a
fan-out moved ahead of the hook inside a helper passes a gate that counts the calls it can see in
one function body). The first reads the order off the source. The second injects a hook that
refuses, against a fake server that has answered a Hello and counts frames, and reads what a
refusal does: nothing was sent, nothing is staged, the epoch did not move, and the same commit
can be staged again.

**Property 1.** In `publishCommitLocked` the hook is called exactly once, before every submit and before the merge.

**Property 2.** A hook that refuses leaves nothing staged and nothing sent: the server saw no request of the epoch, the epoch did not move, and the same join code can be staged again.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/joinseal_test.go`:

```diff
--- a/sdk/urmessage/joinseal_test.go
+++ b/sdk/urmessage/joinseal_test.go
@@ -2,10 +2,21 @@ package urmessage
 
 import (
 	"bytes"
+	"context"
 	"crypto/sha256"
 	"encoding/hex"
 	"errors"
+	"go/ast"
+	"go/parser"
+	"go/token"
+	"sync/atomic"
 	"testing"
+	"time"
+
+	"github.com/urnetwork/connect"
+	connectprotocol "github.com/urnetwork/connect/protocol"
+	messageprotocol "github.com/urnetwork/message/protocol"
+	"github.com/urnetwork/message/sdk"
 )
 
 // THE JOIN SEAL'S FORMATS, as octets a second implementation can check, and the seal itself from
@@ -85,3 +96,172 @@ func TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens(t *testing.T) {
 		t.Error("a 31 octet pq_secret was sealed")
 	}
 }
+
+// THE SEAL IS MADE BEFORE ANYTHING OF THE EPOCH IS SUBMITTED, read off the source of
+// publishCommitLocked: the one call of beforeSubmit stands above every submitLocked and above
+// MergePendingCommit. A seal made after a submit is an epoch the server has taken and an invite
+// nobody was handed, which no behaviour of a run in which the seal succeeds can show.
+func TestTheJoinSealIsMadeBeforeAnythingOfTheEpochIsSubmitted(t *testing.T) {
+	files := token.NewFileSet()
+	parsed, err := parser.ParseFile(files, "group.go", nil, 0)
+	if err != nil {
+		t.Fatalf("parsing group.go: %v", err)
+	}
+	hook, later := []token.Pos{}, []token.Pos{}
+	found := false
+	for _, declaration := range parsed.Decls {
+		function, isFunction := declaration.(*ast.FuncDecl)
+		if !isFunction || function.Name.Name != "publishCommitLocked" {
+			continue
+		}
+		found = true
+		ast.Inspect(function.Body, func(node ast.Node) bool {
+			call, isCall := node.(*ast.CallExpr)
+			if !isCall {
+				return true
+			}
+			switch callee := call.Fun.(type) {
+			case *ast.Ident:
+				if callee.Name == "beforeSubmit" {
+					hook = append(hook, call.Pos())
+				}
+			case *ast.SelectorExpr:
+				if callee.Sel.Name == "submitLocked" || callee.Sel.Name == "MergePendingCommit" {
+					later = append(later, call.Pos())
+				}
+			}
+			return true
+		})
+	}
+	if !found || len(hook) != 1 || len(later) < 3 {
+		t.Fatalf("publishCommitLocked found %v, with %d call(s) of beforeSubmit and %d submit or merge call(s); this gate reads one and at least three", found, len(hook), len(later))
+	}
+	for _, position := range later {
+		if position < hook[0] {
+			t.Errorf("%s submits or merges ahead of the join seal's hook at %s", files.Position(position), files.Position(hook[0]))
+		}
+	}
+}
+
+// frameCounter is an [answeringClient] that also counts every frame of a request it is handed,
+// WHOLE OR IN FRAGMENTS. A request too large for one frame is cut into fragment frames, which the
+// fake under it neither answers nor counts, and an epoch wrap is one of those.
+type frameCounter struct {
+	*answeringClient
+	frames atomic.Int64
+}
+
+func (self *frameCounter) SendWithTimeout(frame *connectprotocol.Frame, destination connect.Id,
+	ackCallback connect.AckFunction, timeout time.Duration, opts ...any) bool {
+
+	switch frame.GetMessageType() {
+	case connectprotocol.MessageType_MessageMessageServerRequest, connectprotocol.MessageType_MessageMessageServerFragment:
+		self.frames.Add(1)
+	}
+	return self.answeringClient.SendWithTimeout(frame, destination, ackCallback, timeout, opts...)
+}
+
+// A HOOK THAT REFUSES LEAVES NOTHING STAGED AND NOTHING SENT. The hook is where a live add seals
+// the join secrets, so its refusal is a seal that could not be made. The commit is staged through
+// the real seam, publishCommitLocked is handed a hook that refuses, and four things are read: the
+// server was sent no request, the staged commit was erased, the epoch did not move, and the SAME
+// join code can be staged again.
+//
+// THE SERVER IS A FAKE THAT HAS ANSWERED A HELLO AND THAT COUNTS FRAMES, and both halves are
+// load-bearing. The transport sends no submit before a Hello has issued its nonce, and a wrap is
+// too large for one frame and goes out as fragments; a count that missed either would be zero
+// whatever the hook did. Both were measured on the way to this test, and the control at the end
+// is what says this count can be other than zero.
+//
+// THE SOURCE GATE ABOVE READS WHERE THE HOOK STANDS; THIS READS WHAT A REFUSAL DOES. A fan-out
+// moved ahead of the hook inside a helper passes the gate, which counts the calls it can see in
+// one function body, and is counted here as a request the server was sent.
+//
+// WHAT WOULD GO RED: return the hook's error without ClearPendingCommit, and the second staging is
+// refused over the first; submit the epoch's wraps before the hook, by any route, and the server's
+// count moves.
+func TestAHookThatRefusesLeavesNothingStagedAndNothingSent(t *testing.T) {
+	ctx := context.Background()
+	world := newRoleWorld(t, "owner", "bob")
+	owner := world.member("owner")
+	server := &frameCounter{answeringClient: &answeringClient{
+		reason: messageprotocol.Reason_REASON_OK, nonce: []byte("the nonce of the transport under test"),
+	}}
+	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
+		Client:          server,
+		Server:          connect.NewId(),
+		ProtocolVersion: 1,
+	})
+	if err != nil {
+		t.Fatalf("sdk.NewMessageTransport: %v", err)
+	}
+	t.Cleanup(transport.Close)
+	streamStore, err := sdk.OpenStreamStore(t.TempDir())
+	if err != nil {
+		t.Fatalf("sdk.OpenStreamStore: %v", err)
+	}
+	t.Cleanup(func() { streamStore.Close() })
+	connected, err := NewDevice(DeviceConfig{Transport: transport, Reserver: sdk.NewStreamIndexReserver(streamStore)})
+	if err != nil {
+		t.Fatalf("NewDevice: %v", err)
+	}
+	t.Cleanup(func() { connected.Close() })
+	if err := connected.Connect(ctx); err != nil {
+		t.Fatalf("the Hello of the transport under test: %v", err)
+	}
+	owner.group.device.transport = transport
+	before := server.frames.Load()
+
+	joiner, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("the joiner's nonce"))
+	joinCode, err := joiner.KeyPackage()
+	if err != nil {
+		t.Fatalf("the joiner's KeyPackage: %v", err)
+	}
+	wrapped := &pendingFailingHandle{GroupHandle: owner.handle}
+	owner.group.handle = wrapped
+	defer func() { owner.group.handle = owner.handle }()
+	commit, _, _, err := owner.handle.CommitAdd([][]byte{joinCode})
+	if err != nil {
+		t.Fatalf("staging the add: %v", err)
+	}
+
+	injected := errors.New("the join seal could not be made")
+	called := 0
+	err = owner.group.publishCommitLocked(ctx, commit, func(opensEpoch uint64, pqSecret []byte, epochKeysDigest []byte) error {
+		called += 1
+		if opensEpoch != 2 || len(pqSecret) != 32 || len(epochKeysDigest) != sha256.Size {
+			t.Errorf("the hook was handed epoch %d, a %d octet secret and a %d octet digest, want 2, 32 and 32",
+				opensEpoch, len(pqSecret), len(epochKeysDigest))
+		}
+		return injected
+	})
+	if !errors.Is(err, injected) || called != 1 {
+		t.Fatalf("publishCommitLocked answered %v after calling the hook %d time(s), want the hook's own refusal after one call", err, called)
+	}
+	if sent := server.frames.Load() - before; sent != 0 {
+		t.Errorf("the server was sent %d frame(s) of an epoch whose join seal could not be made", sent)
+	}
+	if wrapped.cleared != 1 {
+		t.Errorf("the refusal called ClearPendingCommit %d time(s), want 1: the staged commit was left behind", wrapped.cleared)
+	}
+	if owner.handle.Epoch() != 1 || owner.group.Epoch() != 1 {
+		t.Errorf("the owner's handle is at epoch %d and its group at %d after the refusal, want 1 and 1", owner.handle.Epoch(), owner.group.Epoch())
+	}
+	// THE CONTROL, AND IT FIRES FOR ITS OWN REASON. The same join code is staged again, which the
+	// seam refuses over a value left staged; and published with a hook that does NOT refuse, it
+	// reaches the server. So the zero above is a refusal that came before the first submit, and
+	// not a transport that sends nothing.
+	commit, _, _, err = owner.handle.CommitAdd([][]byte{joinCode})
+	if err != nil {
+		t.Fatalf("the seam refused to stage the same add again after the refusal: %v", err)
+	}
+	brief, cancel := context.WithTimeout(ctx, 2*time.Second)
+	defer cancel()
+	err = owner.group.publishCommitLocked(brief, commit, func(uint64, []byte, []byte) error { return nil })
+	if err == nil {
+		t.Fatalf("CONTROL FAILED: a publish to a fake that answers no submit answered nil")
+	}
+	if sent := server.frames.Load() - before; sent == 0 {
+		t.Fatalf("CONTROL FAILED: a publish whose hook did not refuse sent the server no frame (%v), so the zero above proves nothing", err)
+	}
+}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk test -count=1 -run ^(TestAHookThatRefusesLeavesNothingStagedAndNothingSent|TestTheJoinSealIsMadeBeforeAnythingOfTheEpochIsSubmitted) ./urmessage/
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\joinseal_test.go:230:53: too many arguments in call to owner.group.publishCommitLocked
urmessage\joinseal_test.go:260:55: too many arguments in call to owner.group.publishCommitLocked
urmessage\rolescommit_test.go:915:53: too many arguments in call to owner.group.publishCommitLocked
```

- [ ] **Step 3: the change.**

`sdk/urmessage/group.go`:

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1907,7 +1907,7 @@ func (self *Group) AddMemberAndPublish(ctx context.Context, keyPackage []byte) (
 	// (2)-(5) announce, submit, and -- once the server has taken it -- merge, enter and fan out
 	// the epoch the commit opens. A refusal erases the staged epoch and answers here with nothing
 	// moved; the key package is the joiner's and a retry after Receive may offer it again.
-	if err := self.publishCommitLocked(ctx, commit); err != nil {
+	if err := self.publishCommitLocked(ctx, commit, nil); err != nil {
 		return nil, err
 	}
 
@@ -2057,7 +2057,15 @@ func (self *Group) streamFloorRefusalLocked() error {
 // is granted to it, and that its own table never gains the removed-from epoch's row. The exclusion
 // it drives is this method's derivation and no argument of the case's own, which is what makes it
 // a property of the code rather than of the fixture.
-func (self *Group) publishCommitLocked(ctx context.Context, commit []byte) error {
+//
+// beforeSubmit, WHEN IT IS NOT NIL, RUNS ONCE THE EPOCH IS FULLY DECIDED AND BEFORE ANYTHING OF IT
+// IS ON THE WIRE: after the rotation is staged and the digest the commit record will carry is
+// built, and ahead of the first wrap. It is handed the epoch the commit opens, that epoch's
+// pq_secret and that digest's H(epoch_keys). It is how [Group.AddMemberAndPublish] seals the join
+// secrets over exactly what is about to be published, and a refusal from it erases the staged
+// commit like every other exit above the submit.
+func (self *Group) publishCommitLocked(ctx context.Context, commit []byte,
+	beforeSubmit func(opensEpoch uint64, pqSecret []byte, epochKeysDigest []byte) error) error {
 	// (2) the facts of the epoch the staged commit opens, off the staged value: the epoch, the
 	// member count the fan-out will wrap to, the group context the server keys the epoch under,
 	// and the NEW epoch's write and read keys, derived STRAIGHT OFF the staged exporter -- the
@@ -2139,6 +2147,32 @@ func (self *Group) publishCommitLocked(ctx context.Context, commit []byte) error
 	zeroizeState(newRoot)
 	contextHash := sha256.Sum256(pending.GroupContext)
 
+	// (2b') THE DIGEST THE COMMIT RECORD WILL CARRY, BUILT HERE, AHEAD OF THE WRAPS. It reads only
+	// the staged keys, the epoch and the target count, so nothing about it waits for a submit; it
+	// stands above them so that beforeSubmit is handed the value the record below carries, and
+	// the join seal and the commit cannot come to name two digests.
+	group, err := epochDigestGroupId(self.id)
+	if err != nil {
+		self.handle.ClearPendingCommit()
+		return err
+	}
+	commitDigest, err := message.NewEpochDigestAttachment(group, message.EpochDigestAttachment{
+		Epoch:             newEpoch,
+		AlgId:             epochAttachmentAlgId,
+		GroupContextHash:  contextHash[:],
+		ExpectedWrapCount: uint32(len(targets)),
+	}, writeKey, readKey)
+	if err != nil {
+		self.handle.ClearPendingCommit()
+		return fmt.Errorf("urmessage: the digest of the keys epoch %d opens with: %w", newEpoch, err)
+	}
+	if beforeSubmit != nil {
+		if err := beforeSubmit(newEpoch, pqNext, commitDigest.EpochKeysDigest); err != nil {
+			self.handle.ClearPendingCommit()
+			return err
+		}
+	}
+
 	// (2c) RULING 37's WRAPS: SEALED AND SUBMITTED HERE, PRE-MERGE, AT EPOCH n -- AND AHEAD OF THE
 	// COMMIT RECORD.
 	//
@@ -2165,22 +2199,8 @@ func (self *Group) publishCommitLocked(ctx context.Context, commit []byte) error
 
 	// (3) the commit record, sealed at the OLD epoch by self.session -- which is the epoch the
 	// handle is still at -- announcing the new epoch. The server takes it iff its header names
-	// the current epoch and its attachment opens the next.
-	group, err := epochDigestGroupId(self.id)
-	if err != nil {
-		self.handle.ClearPendingCommit()
-		return err
-	}
-	commitDigest, err := message.NewEpochDigestAttachment(group, message.EpochDigestAttachment{
-		Epoch:             newEpoch,
-		AlgId:             epochAttachmentAlgId,
-		GroupContextHash:  contextHash[:],
-		ExpectedWrapCount: uint32(len(targets)),
-	}, writeKey, readKey)
-	if err != nil {
-		self.handle.ClearPendingCommit()
-		return fmt.Errorf("urmessage: the digest of the keys epoch %d opens with: %w", newEpoch, err)
-	}
+	// the current epoch and its attachment opens the next. The attachment is the digest built at
+	// (2b') above.
 	commitRecord, err := self.session.SealRecord(message.RetentionPermanent, 0, true,
 		encodeHead(self.device.nowMs()), commit, 0, &message.ServerAttachment{
 			Kind:        message.AttachmentEpochDigest,
```

`sdk/urmessage/rolescommit.go`:

```diff
--- a/sdk/urmessage/rolescommit.go
+++ b/sdk/urmessage/rolescommit.go
@@ -604,7 +604,7 @@ func (self *Group) RemoveMember(ctx context.Context, identityPub []byte) error {
 	if err != nil {
 		return fmt.Errorf("urmessage: CommitRemoveWithExtensions: %w", err)
 	}
-	return self.publishCommitLocked(ctx, commit)
+	return self.publishCommitLocked(ctx, commit, nil)
 }
 
 // editablePolicyLocked is the live policy as a value the verbs may write into: freshly decoded off
@@ -656,5 +656,5 @@ func (self *Group) commitPolicyAndPublishLocked(ctx context.Context, policy []by
 	if err != nil {
 		return fmt.Errorf("urmessage: CommitPolicy: %w", err)
 	}
-	return self.publishCommitLocked(ctx, commit)
+	return self.publishCommitLocked(ctx, commit, nil)
 }
```

- [ ] **Step 4: the gates this moves.** The other callers pass `nil`, one of them in a test; and both censuses see the hook.

`sdk/urmessage/rolescommit_test.go`:

```diff
--- a/sdk/urmessage/rolescommit_test.go
+++ b/sdk/urmessage/rolescommit_test.go
@@ -912,7 +912,7 @@ func TestPublishCommitLockedsFirstExitErasesTheStagedEpoch(t *testing.T) {
 	if err != nil {
 		t.Fatalf("staging the promotion: %v", err)
 	}
-	err = owner.group.publishCommitLocked(ctx, commit)
+	err = owner.group.publishCommitLocked(ctx, commit, nil)
 	if !errors.Is(err, injected) {
 		t.Fatalf("publishCommitLocked answered %v, want the injected PendingEpoch error", err)
 	}
```

`sdk/urmessage/pqsecretgate_test.go`:

```diff
--- a/sdk/urmessage/pqsecretgate_test.go
+++ b/sdk/urmessage/pqsecretgate_test.go
@@ -247,6 +247,10 @@ var pqSecretProducerSites = map[string]string{
 }
 
 var pqSecretSinks = map[string]pqSecretSink{
+	"publishCommitLocked|call beforeSubmit": {
+		carries: []string{"commitDigest", "pqNext"},
+		why:     "THE JOIN SEAL'S HOOK: the rotated secret of the epoch this commit opens, to the closure that seals it to the joiner, before anything of the epoch is submitted. It is the only way that secret can reach a leaf that does not exist yet.",
+	},
 	"epochKeysDigestOver|return": {
 		carries: []string{"digest"},
 		why:     "H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes. It is not a key.",
```

`sdk/urmessage/epochkeygate_test.go`:

```diff
--- a/sdk/urmessage/epochkeygate_test.go
+++ b/sdk/urmessage/epochkeygate_test.go
@@ -134,6 +134,10 @@ type epochKeySink struct {
 // measurement that says why they cannot move yet -- and because the map is held BOTH ways, the day
 // they do move this file goes red until somebody deletes the entry and the sentence with it.
 var epochKeySinks = map[string]epochKeySink{
+	"publishCommitLocked|call beforeSubmit": {
+		carries: []string{"commitDigest"},
+		why:     "THE JOIN SEAL'S HOOK. It is handed the digest the commit record below carries, so that a seal and its commit cannot come to name two digests. H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes.",
+	},
 	"epochKeysDigestOver|return": {
 		carries: []string{"digest"},
 		why:     "H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes. It is not a key.",
```

- [ ] **Step 5: run it and see it pass.**

```bash
go -C sdk test -count=1 ./...
go -C sdk/cp3b test -count=1 ./...
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run):

```
sdk            exit=0 pass=326 fail=0
cp3b           exit=0 pass=114 fail=0
advsim-strict  exit=1 pass=17 fail=9
```

- [ ] **Step 6: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ32`: the seal is made after the epoch's wraps were submitted. Property 1 must fail. Measured: killed by `TestTheJoinSealIsMadeBeforeAnythingOfTheEpochIsSubmitted`, and 1 other test.
2. `MJ32b`: the epoch's wraps submitted ahead of the hook from inside a helper, where the source gate does not look. Property 2 must fail. Measured: killed by `TestAHookThatRefusesLeavesNothingStagedAndNothingSent`.
3. `MJ32c`: a hook that refuses leaves the commit it was called for staged. Property 2 must fail. Measured: killed by `TestAHookThatRefusesLeavesNothingStagedAndNothingSent`.

- [ ] **Step 7: commit.**

```bash
git add sdk/urmessage/joinseal_test.go sdk/urmessage/group.go sdk/urmessage/rolescommit.go sdk/urmessage/rolescommit_test.go sdk/urmessage/pqsecretgate_test.go sdk/urmessage/epochkeygate_test.go
git commit -m "urmessage: the epoch digest is built ahead of the wraps, and a hook runs before anything is submitted"
```

### Task 45: The adder judges a join code before it stages anything, and names the remedy for a leaf that stands

- Consumes: the capability (Task 42); `mls.KeyPackage.Validate`, `mls.LeafKeysOf`, `messagegroup.ParseXwingPublicKey`, `mls.UnmarshalRatchetTree`; `ErrCommitIdentityClaimed`, `mls.ErrAddDuplicateSignatureKey`
- Produces: `joinerOf`, `joinerKeys`, `joinerLeafIn`, `joinerAlreadyHasALeaf`, `ErrKeyPackageInvalid`, `ErrJoinerCannotOpenSealedInvite`, `ErrJoinerAlreadyHasALeaf`

**Behaviour.** In this order, before a commit is staged: the join code decodes; it is a valid
key package of this suite today; it lists the capability; its leaf publishes an X-Wing key. A
damaged code is told it is invalid (`ErrKeyPackageInvalid`), never that it is old; a code from a
build that cannot open a sealed invitation is told so by name
(`ErrJoinerCannotOpenSealedInvite`). After either refusal the adder is where it was. The joiner's
leaf is found in the tree the commit returned by its WHOLE leaf node, not by its signature key
alone: one device's two join codes carry one signature key and two leaves.

**On the live road the role model keeps its place ahead of the check**, as the design orders them:
who may add is a fact about the adder, and a plain member's add is refused by the role model
whatever the join code is. The role model reads the join code first, so its own decode failure
takes the same name, `ErrKeyPackageInvalid`.

**An identity whose leaf already stands is told what to do.** The commonest cause is an invitation
that was made and never opened: the leaf is in the group and nobody is behind it. Both refusals
that mean this (the role model's `ErrCommitIdentityClaimed` and `mls`'s duplicate signature key)
are wrapped in `ErrJoinerAlreadyHasALeaf`, whose sentence is the remedy: remove that entry, then
add the new join code.

**The clock is the WALL clock.** The design does not say. Measured on the first revision: with
the device's own clock, `TestAnOldOwnLineIsDeletedOnEveryRoadAndAcrossRestarts` (an adder 400
days in the past) failed with "leaf node lifetime is not current". `mls` judges the same package
by `time.Now()` at the commit, and this check must not disagree with that one.

**Property 1.** A founding adder refuses a damaged join code as invalid and a join code without the capability by name, with nothing staged and the epoch unmoved, and then adds the honest one.

**Property 2.** The joiner's leaf is the leaf whose whole node the join code published: a second join code of the same device, never added, is answered no leaf.

**Property 3.** On the live road a damaged join code and octets that are no join code are refused as invalid, an identity whose leaf stands is told so with its remedy, the group does not move, and the remedy works as its sentence gives it.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/joinseal_test.go`:

```diff
--- a/sdk/urmessage/joinseal_test.go
+++ b/sdk/urmessage/joinseal_test.go
@@ -15,8 +15,10 @@ import (
 
 	"github.com/urnetwork/connect"
 	connectprotocol "github.com/urnetwork/connect/protocol"
+	"github.com/urnetwork/message/mls"
 	messageprotocol "github.com/urnetwork/message/protocol"
 	"github.com/urnetwork/message/sdk"
+	"github.com/urnetwork/message/syntax"
 )
 
 // THE JOIN SEAL'S FORMATS, as octets a second implementation can check, and the seal itself from
@@ -265,3 +267,154 @@ func TestAHookThatRefusesLeavesNothingStagedAndNothingSent(t *testing.T) {
 		t.Fatalf("CONTROL FAILED: a publish whose hook did not refuse sent the server no frame (%v), so the zero above proves nothing", err)
 	}
 }
+
+// keyPackageWithout is a valid key package of bob's own device that does not list one capability.
+func keyPackageListing(t *testing.T, extensions []mls.ExtensionType) []byte {
+	t.Helper()
+	crypto, err := mls.NewCryptoProvider(deviceCipherSuite)
+	if err != nil {
+		t.Fatalf("the crypto provider: %v", err)
+	}
+	signer, signerPub, err := crypto.SignatureKeyPair()
+	if err != nil {
+		t.Fatalf("the signature key pair: %v", err)
+	}
+	leafKeysBody, _ := mintLeafKeys(t)
+	leafKeys, err := mls.ParseLeafKeysExtension(leafKeysBody)
+	if err != nil {
+		t.Fatalf("the leaf keys body: %v", err)
+	}
+	extension, err := leafKeys.Encode()
+	if err != nil {
+		t.Fatalf("the leaf keys extension: %v", err)
+	}
+	keyPackage, initPrivate, encryptPrivate, err := mls.NewKeyPackageWithSigner(crypto, crypto.Suite(), signer,
+		mls.BasicCredential(signerPub), mls.Capabilities{
+			Versions:     []mls.ProtocolVersion{mls.ProtocolVersionMls10},
+			CipherSuites: mls.Suites(),
+			Extensions:   extensions,
+			Proposals:    []mls.ProposalType{},
+			Credentials:  []mls.CredentialType{mls.CredentialTypeBasic},
+		}, []mls.Extension{extension})
+	if err != nil {
+		t.Fatalf("NewKeyPackageWithSigner: %v", err)
+	}
+	defer keyPackage.Zeroize()
+	defer clear(initPrivate)
+	defer clear(encryptPrivate)
+	encoded, err := syntax.Marshal(keyPackage)
+	if err != nil {
+		t.Fatalf("encoding the key package: %v", err)
+	}
+	return encoded
+}
+
+// A join code is judged BEFORE anything is staged: a damaged one is told it is invalid, one from a
+// build that cannot open a sealed invite is told so by name, and after either the founder is where
+// it was and adds the honest join code.
+func TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged(t *testing.T) {
+	ctx := context.Background()
+	alice, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
+	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
+	for _, device := range []*Device{alice, bob} {
+		if err := device.Connect(ctx); err != nil {
+			t.Fatalf("Connect: %v", err)
+		}
+	}
+	group, err := alice.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, GroupIdBytes))
+	if err != nil {
+		t.Fatalf("CreateGroup: %v", err)
+	}
+	honest, err := bob.KeyPackage()
+	if err != nil {
+		t.Fatalf("bob's KeyPackage: %v", err)
+	}
+	damaged := bytes.Clone(honest)
+	damaged[len(damaged)-1] ^= 0x01 // the last octet of its signature
+	withoutTheCapability := keyPackageListing(t, []mls.ExtensionType{
+		mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys,
+	})
+	// THE CONTROL for the capability row: the same fixture WITH the capability is not refused for it
+	withTheCapability := keyPackageListing(t, []mls.ExtensionType{
+		mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys, mls.ExtensionTypeUrmessageJoinSeal,
+	})
+	if _, err := alice.joinerOf(withTheCapability); err != nil {
+		t.Fatalf("CONTROL FAILED: the fixture's key package is refused with the capability listed: %v", err)
+	}
+
+	for _, one := range []struct {
+		name     string
+		joinCode []byte
+		want     error
+	}{
+		{"a join code with one bit of its signature flipped", damaged, ErrKeyPackageInvalid},
+		{"octets that are not a key package", []byte("not a key package"), ErrKeyPackageInvalid},
+		{"a join code that does not list the join seal", withoutTheCapability, ErrJoinerCannotOpenSealedInvite},
+	} {
+		if _, err := group.AddMember(one.joinCode); !errors.Is(err, one.want) {
+			t.Errorf("%s answered %v, want %v", one.name, err, one.want)
+		}
+		if epoch := group.handle.Epoch(); epoch != 0 {
+			t.Fatalf("%s left the founder's handle at epoch %d", one.name, epoch)
+		}
+		if _, err := group.handle.PendingEpoch(); err == nil {
+			t.Fatalf("%s left a commit staged on the founder", one.name)
+		}
+	}
+	if _, err := group.AddMember(honest); err != nil {
+		t.Fatalf("the honest join code after three refused ones: %v", err)
+	}
+}
+
+// THE JOINER'S LEAF IS THE WHOLE LEAF THE JOIN CODE PUBLISHED, and not merely a leaf under its
+// signature key. One device mints two join codes: they carry one signature key and two different
+// leaves. The first is added; asked for the leaf of the SECOND in the tree that add returned, the
+// search must refuse, because the leaf standing there is not the one that join code published.
+//
+// WHAT WOULD GO RED: find the leaf by signature key alone, and the second join code is answered
+// the first one's leaf, which is a seal and an authenticator made for a leaf its holder never
+// published.
+func TestTheJoinersLeafIsTheWholeLeafTheJoinCodePublished(t *testing.T) {
+	ctx := context.Background()
+	alice, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
+	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
+	for _, device := range []*Device{alice, bob} {
+		if err := device.Connect(ctx); err != nil {
+			t.Fatalf("Connect: %v", err)
+		}
+	}
+	group, err := alice.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, GroupIdBytes))
+	if err != nil {
+		t.Fatalf("CreateGroup: %v", err)
+	}
+	added, err := bob.KeyPackage()
+	if err != nil {
+		t.Fatalf("bob's first KeyPackage: %v", err)
+	}
+	other, err := bob.KeyPackage()
+	if err != nil {
+		t.Fatalf("bob's second KeyPackage: %v", err)
+	}
+	_, _, ratchetTree, err := group.handle.CommitAdd([][]byte{added})
+	if err != nil {
+		t.Fatalf("CommitAdd: %v", err)
+	}
+	defer group.handle.ClearPendingCommit()
+	decode := func(joinCode []byte) *mls.KeyPackage {
+		decoded := &mls.KeyPackage{}
+		if err := syntax.Unmarshal(joinCode, decoded); err != nil {
+			t.Fatalf("decoding a join code: %v", err)
+		}
+		return decoded
+	}
+	// THE CONTROL: the join code that WAS added is found, at the second leaf
+	if leaf, err := joinerLeafIn(ratchetTree, decode(added)); err != nil || leaf != 1 {
+		t.Fatalf("CONTROL FAILED: the added join code's leaf answered %d, %v, want 1", leaf, err)
+	}
+	if !bytes.Equal(decode(added).LeafNode.SignatureKey, decode(other).LeafNode.SignatureKey) {
+		t.Fatalf("CONTROL FAILED: one device's two join codes carry two signature keys, so this is not the case it is written for")
+	}
+	if leaf, err := joinerLeafIn(ratchetTree, decode(other)); err == nil {
+		t.Fatalf("a join code that was never added was answered leaf %d: the search matched its signature key and not its leaf", leaf)
+	}
+}
```

`sdk/cp3b/joinseal_test.go` (new file, 93 lines):

```go
package cp3b

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/message/sdk/urmessage"
)

// THE JOIN SEAL AGAINST THE REAL SERVER: what the unit cases in sdk/urmessage cannot hold, because
// each needs a group that is open and a commit the server takes.

// THE LIVE ADDER JUDGES A JOIN CODE BEFORE IT STAGES ANYTHING, AND NAMES THE REMEDY FOR A LEAF
// THAT STANDS. Three refusals on the live road, and after them the group is where it was: a
// damaged join code and octets that are no join code are told they are invalid, and the join code
// of an identity that already has a leaf is told so by [urmessage.ErrJoinerAlreadyHasALeaf]. The
// leaf that stands is the common one: an invitation that was made and never opened. Then the
// remedy that name's sentence gives is driven as written: the entry is removed, and the join code
// that was refused is added and joins.
//
// WHAT WOULD GO RED: hand the role model's refusal back under its own name, and the adder is told
// an identity is claimed with nothing saying what to do; or judge the join code after the commit
// is staged, and the honest add that follows is refused over what was left behind.
func TestTheLiveAdderJudgesAJoinCodeAndNamesTheRemedyForALeafThatStands(t *testing.T) {
	scene := advFounding(t, true)
	dave := scene.world.newPersona(t, "dave")
	if err := dave.device.Connect(scene.ctx); err != nil {
		t.Fatalf("dave's Connect: %v", err)
	}
	first, err := dave.device.KeyPackage()
	if err != nil {
		t.Fatalf("dave's first KeyPackage: %v", err)
	}
	second, err := dave.device.KeyPackage()
	if err != nil {
		t.Fatalf("dave's second KeyPackage: %v", err)
	}
	damaged := bytes.Clone(first)
	damaged[len(damaged)-1] ^= 0x01 // the last octet of its signature
	if _, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, damaged); !errors.Is(err, urmessage.ErrKeyPackageInvalid) {
		t.Errorf("a join code with one bit of its signature flipped answered %v, want ErrKeyPackageInvalid", err)
	}
	// the role model reads the join code before the adder's own check does, so octets that do not
	// decode are met there; they take the same name
	if _, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, []byte("not a key package")); !errors.Is(err, urmessage.ErrKeyPackageInvalid) {
		t.Errorf("octets that are not a key package answered %v, want ErrKeyPackageInvalid", err)
	}
	if epoch := scene.aliceGroup.Epoch(); epoch != 1 {
		t.Fatalf("the two refused adds left the group at epoch %d, want 1", epoch)
	}

	// NOTHING WAS LEFT STAGED: the honest add that follows is made, and lands at the next epoch.
	// Its invitation is never opened, so dave's leaf stands with nobody behind it.
	if _, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, first); err != nil {
		t.Fatalf("the honest add after two refused ones: %v", err)
	}
	if epoch := scene.aliceGroup.Epoch(); epoch != 2 {
		t.Fatalf("the honest add left the group at epoch %d, want 2", epoch)
	}
	_, err = scene.aliceGroup.AddMemberAndPublish(scene.ctx, second)
	if !errors.Is(err, urmessage.ErrJoinerAlreadyHasALeaf) {
		t.Fatalf("the join code of an identity whose leaf stands answered %v, want ErrJoinerAlreadyHasALeaf", err)
	}
	if epoch := scene.aliceGroup.Epoch(); epoch != 2 {
		t.Fatalf("the refused add left the group at epoch %d, want 2", epoch)
	}

	// THE REMEDY, AS THE SENTENCE GIVES IT: remove that entry, then add the new join code
	bobIdentity := rolesIdentityOf(t, scene.bobGroup)
	var daveIdentity []byte
	for _, member := range removalRoster(t, scene.aliceGroup) {
		if !member.Mine && !bytes.Equal(member.IdentityPub, bobIdentity) {
			daveIdentity = member.IdentityPub
		}
	}
	if daveIdentity == nil {
		t.Fatalf("alice's roster holds no entry for the invitation that was never opened")
	}
	if err := scene.aliceGroup.RemoveMember(scene.ctx, daveIdentity); err != nil {
		t.Fatalf("alice's RemoveMember of the entry nobody is behind: %v", err)
	}
	invite, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, second)
	if err != nil {
		t.Fatalf("the same join code after its identity's entry was removed: %v", err)
	}
	daveGroup, err := dave.device.Join(scene.ctx, gcReencodeInvite(t, invite))
	if err != nil {
		t.Fatalf("dave's Join over the join code that was refused before: %v", err)
	}
	canary := scene.say(t, "alice", scene.aliceGroup)
	gcReceiveText(t, scene.ctx, "dave", daveGroup, canary)
}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk/cp3b test -count=1 -run ^(TestTheLiveAdderJudgesAJoinCodeAndNamesTheRemedyForALeafThatStands) ./...
exit status 1
FAIL	github.com/urnetwork/message/sdk/cp3b [build failed]
FAIL
 # github.com/urnetwork/message/sdk/cp3b [github.com/urnetwork/message/sdk/cp3b.test]
.\joinseal_test.go:41:99: undefined: urmessage.ErrKeyPackageInvalid
.\joinseal_test.go:46:119: undefined: urmessage.ErrKeyPackageInvalid
.\joinseal_test.go:62:31: undefined: urmessage.ErrJoinerAlreadyHasALeaf
$ go -C sdk test -count=1 ./
exit status 0
ok  	github.com/urnetwork/message/sdk	7.062s
$ go -C sdk test -count=1 -run ^(TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged|TestTheJoinersLeafIsTheWholeLeafTheJoinCodePublished) ./urmessage/
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\joinseal_test.go:341:21: alice.joinerOf undefined (type *Device has no field or method joinerOf)
urmessage\joinseal_test.go:350:66: undefined: ErrKeyPackageInvalid
urmessage\joinseal_test.go:351:70: undefined: ErrKeyPackageInvalid
urmessage\joinseal_test.go:352:74: undefined: ErrJoinerCannotOpenSealedInvite
urmessage\joinseal_test.go:411:18: undefined: joinerLeafIn
urmessage\joinseal_test.go:417:18: undefined: joinerLeafIn
```

- [ ] **Step 3: the change.**

`sdk/urmessage/joinseal.go`:

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -3,10 +3,13 @@ package urmessage
 import (
 	"crypto/sha256"
 	"crypto/subtle"
+	"errors"
 	"fmt"
+	"time"
 
 	"github.com/urnetwork/message/message"
 	"github.com/urnetwork/message/messagegroup"
+	"github.com/urnetwork/message/mls"
 	"github.com/urnetwork/message/syntax"
 )
 
@@ -71,6 +74,85 @@ const (
 	groupHandleKeyBytes = 32
 )
 
+// joinerKeys is what an adder reads off a join code before it stages anything: the decoded key
+// package, and the X-Wing key its leaf publishes.
+type joinerKeys struct {
+	keyPackage *mls.KeyPackage
+	xwing      *messagegroup.XwingPublicKey
+}
+
+// joinerOf judges a join code, in this order, BEFORE a commit is staged: it decodes, it is a valid
+// key package of this suite today, it lists the join seal capability, and its leaf publishes an
+// X-Wing key a seal can be made to.
+//
+// VALIDITY BEFORE CAPABILITY, so that a damaged join code is told it is damaged and not that it is
+// old. The capability is also required by every group this build founds, so connect/mls refuses a
+// key package without it at CommitAdd; it is asked here as well so that the refusal has a name of
+// its own and is made before anything is built.
+func (self *Device) joinerOf(keyPackage []byte) (*joinerKeys, error) {
+	decoded := &mls.KeyPackage{}
+	if err := syntax.Unmarshal(keyPackage, decoded); err != nil {
+		return nil, fmt.Errorf("%w: it does not decode: %w", ErrKeyPackageInvalid, err)
+	}
+	// THE WALL CLOCK, AND NOT THE DEVICE'S OWN: it is the clock connect/mls judges the same key
+	// package's lifetime by at CommitAdd, so this check and that one cannot come to disagree.
+	if err := decoded.Validate(self.crypto, deviceCipherSuite, time.Now()); err != nil {
+		return nil, fmt.Errorf("%w: %w", ErrKeyPackageInvalid, err)
+	}
+	if !decoded.LeafNode.Capabilities.SupportsExtension(mls.ExtensionTypeUrmessageJoinSeal) {
+		return nil, ErrJoinerCannotOpenSealedInvite
+	}
+	leafKeys, err := mls.LeafKeysOf(&decoded.LeafNode)
+	if err != nil {
+		return nil, fmt.Errorf("%w: its leaf publishes no key a join seal can be made to: %w", ErrKeyPackageInvalid, err)
+	}
+	xwing, err := messagegroup.ParseXwingPublicKey(leafKeys.DeviceXwingPub)
+	if err != nil {
+		return nil, fmt.Errorf("%w: its leaf's x-wing key: %w", ErrKeyPackageInvalid, err)
+	}
+	return &joinerKeys{keyPackage: decoded, xwing: xwing}, nil
+}
+
+// joinerLeafIn is the leaf of a ratchet tree the joiner's key package was installed at: the one
+// leaf whose signature key AND whole leaf node are the key package's. It is read off the tree the
+// commit returned, which is the tree the joiner is handed, so the adder and the joiner cannot come
+// to name two different leaves.
+func joinerLeafIn(ratchetTree []byte, keyPackage *mls.KeyPackage) (uint32, error) {
+	tree, err := mls.UnmarshalRatchetTree(ratchetTree)
+	if err != nil {
+		return 0, fmt.Errorf("urmessage: the tree the add returned: %w", err)
+	}
+	leaf, found := tree.FindLeafBySignatureKey(keyPackage.LeafNode.SignatureKey)
+	if !found {
+		return 0, fmt.Errorf("urmessage: the tree the add returned holds no leaf with the joiner's signature key")
+	}
+	inTree, err := syntax.Marshal(tree.Leaf(leaf))
+	if err != nil {
+		return 0, err
+	}
+	published, err := syntax.Marshal(&keyPackage.LeafNode)
+	if err != nil {
+		return 0, err
+	}
+	if subtle.ConstantTimeCompare(inTree, published) != 1 {
+		return 0, fmt.Errorf("urmessage: leaf %d of the tree the add returned is not the leaf the join code published", leaf)
+	}
+	return uint32(leaf), nil
+}
+
+// joinerAlreadyHasALeaf gives the two refusals of an add that mean "this identity already has a
+// leaf in this group" the one name an adder can act on, and hands every other error back as it
+// came. The role model refuses first ([ErrCommitIdentityClaimed]: an added leaf claims an identity
+// that is in the group), and connect/mls refuses a signature key the tree already holds. Either is
+// what an adder sees when an invitation it made was never opened and it tries again; the remedy is
+// in the name's own sentence.
+func joinerAlreadyHasALeaf(err error) error {
+	if errors.Is(err, ErrCommitIdentityClaimed) || errors.Is(err, mls.ErrAddDuplicateSignatureKey) {
+		return fmt.Errorf("%w: %w", ErrJoinerAlreadyHasALeaf, err)
+	}
+	return err
+}
+
 // joinerLeafId is u32(joiner_leaf): the wrap's target_id and the join key's exporter context.
 func joinerLeafId(leaf uint32) []byte {
 	return []byte{byte(leaf >> 24), byte(leaf >> 16), byte(leaf >> 8), byte(leaf)}
```

`sdk/urmessage/errors.go`:

```diff
--- a/sdk/urmessage/errors.go
+++ b/sdk/urmessage/errors.go
@@ -820,4 +820,18 @@ var (
 	// is what is left: the store would not take the join code back, or the joined state was
 	// written and the group's record then could not be. Make a new join code and be added again.
 	ErrJoinCodeSpent = errors.New("urmessage: this join did not complete and its join code is spent; make a new join code and ask to be added again")
+
+	// THE THREE REFUSALS AN ADDER MAKES OF A JOIN CODE, each before a commit is staged, so the group
+	// is exactly where it was.
+	//
+	// Invalid: the join code does not decode, is not a key package this suite admits, has expired,
+	// or its leaf publishes no key a join seal can be made to.
+	ErrKeyPackageInvalid = errors.New("urmessage: this join code is not a valid key package")
+	// The join code is valid and does not list the join seal capability, so the device that made
+	// it could not open the invite this build would answer with.
+	ErrJoinerCannotOpenSealedInvite = errors.New("urmessage: this join code was made by a build that cannot open a sealed invite; ask for a join code from an updated URmessage")
+	// The join code is valid, and its identity already has a leaf in this group: most often an
+	// invitation that was made and never opened. A group holds one leaf per identity it admits
+	// this way, so the leaf that stands is removed first.
+	ErrJoinerAlreadyHasALeaf = errors.New("urmessage: this identity already has an entry in this group, perhaps from an invitation that was never opened; remove that entry, then add the new join code")
 )
```

`sdk/urmessage/group.go`:

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1583,9 +1583,13 @@ func (self *Group) AddMember(keyPackage []byte) (*Invite, error) {
 	// CommitAdd carries the Add inside the commit, attributed to the committer, and the SAME
 	// call takes N key packages: one commit admits N members. Nothing is staged on its refusal,
 	// and mls refuses the same things it refused through ProposeAdd, at the same call.
+	// THE JOIN CODE IS JUDGED BEFORE ANYTHING IS BUILT: see [Device.joinerOf].
+	if _, err := self.device.joinerOf(keyPackage); err != nil {
+		return nil, err
+	}
 	commit, welcome, ratchetTree, err := self.handle.CommitAdd([][]byte{keyPackage})
 	if err != nil {
-		return nil, fmt.Errorf("urmessage: CommitAdd: %w", err)
+		return nil, joinerAlreadyHasALeaf(fmt.Errorf("urmessage: CommitAdd: %w", err))
 	}
 	if err := self.handle.MergePendingCommit(); err != nil {
 		return nil, fmt.Errorf("urmessage: MergePendingCommit: %w", err)
@@ -1890,18 +1894,24 @@ func (self *Group) AddMemberAndPublish(ctx context.Context, keyPackage []byte) (
 	// built: a refusal is a fact about this group and this device's role, and it costs no round
 	// trip and touches no session.
 	if _, err := self.authorizeOutgoingLocked(&outgoingCommit{addKeyPackages: [][]byte{keyPackage}}); err != nil {
-		return nil, err
+		return nil, joinerAlreadyHasALeaf(err)
 	}
 	if err := self.rebindLocked(); err != nil {
 		return nil, err
 	}
+	// THE JOIN CODE IS JUDGED BEFORE ANYTHING IS BUILT: see [Device.joinerOf]. The role model
+	// stands ahead of it, because who may add is a fact about this device and is answered the
+	// same way whatever the join code is.
+	if _, err := self.device.joinerOf(keyPackage); err != nil {
+		return nil, err
+	}
 
 	// (1) build the commit that admits the new member, BY VALUE. It is STAGED behind the seam and
 	// not merged: the handle and self.session both stay at the epoch that is closing, and the
 	// Welcome and the ratchet tree it answers are the joiner's whether or not the commit lands.
 	commit, welcome, ratchetTree, err := self.handle.CommitAdd([][]byte{keyPackage})
 	if err != nil {
-		return nil, fmt.Errorf("urmessage: CommitAdd: %w", err)
+		return nil, joinerAlreadyHasALeaf(fmt.Errorf("urmessage: CommitAdd: %w", err))
 	}
 
 	// (2)-(5) announce, submit, and -- once the server has taken it -- merge, enter and fan out
```

`sdk/urmessage/rolescommit.go`:

```diff
--- a/sdk/urmessage/rolescommit.go
+++ b/sdk/urmessage/rolescommit.go
@@ -276,7 +276,7 @@ func (self *Group) outgoingAuthorizationLocked(intent *outgoingCommit) (*CommitA
 	for at, encoded := range intent.addKeyPackages {
 		var keyPackage mls.KeyPackage
 		if err := syntax.Unmarshal(encoded, &keyPackage); err != nil {
-			return nil, fmt.Errorf("urmessage: key package %d of %d does not decode: %w", at, len(intent.addKeyPackages), err)
+			return nil, fmt.Errorf("%w: key package %d of %d does not decode: %w", ErrKeyPackageInvalid, at, len(intent.addKeyPackages), err)
 		}
 		for occupied[next] {
 			next += 1
```

- [ ] **Step 4: the gates this moves.** The crypto-scope row of `joinseal.go` says what its two imports are now for.

`sdk/message_crypto_scope_test.go`:

```diff
--- a/sdk/message_crypto_scope_test.go
+++ b/sdk/message_crypto_scope_test.go
@@ -78,7 +78,7 @@ var sdkCryptoImports = map[string]sdkCryptoImport{
 	"urmessage/group.go": {[]string{"crypto/sha256"},
 		"pq secret witnesses, group-context hashes and a sealed body's hash check"},
 	"urmessage/joinseal.go": {[]string{"crypto/sha256", "crypto/subtle"},
-		"the three hashes join_auth's preimage is over and the width of the sealed digest; and the constant-time comparison of that digest and of an all-zero secret"},
+		"the three hashes join_auth's preimage is over and the width of the sealed digest; and the constant-time comparison of that digest, of an all-zero secret and of the joiner's leaf"},
 	"urmessage/invite.go": {[]string{"crypto/sha256"},
 		"an invite's checksum"},
 	"urmessage/pqepoch.go": {[]string{"crypto/sha256", "crypto/subtle"},
```

- [ ] **Step 5: run it and see it pass.**

```bash
go -C sdk test -count=1 ./...
go -C sdk/cp3b test -count=1 ./...
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run):

```
sdk            exit=0 pass=328 fail=0
cp3b           exit=0 pass=115 fail=0
advsim-strict  exit=1 pass=17 fail=9
```

- [ ] **Step 6: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ11`: the adder does not ask for the capability. Property 1 must fail. Measured: killed by `TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged`.
2. `MJ11b`: the adder does not validate the join code before it stages. Property 1 must fail. Measured: killed by `TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged`, and 1 other test.
3. `MJ62`: the joiner's leaf found by its signature key alone, and not by the whole leaf. Property 2 must fail. Measured: killed by `TestTheJoinersLeafIsTheWholeLeafTheJoinCodePublished`.
4. `MJ11c`: an identity whose leaf stands is answered the role model's own refusal, with no remedy named. Property 3 must fail. Measured: killed by `TestTheLiveAdderJudgesAJoinCodeAndNamesTheRemedyForALeafThatStands`.

- [ ] **Step 7: commit.**

```bash
git add sdk/urmessage/joinseal_test.go sdk/cp3b/joinseal_test.go sdk/urmessage/joinseal.go sdk/urmessage/errors.go sdk/urmessage/group.go sdk/urmessage/rolescommit.go sdk/message_crypto_scope_test.go
git commit -m "urmessage: an adder judges a join code before it stages anything"
```

### Task 46: The flip to invite version 3: the adder seals on both roads, the joiner verifies, opens and checks

- Consumes: the formats (Task 43), the hook (Task 44), the join-code check (Task 45), the two-phase join (Task 36); the harvest, paste-observer and chosen-secret scenarios of phase S0
- Produces: `Invite.JoinSeal`, `Invite.JoinAuth`, `sealJoinLocked`, `sealFoundingJoinLocked`, `openJoinSeal`, `foundingJoinDigest`, `ErrInviteVersion`, `ErrJoinSealShape`, `ErrJoinSealUnauthenticated`, `ErrJoinSealWrongEpoch`, `ErrInviteDigestDrift`, and the scenarios `S4-seed-plus-recorder` and `S4-seed-plus-recorder-live-add`

**One commit.** The invitation's format is one fact: the adder that writes it and the joiner
that reads it cannot change in two green commits.

**The adder.** On the founding road `AddMember` seals OFF THE STAGED COMMIT and before the merge:
everything the seal binds is readable then, and a failure clears the commit, so the add can simply
be made again. It keeps the digest it sealed, and `Open` refuses to publish keys whose digest is
not that one (`ErrInviteDigestDrift`). On the live road `AddMemberAndPublish` seals inside the
hook, over the two values the publish itself decided: the ROTATED secret of the epoch the commit
opens, and the digest that epoch's commit record is about to carry.

**The joiner.** `openJoinSeal` is VERIFY, OPEN, CHECK, in that order, before the joined state
reaches the store: the MAC over the received octets under this epoch's own exporter; the open to
this device's own leaf key; then the payload's shape and the digest. Every expectation is the
joiner's own: the group id, the epoch and the leaf come off the handle its own join built, and
the envelope's four octets are constants. The two secrets are DEFINED where the seal opens
(measured: assigned to variables declared earlier, the join left the pq_secret census's sight and
the gate reported every `Join` site as not found); the epoch's secret is erased when `Join`
returns, and the handle key by a deferred call of its own on a refusal made before the commit.

**The harness follows the format.** Four scenarios bent a plaintext field and are re-pointed at
version 3; the recorder now tries the seal with the X-Wing key it holds, which is a useless one;
and the residual the seal leaves is pinned as two new scenarios, founding and live, which are also
the controls for the harvest rows, because the seed is the only thing those withhold.

**The sentences that described an invitation by its two plaintext fields are corrected in the same
commit** (the grounding review: nine statements, none read by a gate). The C header's section
title and the Go section title above it are left on purpose: "secret in full" stays a safe
instruction, and the header is vendored byte for byte, so `message-windows` needs no re-vendor for
this commit. No exported symbol changes.

**Property 1.** An invitation is version 3 and carries five fields; neither secret is among its octets; and the joiner nevertheless ends up holding both.

**Property 2.** A version 2 invitation is refused by its version, and a seal that is not the shape version 3 fixes is refused at the paste.

**Property 3.** Every alteration of the seal or of its authenticator is refused inside the window as unauthenticated, and the honest invitation still joins over the same join code; a seal an outsider makes, which does open, is refused by the MAC.

**Property 4.** A seal that cannot be made leaves the founder where it was and the add can be made again; and `Open` refuses to publish keys its invitation was not sealed over.

**Property 5.** The recorder of both pasted codes with the classical join reads nothing on any of the four roads, the paste observer finds no handle key, and a chosen secret is not installed; with the joiner's own seed the same recorder reads the join epoch on both roads.

**Property 6.** The version an invitation is written at is the version its authenticator is over.

**Property 7.** Every site a join secret reaches has a disposition, and the payload and the handle key are erased where the census says.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/urmessage_test.go`:

```diff
--- a/sdk/urmessage/urmessage_test.go
+++ b/sdk/urmessage/urmessage_test.go
@@ -14,6 +14,7 @@ import (
 	"github.com/urnetwork/message/messagegroup"
 	messageprotocol "github.com/urnetwork/message/protocol"
 	"github.com/urnetwork/message/sdk"
+	"github.com/urnetwork/message/syntax"
 )
 
 // THE CASES THAT DO NOT NEED A SERVER LIVE HERE, and the one that does lives in the nested module
@@ -30,11 +31,11 @@ import (
 
 func TestAnInviteSurvivesTheOnlyThingACarrierDoesToIt(t *testing.T) {
 	original := &Invite{
-		GroupId:        bytes.Repeat([]byte{0x71}, GroupIdBytes),
-		Welcome:        []byte("a welcome, which carries the mls init secret and is therefore key material"),
-		RatchetTree:    []byte("a ratchet tree"),
-		PqSecret:       bytes.Repeat([]byte{0x2A}, messagegroup.PqSecretBytes),
-		GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32),
+		GroupId:     bytes.Repeat([]byte{0x71}, GroupIdBytes),
+		Welcome:     []byte("a welcome, which carries the mls init secret and is therefore key material"),
+		RatchetTree: []byte("a ratchet tree"),
+		JoinSeal:    testJoinSeal(),
+		JoinAuth:    bytes.Repeat([]byte{0x5C}, joinAuthBytes),
 	}
 	encoded, err := original.Encode()
 	if err != nil {
@@ -52,8 +53,8 @@ func TestAnInviteSurvivesTheOnlyThingACarrierDoesToIt(t *testing.T) {
 		{"group_id", original.GroupId, parsed.GroupId},
 		{"welcome", original.Welcome, parsed.Welcome},
 		{"ratchet_tree", original.RatchetTree, parsed.RatchetTree},
-		{"pq_secret", original.PqSecret, parsed.PqSecret},
-		{"group_handle_key", original.GroupHandleKey, parsed.GroupHandleKey},
+		{"join_seal", original.JoinSeal, parsed.JoinSeal},
+		{"join_auth", original.JoinAuth, parsed.JoinAuth},
 	} {
 		if !bytes.Equal(field.want, field.got) {
 			t.Errorf("%s came back as %x and was encoded as %x", field.name, field.got, field.want)
@@ -70,11 +71,11 @@ func TestAnInviteSurvivesTheOnlyThingACarrierDoesToIt(t *testing.T) {
 func TestAnInviteMissingAnyHalfIsRefused(t *testing.T) {
 	whole := func() *Invite {
 		return &Invite{
-			GroupId:        bytes.Repeat([]byte{0x71}, GroupIdBytes),
-			Welcome:        []byte("a welcome"),
-			RatchetTree:    []byte("a ratchet tree"),
-			PqSecret:       bytes.Repeat([]byte{0x2A}, messagegroup.PqSecretBytes),
-			GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32),
+			GroupId:     bytes.Repeat([]byte{0x71}, GroupIdBytes),
+			Welcome:     []byte("a welcome"),
+			RatchetTree: []byte("a ratchet tree"),
+			JoinSeal:    testJoinSeal(),
+			JoinAuth:    bytes.Repeat([]byte{0x5C}, joinAuthBytes),
 		}
 	}
 	clear := []struct {
@@ -84,8 +85,8 @@ func TestAnInviteMissingAnyHalfIsRefused(t *testing.T) {
 		{"group_id", func(i *Invite) { i.GroupId = nil }},
 		{"welcome", func(i *Invite) { i.Welcome = nil }},
 		{"ratchet_tree", func(i *Invite) { i.RatchetTree = nil }},
-		{"pq_secret", func(i *Invite) { i.PqSecret = nil }},
-		{"group_handle_key", func(i *Invite) { i.GroupHandleKey = nil }},
+		{"join_seal", func(i *Invite) { i.JoinSeal = nil }},
+		{"join_auth", func(i *Invite) { i.JoinAuth = nil }},
 	}
 	if fields := invitefieldCount(); fields != len(clear) {
 		t.Fatalf("Invite declares %d fields and this case empties %d of them, so a field is untested", fields, len(clear))
@@ -105,6 +106,61 @@ func TestAnInviteMissingAnyHalfIsRefused(t *testing.T) {
 	}
 }
 
+// testJoinSeal is octets of the SHAPE a join seal has and nothing more: the four constants of its
+// envelope and filler to its exact length. It opens to nothing, which is all the codec's own cases
+// need; the cases that open a seal make a real one.
+func testJoinSeal() []byte {
+	seal := bytes.Repeat([]byte{0x2A}, joinSealBytes)
+	copy(seal, messagegroup.WrapEnvelope{
+		FormatVersion: messagegroup.WrapFormatVersion,
+		TargetType:    wrapTargetTypeJoiner,
+		PayloadType:   wrapPayloadTypeJoinSecrets,
+		ContentEpoch:  0,
+	}.Encode())
+	return seal
+}
+
+// The seal's shape is refused at the paste: its length, its authenticator's length, and each of the
+// four constants of its envelope, one at a time. The envelope rows are the ones that matter most:
+// a DEVICE WRAP's octets (target 0x01, payload 0x01) and a non-zero content epoch are both
+// well formed wrap bodies, and neither is a join seal.
+func TestAnInviteWhoseSealIsNotTheShapeVersionThreeFixesIsRefused(t *testing.T) {
+	whole := func() *Invite {
+		return &Invite{
+			GroupId:     bytes.Repeat([]byte{0x71}, GroupIdBytes),
+			Welcome:     []byte("a welcome"),
+			RatchetTree: []byte("a ratchet tree"),
+			JoinSeal:    testJoinSeal(),
+			JoinAuth:    bytes.Repeat([]byte{0x5C}, joinAuthBytes),
+		}
+	}
+	if joinSealBytes != 1253 || joinSecretsBytes != 96 {
+		t.Fatalf("a join seal is %d octets over a %d octet payload; invite version 3 fixes 1253 and 96", joinSealBytes, joinSecretsBytes)
+	}
+	if _, err := whole().Encode(); err != nil {
+		t.Fatalf("CONTROL FAILED: the untouched invite does not encode: %v", err)
+	}
+	for _, one := range []struct {
+		name string
+		bend func(*Invite)
+	}{
+		{"a seal one octet short", func(i *Invite) { i.JoinSeal = i.JoinSeal[:joinSealBytes-1] }},
+		{"a seal one octet long", func(i *Invite) { i.JoinSeal = append(i.JoinSeal, 0x00) }},
+		{"an authenticator one octet short", func(i *Invite) { i.JoinAuth = i.JoinAuth[:joinAuthBytes-1] }},
+		{"an authenticator one octet long", func(i *Invite) { i.JoinAuth = append(i.JoinAuth, 0x00) }},
+		{"another wrap format version", func(i *Invite) { i.JoinSeal[0] = 0x02 }},
+		{"the device wrap's target type", func(i *Invite) { i.JoinSeal[1] = wrapTargetTypeDeviceLeaf }},
+		{"the device wrap's payload type", func(i *Invite) { i.JoinSeal[2] = wrapPayloadTypePqSecret }},
+		{"a content epoch that is not zero", func(i *Invite) { i.JoinSeal[10] = 0x01 }},
+	} {
+		invite := whole()
+		one.bend(invite)
+		if _, err := invite.Encode(); !errors.Is(err, ErrJoinSealShape) {
+			t.Errorf("%s answered %v at Encode, want ErrJoinSealShape", one.name, err)
+		}
+	}
+}
+
 // invitefieldCount is [Invite]'s field count READ THROUGH REFLECTION AT TEST TIME, so a sixth
 // field added to the struct with no clause in check() fails the case above instead of passing it.
 // A constant here would be the check that cannot fail.
@@ -114,11 +170,11 @@ func invitefieldCount() int {
 
 func TestAnInviteFromAnotherVersionOrWithOctetsAfterItIsRefused(t *testing.T) {
 	whole := &Invite{
-		GroupId:        bytes.Repeat([]byte{0x71}, GroupIdBytes),
-		Welcome:        []byte("a welcome"),
-		RatchetTree:    []byte("a ratchet tree"),
-		PqSecret:       bytes.Repeat([]byte{0x2A}, messagegroup.PqSecretBytes),
-		GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32),
+		GroupId:     bytes.Repeat([]byte{0x71}, GroupIdBytes),
+		Welcome:     []byte("a welcome"),
+		RatchetTree: []byte("a ratchet tree"),
+		JoinSeal:    testJoinSeal(),
+		JoinAuth:    bytes.Repeat([]byte{0x5C}, joinAuthBytes),
 	}
 	encoded, err := whole.Encode()
 	if err != nil {
@@ -131,8 +187,25 @@ func TestAnInviteFromAnotherVersionOrWithOctetsAfterItIsRefused(t *testing.T) {
 
 	later := append([]byte(nil), encoded...)
 	later[1] = byte(InviteVersion) + 1
-	if _, err := ParseInvite(later); err == nil {
-		t.Error("an invite at a version this build does not write parsed without complaint")
+	if _, err := ParseInvite(later); !errors.Is(err, ErrInviteVersion) {
+		t.Errorf("an invite at a version this build does not write answered %v, want ErrInviteVersion", err)
+	}
+	// VERSION TWO, WHOLE AND WELL FORMED: the plaintext format, with a checksum that covers it.
+	// It is refused by version before a field of it is read.
+	plaintext := syntax.NewWriter()
+	plaintext.WriteUint16(0x0002)
+	plaintext.WriteOpaqueLP(whole.GroupId)
+	plaintext.WriteOpaqueLP(whole.Welcome)
+	plaintext.WriteOpaqueLP(whole.RatchetTree)
+	plaintext.WriteOpaqueLP(bytes.Repeat([]byte{0x2A}, messagegroup.PqSecretBytes))
+	plaintext.WriteOpaqueLP(bytes.Repeat([]byte{0x5C}, 32))
+	versionTwo, err := plaintext.Bytes()
+	if err != nil {
+		t.Fatalf("encoding a version two invite: %v", err)
+	}
+	versionTwoSum := sha256.Sum256(versionTwo)
+	if _, err := ParseInvite(append(versionTwo, versionTwoSum[:]...)); !errors.Is(err, ErrInviteVersion) {
+		t.Errorf("a well formed version two invite answered %v, want ErrInviteVersion", err)
 	}
 
 	// an octet after the last field UNDER A CHECKSUM THAT COVERS IT, so the refusal is the framing's
@@ -166,11 +239,11 @@ func TestAnInviteFromAnotherVersionOrWithOctetsAfterItIsRefused(t *testing.T) {
 // WHAT WOULD GO RED: take the checksum comparison out of ParseInvite, and almost every flip parses.
 func TestEveryBitFlippedAnywhereInAnInviteIsRefusedAtParse(t *testing.T) {
 	whole := &Invite{
-		GroupId:        bytes.Repeat([]byte{0x71}, GroupIdBytes),
-		Welcome:        bytes.Repeat([]byte("a welcome of some length "), 12),
-		RatchetTree:    []byte("a ratchet tree"),
-		PqSecret:       bytes.Repeat([]byte{0x2A}, messagegroup.PqSecretBytes),
-		GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32),
+		GroupId:     bytes.Repeat([]byte{0x71}, GroupIdBytes),
+		Welcome:     bytes.Repeat([]byte("a welcome of some length "), 12),
+		RatchetTree: []byte("a ratchet tree"),
+		JoinSeal:    testJoinSeal(),
+		JoinAuth:    bytes.Repeat([]byte{0x5C}, joinAuthBytes),
 	}
 	encoded, err := whole.Encode()
 	if err != nil {
@@ -314,11 +387,11 @@ func TestEverythingIsRefusedBeforeHello(t *testing.T) {
 		t.Errorf("CreateGroup before Hello answered %v, want ErrNotConnected", err)
 	}
 	if _, err := device.Join(ctx, &Invite{
-		GroupId:        bytes.Repeat([]byte{0x71}, GroupIdBytes),
-		Welcome:        []byte("a welcome"),
-		RatchetTree:    []byte("a ratchet tree"),
-		PqSecret:       bytes.Repeat([]byte{0x2A}, messagegroup.PqSecretBytes),
-		GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32),
+		GroupId:     bytes.Repeat([]byte{0x71}, GroupIdBytes),
+		Welcome:     []byte("a welcome"),
+		RatchetTree: []byte("a ratchet tree"),
+		JoinSeal:    testJoinSeal(),
+		JoinAuth:    bytes.Repeat([]byte{0x5C}, joinAuthBytes),
 	}); !errors.Is(err, ErrNotConnected) {
 		t.Errorf("Join before Hello answered %v, want ErrNotConnected", err)
 	}
```

`sdk/urmessage/joinseal_test.go`:

```diff
--- a/sdk/urmessage/joinseal_test.go
+++ b/sdk/urmessage/joinseal_test.go
@@ -9,12 +9,15 @@ import (
 	"go/ast"
 	"go/parser"
 	"go/token"
+	"io"
+	"strings"
 	"sync/atomic"
 	"testing"
 	"time"
 
 	"github.com/urnetwork/connect"
 	connectprotocol "github.com/urnetwork/connect/protocol"
+	"github.com/urnetwork/message/messagegroup"
 	"github.com/urnetwork/message/mls"
 	messageprotocol "github.com/urnetwork/message/protocol"
 	"github.com/urnetwork/message/sdk"
@@ -418,3 +421,261 @@ func TestTheJoinersLeafIsTheWholeLeafTheJoinCodePublished(t *testing.T) {
 		t.Fatalf("a join code that was never added was answered leaf %d: the search matched its signature key and not its leaf", leaf)
 	}
 }
+
+type sealPair struct {
+	ctx        context.Context
+	alice, bob *Device
+	// the fake server alice's device talks to, which counts what it answered
+	aliceServer *answeringClient
+	aliceGroup  *Group
+	joinCode    []byte
+	invite      *Invite
+}
+
+// newSealPair founds a group on alice and adds bob's join code. Nothing reaches a server: the
+// founding add and the join are both local.
+func newSealPair(t *testing.T) *sealPair {
+	t.Helper()
+	ctx := context.Background()
+	alice, aliceServer := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
+	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
+	for _, device := range []*Device{alice, bob} {
+		if err := device.Connect(ctx); err != nil {
+			t.Fatalf("Connect: %v", err)
+		}
+	}
+	aliceGroup, err := alice.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, GroupIdBytes))
+	if err != nil {
+		t.Fatalf("CreateGroup: %v", err)
+	}
+	joinCode, err := bob.KeyPackage()
+	if err != nil {
+		t.Fatalf("bob's KeyPackage: %v", err)
+	}
+	invite, err := aliceGroup.AddMember(joinCode)
+	if err != nil {
+		t.Fatalf("AddMember: %v", err)
+	}
+	return &sealPair{ctx: ctx, alice: alice, bob: bob, aliceServer: aliceServer, aliceGroup: aliceGroup, joinCode: joinCode, invite: invite}
+}
+
+// THE STRUCTURAL PROPERTY: the invite is version 3, the two secrets are NOWHERE in its octets, and
+// the joiner nevertheless ends up holding both. The second half is the control: without it, an
+// adder that sealed nothing at all would pass the first.
+func TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth(t *testing.T) {
+	pair := newSealPair(t)
+	encoded, err := pair.invite.Encode()
+	if err != nil {
+		t.Fatalf("Encode: %v", err)
+	}
+	if encoded[0] != 0x00 || encoded[1] != 0x03 {
+		t.Fatalf("the invite begins %x, want version 00 03", encoded[:2])
+	}
+	if len(pair.invite.JoinSeal) != 1253 || len(pair.invite.JoinAuth) != 32 {
+		t.Fatalf("the invite carries a %d octet seal and a %d octet authenticator, want 1253 and 32",
+			len(pair.invite.JoinSeal), len(pair.invite.JoinAuth))
+	}
+	pair.aliceGroup.mutex.Lock()
+	pqSecret := append([]byte(nil), pair.aliceGroup.pqSecretLocked()...)
+	groupHandleKey := append([]byte(nil), pair.aliceGroup.groupHandleKey...)
+	pair.aliceGroup.mutex.Unlock()
+	if len(pqSecret) != 32 || len(groupHandleKey) != 32 {
+		t.Fatalf("CONTROL FAILED: the founder holds a %d octet pq_secret and a %d octet group_handle_key", len(pqSecret), len(groupHandleKey))
+	}
+	for name, secret := range map[string][]byte{"pq_secret": pqSecret, "group_handle_key": groupHandleKey} {
+		if bytes.Contains(encoded, secret) {
+			t.Errorf("%s is in the clear in the encoded invite", name)
+		}
+	}
+
+	bobGroup, err := pair.bob.Join(pair.ctx, pair.invite)
+	if err != nil {
+		t.Fatalf("bob's Join: %v", err)
+	}
+	bobGroup.mutex.Lock()
+	defer bobGroup.mutex.Unlock()
+	if !bytes.Equal(bobGroup.pqSecretLocked(), pqSecret) {
+		t.Error("the joiner does not hold the founder's pq_secret for the epoch it joined")
+	}
+	if !bytes.Equal(bobGroup.groupHandleKey, groupHandleKey) {
+		t.Error("the joiner does not hold the group's group_handle_key")
+	}
+}
+
+// EVERY ALTERATION OF THE SEAL OR ITS MAC IS REFUSED INSIDE THE WINDOW, AND THE JOIN CODE SURVIVES.
+// Each bent invite is refused as unauthenticated, because the MAC is over the seal's hash and is
+// checked first; and after all of them the honest invite still joins, over the same join code.
+func TestABentSealIsRefusedAndTheHonestInviteStillJoins(t *testing.T) {
+	pair := newSealPair(t)
+	bend := func(change func(*Invite)) *Invite {
+		bent := &Invite{
+			GroupId:     bytes.Clone(pair.invite.GroupId),
+			Welcome:     bytes.Clone(pair.invite.Welcome),
+			RatchetTree: bytes.Clone(pair.invite.RatchetTree),
+			JoinSeal:    bytes.Clone(pair.invite.JoinSeal),
+			JoinAuth:    bytes.Clone(pair.invite.JoinAuth),
+		}
+		change(bent)
+		return bent
+	}
+	for _, one := range []struct {
+		name string
+		bent *Invite
+	}{
+		{"one bit of the authenticator", bend(func(i *Invite) { i.JoinAuth[0] ^= 0x01 })},
+		{"the last octet of the seal's ciphertext", bend(func(i *Invite) { i.JoinSeal[len(i.JoinSeal)-1] ^= 0x01 })},
+		{"one octet of the KEM ciphertext", bend(func(i *Invite) { i.JoinSeal[40] ^= 0x01 })},
+		{"an authenticator of zeros", bend(func(i *Invite) { i.JoinAuth = make([]byte, joinAuthBytes) })},
+	} {
+		if _, err := pair.bob.Join(pair.ctx, one.bent); !errors.Is(err, ErrJoinSealUnauthenticated) {
+			t.Errorf("%s answered %v, want ErrJoinSealUnauthenticated", one.name, err)
+		}
+		if held := len(pair.bob.Groups()); held != 0 {
+			t.Fatalf("%s left bob holding %d group(s)", one.name, held)
+		}
+	}
+	if _, err := pair.bob.Join(pair.ctx, pair.invite); err != nil {
+		t.Fatalf("the honest invite after four refused ones: %v", err)
+	}
+}
+
+// A seal an OUTSIDER makes opens under the AEAD and is refused by the MAC. Anybody can encapsulate
+// to a public key, so this forger seals secrets of its own choosing to bob's leaf, with every
+// envelope octet right; what it cannot make is the MAC, whose key is the join epoch's exporter.
+func TestAnOutsidersSealOpensAndIsRefusedByTheMac(t *testing.T) {
+	pair := newSealPair(t)
+	joiner, err := pair.alice.joinerOf(pair.joinCode)
+	if err != nil {
+		t.Fatalf("joinerOf: %v", err)
+	}
+	leaf, err := joinerLeafIn(pair.invite.RatchetTree, joiner.keyPackage)
+	if err != nil {
+		t.Fatalf("joinerLeafIn: %v", err)
+	}
+	chosen, err := encodeJoinSecrets(bytes.Repeat([]byte{0xA7}, 32), bytes.Repeat([]byte{0x5E}, 32), bytes.Repeat([]byte{0x01}, 32))
+	if err != nil {
+		t.Fatalf("encodeJoinSecrets: %v", err)
+	}
+	forgedSeal, err := messagegroup.SealWrapBody(pair.alice.random, joiner.xwing, messagegroup.WrapEnvelope{
+		FormatVersion: messagegroup.WrapFormatVersion,
+		TargetType:    wrapTargetTypeJoiner,
+		PayloadType:   wrapPayloadTypeJoinSecrets,
+	}, pair.invite.GroupId, joinerLeafId(leaf), chosen)
+	if err != nil {
+		t.Fatalf("the forger's SealWrapBody: %v", err)
+	}
+	// THE CONTROL: the forged seal really does open to bob's leaf, so the refusal below is the MAC's
+	if _, opened, err := pair.bob.openWrapToOwnLeaf(pair.invite.GroupId, 0, wrapTargetTypeJoiner,
+		joinerLeafId(leaf), wrapPayloadTypeJoinSecrets, forgedSeal); err != nil || !bytes.Equal(opened, chosen) {
+		t.Fatalf("CONTROL FAILED: the forged seal does not open to the joiner's leaf (%v), so nothing below is about the MAC", err)
+	}
+	// the forger's best MAC: the right preimage under a key it can compute, which is not the exporter
+	preimage, err := joinAuthPreimage(pair.invite.GroupId, 1, leaf, pair.invite.Welcome, pair.invite.RatchetTree, forgedSeal)
+	if err != nil {
+		t.Fatalf("joinAuthPreimage: %v", err)
+	}
+	guessedKey := sha256.Sum256(pair.invite.Welcome)
+	forged := &Invite{
+		GroupId: pair.invite.GroupId, Welcome: pair.invite.Welcome, RatchetTree: pair.invite.RatchetTree,
+		JoinSeal: forgedSeal, JoinAuth: pair.alice.crypto.Mac(guessedKey[:], preimage),
+	}
+	if _, err := pair.bob.Join(pair.ctx, forged); !errors.Is(err, ErrJoinSealUnauthenticated) {
+		t.Fatalf("an outsider's seal answered %v, want ErrJoinSealUnauthenticated", err)
+	}
+	if _, err := pair.bob.Join(pair.ctx, pair.invite); err != nil {
+		t.Fatalf("the honest invite after the forged one: %v", err)
+	}
+}
+
+// failingRandom fails every read while it is armed, and is the device's own source otherwise.
+type failingRandom struct {
+	armed bool
+	under io.Reader
+}
+
+func (self *failingRandom) Read(octets []byte) (int, error) {
+	if self.armed {
+		return 0, errors.New("the test's random source is failing")
+	}
+	return self.under.Read(octets)
+}
+
+// A SEAL THAT CANNOT BE MADE LEAVES NOTHING BEHIND. The founder's random source fails while the
+// seal is being made: the staged commit is cleared, the founder is still at epoch 0, and the SAME
+// join code is added once the source works again and joins.
+func TestAFailedSealLeavesTheFounderWhereItWasAndTheAddCanBeMadeAgain(t *testing.T) {
+	ctx := context.Background()
+	alice, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("alice's nonce"))
+	bob, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("bob's nonce"))
+	for _, device := range []*Device{alice, bob} {
+		if err := device.Connect(ctx); err != nil {
+			t.Fatalf("Connect: %v", err)
+		}
+	}
+	group, err := alice.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, GroupIdBytes))
+	if err != nil {
+		t.Fatalf("CreateGroup: %v", err)
+	}
+	joinCode, err := bob.KeyPackage()
+	if err != nil {
+		t.Fatalf("bob's KeyPackage: %v", err)
+	}
+	source := &failingRandom{armed: true, under: alice.random}
+	alice.random = source
+	_, err = group.AddMember(joinCode)
+	if err == nil || !strings.Contains(err.Error(), "sealing the join secrets") {
+		t.Fatalf("an add whose seal could not be made answered %v, want the seal's own failure", err)
+	}
+	if epoch := group.handle.Epoch(); epoch != 0 {
+		t.Fatalf("the failed seal left the founder's handle at epoch %d", epoch)
+	}
+	if _, err := group.handle.PendingEpoch(); err == nil {
+		t.Fatal("the failed seal left a commit staged on the founder")
+	}
+	source.armed = false
+	invite, err := group.AddMember(joinCode)
+	if err != nil {
+		t.Fatalf("the same join code after the failed seal: %v", err)
+	}
+	if _, err := bob.Join(ctx, invite); err != nil {
+		t.Fatalf("bob's Join over the invite the second add made: %v", err)
+	}
+}
+
+// THE FOUNDER PUBLISHES THE DIGEST ITS INVITE WAS SEALED OVER, OR NOTHING. The digest AddMember
+// kept is bent by one bit, and Open refuses before a request leaves the device.
+func TestOpenRefusesToPublishKeysItsInviteWasNotSealedOver(t *testing.T) {
+	pair := newSealPair(t)
+	if len(pair.aliceGroup.foundingJoinDigest) != sha256.Size {
+		t.Fatalf("CONTROL FAILED: AddMember kept a %d octet founding digest", len(pair.aliceGroup.foundingJoinDigest))
+	}
+	// The fake server answers no submit, so an Open that gets as far as one ends on this deadline.
+	brief, cancel := context.WithTimeout(pair.ctx, 250*time.Millisecond)
+	defer cancel()
+	pair.aliceGroup.foundingJoinDigest[0] ^= 0x01
+	before := pair.aliceServer.answered()
+	if err := pair.aliceGroup.Open(brief); !errors.Is(err, ErrInviteDigestDrift) {
+		t.Fatalf("Open over a bent founding digest answered %v, want ErrInviteDigestDrift", err)
+	}
+	if after := pair.aliceServer.answered(); after != before {
+		t.Fatalf("the refused Open sent %d request(s)", after-before)
+	}
+	// THE CONTROL: the same group with the digest put back is not refused for drift.
+	pair.aliceGroup.foundingJoinDigest[0] ^= 0x01
+	if err := pair.aliceGroup.Open(brief); errors.Is(err, ErrInviteDigestDrift) {
+		t.Fatalf("CONTROL FAILED: Open over the untouched founding digest answered %v", err)
+	}
+}
+
+// THE VERSION AN INVITE IS WRITTEN AT IS THE VERSION ITS AUTHENTICATOR IS OVER. The preimage of
+// join_auth names invite version 0x0003 by a constant of its own, so that its 181 octets do not
+// move if the codec's version does; this is what holds the two together. A build that wrote
+// invites at another version would otherwise authenticate a preimage that names this one.
+func TestTheInviteVersionIsTheOneJoinAuthIsOver(t *testing.T) {
+	if InviteVersion != joinAuthInviteVersion {
+		t.Fatalf("an invite is written at version %#04x and join_auth is over version %#04x", InviteVersion, joinAuthInviteVersion)
+	}
+	if InviteVersion != 0x0003 {
+		t.Fatalf("an invite is written at version %#04x, and the sealed invite is version 0x0003", InviteVersion)
+	}
+}
```

`sdk/urmessage/joinwindow_test.go`:

```diff
--- a/sdk/urmessage/joinwindow_test.go
+++ b/sdk/urmessage/joinwindow_test.go
@@ -42,11 +42,11 @@ func windowInvite(t *testing.T, joiner *Device) (*Invite, []byte) {
 // bentInvite is a copy of an invite with one thing changed.
 func bentInvite(invite *Invite, change func(*Invite)) *Invite {
 	bent := &Invite{
-		GroupId:        bytes.Clone(invite.GroupId),
-		Welcome:        bytes.Clone(invite.Welcome),
-		RatchetTree:    bytes.Clone(invite.RatchetTree),
-		PqSecret:       bytes.Clone(invite.PqSecret),
-		GroupHandleKey: bytes.Clone(invite.GroupHandleKey),
+		GroupId:     bytes.Clone(invite.GroupId),
+		Welcome:     bytes.Clone(invite.Welcome),
+		RatchetTree: bytes.Clone(invite.RatchetTree),
+		JoinSeal:    bytes.Clone(invite.JoinSeal),
+		JoinAuth:    bytes.Clone(invite.JoinAuth),
 	}
 	change(bent)
 	return bent
@@ -54,8 +54,8 @@ func bentInvite(invite *Invite, change func(*Invite)) *Invite {
 
 // EVERY REFUSAL INSIDE THE JOIN'S WINDOW BEGINS WITH ONE SENTENCE, AND COSTS NOTHING. Three
 // refusals, made at the three places the window can refuse: the engine (a Welcome for another
-// group), this package's own checks (a secret the session will not take), and the create-only
-// commit (a state already held at the joined epoch). Each answers [ErrJoinRefused] and begins with
+// group), this package's own checks (a join seal whose authenticator is not a member's), and the
+// create-only commit (a state already held at the joined epoch). Each answers [ErrJoinRefused] and begins with
 // its sentence; none answers [ErrJoinCodeSpent]; the device holds no group; and the honest invite
 // then joins OVER THE SAME JOIN CODE, which is what "not spent" means.
 //
@@ -83,8 +83,8 @@ func TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent(t *testing.T)
 	}{
 		{"a welcome for another group, refused by the engine",
 			func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }, false, nil},
-		{"a pq_secret one octet short, refused by this package",
-			func(invite *Invite) { invite.PqSecret = invite.PqSecret[:len(invite.PqSecret)-1] }, false, nil},
+		{"a join seal whose authenticator has one bit flipped, refused by this package",
+			func(invite *Invite) { invite.JoinAuth[0] ^= 0x01 }, false, ErrJoinSealUnauthenticated},
 		{"a state already held at the joined epoch, refused by the commit",
 			func(invite *Invite) {}, true, ErrJoinWouldOverwrite},
 	} {
@@ -221,7 +221,7 @@ func TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent(t *testing.T) {
 		name string
 		bend func(*Invite)
 	}{
-		{"this package's refusal", func(invite *Invite) { invite.PqSecret = invite.PqSecret[:len(invite.PqSecret)-1] }},
+		{"this package's refusal", func(invite *Invite) { invite.JoinAuth[0] ^= 0x01 }},
 		{"the engine's refusal", func(invite *Invite) { invite.GroupId = bytes.Repeat([]byte{0x5D}, GroupIdBytes) }},
 	} {
 		store := &keyPackageSink{MemoryStateStore: NewMemoryStateStore()}
```

`sdk/cp3b/roles_test.go`:

```diff
--- a/sdk/cp3b/roles_test.go
+++ b/sdk/cp3b/roles_test.go
@@ -490,6 +490,8 @@ type seamMember struct {
 	session     *messagegroup.GroupSession
 	groupId     []byte
 	pqSecret    []byte
+	// the private half of the X-Wing key this member's leaf publishes, which a join seal is made to
+	xwing *messagegroup.XwingPrivateKey
 }
 
 // seamMember stands one up and says Hello through its own transport.
@@ -561,6 +563,7 @@ func (self *world) seamMemberClaiming(t *testing.T, ctx context.Context, name st
 		// the identity this member is KNOWN BY, which is its credential's and not its signer's:
 		// the roster, the policy and every role decision are keyed on the credential identity.
 		identityPub: append([]byte(nil), credential...),
+		xwing:       xwing,
 	}
 }
 
@@ -582,7 +585,19 @@ func (self *seamMember) join(t *testing.T, invite *urmessage.Invite) {
 	if err != nil {
 		t.Fatalf("%s's JoinFromWelcome: %v", self.name, err)
 	}
-	session, err := messagegroup.NewGroupSession(handle, invite.PqSecret, invite.GroupHandleKey,
+	// THE JOIN SEAL, OPENED FROM THE PUBLIC PACKAGES AND NOT THROUGH urmessage: target type 0x03,
+	// payload type 0x04, content epoch 0, target id u32(own leaf), and a 96 octet payload whose
+	// first two thirds are pq_secret and group_handle_key. A second spelling of the format, which
+	// is what a member that is not this sdk is.
+	leaf := handle.OwnLeafIndex()
+	_, joinSecrets, err := messagegroup.OpenWrapBody(self.xwing, invite.GroupId, 0, 0x03,
+		[]byte{byte(leaf >> 24), byte(leaf >> 16), byte(leaf >> 8), byte(leaf)}, 0x04, invite.JoinSeal)
+	if err != nil || len(joinSecrets) != 96 {
+		handle.Close()
+		t.Fatalf("%s opening its join seal: %d octets, %v", self.name, len(joinSecrets), err)
+	}
+	pqSecret, groupHandleKey := joinSecrets[:32], joinSecrets[32:64]
+	session, err := messagegroup.NewGroupSession(handle, pqSecret, groupHandleKey,
 		self.reserver, func() int64 { return time.Now().UnixMilli() }, self.transport.Nonce())
 	if err != nil {
 		handle.Close()
@@ -591,7 +606,7 @@ func (self *seamMember) join(t *testing.T, invite *urmessage.Invite) {
 	t.Cleanup(func() { session.Close() })
 	self.handle, self.session = handle, session
 	self.groupId = append([]byte(nil), invite.GroupId...)
-	self.pqSecret = append([]byte(nil), invite.PqSecret...)
+	self.pqSecret = append([]byte(nil), pqSecret...)
 }
 
 // commitAddAndSubmit builds an Add of one key package through the seam's by-value arm, merges it,
```

`sdk/cp3b/advsim_oracle_test.go`:

```diff
--- a/sdk/cp3b/advsim_oracle_test.go
+++ b/sdk/cp3b/advsim_oracle_test.go
@@ -119,6 +119,9 @@ type advShadow struct {
 	exporter []byte
 	epoch    uint64
 	ownLeaf  uint32
+	// the X-Wing key the shadow opens a join seal with: made from the RANDOM seed that replaced the
+	// joiner's, unless a scenario grants the true one with [advTrueSeed]
+	xwing *messagegroup.XwingPrivateKey
 }
 
 // advShor is the grant rule and the grant.
@@ -180,7 +183,85 @@ func advShor(t *testing.T, captured [][]byte, joinCode []byte, preJoinStateDir s
 	if err != nil {
 		advHarness(t, "the shadow's exporter: %v", err)
 	}
-	return &advShadow{handle: handle, exporter: exporter, epoch: handle.Epoch(), ownLeaf: handle.OwnLeafIndex()}, true
+	xwing, err := messagegroup.XwingKeyGenFromSeed(seed)
+	if err != nil {
+		advHarness(t, "an x-wing key from the replacement seed: %v", err)
+	}
+	return &advShadow{handle: handle, exporter: exporter, epoch: handle.Epoch(), ownLeaf: handle.OwnLeafIndex(), xwing: xwing}, true
+}
+
+// advTrueSeed is the DEVICE COMPROMISE grant, and it is not a quantum computer's: the joiner's own
+// X-Wing seed, read out of a copy of its state directory. A scenario that passes it is measuring
+// what a thief of that directory holds, and says so in its name.
+func advTrueSeed(t *testing.T, stateDir string) func(*advShadow) {
+	t.Helper()
+	return func(shadow *advShadow) {
+		copyDir := filepath.Join(t.TempDir(), "seed-thief")
+		copyAppData(t, stateDir, copyDir)
+		store, err := urmessage.OpenDurableStateStore(copyDir)
+		if err != nil {
+			advHarness(t, "the seed thief's copy does not open: %v", err)
+		}
+		defer store.Close()
+		_, _, _, seed, err := store.GetDeviceIdentity()
+		if err != nil || len(seed) != messagegroup.XwingSeedSize {
+			advHarness(t, "the seed thief's copy holds a %d octet x-wing seed: %v", len(seed), err)
+		}
+		xwing, err := messagegroup.XwingKeyGenFromSeed(seed)
+		if err != nil {
+			advHarness(t, "an x-wing key from the joiner's seed: %v", err)
+		}
+		shadow.xwing = xwing
+	}
+}
+
+// advLeafId is u32(leaf): a join seal's target id.
+func advLeafId(leaf uint32) []byte {
+	return binary.BigEndian.AppendUint32(nil, leaf)
+}
+
+// advOpenSeal opens a join seal with the X-Wing key the shadow holds, stating the wrap by the
+// constants of its format: target type 0x03, payload type 0x04, content epoch 0, target id
+// u32(leaf). It answers the first two thirds of a 96 octet payload.
+func advOpenSeal(t *testing.T, shadow *advShadow, groupId []byte, joinSeal []byte) ([]byte, []byte, bool) {
+	t.Helper()
+	_, payload, err := messagegroup.OpenWrapBody(shadow.xwing, groupId, 0, 0x03, advLeafId(shadow.ownLeaf), 0x04, joinSeal)
+	if err != nil || len(payload) != 96 {
+		t.Logf("the shadow's x-wing key does not open the join seal: %d octets, %v", len(payload), err)
+		return nil, nil, false
+	}
+	return payload[:32], payload[32:64], true
+}
+
+// advForgedSeal is a join seal an OUTSIDER makes: a wrap body sealed to the X-Wing key one leaf of
+// the invitation's own ratchet tree publishes, carrying secrets the attacker chose, with every
+// octet of the envelope right. Anybody can encapsulate to a public key, and the tree is in the
+// clear in the invitation the attacker is rewriting.
+func advForgedSeal(t *testing.T, groupId []byte, ratchetTree []byte, leaf uint32, pqSecret []byte, groupHandleKey []byte) []byte {
+	t.Helper()
+	tree, err := mls.UnmarshalRatchetTree(ratchetTree)
+	if err != nil {
+		advHarness(t, "the invitation's ratchet tree does not decode: %v", err)
+	}
+	leafKeys, err := mls.LeafKeysOf(tree.Leaf(mls.LeafIndex(leaf)))
+	if err != nil {
+		advHarness(t, "leaf %d of the invitation's tree publishes no leaf keys: %v", leaf, err)
+	}
+	target, err := messagegroup.ParseXwingPublicKey(leafKeys.DeviceXwingPub)
+	if err != nil {
+		advHarness(t, "leaf %d's x-wing key: %v", leaf, err)
+	}
+	// the third value is the epoch's digest, which an outsider cannot compute: any 32 octets
+	payload := append(append(append([]byte(nil), pqSecret...), groupHandleKey...), bytes.Repeat([]byte{0x01}, 32)...)
+	seal, err := messagegroup.SealWrapBody(rand.Reader, target, messagegroup.WrapEnvelope{
+		FormatVersion: messagegroup.WrapFormatVersion,
+		TargetType:    0x03,
+		PayloadType:   0x04,
+	}, groupId, advLeafId(leaf), payload)
+	if err != nil {
+		advHarness(t, "the forger's seal: %v", err)
+	}
+	return seal
 }
 
 // THE INIT KEY READER'S OWN CONTROL. The grant rule turns on thirty-two octets read by offset, so
```

`sdk/cp3b/advsim_join_test.go`:

```diff
--- a/sdk/cp3b/advsim_join_test.go
+++ b/sdk/cp3b/advsim_join_test.go
@@ -157,7 +157,7 @@ func (self *advJoin) recordOf(t *testing.T, who *persona) *urmessage.GroupRecord
 // advHarvest is the recorder's whole attack on one join: the Shor grant over what was captured,
 // the scrape of the haystack, and the read. It answers the epochs it read.
 func advHarvest(t *testing.T, world *world, groupId []byte, captured [][]byte, haystack []byte,
-	joinCode []byte, beforeJoin string, invite []byte, canaries map[string]uint64) []string {
+	joinCode []byte, beforeJoin string, invite []byte, canaries map[string]uint64, grants ...func(*advShadow)) []string {
 
 	t.Helper()
 	version, fields := advInviteFields(t, invite)
@@ -169,7 +169,17 @@ func advHarvest(t *testing.T, world *world, groupId []byte, captured [][]byte, h
 		t.Logf("the recorder captured no init key, so the CRQC inverts nothing and the shadow does not exist")
 		return []string{}
 	}
+	for _, grant := range grants {
+		grant(shadow)
+	}
 	scraped := advScrape(t, world, groupId, shadow, haystack)
+	if scraped.pqSecret == nil && len(fields) == 5 {
+		// NOTHING IN THE CLEAR, SO THE SEAL: opened with the X-Wing key the shadow holds, which is
+		// a useless one unless a grant above replaced it.
+		if pqSecret, groupHandleKey, opened := advOpenSeal(t, shadow, groupId, fields[3]); opened {
+			return advRead(t, world, shadow, pqSecret, groupHandleKey, canaries)
+		}
+	}
 	if scraped.pqSecret == nil {
 		shadow.handle.Close()
 		return []string{}
@@ -396,22 +406,21 @@ func TestAdvSimTheInvitationAloneReadsNothing(t *testing.T) {
 	advJudge(t, "P1-c1-invite-alone", observed)
 }
 
-// CONTROL: both codes, with the pq_secret field of the RECORDED invitation replaced by random
-// octets. The honest joiner still joined on the real one. The read is causal in that field.
+// CONTROL: both codes and the group's TRUE group_handle_key handed to the recorder, with 32 random
+// octets where the control below hands it the true pq_secret. The read is causal in that one value.
 func TestAdvSimAReplacedPqSecretReadsNothing(t *testing.T) {
 	scene := advFounding(t, true)
-	version, fields := advInviteFields(t, scene.invite)
-	if len(fields) < 4 {
-		advHarness(t, "the invite carries %d fields, so there is no fourth to replace", len(fields))
+	record := scene.recordOf(t, scene.alice)
+	if record == nil || len(record.GroupHandleKey) != 32 {
+		advHarness(t, "the founder's durable record does not hold the group_handle_key to inject")
 	}
-	replaced := make([]byte, len(fields[3]))
+	replaced := make([]byte, 32)
 	if _, err := rand.Read(replaced); err != nil {
 		advHarness(t, "drawing the replacement: %v", err)
 	}
-	fields[3] = replaced
-	recorded := advEncodeInvite(version, fields)
-	haystack := append(append([]byte(nil), scene.joinCode...), recorded...)
-	observed := advHarvest(t, scene.world, scene.groupId, [][]byte{scene.joinCode, recorded}, haystack,
+	haystack := append(scene.paste.haystack(), replaced...)
+	haystack = append(haystack, record.GroupHandleKey...)
+	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, haystack,
 		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
 	advJudge(t, "P1-c2-replaced-pq", observed)
 }
@@ -493,21 +502,40 @@ func TestAdvSimFirstAppearanceLinksThisPastesMembersToTheirHandles(t *testing.T)
 
 // ── S3: an active attacker on the paste channel ──────────────────────────────────────────────
 
-// The attacker rewrites the invitation in flight into the plaintext format, carrying a pq_secret
-// and a group_handle_key IT chose, and recomputes the checksum.
+// The attacker rewrites the invitation in flight so that it carries a pq_secret and a
+// group_handle_key IT chose, and recomputes the checksum. Two forgeries, and neither may install
+// anything: the plaintext format, which this build no longer reads; and a version 3 invitation
+// whose seal the attacker made itself, to the joiner's published X-Wing key, under the honest
+// invitation's own authenticator. The second must be refused BY THE AUTHENTICATOR, before the seal
+// is opened: a refusal by anything later is reported, because it means a forged seal was opened.
 func TestAdvSimAnAttackerChosenSecretIsNotInstalled(t *testing.T) {
 	scene := advFounding(t, false)
-	_, fields := advInviteFields(t, scene.invite)
+	version, fields := advInviteFields(t, scene.invite)
+	if version != 0x0003 || len(fields) != 5 {
+		advHarness(t, "the honest invitation is version %#04x with %d fields, so there is no seal to forge", version, len(fields))
+	}
 	chosenPq := bytes.Repeat([]byte{0xA7}, 32)
 	chosenGhk := bytes.Repeat([]byte{0x5E}, 32)
-	forged := advEncodeInvite(0x0002, [][]byte{fields[0], fields[1], fields[2], chosenPq, chosenGhk})
 
 	observed := []string{}
-	parsed, err := urmessage.ParseInvite(forged)
+	plaintext := advEncodeInvite(0x0002, [][]byte{fields[0], fields[1], fields[2], chosenPq, chosenGhk})
+	parsed, err := urmessage.ParseInvite(plaintext)
 	if err == nil {
 		_, err = scene.bob.device.Join(scene.ctx, parsed)
 	}
-	t.Logf("the forged invitation was answered: %v", err)
+	t.Logf("the forged plaintext invitation was answered: %v", err)
+
+	// the joiner is the second leaf of a group its founder is the first of
+	forgedSeal := advForgedSeal(t, scene.groupId, fields[2], 1, chosenPq, chosenGhk)
+	parsed, err = urmessage.ParseInvite(advEncodeInvite(version, [][]byte{fields[0], fields[1], fields[2], forgedSeal, fields[4]}))
+	if err != nil {
+		advHarness(t, "the forged version 3 invitation does not parse, so the join was never reached: %v", err)
+	}
+	_, err = scene.bob.device.Join(scene.ctx, parsed)
+	t.Logf("the forged sealed invitation was answered: %v", err)
+	if err != nil && !errors.Is(err, urmessage.ErrJoinSealUnauthenticated) {
+		observed = append(observed, "forged-seal-opened")
+	}
 	if record := scene.recordOf(t, scene.bob); record != nil {
 		if bytes.Equal(record.PqSecret, chosenPq) || bytes.Equal(record.GroupHandleKey, chosenGhk) {
 			observed = append(observed, "installed:attacker-secret")
@@ -550,24 +578,25 @@ func TestAdvSimARefusedInvitationDoesNotSpendTheJoinCode(t *testing.T) {
 }
 
 // The same property as the refused invitation above, at the OTHER place a refusal is made: after
-// the engine has joined. The attacker shortens the fourth field by one octet and recomputes the
-// checksum, the welcome is the right group's, and the refusal is this package's own.
+// the engine has joined. The attacker flips one bit of the authenticator and recomputes the
+// checksum. The welcome is the right group's and the key that judges the authenticator is the
+// joined epoch's own, so this refusal cannot be made any earlier than it is.
 func TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode(t *testing.T) {
 	scene := advFounding(t, false)
 	version, fields := advInviteFields(t, scene.invite)
-	if len(fields) < 4 {
-		advHarness(t, "the invite carries %d fields, so there is no fourth to shorten", len(fields))
+	if len(fields) != 5 || len(fields[4]) != 32 {
+		advHarness(t, "the invite carries %d fields, so there is no authenticator to bend", len(fields))
 	}
-	fields[3] = fields[3][:len(fields[3])-1]
+	fields[4][0] ^= 0x01
 	observed := []string{}
 	bent, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
-	if err == nil {
-		_, err = scene.bob.device.Join(scene.ctx, bent)
+	if err != nil {
+		advHarness(t, "the bent invitation does not parse, so the join was never reached: %v", err)
 	}
-	if err == nil {
-		advHarness(t, "an invitation with a shortened fourth field was accepted")
+	if _, err = scene.bob.device.Join(scene.ctx, bent); err == nil {
+		advHarness(t, "an invitation with one bit of its authenticator flipped was accepted")
 	}
-	t.Logf("the shortened invitation was refused: %v", err)
+	t.Logf("the bent invitation was refused: %v", err)
 	honest, err := urmessage.ParseInvite(scene.invite)
 	if err != nil {
 		advHarness(t, "parsing the honest invite: %v", err)
@@ -675,6 +704,29 @@ func TestAdvSimACopiedStateDirectoryReadsTheJoinEpoch(t *testing.T) {
 	advJudge(t, "S4-state-thief", observed)
 }
 
+// THE RESIDUAL, PINNED ON PURPOSE. The same recorder as the harvest scenarios, and this time the
+// joiner's X-Wing seed as well, out of a copy of its state directory taken BEFORE the join. It
+// joins the recorded Welcome, opens the recorded seal and reads the join epoch: the seal is to a
+// static key, so whoever holds that key and the paste holds the epoch. It is also the harvest
+// scenarios' control, because the seed is the only thing they withhold.
+func TestAdvSimTheJoinersSeedAndTheRecordingReadTheJoinEpoch(t *testing.T) {
+	scene := advFounding(t, true)
+	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, scene.paste.haystack(),
+		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries, advTrueSeed(t, scene.bobBeforeJoin))
+	advJudge(t, "S4-seed-plus-recorder", observed)
+}
+
+// THE SAME RESIDUAL ON THE LIVE ROAD, where the sealed secret is the rotated one. It is the control
+// for the live add's harvest row: that row reads nothing since the seal, and this one shows the
+// recorder reading the same epoch through the same pipeline once it holds the one thing that row
+// withholds.
+func TestAdvSimTheJoinersSeedAndTheRecordingReadALiveAddsEpoch(t *testing.T) {
+	live := advLiveAddScene(t)
+	observed := advHarvest(t, live.scene.world, live.scene.groupId, live.paste.captured, live.paste.haystack(),
+		live.joinCode, live.beforeJoin, live.invite, live.canaries, advTrueSeed(t, live.beforeJoin))
+	advJudge(t, "S4-seed-plus-recorder-live-add", observed)
+}
+
 // ── S7: an invitation over a group the device already holds ──────────────────────────────────
 
 // advHostile is an attacker's own group founded under the SAME group id the victim holds, with an
@@ -765,24 +817,24 @@ func TestAdvSimAValidInvitationUnderAHeldGroupIdReplacesNothing(t *testing.T) {
 	advJudge(t, "S7a-held-id-valid-invite", advHeldGroupOutcome(t, scene, before))
 }
 
-// The same invitation carrying a pq_secret one octet short: the session refuses it, which is a
-// refusal that arrives AFTER the engine has joined.
+// The same invitation with one bit of its authenticator flipped: a refusal that, without the gate,
+// arrives AFTER the engine has joined.
 func TestAdvSimAnInvitationRefusedLateUnderAHeldGroupIdReplacesNothing(t *testing.T) {
 	scene := advFounding(t, true)
 	version, fields := advInviteFields(t, advHostile(t, scene, scene.bob.device))
-	if len(fields) < 4 {
+	if len(fields) != 5 || len(fields[4]) != 32 {
 		advHarness(t, "the hostile invite carries %d fields", len(fields))
 	}
-	fields[3] = fields[3][:len(fields[3])-1]
+	fields[4][0] ^= 0x01
 	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
 	parsed, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
-	if err == nil {
-		_, err = scene.bob.device.Join(scene.ctx, parsed)
+	if err != nil {
+		advHarness(t, "the bent hostile invitation does not parse, so the join was never reached: %v", err)
 	}
-	if err == nil {
-		advHarness(t, "an invitation with a truncated fourth field was accepted")
+	if _, err = scene.bob.device.Join(scene.ctx, parsed); err == nil {
+		advHarness(t, "an invitation with one bit of its authenticator flipped was accepted")
 	}
-	t.Logf("the truncated invitation was answered: %v", err)
+	t.Logf("the bent invitation was answered: %v", err)
 	advJudge(t, "S7b-held-id-refused-late", advHeldGroupOutcome(t, scene, before))
 }
 
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk/cp3b test -count=1 -run ^(TestAdvSim|TestAdvSimTheJoinersSeedAndTheRecordingReadALiveAddsEpoch|TestAdvSimTheJoinersSeedAndTheRecordingReadTheJoinEpoch) ./...
exit status 1
FAIL	github.com/urnetwork/message/sdk/cp3b [build failed]
FAIL
 # github.com/urnetwork/message/sdk/cp3b [github.com/urnetwork/message/sdk/cp3b.test]
.\advsim_join_test.go:536:45: undefined: urmessage.ErrJoinSealUnauthenticated
.\roles_test.go:594:89: invite.JoinSeal undefined (type *urmessage.Invite has no field or method JoinSeal)
$ go -C sdk test -count=1 -run ^(TestABentSealIsRefusedAndTheHonestInviteStillJoins|TestAFailedSealLeavesTheFounderWhereItWasAndTheAddCanBeMadeAgain|TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth|TestAnInviteWhoseSealIsNotTheShapeVersionThreeFixesIsRefused|TestAnOutsidersSealOpensAndIsRefusedByTheMac|TestOpenRefusesToPublishKeysItsInviteWasNotSealedOver|TestTheInviteVersionIsTheOn
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\joinseal_test.go:474:21: pair.invite.JoinSeal undefined (type *Invite has no field or method JoinSeal)
urmessage\joinseal_test.go:474:58: pair.invite.JoinAuth undefined (type *Invite has no field or method JoinAuth)
urmessage\joinseal_test.go:476:20: pair.invite.JoinSeal undefined (type *Invite has no field or method JoinSeal)
urmessage\joinseal_test.go:476:47: pair.invite.JoinAuth undefined (type *Invite has no field or method JoinAuth)
urmessage\joinseal_test.go:515:4: unknown field JoinSeal in struct literal of type Invite
urmessage\joinseal_test.go:515:41: pair.invite.JoinSeal undefined (type *Invite has no field or method JoinSeal)
urmessage\joinseal_test.go:516:4: unknown field JoinAuth in struct literal of type Invite
...
```

- [ ] **Step 3: the change.**

`sdk/urmessage/invite.go`:

```diff
--- a/sdk/urmessage/invite.go
+++ b/sdk/urmessage/invite.go
@@ -5,52 +5,60 @@ import (
 	"crypto/sha256"
 	"fmt"
 
+	"github.com/urnetwork/message/messagegroup"
 	"github.com/urnetwork/message/syntax"
 )
 
-// InviteVersion is the version every [Invite] this build encodes carries. A blob written by another
-// build is refused by [ParseInvite] rather than read as this one.
+// InviteVersion is the version every [Invite] this build encodes carries, and the only one it
+// reads. A blob at any other version is refused by [ParseInvite] with [ErrInviteVersion].
+//
+// 0x0003 SEALS THE JOIN SECRETS. Version two carried pq_secret and group_handle_key as two fields
+// in the clear; version three carries a join seal and its authenticator in their place, and
+// nothing secret in the clear. See joinseal.go. A version two blob is refused BY VERSION and is
+// never read: reading one would be installing two secrets whoever pasted it chose.
 //
 // 0x0002 ADDED THE CHECKSUM, AND AN 0x0001 BLOB IS REFUSED BY VERSION. Version one was framing and
 // nothing else, so a damaged invite PARSED and JOINED and the damage surfaced one call later: a
-// review flipped one bit at each of 3,408 positions of a real invite and 3,386 parsed; one that
-// corrupted group_handle_key joined cleanly as the intended recipient and then never received a
-// message, with the precise error arriving at Receive instead of at the paste. See [ParseInvite].
-const InviteVersion uint16 = 0x0002
+// review flipped one bit at each of 3,408 positions of a real invite and 3,386 parsed. See
+// [ParseInvite].
+const InviteVersion uint16 = 0x0003
 
 // inviteChecksumBytes is the width of the SHA-256 an encoded invite ends with.
 const inviteChecksumBytes = sha256.Size
 
 // Invite is everything a second device needs in order to join a group, and it is a HAND-OFF rather
-// than a message: this package has no channel to carry it and does not invent one, because the
-// rendezvous and the contact card are out of scope for the alpha.
+// than a message: this package has no channel to carry it and does not invent one.
+//
+// NOTHING IN IT IS A SECRET IN THE CLEAR. The two secrets a joiner needs are inside JoinSeal,
+// sealed under X-Wing to the key the joiner's own leaf publishes, so only the device whose join
+// code was added can open it. What a third party who obtains an invite DOES learn is the group's
+// id, its ratchet tree -- who is in it, by credential -- and that this joiner was added.
 //
-// IT IS SECRET IN FULL. Two of its four fields are key material -- pq_secret is the IKM of every
-// storage root this group will ever extract, and the Welcome carries the MLS init secret -- so an
-// invite that reaches a third party is a group that third party is in. Move it the way you would
-// move a private key: over a channel that is already authenticated and already confidential, once,
-// and destroy it afterwards.
+// IT IS STILL NOT AUTHENTICATED, and it must still travel over a channel the two people trust.
+// Whoever controls that channel can substitute a different join code on the way out or a different
+// invite on the way back, and the joiner then joins a group that is real and is not the one it
+// meant (MG-1). The seal does not change that and does not claim to.
 //
-// WHAT EACH FIELD IS AND WHOSE OPEN ITEM ITS DELIVERY IS. Every one is a value a PRODUCTION
-// function of connect produced; what does not exist is a carrier.
+// WHAT EACH FIELD IS.
 //
-//   - Welcome and RatchetTree: connect/mls's own, from GroupHandle.Commit. Ledger 44a's named,
-//     gated hand-off.
-//   - PqSecret: messagegroup.NewPqSecret. Its delivery is M1-20 and m1 task 14.
-//   - GroupHandleKey: GroupHandleKey(StorageRoot(mls_secret[0], pq_secret)), computed at epoch zero
-//     and never recomputed. Its carrier is M1-2. It is in here because a session opened at any
-//     epoch after zero is REFUSED without it -- a value recomputed from a later root would give
-//     every epoch a different sender_handle and end every member's stream at every commit.
-//   - GroupId: the 32 octets the server keys its rows by.
+//   - GroupId: the 32 octets the server keys its rows by, and the group this device's join is
+//     BOUND to: a Welcome describing any other group is refused before anything is written.
+//   - Welcome and RatchetTree: the MLS hand-off, from the commit that added the joiner.
+//   - JoinSeal: join_secrets_v1 -- pq_secret of the epoch joined, group_handle_key, and the digest
+//     of that epoch's published keys -- as a MASTER section 7 wrap body addressed to the joiner's
+//     leaf. Exactly 1,253 octets.
+//   - JoinAuth: the 32 octet MAC over all of the above that only a member of the join epoch can
+//     make.
 type Invite struct {
-	GroupId        []byte
-	Welcome        []byte
-	RatchetTree    []byte
-	PqSecret       []byte
-	GroupHandleKey []byte
+	GroupId     []byte
+	Welcome     []byte
+	RatchetTree []byte
+	JoinSeal    []byte
+	JoinAuth    []byte
 }
 
-// check refuses an invite that is missing a half nothing downstream could recover.
+// check refuses an invite that is not the shape version three fixes. It reads no key and opens
+// nothing, so it runs at the paste, before a join code is touched.
 func (self *Invite) check() error {
 	if len(self.GroupId) != GroupIdBytes {
 		return fmt.Errorf("urmessage: an invite names a %d octet group id, want %d", len(self.GroupId), GroupIdBytes)
@@ -61,21 +69,32 @@ func (self *Invite) check() error {
 	if len(self.RatchetTree) == 0 {
 		return fmt.Errorf("urmessage: an invite carries no ratchet tree")
 	}
-	if len(self.PqSecret) == 0 {
-		return fmt.Errorf("urmessage: an invite carries no pq_secret, which is the ikm of every storage root this group extracts")
+	if len(self.JoinSeal) != joinSealBytes {
+		return fmt.Errorf("%w: it is %d octets and invite version %#04x carries exactly %d",
+			ErrJoinSealShape, len(self.JoinSeal), InviteVersion, joinSealBytes)
+	}
+	if len(self.JoinAuth) != joinAuthBytes {
+		return fmt.Errorf("%w: its authenticator is %d octets, want %d", ErrJoinSealShape, len(self.JoinAuth), joinAuthBytes)
+	}
+	// THE ENVELOPE IS FOUR CONSTANTS. The content epoch is zero by construction, so that the epoch
+	// a member joined at is not in the clear; a seal carrying any other envelope is some other
+	// wrap, and is refused here rather than at the open.
+	envelope, err := messagegroup.ParseWrapEnvelope(self.JoinSeal[:messagegroup.WrapEnvelopeBytes])
+	if err != nil {
+		return fmt.Errorf("%w: %w", ErrJoinSealShape, err)
 	}
-	if len(self.GroupHandleKey) == 0 {
-		return fmt.Errorf("urmessage: an invite carries no group_handle_key, and a session at any epoch after zero is refused without it")
+	if envelope.FormatVersion != messagegroup.WrapFormatVersion || envelope.TargetType != wrapTargetTypeJoiner ||
+		envelope.PayloadType != wrapPayloadTypeJoinSecrets || envelope.ContentEpoch != 0 {
+		return fmt.Errorf("%w: its envelope is version %#02x, target %#02x, payload %#02x, content epoch %d",
+			ErrJoinSealShape, envelope.FormatVersion, envelope.TargetType, envelope.PayloadType, envelope.ContentEpoch)
 	}
 	return nil
 }
 
 // Encode is the invite as octets a caller can move.
 //
-// The encoding is connect/mls/syntax's length prefixes, which is the one length prefix this corpus
-// writes, so a field added to [Invite] later is a version bump here rather than a second framing --
-// followed by the SHA-256 of every octet before it. See [ParseInvite] for what the checksum is and
-// is not.
+// The encoding is this corpus's one length prefix, five fields, followed by the SHA-256 of every
+// octet before it. See [ParseInvite] for what the checksum is and is not.
 func (self *Invite) Encode() ([]byte, error) {
 	if err := self.check(); err != nil {
 		return nil, err
@@ -85,8 +104,8 @@ func (self *Invite) Encode() ([]byte, error) {
 	writer.WriteOpaqueLP(self.GroupId)
 	writer.WriteOpaqueLP(self.Welcome)
 	writer.WriteOpaqueLP(self.RatchetTree)
-	writer.WriteOpaqueLP(self.PqSecret)
-	writer.WriteOpaqueLP(self.GroupHandleKey)
+	writer.WriteOpaqueLP(self.JoinSeal)
+	writer.WriteOpaqueLP(self.JoinAuth)
 	encoded, err := writer.Bytes()
 	if err != nil {
 		return nil, fmt.Errorf("urmessage: encoding an invite: %w", err)
@@ -99,16 +118,12 @@ func (self *Invite) Encode() ([]byte, error) {
 //
 // A DAMAGED INVITE IS REFUSED HERE, AT THE PASTE, AND NOT ONE CALL AFTER THE JOIN. The last 32
 // octets are the SHA-256 of everything before them, and a blob whose checksum does not match is
-// [ErrInviteDamaged] before any field is read. That is the whole of what changed at version 0x0002,
-// and the reason is where a user is told: a truncated copy, a mangled paste or a carrier that
-// rewrote one octet used to PARSE, JOIN, and then fail at the first Receive with a sentence about
-// sender handles that no user can act on.
+// [ErrInviteDamaged] before any field is read.
 //
 // THE CHECKSUM IS NOT AN AUTHENTICATION AND MUST NOT BE READ AS ONE. Anybody who can change an
-// invite can recompute it. What stands between a hostile carrier and a group is what always stood
-// there -- the invite is key material and must travel over a channel that is already authenticated
-// and confidential -- and, one layer down, MLS: a Welcome addressed to a key package this device did
-// not publish is refused at the join whatever the checksum says.
+// invite can recompute it. What stands between a hostile carrier and this device is the join's own
+// checks: the Welcome must be addressed to a key package this device published, it must describe
+// the group the invite names, and the seal must carry a MAC made under that group's own epoch.
 func ParseInvite(encoded []byte) (*Invite, error) {
 	reader := syntax.NewReader(encoded)
 	version, err := reader.ReadUint16()
@@ -116,8 +131,8 @@ func ParseInvite(encoded []byte) (*Invite, error) {
 		return nil, fmt.Errorf("%w: it has no version: %w", ErrInviteDamaged, err)
 	}
 	if version != InviteVersion {
-		return nil, fmt.Errorf("urmessage: an invite at version %#04x, and this build reads only %#04x",
-			version, InviteVersion)
+		return nil, fmt.Errorf("%w: it is at version %#04x, and this build reads only %#04x",
+			ErrInviteVersion, version, InviteVersion)
 	}
 	if len(encoded) < 2+inviteChecksumBytes {
 		return nil, fmt.Errorf("%w: %d octets is shorter than a version and a checksum", ErrInviteDamaged, len(encoded))
@@ -140,8 +155,8 @@ func ParseInvite(encoded []byte) (*Invite, error) {
 		{"group_id", &invite.GroupId},
 		{"welcome", &invite.Welcome},
 		{"ratchet_tree", &invite.RatchetTree},
-		{"pq_secret", &invite.PqSecret},
-		{"group_handle_key", &invite.GroupHandleKey},
+		{"join_seal", &invite.JoinSeal},
+		{"join_auth", &invite.JoinAuth},
 	} {
 		value, err := reader.ReadOpaqueLP()
 		if err != nil {
```

`sdk/urmessage/joinseal.go`:

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -236,6 +236,106 @@ func epochKeysDigestOver(groupId []byte, epoch uint64, mlsSecret []byte, pqSecre
 	return digest, err
 }
 
+// sealJoinLocked builds the join seal and its authenticator for one joiner, OFF THE STAGED COMMIT
+// that adds it: nothing has been merged and nothing has been submitted, so a failure here is a
+// commit the caller clears and an add that can simply be made again.
+//
+// pqSecret is the secret of the epoch the staged commit opens, and epochKeysDigest is the digest
+// that epoch's commit publishes; both are the caller's, because the founding add and a live add
+// come by them differently and this function must not guess which it is serving.
+func (self *Group) sealJoinLocked(joiner *joinerKeys, welcome []byte, ratchetTree []byte,
+	opensEpoch uint64, pqSecret []byte, epochKeysDigest []byte) (joinSeal []byte, joinAuth []byte, err error) {
+
+	leaf, err := joinerLeafIn(ratchetTree, joiner.keyPackage)
+	if err != nil {
+		return nil, nil, err
+	}
+	payload, err := encodeJoinSecrets(pqSecret, self.groupHandleKey, epochKeysDigest)
+	if err != nil {
+		return nil, nil, err
+	}
+	defer zeroizeState(payload)
+	joinSeal, err = messagegroup.SealWrapBody(self.device.random, joiner.xwing, messagegroup.WrapEnvelope{
+		FormatVersion: messagegroup.WrapFormatVersion,
+		TargetType:    wrapTargetTypeJoiner,
+		PayloadType:   wrapPayloadTypeJoinSecrets,
+		ContentEpoch:  0,
+	}, self.id, joinerLeafId(leaf), payload)
+	if err != nil {
+		return nil, nil, fmt.Errorf("urmessage: sealing the join secrets to leaf %d: %w", leaf, err)
+	}
+	if len(joinSeal) != joinSealBytes {
+		return nil, nil, fmt.Errorf("urmessage: the join seal is %d octets and invite version 3 carries exactly %d", len(joinSeal), joinSealBytes)
+	}
+	joinKey, err := self.handle.PendingExport(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	if err != nil {
+		return nil, nil, fmt.Errorf("urmessage: the join key of epoch %d: %w", opensEpoch, err)
+	}
+	defer zeroizeState(joinKey)
+	preimage, err := joinAuthPreimage(self.id, opensEpoch, leaf, welcome, ratchetTree, joinSeal)
+	if err != nil {
+		return nil, nil, err
+	}
+	return joinSeal, self.device.crypto.Mac(joinKey, preimage), nil
+}
+
+// openJoinSeal is the joiner's half, in the order VERIFY, OPEN, CHECK: it answers the two secrets
+// only once the seal is authenticated, opens, has the right shape and reproduces the digest it
+// carries at the epoch this device joined.
+//
+// EVERY EXPECTATION IS THIS DEVICE'S OWN. The group id, the epoch and the leaf come off the handle
+// its own join built; the envelope's three octets and its zero epoch are constants; nothing is
+// copied out of the seal to judge the seal with.
+//
+// IT RUNS BEFORE THE JOINED STATE REACHES THE STORE, so every refusal here costs nothing: see
+// [joinStage].
+func (self *Device) openJoinSeal(handle messagegroup.GroupHandle, invite *Invite) (pqSecret []byte, groupHandleKey []byte, err error) {
+	leaf := handle.OwnLeafIndex()
+	epoch := handle.Epoch()
+
+	// VERIFY: join_auth over the received octets, under this epoch's own exporter.
+	joinKey, err := handle.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	if err != nil {
+		return nil, nil, fmt.Errorf("urmessage: the join key of epoch %d: %w", epoch, err)
+	}
+	defer zeroizeState(joinKey)
+	preimage, err := joinAuthPreimage(handle.GroupId(), epoch, leaf, invite.Welcome, invite.RatchetTree, invite.JoinSeal)
+	if err != nil {
+		return nil, nil, err
+	}
+	if !self.crypto.MacVerify(joinKey, preimage, invite.JoinAuth) {
+		return nil, nil, ErrJoinSealUnauthenticated
+	}
+
+	// OPEN: to this device's own leaf key, stating the wrap it is honouring.
+	_, payload, err := self.openWrapToOwnLeaf(handle.GroupId(), 0, wrapTargetTypeJoiner,
+		joinerLeafId(leaf), wrapPayloadTypeJoinSecrets, invite.JoinSeal)
+	if err != nil {
+		return nil, nil, fmt.Errorf("%w: %w", ErrJoinSealUnreadable, err)
+	}
+	defer zeroizeState(payload)
+
+	// CHECK: the shape, and that the secret is the one this epoch's published keys come from.
+	pqSecret, groupHandleKey, sealedDigest, err := decodeJoinSecrets(payload)
+	if err != nil {
+		return nil, nil, err
+	}
+	mlsSecret, err := handle.Export(storageExporterLabel, nil, storageExporterBytes)
+	if err != nil {
+		zeroizeState(pqSecret)
+		zeroizeState(groupHandleKey)
+		return nil, nil, fmt.Errorf("urmessage: the exporter of epoch %d: %w", epoch, err)
+	}
+	computed, err := epochKeysDigestOver(handle.GroupId(), epoch, mlsSecret, pqSecret)
+	zeroizeState(mlsSecret)
+	if err != nil || subtle.ConstantTimeCompare(computed, sealedDigest) != 1 {
+		zeroizeState(pqSecret)
+		zeroizeState(groupHandleKey)
+		return nil, nil, fmt.Errorf("%w: at epoch %d", ErrJoinSealWrongEpoch, epoch)
+	}
+	return pqSecret, groupHandleKey, nil
+}
+
 // sameDigest compares two H(epoch_keys) values, and answers false for one that is absent. The
 // values are published, so nothing here is secret; it goes through subtle because every comparison
 // of key-derived octets in this package does.
```

`sdk/urmessage/group.go`:

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -838,6 +838,11 @@ type Group struct {
 	// the record the server stores as is_commit actually carries a commit.
 	commit []byte
 
+	// foundingJoinDigest is H(epoch_keys) of epoch one AS [Group.AddMember] SEALED IT INTO THE
+	// INVITE, kept for [Group.Open] to hold the digest it publishes against. It is a digest and
+	// not a key. Nil on every group but a founder's between its add and its open.
+	foundingJoinDigest []byte
+
 	opened bool
 	closed bool
 
@@ -1469,7 +1474,22 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (joined *Group, er
 		return nil, fmt.Errorf("%w: the welcome stands at epoch %d and this device was removed at epoch %d",
 			ErrReaddStale, handle.Epoch(), removedEpoch)
 	}
-	session, err = messagegroup.NewGroupSession(handle, invite.PqSecret, invite.GroupHandleKey,
+	// THE JOIN SEAL: verified, opened and checked, in that order, before anything is honoured. See
+	// [Device.openJoinSeal]. The two secrets exist in this function only from here.
+	pqSecret, groupHandleKey, err := self.openJoinSeal(handle, invite)
+	if err != nil {
+		return nil, err
+	}
+	// the epoch's secret is this function's copy, and the group below files a copy of its own
+	defer zeroizeState(pqSecret)
+	// the handle key is the group's once the join has committed; a refusal made between here and
+	// the commit erases it with everything else that refusal leaves
+	defer func() {
+		if !committed {
+			zeroizeState(groupHandleKey)
+		}
+	}()
+	session, err = messagegroup.NewGroupSession(handle, pqSecret, groupHandleKey,
 		self.reserver, self.nowMs, nonce)
 	if err != nil {
 		return nil, fmt.Errorf("urmessage: the session at epoch %d: %w", handle.Epoch(), err)
@@ -1491,12 +1511,12 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (joined *Group, er
 		device:         self,
 		id:             append([]byte(nil), invite.GroupId...),
 		handle:         handle,
-		groupHandleKey: append([]byte(nil), invite.GroupHandleKey...),
-		// AT THE EPOCH THE WELCOME ADMITTED THIS DEVICE AT, and at no other. MASTER section 7's
-		// out-of-band delivery is what an [Invite] is: the joiner is handed the secret of the
-		// epoch it is joining, it was not present for any epoch below and can vouch for none of
-		// them, and every epoch ABOVE arrives through that epoch's own device wrap.
-		pqSecrets:    map[uint64][]byte{handle.Epoch(): append([]byte(nil), invite.PqSecret...)},
+		groupHandleKey: groupHandleKey,
+		// AT THE EPOCH THE WELCOME ADMITTED THIS DEVICE AT, and at no other. The join seal hands
+		// the joiner the secret of the epoch it is joining; it was not present for any epoch below
+		// and can vouch for none of them, and every epoch ABOVE arrives through that epoch's own
+		// device wrap.
+		pqSecrets:    map[uint64][]byte{handle.Epoch(): append([]byte(nil), pqSecret...)},
 		session:      session,
 		sessionBound: nonceEpoch,
 		epoch:        handle.Epoch(),
@@ -1584,13 +1604,29 @@ func (self *Group) AddMember(keyPackage []byte) (*Invite, error) {
 	// call takes N key packages: one commit admits N members. Nothing is staged on its refusal,
 	// and mls refuses the same things it refused through ProposeAdd, at the same call.
 	// THE JOIN CODE IS JUDGED BEFORE ANYTHING IS BUILT: see [Device.joinerOf].
-	if _, err := self.device.joinerOf(keyPackage); err != nil {
+	joiner, err := self.device.joinerOf(keyPackage)
+	if err != nil {
 		return nil, err
 	}
 	commit, welcome, ratchetTree, err := self.handle.CommitAdd([][]byte{keyPackage})
 	if err != nil {
 		return nil, joinerAlreadyHasALeaf(fmt.Errorf("urmessage: CommitAdd: %w", err))
 	}
+	// THE JOIN SEAL, OFF THE STAGED COMMIT AND BEFORE THE MERGE. Everything the seal binds is
+	// readable now -- the epoch the commit opens, that epoch's exporter, the leaf the joiner was
+	// installed at -- and nothing is irrevocable yet, so a failure here clears the staged commit
+	// and this call can simply be made again. After the merge it could not: the group would stand
+	// at epoch one with a member nobody can hand an invite to.
+	//
+	// THE SECRET IS EPOCH ZERO'S, which is the one epoch change that does not rotate: see the
+	// paragraph below the merge. [Group.epoch] has not moved, so this read and that one are one
+	// value.
+	foundingSecret := self.pqSecretLocked()
+	joinSeal, joinAuth, joinDigest, err := self.sealFoundingJoinLocked(joiner, welcome, ratchetTree, foundingSecret)
+	if err != nil {
+		self.handle.ClearPendingCommit()
+		return nil, err
+	}
 	if err := self.handle.MergePendingCommit(); err != nil {
 		return nil, fmt.Errorf("urmessage: MergePendingCommit: %w", err)
 	}
@@ -1609,10 +1645,9 @@ func (self *Group) AddMember(keyPackage []byte) (*Invite, error) {
 	// than an exception. The device wrap is what delivers a rotated secret, a wrap is addressed to
 	// a leaf's published X-Wing key, and at this moment the only OTHER member of this group has
 	// not joined yet -- it is holding the Welcome this call is about to answer. Its copy of epoch
-	// one's secret is [Invite.PqSecret], out of band, MASTER section 7's founding delivery. So
+	// one's secret is inside [Invite.JoinSeal], sealed to the key that leaf will publish. So
 	// epoch one's entry is filed here as a COPY of epoch zero's, deliberately and once, and every
 	// commit to an OPEN group from then on draws a fresh one ([Group.publishCommitLocked]).
-	foundingSecret := self.pqSecretLocked()
 	self.filePqSecretLocked(self.handle.Epoch(), foundingSecret)
 	session, err := messagegroup.NewGroupSession(self.handle, foundingSecret, self.groupHandleKey,
 		self.device.reserver, self.device.nowMs, nonce)
@@ -1650,18 +1685,46 @@ func (self *Group) AddMember(keyPackage []byte) (*Invite, error) {
 	if err := self.enterEpochLocked(); err != nil {
 		return nil, err
 	}
-	// THE SECRET OF THE EPOCH THIS INVITE ADMITS INTO, read out of the table after the entry above
-	// rather than off a field that used to mean one thing forever. [Device.Join] files it at
-	// `handle.Epoch()`, which is the same epoch, and the two sides are two reads of one value.
+	// THE INVITE CARRIES THE SEAL MADE ABOVE, off the staged commit: the secret of the epoch it
+	// admits into is inside it and nowhere else in what is returned. [Device.Join] files what it
+	// opens at `handle.Epoch()`, which is the epoch that secret was sealed for.
+	self.foundingJoinDigest = joinDigest
 	return &Invite{
-		GroupId:        append([]byte(nil), self.id...),
-		Welcome:        append([]byte(nil), welcome...),
-		RatchetTree:    append([]byte(nil), ratchetTree...),
-		PqSecret:       append([]byte(nil), self.pqSecretLocked()...),
-		GroupHandleKey: append([]byte(nil), self.groupHandleKey...),
+		GroupId:     append([]byte(nil), self.id...),
+		Welcome:     append([]byte(nil), welcome...),
+		RatchetTree: append([]byte(nil), ratchetTree...),
+		JoinSeal:    joinSeal,
+		JoinAuth:    joinAuth,
 	}, nil
 }
 
+// sealFoundingJoinLocked is [Group.sealJoinLocked] for the FOUNDING add, where there is no staged
+// rotation to read the epoch's digest off: it computes H(epoch_keys) of the epoch the staged commit
+// opens from that epoch's exporter and the secret the caller names, and answers it beside the seal
+// so that [Group.Open] can hold what it publishes against what was sealed.
+func (self *Group) sealFoundingJoinLocked(joiner *joinerKeys, welcome []byte, ratchetTree []byte,
+	foundingSecret []byte) (joinSeal []byte, joinAuth []byte, joinDigest []byte, err error) {
+
+	pending, err := self.handle.PendingEpoch()
+	if err != nil {
+		return nil, nil, nil, fmt.Errorf("urmessage: the epoch the founding commit opens: %w", err)
+	}
+	mlsSecret, err := self.handle.PendingExport(storageExporterLabel, nil, storageExporterBytes)
+	if err != nil {
+		return nil, nil, nil, fmt.Errorf("urmessage: the exporter of epoch %d: %w", pending.Epoch, err)
+	}
+	joinDigest, err = epochKeysDigestOver(self.id, pending.Epoch, mlsSecret, foundingSecret)
+	zeroizeState(mlsSecret)
+	if err != nil {
+		return nil, nil, nil, err
+	}
+	joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, pending.Epoch, foundingSecret, joinDigest)
+	if err != nil {
+		return nil, nil, nil, err
+	}
+	return joinSeal, joinAuth, joinDigest, nil
+}
+
 // Open publishes this group on the message server: 6.1's founding commit, the epoch's wrap set,
 // and the marker that closes the fan-out.
 //
@@ -1717,7 +1780,7 @@ func (self *Group) Open(ctx context.Context) error {
 	// THE FOUNDING FAN-OUT IS THE ONE THAT CARRIES NO KEY MATERIAL, and it stays that way. Every
 	// other epoch's fan-out delivers pq_secret[n+1] under X-Wing to each leaf that is already a
 	// member; at epoch one there is no such leaf -- the only other member is holding the Welcome
-	// and takes its copy out of band in [Invite.PqSecret], MASTER section 7's founding delivery.
+	// and takes its copy out of the join seal its [Invite] carries.
 	// A wrap addressed to a leaf for a secret the device at that leaf already has would be a second
 	// copy of the same value on the wire for nothing. See [alphaWrapBody], and pqepoch.go's header.
 	//
@@ -1755,6 +1818,13 @@ func (self *Group) Open(ctx context.Context) error {
 	if err != nil {
 		return fmt.Errorf("urmessage: the digest of the keys epoch %d opens with: %w", self.epoch, err)
 	}
+	// THE DIGEST THE INVITE WAS SEALED OVER, OR NOTHING IS PUBLISHED. [Group.AddMember] computed
+	// it off the staged commit and this is the same value off the session; the joiner recomputes
+	// it a third time and refuses an invite it does not reproduce. Two derivations in one build
+	// are held together here rather than assumed to agree.
+	if !sameDigest(self.foundingJoinDigest, foundingDigest.EpochKeysDigest) {
+		return fmt.Errorf("%w: epoch %d", ErrInviteDigestDrift, self.epoch)
+	}
 	founding, err := self.founding.SealRecord(message.RetentionPermanent, 0, true,
 		encodeHead(self.device.nowMs()), self.commit, 0, &message.ServerAttachment{
 			Kind:        message.AttachmentEpochDigest,
@@ -1902,7 +1972,8 @@ func (self *Group) AddMemberAndPublish(ctx context.Context, keyPackage []byte) (
 	// THE JOIN CODE IS JUDGED BEFORE ANYTHING IS BUILT: see [Device.joinerOf]. The role model
 	// stands ahead of it, because who may add is a fact about this device and is answered the
 	// same way whatever the join code is.
-	if _, err := self.device.joinerOf(keyPackage); err != nil {
+	joiner, err := self.device.joinerOf(keyPackage)
+	if err != nil {
 		return nil, err
 	}
 
@@ -1917,21 +1988,27 @@ func (self *Group) AddMemberAndPublish(ctx context.Context, keyPackage []byte) (
 	// (2)-(5) announce, submit, and -- once the server has taken it -- merge, enter and fan out
 	// the epoch the commit opens. A refusal erases the staged epoch and answers here with nothing
 	// moved; the key package is the joiner's and a retry after Receive may offer it again.
-	if err := self.publishCommitLocked(ctx, commit, nil); err != nil {
+	//
+	// THE JOIN SEAL IS MADE INSIDE THE PUBLISH, BEFORE ANYTHING IS SUBMITTED, over the two values
+	// the publish itself decided: the ROTATED secret of the epoch the commit opens, which no wrap
+	// can carry to a leaf that does not exist yet, and the digest that epoch's commit record is
+	// about to publish. It is not the table's current entry: until the server has taken the
+	// commit that entry is the epoch that is closing.
+	var joinSeal, joinAuth []byte
+	seal := func(opensEpoch uint64, pqSecret []byte, epochKeysDigest []byte) error {
+		var err error
+		joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, opensEpoch, pqSecret, epochKeysDigest)
+		return err
+	}
+	if err := self.publishCommitLocked(ctx, commit, seal); err != nil {
 		return nil, err
 	}
-
-	// THE ROTATED SECRET AND NOT THE ONE THE GROUP HAD A MOMENT AGO. publishCommitLocked drew
-	// pq_secret[n+1], fanned it out to the members that were already here and entered the epoch,
-	// so the table's current entry IS the new epoch's -- which is what this joiner needs and what
-	// no wrap could have carried to it, because the leaf it will occupy did not exist when the
-	// fan-out was sealed. See [Group.wrapTargetsAtLocked]'s Add arm.
 	return &Invite{
-		GroupId:        append([]byte(nil), self.id...),
-		Welcome:        append([]byte(nil), welcome...),
-		RatchetTree:    append([]byte(nil), ratchetTree...),
-		PqSecret:       append([]byte(nil), self.pqSecretLocked()...),
-		GroupHandleKey: append([]byte(nil), self.groupHandleKey...),
+		GroupId:     append([]byte(nil), self.id...),
+		Welcome:     append([]byte(nil), welcome...),
+		RatchetTree: append([]byte(nil), ratchetTree...),
+		JoinSeal:    joinSeal,
+		JoinAuth:    joinAuth,
 	}, nil
 }
 
```

`sdk/urmessage/errors.go`:

```diff
--- a/sdk/urmessage/errors.go
+++ b/sdk/urmessage/errors.go
@@ -48,13 +48,30 @@ var (
 	// told, and never at the join or at the first Receive after it.
 	ErrInviteDamaged = errors.New("urmessage: this invite is damaged: it is not the octets the founder encoded")
 
-	// THE REFUSALS OF THE JOIN SEAL INSIDE THE JOIN. Each is made before the joined state reaches
-	// the store, so the store is as it was and the join code is not spent: the honest invite,
-	// pasted again, still joins.
-	//
+	// An invite at a version this build does not read. Version 0x0002 is among them, deliberately:
+	// it carried the join secrets in the clear, and reading one would be installing two secrets
+	// whoever pasted it chose.
+	ErrInviteVersion = errors.New("urmessage: this invite is at a version this build does not read")
+
+	// An invite whose join seal is not the shape version 0x0003 fixes: its length, its
+	// authenticator's length, or the four constants of its envelope. Refused at the paste, before
+	// a join code is touched.
+	ErrJoinSealShape = errors.New("urmessage: this invite's join seal is not the shape an invite carries")
+
+	// THE FOUR REFUSALS OF THE JOIN SEAL INSIDE THE JOIN. Each is made before the joined state
+	// reaches the store, so the store is as it was and the join code is not spent: the honest
+	// invite, pasted again, still joins.
+	//
+	// Unauthenticated: the seal's MAC is not one a member of the epoch this Welcome opened made
+	// for this leaf, this Welcome and this tree. A seal an outsider made to this device's public
+	// key, a seal lifted from another invite, and an invite altered on the way all answer this.
+	ErrJoinSealUnauthenticated = errors.New("urmessage: this invite's join seal was not made by a member of the group it joins, for this invite")
 	// Unreadable: the seal is authenticated and does not open to this device's leaf key, or opens
 	// to something that is not join_secrets_v1.
 	ErrJoinSealUnreadable = errors.New("urmessage: this invite's join seal does not open to this device")
+	// Wrong epoch: the seal opened, and the secret in it does not reproduce the digest of the keys
+	// the epoch this device joined was opened with. The adder sealed some other epoch's secret.
+	ErrJoinSealWrongEpoch = errors.New("urmessage: this invite's join seal carries a secret that is not the one the epoch it joins runs on")
 
 	// A record came back that a key should have opened and did not.
 	ErrRecordOpen = errors.New("urmessage: a record from a member of this group did not open")
@@ -834,4 +851,9 @@ var (
 	// invitation that was made and never opened. A group holds one leaf per identity it admits
 	// this way, so the leaf that stands is removed first.
 	ErrJoinerAlreadyHasALeaf = errors.New("urmessage: this identity already has an entry in this group, perhaps from an invitation that was never opened; remove that entry, then add the new join code")
+
+	// [Group.Open] found that the digest of the keys it is about to publish epoch one with is not
+	// the digest [Group.AddMember] sealed into the invite. The joiner would refuse that invite, so
+	// the group is not published under it.
+	ErrInviteDigestDrift = errors.New("urmessage: the keys this group would open with are not the keys its invite was sealed over")
 )
```

`sdk/urmessage/pqepoch.go`:

```diff
--- a/sdk/urmessage/pqepoch.go
+++ b/sdk/urmessage/pqepoch.go
@@ -1132,7 +1132,8 @@ func (self *Group) resolvePqSecretLocked(mlsSecret []byte, opensEpoch uint64,
 //  1. THE SUBJECT IS THE RECEIVER'S OWN HISTORY, SO A LATE JOINER REFUSES LESS, AND ITS FALSE
 //     NEGATIVE IS A THEOREM AND NOT A BUG. [Group.pqSecretHeldAtLocked] answers over
 //     [Group.pqSecretWitness], which is every pq_secret THIS DEVICE has filed. [Device.Join] files
-//     exactly ONE row -- `pqSecrets: {handle.Epoch(): invite.PqSecret}` and nothing else -- so a
+//     exactly ONE row -- `pqSecrets: {handle.Epoch(): pqSecret}`, the secret its join seal
+//     opened to, and nothing else -- so a
 //     member admitted at epoch k has a history STRICTLY SMALLER than a founder's and answers *not
 //     held* for octets a founder answers *held* for. Measured for ledger item 254 at
 //     `connect 74abe029` / `sdk 8b59a96`: after two honest rotations a founder holds 3 live rows
@@ -1380,9 +1381,9 @@ func parseLeafWrapKey(leafKeys []byte) ([]byte, error) {
 //     staged commit itself. That exclusion is the whole of item 243 -- the removed member gets no
 //     wrap, so it holds no pq_secret[n+1], so it derives no storage_root[n+1].
 //   - AN ADD: the added leaf is not in the live tree and gets no wrap. It does not need one: a
-//     joiner receives the epoch's secret in [Invite.PqSecret], out of band through the Welcome,
-//     which MASTER section 7 has always been the founding delivery and which
-//     [Group.AddMemberAndPublish] answers AFTER the rotation has filed the new epoch's value. So
+//     joiner receives the epoch's secret in its invite's join seal ([Invite.JoinSeal]), sealed to
+//     the key its own leaf publishes, which [Group.AddMemberAndPublish] makes inside the publish
+//     over the ROTATED value. So
 //     NO EQUALITY BETWEEN THIS LIST'S LENGTH AND pending.MemberCount HOLDS in either direction:
 //     it is false on every Add, which is the shape two separate passes offered as a one-line
 //     invariant for this function and which fires on [Group.AddMemberAndPublish].
```

`sdk/urmessage/statestore_durable.go`:

```diff
--- a/sdk/urmessage/statestore_durable.go
+++ b/sdk/urmessage/statestore_durable.go
@@ -138,8 +138,8 @@ var _ DeviceStore = (*DurableStateStore)(nil)
 //
 // EVERYTHING ON IT IS SECRET IN FULL. The identity private key speaks as this device in every
 // group it is in; the wrap seed opens every X-Wing encapsulation addressed to this device's leaf;
-// a [GroupRecord] carries two of the [Invite]'s four values, and whoever holds those plus the MLS
-// state this store keeps beside them is in the group.
+// a [GroupRecord] carries the two values an [Invite]'s join seal delivers, and whoever holds those
+// plus the MLS state this store keeps beside them is in the group.
 type DeviceStore interface {
 	mls.StateStore
 
@@ -291,7 +291,8 @@ type SentRecord struct {
 // GroupRecord is the urmessage-side state of one group: the values that do not live in MLS and
 // that [Device.Restore] cannot rebuild a session without.
 //
-// IT IS SECRET IN FULL. PqSecret and GroupHandleKey are two of the [Invite]'s four values; see
+// IT IS SECRET IN FULL. PqSecret and GroupHandleKey are the two values an [Invite]'s join seal
+// delivers; see
 // [DurableStateStore] for what does and does not protect them on the disk.
 type GroupRecord struct {
 	// The 32 octet group id the server keys its rows by.
```

`sdk/cgo/exports_message.go`:

```diff
--- a/sdk/cgo/exports_message.go
+++ b/sdk/cgo/exports_message.go
@@ -933,11 +933,11 @@ func urnet_message_group_add_member_and_publish(self C.uint64_t, ctx C.uint64_t,
 	return C.uint64_t(newHandle(invite))
 }
 
-// urnet_message_invite_encode is the buffer-out pattern. WHAT COMES OUT IS KEY MATERIAL: two of
-// an invite's four fields are secret (pq_secret, and the MLS init secret inside the Welcome), so
-// an invite that reaches a third party is a group that third party is in. Move it the way you
-// would move a private key, once, over a channel that is already authenticated and already
-// confidential, and destroy it afterwards.
+// urnet_message_invite_encode is the buffer-out pattern. TREAT WHAT COMES OUT AS SECRET. Since
+// invite version 3 it carries no secret in the clear: the join secrets are sealed to the joiner's
+// own device key. It still carries the Welcome, which is sealed classically, and it names the
+// group and who is in it. Move it the way you would move a private key, once, over a channel that
+// is already authenticated and already confidential, and destroy it afterwards.
 //
 //export urnet_message_invite_encode
 func urnet_message_invite_encode(self C.uint64_t, out *C.uint8_t, inoutLen *C.int32_t, outError **C.char) C.bool {
```

`sdk/livepeer/main.go`:

```diff
--- a/sdk/livepeer/main.go
+++ b/sdk/livepeer/main.go
@@ -22,9 +22,9 @@
 // is what makes "the file is there" mean "the file is fresh".
 //
 // WHAT IS SECRET HERE. The credential is an operator-minted by_client_jwt and is read from a path;
-// it is never printed. The INVITE is key material in full — an invite that reaches a third party is
-// a group that third party is in — so it is written 0600 to a path outside any repository and
-// deleted as soon as it is consumed. Neither is ever formatted into a log line.
+// it is never printed. The INVITE is treated as secret — it carries the Welcome, and it names the
+// group and who is in it — so it is written 0600 to a path outside any repository and deleted as
+// soon as it is consumed. Neither is ever formatted into a log line.
 //
 // NEVER RUN THIS UNDER THE APP'S OWN ACCOUNT. Two clients at one client_id, or two state
 // directories descended from one, is two devices at ONE MLS leaf: one sender_handle, one stream
```

`sdk/livepeer/README.md`:

```diff
--- a/sdk/livepeer/README.md
+++ b/sdk/livepeer/README.md
@@ -53,9 +53,9 @@ joined will simply wait, because no key package is published.
   each gets its own `-dir`.
 * **The credential is a secret.** It is read from a path and never printed; the only thing said
   about it is its length.
-* **The invite is key material in full.** Whoever reads it is in the group. It is written 0600, to
-  a path outside any repository, and deleted as soon as it has been used. Neither file may ever
-  enter a working tree.
+* **Treat the invite as secret.** It carries the Welcome, and it names the group and who is in
+  it. It is written 0600, to a path outside any repository, and deleted as soon as it has been
+  used. Neither file may ever enter a working tree.
 * **`-dir` must not be inside a repo either** — it holds the durable MLS state.
 
 ## What it asserts, and what it does not
```

- [ ] **Step 4: the gates this moves.** The censuses moved, and every entry below was written against what the two gates printed: the pq_secret census loses 15 entries, gains 28 (one of them `openJoinSeal`, a name in its producer net) and has 4 rewritten because the values they carry moved; the epoch-key census gains 1. The third file is a comment in a test that named the removed field.

`sdk/urmessage/pqsecretgate_test.go`:

```diff
--- a/sdk/urmessage/pqsecretgate_test.go
+++ b/sdk/urmessage/pqsecretgate_test.go
@@ -79,9 +79,11 @@ import (
 //     `table` are wide on purpose: they are the names the value has when it has no name of its
 //     own, which is the gap the wrap-seed gate's `parts` entry was added to close.
 //   - `into` IS THE INVITE DECODE'S POINTER TABLE, and it is here for one shape: `field.into` is
-//     a `*[]byte` aimed at `invite.PqSecret`, so a `%x` of `*field.into` in ParseInvite's own
-//     refusal would be a secret in an error string. Without this name that expression carries only
-//     `field`, which the refusal is already permitted to format.
+//     a `*[]byte` aimed at a field of the invite, so a `%x` of `*field.into` in ParseInvite's own
+//     refusal would be that field in an error string. Since invite version 3 no field it aims at
+//     is a secret in the clear. The name stays, so that a secret field given to an invite later is
+//     in this net from the day it is added. Without it that expression carries only `field`,
+//     which the refusal is already permitted to format.
 //   - `parts` IS THE DURABLE RECORD'S ROAD, in BOTH directions, and it is here because a mutant
 //     survived without it. It is seeded as a PARAMETER only -- [groupRecordOf] on the read side,
 //     [DurableStateStore.writeRecord] and [encodeStateRecord] on the write side -- which is what
@@ -90,6 +92,7 @@ import (
 //     inside the group record's own decode, survived the whole suite while that decode was the
 //     body of a loop and its record had no name a walk could seed.
 var pqSecretProducerNames = map[string]bool{
+	"openJoinSeal":          true,
 	"decodeJoinSecrets":     true,
 	"NewPqSecret":           true,
 	"OpenWrapBody":          true,
@@ -131,22 +134,15 @@ var pqSecretProducerSites = map[string]string{
 	"decodeJoinSecrets|result groupHandleKey":  "the second third: the group's handle key, which is secret, and is held to the same dispositions as the secret beside it.",
 	"decodeJoinSecrets|result pqSecret":        "the first third of the payload: the secret of the epoch the joiner is admitted at.",
 	"decodeJoinSecrets|parameter pqSecret":     "the named result the first third of an opened join_secrets_v1 is answered through.",
-	"AddMemberAndPublish|self.pqSecretLocked": "the same read after the rotation has run, so the invite carries pq_secret[n+1] and not " +
-		"the secret the group is standing on.",
-	"AddMember|self.pqSecretLocked": "THE FOUNDING EPOCH'S SECRET READ BACK FOR THE WELCOME. Epoch one's secret travels in " +
-		"[Invite.PqSecret] -- MASTER section 7's out-of-band delivery -- because the only other " +
+	"AddMember|self.pqSecretLocked": "THE FOUNDING EPOCH'S SECRET, READ FOR THE JOIN SEAL. Epoch one's secret travels sealed " +
+		"inside [Invite.JoinSeal], to the key the joiner's leaf publishes, because the only other " +
 		"member is holding the Welcome and has no leaf to address a wrap to yet.",
 	"CreateGroup|messagegroup.NewPqSecret": "THE FOUNDING DRAW. The group's first pq_secret, at epoch zero, and the only one drawn " +
 		"outside [Group.stageEpochRotationLocked].",
-	"Encode|self.PqSecret": "the wire write: the same field going out under an LP prefix.",
-	"Join|invite.PqSecret": "the joiner's arrival: the secret of the epoch it is admitted at, off the invite it was " +
-		"handed.",
 	"ParseInvite|field.into":                        "T",
-	"ParseInvite|invite.PqSecret":                   "the wire decode's DESTINATION, in the five-field table ParseInvite walks.",
 	"PutGroupRecord|encodePqSecretTable":            "the table as the one octet string part six is.",
 	"PutGroupRecord|record.PqSecret":                "the scalar the record still carries, part two.",
 	"PutGroupRecord|record.PqSecrets":               "the table, part six, or nil for a caller that built neither.",
-	"check|self.PqSecret":                           "the invite's own validity check, which refuses one carrying no secret.",
 	"decodePqSecretTable|result rows":               "the rows read back out of it.",
 	"dropPqSecretsBelowWindowLocked|self.pqSecrets": "the window's own pass: every entry PastEpochWindow behind is erased and dropped.",
 	"dropWrapCandidatesLocked|candidate.secret":     "every staged candidate for a resolved epoch, on its way to the erase.",
@@ -244,6 +240,13 @@ var pqSecretProducerSites = map[string]string{
 		"wrapseedgate_test.go added for the seed, seeded by the same clause.",
 	"zeroizePqSecretsLocked|self.pqSecrets":        "the whole-table erase at [Group.Close].",
 	"zeroizeWrapCandidatesLocked|candidate.secret": "the same, whatever epoch it is for, at Close.",
+	"openJoinSeal|self.openWrapToOwnLeaf":          "THE OPEN: the join seal, to this device's own X-Wing key, through the one door every later epoch's wrap is opened through.",
+	"openJoinSeal|decodeJoinSecrets":               "the three values cut out of the opened payload.",
+	"openJoinSeal|parameter pqSecret":              "the named result the joiner's half answers the secret through.",
+	"sealJoinLocked|parameter pqSecret":            "the secret of the epoch the staged commit opens, handed in by whichever adder is sealing.",
+	"Join|self.openJoinSeal":                       "THE JOINER'S ARRIVAL SINCE INVITE VERSION 3: the two secrets of the epoch it is admitted at, opened from the invite's join seal inside the join's window. An invite no longer carries either in the clear.",
+	"openJoinSeal|result pqSecret":                 "what the joiner's half answers once the seal is authenticated, opened and checked.",
+	"openJoinSeal|result groupHandleKey":           "the same, for the group's handle key.",
 }
 
 var pqSecretSinks = map[string]pqSecretSink{
@@ -295,23 +298,10 @@ var pqSecretSinks = map[string]pqSecretSink{
 		carries: []string{"payload", "pqSecret"},
 		why:     "the payload's assembly, into a buffer of exactly its length.",
 	},
-	"AddMemberAndPublish|call append": {
-		carries: []string{"self.pqSecretLocked"},
-		why:     "the same copy after the rotation.",
-	},
-	"AddMemberAndPublish|literal Invite.PqSecret": {
-		carries: []string{"self.pqSecretLocked"},
-		why: "the same delivery, now carrying pq_secret[n+1] because the rotation has already filed " +
-			"it.",
-	},
 	"AddMember|assign self.session": {
 		carries: []string{"session"},
 		why:     "that session parked on the group.",
 	},
-	"AddMember|call append": {
-		carries: []string{"self.pqSecretLocked"},
-		why:     "the copy the invite carries.",
-	},
 	"AddMember|call messagegroup.NewGroupSession": {
 		carries: []string{"foundingSecret"},
 		why:     "the session built over it.",
@@ -321,12 +311,6 @@ var pqSecretSinks = map[string]pqSecretSink{
 		why: "the founding epoch's secret filed at the epoch the handle is standing at, which is where " +
 			"the table's first row comes from for a founder that has not yet committed.",
 	},
-	"AddMember|literal Invite.PqSecret": {
-		carries: []string{"self.pqSecretLocked"},
-		why: "THE OUT-OF-BAND DELIVERY, MASTER section 7's founding arm. It is the one place a secret " +
-			"leaves this package unsealed, and the invite is a value the caller hands over some " +
-			"channel of its own.",
-	},
 	"CreateGroup|call messagegroup.GroupHandleKey": {
 		carries: []string{"pqSecret"},
 		why: "the group_handle_key, derived from that root. It carries `pqSecret` because the root " +
@@ -363,19 +347,6 @@ var pqSecretSinks = map[string]pqSecretSink{
 		carries: []string{"group"},
 		why:     "the same group handed back.",
 	},
-	"Encode|call writer.WriteOpaqueLP": {
-		carries: []string{"self.PqSecret"},
-		why: "THE INVITE'S WIRE WRITE. The secret goes out under an LP prefix, in the clear, because " +
-			"the invite itself is the out-of-band channel.",
-	},
-	"Join|call append": {
-		carries: []string{"invite.PqSecret"},
-		why:     "the joiner's own copy for its table.",
-	},
-	"Join|call messagegroup.NewGroupSession": {
-		carries: []string{"invite.PqSecret"},
-		why:     "the joiner's session, built over the secret of the epoch it is admitted at.",
-	},
 	"Join|call self.holdReplacing": {
 		carries: []string{"group"},
 		why: "the group going onto the device, in place of the one a commit removed this device from " +
@@ -385,10 +356,6 @@ var pqSecretSinks = map[string]pqSecretSink{
 		carries: []string{"group"},
 		why:     "the group's first record going to disk.",
 	},
-	"Join|literal ?.handle.Epoch(...)": {
-		carries: []string{"invite.PqSecret"},
-		why:     "that copy filed at the handle's epoch.",
-	},
 	"Join|literal Group.session": {
 		carries: []string{"session"},
 		why:     "the session parked on the group.",
@@ -397,23 +364,6 @@ var pqSecretSinks = map[string]pqSecretSink{
 		carries: []string{"group"},
 		why:     "the same group handed back.",
 	},
-	"ParseInvite|call fmt.Errorf": {
-		carries: []string{"field"},
-		why: "THE ONE FORMATTING SITE IN THE INVITE'S DECODE, and the operand is `field.name` -- one " +
-			"of five string constants written three lines above. It carries `field` because `field` " +
-			"is a struct the walk taints wholesale through the `&invite.PqSecret` in its literal. A " +
-			"`%x` of `field.into` would carry `field.into`, which this entry does not list, and would " +
-			"be refused.",
-	},
-	"ParseInvite|literal ?.element 1": {
-		carries: []string{"invite.PqSecret"},
-		why: "the ADDRESS of the field the decoder fills, in the five-field table. What lands is a " +
-			"*[]byte and never octets.",
-	},
-	"ParseInvite|return": {
-		carries: []string{"field"},
-		why:     "that error.",
-	},
 	"PutGroupRecord|call encodePqSecretTable": {
 		carries: []string{"rows"},
 		why:     "the rows going to the encoder.",
@@ -1025,13 +975,92 @@ var pqSecretSinks = map[string]pqSecretSink{
 		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
 			"can still reach these octets. Here it is every candidate at all, at Close.",
 	},
+	"sealJoinLocked|call messagegroup.SealWrapBody": {
+		carries: []string{"payload"},
+		why:     "THE ONE PLACE THE JOIN SECRETS LEAVE THIS DEVICE: sealed to the X-Wing key the joiner's own leaf publishes.",
+	},
+	"sealJoinLocked|call encodeJoinSecrets": {
+		carries: []string{"pqSecret"},
+		why:     "into join_secrets_v1.",
+	},
+	"sealJoinLocked|call joinAuthPreimage": {
+		carries: []string{"joinSeal"},
+		why:     "the SEALED octets, hashed into the authenticator's preimage. Ciphertext.",
+	},
+	"sealJoinLocked|return": {
+		carries: []string{"joinSeal", "preimage"},
+		why:     "the seal and its authenticator, to the adder that puts them in the invite.",
+	},
+	"openJoinSeal|return": {
+		carries: []string{"groupHandleKey", "pqSecret"},
+		why:     "the two secrets, to Join, only once the seal is authenticated, opened and checked.",
+	},
+	"AddMember|literal Invite.JoinSeal": {
+		carries: []string{"joinSeal"},
+		why:     "THE INVITE'S FOURTH FIELD SINCE VERSION 3: the two secrets sealed to the joiner's X-Wing key, where they used to stand in the clear.",
+	},
+	"sealJoinLocked|call zeroizeState": {
+		carries: []string{"payload"},
+		why:     "the erase of the payload, deferred from the moment it exists.",
+	},
+	"openJoinSeal|call epochKeysDigestOver": {
+		carries: []string{"pqSecret"},
+		why:     "THE CHECK: the opened secret must reproduce, under this device's own exporter, the digest sealed beside it.",
+	},
+	"openJoinSeal|call zeroizeState": {
+		carries: []string{"groupHandleKey", "payload", "pqSecret"},
+		why:     "the erase of the payload always, and of both secrets on every refusal after they were cut out.",
+	},
+	"AddMember|literal Invite.JoinAuth": {
+		carries: []string{"joinAuth"},
+		why:     "the invite's authenticator. It is an HMAC over public values under an exporter key, and carries no secret.",
+	},
+	"AddMember|assign self.foundingJoinDigest": {
+		carries: []string{"joinDigest"},
+		why:     "the digest the invite was sealed over, kept so that Open can hold what it publishes against it. H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes.",
+	},
+	"sealJoinLocked|call self.device.crypto.Mac": {
+		carries: []string{"preimage"},
+		why:     "the authenticator over the preimage, which is public values and three hashes.",
+	},
+	"AddMember|call self.sealFoundingJoinLocked": {
+		carries: []string{"foundingSecret"},
+		why:     "THE FOUNDING ADD'S SEAL. pq_secret[1] goes into the join seal, off the staged commit, and into nothing else of the invite.",
+	},
+	"openJoinSeal|call decodeJoinSecrets": {
+		carries: []string{"payload"},
+		why:     "the opened payload, to be cut into its three values.",
+	},
+	"Join|literal Group.groupHandleKey": {
+		carries: []string{"groupHandleKey"},
+		why:     "the group's handle key, into the joiner's group.",
+	},
+	"openJoinSeal|call subtle.ConstantTimeCompare": {
+		carries: []string{"computed", "sealedDigest"},
+		why:     "two digests, compared in constant time. H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes.",
+	},
+	"Join|call append": {
+		carries: []string{"pqSecret"},
+		why:     "the joiner's own copy for its table, of the secret the seal opened to.",
+	},
+	"Join|call messagegroup.NewGroupSession": {
+		carries: []string{"groupHandleKey", "pqSecret"},
+		why:     "the joiner's session, built over the two secrets the seal opened to.",
+	},
+	"Join|call zeroizeState": {
+		carries: []string{"groupHandleKey", "pqSecret"},
+		why:     "THE TWO ERASES OF THE JOIN: this function's copy of the epoch's secret when it returns, the group having filed a copy of its own; and the handle key, on a refusal made after the seal opened and before the join committed. Once the join has committed the handle key is the group's.",
+	},
+	"Join|literal ?.handle.Epoch(...)": {
+		carries: []string{"pqSecret"},
+		why:     "the one row of the joiner's table: the epoch it is admitted at, and that epoch's secret.",
+	},
 }
 
 var pqSecretCountedNotCarriedSites = map[string]string{
 	"encodeJoinSecrets|len pqSecret":     "the encoder's width check and its refusal text: three 32 octet values or nothing.",
 	"PutGroupRecord|len record.PqSecret": "the durable writer's 'this record carries neither' refusal.",
 	"PutGroupRecord|len rows":            "the arity of the table about to be written.",
-	"check|len self.PqSecret":            "the invite's own emptiness check, and its refusal text.",
 	"encodePqSecretTable|len row.PqSecret": "THE ENCODER'S WIDTH, at the one place a secret's own length is read and formatted. It is " +
 		"the site the ADV-M1 shape would attack from: one edit turns the count into the value, " +
 		"and the sink census refuses it.",
@@ -1074,15 +1103,13 @@ var pqSecretCountedNotCarriedSites = map[string]string{
 	"restoredPqSecrets|len record.PqSecrets": "the six-part arm's row count, and the refusal text for a table that does not cover its " +
 		"own epoch.",
 	"sortEpochPqSecrets|len rows": "the sort's bound.",
+	"sealJoinLocked|len joinSeal": "the seal's exact length, asserted before it is handed on, and that refusal's text. A count of ciphertext.",
 }
 
 var pqSecretAccumulatorSites = map[string]string{
 	"CreateGroup|accumulate self.hold": "THE DEVICE. A group whose table holds the founding secret goes into [Device.groups], and " +
 		"what that map does with it afterwards is not a thing this walk over names can follow. It " +
 		"is bounded: the group's own table is censused wherever it is read.",
-	"Encode|accumulate writer.WriteOpaqueLP": "THE INVITE'S BUFFER. The secret goes into the syntax writer and the walk does not follow " +
-		"it into that object; it comes back out as the encoded invite, which is the out-of-band " +
-		"value by design.",
 	"Join|accumulate self.holdReplacing": "the same, for a joiner.",
 	"Join|accumulate self.persistGroup": "THE DISK, one frame out. [Device.persistGroup] hands the record to the store, whose own " +
 		"write path IS censused -- PutGroupRecord, and the two calls under it -- so the blindness " +
@@ -1115,6 +1142,8 @@ var pqSecretAccumulatorSites = map[string]string{
 	"writeRecord|accumulate temp.Write": "THE DISK. What happens to those octets after this call is the filesystem's and not a " +
 		"value any walk over this package's names can follow. It is the honest end of this census " +
 		"on the durable road.",
+	"sealJoinLocked|accumulate self.device.crypto.Mac": "the MAC's input. What goes in is the preimage, which is public values and three hashes; the provider keeps nothing of it.",
+	"AddMember|accumulate self.sealFoundingJoinLocked": "THE FOUNDING SEAL, one frame out. The secret goes into [Group.sealJoinLocked], whose own body IS censused, so the blindness here is bounded by one call.",
 }
 
 func TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes(t *testing.T) {
```

`sdk/urmessage/epochkeygate_test.go`:

```diff
--- a/sdk/urmessage/epochkeygate_test.go
+++ b/sdk/urmessage/epochkeygate_test.go
@@ -318,6 +318,10 @@ var epochKeySinks = map[string]epochKeySink{
 			"holds. See publishCommitLocked|call self.submitLocked for the same correction at the " +
 			"other commit path.",
 	},
+	"Open|call sameDigest": {
+		carries: []string{"foundingDigest"},
+		why:     "THE DIGEST THE INVITE WAS SEALED OVER, held against the one this Open is about to publish. H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes. The comparison answers a bool.",
+	},
 }
 
 // The types in this package's production source that are built AROUND an epoch key, as
```

`sdk/urmessage/pqrotation_test.go`:

```diff
--- a/sdk/urmessage/pqrotation_test.go
+++ b/sdk/urmessage/pqrotation_test.go
@@ -152,7 +152,8 @@ func (self *rotWorld) enroll(name string, dev *crossProcessDevice, handle messag
 
 // enrollAt is enroll with the ONE pq_secret row this member starts life holding, and that row is
 // the whole of what separates a founder from a member admitted later. [Device.Join] files exactly
-// one row -- `pqSecrets: {handle.Epoch(): invite.PqSecret}` -- so a device admitted at epoch k
+// one row -- `pqSecrets: {handle.Epoch(): pqSecret}`, the secret its join seal opened to -- so a
+// device admitted at epoch k
 // knows nothing of the values drawn below it, which is the subject of ledger ruling 43's first
 // residual. [rotWorld.admit] is the door that uses it; `enroll` passes the founding value because
 // every member of a world built by [newRotWorld] is named in the founding commit.
```

- [ ] **Step 5: the registry.** Six entries close and two residuals are added.

`sdk/cp3b/testdata/advsim/known-gaps.json`:

```diff
--- a/sdk/cp3b/testdata/advsim/known-gaps.json
+++ b/sdk/cp3b/testdata/advsim/known-gaps.json
@@ -1,20 +1,22 @@
 {
   "format": "advsim-known-gaps/1",
   "entries": [
-    {"id": "P1-hndl-founding", "state": "open", "expect": ["epoch:1"], "goal": [], "closed_by": "T1", "reads": "a recorder of both pasted codes and the server's rows, with a later CRQC, reads the epoch a founding add admitted the joiner at"},
-    {"id": "P1-hndl-live-add", "state": "open", "expect": ["epoch:2"], "goal": [], "closed_by": "T1", "reads": "the same recorder reads the epoch a live add (a rotated pq_secret) admitted the joiner at"},
-    {"id": "P1-hndl-admin-add", "state": "open", "expect": ["epoch:4"], "goal": [], "closed_by": "T1", "reads": "the same recorder reads the epoch an admin's add admitted the joiner at, in a group of four: the adder hands on secrets it was itself handed"},
-    {"id": "P1-second-device-invitation", "state": "open", "expect": ["ghk", "storage-root:2"], "goal": [], "closed_by": "T1", "reads": "a recorder of a second device's pasted codes, handed the exporter of the classical join, finds the join epoch's secret and the group's handle key in the invitation; the device is added by a plain member that holds the identity, and no canary is read"},
+    {"id": "P1-hndl-founding", "state": "closed", "expect": [], "goal": [], "closed_by": "T1", "reads": "a recorder of both pasted codes and the server's rows, with a later CRQC, reads the epoch a founding add admitted the joiner at"},
+    {"id": "P1-hndl-live-add", "state": "closed", "expect": [], "goal": [], "closed_by": "T1", "reads": "the same recorder reads the epoch a live add (a rotated pq_secret) admitted the joiner at"},
+    {"id": "P1-hndl-admin-add", "state": "closed", "expect": [], "goal": [], "closed_by": "T1", "reads": "the same recorder reads the epoch an admin's add admitted the joiner at, in a group of four: the adder hands on secrets it was itself handed"},
+    {"id": "P1-second-device-invitation", "state": "closed", "expect": [], "goal": [], "closed_by": "T1", "reads": "a recorder of a second device's pasted codes, handed the exporter of the classical join, finds the join epoch's secret and the group's handle key in the invitation; the device is added by a plain member that holds the identity, and no canary is read"},
     {"id": "P1-c1-invite-alone", "state": "control", "expect": [], "goal": [], "closed_by": "none", "reads": "the recorder holds the invitation and not the join code, so the CRQC has no init key to invert and reads nothing"},
     {"id": "P1-c2-replaced-pq", "state": "control", "expect": [], "goal": [], "closed_by": "none", "reads": "both codes, with random octets where the pq_secret would be: the read goes through that one value and nothing else"},
     {"id": "P1-c3-injected-secrets", "state": "control", "expect": ["epoch:1"], "goal": [], "closed_by": "none", "reads": "both codes plus the true pq_secret and group_handle_key handed to the recorder: the pipeline reads exactly the join epoch"},
-    {"id": "S2a-ghk-paste-observer", "state": "open", "expect": ["ghk"], "goal": [], "closed_by": "T1", "reads": "a classical observer of one pasted invitation plus the server's rows recovers group_handle_key, which maps every sender_handle to a leaf for the group's life"},
+    {"id": "S2a-ghk-paste-observer", "state": "closed", "expect": [], "goal": [], "closed_by": "T1", "reads": "a classical observer of one pasted invitation plus the server's rows recovers group_handle_key, which maps every sender_handle to a leaf for the group's life"},
     {"id": "S2b-first-appearance-link", "state": "residual", "expect": ["linked:2/2"], "goal": [], "closed_by": "none", "reads": "with no key at all, the order sender handles first appear in the server's rows links the founder and this paste's joiner to their handles; sealing the secrets does not change it"},
-    {"id": "S3-chosen-secret", "state": "open", "expect": ["installed:attacker-secret"], "goal": [], "closed_by": "T1", "reads": "an attacker on the paste channel rewrites the invitation so that it carries secrets the attacker chose, and the joiner installs them"},
+    {"id": "S3-chosen-secret", "state": "closed", "expect": [], "goal": [], "closed_by": "T1", "reads": "an attacker on the paste channel rewrites the invitation so that it carries secrets the attacker chose, and the joiner installs them"},
     {"id": "S3-refusal-spends-join-code", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "an invitation refused for naming another group costs the joiner its one-use join code, so the honest invitation that follows cannot be joined"},
     {"id": "S3-late-refusal-spends-join-code", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "an invitation refused after the engine has joined costs the joiner its join code and leaves state behind"},
     {"id": "S3-mg1-join-code-substitution", "state": "open", "expect": ["swapper-read:1"], "goal": [], "closed_by": "T2", "reads": "a swapper substitutes its own join code; the founder adds the swapper believing it is the victim, and the swapper reads what the founder sends"},
     {"id": "S4-state-thief", "state": "open", "expect": ["epoch:1"], "goal": [], "closed_by": "T3", "reads": "a copy of the joiner's state directory taken after the join reads the join epoch: keys at rest are plaintext"},
+    {"id": "S4-seed-plus-recorder", "state": "residual", "expect": ["epoch:1"], "goal": [], "closed_by": "none", "reads": "the recorder also holds the joiner's X-Wing seed, copied before the join: it opens the recorded seal and reads the join epoch. The seal is to a static key"},
+    {"id": "S4-seed-plus-recorder-live-add", "state": "residual", "expect": ["epoch:2"], "goal": [], "closed_by": "none", "reads": "the same, for a live add: the seed and the recording read the epoch the rotated secret was sealed for. It is the live road's control that the recorder still reads when the seal is the only thing in its way"},
     {"id": "S7a-held-id-valid-invite", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "a valid invitation into an attacker's group founded under a group id the victim holds replaces the victim's group"},
     {"id": "S7b-held-id-refused-late", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "the same invitation, bent so that it is refused after the engine has joined, still replaces the held group's epoch state"},
     {"id": "S7c-fresh-id-held-welcome", "state": "closed", "expect": [], "goal": [], "closed_by": "T1a", "reads": "an invitation that names a fresh group id and carries a welcome for the held group replaces the held group's epoch state"},
```

Measured at this commit with the registry of the commit before: each of these FAILS and names the edit.

```
ADVSIM P1-hndl-founding state=open     expect=[epoch:1] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
ADVSIM P1-hndl-live-add state=open     expect=[epoch:2] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
ADVSIM P1-hndl-admin-add state=open     expect=[epoch:4] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
ADVSIM P1-second-device-invitation state=open     expect=[ghk storage-root:2] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
ADVSIM S2a-ghk-paste-observer state=open     expect=[ghk] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
ADVSIM S3-chosen-secret state=open     expect=[installed:attacker-secret] observed=[] :: FAIL: the gap has CLOSED: observed [] is the goal. Set this entry's state to "closed" and its expect to [] in the commit that closed it
```

- [ ] **Step 6: run it and see it pass.**

```bash
go -C sdk test -count=1 ./...
go -C sdk/cp3b test -count=1 ./...
go -C sdk/livepeer test -count=1 ./... && go -C sdk/liveprobe test -count=1 ./...
go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./... | grep -E '^ADVSIM'
ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./... | grep -c '^--- FAIL'
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run): Strict mode has 3 FAIL: the two gaps of the identity track and the one of the healing track.

```
sdk            exit=0 pass=335 fail=0
cp3b           exit=0 pass=117 fail=0
advsim-strict  exit=1 pass=25 fail=3
```

- [ ] **Step 7: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ3`: sealed to a key that is not the joiner's. Property 1 must fail. Measured: killed by `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth`, and 119 other tests.
2. `MJ8`: join_key at the epoch that is closing, not the one the commit opens. Property 1 must fail. Measured: killed by `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth`, and 119 other tests.
3. `MJ9`: the adder seals and authenticates for a leaf that is not the joiner's (the design's MJ9). Property 1 must fail. Measured: killed by `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth`, and 119 other tests.
4. `MJV2`: THE VERSION 2 READER RESTORED: a plaintext invitation parses and its two secrets are honoured. Property 2 must fail. Measured: killed by `TestAnInviteFromAnotherVersionOrWithOctetsAfterItIsRefused`, and 2 other tests.
5. `MJ10`: a seal with a non-zero content epoch is accepted at the paste. Property 2 must fail. Measured: killed by `TestAnInviteWhoseSealIsNotTheShapeVersionThreeFixesIsRefused`, and 1 other test.
6. `MJ4`: the joiner does not verify join_auth. Property 3 must fail. Measured: killed by `TestABentSealIsRefusedAndTheHonestInviteStillJoins`, and 7 other tests.
7. `MJ13`: the joined state is committed to the store before the seal is verified, opened and checked. Property 3 must fail. Measured: killed by `TestABentSealIsRefusedAndTheHonestInviteStillJoins`, and 8 other tests.
8. `MJ34`: a failed seal leaves its commit staged on the founding road. Property 4 must fail. Measured: killed by `TestAFailedSealLeavesTheFounderWhereItWasAndTheAddCanBeMadeAgain`.
9. `MJ33`: Open publishes without holding the digest the invitation was sealed over. Property 4 must fail. Measured: killed by `TestOpenRefusesToPublishKeysItsInviteWasNotSealedOver`.
10. `MJV2`: THE VERSION 2 READER RESTORED: a plaintext invitation parses and its two secrets are honoured. Property 5 must fail. Measured: killed by `TestAdvSimAnAttackerChosenSecretIsNotInstalled`, and 2 other tests.
11. `MJ1`: pq_secret left in the clear beside the seal, as a sixth field. Property 5 must fail. Measured: killed by `TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch`, and 12 other tests.
12. `MJ2`: group_handle_key left in the clear beside the seal. Property 5 must fail. Measured: killed by `TestAdvSimAPasteObserverRecoversTheGroupHandleKey`, and 8 other tests.
13. `MJ21`: a live add seals the secret of the epoch that is closing. Property 5 must fail. Measured: killed by `TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch`, and 34 other tests.
14. `MJ22`: MJ21, and the sealed digest recomputed from the value that was sealed. Property 5 must fail. Measured: killed by `TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch`, and 26 other tests.
15. `MJ65`: the codec's invite version moves and the authenticator's does not. Property 6 must fail. Measured: killed by `TestTheInviteVersionIsTheOneJoinAuthIsOver`, and 2 other tests.
16. `MJ19`: the sealed payload is not erased. Property 7 must fail. Measured: killed by `TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes`.
17. `MJ19b`: the handle key the seal opened to is not erased on a refusal made before the join commits. Property 7 must fail. Measured: killed by `TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes`.

- [ ] **Step 8: commit.**

```bash
git add sdk/urmessage/urmessage_test.go sdk/urmessage/joinseal_test.go sdk/urmessage/joinwindow_test.go sdk/cp3b/roles_test.go sdk/cp3b/advsim_oracle_test.go sdk/cp3b/advsim_join_test.go sdk/urmessage/invite.go sdk/urmessage/joinseal.go sdk/urmessage/group.go sdk/urmessage/errors.go sdk/urmessage/pqepoch.go sdk/urmessage/statestore_durable.go sdk/cgo/exports_message.go sdk/livepeer/main.go sdk/livepeer/README.md sdk/urmessage/pqsecretgate_test.go sdk/urmessage/epochkeygate_test.go sdk/urmessage/pqrotation_test.go sdk/cp3b/testdata/advsim/known-gaps.json
git commit -m "urmessage: invite version 3 carries the join secrets sealed to the joiner and authenticated by the join epoch"
```

The harness on this commit, every line:

```
ADVSIM P1-hndl-founding state=closed   expect=[] observed=[] :: CLOSED
ADVSIM P1-hndl-live-add state=closed   expect=[] observed=[] :: CLOSED
ADVSIM P1-hndl-admin-add state=closed   expect=[] observed=[] :: CLOSED
ADVSIM P1-second-device-invitation state=closed   expect=[] observed=[] :: CLOSED
ADVSIM P1-c1-invite-alone state=control  expect=[] observed=[] :: CONTROL
ADVSIM P1-c2-replaced-pq state=control  expect=[] observed=[] :: CONTROL
ADVSIM P1-c3-injected-secrets state=control  expect=[epoch:1] observed=[epoch:1] :: CONTROL
ADVSIM S2a-ghk-paste-observer state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S2b-first-appearance-link state=residual expect=[linked:2/2] observed=[linked:2/2] :: RESIDUAL
ADVSIM S3-chosen-secret state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S3-refusal-spends-join-code state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S3-late-refusal-spends-join-code state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S3-mg1-join-code-substitution state=open     expect=[swapper-read:1] observed=[swapper-read:1] :: KNOWN GAP (closed by T2)
ADVSIM S4-state-thief state=open     expect=[epoch:1] observed=[epoch:1] :: KNOWN GAP (closed by T3)
ADVSIM S4-seed-plus-recorder state=residual expect=[epoch:1] observed=[epoch:1] :: RESIDUAL
ADVSIM S4-seed-plus-recorder-live-add state=residual expect=[epoch:2] observed=[epoch:2] :: RESIDUAL
ADVSIM S7a-held-id-valid-invite state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S7b-held-id-refused-late state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S7c-fresh-id-held-welcome state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S7d-held-on-disk-only state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S7e-held-id-unheld-epoch state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S7f-on-disk-unheld-epoch state=closed   expect=[] observed=[] :: CLOSED
ADVSIM S7g-removed-group-second-founder state=open     expect=[record-replaced removal-forgotten] observed=[record-replaced removal-forgotten] :: KNOWN GAP (closed by T2)
ADVSIM S7-c1-unrestorable-rejoins state=control  expect=[rejoined] observed=[rejoined] :: CONTROL
ADVSIM S7-c2-unreadable-record-costs-one-group state=control  expect=[damage-reported damaged-id-not-founded damaged-invite-refused fresh-id-founded other-group-joined others-restored rejoined] observed=[damage-reported damaged-id-not-founded damaged-invite-refused fresh-id-founded other-group-joined others-restored rejoined] :: CONTROL
```

### Task 47: Only a group that requires the join seal is joined or restored

- Consumes: the capability and its requirement (Task 42); the join's window (Task 36); `ForgetGroup`'s leave of a group that did not restore (Task 33); `joinAuthPreimage`, `encodeJoinSecrets`, `epochKeysDigestOver`, `joinerLeafIn`
- Produces: `requireJoinSeal`, `ErrGroupPredatesJoinSeal`, and the test helper `foundByHand`

**Why.** The reset is an assumption, and nothing in the code checked it (the security review).
The record format is unchanged, so a state directory an earlier build wrote restores under this
one with no signal, and a group in it is one whose handle key crossed a paste channel as plain
octets in every invitation ever made for it. Nothing this build does can take that back.

**Behaviour.** One function, two call sites, one error. A group's required capabilities are fixed
in its context, and every group this build founds requires the join seal, so a group WITHOUT the
requirement was founded by a build that sent its join secrets in the clear. `Join` refuses it
inside the window (the join code is not spent). `Restore` answers it inside `ErrRestore`, before a
session is built, and remembers it as a group that did not come back, so `ForgetGroup` leaves it.
The requirement is read off the handle's own group context, which is the group's and not a
caller's claim about it.

**The test founds its groups by hand**, through `mls` directly, because the engine does not let
its caller choose what a group requires. Each case has its control: the same hand founder
requiring the seal joins, over the same join code; and the same planting for a group that
requires the seal restores.

**Property 1.** An invitation into a group that does not require the join seal is refused inside the window by name, with the join code unspent; the same founder requiring the seal, over the same join code, joins.

**Property 2.** A group on the disk that does not require the join seal is not restored, by name, and `ForgetGroup` then leaves it; the same planting for a group that requires the seal restores.

- [ ] **Step 1: the tests first.**

`sdk/urmessage/joinsealmember_test.go` (new file, 261 lines):

```go
package urmessage

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// WHICH GROUPS THIS BUILD OPENS AT ALL. Every group this build founds requires the join seal of
// its members, and the engine does not let its caller choose otherwise; so a group that does not
// require it is made here by hand, through connect/mls, to stand for one an earlier build founded.

// handFounded is a group founded THROUGH connect/mls AND NOT THROUGH THIS PACKAGE OR THE ENGINE,
// with one joiner added, and the version 3 invite a member of it makes for that joiner.
type handFounded struct {
	invite         *Invite
	pqSecret       []byte
	groupHandleKey []byte
}

// foundByHand founds a group whose context REQUIRES exactly the capabilities the caller lists, and
// adds one join code to it. It exists because the engine does not let its caller choose that
// list: every group the engine founds requires the join seal, so a group that does not can only
// be made beside it.
func foundByHand(t *testing.T, groupId []byte, required []mls.ExtensionType, joinCode []byte) *handFounded {
	t.Helper()
	crypto, err := mls.NewCryptoProvider(deviceCipherSuite)
	if err != nil {
		t.Fatalf("the crypto provider: %v", err)
	}
	signer, signerPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("the signature key pair: %v", err)
	}
	leafKeysBody, _ := mintLeafKeys(t)
	leafKeys, err := mls.ParseLeafKeysExtension(leafKeysBody)
	if err != nil {
		t.Fatalf("the founder's leaf keys: %v", err)
	}
	policy := &mls.GroupPolicyExtension{Roles: []mls.RoleEntry{{MemberId: signerPub, Role: mls.RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("the group policy: %v", err)
	}
	encodedPolicy, err := policy.Encode()
	if err != nil {
		t.Fatalf("the group policy: %v", err)
	}
	group, err := mls.NewGroup(&mls.GroupConfig{
		Suite:   crypto.Suite(),
		GroupId: groupId,
		Extensions: []mls.Extension{{
			ExtensionType: mls.ExtensionTypeUrmessageGroupPolicy,
			ExtensionData: encodedPolicy.ExtensionData,
		}},
		RequiredCaps: mls.RequiredCapabilities{ExtensionTypes: required},
		Crypto:       crypto,
		Store:        NewMemoryStateStore(),
		LeafKeys:     *leafKeys,
	}, signer, mls.BasicCredential(signerPub))
	if err != nil {
		t.Fatalf("mls.NewGroup requiring %v: %v", required, err)
	}
	t.Cleanup(func() { group.Close() })
	decoded := &mls.KeyPackage{}
	if err := syntax.Unmarshal(joinCode, decoded); err != nil {
		t.Fatalf("decoding the join code: %v", err)
	}
	result, err := group.CreateCommit([][]byte{}, []mls.Proposal{{
		ProposalType: mls.ProposalTypeAdd,
		Add:          &mls.Add{KeyPackage: *decoded},
	}}, nil)
	if err != nil {
		t.Fatalf("the hand founder's commit adding the join code: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("the hand founder's merge: %v", err)
	}
	leaf, err := joinerLeafIn(result.RatchetTree, decoded)
	if err != nil {
		t.Fatalf("joinerLeafIn: %v", err)
	}
	joinerLeafKeys, err := mls.LeafKeysOf(&decoded.LeafNode)
	if err != nil {
		t.Fatalf("the joiner's leaf keys: %v", err)
	}
	xwing, err := messagegroup.ParseXwingPublicKey(joinerLeafKeys.DeviceXwingPub)
	if err != nil {
		t.Fatalf("the joiner's x-wing key: %v", err)
	}
	pqSecret, groupHandleKey := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(pqSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(groupHandleKey); err != nil {
		t.Fatal(err)
	}
	mlsSecret, err := group.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the hand founder's storage exporter: %v", err)
	}
	digest, err := epochKeysDigestOver(groupId, group.Epoch(), mlsSecret, pqSecret)
	if err != nil {
		t.Fatalf("epochKeysDigestOver: %v", err)
	}
	payload, err := encodeJoinSecrets(pqSecret, groupHandleKey, digest)
	if err != nil {
		t.Fatalf("encodeJoinSecrets: %v", err)
	}
	seal, err := messagegroup.SealWrapBody(rand.Reader, xwing, messagegroup.WrapEnvelope{
		FormatVersion: messagegroup.WrapFormatVersion,
		TargetType:    wrapTargetTypeJoiner,
		PayloadType:   wrapPayloadTypeJoinSecrets,
	}, groupId, joinerLeafId(leaf), payload)
	if err != nil {
		t.Fatalf("the hand founder's SealWrapBody: %v", err)
	}
	joinKey, err := group.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
	if err != nil {
		t.Fatalf("the hand founder's join key: %v", err)
	}
	preimage, err := joinAuthPreimage(groupId, group.Epoch(), leaf, result.Welcome, result.RatchetTree, seal)
	if err != nil {
		t.Fatalf("joinAuthPreimage: %v", err)
	}
	return &handFounded{
		invite: &Invite{
			GroupId:     bytes.Clone(groupId),
			Welcome:     result.Welcome,
			RatchetTree: result.RatchetTree,
			JoinSeal:    seal,
			JoinAuth:    crypto.Mac(joinKey, preimage),
		},
		pqSecret:       pqSecret,
		groupHandleKey: groupHandleKey,
	}
}

var (
	requiredBeforeTheJoinSeal = []mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys}
	requiredWithTheJoinSeal   = []mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys, mls.ExtensionTypeUrmessageJoinSeal}
)

// ONLY A GROUP THAT REQUIRES THE JOIN SEAL IS JOINED. The invite is at version 3 and everything in
// it is right: a valid join_auth, a seal that opens, a digest that reproduces. The one thing wrong
// is the group, whose context requires what a build before the join seal required and no more. It
// is refused inside the window, by name, and the join code is not spent.
//
// THE CONTROL IS THE SAME FOUNDER REQUIRING THE SEAL, OVER THE SAME JOIN CODE: it joins. So the
// refusal above is the missing requirement and nothing else about a group founded by hand; and
// the join code was still there to be used.
func TestOnlyAGroupThatRequiresTheJoinSealIsJoined(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStateStore()
	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
	joinCode, err := joiner.KeyPackage()
	if err != nil {
		t.Fatalf("the joiner's KeyPackage: %v", err)
	}
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)

	before := foundByHand(t, groupId, requiredBeforeTheJoinSeal, joinCode)
	_, err = joiner.Join(ctx, before.invite)
	if !errors.Is(err, ErrGroupPredatesJoinSeal) {
		t.Fatalf("an invite into a group that does not require the join seal answered %v, want ErrGroupPredatesJoinSeal", err)
	}
	if !errors.Is(err, ErrJoinRefused) || errors.Is(err, ErrJoinCodeSpent) {
		t.Errorf("that refusal is %v, which is not one made inside the window that leaves the join code", err)
	}
	if held := len(joiner.Groups()); held != 0 {
		t.Fatalf("the refused invite left the joiner holding %d group(s)", held)
	}
	if _, err := store.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("the refused invite left a state in the store: %v", err)
	}

	sealed := foundByHand(t, groupId, requiredWithTheJoinSeal, joinCode)
	if _, err := joiner.Join(ctx, sealed.invite); err != nil {
		t.Fatalf("CONTROL FAILED: the same founder requiring the join seal, over the same join code, answered %v", err)
	}
}

// A GROUP FOUNDED BEFORE THE JOIN SEAL IS NOT RESTORED, AND IT CAN BE LEFT. The group is put on
// the disk the only way it can get there in this build, which is around [Device.Join]: the engine
// joins the hand founder's welcome and the record is written beside it. That is what a state
// directory an earlier build wrote looks like to this one. After a restart, Restore answers
// [ErrGroupPredatesJoinSeal] inside [ErrRestore] and holds nothing, and ForgetGroup leaves it.
//
// THE CONTROL IS THE FIRST ROW: the same planting for a group that requires the seal restores. So
// a planted group is restorable, and the second row's refusal is the requirement's.
func TestAGroupFoundedBeforeTheJoinSealIsNotRestoredAndCanBeLeft(t *testing.T) {
	ctx := context.Background()
	groupId := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	for _, one := range []struct {
		name     string
		required []mls.ExtensionType
		want     error
	}{
		{"a group that requires the join seal", requiredWithTheJoinSeal, nil},
		{"a group founded before the join seal", requiredBeforeTheJoinSeal, ErrGroupPredatesJoinSeal},
	} {
		dir := t.TempDir()
		durable, err := OpenDurableStateStore(dir)
		if err != nil {
			t.Fatalf("%s: OpenDurableStateStore: %v", one.name, err)
		}
		device := newAnsweringDeviceOver(t, durable, []byte("the device's nonce"))
		joinCode, err := device.KeyPackage()
		if err != nil {
			t.Fatalf("%s: KeyPackage: %v", one.name, err)
		}
		founded := foundByHand(t, groupId, one.required, joinCode)
		handle, err := device.engine.JoinFromWelcomeInto(founded.invite.Welcome, founded.invite.RatchetTree, groupId)
		if err != nil {
			t.Fatalf("%s: planting the joined state through the engine: %v", one.name, err)
		}
		handle.Close()
		if err := durable.PutGroupRecord(&GroupRecord{
			GroupId:        groupId,
			Epoch:          1,
			PqSecret:       founded.pqSecret,
			GroupHandleKey: founded.groupHandleKey,
			Opened:         true,
		}); err != nil {
			t.Fatalf("%s: planting the record: %v", one.name, err)
		}
		device.Close()
		if err := durable.Close(); err != nil {
			t.Fatalf("%s: closing the store before the restart: %v", one.name, err)
		}

		reopened, err := OpenDurableStateStore(dir)
		if err != nil {
			t.Fatalf("%s: reopening the store: %v", one.name, err)
		}
		t.Cleanup(func() { reopened.Close() })
		restarted := newAnsweringDeviceOver(t, reopened, []byte("the device's nonce"))
		groups, err := restarted.Restore(ctx)
		if one.want == nil {
			if err != nil || len(groups) != 1 {
				t.Fatalf("CONTROL FAILED: %s restored %d group(s), %v: a planted group is not restorable, so the row below proves nothing", one.name, len(groups), err)
			}
			continue
		}
		if len(groups) != 0 || !errors.Is(err, ErrRestore) || !errors.Is(err, one.want) {
			t.Fatalf("%s restored %d group(s) and answered %v, want none and %v inside ErrRestore", one.name, len(groups), err, one.want)
		}
		if err := restarted.ForgetGroup(groupId); err != nil {
			t.Fatalf("%s: ForgetGroup of the group Restore refused: %v", one.name, err)
		}
		records, err := reopened.GroupRecords()
		if err != nil || len(records) != 0 {
			t.Fatalf("%s: the store holds %d record(s) after the group was left: %v", one.name, len(records), err)
		}
	}
}
```

- [ ] **Step 2: run them and see them fail.** On the tree before the change, with these test files laid over it. Measured:

```
$ go -C sdk test -count=1 -run ^(TestAGroupFoundedBeforeTheJoinSealIsNotRestoredAndCanBeLeft|TestOnlyAGroupThatRequiresTheJoinSealIsJoined) ./urmessage/
exit status 1
FAIL	github.com/urnetwork/message/sdk/urmessage [build failed]
FAIL
 # github.com/urnetwork/message/sdk/urmessage [github.com/urnetwork/message/sdk/urmessage.test]
urmessage\joinsealmember_test.go:169:21: undefined: ErrGroupPredatesJoinSeal
urmessage\joinsealmember_test.go:205:71: undefined: ErrGroupPredatesJoinSeal
```

- [ ] **Step 3: the change.**

`sdk/urmessage/joinseal.go`:

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -5,6 +5,7 @@ import (
 	"crypto/subtle"
 	"errors"
 	"fmt"
+	"slices"
 	"time"
 
 	"github.com/urnetwork/message/message"
@@ -336,6 +337,38 @@ func (self *Device) openJoinSeal(handle messagegroup.GroupHandle, invite *Invite
 	return pqSecret, groupHandleKey, nil
 }
 
+// requireJoinSeal answers [ErrGroupPredatesJoinSeal] for a group whose context does not REQUIRE
+// the join seal capability of every member, and nil for one that does.
+//
+// THE REQUIREMENT IS HOW A GROUP SAYS WHICH BUILD FOUNDED IT. Every group this build founds
+// requires the capability, and a group's required capabilities are fixed in its context, so a
+// group without the requirement was founded by a build whose invitations carried the join secrets
+// in the clear. It is read off the handle's own group context, which is the group's and not a
+// caller's claim about it.
+func requireJoinSeal(handle messagegroup.GroupHandle) error {
+	contextBytes, err := handle.GroupContextBytes()
+	if err != nil {
+		return fmt.Errorf("urmessage: the group context: %w", err)
+	}
+	context := &mls.GroupContext{}
+	if err := syntax.Unmarshal(contextBytes, context); err != nil {
+		return fmt.Errorf("urmessage: decoding the group context: %w", err)
+	}
+	for _, extension := range context.Extensions {
+		if extension.ExtensionType != mls.ExtensionTypeRequiredCapabilities {
+			continue
+		}
+		required := &mls.RequiredCapabilities{}
+		if err := syntax.Unmarshal(extension.ExtensionData, required); err != nil {
+			return fmt.Errorf("urmessage: the group's required capabilities: %w", err)
+		}
+		if slices.Contains(required.ExtensionTypes, mls.ExtensionTypeUrmessageJoinSeal) {
+			return nil
+		}
+	}
+	return ErrGroupPredatesJoinSeal
+}
+
 // sameDigest compares two H(epoch_keys) values, and answers false for one that is absent. The
 // values are published, so nothing here is secret; it goes through subtle because every comparison
 // of key-derived octets in this package does.
```

`sdk/urmessage/group.go`:

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1474,6 +1474,10 @@ func (self *Device) Join(ctx context.Context, invite *Invite) (joined *Group, er
 		return nil, fmt.Errorf("%w: the welcome stands at epoch %d and this device was removed at epoch %d",
 			ErrReaddStale, handle.Epoch(), removedEpoch)
 	}
+	// ONLY A GROUP THAT REQUIRES THE JOIN SEAL IS JOINED: see [ErrGroupPredatesJoinSeal].
+	if err := requireJoinSeal(handle); err != nil {
+		return nil, err
+	}
 	// THE JOIN SEAL: verified, opened and checked, in that order, before anything is honoured. See
 	// [Device.openJoinSeal]. The two secrets exist in this function only from here.
 	pqSecret, groupHandleKey, err := self.openJoinSeal(handle, invite)
```

`sdk/urmessage/restore.go`:

```diff
--- a/sdk/urmessage/restore.go
+++ b/sdk/urmessage/restore.go
@@ -297,6 +297,12 @@ func (self *Device) restoreOne(store DeviceStore, record *GroupRecord, nonce []b
 	if err != nil {
 		return nil, fmt.Errorf("%w: group %x at epoch %d: %w", ErrRestore, record.GroupId, record.Epoch, err)
 	}
+	// ONLY A GROUP THAT REQUIRES THE JOIN SEAL IS RESTORED: see [ErrGroupPredatesJoinSeal]. It is
+	// asked before a session is built, so nothing of the group is in memory when it is refused.
+	if err := requireJoinSeal(handle); err != nil {
+		handle.Close()
+		return nil, fmt.Errorf("%w: group %x at epoch %d: %w", ErrRestore, record.GroupId, record.Epoch, err)
+	}
 	// THE TABLE THIS RECORD CAME BACK WITH, AND WHAT IT IS WHEN THERE IS NONE. A record written
 	// before item 251's ruling 40 has five parts and nil here; one written by this build has six
 	// and a table, possibly empty. [restoredPqSecrets] turns either into the map this group runs
```

`sdk/urmessage/errors.go`:

```diff
--- a/sdk/urmessage/errors.go
+++ b/sdk/urmessage/errors.go
@@ -856,4 +856,13 @@ var (
 	// the digest [Group.AddMember] sealed into the invite. The joiner would refuse that invite, so
 	// the group is not published under it.
 	ErrInviteDigestDrift = errors.New("urmessage: the keys this group would open with are not the keys its invite was sealed over")
+
+	// The group's context does not REQUIRE the join seal capability of its members, so it was
+	// founded by a build that sent its join secrets in the clear: its handle key has crossed a
+	// paste channel as plain octets, and nothing this build does can take that back. This build
+	// neither joins such a group ([Device.Join] refuses inside the join's window, so the join
+	// code is not spent) nor restores one ([Device.Restore] answers this inside [ErrRestore]).
+	// A group Restore refused this way is left with [Device.ForgetGroup], like any group that
+	// does not come back, and is founded again.
+	ErrGroupPredatesJoinSeal = errors.New("urmessage: this group was founded before invitations were sealed, so this build does not open it; leave it and start the group again")
 )
```

- [ ] **Step 4: run it and see it pass.**

```bash
go -C sdk test -count=1 ./...
go -C sdk/cp3b test -count=1 ./...
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run):

```
sdk            exit=0 pass=337 fail=0
cp3b           exit=0 pass=117 fail=0
advsim-strict  exit=1 pass=25 fail=3
```

- [ ] **Step 5: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ51`: a group that does not require the join seal is joined. Property 1 must fail. Measured: killed by `TestOnlyAGroupThatRequiresTheJoinSealIsJoined`.
2. `MJ52`: a group founded before the join seal is restored like any other. Property 2 must fail. Measured: killed by `TestAGroupFoundedBeforeTheJoinSealIsNotRestoredAndCanBeLeft`.

- [ ] **Step 6: commit.**

```bash
git add sdk/urmessage/joinsealmember_test.go sdk/urmessage/joinseal.go sdk/urmessage/group.go sdk/urmessage/restore.go sdk/urmessage/errors.go
git commit -m "urmessage: only a group that requires the join seal is joined or restored"
```

### Task 48: The seal held from the member's side, by a second spelling, and at every octet

- Consumes: `openJoinSeal`, `sealJoinLocked` and the window (Task 46, Task 36); `foundByHand`'s neighbours in `joinsealmember_test.go` (Task 47); the seam member of `sdk/cp3b`, which opens a seal and never verifies its authenticator
- Produces: the test helpers `memberInvite` and `jsSecondSpelling`

**Why these are their own task.** The security review ran eleven mutants of its own over the
first revision of this plan and ten survived: the digest check, the join key's derivation and its
context, and the order of the preimage's fields could each be changed with every suite green. A
forger outside the group cannot make `join_auth`, so no test that bends an honest invitation or
forges one from outside gets past the authenticator. The checks BEHIND it are reached only by an
invitation whose authenticator is valid, and a valid one is made only by a member. So:

- `memberInvite` makes one, off the founder's own handle, over a payload and an addressee of the
  test's choosing. Its control is the last join of the test: carrying the three true values, it
  joins, over the same join code five refusals left.
- `jsSecondSpelling` recomputes `join_auth` in `sdk/cp3b` with the standard library's HMAC alone,
  from the joined group's own exporter asked for by the label and the context written out there,
  over a preimage assembled field by field. The key cannot have a fixed known answer, because it
  comes out of a live group, so it is pinned by this second derivation, on both adder roads; three
  keys it must NOT be are tried as well.
- The every-octet case flips one bit of each octet of an encoded invitation in turn, RECOMPUTES
  THE CHECKSUM as anybody on the paste channel can, and prints which authority refused each
  field. Measured:

**Property 1.** A seal a member made is still held to its epoch, its shape and its addressee inside the window: a secret that does not reproduce the digest sealed beside it, an all-zero secret, and a seal made to another device's key are each refused by name with the join code unspent.

**Property 2.** Every octet of an invitation is held by a named authority, no bent invitation joins, every refusal inside the window says so but the one that must not (a welcome bent to address a join code this device does not hold, which comes from the welcome and from no other field), and the join code is still in the store after all of them.

**Property 3.** `join_auth` is HMAC-SHA-256 under the join epoch's exporter, asked for by the join key's label with the joiner's leaf as context, over the 181-octet preimage, on the founding road and on the live road; and it is not that MAC under the storage exporter, under the join key with no leaf, or under another leaf's.

**Property 4.** A genuine seal replayed from another epoch of the same device is refused by the authenticator, and the honest invitation then joins.

- [ ] **Step 1: the tests.**

`sdk/urmessage/joinsealmember_test.go`:

```diff
--- a/sdk/urmessage/joinsealmember_test.go
+++ b/sdk/urmessage/joinsealmember_test.go
@@ -4,7 +4,10 @@ import (
 	"bytes"
 	"context"
 	"crypto/rand"
+	"crypto/sha256"
 	"errors"
+	"sort"
+	"strings"
 	"testing"
 
 	"github.com/urnetwork/message/messagegroup"
@@ -259,3 +262,294 @@ func TestAGroupFoundedBeforeTheJoinSealIsNotRestoredAndCanBeLeft(t *testing.T) {
 		}
 	}
 }
+
+// THE JOIN SEAL HELD FROM THE MEMBER'S SIDE. The cases in joinseal_test.go bend an honest invite or
+// forge one from outside; a forger outside the group cannot make join_auth, so none of them gets
+// past the authenticator. The checks behind it -- the open, the payload's shape and the digest --
+// are reached only by an invite whose join_auth is VALID, and a valid one is made only by a member.
+// So the invites below are made by one.
+
+// memberInvite is an invite a MEMBER of the join epoch could make for the pair's joiner: the
+// pair's own welcome and tree, a seal of the caller's payload to a key of the caller's, and a
+// join_auth that IS valid for that seal, under the join epoch's own exporter off the founder's
+// handle. With sealTo nil the seal is made to the joiner's own published key.
+func memberInvite(t *testing.T, pair *sealPair, sealTo *messagegroup.XwingPublicKey, payload []byte) *Invite {
+	t.Helper()
+	joiner, err := pair.alice.joinerOf(pair.joinCode)
+	if err != nil {
+		t.Fatalf("joinerOf: %v", err)
+	}
+	leaf, err := joinerLeafIn(pair.invite.RatchetTree, joiner.keyPackage)
+	if err != nil {
+		t.Fatalf("joinerLeafIn: %v", err)
+	}
+	if sealTo == nil {
+		sealTo = joiner.xwing
+	}
+	seal, err := messagegroup.SealWrapBody(pair.alice.random, sealTo, messagegroup.WrapEnvelope{
+		FormatVersion: messagegroup.WrapFormatVersion,
+		TargetType:    wrapTargetTypeJoiner,
+		PayloadType:   wrapPayloadTypeJoinSecrets,
+	}, pair.invite.GroupId, joinerLeafId(leaf), payload)
+	if err != nil {
+		t.Fatalf("the member's SealWrapBody: %v", err)
+	}
+	// the founder's handle stands at epoch one once AddMember has merged, so this is the exporter
+	// of the epoch the joiner is admitted at
+	joinKey, err := pair.aliceGroup.handle.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	if err != nil {
+		t.Fatalf("the member's join key: %v", err)
+	}
+	preimage, err := joinAuthPreimage(pair.invite.GroupId, 1, leaf, pair.invite.Welcome, pair.invite.RatchetTree, seal)
+	if err != nil {
+		t.Fatalf("joinAuthPreimage: %v", err)
+	}
+	return &Invite{
+		GroupId:     bytes.Clone(pair.invite.GroupId),
+		Welcome:     bytes.Clone(pair.invite.Welcome),
+		RatchetTree: bytes.Clone(pair.invite.RatchetTree),
+		JoinSeal:    seal,
+		JoinAuth:    pair.alice.crypto.Mac(joinKey, preimage),
+	}
+}
+
+// A SEAL A MEMBER MADE IS STILL HELD TO ITS EPOCH, ITS SHAPE AND ITS ADDRESSEE, INSIDE THE WINDOW.
+// Every invite here carries a valid join_auth, so each is refused by a check that stands BEHIND
+// the authenticator: a secret that does not reproduce the digest sealed beside it, a digest that
+// is not this epoch's, an all-zero secret, and a seal made to somebody else's key. After all of
+// them the device holds nothing, and the join code is not spent.
+//
+// THE CONTROL IS THE LAST JOIN: a member-made invite carrying the three TRUE values joins, over the
+// same join code. It proves two things at once: the authenticator this helper makes is one the
+// joiner accepts, so every refusal above was made behind it; and five refusals cost nothing.
+//
+// WHAT WOULD GO RED: drop the comparison of the recomputed digest with the sealed one, and the
+// first two rows install a secret that is not the epoch's, with the join code spent on it.
+func TestAMemberMadeSealIsHeldToItsEpochItsShapeAndItsAddressee(t *testing.T) {
+	pair := newSealPair(t)
+	truePq := bytes.Clone(pair.aliceGroup.pqSecrets[1])
+	trueGhk := bytes.Clone(pair.aliceGroup.groupHandleKey)
+	trueDigest := bytes.Clone(pair.aliceGroup.foundingJoinDigest)
+	if len(truePq) != 32 || len(trueGhk) != 32 || len(trueDigest) != sha256.Size {
+		t.Fatalf("CONTROL FAILED: the founder holds %d, %d and %d octets for the secret, the handle key and the digest", len(truePq), len(trueGhk), len(trueDigest))
+	}
+	payload := func(pq []byte, ghk []byte, digest []byte) []byte {
+		return append(append(bytes.Clone(pq), ghk...), digest...)
+	}
+	carol, _ := newAnsweringDevice(t, 0, []byte("carol's nonce"))
+	carolCode, err := carol.KeyPackage()
+	if err != nil {
+		t.Fatalf("carol's KeyPackage: %v", err)
+	}
+	carolKeys, err := pair.alice.joinerOf(carolCode)
+	if err != nil {
+		t.Fatalf("joinerOf(carol): %v", err)
+	}
+	other := bytes.Repeat([]byte{0xA7}, 32)
+
+	for _, one := range []struct {
+		name   string
+		invite *Invite
+		want   error
+	}{
+		{"another secret beside this epoch's digest",
+			memberInvite(t, pair, nil, payload(other, trueGhk, trueDigest)), ErrJoinSealWrongEpoch},
+		{"this epoch's secret beside another digest",
+			memberInvite(t, pair, nil, payload(truePq, trueGhk, other)), ErrJoinSealWrongEpoch},
+		{"an all-zero secret",
+			memberInvite(t, pair, nil, payload(make([]byte, 32), trueGhk, trueDigest)), ErrJoinSealUnreadable},
+		{"an all-zero handle key",
+			memberInvite(t, pair, nil, payload(truePq, make([]byte, 32), trueDigest)), ErrJoinSealUnreadable},
+		{"the true values, sealed to another device's key",
+			memberInvite(t, pair, carolKeys.xwing, payload(truePq, trueGhk, trueDigest)), ErrJoinSealUnreadable},
+	} {
+		_, err := pair.bob.Join(pair.ctx, one.invite)
+		if !errors.Is(err, one.want) {
+			t.Errorf("%s answered %v, want %v", one.name, err, one.want)
+		}
+		if !errors.Is(err, ErrJoinRefused) || errors.Is(err, ErrJoinCodeSpent) {
+			t.Errorf("%s answered %v, which is not a refusal inside the window that leaves the join code", one.name, err)
+		}
+		if held := len(pair.bob.Groups()); held != 0 {
+			t.Fatalf("%s left bob holding %d group(s)", one.name, held)
+		}
+	}
+	// THE CONTROL, and the join code's survival
+	group, err := pair.bob.Join(pair.ctx, memberInvite(t, pair, nil, payload(truePq, trueGhk, trueDigest)))
+	if err != nil {
+		t.Fatalf("CONTROL FAILED: a member-made invite carrying the true values answered %v, so the refusals above may be the authenticator's and not the checks behind it", err)
+	}
+	if !bytes.Equal(group.pqSecrets[1], truePq) || !bytes.Equal(group.groupHandleKey, trueGhk) {
+		t.Fatalf("the joiner does not hold the two values the member sealed")
+	}
+}
+
+// EVERY OCTET OF AN INVITE IS HELD BY SOME AUTHORITY, AND NO REFUSAL COSTS THE JOIN CODE. One bit
+// of each octet of an encoded invite is flipped in turn, and the checksum is recomputed over the
+// result, as anybody on the paste channel can: so the checksum, which is not an authentication,
+// never does the refusing here. Each bent invite is parsed and joined, and four things are held
+// for every one of them: it does not join; it is refused by a named authority; a refusal made
+// inside the join's window says so and does not say the join code is spent; and the join code is
+// still in the store. At the end the honest invite joins over it.
+//
+// ONE REFUSAL INSIDE THE WINDOW DOES NOT SAY SO, AND IS HELD TO ITS FIELD. A bit flipped in the
+// reference by which the Welcome addresses a join code makes it a Welcome no join code of this
+// device was made for. The engine takes nothing, and the answer is [ErrNoJoinCodeForInvite], which
+// must NOT say the join code is not spent: the same answer is what an invite gets once its join
+// code really has gone. Here the join code has not gone, and the count after it shows that.
+//
+// THE TABLE IT PRINTS is the authority that refused each field's octets. Five things in it are
+// asserted: it accounts for every octet; every octet of the authenticator, and every octet of the
+// seal past its envelope, is refused by the authenticator; every octet of the envelope is
+// refused at the paste as the seal's shape; and the refusal for a join code this device does not
+// hold comes from the welcome and from no other field, and does come.
+func TestEveryOctetOfAnInviteIsHeldAndNoRefusalCostsTheJoinCode(t *testing.T) {
+	ctx := context.Background()
+	store := NewMemoryStateStore()
+	joiner := newAnsweringDeviceOver(t, store, []byte("the joiner's nonce"))
+	honest, groupId := windowInvite(t, joiner)
+	encoded, err := honest.Encode()
+	if err != nil {
+		t.Fatalf("Encode: %v", err)
+	}
+	body := encoded[:len(encoded)-sha256.Size]
+	// the fields, by where each begins: u16 version, then five u32-length-prefixed fields
+	type span struct {
+		name       string
+		start, end int
+	}
+	spans := []span{{"version", 0, 2}}
+	at := 2
+	for _, field := range []struct {
+		name   string
+		octets []byte
+	}{{"group id", honest.GroupId}, {"welcome", honest.Welcome}, {"ratchet tree", honest.RatchetTree},
+		{"join seal", honest.JoinSeal}, {"join auth", honest.JoinAuth}} {
+		spans = append(spans, span{"length of " + field.name, at, at + 4})
+		spans = append(spans, span{field.name, at + 4, at + 4 + len(field.octets)})
+		at += 4 + len(field.octets)
+	}
+	if at != len(body) {
+		t.Fatalf("CONTROL FAILED: the fields end at octet %d and the invite's body is %d octets, so the table below would name the wrong fields", at, len(body))
+	}
+	fieldOf := func(index int) string {
+		for _, one := range spans {
+			if one.start <= index && index < one.end {
+				return one.name
+			}
+		}
+		return "?"
+	}
+	tally := map[string]map[string]int{}
+	note := func(field string, authority string) {
+		if tally[field] == nil {
+			tally[field] = map[string]int{}
+		}
+		tally[field][authority] += 1
+	}
+	joinCodes := func() int {
+		store.lock.Lock()
+		defer store.lock.Unlock()
+		return len(store.keyPackages)
+	}
+	if held := joinCodes(); held != 1 {
+		t.Fatalf("CONTROL FAILED: the joiner's store holds %d join code(s) before anything was pasted, want 1", held)
+	}
+	for index := range body {
+		bent := bytes.Clone(body)
+		bent[index] ^= 0x01
+		sum := sha256.Sum256(bent)
+		field := fieldOf(index)
+		invite, err := ParseInvite(append(bent, sum[:]...))
+		if err != nil {
+			switch {
+			case errors.Is(err, ErrInviteVersion):
+				note(field, "the paste: ErrInviteVersion")
+			case errors.Is(err, ErrJoinSealShape):
+				note(field, "the paste: ErrJoinSealShape")
+			case errors.Is(err, ErrInviteDamaged):
+				// the checksum was recomputed over the bent octets, so it holds, and "damaged" is
+				// the checksum's own name
+				t.Fatalf("octet %d (%s): refused as damaged under a checksum that covers it: %v", index, field, err)
+			default:
+				note(field, "the paste: its framing")
+			}
+			continue
+		}
+		_, err = joiner.Join(ctx, invite)
+		if err == nil {
+			t.Fatalf("octet %d (%s): an invite with one bit flipped JOINED", index, field)
+		}
+		if errors.Is(err, ErrJoinCodeSpent) {
+			t.Fatalf("octet %d (%s): the refusal says the join code is spent: %v", index, field, err)
+		}
+		switch {
+		case errors.Is(err, ErrNoJoinCodeForInvite):
+			// THE ONE REFUSAL INSIDE THE WINDOW THAT DOES NOT CARRY ITS SENTENCE. The bit was in the
+			// reference the Welcome addresses a join code by, so the Welcome now names a join code
+			// this device does not hold, and the engine took nothing. It is held to the one field
+			// it can come from, and it must not say the join code is not spent; the join code is
+			// counted below like after every other refusal, and it is still there.
+			if field != "welcome" {
+				t.Fatalf("octet %d (%s): refused as an invite no join code of this device was made for, and only the welcome addresses one: %v", index, field, err)
+			}
+			if errors.Is(err, ErrJoinRefused) || strings.Contains(err.Error(), "the join code is not spent") {
+				t.Fatalf("octet %d (%s): the refusal for a join code this device does not hold also says the join code is not spent: %v", index, field, err)
+			}
+			note(field, "in the window: no join code of this device is addressed")
+		case !errors.Is(err, ErrJoinRefused):
+			t.Fatalf("octet %d (%s): an invite that parsed was refused with %v, which is not a refusal inside the window", index, field, err)
+		case !strings.HasPrefix(err.Error(), ErrJoinRefused.Error()+": "):
+			t.Fatalf("octet %d (%s): the refusal %q does not begin with the window's sentence", index, field, err)
+		case errors.Is(err, ErrJoinSealUnauthenticated):
+			note(field, "in the window: ErrJoinSealUnauthenticated")
+		case errors.Is(err, ErrJoinSealUnreadable), errors.Is(err, ErrJoinSealWrongEpoch):
+			t.Fatalf("octet %d (%s): a bent invite got past the authenticator and was refused behind it: %v", index, field, err)
+		default:
+			note(field, "in the window: the engine")
+		}
+		if held := joinCodes(); held != 1 {
+			t.Fatalf("octet %d (%s): the joiner's store holds %d join code(s) after the refusal, want 1: the refusal cost the join code", index, field, held)
+		}
+		if held := len(joiner.Groups()); held != 0 {
+			t.Fatalf("octet %d (%s): the joiner holds %d group(s) after a refusal", index, field, held)
+		}
+	}
+	if _, err := store.GetGroupState(groupId, 1); !errors.Is(err, ErrStateNotFound) {
+		t.Fatalf("%d refused invites left a state in the store: %v", len(body), err)
+	}
+
+	total := 0
+	for _, one := range spans {
+		authorities := []string{}
+		for authority, count := range tally[one.name] {
+			authorities = append(authorities, authority)
+			total += count
+		}
+		sort.Strings(authorities)
+		for _, authority := range authorities {
+			t.Logf("%-22s %5d octet(s)  %s", one.name, tally[one.name][authority], authority)
+		}
+	}
+	if total != len(body) {
+		t.Fatalf("the table accounts for %d octets and the invite's body is %d", total, len(body))
+	}
+	if got := tally["welcome"]["in the window: no join code of this device is addressed"]; got == 0 {
+		t.Errorf("no octet of the welcome was refused as addressing a join code this device does not hold, so the arm above that holds that refusal to its field was never reached")
+	}
+	if got := tally["join auth"]["in the window: ErrJoinSealUnauthenticated"]; got != len(honest.JoinAuth) {
+		t.Errorf("%d of the authenticator's %d octets were refused by the authenticator", got, len(honest.JoinAuth))
+	}
+	pastEnvelope := len(honest.JoinSeal) - messagegroup.WrapEnvelopeBytes
+	if got := tally["join seal"]["in the window: ErrJoinSealUnauthenticated"]; got != pastEnvelope {
+		t.Errorf("%d of the %d seal octets past its envelope were refused by the authenticator", got, pastEnvelope)
+	}
+	if got := tally["join seal"]["the paste: ErrJoinSealShape"]; got != messagegroup.WrapEnvelopeBytes {
+		t.Errorf("%d of the envelope's %d octets were refused as the seal's shape", got, messagegroup.WrapEnvelopeBytes)
+	}
+
+	// THE JOIN CODE SURVIVED EVERY ONE OF THEM
+	if _, err := joiner.Join(ctx, honest); err != nil {
+		t.Fatalf("the honest invite after %d refused ones answered %v", len(body), err)
+	}
+}
```

`sdk/cp3b/joinseal_test.go`:

```diff
--- a/sdk/cp3b/joinseal_test.go
+++ b/sdk/cp3b/joinseal_test.go
@@ -2,9 +2,15 @@ package cp3b
 
 import (
 	"bytes"
+	"context"
+	"crypto/hmac"
+	"crypto/sha256"
+	"encoding/binary"
 	"errors"
 	"testing"
+	"time"
 
+	"github.com/urnetwork/message/messagegroup"
 	"github.com/urnetwork/message/sdk/urmessage"
 )
 
@@ -91,3 +97,178 @@ func TestTheLiveAdderJudgesAJoinCodeAndNamesTheRemedyForALeafThatStands(t *testi
 	canary := scene.say(t, "alice", scene.aliceGroup)
 	gcReceiveText(t, scene.ctx, "dave", daveGroup, canary)
 }
+
+// jsSecondSpelling recomputes an invite's join_auth THE WAY A MEMBER THAT IS NOT THIS SDK WOULD,
+// and holds it against the invite's fifth field. Nothing here calls urmessage: the key is the
+// joined group's own exporter, asked for by the label and the context written out below, the
+// preimage is assembled field by field, and the MAC is the standard library's HMAC-SHA-256.
+//
+// IT IS THE KNOWN ANSWER FOR THE KEY. The preimage has one in sdk/urmessage; the key cannot have a
+// fixed one, because it comes out of a live group, so it is pinned by a second derivation instead.
+// Three keys it must NOT be are tried as well, each of which no other case could tell from the
+// right one: the storage exporter, which is what storage_root is extracted from; the join key
+// with no leaf in its context; and the join key of another leaf.
+func jsSecondSpelling(t *testing.T, road string, handle messagegroup.GroupHandle, invite *urmessage.Invite) {
+	t.Helper()
+	leaf, epoch := uint32(handle.OwnLeafIndex()), handle.Epoch()
+	leafId := binary.BigEndian.AppendUint32(nil, leaf)
+	preimage := []byte("URmessage/v1/joinauth")
+	preimage = append(preimage, 0x00, 0x41) // alg_id: HMAC-SHA-256
+	preimage = append(preimage, 0x00, 0x03) // invite version
+	lengthPrefixed := func(octets []byte) {
+		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(octets)))
+		preimage = append(preimage, octets...)
+	}
+	lengthPrefixed(invite.GroupId)
+	preimage = binary.BigEndian.AppendUint64(preimage, epoch)
+	preimage = binary.BigEndian.AppendUint32(preimage, leaf)
+	for _, part := range [][]byte{invite.Welcome, invite.RatchetTree, invite.JoinSeal} {
+		sum := sha256.Sum256(part)
+		lengthPrefixed(sum[:])
+	}
+	if len(preimage) != 181 {
+		t.Fatalf("%s: the preimage written out here is %d octets, want 181", road, len(preimage))
+	}
+	under := func(key []byte) []byte {
+		mac := hmac.New(sha256.New, key)
+		mac.Write(preimage)
+		return mac.Sum(nil)
+	}
+	export := func(label string, context []byte) []byte {
+		key, err := handle.Export(label, context, 32)
+		if err != nil {
+			t.Fatalf("%s: Export(%q): %v", road, label, err)
+		}
+		return key
+	}
+	joinKey := export("URmessage/v1/joinkey", leafId)
+	if !hmac.Equal(under(joinKey), invite.JoinAuth) {
+		t.Fatalf("%s: join_auth is not HMAC-SHA-256 under Export(URmessage/v1/joinkey, u32(leaf %d), 32) at epoch %d over the preimage written out here", road, leaf, epoch)
+	}
+	for name, other := range map[string][]byte{
+		"the storage exporter":                     export("URmessage/v1/storage", nil),
+		"the join key with no leaf in its context": export("URmessage/v1/joinkey", nil),
+		"the join key of the leaf beside this one": export("URmessage/v1/joinkey", binary.BigEndian.AppendUint32(nil, leaf+1)),
+	} {
+		if bytes.Equal(other, joinKey) || hmac.Equal(under(other), invite.JoinAuth) {
+			t.Errorf("%s: join_auth verifies under %s", road, name)
+		}
+	}
+}
+
+// JOIN_AUTH IS THE JOIN EPOCH'S EXPORTER OVER THE PREIMAGE, ON BOTH ADDER ROADS. The joiner is a
+// seam member, which opens the seal and never verifies the authenticator, so this is the only
+// place the authenticator an adder makes is checked by code that shares nothing with the adder.
+//
+// WHAT WOULD GO RED: derive the key from a value that is not secret to the group, drop the leaf
+// from its context, take it from the storage exporter, or change the preimage's field order on
+// both sides at once. Each of those passes every case that only asks the sdk to agree with itself.
+func TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads(t *testing.T) {
+	// THE FOUNDING ROAD: AddMember, off the staged commit that opens epoch one
+	world := newWorld(t)
+	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
+	defer cancel()
+	alice := world.newPersona(t, "alice")
+	if err := alice.device.Connect(ctx); err != nil {
+		t.Fatalf("alice's Connect: %v", err)
+	}
+	laptop := world.seamMember(t, ctx, "laptop")
+	founded, err := alice.device.CreateGroup(ctx, bytes.Repeat([]byte{0x47}, urmessage.GroupIdBytes))
+	if err != nil {
+		t.Fatalf("CreateGroup: %v", err)
+	}
+	invite, err := founded.AddMember(laptop.keyPackage(t))
+	if err != nil {
+		t.Fatalf("AddMember: %v", err)
+	}
+	if err := founded.Open(ctx); err != nil {
+		t.Fatalf("Open: %v", err)
+	}
+	carried := gcReencodeInvite(t, invite)
+	laptop.join(t, carried)
+	if epoch := laptop.handle.Epoch(); epoch != 1 {
+		t.Fatalf("the founding road joined at epoch %d, want 1", epoch)
+	}
+	jsSecondSpelling(t, "the founding road", laptop.handle, carried)
+
+	// THE LIVE ROAD: AddMemberAndPublish, inside the publish, over the rotated secret's epoch
+	scene := advFounding(t, true)
+	tablet := scene.world.seamMember(t, scene.ctx, "tablet")
+	invite, err = scene.aliceGroup.AddMemberAndPublish(scene.ctx, tablet.keyPackage(t))
+	if err != nil {
+		t.Fatalf("AddMemberAndPublish: %v", err)
+	}
+	carried = gcReencodeInvite(t, invite)
+	tablet.join(t, carried)
+	if epoch := tablet.handle.Epoch(); epoch != 2 {
+		t.Fatalf("the live road joined at epoch %d, want 2", epoch)
+	}
+	jsSecondSpelling(t, "the live road", tablet.handle, carried)
+}
+
+// A GENUINE SEAL REPLAYED FROM ANOTHER EPOCH IS REFUSED BY THE AUTHENTICATOR. The seal's envelope
+// carries a content epoch of zero, so that the epoch a member joined at is not in the clear, and
+// the price is that the seal's own encryption no longer names its epoch: a seal made for one add
+// of a device opens, as a wrap, under a later add of the same device at the same leaf. Here the
+// device is added twice, at epochs 2 and 4, and the second invite is pasted carrying the FIRST
+// invite's seal. It is refused as unauthenticated, the join code is not spent, and the honest
+// second invite then joins.
+func TestAGenuineSealReplayedFromAnotherEpochIsRefused(t *testing.T) {
+	scene := advFounding(t, true)
+	dave := scene.world.newPersona(t, "dave")
+	if err := dave.device.Connect(scene.ctx); err != nil {
+		t.Fatalf("dave's Connect: %v", err)
+	}
+	first, err := dave.device.KeyPackage()
+	if err != nil {
+		t.Fatalf("dave's first KeyPackage: %v", err)
+	}
+	second, err := dave.device.KeyPackage()
+	if err != nil {
+		t.Fatalf("dave's second KeyPackage: %v", err)
+	}
+	earlier, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, first)
+	if err != nil {
+		t.Fatalf("the first add: %v", err)
+	}
+	bobIdentity := rolesIdentityOf(t, scene.bobGroup)
+	var daveIdentity []byte
+	for _, member := range removalRoster(t, scene.aliceGroup) {
+		if !member.Mine && !bytes.Equal(member.IdentityPub, bobIdentity) {
+			daveIdentity = member.IdentityPub
+		}
+	}
+	if err := scene.aliceGroup.RemoveMember(scene.ctx, daveIdentity); err != nil {
+		t.Fatalf("removing the entry of the invitation that was never opened: %v", err)
+	}
+	later, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, second)
+	if err != nil {
+		t.Fatalf("the second add: %v", err)
+	}
+	if epoch := scene.aliceGroup.Epoch(); epoch != 4 {
+		t.Fatalf("CONTROL FAILED: the group stands at epoch %d after an add, a removal and an add, want 4", epoch)
+	}
+	if bytes.Equal(earlier.JoinSeal, later.JoinSeal) {
+		t.Fatalf("CONTROL FAILED: the two adds carry one seal, so nothing below is a replay")
+	}
+	replayed := gcReencodeInvite(t, &urmessage.Invite{
+		GroupId:     later.GroupId,
+		Welcome:     later.Welcome,
+		RatchetTree: later.RatchetTree,
+		JoinSeal:    earlier.JoinSeal,
+		JoinAuth:    later.JoinAuth,
+	})
+	_, err = dave.device.Join(scene.ctx, replayed)
+	if !errors.Is(err, urmessage.ErrJoinSealUnauthenticated) {
+		t.Fatalf("the later invite carrying the earlier epoch's seal answered %v, want ErrJoinSealUnauthenticated", err)
+	}
+	if !errors.Is(err, urmessage.ErrJoinRefused) || errors.Is(err, urmessage.ErrJoinCodeSpent) {
+		t.Errorf("that refusal is %v, which is not one made inside the window that leaves the join code", err)
+	}
+	daveGroup, err := dave.device.Join(scene.ctx, gcReencodeInvite(t, later))
+	if err != nil {
+		t.Fatalf("the honest later invite after the replay: %v", err)
+	}
+	canary := scene.say(t, "alice", scene.aliceGroup)
+	gcReceiveText(t, scene.ctx, "dave", daveGroup, canary)
+}
```

- [ ] **Step 2: run them.** This task changes no production file: its tests hold what the tasks before it built, so on the tree as it stands they PASS, and what shows that each can fail is its mutation below. Measured, on the tree before this commit with these test files laid over it:

```
$ go -C sdk/cp3b test -count=1 -run ^(TestAGenuineSealReplayedFromAnotherEpochIsRefused|TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads) ./...
exit status 0
ok  	github.com/urnetwork/message/sdk/cp3b	1.727s
$ go -C sdk test -count=1 -run ^(TestAMemberMadeSealIsHeldToItsEpochItsShapeAndItsAddressee|TestEveryOctetOfAnInviteIsHeldAndNoRefusalCostsTheJoinCode) ./urmessage/
exit status 0
ok  	github.com/urnetwork/message/sdk/urmessage	1.791s
```

- [ ] **Step 3: run it and see it pass.**

```bash
go -C sdk test -count=1 ./...
go -C sdk/cp3b test -count=1 ./...
```

Measured on this commit (`lab-s0t1plan/out2/verify/`; `pass` and `fail` count the lines of a `-v` run):

```
sdk            exit=0 pass=339 fail=0
cp3b           exit=0 pass=119 fail=0
advsim-strict  exit=1 pass=25 fail=3
```

- [ ] **Step 4: the mutations.** Each restores a rejected design with one edit, applied alone. Appendix B prints the edits.

1. `MJ43`: the joiner does not compare the digest it recomputes with the one sealed beside the secret. Property 1 must fail. Measured: killed by `TestAMemberMadeSealIsHeldToItsEpochItsShapeAndItsAddressee`.
2. `MJ13`: the joined state is committed to the store before the seal is verified, opened and checked. Property 2 must fail. Measured: killed by `TestEveryOctetOfAnInviteIsHeldAndNoRefusalCostsTheJoinCode`, and 8 other tests.
3. `MJ60`: an invitation whose join code is already gone is answered with the window's sentence: it says the join code is not spent, and it is gone. Property 2 must fail. Measured: killed by `TestEveryOctetOfAnInviteIsHeldAndNoRefusalCostsTheJoinCode`, and 1 other test.
4. `MJ5`: join_key from a public value: the hash of the welcome, on both sides. Property 3 must fail. Measured: killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`, and 3 other tests.
5. `MJ5b`: join_key from another public value: the hash of the ratchet tree, on both sides. Property 3 must fail. Measured: killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`, and 2 other tests.
6. `MJ5c`: the join key's exporter context without the leaf, on both sides. Property 3 must fail. Measured: killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`, and 2 other tests.
7. `MJ5d`: the join key is the storage exporter itself, which is what storage_root is extracted from. Property 3 must fail. Measured: killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`, and 2 other tests.
8. `MJ5e`: the welcome and the tree transposed in the preimage, at both call sites. Property 3 must fail. Measured: killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`, and 2 other tests.
9. `MJ15`: the join seal reuses the device wrap's code points (target 0x01, payload 0x01). Property 3 must fail. Measured: killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`, and 9 other tests.
10. `MJ6`: the preimage does not cover the seal. Property 4 must fail. Measured: killed by `TestAGenuineSealReplayedFromAnotherEpochIsRefused`, and 5 other tests.

- [ ] **Step 5: commit.**

```bash
git add sdk/urmessage/joinsealmember_test.go sdk/cp3b/joinseal_test.go
git commit -m "urmessage, cp3b: the join seal held from the member's side, by a second spelling, and at every octet"
```

The every-octet table, as that run printed it:

```
version                    2 octet(s)  the paste: ErrInviteVersion
length of group id         4 octet(s)  the paste: its framing
group id                  32 octet(s)  in the window: the engine
length of welcome          4 octet(s)  the paste: its framing
welcome                   32 octet(s)  in the window: no join code of this device is addressed
welcome                  397 octet(s)  in the window: the engine
length of ratchet tree     4 octet(s)  the paste: its framing
ratchet tree            2867 octet(s)  in the window: the engine
length of join seal        4 octet(s)  the paste: its framing
join seal               1242 octet(s)  in the window: ErrJoinSealUnauthenticated
join seal                 11 octet(s)  the paste: ErrJoinSealShape
length of join auth        4 octet(s)  the paste: its framing
join auth                 32 octet(s)  in the window: ErrJoinSealUnauthenticated
```

**One row of that table is new with this revision, and the first run of the revised chain
found it the hard way.** R13 gives an invitation whose join code is gone its own sentence, chosen
by the engine's one refusal for "no key package of this store is addressed by this Welcome". A bit
flipped in the reference by which a Welcome addresses its join code is the same refusal: the
Welcome then names a join code this device does not hold. So those octets of the welcome are no
longer answered with the window's sentence, and this case, which asserted the window's sentence of
EVERY refusal inside the window, failed on this commit and on the five after it. It now holds that
refusal to the one field it can come from, holds that it does NOT say the join code is not spent,
and counts the join code after it like after every other: it is still there. `MJ60`, which takes
R13's sentence away, is killed here as well as by the window's own test.

**The live probe's four new steps** are the next four tasks (the lead's ruling: they are tasks of
this plan). `sdk/liveprobe` is one program that runs against a real server with three real
accounts, so it cannot be run in the lab: each step below was BUILT, VETTED and the module's own
tests run, and its first real run is Task 56. Each asserts over the wire what a named in-process test
already holds, and each is its own commit so that the probe's step count in its README is true at
every commit. None supplies a Go test or states a property.

### Task 49: The live probe, join seal step 1 of 4: an invitation at version 2 is refused by its version

- Consumes: the errors of Task 33, Task 36 and Task 46; the probe's own `step`, `check` and `fail`
- Produces: one more step of `sdk/liveprobe`, and its README's step count

**What it asserts.** The invitation A just made, with its version octets changed to 2 under a checksum that covers the change, is refused with `ErrInviteVersion` and not as damaged. It is the first use of `crypto/sha256` in the probe, and the crypto-scope gate of `sdk` holds the nested modules too, so its row for `liveprobe/main.go` gains the import in the same commit (measured: without it the sdk suite has one failing test from this commit on). In process the same is held by the unit case `TestAnInviteFromAnotherVersionOrWithOctetsAfterItIsRefused`.

- [ ] **Step 1: the step.**

`sdk/liveprobe/README.md`:

```diff
--- a/sdk/liveprobe/README.md
+++ b/sdk/liveprobe/README.md
@@ -266,7 +266,8 @@ JWT-shaped value fails and prints the disclosure, naming the count and never the
 stdout by its own hand; catching those needs the file descriptor replaced by a pipe, which costs a
 drained goroutine and loses whatever is in flight when the probe exits on a failure.
 
-The run therefore prints **13 steps**: the eleven scenario steps, the counters, and the read-back.
+The run therefore prints **14 steps**: the eleven scenario steps, one for the join seal, the
+counters, and the read-back.
 
 ## What it does NOT assert
 
```

`sdk/liveprobe/main.go`:

```diff
--- a/sdk/liveprobe/main.go
+++ b/sdk/liveprobe/main.go
@@ -14,6 +14,7 @@ import (
 	"bytes"
 	"context"
 	"crypto/rand"
+	"crypto/sha256"
 	"errors"
 	"flag"
 	"fmt"
@@ -271,6 +272,24 @@ func main() {
 	fmt.Fprintf(out, "  group %x epoch %d; invite %d octets, carried out of band as the design says\n",
 		aGroup.Id()[:8], aGroup.Epoch(), len(encoded))
 
+	// ── the join seal, 1 of 4 ────────────────────────────────────────────────────────────
+	step("an invitation at version 2, the format that carried its secrets in the clear, is refused by its version")
+	fmt.Fprintf(out, "  WHAT THIS IS FOR: version 2 put the join epoch's secret and the group's handle key in the\n"+
+		"  invitation as plain octets. This build writes version 3 and reads nothing else, so that no\n"+
+		"  paste can hand a joiner two secrets somebody on the channel chose. The blob below is the\n"+
+		"  invitation A just made with its version octets changed to 2, under a checksum that covers\n"+
+		"  the change: what is refused is the version, and not a damaged paste.\n")
+	check(2 < len(encoded) && encoded[0] == 0x00 && encoded[1] == 0x03,
+		"the invitation A made begins with the octets %x, want 00 03", encoded[:2])
+	versionTwo := append([]byte{0x00, 0x02}, encoded[2:len(encoded)-sha256.Size]...)
+	versionTwoSum := sha256.Sum256(versionTwo)
+	_, err = urmessage.ParseInvite(append(versionTwo, versionTwoSum[:]...))
+	check(errors.Is(err, urmessage.ErrInviteVersion),
+		"an invitation at version 2, under a checksum that covers it, answered %v, want ErrInviteVersion", err)
+	check(!errors.Is(err, urmessage.ErrInviteDamaged),
+		"the version 2 invitation was refused as DAMAGED (%v): the refusal is the checksum's and says nothing about the version", err)
+	fmt.Fprintf(out, "  refused by its version, before a field of it was read\n")
+
 	// ── 3 ────────────────────────────────────────────────────────────────────────────────
 	step("B joins from the invite and reads the string A typed")
 	carried, err := urmessage.ParseInvite(encoded)
```

`sdk/message_crypto_scope_test.go`:

```diff
--- a/sdk/message_crypto_scope_test.go
+++ b/sdk/message_crypto_scope_test.go
@@ -66,8 +66,8 @@ var sdkCryptoImports = map[string]sdkCryptoImport{
 		"the loopback harness's peer connections draw on crypto/rand.Reader"},
 	"livepeer/main.go": {[]string{"crypto/rand"},
 		"a fresh group id"},
-	"liveprobe/main.go": {[]string{"crypto/rand"},
-		"a fresh group id, and the reader messagegroup.XwingGenerateKey draws a key pair from"},
+	"liveprobe/main.go": {[]string{"crypto/rand", "crypto/sha256"},
+		"a fresh group id, and the reader messagegroup.XwingGenerateKey draws a key pair from; and the checksum over an invite whose version octets the probe changed, so that what is refused is the version"},
 	"message_route.go": {[]string{"crypto/sha256", "crypto/subtle", "crypto/tls"},
 		"the route client's pin: the SHA-256 of the server's public key, compared in constant time, " +
 			"inside a TLS 1.3 configuration"},
```

- [ ] **Step 2: build it, vet it, run the module's tests.**

```bash
go -C sdk/liveprobe vet ./... && go -C sdk/liveprobe test -count=1 ./...
go -C sdk test -count=1 -run 'TestThisModulesProductionCryptoImportsAreTheDeclaredOnes' ./
```

Measured on this commit: clean, and `ok` twice; the whole of `sdk` and `sdk/cp3b` on it is a row of "Measured results". NOT RUN LIVE.

- [ ] **Step 3: commit.**

```bash
git add sdk/liveprobe/README.md sdk/liveprobe/main.go sdk/message_crypto_scope_test.go
git commit -m "liveprobe: an invitation at version 2 is refused by its version"
```

### Task 50: The live probe, join seal step 2 of 4: an invitation with one bit of its authenticator flipped is refused, and the join code is not spent

- Consumes: the errors of Task 33, Task 36 and Task 46; the probe's own `step`, `check` and `fail`
- Produces: one more step of `sdk/liveprobe`, and its README's step count

**What it asserts.** One bit of `join_auth` is flipped in a copy; B's join answers `ErrJoinSealUnauthenticated` inside `ErrJoinRefused` and not `ErrJoinCodeSpent`, B holds no group, and the probe's next step joins the honest invitation over the SAME join code. In process the same is held by `TestABentSealIsRefusedAndTheHonestInviteStillJoins` and the every-octet case.

- [ ] **Step 1: the step.**

`sdk/liveprobe/README.md`:

```diff
--- a/sdk/liveprobe/README.md
+++ b/sdk/liveprobe/README.md
@@ -266,7 +266,7 @@ JWT-shaped value fails and prints the disclosure, naming the count and never the
 stdout by its own hand; catching those needs the file descriptor replaced by a pipe, which costs a
 drained goroutine and loses whatever is in flight when the probe exits on a failure.
 
-The run therefore prints **14 steps**: the eleven scenario steps, one for the join seal, the
+The run therefore prints **15 steps**: the eleven scenario steps, two for the join seal, the
 counters, and the read-back.
 
 ## What it does NOT assert
```

`sdk/liveprobe/main.go`:

```diff
--- a/sdk/liveprobe/main.go
+++ b/sdk/liveprobe/main.go
@@ -290,6 +290,28 @@ func main() {
 		"the version 2 invitation was refused as DAMAGED (%v): the refusal is the checksum's and says nothing about the version", err)
 	fmt.Fprintf(out, "  refused by its version, before a field of it was read\n")
 
+	// ── the join seal, 2 of 4 ────────────────────────────────────────────────────────────
+	step("an invitation with one bit of its authenticator flipped is refused, and B's join code is not spent")
+	fmt.Fprintf(out, "  WHAT THIS IS FOR: the two join secrets travel sealed to B's own device key, and the seal\n"+
+		"  is authenticated by a key only a member of the epoch B is joining can derive. B checks\n"+
+		"  that before it opens anything, and before anything of the join reaches its disk. So an\n"+
+		"  invitation altered on the way is refused AND costs nothing: B's one-use join code goes\n"+
+		"  back, and the honest invitation joins over it in the next step.\n")
+	altered, err := urmessage.ParseInvite(encoded)
+	if err != nil {
+		fail("parse invite: %v", err)
+	}
+	// a copy, so that the octets A's invitation is carried in are not the ones that are bent
+	altered.JoinAuth = bytes.Clone(altered.JoinAuth)
+	altered.JoinAuth[0] ^= 0x01
+	_, err = b.device.Join(ctx, altered)
+	check(errors.Is(err, urmessage.ErrJoinSealUnauthenticated),
+		"an invitation with one bit of its authenticator flipped answered %v, want ErrJoinSealUnauthenticated", err)
+	check(errors.Is(err, urmessage.ErrJoinRefused) && !errors.Is(err, urmessage.ErrJoinCodeSpent),
+		"that refusal is %v: it must say the join code is not spent, and must not say it is", err)
+	check(len(b.device.Groups()) == 0, "B holds %d group(s) after an invitation it refused", len(b.device.Groups()))
+	fmt.Fprintf(out, "  refused inside the join's window; the next step joins the honest invitation over the SAME join code\n")
+
 	// ── 3 ────────────────────────────────────────────────────────────────────────────────
 	step("B joins from the invite and reads the string A typed")
 	carried, err := urmessage.ParseInvite(encoded)
```

- [ ] **Step 2: build it, vet it, run the module's tests.**

```bash
go -C sdk/liveprobe vet ./... && go -C sdk/liveprobe test -count=1 ./...
go -C sdk test -count=1 -run 'TestThisModulesProductionCryptoImportsAreTheDeclaredOnes' ./
```

Measured on this commit: clean, and `ok` twice; the whole of `sdk` and `sdk/cp3b` on it is a row of "Measured results". NOT RUN LIVE.

- [ ] **Step 3: commit.**

```bash
git add sdk/liveprobe/README.md sdk/liveprobe/main.go
git commit -m "liveprobe: an invitation with one bit of its authenticator flipped is refused, and the join code is not spent"
```

### Task 51: The live probe, join seal step 3 of 4: the invitation B already joined is refused when it is pasted again

- Consumes: the errors of Task 33, Task 36 and Task 46; the probe's own `step`, `check` and `fail`
- Produces: one more step of `sdk/liveprobe`, and its README's step count

**What it asserts.** B's join of the invitation it has already joined answers `ErrGroupAlreadyHeld`; B holds the one group it joined, at the epoch it joined at; and the probe's next step is B reading what A sends in it. In process the same is held by the scenarios `S7a` to `S7f`.

- [ ] **Step 1: the step.**

`sdk/liveprobe/README.md`:

```diff
--- a/sdk/liveprobe/README.md
+++ b/sdk/liveprobe/README.md
@@ -266,7 +266,7 @@ JWT-shaped value fails and prints the disclosure, naming the count and never the
 stdout by its own hand; catching those needs the file descriptor replaced by a pipe, which costs a
 drained goroutine and loses whatever is in flight when the probe exits on a failure.
 
-The run therefore prints **15 steps**: the eleven scenario steps, two for the join seal, the
+The run therefore prints **16 steps**: the eleven scenario steps, three for the join seal, the
 counters, and the read-back.
 
 ## What it does NOT assert
```

`sdk/liveprobe/main.go`:

```diff
--- a/sdk/liveprobe/main.go
+++ b/sdk/liveprobe/main.go
@@ -340,6 +340,26 @@ func main() {
 	check(len(back) == 1 && back[0].Text == reply, "A read %s for B's one answer", texts(back))
 	fmt.Fprintf(out, "  the string crossed both ways; B's sender_handle %x\n", back[0].SenderHandle)
 
+	// ── the join seal, 3 of 4 ────────────────────────────────────────────────────────────
+	step("the invitation B already joined is pasted again and is refused, and B's group is the one it holds")
+	fmt.Fprintf(out, "  WHAT THIS IS FOR: a join writes an epoch state, a record and a map entry under the group's\n"+
+		"  id, so a join over a group a device holds would be that group replaced by whatever the\n"+
+		"  invitation carries, and an invitation authenticates nobody. Until this build an invitation\n"+
+		"  into a held group was honoured. It is refused now, before B's join code is looked at, and\n"+
+		"  the next step is B reading what A sends in the group it still holds.\n")
+	again, err := urmessage.ParseInvite(encoded)
+	if err != nil {
+		fail("parse invite: %v", err)
+	}
+	_, err = b.device.Join(ctx, again)
+	check(errors.Is(err, urmessage.ErrGroupAlreadyHeld),
+		"the invitation B had already joined, pasted again, answered %v, want ErrGroupAlreadyHeld", err)
+	bHolds := b.device.Groups()
+	check(len(bHolds) == 1 && bHolds[0] == bGroup,
+		"B holds %d group(s) after the refused invitation, and the one it joined is not the one it holds", len(bHolds))
+	check(bGroup.Epoch() == 1, "B's group is at epoch %d after the refused invitation, want 1", bGroup.Epoch())
+	fmt.Fprintf(out, "  refused; B holds the group it joined, at the epoch it joined at\n")
+
 	// ── 4 ────────────────────────────────────────────────────────────────────────────────
 	step(fmt.Sprintf("%d messages in order, which is what crosses a fetch page", lineCount))
 	fmt.Fprintf(out, "  WHAT THIS IS FOR: 4.3.4 truncates a page by `limit` OR by `max_response_bytes` and\n"+
```

- [ ] **Step 2: build it, vet it, run the module's tests.**

```bash
go -C sdk/liveprobe vet ./... && go -C sdk/liveprobe test -count=1 ./...
go -C sdk test -count=1 -run 'TestThisModulesProductionCryptoImportsAreTheDeclaredOnes' ./
```

Measured on this commit: clean, and `ok` twice; the whole of `sdk` and `sdk/cp3b` on it is a row of "Measured results". NOT RUN LIVE.

- [ ] **Step 3: commit.**

```bash
git add sdk/liveprobe/README.md sdk/liveprobe/main.go
git commit -m "liveprobe: the invitation B already joined is refused when it is pasted again"
```

### Task 52: The live probe, join seal step 4 of 4: every invitation the run carried is at version 3 and carries neither of its adder's two secrets

- Consumes: the errors of Task 33, Task 36 and Task 46; the probe's own `step`, `check` and `fail`
- Produces: one more step of `sdk/liveprobe`, and its README's step count

**What it asserts.** Each invitation the probe carries (B's, from the founding add, and C's, from a live add) is searched at the moment it is made for the adder's `pq_secret` and for the group's handle key as the adder's own durable record holds them; the control is that the record holds both. A closing step counts the invitations read. In process the same is held by the scenarios `P1-hndl-founding`, `P1-hndl-live-add` and `S2a-ghk-paste-observer`.

- [ ] **Step 1: the step.**

`sdk/liveprobe/README.md`:

```diff
--- a/sdk/liveprobe/README.md
+++ b/sdk/liveprobe/README.md
@@ -266,7 +266,7 @@ JWT-shaped value fails and prints the disclosure, naming the count and never the
 stdout by its own hand; catching those needs the file descriptor replaced by a pipe, which costs a
 drained goroutine and loses whatever is in flight when the probe exits on a failure.
 
-The run therefore prints **16 steps**: the eleven scenario steps, three for the join seal, the
+The run therefore prints **17 steps**: the eleven scenario steps, four for the join seal, the
 counters, and the read-back.
 
 ## What it does NOT assert
```

`sdk/liveprobe/main.go`:

```diff
--- a/sdk/liveprobe/main.go
+++ b/sdk/liveprobe/main.go
@@ -67,6 +67,9 @@ var (
 	steps   int
 	checks  int
 	current string
+
+	// the invitations this run carried that [sealed] has read, for the step that counts them
+	sealedInvites int
 )
 
 // ── the transcript, which this run reads back at the end ─────────────────────────────────────
@@ -269,6 +272,7 @@ func main() {
 		fail("A Open: %v", err)
 	}
 	check(aGroup.IsOpen(), "Open returned no error and the group does not say it is open")
+	sealed("B's invitation, from the founding add", encoded, a, groupId)
 	fmt.Fprintf(out, "  group %x epoch %d; invite %d octets, carried out of band as the design says\n",
 		aGroup.Id()[:8], aGroup.Epoch(), len(encoded))
 
@@ -426,6 +430,7 @@ func main() {
 	if err != nil {
 		fail("encode C's invite: %v", err)
 	}
+	sealed("C's invitation, from a live add", thirdEncoded, a, groupId)
 	thirdCarried, err := urmessage.ParseInvite(thirdEncoded)
 	if err != nil {
 		fail("parse C's invite: %v", err)
@@ -1362,6 +1367,16 @@ func main() {
 	removalReport("B  owner, committed it", bGroup, cId)
 	removalReport("C  removed, two leaves", cGroup, cId)
 
+	// ── the join seal, 4 of 4 ────────────────────────────────────────────────────────────
+	step("every invitation this run carried is at version 3 and carries neither of its adder's two secrets")
+	fmt.Fprintf(out, "  WHAT THIS IS FOR: it is the claim itself, read off what this run pasted. Each invitation\n"+
+		"  was searched, at the moment it was made, for the join epoch's secret and for the group's\n"+
+		"  handle key as its adder's own disk holds them. What an invitation still shows is the\n"+
+		"  group's id and who is in it: the seal narrows what a paste gives away, and does not make\n"+
+		"  an invitation something to post in public.\n")
+	check(sealedInvites == 2, "this run read %d invitation(s) for their adder's secrets, and it carried 2", sealedInvites)
+	fmt.Fprintf(out, "  %d invitations, one from the founding add and one from a live add; neither secret in either\n", sealedInvites)
+
 	// ── the counters, which are the last thing a reader should see ───────────────────────
 	step("the counters")
 	report("A", aGroup)
@@ -1674,6 +1689,33 @@ func connectAcrossTheReconnectWindow(ctx context.Context, p *party, what string,
 	fmt.Fprintf(out, "  %s was routed to after %v\n", what, time.Since(began).Round(time.Millisecond))
 }
 
+// sealed holds one invitation this run carried to the two things the join seal promises of it: it
+// is at version 3, and NEITHER SECRET OF ITS ADDER IS AMONG ITS OCTETS. The adder is a party of
+// this run, so the two values are read off its own durable record and searched for as octets;
+// the control is that the record holds them, since a search for nothing finds nothing.
+func sealed(what string, encoded []byte, adder *party, groupId []byte) {
+	check(2 < len(encoded) && encoded[0] == 0x00 && encoded[1] == 0x03,
+		"%s begins with the octets %x, want 00 03", what, encoded[:2])
+	records, err := adder.stateStore.GroupRecords()
+	if err != nil {
+		fail("%s: reading %s's durable record: %v", what, adder.name, err)
+	}
+	var record *urmessage.GroupRecord
+	for _, one := range records {
+		if bytes.Equal(one.GroupId, groupId) {
+			record = one
+		}
+	}
+	check(record != nil && len(record.PqSecret) == 32 && len(record.GroupHandleKey) == 32,
+		"CONTROL FAILED: %s's durable record does not hold the two secrets to search %s for, so a "+
+			"count of zero would be a search for nothing", adder.name, what)
+	check(!bytes.Contains(encoded, record.PqSecret),
+		"%s CARRIES ITS ADDER'S pq_secret IN THE CLEAR, among its %d octets", what, len(encoded))
+	check(!bytes.Contains(encoded, record.GroupHandleKey),
+		"%s CARRIES THE GROUP'S HANDLE KEY IN THE CLEAR, among its %d octets", what, len(encoded))
+	sealedInvites += 1
+}
+
 func step(s string) {
 	steps += 1
 	current = s
```

- [ ] **Step 2: build it, vet it, run the module's tests.**

```bash
go -C sdk/liveprobe vet ./... && go -C sdk/liveprobe test -count=1 ./...
go -C sdk test -count=1 -run 'TestThisModulesProductionCryptoImportsAreTheDeclaredOnes' ./
```

Measured on this commit: clean, and `ok` twice; the whole of `sdk` and `sdk/cp3b` on it is a row of "Measured results". NOT RUN LIVE.

- [ ] **Step 3: commit.**

```bash
git add sdk/liveprobe/README.md sdk/liveprobe/main.go
git commit -m "liveprobe: every invitation the run carried is at version 3 and carries neither of its adder's two secrets"
```

### Task 53: The open items file records what the join seal takes of MG-7, and what it settles

- Consumes: `messagegroup/OPENITEMS.md`'s MG-7; the formats of Task 43; open items M1-52 and M1-54 of the message-crypto plan, which it leaves as they are
- Produces: a subsection of MG-7

**Behaviour.** A document change. MG-7 says three of the wrap key's inputs have no ruled code
point and that the wrap envelope's version octet is authenticated by nothing. The join seal takes
two more code points and is the first wrap whose version octet IS authenticated, by `join_auth`
over `SHA-256(join_seal)`. The item says so, and says what is unchanged: a device wrap's version
octet. This task supplies no Go test and states no property; `messagegroup`'s own gates read the
file and pass.

- [ ] **Step 1: the change.**

`messagegroup/OPENITEMS.md`:

```diff
--- a/messagegroup/OPENITEMS.md
+++ b/messagegroup/OPENITEMS.md
@@ -841,6 +841,29 @@ names and leaves to the implementation — *"may or may not compare the carried
 and refuse a mismatch"* — so it rules nothing: the wire does not move, and the ruling M1-55 owes is
 owed exactly as before.
 
+### What the join seal takes, and what it settles for itself
+
+The sealed invite (`sdk/urmessage/joinseal.go`, invite version `0x0003`) is the second user of this
+door. It takes two more code points and it is the first wrap whose version octet is authenticated.
+
+- **Code points, still provisional, now with two users.** The join seal's envelope is
+  `u8(0x01) ‖ u8(target_type = 0x03 JOINER) ‖ u8(payload_type = 0x04 JOIN_SECRETS_V1) ‖ u64(0)`,
+  with `target_id = u32(joiner_leaf)`. The device wrap keeps target `0x01` and payloads `0x01` and
+  `0x02`; target `0x02` and payload `0x03` stay unassigned for the recovery wrap. This package still
+  takes all of them as parameters and chooses none: the table this item asks MASTER §7 for now has
+  five rows to write down and not three.
+- **The content epoch is the constant zero**, so that the epoch a member joined at is not in the
+  clear. The seal's own key therefore names no epoch, and a seal made for one add of a device opens,
+  as a wrap, under a later add of the same device at the same leaf. What refuses it is not this
+  door: it is the invite's authenticator.
+- **The version octet of a join seal IS authenticated.** `join_auth` is an HMAC-SHA-256, keyed by
+  the join epoch's exporter, over a preimage that carries `SHA-256(join_seal)`: all eleven envelope
+  octets and the whole body. The joiner verifies it before it opens the seal, and refuses any
+  envelope that is not the four constants above before that. So this item's second half is closed
+  **for the join seal and for no other wrap**: a device wrap's version octet is authenticated by
+  nothing, exactly as this item's reproduction measures, and `M1-52` and `M1-54` are owed exactly
+  as before.
+
 ### What a ruling has to choose
 
 1. **The three code points**, as a table: which octet a device leaf is and which a member's
```

- [ ] **Step 2: run the package that reads the file.**

```bash
go test -count=1 ./messagegroup/
```

Measured on this commit: `ok`.

- [ ] **Step 3: commit.**

```bash
git add messagegroup/OPENITEMS.md
git commit -m "messagegroup: the open items file records what the join seal settles"
```

### Task 54: Run every mutant on the T1 tree

- Consumes: the mutations stated in every task of phases T1a and T1; Appendix B
- Produces: a table of kills made on the branch, to stand beside the lab's

This task changes no file and states no property. Apply each of the 40 T1 mutants and the 35
T1a mutants of Appendix B alone to the tree of Task 52, run `messagegroup`, `sdk/urmessage` and the
whole of `sdk/cp3b`, and restore the tree. Every one must be killed by the test its task names. The
lab's run of the same 75 is the second table of "Mutation proofs". One of them, `MJ63`, is killed
in `./mls/` and by none of those three suites: run that package for it, as Appendix B says.

### Task 55: The reset, defined and checked

- Consumes: the owner's statement that the alpha server is disposable in development; `ErrGroupPredatesJoinSeal` (Task 47); `ErrNoDeviceWrapKey` from `KeyPackage()` (Task 42); `ForgetGroup`'s leave of a group that did not restore (Task 33)
- Produces: a reset that is a list of things done and not an assumption

**Why this is a task.** Every part Appendix A drops rests on "no version 2 invitation and no
group founded before T1 survives". The server being disposable does not make that true of a
laptop: the record format is unchanged, so a state directory an earlier build wrote opens under
this one. This task changes no file of this repository and states no property; what it leans on is
measured in Task 47.

- [ ] **Step 1: the server.** The alpha message-server's store is emptied by the lead, who holds
  the box (not by this plan: it uses no VPS access). Recorded in the ledger with the date.
- [ ] **Step 2: every client state directory, listed**, by the lead with the owner. The owner's app directory on each device
  the alpha ran on; every `-dir` the probe and `livepeer` were ever given. For each, one of two
  things, written down: DELETED, or KEPT.
- [ ] **Step 3: what a kept directory does under this build**, which is the check and needs no
  trust in step 2:
  - every group in it that was founded before T1 does not restore, and `Restore` says why by name
    (`ErrGroupPredatesJoinSeal`); it is left with `ForgetGroup` and founded again;
  - a directory written before the X-Wing seed was kept answers `ErrNoDeviceWrapKey` from
    `KeyPackage()`: it can publish no join code, and is deleted;
  - an old invitation or join code pasted into this build is refused by name
    (`ErrInviteVersion`, `ErrJoinerCannotOpenSealedInvite`).
- [ ] **Step 4: the one rule a reset does not retire.** NEVER RUN A PACKAGE FROM BEFORE T1 OVER A
  STATE DIRECTORY THIS BUILD HAS USED. The old build restores a T1 group, because the record
  format is unchanged, and an add made from it pastes the group's handle key and the epoch's
  secret in the clear, with nothing on any side to detect it. Delete the directory instead. The
  rule goes in the owner's report and in the T1 package's notes, and THE NOTES HAVE A WRITER AND A
  STEP: the lead writes them at Task 59, which is where a T1 package is first built. A technical stop
  (an old build that cannot open a T1 directory) would be a change to the record format; it is not
  planned, and Appendix A prices it.
- [ ] **Step 5: what the owner is told, in plain words (R9).** Test conversations made before
  this package stop opening under it, and each folder is started fresh. It is one of the two
  duties that follow from refusing a group founded before T1; the other is the app's sentence
  (Task 58). Both sentences are in the T1 report as this plan prints it.

### Task 56: Live verification after the reset: the probe's 17 steps

- Consumes: the reset (Task 55); the probe's four new steps (Task 49 to Task 52); three probe accounts and the server's own endpoint and pin, which the lead holds
- Produces: a transcript ending "17 STEPS", and a note that the server was not touched

This task changes no file and states no property. It is ordinary client traffic from the probe
accounts; nothing is installed on the server. It is run by the lead, who holds the access; this
plan used none.

- [ ] **Step 1: build the probe as its README does.** For the linux host it is staged on:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go -C sdk/liveprobe build -o liveprobe .
```

- [ ] **Step 2: run it, all three parties on the T1 commit, fresh state directories.**

```bash
sdk/liveprobe/liveprobe -a <A.jwt> -b <B.jwt> -c <C.jwt> -server <server client_id> -dir <fresh dir> -route urnetwork -endpoint wss://<the server's own endpoint> -pin <64 hex>
```

The last line must read `=== 17 STEPS, <n> ASSERTIONS, ALL HELD ===`: the thirteen it prints
today, unchanged over version 3 invitations, and the four of Task 49 to Task 52.

- [ ] **Step 3: the owner's own state.** Start the T1 app, or `livepeer`, once over each directory Task 55 kept, and read what it restores: each group is either one founded since the reset or is answered by name and left. The live check is made on the owner's ACTUAL state and not only on fresh directories.

- [ ] **Step 4: the server is untouched.** By hand: its process id and uptime are unchanged, and its journal shows no new error kind.

### Task 57: Pre-merge review: the join seal design's round-2 prompts 3 to 7, and this plan's departures

- Consumes: the join seal design's section 7.3; the code of phases T1a and T1 as it stands on the branch; the scenarios and mutants of this plan
- Produces: a red-team record in the ledger, with every finding dispositioned, before the T1 pull request merges

**Why this is a task.** The design's status line requires a round-2 red team on its new
mechanisms before any spec edit. It was not run. The lead's ruling of 2026-10-09: its untouched
prompts are a pre-merge review at the end of T1. The lead assigns the reviewer, who wrote neither
the design nor this plan nor the code under review. This task changes no file and states no
property.

**It reviews T1a's mechanisms AFTER they have merged** (the lead's ruling; the final check's F15).
The removed-group exception, the admission mutex and `ForgetGroup` without the owner's question
are on `main` from the T1a pull request on. Task 40 records that in the ledger and in its
report, so that "merged" is not read as "reviewed"; a finding here against one of them is a
change to `main`, not a change to a branch.

**What this plan already answers by measurement**, so the review starts from evidence: prompt 2
(the create-only probe treats only `ErrStateNotFound` as absent; any other answer refuses). Prompt
1 (the two-phase join: Task 36, with a window that has one exit) is answered IN PART: every
refusal inside the window is driven, and NO TEST CRASHES THE PROCESS INSIDE THE WINDOW, so what a
crash there leaves is argued and not measured. It is question (a) of step 6. Prompts 8 to 10 are
about parts the reset variant drops.

- [ ] **Step 1: prompt 3, the removed-group exception.** Can it be used for more than a denial
  of service? MEASURED HERE, AND THE ANSWER IS YES: a second founder's invitation above the
  removal's epoch replaces the removed group's record and the device stops reading as removed
  (`S7g-removed-group-second-founder`, pinned open until the identity track). The review decides
  whether pinning is enough until then, or whether the exception should also require something
  the removing group alone can show.
- [ ] **Step 2: prompt 4, the requirement and the leaf capabilities.** Can either block an honest
  flow: update leaves, path leaves, owner succession? And, new in this plan: a build that refuses
  to join or restore a group without the requirement (Task 47).
- [ ] **Step 3: prompt 5, content epoch 0.** Any replay or cross-protocol consequence beyond the
  one measured: a seal of one add opens, as a wrap, under a later add of the same device at the
  same leaf, and the authenticator refuses it (Task 48).
- [ ] **Step 4: prompt 6, the digest in the payload.** Is there an oracle? A member that seals the
  wrong epoch's secret AND recomputes the digest from it survives the window and fails at the
  first read; is that acceptable?
- [ ] **Step 5: prompt 7, the reorder and the hook.** Does the server check anything that moving
  the digest ahead of the wraps disturbs?
- [ ] **Step 6: this plan's departures from the design**, each as a question:
  the staging store in `sdk/urmessage` and not `messagegroup`; the capability unconditional; the
  adder's clock is the wall clock; no drift check on the live road, because one value serves the
  hook and the record; and one mutex (`Device.admitMutex`) held across the whole of a join, a
  founding and a restore: what it blocks, and for how long. And the two choices the lead
  confirmed and kept on this list (R9): a group founded before T1 is REFUSED at `Restore` and at
  `Join` and not merely marked; and `ForgetGroup` leaves a group that did not restore, or whose
  record does not read, WITHOUT asking the owner's question. Then the questions the final check
  of this plan left open, which the lead did not rule and gave to this task (R14):
  - **(a) a crash inside the join's window.** No test kills the process between `begin` and
    `commit`. What is on the disk then, and what does the next start do with it? The design
    accepts the residual (the join code is lost, and nobody was told); the sentence a person meets
    afterwards is `ErrNoJoinCodeForInvite` (Task 36).
  - **(b) the read path during a join's window (the final check's F15).** While a join is staged,
    the stage answers the STAGED state to any reader of that group id and epoch (`joinstage.go`,
    `GetGroupState`). Read, not run: a group a commit removed this device from is still open
    while the join that replaces it is staged, and its history loader reads through the same
    store. Can a reader other than the join be handed the staged state, and does it matter?
  - **(c) the erase after a failed record write (the final check's F16).** Read in the final
    `Join`, not run: past the commit, a join whose record cannot be written closes its session and
    its handle and returns `ErrJoinCodeSpent`, and neither the group's handle key nor that
    group's copy of the epoch's secret is erased on that path; and a hold refused at that point
    (`holdReplacing`) is not typed as spent although the join code is gone. Is each a defect, and
    does it change what `ErrJoinCodeSpent` promises?
  - **(d) the sentence for a join code that is gone (R13).** `ErrNoJoinCodeForInvite` is chosen by
    the engine's one refusal for "no key package of this store is addressed by this Welcome",
    which a store that FAILED TO READ a join code it holds also answers. Is "this device holds no
    join code this invitation was made for" acceptable for that case, or does the store's
    not-found need a type the engine can pass on? The same sentence is also what a Welcome bent
    on the paste channel gets when the bit is in its reference to a join code (measured: 32 of a
    founding invitation's octets, Task 48); the join code is still there after it.
  - **(e) one record that does not read (R12).** `Restore` now goes on past it, which is behaviour
    that was there before this plan, changed on purpose; and "does not read" covers a file the
    disk would not hand over as well as one whose checksum fails, so `ForgetGroup` leaves either
    without the owner's question. Is a read that fails for a moment (another process holding the
    file) a reason to make that leave wait for a `Restore` that tried? And should the list recover
    a damaged record's group id, by reading it out of the file's first part and keeping it only
    if it hashes to the directory's name, so that a restore can say WHICH conversation is damaged
    (R12 asks for the id "where the store's own naming gives one", and this store's gives none)?
  - **(f) the store's own words for a damaged record (the second check's note; R17).** When a
    group's own record is damaged, the refusal's chain ends with the store's older words "this is
    not a state record this build wrote", which is untrue of a record this build wrote and the
    disk damaged. It predates this plan, and a person sees the app's sentence (Task 39), not the
    chain. Should the store say what it found instead?
- [ ] **Step 7: record and disposition.** The record goes in the ledger. A finding that changes
  the seal, the payload or the authenticator is a new invite version and a new capability, and
  stops the T1 pull request until it is answered.

### Task 58: The app's sentences and its pending mark (message-windows writer)

- Consumes: the typed errors of this plan, the one sentence every refusal inside the join's window begins with and the one refusal that does not carry it (Task 36); the leave action of Task 39; the native bridge, which carries sentences and not types
- Produces: the app's copy for each refusal, a mark on an entry nobody has joined behind, and the screenshots the message-server writer writes Spec C from

**Why this is a task with an owner, and not a footnote.** The design's own round 1 found "the
app is optional" to be wrong. The bridge hands the app an error's sentence, so the app tells the
cases apart by text; and pending entries still arise after a reset: an invitation that is lost, or
a live add whose commit landed and whose invitation never reached anybody. This task changes no
file of this repository and states no property. No exported symbol and no header octet changes in
this plan, so the app builds against the T1 library as it is; what it owes is copy.

**One row is not here any more (R13).** `ErrGroupAlreadyHeld`, with the action it needs, is
Task 39, at the close of T1a: its refusal ships with T1a, so its half of the app does too.

**Spec C is not this writer's file (R7).** `docs/specs/2026-08-12-spec-c-windows-client-ui.md` is
a file of `message-server`. This task produces the app and its screenshots; the message-server
writer writes Spec C's text from them (Task 41, step 4).

| The sdk answers | The app says |
|---|---|
| a sentence beginning with `ErrJoinRefused`'s | "This invitation was refused. Your join code is still good: ask for the invitation to be sent again another way." |
| `ErrNoJoinCodeForInvite`, which does NOT begin with that sentence (R13, R17) | "This invitation cannot be used with any join code this device can read. Make a new join code and ask to be invited again." It must never be shown the row above: asking for the same invitation again can never work. The copy does not say the join code "was used", and does not say the device has none: the same answer is given to an invitation made for another device, and when the store holds the join code and cannot read it. |
| `ErrJoinCodeSpent` | "This join did not complete. Make a new join code and ask to be added again." |
| `ErrInviteVersion` | "This invitation was made by an older URmessage. Ask them to update and invite you again." |
| `ErrGroupPredatesJoinSeal` (R9: a sentence, never the raw error) | "This group was started before invitations were sealed. Leave it and start it again." |
| `ErrJoinerCannotOpenSealedInvite` | "This join code was made by an older URmessage. Ask them for a new one from an updated app." |
| `ErrKeyPackageInvalid` | "This is not a valid join code. Ask them to send it again." |
| `ErrJoinerAlreadyHasALeaf` | "They already have an entry in this group, perhaps from an invitation that was never opened. Remove that entry, then add their new join code." |
| `ErrNoDeviceWrapKey` from `KeyPackage()` at startup | an on-screen refusal: this installation cannot make a join code |

- [ ] **Step 1: the sentences above**, each screenshotted from the running app (a green build is
  not a check of what a person sees).
- [ ] **Step 2: a "has not joined yet" mark** on an entry with no record under its handle since
  its add, with a remove action for an admin or the owner.
- [ ] **Step 3: the adder's copy** for an invitation: "Only their device can open it. It works
  once. Send it privately." The joiner's paste label keeps its "secret" framing.
- [ ] **Step 4: hand the sentences and the screenshots to the message-server writer**, for Spec C.

### Task 59: Close T1: the full run on both hosts, the ledger, the pull request, the final report

- Consumes: every T1 task, Task 41 to Task 58
- Produces: the T1 pull request, the ledger's close of the track, and the owner's final report

This task changes no file of this repository and states no property.

- [ ] **Step 1: the full run, on both hosts (R8).** On linux with gcc, on the host `alt-2` (the race detector, the composed native library and `sdk/cgo`, `nm`, the pinned protoc), and on Windows from a clone made with `core.autocrlf=true`. Neither was run in the lab, which has no C compiler. The verdicts are R8's, as R15 words them. `alt-2` prints `VERDICT: PASS, narrower than the full run (above)` with exactly one narrowing, the loopback library's C consumer, which is a Windows program. The Windows run is the `windows` leg of Step 2 (a `core.autocrlf=true` clone on GitHub's Windows runner, MinGW-w64 gcc on `PATH`), and it prints `VERDICT: PASS`, or the narrowed verdict with exactly one narrowing, the C consumer's second pass under ThreadSanitizer. Any other narrowing, or a second one, stops the close; a run on a host with no C compiler ends `VERDICT: FAIL` by design and is not this run. Print every narrowing line each run lists, and hold the set to the allowed one both ways. Both runs are under the toolchain pin of the day (R6), and the numbers this phase reports are these runs' numbers. T1 changes the `Invite` type the native bridge hands through, and the composed native library was not built in the lab.

```bash
./test.sh
```

- [ ] **Step 2: the fork's workflow, all four legs (R8, R11).** Run `fork-ci.yml` on the branch head, on the owner's fork, with all four legs, and wait for four green legs. The fourth is the provenance leg in R11's form: the recorded tip of the import's proof (the head of the pins switch) is an ancestor of this branch, and the proof passes AT that tip. THIS PHASE ADDS NO ROW TO `docs/history/adaptations.tsv` AND CHANGES NO FILE UNDER `docs/history`. The leg's change landed with the pins switch: it holds the recorded tip `7a33917306ae` (`docs/history/recorded-tip.txt`) and runs that tip's own proof, and it is green on `0bb2128f` (fork run 38290870884). If it is red on a phase head, that is a finding for the lead, and no row is improvised to make it pass. The workflow file is fork-only and is in no upstream pull request.

- [ ] **Step 3: the pull request.** From a branch CUT FROM `urnetwork/message` `main`, pushed to the fork, to `urnetwork/message` main: merge commit only, never force-pushed (`README.md`, Contributing). When `main` moves, `main` is merged into the branch. It is opened after Task 57 has no open finding. Its description carries the two verdict lines, the id of the fork's run with its four legs, the scan's verdict, the kills of Task 54 and the live transcript of Task 56.

- [ ] **Step 4: the scan, by hand, under the moved pin (R6, R16).** The pin moved before S0 (`0bb2128f`), and the scan's tool is `govulncheck` v1.9.0 (R16). Run it on `alt-2`, where the native library is scanned as well: this run MUST PRINT `VERDICT: PASS`. If it does not, an advisory now reaches the code (the database has moved, or a change of this plan reached one), or the tool did not run: either is a finding for the lead, and it stops the pull request.

```bash
MESSAGE_TEST_VULNCHECK=1 ./test.sh
```

- [ ] **Step 5: the T1 package's notes (the lead).** Whoever builds the first package on a T1 library writes its notes, and that is the lead. They carry, in plain words: (1) the one rule of Task 55 step 4, NEVER RUN A PACKAGE FROM BEFORE T1 OVER A FOLDER THIS BUILD HAS USED; (2) R9's two sentences: test conversations made before this package will not open under it, and each folder is started fresh; (3) what the package was built under, and the scan's verdict of the step above.

- [ ] **Step 6: the ledger (message-server writer, R7).** The same writer as Task 1, in its own small pull request to urnetwork/message-server, paired with this phase and merged first. The close of the track: the live transcript of Task 56, the kills of Task 54, the review record of Task 57, the program plan's status row for the join seal, and a PROGRESS.md row.

- [ ] **Step 7: the report.** Send "At the end of T1" from "Reports to the owner", with the numbers of the runs made on the branch, under the compiler of the day, and finalize the track with the owner.

---

# Mutation proofs

Each mutant restores a rejected design with one edit. Each was applied alone to a fresh
worktree of the lab's chain, the three suites were run (`messagegroup`, `sdk/urmessage`, the whole
of `sdk/cp3b`; and `mls` as well for `MJ63`, the one mutant whose kill is there), and the worktree
was discarded. "Killed by" is the test this plan relies on, and it was among the tests that failed;
"also" counts the other tests that failed. Every mutant below was killed. Appendix B prints each
as a diff. ALL OF IT WAS RUN AGAIN ON THE REVISED CHAIN: the commits of T1a and T1 are new commits
since the final check, and a kill measured on the chain before is not quoted here.

**The harness's own instruments, on the S0 tree (the harness's tests only): 8 mutants.**

| Mutant | The rejected design it restores | Mechanism | Stated in | Killed by | Also |
|---|---|---|---|---|---|
| HV1 | an open entry whose adversary observes the goal passes: a gap that closed stays recorded as open | the verdict rules | Task 2 | `TestAdvSimVerdictRules` | 0 |
| HV2 | a closed entry passes whatever its adversary observes | the verdict rules | Task 2 | `TestAdvSimVerdictRules` | 0 |
| HV3 | strict mode passes an open gap: the RED report is green | the verdict rules | Task 2 | `TestAdvSimVerdictRules` | 0 |
| HV4 | the registry carries an entry no scenario judges | the registry | Task 2 | `TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario` | 0 |
| HV5 | the grant reads the init key one octet off: the octets it looks for are not the key the Welcome is sealed to | the quantum grant | Task 3 | `TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf` | 0 |
| HV6 | the grant ignores its rule: the joiner's classical keys are granted whether or not the init key was captured | the quantum grant | Task 9 | `TestAdvSimTheInvitationAloneReadsNothing` | 0 |
| HV7 | the scrape for pq_secret confirms nothing: it has gone blind | the scrape | Task 8 | `TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets` | 4 |
| HV8 | the scrape for the group handle key confirms nothing: it has gone blind | the scrape | Task 12 | `TestAdvSimAPasteObserverRecoversTheGroupHandleKey` | 5 |

**T1a, on the T1a tree: 35 mutants.**

| Mutant | The rejected design it restores | Mechanism | Stated in | Killed by | Also |
|---|---|---|---|---|---|
| MJ25 | the held-group gate removed: nothing asks whether the device holds the group | the held-group gate | Task 33 | `TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing` | 12 |
| MJ25b | the gate asks the device's memory and not its disk | the held-group gate | Task 33 | `TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing` | 5 |
| MJ25c | the removed-group exception removed: a re-add is refused like any held group | the held-group gate | Task 33 | `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins` | 3 |
| MJ35 | the gate is asked ABOVE the admission mutex (the first revision of this plan): two joins that overlap both read "not held" | the admission mutex | Task 33 | `TestTwoJoinsIntoOneGroupIdThatOverlapAdmitExactlyOne` | 2 |
| MJ38 | the map is written without looking: hold and holdReplacing replace whatever is there | the admission mutex | Task 33 | `TestAMapEntryIsReplacedOnlyByTheJoinThatJudgedIt` | 0 |
| MJ42 | a founding asks nothing first: the second group under one id is refused only at the hold, after mls wrote its epoch zero | the admission mutex | Task 33 | `TestNoGroupIsFoundedUnderAnIdThisDeviceHolds` | 2 |
| MJ37 | the re-add rule removed: an invitation at or below the epoch of the removal is honoured | the re-add rule | Task 33 | `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins` | 0 |
| MJ36 | ForgetGroup refuses a group Restore could not bring back (the first revision of this plan): such a group can be neither restored, left nor joined again | leaving a group that does not restore | Task 33 | `TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain` | 1 |
| MJ36b | ForgetGroup leaves ANY group that is on the disk and not in memory: a restart is a way round the owner's refusal | leaving a group that does not restore | Task 33 | `TestForgetGroupOverAGroupOnTheDiskAnswersByWhatRestoreSaid` | 1 |
| MJ53 | the held-group gate asks the store for EVERY record (this plan as it stood at its final check): one record that does not read refuses every invitation on the device | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 4 |
| MJ53b | a founding asks the store for every record: one record that does not read refuses a founding under any id | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ53c | ForgetGroup asks the store for every record: the damaged record of one group is the answer for another | one record that does not read | Task 33 | `TestForgetGroupLeavesAGroupWhoseRecordDoesNotReadAndThatGroupAlone` | 0 |
| MJ54 | the gate reads any answer but a record as "not held": a store that cannot answer, and a record that does not read, let the join write | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ54b | a founding that finds the disk unreadable founds anyway | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ55 | the list answers an error and no list over one record that does not read (the store as it was): Restore brings back nothing | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ55b | Restore returns on the list's report, before its loop (the device as it was): one damaged file costs every group on the device | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 0 |
| MJ55c | Restore goes on past a record that does not read and says nothing of it | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 0 |
| MJ56 | ForgetGroup refuses a group whose record does not read (this plan as it stood at its final check): it can be neither restored, left nor joined again | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ66 | a record that does not read is refused as "could not be read", which names no remedy (this plan as it stood at its final check): the person is not sent to ForgetGroup | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 0 |
| MJ59 | a record is answered from a directory it does not name: the list holds a group the one-id read answers "not held" for | one record that does not read | Task 33 | `TestOneRecordThatDoesNotReadIsReportedByTheListAndAnsweredOnlyForItsOwnGroup` | 0 |
| MJ57 | Restore is outside the admission mutex: it files groups while a join is between its question and its hold | the admission mutex | Task 33 | `TestARestoreThatOverlapsAJoinWaitsForIt` | 0 |
| MJ58 | CreateGroup is outside the admission mutex: a founding asks whether its id is held while a join into that id is between its question and its hold | the admission mutex | Task 33 | `TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld` | 0 |
| MJ26 | the engine does not hand mls the group id: the intent match is off through both doors | the bound join | Task 34 | `TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing` | 4 |
| MJ26b | the sdk joins through the unbound door and compares the group id afterwards | the bound join | Task 35 | `TestProductionJoinsOnlyThroughTheBoundDoor` | 3 |
| MJ27 | the create-only probe removed: the commit writes over a state that is already there | the create-only commit | Task 36 | `TestAStagedJoinReachesTheStoreOnlyAtCommitAndNeverOverAStateAlreadyThere` | 2 |
| MJ27b | a store that fails to answer is read as "nothing there" | the create-only commit | Task 36 | `TestACommitOverAStoreThatCannotAnswerIsRefused` | 0 |
| MJ31 | the probe erases what the store answered, which is the store's own array | the create-only commit | Task 36 | `TestTheCreateOnlyProbeLeavesTheStoresOwnArrayAlone` | 0 |
| MJ28 | the one-phase join: the stage never stages, and the joined state is written as the engine joins | the two-phase join | Task 36 | `TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode` | 7 |
| MJ28b | a refused join does not put the join code back | the two-phase join | Task 36 | `TestAnAbortedJoinPutsTheJoinCodeBack` | 3 |
| MJ39 | a refusal inside the window answers its bare cause: nothing says the join code is not spent | what a refusal says | Task 36 | `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent` | 0 |
| MJ26c | the bound door takes an empty group id, which turns the intent match off and makes it the unbound door under another name | the bound join | Task 34 | `TestJoinFromWelcomeIntoRefusesAnEmptyGroupId` | 0 |
| MJ40 | the put-back's failure is discarded (the first revision of this plan, on the engine's refusal): a join code the store did not take back is reported as still good | what a refusal says | Task 36 | `TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent` | 1 |
| MJ41 | a join whose record could not be written does not say its join code is spent | what a refusal says | Task 36 | `TestAJoinWhoseRecordCannotBeWrittenSaysTheJoinCodeIsSpent` | 1 |
| MJ60 | an invitation whose join code is already gone is answered with the window's sentence: it says the join code is not spent, and it is gone | what a refusal says | Task 36 | `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent` | 0 |
| MJ61 | a record of an earlier epoch that does not authenticate is handed back as a gap: the symptom of MG-8 goes away, and with it the tampering signal for every past epoch | the open item MG-8 | Task 37 | `TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen` | 1 |

**T1a and T1, on the T1 tree: 75 mutants.**

| Mutant | The rejected design it restores | Mechanism | Stated in | Killed by | Also |
|---|---|---|---|---|---|
| MJ25 | the held-group gate removed: nothing asks whether the device holds the group | the held-group gate | Task 33 | `TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing` | 12 |
| MJ25b | the gate asks the device's memory and not its disk | the held-group gate | Task 33 | `TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing` | 5 |
| MJ25c | the removed-group exception removed: a re-add is refused like any held group | the held-group gate | Task 33 | `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins` | 3 |
| MJ35 | the gate is asked ABOVE the admission mutex (the first revision of this plan): two joins that overlap both read "not held" | the admission mutex | Task 33 | `TestTwoJoinsIntoOneGroupIdThatOverlapAdmitExactlyOne` | 2 |
| MJ38 | the map is written without looking: hold and holdReplacing replace whatever is there | the admission mutex | Task 33 | `TestAMapEntryIsReplacedOnlyByTheJoinThatJudgedIt` | 0 |
| MJ42 | a founding asks nothing first: the second group under one id is refused only at the hold, after mls wrote its epoch zero | the admission mutex | Task 33 | `TestNoGroupIsFoundedUnderAnIdThisDeviceHolds` | 2 |
| MJ37 | the re-add rule removed: an invitation at or below the epoch of the removal is honoured | the re-add rule | Task 33 | `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins` | 0 |
| MJ36 | ForgetGroup refuses a group Restore could not bring back (the first revision of this plan): such a group can be neither restored, left nor joined again | leaving a group that does not restore | Task 33 | `TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain` | 2 |
| MJ36b | ForgetGroup leaves ANY group that is on the disk and not in memory: a restart is a way round the owner's refusal | leaving a group that does not restore | Task 33 | `TestForgetGroupOverAGroupOnTheDiskAnswersByWhatRestoreSaid` | 1 |
| MJ53 | the held-group gate asks the store for EVERY record (this plan as it stood at its final check): one record that does not read refuses every invitation on the device | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 4 |
| MJ53b | a founding asks the store for every record: one record that does not read refuses a founding under any id | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ53c | ForgetGroup asks the store for every record: the damaged record of one group is the answer for another | one record that does not read | Task 33 | `TestForgetGroupLeavesAGroupWhoseRecordDoesNotReadAndThatGroupAlone` | 0 |
| MJ54 | the gate reads any answer but a record as "not held": a store that cannot answer, and a record that does not read, let the join write | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ54b | a founding that finds the disk unreadable founds anyway | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ55 | the list answers an error and no list over one record that does not read (the store as it was): Restore brings back nothing | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ55b | Restore returns on the list's report, before its loop (the device as it was): one damaged file costs every group on the device | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 0 |
| MJ55c | Restore goes on past a record that does not read and says nothing of it | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 0 |
| MJ56 | ForgetGroup refuses a group whose record does not read (this plan as it stood at its final check): it can be neither restored, left nor joined again | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 1 |
| MJ66 | a record that does not read is refused as "could not be read", which names no remedy (this plan as it stood at its final check): the person is not sent to ForgetGroup | one record that does not read | Task 33 | `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther` | 0 |
| MJ59 | a record is answered from a directory it does not name: the list holds a group the one-id read answers "not held" for | one record that does not read | Task 33 | `TestOneRecordThatDoesNotReadIsReportedByTheListAndAnsweredOnlyForItsOwnGroup` | 0 |
| MJ57 | Restore is outside the admission mutex: it files groups while a join is between its question and its hold | the admission mutex | Task 33 | `TestARestoreThatOverlapsAJoinWaitsForIt` | 0 |
| MJ58 | CreateGroup is outside the admission mutex: a founding asks whether its id is held while a join into that id is between its question and its hold | the admission mutex | Task 33 | `TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld` | 0 |
| MJ26 | the engine does not hand mls the group id: the intent match is off through both doors | the bound join | Task 34 | `TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing` | 5 |
| MJ26b | the sdk joins through the unbound door and compares the group id afterwards | the bound join | Task 35 | `TestProductionJoinsOnlyThroughTheBoundDoor` | 4 |
| MJ27 | the create-only probe removed: the commit writes over a state that is already there | the create-only commit | Task 36 | `TestAStagedJoinReachesTheStoreOnlyAtCommitAndNeverOverAStateAlreadyThere` | 2 |
| MJ27b | a store that fails to answer is read as "nothing there" | the create-only commit | Task 36 | `TestACommitOverAStoreThatCannotAnswerIsRefused` | 0 |
| MJ31 | the probe erases what the store answered, which is the store's own array | the create-only commit | Task 36 | `TestTheCreateOnlyProbeLeavesTheStoresOwnArrayAlone` | 0 |
| MJ28 | the one-phase join: the stage never stages, and the joined state is written as the engine joins | the two-phase join | Task 36 | `TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode` | 13 |
| MJ28b | a refused join does not put the join code back | the two-phase join | Task 36 | `TestAnAbortedJoinPutsTheJoinCodeBack` | 9 |
| MJ39 | a refusal inside the window answers its bare cause: nothing says the join code is not spent | what a refusal says | Task 36 | `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent` | 4 |
| MJ26c | the bound door takes an empty group id, which turns the intent match off and makes it the unbound door under another name | the bound join | Task 34 | `TestJoinFromWelcomeIntoRefusesAnEmptyGroupId` | 0 |
| MJ40 | the put-back's failure is discarded (the first revision of this plan, on the engine's refusal): a join code the store did not take back is reported as still good | what a refusal says | Task 36 | `TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent` | 1 |
| MJ41 | a join whose record could not be written does not say its join code is spent | what a refusal says | Task 36 | `TestAJoinWhoseRecordCannotBeWrittenSaysTheJoinCodeIsSpent` | 1 |
| MJ60 | an invitation whose join code is already gone is answered with the window's sentence: it says the join code is not spent, and it is gone | what a refusal says | Task 36 | `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent` | 1 |
| MJ61 | a record of an earlier epoch that does not authenticate is handed back as a gap: the symptom of MG-8 goes away, and with it the tampering signal for every past epoch | the open item MG-8 | Task 37 | `TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen` | 1 |
| MJV2 | THE VERSION 2 READER RESTORED: a plaintext invitation parses and its two secrets are honoured | the version table | Task 46 | `TestAdvSimAnAttackerChosenSecretIsNotInstalled` | 2 |
| MJ1 | pq_secret left in the clear beside the seal, as a sixth field | the seal | Task 46 | `TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch` | 12 |
| MJ2 | group_handle_key left in the clear beside the seal | the seal | Task 46 | `TestAdvSimAPasteObserverRecoversTheGroupHandleKey` | 8 |
| MJ3 | sealed to a key that is not the joiner's | the seal | Task 46 | `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth` | 119 |
| MJ10 | a seal with a non-zero content epoch is accepted at the paste | the formats | Task 46 | `TestAnInviteWhoseSealIsNotTheShapeVersionThreeFixesIsRefused` | 1 |
| MJ14 | the payload's length is not held to exactly 96 | the formats | Task 43 | `TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens` | 0 |
| MJ14b | an all-zero secret is accepted | the formats | Task 43 | `TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens` | 1 |
| MJ15 | the join seal reuses the device wrap's code points (target 0x01, payload 0x01) | the formats | Task 48 | `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads` | 9 |
| MJ4 | the joiner does not verify join_auth | authentication | Task 46 | `TestABentSealIsRefusedAndTheHonestInviteStillJoins` | 7 |
| MJ5 | join_key from a public value: the hash of the welcome, on both sides | authentication | Task 48 | `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads` | 3 |
| MJ5b | join_key from another public value: the hash of the ratchet tree, on both sides | authentication | Task 48 | `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads` | 2 |
| MJ5c | the join key's exporter context without the leaf, on both sides | authentication | Task 48 | `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads` | 2 |
| MJ5d | the join key is the storage exporter itself, which is what storage_root is extracted from | authentication | Task 48 | `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads` | 2 |
| MJ5e | the welcome and the tree transposed in the preimage, at both call sites | authentication | Task 48 | `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads` | 2 |
| MJ6 | the preimage does not cover the seal | binding | Task 43 | `TestTheJoinAuthPreimageIsThese181Octets` | 5 |
| MJ7 | the preimage does not carry the epoch | binding | Task 43 | `TestTheJoinAuthPreimageIsThese181Octets` | 1 |
| MJ8 | join_key at the epoch that is closing, not the one the commit opens | the key schedule | Task 46 | `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth` | 119 |
| MJ21 | a live add seals the secret of the epoch that is closing | the key schedule | Task 46 | `TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch` | 34 |
| MJ22 | MJ21, and the sealed digest recomputed from the value that was sealed | the key schedule | Task 46 | `TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch` | 26 |
| MJ43 | the joiner does not compare the digest it recomputes with the one sealed beside the secret | the key schedule | Task 48 | `TestAMemberMadeSealIsHeldToItsEpochItsShapeAndItsAddressee` | 0 |
| MJ32 | the seal is made after the epoch's wraps were submitted | the key schedule | Task 44 | `TestTheJoinSealIsMadeBeforeAnythingOfTheEpochIsSubmitted` | 1 |
| MJ32b | the epoch's wraps submitted ahead of the hook from inside a helper, where the source gate does not look | the key schedule | Task 44 | `TestAHookThatRefusesLeavesNothingStagedAndNothingSent` | 0 |
| MJ32c | a hook that refuses leaves the commit it was called for staged | the key schedule | Task 44 | `TestAHookThatRefusesLeavesNothingStagedAndNothingSent` | 0 |
| MJ33 | Open publishes without holding the digest the invitation was sealed over | the key schedule | Task 46 | `TestOpenRefusesToPublishKeysItsInviteWasNotSealedOver` | 0 |
| MJ11 | the adder does not ask for the capability | the adder | Task 45 | `TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged` | 0 |
| MJ11b | the adder does not validate the join code before it stages | the adder | Task 45 | `TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged` | 1 |
| MJ11c | an identity whose leaf stands is answered the role model's own refusal, with no remedy named | the adder | Task 45 | `TestTheLiveAdderJudgesAJoinCodeAndNamesTheRemedyForALeafThatStands` | 0 |
| MJ62 | the joiner's leaf found by its signature key alone, and not by the whole leaf | the adder | Task 45 | `TestTheJoinersLeafIsTheWholeLeafTheJoinCodePublished` | 0 |
| MJ34 | a failed seal leaves its commit staged on the founding road | the adder | Task 46 | `TestAFailedSealLeavesTheFounderWhereItWasAndTheAddCanBeMadeAgain` | 0 |
| MJ18 | a device with no X-Wing seed publishes a join code it can never open an invitation for | the adder | Task 42 | `TestADeviceWithNoWrapSeedPublishesNoJoinCode` | 0 |
| MJ13 | the joined state is committed to the store before the seal is verified, opened and checked | the joiner | Task 46 | `TestABentSealIsRefusedAndTheHonestInviteStillJoins` | 8 |
| MJ19 | the sealed payload is not erased | erasure | Task 46 | `TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes` | 0 |
| MJ19b | the handle key the seal opened to is not erased on a refusal made before the join commits | erasure | Task 46 | `TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes` | 0 |
| MJ50 | a group this build founds does not require the join seal of its members | the capability | Task 42 | `TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt` | 140 |
| MJ51 | a group that does not require the join seal is joined | the capability | Task 47 | `TestOnlyAGroupThatRequiresTheJoinSealIsJoined` | 0 |
| MJ52 | a group founded before the join seal is restored like any other | the capability | Task 47 | `TestAGroupFoundedBeforeTheJoinSealIsNotRestoredAndCanBeLeft` | 0 |
| MJ63 | the profile row for 0xF004 removed: the join seal's code point is no longer refused as a group-context extension | the capability | Task 42 | `TestTheV1ProfileClassifiesEveryRegisteredExtensionTypeAsAGroupContextExtension` | 0 |
| MJ64 | no leaf this build makes lists the capability its own groups require | the capability | Task 42 | `TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt` | 314 |
| MJ9 | the adder seals and authenticates for a leaf that is not the joiner's (the design's MJ9) | binding | Task 46 | `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth` | 119 |
| MJ65 | the codec's invite version moves and the authenticator's does not | the version table | Task 46 | `TestTheInviteVersionIsTheOneJoinAuthIsOver` | 2 |

**The harness's instruments again, on the T1 tree**, where the recorder scenarios observe
nothing and a blind instrument would look like a closed gap: 7 of the 8 are killed there too (`HV1` by `TestAdvSimVerdictRules`; `HV2` by `TestAdvSimVerdictRules`; `HV3` by `TestAdvSimVerdictRules`; `HV4` by `TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario`; `HV5` by `TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf`; `HV7` by `TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets`; `HV8` by `TestAdvSimAPasteObserverRecoversTheGroupHandleKey`).
A blind scrape is caught on that tree by controls and by nothing else: the true values planted
in the same query, which the second-device scenario and the paste-observer scenario each carry,
and the injected-secrets control. Each of the eight diffs Appendix B prints for them applies to
the T1 tree as well as to the S0 tree. `HV4`'s did not when the plan was checked: its entry went
in at the head of the registry, so its context was lines T1 flips. It goes in between two
controls no commit touches now, and is printed with one line of context.

**ONE SURVIVES ON THE T1 TREE, AND IT IS SAID RATHER THAN HIDDEN: `HV6`.** With the secrets
sealed, a recorder that is granted a classical join it did not earn still reads nothing, so
`P1-c1-invite-alone`, the control that pins the grant's rule, holds there for a second reason and
no longer pins the rule by itself. The rule is pinned on the S0 tree. A direct case for the grant
(handed an invitation alone, it must answer "not granted") would pin it on every tree; it is one
test, and it is owed to the testing track's own harness plan together with the rest of "Not in
S0".

What the measurements say that the design's table does not:

- **A public or misderived join key is caught only by a second derivation of the key.** With the
  sealed digest in place, a forged seal is refused by the digest check even when the MAC key is
  public, so no scenario sees it, and no test that only asks the adder and the joiner to agree
  with each other. `MJ5` and its four siblings are killed by `sdk/cp3b`'s recomputation with the
  standard library's HMAC, and by the member-side helpers of `sdk/urmessage`, which export the key
  themselves.
- **The digest check is caught only from the member's side.** `MJ43` is killed by an invitation
  whose authenticator is valid, which only a member can make.
- **The source gate over the publish is one line of two.** `MJ32` moves the hook and is caught by
  the gate; `MJ32b` submits the wraps ahead of it from inside a helper, which the gate cannot see,
  and is caught by the injected refusal.
- **`MJ7` (the preimage without the epoch) is killed by the known answer and by the second
  spelling, and by no scenario**, as the design expects: the key and the digest bind the epoch as
  well, so nothing an adversary can do shows it.
- **A damaged file, and a store that will not answer, were in no test.** The final check wrote two
  mutants, a gate and a founding that read "the store could not say" as "not held", and both
  passed every suite of the plan as it stood: nothing in it had a record that does not read. They
  are `MJ54` and `MJ54b`, and each is now killed twice over: by the control scenario, through a
  record cut to half its length, and by a unit case over a store that will not answer for one
  group id. `MJ53`, `MJ53b` and `MJ53c` put the plan's own earlier design back, one caller at a
  time: asked for every record, one that does not read is every group's answer. `MJ66` puts back
  the refusal that named no remedy: a record that does not read answers "could not be read", and
  nothing sends the person to `ForgetGroup`. THE CONTROL SCENARIO IS ITS ONLY KILL: both unit
  suites pass with it applied, on both trees, so the class of that one refusal is held by the
  scenario and by nothing else.
- **A lock is pinned by a forced order or by nothing.** The final check took the admission mutex
  away from `Restore` and from `CreateGroup`, and every suite passed. `MJ57` and `MJ58` are those
  two removals. Each is killed by a case that stops a join inside the gate, starts the other
  admission and reads whether it reached the disk; no timing decides who got where. Nine cases were then run 40 times in a row each on the T1 tree, because a forced order that only usually holds is worse than none: the seven this revision added, and the two it leans on (the overlapping joins of the first form, and the case that holds the sentences of the join window, which gained a row). 240 and 120 PASS lines, and no FAIL (`go test -count=40`; `lab-s0t1plan/out2/stress-new-cp3b.txt`, `stress-new-sdk.txt`).
- **Three mutants the first form of this plan only stated are run.** `MJ63` (the profile row for
  `0xF004` removed) and `MJ64` (no leaf lists the capability) replace a "mutation" of the
  capability task that was a build failure and not a rejected design; `MJ65` (the codec's version
  moves and the authenticator's does not) was "stated, not run". The final check ran all three
  first, and they are run again here.
- **Two names changed, and one mutant is new under an old name.** This plan's `MJ9` used to be
  the whole-leaf search of the join-code task, which is not what the join seal design calls MJ9
  ("wrong leaf", killed by the join). The whole-leaf search is `MJ62` now, and `MJ9` here IS the
  design's: the adder seals and authenticates for a leaf that is not the joiner's.
- **Not expressible in the reset variant, so not mutants here:** the design's MJ12 (the capability
  check after the commit: `mls` refuses there anyway, so it is `MJ11`), MJ16, MJ17, MJ23, MJ24 and
  MJ29 (the legacy arm and its sidecar), MJ20 (version 3 has no plaintext field to leave) and MJ30
  (the engine option, which is gone).
- **One erase is pinned by nothing, and it is said rather than hidden.** `join_key` is erased by a
  deferred call in both halves, and no gate would notice that call removed: the two key-material
  censuses follow values by the names in their nets, and the exporter's results are in neither.
  Adding them is a change to a census's own net and belongs with the healing track's work on keys
  at rest. The payload's erase and the handle key's are pinned (`MJ19`, `MJ19b`).

---

# Gates the change keeps green, and which task touches which

| Gate | Where | Touched by | What changes |
|---|---|---|---|
| Layering (who may import whom) | `internal/layering` | none | the harness and the new cp3b tests use only what `sdk/cp3b`'s row allows; measured `ok` on every commit |
| Engine interface is exactly its block | `messagegroup`, `TestTheEngineInterfacesAreExactlySectionSixsBlock` | Task 34 | 6 methods on `GroupEngine`, 35 on `GroupHandle`, 41 in all |
| The join config's fields | `messagegroup`, `TestTheJoinConfigCarriesExactlyTheFieldsTheJoinReads` | Task 34 | reversed: `GroupId` must be set, from the parameter |
| No sentence says a join is impossible | `messagegroup`, `TestNoProductionSentenceOfThisPackageSaysAJoinIsImpossible` | Task 34 | a second seam method and one disposition |
| The open items file | `messagegroup/OPENITEMS.md`, held both ways by `TestTheOpenItemThisPackageCitesIsFiledWhereItSaysItIs` | Task 34, Task 37, Task 53 | MG-1 says the second door authenticates nobody; MG-8 is a new row, cited from `messagegroup/errors.go` in the same commit (8 rows, 8 cited); MG-7 says what the join seal takes and settles |
| No engine method names an `mls` type; package imports | `messagegroup` | none | hold as they are |
| Registry code points; the profile | `mls` | Task 42 | one row each |
| Seed corpus is the generated corpus | `mls`, two tests | Task 42 | the corpus regenerated |
| Vector manifest | `mls`, `TestVectorManifestIsComplete` | Task 30 | 16 leaves the pending list |
| The pin file | `mls`, `TestThePinFileNamesNothingThatDoesNotExist` | Task 28 | new |
| Pinned toolchain | `mls`, `TestPinnedToolchain` | none | R6 moved the pin in a reviewed change of its own, which landed as `0bb2128f`, before S0. No task here changes `go.mod`, a pin line or `mls/pins_test.go` |
| The import's provenance proof | `docs/history`, and the fork's provenance leg | none | R11: the proof is held at ONE recorded tip, the head of the pins switch. No task here adds a row to `docs/history/adaptations.tsv` or changes a file under `docs/history` |
| One door for the group's epoch | `sdk/urmessage`, `TestEveryAssignmentToGroupEpochIsInsideTheOneDoor` | Task 36 | the stage's field is `stagedEpoch` |
| Production joins through the bound door | `sdk/urmessage`, `TestProductionJoinsOnlyThroughTheBoundDoor` | Task 35 | new |
| A closed store refuses | `sdk/urmessage`, `TestAClosedDurableStoreRefusesRatherThanAnsweringAnEmptyValue` | none | its table is hand-kept and does not list the store's new one-id read; the new store case of Task 33 holds that read on a closed store |
| Key-material censuses (erasure and sinks) | `sdk/urmessage`: pq_secret, epoch key, wrap seed | Task 33, Task 42, Task 43, Task 44, Task 46 | every new site has an entry with a reason |
| Constant time | `sdk/urmessage/joinseal.go` | Task 43, Task 45, Task 46 | every comparison of key-derived octets goes through `crypto/subtle`; the MAC through the provider's `MacVerify` |
| Crypto imports per file | `sdk`, `TestThisModulesProductionCryptoImportsAreTheDeclaredOnes` | Task 43, Task 45 | one row for `urmessage/joinseal.go` |
| Citation gates; fsync source gate | `sdk/urmessage` | none | measured `ok` |
| Wire golden, and the append-only schema rule | `protocol/` | none | no `.proto` file and no wire octet changes; the invitation is not a wire message |
| Module census | `scripts/module-census.sh`, in `test.sh` | none | no `go.mod` changes |
| Native exports | `scripts/native-exports.sh`, `sdk/cgo` | none | no exported symbol or signature changes; one comment of `exports_message.go` changes. NOT RUN in the lab |
| The plan linter and the edit-log gate | `message-server` | Task 1, Task 32, Task 41 | this plan is read by the first; each spec commit owes the second its log row |

---

# Measured results

One row per commit of the lab's chain, from its last verification run
(`lab-s0t1plan/out2/verify/summary.txt`; `v2/verify_all.sh` is the runner). Each commit was checked
out into a fresh worktree; `gofmt`, build and vet of every module, and the layering gate were clean
on every row. The numbers count the `--- PASS` lines of a `-v` run, and no suite on any row has a
`--- FAIL` line outside strict mode. "Strict" is the number of harness scenarios that FAIL with
`ADVSIM_STRICT=1`, which is the number of gaps still open. No run used the race detector.

**Every number here was measured under go1.26.5, on the lab's base.** After the pin moves (R6),
the branch's own run replaces it, and a count that differs is a finding. THE WHOLE TABLE WAS
MEASURED AGAIN FOR THIS REVISION, the four S0 rows included although their commits did not change;
"Review dispositions" sets the three phase ends beside what they were when the plan was checked.

| Commit | messagegroup | sdk | sdk/cp3b | strict | root module with mls |
|---|---|---|---|---|---|
| the base, 4d365abf | 359 | 308 | 81 | - | 2520 |
| S0: the harness | 359 | 308 | 106 | 17 | - |
| S0: the pin file | 359 | 308 | 106 | 17 | - |
| S0: the scan | 359 | 308 | 106 | 17 | - |
| S0: family 16 | 359 | 308 | 106 | 17 | 2522 |
| T1a: the gate | 359 | 313 | 113 | 12 | - |
| T1a: the bound door | 361 | 313 | 113 | 12 | - |
| T1a: the sdk through it | 361 | 314 | 113 | 10 | - |
| T1a: the two-phase join | 361 | 321 | 113 | 9 | - |
| T1a: the open item | 361 | 321 | 114 | 9 | 2524 |
| T1: the capability | 362 | 322 | 114 | 9 | 2525 |
| T1: the formats | 362 | 324 | 114 | 9 | - |
| T1: the hook | 362 | 326 | 114 | 9 | - |
| T1: the join-code check | 362 | 328 | 115 | 9 | - |
| T1: the flip | 362 | 335 | 117 | 3 | - |
| T1: the requirement | 362 | 337 | 117 | 3 | - |
| T1: the member's side | 362 | 339 | 119 | 3 | - |
| T1: probe step 1 | 362 | 339 | 119 | 3 | - |
| T1: probe step 2 | 362 | 339 | 119 | 3 | - |
| T1: probe step 3 | 362 | 339 | 119 | 3 | - |
| T1: probe step 4 | 362 | 339 | 119 | 3 | 2525 |
| T1: the open items note | 362 | 339 | 119 | 3 | - |

---

# Where the design and the moved code disagree

1. **Paths.** Every `C:` and `S:` path in the designs is a path of this repository now (`mls/`,
   `messagegroup/`, `message/`, `syntax/`, `protocol/`, `sdk/urmessage/`, `sdk/cp3b/`, `sdk/cgo/`).
2. **"The held-group gate is sdk-only" (the design's Q9) is not enough.** Measured: with only the
   sdk gate, `S7c` still replaces the held group's epoch state. The engine must bind the join to
   the invitation's group id: a sixth `GroupEngine` method and three amended gates (Task 34).
3. **The gate needs its own critical section.** The design does not say where it stands relative
   to a lock. Asked above the join's lock, two overlapping joins both read "not held"
   (Task 33, mutant `MJ35`).
4. **"To repair a dark or halted group, ForgetGroup it first" named a remedy that did not exist**
   for a group that does not restore: `ForgetGroup` refused a group that is not in memory.
   Task 33 makes it true.
5. **Where the staging store lives.** Design: `messagegroup`. Plan: `sdk/urmessage`, for the gate
   cost measured on the first revision.
6. **The create-only probe.** The design treats any store error as "absent" (its own red-team
   prompt 2). The plan lets only `ErrStateNotFound` mean absent.
7. **The re-add epoch rule needs no "list held epochs" store method.** With create-only it is
   `epoch > RemovedEpoch`.
8. **The removed-group exception is wider than a denial of service** (the design's prompt 3,
   measured): a second founder's invitation above the removal replaces the removed group. It is
   pinned open as `S7g`, and no sentence of this plan says an invitation can never replace a group.
9. **`EngineOptions{JoinSeal}` and the mis-pair tests have no subject.** `sdk/go.mod` replaces
   `github.com/urnetwork/message` with `../`. The capability is unconditional.
10. **The adder's validation clock.** Unstated in the design; it must be the wall clock.
11. **`ParseInvite`'s order and names.** The design's J0 lists the checksum, then the version;
    the code checks the version first and the plan keeps that. The design answers a field of the
    wrong shape with `ErrInviteDamaged`; the code keeps that name for a checksum that does not
    hold, refuses a blob whose checksum holds and whose framing is wrong by its framing (an
    existing test holds the distinction), and answers a seal of the wrong shape with
    `ErrJoinSealShape`.
12. **"Every test keeps a version 2 arm that must breach."** Impossible once nothing writes or
    reads version 2. Its job is done by three controls: `P1-c3-injected-secrets`, and the two
    residual scenarios in which the recorder also holds the joiner's seed.
13. **The design's mutant table** lists scenarios as the kill for a public MAC key (MJ5). With the
    sealed digest in place no scenario sees it. See "Mutation proofs".
14. **The reset was an assumption.** Task 47 makes a build that operates only groups requiring
    the join seal, and Task 55 lists what a reset is.
15. **A drift check on the live road is unnecessary.** One digest value serves the hook and the
    record. The founding road keeps its check, because `AddMember` and `Open` are two calls.
16. **No CI service upstream.** The testing design's workflows, Dependabot file, fuzz workflows and
    nightly jobs have nowhere to live in `urnetwork/message`; `test.sh` says the maintainers do
    not use GitHub Actions. The owner's fork runs `fork-ci.yml` on request, and R8 makes its four
    legs a condition of each phase close; that workflow is fork-only.
17. **The testing design's document fixes, and the join seal design's spec edits, are in another
    repository.** MASTER and the three specs are in `message-server`. This plan gives that
    repository's writer three tasks and lists the rest.
18. **`sdk/cp3b` may not import `syntax` or `x/crypto`.** The harness reads by grammar, and its
    second spelling of `join_auth` uses the standard library's HMAC, which is what the testing
    design wants of an oracle anyway.
19. **"Which line ships it" is moot.** One repository, a fork branch, a pull request per phase.
20. **The pq_secret census follows a definition and not an assignment.** Measured at the flip:
    the two secrets assigned to variables declared earlier took the whole of `Join` out of its
    sight. They are defined where the seal opens.
21. **`sdk/cp3b`'s seam member** built its session from the invitation's plaintext fields; it
    opens the seal itself now, from the public packages, which is a second spelling of the format.
22. **Sizes.** At the base a join code is 1,531 octets and an invitation 3,440, with the two
    secrets at octets 3340 and 3376, as the design's lab found. A founding invitation at version 3
    is 4,667 octets (the every-octet case reads 4,635 of them, all but the checksum).
23. **The C header** says "the invite, which is secret in full". That stays a safe instruction,
    so the header is left alone and `message-windows` needs no re-vendor. No exported symbol
    changes.
24. **`message-server` imports only `message`, `protocol` and `syntax`**, so no code of it changes.
    Its documents do.
25. **Vector runners.** The testing design gives families 16, 2, 9 and 8 "no production change"
    in one breath. Only 16 is a shim (measured); the other three are real runners and are the
    testing track's own plan.
26. **The second device.** One of the design's four harvest worlds is an identity's second device.
    The sdk mints one identity per state store, so that world has no sdk joiner and no device
    store for the quantum grant; it is measured as far as it can be (Task 8).
27. **The gate has to ask the disk about ONE group.** The design says the device asks whether it
    holds the group, and not how. Asked for every record the store holds, one record that did not
    read was the answer for every group, and the device could join, found and leave nothing
    (the final check of this plan, measured; R12). The store answers one group now, its list
    tolerates a record that does not read, and `Restore` goes on past one (Task 33).
28. **"A refused invitation costs nothing" has one case it is not true of**, and the design does
    not name it: an invitation whose join code is already gone. Refused inside the window, it
    carried the sentence that says the join code is not spent. It has its own sentence (Task 36,
    R13).
29. **A store names a group's directory by a hash of its id.** R12 asks for a damaged record to be
    reported "with its group id where the store's own naming gives one". This store's naming
    gives none, so the report names the directory, and every caller that has to act on such a
    group reaches it by an id it already holds.

---

# Appendix A: what the reset variant drops (a record)

Not planned. The reset is confirmed and is the only variant. Sizes are an estimate from the
code this plan touched (S: a day or less, M: days, L: a week or more).

| # | Dropped part | Cost to bring back |
|---|---|---|
| A1 | The version 2 reader | S for the parser; it re-opens `S3-chosen-secret` on its own (mutant `MJV2`, measured), so it is only safe with A3 |
| A2 | The downgrade refusal (`ErrInviteDowngraded`) | S. Its other half is KEPT in a stronger form: `requireJoinSeal` refuses any group that does not require the capability, whatever the invitation's version |
| A3 | Legacy verification (the joiner proves a plaintext secret before it sends or commits) | L: it reaches the send path, the commit path, the restore and the first walk |
| A4 | The `joinstate` sidecar | M: a new durable file and its ordering against the record |
| A5 | T1b, `Group.Rekey`, and its persisted intent | M to L: a new commit path and its scenarios |
| A6 | The upgrade sweep and its designated device | M, and an operational step per group |
| A7 | `EngineOptions{JoinSeal}` and the mis-pair tests | S; no subject while both halves are one repository. The seedless `KeyPackage()` refusal that travelled with it is KEPT |
| A8 | The mixed-version table and its live checks | L: the harness needs an old build as a second module version |
| A9 | The rollback runbook | M. One rule of it is KEPT (Task 55, step 4). A technical stop, an old build unable to open a T1 directory, is a record format change: M, and it breaks every existing directory once |
| A10 | Two shipping lines | none: moot in one repository |
| A11 | The counters `JoinSealOpened`, `JoinLegacy`, `JoinLegacyVerified` | S in Go; a C header addition and a re-vendor in the app |
| A12 | The version 2 arm of every scenario | S with A1; otherwise a test-only version 2 writer |

---

# Appendix C: tests the join seal design lists that this plan does not add

| The design's test | Why it is not here |
|---|---|
| The seal's known answer through `sealWrapBodyWith` | That function is `messagegroup`'s and already has a known answer there, with the info string, the key and the nonce each derived a second time by hand. The join seal differs from it in three envelope octets and the target id, all of which enter through `WrapInfo`. Its own constants are held by the shape case, its exact length by the codec, and its authenticator by the second spelling. A join-seal vector file is worth adding when a second implementation exists to read it |
| A legacy version 2 fixture still parses; `Invite` has no exported secret field | A1: nothing reads version 2. The second half holds by construction: the type has five fields |
| The sidecar's three tests; the counters; `KeyPackage()`'s self-check against a mis-paired tree | A4, A11, A7 |
| The design's scenarios S5 (mixed versions) and S6 (the rekey) | A8, A5 |
| A genuine old-build join code replayed to a T1 adder | No old build exists to mint one in this repository's tests. What it would show is held by `MJ11`: a join code without the capability is refused before anything is staged |

---

# Appendix B: every mutant, as a diff

So that no proof depends on the lab surviving. Each diff is against the tree named above it
and applies with `git apply`. Run each alone:

```bash
git apply mutant.diff
go test -count=1 ./messagegroup/ ; go -C sdk test -count=1 ./urmessage/ ; go -C sdk/cp3b test -count=1 ./...
git checkout -- . && git clean -fdq
```

For a mutant of the harness (`HV1` to `HV8`) the third command alone is enough, with
`-run TestAdvSim`; their diffs apply to the T1 tree as well as to the S0 tree. For `MJ63` run
`go test -count=1 ./mls/` as well: its kill is there. A mutant whose diff does not apply is a
mutant whose subject has moved: say so, and do not count it as killed.

**HV1** (the verdict rules; against the S0 tree and the T1 tree). An open entry whose adversary observes the goal passes: a gap that closed stays recorded as open. Killed by `TestAdvSimVerdictRules`.

```diff
--- a/sdk/cp3b/advsim_registry_test.go
+++ b/sdk/cp3b/advsim_registry_test.go
@@ -102,5 +102,5 @@
 			return true, fmt.Sprintf("KNOWN GAP (closed by %s)", entry.ClosedBy)
 		case slices.Equal(observed, goal):
-			return false, fmt.Sprintf("FAIL: the gap has CLOSED: observed %v is the goal. Set this entry's state to \"closed\" and its expect to %v in the commit that closed it", observed, goal)
+			return true, fmt.Sprintf("FAIL: the gap has CLOSED: observed %v is the goal. Set this entry's state to \"closed\" and its expect to %v in the commit that closed it", observed, goal)
 		default:
 			return false, fmt.Sprintf("FAIL: the gap MOVED: observed %v, the registry models %v and the goal is %v. This is a regression, or a registry edit that needs a ledger entry", observed, expect, goal)
```

**HV2** (the verdict rules; against the S0 tree and the T1 tree). A closed entry passes whatever its adversary observes. Killed by `TestAdvSimVerdictRules`.

```diff
--- a/sdk/cp3b/advsim_registry_test.go
+++ b/sdk/cp3b/advsim_registry_test.go
@@ -91,5 +91,5 @@
 	switch entry.State {
 	case "closed", "control", "residual":
-		if slices.Equal(observed, expect) {
+		if slices.Equal(observed, expect) || entry.State == "closed" {
 			return true, strings.ToUpper(entry.State)
 		}
```

**HV3** (the verdict rules; against the S0 tree and the T1 tree). Strict mode passes an open gap: the RED report is green. Killed by `TestAdvSimVerdictRules`.

```diff
--- a/sdk/cp3b/advsim_registry_test.go
+++ b/sdk/cp3b/advsim_registry_test.go
@@ -98,5 +98,5 @@
 		switch {
 		case slices.Equal(observed, expect) && strict:
-			return false, fmt.Sprintf("RED: the gap is open, closed by %s: the adversary observed %v, and the goal is %v", entry.ClosedBy, observed, goal)
+			return true, fmt.Sprintf("RED: the gap is open, closed by %s: the adversary observed %v, and the goal is %v", entry.ClosedBy, observed, goal)
 		case slices.Equal(observed, expect):
 			return true, fmt.Sprintf("KNOWN GAP (closed by %s)", entry.ClosedBy)
```

**HV4** (the registry; against the S0 tree and the T1 tree). The registry carries an entry no scenario judges. Killed by `TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario`.

```diff
--- a/sdk/cp3b/testdata/advsim/known-gaps.json
+++ b/sdk/cp3b/testdata/advsim/known-gaps.json
@@ -8,2 +8,3 @@
     {"id": "P1-c1-invite-alone", "state": "control", "expect": [], "goal": [], "closed_by": "none", "reads": "the recorder holds the invitation and not the join code, so the CRQC has no init key to invert and reads nothing"},
+    {"id": "ZZ-judged-by-nobody", "state": "closed", "expect": [], "goal": [], "closed_by": "none", "reads": "an entry no scenario names"},
     {"id": "P1-c2-replaced-pq", "state": "control", "expect": [], "goal": [], "closed_by": "none", "reads": "both codes, with random octets where the pq_secret would be: the read goes through that one value and nothing else"},
```

**HV5** (the quantum grant; against the S0 tree and the T1 tree). The grant reads the init key one octet off: the octets it looks for are not the key the Welcome is sealed to. Killed by `TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf`.

```diff
--- a/sdk/cp3b/advsim_oracle_test.go
+++ b/sdk/cp3b/advsim_oracle_test.go
@@ -108,5 +108,5 @@
 		advHarness(t, "these %d octets do not begin as an mls10 key package at suite 0x0003 with a 32 octet init key", len(keyPackage))
 	}
-	return append([]byte(nil), keyPackage[5:37]...)
+	return append([]byte(nil), keyPackage[6:38]...)
 }
 
```

**HV6** (the quantum grant; against the S0 tree and the T1 tree). The grant ignores its rule: the joiner's classical keys are granted whether or not the init key was captured. Killed by `TestAdvSimTheInvitationAloneReadsNothing`.

```diff
--- a/sdk/cp3b/advsim_oracle_test.go
+++ b/sdk/cp3b/advsim_oracle_test.go
@@ -141,5 +141,5 @@
 	t.Helper()
 	initKey := advKeyPackageInitKey(t, joinCode)
-	if !bytes.Contains(bytes.Join(captured, nil), initKey) {
+	if false && !bytes.Contains(bytes.Join(captured, nil), initKey) {
 		return nil, false
 	}
```

**HV7** (the scrape; against the S0 tree and the T1 tree). The scrape for pq_secret confirms nothing: it has gone blind. Killed by `TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets`.

```diff
--- a/sdk/cp3b/advsim_oracle_test.go
+++ b/sdk/cp3b/advsim_oracle_test.go
@@ -307,5 +307,5 @@
 			advHarness(t, "H(epoch_keys) over a candidate: %v", err)
 		}
-		if bytes.Equal(digest, published) {
+		if false && bytes.Equal(digest, published) {
 			return append([]byte(nil), window...), at
 		}
```

**HV8** (the scrape; against the S0 tree and the T1 tree). The scrape for the group handle key confirms nothing: it has gone blind. Killed by `TestAdvSimAPasteObserverRecoversTheGroupHandleKey`.

```diff
--- a/sdk/cp3b/advsim_oracle_test.go
+++ b/sdk/cp3b/advsim_oracle_test.go
@@ -285,5 +285,5 @@
 		window := haystack[at : at+32]
 		for leaf := uint32(0); leaf < 16; leaf += 1 {
-			if handles[messagegroup.SenderHandle(window, leaf)] {
+			if false && handles[messagegroup.SenderHandle(window, leaf)] {
 				return append([]byte(nil), window...), at
 			}
```

**MJ25** (the held-group gate; against the T1 tree and the T1a tree). The held-group gate removed: nothing asks whether the device holds the group. Killed by `TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1415,8 +1415,6 @@
 	}
 	// THE HELD-GROUP GATE, before the join code is touched: see [Device.joinOverHeldGroup].
-	replaces, readd, removedEpoch, err := self.joinOverHeldGroup(invite.GroupId)
-	if err != nil {
-		return nil, err
-	}
+	var replaces *Group
+	readd, removedEpoch := false, uint64(0)
 
 	// ── THE WINDOW ─────────────────────────────────────────────────────────────────────────────
```

**MJ25b** (the held-group gate; against the T1 tree and the T1a tree). The gate asks the device's memory and not its disk. Killed by `TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -55,5 +55,5 @@
 	}
 	store, durable := self.stateStore.(DeviceStore)
-	if !durable {
+	if !durable || true {
 		return replaces, readd, removedEpoch, nil
 	}
```

**MJ25c** (the held-group gate; against the T1 tree and the T1a tree). The removed-group exception removed: a re-add is refused like any held group. Killed by `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -65,5 +65,5 @@
 		return nil, false, 0, heldUnread(groupId, err, "the invite into it is refused")
 	}
-	if record.RemovedKind == removedNone {
+	if record.RemovedKind == removedNone || true {
 		return nil, false, 0, fmt.Errorf("%w: group %x has a record on this device's disk", ErrGroupAlreadyHeld, groupId)
 	}
```

**MJ35** (the admission mutex; against the T1 tree and the T1a tree). The gate is asked ABOVE the admission mutex (the first revision of this plan): two joins that overlap both read "not held". Killed by `TestTwoJoinsIntoOneGroupIdThatOverlapAdmitExactlyOne`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1405,18 +1405,18 @@
 	// gate's answer is only worth the time it stays true for, so everything from the question to
 	// the map entry is one critical section.
+	if err := self.finishLeaveBefore(invite.GroupId); err != nil {
+		return nil, err
+	}
+	nonce, nonceEpoch, err := self.nonce()
+	if err != nil {
+		return nil, err
+	}
+	// THE HELD-GROUP GATE, before the join code is touched: see [Device.joinOverHeldGroup].
+	replaces, readd, removedEpoch, err := self.joinOverHeldGroup(invite.GroupId)
+	if err != nil {
+		return nil, err
+	}
 	self.admitMutex.Lock()
 	defer self.admitMutex.Unlock()
-	if err := self.finishLeaveBefore(invite.GroupId); err != nil {
-		return nil, err
-	}
-	nonce, nonceEpoch, err := self.nonce()
-	if err != nil {
-		return nil, err
-	}
-	// THE HELD-GROUP GATE, before the join code is touched: see [Device.joinOverHeldGroup].
-	replaces, readd, removedEpoch, err := self.joinOverHeldGroup(invite.GroupId)
-	if err != nil {
-		return nil, err
-	}
 
 	// ── THE WINDOW ─────────────────────────────────────────────────────────────────────────────
```

**MJ38** (the admission mutex; against the T1 tree and the T1a tree). The map is written without looking: hold and holdReplacing replace whatever is there. Killed by `TestAMapEntryIsReplacedOnlyByTheJoinThatJudgedIt`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -117,5 +117,5 @@
 	self.mutex.Lock()
 	defer self.mutex.Unlock()
-	if held := self.groups[string(group.id)]; held != nil && held != group {
+	if held := self.groups[string(group.id)]; held != nil && held != group && false {
 		return fmt.Errorf("%w: group %x is live on this device", ErrGroupAlreadyHeld, group.id)
 	}
@@ -136,5 +136,5 @@
 func (self *Device) holdReplacing(group *Group, judged *Group) error {
 	self.mutex.Lock()
-	if held := self.groups[string(group.id)]; held != judged {
+	if held := self.groups[string(group.id)]; held != judged && false {
 		self.mutex.Unlock()
 		return fmt.Errorf("%w: the group this device holds under %x is not the one this join was judged against", ErrGroupAlreadyHeld, group.id)
```

**MJ42** (the admission mutex; against the T1 tree and the T1a tree). A founding asks nothing first: the second group under one id is refused only at the hold, after mls wrote its epoch zero. Killed by `TestNoGroupIsFoundedUnderAnIdThisDeviceHolds`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1308,7 +1308,4 @@
 	// NOTHING IS FOUNDED UNDER AN ID THIS DEVICE HOLDS: see [Device.foundOverHeldGroup]. It is asked
 	// before the MLS group is made, because making it writes an epoch-zero state under that id.
-	if err := self.foundOverHeldGroup(groupId); err != nil {
-		return nil, err
-	}
 	nonce, nonceEpoch, err := self.nonce()
 	if err != nil {
```

**MJ37** (the re-add rule; against the T1 tree and the T1a tree). The re-add rule removed: an invitation at or below the epoch of the removal is honoured. Killed by `TestAReaddBelowTheRemovalIsRefusedAndTheRealReaddStillJoins`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1471,5 +1471,5 @@
 			ErrInviteDamaged, handle.GroupId(), invite.GroupId)
 	}
-	if readd && handle.Epoch() <= removedEpoch {
+	if false && readd && handle.Epoch() <= removedEpoch {
 		return nil, fmt.Errorf("%w: the welcome stands at epoch %d and this device was removed at epoch %d",
 			ErrReaddStale, handle.Epoch(), removedEpoch)
```

**MJ36** (leaving a group that does not restore; against the T1 tree and the T1a tree). ForgetGroup refuses a group Restore could not bring back (the first revision of this plan): such a group can be neither restored, left nor joined again. Killed by `TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain`.

```diff
--- a/sdk/urmessage/forget.go
+++ b/sdk/urmessage/forget.go
@@ -100,5 +100,5 @@
 				return err
 			}
-			if onDisk && (!reads || self.didNotRestore(groupId)) {
+			if onDisk && !reads {
 				return self.forgetUnrestored(store, groupId)
 			}
```

**MJ36b** (leaving a group that does not restore; against the T1 tree and the T1a tree). ForgetGroup leaves ANY group that is on the disk and not in memory: a restart is a way round the owner's refusal. Killed by `TestForgetGroupOverAGroupOnTheDiskAnswersByWhatRestoreSaid`.

```diff
--- a/sdk/urmessage/forget.go
+++ b/sdk/urmessage/forget.go
@@ -100,5 +100,5 @@
 				return err
 			}
-			if onDisk && (!reads || self.didNotRestore(groupId)) {
+			if onDisk && (!reads || true) {
 				return self.forgetUnrestored(store, groupId)
 			}
```

**MJ53** (one record that does not read; against the T1 tree and the T1a tree). The held-group gate asks the store for EVERY record (this plan as it stood at its final check): one record that does not read refuses every invitation on the device. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -58,5 +58,5 @@
 		return replaces, readd, removedEpoch, nil
 	}
-	record, err := store.GroupRecord(groupId)
+	record, err := listedRecord(store, groupId)
 	if errors.Is(err, ErrStateNotFound) {
 		return replaces, readd, removedEpoch, nil
@@ -163,2 +163,17 @@
 	return self.unrestored[string(groupId)]
 }
+
+
+// MUTANT: the record of one group, found by asking the store for every record it holds.
+func listedRecord(store DeviceStore, groupId []byte) (*GroupRecord, error) {
+	records, err := store.GroupRecords()
+	if err != nil {
+		return nil, err
+	}
+	for _, record := range records {
+		if string(record.GroupId) == string(groupId) {
+			return record, nil
+		}
+	}
+	return nil, ErrStateNotFound
+}
```

**MJ53b** (one record that does not read; against the T1 tree and the T1a tree). A founding asks the store for every record: one record that does not read refuses a founding under any id. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -99,5 +99,5 @@
 		return nil
 	}
-	_, err := store.GroupRecord(groupId)
+	_, err := listedRecord(store, groupId)
 	if errors.Is(err, ErrStateNotFound) {
 		return nil
@@ -163,2 +163,17 @@
 	return self.unrestored[string(groupId)]
 }
+
+
+// MUTANT: the record of one group, found by asking the store for every record it holds.
+func listedRecord(store DeviceStore, groupId []byte) (*GroupRecord, error) {
+	records, err := store.GroupRecords()
+	if err != nil {
+		return nil, err
+	}
+	for _, record := range records {
+		if string(record.GroupId) == string(groupId) {
+			return record, nil
+		}
+	}
+	return nil, ErrStateNotFound
+}
```

**MJ53c** (one record that does not read; against the T1 tree and the T1a tree). ForgetGroup asks the store for every record: the damaged record of one group is the answer for another. Killed by `TestForgetGroupLeavesAGroupWhoseRecordDoesNotReadAndThatGroupAlone`.

```diff
--- a/sdk/urmessage/forget.go
+++ b/sdk/urmessage/forget.go
@@ -150,5 +150,5 @@
 // remedy every held-group refusal names, failed for the reason the refusal was given.
 func recordOnDisk(store DeviceStore, groupId []byte) (onDisk bool, reads bool, err error) {
-	_, err = store.GroupRecord(groupId)
+	_, err = listedRecord(store, groupId)
 	switch {
 	case err == nil:
@@ -280,2 +280,17 @@
 	return nil
 }
+
+
+// MUTANT: the record of one group, found by asking the store for every record it holds.
+func listedRecord(store DeviceStore, groupId []byte) (*GroupRecord, error) {
+	records, err := store.GroupRecords()
+	if err != nil {
+		return nil, err
+	}
+	for _, record := range records {
+		if string(record.GroupId) == string(groupId) {
+			return record, nil
+		}
+	}
+	return nil, ErrStateNotFound
+}
```

**MJ54** (one record that does not read; against the T1 tree and the T1a tree). The gate reads any answer but a record as "not held": a store that cannot answer, and a record that does not read, let the join write. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -59,5 +59,5 @@
 	}
 	record, err := store.GroupRecord(groupId)
-	if errors.Is(err, ErrStateNotFound) {
+	if err != nil {
 		return replaces, readd, removedEpoch, nil
 	}
```

**MJ54b** (one record that does not read; against the T1 tree and the T1a tree). A founding that finds the disk unreadable founds anyway. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -100,5 +100,5 @@
 	}
 	_, err := store.GroupRecord(groupId)
-	if errors.Is(err, ErrStateNotFound) {
+	if err != nil {
 		return nil
 	}
```

**MJ55** (one record that does not read; against the T1 tree and the T1a tree). The list answers an error and no list over one record that does not read (the store as it was): Restore brings back nothing. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/statestore_durable.go
+++ b/sdk/urmessage/statestore_durable.go
@@ -1873,9 +1873,5 @@
 				continue
 			}
-			damaged = append(damaged, name)
-			if firstDamage == nil {
-				firstDamage = err
-			}
-			continue
+			return nil, err
 		}
 		records = append(records, record)
```

**MJ55b** (one record that does not read; against the T1 tree and the T1a tree). Restore returns on the list's report, before its loop (the device as it was): one damaged file costs every group on the device. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/restore.go
+++ b/sdk/urmessage/restore.go
@@ -238,5 +238,5 @@
 	// (see [DurableStateStore.GroupRecords]); [Device.ForgetGroup] leaves it by its id.
 	records, err := store.GroupRecords()
-	if err != nil && !errors.Is(err, ErrGroupRecordDamaged) {
+	if err != nil && (true || !errors.Is(err, ErrGroupRecordDamaged)) {
 		return nil, err
 	}
```

**MJ55c** (one record that does not read; against the T1 tree and the T1a tree). Restore goes on past a record that does not read and says nothing of it. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/restore.go
+++ b/sdk/urmessage/restore.go
@@ -243,5 +243,5 @@
 	restored := []*Group{}
 	var firstFailure error
-	if err != nil {
+	if err != nil && false {
 		firstFailure = fmt.Errorf("%w: %w", ErrRestore, err)
 	}
```

**MJ56** (one record that does not read; against the T1 tree and the T1a tree). ForgetGroup refuses a group whose record does not read (this plan as it stood at its final check): it can be neither restored, left nor joined again. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/forget.go
+++ b/sdk/urmessage/forget.go
@@ -100,5 +100,5 @@
 				return err
 			}
-			if onDisk && (!reads || self.didNotRestore(groupId)) {
+			if onDisk && (!reads && false || self.didNotRestore(groupId)) {
 				return self.forgetUnrestored(store, groupId)
 			}
```

**MJ66** (one record that does not read; against the T1 tree and the T1a tree). A record that does not read is refused as "could not be read", which names no remedy (this plan as it stood at its final check): the person is not sent to ForgetGroup. Killed by `TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther`.

```diff
--- a/sdk/urmessage/heldgroup.go
+++ b/sdk/urmessage/heldgroup.go
@@ -80,5 +80,5 @@
 // not answer is refused as that, and names no remedy, because it has none to name.
 func heldUnread(groupId []byte, err error, refused string) error {
-	if errors.Is(err, ErrGroupRecordDamaged) {
+	if false && errors.Is(err, ErrGroupRecordDamaged) {
 		return fmt.Errorf("%w: group %x has a record on this device's disk that does not read: %w", ErrGroupAlreadyHeld, groupId, err)
 	}
```

**MJ59** (one record that does not read; against the T1 tree and the T1a tree). A record is answered from a directory it does not name: the list holds a group the one-id read answers "not held" for. Killed by `TestOneRecordThatDoesNotReadIsReportedByTheListAndAnsweredOnlyForItsOwnGroup`.

```diff
--- a/sdk/urmessage/statestore_durable.go
+++ b/sdk/urmessage/statestore_durable.go
@@ -1930,5 +1930,5 @@
 		return nil, fmt.Errorf("%w: %w", ErrGroupRecordDamaged, err)
 	}
-	if stateNameOf(record.GroupId) != name {
+	if false && stateNameOf(record.GroupId) != name {
 		return nil, fmt.Errorf("%w: %w: the record in %s does not name its own group",
 			ErrGroupRecordDamaged, ErrStateStoreFormat, name)
```

**MJ57** (the admission mutex; against the T1 tree and the T1a tree). Restore is outside the admission mutex: it files groups while a join is between its question and its hold. Killed by `TestARestoreThatOverlapsAJoinWaitsForIt`.

```diff
--- a/sdk/urmessage/restore.go
+++ b/sdk/urmessage/restore.go
@@ -210,6 +210,4 @@
 	// ONE ADMISSION AT A TIME: a Join or a CreateGroup of a group this call is about to restore
 	// waits for it and reads the answer it leaves. See [Device.admitMutex].
-	self.admitMutex.Lock()
-	defer self.admitMutex.Unlock()
 	// A LEAVE THAT DID NOT FINISH ERASING IS FINISHED FIRST, and before the nonce is asked for: it
 	// needs no connection, and a device that cannot connect should still not keep a group it left
```

**MJ58** (the admission mutex; against the T1 tree and the T1a tree). CreateGroup is outside the admission mutex: a founding asks whether its id is held while a join into that id is between its question and its hold. Killed by `TestAFoundingThatOverlapsAJoinWaitsForItAndFindsTheGroupHeld`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1301,6 +1301,4 @@
 	}
 	// ONE ADMISSION AT A TIME, from the question below to the hold: see [Device.admitMutex].
-	self.admitMutex.Lock()
-	defer self.admitMutex.Unlock()
 	if err := self.finishLeaveBefore(groupId); err != nil {
 		return nil, err
```

**MJ26** (the bound join; against the T1 tree and the T1a tree). The engine does not hand mls the group id: the intent match is off through both doors. Killed by `TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing`.

```diff
--- a/messagegroup/engine.go
+++ b/messagegroup/engine.go
@@ -944,5 +944,5 @@
 		Crypto:  self.crypto,
 		Store:   self.store,
-		GroupId: groupId,
+		GroupId: nil,
 	}, welcome, ratchetTree, keys)
 	if err != nil {
```

**MJ26b** (the bound join; against the T1 tree and the T1a tree). The sdk joins through the unbound door and compares the group id afterwards. Killed by `TestProductionJoinsOnlyThroughTheBoundDoor`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1463,5 +1463,5 @@
 	// BOUND TO THE GROUP THE INVITE NAMES. A Welcome that describes any other group is refused
 	// inside mls, ahead of its persist, and the engine puts the join code back itself.
-	handle, err = self.engine.JoinFromWelcomeInto(invite.Welcome, invite.RatchetTree, invite.GroupId)
+	handle, err = self.engine.JoinFromWelcome(invite.Welcome, invite.RatchetTree)
 	if err != nil {
 		return nil, fmt.Errorf("urmessage: JoinFromWelcomeInto: %w", err)
```

**MJ27** (the create-only commit; against the T1 tree and the T1a tree). The create-only probe removed: the commit writes over a state that is already there. Killed by `TestAStagedJoinReachesTheStoreOnlyAtCommitAndNeverOverAStateAlreadyThere`.

```diff
--- a/sdk/urmessage/joinstage.go
+++ b/sdk/urmessage/joinstage.go
@@ -88,5 +88,5 @@
 	_, err := self.store.GetGroupState(self.groupId, self.stagedEpoch)
 	if err == nil {
-		return fmt.Errorf("%w: group %x epoch %d", ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch)
+		err = ErrStateNotFound
 	}
 	if !errors.Is(err, ErrStateNotFound) {
```

**MJ27b** (the create-only commit; against the T1 tree and the T1a tree). A store that fails to answer is read as "nothing there". Killed by `TestACommitOverAStoreThatCannotAnswerIsRefused`.

```diff
--- a/sdk/urmessage/joinstage.go
+++ b/sdk/urmessage/joinstage.go
@@ -90,5 +90,5 @@
 		return fmt.Errorf("%w: group %x epoch %d", ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch)
 	}
-	if !errors.Is(err, ErrStateNotFound) {
+	if !errors.Is(err, ErrStateNotFound) && false {
 		return fmt.Errorf("%w: whether group %x epoch %d is already held could not be read: %w",
 			ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch, err)
```

**MJ31** (the create-only commit; against the T1 tree and the T1a tree). The probe erases what the store answered, which is the store's own array. Killed by `TestTheCreateOnlyProbeLeavesTheStoresOwnArrayAlone`.

```diff
--- a/sdk/urmessage/joinstage.go
+++ b/sdk/urmessage/joinstage.go
@@ -86,5 +86,6 @@
 		return fmt.Errorf("urmessage: no join is staged, or the engine wrote no epoch state for it")
 	}
-	_, err := self.store.GetGroupState(self.groupId, self.stagedEpoch)
+	probed, err := self.store.GetGroupState(self.groupId, self.stagedEpoch)
+	zeroizeState(probed)
 	if err == nil {
 		return fmt.Errorf("%w: group %x epoch %d", ErrJoinWouldOverwrite, self.groupId, self.stagedEpoch)
```

**MJ28** (the two-phase join; against the T1 tree and the T1a tree). The one-phase join: the stage never stages, and the joined state is written as the engine joins. Killed by `TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode`.

```diff
--- a/sdk/urmessage/joinstage.go
+++ b/sdk/urmessage/joinstage.go
@@ -65,5 +65,5 @@
 		return fmt.Errorf("urmessage: a join into group %x is still staged, and a device stages one join at a time", self.groupId)
 	}
-	self.joining = true
+	self.joining = false
 	self.groupId = append([]byte(nil), groupId...)
 	return nil
@@ -84,5 +84,5 @@
 	defer self.mutex.Unlock()
 	if !self.joining || !self.held {
-		return fmt.Errorf("urmessage: no join is staged, or the engine wrote no epoch state for it")
+		return nil
 	}
 	_, err := self.store.GetGroupState(self.groupId, self.stagedEpoch)
```

**MJ28b** (the two-phase join; against the T1 tree and the T1a tree). A refused join does not put the join code back. Killed by `TestAnAbortedJoinPutsTheJoinCodeBack`.

```diff
--- a/sdk/urmessage/joinstage.go
+++ b/sdk/urmessage/joinstage.go
@@ -111,5 +111,5 @@
 	}
 	var err error
-	if self.taken {
+	if self.taken && false {
 		err = self.store.PutKeyPackage(self.takenRef, self.takenPackage, self.takenInit, self.takenEncrypt)
 	}
```

**MJ39** (what a refusal says; against the T1 tree and the T1a tree). A refusal inside the window answers its bare cause: nothing says the join code is not spent. Killed by `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1459,5 +1459,5 @@
 			return
 		}
-		joined, err = nil, fmt.Errorf("%w: %w", ErrJoinRefused, err)
+		joined = nil
 	}()
 	// BOUND TO THE GROUP THE INVITE NAMES. A Welcome that describes any other group is refused
```

**MJ26c** (the bound join; against the T1 tree and the T1a tree). The bound door takes an empty group id, which turns the intent match off and makes it the unbound door under another name. Killed by `TestJoinFromWelcomeIntoRefusesAnEmptyGroupId`.

```diff
--- a/messagegroup/engine.go
+++ b/messagegroup/engine.go
@@ -836,7 +836,4 @@
 // JoinFromWelcomeInto is JoinFromWelcome with connect/mls's intent match on: see the interface.
 func (self *connectMlsEngine) JoinFromWelcomeInto(welcome []byte, ratchetTree []byte, groupId []byte) (GroupHandle, error) {
-	if len(groupId) == 0 {
-		return nil, ErrEngineJoinGroupId
-	}
 	return self.joinFromWelcome(welcome, ratchetTree, groupId)
 }
```

**MJ40** (what a refusal says; against the T1 tree and the T1a tree). The put-back's failure is discarded (the first revision of this plan, on the engine's refusal): a join code the store did not take back is reported as still good. Killed by `TestARefusalThatCannotPutTheJoinCodeBackSaysItIsSpent`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1448,8 +1448,5 @@
 			handle.Close()
 		}
-		if abortErr != nil {
-			joined, err = nil, fmt.Errorf("%w: %w, and the join code could not be put back: %w", ErrJoinCodeSpent, err, abortErr)
-			return
-		}
+		_ = abortErr
 		// THE ONE REFUSAL IN HERE THAT DOES NOT CARRY THE WINDOW'S SENTENCE: the engine found no
 		// join code of this device that the invite was made for. "The join code is not spent" is
```

**MJ41** (what a refusal says; against the T1 tree and the T1a tree). A join whose record could not be written does not say its join code is spent. Killed by `TestAJoinWhoseRecordCannotBeWrittenSaysTheJoinCodeIsSpent`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1563,5 +1563,5 @@
 		handle.Close()
 		return nil, fmt.Errorf(
-			"%w: this group joined and its record could not be persisted, so a restart would not come back into it: %w", ErrJoinCodeSpent, err)
+			"urmessage: this group joined and its record could not be persisted, so a restart would not come back into it: %w", err)
 	}
 	if err := self.holdReplacing(group, replaces); err != nil {
```

**MJ60** (what a refusal says; against the T1 tree and the T1a tree). An invitation whose join code is already gone is answered with the window's sentence: it says the join code is not spent, and it is gone. Killed by `TestEveryRefusalInsideTheJoinWindowSaysTheJoinCodeIsNotSpent`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1455,5 +1455,5 @@
 		// join code of this device that the invite was made for. "The join code is not spent" is
 		// not true of a join code that is not there. See [ErrNoJoinCodeForInvite].
-		if errors.Is(err, messagegroup.ErrEngineNoKeyPackageForWelcome) {
+		if false && errors.Is(err, messagegroup.ErrEngineNoKeyPackageForWelcome) {
 			joined, err = nil, fmt.Errorf("%w: %w", ErrNoJoinCodeForInvite, err)
 			return
```

**MJ61** (the open item MG-8; against the T1 tree and the T1a tree). A record of an earlier epoch that does not authenticate is handed back as a gap: the symptom of MG-8 goes away, and with it the tampering signal for every past epoch. Killed by `TestADeviceAddedBackAnswersAnAuthenticationFailureForHistoryItCannotOpen`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -4569,5 +4569,5 @@
 		headPlain, bodyPlain, err := self.session.OpenRecord(parsed)
 		if err != nil {
-			if pastEpochGap(err) {
+			if pastEpochGap(err) || (errors.Is(err, messagegroup.ErrRecordAeadOpen) && header.Epoch < self.epoch) {
 				self.noteEpochGapLocked(walk, recordId, header)
 				resolve(recordId)
```

**MJV2** (the version table; against the T1 tree). THE VERSION 2 READER RESTORED: a plaintext invitation parses and its two secrets are honoured. Killed by `TestAdvSimAnAttackerChosenSecretIsNotInstalled`.

```diff
--- a/sdk/urmessage/invite.go
+++ b/sdk/urmessage/invite.go
@@ -61,4 +61,7 @@
 // nothing, so it runs at the paste, before a join code is touched.
 func (self *Invite) check() error {
+	if _, legacy := mutantLegacy[self]; legacy {
+		return nil
+	}
 	if len(self.GroupId) != GroupIdBytes {
 		return fmt.Errorf("urmessage: an invite names a %d octet group id, want %d", len(self.GroupId), GroupIdBytes)
@@ -130,4 +133,7 @@
 	if err != nil {
 		return nil, fmt.Errorf("%w: it has no version: %w", ErrInviteDamaged, err)
+	}
+	if version == 0x0002 {
+		return parseLegacyInvite(encoded)
 	}
 	if version != InviteVersion {
@@ -173,2 +179,22 @@
 	return invite, nil
 }
+
+var mutantLegacy = map[*Invite][2][]byte{}
+
+func parseLegacyInvite(encoded []byte) (*Invite, error) {
+	reader := syntax.NewReader(encoded[:len(encoded)-inviteChecksumBytes])
+	if _, err := reader.ReadUint16(); err != nil {
+		return nil, err
+	}
+	invite := &Invite{}
+	var pqSecret, groupHandleKey []byte
+	for _, into := range []*[]byte{&invite.GroupId, &invite.Welcome, &invite.RatchetTree, &pqSecret, &groupHandleKey} {
+		value, err := reader.ReadOpaqueLP()
+		if err != nil {
+			return nil, err
+		}
+		*into = value
+	}
+	mutantLegacy[invite] = [2][]byte{pqSecret, groupHandleKey}
+	return invite, nil
+}
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1482,4 +1482,7 @@
 	// [Device.openJoinSeal]. The two secrets exist in this function only from here.
 	pqSecret, groupHandleKey, err := self.openJoinSeal(handle, invite)
+	if legacy, isLegacy := mutantLegacy[invite]; isLegacy {
+		pqSecret, groupHandleKey, err = append([]byte(nil), legacy[0]...), append([]byte(nil), legacy[1]...), nil
+	}
 	if err != nil {
 		return nil, err
```

**MJ1** (the seal; against the T1 tree). Pq_secret left in the clear beside the seal, as a sixth field. Killed by `TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch`.

```diff
--- a/sdk/urmessage/invite.go
+++ b/sdk/urmessage/invite.go
@@ -107,4 +107,5 @@
 	writer.WriteOpaqueLP(self.JoinSeal)
 	writer.WriteOpaqueLP(self.JoinAuth)
+	writer.WriteOpaqueLP(mutantClear)
 	encoded, err := writer.Bytes()
 	if err != nil {
@@ -165,4 +166,5 @@
 		*field.into = value
 	}
+	_, _ = reader.ReadOpaqueLP()
 	if err := reader.Done(); err != nil {
 		return nil, fmt.Errorf("urmessage: an invite with octets after its last field: %w", err)
@@ -173,2 +175,4 @@
 	return invite, nil
 }
+
+var mutantClear []byte
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1628,4 +1628,5 @@
 	foundingSecret := self.pqSecretLocked()
 	joinSeal, joinAuth, joinDigest, err := self.sealFoundingJoinLocked(joiner, welcome, ratchetTree, foundingSecret)
+	mutantClear = append([]byte(nil), foundingSecret...)
 	if err != nil {
 		self.handle.ClearPendingCommit()
@@ -2003,4 +2004,5 @@
 		var err error
 		joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, opensEpoch, pqSecret, epochKeysDigest)
+		mutantClear = append([]byte(nil), pqSecret...)
 		return err
 	}
```

**MJ2** (the seal; against the T1 tree). Group_handle_key left in the clear beside the seal. Killed by `TestAdvSimAPasteObserverRecoversTheGroupHandleKey`.

```diff
--- a/sdk/urmessage/invite.go
+++ b/sdk/urmessage/invite.go
@@ -107,4 +107,5 @@
 	writer.WriteOpaqueLP(self.JoinSeal)
 	writer.WriteOpaqueLP(self.JoinAuth)
+	writer.WriteOpaqueLP(mutantClear)
 	encoded, err := writer.Bytes()
 	if err != nil {
@@ -165,4 +166,5 @@
 		*field.into = value
 	}
+	_, _ = reader.ReadOpaqueLP()
 	if err := reader.Done(); err != nil {
 		return nil, fmt.Errorf("urmessage: an invite with octets after its last field: %w", err)
@@ -173,2 +175,4 @@
 	return invite, nil
 }
+
+var mutantClear []byte
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1628,4 +1628,5 @@
 	foundingSecret := self.pqSecretLocked()
 	joinSeal, joinAuth, joinDigest, err := self.sealFoundingJoinLocked(joiner, welcome, ratchetTree, foundingSecret)
+	mutantClear = append([]byte(nil), self.groupHandleKey...)
 	if err != nil {
 		self.handle.ClearPendingCommit()
@@ -2003,4 +2004,5 @@
 		var err error
 		joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, opensEpoch, pqSecret, epochKeysDigest)
+		mutantClear = append([]byte(nil), self.groupHandleKey...)
 		return err
 	}
```

**MJ3** (the seal; against the T1 tree). Sealed to a key that is not the joiner's. Killed by `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -257,5 +257,9 @@
 	}
 	defer zeroizeState(payload)
-	joinSeal, err = messagegroup.SealWrapBody(self.device.random, joiner.xwing, messagegroup.WrapEnvelope{
+	other, err := messagegroup.XwingGenerateKey(self.device.random)
+	if err != nil {
+		return nil, nil, err
+	}
+	joinSeal, err = messagegroup.SealWrapBody(self.device.random, other.Public(), messagegroup.WrapEnvelope{
 		FormatVersion: messagegroup.WrapFormatVersion,
 		TargetType:    wrapTargetTypeJoiner,
```

**MJ10** (the formats; against the T1 tree). A seal with a non-zero content epoch is accepted at the paste. Killed by `TestAnInviteWhoseSealIsNotTheShapeVersionThreeFixesIsRefused`.

```diff
--- a/sdk/urmessage/invite.go
+++ b/sdk/urmessage/invite.go
@@ -85,5 +85,5 @@
 	}
 	if envelope.FormatVersion != messagegroup.WrapFormatVersion || envelope.TargetType != wrapTargetTypeJoiner ||
-		envelope.PayloadType != wrapPayloadTypeJoinSecrets || envelope.ContentEpoch != 0 {
+		envelope.PayloadType != wrapPayloadTypeJoinSecrets {
 		return fmt.Errorf("%w: its envelope is version %#02x, target %#02x, payload %#02x, content epoch %d",
 			ErrJoinSealShape, envelope.FormatVersion, envelope.TargetType, envelope.PayloadType, envelope.ContentEpoch)
```

**MJ14** (the formats; against the T1 tree). The payload's length is not held to exactly 96. Killed by `TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -178,5 +178,5 @@
 // what a buffer that was erased before it was sealed looks like.
 func decodeJoinSecrets(payload []byte) (pqSecret []byte, groupHandleKey []byte, epochKeysDigest []byte, err error) {
-	if len(payload) != joinSecretsBytes {
+	if len(payload) < joinSecretsBytes {
 		return nil, nil, nil, fmt.Errorf("%w: the seal opened to %d octets and join_secrets_v1 is %d",
 			ErrJoinSealUnreadable, len(payload), joinSecretsBytes)
```

**MJ14b** (the formats; against the T1 tree). An all-zero secret is accepted. Killed by `TestJoinSecretsAreThreeValuesInOneOrderAndNothingElseOpens`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -186,5 +186,5 @@
 	groupHandleKey = append([]byte(nil), payload[messagegroup.PqSecretBytes:messagegroup.PqSecretBytes+groupHandleKeyBytes]...)
 	epochKeysDigest = append([]byte(nil), payload[messagegroup.PqSecretBytes+groupHandleKeyBytes:]...)
-	if subtle.ConstantTimeCompare(pqSecret, zero) == 1 || subtle.ConstantTimeCompare(groupHandleKey, zero) == 1 {
+	if false && (subtle.ConstantTimeCompare(pqSecret, zero) == 1 || subtle.ConstantTimeCompare(groupHandleKey, zero) == 1) {
 		zeroizeState(pqSecret)
 		zeroizeState(groupHandleKey)
```

**MJ15** (the formats; against the T1 tree). The join seal reuses the device wrap's code points (target 0x01, payload 0x01). Killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -52,6 +52,6 @@
 	// payloads 0x01 and 0x02 (pqepoch.go); target 0x02 and payload 0x03 are left for the recovery
 	// wrap. Like those, these are provisional until MG-7 is ruled.
-	wrapTargetTypeJoiner       uint8 = 0x03
-	wrapPayloadTypeJoinSecrets uint8 = 0x04
+	wrapTargetTypeJoiner       uint8 = 0x01
+	wrapPayloadTypeJoinSecrets uint8 = 0x01
 
 	joinSecretsBytes = messagegroup.PqSecretBytes + groupHandleKeyBytes + sha256.Size
```

**MJ4** (authentication; against the T1 tree). The joiner does not verify join_auth. Killed by `TestABentSealIsRefusedAndTheHonestInviteStillJoins`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -305,5 +305,5 @@
 		return nil, nil, err
 	}
-	if !self.crypto.MacVerify(joinKey, preimage, invite.JoinAuth) {
+	if false && !self.crypto.MacVerify(joinKey, preimage, invite.JoinAuth) {
 		return nil, nil, ErrJoinSealUnauthenticated
 	}
```

**MJ5** (authentication; against the T1 tree). Join_key from a public value: the hash of the welcome, on both sides. Killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -274,4 +274,6 @@
 	}
 	defer zeroizeState(joinKey)
+	publicKey := sha256.Sum256(welcome)
+	joinKey = publicKey[:]
 	preimage, err := joinAuthPreimage(self.id, opensEpoch, leaf, welcome, ratchetTree, joinSeal)
 	if err != nil {
@@ -301,4 +303,6 @@
 	}
 	defer zeroizeState(joinKey)
+	publicKey := sha256.Sum256(invite.Welcome)
+	joinKey = publicKey[:]
 	preimage, err := joinAuthPreimage(handle.GroupId(), epoch, leaf, invite.Welcome, invite.RatchetTree, invite.JoinSeal)
 	if err != nil {
```

**MJ5b** (authentication; against the T1 tree). Join_key from another public value: the hash of the ratchet tree, on both sides. Killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -274,4 +274,6 @@
 	}
 	defer zeroizeState(joinKey)
+	publicKey := sha256.Sum256(ratchetTree)
+	joinKey = publicKey[:]
 	preimage, err := joinAuthPreimage(self.id, opensEpoch, leaf, welcome, ratchetTree, joinSeal)
 	if err != nil {
@@ -301,4 +303,6 @@
 	}
 	defer zeroizeState(joinKey)
+	publicKey := sha256.Sum256(invite.RatchetTree)
+	joinKey = publicKey[:]
 	preimage, err := joinAuthPreimage(handle.GroupId(), epoch, leaf, invite.Welcome, invite.RatchetTree, invite.JoinSeal)
 	if err != nil {
```

**MJ5c** (authentication; against the T1 tree). The join key's exporter context without the leaf, on both sides. Killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -269,5 +269,5 @@
 		return nil, nil, fmt.Errorf("urmessage: the join seal is %d octets and invite version 3 carries exactly %d", len(joinSeal), joinSealBytes)
 	}
-	joinKey, err := self.handle.PendingExport(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	joinKey, err := self.handle.PendingExport(joinKeyExporterLabel, nil, joinKeyBytes)
 	if err != nil {
 		return nil, nil, fmt.Errorf("urmessage: the join key of epoch %d: %w", opensEpoch, err)
@@ -296,5 +296,5 @@
 
 	// VERIFY: join_auth over the received octets, under this epoch's own exporter.
-	joinKey, err := handle.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	joinKey, err := handle.Export(joinKeyExporterLabel, nil, joinKeyBytes)
 	if err != nil {
 		return nil, nil, fmt.Errorf("urmessage: the join key of epoch %d: %w", epoch, err)
```

**MJ5d** (authentication; against the T1 tree). The join key is the storage exporter itself, which is what storage_root is extracted from. Killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -269,5 +269,5 @@
 		return nil, nil, fmt.Errorf("urmessage: the join seal is %d octets and invite version 3 carries exactly %d", len(joinSeal), joinSealBytes)
 	}
-	joinKey, err := self.handle.PendingExport(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	joinKey, err := self.handle.PendingExport(storageExporterLabel, nil, joinKeyBytes)
 	if err != nil {
 		return nil, nil, fmt.Errorf("urmessage: the join key of epoch %d: %w", opensEpoch, err)
@@ -296,5 +296,5 @@
 
 	// VERIFY: join_auth over the received octets, under this epoch's own exporter.
-	joinKey, err := handle.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	joinKey, err := handle.Export(storageExporterLabel, nil, joinKeyBytes)
 	if err != nil {
 		return nil, nil, fmt.Errorf("urmessage: the join key of epoch %d: %w", epoch, err)
```

**MJ5e** (authentication; against the T1 tree). The welcome and the tree transposed in the preimage, at both call sites. Killed by `TestJoinAuthIsTheJoinEpochsExporterOverThePreimageOnBothRoads`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -274,5 +274,5 @@
 	}
 	defer zeroizeState(joinKey)
-	preimage, err := joinAuthPreimage(self.id, opensEpoch, leaf, welcome, ratchetTree, joinSeal)
+	preimage, err := joinAuthPreimage(self.id, opensEpoch, leaf, ratchetTree, welcome, joinSeal)
 	if err != nil {
 		return nil, nil, err
@@ -301,5 +301,5 @@
 	}
 	defer zeroizeState(joinKey)
-	preimage, err := joinAuthPreimage(handle.GroupId(), epoch, leaf, invite.Welcome, invite.RatchetTree, invite.JoinSeal)
+	preimage, err := joinAuthPreimage(handle.GroupId(), epoch, leaf, invite.RatchetTree, invite.Welcome, invite.JoinSeal)
 	if err != nil {
 		return nil, nil, err
```

**MJ6** (binding; against the T1 tree). The preimage does not cover the seal. Killed by `TestTheJoinAuthPreimageIsThese181Octets`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -212,5 +212,5 @@
 	writer.WriteOpaqueLP(welcomeHash[:])
 	writer.WriteOpaqueLP(treeHash[:])
-	writer.WriteOpaqueLP(sealHash[:])
+	_ = sealHash
 	preimage, err := writer.Bytes()
 	if err != nil {
```

**MJ7** (binding; against the T1 tree). The preimage does not carry the epoch. Killed by `TestTheJoinAuthPreimageIsThese181Octets`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -208,5 +208,5 @@
 	writer.WriteUint16(joinAuthInviteVersion)
 	writer.WriteOpaqueLP(groupId)
-	writer.WriteUint64(epoch)
+	_ = epoch
 	writer.WriteUint32(leaf)
 	writer.WriteOpaqueLP(welcomeHash[:])
```

**MJ8** (the key schedule; against the T1 tree). Join_key at the epoch that is closing, not the one the commit opens. Killed by `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -269,5 +269,5 @@
 		return nil, nil, fmt.Errorf("urmessage: the join seal is %d octets and invite version 3 carries exactly %d", len(joinSeal), joinSealBytes)
 	}
-	joinKey, err := self.handle.PendingExport(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
+	joinKey, err := self.handle.Export(joinKeyExporterLabel, joinerLeafId(leaf), joinKeyBytes)
 	if err != nil {
 		return nil, nil, fmt.Errorf("urmessage: the join key of epoch %d: %w", opensEpoch, err)
```

**MJ21** (the key schedule; against the T1 tree). A live add seals the secret of the epoch that is closing. Killed by `TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -2002,5 +2002,5 @@
 	seal := func(opensEpoch uint64, pqSecret []byte, epochKeysDigest []byte) error {
 		var err error
-		joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, opensEpoch, pqSecret, epochKeysDigest)
+		joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, opensEpoch, self.pqSecretLocked(), epochKeysDigest)
 		return err
 	}
```

**MJ22** (the key schedule; against the T1 tree). MJ21, and the sealed digest recomputed from the value that was sealed. Killed by `TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -2002,5 +2002,8 @@
 	seal := func(opensEpoch uint64, pqSecret []byte, epochKeysDigest []byte) error {
 		var err error
-		joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, opensEpoch, pqSecret, epochKeysDigest)
+		stale := self.pqSecretLocked()
+		mlsSecret, _ := self.handle.PendingExport(storageExporterLabel, nil, storageExporterBytes)
+		staleDigest, _ := epochKeysDigestOver(self.id, opensEpoch, mlsSecret, stale)
+		joinSeal, joinAuth, err = self.sealJoinLocked(joiner, welcome, ratchetTree, opensEpoch, stale, staleDigest)
 		return err
 	}
```

**MJ43** (the key schedule; against the T1 tree). The joiner does not compare the digest it recomputes with the one sealed beside the secret. Killed by `TestAMemberMadeSealIsHeldToItsEpochItsShapeAndItsAddressee`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -330,5 +330,5 @@
 	computed, err := epochKeysDigestOver(handle.GroupId(), epoch, mlsSecret, pqSecret)
 	zeroizeState(mlsSecret)
-	if err != nil || subtle.ConstantTimeCompare(computed, sealedDigest) != 1 {
+	if err != nil || (false && subtle.ConstantTimeCompare(computed, sealedDigest) != 1) {
 		zeroizeState(pqSecret)
 		zeroizeState(groupHandleKey)
```

**MJ32** (the key schedule; against the T1 tree). The seal is made after the epoch's wraps were submitted. Killed by `TestTheJoinSealIsMadeBeforeAnythingOfTheEpochIsSubmitted`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -2258,10 +2258,4 @@
 		return fmt.Errorf("urmessage: the digest of the keys epoch %d opens with: %w", newEpoch, err)
 	}
-	if beforeSubmit != nil {
-		if err := beforeSubmit(newEpoch, pqNext, commitDigest.EpochKeysDigest); err != nil {
-			self.handle.ClearPendingCommit()
-			return err
-		}
-	}
 
 	// (2c) RULING 37's WRAPS: SEALED AND SUBMITTED HERE, PRE-MERGE, AT EPOCH n -- AND AHEAD OF THE
@@ -2293,4 +2287,10 @@
 	// the current epoch and its attachment opens the next. The attachment is the digest built at
 	// (2b') above.
+	if beforeSubmit != nil {
+		if err := beforeSubmit(newEpoch, pqNext, commitDigest.EpochKeysDigest); err != nil {
+			self.handle.ClearPendingCommit()
+			return err
+		}
+	}
 	commitRecord, err := self.session.SealRecord(message.RetentionPermanent, 0, true,
 		encodeHead(self.device.nowMs()), commit, 0, &message.ServerAttachment{
```

**MJ32b** (the key schedule; against the T1 tree). The epoch's wraps submitted ahead of the hook from inside a helper, where the source gate does not look. Killed by `TestAHookThatRefusesLeavesNothingStagedAndNothingSent`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -2257,4 +2257,8 @@
 		self.handle.ClearPendingCommit()
 		return fmt.Errorf("urmessage: the digest of the keys epoch %d opens with: %w", newEpoch, err)
+	}
+	if err := self.mutantEarlyFanOut(ctx, staged.wraps); err != nil {
+		self.handle.ClearPendingCommit()
+		return err
 	}
 	if beforeSubmit != nil {
@@ -7349,2 +7353,11 @@
 	return nil
 }
+
+func (self *Group) mutantEarlyFanOut(ctx context.Context, wraps []*message.Record) error {
+	for _, wrap := range wraps {
+		if _, err := self.submitLocked(ctx, self.session, wrap, "an epoch wrap", nil); err != nil {
+			return err
+		}
+	}
+	return nil
+}
```

**MJ32c** (the key schedule; against the T1 tree). A hook that refuses leaves the commit it was called for staged. Killed by `TestAHookThatRefusesLeavesNothingStagedAndNothingSent`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -2260,5 +2260,4 @@
 	if beforeSubmit != nil {
 		if err := beforeSubmit(newEpoch, pqNext, commitDigest.EpochKeysDigest); err != nil {
-			self.handle.ClearPendingCommit()
 			return err
 		}
```

**MJ33** (the key schedule; against the T1 tree). Open publishes without holding the digest the invitation was sealed over. Killed by `TestOpenRefusesToPublishKeysItsInviteWasNotSealedOver`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1827,5 +1827,5 @@
 	// it a third time and refuses an invite it does not reproduce. Two derivations in one build
 	// are held together here rather than assumed to agree.
-	if !sameDigest(self.foundingJoinDigest, foundingDigest.EpochKeysDigest) {
+	if false && !sameDigest(self.foundingJoinDigest, foundingDigest.EpochKeysDigest) {
 		return fmt.Errorf("%w: epoch %d", ErrInviteDigestDrift, self.epoch)
 	}
```

**MJ11** (the adder; against the T1 tree). The adder does not ask for the capability. Killed by `TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -101,5 +101,5 @@
 		return nil, fmt.Errorf("%w: %w", ErrKeyPackageInvalid, err)
 	}
-	if !decoded.LeafNode.Capabilities.SupportsExtension(mls.ExtensionTypeUrmessageJoinSeal) {
+	if false && !decoded.LeafNode.Capabilities.SupportsExtension(mls.ExtensionTypeUrmessageJoinSeal) {
 		return nil, ErrJoinerCannotOpenSealedInvite
 	}
```

**MJ11b** (the adder; against the T1 tree). The adder does not validate the join code before it stages. Killed by `TestAnAdderRefusesAJoinCodeItCannotSealToBeforeAnythingIsStaged`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -98,5 +98,5 @@
 	// THE WALL CLOCK, AND NOT THE DEVICE'S OWN: it is the clock connect/mls judges the same key
 	// package's lifetime by at CommitAdd, so this check and that one cannot come to disagree.
-	if err := decoded.Validate(self.crypto, deviceCipherSuite, time.Now()); err != nil {
+	if err := decoded.Validate(self.crypto, deviceCipherSuite, time.Now()); false && err != nil {
 		return nil, fmt.Errorf("%w: %w", ErrKeyPackageInvalid, err)
 	}
```

**MJ11c** (the adder; against the T1 tree). An identity whose leaf stands is answered the role model's own refusal, with no remedy named. Killed by `TestTheLiveAdderJudgesAJoinCodeAndNamesTheRemedyForALeafThatStands`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -149,5 +149,5 @@
 // in the name's own sentence.
 func joinerAlreadyHasALeaf(err error) error {
-	if errors.Is(err, ErrCommitIdentityClaimed) || errors.Is(err, mls.ErrAddDuplicateSignatureKey) {
+	if false && (errors.Is(err, ErrCommitIdentityClaimed) || errors.Is(err, mls.ErrAddDuplicateSignatureKey)) {
 		return fmt.Errorf("%w: %w", ErrJoinerAlreadyHasALeaf, err)
 	}
```

**MJ62** (the adder; against the T1 tree). The joiner's leaf found by its signature key alone, and not by the whole leaf. Killed by `TestTheJoinersLeafIsTheWholeLeafTheJoinCodePublished`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -136,5 +136,5 @@
 		return 0, err
 	}
-	if subtle.ConstantTimeCompare(inTree, published) != 1 {
+	if false && subtle.ConstantTimeCompare(inTree, published) != 1 {
 		return 0, fmt.Errorf("urmessage: leaf %d of the tree the add returned is not the leaf the join code published", leaf)
 	}
```

**MJ34** (the adder; against the T1 tree). A failed seal leaves its commit staged on the founding road. Killed by `TestAFailedSealLeavesTheFounderWhereItWasAndTheAddCanBeMadeAgain`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1629,5 +1629,4 @@
 	joinSeal, joinAuth, joinDigest, err := self.sealFoundingJoinLocked(joiner, welcome, ratchetTree, foundingSecret)
 	if err != nil {
-		self.handle.ClearPendingCommit()
 		return nil, err
 	}
```

**MJ18** (the adder; against the T1 tree). A device with no X-Wing seed publishes a join code it can never open an invitation for. Killed by `TestADeviceWithNoWrapSeedPublishesNoJoinCode`.

```diff
--- a/sdk/urmessage/device.go
+++ b/sdk/urmessage/device.go
@@ -741,5 +741,5 @@
 	seedless := len(self.wrapSeed) == 0
 	self.mutex.Unlock()
-	if seedless {
+	if seedless && false {
 		return nil, fmt.Errorf("%w, and so it publishes no join code: an invite to one is sealed to that leaf", ErrNoDeviceWrapKey)
 	}
```

**MJ13** (the joiner; against the T1 tree). The joined state is committed to the store before the seal is verified, opened and checked. Killed by `TestABentSealIsRefusedAndTheHonestInviteStillJoins`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1475,4 +1475,10 @@
 			ErrReaddStale, handle.Epoch(), removedEpoch)
 	}
+	// THE COMMIT, CREATE-ONLY: the joined state reaches the store only if the store holds none for
+	// this group and epoch. It is the last thing that can refuse without costing the join code.
+	if err := self.joinStage.commit(); err != nil {
+		return nil, err
+	}
+	committed = true
 	// ONLY A GROUP THAT REQUIRES THE JOIN SEAL IS JOINED: see [ErrGroupPredatesJoinSeal].
 	if err := requireJoinSeal(handle); err != nil {
@@ -1505,10 +1511,4 @@
 		return nil, fmt.Errorf("urmessage: the past epoch loader: %w", err)
 	}
-	// THE COMMIT, CREATE-ONLY: the joined state reaches the store only if the store holds none for
-	// this group and epoch. It is the last thing that can refuse without costing the join code.
-	if err := self.joinStage.commit(); err != nil {
-		return nil, err
-	}
-	committed = true
 	// ── THE WINDOW IS CLOSED ───────────────────────────────────────────────────────────────────
 	group := &Group{
```

**MJ19** (erasure; against the T1 tree). The sealed payload is not erased. Killed by `TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -256,5 +256,4 @@
 		return nil, nil, err
 	}
-	defer zeroizeState(payload)
 	joinSeal, err = messagegroup.SealWrapBody(self.device.random, joiner.xwing, messagegroup.WrapEnvelope{
 		FormatVersion: messagegroup.WrapFormatVersion,
```

**MJ19b** (erasure; against the T1 tree). The handle key the seal opened to is not erased on a refusal made before the join commits. Killed by `TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1489,9 +1489,4 @@
 	// the handle key is the group's once the join has committed; a refusal made between here and
 	// the commit erases it with everything else that refusal leaves
-	defer func() {
-		if !committed {
-			zeroizeState(groupHandleKey)
-		}
-	}()
 	session, err = messagegroup.NewGroupSession(handle, pqSecret, groupHandleKey,
 		self.reserver, self.nowMs, nonce)
```

**MJ50** (the capability; against the T1 tree). A group this build founds does not require the join seal of its members. Killed by `TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt`.

```diff
--- a/messagegroup/engine.go
+++ b/messagegroup/engine.go
@@ -983,5 +983,4 @@
 			mls.ExtensionTypeUrmessageGroupPolicy,
 			mls.ExtensionTypeUrmessageLeafKeys,
-			mls.ExtensionTypeUrmessageJoinSeal,
 		},
 	}
```

**MJ51** (the capability; against the T1 tree). A group that does not require the join seal is joined. Killed by `TestOnlyAGroupThatRequiresTheJoinSealIsJoined`.

```diff
--- a/sdk/urmessage/group.go
+++ b/sdk/urmessage/group.go
@@ -1474,8 +1474,4 @@
 		return nil, fmt.Errorf("%w: the welcome stands at epoch %d and this device was removed at epoch %d",
 			ErrReaddStale, handle.Epoch(), removedEpoch)
-	}
-	// ONLY A GROUP THAT REQUIRES THE JOIN SEAL IS JOINED: see [ErrGroupPredatesJoinSeal].
-	if err := requireJoinSeal(handle); err != nil {
-		return nil, err
 	}
 	// THE JOIN SEAL: verified, opened and checked, in that order, before anything is honoured. See
```

**MJ52** (the capability; against the T1 tree). A group founded before the join seal is restored like any other. Killed by `TestAGroupFoundedBeforeTheJoinSealIsNotRestoredAndCanBeLeft`.

```diff
--- a/sdk/urmessage/restore.go
+++ b/sdk/urmessage/restore.go
@@ -300,8 +300,4 @@
 	// ONLY A GROUP THAT REQUIRES THE JOIN SEAL IS RESTORED: see [ErrGroupPredatesJoinSeal]. It is
 	// asked before a session is built, so nothing of the group is in memory when it is refused.
-	if err := requireJoinSeal(handle); err != nil {
-		handle.Close()
-		return nil, fmt.Errorf("%w: group %x at epoch %d: %w", ErrRestore, record.GroupId, record.Epoch, err)
-	}
 	// THE TABLE THIS RECORD CAME BACK WITH, AND WHAT IT IS WHEN THERE IS NONE. A record written
 	// before item 251's ruling 40 has five parts and nil here; one written by this build has six
```

**MJ63** (the capability; against the T1 tree). The profile row for 0xF004 removed: the join seal's code point is no longer refused as a group-context extension. Killed by `TestTheV1ProfileClassifiesEveryRegisteredExtensionTypeAsAGroupContextExtension`, in `./mls/`.

```diff
--- a/mls/validate_commit.go
+++ b/mls/validate_commit.go
@@ -196,5 +196,4 @@
 	ExtensionTypeUrmessageLeafKeys:       errProfileGroupExtension,
 	ExtensionTypeUrmessageOwnerSuccessor: nil,
-	ExtensionTypeUrmessageJoinSeal:       errProfileGroupExtension,
 }
 
```

**MJ64** (the capability; against the T1 tree). No leaf this build makes lists the capability its own groups require. Killed by `TestAFoundedGroupRequiresTheJoinSealAndAdmitsNoKeyPackageWithoutIt`.

```diff
--- a/mls/group.go
+++ b/mls/group.go
@@ -724,5 +724,4 @@
 			ExtensionTypeUrmessageLeafKeys,
 			ExtensionTypeUrmessageOwnerSuccessor,
-			ExtensionTypeUrmessageJoinSeal,
 		},
 		Proposals:   []ProposalType{},
```

**MJ9** (binding; against the T1 tree). The adder seals and authenticates for a leaf that is not the joiner's (the design's MJ9). Killed by `TestAnInviteCarriesNoSecretInTheClearAndTheJoinerStillHoldsBoth`.

```diff
--- a/sdk/urmessage/joinseal.go
+++ b/sdk/urmessage/joinseal.go
@@ -252,4 +252,5 @@
 		return nil, nil, err
 	}
+	leaf ^= 1
 	payload, err := encodeJoinSecrets(pqSecret, self.groupHandleKey, epochKeysDigest)
 	if err != nil {
```

**MJ65** (the version table; against the T1 tree). The codec's invite version moves and the authenticator's does not. Killed by `TestTheInviteVersionIsTheOneJoinAuthIsOver`.

```diff
--- a/sdk/urmessage/invite.go
+++ b/sdk/urmessage/invite.go
@@ -22,5 +22,5 @@
 // review flipped one bit at each of 3,408 positions of a real invite and 3,386 parsed. See
 // [ParseInvite].
-const InviteVersion uint16 = 0x0003
+const InviteVersion uint16 = 0x0004
 
 // inviteChecksumBytes is the width of the SHA-256 an encoded invite ends with.
```

---

# Reports to the owner

Plain text, to be sent by the lead at the close of each phase. THE NUMBERS ARE THE LAB'S, MEASURED UNDER go1.26.5. Every one is measured again on the day, on the branch, under the compiler of the day (R6), and the report carries those. A count that differs from the lab's is a finding and is said, not smoothed.

**At the end of S0.**

> S0 is in: the adversary tests exist and they are red where we said the gaps are.
>
> - 22 scenarios run real devices against the real server in one process. 17 report a gap
>   that is open today, 4 are controls and 1 is a known residual.
> - In strict mode the run is RED: 17 FAIL, 8 PASS. In normal mode all 25 pass,
>   because a known gap passes only while it is exactly as recorded.
> - What the adversaries got, on today's build: a recorder of both pasted codes with a future
>   quantum computer read the join epoch on every road we add people by (a founding add, a live
>   add, an admin's add) and found both join secrets in a second device's invitation; an observer
>   of one pasted invitation recovered the group's handle key; an attacker's chosen secret was
>   installed; a refused invitation spent the join code (two ways); and an invitation replaced a
>   group the device already held (six ways as a member, and one more after it was removed).
> - Three of the 17 are not this step's to close and stay red on purpose: join-code substitution
>   and the removed-group case (both need the identity layer) and keys at rest (the healing step).
> - Also in: the pin file no longer names things that do not exist; vector family 16 runs (10 of
>   16 families now; 14 cases, 28 comparisons); and a vulnerability scan exists as an opt-in step.
>   Its first run, under the old compiler, found 15 known vulnerabilities in the Go release
>   our toolchain was pinned to (14 reached by the code we ship, one more only by a test suite),
>   all in its standard library and all fixed in a later release.
>   That was ruled on, not coded around: the toolchain moved to go1.27.2 in a reviewed change of
>   its own before this step landed. [Say here what the scan prints today, under that compiler.]
> - Every other suite is unchanged. Passing tests: messagegroup 359, sdk 308, cp3b 106.
> - Run for this report, and never in the planning lab: the full `test.sh` on linux, with the race
>   detector and the native library, and on Windows; and the four automatic checks on the branch.
>   [Quote the two verdict lines and the run.]

**At the end of T1a.**

> The fast track is in: an invitation can no longer replace a group you are in, and a refused
> invitation no longer costs you your join code.
>
> - RED before, GREEN after: the six "replace a held group" scenarios and the two "refusal spends
>   the join code" scenarios. Strict mode went from 17 FAIL to 9.
> - No format changed, so nothing needs a reset for this.
> - If a group will not restore after a crash, you can now leave it and be invited again. Before
>   this, that state would have had no way out once the gate was in.
> - ONE DAMAGED FILE NO LONGER COSTS YOU THE DEVICE. A check of this plan, before any of it
>   shipped, found that one unreadable group file would have stopped the device joining, starting
>   or leaving ANY conversation, with no way out. That is fixed in this step: your other
>   conversations still open, the damaged one is reported, and you can leave it and be invited
>   again. Opening the others past a damaged file is a deliberate change to how restore behaved
>   before.
> - One thing it does NOT close, and it stays red on purpose: a device that was REMOVED from a
>   group can be taken into a different group under the same id by somebody else's invitation.
>   An invitation does not yet say who made it. The identity layer closes that.
> - ONE DEFECT FOUND, WRITTEN DOWN AND NOT FIXED HERE: a device that was removed from a group and
>   added back reads everything sent after it came back, but its first fetch also reports "a
>   record ciphertext did not authenticate" for old history it cannot open. Nothing was tampered
>   with; the wrong alarm rings. It is filed as open item MG-8 with a test that holds it as it
>   is, and the healing step takes it.
> - THE WINDOWS APP WAITS FOR ONE THING: no app package is built on this library until the app
>   can offer "leave this group" for a conversation that did not open. [Say whether that is done.]
> - The pieces of this step were reviewed while planning; the outside review of its new
>   mechanisms is at the end of the next step, after this one has merged.
> - New tests: 23, one of them a new scenario. 35 deliberate breakages were each
>   caught by a named test.
> - Passing tests: messagegroup 361, sdk 321, cp3b 114.
> - Run for this report: the full `test.sh` on linux, with the race detector, and on Windows; and
>   the four automatic checks. This step adds two locks to the join path, so a race report would
>   have been a finding. [Quote the verdicts and the run.]

**At the end of T1.**

> The join secret is sealed. The paste-channel gap is narrowed, and the tests that were red for
> it are green.
>
> | | RED before (strict) | After |
> |---|---|---|
> | Replace a group you are in (S7a to S7f) | 6 FAIL | 6 CLOSED, after T1a |
> | A refused invitation spends the join code | 2 FAIL | 2 CLOSED, after T1a |
> | Harvest now, decrypt later: founding add, live add, an admin's add, a second device | 4 FAIL | 4 CLOSED, after T1 |
> | A paste observer recovers the group's handle key | 1 FAIL | CLOSED, after T1 |
> | An attacker's chosen secret is installed | 1 FAIL | CLOSED, after T1 |
> | Join-code substitution; a removed device taken into another founder's group | 2 FAIL | still open: the identity layer |
> | A copied device reads the join epoch | 1 FAIL | still open: the healing step |
>
> - Strict mode: 17 FAIL at S0, 9 after T1a, 3 after T1.
> - An invitation now carries no secret in the clear. The joiner checks it before anything is
>   written, so a bad invitation costs nothing.
> - NARROWED, NOT CLOSED: an invitation still shows the group's id and who is in it, and the order
>   of first messages still links a new member to its handle (pinned by a test). Whoever copies a
>   device's data AND recorded the paste reads the join epoch; that is pinned by a test too.
> - TEST CONVERSATIONS MADE BEFORE THIS BUILD WILL NOT OPEN AFTER IT. START EACH FOLDER FRESH.
>   This build opens only groups started under it. An old group is refused by name and can be
>   left; old invitations and old join codes are refused by name. The app says so in a sentence.
> - ONE RULE: never run an older package over a folder this build has used. Delete the folder
>   instead. The older build would paste the group's keys in the clear with nothing to notice it.
> - New tests: 24 for T1, two of them new scenarios. 83 deliberate breakages in all, each
>   caught by a named test on the tree it was made for.
> - Passing tests at the end: messagegroup 362, sdk 339, cp3b 119. No suite has a failure.
> - Run for this report: the full `test.sh` on linux and on Windows, the four automatic checks,
>   the vulnerability scan under the new compiler, and the live probe against the server after
>   its reset. [Quote the verdicts, the run and the probe's last line.]
> - Still open and written down, not this step's: the wrong alarm for a re-added device's old
>   history (open item MG-8, the healing step).
> - Still to do when this is sent: nothing of this step. Next is the identity layer.

---

# Counts

| | S0 | T1a | T1 | All |
|---|---|---|---|---|
| Tasks | 31 | 9 | 19 | 59 |
| Commits to this repository | 4 | 5 | 12 | 21 |
| New Go tests | 27 | 23 | 24 | 74 |
| Of those, adversary simulations (scenarios) | 22 | 1 | 2 | 25 |
| Mutants, each run and killed | 8 | 35 | 40 | 83 |

The commits are counted off the lab's chain (`git log base..chain`), the scenarios off the
harness's registry at each phase end, and the new tests off the commits: every `func Test` a
commit adds, less every one it removes (`git diff <commit>~1 <commit> -- '*_test.go'`). The
scenarios are counted among the tests. The mutants are the entries of Appendix B. The tasks that
write `message-server` (Task 1, Task 32, Task 41) and the two that write `message-windows` (Task 39, Task 58) are counted
in their phase and commit nothing here.

**Before this revision** the same table read: tasks 31, 7 and 19 (57); commits 4, 4 and 12 (20);
new tests 27, 16 and 24 (67); scenarios 22, 0 and 2 (24); mutants 8, 20 and 36 (64).

---

# Review dispositions

This plan was reviewed twice. Its first form had two reviews, and the 25 findings of those are
the first table. Its final form then had ONE INDEPENDENT CHECK BY TWO CHECKERS before execution,
which the lead's rulings ask for; both said FIX-FIRST, the lead ruled (R11 to R14), and this
document is the plan revised to those rulings. The second section has every finding of that check.
The revised plan then had A SECOND CHECK (2026-10-12), on `main` `0bb2128f` under go1.27.2. It said
FIX-FIRST for two gates and four points of text, the lead ruled (R15 to R18), and the third section
has every finding of it.

## The two reviews of the first form

25 findings: 13 MAJOR, 9 MINOR, 3 NIT, no BLOCKER. Every MAJOR and MINOR is applied; two are
applied in a narrower form than the reviewer's fix, by the lead's ruling or for a measured reason,
and each says so. Where the final check reopened one of them, the row says so.

| # | Lens | Sev. | Finding | Disposition | Where |
|---|---|---|---|---|---|
| 1 | security | MAJOR | The held-group gate is asked above the join's lock: two overlapping joins both pass | APPLIED. One admission mutex from the question to the hold, for `Join`, `CreateGroup` and `Restore`; `holdReplacing` replaces only the group the gate judged; a forced-order test and three mutants | Task 33 |
| 2 | security | MAJOR | `ErrGroupAlreadyHeld` sends the caller to a `ForgetGroup` that refuses a group which does not restore | APPLIED. `ForgetGroup` leaves a group `Restore` could not bring back; a control scenario and two mutants. REOPENED BY THE FINAL CHECK (F1): it held for a record that reads and a state that does not load, and not for a record that does not READ. Applied in full now, by R12 | Task 33, Task 26 |
| 3 | security | MAJOR | The digest check survives removal; the question of dropping the digest | APPLIED. A member-made invitation with a valid authenticator and a wrong secret; mutant `MJ43`. The digest is kept (the lead's ruling) | Task 48 |
| 4 | security | MAJOR | The join key's derivation has no known answer; four mutants survive | APPLIED. A second spelling in `sdk/cp3b` with the standard library's HMAC, on both roads; it is the kill for `MJ5` and four new mutants | Task 48 |
| 5 | security | MAJOR | The reset is an assumption nothing checks | APPLIED. A build that joins and restores only groups requiring the join seal; the seedless join-code refusal; a task that lists what a reset is; the live step on the owner's actual state | Task 47, Task 42, Task 55, Task 56 |
| 6 | security | MAJOR | Round 2 was not run; the removed-group case replaces a group; the re-add rule is untested | APPLIED, with the review placed by the lead's ruling at the END of T1 as a pre-merge task and not before it. The removed-group case is a pinned open scenario and the plan's sentences are corrected; the re-add rule has a test and mutant `MJ37` | Task 57, Task 25, Task 33 |
| 7 | security | MAJOR | No task for the ledger, the spec edits or the open items file | APPLIED. Three message-server tasks, and the open items file in two commits | Task 1, Task 32, Task 41, Task 34, Task 53 |
| 8 | security | MINOR | The live road's seal failure has only a source gate | APPLIED. An injected refusal against a fake server that counts frames; mutants `MJ32b` and `MJ32c` | Task 44 |
| 9 | security | MINOR | `ErrJoinerAlreadyHasALeaf`, the one sentence prefix, and the app follow-up are dropped as if they were compatibility | APPLIED. All three are in; the app follow-up is a task with an owner | Task 45, Task 36, Task 58 |
| 10 | security | MINOR | Tests the design lists and the plan omits | APPLIED: the every-octet matrix, a replayed seal, `ErrJoinCodeSpent` on both arms, `ErrJoinSealUnreadable` at the join, the source gate over the unbound door, the requirement of `0xF004`, the whole-leaf search, and the design's MJ13 and MJ15 as run mutants. ONE NOT ADDED, with its reason: the seal's known answer through `sealWrapBodyWith` | Task 48, Task 35, Task 36, Task 42, Task 45, Appendix C |
| 11 | security | MINOR | One rollback rule still matters after a reset | APPLIED as a rule in the package notes and the owner report. The notes have a writer and a step since the final check (F14). The technical stop is priced and not planned | Task 55, Task 59, Appendix A |
| 12 | security | NIT | No control in the paste-observer scenario; no seed-plus-recorder on the live road; "closed" in the report | APPLIED, all three | Task 12, Task 46, "Reports to the owner" |
| 13 | security | NIT | Erase and typed-error gaps; the stage closed by explicit calls | APPLIED: one deferred exit; the put-back's failure is typed; the handle key is erased on a refusal (mutant `MJ19b`). NOT APPLIED: `join_key`'s erase is pinned by no gate, and "Mutation proofs" says so and why | Task 36, Task 46 |
| 14 | grounding | MAJOR | The preimage test fails until the flip, because the preimage reads the codec's version | APPLIED. The preimage has its own constant; the flip holds the two equal; the commit was built and is measured | Task 43, Task 46 |
| 15 | grounding | MAJOR | T1.2 to T1.5 were slices of one diff | APPLIED. The lab is a git repository with one commit per task, and each diff printed is that commit's; the flip is smaller, with three tasks moved out of it | "How this plan is laid out", Task 46, Task 47, Task 48 |
| 16 | grounding | MAJOR | The plan is not filed, not in the plan shape, and no spec or ledger task exists | APPLIED. This document is in the plan shape and was run through the linter in the lab; the tasks are the ones in row 7. The message-server writer makes the edits, by the one-writer rule | Task 1 |
| 17 | grounding | MAJOR | The scan script loads three modules the wrong way | APPLIED. Each module by the census's wiring, counted before it is read; run once in the lab, which is how the toolchain finding came to light | Task 29 |
| 18 | grounding | MAJOR | Two test commands are wrong; `-race` and the composed library were never run | APPLIED. The commands are corrected, and each phase closes on `./test.sh` on both hosts and on the fork's four legs (R8, R11). The lab still has no C compiler, and the plan says so | "Test commands", Task 31, Task 40, Task 59 |
| 19 | grounding | MAJOR | S0 is not the testing design's whole harness, and keys at rest were entered as accepted | APPLIED. "Not in S0" lists what is deferred and to which plan; `S4-state-thief` is open, closed by the healing track; the names T1, T1a and "the identity track" are mapped to the program's | "Not in S0", Task 18 |
| 20 | grounding | MINOR | Five section dividers were not printed | APPLIED by construction: the harness file is cut into pieces that the generator asserts concatenate to the file | Task 27 |
| 21 | grounding | MINOR | Stale sentences: five methods, 40 members, the invitation's plaintext fields | APPLIED, in the commits that make them stale. Two section titles are left on purpose, and the plan says which | Task 34, Task 46 |
| 22 | grounding | MINOR | The pin file gains a claim that is not true | APPLIED. It says what `test.sh` does: hash-checks sixteen files and verifies the installed families | Task 28 |
| 23 | grounding | MINOR | The mutants live only in the session scratchpad | APPLIED. Every mutant is printed as a diff, with the command | Appendix B |
| 24 | grounding | MINOR | Three vector-family tasks cannot be done in a sitting | APPLIED. They are not tasks of this plan (the lead's ruling) | "Not in S0" |
| 25 | grounding | NIT | Six small corrections | APPLIED where the text survives: the probe's build command; no count without its query; no diff that ends in an unchanged line; every file's import block is printed or its first uses named | Task 56, Task 4 |

## The final check of the final form (2026-10-09), and what was done with every finding

Two checkers, independent of each other and of the planner, each with a lab of its own:
`_finalcheck_fidelity.md` (security fidelity: 0 BLOCKER, 3 MAJOR, 8 MINOR, 6 NIT; findings F1 to
F17, and an edit list E1 to E22) and `_finalcheck_grounding.md` (grounding against
`urnetwork/message` main as it was that day: 1 BLOCKER, 2 MAJOR, 6 MINOR). 26 findings, both
verdicts FIX-FIRST. What both found to hold: the 20 commits of the checked chain applied to main
with no conflict, every count the plan stated reproduced, all 64 mutants were killed, and the
held-group gate and the act it guards were under one lock.

The lead ruled on what did not hold (R11 to R14, in `LEAD-RULINGS-2026-10-09.md`). EVERY ROW BELOW
THAT SAYS "BUILT" WAS BUILT AND RUN IN THE LAB FOR THIS REVISION, and its numbers are in "Measured
results" and "Mutation proofs". Nothing here is applied by sentence alone where code was asked for.

**Fidelity.**

| # | Sev. | Finding | Disposition | Where |
|---|---|---|---|---|
| F1 | MAJOR | One group record that does not read wedges the whole device: the gate asks the store for EVERY record, and no call clears it | BUILT, by R12. The store answers about ONE group (`DeviceStore.GroupRecord`); its list tolerates a record that does not read and reports it; `Restore` goes on past it; `ForgetGroup` leaves it, and the refusal's sentence names `ForgetGroup`; a control scenario beside `S7-c1` (`S7-c2-unreadable-record-costs-one-group`); 11 mutants, the checker's two among them. ONE CLAUSE COULD NOT BE MET AS WORDED: see "What could not be done as ruled", below | Task 33 |
| F2 | MAJOR | Ruling R6 is not in the plan: the order of merges, the base, the compiler | APPLIED, by R14 (E1 to E9) | the rows Order, Base and Compiler at the head; "What the lead has ruled"; "Test commands"; Task 28, Task 29, Task 59; "Measured results"; "Reports to the owner" |
| F3 | MAJOR | Ruling R10 gives T1a's pull request a deliverable the plan has no task for | BUILT, by R14: a task and a commit of three files, the row `MG-8`, the line that cites it and the named test; one mutant. The counts follow | Task 37 |
| F4 | MINOR | The app's half of finding 2's remedy is scheduled at T1's end | APPLIED, by R13. The row for `ErrGroupAlreadyHeld` and its leave action are a task at T1a's close, and no app package is built on a T1a library before it | Task 39, Task 40 |
| F5 | MINOR | The admission mutex on `Restore` and `CreateGroup` is pinned by nothing | BUILT, by R12: one forced-order test each, and the mutants that take each lock away (`MJ57`, `MJ58`) | Task 33 |
| F6 | MINOR | "A store that cannot be read refuses" has no test | BUILT, by R12: the control scenario through a record cut short, and a unit case over a store that will not answer for one group; `MJ54` and `MJ54b`, the two the checker found alive | Task 33 |
| F7 | MINOR | The window's sentence says "the join code is not spent" for an invitation whose join code is already gone | BUILT, by R13: `ErrNoJoinCodeForInvite`, with the lead's sentence; a row in the test that holds the window's sentences, both ways a join code goes; mutant `MJ60`; the app's row. One thing it cannot tell apart is said in its header and is a question of the review | Task 36, Task 58, Task 57 |
| F8 | MINOR | R7 against the text (E10 to E13) | APPLIED: one message-server writer, each task its own small pull request paired with its phase and merged first; Spec C is that writer's file | Task 1, Task 32, Task 41, the three closes, Task 58 |
| F9 | MINOR | R8 against the text (E14 to E16) | APPLIED: `alt-2` prints the plain verdict, the fork's four legs run on the branch head, and the pull request cites the run | "Test commands", Task 31, Task 40, Task 59 |
| F10 | MINOR | R9 against the text, and the ledger list of the filing task (E17, E18, E11) | APPLIED: both choices confirmed and kept on the review's list; the T1 report carries R9's two plain sentences; the ledger entry records R6 to R14 | "What the lead has ruled", Task 1, Task 55, Task 57, "Reports to the owner" |
| F11 | MINOR | The capability task's `git add` omits `mls/testdata/corpus/` | APPLIED: the line names the directory, and the generator of this plan now asserts that a task's `git add` names every file of its commit | Task 42 |
| F12 | NIT | The family-16 task's "see it fail" prints `ok` | MEASURED AGAIN, with only the pending list laid over: `TestVectorManifestIsComplete` fails, as the checker found | Task 30 |
| F13 | NIT | "the 19 kills" where there were 20 | APPLIED: the number is counted from the mutants, not written | Task 40 |
| F14 | NIT | The header says "no rollback rules" and one is kept; "the T1 package's notes" has no task and no writer | APPLIED: the header says one rule is kept; the notes are a step of the T1 close, and the lead writes them | the Variant row, Task 55, Task 59 |
| F15 | NIT | The review task reviews T1a's mechanisms after T1a has merged; "answered by measurement" overstates prompt 1; one read path is unexamined | NOT RULED (R14), so NOT CHANGED IN CODE. It is three things in the text: the T1a close records that its mechanisms are reviewed after they merge; prompt 1 is "answered in part"; and the crash inside the window and the read path during it are questions (a) and (b) of the review | Task 40, Task 57 |
| F16 | NIT | After the commit, a join whose record cannot be written does not erase the group's handle key or its copy of the epoch's secret; a hold refused there is not typed as spent | NOT RULED (R14), so NOT CHANGED IN CODE. Question (c) of the review | Task 57 |
| F17 | NIT | The capability task's third mutation is a build failure; the flip's mutation 16 is "stated, not run"; the design's name MJ9 is reused | BUILT: `MJ63`, `MJ64` and `MJ65` are the three, run on the revised chain; this plan's `MJ9` is `MJ62` now, and `MJ9` is the design's own mutant, new and run | Task 42, Task 46, Task 45, "Mutation proofs" |

**Grounding.**

| # | Sev. | Finding | Disposition | Where |
|---|---|---|---|---|
| BLOCKER 1 | BLOCKER | R8's fourth leg fails at every phase head by the plan's own changes: `verify_split.py` holds every path of the tip to the import's manifest | RULED (R11), and the ruling is not this plan's to build: the proof is held at ONE recorded tip, and the leg's change is the pins-switch pull request's. This plan states the leg in that form at each close, and ADDS NO ROW TO THE IMPORT'S MANIFEST | "What the lead has ruled", the three closes, "Rules for every task", the gates table |
| MAJOR 1 | MAJOR | The same leg is red on `main` itself since urnetwork/sdk#158 merged: `carried.py` takes a removal's base as a merge base with a moving `main` | RULED (R11): `carried.py` takes the two removals' ranges as recorded commits. The pins-switch pull request's change, not this plan's | "What the lead has ruled" |
| MAJOR 2 | MAJOR | R10's filing is refused by a `messagegroup` gate unless a commit the chain does not hold is written | BUILT, by R14, as the checker's stand-in showed it could be: the gate reads 8 rows and 8 cited, and the 12 T1 commits apply behind the new one | Task 37 |
| MINOR 1 | MINOR | The Base row and the assumption are stale | APPLIED: the base is `urnetwork/message` `main` on the day a phase is cut; the revised chain was applied to it again, and the result is printed | the Base row, "What was verified" |
| MINOR 2 | MINOR | R6 to R9 are not in the plan | APPLIED, as F2 and F8 to F10 | as there |
| MINOR 3 | MINOR | The family-16 task's "see it fail" prints a pass | MEASURED AGAIN, as F12 | Task 30 |
| MINOR 4 | MINOR | "the 19 kills" | APPLIED, as F13 | Task 40 |
| MINOR 5 | MINOR | `HV4`'s diff does not apply to the T1 tree | BUILT: its entry goes in between two controls no commit touches and is printed with one line of context; the appendix check now applies every harness mutant to both trees | "Mutation proofs", Appendix B |
| MINOR 6 | MINOR | "A branch of the owner's fork" would carry a workflow file upstream | APPLIED: a phase branch is cut from `urnetwork/message` `main` | the Repository row, the three closes, "Rules for every task" |

**The fidelity check's edit list, E1 to E22, edit by edit.** R14 asks for the text to follow it.

| Edit | What it asked | Where it is now |
|---|---|---|
| E1, E2 | the order of merges; `main` is `a0d47bef`, and one hunk of `test.sh` sits one line lower | the rows Order and Base |
| E3 | the pin's ruling in place of "not planned here" | "What the lead has ruled", R6 |
| E4 | "go1.26.5" becomes "the pin" | "Test commands"; the Compiler row |
| E5 | every number is under go1.26.5, and the branch's own run replaces it | "Measured results"; "What was verified"; "Reports to the owner" |
| E6 | the assumption about the import is a fact with one exception | "What was verified", under Assumed |
| E7 | "Until that is ruled" becomes "Ruled: R6" | Task 29 |
| E8 | the scan at T1's close runs under the moved pin and must pass | Task 59 |
| E9 | the gates table and the S0 report name the ruling; the pin FILE's prose is not a pin | the gates table, "Reports to the owner", Task 28 |
| E10 | each message-server task is its own small pull request, merged first | Task 1, Task 32, Task 41 |
| E11 | the ledger list gains the rulings | Task 1, step 3 |
| E12 | Spec C is a file of `message-server` | Task 41 step 4, Task 58 |
| E13 | the three close entries are the same writer's | Task 31, Task 40, Task 59 |
| E14, E16 | the fork's four legs; the pull request cites the run; "no CI service" is true of upstream only | "Test commands", the three closes, "Not in S0" |
| E15 | `alt-2` prints the full verdict; a race report at T1a is a finding | the three closes; Task 40 |
| E17 | both choices confirmed, and both questions of the review | "What the lead has ruled", R9; Task 57 step 6 |
| E18 | the T1 report's two plain sentences | "Reports to the owner"; Task 55 step 5 |
| E19 | the ruling in place of "no task here depends on it" | "What the lead has ruled", R10 and R14 |
| E20 | a new T1a task: the row, the test | Task 37. It is three files and not two: the gate needs the citing line as well, as the grounding check found |
| E21 | the counts | "Counts". T1a is 9 tasks and 5 commits, and the plan 59 and 21: one task more than the edit list counted, because R13 then made the app's leave action a task of T1a |
| E22 | the T1a close and report name the open item | Task 40, "Reports to the owner" |

**What could not be done as ruled, and why.** One clause, of R12.

- **"The listing ... reports it as damaged, with its group id where the store's own naming gives
  one."** `DurableStateStore`, the one durable store this repository ships, names a group's
  directory by the SHA-256 of its id (`stateNameOf`). That name cannot be turned back into an id,
  and the id inside a record that does not read is not one to believe. So the store's naming
  NEVER gives one: the list reports a damaged record by its directory, `Restore` reports it by
  that name inside `ErrRestore`, and nothing is added for it to the device's memory of groups
  that did not restore. The clause is met for any store whose naming does give an id, and that is
  none today.
- **What that costs, and what it does not.** A person cannot be told WHICH conversation is
  damaged from the restore's report alone. Every act on the group still works, because each takes
  an id the caller already holds: the gate refuses an invitation into it and names `ForgetGroup`;
  `ForgetGroup` leaves it by that invitation's id; and the same invitation then joins. The control
  scenario drives exactly that.
- **What would meet the clause in full**, and is NOT done here because nothing asked for it: read
  the id out of the first part of the damaged file and keep it only if it hashes to the
  directory's name. It is a second reader of a record that failed its checksum. It is listed for
  the pre-merge review with question (e).

Nothing else of R6 to R14 was left undone. Two things were done that no ruling words, and each is
said where it is: the store answers a record only from the directory it names, so that its list
and its one-id read cannot disagree (Task 33); and "does not read" covers a file the disk would
not hand over as well as one whose checksum fails, which is question (e) of Task 57.

**The task numbers, before and after.** The rulings and the two checks name tasks by the numbers
of the checked plan. Phase S0 did not move (Tasks 1 to 31), and neither did Tasks 32 to 36. Two
tasks are new, so every task after them has a new number:

| Before the revision | Now | Task |
|---|---|---|
| (new) | Task 37 | The open item for a re-added device's first `Receive`: filed, cited and reproduced, and not fixed |
| Task 37 | Task 38 | Run every T1a mutant |
| (new) | Task 39 | The app can leave a group that did not restore, before any app package is built on a T1a library (message-wind |
| Task 38 | Task 40 | Close T1a: the full run on both hosts, the ledger, the report, the pull request |
| Task 39 | Task 41 | The sealed invite in MASTER and Spec A, reset-variant form (message-server writer) |
| Task 40 | Task 42 | The capability: every leaf lists `0xF004`, every group requires it, and a device that cannot open a seal publi |
| Task 41 | Task 43 | The formats: the payload, the preimage and the digest a joiner recomputes |
| Task 42 | Task 44 | The key schedule: the epoch's digest is built ahead of the wraps, and a hook runs before anything is submitted |
| Task 43 | Task 45 | The adder judges a join code before it stages anything, and names the remedy for a leaf that stands |
| Task 44 | Task 46 | The flip to invite version 3: the adder seals on both roads, the joiner verifies, opens and checks |
| Task 45 | Task 47 | Only a group that requires the join seal is joined or restored |
| Task 46 | Task 48 | The seal held from the member's side, by a second spelling, and at every octet |
| Task 47 | Task 49 | The live probe, join seal step 1 of 4: an invitation at version 2 is refused by its version |
| Task 48 | Task 50 | The live probe, join seal step 2 of 4: an invitation with one bit of its authenticator flipped is refused, and |
| Task 49 | Task 51 | The live probe, join seal step 3 of 4: the invitation B already joined is refused when it is pasted again |
| Task 50 | Task 52 | The live probe, join seal step 4 of 4: every invitation the run carried is at version 3 and carries neither of |
| Task 51 | Task 53 | The open items file records what the join seal takes of MG-7, and what it settles |
| Task 52 | Task 54 | Run every mutant on the T1 tree |
| Task 53 | Task 55 | The reset, defined and checked |
| Task 54 | Task 56 | Live verification after the reset: the probe's 17 steps |
| Task 55 | Task 57 | Pre-merge review: the join seal design's round-2 prompts 3 to 7, and this plan's departures |
| Task 56 | Task 58 | The app's sentences and its pending mark (message-windows writer) |
| Task 57 | Task 59 | Close T1: the full run on both hosts, the ledger, the pull request, the final report |

**The measured phase ends, beside what they were.** Counts of `--- PASS` lines of a `-v` run in
a fresh worktree of each commit, under go1.26.5, with no race detector; no suite has a `--- FAIL`
line outside strict mode on any row. "As checked" is the run the checked plan quoted
(`lab-s0t1plan/out2.before-revision/verify/summary.txt`); "revised" is this revision's
(`out2/verify/summary.txt`, `v2/verify_all.sh`). The root module at the end of T1 is measured on
the last commit that changes a Go file, as it was before.

| | messagegroup | sdk | sdk/cp3b | strict: FAIL / PASS | root module with mls |
|---|---|---|---|---|---|
| the base, as checked | 359 | 308 | 81 | - | 2520 |
| the base, revised | 359 | 308 | 81 | - | 2520 |
| the end of S0, as checked | 359 | 308 | 106 | 17 / 8 | 2522 |
| the end of S0, revised | 359 | 308 | 106 | 17 / 8 | 2522 |
| the end of T1a, as checked | 361 | 319 | 109 | 9 / 16 | 2524 |
| the end of T1a, revised | 361 | 321 | 114 | 9 / 17 | 2524 |
| the end of T1, as checked | 362 | 337 | 114 | 3 / 24 | 2525 |
| the end of T1, revised | 362 | 339 | 119 | 3 / 25 | 2525 |

What moved, and why: the base and the end of S0 did not move, because their commits did not
change. T1a gains tests in `sdk` and in `sdk/cp3b` (R12's store, gate, restore and lock cases; the
row for a join code that is gone; the open item's reproduction) and one PASS in strict mode, which
is the new control. T1 carries the same additions through. All twelve T1 commits were applied
again behind the new T1a, with no conflict, and ONE of them was then changed by hand: the
member-side tests (Task 48), whose every-octet case met R13's new sentence. The first verification run
of the revised chain found that case failing on that commit and on the five after it, which is
how it was found; it is fixed in the commit that owns the case, and those six rows were measured
again.

**The revised chain on today's `main`.** `21 of 21 applied with git am --keep-cr (no --3way); hunks at an offset: 1; hunks with fuzz: 0`. Each applied tree differs from the lab's tree of
the same commit only in files `main` changed since the lab's base, and the one hunk at an offset
is hunk 3 of `test.sh` in the scan's commit, one line lower (`lab-s0t1plan/out2/apply-main.txt`,
`v2/apply_to_main.sh`).

**The three phase ends were run again on those applied trees**, with the same runner
(`v2/verify_all.sh` over `lab-s0t1plan/base/main-check`; `out2/applied/summary.txt`): gofmt, build
and vet, the layering gate, the three suites, the harness in strict mode, the probes' own tests and
the whole root module with `mls`. No suite has a `--- FAIL` line outside strict mode.

| On `main` plus the chain | messagegroup | sdk | sdk/cp3b | strict: FAIL / PASS | root module with mls | Equal to the lab's row |
|---|---|---|---|---|---|---|
| the end of S0 | 359 | 308 | 106 | 17 / 8 | 2522 | yes |
| the end of T1a | 361 | 321 | 114 | 9 / 17 | 2524 | yes |
| the end of T1 | 362 | 339 | 119 | 3 / 25 | 2525 | yes |

Every number on `main` plus the chain equals the lab's.


## The second check of the revised form (2026-10-12), and what was done with every finding

`_revcheck2_report.md`: no BLOCKER, two MAJOR, four MINOR, and no finding in the code of T1a or T1.
What it measured as holding, under go1.27.2 on `0bb2128f`: R12; the held-group gate, when another
group's record is damaged and when the group's own is; 19 of 19 new mutants killed, and the first
check's FX2, FX3, FX6 and FX9; every phase-end count equal to this plan's; `./test.sh` on `alt-2`
at the T1 tip with `-race` and `sdk/cgo`, and no data race; and the fork CI's provenance step. The
lead reproduced both MAJORs before ruling (`LEAD-RULINGS-2026-10-12.md`).

| Finding | What it said | Ruling | What changed |
|---|---|---|---|
| MAJOR 1 | The verdict rule at each phase close could not be met: a linux run always names the C consumer as a narrowing, and a host with no C compiler ends FAIL | R15 | R8 above; "Test commands"; Step 1 of Tasks 31, 40 and 59 |
| MAJOR 2 | The scan's tool, v1.1.4, cannot read go1.27's standard library on linux, so Task 59's gate failed for a reason the plan did not name | R16 | Task 29's script and its ruling paragraph; R6 above; Task 59 Step 4 |
| MINOR 1 | Task 29's first `test.sh` hunk no longer applies strictly on `0bb2128f`, and the plan said the chain applies cleanly | R17 | the Base row and "What was verified"; Task 29's blocks, cut from the S0 writer's commit |
| MINOR 2 | The text still described urnetwork/message#3 and #4 as ahead of it | R17 | the Order, Base and Compiler rows; R6; R11; "Test commands"; "What was verified"; the gates table; Step 2 of Tasks 31, 40 and 59 |
| MINOR 3 | The app's sentence for `ErrNoJoinCodeForInvite` is false when the store fails to read a join code it holds | R17 | Task 58's row |
| MINOR 4 | Task 29's releasing note names a `toolchain` line that only the root `go.mod` has | R16 | Task 29's `docs/RELEASING.md` text, in the S0 writer's commit |
| Not counted | The store's older words for a record the disk damaged | R17 | Task 57, question (f) |
