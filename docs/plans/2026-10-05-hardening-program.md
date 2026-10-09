# [Security Hardening — Seal the Join, Verify the Keys, Heal After a Compromise, Test the State Machine] Program Plan

> **For agentic workers:** this is a PROGRAM plan. It orders six tracks and states the gates each
> must pass. It is not executed step by step. Each track gets its own implementation plan in this
> directory, reviewed before any code is written, and that plan is executed with
> superpowers:subagent-driven-development (recommended) or superpowers:executing-plans.

**Goal:** Close the gaps that a check of two external AI reviews found real in URmessage's
cryptography as built, in the order the lead recommended and the owner adopted on 2026-10-05
(ledger item 280). The gaps:
- the epoch a join opens has no post-quantum protection, because the joiner's `pq_secret` is pasted
  in the clear;
- nobody can verify a key, so whoever controls the paste channel can substitute one unseen;
- nothing heals after a device is compromised;
- the test corpus checks the cryptography and not the group state machine.

The cheap documentation and hygiene fixes come first. When the program ends, each gap is closed by a
change whose simulation test was red on the tree before it and is green after it. The alpha runs the
result as a new package, and the owner has signed off.

**And it does not deliver a post-quantum MLS ciphersuite, deniability or post-quantum
authentication. That is the first paragraph rather than a footnote.**
- C6 keeps v1's MLS suite classical, and MASTER §7 (:1098) adopts a PQ suite once
  draft-ietf-mls-pq-ciphersuites is an RFC.
- No deniability: ledger item 232 declines the rework, and MASTER makes deniability a permanent
  non-goal (:554).
- Authentication stays Ed25519, under C6's classical suite.

A program that ships every track below and is then described as "post-quantum MLS" has been
misdescribed. What the program does buy is stated in S0.3's honest PQ statement, and nowhere
stronger.

**Architecture:** six tracks, in one order.
- **S0 lays the foundations every later track consumes:** the rulings on record, an adversary
  simulation harness that runs red on today's gaps, the quick fixes, and the missing state-machine
  vectors.
- **S1 and S3 change the protocol, and S2 builds one the spec already defines.** Each starts with
  a red team, and with a spec edit wherever the spec moves, before code.
- **S4 builds the cross-implementation checks** that Spec A has always required and the tree has
  never had.
- **S5 ships the result to the alpha** and closes the program with the owner.

This document orders the tracks and states their gates. The design of each track is its own plan's.

**Tech Stack:**
- Go 1.26.5, the Go that connect's, sdk's and this repository's go.mod pin, with the standard
  library and `golang.org/x/crypto`, as today. No new cryptographic dependency.
- Rust stable, on a test VPS or in CI only, for the OpenMLS oracle. It is never linked (C2).

---

## Status

As of the commit that adds this plan. Each track's progress lands as a ledger entry, and this table
moves in that commit.

| Track | What | Gate before it closes | Status | Reports to the owner |
|---|---|---|---|---|
| S0.1 | Record the rulings: ledger item 280, this plan, the report | a diff review of that commit | this commit | no |
| S0.2 | The adversary simulation harness: in process, N members by M devices, three adversary oracles | the test-methodology red team; red on today's gaps first | design in review | no |
| S0.3 | The quick fixes: the X-Wing pin docs, MASTER's PQ overclaims, an honest PQ statement, govulncheck and Dependabot, the `req_auth` KAT | a diff review; the KAT must fail under a seeded marshal change | design in review | no |
| S0.4 | The MLS state-machine vectors: the seven pending families, ValSem240 to 246 | each must fail for the right reason | design in review | no |
| S1 | Seal the join secret | red team, spec, simulation red to green, a live probe | design and red team running | yes |
| S2 | Safety numbers and TOFU | red team, a simulated key swap that must be caught, Windows screenshots | design and red team running | yes |
| S3 | Healing: a self-update cadence, X-Wing key rotation, keys at rest | red team, spec, a simulated stolen device and then healing | design and red team running | yes |
| S4 | OpenMLS main interop and differential state-machine fuzzing | must catch seeded divergences | design in review | yes |
| S5 | Ship to the alpha as a new package, then finalize with the owner | a live probe and an as-shipped smoke test | not started | yes, and the final sign-off |

The design work behind the "design" statuses is an ultracode workflow, read-only. Each track has a
designer, a red team and a revision that answers every finding. The three protocol tracks get three
red-team lenses each, and the testing track, which holds S0.2 to S0.4 and S4, gets one: a
test-methodology skeptic. Its output becomes the per-track plans.

---

## The rulings this program is written under

**The directive, verbatim** (ledger item 280, 2026-10-05, 04:58 UTC): "All of the above in best
recommended order. Focus on improving security, update me with tests on each major success and
finalize with me when all tasks are completed, use ledger system, ultracode and use simulation
tests. Use VPSs to your advantage, let me know if you need to install major changes on them or need
access or administrative help. Create new task list and update ledger as well"

**The audit ruling, verbatim** (the same answer): "Audit comes after the alpha is out. It’s
planned in our wider scope so don’t worry and move forward, we plan to use some of the best
auditors". So no track waits for an audit, and none is a substitute for one.

**What stays as it was:**
- **C6.** v1's MLS suite stays classical. MASTER §7 (:1098) adopts a PQ suite once
  draft-ietf-mls-pq-ciphersuites is an RFC.
- **Ledger item 232, and MASTER's permanent non-goal (:554).** No deniability: application
  messages are signed.
- **Classical authentication,** under C6's classical suite: Ed25519 credentials and signatures.
- **C2.** OpenMLS is an oracle and never a dependency.

**The VPSs.** The directive says to use them, and to tell the owner before installing a major change
on one, or when access or administrative help is needed. Two further test VPSs carry the heavy work:
go1.26.5 is on both, and Rust on one. The live message-server box carries none of it.

---

## The gates every track passes

1. **Its own plan, reviewed before code.** The plan is written in this directory, in this
   repository's plan shape. A subagent reviews it, and it lands with a ledger entry under
   SPEC-LEDGER.md §6, before any code of the track is written.
2. **A red team before the spec, for a protocol change.** S1 and S3 change what goes on the wire,
   into a record, or into a key. S2 builds a specified check, and its red team tests that design.
   The track's plan dispositions each red-team finding, accepted or rejected with evidence, before
   the spec moves.
3. **A diff review and a ledger entry for every spec or plan change**, in the same commit. The
   edit-log gate (`editlog_test.go`) holds the ledger half.
4. **One writer per repository.** Two tracks may run at once only when they write different
   repositories. A gate that reads a sibling repository counts as a writer of it while it runs,
   because a second writer there changes what the gate reads.
5. **Simulation tests: red before, green after.**
   - Each track's scenario runs on the tree before its change, and must FAIL there, for the
     reason the gap names.
   - It must pass after the change.
   - A scenario that passes on today's tree is not evidence of anything.
   - Each scenario carries a control: a mutation of the fix that turns it red again.
6. **A test-backed report to the owner at each major success.** It says what changed, which test
   was red and is now green, and how to see it: a live probe, or screenshots. This is the
   directive's "update me with tests on each major success".

---

## S0 — Foundations

### S0.1 — Record the rulings

Ledger item 280, its section 7 entry, this plan, and `docs/reports/2026-10-05-crypto-review.md`,
which is the evidence behind them. **Gate:** a diff review of that commit. **Status:** that commit.

### S0.2 — The adversary simulation harness

**What:** an in-process harness that drives real groups. N members, each with M devices, joining,
being removed and updating at random, through the production code paths rather than a
re-implementation of them. Three adversary oracles, each asserting what its adversary can do:
- **A passive recorder.** It holds every pasted code and every record the server stores, and it is
  allowed to break the classical layer, as a quantum adversary would. It asserts which epochs it
  can read.
- **A device-state snapshot.** A copy of one device's state at time t. It asserts which later
  epochs it can still read.
- **A paste-channel key swapper.** It substitutes a key package or an invite in transit. It
  asserts whether the substitution is noticed.

**Red first.** On today's tree the harness must fail exactly where this program exists to close a
gap, and each red scenario names the track that turns it green:
- the recorder reads the epoch a join opens (S1);
- the swap goes unnoticed (S2);
- the snapshot reads after the next commit (S3).

**Gate:** the test-methodology red team. It looks for vacuous passes, narrowing filters, line-ending
anchors that match nothing, oracles that agree because they share a bug, and simulations that
assert nothing.

**Where it lives** is its plan's decision. It must reach the sdk's group, invite and record code.

### S0.3 — The quick fixes

- **The X-Wing pin docs.**
  - Spec A's A-ASSUME-3 (:72) says draft -06.
  - Spec A §5.4's table (:1687) puts the label first in the combiner.
  - MASTER (:884) names no version.
  - The code pins draft-10's vectors, byte-identical from -05 to -11, and puts the label last
    (connect `messagegroup/xwing.go:90-96`, `mls/interop/PINS.md:83-106`).
- **MASTER's PQ overclaims.**
  - §13 (:3302-3305) says "Post-quantum protection for stored messages", with neither the join
    epoch nor the static key as a caveat.
  - §7 (:879) still says the combination makes "an adversary must break **both**", which is M-5's
    clause 2 (ledger item 153).
- **An honest PQ statement**, public, in the G4 style. What is post-quantum and against whom, and
  what is not: the join epoch, until S1; healing, until S3; authentication, always, under C6.
- **govulncheck and Dependabot** for connect, sdk and this repository. None of the three has
  either. gorilla/websocket parses unauthenticated input on this server's public :443
  (`endpoint/endpoint.go:49`).
- **The `req_auth` KAT.**
  - Both ends marshal the request with protobuf's deterministic option (sdk
    `urmessage/record.go:246`, `:269`; `api/fetch.go:250`), and protobuf does not promise that
    output across languages or versions.
  - connect already pins the framing and the tag over raw request octets
    (`message/writeauth_test.go:457`, `:509`).
  - What is missing is a known request pinned to its known bytes, for every request type that
    carries a `req_auth`.
  - If the plan proposes a canonical preimage instead, that is a protocol change, and gate 2
    applies.

**Also owed, found while writing this program.** The S0.3 plan decides whether it takes them:
- MASTER §14 (:3417-3420), MASTER §15 item 7 (:3468-3474) and owner decision #25 still read the
  audit as a decision taken at slice 5. Ledger item 280 records the ruling.
- MASTER §7 (:874-877) cites draft-ietf-mls-pq-ciphersuites-01 and draft-ietf-mls-combiner-02. The
  first is at -06, and the second has expired.

**Gate:** a diff review. The KAT must fail under a seeded change to the marshal, such as a reordered
field or a default written out.

### S0.4 — The MLS state-machine vectors

- **The seven pending families.** connect's registry has no runner for families 2, 8, 9, 13, 14, 15
  and 16 (`mls/vectors_test.go:110`). Among them are tree operations, the Welcome, and the three
  passive-client families, which are the published corpus that exercises the group state machine.
  This is ledger item 162's acceptance half. Two of the seven are partly covered outside the
  registry: 16's runner exists in `mls/syntax` and is not installed, and
  `mls/crypto_labels_test.go` checks 2's constructions.
- **ValSem240 to 246.** No test names them. The 29 `TestValSem` tests cover other codes.
  - Spec A (:884-889; six codes, since there is no 243) expects `ErrProfileExternalCommit`. The
    code refuses the new_member_commit sender earlier, with `errProcessSenderType`
    (`mls/commit_process_test.go:871-877`).
  - S0.4 maps the existing tests to Spec A's table and settles which sentinel is right.

**Gate:** each must fail for the right reason. A seeded defect per family must be caught. A runner
that declines cases says how many it compared, and a count of zero is a failure, not a pass.

---

## S1 — Seal the join secret

**The gap.**
- The joiner's `pq_secret` travels in the clear in the pasted invite (sdk
  `urmessage/invite.go:45-51`, `:88`; `urmessage/pqepoch.go:1383`).
- The Welcome's HPKE is X25519 (connect `mls/hpke.go:214`).
- So a recorder of both pasted codes, with a future quantum computer, reads the epoch the join
  opens. For a two-person chat that never commits again, that is the whole chat (ledger item 266).

**The candidate** is the lead's recommendation, and the red team decides:
- Seal the joiner's `pq_secret` to the X-Wing public key its KeyPackage already carries, in leaf
  extension 0xF002 (connect `mls/extension.go:87`). XMTP seals Welcomes this way.
- The design also weighs an immediate post-join commit, which gives the first epoch after the join
  a fresh sealed secret.

**What the design must also answer:**
- the wrap's signature (open item M1-52);
- binding the sealed secret to the Welcome, the group and the epoch, against replay across invites;
- what the joiner checks, and what it does when it cannot open the seal;
- invites already in flight, and mixed versions on the live alpha.

**Gates, in order:**
1. the red team;
2. the spec edit;
3. simulation red to green: S0.2's recorder reads the join epoch on today's tree, and cannot after;
4. a live probe on the alpha deployment;
5. the report to the owner.

---

## S2 — Safety numbers and TOFU

**The gap.**
- Joins are unauthenticated (ledger item 266).
- Join codes and invitations are pasted over an outside channel (ledger item 265). The server and
  the operator never carry a key package, so they cannot substitute one, but whoever controls that
  channel can. The user has nothing to compare against.

**The spec exists**, and none of it is built:
- MASTER §10.2 (:2994-3024), Spec A §7.6 (:4621), and Spec C's screens 16 to 18 (:307-309);
- the sdk has no safety-number API;
- the Windows app shows a key-change record only in its demo data.

**What the design must answer:**
- which keys the number commits to: the credential's signature key, the device's X-Wing key, and
  every device of a member with several;
- where a change is detected: the join code, the invite, a key package, a leaf update, a new device;
- the blocking warning, and the honest copy;
- how S3's key rotation avoids raising a false alarm.

**Gates, in order:**
1. the red team;
2. the spec edit, where the existing spec needs one;
3. a simulated paste-channel key swap that must be caught: S0.2's swapper goes unnoticed on today's
   tree, and is caught after;
4. Windows screenshots, captured with PrintWindow only;
5. the report to the owner.

---

## S3 — Healing

**The gap.**
- The device X-Wing key is minted once (sdk `urmessage/device.go:513-555`), and an update
  re-encodes it (connect `mls/group.go:1800-1803`).
- Each wrap is a PERMANENT record (sdk `urmessage/pqepoch.go:1556`), so whoever later obtains that
  key opens every wrap ever addressed to it.
- Nothing sends a self-update (ledger items 266 and 270).
- Every key is on disk in the clear, protected by file permissions alone, and on Windows, where the
  alpha runs, only by the ACL of the directory the caller chose (sdk
  `urmessage/statestore_durable.go:29-50`; ledger item 229).
- So a copied device state keeps decrypting until that device is removed.

**Scope:**
- **A self-update cadence.** A commit with an update path from each device, on a timer, a message
  count, or an event.
- **X-Wing key rotation** inside that update, in leaf extension 0xF002. The design says what
  rotation does to the wraps, `storage_root`, recovery, and the `eph_root` wrap (ledger item 185).
- **Keys at rest on Windows**, with DPAPI. This is ledger item 229. The sdk's own comment files it
  as S2-24, an id that resolves to a different item; ledger item 229 says to cite it instead.
- **The honest limits.** An attacker active during the healing commit. The 33 epochs a device
  keeps. What post-compromise security against a quantum adversary means while MLS stays classical.

**Gates, in order:**
1. the red team;
2. the spec edit;
3. a simulated stolen device, then healing: S0.2's snapshot reads after the next commit on today's
   tree, and stops reading after the healing update;
4. the report to the owner.

---

## S4 — OpenMLS main interop and differential state-machine fuzzing

**The gap.**
- Spec A §4.2 (:677) and §4.4 (:953) require the mlswg interop harness, in both roles, and
  differential fuzzing against OpenMLS's nine targets.
- The interop peers' image digests are placeholders (connect `mls/interop/PINS.md:21-23`), and
  nothing has ever run.
- C7 records why the vectors alone are not a gate.

**The oracle is OpenMLS main, at or after `ff94cdc2b0`, and never 0.9.0.** That is the lead's
ruling, and its reason has a scope.
- **Any cross-check that runs X-Wing inside HPKE needs main.** 0.9.0 derives X-Wing keys the way
  the IETF draft is replacing, and main takes the labeled derivation from that commit on. The split
  is in the report's section 4, and its reproduction in ledger item 280's section 7 entry.
- **S4's own runs do not need main.** The interop harness and the differential fuzzing run our one
  suite, 0x0003, whose HPKE is X25519 only (connect `mls/hpke.go:214`), so 0.9.0 would serve there
  as well. Main is chosen so that one oracle serves both, and S4's plan pins its commit in
  `mls/interop/PINS.md`.
- **0.9.0's side can move.** OpenMLS asks for hpke-rs `0.7`, so a 0.7.x release with the labeled
  form would change what a fresh resolve of 0.9.0 gets. A pinned commit, built with its lockfile,
  does not move.

**Where it runs:** on CI, or on one of the two further test VPSs, never on the message-server box.

**Gate:** it must catch seeded divergences. A deliberately broken build of ours is the positive
control, and every fuzz target reports how many inputs it compared.

---

## S5 — Ship to the alpha, then finalize with the owner

- **A new package after 02d**, built the way its README says, and smoke-tested as shipped: the
  extracted zip, no flags, a fresh root.
- **A live probe** on the alpha deployment.
- **The owner's sign-off** on the whole program.

**S5 meets an open item of ledger item 279:** the alpha still ships `alpha/premerge` (ledger item
277's ruling). Either the alpha moves to the forks' mains first, or the hardening also lands on that
branch. S5's plan decides, and the owner rules if it is a choice between the two.

**Gate:** the live probe and the as-shipped smoke test, then the final report and sign-off.

---

## Order, and what may run in parallel

1. **S0.1 first.** It is the commit that adds this plan.
2. **S0.2 before any track's simulation step**, because the simulations are its scenarios.
   - S0.3 and S0.4 can run beside it where they write different repositories.
   - S0.3 writes this repository's specs, CI files in three repositories, and wherever its KAT
     lands.
   - S0.4 writes connect's tests.
3. **S1, then S2, then S3.**
   - S1 and S3 both change the wrap path in sdk and connect, so they cannot share a writer.
   - S2's sdk and app work can follow S1 as soon as S1's sdk half lands.
   - Their designs and red teams already run in parallel, read-only.
4. **S4 beside S1 to S3**, on CI or a test VPS. Where it writes connect's `mls/interop`, it takes
   its turn as connect's one writer.
5. **S5 last.**

---

## Where the per-track plans go, and one naming trap

Each track's plan is `docs/plans/<date>-hardening-<name>.md`, for example
`2026-10-06-hardening-join-seal.md`.

**Do not put a `-s1-` segment, or any `-p<n>-`, `-s<n>-` or `-m<n>-` one, in the file name.**
- The plan linter reads `-((?:p|s|m)[0-9]+)-` out of a plan's file name as its token
  (`planlint_test.go:158`).
- `s1` and `s2` already name the sdk-surface and submit-leg plans.
- A second document with the same token takes over the references to it.

---

## What this program does not do

- **A PQ MLS ciphersuite.** It is deferred by C6. When it comes, Go's `crypto/hpke` has the hybrid
  KEM, as a test oracle.
- **Deniability** (ledger item 232), or post-quantum authentication.
- **Key transparency.** It is specified in MASTER §10.1 and Spec B §9.4, and it gates general
  availability, not the beta. Until it exists, S2 is the defence against a substituted key.
- **An external audit.** It comes after the alpha (ledger item 280).
- **Formal models.** One reviewer suggested a machine-checked proof. It is not in the adopted list,
  and this program does not add it.
