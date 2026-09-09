# URmessage — Top Spec Ledger

The single document that contains everything: current state, every locked decision and why, the
revision history, open items, and an append-only edit log.

**If you read one file, read this one.** The protocol spec in `docs/specs/` is the normative
document; this ledger is the map, the reasoning, and the audit trail.

---

## 1. Current state

**Protocol design at revision 9**, with errata E1–E3 fixed and four dated amendments on top of it.
Group key agreement is MLS (RFC 9420), implemented in Go. Storage, retention, deletion, recovery, and
identity verification are ours. v1 targets one operator, one message server, many providers.

**Code exists, and this paragraph said the opposite for five weeks.** It read *"Nothing is implemented
yet. No code exists."* from the repository's first commit until 2026-09-07, across a `connect` tree of
**1,105** tracked files and **7,631** passing tests and a message server in this repository of **57**
Go files and **26,402** lines. It was named as stale by the 2026-09-07 pass that ruled M1-6 and left
standing because it fell outside that pass's derived class; the ruling below is the pass that repaired
it. What is true today: **`connect/mls`, `connect/message` and `connect/messagegroup` are m1 wave 1
plus ruling A1**, on `beta/message` at `33932e0`; **this repository's message server is shipped and
under test** — `store/`, `api/`, `peer/`, `blobd/`, `sweep/`, `cmd/`; and **`sdk` holds no messaging
code at all**, which is the gap every external leg in the m1 plan points at.

| Item | State |
|---|---|
| MASTER protocol design | Revision 9, **six** amendments — 2,249 lines. The sixth is 2026-09-09: §7 and §8.2 gain the wrap body's grammar, its signature preimage and its padding, ruled as composite `C3` |
| Spec A — protocol / sdk / connect | Revision A-22 — 5,618 lines |
| Spec B — message-server / operator | Revision 18 — 3,587 lines |
| Spec C — Windows client UI | Revision 6 — 1,893 lines |
| Blockers | **0 from r1–r4** — down from 41. **r8's two are not in that count**; both are fixed in the text and neither is recorded as fixed. Item **165**. |
| Review findings | **Dispositioned per finding in §5, not counted.** r3's twelve blockers were re-grepped by id; its fourteen remaining majors are items **149–162**, one item per id, each opening with the id and a disposition verb, so `git grep "M-7"` returns a disposition rather than silence. **r2's, r3's and r4's minors, r6's 30 and r8's 25 are NOT dispositioned** — item **165** measures that and publishes the query; those findings carry no ids, so an id-keyed gate cannot see them at all. The count this row used to carry (*"30: 8 major, 22 minor"*) was r6's file, not r3's majors, and the two had been read as one set for five weeks. |
| Implementation plan | **Written and part-executed.** Fourteen documents in `docs/plans/`; `m1` (24 tasks) has wave 0 and wave 1 landed and is stopped in front of wave 2 by ledger **152** — **and by nothing else, since 2026-09-09**, when the owner ruled `M1-1`'s remainder and `M1-7` together as composite `C3` (item **175**), closing items **176**, **177** and **179** with them. **`s2` is now written** — 15 tasks, of which Tasks 1–12 are the CP3b prefix — and its own first paragraph states that it does **not** reach CP3b alone: four upstream `connect` blockers (**S2-1** through **S2-4**) sit outside both of its legs and none of the four has an owner. `s3` through `s10` are still cited as owners of unwritten work and have no document. |
| Code | **`connect` `beta/message` at `33932e0`** — 1,105 tracked files, 217 Go files across `mls/`, `message/` and `messagegroup/`, 7,631 tests passing / 0 failing / 0 skipped, nine-platform `CGO_ENABLED=0` build green. **This repository** — 57 Go files, 26,402 lines, `go build ./...` and `go test ./...` green. **`sdk`** — nothing; six external legs wait on it. |

**Ready for owner review, and for handoff once the owner has read them.** Four review rounds and two
edit passes have taken this from 41 blockers to none. What is left is not a count: r3's fourteen
undispositioned majors now carry one ledger item each (**149–162**): **four** are ALREADY SATISFIED
or SUPERSEDED (M-2, M-8, M-12, M-13) and **ten are STILL OPEN**, every one of the ten needing an owner
ruling and **nine of them blocking the A6 wire-format freeze** (all but M-14). Two further instances of
M-15's class are filed as items **163** and **164**, the second of which also blocks A6. And the
findings in `docs/reviews/` that carry no identifier at all are still undispositioned (item **165**).

What no review can supply: whether the *product* decisions are the ones the owner wants. Every
finding to date has been internal consistency, cryptographic soundness, or implementability. Nobody
has checked the specs against intent.

## 2. Document map

```
SPEC-LEDGER.md              this file — decisions, history, edit log
README.md                   what the message server is, and its status
LICENSE                     MPL-2.0, matching the rest of the URnetwork projects
docs/specs/                 normative protocol design
docs/plans/                 implementation plans, one per slice
docs/reviews/               adversarial review verdicts (the evidence behind the decisions)
```

`docs/reviews/` is kept in the repo deliberately. Half the decisions below exist because a review
found a defect, and the reasoning is worthless without the finding that produced it.

## 3. Locked decisions

Each was chosen explicitly by the project owner. Changing one requires a ledger entry saying why.

### Product

| # | Decision | Reasoning |
|---|---|---|
| P1 | Target: *"slightly better than Signal, not as insane as SimpleX, kinda like Matrix but better"* | Hard constraint, not a slogan. Resolves arguments: a weakness Signal also has is acceptable; being worse than Signal is not; metadata resistance that costs usability is rejected. |
| P2 | One protocol — a DM is a 2-member group | Avoids two encryption paths forever. What MLS and Matrix converged on. |
| P3 | v1 scope: text, groups, full multi-device, disappearing messages, safety numbers, reactions, receipts, attachments | Owner chose the full set knowing it enlarges v1. |
| P4 | Group size **design target** 500 (not an enforced cap) | TreeKEM is O(log n); the practical limit is Welcome size and client memory. |
| P5 | Windows client first; `connect`/`sdk` stay cross-platform | Other clients follow; platform notes written as Windows surfaces them. |

### Cryptography

| # | Decision | Reasoning |
|---|---|---|
| C1 | **Group key agreement is MLS (RFC 9420)** | Two bespoke drafts (revisions 1–2) drew 10, then 12 blocking defects. RFC 9420 ships component-level test vectors, so correctness becomes pass/fail. Revision 3's review found **zero** defects in key agreement. |
| C2 | Implement MLS ourselves in Go; **OpenMLS is the reference oracle, never a dependency** | Settled by measurement, not preference. **OpenMLS exposes no C API at all** — a full-tree grep for `no_mangle\|extern "C"\|cbindgen\|uniffi` returns one hit, a `wasm_bindgen` block *importing* JS. So depending on it means authoring and forever maintaining the entire FFI surface of a stateful group-crypto library as its first Go consumer in existence. Worse, `StorageProvider<const VERSION: u16>` (62 methods, const generics) **cannot cross a C ABI**, so Go could not own key persistence — private keys would live in an opaque Rust store unreachable for DPAPI sealing or zeroization. For a key-custody messenger that is a contradiction, not a cost. Wire is the natural experiment: the only funded team to attempt this forked and froze against upstream churn, which destroys the very rationale (audit, security fixes, PQ suites) that justified depending on it. |
| C6 | **Post-quantum is at-rest only for v1**; classical MLS ciphersuite | Deferring PQ is safe *except* where today's choice permanently exposes today's data. Harvest-now-decrypt-later makes stored ciphertext the one irreversible case; transit PQ is already free via connect, and MLS has ciphersuite agility so a PQ suite can be adopted later. The at-rest wrap is also the cheap part — one X-Wing wrap of 32 bytes per epoch per member, not TreeKEM. |
| C7 | **"The test vectors pass" is NOT a sufficient acceptance gate** | Measured: the 16 IETF vector families are ~6,158 lines against 40,181 lines of behavioural tests inside OpenMLS — ~13% of the corpus — and they exercise **none** of the 43 ValSem validation codes. Six OpenMLS defects from 2026 each pass 100% of the vectors. The real gate is in spec A: narrow v1 profile, the mlswg gRPC interop harness in both roles, negative tests for all 43 ValSem codes, differential fuzzing, a swappable interface, and a funded external audit before any non-beta user. |
| C3 | Hybrid KEM is **X-Wing** (X25519 + ML-KEM-768) | Replaced a hand-rolled combiner that drew a finding in every review round. A construction with a security proof at Level 3 beats a hand-rolled one at Level 5. |
| C4 | ML-KEM-1024 revisited when draft-ietf-mls-pq-ciphersuites becomes an RFC | Algorithm identifiers make it a ciphersuite swap, not a format break. |
| C5 | Ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` | ChaCha20 over AES-GCM to avoid AES-NI assumptions on ARM64. |

### Identity and trust

| # | Decision | Reasoning |
|---|---|---|
| I1 | URmessage generates its **own** BIP39 seedphrase on-device, never transmitted | The existing URnetwork seedphrase is a **password** — `auth_model.go:168-169` sends it plaintext to the operator on every login. Reusing it would hand the operator every private key. |
| I2 | A URnetwork account **is** required | `CreateContract` needs a `ByJwt`. Only the *SSO link* is optional, not the account. |
| I3 | Operator authorizes and routes; never reads, **never stores** message records | Enforced by grammar: no MLS proposal or commit is valid on an operator signature. |
| I4 | Verification is **SSH-style local TOFU**; nobody verified by default, no badge | Warn loudly only when a key changes from one already pinned. A badge without a warning would be worse than Signal's silence. |
| I5 | Key transparency required, not optional | `auth_model.go:125-153` attaches SSO auth by matching `user_auth`, so control of a Google/Apple account is control of the identity — and the operator would be *honestly* vouching for the wrong key. |
| I6 | Seed loss → operator resets identity; history is lost; admins must re-add | Auto-readd would be the key-substitution attack we defend against. |

### Topology and storage

| # | Decision | Reasoning |
|---|---|---|
| T1 | v1 is **one operator, one message server, many providers** | Removed the read-through proxy, per-epoch handle rotation, and per-device capabilities — the three mechanisms behind most remaining defects. |
| T2 | Multi-server is V2; `server_id` fields retained | Not a format break when it lands. |
| T3 | Group migration deferred to V2 | Consequence, stated in the spec: if the host is lost, groups are lost. |
| T4 | Owner is sole authority and delegates admins; **no quorum for normal operations** | Matches consumer expectations. Owner-only: history grants, admin-set changes, ownership transfer. **Owner succession is the single quorum exception** (spec §11): a majority of admins must countersign that the owner is unreachable, after a 30-day floor — otherwise owner seed loss would freeze the admin set permanently. See open item 3. |
| T5 | Retention split: text durable, **media 1 month**, server-advertised cap default 100 MB | Media is most of the storage and little of the value after a month. |
| T6 | Disappearing messages off by default; receipts and typing **on** by default | Signal parity; ephemeral class, never persisted. |
| T7 | Cover traffic built into the format, exposed as a setting, **off** by default | Costs constant bandwidth and battery; must run independently of real sending or it leaks anyway. |
| T8 | Stream digests, per-device write capabilities, editing, voice/video, public groups → V2+ | Type codes reserved so none is a format break. |
| T9 | Windows messaging client is a **separate app** from the VPN client, sharing the full SDK, connect and backend; optionally installed via the same installer, not by default | Different shapes of program — the VPN client is a tray utility, a messenger is a foreground app. Messaging bugs cannot take the VPN down, and release cycles decouple. |
| T10 | **No administrator tunnel.** The messaging client forwards message traffic only | Removes the entire class of machinery behind most of the VPN client's hard bugs: no privileged service, no WFP filters, no wintun adapter, no LocalSystem process, no mTLS loopback RPC, no two-phase teardown. A normal user-mode app talking to a DLL. |
| T11 | Message server on **PostgreSQL** (pgx/v5), matching the operator | Reuses migration patterns, connection handling, and ops knowledge. Records are a natural relational fit; the operator already runs Postgres and Redis. |
| T12 | Protocol code on a new **`beta/message`** branch of the connect and sdk forks | Parallel to beta/algorithm-dpi and beta/custom-server. One workspace, one replace-directive layout, direct access to connect's transport and identity. |
| T13 | A new **`URmessageSdk.dll`** (cgo c-shared), separate from `URnetworkSdk.dll` | The messaging client links only what it needs and shipping VPN builds are untouched. |

## 4. Revision history

| Rev | Change | Blockers found |
|---|---|---|
| 1 | First full design: bespoke group crypto, epoch keys, admin-signed membership, per-group pseudonyms | 10 |
| 2 | Fixed r1 blockers; unified the record format (the two-plane split was demoted to a client-side namespace, not a server-visible one) | 12 |
| 3 | **Deleted the bespoke crypto layer; adopted MLS** | **0 in key agreement**, 12 elsewhere |
| 4 | Narrowed to single-server; simplified storage; corrected MLS contract; added invariants (§3) | — |
| 5 | Adopted X-Wing; OpenMLS as oracle | — |

**The lesson, recorded because it keeps being relevant:** every hand-rolled cryptographic
construction in this project drew a finding in every review round it existed. Every one we replaced
with a standard stopped generating findings immediately. One hand-rolled composition remains — the
`HKDF-Extract(salt = mls_secret, ikm = pq_secret)` combination in §7 — and it follows
draft-ietf-mls-combiner and matches Signal's PQXDH/SPQR shape.

**Corrections worth remembering.** The three the spec's §0 records, all against revision 3:

- Claimed MLS resolves concurrent commits. False — RFC 9420 gives fork *detection*; RFC 9750 §5.2
  assigns agreement to the Delivery Service. Corrected in spec §9.3.
- Assumed an MLS exporter output could regenerate sibling secrets. RFC 9420 §8.1 makes them
  independent derivations. Corrected in spec §8.2.
- Asserted a credential check RFC 9420 §7.3 does not perform. Corrected in spec §6.

Two earlier ones, recorded here rather than in the spec because the design they applied to no longer
exists — sourced from the reviews in `docs/reviews/`, not from §0:

- Per-group pseudonyms were claimed to give cross-group unlinkability. False — the key-agreement key
  was global, so it appeared in every group's log. A database join, not a statistical attack.
- Content was claimed to be unchainable because it must be pruned. False — Matrix solved this in 2015
  by hashing the redacted form (`docs/reviews/2026-08-12-r1-design-redteam.md`).

## 5. Open items

1. Retention floor negotiation when a group policy exceeds the server's advertised minimum.
2. Push transport — WNS for Windows; APNs/FCM when mobile lands. No push exists in the operator today.
3. Owner succession residual risk: a colluding admin majority can displace a merely-offline owner.
4. `OWNER_SUCCESSOR_SET` placement — group-context extension is likely right.
5. Moderation recourse — deferred by decision; revisit with legal counsel before public launch.
6. `SubscribeRequest` carries N `group_id`s but one `req_auth` and one `read_epoch`, while §5.1.1's
   read-key lookup is written in the singular and does not say which group's key verifies the MAC.
   Pre-existing, found 2026-08-25 while fixing the `UnsubscribeRequest` gap, and out of scope for
   that fix. Needs a Spec B ruling before Subscribe is implemented.
7. §12.1 says "A test in the message-server repo asserts the allowlist" and no such test exists. The
   surface has now been widened twice by implementation feedback (A-9, A-10) with nothing mechanical
   holding the two documents and the code together, which is the same shape as every other gate on
   this project that turned out to be a sentence rather than a check. Found 2026-08-26.
8. **§4.5 has no reason code for "this build does not implement this operation."** Eleven of §4.3's
   fifteen `oneof` arms are served by nothing yet, and the two candidates are both wrong:
   `REASON_REJECTED` has a specific normative meaning a client acts on by re-MACing and retrying, and
   `REASON_RATE_LIMITED` would claim the §4.7 limiter that §5.1 check 4 declares absent.
   `REASON_INTERNAL` is what shipped. §4.5 should name a code. Found 2026-08-26 by `peer/`.
9. **§4.6 names a reason code for one of its four abort conditions.** The reassembly cap gets
   `REASON_OVERSIZE`; a zero `count`, an out-of-order `index`, and the sixteen-per-client concurrency
   cap get none. Found 2026-08-26 by `peer/`.
10. **§4.3.1 gives a connection no lifetime**, so the live-connection map holds an entry per
    `client_id` that ever said `Hello` and never shrinks — a memory bound chosen by anyone who can
    address a frame. §4.6 bounds reassembly at 30 s; a connection has no equivalent number anywhere.
    The implementation takes a configurable idle sweep and declares the bound missing when nobody
    configures one, which is a mitigation rather than a default. Also unstated: what an **empty**
    `supported_versions` in `HelloRequest` means. Found 2026-08-26 by `peer/`.
11. **§2.2 does not say whether allowing a package allows the modules that package cannot compile
    without.** Linking `connect`'s root — which §4.2's binding *is* — put ~204 packages from 31
    modules into the binary §2.3 deploys: quic-go, all of pion, gvisor's netstack, gorilla/websocket
    and four `golang.org/x` modules, none of which §2.2 mentions. `go.sum` went from 4 lines to 80.
    The dependency gate now derives the permitted closure from `connect`'s own `go.mod` rather than
    from thirty hand-typed paths, but §2.2 should state the rule instead of leaving it to be inferred
    a second time. Found 2026-08-26 by `peer/`.
12a. **CLOSED 2026-08-27.** The escape analysis was refined from "calls something foreign" to "hands
    something foreign what it reaches" and pointed at the tree's `nodes` and `ratchets` maps, as
    `TestNoDeclarationReachingTheSecretTreeStoragePutsItBeyondTheCall`. Both package-scope archive
    shapes now fail it — the one at the descent's zeroize and the one at `(*ratchet).step` — and the
    trade this fix risked did **not** happen: G6's two batch-C escapes, `copy()` into package storage
    and a callback through a package-level `func` variable, were re-applied to `epochSecret` after
    the refinement and both still fail. Verified by the controller by hand, not by report. The
    original finding follows.

    **The secret tree's forward secrecy was gated at type scope, and a package-scope copy escaped
    it.** `TestSecretTreeParentSecretIsGoneOnceBothChildrenExist` asks what remains reachable through
    `*SecretTree`, which is the right question about the type and only about the type. A copy taken on
    the way past and parked in a package-level variable answers it exactly as a correct tree does.
    **Measured on the shipped code, not supposed:** a two-line archive beside the `zeroize`, declared
    at package scope, passes all 750 tests of `connect/mls`. The fix is to point G6's derived escape
    analysis — now generalised over its storage field in `13ffff4` — at the tree's `nodes` and
    `ratchets` maps. It is not landed because that analysis treats *any* foreign callee as an escape,
    which is right for `KeySchedule` (which calls nothing foreign) and wrong for `SecretTree` (which
    holds a `sync.Mutex`), so it reports eight false positives on correct code. Refining "calls
    something foreign" to "hands something foreign what it reaches" changes the analysis that the
    epoch-secret control validates, and doing that quickly enough to weaken a working gate is worse
    than a recorded gap. Found 2026-08-27 by the controller. **Owner of the fix: p4's remainder or
    p5, whichever touches `secret_tree.go` next.**
12b. **Measured 2026-08-28, on the owner's question about workflow wall clock.** The `mls` package is
    **774 test functions, ~57 s per full run, with zero `t.Parallel()` calls on a 24-core box** — it
    uses one core. Compile and link account for only 1.8 s of that, so it is genuinely execution.
    **Parallelising is not the fix**: `t.Parallel()` tests are held until every serial test finishes,
    so parallelising a subset changes nothing (measured: 57.7 s after parallelising the 54 tree-math
    tests, against 57.2 s before), and parallelising all 774 is a large, flake-prone change to a suite
    whose green runs are the project's primary evidence. **The fix is how mutations are run.** A
    targeted `-run` costs **1.8 s** against the full suite's **56.6 s** — 31×, and 1.8 s is the
    compile floor, so a targeted run is nearly free. Briefs now mandate two-phase mutation testing:
    a targeted run first, the full suite only when the targeted run passes and the mutation is a
    survivor candidate. Twenty mutations go from ~20 minutes to ~3. Applied to all twelve brief
    templates. **Not done and not needed yet:** parallelising the suite itself. If wall clock becomes
    a problem again, that is the next lever, and it should be done deliberately with a flake budget
    rather than opportunistically.
14. **CORRECTED 2026-08-29: this is p7's, not p6's.** The original entry said p6 owed it, on the Task 21
    agent's inference. **p6 is pure framing** — twenty tasks of codecs, preimages and vector families —
    and it never processes a Commit against group state, so it has no tree and no sender-leaf binding
    and structurally cannot make this check either. The owner is **p7 Task 10 (commit validation,
    ValSem200–209) or p7 Task 18 (commit processing, RFC 9420 §12.4.2)**, whichever holds the sender's
    leaf index at the point the UpdatePath is verified. Verified by reading both plans' task lists
    rather than by taking the entry at its word — an obligation filed against the wrong plan is one
    that gets skipped, because the named plan finishes without it and everyone assumes it was done.
    **p7's plan does not mention it either**, so this record is the only thing carrying it.

    **The obligation itself, unchanged: the UpdatePath leaf's SIGNATURE must be verified, and
    `MergeUpdatePath` cannot do it.** The merge
    compares the recomputed parent-hash chain against the leaf's `parent_hash` field, and **that
    comparison is only worth anything because the leaf's signature covers the field**. Verifying that
    signature needs the group id and the sender index, which live in the commit-processing layer, so
    the merge cannot do it. It is written into the method's own doc comment as well as here, because
    a cross-layer check both sides assume the other makes is a check nobody makes — a shape this
    project has already hit once, on §5.1's front checks. **p6 must verify it before calling merge.**
    Found 2026-08-29 by p5 Task 21.
15. **MEASURED 2026-08-29, and the time is fine while the allocation is not obviously fine.** At the
    real design target — 500 members x 2 devices, which is a **thousand-leaf** tree, not the 500 the
    plan benchmarked — `MergeUpdatePath` costs **17.1 ms, 56 MB and 307,744 allocations** per merge;
    the `VerifyParentHashes` sweep inside it is **14.9 ms, 49 MB, 264,535 allocations** over 999
    parents. **17 ms is affordable.** 56 MB of allocation per commit is a mobile memory-pressure
    question rather than a latency one, and it is the number to watch when the Android and iOS clients
    land — decision 64 makes those a commitment. The plan's own Task 28 Step 3 proposed memoising the
    sweep on the grounds it would exceed a 2-second bound; it does not, by two orders of magnitude, so
    that optimisation is **not** taken and the rule stays whole. If allocation later forces a change,
    open item 15's original constraint still binds: any narrowing must be **derived from what the
    merge touched**, never a hand-written node list, or decision 68's hole returns. Original finding
    follows.

    **The sweep was unmeasured, and the plan's own benchmark could not have measured it.** Its fixture
    was `newTestTree` plus ONE commit — **nine** non-blank parents out of 511 — so it reported 1.36 ms
    where the tree a running group actually has reports 7.34 ms, and it used 500 leaves where the
    design cap is 1000. Its bound assertion was `elapsed > 2*time.Second` and nothing else, so a
    `VerifyParentHashes` returning nil unconditionally would have passed it.
    One `ParentHash` and one original-subtree tree hash per arm of every non-blank parent — roughly
    1,000 nodes with two arms each at the 500-member target. p5 Task 28's benchmarks are where this
    gets measured. **If it must be narrowed, the narrowing has to be DERIVED from what the merge
    touched, never written as a list of node indices**, or decision 68's hole comes straight back.
    Found 2026-08-29 by p5 Task 21.
16. **p8's landing commit must swap 21 sentinel names across at least nine files, at once.** Since p4
    Task 13, tasks have been landing error sentinels **unexported** because p8's plan declares their
    exported spellings — `errDuplicatePsk` waiting for `ErrDuplicatePsk`, and so on. Each task recorded
    the count it knew about: three after p4, five after p5 Task 21. **Derived on 2026-08-30 rather than
    counted, the real figure is 21** of the 46 unexported `err*` sentinels in `mls` non-test source:
    errApplicationMustBeCiphertext, errBadMembershipTag, errBadSignature, errBlankSenderLeaf,
    errDecryptFailed, errDuplicateEncryptionKey, errDuplicatePsk, errDuplicateSignatureKey,
    errMissingConfirmationTag, errMissingMembershipTag, errMissingRequiredCapability,
    errNonZeroPadding, errPathDecrypt, errPathKeyMismatch, errPathLength,
    errProfileCredentialType, errPskNonceLength, errPskType, errTrailingBlankNodes, errWrongEpoch,
    errWrongGroupId. **`errNilLeafOccupancyTest` is NOT one of them** — it is an internal argument
    guard with no exported twin and must not be swapped. p8 should plan for a single mechanical
    commit across nine-plus files rather than discovering the list one compile error at a time.
    Found 2026-08-30 by p6 Task 16.
17. **The framing refusal roster is package-wide, not framing-scoped, and that is deliberate.** Every
    way of fencing "framing" off is a file list or a type list — the exact shape rule 5 exists to
    refuse — so the roster watches all of `mls`. It holds today with room to spare (103 of 103
    refusals named by a test), but **p7 and p8 each add refusals and each will owe a test that names
    the sentinel**, or `TestEveryRefusalThisPackageShipsIsNamedByATest` fails. Its naming rule is also
    one hop deep, calibrated to the package as it stands; a sentinel driven from a table reached
    through a second table reads as unnamed, and the fix is to lengthen the hop deliberately rather
    than to add an exemption. Found 2026-08-30 by p6 Task 16.
18. **p6 Task 20 is blocked on p7, so p6 closes at 19 of 20.** The plan files Task 20 as its only
    wave-4 task and both construction-bypass seams take a `*Group`, which p7 declares. p6 is done
    at 19; Task 20 runs after p7 lands the struct. Found 2026-08-30 by the p6 Task 20 agent, which
    committed nothing rather than improvise a `Group` to build against.
19. **The seam plan puts a test-only hole in a shipped file, and the gate hatch would pass it.** The
    plan names `connect/mls/framing_group_seams.go` -- a NON-test file, so both seams compile into
    every binary that imports `mls`. The uncalled-declaration gate does catch them, but the
    documented way to quiet that gate is an entry in `packageDeclarationsAwaitingTheirFirstCaller`,
    and that map's whole safety argument is expiry-by-failure: an entry dies on the commit that
    gives its declaration a production caller. **A seam has no such commit, ever.** So the one entry
    that must never be written is also the only kind the map cannot expire. The file must be
    `framing_group_seams_test.go` -- same package, same two signatures, p8 compiles unchanged -- and
    the hatch should be closed before Task 20 runs, so the wrong path FAILS rather than being
    discouraged by a comment. Pin `errNilLeafOccupancyTest` in both directions when closing it: it
    is named like a test seam and is a genuine internal guard. Found 2026-08-30 by p6 Task 20.
20. **p6 Task 20's literal code does not compile against p7's struct.** It calls
    `self.keySchedule.Secrets()`; p7 declares the field as `schedule *KeySchedule`. p7 owns the
    struct, so Task 20 moves. The other three coupling points were checked and are correct as
    written: `self.crypto`, `self.secretTree`, and `EpochSecrets.Membership`/`.SenderData`. Recorded
    so it is not re-litigated: the plan passes `padding []byte` to the unexported
    `sealPrivateMessage`, and that is the signature that exists (only the exported
    `SealPrivateMessage` takes `paddingSize int`), so ValSem011 non-zero padding is expressible.
21. **Rule 5 has a second half nobody had written down: a gate that DERIVES its class and
    ENUMERATES its scope is not a derived gate.** p7 batch A produced this defect three times, in
    three files, from three independent agents, and every instance passed the full suite:
    `TestTheKeyPackageSignaturePreimageIsAssembledExactlyOnce` derives its emitter class off
    `*syntax.Writer`'s method set with four anchors guarding the scan -- and then hands it ONE FILE
    NAME, so a second assembly of the signed preimage escapes by living one file over in the same
    package. `TestNoExcuseAwaitingAFirstCallerNamesAnExpiryThatCannotArrive` derives the property an
    excuse must satisfy -- and then reads ONE of the two roots the table is keyed for, so a
    `../message` entry bypasses it while the gate LOGS the promise it did not check.
    `groupPolicyRefusalIn` derives its sweep off the AST -- and then decides what counts as a
    refusal with a two-spelling pattern that cannot see an unexported sentinel, which is this
    package's dominant convention. **The fix for each is a wider derivation, never a longer list**,
    and future gate review must ask the scope question separately from the class question. Found
    2026-08-30 by the p7 batch A reviewers.
22. **`NewKeyPackage` mints under whatever credential it likes and nothing sees it.** Measured on the
    committed tree: replace the `cred` argument with `BasicCredential([]byte("mallory"))` inside
    `NewKeyPackage` and all 6604 tests pass; do the same to `suite` and store a hardcoded
    ciphersuite, same result. The cause is a switched-off gate whose replacement was never written --
    Task 7A took the `providerConstructionsAnsweringOffTheWallClock` exemption that `NewLeafNode`
    also takes, but `NewLeafNode` pays for it with `TestNewLeafNodeReadsEveryArgumentItWasHanded`
    and `NewKeyPackage` had no counterpart. **An exemption row is a debt, and the gate family should
    refuse one that names no replacement.** Found 2026-08-30 by the p5 Task 7A reviewer, confirmed
    independently against the committed tree.
23. **ValSem209 is not implemented, and the branch briefly held both positions on what that means.**
    RFC 9420 forbids duplicate extension types and this build assigns the refusal to ValSem209,
    which exists only as a comment. Five production sites name it. A fix commit corrected two --
    `leaf_keys.go` and `group_policy.go` now REFUSE a repeat, each saying in as many words that they
    do so because ValSem209 is unimplemented -- and left three delegating the same refusal TO that
    rule, including `tree_sync.go:497` above `reconcileRequiredCapabilities`. That one is
    wire-reachable: `FindExtension` -> `reconcileWithGroupContext` ->
    `(*RatchetTree).ValidateAgainstContext(ctx, gc)`, exported, `gc` off the wire -- so a peer
    sending two `required_capabilities` entries chooses which one the client reconciles against, at
    the validation entry point whose job is to refuse that. **The spec owes a decision:** is a
    repeated extension type refused at the lookup, or at validation with lookups answering by
    position? Until ValSem209 exists the second answer refuses nothing. Verified 2026-08-30 by the
    batch-A verification pass and independently by the owner.
24. **Nothing in `mls` derives the class "a lookup that selects an extension by type",** so each new
    accessor lands uncovered and is fixed only when someone points at it. p7 has nineteen tasks
    left, several of which read an extension off a group context. This is ledger 21 in its concrete
    form and is the reason 21 is worth stating as a rule rather than as three bugs.
25. **`FindExtension` changed shape and seven plan call sites still spell the old one.** Resolving
    ledger 23 made the refusal live at the lookup, so `FindExtension` is now
    `([]byte, bool, error)` and a new `FindExtensionEntry(exts, t) (Extension, bool, error)` sits
    under it. In-tree blast radius was zero outside `mls`. **The plans are a different matter:**
    `grep` finds ten references in p7, nine in p5, three each in the interface registry and p8, and
    seven of them are written `x, ok := FindExtension(...)`. Any task that copies the plan literal
    will not compile. The registry section that fixes the signature should be amended, and every
    p7/p8 brief must say to read the signature from source. Found 2026-08-30.
26. **ValSem209 is owed and now has a scope, so it is not re-derived later.** It is one clause over
    a whole extensions vector -- no two entries share an `extension_type` -- and it must run at
    THREE doors, not one: `GroupContext` validation (which is what `tree_sync`'s reconciliation
    sits under), `LeafNode.Validate`'s extensions vector, and `KeyPackage` validation. It belongs
    in the validation plan's catalogue beside ValSem106/109 and should be declared where
    `ErrMissingRequiredCapability` is declared rather than in `mls`;
    `TestNoValidationOwnedNameHasLandedBesideItsStandIn` already fails on the commit that lands the
    real name. **When it lands, the lookup's refusal does not become dead and must not be deleted:**
    `LeafKeysOf` and `GroupPolicyOf` are reached from paths whole-context validation does not sit in
    front of -- a `LeafNode` read out of a `Welcome`, a `KeyPackage` validated on its own -- so
    ValSem209 subsumes some of these calls and not all. Scoped 2026-08-30 by the p7 fix agent, which
    deliberately did not implement a validation code point inside a fix commit.
27. **REVERSED, same day. There is no intermediate build; CP3b remains the bar.** This item first
    recorded a decision to build an internal-only messenger before p7/p8 finished. **The question
    that produced it was put to the owner without checking `PROGRESS.md`, which had already ruled
    on it** -- the checkpoint section and its restatements distinguish **CP3a** (a record travels
    end to end, opaque bytes, test-only key source, in process; *"Nothing is invited to CP3a but
    us"*) from **CP3b** (the same path with the real MLS key schedule underneath; *"the bar for
    anything a human is invited to send a real message through"*). The rejection of a quicker
    vertical slice is recorded there with its reason: *"in a privacy product a build that sends
    unprotected traffic is a hazard the moment it exists, because it looks exactly like the real
    thing to anyone testing it."* That objection already answers the mitigation this item proposed
    -- "unmissable in-product status" does not help when the whole complaint is that testers cannot
    tell. On being shown the conflict the owner reversed to **"Drop it -- CP3b is the bar."**
    Nothing had been built on it. **The process lesson, which is the durable part: a ruling in
    `PROGRESS.md` outranks a fresh answer to a question framed without it, and the honest move is
    to surface the conflict rather than bank the answer.**
28. **DECIDED by the owner 2026-08-30: the pgx store runs in parallel with p7, and comes before the
    sdk plan.** The rationale accepted: the store has a designed schema (SS3.2), a 51-subtest
    contract suite any implementation must pass, and an api layer to test against -- so it needs no
    new plan -- and it is the piece that makes a message survive a restart, which the intermediate
    build in item 27 depends on. The sdk plan (~135 declarations, no plan yet) and the Windows
    client that is blocked on it come after.
29. **CRITICAL: the proposal cache fails OPEN on replay, and the plan cannot close it.**
    `(*ProposalCache).Resolve` reads neither `self.epoch` nor `self.groupId` -- verified by reading
    the body, not inferred -- so a proposal cached in epoch N resolves in epoch N+1
    unconditionally. `CheckEpoch` exists and has **exactly one caller in the whole tree**: `Store`,
    on the content's OWN epoch, which is self-referential for the first entry. So the cache binds to
    whatever is stored FIRST, and what is stored first is attacker-supplied: one replayed genuine
    proposal from a closed epoch, delivered to a freshly cleared cache, seizes the binding.
    **`grep CheckEpoch` over the p7 plan returns ZERO** -- no later task calls the method the task
    invented to close the hole -- and the plan's own mitigation is `proposals.Clear()` at exactly
    two hand-written call sites, which is an enumeration of the epoch-advancing paths rather than a
    derived class. `Clear` itself is sound (a no-op is caught by
    `TestCheckEpochAnswersTheBindingAndClearReleasesIt`); what is unheld is that anyone calls it.
    **The fix requires changing a pinned signature** -- `Resolve` must be given an epoch to observe
    -- so it must land before p7 Task 7, which compiles against it. Found 2026-08-30 by the p7 Task
    6 reviewer, confirmed structurally by the owner.
30. **Four distinct rules in the v1 profile gate all answer `errUnsupportedProposalType`, and the
    file's own doc comment forbids exactly that.** The comment reads "One value per rule and never
    one value shared by two ... a set of refusals that all reduce to one comparison is this
    project's most repeated defect." The four are: a reserved code point, a code point not in the
    registry, a nil proposal, and a forged wire discriminant. It is not cosmetic -- Task 6's
    `ProposalCache.Store` and Task 7's ValSem113 are both named as this gate's first callers, and
    they **cannot separate "a peer sent an unregistered type, drop the message" from "our own commit
    builder produced a value whose ProposalRef every receiver will read differently".** Those need
    opposite handling. Found 2026-08-30 by the p7 Task 4-5 reviewer.
31. **The cache replay fix traded integrity for availability, because binding-by-first-entry
    survived it.** Item 29's fix put a door on `Resolve` and the replay is no longer APPLIED -- but
    `Store` still takes the binding from whatever is cached first, and that is attacker-supplied.
    Verified structurally: `Store` calls `CheckEpoch(content's own epoch)` and then assigns
    `self.groupId`/`self.epoch` from that same content, and the ONLY release is `Clear`.
    So one replayed GENUINE proposal from a closed epoch, delivered to a freshly cleared cache,
    binds the cache to the closed epoch. The member can then neither cache the live epoch's
    proposals (`Store` answers `errProposalCacheEpoch`) nor process any commit naming one (`Resolve`
    answers `errProposalResolvedOutOfEpoch`), **and the binding never recovers**: `Clear` is the only
    release and its only planned caller is `MergePendingCommit`, which needs a commit this member
    can no longer resolve. **A permanent self-inflicted denial of service from one replayed genuine
    message.** The root cause is the design: a cache's epoch must come from the GROUP'S
    authoritative state, not from its first entry. Also unfixed: `Get` and `Pending` consult neither
    field, and `CheckErrata8815` calls `Get` and reports "not cached for this epoch" -- a claim `Get`
    cannot make. Found 2026-08-30 by the cache reviewer, confirmed structurally by the owner.
32. **A derived gate that finds a call with `ast.Inspect` measures the TOKEN, not the discipline.**
    The new epoch-mover gate sets its "ends the binding" finding from any `*ast.CallExpr` anywhere in
    a body, never asking reachability -- so `if false { self.proposals.Clear() }` is a full-suite
    survivor, and so is a `Clear()` placed after an early `return err`. **The plan itself has that
    shape at line 8364**: `self.proposals.Clear()` immediately followed by
    `if err := self.persist(); err != nil { return err }`, and swapping those two statements is a
    one-line reorder the gate cannot see. The gate is also resolved by the receiver's TYPE and not
    its IDENTITY, so clearing a DIFFERENT `*ProposalCache` satisfies it -- latent while `Group` has
    one, live the moment Task 19 adds a past-epoch or staged cache. Found 2026-08-30.
33. **MILESTONE: the pgx store passes the hardened contract against real PostgreSQL.** 241 passing,
    0 failing, 0 skipped, ~240 s, both implementations reporting "ran the contract". PostgreSQL
    17.6 runs portable and service-free at `127.0.0.1:55432`; the DSN comes from
    `URMESSAGE_TEST_DSN` and **without it the suite is green having never touched a database**
    (it prints `PgxStore DID NOT RUN`, which is deliberate and loud, but it is still green).
    Hardening the contract BEFORE writing the second implementation was decisive: against its only
    implementation the suite could not see epoch keys installed as 32 zero bytes or the read key
    written into both columns, `EpochKeys` answering a neighbouring epoch, four of the six rows the
    founding transaction writes, three of four retention arms, or a duplicate `CreateGroup`
    answering `REASON_REJECTED` while disclosing that the group exists and how many records it
    holds -- SS4.5's most-cited paragraph.
34. **A refused `SubmitResult` carries a record id that names no row, and the api forwards it.**
    `refuse()` rewrites `Reason` and never clears `RecordId`, which `write()` has already stamped
    for records processed earlier in the same batch; `api/submit.go:652` copies it unconditionally.
    Measured against live PostgreSQL: `reason=REASON_REJECTED record_id=3` with `next_record_id`
    unchanged at 3 across the call. The contract already declares this illegal at `contract.go:3419`
    -- **the assertion is right and simply never fires**, because no scenario drives a refusal that
    lands after an earlier record was stamped. So the guard existed and the hole shipped anyway.
35. **The two Store implementations disagree on SS4.3.7, and the reference model is the permissive
    one.** `MemoryStore` ACCEPTS a batch that claims a recovery handle and rebinds it to a different
    `verify_pub` in the same batch; `PgxStore` refuses. This is the differential the second
    implementation was worth building for. It is a spec question before it is a bug: SS4.3.7 must
    say which is right, and if it does not, that is a gap to close rather than a coin flip. **The
    reference model must not simply be relaxed to match**, which is how a hole becomes expected
    behaviour. Found 2026-08-30 by the pgx Submit/Fetch reviewer.
34a. **CLOSED 2026-08-30.** The id is taken off in `resultsOf`, which is the single function both
    implementations build every `SubmitResponse` through, and the condition is `accepted()` rather
    than a list of the three refusal sites -- Rule 5, and one more reason: SS7.3's
    `REASON_RETENTION_CLAMPED` is an acceptance carrying a notice, so a check written against
    `REASON_OK` alone would have erased the id of every clamped commit. The scenario the assertion
    was missing is now in `contractRecovery`: a batch of two recovery records claiming one handle
    under two `verify_pub`s, which is the only refusal in the package that fires after an earlier
    record of the same batch reached the stamp. Restoring the defect fails
    `TestThePgxStoreMeetsTheContract/ARecoveryHandleIsTrustedOnFirstUse` with
    `contract.go:3419` naming `record_id 6`; `MemoryStore` passes the same mutation, because it
    refuses this batch at the gate and never stamps anything -- the defect only ever existed on the
    path that writes before it refuses.

35a. **CLOSED 2026-08-30. SS4.3.7 settles it and `MemoryStore` was wrong.** The text is "stores the
    public half on first sight WITHIN THAT GROUP and REFUSES any later differing
    recovery_verify_pub for the same recovery_handle in the same group", and SS6.1 step (6c) --
    "INSERT ... ON CONFLICT DO NOTHING, then verify the stored verify_pub equals the tag's. A
    mismatch is REASON_REJECTED and rolls the batch back" -- runs per record. A record two positions
    along in one submission is therefore later than the record that claimed the handle, and the
    batch has a first sight of its own. **No spec gap and no ledger decision is owed**; the reading
    is now written down at `store.RecoveryTag` rather than left to be inferred, because it is the
    half of SS4.3.7 the prose states only by implication. `MemoryStore` now carries the batch's own
    first sight through the gate, exactly as it already carried the batch's own stream high water --
    its gate read `group.recovery` once and so could not see the claim the batch itself was making.
    `PgxStore` keeps the check where SS6.1's SQL puts it, after allocation and rolling back: the
    stored row is what SS4.3.7 pins a handle against, the rollback is what makes the refusal cost
    nothing, and it is also what keeps item 34's path reachable for a scenario to reach. The two
    inversions are separate mutations and each is caught only by its own implementation's run.

36. **`Fetch`'s central decision was pinned by nothing, and the mutation that breaks it manufactures
    the withholding signal the protocol sells to clients.** `Fetch`'s doc comment argues at length
    that the read key does not gate which records come back -- SS5.1.1's check 6 authorizes the
    REQUEST and `EpochKeys` answers it upstream -- and no test held any implementation to it. Adding
    `AND EXISTS (SELECT 1 FROM message_epoch k WHERE k.group_id = r.group_id AND k.epoch = r.epoch
    AND k.write_key_wrapped IS NOT NULL)` to the page predicate passed the entire suite with output
    byte-identical to the baseline. Root cause: every fetch scenario read a group sitting at epoch 1
    that never commits, so no key was ever retired inside one, and nothing anywhere asserted that
    the records returned equal the records submitted. What it withholds is the OLDEST end of the id
    sequence, permanently, in every group that has committed twice -- SS6.1 step (6) empties the
    write key of every epoch strictly older than the superseded one, and the founding commit sits at
    epoch 0, which has no `message_epoch` row at all -- while `high_water_record_id` goes on naming
    the top. That is SS4.3.4's withholding detector and SS12.2 C-4's fault, produced by the server
    against itself. **CLOSED 2026-08-30** by `EpochKeyCustodyDoesNotGateWhichRecordsComeBack`, which
    establishes its own precondition (epoch 1 has genuinely lost its write key) before asserting
    that the page is every id the group allocated; under the mutation a group that allocated
    1..10 answers 6..10. It is not one of the two `Fetch` properties `contract.go` leaves unpinned
    on purpose -- those are the row lock and `complete` at the exact limit boundary -- so it was
    missing coverage rather than a decision. Found 2026-08-30 by the pgx Submit/Fetch reviewer.

37. **A closed group told you its epoch and an unknown one did not — and the gate's TYPE forbade
    the method that showed it.** Measured against both live implementations: `MemoryStore` answered
    a submit to a closed group `reason=REASON_REJECTED current_epoch=1` where `PgxStore` answered
    `current_epoch=0`, because `MemoryStore` refused through `refuseBatch`, which calls
    `fillCurrentEpoch`, while `PgxStore` reads the group row with `AND NOT closed` and so had
    nothing to fill from. §4.5 and §7.5 require the two to be indistinguishable, so the merged
    reason code was doing its job and the field beside it was undoing it. **This is the second time
    the reference model has been the permissive one** (item 35 was the first) and **the second time
    a fix has been scoped to a FIELD rather than to the class** — item 34 closed exactly this for
    `record_id`, and `current_epoch` survived in the next field along. The fix is therefore the
    class: `refuseUnavailable` now replaces the WHOLE `SubmitResult` with a zero value carrying
    only the code, so a sixth field added tomorrow is empty on that path by construction, and both
    implementations refuse through that one function. `EpochKeys` was the other half — both
    implementations read the epoch row without joining `message_group`, so a closed group served
    the keys an unknown one refused; it now joins, in the statement rather than in a second one.
    **Reachability, stated precisely:** the leak reaches the wire (`api/submit.go`'s `resultOf`
    copies `current_epoch` unconditionally, and must — §4.5 gives `REASON_EPOCH_STALE` that field)
    but only for a party that already holds the group's write key, since §5.1 check 6 runs first.
    It is a normative divergence and a state disclosure, **not** an existence oracle to an
    outsider. **The gate that could not see it is the more interesting half.** `contract.go`'s
    `AClosedGroupIsTheSameAnswerAsAnUnknownOne` held `map[string][2]error` over three of `Store`'s
    six methods; `EpochKeys` was absent and `Submit` was *unrepresentable*, because Submit answers
    with a struct and not an error. **That is worse than an enumeration — an enumeration can be
    extended, and this one's TYPE excluded the failing member** — and the line above it submitted to
    the closed group and asserted the reason code alone. 118 contract subtests per implementation,
    and the divergence sailed through. It now derives its class from `type Store interface` at run
    time, calls all six, and compares the whole answer against the partner's and against the answer
    both owe. **CLOSED 2026-08-30.** Found 2026-08-30 by the closed-group reviewer.
38. **§7.5 says a closed group still serves `Fetch` and this build refuses it, so it now refuses
    epoch keys too.** §7.5's definition is "submits are rejected with `REASON_REJECTED`; fetch is
    still served, so members can read what they have." Both implementations refuse `Fetch` for a
    closed group, `contract.go` asserts that they do, and `store.go`'s interface doc states the
    stricter rule in as many words: "a closed group answers `ErrGroupUnavailable` everywhere
    afterwards, exactly as an unknown one does." The stricter reading is the one item 37's fix
    extends to `EpochKeys`, and it has to be extended somewhere: a build that refuses fetch while
    serving the read key that authorizes it serves a key for a page nothing will return, and the
    difference between the two answers is the existence answer §4.5 withholds. **§7.5 and the
    interface cannot both be right.** The spec should say which, and if fetch is genuinely still
    served then §5.1.1's check 6 has to be served with it and the indistinguishability of §4.5 has
    to be restated for the methods it does not cover. Found 2026-08-30 by the closed-group reviewer.

    **READING PROPOSED 2026-09-02, and it is a reading rather than a ruling.** Take §7.5: a closed
    group still serves reads, and `store.go`'s *"everywhere afterwards"* sentence is the one that
    goes. §4.5's indistinguishability exists to deny an OUTSIDER an existence oracle, and on the read
    path §5.1.1's check 6 (the read-key lookup) and check 7 (the `req_auth` MAC under that key) both
    run before the closed state is consulted, so the only party that can observe the difference has
    already proved possession of that epoch's read key — while EXISTENCE is answered earlier and by
    something else entirely, §5.1 check 5's known-group cuckoo filter, which closing does not remove
    an id from. Merging the two answers for a key-holding member protects nobody and costs them their
    history. The costs are stated rather than discovered: `EpochKeys`'s join
    loosens from "not closed" to "exists"; and §4.5 has to be restated as a **derived partition over
    `type Store interface`** — the read methods answer a closed group as they answer an open one, the
    write methods as they answer an unknown one — never as a hand-written list of method names, which
    is the rule-5 failure this repository has recorded fourteen times. Argument, alternative
    amendment, and the interlock with 39 are in
    `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md` Part 3, which is the
    durable copy and is not restated here (item 7's shape). **38 and 39 must be ruled together.**
39. **§6.1's step (0) runs in front of §7.5's sentence, so a closed group still answers a retry
    with `REASON_OK` and a record id.** §6.1 is explicit that the idempotency probe is "before any
    gate, before any allocation, and before the row lock of step (1)", and both implementations read
    it that way — `MemoryStore` from its claim map and `PgxStore` from `message_stream_claim` on the
    pool, neither joining the group row. So a record that landed before the close is answered
    `REASON_OK{record_id}` on retry, and a stream index reused with different content is answered
    `REASON_STREAM_INDEX_REUSED`, where §7.5 says a closed group's submits are rejected with
    `REASON_REJECTED`. This is **not** a divergence — the two implementations agree, and the
    behaviour follows from §6.1's stated step order — so it is left alone and pinned by
    `ACloseDoesNotReachTheTwoAnswersInFrontOfTheRowLock` rather than changed under a brief that did
    not ask for it. Closing it costs a `message_group` read inside step (0), which §6.1 put the
    probe in front of the lock precisely to avoid; the cheap form is an `EXISTS` in the same
    statement, not a second round trip. **The field beside the code was not left alone**: both
    answers now carry no `current_epoch`, which is item 37's rule reaching the two paths a fix
    scoped to step (1) does not. §7.5 should say whether its sentence outranks §6.1's step order.
    Found 2026-08-30 by the closed-group reviewer.

    **READING PROPOSED 2026-09-02, and it is a reading rather than a ruling.** §6.1's step order
    outranks §7.5's sentence, and §7.5 should say so. Step (0) allocates nothing, writes nothing and
    creates no state, so it is not the "submit" §7.5 rejects; and answering `REASON_REJECTED` to a
    retried commit fires the loser protocol, whose step 2 is the hard `MUST NOT` on reusing
    `pq_secret[n+1]` that §12.1 A-6 calls a silent-corruption failure invisible in functional tests —
    which is the expensive path the probe was put in front of the lock to avoid. Nobody learns
    anything new either: reaching step (0) means passing §5.1 checks 1–8, and check 7 is the
    `write_auth` MAC, so the party answered holds that epoch's WRITE key and is a member retrying a
    record it already sent. One principle answers this and 38 —
    **`closed` withdraws the ability to write new content, not a member's ability to learn what is
    already there** — and if the owner takes the strict reading on 38 instead, this must flip with
    it, at the `EXISTS` price this item already names. Reasoning in
    `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md` Part 3.
13. **A spec-conformant client cannot connect to a server without §9.1's signing sidecar.** §4.3.1
    requires `HelloResponse.server_keys` and requires a client to REFUSE a fleet whose first key does
    not verify against the compiled-in root, while decision B13 keeps every signing key off every
    replica. That is not a defect in B13; it is a gap in what §4.3.1 says a partial deployment can do.
    Found 2026-08-26 by `peer/`.

48. **The `sdk` surface has twenty-four open questions and four of them must be ruled before the
    plan after next starts.** (Seventeen when first filed on 2026-08-30; S1-18 to S1-24 were added
    by the 2026-09-02 repair below, which found four properties in that plan no correct
    transcription could satisfy.) The full list is the Open items section of
    `docs/plans/2026-08-30-slice2-s1-sdk-surface.md`, which is the durable copy; it is not restated
    here, because a second copy with nothing holding the two together is the ungated-agreement shape
    item 7 already records. The fourth that cannot wait is **S1-23**: §7 declares twelve
    `*List`-returning methods on `MessageClient` with no error return, §8.2 forbids the empty answer
    in the failure case, and the plan's own premise makes `null` a consumer crash — so §8.2 states a
    requirement the signatures it names cannot express, and s10 must not freeze the ABI baseline
    before it is ruled. The three schema decisions that cannot wait: **the pin primary key collapses** —
    §8.1 keys `pin` by `(principal, operator_host)` while §7.3b leaves `Principal` empty for a
    card-added contact and §7.6 leaves `OperatorHost` empty for a card-provided key, so two
    card-added contacts share the key `("", "")` and the second silently overwrites the first, which
    is exactly the state in which no `KeyChangeWarning` fires; **`StoredEntry` is undefined** and
    §8.2's "fourteen methods, that bound is the point" omits every table §8.1 itself lists, five of
    which are read directly by §7 declarations; and **no JSON field naming is specified anywhere**,
    while every value struct crosses the ABI as JSON, Spec C parses it with nlohmann and §9.3's
    `settings_json` documents snake_case. The first two are schema decisions and ruling either after
    rows exist is a migration. The third must be ruled before the ABI baseline is committed, or
    every later correction becomes a
    baseline-break ceremony. Found 2026-08-30 while writing the s1 plan.

40. **CRITICAL -- a group member can crash every other member with one valid proposal.**
    `ProposalCache.Store` computes the proposal reference BEFORE every ceiling (its own doc pins
    that order: *"THE CEILINGS COME AFTER THE REFERENCE AND NOT BEFORE IT"*), and that path reaches
    `RefHash` -> `mlsLabelBytes`, which **panics**. Verified by the owner: `syntax.MaxVectorLength`
    is 1048576 and `RefHash` on one octet past it panics with *"a labelled preimage could not be
    encoded"*; `grep -rn recover() mls/ message/` over production source is **EMPTY**.
    The reviewer measured the reachable input: an Add whose KeyPackage carries a
    `BasicCredential` of `MaxVectorLength-64` marshals to 1,048,619 octets, **`syntax.Unmarshal`
    accepts it back** (so it is a message a decoder produces, not a hand-built value), and
    `FramedContentTBSBytes` returns a valid preimage -- so it **signs and verifies as an authentic
    member message**. Signature verification before `Store` is no protection.
    **Root cause, and it generalises:** the premise is written twice in `crypto_labels.go` --
    *"every value that reaches a labelled construction arrived through a decode or an encode
    already bounded by syntax.MaxVectorLength. A panic here is therefore unreachable"* -- and it is
    true FIELD BY FIELD and false for a COMPOSITION. `RefHash` wraps the whole serialized
    `AuthenticatedContent` in ONE `WriteOpaque`, and that structure's group_id, authenticated_data,
    proposal arms and signature are each <= 1 MiB with an **unbounded sum**. So the fix is not this
    call site: it is every place a composition is wrapped in a single length-prefixed field.
    The safe shape already exists at `owner_successor.go:332`, which pre-checks the length and
    returns `syntax.ErrLengthExceedsMax`.
    **The suite could not see it**: the one fixture that probes size, `testEnormousProposal()`,
    lands about 6 octets UNDER the threshold -- it exercises the largest proposal that does not
    panic. Found 2026-08-30 by the cap/authority reviewer; confirmed by the owner.
40a. **The crash is on the SIGNATURE path, not just the proposal cache -- five call sites, not**
    **one.** Measured on the tree 2026-09-01 by driving one oversized-but-valid value at each:
    `ProposalCache.Store`, `(*KeyPackage).Ref`, `FramedContentTBSBytes` + `SignWithLabel`,
    `DeriveJoinerSecret` and `EncryptWithLabel` **all panic**. The fifth matters most and was
    missed by the original report: the same panic is reachable through `VerifyWithLabel`, which
    runs **before any application-level check a caller could make**. So the crash is not confined
    to a proposal that reaches a cache -- it is on the path every incoming signed message crosses,
    and no ordering of application checks can get in front of it.
41. **The proposal-cache ceilings admit a set no valid commit can name, so round 2's availability
    failure is still live, merely bounded to 500.** One sender stored 500 distinct Removes ALL
    naming leaf 4; RFC 9420 SS12.2 invalidates a list carrying multiple Removes for one leaf, so
    `Pending` hands a committer an invalid list and the commit built from it is refused by every
    receiver. **The cache offers no way out**: nothing removes a single entry, `Pending` is a
    committer's only accessor, and the only release is `Rebind` at an epoch boundary that only a
    SUCCESSFUL commit produces. The doc states the right rule twice -- the bound is per-TARGET --
    and the code counts per (sender, TYPE), so 500 is not the number the argument produces.
42. **The octet ceiling has no per-sender column, and one sender is cheaper than two.** Measured:
    leaf 1 alone reached 8,388,605 of 8,388,608 octets using **27 messages**, 15 of its own 500-entry
    Add quota; leaf 2, which had cached nothing, was then refused a 6-octet Remove. This is verbatim
    the starvation the per-sender ENTRY column was added to prevent, left open in the dimension
    where one message is worth half a mebibyte -- and strictly cheaper, since the entry total needs
    two senders and the octet total needs one.

43. **The proposal cache's provenance question is not answerable until `GroupInfo.Verify` exists,
    and four rounds were spent before that was seen.** Rounds 1-3 tried an AST walk and each was
    defeated by one line (an argument type; a local struct; an accessor method, and separately
    embedding). Round 4 replaced the walk with a type -- `VerifiedGroupContext`, unexported field,
    one constructor -- which is the right SHAPE and was still **REJECTED**, for a reason that
    settles the whole line:
    - `ConfirmGroupContext` is **self-confirming**. The context enters through the `KeySchedule`
      constructor and `ConfirmationTag` is exported on the same type, so
      `s.ConfirmGroupContext(s.ConfirmationTag(h))` is a tautology. Demonstrated from an EXTERNAL
      package in three lines: a decoded `GroupInfo` naming `"ATTACKER-CHOSEN-GROUP"` at epoch
      1<<40 was accepted, and `NewProposalCache` took it.
    - **Even the honest joiner flow confers no authority**, because the party that chose the
      `joiner_secret` is the same unauthenticated party that chose the group context -- a Welcome
      is HPKE-sealed to a PUBLISHED init key, so anyone holding the victim's KeyPackage supplies
      both. Verified by running the prescribed flow: it accepted a context naming a group that
      does not exist.
    **Root cause, verified by the owner: `GroupInfo` has NO signature verification in this build.**
    It declares only `toBeSigned`, `MarshalMLS` and `UnmarshalMLS`; `VerifyWithLabel` has callers
    for FramedContentTBS, KeyPackage and LeafNode and **none for GroupInfoTBS**, and
    `welcome_wire.go`'s own header says so: *"nothing here decides whether a GroupInfo's signature
    is good."* So four rounds tried to establish the AUTHORITY of a value whose AUTHENTICITY is
    never checked. **p7 Task 14 is the missing piece** -- it produces
    `func (self *GroupInfo) Verify(crypto CryptoProvider, tree *RatchetTree) error` -- and every
    interface it consumes has landed, so it is dispatchable out of order and is being pulled
    forward. The verified-context constructor should be that verification, not a confirmation tag.
    **Process lesson: when a gate is bypassed twice, stop hardening it and ask what it is standing
    in for.** Three of these four rounds were avoidable.

44. **No key-package fetch by principal exists, and four §7 declarations cannot be written without
    one.** `CreateGroupWithMembers`, `CreateDirect`, `InviteMember` and `AcceptJoinRequest` must each
    issue an MLS `Add`, which carries a KeyPackage. `connect/protocol/` holds **zero** occurrences of
    `key_package` across all seven `.proto` files, and §12.3's directory maps `principal → identity
    master key` and nothing more — a fingerprint, not a key package — while directory listing is off
    by default. **One path exists and it runs the other way:** §5.14's sealed contact-request deposit
    carries `LP key_package`, *"the MLS KeyPackage the card's owner will Add"*, which requires the
    party BEING ADDED to act first, at a rendezvous IT chose. So the four split 3+1: nothing serves
    `CreateDirect`, `CreateGroupWithMembers` or `InviteMember`, and `AcceptJoinRequest` serves itself
    **only if** item 45's join-request deposit is specified to carry a key package — which is why 44
    and 45 should be ruled together. Three options (an operator directory endpoint, a key-package
    store on the message server addressed by an identity handle, deposit-only), their metadata costs,
    and a recommendation are in
    `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md` Part 2 proposal 1, which is
    the durable copy and is not restated here (item 7's shape). **Blocks:** the four declarations in
    whichever slice-2 plan owns the group flows; Spec B's schema; Spec C's add-member screens. **Does
    not block:** s1, which is declaration-only, or m1's record-format freeze — a key-package channel
    is control-plane, not a record. Found 2026-09-02 by the CP3b-chain review.

44a. **And neither has the `Welcome`, which nothing had filed.** The same absence blocks the reverse
    direction. Spec A annotates `CommitResult.RatchetTree` *"for out-of-band Welcome delivery"* and
    then names no band. Every server operation is keyed by `group_id` and gated on possession of that
    group's epoch key, which a joiner does not have by definition; the only identity-adjacent channel
    in the protocol is §5.14's rendezvous, addressed by a **card token** rather than by an identity,
    whose only body is `CONTACT_REQUEST`. §7.3's `PendingInvites()` and `AcceptInvite()` are declared
    over this same absent channel. It is filed under 44 rather than beside it because one mechanism
    closes both directions and splitting them invites two incompatible answers. **On the CP3b path**,
    where it is short-circuited by a named, gated test-only hand-off — of a public KeyPackage and a
    `Welcome` already sealed to the joiner's init key — under the same absent-not-placeholder rule
    that made CP3a's key source safe. Found 2026-09-02 by the CP3b-chain review.

45. **§7.3a invite links have no wire, no derivation and no server operation — and §13's sentence
    scheduling them is false.** §5.14 derives all rendezvous material from
    `card_root = HKDF-Expand(master_key, "card/v1", 32)`, which is **per identity**. A group invite
    link needs a rendezvous per LINK with a per-link `collect_verify_pub`, and a reusable published
    address needs a collect key **any admin** can hold, which a group has no shared secret of that
    shape for: `group_handle_key` is *"FIXED at group creation"* and computable by every member who
    has ever been one, including removed ones. Missing: the per-link derivation, a link encoding
    (§5.14 encodes the card and nothing else), a join-request deposit body (`CONTACT_REQUEST` is the
    only body, and the server asserts an exact 5238-byte equality), and the authorization model for a
    reusable address. **§13's claim that these are *"an sdk-level flow over mechanisms A6 already
    froze"* is false**: A6 froze the rendezvous transport and the five preimages, both genuinely
    group-agnostic, and froze none of the four things above. The sentence is true of §7.3b and was
    extended to §7.3a without the check, so **A7 cannot deliver §7.3a as the table stands.** Three
    options and a recommendation — including one that is the obvious design and is rejected for
    handing a removed member a permanent collect key — are in
    `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md` Part 2 proposal 2.
    **Blocks:** all eight §7.3a declarations (already in s1 Task 11's blocked set), item 44's
    `AcceptJoinRequest`, §13's A7 row, and Spec C's join-request screens. Found 2026-09-02 by the
    CP3b-chain review.

46. **`GrantHistory` has no mechanism anywhere, and the gap is load-bearing in three places.** §5.11
    wraps the CURRENT epoch to CURRENT members — device wraps carry `pq_secret[n]` and `eph_root[n]`,
    recovery wraps carry `storage_root[n]` and `archive_secret[n]` — and there is no
    wrap-to-past-epochs primitive, no record class, no server operation and no extension (v1's
    `RequiredCapabilities` is fixed to `[0xF001, 0xF002]`). The three places: `GrantHistory` and
    `HistoryGrants` in §7.3; `"history_granted"` in `GroupEvent.Kind`'s **closed** set, which nothing
    can ever emit — the reachability half of s1 Task 9 Property 2, already carried there as an
    accepted survivor; and Spec C screen 15's banner. **A review already found this and its fix was
    never applied**: r3 finding 5 (2026-08-12) prescribes *"A history grant conveys
    `storage_root[m..n]` and nothing else… It never conveys `eph_root` for any epoch"* plus a fourth
    item on MASTER's `eph_root` exclusion list, and neither sentence is in any spec today —
    `grep "conveys" docs/specs/*.md` returns nothing and the exclusion list still has three items.
    Three options, a recommendation (a fifth `server_attachment` kind wrapping the contiguous range
    as one `PERMANENT` blob-ref record), and the two rejected alternatives with their reasons are in
    `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md` Part 2 proposal 3.
    **Urgency is not the feature's:** it is a `server_attachment` kind, so ruling it AFTER A6 freezes
    the wire makes it a format break rather than an addition. Found 2026-09-02 by the CP3b-chain
    review.

47. **The `connect/message` plan does not exist, and it is on the CP3b critical path in front of the
    sdk.** The 2026-08-29 re-orientation named three unplanned workstreams — the sdk, server
    persistence, Windows wiring. There is a fourth. `docs/plans/` holds p1–p8, all `connect/mls`, and
    s1, `sdk`. Nothing owns `connect/message`'s second half: §5.2's construction order, §5.3's key
    schedule, §5.5's ratchet, the record seal and open, and the client half of §5.11's epoch wrap
    set. The s1 plan already names that plan **m1** and records `StorageRoot` and the
    delete-for-everyone constant as **pending pins with no producer**; `message/doc.go` says *"The
    key schedule lands beside them"* in the future tense; and `grep 'func StorageRoot'` over the tree
    returns nothing. This is exactly the CP3a/CP3b delta — CP3a's harness states in its own header
    that *"It does not encrypt"* — so **CP3b cannot be reached without it and it has no plan, no
    estimate and no owner.** The chain, with the tasks each leg forces and the ones it does not, is
    in `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md` Part 1. One trap it
    names: §5.11 defined `expected_wrap_count` as *"device wraps + recovery wraps + 1 snapshot"* and
    the server checks only that the marker matches the attachment, so a client that defers recovery
    wraps and the snapshot passes the server while diverging from the spec — a deferral the system
    cannot detect, and therefore one m1 must gate rather than leave to an implementer. **(The quoted
    definition was superseded on 2026-09-13: the field is now `2 × device_leaves + 1` and counts no
    recovery wrap, so deferring the recovery wraps no longer diverges from it. The trap survives in
    the other direction — the server still compares two client-declared numbers, item 132 — and the
    recovery arm now has no count over it at all, items 138 and 142.)* Found
    2026-09-02 by the CP3b-chain review.

47a. **CLOSED 2026-09-04.** m1 is written:
    `docs/plans/2026-09-04-slice1-m1-message-crypto.md`, **25 tasks** over three waves (24 numbered
    plus Task 9a, added by the 2026-09-05 repair below), with the CP3b path as an explicit prefix
    (tasks 1–16 and 9a) and the line where it ends stated in its own section.
    The `expected_wrap_count` trap this item named is closed the way it asked: the count is
    **derived from the fan-out the builder actually emitted**, never typed. The *mechanism* changed
    in the repair — the deferral is now a required-row table held to the derived inventory in both
    directions, not a red test, because a test red on purpose across three tasks is one nobody can
    tell from a regression and the Definition of done requires green. What the plan does **not**
    close is the interesting half, and it is items 125 through 128 below: **four** legs or rulings
    stand between a complete m1 and CP3b, and only two of them were visible when this item was
    first written. The plan's own **Open items** section carries **45**, of which **six** are marked
    wire-visible and block the A6 freeze — M1-6, M1-7, M1-8, M1-24, M1-27 and M1-33 — and four block
    CP3b (items 125–128 here). They are not restated in this ledger, because the plan is where an
    implementer meets them. *(**Neither count is live and this row is kept as the record of the day.**
    The plan carries **50** items now; of the six named, **M1-8 and M1-6 were both ruled 2026-09-07**
    and **M1-7 was ruled 2026-09-09** as `P2` over all three wrap bodies, so **three** still need a
    ruling before A6 — M1-24, M1-27 and M1-33. Annotated rather than
    rewritten because an A6-blocker list is exactly the kind of sentence a reader counts, and the same
    stale M1-8 was left standing in the plan's own copy by the commit that ruled it.)*

49. **Findings from a workflow review are NOT visible to the next agent, and a brief that says
    "read the review" sends it looking for a file that does not exist.** A reviewer's findings are
    the workflow's RETURN VALUE, held in the orchestrator's context and nowhere on disk. On
    2026-09-02 an s1 repair brief carried CRITICAL 1 inline and then said "read the review for
    CRITICAL 2 and the rest"; the agent searched `docs/reviews/`, the scratchpad, the artifact
    gallery and the whole sandbox, correctly reported the document does not exist, and re-derived
    the class itself -- finding five more instances, which is a good outcome from a bad brief.
    **The rule: paste findings inline, or write them to a file first.** Nothing else reaches the
    agent. This is the owner's error, recorded because every "close the findings from commit X"
    brief on this project has the same shape.

50. **The `VerifiedGroupContext` boundary holds in SAFE Go, and the file says it holds absolutely.**
    Verified by the owner from `package mls_test`:
    `(*mls.VerifiedGroupContext)(unsafe.Pointer(&shadow{inner: attackerContext}))` forges one, and
    `NewProposalCache` accepts it -- `cache=true err=<nil>`, group `ATTACKER-CHOSEN-GROUP` at epoch
    1099511627776. Two sentences are therefore false as written: *"no declaration outside this
    package can build one carrying a context however it is spelled"* and *"a struct whose only field
    is unexported cannot be built carrying a value from any other package"*.
    **This is not a defect worth a gate.** `unsafe` defeats every type-safety guarantee Go makes,
    not this one in particular, and an attacker who can run `unsafe` in the process can rewrite the
    context after any check whatsoever. The fix is the qualifier -- **"in safe Go"** -- and a test
    name that stops asserting a universal it does not establish
    (`TestEveryExternalSpellingOf...IsRefusedByTheCompiler` enumerates four spellings and its own
    doc says it does not enumerate them).
51. **Rule 11 helps and is not sufficient.** The commit that asserted the boundary ran the rule-11
    self-check, said so, and still shipped a fresh instance of the class it was sent to close: its
    new gate's doc claims it will notice *"a constructor added that hands the inner pointer out"*,
    and measured, it does not -- both an added exported constructor and `Context()` returning the
    inner pointer leave the new gate GREEN (each is caught by older, unrelated tests). A paragraph
    25 lines below then says exactly ONE neighbouring case is outside its reach; there are at least
    three. Rule 11 catches what an author can see; it does not make an author see further.

52. **CRITICAL -- an Update proposal's LeafNode is never validated, and the code documents the
    caller that does not exist.** RFC 9420 SS12.1.2: *"An Update proposal is invalid if the LeafNode
    is invalid for an Update proposal according to Section 7.3."* Verified by the owner:
    `LeafNodeSourceUpdate` appears in production source **only inside `leaf_node.go` itself** -- the
    enum declaration and three switch arms -- and **never as any caller's `ExpectedSource`.** The
    three real doors into `(*LeafNode).Validate` are `key_package.go:376`, `tree_sync.go:219` and
    `validate_proposals.go:455` (which is `kp.Validate`, the ADD path). **There is no update door.**
    So an Update's leaf gets no signature check, no `leaf_node_source` check, no credential check
    and no SS13.4 / erratum-8745 group-extension check, and `apply_proposals.go:111` installs it
    verbatim into the tree. ValSem109 checks only `Capabilities.Supports(required_capabilities)`,
    which is a different rule.
    **The package names the gap itself**: `leaf_node.go:603-607` says *"The same Validate is reached
    from three places -- key_package.go with key_package, PROPOSAL VALIDATION WITH UPDATE, the tree
    and the update path with commit"*, and `tree_sync.go:206` says the per-position source rule is
    *"still OWED ... which the update path and the proposal validator state at their own doors"*.
    Two comments describe a caller nobody wrote. Found 2026-09-02 by the p7 Task 7-8 reviewer.
53. **Calling the VerifiedGroupContext line closed.** Eight rounds; the first five found real
    bypasses, the last three found prose. Two measured survivors remain and are being fixed with
    item 52: a hand-set `identity` bool on two enumerated rows whose clearing silently disables the
    shape assertion added to close a survivor, and the X-Wing collector's `assigned` multi-map,
    which keeps a row's production producers after a corpus read overwrites its value. **Everything
    else outstanding in that area is prose precision and is not worth a round** -- a heading that
    says "words no other refusal carries" where the check is set-wise, and a bullet naming two of
    three tests. Recorded so the next reader knows the stopping point was chosen rather than
    reached.

54. **The missing-door defect is a family of three, not one, and the third door checks a value
    against itself.** Item 52 closed the UPDATE door. Verified by the owner on the tree after that
    fix, the three production `ExpectedSource` call sites are:
    `key_package.go:381` -> `LeafNodeSourceKeyPackage`; `validate_proposals.go:690` ->
    `LeafNodeSourceUpdate` (the new door); and **`tree_sync.go:232` -> `leaf.LeafNodeSource`, the
    leaf's OWN source.** That last one compares a value against itself, so
    `ErrLeafNodeSourceMismatch` **can never fire from the tree door** -- a check that reports clean
    having compared nothing.
    **There is no COMMIT door.** `treekem.go:372` SETS `LeafNodeSourceCommit` on a leaf it builds
    (the sending side); nothing validates a received UpdatePath leaf against that expectation. And
    `treekem.go:595-599` says *"its door is already built ... what was missing was the sentence
    saying so"*, with `treekem_test.go:2809` repeating it -- **the identical false-comment shape as
    item 52, one door over, left standing by the commit that fixed item 52.**
55. **Rule 11 refined: search the class PACKAGE-WIDE, not only in the diff.** The item-52 fix ran
    its rule-11 self-check, scoped it to its own changes, and therefore could not see the two
    comments in `treekem.go` making the same false claim about the commit door. The class is the
    defect; the diff is only where the author happened to be standing. Added to the brief template
    as rule 11a.
56. **The gate written to enforce rule 5 enumerated its own scope.** Item 52's flagship test bounds
    *"every refusal `(*LeafNode).Validate` can answer"* with three hand-named bodies
    (`Validate`, `VerifySignature`, `validateLifetime`) while `Validate` delegates to five, so
    `errProfileCredentialType` and `errMissingRequiredCapability` escape the class entirely --
    both measured reachable through the new door with real inputs. The commit's summary claims
    *"Nine names"*; the class is at least eleven.
    Two further measured survivors from the same commit: both new rules can be narrowed to
    `updates[0]` with the suite green, because **every fixture carries exactly one Update** -- the
    p4 ValSem401 shape this file's own comments cite three times as what they guard against -- and
    the door's use of `effectiveExtensions()` is unobserved, dropping the erratum-8745 case its own
    header claims to own.

57. **The door class is now genuinely derived, and the proof is a fourth source.** Adding a fourth
    `LeafNodeSource` to the enum with no door **fails** the new gate -- which is the property three
    earlier rounds could not claim. It also distinguishes *"no door"* from *"an expectation that
    cannot fire"*: restoring `tree_sync.go`'s `ExpectedSource: leaf.LeafNodeSource` self-comparison
    is caught by name (*"passes an ExpectedSource this gate cannot read as a constant ... x != x"*).
    **The commit door is built and deliberately unwired.** `ValidateUpdatePathLeafNode` is declared
    at `treekem.go:1096`; every other production mention is a comment and every caller is a test.
    Verified by the owner. **p7 Task 18 wires it**, and `rulesThisPackageExportsAndNothingApplies`
    pins the awaiting-a-caller state, so this is sequencing rather than a hole -- but until Task 18
    lands, a received UpdatePath leaf is validated by nothing on any production path.
58. **The gate written to close the base-name-exemption class exempts by base name.**
    `leafValidationPositionsThatDoNotJudgeTheSource` is keyed by **file**, and `waivers[door.file]
    = door.position` is last-write-wins, so a SECOND waiving call of `(*LeafNode).Validate` inside
    an already-admitted file is admitted **with no reason of its own** -- while the map's own header
    claims call-site granularity in as many words (*"a call site that waives and is not named here
    fails"*). Measured: a second waiving call in `tree_sync.go` runs 1741/0/0; the identical call in
    `validate_proposals.go` fails immediately. `tree_sync.go` is precisely the file a later
    per-position tree door would be written in. This is the fourth instance of the base-name shape
    on this project, and the first inside the gate written to close it.
59. **Two residual limits worth knowing rather than fixing now.** The door gate's reading is
    syntactic, so a door made UNREACHABLE -- `if true { return nil }` in front of it -- leaves it
    green; every door happens to have behavioural backing today and nothing makes that a property
    of the class. And comment claims about WHO CALLS a door are ungated: a false header saying
    `MergeUpdatePath` calls the commit door survives the suite. All of that residual risk sits on
    the one door nothing calls, which is separately pinned.

60. **`ValidateCommit` decides SS12.4's path rule off a different field than the RFC names, and the
    two are never joined.** RFC 9420 SS12.4: `if len(commit.proposals) == 0 || pathRequired:
    assert(commit.path != null)`. The implementation is
    `if CommitPathRequired(in.List) && in.Commit.Path == nil` -- decided off `List`, while erratum
    8815 is decided off `Commit.Proposals`. Verified by the owner: `ValidateCommit`'s body never
    mentions the two together, and no invariant is stated between them. **So a commit whose
    proposals vector is EMPTY and whose path is nil -- the exact input SS12.4 asserts against -- is
    ACCEPTED whenever the caller hands over a non-empty `List`.**
61. **`ValidateCommit` panics on a malformed proposal instead of refusing it.** A `Remove` entry
    with a nil `Remove` arm reaches `validate_proposals.go:801`
    (`in.List.Removes[i].Proposal.Remove.Removed`), `:816`, and `proposal_list.go:393`
    (`self.GCE[0].Proposal.GroupContextExtensions.Extensions`) -- all unguarded arm reads, verified.
    The file's own `check()` doctrine is *"refused rather than dereferenced, so a missing argument
    cannot read as 'nothing collided'"*, and the newly EXPORTED aggregate is the first door that
    exposes those reads to a caller. Same class as item 40: a panic on peer-shaped input, reachable
    through an exported door. The precondition is stated in prose in ValSem200's header and
    enforced nowhere; `ValidateCommit` does not call `ValidateProposalList`.
62. **Neither erratum observably runs, and the extension-set preference is unobserved.**
    `validateCommitErrata` can be neutered to `return nil` with the full 6961-test suite green --
    the `Pending *ProposalCache` field the task added is **never set by any test**. Proven
    non-equivalent by probe (an uncached reference; a GCE installing an extension the path leaf does
    not support). Separately, deleting `effectiveExtensions`' preference for the commit's OWN
    GroupContextExtensions proposal also leaves the suite green -- and that branch buys the
    security-relevant property, a commit that installs an extension while publishing a path leaf
    that does not support it. **ValSem209 cannot cover it**: it walks `PostTree`'s members and the
    path leaf is not in `PostTree`, because the merge has not happened.
63. **`commitRefusalRoster` derives its owned half and hand-lists its borrowed half**, missing at
    least eight reachable sentinels. Measured: ValSem205's nil-provider refusal changed from
    `ErrNilCryptoProvider` to `ErrTreeMalformed` leaves the full suite green -- a rule about a
    missing provider reporting a malformed tree, invisible to both exclusivity sweeps. Rule 5,
    inside a gate written to enforce it, for the fifth time.

64. **CRITICAL -- `ValidateCommit` accepts a commit that removes its own committer, and two more
    SS12.2/SS12.4 rules besides.** Item 60's fix joined `List.All` to the commit's ProposalOrRef
    vector -- correct -- but **never joined the typed BUCKETS to `List.All`**, and four of the twelve
    rules decide off a bucket. Verified by the owner: `ValSem200` reads `in.List.Removes`, and
    `validateBucketsAgreeWithTheCommitOrder` **exists** at `validate_proposals.go:327` with exactly
    **one caller -- `apply_proposals.go:90`**. `ValidateCommit` does not run it.
    Probed on unmutated HEAD: `All=[selfRemoveOfCommitter]` with `Removes` empty and
    `Commit.Proposals = List.Refs()` -> **ValidateCommit returns nil**, while `ValidateProposalList`
    over the identical list refuses. Same shape bypasses ValSem208 (`All=[gce,gce]`, `GCE=[gce]`)
    and ValSem206 (an Add whose KeyPackage encryption key equals the path leaf's, `Adds` empty).
    **This is item 60's own class -- a rule decided off a field the door does not join -- one level
    down, in the same file, at the same door, introduced by the commit that closed item 60.**
65. **The fix's largest new construct is a loop nothing drives past entry zero.**
    `checkListResolvesTheCommitsVector` narrowed to `i < 1` leaves the whole suite green: all seven
    rows of its table build a base list of exactly ONE entry. The same commit's own file header
    states the doctrine it violates -- *"EACH RULE OWES A FIXTURE WHOSE FAULT IS NOT AT ELEMENT
    ZERO ... a fixture carrying one entry cannot tell a loop from a read of its head."* Third
    instance of the element-zero class in three consecutive p7 tasks.
66. **PreTree/PostTree remain interchangeable at three more reads.** `proposalValidationInput`'s
    `Tree: self.PreTree` (whose header argues at length that it must be the pre-commit tree), and
    both of `ValSem203PathDecrypt`'s filtered-direct-path reads, each swap to the other tree with
    the suite green -- because **every fixture makes PostTree a Clone of PreTree.** ValSem202 has a
    test for exactly this and ValSem203 does not; ValSem209's two reads are covered asymmetrically,
    the leaf read observed and the member walk not.

67. **A count join is not an identity join, and the two doors of this package read different
    fields.** Item 64's fix added `validateBucketsAgreeWithTheCommitOrder` to the door -- correct --
    but the join is a per-type **COUNT** (`inOrder[type] += 1` over `All` against
    `len(bucket.entries)`), verified by the owner. Every bypass therefore returns in
    **count-preserving** form:
    `All=[remove(committer)]`, `Removes=[remove(3)]` -> `ValidateCommit` answers nil, and
    `ApplyProposals` removes leaf 3 -- **the member applies a different commit than the one the
    transcript covers.** `All=[add colliding with the path leaf key]`, `Adds=[innocent]` -> nil, and
    application then installs a leaf whose encryption key is **byte-identical** to the path leaf key
    ValSem206 exists to refuse. Same for Updates, and for a GCE installing an extension outside the
    v1 profile.
    **Root cause: the buckets are independently-writable fields** (`Removes []CachedProposal`),
    and the readers disagree -- `apply_proposals.go` reads `list.Updates` at :127, `list.Removes` at
    :137 and `list.All` at :155, while validation reads buckets. Two representations of one thing,
    no identity relation, different consumers.
    **The fix is not a stronger check.** As with `VerifiedGroupContext`, the answer is to make the
    divergent state unrepresentable: the buckets become derived views of `All` rather than fields a
    caller fills in beside it. A check leaves the dual representation in place for the next reader.
68. **The establishment table certifies the strong claim while exercising the weak one.** Its
    generated rows say a bucket *"holds exactly the &lt;type&gt; proposals of the commit order"*, and
    every row's break EMPTIES the bucket -- the one shape a count catches. No row applies a
    count-preserving edit. So the gate written to end this class asserts a property its own drive
    cannot fail on. Also: the rows are generated but their FIXTURE is hand-written
    (`testCommitCarryingOneOfEveryBucket`), so a fifth bucket gets a row whose break empties an
    already-empty field -- it fails red, safely, but because the row is unusable rather than because
    anything is wrong.

69. **RULED by the owner 2026-09-02 -- key package distribution: Option B, a key-package store on
    the message server.** Closes ledger 44 and unblocks `CreateDirect`, `CreateGroupWithMembers`,
    `InviteMember` and `AcceptJoinRequest`. Chosen because it is the only option that serves the
    default user -- unlisted and offline -- and the only one that also closes the **Welcome delivery**
    hole (item 44a), which is on the CP3b chain and which nothing else closes.
    **Three things the amendment must state explicitly rather than leave to an implementer:**
    (1) the handle is derived from the identity **KEY**, never the principal; (2) the last-resort
    package's existence and its labelling, so a client can tell a user which kind of key their first
    message went under; (3) **the new disclosure class is a locked trade-off** and belongs in SS3 of
    this ledger, so nobody rediscovers why the message server carries an identity-adjacent index.
    The privacy argument accepted: this is precisely the weakness Signal has, and P1 fixes the target
    at "slightly better than Signal".
70. **RULED by the owner 2026-09-02 -- invite links: Option A for one-time, Option C for reusable.**
    Closes ledger 45. One-time links -- SS7.3a's stated default and the common case -- get a new
    derivation and encoding only, **no new server operation**. Reusable published addresses get
    revocation bound to membership, which only C provides. SS7.3a already describes the two as
    different things with different approval models. **Keep on purpose:** the server asserts a
    deposit is exactly `rendezvous_deposit_bytes`, so if the join-request body pads to
    `CONTACT_REQUEST`'s total, a contact request and a join request are **indistinguishable by
    length on the wire** -- a property worth having deliberately rather than by accident.
    SS13's A7 row must also be corrected: it currently promises a flow over mechanisms A6 does not
    deliver.
71. **RULED by the owner 2026-09-02 -- history grants: Option A, and ruled NOW because of the
    freeze.** Closes ledger 46. A grant record carries an X-Wing wrap of `storage_root[m..n]` to the
    grantee's device. **Timing was the deciding factor**: this is a `server_attachment` kind, so
    ruling it after A6 freezes the wire would make it a format BREAK rather than an addition.
    **Three things the amendment must state that no document states today:**
    (1) a grant conveys `storage_root[m..n]` and **nothing else** -- never `eph_root` for any epoch,
    so granted history contains no disappearing messages, live or expired, and the banner must say
    so (r3 finding 5, accepted 2026-08-12 and never applied); (2) **MASTER's `eph_root` exclusion
    list gains a fourth item** -- "never in a history grant" -- the other half of the same unapplied
    finding; (3) what makes it non-erasable **on the wire** and not only in a UI: the grant record is
    class `PERMANENT` so the retention sweep never prunes it, and `HistoryGrants` is projected from
    the record set rather than from a local flag. Spec C forbids a dismiss affordance, and a rule
    enforced only in a renderer is a sentence.

72. **There is a fourth level, and two proxies remain in the one function.** Item 67's derivation
    made the bucket divergence unrepresentable -- that holds. The vector/list join was then repaired
    on its **by-value** arm only:
    - **The by-REFERENCE arm still joins by a proxy.** It compares `cached.Ref` to
      `vector[i].Reference` and **nothing joins the proposal BODY the list carries under that
      reference to the body this member holds under it.** A `ProposalRef` is a hash over the framed
      proposal the SENDER named -- an identity for the cache's entry, not for whatever the list put
      beside it. Probed: cache holds a remove of leaf 2 under one ref; give the list's by-reference
      entry a fresh arm removing leaf 3, leaving `Ref`, `ByValue`, length, order and every per-type
      count untouched -> **accepted, and `ApplyProposals` removes leaf 3.** The repaired header says
      *"AN IDENTITY ON BOTH ARMS"*; it is one arm.
    - **Neither arm joins `CachedProposal.Sender`, and it decides a leaf.** Verified by the owner:
      `apply_proposals.go:131` is `result.Tree.UpdateLeaf(cached.Sender, ...)`, and the join
      mentions `Sender` **zero times**. The commit fully determines the field -- `Resolve`
      attributes a by-value proposal to the COMMITTER and a by-reference one to the sender the cache
      recorded -- so a commit carrying an inline Update whose list names leaf 2 **writes the
      committer's update into leaf 2.** The door's own fixture carries a state `Resolve` cannot
      produce (by-value Update with `Sender=1` under `Committer=0`) and is accepted, so no test
      observes the invariant either.
    Feasibility is established: a ~16-line join through `Pending.Cached` + `proposalOctets` +
    `subtle.ConstantTimeCompare` refuses the probe.
73. **The cost gate was reworded rather than tightened -- the same defect it replaced.** The test
    written to close item 67's "a bound that cannot be reached by the change it protects against"
    says its bound *"would catch ... a third encode per entry, or an arm that encoded inside a
    loop"*. **Both named changes pass the entire suite** (overApply 2.18 -> 3.86 and -> 4.6 against
    a bound of 8). Its companion `copies` assertion cannot move with cost at all -- 10.7, 13.4, 13.6
    across baseline/1.5x/3x -- so it is a structure check listed as one of "the two things that CAN
    fail". At the fixture's width of four proposals the bound needs roughly a tenfold regression.
74. **The unrepresentability gate derives its ROUTES and enumerates its TARGET.** It now follows
    every route reflect offers -- a genuine repair, and struct-wrapped, pointer and map-valued
    indexes are all caught by name. But it asks *"does this field reach the TYPE
    `CachedProposal`"*, while its own comment states the class as *"a second representation of one
    fact whatever it is called"*. **An index of POSITIONS is invisible**: `addsAt []int` filled in
    `NewProposalList`, kept in step in `Resolve`, answered by `Adds()`, passes every derivation gate
    and is caught only incidentally, by the source-establishment gate -- the exact "incidental red"
    the file's own comment dismisses as saying nothing about its property.

75. **The derived join landed and works; what is left is a DEGENERATE FIXTURE CORPUS, and it is the
    root cause of the last three rounds of survivors.** The vector/list join is now computed from
    what the consumers read and both probed divergences are refused. Every remaining finding
    reduces to one fact, measured by the owner:
    - **`grep -c 'Committer: LeafIndex'` over the whole `mls` test corpus returns ONE, and it is
      `LeafIndex(0)`.** So `Sender: self.Committer` cannot be told from the constant `LeafIndex(0)`.
      Proved non-equivalent: with `Committer = LeafIndex(1)` the join accepts `Sender=1` and refuses
      `Sender=0`, and both verdicts invert under the mutation. In a group whose committer is not at
      leaf 0, the mutated door refuses every honest inline proposal and accepts one attributed to
      leaf 0 -- which `apply_proposals.go:131` then writes into leaf 0.
    - **Exactly one leaf index above 255 exists anywhere in the corpus.** So the Sender
      comparator's width is unobserved: `AppendUint64` -> `AppendUint32`, and even a **one-octet**
      comparison, both leave the suite green. The gate that claims to hold it asserts
      `reflect.TypeFor[LeafIndex]().Size() > 8` -- a fact about the TYPE, with the comparator's
      octet count in prose.
    - The `Ref` row has **zero** observation: emptying its comparator to `nil` is green, because
      `subtle.ConstantTimeCompare(nil, nil) == 1`.
    **This is the same shape as the previous two rounds** -- "every fixture carries exactly one
    Update" and "every fixture makes PostTree a Clone of PreTree". Three consecutive rounds of
    survivors trace to fixtures that cannot separate the right answer from a constant. **The
    deliverable is the corpus, not the comparators.**
76. **A justification that is false in this build, currently unreachable.**
    `checkListResolvesTheCommitsVector`'s header omits a `ProposalType` comparison because *"the
    discriminant is the first field of a proposal's encoding, so a type disagreement is an octet
    disagreement"*. `proposal_wire.go:176-180` writes **`UnknownType`** as the wire discriminant
    while selecting the arm by `ProposalType`, so two proposals whose `ProposalType` differs encode
    identically -- measured, both to `000303bbccdd` under types 3 and 6. Not reachable today
    (`UnmarshalMLS` normalises, `NewProposalList` clones through the codec), but the join's safety
    rests on a normalisation in another file that no assertion ties to it, and
    `NewProposalList`'s documented `if err != nil { continue }` path keeps an un-normalised value
    verbatim.

77. **The corpus gate derives its WALK and enumerates its DIMENSION TYPES.** Item 75's hardening
    worked for leaf indices -- the committer, the senders and a leaf index above 255 now separate,
    and the four named survivors fail. But the gate names two types,
    `reflect.TypeFor[LeafIndex]()` and `reflect.TypeFor[*RatchetTree]()` (owner-verified), so every
    other dimension the door decides off is unmeasured -- **group id, cipher suite, version, epoch,
    clock** -- and that is exactly where five survivors live. Proved: a collapsed `Generation uint32`
    field added to `CommitValidationInput` leaves the gate PASSING and logging "11 fixtures, 5 leaf
    dimensions"; the same field typed `LeafIndex` fires. The derivation is real inside `{LeafIndex}`
    and absent outside it. Same shape as ledger 21, applied to types rather than files.
78. **Five live survivors, all in the collapsed dimensions.**
    - `in.Context.GroupId` -> `[]byte("group")` is **green**. Every `ProposalValidationInput` and
      `CommitValidationInput` in the package is judged under one group id, so the **cross-group
      replay** binding that function's own header exists to close is untested. Note the same struct
      literal's `LeafIndex: cached.Sender` IS separable, caught by six tests -- two fields of one
      context, one measured, one not.
    - **`ValSem105SuiteAndVersionMatch` and a constant are the same program.** The rule whose stated
      purpose is *"an Add's KeyPackage names THIS GROUP's ciphersuite and protocol version"*
      rewritten to compare against two build-time literals is green. Two suites are registered, so
      the dimension is live; no test ever gives an input a `Context.CipherSuite` other than the
      default.
    - The suite collapse repeats at two more call sites, and **`in.Now` and the machine wall clock
      are the same program** -- the two tests that move the clock are both on the door that ignores
      it.
79. **The proposal door has no corpus gate at all.** Owner-verified: zero `ProposalValidationInput`
    references in `fixture_corpus_test.go`, across **50** call sites of `testValidationInput`, 48 of
    which pass `LeafIndex(0)`. It hard-codes one group id, one cipher suite, one version, one epoch
    and one clock. **All five survivors above are in that corpus** -- so extending the gate to the
    proposal door is not the polish it looks like, it is where the live gap is.

80. **SEPARATION IS NOT DISCRIMINATION -- the deepest form of this class so far.** The corpus gate
    now derives its dimensions over both doors and every named survivor dies. It still measures the
    wrong thing: **every claim is stated over ONE path** (*"no path holds one value across the
    corpus"*) and **no claim is stated over a RELATION between two paths.** A corpus in which two
    dimensions are separately varied and **jointly degenerate** -- always equal, or always in a
    fixed relation -- is one in which a rule comparing them and a rule comparing one against a
    constant are **the same program**, and the gate is silent.
    Both surviving mutations are exactly that shape. `ValSem203PathDecrypt`'s self-exclusion
    `if in.Own == in.Committer` can become `if in.Own == LeafIndex(0)` **or `if false`** with the
    full suite green -- because `Own` is 0 and `Committer` is 1 in every default fixture, so the
    two are separated and never independent. The gate separates the `Own` dimension (0, 1, 257,
    258) and says nothing.
81. **The gate also names its POPULATION and its UNIT.** Population: it is stated over the 8 + 14
    registry rows, while the inputs the rules actually drive are built ad hoc -- **49 of 51
    `testValidationInput` call sites still pass `LeafIndex(0)`**, owner-verified, and the round that
    reported the figure changed none of them. So a perfect corpus and a door whose own tests are all
    pinned at leaf zero coexist. Measured consequence: ValSem111's `updates[i].Sender ==
    in.Committer` -> `== LeafIndex(0)` survived phase 1 entirely and died in phase 2 only to a gate
    about **bucket positions** -- luck, not design. Unit: one path, per item 80.
82. **A doc comment that is false against the line below it, twice.**
    `validate_proposals_test.go:214` reads *"testOwnLeaf is the leaf the member JUDGING these
    commits sits at, and it is neither zero nor the committer's"* -- and line 220 is
    `const testOwnLeaf = LeafIndex(0)`. `validate_commit_test.go:143` repeats the claim. **A reader
    auditing ValSem203's leaf-zero exposure is told by two files that it cannot exist**, which is
    how the seventh survivor stayed hidden. Same class as the two `treekem.go` comments in item 54.
83. **The measurement was generalised to both doors; the VERDICT was not.**
    `TestEveryProposalFixtureIsJudgedTheWayItsRowSays` drives all 8 proposal fixtures against an
    expected verdict; there is **no commit equivalent**, commit rows carry no `refuses` field, and
    **10 of the 14 commit fixtures are measured for dimension variety and never driven through any
    door.** All three confirmed survivors are commit-door reads. Varying a corpus nothing runs
    changes nothing.

84. **A derived class whose SIZE is not held shrinks silently.** The relation gate derives its pair
    class off the AST -- 14 pairs at the commit door, 6 at the proposal door -- and asserts
    non-empty, at least two input types, at least one pair each, and three shape flags. **None of
    those is a count.** So changing one `:=` to a `var` deletes **three of fourteen** pairs and the
    gate passes, its log moving from *"14 of 14 compared pairs are witnessed both equal and
    unequal"* to *"11 of 11"* -- **both read as success.** Routing one comparison through a
    package-local helper drops another (the borrowed comparator class admits only imported,
    exported, non-method functions). A derived class must assert its own size against something
    that does not move with it.
85. **The pin moved rather than vanished.** Item 79's fix moved 49 call sites off `LeafIndex(0)`
    **so that `updates[i].Sender == in.Committer` would stop being `== LeafIndex(0)`.**
    `testCommitterLeaf` is `LeafIndex(1)` and every proposal fixture reaching ValSem111 carries
    `Committer = 1`, so it is now indistinguishable from `== LeafIndex(1)` -- and the gate reports
    *"6 of 6 pairs witnessed both equal and unequal"* either way. Separability from ONE constant is
    not separability from EVERY constant. The sibling comparison on `Removes` IS caught, because
    `testWideCommitInput` puts the committer at 258.
86. **The relation claim is stated over the PAIR and not over the CLAUSE that reads it.** Two
    clauses of one rule that share a sentinel and share a single witness mask each other:
    `checkExtensionsAreTheSetThisCommitInstalls` has a type clause and a data clause, and the
    corpus's only differ-witness is a **swap of two entries**, which makes both pairs differ at
    once -- so either clause can be deleted with the corpus gate green. **The fixture's own comment
    argues the swap is the right shape because "rewriting one entry's body leaves every type
    equal"; that argument is inverted** -- making the data clause decidable requires types that
    AGREE and bodies that differ, which is exactly what the swap removes.
87. **The root class is the two input types, so the commit door's own central join contributes zero
    pairs.** `joinCachedProposals` compares the signed vector against the resolved list over every
    field of a `CachedProposal`, and `CheckUpdatePathKeyUniqueness` is ValSem207's whole body --
    both take `*CachedProposal` parameters, so `rootsOfType` finds no root and neither is in the
    class. Both are door logic, not neighbouring code.

88. **`Group` has landed, and p6 Task 20 is unblocked after four days.** `mls/group.go:167`
    declares it and the key schedule field is spelled **`schedule`**, so ledger 20 resolves in p7's
    favour: **Task 20's literal `self.keySchedule.Secrets()` (p6 plan line 6243) must become
    `self.schedule.Secrets()`**, and the plan's line 6185 naming the field `keySchedule` is stale.
    Six later p7 tasks -- 12, 13, 15, 16, 18, 19 -- can now proceed as well.
89. **`NewGroup` retains a live view over the caller's extension bodies, and the key schedule was
    derived over the original.** `group.go:272` is
    `append([]Extension(nil), cfg.Extensions...)`, which copies the `Extension` STRUCTS and not the
    `[]byte` each `ExtensionData` points at, and that slice becomes `self.context.Extensions`.
    Probed: writing into `cfg.Extensions[0].ExtensionData` after `NewGroup` returns changes what
    `GroupContext()` answers, and `GroupPolicy()` then fails with *"varint prefix 0b11 is
    reserved"* over a group founded with a perfectly good policy -- **while every epoch secret
    remains expanded over octets the group no longer publishes.**
    `Members()` has the same class three lines apart: `IdentityPub` is cloned and `SignatureKey` is
    not. And `GroupId: cfg.GroupId` without a clone also survives, because the existing gate reads
    only what a construction ANSWERS and `GroupId()` clones on the way out.
    The package's own row for this class takes four caller arrays and its comment says *"handed a
    caller's array in four places at once"* -- **the extension bodies are the fifth**, so the row
    passes vacuously over them.
90. **The relation gate is closed, on evidence rather than exhaustion.** Four more respellings of a
    COMPARISON shrink the derived class -- a tag switch, a closure, a type switch, an ambiguous
    callee -- each behaviour-identical and full-suite green. **But the reviewer read every `==`,
    `!=` and comparator call in the three door files and confirmed every path-vs-path equality is
    among the 25**, so none is live. **One genuinely live gap remains and is worth recording rather
    than closing:** eleven door rules compare two paths through a **map key** instead of an
    operator, and `validateSingleUpdateOrRemovePerLeaf` holds `List.Updates()[].Sender` against
    `List.Removes()[].Proposal.Remove.Removed` -- two differently-named paths of one input, exactly
    the shape the gate exists for, and not among the 25.

91. **MILESTONE: p6 is complete at 20 of 20.** Task 20 landed at `e98cecb` with both
    construction-bypass seams in **`framing_group_seams_test.go`** -- a test file, so the compiler
    keeps them out of every shipped binary -- and without reopening the excuse-map hatch. It had
    been blocked since 2026-08-30 on p7's `Group`, and the agent sent at it then committed nothing
    and said so, which is why the block was visible at all. All three corrections that agent earned
    were applied: the field is `schedule`, the file is `_test.go`, the hatch stays shut.
92. **The seam gate anchors on one identifier and misses the type that carries it.**
    `seamCandidatesIn` marks a parameter forgeable only when its type contains the Ident
    `FramedContentAuthData` -- but `AuthenticatedContent` **carries** that type
    (`framing.go:462`), and **both production seal entry points take it**
    (`SealPublicMessage`, `sealPrivateMessage`). So a bypass of identical power written over
    `*AuthenticatedContent` **ships in every binary importing mls** while the gate reports the
    package clean. Proved by controlled A/B: identical file, identical caller, only the parameter
    type differing -- the real seams fail five gates, the `AuthenticatedContent` version passes.
    The executor's rule-11 pass found the enumerated-SCOPE instance and closed it, and left the
    enumerated-ANCHOR instance standing.
93. **`(*Group).persist` hands the group's live group id to a caller-supplied store.**
    `group.go:637` is `self.store.PutGroupState(self.context.GroupId, ...)`, where `self.store` is
    an object the caller supplies and goes on holding. `GroupId()` clones on the way out for exactly
    this reason; `persist` does not. **The sdk writes these StateStore implementations**, and one
    that keeps the slice it was handed shares an array with the group for the group's lifetime --
    a store that writes through it rewrites the group id the epoch secrets were derived over.
    Neither gate sees it: both read method RESULTS, so an octet handed outward as an ARGUMENT is
    invisible.
94. **The caller-array gate walks the group BEFORE the call, so "answered cloned, retained
    afterwards" is structurally invisible.** Confirmed survivor: a method that clones its answer and
    then files the clone on the group leaves 7286 tests green. That is not hypothetical -- memoising
    `GroupContext()`'s marshalled bytes is the obvious next optimisation for Tasks 19/20 and lands
    exactly here. Related: the gate's scope half is a **parameter-spelling** match while its arrays
    half is a type walk at unbounded depth, so `NewProposalList` and `ParseRatchetTreeFrom` meet the
    property and are outside the class -- a real retention in `NewProposalList` was caught only by a
    hand-written test, i.e. by the enumeration this gate was meant to replace.

95. **A commit retuned a CONTROL so its own gate would stay green.** The seam-anchor fix changed a
    control member's parameter from `*MLSMessage` to `*FramedContent` **precisely so it would go on
    reading as a receiver negative once `*MLSMessage` became a carrier.** The control then certified
    an exclusion that had silently grown from `{FramedContentAuthData}` to the whole derived carrier
    closure. **A control that starts failing as a class widens is reporting that the class widened.**
    Now standing rule 12 in the brief template.
96. **The seam gate derives WHICH types carry an authenticator and then names the POSITION.**
    Owner-verified at `framing_group_seams_test.go:453-456`: the receiver is read only to build a
    NAME, and `forgeable` is set from `function.Type.Params` alone. **The rework made it strictly
    worse** -- the unprotected receiver set grew from `{FramedContentAuthData}` to the full carrier
    closure, so every type newly protected in parameter position became newly unprotected in
    receiver position. Confirmed with a production-file forge of identical power
    (`(*FramedContentAuthData).reviewSealUnder`) that seals under the group's real epoch keys and
    leaves 7294 tests green.
97. **The generator emits a proposal its own package refuses -- found by the test that asks it to.**
    `ProposeAdd` signs, seals and **caches** an Add carrying a signature key a member already
    publishes; `ValidateProposalList` refuses that same Add **as a one-entry list**, so the
    "cross-proposal rules are the committer's" defence does not cover it. `group.go:787-792` runs
    `kp.Validate` and `LeafKeysOf` and nothing else, while ValSem101 and ValSem103 are both
    decidable at generation time off the group's own pre-commit tree. **`ProposeRemove` DOES ask its
    equivalent question**, so the asymmetry is inside one file.

98. **REGRESSION: the seam gate derived the POSITION and paid for it by narrowing the DOOR.**
    `seamWireDoor` is the single name `"MarshalMLSMessage"`, and that function is five lines --
    a nil check and `return syntax.Marshal(message)` (owner-verified, `framing.go:1047`). So a
    production forge calling `syntax.Marshal` or `(*MLSMessage).MarshalMLS` emits **byte-identical**
    wire octets and the gate reports the package clean. **The pre-fix gate caught that forge; HEAD
    does not** -- the commit traded a body-mention read for a results-only read to buy the receiver
    widening. Measured: 13 production forges compiled in, 9 caught, the negative control correctly
    not caught, **3 survived**, and a full-suite run with a real forge plus its caller gave 7314
    PASS / 2 FAIL where neither failure mentions a construction bypass.
99. **The generator obligation is stated over proposal TYPES, not over generators.** It rests on the
    unasserted fact that all four generators funnel through `(*Group).propose` -- true today
    (owner-verified: four call sites) and enforced by nothing. A fifth generator doing its own
    framing, signing, sealing and `proposals.Store` **passes**
    `TestNoGeneratorOnThisGroupEmitsAProposalItsOwnDoorsRefuse` while putting 1670 octets on the
    wire over a proposal its own doors refuse. The four failures it did cause were all roster lines,
    none mentioning a validation door.
100. **DECISION: after the regression and the obligation are fixed, the seam gate is closed.** It is
    in its third round; each has traded one axis for another (anchor to door, position to door,
    types to generators), and it is test infrastructure for p8's forge rather than CP3b work. Its
    irreducible property -- "no production declaration forges a message" -- is a code-review
    property; **what the compiler actually enforces is that a `_test.go` file is not in any shipped
    binary**, and that already holds. So the gate keeps its derived position and its restored door,
    and gains the paragraph `constant_time_test.go` already sets the precedent for: **"What this
    cannot see, said out loud"** -- naming the stash-in-a-package-var shape and the ambiguous-helper
    edge. Same basis as the VerifiedGroupContext line at item 53.

101. **A pending commit's key material is never erased, on the ORDINARY path.** Owner-verified:
     `(*Group).Close` zeroizes `self.schedule` and `self.secretTree` and **never touches
     `self.pending`**, and `ClearPendingCommit` is literally `self.pending = nil`. A staged commit
     holds a **complete second epoch** -- a `*KeySchedule` (init_secret, confirmation_key,
     encryption secret, epoch authenticator, exporter, resumption PSK), its own `*SecretTree`, and
     the committer's freshly drawn leaf private key in `ownPriv` -- and nothing in the package calls
     `Zeroize` on any of it. Measured: all three compare **byte-equal after `Close()`**, and
     `staged.secretTree` is still non-nil. `ClearPendingCommit` is not an edge case; it exists for
     MASTER SS9.3's lost-commit race. This contradicts the discipline `StagedCommit`'s own comment
     invokes -- *"its erase is held by the type that DECLARES that storage"* -- since the staged
     schedule is declared by `StagedCommit` and held by nothing that erases it.
102. **A gate that fires on CORRECT code, which is worse than one that misses.** The generator
     obligation certifies `emitsAProposal` through `SealPrivateMessage` ->
     `marshalPrivateMessageContentWithPadding`, whose switch names **every** content type. So an
     exported `(*Group)` method that sends an **application** message is reported as *"puts a
     proposal on the wire and reaches ValidateProposalList through nothing"* -- measured, the test
     FAILS on it. Deleting the conjunct leaves the real scan green with the same four generators,
     so it does no work over real source and only the synthetic control needs it.
     Two more in the same gate: it is a **name-reachability** read, so `_ = ValidateProposalList`
     in a body certifies a generator that never calls it (measured, green); and it **names the
     position** (`candidate.receiver != proposalGenerationReceiver`), so a free function taking
     `*Group`, or a method on a type holding one, is outside the class -- the same defect the same
     commit fixed for the seam gate, reintroduced in its own new code.
103. **The seam gate is closed, per item 100.** The remaining escapes are recorded rather than
     built for: a generic door (`syntax.Marshal`/`MarshalLimit`/`MarshalMLS`) driven over a whole
     `*MLSMessage` handed in by the caller; a hand-written two-uint16 header plus the arm's own
     encoder, which emits byte-identical octets; and the package-var stash. Note the limits
     paragraph's own third bullet was measurably wrong -- **five** production declarations take
     `*MLSMessage` and **none** also takes a carrier that is not the door type, so
     "no derivation separates the two" is false and the predicate that separates them exists.

104. **The Welcome's joiner pairings are unobserved, because no fixture commits more than one Add.**
     `errWelcomeAddPairing` compares `len(adds) != len(self.added)` while its own comment says the
     divergence it guards *"would seal each joiner's group secrets to some OTHER joiner's init key,
     silently, with every length equal"* -- i.e. the comment names the class and the code checks the
     one thing that cannot see it. Two mutations pass: every joiner sealed to the FIRST Add's key
     package, and every joiner handed the same leaf index. **Same one-element fixture shape as the
     ValSem111 and element-zero survivors, now on the join path** -- the most security-critical
     surface in the plan.
105. **The erase class is seeded on types that DECLARE an erase, so a new key-material type is not
     in it at all.** Confirmed survivor: a production
     `type reviewPastEpochWindow struct { initSecret []byte; encryptionPriv HpkePrivateKey }` with no
     erase leaves the suite green, while the same type holding a `*KeySchedule` IS caught. The
     upward closure over holders works; **the seed is the gap** -- and the reviewer names the
     consequence: *"precisely the shape task 19's past-epoch window will take."*
     Two more in the same gate: an erase of ONE SUB-FIELD certifies the whole held value (the call
     resolves to the root field), and the drop-site gate's "refuses to overwrite a live one" arm is
     satisfied by **any** nil comparison including a PRESENCE guard -- the opposite of a refusal --
     which is the shape `MergePendingCommit` has today.
106. **The generator repair traded one under-report for another.** Narrowing "emits a proposal" to a
     literal `ContentTypeProposal` in value position rests on **one** production occurrence
     (`group.go:1187`), so a generator setting its content type from a variable -- re-framing a
     cached proposal -- frames, signs, seals and sends it with no validation door and is not
     reported. **The pre-fix name-based reading did report that shape.** The non-vacuity floor
     cannot see it either: four real proposers hold the count at the floor.

107. **A real production bug from the one-element fixture class: `(*LeafNode).Clone`.**
     `leaf_node.go:247` pairs `out.Extensions[i]` with `self.Extensions[i]`, and no fixture clones a
     leaf carrying more than one extension -- so `self.Extensions[i*0]` passes the whole suite.
     **A cloned leaf holding two extensions would carry entry zero's body in every entry**, silently
     replacing `required_capabilities` or the leaf-keys extension. It is the only index-paired clone
     loop in the package; the neighbouring `GroupContext` clone gate sweeps two entries and catches
     its equivalent. Fourth appearance of this class, and the first that is a defect in shipped
     production code rather than in a gate.
108. **`JoinFromWelcome` installs a signing key it never checks against the published leaf.**
     `group.go:2415` does `signer: SignaturePrivateKey(cloneBytes(keys.SignPrivate))` and nothing
     compares it to `keys.KeyPackage.LeafNode.SignatureKey`. **The package already has the
     derivation** -- `signaturePublicKeyOf` at `crypto_labels.go:525` -- and **both other doors that
     produce a leaf for this client use it.** So the join door is the one that does not.
109. **An over-claim written into the record itself.** The erase commit's message and its new
     `EpochSecrets` excuse row both state that the part-by-part reading *"now checks rather than
     infers"* that `(*KeySchedule).Zeroize` names all nine secrets. It does not -- the gate skips
     `KeySchedule` outright, and deleting one of the nine `zeroizeSecret` calls passes **both** gates
     under review, caught only by the field-by-field test the commit says it replaced. Related:
     the drop gate's refusal excuse is **position-blind** while its erase excuse is position-checked,
     so a nil comparison written AFTER an assignment excuses the unerased drop above it; and the
     erase seed excludes wire types wholesale, so **`KeyPackage.signPriv` -- a signature private key**
     -- is outside the class entirely.

110. **CRITICAL: `(*Group).ApplyCommit` installs any staged commit it is handed.** Owner-verified:
     it checks `Kind`, nil, `closed` and `RemovesSelf()` and **nothing about provenance** -- not the
     group id, not the epoch -- and it overwrites `self.pending` unconditionally where
     `CreateCommit` refuses with `ErrPendingCommitExists`. Measured: **group B applied group A's
     staged commit, moved from epoch 1 to epoch 2, and derived byte-identical epoch
     authenticators.** *(**"epoch 3" corrected to "epoch 2", 2026-09-07**, here and in `PROGRESS.md`'s
     2026-09-07 entry, which are the two places it was written. The number was never in the source:
     `connect/mls/commit_provenance_test.go`'s header says *"moved B out of epoch 1 into the epoch A's
     commit opened"* and carries no digit, deliberately. Measured through a `go test -overlay` that
     adds a case and edits no file in `connect`: the two-member fixture leaves both receivers at
     **epoch 1**, and `receiverA.ApplyCommit` of A's own staged commit moves A **1 → 2**. One commit
     opens one epoch. The 3 was carried in one agent's notes and repeated for weeks in both
     documents.)* `Processed` and its `Commit` field are exported and `connect/message` is
     documented as holding `Processed` values across a policy decision, so that is the expected
     caller shape rather than a contrived one.
111. **The index-paired class was measured properly and the previous pass had covered a fifth of
     it.** A derived AST scan -- loops indexing two different sequences by the same variable --
     finds **20 sites**; the round that claimed to have swept it named 6, of which only 4 are
     actually in the class, and **15 were never examined**. `(*GroupPolicyExtension).Clone`
     (`group_policy.go:555`) is a second uncovered member: `out.Roles[len(self.Roles)-1-i]`, an
     **order-preserving** mispairing with no zero entries, survives the full suite. Dormant only
     because that Clone has no production caller yet.
112. **A justification comment that is factually wrong, and it is blocking a one-call fix.** The
     join door leaves `keys.EncryptPrivate` unchecked, and the reason given -- in the production
     comment and repeated in the summary -- is *"the provider has no private-to-public operation for
     HPKE"*. `hpke.go:152-164` returns the private half as `HpkePrivateKey(priv.Bytes())` off an
     `*ecdh.PrivateKey`, so **the private key IS the raw X25519 scalar and the public half is one
     call away**, for both registered suites. `signaturePublicKeyOf` is the precedent -- a
     package-level derivation deliberately outside `CryptoProvider` -- and it applies verbatim. So
     the join door now holds the signing half against the published leaf and installs the encryption
     half against nothing, on a false premise.

113. **CRITICAL: persistence does not work for real groups, and the two-member corpus is why.**
     `groupStateBlob` carries `OwnEncPriv` and `RestoreSecret` and **no direct-path private state**;
     `LoadGroup` rebuilds through `NewTreeKEMPrivate`, which starts `PathSecrets` as an **empty
     map**. `DecryptUpdatePath` resolves the copath node at the common ancestor and `NodePrivateKey`
     answers only for the member's OWN leaf -- so **a member restored by `LoadGroup` in a group of
     four or more cannot process the next commit from the other side of the tree.** Persistence is
     the whole deliverable of Task 19 and it is green.
     **The root cause is the corpus, and it now explains this whole session's findings.**
     Owner-verified: **32 call sites use `testTwoMemberGroup`** and nothing larger exists except
     `testWideCommitInput` (5 uses). In a two-member group the copath is trivial and the member's
     own leaf answers everything, so `PathSecrets` is never consulted. **Every structural defect
     this session that needed three or more members to observe has been invisible** -- ValSem111,
     element-zero, the Welcome pairings, `(*LeafNode).Clone`, and now this.
114. **The provenance refusals' ORDERING is load-bearing and untested.** Moving the two new checks
     after the `RemovesSelf` arm is a four-line reorder that leaves the suite green -- and it lets a
     **foreign** staged commit **Close** a live group and destroy its key material. On HEAD
     `receiverB.ApplyCommit` refuses with the group ids named; reordered, it would Close B and
     answer `ErrRemovedFromGroup`. Both provenance fixtures use non-removing commits, so nothing
     goes red on the commit that reorders those lines.
115. **`ApplyCommit` installs an ERASED staged commit and answers nil.** A group id and an epoch
     survive `Zeroize`, so the new provenance pair passes. Measured through exported API only
     (`processed.Commit.Zeroize(); receiver.ApplyCommit(processed)`): the member advances to epoch 2
     with a **32-zero epoch authenticator**, then bricks on first use. **Two members that both took
     this path would compare equal.**
116. **Two gates keyed by a name rather than a site.** The staged-commit construction gate reads
     keyed composite literals and refuses `new(T)` and positional literals, but `var staged
     StagedCommit` plus field assignment is invisible -- **precisely the spelling that yields nil
     groupId and zero priorEpoch**. And the index-pairing gate is keyed by function name plus sorted
     sequence names, so a **second** mispaired loop added inside an already-named function is
     silently certified by the existing row; the loop/site discrepancy is logged and never asserted.
     Credit where due: the reviewer independently reimplemented the pairing rule and reproduced the
     same 19 sites key for key, and widening it added zero new ones.

117. **CRITICAL: a restored member reuses its AEAD nonces.** The four-member fixture worked -- it
     found something worse than the defect it was built for. The blob now carries `PathSecrets` and
     still carries **no consumed-generation state** (owner-verified: no such field, and
     `NewSecretTree(...)` is rebuilt at generation 0 at both call sites), so **a restored member
     restarts its sender ratchet at generation 0.** Measured through the exported API: live bob
     Protects twice, restored bob Protects, carol answers *"ratchet generation already consumed:
     generation 0, head 2"*.
     Two consequences: **(a)** every message a restored member sends is DROPPED by each peer until
     it burns past that peer's head, and the head differs per peer; **(b)** two different plaintexts
     are sealed under the **same (key, base nonce)** for that leaf and generation, with only the
     32-bit `reuse_guard` between that and an AEAD nonce collision. The ladder defect was a liveness
     failure; **this is key reuse.** *"No test in the package Protects after a restore."*
118. **The index-pairing repair is held by nothing and both claims about it are false.** The file
     header and the commit message both say the control now holds a colliding pair and that the two
     counts are compared. The control was **not modified** and contains no colliding pair, and
     `len(derived)` appears exactly **once** -- inside the closing `t.Logf` (owner-verified). The
     ordinal that was supposed to fix it is a confirmed survivor: neutralised, a second mispaired
     loop inside an existing function is still certified by the first one's row and the gate logs
     *"20 loops at 19 sites"* and PASSES. Rule 12 again -- a claim written into the record that the
     code does not support.
119. **Three smaller ones, all in code this change added.** A new `errGroupStateLadderOrder` exit
     from `UnmarshalMLS` drops fully-decoded key material -- `OwnEncPriv`, `RestoreSecret` and the
     whole path-secret vector -- **without erasing any of it**, and `LoadGroup`'s three defers then
     erase nil because `*self` was never assigned. A fifth erase survivor: `ownPriv.Zeroize()` on
     the Consistent-failure path is caught by nothing. And **the fixture SETTLES**, so it carries
     zero unmerged leaves and zero blank nodes at every size -- **no group fixture in this package
     ever puts a member in a resolution reached through an unmerged leaf**, which the size widening
     does not touch.
120. **My own "four or more" is wrong at five.** Measured over sizes 2..8: at five, **leaf 4 stands
     alone under the right subtree** exactly as leaf 2 does at three, so it enters every sender's
     commit at its own leaf and would have restored correctly with an empty ladder. The production
     comments and ledger 113 both say "a group of four or more"; the true statement is about a
     member having a copath node above its own leaf, which is a property of position, not size.

121. **The round trip catches ONE of the four defects this package shipped, and its header claims
     it catches all four.** Measured by reintroducing each: the cached Add is caught by the
     generator gates and **not** by the round trip, because the cohort only ever adds fresh valid
     identities. Three of the four are **unreachable by any arrangement that file builds**. The
     header says *"every case here has the same shape"* as the four -- an overclaim that would tell
     the next reader coverage exists where none does. **This is the right measure for a round trip**
     and it should be reported as a number, not a shape.
122. **A fixture was moved so it stopped covering the thing it covered.** The persist-before-handout
     in `sealAndRecordLocked` -- whose own comment calls it load-bearing, *"it runs before the
     caller is handed anything ... hands out a message whose generation nothing has recorded"* -- is
     observed by nothing: `_ = self.persist()` passes 7453 tests. The package's only refusing-store
     fixture had `store.refusing = true` **moved from before `CreateCommit` to after it** by the
     same commit, and `refusing = false` added before `ProposeUpdate`, so no test now runs a
     refusing store across any of the three seal sites. Rule 12, a second time.
123. **A restored member is permanently deaf to a busy peer, not merely missing a replay guard.**
     Measured on a settled four: alice Protects 1026 times, live bob opens all of them, bob restores,
     alice Protects once more -- restored bob answers *"generation too far ahead: generation 1026,
     head 0, bound 1024"*. `peekFor` refuses **without advancing the head**, so every later message
     from that peer in that epoch is refused identically: unbounded, epoch-long message loss. The
     shipped disclosure calls this *"a lost replay guard rather than key reuse"*, which is
     materially incomplete.
124. **`RestoreSenderRatchets` accepts the all-zero secret that `SenderRatchets` refuses to write.**
     The write side opens with `refuseIfErased` because a state written from an erased tree
     *"restores a member sending under a ratchet every party in the world can compute"*; the read
     side checks only **length**. Measured: two right-length all-zero secrets restore cleanly and
     `NextSenderKey` then hands out a key derived from a public constant. Related: the persisted
     ratchet vector is sorted only for determinism and **the sort is stochastically observed** --
     the 2-entry map iterates descending about 59 times in 500, so roughly **one persist in eight**
     would write a vector the strict-ordering read then refuses to load.

125. **BLOCKS CP3b — the device wrap has no body encoding and no stated seal, and `wrap.go` has no
     section in any spec.** §5.11 specifies the server-visible `WrapTag` — `{wrap_target_handle,
     epoch}` — and says nothing about the bytes inside `ct_body`. MASTER §8.2 says what a device wrap
     *carries* (`pq_secret[n]` and `eph_root[n]`) and not how it is laid out, framed or versioned.
     Worse, §5.11's own sizing (*"a device wrap (~1,210 B) … land in `size_bucket 2`, a `ct_body` of
     exactly 4,112 bytes"*) makes the wrap an ordinary record whose body goes through the record
     AEAD — **whose key comes from the `storage_root` the wrap delivers.** Either the wrap's body is
     sealed under the previous epoch's class key, which serves no joining member, or the X-Wing
     ciphertext is the seal and the record AEAD is a second layer under some other key. No document
     says which. A ruling must state the body's field list and framing with its `alg_id` (MASTER
     §7.1 requires one on every hybrid ciphertext); the key the wrap record's `ct_body` is sealed
     under, **separately for a continuing member and for a joining one**; and whether the X-Wing
     ciphertext sits inside the record body or replaces it. Blocks m1 Task 14 and therefore CP3b.
     Found 2026-09-04 while writing m1. Filed as m1 Open item M1-1.

126. **BLOCKS CP3b — `group_handle_key` and the joining epoch's `read_key` are said to travel "in the
     `Welcome`" and no mechanism carries them.** MASTER §8: *"It is delivered to a joining member in
     its `Welcome` alongside the group-context extension … A member that does not hold it cannot
     compute its own handle and therefore cannot write."* Spec A §5.7 says the same of `read_key`.
     Measured 2026-09-04: `grep -rn 'group_handle_key\|GroupHandleKey'` over the whole of `connect`
     returns **0**; `mls/extension.go` declares three URmessage extension types (`0xF001` group
     policy, `0xF002` leaf keys, `0xF003` owner successor) and none is this; and RFC 9420's `Welcome`
     carries a `GroupInfo` and a `GroupSecrets`, neither with a free-form slot. There is a second
     layer to it that neither sentence mentions: `group_handle_key = HKDF-Expand(storage_root[0],
     "gh/v1", 32)` needs **epoch zero's** `pq_secret`, which a joiner never had and which no wrap at
     its joining epoch carries. A ruling must name the carrier — a `GroupInfo` extension is the only
     slot in the v1 profile that is both authenticated and encrypted to the joiner — state its
     contents, and state its validation, because a `group_handle_key` accepted from an unvalidated
     field is an attacker-chosen `sender_handle`, and `sender_handle` is inside every AAD and every
     MAC in the system. Related and already filed: items 44 and 44a, the key-package fetch and the
     `Welcome`'s own delivery channel. Blocks m1 Task 16 and therefore CP3b. Found 2026-09-04 while
     writing m1. Filed as m1 Open item M1-2.

127. **OWNED 2026-09-06 — the client-side submit leg is `s2`'s, an sdk plan that has not been
     written.** The owner ruled shape **(a)** below, on the reasoning that `sdk` already owns
     transport and storage and that Spec A §8.2's `MessageStore` already declares
     `ReserveStreamIndex` and `StreamHighWater`, which is `message.StreamIndexReserver` method for
     method and which m1 Task 6 now only interfaces. So the item is no longer *"no plan owns it"*;
     it is *"the plan that owns it does not exist yet"*, and **`s2` is on the CP3b critical path**
     carrying two of the milestone's six external legs — the submit path and the durable
     `StreamIndexReserver`. m1's **O-5** is answered by the same ruling: `s2` inherits Task 6's
     interface, its five properties and its whole mutation set, `TestStreamIndexNeverReused`
     included. Shape (b) was rejected: it reaches the milestone sooner through a harness that is not
     the product's transport, so what it proves is the record half and not the client half. It stays
     **BLOCKS CP3b** until `s2` is written and executed. The problem as filed, which is what `s2`
     has to close, follows.

     CP3b is *"a message is private — the same path"* as CP3a, and CP3a's path ends
     at the message server. Measured 2026-09-05 over the m1 plan: `grep -nE 'Submit|transport|
     harness'` finds **no task producing a submit path**, and no task's Produces names one; every
     m1 task ends at a `*Record` in memory. The server half needs nothing new — `store` and the api
     layer serve `Hello`, `CreateGroup`, `Submit` and `Fetch`, which is leg 3 of the 2026-09-02
     chain review and was verified then. The client half is `sdk`'s — *"the transport binding, a
     send path and a receive path"* — and that review assigns it to **the two-to-four sdk plans that
     do not exist**; m1 does not touch `sdk`. The only other client-side sealer-and-submitter in
     either tree is this repository's own `harness`, which is `msgrepo`-local, held test-only by
     `TestTheHarnessIsReachedOnlyFromTests`, and whose doc comment says *"It does not encrypt."*
     A ruling must name the owning plan. Two shapes and they are not equivalent: **(a)** an sdk plan
     owns it and CP3b waits for s1 and for that plan; **(b)** an `msgrepo`-side integration test owns
     it — two `connect/message.GroupSession`s sealing, `harness` submitting and fetching, where the
     import direction already allows it — which reaches the milestone sooner and proves the *record*
     half rather than the *client* half, and requires changing a package whose doc comment is an
     argument for the absences it has. **(a) was ruled.** While it was open this was the largest
     thing m1 filed: every other open item it carries is a rule that is missing, and this is a
     milestone leg that is missing. Found 2026-09-05 repairing m1; filed as m1 Open item M1-42;
     owned 2026-09-06.

128. **RULED 2026-09-07 — `ct_head` is always sealed under the DURABLE class ratchet, whatever the
     record's own retention class. THE ITEM IS KEPT WHOLE BELOW, and so is item 152's objection,
     which was NOT beside it when it was ruled although item 152 asked in terms that it be.**

     **The ruling.** MASTER §8.1 stands as written and Spec A §5.3 is the document that changes
     (revision **A-20**): `RecordAeadHead` takes a `record_key` from the ladder rooted at
     `ClassKeys.Durable`, always; `RecordAeadBody` takes one from the record's own class ladder. For a
     `DURABLE` record the two are one ladder. Filed as m1 open item **M1-6**, which carries the same
     ruling.

     **The owner's reason, recorded because this item asked for a rule.** The head is always retained,
     so it is keyed by the class that is always retained. Under the reading this replaces, an `EPH`
     record's head would be keyed under a ratchet whose whole purpose is to be destroyed on schedule,
     so a **retained** header becomes unopenable at exactly the moment the body is meant to vanish.

     **The accepted cost, and it is this item's own second half.** A non-`DURABLE` record draws head
     and body from two ratchets, so one record's single `stream_index` covers two ratchet positions —
     which no document states. That is item **143**'s pin, and this ruling moves it from *owed* to
     **DUE**; item **169** is the concrete instantiation it creates and why 143 cannot take its own
     proposed form. **The bookkeeping half of this item is therefore not closed by the ruling; it is
     handed to 143 and 169.**

     **What the ruling does not reach, and it is the half item 152 owns.** The lift on m1 Task 11(a)'s
     refusal reaches `PERMANENT` and `MEDIA`. It does **not** reach `EPH`, and `messagegroup.SealRecord`
     keeps refusing that class under item **152** rather than under this one — see 152 for the
     argument, which is that `K_durable[n]` is destroyed nowhere and rides every recovery wrap. **The
     ruling's stated premise is also false for that one class:** *"the head is always retained"* holds
     for `PERMANENT`, `DURABLE` and `MEDIA` and does not hold for `EPH`, because Spec B §7.2 sets
     `ct_head = NULL` for `EPH(1..5)` at `prune_after`. Item 152 stays **FILED, NOT RULED**, and it now
     blocks A6 for the head ciphertext in the place this item used to.

     *Blocks after the ruling:* nothing in m1 wave 1; `EPH` sealing, through **152**; the ladder
     position, through **143** and **169**. m1 Task 15 is unblocked; m1 Task 14 is not.

     *The item as it was filed, which is what the ruling answers half of:*

     **BLOCKS CP3b — `ct_head`'s retention class is unruled, and m1's own refusal for it stops a
     wave-2 task.** MASTER §8.1: *"`ct_head` is always under the **durable** class, since it is
     always retained."* Spec A §5.3 hands `RecordAeadHead` and `RecordAeadBody` the **same**
     `record_key[i]`. For a `DURABLE` record the two readings coincide; for `PERMANENT`, `MEDIA` and
     `EPH` they are two keys from two ratchets, and one record then has one `stream_index` covering
     two ratchet positions. m1 Task 11 therefore makes `SealRecord` refuse every non-`DURABLE` class
     until it is ruled, which is right — and m1 Task 15 must emit the ratchet-tree snapshot, which
     §5.11 step 2 fixes as *"one `PERMANENT`-class record"*. So a wave-1 refusal blocks a wave-2 task
     on the CP3b path. The item was filed under the A6 wire-format freeze until 2026-09-05 on the
     reading that the freeze is months out; by the plan's own construction it blocks CP3b three tasks
     from the end of wave 2, and it is now the third schedule ruling beside items 125 and 126. It
     must **not** be closed by carving a `PERMANENT` exemption into `SealRecord`: the retention class
     is inside `AAD_head` and inside the `write_auth` preimage, so a snapshot written at a guessed
     class is wire-visible and unrecoverable after A6. Wire-visible. Found 2026-09-04 while writing
     m1, promoted 2026-09-05 while repairing it. Filed as m1 Open item M1-6.

129. **RULED 2026-09-06 — `connect/message` is split in two, and item 11 was the wrong diagnosis
     of the failure that forced it.** `TestEveryDependencyOfThisModuleIsOneSpecB22Allows` has been
     red since `c089bb3` with *"spec B §2.2 forbids these outright and this module reaches them:
     github.com/urnetwork/connect/mls"*. The 2026-09-06 entry below it read that as item 11's
     question — whether §2.2 says that allowing a package allows the module behind it —
     *"arriving as a failing test rather than as a hypothetical"*, and said it *"wants a ruling
     rather than an allow-list edit"*. **The first half of that was wrong and is corrected here.**
     Item 11 is about the ~204 packages of 31 modules that arrive behind `connect`'s root; this was
     one package of the **same** module reached by one import, and no rule about modules would have
     answered it. The second half was right, and the ruling is not a rule about §2.2 at all: the
     import was wrong.

     **Measured before the ruling, at `c089bb3`.** `go list -deps -test ./...` over this module
     names **exactly one** direct importer of `github.com/urnetwork/connect/mls` in a 481-package
     closure, and it is `github.com/urnetwork/connect/message`. Inside that package it is
     **`xwing.go` alone** — Spec A §5.4's four reviewed X25519 wrappers, `ErrNilRandomSource`, and
     two compile-time pins. `connect/mls/syntax`, which `aad.go`, `codec.go`, `attachment.go` and
     `writeauth.go` use, is separately allowed as of spec B revision 10 and is not the cause. This
     module names `Xwing` **zero** times, tests included.

     **The ruling.** `connect/message` keeps the server-safe half — the record, its codec, the two
     AAD preimages, the `write_auth`/`req_auth` MACs, the server attachment, the recovery proof and
     §12.1's rendezvous verifiers. `connect/messagegroup`, a **sibling** package, takes the client
     half — the key schedule, both ratchets, the stream-index reserver, X-Wing, the wraps, the
     session, the sealer, the cards, the client's rendezvous signatures and §6's engine. The
     property is a **capability**: the message server *cannot* link an MLS parser, rather than does
     not call one.

     *Blocks:* nothing in the plan; it is one commit in the `connect` tree and it is m1's wave 0.
     Until it lands the gate stays red, **and that red is expected and must not be silenced** —
     no allow-list entry for `connect/mls`, no skip, no known-failure marker. *Verified:* with
     `xwing.go` and `xwing_errors.go` moved in a working copy and nothing else changed, the gate
     passes with no edit to `allowedDependencies` and none to spec B. Filed as m1's ruling section;
     the split's own findings are m1 **M1-46**, **M1-47** and **M1-48**.

130. **`msgrepo/deps_test.go` allows `connect/message` as a *subtree* while its own comment says the
     list is at §2.2's granularity, and §2.2 states a package.** Measured 2026-09-06.
     `allowedDependencies` carries `{path: "github.com/urnetwork/connect/message", subtree: true}`
     (`deps_test.go:145`); the comment above the list (`:89`) opens *"The whole of what spec B §2.2
     ALLOWS, at the granularity §2.2 states it"* and adds that §2.2 *"names three packages of
     connect rather than connect as a whole"*. Spec B §2.2 writes
     `github.com/urnetwork/connect/message   (record parser, shared with spec A)` — one package —
     and `connect/mls/syntax` is a separate entry kept **exact** on the stated reasoning that *"a
     second child of connect/mls entering this closure is a different question, and it should fail
     this gate and be looked at rather than inherit an answer given to the codec."* The `message`
     entry takes the opposite treatment with no sentence saying so, and `connect/protocol` (`:144`)
     is in the same position with at least a generated-code argument in the comment.

     **This is the gap that made `connect/message/group` invisible**, which is the measurement item
     129's ruling rests on: under the subtree entry the message server could link the whole key
     schedule, both ratchets, the session and the sealer and this gate would say nothing. The
     sibling name `connect/messagegroup` routes around it; it does not close it, and the day
     somebody proposes a child of `connect/message` for any reason the gate is silent again.

     *Blocks:* nothing today — item 129's split does not depend on it. **This is an owner's call and
     is filed, not ruled.** Two shapes: make the entry exact, so a child of `connect/message` fails
     the gate and is looked at, which is what the comment's own rule says and what
     `connect/mls/syntax` already gets; or keep `subtree: true` and write the sentence that
     justifies it, so the next reader finds an argument rather than a widening. Found 2026-09-06
     while finishing the split. Filed as m1 Open item **M1-49**.

131. **Four files in this repository are mixed WITHIN THEMSELVES, and nothing here looks for it.**
     Recorded as Residual A of the 2026-09-10 entry below and **promoted to a numbered item here**,
     because a residual in an append-only log is a thing nobody is holding: the log is read
     forward once and the open items are what get worked. Re-measured on the tree this entry
     commits, unchanged: `docs/reviews/2026-08-12-r1-design-redteam.md` (1 CRLF line among 325),
     `r2-spec-review.md` (1 among 157), `r3-spec-review.md` (1 among 217) and
     `r4-three-spec-review.md` (1 among 156), against `*.md text working-tree-encoding=UTF-8
     eol=lf`. **A file mixed within itself is never a checkout** — git cannot produce one — so it
     is always a tool that wrote part of a file, and no pin can prevent it: `eol=lf` acts at
     checkout, and this happened after one.

     *Why it is filed rather than fixed.* Rewriting the four lines takes one command and closes
     nothing, because what is missing is the **observer**. `connect/mls`'s
     `TestThePackageSourceIsOneLineEndingThroughout` reports exactly this condition per file, and
     as of `connect` `b4e84f4` it also holds every file it judges to the ending
     `.gitattributes` pins, deriving that ending by reading the rule set nearest the file. This
     repository has no equivalent. What it has instead is defensive normalisation at every read —
     `deps_test.go`, `api/checks_test.go`, `api/gates_test.go` and
     `api/second_implementation_test.go` all strip the carriage returns before matching — which
     makes the anchors safe and makes the condition **invisible**. That is the opposite trade from
     `connect`'s, and which trade this repository wants is the question, not which four files are
     currently affected.

     *Blocks:* nothing. **Owner's call, filed not ruled.** Two shapes. Port the gate, deriving its
     requirement from this repository's own `.gitattributes` the way `connect`'s now does — which
     would give the `*.go`, `*.md`, `*.txt` and `go.mod`/`go.sum` pins a single observer instead of
     four unguarded statements, and would make deleting any of them fail a test. Or rule that
     defensive normalisation is the answer here and the four files are cosmetic, in which case say
     so where the next reader who opens a mixed file will find it, rather than in an edit-log
     residual. Found 2026-09-10 during the `*.go text eol=lf` ruling; promoted here.

132. **The fan-out has no coverage check, and `expected_wrap_count` has no upper bound.** Measured
     2026-09-12. `store/memory.go:720-724` opens a group for ordinary writes when the marker's
     `wrap_count` equals `row.expectedWrapCount` — **two client-declared numbers compared against
     each other**. Neither store ever counts a wrap record. `wellFormedEpochAttachment`
     (`memory.go:962`) bounds `expected_wrap_count` only at non-zero. The wrap index is deliberately
     **not unique** (`store/migrations.go:222-226`) and **nothing binds `sender_handle` to the party
     that submitted the record** — it appears in `api/submit.go` only as a copy and in
     `store/memory.go` only as a map key.

     Every member holds `write_key[n+1]`, in the clear, from the commit's plaintext `EpochAttachment`
     (`connect/message/attachment.go:155-157`). So: a decoy wrap can be landed at a victim's handle
     while the declared count still matches; any member can close a fan-out that never happened with
     one record, forcing a permanent `no_wrap` gap on everyone at once; and a committer declaring an
     `expected_wrap_count` of 0xFFFFFFFF freezes a group readable-but-not-writable **permanently**,
     with item 134 showing the only exit is a marker that lies.

     *Why this is filed here and not in m1.* **The single detector every M1-1 option offers against
     M1-22's omission attack is this count**, and it is correct while the coverage is wrong — so no
     M1-1 ruling means anything until it is fixed, and the fix is Spec B's. *Blocks:* the value of
     any M1-1 ruling. **Filed, not ruled.** *(**Unchanged by the 2026-09-09 `C3` ruling**, and the
     ruling makes this item's sentence load-bearing rather than hypothetical: `M1-1` is now ruled in
     full and this coverage defect is still not, so the detector the ruling's field list leans on is
     still wrong. The one thing the ruling adds is a second, independent detector for **one** of the
     failures — `u64(content_epoch)` in the body turns a misread into a refusal — which is not the
     omission this item is about.)* Found 2026-09-12 by the M1-1/M1-2 red team; see
     `docs/reviews/2026-09-12-m1-wrap-and-welcome-redteam.md` finding B.

     **Two interactions added 2026-09-13 by the owner's rulings, neither of which resolves this item
     and both of which change what its repair can be.**

     *From ruling 1, the resequence.* The recovery wraps now land **after** the `EpochComplete`
     marker, so `expected_wrap_count` names a set that has closed before they are due. Counting
     landed wraps at distinct handles before honouring a marker — this item's first proposed repair —
     therefore covers the device arm and the snapshot and **cannot cover the recovery arm at all**,
     whatever the server counts. Item 138 files what that leaves open.

     *From ruling 3, the device-wrap split.* A leaf now has **two** wrap records at one
     `wrap_target_handle` — a `PERMANENT` one and an `EPH(5)` one — by design and in the normal case.
     So *two wraps at one handle* is no longer an attack signature, and **a uniqueness constraint on
     `(group_id, epoch, wrap_target_handle)`** — this item's second proposed repair — would refuse a
     conforming fan-out unless it also takes the retention class. The repair is still available; the
     column list is not the one this item wrote down.

133. **Removal revokes nothing at the server layer, and two published claims are false.** Measured
     2026-09-12. `EpochAttachment.WriteKey` and `.ReadKey` are plaintext fields of every commit
     record. `Fetch` runs exactly four stages (`api/fetch.go`, `fetchStages`) — request shape,
     known-group, read-key lookup on `(group_id, read_epoch)`, `req_auth` — and **none scopes the
     returned records to an epoch**; `MemoryStore.Fetch` (`store/memory.go:217-255`) filters on
     `record_id` and the class mask and nothing else.

     So a member removed at epoch *n* fetches the commit that removed it under `read_key[n]`, reads
     `read_key[n+1]` and `write_key[n+1]` out of that commit's cleartext attachment, and chains
     forward with a fresh ninety-day window each time. With `sender_handle` derivable by any holder
     of `group_handle_key` (MASTER:650) and stream monotonicity unbounded on the jump
     (`memory.go:609-611`, no reset path in any spec), ~500 records at the maximum index permanently
     silence the entire membership.

     **False as published:** MASTER §8's *"A member removed at epoch n keeps metadata access only
     until epoch n's key falls out of that window"*, and §9.2's *"Revocation is by epoch rotation"*
     as it reads today. *Blocks:* nothing mechanically; it is a design change rather than an edit,
     and it decides one M1-1 option comparison — a removed member's residual read of the fan-out is
     not a discriminator between options when every option grants far more than reading. **Filed,
     not ruled.** Found 2026-09-12; review finding D.

134. **A stalled fan-out is terminal, not readable-but-not-writable, and a conforming client can
     cause one.** Measured 2026-09-12, and it is strictly worse than m1's **M1-22** as filed. When
     `pq_secret[n+1]` is lost: no member can write (`memory.go:582`, `REASON_EPOCH_INCOMPLETE`); no
     member can commit out, because a commit carries `AttachmentEpoch` and `exemptFromEpochComplete`
     (`memory.go:937-944`) exempts only `AttachmentWrap` and `AttachmentEpochComplete`; and past that
     gate it still fails, because `memory.go:578` refuses any record whose epoch is not the current
     one with `REASON_EPOCH_STALE`, so the escape commit must be submitted **at epoch n+1** and
     sealed under the class keys that were lost.

     **And no crash is required.** Spec A §5.12 / G10 mandate destroying `pq_secret[n+1]` on *any
     rejection* of a commit submission, while Spec B **§6.3** — anchor *"a retried identical commit
     returns `REASON_OK`, not `REASON_COMMIT_LOST`"*, cited as `spec-b:2234` until 2026-09-13 — makes a
     retried identical commit return `REASON_OK`. A timeout on a commit that actually landed therefore drives a **conforming** client
     to burn the secret for an epoch that is already open. Spec B's own sentence notices the adjacent
     hazard — getting idempotency backwards *"burns a `pq_secret`"* — and not that burning it after
     acceptance is unrecoverable rather than expensive.

     **A third copy of the false sentence.** *"they are all derivable from the epoch state every
     member holds"* is in **Spec A §5.11 step 6**, **Spec B §6.1 step 6's quoted sequence** and at
     **MASTER:852**. Every prior write-up reported two. *(Cited as `spec-a:1662` and `spec-b:2164`
     until 2026-09-13; both moved that day when the rulings landed, and the sentence is now step 6 of
     Spec A's sequence rather than step 5. The quoted string is the citation and the line number is
     not — `grep -rn -F 'derivable from the epoch' docs/specs/` re-derives all three, one hit per file.
     (The longer form of the sentence spans a line break in every document, so grep it short.)
     MASTER:852 still resolves, because MASTER was not amended; item 141.)*

     *(**Two corrections, 2026-09-14, both to this item's own citations and neither to what it
     files.** The resequence sweep of 2026-09-13 rewrote this sentence and moved Spec A's number from
     step 5 to step 6 and left **Spec B's at step 5**, which is Spec B §6.1's `no_wrap` step; the
     derivability sentence is **step 6 there too**, and the two documents' sequences are numbered
     alike. And the refusal above was cited `memory.go:581`, which is the `if`; the
     `return protocol.Reason_REASON_EPOCH_INCOMPLETE` is **`:582`**, which is what item 137, Spec A
     §5.11 and Spec B §6.1 all already cite — the off-by-one was this item's alone.)*

     *Blocks:* nothing mechanically. **Filed, not ruled.** Found 2026-09-12; review finding E.

135. **CLOSED — RULED by the owner 2026-09-13, carried in with ruling 2, and recorded as ruled on
     2026-09-13 in the review of that pass. The wrap is the only record class carrying no MLS frame,
     and MASTER §5.3's own signature rule has nothing to verify.** **Every wrap body is signed under
     the publisher's `identity` key and a client MUST NOT honour an unverified one** — Spec A §5.11
     part (4) is the normative text. **Half of that is existing policy and half of it is new, and the
     halves are named apart because Spec A first published the whole of it as *"not new policy"*,
     which understates it:** for the **recovery** wrap it is MASTER §5.3:441 applied where it already
     applied, since that record carries a `RecoveryTag`; for the **two device-wrap records** it is a
     **new normative obligation**, because they carry a `WrapTag` and no `RecoveryTag` and no document
     required a signature over them before. 64 octets into `size_bucket 2`'s existing slack, so it
     costs nothing on the wire. The item is kept below with the problem it stated, because an item
     that vanishes is an item somebody files again.

     *The problem as filed, kept:* MASTER **I5** (`:248`) gives sender authentication to MLS and says
     the storage layer adds no second signature; **I8** (`:254`) requires every field a client validates
     to be inside the MLS payload or covered by `write_auth`; and Spec A **§2.4** — anchor
     *"`write_auth` is **zero on read**"* through *"A client MUST NOT verify `write_auth` on a fetched
     record"*, cited as `spec-a:300-303` until 2026-09-13 — empties that second arm on the read path. A wrap's body is `hybrid_ct` and carries no MLS frame, so **no field of any wrap satisfies
     I8** under any of the three M1-1 options.

     MASTER §5.3 (`:441-443`) already states the rule that would fix it — *"A client MUST NOT honour
     a `RecoveryTag` on any record whose `RECOVERY_PUB` body signature it has not verified under the
     publishing member's `identity` key"* — and every **recovery wrap** carries a `RecoveryTag`. So
     every option as written publishes ~500 records per epoch that §5.3, in its own words, says a
     client MUST NOT honour. *Blocks:* M1-1's ruling should carry the answer; the recommendation in
     the review is to sign every wrap body under the publisher's identity key, at 64 octets in 2,886
     octets of existing slack. **RULED 2026-09-13**, as stated at the head of this item — the ruling
     adopted exactly that recommendation. It was carried into Spec A §5.11 by the 2026-09-13 pass
     while item 137 and this item still read *"filed, not ruled"*; that contradiction — a normative
     MUST whose own ledger said it had never been decided — is what the review of that pass found, and
     resolving it in this direction is what the owner's ruling 2 actually did. Found 2026-09-12;
     review finding C.

136. **CLOSED — RULED by the owner 2026-09-13. MASTER §8.1's disappearing-message guarantee is a
     property of behaviour, not of cryptography, and the split that makes it cryptographic is
     adopted.** The device wrap becomes **two records**: a `PERMANENT` one carrying `pq_secret[n]` and
     an `EPH(5)` one carrying `eph_root[n]`, at the same `wrap_target_handle`. Written into Spec A
     §5.11 and §5.10, Spec B §3.5 and §6.1, and m1 Tasks 11, 13, 14 and 15. The accepted cost is the
     one this item named — the device-wrap count doubles, 2,000 rather than 1,000 at the design
     target, and `expected_wrap_count` becomes `2 × device_leaves + 1` — plus two the ruling exposed
     and item 132 and item 140 now carry. The item is kept below with the problem it stated, because
     an item that vanishes is an item somebody files again.

     `eph_root[n]` rode in the **device wrap**, which is `PERMANENT` and prunable **never**
     (Spec B **§3.5**'s storage table, the `PERMANENT` device-wrap row — cited as `spec-b:907` until
     2026-09-13, when the row moved and was split in two; grep the row, not the number), encapsulated to a device X-Wing key that never rotates — `ProposeUpdate`'s own
     header (`connect/mls/group.go:1613`): *"The device wrap key is read off the leaf being REPLACED
     and re-encoded, so an update publishes the same `urmessage_leaf_keys` the group already wraps
     to."* One device key obtained once opens every retained device wrap for every epoch, hence every
     `K_eph[n][b][t]` that ever existed. §8.1's *"after the timer, retained server ciphertext, a
     seized device, a newly provisioned device, and a seedphrase holder all fail to decrypt"*
     therefore holds only while every party that ever held an EPH ciphertext deleted it. §8.1 already
     calls this *"the most easily broken property here."*

     The construction that would make it cryptographic — split the device wrap into a `PERMANENT`
     record carrying `pq_secret` and an `EPH(5)` record carrying `eph_root` — is offered inside M1-1
     Option 1's failure list and left unchosen. It doubles the device-wrap count (2,000 rather than
     1,000 at the design target) and changes `expected_wrap_count`'s shape, so it **cannot be
     deferred past the M1-1 ruling** and interacts with item 132. *Blocks:* nothing mechanically; it
     was a sizing decision. **RULED 2026-09-13**, as stated at the head of this item. Found
     2026-09-12; review finding F.

137. **RULED by the owner 2026-09-13 — three of the five M1-1/M1-2 questions. The device wrap's seal,
     its record count and the fan-out's order.** This is the anchor entry; the normative text is Spec
     A §5.11 and nothing here restates it normatively.

     **Ruling 1 — the fan-out is resequenced: recovery wraps land AFTER the `EpochComplete` marker**,
     as ordinary records of the now-open epoch, rather than before it. Finding A is confirmed:
     `exemptFromEpochComplete` (`store/memory.go:937`) exempts exactly `AttachmentWrap` and
     `AttachmentEpochComplete`, `AttachmentRecovery` is refused `REASON_EPOCH_INCOMPLETE`
     (`memory.go:582`), and `store/contract.go:2555` derives that class from the declared kinds **in
     both directions across both stores**. The alternative — exempting the kind — was rejected for
     reversing a green derived assertion. **Nothing in the store gate changes and that contract test
     stays green as written; verified by reading both, not assumed.** *The accepted cost, written into
     §5.11 itself and not only here:* `expected_wrap_count` becomes **decorative for the recovery
     arm**, and **nothing detects a missing recovery wrap** — item 138.

     **Ruling 2 — the device wrap is sealed under an MLS-exporter envelope**, `env_key[k] =
     MLS-Exporter("URmessage/v1/envelope", "", 32)` at the wrap's own epoch, over §5.3's existing
     record ladder. The only outer key neither the message server nor a member removed at that epoch
     can derive. **Two things follow as consequences and were written as consequences with their
     reasons, not as second rulings.** (i) The **recovery wrap cannot use the envelope**, by necessity:
     its only intended reader has no MLS state and no `storage_root` **by definition** (MASTER:818),
     so it is KEM-sealed — and it carries the review's repair, a real head keyed
     `HKDF-Expand(wrap_key, "wraphead/v1", 56)`, because a zero-length `ct_head` is refused by the
     shipped server four ways. (ii) The **past-epoch caching obligation is live and is the accepted
     cost**. Verified against `connect/mls` before writing: `(*Group).Export` (`group.go:821`) reads
     `self.schedule`, the current schedule; `grep -rn 'ExportAt'` over the whole of `connect` returns
     **0**; `PastEpochWindow` is **32** (`key_schedule.go:30`). The consequence is stronger than 32
     suggests and §5.11 states it in the strong form: `env_key[k]` is computable **only while the
     group is at epoch k**, because no published API reaches a past epoch's exporter. §5.11 specifies
     who caches, for how long, where, and what a client does on a miss — and **the honest answer to
     the last is that a missed window is unrecoverable** for that epoch's `storage_root`; item 139.
     **A signature over every wrap body under the publisher's `identity` key** is carried in with the
     ruling as the review asked. **It closes item 135, and it is not wholly "existing policy":** for
     the recovery wrap it is MASTER §5.3:441 applied where it already applied, and for the **two
     device-wrap records it is new normative policy ruled here**, because they carry a `WrapTag` and no
     `RecoveryTag`. This paragraph first read *"as MASTER §5.3:441's existing rule applied where it
     already applies"*, and the paragraph below listed 135 as still filed — a normative MUST in Spec A
     against a ledger saying it had never been decided. Corrected 2026-09-13 in the review of this pass.

     **Ruling 3 — `pq_secret` is split from `eph_root`.** Two records: a `PERMANENT` one and an
     `EPH(5)` one. Closes item **136**. *The accepted cost:* the device-wrap count doubles and
     `expected_wrap_count`'s shape changes. **What the count now counts, worked out here because the
     review says it cannot be deferred past this ruling:** `2 × (active device leaves) + 1`, covering
     **both** device-wrap record kinds and the snapshot and **no** recovery wrap — 2,001 at the design
     target. Reconciled with ruling 1: the field is a true statement about the device arm and the
     snapshot, and says nothing whatever about the recovery arm, which is what "decorative for the
     recovery arm" means precisely.

     **What is NOT ruled and stays open.** Where `group_handle_key` lives — deliberately deferred, and
     **CP3b is not blocked by the deferral**, because ledger 44a's already-blessed gated test-only
     hand-off can carry it **provided** the hand-off's own doc comment says it is not the production
     carrier; that proviso is written into m1 Task 16 as Property 5 with a mutation, as a requirement
     on whoever builds it. Items **132–134** stay filed and unruled; 132 gains two interactions from
     rulings 1 and 3, recorded in 132 itself. (**135 does not stay filed**: the signature carried in
     with ruling 2 *is* 135's answer, and 135 is now recorded CLOSED. This paragraph said *132–135*
     when it was written, which is the contradiction the review of this pass found.) And one fact the review treats as an unknown is not one:
     **`git grep -n 'KeyPackage' -- '*.go'` over `msgrepo` returns 0**, and the measurement is stated
     here **with its scope**, because the scope is what carries the argument: **no Go code in this
     repository names a key package, therefore there is no key-package store, therefore this is a
     requirement to write and not a fact anyone can measure.** *"Does it authenticate a served package
     against the claimed identity's signature key?"* has no answer to look up; it has an answer to
     specify, before the store exists, which is cheaper than the review's ranking assumed.

     *The unscoped form does not reproduce, and since 2026-09-14 it is not published as a count at
     all.* The brief that carried this ruling stated it as `grep -rn 'KeyPackage'` over the whole of
     `msgrepo` returning **0**; the whole tree is not 0 and never was. **What stands in its place is
     the property, with the query beside it**, because a property is checkable at every future commit
     and a count over a moving tree is not:

     - `git grep -l 'KeyPackage' -- '*.go'` names **no file**. *No Go file in this repository
       references `KeyPackage`* — the measurement that carries the whole argument, true until a Go file
       does, which is exactly when a reader should notice.
     - `git grep -l 'KeyPackage'` names **documents only** — plans, reviews, Spec A, `PROGRESS.md`,
       this ledger and the JSON findings file, and no `.go` file among them. That is the property the whole-tree count was
       standing in for, and it does not move when a paragraph is added to one of them.
     - The scope `-- '*.go' '*.proto'` is **half vacuous and is not the one to use**: `git ls-files
       '*.proto'` names no file, so that half of the scope asserts nothing about anything. `'*.go'`
       alone is the scope. (`key_package` over `'*.go'` names no file either.)

     **The count is dropped rather than corrected a third time, and the reason is worth the sentence.**
     This paragraph first published **456** — the count at `2cbbb71`, the **parent** commit: a
     pre-commit number published post-commit. The 2026-09-13 review corrected that to *"Measured at
     `7fb0dd9`:"* **464** *"matching lines across 15 files"* — and `7fb0dd9` is the parent of `7681f4c`,
     the commit that published the 464, **so the correction reproduced the error it was correcting**.
     *(The quotation was itself repaired 2026-09-15. It read* **"464 matching lines across 15 files,
     measured at `7fb0dd9`"** *as one quoted string, which is the sentence's two clauses in the reverse
     order — a paraphrase presented as a quotation, and `grep -F` returns zero hits for it anywhere,
     including in the revision it quotes. The rule this very paragraph states is that a citation is its
     quoted string; a re-ordered quotation is a citation that resolves to nothing.)* A
     measurement between two named commits is the form worth writing down: at `7681f4c` the same query
     gives **468**, four more than the number that commit published about itself. Naming the commit a
     count was measured at does not save it when that commit is not the one publishing it, and the
     third instance of one failure is a rule rather than a fourth number. **The rule: publish the query
     beside the value, and prefer a property over a count wherever one carries the same argument.**
     Corrected 2026-09-14; first corrected 2026-09-13 in the review of the rulings pass.

     *Blocks:* nothing further of its own. m1 Task 14 is still blocked on M1-1's remainder — the wrap
     body's field list beyond MASTER §8.2, the signature's placement, and M1-7's padding — and on
     **M1-6**, which after ruling 3 blocks Task 14 as well as Task 15, because every record the fan-out
     writes is now non-`DURABLE`. *(**M1-6 was ruled 2026-09-07** and the lift reaches `PERMANENT` and
     `MEDIA`, so Task 15 is through and Task 14 is not: its `EPH(5)` `eph_root` wrap is refused under
     item **152** now, and both tasks additionally owe the pin of items **143** and **169**.)*
     *(**2026-09-09, and this parenthesis was superseded the same day it was written:** `M1-1`'s
     remainder — the field list, the signature's placement and coverage, and `M1-7`'s padding — first
     got an options amendment at item **175**, recording all twenty-one shapes the three independently
     produced option sets offered, composing them against each other, and filing the five things they
     disagree about as items **176** through **180**; and it was then **RULED, as composite `C3`**,
     which is the head of item 175. **So `M1-1` and `M1-7` no longer block Task 14 and the *Blocks*
     line above is stale in exactly that respect: what blocks Task 14 is item 152, alone.** This
     ruling of 2026-09-13 is unchanged by either the options pass or the ruling.)*

138. **Nothing detects a missing recovery wrap, and after the 2026-09-13 resequence nothing can
     without a change item 132 owns.** Filed as the named cost of ruling 1 rather than discovered.
     `expected_wrap_count` cannot see one: it names a set that closed when the marker landed, and the
     recovery wraps are published after that. §5.11 **step 5** — *the `no_wrap` step*, step 4 before
     the resequence — cannot either: it is keyed on
     *"after the marker has landed"*, and after the marker an absent recovery wrap is
     indistinguishable from one not yet published. No live member notices, because no live member
     reads its own recovery wrap on any normal path — its reader is a seed-only restorer, by
     definition not present when the wrap is due. And the server cannot, for item 132's reasons.

     **So a missing recovery wrap is discovered at restore time, by the party least able to act on it,
     potentially years later, and by then that epoch's `storage_root` is unrecoverable for that
     member.** A conforming committer that dies after the marker and before the recovery leg produces
     exactly this, with a fully writable group and no signal to anyone — **and so does one that does
     not die**, because after the marker the group is writable and another member's commit strands the
     rest of the arm under `REASON_EPOCH_STALE`. That second producer is **item 142**, found in the
     review of this pass, and it is why this item is not a rare-crash item. *Blocks:* nothing
     mechanically. **Filed, not ruled** — the repair is a coverage check the server can actually make,
     which is item 132's and is not m1's. Found 2026-09-13 while writing ruling 1 into §5.11.

139. **A client that misses the `env_key` window cannot recover that epoch's `storage_root`, and
     `GapReason` is a closed set with no member for that failure.** Filed as the named cost of ruling
     2. `env_key[k]` is computable only while the group is at epoch *k*; a client that merges past
     epoch *k* without exporting and caching, or that restarts before persisting the cache, loses
     `storage_root[k]` permanently — with it every class key of that epoch, every record sealed under
     them, and that epoch's snapshot under `K_snapshot[k]`. It is not locked out of the group:
     `read_key[k]` and `write_key[k]` arrive in the clear in the commit attachment.

     §5.11 requires the failure to be **visible** and forbids a silent skip or a retry loop, and
     stops there deliberately, because `GapReason` is a **closed set of six** — `"expired"`,
     `"out_of_window"`, `"not_a_member_yet"`, `"withheld"`, `"no_wrap"`, `"malformed"` (Spec A §7.4) —
     and none of them is this. Whether one of the six carries it or the set gains a seventh is a
     published-surface change and was **not ruled**. *Two things would change the answer and neither
     is decided:* an `ExportAt` on `connect/mls` bounded by `PastEpochWindow`, which does not exist
     today; and the review's Part 5 item 2 — whether §5.4's provisioning bundle gives a linked device
     the master key, in which case that device could open its **own recovery wrap** at epoch *k* and
     obtain `storage_root[k]` outright. Nothing in the corpus states the second either way, and every
     option write-up missed it. *Blocks:* nothing mechanically; m1 Task 14 Property 8 is written
     against the requirement as it stands. **Filed, not ruled.** Found 2026-09-13.

140. **The `eph_root` wrap's EPH(5) rung is measured from its publication, not from its epoch's end.**
     A consequence of ruling 3, filed because it is a real availability edge and not a defect in the
     ruling. The `eph_root` device wrap is published at the start of epoch *n* on the EPH(5) rung —
     2,419,200 seconds, twenty-eight days — while an EPH(5) **record** written later in the same epoch
     expires later. A device that has not opened the `eph_root` wrap before the server erases its body
     loses the tail of that epoch's ephemeral traffic, and the gap widens with the epoch's lifetime.
     Whether the wrap's rung should instead track the epoch's own lifetime is **not ruled**; lengthening
     it trades away part of what ruling 3 bought, and shortening it is worse. *Blocks:* nothing.
     **Filed, not ruled.** Found 2026-09-13 while writing ruling 3 into §5.11.

141. **CLOSED 2026-09-18 — MASTER is amended, and the location list was short a THIRD TIME: four
     named, SIX found — and a FOURTH time, because the query published to stop that finds four of the
     six and a SEVENTH location existed. Both are repaired 2026-09-19 and the item stays closed.** The three rulings of 2026-09-13 are now in MASTER §8.1, §8.2 and §8.3, under
     an *"Amendment to revision 9"* entry in §0. Re-run this item's own query and the eight
     `EpochAttachment` field declarations are still **byte-identical** across the three documents,
     while MASTER's `expected_wrap_count` annotation's first four lines are now byte-identical to Spec
     A's and diverge only in the cross-reference — the form `read_key`'s annotation already uses
     legitimately in each document. **The one normative divergence this item existed for is gone.**

     **The two the list missed, and both are the same shape as the fourth: not a stale NUMBER but a
     CLAIM the ruling makes false.**

     - **MASTER §8.2 step 4's detector was unscoped.** It read *"A member or device that finds no wrap
       for its target at epoch `n+1` after the marker has landed surfaces a `gap` entry with reason
       `no_wrap`"* — no qualifier — so it claimed for the recovery arm precisely the detector ruling 1
       removes, in the same numbered list whose step 2 this item already flagged. Spec A §5.11 step 5
       scopes it to the **device** arm and the snapshot; MASTER now does too. This is worse than a
       stale figure: a reader of MASTER alone concluded a missing recovery wrap is detected, and item
       **138** is the record that nothing detects it.
     - **A SECOND copy of the pre-split sizing, thirteen lines outside the sizing paragraph.** §8.2's
       indexing requirement closed *"Without this a 500-member group makes every join a 6.9 MB
       download"* (`:875`). A pass that edited only the paragraph this item's third bullet names would
       have left it standing.

     **Why the list was short, stated so the next one is not.** All four bullets resolved exactly —
     the item was right about everything it said. It was built by looking for where the rulings change
     a **number**, and both misses are places where the rulings change a **sentence's truth value**.

     **AMENDED 2026-09-19 — THE QUERY PUBLISHED WITH THAT DIAGNOSIS FAILS THE DIAGNOSIS. It finds
     FOUR of the six, and the two it misses are the two this item's own headline names.** As published
     it was
     `grep -nE 'no wrap|6\.9 MB|1,000 device|1,503|~55 round|device wraps \+ recovery wraps'`,
     offered as the artefact that *"answers all six locations and costs one command"* — and it was
     never run against that claim. Run against it: it hits the `no_wrap` detector, the sizing
     paragraph, the join-cost sentence and the `expected_wrap_count` annotation, **misses §8.2's
     payload table and the fan-out's step 2** — *the single-record device wrap and the pre-ruling
     fan-out*, which is verbatim what this item is titled after — and returns one line
     (`:371`, *"appears in no wrap"*) that is none of them. **Five of its six alternations are
     numbers**, so it is the number-shaped query the diagnosis one paragraph above says cannot find a
     truth-value change. A query offered as an artefact and never run against its own claim is the
     same defect as a gate that reports clean having read nothing.

     **The derived query, built from the rulings' SUBJECTS rather than from the answers.** Each
     alternation is one thing a ruling changed the truth of, not one value it changed: *a device wrap
     carrying both secrets* (ruling 3), *the recovery arm inside the device arm's set* (ruling 1),
     *the omission detector*, *what a join costs*, and *whether this layer signs* — the last being the
     seventh location, below.

     ```
     grep -nE 'pq_secret.*eph_root|device wraps? .*recovery wraps?|recovery wraps? .*(device wrap|snapshot)|no_wrap|finds no wrap|every join|adds no signature'
     ```

     **The verification, published beside it, because that is the half this item got wrong.** Over
     MASTER at `bed5b84` — the last commit before the amendment, which is the only tree where all
     seven are still false — it returns **nine lines in exactly seven locations** (hits within two
     lines of each other are one location) and **zero lines outside them**:

     ```
     item 141's published query: 4/7 locations, 1 line outside all seven
       MISS L1 signature (:741)          MISS L2 payload-table (:806)
       MISS L3 fanout-step2 (:841-844)   HIT  L4 no_wrap-detector (:848-850)
       HIT  L5 sizing (:854-864)         HIT  L6 join-cost (:873-875)
       HIT  L7 attachment-annot (:912)
     the derived query:          7/7 locations, 0 lines outside all seven
     ```

     **THE SEVENTH LOCATION, found 2026-09-19 and now fixed.** MASTER §8 said flatly *"Per **I5**,
     this layer adds no signature"* while §8.2, rewritten by the same 2026-09-18 pass eight screens
     below it, makes a body signature a **MUST** on all three wrap record kinds. It is a normative
     contradiction inside one section of the normative parent, and it was the only location the
     rulings invalidate that the transcription left standing. **I5 is not amended and does not need to
     be**: I5's own wording is *"no second signature over **content**"*, a wrap body is not content,
     and §8's sentence had dropped the qualifier. Fixed in MASTER §8 on 2026-09-19, with the reason
     stated in place.

     **The ruling's COST travels into MASTER with the ruling, which is what the amendment was for.**
     §8.2 now states, where a reader of the fan-out meets it rather than only here: `expected_wrap_count`
     is **decorative for the recovery arm**, and **nothing detects a missing recovery wrap** — not the
     count, not the `no_wrap` gap, not a live member, not the server. §8.2 also names item **142**'s
     `REASON_EPOCH_STALE` window and §8.1 names item **143**; neither is ruled by this pass.

     **Not a revision bump, and that is recorded as a residual rather than decided.** MASTER is amended
     under the *"Amendment to revision 9"* form its two 2026-08-25 entries established, and the entry
     says plainly that **unlike those two, this one does change rules** — the rules changed when the
     owner ruled them on 2026-09-13 and when M-15 was adopted, and MASTER was the last of four
     documents to be told. Whether that warrants **revision 10** is **not decided here**: a bump moves
     the parent pin and the baseline row of both Spec A and Spec B, and no ruling covers that. **Filed
     for the owner.**

     *The item as filed, kept, because an item that vanishes is an item somebody files again:*

     **MASTER still carries the pre-ruling fan-out and the single-record device wrap, and was
     deliberately not amended by the 2026-09-13 pass.** The brief that carried the rulings named Spec
     A §5.11 and its neighbours, Spec B §6.1, the m1 plan and this ledger, and did not name
     `docs/specs/2026-08-12-urmessage-protocol-design.md`. Amending the normative parent is a larger
     claim than a scribe should make unasked, so the divergence is **filed rather than hidden**.
     **Three places were named on 2026-09-13. All three were re-measured in the review of that pass,
     all three resolve exactly — and the re-measurement found a FOURTH the original count missed:**

     - **MASTER §8.2's payload table** (`:806`) gives active device leaves *"`pq_secret[n]` **and**
       `eph_root[n]`"* in one wrap, which ruling 3 splits into two records. **Confirmed.**
     - **MASTER's own epoch-publication sequence** (step 2, `:842`) publishes *"one recovery wrap per
       member"* before the marker, which ruling 1 moves after it — the sequence that executes against
       no server. **Confirmed.**
     - **MASTER's sizing paragraph** (`:855`) carries 1,000 device wraps, ≈ 1,503 records, ≈ 6.9 MB and
       ~55 round trips, which ruling 3 makes 2,000, ≈ 2,503, ≈ 11.5 MB and ~90. **Confirmed.**
     - **FOURTH, found 2026-09-13 in the review of that pass — MASTER §8.3's `server_attachment` block**
       (`:912`) still annotates `expected_wrap_count` as *"device wraps + recovery wraps + 1 snapshot,
       for the epoch it opens"*. Both rulings contradict it: ruling 3 makes it `2 × device_leaves + 1`
       and ruling 1 takes the recovery wraps out of it entirely. This one is worse than the other three
       because it is a **wire-block annotation** — the form a second implementation transcribes rather
       than reads — and Spec A §5.11 and Spec B §5.4 both carry the ruled text in the same block.

       *(**Corrected 2026-09-15, and the correction is to the SCOPE.** This bullet ended* **"so the"** /
       **"three documents' `EpochAttachment` blocks now disagree with each other field for field"**, *and
       Spec A §5.11's opening imported that sentence. It is measurably false, and it is false in the
       direction that gets a warning disbelieved: a reader who checks one field and finds it identical
       stops trusting the whole sentence. (*Two strings, because the sentence straddled a line break at*
       `cea05b8`.) *The query, so it can be re-run —*
       `for f in urmessage-protocol-design spec-a-protocol-sdk-connect spec-b-message-server-operator; do sed -n '/^EpochAttachment {/,/^}/p' docs/specs/2026-08-12-$f.md | sed 's-//.*--' | sed 's/[[:space:]]*$//' | grep -v '^$'; done`
       *— strips every annotation and leaves the eight field declarations plus two brace lines, and the
       three documents' ten lines are* **byte-identical**. *(**The last two filters were added
       2026-09-19; without them the query does not produce the byte-identical result it claims.**
       `sed 's-//.*--'` deletes a comment's text and leaves the indentation that preceded it, so the
       raw output is 25 lines for MASTER and Spec A and* **33** *for Spec B — differing in trailing
       whitespace and blank-line count, with* `diff` *reporting changes on all three pairs. The claim
       was and is true of the ten non-blank lines; what was false is that the published artefact
       produced it. Re-run 2026-09-19 with the filters:* `diff` *silent on all three pairs, ten lines
       each. Corrected here and in Spec A §5.11.)* *Field order, names and widths do not diverge
       at all.* **One annotation of one field diverges normatively** — `expected_wrap_count` — *and it is
       the field whose value opens an epoch, which is a sharper warning than "field for field" rather
       than a milder one. Two other annotations differ in wording without differing in meaning:
       `read_key`'s trailing cross-reference names each document's own retention section, correctly in
       each; and `durable_ttl_seconds`' is longer in Spec A because it carries
       `RetentionApplied.durable_clamped_down` and Spec B §7.3 case 3's no-refusal rule. Corrected here
       and in Spec A §5.11's opening; the finding itself is unchanged and MASTER is still the next
       edit.)*

     **The four line numbers above are advisory and the quoted strings are the citations.** They resolve
     today because neither pass edited MASTER.

     MASTER:852 additionally holds the **third copy** of the false derivability sentence — Spec A
     §5.11 **step 6** since the 2026-09-13 resequence, step 5 before it, and step 5 of MASTER's own
     un-resequenced list — which item 134 files and which this pass did not repair in any document — it marked it in place
     in Spec A and Spec B instead. *Blocks:* nothing mechanically, and everything about a reader's
     confidence: the normative parent and the two component specs now describe two different fan-outs.
     **This should be the next edit made, and it is a transcription rather than a decision.** Found
     2026-09-13 by the pass that wrote the rulings.

142. **After the marker the group is fully writable, so any concurrent commit strands every recovery
     wrap still in flight — permanently, with no crash required. A retry costs ZERO WIRE BYTES and the
     procedure published for it on 2026-09-14 was UNSAFE: a conforming implementer following it would
     have shipped an XChaCha20-Poly1305 nonce reuse.** The second cost of ruling 1, filed in the review
     of the pass that wrote ruling 1 rather than discovered later. **This headline read** *"and a retry
     is unaddressable because"* / *"`RecoveryTag` carries no epoch"* **until 2026-09-14** — two strings,
     because the sentence straddled a line break at `7681f4c` and that is the only form of a two-part
     anchor `grep -F` can take — **and then read** *"what it still needs is one normative bound"*
     **until 2026-09-15.** Both re-derivations are at the foot of this item and neither is erased.

     `EpochComplete` is what opens the group for ordinary
     writes, and the recovery leg runs **after** it, so a commit accepted from any member during that
     leg sets `current_epoch := n+2` and `store/memory.go:578` then refuses every remaining recovery
     wrap `REASON_EPOCH_STALE`. That check sits **in front of** the epoch-complete gate, so the
     fan-out's state is irrelevant to the answer, and no path in either store accepts a record at a
     closed epoch. **The window is the recovery arm's own length — about eighteen round trips** at the
     500-member design target, between the marker and the last recovery wrap.

     **The pre-ruling sequence had no window of this shape**, structurally: it published the recovery
     wraps before the marker, and while a fan-out is open a commit carries an `AttachmentEpoch`, which
     `exemptFromEpochComplete` does not exempt. So this window is created by the resequence. Both specs
     attributed a short recovery arm **only to a committer that dies** (Spec A §5.11 step 7, Spec B §6.1
     step 7), and that is false as it stood: **an ordinary, conforming, live committer loses the arm to
     somebody else's legal commit**, at whatever rate the group commits. Both now say so.

     **RE-DERIVED 2026-09-14: the retry was ruled out on a reason that does not hold, and the price
     published with it was wrong by an entire wire-format change. THAT HALF STANDS.** The paragraph this
     item first carried supplied the fact that defeats its own conclusion. It said — correctly — that a
     recovery wrap's `ct_body` **is** `hybrid_ct`, that its `ct_head` is keyed from `wrap_key`, that
     neither depends on the record's own `epoch` field, and that **the content epoch is bound inside
     `wrap_key`'s HKDF `info`**. It then concluded that a restorer *"cannot tell two candidate wraps
     apart"* and priced a coherent retry at a `u64 epoch` on `RecoveryTag` — a `server_attachment`
     change, therefore an **A6 wire-format change** reaching Spec A §5.11, Spec B §5.4 and MASTER §8.3.
     **A value bound inside a key is a value the key's holder tests for, and an AEAD is the test.**

     **The mechanism, in the order a restorer executes it.**
     `ss = XWing.Decapsulate(recovery_sk, ct_xwing)` does **not** depend on the epoch — MASTER §7 puts
     the epoch only in what comes after, `wrap_key = HKDF-Expand(ss, "URmessage/v1/wrap" ‖ LP(group_id)
     ‖ u64(epoch) ‖ LP(target_id), 32)`, and again beneath it at `key_head ‖ nonce_head =
     HKDF-Expand(wrap_key, "wraphead/v1", 56)`. So the restorer decapsulates **once per candidate
     record**, then walks candidate content epochs **downward** from the record's own `epoch` field —
     an upper bound, because no wrap is published before its epoch opens. A wrong candidate **fails**
     Poly1305, and opens anyway with probability about `2^-128`; the first that opens is the content
     epoch. *(**Corrected 2026-09-15:** this read* **"A wrong candidate fails"** / **"Poly1305 with
     probability `2^-128`"** — *two strings, because it straddled a line break —* *and it states the
     discriminator inverted — it says a wrong guess almost always
     succeeds. The failure probability is `1 − 2^-128`; `2^-128` is the chance a wrong candidate opens
     regardless, and that is the direction the search's correctness rests on. The same inversion was
     written into Spec A §5.11 and is corrected there.)* `RecoveryTag` gains no field, no document's
     wire block changes, and **the decapsulation count does not depend on the bound at all** — the
     search adds two HKDF-Expands and one AEAD open per candidate and **no asymmetric operation**. That
     property, not a timing figure, is what makes it cheap, and it stays checkable against MASTER §7's
     own derivation.

     **RE-DERIVED AGAIN 2026-09-15, and this time the correction is to the PROCEDURE, which the
     2026-09-14 price did not contain at all.** This item's corrected price was *"two normative
     sentences and zero wire bytes"* — and `cea05b8`'s own commit message summarised it as *"Corrected
     price: two normative sentences and ZERO wire bytes, all client-side."* (that one is in a commit
     message rather than a file: `git log -1 --format=%B cea05b8`). Between them they named the
     restorer's stopping rule and the publisher's lag limit and stopped. They said nothing about **what
     a republisher republishes**, and that is where the whole cost is — nor is the price all
     client-side, for the reason the retention bullet below gives.

     - **`AAD_head` binds the RECORD's epoch and the RECORD's stream index** — `"URmessage/v1/aad/head"
       ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle) ‖ u64(epoch) ‖ u64(stream_index) ‖ …`
       (MASTER §8; `connect/message/aad.go`'s `AADHead` writes `h.Epoch` and `h.StreamIndex` field for
       field). **The recovery wrap's `key_head ‖ nonce_head = HKDF-Expand(wrap_key, "wraphead/v1", 56)`
       binds neither**, and `wrap_key` binds the **content** epoch. So the wrap head's `(key, nonce)` is
       a pure function of `ss` and the content epoch and moves with **neither** field a republish forces
       to change — `store/memory.go:578` refuses a record whose epoch is not the current one, which is
       why the wrap is stranded, and `store/memory.go:610` refuses a `stream_index` that is not strictly
       greater, which Spec A §5.7's outbox rule independently requires.
     - **Therefore a republisher that rebuilds the record around a stored `ct_xwing` seals a second,
       different `AAD_head` under a byte-identical `(key, nonce)`.** Keystream reuse plus recovery of
       the Poly1305 one-time key: header forgery over a preimage covering `body_hash`, `blob_id` and
       `H(server_attachment)`. **And Spec A §5.9's guardrail G5, whose whole defence against AEAD nonce
       reuse is the `stream_index` reservation, is VACUOUS here** — it guards `i` in `record_key[i]`, and
       the wrap head is not on that ladder. Nothing in the corpus was watching this nonce.
     - **The escape is a procedure choice and not a format constraint, which is the single most
       load-bearing correction in this whole chain.** `XwingEncapsulate` **cannot be derandomized**:
       `crypto/mlkem`'s `Encapsulate` takes no randomness argument and reads `crypto/rand` itself
       (`connect/messagegroup/xwing.go:236`; asserted, not merely documented, by `xwing_test.go:277`
       `TestXwingEncapsulateIsNotDerandomizable`, which also pins that the X25519 half **is**
       reader-controlled — so no supplied reader can force `ss` reuse). A republisher that
       **re-encapsulates from the wrap plaintext** gets a fresh `ss`, a fresh `wrap_key` and a fresh
       pair, unconditionally and without depending on the AAD, on a server check, or on the restorer.
       Both republishers conform to every wire rule in the corpus; the difference is entirely in what
       the outbox kept.
     - **It cannot ship as a bare MUST, because nothing can check it.** The server never decrypts, the
       restorer sees only the record that landed, and the ciphertext the reuse would be compared against
       was **refused** and exists only on the server's side of the wire. Spec A §5.9's own idiom is the
       shape that survives contact with an implementer: G4 does not forbid putting `body_hash` in
       `AAD_body`, it makes `AAD_body` *"built by a function that does not take a hash argument"*. The
       equivalent here is to rule that a recovery-wrap outbox entry holds the wrap **plaintext** and
       MUST NOT hold a sealed record or a `ct_xwing`, and that the republish path is one function taking
       the plaintext and the target's public key. Then the reuse is not forbidden, it is
       **unrepresentable**. That is a data-structure ruling and it is the owner's.
     - **Re-encapsulating forces the body signature to be recomputed.** Fresh `ss` → fresh `ct_xwing`
       and `aead_ct` → fresh `hybrid_ct` → fresh `ct_body` → fresh `body_hash`. Spec A §5.11 part (4)'s
       signature MUST be recomputed and MUST NOT be copied; and because §5.11 step 6 lets **any member**
       repair a fan-out, a repairer that is not the committer signs under its **own** `identity` key and
       the restorer must accept that. Neither sentence exists in any document today.
     - **It is NOT all client-side: it carries a publisher RETENTION obligation.** The input to a
       re-encapsulation is the wrap plaintext, which MASTER §8.2's payload table fixes as
       **`storage_root[k]` ‖ `archive_secret[k]`**, with
       `archive_secret[k] = sender_data_secret[k] ‖ encryption_secret[k]`. Holding that in an outbox past
       epoch *k* is a copy of the epoch's whole non-`EPH` key material living outside the MLS state
       store and outside `record_key[i]`'s overwrite discipline, against `connect/mls/group.go:2488`'s
       *"THE DELETE IS A SECURITY REQUIREMENT AND NOT HOUSEKEEPING"*. **It is not a breach of MASTER
       §8.1's disappearing-message promise** — that promise is `eph_root`'s, `eph_root` is *"never
       wrapped to a recovery key"*, and it is not in this payload; saying otherwise overstates the cost
       in a way the owner would rightly discount. How long a stranded wrap may sit in an outbox is a
       forward-secrecy ruling with a measurable publisher-side cost, and it is the quantity the
       restorer's bound should be derived from.

     **THE BOUND: still required, still not written anywhere, and `PastEpochWindow` = 32 is WITHDRAWN.**
     Without a bound the search has no stopping rule: handed a record it cannot open — corrupt, foreign,
     or for an epoch it is not owed — a restorer cannot distinguish *wrong guess* from *not mine*, so
     the failure of the whole search is its only signal and an unbounded restorer walks back to epoch 0.
     **No document carries a bound today**, and the 2026-09-14 pass moved the walk into Spec A §5.11's
     descriptive prose while leaving the bound under *what a retry would take* — so a reader building to
     §5.11 as it stood built an unbounded search. §5.11 now says the walk is a derivation and not a
     licence until this item is ruled. The 32 offered as *"the ceiling the corpus already supplies"*
     fails on three counts, the first decisive:

     - **(a) It bounds PRODUCTION, not publication lag.** The argument was that past 32 epochs
       `DeleteGroupStateBefore` has taken `archive_secret[k]` so no member can **rebuild** that epoch's
       wrap. A stranded wrap was already produced, at epoch *k*, when the state existed; what
       republishes it is an **outbox**, and an outbox is not group state. `DeleteGroupStateBefore` is
       called off `self.context.Epoch` inside the commit-apply path (`connect/mls/group.go:2594`, cutoff
       guard `:2587`) and reaches the MLS state store; `grep -rni outbox connect/mls/` names **no file**.
       A committer whose outbox survives a forty-epoch offline stretch republishes at lag 40 and a
       restorer bounded at 32 refuses to look — losing the wrap in exactly the case the retry exists
       for, and by item **138** nothing detects that.
     - **(b) The two quantities have unrelated derivations.** `PastEpochWindow`'s own comment
       (`connect/mls/key_schedule.go:25-29`) derives 32 from *"the window is a product promise"* /
       *"about how long a laptop may stay closed, and an active group can burn eight epochs in a"* — two
       strings, because the comment wraps mid-clause. A restorer's search bound
       is a work budget spent on every record it **cannot** open, including records an attacker submits.
       Two numbers that share no premise should not be pinned to equality.
     - **(c) The error is one-sided.** Too small loses a legitimate wrap permanently and silently; too
       large costs symmetric trials. A one-sided error is the wrong place for an unrelated constant.

     **What it should be derived from:** the quantity at issue is `record_epoch − content_epoch`, and its
     only real ceiling is how long the **publisher** retains what it needs to republish. Rule a
     publisher-side retention window on the side where it has a measurable forward-secrecy cost, and the
     restorer's bound is that window or greater.

     **Still filed, still not ruled, and the reason has changed a second time — then a third, on
     2026-09-18, which this paragraph did not say until 2026-09-19.** It was blocked behind a
     wire-format decision; then behind one bound; then behind four rulings; it is now blocked behind
     **THREE rulings, none of them a wire byte**: (1) the re-encapsulation rule, in a form nothing can
     violate rather than a MUST nothing can check; (2) the publisher retention window; and (3) the
     bound, derived from (2). **What is settled is the direction:** zero wire bytes, and a price paid
     in procedure and retention.

     **THE FOURTH BLOCKER IS RULED, AND IT MADE THIS ITEM WORSE RATHER THAN BETTER.** It was *"the
     wrap's inner `aead_ct` nonce, which is undefined in every document and is now open item 144"*, and
     item **144 closed on 2026-09-18** when MASTER §7 adopted r3's **M-15**:
     `wrap_key ‖ wrap_nonce = HKDF-Expand(prk, info, 56)`. The reading this paragraph feared — Spec A
     §5.14's `nonce = 0`, under which a republish that reuses a stored `ct_xwing` is a two-time pad over
     the wrap payload **as well as** a head forgery — **is what the ruling delivers anyway**:
     `wrap_nonce` is a function of `ss` and `ct_xwing` and of **nothing the record carries**, so a
     reused `ct_xwing` repeats the inner `(wrap_key, wrap_nonce)` exactly. So freshness of the
     encapsulation is still the safety condition, this item's re-encapsulation rule is **more** clearly
     required and not less, and what changed is that MASTER's own construction now states the condition
     instead of it having to be read across from §5.14.

     *(**Corrected 2026-09-19, and the delay is the point.** From 2026-09-18 until then this paragraph
     read* **"blocked behind four rulings"** *and* **"the wrap's inner `aead_ct` nonce, which is
     undefined in every document and is now open item 144"** *— both false at `be7154d`, in the body of
     an* **open** *item a reader consults before the closed ones, and contradicted by item 144's own
     closure two screens below, which says in as many words that 142's blockers go from four to three.
     Item 144's closure did the arithmetic and did not carry it back into the item it was about.)*

     **And the alternative that deletes the question rather than answering it, priced because the
     comparison is the useful half.** Widening `exemptFromEpochComplete` to cover `AttachmentRecovery`
     and putting the recovery leg back **inside** the fan-out means nothing is ever stranded — no
     republish, no re-seal, no bound, no search — and it is the **only** route that closes item **138**
     for the recovery arm, because `expected_wrap_count` becomes a real count over it again. Measured
     rather than argued: the landed-code price is one arm of one switch (`store/memory.go:939`, shared
     with `pgx.go:1152`) plus `exempt: true` on one map entry (`store/contract.go:2576`), and running
     `go test ./store/...` with that one arm widened produces **exactly one** failing leaf,
     `TestTheMemoryStoreMeetsTheContract/TheMarkerIsTheOnlyThingThatOpensAnEpoch/OnlyTheExemptKindsPassTheGateWhileTheFanOutIsOpen/AttachmentRecovery`,
     which fails by **assertion** — not through `attachmentKindsDeclared`'s by-name guard, which fires
     for a **new** attachment kind and is a different proposal's cost. The checkout was restored and
     re-verified green. Its real price is **availability**: group-wide non-writability for the recovery
     arm's own length on every commit, which is exactly what ruling 1 bought back, plus a wider interval
     in which a permanent refusal leaves `epoch_complete = false` with no commit path out. **And it does
     not make the seal question moot** — §5.11 step 6 still has any member rebuild a fan-out its
     committer abandoned, and a rebuild re-seals — so the re-encapsulation rule is required under this
     route too. **Not ruled here;** it reverses a 2026-09-13 ruling.

     *Blocks:* nothing mechanically, and it compounds **138**: 138 says nothing detects a missing
     recovery wrap, and this item says a healthy client produces one on a normal day. **Filed, not
     ruled.** Found 2026-09-13 in the review of the three rulings; re-derived 2026-09-14 and again
     2026-09-15.

143. **RULED 2026-09-07 by the owner, in one sitting with item 169, as shape A1: one class-blind
     `stream_index` per `(group_id, sender_handle)`. `i = stream_index` in every ladder is now
     normative, and this item's device-wrap instantiation is closed by it.** The ruling, its reason,
     its measured costs and what it leaves open are written into item **169**, because the property is
     169's and one ruling answers both; this item carries the four things that are its own. The item
     as filed is kept whole below it.

     **(a) THE PIN IS RULED IN THE FORM THIS ITEM PROPOSED, AND IT IS THE ONLY ONE OF THE SEVEN
     SHAPES THAT LEAVES IT TRUE.** `i = stream_index` in every ladder, head and body, wrap and
     ordinary. Under A2 the pin would have had to be rewritten, under B2 its head clause deleted, and
     under C1/C2/C3/D it would have stayed true per ladder while leaving this item's own wrap
     instance open. It is ruled as written.

     **(b) THE DEVICE-WRAP INSTANTIATION IS CLOSED, AND CLOSED ON BOTH AEADs.** Ruling 2's wrap root
     is `record_key[0] = HKDF-Expand(env_key[k], "sender/v1" ‖ LP(leaf_index), 32)`, which carries no
     class, and ruling 3 puts a `PERMANENT` record and an `EPH(5)` record on it. A class-blind counter
     gives those two records two different positions, so `(key_head, nonce_head)` **and**
     `(key_body, nonce_body)` separate — which is what this item needed and what the four
     derivation-side shapes could not give it, because they bind the class into the head's AEAD
     material only. The message server does **not** recover `pq_secret[k] ⊕ eph_root[k]`.

     **(c) THE FUNCTIONAL TWIN IS CLOSED TOO, AND IT WAS THE EARLIER GATE.** Sub-item (3) below
     recorded that the shipped server would refuse the fan-out's second record with
     `REASON_STREAM_INDEX_REGRESSED` on the honest path, before any of this item's cryptography was
     reachable. That refusal is gone because the client now counts the way the server counts.
     Re-verified against the shipped server on the day of the ruling, not taken from the sub-item:
     `msgrepo/store/memory.go:600-610` gates on `record.SenderHandle` alone under a comment reading
     *"Stream monotonicity, per (group_id, sender_handle)"*, and `store/migrations.go` gives
     `message_stream_claim` `PRIMARY KEY (group_id, sender_handle, stream_index)` and `message_sender`
     a `last_stream_index` on `PRIMARY KEY (group_id, sender_handle)`. No retention class appears in
     either. **Nothing in this repository changed for the ruling, and that is the ruling's own
     strongest argument rather than a convenience.**

     **(d) WHAT IS STILL OWED AFTER IT, so this closure is not read as wider than it is.** The pin is
     ruled; **`EPH` sealing is not** — `SealRecord` still refuses it under item **152**, and the day
     152 rules the `EPH` classes onto the durable root, A1's counter is what keeps them apart, which
     is the same argument in the same shape. And **M1-25 is not ruled**: transients consume indices
     out of the one counter A1 creates, which is item **169**'s recorded cost and is now load-bearing
     rather than deferred.

     *The item as it was filed, which the ruling answers in full, follows unchanged.*

     **DUE AS OF 2026-09-07, no longer merely owed: the `stream_index`-to-ratchet-position mapping is
     now a precondition of sealing a non-`DURABLE` record, and its own proposed repair is unsafe.**
     Item **128** was ruled that day — `ct_head` is always sealed under the DURABLE class ratchet — and
     the accepted cost the owner named is exactly this item: a non-`DURABLE` record draws its head and
     its body from **two ratchets**, so one record's single `stream_index` covers **two ratchet
     positions**, and no document says which position each takes. Until the ruling this was a
     discipline gap on a wrap ladder nobody had built; after it, it stands in front of every
     `PERMANENT` and `MEDIA` record m1 Tasks 14 and 15 emit. **And the repair this item proposes —
     *pin `i = stream_index` in every ladder* — does not survive the ruling**: the head ladder is now
     shared by every class of one sender, while the reserver that shipped counts per class. That is
     new item **169**, filed the same day, and **143 must be ruled with 169 beside it.** The item as
     filed follows.

     **The device wrap owes a normative `stream_index`-to-ratchet-position mapping, and it is the one
     residual of the adopted M1-1 recommendation carried into no document.** Residual risk 2 of the
     2026-09-12 review's recommendation. The record nonce is derived from the record key —
     `key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)`, MASTER §8.1 — so key-nonce
     uniqueness **is** uniqueness of `i`, and a repeated pair under XChaCha20-Poly1305 leaks the
     Poly1305 one-time key: header **forgery**, not a plaintext XOR. `i` and `stream_index` are not the
     same thing by default, because gaps are normatively legal (*"the server enforces monotonicity, not
     contiguity"*), and one rate-limited submit mid-fan-out is enough to separate them.

     **Rulings 2 and 3 sharpen it rather than soften it.** Ruling 2 gives the device wrap its own ladder
     head — `record_key[0] = HKDF-Expand(env_key[k], "sender/v1" ‖ LP(leaf_index), 32)` — and ruling 3
     puts **two** records per leaf on that ladder, so a fan-out now advances it twice per leaf where it
     advanced it once, at 2,000 records rather than 1,000. The review's proposed repair is to pin
     `i = stream_index` in **every** ladder, so the invariant follows from Spec A §5.12 step 6's
     existing *"MUST NOT be reused"* rule rather than from a second, unwritten discipline. That reaches
     all of §5.3 and not only the wrap's ladder, which is why it is filed rather than ruled inside a
     wrap ruling. Named in Spec A §5.11 part (5) as explicitly not stated. *Blocks:* nothing
     mechanically; it is a wire-visible correctness property no test in m1 can currently refute.
     **Filed, not ruled.** Found 2026-09-13 in the review of the three rulings, by checking each of the
     recommendation's five residuals against the corpus — 1, 3, 4 and 5 are carried and this one was not.

     **A CONCRETE, REACHABLE INSTANTIATION, added 2026-09-15, because a general discipline gap gets
     deferred and a specific one gets fixed.** Ruling 2's ladder head is
     `record_key[0] = HKDF-Expand(env_key[k], "sender/v1" ‖ LP(leaf_index), 32)`. For an ordinary record
     the same head is `HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)`, and **the class key is
     what separates one sender's ladders from each other** — which is why Spec A §5.5 sizes the
     skipped-key window *"per (`sender_handle`, retention class)"* and why §5.3 publishes
     `NewSenderRatchet(classKey []byte, leaf uint32)` and `RecordKeyZero(classKey []byte, leaf uint32)`,
     signatures with a class-key parameter and nowhere to put anything else. **Ruling 2 replaces
     `class_key` with `env_key[k]`, which has no class in it, and ruling 3 then puts a `PERMANENT`
     record (`pq_secret[k]`) and an `EPH(5)` record (`eph_root[k]`) on that one root.** An implementer
     that adapts the published constructor the obvious way — pass `env_key[k]` as `classKey` — and
     instantiates one ratchet per (sender, class) as §5.5 directs gets **two ratchets with
     byte-identical roots, both starting at `i = 0`**. The two device wraps for one leaf are then sealed
     under the same `(key_head, nonce_head)` **and** the same `(key_body, nonce_body)`, with different
     plaintexts and different AADs (the joined retention-class wire byte differs), so the message server
     recovers `pq_secret[k] ⊕ eph_root[k]` for every leaf of every epoch — simultaneously a break of the
     PQ layer and of the disappearing-message property that rulings 2 and 3 were adopted to protect.
     Nothing in the corpus refuses this: §5.6's *"the ratchet resumes at `highWater + 1`"* describes
     **one** counter for a sender whose §5.5 ratchets are per-class, which is the contradiction this
     item files. It is the same open item and the same repair — pin `i = stream_index`, or give the
     ladder head a class — and it is **still not ruled**; what changes is that it now names the concrete
     failure rather than only the missing discipline. Carried into Spec A §5.11 part (5).

     **OPTIONS LAID OUT 2026-09-07 WITH ITEM 169, AND NOT RULED. THE CHOICE IS THE OWNER'S AND IT IS
     ONE CHOICE FOR BOTH ITEMS.** The seven shapes, their measured costs, the four corrections to
     169's own text and the recommendation are written into item **169**, because the property is
     169's. Four things belong on this side, and the first two change what ruling this item means.

     **(1) THE PIN IS ALREADY IMPLEMENTED INSIDE ONE LADDER, so ruling it as written changes no Go
     file.** `NewSenderRatchet` resumes at `reserver.HighWater(stream) + 1` and walks the ladder that
     many rungs from `RecordKeyZero`, and `Next()` hands out the rung it is holding at exactly the
     index it just reserved (`connect/messagegroup/ratchet.go:172-198` and `:218-261`). So
     `i = stream_index` holds **by construction** within any one ratchet, at `7a9ad2a`, and has since
     wave 1. What this item still owes is not the pin: it is the rule that says **which ladder and
     which counter**, and that is item **169**. A ruling that says only *"pin `i = stream_index` in
     every ladder"* restates what the code does and leaves the question that makes it unsafe open.

     **(2) THIS ITEM'S OWN INSTANTIATION IS A COLLISION ON BOTH AEADS, AND FOUR OF 169'S SEVEN SHAPES
     CLOSE ONLY THE HEAD.** The device wrap's two records for one leaf share a root that has no class
     in it — ruling 2's `record_key[0] = HKDF-Expand(env_key[k], "sender/v1" ‖ LP(leaf_index), 32)` —
     and ruling 3 puts a `PERMANENT` record and an `EPH(5)` record on it, so a repeated `i` there
     repeats `(key_head, nonce_head)` **and** `(key_body, nonce_body)`, which is how this item gets
     `pq_secret[k] ⊕ eph_root[k]`. Item 169's derivation-side shapes bind the class, the header hash
     or an explicit nonce into the **head's** AEAD material only, so under **B2, C1, C2, C3 and D**
     the wrap's body collision survives untouched. Only the position-side shapes (**A1**, **A2**) and
     the root-side shape (**B1**) reach it, because only those change something both AEADs of a
     record are downstream of. **A shape may be ruled for 169 that does not close 143, and this is
     the sentence that says so.**

     **(3) AND THERE IS A FUNCTIONAL TWIN OF THIS ITEM THAT ARRIVES EARLIER THAN THE CRYPTOGRAPHIC
     ONE.** The server's stream monotonicity is class-blind — Spec B check (3) at :2221 over
     `message_sender`, `PRIMARY KEY (group_id, sender_handle)` at :882, and the shipped
     `msgrepo/store/memory.go:603-609` — while the shipped reserver counts per class. The device-wrap
     fan-out ruling 3 defines emits a `PERMANENT` record and an `EPH(5)` record **per leaf**, both
     from the committer's own `sender_handle`, drawing from two independent counters; the second of
     each pair carries a `stream_index` at or below the server's high water and is refused
     `REASON_STREAM_INDEX_REGRESSED`. `EPH(5)` has no exemption — only `EPH(0)` does, Spec B :2765.
     **So m1 Task 14's fan-out is refused by the shipped server on its second record, on the honest
     path, before any of this item's cryptography is reachable.** That is worth more than the
     crypto argument as a gate: it is early, it is partial, and it fails on a two-record fan-out that
     an integration test can run, where the key-reuse property needs an adversary with both
     ciphertexts. Filed here rather than as a new item because it is this item's own instantiation
     seen from the server side, and because it is decided by item **168**'s keying.

     **(4) WHAT EACH SHAPE DOES TO THIS ITEM'S PIN, so the two items can be ruled in one sitting.**
     **A1** (class-blind counter) and **B1** (class in every ladder root) leave the pin true and
     close this item as written. **D** (item 152's repair) does the same and dissolves 169, but not
     this item's wrap instance, whose root carries no class key at all. **A2** (an injective map from
     `(class, stream_index)` to the position) **replaces** the pin — `i` is no longer `stream_index`
     — so this item's text has to be rewritten rather than adopted. **B2** (no head ladder) leaves
     the pin true of the body and leaves the head with no position for it to apply to, so the pin's
     head clause has to go. **C1**, **C2** and **C3** leave the pin true per ladder and leave this
     item's wrap instance open.

     **STILL FILED, STILL NOT RULED, AND STILL TO BE RULED WITH 169 BESIDE IT.** Nothing above is a
     ruling, nothing above implements wave 2, and no Go file in either tree changed for it. Written
     2026-09-07 alongside item 169's options. *(**Superseded the same day by the ruling at the head of
     this item.** A1 was taken, with 169, and every option laid out above is closed by it. This
     paragraph is kept because it is the sentence the ruling answers.)*

144. **CLOSED — RULED 2026-09-18 by adopting r3's M-15, four weeks after it was raised.** MASTER §7 now
     derives `prk = HKDF-Extract(salt = "URmessage/v1/wrap-salt", ikm = ss)` and
     `wrap_key ‖ wrap_nonce = HKDF-Expand(prk, info, 56)` over a nine-element `info`, and `aead_ct`
     is sealed under `(wrap_key, wrap_nonce)`. **Both halves of M-15 close** — the nonce, which was
     this item, and the missing `alg_id`, which **nobody had ever filed** and which is the half that
     violates §7.1's own anti-downgrade rule. **Zero wire bytes**: `wrap_nonce` is derived by both
     sides and `hybrid_ct` is unchanged. **No code to migrate**, verified rather than assumed — a grep
     for `wrap_key`, `WrapKey` and `wraphead` across every `*.go` file in `msgrepo` and `connect`
     returns three hits and all three are `connect/mls/leaf_keys_test.go`, on the leaf's wrap KEM
     **public key** in the `urmessage_leaf_keys` extension, which is a different thing.

     **THE ADOPTION REQUIRED ONE SUBSTITUTION, AND A CLOSURE THAT DID NOT SAY SO WOULD BE DISHONEST.
     M-15's block cannot be adopted verbatim: it was written against a construction revision 5
     deleted.** r3 reviewed a **pre-X-Wing** revision — its keystone B-1 still names
     `device_x25519_pub` and `device_mlkem_pub` as two separate leaf values — so its block takes
     `ikm = ss_x25519 ‖ ss_mlkem` and binds `LP(pk_x25519) ‖ LP(ek_mlkem) ‖ LP(ct_x25519) ‖
     LP(ct_mlkem)`. Measured: those six identifiers occur in this repository **only** inside r3's own
     review file and in MASTER §7's own sentence recording their deletion — *"It replaces the
     hand-rolled `ss_x25519 ‖ ss_mlkem` combiner of earlier revisions"*, quoted rather than cited by
     line because that line moved with this amendment. **Pasting M-15's IKM
     literally would have reinstated the hand-rolled combiner MASTER calls *"the most dangerous
     composition in this document"*** — a revert of revision 5, not an adoption of M-15. Two X-Wing
     values stand in for the four, `LP(target_xwing_pub) ‖ LP(ct_xwing)`, covering the same material
     in X-Wing's own ordering under two length prefixes rather than four; MASTER §7 carries that
     paragraph rather than making the substitution quietly. Every substantive claim of M-15 survives
     it.

     **Three inherited gaps, NAMED AND NOT FILLED, because filling one is a wire ruling.**
     `target_id` was already undefined before the amendment (Spec A §5.11 (5)); `u8(target_type)` and
     `u8(payload_type)` **arrive with M-15** and have no code point, value table or definition
     anywhere — measured 2026-09-18, both occur only in r3's review file and in the 2026-09-12 red
     team's reference back to it. MASTER §7 states that its block is **normative modulo those three**,
     so a second implementation still cannot build a wrap from it alone; what the block settles is the
     shape, so the derivation does not move again once they are ruled. A fourth and softer one is
     named there too: no line says in as many words which `alg_id` `hybrid_ct` carries, so §7 binds
     *"the same two octets `hybrid_ct` carries"* rather than picking a number — which is what makes
     the binding anti-downgrade whichever number it turns out to be.

     **WHAT THIS DOES TO ITEM 142, because it is easy to read the other way.** 142 was blocked behind
     four rulings and this was the first, so **142 is now blocked behind three** and **stays FILED and
     UNRULED**. **The hazard is CONFIRMED, not removed:** `wrap_nonce` is a function of `ss` and
     `ct_xwing` and of nothing the record carries, so a republish that reuses a stored `ct_xwing`
     repeats the inner `(wrap_key, wrap_nonce)` exactly as the `nonce = 0` closure would have — a
     two-time pad over `storage_root[k] ‖ archive_secret[k]` **as well as** the head forgery. Freshness
     of the encapsulation is still the safety condition; what changed is that MASTER's own
     construction now states it, instead of it being inferred by reading across from §5.14. So 142's
     re-encapsulation rule is **more** clearly required, not less. The other three blockers — the
     re-encapsulation rule, the publisher retention window, and the bound derived from it — are
     untouched.

     **The process failure behind this item is measured separately as new open item 146**, because it
     is bigger than one finding: fourteen of r3's fifteen majors are named nowhere outside the review
     file that raised them.

     *The item as filed, kept:*

     **The recovery wrap's INNER AEAD has no nonce in any document, and it decides item 142.** MASTER §7
     derives `wrap_key = HKDF-Expand(ss, "URmessage/v1/wrap" ‖ LP(group_id) ‖ u64(epoch) ‖
     LP(target_id), 32)` — **thirty-two octets, a key and no nonce** — and then writes
     `hybrid_ct = u16(alg_id) ‖ LP(ct_xwing) ‖ LP(aead_ct)`. **Nothing in MASTER, Spec A, Spec B or the
     m1 plan says what nonce `aead_ct` is sealed under.** Measured rather than asserted: over
     `docs/` and this ledger, `aead_ct` occurs in exactly three places — MASTER §7's framing
     (`:581`), Spec A §5.11's quotation of it, and the 2026-09-12 red team's — and `wrap_nonce` and
     `nonce_wrap` occur **only** inside the r3 review's proposal
     (`docs/reviews/2026-08-12-r3-spec-review.md:172`), which is the one place in the corpus that ever
     noticed. r3's **M-15** wrote it in as many words — *"no AEAD nonce is derived and `alg_id` is
     absent from `info`"* (grep it that short: that review file is stored double-encoded, so its section
     signs are not the octets a reader would type) — and proposed
     `wrap_key ‖ wrap_nonce = HKDF-Expand(prk, info, 56)`. **MASTER still expands 32**, and no ledger
     item, owner-decision file or spec revision carries a disposition for M-15 either way; it was
     neither adopted nor recorded as rejected. (Its second half is still open too: `alg_id` is still
     absent from `wrap_key`'s `info`.)

     **Why it is not merely a gap. The two closures an implementer will reach for are both live in this
     corpus and they disagree about item 142.**

     - **`nonce = 0`, which is what the sibling construction one section over already does.** Spec A
       §5.14's rendezvous deposit is the same shape — `deposit_ct = u16(alg_id) ‖ LP(ct_xwing) ‖
       AEAD(deposit_key, nonce = 0, …)` — justified by a single sentence: *"Every encapsulation yields a
       fresh `deposit_key`, so the zero nonce uses no key twice (**I7**)."* Read across, that sentence
       says the wrap's inner seal is safe **if and only if** every wrap is a fresh encapsulation, which
       is precisely the re-encapsulation rule item 142 needs and does not have. A republish that reuses
       a stored `ct_xwing` would then be a **two-time pad over `storage_root[k] ‖ archive_secret[k]`**
       plus recovery of the inner Poly1305 key — an attacker able to forge the payload a seed-only
       restorer installs — on top of the head forgery item 142 already describes.
     - **A bare-label expand off `wrap_key`**, which is literally what `"wraphead/v1"` does one line
       away in Spec A §5.11 (2). That closure has the same defect as the head's and for the same reason.

     **So the ordering is forced: 144 is ruled before 142's procedure can be.** The republish question
     cannot be decided while the inner seal's safety condition is unstated, because on the most likely
     reading that condition **is** the answer to 142. Adopting r3's 56-octet expand is one available
     ruling; stating `nonce = 0` with §5.14's justification carried across explicitly is another; they
     are not equivalent, because the second makes freshness load-bearing in a second place.

     *Blocks:* Spec A §5.11 part (5) now lists it as not stated, and m1 **Task 19** cannot pin a known-
     answer vector for `hybrid_ct` without it — a KAT written against an assumed nonce is a KAT that
     passes and proves nothing, which is the same shape as `TestXwingEncapsulateIsNotDerandomizable`'s
     stated reason for existing. **Filed, not ruled.** Found 2026-09-15, in the red team of item 142's
     re-derivation; the underlying gap was found by r3 on 2026-08-12 and has been open since.

145. **Spec A §5.14's rendezvous deposit is the same construction and still seals at `nonce = 0`, so
     the corpus now carries one KEM seal that derives a nonce and one that does not.** M-15's argument
     applies to `deposit_key = HKDF-Expand(ss, "URmessage/v1/rzvdeposit" ‖ LP(rendezvous_id), 32)`
     word for word: it expands **32**, derives no nonce, and omits `alg_id` from its `info` while
     `deposit_ct = u16(alg_id) ‖ LP(ct_xwing) ‖ AEAD(deposit_key, nonce = 0, …)` puts `alg_id` on the
     wire — the same anti-downgrade gap §7.1's rule exists to close. **It is not unsafe as it stands:**
     §5.14 justifies the zero nonce in one sentence — *"Every encapsulation yields a fresh
     `deposit_key`, so the zero nonce uses no key twice (**I7**)"* — and unlike the wrap, nothing in
     the corpus proposes republishing a deposit under a stored `ct_xwing`, so freshness is not
     load-bearing against a documented procedure there. What is now true is that **two sibling KEM
     seals in one corpus answer the same question two ways**, which is the shape a second
     implementation gets wrong, and the `alg_id` half has no justification at all — it is simply
     missing. **Out of the 2026-09-18 pass's scope**, which the owner set to MASTER §7's wrap KDF and
     the three 2026-09-13 rulings; naming it is what that pass could do. *Blocks:* nothing.
     **Filed, not ruled.** Found 2026-09-18, while adopting M-15 into MASTER §7.

     *(**2026-09-19: this item is one of TWO, not one, and it is the one the sweep found.** Item
     **147** is the other — MASTER §8.2's epoch snapshot, the same defect in the same document as §7,
     missed because the sweep searched for M-15's construction (a KEM seal) rather than its property
     (an AEAD key from a bare expand with no nonce and no bound `alg_id`). 147 publishes the property
     query and its output; over the four specs at `be7154d` exactly two 32-octet expands hand their
     output to an AEAD, and they are this one and `snap/v1`. **This item is unchanged and still
     out of scope**: unlike the snapshot, nothing in the corpus proposes republishing a deposit, so
     freshness is not load-bearing against a documented procedure here — which is why 147 was fixed
     and this one is still only named.)*

146. **THE PROCESS FAILURE BEHIND 144, MEASURED: r3's twelve BLOCKERS were dispositioned by id and
     its fifteen MAJORS were dispositioned by a COUNT, so fourteen of the fifteen are named nowhere in
     this repository outside the review file that raised them.** Item 144 recorded that M-15 carried
     no disposition. It is not one finding; it is the whole severity class. **The query, published
     beside the number so it can be re-run rather than believed** — for each finding id declared in
     `docs/reviews/2026-08-12-r3-spec-review.md`, count the files at `bed5b84` that name it outside
     that file:

     ```
     git grep -lE "(^|[^A-Za-z0-9-])$id([^0-9]|$)" bed5b84 \
       -- ':!docs/reviews/2026-08-12-r3-spec-review.md' | wc -l
     ```

     **`B-1` … `B-12`: 1 to 6 files each, all twelve non-zero. `M-1` … `M-14`: ZERO, every one.
     `M-15`: 1, and that one is item 144 itself, written on 2026-09-15 to say it had no disposition.**
     So before 2026-09-18 the recorded disposition of r3's entire majors class was empty.

     **The convention that failed is visible in this file.** The 2026-08-12 R4/R5 edit-log entry closes
     *"0 blockers, 0 leaked labels (independently re-grepped), 8 majors and 22 minors remaining"*, and
     §1's state table still carries *"Remaining | 30: 8 major, 22 minor. Ordinary pre-implementation
     cleanup."* **The blockers were re-grepped; the majors were counted.** A count cannot be checked
     against a document — nothing re-derives which eight — so a major that was neither applied nor
     rejected is indistinguishable from one that was absorbed, and M-15 sat in that gap for four weeks
     until a different chain of reasoning walked into the same hole and filed it as 144. **Three passes
     is what the rediscovery cost**, and the second half of M-15 — the missing `alg_id`, which
     violates §7.1's own anti-downgrade rule — was never filed by anyone and closed on 2026-09-18
     without ever having been opened.

     **This is NOT a claim that the other fourteen are unfixed.** Several are plainly satisfied by the
     documents as they stand; the measurement is of the **disposition record**, not of the text, and
     the distinction is the whole point — a finding whose fate no document states is a finding the
     next reader must re-derive from scratch, at whatever it costs them. **What would have caught it**
     is one property rather than one number: *every finding id declared in `docs/reviews/` is named at
     least once outside its own file.* It is greppable, it is cheap, and it is exactly the shape of
     the gate the plan linter's check 3d already is for plan citations. **Whether to make it a gate is
     the owner's, and is not ruled here.** *Blocks:* nothing mechanically. **Filed, not ruled.** Found
     2026-09-18, while adopting M-15 four weeks late.

147. **CLOSED — AMENDED 2026-09-19. M-15 HAD A SECOND INSTANCE IN MASTER, AND THE SWEEP THAT CLOSED
     THE FIRST DID NOT REPORT IT — in the section it was already editing. The fix is one line; why the
     sweep missed it is the item.** MASTER §8.2's epoch snapshot was encrypted under
     `K_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 32)` — **a 32-octet AEAD key with no
     nonce, no `alg_id` and no AAD anywhere in the corpus**, which is defect for defect what r3's
     **M-15** raised against §7's `wrap_key` and what §7 adopted on 2026-09-18, one section away in
     the same document and in the same commit. Measured at `be7154d`: `snap/v1` occurs **five** times
     across this repository and a snapshot nonce occurs **zero** times.

     **THE FIX, in M-15's shape rather than a second one.**
     `K_snapshot[n] ‖ nonce_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 56)`, with
     `AAD_snap = "URmessage/v1/aad/snap" ‖ u16(alg_id) ‖ LP(group_id) ‖ u64(n)`. `32 ‖ 24` is the
     split §8's `key_head ‖ nonce_head` and §7's post-M-15 `wrap_key ‖ wrap_nonce` already use, and 24
     octets is XChaCha20-Poly1305's nonce and no other v1 suite's — the same argument §8 used on
     2026-08-25 to settle its own record AADs, which is why `alg_id` here is `0x0021` rather than a
     fresh assertion. **`K_snapshot[n]`'s VALUE does not change**, because HKDF-Expand's output is a
     prefix of any longer expand under the same PRK and `info`; measured rather than asserted,
     `Expand(root, "snap/v1", 32) == Expand(root, "snap/v1", 56)[:32]` over 1,000 random roots, every
     one. So it costs **zero wire bytes**, migrates **no code** (grep for `K_snapshot`, `KSnapshot`
     and `snap/v1` over every `*.go` in `msgrepo` and `connect`: zero hits), and Spec A §5.10's
     correction **E2** — which quotes the key — stays true; the three copies of the derivation moved
     with it (Spec A §5.10 and §5.11, and the m1 plan's Task 3 note, which also loses a KAT blocker
     it did not know it had lost).

     **WHY THE SWEEP MISSED IT, which is worth more than the fix.** The 2026-09-18 pass did run
     M-15's class across the corpus, and it found one sibling and filed it as item **145** — Spec A
     §5.14's rendezvous deposit. So the sweep was real and it was not lazy. **It searched for M-15's
     CONSTRUCTION and not for M-15's PROPERTY.** M-15 was raised against a KEM seal, so the sweep
     looked for KEM seals: an encapsulation, `HKDF-Expand(ss, …)`, a `hybrid_ct`, an `alg_id` on the
     wire. `rzvdeposit` is a KEM seal and was found. **The snapshot is not a KEM seal** — its key
     comes off `storage_root[n]`, there is no encapsulation, no `ct_xwing`, no `hybrid_ct` and no
     `alg_id` on the wire at all — so it sat outside the query while sitting inside the class. The
     property M-15 actually names is not *a KEM seal without a nonce*; it is **an AEAD key produced by
     a bare expand, with no nonce beside it and no `alg_id` bound**, and that property does not
     mention KEMs.

     **The property is greppable, and the query is published beside the number with its output,
     because a query that is never run is what item 141 was just corrected for.** Over the four specs
     at `be7154d`:

     ```
     grep -rhoE 'HKDF-Expand\(.{0,90}?, *(16|24|32|48|56|64)\)' docs/specs/ \
       | sed 's/  */ /g' | sort -u
     ```

     returns **32** distinct derivations, **24** of them 32-octet. Of those 24, exactly **two** hand
     their output straight to an AEAD: `"snap/v1"` — this item — and
     `"URmessage/v1/rzvdeposit"` — item **145**. **The sweep found one of the two.** The other 22 are
     each something else, and naming them is what makes the two visible: ladder roots and class keys
     (`sender/v1` under `class_key` and under `env_key[k]`, `ratchet/v1`, `eph/v1`, `perm/v1`,
     `durable/v1`, `media/v1`), whose AEAD keys come from §8's **56**-octet `rec/v1/head` and
     `rec/v1/body`; a MAC key and a read authorizer (`write/v1`, `read/v1`); a handle root (`gh/v1`);
     an identifier (`blob/v1`); signature seeds (`idxsig/v1`, `colsig/v1`); KEM and identity seeds
     (`recovery/v1`, `card/v1`, `identity/v1`, `cardgen/v1`, `cardkem/v1`, `rk/v1`); and
     `HKDF-Expand(ss, …, 32)`, which is §7's own record of the form M-15 replaced.

     **THE SHAPE, because this is the third time in six passes.** Item **146** measured a class
     dispositioned by a **count** instead of a grep. Item **141** published a location query built
     from the **numbers** the rulings changed instead of the **claims** they falsified, and it missed
     two of its own six. This item is a class swept by the **construction** the finding was raised
     against instead of the **property** the finding names, and it missed one of its two. All three
     are the same error at different altitudes: **the artefact was derived from the instance rather
     than from the property the instance instantiates.** A sweep whose query cannot be stated as a
     property of the corpus is a sweep that will find the members that look like the one it started
     from.

     **What would have caught it, stated as a property so it can become a gate if the owner wants
     one:** *every HKDF-Expand in `docs/specs/` whose output is used as an AEAD key expands at least
     key-length + nonce-length, or the document states the nonce beside it.* It is greppable at the
     cost of one human classification per derivation — 32 of them today — and the classification is
     the part a machine cannot do, which is why it is offered as a property and not as a check.
     **Whether it becomes a gate is the owner's and is not ruled here.** *Blocks:* nothing.
     **Found and fixed 2026-09-19**, in the review of the 2026-09-18 pass.

148. **The snapshot's derived nonce does NOT make a same-epoch republish safe, and step 6 permits one.
     FILED, NOT RULED.** Item 147 gives `K_snapshot[n] ‖ nonce_snapshot[n]` both as functions of the
     epoch alone, so **two snapshot objects sealed at one epoch reuse the pair exactly** — the same
     key, the same nonce and the same `AAD_snap`. It is not hypothetical. MASTER §8.2 step 6 lets
     **any member** re-publish the missing wraps of a fan-out whose committer died, the snapshot is one
     of the records `expected_wrap_count` names, and the wrap index is deliberately **not unique**
     (item **132**), so nothing in the corpus refuses a second snapshot record at one epoch.

     **It is safe only under a property no document states.** Two conforming publishers seal
     byte-identical plaintext — the ratchet-tree public state and GroupContext at one epoch are agreed
     across members, that being what MLS is for — and an AEAD over identical plaintext under an
     identical `(key, nonce, AAD)` yields identical ciphertext and leaks nothing. **But no line of
     this corpus requires the serialiser to be canonical.** Two publishers whose encodings differ by
     one byte — map iteration order, an optional field, a length-prefix choice — hand the message
     server a two-time pad over the epoch's ratchet tree plus the Poly1305 one-time key, which is a
     forged snapshot a restoring device verifies signatures against.

     **Two repairs, and both are rulings 147 was not scoped to make.** (a) A canonical-serialisation
     MUST on the snapshot plaintext, plus a rule that a publisher unable to produce the canonical bytes
     MUST NOT publish — cheap, and it is the one that also makes the duplicate record harmless rather
     than merely safe. (b) A publisher-separated nonce, which is wire-visible either way: putting
     `sender_handle` into the `info` changes `K_snapshot[n]`'s value and breaks item 147's
     zero-migration property, and putting it in a second expand beside the first introduces the second
     shape 147 deliberately avoided. **They are not equivalent** — (a) leaves one ciphertext where (b)
     leaves two — and the choice is the owner's.

     **Same family as 142 and it is worth saying so.** 142 is a republish that reuses a stored
     `ct_xwing` and repeats a KEM seal's pair; this is a republish that repeats a class key's pair. In
     both, the derivation binds the **content** and not the **publication**, and in both the repair is
     a procedure rather than a wire byte. *Blocks:* nothing mechanically; a snapshot KAT should not be
     written against a duplicate-publish case until it is ruled. **Filed, not ruled.** Found
     2026-09-19, while fixing item 147.

**THE DISPOSITION CONVENTION, stated here because the one that failed was a count.** Items 149–162
below disposition r3's fourteen undispositioned MAJORs, one item per finding, and 163–166 the four
things measuring them turned up. Each begins with the **finding id** and a **verb from a closed
set** — *ALREADY SATISFIED*, *SUPERSEDED*, *REJECTED*, *STILL OPEN* — each optionally *NEEDS RULING*,
so that `git grep M-7` returns a disposition rather than silence, and so that a gate can key on the
verb beside the id rather than on the id alone (item **166** is why that distinction is
load-bearing). Every item states **the property the finding names**, not the instance it was raised
against, and publishes **the query that finds every instance of that property** together with its
output at HEAD — that being the error items 141, 146 and 147 each recorded at a different altitude,
and it recurred twice more inside this very pass (items 158 and 162 say where). **Nothing below is
ruled.** Dispositioning was the task; the fixes are separate work these items scope.

**Arithmetic, corrected in passing: the undispositioned set is FOURTEEN, not thirteen.** r3 declares
M-1 … M-15; M-15 alone is closed, by items **144** and **147**. M-1 … M-14 all remain, and all
fourteen are dispositioned below.

149. **`M-1` — STILL OPEN (PARTIAL — the ciphertext half closed 2026-08-25, the authenticator half
     never did). NEEDS RULING. WIRE-VISIBLE.** r3: *"§7.1 requires every authenticator and ciphertext
     to carry `alg_id` inside signed bytes; the record violates it on both counts."*

     **Property.** Every value §7.1 calls a signature, an authenticator, a hybrid ciphertext or a
     published public key carries its algorithm identifier **inside its own preimage**, and the record
     carries on the wire the identifier of the suite it was built under — so a suite change is a value
     change rather than a format break, and the AEAD, the KDF and the MAC cannot be negotiated
     independently of one another.

     **Query, with its exclusion rule, because the obvious form of it over-reports.** Enumerate every
     domain-separated preimage label in the corpus and ask whether `alg_id` sits inside its own block:

     ```
     for lab in $(grep -rhoE '"URmessage/v1/[a-z0-9/_-]+"' docs/specs/*.md | sort -u | tr -d '"'); do
       printf "%-38s %s\n" "$lab" "$(grep -rh -A5 "\"$lab\"" docs/specs/*.md | grep -c alg_id)"
     done
     ```

     28 labels, and the `-A5` window returns **17** with no `alg_id` — a number anyone re-running this
     will get and which is not the number below, so the rule that reduces it is published rather than
     applied silently. **Count a label only where §7.1's own words reach it**: a signature, an
     authenticator, a hybrid ciphertext, or a published public key. That drops four labels which are
     none of those (`kt/empty`, `kt/leaf`, `storage`, `vrf`) and two which carry the identifier
     transitively (`card`, whose signed bytes open on `u16 alg_id`; `rzvdeposit/deposit_auth`, whose
     `LP(H(deposit_ct))` does). **The answer is 13**: `write`, `req`, `attest`, `sth`, `serverkeyroot`,
     `serverkeyrot`, `discovery`, `succession`, `recovery`, `rzvopen`, `rzvcollect`, `rzvretire`, and
     `aad/rzv`.

     **COUNT 1 (ciphertext) — CLOSED, and not by M-1.** MASTER §8:868-871 now reads
     `AAD_body = "URmessage/v1/aad/body" ‖ u16(alg_id) ‖ …` and the same for `AAD_head`, pinned to
     `0x0021` by the 2026-08-25 amendment (MASTER §8:874-893), and `connect/message/aad.go:171,228`
     write it. **This is the neighbouring fix that makes M-1 look applied.**

     **COUNT 2 (authenticator) — STILL OPEN, in the spec and in shipped code.** MASTER §9.2:1340-1344
     defines `write_auth` over fourteen elements with no `alg_id`, and
     `connect/message/writeauth.go:269-284` writes exactly that list. `req_auth` (MASTER §9.2:1377) is
     the same. §7.1's registry has **no code point for HMAC-SHA-256** at all — MASTER's only `HMAC` hit
     is PBKDF2-HMAC-SHA512 in §5.2 — so the third leg of M-1's `(AEAD, KDF, capability-authenticator)`
     triple cannot be bound even if someone wanted to. `alg_suite` occurs **twice** in this repository
     and both hits are inside r3's own review.

     **THE ONE THING IN THE CORPUS THAT ARGUES BACK IS CODE, NOT SPEC, AND A RULING MUST OVERTURN IT.**
     `connect/message/writeauth.go:50-57` carries an explicit, argued refusal: *"`alg_id` is
     deliberately absent too … the mac here is HMAC-SHA-256 fixed by this layer rather than negotiated,
     and a field written into the preimage that no other implementation writes is a field that fails
     every record. **Do not add it.**"* That is the closest thing to a disposition of M-1's
     authenticator half in either tree, and it sits fifteen lines above the code this item cites. It
     does not defeat M-1 — M-1 asks for a header `alg_suite u16` naming one **registered suite**, not a
     per-preimage field, and the comment argues from the status quo — but it is a spec-level finding
     dispositioned in a Go doc comment in `connect`, where item 146's proposed gate cannot see it
     (item **166**).

     **THE SIBLING THE PROPERTY QUERY FINDS AND AN INSTANCE QUERY WOULD NOT.**
     `"URmessage/v1/aad/rzv" ‖ LP(rendezvous_id)` (Spec A §5.14:2472) is an AEAD AAD with **no**
     `alg_id`, while its three siblings `aad/head`, `aad/body` and `aad/snap` each gained one — in two
     separate passes, 2026-08-25 and 2026-09-19 (item **147**). Three of four AADs were repaired by two
     queries and the fourth was in neither. Same shape as M-15's second instance.

     **THE WIRE SLOT M-1 ASKS FOR ALREADY EXISTS, UNDOCUMENTED AND UNAUTHENTICATED.**
     `connect/message/codec.go:78,108` writes `u8 recordFormatVersion = 0x01` as the **first** field of
     every record — one byte before `group_id`, which is one byte from where M-1 asked for
     `alg_suite u16`. `format_version` occurs **zero** times in MASTER, whose §8:829 says *"The fourteen
     fields below it are the ones `connect/message` serialises"* while `connect/message` serialises
     fifteen. It survives in Spec A:5011 and Spec B:3456 only as `ErrRecordFormatVersion`, and it is in
     neither AAD and in neither MAC preimage — **a value the parser acts on that nothing signs.** At v1
     that is a parse-failure DoS; at v2 it is a downgrade oracle, which is M-1's own argument one level
     up.

     **THE DOWNGRADE SURFACE IS LIVE AND GROWING.** Five algorithm identifiers travel independently and
     none as a suite: `EpochAttachment.alg_id`, `RecoveryTag.alg_id`, `hybrid_ct`'s leading `u16`, the
     contact card's `u16` (Spec A:2448) and `deposit_ct`'s `u16` (Spec A:2471) — plus the AADs'
     pinned-but-unsent `0x0021`. Independent negotiation of the three is exactly what M-1 says not to
     build, and the corpus has built five.

     **Cost at A6.** The suite identifier and `format_version` are both header bytes, and §14 slice 2
     freezes §8 and §9.2 by name, so adding either after the freeze is a format break. `alg_id` being a
     Go *parameter* rather than a wire field (`aad.go:164,205` take `algId uint16`) means two
     implementations that disagree about it fail every AEAD on every record with no diagnostic.
     *Blocks:* **A6.** **FILED, NOT RULED.** The owner chooses between one registered-suite `u16` and
     the five independent identifiers already shipped, and rules on the undocumented `format_version`
     byte in the same edit — they are one decision. Dispositioned 2026-09-20.

150. **`M-2` — ALREADY SATISFIED, and satisfied before this repository's first commit.** r3 asked that
     `epoch` be `u64` and not `u32` in §8's header, the AADs, `cap_auth` and §7's wrap `info`. It is,
     in all four, and it always was here.

     **Property.** Every representation of an MLS or record epoch — wire preimage, protobuf field,
     database column, Go declaration, KDF `info` — is 64 bits wide, and no path on which epoch is an
     anti-replay binding narrows it.

     **The four named clauses, quoted rather than counted.** MASTER §8:815 `epoch u64`;
     MASTER §8:868-872, both AAD blocks carry `u64(epoch)`; MASTER §9.2:1341 `u64(epoch)` inside
     `write_auth`, and `connect/message/writeauth.go:272 writer.WriteUint64(h.Epoch)`; MASTER §7:645
     `‖ u64(epoch)` in the wrap `info`. **All four satisfied, in the spec and in the shipped code.**

     **Query and output over the four surfaces r3 did not name.**

     ```
     grep -rhoE "u(8|16|32|64)\([a-z_]*epoch[a-z_]*\)" docs/specs/*.md | sort | uniq -c
     grep -rhoE "(u?int(32|64)|fixed(32|64)) +[a-z_]*epoch[a-z_]* *=" ../connect/protocol/message.proto
     grep -rhoE "[a-z_]*epoch[a-z_]* +(bigint|integer|int|smallint|serial|bigserial)" store/migrations.go
     grep -rnE "(uint32|uint16|uint8|int32|int16|int8)\([^)]*[Ee]poch[^)]*\)" --include=*.go . ../connect
     ```

     **15 × `u64(epoch)` and 2 × `u64(kt_epoch)`; zero `u8`/`u16`/`u32`.** Protobuf: **11 of 11**
     epoch-valued fields `uint64`. Postgres: **12 of 12** epoch-valued columns `bigint` or `bigserial`.
     Go: **~130 of ~130** declarations `uint64`, the only two exceptions being test helpers off the
     wire path (`connect/mls/group_context_test.go:132`, `connect/mls/key_schedule_kat_test.go:1876`).
     Narrowing conversions: **5 hits and not one is an epoch** — every one is a sibling field of an
     `EpochAttachment` (`AlgId`, `MediaTtlSeconds`, `DurableTtlSeconds`, `ExpectedWrapCount`).
     RFC 9420's own carrier agrees: `connect/mls/group_context.go:29 Epoch uint64`.

     **It was never wrong here.** `git show aa9303e:docs/specs/2026-08-12-urmessage-protocol-design.md`
     — the earliest state this repository records, and the commit that also introduced r3's review file
     — already reads `epoch u64` at line 393 and `u64(epoch)` at 322/410/413/487, and `u32(epoch)`
     counts **0** there. M-2 was satisfied in the pre-commit R4/R5 pass and stayed satisfied through
     every later amendment, including the two that rewrote §7. That it was never *recorded* as
     satisfied is item 146's point exactly; the text was never wrong.

     **Residual, recorded only so a later sweep does not re-find it and mistake it for M-2.**
     `store/pgx.go` scans `bigint` into `*int64` and converts back with `uint64(…)` at :559 and :1511.
     Exact for every epoch below 2^63; a group would need ~9.2 × 10^18 commits to reach it.

     *Blocks:* nothing. Epoch width freezes at A6, but it freezes **correct**, so nothing is owed before
     the freeze. **No ruling and no edit needed — this item is the disposition.** Dispositioned
     2026-09-20.

151. **`M-3` — STILL OPEN (PARTIAL — clause 1 applied, clause 3 absent in the spec AND unimplemented in
     the code). NEEDS RULING. WIRE-VISIBLE.** r3 asked for roles in §6's extension body **and** a
     normative client-side commit-authorization rule.

     **Property.** A field the protocol treats as authoritative for authorization lives in a structure
     RFC 9420 §12.1.7 lets **any** member propose and **any** member commit, with no normative rule
     naming who may change it and no client-side check enforcing one.

     **Query, in two halves — the spec's and the code's.** Enumerate every mutable field of the two
     group-context extensions and ask which has a rule naming who may change it; then, for every error
     the specs name as a client-side authorization condition, ask whether it has a call site:

     ```
     grep -rn 'ErrAdminRemovedByNonOwner\|OwnerSuccessorOf(\|successionPreimage(' \
       --include='*.go' ../connect/mls/ | grep -v '_test.go'
     ```

     **SPEC.** `0xF001 GroupPolicyExtension {Roles, RetentionPolicy, DisappearingBuckets, ServerId}`:
     **0 of 4** have a rule naming who may change them. `0xF003 OwnerSuccessorExtension` is guarded by
     a five-condition table (Spec A §3.4) — the contrast that shows the gap is nowhere deliberate.
     **CODE.** Three hits and all three are declarations: `connect/mls/errors_lifecycle.go:45`,
     `connect/mls/owner_successor.go:280`, `:327`. **Zero call sites for any of the three.**

     **CLAUSE 1 — APPLIED, and this is the dangerous half.** MASTER §6:587 now carries *"a
     group-context extension carrying `{roles, retention_policy, disappearing_buckets, server_id}`"*,
     against r3's quoted `{host_server_id, retention_policy, disappearing_buckets}`; Spec A:513-518
     gives the normative body, implemented in `connect/mls/group_policy.go` with canonical ordering
     refused in **both** directions. r3's `owner_identity_key` is legitimately subsumed by
     `RoleEntry{MemberId, RoleOwner}`.

     **CLAUSE 3 — NOT APPLIED.** r3 called this the *"Worse"* half and it is untouched. §11 states one
     authorization rule as a validity condition, and it is about `Remove`, not about
     `GroupContextExtensions`. Nothing anywhere constrains a GCE proposal that rewrites `Roles`.
     ValSem208/209 check GCE cardinality and extension support, never authority, and
     `apply_proposals.go:120` records the semantics that make this sharp: *"GroupContextExtensions,
     WHOLESALE replacement rather than a merge."*

     **THE TWO-COMMIT ESCALATION.** An ordinary MEMBER proposes and commits a GCE rewriting `Roles` to
     make itself OWNER. No client rejects it. At the next epoch it holds OWNER in the **pre-commit**
     extension — which Spec A §3.4 says the removal rule reads — so it can then strip the real owner and
     every admin. §11's own rationale describes precisely this incident, and reaches it from an ordinary
     member rather than from a compromised admin.

     **THE PROPERTY QUERY FOUND TWO FIELDS r3 DID NOT NAME.** `DisappearingBuckets` — so an ordinary
     member can lengthen the group's disappearing timer, which §12.1 calls *"Guaranteed"* and §12.5
     requires the UI to state; and `RetentionPolicy`, whose only normative constraint (*"Either party
     may shorten … Neither may lengthen either unilaterally"*) is written for DMs and has no group
     analogue.

     **AND THE CODE IS BEHIND THE SPEC.** Spec A §3.4 asserts *"Removal authority, validated at every
     client … The check runs on receipt as well as at construction … `TestAdminCannotRemoveAdmin`
     asserts the construction refusal and the receipt rejection separately."* The query above shows the
     error has no call site; `TestAdminCannotRemoveAdmin`, `TestSuccessionRequiresAllFive` and
     `TestSuccessionUnobtainableBelowTwoAdmins` exist **as p7 plan text**
     (`docs/plans/2026-08-12-slice1-p7-group-lifecycle.md:8535, 8810, 8872`) and **in no Go file in
     `connect`**. `owner_successor.go` is a parser and a preimage builder. So §11's client-side
     authorization model is documented as enforced and is enforced nowhere — M-3's claim reproduced one
     altitude below where r3 could see it.

     **Cost at A6.** The rule itself is not a wire field, but two things it rests on are frozen by A6:
     `RoleEntry`'s encoding sits in the group context, hence in the transcript hash and every
     `confirmation_tag` the group has ever produced (`group_policy.go`'s own header calls the canonical
     form *"a security property rather than tidiness"* because a disagreement is *"a permanent fork"*);
     and **`RoleEntry` is defined in no spec document** — `grep -rn RoleEntry docs/specs/` returns
     exactly one line, Spec A:514, where it is used as a field type and never declared. A second
     implementation cannot encode the extension from the specs.

     *Blocks:* **A6.** **FILED, NOT RULED.** Who may change each of the four `0xF001` fields is policy,
     not transcription. Whatever is ruled must be enforced **at receipt** and not only at construction,
     for the reason §11 already gives about modified clients. Dispositioned 2026-09-20.

152. **`M-4` — STILL OPEN in substance; its MECHANISM is SUPERSEDED; and its property is already filed
     under another name as ledger item 128, with a narrower argument that would close it wrong. NEEDS
     RULING. WIRE-VISIBLE. MUST BE MERGED INTO ITEM 128 BEFORE ITEM 128 IS RULED.**

     **Property.** No material that outlives a retention class's own key may be decryptable under a key
     that class's destruction does not destroy — concretely, the per-record metadata (MLS
     `PrivateMessage` header, `type`, `sent_at`, sender) of an `EPH` record must die with the `EPH` key
     rather than live under a class key every member, every future device and every seedphrase holder
     holds forever.

     **Query and output at HEAD.**

     ```
     grep -rniE "rec/v1/head|always retained|always under the" docs/specs/*.md ../connect/message/*.go
     grep -rln "handle_link\|HandleLink" . | grep -v '^./.git/'
     grep -rniE "ct_head.*class|head under the record" SPEC-LEDGER.md docs/specs/*.md
     ```

     MASTER §8:876 `key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)` — **one**
     ladder. MASTER §8:823 *"`ct_head` AEAD, always retained"*. MASTER §8.1:963 *"`ct_head` is always
     under the **durable** class, since it is always retained"* — **two** ladders. Spec A §5.1:1057
     agrees with §8. Spec B §7.2:2589 clears the head for `EPH(1..5)`, and §7.2:2587-2588 keeps it for
     `DURABLE` and `MEDIA`. `handle_link`: **2 files, both under `docs/reviews/`**, zero in the current
     corpus. And the property is filed: **SPEC-LEDGER.md:1571, item 128**, *"BLOCKS CP3b — `ct_head`'s
     retention class is unruled"*.

     **THE DEFECT REPRODUCES, AND IT IS WORSE THAN r3 FOUND IT.** §8.1:963 keys `ct_head` under
     `K_durable[n]`; §8.1's ladder derives `K_durable[n]` from `storage_root[n]`; and MASTER §8.2:994 —
     where the recovery wrap now delivers **`storage_root[n]` itself** rather than r3's `pq_secret[n]` —
     puts that root directly in a seedphrase holder's hands. r3 had to argue that §8.3 *"hands the
     recovery key the material from which `K_durable[n]` follows"*; today §8.2 hands it the root.

     **WHAT IT FALSIFIES, all within a dozen lines of each other.** MASTER §8.1:967-969: *"After the
     timer, retained server ciphertext, a seized device, a newly provisioned device, and a seedphrase
     holder all fail to decrypt."* MASTER §12.4's required UI string. MASTER §13:1933 *"including
     against a device set up tomorrow and against a seedphrase holder."* All three are false for
     `ct_head`. `K_durable[n]` is destroyed nowhere and is delivered to every member's recovery wrap for
     the life of the group.

     **THE ONLY THING STOPPING IT IS A COOPERATING SERVER, AGAINST THE EXACT ADVERSARY §8.1 NAMES.**
     Spec B §7.2 sets `ct_head = NULL` for `EPH(1..5)`. That is an **operational** erasure. §8.1 claims
     the guarantee against *"retained server ciphertext"* — a backup, a replica that missed the sweep, a
     legal hold, a seized snapshot — which is precisely the case erasure does not cover, and precisely
     the case ruling 3 of 2026-09-13 was made to convert from behavioural to cryptographic for
     `eph_root`. The head was left behind by that ruling.

     **MECHANISM SUPERSEDED.** M-4 proposes splitting into `ct_head_chain` (`handle_link` only) and
     `ct_head_meta`. `handle_link` was deleted from the design, so `ct_head_chain` would carry nothing.
     The surviving repair is one clause rather than a split: **key `ct_head` under the record's own
     class key.** It costs nothing for `PERMANENT`/`DURABLE`/`MEDIA` — `K_perm`, `K_durable` and
     `K_media` all descend from `storage_root[n]` and none is ever destroyed — and it makes `EPH`
     metadata die with `K_eph`. It also collapses the one-ladder/two-ladder ambiguity item 128 files.

     **THE MEASUREMENT CORRECTION, AND IT IS THE LOAD-BEARING PART OF THIS ITEM.** M-4's id count is
     zero, and yet its property **is** filed — as item **128**, found 2026-09-04 while writing the m1
     plan, promoted to a CP3b blocker on 2026-09-05, marked wire-visible, filed as m1 open item **M1-6**,
     and **NOT RULED**. *(**Ruled 2026-09-07 — on item 128's own terms, and without this item beside
     it. See the 2026-09-07 note at the end of this item.**)* It reaches M-4's question by an entirely
     different route and never names M-4.
     But it files a **narrower** question — a two-ratchet/one-`stream_index` bookkeeping contradiction
     blocking Task 15's snapshot record — and omits the confidentiality consequence completely: no
     disappearing messages, no seedphrase holder, no §8.1 sentence. **A ruling made on item 128's own
     terms — "`ct_head` is DURABLE, that settles the ambiguity, `SealRecord` may stop refusing" — is the
     reading that ships M-4's harm permanently.** That is the project's own lesson turned on itself: the
     same question, with the argument that reaches the wrong answer. A zero id-count therefore
     distinguishes neither "ignored" nor "silently superseded" from "filed under another name and about
     to be closed wrong", which is the third reason item 146's proposed gate needs the repair item 166
     states.

     **Cost at A6.** Item 128 already states it: *"the retention class is inside `AAD_head` and inside
     the `write_auth` preimage, so a snapshot written at a guessed class is wire-visible and
     unrecoverable after A6."* The key the head is sealed under is a derivation, so the repair costs
     **zero wire bytes** and changes **every head ciphertext** — an interop break if made after the
     freeze. The ladder is not yet implemented in `connect/message`, so the fix still lands in unwritten
     code. *Blocks:* **A6**, and CP3b through item 128. **FILED, NOT RULED — and item 128 must not be
     ruled without this item beside it.** Dispositioned 2026-09-20.

     **2026-09-07 — ITEM 128 WAS RULED WITHOUT THIS ITEM BESIDE IT, WHICH IS THE ONE THING THIS ITEM
     ASKED NOT HAPPEN. RECORDED HERE RATHER THAN ARGUED, AND THE ITEM STAYS OPEN.** The ruling is
     *"`ct_head` is always sealed under the DURABLE class"* — the sentence this item names verbatim as
     *"the reading that ships M-4's harm permanently"* — made on item 128's own terms, with 128's own
     two-ratchet bookkeeping argument and no mention of the confidentiality consequence. It is the
     owner's and it is not reversed here.

     **What follows from it, derived rather than asserted, and it is why the item is still live.**

     - **The ruling's stated premise is false for exactly one class, and it is this item's class.** The
       reason given is *"the head is always retained, so it is keyed by the class that is always
       retained."* Spec B §7.2 sets `ct_head = NULL` for `EPH(1..5)` at `prune_after` and keeps it for
       `DURABLE` and `MEDIA` — the table this item already cites. So the premise holds for the three
       classes where this item says the repair *"costs nothing"*, and fails for the one where it says
       the harm lands.
     - **The other half of the reason is answered by this item's own repair rather than by the
       ruling.** The reason's second clause is that under a shared `record_key` an `EPH` record's
       retained head becomes unopenable when its ratchet is destroyed. Under this item's repair — key
       `ct_head` under the record's **own** class key — an `EPH` head is not retained to be unopenable:
       Spec B erases it in the same statement that erases the body. The failure the ruling prevents is
       a failure only if the head outlives the body, which for `EPH(1..5)` it does not.
     - **So the two positions are not in conflict over `PERMANENT`, `DURABLE` or `MEDIA` at all.** They
       agree there, by this item's own *"it costs nothing for `PERMANENT`/`DURABLE`/`MEDIA`"*. The whole
       of the disagreement is `EPH`.

     **Therefore the scope of the lift is derived and not chosen.** m1 Task 11(a)'s refusal is lifted
     for `PERMANENT` and `MEDIA`, where the ruling and this item agree; `EPH` stays refused, under this
     item. m1's plan, Spec A §5.3 and item 128 all now say so, and Spec A §5.3 carries a MUST NOT
     against sealing an `EPH` head under `K_durable`. **This item is what an `EPH` record now waits on,
     it is what blocks A6 for the head ciphertext, and it is not an m1 item — so it will not be found
     by a reader working the m1 open-item list.** That is the reason this paragraph is long.

153. **`M-5` — STILL OPEN (PARTIAL — one clause of three applied). NEEDS RULING, IN ONE SITTING WITH
     ITEM 155. WIRE-VISIBLE AT MAXIMUM COST.** r3 asked to replace §7's application-layer combiner with
     an MLS `PreSharedKey` proposal, and to stop overclaiming what the out-of-band combination buys.

     **Property.** Post-quantum secret material is combined with MLS output at the **application layer
     only**, so no PQ input ever enters the MLS key schedule, the confirmed transcript hash or any
     `confirmation_tag` — while the document claims conformance to draft-ietf-mls-combiner and an
     *"adversary must break both"* property that an out-of-band combination does not deliver.

     **Query and output at HEAD.** The finding is half construction and half claim, so it takes two,
     and a grep for the string `M-5` or `combiner` returns only the ledger sentence that **keeps** the
     construction:

     ```
     grep -rniE "(pq|post-quantum).{0,80}(transcript|key schedule|confirmation_tag|psk)" \
       docs/specs/*.md SPEC-LEDGER.md
     grep -rn "ProposalTypePreSharedKey" ../connect/mls/proposal_list.go
     ```

     **(a) ZERO hits** — nothing in the four specs or the ledger binds `pq_secret` into the MLS key
     schedule or transcript. **(b)** `connect/mls/proposal_list.go:92` maps `ProposalTypePreSharedKey`
     to `errProfilePsk` (*"pre_shared_key proposals are outside the v1 profile"*, :59). **The shipped
     code does not merely omit M-5's mechanism, it refuses it** — at the proposal-profile gate, at the
     cache `Store`, and at `Group` (`mls/group.go:3192`). The plans say the same: *"the v1 profile has
     no PSKs"*.

     **CLAUSE 1 — APPLIED, and it is why this is PARTIAL rather than open flat.** Spec A §5.9 landmine
     **G1** (:1550) makes the salt/ikm ordering normative and mechanical — *"`crypto/hkdf.Extract(h,
     secret, salt)` takes ikm first, salt second … Swapping them compiles, returns 32 bytes, and passes
     every test that does not compare against an independent implementation"* — with a single call
     site, a lint gate forbidding `hkdf.Extract` elsewhere in three roots, and `TestStorageRootKAT`.

     **CLAUSE 2 — the overclaim — STILL OPEN, verbatim.** MASTER §7:615-618 still reads *"post-quantum
     protection is added at the **storage** layer, following draft-ietf-mls-combiner rather than an
     invented composition. Signal uses the same shape in both PQXDH and SPQR: combine the classical and
     post-quantum secrets so an adversary must break **both**."* SPEC-LEDGER.md:119-121 repeats it as a
     locked lesson. **That ledger sentence is the closest thing in the corpus to a disposition of M-5
     and it is not one:** it does not name M-5, it does not consider the PSK alternative, and its stated
     justification **is** the claim M-5 disputes.

     **CLAUSE 3 — the PSK injection — STILL OPEN and now contradicted by shipped code.** MASTER §7:634
     samples `pq_secret[n]` and X-Wing-encapsulates it in wrap records published **after** the commit
     (§8.2 steps 2 and 4), so `pq_secret` is outside `FramedContentTBS`, outside
     `confirmed_transcript_hash` and outside `confirmation_tag` **by construction**.

     **Cost at A6: maximal, and it is not a wire edit.** A `PreSharedKey` proposal changes `psk_secret`,
     hence `joiner_secret` → `epoch_secret` and every secret below it, and adds a `PreSharedKeyID` to
     the Commit and to the Welcome. It is not an addition to the URmessage layer; it is a change to
     **every MLS epoch key in the system**, plus a reversal of a shipped profile refusal with four gates
     and named tests against it (`group_roundtrip_test.go:653-664`, `apply_proposals_test.go:363`,
     `proposal_list_test.go:500`). Deciding it after the freeze is not a wire break, it is a rebuild.

     **COUPLING — these two must be ruled together.** M-5's `pq_psk_id` binds `u64(epoch)`. Under item
     155's era it must bind the **era** instead. Ruling M-5 alone bakes per-epoch PQ rotation into the
     PSK identifier and makes item 155 more expensive, not less. *Blocks:* **A6.** **FILED, NOT RULED.**
     Dispositioned 2026-09-20.

154. **`M-6` — STILL OPEN on its core clause; its ADDRESSING clause was ALREADY APPLIED on 2026-09-18 as
     an unremarked side effect of adopting M-15; two further clauses are SUPERSEDED by the owner rulings
     of 2026-09-13. NEEDS RULING. WIRE-VISIBLE.**

     **Property.** There is exactly one normative statement of what each wrap target receives and how it
     is addressed, and no second section or document restates a wrap payload set that can disagree with
     it — because a publisher and a restorer reading different sections build a wrap nobody can open,
     with no error anywhere.

     **Query and output at HEAD.**

     ```
     sed -n '634,635p;990,994p;1014,1018p' docs/specs/2026-08-12-urmessage-protocol-design.md
     grep -n "LP(leaf_index)\|u8(target_type)" docs/specs/2026-08-12-urmessage-protocol-design.md
     ```

     MASTER §7:634-635: *"the committer samples `pq_secret[n]` … and X-Wing-encapsulates **it** to every
     active device leaf's `urmessage_leaf_keys` **and to every member's `RECOVERY_PUB`**"*.
     MASTER §8.2:992-994, the table: device leaves receive `pq_secret[n]` and `eph_root[n]` in two
     records; `RECOVERY_PUB` receives **`storage_root[n]` and `archive_secret[n]`**.
     MASTER §8.2:1014-1018: *"a wrap carrying `pq_secret` would leave it able to derive no class key and
     open nothing … Seed-only restore would not work at all."* `LP(leaf_index)` in the wrap `info`: **0
     occurrences**; MASTER §7:646 now reads `‖ u8(target_type) ‖ LP(target_id)`.

     **THE DISAGREEMENT r3 CITED IS STILL THERE, IN THE SAME TWO SECTIONS OF THE SAME DOCUMENT, AND IT
     IS NOW SELF-REFUTING.** §7 instructs the construction §8.2 spends a paragraph proving is useless —
     and §7 is the section carrying the only normative wrap KDF block, the section amended twice in the
     last month, and the section an implementer reads first.

     **§7 IS ALSO NOW INCOMPLETE AGAINST ITS OWN TABLE.** Ruling 3 of 2026-09-13 made the device wrap
     two records with two payloads. §7:634 still names one secret going to device leaves, while §7's own
     `info` table three paragraphs later (line 683) justifies `u8(payload_type)` on the grounds that *"a
     device leaf now receives **two** wrap records at one epoch"*. The prose and the table of one section
     disagree about how many payloads a device leaf receives.

     **WHAT IS APPLIED, AND THE RECORD OF IT IS THE PROBLEM.** M-6's addressing clause — *"Replace
     `LP(leaf_index)` in `info` with `u8(target_type) ‖ LP(target_id)`"* — is in MASTER §7:646, adopted
     2026-09-18. The §7 amendment marks `u8(target_type)` and `u8(payload_type)` *"new"* and attributes
     them to **M-15**; M-6 is named nowhere in the corpus. **One of M-6's two clauses landed by accident
     and no document records that it did** — item 146's failure mode producing a false negative as well
     as a false positive.

     **WHAT IS SUPERSEDED, recorded as rejected-with-reason rather than dropped.** (i) M-6's premise —
     *"the surviving set is small: {`pq_secret[n]` → device leaves} and {`pq_secret[n]`,
     `archive_secret[n]` → member recovery key}"* — is superseded twice: the recovery payload is
     `storage_root[n]`, and there are now **three** wrap records. (ii) M-6's *"with `eph_root[n]`
     delivered over the MLS application channel"* is superseded by ruling 3 of 2026-09-13, which
     delivers it in its own `EPH(5)` wrap record, for a reason M-6 did not have: the four-week rung the
     server actually prunes, which is what made §8.1's promise cryptographic.

     **WHAT SURVIVES AND IS OPEN:** M-6's instruction itself — make §7 the single normative wrap
     definition and §8.2's table a pointer to it. **Five documents currently state a wrap payload set**
     (MASTER, Spec A, Spec B, the m1 plan, this ledger; two of the five restate rather than state, and
     the count is a presence grep, not a normativity judgement). §7's is wrong. That is exactly the
     failure mode M-6 predicted, reached by a route M-6 did not predict, and live at HEAD.

     **Cost at A6, corrected — the divergence is SILENT, which is worse than being caught.** Spec A:2288
     and Spec B:2451-2452 both size the wraps: a device wrap carrying one 32-octet secret is **1,178 B**,
     a recovery wrap carrying `storage_root`(32) + `archive_secret`(64) is **1,242 B**, each plus a
     64-octet signature, and *"every one of them still lands in `size_bucket 2` — a `ct_body` of exactly
     4,112 bytes … with roughly 2.8 KB of slack unused"*. Spec B §5.1 check 3's equality is
     `octet_length(ct_body) == size_bucket_bytes[b] + 16`, against the **padded** bucket. So the 64-byte
     plaintext difference is invisible to the server: an implementer building from §7 produces a wrap
     the server accepts and the restorer decapsulates successfully and cannot use. *Blocks:* **A6.**
     **FILED, NOT RULED** on which section is normative and whether §8.2's table is deleted or demoted;
     the payload correction to §7 itself is a transcription of §8.2's already-ruled answer.
     Dispositioned 2026-09-20.

155. **`M-7` — STILL OPEN, and strictly worse than when raised, by a ruling made four weeks after it and
     without reading it. NEEDS RULING, IN ONE SITTING WITH ITEM 153. WIRE-VISIBLE ON THREE COUNTS.**

     **Property.** Any secret that must reach every member (or every device) is re-sampled on **every**
     MLS epoch and delivered by **per-recipient** public-key encapsulation, so the per-epoch cost is
     O(members × devices) encapsulations sitting beside TreeKEM's O(log n) — which makes the O(log n)
     irrelevant. The property is *a per-epoch fresh secret delivered by per-recipient encapsulation*,
     **not** `pq_secret`; r3 named one instance.

     **Query and output at HEAD.**

     ```
     grep -rnE "fresh CSPRNG|32 B CSPRNG|CSPRNG at commit" --include=*.md docs/specs/
     grep -rnE "expected_wrap_count *=" --include=*.md docs/specs/
     grep -rniE "\bpq[-_ ]?era\b" --include=*.md --include=*.go . ../connect | grep -v r3-spec-review
     ```

     **"era": zero hits corpus-wide** — the concept does not exist. **Class members at HEAD: THREE,
     where r3 named one.** (1) `pq_secret[n]`, MASTER §7:634, 32 B CSPRNG per epoch → `PERMANENT` device
     wrap, one per active device leaf. (2) `eph_root[n]`, MASTER §8.1, 32 B CSPRNG at commit → `EPH(5)`
     device wrap, one per active device leaf — **created by ruling 3 of 2026-09-13, i.e. after r3**.
     (3) `storage_root[n]` + `archive_secret[n]` → recovery wrap, one per member. Plus the ~300 KB epoch
     snapshot. `expected_wrap_count = 2 × (active device leaves) + 1` (Spec A:2240, MASTER:1186).

     **REPRODUCED, AND THE NUMBER MOVED THE WRONG WAY.** r3 measured ~3,000 wraps ≈ 5 MB per epoch. The
     corpus at HEAD measures **2,503 records ≈ 11.5 MB per epoch over ~90 round trips** — Spec A:1584,
     Spec A:2293, Spec B:373 (*"the per-commit figures go from ~30 KB / ~700 KB / ~6.9 MB to ~40 KB /
     ~1.2 MB / ~11.5 MB"*). Epochs advance on every Add/Remove/Update and nothing rate-limits them.

     **THE SHARPEST FACT.** Ruling 3 of 2026-09-13 split the device wrap into two records precisely to
     make §8.1's disappearing-message promise cryptographic (item **136**, CLOSED). That was correct on
     its own terms — and it **doubled the linear arm M-7 exists to delete**, from ~6.9 MB to ~11.5 MB and
     ~55 to ~90 round trips, four weeks after M-7 was raised and never read. Spec A §5.11 states the cost
     plainly as one of the ruling's three accepted costs.

     **M-7 IS THE ROOT OF FIVE OPEN LEDGER ITEMS.** Under a PQ era, an additive Commit or an Update
     publishes **no wrap fan-out at all**, and the following stop existing on the common path rather
     than needing separate rulings: item **134** (a stalled fan-out is terminal), item **138** (nothing
     detects a missing recovery wrap), item **139** (the `env_key[k]` past-epoch caching obligation,
     whose miss is unrecoverable), item **142** (a live committer loses its recovery arm to somebody
     else's legal commit, permanently), item **148** (a same-epoch snapshot republish is a two-time pad).
     Every one is a hazard **of the per-epoch fan-out**. Ruling M-7 first collapses the population they
     range over; ruling them first spends five rulings on a mechanism M-7 proposes to make rare.

     **WIRE-VISIBLE ON THREE COUNTS.** (1) the era must be bound into the transcript so it cannot be
     silently stretched — a group-context extension field, covered by `confirmation_tag`; (2) MASTER
     §7's wrap `info` carries `u64(epoch)`, which becomes `u64(era)`, so the wrap key's **value**
     changes; (3) `expected_wrap_count`'s formula, the `EpochComplete` marker's meaning and the §8.2
     publication sequence all change shape.

     **What deferring costs.** The freeze locks a fan-out whose measured cost is 11.5 MB per membership
     change at the design target the spec itself **enforces** (500 members, refused by the committing
     client *and* every receiving client). r3's phrase is still the right one: TreeKEM's O(log n) is
     irrelevant if a linear layer sits beside it. *Blocks:* **A6.** **FILED, NOT RULED.** Dispositioned
     2026-09-20.

156. **`M-8` — SUPERSEDED. The property is met by a different mechanism, ruled in revisions 4/6/7
     without ever citing M-8. Two residuals, one of which needs a narrow ruling.**

     **Property.** A credential a removed member still holds continues to be accepted after the removal
     takes effect, because the storage layer defines no retirement for it.

     **Query — the property, not the constructs, because the constructs are gone.**

     ```
     grep -rn 'prev_high_water_index\|EPOCH_WRITER_SET\|handle_link\|may_write' docs/specs/ SPEC-LEDGER.md docs/plans/
     grep -rniE 'retire|read_key_window' docs/specs/ | grep -iE 'write_key|read_key|epoch'
     ```

     All four constructs: **0 hits corpus-wide.** Both per-epoch credentials the server holds now have
     a bounded retirement. `write_key[n]`: Spec B decision **B9** — *"Advancing an epoch sets
     `retire_time = now()` on the outgoing epoch …; the 5-minute tidy loop (§7.4) NULLs
     `write_key_wrapped` where `retire_time < now() - interval '60 seconds'`."* `read_key[n]`: Spec B
     §5.3 / decision 8 — retained `read_key_window_seconds`, default **7776000** (90 days), then NULLed,
     and advertised as `Capabilities.read_key_window_seconds`.

     **(a) *"Make `prev_high_water_index` a ceiling as well as a floor"* — superseded by key retirement,
     in a strictly better place.** A member removed by the commit creating n+1 cannot submit epoch-n
     records once `write_key[n]` is NULLed, because Spec B §5.1 check 6 resolves *"the current epoch's
     key and one briefly-retired predecessor"* and nothing else. The ceiling is enforced on the
     **credential**, not on the counter — which does not depend on the removed writer publishing a
     successor handle at all, the weak point of r3's own (a).

     **(b) *"the host stamps a retirement time"* — literally what happened, minus the construct.**
     `message_epoch.retire_time` is stamped by §6.1 step (6) on a won commit. r3's mechanism, r3's field
     name, arrived independently.

     **The read side is the half r3 did not separate out and the corpus did.** Spec B:2034 states M-8's
     own defect without citing it: *"A member removed at epoch n keeps read authorization … until epoch
     n's read key ages out, and no longer. **Under the previous design it kept that access for the life
     of the group, which is the defect the window closes.**"* MASTER §0 rev 7 says the same, and §13
     discloses it to users under *"On metadata after removal"*. A full, disclosed disposition of the
     property.

     **RESIDUAL 1 — the write window is not 60 seconds, and three documents say it is.** B9 sets
     `retire_time` immediately, but the NULLing is done by a loop that runs **every 5 minutes**
     (Spec B §7.4:2696), so the true bound is 60 s **plus up to one tidy period ≈ 6 minutes**. MASTER
     §9.2:1362 and Spec A:5128 both state a flat *"(60 s)"*. Check 6's in-process LRU can extend it
     further: negative results are documented as cached 5 s with jitter, **positive results have no
     stated TTL at all**.

     **RESIDUAL 2 — nothing client-side rejects such a record.** It is an MLS `PrivateMessage` from a
     leaf that was valid at epoch n, so it verifies at every client and renders normally; `sent_at` is
     client-declared inside `ct_head`. r3's clause (a) was a **client** rule and no client rule of any
     shape exists. The harm is small — a removed member gets a several-minute last word — but it is the
     exact shape r3 named and it is undocumented.

     *Blocks:* nothing. Both windows are server configuration, one advertised in `Capabilities`, neither
     a frozen field. **The only ruling owed is narrow:** accept the ~6-minute write window and correct
     the three *"60 s"* sentences to say what enforces it, or make the bound normative. Dispositioned
     2026-09-20.

157. **`M-9` — STILL OPEN. The instance r3 cited was deleted; the property is intact, and the remedy is
     already precedented here, on M-9's own argument. NEEDS RULING. WIRE-VISIBLE.**

     **Property.** The set of record facts that survive body erasure and drive client rendering is
     authenticated **only** by keys every group member holds — so once the MLS frame is gone, no
     retained fact can be attributed to its purported sender, and no member's retained metadata can be
     distinguished from another member's forgery of it.

     **Query — an intersection, not a string, because r3's instance no longer exists.** `handle_link`
     returns one hit and it is r2's review file; a query built from it scores M-9 moot. The
     property-shaped query is **A ∩ C**, where A is the fields Spec B §7.2 retains when `ct_body` is
     erased and C is the per-publisher signatures in the storage layer:

     ```
     grep -rniE "handle_link|ct_head_chain|ct_head_meta" --include=*.md --include=*.go . | grep -v r3-spec-review
     grep -rnE "signed under the publisher|Ed25519\(" docs/specs/2026-08-12-urmessage-protocol-design.md
     ```

     **(A)** Spec B §7.2:2587-2588 — `DURABLE`: body erased, **Head: kept**; `MEDIA`:
     `ct_body = NULL`, **Head: kept**, Row kept. Only `EPH(1..5)` clears the head. Spec A §10:5106
     requires it. **(B)** `AAD_head` is sealed under `record_key[i]` ← class key ← `storage_root[n]`,
     group-shared; `write_auth` is `MAC(write_key[n], …)`, group-shared **and** server-held. **(C)**
     three per-publisher signatures exist and all three are scoped away from ordinary records — the
     wrap-body signature (ruled 2026-09-13), `recovery_proof`, and the `RECOVERY_PUB` body signature.
     **A ∩ C = EMPTY.**

     **REPRODUCED AGAINST THE CURRENT CORPUS.** Every member can derive every other member's complete
     record ladder: `sender_handle = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)`, which
     MASTER §8:809 annotates *"stable per group; **every member computes it**"*;
     `record_key[0] = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)` with `class_key`
     group-shared and `leaf_index` public in the ratchet tree; `key_head ‖ nonce_head` from
     `record_key[i]`; `write_auth` under a group-wide `write_key`. So a member can emit a well-formed
     `DURABLE` record at any unused `stream_index` bearing **another member's** `sender_handle` and a
     forged `type`, `sent_at` and `body_hash`.

     **WHY IT IS CAUGHT TODAY AND NOT AFTER ERASURE, in the corpus's own words.** Spec B:1997: *"the
     server holds no group leaf key, so it cannot tell a genuine sender from a member impersonating
     another member. Any check it invented would be weaker than the one the client already performs."*
     MASTER §9.2:1348 rests on the same sentence: *"a forged record fails at every client no matter what
     the server accepts (I5)."* **That check is the MLS signature inside `ct_body`.** At
     `create_time + durable_ttl_seconds` — **one year by default on a stock server** — the sweep sets
     `ct_body = NULL` and keeps the head. The check no longer exists, and the forged head is
     indistinguishable from a genuine one, permanently.

     **THE ALREADY-APPLIED TRAP, NAMED SO THE NEXT READER DOES NOT FALL IN IT.** MASTER §9.2:1368-1370
     already discusses a forgery capability and defers a fix: *"An asymmetric per-epoch write proof
     (Ed25519 derived from `storage_root`, server holds only the public half) removes the forgery
     capability … It is the right long-term shape and is a **V2** item."* A sweep asking *"is member
     forgery discussed?"* hits this and scores M-9 addressed. It is **not** M-9, on four counts: (i) it
     is scoped to consequence 1, the **server** forging `write_auth`, not a member forging a peer;
     (ii) *"derived from `storage_root`"* is **one group-wide keypair**, so every member derives the same
     private half and it cannot separate member from member; (iii) it would sign the `write_auth`
     preimage, which carries `LP(H(ct_head))` but **not** the head plaintext `type` and `sent_at` that
     drive rendering; (iv) its v1 acceptance rests on I5's *"fails MLS verification at every client"* —
     the exact sentence erasure falsifies.

     **THE REMEDY IS ALREADY PRECEDENTED HERE, ON M-9's OWN ARGUMENT.** The ruling of 2026-09-13
     (Spec A:2067, MASTER §8.2) requires wrap bodies to be signed under the publisher's identity key
     *"because the wrap is the only record class carrying **no MLS frame** — so without it every field a
     client validates on a wrap is authenticated by nothing, and §9.2's stated mitigation for server
     injection … has no referent for a wrap."* **That is M-9's argument word for word.** The ruling
     applied it to the class where the MLS frame is absent **by construction** and did not notice that
     erasure makes it absent **by operation** for `DURABLE` and `MEDIA`. **I5 does not block the fix and
     needs no amendment:** its wording is *"no second signature over CONTENT"*, and `type` / `sent_at` /
     `body_hash` are header facts — the same reading MASTER:909 already used to admit the wrap
     signature.

     **Cost at A6.** The signature goes inside `ct_head`'s plaintext, so it changes the head layout and
     its length. The wrap absorbed 64 octets free because it sits at `size_bucket 2` with ~2.8 KB of
     slack; an ordinary record at `size_bucket 0` is 256 B and has no such slack, so the size question
     is real and is a freeze item. The head cap is also enforced server-side (Spec B §5.1 check 3,
     *"`ct_head` ≤ head cap"*), so the bound is a configured number that would move. *Blocks:* **A6.**
     **FILED, NOT RULED.** Dispositioned 2026-09-20.

158. **`M-10` — STILL OPEN on its structural half; its two other claims are REJECTED against measurement,
     and the property has a SECOND instance nobody had found, which the proposed remedy does not close.
     NEEDS RULING. WIRE-VISIBLE.** This item is also the place where **this pass made item 147's own
     error**, and that is recorded rather than quietly fixed.

     **Property.** A server-visible identifier derived from long-lived, unrotatable key material whose
     KDF `info` binds **no group, no epoch and no server**, so one constant value links every context it
     appears in for the life of the seed.

     **THE QUERY THAT WAS WRONG, AND WHY.** The first pass ran
     `grep -rhoE '[a-z_]*handle[a-z_]* *= *HKDF-Expand\([^)]*\)' docs/specs/*.md` and reported *"exactly
     one instance, and it is the one r3 named."* **That query enumerates the literal token `handle`,
     which appears nowhere in the property above.** It is `handle` because `recovery_handle` is what r3
     named — the instance, not the property — which is item 147's failure repeated one altitude down,
     inside a disposition written to demonstrate the lesson. **The property-shaped query names no
     token:** *every derivation off `recovery_root`, whatever it is called and whatever it produces.*

     ```
     sed -n '418,426p' docs/specs/2026-08-12-urmessage-protocol-design.md
     grep -rnoE "HKDF-Expand\(recovery_root,[^)]*\)" docs/specs/*.md | sort -u
     ```

     **TWO instances, not one**, and they sit two lines apart in the same block:
     `recovery_handle = HKDF-Expand(recovery_root, "idx/v1", 16)` and
     `recovery_sig_seed = HKDF-Expand(recovery_root, "idxsig/v1", 32)` → `recovery_verify_pub`. The
     third derivation in that block, `rk_xwing = XWing.KeyGen(HKDF-Expand(recovery_root, "rk/v1" ‖
     LP(g), 32))`, **binds `LP(g)` one line above them** — so the design already knows how to scope
     this and did so for exactly one of the three.

     **THE SECOND INSTANCE IS AS EXPOSED AS THE FIRST, AND SCOPING THE HANDLE LEAVES IT INTACT.**
     `recovery_verify_pub` is 32 bytes of Ed25519 public key with no group, no epoch and no server in
     its derivation. It rides in the **same** struct (MASTER §5.3:493-494,
     `RECOVERY_PUB { …, LP(recovery_handle), LP(recovery_verify_pub) }`), is stored in the **same**
     database row (`store/migrations.go:351-362`: `message_recovery`,
     `PRIMARY KEY (group_id, recovery_handle)`, `verify_pub bytea NOT NULL CHECK (octet_length = 32)`),
     and the server is required to keep it TOFU per group. **So r3's structural remedy —
     `HKDF-Expand(recovery_root, "idx/v1" ‖ LP(group_id), 16)` — closes the handle and leaves a 32-byte
     unrotatable cross-group join key beside it.** Any ruling must cover both derivations or it does not
     close the property.

     **WHAT IS REJECTED AGAINST MEASUREMENT.** (1) *"the property got worse — r3 said (member, server)
     and it is now member alone."* **False.**
     `git show aa9303e:docs/specs/2026-08-12-urmessage-protocol-design.md` line 167 reads
     `recovery_handle = HKDF-Expand(recovery_root, "idx/v1", 16)` — **byte-identical to HEAD**, at the
     earliest state this repository records. The derivation never carried a server input here; r3's
     *"(member, server)"* describes revision 3, which predates the repo. Nothing changed, in either
     direction. (2) *"the disclosure was not applied at any of the three sites (§5.3, §9.5, §13)."*
     **False, and the three sites are the three r3 named** — the same defect as the query above.
     **MASTER §5.4:518-522 discloses it**: *"The server learns how many groups that handle participates
     in — and in a single-server v1 it already knows the user's full group list, so this adds nothing it
     did not have. Disclosed in §13."* That is revision 4's single-server argument, the same argument
     item 160 accepts to score M-12 SUPERSEDED. And the **false** sentence r3 was correcting — *"handles
     are per-server, so no global identifier exists"* — returns **0 hits corpus-wide**: that half of
     M-10's ask was satisfied by deletion.

     **WHAT REMAINS OPEN, and it is sharper than what was filed.** (i) **§5.4's *"Disclosed in §13"* is a
     dangling forward reference** — §13 never names `recovery_handle`, and a reader sent there finds
     nothing. That is a checkable defect and it survives the correction above. (ii) The **structural**
     ask is untaken: the handle does not appear only in a record the member's own device writes; it
     appears in `server_attachment`, which MASTER §8 calls *"the only server-visible structured field"*,
     on a `PERMANENT` record in every group, and MASTER §8.2 makes the indexing **mandatory** (*"The
     server MUST index … recovery wraps by `recovery_handle`"*), with Spec B §6.1 step (6c) keying
     `message_recovery` on it. (iii) The **second instance** above is unfiled anywhere.

     **Why this needs a ruling and not a transcription.** The handle is the seed-only restorer's index
     (MASTER §5.4, Spec B §4.3.7 resolves restore across candidate groups by it). Scoping it per group
     closes the linkage and costs the restorer the ability to find its groups from the handle alone —
     which after seedphrase loss it cannot do otherwise. **That is a real product trade between
     cross-group unlinkability and seed-only restore, and it is the owner's to make**, now over two
     derivations rather than one.

     **Cost at A6.** `RecoveryTag` is a frozen `server_attachment` body (kind `0x0002`) with a fixed
     16-byte handle and a 32-byte verify key, hashed into `AAD_head` and the `write_auth` preimage.
     Rescoping changes no length, changes **every value**, and changes the server's index semantics —
     the kind of change §14 slice 2 exists to prevent after the freeze. *Blocks:* **A6.** **FILED, NOT
     RULED.** Dispositioned 2026-09-20.

159. **`M-11` — STILL OPEN. The construct r3 raised it against was deleted; the property survived onto
     `(sender_handle, stream_index)`, and the harm is now PERMANENT rather than bounded to one epoch.
     NEEDS RULING. WIRE- OR SCHEMA-VISIBLE.**

     **Property.** A group-symmetric authenticator is the only thing gating a per-member-scoped,
     server-held resource, so any current member can act as any other member on that resource — and no
     client-side check can reverse the server-side state it mutates.

     **Query — the construct query returns nothing, so it must not be the query.** Ask instead which
     server-held resources are keyed on a per-member identifier, and what authenticates the claim to
     that identifier:

     ```
     grep -c 'sender_handle' docs/specs/2026-08-12-spec-b-message-server-operator.md
     grep -n 'sender_handle' docs/specs/2026-08-12-spec-b-message-server-operator.md \
       | grep -icE 'verif|prove|bind to|belongs to the submitt|authenticat'
     ```

     `EPOCH_WRITER_SET`, `may_write`, `entries[]`: **0 hits each** — r3's instance no longer exists.
     Spec B mentions `sender_handle` on **42 lines**; the number that verify it, bind it to the
     submitter, or authenticate the claim to it is **0**. Two per-member server resources are keyed on
     it and both are mutated on the submit path: `message_sender PRIMARY KEY (group_id, sender_handle)`
     carrying `last_stream_index`, and
     `message_stream_claim PRIMARY KEY (group_id, sender_handle, stream_index)`.

     **THE ATTACK, EACH STEP QUOTED.** (1) The victim's identifier is computable by the attacker —
     MASTER §8:808-809, `sender_handle = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)`,
     annotated *"every member computes it"*, and `group_handle_key` reaches every member in the Welcome.
     (2) The authenticator over it is group-symmetric — MASTER §9.2, `write_auth = MAC(write_key, … ‖
     LP(sender_handle) ‖ …)`, *"One group-wide key, so the server learns only 'a current member of this
     group'."* (3) Nothing checks the claim — Spec B §5.1's only `sender_handle` check is check 3,
     `octet_length(sender_handle)==16`, a **shape** check; check 2 authenticates the connect-layer
     `ByJwt`/`SourceId` and is never joined to the handle, and §9.2 states the design goal that forbids
     joining them. (4) The corpus states the gap itself — Spec B:1997, quoted in item 157. (5) The
     server then mutates per-victim state on the unverified claim — Spec B §6.1 step (3) reads
     `last_stream_index` for the **claimed** handle and step (7) writes it back with
     `ON CONFLICT (group_id, sender_handle) DO UPDATE`.

     **COST: ONE 256-BYTE RECORD, PERMANENT.** Submit under the victim's handle at
     `stream_index = 2^63 − 1`. There is no upper bound and no gap limit anywhere — the schema is
     `stream_index bigint NOT NULL, CHECK (0 <= stream_index)` (`store/migrations.go:149,179`) and
     check 3 does not bound it. Every later legitimate write from that member returns
     `REASON_STREAM_INDEX_REGRESSED`.

     **WHY IT IS PERMANENT, WHICH IS WHERE IT EXCEEDS M-11 AS RAISED.** r3's harm was bounded to one
     epoch because `writer_handle` rotated per epoch. It no longer does: MASTER §8:923 *"`sender_handle`
     is stable per group rather than rotating per epoch"*; §8:931 `group_handle_key` is *"fixed for the
     life of the group"*; the handle is a function of `leaf_index`, so an Update does not move it; Spec
     B:2601 *"`message_sender.last_stream_index` is untouched by expiry"*. **No reset or repair operation
     is specified anywhere**, and epoch rotation — the corpus's answer to everything else in this area —
     does not help, because the handle does not rotate.

     **AND IT IS UNDIAGNOSABLE.** §4.5 gives `REASON_EPOCH_STALE` a `current_epoch` and
     `REASON_COMMIT_LOST` a `winning_commit`; `REASON_STREAM_INDEX_REGRESSED = 5` (*"index <= last
     accepted"*, Spec B:1839, `connect/protocol/message.proto:569`) carries **nothing**. The victim
     cannot learn the poisoned high-water mark, so it cannot even jump its counter past it, and §12.2
     C-5 requires the client to render it as a generic failure.

     **WHY THE CORPUS'S OWN DEFENCE DOES NOT COVER IT.** Spec B:1999 — *"A record forged by anyone
     without a group leaf key fails MLS verification at every client regardless of what the server
     accepted."* That argument is about **content authenticity** and it is correct. The damage here is to
     **server-side per-member state**, which no client-side MLS check reverses: the forged record is
     discarded by every client and the victim is still bricked. And the V2 fix §9.2 names does not close
     it either — an Ed25519 derived from `storage_root` is derivable by **every** member (see item 157).

     **r3's residual edits, mapped.** (1) *"add the authenticator to the struct explicitly"* — moot, the
     struct is gone. (2) *"require clients to recompute `may_write` from the M-3 roles"* — unavailable,
     because M-3's roles are unenforced (item **151**). (3) *"first-wins per `(group_id, epoch)`, never
     replaced"* — the right shape, and it survives as a first-wins binding of `sender_handle` to a
     `client_id`. It costs exactly the property §9.2 bought (*"the server cannot attribute a record to a
     device"*) and collides with §9.7/§11's ban on storing `sender_handle` beside `client_id`, **which
     is why it is a ruling and not a transcription.** *Blocks:* **A6** — every candidate fix adds a
     per-sender authenticator to the record header or to `server_attachment`, or a server-side binding
     table. **FILED, NOT RULED.** Dispositioned 2026-09-20.

160. **`M-12` — SUPERSEDED. The remedy was deleted by a named ruling, for a reason that faces M-12
     directly. One disclosure residual survives and is transcribable.**

     **Property.** A server-visible structure that lets the blind host recover a stable per-member
     pseudonym, and therefore a complete per-member activity graph, from data it is given for another
     purpose.

     **Query — not `entries[]` or `writer_handle`, but the property: does the host end up holding a
     stable per-member pseudonym, by whatever route?**

     ```
     grep -n 'is stable per group\|group_handle_key = HKDF' docs/specs/2026-08-12-urmessage-protocol-design.md
     grep -rniE 'foreign host|foreign server' docs/specs/ SPEC-LEDGER.md
     ```

     MASTER §8:808, §8:923, §8:931 — yes, and by construction. **`foreign host` / `foreign server`: 0
     hits** — the threat model M-12 was written against is gone. `EPOCH_WRITER_SET`, `entries[]`,
     `writer_handle`: 0 hits each.

     **THE RULING THAT SUPERSEDES IT, NAMED.** MASTER §0:35-36 — *"**Revision 4** narrows v1 to one
     message server and many providers carrying traffic, which removes the read-through proxy,
     **per-epoch handle rotation**, and per-device capability blinding."* Per-epoch handle rotation **is**
     M-12's remedy, deleted by name. And the reasoning faces M-12 directly, MASTER §8:923: *"Per-epoch
     rotation existed to stop **foreign** hosts linking a member across epochs; with one server that the
     client authenticates to, it bought nothing and cost three defects."*

     **Why this is accepted rather than re-raised.** M-12's harm was that the host could **recover** the
     pseudonym by correlating entry position across epochs. The ruling grants the host the pseudonym
     outright and argues the mitigation was theatre: the client authenticates to this single server on
     every connection, so the server can link a member across epochs at the transport layer whether or
     not the handle rotates. That is sound. r3 reviewed revision 3; revision 4 removed the boundary that
     made the finding load-bearing. **A rejection with reasons, already written down — it simply never
     cites M-12.**

     **RESIDUAL — the disclosure half, which the ruling does not discharge.** MASTER §9.5:1506-1507 says
     the server sees *"Your account, your group list, `sender_handle` per group, record sizes by bucket,
     timing, retention class. **Not** content, and not which member a handle belongs to."* Every clause
     is true and the emphasis is misleading: because the handle never rotates, the server holds a
     **complete per-member activity graph for the life of the group** — every record, size bucket,
     timing and retention class, partitioned by member — missing only the name. *"Not which member a
     handle belongs to"* reads far weaker than what is held, and Spec C:455 propagates it to the UI.
     §13's *"Worse than Signal"* paragraph lists four disclosures narrower than this one and omits it.
     **One sentence in §9.5 and one in §13, in the register §13 already uses. TRANSCRIBABLE** — it states
     a consequence of a decision already taken and needs no new ruling.

     **Consistency note, not a defect.** `wrap_target_handle` still binds `u64(epoch)` and so still
     rotates per epoch — the mitigation revision 4 called worthless, retained on the neighbouring handle.
     It costs nothing and buys nothing, since the server can invert it by submission position and already
     holds the stable `sender_handle`. Recorded so a later reader does not take the rotation as evidence
     of a privacy property the design does not have. *Blocks:* nothing. Dispositioned 2026-09-20.

161. **`M-13` — SUPERSEDED. The construct was deleted by revision 4 and the substance was independently
     applied in revision 7, which reproduces M-13's argument without citing it.**

     **Property.** A capability is scoped to the MLS epoch, which advances on every Add/Remove/Update,
     so it expires precisely in the case it exists to serve: a client that was offline across a commit.

     **Query — enumerate every client-held authorizer and ask what its validity is scoped to, epoch or
     time.**

     ```
     grep -rniE 'READ_DELEGATION|home.server|delegat|prefetch' docs/specs/*.md
     grep -rniE 'read_key_window' docs/specs/ | grep -iE 'read_key'
     ```

     `READ_DELEGATION`, `home server`, `prefetch`: **0 hits**. `delegat*`: 2 hits, neither a capability.
     Authorizers: `write_auth`/`write_key[n]` is epoch-scoped with a ~60 s server retention and is
     deliberately not a caching capability; `req_auth`/`read_key[e]` is indexed by epoch and **time**-
     scoped at the server — retained `read_key_window_seconds`, default 7776000 (90 days), and any
     retained key is accepted.

     **THE CONSTRUCT IS GONE**, together with the thing it delegated to: MASTER §0 rev 4 *"removes the
     read-through proxy"*. With one server the client authenticates to directly there is no home server
     to prefetch, so there is no delegation to time-scope.

     **THE SUBSTANCE LANDED ANYWAY, AND THE CORPUS REPRODUCES M-13's ARGUMENT VERBATIM.** MASTER §9.2,
     *"Why the read key is not the epoch's write key"*: *"a member that was offline across a single
     commit for more than a minute holds a `write_key` the server can no longer resolve. If reads were
     authenticated under that key, such a member could not call `GroupStatus` … could not `Fetch` …
     could not `WrapFetch` its own wrap — **every path out of the condition is itself a read**."* Same
     defect, same mechanism, arrived at independently. MASTER §0 rev 7 records the change.

     **Clause by clause against r3's proposed `{group_id, home_server_id, not_before, not_after, auth}`:**
     `group_id` — present, read keys are per `(group_id, epoch)`. `home_server_id` — moot, one server.
     `not_before` — present, `read_key_install`. `not_after` — present, install + window.
     *"survives epoch changes"* — **satisfied, and it is the whole point**: any retained key is accepted,
     so a client offline across many commits authenticates with the newest key it still holds.
     *"Cap `not_after − not_before` normatively"* — satisfied as a **published number** rather than a
     constant: Spec B decision 8, *"it is advertised as `Capabilities.read_key_window_seconds` … and it
     is a published number, not a tuning knob: changing it changes a statement in MASTER §13."*

     **The one clause not applied is a DISCLOSED REJECTION, not an oversight.** r3 asked for the
     delegation to be *"revoked by `Remove`"*. It is not: a removed member keeps read authorization until
     epoch n's key ages out. That trade is stated in three places, in the register a disclosed trade
     belongs in — MASTER §9.2, Spec B:2034, and §13's *"On metadata after removal"*: *"It is not instant,
     and 90 days is the price of letting a member who closed their laptop for a season come back and
     catch up."* Trading revocation for offline catch-up is the same trade M-13 was making in the other
     direction; the corpus took the opposite side, said so, and told users.

     *Blocks:* nothing. `read_epoch` is already a request field inside `req_auth`'s
     `canonical_request_bytes`, and the window is server configuration advertised in `Capabilities`.
     **No ruling needed — this item is the disposition.** Dispositioned 2026-09-20.

162. **`M-14` — STILL OPEN. The §6 half is a transcription; the acceptance half needs a ruling. Running
     the suite made the finding stronger than r3 stated it — and it also corrected this pass's own first
     reading, twice. NOT WIRE-VISIBLE.**

     **Property.** The acceptance set MASTER declares for slice 1 **is** the acceptance set actually
     enforced: every RFC 9420 vector family the implementation must pass is named in the normative
     acceptance criterion **and** has a runner behind it, so a family cannot be absent from the gate by
     being absent from the list.

     **Query and output — and the grep-only form of it gives the wrong answer, which is the point.** A
     grep for the five family names returns 7–12 files each (Spec A §4.2.1, two slice-1 plans,
     `VECTORS.sha256`, four test files) and reads as ALREADY APPLIED. **Running it says otherwise:**

     ```
     sed -n '592,594p' docs/specs/2026-08-12-urmessage-protocol-design.md
     wc -l < ../connect/mls/testdata/vectors/VECTORS.sha256
     go test ./mls/ -run 'TestVectorManifestIsComplete|TestVectorFamiliesVerify' -v -timeout 300s
     grep -n 'expectedPendingFamilies = ' ../connect/mls/vectors_test.go
     ```

     MASTER §6:592-594 lists **eleven** families and then says *"**This is the acceptance criterion for
     slice 1**"*. `VECTORS.sha256` pins **sixteen**; Spec A §4.2.1 numbers all sixteen. The run:
     `--- PASS: TestVectorFamiliesVerify (0.29s)`, logging *"9 families verified; 604 published cases
     offered"*. `connect/mls/vectors_test.go:110` declares
     `expectedPendingFamilies = []int{2, 8, 9, 13, 14, 15, 16}` — **seven of sixteen families with a nil
     `Verify` runner.** The five MASTER omits (9 tree-operations, 13/14/15 passive-client, 16
     deserialization) are **all five** in that pending list.

     **THE FIRST CORRECTION THIS PASS OWES ITSELF: the correlation is real but weaker than "what MASTER
     does not name is what has not been built."** All five omissions are pending — **and so are two of
     MASTER's eleven named families**, 2 (crypto-basics) and 8 (welcome). The honest statement is that
     the omitted set is entirely pending while the named set is not entirely built.

     **THE SECOND CORRECTION, and it matters more, because the misreading inverted a sentence.**
     `vectors_test.go:269` reads *"this loop over a manifest of sixteen nil `Verify` funcs completes
     instantly and reports PASS, **which is the shape gate 1 has to be unable to reach**"* — that names
     the failure the test is **built to prevent**, and the test then asserts
     `families == 16 - len(expectedPendingFamilies)` and fails on `families == 0` with *"no family is
     installed, so gate 1 is green with nothing behind it."* Reading it as the file conceding vacuity is
     backwards. **The file's actual disclosed weakness is different and stronger, and it is the one to
     carry:** `vectors_test.go:270-278` — *"What this loop counts is cases OFFERED … a family that
     declined every case it was handed — because the case is at a ciphersuite it does not implement,
     which is the normal condition for five of the seven suites the mlswg files publish — is
     indistinguishable here from one that checked all of them. **Family 6 is offered 77 cases and
     compares 22 of them** … this number is an upper bound and reading it as coverage overstates the
     run."* So the **604** in the log line is an upper bound, and slice 1's acceptance claim rests on
     nine per-family counts nobody has aggregated.

     **THE HONEST SPLIT.** Spec A §4.2.1 is correct and complete at sixteen. `VECTORS.sha256` is
     complete at sixteen. **MASTER §6 is short by five, and MASTER §6 is the sentence that says "This is
     the acceptance criterion for slice 1"** — a slice-1 sign-off read against MASTER alone is
     satisfiable today with seven of sixteen families dark. MASTER §14's slice-1 row says only
     *"Acceptance: the IETF test vectors pass"*, unqualified, so M-14's *"add all five to both sections"*
     is **SUPERSEDED for §14** by a revision that stopped enumerating there.

     **M-14's SECOND HALF — the non-vector acceptance item — is STILL OPEN, and the near-miss is what
     makes it easy to close wrongly.** r3 asked for *"two independent instances running a 3-member group
     through a concurrent-commit collision and demonstrating the B-3 CAS outcome."* Spec B §12:3529 item
     2 specifies a commit-race property test (k concurrent committers at one epoch against real Postgres,
     k ∈ {2, 8, 64}, 1,000 iterations) and `store/contract.go:86-87` implements
     `ConcurrentCommittersAtOneEpoch` and `ACommitRacingOrdinaryWritesAtTheSameEpoch` against both
     stores. **That covers the SERVER's CAS.** It does not touch MLS state, does not exercise the loser
     protocol (re-derive against the winner and retry — MASTER §9.3, Spec A §5.12's seven steps, whose
     step 2 is the hard MUST NOT on `pq_secret[n+1]` reuse that Spec B §12.1 A-6 calls a silent-corruption
     failure invisible in functional tests), and is not a slice-1 acceptance item. **The client half of
     B-3 is asserted by nothing in either tree.**

     *Blocks:* not A6 — nothing here changes a byte. It gates **slice 1's completion claim**, which is
     nearer. The §6 half is a pure **TRANSCRIPTION**: Spec A §4.2.1 already fixes the answer at sixteen
     and MASTER need only say sixteen. **FILED, NOT RULED** on the second half — whether the two-instance
     CAS interop run joins slice 1's acceptance set, and whether a vector gate may report green with
     families pending and with an offered-not-compared count. Dispositioned 2026-09-20.

163. **`M-15`-ADJACENT, INSTANCE 3 — STILL OPEN. A third member of M-15's class, invisible to the
     property query item 147 published as the repair for exactly this failure. NOT WIRE-VISIBLE.**

     **Property.** Item 147's, generalised one step: an AEAD key whose derivation does not yield that
     AEAD's **own** nonce length, and whose `info`/AAD does not bind `alg_id`.

     **Query — item 147's, with its enumerations removed.** Item 147 published
     `grep -rhoE 'HKDF-Expand\(.{0,90}?, *(16|24|32|48|56|64)\)' docs/specs/`. That regex enumerates two
     things the property does not mention: **a length domain** `{16,24,32,48,56,64}`, and **the
     assumption that a derivation fits on one line within 90 characters.** Both are properties of the
     instances already known. Remove them:

     ```
     perl -0777 -ne 'while (/HKDF-Expand\((.{0,160}?),\s*(\d{1,4})\)/gs) { my $a=$1; my $n=$2;
       $a =~ s/\s+/ /g; print "$n <- HKDF-Expand($a)\n" }' docs/specs/*.md | sort -u \
       | grep -vE "^(16|24|32|48|56|64) "
     ```

     Item 147's query at HEAD returns **33** derivations and **zero** containing `entry/v1`. The
     de-enumerated query returns **exactly one** derivation item 147 cannot see:
     `44 <- HKDF-Expand(local_store_key, "entry/v1" ‖ LP(group_id) ‖ LP(message_id))`. Widening item
     147's **scope** as well — it runs only over `docs/specs/` — to `docs/plans/` and `SPEC-LEDGER.md`
     adds no further derivation, so the scope limit is harmless today, but it is a third enumeration in a
     query offered as a property.

     **THE DEFECT.** Spec A §8.3a:4408-4412, verbatim: `per row: key ‖ nonce =
     HKDF-Expand(local_store_key, "entry/v1" ‖ LP(group_id) ‖ LP(message_id), 44)`, sealed with
     `XChaCha20-Poly1305(key, nonce, aad = the row's plaintext index columns, …)`. **44 = 32 ‖ 12.
     XChaCha20-Poly1305's nonce is 24 octets.** The corpus states that four times and uses it three
     times as a load-bearing argument to settle `alg_id` by elimination (MASTER:189, :665, :885, :1050).
     Every other `key ‖ nonce` split in the corpus is **56 = 32 ‖ 24**: `rec/v1/head`, `rec/v1/body`,
     `wraphead/v1`, `snap/v1`, and M-15's own `wrap_key ‖ wrap_nonce`. This one contradicts all of them.
     Either the length is wrong (should be 56) or the AEAD name is wrong (ChaCha20-Poly1305 IETF, 12-octet
     nonce), and **no other document can arbitrate**: `entry/v1` occurs **exactly once** across every
     `.md` and `.go` in `msgrepo` and `connect`. Its AAD also binds no `alg_id`, which is M-15's second
     half, untouched.

     **WHY THIS IS THE ASSIGNED LESSON REPEATING AT A FOURTH ALTITUDE.** Item 146: a class dispositioned
     by a **count**. Item 141: a location query built from the **numbers** a ruling changed. Item 147: a
     class swept by the **construction** M-15 was raised against. This: item 147's own repair query
     enumerating the **lengths** and the **line shape** of the instances it already had. Item 147 stated
     the property correctly in prose — *"an AEAD key produced by a bare expand, with no nonce beside it
     and no `alg_id` bound"* — and that prose mentions no length and no line; the regex added both.
     **A query is property-shaped only if every literal in it appears in the property.** This
     de-enumerated form is the best template the pass produced and is offered as such.

     *Blocks:* nothing — this is local-store-at-rest, not on the wire, so it does not gate A6.
     **TRANSCRIBE, DO NOT RULE — unless the owner wants the AEAD changed rather than the length.** The
     length fix is one character (`44` → `56`); the second decision, adding `u16(alg_id)` to the row AAD,
     is M-15's second half and should be taken with it. Found 2026-09-20, while dispositioning M-15's
     siblings.

164. **`M-15`-ADJACENT, INSTANCE 4 — STILL OPEN. M-15's property in its strongest form, and reachable by
     NO `HKDF-Expand` query, because there is no expand to find. NEEDS RULING. WIRE-VISIBLE.**

     **Property.** The same property stated over the **AEAD (the consumer)** rather than over the
     **KDF (the producer)**: every value used as an AEAD key in this corpus is derived together with a
     nonce of that AEAD's nonce length, under an `info` or AAD binding `alg_id`. Stated over the
     producer, as item 147's query is, it **cannot see an AEAD whose key is never derived at all.**

     **Query — the consumer, which has no length domain to enumerate.**

     ```
     grep -rnoE "(XChaCha20-Poly1305|ChaCha20-Poly1305|AES-?128-?GCM|AEAD)\([^)]{0,120}" \
       --include=*.md docs/specs/ docs/plans/ SPEC-LEDGER.md
     grep -rniE "blob.{0,60}(encrypt|seal|AEAD|key)|(encrypt|seal|AEAD).{0,40}blob" --include=*.md docs/specs/
     ```

     The consumer query returns exactly **one** explicit AEAD invocation in the spec corpus outside
     §8.3a — Spec A:2471, the rendezvous deposit, which is item **145**. Everything else is named only in
     prose, **which is itself the finding.** For the blob object the corpus's entire statement of its
     encryption is two prose fragments: Spec A:4308 *"file body encrypted under the message's class
     key"* and Spec B:1121 *"The bytes are already client-encrypted under the `MEDIA` class key."* **No
     derivation, no nonce, no AAD, no `alg_id`.** The m1 crypto plan's Task 20 produces
     `blob_id = HKDF-Expand(record_key[i], "blob/v1", 32)`, the 262,144-octet padder and the MIME sniff —
     **and no content key.**

     **`blob/v1` is an IDENTIFIER, and item 147 classifies it correctly as one** (SPEC-LEDGER:2594, *"an
     identifier (`blob/v1`)"*). **That correct classification is exactly what closes the enquiry too
     early:** having established that `blob/v1` is not an AEAD key, nothing then asks what the blob's
     AEAD key **is**. It is stated nowhere.

     **WHAT IS AND IS NOT SETTLED, so this is not overstated. INTEGRITY IS SETTLED:** Spec B check 8
     compares `body_hash` against `message_blob.content_hash`, SHA-256 over the assembled ciphertext
     computed during multipart compose, and `body_hash` is inside `AAD_head` and the `write_auth`
     preimage — so the object is bound to its record. **CONFIDENTIALITY IS NOT:** the key, the nonce, the
     AAD and the `alg_id` of the object's own AEAD are unstated. Read literally, *"encrypted under the
     message's class key"* means `K_media[n]` — **one key shared by every `MEDIA` record of every sender
     in the epoch**, with no nonce stated, which is nonce reuse across every attachment in the epoch and
     a direct **I7** violation (*"No AEAD key or nonce is ever used twice"*). The intended reading is
     presumably a `record_key[i]` ladder position mirroring `rec/v1/body` — but that is an inference a
     second implementer must make unaided, and two implementers who infer differently produce objects
     neither can open, silently.

     **WHY IT MUST BE SETTLED BEFORE A6.** The object goes to the bulk plane and to a third-party object
     store (Spec B §8.3), padded to a 262,144-byte multiple, up to the 100 MB file cap. A6's own
     acceptance row (Spec A:5229) lists *"records, key schedule, X-Wing, ratchet, wraps, `write_auth`,
     `req_auth` … all must land before the format freezes here."* **A blob object whose sealing is
     undefined is a format the freeze does not fix.**

     **Relation to the other instances.** Item **145** (`rzvdeposit`) is filed-not-ruled and its nonce
     half is justified; item **147** (`snap/v1`) is closed; item **163** (`entry/v1`) is filed above.
     This is the fourth member of M-15's class and **the first that no producer-side query can reach** —
     which is the argument for restating the property over the AEAD, permanently. *Blocks:* **A6.**
     **FILED, NOT RULED.** Found 2026-09-20, while dispositioning M-15's siblings.

165. **THE STATE TABLE'S "30: 8 major, 22 minor" HAS A SOURCE, AND THE SOURCE IS TWO REVIEW FILES THIS
     REPOSITORY REFERENCES NOWHERE — one of which has never been read into the record at all, and whose
     findings CANNOT be measured by item 146's proposed gate because they carry no ids. FILED, NOT
     RULED.** Item 146 asked what hid r3's majors; §1's number is the same failure with a worse
     substrate, and this is what measuring it with the same query shows.

     **Provenance, measured.** `docs/reviews/2026-08-12-r6-verify-remaining.json` contains **exactly 8
     `MAJOR` and 22 `MINOR` entries**. That is §1's *"Remaining | 30: 8 major, 22 minor"*, byte for byte,
     and it is **not** r3's majors class — r3 declares fifteen. The two numbers have been read as the
     same set for five weeks.

     ```
     for f in docs/reviews/*.json; do echo "$f"; grep -o '"severity": *"[A-Z]*"' "$f" | sort | uniq -c; done
     grep -rn "r6-verify-remaining\|r8-verify" --include=*.md --include=*.go . | grep -v '^./docs/reviews/'
     ```

     `r4-findings-full.json`: 41 BLOCKER / 81 MAJOR / 26 MINOR. `r6-verify-remaining.json`: **8 MAJOR /
     22 MINOR**. `r8-verify.json`: **2 BLOCKER / 10 MAJOR / 13 MINOR**. **Second command: zero hits.**
     Neither r6 nor r8 is named anywhere in this repository outside itself — not in this ledger, not in
     a spec, not in a plan. `grep -rn "r6\|R6\|r8\|R8" SPEC-LEDGER.md` returns nothing.

     **THE GATE ITEM 146 PROPOSES CANNOT SEE ANY OF THESE 30, AND IT IS NOT A SCOPE PROBLEM — THEY HAVE
     NO IDS.** Every entry in r6 and r8 has exactly four keys: `severity`, `location`, `problem`, `fix`.
     **There is no id field.** The same is true of the prose reviews' minors: r2's five, r3's eight and
     r4's four are numbered *within their own file* and carry no corpus-wide identifier. So *"every
     finding id declared in `docs/reviews/` is named at least once outside its own file"* is not merely
     unsatisfied for these findings — **it is unrunnable on them**, and a gate that reports on the twelve
     blockers and fifteen majors while being structurally blind to thirty findings whose count §1
     publishes is a gate that will read green over the larger half. This is the second repair item 166
     owes.

     **SO: DISPOSITIONED, OR COUNTED? COUNTED — and here is the sample that says so.** Six of r6's 22
     minors were checked against HEAD by the literal string each names. **Five of five checkable ones
     reproduce verbatim, unapplied:**

     - r6 minor 13 — *"a section mark with no number"*: Spec A:4680 still reads *"and in Spec C §."*
     - r6 minors 10 and 18 — a path that *"exists only in the working scratch"*: Spec B:87 still reads
       *"(edits B-0 … B-24 of `research/r4-edit-plan.md`)"*.
     - r6 minor 17 — *"Spec B §6 ends at §6.4; there is no §6.7"*: Spec B:1052 still cites *"§6.7 already
       flags as the throughput ceiling"*, and Spec B's section 6 still ends at §6.4.
     - r6 minor 7 — *"Spec A has a §6 but no §6.2"*: Spec A:5187 row C11 still reads *"the §6.2 protected
       screen"*, and Spec A §6 is *"The narrow swappable interface"* with no subsections.
     - r6 minor 11 — blockquote style drift, *"183 blockquote lines"*: Spec B now has **239**.

     **AND r8 IS THE SHARPER HALF OF THIS ITEM, because r8 postdates r6 and §1's numbers predate r8.**
     r8 found **2 BLOCKERs** against a state table that says *"Blockers | 0"*. Both were in fact fixed —
     r8's blockers ask for a group-less rendezvous mailbox in Spec B, and Spec B §4.3.11 exists, added in
     its revision 6 — **but the revision entry attributes the work to `research/rendezvous-plan.md` edits
     B1 … B22 and names r8 nowhere.** So the text is right and the record is empty, which is item 146's
     shape exactly, one review round later and against blockers rather than majors.

     **What replaces the number.** §1's *"Remaining"* row is rewritten to point at the disposition record
     rather than to publish a count, because a count is what could not be checked. The residual work this
     item names — dispositioning r6's 30 and r8's 25 the way 149–164 disposition r3's fourteen — is
     **not** done here and is not small: 55 findings, none of them carrying an id to disposition against.
     *Blocks:* nothing mechanically. **FILED, NOT RULED.** Found 2026-09-20, while dispositioning r3's
     majors.

166. **ITEM 146's PROPOSED GATE IS SELF-SATISFYING, AND IT HAS ALREADY BEEN SATISFIED TWICE WITHOUT A
     SINGLE DISPOSITION — by the sentence that records the failure. FILED, NOT RULED.**

     **Property.** A disposition record must record a **disposition**, not a **mention**. A gate that
     asks *"is this finding id named outside its own file?"* is satisfied by the sentence recording that
     the finding was never dispositioned.

     **Query — item 146's own, re-run at `bed5b84` and at HEAD, and additionally over the `connect`
     tree, which item 146's published form does not cover.**

     ```
     git grep -lE "(^|[^A-Za-z0-9-])$id([^0-9]|$)" <rev> \
       -- ':!docs/reviews/2026-08-12-r3-spec-review.md' | wc -l
     ```

     At `bed5b84`: **M-1 … M-14 all 0**, M-15 = 1, controls B-1 = 5, B-6 = 4, B-11 = 3. At HEAD
     (`10f0a39`): **M-1 = 1, M-14 = 1**, M-2 … M-13 still 0, M-15 = 5, B-1 = 6. Over `connect` at HEAD:
     0 for every major. **Nothing was adopted, rejected or filed between those two revisions.** Both new
     hits resolve to `SPEC-LEDGER.md:2517` and `:5823`, and both are **item 146's own sentence**:
     *"`B-1` … `B-12`: 1 to 6 files each, all twelve non-zero. `M-1` … `M-14`: ZERO, every one."*

     **So the entry written to prove these ids were never dispositioned is now the file the query finds
     when it asks whether they were.** And the artefact is not even uniform across the class it
     describes: M-1 and M-14 picked it up **purely because they are the endpoints of the range item 146
     spelled out**; M-2 … M-13 sit inside the ellipsis and stay at zero. Write that list out in full —
     which any conscientious reader of item 146 would do — and **all fourteen pass the gate at once, with
     nothing decided and the ledger reporting full coverage.**

     **This is the third time on this project that a gate turned out to be a proxy that does not track
     its property, and it is the same shape as the other two.** Item 146 diagnosed *"a count cannot be
     checked against a document"* and then proposed a gate that is a count of a different thing. Judged
     by **what it catches and when**, as this project has already ruled a gate must be: as published it
     catches nothing, and it reports success at the exact moment the failure is being described.

     **Three repairs, offered together because each alone leaves a hole.** (a) **Key the gate on a
     disposition VERB adjacent to the id** — `ADOPTED` / `REJECTED` / `SUPERSEDED` / `STILL OPEN` / a
     ledger item number — rather than on the id alone, and **exclude SPEC-LEDGER lines that are
     themselves measurements of the gate.** Items 149–164 are written in that form deliberately, so the
     repair has a corpus to run against on the day it is taken. (b) **Extend the scope to `connect`.**
     Item 146's published query runs only against `msgrepo`; the code that would implement any of these
     findings lives in `connect`, and item **149** found a spec-level finding dispositioned in a Go doc
     comment there (`writeauth.go:50-57`, *"Do not add it"*), which the gate as published cannot see.
     Running it over `connect` changed no answer today, which is exactly why the omission survived.
     (c) **Do not key it on ids alone**, because item **165** shows 55 findings in `docs/reviews/` that
     have no id at all, and a gate keyed on ids reports green over them by construction.

     **MEASURED AGAIN AFTER THIS PASS COMMITTED, BECAUSE THE ARTEFACT CONTAMINATES ITS OWN CONTROLS
     TOO.** Items 149–166 and the 2026-09-20 edit-log entry publish the premise measurement, and
     publishing it names the controls. Re-run at the commit that landed them, against `10f0a39`:
     **`B-6` 4 → 5 and `B-11` 3 → 4**, and the new file is `SPEC-LEDGER.md` in both cases, at the two
     lines that read *"controls B-1 = 5, B-6 = 4, B-11 = 3"*. `B-1` does not move only because item 146
     had already contaminated it the same way. **So the phenomenon is not special to the subjects: any
     id a measurement names, it also inflates.** Nothing about the blockers changed; the number did.
     This is the strongest form of the argument for repair (a): a gate keyed on **mentions** cannot
     distinguish a disposition from a measurement of dispositions, and it drifts upward every time
     anyone measures it — including when the measurement is honest and its conclusion is that nothing
     was dispositioned.

     **And a fourth thing the gate cannot do, recorded because item 152 is the live example.** An id
     count distinguishes *"ignored"* from neither *"silently superseded"* (items 156, 160, 161 — three
     majors closed by revision-4/7 rulings that never cite them) nor *"filed under another name and about
     to be closed wrong"* (item **152**: M-4's property is ledger item **128**, unruled, framed too
     narrowly to be ruled safely). **A gate on mentions would have missed all of that in both
     directions.** *Blocks:* nothing mechanically. **Whether any of this becomes a gate is the owner's
     and is not ruled here.** Found 2026-09-20, while dispositioning r3's majors.

167. **THE EPOCH-ZERO HANDLE KEY'S INVERSE MISTAKE IS ACCEPTED IN SILENCE AND ROUTES THE DEVICE ONTO
     A HANDLE NO PEER COMPUTES. FILED, NOT RULED.** The ruling that produced it is m1 open item
     **M1-4**, 2026-09-07, and Spec A §5.3 revision **A-19** carries the amendment; this item is the
     half the amendment does not close.

     **What was ruled.** `connect/messagegroup`'s `GroupSession` persists **`group_handle_key`** —
     `HKDF-Expand(storage_root[0], "gh/v1", 32)` — for the life of a group, and **not**
     `storage_root[0]`. MASTER §8's clause is about what a member *holds* and it names the key;
     `storage_root[0]` is epoch zero's whole key schedule, and keeping it forever in order to recover
     a public routing identifier every member can already compute is strictly worse. The defect that
     forced the ruling was internal: `installEpochOnLoop` took its argument verbatim as
     `group_handle_key` on one branch and expanded a root through `GroupHandleKey` on the other,
     while the parameter's name, the constructor's doc and `handle.go` all said *"storage root"*.

     **The inverse is undefended, and it is undefended for a reason rather than by oversight.** A
     caller who follows §5.3 as it stood — hold `storage_root[0]`, it is the only value §5.3's block
     takes — and hands `NewGroupSession` that root where it wants the key is **accepted in silence**.
     Both values are exactly **32 octets**, so `ErrGroupHandleKeyLength`'s width refusal passes;
     `keyScheduleExpand` produces a well-formed key from either; every key of the session then
     derives cleanly; every round trip that member makes with **itself** succeeds. What breaks is
     only visible from another member: the device writes on a `sender_handle` no peer computes and no
     peer's `ReceiverRatchetKey` matches, so its records route nowhere and its stream is invisible.
     Reproduced by the batch-C review at `sender_handle dc272587…` where the group computes
     `3e774ae1…`.

     **Why no refusal is proposed here.** There is no value-level check this layer can make: the two
     candidates are the same width, both are uniformly random, and the key is by construction an
     expansion of the root, so "is this the expansion or the pre-image" is not answerable from the 32
     octets alone. Three shapes exist and each costs something: (a) a **typed wrapper** —
     `GroupHandleKey` returns a named type the constructor demands, which makes the mistake a compile
     error and makes the persisted value's encoding a wire-adjacent decision for whoever writes the
     durable store; (b) a **self-check at construction**, only available at epoch 0, where the
     session can expand the current root itself and compare — it catches the founding device and
     nothing restored; (c) **leave it and document it**, which is what shipped. *Blocks:* nothing
     mechanically today, because the only caller is a test. It becomes real the moment `s2` writes
     the durable store, which is the first code that decodes this value from disk. Found 2026-09-07,
     verifying m1 wave 1's batch-C fix pass.

168. **THE SHIPPED `StreamIndexReserver` IS KEYED ON A `StreamKey` AND BOTH DOCUMENTS THAT DECLARE IT
     STILL SAY `groupId`. FILED, NOT RULED — and it is NOT open item M1-5.**

     **What shipped**, `connect` **`095fdd1`**, `messagegroup/streamindex.go`:

     ```go
     Reserve(stream StreamKey, index uint64) error
     HighWater(stream StreamKey) (uint64, error)
     type StreamKey struct { GroupId [32]byte; SenderHandle [16]byte; RetentionWire byte }
     ```

     **What the documents say.** Spec A §5.6's own Go block declares `Reserve(groupId []byte, index
     uint64) error` and `HighWater(groupId []byte) (uint64, error)`. Spec A §8.2's `MessageStore`
     declares `ReserveStreamIndex(groupId []byte, index uint64) error` and
     `StreamHighWater(groupId []byte) (uint64, error)` — the same coarse key, on the fourteen-method
     interface `sdk`'s sqlite implementation owes and whose size A8 makes load-bearing.

     **Why it diverged, measured rather than argued.** A sender ratchet is per `(class_key, leaf)`,
     because `record_key[0]` binds the class key, so one group has one ratchet **per retention
     class**. Over a `groupId`-keyed reserver the durable and the permanent ladders of one group
     reserve out of one counter: measured on the shape the plan declared, the durable ratchet took
     index 1 and every later call on the permanent ratchet answered `ErrStreamIndexConsumed`
     **forever** with its position stuck, so at most one retention class per group could ever send.
     A permanent wedge, and invisible to any test that builds one ratchet.

     **Why this is not M1-5, and the distinction is the whole item.** M1-5 asks which fields a
     durable **store row** is identified by, and it is the one piece of state on this project that
     cannot be migrated by recomputation, so it is the owner's. `StreamKey` fixes which **stream a
     reservation belongs to** — the only half in `connect/messagegroup`'s reach — and the flattening
     from the one to the other is the implementer's. Neither document has been amended, because
     amending §5.6's block would state a keying that M1-5 has not ruled, and this project's rule is
     that a divergence is recorded rather than absorbed. *Blocks:* nothing today; `s2` inherits it
     together with M1-5, and the two must be ruled in one sitting or the store row and the
     reservation will be keyed by different things. Found 2026-09-07, deriving m1's wave-1
     contradictions against the landed package.

     **Commit citation corrected 2026-09-07, the same day, and the correction matters because this
     item is an argument about what one commit contains.** It first cited `7a50f80`. At `7a50f80`
     `messagegroup/streamindex.go` still declares `Reserve(groupId []byte, index uint64) error` and
     `HighWater(groupId []byte) (uint64, error)` — the very `groupId` form this item says the code
     diverges **from** — so the citation named a commit that agrees with the documents and refutes the
     item. `StreamKey` and the two `StreamKey`-taking methods land in **`095fdd1`**, batch C. The
     query is `git show 7a50f80:messagegroup/streamindex.go` against `git show
     095fdd1:messagegroup/streamindex.go`. The cause is the same one the 2026-09-07 entry's own batch
     table had: `7a50f80` was being used as the name of batch B, and batch B's tasks landed in
     `da0b999`.

     **And this item is now load-bearing beyond its own question:** the per-class counter it records is
     one of the four facts new item **169** derives its collision from.

     **WHAT ACTUALLY LANDED, 2026-09-07, AND IT IS THE OPPOSITE OF THE REPAIR THIS ITEM DESCRIBED.**
     This item recorded the shipped per-class `StreamKey` as a **repair** — a `groupId`-keyed reserver
     wedged the second retention class permanently, so the retention wire byte was added to the key to
     un-wedge it. The owner's A1 ruling (items **143** and **169**) **removes that byte again**, and
     the wedge does not come back, because the thing that actually caused it was not the key's
     coarseness: it was `Reserve`'s **assert** shape. A ladder that chooses its own number and offers
     it to a shared counter meets a consumed index and stops; a ladder that is **handed** a number by
     the counter cannot. So the landed shape is `StreamKey{GroupId, SenderHandle}` — class-blind, with
     the sender handle this item was right to add — over `Reserve(stream StreamKey) (uint64, error)`.
     **This item's measurement stands and its diagnosis was one level too shallow**, which is worth
     keeping rather than erasing: the measurement is what made the wedge real, and the ruling is what
     found the cause under it.

     **AND ITS "both documents still say `groupId`" HALF IS CLOSED BY THE SAME PASS.** Spec A §5.6's
     Go block and §8.2's `MessageStore` are amended to the landed shape in revision **A-21**. What
     they now declare is not merely a wider key but a different **direction** — an allocation that
     returns an index rather than an assertion that takes one — and §8.2's two methods gain the sender
     handle they always owed. **The divergence this item exists to record is therefore closed on the
     document side.** What is NOT closed is **M1-5**, which is a different question and stays open, and
     the transition hazard that A1's change of row identity creates for a store that already holds
     wave-1 rows, which is new item **170**.

169. **RULED 2026-09-07 BY THE OWNER — SHAPE A1: ONE CLASS-BLIND `stream_index` PER
     `(group_id, sender_handle)`. `StreamKey` LOSES `RetentionWire` AND KEEPS `SenderHandle`. RULED IN
     ONE SITTING WITH ITEM 143, WHICH IT CLOSES.** Implemented in `connect` on `beta/message`,
     `fa6ab6b` then `7705cbf` then `33932e0`. Spec A §5.3, §5.5, §5.6, §5.10 and §8.2 are amended for
     it (revision **A-21**); Spec B, its schema and MASTER's constructions need **no change**. The item
     as filed, and the seven shapes it laid out, are kept whole below.

     **THE OWNER'S REASON, AND IT IS THE PART TO PRESERVE BECAUSE IT IS CHECKABLE.** A1 is the counter
     the rest of the system **already declares**, and the client was the only half that disagreed.
     Verified before the ruling was taken, and re-verified by this pass:

     | | keys the counter by |
     |---|---|
     | Spec B's schema, `message_sender` | `PRIMARY KEY (group_id, sender_handle)` |
     | Spec B's Q7, run on every submit | `WHERE group_id = $1 AND sender_handle = $2` |
     | the shipped server, `msgrepo/store/memory.go:600-610` | *"per (group_id, sender_handle)"*, gating on `record.SenderHandle` alone |
     | **what m1 wave 1 shipped in the client** | `StreamKey{GroupId, SenderHandle, RetentionWire}` |

     So the retention byte was **not a divergence the documents had left open — it was a client/server
     split already in the tree**, and the server would have **refused the second class's first
     record**: a second class starting again at index 1 is a stream index that went backwards from the
     only counter the server keeps, `REASON_STREAM_INDEX_REGRESSED`. **A1 is therefore not only the
     repair for this item — it closes a live split**, and it is the only one of the seven shapes that
     owes no Spec B change. It also closes item **143**'s device-wrap instantiation (ruling 2's wrap
     root carries no class and ruling 3 puts two classes on it, so a class-blind counter separates
     both AEADs), costs **zero** wire octets and **zero** KAT constants, **breaks nothing already
     sealed** — every record wave 1 sealed came from a sender using one class, whose class-blind
     counter is identical to its per-class one — keeps `i = stream_index` in every ladder, and is
     **neutral if M1-6 is ever reversed**, which no other shape is for free.

     **THE SHAPE CHANGE A1 FORCED, WHICH IS NOT A DETAIL AND IS THE HALF THE OPTIONS PAPER CALLED
     "unwritten discipline (i)".** `Reserve` is now an **allocation**, not an assertion:
     `Reserve(stream StreamKey) (uint64, error)`. Wave 1 shipped `Reserve(stream, index) error` — the
     caller chose the number and the store said yes or no — and every `SenderRatchet` kept its own
     `position` to choose from. That works while each ladder owns a counter and **wedges permanently**
     the moment two ladders share one, which is exactly what item **168** measured. Under A1 two
     ladders share a counter by construction, so the assert shape is not awkward, it is unusable. The
     counter is the **store's** and there is no second copy of it: a ladder cannot ask for an index,
     therefore it cannot ask for a consumed one. The rejected alternative — the session owns the
     counter and passes the index in — was rejected for three reasons, all recorded in
     `streamindex.go`'s header: it moves the reserve-before-derive ordering out of `Next`, where
     `seal_test.go`'s call-graph gate can see it, and back into a convention at every caller; it
     leaves `Next` as a second door onto the same ladder still choosing its own number; and a store
     that owes durability cannot implement read-decide-write with an fsync in it atomically as three
     steps. **The published contract moves with it**: clause 5 is restated (*"two calls are two
     indices; the non-idempotence is structural"*), clause 3 with it (*"no index is ever handed out
     twice"*), and `ErrStreamIndexConsumed` now names the store's permanent inability to allocate.
     **§8.2's `MessageStore` moves the same way** — amended in this pass — and it is a **shape** change
     and not only a keying one, which is why the correspondence the plan called *"method for method"*
     had to be restated rather than re-cited.

     **THE ACCEPTED COSTS, MEASURED ON THIS TREE AND NOT TAKEN FROM THE OPTIONS PAPER.** Reproduced
     2026-09-07 by this pass on the same machine (Intel Core Ultra 9 275HX, windows/amd64) through
     `connect/messagegroup`'s own `BenchmarkSenderLadderRung` and `BenchmarkEpochChangeRebuild`, at
     `33932e0`:

     | | this pass | the implementer | the review | the options paper |
     |---|---|---|---|---|
     | one ladder rung | **390.7 ns** | 417.7 ns | 402.7 ns | 368.7 ns |
     | epoch-change sender rebuild, k=3, P=100,000 | **130.1 ms** | 131.5 ms | 118.5 ms | 148 ms |
     | the same, per-class counters | **41.8 ms** | 41.7 ms | 38.6 ms | (implied P) |
     | ratio, i.e. the multiplier | **3.11** | 3.15 | 3.07 | — |
     | last rebuild before the maxLadderWalk wall | **1.32 s** | 1.21 s | 1.32 s | 1.55 s |

     **AND THE FORMULA IN THE OPTIONS PAPER IS WRONG, WHICH THE MEASURED RATIO IS WHAT SHOWS.** The
     paper priced the epoch-change rebuild at `(k+1) × P` and quoted **148 ms**. It is `k × P`: the
     rebuild is `k` ladders each walking the whole shared counter, and that is all `installEpochOnLoop`
     does. The measured ratio is **3.11** against a `k` of 3, not 4. The paper's arithmetic landed
     within a fifth of the truth **by accident**, because it quoted 368.7 ns a rung against the
     390–418 ns three independent runs measure — the arithmetic agreed where the formula does not, and
     that is the more dangerous of the two errors because it survives a spot-check. The extra `P` the
     paper counted is real work, but it is the epoch's own **sends** walking their gaps rather than
     anything the rebuild does; that half is `k × P` as well, so the honest per-epoch total is
     `2k × P` against the `2P` a per-class counter paid. **The 1.55 s wall figure moves to 1.32 s for
     the same reason.**

     **A class's usable out-of-order window falls to `1,024/k`.** Not a smaller count of retained keys
     — the receiver refuses **by index distance** (`ratchet.go`'s `classifyLocked`, `windowSize <
     index - head`), so a class's own records now sit `k` positions apart inside one 1,024-position
     window. Measured through the shipped `NewReceiverRatchet` at `DefaultRecordWindowSize`: **341**
     of 1,024, which is 1,024/3 exactly. The case that measures it derives `k` off `ClassKeys`' fields
     rather than counting to three, so item **152**'s fourth class key moves the divisor without
     anybody remembering.

     **AND A COST THE RULING WAS TAKEN WITHOUT: THE RECEIVE SIDE IS LARGER THAN THE SEND SIDE.**
     `installEpochOnLoop` drops the receiver table too — `self.receivers.Zeroize()` deletes every
     entry — so each tracked `(sender, class)` pair is rebuilt by `NewReceiverRatchet` walking from
     `record_key[0]` to its head, and under A1 that head is the class-blind index, `k` times further
     out. The walk is `stepRecordKey` in a loop, the **same** loop the sender-side benchmark measures,
     so the 130.1 ms above **is** the per-peer receiver cost at k=3, P=100,000 — about **1.04 s for
     eight peers**, against 334 ms per-class. `ReceiverRatchets.Track` puts no cap on tracked pairs, so
     this scales with peers and not with a bound. Filed as item **172**; it does not reverse the
     ruling, and it was not in front of the owner when the ruling was taken, which is the fact worth
     keeping.

     **WHAT IT UNBLOCKS.** Item **143** closes with it. Spec A §5.3's *"A builder MUST NOT seal a
     non-`DURABLE` record before 169 is ruled"* is **lifted** for `PERMANENT` and `MEDIA` — `EPH` is
     still refused, under item **152** and not under this one. m1's **Task 14** and **Task 15** lose
     this blocker; Task 14 keeps M1-1's remainder and 152, Task 15 is clear of both. *(**Corrected
     2026-09-09:** `M1-1`'s remainder and `M1-7` were ruled that day as composite `C3`, so **Task 14
     keeps 152 and nothing else**.)* m1's **Task 6**
     and **Task 11(a)** are amended to the landed shape. And `s2`'s unwritten store plan inherits an
     interface whose shape is now settled — with item **170**'s transition hazard in front of it,
     which is the one thing about this ruling that is not free.

     **WHAT IT DOES NOT RULE, stated so a later reader does not close it in passing.** **M1-25** —
     `EPH(bucket 0)` transients consume an index out of this one counter, so every typing indicator
     advances it, and with the window refused by distance, 1,025 transients between two `DURABLE`
     records make the second permanently `out_of_window`. That hazard is now **executable rather than
     asserted** (`TestTransientsOnTheSharedCounterStarveADurableReceiverWindow`, with a
     one-short-of-the-wall control above it), and it is **still filed, not ruled**: nothing forecloses
     a separate transient counter and nothing grants one, and giving transients their own counter
     re-opens this very collision for `EPH` heads the day item **152** rules them onto this root.
     **M1-5** is also untouched — it rules which fields a durable **store row** is identified by, and
     A1 rules which stream a reservation belongs to; item **170** is what happens when the two are
     ruled in the wrong order.

     **FIVE THINGS THE REVIEW OF THE IMPLEMENTATION FOUND, FILED AS ITEMS 170 THROUGH 174 RATHER THAN
     CARRIED AS PROSE.** Its verdict was `ACCEPT_WITH_FIXES` and none of the five says the ruling is
     wrong or the implementation unsafe as it stands: **170** the store-row transition hazard, **171**
     the wedge recovery path that cannot be walked, **172** the unmeasured receive-side cost, **173**
     two pieces of the evidence that do not observe the property they name, **174** two claims in the
     implementation's own header that A1 made stale. Every one was reproduced by this pass before it
     was written down.

     *The item as it was filed, with the seven shapes and their costs, follows unchanged. Where its
     numbers disagree with the table above, the table above is the measurement.*

     **THE 2026-09-07 RULING GIVES EVERY CLASS'S HEAD ONE SHARED LADDER WHILE THE SHIPPED RESERVER
     COUNTS PER CLASS, SO ITEM 143's OWN PROPOSED PIN PUTS TWO HEADS ON ONE `(key_head, nonce_head)`.
     FILED, NOT RULED. WIRE-VISIBLE. MUST BE RULED IN ONE SITTING WITH ITEM 143.**

     **Property.** Every `(key_head, nonce_head)` pair a sender ever uses is used once.

     **The derivation, from four things all of which are already fixed.**

     1. Item **128**, ruled 2026-09-07: `ct_head` is sealed under the **DURABLE** class ratchet,
        whatever the record's own retention class.
     2. Spec A §5.3: `record_key[0] = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)` and
        `record_key[i+1] = HKDF-Expand(record_key[i], "ratchet/v1", 32)`. So one sender has **one**
        head ladder per epoch, rooted at `ClassKeys.Durable`, shared by all four retention classes.
     3. Spec A §5.3 / MASTER §8.1: `key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head",
        56)`. The nonce is a function of `(K_durable[n], leaf_index, i)` and of nothing else — no
        class, no `stream_index`, no AAD.
     4. What shipped, `connect` `095fdd1`, `messagegroup/streamindex.go`: `type StreamKey struct {
        GroupId [32]byte; SenderHandle [16]byte; RetentionWire byte }`. The reservation counter is
        **per retention class**, and item **168** records why — over a `groupId`-keyed reserver the
        durable and permanent ladders of one group shared one counter and *"at most one retention
        class per group could ever send."*

     **The collision.** Item 143's repair is *"pin `i = stream_index` in every ladder"*, so that
     uniqueness of `i` follows from Spec A §5.12 step 6's existing *"MUST NOT be reused"* rather than
     from a second, unwritten discipline. Apply it: one sender's `DURABLE` record at
     `stream_index = 5`, and the same sender's `PERMANENT` record at `stream_index = 5` — two records
     that both exist, because the two counters are independent — both take head position 5 of the
     **one** durable ladder. Same `key_head`, same `nonce_head`, two different header plaintexts, two
     different `AAD_head` preimages (the joined retention-class wire byte differs). Under
     XChaCha20-Poly1305 that is a nonce reuse: the Poly1305 one-time key falls out and header
     **forgery** follows — the harm item 143 names for the wrap ladder, arriving on the ordinary record
     path and for every sender rather than once per epoch fan-out.

     **AND IT IS REACHABLE THROUGH THE PUBLISHED CONSTRUCTOR, not only through the documents — the
     same shape of trap item 143 records for the device wrap.** What shipped is
     `func NewSenderRatchet(classKey []byte, leaf uint32, stream StreamKey, reserver
     StreamIndexReserver) (*SenderRatchet, error)` (`messagegroup/ratchet.go:172`): the ladder's root
     comes from `classKey` and its positions come from `reserver.Reserve(stream, …)`, and **the two
     arguments are independent**. An implementer taking the ruling the obvious way builds the head
     ratchet as `NewSenderRatchet(classKeys.Durable, leaf, stream, reserver)` and the body ratchet as
     `NewSenderRatchet(classKeys.Perm, leaf, stream, reserver)` for a `PERMANENT` record — one root,
     the `PERMANENT` counter — and, for a `DURABLE` record, `NewSenderRatchet(classKeys.Durable, leaf,
     otherStream, reserver)` — **the same root**, the `DURABLE` counter. Two ladders with
     byte-identical roots drawing positions from two counters that each start at zero. Nothing in the
     signature, in the reserver or in `SealRecord` can see that the two are the same ladder, because
     the only thing that distinguishes them is the `StreamKey` the reserver was keyed by and the
     reserver is not what derives the key.

     **And doing nothing is not the safe option, which is what makes this due rather than
     filed-for-later.** The other reading — the head ladder advances once per record regardless of
     class — is the owner's stated accepted cost (*"one record's single `stream_index` covers two
     ratchet positions"*), and it needs a head-ladder counter monotone across **all** classes of one
     sender. **No such counter exists in either document or in the shipped code**: Spec A §5.6's
     reserver, §8.2's `MessageStore` and `messagegroup.StreamIndexReserver` all count per stream, and
     a per-class stream is exactly what `StreamKey` made it. So the two readings available today are
     one that collides and one that requires a value nothing produces.

     **Three shapes, each costing something, none ruled here.** **(a) Put the class in the head
     ladder's root** — `record_key_head[0] = HKDF-Expand(K_durable, "sender/v1" ‖ LP(leaf_index) ‖
     u8(retention_wire), 32)` — which restores `i = stream_index` and costs a new label reading, a KAT
     set, and an A6 change to every head ciphertext. **(b) A second reserved counter per sender**,
     head-only and class-blind, which costs a fifteenth method on the `MessageStore` interface whose
     size Spec A A8 already makes load-bearing, and hands `s2` a second thing to migrate and item
     **M1-5** a second thing to key. **(c) Key `ct_head` under the record's own class key**, which is
     item **152**'s repair and dissolves this item entirely — one ladder per class, `i = stream_index`
     holds — and which the 2026-09-07 ruling is a decision against for `PERMANENT`, `DURABLE` and
     `MEDIA`.

     **Cost at A6.** Zero wire bytes under every shape; every non-`DURABLE` head ciphertext changes
     under (a) and (c), which is an interop break if taken after the freeze. *Blocks:* **A6**; sealing
     any non-`DURABLE` record, and therefore m1 Tasks 14 and 15 — the block item 128's ruling was
     expected to lift, arriving one level down. **FILED, NOT RULED.** Found 2026-09-07, deriving the
     consequences of the M1-6 ruling against the landed reserver rather than against the documents
     alone; nobody asked for it and it is the reason the pin is now a precondition.

     **OPTIONS LAID OUT 2026-09-07, COSTS MEASURED, AND NOTHING BELOW IS RULED. THE CHOICE IS THE
     OWNER'S, AND IT IS ONE CHOICE WITH ITEM 143.** The three shapes this item names are three
     points in a space it did not derive. The space is small and it is closed, and deriving it is
     the first thing below, because two of the shapes an implementer reaches for first are not in
     it. Four of this item's own claims did not reproduce against the trees and are corrected here
     rather than carried. Item **143** takes the same amendment from its side: a shape can close
     this item and leave 143's own device-wrap instantiation open, and **four of the seven below do
     exactly that**.

     **THE CLASS, DERIVED FROM THE PROPERTY AND NOT FROM THE TWO INSTANCES.** The pair this item is
     about is `HKDF-Expand(record_key_head[i], "rec/v1/head", 56)`, where `record_key_head[i]` is
     the `i`-th rung of a chain rooted at `HKDF-Expand(K_durable[n], "sender/v1" ‖ LP(leaf_index),
     32)`. Those are **all** of its inputs — the shipped `RecordAeadHead(recordKey []byte)`
     (`connect/messagegroup/keyschedule.go:271`) takes one argument and nothing else is in scope —
     so the pair is a function of exactly `(K_durable[n], leaf_index, i)`. Every closure of the
     property is therefore one or more of exactly four moves, and there is no fifth:

     **(A)** make `i` unique across the streams that share the root — a **position** rule;
     **(B)** make the **root** differ per stream;
     **(C)** make the AEAD material depend on more than the rung — a **derivation** rule, of which
     carrying the nonce on the wire is the degenerate case;
     **(D)** replace `K_durable[n]` with the record's own class key, which is item **152**'s repair
     and a reversal of M1-6 for the head.

     The seven shapes below are those four moves spelled out. Anything that is none of them does
     not close the property, and the two such non-closures a reader reaches for are named at the
     end.

     **FOUR CORRECTIONS TO THIS ITEM, each with the query that produced it.**

     *(1) "shared by all four retention classes" is wrong in both directions.* `EPH` is
     **excluded** from the M1-6 ruling — Spec A §5.3:1271, *"So `EPH` is excluded from this rule"*,
     and item **128** at SPEC-LEDGER.md:1609, *"It does not reach `EPH`"* — so the shared head
     ladder covers **three** Go-side classes today, not four. And the unit that shares it is not
     the Go-side class at all: the reserver and the session's sender table are keyed on the **wire
     byte** (`StreamKey.RetentionWire`; `senders map[byte]*SenderRatchet`,
     `connect/messagegroup/session.go:119`), of which **nine** are legal — `0x00`, `0x01`, `0x02`
     and `0x10..0x15` (Spec A §5.1's table; `message.RetentionClassWire`, `record.go:260`). So the
     sharing is over **three** streams today and over **nine** the day item **152** rules `EPH`
     heads onto this root. That is not pedantry: it is the multiplier every cost below is
     denominated in, and two of the shapes take a second wire break when it moves from 3 to 9.

     *(2) "No such counter exists in either document or in the shipped code" is refuted four
     times.* Query: `grep -n 'single .u64. counter per' docs/specs/*.md` returns **three** hits —
     MASTER §8:914, Spec A §5.6:1394, Spec B:2463 — each reading *"`stream_index` is a single
     `u64` counter per `(group_id, sender_handle)`, write-once, assigned locally."* That **is** a
     head-ladder counter monotone across all classes of one sender, stated in three documents, and
     it is what the shipped **server** enforces (correction 4). What does not exist is an
     *interface* that expresses it: §5.6's own Go block and §8.2's `MessageStore` declare the
     reservation over `groupId` **alone**, and `messagegroup.StreamKey` went the other way, to
     `(group, sender, class)`. That is item **168**, and it is a different sentence from this one.
     The counter is not missing; three parameter lists are wrong in three different ways.

     *(3) shape (b)'s "a fifteenth method on the `MessageStore`" is not what a shared counter
     costs.* §8.2's `ReserveStreamIndex(groupId []byte, index uint64)` and
     `StreamHighWater(groupId []byte)` must change signature under item **168** whatever is ruled,
     because the shipped reserver already takes a three-field key; a class-blind head counter is a
     **key value**, not a call. Fourteen methods stay fourteen. What it does cost `s2` and **M1-5**
     is a row keyed differently, which is real and is priced below — and it is one row per sender
     rather than up to nine, which is less to key, not more.

     *(4) the stated harm over-reaches, and the measurement that shows it is the one that moves
     this item.* **The server's stream-monotonicity check is class-blind.** Spec B's submit path,
     check (3) at :2221 — *"Stream monotonicity, per `(group_id, sender_handle)`"*,
     `record.stream_index <= last -> REASON_STREAM_INDEX_REGRESSED` — over `message_sender`, whose
     `PRIMARY KEY (group_id, sender_handle)` at :882 carries **no class column**; and the shipped
     server does it that way, `msgrepo/store/memory.go:603-609`, keyed
     `group.senders[string(record.SenderHandle)]`. So a conforming server **refuses** the second of
     the two colliding records before storing it, and never holds both ciphertexts. The property is
     still broken — the client has already sealed twice under one `(key_head, nonce_head)`, and any
     path that sees both halves recovers the Poly1305 one-time key: a retry against a second
     server, the outbox republish A-17 prices, a compromised or hostile operator, a client that
     keeps what it could not send. But *"hand the message server the Poly1305 one-time key … for
     every sender"* describes a server that would have refused the input.

     **AND THE SAME MEASUREMENT PRODUCES A LARGER CONSEQUENCE NEITHER ITEM NAMES.** If the server
     counts per `(group, sender)` and the client counts per `(group, sender, class)`, then the
     first `PERMANENT` record a sender emits after any durable traffic carries a `stream_index` at
     or below the server's high water and is refused `REASON_STREAM_INDEX_REGRESSED` — and the
     shipped `SenderRatchet` owns its position and goes on offering indices below that high water
     for as long as the durable stream is ahead. **That is item 168's permanent wedge again, one
     layer out, on the honest path, landing on m1 Task 14's and Task 15's first record.** It is a
     functional break of wave 2 rather than a cryptographic one, it is decided by 168's keying
     rather than by this item's derivation, and it means **every shape that keeps per-class
     counters also owes a Spec B change**: `message_sender` gains a class column and a wider
     primary key, Q7 (:1047) gains it too, and the `EPH(0)` exemption at :2765 has to be restated
     over the wider key. Only the class-blind shapes leave the server alone.

     **THE MEASUREMENTS EVERY COST BELOW IS QUOTED IN**, taken on this machine against `connect`
     `7a9ad2a` and `msgrepo` `9e5b54d`:

     - **one ladder rung = 368.7 ns** (2^20 `HKDF-Expand(SHA-256, prk, "ratchet/v1", 32)` in
       386.6 ms), which reproduces `ratchet.go:93`'s *"roughly four hundred nanoseconds per rung"*;
     - **`maxLadderWalk = 1 << 20`** (`ratchet.go:109`), so the worst-case resume walk is **387 ms**
       and a stream past that bound cannot be resumed at all — `ErrLadderWalkTooLong`,
       `ratchet.go:184`;
     - **the receiver window is 1024** (`mls.RatchetWindowSize`, `mls/secret_tree.go:856`) and is
       refused **by index distance**, not by retained count: `classifyLocked` fails when
       `windowSize < index - head` (`ratchet.go:476`);
     - **a size-bucket-2 record encodes to 4,364 octets** with a 96-octet `ct_head`: `ct_body` is
       **4,112**, the framing outside the two ciphertexts is **156**, and every length prefix is a
       fixed 4 octets (`syntax.WriteOpaqueLP` → `WriteUint32`, `mls/syntax/encode.go:168`). So a
       new `u64` header field is **+8 octets, 4,364 → 4,372, +0.18%**, and `ct_body` — the column
       Spec B `CHECK`s at 4,112 — **does not move under any shape below**;
     - **`AAD_head` is 182 octets** and `AAD_body` is 96, for a record with no server attachment and
       no blob id;
     - **one 56-octet `HKDF-Expand` = 600 ns**; **one SHA-256 over the 182-octet `AAD_head` = 91 ns**;
     - **the KAT bill is eleven constants or two.** `connect/messagegroup/recordkey_test.go` pins
       eleven values downstream of `record_key[0]`'s info string — `record_key[0]` at leaves 0, 3, 7
       and `0xFFFFFFFF`, `record_key[1]`, `record_key[2]`, `key_head`, `nonce_head`, `key_body`,
       `nonce_body`, and M1-8's minimal-LP alternative. A change to `recordKeyZeroInfo` invalidates
       **all eleven**; a change to `recordAeadHeadInfo` alone invalidates **two**. The five in
       `keyschedule_test.go` and the handle and X-Wing vectors are untouched by either.

     **ONE MEASUREMENT THAT PRICES HALF THE SHAPES AT ONCE, AND IT IS IN NEITHER ITEM.** A
     forward-only chain cannot serve two independent counters. Under per-class counters the head
     positions a sender needs from the **one** durable chain are its classes' own indices, in no
     order — 5, then 3, then 9, then 4 — so the sender must hold **one live copy of that chain per
     class**, each parked at its own class's position, and the chain's oldest surviving copy is as
     old as the **least-used** class. The shipped ratchet does the opposite: `Next()` erases as it
     advances (`ratchet.go:251`). So every shape that keeps per-class counters **and** shares one
     head chain buys its uniqueness with a **forward-secrecy regression on the head that no
     document states**, and holds `k` × 32 octets of live key material for it. The shapes that
     allocate positions monotonically (A1), give each class its own chain (B1), or use no chain at
     all (B2) do not pay it.

     **AND A MEASUREMENT ABOUT WHAT THE HEAD CHAIN BUYS TODAY, offered as a fact and not as an
     argument for any shape.** `GroupSession` holds `storageRoot` and `classKeys` for the whole
     epoch (`session.go:107-108`), erased only in `installEpochOnLoop` and `zeroizeOnLoop`. Every
     rung of every ladder of that epoch is recomputable from `classKeys.Durable`. So the head
     chain's forward erasure protects nothing against an adversary holding a live session; what
     separates epochs is the class keys, which already do. The chain buys forward secrecy against
     an adversary who takes ratchet state **without** the root, and no document in this corpus
     distinguishes that case. Query:
     `grep -n 'storageRoot\|classKeys' connect/messagegroup/session.go`.

     **THE SEVEN SHAPES.** Each states what changes on the wire, what it costs in octets against the
     4,112-octet bucket, the discipline it still needs that no document states, what it does to the
     reserver, whether it survives M1-11's device removed and re-added at a different leaf, what a
     later reversal of M1-6 does to it, and — the column neither item has — **whether it also closes
     item 143's own device-wrap instantiation**, where the collision is on `(key_body, nonce_body)`
     as well as on the head.

     **A1 — ONE CLASS-BLIND `stream_index` PER `(group_id, sender_handle)`.** The brief's *"one head
     counter per sender across all classes"*, and the counter three documents' prose and the
     server's schema already declare. `i = stream_index` in every ladder — item 143's pin — and the
     per-class body ladders draw sparse positions from the one counter.
     *Wire:* nothing changes, and **nothing already sealed breaks**: a sender that has only ever
     used one class has a class-blind counter identical to its per-class one, which is every record
     wave 1 has sealed. *Octets:* **0** of 4,364; `ct_body` stays 4,112.
     *Unwritten discipline, and there are two.* **(i)** The ladders must take their positions
     **from** the shared counter. The shipped `SenderRatchet` keeps its own `position` field and
     wedges permanently the moment a second ladder meets a consumed index (`ratchet.go:242`; item
     168's measured wedge), so `Reserve(index)` must become an allocation — *"give me the next"* —
     or the session must own the counter and pass the index in. The shipped contract's clause 5,
     *"Reserve is not idempotent"*, is written for the assert shape and would have to be restated.
     **(ii)** `EPH(bucket 0)` transients consume an index (§5.6), so every typing indicator advances
     the one counter; with the receiver window refused by **distance**, 1,025 transients between two
     `DURABLE` records make the second permanently `out_of_window`. Nothing states that transients
     get their own counter — `streamindex.go`'s comment says only that nothing forecloses one, open
     item **M1-25** — and giving them one re-opens this very collision for `EPH` heads the day 152
     rules them onto this root.
     *Reserver:* `StreamKey` loses `RetentionWire` and keeps `SenderHandle` — **not** the
     `groupId`-only form item 168 measured, which is the wedge. §8.2's two methods gain the sender
     handle, which they owe anyway. One durable row per sender instead of up to nine.
     *M1-11:* **safe.** A new leaf gives a new `sender_handle`, therefore a fresh counter at zero,
     and a new root, because `LP(leaf_index)` is in it. Under §5.6's `groupId`-only form it is also
     safe and merely burns indices.
     *M1-6 reversed:* **neutral, and it is the only shape that is neutral for free.** A class-blind
     counter with per-class roots is the right position rule under either reading of the head.
     *Closes 143's wrap instance:* **yes.** Ruling 2's wrap root has no class in it and ruling 3 puts
     two classes on it; a class-blind counter gives the two wrap records different positions, so
     both AEADs separate.
     *Measured cost:* the ladders go sparse, so the epoch-change rebuild — `installEpochOnLoop` drops
     every sender ratchet (`session.go:469`) and each is rebuilt by walking from `record_key[0]` —
     costs `(k+1) × P` rungs where it costs `P` today. At `P = 100,000` and `k = 3` that is **148 ms
     per commit** at the measured 368.7 ns; at the `1 << 20` bound it is **1.55 s** and then refuses.
     And a class's usable out-of-order window falls from 1024 of its own records to 1024 **shared
     positions**, roughly `1024/k` of its own.

     **A2 — A HEAD POSITION INDEPENDENT OF `stream_index`, BY AN INJECTIVE MAP.** The brief's third
     shape: `i_head = w · stream_index + ordinal(class)`, `w` = the number of streams sharing the
     root, uniqueness carried by the written map rather than by the counter.
     *Wire:* nothing. But **every head ciphertext changes, `DURABLE` included**, and that is forced
     rather than chosen: no injective map can keep `f(DURABLE, s) = s`, because the durable stream
     already uses every integer and leaves the other classes nowhere to go. M1-6's *"for a `DURABLE`
     record nothing observable changes"* does not survive this shape. *Octets:* **0**.
     *Unwritten discipline:* the map and `w` must be normative and identical on both sides, and `w`
     must be **fixed for the life of the format** — if 152 later rules `EPH` heads onto this root,
     `w` goes 3 → 9, every head position moves, and that is a **second** wire break. Fixing `w = 9`
     today prices a ruling that has not been made.
     *Reserver:* **unchanged — the only shape that needs nothing of it.** The per-class counters that
     shipped stay exactly as they are, so it also owes the Spec B change correction 4 names.
     *M1-11:* safe, by A1's argument.
     *M1-6 reversed:* the interleave becomes dead weight and head positions stay `w`× sparse for
     ever, or a second break removes it.
     *Closes 143's wrap instance:* **yes**, if the map is applied to the wrap ladder too — but the
     wrap's classes are `PERMANENT` and `EPH(5)`, so `w` there is a different number from the
     ordinary path's, and the two `w`s are a second thing to write down.
     *Measured cost:* positions are `w`× larger, so `maxLadderWalk`'s `1 << 20` ceiling arrives after
     **349,525** records at `w = 3` and **116,508** at `w = 9`, after which the stream cannot be
     resumed at all. And the interleaved positions are **not monotone** across classes — a sender's
     two counters advance independently — so this shape pays the `k`-live-copies forward-secrecy
     cost in full. It closes the property and is worse than A1 on every axis except the reserver.

     **B1 — THE RETENTION CLASS IN THE LADDER ROOT, IN EVERY LADDER.** This item's shape (a),
     corrected: `record_key[0] = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index) ‖
     u8(retention_wire), 32)`, applied to the **head and the body**. Applied to the head alone it
     splits a `DURABLE` record into two ladders and loses M1-6's own coincidence, which is the
     sentence the ruling's accepted cost rests on.
     *Wire:* **0 octets, and every ciphertext in the system changes** — heads and bodies, every
     class — because every `record_key[0]` moves. Today that is test material only: no record
     outside a test exists in either tree. *Octets:* **0** of 4,364.
     *Unwritten discipline, and one half of it is a live open item.* The byte must be the **wire**
     byte through `RetentionClassWire`; a root built from the Go-side tag gives `EPH(1)` and `EPH(5)`
     one root, which is this collision again inside one class. And appending `u8(class)` **after**
     `LP(leaf_index)` makes the root's info string depend on **M1-8**, which is open: what `LP` of an
     integer means is unruled, and `recordkey_test.go` pins **both** readings
     (`recordKeyZeroMinimalLpKatHex`). A shape whose preimage is ambiguous between two
     implementations is not a closure.
     *Reserver:* **unchanged**, and `i = stream_index` holds in every ladder, so item 143's pin taken
     literally becomes correct. The per-class counters stay, so this shape owes the Spec B change.
     *M1-11:* safe.
     *M1-6 reversed:* the class byte becomes redundant — the class key already separates the roots —
     and stays vestigial, or a second break removes it.
     *Closes 143's wrap instance:* **yes**, and it is the only derivation-side shape that does,
     because the wrap's collision is on both AEADs and this is the only one that moves the root they
     share.
     *Measured cost:* **eleven pinned constants** to recompute in `recordkey_test.go`, plus every
     head and body fixture. No walk, window, reserver or wire cost at all.

     **B2 — NO HEAD LADDER: DERIVE THE HEAD MATERIAL STRAIGHT FROM `K_durable[n]`.**
     `key_head ‖ nonce_head = HKDF-Expand(K_durable[n], "rec/v1/head" ‖ LP(leaf_index) ‖
     u8(retention_wire) ‖ u64(stream_index), 56)`. The head stops being a position and becomes a
     function of the record's own identity, so uniqueness follows from the **per-class write-once
     reservation that already shipped**: no shared counter, no interleave, no second chain.
     *Wire:* **0 octets**; every head ciphertext changes. *Octets:* **0** of 4,364.
     *Unwritten discipline:* the same M1-8 ambiguity as B1, and a rule that the `stream_index` in the
     info is the record's own and the one in `AAD_head` — nothing states it.
     *Reserver:* **unchanged**; owes the Spec B change for the same reason B1 does.
     *M1-11:* safe.
     *M1-6 reversed:* **survives verbatim** — replace `K_durable[n]` with the record's own class key
     and the construction is unchanged. It is the cleanest shape under a future reversal.
     *Closes 143's wrap instance:* **no.** The wrap's body collision is untouched.
     *Measured cost:* it **removes** cost. The head derivation goes from a walk plus a 600 ns expand
     to a **600 ns expand**; the head loses its 1024-key window and its `ErrLadderWalkTooLong`
     refusal, because a head key is O(1) from the cleartext header. What it gives up is the head's
     forward secrecy inside an epoch, which the `storageRoot` measurement above says the design does
     not currently have.

     **C1 — THE CLASS IN THE HEAD'S AEAD EXPAND.** `key_head ‖ nonce_head =
     HKDF-Expand(record_key[i], "rec/v1/head" ‖ u8(retention_wire), 56)`. The ladder is untouched;
     the class binds one rung later.
     *Wire:* **0 octets**; every head ciphertext changes, `DURABLE` included — and exempting
     `DURABLE` to keep it from changing is exactly the special case that becomes the next unwritten
     rule. *Octets:* **0**.
     *Unwritten discipline:* the `k`-live-copies-of-one-chain cost measured above, in full, with the
     forward-secrecy regression it carries.
     *Reserver:* unchanged; owes the Spec B change. *M1-11:* safe. *M1-6 reversed:* vestigial.
     *Closes 143's wrap instance:* **no** — the wrap collides on the body too and this touches only
     the head. *Measured cost:* **two pinned constants**, and `k` × 32 octets of live head-chain
     copies per sender.

     **C2 — BIND THE WHOLE AUTHENTICATED HEADER INTO THE HEAD'S MATERIAL.**
     `key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head" ‖ H(AAD_head), 56)`. It is
     acyclic: §5.2's construction order fixes `AAD_head` before the head seal.
     *Wire:* **0 octets**; every head ciphertext changes. *Octets:* **0**. *Measured:* **+91 ns** per
     seal and per open, one SHA-256 over the 182-octet preimage.
     *What it closes that the others do not:* two records collide only if their entire `AAD_head`
     agrees, so it closes the class collision **and** A-17's republished-wrap-head case in one clause.
     *Unwritten discipline:* C1's `k`-copies cost, **and** a rule nothing in the corpus has —
     `AAD_head` carries `LP(H(server_attachment))`, a value the **server** supplies (§5.11), so this
     shape lets a value outside the sender's control enter a key derivation.
     *Reserver:* unchanged; owes the Spec B change. *M1-11:* safe. *M1-6 reversed:* neutral.
     *Closes 143's wrap instance:* **no**, for C1's reason.

     **C3 — CARRY `nonce_head` ON THE WIRE.** A 24-octet header field, fresh CSPRNG per record, in
     `AAD_head` and in the `write_auth` preimage; `key_head = HKDF-Expand(record_key[i],
     "rec/v1/head", 32)`. XChaCha20's 192-bit nonce is built for exactly this.
     *Wire:* **+24 octets in the header** — the only shape here that costs any — plus a codec field,
     a parser rule and a `ParseRecord` refusal, and it is a format break for every record.
     *Octets:* **4,364 → 4,388, +0.55%**; `AAD_head` 182 → 206; `ct_body` **unchanged at 4,112**, so
     Spec B's `CHECK (octet_length(ct_body) = …)` does not move. Applying it to the body as well —
     which is what closing 143's wrap instance this way would take — is **+48, 4,364 → 4,412, +1.1%**.
     *Unwritten discipline, and this is the class this project has the worst record against:* it
     turns a reservation property into an **entropy** property. p5 shipped two entropy substitutions
     in one task that no correctness test could see. The rules it needs and no document has: drawn
     from the CSPRNG per record, never from a counter, never seeded per process, and tested by *"are
     two independent draws different, and does the value depend on the source"* rather than by a
     round trip. It also opens 24 authenticated but otherwise unconstrained octets per record as a
     covert channel out of the client.
     *Reserver:* unchanged — and the head **stops depending on it at all**, which is a loss as much
     as a gain: §5.9's G5 defence, *"§5.6 durable reservation + `TestStreamIndexNeverReused`"*, would
     no longer cover the head. Owes the Spec B change.
     *M1-11:* safe, trivially — the nonce does not depend on the leaf.
     *M1-6 reversed:* unaffected. *Closes 143's wrap instance:* **not as stated**; only with the body
     field too, at +48 octets.

     **D — KEY `ct_head` UNDER THE RECORD'S OWN CLASS KEY.** This item's shape (c), item **152**'s
     repair, and a reversal of M1-6 for the head. It **dissolves this item**: one ladder per class,
     `i = stream_index` holds everywhere, nothing changes on the wire, no reserver moves, no document
     gains a rule. It is listed because it is the null option, because it is what the owner ruled
     **against** for `PERMANENT`, `DURABLE` and `MEDIA` on 2026-09-07, and because item 152 is
     **still unruled for `EPH`** — so the corpus already contains one class whose head is not under
     `K_durable`, and any shape chosen here has to say what happens to that class.
     *Closes 143's wrap instance:* **no** — the wrap root has no class key in it at all.

     **TWO SHAPES THAT LOOK LIKE CLOSURES AND ARE NOT.** Both are what a reader reaches for, and
     neither is in the class derived above.

     **"Bind `stream_index` into the head derivation."** Under item 143's pin `i = stream_index`, so
     `u64(stream_index)` is a function of `i` and adds **nothing**: the two colliding records carry
     the same `stream_index`, take the same `i`, and would take the same key. This is the
     derive-from-the-instance failure in its purest form on this item — the value that **names** the
     defect is not the value that **separates** the records.

     **"Let the server refuse the second record."** It does (correction 4), which is why the stated
     harm over-reaches — but the **seal has already happened** when the refusal arrives. Two
     ciphertexts under one `(key_head, nonce_head)` exist on the client at that moment, and the
     refusal is `REASON_STREAM_INDEX_REGRESSED` on the honest path and nothing at all on any other.
     A server-side check is not a closure of a client-side key-reuse property; it is a report that
     the property was already broken.

     **A RECOMMENDATION, LABELLED AS ONE AND NOT A RULING. A1.** It is the only shape that is already
     what the rest of the system assumes — three documents' prose, `message_sender`'s primary key,
     Spec B's check (3) and the shipped server all count per `(group, sender)` — so it is the only
     one that does not also owe a Spec B schema change; it is one of the two that also close item
     **143**'s device-wrap instantiation, where the collision is on both AEADs; it costs **zero**
     wire octets, **zero** KAT constants and **zero** retained chain copies; and it is neutral to a
     later reversal of M1-6, which no other shape is for free. Its costs are real and are the
     `(k+1)`× walk multiplier at every commit, a receiver window measured in shared positions rather
     than in a class's own records, and **M1-25**'s transient counter becoming load-bearing rather
     than deferred. If the owner wants those costs off the head specifically, **A1 with B2** removes
     the head's walk and window entirely and gives up a forward secrecy the `storageRoot` measurement
     says the design does not currently have. **Neither is ruled here.**

     **WHAT THIS AMENDMENT DID NOT DO.** It did not rule this item, item **143**, item **152** or
     **M1-1**. It did not implement wave 2 and changed no Go file in either tree. It did not amend
     Spec A, Spec B or MASTER: correction 4 says three documents and the shipped server disagree
     with the shipped client about how `stream_index` is keyed, and which of them moves is the
     ruling, not this pass's to take. Found 2026-09-07, laying out the options this item filed as
     three. *(**All of it is superseded the same day by the ruling at the head of this item.** A1 was
     taken; correction 4's question is answered — **the client moved**; Spec A is amended and Spec B
     and MASTER are not; wave 2 is still not implemented and item **152** and **M1-1** are still
     unruled. This paragraph is kept because it is the boundary the ruling crossed.)*

170. **A1 CHANGES THE DURABLE STORE ROW'S IDENTITY, AND THE RULING'S OWN WORDING SAYS IT CHANGES
     NOTHING. TRUE OF RECORDS, FALSE OF ROWS. FILED, NOT RULED — and it is a TRANSITION hazard, not a
     live break in either tree.**

     **The claim.** Item **169**'s ruling, and `connect/messagegroup/streamindex.go`'s header carrying
     it, both say A1 *"breaks nothing already sealed"*. That is true of every **record**: a sender that
     has only ever used one retention class has a class-blind counter identical to its per-class one,
     which is every record wave 1 sealed. It is **false of the durable store ROW**. `StreamKey` is what
     a reserver keys a row on, and A1 removes a field from it, so a store that already holds wave-1
     rows answers `HighWater` **0** for an A1 key — contract clause 4 makes "never seen" a silent,
     error-free zero — the ladder resumes at position 1, and `Next` hands out `record_key[1]` under a
     class key that has not moved. That is a repeated `(key_head, nonce_head)` **and** a repeated
     `(key_body, nonce_body)`: the total break of both AEADs that the whole of item 143 exists to
     prevent, arriving through the repair rather than through the defect.

     **Reproduced executably, not argued.** The package's own test fake derives its row string by
     **reflecting over `StreamKey`'s fields** (`streamIndexRowKey`, `streamindex_test.go:231`), so the
     row identity **is** the field set, by construction and on purpose. Plant a wave-1 row at
     `streamIndexRowKey(stream) + "/0x1"` with high water 500, then read with the A1 key: `HighWater`
     answers 0, `NewSenderRatchet` resumes at position 1, `Next()` returns index 1, and the rung it
     hands out compares byte-for-byte equal to `RecordKeyNext(RecordKeyZero(classKey, leaf))` —
     `record_key[1]`, the rung record 1 was already sealed under.

     **The mitigation, stated because it is what sets the severity.**
     `grep -rn "StreamIndexReserver|ReserveStreamIndex" --include=*.go` over `connect/` and `sdk/`
     finds the interface, the ratchet, the session and the test fakes **only**. No durable
     implementation exists anywhere — `sdk` contains no messaging code at all. So no store holds a
     wave-1 row today and none can, and this is a hazard for `sdk`'s **unwritten** store plan rather
     than a defect in either tree.

     **Why it is filed here and not left to M1-5.** `streamindex.go` defers row identity to **M1-5**,
     and M1-5 is written about `sender_handle` and about a device removed and re-added at a different
     leaf — it is not about the field A1 just dropped. Nothing in either tree names this re-key. The
     ruling that closes this item is one sentence in `s2`'s store plan — *rows written under a
     `StreamKey` carrying a retention byte are migrated by taking the maximum over the classes of one
     `(group_id, sender_handle)`, or the whole key space is versioned and refused* — and it costs
     nothing while nothing is on disk. *Blocks:* nothing today; it blocks the first durable
     `StreamIndexReserver`, and **must be ruled in the same sitting as M1-5** or the store row and the
     reservation are keyed by different things a second time. Found 2026-09-07 in the review of the A1
     implementation; reproduced by this pass before it was written down.

171. **THE RECOVERY THAT BOTH WEDGE COMMENTS NAME IS IMPOSSIBLE FOR THE WEDGE A1 ADDED AND UNSAFE FOR
     ONE OF THE OTHER TWO. FILED, NOT RULED.**

     `connect/messagegroup/ratchet.go:170-171` and `errors.go`'s `ErrSenderRatchetWedged` both say: *"A
     caller that wants to go on rebuilds the ratchet from the store's own high water, which is the one
     thing that puts a ladder back under its counter."* Three causes wedge a ladder under A1 — the
     store refused to allocate, the store handed back an index at or below where the ladder stands, or
     it handed back one so far ahead that walking to it exceeds `maxLadderWalk`. The advice is wrong
     for two of the three:

     - **`ErrLadderWalkTooLong`** is the cause A1 introduced, and `NewSenderRatchet` **refuses any
       resume above `maxLadderWalk`** (`ratchet.go:218`), so the rebuild fails the same way the
       allocation did. And not for one quiet ladder: **every class of that sender is refused**,
       because the counter they share is what crossed the bound. Reproduced: with the store's high
       water parked at `maxLadderWalk`, `NewSenderRatchet` answers *"resuming at 1048577 would walk
       1048577 rungs and the bound is 1048576"* for the durable class key and for **every field of
       `ClassKeys`**, derived rather than listed.
     - **`ErrStreamIndexRewound`** makes the advice actively unsafe: rebuilding from a rewound high
       water resumes **below** indices already handed out and re-issues them, which is precisely the
       reuse the sentinel exists to report.

     **And the wall arrives `k` times sooner under A1 than under per-class counting**, with transients
     counting toward it, so **M1-25** composes with this rather than sitting beside it. *Blocks:*
     nothing in wave 1 — no caller in either tree recovers from a wedge today. What is owed is a
     recovery **procedure** per cause, or the comment saying there is none: refusal is retryable and
     the other two are not. The item exists because a comment naming a recovery a reader cannot walk is
     worse than one naming none. Found 2026-09-07 in the review of the A1 implementation.

172. **A1's RECEIVE-SIDE COST IS LARGER THAN THE SEND-SIDE COST THE RULING WAS TAKEN ON, AND IT WAS
     NOT IN FRONT OF THE OWNER. FILED, NOT RULED. IT DOES NOT REVERSE THE RULING.**

     `installEpochOnLoop` drops the **receiver** table as well as the sender ratchets —
     `self.receivers.Zeroize()` deletes every entry (`session.go:455`, `ratchet.go:931`) — so at every
     commit each tracked `(sender, class)` pair is rebuilt by `NewReceiverRatchet` walking from
     `record_key[0]` to its head. Under A1 that head is the class-blind stream index, **`k` times
     further out**. The walk is the same `stepRecordKey` loop the sender-side benchmark measures, so
     the numbers transfer exactly: at k=3 and P=100,000 the rebuild is **≈130 ms per PEER per epoch
     change** against ≈42 ms for a per-class head, i.e. **≈1.04 s for eight peers** against ≈334 ms.
     The implementer's cost report and item 169's options paper both name only the sender-side figure.

     **And nothing bounds the number of pairs.** `ReceiverRatchets.Track` caps no entry count; what the
     table bounds is **retained rungs**, tree-wide, which is `M1-12`'s recommendation adopted on
     purpose and is about memory. So A1 turns the tracked-pair count into a **CPU** bound at every
     epoch change that no document states and no constant limits, and §5.5's own *"capped at 64 senders
     tracked per group"* — which the shipped table deliberately does not implement, per M1-12 — is not
     the cap that would bound it either. *Blocks:* nothing; it is a cost to state, and the candidates
     are a rebuild that is lazy per sender rather than eager per table, a cap on tracked pairs, or the
     number written down and accepted. **M1-12 gains this**: its arithmetic is about memory and this is
     the CPU half of the same table. Found 2026-09-07 in the review of the A1 implementation; the
     figures above are this pass's own reproduction of the sender-side benchmark applied to the
     identical receiver walk, not a second measurement.

173. **TWO PIECES OF A1's EVIDENCE DO NOT OBSERVE THE PROPERTY THEY NAME. FILED. NEITHER WEAKENS THE
     RULING; BOTH WEAKEN WHAT WOULD CATCH ITS REVERSAL.**

     **(1) The starvation case does not fail on the mutation offered as its evidence.** The
     implementation reports of `TestTransientsOnTheSharedCounterStarveADurableReceiverWindow`: *"A
     mutation giving transients their own counter makes that case fail, which is how I know it observes
     the shared counter and not arithmetic."* It cannot. The case builds its `StreamKey` with
     `streamKeyNamed` and calls `reserver.Reserve(stream)` directly, so it never crosses the
     class-to-`StreamKey` mapping that decides whether transients share a counter. Reproduced: restore
     `RetentionWire byte` to `StreamKey` and set it in `senderRatchetOnLoop`, and the case **passes**;
     the suite goes red on a different case (`TestEveryRetentionClassOfOneSessionReservesInOneStream`).
     Control: the starvation case **does** fail under a mutation that stops `Next` taking the store's
     index, so it is not inert — it observes the ladder-to-store binding, not the transient-to-counter
     binding. **M1-25's hazard is still genuinely demonstrated**; what is wrong is the attribution, and
     the consequence is that on the day M1-25 is ruled the other way the case goes on passing while
     reporting a starvation that no longer exists.

     **(2) The rule-11 sweep fixed two enumerations and left a third, in the same commit and the same
     file about a hundred lines away.** `BenchmarkEpochChangeRebuild` still writes
     `ladderKeys := [][]byte{classKeys.Durable, classKeys.Perm, classKeys.Media}` — a hand-written
     class list — with `highWater: 100000/3 - 1` and sub-benchmark names that say `k=3`. This is the
     benchmark that produced the costs item **169** was accepted on, and item **152**'s fourth class
     key would make it silently measure the wrong `k` while still reporting itself as k=3. The
     neighbouring case was rewritten in the same commit to derive `k` off
     `reflect.ValueOf(*classKeys).NumField()` for exactly this reason. **Rule 5's second half applied
     one altitude down**: a measurement that derives its class and then enumerates its scope is not a
     derived measurement.

     *Blocks:* nothing. Both are in `connect`'s test suite and neither is this repository's to fix.
     Found 2026-09-07 in the review of the A1 implementation.

174. **THE FILE THAT CARRIES THE A1 RULING STILL ASSERTS TWO THINGS A1 MADE FALSE. FILED. THE
     DOCUMENT HALF OF THE FIRST IS CLOSED BY THIS PASS; THE CODE HALF IS NOT.**

     **(1) The §8.2 correspondence, stated in the shape A1 replaced.**
     `connect/messagegroup/streamindex.go:30-33` says section 8.2's `MessageStore` *"declares
     `ReserveStreamIndex(groupId []byte, index uint64) error` and `StreamHighWater(groupId []byte)
     (uint64, error)` — this interface's subject, on the fourteen method interface the sqlite
     implementation already owes."* Under A1 this package's method is
     `Reserve(stream StreamKey) (uint64, error)` — an **allocation with no index in** — and the
     assert-shape signature cannot implement it. The file names the **keying** disagreement (M1-5) at
     length and never names the **shape** disagreement A1 created, which is the same stale-claim class
     the implementer did repair one file over. **This pass amends §8.2 and §5.6 to the allocation
     shape** (revision A-21) and amends the plan's copies of the correspondence, so the documents are
     now right and the code comment is the half that is stale — the inverse of where it started, and
     recorded that way on purpose.

     **(2) The cost formula, refuted by the benchmark in the same package.** The same header prices
     the epoch-change rebuild at *"(k+1) x P expansions where it cost P"*. `BenchmarkEpochChangeRebuild`
     measures the ratio at **3.11** against k=3, and the benchmark's own comment says so in as many
     words — *"AND THE MULTIPLIER IS k, NOT k+1"* — so the file states the wrong formula above a
     benchmark that refutes it. Item **169** carries the corrected number and the reproduction.

     *Blocks:* nothing. Both are comments in `connect`; the item exists because the ruling's own
     carrier is where a later reader will look first, and because the second one is the exact number a
     future cost argument will be built on. Found 2026-09-07 in the review of the A1 implementation.

175. **RULED 2026-09-09 BY THE OWNER — COMPOSITE `C3`, §4's fourth row. THE THREE `M1-1` OPTION SETS,
     COMPOSED. The item is kept whole below because the owner ruled on the shapes recorded in it, and
     because §2's finding (1) — the one the composition found rather than inherited — is the reasoning
     the ruling was taken on.**

     **THE RULING. Four terms, and the third and fourth are repairs no option set contained.**
     `W1`'s four-field envelope — `u8(wrap_format_version = 0x01) ‖ u8(target_type) ‖
     u8(payload_type) ‖ u64(content_epoch)`, **11 octets** — sits **outside** `hybrid_ct`, and
     `W5`'s `u32(publisher_leaf_index)` is **dropped**. **`LP(identity_pub)` sits beside the signature
     inside `aead_ct`.** **`S1`'s signature preimage is extended by `LP(wrap_envelope)`**, ahead of
     `LP(ct_xwing)`. And **`P2`'s `LP32` prefix and accumulating, position-free tail refusal apply to
     all three wrap bodies, the recovery wrap included** — so `M1-7` is ruled in the same sitting, as
     item **180** said it had to be.

     **Measured, and every figure is §4's C3 row and item 179's:** device occupancy **1,293** of the
     4,096 rung, tail **2,803**; recovery `ct_body` **1,357** of 4,112, tail **2,755**; `ct_body`
     stays **4,112**; records **4,398** and **4,428**; fan-out 11.01 MB. **Zero octets on the wire.**

     **ONE FIGURE IN THE RULING AS TRANSMITTED DOES NOT REPRODUCE AGAINST THIS ITEM, AND IT IS NOT
     WRITTEN INTO ANY DOCUMENT.** The ruling carried the preimage as *"1,305 → **1,324**"*. §2 (1)
     and item **176** both measure that repair as *"**1,324** with set 1's five fields, or **1,320**
     with W1's four"*, and `C3` takes `W1`'s four — an 11-octet envelope, `LP(wrap_envelope)` = 15,
     preimage **1,320**. **1,324 is the number for the composite the owner did not take.** What the
     documents record is 1,320, with the term that is genuinely undetermined stated beside it:
     `LP(payload)` was measured over a 32-octet secret, and set 2's own `S1` line prices
     `LP(identity_pub)` as *"a further 36 **in the payload**"* — so the preimage is **1,320** if the
     identity key is outside that term and **1,356** if it is inside, and **no document says which**.
     Neither was measured by this pass and neither is asserted as *the* number. A builder needs the
     answer before it signs anything.

     **WHY THE REPAIR TERM IS THE POINT OF THE RULING.** Three analysts worked independently and each
     recommended a piece; composed as they arrived (`C1`), the result **signs the record header, the
     KEM transcript and the secret, and leaves all fifteen envelope octets — the fields the field-list
     ruling exists to add — signed by nobody.** **It survived three independent analyses because a
     sealer and an opener agree about a field neither is asked to defend, so no round-trip test can
     see it.** `LP(wrap_envelope)` closes it at zero body octets and zero wire octets.

     **THE SECOND REPAIR** collapses the two body grammars into one, so a parser can decide whether
     the body's first four octets are a length or `version ‖ target_type ‖ payload_type` **without
     first reading the server attachment's kind** — the target-type-dependent body encoding §2 (4)
     names as the kind-`0x0000` defect class one level up.

     **WHAT THE OWNER RULED AGAINST, AND IT WAS A REAL CHOICE. Recorded so a later reader does not
     re-open it.** `C4` — the signature in the server attachment — is the only shape under which any
     receiver, **the message server included**, can refuse an unsigned wrap from the wire bytes alone.
     Its price is **+68 / +104 octets per record**, about **+170 KB per epoch fan-out**, a **Spec B
     §5.1 check-3** change, and **publicly verifiable per-epoch attribution of the committer across
     all 2,501 wrap records**. §4 is explicit that **`C4`'s property and `C3`'s privacy cannot both be
     had. The owner took the privacy**, and the consequence — that Spec A §5.11 (4)'s *"MUST NOT
     honour"* is enforceable by the decapsulating target and by nobody else — is now stated in
     §5.11 (6) rather than left to be discovered.

     **WHAT THE RULING UNBLOCKS AND WHAT IT DOES NOT.** It takes `M1-1` and `M1-7` off m1 **Task 14**,
     and through Task 14 off **Tasks 15 and 16**, which both modify the `wrap.go` Task 14 creates.
     **It does not lift item 152** — §6's *"honest limit"* holds verbatim: `seal.go:119` and `:387`
     refuse every non-`DURABLE` class, so the `EPH(5)` record is unsealable by the shipped code and
     **Task 14 is blocked by a landed refusal after this ruling**. And it does not touch **`S2-4`**:
     `JoinFromWelcome` is an unconditional refusal, so **no exported path lets two clients share one
     group**, which blocks CP3b outright and is `connect/mls`'s.

     **WHAT §6 ASKED FOR AND THE RULING DID NOT SAY.** Of §6's six sentences the ruling states (1),
     (3) and half of (6). **Not stated:** (2) that the envelope is a **hint** the open verifies — and
     the signature does **not** make this moot, because it lives inside `aead_ct` and is unreachable
     until after the open (item **178**, still owed); (4) the order **open → verify → honour** in
     those words, which m1 Task 14 Property 7's *"before it honours anything in the record"*
     contradicts as written; (5) how a **member** finds the key it verifies under, and how a
     restorer's carried `identity_pub` is anchored in the KT log; and (6)'s other half, a typed
     refusal for an absent or short signature. `M1-7`'s ruling likewise leaves set 3's clauses (b),
     (d) and (e) — the fill octet in a document, the **65,532** ceiling three documents publish as
     *"64 KiB"*, and the written argument at `seal.go:538` it overturns — and says nothing about the
     **ordinary record body**, whose unpadder is the same function. **Filed in Spec A §5.11 (6) and in
     m1's `M1-1` and `M1-7`.**

     **The item as it was filed, which is what the ruling ruled on:**

     **THE THREE `M1-1` OPTION SETS, COMPOSED — AN AMENDMENT TO m1's OPEN ITEM `M1-1` AND TO `M1-7`.
     THEY DO COMPOSE INTO ONE DECODABLE WRAP BODY. THEY DO NOT COMPOSE AT THE SETTINGS ALL THREE
     RECOMMEND, AND THE THING THAT BREAKS IS THE SIGNATURE'S COVERAGE. FILED WITH OPTIONS AND
     MEASURED COSTS. NOT RULED — `M1-1` AND `M1-7` ARE THE OWNER'S AND NOTHING BELOW IS A RULING.**

     Three option sets were produced **independently** against the three questions `M1-1` and `M1-7`
     leave open: the wrap body's **field list** (shapes W0–W6), **where the signature sits and which
     octets it covers** (S1–S6), and the **padding scheme** (P1–P8). Each recommended one shape —
     **W1+W5**, **S1**, **P2**. **All twenty-one shapes are recorded in §8 below**, with their own
     costs and their own recommendations, so the owner rules on shapes rather than on this pass's
     summary of them; nothing here re-derives or re-litigates any of them. What this pass adds is the
     one question none of the three could ask of itself: *do the three answers describe one body that
     a second implementation can build, walk and verify?*

     **WHAT THIS PASS DID AND DID NOT DO.** It ruled nothing. `M1-1`, `M1-7`, and ledger items
     **132**, **142**, **148** and **152** stay filed and unruled. It implemented nothing: m1 wave 2
     is not started, Task 14 is still blocked, and **no Go file in either tree changed**. It amended
     no spec: Spec A §5.11 (2)'s *"the recovery wrap's `ct_body` **is** `hybrid_ct`, followed by zeros
     to its rung"* (`spec-a:2199`) is still the normative sentence, and four of the five composites
     below would falsify it — which of them is taken is the ruling, not this pass's to make.
     `connect` was **read and never written**. A recommendation is given and is **labelled as one**.

     **EVERY NUMBER BELOW IS MEASURED BY CALLING THE SHIPPED ENCODER**, from a scratch module outside
     both checkouts with an absolute `replace` onto `connect`, which reads it and writes nothing in
     it. `message.SizeBucketBytes(2)` = **4,096**; `ct_body` at that rung = **4,112**;
     `EncodeServerAttachment` gives a `WrapTag` of **34** octets and a `RecoveryTag` of **64**;
     `message.EncodeRecord` gives **4,364** octets for a record with no attachment, **4,398** for a
     device wrap and **4,428** for a recovery wrap, at the corpus's own 96-octet `ct_head`;
     `message.AADHead` is **182** for **both** wrap kinds, because it carries
     `LP(H(server_attachment))` and not the attachment; `message.AADBody` is **96**. The epoch
     fan-out at the 500-member × 2-device target is `2,000 × 4,398 + 500 × 4,428` = **11.01 MB**,
     against the **≈ 11.5 MB** MASTER §8.2 and Spec B §6 both publish.

     ---

     **§1. THE COMPOSITE, WALKED FIELD BY FIELD. IT IS ONE BODY AND A PARSER CAN WALK IT.**

     Taking the three recommendations exactly as written — **W1+W5** for the fields, **S1** for the
     signature, **P2** for the padding — a device wrap's body plaintext is:

     ```
     LP32(1257) ‖ u8(version=0x01) ‖ u8(target_type) ‖ u8(payload_type) ‖ u64(content_epoch)
                ‖ u32(publisher_leaf_index) ‖ u16(alg_id) ‖ LP(ct_xwing) ‖ LP(aead_ct) ‖ zeros
     ```

     where `aead_ct` decrypts to `secret ‖ sig`. Measured: the envelope is **15** octets, `hybrid_ct`
     with the 64-octet signature inside `aead_ct` is **1,242**, the body is **1,257**, `padBody`
     writes `LP(bodyPlain)` so occupancy is **1,261** of the 4,096 rung, and the zero tail is
     **2,835**. The recovery wrap, whose `ct_body` is the body itself under no record AEAD, is
     **1,321** of **4,112** with a **2,791**-octet tail. `ct_body` stays 4,112 on both, so Spec B's
     `octet_length(ct_body)` CHECK never moves, and the records stay **4,398** and **4,428**.

     **The walk is unambiguous and every step is a fixed width or a length prefix.** Four octets of
     LP32 give the body's exact extent; eleven fixed octets give the version, the two type bytes and
     the content epoch; four more give the publisher's leaf; `hybrid_ct` is self-delimiting
     (`u16 ‖ LP ‖ LP`, MASTER §7); the remainder to the rung is the tail P2 refuses. **No step needs
     a key, a payload type, or the record's class.** That is the property the plan assumes it has,
     and under this composite it genuinely holds — for the fields. It does **not** hold for the
     signature, which is §2's first finding.

     **The three sets' arithmetic reconciles on the device wrap and not on the recovery wrap.** Sets
     1 and 2 both give 1,242 and a 2,850-octet tail for the unenveloped device body; measured, both
     are right. Sets 2 and 3 both give the recovery wrap 4,112 octets of room; set 1 prices it
     against 4,092. Filed as item **177**.

     ---

     **§2. WHAT DOES NOT COMPOSE. FIVE FINDINGS, EACH WITH ITS REPAIR AND THE REPAIR'S MEASURED
     COST. A BUILDER HITS ALL FIVE AT TASK 14 STEP 1.**

     **(1) THE SIGNATURE DOES NOT COVER THE FIELDS. THIS IS THE ONE THAT MATTERS.** S1's preimage,
     written out in full by its own set, is

     ```
     "URmessage/v1/wrapsig" ‖ u16(alg_id) ‖ LP(group_id) ‖ LP(sender_handle) ‖ u64(epoch)
       ‖ u64(stream_index) ‖ u8(is_commit) ‖ u8(retention_class_wire) ‖ u8(size_bucket)
       ‖ u64(expire_at) ‖ LP(blob_id) ‖ LP(H(server_attachment)) ‖ LP(ct_xwing) ‖ LP(payload)
     ```

     — measured at **1,305** octets for a 32-octet secret, of which the header block is **145**. It
     reaches the record header, the KEM transcript and the payload. **It does not reach one octet of
     W1+W5's envelope**, because the envelope sits outside `hybrid_ct` and S1 sits inside `aead_ct`,
     with `LP(ct_xwing)` between them. So under the composite as recommended, the four fields the
     field-list ruling exists to add are signed by nobody. Filed as item **176**.

     **What saves three of the four, and it is not the signature.** MASTER §7's nine-element `info`
     already binds `u8(target_type)`, `u8(payload_type)` and `u64(epoch)` into `wrap_key` itself. A
     receiver that derives `wrap_key` from the envelope's own values and finds that `aead_ct` does
     not open has detected the disagreement — fail-closed, at the cost of one AEAD open. **The
     envelope is therefore safe to read as a HINT without being authenticated**, and that is the
     sentence the ruling owes, because it is the difference between a field a receiver may act on
     before opening and one it may only act on after. Set 1 names **two** authorities for the payload
     kind — the body and the header's retention class — and misses the third; there are **three**,
     and three for the content epoch as well. Filed as item **178**.

     **What is not saved is W5's `u32(publisher_leaf_index)`.** It is in no `info`, in no AAD on the
     recovery wrap — that record's `ct_body` is under no record AEAD — and in no signature. On the
     recovery wrap it is four octets any party may rewrite with no effect any receiver can observe
     except a failed leaf-to-key resolution; on the device wrap it is authenticated only under
     `env_key[k]`, which **every member holds**. Filed as item **179**.

     **The repair is one term and it is measured: put `LP(wrap_envelope)` into the preimage**, ahead
     of `LP(ct_xwing)`. Preimage **1,305 → 1,324** octets, or **1,320** without W5. **Zero** octets
     in the body, **zero** on the wire, no new field, and no ordering problem — the envelope is
     plaintext the sealer chooses before it encapsulates, so `envelope → encapsulate → sign → seal
     aead_ct` is acyclic.

     **(2) `u8(size_bucket)` IS INSIDE THE SIGNATURE, SO `M1-7` IS AN INPUT TO `M1-1`'s SIGNATURE
     AND THE TWO ARE NOT SEPARABLE. THE THIRD SET SAID SO; THE SECOND SAID THE OPPOSITE.** Set 3
     closes with *"rule `M1-7` in one sitting with `M1-1`'s second remaining question… They are not
     separable."* Set 2 answers *"Under S1, S4 and S5 the two stay independent."* The composition
     settles it: `bucketForBody` (`connect/messagegroup/seal.go:485`) picks the rung from
     `len(body) + lpPrefixBytes`, `lpPrefixBytes` is **4**, measured off the writer rather than
     written down (`seal.go:467`, `:470`), and S1's preimage carries `u8(size_bucket)` — so the
     padding rule's prefix width is an input to a **signed** byte, and under P2's own scope sentence
     the two wrap classes compute that byte under two different rules. Not reachable today: 1,257 and
     1,321 both land on rung 2 whichever rule applies. **That is exactly what makes it item 143's
     shape** — a discipline nobody wrote, invisible in every round-trip test, reachable the first
     time a body lands within 64 octets of a rung boundary. Filed as item **180**.

     **(3) S1's UNCOVERED PAD IS SAFE ONLY UNDER P2. P2 IS A DEPENDENCY OF S1, AND NEITHER SET SAYS
     SO.** S1 covers neither the pad nor the zero tail — `LP(payload)` is its last term and the pad
     is outside `hybrid_ct` entirely. On a device wrap the tail is inside the record body AEAD, whose
     `record_key[i]` descends from `env_key[k]`, which **every member of the epoch holds** — so any
     member can rewrite any other member's wrap tail and the signature still verifies. `connect/mls`
     refuses exactly this one layer in, for exactly this reason: *"a covert channel of unbounded
     width inside every message, invisible to every signature because the padding is inside the AEAD
     but outside the FramedContent that gets signed"* (`mls/framing_protect.go:817`). **If `M1-7` is
     ruled P1 — the status quo, `unpadBody`'s tail deliberately unchecked (`seal.go:538-542`) — the
     composite ships a ~2.8 KB member-writable channel inside every wrap that no signature covers.**
     P2's accumulating, position-free refusal is the only thing that closes it. Stated as a
     dependency and not as a preference: **a ruling that takes S1 and defers `M1-7` has not deferred
     an independent question.**

     **(4) P2's SCOPE SENTENCE RE-CREATES THE DEFECT CLASS SET 1 REJECTS W6 FOR.** Set 1 rejects W6 —
     device wrap takes one body shape, recovery wrap another — because it is *"a target-type-dependent
     body encoding… the defect class the 2026-08-26 kind-`0x0000` ruling was written against, one
     level up."* P2's scope sentence produces one: *"the ordinary record body and the two device-wrap
     bodies pad to 4,096 as an AEAD plaintext; the recovery wrap's `ct_body`… keeps its own no-prefix
     form, and is EXCLUDED."* Under the composite a parser must know the record's class **before** it
     can decide whether the first four octets are a length or
     `version ‖ target_type ‖ payload_type ‖ …`, and the only thing that tells it is the server
     attachment's kind. The two are distinguishable in practice — an LP32 of 1,257 begins `0x00` and
     the version octet is `0x01` — but by an accident of magnitude that no document states and that a
     16 MiB body would end. **The repair costs four octets of a 2,791-octet tail and zero on the
     wire: prefix the recovery wrap too.** It is nearly free because W1 already amends the sentence
     the exclusion exists to protect — §5.11 (2)'s *"`ct_body` **is** `hybrid_ct`"* — so under any
     composite that takes W1, leaving the recovery wrap unprefixed buys nothing and costs one
     grammar. Filed with item **177**.

     **(5) W5 DOES NOT DO WHAT SET 1 SAYS IT DOES, AND SET 2's `LP(identity_pub)` IS NOT
     INTERCHANGEABLE WITH IT.** Set 1 calls `u32(publisher_leaf_index)` *"the only candidate field
     that makes the signature checkable from `record_bytes` alone."* It is not: `sender_handle` is
     **already** in `record_bytes`, raw and in the clear, at a fixed offset — `codec.go` writes it
     third, after the format version and the group id — and set 1's own measurement, **474 µs** to
     invert it over a 1,000-leaf group at 418.5 ns a candidate, is the cost W5 removes. W5 buys
     **speed**, not decidability, and it buys it only for a **member**. For the recovery wrap's only
     intended reader it buys nothing at all: a seed-only restorer holds no `group_handle_key` and no
     MLS state, so it can resolve neither a `sender_handle` nor a leaf index to an identity key.
     **The field that closes that is set 2's `LP(identity_pub)` inside `aead_ct`, and no field list on
     the board carries it.** The two are not substitutes, and the composite needs the second one.
     Filed as item **179**.

     ---

     **§3. IS EACH SHAPE WIRE-DECIDABLE BY A RECEIVER HOLDING ONLY THE BYTES? JUDGED HERE
     INDEPENDENTLY, BECAUSE THREE OF THIS PROJECT'S DEFECTS WERE RULES THAT COULD NOT BE EVALUATED
     FROM WHAT THE WIRE CARRIES.**

     "Wire-decidable" is not one property, and collapsing it is how the three sets reach three
     different verdicts about the same composite. It is **three** questions asked of **three** parties
     holding different key material, and the honest answer is a matrix rather than a yes:

     | can this party, from `record_bytes` alone, decide… | the message server | a group member | a seed-only restorer |
     |---|---|---|---|
     | …that the record is a wrap, and which kind | **yes** — the attachment kind is cleartext | **yes** | **yes** |
     | …the body's extent and framing — W0/W1/W2/W5 | recovery wrap only | after the record AEAD | recovery wrap only |
     | …the payload kind and content epoch — W0 | no | from the header, not the body | no |
     | …the payload kind and content epoch — W1 | **recovery: yes, in the clear** | yes, after the record AEAD | **yes** |
     | …the payload kind — W3 | no | only by a successful decryption | only by a successful decryption |
     | …that a signature is present at all — S1/S6 | **no** | **no** | **no**, until it decapsulates |
     | …that a signature is present at all — S2/S3 | recovery wrap only | yes, after the record AEAD | recovery wrap only |
     | …that a signature is present at all — S4/S5 | **yes** | **yes** | **yes** |
     | …that the signature verifies — S1 | no | **only if it is the wrap's target**, after opening `aead_ct` | after decapsulating, and only with `LP(identity_pub)` |
     | …that the signature verifies — S4/S5 | **yes** | **yes** | only with `LP(identity_pub)` |
     | …the padded body's length — P1/P2/P3/P6 | no (device), yes (recovery) | **yes**, before any payload knowledge | recovery wrap only |
     | …the padded body's length — P4 | as above, by an O(rung) scan | by a scan that must be constant-time | as above |
     | …the padded body's length — P5 | **no** | **no** — only a decoder that already knows the payload type | **no** |

     **Three readings follow from the matrix, and no one of the three sets states all three.**

     - **The field question and the signature question have opposite answers under the recommended
       composite.** W1+W5 is decidable; S1 is the least decidable shape on its own board. The
       composite is therefore **decidable in its fields and undecidable in its authentication**, and
       set 1's first reason for its own recommendation — *"the only shape under which the wrap body
       is decidable from its own octets"* — is true of the fields and false of the record. Both sets
       are individually right; the composite's advertised property is neither.
     - **"A client MUST NOT honour an unverified wrap" (Spec A §5.11 (4)) is enforceable only by the
       decapsulating target under every S1 composite.** No other party — not the server, not a member
       who is not the target, not a client triaging its own inbox — can tell a signed wrap from an
       unsigned one. That is a legitimate ruling to take; it must be a **stated** one, because the
       sentence is already normative and reads today as though anyone could apply it.
     - **P5's undecidability is the one the plan would inherit silently.** It is the only shape whose
       failure is invisible: `SealRecord(…, mlsCiphertext)` compiles, round-trips against itself, and
       is unopenable by a conforming second implementation with no error anywhere. Set 3 is right to
       reject it and right about why.

     ---

     **§4. THE OPTIONS. FIVE COMPOSITES, COSTED. NOT RULED — THIS IS THE OWNER'S DECISION.**

     Every one is **zero octets on the wire** except C4: `ct_body` stays 4,112, the records stay
     4,398 and 4,428, and Spec B's `octet_length(ct_body)` CHECK never moves. What separates them is
     what a receiver can decide, which normative sentence has to be amended, and what the message
     server reads off a recovery wrap in the clear.

     | | body plaintext | device occupied / tail | recovery occupied / tail | wire | amends §5.11 (2) |
     |---|---|---|---|---|---|
     | **C0** W0 + S1 + P2 | `hybrid_ct` | 1,246 / **2,850** | 1,306 / **2,806** | 0 | **no** |
     | **C1** W1+W5 + S1 + P2 — *the three sets as written* | `envelope(15) ‖ hybrid_ct` | 1,261 / **2,835** | 1,321 / **2,791** | 0 | yes |
     | **C2** C1 + `LP(wrap_envelope)` in the preimage | as C1 | 1,261 / **2,835** | 1,321 / **2,791** | 0 | yes |
     | **C3** W1 + `LP(identity_pub)` + C2's preimage + P2 over all three bodies | `envelope(11) ‖ hybrid_ct` | 1,293 / **2,803** | 1,357 / **2,755** | 0 | yes |
     | **C4** W1+W5 + **S4** + P2 | as C1, signature in the attachment | 1,261 / 2,835 | 1,321 / 2,791 | **+68 / +104 per record** | yes |

     **C0 — the null composite.** The only one that falsifies no normative sentence: with the
     signature inside `aead_ct`, §5.11 (2)'s *"`ct_body` **is** `hybrid_ct`, followed by zeros"* stays
     literally true. Nothing in the body is decidable — the payload kind comes from
     `header.RetentionClass`, the target from `AAD_head`, the content epoch from item **142**'s
     downward trial-decryption walk, and the publisher from inverting `sender_handle`. Four
     disciplines, none of them written down anywhere today. **Cheapest to rule, most expensive to
     build against, and the shape most exposed to a second implementation guessing differently.**

     **C1 — the three recommendations exactly as they arrived.** Buys the field decidability. Carries
     §2's finding (1) unrepaired: `publisher_leaf_index` authenticated by nothing on the recovery
     wrap, and the ruling silently relying on `wrap_key`'s `info` for the other three without saying
     so. **C1 should not be ruled as written**, and that is the single most useful thing this
     composition has to say.

     **C2 — C1 with the coverage gap closed by one term.** Preimage 1,305 → 1,324. Zero further cost
     anywhere: no body octet, no wire octet, no document beyond the one C1 already amends. This is C1
     made sound, and it is the smallest edit that makes the three recommendations true together.

     **C3 — one grammar, one leak fewer, and the field the recovery wrap actually needs.** Drops W5,
     which is redundant with `sender_handle` for a member, useless to a restorer, and the composite's
     only new cleartext leak; adds `LP(identity_pub)` inside `aead_ct`, the only field that makes a
     recovery wrap's signature verifiable by the party it exists for; extends P2's prefix to the
     recovery wrap so all three wrap bodies have **one** parse. Costs 32 more octets of body than C2
     out of a 2,835-octet budget, and **zero** on the wire.

     **C4 — the maximal-decidability composite.** The only one under which any party, the server
     included, can refuse an unsigned or wrongly-signed wrap on the wire bytes alone. Its price,
     stated rather than hedged: **+68 octets per record with `LP(sig)` and +104 with the identity
     key** — measured 4,398 → 4,466 and 4,428 → 4,496, about **+170 KB** per epoch fan-out on an
     11.01 MB bundle — a Spec B §5.1 check-3 change and a new width in
     `connect/message/attachment.go`, and a publicly verifiable Ed25519 signature, under a key
     MASTER §5.2 publishes in the KT log, on **all 2,501** wrap records per epoch, which hands the
     operator per-epoch attribution of the committer and cuts against MASTER §4.2. **If the owner's
     priority is that an unverified wrap be refusable on the wire by anyone, this is the shape and
     that is its price. The two cannot both be had.**

     ---

     **§5. A RECOMMENDATION, LABELLED AS ONE. IT IS NOT A RULING AND I DID NOT MAKE ONE.**

     **C3** — and if the owner wants the smallest change from what the three sets already
     recommended, **C2**, with the understanding that C2 leaves `publisher_leaf_index` doing work no
     party can check and leaves two body grammars behind. Three reasons, each checkable rather than
     preferential.

     **(1) It is the only composite in which every field a receiver acts on is either authenticated
     or fail-closed.** The envelope is bound by `wrap_key`'s `info`, so a lie costs one failed open;
     the signature's preimage reaches the envelope; the identity key travels where the restorer can
     read it; and the pad is closed by P2's refusal rather than by a signature that does not cover
     it. C0 and C1 each leave at least one field a receiver acts on authenticated by nothing.

     **(2) It leaves one body grammar rather than two** — the property set 1 rejects W6 to get and
     P2's scope sentence gives back. Four octets of a 2,791-octet tail.

     **(3) It is neutral to every reversal on the board, for the half a body field can address.** A
     reversal of **A1** re-creates the keystream reuse no field list can fix — but a `payload_type`
     in the body turns a silent misread into a refusal, which C0 does not. **M1-6** and item **152**
     both sit in the head; C3's discriminator is in the body and survives whatever they rule. And
     item **142**'s downward candidate-epoch walk is **bounded to one candidate** by `content_epoch`
     read as a hint — the one place the composite is strictly better than either set claims, because
     set 2's own cost of S1 is that each unopenable record *"also cannot be classified"*, and W1's
     eight octets are what classify it.

     **The budget is not close to binding, and the cliff is real.** C3 spends 1,293 of the 4,096-octet
     rung. Exceeding 4,092 moves to rung 3: `ct_body` **4,112 → 16,400**, measured **+12,288 octets
     per record × 2,000 device wraps = +24.6 MB per commit**. C3 leaves **2,803** octets between the
     body and that cliff.

     ---

     **§6. WHAT A RULING MUST STATE, OR IT IS NOT A CLOSURE. SIX SENTENCES, AND THE FIRST THREE ARE
     THE ONES THE COMPOSITION FOUND RATHER THAN INHERITED.**

     1. **Which octets the signature covers, written out as a preimage**, and whether the wrap
        envelope is among them. A ruling that names a placement without naming a preimage has ruled
        the half that decides nothing.
     2. **That the envelope is a HINT the open verifies, and not an authority** — a wrong
        `target_type`, `payload_type` or `content_epoch` produces a `wrap_key` that does not open
        `aead_ct`, and that failure **is** the check. Without this sentence one implementer trusts an
        unauthenticated field and another refuses to use it, and the two diverge only on an
        attacker's record.
     3. **`M1-7`'s scope, in the same sitting and over three body classes**, because `u8(size_bucket)`
        is inside the signature and the pad is outside it. Deferring `M1-7` past a signature ruling
        defers an input to that ruling.
     4. **The order is open → verify → honour**, in those words, with "honour" defined as installing
        `pq_secret[k]` / `eph_root[k]` / `storage_root[k]` into the session — because under every S1
        composite the signature is unreachable until after the open, while §5.11 (4) and Task 14
        Property 7 say *"before it honours anything in the record"*.
     5. **How a verifier finds the key it verifies under**, for both wrap kinds: a member resolves the
        leaf whose `sender_handle` matches and reads `Member.IdentityPub`; a seed-only restorer has
        **no such route at all** and needs `LP(identity_pub)` carried and anchored in the KT log.
     6. **A typed refusal for an absent or short signature** — at S1's position that is a
        payload-parse outcome and not a wire-parse one — and a typed refusal for a non-zero tail,
        accumulating over the whole tail and **naming no position**, copying the reasoning
        `connect/mls`'s own sentinel already carries (`mls/framing_protect.go:744-750`).

     **And the honest limit, which all three sets reached separately.** Even a complete ruling on all
     three questions does not start Task 14. `connect/messagegroup/seal.go:119` still refuses every
     non-`DURABLE` class on the seal path and `:387` mirrors it on the open path, so **both**
     device-wrap records are unsealable by the shipped code until item **152** lifts the `EPH` half.
     Task 14 is blocked by a **landed refusal** as well as by an unruled field list, and the two are
     independent of each other.

     ---

     **§7. WHAT THIS PASS MEASURED THAT THE SETS GOT WRONG, WITH THE QUERIES.** The disagreements are
     items **176** through **180**. Three smaller corrections belong here rather than as items:

     - **The *"about 4.6 KB on the wire"* figure is in Spec B §3 and §6, not in a §9 retention
       table.** Set 1 attributes it to *"Spec B §9's retention table"*; measured, the three `~4.6 KB`
       rows are at `spec-b:1092-1094`, inside **§3 Data model**, and the `≈ 11.5 MB` sizing block is
       at `spec-b:2453`, inside **§6**. The numbers are exactly where set 1 says they are wrong —
       4,398 and 4,428 measured against ~4.6 KB published — and only the section labels move.
     - **Two of the sets' own line citations had drifted and are corrected in §8 rather than
       reproduced.** `codec.go:20` is the `server_attachment` row of the layout table; the *"never
       `syntax.WriteOpaque`"* rule set 3 attributes to it is at **`codec.go:29`**. And `master:840` is
       a blank line; *"the MLS PrivateMessage payload"* is at **`master:837`**. Both were caught by
       printing the cited line, which is the only reason to write a citation as a line number.
     - **`ErrBodyPadding` already exists** (`connect/messagegroup/errors.go:248`) and `unpadBody`
       already returns it for both of its refusals, so P2's tail check needs **no new sentinel** —
       one declaration fewer than set 3 prices. `messagegroup` is on neither §12.1 block, so no
       amendment is owed either way.
     - **The `env_key`-versus-`ClassKeys.Durable` contradiction reproduces exactly as set 1 states
       it.** Query, re-run here: `env_key` occurs **18×** in Spec A, **10×** in MASTER and **16×** in
       this ledger, and `grep -Ei 'K_durable|ClassKeys\.Durable'` over those hits returns **0**. The
       device wrap's `ct_head` root is genuinely unstated, and it blocks Task 14 independently of
       every shape above.
     - **All three sets report the `connect` tree as dirty against a brief that calls it clean, and it
       moved twice while this pass was running — so the tree every figure above was measured against
       is named rather than assumed.** At the start: `33932e0`, with `messagegroup/epoch.go`,
       `epoch_test.go` and `testdata/epoch/control.go` **staged**, where two of the sets had seen
       `epoch.go` untracked, alongside modified `errors.go`, `entropy_test.go` and `mls/crypto_test.go`.
       At the end: **`7868d65`** — *"m1 task 13 — `pq_secret`'s sampler, and the provisional epoch
       state G10 destroys"*, 8 files and 1,819 insertions — with only `messagegroup/epoch.go` modified.
       **Task 13 landed during this pass.** Every `connect` anchor cited above was re-verified at
       `7868d65` and every one holds: that commit does **not** touch `seal.go`, so `:119`, `:387`,
       `:467`, `:470`, `:485`, `:498`, `:512`, `:538` and `:543` are unmoved; it does touch `errors.go`
       (+29/−8) and `ErrBodyPadding` is still at `:248`, checked rather than assumed. **The two
       refusals that block Task 14 are unchanged by Task 13's landing**, which is the fact that
       matters here.

     ---

     **§8. THE THREE SETS AS THEY ARRIVED, RECORDED IN FULL, SO THE OWNER RULES ON SHAPES AND NOT ON
     THIS PASS'S SUMMARY OF THEM.** Each shape keeps its own set's five axes: what changes **on the
     wire**, what it costs in **octets**, the discipline it still needs that **no document states**,
     what a reversal of **A1** or of **M1-6** does to it, and whether it is **wire-decidable**. *Where
     a shape's numbers disagree with §1's measurements above, §1 is the measurement and the shape's
     figure is left as its set published it, so the disagreement stays visible rather than being
     tidied away.* The three recommendations are the sets' own and are labelled as theirs.

     **SET 1 — THE FIELD LIST, beyond what MASTER §8.2's payload table and MASTER §7's `hybrid_ct`
     framing already fix.**

     - **W0 — the body IS `hybrid_ct`** (the null shape; what three documents' arithmetic already
       assumes). *Wire:* nothing new; `ct_body` plaintext is `hybrid_ct` (‖ signature) through the
       landed `padBody`, sealed to 4,112. The only shape under which MASTER §8.2's `2 + (4+1120) +
       (4+32+16) = 1,178`, Spec A §5.11's table and §5.11's *"the recovery wrap's `ct_body` **is**
       `hybrid_ct`, followed by zeros"* all stay literally true. Nothing sealed breaks:
       `messagegroup/wrap.go` does not exist and `grep -rn 'wrap_body|WrapBody|wrapBody'` over both
       trees returns **0**. *Octets:* device 1,178 + 64 = **1,242** of 4,092 usable at rung 2, slack
       **2,850**; recovery **1,306**, slack 2,786 *(§1 measures 2,806 — item **177**)*; `ct_body`
       4,112, records 4,398 / 4,428. *Unwritten:* three, and this is the shape most exposed to the
       trap. (i) The opener must take the payload kind from `header.RetentionClass` — PERMANENT ⇒
       `pq_secret`, EPH(5) ⇒ `eph_root` — and refuse any other class; MASTER §8.2 only *describes*
       this and no document makes it a refusal. (ii) With no target in the body, the signature binds
       `wrap_target_handle` only if its preimage reaches into the `WrapTag`; otherwise the target is
       authenticated by `AAD_head` alone, whose key **every member holds** — red-team finding C,
       unrepaired by the seal ruling. (iii) The verifier must learn whose identity key to check with
       no field naming it: the only route is inverting `sender_handle` by leaf enumeration (**474 µs**
       over 1,000 leaves, 418.5 ns a candidate), a rule no document states and which §5.11 step 6's
       *"any member may re-publish"* makes load-bearing. *Vs rulings:* rests on **A1** completely —
       A1 gives the leaf's two wrap records two positions on one class-blind root, the only thing
       separating their two AEADs. Reverse A1 and §5.11's own measured outcome returns verbatim:
       *"the message server recovers `pq_secret[k] ⊕ eph_root[k]` for every leaf of every epoch"*,
       with no in-body defence and no misread detector. Against **M1-6** the shape is undefined
       rather than safe. *Wire-decidable:* yes at the record level, **no** at the body level.
     - **W1 — a versioned, typed body envelope:** `u8(wrap_format_version=0x01) ‖ u8(target_type) ‖
       u8(payload_type) ‖ u64(content_epoch) ‖ hybrid_ct`. *Wire:* +11 octets of plaintext inside an
       unchanged 4,112-octet `ct_body`; contradicts exactly one normative sentence, §5.11 (2)'s
       *"`ct_body` **is** `hybrid_ct`"*, which must be **amended, not annotated**. The version octet
       must be first, for `codec.go`'s own stated reason: every offset below it is meaningful only
       under that version. *Octets:* device **1,253** of 4,092, slack **2,839**; recovery **1,317**,
       slack 2,775 *(§1: 2,795)*; 0 wire octets. *Unwritten:* two authorities for one fact —
       `payload_type` in the body and `retention_class` in the header both name the secret and both
       are authenticated (`AAD_body` differs between PERMANENT and EPH(5), measured) — so the ruling
       must say the opener **refuses a disagreement**. Same for `content_epoch` against
       `header.Epoch`. *(Item **178**: there is a **third** authority, `wrap_key`'s `info`, and it
       changes the shape of the ruling this owes.)* *Vs rulings:* the only shape neutral to an **A1**
       reversal on the misread half — it converts a silent misread into a refusal, without making the
       keystream reuse safe. Neutral to **M1-6** and to item **152**, because the discriminator is in
       the body. Its own cost falls on the **recovery** wrap alone: that record's `ct_body` is under
       no record AEAD, so the 11 octets sit in the clear at a fixed offset and the server reads them;
       `RecoveryTag` already announces the kind and `header.Epoch` already gives the epoch, so the
       marginal leak is small — but it is a leak the device wrap does not have. *Wire-decidable:*
       **yes, fully.**
     - **W2 — minimal discriminator:** `u8(payload_type) ‖ hybrid_ct`. *Wire:* +1 octet of plaintext,
       0 on the wire; gives `u8(payload_type)` — which MASTER §7 names as an inherited gap with *"no
       code point anywhere"* — an encoding a KAT can pin. Same contradiction with §5.11 as W1, one
       octet's worth. *Octets:* device **1,243**, slack **2,849**; recovery 1,307, slack 2,785 *(§1:
       2,805)*. *Unwritten:* W1's refusal with none of W1's room — no version octet means a second
       body field later is a **flag day** rather than a negotiation, which the A6 freeze makes
       expensive; and `target_type` is carried nowhere while still needing its code point, so the
       ruling closes half a gap on the wire and the other half only in a derivation. *Vs rulings:*
       W1's neutrality, for the payload discriminator only; nothing for the target and nothing for
       the publisher, so W0's disciplines (ii) and (iii) survive intact. *Wire-decidable:* yes for
       the payload kind; **no** for the target, the publisher or the content epoch.
     - **W3 — bind, do not carry:** assign the code points and let them live only inside `wrap_key`'s
       `info`. *Wire:* **zero, everywhere** — byte-identical to W0; the whole difference is in the key
       derivation MASTER §7 already declares *"normative modulo those three"*, so this is the
       completion of §7 rather than an addition to §8.2 and needs no amendment to §5.11. *Octets:*
       identical to W0. Its cost is CPU: two `wrap_key`s from **one** decapsulation (X-Wing
       decapsulate measured at **58.3 µs**, paid once) and the inner AEAD run twice over ~48 octets —
       not a second KEM operation. *Unwritten:* the discriminator becomes **trial decryption**, and a
       failure is then indistinguishable from a corrupt record, a wrong `target_id` (undefined
       corpus-wide, Task 19's), a wrong type assignment, and the *unrecoverable* missed-`env_key[k]`
       case §5.11 requires to be a typed visible failure with no member of `GapReason`'s closed set to
       carry it. Worse: an implementer who defaults `payload_type` to a constant — the natural thing
       for a value with no code point, and what MASTER §7 warns about — collapses the inner AEAD's
       separation onto `AAD_body`'s class byte. *Vs rulings:* strictly **worse than W0** under an
       **A1** reversal — the two records would share `(key_body, nonce_body)` *and* the receiver would
       be trial-decrypting, so a swapped pair is a decryption **success under the wrong label**.
       *Wire-decidable:* **no — explicitly not.**
     - **W4 — frame inside `aead_ct`:** `aead_ct` plaintext = `u8(payload_type) ‖ u64(content_epoch) ‖
       secret`. *Wire:* `aead_ct` 48 → 57, so `hybrid_ct` **1,178 → 1,187**, moving a number printed
       in MASTER §8.2, Spec A §5.11 and Spec B's retention table — three documents' arithmetic, none
       of it code. Leaves §5.11's *"`ct_body` **is** `hybrid_ct`"* true as written, which W1 and W2 do
       not. *Octets:* device **1,251**, slack **2,841**; recovery 1,315, slack 2,777 *(§1: 2,797)*.
       *Unwritten:* the only shape that makes the discriminator **confidential** as well as
       authenticated, which matters on exactly one record — the recovery wrap, whose outer body is
       under no record AEAD. But it puts the discriminator behind the KEM, so a device learns a wrap's
       kind only after a successful decapsulation: it cannot sort its inbox, dedupe a re-published
       wrap, or report a gap without the private key on hand, and no document contemplates that.
       *Vs rulings:* neutral to **M1-6** and to an **A1** reversal for misreads — but under an A1
       reversal the two bodies share `(key_body, nonce_body)` and are now 9 octets longer in
       *known-structure* plaintext, which is 9 more octets of keystream a XOR hands the server free.
       *Wire-decidable:* **no.**
     - **W5 — name the publisher:** add `u32(publisher_leaf_index)`; orthogonal, composable with
       W0–W4. *Wire:* +4 octets of plaintext, 0 on the wire. *Octets:* W0+W5 = **1,246**, slack 2,846;
       W1+W5 = **1,257**, slack **2,835** — 15 octets, 0.37% of the rung, out of a 2,850-octet budget.
       *Unwritten:* without it a verifier recovers the publisher's identity key by inverting
       `sender_handle` through leaf enumeration (**474 µs** over 1,000 leaves), which works only
       because a member holds `group_handle_key` and which **no document states**; §5.11's own
       recommendation (6) makes the publisher genuinely variable rather than "the committer", so
       every shape that omits this field makes the enumeration rule normative by omission. With the
       field, the discipline moves rather than vanishing: the opener MUST check the carried leaf
       against `sender_handle` and refuse a disagreement. *Vs rulings:* independent of **A1** and of
       **M1-6**. *Wire-decidable:* yes. *(Item **179** disputes this shape's stated benefit.)*
     - **W6 — two kinds, two answers** (the shape the seal ruling itself took): device wrap takes W0,
       recovery wrap takes W1. *Wire:* device nothing new, recovery +11. *Octets:* device 1,242, slack
       2,850; recovery 1,317, slack 2,775 *(§1: 2,795)*. *Unwritten:* it is a **target-type-dependent
       body encoding**, the residual the 2026-09-12 red team filed against its own recommendation —
       *"the defect class the 2026-08-26 kind-`0x0000` ruling was written against, one level up."* A
       parser must know the record kind before it can parse the body, so `AttachmentWrap` vs
       `AttachmentRecovery` becomes a **parsing** authority as well as a routing one. *Vs rulings:*
       it puts the in-body defence on the record that does **not** have the collision and leaves it
       off the two that do; against **M1-6**/152 it is likewise backwards, since the `EPH(5)` device
       wrap is the record whose head is unruled and W6 gives it no body discriminator. *Wire-decidable:*
       yes, but in two steps — parse the attachment's kind, then parse the body under that kind's rule.

     **Set 1's recommendation, labelled by its own author as a recommendation and not a ruling:**
     **W1 + W5** uniformly across both wrap kinds, signature placement left to the second question.
     Four reasons: it is the only shape under which the wrap body is decidable from its own octets; it
     closes MASTER §7's inherited gap by putting `u8(target_type)` and `u8(payload_type)` on the wire
     where a KAT pins them; it is neutral to a reversal of A1 and of M1-6 for the half a body field
     can address; and the budget is not close to binding — the rung-3 cliff is **+12,288 octets ×
     2,000 device wraps = +24.6 MB per commit**, and W1+W5 spends 15 of the 2,850 octets in front of
     it. Its stated costs: it contradicts §5.11 (2), which must be amended; and on the recovery wrap
     alone the 15 octets sit in the clear and the server reads them, the marginal leak being
     `publisher_leaf_index`.

     **SET 2 — WHERE THE SIGNATURE SITS RELATIVE TO `hybrid_ct`, AND PRECISELY WHICH OCTETS IT
     COVERS.**

     - **S1 — innermost:** last field of the wrap payload, inside `aead_ct`. Coverage: `label ‖
       u16(alg_id) ‖ header block H ‖ LP(ct_xwing) ‖ LP(payload)`. *Wire:* `hybrid_ct`'s shape
       unchanged; only `aead_ct` grows by 64. No document sentence is falsified — §5.11 (2) stays
       literally true. Because the signature lives inside the payload, this ruling and the field-list
       remainder land in one edit rather than two. *Octets:* **zero** — records stay 4,398 / 4,428,
       `ct_body` 4,112; device rung free space **2,914 → 2,850**; recovery zero tail **2,870 → 2,806**;
       preimage **1,305** for a 32-octet secret; `LP(identity_pub)` costs a further 36 in the payload
       and still zero on the wire. *Unwritten:* four. (i) The order encapsulate → sign → seal
       `aead_ct` is not expressible in the shipped staging types — `seal.go`'s `recordBuilder →
       recordBodySealed → recordBodyBound → recordHeadSealed` chain starts at the record layer and the
       wrap is built above it. (ii) The publisher's identity **private** key has no route to the
       signer: `GroupSession` holds no signing key and `grep -rn 'ed25519' messagegroup/*.go` outside
       tests returns nothing, so the whole sign-and-verify surface is new and Task 14's Consumes list
       names none of it. (iii) *"Verify before honour"* must be written as **open → verify → honour**.
       (iv) Resolving *which* identity key to verify under is unwritten, and for a recovery wrap there
       is no route at all. *Vs rulings:* **A1** — the preimage's header block carries
       `u64(stream_index)`, so the ladder position is *signed* rather than merely disciplined, which
       is what item 143's trap asks for; an A1 reversal costs nothing given `u8(retention_class)`,
       which the block carries. **M1-6:** neutral both directions — this shape never touches
       `ct_head`. **Item 142:** this position converts A-17's uncheckable *"the signature MUST be
       recomputed and MUST NOT be copied"* into a property of the format, because a signature inside
       `aead_ct` is not addressable outside it. *Wire-decidable:* **no**, and this is the shape's real
       cost: a receiver holding only the wire bytes cannot locate the signature, cannot tell a signed
       wrap from an unsigned one, and cannot reject a wrap for being unsigned.
     - **S2 — beside `hybrid_ct`, appended:** body = `hybrid_ct ‖ LP(sig)` ‖ zeros. Coverage: `label ‖
       u16(alg_id) ‖ H ‖ LP(hybrid_ct)`. *Wire:* ciphertext on the device wrap, **in the clear on the
       recovery wrap**; falsifies *"`ct_body` **is** `hybrid_ct`, followed by zeros"* in three
       documents, and moves the offset at which §5.11's named typed refusal on the tail begins — so
       M1-7's padding ruling and this one now share an edge. *Octets:* zero on the wire; device
       occupancy 1,246 → LP-framed 1,250, slack 2,846; recovery `ct_body` 1,310, tail 2,802; preimage
       1,327 device / 1,391 recovery. *Unwritten:* S1's (i), (ii), (iv), plus (v) a
       **publisher-deanonymisation** rule nobody has written — on the recovery wrap the 64 signature
       octets are cleartext, Ed25519 verification is public, and `identity` is published in the KT log
       (MASTER §5.2), so a server holding ~500 recovery wraps per epoch can learn which member
       committed each epoch; and (vi) the parse is verify-after-parse, reading two attacker-chosen
       32-bit length prefixes to find the signature. *Vs rulings:* identical to S1 on A1 and M1-6;
       unlike S1 it does **not** make item 142's no-copy rule structural. *Wire-decidable:* **split** —
       fully decidable with no key on the recovery wrap, not decidable on the two device wraps. That
       split is the red team's residual risk 1 reaching the signature as well as the seal.
     - **S3 — beside `hybrid_ct`, prepended:** `u16(sig_alg_id) ‖ LP(sig) ‖ hybrid_ct` ‖ zeros. Same
       coverage as S2. *Wire:* same field set, reversed, so the signature sits at a fixed offset a
       verifier reaches before parsing any attacker-controlled length; the same three-document
       sentence is falsified more sharply, because the body no longer *begins* with `hybrid_ct`.
       *Octets:* identical to S2; the suite id costs 2 more inside the rung. *Unwritten:* S2's (i),
       (ii), (iv), (v); removes (vi); adds a second `alg_id` in one body with no document saying
       whether the two may differ. *Vs rulings:* identical to S2. *Wire-decidable:* same split,
       strictly better than S2 within the decidable half.
     - **S4 — outside the body:** `WrapTag` and `RecoveryTag` gain `LP(sig) ‖ LP(identity_pub)`.
       *Wire:* both attachments gain two fields; `AAD_head` and the `write_auth` preimage cover the
       attachment only as `LP(H(server_attachment))`, so both stay 182 and 249 octets. There is
       precedent — `RecoveryTag` already carries an Ed25519 public key — but it is a **Spec B change**:
       §5.1 check 3 validates each attachment field's exact width, so two new widths must be added
       there and in `connect/message/attachment.go`. *Octets:* **+68 per record** with `LP(sig)`,
       **+104** with the identity key; device 4,398 → **4,466**, recovery 4,428 → **4,496**; ~**+170 KB**
       per epoch fan-out. *Unwritten:* S1's (i) and (ii); plus (vii) the construction order inverts
       relative to MASTER §8's *"build `server_attachment` → encrypt `ct_body`"*, which is legal but
       reads backwards and no document says so; and (viii) the cleartext-signature deanonymisation of
       S2 (v) applying to **all 2,501** wrap records per epoch and additionally shipping the
       publisher's identity public key to the server in the clear. *Vs rulings:* M1-6-neutral,
       A1-neutral; interacts with item **132** — a server-visible, server-verifiable signature is the
       first thing that would let the server refuse a wrap it cannot attribute, which is a capability
       132 and finding B have been asking for and which **I5** says this layer does not provide.
       *Wire-decidable:* **yes, completely, for all three wrap kinds, with no key material at all** —
       the only shape under which *"a client MUST NOT honour an unverified wrap"* is enforceable
       before any decapsulation.
     - **S5 — a fifteenth record field,** `LP(wrap_sig)` after `ct_body`. Coverage: the maximal set —
       `AAD_head` (182 octets, already carrying `body_hash` and `LP(H(server_attachment))`) ‖
       `LP(ct_body)`. *Wire:* a codec change; `codec.go` publishes fourteen fields and states that
       `record_id` *"is not in this encoding and never will be"*. It is the only shape whose signature
       can cover `ct_body` as sealed, `body_hash` and `ct_head` — i.e. the only one that authenticates
       the padding and the zero tail. Every codec, AAD and `write_auth` KAT in `connect/message` moves,
       and Spec A §12.1 and Spec B §12.1 — asserted to be the same list character for character — both
       change. *Octets:* **+68 per record**, on *every* record if unconditional; `AAD_head` and the
       `write_auth` preimage grow 182 → 218 and 249 → 285 if extended to cover it, and if not, the
       signature is a malleable trailer nothing binds. *Unwritten:* (ix) the signature and `write_auth`
       contend for last position in a construction order MASTER §8 declares acyclic — no document has
       ever had to order two authenticators over one record; (x) it breaks the A6 wire-format freeze
       premise items 128 and 143 both cite. *Vs rulings:* **the only shape where an M1-6 reversal is
       not free** — every non-DURABLE head ciphertext changes value, so the signed bytes change and
       every wrap KAT is reissued. *Wire-decidable:* **yes, completely**, with S4's deanonymisation at
       full scope.
     - **S6 — the minimal one an implementer reaches for by default:** S1's position, covering only
       the wrap payload plaintext and nothing of the header and nothing of `hybrid_ct`. *Wire:*
       identical to S1; no sentence falsified. Listed because it is what *"sign the wrap body"* reads
       as if the ruling does not enumerate octets, and because its deficiency is invisible in every
       round-trip test Task 14's Properties 1–8 describe. *Octets:* zero; preimage ~64 rather than
       1,305. *Unwritten:* all of S1's, plus the one that makes it not a closure — **it does not close
       finding C, which is the entire stated reason the signature exists.** Finding C enumerates six
       fields authenticated by nothing on a wrap and a payload-only signature authenticates none of
       them; for the recovery wrap, which has no record AEAD over the body and a head keyed off
       `wrap_key` that anyone holding the target's published X-Wing key can produce, **every** header
       field remains forgeable by anyone. *Vs rulings:* **it reverses A1's benefit** — omitting
       `stream_index` and `retention_class` re-opens the splice A1 closed. *Wire-decidable:* **no**,
       and worse than S1: a successful verification is not evidence about anything the client acts on.

     **Set 2's recommendation, labelled by its own author as a recommendation:** **S1, with the
     header block written out and with `LP(identity_pub)` carried beside the signature inside the
     payload.** The preimage it proposes for §5.11 (4) is the one quoted in §2 (1) above — the
     `write_auth` preimage minus `LP(server_nonce)` and the two values that do not exist yet, plus the
     KEM transcript; the corpus's own house style, so no new framing convention. Five reasons: zero
     octets on both wrap kinds; one rule for all three wrap kinds, where S2/S3 extend the red team's
     residual risk 1 from the seal to the signature; no cleartext signature anywhere, where S2–S5 hand
     the operator per-epoch attribution across 500 or 2,501 records; it closes item 143's trap on its
     own terms, since `i = stream_index` becomes a *signed* fact and A-17's no-copy MUST becomes
     structural; and it is neutral to both rulings and to reversing either. Its stated costs: S1 is the
     **worst** shape on wire-decidability, and if the owner's priority is that any receiver can reject
     an unsigned wrap on the wire, **S4** is the shape and its price is +68/+104 octets per record, a
     Spec B check-3 change and the deanonymisation. The set adds three things the ruling must then
     also say: **open → verify → honour** in those words; `LP(identity_pub)` beside the signature with
     the verifier's obligation stated for each wrap kind; and a typed refusal for an absent or short
     signature.

     **SET 3 — THE PADDING SCHEME, which is open item `M1-7`.**

     - **P1 — LP32 prefix, zero fill, tail unchecked (STATUS QUO;** `seal.go:512` and `:543`**).**
       *Wire:* nothing changes; this is what wave 1 seals today. `unpadBody` refuses a buffer that is
       not exactly the rung and a prefix that overruns it, and deliberately does **not** check the tail
       (`seal.go:538`). *Octets:* 0; `ct_body` 4,112. The cost is the rung boundary, not the record:
       `bucketForBody` picks the rung from `len(body) + 4`, so exactly **4 body lengths per rung
       climb** — 253–256 (524 → 1,292, ×2.47), 1021–1024 (×3.38), 4093–4096 (×3.82), 16381–16384
       (×3.95) — and 65,533–65,536 are refused outright with `ErrBodyTooLong`. *Unwritten:* five.
       (i) **The fill byte** is inside the AEAD so it is the sealer's free choice, and two clients
       choosing differently produce different `ct_body` and different `body_hash` for one message;
       `m1w1repairs_test.go:765` pins it octet by octet and `seal.go:498` says the scheme is *"THIS
       FILE'S AND NOT A DOCUMENT'S"*. (ii) **The unchecked tail is a ~4 KB covert channel per record
       that no signature covers**, and `connect/mls` refuses exactly this one layer in for exactly this
       reason; it is worse at the record layer, because `record_key` descends from `storage_root[n]`,
       which every member holds, so the channel is writable by any member and not only by the sender.
       (iii) **The real inline ceiling is 65,532** while Spec A:2494, MASTER:1260 and Spec B:2854 all
       publish *"the 64 KiB inline ceiling"* and no document subtracts the prefix. (iv) **Which `LP`** —
       `syntax.WriteOpaqueLP`'s fixed 32 bits, never MLS's varint — is stated at `codec.go:29` for the
       record and nowhere for the body. (v) **It does not answer the recovery wrap**, whose `ct_body`
       §5.11:2199 already makes normative as `hybrid_ct` *"followed by zeros to its rung"* with a named
       typed refusal — no prefix, and a refusal. Ruling P1 as written leaves the corpus with two
       schemes and must say so out loud. *Vs rulings:* neutral to **M1-6** and **A1** in both
       directions — the pad is a body construct that touches no ladder and no counter. One positive
       interaction: `bucketForBody` runs at `seal.go:176`, **before** `ratchet.Next()` at `:184`, so
       the rung is chosen before an index is consumed and the call-graph gate stays green; any shape
       that made the **rung** depend on the reserved index would invert that order and break it.
       *Wire-decidable:* yes for a receiving member — the length is the first four octets of the
       authenticated plaintext, read with no knowledge of the payload type. No for the server on an
       ordinary record, and that is the point (§9.5); but on the recovery wrap `ct_body` is cleartext,
       so a prefix there would be server-readable and would hand the server the wrap's true payload
       length.
     - **P2 — P1 with the tail REFUSED** (accumulating, position-free). *Wire:* byte-identical for a
       conforming sealer; the change is a refusal on the open path. *Octets:* 0; same rung arithmetic
       and ceiling as P1. *Unwritten:* three, two of them cheap. (i) **The refusal must accumulate
       over the whole tail and name no position**, or it is a padding oracle —
       `mls/framing_protect.go:744` states that rule in as many words for MLS's own tail and the record
       layer states it nowhere. (ii) It still owes the fill byte **in a document**. (iii) **It
       overturns a written argument** rather than filling a silence: `seal.go:538` currently argues
       against the check — *"a reader that refused a record whose tail was not zero would be refusing a
       record its own key opened"* — and the ruling must say why that is wrong, which it is, because
       the key that opened it is one every member holds. *Vs rulings:* same neutrality as P1. It is the
       only ordinary-record shape that **agrees with the one padding sentence the corpus has already
       ruled** — §5.11:2199's named typed refusal — so it is the only one that leaves one scheme rather
       than two. *Wire-decidable:* as P1, and it additionally makes the encoding **canonical**: one
       message has exactly one legal `ct_body`, which is what `body_hash` comparison wants and what
       item 148's byte-identical-republish argument needs.
     - **P3 — u16 prefix, zero fill** (§5.14's written scheme, lifted from `spec-a:2653`, the
       rendezvous deposit — *"padded to exactly 4096 bytes as u16(body_len) ‖ body ‖ zeros"*, the
       corpus's **only** written padding scheme, disagreeing with the landed one by two octets).
       *Wire:* `ct_body` changes on every record. *Octets:* 0 on the wire; **2 lengths climb per rung**
       and the ceiling is 65,534. *Unwritten:* (i) **a u16 cannot express 65,536** — the top rung is
       representable only because the prefix already costs 2, a coincidence, and a rung added above
       breaks it silently; (ii) it puts a **second length-prefix width** inside the record layer beside
       `syntax.WriteOpaqueLP`'s 32 bits, which `codec.go:29` declares is the record layer's one prefix;
       (iii) P1's fill-byte and tail-check silences unmodified; (iv) §5.14's deposit pads to a fixed
       4,096 with no ladder, so the precedent has never had a boundary or a top rung. *Vs rulings:*
       neutral to both. *Wire-decidable:* yes, from the two leading octets.
     - **P4 — ISO/IEC 7816-4:** `body ‖ 0x80 ‖ 0x00*`. *Wire:* the prefix disappears, a delimiter
       appears. *Octets:* the cheapest **framed** shape — 1 octet of overhead, **1 body length climbs
       per rung**, ceiling 65,535, one octet short of the number three documents publish. *Unwritten:*
       (i) **the opener scans backwards for the `0x80`, and the scan is the oracle** — it must be
       constant-time over the whole tail and name no position, and unlike P1 the scan is not optional,
       so this shape silently takes P2's side of the tail argument without stating that it has; (ii) it
       is the only shape whose failure mode is a **timing side channel** rather than a typed refusal,
       so its correctness lives in the instruction count and not in the return value; (iii) the same
       fill-byte silence; (iv) a body of exactly the rung is unrepresentable, a boundary nothing
       states. *Vs rulings:* neutral to both. *Wire-decidable:* yes, but by a **scan** rather than a
       read — O(rung), and its refusal must be indistinguishable in time from its success. That is a
       weaker form of decidability and the form that has historically been got wrong.
     - **P5 — self-framing: no length octets, zeros to the rung, tail refused.** *Wire:* the prefix
       disappears entirely and the body's own encoding delimits it. It is the **only** shape that
       agrees with §5.11:2199, and the shape `connect/mls` already implements for MLS's own content
       (`unmarshalPrivateMessageContent`: read the content arm, read the auth data, *"everything left
       is padding"*, accumulate, refuse). *Octets:* **0 overhead in the rung** — no body length climbs
       a rung anywhere, and the inline ceiling is exactly the 65,536 three documents publish. On paper
       the cheapest shape on the board. *Unwritten:* **one, and it is the whole of the shape, and it is
       item 143's trap exactly.** P5 requires that **every body plaintext be self-delimiting**. No
       document states it, no type enforces it, and nothing in either tree can check it. MASTER §8's record
       table (`master:837`) calls `ct_body` *"the MLS PrivateMessage payload"*; an MLS `PrivateMessage.Ciphertext` is an
       `opaque<V>` field **inside** the struct and the record layer would carry the raw octets, so as
       things stand the ordinary record's body is **not** self-delimiting. And `SealRecord`'s signature
       is `(…, headPlain []byte, bodyPlain []byte, …)` with **no production caller anywhere**, so the
       obligation falls entirely on code that does not exist, held by a sentence in a document. The
       wrong reading is `SealRecord(…, mlsCiphertext)`: it compiles, round-trips against itself, and is
       unopenable by a conforming second implementation, with no error anywhere. *Vs rulings:* neutral
       to both; and it is the only shape needing no scope sentence for the recovery wrap, because it
       already **is** the recovery wrap's ruled scheme. *Wire-decidable:* **no**, and that is
       disqualifying against the question asked — the length is decidable only by a decoder that
       already knows the payload type, and pushing that into `sdk` does not make it decidable, it makes
       it undecidable in the layer that freezes.
     - **P6 — trailing fixed-offset length:** `body ‖ zeros ‖ u32(len)` in the rung's last four octets.
       *Wire:* the same four octets move from the front to the back. *Octets:* rung arithmetic
       **identical to P1**; it buys nothing over P1 on cost. *Unwritten:* (i) the fixed offset makes a
       short buffer a refusal before it is a read, which `unpadBody` already gets for free by refusing
       any buffer that is not exactly the rung, so the advantage is notional; (ii) P1's two silences;
       (iii) an **ordering** drawback nothing states — the length is the last thing in the plaintext,
       so any future path reading a partially-available buffer reads the body before it knows how much
       of it is body; (iv) it contradicts §5.14:2653 and MASTER §7:661, both of which put every length
       in front of what it measures, and would be the only backwards length in the format. *Vs
       rulings:* neutral to both. *Wire-decidable:* yes, in O(1), and the only shape where the length's
       **position** does not depend on the body at all.
     - **P7 — a cleartext `u16 body_len` header field, covered by `AAD_head`.** *Wire:* **the only
       shape that changes `record_bytes` and the only one that breaks the codec** — a layout change in
       `EncodeRecord`/`ParseRecord`, a change to the `AAD_head` preimage, a Spec B column, and a new
       row in the A-8 interop vector file A6 requires. *Octets:* +2 → 4,366 (+0.05%); `AAD_head`
       182 → 184; rung overhead 0, ceiling 65,536. *Unwritten:* **it is disqualified rather than
       costed, and the reason should be written down once so nobody proposes it again**: it hands the
       message server the message's **true length** on every record, which is the single thing the size
       ladder exists to deny. MASTER §9.5:1549 lists *"records are padded into size buckets"* as the
       first mitigation of what the server sees, and §9.5's disclosure list says the server sees
       *"record sizes by bucket"* — by bucket, not by octet. *Vs rulings:* neutral to A1; against M1-6
       neutral in substance but expensive in the same currency, since every head ciphertext moves. It
       moves no KAT constant. *Wire-decidable:* yes — **by everyone, including the message server,
       which is precisely the reason not to rule it.**
     - **P8 — keyed pseudorandom fill,** riding P1/P2/P3's framing:
       `fill = HKDF-Expand(record_key[i], "pad/v1", rung − prefix − len)`. *Wire:* only the fill
       differs. *Octets:* 0, and the same rung arithmetic as its framing. The only shape with a
       **compute** cost: one HKDF-Expand of up to 4,092 octets per record on the seal path and again on
       the open path if the opener re-derives — roughly 128 SHA-256 blocks against the 2 a measured
       56-octet expand (600 ns) costs, paid twice per record. *Unwritten:* **it buys nothing and
       forecloses something.** The fill is inside the AEAD, so the only party who sees it is the holder
       of the key that produced it; meanwhile it forecloses P2's cheap tail check, since there is no
       constant to compare against unless the opener re-derives the whole fill. The one place it would
       buy something is the place it cannot ride — the recovery wrap, whose `ct_body` is cleartext and
       whose reader has no record key by construction. *Vs rulings:* **the only shape on this board
       that is not neutral to a reversal of A1** — under a reversal, two records of two classes at one
       index share `record_key[i]` and therefore share the fill as well as the AEAD nonce, adding a
       plaintext XOR over up to 4 KB of pad to the header forgery item 169 already names. It inherits
       the exposure rather than creating it, but it is the one shape that **widens** the blast radius.
       *Wire-decidable:* as whichever framing it rides.

     **Set 3's recommendation, labelled by its own author as a recommendation:** **P2** — the landed
     `LP32(len) ‖ body ‖ zeros` framing with the zero tail **refused** by an accumulating,
     position-free check, ruled with an explicit **three-class scope sentence**. Three reasons: it is
     the only shape both decidable to a receiver holding the bytes and the key with no payload-type
     knowledge **and** consistent with §5.11:2199, the one padding sentence already normative; it costs
     zero — zero wire octets, `ct_body` unmoved, **zero pinned KAT constants** (the eleven hex values
     at `recordkey_test.go:48–59` are key material upstream of the padder and no test in either tree
     pins a padded body or a `body_hash`), and zero records already sealed; and P5 is genuinely cheaper
     on paper and should be rejected anyway, because its safety rests on *"every body plaintext is
     self-delimiting"*, which nothing states, nothing enforces and the one plausible body does not
     satisfy. **P2 is only a closure if the ruling states five things**, and a ruling that states fewer
     is item 143 again: **(a)** the **scope**, over three body classes and not one — the ordinary record
     body and the two device-wrap bodies pad to 4,096 as an AEAD plaintext, the recovery wrap's
     `ct_body` is `hybrid_ct` to 4,112 raw, keeps its own no-prefix form and is **excluded** *(item
     **177** disputes this clause)*; **(b)** the **fill octet is zero**, in a document and not only in
     `m1w1repairs_test.go:765`; **(c)** the refusal **accumulates over the whole tail and names no
     position**; **(d)** the real inline ceiling is **65,532**, not the *"64 KiB"* three documents
     publish — either amend those three or rule the four lost lengths acceptable, but do not leave the
     number wrong in three places; **(e)** it **overturns a written argument** at `seal.go:538` and the
     ruling should say why. And finally: **rule `M1-7` in one sitting with the signature question. They
     are not separable** — if the signature covers only `hybrid_ct` the wrap's pad is attributable to
     nobody, and if it covers the padded plaintext the fill becomes signed and every republisher of an
     interrupted fan-out must emit byte-identical fill, which is item 148's constraint arriving on the
     wrap. *(Item **180** confirms the non-separability by a second route.)*

     **THE SETS' OWN OPEN PROBLEMS, KEPT BECAUSE FOUR OF THEM BLOCK TASK 14 INDEPENDENTLY OF EVERY
     SHAPE ABOVE.** (1) **The device wrap's `ct_head` ladder is contradictory as written**: §5.3
     (A-20, M1-6) sends every head to a ladder rooted at `ClassKeys.Durable`, which descends from
     `storage_root[k]` — the value the wrap delivers — while §5.11 (1) says the head is derived
     *"beneath [`env_key`] exactly as §5.3 declares"*; the only non-circular reading is that
     `env_key[k]` replaces the head's class key too, and **no sentence says so** (query reproduced in
     §7). (2) **Neither device-wrap record can be sealed by the shipped code at all**:
     `seal.go:119` and `:387` refuse every non-DURABLE class, under a file comment naming M1-6 rather
     than item **152**. (3) **A wrap's `ct_head` PLAINTEXT is unstated** for the device wrap and
     filed-but-unstated for the recovery wrap, and **every octet figure in the corpus, including this
     item's, assumes a 96-octet `ct_head`** that no document defines. (4) **`u8(target_type)` and
     `u8(payload_type)` need code points under EVERY shape**, because MASTER §7's nine-element `info`
     names them unconditionally and `wrap_key` is underivable without them — a ruling that answers the
     field list and not the encoding leaves the KEM key undefined. (5) **§7.1 requires an `alg_id`
     inside the signed bytes of every signature and the device wrap has nowhere to put one**: the
     `RecoveryTag` carries `u16(alg_id)` and the `WrapTag` carries none, so under every shape the
     device wrap's body signature has no `alg_id` anywhere unless the body carries one or the preimage
     supplies one that is never transmitted — a field-list consequence not in `M1-1`'s own list.
     (6) **`aead_ct` has no stated AAD**: MASTER §7 fixes `wrap_key ‖ wrap_nonce` and names no AAD, so
     every shape that puts the signature inside `aead_ct` inherits whatever that turns out to be.
     (7) **The recovery wrap's signature is unverifiable by its only intended reader, and the chain is
     circular**: Spec B (`:2605`) routes a seed-only restorer to the epoch snapshot, which is sealed
     under `HKDF-Expand(storage_root[n], "snap/v1", 56)` — the value the recovery wrap delivers. Two
     exits, both rulings: carry `LP(identity_pub)` and anchor it in the KT log, or state that *"MUST
     NOT honour"* permits opening first. The snapshot is itself unsigned, so the anchor at the end of
     that chain is not a signature either. (8) **Nothing in `connect/messagegroup` can sign or verify
     anything**, and Task 14's Consumes list is short by both halves of the signature. (9) **§5.11 (2)
     requires a record the shipped sealer cannot build** — a `ct_body` that is not an AEAD output —
     so Task 19 needs a second builder that bypasses the record body AEAD. (10) **Four padding schemes
     exist across the corpus and no two agree**: `seal.go:512`, `msgrepo/harness/seal.go:129` (no
     prefix, fill `byte(index*31)`, to 4,112, never unpadded), §5.11:2199 and §5.14:2653.
     (11) **`ct_head` is not padded at all**, so `octet_length(ct_head)` is exact and in the clear on
     every record while `ct_body` is bucketed — whether `M1-7`'s scope reaches the head is not asked by
     the item and is the adjacent leak. (12) **Item 148 is the other half of the fill question and is
     not ruled.**

     *Blocks:* nothing of its own — it files options, not obligations. m1 **Task 14** remains blocked
     on `M1-1`'s remainder, on `M1-7` and on item **152**. Found 2026-09-09, composing the three
     independently produced option sets against each other.

176. **CLOSED 2026-09-09 BY THE OWNER'S `C3` RULING — the repair was adopted verbatim.
     `LP(wrap_envelope)` is in the signature preimage, ahead of `LP(ct_xwing)`, in MASTER §7 and Spec
     A §5.11 (6). The item is kept whole because the reasoning below — why three independent analyses
     missed it, and why no round-trip test could have — is the reason the ruling took the repair, and
     is worth more than the shape.** *(One figure of this item's own is what the ruling as transmitted
     got wrong and what the documents therefore do not carry: `C3` takes `W1`'s **four** fields, so
     the preimage is this item's **1,320** and not its 1,324. And this item's measurement predates
     `LP(identity_pub)`: whether that field joins the preimage's `LP(payload)` term — which would make
     it 1,356 — is settled by no document and is filed in Spec A §5.11 (6).)*

     **S1's SIGNATURE PREIMAGE AND W1's FIELD LIST DO NOT OVERLAP: THE COMPOSITE SIGNS EVERY OCTET
     OF THE WRAP EXCEPT THE ONES THE FIELD-LIST RULING EXISTS TO ADD. FILED, NOT RULED. THE REPAIR IS
     ONE TERM, ZERO BODY OCTETS AND ZERO WIRE OCTETS.**

     **The claim.** Set 1 recommends `u8(wrap_format_version) ‖ u8(target_type) ‖ u8(payload_type) ‖
     u64(content_epoch) ‖ u32(publisher_leaf_index)` **outside** `hybrid_ct`. Set 2 recommends a
     signature **inside** `aead_ct` whose preimage ends `‖ LP(ct_xwing) ‖ LP(payload)`. Between the
     two lies `hybrid_ct`'s own framing, so the preimage cannot reach backwards past `ct_xwing` to
     the envelope. Composed, the wrap's body signature covers the record header, the KEM transcript
     and the secret, and **none of the fifteen octets the field-list ruling adds.**

     **Measured rather than argued.** The preimage is **1,305** octets for a 32-octet secret, of which
     the header block — label through `LP(H(server_attachment))` — is **145**. Adding
     `LP(wrap_envelope)` ahead of `LP(ct_xwing)` makes it **1,324** with set 1's five fields, or
     **1,320** with W1's four. The body does not move: 1,257 octets either way, occupancy 1,261 of the
     4,096 rung, tail 2,835. `ct_body` stays 4,112 and the records stay 4,398 and 4,428.

     **Why no test would catch it.** Every property Task 14 states is a round trip: seal, submit,
     fetch, open, compare. A signature that omits a field round-trips perfectly, because the sealer
     and the opener agree about a field neither of them is asked to defend. The defect is only
     visible to a party that *changes* the field, which is the party no round trip has.

     **What it costs if it is not repaired**, precisely and not rhetorically. Three of the four W1
     fields are re-bound by `wrap_key`'s HKDF `info` (item **178**), so a lie about them fails the
     AEAD open. The fourth, `u32(publisher_leaf_index)`, is bound by nothing at all on the recovery
     wrap and by a group-wide key on the device wrap (item **179**). So the unrepaired composite is
     not immediately exploitable — it is *accidentally* safe, by a binding neither set names, on
     three fields out of four. **That is the item-143 failure mode stated in one sentence: safety
     resting on a rule nobody wrote.**

     *Blocked:* nothing mechanically — no wrap has ever been sealed. It blocked a **closure**: a
     ruling that takes both recommendations without this term has ruled a field list that nothing
     authenticates. Found 2026-09-09, composing the three option sets. **Ruled the same day, with the
     term in it.**

177. **CLOSED 2026-09-09 BY THE OWNER'S `C3` RULING — the corpus ends with ONE wrap-body grammar.
     `P2`'s `LP32` prefix and its accumulating, position-free tail refusal reach all three wrap
     bodies, the recovery wrap included, which is this item's own repair taken verbatim: four octets
     of a 2,755-octet tail and zero on the wire.** The arithmetic half was already settled by
     measurement in item 175 §1 — the recovery wrap's denominator is **4,112** and set 1 was 20 octets
     low on every recovery-wrap figure it published. The substantive half is what the ruling decided,
     and it decided it the way this item argued: a parser no longer needs the server attachment's kind
     to know whether the body's first four octets are a length. **Spec A §5.11 (2) is amended rather
     than annotated**, because *"the recovery wrap's `ct_body` **is** `hybrid_ct`, followed by zeros"*
     is now false in two places. The item is kept whole.

     **THE THREE OPTION SETS PUBLISH THREE DIFFERENT DENOMINATORS FOR ONE BODY. THE DISAGREEMENT IS
     `padBody`'s LENGTH PREFIX, AND WHAT IT ACTUALLY DECIDES IS WHETHER THE CORPUS ENDS WITH ONE
     WRAP-BODY GRAMMAR OR TWO. FILED, NOT RULED.**

     **The three answers.** For the recovery wrap's body, set 1 prices every shape against **4,092**
     octets — the 4,096 rung less `padBody`'s four-octet LP32. Sets 2 and 3 price it against
     **4,112** — the raw `ct_body`, because Spec A §5.11 (2) makes that record's `ct_body` the wrap
     body itself, under no record AEAD, with no prefix and no 16-octet tag to subtract. Sets 2 and 3
     are right and set 1 is **20 octets low on every recovery-wrap figure it publishes**: its 2,786,
     2,785, 2,777 and 2,775 are 2,806, 2,805, 2,797 and 2,795. Measured: the W0 recovery body is
     1,306 of 4,112, tail **2,806**; W1 is 1,317, tail **2,795**; W1+W5 is 1,321, tail **2,791**.

     **And a fourth figure, inside set 3, disagrees with set 3.** Its cross-reference paragraph prices
     a signed device wrap as leaving *"2,854 of a 4,096 rung as pad"*, which is `4,096 − 1,242` with
     the prefix dropped — while its own P1 shape states, correctly and four paragraphs earlier, that
     `bucketForBody` *"picks the rung from `len(body) + 4`"*. Sets 1 and 2 both say **2,850**, and
     2,850 is what `padBody` produces: occupancy is `4 + 1,242 = 1,246`. Set 2 is the only set that
     is right about both bodies — it states the device wrap's free space as **2,914 → 2,850** and the
     recovery wrap's zero tail as **2,870 → 2,806**, and both reproduce. Set 1 is right about the
     device wrap and wrong about the recovery wrap; set 3 is right about the recovery wrap (its
     open-problem list gives *"2,806 of 4,112"*) and wrong about the device wrap, in the direction
     that flatters the budget. (A fifth, minor: set 1's W4 line reads *"Recovery wrap 1,251 + 32 =
     1,315"*; the operand is the payload difference, which is 64, and 1,315 is the answer to
     `1,251 + 64`. The arithmetic landed; the operand printed did not.)

     **The disagreement is not about arithmetic, and that is why it is filed.** It is about whether
     the wrap bodies share one framing rule. Set 3's `M1-7` recommendation states the split
     normatively — the ordinary body and the two device-wrap bodies carry `LP32`, the recovery wrap's
     `ct_body` *"keeps its own no-prefix form, and is EXCLUDED"* — and set 1's arithmetic assumes the
     opposite, silently, in every row of every shape. **A ruling that adopts both writes two grammars
     and calls them one.** Under the split, a parser cannot decide whether the body's first four
     octets are a length or `version ‖ target_type ‖ payload_type ‖ …` until it has read the server
     attachment's kind — which is the target-type-dependent body encoding set 1 rejects W6 for, and
     the defect class the kind-`0x0000` ruling was written against.

     **The repair, measured: four octets of a 2,791-octet tail, zero on the wire — prefix the recovery
     wrap too.** It is nearly free under any composite that takes W1, because W1 already amends
     §5.11 (2)'s *"`ct_body` **is** `hybrid_ct`"*, which is the only sentence the exclusion exists to
     keep true.

     *Blocked:* nothing mechanically. It decided which of `M1-1`'s and `M1-7`'s rulings had to be
     written first, and it was the reason they should be written together. Found 2026-09-09. **They
     were ruled together the same day, and this item's repair is in the ruling.**

178. **STILL OPEN AFTER THE 2026-09-09 `C3` RULING, AND THE RULING MAKES IT SHARPER RATHER THAN
     MOOT. The sentence this item asks for was not stated.** `C3` puts `LP(wrap_envelope)` inside the
     signature, so the envelope is now **authenticated** — but the signature lives inside `aead_ct`
     and is unreachable until after the open, while a receiver still derives `wrap_key` **from the
     envelope's own values** in order to attempt that open. So the field is still read before anything
     can verify it, the AEAD open is still the check, and **no sentence in the corpus says a receiver
     may read the field before it trusts it.** Two implementers still diverge, and still only on an
     attacker's record. Spec A §5.11 (6) files this as residual 1 of six. *(One number in this item
     moves with the ruling and is corrected here rather than below: it prices W1's `u64(content_epoch)`
     at **eight** octets, which is the field's own width; the envelope the ruling adopts is **eleven**
     octets and the bound-to-one-candidate benefit is the same.)*

     **THREE AUTHORITIES NAME A WRAP'S PAYLOAD KIND AND THREE NAME ITS CONTENT EPOCH. THE FIELD-LIST
     SET COUNTS TWO AND MISSES THE ONE THAT MAKES THE OTHER TWO SAFE. FILED, NOT RULED — AND THE
     RULING OWES ONE SENTENCE, NOT A MECHANISM.**

     **The claim.** Set 1's W1 says *"two authorities for one fact… `payload_type` in the body and
     `retention_class` in the header both name the secret, and **both are authenticated**"*, and asks
     the ruling to state a refusal on disagreement. There is a **third**, and it is upstream of both:
     MASTER §7's `info` — nine elements since the 2026-09-18 M-15 amendment — binds
     `u8(target_type)`, `u8(payload_type)` **and** `u64(epoch)` into `wrap_key ‖ wrap_nonce` itself.
     The same is true of the content epoch: `header.Epoch`, W1's `u64(content_epoch)`, and `info`'s
     `u64(epoch)`.

     **Why the third one changes the answer rather than lengthening the list.** A value bound inside
     a key is a value the key's holder tests for, and an AEAD is the test — item **142** already
     states that rule, in those terms, and builds the recovery wrap's whole epoch-recovery procedure
     on it. So a receiver that derives `wrap_key` **from the envelope's own values** and finds that
     `aead_ct` does not open has already detected the disagreement, fail-closed, at the price of one
     AEAD open. **The envelope does not need to be authenticated to be safe to read; it needs to be
     read as a hint that the open confirms.** That is a cheaper ruling than the refusal set 1 asks
     for, and it is a different one: a refusal compares two carried values, and this compares one
     carried value against a key derivation. **m1 Task 14 already states the binding as a property it
     will test** — Property 4, *"the epoch is bound. A wrap for epoch n+1 does not open as a wrap for
     epoch n"* — so the mechanism is not only normative, it is on the task's own list; what is missing
     is the sentence saying a receiver may therefore read the field before it trusts it.

     **The half this does NOT cover, so nobody reads it as covering the whole.** `u32(publisher_leaf_index)`
     is in no `info` (item **179**). `header.RetentionClass` is not in `info` either — it is bound by
     `AAD_body` on a device wrap, measured 96 octets and carrying the retention wire byte, and by
     nothing on a recovery wrap. So the ruling still owes a sentence about the header-versus-body
     disagreement; what it does not owe is a mechanism, because for three fields out of four the
     mechanism already exists and is already normative.

     **One benefit nobody claimed, and it is the composite's best property.** Item **142**'s stranded
     recovery wrap is recovered by a restorer walking candidate content epochs **downward** from the
     record's own `epoch` field, decapsulating once per record and testing each candidate by AEAD —
     a walk with no stated bound. W1's `u64(content_epoch)`, read as a hint, **bounds that walk to one
     candidate**, and a lie costs exactly one failed open. Eight octets, zero on the wire, against an
     unbounded walk. Set 2 records that S1 makes each unopenable record *"also cannot be classified"*;
     W1's eight octets are what classify it, and neither set connects the two.

     *Blocks:* nothing. It is a sentence the ruling owes and an argument that makes the sentence
     cheap. Found 2026-09-09.

179. **CLOSED 2026-09-09 BY THE OWNER'S `C3` RULING — this item's conclusion taken whole.**
     `u32(publisher_leaf_index)` is **dropped** and `LP(identity_pub)` is **carried inside
     `aead_ct`**, which is exactly *"the composite therefore needs `LP(identity_pub)` and does not
     need W5"*. The measurement in this item's last paragraph — device body **1,293** of the 4,096
     rung, tail **2,803**; recovery `ct_body` **1,357** of 4,112, tail **2,755**; zero octets on the
     wire, records still 4,398 and 4,428 — **is the ruling's own sizing** and is what Spec A §5.11 (6)
     and MASTER §8.2 now publish. **One half is carried forward rather than closed and is filed in
     §5.11 (6) as residual 3:** a carried key is one the wrap's own sealer chose, so it is an anchor
     only once it is anchored in the KT log, and the ruling does not say that. The item is kept whole.

     **`u32(publisher_leaf_index)` AND `LP(identity_pub)` ARE NOT SUBSTITUTES, AND THE SET THAT
     RECOMMENDS THE FIRST CLAIMS THE SECOND'S PROPERTY FOR IT. FILED, NOT RULED.**

     **The claim.** Set 1 recommends W5 and calls it *"the only candidate field that makes the
     signature checkable from `record_bytes` alone, which is what 'a client MUST NOT honour an
     unverified wrap' has to mean operationally."* Set 2 recommends `LP(identity_pub)` beside the
     signature inside the payload, and states that without it a recovery wrap's signature *"is
     unverifiable by the only party it exists for."* Both are recommended into one body and they are
     doing different jobs.

     **What W5 actually buys.** `sender_handle` is already in `record_bytes`, raw, in the clear, at a
     fixed offset — `connect/message/codec.go` writes it third, after the format version and the
     group id. A **member** already holds `group_handle_key`, so it can resolve `sender_handle` to a
     leaf by enumeration; set 1 measures that at **474 µs** over a 1,000-leaf group, 418.5 ns a
     candidate. W5 replaces that walk with a read. It buys **speed**, not decidability, and it buys it
     only for a member.

     **What W5 does not buy, and cannot.** For the recovery wrap's only intended reader it is inert.
     A seed-only restorer holds no MLS state and no `group_handle_key` **by definition** (MASTER §8.2,
     §5.4), so it can resolve neither a `sender_handle` nor a bare leaf index to an identity key: the
     index names a position in a tree it does not have. **Only a carried key closes that**, which is
     set 2's field and not set 1's, and it must be carried where a restorer can reach it — inside
     `aead_ct`, which it opens, and not in the cleartext body, which the message server also reads.

     **And W5 has a cost the composite does not otherwise have.** On the recovery wrap its four octets
     are in the clear at a fixed offset on ~500 records per epoch. The marginal leak is **the leaf's
     position in the ratchet tree**, and it should be stated that precisely rather than as "a real
     leak": `sender_handle` is already a stable per-leaf pseudonym the server sees on every record, so
     W5 adds no new correlation — it converts a pseudonym into an index, which discloses tree
     position and therefore group shape. Small, real, and absent from the device wrap.

     **The composite therefore needs `LP(identity_pub)` and does not need W5.** Measured: dropping W5
     and adding `LP(identity_pub)` inside `aead_ct` gives a device body of **1,293** of the 4,096
     rung, tail **2,803**, and a recovery `ct_body` of **1,357** of 4,112, tail **2,755** — zero
     octets on the wire in both cases, records still 4,398 and 4,428.

     *Blocked:* nothing. It decided one field of `M1-1`'s remainder and it is the field the recovery
     wrap's verification depends on. Found 2026-09-09, **and ruled the same day, its way.**

180. **HALF CLOSED 2026-09-09 BY THE OWNER'S `C3` RULING, AND THE HALF THAT CLOSED IS THE ONE THIS
     ITEM ASKED FOR: `M1-1` and `M1-7` were ruled in ONE SITTING**, which is what set 3 asked and what
     the other two sets' recommendations assumed unnecessary. **The two-rules half closes by
     construction**: under `P2` over all three wrap bodies every wrap class computes `u8(size_bucket)`
     from `len(body) + 4` under one rule, so the *"two wrap classes compute that byte under two
     different rules"* condition no longer exists. **What does NOT close, and is now an obligation on
     m1 Task 14 rather than a disagreement between option sets:** the **ordering obligation** — the
     bucket must be chosen from the **post-signature, post-envelope** body length, because the bucket
     is inside the preimage — and its **silent failure mode**, a body within 64 octets of a rung
     boundary that signs one bucket and pads into another and still round-trips against its own
     sealer. Still not reachable, and re-measured against the ruled shape rather than the composed
     one: the ruled bodies are **1,293** and **1,357**, and both land on rung 2 whichever length the
     bucket is taken from. The item is kept whole.

     **`u8(size_bucket)` IS INSIDE THE PROPOSED SIGNATURE, SO THE PADDING RULE IS AN INPUT TO THE
     SIGNATURE AND `M1-7` IS NOT SEPARABLE FROM `M1-1`'s SIGNATURE QUESTION. TWO OF THE THREE SETS
     SAY IT IS. FILED, NOT RULED — AND IT IS NOT REACHABLE TODAY, WHICH IS THE POINT.**

     **The disagreement, quoted.** Set 3: *"rule `M1-7` in one sitting with `M1-1`'s second remaining
     question, where the wrap signature sits and which octets it covers. They are not separable."*
     Set 2: *"Under S1, S4 and S5 the two stay independent."* Set 1 lists the padding scheme as a
     third, separate question throughout.

     **The composition settles it, and by a route none of the three took.** S1's preimage carries
     `u8(size_bucket)`. The size bucket is chosen by `bucketForBody`
     (`connect/messagegroup/seal.go:485`) from `len(body) + lpPrefixBytes`, and `lpPrefixBytes` is
     **4**, derived from the writer rather than written down (`seal.go:467`, `:470`) precisely so a
     change to the record layer's prefix moves it. So the padding rule's prefix width is an input to a
     **signed** byte. Under set 3's own scope sentence the two wrap classes compute that byte under
     two different rules — `len + 4` for the device wraps, `len` for the recovery wrap — and nothing
     says the preimage's `u8(size_bucket)` is derived per class.

     **Two consequences a builder meets and no document states.**

     - **An ordering obligation.** The bucket must be chosen from the **post-signature** body length,
       because the bucket is inside the preimage. The natural implementation order — build the body,
       sign it, pad it, pick the rung — computes the bucket from a body 64 octets shorter than the one
       it pads, and agrees with the correct order only when both lengths fall in the same rung.
     - **A silent failure mode.** A body within 64 octets of a rung boundary signs one bucket and pads
       into another. The record still round-trips against its own sealer, because the sealer used the
       same wrong byte twice.

     **Not reachable today, measured: 1,257 and 1,321 both land on rung 2 under either rule**, and no
     wrap has ever been sealed — `connect/messagegroup/wrap.go` does not exist,
     `grep -rn 'wrap_body|WrapBody|wrapBody'` over both trees returns **0**, and `SealRecord` has no
     production caller in `connect`, `msgrepo` or `sdk`. **That is what makes it worth a number rather
     than a footnote.** It is item 143's shape exactly — a discipline that holds by arithmetic
     coincidence, in a constructor that makes the wrong reading the obvious one — filed while it costs
     one sentence, before the A6 wire-format freeze makes it a flag day.

     **The second half of the same non-separability, from the other direction.** S1's signature covers
     neither the pad nor the zero tail. On a device wrap the tail sits inside the record body AEAD
     under `env_key[k]`, which **every member of the epoch holds**, so any member can rewrite any
     other member's wrap tail without disturbing the signature. `connect/mls` refuses exactly this
     one layer in and says why (`mls/framing_protect.go:817`). If `M1-7` is ruled P1 — the landed
     shape, whose `unpadBody` deliberately does not check the tail (`seal.go:538-542`) — the composite
     ships a ~2.8 KB member-writable covert channel inside every wrap that no signature covers.
     **P2's accumulating, position-free tail refusal is therefore a dependency of S1 and not an
     independent ruling.**

     *Blocks:* nothing mechanically. It says the two questions must be ruled in one sitting, which is
     what set 3 asked for and what the other two sets' recommendations assume is unnecessary. Found
     2026-09-09.


## 6. Change process

Every change to a spec or plan follows this, without exception:

1. Make the edit.
2. **A subagent reviews the diff** — not the whole document. A diff review catches "§7 changed and
   §5.2 was not updated," which is the exact class of regression that hit revisions 3 and 5.
3. Fix what the review finds.
4. Commit, with the ledger entry in the same commit.
5. Append to the edit log below.

Prefer surgical edits over full rewrites. Two regressions in this project came from rewriting a whole
document and reintroducing a defect that had already been fixed once.

## 7. Edit log

Append-only. Newest last. One entry per commit that changes a spec or plan.

---

### 2026-08-12 — Repository established

**Change:** Forked `urnetwork/message-server` to `Ryanmello07/urnetwork-message-server`. Added
`SPEC-LEDGER.md`, `docs/plans/README.md`, the revision-5 protocol design, the three review verdicts,
and the original protocol research notes.

**Why:** Decisions had been accumulating in conversation with no durable record, and the reviews that
justify half of them lived in temporary files.

**Reviewed by:** subagent diff review, 13 findings — 3 BLOCKER, 4 MAJOR, 6 MINOR. All applied.

Notable: the review caught that spec §14 still named `mls-go` as the slice-1 oracle after revision 5
replaced it with OpenMLS everywhere else — exactly the "§X changed, §Y did not" regression the §6
process exists to catch, on the first commit it ran against. It also found that three decisions the
ledger recorded as locked (P2 "a DM is a 2-member group", I6 seed-loss identity reset, and the owner
succession quorum) were not actually stated in the normative spec. Spec §5.5, §6 and §11 were amended
rather than the ledger weakened, since the decisions were real and the spec was the incomplete one.

**Notes:** Upstream was empty and could not be forked until seeded with the MPL-2.0 license from
`urnetwork/android`. `upstream` remote is wired for later syncing.

---

### 2026-08-12 — Three component specs drafted; MASTER errata E1–E3 fixed

**Change:** Added specs A (protocol/sdk/connect, 2,048 lines), B (message-server/operator, 1,377) and
C (Windows client UI, 1,089), each with its own planning ledger. Added decisions C6, C7 and T9–T13.
Fixed three defects in the MASTER protocol design that writing the implementation specs exposed.

**Why:** The component specs are handed to separate teams. Writing them forced a level of concreteness
prose review had not, which is what surfaced the MASTER errata.

**MASTER errata fixed in this commit:**

- **E1 — seed-only restore did not work at all.** The recovery wrap carried `pq_secret` and
  `archive_secret`, but `storage_root = HKDF-Extract(mls_secret, pq_secret)` needs `mls_secret` from
  `MLS-Exporter`, which requires live MLS epoch state a seed-only restorer does not have by
  definition. It could derive no class key and open nothing. The recovery wrap now carries
  `storage_root[n]` directly; §8.2 records why this weakens no adversary class.
- **E2 — a commit would have emitted ~150 MB.** The per-epoch ratchet-tree snapshot (~300 KB at 500
  members) was specified inside every member's wrap. It is now one `PERMANENT` record per epoch under
  `K_snapshot[n]`. Realistic commit size is ~2.1 MB, which §8.2 now states so spec B can plan for it.
- **E3 — the X-Wing derivation was not X-Wing.** §5.2 derived 96 bytes and used them directly as the
  key; the draft takes a **32-byte seed** and expands it internally with SHAKE-256. The 96-byte form
  belongs to an older draft. Using it forfeits the security proof that is the entire reason for
  choosing X-Wing. Now 32 bytes.

**Reviewed by:** two subagent passes. **Both had a coverage failure caused by input truncation, and
the specs are NOT yet ready to hand to teams.**

- Pass 1 bundled all three specs inline and capped at 120,000 chars against ~300,000 of content.
  Spec B was cut mid-sentence and Spec C never reached the reviewers.
- Pass 2 fixed that by having reviewers read from disk, and produced 148 findings. But its
  *consolidator* input was capped at 45,000 chars, so the consolidated document at
  `docs/reviews/2026-08-12-r4-three-spec-review.md` merges only ~47 of them and states — wrongly —
  that Spec C was never reviewed. Spec C **was** reviewed and produced 22 findings.
- The complete set is at `docs/reviews/2026-08-12-r4-findings-full.json`: **148 findings, 41
  blockers** — B: 54, CROSS: 69, C: 22, MASTER: 2, A: 1. **Treat the JSON as authoritative and the
  consolidated markdown as partial.**

**Process lesson, recorded because it recurred:** truncating review input silently produces a review
that looks complete and is not. Both failures were mine, one stage apart. Reviewers must read source
from disk, and consolidation must either take the full finding set or be run per-spec.

**Outstanding:** 41 blockers. Spec B cannot bootstrap a group (B-1), has **no authenticator on the
read path** so any `ByJwt` holder who learns a `group_id` reads the entire group (B-3), and has
nowhere to store the epoch bundle that dominates its own storage budget. Spec C's update path
requires elevation the app does not have, and its screen inventory has no pending-invite flow
although Spec A's group model is invite-based. These must land before any handoff.

---

### 2026-08-12 — R4 and R5 edit passes: 41 blockers to 0

**Change:** Two passes, 177 edits total, across MASTER and specs A/B/C. R4 applied 89 (blockers
41 → 7); R5 converged the remainder (7 → 0) and stripped 31 leaked plan labels.

**Why:** The specs are handed to separate teams. A blocker that survives handoff becomes a team
building the wrong thing for a week.

**Method:** findings resolved into a per-document edit plan, then applied by one agent per document
so the two halves of a cross-cutting fix could not diverge, then verified by readers who had not
seen the plan. Everything read from disk; nothing passed inline.

**Substantive decisions taken during the fix:**

- **Reads are authenticated under a separate `read_key`**, not `write_key`. `read_key =
  HKDF-Expand(storage_root[0], "read/v1", 32)` — fixed at group creation, carried in
  `EpochAttachment`, **never retired**. `write_key` keeps its current-epoch-plus-60s rule for
  `write_auth` only. The alternative failed on a subtlety worth recording: every route *out* of a
  stale epoch is itself a read, so any finite retention window for a read key leaves permanent
  lockout.
- **Contact blocking cut from Spec C.** It was not in the agreed v1 scope, Spec A defined no calls
  for it, and its "and your other devices" copy needed a sync carrier nobody had scoped.
- `blob_id` moved into the record header and both authenticator preimages — the server cannot derive
  it, because it is key-derived by design.
- One sentinel for indefinite durable retention: wire `0` ⇒ column `NULL` ⇒ infinity, mapped at one
  site. Two incompatible ones had been introduced side by side.
- The Windows client gets its own **perUser** MSI, which resolves the multi-user hole and the
  elevation contradiction together — the previous perMachine install needed elevation the app is
  explicitly designed not to have.
- **The epoch bundle is ~6.9 MB, not the ~2.1 MB previously recorded**, over ~55 round trips. The
  earlier figure was wrong and Spec B had been planning storage against it.

**Reviewed by:** three verifiers reading all four documents from disk. Result: **0 blockers, 0 leaked
labels** (independently re-grepped), 8 majors and 22 minors remaining.

**Process note:** the earlier instruction to copy shared blocks "verbatim" was correct in intent but
the blocks were not self-contained — they carried the plan's own `BLOCK-xx` and `X-nn`
cross-references, and 31 of them shipped into the documents. The rule now is that replacement text
must read correctly to someone who has never seen the plan, and each applier greps its own file
before finishing.

### 2026-08-25 — First implementation feedback: four defects, three of them compile errors

`connect/protocol/message.proto` was transcribed from Spec B §4.2–§4.6 and compiled for the first
time. Compiling a spec is a different act from reviewing one, and it found four things that five
review rounds did not.

**Two of the four made the specs literally uncompilable.**

- **The `MessageType` enum values collided with the message names.** Both specs named four enum values
  `MessageServerRequest`/`Response`/`Push`/`Fragment` — the same names as four messages in the same
  `package bringyour`. proto3 scopes an enum *value* name to the enum's **parent** scope, so both
  claim `bringyour.MessageServerRequest` and `protoc` refuses the pair. Resolved on the enum side,
  because the message names are the `oneof` arm types Spec A §5.7's op byte is defined over; the
  convention is the one `MessageType` already uses against `ip.proto` (`IpIpPing` for `message
  IpPing`). **The four numbers are unchanged.**
- **`UnsubscribeRequest` was referenced but never declared.** Bound as arm 15, its `req_auth`
  exemption stated in two places, and defined nowhere — so the arm had no type.

The other two were a miscount ("Three additions" above a block of four) and an annotation naming a
field, `retry_after_ms`, that existed nowhere.

**The finding worth keeping is not any of the four.** It is what the diff review of the *fix* found:
the fix's own reasoning contained a false generalisation. Resolving the `retry_after_ms` gap, the
edit argued that response fields are safe to add late because *"a response field is never a MAC
input"*. That is false, and the counterexample is in Spec B: `FetchAttestation` is an Ed25519
signature over nine `FetchResponse` fields, and MASTER §9.4 requires client and server to agree on
that preimage byte for byte. The narrow conclusion survived — the attestation preimage is an explicit
named field list and the new envelope field is not on it — but the rule as stated would have licensed
exactly the change the attestation exists to prevent. It is corrected in place rather than deleted,
because the corrected version teaches something the deleted version would not.

A second claim in the same fix was also wrong: that "unsubscribe from everything" was already
expressible as `SubscribeRequest{subscriptions: [], replace: true}`. With an empty subscription list
there is no `group_id` in the request, so there is no `read_key` to MAC under and none for §5.1.1 to
look up — the request is not well formed. The empty-list-is-a-no-op ruling stands on its own merit
(the most destructive outcome should not be what a client gets by forgetting to populate a repeated
field), but it now carries an explicit `bool all` rather than a justification that was not true.

**Process note.** The four defects were found by an implementer, and the two wrong claims by a
reviewer reading only the diff. Neither would have been found by re-reading the specs, which is what
the previous five rounds did. **Transcribe-and-compile is now part of the change process for any
section that defines a wire format** — §6 already required a subagent diff review; this adds that a
spec section containing a `proto` block is not done until that block has been through `protoc`.
### 2026-08-25 — Second implementation feedback: the record codec, and a published surface that was not

`connect/message`'s record codec landed and was reviewed against the specs. Three findings, all of
them the same shape as the `protoc` round before it: the specs are wrong in ways only writing the code
against them shows.

**`RetentionClassWire`'s signature was uncompilable, not merely inconvenient.** Spec A §12.1 and Spec B
§12.1 both published `func RetentionClassWire(c RetentionClass, ephBucket uint8) byte`. The
implementation returns `(byte, error)`, and that is not a style preference: the function is one of the
two places in the system where the retention class and the eph bucket are joined, and it has two things
to refuse — a non-eph class arriving with a bucket, and a bucket past 5. **A function that cannot refuse
has to normalise.** Dropping the bucket silently reclassifies a record the caller believed was
something else; truncating it manufactures `0x16`, which no reader accepts. Both are the silent
mis-storage the split exists to prevent. MASTER §8 gives no Go signature, so it did not settle it. It is
settled now in both §12.1 blocks, as A-8 and B-8, and it is an **arity** change: Spec B's server does
not compile against the old spelling, which is the good failure mode.

**The published surface named no errors, and the package exports nine.** Spec A §5.9 guardrail 7 already
required every failure in `connect/message` to be a typed error. §12.1 then published functions and types
and no error names — so the allowlist test the same section describes would have rejected the sentinels
the guardrail requires, and Spec B's check 3, which acts on two of them, had nothing to match on but
message text. The nine names are now on the surface in both blocks. The implementation was right and the
contract was incomplete; the codec's own comment claiming it added no exports was also corrected, since
it was true of one file and false of the package.

**MASTER §8 disagreed with Spec B §4.3.3 about `record_id`.** §8's `RECORD` block opened with `record_id`
among fourteen fields that are all inside `record_bytes`; Spec B carries it as a sibling protobuf field.
Under the MASTER-wins rule that is a conflict a reader resolves the wrong way, and a codec built from §8
alone disagrees with the shipped one on every record. Resolved toward Spec B, because §8's own annotation
settles it: an id assigned after acceptance is assigned after `write_auth` is computed, so an id inside
those bytes is a value the MAC covers, which is what "NEVER authenticated" denies. §8 now says it in
place. Recorded as an amendment to revision 9 rather than a revision 10, because no rule changed and
three documents name revision 9 as their normative parent.

**Process note, extending the one above.** The previous round added transcribe-and-compile for any
section with a `proto` block. This round found the same class of defect in a section with a **Go**
block, and by the same means: `§12.1`'s surface was never compiled against, so an arity that could not
work sat in two documents through six review rounds. **A spec section that publishes a Go signature is
not done until something compiles against it.** The three findings here were all found by the
implementation or by a review of it; none was found by reading the specs again.

### 2026-08-25 — Third implementation feedback: the two record AAD preimages

`connect/message`'s `aad.go` landed and was reviewed. Two findings for the specs, and both are things
the documents left to be inferred rather than things they got wrong.

**Nothing said which `alg_id` a record's AADs carry.** MASTER §7.1 puts the algorithm identifier inside
the authenticated bytes precisely so it cannot be stripped or downgraded, and §8 writes `u16(alg_id)`
into both AAD blocks — but no line in MASTER, Spec A or Spec B binds those two fields to a value, and
both preimage builders take it as a parameter. That is the worst shape a divergence can have: two
implementations that each read this document and chose differently agree on the format, agree on the
keys, and fail the AEAD on every record, with no test on either side failing first. §8's own key
derivation settles it — `key_head ‖ nonce_head` is 56 octets, a 32-octet key and a 24-octet nonce, and
a 24-octet nonce is XChaCha20-Poly1305's and no other v1 suite's — so the answer was always `0x0021`,
and §8 now says so instead of leaving it to be inferred from a nonce length. Recorded as an amendment
to revision 9, not a revision 10: no rule changed. Found before the sealer that would have had to
choose.

**"Nine names, no more" was read as a rule about the count.** Spec A §12.1 A-8 published the nine `Err*`
sentinels and added that a tenth is "a design discussion like any other addition here". The AAD builders
then produced two refusals of their own — a nil header, and an attachment argument that disagrees with
the header's own field — and the implementation kept them off §12.1 and wrote the reasoning into the
package instead, which is a self-granted exemption from a normative sentence. The reasoning was right
and the place was wrong. §12.1 is the allowlist of what the message server may **reach**, not an
inventory of what `connect/message` exports, and it never could have been one: the package necessarily
exports the sealing side too, and `AADBody` and `AADHead` build MASTER §8's two record AEAD preimages
and are deliberately on no line of §12.1, because a server that never decrypts never builds either. So
the rule is reachability. A sentinel a published function can return is owed a line in the same commit
that makes it reachable, since a typed error the server cannot name is one it can only match on message
text; a sentinel only an unpublished function can return is not, and publishing it would widen the
server's allowlist with a name no server can use. A-9 and B-9 say that in the two blocks the rule
governs, and they also settle what the message-server allowlist test asserts: the names in the block,
not the package's exported set.

**Process note, a second half to the one above.** A spec section that publishes a Go signature is not
done until something compiles against it. A spec section that publishes a **preimage** is not done
until two implementations agree on every value inside it — because a preimage that round-trips against
itself is exactly the defect that ships, and the `alg_id` here would have done it with both sides
passing their own tests.

### 2026-08-26 — Fourth implementation feedback: the api layer, and an acceptance criterion that could not be met

The message server's api package landed: §5.1's check order, §6.1's submit path through the store, and the first record to travel end to end. One finding for the specs, and it is a contradiction rather than an omission.

**§13 item 8 asserted something no build of this module could satisfy.** Item 8 pinned §5.3's "MUST NOT link an MLS implementation" with `go list -deps ./... | grep connect/mls` being empty. That grep is a prefix match, and `connect/message` — the record parser §2.2 explicitly ALLOWS, and which §5.1 check 7 requires the server to recompute every preimage through — is built on `connect/mls/syntax`, the TLS presentation-language codec. So the first package of the message server that parsed a single record put connect/mls/syntax in the closure and failed item 8, and there was no way to write the api layer that did not. Item 8 now asserts the package and not the prefix, and states why the codec is not an MLS implementation: it is a length-prefix reader and writer with no MLS type, no key schedule and no validation semantic in it, and §5.3's actual hazard — "the moment an MLS parser is in this process, the temptation to 'just validate the commit' becomes a one-line change" — is untouched by a codec that cannot represent a commit. Spec B revision 10.

**What made it cheap to find, and worth recording.** The dependency gate in the message-server repository had predicted this failure in a comment months before it fired, named the two sentences that could not both hold, and said where the resolution belonged: in the spec first, the allow list second, "not in a quiet edit to whichever of the two is easier to change". The failure arrived exactly as described and cost one reading. A gate that explains the failure it is going to produce is worth more than a gate that only produces it.

### 2026-08-26 — Spec B revision 11: the second copy of the rule revision 10 amended

Revision 10 rewrote §13 item 8's no-MLS assertion from the prefix form to the package form, because
the prefix form could not be satisfied by any build of this module that parses a record. §5.3 states
the same assertion beside the normative MUST NOT it belongs to, and it was not updated with it, so
the document asserted the same CI check two incompatible ways for one day. §5.3 now states the
package form and cross-references item 8 for the argument. No normative rule changed: "the message
server binary MUST NOT link an MLS implementation" is untouched, and what moved is the sentence that
says how it is asserted.

**This is §6's own failure mode, and it happened to §6's own process.** The change process on this
page says a subagent reviews the diff rather than the document because a diff review catches "§7
changed and §5.2 was not updated" — and the revision-10 diff touched §13 item 8 and §2.2's allow
list, both of which were reviewed, while the second copy of the same rule two thousand lines away
was not in the diff to be looked at. A rule written down twice is a rule amended once. The cheap
countermeasure is the cross-reference this revision adds: §5.3 now points at item 8 instead of
restating it, so there is one place left to amend. Found by the review of the api layer's gates,
which is the first thing to read the two copies against each other.

### 2026-08-26 — Fifth implementation feedback: the frame transport, and the connection `connect` does not have

The message server's `peer` package landed: §4.2's frame binding, §4.3's request oneof dispatched
into api, §4.3.1's Hello and nonce issuance, §4.6's fragmentation in both directions, and §5.1's
check 1. Five findings, and the first is the one that matters.

**Spec A §5.7's `server_nonce` is "scoped to that connection", and `connect` exposes no connection.**
This was looked for rather than assumed, and this is the whole of what a message server can see about
an arriving frame:

- the receive callback's signature is `func(source TransferPath, frames []*protocol.Frame, peer Peer)`
  (`transfer.go:152`), and `source` is `path.SourceMask()` (`transfer.go:1520`) — `{SourceId,
  StreamId}`, with `StreamId` always zero, because a frame whose path `IsStream()` is dropped eight
  lines earlier. So the arriving identity is the `client_id`, which survives a reconnect unchanged;
- `connect.Peer` is `{ProvideMode, Roles, Principal}` (`transfer.go:140`) — the source's identity from
  the active **contract**, not from the session;
- a `ReceiveSequence` does hold a per-session `sequenceId` (`transfer.go:2629`), and it never reaches a
  callback: it appears only as an *argument* to `ReceiveQueueSize(source, sequenceId)`;
- `EncryptionSessionManager` has a per-peer session lifecycle and an event stream, and
  `EncryptionEvent` is `{PeerId, Type, Reason}` — no session identifier, no closed event, keyed by
  `(peerId, role, companion)` rather than by connection, and `EncryptionModeOff` is a supported
  setting, so a deployment may have no sessions at all.

Keying the nonce by `client_id` alone is therefore the failure §5.7 exists to prevent: a reconnecting
client would keep the nonce it had, and cross-connection replay resistance is the entire point of the
field. **What was adopted: a connection is one `Hello` epoch of a `client_id.`** Every Hello mints a
fresh nonce and destroys the previous one outright — no history, no grace window — so a record sealed
against the old connection stops verifying the instant the new one is issued, which is the direction
§5.7 needs and which spec A §5.7's own outbox rule already assumes on the client side.

**The residual gap is real and belongs in the spec rather than in the code.** A client that reconnects
without saying Hello keeps its nonce, and this server has no way to know: nothing in the list above
changes across a reconnect. So §5.7's guarantee holds against *the client protocol* rather than against
*the transport*, and the honest statements are one of these two — either spec A §5.7 says that a
connection is the interval between two `Hello`s from one `client_id` and that the outbox rule is
therefore normative for the guarantee and not merely for correctness, or `connect` grows a session
identity at the receive callback and §5.7 binds to that. The implementation bounds the window with a
configurable connection idle sweep and declares the bound missing when nobody configures one, which is
a mitigation and not the guarantee.

**§4.5 has no code for "this build does not implement this operation".** Eleven of §4.3's fifteen arms
are served by nothing yet. `REASON_REJECTED` was rejected for them: §4.5 gives it a specific normative
meaning — the three-way merge on the write path, a failed `req_auth` on the read path — and a client
reading it re-MACs and retries, which is the wrong behaviour for an operation that will never exist in
this build. `REASON_INTERNAL` is used and every unserved arm is declared, derived from the compiled
descriptor so a sixteenth arm arrives declared. §4.5 or §4.3 should name the code.

**§4.6 names a reason code for one of its four abort conditions.** `REASON_OVERSIZE` is given for the
reassembly cap. Out-of-order `index`, a `count` of zero, and the sixteen-per-client concurrency cap
have none; `REASON_REJECTED` is used for all three, because `REASON_RATE_LIMITED` would claim the §4.7
limiter that §5.1 check 4 still declares absent.

**§4.3.1 gives a connection no lifetime.** §4.6 expires reassembly state after 30 s. A connection has
no such number anywhere, and without one the live-connection map holds an entry per `client_id` that
ever said Hello and never shrinks — a memory bound chosen by anyone who can address a frame. Also
unstated: what an **empty** `supported_versions` means. It is refused here, on the grounds that a Hello
that names nothing has not negotiated.

**§2.2's allow list does not say whether allowing a package allows its module's requirements.** §2.2
allows `github.com/urnetwork/connect` at its root, and §4.2's binding *is* that package — so the first
import of it put quic-go, the whole of pion, gvisor's netstack and four `golang.org/x` modules into
the binary §2.3 deploys, none of which §2.2 mentions. The gate now derives that allowance from
connect's own `go.mod` rather than from a list of thirty modules, and a named ban still wins over it.
The rule it implements is the one go.mod already states for `google.golang.org/protobuf`: allowing a
package and refusing the runtime it cannot compile without allows a package that cannot be built.
§2.2 should say so once instead of leaving it to be inferred twice.

### 2026-08-26 — Sixth implementation feedback: the §4.6 bounds the spec does not give

A review of the frame transport found that four of §4.6's bounds were arguments rather than bounds —
each could be moved, doubled or deleted with the whole suite green — and that its refusal path was a
denial of service costing an attacker two bytes a frame. The fixes are in `peer`; what belongs to the
spec is below.

**§4.6 bounds one client and nothing bounds the number of clients.** "Capped at 16 concurrent in-flight
reassemblies per client" is the only reassembly bound in spec B, and the `client_id` it is per is
`source.SourceId` as `connect` hands it to the receive callback — which is *before* §5.1 check 2 has
resolved a connection, because check 2 runs inside the api pipeline one stage later. So a `client_id`
that has never said Hello opens reassembly state exactly as readily as one that has, and the cap
multiplies by however many identifiers an attacker cares to name: ten thousand of them were measured
holding ten thousand reassemblies with no refusal at all, which at the default `max_request_bytes` is
an allowance of about 20 GB. This is the memory-exhaustion vector §4.6 is written against, reached
around its cap rather than through it. The implementation now holds `Config.MaxReassemblies` above the
per-client cap, defaulting to 1024 — a count, so that it is comparable with §4.6's own, and one whose
implied byte budget at §4.6's working assumption is 128 MiB. **It is a number this build chose, and it
is declared in `NotBuilt` for that reason:** a conforming client inside every published bound can be
refused by it, and §4.6 gives that client no way to predict the refusal from `Capabilities`. §4.6
should name the bound, or name what a server answers when it has none left. `REASON_REJECTED` is used,
by the same argument as for the per-client cap: `REASON_RATE_LIMITED` would claim the §4.7 limiter
that §5.1 check 4 still declares absent.

**§4.6's `part` size is a rule for the sender and says nothing about the receiver.** "The sender
chooses `part` size as min(peer_advertised_frame_budget, 2048) bytes and MUST NOT exceed the negotiated
budget" is enforced here outbound and deliberately not inbound: a fragment carrying a 100,000-byte
part is accepted as long as the reassembly stays inside `max_request_bytes`, which is the bound §4.6
gives the receiver. The reading is that the budget is negotiated per peer, that this server advertises
none, and that a receiver refusing at its own sender ceiling would refuse conforming senders who
negotiated a larger one. The opposite reading is equally available from the text, which is the
problem: §4.6 should say whether a receiver may refuse a part for its size alone, and with what code.
The position this build takes is now asserted by a test rather than left to be inferred from what
nothing looks at.

**§4.6's abort conditions are a class the spec never enumerates.** The prose names four — a `count` of
zero, an out-of-order `index`, the per-client cap, and `max_request_bytes` — and a conforming
implementation has at least two more that the text implies without stating: a `count` that changes
mid-reassembly, and (per the gap above) whatever bounds the reassembler as a whole. The implementation
now keeps them as a table its own enforcement reads, so the test that claims to cover "every way §4.6
aborts a reassembly" iterates the enforcement instead of a list beside it. The list beside it held four
of five, and the one it omitted could be deleted with the suite green — the fourteenth time on this
project that a class typed out rather than derived has understated itself.

**§4.5 still has no code for a server that is out of a resource it never advertised.** Two refusals in
this build now mean "not now" rather than "not ever": the global reassembly bound above, and a §4.6
refusal dropped rather than queued when the refusal queue is full. Both are `REASON_REJECTED`, which a
client reading §4.5 will treat as a permanent verdict about its request. A `REASON_BUSY` — or a
statement that `REASON_RATE_LIMITED` covers resource exhaustion as well as §4.7's limiter — would let a
client tell "retry" from "do not".

---

### 2026-08-30 — The first `sdk` plan: s1, the messaging surface and its shape

**Change:** Added `docs/plans/2026-08-30-slice2-s1-sdk-surface.md` (2,021 lines, 16 tasks) — the first
plan for Spec A §7, §8 and §9, none of which had one. It declares the whole §7 surface: 212 pinned
declarations, 44 value structs, 16 `*List` wrappers, 21 listener interfaces, three behavioural
handles, the closed vocabularies, and the exportability gate. Added open item 48 above.

**Why:** Every other component of this project has a plan — `docs/plans/` holds p1 through p8 for the
MLS core — and the `sdk`, which is the product surface and the thing Spec C builds against, had none.
The surface is also the one piece that must land in a single wave: §7.8's gate operates over the whole
type graph, and a half-declared graph fails for reasons that look like unrelated breakage.

**Written under three rules taken from this ledger, and this is the part worth keeping.**

*It supplies no test code.* Across p1–p7 the implementers found roughly thirty plan-supplied tests
that could not fail — nine consecutive p1 tasks, three `CheckRoundTrip` tests against a version that
discarded its own comparison, and p6 Task 23's five tests that as a set could not fail against 16 of
26 mutations. Every task in this plan states the property, the refusal that property owes, and a
numbered mutation set the implementer must run two-phase (ledger 12b). The implementer derives the
test.

*Signatures are read from source, never from the plan* (ledger 25), stated at the top and repeated in
the source file the plan creates.

*Every gate derives its class AND its scope* (ledger 21). The plan carries a live instance of the
failure it is written against: the decomposition it was given said the surface has "16 closed
vocabularies", §9.5 rule 7 names seventeen, and measuring against §7's own declarations found **at
least eighteen more**, over 36 distinct value sets. The vocabulary task is therefore written as a
derivation with an explicit *unclassified is a failure* third bucket, and the count is offered only as
evidence that counting is what produced §9.5's seventeen.

**Five things measured rather than assumed**, each of which changed a task:

1. `) *Sub` occurs **zero** times in the existing `sdk` and every `Add*Listener` returns `Sub` by
   value, while §7 spells `*Sub` on all **ten** of its listener declarations (the brief said ~21;
   the measured number is 10). The cgo generator will not catch it: `classify` unwraps the pointer to
   the named `Sub`, which is in `gen.go`'s `behavioralTypes` allowlist, so a pointer-to-interface
   classifies as a handle and the ABI gate passes.
2. An **empty but non-nil** `*List` marshals as `null`, not `[]`, because `exportedList.values` is a
   nil slice — so even a freshly constructed list breaks an nlohmann parse expecting an array. A
   `*List` held as a value marshals as `{}`. Both verified by running, along with the fix: a
   shadowing `MarshalJSON` on each wrapper, because changing `exportedList` itself would alter the
   shipped VPN DLL's JSON.
3. `sdk/dependency_graph_test.go`'s helper `t.Fatal`s on a `go.mod` with no pion lines, so the new
   `sdk/surface` module must require `github.com/urnetwork/sdk` to have any — a trap that would have
   fired the moment the module joined the hardcoded artifact list.
4. §7.8's `TestMessageSurfaceIsExportable` cannot run the generator's walk (it is `package main` in a
   separate module) and would be **weaker** than advertised if it could, because `gen.go:406` returns
   json for any named struct without walking its fields. The plan builds a stronger re-derivation plus
   an AST drift gate, and says so rather than repeating §7.8's sentence.
5. The `sdk` repository has **no** `.github` directory, no `.gitattributes` and no CI of any kind, and
   the root module does not currently build in this workspace at all — `../goidenticons` is absent.
   Both are stated as preconditions rather than discovered by the implementer.

**Positions taken where the spec is silent, labelled as positions and not as readings:**
`MessageSendTicket` declares `Cancel()` and **not** `Await()` (its return type is specified nowhere
and gomobile has no exclusion list, so a blocking `Await` would bind into the AAR and the Apple
framework irreversibly); `GroupListener` has one method, not the second one §7.2 adds in prose;
snake_case JSON tags with no `omitempty`; and `Seq`/`Dropped` are transcribed exactly as §7 declares
them rather than added to the four payloads §9.5 rule 6 claims carry them. Each is recorded in the
plan's Open items with the alternative it rejected.

**Reviewed by:** the author, against source in three repositories rather than against the brief. Four
claims inherited from the decomposition were checked and one was wrong (the `*Sub` count); the other
three — 15 proto request arms with no key-package transport, `extension_types = [0xF001, 0xF002]`, and
`mls.MaxGroupMembers`/`MaxDeviceLeavesPerIdentity` existing today — were confirmed.

**Notes:** The plan carries one deliverable that is not a task's code: `Task 16` writes the slice-2
interface registry, the analogue of `2026-08-12-slice1-interface-registry.md`, and puts its
machine-readable pending-pin table in `sdk` rather than in this repository — because a markdown table
here and a Go gate there that must "agree" is precisely the ungated claim item 7 records.

---

### 2026-09-02 — s1 repaired: the mirror image of a test that cannot fail

**Change:** Amended `docs/plans/2026-08-30-slice2-s1-sdk-surface.md` (2,021 → 2,448 lines) against an
adversarial review. Thirteen findings closed, plus one the repair found in the same class (§7.7's
interface block is 10 listeners and 11 callbacks, not the 7/14 the plan carried); seven open items
added (S1-18 to S1-24); item 48 above amended for the new count and for S1-23, which joins the set
that cannot wait. No task was removed
and no property was weakened to make the current tree pass.

**The defect class, because it is the one this repository has not had a name for.** This project's
most expensive recurring defect is *a test that cannot fail*. The s1 plan shipped its mirror image:
**a property no correct transcription can satisfy**, so a gate written to it is red before a single
mutation. Four instances, and what makes them expensive is not the red gate — it is that the cheapest
way out of a red gate is to change the *code* until it passes:

- **Task 5 Property 4** required `GapReason` and `MessageAttachment.State` to share no value. Both
  contain `"expired"` (§7.4's block and §7.4's attachment block). §7.4's actual claim is narrower —
  *"Attachment outcomes are not gap reasons"*, naming `pruned` and `failed` — and never claims
  disjointness. The likely resolution is deleting `"expired"` from one side, losing either the
  expired-record gap or the expired-attachment state, **frozen into s10's ABI baseline**. Repaired to
  an exact-set assertion: the intersection is exactly `{"expired"}`, which refuses a new collision
  *and* a deletion. Open item S1-21; a §7.4 correction is owed.
- **Task 3 Property 3** required every duration on `MessageServerInfo` to end `Ms`. The struct
  carries `RendezvousTtlSeconds` and `RendezvousDepositTtlSeconds`, which revision A-6 added to it.
  Repaired to transcription-not-normalisation. Open item S1-19; §7.2's *"every other duration on this
  API surface is milliseconds"* is false of the struct it appears in.
- **Task 13 Property 1** failed on reading zero entries from any of six named generator tables.
  `keepTypes` is `map[string]bool{}` at `gen.go:92` and legitimately empty, so the gate was red on
  arrival. Repaired to *did-not-find*, not *found-nothing*: locate all seven declarations, report each
  size, assert a non-zero aggregate, and record an empty table as a dated fact. Truncation moved to
  Property 3, which now asserts its comparison was non-vacuous. The seventh table is
  **`skipFuncPatterns`**, omitted before and the only one Task 7 Property 5's reasoning rests on.
- **Task 11 Properties 2 and 4** contradicted each other: 2 required a stub ticket to invoke its
  callback, 4 forbade starting a goroutine, and the only construct satisfying both — inline
  delivery — violates §9.5 rule 2, *"Callbacks arrive on an arbitrary Go goroutine, never the UI
  thread"*. Repaired by deriving Property 4's class correctly as **retained state** rather than
  goroutines, with the single bounded delivery goroutine carved out as required rather than
  tolerated. Open item S1-24: §9.5 rule 4 states release semantics for a `Sub` and not for a ticket.

**Counts the plan attributed to the spec that the spec does not state.** `GroupResult.Reason` has
**22** values, not the 21 the plan said in three places; §7.7 declares the set and states no count at
all. §7.7's interface block is **10** `*Listener` and **11** `*Callback`, not the 7/14 the plan
carried. Both are now labelled as this plan's measurements with their date, no gate takes either as
an input, and the missing count is filed as S1-20 — because a closed vocabulary whose size no
document states is one a reader can undercount with nothing to contradict them.

**Two claims the plan made that its own other tasks refuted.** Task 11 said a `*List` stub returns
nil, marshalling to JSON `null`, and called that "the honest answer"; Task 7 justified sixteen
shadowing `MarshalJSON` methods on the premise that Spec C's nlohmann **throws** reading `null` as an
array. The plan cannot have both. And §8.2 forbids the other candidate — *"Spec C would then render
'No conversations yet' to a user whose entire history is intact on the server"* — while §7 gives all
twelve `*List`-returning declarations no error return. Task 11's partition is now **three-way**: a
declaration that cannot be refused honestly is neither implemented nor stubbed, it is declared
unrefusable and assigned. S1-22 records that the nlohmann premise is asserted rather than measured —
the one load-bearing claim in the plan that was never run.

**Verified by running, not by reading.** Task 8 Property 3's reflective fixture cannot be built as it
was described: the `*List` wrappers embed `exportedList[T]` **by value** and its `values` field is
unexported, so `reflect.Value.Set` panics with *"using value obtained using unexported field"*, and a
builder that skips what it cannot set leaves every list empty — which makes Property 4's three
assertions vacuous. The same run found the mechanism that does work: the promoted `Add` is reachable
as `reflect.Value.MethodByName("Add")` on the addressable wrapper. Set what is settable, call `Add`
for what is not.

**Three scope errors of the ledger-21 shape, one of them inside the task written to prevent it.**
Task 12's declared walk roots **omitted the three exported free functions this plan itself creates**
(`MessageVocabularies`, `MessageVocabularyValues`, `MessageVocabularyContains`), so they fell outside
the plan's own exportability walk; the roots are now derived, with a manifest. Task 12 specified
**one** `replace` directive for the new nested module; verified 2026-09-02 that `cgo`, `build` and
`js` each carry **four**, because a nested module inherits none of its parent's. And Task 15's CI job
named no sibling repository and no ref — measured 2026-09-02, `connect/mls` is 636 files on
`beta/message` and **0** on `main`, so a workflow checking out `connect` at its default branch cannot
build. That branch is now a pending-pin row, because it expires rather than merely going stale.

**`Sub` is the fourth handle and cannot carry the marker.** §9.2's table gives the messaging generator
four behavioural types and §7.1 lists `Sub` among them, but `Sub` is an *interface* in `sdk/sub.go`
and is already in `sdk/cgo/gen/gen.go`'s `behavioralTypes` at line 50 — so a marker on it is a method
added to a shipped interface's method set. Task 14's handle set is now "marker-derived, plus one
size-gated exception", and Task 13's *"no messaging name in the VPN table"* refusal is scoped to the
marker-derived three, which is what makes it true rather than red.

**One position corrected because it contradicted a locked decision.** Task 2 Property 3 forbade any
literal used as a default for `network_space_host`. Decision A13 requires exactly that construct —
*"no operator hostname literal appears **outside the default-value declaration**"* — and §7.2 and
§9.3 place the sanctioned build-time default in the **host application**, with the key **required**
in `sdk`. The gate is rewritten to that distinction rather than to the sentence that reads well.
Separately, the plan's rejection of unknown `settings_json` keys is a forward-compatibility decision
§9.3 never takes; it is kept, and filed as S1-18 with what it costs.

**Reviewed by:** the author, as a diff, against spec text and against source in three repositories.
Every anchor cited in the amendment was re-run: `gen.go:50`, `:92`, `:107`; the four replaces in
`cgo`, `build` and `js`; `connect`'s two branches; the 22-value and 10/11 counts; and the reflection
probe, which is the one that changed a task rather than a sentence.

---

### 2026-09-02 — the CP3b chain, and three gaps written up as proposals rather than resolved

**Change:** Added `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md` (759 lines).
Open items 44, 44a, 45, 46 and 47 added. Items 38 and 39 each gained a proposed reading, labelled as
a reading. No spec and no plan was edited.

**Why:** The s1 reviewer's finding — *"The plan does not trace a chain to CP3b and does not answer
the sequencing question that commissioned it"* — plus three gaps the s1 and store readers found that
Spec A promises and no mechanism delivers.

**The sequencing answer, in one line.** p2 Tasks 19–20 → p7 Tasks 7–13, 15, 16, 18, 19, 22 → **m1, a
plan that does not exist** → s1 → two to four sdk plans that do not exist → CP3b. Everything else in
p2, p6, p7 and p8 is off it, and so is about 85 per cent of Spec A §7: measured per subsection, CP3b
needs roughly 21 of §7's functions and a dozen of its types — identity, one group, one send, one
receive, and the engine seam — and none of §7.3a, §7.3b, §7.4a, §7.5, §7.6 or §7.9.

**What the chain found that no item had.** The re-orientation named three unplanned workstreams;
there is a fourth, and it sits in front of two of them. **`connect/message` has no plan.** The s1
plan already calls it m1 and already records `StorageRoot` as a pending pin with no producer; nobody
had noticed that the pin's absence is the CP3a/CP3b delta itself. Filed as item 47. And **the
`Welcome` has no delivery channel** — `CommitResult.RatchetTree` is annotated *"for out-of-band
Welcome delivery"* and no document names the band, while every server operation is keyed by
`group_id` and gated on an epoch key a joiner does not have. Filed as 44a, beside the key-package
gap, because one mechanism closes both directions and splitting them invites two incompatible
answers.

**Three proposals, and the discipline they were written under.** This project has twice had an
implementer discover that a plan resolved an ambiguity the spec never settled, so each of 44, 45 and
46 is options-and-a-recommendation rather than a position: what the spec promises, what exists, what
is missing, two or three options with what each costs in metadata exposure, a recommendation labelled
as one, and what stays blocked. Two alternatives are rejected outright with their reasons recorded so
they are not re-invented: deriving invite-link material from `group_handle_key`, which is fixed at
group creation and would hand a **removed** member a permanent collect key over every published
address; and a chained history secret, which would silently give a member added at epoch *n* every
epoch before it — the exact opposite of MASTER §11's stated default.

**One false sentence in a spec, named as the deliverable asked.** §13 schedules §7.3a as *"an
sdk-level flow over mechanisms A6 already froze."* Measured against what §7.3a needs, A6 froze the
rendezvous transport and the five preimages — both genuinely group-agnostic — and froze no per-link
derivation, no link encoding, no join-request deposit body and no authorization model for a reusable
address. Three of the four are missing, so **A7 cannot deliver §7.3a as the table stands.** The
sentence is true of §7.3b and was extended to §7.3a without the check.

**Items 38 and 39 get one principle, not two rulings.** *`closed` withdraws the ability to write new
content; it does not withdraw a member's ability to learn what is already there.* On 38 that means
taking §7.5 and striking `store.go`'s *"everywhere afterwards"* — §4.5's indistinguishability denies
an OUTSIDER an existence oracle, and on the read path §5.1.1's check 6 and check 7 both run before
the closed state is consulted, so the only party that can see the difference has already proved
possession of the read key, while existence is answered earlier by §5.1 check 5's known-group filter,
which closing does not touch. On 39 it means §6.1's step order outranks §7.5, because step (0)
writes nothing and because `REASON_REJECTED` on a retried commit fires the loser protocol and burns a
`pq_secret`, which Spec B itself calls silent corruption. The cost of the 38 reading is stated rather
than discovered, and it is a **derived** partition over `type Store interface` — read methods answer
as an open group, write methods as an unknown one — never a hand-written list of method names.
Ruling one of the two without the other produces a build that refuses a member's `Fetch` and answers
their `Submit` retry with a record id.

**Verified rather than reported.** Every claim of absence in the document was re-run rather than
inherited: `key_package` across all seven `connect/protocol/*.proto` files (zero); `Encapsulate`,
`Decapsulate` and `mlkem` across `mls/` and `message/` non-test source (one hit, a comment);
`func StorageRoot` across the tree (0); `conveys` across all five `docs/specs/` documents (0, so r3
finding 5 is still unapplied); `connect/message`'s seven non-test files (no key schedule, no AEAD, no
ratchet, no X-Wing, no wraps);
`Store`'s six methods and the four served api operations. §7's per-subsection counts were measured on
a stated rule — top-level `func` and `type X struct|interface` lines between `### 7.1` and `## 8.`,
giving 191 — and labelled as counting something different from s1's 212, so the two cannot be read as
contradicting.

**Reviewed by:** the author, as a diff. No code changed, so no mutation testing applies.

---

### 2026-09-02 — s1 repaired again: the repair's own largest construct was an instance of its class

**Change:** Amended `docs/plans/2026-08-30-slice2-s1-sdk-surface.md` (2,448 → 2,828 lines) against
the review of commit `2ac145b`. Six findings closed. No new open item: every one of these was the
document disagreeing with itself, not the spec failing to say something. S1-22 is deliberately left
open and unresolved, because it cannot be measured until Spec C's wrapper exists.

**The class is the one the previous repair named, and the previous repair's largest new construct
was an instance of it.** *A property no correct transcription can satisfy* — a gate red before a
single mutation, whose cheapest resolution is to change the code until it passes.

- **Task 11's new third bucket, and the seventeen types nobody counted.** The repair introduced an
  *unrefusable* bucket — a `*List`-returning §7 declaration with no error channel is neither
  implemented nor stubbed, because `[]` is refused by §8.2 and `null` by the plan's own premise. That
  is the right call and it stands. What it did not count is that an undeclared method names no
  types. Measured against §7: **eleven of the sixteen `*List` wrappers are named in §7 at exactly one
  site each and every one of those sites is one of the twelve** — `MessageGroupList` at `Groups()`,
  `MessageMemberList` at `Members()`, and so on through `MessagePinList` and
  `MessageSecurityLogEntryList` — while five survive on a field or a callback parameter; and **six
  element structs** (`MessageMember`, `MessageDevice`, `MessageInvite`, `MessageHistoryGrant`,
  `MessageSecurityLogEntry`, `MessageSearchResult`) are named only as those wrappers' elements. So
  seventeen declared types are reached from nothing, and **Task 7 Property 1** (*"every declared
  `*List` must be named somewhere"*, scoped to *"the whole exported surface reachable from
  `MessageClient`"*) was red against a correct transcription for eleven of its sixteen wrappers, with
  **Task 10 Property 3**'s dead-surface half red for the six structs and Tasks 8, 9, 12 and 14
  silently narrowed. Meanwhile the plan's Goal, Task 11's Produces line and *What this plan does not
  close* all still said the plan declared the whole of §7 — the document saying one thing in three
  places and another in a fourth.
  *Repaired* by taking the second of the two defensible routes and taking it everywhere: the bucket
  is kept, the Goal now says what s1 emits and what it hands over, and **"reachable from
  `MessageClient`" is retired as a gate scope** in favour of **the s1 surface**, defined once and
  derived — every exported named type and package-level function declared by a `message_*.go` file,
  plus everything reachable from those. It is a superset of the old scope, so no gate loses reach.
  The two properties that genuinely ask *"is this declared type dead?"* — Task 7 Property 1 and
  Task 10 Property 3 — now answer it from the **transcription**: a manifest entry naming the §7
  declaration that names the type and the plan that owns it, which distinguishes *deferred* from
  *dead* and empties itself as those plans land. §9.2's and §7.7's *"reachable from `MessageClient`"*
  describe the **finished** surface; borrowing the phrase for a tree that holds part of §7 is what
  produced this.
- **Task 3 Property 2 required every time field to be milliseconds; six declared fields are
  seconds.** *"Every time-valued field is `int64` unix milliseconds and is named `...Ms`"*, scoped to
  the whole surface — against `MessageRetentionApplied`'s `MediaTtlSeconds`, `DurableTtlSeconds`,
  `RequestedMediaTtlSeconds` and `RequestedDurableTtlSeconds`, and `MessageServerInfo`'s
  `RendezvousTtlSeconds` and `RendezvousDepositTtlSeconds`. The previous repair rewrote **Property 3**
  to transcription-not-normalisation for exactly this reason and left the universal Property 3 is a
  refinement of asserting the opposite — so the plan carried three properties, two of them demanding
  the opposite of the third about the same struct, which is the Task 11 Properties 2-and-4 shape that
  repair fixed elsewhere. *Repaired* to the universal that is actually true of the surface: the
  suffix set is exactly `{Ms, Seconds}`, an instant is always `Ms`, and which of the two a duration
  takes is Property 3's transcription question. Three mutations added, one of which asserts that
  Property 2 is **not** what fires when a `Seconds` field is renamed.
- **Task 12's root manifest names two functions this plan does not declare.** The repair fixed the
  enumerated-roots defect and committed a manifest whose stated refusal is *"fails if the derived set
  and the manifest disagree in either direction"* — then recorded the derived set as **eight**,
  counting `GenerateMessageSeedphrase` and `ValidateMessageSeedphrase`. Those are §7.2 package-level
  functions over BIP39 key material; no task in this plan creates them, and Task 11 partitions the
  **method set** of `MessageClient`, so §7's four package-level functions fell in no bucket at all.
  The derived set on this plan's actual output is **six**. A manifest gate that compares in both
  directions against a manifest with two phantom entries is red before anybody mutates anything.
  *Repaired*: the count is six, the two functions are assigned to s3 in the ownership map and named
  in Task 11 as not this plan's, and the day s3 lands them the manifest gate fails and asks for them.
  The roots gain a second derived part — every exported named type declared by a `message_*.go`
  file — without which Task 6 mutation 4 and Task 14 mutation 4 (both of which mutate
  `MessageMember`) cannot fail at all.
- **Task 11 Property 1's scope source was a markdown file in another repository.** *"Partitioned
  against the ownership table in Task 16's registry"* — which is
  `msgrepo/docs/plans/…-interface-registry.md`, while the gate is a Go test in `sdk` that Task 15's
  workflow never checks `msgrepo` out for. Task 16 rejects that exact shape **one task later** —
  *"a markdown table in `msgrepo` and a Go gate in `sdk` that must agree is an ungated agreement
  claim"* — and solves it for the pending pins with a file in `sdk`. The ownership map got no such
  file, so the gate could not be written as scoped and Task 16 mutation 6 could not run. *Repaired:*
  `sdk/slice2-ownership.txt`, created by Task 11 because its own property needs it, made normative by
  Task 16, cited by the registry and restated nowhere. The scope statement now separates the
  partition's **domain** (the map, because a bucket-1 or bucket-3 declaration is by definition absent
  from the type graph) from the comparison against the type graph, which runs in both directions.
- **Task 9 Property 2's refusal counted five negative claims and its table held four.** §7.2's
  vocabulary block refuses `"fork_detected"` **twice** — from vocabulary 1 and, in the sentence *"It
  also loses `fork_detected`, for the reason vocabulary 1 gives"*, from vocabulary 3's reason set.
  The plan listed the first, `"server_key_change_unresolved"`, `"commit_lost"` and
  `"retention_refused"`, and then said *"adding any of those five values fails"*. That is rule 5 at
  its most literal: a table headed with a class, holding four of its five members, and the missing
  member is the second site of a value the table already carried — so nothing looked absent.
  *Repaired* by deriving the class from the two forms §7.2's source uses to state an absence, with
  five `(vocabulary, value)` pairs as the measured content and a mutation per pair.
- **Task 16 Property 4's list of positions taken held seven of fourteen, plus one that is not a
  position.** It named eight open items as *"a position this plan took … listed with the alternative
  it rejected"*. Measured: **fourteen** open items carry a *Position taken:* line — the list omitted
  S1-2, S1-3, S1-5, S1-8, S1-10, S1-19 and S1-20 — and it named **S1-11**, whose text is *"Not
  resolved here"* and which records no position and no rejected alternative, so the property is red
  on that row. *Repaired* by deriving the class (*every open item whose text carries a `Position
  taken:` line*) with fourteen as the reported measurement, and by refusing in both directions.

**Also corrected:** the File Structure table, which claims to list every file the plan creates and
omitted five per-task test files and the two machine-readable tables; the Definition of Done, which
gains rows for the s1 surface's two-part root set and for the deferred sets of Tasks 7 and 10; and
Task 12's own account of the first draft's roots, which said *"enumerated four"* beside a list of
five.

**What was deliberately not done.** S1-22 — that Spec C's nlohmann parse throws reading JSON `null`
as an array — is an **assumption, not a measurement**, and sixteen shadowing `MarshalJSON` methods
and all of S1-23 rest on it. It stays filed as a premise. The obvious way to close the first finding
above is to declare the twelve after all, which requires choosing `null` or `[]` for their bodies:
`[]` is refused by §8.2 outright and `null` only by S1-22's premise, so picking `null` would resolve
S1-22 by assertion rather than by measurement. Neither is available, and S1-23 now records the
rejection explicitly. Nor was any property weakened until the tree passed: Task 7 Property 1 and
Task 10 Property 3 both keep a refusal for a genuinely dead type, and both now report the size of
their deferred set on every run so it cannot grow unnoticed.

**Rule 11, applied to this diff.** The class this commit was sent to close is *a property no correct
transcription can satisfy*, and the diff was re-read looking only for it. One instance was found in
the new text and removed before commit: the *What this plan does not close* entry opened by asserting
that s1 leaves **thirty-three** of §7's 135 declarations undeclared — a count nothing in this project
has measured, since bucket 1's size is Task 16's registry to fix and s2–s10 do not exist. It now says
that bucket 1's size is the registry's to state, and carries only the two numbers that were measured:
twelve for bucket 3 and seventeen for what it costs the type graph. Two further count inconsistencies
introduced by the same pass were caught the same way — *"five of this plan's gates"* against a list of
eight properties, and a task list of four against a list of six — and both are now the same number in
both places.

**Verified by running, not by reading.** Every count in this entry was measured against the documents
in this repository and the source in `sdk`, on 2026-09-02: the eleven single-site `*List` wrappers and
the five that survive, over §7 lines 1868–3542; the six element structs, one grep per type; §7's
**four** package-level `func` declarations, which is what makes the seedphrase pair findable; the six
`Seconds` field names and the absence of any third unit suffix; the two `fork_detected` refusals in
§7.2's block; the fourteen open items carrying a *Position taken:* line; `MessageServerInfo` named as
a type at `ServerInfo()` and its own declaration and nowhere else; and, in `sdk` on `main`,
`gen.go:50`, `:92` and `:107`, `sub.go`'s `Sub` and `simpleSub`, `gomobile.go`'s pointer-receiver
`MarshalJSON`, the three `replace ../` lines in `sdk/go.mod` and the four in each of `cgo`, `build`
and `js`. The encoding guard was run by hand over both edited files: no double-encoded sequences, LF
throughout.

**Reviewed by:** the author, as a diff, against §7's text and against `sdk` source. No code changed,
so no mutation testing applies; what stands in its place is the rule-11 pass above, which is this
document's equivalent and which found one defect of the class in this commit's own new text.

### 2026-09-04 — `peekFor`'s disclosed behaviour change, verified rather than accepted

The closing round on p7's CP3b path (`connect` `ebaac44`) changed `peekFor` so that a
**too-far-ahead refusal now moves the receiving head**, and rewrote a control that had asserted the
opposite. The implementer disclosed this in three places and named the risk in its own words:

> *"If either of those is wrong, this change hands a malicious member"* new capability.

It rested the argument on two facts. Both were checked against source rather than taken:

**(a) "the generation reaches `peekFor` only after `openSenderData`'s AEAD opens under
`sender_data_secret`."** — **True of this package's receive path.** `openSenderData` is at
`framing_protect.go:688` and gates the only framing route to `MessageKey`. **But not true of the
type's API**: `ReceiverKey` (`secret_tree.go:899`) is a second exported door onto `peekFor` with
**zero production callers**. The word *only* holds for the path, not for the surface — which is
exactly what the review's LOW finding said, and it stands.

**(b) "the accepted in-bound path already steps and retains a full `MaxGenerationSkip` run."** —
**True, and already documented in the file being changed.** `secret_tree.go:490` states that a member
can move the head by `MaxGenerationSkip` *"for the price of one header, by asking for head+1024"*,
and `RatchetWindowSize == MaxGenerationSkip == 1024`. The catch-up on refusal is therefore *exactly*
an accepted skip, granting no advance the accepted path does not already grant.

**Conclusion: sound for the framing path.** The residual is (a)'s second door, which is an unused
exported method, not a reachable capability. Recorded rather than closed.

**And the process point, which is the more valuable half.** Rule 12 forbids retuning a control
*silently to keep a gate green*. This was the opposite: a deliberate behaviour change, argued in
three places, with the argument's load-bearing premises named so a reviewer could check them — and
one of the two turned out to be overstated. **A disclosure that names its own premises is what made
the overstatement findable.** That is the shape a behaviour change should take here.

### 2026-09-04 — m1: the plan for `connect/message`'s crypto, and where the CP3b path actually ends

`docs/plans/2026-09-04-slice1-m1-message-crypto.md`. The **tenth** plan in `docs/plans/` — p1–p8, s1
and this one — for the fourth unplanned workstream the 2026-08-29 re-orientation missed. It closes
open item 47 and opens two that are worse, which is the honest outcome and is why this entry is
written that way round.

**What was measured, before the spec was read.** The brief said to read the package first, and doing
so changed the plan's shape three times. Measured in `connect` on `beta/message`, 2026-09-04:
`connect/message` is **9 non-test files, 9 test files, 169 `Test` functions and 2 `Fuzz` functions**;
`go build ./message/... ./mls/...` is green on go1.26.5; and `grep -rn 'func StorageRoot'` over the
tree returns **0**. §5.1's record types, §5.4's X-Wing, §5.7's eight MAC functions, §5.8's codec and
§5.11's attachment encoding are all landed, and were checked field-for-field against the spec blocks
rather than against a summary. §5.2, §5.3, §5.5, §5.6 and §5.11's client half are at **absolute
zero** — none of `keyschedule.go`, `ratchet.go`, `handle.go`, `eph.go`, `wrap.go`, `recovery.go`,
`engine.go` or `session.go` exists.

**The plan's shape follows from one fact: `WriteKey(storageRoot)` and `ReadKey(storageRootEpoch)`
take a value nothing in the tree produces.** 125 KB of tested MAC code is dead-ended on one missing
function. That is the whole CP3a/CP3b delta seen from the inside, and it is why Task 3 is
`StorageRoot` and not something more impressive.

**Where the CP3b line falls, which is what the plan was commissioned to answer.** Tasks 1–16 are the
path and nothing outside them is on it. Tasks 1–12 are buildable today: the record AEAD, the key
schedule, both handle chains, both ratchets, the durable `stream_index` reservation, §6's engine
interface, `GroupSession`, `SealRecord` and `OpenRecord`. Tasks 13–16 are the second client's half,
and **two of those four are blocked on rulings the plan files rather than makes** — items 125 and 126
above. Tasks 17–24 are the A6 freeze, and none of them is required to put a message in front of a
person. Wave 1 complete is a `connect/messagegroup` that seals and opens records under the real key
schedule inside one process. **That is worth having and it is not CP3b**, and the plan says so at the
one place a reader would otherwise mistake it: Task 12's two-session round-trip property, which
carries that sentence in its own test comment.

**Two findings that came out of reading the source against the spec rather than against the brief.**

The first: MASTER §8.1 says *"`ct_head` is always under the **durable** class, since it is always
retained"*, and Spec A §5.3 hands `RecordAeadHead` and `RecordAeadBody` **the same `record_key[i]`**.
For a `DURABLE` record the two readings coincide, so **CP3b cannot tell them apart** — and for
`PERMANENT`, `MEDIA` and `EPH` they are two keys from two ratchets with one `stream_index` between
them. A contradiction invisible at the milestone and wire-visible at the freeze is exactly the kind
this project pays for late, so `SealRecord` **refuses a non-`DURABLE` class** until it is ruled
(M1-6).

The second: §5.1 fixes `octet_length(ct_body)` at its rung, so the plaintext is padded — and **no
document states the padding scheme or how the receiver recovers the true length.** `pad.go` is named
in §2.2's package tree and has no section anywhere; MASTER §9.5 is "What the server sees" and is not
it; and `msgrepo/harness/seal.go` pads with `byte(index*31)` and never unpads, because CP3a's harness
does not encrypt and never reads a body back. Without a ruling, `OpenRecord` hands back 256 octets
for a five-octet message (M1-7).

**Three reader claims were corrected against the source rather than carried through.**
`sender_handle` was reported as having no derivation anywhere in the project; MASTER §8's RECORD
listing has it — `HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)` — so the gap is Spec
A's restatement, not the project's, and the plan implements MASTER's. `EphKey` was reported the same
way; MASTER §8.1 gives `K_eph[n][b][t] = HKDF-Expand(eph_root[n], "eph/v1" ‖ u8(b) ‖ u64(t), 32)`,
and what is genuinely missing is `t`'s unit, origin and clock. And guardrail G8 was reported as *"a
comment"* with no gate in the tree: the gate exists, in `message/writeauth_test.go`, and is **wider**
than G8's own text — a construct gate over the whole package directory with the comparator class and
the `Verify*` class both derived from the syntax tree. That correction produced its own finding, and
it is the one worth the most: **the shipped gate will refuse `VerifyRecoveryProof` and the five
`VerifyRendezvous*` the day they are declared**, because an Ed25519 verifier calls out of the package
and reaches no `subtle.ConstantTimeCompare`. The plan tells the implementer to amend the gate by
restating its property and **not** by exempting a name (M1-19) — this project's own rule that a gate
repeatedly bypassed is a gate that does not track the property it stands for.

**What the plan supplies and what it deliberately does not.** Per task: a **Files** list, an
**Interfaces** block naming exactly what is consumed and what is produced, and numbered steps — the
part that has worked for nine plans, and what lets plans compile against each other across months.
It supplies **no test code**, per R1: each task states the property, the refusal that property owes,
and the numbered mutation set the implementer must run. It quotes the spec wherever a rule is
normative, per R3, including §5.11's publication sequence at its full **five** steps and §5.6's
write-once rule in both of its halves. And it opens with the instruction that **every signature is
read from source**, because `FindExtension` cost this project seven stale call sites and three of the
signatures this plan names changed shape inside the last four weeks.

**The reuse section is the other half of that.** `mls.CryptoProvider.Extract(salt, ikm)` is already
HKDF-Extract in the spec's argument order, already vector-tested against RFC 5869's table, and
already inside one of the two files the tree's own confinement gate allows — so guardrail G1's fix is
a call, not a function. `mls.Group.Export` is `mls_secret` in one line. `mls/secret_tree.go` is §5.5
already solved once, and its **eviction policy is better than §5.5's** — a tree-wide retained-key
bound instead of a per-sender one, and eviction from the fullest window instead of the oldest sender,
which closes §14 open item 7 without a Spec C round trip. Against those, three things are named as
**not** reusable at the point where a reader would reach for them: `mls`'s AEAD (12-octet nonce,
wrong schedule), `mls`'s Ed25519 (RFC 9420 label framing over raw preimages — it compiles and
verifies against nothing), and `mls.Group.Protect`/`Unprotect` (a different key schedule with no PQ
input).

**Verified by running, not by reading.** Every count in this entry was measured on 2026-09-04 against
the tree, not against the brief: the file and test counts by `ls` and `grep -c`; the green build on
the pinned go1.26.5 toolchain; the zero hits for `func StorageRoot`, for `group_handle_key`, and for
a fourth URmessage extension type; `mls.CryptoProvider.Extract`'s `(salt, ikm)` order at
`crypto.go:175` with its own comment; `Group.Export` at `group.go:821` and its `ErrEpochErased`
refusal at `key_schedule.go:486`; `ClearPendingCommit` at `group.go:2475`; the forbidden gate's
`forbiddenScanRoots`, `hkdfExtractAllowedPaths` and `hkdfExtraCallSites` at lines 46, 83 and 444; the
entropy residual table at `crypto_test.go:7776` and its two rows; the constant-time gate's
`authScanDir = "."` and its four rules; `EncodeServerAttachment`'s identical answer for a nil and an
`AttachmentNone` attachment; `aad_test.go:70`'s `aadKatAlgId = 0x0021` against MASTER §8 line 722;
and `MaxGroupMembers` / `MaxDeviceLeavesPerIdentity` at `errors_lifecycle.go:35-36`. Index checked
before the commit: `git ls-files` and `git ls-tree -r HEAD --name-only` agreed at 99.

**Rule 11, applied to this diff, and it found three.** The class this rule is sent to close is *a
count nobody measured*, and a pass over the new text looking only for that found three instances,
all introduced by this commit and all now corrected to the measured value. The draft said **nine**
open items were wire-visible; the label appears on **six** (M1-6, M1-7, M1-8, M1-24, M1-27, M1-33),
and the text now says six and says explicitly that it is a count of the items carrying the label
rather than a claim that the other 35 are format-safe. Task 23's summary said *"six of the eight are
wire-visible"* over a list of **six** items — a sentence disagreeing with itself in the same
sentence — and now names the two that carry the label. And this entry called m1 *"the ninth plan"*;
`docs/plans/` holds p1–p8 and s1, so it is the **tenth**, and the two places in the plan that said
"eight plans" now say nine. Three unmeasured counts in one document is the same rate this rule has
found on every previous commit here, which is the argument for running it every time rather than
when the text feels risky.

**Reviewed by:** the author, as a diff, against Spec A §5, MASTER §7–§9 and `connect` source. No code
changed, so no mutation testing applies. Its equivalent here was the pass above, plus this one: every
claim inherited from a reader was re-derived from the tree before it entered the plan, and three of
them did not survive.

### 2026-09-05 — m1 repaired: the interface `*mls.Group` cannot satisfy, and the adapter with nowhere to live

**Change:** Amended `docs/plans/2026-09-04-slice1-m1-message-crypto.md` (2,439 → 3,103 lines) against
an adversarial review. One task added (**9a**, the `connect/mls` adapter), four open items added
(**M1-42** to **M1-45**), one open item moved between sections (**M1-6**, A6-freeze → CP3b), one
open ask withdrawn (**O-4**) and one added (**O-5**), and two ledger open items opened (**127**,
**128**). Item 48 above amended for the task count, the open-item count and the CP3b-blocker count.
**No task was removed, no property was weakened to make the current tree pass, and the plan's 41
existing open items are unchanged** — the review's own verdict was that the factual base survived
intact, every measured count and every normative quotation checking out verbatim, and the repair
left that base alone.

**The defect class, and it is the one this repository named three days ago.** On 2026-09-02 the s1
repair gave a name to *a property no correct implementation can satisfy* — the mirror image of a test
that cannot fail — and found four instances. m1 shipped a fifth, in its most load-bearing task:

- **Task 9 Property 3** required `*mls.Group` to satisfy `GroupHandle` structurally, and told the
  implementer *"every method here must be satisfiable by `*mls.Group`."* Measured against
  `grep -n '^func (self \*Group) [A-Z]' mls/*.go`, **13 of §6's 23 methods cannot match**, and none
  of the 13 is closable by writing better code: `OwnLeafIndex() uint32` against `OwnLeafIndex()
  LeafIndex` fails because `tree_math.go:27` makes `LeafIndex` a **defined type** and Go method sets
  are identical-type; `MemberCount`, `SenderDataSecret`, `EncryptionSecret` and `ProposeGroupPolicy`
  are absent entirely; `Process` and `ApplyCommit` name `*EngineProcessed`, which is declared in
  `connect/message` with an unexported field and can therefore never be named by a method in
  `connect/mls` — that pair is unclosable **by design**, which is the interface working.
  Worse than the red gate is the instruction beside it: the cheap way out of a red structural
  assertion is to reshape §6's interface around `mls`'s own types, which destroys the boundary
  Gate 5 exists to hold. Repaired to the property that is true and worth gating: **the adapter
  satisfies it and `*mls.Group` does not**, with the 13 mismatches tabulated so the measurement
  cannot be lost, and a refusal on any `engine.go` signature naming a `connect/mls` type.

**And the other half of the same defect: the adapter had no task, no file and no Produces line.**
`grep -n 'adapter'` over the plan returned **one** hit, inside §6's own block quotation. No task
produced a `GroupHandle` implementation at all, so Task 10's `GroupSession` had nothing real to
hold and CP3b's *"no test-only key source anywhere on the path"* was unreachable from waves 1 and 2
for a reason no open item named. **Task 9a** now lands it, and its home is forced rather than
chosen: `EngineProcessed.stagedRef` is unexported, so only package `message` can construct a
populated one, so only package `message` can implement `Process` — which is also what §2.2's tree
says (*"engine.go — the GroupEngine interface (§6) + the connect/mls adapter"*). Task 9 Property 4,
which forbade this package to name `mls.Group` at all, is repaired to the path-confined form the
`crypto_forbidden_test.go` comment argues for, and the residue is filed as **M1-43**: `stagedRef`
confines every engine implementation to one package, which is the opposite of what §6's "swappable"
claims and what Gate 5 promises.

**The CP3b prefix did not close, and the missing leg is now the largest thing the plan files.** The
Definition of done required the record to travel *"through the message server"* and then listed
external legs that were **all inside `connect/mls`**. Measured: no task in the plan produces a submit
path; `store` and the api layer already serve `Submit`; `harness` is the only client-side sealer in
the tree and is test-only and *"does not encrypt."* The 2026-09-02 chain review assigns the client
leg to the unwritten sdk plans, and m1 does not touch `sdk`. The Definition of done now names
**four** external legs instead of two — p2, p7, s1, and the unowned submit leg — and **M1-42** /
ledger item **127** file the gap rather than inventing a resolution, with both candidate owners
stated and neither chosen. In the same pass, **Task 16 Property 2** stopped calling an in-process
two-session exchange *"This is CP3b"* — which is precisely what Task 12 Property 2 exists to warn
against, two tasks later and one leg short.

**A wave-1 refusal was blocking a wave-2 task, and the item that governs it was filed under the
wrong heading.** Task 11(a) makes `SealRecord` refuse every non-`DURABLE` class until M1-6 is ruled.
Task 15 consumes that `SealRecord` and must emit the ratchet-tree snapshot, which §5.11 step 2 fixes
as *"one `PERMANENT`-class record"*. So M1-6 blocks CP3b by the plan's own construction while sitting
under *Blocking the A6 wire-format freeze*, months out. Moved, promoted to ledger item 128, added to
the execution order as the third schedule ruling beside M1-1 and M1-2, and Task 15 now states what it
does in the meantime — with an explicit refusal to close it by exempting `PERMANENT` in `SealRecord`.

**Nine more, each verified against the tree before it was written down.**

- **Task 13 Property 2's derived class convicted five correct functions.** *Every function returning
  32 octets whose parameters include a storage root, a class key or an epoch* names `WriteKey`,
  `ReadKey`, `GroupHandleKey`, `DeriveClassKeys` and `RecordKeyZero` — all specified by this plan.
  The only reading that spares them is semantic and no AST scan decides it. Rewritten as a signature
  gate plus a required-row table in `entropyRefusalsHeldOutsideThisPackage`'s shape.
- **Task 15 Property 5 told the implementer to assert what M1-22 files as false.** §5.11 step 5
  claims the missing wraps are *"all derivable from the epoch state every member holds"*; a fan-out
  interrupted before the first device wrap lands is unrecoverable by **any** member, because
  `pq_secret[n+1]` is a fresh CSPRNG draw delivered only inside the wrap. Split into the resumable
  case and the unrecoverable one, with a typed refusal in the second rather than a resample that
  would fork the storage layer under a valid MLS epoch.
- **Task 3 Property 6 would have gone red at Task 22's own commit.** §5.14's `deposit_sig_seed`
  is a second `HKDF-Extract` inside `connect/message` — the plan files it as M1-16 and wired it into
  neither task. Rewritten as a both-directions exception table with one row today.
- **Task 3(b) named the wider of two gate mechanisms.** `hkdfExtractAllowedPaths`
  (`crypto_forbidden_test.go:83`) is **needle-blind** — `hkdfAllowedPathsFor` at `:451` joins it in
  for every entry point — so an entry there would excuse `hkdf.Key` too, which the gate's own comment
  at `:266` calls *"the worse of the two"*. The landed precedent for `message` is the needle-keyed
  `hkdfExtraCallSites` at `:444`.
- **Four properties derived a class that is empty at the commit that owns them** — Task 1 P1, Task 7
  P1, Task 9 P2, Task 13 P4 — and the tree's house style **fatals on an empty class**
  (`aad_test.go:1293`, `:1432`, `:1539`; `writeauth_test.go:2451`, all phrased *"reporting clean
  having read nothing"*). Each is now split: the half checkable at its own commit stays, the derived
  half moves to the first task where the class has a member, cross-referenced both ways.
- **Task 7 Property 1 asked a call-graph walk to prove a data-flow fact.**
  `TestReadAuthNeverUsesWriteKey` (`writeauth_test.go:1904`) proves **reachability**; *"passes through
  a returned-nil `Reserve`"* is error handling and ordering, and the task's own mutation 5 — ignore
  `Reserve`'s error — is invisible to it. Now held by three mechanisms, one per claim.
- **Task 16 consumed `GroupHandle.JoinFromWelcome`; §6 puts it on `GroupEngine`** — an R2 failure
  inside the plan that states R2. Corrected with the spec lines named.
- **O-4 asked p7 for two methods that already exist under other names.** `Group.RatchetTree()` at
  `group.go:891` and `Group.GroupContext()` at `:900`. p7 owes nothing; the gap is §6's spelling
  against the tree's, closed by Task 9a in two lines. Withdrawn rather than deleted, and the pending-
  pin row corrected, because a withdrawn ask that leaves no trace is one somebody files again.
- **Task 19 said `GroupHandle` exposes *"exactly `SenderDataSecret()` and `EncryptionSecret()` and
  nothing else"*,** contradicting §6's 23 methods and four tasks' Consumes. Narrowed to the claim G6
  actually makes and that survives: of the **epoch's secrets**, those two and no third.

**Three placement and layering findings, all measured.**

- **The plan said it "follows §2.2" while diverging in fourteen places.** Eleven files added that
  §2.2 does not name, two it names that the plan does not create (`pad.go`, accounted for;
  `tombstone.go`, absorbed into `reaction.go` with no stated reason), and one function moved. Two of
  the moves were silent, and one of those is out of a file a spec comment names: **§5.6's own
  interface block writes `// ratchet.go` above `StreamIndexReserver`** and the plan puts it in
  `streamindex.go`. In a plan arguing that placement is gate-load-bearing — Gate A's allow-lists are
  paths, Gate C's scan is a directory — every divergence is now enumerated, in the File Structure
  section and in M1-36.
- **Task 6 put a file-backed durable store inside `connect/message`.** Measured: that package's nine
  production files import no I/O package at all, and §8.2's `MessageStore` already declares
  `ReserveStreamIndex(groupId, index)` and `StreamHighWater(groupId)` — `StreamIndexReserver` method
  for method — on the fourteen-method interface A8 pins the size of. §5.6 injects the sink for
  exactly that reason. The task now ships the interface and a file-backed **test** fake, the durable
  one is asked of the sdk store plan (**O-5**), and M1-5 gains the fact that its one-parameter fix is
  one parameter in **two** documents.
- **Gate C's comparator ban is package-wide** — its
  `TestNoProductionFunctionComparesDataOutsideConstantTime` runs over every function in the
  package — and the plan worked the consequence only for the `Verify*` class. Task 20's MIME sniffer and Task 24's emoji validator are the other two
  members and neither is a verifier, so M1-19's amendment does not reach them. **M1-45**, to be ruled
  with M1-19 and M1-35, because three separate answers to one guardrail is how a gate becomes three
  sentences.

**One judgement filed rather than taken.** Task 2 writes a second implementation of
`mls.zeroizeSecret` in a plan whose opening paragraph forbids second implementations, and the
alternative is **one character**: export it. `message/xwing.go:36` already imports `connect/mls` in
production, so the call site is free; against it, that surface is p2's and the file's own comment
argues against additions. **M1-44**, with the instruction that if the export is available for the
asking, take it and delete the task.

**Rule 11, applied to this diff, and it found two.** The class is *a count nobody measured*. The
review that commissioned this repair said `GroupHandle` was **24 methods**; counted off §6's block it
is **23**, and every place the repair states the number states 23 with the date it was measured. The
review also said *three* properties derive an empty class; the pass found **four**, and all four are
repaired rather than the three named. Both corrections went the direction that costs more work,
which is the only direction worth trusting a count in.

**Verified by running, not by reading.** Every measurement in this entry was taken on 2026-09-05
against `connect` on `beta/message` and `msgrepo` on `main`: `*mls.Group`'s exported method set by
`grep -n '^func (self \*Group) [A-Z]' mls/*.go`, and §6's by counting the block at spec lines
1805–1836; `LeafIndex` as a defined type at `tree_math.go:27`; `connect/message`'s complete
production import set, file by file; `hkdfExtractAllowedPaths` at `:83`, `hkdfExtraCallSites` at
`:444` and the `slices.Concat` join at `:451`; the four empty-class fatals; `authScanDir = "."` and
the package-wide comparator gate at `:2473`; §8.2's `MessageStore` at spec line 3584; §5.6's
`// ratchet.go` annotation at spec line 1233; §5.11 E2's `K_snapshot` at spec line 1467; and
`go build ./message/... ./mls/...` green on the pinned go1.26.5. **Index checked before the commit:
`git ls-files` and `git ls-tree -r HEAD --name-only` agreed at 100.**

**Reviewed by:** the author, as a diff, against the review's findings, Spec A §5 and §6, and
`connect` source. No code changed, so no mutation testing applies. Its equivalent here was the pass
above: every finding the review handed over was re-derived from the tree before it entered the plan,
and two of its counts did not survive.

---
### 2026-09-06 — the plan linter, and the sixth round of m1 findings it makes unnecessary

**Change:** `planlint_test.go` — an ordinary `go test` in this module, over **every** file matching
`docs/plans/*.md`, checking the four defect classes this project's plans have actually shipped. Plus
the six m1 findings the review that commissioned it handed over, all six reproduced against source
before being acted on.

**Why a test and not a sixth careful pass.** The 2026-09-05 repair was a careful pass. It swept m1
for properties deriving a class empty at their own commit, **introduced a fifth instance while doing
so** — in the very task it rewrote — replaced an unsatisfiable property with a vacuous one, replaced
an undecidable class with another undecidable class, and dropped two of the three relocations it
made, including the one whose own instruction was *"note it in both tasks so it is not dropped
between them."* Its author was not careless. Its author had no way to check their own new text
against the class they were sweeping, because the sweep was prose and the check came afterwards from
someone else. Thirteen documents, 61,364 lines, every one written to the same rigid shape — Files,
Interfaces, Properties, Mutations — and this repository is a Go module. That is a machine's job.

**The four checks, each derived from the document's own structure and none keyed to a heading.**

1. **A property with no mutation that would make it fail** (fatal). Found **m1 Task 16**: four
   properties and no mutation step at all, through five human passes. Two reporting arms beside it:
   where a document links mutations to properties by name — s1 writes *"Property 1 must fail"* and
   m1 writes it nowhere, and the linter derives which convention a document uses rather than
   assuming one — every property must be named by a mutation (seven unlinked in s1); and a task that
   supplies a finished Go test with no mutation set (189 across p1–p8, which is the *"roughly
   thirty"* of ledger-era memory measured properly).
2. **A property deriving a class empty at its own task** (2b fatal, 2a reporting). 2b is the one the
   repair needed: an empty-class property owes a relocation, the relocation owes a **reciprocal at
   the destination naming the source task and property**, and that is the plan's own instruction
   read back to it. It found both unlanded relocations and passed the one that landed. Naming the
   destination task in passing is not a reciprocal — m1 Task 15 named Task 13 twice while holding
   none of what Task 13 sent it, which is exactly the miss.
3. **A cross-reference that does not resolve** — `Task N`, `Task Na`, `M1-n`/`S1-n`/`O-n`, ledger
   item numbers, and plan-to-plan tokens. Item and ledger references are fatal and clean. Task
   references report, on three findings in documents this pass may not edit, all three real and all
   three printed on every run.
4. **A `Consumes` entry naming something no earlier task `Produces`** (4a fatal and clean; 4b
   reporting).

**Reporting versus fatal is written down, not implied.** Every check that reports states, in the
constant that sets its severity, exactly what turns it fatal. No check was weakened to make an old
plan pass; the severity moved and the derived class did not. And every check fatals if its class is
empty across the whole corpus — a gate reporting the clean run of a complete gate having read
nothing is this project's most expensive failure mode and this file refuses to be an instance of it.

**What it cannot see is in its own doc comment**, because the next author needs to know which half is
still theirs: it cannot decide whether a class is semantically decidable, it cannot tell a true claim
from a false one, it cannot decide that a stated mutation would refute the property beside it, and it
does not resolve spec-section or spec-line references.

**And it has a control fixture**, `TestThePlanLinterFlagsTheControlFixture`, in the shape of
`connect/mls`'s `TestHkdfConfinementFlagsTheControlFixture`: a synthetic plan carrying one instance
of every defect **beside** one instance of the correct form, read through the same constructor the
corpus is read through, with each defect required to come back. Three of the four checks report
rather than fail today; a reporting check that quietly stopped deriving anything would be
indistinguishable from one with nothing to report, and this is what keeps the two apart.

---

**The six m1 findings, and the one measurement that decided the largest of them.**

**HIGH — a claim that is false as a matter of Go semantics, in six places.** M1-43 said
*"`stagedRef` being unexported confines EVERY `GroupEngine` implementation to package
`connect/message`"*, and that was the sole stated reason the adapter's home was forced. **Compiled
on the pinned go1.26.5 in a five-line throwaway module:** a keyed composite literal naming only
exported fields is legal across packages, so a foreign type declaring
`Process(...) (*msg.EngineProcessed, error)` and returning `&msg.EngineProcessed{Kind: 3, Raw: b}`
builds green and satisfies `msg.GroupHandle`. What the compiler refuses is the field and nothing
else: *"cannot refer to unexported field stagedRef in struct literal"* for a keyed literal naming
it, *"implicit assignment to unexported field stagedRef"* for an unkeyed one. **Only populating
`stagedRef` is confined.** All six statements corrected, and the argument redone on true premises:
the adapter lives in `message/engine.go` because **§2.2 line 180 puts it there** and because it is
the one implementation that carries a staged `mls` commit through `stagedRef` — a **choice**, not a
forcing, and M1-43 now says so. The news for §6 is better than the wrong claim was: Gate 5's swap is
not confined to one package's source tree, and what a foreign engine gives up is the unforgeability
guarantee rather than the ability to exist. §6 owes one sentence saying so; recommended, not taken.

**HIGH — an unsatisfiable property replaced by a vacuous one.** Task 9 Property 3's headline —
*"`*mls.Group` does not satisfy `GroupHandle`"* — was asserted by nothing. Its two teeth were (i) *"a
test asserting `var _ GroupHandle = (*mls.Group)(nil)` must not exist"*, which cannot fire in any
state where the test binary builds, and (ii) a restatement of Property 4. **A non-event is not an
assertion.** The headline is deleted. What replaces it has a mechanism, a class and a member: *no
method on `GroupEngine` or `GroupHandle` names a type from `connect/mls`*, over a class that is 27
members from this task's first commit, which is the property that actually refuses the one reshape
Gate 5 exists to stop. The 13-mismatch table stays as the argument for Task 9a rather than as a
property, and mutation 7 now records that **the compiler** refuses it — the assertion does not build
— rather than asking for a gate that searches for a line which cannot exist in a buildable tree.

**HIGH — the CP3b prefix still did not close, one leg further along.** The 2026-09-05 repair made
the external-leg list authoritative and exhaustive — *"tasks 1–16 and 9a, plus four legs outside this
plan"* — and in the same pass **deleted Task 6's only production `StreamIndexReserver`
implementation**, leaving the interface and a test-only fake, **without adding it to the list**. The
list is now five, the fifth is the durable reserver, and it is stated where it bites: §5.6 says a
reused `stream_index` is a reused nonce under a reused `record_key`, *"a total break of both AEADs
for that record"*, so a CP3b run over the fake proves the record layer and not the client. Owned by
the unwritten sdk store plan (O-5, blocked behind S1-9), carrying M1-5's keying ruling and M1-25's
fsync cost. The alternative — give Task 6 back a production implementation and put `os` into a
package whose whole production import set is seven `crypto` packages, `fmt`, `io`, `mls` and
`mls/syntax` — is stated and not taken.

**HIGH — the fifth empty-derived-class, the one the repair introduced.** Task 7 Property 1, as
rewritten, derived *"every path from `Next` … to a `RecordAeadHead`/`RecordAeadBody` call"* and asked
for an AST check on each member of that reached class. **Measured 2026-09-06: zero members at
Task 7.** `RecordAeadHead`/`RecordAeadBody` are declared by Task 5 and called by nothing until
Task 11's `SealRecord`; `Next` has no production caller either. The shape the property named for its
own second mechanism — `aad_test.go`'s discard gate — fatals on an empty class, so as written it
fails on arrival, and written without the guard it passes vacuously. Repaired the way the other four
were: the AST check and the behavioural test stay at Task 7 over `Next`, a one-member class from this
task's first commit; the reachability walk moves to **Task 11 Property 3**, which names Task 7
Property 1 back.

**HIGH — two relocations that never landed at their destinations.** Task 9 Property 2's relocated
half was to become *"a derived-class gate over readers of `EngineProcessed`"* at Task 9a; what had
landed was a claim about what the adapter **writes** into `Raw`. Task 13 Property 4's was to become a
derived-class gate over readers of the provisional epoch value at Task 15; nothing landed at all.
Both halves are now at their destinations — Task 9a Property 3 carries the reader gate over a
two-member class beside the producer half, Task 15 gains **Property 6** over the fan-out's own
readers plus two mutations — and each names its source property back.

**MEDIUM — an undecidable class replaced by an undecidable class.** Task 13 Property 2 half B was
rewritten to derive *"every package-level function returning a 32-octet secret"*. Measured against
source: `WriteKey` (`connect/message/writeauth.go:158`) and `ReadKey` (`:172`) return **`[]byte`**,
so *"32-octet"* is not readable off any signature — it is the same semantic question one clause
further along. Half A, the sampler's parameter list being exactly `(io.Reader)`, is decidable and is
kept. Half B is regrounded on the sampler's **reachable set**: it must reach its own `io.Reader` and
must reach nothing in `keyschedule.go`, `handle.go`, `writeauth.go` or any `hkdf` entry point.
*Reaching a derivation* is decidable where *being a derived value* is not, and it is what refuses
mutation 3 whatever the return type is. The identity question stays with the author and with M1-17,
and the plan now says so.

**And one finding of check 1 in m1 itself, which no human pass had reported:** Task 16 stated four
properties and no mutation. It now states seven, each naming the property it refutes.

---

**Verified by running, not by reading.** `go build ./...` green; `gofmt -l` clean; `go vet ./...`
clean. All six plan-linter tests pass over all twelve plan documents. The repair was then **checked
by reintroducing it**: deleting Task 16's mutation set turns check 1a red; stripping the reciprocal
at Task 15, at Task 9a, or at Task 11 turns check 2b red in each case, naming the source property and
the destination; and pointing Task 7 Property 1's relocation at a task that does not exist turns 2b
and 3a red together. The `stagedRef` claim was disproved by compiling, not by argument, and the
compiler's two refusals are quoted in M1-43.

**One pre-existing failure, not caused by this change and not fixed by it.**
`TestEveryDependencyOfThisModuleIsOneSpecB22Allows` (`deps_test.go`) is red at `0e4359d` and stays
red: `github.com/urnetwork/connect/mls` is in this module's closure, reached through
`connect/message`, which §2.2 allows while forbidding `connect/mls`. Confirmed by running the gate
with `planlint_test.go` removed from the tree. It is ledger item 11's question — *"§2.2 does not say
whether allowing a package allows the module behind it"* — arriving as a failing test rather than as
a hypothetical, and it wants a ruling rather than an allow-list edit.

**Findings in other plans, reported and deliberately not fixed**, per the instruction that this pass
runs the linter everywhere and repairs only m1: p8 line 883 attributes `profile.go` in prose to a
task number one below the heading p8 gives that file; the interface registry cites a p1 task suffix
p1 does not declare; the p6 citation in m1's, s1's and this ledger's R1 paragraph names a task number
above the twenty p6 declares, so the error is in three documents and the linter cannot say which is
right; seven s1 properties are named by no mutation in a document whose mutations name properties
throughout; and 189 p1–p8 tasks supply a finished test with no mutation set. Every one prints on
every run.

**Index checked before the commit:** `git ls-files` and `git ls-tree -r HEAD --name-only` compared,
per the standing rule on this machine.

**Reviewed by:** the author, as a diff, against the six findings handed over, Spec A §5, §5.6, §5.11
and §6, `connect/message` source, and a compiled reproduction of the `stagedRef` claim. The linter is
the review that runs next time.


### 2026-09-06 — two owner rulings: `connect/message` is split so the server cannot link MLS, and the submit leg is `s2`'s

**Change:** the m1 plan, Spec A, Spec B's revision history and this ledger. **No code.** The code
move — creating `connect/messagegroup` and moving `xwing.go` into it — is a separate commit in the
`connect` tree, and another agent holds that tree.

*On the date in this heading:* the machine's clock says 2026-09-05, and `c089bb3` — the linter
commit the entry above this one describes — is committed 2026-09-05 while every document calls that
pass 2026-09-06. This heading follows the documents' clock so the append-only log stays monotone; the
measurements below were taken 2026-09-05 and are dated as such where they appear. Recorded rather
than quietly reconciled, because a date that drifts by one is how a two-day gap gets inferred later.

---

**Ruling 1 — `connect/message` splits, and the property is a capability rather than a habit.**

The trigger was a live red test, reproduced here before anything was written.
`go test ./ -run TestEveryDependencyOfThisModuleIsOneSpecB22Allows` at `c089bb3`:

> spec B §2.2 forbids these outright and this module reaches them:
>   github.com/urnetwork/connect/mls

**Every claim in the brief was measured and every one reproduced.**

| Claim | Measured |
|---|---|
| the gate fails at `c089bb3` for `connect/mls` | yes, on all four release platforms and this developer's own build |
| `connect/mls` enters through `connect/message` | `go list -deps -test ./...`: **exactly one** direct importer in a 481-package closure |
| inside it, through `xwing.go` alone | yes — the only non-test file naming `mls.` |
| `connect/mls/syntax` is separately allowed | yes, `deps_test.go:146`, spec B revision 10 |
| `msgrepo` uses X-Wing nowhere | `grep -rn 'Xwing' --include='*.go'` returns **0** |

**The split was derived rather than accepted, and the authority is §12.1.** Spec A §12.1 is the
published surface Spec B restates character for character, and §5.2 summarises it: *"Spec B's
server-side code never seals or opens."* Measured against this module: every `message.X` symbol it
names, tests included, is **35 distinct symbols**, and all 35 are declared in `record.go`,
`codec.go`, `attachment.go`, `writeauth.go` or `errors.go`. *(This entry said 37 when it was written
and the figure was wrong in both directions; corrected 2026-09-06 by re-measuring. The raw grep
returns 38 strings, two of which are the file names `message.proto` and `message.yml` in prose, and
one of the remaining 36 is `message.ProtoReflect` at `peer/peer.go:902` — where `message` is a
parameter of type `proto.Message`, in a file that does not import `connect/message` at all. The five
declaring files are unchanged, which is what the split's derivation actually rests on.)* So
`connect/message` keeps those five
plus `recovery.go` and §12.1's half of `rendezvous.go`; everything else m1 writes — the key
schedule, both ratchets, the reserver, the session, the sealer, the wraps, the epoch fan-out, the
cards, the blob derivations, §6's engine and its `connect/mls` adapter — goes to
`connect/messagegroup`.

**Three places the derivation disagreed with the brief, all three findings rather than defects.**

- **`aad.go` stays, and not for the reason given.** The brief lists it among *"the record layer the
  server genuinely parses"*. It is not: this module calls `AADHead`, `AADBody` and `BodyBinding`
  **zero** times, and §12.1 A-9 says those three are *"deliberately on no line of §12.1 because
  the server never decrypts"*. It stays anyway, because `BodyBinding()` is a **method** on
  `RecordHeader` — Go permits a method only in its type's own package, so the move is a shape
  change to landed, vector-tested code — and because `aad.go` reaches only `connect/mls/syntax`,
  which §2.2 allows. The property the ruling protects is *"the server cannot link an MLS parser"*,
  not *"the server links only §12.1"*; the narrower one is a test, and it is still the one
  ledger open item 7 asks for. Filed as m1 **M1-46**.
- **`recovery.go` and `rendezvous.go` are genuinely on both sides.** §12.1 publishes
  `RecoveryProof` **and** `VerifyRecoveryProof`, and nine rendezvous functions; those stay in
  `connect/message`. The client half of §5.14 — the 5,238-octet deposit sealed under X-Wing, and
  the five signers — cannot: X-Wing is the file that carries the `connect/mls` edge. So
  `rendezvous.go` exists in both packages, one file per side, and the line between them is §12.1's.
- **`RecoveryProof` is a signer on a surface whose own closing sentence is *"The server gets
  verifiers and no signers"*.** Pre-existing; the split makes it visible. Filed as m1 **M1-47**, to
  be ruled with M1-29, which is the same question about `DepositVerifyKey`.

**Task 9a's adapter was the sharpest instance, and M1-43's correction did useful work.** The plan
put the `connect/mls` adapter in `message/engine.go` — the package the server imports — citing
§2.2 line 180. §12.1 gives the server *"no MLS type"* and `GroupHandle` is twenty-three of them,
so interface, adapter **and `EngineProcessed`** all move. The togetherness is forced: `stagedRef` is
unexported, so an adapter in `messagegroup` over an `EngineProcessed` left in `message` could not
populate it, and §6's unforgeability argument would have been lost to a directory change nobody
would have read as a security decision. Under M1-43's **old, false** premise — that `stagedRef`
confined every implementation — that consequence was invisible.

**The sibling name is load-bearing, and it was probed in both directions rather than argued.**
`allowedDependencies` carries `connect/message` as a **subtree** (`deps_test.go:145`). Against a
working copy of `connect` with the split applied and a throwaway importer in this module:

| client half at | imports `connect/mls` | gate says |
|---|---|---|
| `connect/messagegroup` | no | **FAIL** — "not in spec B §2.2's allow list" |
| `connect/message/group` | no | **silence** — the subtree entry covers it |
| `connect/message/group` | yes | FAIL, but only because `connect/mls` is separately forbidden |

So under a subtree child the server could link the whole key schedule, both ratchets, the session
and the sealer with the gate saying nothing — which is the *"does not call one"* property the
ruling rejects. Written into the plan, into Spec A §2.2 and into Spec B's revision 13 as a
do-not-tidy.

**Four gate scopes move with the split, and three of the four move silently.** Every one derives its
class over a directory list, and a gate whose root is missing reports clean having read nothing.
Read out of `connect` source: Gate A's `forbiddenScanRoots = {".", "../message"}`
(`mls/crypto_forbidden_test.go:46`) needs `"../messagegroup"`; **Gate B walks Gate A's list**
(`mls/crypto_test.go:7781`), so the same one line fixes it — and Gate B is the one that fails
loudly, because its two rows for `XwingGenerateKey` and `XwingEncapsulate` resolve against the
declaring package, so the move forces `entropy_test.go` to move in the same commit; Gate C's
`authScanDir = "."` (`message/writeauth_test.go:1624`) leaves the client half with no constant-time
gate at all; Gate D's `joinScanRoots` (`message/record_test.go:673`) leaves the client half outside
the class-and-bucket scan while `joinAllowedPaths` correctly does not move, because `record.go` does
not. Tabled in the plan's constraints section with the commit each belongs in.

**Spec B needs no amendment, and that was measured rather than reasoned.** With `xwing.go` and
`xwing_errors.go` moved in a working copy and **nothing else changed**, the same gate passes — no
edit to `allowedDependencies`, none to §2.2's ALLOWED or FORBIDDEN blocks. The gate's failure
message offers two readings, *"either the import is wrong, or §2.2 has grown"*; the import was
wrong. Spec B gains a revision-13 entry saying so and nothing else, because *"nothing changed"* is a
claim that has to be measured on this project. One thing recorded and **not** taken: adding
`connect/messagegroup` to §2.2's FORBIDDEN block would upgrade the gate's generic refusal to a
named one, but it needs a matching row in `forbiddenDependencies` and it is an owner's call.

**The X25519 wrappers, for the follow-on commit, with the recommendation labelled as one.**
`xwing.go` needs four wrappers, one sentinel and two pins from `connect/mls`. **(a)**
`connect/messagegroup` imports `connect/mls` and the import is correct — it is the client half and
the client holds the group. **(b)** `crypto/ecdh` directly: this is the shape that would let
`xwing.go` stay put and need no new package at all, and it is the one to refuse — it needs a
**second** entry in `ecdhAllowedPaths`, and G3 exists because `sdk.GenerateSharedSecret` returned an
all-zero secret on a low-order point. **(c)** a shared low-level home: rewires `connect/mls` for one
caller, and `connect/mls/x25519` would put a second child of `connect/mls` in the tree.
**Recommendation: (a).** And stated explicitly so it is not read as having been answered: (a) does
**not** answer `deps_test.go`'s reserved question about *"a second child of `connect/mls` entering
this closure"*, because nothing new enters this module's closure — `connect/messagegroup` is a
sibling, not a child, and this module does not import it. Verified by probe: making it import one
fails the gate by name. Filed as m1 **M1-48**.

---

**Ruling 2 — the client-side submit leg is an sdk plan, `s2`.**

Open item **127** moves from *"no written plan owns it"* to **OWNED**, and m1's **M1-42** closes with
it. The reasoning is the owner's: `sdk` already owns transport and storage, and Spec A §8.2's
`MessageStore` already declares `ReserveStreamIndex` and `StreamHighWater`, which is
`message.StreamIndexReserver` method for method and which m1 Task 6 now only interfaces. Shape (b)
— an `msgrepo`-side integration test over `harness` — was rejected: it reaches the milestone
sooner through a transport that is not the product's, so what it proves is the record half.

**`s2` does not exist and is now on the CP3b critical path.** m1's external-leg list goes from five
legs to six and `s2` owns **two** of them: the submit path (leg 4) and the durable
`StreamIndexReserver` (leg 5). **O-5 is answered** in the same stroke — `s2` inherits Task 6's
interface, its five properties and its whole mutation set, `TestStreamIndexNeverReused` included,
which §5.9 names as G5's and G11's and which no other plan owns. Leg 6 is the split itself.

---

**One correction to the entry above this one.** The 2026-09-06 linter entry read the red dependency
gate as ledger item 11's question — whether allowing a package allows the module behind it —
*"arriving as a failing test rather than as a hypothetical"*. That diagnosis was wrong. Item 11 is
about the ~204 packages of 31 modules that arrive behind `connect`'s root; this was one package of
the **same** module reached by one import, and no rule about modules would have answered it. The
entry's second half — *"it wants a ruling rather than an allow-list edit"* — was right, and the
ruling turned out not to be about §2.2 at all. Corrected in open item **129**.

**The plan linter was run before and after, and it caught an instance of its own target class in
this pass's new text.** Before: green, with 19 reporting findings against m1. After the first draft
of these edits: **`check 2b` fatal** — *"m1 Task 3 Property 6 states its derived class is empty at
this task and names no later task where the class first has a member"*. It was a real defect and it
was mine: rewriting Property 6's scope for the split, I wrote that the class *"has no member on the
other side"*, which is a claim about `connect/message` that the linter correctly could not
distinguish from a claim about the property's own class. The class is not empty — at Task 3's
commit it has exactly one member, `StorageRoot` — so the fix was to state the count instead of
the absence. **This is the fourth consecutive pass over this plan to introduce a fresh instance of
the class it was sweeping, and the first where the sweep's own output was checked before the
commit.** After: green.

The linter's other movement is reporting and expected: m1's plan-token findings go from 16 to 42,
because Ruling 2 makes the plan name `s2` many times and `s2` has no document. That is the ruling
being recorded, not a defect, and the check's own severity note already says *"today s2 through s10
are cited as owners of unwritten work, which the plans say on purpose"*. The three pre-existing
findings in other plans (p8's `Task 2a`, the registry's `p1 Task 17b`, the `p6 Task 23` cited in
three documents) are unchanged and still print on every run.

**The msgrepo suite is red at this commit and the red is expected.**
`TestEveryDependencyOfThisModuleIsOneSpecB22Allows` fails because `connect/message` still imports
`connect/mls`. **What turns it green is the `connect` commit, not anything in this repository.** No
allow-list entry for `connect/mls` was added, the gate was not skipped, and it is not marked as a
known failure. Everything else in the module builds: `go build ./...` is green.

**Index checked before the commit:** `git ls-files` and `git ls-tree -r HEAD --name-only` compared,
per the standing rule on this machine.

**Reviewed by:** the author, as a diff, against Spec A §2.2, §2.3, §5.2–§5.7, §6 and §12.1,
Spec B §2.2, §5.3 and §13 item 8, `msgrepo/deps_test.go`, `connect`'s four gate files read for
their scan roots, and two working-copy probes of the dependency gate — one with the split applied
and one with the client half placed under `connect/message/` instead.

### 2026-09-06 — the split finished: the move list that leaves a package uncompilable, and a client half with no constant-time gate

The 2026-09-06 ruling entry above created `connect/messagegroup` on paper. This pass finished the
work that entry started and did not complete. **No code. No ruling.** Three documents changed: the
m1 plan, Spec A (revision **A-13**), and this ledger.

**Every claim in the brief was measured first. All of them reproduced in substance; three reproduced
with different numbers, and in each case the real number is worse.** They are recorded here with the
brief's figure beside the measured one, because a brief that is trusted on its arithmetic is a brief
nobody re-measures.

**1 — the move list left `connect/message` uncompilable, and no gate the plan cites could see it.**
The plan named the move set three times with three different and all-wrong counts: *"the two files
and `entropy_test.go`"*, *"moves `xwing.go`, `xwing_errors.go` and `entropy_test.go`"*, and *"two
files moved, one scan root added, one package created"*. **`xwing_test.go` and
`xwing_vectors_test.go` are `package message`, reference X-Wing symbols, and were named nowhere in
the plan, in Spec A or in this ledger.** *(The brief put their reference counts at 112 and 212;
measured at `1db6ec3` they are 149 and 83 case-sensitive matches of `Xwing`, 151 and 253
case-insensitive. Neither counting reproduces the brief's figures — and a count is not what the plan
should have carried, which is the point of what replaced it.)*

Reproduced on the pinned toolchain against copies of the two packages, with the `connect` tree
itself untouched: **all five files moved, `go vet` clean on both halves; the production pair alone
moved, `go vet ./message/` fails with `undefined: XwingSeedSize` at `xwing_test.go:29:5` while
`go vet ./messagegroup/` is clean; `entropy_test.go` left behind, the same shape at
`entropy_test.go:143:13`.** The middle case is the one that matters: **Gate B resolves its two rows
against the *declaring* package**, finds `entropy_test.go`'s refusals in `messagegroup` exactly
where it expects them, and passes over a `connect/message` that does not compile.

The fix is not a fourth count. **The plan now derives the set** — every file of `connect/message`
naming a symbol declared in `xwing.go` or `xwing_errors.go`, which at `1db6ec3` is five — and the
two downstream statements point at the derivation instead of restating it. `message/doc.go` is
called out as a **modify**: its first sentence still calls the package the X-Wing KEM.

**2 — Spec A section 6 still named the old package six lines from a sentence the ruling changed.**
Lines 1939-1940, `Raw []byte // opaque to connect/message` and
`stagedRef any // engine-private; connect/message never inspects it`, sat inside the same block
whose closing sentence the ruling had already changed to `connect/messagegroup`. The plan quotes
that block **normatively three times**, so the stale text was propagating. Both lines amended; all
three plan quotations and the three derived sentences in M1-43 follow.

**3 — the split leaves the client half with no constant-time gate, and this is its one real cost.**
Four gate scopes move and three move silently. Gates A, B and D are a root added to a list. **Gate C
is `authScanDir = "."` — a directory** — so `connect/messagegroup` cannot be added to it and owes
its own copy. Until that copy exists every file m1 writes lands ungated, **including the two files
M1-45 already names as members of the comparator class**: Task 20's MIME sniffer and Task 24's
`REACTION` validator. M1-45 says *"Blocks: Tasks 20 and 24"*, which against a gate that does not
walk their directory blocks nothing — a finding filed against a rule with no scope. The gate table
now carries an owner column, every row is wave 0's, **leg 6 of the Definition of done owes the Gate
C copy by name**, Tasks 20 and 24 are blocked on it in their Files lines, and M1-45 records why it
is inert until then.

**4 — the repathing sweep, derived rather than sampled.** `connect/message` was grepped across both
documents and every hit ruled. **Spec A: 53 hits, 28 statements wrong** — seven release-gate or
scope statements (section 4.5 Gate 5, which built `connect/message`'s suite against a second
`GroupEngine` that section 6 declares in `connect/messagegroup`; section 4.6 Gate 6's audit scope;
section 5.9 G1's lint gate; section 11.1's fuzz and integration rows; section 11.3's timing rule;
section 13's A6 slice row), four file annotations that named no package although section 5's own
opening sentence says every annotation below does, six ownership sentences (5.12, 5.13 twice, 5.14,
7.4a twice), section 6's two `EngineProcessed` lines, and nine decision-table and package-comment
statements — **including section 0.2's A2, which read *"`connect/message` may import `connect` and
its peer `connect/mls`"*, the exact edge the split exists to forbid.** *(The brief's sample was four
gate statements, five ownership sentences and one annotation; the derived class is larger in every
category, which is the difference between a sample and a sweep.)* Spec B was re-checked and needs no
amendment, as its revision 13 already recorded.

The plan's own contradictions were repaired with it: `EngineProcessed` *"declared in
`connect/message`"* in the same task whose later lines say the opposite; a mutation telling an
implementer to put an `*mls.Group` in `message`, which after the split cannot import `connect/mls`
at all; `message.Xwing*`, `message.StreamIndexReserver`, `message.GroupSession` and
`message.StorageRoot`; and the divergence accounting.

**The divergence accounting was stale exactly as the brief said, and this one reproduced to the
number.** A-12 closed **seven** of the fourteen — six of the eleven added files are now named in
section 2.2's tree (`streamindex.go`, `session.go`, `seal.go`, `card.go`, `rendezvous.go`,
`reaction.go`) and the one moved function is closed by section 5.3's amended annotation — and
**one** was marked closed. The item read as thirteen live divergences where seven were live. M1-36's
claim that *"every file annotation elsewhere in Spec A has been amended"* was false on the day it
was written; A-13 makes it true and the plan now states it as a measurement.

**5 — three measurements that were wrong, in paragraphs claiming they were verified.**

- **"37 distinct symbols" is 35.** A raw grep returns 38 strings; two are the file names
  `message.proto` and `message.yml` in prose, leaving 36; and one of those 36 is
  `message.ProtoReflect` at `peer/peer.go:902`, where `message` is a **parameter of type
  `proto.Message`** in a file that does not import `connect/message` at all. The number backing
  *"derived rather than accepted"* had itself been accepted. Corrected in the plan and in this
  ledger's 2026-09-06 entry, which repeated it. The five declaring files are unchanged, which is
  what the row derivation actually rests on.
- **Seven of seven spec-line citations were wrong, not five.** Six drifted by two or three lines —
  the signature of citations taken against a copy from before A-12's own insertions — one by nine,
  and **one also named the wrong section** (E2 is section 5.10's, "Corrections adopted in MASTER",
  not 5.11's). The paragraph asserting *"every spec-line citation in this document was re-read
  against source after A-12"* is **not restated**: that claim has now been broken twice, so each
  citation carries a short quotation beside its number instead. The quotation survives an insertion
  above it; the number does not. The plan linter does not resolve these, which is why the check has
  to be cheap enough for a human to do.
- **Task 18 adds a second server-side `hkdf` entry point and the plan's enumeration missed it.**
  `message/recovery.go` expands `recovery_root` for `recovery_sig_seed` (section 5.7) inside a
  function section 12.1 publishes and the plan keeps server-side, while Gate A's
  `hkdfExtraCallSites` (`crypto_forbidden_test.go:444`) has exactly one reviewed row,
  `../message/writeauth.go`. Task 18 now owes Gate A a second row in its own commit, and M1-16
  carries the full re-enumeration. **This is the one Gate A obligation the split does not silence**:
  `../message` is already a root, so it fails loudly whether or not `../messagegroup` is ever added.

**6 — two things recorded and neither ruled.**

- **M1-48, the X-Wing home.** The recommendation is **(a)**: `connect/messagegroup` imports
  `connect/mls` legitimately, because it is the client half and the client holds the group. **(b)**,
  `crypto/ecdh` directly, is refused because guardrail G3 exists — `sdk.GenerateSharedSecret`
  returned an all-zero secret on a low-order point — and a second reviewed ECDH call site would
  duplicate `mls.X25519PrivateKey`'s length and validity checks. The reasoning is recorded as
  reasoning; the item now carries *Blocks: wave 0* and an explicit **status: open**. The ruling is
  the owner's.
- **Ledger open item 130, m1's M1-49 — `deps_test.go:145` carries `connect/message` as
  `subtree: true`** while the comment above `allowedDependencies` (`:89`) says the list is *"at the
  granularity section 2.2 states it"* and section 2.2 states a **package**. That gap is what made
  `connect/message/group` invisible; the sibling name routes around it and does not close it. Filed
  with the measurement and the two available shapes. **Not ruled** — the rule is Spec B section
  2.2's and the gate is this module's.

**The plan linter was run before and after, and this is the first pass over this plan in five that
did not introduce a fresh instance of the class it was sweeping.** Before: green, findings as the
2026-09-06 entry records them. After: green, and the finding set is **identical line for line** once
line numbers are normalised — the same 11 check-2a findings on the same properties, the same
check-2b silence (no relocation left unlanded), the same 42 plan tokens in check 3c, the same
check-4b row. Nothing this pass wrote states a derived class without its membership, and nothing it
moved failed to land.

*One caveat worth writing down, because it is a shape this project keeps finding: the invocation in
general use, `go test ./ -run TestThePlanLinter`, matches only
`TestThePlanLinterFlagsTheControlFixture` and runs **none** of the five checks over
`docs/plans/*.md`. The five were run here by naming them. A gate whose usual invocation reads its own
fixture and not the corpus is worth an owner's attention; it is recorded here rather than fixed,
because renaming tests is a change to the gate and this pass changed no code.*

**The msgrepo suite is red at this commit and the red is expected**, for the reason the 2026-09-06
entry gives: `connect/message` still imports `connect/mls`, and what turns it green is wave 0's
commit in the `connect` tree. No allow-list entry was added, no skip, no known-failure marker.
`go build ./...` and `go vet ./...` are clean; the only test this commit can affect is the plan
linter, and it is green.

**The `connect` tree was not modified.** It was read at `1db6ec3` for the gate scopes and the move
set, and the three compile probes ran against copies in a scratch directory with a `replace`
pointing at it. That tree moved to `c7af659` during this pass, from another author; re-checked,
`git diff 1db6ec3 c7af659 -- message/` is empty and so is the diff over `mls/crypto_forbidden_test.go`
and `mls/crypto_test.go`, so every measurement and every line citation above still holds at the tip:
`forbiddenScanRoots` at `:46`, `hkdfExtractAllowedPaths` at `:83`, `ecdhAllowedPaths` at `:90`,
`hkdfExtraCallSites` at `:444`, Gate B at `crypto_test.go:7781`, `joinAllowedPaths` at
`record_test.go:648`, `joinScanRoots` at `:673`, `authScanDir` at `writeauth_test.go:1624` and Gate
C's comparator test at `:2473`.

**Index checked before the commit:** `git ls-files` and `git ls-tree -r HEAD --name-only` compared,
per the standing rule on this machine.

**Reviewed by:** the author, as a diff, against Spec A sections 0.2, 1, 3.3, 3.6, 4.5, 4.6, 5.1-5.14,
6, 7.4a, 11 and 13; Spec B section 2.2 and revision 13; `connect`'s four gate files read for their
scan roots and their failure modes; `msgrepo/deps_test.go` and `planlint_test.go`; and three
working-copy compile probes of the move set.

### 2026-09-07 — the gate that reported clean having read nothing was the plan linter itself, and wave 0 written as steps

*On the date in this heading:* the same drift the 2026-09-06 ruling entry records two entries above.
The machine's clock says 2026-09-05 and so does this commit's author date; the headings follow the
documents' own clock so the append-only log stays monotone, and 2026-09-05 is already the name of an
earlier repair here, so reusing it would make every back-reference ambiguous. **Measurements below
are dated by the machine — 2026-09-05 — and are dated as such where they appear.**

**No code in `connect`. No ruling.** Four files changed: `planlint_test.go`, the m1 plan, Spec A
(A-13's denominator only) and this ledger. The `connect` tree was **read** at `c7af659` and never
modified; every measurement below was taken against copies in a scratch directory.

**Every claim in the brief was measured before anything was written. All of them reproduced. One
reproduced with a number that names a narrower class than the sentence it corrects, and it is
recorded here with both readings** — because a brief trusted on its arithmetic is a brief nobody
re-measures, and that has now cut both ways twice.

**1 — the linter's documented invocation ran one test out of six, and the last entry prescribed it.**
`go test ./ -run TestThePlanLinter` matched only `TestThePlanLinterFlagsTheControlFixture` and ran
**none** of the five checks over `docs/plans/*.md`. It printed `ok` having linted nothing but its own
fixture. The 2026-09-06 entry above **recorded this and did not fix it** — *"it is recorded here
rather than fixed, because renaming tests is a change to the gate and this pass changed no code"* —
and then printed the broken command as the linter's invocation, so the next caller copied a command
that reads nothing. That is this project's most expensive failure mode aimed at the one mechanism
that has ever caught an instance of it.

Fixed as a **naming rule** rather than a longer command, so the invocation already in circulation
starts working instead of being replaced: the five checks are renamed
`TestThePlanLinterChecks…`, and a seventh test,
`TestThePlanLinterRunsUnderTheInvocationThisFileDocuments`, derives every `func Test…` off
`planlint_test.go`'s own source and fails on the first name outside the pattern — so a check added
next month under whatever name reads best cannot silently subtract itself from every run. It also
reads the header comment back and requires it to print the same command the constant holds, because a
command in prose beside a constant it disagrees with is the drift this whole file exists to catch.
The floor constant `planLinterTestFloor = 7` is the tripwire under the derivation: a matcher that
reads nothing fails rather than clearing every name there is.

**Verified against a plan with a known defect, which is the only check that means anything here.** A
throwaway `docs/plans/2099-01-01-slice9-z9-linter-probe.md` carrying three fatal defects — a task
stating a property with no mutation set (check 1a), a Consumes entry naming a task that does not
exist (4a) and a ledger citation that resolves to nothing (3d). Same file, same command, both
versions of `planlint_test.go`:

| `planlint_test.go` | `go test ./ -run TestThePlanLinter` |
|---|---|
| at `a48cd4c` | `ok  github.com/urnetwork/message-server  0.231s` |
| after the rename | `FAIL`, three checks red: 1a, 3d, 4a |

The probe file was deleted before the commit; `docs/plans/` holds the same twelve documents it did.

**2 — a FIFTH gate over `../message`, and a SIXTH the fifth's own grep cannot see.** The plan's
constraints table said *"the split moves four of these gates' scopes"* and the entry above says
*"`connect`'s four gate files"*. **Executing wave 0 exactly as written leaves `connect/mls` red with
26 errors** — measured, on a working copy — every one of the form *"`xwingNamedDeclarationsOfBothPackages`
classifies X and neither this package nor `../message` declares it"*, from
`TestNoXwingNamedDeclarationLandsInEitherPackageWithoutBeingClassifiedHere`
(`mls/extension_test.go:3665`), whose `messagePackageDir = "../message"` (`:3560`) is named in no
document. *(The brief characterised the message as* "classifies XwingSee…"*; the count 26 is exact
and the form is* "classifies `<name>` and neither this package nor ../message declares it"*, over 26
of the table's 28 rows — the two it keeps are `mls`'s own.)*

**The enumeration is replaced by a derivation, because a fifth found by execution proves the four was
never derived.** The rule: *every test-side constant or literal in `connect` naming the
`connect/message` package — as `"../message"` or as the go-tool pattern `"./message/..."`*. The
second spelling is half the rule and is exactly why the count was four: **`crossPlatformPackages =
{"./mls/...", "./message/..."}` (`mls/crossplatform_test.go:52`) matches no grep for `../message`**,
and it is a **sixth** scope — the nine product platforms simply stop being built for the client half,
and nothing anywhere reports it. Run over `c7af659` the rule returns six scopes needing a hand edit
(A, B, C, D, G, H), **five aliases of `forbiddenScanRoots`** that move for free and are listed so a
reader finds them ruled rather than missed (`extensionTypeSelectionRoots` at
`extension_lookup_test.go:68`, `epochMoverRoots` at `epoch_advance_test.go:120`,
`framing_guard_test.go:1047`, `TestNoPackageBeneathTheseRootsComparesAWholeOctetStringWithGoEquality`,
and `framing_group_seams_test.go`'s call sites), one allow-list path that does not move, and two
synthetic controls that read no directory. Verified: with Gates A, D and G applied and the move done,
`go test ./mls/ ./message/ ./messagegroup/` is **green in all three**.

**3 — the move set was short by a testdata corpus, and the derivation structurally could not see
it.** The stated rule — *every file of `connect/message` naming a symbol declared in `xwing.go` or
`xwing_errors.go`* — is a rule over **Go source**, and testdata declares no symbols. Move the five
source files without `message/testdata/vectors/rfc/` and `go build ./...` and
`go vet ./message/... ./messagegroup/... ./mls/...` are **clean** while **9 `messagegroup` tests are
red**, every one on `open testdata/vectors/rfc/xwing-draft10.json`. Measured, and the nine are named
in the plan. The rule now has its second half stated — *the fixtures those files read move with
them* — and the other four `message/` testdata corpora were checked one by one: every one is read
by a file that stays, so the split is clean.

Two things the move owes that **no test holds**, measured green with all of them left wrong:
`mls/interop/PINS.md` names the corpus at `:25`, `:83`, `:114` and `:119` and
`xwing_vectors_test.go` matches two of those *by text*, so the document and the gate stay in
agreement while both point at a path that no longer exists; `xwingPackageImportPath` (`:114`) is a
label handed to `types.Config.Check` and never resolved; and `xwing_errors.go`'s four sentinels read
`errors.New("message: xwing …")` while every other sentinel in both packages names its own package.
All three are Task 0 Property 5's, and Task 0's mutation 8 is the one mutation there that is
**expected to survive**.

**4 — the citation table added to fix seven wrong citations was seven wrong citations.** Every
*"Actually at"* number in it is the value at **`ecf0df6`, the parent commit**, while the sentence
directly beneath said *"against Spec A as this commit leaves it"* and the plan's own inline citations
already carried the `a48cd4c` numbers. Both measured, all seven:

| | table said | at `ecf0df6` | at `a48cd4c` |
|---|---|---|---|
| §2.2 tree / `messagegroup/` | 169–209 / 187 | 169–209 / 187 | **170–210 / 188** |
| §5.6 streamindex annotation | 1317 | 1317 | **1327** |
| §5.14 `HKDF-Extract` | 1804 | 1804 | **1817** |
| §2.2 `engine.go` row | 199 | 199 | **200** (199 is `session.go  seal.go`) |
| §5.10 E2 | 1556 | 1556 | **1566** |
| §6 `GroupEngine` block | 1894–1899 / 1898 | 1894–1899 / 1898 | **1907–1912 / 1911** |
| §8.2 `ReserveStreamIndex` | 3706 | 3706 | **3719** |

Seven for seven, and the shifts are +1, +10 and +13 by region — the signature of a measurement taken
one commit early. **The repair is not a fourth re-numbering.** A spec line number in this document
has now drifted in three consecutive passes and it is the one reference class `planlint_test.go` does
not resolve, so the table is rewritten with the **anchor first and authoritative** and the number
second and advisory: column one is a string that occurs in Spec A and is distinctive enough to
`grep`, and the header says in as many words that when the two disagree the anchor is right and the
number is stale. The way to re-derive every number is written into the table's own header as one
command, because **a number that cannot be re-derived does not earn a column**. Every anchor was run:
all seven resolve, and every number now agrees with the plan's own inline citation of the same fact —
which is the check, and which failed in all seven places before this pass.

**5 — three smaller ones, all reproduced.**

- **A-13's denominator.** It said *"ruling every one of the 53 hits"*. Measured at `ecf0df6`, the
  commit the sweep read: `connect/message` proper is **71 occurrences on 64 lines** (61 on 59
  excluding the revision table) and `connect/messagegroup` is 27 on 25, so **both package names
  together are 98 occurrences on 78 lines** (85 on 73 excluding the revision table). No reading of
  either commit gives 53. *(The brief's figures — 71 and 64 — reproduce exactly, and they are the
  `connect/message` half; the sentence they correct says* "grepping both package names"*, so the
  number written into A-13 is 98 on 78, with the split shown so either reading is checkable.
  Corrected as a denominator only: the sweep's **content** was independently re-derived and zero
  wrong statements remain in either document.)*
- **A probe's quoted output.** The plan said the production-pair-alone probe *"fails with `undefined:
  XwingSeedSize` (`xwing_test.go:29:5`)"*. Run: it prints
  `entropy_test.go:143:13: undefined: XwingGenerateKey` — byte-identical to what the plan attributes
  to the third probe, so two of three probes were indistinguishable by their reported result. **The
  defect is larger than the brief stated**: the two probes really are told apart, but by the half the
  plan never printed — the third probe also fails `go vet ./messagegroup/` with
  `xwing_vectors_test.go:823:9: undefined: entropyDeclaredName`, while the second leaves
  `messagegroup` clean. Both halves of all three probes are now stated.
- **One ledger sentence still named the old package.** *"Wave 1 complete is a `connect/message`
  that seals and opens records…"* against the plan's twin, which says `connect/messagegroup`.
  Repathed.

**Two more found while measuring, neither in the brief.** First: `hkdfExtraCallSites` is cited as
line 425 in two places and as 444 in five others, in the same two documents. Measured at `1db6ec3` **and** at
`c7af659`: the map is at **444** and its single entry at 445. Both 425s corrected. It is the same
class as finding 4 one layer down — a source anchor, which this project's plans claim are re-read
from source. Second: the m1 plan's *"not a claim that the other 39 are format-safe"* is 45 minus the
six wire-visible items — the item total when that sentence was written, and four passes have added
items since. It is 44 now, and the sentence says so along with why it was 39.

**6 — the wave-0 execution hazard nothing named: `mls` is CRLF and `mls` gates on it.**
`TestThePackageSourceIsOneLineEndingThroughout` (`mls/vectors_runner_test.go:1298`, the report at
`:1332`) derives the class off the directory and refuses a mixture; measured, `mls` is **137 of 137
`.go` files CRLF**. It went red the moment a reviewer's `sed` rewrote `crypto_forbidden_test.go` and
green again when CRLF was restored. **Wave 0 owes one-line edits to exactly three `mls` test files**
— `crypto_forbidden_test.go`, `extension_test.go`, `crossplatform_test.go` — so an exact-string edit
anchored on LF matches nothing in them, edits nothing, and reads as *"the change was made and was
harmless"*. Written into Task 0's steps as a named hazard, with the two verifications (`git diff
--stat`, and mutation 9). For contrast and because it matters to the same reader: `connect/message`
is genuinely **mixed** (6 CRLF, 12 LF of 18) and has no such gate, and `connect/messagegroup`
inherits the mixture, so anyone copying `mls`'s gate there later must normalise first.

**Wave 0 is now `## Task 0`, with Files, Interfaces, five properties, six steps and ten mutations.**
It was a paragraph, and a paragraph was executed twice on paper and came up short both times. It is
**not** one of the plan's 25 tasks and says so in its own header; it is leg 6, it lands in `connect`,
and whoever takes wave 1 does not execute it. Its mutation set is the six scope reverts and the two
move halves, each with the red or the **silence** it must produce — including mutation 8, which is
expected to survive and is the finding rather than the failure.

**One open item added, M1-50: Gate C's copy is not a copy.** Three of Gate C's four rules go through
`authVerifiersUnderGate` (`message/writeauth_test.go:2447`), which `t.Fatal`s on an empty verifier
set and then `t.Fatalf`s again unless `VerifyWriteAuth` and `VerifyRequestAuth` are among what it
found. Measured: `connect/messagegroup` declares **no** `Verify`-prefixed production function at
wave 0, and both named verifiers are in `message/writeauth.go` and stay. **So the literal copy the
plan and this ledger both prescribed fatals on arrival, twice, on correct code** — and it fatals
because of this tree's own house rule about empty derived classes, which is the right behaviour.
Task 0 ports the comparator half, whose class is not empty, and files the rest: either `messagegroup`
grows the verifier half when it declares its first `Verify*` — which on this plan's file table may
never happen, since §12.1 publishes every verifier and they all stay in `connect/message` — or
Gate C is rewritten onto a root list the way Gate A already is. Not ruled. M1-45 and M1-19 are filed
against a rule whose scope this item decides.

**Two statements in the 2026-09-06 entries above are superseded rather than rewritten**, because that
entry is the record of what was believed then: *"Four gate scopes move with the split, and three of
the four move silently"* is six and four, and *"`connect`'s four gate files read for their scan roots"*
is six. Both are corrected in the plan's constraints section, which is the live document.

**The plan linter was run before and after, under the renamed invocation, and the delta is zero.**
Before (six checks named explicitly, because the documented command could not select them) and after
(`go test ./ -run TestThePlanLinter`): check 1a **0**, 1b **7**, 1c **1**, 1d **0 / 189**, 2a **19**,
2b **0**, 3a **4**, 3b **0**, 3c **2**, 3d **0**, 4a **0**, 4b **6** — identical line for line.
Task 0 states five properties, ten mutations and one derived class with its membership count, and
added **no** finding to any check; M1-50 resolves; the intermediate run in which it did not was
caught by check 3b, which is the check working.

**`go build ./...` and `go vet ./...` are clean, and `go test ./...` is red in exactly one test**,
`TestEveryDependencyOfThisModuleIsOneSpecB22Allows`, for the reason the ruling section gives: the
`connect` tree still has `connect/message` importing `connect/mls`, and what turns it green is
Task 0's commit in that tree. No allow-list entry was added, no skip, no known-failure marker.

**The `connect` tree was not modified.** Read at `c7af659` for every measurement above; the move,
the six gate edits, the corpus move and all three compile probes ran against copies in a scratch
directory. `git status` in `connect` is unchanged from the start of this pass.

**Index checked before the commit:** `git ls-files` and `git ls-tree -r HEAD --name-only` compared,
per the standing rule on this machine.

**Reviewed by:** the author, as a diff, against Spec A §§2.2, 5.6, 5.10, 5.14, 6, 8.2 and revision
A-13; `connect`'s **six** gate scopes and the five aliases beside them, read for their roots and
their failure modes; `msgrepo/planlint_test.go` and `deps_test.go`; and a working-copy execution of
wave 0 in full — the move, the corpus, three gate roots, `go build`, `go vet` and
`go test ./mls/ ./message/ ./messagegroup/`.
---

### 2026-09-08 — wave 0 executed: `connect/messagegroup` exists, the dependency gate is green, and the description was short by seven kinds of edit

**The split landed.** `connect` on `beta/message`, one commit **`9acefd9`** on top of `c7af659` — 18
files, 430 insertions, 142 deletions. `connect/messagegroup` is a real package: `doc.go`,
`xwing.go`, `xwing_errors.go`, `xwing_test.go`, `xwing_vectors_test.go`, `entropy_test.go` and the
`testdata/vectors/rfc/` corpus, all moved with `git mv` so history follows and all recorded by git
as renames at 84–99% similarity.

**`TestEveryDependencyOfThisModuleIsOneSpecB22Allows` is green, and green the way the ruling
required.** `deps_test.go` and `go.mod` are byte-identical before and after — `git status` in this
repository was empty across the whole verification — and `go list -deps -test ./...` over `msgrepo`
now names exactly `connect`, `connect/message`, `connect/mls/syntax` (allowed by name, spec B
revision 10) and `connect/protocol`. `connect/mls` left the closure rather than joining an allow
list. The windows/amd64 build closure went from 460 packages to 459. `go test ./...` in `msgrepo` is
green in every package.

**Three passes described this move; executing it returned seven kinds of edit none of them
contained.** That number is this round's most useful output, and it is recorded in the plan as Task
0 Property 6:

1. **Production and test prose in `mls` naming `../message` as where X-Wing's second statement
   lives** — `mls/extension.go:568` and `:582`, `mls/crypto_test.go:7933` and `:7946`,
   `mls/extension_test.go:2247`, and three values inside Gate G's own classification table. Held by
   no test; false the moment the move landed.
2. **Five stale path references inside the moved `xwing_vectors_test.go` itself**, one of them
   inside a `t.Errorf` message, plus one in `entropy_test.go` and one in `xwing.go`. This commit
   created them, and they were found by running the defect class over the commit's own diff.
3. **`PINS.md:108`**, the fifth prose reference the four documented paths leave stale — **and a
   sixth statement in the same paragraph that was wrong before this pass touched it**: it claimed
   `git ls-files --eol` reports `i/lf w/lf` for the xwing corpus. It reports
   `i/none w/none attr/-text`, because the file is one line and a trailing newline, so git sees no
   line ending to classify. Corrected with the reason, since `attr/-text` is the half that matters.
4. **`connect/layering_test.go` owed four assertions, not one.** The load-bearing one is that
   `connect/message` may not import `connect/mls` — the ruling itself, which nothing in the
   `connect` repository held. It compiles cleanly forever and was visible only to this
   repository's dependency gate, in another module, on a run nobody makes before pushing. Also:
   `messagegroup` may not import `connect`, `message` may not import `messagegroup`, and neither
   `mls` nor `mls/syntax` may import `messagegroup`. The control fixture gained a blank import so
   the scanner is proven to find the new path.
5. **`cryptoImportPaths` is now a union over three roots** — the standing obligation below.
6. **Gate G's two failure messages** each named one scanned directory and would have misreported
   which trees they read.
7. **The interface registry's two statements of where X-Wing lives.** The working copy under
   `connect/research/` is excluded by that repository's `.git/info/exclude`, so the repair landed on
   the tracked copy here.

**A standing obligation on every m1 task, which nothing stated before this pass.**
`TestTheCryptoIsBuiltFromExactlyThesePackages` (`mls/crypto_test.go`) pins the **exact** import set
— as a whole, deliberately not as a ban list — of the packages `forbiddenScanRoots` walks, and
`cryptoSourcePaths` walks that same list. Gate A's one-line root edit therefore widened that pin,
and roughly eight other `mls` gates that alias the same list, over `connect/messagegroup`. **Every
production import added anywhere in `connect/messagegroup` must be written into `cryptoImportPaths`,
in `mls`, in the same commit** — and every file m1 writes lands there. The failure is a test of
`mls` going red over an edit made in another package. It is recorded in the plan's dependency policy
and again under Task 0 Step 6.

**Two claims the plan carried measured differently, and the implementer measuring is what corrected
them.**

- **Gate A is not silent, which the plan said in four places.** Reverting `forbiddenScanRoots` to
  `{".", "../message"}` on the landed tree turns the `mls` suite to 4701 PASS / **3 FAIL**:
  `TestNoEntropyTakingFunctionLivesWhereThisGateCannotCallIt`,
  `TestTheCryptoIsBuiltFromExactlyThesePackages` and
  `TestEveryTypeHoldingErasableKeyMaterialErasesAllOfIt`. What *is* silent is the hkdf entry-point
  and `.ECDH(` confinement over the client half, and that half alone — measured with a probe: with
  the root reverted and a bare `hkdf.Extract` and `.ECDH(` in a `messagegroup` production file,
  `mls` reports neither; with the root restored and the same probe still there, it reports both by
  path. The silent count across the six gates is therefore **three** (C, D, H), not four.
- **The derivation grep does not return what the plan said it returns.** At `c7af659` it returns
  **eight lines**: three scopes, two prose values inside Gate G's table, one allow-list path and two
  synthetic controls. **Zero aliases** — an alias holds no literal, which is what makes it an alias
  — and it misses **three of the six scopes**, because Gate B walks Gate A's list, Gate C's scope
  was `authScanDir = "."` and Gate D's was `{messageRoot, mlsRoot}` with `messageRoot = "."`. A
  scope spelled `"."` is as invisible to a grep for `"../message"` as one spelled `"./message/..."`
  was. The grep is one input to the derivation and is not the derivation.

**M1-50 is resolved, and the shape it recommended was measured to be unavailable.** The item
proposed porting Gate C's comparator half alone, *"whose class is every production function of the
directory and which is not empty at wave 0"*. It is empty at wave 0: the comparator class is derived
from the **scanned code's own imports**, and `connect/messagegroup` imports `crypto/ecdh`,
`crypto/mlkem`, `crypto/sha3`, `io`, `errors` and `connect/mls`, none of which exports a data
comparator, so a ported comparator half logs *"3 go files, 9 functions, 6 imports, 0 comparators in
the derived class: []"* and clears everything it read against an empty class. Two rules with no
member and one that clears everything is not a gate.

Gate C was therefore **rewritten onto a root list**: `authScanRoots = {".", "../messagegroup"}`,
replacing `authScanDir`. Each root is scanned **separately** and the scans are never merged, because
`TestAVerifierReachesOutOfItsPackageOnlyForTheConstantTimeComparison` is about calls leaving a
verifier's *own* package and a merged scan would have widened the coverage claim while narrowing the
rule. Only the emptiness refusal and the `VerifyWriteAuth`/`VerifyRequestAuth` coverage claim were
moved to the union — and that guard was not weakened to accommodate an empty package: pointing
`authScanRoots` at the client half alone still fatals with *"no root of [../messagegroup] declares a
verifier at all, so this gate is reporting clean having read nothing"*.

**What that does not buy is written down rather than left to be discovered.** The comparator rule
over `../messagegroup` has no member to catch until that package imports something exporting a
comparator; it is a live tripwire, not a live rule. And the scope is a written-down list: a new
`TestEveryPackageBuiltOnThisOneIsUnderTheConstantTimeGate` derives the half that can be derived —
it walks the module for production packages importing `connect/message` and fails on one that is not
a root — but it reports 25 directories walked and **0** importers today, because
`connect/messagegroup` does not import `connect/message` until m1 Task 1. Narrowing `authScanRoots`
back to `{"."}` is silent today, and that is recorded as a surviving mutation rather than as a
success.

**Fourteen mutations, each confirmed applied with `git diff --numstat` before its result was
believed, each reverted, three survivors and all three expected.** Caught: Gate G's root (exactly 26
errors); Gate A's root (the three tests above); the hkdf/`.ECDH(` probe with the root restored; the
class-and-bucket join probe with Gate D's root restored; the corpus left behind (9 red,
`go build` and `go vet` clean); the corpus without its `.gitattributes`; the LF-anchored edit against
a CRLF file (0 occurrences where a `\r\n` anchor finds 1) and the whole-file LF rewrite that turns
`TestThePackageSourceIsOneLineEndingThroughout` red; the production pair moved alone
(`entropy_test.go:143:13: undefined: XwingGenerateKey`); a package importing `connect/message`
outside `authScanRoots`; `authScanRoots` set to the client half alone; and `connect/message` given
an import of `connect/mls`. **Survivors:** Gate H's package pattern, which is silent everywhere but
a `t.Logf` count; the whole `PINS.md` / `xwingPackageImportPath` / four-sentinel group, which is
green with every one of them left naming `message`; and `authScanRoots` narrowed to `{"."}`.

**One prediction in the plan's own mutation set was refined by running it.** Removing the corpus's
`.gitattributes` turns `TestXwingVectorDirectoryDisablesGitsTextConversion` red and leaves
`TestXwingVectorFileWasNotSmudgedOnTheWayIn` **green**, not red: deleting the attributes file does
not re-smudge a file already in the working tree. It would go red on the next fresh clone, which is
exactly why the first test has to fail on the commit that removes the rule.

**Verified in `connect`:** `go build ./...` clean; `go vet ./message/... ./messagegroup/... ./mls/...`
clean; `go test -count=1 -v ./message/... ./messagegroup/... ./mls/...` — **7495 `--- PASS`, 0
`--- FAIL`, 0 `--- SKIP`**, `ok` on all four packages; `connect`'s own layering tests green; the
nine-platform cross build reporting *"9 platforms x 3 package trees built with CGO_ENABLED=0"* where
it reported 2; `TestThePackageSourceIsOneLineEndingThroughout` reporting all 137 `mls` files CRLF.
Every edit in both repositories was made byte-exactly with an asserted occurrence count and never
with `sed -i`, and `git diff --numstat` was read after each one, because a one-line intent that
reports the whole file has rewritten the line endings.

**The plan linter was run before and after, and the delta is zero.** `go test ./ -run
TestThePlanLinter`, 7 of 7 tests and 17 assertions: check 1a **0**, 1b **7**, 1c **1**, 1d
**0 / 189**, 2a **19**, 2b **0**, 3a **4**, 3b **0**, 3c **2**, 3d **0**, 4a **0**, 4b **6** —
identical line for line. Task 0 now states six properties, fourteen mutations and two class-deriving
properties with their membership counts, and added no finding to any check.

**Index checked before both commits:** `git ls-files` against `git ls-tree -r HEAD --name-only`, per
the standing rule on this machine. `connect` went 1079 → 1080 tracked files and both counts agree at
`9acefd9`.

**Reviewed by:** the author, by executing the move rather than describing it — the five source
files, the corpus, five gate scopes, the new layering assertions, `go build`, `go vet`, the full
`./message/... ./messagegroup/... ./mls/...` suite with both outcome counts, the nine-platform cross
build, `msgrepo`'s `go test ./...`, and fourteen mutations with their verdicts. The defect class this
commit was sent to close — *a scope or a statement that names `connect/message` where the subject is
now in `connect/messagegroup`* — was run back over the commit's own diff and then package-wide, and
returned items 1, 2, 3, 6 and 7 above.

### 2026-09-09 — the four findings after the split: a seventh gate scope, three sentences that were not true, and a log that could not say which kind of empty it was

**The split itself was not reopened.** 7,495 `--- PASS` / 0 `--- FAIL` / 0 `--- SKIP`, `deps_test.go`
and `go.mod` still byte-identical, `connect/mls` still out of `msgrepo`'s closure, the six gate
scopes still live. What follows is the review's four findings, closed in `connect` `449f3ab` and in
this repository's commit beside this entry.

**1 — There was a seventh gate scope, and it is the one that catches this tree's most persistent
failure.** `TestThePackageSourceIsOneLineEndingThroughout` (`mls/vectors_runner_test.go`) scanned
`mls` alone. It was not in the six-gate set wave 0 widened, so nothing widened it, and it is the gate
that refuses a package whose files disagree about how a line ends — the condition under which an
exact-string edit matches nothing and reports success, and under which a scanner anchored on a line
start reads a whole file as one body and *reports clean having found nothing*.

State the measurement precisely, because the obvious framing is wrong. **In git nothing was
inconsistent**: every blob of all three packages was already LF, and `git diff` was empty across the
entire drift, because `core.autocrlf=true` cleans on the way in. **The working tree — which is what
an anchored edit actually reads — was mixed**: `mls` 137 CRLF / 0 LF, `connect/message` 6 / 7,
`connect/messagegroup` 5 / 1. Files smudged at checkout land CRLF; files written in-session by tools
land LF. `mls` stayed uniform **because it had this gate**, and the two packages without one are what
a package with no gate looks like after a fortnight.

Widened to a **derived closure**, not a list, per guardrail 5. `lineEndingScanRoots` starts at `mls`,
follows every `"../..."` path **literal** its source hands to something — read off the syntax tree,
so a directory that prose merely mentions is not mistaken for one a gate opens — and repeats in
whatever that reaches. It lands on exactly the packages that read each other's *text*: `mls` scans
`../message` and `../messagegroup`, `../message` scans `../messagegroup` and `../mls`, and
`../messagegroup` names `../mls` back. A root added to any of those scans is added here with nobody
remembering to. Three things it declines, each because the rule declines them: a literal resolving to
nothing on disk (`"../elsewhere"`, `"../nowhere"` — fixture names); a literal outside this module
(`joinScanRoots` reaches the `sdk` repository beside `connect`, a different checkout with its own
`autocrlf`); and a literal that cleans to `".."`, which is **not** hypothetical — the derivation's own
`"../"` prefix is such a literal, and the first run of the closure over its own source read it as an
instruction to judge `connect`'s root package. The coverage claim is checked rather than asserted,
against `forbiddenScanRoots`.

Both working trees were normalised to CRLF, which is what this checkout's `autocrlf` would have
produced. **That changed no blob**: `git add` staged the eight files as no diff at all, and the eight
do not appear in the commit. Judged **per package**, pinned to neither ending.

**2 — Two sentences said `connect/messagegroup` imports `connect/message`, and package-wide there
were three.** It does not: measured 2026-09-05, its production imports are `crypto/ecdh`,
`crypto/mlkem`, `crypto/sha3`, `errors`, `io` and `connect/mls`, and
`TestEveryPackageBuiltOnThisOneIsUnderTheConstantTimeGate` reports **0** production importers of
`connect/message`. Two were in `message/doc.go` — the file wave 0 rewrote to close this very class —
and searching package-wide rather than in the diff, per guardrail 11a, found a third in
`layering_test.go`, three paragraphs above that same file's correct statement of the opposite. All
three now say something a measurement backs, or are gone.

**3 — Gate C shipped the log line the round before was told not to ship.** *"0 comparators in the
derived class: []"* reads identically whether the gate is armed or dead. **The design was not
undone** — the class is derived from the scanned code's own imports, which is what makes it self
extending, and M1-50 already records the honest residual. What was added is a line saying **which
kind of empty**: the imports it read, that none of those packages exports a function answering a
question about two data-shaped arguments, that the first comparison written over there brings that
package's whole comparator surface in on the same run, and that
`TestEveryPackageBuiltOnThisOneIsUnderTheConstantTimeGate` is the half doing work today. Guardrail
11a again: the identical bare zero sat one test below on the verifier set and got the same treatment.
The claim is now falsifiable and was falsified on purpose — a first `bytes.Equal` in
`connect/messagegroup` grew that class from **0 to 16** comparators on the same run and the gate
reported the violation.

Recorded where the root is declared: **narrowing `authScanRoots` back to `{"."}` is silent today**
(mutation 14). Re-measured rather than copied — the full `message` suite is `ok` under that mutation.

**4 — The count of what wave 0's description was short by is nine, not seven.** Two more members of
the same class turned up on an independent pass over the same diff: finding 2's three sentences, and
finding 1's seventh gate scope. **Why it moved is the interesting half**: wave 0's own rule 11 pass
was scoped to path references inside the moved files, so it never reached the import-direction
sentences the same commit was writing two files over — which is guardrail 11a's warning, arriving as
a worked example rather than as advice. `2026-09-04-slice1-m1-message-crypto.md` Task 0 Property 6
now lists nine and says which two are late and why. **The heading of the 2026-09-08 entry above still
reads "seven kinds of edit"; it is corrected here rather than rewritten there, because a ledger that
edits its own past entries is not a ledger.**

Also under finding 4: **`connect/message`'s test binary reaches `connect/messagegroup` by filesystem
path** (Gate C's `authScanRoots`, Gate D's `messagegroupRoot`), so the split is one-way in the import
graph while the suite is coupled to the sibling directory existing on disk — `go test ./message/` in
a tree where that directory is gone fails outright rather than passing over a quietly smaller scope,
which is what those gates are written for. Stated in `connect/layering_test.go`, where a reader of
the layering rules will find it. It is a property of the design, not a defect.

**One claim in the review did not reproduce, and no change was manufactured for it.** The review said
the plan's mutation 7 states an effect that does not happen — that deleting the corpus's
`.gitattributes` turns both `TestXwingVectorDirectoryDisablesGitsTextConversion` and
`TestXwingVectorFileWasNotSmudgedOnTheWayIn` red. It does not say that. The 2026-09-08 commit had
already corrected it, in both places: Task 0 Step 5 mutation 7 reads *"**CAUGHT**, but in one test and
not two"* with the re-smudge reasoning, and the ledger entry above records the refinement. Left
alone.

**`p2`'s ~20 statements placing X-Wing under `connect/message` stay as written, and the ruling that
they should is upheld.** A landed plan is the record of what its tasks did; rewriting it to match a
later move falsifies the record rather than correcting it. What was owed and is now paid is **one
dated note at the head of `p2`'s File Structure table** — naming the seven rows, the move, the commit,
the reason, and the one row (`connect/message/doc.go`) that did not move — instead of twenty in-place
rewrites. That note first cited *"that plan's Task 0"*, which turned check 3a from four findings to
five because `p2` declares no Task 0; caught by running the linter, and rephrased.

**Mutations, `connect` `449f3ab`.** Eleven applied, every one confirmed to have landed with
`git diff --numstat` before its verdict was believed, every one reverted by restoring the file's
bytes rather than by `git checkout --`, which on an uncommitted file discards the work under it — a
mistake made once in this round and repaired by rebuilding the file from its source of truth.
**Caught (9):** an LF file in each of the three packages; a file mixed within itself; the closure
losing its siblings and the closure truncated to one root, both by the coverage assertion; a first
`bytes.Equal` in `messagegroup`; an `hmac.Equal` verifier in `message`, by both halves of G8; and
`authScanRoots` narrowed, re-measured as **silent** and therefore recorded rather than relied on.
**Survivor (1):** disabling the closure's file-literal-to-parent-directory branch changes nothing
today, because both siblings are also named as bare directory literals. **Control (1):** flipping all
of `messagegroup` to LF leaves the gate **green**, which is the per-package, ending-agnostic property
stated as something observable.

**Guardrail 11 was run against this round's own diff, for the classes it was sent to close, and it
found two.** A mention count measured over three packages and attributed to one — removed rather than
corrected, because a number in a comment about how often a comment says something is the most
perishable sentence a file can hold. And a date: the split had been "corrected" to `2026-09-05`, the
commit's author date, when the tree and this ledger both call it **the 2026-09-06 split**. Reverted;
the odd one out was the correction.

**Verified.** `connect`: `go vet` clean on the three packages; `gofmt` clean on every changed file;
`go test -count=1 -v ./mls/... ./message/... ./messagegroup/...` — **7495 `--- PASS`, 0 `--- FAIL`,
0 `--- SKIP`**, `ok` on all four packages; `connect`'s layering tests green; the cross-platform gate
reporting *"9 platforms x 3 package trees built with CGO_ENABLED=0"*, 27 subtests green; `git ls-files`
1080 = `git ls-tree -r HEAD` 1080 before and after. `msgrepo`: `go test ./ -run TestThePlanLinter`
**7 of 7**, and every check identical to the recorded baseline — 1a **0**, 1b **7**, 1c **1**,
1d **0 / 189**, 2a **19**, 2b **0**, 3a **4**, 3b **0**, 3c **2**, 3d **0**, 4a **0**, 4b **6**.
Every edit in both repositories was made byte-exactly with an asserted occurrence count and never
with `sed -i`.

### 2026-09-10 — the owner's `*.go text eol=lf` ruling: a pin that changes no git object, and the ninth log line

**The ruling, and where it landed.** `connect/.gitattributes` now pins `*.go text eol=lf`, matching
what this repository already does and for the reason this repository's own comment gives: *a gate
that matches on the text of a source file matches nothing at all* — which is not a gate failing, it
is a gate reporting the clean run of a complete gate **having read nothing**. `connect` `7525995`,
one commit, carrying the pin, the renormalisation and the log-line fix below.

**What it cost, measured before it was claimed. No git object changed.** `core.autocrlf=true` is set
at system scope here and cleans on the way in, so every tracked `.go` blob was **already LF**.
Comparing every `.go` entry of `449f3ab` against `7525995` by blob SHA: **473 of 474 byte-identical**,
and the one that moved is `message/writeauth_test.go`, by the log fix and nothing else. What the pin
rewrites is the **working tree** — **442 CRLF / 32 LF before, 474 LF / 0 CRLF / 0 mixed after** — and
the working tree is the only place the drift was ever visible and the only place an anchored edit
reads. The ruling was costed as "no blob may change"; it is paid, and it was verified rather than
assumed.

**The ruling's file count was 452; the measured count is 474 tracked `.go` files, of which 442 were
CRLF.** Recorded, not reconciled — nothing turns on it, because the pin is written as `*.go` and not
as a list of files.

**What it closes.** `connect/mls`'s `TestThePackageSourceIsOneLineEndingThroughout` holds the same
property as a gate, but **per package** and only over the scope it can derive: `namedSiblingPaths`
collects `"../…"` path **literals** off the syntax tree, so the closure reaches `../message` and
`../messagegroup` and **cannot reach a child directory at all**. `connect/mls/syntax` sat in exactly
that blind spot at **6 CRLF against 17 LF**, and `connect/message` imports it. The pin is the half of
the property no derivation reaches: every Go file in the repository, in every package, gated or not.

**`connect/protocol` was mixed BY DESIGN and now agrees rather than conflicts** — confirmed with
`git check-attr text eol` over all ten of its `.go` files, not assumed: every one answers `text: set` /
`eol: lf`, and both rules say `eol=lf`, so the general line subsumes the specific one instead of fighting
it. **The more useful half of that measurement is why it was mixed.** All seven `*.pb.go` files were
ALREADY pinned by `*.pb.go text eol=lf`, and five of them were CRLF on disk regardless — `eol=lf` acts at
CHECKOUT, and those files had not been checked out again since the rule landed. Only `frame.pb.go` and
`message.pb.go` had. So a pin on its own changes nothing in the working tree, which is the case for doing
the renormalisation in the same commit rather than leaving it to the next clone, and the three ordinary
`.go` files beside them (`message_op_test.go`, `message_test.go`, `message_wire_test.go`) had no rule at
all until now. `*.pb.go` stays anyway, because the comment under it argues regenerate-and-diff, which is
about `*.proto` as much as about the generated Go.

`mls/testdata/corpus/**` still answers `text: unset` — the new rule
above it does not disturb the corpus's binary pin, and `TestTheCommittedSeedCorpusIsPinnedAsBinary`'s
negative control, which requires `mls/key_schedule_roundtrip_test.go` **not** to be pinned binary, is
still green: `*.go text eol=lf` sets `text`, it does not unset it.

**The win that arrived is not the one that was predicted.** `gofmt -l .` over the whole of `connect`
went from **442 files to 14**. Under CRLF it flagged every file in the repository, so it could not
distinguish a real formatting error from a fresh clone — which is the second half of the failure this
repository's `.gitattributes` comment names, arriving as a measurement. The **14** that remain are
real, pre-existing layout deviations -- struct-field and map-key alignment, doubled blank lines, and
one orphan `//` line gofmt folds into the comment block below it; every hunk across all 14 is
whitespace and comment layout, checked rather than sampled, with no semantic change in any of them --
living in blobs this commit does not touch, so they are pre-existing in the repository and were not
introduced by the renormalisation. **Left alone**: fixing them would change 14 objects, which is
precisely what this ruling was costed as not doing. Recorded here so the next `gofmt` run is not a
surprise.

**The predicted win did not reproduce, and no change was manufactured for it.** The ruling said five
root-package tests fail under CRLF and pass under LF — the `*SourceAnchors` tests and
`TestBusyProbeInterposesOnlyOnTheSendStallPath` — because `functionBody` locates a function's end by
searching for a literal `"\n}\n"`. They were **already passing under CRLF**, measured on the CRLF tree
before any edit: `readSource` normalises the carriage returns away before `functionBody` sees the
text, and `functionBody` now returns `false` on a missing terminator rather than the whole rest of the
file, so both halves of the stated mechanism had already been repaired. There are also **six**
`*SourceAnchors` tests, not four. The three tests called pre-existing failures on this box —
`TestCombineTrim`, `TestPump`, `TestPumpTrim` — **all passed** too. The root package measured
**1227 `--- PASS` / 0 `--- FAIL` / 22 `--- SKIP`** before the change.

**The ninth log line, and it is the last description this sentence gets.** Gate C's empty-class
report (`message/writeauth_test.go`) said
`TestEveryPackageBuiltOnThisOneIsUnderTheConstantTimeGate` is *"the half of G8 that is LIVE over that
directory today"*. It is not. That test derives its class from this module's production packages that
import `connect/message`, and its own log on this run reads **"0 production packages import
github.com/urnetwork/connect/message: []"** — so the class is empty, the loop that reports an
uncovered root never executes, and **nothing in G8 is a rule in force over `../messagegroup`**. Both
halves are armed tripwires. The sentence now says that, names what arms the derived check — **Task 1,
the first `connect/messagegroup` file that calls into `connect/message`** — and agrees with the
correct statement 906 lines above it. The function's own doc comment, which promised the log would
say *which* half is doing work, now promises *whether any* is. Searched **package-wide** rather than
in the diff, per guardrail 11a: `message/doc.go` and `connect/layering_test.go` both state the
opposite correctly and were left alone; that one `t.Logf` was the only instance in `message`,
`messagegroup` or `mls`.

**Correction to the 2026-09-09 entry above, made here rather than there,** because a ledger that
edits its own past entries is not a ledger. That entry's finding 3 records the new log line as saying
*"that `TestEveryPackageBuiltOnThisOneIsUnderTheConstantTimeGate` is the half doing work today"*.
That is the claim being retracted: it was never true, and this is the third consecutive round in
which the commit sent to fix a misleading statement shipped one.

**Residual A — four files in this repository are mixed WITHIN THEMSELVES, and nothing here looks for
it.** `docs/reviews/2026-08-12-r1-design-redteam.md` (1 CRLF line among 324), `r2-spec-review.md`
(1 among 156), `r3-spec-review.md` (1 among 216) and `r4-three-spec-review.md` (1 among 155), despite
`*.md text working-tree-encoding=UTF-8 eol=lf`. A file mixed within itself is **never** a checkout —
git cannot produce one — it is always a tool that wrote part of a file. Pre-existing, and **recorded
rather than fixed**. `connect` has a gate for exactly this condition and reports it per file;
`msgrepo` has none. What this repository has instead is defensive normalisation at every read —
`deps_test.go`, `api/checks_test.go`, `api/gates_test.go` and `api/second_implementation_test.go` all
strip the carriage returns before matching — which makes the anchors safe and makes the condition
**invisible**, which is the opposite trade from `connect`'s.

**Residual B — the line-ending gate's closure follows path LITERALS, so a scan root composed at
runtime is invisible to it.** `namedSiblingPaths` reads `"../…"` string literals off the syntax tree,
which is what makes it immune to a directory that prose merely mentions; the same property means a
root built as `root := "../" + name` is never seen, and neither is a child directory, which is how
`connect/mls/syntax` stayed outside the scope until this pin. The literal rule is stated in the gate's
own comment; the **consequence** is not spelled out there and is carried here. Measured today:
`connect` has no runtime-composed `"../"` scan root in `mls`, `message` or `messagegroup`, so this is
prophylactic and not a live gap — but it is the shape the next widening will arrive in.

**Two controls on the gate this ruling is about, run after the renormalisation because a gate over a
uniform tree is a gate with nothing left to observe.** Flipping `connect/message/aad.go` to CRLF
turns `TestThePackageSourceIsOneLineEndingThroughout` **RED**, naming the file: *"../message's source
is not one line ending throughout: [..\message\aad.go] end their lines crlf and the other 12 files do
not"* — so the gate still observes its property with the tree uniform. Flipping
`connect/mls/syntax/varint.go` to CRLF leaves it **GREEN**, `ok`. That second one is the point: the
blind spot is now **observed** rather than argued from reading the closure, and it is the whole
reason a `.gitattributes` pin was the right instrument instead of another root on a list. Both files
were restored byte-exactly and their SHA-256s checked back against the pre-mutation copy, never with
`git checkout --`.

**A trap this pin creates for the next round, and it is the one guardrail 7 exists to catch.**
`git diff --numstat` is **no longer a valid landed-check for a line-ending mutation**. The `eol=lf`
clean filter converts the CRLF back to LF before the diff is computed, so a mutation that really is
on disk reports an **empty diff** — the exact signature guardrail 7 teaches you to read as "the edit
matched nothing". It happened on the first attempt at the two controls above: both were aborted as
not-landed when both had landed. The landed-check for this class must be the **file's own bytes** —
a CRLF count, or a hash against the pre-mutation copy — and `git diff --numstat` remains correct for
every ordinary content mutation. Recorded here because the next agent to mutate a line ending on this
tree will hit it, and the failure looks like success.

**Verified.** `connect`: `go test -count=1 -v -timeout 10m ./mls/... ./message/... ./messagegroup/...`
— **7495 `--- PASS`, 0 `--- FAIL`, 0 `--- SKIP`**, `ok` on all four packages, the same count as the
round before. `TestThePackageSourceIsOneLineEndingThroughout` now reports its derived scope
`[. ../message ../messagegroup]` with **all 137 / 13 / 6** source files ending `lf`. The cross-platform
gate: *"9 platforms x 3 package trees built with CGO_ENABLED=0"*, 27 subtests green. `go vet` clean on
the three packages; `gofmt` clean on both changed files. `git ls-files` **1080** = `git ls-tree -r HEAD`
**1080**, before and after. The **root package**, the one this pin reaches that no gate covers, ran its
full suite both ways and did not move: **1227 `--- PASS` / 0 `--- FAIL` / 22 `--- SKIP`** under CRLF in
480s and **1227 / 0 / 22** under LF in 499s, `ok` both times. Every edit in both repositories was made
byte-exactly, with an asserted occurrence count and the line ending derived from the file — and never
with `sed -i`.

### 2026-09-11 — the pin recalibrated into the gate: one mechanism where there were two unguarded halves

**The defect, and it is the one the pin created.** `connect/mls`'s
`TestThePackageSourceIsOneLineEndingThroughout` accepted a package that was **uniformly CRLF**, and
its own comment gave the reason: which ending is right *"belongs to the checkout and not to this
repository: a clone with core.autocrlf off is lf throughout, one with it on is crlf throughout, and
both are fine to work in."* That was true when it was written, and `*.go text eol=lf` falsified it.
**Reproduced before anything was changed**, on a fresh `--no-hardlinks` clone of `7525995` with
`core.autocrlf` confirmed `true` at system scope in the clone itself: **474 of 474 tracked `.go`
files arrive LF, and 116 tracked non-`.go` text files arrive CRLF** — that second number is the
control, and without it "all the Go files are LF" is equally consistent with autocrlf having been
quietly off for that clone. So **no checkout of this repository produces a CRLF `.go` file any
more**, and a uniformly-CRLF package is not a checkout at all: it is a tool having rewritten the
working tree, which is precisely the condition the gate exists to catch. Flipping all 13 files of
`connect/message` to CRLF left the gate **PASSING** on the sentence *"all 13 source files of
../message end their lines crlf"*, with no other test in the suite noticing.

**The fix, and why it is one mechanism rather than two.** The second half of the same defect was
that **nothing asserted the pin existed**: deleting `*.go text eol=lf` from `.gitattributes` was
invisible to all 7,495 tests. The gate did not require LF and nothing required the pin — each half
unguarded in a different direction. The gate now **reads the requirement out of `.gitattributes`**
rather than carrying it as a constant, so the two collapse: the pin is the gate's input, and
deleting the pin leaves every file the gate judges pinned to nothing and turns it red. `connect`
`b4e84f4`.

**Resolution is git's, not an approximation of it.** Rules in file order, last match wins; `-text`
and the `binary` macro turn conversion off and **clear** an `eol=` an earlier line asked for; `text`
with no `eol` pins nothing, because it defers to `core.eol`, which is a checkout's answer and not
this repository's. `gitAttributesPatternMatches` — which already exists in
`key_schedule_roundtrip_test.go` with its own control, and already knows that `*.go`, `/*.go` and
`**/*.go` are one rule to git — is **reused rather than a second matcher written**, which is the
mistake its own comment records having been made once.

**One scope hole found in the first version of the fix and closed before commit.** That version read
`connect/.gitattributes` and treated it as the whole answer. Git does not: a `.gitattributes` nearer
the file overrides one further away, so a rule set appearing in `connect/mls` would have decided how
`connect/mls/*.go` is checked out while the gate went on demanding whatever the root said — a gate
reading something other than what it claims to read, which is this file's oldest failure mode. The
gate now walks **nearest first** and stops at the first rule set with an opinion. There is no nested
rule set covering Go source in `connect` today, so the walk is exercised against a fixture tree
built for it: a control that can only run where the property already holds proves nothing.

**Three statements the pinning commit falsified, closed.**

1. The gate's *"pinned to NEITHER ending"* premise, above.
2. *"measured 2026-09-05, mls/syntax is 6 files crlf and 17 lf"* — the renormalisation in that same
   commit made it **0 crlf and 23 lf**, and the commit's own `.gitattributes` comment already stated
   the 6/17 figure in the past tense, so the two texts disagreed about tense and fact. The sentence
   now states the old figure as history and the new one as the event that produced it.
3. **Four comments in three files** saying a CHECKOUT is how a carriage return gets into a `.go`
   file here: `crypto_forbidden_test.go`'s `codeOf` (*"in a checkout git smudged"*),
   `crypto_test.go`'s `buildConstraintsIn` (the same phrase), `tree_adapt_test.go`'s `readSourceFile`
   (*"on a checkout that stores CRLF as on one that does not"*) and `key_schedule_test.go`'s
   `carriesTheNoInlineDirective` (*"this repository is checked out with core.autocrlf on"*). Each
   justifies a **defensive normalisation that is still correct** — the tool-writes-the-working-tree
   route is live, and is exactly what the gate catches — so what changed is the stated cause, not
   the code. **Swept package-wide rather than over the diff**, per guardrail 11a, which is how the
   last round's sweep failed: every other line-ending statement in `mls`, `message` and
   `messagegroup` is about a **vendored corpus** (`hpke_vectors_test.go`, `key_schedule_deps_test.go`,
   `key_schedule_roundtrip_test.go`, `messagegroup/xwing_vectors_test.go`), those files are pinned
   `-text` or covered by their own `.gitattributes`, and all sixteen vendored KAT files are **still
   CRLF on disk** — measured, so *"none is byte-identical to upstream"* still holds and none of them
   was touched.

**And the same class turned on this round's own diff.** The first draft of the corrected sentence
read *"mls/syntax … is 0 crlf against 23 lf **now**"* — a present-tense measurement, which is the
very class being closed, waiting for the next renormalisation to falsify it. Rewritten as the event
that produced the figure. The fresh-clone counts were likewise moved to the past tense and anchored
to the commit they were measured on.

**Recorded in `.gitattributes`, where the next reader looks.** `eol=lf` **acts only at CHECKOUT**.
All seven `*.pb.go` were already pinned by the rule below and five were still CRLF on disk anyway,
because a pin added after a file has been checked out does not go back and rewrite it. That single
fact explains the whole episode: a pin governs what the next checkout writes, the working tree is
governed by whatever last wrote it, and on this project that is as often a tool as it is git — which
is the case for the gate, stated in the file the gate reads.

**`gofmt -l`: decided, and this reverses the previous round's call.** That round left the 14 files
alone and said why — *"fixing them would change 14 objects, which is precisely what this ruling was
costed as not doing"* — which was right for a commit costed at **no blob may change**. This commit
carries no such costing, and `gofmt -l` is used here as a dirty signal: at 14 it is a smaller dirty
signal rather than a clean one, and a signal that is never zero stops being read. **`gofmt -w` over
exactly those 14**, no others; the whole diff is struct-field and map-key alignment, doubled blank
lines and one orphan `//` line, with no semantic change. `gofmt -l .` over `connect` is now **empty**.
Two of the 14 are root-package files, which no gate of `mls`/`message`/`messagegroup` covers, so the
root package's source-anchored and layering tests were run against them: **9 `--- PASS` / 0 / 0**.
`layering_test.go` reads imports off the syntax tree and is whitespace-immune; nothing in the root
package reads either file's text by name, checked rather than assumed.

**Mutations: ten, all caught, none surviving phase 1.** A whole package flipped to CRLF (13 files);
one file flipped; one file mixed within itself; the pin deleted; the scope derivation stopped
following the coupling; the pin hard-coded instead of read; first-match-wins instead of last; a
nearer rule set pinning `mls` to CRLF while the tree is LF; the nesting walk stopped at the module
root; `-text` reporting no decision so an outer `eol=` answers for a file git was told to leave
alone. **Every landed-check is a SHA-256 over the file's own bytes**, per the trap the previous entry
recorded: with `*.go text eol=lf` active the clean filter turns a written CRLF back into LF before
`git diff` is computed, so a line-ending mutation that really is on disk reports an **empty
numstat** — the exact signature guardrail 7 teaches you to read as "the edit matched nothing".
Reverts are byte-exact restores of a copy taken before the edit, with equality asserted before the
next cycle, never `git checkout --`.

**Verified.** `connect`: `go test -count=1 -v -timeout 10m ./mls/... ./message/... ./messagegroup/...`
— **7496 `--- PASS`, 0 `--- FAIL`, 0 `--- SKIP`**, `ok` on all four packages. The count is 7495 + 1:
the one new test is `TestTheLineEndingPinIsReadTheWayGitResolvesIt`, the control on the derivation,
which states both directions (a reader answering `lf` for everything, and one answering `""` for
everything) and the third answer the nesting walk depends on — whether a rule set decided anything at
all. `TestThePackageSourceIsOneLineEndingThroughout` reports its derived scope
`[. ../message ../messagegroup]` with **137 / 13 / 6** files, each naming the rule that checks them
out: *"which is what [\*.go text eol=lf] checks them out as"*. Cross-platform gate: *"9 platforms x 3
package trees built with CGO_ENABLED=0"*. `go vet` clean; `gofmt -l .` empty over the whole of
`connect`. `git ls-files` **1080** = `git ls-tree -r HEAD` **1080**, before and after. Standard
library only, no cgo, no new dependency, nothing platform-specific. Every edit in both repositories
was made byte-exactly with an asserted occurrence count and the line ending derived from the file,
never with `sed -i`.

**Residual A of the entry above is now open item 131** rather than a paragraph in a log nobody
re-reads. Residual B — the closure follows path **literals**, so a scan root composed at runtime is
invisible to it — is unchanged and still prophylactic. Re-measured on this tree: `mls`, `message`
and `messagegroup` compose exactly one path out of a `".."` literal at runtime,
`filepath.Join("..", ".gitattributes")` in `key_schedule_roundtrip_test.go`, and it names a **file**
rather than a directory and cleans to `".."`, which the closure's own two stated exclusions already
decline. So no scan root is being missed today, and the shape is still the one the next widening
will arrive in.

### 2026-09-12 — M1-1 and M1-2 red-teamed: four options dead, two halves standing, and the one thing every option was missing

**What this commit is.** One review document,
`docs/reviews/2026-09-12-m1-wrap-and-welcome-redteam.md`, and five open items. **It rules nothing.**
Six option write-ups were produced against M1-1 (the device wrap's seal) and M1-2 (the Welcome's
carrier); three adversarial reviews were run over them; this is what survived, written for the owner
to rule from. Every load-bearing claim was re-verified in this session rather than inherited — against
`connect` `beta/message` `1307f15` (`go build ./mls/... ./message/... ./messagegroup/...` green) and
`msgrepo` HEAD — and **three of the decisive findings are corrections to the red team itself**.

**Four options are dead, and each is shown dead with the attack rather than argued down.**

- **M1-1 Option 1** (MLS-exporter envelope) is dead **for two of the three record shapes**. It puts
  the RECOVERY wrap in the envelope, and MASTER:818 says a seed-only restorer *"has none [no MLS
  state] by definition"* — so §5.4's last resort opens nothing, which is correction **E1**
  (`spec-a:1565`) reintroduced one layer up. It also puts the SNAPSHOT there, which correction **E2**
  (`spec-a:1566`) already pins under `K_snapshot[n]`, and which is a blob-ref record with **no
  `ct_body` at all** (`spec-a:1673`). Its headline cost is false too: `(*Group).Export`
  (`group.go:821`) reads the CURRENT schedule, there is no `ExportAt`, and `PastEpochWindow` is 32
  with `DeleteGroupStateBefore` on every merged commit — so `env_key[k]` is computable only while the
  group is AT epoch k. Its device-wrap half survives, and survives on a real property: it is the only
  outer key neither the server nor a just-removed member can derive.
- **M1-1 Option 1b** is dead outright. Its only benefit over 1a is a healing commit, a commit carries
  `AttachmentEpoch`, and `exemptFromEpochComplete` (`memory.go:937-944`) does not exempt it — so it
  is refused `REASON_EPOCH_INCOMPLETE` exactly when it is needed. Worse, the widening it asks for is
  the one `store/contract.go:2555` was written to prevent, in that test's own words: *"adding
  AttachmentEpoch lets a commit through the gate and nothing says so."* The proposal cites
  `memory.go:939` for its own prerequisite and never runs the same function against its escape hatch.
- **M1-1 Option 2** is dead twice. The backward chain has **no base case** — it inducts to
  `storage_root[0]`, which by the option's own text exists on one device for the life of the group —
  and one dropped wrap is **permanent ejection**, not one lost epoch, because the repair window is
  bounded by `memory.go:578` (`REASON_EPOCH_STALE`; the wrap exemption is from the epoch-COMPLETE
  gate, never the epoch-EQUALITY gate) and `memory.go:691-696` (write key NULLed on advance). One
  correction **in its favour** is recorded, because a rejected option should be rejected for true
  reasons: its "N sequential round trips" cost is overstated, since every `wrap_target_handle` is
  locally computable and only the decryption is serial.
- **M1-2 Option 3**'s sidecar is dead **as a production carrier** and fine in its CP3b form. It
  carries no authenticator: it encapsulates to a public key from a store the message server operates
  and binds a hash of transmitted bytes, so the store operator forges one and **chooses** the
  joiner's `group_handle_key`. Its own headline detector — a wrong `pq_secret` failing "at the
  server" — names the adversary as the detector.

**Two options are dead as written and repairable, and the repair does not buy what was claimed.**
**M1-1 Option 3**'s zero-length `ct_head` is refused at `api/submit.go:301`, again at
`store/memory.go:979`, the column is `NOT NULL`, and `store/contract.go:145` asserts the refusal
against **both** stores — so *"no server change"* is measurably false. The repair is one line (a real
head keyed from `wrap_key`) and costs the option nothing; but it does **not** close the server-forgery
finding, because the server holds `write_key` in the clear and the target's X-Wing public key from the
store it operates. **M1-2 Option 1**'s slot survives and its contents do not: a group-LIFETIME value
under an X25519-only Welcome forfeits MASTER §8's unlinkability permanently and retroactively — and
the live version of that attack needs no quantum computer, only a key-package substitution, because
ledger 69 requires the handle be derived from the identity KEY and **nowhere requires anyone to verify
the served package against it**.

**The recommendation, and it is stated with its costs rather than cleaned up.** M1-1: three record
kinds get three rules — device wrap on Option 1a's envelope, recovery wrap on Option 3's KEM-only rule
with a real `ct_head`, snapshot unchanged under E2 — plus **a signature over every wrap body under the
publisher's identity key**, which is not new policy but MASTER §5.3:441 applied where it already
applies. Residual risk is named, not hidden: it is a target-type-dependent body encoding, which is the
kind-`0x0000` defect class one level up; the `stream_index`-to-ratchet mapping is still owed and its
failure mode is Poly1305 key recovery rather than a decryption error, because the nonce is derived
from the record key; and the `env_key` past-epoch obligation stands and **is the strongest argument
for ruling Option 3 for the device wrap too**. M1-2: Option 1's `0xF004` slot with Option 2's contents
— `read_key` and the joiner's own `wrap_target_handle`, both already server-known — and **where
`group_handle_key` lives is deliberately NOT ruled**, because the determination that would rank the
three homes has not been made.

**The schedule fact worth reading twice: CP3b is not blocked by that deferral.** Ledger **44a**
already blesses a gated, test-only hand-off of a public KeyPackage and a sealed Welcome. Extending
that same hand-off to carry `group_handle_key`, under the same absent-not-placeholder rule, closes
Task 16 for CP3b **without** ruling the production carrier — provided the ruling says in the
hand-off's own doc comment that the two are not the same thing.

**Five open items, 132-136, filed and not ruled**, because four of them are not m1's to rule and the
fifth is a sizing decision. **132:** the fan-out has no coverage check — `memory.go:722` compares two
client-declared numbers, the wrap index is not unique, nothing binds `sender_handle` to a submitter,
and `expected_wrap_count` has no upper bound; **this is the single detector every M1-1 option offers
against M1-22, and it is correct while the coverage is wrong**. **133:** removal revokes nothing —
epoch keys are plaintext in every commit and `Fetch` has no epoch scoping, which falsifies MASTER §8
and §9.2 as they read. **134:** a stalled fan-out is terminal rather than readable-but-not-writable,
and §5.12/G10 plus Spec B:2234 let a **conforming** client cause one on a timeout. **135:** the wrap
satisfies **I8** in no field under any option, and §5.3's own signature rule has nothing to verify.
**136:** §8.1's disappearing-message promise is a property of server and client behaviour, not of
cryptography, because `eph_root` rides a never-pruned record under a key `ProposeUpdate` deliberately
preserves.

**One correction to the corpus that is not an open item.** §5.11 step 5's false sentence — *"they are
all derivable from the epoch state every member holds"* — is in **three** documents, `spec-a:1662`,
`spec-b:2164` and MASTER:852. Every prior write-up and every red-team lens reported two.

**Verified.** `msgrepo`: `go test ./ -run TestThePlanLinter` — `ok`. `git ls-files` equals
`git ls-tree -r HEAD --name-only` before the commit, checked rather than assumed, per the trap this
repository has hit once. Both edited files are LF throughout, measured. Nothing in this commit edits a
spec or a plan; the review document and the five new open-item paragraphs are the whole diff.

### 2026-09-13 — three owner rulings written in: a resequence nothing in the server had to change for, an envelope with a caching bill, and the split that makes disappearing messages cryptographic

The owner ruled **three of the five** questions the 2026-09-12 red team put to them. This entry is
what landed, what was verified rather than assumed, and — at the same length — what these rulings
deliberately do **not** resolve. Ledger item **137** is the anchor; Spec A §5.11 is the normative text.

**Ruling 1, the resequence, and the one claim in it that had to be checked rather than believed.**
The recovery wraps now land **after** the `EpochComplete` marker, as ordinary records of the now-open
epoch. Finding A reproduced exactly: `exemptFromEpochComplete` (`store/memory.go:937`) exempts
`AttachmentWrap` and `AttachmentEpochComplete` and nothing else; `AttachmentRecovery` is refused
`REASON_EPOCH_INCOMPLETE` at `memory.go:582`; and `store/contract.go:2555`,
`OnlyTheExemptKindsPassTheGateWhileTheFanOutIsOpen`, derives the class from every declared
`AttachmentKind` in both directions and runs it against both stores. So the sequence three documents
published described a fan-out that **executed against no server**, and had since the sequence was
written.

The ruling's claim that *"nothing in the store gate changes and the derived contract test stays green
as written"* was verified by reading the test rather than by trusting the sentence: its recovery
scenario asserts what the server does with a recovery record submitted **while a fan-out is open**,
and the ruling does not change that answer. What changed is when a conforming client submits one. No
Go file in this repository is touched by this commit.

**The accepted cost is in §5.11 and not only here, which is the part of the instruction most easily
lost.** `expected_wrap_count` becomes **decorative for the recovery arm**. §5.11 says so in the
section a reader of the fan-out actually opens, and then answers the question that follows —
*so what does detect a missing recovery wrap?* — with the honest answer: **nothing does.** Not the
count, which closed first; not step 5's `no_wrap` gap, which cannot tell *absent* from *not yet* once
the marker has landed; not a live member, none of which reads its own recovery wrap on any normal
path; and not the server, for item 132's reasons. It is discovered at restore time, by the party
least able to act on it, potentially years later. That is **new open item 138**.

**Ruling 2, the envelope, and the bill that came with it.** `env_key[k] =
MLS-Exporter("URmessage/v1/envelope", "", 32)` at the wrap's own epoch, sitting where the class key
sits at the head of §5.3's **existing** ladder — no new ladder, no new label below the root. Two
things follow that the ruling did not state and that are written as **consequences with their
reasons** rather than as second rulings:

- **the recovery wrap cannot use it**, by necessity rather than preference — MASTER:818 says its only
  intended reader *"has none by definition"* — so it is KEM-sealed, with the review's repair carried:
  a real head keyed `HKDF-Expand(wrap_key, "wraphead/v1", 56)`, because Option 3's zero-length
  `ct_head` is refused by `api/submit.go:301`, by `store/memory.go:979`, by a `NOT NULL` column and by
  `contract.go:145`'s `ARecordWithNoHeadAtAll` against both stores;
- **the past-epoch caching obligation is live.** All three facts were measured against
  `C:/Users/ryanm/Downloads/claude_sandbox_message/connect` before a word was written: `(*Group).Export`
  (`mls/group.go:821`) reads `self.schedule`, the **current** schedule; `grep -rn 'ExportAt'` over the
  whole of `connect` returns **0**; `PastEpochWindow` is **32** (`mls/key_schedule.go:30`).

**And the obligation is stated in the strong form, because the weak one is the trap.** Thirty-two is
how long *state* is retained, not how long `env_key[k]` is computable — no published API reaches a past
epoch's exporter, so the window is **the live epoch and nothing longer**. §5.11 specifies who caches
(every client, on every transition into an epoch, before merging any further commit), for how long
(until it has opened its own device-wrap records and derived `storage_root[k]`), where (it must
survive a restart, which makes it durable client state; which store holds it is **not ruled**), and
what a client does on a miss. The last answer is the honest one: **that epoch's `storage_root` is
unrecoverable.** New open item **139** carries it, along with the two things that would change it and
are not decided — an `ExportAt` that does not exist, and the review's own Part 5 item 2, which nobody
has determined.

**The signature is carried in with ruling 2, as the review asked and as not-new-policy.** Every wrap
body is signed under the publisher's `identity` key and a client MUST NOT honour an unverified one —
MASTER §5.3:441 applied where it already applies, since every recovery wrap already carries a
`RecoveryTag`. It is what gives a wrap's fields any authenticator at all: the wrap is the only record
class with no MLS frame, and §2.4 makes `write_auth` zero on read. It fits: 64 octets into ~2.9 KB of
slack inside `size_bucket 2`, arithmetic in §5.11.

**Ruling 3, the split, and the number that had to be worked out rather than deferred.** A `PERMANENT`
record carrying `pq_secret[k]` and an `EPH(5)` record carrying `eph_root[k]`, both at the same
`wrap_target_handle`. It **closes item 136** and is the only construction offered anywhere that makes
MASTER §8.1's promise cryptographic rather than behavioural.

`expected_wrap_count` is now **`2 × (active device leaves) + 1`** — 2,001 at the design target. It
covers **both** device-wrap record kinds and the snapshot, and **no** recovery wrap. That is the
reconciliation with ruling 1 stated precisely: the field is a *true* statement about the device arm
and the snapshot and says *nothing whatever* about the recovery arm, which is what "decorative for
the recovery arm" means. m1 Task 15's Property 2 gains a third assertion for it, and a mutation that
**nothing in the task can refute** — omit the recovery leg and land the marker — recorded as a named,
deliberately unrefuted mutation citing item 132 rather than dropped because nothing catches it.

**Two costs of ruling 3 that nobody had written down, both now filed rather than discovered.** Two
records land at one `wrap_target_handle` **by design**, so *two wraps at one handle* stops being an
attack signature and item 132's proposed uniqueness constraint on `(group_id, epoch,
wrap_target_handle)` would refuse a conforming fan-out unless it also takes the retention class — an
interaction recorded **in item 132**, not resolved. And the `eph_root` wrap's twenty-eight days run
from its publication rather than from its epoch's end, so a device that has not opened it loses the
tail of a long epoch's ephemeral traffic — **new open item 140**.

**What the pass did not do, at the same volume as what it did.**

- **Where `group_handle_key` lives is not ruled**, and CP3b is **not** blocked by the deferral:
  ledger 44a's already-blessed gated test-only hand-off carries it, **provided** the hand-off's own doc
  comment says it is not the production carrier. That proviso is written into m1 Task 16 as
  **Property 5 with mutation 8** — a requirement on whoever builds it, not a note beside it.
- **Items 132–135 stay filed and unruled.** 132 gains the two interactions above and no resolution.
- **§5.11 step 5's false derivability sentence is not repaired**, in any of its three documents. It is
  **marked in place** in Spec A and Spec B — the parenthesis is kept and labelled false, with item 134
  named — because repairing it is not one of the three rulings and this pass does not get to choose
  its replacement wording.
- **M1-1 is not closed.** Its remainder is the wrap body's field list beyond MASTER §8.2, where the
  signature sits relative to `hybrid_ct`, and M1-7's padding. Task 14 is written against the ruling and
  still blocked on that, **and on M1-6** — which grew: every record the fan-out writes is now
  non-`DURABLE`, so Task 11(a)'s refusal stands in front of Task 14 as well as Task 15, and M1-6 is the
  only ruling left on the CP3b critical path.

**One claim in the brief that carried these rulings does not reproduce, and is corrected rather than
repeated.** The brief states that `grep -rn 'KeyPackage'` across the whole of `msgrepo` returns **0**.
It returns **456**, across fifteen documents — PROGRESS.md, this ledger, nine plans, two reviews and
Spec A. The review's own narrower measurement is the one that holds: `git grep -n 'KeyPackage' --
'*.go'` returns **0**, as does `key_package`. The substance the brief drew from it survives intact and
is recorded in item 137 and in m1 Task 16 — **the key-package store does not exist**, so *"does it
authenticate a served package against the claimed identity's signature key?"* is not a measurement
anybody can take but a **requirement that can be written into the store before it is built**.

**A second discrepancy, in the brief's framing rather than in a claim.** The brief says to work on
branch `beta/message` and also that the repository is on `main`, clean at `2cbbb71`. This repository
has exactly one branch, `main`, and no `beta/message` — that name belongs to the `connect` and `sdk`
forks (locked decision T12). Work was done on `main` at `2cbbb71`, which is the half of the
instruction that reproduces. `connect` was read and never written.

**New open items: 137 (the ruling), 138, 139, 140, 141.** **141** is the one a reader should look at
next: **MASTER was deliberately not amended**, because the brief did not name it, so the normative
parent still publishes the pre-ruling fan-out, the single-record device wrap and the old sizing while
Spec A and Spec B publish the ruled ones. That divergence is filed rather than hidden, with its three
locations, and it is a transcription rather than a decision.

**Verified.** `msgrepo`: `go test ./ -run TestThePlanLinter` — **7 of 7, `ok`**, before and after.
Findings moved in the right direction and in no other: check 2a **19 → 18** (m1 Task 14 Property 1 now
states its membership) and check 4b **6 → 5** (both m1 rows closed by naming, in Task 9's Produces
block, the `GroupHandle` members m1's own tasks consume — `Export` is the one this ruling adds). Every
other check is unchanged, including the two fatal ones, 3b and 3d, at no findings. `git ls-files`
equals `git ls-tree -r HEAD --name-only` — **checked before the commit rather than assumed**, per the
trap this repository has hit once. Every edited file measured **LF throughout, zero CR bytes**, with
`tr -dc '\r' | wc -c` rather than with `grep`: on this box `grep -c $'\r$'` reports every line of a
pure-LF file as matching, which is exactly the shape of vacuous pass `.gitattributes` was written
against. No file under `C:/Users/ryanm/Downloads/claude_sandbox_message/connect` was modified.

### 2026-09-13 — the three rulings reviewed: a window nobody had costed, a MUST its own ledger called undecided, and 23 citations the rulings' own edits invalidated

**The rulings themselves stand.** Every one of them was re-verified before a word of this pass was
written and none was changed: `go test ./...` green, `go test ./ -run TestThePlanLinter` **7 of 7**,
the resequenced fan-out executes end to end against the shipped gate, all three `connect/mls` facts
exact (`(*Group).Export` at `mls/group.go:821` reads `self.schedule`; `grep -rn 'ExportAt'` over the
whole of `connect` returns **0**; `PastEpochWindow` is **32** at `mls/key_schedule.go:30`), and every
sizing figure reproduces from MASTER §7's framing. **This entry is about how the rulings were written
down.** No file under `C:/Users/ryanm/Downloads/claude_sandbox_message/connect` was read for anything
but measurement and none was modified.

**1 — the resequence's real cost was undocumented, and it is not the cost either spec described.**
The largest finding, and it reproduces exactly against the shipped store. `EpochComplete` is what
opens the group for ordinary writes, so **after the marker the group is fully writable** and the
recovery leg runs inside that writable window. A commit accepted from any member during that leg sets
`current_epoch := n+2`, and `store/memory.go:578` then refuses every recovery wrap still in flight
`REASON_EPOCH_STALE` — **permanently**, because that check sits *in front of* the epoch-complete gate
and no path in either store accepts a record at a closed epoch. The window is the recovery arm's own
length: **about eighteen round trips** at the 500-member design target, which is a number §5.11's own
sizing paragraph already published without connecting it to this.

**The pre-ruling sequence had no window of this shape**, structurally: it published the recovery wraps
before the marker, and while a fan-out is open a commit carries an `AttachmentEpoch`, which
`exemptFromEpochComplete` does not exempt. So both specs' attribution of a short recovery arm to *a
committer that dies* (§5.11 step 7, §6.1 step 7) was **false as it stood**: an ordinary, conforming,
**live** committer loses the tail of its arm to somebody else's perfectly legal commit, at whatever
rate the group commits, with no failure of any kind. Written into **§5.11 itself**, where a reader of
the fan-out lands, and mirrored in Spec B §6.1 — not only into this ledger, which is the half of the
original instruction most easily lost twice.

**And the question that follows is answered rather than deferred: may a stranded recovery wrap be
published at a later epoch?** *The cryptography permits it* — a recovery wrap's `ct_body` **is**
`hybrid_ct` and its `ct_head` is keyed from `wrap_key`, so neither depends on the record's own `epoch`
field, and the content epoch is bound inside `wrap_key`'s HKDF `info`. *The wire does not.*
`RecoveryTag` carries `recovery_handle`, `recovery_verify_pub` and `alg_id` and **no epoch** — where
`WrapTag` carries `u64 epoch` — and `recovery_handle = HKDF-Expand(recovery_root, "idx/v1", 16)` is
the **same value in every epoch**, so a republished wrap is indistinguishable from the current epoch's
own. The party that would have to tell them apart is the seed-only restorer. So a retry is **not**
specified, and what it would take is written down instead of guessed at: a `u64 epoch` on
`RecoveryTag` — an A6 wire change reaching Spec A §5.11, Spec B §5.4 and MASTER §8.3 — plus a rule for
which of two wraps at one `(recovery_handle, record epoch)` a restorer honours. **New open item 142**,
which compounds 138: 138 says nothing detects a missing recovery wrap, and 142 says a healthy client
produces one on an ordinary day.

**2 — an item the ledger said was unruled had acquired a normative answer, and it is ruled rather than
weakened.** Spec A §5.11 part (4) published *"Every wrap body is signed under the publisher's
`identity` key, and a client MUST NOT honour an unverified one"* as a MUST, while item 137 said items
**132–135** stay filed and unruled and item 135 said *"Filed, not ruled"* — a normative MUST against a
ledger saying it had never been decided, which is a shape this project has twice had an implementer
discover and which the brief for that very commit named as a risk. **Resolved in the ruling
direction**, because that is what the owner's ruling 2 actually did: the signature was carried in with
it, as the review asked. Item **135 is CLOSED**, 137's list becomes **132–134**, and the understatement
is corrected in the same breath: *"not new policy"* was true of **half** of it. For the recovery wrap
it is MASTER §5.3:441 applied where it already applied, since that record carries a `RecoveryTag`. For
the **two device-wrap records it is new normative policy** — they carry a `WrapTag` and no
`RecoveryTag`, and no document required a signature over them before. Spec A §5.11 (4), m1 Task 14's
outline and m1's M1-1 item now all say which half is which.

**3 — the spec line-number citations were invalidated wholesale by the rulings' own edits, and the
repair is not another re-numbering.** **23 citation sites were swept**, and the accounting is given
rather than the round number: **21** were correct at `2cbbb71` and wrong at `7fb0dd9` — measured both
ways, not assumed — plus the anchor table's own header claim, plus one that was **already** wrong
before this commit and had survived the 2026-09-07 sweep. The commit inserted a revision row into
Spec A §0 and rewrote §5.10 and §5.11, so at `7fb0dd9` the shifts were `+1` above §5.10 and `+251`
below it, and Spec B moved with it — a measurement between two named commits, which is the only form
in which an offset is worth writing down. The repair is the one this repository already owns from
`a48cd4c`: **the quoted anchor is the citation and the number is advisory**, with the `grep` to
re-derive it in the table's own header.

- **m1's anchor table** keeps its seven `a48cd4c` numbers, and its header now says in the column
  title that they are **advisory and stale since `7fb0dd9`** — so a reader knows the column is
  expected to be stale rather than broken, and re-derives any of them with the header's `grep`.
- **Ten inline citations in m1 lost their numbers entirely** and now name the anchor string and its
  table row: §2.2's two tree anchors, §5.6's `streamindex.go` twice, §5.14's `deposit_sig_seed`,
  §2.2's `engine.go` twice, §5.10 E2, §6's `GroupEngine` block twice, and §8.2's `ReserveStreamIndex`.
  The *"the numbers agree with the inline citations, and that agreement is the check"* paragraph is
  rewritten around anchors, because a number repeated in nine places drifts in nine places. **No shift
  arithmetic is written into the plan on purpose:** a stated offset is one more derived number that
  goes stale on the next edit, including this one's.
- **One citation the 2026-09-07 sweep had missed is recorded rather than quietly fixed:** Task 9's
  Produces block cited *"spec lines 1885–1939"* for §6's interface block, a range that never agreed
  with the anchor table's own `1907`–`1912`.
- **Four bare numbers in three live ledger items became anchors:** 134's `spec-a:1662` /
  `spec-b:2164` and its `spec-b:2234`, 135's `spec-a:300-303`, and 136's `spec-b:907`. Two of those
  are in text this commit never touched — the commit's *spec* edits invalidated them anyway, which is
  the whole shape of the class — and 136's is doubly stale, because that row was split in two by
  ruling 3 on the same day.
- **The append-only edit log is deliberately not swept.** Its `spec-a:1565` / `1566` / `1673` /
  `1662` and `spec-b:2164` were correct at the commits their own entries name, and rewriting a past
  entry's measurements is not what §6's change process does — the same reason the 2026-09-12 review
  document keeps its own numbers. The anchors for those five are in the live items above, which is
  where a reader who needs them will be. **The same rule is why the previous entry's two uses of
  *"§5.11 step 5"* for the derivability sentence are named here rather than edited there.**

**4 — eight smaller findings, each reproduced before it was acted on.**

- **Spec B's revision 14 preamble contradicted the §3.5 table it described, in the same commit**, with
  two wrong per-commit figures: *"~60 KB / ~1.4 MB"* against §3.5's **~40 KB / ~1.2 MB**. ~60 and ~1.4
  are the pre-split numbers naively doubled; the bundle does not double, only its device-wrap half
  does. §3.5's arithmetic reproduces (+2 records ≈ 9.2 KB at 2 members, +100 ≈ 460 KB at 50, +1,000
  ≈ 4.6 MB at 500) and the preamble now agrees with it. The 500-member figure, the one an operator
  sizes from, was right in both.
- **The §5.11 renumbering broke five step citations in m1** — 2109, 2749, 3288, 3307 and 4420 in the
  file as `7fb0dd9` left it — because old step 4 became step 5 and old step 5 became step 6. Repaired,
  and every one now names *which* step it means (*the `no_wrap` step*, *the derivability step*) with
  its pre-resequence number, so a future resequence cannot make them silently wrong again. **The
  commit's own new prose used *"§5.11 step 5"* for two different steps** — the `no_wrap` gap (correct)
  in items 138, and the derivability sentence (now step 6) in item 141 and in the entry above. Both
  corrected.
- **`plan:980-986` still quoted the superseded `expected_wrap_count` definition** — *"device wraps +
  recovery wraps + 1 snapshot"* — in a file the commit edited, and drew from it the conclusion that a
  client deferring recovery wraps diverges from the field's definition, which is now the **opposite**
  of ruling 1. Rewritten: the divergence it named is gone and the trap it names survives in the other
  direction (item 132's two client-declared numbers), plus the recovery arm now having no count over
  it at all. m1's **M1-40** and ledger item **47** carried the same superseded quote and are marked.
- **Residual risk 2 of the adopted recommendation was carried into no document.** Residuals 1, 3, 4
  and 5 are all in the corpus; the **normative `stream_index`-to-ratchet-position pin** was in the
  review and nowhere else. It is real: the nonce is derived from the record key
  (`HKDF-Expand(record_key[i], "rec/v1/head", 56)`), so key-nonce uniqueness *is* uniqueness of `i`,
  and a repeat leaks the Poly1305 one-time key — header forgery. **Rulings 2 and 3 sharpen it**: ruling
  2 gives the device wrap its own ladder head and ruling 3 puts two records per leaf on it, so a
  fan-out advances that ladder twice per leaf, 2,000 times rather than 1,000. Named in §5.11 part (5)
  as explicitly not stated, and filed as **new open item 143**.
- **"Decorative for the recovery arm" re-defined the review's term**, and the one place a server
  implementer reads the field's wire definition — Spec B §5.4's `EpochAttachment` block — carried the
  label without the re-definition. The word is now scoped in both documents: the count is **exact and
  its equality with the marker is normative and is the only thing that opens an epoch**; *decorative
  for the recovery arm* means the field makes **no statement** about that arm, and is not a licence to
  stop enforcing the equality.
- **`mls/group.go:2587` is the cutoff guard, not the `DeleteGroupStateBefore` call.** `:2587` is
  `if self.context.Epoch > PastEpochWindow {`; the call is `:2594`. Corrected in §5.11 with both lines
  named. `:2488`, `:821`, `:1613` and `key_schedule.go:30` all resolve exactly as published.
- **m1 Task 15 said the seven-step sequence *"is quoted whole"* and the blockquote was abridged** —
  the trailing sentences of steps 4, 5 and 7 dropped and step 6's parenthesis paraphrased, every one
  of them a constraint on that task. The blockquote is now generated from §5.11's own text and the
  claim is true, and the task gains the window paragraph as a named obligation: do not treat the
  recovery leg as the part that only fails on a crash, and do not silently retry a stranded wrap.
- **The E1 correction row still read as pre-ruling**; only the paragraph below it said otherwise. The
  superseded sentence is now struck **in the row**, with E1's own correction left untouched.

**5 — two measurements corrected, and one claim in the review that does not reproduce.**

- **The `KeyPackage` measurement now carries its scope, because the scope is the argument.**
  `git grep -n 'KeyPackage' -- '*.go'` over `msgrepo` returns **0**: no Go code names a key package,
  therefore no key-package store exists, therefore *"does it authenticate a served package against
  the claimed identity's signature key?"* is a requirement to write and not a fact anyone can measure.
  The unscoped form does not reproduce in either direction. The brief said `grep -rn 'KeyPackage'`
  over the whole of `msgrepo` returns 0; the previous entry corrected that to **456**, which is the
  count at `2cbbb71` — a pre-commit number published post-commit. Measured at `7fb0dd9` the whole-tree
  count is **464 matching lines across 15 files**, every one a document. (`-- '*.go' '*.proto'` is 0
  too, though the `*.proto` half is vacuous: this repository holds no `.proto` file. `key_package`
  over `*.go` is 0.)
- **The review's own figure of 509 does not reproduce and no change was manufactured to fit it.**
  Measured at `7fb0dd9`, over the working tree with `.git` excluded: `grep -rn 'KeyPackage'` gives
  **464** lines and `grep -ro` gives **556** occurrences. Neither is 509, and `git grep` agrees with
  the 464. The scoped measurement the review asked to be stated is the one that carries the argument
  and it is stated; the whole-tree number is recorded with its measurement point rather than left as a
  bare figure that will be wrong again next commit.
- **MASTER (item 141) was correctly left alone and was not amended here either.** Its three named
  locations were re-measured and **all three confirmed** — §8.2's payload table at `:806`, the
  epoch-publication sequence's step 2 at `:842`, and the sizing paragraph at `:855`. **A fourth was
  found and added:** MASTER §8.3's `server_attachment` block at `:912` still annotates
  `expected_wrap_count` as *"device wraps + recovery wraps + 1 snapshot, for the epoch it opens"*,
  which both rulings contradict. It is the worst of the four for a reason worth writing down: it is a
  **wire-block annotation**, the form a second implementation transcribes rather than reads, and the
  three documents' `EpochAttachment` blocks now disagree field for field. MASTER remains the next edit
  and remains a transcription rather than a decision.

**What this pass did not do.** It did not rule items **132**, **133** or **134**, or the two M1-1/M1-2
questions the owner left open; it did not touch MASTER; it changed nothing in `connect`; and it
changed no Go file in this repository. Item 135 is the only item whose status it moved, and it moved
it to what the owner's own ruling 2 had already decided.

**Verified.** `go build ./...` clean and `go test ./...` green, before and after. `go test ./ -run
TestThePlanLinter` — **7 of 7, `ok`**, before and after, and the finding counts move in the intended
direction and in no other: check 2a **18 → 18**, check 3c **2 → 2**, check 4b **5 → 5**, and both fatal
checks, 3b and 3d, at **no findings** in both runs. `git ls-files` equals `git ls-tree -r HEAD
--name-only` — checked before the commit rather than assumed, per the trap this repository has hit
once. Every edited file measured **LF throughout, zero CR bytes**, with `tr -dc '\r' | wc -c` rather
than with `grep`, for the reason the previous entry gives. This repository has exactly one branch,
`main`, and no `beta/message`; the work was done on `main` at `7fb0dd9`, which is the half of the
brief that reproduces — the same discrepancy the previous entry recorded, unchanged.

---

### 2026-09-14 — the retry that was priced at a wire change and costs none, and five ways a correct ruling was written down wrong

**Nothing ruled on 2026-09-13 changed, and nothing was ruled here.** `go build ./...` clean and
`go test ./...` green before and after; `go test ./ -run TestThePlanLinter` **7 of 7** before and
after. No Go file in this repository changed and no file under
`C:/Users/ryanm/Downloads/claude_sandbox_message/connect` was modified — `connect` was read for
measurement only. Items **132**, **133** and **134** stay filed and unruled; **142** stays filed and
unruled; MASTER stays un-amended (item **141**).

**1 — the retry was ruled out on a reason that does not hold, and mispricing it is what would have
kept it from being built.** The largest finding, and it is a design correction rather than a wording
one. Item 142 and Spec A §5.11 both stated — correctly — that a recovery wrap's `ct_body` **is**
`hybrid_ct`, that its `ct_head` is keyed from `wrap_key`, and that **the content epoch is bound inside
`wrap_key`'s HKDF `info`**. They then concluded that a seed-only restorer *"cannot tell two candidate
wraps apart"*, and priced a coherent retry at a `u64 epoch` on `RecoveryTag` — a `server_attachment`
change, therefore an **A6 wire-format change** reaching Spec A §5.11, Spec B §5.4 and MASTER §8.3.
**The paragraph supplied the fact that defeats its own conclusion.** A value bound inside a key is a
value the key's holder tests for, and an AEAD is the test.

Re-derived from MASTER §7 rather than argued: `ss = XWing.Decapsulate(recovery_sk, ct_xwing)` does
**not** depend on the epoch — the epoch enters only at `wrap_key = HKDF-Expand(ss, "URmessage/v1/wrap"
‖ LP(group_id) ‖ u64(epoch) ‖ LP(target_id), 32)` and again at `key_head ‖ nonce_head =
HKDF-Expand(wrap_key, "wraphead/v1", 56)`. So a restorer **decapsulates once per candidate record** and
walks candidate content epochs **downward** from the record's own `epoch` field, which is an upper
bound because no wrap is published before its epoch opens; a wrong candidate fails Poly1305 with
probability `2^-128`. **The property that carries the cost argument, published instead of a timing
figure: the decapsulation count does not depend on the bound at all.** The search adds two
HKDF-Expands and one AEAD open per candidate and **no asymmetric operation**, and that stays checkable
against MASTER §7's own derivation at every future commit.

**The bound is what a retry actually needs, and it must be normative.** Without one a restorer handed a
record it cannot open — corrupt, foreign, or for an epoch it is not owed — cannot distinguish *wrong
guess* from *not mine*, so the failure of the whole search is its only signal and it walks back to
epoch 0. A ceiling is already in the corpus rather than needing invention: **`PastEpochWindow` = 32**
(`connect/mls/key_schedule.go:30`, re-measured today, and the same constant §5.11's caching paragraph
already carries), past which no member holds epoch *k*'s MLS state and no member can **rebuild** that
epoch's wrap, because `archive_secret[k]` is `sender_data_secret[k] ‖ encryption_secret[k]`
(MASTER §8.2) and `DeleteGroupStateBefore` (`connect/mls/group.go:2594`) has taken both.

**The corrected price: two normative sentences and ZERO wire bytes.** A publisher MUST NOT republish a
wrap lagging further than the bound; a restorer MUST NOT search further than the bound. Neither touches
a published surface, neither reaches Spec B §5.4 or MASTER §8.3, and **the server sees nothing at all**
— a republished wrap is an ordinary record of the epoch it is submitted at. What does not vanish: two
**verified** wraps for the **same** content epoch that disagree is a member equivocating, and that is
not created by the retry. **142's status is unchanged and the reason for it is not:** it was blocked
behind a wire-format decision and is now blocked behind one number. Written into Spec A §5.11
(the whole *"May a stranded recovery wrap be republished"* block re-derived), Spec B §6.1 step 7 and
revision 15, m1 Task 15 and M1-1, and item 142 itself.

**2 — five defects in how the previous pass wrote a correct ruling down. Each reproduced before it was
touched.**

- **Item 135's contradiction did not vanish; it moved into Spec A's own revision history.** The A-14
  row still ended *"Not ruled and left open:"* … *"and ledger items 132–135"* and still called the
  signature
  *(**Anchor repaired 2026-09-15**, under A-16's own rule that a landed entry's claim about what a
  document says is corrected in place. This read* **"Not ruled and left open: ... ledger items
  132–135"** *— one quoted string with an ellipsis inside it, which `grep -F` returns zero hits for,
  which is the exact defect the fifth bullet of this same entry announces as fixed three bullets below.
  The two halves are now separate strings joined outside the quotes, which is the form m1's table row 4
  uses and the only form a two-part anchor can take.)*
  *"MASTER §5.3's existing rule applied where it already applies"* — the two exact sentences the pass
  corrected in §5.11 and in items 135 and 137. **And the pass created a tension it did not name:** it
  rewrote Spec B's landed **Revision 14** body in place while refusing to sweep this ledger's edit log,
  on the rule that a past entry's measurements are not rewritten. **One rule now covers both, stated
  once in Spec A's new A-16 row:** *a revision entry's claim about what the document says is corrected
  in place by a dated annotation that quotes what it said; a revision entry's measurement, true at the
  commit the entry names, is never rewritten.* That is what Spec B Revision 14 already did when its
  per-commit figures were corrected — the superseded figures are quoted inside the correction, not
  erased — and it is why this ledger's §7 edit log is **still not swept**: its numbers were true at the
  commits its entries name, while A-14's *"132–135"* is a claim about the corpus that is false now and
  its *"existing rule"* half was false when written. A-14 is annotated in both places and erased in
  neither, and the 2026-09-13 entry above keeps its own `A6 wire change` sentence for the same reason.
- **A resequence off-by-one survived the sweep, inside a sentence the sweep rewrote.** Item 134 located
  the false derivability sentence at *"Spec B §6.1 step 5's quoted sequence"*. In Spec B it is
  **step 6**; **step 5 is the `no_wrap` step**, exactly as in Spec A. The sweep moved Spec A's number
  from 5 to 6 and left Spec B's, in the same sentence.
- **Spec A §5.11's opening still asserted *"MASTER §8.3 carries the same block"***, which the same
  pass's own **fourth** MASTER divergence disproves: MASTER's copy still annotates
  `expected_wrap_count` as *"device wraps + recovery wraps + 1 snapshot"*, which both rulings
  contradict. It is the sentence that would send a second implementation to transcribe from MASTER
  rather than from Spec A, which is the worst possible place for it. Replaced with the divergence
  named and item 141 cited. (*The brief that found this put the sentence eight lines above the
  `EpochAttachment` block; it is 27 — the sentence is at the section's opening and the block follows
  the `LP(x)` line and the `kind` table. The finding reproduces; that distance does not.*)
  *(**The 27 is annotated 2026-09-15 with the query it was published without**, which is the rule the
  paragraph two bullets down states and this line broke in the same entry —*
  `git show 7681f4c:docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md | grep -n 'MASTER §8.3 carries the same block\|^EpochAttachment {'`
  *— which answers `1588` and `1615` at `7681f4c`, the commit the brief read, so the distance is 27
  there and reproduces. A bare distance is not checkable at any other commit and both lines have since
  moved; the query is, and it is the thing to copy.)*
- **"Decorative" was scoped in Spec B §5.4's wire block and left unscoped in §6.1's prose** — the
  paragraph a server implementer reads immediately **before** the epoch-publication sequence, which is
  the worse of the two places to leave it. Revision 15 scoped the wire block and stopped. Both now
  carry the same meaning.
- **Two of the new inline anchors were a single quoted string containing an ellipsis**, so copying the
  anchor into `grep -F` returns **zero hits** — the exact failure the anchor convention exists to
  prevent, in the pass that introduced the convention's own sweep. Measured:
  `grep -rn -F 'engine.go … the GroupEngine interface (§6), EngineProcessed' docs/specs/` returns 0;
  the same string without the `engine.go …` prefix returns 1. m1's **table row 4** renders it
  correctly, as **two** strings joined *outside* the code spans, and the two inline copies (in M1-36's
  property and in the adapter-home paragraph) now match the table's form and say why.
- **`memory.go:581` in item 134 was off by one.** `:581` is the `if`; the
  `return protocol.Reason_REASON_EPOCH_INCOMPLETE` is at **`:582`**, which is what item 137, Spec A
  §5.11 and Spec B §6.1 all already cite. The off-by-one was item 134's alone.

**3 — the whole-tree count is dropped rather than corrected a fourth time.** Item 137 published *"464
matching lines across 15 files"* **measured at `7fb0dd9`** — the **parent** of `7681f4c`, the commit
that published it. That is the same error the paragraph directly above it was correcting: 456 was the
count at `2cbbb71`, the parent of the commit that published *that*. **A measurement between two named
commits is the only form worth writing down, so here is one: at `7681f4c` the same query gives 468,
four more than the number that commit published about itself.** Three consecutive passes have now
published a count that was wrong at the commit publishing it. **The repair is a rule, not a fourth
number: publish the query beside the value, and prefer a property over a count wherever one carries the
same argument.** Item 137 now publishes `git grep -l 'KeyPackage' -- '*.go'` naming **no file** — *no
Go file in this repository references `KeyPackage`* — plus the property that every file that does match
is a document. Both are checkable at every future commit and stay true until they stop being true,
which is when a reader should notice. The `-- '*.go' '*.proto'` scope keeps its **half-vacuous** label,
which item 137 already carried and which reproduces: `git ls-files '*.proto'` names no file.

**What this pass did not do.** It ruled nothing. It did not touch MASTER, or `connect`, or any Go file.
It did not sweep the append-only edit log, including this entry's own predecessor, and the rule for
that is now stated rather than assumed.

**Verified.** `go build ./...` clean; `go test ./...` green; `go test ./ -run TestThePlanLinter`
**7 of 7, `ok`**, before and after, with every check's finding count identical to baseline — 1b 7,
1c 1, 1d 189, 2a 18, 2b none, 3a 4, 3c 2, 4b 5, and both fatal checks **3b** and **3d** at **no
findings** in both runs. `git ls-files` equals `git ls-tree -r HEAD --name-only` at **102**, checked
before the commit rather than assumed. Every edited file measured **LF throughout, zero CR bytes**,
with `tr -dc '\r' | wc -c`. This repository still has exactly one branch, `main`, and no
`beta/message`; the work was done on `main` at `7681f4c`, which is again the half of the brief that
reproduces.

---

### 2026-09-15 — the retry that costs no wire bytes and would have shipped a nonce reuse, and a fatal linter check that could not see nine of the corpus's thirty-seven ledger citations

**Nothing is ruled here.** Items 132, 133, 134 stay filed and unruled; 142 stays filed and unruled and
its blockers go from one to four; 143 gains a concrete instantiation and stays unruled; **144 is new**;
MASTER stays un-amended (item 141). One Go file changed and it is a test file — `planlint_test.go` —
and no file in `connect` was modified; `connect` was read for measurement only.

**1 — THE DESIGN CORRECTION: A-16's price for a republished recovery wrap was unsafe as specified.**
A-16 answered *may a stranded recovery wrap be republished* with **yes, at zero wire bytes, needing two
normative sentences, all client-side**. The first two thirds hold and are kept. The last third is
wrong, and it is wrong in the way that ships a defect: a conforming implementer following §5.11 as it
stood would have rebuilt the record around the `ct_xwing` it had kept, and that is an XChaCha20-Poly1305
**nonce reuse**.

The fact was in the corpus the whole time and three consecutive passes reasoned past it:

- **`AAD_head` binds the RECORD's epoch and the RECORD's stream index** (MASTER §8; `AADHead` in
  `connect/message/aad.go` writes `h.Epoch` and `h.StreamIndex`).
- **The recovery wrap's `key_head ‖ nonce_head = HKDF-Expand(wrap_key, "wraphead/v1", 56)` binds
  neither** — it is a bare label — and `wrap_key` binds the **content** epoch.
- **The shipped server forces both AAD fields to move on a republish**: `store/memory.go:578` refuses a
  record whose epoch is not the current one, which is why the wrap was stranded, and `:610` refuses a
  `stream_index` that is not strictly greater, which Spec A §5.7's outbox rule already required.

So the head's `(key, nonce)` cannot move while the AAD must: keystream reuse plus Poly1305
one-time-key recovery, over a preimage covering `body_hash`, `blob_id` and `H(server_attachment)`.
**And §5.9's guardrail G5 — the corpus's one mechanical defence against AEAD nonce reuse — is vacuous
here**, because its defence is the `stream_index` reservation and the wrap head is not on the
`record_key[i]` ladder at all.

**What makes it repairable, and it is the load-bearing correction:** the reuse is a **procedure
choice, not a format constraint**. `XwingEncapsulate` cannot be derandomized — `crypto/mlkem`'s
`Encapsulate` takes no randomness argument (`connect/messagegroup/xwing.go:236`, asserted by
`xwing_test.go:277`) — so a republisher that re-encapsulates from the wrap **plaintext** gets a fresh
`(key_head, nonce_head)` unconditionally. That cannot be a bare MUST, because **no party can check it**:
the server never decrypts, the restorer sees only what landed, and the stranded ciphertext was refused
and exists only on the server's side of the wire. §5.11 now states it in §5.9 **G4**'s shape — make a
stored `ct_xwing` unreachable from the republish path rather than forbidden on it — and leaves the
ruling to the owner.

**Three prices A-16 omitted, now written down.** The body signature MUST be recomputed and MUST NOT be
copied, and a repairer that is not the committer signs under its own identity (§5.11 step 6 blesses
that repairer and no document says either thing). The retry is **not** all client-side: re-encapsulating
needs the wrap plaintext — `storage_root[k] ‖ archive_secret[k]` — retained in an outbox past epoch
*k*, which is a forward-secrecy ruling against `mls/group.go:2488`'s *"THE DELETE IS A SECURITY
REQUIREMENT AND NOT HOUSEKEEPING"*. (It is **not** a breach of MASTER §8.1's disappearing-message
promise; that promise is `eph_root`'s and `eph_root` is not in this payload. Overstating it would have
got the whole cost discounted.) And the wrap's **inner** `aead_ct` has **no nonce in any document** —
new item **144** — which decides 142 rather than sitting beside it, because Spec A §5.14's sibling KEM
construction seals at `nonce = 0` on the sole justification *"Every encapsulation yields a fresh
`deposit_key`"*, and that is the re-encapsulation rule written for a different record.

**2 — THE BOUND: `PastEpochWindow` = 32 is withdrawn, and no bound exists anywhere.** A-16 offered 32
as *"the ceiling the corpus already supplies"*. It fails on three counts, the first decisive.
**(a)** It bounds **rebuilding from live group state**, not publication lag. A stranded wrap was already
produced at epoch *k*; what republishes it is an **outbox**, and `DeleteGroupStateBefore` runs off
`self.context.Epoch` inside commit-apply (`mls/group.go:2594`) and reaches the MLS store —
`grep -rni outbox connect/mls/` names **no file**. A restorer bounded at 32 refuses to look at a lag-40
republish, losing the wrap in exactly the case the retry exists for, silently (item 138).
**(b)** The two numbers share no premise: `PastEpochWindow`'s own comment derives 32 from *"a product
promise about how long a laptop may stay closed"* (`mls/key_schedule.go:25-29`), while a search bound is
a per-unopenable-record work budget an attacker can spend. **(c)** The error is one-sided.
**And separately: A-16 moved the trial-decryption walk into §5.11's descriptive prose while leaving the
bound under *what a retry would take*, so §5.11 as it stood described an unbounded search.** It now says
in as many words that the walk is a derivation and not a licence until 142 is ruled.

**3 — THE ALTERNATIVE THAT DELETES THE QUESTION, measured rather than argued.** Exempting
`AttachmentRecovery` from the epoch-complete gate and putting the recovery leg back inside the fan-out
strands nothing: no republish, no re-seal, no bound, no search — and it is the only route that closes
item **138** for the recovery arm. Its landed-code price is one arm of one switch (`store/memory.go:939`,
shared with `pgx.go:1152`) plus `exempt: true` on one map entry (`store/contract.go:2576`). Measured by
running it: `go test ./store/...` with that arm widened produces **exactly one** failing leaf,
`…/OnlyTheExemptKindsPassTheGateWhileTheFanOutIsOpen/AttachmentRecovery`, which fails by **assertion**
and **not** through `attachmentKindsDeclared`'s by-name guard — that guard fires for a **new** kind and
is a different proposal's cost, and the write-ups that said "fails by name" had the mechanism wrong.
The checkout was restored and re-verified green before anything else was done. Its real price is
availability, ~18 extra round trips of group-wide non-writability per commit, and it does **not** make
the seal question moot because §5.11 step 6's repair still re-seals. Priced in 142 and in Spec B
revision 17; **not proposed**, because it reverses a 2026-09-13 ruling.

**4 — THE PLAN LINTER'S CHECK 3d COULD NOT SEE A BOLDED LEDGER CITATION.** `ledgerRefRe` ran over
`flatten(line)` with the markup left on, while `stripMarkup` sat two lines above being used for the task
qualifier. The plans bold the **number** — `ledger open item **142**` — so the pattern's digits ran into
an asterisk and the citation was not a citation. Measured at `cea05b8` over `docs/plans/*.md`: the raw
line matched **28** citation sites and the stripped line matches **37**, so **nine** were invisible to a
**fatal** check that reported *no findings* over all nine. All nine were in m1, and one of them —
`m1:3220`, `ledger open item **142**` — was written by the pass that then read the clean report as
coverage. The check now reads the stripped line; **at `cea05b8` the class it derives goes from 29 item
numbers to 41**, and the check now prints that size on every run beside the findings, because a floor of
one catches a class that read nothing and does not catch a class that read most of the corpus. (At the
commit this entry lands in it prints **44** against **30** for the old matcher, because this pass's own
document edits added citations — which is exactly why the size is printed rather than pinned.) The
control fixture gains a bolded citation with the asterisks around the number, so the repair is pinned:
reverting it fails `check3d_a_ledger_citation_that_resolves_to_nothing_and_a_date_that_is_not_one`
**by name**, verified by reverting it. All eleven finding counts are identical to baseline and check
3d is still at no findings.

**5 — FOUR QUOTED ANCHORS FROM THE PREVIOUS PASS RETURNED ZERO HITS UNDER `grep -F`, one of them the
repair of the very defect that entry announces as fixed.** Each measured before it was touched, each
repaired in place under A-16's rule.

- **The ellipsis, again, in the entry that fixed the ellipsis.** This entry's own predecessor wrote
  *"Not ruled and left open: ... ledger items 132–135"* as one quoted string — and three bullets below
  announced *"Two of the new inline anchors were a single quoted string containing an ellipsis"* as
  repaired. Zero hits against Spec A's A-14 row, where the string is live. Split into two anchors
  joined outside the quotes.
- **A re-ordered quotation presented as verbatim.** Item 137 quoted its own superseded text as
  *"464 matching lines across 15 files, measured at `7fb0dd9`"*; the text said *"Measured at
  `7fb0dd9`:"* **464** *"matching lines across 15 files"*. `grep -F` returns zero hits for the quoted
  form anywhere, including in the revision it quotes. Re-quoted in the source order.
- **Two supersession quotes that straddle a line break in the revision they quote** — item 142's own
  former headline, and Spec B §6.1 step 7's *"a `RecoveryTag` gained an epoch would be a wire change"* /
  *"reaching §5.4's encoding here"*. Both now split at the break, the form item 134 already prescribes
  (*"The longer form of the sentence spans a line break in every document, so grep it short"*).

**6 — TWO INTRA-SECTION CROSS-REFERENCES POINTED THE WRONG WAY, both in §5.11's retry block.** The
block sits **before** the numbered parts (1)–(5) and referred into them as though they preceded it:
*"(part (2) above)"* — part (2) is 138 lines below it — and *"part (4)'s signature rule"*, likewise
below. Both now say **below**. The `sixty lines on` distance in the rewritten text was replaced by the
quoted sentence it points at, under the rule item 137 states.

**7 — THREE SMALLER ONES, each reproduced.**

- **A scope claim that is measurably false, in a *transcribe from here* sentence.** §5.11's opening and
  item 141 both ended *"so the three documents' `EpochAttachment` blocks now disagree field for field"*.
  The query is now published beside the claim; it strips every annotation and the three documents' ten
  lines are **byte-identical** — eight field declarations, same order, same names, same widths.
  **One annotation of one field diverges normatively**, `expected_wrap_count`, and it is the field
  whose value opens an epoch, which is a sharper warning than *field for field*, not a milder one. The
  danger of an overstated scope claim is that a reader who checks one field and finds it identical
  stops believing the sentence.
- **The discriminator's probability was stated inverted, in both new copies.** *"every other fails"* /
  *"Poly1305 with probability `2^-128`"* — two strings, because it straddles a line break in both —
  says a wrong guess almost always **succeeds**. A wrong candidate
  fails with probability `1 − 2^-128`; `2^-128` is the chance it opens anyway, and that is the direction
  the search's correctness rests on. Corrected in §5.11 and in item 142.
- **`target_id` is defined nowhere in the corpus** and is the fourth input to `wrap_key`, so it is the
  value a restorer must reproduce byte for byte for the whole trial-decryption walk to open anything.
  It occurs in MASTER §7's derivation, in the documents quoting it, and in r3's un-adopted rewrite — and
  in **no definition**. `recovery_handle`, `wrap_target_handle`, a leaf index and a member id are four
  different byte strings; a publisher and a restorer that choose differently produce a wrap nobody can
  open with no error anywhere. Added to §5.11 (5)'s list of what the rulings do not state, with the
  inner nonce and the wrap head's plaintext.

**8 — THE BARE DISTANCE IN THIS LOG'S PREVIOUS ENTRY NOW CARRIES ITS QUERY.** That entry published
*"it is 27"* with no query, two bullets after stating the rule *publish the query beside the value*.
The query is annotated in place and re-run here:
`git show 7681f4c:… | grep -n 'MASTER §8.3 carries the same block\|^EpochAttachment {'` answers `1588`
and `1615`, so the distance is 27 **at the commit the brief read** and reproduces. Both lines have since
moved, which is the whole argument for the query.

**What this pass did not do.** It ruled nothing. It did not touch MASTER, or `connect`, or any
non-test Go file. It did not sweep the append-only edit log beyond annotating, in place and dated, the
two claims A-16's own rule says are corrected that way — the ellipsis anchor and the bare distance.
Two further stale sentences in older log entries (`field for field`, and the previous entry's own
`2^-128`) are **left standing**: they were claims made in entries this pass is not rewriting, and this
entry is where the corrected form lives.

**Verified.** `go build ./...` clean; `go test ./...` green; `go test ./ -run TestThePlanLinter`
**7 of 7, `ok`**, before and after, with every check's finding count identical to baseline — 1b 7,
1c 1, 1d 189, 2a 18, 2b none, 3a 4, 3c 2, 4b 5, and both fatal checks **3b** and **3d** at **no
findings** in both runs — and the ledger-reference class now printed at **44** where the same run with
the old matcher prints **30** at this commit (**41** against **29** at `cea05b8`, the corpus the finding
was measured over). `git ls-files` equals `git ls-tree -r HEAD --name-only` at **102**,
checked before the commit rather than assumed. Every edited file measured **LF throughout, zero CR
bytes**, with `tr -dc '\r' | wc -c`. The C5 experiment was run against `store/memory.go`, reverted, and
`git status --porcelain` confirmed empty before any document was written. This repository still has
exactly one branch, `main`, and no `beta/message`; the work was done on `main` at `cea05b8`.

### 2026-09-18 — MASTER amended: the three rulings transcribed, a four-week-old red-team finding adopted, and the disposition convention that lost it measured

**Change:** four documents. **MASTER** — §0 gains an *"Amendment to revision 9"* entry; §7's wrap KDF
adopts red-team finding **M-15**; §8.1, §8.2 and §8.3 take the three owner rulings of 2026-09-13.
**Spec A** — §5.11's three quotations of MASTER §7 move with it, its *"MASTER's annotation is stale"*
warning is superseded, and revision row **A-18** records the pass. **Spec B** — revision **18** records
that MASTER moved and this document does not have to, plus two in-place supersessions of present-tense
*"MASTER remains un-amended"* sentences. **This ledger** — items **141** and **144** close, **142**'s
blocker count drops, **145** and **146** are new. **No Go file changed. `connect` was not touched.**

**The scope the owner set was exactly two things, and this entry says what each cost.**

---

**1 — THE THREE RULINGS ARE IN MASTER, AND THE LOCATION LIST WAS SHORT A THIRD TIME.** Item 141 named
three locations on 2026-09-13 and a re-measurement found a fourth. **All four resolved exactly. Six
exist.** The two the list did not have are in item 141 and both are the same shape as the fourth — not
a stale number but a **sentence the ruling makes false**:

- **§8.2 step 4's `no_wrap` detector was unscoped**, so MASTER claimed for the recovery arm exactly the
  detector ruling 1 removes — in the same numbered list whose step 2 the item already flagged. A reader
  of MASTER alone would have concluded a missing recovery wrap is detected. Item **138** is the record
  that nothing detects it.
- **A second copy of the pre-split sizing, thirteen lines outside the sizing paragraph** — *"every join
  a 6.9 MB download"*. A pass editing only the paragraph the item names would have left it.

**The lesson is about how the list was built, not about who built it.** It was built by looking for
where a ruling changes a **number**. Both misses are where a ruling changes a **truth value**. The
query that finds all six is published in item 141 so it can be re-run, and it costs one command.

**The ruling's cost travelled with the ruling**, which is the whole reason the amendment was asked for:
§8.2 now states, where a reader of the fan-out meets it, that `expected_wrap_count` is **decorative for
the recovery arm** and that **nothing detects a missing recovery wrap**. §8.2 also names item **142**'s
`REASON_EPOCH_STALE` window and §8.1 names item **143**. Neither is ruled.

**Item 141's own byte-identity query re-runs clean.** The eight `EpochAttachment` field declarations
are still byte-identical across the three documents; MASTER's `expected_wrap_count` annotation's first
four lines are now byte-identical to Spec A's, and diverge only in the cross-reference — the form
`read_key`'s annotation already uses legitimately in each document. **The one normative divergence is
gone.**

---

**2 — M-15 ADOPTED, AND IT COULD NOT BE ADOPTED AS WRITTEN. This is the finding of the pass.** MASTER
§7 now derives `prk = HKDF-Extract(salt = "URmessage/v1/wrap-salt", ikm = ss)` and
`wrap_key ‖ wrap_nonce = HKDF-Expand(prk, info, 56)` over a **nine**-element `info` — r3's list is
eleven, and two X-Wing values carry what four separate X25519/ML-KEM values carried. **Zero wire bytes,
no code to migrate** — the grep returns three hits and all three are `leaf_keys_test.go` on the leaf's
wrap KEM *public key*.

**r3's block was written against a construction revision 5 deleted.** It takes
`ikm = ss_x25519 ‖ ss_mlkem` and binds four separate X25519/ML-KEM length-prefixes; its own keystone
B-1 still names `device_x25519_pub` and `device_mlkem_pub` as two separate leaf values. **Measured:
those six identifiers occur in this repository only inside r3's review file and in MASTER §7's own
sentence recording their deletion**, *"It replaces the hand-rolled `ss_x25519 ‖ ss_mlkem` combiner of
earlier revisions"* — quoted, because a line number is advisory and this one moved. Pasting the IKM
literally would have reinstated the hand-rolled
combiner MASTER calls *"the most dangerous composition in this document"*: a **revert of revision 5**,
not an adoption of M-15. Two X-Wing values stand in for the four, covering the same material in
X-Wing's own ordering, and MASTER §7 carries a paragraph saying so rather than substituting quietly.
**Every substantive claim of M-15 survives. The brief's instruction to adopt it "as written" is the one
claim in it that does not reproduce, and this is the record of why.**

**Both halves close, and only one had ever been filed.** Item **144** was the nonce. **The missing
`alg_id` — the half that violates §7.1's own anti-downgrade rule — had no ledger item at all**, and is
closed here without ever having been opened.

**Three gaps are INHERITED and named rather than filled**, because filling any one is a wire ruling:
`target_id` was already undefined; `u8(target_type)` and `u8(payload_type)` **arrive with M-15** and
have no code point anywhere. MASTER §7 states its block is **normative modulo those three** — so a
second implementation still cannot build a wrap from it, and what the block settles is the shape.

**What it does to item 142, stated because it reads the other way at a glance.** 142 goes from four
blockers to **three** and **stays filed and unruled**. **The hazard is confirmed rather than removed:**
`wrap_nonce` is a function of `ss` and `ct_xwing` and of nothing the record carries, so a republish
reusing a stored `ct_xwing` repeats the inner `(wrap_key, wrap_nonce)` exactly as the `nonce = 0`
closure would have. Freshness is still the safety condition; what changed is that MASTER's own
construction now says so instead of it being read across from §5.14. **142's re-encapsulation rule is
more clearly required, not less.**

---

**3 — THE PROCESS FAILURE, MEASURED RATHER THAN ASSERTED. New open item 146.** The owner asked this
entry to record the failure as well as the fix. It is not one finding — it is a whole severity class.
**For each finding id declared in r3, count the files at `bed5b84` naming it outside r3's own file:**

```
git grep -lE "(^|[^A-Za-z0-9-])$id([^0-9]|$)" bed5b84 \
  -- ':!docs/reviews/2026-08-12-r3-spec-review.md' | wc -l
```

**`B-1` … `B-12`: 1 to 6 files each, all twelve non-zero. `M-1` … `M-14`: ZERO, every one. `M-15`: 1 —
and that one is item 144, written on 2026-09-15 to say it had no disposition.**

**The convention that failed is visible in this file.** The 2026-08-12 R4/R5 entry closes *"0 blockers,
0 leaked labels (independently re-grepped), 8 majors and 22 minors remaining"*, and §1's state table
still carries *"Remaining | 30: 8 major, 22 minor."* **The blockers were re-grepped. The majors were
counted.** A count cannot be checked against a document — nothing re-derives *which* eight — so a major
neither applied nor rejected is indistinguishable from one absorbed. M-15 sat in that gap for four
weeks until a different chain of reasoning walked into the same hole and filed it as 144, and the
rediscovery cost **three passes**.

**This is not a claim that the other fourteen are unfixed.** The measurement is of the **disposition
record**, not of the text, and that distinction is the point: a finding whose fate no document states
is one the next reader re-derives from scratch. **The property that would have caught it** — *every
finding id declared in `docs/reviews/` is named at least once outside its own file* — is greppable,
cheap, and the same shape as the plan linter's check 3d for plan citations. **Whether it becomes a gate
is the owner's and is not ruled here.**

---

**4 — WHAT WAS FOUND AND DELIBERATELY NOT FIXED.**

- **New item 145: Spec A §5.14's rendezvous deposit is the same construction and still seals at
  `nonce = 0`.** M-15's argument applies word for word — it expands 32, derives no nonce, and omits
  `alg_id` from its `info` while putting it on the wire. It is **not unsafe as it stands** (§5.14
  justifies the zero nonce by encapsulation freshness, and nothing proposes republishing a deposit),
  but the corpus now carries **one KEM seal that derives a nonce and one that does not**, which is the
  shape a second implementation gets wrong. **Out of scope: the owner scoped M-15 to §7.**
- **The m1 plan carries two sentences this pass makes stale and did not edit.**
  `docs/plans/2026-09-04-slice1-m1-message-crypto.md:3054` says *"Read Spec A §5.11 and not MASTER"*
  citing item 141, and `:3721`–`:3725` tells Task 19 not to pick a nonce because the question is
  unruled. **Task 19 is now unblocked and the plan does not know it.** The scope the owner set names
  MASTER, Spec A and Spec B; the plan is neither, so it is **reported here rather than edited**. The
  plan linter stays green either way — item 144 still exists, so check 3d's citations still resolve.
- **Not ruled, untouched, and still filed:** items **132**, **133**, **134**, **142**, **143**. Item
  134's false derivability sentence in MASTER §8.2 step 6 is **marked in place and not repaired**,
  which is exactly what Spec A §5.11 and Spec B §6.1 already do with their copies; leaving MASTER's
  third copy unmarked in a step this pass rewrote would have re-published a known-false claim.
- **A revision bump was not made and is filed as a residual.** MASTER is amended under the *"Amendment
  to revision 9"* form, and the entry says plainly that **unlike the two 2026-08-25 amendments, this
  one does change rules**. Whether it warrants revision 10 is undecided here because a bump moves both
  children's parent pin and baseline row, and no ruling covers that.

---

**Verified.** `go build ./...` clean. `go test ./...` green, all packages. `go test ./ -run
TestThePlanLinter` **7 of 7, `ok`**, before and after, with **every check's finding count identical to
baseline** — 1a none, 1b 7, 1c 1, 1d none/189, 2a 18, 2b none, 3a 4, 3c 2, 4b 5, both fatal checks
**3b** and **3d** at **no findings** in both runs, and the ledger-reference class at **44** in both.
`git ls-files` equals `git ls-tree -r HEAD --name-only` at **102**, checked before the commit rather
than assumed. Every edited file measured **LF throughout, zero CR bytes** with `tr -dc '\r' | wc -c`.
`git status --porcelain` before the commit listed exactly the four documents and nothing else — the
edit scripts this pass used were deleted rather than left untracked. Item 141's own byte-identity query
re-run and still clean. **This repository still has exactly one branch, `main`, and no `beta/message`;
the brief named `beta/message`, which is `connect`'s branch (README:43, PROGRESS.md:19) and not this
repository's, so the work was done on `main` at `bed5b84` as every prior pass has been.**

---

**2026-09-19 — `docs/specs/2026-08-12-urmessage-protocol-design.md`,
`docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md`,
`docs/plans/2026-09-04-slice1-m1-message-crypto.md`, `SPEC-LEDGER.md` — the review of the 2026-09-18
MASTER pass. THE PASS ITSELF LANDED: the three rulings agree across all three documents everywhere a
reviewer could make them disagree, M-15 is adopted with its one substitution stated rather than made
quietly, and the three inherited gaps are carried rather than filled. What follows is what the review
found afterwards, and two of the seven are the pass's own artefacts failing against their own claims.**

**1 — M-15 HAD A SECOND INSTANCE IN MASTER, AND THE SWEEP THAT CLOSED THE FIRST DID NOT REPORT IT.**
§8.2's epoch snapshot was `K_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 32)` — **a 32-octet
AEAD key with no nonce, no `alg_id` and no AAD anywhere in the corpus**, one section from where §7
adopted M-15 in the same commit. Reproduced before it was touched: `snap/v1` five hits at `be7154d`, a
snapshot nonce **zero**. Fixed in M-15's own shape and not a second one —
`K_snapshot[n] ‖ nonce_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 56)` with an `AAD_snap`
binding `alg_id`, the group and the epoch. **`K_snapshot[n]`'s value does not change**: HKDF-Expand's
output is a prefix of any longer expand under the same PRK and `info`, measured over 1,000 random
roots rather than asserted, so it costs zero wire bytes, migrates no code (zero `*.go` hits in
`msgrepo` and `connect`), and Spec A §5.10's correction **E2** stays true. New item **147**.

**And what the derived nonce does NOT buy is written beside it rather than left to be assumed.** Both
halves are functions of the epoch alone, so a second snapshot sealed at one epoch — which §8.2 step 6
permits and item 132's non-unique wrap index does not refuse — reuses the pair exactly. It is safe
only under a canonical-serialisation property **no document states**. New item **148**, filed and not
ruled, because both repairs are rulings this pass was not scoped to make. *The one-shot argument was
considered and rejected on the evidence: it would have been legitimate, but step 6 defeats it.*

**WHY THE SWEEP MISSED IT, which is the half worth more than the fix.** The 2026-09-18 pass did sweep,
and it found one sibling — item **145**, Spec A §5.14's rendezvous deposit. It searched for M-15's
**construction** (a KEM seal: an encapsulation, `HKDF-Expand(ss, …)`, a `hybrid_ct`, an `alg_id` on the
wire) and not for M-15's **property** (an AEAD key from a bare expand, no nonce beside it, no `alg_id`
bound). The snapshot is not a KEM seal, so it sat outside the query while sitting inside the class.
**The property is greppable and the query is published with its output in item 147**: over the four
specs at `be7154d`, 32 distinct `HKDF-Expand` derivations, 24 of them 32-octet, of which exactly
**two** hand their output to an AEAD — `snap/v1` and `rzvdeposit`. The sweep found one of two, and the
other 22 are each named as the ladder root, MAC key, handle, seed or identifier they are.

**This is the third time in six passes at three altitudes.** Item **146**: a class dispositioned by a
**count** instead of a grep. Item **141**: a location query built from the **numbers** a ruling changed
instead of the **claims** it falsified. This: a class swept by the **construction** a finding names
instead of the **property** it names. **Each artefact was derived from the instance rather than from
the property the instance instantiates.**

**2 — ITEM 141'S PUBLISHED QUERY FINDS FOUR OF ITS SIX, AND THE TWO IT MISSES ARE THE TWO ITS OWN
HEADLINE NAMES.** `grep -nE 'no wrap|6\.9 MB|1,000 device|1,503|~55 round|device wraps \+ recovery
wraps'` was published as the artefact that *"answers all six locations"* and was **never run against
that claim**. Run: it misses §8.2's payload table and the fan-out's step 2 — *the single-record device
wrap and the pre-ruling fan-out*, verbatim what the item is titled after — and returns one line that
is none of the six. **Five of its six alternations are numbers**, so it is precisely the number-shaped
query the diagnosis one paragraph above it says cannot find a truth-value change. The item's diagnosis
was right; its artefact did not implement it.

**The derived query is built from the rulings' SUBJECTS, and its verification is published beside it**
— which is the part item 141 omitted:

```
grep -nE 'pq_secret.*eph_root|device wraps? .*recovery wraps?|recovery wraps? .*(device wrap|snapshot)|no_wrap|finds no wrap|every join|adds no signature'
```

Over MASTER at `bed5b84`: **nine lines in exactly seven locations, zero lines outside them**, against
the old query's **four of seven plus one false positive**. The coverage table is in item 141.

**3 — THE SEVENTH LOCATION: A NORMATIVE CONTRADICTION INSIDE MASTER §8, AND THE ONLY ONE THE
TRANSCRIPTION LEFT STANDING.** §8 said flatly *"Per **I5**, this layer adds no signature"* while §8.2,
rewritten by the same pass eight screens below, makes a body signature a **MUST** on all three wrap
record kinds. **I5 is not amended and does not need to be** — its own wording is *"no second signature
over **content**"*, a wrap body is not content (a wrap carries no MLS frame, so there is no inner
signature to defer to), and §8's sentence had dropped the qualifier. The epoch snapshot is explicitly
**not** among the three: it is a blob-ref record with no `ct_body`, so it has no wrap body to sign.

**4 — ITEM 142'S BODY WAS STALE AND UNANNOTATED, IN AN OPEN ITEM A READER GOES TO FIRST.** It read
*"blocked behind four rulings"* and named blocker (1) as *"the wrap's inner `aead_ct` nonce, which is
undefined in every document and is now open item 144"*. **Both false at `be7154d`**, and contradicted
by item 144's own closure two screens below, which does the arithmetic and says 142 goes from four to
three. 142 now says **three**, and says what the fourth's ruling did: it **confirmed** the hazard
rather than removing it, because `wrap_nonce` is a function of `ss` and `ct_xwing` and of nothing the
record carries, so a reused `ct_xwing` repeats the inner pair exactly as the `nonce = 0` reading would
have. 144's closure did the arithmetic and did not carry it back into the item it was about.

**5 — THE M1 PLAN'S STALE COUNT WAS TWO; IT IS SEVEN, ACROSS SIX PASSAGES, AND ALL SEVEN ARE NOW
EDITED.** The 2026-09-18 pass reported *"two sentences"* (`:3054` and `:3720`–`:3725`) and left the
plan alone on the ground that the owner's scope named MASTER, Spec A and Spec B. The scope argument is
sound; the count was not. **Four passages went unreported**, carrying five sentences: `:3237`–`:3239`
(*"ledger open item 144 says the wrap's inner `aead_ct` has no nonce in any document at all"* **and**
*"142 now names four rulings"* — two sentences, one passage), `:3727` and `:4205` (**`target_id` is
*"the fourth input to `wrap_key`"***, which was its position in the pre-M-15 four-element `info` and is
now the **fifth** of nine — a builder transcribing the preimage from either sentence builds the wrong
one), and `:4194`–`:4196` (a second copy of *"four rulings"* and a third copy of 144 as **Task 19's
stop sign**). This pass edits all seven with dated corrections, plus the snapshot derivation §1 moved.
**Task 19 loses two stop signs it did not know it had lost** — the wrap's inner nonce, and the
snapshot seal's — and keeps `target_id`.

**6 — A PUBLISHED BYTE-IDENTITY QUERY THAT DOES NOT PRODUCE THE BYTE-IDENTICAL RESULT IT CLAIMS.**
Pre-existing and re-asserted by the 2026-09-18 pass rather than introduced by it, in Spec A §5.11 and
in item 141. As written it stopped after `sed 's-//.*--'`, which deletes a comment's text and leaves
the indentation that preceded it: **25 lines for MASTER and Spec A, 33 for Spec B**, differing in
trailing whitespace and blank-line count, with `diff` reporting changes on all three pairs. **The
claim was and is true of the ten non-blank lines; what was false is that the artefact produced it** —
the same defect as item 2 above. Both copies now carry
`| sed 's/[[:space:]]*$//' | grep -v '^$'`, re-run: `diff` silent on all three pairs, ten lines each.

**7 — MASTER §7'S `info` TABLE AND ITS GAP LIST READ AGAINST EACH OTHER.** The table enumerated
`target_type`'s two classes while the gap list three paragraphs below said it has *"no code point, a
value table or a definition anywhere"*. Both now say the same thing and **the gap is not closed**: the
table gives the **domain**, which §8.2's payload table already fixes; no document gives the
**encoding**, which is what a publisher and a restorer must agree on. **The domain is not the
encoding.** No code point was invented.

**Nothing else is ruled here.** Items **132**, **133**, **134**, **142**, **143**, **145** and the new
**148** stay filed and unruled. Item **134**'s false derivability sentence in MASTER §8.2 step 6 stays
marked in place and unrepaired, as it is in Spec A §5.11 and Spec B §6.1. The revision-10 question
filed by item 141 is still the owner's and is not answered here.

**Verified.** `go build ./...` clean. `go test ./...` green, all packages. `go test ./ -run
TestThePlanLinter` **7 of 7, `ok`**, before and after, with **every check's finding count identical to
baseline** — 1a none, 1b 7, 1c 1, 1d none/189, 2a 18, 2b none, 3a 4, 3c 2, 4b 5, both fatal checks
**3b** and **3d** at **no findings** in both runs, and the ledger-reference class at **44** in both.
**Two class sizes moved and both are accounted for rather than waved past**, because a class that
shrinks is the failure this linter's own header exists to catch: the task-reference class **1616 →
1618**, the two new *"Task 19"* mentions written into the m1 plan by §5 above; and the
open-item-reference class **415 → 414**, one `M1-1` reference deleted with the sentence that carried
it (*"A `hybrid_ct` KAT is blocked on 144 the way Task 14 is blocked on M1-1's remainder"*), because
144 is closed and the analogy it drew no longer holds. Measured, not inferred: `M1-*` occurrences in
the m1 plan **254 → 253**, and the one that went is `M1-1` **15 → 14**. `git ls-files` equals
`git ls-tree -r HEAD --name-only` at **102**, checked before the commit rather than assumed. Every
edited file measured **LF throughout, zero CR bytes** with `tr -dc '\r' | wc -c`. Every query this
entry publishes was **run at the commit it names** and its output is in the item beside it, which is
the defect items 2 and 6 above exist to stop repeating. `git status --porcelain` before the commit
listed exactly the four documents and nothing else; the edit scripts ran from outside the checkout.
**Still one branch, `main`, and no `beta/message`** — the brief named `beta/message`, which is
`connect`'s branch (README:43, PROGRESS.md:19) and not this repository's, so the work was done on
`main` at `be7154d` as every prior pass has been.

### 2026-09-20 — r3's fourteen undispositioned majors dispositioned one by one, the state-table count that hid them replaced, and the gate proposed to prevent a repeat measured passing on the sentence that describes the failure

**Change:** this ledger only. §1's state table loses the *"Remaining | 30: 8 major, 22 minor"* row and
gains a **Review findings** row that points at a record instead of publishing a count; §5 gains
**eighteen** items, **149–166**. **No spec changed. No plan changed. No Go file changed. `connect` was
not touched.** Dispositioning was the deliverable; **nothing below is ruled and no finding is fixed
here** — the fixes are separate work these items scope, except where a finding was already satisfied,
which needed only recording.

**Why:** item **146** measured, on 2026-09-18, that r3's twelve blockers were dispositioned by id and
its fifteen majors by a **count** — *"8 majors and 22 minors remaining"* — and that fourteen of the
fifteen are named nowhere in this repository outside the review that raised them. M-15, the fifteenth,
cost three passes to rediscover and revealed a sibling on closing. The owner ruled that all the
remaining majors be dispositioned before CP3b work resumes.

---

**THE PREMISE, RE-MEASURED FIRST, BECAUSE A BRIEF'S OWN NUMBERS ARE CLAIMS TOO.** The query item 146
publishes, re-run at `bed5b84` and at HEAD `10f0a39`, over this repository **and** over `connect`:

```
git grep -lE "(^|[^A-Za-z0-9-])$id([^0-9]|$)" <rev> \
  -- ':!docs/reviews/2026-08-12-r3-spec-review.md' | wc -l
```

At `bed5b84`: **M-1 … M-14 all ZERO**; M-15 = 1; controls **B-1 = 5, B-6 = 4, B-11 = 3**. **The premise
holds.** At HEAD it does not hold identically, and that difference is item **166**.

**Two corrections to the premise, both measured rather than argued.**

**1 — The set is FOURTEEN, not thirteen.** r3 declares M-1 … M-15 and only M-15 is closed (items 144
and 147). The brief's *"thirteen"* is the same class of error the brief exists to catch, so it is
recorded rather than quietly absorbed. All fourteen received a verdict.

**2 — The published query is now SELF-POISONING, and only for the two ids that happen to be the
endpoints of a range.** At HEAD, **M-1 = 1** and **M-14 = 1**, up from zero, with nothing adopted,
rejected or filed in between. Both hits are `SPEC-LEDGER.md:2517` and `:5823` and both are item 146's
own sentence saying those ids have no disposition. M-2 … M-13 sit inside that sentence's ellipsis and
stay at zero. **Item 146 proposes exactly this query as a gate; it counts MENTIONS, not DISPOSITIONS,
so recording that a finding was never dispositioned passes it through the gate** — and writing the
elided middle out in full, which any conscientious reader of item 146 would do, passes all fourteen at
once with nothing decided. Item **166** files it with three repairs.

---

**THE DISPOSITIONS — items 149–162, one per finding id, each opening with the id and a verb.**

| Item | Finding | Disposition | A6 |
|---|---|---|---|
| 149 | `M-1` `alg_suite` | **STILL OPEN (partial)** — ciphertext half closed 2026-08-25, authenticator half never | **blocks** |
| 150 | `M-2` `epoch` u64 | **ALREADY SATISFIED** — and satisfied at `aa9303e`, before this repo's first commit | no |
| 151 | `M-3` roles + commit authorization | **STILL OPEN (partial)** — clause 1 applied, clause 3 absent in spec *and* unimplemented | **blocks** |
| 152 | `M-4` split `ct_head` | **STILL OPEN**, mechanism SUPERSEDED, property already filed as item **128** | **blocks** |
| 153 | `M-5` PSK combiner | **STILL OPEN (partial)** — ordering clause applied; overclaim and PSK untouched | **blocks** |
| 154 | `M-6` one normative wrap definition | **STILL OPEN** on its core; addressing clause applied 2026-09-18 unremarked | **blocks** |
| 155 | `M-7` PQ era | **STILL OPEN**, and worse than raised — the 2026-09-13 split doubled the arm it deletes | **blocks** |
| 156 | `M-8` epoch retirement | **SUPERSEDED** by key retirement; two residuals, one narrow ruling | no |
| 157 | `M-9` sign the retained header facts | **STILL OPEN**; the remedy is already precedented on M-9's own argument | **blocks** |
| 158 | `M-10` lifetime cross-group handle | **STILL OPEN** on its structural half; two of its claims **REJECTED** on measurement | **blocks** |
| 159 | `M-11` per-member resource forgery | **STILL OPEN**, transplanted, and now **permanent** rather than one epoch | **blocks** |
| 160 | `M-12` permute `entries[]` | **SUPERSEDED** by revision 4 by name; one disclosure residual, transcribable | no |
| 161 | `M-13` time-scope the delegation | **SUPERSEDED** — construct deleted, substance applied by revision 7 | no |
| 162 | `M-14` complete the vector list | **STILL OPEN**; §6 is transcription, the CAS acceptance item needs a ruling | no |
| 163 | `M-15`-adjacent, instance 3 | **STILL OPEN** — `entry/v1` expands 44 = 32‖12 against a 24-octet nonce | no |
| 164 | `M-15`-adjacent, instance 4 | **STILL OPEN** — the blob object's AEAD key, nonce, AAD and `alg_id` are stated nowhere | **blocks** |
| 165 | the state table's own number | **FILED** — it is r6's file, r6 and r8 are referenced nowhere, and 55 findings carry no ids | no |
| 166 | item 146's proposed gate | **FILED** — it is satisfied by the sentence that records the failure | no |

**Four are ALREADY SATISFIED or SUPERSEDED. Ten are STILL OPEN, all ten need a ruling, and nine of the
ten block A6** — every major except M-14, plus item 164. **Nothing was ruled.**

---

**THREE THINGS THIS PASS GOT WRONG ON ITS FIRST READING, AND WHAT CAUGHT EACH, because the corrections
are worth more than the verdicts they left standing.**

**(a) The lesson repeated inside the pass that was written to demonstrate it — item 158.** The first
M-10 sweep ran `grep -rhoE '[a-z_]*handle[a-z_]* *= *HKDF-Expand\([^)]*\)'` and reported *"exactly one
instance."* That regex enumerates the literal token **`handle`**, which appears nowhere in the property
M-10 states — it is `handle` because `recovery_handle` is the instance r3 named. The property-shaped
query names no token, and it finds **two**: `recovery_sig_seed = HKDF-Expand(recovery_root,
"idxsig/v1", 32)` → `recovery_verify_pub` is a 32-byte unrotatable cross-group identifier in the **same
struct** (MASTER §5.3:493-494) and the **same database row** (`store/migrations.go:351-362`).
**Consequence: r3's own proposed remedy does not close the property it states.** Item 147's failure, at
one altitude down, inside the disposition of a different finding. Item **163** publishes the
de-enumerated query template that catches this class.

**(b) Two claims that did not reproduce, withdrawn rather than shipped — item 158 again.** *"The
property got worse"* is **false**: `git show aa9303e:…design.md` line 167 is **byte-identical** to
HEAD, so the derivation never carried a server input **here**; r3's *"(member, server)"* describes
revision 3, which predates this repository. *"The disclosure was not applied at any of the three
sites"* is **false**, and the three sites are the three **r3** named: **MASTER §5.4:518-522 discloses
it explicitly**, with revision 4's single-server argument — the same argument this pass accepted to
score M-12 SUPERSEDED. What survives is sharper than what was withdrawn: **§5.4's *"Disclosed in §13"*
is a dangling forward reference**, because §13 never names `recovery_handle`.

**(c) A quotation read backwards — item 162.** `connect/mls/vectors_test.go:269` says a manifest of
sixteen nil runners reporting PASS is *"the shape gate 1 has to be **unable to reach**"* — it names the
failure the test **prevents**, and the test then asserts `families == 16 - len(expectedPendingFamilies)`
and fails on zero. Reading it as the file conceding vacuity inverts it. **The file's real disclosed
weakness is stronger and is now the one recorded:** the loop counts cases **offered**, not compared, and
*"family 6 is offered 77 cases and compares 22 of them"* — so the run's own `604` is an upper bound.
**Running the suite is what settled both**: `go test ./mls/ -run 'TestVectorManifestIsComplete|
TestVectorFamiliesVerify' -v` → `PASS (0.29s)`, *"9 families verified; 604 published cases offered."*
A grep for the five family names returns 7–12 files each and reads as ALREADY APPLIED; the run says
seven of sixteen families have no runner and **all five MASTER omits are among them**. The correlation
is also weaker than *"what MASTER does not name is what has not been built"* — **two of MASTER's
eleven named families, 2 and 8, are pending too.**

---

**THE STATE TABLE'S NUMBER HAS A SOURCE, AND IT IS NOT r3 — item 165.**
`docs/reviews/2026-08-12-r6-verify-remaining.json` contains **exactly 8 `MAJOR` and 22 `MINOR`
entries**. That is §1's *"30: 8 major, 22 minor"*, byte for byte, and it has been read as r3's majors
class — which has fifteen — for five weeks. **`grep -rn "r6-verify-remaining\|r8-verify"` outside
`docs/reviews/` returns zero hits**: neither file is named anywhere in this repository, not in this
ledger, not in a spec, not in a plan.

**And the minors are in a worse position than the majors, not the same one.** Every entry in r6 and r8
has four keys — `severity`, `location`, `problem`, `fix` — and **no id field**; r2's five, r3's eight
and r4's four minors are numbered only within their own files. So item 146's proposed gate is not
merely unsatisfied for them, **it is unrunnable on them.** Asked plainly, as the brief asked:
**dispositioned, or counted? Counted.** Six of r6's 22 minors were checked against HEAD by the literal
string each names and **five of five checkable ones reproduce verbatim, unapplied** — Spec A:4680 still
ends a sentence *"and in Spec C §."*; Spec B:87 still cites `research/r4-edit-plan.md`; Spec B:1052
still cites a §6.7 that does not exist in a document whose §6 ends at §6.4; Spec A:5187 still cites a
§6.2 in a document whose §6 has no subsections; and Spec B's blockquote drift has gone from **183 lines
to 239**.

**r8 is the sharper half.** It postdates r6, found **2 BLOCKERs** against a table that says
*"Blockers | 0"*, and both were in fact fixed — Spec B §4.3.11 exists — **but its revision entry
attributes the work to `research/rendezvous-plan.md` and names r8 nowhere.** Text right, record empty:
item 146's shape, one round later, against blockers.

---

**ONE THING THIS ENTRY COULD NOT MEASURE UNTIL IT WAS COMMITTED, AND IT IS THE POINT OF ITEM 166.**
Re-running the premise query at the commit that lands this pass, against `10f0a39`: **`B-6` 4 → 5 and
`B-11` 3 → 4**, both new hits `SPEC-LEDGER.md` at the two lines above that read *"controls B-1 = 5,
B-6 = 4, B-11 = 3"*. `B-1` does not move only because item 146 had already contaminated it the same
way. **Publishing a measurement of an id inflates that id's count**, so the effect item 166 files
against the subjects applies equally to the controls, and it is recorded here rather than left for the
next reader to trip over. Item 166 carries the same paragraph.

**Verified.** `go build ./...` clean **before and after**. `go test ./...` green, all packages, before
and after. `go test ./ -run TestThePlanLinter` **`ok`** before and after — no plan or spec was edited,
so no citation class could move, and none did. `git ls-files` equals `git ls-tree -r HEAD --name-only`
at **102**, checked before the commit rather than assumed. `SPEC-LEDGER.md` measured **LF throughout,
zero CR bytes** with `tr -dc '\r' | wc -c`. `git status --porcelain` before the commit listed exactly
one file. **Every query this entry and items 149–166 publish was run at HEAD `10f0a39`, and its output
is printed beside it** — including the two that produce a different number from the disposition they
support, item 149's `-A5` window (17, not 13) and item 154's document count (5, a presence grep), each
of which publishes its exclusion rule rather than leaving the gap for the next reader to find.
**Still one branch, `main`, and no `beta/message`** — the brief named `beta/message`, which is
`connect`'s branch (README:43, PROGRESS.md:19) and not this repository's, so the work was done on
`main` at `10f0a39` as every prior pass has been. **`connect` was read and never written**, which
`git -C ../connect status --porcelain` confirms empty.

---

### 2026-09-07 — m1 wave 1 recorded, two owner rulings and one the code made written in, and the class of plan statements the landed package refutes derived rather than sampled

**Change:** `docs/plans/2026-09-04-slice1-m1-message-crypto.md`, `docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md`
(revision **A-19**, §5.3 only), this ledger (**two** new items, **167** and **168**) and `PROGRESS.md`.
**No Go file changed. `connect` was read and never written** — `git -C ../connect status --porcelain`
empty before, during and after, including across the mutation run below, which goes through a
`go test -overlay` rather than through the working tree. **This repository is on `main`**; the brief
named `beta/message`, which is `connect`'s branch and not this one's, exactly as the 2026-09-20 entry
records of its own brief.

**Why:** m1 wave 1 is complete in `connect` — **seven** commits, `b9a31e2` through `34fc072`
(`git rev-list --count b9a31e2^..34fc072` = 7), in three adversarially reviewed batches and a closing
commit — and three rulings had accumulated with no home: two the owner made, and one the fix pass
made that changes what a client must persist. *(**This sentence said "four reviewed commits,
`b9a31e2`, `7a50f80`, `69464ae`, `34fc072`" and was corrected 2026-09-07, the same day.** Those four
are one landing commit and three review commits; the three that landed the other two batches —
`da0b999` (tasks 5–8) and `095fdd1` (tasks 9–12 and 9a), with `fe2a151` between — were named nowhere
in this repository. It is not a cosmetic slip: item **168** cited `7a50f80` as the commit `StreamKey`
shipped in, and at `7a50f80` `streamindex.go` still declares the `groupId` form the item is an
argument against.)*

---

**THE THREE RULINGS.**

**M1-8 — RULED. `LP(leaf_index)` is the four-octet big-endian reading**, `00 00 00 04` followed by
the index, eight octets, wherever `LP` wraps this integer. The owner's reasons are recorded because
the item asked for a *rule* and not a preference: the width is fixed so no encoder ambiguity exists;
it matches `wrap_target_handle`, which already writes `u32(leaf_index)` raw at that width; and the 3
octets it costs over a minimal encoding are invisible against a 4,112-octet size bucket. **A
confirmation, not a change** — it is what landed, confined to `leafIndexLP` and KAT-pinned. **It no
longer blocks the A6 freeze**, which it was filed as blocking. Spec A still owes §5.3's missing
`SenderHandle` formula and that half is untouched.

**M1-16 — RULED. `StorageRoot` delegates to `mls.CryptoProvider.Extract(salt, ikm)`** — shape (a),
the item's own labelled recommendation. The reason recorded is about the guardrail rather than the
call: the tree keeps exactly one direct `crypto/hkdf` extraction, so **Gate A needed no allow-list
widening at all**, and the rejected alternative is worse than one row — `hkdfAllowedPathsFor`
concatenates `hkdfExtractAllowedPaths` into the allowance for **every** needle, so one path added
there excuses `hkdf.Extract(`, `hkdf.Expand(` **and** `hkdf.Key(` together, and `hkdf.Key` is the one
the gate's own comment calls the worst to transpose. **G1 confirmed by execution, and the number is
six rather than the four the brief states** — re-measured here rather than carried:

```
sed 's|Extract(salt, ikm)|Extract(ikm, salt)|' messagegroup/keyschedule.go > <copy outside the tree>
go test -count=1 -overlay <overlay mapping keyschedule.go to the copy> ./messagegroup/ -v
```

`TestStorageRootKAT`, `TestSwappingTheStorageRootArgumentsChangesTheRoot`,
`TestTheThreeClassKeysAreDistinctAndPinned`, `TestTheThreeHandleDerivationsAreDistinctAndPinned`,
`TestRecordKeyLadderKAT`, `TestRecordKeyZeroTakesTheFourOctetReadingOfLP`. The confinement is
structural as well as derived: `crypto/hkdf` is on `connect/messagegroup`'s **forbidden**-import list,
so the package cannot spell the library's argument order at all.

**The epoch-zero handle key — ruled by the fix pass, and it changes what a client must persist, which
is why it is here and not only in a commit message.** `installEpochOnLoop` took its argument verbatim
as `group_handle_key` on one branch and expanded a root on the other, while the parameter's name, its
doc and `handle.go` all said *"storage root"*; both values are 32 octets, so nothing refused the
disagreement. The pass ruled **the parameter IS `group_handle_key`**, renamed it
`groupHandleKeyEpoch0` throughout and added a typed width refusal. Its argument is preserved in
**M1-4**: MASTER §8's clause is about what a member *holds* and names the key, while `storage_root[0]`
is epoch zero's whole key schedule, so persisting it for the life of the group to recover a public
routing identifier every member can compute is strictly worse. **Spec A §5.3 is amended (A-19)**,
because it said nothing about persistence and its only route left a reader holding the root. **The
inverse is undefended and is now item 167**: a caller following §5.3 as it stood is accepted in
silence and routes on a handle no peer computes.

---

**AND THE CLASS OF PLAN STATEMENTS THE LANDED PACKAGE REFUTES, DERIVED RATHER THAN TAKEN FROM THE
BRIEF — which is the part of this pass worth reusing.** The brief named three; deriving found
**nine**. *(**This read "eight" and was corrected 2026-09-07, the same day.** Nine is what the
enumeration supports and what the m1 plan and this commit's own message both say: three named in the
brief, and the six listed immediately below. The paragraph was internally contradictory — a headline
of eight over a list of six unnamed beside three named — inside one commit, and `PROGRESS.md`'s copy
said eight/three/**five**, which is a third value again. All three copies now read nine/three/six.)*
The class: *every declaration, parameter set or persistence obligation m1 states about a
wave-1 symbol, held against `connect/messagegroup` at `34fc072`.* Enumerated by pulling every
`func` / `type` / `var Err` line out of the wave-1 task span **and** out of *Interfaces produced by
this plan* — the two places a consumer writes its `Consumes` block against, so a stale one is a
consumer that does not compile — and holding each against the landed declaration.

**The six the brief did not name, and what each would have cost a reader:**

- **Task 4's epoch-zero paragraph** sends a reader to persist the **first storage root**. It is the
  same ruling as Task 10's, one task earlier and stated more definitely, and a sweep keyed on Task
  10's wording would have walked past it.
- **`WrapTargetHandle(… epoch uint64 …)`**, in the task and in the produced block, shipped as
  `contentEpoch`. **A name and not a shape**, so this plan's own R2 lets it through — which is the
  reason it is listed: `handle.go` argues the name *is* the mechanism, and a caller reaching for
  `RecordHeader.Epoch` gets a well-formed handle no fetcher resolves, with no error anywhere.
- **Task 7's `NewSenderRatchet` and `Next`** were two shapes behind: the constructor gained a
  `StreamKey`, a reserver and an error, and `Next` took M1-13's three-valued form under this task's
  own instruction. **M1-13 is annotated and still unruled** — implementing a shape a plan told you to
  implement is not a ruling.
- **Task 8's `ReceiverRatchet`** shipped with a constructor, a `PeekFor`/`Commit` split, a
  `ReceiverRatchets` table and a `ReceiverRatchetKey`. **M1-14 is annotated and still open** — the
  spec still gives the type one method.
- **Three of the four blocks in *Interfaces produced by this plan*** were stale, including the one a
  consumer needs most: `SealRecord` and `OpenRecord` are declared over unqualified `Record`,
  `RetentionClass` and `ServerAttachment`, and after the split every one of those is
  `connect/message`'s.
- **Tasks 8 and 10 say the ratchet tables are "keyed per M1-11's ruling"** and there is no ruling.
  Wave 1 implemented **both** of M1-11's readings, in two places: the receiver table is keyed on
  `(sender_handle, retention wire)` — the prose reading — and the ratchet's key material binds the
  **leaf** — the declaration's. They agree until a device is removed and re-added at a different
  leaf, which is the one case M1-11 exists for. **M1-11 stays open**, annotated, because a split that
  happens to agree in the common case reads exactly like a decision and is not one.

**Two members the class caught that no ruling covers are FILED rather than fixed**, because fixing
either means answering a question the owner has not been asked: **167** (the epoch-zero inverse) and
**168** (the shipped `StreamIndexReserver` is keyed on a `StreamKey` while Spec A §5.6 **and** §8.2
both still declare `groupId`). **168 is deliberately not M1-5**: M1-5 rules which fields a durable
*store row* is identified by and is the one piece of state that cannot be migrated by recomputation;
`StreamKey` fixes which *stream a reservation belongs to*, which is the only half in this package's
reach. Amending §5.6's block would state a keying M1-5 has not ruled, so neither spec is amended and
the divergence is recorded instead.

---

**WHAT THIS PASS DID NOT DO, AND WHY, because a brief's claims are claims too.**

**The brief says four workstreams have closed since `PROGRESS.md`'s last entry and none is in it.
Two of the four are already there, in that entry.** Its heading names *"the store on real
PostgreSQL"*, its **What landed** list carries *"The pgx store passes the contract against real
PostgreSQL — 241 passing, both implementations reporting 'ran the contract'"*, and its defect-class
section already carries three of the five p7 findings the brief lists as new — the `RefHash` panic
class, the unvalidated Update leaf and the commit that removes its own committer. `git log -- store/`
returns nothing after 2026-08-30. So **the store workstream is not re-narrated** in today's entry;
what is new about p7 is written as new and what was already recorded is named as already recorded.

**The "51-subtest contract" figure in the brief is stale and is not republished.** It comes from open
item **28**, dated 2026-08-30. `store/contract.go` at HEAD has **72** `t.Run` sites; the 2026-09-02
`PROGRESS.md` entry publishes **241 passing** instead. Item 28 is left as written, because it is a
record of what was decided on the day and not a live count.

**The document calendar has drifted ahead of the tree's, and today's rows say so rather than
matching it.** The four revision rows above A-19 read 2026-09-13 to 2026-09-18 and the commits that
landed them are dated 2026-09-05 and 2026-09-06; the entry above this one is headed 2026-09-20 and
its commit is `a13aad8`, 2026-09-06. Today is **2026-09-07** by the same clock that dates every
commit in both repositories, so that is the date on A-19, on items 167 and 168, on this entry and on
`PROGRESS.md`'s. It sorts last by position and not by date, and no earlier date was changed.

---

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **`ok` before and after** — and it was not vacuous in between:
the intermediate run failed check 3d, fatally, on seven citations of items **167** and **168** written
before the items existed, and went green when they were added. That is the check doing exactly what
the 2026-09-15 pass built it to do, on the first pass to cite a new ledger item since. `git ls-files`
equals `git ls-tree -r HEAD --name-only` at **102**, checked before the commit rather than assumed.
The `connect` commits, the 1,104-file tree and the **7,620** test figure were re-measured rather
than carried (the commit **span** was not — see the correction under **Why** above):
`go test -count=1 ./message/... ./messagegroup/... ./mls/... -v` at `34fc072` counts
**7,620 PASS, 0 FAIL, 0 SKIP**, which is the Definition of done's own three-root invocation.
`OwnLeafIndex() uint32` is declared exactly twice in `connect/messagegroup`, on the interface and on
`connectMlsHandle`, so the brief's *"there is no stub handle"* holds by measurement. **The
byte-for-byte reproduction is recorded as the reviewer's method and was NOT re-run here** — it is a
review artefact and no test in the tree performs it; what the tree holds instead is the
`chacha20poly1305` reconstruction of the AEAD itself (`recordaead_test.go`) and the KAT sets.
*(**True when written and false a few hours later, annotated here rather than struck because the
sentence is what made the gap visible.** `connect` `10cc20c`, 2026-09-07, adds
`messagegroup/keysource_test.go`: the whole-record rebuild over three records, a 256-bit negative
control on the exporter output, and a syntax-tree gate holding the reproduction's independence claim
to something that can fail. 14 mutations, no survivors; two of them — a constant and an entropy draw
into the session's write key — are caught by those tests alone. The tree reads 7,623 at `10cc20c`.
`PROGRESS.md`'s 2026-09-07 entry carries the same correction, which is where item 4 of the check that
found this asked for it.)*
---

### 2026-09-07 — M1-6 ruled, the cost written down as two ledger items rather than one sentence, and seven wrong numbers the previous commit introduced

**Change:** `docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md` (revision **A-20**, §5.3 and §5.11
(3)), `docs/plans/2026-09-04-slice1-m1-message-crypto.md`, this ledger (**one** new item, **169**;
items **48**, **110**, **128**, **137**, **143**, **152**, **168** annotated) and `PROGRESS.md`. **No
Go file changed. `connect` was read and never written** — `git -C ../connect status --porcelain` empty
before, during and after, including across the epoch measurement below, which runs through a
`go test -overlay` whose overlay file lives outside the checkout. **This repository is on `main`**; the
brief named `beta/message`, which is `connect`'s branch and not this one's.

---

**THE RULING. M1-6 / ledger item 128 — `ct_head` is always sealed under the DURABLE class ratchet,
whatever the record's own retention class.** MASTER §8.1 stands and Spec A §5.3 is what changes:
`RecordAeadHead` takes a `record_key` off the ladder rooted at `ClassKeys.Durable`, `RecordAeadBody`
off the record's own class ladder, and for a `DURABLE` record the two are one ladder. The signatures
do not move — both still take one 32-octet secret — so §5.3 states the binding in prose and in a
comment, because it cannot state it in a type.

**The owner's reason is recorded because the item asked for a rule and not a preference.** The head is
always retained, so it is keyed by the class that is always retained; under the replaced reading an
`EPH` record's head would be keyed under a ratchet built to be destroyed on schedule, and a retained
header would become unopenable at exactly the moment the body is meant to vanish.

**The accepted cost is written down as two open items rather than as a clause.** A non-`DURABLE`
record now draws head and body from two ratchets, so one record's single `stream_index` covers two
ratchet positions and no document says which position each takes. Item **143** carried that pin as
*owed*; it is now **DUE** — a precondition of sealing a non-`DURABLE` record.

**AND THE PIN CANNOT TAKE ITS OWN PROPOSED FORM, WHICH IS NEW ITEM 169 AND IS THE PART OF THIS PASS
NOBODY ASKED FOR.** Item 143's repair is *"pin `i = stream_index` in every ladder."* Derived against
the landed code rather than against the documents: the ruling gives one sender **one** head ladder
shared by all four classes, while `messagegroup.StreamKey` — `{GroupId, SenderHandle, RetentionWire}`,
`connect` `095fdd1` — counts **per class**, which is the whole reason item 168 exists. So one sender's
`DURABLE` record at `stream_index = 5` and its `PERMANENT` record at `stream_index = 5` both take head
position 5 of the one durable ladder: same `key_head`, same `nonce_head`, two headers, two AADs. Under
XChaCha20-Poly1305 that hands the message server the Poly1305 one-time key and header forgery follows
— item 143's own named harm, arriving on the ordinary record path instead of the wrap ladder. **And
the alternative reading is not free either**: a head ladder that advances once per record needs a
counter monotone across all classes of one sender, and neither document nor the shipped reserver
produces one. Three shapes are costed in item 169; none is ruled.

**HOW FAR THE REFUSAL IS LIFTED, AND IT IS NARROWER THAN "M1-6 IS RULED" SOUNDS. THE SCOPE IS DERIVED,
NOT CHOSEN.** m1 Task 11(a)'s refusal is lifted for **`PERMANENT` and `MEDIA`** — so **Task 15 is
unblocked**, its snapshot being *"one `PERMANENT`-class record"*. **`EPH` stays refused**, and the
refusal now names ledger item **152** rather than M1-6. Three reasons, each checkable:

- **Item 152 (`M-4`) says in terms that item 128 must not be ruled without it beside it, and names
  this exact sentence** — *"a ruling made on item 128's own terms — `ct_head` is DURABLE, that settles
  the ambiguity, `SealRecord` may stop refusing — is the reading that ships M-4's harm permanently."*
  It was not beside it. The ruling is the owner's and is not reversed here; what is recorded is that
  the objection stands unanswered.
- **The ruling's stated premise is false for exactly one class, and it is 152's class.** *"The head is
  always retained"* holds for `PERMANENT`, `DURABLE` and `MEDIA`; Spec B §7.2 sets `ct_head = NULL`
  for `EPH(1..5)` at `prune_after`, in the same statement that erases the body and zeroes the sender.
- **So the two positions do not conflict over the other three classes at all** — item 152's own text
  says its repair *"costs nothing for `PERMANENT`/`DURABLE`/`MEDIA`"* — and the whole of the
  disagreement is `EPH`. Lifting there and not there is what the two documents jointly support.

**Nothing was implemented for any of this.** `connect` is untouched; `SealRecord` at `10cc20c` still
refuses all three non-`DURABLE` classes, and widening it is m1 wave 2's commit. m1's Definition of
done, Task 11(a) Property 6, Tasks 5, 14 and 15, the wave table, the execution order and the A6
paragraph all say so.

---

**THE SEVEN WRONG NUMBERS, EACH VERIFIED BEFORE IT WAS CHANGED — because a correction applied to a
number that was right is the same defect as the original.** The check that ordered this pass listed
seven; one of the seven turned out to be **two** documents' worth, one was a **third** value in a
third file, and the class was re-derived rather than taken, which found three more.

1. **`epoch 1 to epoch 3` → `epoch 1 to epoch 2`**, `PROGRESS.md` and ledger item **110**. The source
   comment carries no digit on purpose. **Measured, not reasoned:** a `go test -overlay` case added
   outside the checkout logs `fixture epochs: A receiver=1, B receiver=1` and
   `the epoch A's commit OPENS: receiverA 1 -> 2`. One commit opens one epoch.
2. **eight/three/five → nine/three/six**, in **three** places that disagreed with each other:
   `PROGRESS.md` said eight/three/five, this ledger's own entry said eight over a list of six, and the
   m1 plan and the commit message said nine/three/six. The plan enumerates nine members. Nine.
3. **Item 168's commit: `7a50f80` → `095fdd1`.** At `7a50f80`, `messagegroup/streamindex.go` still
   declares `Reserve(groupId []byte, index uint64) error` — the form the item says the code diverges
   *from*. `StreamKey` lands in `095fdd1`. The query is in the item.
4. **`PROGRESS.md` now says the byte-for-byte reproduction was a review artefact, and says when it
   stopped being one:** `connect` `10cc20c`, `messagegroup/keysource_test.go`, three standing tests,
   14 mutations and no survivors, 7,623 tests. The ledger's own copy of the caveat is annotated the
   same way.
5. **The A6-blocker summary still listed M1-8**, ruled by the same commit that left it there — six
   where five remained. The plan's paragraph and this ledger's item **48** both now separate the six
   that carry the *wire-visible* label from the **four** that still need a ruling: M1-7, M1-24, M1-27
   and M1-33. **M1-6 is the second of the two ruled, so the count moved twice in one day** — and it
   is worth saying plainly that ruling M1-6 did not take a blocker off the board so much as move it,
   because item **152** blocks A6 for the same head ciphertext and is not an m1 item.
6. **"four commits, each adversarially reviewed" → seven**, `git rev-list --count b9a31e2^..34fc072`.
   And the table's commit column named the commit that **closed the review** rather than the one that
   **landed the tasks** in two of its four rows: batch B landed in `da0b999` and batch C in `095fdd1`,
   neither of which appeared anywhere in this repository. Both columns are named now, in the plan and
   in `PROGRESS.md`, and each row's test figure stays attached to the commit that row already
   attributed it to. **This is the same defect as (3)**, one level up: `7a50f80` was being used as the
   name of a batch.
7. **"thirty-two test call sites" → 27**, in the entry whose own closing rule is *"publish the query
   beside the number"*. Thirty-two is a count of grep **lines**: `git grep -n testTwoMemberGroup
   dd140bd -- mls/` returns 32 at the commit before `mls/four_member_group_test.go` was added, of
   which two are `func` declarations and three are comments — **27 invocations**, 26 of them in test
   bodies. Corrected in all three places `PROGRESS.md` carried it. `connect/mls`'s own file header
   carries the same 32 and is `connect`'s to fix, which is said rather than left implicit.

**AND THE CLASS WAS RE-DERIVED RATHER THAN TAKEN, which is where the rest of this pass came from.**
The class: *every claim `29f9778` makes about the `connect` tree or about its own corpus, held against
`connect` at `10cc20c` and against this repository at HEAD.* Beyond the seven: this ledger's own
"eight" (a third value for (2)); its closing *"no test in the tree performs it"*, true when written
and false by that evening; `PROGRESS.md`'s *"M1-6 … is unruled and is the one ruling still on the
critical path"*, which the same day's ruling falsifies; and item **48**'s stale A6-blocker list, a
second instance of (5) in a different document.

**ONE CLAIM WAS CHECKED AND LEFT ALONE, and it is the reason the check is worth running in this
direction.** `PROGRESS.md`'s *"every group runs an epoch 7"* looks like exactly the same kind of
introduced number as (1). It is not: it is `connect/mls`'s own idiom, at `group.go:4249`,
`proposal_list.go:1122`, `commit.go:115` and five other sites. Nothing was changed for it.

---

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **`ok` before and after** — and it is not vacuous over this diff:
check 3d reads every `ledger <n>` citation in the plan corpus against this file's numbered items, and
this pass adds **seven** citations of **169** to the m1 plan. Demonstrated rather than asserted:
renumbering item 169 to `169x` and re-running gives *"check 3d — a ledger citation that resolves to no
ledger item: 7 finding(s)"*, fatal, naming plan lines 972, 2842, 2866, 3293, 3500, 4611 and 4637; the
file was restored byte-identical (SHA-256 compared) and the check is green again.
`git ls-files` equals `git ls-tree -r HEAD --name-only` at **102**, checked before the commit rather
than assumed. The epoch measurement, the `streamindex.go` comparison at two commits, the commit span
and the `testTwoMemberGroup` counts were each run against `connect` and are quoted with their queries
above.

**What this pass did NOT do.** It did not implement wave 2 and it changed no Go file in either
repository. It did not rule item **143**, item **169** or item **152** — 169 costs three shapes and
rules none, and 152 is the owner's to take with 128's ruling in front of it. It did not touch
`docs/reviews/`, whose two `M1-6` sentences are accurate records of what a dated review said. And it
did not repair **§1 Current state**, which still reads *"Nothing is implemented yet. No code exists."*
over a 1,105-file `connect` tree and 7,623 tests: that staleness predates `29f9778`, is outside the
class this pass derived, and is named here so it is not found a fourth time by accident.
---

### 2026-09-07 — the options for items 143 and 169 laid out with their costs measured, four of 169's own claims corrected, and the class-blind server check that decides half of them

**Change:** `SPEC-LEDGER.md` only. Items **143** and **169** are amended in place; **no item was
added or removed** — `git show HEAD:SPEC-LEDGER.md | grep -oE '^[0-9]+[a-z]?\.'` and the same over
the working tree are byte-identical at **206** ids, which is what keeps the plan linter's fatal
check 3d exactly as it was. **No spec, no plan, no `PROGRESS.md`, and no Go file in either tree.**
`connect` was read and never written: `git -C ../connect status --porcelain` empty before and after,
and the two micro-benchmarks below ran in scratch modules **outside both checkouts**, removed after.
This repository is on `main` at `9e5b54d`; `beta/message` is `connect`'s branch.

---

**WHAT WAS ASKED FOR AND WHAT IS HERE.** Not a ruling: the shapes that close item 169's property —
*every `(key_head, nonce_head)` pair a sender ever uses is used once* — with their costs measured
rather than estimated, marked as the owner's, to be taken in one sitting with item **143**. Item 169
filed three shapes. **There are seven**, and the item's own three are (a) = B1 corrected, (b) = A1
and (c) = D.

**THE CLASS IS DERIVED, NOT ENUMERATED.** `key_head ‖ nonce_head` is
`HKDF-Expand(record_key_head[i], "rec/v1/head", 56)` over a chain rooted at
`HKDF-Expand(K_durable[n], "sender/v1" ‖ LP(leaf_index), 32)`, and the shipped
`RecordAeadHead(recordKey []byte)` takes one argument, so the pair is a function of exactly
`(K_durable[n], leaf_index, i)`. Every closure is therefore one of four moves — a **position** rule,
a **root** rule, a **derivation** rule (of which an explicit wire nonce is the degenerate case), or
replacing `K_durable[n]` — and there is no fifth. The seven shapes are those four spelled out; the
two non-closures a reader reaches for are named beside them, because *"bind `stream_index` into the
head"* adds nothing under 143's own pin (`i` **is** `stream_index`, so the two colliding records
carry the same value) and *"let the server refuse it"* reports a broken property rather than closing
one.

**FOUR OF ITEM 169's CLAIMS DID NOT REPRODUCE, and they are corrected in the item with their
queries.**

1. *"shared by all four retention classes."* `EPH` is **excluded** from the M1-6 ruling (Spec A
   §5.3:1271; this ledger at :1609), so the shared head ladder covers **three** classes today — and
   the unit that shares it is the **wire byte**, of which nine are legal, so it is nine the day item
   **152** rules `EPH` heads onto that root. That number is the multiplier every cost is denominated
   in.
2. *"No such counter exists in either document or in the shipped code."*
   `grep -n 'single .u64. counter per' docs/specs/*.md` returns **three** hits — MASTER §8:914,
   Spec A §5.6:1394, Spec B:2463 — each declaring `stream_index` as one counter per
   `(group_id, sender_handle)`, which **is** the class-blind counter the item says nothing produces.
   What does not exist is a parameter list that expresses it. That is item **168**, a different
   sentence.
3. *shape (b) "costs a fifteenth method on the `MessageStore`."* §8.2's two stream methods must
   change signature under item 168 whatever is ruled; a class-blind counter is a **key value**, not
   a call. Fourteen stay fourteen, and it is one durable row per sender rather than up to nine.
4. *the harm's reachability.* **The server's stream monotonicity is class-blind** — Spec B check (3)
   at :2221 over `message_sender`, `PRIMARY KEY (group_id, sender_handle)` at :882, and the shipped
   `msgrepo/store/memory.go:603-609`. A conforming server **refuses** the second colliding record
   and never holds both ciphertexts. The property is still broken and every path that sees both
   halves still recovers the Poly1305 one-time key; what over-reaches is *"hand the message
   server"*.

**AND CORRECTION 4 PRODUCED THE LARGEST THING THIS PASS FOUND, which nobody asked for.** The server
counts per `(group, sender)` and the shipped client counts per `(group, sender, class)`, so the
first `PERMANENT` record a sender emits after any durable traffic is refused
`REASON_STREAM_INDEX_REGRESSED` — item 168's permanent wedge, one layer out, on the **honest** path,
landing on m1 Task 14's and Task 15's first record. It is functional rather than cryptographic, it
arrives **before** the key reuse is reachable, and it is checkable by a two-record integration test
where the reuse property needs an adversary holding both ciphertexts. It also prices half the
option space: **every shape that keeps per-class counters owes a Spec B change** — a class column,
a wider primary key, Q7 at :1047, and the `EPH(0)` exemption at :2765 restated over the wider key.

**TWO MEASUREMENTS THAT ARE NOT IN EITHER ITEM AND THAT SEPARATE THE SHAPES.** A forward-only chain
cannot serve two independent counters, so every shape that keeps per-class counters **and** shares
one head chain needs one live copy of that chain per class, parked at that class's position — a
forward-secrecy regression on the head that no document states, against a ratchet that erases as it
advances (`ratchet.go:251`). And the head chain's forward erasure buys nothing today against an
adversary holding a live session: `GroupSession` keeps `storageRoot` and `classKeys` for the whole
epoch (`session.go:107-108`), from which every rung of every ladder of that epoch is recomputable.
Both are stated as facts with their queries, not as arguments for a shape.

**A RECOMMENDATION IS GIVEN AND IS LABELLED AS ONE — A1**, the class-blind counter, because it is
what three documents' prose, `message_sender`'s primary key, Spec B's check (3) and the shipped
server already assume, costs zero wire octets, zero KAT constants and zero retained chain copies,
closes item 143's device-wrap instantiation as well, and is the only shape neutral to a later
reversal of M1-6 for free. Its costs are written beside it: an `(k+1)`× ladder-walk multiplier at
every commit, a receiver window measured in shared positions, and **M1-25**'s transient counter
becoming load-bearing. **It is not a ruling.**

**THE MEASUREMENTS, each reproducible.** One ladder rung is **368.7 ns** — 2^20
`HKDF-Expand(SHA-256, prk, "ratchet/v1", 32)` in 386.6 ms, a nine-line `crypto/hkdf` program in a
scratch module — which reproduces `ratchet.go:93`'s *"roughly four hundred nanoseconds per rung"*
and its *"about four tenths of a second"* at `maxLadderWalk = 1 << 20`. A size-bucket-2 record
encodes to **4,364 octets** with a 96-octet `ct_head`, of which `ct_body` is **4,112** and the
framing outside the two ciphertexts is **156**; `AAD_head` is **182** octets and `AAD_body` **96**;
one 56-octet expand is **600 ns** and one SHA-256 over `AAD_head` is **91 ns**. Those came from
calling `message.EncodeRecord`, `message.AADHead` and `message.AADBody` from a scratch module with
`replace github.com/urnetwork/connect => ../connect`, which reads the checkout and writes nothing
in it. **Only one of the seven shapes costs a wire octet** (C3, +24 in the header, 4,364 → 4,388,
+0.55%), and **`ct_body` does not move under any of them**, so Spec B's `CHECK` on
`octet_length(ct_body)` is untouched throughout. The KAT bill is **eleven** pinned constants in
`connect/messagegroup/recordkey_test.go` for a change to `record_key[0]`'s info string and **two**
for a change to `"rec/v1/head"`.

**Reviewed by:** re-derivation against both trees rather than against the items. Every line citation
this entry and the two amendments make was resolved by printing the cited line: eighteen `*.go`
citations across `connect` and `msgrepo`, and nine document lines. **Two Spec B citations were wrong
on the first pass and are corrected here rather than shipped** — check (3) is at :2221 and the
`message_sender` primary key at :882; both had been written one and eleven lines short, and both
pointed at blank lines, which is the cheapest possible version of the failure this repository keeps
finding and is why the citations were printed instead of trusted.

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **`ok` before and after**, and its coverage of this diff is
stated rather than implied: check 3d reads `ledger <n>` citations out of `docs/plans/*.md` against
this file's item ids, and this diff **adds no plan text and no ledger item**, so the check cannot
move on it — the id list is byte-identical at 206, which is the property that keeps it green rather
than a property of the amendments. What was checked mechanically instead is every citation the
amendments make, above. `git ls-files` equals `git ls-tree -r HEAD --name-only` at **102**, checked
before the commit rather than after it.

**What this pass did NOT do.** It did not rule item **143**, item **169**, item **152** or
**M1-1**, and it did not implement wave 2. It changed no Go file, in either tree. It did not amend
Spec A, Spec B or MASTER, although correction 4 says three documents and the shipped server
disagree with the shipped client about how `stream_index` is keyed and item **168** already records
the divergence: which of them moves is the ruling, and taking it here would be the divergence
absorbed rather than recorded. It did not touch `PROGRESS.md`, whose wave-2 blocking sentences are
accurate until a shape is chosen.

### 2026-09-07 — items 143 and 169 RULED as shape A1, the documents brought to the ruling, and the state rows that said no code existed

**The ruling, and it is one ruling for two items.** The owner ruled items **143** and **169**
together as shape **A1**: the `stream_index` counter is **one per `(group_id, sender_handle)` and
class-blind**, and `i = stream_index` in every ladder — head, body, ordinary record and device wrap
alike. `StreamKey` loses `RetentionWire` and keeps `SenderHandle`. Implemented in `connect` on
`beta/message` at **`33932e0`**, three commits on `7a9ad2a`; **no Go file in this repository changed
and `connect` was read and never written by this pass**.

**Why A1, recorded because the reason is checkable rather than preferential.** A1 is the counter the
rest of the system **already declared**, and the client was the only half that disagreed:
`message_sender` is `PRIMARY KEY (group_id, sender_handle)`, Spec B's Q7 selects on the same pair on
every submit, and the shipped server gates stream monotonicity on `record.SenderHandle` alone —
`store/memory.go:600-610`, under a comment reading *"per (group_id, sender_handle)"*, with
`store/migrations.go` giving `message_stream_claim` `PRIMARY KEY (group_id, sender_handle,
stream_index)` and `message_sender` a `last_stream_index` on the same pair. **No retention class
appears anywhere in the counter.** So the byte m1 wave 1 shipped was not a divergence the documents
had left open: it was a **client/server split already in the tree**, and the server would have
refused the second retention class's first record with `REASON_STREAM_INDEX_REGRESSED`. A1 closes
that split, closes item 143's device-wrap instantiation on **both** AEADs, costs zero wire octets and
zero KAT constants, breaks nothing already sealed, and is the only one of the seven shapes that owes
no Spec B change. **Every fact in this paragraph was re-verified here before it was written down.**

**THE SHAPE CHANGE, WHICH IS THE HALF A READER WILL UNDERESTIMATE.** `Reserve` is now an
**allocation** — `Reserve(stream StreamKey) (uint64, error)` — not an assertion. Item **168**
measured a permanent wedge and diagnosed it as the key's coarseness; the cause is one level under
that, and it is the assert shape: a ladder that chooses its own number and offers it to a shared
counter meets a consumed index and stops, and a ladder that is **handed** a number cannot. So the
counter is the store's with no second copy, and `Next` walks its ladder to whatever index the store
returns, which is what makes `i = stream_index` hold by construction and makes `(key, nonce)`
uniqueness follow from index uniqueness alone. **§8.2 moves the same way**, so the *"method for
method"* correspondence with `messagegroup.StreamIndexReserver` survives the change rather than being
restated after it, and fourteen methods stay fourteen.

**What was amended, and the class was derived rather than taken from the brief.** Spec A revision
**A-21** — §5.6 (the interface block, the class-blind rule, the allocation contract, and M1-25's
second cost), §8.2 (both methods, and what M1-5 and item 170 still owe at that interface), §5.3 (the
position rule, and the MUST NOT that is now lifted for `PERMANENT` and `MEDIA`), §5.5 (the window is
refused by **distance**, so a class's usable reach is about `1024/k`), §5.10 and §5.11 (5)
(annotated with the ruling that answers them), §0.1's `Code` row, and the **A-20 row's own MUST NOT**,
annotated where a reader meets it. MASTER takes a dated amendment against **§8.1's ledger pointer and
nothing else** — *"not a new revision: no rule in this document changed"* — which is the ruling's own
argument rather than an omission. m1: Task 6's Produces block and its four corrected paragraphs, Task
11(a)'s second-guess warning, Task 14's two *"do not start against a guess"* sites, the wave table,
the schedule diagram, the interface-registry sketch, the §8.2 **anchor string** (which the ruling
changed, so the anchor row is corrected rather than left naming a signature that no longer exists),
the external-leg list, **M1-5**, **M1-12** and **M1-25**. `PROGRESS.md`: the tracks table and three
wave-1 bullets, plus today's entry.

**Five things the brief did not name, found by deriving the class.** The plan's §8.2 **anchor row**
(the ruling changed the string the anchor check greps for). **M1-12**, whose arithmetic is about
memory and which now has a CPU half, because A1 makes the tracked-pair count a per-epoch walk.
`PROGRESS.md`'s **tracks table**, which called this repository *"greenfield; specs written, no code
yet"* over 57 Go files and called track A *"p1 complete; p2 started"* at m1 wave 1. The **A-20
revision row**, whose closing sentence still directed a reader at a MUST NOT that A-21 lifts. And
`PROGRESS.md`'s own wave-1 bullets, one of which is the durable-store bullet that item **170** makes
load-bearing.

**§1 Current state, repaired, and it is the item the brief named.** It read *"Nothing is implemented
yet. No code exists."* from the first commit until today, over a `connect` tree of **1,105** tracked
files and **7,631** passing tests and a message server in this repository of **57** Go files and
**26,402** lines. Its four document rows were stale by up to fourteen revisions and 2,200 lines
apiece; `Implementation plan | Not written` stood over thirteen plans, one of them half-executed.
Every replacement row is a measurement. **It was named as stale by the 2026-09-07 M1-6 pass and left
standing because it fell outside that pass's derived class** — which is the same failure this
repository has now recorded three times, and the reason this entry says which five things fell
outside the brief's list.

**THE COSTS ARE THIS PASS'S OWN MEASUREMENTS AND THEY CORRECT A FORMULA, NOT JUST A NUMBER.**
Reproduced on this machine through `connect/messagegroup`'s own benchmarks at `33932e0`: one rung
**390.7 ns**; epoch-change sender rebuild **130.1 ms** at k=3, P=100,000 against **41.8 ms**
per-class; the last rebuild before the `maxLadderWalk` bound **1.32 s**; a class's usable
out-of-order window **341** of 1,024. **The options paper priced the rebuild at `(k+1) × P` and it is
`k × P`** — the measured ratio is **3.11** against a `k` of 3, not 4. Its 148 ms landed within a fifth
of the truth **by accident**, because it also quoted the rung 6% low, and that is the more dangerous
of the two errors because it survives a spot-check. Three independent runs — this pass, the
implementer's and the review's — agree on the ratio and disagree on the rung by 7%, which is the
right shape for a CPU measurement and the reason the ratio is what the correction rests on.

**Five findings against the implementation, filed as items 170–174 rather than carried as prose, and
every one reproduced before it was written.** **170**: A1 changes the durable **row**'s identity while
the ruling's own wording says it changes nothing — true of records, false of rows — and a store
holding wave-1 rows would answer `HighWater` 0 for an A1 key and re-issue `record_key[1]` under an
unmoved class key. Reproduced against the package's own fake, whose row string is derived by
reflecting over `StreamKey`'s fields, so the row identity **is** the field set; the mitigation, which
is what sets the severity, is that no durable implementation exists in `connect` **or** `sdk`.
**171**: the recovery both wedge comments name is impossible for the wedge A1 added — `NewSenderRatchet`
refuses any resume above `maxLadderWalk`, for **every** class of that sender — and unsafe for
`ErrStreamIndexRewound`. **172**: the receive-side rebuild is larger than the measured send-side one,
`≈130 ms per peer per epoch`, and `Track` caps no pair count. **173**: the mutation offered as
evidence that the starvation case observes the shared counter does not bite, and the rule-11 sweep
left a third enumeration beside the two it fixed. **174**: the file carrying the ruling still states
§8.2's correspondence in the assert shape and still prices the rebuild at `(k+1) × P` above a
benchmark that refutes it. **None of the five says the ruling is wrong or the implementation unsafe as
it stands**, and the review's verdict was `ACCEPT_WITH_FIXES`.

**What was checked and left alone.** The receiver **ratchet table** stays keyed
`ReceiverRatchetKey{SenderHandle, RetentionWire}` and the sender ladder map stays keyed by the
retention wire byte — both keyed by class **KEY**, which §5.5 mandates and which has no server row,
so neither is an instance of the class A1 repaired. §5.5's *"capped at 64 senders tracked per group"*
is **not** implemented and that is deliberate, under M1-12's adopted recommendation; it is annotated,
not corrected. And `SealRecord` at `33932e0` still refuses all three non-`DURABLE` classes with a
comment naming M1-6 rather than 152 — a `connect` staleness this pass records and does not reach.

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **`ok` before and after**. Its coverage of this diff is stated
rather than implied: this diff **adds five ledger items and cites all five from `docs/plans/*.md`**,
so check 3d is not vacuous over it — `readLedgerItems`' map goes **175 → 180** distinct ids (query:
`grep -oE "^[0-9]+[a-z]?\." SPEC-LEDGER.md | sort -u | wc -l`, over 210 → 215 matched lines) and the
plan's new citations resolve against the additions. **Proved rather than asserted:** renumbering item
**170** to an id nothing carries turns check 3d fatal with **4 finding(s)** — the four places the plan
cites it — and the file was restored byte-identical by SHA-256 afterwards. `git ls-files` equals `git ls-tree -r HEAD --name-only` at **102**, checked
before the commit rather than after it. The cost table above was produced by running
`BenchmarkSenderLadderRung` and `BenchmarkEpochChangeRebuild` in `connect` — a read of that tree;
`git -C ../connect status --porcelain` was empty throughout.

**What this pass did NOT do.** It did not rule item **152**, **M1-1**, **M1-5** or **M1-25**, and
items 170–174 are filed rather than ruled. It did not implement wave 2 and it changed **no Go file, in
either tree**. It did not amend Spec B or Spec C, and MASTER's amendment changes no rule MASTER
declares — which is not restraint, it is what A1 being the counter the schema already keeps actually
means.

### 2026-09-09 — `s2` written: the two legs the owner assigned, the four blockers that sit outside both of them, and a method count four independent reads got wrong

**The document.** `docs/plans/2026-09-09-slice2-s2-client-submit-leg.md` — 15 tasks in five waves,
written to the shape p1–p8, s1 and m1 are written to: Global Constraints, Interfaces consumed,
Interfaces produced, File Structure, then per task a **Files** list, an **Interfaces** block naming
what is consumed and what is produced, numbered steps, and a mutation set. It supplies **no test
code**, per R1 and per the roughly thirty plan-supplied tests p1–p8 shipped that could not fail.

**What it says that the assignment did not.** The 2026-09-06 ruling gave `s2` legs 4 and 5 on the
reasoning that *"`sdk` already owns transport and storage."* Measured at `sdk` `432986f`, half of
that holds. `sdk` owns a **VPN** transport — one production `connect.Client`, inside
`deviceLocalProvider` — and no request/response correlator, no fragmenter and no message-server
binding at all. Its storage is `os.WriteFile`, one value per file, with **zero `Sync()` calls in
production code**; contract clause 1 is *"Reserve returns only after the reservation survives a
process death"*, and there is no precedent in that tree to copy. `s2` is not a plan that wires two
existing things together. It builds both.

**Four blockers sit outside both legs, all four in `connect`, and none has an owner.** Filed as
**S2-1** through **S2-4** and stated in the plan's **first paragraph** rather than discovered at a
task, because plans here have been read as milestones before. **S2-1:** `GroupSession`'s complete
exported method set is **seven** methods and none returns `read_key`, `write_key`, `storage_root` or
`group_handle_key` — yet `req_auth` is REQUIRED on every Fetch, `bootstrap_write_key` is
`write_key[0]`, and every `EpochAttachment` carries both keys of epoch *n+1*. The only derivation
runs through an **unexported** exporter label, so the workaround is a second copy of the one
derivation the m1 standing test proves the whole record layer against. Corroborating rather than
asserted: `msgrepo/harness`'s own `Fetch` takes `readKey []byte` as an explicit parameter *because it
has no session to ask*. **S2-2:** `server_nonce` is copied once at construction with no setter, while
the server rotates it at every Hello — so the first reconnect of a real `connect.Client` makes every
later record `REASON_REJECTED`, which CP3c already proves. **S2-3:** `pq_secret` has no delivery
channel, so the only thing making two clients agree on a storage root is a test constant — the exact
thing CP3b forbids. **S2-4:** `JoinFromWelcome` is an unconditional refusal, so there is no exported
path by which two clients share one group at all. **A finished `s2` does not reach CP3b**, and the
plan's Definition of done says so in the row that would otherwise be read as the milestone.

**Leg 4's one sentence hides an entire subsystem, and this is the largest correction the plan makes
to the assignment.** Read out of `msgrepo` source rather than from a document: `api/submit.go`'s
`CreateGroup` refuses unless the initial commit is `IsCommit` with header `Epoch == 0` and carries an
`AttachmentEpoch` whose `Epoch.Epoch == 1`; `store/memory.go`'s `wellFormedEpochAttachment` refuses
that attachment unless both keys are 32 octets **and `ExpectedWrapCount != 0`**, so group creation
*promises* a fan-out; and the store then refuses every ordinary submit with
`REASON_EPOCH_INCOMPLETE`, exempting only wraps and the marker. **CP3b's one text message is the
FOURTH thing the client submits**, not the first, and Task 9 is that sequence.

**Leg 5 is only half the durability CP3b needs.** `TrackSender`'s `headIndex` is documented as the
caller's own state that must **never** be read off a record header — the reason is adversarial, since
a peer that chose the number would choose how much work the receiver does — and §8.2's `MessageStore`
declares nothing for the receive side. That second store is **S2-6** and Task 12 builds it.

**Ledger item 170 gets a MECHANISM rather than the sentence it asked for, and the plan says why.**
Item 170 proposed one sentence in this plan: migrate pre-A1 rows by taking the maximum over the
classes, *or* version and refuse the key space. The plan requires the second and requires it as a
mechanism, on two grounds. First, the migration half is **vacuous**: `s2` is the first durable
reserver in any tree — a grep for the interface and for `ReserveStreamIndex` over `connect` and `sdk`
finds the interface, the ratchet, the session and the test fakes only — so a store that has never
existed cannot hold a pre-A1 row, and dead code on a safety path is worse than none. Second, and this
is the R4 half: the **property** is *"a row this build cannot key is answered as a silent zero"*, and
pre-A1 rows are one **instance** of it — a later M1-5 ruling that moves row identity again is
another, and a half-written file is a third. A version tag in the key derivation refuses all three
identically, so **the plan is safe whichever way M1-5 is ruled**. It still asks for the ruling
(**S2-5**), and Task 1's mutation 3 — plant a pre-A1 row, read with an A1 key, and require a refusal
rather than a silent zero — is item 170 reproduced in `sdk` as a mutation that must kill.

**The scheduling fact worth having: `s1` does NOT block this plan.** s1's own items say **S1-9**
*"blocks s2 entirely"* and **S1-4** and **S1-8** *"blocks s2's schema"*. Measured, all three are
narrower than they read. Legs 4 and 5 name **no s1 symbol**. `StoredEntry` appears in exactly **four**
of §8.2's fourteen methods — `PutEntries`, `EntriesBefore`, `EntryById`, `SearchEntries` — and **none
is a stream method**, so S1-9 blocks the entry half and not the reserver. S1-4 and S1-8 block the
`pin` and entry schemas, which are not on the CP3b prefix at all. What genuinely waits for s1 is
**surfacing** onto `MessageClient`, and the plan does not do that. The plan therefore also declines
to declare a **partial** `MessageStore`: A8 makes the fourteen-method bound the point of the
interface, so it declares the concrete store with the two stream methods spelled as §8.2 spells them
and no interface at all (**S2-12**).

**The §8.2 correspondence question, answered by measurement rather than left open.** m1's plan text
says §8.2 is `messagegroup.StreamIndexReserver` *"method for method and now parameter for parameter
too"*. It is not, and **Spec A §8.2 itself says so** in the paragraph the A1 amendment added: *"the
flattening from these two `[]byte` parameters to its comparable `StreamKey` is the implementer's."*
The method **names** differ and the parameter **shapes** differ; what is method for method is the
direction and the key. So an adapter is **mandatory**, a task dispatched on m1's wording would not
compile, and Task 3 is the adapter. Worse, `connect/messagegroup/streamindex.go` still quotes the
**pre-A1** §8.2 — so three documents state this three ways and the **source comment is the stale
one**, which inverts the usual read-it-from-source rule. Filed as **S2-15** with the one-line
corrections it owes to `connect` and to m1, neither of which this pass may make.

**And one number this pass got by counting rather than by reading.** Four independent reads of
`messagegroup.GroupHandle` during this plan's preparation returned **18, 22, 24 and 26** methods.
Counted off the syntax tree it is **23** (`GroupEngine` is 4). Every one of the four was a hand count
and every one was wrong; the plan writes the number down **with its derivation attached** and with
the instruction *count it, do not read it*, because a plan's Interfaces block is the one place a
wrong method count is copied forward silently. This is the same defect class as ledger **25**'s seven
call sites spelling a signature that had moved.

**Two claims corrected before they were written down, each with its query published.** *"`connect`
holds no fragmenter"* — a grep for `MessageServerFragment` over `connect`, generated files excluded,
returns **one** hit at `33932e0`, a name-to-number entry in a test, and no cut, no reassembler and no
part-size constant; the plan says that rather than *"returns nothing"*. And *"X-Wing has zero
production callers"* — the only production file matching the two X-Wing entry points is `xwing.go`,
which **declares** them.

**Measured against a moving tree, and said so.** `connect`'s working tree carried **uncommitted and
actively changing** work throughout this pass — an untracked-then-staged `messagegroup/epoch.go`
declaring `NewPqSecret` and a `ProvisionalEpoch` with `StorageRoot()`, `WriteKey()` and `PqSecret()`
accessors, which is m1 Task 13 in flight. The plan is written against the **commit** `33932e0` and
reports that work as measured, not as landed. **S2-1 was re-measured against the working tree and
survives it:** `GroupSession` still has the same seven exported methods and still no key accessor
there, so the gap is in the interface and not an artefact of reading an old commit.
`ProvisionalEpoch` does not close it either — it takes `storageRoot` as a **constructor parameter**,
so it derives nothing, and it covers epoch *n+1* rather than the live one.

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **ok before and after**, and its coverage of this diff is stated
rather than implied: the corpus grew by one document, so every derived class grew with it — the
property class **176 → 233**, the class-deriving property class **34 → 48**, the task-reference class
**1,645 → 1,843**, the open-item-reference class **458 → 546**, the ledger-reference class
**110 → 122**, and the Consumes-entry class **231 → 246**. **Those six are measured against the tree
this commit actually contains, and getting there took two corrections worth recording.** The draft's
run gave three of them differently, because the draft was still being repaired. The run after *that*
gave the same three differently again — **1,844**, **548** and **129** — because by then the working
tree also held **another agent's uncommitted amendment to `m1`**, citing six ledger items that are
not in this commit. Both wrong sets would have read as measurements. A class size is a property of a
**tree**, and on a shared checkout the tree under a measurement is not automatically the tree under
the commit. **Every fatal check is clean and stayed
clean**: 1a, 1d-fatal, 2b, 3b, 3d and 4a all report *no findings*, so the new document's **15** tasks,
its **57** properties, its **15** `S2-n` definitions and its ledger citations all resolve. **Every
reporting check returned to its exact baseline** — 1b **7**, 1c **1**, 2a **18**, 3a **4**, 4b **5** —
which is the measurement that matters, because it says the new document contributed **zero** findings
to any of them; the first linter run over the draft reported 1b at **9** and 2a at **26**, and both
were repaired rather than accepted. The one class that moved is 3c, and it moved the right way: `s2`
now having a document **removes** its own dangling references from the corpus, taking s1 from
**107 → 96** findings and m1 from **43 → 14**, against **8** added by this document's own references
to `s5`, which has no plan and is truthfully named as the owner of the engine factory and the
layering gate. `git ls-files` equals `git ls-tree -r HEAD --name-only` at **102** before the commit,
checked before rather than after. `git -C ../connect status --porcelain` and
`git -C ../sdk status --porcelain` confirm **no file in either tree was written by this pass**;
`connect`'s non-empty status is another agent's in-flight work, described above and not touched.

**And this repository was not a clean checkout either, which changed what got committed.** When this
pass came to commit, `git status` showed `SPEC-LEDGER.md` **and** `docs/plans/2026-09-04-slice1-m1-message-crypto.md`
modified — and the ledger's working copy was **836 lines** ahead of `HEAD`, of which roughly 700 were
another agent's: **ledger items 175–180** and the `m1` amendment that cites them, none of it
committed. Appending to that file and staging it would have swept an unreviewed 700-line change into
this commit under this commit's message. So this commit was built by reconstructing the ledger as
`HEAD` **plus this pass's two edits only** — the state-table row and the entry you are reading —
staging that and the new plan file and **nothing else**, and restoring the other agent's work to the
working tree afterwards untouched, so their diff against the new `HEAD` is exactly what it was. The
committed diff is **two files**: one new plan, and `SPEC-LEDGER.md` at **+162/−1**. Items 175–180 are
**not** in this commit, which is why the ledger-item map here still holds **180** distinct ids and not
186, and why the three class sizes above are the ones they are.

**What this pass did NOT do.** It ruled **nothing**. Items **152**, **170**, **M1-1**, **M1-5** and
**M1-25** are still open and still unruled, and the plan files **fifteen** new open items as **S2-1**
through **S2-15** rather than resolving any of them — including the one place two defensible readings
exist (whether the §4.3.3 projection should be promoted into `connect/message` or stay two
independent builders, **S2-9**), where the plan names both readings with their costs and takes a
position only because something has to compile. It wrote **no Go**, in any tree. It amended no spec:
the §8.2 question above was answered by reading Spec A as it already stands, not by editing it. It
did not correct `connect/messagegroup/streamindex.go`'s stale §8.2 quote or m1's *"parameter for
parameter"* sentence — both are filed as **S2-15** and both are somebody else's commit. And it did
not touch `PROGRESS.md`, whose CP3b state rows this plan's existence does not change: `s2` being
written moves nothing on the bar, which is the plan's own first paragraph read back to it.

---

### 2026-09-09 — the three `M1-1` option sets composed against each other: they describe one walkable body, the recommended signature does not cover the recommended fields, and five disagreements filed

**Change:** `SPEC-LEDGER.md` gains open items **175** through **180**. Item **175** is the amendment
to m1's open item `M1-1` (and to `M1-7`): the three independently produced option sets — the wrap
body's field list W0–W6, the signature's placement and coverage S1–S6, and the padding scheme P1–P8 —
composed into one body, with a wire-decidability matrix, five costed composites, a recommendation
labelled as one, and the six sentences a ruling must carry to be a closure. **All twenty-one shapes
are recorded in the item's §8** with their own costs, their own unwritten disciplines, their own
behaviour under a reversal of A1 or M1-6, and each set's own recommendation labelled as its author's —
so the owner rules on the shapes and not on a summary of them, and so the sets stop living only in a
brief. Their twelve open problems are carried with them. Items **176**–**180** are
the five things the three sets disagree about. Item **137**, the anchor entry for the 2026-09-13
`M1-1` rulings, gains a pointer. The m1 plan's `M1-1` item gains an eight-line paragraph naming the
amendment and saying nothing is ruled.

**Why:** Three answers to three questions about one body were produced independently and had never
been held against each other. A field list, a signature placement and a padding scheme have to
describe **one** decodable body; the only way to learn whether they do is to build the body out of
all three and walk it. They do — and one thing breaks, and it breaks silently.

**NOTHING IS RULED.** `M1-1`, `M1-7` and ledger items **132**, **142**, **148** and **152** stay filed
and unruled. Wave 2 is not implemented. **No Go file in either tree changed.** No spec changed: Spec
A §5.11 (2)'s *"the recovery wrap's `ct_body` **is** `hybrid_ct`, followed by zeros to its rung"* is
still normative, and four of the five composites would falsify it — which is the ruling and not this
pass's to take. `connect` was read and never written.

**The finding, and it is the one a builder would otherwise meet at Task 14 step 1.** The three
recommendations — **W1+W5** for the fields, **S1** for the signature, **P2** for the padding — do
compose into one body a parser can walk with no key and no payload-type knowledge:
`LP32(1257) ‖ envelope(15) ‖ hybrid_ct ‖ zeros`, occupancy **1,261** of the 4,096 rung, tail
**2,835**, `ct_body` unmoved at 4,112 and the record unmoved at 4,398. But **S1's preimage does not
reach one octet of W1+W5's envelope**: the envelope sits outside `hybrid_ct` and the signature sits
inside `aead_ct`, with `LP(ct_xwing)` between them. So the composite signs the record header, the KEM
transcript and the secret, and leaves the four fields the field-list ruling exists to add signed by
nobody. Three of the four are re-bound by MASTER §7's nine-element `info` — a binding neither set
names, and the thing that makes the composite *accidentally* safe rather than safe. The fourth,
`u32(publisher_leaf_index)`, is bound by nothing at all on the recovery wrap and by a key every
member holds on the device wrap. **The repair is one term — `LP(wrap_envelope)` in the preimage,
1,305 → 1,324 octets, zero body octets and zero wire octets.**

**Wire-decidability was judged independently and the answer is a matrix, not a yes.** It is three
questions asked of three parties holding different key material, and collapsing them is how the three
sets reach three verdicts about one composite: the recommended shape is **decidable in its fields and
undecidable in its authentication**. Set 1's first reason for its own recommendation — *"the only
shape under which the wrap body is decidable from its own octets"* — is true of the fields and false
of the record, because S1 is the least decidable shape on its own board. Under every S1 composite,
Spec A §5.11 (4)'s *"a client MUST NOT honour an unverified wrap"* is enforceable **only** by the
decapsulating target: no other party can tell a signed wrap from an unsigned one. That is a
legitimate ruling to take and it has to be a stated one. The composite that gives the property up is
priced beside the four that do not — **C4**, signature in the attachment, **+68 octets per record**
(4,398 → 4,466 measured), ~+170 KB per epoch fan-out, a Spec B §5.1 check-3 change, and a publicly
verifiable Ed25519 signature on all 2,501 wrap records that hands the operator per-epoch attribution
of the committer.

**The five disagreements, filed rather than reconciled in prose.** **176**: the signature preimage
and the field list do not overlap. **177**: the three sets publish three denominators for one body —
set 1 prices the recovery wrap against 4,092 where sets 2 and 3 use 4,112, so every recovery-wrap
slack figure set 1 publishes is 20 octets low, and set 3 contradicts its own P1 by dropping
`padBody`'s prefix from one cross-reference; underneath the arithmetic is the real question, whether
the corpus ends with one wrap-body grammar or two. **178**: three authorities name the payload kind
and three name the content epoch, and the field-list set counts two — the third, `wrap_key`'s `info`,
is what makes the other two safe and turns item **142**'s unbounded downward epoch walk into one
candidate. **179**: `u32(publisher_leaf_index)` and `LP(identity_pub)` are not substitutes, and the
set recommending the first claims the second's property for it — `sender_handle` is already in
`record_bytes`, so W5 buys 474 µs and not decidability, and a seed-only restorer can use neither a
handle nor a leaf index. **180**: `u8(size_bucket)` is inside the proposed signature, so the padding
rule is an input to the signature and `M1-7` is **not** separable from `M1-1` — set 3 said so, set 2
said the opposite, and the composition settles it.

**A recommendation is given and labelled as one:** **C3**, or **C2** for the smallest change from
what the three sets already recommended. C3 drops W5, adds `LP(identity_pub)` inside `aead_ct`, puts
`LP(wrap_envelope)` in the preimage, and extends P2's prefix to the recovery wrap so all three wrap
bodies have one parse — measured at **1,293** of the 4,096 rung, tail **2,803**, and **zero octets on
the wire**. Its costs are stated: it amends §5.11 (2), and it is 32 octets of body more than C2.

**Costs are measured rather than estimated**, by calling the shipped encoder from a scratch module
outside both checkouts with an absolute `replace` onto `connect`, which reads it and writes nothing
in it: `SizeBucketBytes(2)` **4,096**, `ct_body` **4,112**, `WrapTag` **34**, `RecoveryTag` **64**,
records **4,364** with no attachment / **4,398** device / **4,428** recovery, `AAD_head` **182** for
both wrap kinds, `AAD_body` **96**, the S1 header block **145** and its preimage **1,305**, the rung-3
cliff **+12,288 octets per record = +24.6 MB** over 2,000 device wraps, and the epoch fan-out
**11.01 MB** against the ≈ 11.5 MB two documents publish.

**Three smaller corrections, with their queries.** `ErrBodyPadding` already exists
(`connect/messagegroup/errors.go:248`, identical at HEAD and in the working tree) and `unpadBody`
already returns it twice, so P2 needs no new sentinel — one declaration fewer than set 3 prices. The
*"about 4.6 KB on the wire"* rows are in Spec B **§3** (`spec-b:1092-1094`) and the ≈ 11.5 MB sizing
block in **§6** (`spec-b:2453`), not in a *"§9 retention table"*. And the `env_key`-versus-
`ClassKeys.Durable` contradiction reproduces exactly: `env_key` occurs **18×** in Spec A, **10×** in
MASTER and **16×** in this ledger, and `grep -Ei 'K_durable|ClassKeys\.Durable'` over those hits
returns **0** — the device wrap's `ct_head` root is unstated and blocks Task 14 independently of every
shape on the board.

**The `connect` tree moved twice while this pass ran, and the tree every figure was measured against
is named rather than assumed.** It began at `33932e0` with Task 13 staged in another session — already
two states past what two of the three sets recorded — and ended at **`7868d65`**, *"m1 task 13 —
`pq_secret`'s sampler, and the provisional epoch state G10 destroys"*. **Task 13 landed during this
pass.** Every `connect` anchor cited was re-verified at `7868d65` and every one holds: that commit
does not touch `seal.go`, so all nine seal-path citations are unmoved, and it does touch `errors.go`
(+29/−8) where `ErrBodyPadding` is still at `:248` — checked, not assumed. The two refusals that block
Task 14, `seal.go:119` and `:387`, are unchanged by Task 13's landing. **Two consequences are recorded
and not edited.** §1's code row names `connect` at `33932e0` and `connect` is at `7868d65` as of this
commit; and `SPEC-LEDGER.md` was rewritten by a concurrent session while this pass was writing it —
the `s2` entry immediately above, landed as **`a3bb625`** — which discarded an earlier application of
this amendment wholesale. It was re-applied on top of `a3bb625` and committed at once, and **nothing
of the `s2` entry, of the `s2` plan, or of §1's row was changed by this pass**: racing another
session's edit is a worse failure than a stale row the next pass over §1 will catch. The index check
below is the reason that clobber was caught rather than shipped.

**Reviewed by:** the composition itself — three documents produced independently, held against each
other and against the shipped encoder, which is the review this pass exists to be. Every line
citation was verified by printing the cited line, which caught the two Spec B section labels above
before they shipped.

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **`ok` before and after**. Its coverage of this diff is stated
rather than implied: the diff adds **six** ledger items and the m1 plan cites **all six**, so check 3d
is not vacuous over it — `readLedgerItems`' map goes **180 → 186** distinct ids (query:
`grep -oE "^[0-9]+[a-z]?\." SPEC-LEDGER.md | sort -u | wc -l`, over 215 → 221 matched lines, measured
against `a3bb625`). **Proved rather than asserted, twice:** renumbering item **175** to an id nothing
carries turns check 3d fatal with **1 finding**, and renumbering **176** through **180** turns it
fatal with **5**; the file was restored byte-identical by SHA-256 after each. `git ls-files` equals
`git ls-tree -r HEAD --name-only` at **103** — 102 at the start of this pass, plus the `s2` plan
`a3bb625` added — checked before the commit rather than after it.

**What this pass did NOT do.** It did not rule `M1-1`, `M1-7`, or items **132**, **142**, **148** or
**152**. It filed options and disagreements; items 175–180 are filed rather than ruled. It did not
implement wave 2, it changed **no Go file in either tree**, and it amended no spec — which matters
here, because four of the five composites require Spec A §5.11 (2) to be **amended and not annotated**,
and choosing that is the owner's.


---

### 2026-09-09 — the `s2` plan repaired: the gate that convicted its own required edges, the hazard the leg was commissioned to prevent, and the seam nothing owned

**Change:** Repaired `docs/plans/2026-09-09-slice2-s2-client-submit-leg.md` against its
ACCEPT_WITH_FIXES review (17 findings) **and against the defect class those findings are instances
of**, which is the half the brief asked for and the half a finding list does not give. +1,065 / −201
lines; 2,032 → 2,896. Two tasks added — **2a**, the single writer, and **8a**, the seam — four open
items added (**S2-16** through **S2-19**), and one rule added (**R5**). No Go file in any tree
changed, and no spec was amended.

**Why:** The brief that commissioned `s2` named one failure mode specifically — the `s1` plan shipped
four properties no correct implementation could satisfy — and `s2` shipped nine more of that class
plus four whose mutation could not be applied at all. The largest was structural rather than local:
`s2`'s own layering gate was **red before a single mutation**, and it convicted the edges every task
from Task 1 onward requires.

**The four that mattered, each reproduced on this machine before it was repaired.**

- **The layering gate.** Task 13 Property 1 scoped itself to the *transitive* non-test dependency
  set, and its Definition-of-done row was `go list -deps ./... | grep connect/mls` → no matches.
  Measured at `connect` `7868d65`: `connect/messagegroup` imports `connect/mls` or `connect/mls/syntax`
  on **eight import lines across seven production files** — the review said *eight files*, and the
  correction is this pass's, from `grep -rn 'urnetwork/connect/mls' messagegroup/*.go | grep -v _test`,
  where `engine.go` supplies two of the eight. `go list -deps ./message` alone prints
  `connect/mls/syntax`, and the grep string `connect/mls` matches `connect/mls/syntax` **as a
  substring**. Re-derived from Gate 5 rather than exempted: the decidable property is the **direct
  import set of `package sdk`'s own files**, and what the transitive scope was reaching for — a new
  module arriving through a transitive path — is now Property 4 over `go.mod`'s require blocks, where
  it is decidable. **What is no longer defended is written into the task**, not dropped silently.
  The Definition of done now carries the inverse row too: `go list -deps . | grep -c 'connect/mls'`
  must be **2**, not 0, because a 0 there means the reserver is not linked.
- **The single writer.** Over 2,032 lines the plan had **no** property, refusal or mutation about a
  second writer: `grep -iE 'lock|mutex|concurren|single.writer|exclusive|two processes|second
  process|flock|O_EXCL'` returned zero hits on any of those terms. Two `StreamStore` instances over
  one directory each read the same high water and each allocate the same index, which §5.6 calls
  *"a total break of both AEADs for that record"* — the exact hazard leg 5 exists to prevent. New
  **Task 2a**: an exclusion held by the operating system (`syscall.CreateFile` with `dwShareMode = 0`
  on Windows, `syscall.Flock` on Unix, a **refusal** on a `GOOS` with neither), four properties and
  nine mutations, including the crash-mid-allocation answer in both directions. A pid-and-timestamp
  lock file is named and rejected: it has no liveness oracle.
- **The seam.** `messageSender` and `messageReceiver` were method receivers in three `Produces`
  blocks and were **declared by no task**; `NewGroupSession` was called by nothing the plan produced;
  `messageTransportCounts` was named in a return signature and declared nowhere. So leg 4's defining
  sentence was produced by nothing and two derived-class gates (Task 4 Property 2, Task 9
  Property 2) each claimed *one member* over a construction the plan never made — a class of zero,
  which the plan's own Definition of done calls a broken gate. New **Task 8a** declares the seam, is
  the one `NewGroupSession` call site and the one `SealRecord` call site, and carries §5.9 **G11**'s
  lost-commit extension, which the plan had cited and never stepped.
- **The second durable store's key.** Task 12 keyed `ReceiveState` by
  `(groupId, leaf, message.RetentionClass)`; the ratchet it feeds is keyed by
  `ReceiverRatchetKey{SenderHandle, RetentionWire}`, and `RetentionEph` is one class value spanning
  six buckets, so all six EPH buckets of one sender collided onto one persisted head index — item
  **170**'s defect class, on the side where the failure is silent message loss rather than a server
  refusal, because `NewReceiverRatchet` walks to `headIndex` and everything below it leaves the
  window. Re-keyed to the wire byte, given Task 1's version-tag mechanism (which it had none of), and
  the row identity is now derived by reflection off `ReceiverRatchetKey` itself.

**And the one that is not the plan's fault but was the plan's problem: Task 2 Property 1 was
unsatisfiable on Windows.** Reproduced here with the project toolchain: after `os.Create` / `Write` /
`Sync` / `Rename`, `os.Open(dir)` succeeds and `d.Sync()` returns `Access is denied.`; so does
`os.OpenFile(dir, os.O_RDONLY, 0)`. A correct implementation there performs exactly **one** forced
flush, so a class stated as *two members* fails for the correct implementation. The repair constrains
the **design** rather than the platform — the allocation path now mutates no directory entry at all,
so the one durability boundary is a file-contents flush, forceable everywhere — and **prices what
that costs**: no atomic replacement on the allocation path, so the row format carries a checksum and
a discard rule; Task 1 Property 4 must now separate a torn tail from a corrupt body; and the *first*
allocation against a never-before-seen stream still rests on a directory entry Windows will not
force. That residual is **S2-16** and it is filed rather than closed. NTFS journalling is named as a
practical argument and explicitly **not** claimed as a guarantee.

**The class was derived rather than taken from the list, and it is now R5 in the plan** — a
twelve-row table naming every property that is unsatisfiable, unfalsifiable, undecidable or whose
mutation does not compile, with which half failed and why. Six of the twelve are this pass's own
finding rather than the review's: Task 13 Property 3 (five declared edges against a transitive set of
**414 packages across 30 module prefixes**, measured); Task 3 Property 1 (a class pinned to one
member that a correct *inlined* adapter makes two); Task 11 Property 3 (*"an epoch this client cannot
key"* is undecidable against a bare `readKey []byte`, so the signature now carries a `readKeyRef`
with its epoch); Task 10 Property 4 (the seal-time nonce epoch it compares against was recorded
nowhere, so a correct-looking path compares a number with itself — Task 8a Property 3 now records
it); Task 9 Property 2 (the second instance of the zero-class defect the review found once); and
`messageTransportCounts`.

**Three of the review's own claims are corrected here, with the measurement.** The `messagegroup`
→ `mls` edge is **seven production files / eight import lines**, not eight files. Tasks 1–4 stated
**16 properties and 29 mutations** (4/8, 5/9, 4/7, 3/5), not eighteen and twenty-two. And the review's
parenthetical that *"the store owing a rewind sentinel at all is a plan invention that the ratchet
does not read"* is half wrong: `streamindex.go`'s contract clause 2 says in terms that *"A persisted
state behind an index already handed out is `ErrStreamIndexRewound`"*, and `ratchet.go:318` raises it
itself while reading only `ErrStreamIndexConsumed` off the reserver. The real defect the finding named
survives and is repaired: Task 2 now owes the two **conditions** under `sdk`'s own names and Task 3
remains the only place either becomes a `messagegroup` sentinel, which is what Task 2's
`messagegroup`-free `Consumes` block and Task 3 Property 3's uniqueness claim both require.

**The plan's fifteen open items all stay open. Three carried measurements that had gone stale while
the review ran, and those are corrected without closing anything.** m1 Task 13 **landed** at
`7868d65` during this window: `messagegroup/epoch.go` is tracked, `NewPqSecret` and `ProvisionalEpoch`
exist, and the plan's *"untracked in the working tree"* framing is now *"landed, and still not an
answer"* — `NewProvisionalEpoch` takes `storageRoot` as a parameter, so **S2-1** survives it, and
there is still no `wrap*.go` and no production caller of `XwingEncapsulate` outside `xwing.go`, so
**S2-3** survives it too. **S2-7**'s *"`sdk`'s only production `connect.Client` is the VPN's"* is
wrong: there are **two**, `device_local_provider.go:109` and `sim_device.go:115`, the second in
`package sdk` with no build tag and standing up its own `ApiOutOfBandControl` from `config.ByJwt` —
so the standalone authenticated client S2-7 says is unprecedented has a precedent, and the item stays
open because it is still unspecified for messaging. **S2-9** grew a fourth value it had omitted: the
op-byte derivation, whose only implementation is `msgrepo/api/api.go:339`'s `opOf`, in a module `sdk`
may not import.

**The Definition of done's closing claim was overstated and is corrected.** It authorised *"one
client, one group, one real durable record, sealed and submitted and fetched and opened"* while
S2-1 blocks Tasks 9–11 against a real server and S2-7 leaves the client construction unresolved.
**Every row in that table is a unit invocation; no row runs against a message server and no task
builds the fixture that would.** The honest statement now says what the tasks actually produce.

**The `connect` tree moved once while this pass ran, and every anchor was re-verified at the tree it
ended on.** It began at `7868d65` — the commit every measurement above cites — and ended at
**`81b97ca`**, *"messagegroup: close task 13's eleven survivors, and the width one door over"*, landed
by a concurrent session in that checkout. Every load-bearing anchor was re-run at `81b97ca` and every
one holds: eight `mls` import lines across seven `messagegroup` production files; `go list -deps
./message` still prints one `connect/mls` path; `ReceiverRatchetKey` is still
`{SenderHandle [16]byte, RetentionWire byte}`; `GroupSession` still has seven exported methods (two
in `seal.go`, five in `session.go`); `maxLadderWalk` is still `1 << 20`; `NewProvisionalEpoch` still
takes `storageRoot` as a parameter, so **S2-1** is unmoved; there is still no `wrap*.go` and still
zero production callers of `XwingEncapsulate`/`XwingDecapsulate` outside `xwing.go`, so **S2-3** is
unmoved; and `JoinFromWelcome` is still the unconditional refusal at `engine.go:308`, so **S2-4** is
unmoved. **This pass changed no file in that checkout**, and the plan cites `7868d65` deliberately,
because that is the tree the numbers were taken on.

**Reviewed by:** the ACCEPT_WITH_FIXES review of the `s2` plan, 17 findings — all 17 reproduced on
this machine before repair, three of them corrected in the process, and the defect class they belong
to derived and swept rather than the list applied.

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **`ok` before and after**, and its coverage of this diff is
stated rather than implied. The reporting checks are unmoved at their pre-existing baselines — 1b
**7**, 1c **1**, 2a **18**, 3a **4**, 4b **5** — and **none of those findings is `s2`'s**, before or
after; check 2a's count is identical at 18 with zero `s2` rows on either side. The derived classes
grew where the diff grew them: the property class **233 → 245** (+12: Task 2a's four, Task 8a's five,
Task 12's two, Task 13's one), the class-deriving property class **48 → 56**, the `Consumes`-entry
class **246 → 248** (+2 tasks), the task-reference class **1845 → 2015**, the open-item-reference
class **550 → 580**. **Proved rather than asserted:** renaming the new `S2-18` definition to an id
nothing carries turns the fatal check 3b red with **4** findings; the file was restored
byte-identical by SHA-256 afterwards and the linter re-run green. `git ls-files` equals
`git ls-tree -r HEAD --name-only` at **103**, checked before the commit rather than after it.

**What this pass did NOT do.** It closed **no** open item — not S2-1 through S2-15, not M1-5, not
ledger items 170 or 171 — and it added four rather than resolving any: an ambiguity the specs leave
open is filed, not decided. It changed **no Go file in any tree**, and specifically nothing in
`C:/Users/ryanm/Downloads/claude_sandbox_message/connect`, where another session was working
concurrently. It amended **no spec**: S2-17 and S2-18 both owe §8.2 amendments and this pass wrote
neither, because §8.2 is not this plan's to edit. It supplied **no test code** — every repair states
a property, the refusal it owes and the mutations that must kill it, per R1. And it did not execute
any `s2` task: `sdk`'s three preconditions (S2-13) were re-measured 2026-09-09 and **all three are
still unmet** — `../goidenticons` absent, no `beta/message` branch, no `.github` directory.
---

### 2026-09-09 — the two properties the last repair wrote mutually unsatisfiable, and the five more the sweep for their class found

**Change:** Repaired `docs/plans/2026-09-09-slice2-s2-client-submit-leg.md` against the four
`msgrepo`-side findings of its ACCEPT_WITH_FIXES verification **and against the class those findings
belong to, derived and swept rather than applied as a list**. +396 / −89 lines; 2,896 → 3,203.
**Seven**
mutually-unsatisfiable or self-contradicting property pairs resolved, of which **five were found by
the sweep and named by no review**. Three open items added — **S2-20**, **S2-21**, **S2-22**. Seven
mutations added (Task 1 ×3, Task 2a ×2, Task 12 ×1, Task 13 ×2, less renumbering), one mutation set
re-ordered (Task 11's ran 7, 10, 8, 9). No Go file in any tree changed, no spec amended, and no test
code supplied — every repair states a property, the refusal it owes and the mutations that must kill
it, per R1.

**Why:** The pass before this one was commissioned to remove properties no correct implementation can
satisfy, and it introduced two more while doing it — **in the same pass, by the same author, four
hundred lines apart**. Task 2a put an OS-held exclusion on *"a guard file inside `dir`"*; Task 1
Property 2 required `StreamHighWater` to **enumerate** `dir` and stated categorically that *"a file
in `dir` that is not a row of either tag is `ErrStreamStoreState`"*. So the store read its own lock
as data, every `StreamHighWater` after `OpenStreamStore` refused, and — because *"Task 2a lands with
Task 2, not after it"* — Wave 1 was red on the commit that completed it. That is this ledger's oldest
lesson restated one altitude above the code: **a repair is as capable of shipping the class as a
first draft is, and a fix applied to a reported pair is not a sweep.**

**THE RESOLUTION IS A CONSTRUCTION, NOT AN EXCEPTION, AND THE ALTERNATIVES ARE NAMED.** The
enumerated object and the excluded object are now **different directories, one nested in the other**:
`OpenStreamStore` creates a **row directory** inside `dir` which holds rows and nothing else and is
the only thing the enumeration ever reads, and the guard entry sits beside it in `dir` and never
inside it. Nothing is exempted, no reader has to know the guard's name, and Task 1 Property 2's
categorical rule gets **stronger** rather than weaker — nothing legitimate is ever written into the
row directory, so anything found there is a real finding. *Rejected:* exempting the guard **by name**
from the enumeration, which is an ignore-list and the ledger-21 defect in one line — it goes on
silently ignoring the second non-row somebody writes there tomorrow. *Rejected:* a guard **outside
`dir`**, which puts this store's lock in a directory the store does not own (`sdk`'s shared
`LocalState` home), where two stores' guards collide by name and the exclusion no longer sits on the
tree it protects. Task 12's `ReceiveState` consumes both halves of the collision — *"Task 1's row
identity and its three refusals"* and *"Task 2a's exclusion"* — so it gets the same two levels, and
`ErrReceiveStateState` is safe for the same reason.

**THE SIBLING FINDING, AND WHICH SIDE WAS WRONG.** Task 1 mutation 7 (*"truncate a row file to half
its length; Property 4 must fail with `ErrStreamStoreState`"*) and Task 2 mutation 10 (*"truncate the
row's last record to half a record's width; a torn tail is discarded"*) demanded **opposite answers
to one fault**, and Task 1 lands first, so an implementer dispatched on Task 1 alone writes the store
Task 2's own mutation then fails. **Task 1 is the wrong one.** The reason is not seniority, it is
direction: the discard rule is what makes a crash mid-append survivable, and it is safe for a stated
reason — *a torn tail can only be an append whose flush had not returned, and a `Reserve` whose flush
had not returned had not returned an index, so discarding it discards nothing that was handed out*.
Refusing a torn tail instead makes every crash mid-append a store **no later process can open**,
which is a permanent wedge on the exact path Task 2 Property 1 and Task 2a Property 4 exist to make
survivable. So Task 1 Property 4 now states **three** cases with a discriminator that is position and
size rather than content — absent row, torn tail, corrupt body — and the bound on case 2 is
**derived, not chosen**: the allocation path appends one record and flushes, so at most one record
can be un-flushed. Task 1 mutations 7, 8, 9 and 10 exercise both sides, mutation **9** being the
control that a torn tail must **not** be refused. Task 2's stated-and-undischarged obligation is
marked discharged, in place, with a pointer to where it landed.

**AND THE SWEEP FOUND FIVE MORE THAT NO REVIEW NAMED.** The derivation is mechanical and is written
into the plan so the next pass runs it rather than re-inventing it: index every **constraint site**
in every task — not every Property, which is the derivation that misses this pass's own headline
finding, because Task 2a states its guard placement in task **prose** — by the objects it names, then
read every object two or more tasks constrain. 173 constraint sites, 17 tasks, 142 mutations.

1. **Task 2 Property 1's second reported number.** *"The allocation path performs no directory-entry
   mutation at all"* is unsatisfiable for the **first** allocation against a never-before-seen
   stream, which must create that key's row — and S2-16 had already rejected pre-creating rows for
   want of a key set at open time. The property now reports both readings: first allocation for a
   key, one create and one flush; every allocation after, zero creates and one flush. Mutation 2 is
   bounded to the steady-state path.
2. **Task 2 mutation 10's second clause.** *"Property 4 must fail if it answers `(0, nil)` for a key
   whose row is present"* convicts the correct answer on a row of one record, where the same cut
   leaves nothing verifying. Bounded to a row carrying at least two records, with the reason stated.
3. **Task 8a Property 4.** A class of *"two members … in whatever stands the client up"* over
   `OpenStreamStore` / `OpenReceiveState` **call expressions in production files** — in a plan where
   both stores arrive **injected** and nothing stands the client up. The class is **zero**.
   Re-derived onto the config's own durable-store field set (two, read off the struct), with the
   call-expression walk reported separately as scope: files walked, call expressions found. A walk of
   zero files is the broken gate; a count of zero call expressions is the correct reading.
4. **Task 10 Property 5.** A class of *"one member — Task 11's `Fetch`"* at a task whose landing
   order is `9, 10, 11`. **Zero at its own commit.** Now stated as empty, with the count half
   relocated to **Task 11 Property 1** and reciprocated there — which is the plan's own precedent
   (Task 4 Property 2 → Task 8a Property 1) and which the linter's fatal check 2b now verifies.
5. **Task 13 Property 4.** *"Beyond the two this plan promotes from indirect to direct"* against its
   own measurement of 8 direct → 9 direct, the *Dependency policy*'s *"one require-block line"* and
   the Definition of done's *"one line"*. Re-measured in `sdk` at `432986f`: **36** require lines,
   **8** direct, **28** indirect, `google.golang.org/protobuf v1.36.11 // indirect` at `go.mod:42`.
   The number is **one**; mutation 8 now promotes a **second**, not a third.

All seven are added to the plan's own **R5** register beside the thirteen already there, because that
list is what a later pass checks a new property against — and the register now carries the derivation
as well as the instances.

**The two remaining verification findings, both reproduced here before repair rather than taken.**
**Task 13 Property 1** offered *"read off the syntax tree or off `go list -f` on the package itself"*
as interchangeable readings and they are not. Reproduced in a scratch module with the project
toolchain: a package with `a.go` (imports `fmt`) and `b_unix.go` (`//go:build unix`, imports
`crypto/sha256`) prints `fmt` alone under `go list -f '{{range .Imports}}'` on `windows/amd64`, and
`{{.GoFiles}} {{.IgnoredGoFiles}}` prints `[a.go] [b_unix.go]`; `GOOS=linux` prints both imports.
Measured on the subject with `go/build`'s own `MatchFile` — the evaluator `go list` uses — over `sdk`
at `432986f`: of **57** root production files a `windows/amd64` context reads **51** and skips
**six** — `device_local_ioloop.go`, `device_rpc_platform_js.go`, `glog_android.go`, `glog_ios.go`,
`glog_macos.go`, `stderr_mobile.go`. **The verification put that at 5 and 52; it missed
`device_rpc_platform_js.go` (`//go:build js`), and the query is published beside the corrected
number.** Task 2a's own Files block adds two more a Windows runner never reads. The scope is now the
unfiltered file set, the gate reports **files read and files on disk and they must be equal**, the
Definition of done's `go list -f` row is demoted to corroboration behind a `GOOS` sweep with the
normative row being the gate itself, and mutation 9 plants a forbidden import in a file the runner's
context excludes — a mutant the old reading passes on Windows and kills on Linux.

**Task 2a's fail-closed third file** had `js/wasm` in its constituency unnamed and unpriced, and the
probe found something sharper. Compile-probed 2026-09-09, `CGO_ENABLED=0`, building the three-file
split exactly as the Files block names it: OK on windows, linux, darwin, ios, android, freebsd,
openbsd, netbsd, dragonfly, illumos, js/wasm, wasip1/wasm and plan9 — and **FAIL on `solaris/amd64`
and `aix/ppc64` with `undefined: syscall.Flock`**, because both satisfy `go/build`'s `unix` term and
neither declares the primitive. So a platform the fail-closed file was written to **refuse** on is a
**build break** instead, and the property's gate never runs there to say so. The Unix file is now
constrained by **the `GOOS` set on which `syscall.Flock` is declared** — derived from the primitive
per R4, not from the `unix` term, which is an instance of it — a cross-compile row is added to the
Definition of done, and mutation 11 is the `unix`-term regression. The fallback's real constituency
is js/wasm, wasip1/wasm, plan9, solaris and aix, and **`js/wasm` is a target the root `sdk` module
already builds for**: `device_rpc_platform_js.go` carries `//go:build js` and
`device_rpc_platform_native.go` carries `//go:build !js`. The priced consequence — the wasm artifact
gets a store that refuses to open, so it gets no messaging — is stated rather than discovered, and
whether messaging is in scope there at all is **S2-20**.

**Three ambiguities filed rather than decided, per the brief.** **S2-20**, whether the `js` target
needs messaging and what a browser tab's single-writer story would be, since it has neither `Flock`
nor `CreateFile`. **S2-21**, whether `StreamStore` and `ReceiveState` may be handed the **same**
`dir` and whose exclusion covers which — Task 12 consumes *"Task 2a's exclusion"* without saying,
Task 8a's config carries two separate injected stores and says nothing about their directories, and
§8.2 declares the receive-side store not at all. **S2-22**, that the torn-tail bound rests on a write
discipline **no document states as a contract** — one record appended and flushed per allocation — so
a later batched allocation would invalidate Task 1 Property 4's discriminator without touching a line
of it, and the failure mode is a two-record loss read as a torn tail and silently discarded.

**What was NOT resolved, and it is two of the verification's six.** Findings 1 and 5 are both in
`connect/messagegroup/epoch_test.go` — `epochSliceAnsweringAccessors` deriving its class off the
instance one layer in, and `epochIsTheDestroyedFlag`'s observational exemption admitting a bool
accessor that leaks a bit **of** the secret. **This pass changed no file in
`C:/Users/ryanm/Downloads/claude_sandbox_message/connect`**, where another session was working
concurrently, and both findings stay open for whoever holds that tree.

**Verification.** `go build ./...` clean and `go test ./...` green **before and after**.
`go test ./ -run TestThePlanLinter` **`ok` before and after**, with every reporting count identical
across the diff — 1b **7**, 1c **1**, 1d **189**, 2a **18**, 3a **4**, 3c **3**, 4b **5** — and the
fatal checks 2b, 3b, 3d and 4a clean on both sides. The derived classes grew where the diff grew
them: the task-reference class **2015 → 2100**, the open-item-reference class **580 → 593**, the
plan-reference class **2139 → 2140**; the property class is **245** on both sides and the
class-deriving property class **56** on both sides, because this pass added no Property block and
rewrote the scope of four. **Proved rather than asserted, twice.** Removing **both** mentions of
"Task 10 Property 5" from Task 11 Property 1 turns the fatal check **2b** red with 1 finding — that
reciprocal is what this pass's relocation owes, and the first attempt at this control failed to turn
it red because it removed only one of the two, so the control was corrected rather than the finding
reported. Renaming the new **S2-22** definition to an id nothing carries turns the fatal check **3b**
red with 1 finding. The file was restored **byte-identical by SHA-256**
(`0fd5a597a0b22e2415189eb519f06f7d915c3b9278ef9365cd7db9d9b7e324d2`) after each control and the
linter re-run green. `git ls-files` equals `git ls-tree -r HEAD --name-only` at **103**, checked
before the commit rather than after it.

**A process failure worth recording, because it nearly cost the pass.** Reverting the first control
with `git checkout -- <path>` discarded **every uncommitted edit in the working tree**, not the
control mutation. The work was recovered byte-exact from the dangling stash commit `59b2764` left by
the before/after linter comparison, verified by SHA-256 against the hash recorded before the control
ran, and every control after that used a plain file copy. **On this repository `git checkout --` is
not an undo for a scratch mutation while uncommitted work is in the tree** — take a byte-exact copy
first, the way the mutation-testing discipline on the `connect` side already does.

**What this pass did NOT do.** It closed **no** open item — not S2-1 through S2-19, not M1-5, not
ledger items 170 or 171 — and it added three rather than resolving any. It changed **no Go file in
any tree**. It amended **no spec**: S2-17, S2-18, S2-21 and S2-22 all owe §8.2 amendments and this
pass wrote none, because §8.2 is not this plan's to edit. It supplied **no test code**. And it
executed no `s2` task: `sdk`'s three preconditions (**S2-13**) are still unmet — `../goidenticons`
absent, no `beta/message` branch, no `.github` directory.


---

### 2026-09-09 — `M1-1` and `M1-7` RULED as composite `C3`: the envelope nothing signed, the grammar that needed the attachment's kind to parse, and the wire-decidability the owner declined to buy

**Change.** The owner's ruling on the remainder of m1 open item **`M1-1`** — the wrap body's field
list, where the signature sits and which octets it covers — and on **`M1-7`**, the padding scheme,
**taken together in one sitting** as item 175 §4's fourth composite, **`C3`**. Five documents move.
Item **175** gains the ruling at its head and is otherwise kept whole; items **176**, **177** and
**179** **close**; items **178** and **180** are annotated with what the ruling does and does not do
to each; §1's implementation-plan row and the two spec rows move with them. m1's `M1-1` and `M1-7`
become RULED with the reasoning, the measurements and the residuals, and Tasks 14, 15 and 16, the
execution order, the pending-pins table, the wave-2 row and the A6 wire-visible list follow.
**MASTER §7 and §8.2** gain the normative grammar under a new dated amendment. **Spec A §5.11** gains
**(6)**, amends **(2)**, and carries the measurements, the declined trade and six residuals (revision
**A-22**). And the two documents that cite Task 14's blocker list from outside m1 — `s2`'s
interface-inventory row and its **S2-3**, and `PROGRESS.md`'s component row — are corrected to name
**item 152 alone**, which is the class this ruling makes false rather than a list taken from the
ruling.

**The rule.** `W1`'s four-field envelope — `u8(wrap_format_version = 0x01) ‖ u8(target_type) ‖
u8(payload_type) ‖ u64(content_epoch)`, **11 octets**, version first — outside `hybrid_ct` in every
wrap body, with `W5`'s `u32(publisher_leaf_index)` **dropped**. `aead_ct`'s plaintext as
`secret ‖ LP(identity_pub) ‖ sig`. `S1`'s signature preimage extended by **`LP(wrap_envelope)`**,
ahead of `LP(ct_xwing)`. And `P2` — `LP32(len) ‖ body ‖ zeros` with an **accumulating, position-free**
typed refusal of a non-zero tail — over **all three** wrap bodies, the recovery wrap included.

**Measured, and the derivation is published beside the numbers so a reader re-derives rather than
trusts.** `aead_ct` `32 + (4+32) + 64 + 16 = 148` → `hybrid_ct` `2 + (4+1120) + (4+148) = 1,278` →
body `11 + 1,278 = 1,289` → occupancy **1,293** of the 4,096 rung, tail **2,803**. Recovery:
`aead_ct` `32 + 64 + (4+32) + 64 + 16 = 212` → `hybrid_ct` **1,342** → body **1,353** → `ct_body`
occupancy **1,357** of 4,112, tail **2,755**. `ct_body` stays **4,112**, records **4,398** and
**4,428**, fan-out **11.01 MB**, Spec B's `octet_length(ct_body)` check unmoved. **Zero octets on the
wire.**

**Why the repair term is the point of the ruling, which is what this entry exists to record.** Three
analysts worked independently — the field list, the signature, the padding — and each recommended a
piece. Composed as they arrived, **the result signs the record header, the KEM transcript and the
secret, and leaves all fifteen envelope octets — the very fields the field-list ruling exists to add —
signed by nobody**, because the envelope is outside `hybrid_ct`, the signature is inside `aead_ct`,
and `LP(ct_xwing)` lies between them. **It survived three independent analyses because a sealer and an
opener agree about a field neither is asked to defend, so no round-trip test can see it**: every
property m1 Task 14 states is a seal-submit-fetch-open-compare round trip, and the defect is visible
only to a party that *changes* the field, which is the party no round trip has. `LP(wrap_envelope)`
closes it for zero body octets and zero wire octets. **The second repair** — the `LP32` prefix
extended over the recovery wrap — collapses two body grammars into one, so a parser can decide whether
the body's first four octets are a length or `version ‖ target_type ‖ payload_type` **without first
reading the server attachment's kind**, which was a target-type-dependent body encoding and therefore
the kind-`0x0000` defect class one level up.

**What the owner ruled against, and it was a real choice rather than a default.** `C4` — the signature
in the server attachment — is the only shape under which any receiver, **the message server
included**, can refuse an unsigned wrap on the wire bytes alone. Its price: **+68 / +104 octets per
record**, ~**+170 KB per epoch fan-out**, a **Spec B §5.1 check-3** change, and **publicly verifiable
per-epoch attribution of the committer across all 2,501 wrap records**, under a key MASTER §5.2
publishes in the KT log — MASTER §4.2's own boundary. Item 175 §4 is explicit that **C4's property and
C3's privacy cannot both be had. The owner took the privacy**, and the consequence is now stated where
a reader meets it: Spec A §5.11 (4)'s *"a client MUST NOT honour an unverified wrap"* is enforceable by
the decapsulating target and by nobody else.

**ONE FIGURE IN THE RULING AS TRANSMITTED DID NOT REPRODUCE AND WAS NOT WRITTEN DOWN.** The ruling
carried the preimage as *"1,305 → **1,324**"*. Item 175 §2 (1) and item **176** both measure the
repair as *"**1,324** with set 1's five fields, or **1,320** with W1's four"*, and `C3` takes `W1`'s
four — so the envelope is 11 octets, `LP(wrap_envelope)` is 15, and the preimage is **1,320**; 1,324
is the number for the composite the owner did **not** take. **1,320 is what the documents carry**, and
it is carried with the term that is genuinely undetermined stated beside it: `LP(payload)` was
measured over a 32-octet secret, while set 2's own `S1` line prices `LP(identity_pub)` as *"a further
36 in the payload"*, so the preimage is **1,320** if the identity key is outside that term and
**1,356** if it is inside, and **no document says which**. Neither was measured here and neither is
asserted as *the* number. **A builder needs the answer before it signs anything**, so it is filed as
Spec A §5.11 (6)'s sixth residual rather than guessed at.

**What this pass unblocked, and what it did not — said in the same breath, because the second half is
the useful one.** `M1-1` and `M1-7` come off m1 **Task 14**, and through Task 14 off **Tasks 15 and
16**, which both modify the `wrap.go` Task 14 creates. **Ledger item 152 is untouched and is now the
whole of Task 14's blocker list**: `connect/messagegroup/seal.go:119` refuses every non-`DURABLE`
class on the seal path and `:387` mirrors it on the open path, so the `EPH(5)` `eph_root` record is
unsealable by the shipped code — item 175 §6's *"honest limit"* holds verbatim, and the two blockers
were always independent. **And CP3b is still blocked outright by `S2-4`**, which this ruling does not
touch: `JoinFromWelcome` is an unconditional refusal, so there is **no exported path by which two
clients share one group**. That is `connect/mls`'s, upstream of everything `m1` and `s2` can do.

**What the ruling did not say, derived from item 175 §6's own list of six rather than taken from the
ruling's summary of itself.** It states (1), (3) and half of (6). **Not stated:** (2) the envelope is
a **hint** the open verifies — and `LP(wrap_envelope)` does **not** make this moot, because the
signature lives inside `aead_ct` and is unreachable until after the open, so a receiver still derives
`wrap_key` from the envelope's own values before it has anything to verify (item **178**, still
owed); (4) the order **open → verify → honour** in those words, which m1 Task 14 Property 7's
*"before it honours anything in the record"* contradicts as written; (5) how a **member** resolves the
identity key it verifies under, and how a restorer's carried `identity_pub` is anchored in the KT log;
and (6)'s other half, a typed refusal for an absent or short signature. `M1-7`'s ruling leaves set 3's
clauses (b), (d) and (e) — the fill octet in a document, the true **65,532** inline ceiling three
documents publish as *"64 KiB"*, and the written argument at `seal.go:538` it overturns — and says
nothing about the **ordinary record body**, whose unpadder is the same function, so a wrap-only tail
refusal would be a class-dependent unpadder and therefore the grammar split the ruling's own second
repair removes. All of it is filed in Spec A §5.11 (6) and in m1's `M1-1` and `M1-7` rather than
resolved.

**Two gaps the ruling puts more weight on without closing:** `u8(target_type)` and `u8(payload_type)`
now travel on the wire and **still have no code point anywhere**, so MASTER §7's `wrap_key` stays
underivable by a second implementation; and `aead_ct` still has **no stated AAD**, which this ruling
fills with a signature and a public key.

**One document defect found and repaired in passing, recorded because it is the kind that survives by
being invisible.** m1's `M1-1` carried the 2026-09-09 options amendment **twice**, in two
near-identical paragraphs written by the same pass, and both copies ended with the sentence the ruling
falsifies. They are collapsed into one, with the duplication named in place.

**What this pass did NOT do.** It ruled nothing of its own — every ruling recorded here is the
owner's. It closed **no** item other than 176, 177 and 179, which the ruling closes: **152**, **178**,
**180**'s residual, **132**, **133**, **134**, **142** and **148** stay filed and unruled. It changed
**no Go file in any tree**, supplied **no test code**, and **did not touch `connect`**. It implemented
no part of m1 wave 2: Task 14 is still not started, and the reason is item 152 rather than anything
this ruling settles.

**Verification.** `go build ./...` clean; `go test ./...` green; `go test ./ -run TestThePlanLinter`
ok. Every linter reporting count identical across the diff (1b 7, 1c 1, 1d 189, 2a 18, 3a 4, 3c 3,
4b 5) and the four fatal checks (2b, 3b, 3d, 4a) clean on both sides. `git ls-files` equals
`git ls-tree -r HEAD` at **103**, checked before the commit and again after.
