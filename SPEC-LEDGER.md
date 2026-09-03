# URmessage — Top Spec Ledger

The single document that contains everything: current state, every locked decision and why, the
revision history, open items, and an append-only edit log.

**If you read one file, read this one.** The protocol spec in `docs/specs/` is the normative
document; this ledger is the map, the reasoning, and the audit trail.

---

## 1. Current state

**Protocol design at revision 5**, with errata E1–E3 fixed. Group key agreement is MLS (RFC 9420),
implemented in Go. Storage, retention, deletion, recovery, and identity verification are ours. v1
targets one operator, one message server, many providers.

**Nothing is implemented yet.** No code exists.

| Item | State |
|---|---|
| MASTER protocol design | Revision 6 — 1,078 lines |
| Spec A — protocol / sdk / connect | Revision A-3 — 3,127 lines |
| Spec B — message-server / operator | Revision 3 — 2,411 lines |
| Spec C — Windows client UI | Revision 3 — 1,506 lines |
| Blockers | **0** — down from 41 |
| Remaining | 30: 8 major, 22 minor. Ordinary pre-implementation cleanup. |
| Implementation plan | Not written |
| Code | None |

**Ready for owner review, and for handoff once the owner has read them.** Four review rounds and two
edit passes have taken this from 41 blockers to none. The remaining 8 majors and 22 minors are the
kind a team absorbs alongside the build rather than before it.

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
    names: §5.11 defines `expected_wrap_count` as *"device wraps + recovery wraps + 1 snapshot"* and
    the server checks only that the marker matches the attachment, so a client that defers recovery
    wraps and the snapshot passes the server while diverging from the spec — a deferral the system
    cannot detect, and therefore one m1 must gate rather than leave to an implementer. Found
    2026-09-02 by the CP3b-chain review.

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
