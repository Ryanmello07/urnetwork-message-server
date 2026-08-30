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
27. **DECIDED by the owner 2026-08-30: an intermediate internal-only build, before p7/p8 finish.**
    The record layer and transport already carry a record end to end over two real
    `connect.Client`s (CP3a, reached twice). Once the pgx store lands, that is enough to carry real
    messages between two people -- encrypted in transit by connect's existing hybrid PQ, but
    **without the MLS group ratchet underneath**. The owner wants that build, internal only, to
    surface product problems no test finds. **The constraint that comes with it: the build itself
    must make its own status unmissable** -- not a README, not release notes. A user of it must not
    be able to mistake it for the secure product, and "we told them in the docs" is not a design.
    The app's shape is NOT to be set by this layer; MLS slots underneath as p7/p8 land.
28. **DECIDED by the owner 2026-08-30: the pgx store runs in parallel with p7, and comes before the
    sdk plan.** The rationale accepted: the store has a designed schema (SS3.2), a 51-subtest
    contract suite any implementation must pass, and an api layer to test against -- so it needs no
    new plan -- and it is the piece that makes a message survive a restart, which the intermediate
    build in item 27 depends on. The sdk plan (~135 declarations, no plan yet) and the Windows
    client that is blocked on it come after.
13. **A spec-conformant client cannot connect to a server without §9.1's signing sidecar.** §4.3.1
    requires `HelloResponse.server_keys` and requires a client to REFUSE a fleet whose first key does
    not verify against the compiled-in root, while decision B13 keeps every signing key off every
    replica. That is not a defect in B13; it is a gap in what §4.3.1 says a partial deployment can do.
    Found 2026-08-26 by `peer/`.

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
