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
    implementer meets them.

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
     staged commit, moved from epoch 1 to epoch 3, and derived byte-identical epoch
     authenticators.** `Processed` and its `Commit` field are exported and `connect/message` is
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

128. **BLOCKS CP3b — `ct_head`'s retention class is unruled, and m1's own refusal for it stops a
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
person. Wave 1 complete is a `connect/message` that seals and opens records under the real key
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
`forbiddenScanRoots`, `hkdfExtractAllowedPaths` and `hkdfExtraCallSites` at lines 46, 83 and 425; the
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
