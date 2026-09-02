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
13. **A spec-conformant client cannot connect to a server without §9.1's signing sidecar.** §4.3.1
    requires `HelloResponse.server_keys` and requires a client to REFUSE a fleet whose first key does
    not verify against the compiled-in root, while decision B13 keeps every signing key off every
    replica. That is not a defect in B13; it is a gap in what §4.3.1 says a partial deployment can do.
    Found 2026-08-26 by `peer/`.

40. **The `sdk` surface has seventeen open questions and three of them are schema decisions that
    must be ruled before the plan after next starts.** The full list is the Open items section of
    `docs/plans/2026-08-30-slice2-s1-sdk-surface.md`, which is the durable copy; it is not restated
    here, because a second copy with nothing holding the two together is the ungated-agreement shape
    item 7 already records. The three that cannot wait: **the pin primary key collapses** — §8.1 keys
    `pin` by `(principal, operator_host)` while §7.3b leaves `Principal` empty for a card-added
    contact and §7.6 leaves `OperatorHost` empty for a card-provided key, so two card-added contacts
    share the key `("", "")` and the second silently overwrites the first, which is exactly the state
    in which no `KeyChangeWarning` fires; **`StoredEntry` is undefined** and §8.2's "fourteen methods,
    that bound is the point" omits every table §8.1 itself lists, five of which are read directly by
    §7 declarations; and **no JSON field naming is specified anywhere**, while every value struct
    crosses the ABI as JSON, Spec C parses it with nlohmann and §9.3's `settings_json` documents
    snake_case. The first two are schema decisions and ruling either after rows exist is a migration.
    The third must be ruled before the ABI baseline is committed, or every later correction becomes a
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
handles, the closed vocabularies, and the exportability gate. Added open item 40 above.

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
