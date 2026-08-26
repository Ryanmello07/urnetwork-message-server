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
