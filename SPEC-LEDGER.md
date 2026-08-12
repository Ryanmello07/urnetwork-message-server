# URmessage — Top Spec Ledger

The single document that contains everything: current state, every locked decision and why, the
revision history, open items, and an append-only edit log.

**If you read one file, read this one.** The protocol spec in `docs/specs/` is the normative
document; this ledger is the map, the reasoning, and the audit trail.

---

## 1. Current state

**Protocol design at revision 5.** Group key agreement is MLS (RFC 9420), implemented in Go.
Storage, retention, deletion, recovery, and identity verification are ours. v1 targets one operator,
one message server, many providers.

**Nothing is implemented yet.** No code exists. The next artifact is an implementation plan in
`docs/plans/`.

| Item | State |
|---|---|
| Protocol design | Revision 5 — awaiting owner review |
| Implementation plan | Not written |
| Code | None |

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
| C2 | Implement MLS ourselves in Go; **OpenMLS is the reference oracle, never a dependency** | Both Go libraries fail the owner's bar of *actively maintained and widely trusted*. OpenMLS clears it but is Rust — pure Go builds everywhere gomobile already goes, with no per-platform Rust cross-build. |
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
