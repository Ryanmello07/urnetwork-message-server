# Owner decisions 50–58

Rounds 1–2 are in `2026-08-12-owner-decisions-1-45.md` and `-46-49.md`.

**50–53 were the owner's**, taken 2026-08-12; they were written to a sandbox scratch file
and never committed, which is corrected here.

**54–58 were delegated to the controller** on 2026-08-13 — *"the rest you can handle and
decide on. The plan and ledgers we wrote should apply to most of it"* — and are recorded
with their reasoning so they can be overturned on sight rather than archaeology.

| # | Decision | Affects |
|---|---|---|
| 50 | **Delivery receipts stay always-on and are NOT covered by the reciprocity rule.** Reciprocity (decision 48) governs read receipts and typing indicators only. Delivery is a transport fact — a device decrypted the record — not a behavioural signal, whereas a read receipt reveals attention, which is the thing people actually want to withhold. **Accepted cost:** delivery still leaks per-device online patterns to the server, accepted when delivery receipts were reinstated in decision 7. | Spec A §7.2a, Spec C §5, §12 |
| 51 | **Adding a device is announced in-thread in every affected group; no admin approval.** Self-service stays — approval would block someone setting up a laptop on a Sunday — but each group records a permanent "added a new device" event. Silent device addition is exactly what a compromised account looks like, and an in-thread announcement is the cheapest available detection. **Accepted cost:** noise in groups where people add devices often. | MASTER §11, Spec A device management, Spec C |
| 52 | **Run-at-login ON by default; close button minimises to tray by default.** Both visible and reversible on first run. Push is a GA gate (decision 30), so for the entire beta the app running is the *only* way messages arrive. **Accepted cost:** an app that starts itself and does not quit on close is a pattern users resent, and it invites an unflattering comparison in a privacy product. Revisit once push ships. | Spec C §2, §9, settings |
| 53 | **Font licence: assume covered for beta, verify before GA.** Beta is a handful of internal users, which almost any licence tolerates. **Accepted risk:** if the answer at GA is no, the remedy is a licence extension or a substitute face — and a substitute face changes the visual identity of every screen after they are all built. **Needs a named owner and a date before public release.** | Spec C §2, §15 |
| 54 | **The three fuzz legs stay per-commit for now, with a stated revisit trigger.** They cost a fixed ~189 s wall-clock floor. Keeping them: p1 is the foundation every later plan compiles against, Spec A §13 makes them A1's done-when, and p1 Task 18 measured that mutation-fuzzing catches a defect class — decoder leniency toward bytes no encoder emits — that **no other test in the suite can reach**, because a round-trip property over self-encoded values can never present the malformed octet. **Revisit trigger, not a vague intention:** p8 adds nine more targets. At twelve targets this is 12 minutes of fixed floor per commit and must move to nightly. Decide at p8, not before. | `mls-syntax.yml`, Spec A §13 |
| 55 | **`WriteVector`'s two-pass buffering is accepted; revisit belongs to p5.** It buffers a whole vector to size the byte prefix, so peak memory is ~2× the encoding — p1 Task 12 flagged ~32 MiB transient for a ratchet tree at `MaxRatchetTreeLength`, which would matter on mobile. Accepted because **that figure is the ceiling, not the expected case**: `MaxRatchetTreeLength` is a 16 MiB cap, while a tree at the locked 500-member group size (decision 21) is roughly 1023 nodes — order 1 MB, so order 2 MB peak. *That estimate is arithmetic, not a measurement, and p5 owns confirming it.* The alternative — a size-computing pass so the prefix can be written before the body — requires every encoder to be size-computable, roughly doubling the codec surface, and is not worth paying speculatively. **Revisit if Community Servers raise the group cap**, which is exactly the case that moves the real figure toward the ceiling. | p5 TreeKEM, `vector.go` |
| 56 | **`WriteOpaqueLP`'s 1 MiB cap stays; no change in p1.** The LP prefix is 32-bit while the cap is `MaxVectorLength`, so records larger than 1 MiB cannot be written through the default constructor. No change is needed because `NewWriterLimit`/`NewReaderLimit` already let `connect/message` choose its own bound at construction — the cap is a default, not a ceiling. **p2 records the record layer's chosen bound explicitly** rather than inheriting the default by accident. | p2 record layer |
| 57 | **`CODESTYLE.md` is not amended; the codebase is right and the rule is wrong for exported symbols.** `CODESTYLE.md` forbids repeating a symbol's name in its own comment, but every file in `mls/syntax` opens its doc comments with the name — because **godoc convention requires it**: a doc comment is expected to begin with the symbol being documented, and tooling relies on it. The rule reads as intended for *prose* comments, not doc comments. Not amending the file because it is upstream `urnetwork/connect`'s, this work is not proposed upstream in v1 (Spec A §2.1), and a fork editing the other project's style guide is a divergence with no upside. Recorded here so a reviewer sees the deviation is deliberate. | `CODESTYLE.md`, all p1–p8 Go files |
| 58 | **`provider-release.yml` is NOT restored; `test.yml` is.** The owner asked to restore connect's old CI on the beta branch. `test.yml` — build and test — is restored, with its branch list widened (see below). `provider-release.yml` is **not** restored and needs an explicit owner call, because it is not CI: it force-pushes a rolling tag (`git push -f origin beta-custom-server-latest`) and publishes a GitHub release with `contents: write`. It is also wired end-to-end to `beta/custom-server` — the `sn` and `connect` checkouts, the ref, the tag and the release name — so restoring it onto `beta/message` would be inert at best and wrong at worst. **Outward-facing and hard to reverse, so it is the owner's to authorise, not the controller's to infer.** | `.github/workflows/` |

## Application notes

- Decision 51 needs a control-plane event or an application message so the announcement is
  transcript-covered rather than a client-side guess — otherwise a hostile client simply omits it.
- Decision 52 interacts with decision 30: when push ships, revisit whether run-at-login should still
  default on. Record that dependency rather than leaving it implicit.
- Decision 53 is a risk register entry, not a spec change. It belongs in Spec C §15 and in the
  ledger's open items, with a name against it.
- Decision 54's revisit trigger is a p8 checklist item, not a reminder.
- Decision 55's arithmetic is an estimate and is labelled as one. p5 measures a real tree at the
  500-member cap and either confirms the decision or reopens it.
- **`test.yml`'s branch list is the one change from the restored file.** The original triggered on
  `beta/custom-server` alone, so it never gated `main` even while it existed — which is why its loss
  in merge `35ceb0f0` went unnoticed for nine days across the whole repo. It now triggers on `main`
  and `beta/**`. Its Go version also moves from `stable` to `go-version-file: go.mod`, so the gate is
  built with the toolchain the module declares rather than whatever Go ships next.
