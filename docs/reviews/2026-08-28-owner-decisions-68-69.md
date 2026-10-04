# Owner decisions 68–69

Earlier rounds: `-1-45`, `-46-49`, `2026-08-13-…-50-58`, `2026-08-25-…-59-63`,
`2026-08-26-…-64-65`, `2026-08-28-…-66-67`.

Both were taken by the controller under the standing delegation. **68 is a security finding against
the plan** and is the one worth reading.

| # | Decision | Affects |
|---|---|---|
| 68 | **p5's plan states RFC 9420 §7.9.2's parent-hash rule materially weaker than the RFC does, and the RFC's version was implemented instead.** The plan gives the rule as a two-armed disjunction — *"some node in Resolution(L) carries the parent hash of P with copath child R"* — one arm, one condition. **§7.9.2 states three conditions**, and the third is **absent from the plan entirely**: *D is in the resolution of C, and the intersection of P's `unmerged_leaves` with the subtree under C is equal to the resolution of C with D removed.* **Dropping it is not a conservative simplification, it is a hole.** Condition 3 is what constrains the *resolution* of the child to be exactly the claimant plus the unmerged leaves under it — and the resolution is precisely the set a commit encrypts path secrets to. Without it a forger keeps the legitimate hash chain intact and splices an extra subtree in beside it; the spliced nodes land in the resolution, the next commit seals a path secret to keys the forger chose, and **every parent still "chains"** so whole-tree validation passes. The implementation follows the RFC's three conditions. The reading was validated against the vendored corpus *before* the code was written: **290 of 290 non-blank parents match with exactly one descendant**, so the stricter rule refuses no legal tree. **The standing risk, and why this row exists:** a later task that re-derives this rule from the plan's text rather than from the code will reinstate the hole, and it will pass every test that existed before it because the corpus contains no forged tree. The plan is **not** corrected — it is a historical record — so the code and this row are the defence. | `connect/mls/tree_hash.go`; p5 tasks 21–23; any future re-derivation |
| 69 | **`sed -i` is banned on tracked source in this workspace, and the standing brief that recommended it was wrong.** Rule 7 of every implementer brief told agents to prefer `sed -i` over exact-string Python replaces, on the grounds that Git Bash's `sed` is line-oriented and therefore CRLF-tolerant. On 2026-08-28 it **rewrote a whole `.go` file from CRLF to LF while its own substitution matched nothing** — Rule 7's own failure mode plus a file-wide diff with no semantic content, which is exactly the shape that gets committed by accident. The rule now says the opposite: Python opened with `newline=''`, the line ending derived from the file itself, and an asserted occurrence count before any edit. **Corrected in all eleven brief templates** and in the controller's own notes. | every implementer and reviewer brief; `feedback-crlf-breaks-source-anchors` |

## Amendment, 2026-08-29 — the weak rule is in the plan TWICE, not once

Decision 68 recorded that p5's plan states §7.9.2's rule as one condition where the RFC states three.
p5 Task 21 found **the same hole in different code**: the plan's literal merge body recomputes the
parent-hash chain, compares it to the leaf's signed `parent_hash`, and stops — which is §7.9.2's
**second condition only**. A parent node an attacker splices into a copath resolution is in the set the
next honest commit seals to, and every check the plan's merge body makes passes.

So the plan carries the weakness in **two** independent places: its statement of the rule (Task 14)
and its implementation of the merge (Task 21). The merge now calls Task 14's `VerifyParentHashes` on
the merged tree instead of doing its own partial check. **That is a deliberate divergence from the
plan's literal code**, and it is consistent with the plan's own Task 25 text, which already calls
`VerifyParentHashes` after a merge — so the plan disagrees with itself, and the RFC settles it.

**This raises the standing risk rather than closing it.** A later task re-deriving *either* the rule
or the merge from the plan will reinstate the hole, and it will pass every test that existed before it
because the corpus contains no forged tree. Tasks 23 and 26, and the validation plan, should be told
that the merge now refuses a tree §7.9.2 refuses.

## Application notes

- **Decision 68 leaves a debt.** p5 Task 13's implementer was lost to an API failure mid-response,
  leaving `ParentHash` uncommitted and untested; Task 14's agent committed it because Task 14 does not
  compile without it. So **`ParentHash`'s own behavioural tests are still owed**: nothing pins its
  argument refusals (a copath child that is not a child of the parent, a node-type mismatch, an
  out-of-range index, a blank parent), and RFC 9420 appendix B's worked example is held nowhere. What
  *does* currently hold its bytes to an outside source is the corpus test — 290 non-blank parents,
  several with unmerged leaves inside the sibling subtree — so a wrong preimage or a skipped
  original-tree-hash blanking fails. **That debt is scheduled with p5's remaining tasks and is not
  forgotten.**
- **§7.9.2's "exactly one claimant" has an upper half that is unreachable and is covered by argument
  only.** Two claimants would require the left claimant to store `ph(P, copath=right)` while the right
  stores `ph(P, copath=left)`, and each stored value sits inside the subtree the other's value is a
  hash of — a hash cycle. So the `claims != 1` branch is exercised at 0 and not at 2. A later task
  should not read that branch as tested at 2.
