# Owner decisions 66–67

Earlier rounds: `2026-08-12-owner-decisions-1-45.md`, `-46-49.md`,
`2026-08-13-owner-decisions-50-58.md`, `2026-08-25-owner-decisions-59-63.md`,
`2026-08-26-owner-decisions-64-65.md`.

Both were taken by the controller under the standing delegation and are recorded with their
reasoning so they can be overturned on sight. **66 is the one worth the owner's attention**: it is a
deliberate divergence from the published RFC.

| # | Decision | Affects |
|---|---|---|
| 66 | **We implement RFC 9420 erratum 8745, which is status `Reported` — that is, submitted and nothing more.** It has not been accepted by the responsible Area Director, it is not `Verified`, and it is not `Held for Document Update`. The erratum extends §13.4's capability check from *adding* a member to *updating* a leaf, covering both Update proposals and the `LeafNode` objects inside a Commit's `update_path`. Implementing it is therefore a decision to **diverge from the RFC as published**, and it is stated as such rather than as "the RFC says". **Why implement it anyway:** the gap it names is real — without the check, a member can update their own leaf to drop support for a group extension the group requires, and every other member then has a peer that cannot process the group's messages while the tree still validates. The published text forbids that at join time and says nothing about it afterwards, which reads as an oversight rather than a design. **Accepted cost:** a peer implementing the RFC as published will accept an update this one refuses. That is a strictly-more-permissive peer, so the failure mode is interop friction rather than a security hole on our side, and it is the safe direction to be wrong in. **Revisit trigger, not a vague intention:** the erratum's status. If it is rejected, this becomes a divergence with no standards backing and should be removed; if it is verified or held for document update, this row becomes unremarkable. `connect/mls/ERRATA.md` carries the erratum transcribed verbatim with its status and its retrieval date, so the check is a diff rather than an investigation. | `connect/mls/leaf_node.go`, `connect/mls/ERRATA.md` |
| 67 | **A registry code point is pinned by two independent readings of two different RFC sections, joined on the name rather than the value.** This is a rule about how registries are transcribed, adopted after it caught a live wire-incompatibility defect. `ExtensionTypeExternalSenders` was declared at `0x0004` — which RFC 9420 §17.3 assigns to `external_pub` — and the plan says `0x0004` in two places, so the error was **inherited from the plan rather than introduced**. The gate written to catch exactly this did **not** catch it, because its table was transcribed by the same person from the same section and agreed with the same misreading. What caught it was a second table read out of **§7.2**, where the RFC writes each code point beside its own name for the extension, joined to the first **on the name**. **The general rule:** a pin transcribed once agrees with whatever the transcriber believed. A registry that matters on the wire needs two readings from two places in the source document, joined on the field the two have in common. **Accepted cost:** two tables to maintain, and a reader who has to be told why the duplication is deliberate — which is written into the test file rather than left to be inferred. | `connect/mls/extension_test.go`; every future registry transcription |

## Application notes

- Decision 66's revisit is mechanical and cheap: re-read <https://errata.rfc-editor.org/eid8745>,
  compare the status line against the one `ERRATA.md` records, and act only if it changed. It should
  be done before GA and whenever anyone touches leaf validation.
- **The plan is wrong at `docs/plans/2026-08-12-slice1-p5-treekem.md` lines 405 and 1245**, which both
  declare `ExtensionTypeExternalSenders = 0x0004`. The code is right and the plan is not; a future
  task that follows the plan literally would reintroduce the defect, and the gate would catch it
  again. The plan is left uncorrected deliberately — it is a historical record of what was planned,
  and decision 67 is the mechanism that makes following it safely impossible.
