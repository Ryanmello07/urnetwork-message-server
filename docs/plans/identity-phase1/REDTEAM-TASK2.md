# Red team, Task 2: the ten prompts before the spec (program gate 2)

**Filed copy.** This review is filed in `urnetwork/message-server` as `docs/plans/identity-phase1/REDTEAM-TASK2.md`, and the ledger entry that files it lists every change made in filing it. `PLAN.md` is the plan, filed as `docs/plans/2026-10-16-identity-layer-one-account.md`; `SCOPE.md`, `FOR-OWNER.md`, `REDTEAM.md` and LRI, `LEAD-RULINGS-I1.md`, are filed in this folder. PLAN, SCOPE and FOR-OWNER were revised in place after this review, so its `PLAN:`, `SCOPE:` and `FOR-OWNER:` line numbers are those of the versions it read (1,494, 358 and 73 lines) and do not point into the filed copies. A local path is replaced by a label: `lib@<sha>` is `urnetwork/message` at that commit. The owner's review file (OWN) is in no repository, and neither is the lead's scratch folder, which holds the designs and rulings this review names by a short name, such as OD, M5, F1, V4, D2 and LR.

**Writer:** Task 2's red team, the only writer of this file. I wrote none of SCOPE, PLAN or D2, and I am read-only everywhere. **Date:** 2026-10-16. **Status:** findings for the lead, each dispositioned under THE BUDGET (PLAN:89-101). Nothing was built, run or launched. No repository, server, spec or ledger was changed. No git or gh write ran. **Declined actions:** none.

**Subject.** The revised `PLAN.md` (1,494 lines) and `SCOPE.md` (358 lines), read whole [m]; `D2` §2.0-§2.11; `OD`, `M5`, `F1`, `F3` §2.1/§2.11, `V4` B.5 and F.0, `T1`/`T2` at the cited lines; `OWN` A28-A31; `LRI` R48-R57, `LR` R33-R47. Code read only: lib in a clone whose tree equals `lib@c7949cfd`... see §"What I read". The lead set this pass and REDTEAM's 2026-10-15 pass as the design's ONE pass (LRI R53); one check of these dispositions follows; a third round on one promise goes to the lead.

**Marks.** [m] I read it at the cited place this session. [c] my reasoning. [a] an assumed number or choice. **Budget class.** *Fixed in I1* only if ONE action of one adversary (or ordinary software) makes the code (i) erase without a true reason, (ii) say something false, (iii) accept what the list or the ceremony forbids, or (iv) let a phrase secret go where its disposition does not allow. Otherwise *filed* (new residuals would take MG-19 on, after Task 43's MG-18).

**Read first, and relied on, NOT redone** (LRI R53): REDTEAM §5 ("What holds") and PLAN's "Review dispositions" (PLAN:1455-1495). I rely on REDTEAM §5 for the key tree (a stolen phrase device cannot mint g+1; F1:356), IskCert determinism, validity-reads-trees, the emoji pinned to link-group epoch 1, the deposit sealed inside the code-sealed card, the grant carrying no phrase secret, X1 agreeing with the ship order, and RV-21; and on the dispositions for H1-H4, M1-M13 and L1-L7. Where a prompt lands on one of these I say "holds (REDTEAM §5 / disposition)" and do not re-derive it.

---

## 0. Verdict

**0 CRITICAL, 2 HIGH, 2 MEDIUM, 3 LOW.** The phrase change is, in the main, correctly built on M5's and F1's mechanisms, and the REDTEAM-era fixes (H1 sending side, H2 the (g) erase, H3 the words helper, H4 the reveal order) hold as the dispositions state. Two findings are new to this plan and are not settled by REDTEAM §5 or the dispositions:

- **T2-H1.** The new (g) erase names an order ("before anything is sent") and a postcondition ("holds no phrase key afterwards") but no FAILURE path. One held file at the moment of the (g) erase lets a removed or ended phrase device keep its phrase key in a folder the app then abandons. This is H2 reopening through ordinary software. Budget (iv): fixed in I1.
- **T2-H2.** I1 keeps the ROOT permanent across a phrase change (for a stable account ID), where M5 and F1's reviewed succession made a NEW identity. The consequence: a phrase change does not rotate the root of trust, so the FIRST phrase is a permanent master key, the alarm's "Change my recovery phrase" is a false remedy for a root compromise, and FOR-OWNER's "the old paper is refused" is too absolute. The design trade-off goes to the lead and the owner; the false sentence and the false remedy are fixed in I1 (ii).

| Id | Sev | Prompt | Finding | Budget |
|---|---|---|---|---|
| T2-H1 | HIGH | 7, 10 | (g)/(f)P/(i) erases are not gated on success; a held file leaves a phrase secret in an abandoned folder | (iv) fixed in I1 |
| T2-H2 | HIGH | 10 | Permanent root ⇒ phrase change ≠ root rotation; false remedy + understated owner copy | design → lead; (ii) fixed in I1 |
| T2-M1 | MED | 9 | The device key signs both MLS content and the list/amendment signatures; the 0x00-prefix disjointness is unpinned | (iii) if ever broken; pin with a KAT in I1 |
| T2-M2 | MED | 9, 10 | R3 reads "the old paper"; with a chain it is ANY retired key, the root included, permanently | state in I1 |
| T2-L1 | LOW | 10 | No mutant for "the change re-mints the salt" | add a mutant |
| T2-L2 | LOW | 5 | The order "R6s alias before R8-CUR/R8-SIB" is unstated for Task 42 | state it |
| T2-L3 | LOW | 8 | The own-signature log can be shortened by a put-back (disclosed false positive only) | holds; confirm the wording |

---

## 1. The findings

### T2-H1 · HIGH · The (g) erase is not gated on its own success; a held file leaves a phrase secret behind (prompts 7, 10)

**The attack.**
1. PC-1 is a phrase device; its store holds the phrase key record, `isk_seed[g]`, store kind 13 (PLAN:464; SCOPE A4).
2. The owner taps "Remove this device" (RM1) or, on an only device, "This ends this identity". Task 30 erases record 13 under authority (g) "before the self-removal is signed and sent" (PLAN:903, :131).
3. Ordinary software holds that one file open with no delete sharing at that instant: a backup agent, an antivirus scan, a sync client, or a terminal whose working directory is the store folder (this is R36's own "one program ... holding ... ONE store file", LR:247 [m]).
4. `os.Remove` of record 13 fails. The plan states the ORDER and the postcondition (Property 4, PLAN:910) but not what the code does when the erase FAILS. If it logs and proceeds — the ordinary shape of such code — the self-removal is signed and sent, the device is off the account, and record 13 stays on disk.
5. Task 38 then "opens a fresh store folder at once, and never opens the old one again" (PLAN:1062), and P2 wipes nothing else (PLAN:76). So the un-erased phrase key sits in a folder nothing ever touches again, on a computer the owner may give away.

**The property it breaks.** H2's fix and SCOPE A4: a removed or ended device is not a phrase device, so `isk_seed[g]` may not remain on it (PLAN:83; SCOPE:65). The authority (g) cell covers a MOVED record and a put-back (PLAN:142); it does not cover a HELD erase. Unlike (f), which retries ("erased again at the next start", PLAN:140), (g) has no retry: the fresh folder abandons the old one, so the key is permanent [c].

**Smallest fix (tighten).** Gate the act on the erase: Task 30 refuses to sign or send the self-removal / mark the end unless the (g) erase returns success; on a held file it stops, the device STAYS a phrase device (so the key's disposition still holds — nothing leaks), and the owner retries. Add to the (g) row a column for "the erase itself is held or denied": the answer is "the act is refused; the device stays a phrase device; nothing of the act is sent", with a test that holds record 13 and asserts the self-removal did not go out and record 13 is still present AND the device is still listed as a phrase device. The same gate covers (f)P and (i) where they erase a phrase secret (PLAN:130, :132).

**Budget: fixed in I1.** ONE action (a held file, ordinary software) makes the code let a phrase secret go where its disposition forbids — class (iv). The fix is a tightening of an erase site the plan already has, not a new mechanism.

### T2-H2 · HIGH · A permanent root means a phrase change does not rotate the root of trust (prompt 10)

**The design.** The account ID is `ID1 = SHA-256("…/id" ‖ u16(1) ‖ LP(root_pub) ‖ LP(salt))`, where `root_pub` is "the root, the first phrase's IRK" (PLAN:387; D2:168). The root is permanent: "a phrase change keeps it" (SCOPE K3, :139; D2 ID1 :128, ID3 :174). A change makes a form-1 step `Ed25519(old key, "…/identity-succession" ‖ next key)` (PLAN:419; V4:1012); the chain runs root → key₂ → … The first step is signed by the first phrase's IRK.

**Where it departs.** M5 and F1's REVIEWED succession made a change into a NEW identity: M5 PC2 "It makes a new identity, signed by the old identity key" (M5:185 [m]); V4 B.5 "A becomes B" with a new safety number (V4:308, :312 [m]); F1 §2.11 "B's devices found a new self group" (F1:746 [m]). D2 reconciled this to a permanent root so that "Your ID" survives (D2:174, reconciled by the lead D2:145). The plan inherits that (X13, the self group moves in place; SCOPE:175). The security consequence of that reconciliation was never surfaced.

**The attack.**
1. The owner's FIRST phrase leaks (the P3 premise, "if your seedphrase is leaked your account security is no longer guaranteed", OD:9). The owner changes the phrase with the old one — the natural act to "work around that" (OD:9), and the one FOR-OWNER sells (FOR-OWNER:19).
2. The root stays `IRK₁` — derived from the leaked first phrase. The attacker, holding the first phrase, derives `IRK₁` and signs a rival step `root(IRK₁) → IRK_attacker`. `VerifyIdentityChain(root, [IRK₁→IRK_attacker], IRK_attacker)` passes: the step is a valid form-1 step signed by the root (PLAN:420).
3. Now two successors of the root exist. "The first into a tree shuts the other out" (V4:318; PLAN:1097). In any conversation where none of the owner's devices has run since the change, the attacker publishes `root→IRK_attacker` first and shuts the owner's `root→key₂` out, then drops the owner's devices (R8-CUR). The attacker now holds the account's identity there — SAME root, so SAME account ID, SAME "person" to contacts.
4. This never expires and survives every later change, because the root never rotates. Changing the phrase again keeps `IRK₁` the root.

**The property it breaks, and what is already stated.** SCOPE R3 DOES state the per-conversation window: "whoever holds the old paper … can … make a rival change that shuts yours out of that conversation" (SCOPE:266). I do not redo R3. What R3 and the plan do NOT convey, and what is new here:
- **(ii) a false remedy.** The alarm for a second successor "offers 'Change my recovery phrase'" (PLAN:1148; SCOPE G6 :121). Against a compromised ROOT this is useless: another change keeps the same root, so the attacker keeps forging rival successors. The honest remedy is Start over (a new ID). An alarm that offers an ineffective fix says something false.
- **(ii) understated owner copy.** FOR-OWNER:19 "From then on the old paper is refused" is absolute and contradicts R3; the first paper is NOT refused as a root — it can forge rival successors. FOR-OWNER:64-65 discloses the window but not the permanence.
- **the permanence.** R3 reads "the old paper" (the latest); the first/root phrase is live FOREVER (see T2-M2).

**Smallest fix.** (a) To the lead and the owner: confirm the trade-off — a stable account ID (permanent root, D2) versus real compromise-recovery (rotate the root, a new ID, as M5/F1 did). This is a departure from an owner-accepted line (M5:185), so it is the lead's, as M8's departures were (PLAN:1462). (b) Fixed in I1 (ii): the second-successor alarm offers "Start over", not "Change my recovery phrase", when the conflicting successor is of the ROOT; and FOR-OWNER and the slice-4 report say plainly "changing your phrase keeps your ID but does not undo a leaked phrase — if your recovery phrase ever leaked, Start over with a new ID."

**Budget.** The code itself is correct (it rightly accepts a root-signed successor), so the core is a design question → the lead. The false remedy and the false owner sentence are (ii) → fixed in I1.

### T2-M1 · MEDIUM · The device key signs two domains; the 0x00-prefix disjointness is unpinned (prompt 9)

**The problem.** The device key (DK) signs MLS content AND, in I1, the device-list `author_signature` and every amendment (addition / self-removal) signature: `Ed25519(DK, LP("…/device-list-author") ‖ tbs)` (V4:1001; SCOPE C1). F1 kept these domains disjoint by one invariant: an F1 preimage begins with `LP(label)` = a u32be length < 2²⁴, so its first octet is 0x00, while MLS `SignContent` begins with a varint label length ≥ 8, never 0x00 (F1:367 [m]). The plan drops RetiredLegacy (PLAN:414), which removes one DK-signed F1 object, but KEEPS the DK-signed author and amendment signatures, so the two-domain case is live. The plan carries Ed25519 edge-vector KATs (PLAN:443) but no KAT that pins "a DK's MLS SignContent is not a valid author/amendment signature, and the reverse". The step and the base are IRK-/ISK-signed and IRK/ISK sign nothing in MLS, so those are clean by key separation [c]; the DK is the one key in two domains.

**Smallest fix (add a test).** Task 11 adds a KAT asserting the 0x00-prefix disjointness: a crafted MLS `SignContent` over the same bytes does not verify as an `author_signature`, and an `author_signature` preimage is never a valid `SignContent`. Pin F1:367's reasoning in the code comment.

**Budget.** It holds structurally today, so it is not a single-action break now; but an unpinned cross-protocol reuse invariant in a new build is a (iii) accept-forbidden waiting to happen if an encoding changes. Cheap to pin, so close it in I1.

### T2-M2 · MEDIUM · "The old paper" is any retired key, the root included, forever (prompts 9, 10)

**The problem.** R3 and K9 read "the old paper" / "a copy of a phrase device made before the change" (SCOPE:266, :145), which reads as the single immediately-previous phrase. With a chain of up to 4 steps (X12; PLAN:72), EACH retired key — every intermediate key, and the root — can forge lists (and, for the root, rival successors; T2-H2) in any conversation that has not seen the step PAST that key. The rank rule refuses a list "under a retired key" only "in a tree that holds the step" past it (SCOPE K5 :141); a conversation lagging two changes back has seen neither later step, so TWO different retired keys are each live there. The root is the worst case: live in every lagging or future-reached conversation, forever (T2-H2).

**Smallest fix (state).** Reword R3, K9 and the slice-4 report to say "any key your account has retired — every earlier phrase, and your FIRST phrase permanently — still counts in a conversation none of your devices has run in since that key was replaced." Keep the remedy honest: visiting the conversation on your device closes the window for THAT conversation; only Start over closes it for a leaked root.

**Budget: filed/state.** The multi-key form needs a copy or an old paper AND a lagging conversation (two conditions), so it is not fixed in I1; it is a disclosure the plan must carry, no new OPENITEMS id (it is R3's own scope, widened).

### T2-L1 · LOW · No mutant for a re-minted salt at a change (prompt 10)

`ID1` hashes `root_pub` AND a 16-octet salt (PLAN:387). Property 3 holds "Your ID" stable across a change and `TestAPhraseChangeKeepsYourIdAndEveryDeviceId` would fail if the change re-minted the salt, but the mutant list has none for it (MI104 covers the KEY, not the salt; PLAN:1175). Add `MI…`: the change re-mints the salt; Property 3 must fail.

### T2-L2 · LOW · The alias must run before R8-CUR/R8-SIB (prompt 5)

Task 13 builds R8-CUR and R8-EQ in slice 1 with no alias; Task 26 adds R8-SIB; Task 42 adds the R6s alias in slice 4. F1 runs "the R6s alias … before the other rules" (F1:551 [m]) so that R8-CUR/R8-SIB read the aliased identities; otherwise a device that moved in place would read as non-current and be wrongly removed [c]. Task 42 names R0b, R4, R5 and R7 as reading aliased lists (PLAN:1095) but does not say it re-orders the pipeline to put the alias ahead of R8-CUR/R8-SIB. State it in Task 42.

### T2-L3 · LOW · The own-signature log shortened by a put-back (prompt 8) — holds, confirm the wording

The alarm's second reason reads this device's own-signature log, store kind 12 (PLAN:1020-1022). One put-back of an OLD copy of that record shortens the log, so a change THIS device made and later re-sees is no longer in the log and the alarm fires — a false POSITIVE. P7 and Task 34 already say "its sentence names that case" (PLAN:81, :1022), which is the disposition. It CANNOT be turned into a false negative: a copy cannot write the ORIGINAL device's log, so it cannot pre-insert its own future change to suppress the alarm [c]. So prompt 8 HOLDS; the only action is to confirm Task 34's second-reason text does name the put-back/restore case (it does, PLAN:1022).

---

## 2. The ten prompts, each answered

**1 — TR7's memory of marks; TR12's pool of 16 and its folding; RM6's keep-or-remove dialog; the shorter entry (M5:422).** HOLDS, with one state item. TR7's memory (Task 31, MI65) refuses a list that drops a remembered phrase-device mark (PLAN:943); it is keyed per (key, g) and "starts again under the new key" at a change (PLAN:1145), which is correct because the new base re-states the marks. TR12's pool of 16 and folding (Task 33, MI72) and RM6's dialog over listed devices (Task 32) build M5 H.10's unreviewed items faithfully. The shorter 50-octet entry (Task 11) drops `added_at_ms`/`added_by`; "when and by whom" comes from the self-group notices (Task 26), not the entry, so no surface loses its data [c]. No budget-class defect.

**2 — X1, D off: what a removal promises, against a stolen phrase device and an altered removed device.** HOLDS (stated). A removal acts at once; against an unaltered app the device stops itself; against an ALTERED app the device acts in a conversation until a device of yours brings the new list there (SCOPE R8; L-v5-12). A stolen phrase device removes your other devices at once, and your phrase cannot win the account back in this build (SCOPE R1; REDTEAM M9). The promise table's rows 5 and 7 mark "same subject? no" and name where each stops (PLAN:113, :115). The phrase change adds no new false promise: a removal that races a change is rebuilt or void (Task 43 step 5). Already stated; nothing new.

**3 — X2, the link through the server, with REDTEAM H4's reveal order restored.** HOLDS (REDTEAM §5, disposition H4). The code, its derivations, the card sealed under the code and the deposit sealed to the card's X-Wing key are sound (REDTEAM §5; D2 IB2); commit-then-reveal with N revealing `n_N` only after it reads `n_E` at epoch 1 is restored (Task 22 step 4, Property 5, MI83; PLAN:712). The "not taken" extra check (the grant's root equals the link group's root) is sound to omit: N has no prior account, so there is no wrong-account to protect against — matching emoji put N and E in one link group and only E posts the grant there (disposition H4; F1 variant (a) needs no such check). I confirm the omission is safe.

**4 — the binding in every leaf: VerifyLeafBinding's order; equal versions, different octets; a key package older than the adder's head.** HOLDS. The order (Task 11, Property 1, `TestEveryRefusalStepOfTheLeafBindingIsReached`) reaches each refusal step; the chain check (step 3) sits between the cert and the list checks, and an empty chain forces root == credential [c], so a pre-change leaf with credential ≠ root is refused there. Equal versions with different octets are a fork (R8-EQ, Property 2/7, MI17/MI34). A key package whose list is older than the adder's head and omits its key is refused at the Add door (Task 13, MI32); one that names the key but is older is admitted and then judged by the rank rule, which is correct. No budget-class defect.

**5 — R8-SIB, R8-CUR and R9 over today's role rules (lib roles.go).** HOLDS, with T2-L2. Today `ruleIdentityContinuity` (R6c, roles.go:200-214 [m]) refuses the committer's own path moving its leaf identity, which Task 42's R6s must relax — the plan is right that R6c refuses every move today. The new rules insert "after R6c and before R1 in F1's order" (PLAN:498); R8-SIB (Task 26), R8-CUR and R8-EQ (Task 13) and R9 (Task 13, Task 42 for the chain) are placed as F1:506-527 has them. The one unstated point is that Task 42's alias must run BEFORE R8-CUR/R8-SIB (T2-L2). H1's sending-side fix (the committer's post-commit leaf in `outgoingAuthorizationLocked`, today the PRE-commit leaf at rolescommit.go:236-243 [m]) is correctly carried (Task 13 Property 8, MI81).

**6 — the self group with no server head: a fork, a withheld commit, two lock-outs at once.** HOLDS (part fixed, part filed; REDTEAM M6). A fork raises the alarm's first reason and names I1's remedy, remove-and-re-add (Task 34; REDTEAM M6). A withheld self-group commit makes a device lag; if it sees its own change in a conversation but not the self group it raises the alarm and moves nothing (Task 43 Property 9; scenario `I1-server-withholds-a-phrase-change`). Two lock-outs at once are MG-16 (two first bases of g+1, equal versions → R8-EQ fork → the later device holds a fork and the alarm until removed and re-added; the random first base number is the fix to come, PLAN:347-348). The phrase change's analogue, a fork at a change, is MG-18 (PLAN:1185). All correctly filed as liveness costs of correct refusals (LR R39). No new budget-class defect.

**7 — the new erases (the authority table, every column), P9's (g), and identity-wide leave (P1, not built).** T2-H1 (the (g) erase not gated on success) is here. Otherwise: the (f), (f)P, (g) and (i) rows read true for columns 1-7 against a MOVED record, a stray and a put-back (PLAN:140-143); the gap is a HELD/denied erase of a phrase-secret record, which no column covers and which (g) cannot retry (T2-H1). Identity-wide leave stays unbuilt (P1): a left device's leaf stays (G8), so fan-out never finds it missing, and after an admin's removal Task 25's respected-removal rule keeps it out (SCOPE F3; PLAN:1055). So per-device leave keeps a left device out — HOLDS. A leave is a local forget, no erase, so it adds no authority (correct).

**8 — the alarm's premises (P7): can one put-back make it say something false?** Answered as T2-L3: yes, a disclosed false POSITIVE (the log shortened), not a false negative; P7 states it; HOLDS.

**9 — the phrase: 267 bits as Argon2id's input and their encoding; the labels; every signature domain.** T2-M1 (the DK's two domains, unpinned) is here. Otherwise: 267 bits + an 8-bit checksum = 275 = 25 × 11 (PLAN:382); 267 bits encoded as 34 octets, high bits zero (PLAN:386) [a, the spec fixes it]. The labels are distinct across objects and keys: `"…/isk-cert"` and `"…/identity-succession"` are both IRK-signed but differ in label; `"…/device-list"` is ISK-signed; `"…/device-list-author"` is DK-signed (V4:989, :1000, :1001, :1012). Dropping RetiredLegacy (PLAN:414) removes a DK-signed F1 object, which HELPS; the remaining DK dual-domain (author/amendment vs MLS) holds by F1:367 but is unpinned (T2-M1). IRK and ISK sign nothing in MLS, so those are clean by key separation.

**10 — PC1 to PC5 as I1 builds them, against M5's and F1's reviewed succession.** T2-H2 (permanent root) and T2-M2 (any retired key forever) are here, and they are the heart of this prompt. Beyond them: a stolen phrase device across a change CANNOT make a rival successor, because the step needs IRK (the identity key), which a phrase device does not hold — it holds `isk_seed[g]` only (F1:350; V4:1012) [c]; it can only sign old-key LISTS in unreached conversations (R3). A lying server that withholds the succession → R3 / the alarm (Property 9); replays the old list → refused by the rank rule where the step is seen; forks → MG-18. A copied store before the change keeps the old key with R3/R4's reach. The form-1 chain verifier a stranger runs is pure and store-free (Property 5), and cannot be fooled (it does not decide newest-ness; the heads do). The void change and authority (i) are sound against a lying server: nothing is erased "until the rival is seen" (PLAN:143), and the server cannot forge a valid self-group rival commit, so (i) fires only on a genuine rival [c]. (f)P erases only on a verified step (the server cannot forge it). The account ID and device IDs are kept because both are over the root (Property 3; T2-L1 adds the missing salt mutant). The hooks at PC1 and AD1 run with the keys in scope but no hook is registered in I1 (LRI R51), so no I1 identity leaks an owner key.

---

## 3. What holds (checked, relied on, not redone)

- **The succession machinery itself** is faithful to F1/V4 where those were reviewed: R6s shape (i) with the aliased policy (F1:551-570), the rank rule (V4:317), one successor per key with first-in-wins (V4:318, :1064), R9 reading the self group's key through the chain (Property 5). The move-in-place (X13) is a sound realisation OF a permanent-root model — the finding (T2-H2) is that the model itself trades away compromise-recovery, not that the machinery is wrong.
- **The REDTEAM-era HIGH fixes hold:** H1's sending side (MI81), H2's (g) erase and no-target lock-out (the gap is only its failure path, T2-H1), H3's words helper (MI88/MI89 + the retired-key sentence), H4's reveal order (MI83) — each against its cited code [m: roles.go:200-214, rolescommit.go:236-243].
- **The 90-day leaf** (MG-17) is a true liveness cost: a joiner validates every leaf's lifetime against its clock (`mls/group.go:3633-3647` [m]); accepted because the alpha resets every slice (LR R39; SCOPE R16).
- **The erase gate** holds every site names an authority (erasegate_test.go:19-60 [m]); the halt that makes H1 matter is real and permanent (group.go:1223 [m]).
- From REDTEAM §5: the key tree (no g+1 from a stolen phrase device), IskCert determinism, validity-reads-trees, the emoji pinned to epoch 1, the sealed deposit, the grant carrying no phrase secret, and RV-21. I did not re-derive these.

## 4. What I read

- **Whole [m]:** PLAN (1,494), SCOPE (358), FOR-OWNER (73), REDTEAM (443); LRI R48-R57; LR R33-R47; OD; M5; D2 §2.0-§2.11 (D2:1-461).
- **At the cited lines [m]:** F1 §2.0-§2.6 (:329-627) and §2.7-§2.12 (:629-763), above all the succession §2.11 (:722-746) and VerifyLeafBinding (:463-473) and the rules table (:530-570); F3 §2.1 by reference through SCOPE; V4 B.5 (:299-360) and F.0 (:982-1166), above all the step and formats (:987-1058) and W4/the rank rule (:317-318, :1064); T1/T2 by reference through PLAN and D2; OWN A28-A31 through the citations.
- **Code, read only [m], lib in a clone whose tree equals `lib@c7949cfd` (the task's lib pin):** `sdk/urmessage/roles.go:1-276` (R6c at :200-214), `rolescommit.go:195-254` (the pre-commit committer leaf at :236-243), `mls/group.go:1215-1230` (the permanent halt) and `:3628-3651` (the leaf-lifetime check), `sdk/urmessage/erasegate_test.go:19-60` (the authority allow-list). I did not read or write the app workspace REDTEAM read.
- **Not done.** Nothing was built, run or launched; no size was measured; the cost of forging a rival successor is [c] (it is one Ed25519 signature with the leaked first phrase). I did not read Spec A/B/C, MB, or the lib code the link ceremony and self-group records live in beyond the lines above.
