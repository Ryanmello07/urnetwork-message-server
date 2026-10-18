# Lead rulings: identity phase 1 (I1), and its interface to IDs and requests (R)

**Filed copy.** These rulings are filed in `urnetwork/message-server` as `docs/plans/identity-phase1/LEAD-RULINGS-I1.md`, in the folder beside the plan, and the ledger entry that files them lists every change made in filing them. `identity-phase1/PLAN.md` and `PLAN.md` are the plan, filed as `docs/plans/2026-10-16-identity-layer-one-account.md`: the plan as R87 left it, of 1,573 lines, where R61 read 1,545, R68 left 1,552, R70 1,569, R74 1,570 and R84 1,571, with two lines of legend added at its top. A `PLAN:` line here is of the plan its ruling read, without that legend. R65's `PLAN:148` is line 149 of the plan as filed, and line 151 of the filed copy, since R86 and R87 added a line after its line 140. R66's addendum's `:1395` and `:1488` are of the plan as R66 left it; R68 added a line after its line 493, R70 seventeen after its line 339, R74 one after its line 968, R84 one after its line 779, and R86 and R87 two, after its lines 140 and 151, so they are lines 1,417 and 1,510 of the plan as filed, and 1,419 and 1,512 of the filed copy. `identity-phase1/review-t8-t10/FINDINGS.md`, which R68 cites, `identity-phase1/review-srv-t18-t20/FINDINGS.md`, which R75 cites, and `identity-phase1/review-slice1/FINDINGS.md`, which R84 cites, are the findings files of the library's review, of the server's slice review and of slice 1's review, and `identity-phase1/review-srv-delta/`, which R78 cites, is the folder of the server's delta review; all four are in the lead's scratch folder and not filed. `SCOPE.md`, `FOR-OWNER.md`, `REDTEAM.md` and `REDTEAM-TASK2.md` are filed in this folder. A local path is replaced by a label: `srv@<sha>` is `urnetwork/message-server` at that commit. The lead's scratch folder is in no repository: it holds every `scratchpad/...` path, and the designs and rulings named here by a relative path or a short name, such as D2 and LR.

**Date:** 2026-10-16 (UTC). **Writer:** the lead. These rulings continue LR's numbering (`scratchpad/hardening-plans/LEAD-RULINGS-2026-10-15.md`, R34 to R47; R33 is in `LEAD-RULINGS-2026-10-14.md`).

**Read with:** `identity-phase1/PLAN.md` (46 tasks since R70) and `SCOPE.md`; `accounts-requests/DESIGN-v2.md` (D2). PLAN's Task 1 files this file in `message-server` beside the plan. Every writer reads it before starting a task, and again before finishing one.

**Owner's questions.** The rulings below marked **owner** wait on the owner's answer. The rest stand now.

---

## R48. The bases, corrected

- **srv.** `main` is `37dd710f`, the merge of urnetwork/message-server#11 (2026-10-16 03:08Z). T1's ledger close is ON `main`.
  - PLAN's "Base" row and Task 1 read `srv@20fc48db` and say "not yet on main". That is stale. Task 1 corrects it when it files the plan.
- **lib.** `main` is `c7949cfd`, as PLAN says.
- **app.** `badf2e2c` until urnetwork/message-windows#7 merges, then `main`.
  - The S3 branch `fix/s3-relay-drawer-trim` (a223341 and onward) is the lead's dispatch to W-app. It is not a second writer: W-app is the writer of both.

## R49. SCOPE's departures X1 to X10

- **Taken:**
  - X1: D off in I1. The owner is told in FOR-OWNER, with OD:99.
  - X2: the server carries the link code. It answers A29.
  - X4: T2's labels move to R.
  - X6: the device ID is derived (P8).
  - X7, X9, X10.
- **Sent to the owner,** because each departs from an owner-accepted line (REDTEAM M8):
  - X3, the phrase change in I2: **owner**, FOR-OWNER question 1;
  - X8, keys under file permissions only until I2: **owner**, FOR-OWNER question 3;
  - X5, a cap of 10: a default the owner may flip.

## R50. The lead rows P1 to P11

- **P1:** identity-wide leave is cut to I2. **owner**, FOR-OWNER question 2. Task 37 is not built unless the owner says no.
- **P2, P3, P4, P7:** taken as planned.
- **P5:** Slice 0 is built (Task 6). W-app does it after the S3 fix.
- **P6:** the build-03 folder is kept. No authority (h) exists. READ-ME-FIRST says how to delete it by hand.
- **P8:** taken. ID1 and DID1 follow D2, frozen in Task 3's registry before any known answer.
- **P9:** taken. A phrase device's own removal or end erases its phrase key first, under (g), and the no-target lock-out notice is offered.
  - Why: budget class (iv). One action, a thief at an unlocked phrase device, leaves a phrase secret where its disposition does not allow.
- **P10:** taken. Task 35 moves to R, which writes it against D2 §2.0. The words-scoped hooks stay in I1 (Tasks 32 and 33).
- **P11: FLIPPED.** W-app builds the conversation list during I1, as app-only work in the gaps between its I1 tasks.
  - Order: after Task 6, and never ahead of Tasks 16, 28 or 38.
  - It lands with R's first app slice, not in an I1 build, unless the lead rules otherwise when it is done.
  - Why:
    - it is R's longest pole (D2 §8.1 item 1);
    - W-app has about one commit per I1 slice (REDTEAM M13);
    - the owner asked to speed up development for testing.
  - The owner's order is unchanged: the identity layer still ships first, and more chats ship with R.

## R51. The interface to R: D2 §2.0 against SCOPE §5.1

| D2 | Ruling |
|---|---|
| IL1 to IL4, IL6, IL9, IL12 | Provided as SCOPE §5.1 states. Under P10, the proof, the binding check, the two signers, the two derivers and the events are R's, written against D2 §2.0 |
| IL5 | Provided: `VerifyLeafBinding` and `VerifyDeviceList` are pure functions in `messagegroup` (Task 11), which a stranger can run with no store and no self group |
| IL5b | The heads (C7) hold the newest list per identity. R adds the accessor (REDTEAM L7) |
| IL7 | The words-scoped hooks are I1's. `SignWithPhraseKey` and `DerivePhraseKeyed` are R's (P10) |
| **IL8** | **The words-scoped hooks also run at AD1's `ConfirmWords`, before the words are erased.** Task 32, which makes the hooks, wires AD1 too, with one property and one mutant. No hook is registered in I1. R registers `"inboxown/v1"`, and R's first build resets the alpha, as every slice already does (M1; OD:110-114). So no I1 identity needs an owner key |
| **IL10** | **I1's self-group records keep the server's delivery order** (REDTEAM M12). D2's "first in order" (MD3; RV-18, RV-21) is therefore carried inside a self-group commit. R's plan adds that call. D2 §2.0 is amended to say so |
| IL11 | The events move to R with Task 35 (P10). R raises "a removal finished" only after the removal's self-group commit is applied, hooking I1's removal path |
| **IL13** | **I1 does not build T1b's `Group.Rekey`.** It is stated and filed instead. See R52 |

## R52. The 90-day leaf (D2's F1), in I1

- **The defect.** A joiner checks every leaf of the tree against its clock (lib `mls/group.go:3633-3647`). A conversation that holds a leaf from a key package past its 90-day life refuses every new joiner.
- **Where I1 hits it.** I1's fan-out (JN2) and T1's pasted join both leave a key-package leaf until that device commits. A list change makes each device re-issue its leaf, which replaces it.
- **Disposition in I1: accept and state** (kind 3). The alpha is reset every slice (M1), so no alpha conversation reaches 90 days.
  - SCOPE §7 gains this as risk **R16**.
  - Task 8 files it as **MG-17**. MG-16 is M6's two lock-outs at once.
  - It is a liveness cost of a correct refusal (LR R39).
- **In R:** R builds T1b's `Group.Rekey` and ends **every** join with it, I1's fan-out joins included, not only request-started ones. D2 §2.8 is widened to say so.

## R53. Task 2 runs as written

- The red team of 2026-10-15 reviewed the PLAN with its lenses 1 to 5. It did not take Task 2's prompts 1, 6, 8 and 9:
  - TR12's pool of 16, and the shorter entry (M5 H.10);
  - the self group with no server head;
  - the alarm's premises;
  - the phrase's encoding and every signature domain.
- So Task 2 runs as written, prompts 1 to 9, with two changes:
  - prompt 3 adds H4's reveal order;
  - prompt 7 adds P9's authority (g).
- Its reviewer reads REDTEAM §5 ("what holds") and PLAN's dispositions, and does not redo what they settle.
- **Budget.** The 2026-10-15 pass and Task 2 together are the design's one pass. One check of Task 2's dispositions follows. A third round on one promise comes to the lead.

## R54. D2's lead defaults, and the owner's two questions on D2

- **D2 §9's "Decided by the lead's principles" list stands.** Each is a default the owner can flip. One of them leaves ledger 70's one-time links unbuilt, because invitations go by ID. The owner ruled ledger 70 on 2026-09-02, so the summary names it.
- **To the owner now:**
  - **Q6**, drop the reusable last-resort key. This departs from the owner's ledger 69 item (2), so it needs the owner's word.
  - **Q7**, whether "Accept invitations first" also hides strangers' requests.
- **The UI copy in D2 uses no pronoun for the inviter.** "'Alice' invited you to a group they call 'Book club'" was corrected by the lead on 2026-10-16. The app cannot know anyone's pronouns.

## R55. Order of work once the owner answers

1. W-app: finish S3, then Task 6 (Slice 0), then the conversation list (R50, P11).
2. W-srv: Task 1, filing PLAN, SCOPE, this file and the ledger entry. Then Tasks 3 to 5 (MASTER, Spec A, Spec B), each after Task 2's dispositions.
3. Read-only: Task 2, in parallel with Task 1.
4. W-lib: Tasks 8 to 10 once Task 1 is filed; Task 7 once Tasks 4 and 5 land (REDTEAM L1).
5. **Deploys.** The alpha server's link-box deploy (slice 2) is a major VPS change. The lead tells the owner before it.

---

## R56. The owner's answers of 2026-10-16, verbatim, and what they change

**Asked:** the four questions put in the lead's summary of 2026-10-16. P1 (leave on this computer only) and X5 (10 devices) were offered as defaults to flip, and were not flipped.

1. **The phrase change.** Asked: "You said changing the recovery phrase ships with the identity layer. May it land in phase 2, right after phase 1?"
   - **Answer: "No, in phase 1".**
   - **X3 is FLIPPED by the owner.** PC1 to PC5, the phrase change made with the old phrase (F1's succession, F1:551-570; M5 PC1-PC5), are built in I1.
   - PLAN, SCOPE and FOR-OWNER are revised for it.
   - Task 2's red team takes it as prompt 10, since it is a crypto design (red-team first).
   - The words-scoped hooks run at PC1 too (D2 IL8).
   - I1 now yields a non-empty chain of form-1 steps (D2 IL2), so I1 provides its pure verifier beside `VerifyDeviceList`.
2. **Keys on disk.** Asked: "Until phase 2, may keys on disk be protected only by file permissions, as in build 03? This is for alpha test builds only."
   - **Answer: "Yes, alpha only (Recommended)".**
   - X8 stands, for alpha test builds only. Sealing and the Windows Hello prompt come in I2, before any non-alpha build.
3. **The last-resort key (D2 Q6).** Asked: "Your 2026-09-02 ruling (ledger 69) expected a reusable 'last resort' invite key on the server. May we drop it?"
   - **Answer:** "Talk about this further- we don't realistically want normal users to run out of keys... Unless it's for a theoretical "run out" based on non normal use them via normal use it should never run out"
   - **Open, under discussion.** The lead's reading: a run-out may happen only under abnormal use, such as a deliberate drain, and never under normal use.
   - So D2's 16 keys and 4 claims a day are too tight. A person invited to five groups in a day would hit the cap.
   - This is for R. It does not block I1.
4. **Strangers (D2 Q7).** Asked: "'Accept invitations first' stops the server keeping keys for you. It doesn't cut the requests you see: a stranger's invitation just arrives in another form. Should it also hide requests from people you haven't saved?"
   - **Answer:** "Talk about this further-want it to be similar to matrix, realistically spam won't be an issue with long uuids to start a chat with someone unless they were already in a group chat"
   - **Open, under discussion.** The lead's reading: as in Matrix, anyone who holds your ID can send a request, and no stranger filter is needed. The IDs cannot be guessed, so the people who can reach you are those you gave your ID to and those who share a group with you.
   - This is for R. It does not block I1.

## R57. Order of work, revised (replaces R55's steps 1 to 3)

1. **One workflow:** revise PLAN, SCOPE and FOR-OWNER for PC1 to PC5 (R56.1). Then Task 2's red team, prompts 1 to 9 with R53's additions plus prompt 10 for PC1 to PC5. Then the dispositions, under THE BUDGET.
   - Task 2 runs BEFORE Task 1 (a reorder), so the plan filed in `message-server` already carries Task 2's dispositions.
2. **W-app:** S3 is done (fork `fix/s3-relay-drawer-trim` a832482; the PR opens after message-windows#7 merges). Next, the conversation list (P11 flipped, R50), now, while the workflow runs. Task 6 (Slice 0) follows Task 2's dispositions, and the list pauses for it.
3. **W-srv:** Task 1 after the workflow, then Tasks 3 to 5.
4. **W-lib:** Tasks 8 to 10 after Task 1.

---

## R58. The owner's answers on D2's Q6 and Q7, after the discussion (2026-10-16), verbatim

- **Asked:** "How should invite keys work so that normal use never runs out?"
  - **Answer: "Bigger stock + fallback key".**
  - The option, as offered: "The same, plus one reusable key used only after the one-time keys are gone, replaced when your PC next runs. As Matrix and Signal do. It never slows down, but invitations made with that key share it until it's replaced." "The same" was the first option's "100 keys per PC, topped up whenever the app runs; up to 50 handed out a day".
- **Asked:** "Requests will work like Matrix: anyone with your ID can send one, and nothing filters it. Should 'Accept invitations first' stay as an optional privacy setting?"
  - **Answer: "Keep it, off by default (Recommended)".**
- **What changes in D2 (to become v2.1):**
  - KP2: 16 keys become 100 per device, topped up at every run.
  - KP6: 4 claims a day become 50 per device.
  - KP3: no last resort becomes ONE fallback (last-resort) key package per device. It is served only when the one-time stock is empty, and replaced at the device's next run. This is ledger 69 item (2)'s "last-resort package", with its labelling: the invitation's details say it used the fallback key.
  - "Accept invitations first" withdraws and erases the fallback too.
  - RQ12 and S-17/S-18 change accordingly. K-risks gain the fallback's shared-key window.
  - Q6 and Q7 are answered in §9.
  - Q7: no stranger filter (Matrix-like). The switch is a privacy setting, off by default.
- **The red team of this delta** is R's plan's red team, which covers the whole design. Until v2.1 is written, D2 carries a superseding note at its top.

## R59. W-app's conversation-list design (`scratchpad/convlist/DESIGN.md`): accepted, with these rulings

1. **F1 and F2 ship first, as their own small PR.**
   - F1, reproduced by the lead from source: `SetConversationSelected` names rows from `urmsg::demo::GetWorld()`, at Views/ConversationListView.cpp:499 and :525-528 at a832482. Live builds announce invented names. This breaks G4.
   - Branch `fix/live-row-names` from **badf2e2c** (not a832482), so it can open beside S3 as soon as urnetwork/message-windows#7 merges.
   - Same evidence standard as S3: `--diagnose`, shots, a mutant per property, and the UIA names checked as text.
   - `feat/conversation-list` (from a832482) merges it in by a merge commit. No rebase.
2. **The design is accepted as written:**
   - one session, a loop thread per group, and one push waiter routing by group id;
   - per-group gates and incarnations;
   - the join road always reachable;
   - honest special rows;
   - no unread counts;
   - the seven `--diagnose` lines and nine worker mutants;
   - shots with runner founders.
   F3 (the composer's draft follows a switch) is fixed inside the list work.
3. **The live run: no JWT leaves the box or this machine.** No Actions secrets.
   - The app on a fork runner uses the direct route to the alpha's own pinned endpoint (`wss://74.50.11.53/urmessage/v1`). That endpoint authenticates no client (SCOPE G9), so no account is involved.
   - livepeer runs on the box as before, on user3, with its JWT staying on the box.
   - If the app has no credential-free direct route to a non-local server, the live run waits for an owner session. Until then the hermetic shots are the gate.
   - **No liveprobe** while the owner's app may be connected. **No account** with two clients.
4. **The alpha server's build.** The live probe at c7501a19 (tree = the app's pin c7949cfd) held 17 steps and 1686 assertions on the alpha on 2026-10-16. The lead re-checks the running build before the live run.
5. **Order:**
   - F1/F2 first, then the list;
   - the list pauses for Task 6 when Task 2's dispositions land (R57).

## R60. The list's live run, and one more fit defect (2026-10-16)

- **State.** urnetwork/message-windows#7 MERGED (864354e1; its tree is badf2e2c's). S3 is open as message-windows#8 (a832482). F1/F2 is open as message-windows#9 (efdba5f7).
- **The live run may use CI's placeholder credential file.**
  - Its whole text is "ci-not-a-credential (the DIRECT route reads no credential)", set with `URMESSAGE_ROUTE=direct` (drive.ps1:120-154). The app needs a file to start (LiveMesh.cpp:1983-1999), but the library reads no JWT on DIRECT.
  - A build without the CI endpoint patch dials the compiled-in `wss://74.50.11.53/urmessage/v1` with its pin.
  - So no account and no JWT are involved, and no new route is added.
  - livepeer runs on the box on user3, started by the lead.
- **S5, found by W-app while proving F2:** the inspector rail's ADVANCED card clips the long conversation id and hides its "Conversation id" key. It is S3's shape: key column Star, value column Auto.
  - Fixed inside the list work, as its own commit, by S3's fit (the key whole, the value trimmed, the whole value in the tooltip and the automation name), with a `--diagnose` line and a control.

## R61. On the PC revision and Task 2's red team (workflow wf_d01ad488-cd0, 2026-10-16)

**Read:** PLAN.md (1,545 lines), SCOPE.md, FOR-OWNER.md, REDTEAM-TASK2.md (0 CRITICAL, 2 HIGH, 2 MEDIUM, 3 LOW).

- **Taken as planned:**
  - **X11:** no server part for the change; the backup steps are dropped; PC5's label waits for T2 in R.
  - **X12:** every leaf carries the chain of form-1 steps, at most 4 [a]. A fifth change needs Start over. FOR-OWNER now says so as a default; raising the cap is a spec edit.
  - **X13:** the self group moves in place; M5 wins over F1.
  - **X14:** one action on Settings → Account.
  - **P12:** 10 concepts. Login is absent in I1.
  - **P13:** the phrase change is slice 4, with its own session.
  - **P14:** the root stays, so "Your ID" stays. Its cost is stated.
  - **P15:** no device leaves its account holding a phrase secret.
  - The new authorities (f)P and (i), with all eleven columns, and MG-18.
- **Corrected by the lead: FOR-OWNER and the slice-4 report.**
  - "A change does not undo a leaked phrase" was itself false (budget class (ii)). By K5, once a device of yours has put the step into a conversation's tree, that tree takes no list of the old key and shuts a rival successor out. The device that makes the change does this at once, for its own conversations.
  - The copy now says three things:
    - a replaced phrase counts in a conversation until one of your devices in it has run since the change;
    - in a conversation none of your devices is in any more, it counts for good;
    - a change cannot undo a USE that the alarm reports, and Start over is the answer there.
  - SCOPE R3 and K5 already said this precisely, and are unchanged.
- **The one check of Task 2's dispositions (R53) is Task 1's subagent diff review.**
  - Its read-only reviewer reads REDTEAM-TASK2.md against PLAN's "Task 2 dispositions", and this ruling's corrections, before Task 1's commit. It reports each disposition as holding or not.
  - A disposition that does not hold comes to the lead. It never becomes a third round.
- **Start now:**
  - W-srv: Task 1, then Tasks 3, 4 and 5.
  - W-app: pause the list at a clean commit, then Task 6. Slice 0 adds the phrase-change screen (Task 45's), labelled demo, if its copy is settled in SCOPE K1 to K9.
  - W-lib: Task 8 now. Tasks 9 and 10 once Task 1's review holds.

## R62. On Task 1's filing and Task 8 (2026-10-16)

**Read:**
- W-srv's Task 1 report: `070c7393` on the fork's `plans/identity-phase1`, from `37dd710f`. Its review found 0 BLOCKER, 0 MAJOR, 9 MINOR and 10 NIT, and all 7 of Task 2's dispositions HOLD.
- W-lib's Task 8 report: `aacda6ea` on the fork's `identity/i1`, from `03192c2b`. The four entries are RED on `main` for their stated reasons, each with its control. alt-2 is green, and so is fork-ci 38897051890, whose four job logs each check out `aacda6e` [m].

**Task 1's review holds, so R61's one check is done.** The four findings it left for the lead are fixed in the sources:
- **D1:** PLAN's T2-H2 row now says what the owner's copy has said since R61. It no longer says "a change does not undo a leak".
- **D2:** Task 43's held case has one home, P15's single test `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret`, as Task 30 and the T2-H1 row already said. One promise has one enforcer.
  - `TestAChangeThatLostItsRaceIsRebuiltOrVoid` keeps the races, without the hold.
  - MI117 is killed by Task 43's case of the P15 test.
- **D15:** LR is R34 to R47, and LRI's head is fixed. REDTEAM-TASK2's line keeps its text, since it is the red team's record, and carries a lead's note.
- **D16:** PLAN's L3 row says that the phrase change is offered only where a change can help.
- W-srv files these as a second commit on the same branch, with its edit-log entry, before the plan's PR opens. The filed plan's legend drops its note of D1.

**D5: P2 had not reached the owner.** FOR-OWNER.md was never sent as a file, and the chat named only four of M8's five departures. The lead now sends FOR-OWNER.md and names P2 in the message: ending the account on its last computer erases the phrase's key and marks the account ended, and the rest of the old folder is not wiped. Task 1's M8 line is true from that message.

**Store kinds, as W-srv asked.**
- Task 3 freezes the kinds as Task 12 and P3 have them:
  - 11, the identity record;
  - 12, the heads, which hold the own-signature log;
  - 13, the phrase key.
- SCOPE C7's "kinds 11 and 12" for the heads was stale, and is corrected. F1's heads are one record (F1:603).

**Task 8 is accepted as reported.**
- **c2.** This tree has no list, so the removal control is the bare removal.
  - Task 26 signs the base that drops the phone before the removal, and PLAN Task 26 says so.
  - If it does not, R8-SIB refuses the control and the test fails as FAIL(HARNESS). The gap cannot pass in silence.
- **c4.** The bound-package control adds Carol's real key package, which Task 12 binds with no edit.
  - Task 12 adds the assertion that this package carries 0xF005 naming Carol.
  - Task 12 also gives the seam members bound leaves, since every group it founds requires 0xF005.
  - Task 13 builds the stranger's package without 0xF005 on purpose, and asserts so before the add.
  - PLAN Tasks 12 and 13 say so.
- **The three edits beyond the brief's letter are confirmed:**
  - the comment citations of MG-16 and MG-17, which the register's gate requires;
  - the owner lines of MG-11 and MG-12, by X4 and Step 3;
  - `roles_test.go`'s three lines, in which the seam member keeps its join seal's group_handle_key for `publishRotated`.
- MG-17, read from the code, and MG-16, whose reproduction is owed with Task 32, stand as filed.

**Start now:**
- **W-srv:** the second commit; then Task 3, pushed and reported at once; then Tasks 4 and 5, on a branch cut from the plan branch's head. Their PR opens once the plan's PR has merged.
- **W-lib:** Task 9 now.
  - Its two code points are already fixed by SCOPE and D2.
  - It commits only once Task 3's registry is pushed and its constants match the registry.
  - Task 10 starts when the registry is pushed, as P8 says.
- **The lead** opens the plan's PR after the second commit.

**Addendum, after the second filing (abb09c62).** Its review left two findings in the lead's text, and both are now fixed in the sources:
- **E1:** REDTEAM-TASK2's Subject line (:5) still read R33-R47 with no note. The patch matched only :134's form. It now carries the same lead's note.
- **E4:** PLAN's T2-H2 row quoted the owner's copy as "your devices refuse the old paper". The owner's copy says "your computers", and the slice-4 report says "your devices". The row now quotes each as it reads.

The plan's PR opens at abb09c62. W-srv refiles PLAN, REDTEAM-TASK2 and this file on specs/identity-phase1, as one small commit after Task 3's, with its edit-log entry.

## R63. On Task 3's registry (ledger item 299, `7741c70a` on specs/identity-phase1, 2026-10-16)

**Read:** W-srv's Task 3 report. The review found 26: 0 BLOCKER, 4 MAJOR, 13 MINOR and 9 NIT, all taken. MASTER grows from 3,682 to 4,021 lines, in 20 edits. The registry's values are as PLAN and D2 have them, with two changes from the review: kind 11 no longer holds the key number, and R's block of content kinds is now 0x38 to 0x3F. The commit touches MASTER and SPEC-LEDGER.md only [m].

**Revision 10, not an amendment to revision 9.** I1 changes rules that a revision-9 member cannot follow:
- every leaf carries 0xF005, and every group requires it;
- a device is added through the link box;
- what the server checks changes.

So MASTER's revision number says so.
- Tasks 4, 5 and 40 move their parent pins and baseline rows to revision 10. They edit those specs anyway.
- This answers item 141's question from here on. An edit that changes a rule is a new revision: a wire format, what a member or the server checks, or a guarantee that a user reads. An edit that only brings text into line with rules already in force is an amendment.
- The amendments already made stand as written.

**F15, R's block, stays 8 kinds, at 0x38 to 0x3F.**
- Round 4's numbers 0x2F, 0x30 and 0x33 to 0x36 stay unassigned. They are held for the phases that build their features: the server's delay, QR linking and history transfer.
- Each of those phases assigns or releases them in its own registry edit. Nothing else takes them meanwhile.
- If R's plan needs more than 8 kinds, it asks the lead, with D2 v2.1's count. That is before W-lib's Task 24.

**Start now:** W-lib checks Task 9's constants against item 299, commits Task 9, and starts Task 10. W-srv goes on to CI, then the E1 and E4 refile, then Tasks 4 and 5.

## R64. On Task 4 (Spec A A-36, ledger item 300, `c2b598a0`, 2026-10-16)

**Read:** W-srv's Task 4 report. The resumed reviewer found 28: 0 BLOCKER, 3 MAJOR, 7 MINOR and 18 NIT, all taken. The E1/E4 refile `7596be1d` holds.

- **SCOPE E2 is corrected (the review's F3).** It said that the server never reads the deposit. That is false of a server that finds the 60-bit link code.
  - Such a server holds card_key, answers Open with a card of its own, and is deposited to. It then reads that device's leaf before the emoji differ.
  - E2 now says this, and that the link grants nothing, since the emoji differ (E3).
  - MASTER §9.8 was corrected the same way in Task 4's commit, and Spec B states it in Task 5.
  - W-srv refiles SCOPE as a small commit with its edit-log entry. Task 5's review covers it.
- **Spec A §6 designs the seam's four methods ahead of the code:** NewBoundKeyPackage, CreateBoundGroup, CommitOwnLeaf (with patch, removeLeaves and contextExtensions) and LeafAt.
  - W-lib's Tasks 12, 13 and 42 transcribe them as §6 has them.
  - If code needs a different shape, the task amends §6 first, with a ledger entry, and never diverges silently.
- **Item 300 freezes, beyond item 299:**
  - the list's fourth label, URmessage/v1/device-amendment;
  - the link box's labels and sizes: a card of 4,124 octets and a deposit of 17,526;
  - the emoji label, URmessage/v1/link-sas-emoji;
  - the store's names: state/identity, state/identity-heads and state/phrase-key;
  - the 21 export names.

  The library's tasks read these from item 300.

## R65. On Tasks 9 and 10 (`d9ffec64` and `41699987` on identity/i1, 2026-10-16)

**Read:** W-lib's report.
- **Task 9:**
  - its constants match registry item 299;
  - alt-2 is green;
  - fork-ci 38920058374 is green on 4 legs, with the checkout proven;
  - MI2 to MI5 are killed, and the credential-follow probe sees its mechanism.
- **Task 10:**
  - alt-2 is green;
  - fork-ci 38932900121 is green on 4 legs;
  - MI6 to MI12 are killed;
  - the known answers were computed outside Go, with each outside primitive first reproducing its RFC vectors.

**The seven choices:**
1. **NFKD as a generated fold table, without golang.org/x/text: ACCEPTED in principle.** The generator is committed, so that the repository can rebuild the table.
   - It goes under `messagegroup/testdata/nfkdgen/`, with a go.mod of its own, which leaves the root module and its gates untouched.
   - The table's header names the generator's path and the Unicode version.
   - The independent review checks the table against a second NFKD, and names any code point where Unicode versions differ.
2. **The draw through `mls.NewCryptoProvider`: ACCEPTED.**
3. **The positions as a second result: ACCEPTED.**
4. **`WithPhraseKeys` erases IRK's seed before the ceremony runs: HELD for the review.**
   - IskCert(g) is signed by IRK (PLAN:148), and the phrase change's form-1 step needs a signature too.
   - W-lib answers, in its Task 11 report, how Tasks 12, 31, 32, 42 and 43 get those signatures under this contract: inside WithPhraseKeys before the erase, or by an argument.
   - The review holds that answer against Spec A A-36 §6 to §8 (`c2b598a0`). If the contract cannot serve those tasks, it changes now, before Task 12.
5. **The census in messagegroup: ACCEPTED.** PLAN's gate table is corrected at the next plan refile.
6. **The gate rows go to the review, row by row:** subject and scope, reason, control.
7. **The spellings the gates forced. The RULE from here on: no code is spelled around a gate.**
   - Where a gate's subject is not the code's subject, the code keeps its natural spelling. The gate gets a scoped exemption row with its reason and a control, as item 6's rows do.
   - `%16` for the UUIDv8 octets goes back to `& 0x0F`, with a row in record_test.go's reserved-spellings gate scoped to the UUID function.
   - The tokenizer's tables stay only if they are the better design, and the gate's comment says so. Otherwise they get the same treatment.
   - `.gitattributes`: ACCEPTED.
   - This retrofit comes with the review's fix commit. Task 11 follows the rule from its start.

**Task 11 starts now.** Its normative sources for formats and labels are items 299 and 300 and Spec A A-36 (`c2b598a0`), with R64's note on §6's seam methods. The review of Tasks 8 to 10 runs alongside it, read-only, in its own clones.

## R66. On Task 5 and the server's open items (`ee92954e` on specs/identity-phase1, 2026-10-16)

**Read:** W-srv's report on Tasks 3 to 5 and the three refiles. There are six commits, `7741c70a` to `ee92954e`, and every one has gates.yml and fork-ci green, with the checkout proven. The reviews found:
- Task 3: 26;
- Task 4: 28;
- Task 5: 24 (0 BLOCKER, 3 MAJOR, 9 MINOR, 12 NIT);
- the R65 refile: 3 NIT.

All of them were taken, with no BLOCKER anywhere.

**PLAN is amended, each change marked R66:**
- **Task 19 gains Property 6:** no rendezvous kind but 4 is served, and no kind-4 arm is served while the reject floor is zero. This is Spec B's test 51, which W-srv wrote in Task 5. Its mutants are MR11 and MR12, and its test is `TestOnlyKindFourIsServedAndNothingWithAZeroFloor`. Slice 2 now holds 40 mutants, and the plan 143.
- **Task 20's deploy note** says that the deploy sets `reject_floor_ms`, since its default of 0 serves no kind-4 arm.
- **The gate table** puts the phrase-secret census in `messagegroup` (R65 item 5). A task that holds a phrase secret in `sdk/urmessage` adds that package's row.

**W-srv's small commit now, on specs/identity-phase1, before the specs PR opens:**
- Spec A's two owed notes, from Task 5's review F9 and F10: the kind-4 note on §12.1's out-table row A-18, and ruling 27's seven names in its A-1 block.
- Spec B's line 25 named a local user folder, from its first revision. It is neutralized in the current text. The history stays as it is, with no rewrite.
- The filed SCOPE's legend: it names R64 among the rulings that came after.
- The refile of PLAN and LRI at their hashes when committed.

**Left where it belongs:** the wrong section cite, §4.3.7 where it should be §4.3.11, at `cmd/message-server/config.go:282`, and in the setting notes at :176 and :179 (the R66 review's L1). Task 19 edits those lines.

**Order:**
- W-lib does Task 7, the proto, right after Task 11's commit, and before Task 12. Task 18 consumes Task 7's commit once it is pushed.
- W-srv may start Task 18's storage now, tests first, but commits the pin first, the day Task 7 is pushed.
- The specs PR opens once message-server#12 merges.

**Addendum, on W-srv's note.**
- Two count lines still gave the server 10 mutants. They now say 12, and the plan 143 (PLAN:1395 and :1488).
- MR11 now drops the kind check itself, so kind 0 (the proto's default, the likeliest slip) is served as well as kinds 1 to 3. This matches item 301's Open and Spec B's test 51.

## R67. The list's live run, restated, and where livepeer runs (2026-10-16)

**Read:** W-app's checkpoint. Task 6b is complete except its live run (`feat/conversation-list` at `50f17eac`). It asked for a ruling on holding two client JWTs as fork Actions secrets.

- **No.** No JWT goes into GitHub, as a secret or otherwise (R59, R60). Nothing in this run needs one.
- **Both parties run on the runner, by the DIRECT route, with no account.**
  - The app, as R60 says: the placeholder credential file, `URMESSAGE_ROUTE=direct`, and no CI endpoint patch. It dials the compiled-in alpha endpoint with its pin.
  - livepeer, built from the library at the app's own pin, with `-route direct -endpoint wss://74.50.11.53/urmessage/v1 -pin <the app's compiled pin>`. It has a state folder of its own on the runner.
  - The rig relays the join codes and invitations between the two on the runner, both roads: livepeer founds and the app joins; the app founds and livepeer `-join`s.
  - Nothing runs on the box, and nothing is staged there. This replaces R60's "livepeer runs on the box on user3, started by the lead", which would have needed the lead to relay codes by hand.
- **The alpha's build:**
  - The alpha runs message-server `20c035a1`, the T1 protocol. liveprobe at `c7501a19` (T1's tree, `c7949cfd`) held there on 2026-10-16.
  - The app's pin must be T1's tree, or a descendant whose protocol packages are unchanged. The rig checks this before the run and prints it.
- **Load and privacy:** the alpha is semi-exposed by the owner's word and is wiped before beta. The run's groups are throwaway. The rig's logs print digests, never codes or invitations in full.
- **Then, inside the list:**
  - each conversation draws its own receive errors;
  - a removed conversation's bubble and roster controls say it was removed, not "no live session".
- **The list still lands with R (P11).** Its PR is not opened now, and no I1 build carries it.

## R68. On the independent review of Tasks 8 to 10 (`41699987`; workflow wf_74eb03fb-ece, 2026-10-16)

**Read:** three read-only lenses (crypto and known answers; gates, tests and mutants; spec fidelity and the forward API), each with an adversarial verifier. Every finding above NIT was CONFIRMED, and none was refuted.

- **No BLOCKER.**
  - All 56 known answers were recomputed from the sources' text, with an implementation independent of the writer's: an Argon2id written from RFC 9106, an HKDF over crypto/hmac, and crypto/ed25519. Each reproduces its RFC vectors.
  - The word list is canonical BIP-39 English.
  - The NFKD fold agrees with a second NFKD over the whole parse pipeline, except U+A7F1. Unicode 17.0 added that code point, and the table is at 17.0.0.
- **Findings:**
  - **MAJOR:** L3-1, L1-1, L2-01 and L2-02.
  - **MINOR:** L1-2 (with L3-6), L1-3 (with L3-2), L1-4, L2-03 to L2-12, L3-4 and L3-5.
  - **NIT:** L1-5, L1-6, L2-13 to L2-15, L3-3 and L3-7 to L3-10.
  - The full text is in `identity-phase1/review-t8-t10/FINDINGS.md`.
- **A note on process.** The lead checked out `ee92954e` in the review's local clone of `urnetwork/message-server` during the review, to read Spec B's line 25. Lens 1 saw the move, and re-verified every server-side claim against `c2b598a0` with git show. Nothing was affected. From now on, review clones are not touched while a review runs.

**R65 item 4 is answered: the contract serves every task, once messagegroup signs.**
- R65's premise was wrong. IRK's whole private key is present inside `keys.irk` for the length of the ceremony. Only a separate seed buffer is erased before it.
- What is missing is a way to sign without handing a private half out. So messagegroup gains signing methods on `*PhraseKeys`:
  - IRK over a labelled IskCert preimage;
  - IRK over the form-1 step's preimage;
  - ISK_g over a base;
  - D2 IL8's derivation.
- Each takes and returns public values only, with its known answer. No private half leaves the package.
- `WithPhraseKeys` takes the SET of key numbers it derives in one stretch, so a lock-out costs one Argon2id stretch, not two (L3-3).

**W-lib's fix round, before Task 12.** One or more commits, each with its tests and controls:
1. **L3-1 (MAJOR).** `CreateCommit` validates the committer's own path leaf before staging, at least whenever `OwnLeafPatch` is set. It uses the effective context after the proposals, as the inbound path does. A patched leaf that every receiver refuses is refused at home, with nothing staged. The test carries the reviewer's three refusal cases.
2. **The census (L1-1, L2-01, L2-02, L2-05, L2-06).**
   - The walk follows tainted arguments into package-local callees.
   - A sink holds its occurrences, not only its key and the union of what it carries, asserted both ways.
   - A map key and a keyed literal's key are carried values.
   - `phraseFoldOf` and `phrasePublicHalf` are walked.
   - The census's mutation table exists: the pq census's mechanism rows, driven at the phrase's secrets, plus the reviewers' mutants. Each row names its failure text.
   - The engine is one engine. The pq census in `sdk/urmessage` gets the same fixes, and a test holds the two copies identical, apart from their two named renames.
3. **The signing methods and the key-number set,** as above.
4. **L1-4.** `*RecoveryPhrase` and `*PhraseKeys` format as a fixed redaction under `%v`, `%+v`, `%#v` and `%s`, with a test that no octet of a secret is printed.
5. **L2-03.** The frozen stretch parameters are unwritable by construction: a function returning the literal, or typed constants.
6. **R65 item 7, applied (L2-07, L2-08, L2-09).**
   - The UUID's `& 0x0F` comes back, with a reviewed-context row in `message/record_test.go` scoped to `accountIdOfHash`, matched by its whole AST. The hex uses the natural spelling, or `encoding/hex` with its import row.
   - The tokenizer and the list pin use their natural spellings, with a row scoped to `phrase.go`'s functions in `mls/framing_guard_test.go`, with the gate's own reason. The tables buy no constant time.
   - The crypto/rand ban's reason names its one exception, `NewRecoveryPhrase`. A gate holds messagegroup's process-entropy draws to exactly that one.
7. **The NFKD table (R65 item 1, L2-10).** The generator is committed under `messagegroup/testdata/nfkdgen/`, with a go.mod of its own. A step in test.sh and fork-ci regenerates the table and diffs it, or the table's SHA-256 sits in its header and is checked.
8. **The smaller items:**
   - L2-04: the ladder gate's comment says what it holds.
   - L2-11: the Update fixture is out of type order, and M4 is recorded.
   - L1-6: "clear", not "drop", and the callers clear.
   - L2-13, L2-14 and L2-15: the notes.
   - L3-10: an exported single-word check over the same fold, which Task 14 consumes.
9. **Then:** alt-2's full test.sh and fork-ci, with the checkout proven.

**PLAN is amended, marked R68:**
- Task 10's Property 1 says "refused exactly when the checksum fails, about 255 times in 256" (L3-9).
- Task 12 gains three duties:
  - the mls accessor for a staged leaf's signature key and extensions (L3-5);
  - the engine's capabilities naming 0xF005 and 0xF006 before any bound key package (L3-8);
  - the phrase-secret census of `sdk/urmessage`, whose net is `PhraseKeySeed`, `RecoveryPhrase`, the ceremonies and the kind-13 record (L3-4).
- Task 14 consumes the single-word check (L3-10).
- Task 26's scene links pc2 through the link box and brings it in by fan-out (L2-12).
- The gate table and the promise table follow.

**W-srv's spec amendment on specs/identity-phase1** (L1-2, L3-6, L1-5, L3-7):
- Spec A §8 states the in-memory residual of phrase secrets with its measured scope. The words, S, master_key, isk_root and IRK's private half can survive in freed heap, in Argon2id's working memory and in hash and HMAC states, even after GC.
- MASTER §5.2's unqualified "erased" points to that statement.
- MASTER §5.1 and Spec A §7.2 name the fold as NFKD at Unicode 17.0.0, held to the toolchain's `unicode.Version`, with white space as Unicode's White_Space property.

**F2 of the R66 commit's review, ruled during that commit (recorded here for the ledger to cite).**
- The stale A-1 comments are fixed in R66's commit, in both copies together, against the library code the server pins. They are not carried.
- ErrEpochKeysDigestPresence LEAVES both blocks, by the block's own rule A-9: only the unpublished NewEpochDigestAttachment returns it (attachment.go:485-489).
- The same correction reaches Spec A §5.11's door sentence (:2376), with a note saying what it read. The stale-peer paragraphs, Spec A §5.11 (:2363-2372) and Spec B §5.4 (:2849-2856), keep their text and gain a dating note with the test's current name.
- `api/epochkeys.go:18-25`'s comment is carried to Task 19, the next commit that touches api/.

## R69. The server pins the library's fork through siblings.sh's own exception (2026-10-16)

**Read:** W-srv's note on Task 18's pin.
- Task 7's commit, `e8eaad66`, exists only on Ryanmello07/urmessage.
- `scripts/siblings.sh` refuses every fetch source outside urnetwork, except forks listed by exact URL in its `review_sources`. It lists none today, and its self-test asserts that the urmessage fork is refused.

**Ruled: use the script's documented procedure ("To use the list again", siblings.sh:38-53).** This is the gate's own designed exception, not a spelling around it (R65 item 7). The pin commit:
1. adds exactly `https://github.com/Ryanmello07/urmessage.git` to `review_sources`, so that every mode prints FORK beside that pin;
2. moves the self-test's urmessage case from "refused" to "listed". The listed loop then holds that exact URL accepted, and its spelling without `.git` refused. Every other variant stays refused: the connect fork, other owners, path tricks and http;
3. sets siblings.txt's message line to that URL at `e8eaad66`, with its comment.

**Conditions:**
- The server branch's PR may open while the pin is a fork. It says, in its first line, that it merges only after I1's library PR has merged.
- Before it is ready, a commit moves the line back to urnetwork at the merged commit and deletes the review source, as the script says.
- No other source is ever added this way without a ruling.

## R70. The rendezvous verifiers: a gap no task filled (2026-10-16)

**Read:** W-srv's blocker on Task 19, checked by grep and by the fork's contents listing.
- Spec A §12.1 and Spec B §12.1 name the A-1 rendezvous surface: the registration and collect types, the preimages, the five verifiers, `RendezvousId`, `DepositVerifyKey` and the two sizes.
- None of it exists in `message`, at `e8eaad66` or on main.
- Task 7 is the proto only, and Task 21 is the client. A-1 forbids the server building a preimage, and `api` may not reach crypto or encoding, so it cannot hash either.

**Ruled:**
- **(a) Task 7b is NEW (W-lib):** `message`'s rendezvous preimages and verifiers, exactly the A-1 surface in kind 4's form.
  - It has two properties, and mutants MI122 and MI123.
  - It runs after W-lib's R68 fix round, and before Task 12. It is small, and the server's verify step waits on it. Slice 1's own path does not.
  - PLAN gains the task, and the counts move to 46 tasks and 145 mutants.
- **(b) W-srv builds everything in Tasks 19 and 20 that does not verify:**
  - the config keys;
  - Capabilities 26 and 29, leaving kind 4 out while it is unserved;
  - the LinkBoxes field, with its holder tests, and a nil LinkBoxes failing closed;
  - the cap, failing closed; the kind check; the floor; the one answer; the logging gate;
  - the five routes, with every arm answered as unserved until the verifiers are pinned, and the readiness naming why;
  - the cites and the stale comment;
  - Task 20's sweep.

  The verify step lands in a commit of its own once Task 7b is pinned, with MR6, Open without `open_auth`, killed then.
- **(c) Task 18 is adjusted:** the store computes `deposit_hash` from `deposit_ct` as Spec A §5.14 defines it, and returns it. The Deposit response carries it.
- **The fork pin moves** to Task 7b's commit, by R69's procedure, in a commit of its own.

**Addendum: the shape of an unserved link box (W-srv's proposal, taken).**
- The arms are served only when LinkBoxes is wired, the verifier is wired and `reject_floor_ms` is above zero.
- If any of the three is missing:
  - the peer does not route the five arms, which `peer.unservedArms` then derives and answers with REASON_INTERNAL;
  - a handler method called directly answers REASON_INTERNAL with no store call;
  - `api.NotBuilt` names what is missing;
  - Capabilities 26 and 29 leave kind 4 out.
- This replaces the lead's first idea, which was "answer as an unknown box". That idea fights Spec B §4.3.11 ("as every unserved arm is answered") and the nil-Subscriptions precedent. It would also hide the gap from /readyz, and a server with no store would look alive and empty.
- **Control:** the same request answers REASON_INTERNAL with nil LinkBoxes and no store call, and CARD_RETIRED with an empty LinkBoxes.
- The cap's fail-closed case stays as planned: CARD_RATE_LIMITED on a read error (MR8).
- §5.14's H is SHA-256 (Spec A:8, MASTER:11), so (c) holds.

## R71. On the list's live run, and W-app's next work while #8 and #9 wait (2026-10-16)

**Read:** W-app's report. The R67 live run, with both parties on one runner, the DIRECT route and no account, passed twice with 106 checks and 0 failures (38949957455 at `50f17eac`; 38955292704 at `cba38d14`). The library pin was checked and printed as T1's `c7949cfd`. Codes and invitations went through files, and the logs printed digests only. Proven, with shots:
- the founder road and the join road;
- a join beside open conversations;
- sending in every conversation, both ways;
- two live conversations beside a notice row;
- a leave;
- a restart that restores both.

livepeer cannot remove a member, so the removed conversation is proven by the hermetic legs only. The two R67 fixes are in (`4fa5e91b`, `cba38d14`), with their diagnose lines, mutants and the new listerr leg, whose control fails exactly the fix checks.

**Rulings:**
- **The receive report drawn in a conversation** keeps the library's own sentence. It never draws an absolute path under the user's profile: the drawn text shows the store's root as "the app's data folder", and the log keeps the full sentence. This comes with its diagnose line and a control, as one small commit on the list.
- **One livepeer at a time** was more caution than the rule asks. With no account in the run, there is nothing to collide, so several peers may run at once on the runner, each with its own state folder. No re-run is needed.
- **The owner's leave refused** (ErrOwnerMustTransfer) is the library's rule, and is correct. A test of the owner's road waits for a transfer, which belongs to R.
- **While #8 and #9 wait, W-app ports urnetwork/windows#12 to message-windows:** the icon font falls back to Segoe MDL2 Assets wherever the app names Segoe Fluent Icons. Today the app names Segoe Fluent Icons alone (App.xaml's `UrIconFontFamily`, and four sources), so every icon is an empty box on Windows 10 and on Server 2022, as the runners' shots show.
  - It is a small PR from main: `fix/icon-fallback`.
  - It gets a diagnose line naming every glyph code point the app uses and the family it resolves to.
  - Its shots on windows-2022 (no Fluent font) show icons drawn, and windows-2025's are unchanged.
  - The lead opens it after one read-only review.

## R72. On W-lib's Tasks 11, 7 and 7b and the R68 fix round (head `9cac060b`, 2026-10-16)

**Read:** W-lib's final report. Every commit was pushed to the fork, with alt-2's test.sh and fork-ci green and the checkout proven:
- Task 11 `db348392` (fork-ci 38945873384);
- Task 7 `e8eaad66` (38946856356);
- the R68 round: `73f09fcd`, `32555865`, `51815a7b`, `51bc1a0c` (38962389303) and `a6ea6f3e`;
- Task 7b `9cac060b` (38977073547).

Every planned mutant was killed. R68's census mutation table kills every row except V5b, which survives by design and is killed by four known-answer tests. The two census engines are held identical by a test.

**R65 item 4 is closed.** messagegroup signs, and no private half leaves it. The methods are SignIskCert, SignIdentityStep, SignBase and SignBaseAuthor, DeriveIdentityKeyed, PhraseKey, PhraseKeySeed and KeyNumbers. WithPhraseKeys takes the set of key numbers.

**Task 7b's five decisions:**
1. Only kind 4's form is built: CONFIRMED.
2. RendezvousDepositBytes is left out: CONFIRMED, since kind 0 is not served.
3. The sizes, alg_id and card_xwing_pub are the server's checks (Spec B §4.3.11): CONFIRMED. W-srv is told.
4. AlgId is a u16, and the server refuses any alg_id above 0xFFFF and never truncates: CONFIRMED. W-srv is told, with a mutant.
5. **Small-order keys are REFUSED.** The five rendezvous verifiers refuse a small-order public key, as identityVerify already does.
   - Without the check, Go accepts R = identity, S = 0 under such a key, so a box registered with one could be collected or retired by anyone.
   - Only the registrant chooses that key, but the library's own rule already refuses these keys, and the check costs one call.
   - It is a small commit before Task 12, with mutant MI124 (the check dropped, killed by a verifier test with an identity-point key).
   - W-srv pins that commit rather than 9cac060b.
   - Spec A §5.14 gains the sentence at the next specs-branch commit.

**Also ruled:**
- **vulncheck's rows:** a test holds every go.mod in the repository to a row in scripts/vulncheck.sh, with a control. test.sh then catches what alt-2 caught (a6ea6f3e). It goes in the same small commit.
- **Tasks 31 and 33** add the stored-seed signer that a phrase device without its words needs: ISK_g from the kind-13 record's PhraseKeySeed(g), inside messagegroup, with no private half out. PLAN's Tasks 31 and 33 carry this at the next refile.
- **The R68 commits get no separate delta review.** They are reviewed with slice 1's library review, after Task 14, and their mutation evidence stands until then.
- **Task 12 starts after the small commit,** with R64 (Spec A §6's seam methods, transcribed) and R68's three additions: the mls staged-leaf accessor, the engine's capabilities naming 0xF005 and 0xF006, and the sdk/urmessage phrase-secret census.
- **Memory pressure:** the machine reaped an ssh session and crashed one compile while three writers ran heavy builds. W-lib's mutants now run two at a time. Each writer keeps its parallel jobs modest.

## R73. On Tasks 19 and 20 without the verify step (`85abf77c` and `1bff5904` on identity/i1-srv, 2026-10-16)

**Read:** W-srv's report. Both commits are on the fork, with gates.yml and fork-ci green and the checkout proven (38978403508 and 38978406044; 38980524727 and 38980525514).
- MR4, MR5, MR7 to MR12 and MR10 are killed, plus guards beside them. MR6 waits for the verify step.
- R70's unserved shape is built, with its control.
- The store computes deposit_hash.
- W-srv stopped at the pin as R72 asked, and reverted its uncommitted pin of 9cac060b.

**Rulings:**
- **Tests first was skipped** in both tasks. The code came first, then the tests were shown failing against stubbed arms (Task 19), or not at all (Task 20). The mutant kills are evidence that the tests bite, so both commits are ACCEPTED. The plan's order stands for the verify step and after: tests first, seen failing for their stated reasons.
- **Small-order keys at Register (W-srv's question): REFUSED.** W-lib exports the library's small-order predicate in its R72 commit. Check 3 calls it, so a small-order collect key or deposit key is refused at Register (REJECTED), and no unusable box is stored. A mutant drops the call.
- **The sweep's three departures from Spec B §7.4 are ACCEPTED:**
  - the advisory lock is the two-key form, scoped to the schema, so that two deployments in one database, or the suite's parallel schemas, do not skip each other;
  - `now` comes from the caller, like every LinkBoxes method;
  - PostgreSQL may abort one of a recount and a Collect still running at a box's expiry, and either retry is harmless.

  Spec B §7.4 states all three at the next specs-branch commit.
- **Not built and not planned:** §7.4's gauges and counter, since the metrics package has no code, and `messagectl sweep-now`. They are carried as a residual to the server's later phases, and are not in I1.
- **The deploy note is RECEIVED, and nothing is deployed.**
  - The deploy goes with slice 2's owner session, and the lead tells the owner first (R55).
  - It is message-server and messagectl from the verify commit: Go 1.27.2, linux/amd64, CGO_ENABLED=0.
  - The migrations are 013 and 014. The alpha's database is wiped, then `messagectl migrate` runs.
  - `reject_floor_ms` is set from the slowest refusal path, measured on the box.
  - What changes beyond the link box, and the owner hears all of it:
    - every merged refusal of Submit, CreateGroup, Fetch, Subscribe and the five arms is padded to the floor (corrected by R78: Unsubscribe, REASON_INTERNAL and the peer's own refusals are not);
    - the sweep job runs;
    - there are two new keys with defaults;
    - Capabilities and readiness gain kind 4.
- **The verify step** waits for W-lib's R72 commit:
  - check 7 on all five arms through the library's verifiers only;
  - alg_id held to 0x0014 as the u32;
  - the small-order check at Register;
  - the signed tests in cmd/message-server/linkbox_test.go, since api's second-implementation gate bars signing in api;
  - a static gate: each arm calls its own verifier once, before any write, and never a preimage builder;
  - MR6 killed.

  Then the lead runs the server's slice review of Tasks 18 to 20.
- **Memory:** WindowsTerminal held about 61.5 GB of committed memory while the writers ran, and two parallel suites failed to allocate. The writers run one package at a time while that lasts. The lead tells the owner.

## R74. On the specs commit `4b055342` (Spec A A-38, Spec B revision 27, the refile; 2026-10-17)

**Read:** W-srv's report. gates.yml 38988379780 and fork-ci 38988380132 are green, with the checkout proven. Its review found 15: 0 BLOCKER, 1 MAJOR, 7 MINOR and 7 NIT. All were taken but F1, F14 and F15.

- **F1 (MAJOR, in the lead's text):** R72's stored-seed signer was not in PLAN. It now is, in Task 31's Produces, and Task 33 builds it if Task 31 has not. The next refile carries it.
- **F6: CONFIRMED.** Spec B §7.4's departure names "a Collect or a Retire". Both lock the box and then delete its deposits, which is the reverse of the sweep's order.
- **F14:** Spec A §2's "nine" functions in rendezvous.go, where A-1 lists twelve, is fixed at the next specs-branch commit.
- **RendezvousDepositBytes:** both A-1 blocks list it, but the library leaves it out while kind 0 is not served (R72, decision 2). The next specs-branch commit marks it in both blocks as "exported when kind 0 is served". The block and the library then agree.
- **F15:** api/second_implementation_test.go's "an export beyond A-1's block" is stale since A-38. It is a one-line fix in identity/i1-srv's next commit, which is the slice review's fix round.

## R75. On the server's slice review of Tasks 18 to 20 (`e57ab8ff..0864540c`; workflow wf_f2e98edb-32d, 2026-10-17)

**Read:** three read-only lenses (security and protocol; storage and sweep; tests, gates and wiring), each with an adversarial verifier. Every finding above NIT was CONFIRMED. The full text is in `identity-phase1/review-srv-t18-t20/FINDINGS.md`.

**No BLOCKER.**
- No forged or unauthorized act succeeds, no box can be enumerated, and nothing leaks through the arms.
- 013 and 014 are byte-identical to §3.2.
- The two stores agree on every edge case.
- Every CI run checked out its commit, with FULL RUN 2 of 2.
- MR6 and the dropped small-order call die for their stated reasons, and compile.

**The fix round, before the server PR.** W-srv, on identity/i1-srv. Tests first, each seen failing for its reason, with a mutant where one is named.

**MAJOR:**
1. **T1 and T2: Collect's check 7 must be impossible to skip, and seen to be.**
   - Behavioural cases: every unauthorized request on every arm, with Collect sent both with and without subscribe, against a live box that holds a deposit and a refused third. Each must give the one answer and change nothing; then the holder's own Collect still returns the deposit and the refusal count.
   - The static gate: each arm's verifier `if` is a top-level statement of its body, before any store call, and store receivers are resolved by type (go/types), so that an alias or a parameter is still a write.
   - Mutants: BRANCH-COLLECT and ALIAS-COLLECT, the reviewer's own. Both must die.
2. **T3: the pad holds no worker.**
   - A padded refusal returns at once with a not-before time, and the peer sends its answer from a timer, off the worker pool.
   - A test: eight or more concurrent padded refusals must not delay an unrelated request beyond a stated bound. The mutant that sleeps on the worker must die.
   - Spec B §4.5 says so at the next specs commit.
   - Until this lands, the deploy note states the cost: 8 ÷ floor refusals per second occupy every worker, and check 4 is not built.

**MINOR:**
- **S-1:** rendezvous subscriptions are capped per connection, refused rather than evicted, and indexed by box, so that a deposit or a retire touches only its box's subscribers.
- **D1:** the sweep logs an error class (the SQLSTATE, `connect` or `canceled`) and the totals, never `err.Error()`. The sweep's logger joins the logging gate, with a control.
- **D2 and T9:** newServer gets a seam for the sweep's interval or ticks. A test sees an expired box reclaimed by a tick, without calling Pass, and sees Close stop the job before the pool.
- **T4:** the time envelope. A clock advanced inside Q17 shows each refusal sleeping exactly floor − d, in cmd's tests and in api's.
- **T5:** a round trip through the arms asserts every response field: Collect's deposits, pending and complete; Open's alg_id, deposit_bytes and deposit_sizes; Register's mailbox_depth; and Retire's discarded_deposits.
- **T6:** link_box_ttl_seconds and link_box_live_cap are held to the handler newServer builds, set to values other than the defaults.

**NIT, all taken:**
- S-2: a replayed deposit pushes nothing.
- S-3 and D4: the cap is checked on every insert, with a conditional insert.
- S-4: ON CONFLICT on the deposit insert, per §11.2 item 4.
- S-5: pad overruns are named in NotBuilt until metrics exist.
- D3: what check 7 verified is passed to the write, and a differing locked row answers CARD_RETIRED.
- D6: a test holds 013 and 014 to §3.2's text, with a one-octet control, until they land.
- T8: `<= 0` in the three predicates, and a negative floor refused at load and in api.New.
- T10: the ops guide gains the three keys, the floor's role and cost, and the sweep.
- T11: the readiness line is reworded.
- T7: the deploy note says exactly which refusals are padded. Every merged refusal of Submit, CreateGroup, Fetch, Subscribe and the five arms is padded. Unsubscribe, REASON_INTERNAL and the peer's own refusals are not.
- F15: the stale "beyond A-1's block" comment.

D5 is already done (R74, F6).

**Then:**
- gates.yml and fork-ci, with the checkout proven;
- the mutants, two-phase;
- a report.
- One delta review of the fix round, by the lead.

**After that, one specs-branch commit carries:**
- R74's two items: the "nine" count, and RendezvousDepositBytes marked;
- §4.5's worker-free pad;
- §11.1's logging of the sweep's error class.

## R76. On Task 12 (`4f6af691`, `f496242`, `0fcc6ee` on identity/i1, 2026-10-18)

**Read:** W-lib's report. The head is `0fcc6ee`.
- alt-2's test.sh and vulncheck are green, and fork-ci 39092700178 is green on all four legs, with the checkout proven.
- 22 mutants are KILLED, among them MH1 and MH2, which survived the suite at 4f6af691 until W-lib's own extra test.
- R64's seam methods are transcribed, and R68's three additions and R62's forward costs are in.
- The red windows leg of the first two runs was a missing C declaration, fixed in 0fcc6ee.

**The ten decisions:**
1. ConfirmWords needs a connection: CONFIRMED.
2. No re-founding of a missing self group: OVERRULED, fixed now.
   - A device that dies between writing its identity records and founding its self group must not stay broken. The owner's session 1 includes a restart.
   - At start, a device whose identity records exist and whose self group record does not founds the self group again. That needs the device key and the root, not the words.
   - A test stops the setup between the records and the founding, and checks a restart repairs it. Its mutant drops the repair.
3. The self group's record is written at founding with Opened=false: CONFIRMED.
4. Device holds its signing key, erased at Close: CONFIRMED.
5. The unbound CreateGroup door requires 0xF005: CONFIRMED.
6. PutDeviceIdentity refuses to mint a device key beside existing identity records: CONFIRMED.
7. Gate rows: to slice 1's library review.
8. The loopback-only export: CONFIRMED until Task 14, which removes it, with a gate that it is gone.
9. The seam member's next base, an empty PrevHash, and the stranger bound now: CONFIRMED.
10. Test time: test identities use the seam's fast stretch.
    - The exceptions are the tests that hold the frozen parameters (the known answers and the production-path gate).
    - The gate that production reads only the frozen parameters stays, and is checked to still fire.
    - Each Argon2id at 256 MiB costs time, and memory this machine lacks.

**Order:**
- one small commit for items 2 and 10, with alt-2 and fork-ci;
- then Task 13.

## R77. On the R75 fix round (`9feb19dc` on identity/i1-srv, 2026-10-18)

**Read:** W-srv's report. gates.yml 39098638413 and fork-ci 39098641667 are green at 9feb19dc, with FULL RUN 2 of 2.
- Every R75 finding is answered.
- T3's pad now holds no worker: an Api Deferral, sent by the peer's timer, with at most 1,024 waiting.
- 35 mutants are killed, among them BRANCH-COLLECT, ALIAS-COLLECT and SLEEP-ON-WORKER.

One delta review of 0864540c..9feb19dc runs now, as a single read-only agent. Ultracode is off.

**The specs-branch commit carries:**
- R74's two items;
- §4.5's worker-free pad;
- §11.1's sweep logging of the error class only;
- the four lines W-srv found outside R75's list:
  - Collect's bound of 32 subscriptions, and its CARD_RATE_LIMITED answer;
  - a replayed deposit pushes nothing;
  - Q20's cap checked inside the insert;
  - the write is handed the key that check 7 verified.

**Residuals, seen and not changed, to a later server phase:**
- epochstale_test.go's Store holder gate still matches by name;
- the group path's published() scans every subscription;
- a re-Hello's old rendezvous subscriptions last until their box expires.

## R78. On the delta review of the R75 round (`0864540c..9feb19dc`, 2026-10-18)

**Read:** one read-only reviewer.
- It found no BLOCKER and no MAJOR, and all 22 earlier findings and F15 are FIXED.
- BRANCH-COLLECT, ALIAS-COLLECT and SLEEP-ON-WORKER build, and each dies for its stated reason.
- Every package reproduced its counts locally, store and cmd included, against PostgreSQL.
- Its six new findings are in `identity-phase1/review-srv-delta/`.

**One last small commit on identity/i1-srv, all six taken:**
- **N1 (MINOR):** a cmd test over a peer with a small MaxDeferredAnswers. More concurrent padded refusals than slots, each answered no sooner than the floor. BOUND-CUTS-FLOOR and UNBOUNDED must die.
- **N2:** Collect's undo removes only the subscription that call added, compared by pointer as deliverRendezvous does. Test it with a failing write, with UNDO-DROPPED as the mutant.
- **N3:** a standing subscription record is replaced only when its expiry is earlier than the request's box. A later expiry means the request's own box is gone, so nothing is subscribed. Add the test from the reviewer's probe.
- **N4:** the gates widen:
  - function literals in package-level declarations count as outside every arm;
  - any link box value handed off outside a receiver counts (composite literals, package variables, sends);
  - a \*Subscriptions field selection outside its two files counts as a registry change.

  The behavioural test keeps the holder subscribed, and asserts its push. PKGVAR-COLLECT, STRUCT-HANDOFF and FIELD-REGISTRY-2 must die.
- **N5:** parked answers are bounded by BYTES as well as by count. Past the byte budget, a worker waits, exactly as past 1,024. The comment is corrected. The beta must not hold ~67 MB for clients that read nothing.
- **N6:** the health listener logs an error class, not the error text with its address, and logging_test.go holds the line.

Then CI with the checkout proven, and the mutants two-phase. The lead checks the result from the CI evidence and the mutant logs, and runs no further full review.

The server PR still opens only beside the library's slice-1 PR (R69).

## R79. On the R76 commit and Task 13 (`09b645a` and `e2fa865` on identity/i1, 2026-10-18)

**Read:** W-lib's report. Both commits are on the fork, each with alt-2's test.sh and vulncheck green and fork-ci green with the checkout proven (39096381969 and 39103062463).
- **R76:** a missing self group is founded again at start (MD1 and MD2 killed). Test identities use the fast stretch, and the production gates still fire (MF1 to MF6 killed). sdk/urmessage is back from about 190 s to 67 s.
- **Task 13:** R6e, R6c-sig, R8-EQ, R8-CUR and R9, with their sentinels; the doors; the heads; the send side's post-commit leaf.
  - The three scenarios are registered closed, and I1-unbound-key-package-admitted flips. Each was RED on 09b645a with 0 production lines changed.
  - 18 mutants are killed. MI31 survived once, because its control hid the rollback; the control was moved and MI31 now dies for its reason.

**The eight decisions are CONFIRMED,** with notes:
1. A profile-1 leaf is F1's shape.
2. The Add door's order is confirmed, with the relabelled refusal.
3. The Join door's two extra acts, and Restore reading a tree as the Join door does, are confirmed. The two new refusals are permanent.
4. The heads rise at restore, at join and at epoch entry.
5. The 11th leaf is refused by R6e.
6. The cp3b harness's reflection and unsafe are confirmed for TESTS ONLY, as liveGroupOf already does, and slice 1's review holds that no production file uses them. The forking-server hook and the siblings' base numbers are confirmed.
7. Tests first was not shown against a stub. The mutants and the 09b645a red runs stand in for it, and are accepted. Tests first holds again from Task 14.
8. The cost is about 31% of urmessage's CPU in Ed25519, with F1's cache by body hash not built. It is ACCEPTED for I1, and carried as a residual to build before the beta: the cache, keyed by the 0xF005 body's hash, with a test that a cached verdict is never trusted across a different body.

**Task 14 starts now,** as PLAN says, with:
- R76 item 8: the loopback-only export `urnet_message_loopback_device_identify` is REMOVED, and a gate holds that it is gone;
- R68's L3-10: the single-word check, which `_check_word` exports.

Then Task 15. Slice 1's library review runs after Task 15.

## R80. On the specs commit `e105acb0` and the R78 commit `88602b48` (2026-10-18)

**Read:** W-srv's report. Both are green on gates.yml and fork-ci, with the checkout proven.
- **The specs commit** (Spec A A-39, Spec B revision 28, the refile through R77) came after #13 merged at 4b055342. The lead opened it as **urnetwork/message-server#14**.
- **The R78 commit:**
  - N1 to N6 are fixed;
  - 15 new mutants are killed in cmd;
  - R75's mutant sets were re-run and still die;
  - 832 tests and subtests pass in fork-ci.

**Rulings:**
- **N2, beyond the letter, CONFIRMED.** A pointer check alone does not fix the review's probe, because the second Collect shares the first's subscription. So a failed write removes the subscription only when no Collect kept it with REASON_OK, and no other claim on it is unsettled. An api test holds every settle order.
- **N5's budget of 8 MiB is CONFIRMED.** So is golang.org/x/sync as a direct requirement, since it was already allowed.
- **The last spec lines and one comment** form one small commit on specs/identity-phase1, which joins #14 while it is open:
  - §4.5: the 8 MiB byte budget;
  - §4.3.11: Collect's settle rule (N2) and the earlier-expiry rule (N3);
  - the enum's claim that CARD_RATE_LIMITED carries retry_after_ms, corrected to what the code sends.

  On identity/i1-srv, store/errorclass.go's comment is fixed: a refused connection logs its SQLSTATE.

**The server's slice-2 work, Tasks 18 to 20, is then COMPLETE.**
- Its PR opens only after the library's slice-1 PR has merged.
- Before it opens, a commit moves the pin back to urnetwork at the merged commit and deletes the review source (R69).
- W-srv is idle until then, or until Task 40 in slice 4.

## R81. Task 15's `-entropy`: dropped (2026-10-18)

**Read:** W-lib's question. PLAN Task 15 asks for `-entropy <file>`, but the library takes no caller entropy for the phrase.
- MASTER §5.1 says "no call takes entropy from its caller", and R68 item 6's gate holds messagegroup's process-entropy draws to NewRecoveryPhrase alone.
- DeviceConfig.Random feeds the device's keys, the salt and the self group's id, never the phrase.

**Ruled (a).** `-entropy` is dropped from Task 15.
- Each tool makes its identity as a person does: it types back the words it was shown, and keeps them in memory only.
- (c) would open a door MASTER §5.1 closes on purpose.
- (b) would seed the keys only and repeat them across runs, for little gain.
- The transcript check gains every party's words AS NEEDLES. No word of any party may appear in anything either tool prints, logs or writes, and a planted word is a control that fires.
- The slice table's "an identity from test entropy" now reads "an identity made as a person makes one". PLAN carries this at the next refile.

## R82. The server's last R80 commits (2026-10-18)

**Read:** W-srv's report.
- On identity/i1-srv, `00ffac01` corrects errorclass.go's comment: a refused connection is classed by its SQLSTATE. It was checked against a real PostgreSQL 17.6 first. CI is green: 832 passed, FULL RUN 2 of 2.
- On specs/identity-phase1, `3ba70ad4` is Spec B revision 29, plus LRI refiled through R80. It joins #14, whose body the lead updated. CI is green.

**Carried to the server branch's re-pin commit,** which comes before its PR (R69): two NIT comments in api/rendezvous_push.go.
- `kept` means the write answered REASON_OK, not that the Collect did.
- The stale-write sentence holds only when the later box is pinned under other keys. A client that re-registers the same code with the same keys after a sweep is acted on. Say so.

**Fixed here:** LRI's "Read with" line now says 46 tasks (since R70).

**The server is complete for slices 0 to 2, and W-srv is idle** until the library's slice-1 PR merges (the re-pin), or Task 40.

## R83. R81's word needle, made measurable (2026-10-18)

**Read:** W-lib's measurement (scratchpad/t15/needle_rates.out, 100,000 random phrases against the live probe's own transcript). A single-word needle fires on 99.76% of honest three-party runs, because the word list is English and so is the probes' output.

**Ruled, as W-lib proposed:**
- The needle is any TWO CONSECUTIVE words of a party's phrase, with up to 4 non-letters between them (0.24% per honest run), or half the phrase's words (13 of 25) as tokens (at most 0.003% per run).
- The controls plant the whole phrase, and a two-word run, and both must fire.
- A single planted word does not fire, by design, and the check's comment says why.
- MI37 is held to this needle.

**Task 15 resumes on this,** with W-lib's design as reported:
- identities made after Connect;
- the stranger seam-bound;
- C's second leaf bound from C's words;
- livepeer's roster grouped by identity;
- digests only;
- 17 steps.

**Task 14 (`dd25d3f`) is accepted,** pending its fork-ci 39108202409, where the windows leg is the only run of the C consumer, and its alt-2 fresh-clone run in /root/t14f.

## R84. On slice 1's review (Task 17 step 2; lib `ff712506`, app `418e3e6a`; workflow wf_81be49c1-7dd, 2026-10-18)

**Read:** four lenses, each with an adversarial verifier. Every finding above NIT was CONFIRMED, and none was refuted. The full text is in `identity-phase1/review-slice1/FINDINGS.md`.
- **No BLOCKER.** Every Task 11 and Task 7b known answer was recomputed independently, and they match. No forged or stale binding was admitted, and no refused commit was published, on any road the reviewers tried. The R68 fixes hold.
- **MAJOR:** X-APP-1, L-1 and G-4.
- **MINOR:** X-LIB-1 to X-LIB-3, X-APP-2, C-1, C-2 (with G-3), L-2, L-3, G-1 and G-2.
- **NIT:** the rest.

This is the first of Task 17's two fix rounds. One delta review follows.

**W-lib's round (library), tests first, each with its mutant:**
1. **L-1 (MAJOR): the identity record is the commit point.** Write the heads and the phrase key FIRST and the identity record LAST, each atomically. A stop before the identity record leaves no identity, so setup can run again. A stop after it leaves a whole identity. The test kills the process between every pair of writes, and every restart then works. The mutant puts the old order back.
2. **G-4 (MAJOR):** the "nothing reached the server" assertion counts EVERY frame, fragments included. The reviewer's surviving mutant of the rejected order must die.
3. **X-LIB-1:** confirm_words' result starts as FAILED, so a recovered panic answers FAILED, never OK. Every export with a kind result gets the same treatment, and a test panics inside each.
4. **X-LIB-2:** the positions are capped at the caller's capacity, with the full count returned or a "more" flag. The header promise is corrected.
5. **X-LIB-3:** liveprobe prints refusals by error class or digest, never an identity key in hex. Its transcript needle gains every identity key.
6. **X-LIB-7 and X-LIB-5:** test failure messages print digests, never the words. Fix the "zoo" one-in-2,048 flake, as the sibling test does.
7. **C-1:** R8-EQ compares every pair of one root's lists at one version, not only against the running newest. The reviewer's leaf-order probe becomes the test, and must pass in every order.
8. **C-2 and G-3: R9's link-group half compares the CURRENT identity key,** the chain's end, with 0xF006's identity_root, as MASTER §5.3 and §5.4 and Spec A §3.4 and §7.5 say. The self group keeps the root. The test runs over a chain of one step.
9. **G-1:** livepeer's protobuf allowance becomes a testFiles allowance.
10. **G-2:** a census row, or test, holds sdk/cgo's handling of the words: no copy outlives the call, beyond the stated string residual.
11. **L-4:** Connect's rebind moves the self group's sessions too.
12. **L-5:** the device signing key is erased on NewDevice's refusal exits.
13. **The NITs, taken:**
    - X-LIB-4 and L-9: say the string copy is §8.4a's residual;
    - X-LIB-6: the control's text;
    - L-6: names matched exactly where the filesystem is case-sensitive, or the reason stated;
    - L-7: the read buffer cleared after decoding;
    - G-7: a gate that every registry entry prints a RED-report row;
    - G-6: the row keyed by body, with "branches on typed letters, which are local input" stated.
14. **Forward to Task 23, into PLAN now (L-2 and L-3):**
    - the self group must survive a restart before its first add: persist what AddMember needs, or found it in a way a restart can resume;
    - the re-founding at start fires only on the device that MADE the identity, never on a linked device waiting for its self-group join.

**W-app's round (app), tests first, each with its mutant:**
1. **X-APP-1 (MAJOR): each box holds exactly one word before Check.**
   - An empty box is named by the app itself ("Word 7 is empty"), and so is a box with two words ("Word 7 holds two words"). The app knows which box, without knowing the words.
   - Only then are the 25 tokens joined and sent, so the library's positions are the boxes' positions.
   - The test includes an empty box and a doubled box.
2. **X-APP-5 (Spec C §6.2):** in a remote session (SM_REMOTESESSION), the words screens SKIP the capture affinity, because it would black the window for the only person who can read it, and show the inline warning instead. The capture tests split by session kind.
3. **X-APP-2:** every buffer holding the words or the typed phrase is overwritten before it is freed, or the claim in LiveIdentity.h is narrowed to what is true. Prefer the overwrite.
4. **X-APP-3:** the Unreadable sentence is drawn.
5. **X-APP-4:** the view reads FieldPolicy, so the mx-copy mutant changes what is drawn and dies there.
6. **X-APP-6:** the READ-ME names local_names.json among what this build still reads, or the build stops reading it. Say which.
7. **X-APP-7:** while a live session is up, the strip reads connected during setup and Account; the plain-launch rule applies only before a live world. Use a test and a shot.

**Specs (W-srv, the next specs commit):** G-8. Spec A says the words are answered "once", where the code answers the same words until ConfirmWords, and new ones after a restart, as PLAN Task 12 and M5:405 require. The spec gets the code's sentence.

**The lead's own text:**
- L-8: R79 item 6 is narrowed. No production file uses FIELD-REACHING reflection or unsafe. sdk/cgo's unsafe.Slice at the C boundary is the stated exception.
- G-5: PLAN's gate table is updated at the next refile.

**Then:** one delta review of both rounds, then Task 17's step 3, the alpha. The lead tells the owner before the database is wiped.

## R85. On both R84 rounds (lib `02504d51`, app `2da43e47`, 2026-10-18)

**Read:** both writers' reports.
- **Library:** every R84 item is fixed, and 24 mutants are killed. alt-2's fresh-clone test.sh is green, and fork-ci 39147572571 is green on all four legs, with the C consumer passing on windows.
- **App:** every R84 item is fixed. The live rig passed 59 of 59, 16 diag mutants are killed, and the zip smoke passes on both images.

**Rulings:**
- **The app's per-box check_word, beyond the letter: CONFIRMED.** NFKD folds U+00A8 into two tokens, so a box can be one word to the app and two to the library.
- **The app adds a re-check on WM_WTSSESSION_CHANGE.** The capture affinity follows the session kind while a words screen is up, with a mutant.
- **The library's commit-verb panic tests** are held by gen's source gate. A real one belongs to the loopback harness, later.
- **L-1's leftovers are SWEPT.** At start, a device with no identity record erases any heads record and phrase-key record. This is a named authority, with its own erase-table row. The kill test is extended, and the mutant drops the sweep.
- **L-5's second half:** makeIdentity zeroizes the engine it replaces.
- **The app pins the library's next small commit,** which carries those two items.
- **Then one delta review of both rounds:** lib ff712506 → its final head, and app 418e3e6a → its final head. That is Task 17's second and last pass.

## R86. The setup orphans' sweep rests on a mark, not on an absence (2026-10-18)

**Read:** W-lib's R85 report, at `329244fb`. W-lib reproduced, with a probe, a case where R85's sweep is not true:
- an identity record moved away while the app starts (for example, quarantined by an antivirus) gets a live identity's heads and phrase key swept;
- once the record is put back, every start is refused.

The sweep rested on an ABSENCE, the class R33 rejected for group files. The erase gate's own principle is that an erase rests on "a fact it wrote itself".

**Ruled: the mark, which is the (c) pattern.**
- Setup writes a setup mark FIRST, before the heads. It removes the mark only AFTER the identity record stands.
- The start's sweep erases the heads and the phrase key ONLY where the mark stands and no identity record does.
- With no mark, nothing is erased, whatever is missing. The quarantine case then comes back whole once the record returns.
- The authority keeps the letter (j), "a setup's orphans", now reading "a setup mark that stands with no identity record". PLAN's authority table gains (j)'s row at the next refile.
- **Tests:**
  - the kill test at every write, mark included;
  - the quarantine probe becomes a test: the record moved away, a start, the record put back, and the start whole;
  - a mutant that sweeps without the mark must die, by the quarantine test.
- Then W-app pins that commit, and the delta review runs.

## R87. R86's mark, built (`c6b186cf`, 2026-10-18)

**Read:** W-lib's report.
- The setup mark is store kind 14, at "identity-setup". It is written first and removed only after the identity record stands.
- (j) sweeps only on the mark.
- The kill test runs at all 7 writes, and the quarantine test passes.
- 11 mutants are killed, MSM ("an absence alone decided an erase") among them.
- alt-2's fresh-clone test.sh and fork-ci 39157812390 are green, with the checkout proven.

**Accepted.** The residual is a double fault: a stop between the identity record and the mark's removal, AND the record then moved away before the next start. It is stated in the commit, and is accepted for I1.

**Specs and PLAN, at the next filings:**
- Spec A §8.1 gains "identity-setup", kind 14 (W-srv), together with R84's G-8 sentence.
- PLAN's authority table gains (j)'s row, with the mark as its premise.

W-app re-pins to c6b186cf. Then the delta review (Task 17's second pass): lib ff712506..c6b186cf, and app 418e3e6a..its re-pinned head.
