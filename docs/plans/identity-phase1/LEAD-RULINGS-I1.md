# Lead rulings: identity phase 1 (I1), and its interface to IDs and requests (R)

**Filed copy.** These rulings are filed in `urnetwork/message-server` as `docs/plans/identity-phase1/LEAD-RULINGS-I1.md`, in the folder beside the plan, and the ledger entry that files them lists every change made in filing them. `identity-phase1/PLAN.md` and `PLAN.md` are the plan, filed as `docs/plans/2026-10-16-identity-layer-one-account.md`: the plan as R62 left it, of 1,548 lines where R61 read 1,545, with two lines of legend added at its top. `SCOPE.md`, `FOR-OWNER.md`, `REDTEAM.md` and `REDTEAM-TASK2.md` are filed in this folder. A local path is replaced by a label: `srv@<sha>` is `urnetwork/message-server` at that commit. The lead's scratch folder is in no repository: it holds every `scratchpad/...` path, and the designs and rulings named here by a relative path or a short name, such as D2 and LR.

**Date:** 2026-10-16 (UTC). **Writer:** the lead. These rulings continue LR's numbering (`scratchpad/hardening-plans/LEAD-RULINGS-2026-10-15.md`, R34 to R47; R33 is in `LEAD-RULINGS-2026-10-14.md`).

**Read with:** `identity-phase1/PLAN.md` (45 tasks) and `SCOPE.md`; `accounts-requests/DESIGN-v2.md` (D2). PLAN's Task 1 files this file in `message-server` beside the plan. Every writer reads it before starting a task, and again before finishing one.

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
