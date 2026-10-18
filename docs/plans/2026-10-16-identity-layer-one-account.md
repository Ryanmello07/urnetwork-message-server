# Identity, phase 1: one ID for your account, and an ID for each device

**Filed copy.** This plan is filed in `urnetwork/message-server` as `docs/plans/2026-10-16-identity-layer-one-account.md`, and the ledger entry that files it lists every change made in filing it. `PLAN.md`, in its companions, is this file. They are filed beside it, in `docs/plans/identity-phase1/`: `SCOPE.md`, `FOR-OWNER.md`, `REDTEAM.md`, `REDTEAM-TASK2.md` and `LEAD-RULINGS-I1.md` (LRI). `identity-phase1/<name>`, or a companion named alone, is the file in that folder. Local paths are replaced by labels. `lib@<sha>`, `srv@<sha>` and `app@<sha>` are `urnetwork/message`, `urnetwork/message-server` and `urnetwork/message-windows` at that commit, as read in a local clone, and `app:` paths are under `app/src/App`. The owner's review file (OWN) is the owner's decisions review of 2026-10-05, in no repository. The lead's scratch folder is in no repository either: it holds every `scratchpad/...` path, and the designs, reviews and rulings that this plan's Inputs and SCOPE's place there or name by a relative path, such as OD, M5, F1, D2 and LR. Its head and Inputs name LRI R48 to R60, the rulings it was written to; R61, R62, R65, R66, R68, R70, R72, R81, R84, R86 and R87 came after, and the text cites each where it changed it. R61 takes X11 to X14 and P12 to P15 as planned, which the table under "What the lead ruled" still marks new and open. `app@a832482` is the head of urnetwork/message-windows#8, open when this plan was filed.

**Writers:** the planner of the identity-phase-1 round; then the finalizer, who applied the red team's fixes in place; then the reviser, who brought the phrase change into I1 for the owner's answer of 2026-10-16 and applied the lead's rulings R48 to R57; then Task 2's finalizer, who applied Task 2's dispositions in place. **Date:** 2026-10-16. **Status:** an implementation plan. The lead has ruled on it (`LRI` R48 to R60). Its design has had its one pass (LRI R53): `REDTEAM`'s 24 findings are dispositioned in "Review dispositions", and Task 2's 7 (`REDTEAM-TASK2`) in "Task 2 dispositions". One check of Task 2's dispositions follows, then Task 1 files the plan (LRI R57). Nothing was built or run for it, and no repository, server, spec or ledger was changed. **Declined actions:** none.

## Change log, 2026-10-15 to 2026-10-16

| # | What changed | Caused by |
|---|---|---|
| 1 | **The phrase change made with the old phrase (M5 PC1 to PC5) is built in I1,** as a new slice 4 with its own owner session: Tasks 42 to 45. Task 11 gains the chain of form-1 steps and its pure verifier, beside `VerifyDeviceList` | The owner's "No, in phase 1" (LRI R56.1; OWN:524) |
| 2 | It is slice 4, not slice 3: with it, slice 3 would be ready about day 31 to 37 [a], past about day 35. Task 38b closes slice 3, and Tasks 39 to 41 close I1 after slice 4 | The lead's brief for this revision; P13 |
| 3 | Four departures for it, X11 to X14, and a recount of the concepts, P12 | Row 1 |
| 4 | Two erase rows: (f)P, a phrase key whose identity key a step retired; and (i), a void change's new key | Row 1 |
| 5 | Task 32: the words-scoped hooks also run at AD1's `ConfirmWords`. Task 43 runs them at a change | LRI R51 (IL8), R56.1 |
| 6 | Task 6b, the conversation list (W-app; app-only; it lands with R) | LRI R50 (P11 flipped), R57 |
| 7 | Task 35 moves to R, and Task 37 is not built. Their ids, `MI76`, `MI77`, `MI79`, `MI80` and row (a)S are retired | LRI R50 (P10; P1 stands), R51; the owner kept P1's default (OWN:529) |
| 8 | Task 8 files MG-17, the 90-day leaf, beside MG-16 | LRI R52 |
| 9 | Task 2 runs prompts 1 to 9 as written, with H4's reveal order in prompt 3 and authority (g) in prompt 7, and gains prompt 10 for the phrase change. It runs before Task 1, which files the plan with its dispositions | LRI R53, R56.1, R57 |
| 10 | srv's base is `main` `37dd710f`, which carries T1's close. srv and app are read at `srv@37dd710f` and `app@a832482` | LRI R48 |
| 11 | The lead's table, the timetable, the counts, the mutants, the scenarios, the probe, the sessions and the reports follow rows 1 to 10 | Rows 1 to 10 |
| 12 | FOR-OWNER's three questions are answered, and it now says what the owner gets and tests | LRI R56; OWN:523-529 |
| 13 | **No device leaves its account holding a phrase secret** (P15): (g)'s acts wait for their erase; a lock-out's target erases under (f), and a change its removal made void under (i), before it shows itself removed. Tasks 30, 32 and 43; column 11 of the authority table; `MI115` to `MI117` | Task 2's T2-H1 |
| 14 | The alarm offers "Change my recovery phrase" only where a change can help; the owner's copy says where a replaced phrase still counts, and that a change cannot undo a use the alarm reports (lead, LRI R61); the root stays, as P14 (Tasks 34, 43 to 45; `MI118`, `MA15`) | T2-H2 |
| 15 | Task 11 pins the device key's two signature domains (`MI121`); R3, K5, K9 and the slice-4 report say that every earlier phrase counts for good where its step is not seen; Task 42 places the alias before every rule (`MI119`); a change that re-mints the salt is a mutant (`MI120`); P7 holds | T2-M1, T2-M2, T2-L1 to T2-L3 |
| 16 | The counts, the times, the promise table, FOR-OWNER and "Task 2 dispositions". D2's lines moved down by 4 at 03:04, when the lead put LRI R58's note at its top: D2 lines this file cited before Task 2's dispositions now read 4 lower (ID1 :172, DID1 :189, IL8 :140, the reconcile note :149-163, VID2 :326 [m]), and Task 2's own D2 citations are current | Rows 13 to 15; LRI R58 |

**Inputs.**
- `SCOPE` = `identity-phase1/SCOPE.md`. Its row ids (A1 to S4, K1 to K9, X1 to X14, R1 to R17) are used unchanged.
- `HP` = `srv:docs/plans/2026-10-09-hardening-harness-and-join-seal.md`, the model for this plan's form. `LR` = `scratchpad/hardening-plans/LEAD-RULINGS-2026-10-15.md` (R34 to R47). `LRI` = `identity-phase1/LEAD-RULINGS-I1.md` (R48 to R60), which Task 1 files beside this plan.
- OD, M5, F1, F3, T1, T2, MB, V4, DESIGN, D2 and OWN are the files SCOPE's Inputs name. `REDTEAM` = `identity-phase1/REDTEAM.md`; `REDTEAM-TASK2` = `identity-phase1/REDTEAM-TASK2.md`, Task 2's red team. D2's lines moved by 4 (change log, row 16).
- `lib:` = `lib@c7501a19`; `srv:` = `srv@37dd710f`; `app:` = `app@a832482`, under `app/src/App`. `git status --short` was empty on all three [m]. The first round read srv at `20fc48db` and app at `badf2e2c`. Since then srv changed only SPEC-LEDGER.md, Spec A and Spec C, and app changed seven files that no line here cites [m: `git diff --stat`]. So every code line cited here reads the same, and Task 40 gives Spec C's moved lines.

**Marks.** [m] read at the cited place by the writer of that line: the first round's marks are its writers', and this revision's reads are listed in "What was verified". [c] reasoning or arithmetic. [a] an assumed number or choice, which the spec round fixes or the day measures. Every "see it fail" or "see it pass" below is [c]: what the test must print, not what it printed.

| | |
|---|---|
| Repositories | `urnetwork/message` (**lib**); `urnetwork/message-server` (**srv**: specs, ledger, plans and server); `urnetwork/message-windows` (**app**). One pull request per repository per slice. A slice ships to the owner from its branch heads before its pull requests merge, as build 03 did (LR R43). |
| Base | **lib:** `main` = `c7949cfd`, the merge of T1 (urnetwork/message#7). Its tree equals `c7501a19`: the diff is empty [m]. **srv:** `main` = `37dd710f`, the merge of urnetwork/message-server#11, which carries T1's ledger close (LRI R48) [m]. **app:** `main`, since urnetwork/message-windows#7 merged as `864354e1`, whose tree is `badf2e2c`'s, which pins lib `c7949cfd` (LRI R48, R60 [m]; the merge is not in the read-only clone, so it is the lead's record, unchecked here). The S3 branch, now at `a832482` (message-windows#8), is the lead's dispatch to W-app, which writes both [m]. |
| Order | Each slice branch is cut from `main` after the slice before it has merged (HP:179-184). If the owner has not merged yet, the next slice stacks on the previous branch, and its pull request says so. `main` is merged in when it moves. Nothing is rebased or force-pushed. |
| Compiler | go1.27.2 (lib `go.mod:5` [m]). **No task changes a `go.mod`.** Argon2id comes from `golang.org/x/crypto`, which lib already requires (`go.mod:8` [m]). The layering rows allow it in `messagegroup` and not in `sdk/urmessage` (`internal/layering/layering_test.go:74-77`, :95-99 [m]). |
| Pins across repositories | srv builds against lib at its `scripts/siblings.txt` pin, `0bb2128f` today [m]. lib's `sdk/cp3b` builds against srv at its own pin, `e9eae67a` [m]. So each repository moves the other's pin, in a commit of its own, and only to a pushed commit. |
| Variant | **RESET**, the only one (OD:32, :110-114). No legacy mode, no upgrade step, no compatibility with build 03 (SCOPE §6). |
| Lab | **None.** HP was cut from a lab that built every commit (HP:22); this plan was not. Its sizes, times and counts are [c] or [a]. Every number a report quotes is measured on the day. |
| Writers | One per repository (program gate 4, `srv:docs/plans/2026-10-05-hardening-program.md:113-115` [m]; REDTEAM L6): **W-lib**, **W-srv**, **W-app**. Red-teamers and reviewers are read-only, and are none of the three. |
| Tasks | 46, with ids 1 to 45, 6b, 7b and 38b; 35 and 37 are retired. Before code, 7; slice 1, 12 (7b since LRI R70); slice 2, 12; slice 3, 8; slice 4, 7. |

## Goal

- **One account ID, the same on every device, and a device ID for each device.** This is the owner's first item: "One ID for a whole account and device IDs" (OWN:485).
- **Add a device by a short code and seven emoji.** It then joins your conversations with no paste, which answers OWN:451 for devices.
- **Remove a device, lock out a phrase device, and see who did what.** A stolen device that is not a phrase device can remove nothing but itself.
- **Change the recovery phrase with the old one, at once,** keeping "Your ID", every device and every conversation (M5 PC1 to PC5; LRI R56.1).
- **Ship it in four slices,** each ending in a session with the owner. The first real slice reaches the owner about twelve to fourteen days after the lead's rulings [a] ("Time, size and slices").

## The architecture in four sentences

1. Your account is one identity key made from your 25-word recovery phrase, and each device keeps its own key, which is today's device signer. A device list rides in every leaf of every conversation, and every member checks it. The list is signed by the phrase's key, or, for an addition, by one of your devices.
2. A new device joins by a short code and seven emoji. The server carries the code in a sealed link box, and both screens show the same emoji. Your own devices then bring the new one into your conversations through your self group, so nobody pastes anything.
3. Removing a device means a new list without it, with the phrase as the second factor. Locking out a phrase device makes a new key number. Members refuse what the newest list does not name, once a device of yours brings that list into their conversation.
4. Changing the phrase with the old one makes a new identity key, which the old one signs. The first phrase's key stays the root, so every ID stays, and each device moves itself in place in every group it is in.

## What the lead ruled, and what is still open

Each row says how the lead ruled it (LRI R49, R50, R56), or that it is new and open, and what changes if it is flipped.

| Id | Ruled, or planned | If flipped |
|---|---|---|
| X1 | **Taken.** No security delay: a removal acts at once. FOR-OWNER says so, with OD:99 | RM3 to RM5 on device clocks: +2 tasks in slice 3, and the being-removed state |
| X2 | **Taken.** The server carries the link code (the link box, on arms 20 to 24). It answers A29 | Tasks 18 to 21 go, and Task 22 pastes two codes, of about 2.2K and 6.8K characters (SCOPE X2) |
| X3 | **Flipped by the owner: "No, in phase 1"** (LRI R56.1). The phrase change with the old phrase, PC1 to PC5, is built, as slice 4 (P13) | — |
| X4 | **Taken.** T2's labels and safety numbers move to R | T2's four surfaces return (M5 H.6) |
| X5 | **A default the owner did not flip** (LRI R56): device cap 10 | One constant and its tests, raised together with the 10 leaves per identity (lib `mls/errors_lifecycle.go:38` [m]) |
| X6 | **Taken** (P8). The device ID is derived from the root and the device key, as D2's DID1 is | A `device_id` field in each entry, checked equal to the derivation |
| X7, X9, X10 | **Taken.** Names per device; emoji always, after a typed code; the removed screen points to a device still on the account | As SCOPE §3 states |
| X8 | **The owner: "Yes, alpha only (Recommended)"** (LRI R56.2). Keys under file permissions only, and no Windows Hello prompt, until I2, in alpha test builds only | — |
| X11 | **New, open.** The phrase change runs with no server part: on any device the list names, with no backup, delay or wait to carry (SCOPE X11) | Build PC's backup and delay steps with the server part (I3) |
| X12 | **New, open.** Every leaf carries the chain, the form-1 steps from the root, at most 4 [a] (SCOPE X12; D2 IL2) | One predecessor per leaf (M5 H.2), and a device that missed two changes cannot move |
| X13 | **New, open.** The self group moves in place at a change (M5 AD6, H.4), where F1 founds a new one (SCOPE X13) | Found a new self group, and bring every device into it through the old one |
| X14 | **New, open.** "Change my recovery phrase" is one action on Settings → Account (SCOPE X14) | M5's row 11, a fifteenth surface |
| P1 | **Stands** (LRI R50); the owner kept the default (OWN:529 [m]). Leave is per device, and Task 37 is not built. Per-device leave plus fan-out's respected-removal rule (Task 25) keeps a left device out [c] | Task 37 runs, with its authority row (a)S |
| P2 | **Taken.** Ending an identity, and a removed device, add no whole-store erase. "This ends this identity" marks the identity ended, then leaves each conversation through authority (a). A device removed by another erases nothing else (M5 RM8): a lock-out's target erases only its phrase key, under (f) (P15). A phrase device's own removal or end erases one record, its phrase key, under (g) (P9). The next setup starts in a fresh store folder | A whole-store erase on command: a new authority with crash marks, the shape LR R36 says files and marks lose to |
| P3 | **Taken.** The phrase key is its own record (store kind 13 [a]), naming its identity key and key number [a]. It is erased under (f), a verified higher key number; (f)P, a verified step past its identity key (Task 43); (g), on this device's own removal or end; and (i), when the change that wrote it is void | The key kept inside the identity record, replaced rather than erased |
| P4 | **Taken.** The link deposit is DESIGN's M size, 17,526 octets (DESIGN:244-249), and the card has a fixed size [a]. R then adds kinds, not sizes | A size of its own |
| P5 | **Taken.** Slice 0 is built (Task 6), after Task 2's dispositions (LRI R57) | Task 6 is dropped |
| P6 | **Taken.** The build-03 folder is kept, and READ-ME-FIRST says how to delete it by hand (SCOPE §6, R14). No authority (h) exists | The app deletes it at first run, under an authority of its own |
| P7 | **Taken.** The alarm's second reason reads a log of this device's own signatures. A put-back can shorten that log, so the alarm's sentence names that case (Task 34) | Decided: Task 2's prompt 8 found it holds, a false positive only (T2-L3) |
| P8 | **Taken.** The IDs follow D2 (REDTEAM M10). The account ID is D2's ID1, with `u16(id_version = 1)` where DESIGN had the profile field (D2:168 [m]). The device ID is D2's DID1, over the root and the device key (D2:185 [m]). Task 3's registry freezes both before Task 10 writes known answers | DESIGN's profile field at 2 and SCOPE B2's first device ID; R then rewrites both known answers |
| P9 | **Taken.** A phrase device's own removal or end erases its phrase key first, under (g), and the no-target lock-out notice is offered (Tasks 30 and 32). Why (LRI R50): budget class (iv), one action, a thief at an unlocked phrase device. Its failure path is P15 | A removed or ended phrase device keeps a key that signs lists under the current key number, on a disk that may change hands |
| P10 | **Taken** (LRI R50, R51). Task 35 moves to R, which writes it against D2 §2.0. The words-scoped hooks stay in I1 (Tasks 32, 33 and 43) | — |
| P11 | **Flipped** (LRI R50). W-app builds the conversation list during I1, app-only, as Task 6b, and it lands with R. Why: it is R's longest pole (D2 §8.1 item 1); W-app has about one commit per slice (REDTEAM M13); and the owner asked to speed up testing (OWN:428) | — |
| P12 | **New, open.** With the phrase change, I1 shows 10 concepts: M5 D.1's row 7 comes in, and row 1, "Account login", is not counted, since I1 has no login screen and reads a developer credential (SCOPE G14). The first scope counted row 1 | Count row 1: 11 concepts, one over THE BUDGET, forced by the owner's answer, as L-v5-5 accepted M5's 18 (OD:124 [m]) |
| P13 | **New, open.** The phrase change is slice 4, with session 4. In slice 3 it would make slice 3 ready about day 31 to 37 [a] ("Time, size and slices") | The change in slice 3: one session fewer, and the removal session about five days later |
| P14 | **New, open** (Task 2's T2-H2). The root stays the first phrase's key across a change, so "Your ID" stays (D2 IL1 and ID3, D2:132, :178 [m]; SCOPE K3). Planned: keep it, and state its cost. Every earlier key, the first above all, still counts for good where its step is not seen, as V4's reviewed rule says of "a phrase you have replaced" (V4:318 [m]); the alarm and the owner's copy say so (Task 43; SCOPE R3). I1 still makes a new identity key that the old one signs, as M5 PC2 does (M5:185 [m]), so no owner line is departed from [c] | The ID is taken over the current key: "Your ID" and every device ID change at every change, and D2's IL1, ID3 and DID3, and R's plan, change with them. The window does not narrow, since a replaced key's rival needs no ID [c] |
| P15 | **New, open** (Task 2's T2-H1). No device leaves its account holding a phrase secret. "Remove this device" and "This ends this identity" go ahead only once (g)'s erase has succeeded. A lock-out's target erases its key under (f) before it shows itself removed, as M5 TR7 has every phrase device do on a higher number (M5:141 [m]), and a change made void by this device's removal erases under (i) first. A failed erase sends nothing, changes nothing else, and is tried again (Tasks 30, 32, 43). No new authority, surface or concept | A held file at the erase leaves the key in a folder the app never opens again (Task 38), and P2's "erases nothing", read over (f), leaves a lock-out target's key there with no hold at all |

## THE BUDGET (LR R36, R39; LRI R53)

It is set before any code, so that review rounds cannot grow the design. LR R36: "each round so far closed what it found, and the next found a new combination one move longer".

- **Rounds.** The design gets one red-team pass and one check of its dispositions. The lead ruled that REDTEAM's pass and Task 2 together are that one pass (LRI R53). Each slice gets one independent code review at the subject, then at most two fix rounds. After that, only the class below is fixed in I1, and everything else is filed.
- **Fixed in I1.** A finding produced by ONE action of one adversary, or by ordinary software behaviour. One action means: a server that lies once; one stolen device; one copied store; or one program moving, holding, denying or putting back ONE store file. The finding must show the code doing one of four things:
  - (i) erasing without a true reason;
  - (ii) saying something false: a sentence, a notice, an alarm or an emoji match;
  - (iii) accepting what the list or the ceremony forbids;
  - (iv) letting a phrase secret go somewhere its disposition does not allow.
- **Filed, not fixed.** A finding that needs two or more coordinated actions; a liveness or hygiene cost of a correct refusal (LR R39); and every risk SCOPE §7 accepts (R1 to R17), which is stated rather than found. Filings go in `lib:messagegroup/OPENITEMS.md` from MG-16 on: MG-15 is the last there (OPENITEMS.md:1187 [m]; a search for MG-16 and MG-17 found nothing, while its control, "MG-1", hit). MG-16 and MG-17 are Task 8's, and MG-18 is Task 43's [a: numbered in landing order]. The state store's own files go to the store track. Task 2's dispositions add no id: T2-H1's residual is a store file's, so it goes there (SCOPE R17; LR R39, R45).
- **Sizes.** At most 14 surfaces and 10 concepts (SCOPE §2; P12), and no headline that M5 D.2 lacks (M5 H.9). 10 devices, 16 changes waiting on one base, and 4 steps in a chain.
- **Smallest fix first:** remove, tighten, accept, add (M5:5). A finding answered by adding a mechanism goes to the lead.

## The promise table

Each row is a sentence the owner will read that promises something, with the rule that keeps it, and whether the rule's subject is the promise's subject (LR R34's lesson).

| Promise | Adversary | Enforcer, and its rule | Same subject? | Where it stops |
|---|---|---|---|---|
| "Your ID is the same on every device" | server; network | the grant, inside the link group, carries the root, the chain and the salt; ID1 (D2:168; P8) | yes | — |
| "Only your devices can add a device" | server | every member: TR2 over the list in each leaf, signed by ISK_g or by a listed device | yes | — |
| same | copied store; stolen device | nothing stops it, because each holds a listed key. The alarm (TR11) tells the original | **no** | SCOPE R4, R5; M5 risk 2 |
| "A device cannot remove a sibling the list still names" | stolen linked device | every member: R8-SIB (F1:539) | yes | — |
| "A removed device can no longer act" | an altered app on it | members, once a device of yours brings the list there (JN2, R8-CUR) | **no**: the rule's subject is the list in that tree | SCOPE R8 (L-v5-12) |
| "Seven matching emoji mean nobody is in the middle" | the server carrying the code; the network | commit-then-reveal at link-group epoch 1, the new device revealing only after it has read the other's nonce (REDTEAM H4); 42 bits; three failures burn a session; 5 sessions an hour | yes | SCOPE R10 (confirming without looking) |
| "Removing a phrase device locks it out" | stolen phrase device | key number g+1; devices refuse a lower g (TR4) | **no**, in a conversation where no device of yours runs | SCOPE R8, R13 |
| "Changing your phrase keeps 'Your ID' and your devices" | server; network | ID1 and DID1 over the root, which the chain keeps (D2 IL1); the new key's first list names every device as it stood (Task 43) | yes | — |
| "After a change, your devices refuse the old paper" | the holder of any earlier paper; a copy of an old phrase device | the words helper on your devices (Task 43); the rank rule, in every tree that holds the step and on every device that has seen it (Task 42) | **no** for a conversation: the rule's subject is the tree that holds the step | SCOPE R3: every earlier phrase, the first included, for good, where none of your devices has run since (T2-M2) |
| "Change my recovery phrase" answers what the alarm reports | the holder of an earlier paper | Task 43: the alarm offers it only for a rival of the current key, and otherwise says a change cannot undo it (T2-H2) | yes | SCOPE R3: where the rival got in first, an invitation is the way back |
| "A device that leaves your account takes no key of your phrase" | a program holding or denying the file; a thief at an unlocked phrase device | Tasks 30, 32 and 43: the self-removal, the end and the removed state come only after the phrase-secret erase has succeeded (P15) | yes for a held file; **no** for a thief who copied the record first | SCOPE R4 (the notice's lock-out retires a copied key); R17 (a deny that outlasts every start) |
| "Your phrase is never stored" | memory, swap, the store | the phrase-secret census (Task 10) | **no**: Go cannot promise zeroed memory | a residual, stated in Spec A §8 with its measured scope, and MASTER §5.2 qualified to point there (LRI R68) |
| "Nothing shows your devices' own group" | — | `Groups`, `Restore` and the group-list export exclude system groups (Tasks 12, 14) | yes | — |

## New erases, and the authority table (LR R34 item 10, R36)

I1 adds three erase authorities, (f), (g) and (i), a second premise of (f) named (f)P, and new callers of (a). Each new site joins the erase gate (`lib:sdk/urmessage/erasegate_test.go:19-60` [m]) under its label. The table holds whether each label is TRUE of everything it takes.

**Rows.**
- **(a)L:** a link group, left when its session ends (Task 23). There is no owner question, since a system group has none.
- **(a)E:** each conversation, left when the person ends the identity on an only device (Task 30).
- **(a)S:** not built. It was Task 37's, and Task 37 is retired with P1 (LRI R50). Nor does (h) exist: P6 was taken, so the build-03 folder is kept.
- **(f):** the phrase key record, removed when this device holds a verified certificate for a key number higher than the record's own (Task 32). It is new. A lock-out's target does it before it shows itself removed (P15).
- **(f)P:** the phrase key record of a retired identity key, removed when this device holds a verified form-1 step past that key: its own, at a change, or a sibling's, from its self group (Task 43). It is new.
- **(g):** the phrase key record, erased on this device's own command: before a phrase device's signed self-removal is sent, or before its identity is marked ended (Task 30; P9; REDTEAM H2). It is new. The letter names the authority, not a key number. Neither act goes ahead until this erase has succeeded (P15).
- **(i):** a phrase change's own new key record, erased when the change is void before anything of it was sent: the self group's order shows, ahead of it, another change of the same key or a list that no longer names this device (Task 43). It is new. Where the void is this device's removal, it comes before the removed state (P15).
- **(j)** (LRI R86, R87): a setup's orphans. The heads and the phrase key are erased at a start only where the setup mark (kind 14, "identity-setup") stands and no identity record does; the mark is written first and removed only after the identity record stands, so an absence alone erases nothing.

**Columns.** 1 to 7 are LR's, and 8 to 11 are I1's: (1) the record moved away; (2) an epoch state moved away; (3) the mark's removal held; (4) a stray file; (5) the whole folder moved away and put back; (6) a deny on adding files; (7) one store file put back; (8) a server that lies, by withholding, replaying, reordering or forking; (9) a stolen listed device; (10) a copied store; (11) the erase itself held or denied (Task 2's T2-H1).

| | 1 to 6 | 7 | 8 | 9 | 10 | 11 |
|---|---|---|---|---|---|---|
| (a)L | (a)'s cells as T1 holds them. The premise is a session in memory, which no file move reaches [c] | C: as columns 1 to 6 | T: a withheld or forked link group times out, and the leave is true | — | C: a copy's session lives in its own process | T1's (a): the leave stops at the held file, its mark stays, and the next Restore finishes it (LR R36) |
| (a)E | (a)'s cells. The ended mark is one record, written first | T: an old identity record put back over the ended one is never read, because the app has already opened a fresh folder (Task 38) | — | A: a thief can end your identity, on that device only (SCOPE R1, R5) | A: a copy carries on until members drop its leaves (SCOPE R8) | As (a)L, in each conversation. The ended mark is written first, so the end holds (Property 2) |
| (f) | T: the record's own key number is read at the erase; a moved record erases nothing; a stray is skipped | T: a retired key put back is erased again at the next start, before it signs anything | C: the certificate is signed by IRK, which the server cannot forge | A: a stolen phrase device holds a live key until the lock-out (SCOPE R1) | A: SCOPE R4 | T: the record stays and signs nothing, since its own number is read first, and the next start erases it. A lock-out's target shows itself removed only after (Task 32; P15) |
| (f)P | T: (1) the record's own identity key and key number are read at the erase, and a moved record erases nothing; (2) the step is read from the identity record's chain, and a chain that cannot be read erases nothing; (4) a stray is skipped; (5) the record and the chain come back together, and are read again. C: (3) and (6), since (f)P writes no mark and adds no file | T: an old key's record put back is erased again at the next start, before it signs anything; an older identity record put back alone is overtaken at Restore by the self group, where the move stands (TR8) | C: the step is signed by the old key, which the server cannot forge; a withheld step erases nothing | A: a stolen phrase device whose app is altered keeps the old key; every tree that holds the step refuses its lists (SCOPE R3) | A: a copy made before the change keeps it, with the same reach (SCOPE R3, R4) | T: as (f): the next start erases it, and a device removed meanwhile shows itself removed only after (P15) |
| (g) | T: one record, by its own name, on the person's command on this device; a moved record erases nothing, and a stray is skipped | T: a record put back after the removal or the end is never read, because the app has already opened a fresh folder (Task 38) | C: the erase reads nothing from the server | A: a thief who copies the record before removing the device keeps the key; every other device's notice offers the lock-out that retires it (Task 32) | A: SCOPE R4 | T: the act is refused before anything is signed or sent; the device stays a listed phrase device, and the person acts again (Task 30; P15) |
| (i) | T: (1) the record is read by its own name, and a moved record erases nothing, while the change then cannot be sent, since sending reads it; (2) the void is read from the self group's state at the erase, and a self group that cannot be read erases nothing; (4) a stray is skipped; (5) the record and the self group come back together, and are read again. C: (3) and (6), as for (f)P | T: a void change's record put back is erased again at the next start, before anything is sent, since sending checks the self group first | T: a withheld rival: this device sends, the server refuses its commit for its epoch, and nothing is erased until the rival is seen. A: a self group that the server forks at a change (MG-18) | C: a stolen device without the old words cannot start a change; with them, it is a phrase holder (OD:16) | A: a copy made between the store and the erase keeps a rival step and its key (MG-18) | T: the change stays void and sends nothing, and the next start erases it. If the void is this device's removal, it shows itself removed only after (Task 43; P15) |
| (j) | T: the mark is read by its own name at the erase, under the store's lock; with no mark nothing is erased, so a moved record erases nothing (the quarantine test); a stray is skipped. R: a stop between the identity record and the mark's removal, then that record moved away, sweeps a live identity (LRI R87, accepted) | T: a record put back finds no mark standing and opens whole | C: the server is not read | C: a stolen device holds no setup in progress | R: a copy taken mid-setup sweeps only its own orphans | T: a held erase leaves the mark, and the next start finishes the sweep |

**T** is a test with real moves, holds and denies, named in its task. **C** is a cell that cannot arise, with its reason. **A** is accepted, and filed with its sequence. Each slice's report prints the table whole, and Task 39 holds it.

## How this plan is laid out

It keeps HP's shape, which `srv:planlint_test.go` reads (HP:188-201). Each task has Consumes and Produces, numbered **Properties**, checkbox Steps, and a mutation step whose numbered items each name the Property they must fail. Tasks that only run, review, file or report state no property.

- **Ids.** Library mutants run from MI1, server mutants from MR1, and app mutants from MA1. Scenarios in the adversary harness (`lib:sdk/cp3b`, registry `testdata/advsim/known-gaps.json`) are named `I1-…`. M5's rule ids (TR, AD, RM, JN, PC) are used unchanged. An inserted task takes a letter (6b, 38b), and a task that is not built keeps its heading with its id retired (35, 37), so that no id changes its meaning.
- **Red then green (program gate 5).**
  - A scenario that can run on `main` must fail there in strict mode, for the reason it names.
  - A scenario about a mechanism `main` lacks (a self group, a link, a phrase change) cannot run there. Its red is its control mutant on the I1 tree, which puts the rejected design back. The task says so, as F1:1093 does with its "n/a" column.
- **Tests first, against a stub.** Each task first adds its API answering a named `errNotBuilt`, so each new test fails for its own reason and never on a build error.
- **Mutants run two-phase** (M5:420; LR R35): first each against its named killer's package, then a CONTROL run of every suite. A mutant counts as KILLED only when its named killer kills it.

## Test commands

- **lib:** `./test.sh` whole, on `alt-2` (linux with gcc) and through the fork's `fork-ci.yml` with all four legs, each host printing the verdict R8 and R15 allow it (HP:91-110). The RED report is `ADVSIM_STRICT=1 go -C sdk/cp3b test -count=1 -run TestAdvSim -v ./...` (HP:250-252). The scan is `MESSAGE_TEST_VULNCHECK=1 ./test.sh`.
- **srv:** `go test ./...` with the sibling pins verified (`scripts/siblings.sh --verify`), and `gates.yml`. The plan linter is `go test -count=1 -run TestThePlanLinter -v ./`.
- **app:** `build-and-test.yml`, with the composition dll from the pin; `--diagnose` (PASS n, FAIL 0); `tools/verify-copy.ps1`; the shots run; and the zip smoked as shipped on windows-2022 and windows-2025 (LR R43).
- **Argon2id in tests.** The frozen parameters (t = 3, m = 262,144 KiB, p = 4; M5 H.3) run in one known-answer test and in the probe. Every other test stretches through a test-only seam, and a source gate holds that production never reads it (Task 10, MI9).

## What was verified, and what was not

- **The first round [m, its writers']:** SCOPE, LR, OD and M5, whole; HP's head (:1-400) and :3958-4157, :8274-8403, :13559-13678, :14002-14481, :16101-16240; F1 §2.0-§2.15 and §5-§7; F3 §2.1, §2.2 and §2.11; T1 §2.1-§2.2; DESIGN §1-§3 and §5-§8; OWN A28 to A30; the lib, srv and app code at the lines each task cites; and the finalizer's check of every REDTEAM finding, each absence re-run with its control in the same pass.
- **This revision's documents [m]:** LRI, LR, PLAN, SCOPE, FOR-OWNER, REDTEAM, M5 and OD, whole; F1 :1-150 and :329-837; V4 :299-360 (B.5) and :982-1166 (F.0); F3 :300-381 and :800-905; D2 :1-224, :318-353 and :735-822; T2 :224-240; OWN :286-293 and :426-529.
- **This revision's code [m]:**
  - lib: `sdk/urmessage/roles.go:1-135` and :186-275, where R6c refuses every identity change, the committer's own path included (:200-214), which mls alone would allow (:193-195); `mls/group_policy.go:97-105` and :480-497, where roles key on the identity; `mls/group.go:780-830`, a member's role read by its credential, and :3630-3647, the joiner's lifetime check; `sdk/urmessage/group.go` at :2783, :3054, :5049, :5600, :5664 and :5800, the identity sites; `device.go:933`, a founded group naming its founder's key as owner; `erasegate_test.go:1-70`; and `messagegroup/OPENITEMS.md`'s item headings;
  - srv at `37dd710f`: `planlint_test.go` (:1-166, :282-340, :576-600, :680-800, :940-1012, :1146-1230), the checks this file is written to; `SPEC-LEDGER.md:14153` (§6); Spec A's A-35 (:118, :4146); Spec C's headings (:287, :558, :1552);
  - app at `a832482`: `Live/LiveMesh.cpp:2992-2998`, `Live/LiveWorld.cpp:288-292` and `Views/SettingsView.cpp:221`, :377, which read as SCOPE §1 says; and the three trees' heads and status, with the diffs from `20fc48db` and `badf2e2c`.
- **The linter's fatal patterns** (an open-item id, a ledger item number) were run over this file with a planted control in the same pass. Only the controls fired.
- **Task 2's finalizer [m]:** LRI (R48 to R60) and LR, whole, first and last; REDTEAM-TASK2, PLAN, SCOPE, FOR-OWNER, REDTEAM, OD and M5, whole; D2 :1-30 and :100-229; V4 :299-360 and :985-1069; F1 :340-379, :530-574 and :720-749; OWN :420-534; lib `sdk/urmessage/erasegate_test.go:1-70`; the three trees' heads, `c7501a1`, `37dd710` and `a832482`, each with an empty `git status --short`. Each HIGH's absences were re-run with a control in the same search ("Task 2 dispositions").
- **Not run:** anything. **Not measured:** Argon2id's time on the owner's computers (SCOPE §10), and the worst-case sizes of a leaf's list and chain and of a link invite, which stay [c] until Task 11 measures them.

## Rules for every task

- **Briefs.** Every brief to a writer opens with an AUTHORITY block quoting the owner's grant ("Project is being lead by you so go ahead with everything") and the lead's ruling for the task, and names its target as repo@branch:commit.
- **Writers.** One writer per repository. A gate that reads a sibling repository counts as a writer of it while it runs (program gate 4). Pins across repositories move in commits of their own.
- **Workspaces** (REDTEAM M7). W-lib and W-srv work in separate workspace roots. In each root the other repository is a clone at its pin (`scripts/siblings.sh --verify`), and nobody writes it there. Each repository resolves the other by a sibling path: lib's `sdk/cp3b/go.mod:65` and srv's `go.mod:46` [m].
- **Commits.** A task that changes a tree is one commit, unless it says otherwise. Before every commit, compare `git ls-files | wc -l` with its count before the change. Before trusting a run, read `git status --short` in every repository the run builds.
- **Specs and plans.** A spec or plan change carries its ledger entry and edit-log row in the same commit, after a subagent diff review (`srv:SPEC-LEDGER.md` §6, :14153 [m]).
- **Secrets.** No secret is ever printed, logged, committed or put in a transcript: no words, stretch output, seed, link code, or emoji of a real session. Probes print SHA-256 digests only (F1:1123).
- **Gates.** A gate prints what it narrowed away and holds the allowed set both ways. A search that finds nothing carries a control in the same query. A mutant puts back the rejected design, not a parameter.
- **The app.** After any change a person sees, run the app and look at it. Smoke each build as shipped.
- **Declined actions.** A declined action is never redone in another form. It is reported to the lead and the owner.
- **Outside repositories.** No issue or pull request outside `Ryanmello07/*` and `urnetwork/*`.
- **Rulings.** Read LR and LRI before starting a task, and again before finishing it.

# Phase 0: before code

**The order** (LRI R57; it replaces LRI R55's steps 1 to 3):
1. This revision of PLAN, SCOPE and FOR-OWNER, for the phrase change (LRI R56.1).
2. Task 2: the red team, prompts 1 to 10 (done: `REDTEAM-TASK2`); then its dispositions, under THE BUDGET (done: "Task 2 dispositions"); then one check of them, which is next.
3. Task 1 (W-srv) files the plan, which then carries Task 2's dispositions, with its ledger entry and LRI. Then Tasks 3 to 5 (W-srv), each after those dispositions.
4. W-lib: Tasks 8 to 10 after Task 1, where Tasks 9 and 10 also wait for Task 3's registry, which they consume; Task 7 once Tasks 4 and 5 land (REDTEAM L1).
5. W-app: S3 is done (`a832482`). Task 6b runs now, while Task 2 runs. Task 6 follows Task 2's dispositions, and the list pauses for it.

**The deploys.** The alpha's link-box deploy (slice 2) is a major change to the VPS, and the lead tells the owner before it (LRI R55).

### Task 1: File this plan in `message-server`, with its ledger entry (W-srv)

- Consumes: this document, after the lead's rulings (LRI R48 to R60) and Task 2's dispositions
- Produces: `docs/plans/<date filed>-identity-layer-one-account.md`; its ledger entry; LRI, filed beside it as the rulings file every writer reads first

It runs after Task 2 (LRI R57), so the plan it files carries Task 2's dispositions. The program's gate 1 still holds: a track's plan is written in `srv:docs/plans`, reviewed, and landed with a ledger entry before any code (program plan :104-106). Task 2 changes no tree [c]. **The base** is `main` `37dd710f`, which carries T1's ledger close (LRI R48) [m].

- [ ] **Step 1: the name** carries no `-p<n>-`, `-s<n>-` or `-m<n>-` segment, because the linter would read that as the plan's token (program plan :376-379).
- [ ] **Step 2: the linter.** `go test -count=1 -run TestThePlanLinter -v ./` passes with no finding against this file. The text was written to the linter's fatal checks (`planlint_test.go:957-971`, :994-1011 [m]): it holds no capital-letter-digits-hyphen-digits token that no plan defines, and cites no ledger item by number.
- [ ] **Step 3: the ledger entry, by §6.** It records the owner's words of 2026-10-16 (OWN:451, :485 and the answers at :523-529 [m]); the lead's rulings LRI R48 to R60; the rows X1 to X14 and P1 to P15; the budget; SCOPE; and the dispositions of REDTEAM and of Task 2. It also records that `identity-phase1/FOR-OWNER.md` went to the owner before slice 1 (REDTEAM M8).
- [ ] **Step 4: a subagent diff review,** then the commit.

### Task 2: The red team before the spec (read-only; program gate 2)

- Consumes: SCOPE; the M5 H.10 items that I1 builds on (SCOPE §3); this plan's new erases and its promise table; REDTEAM §5 ("what holds") and this plan's dispositions, which it does not redo (LRI R53)
- Produces: a record of the findings, each dispositioned before any spec moves

A reviewer who wrote neither SCOPE nor this plan answers each prompt with a reproduction or a reason. It runs prompts 1 to 9 as written, with LRI R53's two additions, and prompt 10 for the phrase change (LRI R56.1):
1. TR7's memory of marks; TR12's pool of 16, and its folding; RM6's keep-or-remove dialog; the shorter entry (M5:422).
2. X1, with D off: what a removal promises now, against a stolen phrase device and against an altered removed device.
3. X2, the link through the server: the code's alphabet and length [a: about 12 characters, about 60 bits]; its derivations; the card sealed under the code; the deposit sealed to the card's X-Wing key; commit-then-reveal at link-group epoch 1 when the server carries both directions, **in REDTEAM H4's order: N reveals `n_N` only after it has read `n_E` (F1:654)**.
4. The binding in every leaf: VerifyLeafBinding's order (F1:463-471, without its legacy part); equal versions with different octets; a key package whose list is older than the adder's head.
5. R8-SIB, R8-CUR and R9, laid over today's role rules (`lib:sdk/urmessage/roles.go:24-37` [m]).
6. The self group with no server head (TR8 without its second source): a fork, a withheld commit, two lock-outs at once.
7. The new erases (the authority table), **with P9's authority (g)**; and identity-wide leave (P1), which stays unbuilt: does per-device leave keep a left device out?
8. The alarm's premises (P7): can one put-back file make it say something false?
9. The phrase: 267 bits as Argon2id's input, and their encoding [a]; the labels; every signature domain (device-signed list changes, IskCert, the form-1 step, MLS's own signatures, and R's labels to come).
10. **The phrase change, PC1 to PC5, as Tasks 11, 42 and 43 build it:** the form-1 step's label and preimage; the chain in every leaf, and its bound (X12); R6s shape (i) and the aliased policy (F1:551-570); the rank rule, and the refusal of a second successor (V4:317-318, :1064); the self group moving in place (X13); the store-first order, the void change and authority (i); (f)P; the races with a lock-out, a removal, a self-removal and a second change; the hooks at a change, with both keys; and what a stolen phrase device, a lying server and a copied store can do across a change.

**The budget holds here too** (LRI R53). REDTEAM's pass and this task are the design's one pass, and one check of this task's dispositions follows. A third round on one promise goes to the lead.

**Done, 2026-10-16:** `REDTEAM-TASK2` answered all ten prompts: 0 CRITICAL, 2 HIGH, 2 MEDIUM and 3 LOW, each dispositioned in "Task 2 dispositions".

### Task 3: MASTER for I1 (W-srv)

- Consumes: Task 2's dispositions; SCOPE §2 and §3
- Produces: the MASTER edits, a ledger item, and their edit-log rows

- [ ] **Step 1: the edits** to `docs/specs/2026-08-12-urmessage-protocol-design.md`:
  - **§5.1 and §5.2** (:687-762): 25 words holding 267 random bits and an 8-bit checksum, with no typo repair, never stored; Argon2id, then IRK, `isk_root` and ISK_g; device keys unchanged. Neither backup keys nor `card_root` are derived in I1.
  - **§5.3:** 0xF005 in every leaf, with the chain, and 0xF006 in system groups.
  - **§5.4** (:798-811): a device is added by a code the server carries and seven emoji. This replaces the QR handshake.
  - **§5.5:** Start over; the lock-out by key number; and the phrase change with the old phrase, its step and the rank rule (SCOPE K1 to K8).
  - **§6 and §11** (:3209): one mode; R6e, R6c-sig, R8-EQ, R8-CUR, R8-SIB, R9 and R6s in place; 10 devices.
  - **§9.8:** the link box. **§13:** the self-group and link-timing disclosures (F1:817-819), and SCOPE R1 to R17. **§15:** what moves to R, I2, I3 and I4.
- [ ] **Step 2: the ledger item,** with one registry table: 0xF005 and 0xF006; store kinds 11 to 13; D2's ID1 and DID1, frozen before Task 10 writes known answers (P8); the form-1 step's label, `URmessage/v1/identity-succession` (V4:1012 [m]); the chain's bound, 4 steps [a], and the leaf's, 6,144 octets [a] (M5 TR12); the link box's rendezvous kind, 4 (REDTEAM M10); the content kinds of system groups, and the block kept for R; Task 7's proto fields; and the two advsim entries that now name R (Task 8, Step 3).
- [ ] **Step 3: a subagent diff review,** then one commit.

### Task 4: Spec A for I1 (W-srv)

- Consumes: Task 3
- Produces: the Spec A edits, and their ledger entry

- [ ] **Step 1: the edits.**
  - **§3.1 and §3.4:** the two extensions' rows, and the required capabilities.
  - **§5.14:** the link box: the derivations from the code, the card, the deposit, and the five preimages.
  - **§6:** the seam's new methods, by count. **§7.2 and §7.5:** the identity calls, the device calls, and the phrase change's.
  - **§8.1:** store kinds 11 to 13, and the store root's own names. **§9:** the exports.
  - The erase authorities, with (f), (f)P, (g) and (i) new.
- [ ] **Step 2: the edit-log row and the ledger entry;** a subagent diff review; the commit.

### Task 5: Spec B for I1 (W-srv)

- Consumes: Task 4's §5.14
- Produces: the Spec B edits, and their ledger entry

- [ ] **Step 1: the edits.**
  - **§3.2:** the two rendezvous tables, as NEW appended migrations with `kind` and `public_ct`. A landed migration is never edited (`srv:store/migrations.go:29-35` [m]).
  - **§4.3.11** (:2140-2232 [m]) gains kind 4, the link box. Kinds 1 to 3 are DESIGN's inbox, join box and reply box (D1:461 [m]; D2:502 [m]; REDTEAM M10):
    - Register takes a fixed-size sealed card, and Open returns it. One Deposit of exactly 17,526 octets (P4); then Collect with push, and Retire.
    - Limits [a]: a TTL of 10 minutes, at most 2 deposits, and a global cap on live boxes that fails closed.
    - What it does not stop, stated (REDTEAM L2). The endpoint authenticates no client, so one client can fill the cap and stop all linking until boxes expire. A server that finds a code, by a search of its about 60 bits [a], reads that box's card, which holds a device name.
    - An unknown or retired id gets the merged refusal, behind a non-zero reject floor.
  - **§4.3.1:** Task 7's Capabilities fields. **§7:** the sweep. **§10.2:** the configuration rows.
  - **§11:** `rendezvous_id` and `deposit_hash` are never logged. **§13:** the acceptance tests of Tasks 18 to 20.
- [ ] **Step 2: the ledger entry;** a subagent diff review; the commit.

### Task 6: Slice 0: the new screens in the app's fabricated mode (W-app; P5, taken)

- Consumes: SCOPE §2, H1 to H6; the app's rule that each fabricated string says what it is (`app:RunMode.h:1-60` [m])
- Produces: the new screens drawn over the fabricated world; their `--diagnose` rows; shots for the owner's first look

**Behaviour.**
- **The screens:** "Set up this device", offering the code or "This is my first device"; the 25 words, then typing them back; Settings → Account, with "Your ID" and Devices; Add a device, and the emoji on both screens; the five endings; the Remove dialog and the removed screen; a notice, and the alarm.
- **Honesty.** Every fabricated string says it is fabricated. The words shown are a fixed demo list [a], labelled "Demo words: not a recovery phrase". So a demo never shows a real phrase, and this task waits on neither Task 3 nor Task 10 (REDTEAM L5) [c].

- **Property 1.** No fabricated screen shows a string that the live screen would show as a fact.
- **Property 2.** The words screen is excluded from capture.

- [ ] **Step 1: the screens and their `--diagnose` cases;** each case first fails on its missing row.
- [ ] **Step 2: shots, looked at;** the words screen captures black.
- [ ] **Step 3: the mutations.**
  1. `MA1`: the "Demo words" label is dropped. Property 1 must fail. Killed by a new pair in `RunModeCopyDiagnostics`.
  2. `MA2`: capture exclusion is off on the words screen. Property 2 must fail. Killed by the shot that asserts a black capture.
- [ ] **Step 4: build, smoke the zip as shipped, and send the owner one line:** "These are the screens, with made-up data; nothing is encrypted in this build."

### Task 6b: The conversation list (W-app; app-only; lands with R)

- Consumes: the lead's brief to W-app of 2026-10-16 (LRI R57), and the rulings on its design and live run (LRI R59, R60); D2 §8.1 item 1 (D2:782 [m])
- Produces: the app's conversation list, with Requests at its top, on a branch of its own; its record lands with R's first app slice (LRI R50)

It is P11's flip (LRI R50). W-app builds it in the gaps between its I1 tasks: now, while Task 2 runs (LRI R57 starts it before Task 6, where R50 had it after); it pauses for Task 6, and never goes ahead of Tasks 16, 28, 38 or 45. It touches no I1 property, and no I1 build carries it unless the lead rules otherwise when it is done. Its tests and mutants are the brief's, and R's plan records them.

# Slice 1: "Your ID", on one device

The owner's session 1 ends this slice (SCOPE §8 steps 1 to 3, and 11). The server changes nothing but its database, which the lead wipes.

### Task 7: The proto first, so that the server can start (W-lib)

- Consumes: Spec A §5.14 and Spec B §4.3.11, as Tasks 4 and 5 left them
- Produces: the appended fields in `protocol/message.proto`; the regenerated Go; the wire corpus

**When** (REDTEAM L1). W-lib starts slice 1 at Tasks 8 to 10. It does this task the day Tasks 4 and 5 land, and the server starts the day this task lands.

**Behaviour.** Fields are only appended, in DESIGN's numbering, so that R adds kinds and not fields (DESIGN:452-484):
- `RendezvousRegisterRequest`: `kind = 6` and `public_ct = 7`;
- `RendezvousOpenResponse`: `public_ct = 4` and `deposit_sizes = 5`;
- `RendezvousDepositResponse`: `deposit_hash = 2`;
- `Capabilities`: `rendezvous_deposit_sizes = 26` and `rendezvous_kinds = 29`.

Nothing is renumbered or removed.

- **Property 1.** Every field this commit adds is new, and no existing field changes its number, type or name.

- [ ] **Step 1: the test first.** The append-only schema rule's table gains the new fields, and fails until the proto has them.
- [ ] **Step 2: the code.** The proto; the Go, regenerated under the pinned `protoc-gen-go`; the wire corpus. `test.sh`'s protoc check passes.
- [ ] **Step 3: the mutations.**
  1. `MI1`: an existing field is renumbered to make room. Property 1 must fail. Killed by the append-only check.
- [ ] **Step 4: commit, push to the fork, and send W-srv the commit,** which Task 18 consumes.

### Task 7b: message: the rendezvous preimages and verifiers (W-lib; LRI R70)

- Consumes: Spec A A-37's §5.14 and its A-1 rendezvous section (§12.1); Spec B revision 26's §12.1; item 300's labels and sizes
- Produces, in the `message` package, exactly the A-1 rendezvous surface in kind 4's form: `RendezvousRegistration` and `RendezvousCollectParams`; `RendezvousRegisterPreimage` and the other preimages §5.14 names; `VerifyRendezvousRegister`, `VerifyRendezvousOpen`, `VerifyRendezvousDeposit`, `VerifyRendezvousCollect` and `VerifyRendezvousRetire`; `RendezvousId`; `DepositVerifyKey`; `LinkCardBytes` and `LinkDepositBytes`

**Why.** Task 19 verifies all five signatures through these functions, and A-1 forbids the server building a preimage (`srv:api/second_implementation_test.go`). No task built them: Task 7 is the proto only, and Task 21 is the client. W-srv found the gap (LRI R70).

- **Property 1.** Each verifier accepts exactly the preimage §5.14 defines, under its label and for kind 4. It refuses another label, another kind (kind 0 included), another box id and another key.
- **Property 2.** `RendezvousId`, `DepositVerifyKey` and each preimage are their known answers. `LinkCardBytes` and `LinkDepositBytes` are item 300's 4,124 and 17,526.

- [ ] **Step 1: tests first:** `TestEveryRendezvousVerifierAcceptsOnlyItsOwnPreimage`; `TestTheRendezvousValuesAreTheKnownAnswers`. If `message` holds a gate over the A-1 surface, it gains the section.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI122`: a verifier ignores the kind, so a kind-0 or kind-1 preimage verifies as kind 4. Property 1 must fail. Killed by `TestEveryRendezvousVerifierAcceptsOnlyItsOwnPreimage`.
  2. `MI123`: a preimage omits its label. Property 2 must fail. Killed by `TestTheRendezvousValuesAreTheKnownAnswers`.
- [ ] **Step 4: commit, push to the fork, and send W-srv the commit,** which Task 19's verify step pins.

### Task 8: The harness first: four scenarios RED on `main` (W-lib)

- Consumes:
  - `sdk/cp3b`'s world and registry, the harness of HP's phase S0 (HP:419-686);
  - the seam member that gives one identity a second leaf (`lib:sdk/cp3b/removal_test.go:105-110` [m]). Today a device "mints one identity per state store".
- Produces: four registry entries, open, with `closed_by` I1, and their scenarios, in `sdk/cp3b/advsim_identity_test.go` [a]; MG-16 and MG-17

| Scenario | What the person or the adversary does | Observed on `main` [c] | Goal, and the task that reaches it |
|---|---|---|---|
| `I1-two-devices-one-person` | Alice talks to Bob from two computers | `identities:3`, `kind:group` | `identities:2`, `devices:alice:2`, `kind:direct` (Task 26) |
| `I1-sibling-evicts-sibling` | a second leaf of Alice's identity removes Alice's first, which nothing has dropped | `removed:followed` | `removed:refused` (Task 26) |
| `I1-copy-adds-unnoticed` | a copy of Alice's folder adds a device under Alice's identity | `alarm:none` | `alarm:copy` (Task 34) |
| `I1-unbound-key-package-admitted` | the harness's attacker, which skips the Add door and the sending check, adds a key package that names no identity (REDTEAM M3) | `admitted` | `refused` by every receiver (Task 13) |

- [ ] **Step 1: the four scenarios and their entries,** each with a control. A third real person makes the first conversation a group. A removal passes once a base has dropped the target. The original device's own addition raises no alarm. A bound key package is admitted.
- [ ] **Step 2: see them RED.** Strict mode fails on exactly these four, each for its stated reason; normal mode passes.
- [ ] **Step 3: the two entries T2 was to close now name R.** They are `S3-mg1-join-code-substitution` and `S7g-removed-group-second-founder`, and T2's work moves to R (X4). The registry edit's ledger note is in Task 3's item.
- [ ] **Step 4: commit,** with two items filed in `messagegroup/OPENITEMS.md`:
  - **MG-16:** two lock-outs typed at once on two devices. The later device holds a fork, and the alarm, until it is removed and added again. The fix to come is F1's random first base number under a new key number (F1:617; REDTEAM M6).
  - **MG-17** (LRI R52): a conversation that holds a leaf made from a key package past its 90-day life refuses every new joiner, since a joiner checks each leaf's life against its clock (`lib:mls/group.go:3633-3647` [m]). I1's fan-out joins and T1's pasted joins leave such a leaf until that device commits. It is accepted in I1, since the alpha resets every slice (SCOPE R16), and R ends every join with T1b's `Group.Rekey`. It is a liveness cost of a correct refusal (LR R39).

### Task 9: mls: two code points, leaves that keep their extensions, and the own-leaf patch (W-lib)

- Consumes: Task 3's registry; `lib:mls/extension.go:84-95` and `mls/group.go:550` [m], and :1804-1867 as SCOPE G4 cites it
- Produces, in `mls/extension.go`, `validate_commit.go`, `group.go`, `leaf_node.go`, `key_package.go` and `commit.go`: `ExtensionTypeUrmessageIdentity = 0xF005` and `ExtensionTypeUrmessageGroupPurpose = 0xF006`, with their profile rows; `v1Capabilities` listing both; `LeafExtensions` on key packages and foundings; `CommitOptions.OwnLeafPatch`

**Behaviour.**
- 0xF005 is a leaf extension, never a group-context one; 0xF006 is the reverse.
- Every leaf this build makes carries the extensions its caller gives (F1:750-756).
- An Update keeps every extension of the leaf it replaces. Today it does not (SCOPE C5; T2:234).
- An own commit may patch its own leaf's credential and extensions before the leaf is signed and tree-hashed. The patch needs a path. A phrase change moves a leaf with it (Task 42).
- mls checks none of F1's sizes; `messagegroup` does (F1:333).

- **Property 1.** An Update, a path leaf and a key-package leaf carry exactly the extensions their caller set, and an Update keeps the replaced leaf's.
- **Property 2.** 0xF005 is refused in a group context and 0xF006 in a leaf. A group that requires 0xF005 admits no key package that does not list it.
- **Property 3.** An own-leaf patch is covered by the leaf's signature and by the tree hash, and is refused without a path.

- [ ] **Step 1: tests first:** `TestAnUpdateKeepsEveryExtensionOfTheLeafItReplaces`; `TestTheProfileClassifiesTheIdentityExtensionsByWhereTheyMayStand`; `TestAGroupRequiringTheIdentityExtensionAdmitsNoKeyPackageWithoutIt`; `TestAnOwnLeafPatchIsSignedAndTreeHashedAndNeedsAPath`.
- [ ] **Step 2: see them fail,** each for its reason. On today's code the first fails because an Update drops 0xF005 [c, T2:234].
- [ ] **Step 3: the code,** and the seed corpus regenerated (HP's gate "Seed corpus is the generated corpus").
- [ ] **Step 4: the mutations.**
  1. `MI2`: ProposeUpdate keeps only 0xF002, as today. Property 1 must fail. Killed by `TestAnUpdateKeepsEveryExtensionOfTheLeafItReplaces`.
  2. `MI3`: 0xF005 is accepted as a group-context extension. Property 2 must fail. Killed by `TestTheProfileClassifiesTheIdentityExtensionsByWhereTheyMayStand`.
  3. `MI4`: `v1Capabilities` does not list 0xF005. Property 2 must fail. Killed by `TestAGroupRequiringTheIdentityExtensionAdmitsNoKeyPackageWithoutIt`.
  4. `MI5`: the patch is applied after signing. Property 3 must fail. Killed by `TestAnOwnLeafPatchIsSignedAndTreeHashedAndNeedsAPath`.
- [ ] **Step 5: commit.**

### Task 10: messagegroup: the phrase, the stretch, the keys and the two IDs (W-lib)

- Consumes: OD:36-39; M5 C.0 and H.3; F3 §2.1 (the list, normalization and the per-word check), without its 19-bit checksum and its search; F1:345-352; D2's ID1 and DID1, as Task 3's registry froze them (P8)
- Produces: `messagegroup/phrase.go` and `identity_keys.go`; the vendored BIP-39 English list (`messagegroup/bip39_english.txt` [a]), pinned by SHA-256 (F3:319); `AccountId` and `DeviceId`, with their known answers; the phrase-secret census

**Behaviour.**
- **The phrase, v1.** 25 words of the list, carrying 267 bits from `crypto/rand` and an 8-bit checksum over them [a: F3's form, SHA-256 under a `URmessage/v1/phrase-checksum` label].
  - Input is normalized with NFKD, lowercase and collapsed whitespace (F3:325).
  - A word not in the list is named by its position. A checksum that fails says one or more words are wrong.
  - Nothing is ever corrected (OD:36-39).
- **The stretch.** Argon2id over the 267 bits [a: encoded as 34 octets, high bits zero], with t = 3, m = 262,144 KiB and p = 4, giving 32 octets (M5 H.3, not frozen). From it come IRK, `isk_root` and `isk_seed[g]`, as F1:345-352 names them. ISK_g is the Ed25519 key from `isk_seed[g]`.
- **The IDs** (P8; REDTEAM M10). The account ID is D2's ID1, with `u16(id_version = 1)`: `root_pub` is the root, the first phrase's IRK, with a 16-octet salt (D2:168 [m]). The device ID is D2's DID1: the first 8 octets of SHA-256(`URmessage/v1/device-id` ‖ LP(root_pub) ‖ LP(device_pub)), shown as four groups of four lowercase hex characters (D2:185 [m]; SCOPE B2). Both are taken over the root, so a phrase change moves neither (SCOPE K3).

- **Property 1.** A phrase round-trips. One word changed, or two swapped, is refused exactly when the checksum fails, about 255 times in 256 (LRI R68). A word not in the list is named by its position. No input is ever corrected.
- **Property 2.** IRK, `isk_root`, `isk_seed[g]` and ISK_g are the known answers for the all-zero phrase and one other, under the frozen parameters. Production reads no other parameters.
- **Property 3.** `isk_seed[g]` depends only on `isk_root` and g, and no `isk_seed` equals `isk_root` or IRK's seed.
- **Property 4.** The account ID is the known answer, changes with the salt and with the root, and is a UUIDv8 of 36 characters. The device ID changes with the device key and with the root, and with nothing else (D2 DID3).
- **Property 5.** Every phrase-derived secret goes only where its disposition says. The words, the stretch output, `isk_root` and IRK's private half are erased at the end of the call that made them. `isk_seed[g]` reaches only the phrase key record.

- [ ] **Step 1: tests first:**
  - `TestAPhraseRoundTripsAndOneWrongWordIsRefusedByItsPosition`; `TestNoInputIsEverCorrected`;
  - `TestTheKeysAreTheKnownAnswersForTwoPhrases`; `TestProductionStretchesWithTheFrozenParametersOnly`, a source gate over the seam;
  - `TestEveryKeyNumbersSeedIsTheKnownAnswerAndNoneIsTheRoot`; `TestTheAccountIdIsTheKnownAnswerAndMovesWithTheSalt`;
  - `TestEveryPhraseSecretInThisPackageGoesWhereTheDispositionSaysItGoes`, built like the pq-secret census (`lib:sdk/urmessage/pqsecretgate_test.go:1154` [m]).
- [ ] **Step 2: see them fail** on the stubs.
- [ ] **Step 3: the code.** The known answers are normative from here on; Task 40 writes them into Spec A.
- [ ] **Step 4: the mutations.**
  1. `MI6`: the checksum is not checked. Property 1 must fail. Killed by `TestAPhraseRoundTripsAndOneWrongWordIsRefusedByItsPosition`.
  2. `MI7`: F3's single-substitution repair, which OD:36 rejects, is applied. Property 1 must fail. Killed by `TestNoInputIsEverCorrected`.
  3. `MI8`: no stretch: HKDF straight over the bits. Property 2 must fail. Killed by `TestTheKeysAreTheKnownAnswersForTwoPhrases`.
  4. `MI9`: the test seam's parameters reach production. Property 2 must fail. Killed by `TestProductionStretchesWithTheFrozenParametersOnly`.
  5. `MI10`: `isk_seed[g]` comes straight from the master key, so a holder of one key number could mint the next (F1:356). Property 3 must fail. Killed by `TestEveryKeyNumbersSeedIsTheKnownAnswerAndNoneIsTheRoot`.
  6. `MI11`: the account ID is computed without the salt (DESIGN:132). Property 4 must fail. Killed by `TestTheAccountIdIsTheKnownAnswerAndMovesWithTheSalt`.
  7. `MI12`: the words are kept in a field after the call. Property 5 must fail. Killed by the census.
- [ ] **Step 5: commit.**

### Task 11: messagegroup: the list, the two extensions, the chain, the emoji, and the checks over them (W-lib)

- Consumes: M5 C.0, TR2 to TR4, TR7, TR12, and H.2's 50-octet entry; F1 §2.2's formats, less `added_at_ms`, `added_by`, `not_after_ms`, RetiredLegacy and the predecessor's form 2; V4's form-1 step (V4:1011-1012 [m]); D2 IL2 and IL5 (D2:129-132 [m]); Matrix's 64 emoji (MB:41)
- Produces: `messagegroup/devicelist.go`, holding `IskCert`, `DeviceEntry`, the base, `Amendment`, the chain's `Step`, `UrmessageIdentity` (0xF005 v1) and `GroupPurpose` (0xF006 v1); `VerifyLeafBinding`; `VerifyDeviceList`; `VerifyIdentityChain`; `ListVersion` and its order; `LinkSas`; the known answers, and the size known answer

**Behaviour.**
- **The list** is a base signed by ISK_g, plus additions and self-removals signed by device keys (SCOPE C1). An entry has two flags, *phrase device* and *being removed*; the second is never set in I1.
- **The chain** (SCOPE K4; X12). 0xF005 v1 carries the form-1 steps from the root to the leaf's key, at most 4 [a]. It stays empty until a phrase change (Task 43), and receivers verify one from the start, as F1's B5 fed synthetic predecessors (F1:30). A step is the old key, its form, and `Ed25519(old key, LP("URmessage/v1/identity-succession") ‖ LP(next key))` (V4:1012 [m]).
- **`VerifyIdentityChain(root, chain, key)`** is pure, beside `VerifyDeviceList`, and a stranger can run it with no store (D2 IL5; LRI R51). Each step's old key is the root or the step before's next key, each is form 1, each signature holds, and the last next key is `key`. A form-2 step, the 7-day change's, is refused (D2 VID2, :322 [m]).
- **`VerifyLeafBinding`** runs F1:463-471's steps in order, less the legacy ones, with the chain in place of the predecessor:
  1. the size: at most 6,144 octets [a] (M5 TR12, :146);
  2. the certificate's identity key is the credential, and that key's signature holds;
  3. the chain verifies from its root to the credential (`VerifyIdentityChain`);
  4. the list names that key and g, and the signatures over the base and each amendment hold;
  5. the list is well formed: sorted, unique, at most 10 devices and 16 amendments, and only known flags;
  6. the leaf's signature key is named;
  7. no identity key of the chain is the ISK or the signature key.
- **`ListVersion`** is (step, g, base, count), where step counts the chain's steps. **`VerifyDeviceList`** decides between a stored list and a candidate: a later key of one root's chain retires every list under an earlier key; a higher g retires a lower one; on one base, a chain of amendments only extends; anything else is a fork, two chains that part at one step included (D2 IL5).
- **`LinkSas`** is seven emoji of 6 bits each. They come from the link group's exporter at epoch 1, over the group id, the epoch, the new device's key-package ref, and both nonces (SCOPE E4; F1:416-417).

- **Property 1.** Each refusal step of the leaf binding is reached by an input that fails at it and passes every step before it.
- **Property 2.** A higher key number retires every list under a lower one. On one base a chain only extends. Equal versions with different octets are a fork.
- **Property 3.** A list of 11 devices, or one with 17 amendments, can be neither signed nor verified. A self-removal is never refused for want of a place.
- **Property 4.** The emoji are the known answer, and change with every input, the group id and the epoch included.
- **Property 5.** A chain verifies only if every step is form 1 and is signed by the key before it, from the root to the leaf's key, and a pure call with no store answers it.
- **Property 6.** A list under a later key of one root's chain is newer than every list under an earlier key, whatever their key numbers, and two chains that part at one step are a fork.
- **Property 7.** The device key signs in two domains that never meet (Task 2's T2-M1). Every list and amendment preimage is LP(its label) ‖ tbs, so it begins with 0x00 and is never an MLS SignContent, nor the reverse (F1:365-367 [m]).

- [ ] **Step 1: tests first:**
  - `TestEveryRefusalStepOfTheLeafBindingIsReached`; `TestAHigherKeyNumberRetiresEveryListUnderALowerOne`;
  - `TestOnOneBaseAChainOnlyExtendsAndAnythingElseIsAFork`; `TestEqualListVersionsWithDifferentOctetsAreAFork`;
  - `TestTheListHoldsTenDevicesAndSixteenChangesAndNoMore`; `TestASelfRemovalIsNeverRefusedForWantOfAPlace`;
  - `TestTheSevenEmojiAreTheKnownAnswerAndMoveWithEveryInput`; Ed25519's edge vectors (F1:451); `TestADeviceKeySignsTwoDomainsThatNeverMeet`, a known answer both ways;
  - `TestEveryStepOfTheChainIsSignedByTheKeyBeforeIt`; `TestAFormTwoStepIsRefused`; `TestALaterKeyOfTheChainIsNewerAndAPartedChainIsAFork`; the known answers for one step and for a chain of two.
- [ ] **Step 2: see them fail** on the stubs.
- [ ] **Step 3: the code, and the size measured.** The largest 0xF005 I1 can make (10 devices, 16 amendments, 4 steps) becomes a known answer [c: about 4.6 KB, with about 100 octets a step, V4:1114 [m]]. A two-member link invite carrying it must fit the M deposit beside T1's 4,667 octets (T1 §2.1).
- [ ] **Step 4: the mutations.**
  1. `MI13`: the base's ISK signature is not checked. Property 1 must fail. Killed by `TestEveryRefusalStepOfTheLeafBindingIsReached`.
  2. `MI14`: a signature key the list does not name is accepted (F1:1061). Property 1 must fail. Killed by the same test.
  3. `MI15`: the base number orders before the key number (F1:1062). Property 2 must fail. Killed by `TestAHigherKeyNumberRetiresEveryListUnderALowerOne`.
  4. `MI16`: a longer chain of amendments that leaves one change out is accepted (M5:420). Property 2 must fail. Killed by `TestOnOneBaseAChainOnlyExtendsAndAnythingElseIsAFork`.
  5. `MI17`: lists are compared by version only. Property 2 must fail. Killed by `TestEqualListVersionsWithDifferentOctetsAreAFork`.
  6. `MI18`: the cap is checked against 32. Property 3 must fail. Killed by `TestTheListHoldsTenDevicesAndSixteenChangesAndNoMore`.
  7. `MI19`: a self-removal is refused while 16 changes wait (M5:420). Property 3 must fail. Killed by `TestASelfRemovalIsNeverRefusedForWantOfAPlace`.
  8. `MI20`: the emoji leave out the group id and the epoch (F1:449). Property 4 must fail. Killed by `TestTheSevenEmojiAreTheKnownAnswerAndMoveWithEveryInput`.
  9. `MI91`: a step is checked under the key it names as next, so a key signs its own step. Property 5 must fail. Killed by `TestEveryStepOfTheChainIsSignedByTheKeyBeforeIt`.
  10. `MI92`: a form-2 step is taken, D2 VID2's rejected design. Property 5 must fail. Killed by `TestAFormTwoStepIsRefused`.
  11. `MI93`: lists are ordered by key number before the chain's step. Property 6 must fail. Killed by `TestALaterKeyOfTheChainIsNewerAndAPartedChainIsAFork`.
  12. `MI121`: the author signature is taken over the bare tbs, without its label. Property 7 must fail. Killed by `TestADeviceKeySignsTwoDomainsThatNeverMeet`.
- [ ] **Step 5: commit.**

### Task 12: sdk/urmessage: the identity at the device, and the self group (W-lib)

- Consumes: Tasks 9 to 11; store kinds 1 to 10, all taken (`lib:sdk/urmessage/statestore_durable.go:853-865` [m]); `device.go:445-457`, where the engine is built once
- Produces, in `sdk/urmessage/identity.go` (new), `device.go`, `restore.go` and `statestore_durable.go`: store kinds 11 (identity, holding the root, the chain, the current key and the salt), 12 (heads) and 13 (phrase key) [a], and the store root's own names, defined once; `Device.CreateIdentity`, `ConfirmWords` and `Identity()`; the engine rebuilt with credential = IRK and 0xF005; the self group, founded with 0xF006 {1, root}; `ErrNoIdentity`; `Groups` and `Restore` answering conversations only

**Behaviour.**
- **AD1's order** (M5 H.4). `CreateIdentity` answers the words once, and makes nothing. `ConfirmWords`, with all 25 typed back, then makes the identity, key number 1, the first base naming this device as a phrase device, the salt, and the self group: in that order, and only then. Back shows the same words, and a restart makes new ones (M5:405).
- **Join codes and groups.** A device with no identity publishes no join code (`ErrNoIdentity`). Every group this build founds requires 0xF004 and 0xF005, and a system group also requires 0xF006 (F1:484).
- **`Restore`** loads the identity, re-verifies every leaf, raises the heads, and lists conversations only. This closes the trap at SCOPE G11 (F1:702).

- **Property 1.** No identity, record, key or group exists until the words are typed back, and the identity's records are written before the self group is founded.
- **Property 2.** A device with no identity publishes no join code through `KeyPackage`, and every group this build founds requires the identity extension.
- **Property 3.** No list this device answers holds a system group, at any call and after a restart.
- **Property 4.** Only a phrase device holds the phrase key record, and it holds only the current key number's.
- **Property 5.** Every path the store writes at its root is one of the root's own names, and a stray at the root is never read as one.

- [ ] **Step 1: tests first:**
  - `TestNoIdentityExistsUntilTheWordsAreTypedBack`; `TestADeviceWithNoIdentityPublishesNoJoinCode`;
  - `TestEveryGroupThisBuildFoundsRequiresTheIdentityExtension`; `TestNoListThisDeviceAnswersHoldsAGroupOfItsOwnDevices`, also after a restart;
  - `TestOnlyAPhraseDeviceKeepsThePhrasesKey`; `TestEveryRootPathIsOneOfTheStoresOwnNames`, beside `storenames_test.go:27` [m].
  - From the review of Tasks 8 to 10 (LRI R68): an mls accessor that answers copies of a staged leaf's signature key and extensions, for any leaf and for the pending own leaf, which Spec A §6's ProcessedMember fields and Task 13's sending side need, with its test; `engineCapabilities` and the required lists naming 0xF005 and 0xF006 as Spec A §3.1 and §3.4 say, before any bound key package is made; and the phrase-secret census of `sdk/urmessage`, starting here, whose net is `PhraseKeySeed`, `RecoveryPhrase`, the `WithPhraseKeys` ceremonies and the kind-13 record.
  - Task 8's forward costs (LRI R62): the seam member's leaves carry 0xF005, bound to the identity they claim, since every group this build founds requires it, and the setups in `roles_test.go`, `removal_test.go` and `advsim_identity_test.go` follow; the bound-package control of `TestAdvSimAnUnboundKeyPackageIsAdmittedByEveryReceiver` gains the assertion that Carol's key package carries 0xF005 naming Carol.
- [ ] **Step 2: see them fail.**
- [ ] **Step 3: the code.** The erase gate gains no site here.
- [ ] **Step 4: the mutations.**
  1. `MI21`: the identity is written before the words are typed back. Property 1 must fail. Killed by `TestNoIdentityExistsUntilTheWordsAreTypedBack`.
  2. `MI22`: `KeyPackage` answers on a device with no identity. Property 2 must fail. Killed by `TestADeviceWithNoIdentityPublishesNoJoinCode`.
  3. `MI23`: a founded group does not require 0xF005. Property 2 must fail. Killed by `TestEveryGroupThisBuildFoundsRequiresTheIdentityExtension`.
  4. `MI24`: `Restore` lists the self group (F1:1074). Property 3 must fail. Killed by `TestNoListThisDeviceAnswersHoldsAGroupOfItsOwnDevices`.
  5. `MI25`: a linked device keeps the phrase key. Property 4 must fail. Killed by `TestOnlyAPhraseDeviceKeepsThePhrasesKey`.
  6. `MI26`: a root listing reads a name the store does not write. Property 5 must fail. Killed by `TestEveryRootPathIsOneOfTheStoresOwnNames`.
- [ ] **Step 5: commit.**

### Task 13: sdk/urmessage: the binding rules and the doors (W-lib)

- Consumes: Task 11's checks; the role pipeline (`roles.go:24-37` [m]); T1's join window
- Produces, in `sdk/urmessage/identityrules.go` and `heads.go` (both new), `roles.go`, `rolescommit.go` and `group.go`: R6e, R6c-sig, R8-EQ, R8-CUR and R9 in `authorizeCommit`, each with its own sentinel (F1:530-544); the committer's post-commit leaf in `outgoingAuthorizationLocked`, so that the sending side runs the same rules over the would-be tree (REDTEAM H1); the Add door's binding check; the Join door's checks, inside T1's window; the heads' update rule, under which this identity's own head moves only from its self group (REDTEAM M4); the scenarios `I1-stranger-in-self-group`, `I1-server-rolls-back-a-list` and `I1-server-forks-the-self-group`

**Behaviour.**
- **One mode** (SCOPE C4). Every leaf is profile 2 under 0xF005, except the one profile-1 leaf a link group may hold.
- **The order.** The new rules run after R6c and before R1, in F1:506-527's order less its legacy and succession steps; Task 42 adds the succession. The first refusal is the answer.
- **Validity reads only the trees.** Local heads drive the doors, and never validity (F1:337).
- **The Add door** refuses a key package that is unbound, and one whose list is older than this device's head for that identity and omits the package's key.
- **The Join door** refuses an unbound leaf or an in-tree fork, and runs R9 where 0xF006 stands. It runs inside T1's window, so a refusal writes nothing and keeps the join code (T1:258-266).
- **Heads only rise.**
- **The sending side** (F1:497-506 [m]; REDTEAM H1).
  - `authorizeOutgoingLocked` already runs `authorizeCommit` over the value a commit would produce, and refuses this device's own commit (`lib:sdk/urmessage/rolescommit.go:204-220` [m]).
  - That value models the committer as its pre-commit leaf (:236 [m]). It now carries the committer's post-commit leaf, the own-leaf patch included, so every new rule runs over the would-be tree before anything is sent.
  - Why: a commit the server has taken and members refuse halts the group for every member, for good (`roles.go:18-21`; `group.go:1223` [m]).
  - Rules that later tasks add to `authorizeCommit`, R8-SIB (Task 26) and R6s (Task 42) among them, run on this side too.
- **This identity's own head moves only from its self group** (M5 TR8, M5:142 [m]; REDTEAM M4). A list of this identity seen only in a conversation moves neither this identity's head nor its removed state. It is a list this device cannot explain, which Task 34's alarm reports.

- **Property 1.** A commit that adds or updates an unbound leaf, or a profile-1 leaf outside a link group, is refused by every member.
- **Property 2.** A leaf the newest list in the tree does not name is removed in the commit that brings that list, or the commit is refused.
- **Property 3.** A self group admits leaves of its own identity only. A link group holds at most one leaf of each profile, and takes no commit at epoch 1 or above.
- **Property 4.** A stored head never goes backward, whatever a server serves and in whatever order.
- **Property 5.** The Add door refuses an unbound key package, and one whose list is older than this device's head and omits its key, before anything is staged. The Join door's refusals write nothing and keep the join code.
- **Property 6.** Two members whose local heads differ decide every commit alike.
- **Property 7.** Two lists of one identity at one version with different octets are a fork, which every member refuses in any tree, as R8-EQ says.
- **Property 8.** No commit this device publishes is one its own receiving rules refuse. The sending side runs every new rule over the would-be tree, with the committer's post-commit leaf.
- **Property 9.** This identity's own head and its removed state move only on a list from its self group, never on one seen only in a conversation.

- [ ] **Step 1: tests first:**
  - the rule table, both arms of each new rule; `TestAProfileOneLeafStandsOnlyInALinkGroup`;
  - `TestALeafTheNewestListDoesNotNameIsRemovedInTheCommitThatBringsIt`; `TestTheAddDoorRefusesAKeyPackageWhoseListThisDeviceKnowsIsOlder`;
  - `TestEveryJoinDoorRefusalWritesNothingAndKeepsTheJoinCode`; `TestTwoMembersWithDifferentLocalHeadsAgreeOnEveryCommit`;
  - `TestAnOwnCommitEveryReceiverWouldRefuseIsNeverPublished`, with three cases: a foreign-root patch; a list older than the tree's newest; and an Add whose key package's list the tree's newest supersedes. It asserts that nothing reached the in-process server and that no member halts (REDTEAM H1);
  - `TestAListOfMineSeenOnlyInAConversationMovesNothingOfMine`, in which a copy commits a base into a conversation only (REDTEAM M4);
  - the scenarios `I1-stranger-in-self-group`, `I1-server-rolls-back-a-list` and `I1-server-forks-the-self-group`, registered closed. Each runs red on Task 12's commit, where these rules are absent, as gate 5 asks (REDTEAM L5). In the last, the server accepts two self-group commits at one epoch and serves each to a different device of Alice's (SCOPE §9).
  - Task 8's `I1-unbound-key-package-admitted` builds the stranger's key package without 0xF005 on purpose, and asserts that it carries none before the add, so that the refusal is R6e's and the control's admission is a bound package's (LRI R62);
- [ ] **Step 2: see them fail.** `I1-unbound-key-package-admitted` (Task 8) flips, and its entry closes in this commit.
- [ ] **Step 3: the code.**
- [ ] **Step 4: the mutations.**
  1. `MI27`: R6e is off. Property 1 must fail. Killed by `I1-unbound-key-package-admitted`.
  2. `MI28`: a profile-1 leaf is accepted anywhere. Property 1 must fail. Killed by `TestAProfileOneLeafStandsOnlyInALinkGroup`.
  3. `MI29`: R8-CUR is off. Property 2 must fail. Killed by `TestALeafTheNewestListDoesNotNameIsRemovedInTheCommitThatBringsIt`.
  4. `MI30`: R9 is off. Property 3 must fail. Killed by `I1-stranger-in-self-group`.
  5. `MI31`: the heads take the last list seen. Property 4 must fail. Killed by `I1-server-rolls-back-a-list`.
  6. `MI32`: the Add door skips the binding. Property 5 must fail. Killed by `TestTheAddDoorRefusesAKeyPackageWhoseListThisDeviceKnowsIsOlder`.
  7. `MI33`: validity reads local heads, F1's rejected design (F1:1063). Property 6 must fail. Killed by `TestTwoMembersWithDifferentLocalHeadsAgreeOnEveryCommit`.
  8. `MI34`: R8-EQ is off, so two lists at one version both stand. Property 7 must fail. Killed by `I1-server-forks-the-self-group`.
  9. `MI81`: the outgoing value keeps the pre-commit own leaf, as `rolescommit.go:236` does today. Property 8 must fail. Killed by `TestAnOwnCommitEveryReceiverWouldRefuseIsNeverPublished`.
  10. `MI82`: a list of this identity taken from a conversation raises its own head: SCOPE §9's "a base taken from a conversation". Property 9 must fail. Killed by `TestAListOfMineSeenOnlyInAConversationMovesNothingOfMine`.
- [ ] **Step 5: commit.**

### Task 14: The C exports for slice 1 (W-lib)

- Consumes: Tasks 12 and 13; `lib:sdk/cgo/exports_message.go` (:617-860 [m], and :1486 as SCOPE H6 cites it); `messagegroup`'s single-word check over the phrase's fold, which LRI R68's fix round exports for `_check_word`
- Produces, in `sdk/cgo/exports_message.go`: `urnet_message_device_identity`, whose JSON holds the account ID, the device ID, and the devices with their marks; `_create_identity`, `_confirm_words` and `_check_word`; member JSON with `device_id` and the identity grouping; group lists without system groups

- **Property 1.** No export answers a system group.
- **Property 2.** No export answers a phrase secret. The words leave `_create_identity` once, and no other export or log carries them.

- [ ] **Step 1: tests first,** in `sdk/cgo` and in the native-exports check.
- [ ] **Step 2: the exports, and the header the app vendors.**
- [ ] **Step 3: the mutations.**
  1. `MI35`: the group-list export answers every group. Property 1 must fail. Killed by `TestTheGroupListExportAnswersConversationsOnly`.
  2. `MI36`: the identity JSON carries the words. Property 2 must fail. Killed by `TestNoExportAnswersAPhraseSecret`.
- [ ] **Step 4: commit.**

### Task 15: livepeer and the live probe gain an identity (W-lib)

- Consumes: Task 12; the probe's 17 steps (`lib:sdk/liveprobe/main.go:222-1387` [m]); SCOPE S3
- Produces, in `sdk/liveprobe/main.go` and `sdk/livepeer/main.go`: no `-entropy` (dropped by LRI R81: each tool makes its identity as a person does, typing back the words it was shown and keeping them in memory only, and the transcript check holds every party's words as needles); an identity for every probe party; the probe's existing steps under bound key packages; livepeer printing the roster by identity

**Behaviour.** The probe's step 11 drives a member's two devices (`main.go:863` [m]). In slice 1 it keeps the seam member's shape; Task 27 makes the second device a linked one. The transcript check (`main.go:1387` [m]) gains the words and the entropy's digest among what it must never find.

- **Property 1.** No run prints the words, the entropy, or anything made from them except a SHA-256 digest.

- [ ] **Step 1: the probe's own test first** (`main_test.go`).
- [ ] **Step 2: the code, and the README's step count.**
- [ ] **Step 3: the mutations.**
  1. `MI37`: the transcript check forgets the words. Property 1 must fail. Killed by the `main_test.go` case that plants them.
- [ ] **Step 4: commit.**

### Task 16: The app, slice 1: set up, the words, and Your ID (W-app)

- Consumes: Task 14's header; Task 6's screens
- Produces, in `Live/LiveMesh.cpp`, `Live/LiveWorld.cpp`, `Views/SettingsView.cpp`, `Views/RosterRules.cpp` and a new setup view [a]: the live screens of SCOPE H1, H2 and H4, with their states (words shown, typing back, a wrong word named, done); the roster by identity; a fresh store folder for I1

**Behaviour.**
- **First run:** "Set up this device" → "This is my first device" → the 25 words, once, with "These words cannot bring your account back yet" (M5:416) → typing them back, with a wrong word named in its own field.
- **Settings → Account:** "Your ID" (36 characters) with Copy; Devices, with this device, its device ID and the phrase-device mark.
- **The words screens** are excluded from capture. Spelling and prediction are off, and each word is masked when focus leaves it (F3:894-900). They also keep no clipboard history, and they show F3's warning when the session is remote (`SM_REMOTESESSION`; F3:894-899 [m]; REDTEAM L4).
- **Rosters:** a DM is told by identity count (SCOPE H6). The rule is the app's: the library has no "direct" decision [m: grep for `IsDirect`, `isDirect`, `kindDirect` and `KindDirect` in lib's sdk, messagegroup and mls, no hit outside tests; control: `Mine` hits `forget.go:382`]. So the mutant that puts today's rule back is this task's MA10 (REDTEAM M3).
- **The store** opens in a folder named for this slice's build under `live/` [a]. So neither build 03's `live/state` nor an earlier slice's folder is ever read (P6; REDTEAM M1). Tasks 28, 38 and 45 name their own.

- **Property 1.** The words screens capture black, and no other screen does.
- **Property 2.** A wrong word is named, nothing is corrected, and the identity exists only after all 25 words match.
- **Property 3.** "Your ID" is the library's account ID, character for character.
- **Property 4.** A conversation of two identities is direct, whatever its number of leaves.

- [ ] **Step 1: `--diagnose` cases first:** the words screen's capture flag, the field settings, the typed-back states, the ID's text, and a roster of three leaves and two identities.
- [ ] **Step 2: the screens; shots, looked at.**
- [ ] **Step 3: the mutations.**
  1. `MA3`: capture exclusion is off on the typed-back screen. Property 1 must fail. Killed by the black-capture shot.
  2. `MA4`: the typed-back check accepts 24 of 25. Property 2 must fail. Killed by its `--diagnose` case.
  3. `MA5`: "Your ID" is drawn from the device ID. Property 3 must fail. Killed by its `--diagnose` case.
  4. `MA10`: direct is told by leaf count, today's rule (`app:Live/LiveWorld.cpp:288-292` [m]). Property 4 must fail. Killed by the `--diagnose` roster of three leaves and two identities.
- [ ] **Step 4: commit; CI; smoke the zip as shipped.**

### Task 17: Close slice 1, and the owner's first session

- Consumes: Tasks 7 to 16
- Produces: the slice's runs, its report, and session 1

This task changes no file and states no property.

- [ ] **Step 1: the runs.** lib: `test.sh` on `alt-2`, and fork-ci's four legs. srv: `gates.yml`. app: its CI. Every mutant of the slice, two-phase. Strict mode lists exactly the open scenarios the registry names.
- [ ] **Step 2: the review:** the budget's one review, then at most two fix rounds, at repo@branch:commit.
- [ ] **Step 3: the alpha (the lead).**
  - The database is wiped (OD:32), and the server is not otherwise changed.
  - The probe runs over fresh directories; its last line reads `=== N STEPS, M ASSERTIONS, ALL HELD ===`.
  - The server's PID, its uptime, and its journal's error kinds are unchanged.
- [ ] **Step 4: session 1** ("The owner's sessions"), then the report "At the end of slice 1".

# Slice 2: add a device by a code and seven emoji

The owner's session 2 ends this slice (SCOPE §8 steps 4 to 7, and 11). The server's tasks (18 to 20) start as soon as Task 7 lands, beside the library's slice 1.

### Task 18: The server's library pin, and the link box's storage (W-srv)

- Consumes: Task 7's commit, pushed; Spec B §3.2 as Task 5 left it; `store/contract.go`, `memory.go` and `pgx.go`
- Produces: `scripts/siblings.txt`'s `message` line at Task 7, in a commit of its own; two appended migrations; the store's register, open, deposit, collect, retire and live-box counter, in both stores; the deposit's `deposit_hash`, computed by the store from `deposit_ct` as Spec A §5.14 defines it and returned, since `api` may not hash (LRI R70); the contract tests

**Behaviour.** After the pin moves, `scripts/siblings.sh --verify` and the whole suite pass, and `cmd/message-server/schema_test.go` still finds exactly one copy of the schema.

- **Property 1.** No row of either table holds a `client_id`, or anything made from one.
- **Property 2.** No landed migration is edited, renamed or moved.
- **Property 3.** A collect deletes exactly through its acknowledgement. A retire deletes every deposit and keeps a tombstone. A deposit retried with the same octets is one deposit.

- [ ] **Step 1: the pin,** in its own commit.
- [ ] **Step 2: tests first:** `TestTheLinkBoxHoldsNoDepositor`, in the form of Spec B §13's test 40 (:4240 [m]); the migration audit; `TestCollectDeletesThroughItsAcknowledgementAndRetireKeepsATombstone`; both stores under one contract test.
- [ ] **Step 3: see them fail; the code.**
- [ ] **Step 4: the mutations.**
  1. `MR1`: the deposit row keeps the connection's `client_id`. Property 1 must fail. Killed by `TestTheLinkBoxHoldsNoDepositor`.
  2. `MR2`: the new tables are edited into migration 011's slot. Property 2 must fail. Killed by the migration audit.
  3. `MR3`: a collect deletes past its acknowledgement. Property 3 must fail. Killed by `TestCollectDeletesThroughItsAcknowledgementAndRetireKeepsATombstone`.
- [ ] **Step 5: commit.**

### Task 19: Arms 20 to 24, served for the link box (W-srv)

- Consumes: Task 18; Task 7b's commit, pinned before the verify step lands (until then every arm answers as unserved, and the readiness names why; LRI R70); the route table (`peer/peer.go:830` [m]) and the unserved-arms list derived from it (:405-430 [m]); Spec B §4.3.11 and its check order (:2409 [m])
- Produces, in `peer/peer.go`, a new `api/rendezvous.go` [a] and `cmd/message-server/config.go`: five routes, with their handlers; Capabilities 26 and 29; a push on each deposit; `configurationNotWired`'s rendezvous entry narrowed (`cmd/message-server/config.go:282` [m])

**Behaviour.**
- **Register** self-certifies its collect key and pins it. A second register under another key is refused (Spec B :2214).
- **Open** verifies `open_auth`, and returns the sealed card.
- **Deposit** verifies `deposit_auth`, asserts the length as an equality, counts against the box's depth, and is idempotent.
- **Collect** verifies `collect_auth` and deletes through the ack. With `subscribe`, it pushes on the next deposit.
- **Refusals.** An unknown and a retired id get the same refusal, of the same size, behind the configured floor. No transaction opens before the signature passes (Spec B :2409). A full global cap refuses, and so does a counter that cannot be read.

- **Property 1.** A deposit of any length but the advertised one is refused.
- **Property 2.** An unknown, a retired and an unauthorized box are answered alike, and Open answers nothing without a valid `open_auth`.
- **Property 3.** A live box keeps the key it was registered under.
- **Property 4.** The live-box cap refuses when it is full, and when it cannot be read.
- **Property 5.** No log line, metric label or error carries a rendezvous id, a deposit hash or a key.
- **Property 6.** No rendezvous kind but 4 is served, and no kind-4 arm is served while the reject floor is zero (Spec B's test 51, from Task 5's review; LRI R66).

- [ ] **Step 1: tests first,** one per arm and its refusals, and the round trip over the peer: `TestALinkBoxDepositIsExactlyItsSize`; `TestAnUnknownARetiredAndAnUnauthorizedBoxAnswerAlike`; `TestALiveBoxKeepsTheKeyItWasRegisteredUnder`; `TestTheLiveBoxCapFailsClosed`; the logging gate, with a planted id; and Spec B's test 51 as `TestOnlyKindFourIsServedAndNothingWithAZeroFloor` [a].
- [ ] **Step 2: see them fail; the code.** The unserved-arms count drops by five, printed with its complement.
- [ ] **Step 3: the mutations.**
  1. `MR4`: the deposit's length gets a range check. Property 1 must fail. Killed by `TestALinkBoxDepositIsExactlyItsSize`.
  2. `MR5`: an unknown id answers `REASON_REJECTED` while a retired one answers `REASON_CARD_RETIRED`. Property 2 must fail. Killed by `TestAnUnknownARetiredAndAnUnauthorizedBoxAnswerAlike`.
  3. `MR6`: Open skips `open_auth`, which makes it an existence oracle (Spec B :2216). Property 2 must fail. Killed by the same test.
  4. `MR7`: a register under a new key replaces the pin. Property 3 must fail. Killed by `TestALiveBoxKeepsTheKeyItWasRegisteredUnder`.
  5. `MR8`: a read error on the cap counts as room. Property 4 must fail. Killed by `TestTheLiveBoxCapFailsClosed`.
  6. `MR9`: the handler logs the rendezvous id. Property 5 must fail. Killed by the logging gate.
  7. `MR11`: the kind check is dropped, so a registration of kind 0 (the proto's default) or of kinds 1 to 3 is served as kind 4 is. Property 6 must fail. Killed by `TestOnlyKindFourIsServedAndNothingWithAZeroFloor`.
  8. `MR12`: the arms are served with a reject floor of zero. Property 6 must fail. Killed by the same test.
- [ ] **Step 4: commit.**

### Task 20: The sweep, the gates, and the deploy note (W-srv)

- Consumes: Task 19; Spec B §7 (:3330-3344 [m])
- Produces, in `sweep/` and `api/rendezvous.go`: boxes and deposits expiring after 10 minutes [a]; `gates.yml` and fork-ci green; a deploy note for the lead

- **Property 1.** A box past its TTL opens, deposits and collects as an unknown one would, whether or not the sweep has run.

- [ ] **Step 1: tests first,** with a fake clock, before the sweep and after it.
- [ ] **Step 2: the code; the runs.**
- [ ] **Step 3: the mutations.**
  1. `MR10`: expiry is decided by the sweep alone. Property 1 must fail. Killed by the case before the sweep.
- [ ] **Step 4: commit, and the note.** It names the binary, the two migrations and the reset, and says that nothing else of the server changes. It also says that the deploy sets `reject_floor_ms`, since its default of 0 serves no kind-4 arm (Task 5's review; LRI R66). The lead tells the owner before this deploy (LRI R55).

### Task 21: The library's server pin, and the rendezvous client (W-lib)

- Consumes: Task 20's commit; Spec A §5.14; DESIGN's session rule IB3 (DESIGN:210-214)
- Produces: `scripts/siblings.txt`'s `message-server` line, moved in its own commit; `sdk/urmessage/rendezvous.go`, holding the code, its derivations, the card, the deposit, and the five calls over the generic `Call`

**Behaviour.**
- **The code** is about 12 characters [a]. From it come the rendezvous id, the deposit key and the card key, each under its own label.
- **The card** holds the new device's profile-1 key package, `commit_n`, its name, and a fresh X-Wing public key, padded to a fixed size and sealed under the card key.
- **A deposit** is sealed to the X-Wing key inside the card, never to anything Open returns beside it (DESIGN IB2).
- **Sessions.** Open and Deposit into another device's box run on a fresh session that does nothing else (IB3).

- **Property 1.** A deposit is sealed to the key inside the card, and a card that the code's key does not open is refused.
- **Property 2.** Open and Deposit into another device's box never run on the session that registers or collects.
- **Property 3.** The code's derivations are the known answers, and no two share a key.

- [ ] **Step 1: tests first,** against `sdk/cp3b`'s in-process server at the new pin: `TestTheDepositIsSealedToTheKeyInsideTheCard`; `TestOpenAndDepositIntoAnotherDevicesBoxRunOnAFreshSession`; `TestTheLinkCodesDerivationsAreTheKnownAnswers`.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI38`: the deposit is sealed to a key the server returned. Property 1 must fail. Killed by `TestTheDepositIsSealedToTheKeyInsideTheCard`.
  2. `MI39`: Open runs on the long-lived session (DESIGN:214). Property 2 must fail. Killed by `TestOpenAndDepositIntoAnotherDevicesBoxRunOnAFreshSession`.
  3. `MI40`: the deposit key and the card key share one label. Property 3 must fail. Killed by `TestTheLinkCodesDerivationsAreTheKnownAnswers`.
- [ ] **Step 4: two commits:** the pin, then the client.

### Task 22: The link ceremony, up to the seven emoji (W-lib)

- Consumes: Tasks 11, 13 and 21; F1 §2.8 (a), with emoji for its digits; M5 AD2; SCOPE E1 to E6
- Produces, in `sdk/urmessage/link.go` (new): `Device.OfferLink`, run on the new device (N), and `Device.EnterLinkCode`, run on the existing device (E); the link group; `LinkSession`, with its states, endings, burns and rate; the scenario `I1-server-swaps-the-link-card`

**Behaviour.**
1. N registers its box and shows the code. Its card holds the one profile-1 key package a device with no identity may make, through an internal call only `OfferLink` reaches; `KeyPackage` still answers `ErrNoIdentity` (Task 12).
2. E types the code and opens the card. E checks that its list has a place: 10 devices, and 16 changes waiting. If it has none, it ends with "Remove a device first" or "This device can add no more until ⟨phrase device⟩ is opened".
3. E founds the link group with 0xF006 {2, IRK}, adds N, deposits the invite (T1 v3) sealed to the card, and reveals `n_E` at epoch 1.
4. N joins under T1's window and R9, reads `n_E` at epoch 1, and only then reveals `n_N` (F1:654 [m]; REDTEAM H4). N's nonce is bound by `commit_n` before E reveals, and E's is out before N reveals, so neither side can choose its nonce after seeing the other's. E checks `commit_n`.
5. Both show the seven emoji, and ask "They match" / "They don't match".

**Limits.** Three mismatches burn the session; E opens at most 5 sessions an hour; a session ends after 10 minutes [a]; and any commit at epoch 1 or above ends it (R9).

**The test width** (REDTEAM H4, M3). No test can grind 42 bits. So the scenario and its mutants run at a test-only width [a: two emoji, 12 bits] through a seam, as F1's lab ground a 4-digit target (`f1v2lab/sasgrind/sasgrind_test.go:10-12` [m]). A source gate holds that production computes seven emoji only, as `TestProductionStretchesWithTheFrozenParametersOnly` holds the stretch (Task 10).

- **Property 1.** The emoji are computed at epoch 1 only, from both nonces, after both reveals.
- **Property 2.** A server that substitutes the card or the deposit, with or without the code, makes the two devices show different emoji, except with probability 2^-42 per attempt, and nothing is granted.
- **Property 3.** Three mismatches burn the session, and a sixth session in one hour is refused.
- **Property 4.** A list with no place starts no link.
- **Property 5.** N reveals `n_N` only after it has read `n_E` at epoch 1.
- **Property 6.** Production computes seven emoji; only tests reach the narrow width.

- [ ] **Step 1: tests first:**
  - `TestTheEmojiAreComputedAtEpochOneAfterBothReveals`; `TestThreeMismatchesBurnTheSessionAndTheSixthInAnHourIsRefused`; `TestAListWithNoPlaceStartsNoLink`; `TestOnlyALinkOfferMakesAKeyPackageBeforeAnIdentityExists`;
  - `TestProductionShowsSevenEmojiOnly`, a source gate over the seam;
  - the scenario `I1-server-swaps-the-link-card`, registered closed; its red is its mutant. In it the harness plays the server, at the test width: its own card, its own deposit, and a grinder over the nonce it controls.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI41`: no commitment: N's nonce is sent in the card (F1:1066). Property 2 must fail. Killed by `I1-server-swaps-the-link-card`, whose grinder then finds a match at the test width.
  2. `MI42`: the emoji are computed at the current epoch, with R9's epoch rule off (F1:1081). Property 1 must fail. Killed by `TestTheEmojiAreComputedAtEpochOneAfterBothReveals`.
  3. `MI43`: mismatches burn nothing. Property 3 must fail. Killed by `TestThreeMismatchesBurnTheSessionAndTheSixthInAnHourIsRefused`.
  4. `MI44`: E skips the place check. Property 4 must fail. Killed by `TestAListWithNoPlaceStartsNoLink`.
  5. `MI83`: N reveals `n_N` as soon as it joins, before it has read `n_E`. Property 5 must fail. Killed by `I1-server-swaps-the-link-card`: its server holds back its own `n_E`, then grinds it at the test width.
  6. `MI84`: the test width reaches production. Property 6 must fail. Killed by `TestProductionShowsSevenEmojiOnly`.
- [ ] **Step 4: commit.**

### Task 23: The grant, the self group, and the end of the link (W-lib)

- Consumes: Task 22; F1:658-664; SCOPE E5
- Produces, in `link.go` and `selfgroup.go` (new): the grant and N's identity; N's engine, rebuilt with credential = IRK (`device.go:456-457` builds it once today [m]); N in the self group; the link group, left by both sides under authority (a); the scenario `I1-grant-before-own-match`
- Also, from slice 1's review (LRI R84, L-2 and L-3): the self group survives a restart before its first add, either because what AddMember needs is persisted, or because the founding can be resumed, with a restart test; and Restore's re-founding fires only on the device that MADE the identity, never on a linked device waiting to join its self group, with a sibling test

**Behaviour.**
1. After both matches, E signs an addition naming N's key, or a base if E is a phrase device, and commits it to the self group. If a newer base overtakes the addition before that commit lands, E signs it again on that base and commits again (M5 AD2, M5:153 [m]; REDTEAM M5). A base under a later key of the chain is newer (Task 43).
2. Only then does E post the grant: {IskCert, the list, the chain, the self group's id, the salt, the names}. It holds no phrase key, and nothing made from the words (F1:662).
3. N takes the grant only after its own "They match", and only if the list names N's key under the certificate.
4. N persists its identity, rebuilds its engine, and posts a bound key package in the link group.
5. E adds N to the self group and posts that invite in the link group. N joins, then retires its box.

**Leaving the link group.** Each side leaves it through `ForgetGroup`'s leave path, with no owner question. A link group found at `Restore` with no live session is left the same way, since a session never outlives its process [c]. Self-group records are stored DURABLE [a].

- **Property 1.** N takes no grant before its own "They match", and none whose list does not name N's key under the certificate.
- **Property 2.** The grant is posted only after the list that names N is committed to the self group.
- **Property 3.** No grant carries the phrase key, or anything made from the words.
- **Property 4.** A link group is left when its session ends, by both sides, or at the next `Restore` if the process ended first. Nothing else is erased.
- **Property 5.** An addition that a newer base overtook before its commit is signed again on that base, so the grant names a list that continues the self group's newest base.

- [ ] **Step 1: tests first:**
  - `TestNoGrantIsTakenBeforeTheNewDevicesOwnMatch`; `TestTheGrantFollowsTheSelfGroupCommitThatNamesTheNewDevice`;
  - `TestAnApprovalOvertakenByANewerBaseIsSignedAgainOnIt`, in which a newer base lands between E's signature and E's commit;
  - `TestNoGrantCarriesAPhraseSecret`; `TestALinkGroupIsLeftWhenItsSessionEndsAndAtTheNextRestore`;
  - the scenario `I1-grant-before-own-match`; the erase gate's new sites, each under (a), printed with the complement.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI45`: N takes the grant before its own match (F1:1087). Property 1 must fail. Killed by `I1-grant-before-own-match`.
  2. `MI46`: N takes a grant whose list omits its key. Property 1 must fail. Killed by `TestNoGrantIsTakenBeforeTheNewDevicesOwnMatch`.
  3. `MI47`: the grant goes out before the self-group commit (F1:1067). Property 2 must fail. Killed by `TestTheGrantFollowsTheSelfGroupCommitThatNamesTheNewDevice`.
  4. `MI48`: the phrase key is placed in the grant (F1:1086). Property 3 must fail. Killed by `TestNoGrantCarriesAPhraseSecret`.
  5. `MI49`: a link group found at `Restore` is kept. Property 4 must fail. Killed by `TestALinkGroupIsLeftWhenItsSessionEndsAndAtTheNextRestore`.
  6. `MI85`: E retries the stale addition. Property 5 must fail. Killed by `TestAnApprovalOvertakenByANewerBaseIsSignedAgainOnIt`.
- [ ] **Step 4: commit.**

### Task 24: The self group's records, and Maintain (W-lib)

- Consumes: Task 23; content kinds 0x0A to 0x3F, which are free (`lib:sdk/urmessage/kind.go:70-106` [m])
- Produces, in `kind.go`, `selfgroup.go` and `maintain.go` (new): the registry of self-group kinds [a: their numbers fixed by Task 3]: device names; notices; key-package offers and claims; sibling invites, in parts of at most 60 KB; and a block of kinds kept for R. Also their refusal outside system groups, and `Device.Maintain`

**Order** (REDTEAM M12). List changes are ordered by the self group's commits. Records are application messages, so they keep the server's delivery order, which a lying server may show differently to each device [c]. R therefore carries a decision that must be first in order inside a commit (LRI R51; SCOPE §5.1).

- **Property 1.** A self-group record kind is refused in a conversation, and a conversation kind in a self group.
- **Property 2.** A self-group record is honoured only from a leaf the newest list names.

- [ ] **Step 1: tests first:** `TestASelfGroupRecordIsRefusedOutsideASystemGroup`; `TestASelfGroupRecordIsHonouredOnlyFromAListedDevice`; the kind registry's band test (`kind_test.go:363` [m]).
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI50`: the kind check is skipped for system kinds. Property 1 must fail. Killed by `TestASelfGroupRecordIsRefusedOutsideASystemGroup`.
  2. `MI51`: a record from a leaf the list does not name is honoured. Property 2 must fail. Killed by `TestASelfGroupRecordIsHonouredOnlyFromAListedDevice`.
- [ ] **Step 4: commit.**

### Task 25: Your devices bring a new device into your conversations (W-lib)

- Consumes: Task 24; M5 JN1, JN2 and JN8; F1:686-695; T1:263
- Produces, in `maintain.go`: fan-out; the scenario `I1-fanout-after-respected-removal`

**Behaviour.**
- **JN1.** The approver adds the new device to its own conversations at once.
- **JN2.** Every other device of yours, when it next runs, adds a listed device it finds missing, and removes a leaf the list no longer names. Your lowest leaf is the designated adder; the others act after 10 minutes.
- **The Add.** Each adder claims the sibling's offer, commits the Add (R6a, its own identity), and posts the invite in the self group, in parts.
- **The join.** The sibling joins with no tap, and only from an invite its own identity's device posted. Every expectation comes from its own store (T1:263). This anchors MG-1 for this road (`lib:messagegroup/OPENITEMS.md:49` [m]).
- **Limits.** No device re-adds a device that a commit not of its own identity removed (F1:691), and none passes the cap. A device that left a conversation keeps its leaf there (SCOPE G8), so fan-out never finds it missing (P1).

- **Property 1.** One device adds a missing sibling while the others wait their turn, and two that race leave one leaf.
- **Property 2.** No device is re-added into a conversation from which a commit not of its own identity removed it.
- **Property 3.** A sibling joins only from an invite that a device of its own identity posted in its self group.

- [ ] **Step 1: tests first:** `TestOneDeviceAddsTheNewSiblingAndTheOthersWaitTheirTurn`; `TestASiblingJoinsOnlyFromAnInviteItsOwnIdentityPosted`; the scenario `I1-fanout-after-respected-removal`.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI52`: every device adds at once. Property 1 must fail. Killed by `TestOneDeviceAddsTheNewSiblingAndTheOthersWaitTheirTurn`.
  2. `MI53`: fan-out ignores a removal another identity made (the shape of F1:1085). Property 2 must fail. Killed by `I1-fanout-after-respected-removal`.
  3. `MI54`: a sibling joins any invite in its self group. Property 3 must fail. Killed by `TestASiblingJoinsOnlyFromAnInviteItsOwnIdentityPosted`.
- [ ] **Step 4: commit.**

### Task 26: R8-SIB, "mine" and "from me", one person with several devices, and the notices (W-lib)

- Consumes: Task 25; F1:539; the five identity sites (`lib:sdk/urmessage/group.go:2783`, :3054, :5049-5054, :5664, :5800 [m]); M5 TR10; SCOPE H6
- Produces, in `identityrules.go`, `group.go` and `sdk/cgo/exports_message.go`: R8-SIB, with `ErrSiblingNotRevoked`; `Message.Mine` (this device sealed it) and `Message.FromMe` (any device of mine sealed it); `device_id`, `identity` and `from_me` in the member and message JSON, where `identity` is the leaf's root, its credential while its chain is empty (Task 42); the device-added and device-removed lines that contacts see; each device's notices, "⟨device⟩ was added / removed on ⟨date⟩ by ⟨device⟩", where an added device's notice offers Remove; and `not_a_member_yet` for a record from before this device joined (REDTEAM M2)

- **Property 1.** A leaf of the committer's own identity, other than the committer's own, is removed only if the newest list no longer names it.
- **Property 2.** "Mine" is true only of what this device sealed. "From me" is true of what any device of my identity sealed.
- **Property 3.** A record from before this device joined is answered `not_a_member_yet`, never `out_of_window` (REDTEAM M2). The walk already tells the two apart, and `not_a_member_yet` is one of the closed seven reasons (`lib:sdk/urmessage/group.go:250-262` [m]). The first draft's Property 3, a direct chat told by its identities, is the app's rule, and moved to Task 16 (REDTEAM M3).
- **Property 4.** Every addition and removal reaches every device's notices, with its date and its signer.

- [ ] **Step 1: tests first:** the R8-SIB rows; `TestMineIsThisDeviceAndFromMeIsAnyDeviceOfMine`; `TestARecordFromBeforeThisDeviceJoinedIsNotAMemberYet`; `TestEveryDeviceSeesEveryAdditionAndRemovalWithItsDateAndSigner`. `I1-sibling-evicts-sibling` and `I1-two-devices-one-person` (Task 8) flip, and their entries close in this commit. Task 8's removal control, in `TestAdvSimASiblingRemovesASiblingTheListStillNames`, gets the base that drops the phone, signed before the removal; unedited, R8-SIB refuses it, and the test fails as FAIL(HARNESS) (LRI R62). And `I1-two-devices-one-person`'s scene links pc2 to pc1 through the link box (Tasks 22 and 23) and brings it into the conversation by fan-out (Task 25) before the roster is read: as Task 8 wrote it, pc2 joins by its own join code, which under I1 makes a second account (LRI R68).
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI55`: R8-SIB is off (F1:1079). Property 1 must fail. Killed by `I1-sibling-evicts-sibling`.
  2. `MI56`: "mine" is decided on the identity (F1:1084). Property 2 must fail. Killed by `TestMineIsThisDeviceAndFromMeIsAnyDeviceOfMine`.
  3. `MI86`: a record from before this device joined answers `out_of_window`, as today. Property 3 must fail. Killed by `TestARecordFromBeforeThisDeviceJoinedIsNotAMemberYet`. (`MI57` is retired: today's leaf-count rule lives in the app, so its mutant is `MA10`, Task 16; REDTEAM M3.)
  4. `MI58`: a notice is raised only on the device that made the change. Property 4 must fail. Killed by `TestEveryDeviceSeesEveryAdditionAndRemovalWithItsDateAndSigner`.
- [ ] **Step 4: commit.**

### Task 27: The exports for slice 2, and the probe's link steps (W-lib)

- Consumes: Tasks 22 to 26
- Produces, in `sdk/cgo/exports_message.go`, `sdk/liveprobe/main.go` and `sdk/livepeer/main.go`: `_link_offer`, `_link_state`, `_link_enter_code`, `_link_emoji`, `_link_confirm` and `_link_cancel`; `_device_devices`, `_device_rename`, `_device_notices` and `_device_maintain`; four new probe steps; livepeer printing the roster by identity, and the contacts' lines

**The probe steps** print digests only:
1. A links a second device through the alpha's link box, and both sides' emoji are compared in process.
2. A2 has A's account ID, and a device ID of its own.
3. A2 joins A's conversation by fan-out and reads a canary, with no paste.
4. B sees one identity with two devices.

Step 11's second device becomes a linked one.

- **Property 1.** `_link_emoji` answers nothing before both reveals.

- [ ] **Step 1: tests first; the exports; the probe's `main_test.go`; the README's count.**
- [ ] **Step 2: the mutations.**
  1. `MI59`: `_link_emoji` answers after the first reveal. Property 1 must fail. Killed by `TestTheEmojiExportWaitsForBothReveals`.
- [ ] **Step 3: commit.**

### Task 28: The app, slice 2: the code, the emoji, and a second device (W-app)

- Consumes: Task 27's header; Task 6's screens
- Produces, in `Live/LiveMesh.cpp`, `Live/LiveWorld.cpp`, `Views/RosterRules.cpp`, `Views/ThreadView.cpp` and the setup and settings views: SCOPE H3, H4's Devices list, and H6, with their states (code shown, waiting, emoji, matched, granted, or one of five endings); the conversation adopted on the new device with no paste

**Behaviour.**
- "Set up this device" shows the code and waits. On the other device, Devices → Add a device takes the code.
- Both devices show the seven emoji with their names, and "They match" / "They don't match". One screen holds the five endings (SCOPE E6).
- The app holds one conversation (`app:Live/LiveMesh.cpp:2992-2998` [m]). On the new device, a conversation the library joined by fan-out is adopted as though it were restored.
- Rows show "· N devices", the contacts' line shows in the thread, and devices can be renamed.
- On a device that joined later, a run of records from before it joined shows as one line, "Sent before this device was added" [a: copy] (SCOPE F5; REDTEAM M2). Today each would draw a gap row (`app:Views/ThreadLayout.h:42-47` [m]). Spec C's copy for this reason is the history grant's banner, and the grant comes with I2 (`lib:sdk/urmessage/group.go:261` [m]). So Task 40 records I1's line in its place.
- Leaving a conversation says "on this computer": leave is per device in I1 (P1; SCOPE F3; REDTEAM M8). `verify-copy.ps1` holds the string.

- **Property 1.** Both screens of one session show the library's seven emoji, in order, and nothing before both reveals.
- **Property 2.** A conversation joined by fan-out opens on the new device with no paste box.
- **Property 3.** A run of `not_a_member_yet` records draws one line, never a gap row each.

- [ ] **Step 1: `--diagnose` cases and shot legs first.**
- [ ] **Step 2: the screens.** Two installs on one runner, linked to each other; shots, looked at.
- [ ] **Step 3: the mutations.**
  1. `MA6`: the emoji are drawn from a cached session. Property 1 must fail. Killed by the two-install leg.
  2. `MA7`: the worker waits only for a pasted invitation. Property 2 must fail. Killed by the fan-out leg.
  3. `MA11`: each record from before this device joined draws its own gap row. Property 3 must fail. Killed by its `--diagnose` case.
- [ ] **Step 4: commit; CI; smoke the zip as shipped.**

### Task 29: Close slice 2, and the owner's second session

- Consumes: Tasks 18 to 28
- Produces: the deployed link box, the runs, the report, and session 2

This task changes no file and states no property.

- [ ] **Step 1: the runs,** as in Task 17, on all three repositories.
- [ ] **Step 2: the review,** under the budget.
- [ ] **Step 3: the alpha (the lead).** The new server binary and its two migrations go on, with the database reset, after the owner is told (LRI R55). The probe runs with its new steps, and the server's own checks are as in Task 17.
- [ ] **Step 4: session 2, then the report.**

# Slice 3: remove a device, lock one out, make a phrase device

The owner's session 3 ends this slice (SCOPE §8 steps 8 to 13). Task 38b closes it.

### Task 30: Remove this device, and the end of an identity (W-lib)

- Consumes: Tasks 23 to 26; M5 RM1 and RM8; SCOPE G1 and G5; P2, P9 and P15
- Produces, in `sdk/urmessage/revoke.go` (new) and `identity.go`: `Device.RemoveThisDevice`; JN2's removal of the leaves the list no longer names; `Device.EndIdentity`, on an only device; the phrase key record's erase under (g), on a phrase device, before its self-removal or end, with neither act going ahead until it has succeeded (P9, P15; REDTEAM H2; T2-H1); the removed state, entered only when no phrase-secret record stands (P15); the scenario `I1-removed-device-acts-until-a-sibling-runs`

**Behaviour.**
- **A self-removal** is signed by the device's key and committed to the self group. It is never refused for want of a place (TR12). Your other devices remove its leaves when they run.
- **A phrase device erases its phrase key first** (P9; REDTEAM H2). On a phrase device, "Remove this device" and "This ends this identity" erase the phrase key record, under authority (g), before the self-removal is signed and sent. The disposition allows that key only on phrase devices (SCOPE A4; M5:127 [m]), and a removed or ended device is none. The self-removal is signed by the device key, so a send that fails can be signed and sent again (TR3) [c]. **If the erase fails** (another program holds or denies the file), nothing is signed or sent: the device stays a listed phrase device, the dialog says so in one sentence [a: copy], and the person acts again (P15; T2-H1).
- **On an only device** the dialog says "This ends this identity". Then, in order: the phrase key record, if this device holds one, is erased under (g), and if that fails nothing else happens; the identity record is marked ended; each conversation, and the self group, is left through authority (a); and the ended identity answers every call with `ErrIdentityEnded`. Nothing else is erased (P2).
- **A device whose newest list no longer names it** shows when, and by which device. It erases nothing else (M5 RM8). No device shows itself removed, or its identity ended, while a phrase-secret record of it stands, so Task 38 never leaves one behind in a folder it abandons; Tasks 32 and 43 add the removals another device makes (P15).

- **Property 1.** A self-removal, once sent, is always accepted, and every device of the identity, when it next runs, removes the leaves of a device the list no longer names.
- **Property 2.** An identity ended midway is still ended after a restart. Its conversations are left through authority (a), and nothing else is erased.
- **Property 3.** A removed device with an unaltered app stops itself at once. With an altered app it acts in a conversation only until a device of yours runs there.
- **Property 4.** A phrase device that removes itself, or ends its identity, holds no phrase key record afterwards, and the erase comes before anything of the act is sent.
- **Property 5.** Neither act goes ahead until its erase has succeeded: a failed erase signs, sends and ends nothing, and leaves a listed phrase device. No device shows itself removed or ended while a phrase-secret record of it stands (P15).

- [ ] **Step 1: tests first:**
  - `TestASelfRemovalIsAlwaysTakenAndYourOtherDevicesDropItsLeaves`;
  - `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret`, with record 13 held for real (a share-mode-0 hold on Windows, a deny on unix, as LR R34 item 11's tests did) at "Remove this device" and at "This ends this identity": nothing reaches the in-process server, record 13 stands, the device is still a listed phrase device, and once the hold ends the act goes. Tasks 32 and 43 add their cases;
  - `TestARemovedOrEndedPhraseDeviceKeepsNoPhraseKey`, with a forced stop between the erase and the send, and the authority table's (g) cells;
  - `TestAnIdentityEndedMidwayIsStillEndedAfterARestart`, with a forced stop between each pair of steps;
  - the residual scenario `I1-removed-device-acts-until-a-sibling-runs`, with the unaltered app as its control;
  - the authority table's (a)E cells.
- [ ] **Step 2: see them fail; the code; the erase gate's new (a) and (g) sites.**
- [ ] **Step 3: the mutations.**
  1. `MI60`: the ended mark is written after the leaves. Property 2 must fail. Killed by `TestAnIdentityEndedMidwayIsStillEndedAfterARestart`.
  2. `MI61`: JN2 keeps a leaf the list no longer names. Property 1 must fail. Killed by `TestASelfRemovalIsAlwaysTakenAndYourOtherDevicesDropItsLeaves`.
  3. `MI62`: an unaltered removed device goes on sending. Property 3 must fail. Killed by the scenario's control arm.
  4. `MI87`: "Remove this device" on a phrase device keeps the phrase key record. Property 4 must fail. Killed by `TestARemovedOrEndedPhraseDeviceKeepsNoPhraseKey`.
  5. `MI115`: the self-removal is sent although the (g) erase failed: the order with no failure path. Property 5 must fail. Killed by `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret`.
- [ ] **Step 4: commit.** T2-H1's residual, a deny that outlasts every start, goes to the store track under "Still open" in slice 3's pull request (SCOPE R17; LR R39, R45).

### Task 31: Remove another device, with the phrase as the second factor (W-lib)

- Consumes: Task 30; M5 RM2, TR3 and TR7; X1
- Produces, in `revoke.go`, `heads.go` and `identity.go`: `Device.RemoveDevices(targets, words)`; the remembered marks, in the heads; the words check, one helper in `identity.go` that RM2, RM6, AD5, a phrase change and the words-scoped hooks call first (REDTEAM H3); the scenario `I1-stolen-linked-device-removes`
- Also produces (LRI R72): the stored-seed signer. A phrase device without its words signs under ISK_g from the kind-13 record's `PhraseKeySeed(g)`, inside `messagegroup`, and no private half leaves the package. Its known answer equals `SignBase` under the words for the same g. It is built once, in whichever of Tasks 31 and 33 first needs it, and the other consumes it.

**Behaviour.**
- **Who asks for what.** A phrase device removes without the words. Any other device asks for them, and becomes a phrase device (TR7). One act may name several devices.
- **With D off it acts at once:** a new base under g without the targets, committed to the self group, then JN2 everywhere (M5:166).
- **A device key removes only itself** (TR3). Removing a phrase device from another device is always the lock-out (Task 32).
- **Marks.** Your devices remember every key marked as a phrase device under the current key and g, and refuse a list that names one of them without its mark (TR7).
- **The words are this identity's** (F1:637, :671 [m]; REDTEAM H3).
  - Before anything else, the helper derives IRK and compares it with the identity's current key, which is the root until a phrase change. Then it derives ISK_g and compares it with IskCert(g)'s key. Task 43 adds the answer for a retired key's words.
  - A mismatch answers one sentence: "These words are another account's recovery phrase, or a word is wrong". By then nothing is stored, signed, sent or erased.
  - Why this is the likely input [c]: the owner will hold one paper per fresh setup (M1), and the 8-bit checksum lets about one single-word slip in 256 through (OD:36 [m]).

- **Property 1.** Nothing a device key signs removes another device.
- **Property 2.** A device that is not a phrase device removes another only with the words, and is a phrase device afterwards.
- **Property 3.** A list that names a remembered phrase key without its mark is refused, even when a list in between left it out.
- **Property 4.** Words that are not this identity's change nothing. Every act that takes them refuses before it stores, signs, sends or erases anything.

- [ ] **Step 1: tests first:** `TestNothingADeviceKeySignsRemovesAnotherDevice`; `TestRemovingAnotherDeviceWithoutThePhraseKeyAsksForTheWords`; `TestAListThatDropsAPhraseDevicesMarkIsRefused`; the scenario `I1-stolen-linked-device-removes`.
  - `TestWordsOfAnotherIdentityChangeNothing`. It types a first identity's words into a second, and a one-word substitution that passes the checksum, found by a search over the 2,048 words. The store's listing must be byte-equal before and after. Tasks 32, 33 and 43 add their acts' cases.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI63`: a removal of another device signed by a device key is accepted, TR3's rejected design. Property 1 must fail. Killed by `I1-stolen-linked-device-removes`.
  2. `MI64`: a linked device removes another without the words. Property 2 must fail. Killed by `TestRemovingAnotherDeviceWithoutThePhraseKeyAsksForTheWords`.
  3. `MI65`: there is no memory of marks (M5:420). Property 3 must fail. Killed by `TestAListThatDropsAPhraseDevicesMarkIsRefused`.
  4. `MI88`: RM2 signs under an ISK_g derived from words whose IRK is not the identity's. Property 4 must fail. Killed by `TestWordsOfAnotherIdentityChangeNothing`.
- [ ] **Step 4: commit.**

### Task 32: Lock out a phrase device: a new key number (W-lib)

- Consumes: Task 31; M5 RM6, TR7 and H.4's order; SCOPE G3; authority (f); P15; D2 IL8 (D2:136 [m])
- Produces, in `revoke.go` and `identity.go`: `Device.LockOut(words, keep)` and `IskCert(g+1)`; the phrase key record's erase, on the target too, before it shows itself removed (P15); the words-scoped hooks, wired at AD1's `ConfirmWords` too (LRI R51); a lock-out that names no device, offered by the notice of a phrase device's self-removal (P9; REDTEAM H2); the scenario `I1-stolen-phrase-device-until-lockout`

**Behaviour.**
- **M5 H.4's order:**
  1. the words, checked by Task 31's helper (REDTEAM H3);
  2. the dialog, over every device this device's list names: keep or remove each;
  3. mint g+1, and seal and store its seed and its certificate before anything is sent;
  4. the first base under g+1, naming the kept devices, with this one as the phrase device;
  5. the commit to the self group, then JN2.
- **Other phrase devices.** A phrase device that sees a verified certificate for a number higher than its record's own erases that record (authority (f)), and must type the words again (TR7).
- **The lock-out's target** erases its record the same way before it shows itself removed, as TR7 has every phrase device do on a higher number (M5:141 [m]). While that erase fails it shows when and by which device it was removed, says that this device could not finish leaving [a: copy], and tries again at each start (P15; T2-H1).
- **Hooks** (D2 IL8; LRI R51). The registered hooks run after the words pass the check and before they are erased, for R (SCOPE §5.1). They run at RM6 and AD5, at AD1's `ConfirmWords` after the identity is made, and at a phrase change (Task 43). No hook is registered in I1; tests register one of their own.
- **A phrase device that removed itself** (P9; REDTEAM H2).
  - Every device that sees the self-removal of a device its list marks as a phrase device shows the notice: "⟨device⟩ held your recovery phrase's key and removed itself. If this was not you, lock it out."
  - Its button opens this lock-out with no listed target. Every device is offered as kept, and the new key number retires every key under g. A copy of that device's key, taken before it removed itself, then signs nothing your devices follow.
  - M5 cut a lock-out that names no device because the server's table covered this case (MP-02, M5:430 [m]). I1 has no such table (SCOPE X10).

- **Property 1.** Removing a phrase device always makes the next key number, and every device that has seen the new number refuses the old key's lists.
- **Property 2.** The new seed and certificate are stored before anything of the lock-out is sent.
- **Property 3.** The phrase key record is erased only when its own key number is below a verified certificate's. A retired record that is put back is erased again before it signs anything.
- **Property 4.** The words-scoped hooks run before the words are erased, and cannot run outside that scope.
- **Property 5.** A lock-out needs no listed target, and the self-removal of a device marked as a phrase device offers one.
- **Property 6.** A lock-out given words that are not this identity's mints, stores and sends nothing.
- **Property 7.** At AD1's `ConfirmWords` the words-scoped hooks run once, after the identity is made and before the words are erased.
- **Property 8.** A lock-out's target shows itself removed only after its phrase key record is erased, and a failed erase is tried again at each start.

- [ ] **Step 1: tests first:**
  - `TestRemovingAPhraseDeviceAlwaysMakesTheNextKeyNumber`;
  - `TestAPhraseDevicesSelfRemovalOffersALockOutThatNamesNoDevice`; the RM6 case of `TestWordsOfAnotherIdentityChangeNothing`;
  - `TestALockOutStoresItsKeyBeforeAnythingIsSent`, with a forced stop at each step;
  - `TestThePhraseKeyIsErasedOnlyWhenItsOwnNumberIsBelowTheNewest`, with the authority table's (f) cells as real moves, holds and put-backs;
  - `TestTheWordScopedHooksRunBeforeTheWordsAreErased`; `TestTheWordScopedHooksRunAtConfirmWordsBeforeTheWordsAreErased`;
  - the lock-out case of `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret`: PC-1 locked out from PC-2, once as it stands and once with its record held;
  - the residual scenario `I1-stolen-phrase-device-until-lockout`, whose control is the lock-out.
- [ ] **Step 2: see them fail; the code; the erase gate's (f) row.**
- [ ] **Step 3: the mutations.**
  1. `MI66`: a phrase device is removed under the same key number (M5:420). Property 1 must fail. Killed by `TestRemovingAPhraseDeviceAlwaysMakesTheNextKeyNumber`.
  2. `MI67`: the base is sent before the key is stored. Property 2 must fail. Killed by `TestALockOutStoresItsKeyBeforeAnythingIsSent`.
  3. `MI68`: the erase does not read the record's own number. Property 3 must fail. Killed by `TestThePhraseKeyIsErasedOnlyWhenItsOwnNumberIsBelowTheNewest`.
  4. `MI69`: a phrase device keeps its old key after seeing g+1. Property 3 must fail. Killed by the same test.
  5. `MI70`: the hooks run after the erase. Property 4 must fail. Killed by `TestTheWordScopedHooksRunBeforeTheWordsAreErased`.
  6. `MI89`: RM6 mints g+1 from words whose IRK is not the identity's. Property 6 must fail. Killed by the RM6 case of `TestWordsOfAnotherIdentityChangeNothing`.
  7. `MI90`: a lock-out with no listed target is refused, the design M5 cut (M5:430). Property 5 must fail. Killed by `TestAPhraseDevicesSelfRemovalOffersALockOutThatNamesNoDevice`.
  8. `MI94`: `ConfirmWords` erases the words with no hook run, the design before LRI R51. Property 7 must fail. Killed by `TestTheWordScopedHooksRunAtConfirmWordsBeforeTheWordsAreErased`.
  9. `MI116`: a lock-out's target shows itself removed and keeps its record: P2's "erases nothing" read over (f). Property 8 must fail. Killed by the lock-out case of `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret`.
- [ ] **Step 4: commit.**

### Task 33: Make this a phrase device; folding; the pool of 16 (W-lib)

- Consumes: Task 32; M5 AD5, TR5 and TR12
- Produces, in `identity.go` and `maintain.go`: `Device.MakePhraseDevice(words)`, which also runs the words-scoped hooks; folding, in `Maintain`; the stored-seed signer, if Task 31 has not built it (LRI R72)

- **Property 1.** A device becomes a phrase device only with words whose key matches the current certificate, as Task 31's helper checks (REDTEAM H3).
- **Property 2.** A phrase device that runs folds every waiting change into a new base. An approval past 16 waiting changes is refused, with its named ending.

- [ ] **Step 1: tests first:** `TestMakingAPhraseDeviceChecksTheKeyAgainstTheCertificate`; `TestAPhraseDeviceFoldsWaitingChangesAndTheSeventeenthWaits`; the AD5 case of `TestWordsOfAnotherIdentityChangeNothing`.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI71`: there is no check against the certificate. Property 1 must fail. Killed by `TestMakingAPhraseDeviceChecksTheKeyAgainstTheCertificate`.
  2. `MI72`: a phrase device never folds. Property 2 must fail. Killed by `TestAPhraseDeviceFoldsWaitingChangesAndTheSeventeenthWaits`.
- [ ] **Step 4: commit.**

### Task 34: The alarm, and the removed device's screen (W-lib)

- Consumes: Tasks 30 to 33; M5 TR11 and RM8; P7
- Produces, in `heads.go` and `identity.go`: the alarm, with its two reasons; this device's own-signature log, in the heads; `ErrRemovedFromAccount`, saying when and by which device; `I1-copy-adds-unnoticed`, flipped

**Behaviour.** The alarm has two reasons: a list this device cannot explain; and a change signed with this device's key that this device did not make, read from its own-signature log. Its sentence says that the second can also follow restoring this device's files (P7).
- **What it covers, and offers** (REDTEAM L3). The second reason covers list changes signed with this device's key. It does not cover self-group records or leaves, and the alarm's text does not claim them. In slice 3 the alarm offers "Check my devices" and the lock-out. Slice 4 adds M5's third offer, "Change my recovery phrase", where a change can help (Task 43; M5 TR11, M5:145 [m]; T2-H2).
- **A forked self group** raises the first reason (REDTEAM M6). Its sentence names I1's one remedy: on another device of yours, remove that device and add it again.

- **Property 1.** Each of the alarm's two reasons raises it: a list this device cannot explain, a fork included, and a change signed with this device's key that it did not make. A change it did make never does, including after a restart.
- **Property 2.** A removed device says when, and by which device, and still says so after a restart.

- [ ] **Step 1: tests first:** `TestAListThisDeviceCannotExplainRaisesTheAlarm`; `TestACopyThatSignsAChangeRaisesTheAlarmAndTheOriginalsOwnNever`; `TestARemovedDeviceSaysWhenAndByWhichDeviceAfterARestart`. `I1-copy-adds-unnoticed` (Task 8) flips, and its entry closes.
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI73`: no alarm for a change signed with this device's key (M5:145). Property 1 must fail. Killed by `I1-copy-adds-unnoticed`.
  2. `MI74`: the own-signature log is kept in memory only. Property 1 must fail. Killed by the restart arm of `TestACopyThatSignsAChangeRaisesTheAlarmAndTheOriginalsOwnNever`.
  3. `MI75`: the removed state is lost at a restart. Property 2 must fail. Killed by `TestARemovedDeviceSaysWhenAndByWhichDeviceAfterARestart`.
- [ ] **Step 4: commit.**

### Task 35: Moved to R (P10)

This task built R's interface against DESIGN-v1: the identity proof, `VerifyKeyPackageBinding`, the two signers, the two derivers and the three events. The lead took P10, so R writes them against D2 §2.0 (LRI R50, R51). Its id is retired, with its mutants `MI76` and `MI77`, so that no id changes its meaning. The words-scoped hooks stay in I1 (Tasks 32, 33 and 43).

### Task 36: The exports for slice 3, and the probe's removal steps (W-lib)

- Consumes: Tasks 30 to 34
- Produces, in `sdk/cgo/exports_message.go` and `sdk/liveprobe/main.go`: `_device_remove_this`, `_device_remove_devices`, `_device_lock_out`, `_device_make_phrase_device` and `_device_alarm`, and the removed state in `_device_identity`; three new probe steps: a sibling's eviction, refused by every member; a removal; a lock-out, after which the old key's list is refused

- **Property 1.** The words passed to an export are erased before it returns, on every path.

- [ ] **Step 1: tests first; the exports; the probe; the README's count.**
- [ ] **Step 2: the mutations.**
  1. `MI78`: an export's error path keeps the words. Property 1 must fail. Killed by `TestEveryExportThatTakesTheWordsErasesThemOnEveryPath`.
- [ ] **Step 3: commit.**

### Task 37: Not built (P1)

Identity-wide leave stays with I2: the lead's P1 stood, and the owner kept the default, leave on that computer only (LRI R50, R56; OWN:529 [m]). Its id is retired, with `MI79`, `MI80` and authority row (a)S. A left device's leaf stays until an admin removes it, as today, so fan-out never finds it missing, and Task 25's rule keeps it out after an admin's removal [c]. The leave dialog says "on this computer" (Task 28).

### Task 38: The app, slice 3 (W-app)

- Consumes: Task 36's header
- Produces, in `Views/SettingsView.cpp`, the setup views and `Live/LiveMesh.cpp`: SCOPE H5, with its states (dialog, phrase asked, removing, done; removed): the Remove dialog (every device, several at once, the phrase field when needed, and the only-device line "This ends this identity"); the lock-out's keep-or-remove; "Make this a phrase device"; "This device is no longer on your account", with when, by which device, and "Add this device again"; the notices, where a phrase device's self-removal offers "Lock it out" (P9), and the alarm; a fresh store folder after an end or a removal (P2), and a folder for this slice's build (M1); the sentence of a device that could not finish leaving, which keeps its folder, with its `--diagnose` case (P15)

- **Property 1.** After the library reports an identity ended or this device removed, which it does only once no phrase secret is left (P15), the app opens a fresh store folder at once, and never opens the old one again.
- **Property 2.** The phrase field shows only when the library asks for the words.

- [ ] **Step 1: `--diagnose` cases and shot legs first.**
- [ ] **Step 2: the screens; shots, looked at; `verify-copy.ps1` over the new strings.**
- [ ] **Step 3: the mutations.**
  1. `MA8`: the app reopens the newest folder that holds a store, whether ended or not. Property 1 must fail. Killed by the end-and-restart leg.
  2. `MA9`: the phrase field always shows. Property 2 must fail. Killed by its `--diagnose` case.
- [ ] **Step 4: commit; CI; smoke the zip as shipped.**

### Task 38b: Close slice 3, and the owner's third session

- Consumes: Tasks 30 to 34, 36 and 38
- Produces: the slice's runs, its report, and session 3

This task changes no file and states no property.

- [ ] **Step 1: the runs,** as in Task 17, on all three repositories: every mutant of the slice, two-phase, and the authority table's cells for (a)E, (f) and (g), column 11 included.
- [ ] **Step 2: the review,** under the budget.
- [ ] **Step 3: the alpha (the lead):** the database reset, as for every slice (REDTEAM M1); the probe with its removal steps; the server's own checks.
- [ ] **Step 4: session 3, then the report "At the end of slice 3".**

# Slice 4: change the recovery phrase with the old one

The owner's answer, "No, in phase 1" (LRI R56.1), is this slice. The owner's session 4 ends it, and with it I1 (SCOPE §8 steps 14 to 17). W-lib starts Task 42 while slice 3 closes. Tasks 39 to 41, which close I1, follow Task 45.

### Task 42: The move in place: a retired key's leaves judged as the new key's, in every tree (W-lib)

- Consumes: Task 11's chain and `VerifyIdentityChain`; Tasks 13, 24 and 26; F1:551-570 [m], R6s shape (i) only; V4's rank rule (V4:317-318 [m]) and W4 (V4:1064 [m]); M5 PC3 and PC4 (M5:186-187 [m]); the role pipeline, whose R6c refuses every identity change, the committer's own path included (`lib:sdk/urmessage/roles.go:192-214` [m])
- Produces, in `identityrules.go`, `roles.go`, `heads.go` and `group.go`: R6s shape (i), with `ErrSuccessionInvalid` and `ErrSuccessionRoleConflict` (F1:542 [m]); the rank rule over every tree; the refusal of a second successor, `ErrSuccessionConflict` [a]; R9 reading a system group's key through the chain; the heads kept per root; `Mine` and `FromMe` through this identity's chain; each person's `identity` in the member JSON as its root; the scenario `I1-forged-succession`

**Behaviour** (SCOPE K5 to K7).
- **R6s, shape (i)** (F1:554 [m]). A committer's own leaf may go from key X to key Y, with the same signature key, only when its post-commit leaf carries a chain from the root through X to Y that `VerifyIdentityChain` passes, and Y's list names that signature key. At most one per commit. Shape (ii), an admin's re-add of a lost device, is not built: I1 has no road for it (SCOPE §4). The alias is computed before every other rule, R8-CUR and R8-SIB included (F1:551 [m]; T2-L2).
- **Its effect** (F1:561-570 [m]). X→Y is applied to every member's identity, the committer's, and the policy's role entries, kept in canonical order; R0b, R4, R5 and R7 compare the aliased lists. A move commit re-encodes the policy where it names X. A policy that names two keys of one chain is refused: no role merge. The policy keys roles on the identity (`lib:mls/group_policy.go:97-105`, :490-497 [m]), and today's R6c refuses any move (`roles.go:200-214` [m]), so without this rule an owner who changed the phrase would lose the group's ownership [c].
- **The rank rule** (V4:317 [m]). In any tree, a leaf under a key that some leaf's verified chain shows retired is judged as a leaf of that chain's newest key, by its list, and a policy entry for it as that key's. No list under a retired key is taken.
- **One successor per key** (V4:1064 [m]: "a permanent conflict"). A commit or a Welcome whose tree would hold two different successors of one key is refused. The first into a tree shuts the other out (V4:318 [m]).
- **R9** matches a system group's 0xF006 key through the chain, so the self group moves in place (SCOPE X13).
- **The heads** are kept per root (SCOPE C7), and a list under a later key of the root's chain is newer (Task 11's order). **The doors** read the chain: the Add and Join doors refuse a key package or a Welcome whose chain rivals one this device holds.
- **Mine and from me.** Task 26's identity sites read "my identity" as every key of this identity's chain [c].
- **The sending side** (Task 13, Property 8) runs all of it over the would-be tree. **Tests first** use chains made from test phrases, since the act is Task 43's [c].

- **Property 1.** A committer's own leaf moves from one key to another only with a chain from the root, in the post-commit tree, signed at each step by the key before it, whose newest key's list names the committer's signature key.
- **Property 2.** After a move, every leaf and policy entry under a retired key of that chain is judged as the chain's newest key's, and no list under a retired key is taken.
- **Property 3.** A move keeps every role: the new key holds what the old one held, nobody else's role changes, and a policy naming two keys of one chain is refused.
- **Property 4.** No tree ever holds two different successors of one key.
- **Property 5.** A self group takes a leaf of its root's successor, and still no stranger.
- **Property 6.** "Mine" holds for what this device sealed, and "from me" for what any device of this identity sealed, under any key of its chain.
- **Property 7.** A person's leaves under two keys of one chain answer one identity, its root.

- [ ] **Step 1: tests first:**
  - the rule rows of R6s and of the second-successor refusal, both arms; `TestAMoveInPlaceNeedsAChainSignedAtEveryStepByTheKeyBefore`; `TestALeafUnderARetiredKeyIsJudgedByTheNewestKeysList`, with a moved device committing beside a sibling still under the old key, which neither R8-CUR nor R8-SIB takes;
  - `TestAMoveKeepsEveryRoleAndChangesNoOneElses`: an owner, an admin and a member each move, and a policy naming both keys is refused;
  - `TestTwoSuccessorsOfOneKeyNeverStandInOneTree`, at a commit, at the Add door and at the Join door;
  - `TestASelfGroupTakesItsRootsSuccessorAndNoStranger`; `TestMineAndFromMeHoldUnderEveryKeyOfTheChain`; `TestOnePersonUnderTwoKeysOfOneChainIsOneIdentity`;
  - the scenario `I1-forged-succession`, registered closed. A stolen linked device of Alice's moves its own leaf to its holder's key, with a step that key signed itself, and every member refuses it. On Task 36's commit R6c refuses every move, so the scenario passes there, and its red is its mutant (gate 5).
- [ ] **Step 2: see them fail; the code.**
- [ ] **Step 3: the mutations.**
  1. `MI95`: the step's signature is not checked. Property 1 must fail. Killed by `I1-forged-succession`.
  2. `MI96`: a list under a retired key is taken after the move. Property 2 must fail. Killed by `TestALeafUnderARetiredKeyIsJudgedByTheNewestKeysList`.
  3. `MI97`: the policy is not aliased, so the role stays with the retired key. Property 3 must fail. Killed by `TestAMoveKeepsEveryRoleAndChangesNoOneElses`.
  4. `MI98`: a policy naming two keys of one chain is taken, a role merge. Property 3 must fail. Killed by the same test.
  5. `MI99`: two successors of one key both stand. Property 4 must fail. Killed by `TestTwoSuccessorsOfOneKeyNeverStandInOneTree`.
  6. `MI100`: R9 matches the self group's key by equality only, the design under which F1 founds a new self group (F1:746 [m]). Property 5 must fail. Killed by `TestASelfGroupTakesItsRootsSuccessorAndNoStranger`.
  7. `MI101`: "mine" is decided on the current key only. Property 6 must fail. Killed by `TestMineAndFromMeHoldUnderEveryKeyOfTheChain`.
  8. `MI102`: `identity` is a leaf's credential, not its root. Property 7 must fail. Killed by `TestOnePersonUnderTwoKeysOfOneChainIsOneIdentity`.
  9. `MI119`: the alias runs after R8-CUR and R8-SIB. Property 2 must fail. Killed by the sibling case of `TestALeafUnderARetiredKeyIsJudgedByTheNewestKeysList`.
- [ ] **Step 4: commit.**

### Task 43: Change the recovery phrase with the old one (W-lib)

- Consumes: Task 42; Tasks 31 to 34 (the words helper, the hooks, authority (f), the alarm); Task 10's phrase and keys; M5 PC1, PC2 and H.4's PC1 order (M5:184-185, :408 [m]); V4's B.5 F2 and F4 (V4:306, :308 [m]) and its form-1 step (V4:1011-1012 [m]); D2 IL1, IL2 and IL8 (D2:128-136 [m]); P14 and P15
- Produces, in `identity.go`, `selfgroup.go`, `maintain.go` and `revoke.go`: `Device.ChangePhrase(oldWords)`, which answers the new words once, and `Device.ConfirmNewWords(words)`; the move, stored before it is sent; the chain in the identity record; every other device taking the change from its self group and moving itself in every group it is in; the phrase key records replaced, under (f)P; a void change's key erased, under (i); the hooks at a change; the old paper named; the alarm's offer only where a change can help (T2-H2); MG-18; the scenarios `I1-phrase-change-in-place`, `I1-old-phrase-after-change` and `I1-server-withholds-a-phrase-change`

**Behaviour: H.4's PC1 order, less the backup** (M5:408 [m]; SCOPE K1, K2, K6 and K8; X11).
1. **The old words.** Task 31's helper checks them against the current key and its certificate. Nothing is stored before they pass. Any open link session on this device is cancelled first, which leaves its link group under (a) (Task 23).
2. **The new words.** They are made here (Task 10), shown once, and typed back in full (M5 rows 7 and 8). Back shows the same words, and a restart makes new ones, as at AD1 (M5:405 [m]).
3. **Sign and store the move, before anything is sent** (V4:306 [m]): the new key; the step, `Ed25519(old key, LP("URmessage/v1/identity-succession") ‖ LP(new key))` (V4:1012 [m]); IskCert(1) under the new key; its first base, naming every device of the old key's newest list as it stands, with this device the only phrase device ("A phrase change removes no device", V4:308 [m]); and the new key record. Then the old key's record is erased under (f)P, and the hooks run with both keys in scope (D2 IL8). Then both sets of words are erased.
4. **Publish:** this device's move in its self group (Task 42), with the policy re-encoded. A change stopped after step 3 resumes here, with no words (V4:306 [m]).
5. **The race** (SCOPE K8). If the self group took another commit first:
   - a lock-out, a removal or a self-removal under the old key: the first base is rebuilt on the old key's newest list, signed again with the new key, and published;
   - another change of the old key, or a list that no longer names this device: the change is void. Nothing is sent, the new key record is erased under (i) (where the void is this device's removal, before it shows itself removed: P15), and the toast says "Your recovery phrase was not changed: ⟨reason⟩. Destroy the paper with the new words."

**Every other device** takes the change only from its self group (M5 TR8, M5:142 [m]). It checks the chain from its own current key, and finds its key in the new list. It records the new key, erases its old phrase key record under (f)P if it holds one, rebuilds its engine as Task 23 does, and makes its key packages and offers again. Then it moves itself in place, in its self group first and then in every conversation, the next time it runs (M5 PC4).
- An addition or self-removal it signed on the old key's base is signed again on the new one (Task 23's rule).
- An act that took the old words and lost the race sends nothing, erases what it stored under (f)P, and says "Your recovery phrase was changed on ⟨device⟩ just before, so this did not happen. Do it again with the new phrase." TR7's memory of marks starts again under the new key (M5:141 [m]).

**The old paper.** The helper answers the words of a retired key of this identity's chain with "These are the words of a recovery phrase this account no longer uses. Use your newest one.", and changes nothing.
**The alarm.** A second successor of a key of this identity's chain, seen anywhere, raises the alarm's first reason (Task 34). Its sentence says that someone holds one of this account's recovery phrases [a: copy]. For a successor of the current key it also offers "Change my recovery phrase" (M5 TR11). For an earlier key's it does not, since a change cannot undo it: it says so, and that a fresh ID comes only from ending this identity and setting up again (SCOPE R2, R3; T2-H2).
**Contacts** are asked nothing and shown no line (M5 PC5).

- **Property 1.** Only the current key's words change the phrase. Another account's words, or a retired key's, change nothing, and a retired key's words are named as such.
- **Property 2.** The move is stored before anything of it is sent, and a change stopped after that resumes with no words.
- **Property 3.** "Your ID" and every device ID are the same after a change.
- **Property 4.** The new key's first list names every device the old key's newest list named, with only this device marked as a phrase device.
- **Property 5.** After a change, no device keeps a phrase key record of the old key.
- **Property 6.** Every device of the identity moves itself in place, in its self group and in every conversation it is in, the next time it runs.
- **Property 7.** A change that lost its race to a lock-out, a removal or a self-removal is rebuilt on the newest list. One that lost to another change, or whose device was removed, sends nothing and keeps no key, and its device shows itself removed only once that key is erased (P15).
- **Property 8.** The words-scoped hooks run once at a change, with both keys in scope, after the move is stored and before either set of words is erased.
- **Property 9.** A device takes its own identity's change only from its self group. Seen first in a conversation, the change raises the alarm and moves nothing of this device.
- **Property 10.** Contacts see one person throughout a change, and no line.
- **Property 11.** The alarm for a second successor offers "Change my recovery phrase" only for a successor of the current key. For an earlier key's, its sentence says a change cannot undo it.

- [ ] **Step 1: tests first:**
  - `TestAPhraseChangeTakesOnlyTheCurrentWordsAndNamesTheOldPaper`, with the RM2, RM6 and AD5 cases of the old paper;
  - `TestAPhraseChangeIsStoredBeforeItIsSentAndResumesWithNoWords`, with a forced stop at each step; `TestAPhraseChangeKeepsYourIdAndEveryDeviceId`;
  - `TestTheNewKeysFirstListNamesEveryDeviceAsItStood`, which also holds that the old marks go without tripping TR7's memory;
  - `TestNoDeviceKeepsTheOldKeyAfterAChange`, with the (f)P cells as real moves, holds and put-backs; `TestTheWordScopedHooksRunAtAChangeWithBothKeys`;
  - `TestEveryDeviceMovesItselfInEveryGroupItIsIn`, also with a device that missed two changes, which moves in one commit (SCOPE X12);
  - `TestAChangeThatLostItsRaceIsRebuiltOrVoid`: a lock-out, a removal, a self-removal, a second change and this device's own removal, each landing first; with the (i) cells; `TestTheAlarmOffersAPhraseChangeOnlyWhereOneCanHelp`, with a rival of the current key and one of the root after two changes;
  - Task 43's case of `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret` (Task 30): this device's own removal lands first while its new key record is held for real, and the device shows itself removed only once that record is erased under (i), retrying at each start (P15; review D2, LRI R62);
  - the scenario `I1-phrase-change-in-place`, registered closed. Alice has two devices, a DM with Bob, and a group with Bob and Carol that Alice owns. Alice changes the phrase on PC-1. Bob and Carol see one person throughout, and no line; Alice still owns the group, and Alice's account ID is the same. Red by its mutant `MI113`; its control turns R6s off (Task 42), and then every move is refused;
  - the scenario `I1-server-withholds-a-phrase-change`, registered closed. The server withholds the move from PC-2's self group while PC-1 has moved in a conversation. PC-2 raises the alarm, sends nothing there that members refuse, and moves once its self group shows the change. Red by its mutant;
  - the residual scenario `I1-old-phrase-after-change` (SCOPE R3). The holder of the old paper, and a copy of a phrase device made before the change, each sign a list under the old key. Every member of a group where the step stands refuses it; a group where no device of Alice's has run since takes it. Its control is that group after a device of Alice's has run there. After a second change, the first paper's own rival change is taken in such a group too (T2-M2).
- [ ] **Step 2: see them fail; the code; the erase gate's (f)P and (i) sites.**
- [ ] **Step 3: the mutations.**
  1. `MI103`: the move is sent before it is stored, H.4's order turned round. Property 2 must fail. Killed by `TestAPhraseChangeIsStoredBeforeItIsSentAndResumesWithNoWords`.
  2. `MI104`: the account ID is taken over the current key instead of the root. Property 3 must fail. Killed by `TestAPhraseChangeKeepsYourIdAndEveryDeviceId`.
  3. `MI105`: the new first list names only this device, the shape of F1's restore (F1:734 [m]). Property 4 must fail. Killed by `TestTheNewKeysFirstListNamesEveryDeviceAsItStood`.
  4. `MI106`: a phrase device keeps its old key record after it verifies the step. Property 5 must fail. Killed by `TestNoDeviceKeepsTheOldKeyAfterAChange`.
  5. `MI107`: a device moves in a conversation only when it next commits there for another reason. Property 6 must fail. Killed by `TestEveryDeviceMovesItselfInEveryGroupItIsIn`.
  6. `MI108`: a void change is sent anyway. Property 7 must fail. Killed by `TestAChangeThatLostItsRaceIsRebuiltOrVoid`.
  7. `MI109`: a void change keeps its new key record. Property 7 must fail. Killed by the same test.
  8. `MI110`: at a change the hooks see only the new key. Property 8 must fail. Killed by `TestTheWordScopedHooksRunAtAChangeWithBothKeys`.
  9. `MI111`: a device takes its own change from a conversation, TR8's rejected design. Property 9 must fail. Killed by `I1-server-withholds-a-phrase-change`.
  10. `MI112`: the old paper is answered as another account's, REDTEAM H3's one sentence. Property 1 must fail. Killed by `TestAPhraseChangeTakesOnlyTheCurrentWordsAndNamesTheOldPaper`.
  11. `MI113`: a move raises "added a device" and "removed a device" for the person. Property 10 must fail. Killed by `I1-phrase-change-in-place`.
  12. `MI117`: a device whose removal made its change void shows itself removed while its new key record stands. Property 7 must fail. Killed by Task 43's case of `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret` (review D2, LRI R62).
  13. `MI118`: the alarm offers "Change my recovery phrase" for a rival of an earlier key: M5 TR11's offer kept where it cannot help. Property 11 must fail. Killed by `TestTheAlarmOffersAPhraseChangeOnlyWhereOneCanHelp`.
  14. `MI120`: the change re-mints the salt (T2-L1). Property 3 must fail. Killed by `TestAPhraseChangeKeepsYourIdAndEveryDeviceId`.
- [ ] **Step 4: commit, with MG-18 filed in `messagegroup/OPENITEMS.md`:** a copy made between a void change's store and its erase keeps a rival step and its key, and can move a conversation the true change has not reached (two conditions; (i)'s column 10); and a server that forks the self group at a change leaves devices on two keys, with the alarm, until one is removed and added again (MG-16's shape; (i)'s column 8).

### Task 44: The exports for slice 4, and the probe's phrase-change steps (W-lib)

- Consumes: Tasks 42 and 43
- Produces, in `sdk/cgo/exports_message.go`, `sdk/liveprobe/main.go` and `sdk/livepeer/main.go`: `_device_change_phrase`, which answers the new words once, and `_device_confirm_new_words`; in `_device_identity`, the number of changes; the alarm's offers, as the library names them; three probe steps; livepeer printing each person by root

**The probe steps** print digests only, with the old and the new phrase made as a person makes them (LRI R81):
1. A changes its phrase on A1. A's account ID and every device ID are unchanged.
2. A2 moves in place in the self group and in the conversation, and B sees one identity, with two devices, before and after.
3. A list signed under A's old key is refused by every member, and A2 refuses the old words with the old paper's sentence.

The transcript check also refuses the new words and their entropy.

- **Property 1.** The words passed to or answered by these exports, old and new, are erased before they return, on every path, and no other export or log carries them.

- [ ] **Step 1: tests first; the exports; the probe's `main_test.go`; the README's count.**
- [ ] **Step 2: the mutations.**
  1. `MI114`: `_device_change_phrase` keeps the new words in its buffer after it returns. Property 1 must fail. Killed by `TestEveryExportThatTakesTheWordsErasesThemOnEveryPath`, extended to these exports.
- [ ] **Step 3: commit.**

### Task 45: The app, slice 4: Change my recovery phrase (W-app)

- Consumes: Task 44's header; the word screens of Task 16 and the phrase field of Task 38
- Produces, in `Views/SettingsView.cpp`, the setup views and `Live/LiveMesh.cpp`: "Change my recovery phrase" on Settings → Account (SCOPE X14); the old words in the phrase field (M5 row 5), and the new words once, then typed back (rows 7 and 8), with their states (old words asked, new words shown, typing back, changing, done, void); the done toast, naming the devices that no longer keep the phrase's key (V4:313 [m]); the void toast; the old paper's sentence in the field; "Change my recovery phrase" among the alarm's offers when the library names it (T2-H2); a folder for this slice's build (M1)

**Behaviour.**
- The change's word screens keep every protection Task 16 gives the words: excluded from capture, no spelling or prediction, masking, no clipboard history, and the remote-session warning (F3:894-900 [m]).
- The done toast [a: copy]: "Recovery phrase changed. Your ID and your devices are the same. ⟨device⟩ no longer keeps your phrase's key: type the new phrase there to make it a phrase device again."
- A change is not an end: the app keeps its folder, since Task 38's fresh folder is for an end or a removal only. Rosters group a person by `identity`, the root, never by a leaf's key (Task 42).

- **Property 1.** The change's word screens capture black, and no other screen does.
- **Property 2.** "Your ID" is the same before and after a change, character for character.
- **Property 3.** A contact whose phrase changed stays one person, with no line.
- **Property 4.** The alarm shows "Change my recovery phrase" only when the library offers it.

- [ ] **Step 1: `--diagnose` cases and shot legs first:** the screens' capture flags; the states; "Your ID" across a change; a roster with one person's leaves under two keys of one chain; an alarm for an earlier key's rival.
- [ ] **Step 2: the screens; shots, looked at; `verify-copy.ps1` over the new strings.**
- [ ] **Step 3: the mutations.**
  1. `MA12`: capture exclusion is off on the new words' screen. Property 1 must fail. Killed by the black-capture shot.
  2. `MA13`: the app treats a change as an end, and opens a fresh folder. Property 2 must fail. Killed by its `--diagnose` case.
  3. `MA14`: the roster groups by each leaf's `identity_pub`. Property 3 must fail. Killed by the `--diagnose` roster of one person under two keys.
  4. `MA15`: the app shows "Change my recovery phrase" on every alarm. Property 4 must fail. Killed by the `--diagnose` case of an earlier key's rival.
- [ ] **Step 4: commit; CI; smoke the zip as shipped.**

### Task 39: Every mutant, the authority table, and the pre-merge review

- Consumes: every mutation stated in Tasks 6 to 45; the authority table; the three branches at their heads, named as repo@branch:commit
- Produces: the kills, with the index held against the killed set both ways; every cell of the table answered; a review record with each finding dispositioned

This task changes no file and states no property. It runs after slice 4.

- [ ] **Step 1: every mutant, two-phase,** as LR R35 accepted. A mutant whose named killer did not run is not killed.
- [ ] **Step 2: the table.** Every cell that can arise has its test, or a filed residual. A cell that no test covers gets one, in the task that owns its erase, before the close.
- [ ] **Step 3: the review.** An independent reviewer who wrote none of it reviews at the subject: the promise table's rows, the authority table, R8-SIB, the link, the phrase change, and every sentence the app shows. The budget decides what is fixed.

### Task 40: Spec C, from the app as shipped, and Spec A's known answers (W-srv)

- Consumes: the copy and shots of Tasks 16, 28, 38 and 45; the known answers of Tasks 10 and 11
- Produces: Spec C's screens 1, 3 to 5, 8, 19 and 20, its §6 and its §12.3, with their ledger entry. At `37dd710f` they are `srv:docs/specs/2026-08-12-spec-c-windows-client-ui.md:287-342`, :558-647 and :1552-1578 [m]: Spec C's §9.11 moved them from :285-340, :556-645 and :1434-1460

Spec A §5.14 and §8 gain the known answers, in the same commit. This task changes no code and states no property. Spec C is a file of `message-server`, so its text is this writer's, written from the app writer's copy (HP:8385-8390).

### Task 41: Close I1

- Consumes: Tasks 1 to 40 and 42 to 45
- Produces: the pull requests; the deployed alpha; session 4; the final report; the ledger's close; a PROGRESS row

This task changes no code and states no property. Its one commit is W-srv's ledger close.

- [ ] **Step 1: the full runs** on both hosts, with the verdicts R8 allows; fork-ci's four legs; the scan; `gates.yml`; the app's CI.
- [ ] **Step 2: the pull requests.** One per repository, from branches cut from `main`, with merge commits only, each citing its runs. message-server's goes first.
- [ ] **Step 3: the alpha (the lead):** the database reset, as for every slice (REDTEAM M1); the probe's full run; and the server's own checks.
- [ ] **Step 4: session 4, the final report, and the ledger's close.**

# The live probe on the alpha

| Slice | Steps [c] | What is new |
|---|---|---|
| today | 17 | — (LR R44: 17 steps, 1686 assertions, all held at `c7501a19`) |
| 1 | 17 | every party has an identity made as a person makes one (LRI R81); every key package and group is bound; the transcript check also refuses the words and the entropy |
| 2 | 21 | A's second device, linked through the alpha's link box; the emoji compared in process; fan-out, with a canary; B sees one identity with two devices; step 11's device becomes a linked one |
| 3 | 24 | A2's eviction of A1, refused by every member; a removal; a lock-out, after which the old key's list is refused |
| 4 | 27 | A changes its phrase, and its IDs stay; A2 moves, and B sees one identity throughout; the old key's list and the old words are refused |

**How the lead runs it,** in the form of HP's live verification (HP:14050-14076):
1. Build the probe as its README says.
2. Give it fresh directories, read the three accounts' credentials from paths (no test entropy: LRI R81), and pass the server's endpoint and its pin.
3. The last line must read `=== N STEPS, M ASSERTIONS, ALL HELD ===`.
4. Before and after the run, check `systemctl is-active`, `/readyz`, the PID and uptime, and the journal's error kinds. Check that no URmessage.exe, and no other probe or peer, is running (LR R44).
5. From slice 2 on, also check that no link box is left live at the end, and that the journal holds no rendezvous id.

# The owner's sessions

**Setup, each time.** Two of the owner's Windows computers, PC-1 and PC-2. The lead's participant plays Bob, with livepeer, under an identity made as a person makes one (LRI R81). The alpha is reset for each slice, and each slice's build opens a store folder of its own (Task 16). So every session starts from setup, and "Your ID" is new each time (REDTEAM M1). The zip comes with READ-ME-FIRST, which in session 1 carries P6's line on build 03's folder. **The owner is asked to report** any sentence that reads false, any screen that is unclear, and how long each step took.

**Session 1, at the end of slice 1** [a: about 20 minutes].

| # | The owner does | Expected |
|---|---|---|
| 1 | Installs on PC-1, then "Set up this device" → "This is my first device" | 25 words, once, then typing them back. A wrong word is named, and nothing is corrected |
| 2 | Opens Settings → Account | "Your ID" (36 characters) with Copy. Devices shows PC-1 · this device · phrase device, with its device ID |
| 3 | Starts a conversation with Bob by today's join code | As in build 03; the code is a little longer |
| 4 | Closes and reopens the app | The identity and the conversation come back. Nothing shows the self group |

**Session 2, at the end of slice 2.**

| # | The owner does | Expected |
|---|---|---|
| 0 | On PC-1: sets up, and starts a conversation with Bob (session 1, steps 1 and 3) | As in session 1, under a new "Your ID" |
| 1 | Installs on PC-2: "Set up this device" shows a code. On PC-1: Devices → Add a device, then types the code | Both show the same seven emoji, with names; "They match" on both |
| 2 | Waits on PC-2 | The conversation with Bob appears with no paste. PC-2 shows the same "Your ID" and a different device ID. Earlier messages show as one line, "Sent before this device was added" |
| 3 | Sends from PC-2, and replies from PC-1 | Bob sees one person "· 2 devices", and "⟨name⟩ added a device". PC-1 shows "PC-2 was added … by PC-1" |
| 4 | Starts another link, and taps "They don't match" | "This device was not added: no match". Nothing changes |
| 5 | Closes and reopens both apps | Everything comes back |

**Session 3, at the end of slice 3.**

| # | The owner does | Expected |
|---|---|---|
| 0 | On PC-1: sets up and starts a conversation with Bob; adds PC-2 by its code (session 2, steps 0 and 1) | As in session 2 |
| 1 | On PC-1, removes PC-2. No phrase is asked, because PC-1 is a phrase device | PC-2 shows "This device is no longer on your account", with when and by PC-1. Bob sees "removed a device" |
| 2 | Adds PC-2 again | A new device ID, under the same "Your ID" |
| 3 | On PC-2, which is not a phrase device, removes PC-1, and types this session's phrase | The phrase is asked: this is a lock-out. PC-1 is removed, and PC-2 shows the phrase-device mark. An earlier session's paper is refused with "These words are another account's recovery phrase, or a word is wrong", and nothing changes (REDTEAM H3) |
| 4 | Adds PC-1 again from PC-2; then, on PC-1, "Make this a phrase device", and types this session's phrase | PC-1 shows the mark |
| 5 | Closes and reopens each app | Everything comes back |
| 6 | "Remove this device" on PC-1, then on PC-2 | PC-1 goes at once. It was a phrase device, so PC-2's notice says "PC-1 held your recovery phrase's key and removed itself. If this was not you, lock it out." Here it was you, so ignore it (REDTEAM H2). On PC-2, the last device, the dialog warns "This ends this identity". Setting up again gives a new "Your ID" |

**Session 4, at the end of slice 4.**

| # | The owner does | Expected |
|---|---|---|
| 0 | On PC-1: sets up and starts a conversation with Bob; adds PC-2 by its code (session 2, steps 0 and 1) | As in session 2 |
| 1 | On PC-1: Settings → Account → "Change my recovery phrase". Types this session's phrase, writes down the 25 new words, and types them back | "Recovery phrase changed". "Your ID" is the same as before |
| 2 | On PC-2: opens Settings → Account | The same "Your ID", and PC-2's device ID unchanged |
| 3 | Sends from PC-2; Bob replies | Bob sees one person, "· 2 devices", and no line about a change |
| 4 | On PC-2, removes PC-1, and types the old paper | Refused: "These are the words of a recovery phrase this account no longer uses. Use your newest one." Nothing changes |
| 5 | On PC-2, "Make this a phrase device", and types the new paper | PC-2 shows the phrase-device mark |
| 6 | Closes and reopens both apps | Everything comes back, with the same "Your ID" |

**Not to be expected in any session:** typing the phrase on a new computer to get back in; the security delay; history on a new device; starting a chat by ID, or a request; a QR code; safety numbers.

# What is not in phase 1

| Not in I1 | Why | Moves to |
|---|---|---|
| The security delay, and the being-removed state | X1: without the server's hold, the wait binds honest devices only | I3 |
| Typing the phrase on a new device; the server's device table, head and hold; "Not me" | They need the server's clock and its hold (OD:99) | I3 |
| Contacts letting a device in; Start over as an act of its own | They need the server's carrier and its list | I3 |
| The phrase change's backup and delay steps | X11: there is no backup and no delay in I1 | I3 |
| The 7-day change, and the account tie | The account service must attest a login (OD:76-79) | I4 |
| Backup and its import; history from the approving device | F2's store comes first (OD:89) | F2, I2 and I3 |
| Keys sealed at rest, and Windows Hello | X8, the owner's "Yes, alpha only" | I2 |
| Trusted and Verified; safety numbers; names that follow you | X4, X7 | R |
| QR codes | M5 AD2: "With no camera on either, both show the same seven emoji" (M5:153 [m]). OWN:664 is T2's QR question (REDTEAM L6) | when a camera path exists |
| 32 devices | X5 | a spec edit |
| IDs by request; the profile; inboxes; the server's key stock; Change my ID | R's scope (OWN:485, :490-493) | R |
| R's interface: the proof, the binding check, the signers, the derivers and the events | P10 (Task 35) | R |
| The conversation list | Built by W-app during I1 (Task 6b), app-only; it lands with R (LRI R50) | R |
| Identity-wide leave | P1, which the owner kept (Task 37) | I2 |
| The yearly paper check | There is nothing to check for a year | later |

# Time, size and slices

**Basis [a].** These are agent-days, with the three writers in parallel, counted from the lead's rulings of 2026-10-16. The pace is taken from the hardening plan, whose S0, T1a and T1 were executed between 2026-10-12 and 2026-10-15: 21 planned commits, then six review rounds and two add-ons (LR R46). That plan was cut from a built lab and this one was not, so the figures below allow roughly twice the time per commit. This revision moves them by: Task 2 before Task 1, with a tenth prompt, about +1.5 days at the start; the chain in Task 11, about +0.5 day; Task 35 leaving slice 3, about −1 day; and slice 4. Task 2's dispositions add about half a day to each of slices 3 and 4 [a]: Tasks 30, 32 and 43 each gain a held-erase case, and Task 43 the alarm's.

| Slice | What the owner gets | Tasks | Critical path | Ready for the owner [a] |
|---|---|---|---|---|
| 0 | the screens, with made-up data | 6, with 6b beside it | W-app, after Task 2's dispositions | **day 5 to 6** |
| 1 | "Your ID" on one device, with the real phrase and binding | 7 to 17 | W-lib: 8 to 15, with 7 once Tasks 4 and 5 land (REDTEAM L1) | **day 12 to 14** |
| 2 | a second device by code and emoji; one person with two devices | 18 to 29 | W-lib: 21 to 27, with the server alongside | **day 21 to 24** |
| 3 | remove, lock out, make a phrase device | 30 to 34, 36, 38 and 38b | W-lib: 30 to 34 and 36 | **day 28 to 33** |
| 4 | change the phrase with the old one: I1 complete | 42 to 45, then 39 to 41 | W-lib: 42 to 44, from slice 3's close | **day 33 to 38** |

- **Why slice 4** (P13). In slice 3, the phrase change adds about four library commits' worth of work, heavier than most, and its review [a]. Slice 3 would then be ready about day 31 to 37 [a], and its upper half is past about day 35, the lead's mark for this revision. As slice 4, the removal session comes about five days sooner. The change gets its own review and two fix rounds under THE BUDGET, and it reaches the owner about a day later than it would in slice 3 [a].
- **Earliest:** Slice 0 is the earliest testable slice, around day 5 to 6: the look of the flow, with no crypto. Slice 1 is the earliest real one, around day 12 to 14. The owner's headline, one ID across two devices, arrives with Slice 2, around day 21 to 24.
- **The red team's fixes** add about ten tests and twelve mutants inside existing tasks, and no task. They cost about one agent-day each in slices 2 and 3 [a]. In slice 1, L1's earlier start pays for them [a]. Task 2's add three tests, two `--diagnose` cases, four cases in existing tests and eight mutants, also inside existing tasks [c].
- **What keeps it fast:** the server is built alongside the library from Task 7 on; the app builds against each slice's header while the library finishes; Slice 0; slice 4's library work starting while slice 3 closes; and the budget, with one review and two fix rounds a slice.
- **What would slow it:** a red-team finding against X2, which moves slice 2, or against the phrase change (Task 2's prompt 10), which moves slice 4; Argon2id taking more than about 2 seconds on the owner's computers [a], which changes the parameters and every known answer; and the owner merging slowly, which makes the slices stack.
- **Size [c].** 46 tasks since LRI R70's Task 7b: 27 commits to lib, 10 to srv and 5 to app; Task 6b's commits land with R. About 165 new tests, 17 scenarios, and 118 library, 12 server and 15 app mutants (12 server since LRI R66, 118 library since LRI R70). Production code [a]: about 6,000 new Go lines in lib, about 1,500 in srv, and about 3,300 C++ lines in the app.

# Mutation proofs

Every mutant is stated in its task, with the Property it must fail and the test that kills it. Task 39 runs them all, two-phase.

| Task | Mutants | Task | Mutants | Task | Mutants |
|---|---|---|---|---|---|
| 6 | MA1 to MA2 | 18 | MR1 to MR3 | 30, 31, 33 | MI60 to MI65; MI71, MI72; MI87, MI88; MI115 |
| 7, 7b | MI1; MI122, MI123 | 19 | MR4 to MR9; MR11, MR12 | 32 | MI66 to MI70; MI89, MI90, MI94; MI116 |
| 9 | MI2 to MI5 | 20 | MR10 | 34 | MI73 to MI75 |
| 10 | MI6 to MI12 | 21 | MI38 to MI40 | 36 | MI78 |
| 11 | MI13 to MI20; MI91 to MI93; MI121 | 22 | MI41 to MI44; MI83, MI84 | 38 | MA8 to MA9 |
| 12 | MI21 to MI26 | 23 | MI45 to MI49; MI85 | 42 | MI95 to MI102; MI119 |
| 13 | MI27 to MI34; MI81, MI82 | 24, 25 | MI50 to MI54 | 43 | MI103 to MI113; MI117, MI118, MI120 |
| 14, 15 | MI35 to MI37 | 26 | MI55, MI56, MI58; MI86 | 44 | MI114 |
| 16 | MA3 to MA5; MA10 | 27, 28 | MI59; MA6, MA7, MA11 | 45 | MA12 to MA15 |

**Retired:** MI57 (REDTEAM M3); MI76 and MI77, with Task 35 (P10); MI79 and MI80, with Task 37 (P1). The new ids follow the last ones used, MI91 to MI121 and MA12 to MA15, so no id changes its meaning; MI115 to MI121 and MA15 are Task 2's.

**Scenarios (17).**
- **RED on `main`:** `I1-two-devices-one-person`, `I1-sibling-evicts-sibling`, `I1-copy-adds-unnoticed` and `I1-unbound-key-package-admitted`.
- **RED on Task 12's commit,** the tree before their change (REDTEAM L5): `I1-stranger-in-self-group`, `I1-server-rolls-back-a-list` and `I1-server-forks-the-self-group`.
- **RED by their mutant:** `I1-server-swaps-the-link-card` (at the test width), `I1-grant-before-own-match`, `I1-fanout-after-respected-removal`, `I1-stolen-linked-device-removes`, `I1-forged-succession`, `I1-phrase-change-in-place` and `I1-server-withholds-a-phrase-change`.
- **Residuals, each with a control:** `I1-removed-device-acts-until-a-sibling-runs` (SCOPE R8), `I1-stolen-phrase-device-until-lockout` (R1) and `I1-old-phrase-after-change` (R3, with the first paper after two changes: T2-M2). The copied store until a lock-out (R4) is held inside the (f) cells, and is not a scenario.

# Gates the change keeps green, and which task touches which

| Gate | Where | Touched by | What changes |
|---|---|---|---|
| Layering | lib `internal/layering` | 10, 21 | `messagegroup` imports `x/crypto/argon2`, which its row allows. No new edge |
| The engine interface is exactly its block | lib `messagegroup` | 9, 12 | the seam's new methods, counted in Spec A §6 (Task 4) |
| Every erase names its authority | lib `erasegate_test.go` | 23, 30, 32, 43 | new sites under (a), (f), (f)P, (g) and (i); the property's text gains identity records |
| The store's own names | lib `storenames_test.go` | 12 | the store root's names |
| Key-material censuses | lib `sdk/urmessage`; the phrase-secret census in lib `messagegroup` (LRI R65) | 10, 30 to 33, 43 | the phrase-secret census is new; a change adds the new words and keys to it, and from Task 12 a phrase-secret census in `sdk/urmessage` follows them there (LRI R68) |
| Crypto imports per file | lib `sdk` | 21, 27, 36, 44 | rows for `rendezvous.go` and the probe |
| Kind bands | lib `kind_test.go` | 24 | the self-group kinds |
| Wire golden; the append-only schema rule | lib `protocol/` | 7 | appended fields only |
| Native exports | lib `sdk/cgo`, `scripts/native-exports.sh` | 14, 27, 36, 44 | the new exports |
| The adversary registry | lib `sdk/cp3b` | 8, 13, 22 to 26, 30 to 34, 42, 43 | 17 entries |
| Module census; the pinned toolchain | lib `test.sh` | none | no `go.mod` changes |
| Dependencies, the migration audit, logging, the plan linter, the edit log | srv | 1, 3 to 5, 18 to 20, 40 | as each task says |
| `--diagnose`, the copy check, shots | app | 6, 16, 28, 38, 45 | the new screens and their copy |

# Reports to the owner

These are plain text, sent by the lead at each slice's close. Every number is measured on the day; a count that differs from this plan's is said, not smoothed.

**At the end of slice 1.**
> Your account now has one ID, made from your recovery phrase.
> - Setup shows 25 words once and asks you to type them back. A wrong word is named; nothing is guessed.
> - Settings → Account shows "Your ID", and this device with its own device ID.
> - Every conversation now carries your identity, and everyone's app checks it. That is why the alpha was reset: older builds cannot join.
> - Your phrase cannot bring your account back yet. Changing it comes in slice 4.
> - [The tests that were red and are now green, the mutants killed, and the probe's last line.]
> - Next: adding a second computer with a code and seven emoji.

**At the end of slice 2.**
> You can add a computer to your account by typing a short code and comparing seven emoji.
> - The server carries the code in a sealed box it cannot read. The emoji prove that nobody is in the middle: about one chance in four trillion per try, and three wrong tries end the attempt.
> - The new computer joins your conversations by itself, with no paste. It cannot read what was sent before it joined, and shows one line where those messages were.
> - Contacts see one person with several devices, and a quiet line when you add one.
> - A device can no longer remove another of your devices that your list still names. A test that showed it could, on the old code, now shows it cannot.
> - [Numbers, runs, the probe's last line, and what the server changed.]

**At the end of slice 3.**
> You can remove a device, and lock out a lost phrase device; its old key stops counting on every device that has seen the new one.
> - If someone at an unlocked phrase device of yours removes your other devices before you lock it out, your phrase cannot win your account back in this build.
> - A device leaving your account erases your phrase's key first. If another program stops that, the device says so, and finishes when it can.
> - What else stays true until later phases: a stolen phrase device can remove your other devices at once; losing every device means starting over with a new ID; your keys are protected only by file permissions; and a new device cannot read older messages.
> - [Numbers, runs, the probe's last line, and the authority table.]
> - Next: changing your recovery phrase with the old one.

**At the end of I1 (slice 4).**
> You can change your recovery phrase with the old one, at once. "Your ID", your devices and your conversations stay, and your contacts are asked nothing.
> - From then on your devices refuse the old paper, and name it as a phrase this account no longer uses.
> - Changing the phrase removes no device: remove or lock out a lost one as well.
> - A phrase you replaced still counts in a conversation until one of your devices in it has run since the change. The device you change it on does this at once, for its own conversations. In a conversation none of your devices is in any more, a replaced phrase, your first included, counts for good.
> - If the alarm says a replaced phrase was used, changing again cannot undo it: start over with a new ID.
> - [Numbers, runs, the probe's last line, and the authority table.]
> - Next: IDs and requests, built on this.

# Counts

| | Phase 0 | Slice 1 | Slice 2 | Slice 3 | Slice 4 | All |
|---|---|---|---|---|---|---|
| Tasks | 7 | 12 | 12 | 8 | 7 | 46 |
| Commits to lib [c] | 0 | 10 | 8 | 6 | 3 | 27 |
| Commits to srv [c] | 4 | 0 | 4 | 0 | 2 | 10 |
| Commits to app [c] | 1 | 1 | 1 | 1 | 1 | 5 |
| Scenarios | 0 | 7 | 3 | 3 | 4 | 17 |
| Mutants | 2 | 49 | 40 | 26 | 28 | 145 |

The commits count one per code task, plus the two pin commits; Task 6b's land with R. srv's slice 4 holds Task 40 and the ledger's close. The scenarios are counted where they land. LRI R66 adds MR11 and MR12 to Task 19, so slice 2 holds 40 mutants and the plan 143. LRI R70 adds Task 7b, with MI122 and MI123, so slice 1 holds 12 tasks and 49 mutants, and the plan 46 tasks and 145 mutants. The mutant row was 2 / 43 / 38 / 27 = 110 after the red team's fixes [c]. Slice 1 gains MI91 to MI93. Slice 3 gains MI94 and loses MI76, MI77, MI79 and MI80. Slice 4 is MI95 to MI114 and MA12 to MA14. That made 133. Task 2's dispositions add MI121 to slice 1, MI115 and MI116 to slice 3, and MI117 to MI120 and MA15 to slice 4: 141. By repository: 116 library, 10 server and 15 app. LRI R66's MR11 and MR12 make it 143: 116 library, 12 server and 15 app.

# Review dispositions

## The red team of 2026-10-15 (`REDTEAM`): 0 CRITICAL, 4 HIGH, 13 MEDIUM, 7 LOW

**How they were handled.**
- **Checked first.** The finalizer re-read each HIGH finding's ground at its cited lines, and re-ran each absence the red team claims, with its control in the same pass ("What was verified": the first round) [m]. All four HIGH findings reproduce.
- **Fixed small.** Each fix is the smallest that closes its finding, inside a task the plan already has. No task was added.
- **Sent to the lead.** A fix that adds an erase or moves scope is a row in the lead's table (P9 to P11), with the fix as the planned default.
- **The lead ruled** that this pass and Task 2 together are the design's one pass (LRI R53). Task 2 runs its prompts as written, and does not redo what this section settles. **After the rulings of 2026-10-16,** M8's three questions are answered (FOR-OWNER); M11 is ruled (P10 taken: Task 35 moved to R); M13 is ruled (P11 flipped: Task 6b); and H3's helper compares the words with the current key, while Task 43 names a retired key's words.

| Id | Sev | Disposition | How, or why | Where |
|---|---|---|---|---|
| H1 | HIGH | **Fixed** | The new rules sit in `authorizeCommit`, which `authorizeOutgoingLocked` already runs over the would-be commit (lib `rolescommit.go:204-220` [m]). The value it judges now carries the committer's post-commit leaf, own-leaf patch included, not the pre-commit one (:236 [m]). Property 8; `TestAnOwnCommitEveryReceiverWouldRefuseIsNeverPublished`, with three cases; MI81. No new mechanism | Task 13; SCOPE C6, §9 |
| H2 | HIGH | **Fixed**, as the planned default of P9, which the lead took | (1) On a phrase device, "Remove this device" and "This ends this identity" erase the phrase key record, under new authority (g), before anything is sent. The self-removal stays signed by the device key, so a failed send can be redone (TR3) [c]. Task 30's Property 4, `TestARemovedOrEndedPhraseDeviceKeepsNoPhraseKey`, MI87, and (g)'s cells. (2) A phrase device's self-removal shows a notice, and its button opens a lock-out that names no device. Task 32's Property 5, its test, MI90 | P2, P9; authority table; Tasks 30, 32, 38; SCOPE A4, G1, G3, G6, R4 |
| H3 | HIGH | **Fixed** | One helper in `identity.go` (Task 31), called first by RM2, RM6, AD5, a phrase change and the words-scoped hooks. It derives IRK and ISK_g and compares them with the current key and IskCert(g) (F1:637, :671 [m]). A mismatch answers one sentence, after nothing has been stored, signed, sent or erased. Task 31's Property 4; `TestWordsOfAnotherIdentityChangeNothing`, with another identity's words and with a one-word slip that passes the checksum; MI88 (RM2), and MI89 (RM6) under Task 32's Property 6. MI71 still holds AD5. Session 3, step 3 names the paper to type | Tasks 31 to 33, 43; session 3; SCOPE G2, §9 |
| H4 | HIGH | **Fixed** | SCOPE E3 and Task 22's step 4 now carry F1:654's order [m]: N posts `n_N` only after it has read `n_E` at epoch 1 (Property 5, MI83). MI41 and MI83 die in `I1-server-swaps-the-link-card` at a test-only width of two emoji [a], as F1's lab ground 4 digits (`sasgrind_test.go:10-12` [m]). Property 6, the source gate `TestProductionShowsSevenEmojiOnly` and MI84 keep that width out of production. **Not taken:** the extra check that the grant's root is E's credential. With the order fixed, matching emoji put N and E in one link group, so only E can post a grant there [c] | Task 22; the promise table; SCOPE E3, §9 |
| M1 | MED | **Fixed** (the red team's second option) | Each slice's build opens a store folder of its own, and the alpha is reset for every slice, Task 41's included. Sessions 2 to 4 begin with a step 0 that sets up again, and the setup line says "Your ID" is new each time. One folder across slices would need a promise of compatibility between slices, which the RESET variant does not make [c] | Tasks 16, 38, 45, 41; the owner's sessions; SCOPE §8 |
| M2 | MED | **Fixed**, by building it | Striking the line would leave rows of gaps. A record from before the join already reaches the walk and is answered `out_of_window` (lib `group.go:250-262` [m]), which the app draws as a gap row (app `ThreadLayout.h:42-47` [m]). Task 26 answers `not_a_member_yet` instead, one of the closed seven reasons (Property 3, MI86). Task 28 draws a run of them as one line (Property 3, MA11). SCOPE's 14 surfaces already count this reason of M5's row 18 | Tasks 26, 28; session 2; the slice-2 report; SCOPE F5 |
| M3 | MED | **Fixed** | MI41: H4's test width. MI27: Task 8's row makes the adder the harness's attacker, which skips the Add door and the sending check, so R6e is what refuses. MI57: retired. The direct rule is the app's (app `LiveWorld.cpp:288-292` [m]; none in lib [m: 0 hits outside tests; the control fired]), so its mutant is MA10 in Task 16, killed by a `--diagnose` roster of three leaves and two identities | Tasks 8, 16, 22, 26 |
| M4 | MED | **Fixed** | Task 13: this identity's own head and removed state move only on a list from its self group (M5 TR8, M5:142 [m]). A list of its own seen only in a conversation is one this device cannot explain, which Task 34's first reason reports. Property 9; `TestAListOfMineSeenOnlyInAConversationMovesNothingOfMine`; MI82, which is SCOPE §9's own mutant. A phrase change keeps the rule (Task 43, Property 9) | Tasks 13, 43 |
| M5 | MED | **Fixed** | Task 23, step 1: if a newer base overtakes the addition before its commit lands, E signs it again on that base (M5 AD2, M5:153 [m]). Property 5; `TestAnApprovalOvertakenByANewerBaseIsSignedAgainOnIt`; MI85. H1's fix makes this needed: the sending side would refuse the stale commit, and the link would end after both screens said "They match" [c] | Task 23 |
| M6 | MED | **Partly fixed**; the rest **accepted** and filed | Fixed: a forked self group raises the alarm's first reason, and its sentence now names I1's one remedy (Task 34). Accepted: two lock-outs typed at once. With H1's sending check, neither device publishes a commit others refuse, so nothing halts [c]. The later device holds a fork, with the alarm, until it is removed and added again. That is a liveness cost of a correct refusal, which THE BUDGET files (LR R39). Task 8 files it as MG-16, with F1's random first base number as the fix to come (F1:617 [m]) | Tasks 8, 34 |
| M7 | MED | **Fixed** | One rule under "Rules for every task": separate workspace roots, and in each one the other repository is a clone at its pin, never written there. The cross replaces are lib `sdk/cp3b/go.mod:65` and srv `go.mod:46` [m] | Rules for every task |
| M8 | MED | **Fixed**, and answered | `FOR-OWNER.md` named the departures in plain words before slice 1. Its three questions were the phrase change in I2, leave on one device, and keys unsealed until I2. The owner answered all three on 2026-10-16: "No, in phase 1"; the default kept; "Yes, alpha only" (LRI R56; OWN:523-529). Task 1's ledger entry records that FOR-OWNER was sent | FOR-OWNER.md; Task 1 |
| M9 | MED | **Fixed** | The red team's sentence (28 words) goes into SCOPE R1 and the slice-3 report: "If someone at an unlocked phrase device of yours removes your other devices before you lock it out, your phrase cannot win your account back in this build." | SCOPE R1; Reports to the owner; FOR-OWNER.md |
| M10 | MED | **Fixed** | Task 3's registry freezes D2's ID1 (`u16(id_version = 1)`, D2:168 [m]) and DID1 before Task 10 writes known answers. DID1 is taken over the root and the device key: 8 octets, shown as four groups of four lowercase hex (D2:185 [m]). Task 10's Property 4 now says the device ID moves with the root too (D2 DID3). The link box takes kind 4. D1 gave kinds 1 to 3 to the inbox, join box and reply box (D1:461 [m]), and D2 keeps kind 1 for the inbox (D2:502 [m]). P8 is restated | P8; Tasks 3, 5, 10; SCOPE B1, B2, X6, §5.2 |
| M11 | MED | **Ruled:** P10 taken (LRI R50, R51) | Nothing in I1 called Task 35 [c], and D2 §2.0 names another interface (IL1 to IL13). Task 35 is retired, and R writes its calls against D2 §2.0 | P10; Task 35; SCOPE §0, §5.1 |
| M12 | MED | **Fixed** | SCOPE §5.1 and Task 24 now state the real order: list changes by the self group's commits, and records in the server's delivery order. Task 24's Property 2 no longer claims an order for records. R carries a decision that must come first inside a self-group commit (LRI R51) | Task 24; SCOPE §5.1 |
| M13 | MED | **Ruled:** P11 flipped (LRI R50) | The conversation list is Task 6b: W-app builds it during I1, app-only, and it lands with R. SCOPE §5.2 carries the note for D2 §8 | P11; Task 6b; SCOPE §4, §5.2 |
| L1 | LOW | **Fixed** | W-lib starts slice 1 at Tasks 8 to 10, and does Task 7 when Tasks 4 and 5 land. Task 7 and the time table say so | Task 7; Time, size and slices |
| L2 | LOW | **Fixed** | SCOPE E2 now says that a server which finds the code reads the card, but never the deposit. SCOPE R12 and Task 5's Spec B edit state that one client can fill the global cap until boxes expire. **Not taken:** the 16-character code. With H4's order the emoji hold with or without the code [c] | Task 5; SCOPE E2, R12 |
| L3 | LOW | **Fixed** | Task 34 says the second reason covers list changes signed with this device's key, not records or leaves. In slice 3 it offers "Check my devices" and the lock-out; slice 4 adds M5's "Change my recovery phrase", offered only where a change can help (T2-H2; review D16) | Tasks 34, 43 |
| L4 | LOW | **Fixed** in part; the rest **accepted** | Task 16 adds "no clipboard history" and the `SM_REMOTESESSION` warning (F3:894-899 [m]). **Not taken:** the planted-word `--diagnose` case. No mutant in the plan prints the shown words, so the case would kill nothing. Task 39's review reads every sentence the app shows | Task 16 |
| L5 | LOW | **Fixed** | Task 13's three scenarios run red on Task 12's commit, where the rules are absent, as gate 5 asks (srv program plan :116-121 [m]). Task 6's demo words become a fixed demo list, so Task 6 consumes neither Task 3 nor Task 10. That fix removes a dependency, where the red team's would add one | Tasks 6, 13; Mutation proofs |
| L6 | LOW | **Fixed** | SCOPE X9 and E7, and "What is not in phase 1", now cite M5 AD2's no-camera clause (M5:153 [m]). OWN:664 is T2's question about QR (OWN:653-664 [m]). The Writers row cites gate 4 at :113-115 [m]. SCOPE X1 also cites OD:99, as REDTEAM §5 suggests | SCOPE X1, X9, E7; the Writers row; What is not in phase 1 |
| L7 | LOW | **Fixed**, by leaving it to R in writing | SCOPE §5.1 gains IL5b's row: the heads (C7) hold the newest list for a root, and R adds the accessor | SCOPE §5.1 |

**What else.**
- **REDTEAM §4's other moves are not findings.** Task 37 (P1, now ruled), device rename, Task 40's place and slice 0's start stay with the lead. **REDTEAM §5** lists what holds, and needs no disposition.
- **After the fixes, and before this revision:** 41 tasks; 110 mutants (89 library, 10 server, 11 app), each defined once and each naming a property of its own task [m: counted per task heading, with a planted bad reference as the control]; 13 scenarios; about 140 tests [c]. This revision's counts are under "Counts".

# Task 2 dispositions

## Task 2's red team of 2026-10-16 (`REDTEAM-TASK2`): 0 CRITICAL, 2 HIGH, 2 MEDIUM, 3 LOW

**How they were handled** (LRI R53: with REDTEAM's, this is the design's one pass; one check of these dispositions follows, and a third round on one promise goes to the lead). PLAN, SCOPE and FOR-OWNER lines below are those before this revision, as REDTEAM-TASK2 cites them.
- **Checked first [m].** Both HIGH findings were re-read at every line they cite, and each absence they claim was re-run with a control in the same search. (1) A failure path for a phrase-secret erase, over PLAN and SCOPE (`erase (fails|failed|that fails|is held|cannot)|cannot be erased|could not (be )?erase|erase .{0,40}held|held .{0,30}erase|a send that fails|removal held`): only controls hit, each for its own reason: PLAN:903 (a send that fails), :134 (column 3, the creating mark) and :141 ("a withheld step erases nothing"). (2) Text that says a change leaves earlier phrases live, or does not undo a leak, over PLAN, SCOPE and FOR-OWNER (`leak|for good|forever|permanent|every earlier|any earlier|undo|first phrase`): every hit fired for its own reason: the root's definition (PLAN:55, :387; SCOPE:14, :217), the halt (PLAN:507; FOR-OWNER:54), V4's "permanent conflict" (PLAN:1097) and a leaked link code (SCOPE:97).
- **T2-H1 reproduces, and reaches one case further.** (g) has an order and a postcondition (PLAN:903, :910) and no failure path, and it cannot retry as (f) does (:140), since Task 38 never opens the old folder again (:1062). A lock-out's target is worse: P2 and Task 30 say a device removed by another "erases nothing (M5 RM8)" (:76, :905), while (f) has a phrase device erase on a higher number (:968), and nothing orders the two. M5 has both, TR7 (M5:141 [m]) and RM8 (M5:170 [m]), so the target erases its key and nothing else [c].
- **T2-H2 reproduces in part.** The alarm's offer (PLAN:1148; SCOPE:121) and FOR-OWNER:19 are false as written, and R3 omits the permanence (SCOPE:266; FOR-OWNER:65). It does not reproduce as a departure [c]. I1 makes a new identity key that the old one signs (SCOPE K2), as M5 PC2 does (M5:185 [m]); the root pins only the IDs, which neither M5 nor V4 has (D2:132, :178 [m]); and the window a replaced phrase leaves, for good, is V4's reviewed rule (V4:318 [m]), which M5 PC3 takes (M5:186 [m]). Its attack's step 3 also needs a way into the conversation, a device of yours still there or a member who adds the holder's (V4:318): R3's reach.
- **No owner question** [c]. P15 is M5 TR7's own order; P14 keeps "One ID for a whole account" (OWN:485 [m]); and the alarm still offers a change wherever one helps (M5:145 [m]). FOR-OWNER names P14 as a default to flip.

| Id | Sev | Disposition | How, or why | Where |
|---|---|---|---|---|
| T2-H1 | HIGH | **Fixed** (iv), as P15's planned default | No device leaves its account holding a phrase secret. (g)'s acts go only once their erase has succeeded; a failed erase signs and sends nothing, and leaves a listed phrase device (Task 30, Property 5, MI115). A lock-out's target erases under (f) before it shows itself removed, and retries at each start (Task 32, Property 8, MI116); so does a change its removal made void, under (i) (Task 43, Property 7, MI117). One test, `TestNoDeviceLeavesItsAccountHoldingAPhraseSecret`, holds record 13 for real, with a case in each task, and the authority table gains column 11. No new authority, surface or concept. The residual, a deny that outlasts every start, goes to the store track (SCOPE R17) | P15; Tasks 30, 32, 38, 43; both tables; Reports; SCOPE A4, G1, G5, R17; FOR-OWNER |
| T2-H2 | HIGH | (ii) **Fixed**; the design question **to the lead** as P14, planned: keep the root, and state its cost | The alarm offers "Change my recovery phrase" only for a rival of the current key. For an earlier key's, it says a change cannot undo it, and how to get a new ID (Task 43, Property 11, MI118; Task 45, Property 4, MA15; Tasks 34, 44). The slice-4 report says "your devices refuse the old paper", and the owner's copy "your computers refuse the old paper"; since LRI R61 both also say where a replaced phrase still counts, and that a change cannot undo a use the alarm reports (review D1, LRI R62). An ID over the current key would change "Your ID" at every change and leave V4's window as it is [c] | P14; Tasks 34, 43 to 45; the promise table; Reports; SCOPE G6, K5, R3; FOR-OWNER |
| T2-M1 | MED | **Fixed** | Task 11's Property 7 pins F1:365-367 [m]: every list and amendment preimage is LP(label) ‖ tbs, so it is never an MLS SignContent. `TestADeviceKeySignsTwoDomainsThatNeverMeet`, both ways; MI121. Only the device key signs in both domains [c] | Task 11 |
| T2-M2 | MED | **Stated** | R3, K5, K9, the promise table and the slice-4 report: every earlier phrase, the first included, counts for good where none of your devices has run since it was replaced. It needs a paper or a copy, and a lagging conversation: two conditions. It is V4's UM-18 (V4:318), so no new id | SCOPE R3, K5, K9; Reports; FOR-OWNER |
| T2-L1 | LOW | **Fixed** | MI120: the change re-mints the salt; `TestAPhraseChangeKeepsYourIdAndEveryDeviceId` kills it | Task 43 |
| T2-L2 | LOW | **Fixed** | Task 42: the alias runs before every rule, R8-CUR and R8-SIB included (F1:551 [m]); a sibling case; MI119 | Task 42 |
| T2-L3 | LOW | **Holds** | A put-back gives a false positive only, which Task 34's sentence names (PLAN:81, :1022); a copy cannot write the original's log [c]. P7 is decided | P7 |

**What else.** 45 tasks; 141 mutants (116 library, 10 server, 15 app; 143, with 12 server, since LRI R66; 46 tasks and 145, with 118 library, since LRI R70), MI115 to MI121 and MA15 new, none reused; 17 scenarios; about 165 tests [c]. Slices 3 and 4 move about a day. No MG id is new, and MG-18 stays Task 43's. Declined actions: none.
