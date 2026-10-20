# Red team: identity phase 1 (I1), its plan and its scope

**Filed copy.** This review is filed in `urnetwork/message-server` as `docs/plans/identity-phase1/REDTEAM.md`, and the ledger entry that files it lists every change made in filing it. `identity-phase1/PLAN.md` is the plan, filed as `docs/plans/2026-10-16-identity-layer-one-account.md`, and `identity-phase1/SCOPE.md` is `SCOPE.md` in this folder. Both were revised in place after this review, so its `PLAN:` and `SCOPE:` line numbers are those of the versions it read (1,189 and 318 lines) and do not point into the filed copies. Local paths are replaced by labels. `lib@<sha>`, `srv@<sha>` and `app@<sha>` are `urnetwork/message`, `urnetwork/message-server` and `urnetwork/message-windows` at that commit, as read in a local clone, and `app:` paths are under `app/src/App`. The owner's review file (OWN) is in no repository, and neither is the lead's scratch folder, which holds the designs, reviews and rulings this review names by a relative path or a short name, such as OD, M5, F1, D2, RT2 and LR.

**Writer:** the red team of the identity-phase-1 round, the only writer of this file. **Date:** 2026-10-15. **Status:** findings for the lead. Nothing was built, run or launched. No repository, server, spec or ledger was changed. **Declined actions:** none.

**Subject.** `PLAN` = `identity-phase1/PLAN.md` (1,189 lines) and `SCOPE` = `identity-phase1/SCOPE.md` (318 lines), both read whole [m].

**Other inputs [m].** `OD` = round5/OWNER-DECISIONS.md and `M5` = round5/MODEL-v5.md, both whole. `F1` = F1-identity-layer-FINAL.md §2.0 to §2.11 (:329-747). `F3` §2.1-§2.2 (:304-345) and §2.11.2-§2.11.3 (:883-899). `D2` = accounts-requests/DESIGN-v2.md :1-799 (it exists now; SCOPE:7 and PLAN:146 say it did not). `D1` = DESIGN-v1.md :448-505. `RT2` = accounts-requests/redteam-v2.md, its table (:56-77) and RV-9 (:290-305). `OWN` = URMESSAGE-DECISIONS-REVIEW-2026-10-05.md :286-302, :426-505, :640-680, :1000-1025. `LR` = LEAD-RULINGS-2026-10-15.md, R34 to R39. The program plan's gates (srv:docs/plans/2026-10-05-hardening-program.md:102-125). F1's lab `f1v2lab/sasgrind/sasgrind_test.go:1-40`.

**Code, read only [m].**
- `lib@c7501a19`;
- `srv@20fc48db`;
- `app@badf2e2c`.

`git status --short` was empty on lib and srv, and printed nothing on app. §6 lists the files.

**Marks.** [m] I read it at the cited place in this session. [c] my reasoning. **Severity:**
- **CRITICAL:** one ordinary action breaks a core promise of the test build, past repair;
- **HIGH:** a stated property is false, or a session fails, from one adversary action or ordinary behaviour;
- **MEDIUM:** a gap the plan must close or state;
- **LOW:** wording, hygiene or speed.

---

## 0. Verdict

**0 CRITICAL, 4 HIGH, 13 MEDIUM, 7 LOW.** The design underneath is sound where M5 and F1 were reviewed, and §5 lists what holds. Four places lose a property between F1/M5 and this plan. Each has a small fix inside a task the plan already has:

1. **H1.** An honest device's own commit can halt a conversation for every member, for good. The plan states every new rule for receivers only.
2. **H2.** "Remove this device" on a phrase device leaves the phrase's key valid on its disk. A thief can use the same act to dodge the lock-out.
3. **H3.** The words are checked against the identity only by "Make this a phrase device". Removal and lock-out take any valid phrase, and the owner will hold several.
4. **H4.** The emoji ceremony lost F1's reveal order, so the "with or without the code" property is false. The test meant to show it cannot grind 42 bits.

None of the four is an accepted risk R1 to R15, so the budget's filing rule (PLAN:70) does not cover them.

| Id | Sev | Lens | Finding | Smallest fix |
|---|---|---|---|---|
| H1 | HIGH | 1, 3 | No committing-side rule: an own commit receivers refuse halts the group for everyone | Task 13: Property 8, a test and a mutant on `outgoingAuthorizationLocked` |
| H2 | HIGH | 1, 2 | A removed or ended phrase device keeps a valid ISK_g; the lock-out can be dodged | Erase record 13 before a phrase device's self-removal or end; a notice that opens RM6 |
| H3 | HIGH | 1 | RM2 and RM6 never check that the words are this identity's | One helper: derive, compare IRK and ISK_g, refuse before any write |
| H4 | HIGH | 1, 3 | N may reveal n_N before n_E; MI41 cannot be killed at 42 bits | F1's order as a rule, a property, a mutant and a test-only width |
| M1 | MED | 3 | The owner's sessions 2 and 3 assume state that the per-slice reset wipes | Reset once at slice 1, or begin each session with setup |
| M2 | MED | 3 | "Earlier messages show as one line" has no task | Build it in Tasks 26 and 28, or strike it |
| M3 | MED | 3 | Three mutants whose named killers cannot kill them: MI41, MI27, MI57 | A seam, an attacker adder, and an app mutant |
| M4 | MED | 3 | SCOPE's TR8 mutant ("a base taken from a conversation") is dropped | TR8's rule, test and mutant in Task 13 or 24 |
| M5 | MED | 1 | M5 AD2's re-sign on an overtaken base is missing | One behaviour line, a test and a mutant in Task 23 |
| M6 | MED | 1 | A forked self group or two concurrent lock-outs have no stated outcome | F1's random first base under a new g; the alarm names the remedy |
| M7 | MED | 3 | Sibling-path replaces run both ways while W-lib and W-srv work in parallel | One rule: separate workspaces, the other repository read-only at its pin |
| M8 | MED | 2 | Five departures from owner-accepted lines go to the lead only | One paragraph to the owner before slice 1, as defaults to flip |
| M9 | MED | 2 | Two sentences the owner accepted in M5 are false in I1 | One sentence in the I1 text and in R1 |
| M10 | MED | 4 | Account ID, device ID and link-box kind differ from D2 | Freeze D2's formats in Task 3's registry before Task 10 |
| M11 | MED | 4, 5 | Task 35 builds D1's interface; D2 asks for a different one | Move Task 35 to R |
| M12 | MED | 4 | "Ordered by the group's commits" is false for self-group records | State the real order; R's MD3 builds on it |
| M13 | MED | 4, 5 | D2 puts the conversation list in stage 1; W-app sits idle | An app-only task in parallel, or record the move |
| L1 | LOW | 5 | Task 7 first makes W-lib wait on spec edits slice 1 does not use | Start at Tasks 8 to 10 |
| L2 | LOW | 1 | The card is readable to a server that finds the code; one client can stop all linking | State both |
| L3 | LOW | 1, 2 | The alarm's second reason covers list changes only; its offers are not named | Name what it covers; offer only I1's acts |
| L4 | LOW | 3 | Task 16 keeps 3 of F3's 5 protections for the words screens | Add "no clipboard history" and the remote-session warning |
| L5 | LOW | 3 | Gate 5's red only by mutant where an earlier tree exists; Task 6 misses a Consumes | Run red on the earlier commit; consume Task 3 |
| L6 | LOW | 2, 3 | X9 cites a T2 question about QR; PLAN:22 cites gate 5 as gate 4 | Cite M5 AD2's no-camera clause, and gate 4 at :113-115 |
| L7 | LOW | 4 | R needs to read I1's heads (RT2 RV-2) | One accessor, or leave it to R in writing |

---

## 1. HIGH

### H1 · HIGH · An honest device's own commit can halt a group for every member, for good (lenses 1, 3)

**Problem.**
- Every new rule is stated as "refused by every member": Task 13's Properties 1 to 7 (PLAN:449-455) and Task 36's probe steps (PLAN:949) [m].
- A refused commit the server already took halts the group. "An honest receiver that refuses stays at the epoch before and can no longer write" (lib:sdk/urmessage/roles.go:17-21), and "THE HALT IS PERMANENT" (group.go:1223) [m].
- The committing arm models the committer as "this device's own leaf, as the pre-commit tree carries it" (rolescommit.go:236-243) [m]. Task 9's own-leaf patch (PLAN:306), which carries the new 0xF005, is not in that value [c].
- Neither PLAN nor SCOPE names the sending side, `authorizeOutgoing`, or the halt [m: grep for "sending side|outgoing|authorizeOutgoing|halt": 0 hits in either file beyond SCOPE:199's "outgoing requests"; control: "every member" has 7 hits in PLAN].
- F1 required the committing side: "Builds a commit only if ... it passes the binding checks ... on the would-be tree" (F1:497-502), and "on both the sending and the receiving side" (F1:506) [m].

**Ordinary triggers in I1 [c].**
- H3's wrong phrase puts a foreign IskCert in the patch.
- M5's approval is overtaken by a fold.
- JN1 adds a key package whose list a fold superseded, which breaks R8-CUR.
- A list goes over the cap of 10.

Each, once published, halts the self group, or the conversation with Bob, for every member.

**Smallest fix.** One property, one test and one mutant in Task 13; no new mechanism.
- **Property 8.** No commit this device publishes is one its own receiving rules refuse. `outgoingAuthorizationLocked` builds the committer's post-commit leaf, the own-leaf patch included, and runs every new rule over the would-be tree.
- **Test:** `TestAnOwnCommitEveryReceiverWouldRefuseIsNeverPublished`, with three cases: a foreign-root patch, a stale list after a fold, and an Add whose key package's list the tree's head supersedes. It asserts that nothing reached the in-process server and that no member halts.
- **Mutant:** the outgoing value keeps the pre-commit own leaf, as today's rolescommit.go:236 does. The test kills it.

### H2 · HIGH · A removed or ended phrase device keeps a valid phrase key, and a thief can use that to dodge the lock-out (lenses 1, 2)

**Problem.**
- "Remove this device" (RM1) and "This ends this identity" erase nothing (P2, PLAN:52; PLAN:820-822) [m]. Record 13, `isk_seed[g]`, therefore stays on disk.
- RM1 makes no new key number. Only removing a phrase device "from another device" is a lock-out (PLAN:848) [m].
- That breaks the disposition the plan itself sets [m]:
  - SCOPE A4 (:64): "Only `isk_seed[g]` is kept, and only on phrase devices";
  - M5 C.0 (:127): "on phrase devices only, sealed, for the current g".
  
  A removed device is not a phrase device, so this is budget class (iv) (PLAN:69).
- M5 closed this case at the server: a self-removed device is unregistered at once (M5:163), and the server takes a list "only from a registered device" (M5:169) [m]. I1 has neither (SCOPE X10, :158).

**What follows [c].**
- **(a) A computer the owner removed and gave away** still signs bases under the current g. Wherever its leaf still stands, until JN2 runs there, it can commit a higher base that drops your devices, and R8-SIB lets it. This is worse than R8: R8's locked-out key is a lower g, while this one is current.
- **(b) A thief at an unlocked phrase device** can take that device off the list, which raises no alarm because its own key signed the change, and keep ISK_g. No RM6 dialog lists it, since RM6 lists only listed devices (PLAN:870). No act makes a new g without a listed target (M5 cut "Renew my phrase's key", M5:430). So the owner is never offered the lock-out that OD:59 promises.
- **(c) In R,** ISK_g signs profiles. D2 PR2 (:173) relies on "A copied or removed linked device cannot publish one"; a removed phrase device can.
- R4's remedy, "until you lock that device out" (SCOPE:237), cannot reach a device that is no longer listed, so this is not an accepted risk. F1 saw it: "If L was a holder, the copy recommends rotating with the phrase" (F1:708) [m].

**Smallest fix.** It needs one erase authority, so it goes to the lead (PLAN:72).
1. **Erase record 13 first.** "Remove this device" and "This ends this identity", on a phrase device, erase record 13 before the self-removal is sent. Add an authority row: "(g) this device's own signed self-removal or end". LR R39 already names the person's explicit command as a true reason (LR:380) [m]. Erasing first is safe [c]: a self-removal that then fails to send is signed by the device key, so it can be sent again.
2. **A notice, with an act that exists.** A device that sees a marked device's self-removal shows: "⟨device⟩ held your recovery phrase's key and removed itself. If this was not you, lock it out." It opens RM6 (Task 32) with no listed target. Any lock-out retires every key under g. This adds no concept: a TR10 notice and the RM6 act.
   - It brings back, for I1 only, what M5 cut as "RM1's offer and a lock-out that names no device" (MP-02, M5:430) [m].
   - That cut rested on the server's table (RM7), which I1 does not have [c].
3. **Test and mutant:** `TestARemovedOrEndedPhraseDeviceKeepsNoPhraseKey`, with the mutant "RM1 on a phrase device keeps record 13".

### H3 · HIGH · Removal and lock-out take any valid phrase; only "Make this a phrase device" checks the words (lens 1)

**Problem.**
- Only AD5 compares the key it derives with the certificate (PLAN:903, MI71) [m]. RM2 (PLAN:846) and RM6 (PLAN:869-876) do not [m: grep for "against the cert|WrongAccount|derived IRK" finds only the AD5 lines; control: AD5's own line hits].
- RM6's step 3 stores the new seed and certificate "before anything is sent" (PLAN:872) [m].
- **The likely input [c].** The owner will hold several papers:
  - the alpha is reset for each slice (PLAN:1040);
  - every session therefore sets up anew;
  - session 3 ends by making a new ID (PLAN:1070).
  
  The 8-bit checksum (OD:36) [m] also lets about 1 in 256 single-word slips through [c].
- **What follows [c].**
  - RM6 mints IskCert(g+1) under the other phrase's IRK and stores it as record 13. On a phrase device this replaces the real g record, on the false reason "a verified higher key number": budget class (i).
  - Its base and self-group patch carry a certificate whose root is not the credential, so every receiver refuses it (R6e); with H1, the group halts.
  - RM2 on a linked device signs a base under a foreign ISK_g, with the same ending.
  - Session 3, step 3 (PLAN:1067) is exactly this act.
- F1 had the check in two places: "check that its public half equals the IskCert's isk_pub" (F1:637), and `ErrLinkWrongAccount` (F1:671) [m].

**Smallest fix.**
- **One helper in `identity.go`,** used by RM2, RM6, AD5 and the words-scoped hooks. It derives IRK and compares it with the identity's root; it derives ISK_g and compares it with IskCert(g). A mismatch answers one sentence: "These words are another account's recovery phrase, or a word is wrong". By then it has stored, signed, sent and erased nothing.
- **Test:** `TestWordsOfAnotherIdentityChangeNothing`. It types a first identity's words into a second identity, and also a one-word substitution that passes the checksum, found by a search over the 2,048 words. The store listing must be byte-equal before and after.
- **Mutant:** RM6 mints g+1 from words whose IRK is not the identity's.

### H4 · HIGH · The emoji ceremony lost its reveal order, and its test cannot grind 42 bits (lenses 1, 3)

**Problem.**
- SCOPE E3 (:97) and Task 22 (PLAN:643-644) say: "E ... reveals `n_E` at epoch 1. N joins ... and reveals `n_N`" [m].
- The source says: "N joins ..., **reads n_E**, and posts LINK_REVEAL_N{n_N}" (F1:654) [m].
- No property or mutant holds the order. Property 1 is about when the emoji are computed (PLAN:649).

**Why the order matters [c].**
- `n_E` is the uncommitted nonce.
- A server that knows the code plays E toward N in a second link group. If N reveals first, the server chooses its `n_E` after seeing `n_N`, and grinds about 2^42 exporter calls (GPU-hours) until the emoji equal those of its group with the real E.
- With F1's order, its chance is 2^-42 per try. Property 2 claims that chance "with or without the code" (PLAN:650).
- The server can get the code by an offline search of the rendezvous id, which the code derives (PLAN:618) over about 60 bits [a], or through any leak of a code shown on a screen.

**The test cannot show it [m].** MI41's killer is a grinder that "finds a match" (PLAN:659). A test cannot grind 2^42. F1's lab ground a 4-digit target instead (sasgrind_test.go:7-12).

**Smallest fix.**
- SCOPE E3 and Task 22 step 4 read: "N posts `n_N` only after it has read `n_E` at epoch 1".
- **Property 1b:** N's reveal follows E's.
- **Mutant:** N reveals when it joins. `I1-server-swaps-the-link-card` kills it, and MI41 too, at a test-only emoji width. A source gate holds that production never reads that width, as with MI9's stretch seam (PLAN:129).
- In the same step, N checks that the grant's root equals the link group's 0xF006 root and E's credential, the pattern of F1:671.

---

## 2. MEDIUM

### M1 · The owner's sessions 2 and 3 assume state that the per-slice reset wipes (lens 3)

**Problem.**
- "The alpha is reset for the slice" before each session (PLAN:1040), and Task 29 resets it (PLAN:805) [m].
- Session 2 starts on PC-1's existing identity and conversation with Bob (PLAN:1055-1056), and session 3 on two linked PCs (PLAN:1065) [m].
- The app keeps one I1 folder for all slices (PLAN:515) [m]. After a reset its self group and conversation no longer exist at the server. What Restore then does is stated nowhere [c].
- Task 41 does not reset (PLAN:1017), so the plan disagrees with itself [m].

**Smallest fix.** Either of:
- reset once, at slice 1 (OD:32). Slice 2 only appends migrations (SCOPE:215), and slice 3 changes no server code;
- give each slice's build its own fresh folder, and begin each session table with "set up PC-1; start a chat with Bob".

Either way, tell the owner that "Your ID" is new at each fresh setup.

### M2 · "Earlier messages show as one line" has no task (lens 3)

**Problem.**
- SCOPE F5 (:110), session 2 step 2 (PLAN:1056) and the slice-2 report (PLAN:1162) promise it [m].
- No task produces it, states a property for it, or holds it with a mutant [m: grep for "sent before|one line|JN7": only those three lines].
- The new device will show an empty thread or refused rows, not the line [c]. That reads as a false sentence in the owner's session.

**Smallest fix.**
- Task 26 records, per conversation, the epoch this device joined at.
- Task 28 draws one line from it, with a `--diagnose` case and an app mutant.
- Or strike the line from all three places.

### M3 · Three mutants whose named killers cannot kill them (lens 3)

- **MI41** (PLAN:659): the killer must grind 42 bits. The fix is H4's test-only width.
- **MI27** (PLAN:465): "R6e is off", killed by `I1-unbound-key-package-admitted`.
  - Once Task 13 lands, an honest adder's Add door refuses the package first (MI32, PLAN:470), so R6e is never reached [c].
  - Fix: Task 8's row says the adder is the harness's attacker, which skips the door.
- **MI57** (PLAN:751): "direct is told by leaf count, today's rule (app:Live/LiveWorld.cpp:288-292)".
  - That rule lives only in the app (LiveWorld.cpp:288-292) [m]. The library has no "direct" decision [m: grep for IsDirect or kindDirect in lib sdk: no hit outside routing].
  - Task 16 changes the app's rule (PLAN:514), but its mutants MA3 to MA5 and Task 28's MA6 and MA7 do not hold it [m]. Session 2's "one person" check depends on that rule.
  - Fix: make MI57 an app mutant (MA10) on LiveWorld.cpp. Its killer is a `--diagnose` case with three leaves and two identities.

### M4 · SCOPE's TR8 mutant was dropped (lens 3)

**Problem.**
- SCOPE §9 item 4 lists "a base taken from a conversation" among M5's mutants (SCOPE:281) [m]. PLAN mentions TR8 only as a red-team prompt (PLAN:188) [m: grep for "TR8|taken from a conversation" in PLAN: :188 only].
- M5 TR8: your devices take a list change "Never from a conversation" (M5:142) [m].
- As planned, Restore "raises the heads" from every tree (PLAN:413), its own identity's included [m].
- A list seen only in a conversation can then move this identity's own head. It can even lead to the removed screen and the fresh-folder switch (PLAN:980) [c].

**Smallest fix.**
- **Rule (Task 13 or 24):** a list of this identity seen only in a conversation raises the alarm, and moves neither this identity's head nor the removed state.
- **Mutant:** SCOPE's own. Its killer is a copy that commits a base into a conversation only.

### M5 · M5 AD2's re-sign on an overtaken base is missing (lens 1)

**Problem.**
- M5 AD2: "If a newer base overtakes the addition before it is folded, the approver signs it again on that base" (M5:153) [m]. PLAN and SCOPE have no such rule [m: grep for "overtak|signs it again|re-sign": 0 hits; control: "folds" hits at PLAN:904].
- A fold by a phrase device that races a linked device's approval leaves N on an older chain [c].
  - R8-CUR then removes N everywhere, after both screens said "They match". That is class (ii).
  - With H1 unfixed, the race instead halts the group.

**Smallest fix.**
- Task 23, Behaviour step 1: if the self-group commit fails because the base moved, E signs the addition again on the new base before it posts the grant.
- **Test:** a fold lands between E's signature and E's commit.
- **Mutant:** E retries the stale addition.

### M6 · A forked self group, or two concurrent lock-outs, have no stated outcome (lens 1)

**Problem.**
- P5 defends against a server that "withholds, reorders or rolls back" (OD:21) [m].
- M5 resolves a fork with "a higher base, built on the server's head" (M5:138) [m]. I1 has no head, and Task 2 only asks about it (PLAN:188).
- **A server that splits the self group** leaves your devices on two histories [c].
  - The alarm fires, as Task 34's first reason.
  - No task says what the person does next. `I1-server-forks-the-self-group` asserts only R8-EQ (PLAN:472).
- **Two lock-outs typed at once** each make a first base under g+1 [c].
  - If that base's number is fixed, the two bases are equal versions with different octets. R8-EQ refuses both wherever they meet.
  - F1 gave the first list of a generation a random number, so that two such lists are ordered, not equivocal (F1:617, :738) [m]. The plan does not say.

**Smallest fix.**
- Task 32: the first base under a new g takes a random base number (F1:617).
- Task 34: the fork alarm's sentence names I1's remedy ("remove that device and add it again").
- The scenario asserts both.

### M7 · One writer per repository: the gates span both repositories, and the workspaces are not separated (lens 3)

**Problem.**
- lib's `sdk/cp3b/go.mod:65` has `replace github.com/urnetwork/message-server => ../../../message-server`, and srv's `go.mod:46` has `replace github.com/urnetwork/message => ../message` [m].
- PLAN runs W-srv's Tasks 18 to 20 beside W-lib's slices 1 and 2 (PLAN:548) [m]. It repeats gate 4 (PLAN:151) but never says where each writer's sibling of the other repository lives [m].
- A cp3b run in a workspace whose `message-server` is W-srv's clone reads a tree another writer is changing. That is the collision gate 4 forbids (program plan :113-115) [m].

**Smallest fix.** One line in "Rules for every task": W-lib and W-srv work in separate workspace roots. In each root, the other repository is a clone at the pin (`siblings.sh --verify`), and it is never written.

### M8 · Five departures from owner-accepted lines go to the lead only (lens 2)

The table "What the lead rules before code" (PLAN:38-58) sends these to the lead [m]. OD is binding (OD:3), and each departs from a line the owner accepted:
1. **X3:** "lock-out and the fast phrase change ship with the identity layer" (OD:99, line 19).
2. **X5:** "Up to 32 devices, raisable", and "the sessions limit isnt strict at all" (OD:64).
3. **The phrase's key stays in plaintext until I2:**
   - "One key per device ... in the platform's secure storage" (OD:65, line 20);
   - "Keys at rest are sealed" (OD:90);
   - "on phrase devices only, sealed" (M5:127).
   
   SCOPE lists sealing as deferred (SCOPE:179). It never states the newest and strongest key as a departure.
4. **P1 makes leave per device:**
   - F1 (C7): "Leave is identity-wide", with the copy "Leaving removes this conversation from all your computers" (F1:697-700). It is among the recommendations the owner accepted: "Every other design recommendation is accepted" (F1:124-128) [m].
   - Matrix's leave is account-wide (P6).
   - The cost [c]: the left device's leaf stays (forget.go:33-37) [m], so JN2 sees it present and never re-adds it. If an admin removes it later, Task 25's respected-removal rule keeps it out (PLAN:722). That device can never come back by your own devices, and the leave dialog must say "on this device".
5. **P2 departs from M5 RM1:** "An only device erases the identity from itself" (M5:163).

M5's own practice was to list every lead ruling for the owner as a default to flip (M5:346; OWN:288-289) [m]. The slice-1 report names only recovery and change (PLAN:1150-1157) [m].

**Smallest fix.** One paragraph to the owner before slice 1, with each item's cost as a default to flip. Record it in Task 1's ledger entry.

### M9 · Two sentences the owner accepted in M5 are false in I1 (lens 2)

**Problem.**
- M5 Part A: "If a thief used it to remove your devices first, type your phrase on one of yours within your delay: that puts back the ones you choose" (M5:39) [m].
- Risk 3 of the ten: "only your phrase stops that" (M5:312) [m]. That leaned on the server's hold: "the server's hold (RM7) is what lets your words still act at once" (M5:241) [m].
- In I1 a removed device reaches no group (SCOPE X10, :158). A thief who acts first therefore keeps the account, and OD:59's "the identity and the paper stay" does not hold [c].
- SCOPE R1 (:234) and the I1 report (PLAN:1169) do not say this [m].

**Smallest fix.** One sentence of at most 30 words, in the slice-3 report and in R1: "If someone at an unlocked phrase device of yours removes your other devices before you lock it out, your phrase cannot win your account back in this build."

### M10 · The account ID, the device ID and the link box's kind differ from D2 (lens 4)

**Problem [m].**
- **The account ID.** D2 ID1 hashes `u16(id_version = 1)` (D2:133). PLAN P8 keeps "profile ... at 2" (PLAN:58). The known answer therefore differs.
- **The device ID.**
  - D2 DID1: `SHA-256("URmessage/v1/device-id" ‖ LP(root_pub) ‖ LP(device_pub))[0..8)`, shown as four groups of four lowercase hex characters (D2:150).
  - SCOPE B2 and Task 10 derive it without the root, and show 10 capital letters and digits (SCOPE:71; PLAN:340).
  - Task 10 Property 4 makes the difference normative: "changes with the device key and with nothing else" (PLAN:345). D2's DID3 says it changes with the root too.
  - D2's slot labels and INVITE carriers take an 8-octet `device_id` (D2:196, :264).
- **The link box's kind.** Task 5 gives the link box kind 1 (PLAN:230). D1 and D2 give kind 1 to the inbox (D1:461; D2:472).

**Smallest fix.**
- Task 3's registry freezes D2's ID1 and DID1 before Task 10 writes known answers. Task 10's Property 4 then reads "with the device key and the root".
- The link box takes kind 4.

### M11 · Task 35 builds D1's interface, and D2 asks for another (lenses 4, 5)

**Problem [m].** SCOPE §5.1 (:193-199) and Task 35 (PLAN:931-944) were written against D1. D2 §2.0 (:107-126) now names IL1 to IL12, and they differ in four places:
- **The proof.** D2's IdentityProof ends with `phrase_pub_g`, and requests carry a `SenderRef` with the signer (D2:164-171). Task 35 builds "IdentityProof v2 ... signer_pub", with "signer = this device".
- **IL7.** It needs "a way to type the words that keeps nothing" on a linked device, for Change my ID (D2:119, :425). Task 35 answers `ErrNotPhraseDevice`.
- **IL8.** `own_sk` is needed at the inbox's first Register (D2:216). RT2's RV-9 asks for it to be derived whenever the words are typed, at AD1 included (RT2:290-305). Task 35 runs the hooks at RM6 and AD5 only (SCOPE:198).
- **IL11.** It needs the notice and the alarm "with a reason v2 supplies" (D2:123). Task 34's alarm has two fixed reasons.

Nothing in I1 calls Task 35 [c].

**Smallest fix.** Move Task 35 to R, which writes it against D2 §2.0. That saves one library task in slice 3 and avoids building a shape R would rebuild. SCOPE §5.2 already says R resets or asks for the words once.

### M12 · "Ordered by the group's commits" is false for self-group records (lens 4)

**Problem.**
- SCOPE §5.1 promises R "authenticated per sending device, ordered by the group's commits" (SCOPE:199) [m].
- D2 builds decide-once on that: a device acts "only after its own decision record is first in the self group's order" (MD3, D2:698); and IL10 is "an ordered channel" (D2:122) [m].
- List changes do ride in commits (SCOPE D2, :88). Records, though, are content kinds (SCOPE D3, :89), carried as application plaintexts (lib kind.go:74-84) [m].
- Their order across senders is the server's delivery order, which a malicious server can show differently to each device [c]. Two devices may then both believe their decision was first, and act on two decisions.

**Smallest fix.**
- SCOPE §5.1 and Task 24's Property 2 state what the channel gives: commit order for list changes, and the server's order for records.
- R either carries decisions in commits, or states the doubled decision as a residual.

### M13 · D2 puts the conversation list in stage 1, and the app writer sits idle (lenses 4, 5)

**Problem.**
- D2's stage 1 is the identity layer, "in parallel, app-only: the conversation list" (D2:715). "It is the longest pole ... and stage 1 is the time to build it" (D2:727) [m].
- SCOPE H7 keeps "one conversation per device" (SCOPE:131) [m].
- W-app has four commits in about 30 days (PLAN:1180) [m].
- D2 stage 1 also expects PC1 to PC5 and T2's labels (D2:715), which SCOPE moves to I2 and R (X3, X4).

**Smallest fix.**
- Add one app-only task for the conversation list, run beside the library. The library already holds many groups (D2:520).
- Or record in SCOPE §4 that it moves to R, with what it costs.
- Either way, send D2 §8 a note that PC1 to PC5 move to I2 and T2's labels to R.

---

## 3. LOW

- **L1 · Speed (lens 5).**
  - Task 7 comes first in slice 1 and consumes Tasks 4 and 5, the link box's spec (PLAN:265). So W-lib waits on two W-srv spec commits that slice 1 never uses [m].
  - Tasks 8 to 10 consume only Task 3 (PLAN:305, :331).
  - Fix: W-lib starts at Tasks 8 to 10, and does Task 7 when Tasks 4 and 5 land. The server still starts the day Task 7 lands.
- **L2 · The link box (lens 1).**
  - "The server reads neither the card nor the deposit [c]" (SCOPE:96). That is false for a server that searches the code's roughly 60 bits [a]. The card holds a device name.
  - The global cap "failing closed" (PLAN:232), with no per-client limit, lets one client stop all linking until boxes expire. The endpoint authenticates no client (SCOPE:45) [m].
  - Fix: state both in Spec B §4.3.11 and SCOPE R12; or use 16 characters, about 80 bits.
- **L3 · The alarm (lenses 1, 2).**
  - Its second reason reads only list changes "signed with this device's key" (PLAN:918). M5's TR11 also names "a leaf" (M5:145) [m]. So a copy's self-group records, such as sibling invites and names, raise nothing [c].
  - M5's alarm offers "Change my recovery phrase", which I1 lacks (X3).
  - Fix: Task 34 names what it covers, and offers only "Check my devices" and the lock-out.
- **L4 · The words screens (lens 3).**
  - Task 16 takes capture exclusion, no spelling or prediction, and masking (PLAN:513).
  - F3 §2.11.3 also has "no clipboard history" and the `SM_REMOTESESSION` warning (F3:894-897) [m].
  - Fix: add both, or say why not. Add a `--diagnose` case with a planted word, so that a mutant printing the shown words dies.
- **L5 · Gate 5 and Consumes (lens 3).**
  - Gate 5 wants red "on the tree before its change" (program plan :117-119) [m]. Three scenarios can run red on Task 12's commit, before Task 13: `I1-stranger-in-self-group`, `I1-server-rolls-back-a-list` and `I1-server-forks-the-self-group`. Their red is "its mutant" today (PLAN:461).
  - Task 6 shows "the all-zero test phrase of Task 10's known answers" (PLAN:245), but consumes neither Task 10 nor Task 3's checksum label (PLAN:240) [m].
  - Fix: run those three red on the earlier commit; Task 6 consumes Task 3.
- **L6 · A citation (lens 2).**
  - X9 and E7 cite OWN:664 (SCOPE:101, :157). That line is T2's question about QR for comparing safety numbers (OWN:653-664) [m].
  - The real basis is M5 AD2: "With no camera on either, both show the same seven emoji" (M5:153) [m].
  - Likewise, PLAN:22 cites gate 4 at the program plan's :118-120. That range is gate 5; gate 4 is :113-115 [m].
  - Fix: cite both correctly.
- **L7 · Heads for R (lens 4).** RT2 RV-2 asks R to check V-ID and KP4 "against the newest list this device holds for that identity, from any source" (RT2:140) [m]. SCOPE §5.1 gives R no accessor for I1's heads. Fix: add one, or leave it to R in writing.

---

## 4. Scope against speed: what can move later without harm (lens 5)

| Item | Move to | Harm [c] | Saves |
|---|---|---|---|
| Task 35, R's interface (M11) | R | none: no I1 caller, and D2 changed the shape | one library task in slice 3 |
| Task 37, identity-wide leave (P1) | I2, if the owner agrees (M8 item 4) | per-device leave; the copy must say so | one library task, and authority row (a)S |
| Task 7's place (L1) | after Tasks 8 to 10 | none | W-srv's two spec commits leave W-lib's critical path |
| Device rename (SCOPE H4) | R | names come from the link card; rename waits | one record kind and one app state |
| Task 40, Spec C | after session 3, outside Task 41's Consumes (PLAN:1010) | none to the owner | the close stops waiting on prose |
| Slice 0 "after Task 2" (PLAN:1098) | start when Task 1 lands | none: made-up screens | about two days on the first look |

**Keep.** Each of these is what stops a stated adversary:
- TR7's memory of marks. Without it, a held phrase device clears its own mark and is later removed without a lock-out [c].
- Folding.
- The alarm.
- R8-EQ in every tree.
- The heads.
- The link box (X2). It runs on W-srv beside slice 1 and is not on the library's critical path [c].

---

## 5. What holds (checked, and found sound)

- **The key tree.** `isk_seed[g]` comes from `isk_root` and g, never from the master (PLAN:344, MI10). A stolen phrase device cannot mint g+1 (F1:356) [m].
- **The certificate.** IskCert carries no timestamp, so every phrase holder mints the same octets (F1:370) [m].
- **Validity reads trees only.** Heads drive the doors only (PLAN:444), and MI33 puts F1's rejected design back. That is what keeps two members with different heads in agreement [m].
- **The emoji are pinned to the link group's epoch 1,** with R9's no-commit rule (PLAN:649, MI42). This closes the commit-grinding attack of F1's lab (sasgrind_test.go:3-12) [m]. H4 is the separate nonce-order attack.
- **The deposit** is sealed to the key inside the code-sealed card, never to what Open returns (PLAN:620, MI38; D2 IB2 :209) [m].
- **The grant** follows the self-group commit and carries no phrase secret (MI47, MI48) [m].
- **X1, the delay off,** agrees with the owner's own ship order: "phrase setup and the delay wait for the server" (OD:99) [m]. SCOPE X1 should cite that line.
- **RT2's RV-21,** two devices minting two IDs, cannot arise in I1. The salt is minted once, at AD1, and travels in the grant [c].
- **X5 has a real cause:** `MaxDeviceLeavesPerIdentity = 10` (lib mls/errors_lifecycle.go:38) [m].
- **The counts reconcile [c, recounted]:**
  - tasks: 6 + 11 + 12 + 12 = 41;
  - mutants: MI1-80, MR1-10 and MA1-9 = 99, by slice 2 / 40 / 34 / 23;
  - 13 scenarios;
  - 267 + 8 = 275 = 25 × 11 bits.
- **Ground facts confirmed at their lines:**
  - the credential is the signer's public half (device.go:445-457);
  - store kinds 1 to 10 are taken (statestore_durable.go:853-865);
  - a leaf carries only 0xF002 (mls/group.go:550);
  - a leave is a local forget and the leaf stays (forget.go:11-37) [m].

---

## 6. What was checked, and what was not

**Read in full:** PLAN, SCOPE, OD and M5 [m].

**Read at the cited lines [m]:**
- F1 :120-147 and :329-747;
- F3 :300-345 and :880-910;
- D2 :1-799;
- D1 :448-505;
- RT2 :1-77, :140 and :290-305;
- OWN :286-302, :426-510, :640-680 and :1000-1025;
- LR :1-60, :167-260 and :352-400;
- the program plan :100-125;
- F1's lab sasgrind_test.go :1-40.

**Code read [m]:**
- lib: sdk/urmessage/device.go:440-460, statestore_durable.go:846-866, roles.go:1-30, rolescommit.go:204-244, group.go (grep "halt", :595-1250), forget.go:10-40, kind.go:60-110; mls/group.go:545-553 and :1804-1870 (grep), mls/extension.go:84-95, mls/errors_lifecycle.go:36-39; sdk/cp3b/go.mod; scripts/siblings.txt:40-75.
- srv: go.mod:42-58, and the api tests (grep "epoch").
- app: Live/LiveWorld.cpp:284-293.

**Searches, each with its control in the same pass [m]:**
- the sending side (H1);
- the words check (H3);
- the reveal (H4);
- the history line (M2);
- TR8 (M4);
- the re-sign (M5).

**Not done.**
- Nothing was built, run or launched, and no size was measured.
- The cost of searching the code's 60 bits and of grinding 2^42 is [c].
- I did not read T1, T2, MB, HP, Spec A, Spec B or Spec C, nor F1 beyond §2.11.

H1's claim that the committing arm misses the patch rests on today's code (rolescommit.go:236). Task 13 may change it; the plan does not say that it must.
