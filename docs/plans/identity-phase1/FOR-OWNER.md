# Identity layer, phase 1: what you get, and what you test

**Filed copy.** This note is filed in `urnetwork/message-server` as `docs/plans/identity-phase1/FOR-OWNER.md`, and the ledger entry that files it lists every change made in filing it. PLAN.md is the plan, filed as `docs/plans/2026-10-16-identity-layer-one-account.md`. SCOPE.md and LRI, the lead's rulings, are filed in this folder, as `SCOPE.md` and `LEAD-RULINGS-I1.md`. OD, the owner's decisions of the design rounds, is in the lead's scratch folder, which is in no repository.

From the lead's planning round, revised on 2026-10-16 for your answers and for a second review. This is a plan: nothing is built yet. The brackets point into PLAN.md, the plan, and SCOPE.md, which is in this folder. Days are estimates [a], counted from 2026-10-16.

## Your answers, and what they changed

- **Changing the phrase: "No, in phase 1".** It is in phase 1, as its own slice 4, with its own session (PLAN Tasks 42 to 45; SCOPE K1 to K9).
- **Keys on disk: "Yes, alpha only (Recommended)".** In alpha test builds, keys are protected by file permissions only until phase 2. Sealed keys and Windows Hello come before any build that is not an alpha (SCOPE X8).
- **Leaving a chat, and 10 computers:** you kept both defaults (below).
- **Invite keys and strangers:** your answers after we talked, "Bigger stock + fallback key" and "Keep it, off by default (Recommended)", go into the next build, IDs and requests (LRI R58).

## What phase 1 gives you

- **One ID for your whole account**, the same on every computer. Settings → Account shows it as "Your ID", with Copy (SCOPE §0).
- **A device ID for each computer**, listed under Devices with its name, and who added it and when (SCOPE B2, H4).
- **A 25-word recovery phrase**, made at setup, shown once and typed back. A wrong word is named, and nothing is guessed (SCOPE A1).
- **Adding a computer takes a short code and seven emoji**, as in Matrix, with no long strings to paste. The new computer then joins your chats by itself (SCOPE E1 to E5, F1, F2).
- **You can remove a computer, and lock out a lost one that holds your phrase's key.** Contacts see one person, with "· 2 devices" (SCOPE G1 to G6, H6).
- **You can change your recovery phrase with the old one, at once.** "Your ID", your computers and your chats stay. Your contacts are asked nothing, and see no change. From then on your computers refuse the old paper (SCOPE K1 to K9).

## What you will test

Each session is short and uses two of your Windows PCs. The lead plays your contact "Bob" from a test tool. Each session starts from a fresh setup, so "Your ID" is new each time. Keep that session's paper, because a paper from an earlier session is refused (PLAN, "The owner's sessions").

1. **Session 1 (slice 1).** Set up PC-1, see "Your ID" and its device ID, chat with Bob, then restart the app.
2. **Session 2 (slice 2).**
   - Add PC-2 by its code. Both screens show the same seven emoji.
   - The chat appears on PC-2 with no paste. Earlier messages show as one line, "Sent before this device was added".
   - Bob sees one person with two devices. An attempt where you tap "They don't match" changes nothing.
3. **Session 3 (slice 3).**
   - Remove PC-2 from PC-1, then add it back: it gets a new device ID under the same "Your ID".
   - Lock out PC-1 from PC-2 with the phrase, and make PC-1 a phrase computer again.
   - End the account.
4. **Session 4 (slice 4).**
   - On PC-1, change your phrase: type the old one, write down the 25 new words, and type them back.
   - "Your ID" is the same on both computers. Bob still sees one person, with no message about it.
   - On PC-2, try the old paper. It is refused, and named as a phrase this account no longer uses. The new paper works.

Please report any sentence that reads false, any screen that is unclear, and how long each step took. The lead runs each build end to end on the alpha before your session (SCOPE §9).

## When

- **The earliest thing to test is an optional preview, around day 5 to 6 (slice 0).** You would see the new screens with made-up data. Nothing in it is encrypted (PLAN P5, Task 6).
- **Slice 1, around day 12 to 14.** The first build with a real phrase and a real "Your ID".
- **Slice 2, around day 21 to 24.** Your headline: one ID across two computers.
- **Slice 3, around day 28 to 33.** Then **slice 4, around day 33 to 38**, which completes phase 1.
- Slices 3 and 4 moved about a day, for the second review's fixes. The phrase change is its own slice so that it does not hold your removal session back, and so that it gets its own review (PLAN P13).

## What the reviews fixed before any code

Two red teams read the plan. Every serious gap they found is fixed in it (PLAN, "Review dispositions" and "Task 2 dispositions"):

- **A frozen chat.** One of your computers could have sent a change that every other member refuses. That freezes the chat for everyone, for good. Now each computer checks its own change before sending it.
- **A key left behind.** A phrase computer that removed itself kept the phrase's key on its disk. Now it erases the key first, and your other computers offer to lock it out, in case it was not you.
- **A key left behind, again.** If another program held that key's file at that moment, the key could still stay, in a folder the app never opens again. Now a computer does not finish leaving your account until the key is gone, and it says so. A computer you lock out erases its key too.
- **The wrong phrase.** Another account's phrase, or one slipped word, could have broken things. Now that phrase is refused, and nothing changes.
- **An emoji timing gap.** A server that knew the code could have beaten the emoji check with heavy computing. Now the new computer waits for the other side to reveal first.
- **A false remedy.** The alarm would have offered "Change my recovery phrase" even where a change cannot help. Now it says so, and tells you how to start over.

## What stays true in this build

- **Your phrase cannot bring your account back yet.** If you lose every computer, you start over with a new ID (SCOPE R2).
- **If someone at an unlocked phrase computer of yours removes your other computers before you lock it out, your phrase cannot win your account back in this build** (SCOPE R1).
- **A removal acts at once.** There is no security delay until the server part, as your own ship order says: "phrase setup and the delay wait for the server" (SCOPE X1; OD:99).
- **Changing your phrase removes no computer.** A lost computer stays on your account until you remove it or lock it out (SCOPE R3).
- **A phrase you replaced still counts in a chat until one of your computers in that chat has run since the change.** The computer you change it on does this at once for its own chats, so open URmessage on your other computers soon after. In a chat none of your computers is in any more, a replaced phrase keeps counting for good, your first phrase included. Whoever holds it could act as you there, but only if they get into that chat (SCOPE R3).
- **If the alarm says a replaced phrase was used, changing again cannot undo it.** Start over with a new ID: remove each computer, end the account on the last one, and set up again (SCOPE R2, R3).
- **Not yet:** a new computer cannot read older messages, and there are no safety numbers, no QR codes and no chat by ID (SCOPE §4).

## Defaults we chose (say "flip" to change any)

- **At most 10 computers per account,** which is the chats' own limit. Going to 32 means raising both limits together (SCOPE X5).
- **Leaving a chat leaves it on that computer only,** in phase 1. That computer stays out unless someone invites it again. Leaving on all your computers comes in phase 2 (PLAN P1).
- **Ending the account on its last computer** erases the phrase's key and marks the account ended. The next setup starts in a fresh folder. The rest of the old folder is not wiped (PLAN P2, P9).
- **Up to four phrase changes per ID.** A fifth means starting over with a new ID. The cap keeps the record each of your computers carries in every chat small, and can be raised later (PLAN X12).
- **"Your ID" stays the same when you change your phrase** (PLAN P14). A new ID at each change would not close the gap above, and your contacts would see a new ID each time.
- **The list of many chats is built alongside phase 1, and arrives with IDs and requests**, the next build after this one (PLAN P11).

There is no question for you this time. Nothing the reviews found departs from what you have already decided.
