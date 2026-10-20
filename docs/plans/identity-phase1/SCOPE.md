# Identity layer, phase 1 (I1): the scope of the next test build

**Filed copy.** This scope is filed in `urnetwork/message-server` as `docs/plans/identity-phase1/SCOPE.md`, and the ledger entry that files it lists every change made in filing it. `PLAN.md` is the plan, filed as `docs/plans/2026-10-16-identity-layer-one-account.md`. `identity-phase1/<name>` is the file of that name in this folder, where `FOR-OWNER.md`, `REDTEAM.md`, `REDTEAM-TASK2.md` and `LEAD-RULINGS-I1.md` (LRI) are filed. Local paths are replaced by labels. `lib@<sha>`, `srv@<sha>` and `app@<sha>` are `urnetwork/message`, `urnetwork/message-server` and `urnetwork/message-windows` at that commit, as read in a local clone, and `app:` paths are under `app/src/App`. The owner's review file (OWN) is the owner's decisions review of 2026-10-05, in no repository. The lead's scratch folder is in no repository either: it holds every `scratchpad/...` path, and the designs, reviews and rulings that the Inputs below name by a relative path or a short name, such as OD, M5, F1 and D2, and LR, the lead's rulings of 2026-10-15, which this scope cites without defining. Its Inputs name LRI R48 to R60, the rulings it was written to; R61, R62 and R64 came after. R61 takes X11 to X14, P14 and P15 as planned, which section 3 still gives as new, for the lead. `app@a832482` is the head of urnetwork/message-windows#8, open when this scope was filed.

**Writers:** the scoper of the identity-phase-1 round; then the finalizer, who applied the red team's fixes in place (`identity-phase1/REDTEAM.md`; the dispositions are PLAN.md's "Review dispositions"); then the reviser, who brought the phrase change into I1 for the owner's answer of 2026-10-16 and applied the lead's rulings R48 to R57; then Task 2's finalizer, who applied the dispositions of Task 2's red team (`identity-phase1/REDTEAM-TASK2.md`; PLAN.md's "Task 2 dispositions"). **Date:** 2026-10-16. **Status:** a scope, not a spec. Nothing was built or run; no repository, server, ledger or spec was changed. **Declined actions:** none.

**Inputs.**
- `OD` = `scratchpad/foundation-designs/round5/OWNER-DECISIONS.md` (binding). `M5` = `round5/MODEL-v5.md`; its H.10 (M5:422) says its last revisions are unreviewed, and §3 below names the four of them I1 builds on. `F1` = `foundation-designs/F1-identity-layer-FINAL.md`; `F3` = `F3-seedphrase-recovery-FINAL.md`; `T1`, `T2` = `hardening-designs/T1-join-seal-FINAL.md`, `T2-safety-numbers-FINAL.md`; `MB` = `round5/MATRIX-BASELINE.md`. `V4` = `foundation-designs/round4/CORE-MODEL-v4.md`, whose F.0 (1) holds the formats M5 H.2 takes (M5:377).
- `D2` = `scratchpad/accounts-requests/DESIGN-v2.md`, whose §2.0 carries the lead's reconcile note (D2:145-159). `DESIGN` = `DESIGN-v1.md`, which the first rows of this file were written against. D2's lines moved down by 4 at 03:04, when the lead put LRI R58's note at its top: the D2 lines cited here before Task 2's dispositions now read 4 lower (ID1 :172, DID1 :189, IL8 :140, the reconcile note :149-163, VID2 :326 [m]); the new citations are current.
- `LRI` = `identity-phase1/LEAD-RULINGS-I1.md` (R48 to R60). `REDTEAM-TASK2` = `identity-phase1/REDTEAM-TASK2.md`, Task 2's red team. `OWN` = the owner's review file (OWN) of 2026-10-05, A28 to A31 at OWN:426-529.
- `lib:` = `lib@c7501a19`, whose tree equals `main` `c7949cfd`. `srv:` = `srv@37dd710f` (`main`). `app:` = `app@a832482`, under `app/src/App`. `git status --short` was empty on all three [m].
  - The first round read srv at `srv@20fc48db` and app at `badf2e2c`. Since then srv changed only SPEC-LEDGER.md, Spec A and Spec C, and app changed seven files that no line here cites [m: `git diff --stat`]. So every srv and app line cited here reads the same at the new commits.

**Marks.** [m] read at the cited place in the session that wrote the line: the first round's marks are its writers', and this revision's reads are in §10. [c] reasoning. [a] an assumed number or choice, for the spec to fix. **owner**: the owner's words.

**Names.** **I1** is this phase. **R** is the IDs-and-requests build (D2 §8). **I2, I3, I4** are the later identity phases (§4). A **phrase device** keeps the phrase's key (M5:22). **D** is the security delay. The **self group** is your devices' own group (M5 AD6). The **root** is the identity key of the identity's first phrase (D2 IL1). A **step** is the form-1 record by which an identity key signs its successor (V4:1011-1012), and the **chain** is the steps from the root to the current key (D2 IL2).

---

## 0. The answer in brief

1. **I1 gives one account ID with device IDs under it**, the owner's first item (OWN:485, "One ID for a whole account and device IDs"). It builds M5's identity step (M5 H.7, :416) with three changes, and adds the account ID of D2 §2.1. The three: no labels yet; no wait on a removal; a code the server carries instead of pasted link codes.
2. **In I1:** the 25-word phrase and the identity key made from it; device keys and device IDs; the signed device list, in every leaf and checked by every member; the self group; adding a device with a short code and seven emoji; removing a device, with the phrase as the second factor; locking out a phrase device; **changing the phrase with the old one, which keeps "Your ID"**; Settings → Account with "Your ID" and Devices.
3. **The calls that shape it** (§3 has each, with what it gives up):
   - the delay is **off** in I1 and arrives with the server part (I3);
   - the **server carries the link code**, so nobody pastes a long string again (OWN:451);
   - the **phrase change is in I1.** The owner answered "No, in phase 1" to moving it (LRI R56.1). It has no server part to lean on (X11), every leaf carries the chain (X12), and the self group moves in place (X13);
   - **T2's labels** move to R;
   - the device cap is **10**, the conversations' own cap, until both are raised together.
4. **R plugs into** I1's list checks and chain verifier, its words-scoped hooks, its self-group record channel and its rendezvous client (§5). R builds the proof, the binding check, the signers, the derivers and the events itself, against D2 §2.0 (PLAN P10, taken; LRI R51).
5. **The alpha is reset**; nothing is migrated (§6).
6. **The owner tests,** in four sessions: set up, add a second computer, chat from both, remove one, lock out a phrase device, change the phrase, restart (§8).

---

## 1. The ground: what is built today [m]

| # | Fact | Where |
|---|---|---|
| G1 | **A device is an identity.** The credential is the device signer's public half: "THE CREDENTIAL IDENTITY IS THE SIGNER'S PUBLIC HALF". | lib:sdk/urmessage/device.go:445-457 |
| G2 | The signer and the X-Wing seed are minted once per store and persisted together in the record `device`, kind 4, of 3 or 4 parts. | device.go:542-583; statestore_durable.go:1191-1193, :2035-2096 |
| G3 | Roles key on that identity, and the founder's device is the owner. R6a lets an identity add its own further leaves. The cap is 10 leaves per identity. **R6c refuses every change of a leaf's identity, the committer's own path included; mls alone would allow it.** | device.go:931-934; roles.go:28-39, :70-74, :170-190, :192-214; mls/errors_lifecycle.go:37-38; mls/group_policy.go:97-105 |
| G4 | **A leaf carries only 0xF002**, at creation and after every Update. 0xF004 is capability-only, and 0xF005 and 0xF006 are unclaimed. | mls/group.go:550, :1804-1867; mls/extension.go:86-94 |
| G5 | Key packages are single use, and the store enforces it. | device.go:734-758 |
| G6 | **The store is plaintext:** "FILE PERMISSIONS AND NOTHING ELSE". A copied folder is a second device. Kinds 1 to 10 are taken, and there is one version lever. | sdk/urmessage/doc.go:158-163, :190-205; statestore_durable.go:850, :856-865 |
| G7 | No safety number and no leaf-binding check exist in non-test code. | grep for `SafetyNumber`, `ErrKeyPackageUnbound` and `ErrCommitIdentityUnbound`: no hit outside tests |
| G8 | A leave is a local forget. The leaf stays until an admin removes it. | sdk/urmessage/forget.go:10-40 |
| G9 | **The server has no device and no account table.** All eight tables are keyed by group. Per connection it holds a client_id and a nonce, in memory. The endpoint authenticates no client and mints a fresh id per TLS session. | srv:store/migrations.go:84-363; peer/connection.go:93-104; endpoint/endpoint.go:12-23 |
| G10 | The rendezvous (arms 20 to 24) is designed, and "no rendezvous arm is served". One request is at most 131,072 octets. | lib:protocol/message.proto:846-922; srv:cmd/message-server/config.go:282; peer/frame.go:47 |
| G11 | **The app holds one conversation.** "A device holds one group in this build". At start it opens group 0 of whatever Restore lists. | app:Live/LiveMesh.cpp:2992-2998, :2154-2156 |
| G12 | The app's device list is empty because "The protocol carries no device list". A DM is told from a group by **leaf** count. | Live/LiveWorld.cpp:545-549, :288-292 |
| G13 | Settings shows "This device" and "Linked devices", and ACCOUNT is an inert group. | Views/SettingsView.cpp:209-224, :377 |
| G14 | The URnetwork credential is a developer JWT file, and the app has no login screen. A join code is a key package written to a file and pasted. | LiveMesh.cpp:241-252, :1141-1220; MainWindow.xaml.cpp:472-499, :554-579 |

---

## 2. I1: the exact feature list

Rule ids are M5's unless named. **lib** is `message`, **srv** is `message-server`, **app** is `message-windows`.

### A. The phrase and the keys (lib)
| # | Feature | Source |
|---|---|---|
| A1 | **The phrase, version 1:** 25 words of the BIP-39 English list, holding 267 random bits and an 8-bit checksum. It takes F3's list, normalization and per-word check. It does **not** take F3's 19-bit checksum or its typo search: a wrong word is named, and nothing is corrected. | OD:36-39; M5 C.0 :125, TR13 :147, H.3 :391; F3:306-329 |
| A2 | **One stretch, then the keys.** Argon2id over the phrase's bits (t = 3, m = 262,144 KiB, p = 4) [a, not frozen]. From it come the identity key (IRK) and `isk_root`, and from `isk_root` the phrase's key ISK_g for key number g. Backup keys are not derived in I1. | M5 C.0 :125-128, H.3 :399; F3:339-341; F1:345-352 |
| A3 | `IskCert(g)`: IRK certifies ISK_g, with no timestamp, so every phrase holder mints the same octets. | F1:370-376; M5 H.2 :378 |
| A4 | **What is kept.** The words, the stretch output, `isk_root` and IRK's private half are erased at the end of each ceremony. Only `isk_seed[g]` is kept, and only on phrase devices, for the current key and key number. A phrase device that removes itself or ends its identity erases it first, and does neither while that erase fails; a locked-out device erases it before it shows itself removed (G1, G5; REDTEAM H2; PLAN P15). A phrase change replaces it (K6). | M5 C.0 :126-127, TR7 :141; F1:350, :356 |
| A5 | **The device key is today's device signer**, unchanged. It is never in any backup, and every setup makes a new device with a new key. | OD:65; M5 AD7 :158; device.go:542 |

### B. IDs (lib, app)
| # | Feature | Source |
|---|---|---|
| B1 | **The account ID** follows D2's ID1, with `u16(id_version = 1)`, `root_pub` = the root, and a 16-octet random salt minted at the first device. It is a UUIDv8 of 36 characters, the same on every device. In I1 only Start over changes it; a phrase change keeps it (K3). | DESIGN:95-107; D2:168-174 [m]; REDTEAM M10 |
| B2 | **The device ID** is D2's DID1, over the root and the device key: the first 8 octets of SHA-256(`"URmessage/v1/device-id"` ‖ LP(root_pub) ‖ LP(device_pub)). It is shown as four groups of four lowercase hex characters, so that nobody takes it for an account ID, and only a new device key or a new root changes it (D2 DID1, DID3). It needs no field and no state. | D2:185-187 [m]; §3 X6; REDTEAM M10 |

### C. The device list and the binding (lib)
| # | Feature | Source |
|---|---|---|
| C1 | **The list** is a base signed by ISK_g, plus additions and self-removals signed by device keys. Its version is (step, g, base number, count), where step counts the chain's steps (K4). The entry flags are *phrase device* and *being removed*; the second is reserved and never set in I1. | M5 C.0 :130, H.2 :379-381; D2 IL5 :132 |
| C2 | **The checks:** TR2 (a device is yours only if your newest list names it); TR3 (a device key removes only itself); TR4 (no list goes backward, additions only extend, a fork is refused, a higher g retires a lower one, and a later key of the chain retires an earlier one); TR7 (remembered marks); TR12 (cap 10 in I1, at most 16 waiting changes on one base, a self-removal never refused). | M5:136-146 |
| C3 | **Folding:** a phrase device folds the waiting changes into a new base when it next runs. | M5 TR5 :139, TR12 :146 |
| C4 | **Every leaf of every group** has credential = the current IRK and carries 0xF005 {IskCert, base, changes, the chain (K4)}. Its signature key must be named in the list. A link group is the one place a profile-1 leaf may stand. There is one mode, and no legacy mode. | F1:403-406, :463-473; M5 H.2, H.6 :414; OD:32 |
| C5 | **mls work:** key-package, founding, Update and path leaves carry 0xF005 and keep it, which fixes T2:234; `OwnLeafPatch` on own commits; the 0xF006 group-context extension; F005 and F006 among the capabilities; every group requires F004 and F005. | F1:750-756; G4; OWN:1011 |
| C6 | **Role rules over trees:** the binding (F1's R6e and R8-CUR, which is TR2); fork refusal (R8-EQ); **R8-SIB**, under which a sibling's leaf is removed only once the newest list no longer names it ("It stops a stolen computer evicting its owner's others", a recommendation the owner accepted with every other: F1:128); R9 for system groups; the 10-leaf cap; and, for the phrase change, F1's R6s in place and the rank rule (K5, K6). **They run on the sending side too**, over the would-be tree, so a device never publishes a commit its own rules refuse. Once the server takes such a commit, it halts the group for every member (REDTEAM H1). | F1:497-506 [m], :532-570; OWN:1015 |
| C7 | **Heads:** for every root seen, the newest list, so that none goes backward. The heads are one record, store kind 12 [c]; kind 11 is the identity record and kind 13 the phrase key, as PLAN Task 12 and P3 have them, since F1's proposed 9 and 10 are now taken (LRI R62). | F1:603-612, :797; statestore_durable.go:864-865 |

### D. The self group (lib)
| # | Feature | Source |
|---|---|---|
| D1 | It is founded at the first device, with 0xF006 {1, root}. Every leaf is the identity's (R9), read through the chain, so the self group moves in place at a phrase change (X13). It is **never** in a conversation list, which closes the trap in G11. | M5 AD6 :157; F1:684, :702 |
| D2 | List changes travel in it as patches to the signer's own leaf, linearized by its commits. | M5 TR8 :142; F1:614-617 |
| D3 | **Records, in a kind registry,** refused outside system groups: device names; notices; key-package offers and claims; invites for a sibling, in parts of at most 60 KB. A block of kinds is reserved for R. | F1:420-428; kind.go:72-105 (0x0A-0x3F free) |
| D4 | It restores with the device, in the about 0.5 s the owner timed. | OWN:474 |

### E. Adding a device: a code and seven emoji (lib, srv, app)
| # | Feature | Source |
|---|---|---|
| E1 | **The new device (N)** shows "Set up this device". Its first option is a code of about 12 characters, valid 10 minutes [a]: "type this on a computer you already use". Its second is "This is my first device", which is AD1: the words shown once and typed back, and only then the identity, key number 1, the first base, the salt and the self group. | M5 AD1 :152, H.4 :405, H.7 :416 |
| E2 | **The link box.** N registers a link box at the server (S1 below). Its card holds N's profile-1 key package, `commit_n` and a name, sealed under a key derived from the code. The server reads neither the card nor the deposit unless it finds the code, by a search of about 60 bits [a] or a leak. A server that finds it can answer Open with a card of its own, so that the deposit is made to it and it reads that device's leaf; the emoji still differ then, so the link grants nothing (E3) [c; REDTEAM L2; Task 4's review F3, LRI R64]. | DESIGN:189-198, :236-242 shapes; F1:412-414 |
| E3 | **The existing device (E)** goes to Devices → Add a device and types the code. It checks that the list has a place, creates link group LG (0xF006 {2, IRK}) and adds N. It deposits the T1 v3 invite, sealed to the card's key, then reveals `n_E` at epoch 1. N joins, reads `n_E`, and only then reveals `n_N` (F1:654 [m]). This is commit-then-reveal: N is bound by `commit_n` before E reveals, and E's nonce is out before N reveals, so neither side can choose its nonce after seeing the other's (REDTEAM H4). | F1:651-657; M5 AD2 :153 |
| E4 | **Seven emoji of Matrix's 64** come from LG's exporter at epoch 1, over F1's SAS input: 42 bits. Both devices show them. "They match" / "They don't match" is asked on both. Three failures burn a session, and E runs at most 5 sessions an hour. | OD:62; MB:41; M5 H.3 :396; F1:416-417, :649 |
| E5 | **The grant.** After both matches, E signs an addition, or a base if E is a phrase device, naming N's key. It commits that to the self group and posts the grant {IskCert, list, chain, self group, salt, names} in LG. N accepts it only after its own "They match", and only if the list names its key under the certificate. N then persists, rebuilds its engine with credential = IRK (device.go:456-457 builds it once today) and posts bound key packages. E adds N to the self group, and to its conversations (JN1). N retires its box, and both forget LG. | F1:658-664; M5 AD2 |
| E6 | **Endings, one screen:** timed out; cancelled; no match; "Remove a device first"; "This device can add no more until ⟨phrase device⟩ is opened". | M5:274, :295 |
| E7 | **No QR in I1:** the emoji always run. | M5 AD2: "With no camera on either, both show the same seven emoji" (M5:153 [m]); MB:41, Element X "offers only emoji". OWN:664 is T2's QR question (REDTEAM L6) |

### F. Getting into conversations, by your own devices only (lib)
| # | Feature | Source |
|---|---|---|
| F1 | **JN1 and JN2.** The approver adds the new device at once. Every other device of yours, when it next runs, adds a listed device it finds missing and removes a leaf the list no longer names. The designated adder is your lowest leaf; the others act after 10 minutes. | M5 JN1, JN2 :200-201; F1:686-692 |
| F2 | It claims the sibling's offer, commits the Add, and posts the T1 v3 invite in the self group. The sibling joins with no tap, and only from an invite its own identity's device posted. Its expectations come from its own store. | F1:688; T1:263, via DESIGN:319 |
| F3 | **Leave is per device in I1.** The left device's leaf stays until an admin removes it, as today (G8), so fan-out never finds it missing, and fan-out's respected-removal rule keeps it out after an admin's removal [c]. The dialog says "on this computer". Identity-wide leave is I2's: PLAN P1 stood, and the owner kept the default (LRI R50; OWN:529 [m]). | M5 JN8 :207; F1:697-700; G8; REDTEAM M8 |
| F4 | **"From me" means any device of yours; "mine" means this device sealed it**, under any key of your chain (K6). The device-level identity sites move to the identity: lib group.go:2783, :3054, :5049-5054, :5664, :5800. | F1:774-776 |
| F5 | **A new device starts with no history.** What was sent before it joined shows as one line. The library answers `not_a_member_yet` for such a record, where today it answers `out_of_window` and the app draws a gap row each; the app draws a run of them as one line (PLAN Tasks 26 and 28; REDTEAM M2). | M5 BK4 :215, JN7 :206, row 18 :288 |

### G. Removing a device, with D off (lib, app)
| # | Feature | Source |
|---|---|---|
| G1 | **Remove this device** (RM1) is the device's own signed self-removal; your other devices remove its leaves when they run. On an only device it says "This ends this identity": the identity is marked ended and the app opens a fresh folder (PLAN P2, taken). On a phrase device, both acts first erase the phrase's key record, before anything is sent (PLAN P9, taken; REDTEAM H2). If that erase fails, nothing is sent, and the device stays as it was and says so, until the person acts again (PLAN P15; Task 2's T2-H1). | M5 RM1 :163, H.7 :416 |
| G2 | **Removing another device** (RM2): a phrase device asks nothing, and any other device asks for the phrase and becomes a phrase device. The dialog lists every device, and one act may name several. **It acts at once.** Every act that takes the words (RM2, RM6, AD5, PC1) first checks that they are this identity's current ones: derived IRK against the current key, and ISK_g against the certificate. If they are not, it changes nothing; words of a key the chain has retired are named as an old phrase (F1:637, :671 [m]; REDTEAM H3; K1). | M5 RM2 :164, RM4 :166 ("With D off it is immediate") |
| G3 | **Lock-out** (RM6): removing a phrase device always asks for the phrase. It makes key number g+1, asks "keep or remove" of each device, and the other phrase devices must type the phrase again. It may name no device: that is the lock-out a phrase device's self-removal offers (G6; REDTEAM H2). | M5 RM6 :168, H.4 :407; OD:59 |
| G4 | **Make this a phrase device** (AD5), in Settings. | M5 AD5 :156; OD:61 |
| G5 | **"This device is no longer on your account"** (RM8) says when, and by which device. It offers "Add this device again", which makes a new device with a new ID. "If this was not you" sends you to a device still on your account (§3 X10). A phrase device that was locked out first erases its phrase key, as TR7 has every phrase device do on a higher number; until that erase succeeds it says it could not finish leaving, and tries again at each start (PLAN P15). | M5 RM8 :170, TR7 :141 [m] |
| G6 | **The notice** (TR10): "⟨device⟩ was added / removed on ⟨date⟩ by ⟨device⟩", on every device, from the self group. An added device's notice offers Remove. A phrase device's self-removal says "⟨device⟩ held your recovery phrase's key and removed itself. If this was not you, lock it out.", and offers the lock-out (G3; REDTEAM H2). **The alarm** (TR11) has its two reasons: a list this device cannot explain, a second successor of one of your keys included; or a change signed with this device's key that it did not make. It offers "Check my devices", the lock-out, and from slice 4 "Change my recovery phrase" (M5:145), where a change can help. For a second successor of an earlier key it offers no change: it says a change cannot undo it, and that a new ID comes from ending this identity and setting up again (R2, R3; PLAN Task 43; Task 2's T2-H2). | M5:144-145 |

### H. What the app shows (app)
| # | Surface | Source |
|---|---|---|
| H1 | First run: "Set up this device" (E1). The phrase screens are excluded from screen capture and from spelling and prediction, so screenshots of them come out black. | F3:894-900 |
| H2 | The 25 words, once, with "These words cannot bring your account back yet", then typing them back. The same screens serve a phrase change (M5 row 7). | M5 rows 7-8 :277-278, H.7 |
| H3 | Add a device (enter the code); the emoji; the ending screen. | M5 rows 3, 4, 9 |
| H4 | **Settings → Account**, today inert (G13). "Your ID" with Copy, and "Change my recovery phrase" (X14). **Devices:** each device's name, device ID, "this device", the phrase-device mark, and when and by whom it was added; with rename, Remove and "Make this a phrase device". "Linked devices" is counted from the list (G12). | M5 row 10 :280 |
| H5 | The Remove dialog, the phrase field and the only-device line; the removed screen; the notice and the alarm. | M5 rows 5, 12-15 |
| H6 | **Conversations.** One row per person, with "· N devices". A DM is told by **identity** count, where a person's identity is the root, so a phrase change never splits one person in two (G12; K7). Contacts see the quiet line "⟨name⟩ added a device" or "removed a device". The member JSON already carries `identity_pub` per leaf (lib:sdk/cgo/exports_message.go:1486), and gains `device_id` and `identity`; messages gain `from_me`. | OD:84; M5 SE4 :226; F1:792 |
| H7 | Still one conversation per device (G11), and today's join-code flow for conversations until R; that flow now carries bound key packages. | DESIGN:744-759 |

### K. Changing the phrase with the old one (lib, app)
| # | Feature | Source |
|---|---|---|
| K1 | **With the old phrase, at once,** on a device the newest list names (X11). The old words are checked against the current key and its certificate (G2); the new phrase is made here, shown once and typed back. From then on the old paper is refused wherever words are asked for, named as "a recovery phrase this account no longer uses", and it changes nothing. | M5 PC1 :184, H.4 :408 [m]; OD:75, :99 [m] |
| K2 | **A new identity key, signed by the old one.** The step is Ed25519(old IRK, LP("URmessage/v1/identity-succession") ‖ LP(new IRK)). The new key certifies its key number 1, and its first base names every device as it stands, with this device the only phrase device: "A phrase change removes no device". The move is stored before anything is sent, and a crash after that resumes with no words. | M5 PC2 :185 [m]; V4:306, :308, :1011-1012 [m] |
| K3 | **"Your ID" stays.** The account ID (B1) and every device ID (B2) are taken over the root, which the chain keeps, so neither changes. | D2 IL1 :128, ID3 :174, DID3 :187 [m] |
| K4 | **The chain.** Every leaf carries the steps from the root to its key, at most 4 [a] (X12). `VerifyIdentityChain` checks them: a pure function in messagegroup, beside `VerifyDeviceList`, which a stranger can run with no store. A form-2 step, the 7-day change's, is refused. A list under a later key of the chain is newer than any under an earlier one. | D2 IL2, IL5 :129-132, VID2 :322 [m] |
| K5 | **It ends the old key wherever it is seen** (the rank rule). In a tree that holds the step, a leaf under the old key is judged by the new key's list, and no list of the old key is taken. Two successors of one key are a conflict that no tree takes: the first into a tree shuts the other out. Where none of your devices has run since a key was replaced, that key still counts, for good, the first phrase's included (§7 R3; PLAN P14). | M5 PC3 :186 [m]; V4:317-318, :1064 [m] |
| K6 | **Each device moves itself in place,** with the same device key, in its self group first (X13) and then in every conversation, the next time it runs. Every member accepts the move on the old key's signature, and the roles move with it (F1's R6s). A device takes the change only from its self group (TR8). The other phrase devices erase the old key's record and need the new words (AD5). | M5 PC4 :187, TR7 :141, TR8 :142 [m]; F1:551-570 [m] |
| K7 | **Contacts are asked nothing and shown no line;** they see one person throughout (H6). The label and the dated page of PC5 are T2's, and come with R (X4). | M5 PC5 :188 [m] |
| K8 | **Races.** The self group's commit order decides. A change that a lock-out, a removal or a self-removal overtook is rebuilt on the newest list. One that another change overtook, or whose device was removed, is void: nothing is sent, and its new key is erased (PLAN authority (i)). An act that took the old words and lost says so, and asks for the new ones. | PLAN Task 43 |
| K9 | **Across a change.** A stolen phrase device, or a copy of its folder made before a change, keeps the key it had. Its lists count wherever none of your devices has run since that key was replaced, and so does the paper of any earlier phrase, the first included, which alone can also make a rival change, since a step needs the old words (R3; Task 2's T2-M2). The device stays one of yours until you remove it or lock it out, since a change removes no device. A lying server can withhold the change from one of your devices: that device raises the alarm, sends nothing that others would refuse, and moves once its self group delivers. No server can make a step, which needs the old words. A copy made in the seconds between a void change's store and its erase keeps a rival step: a residual, filed as MG-18. | PLAN Tasks 42, 43; authority (f)P, (i) [c] |

**Counts** [c]: **14 surfaces** (M5 rows 2-5, 7-10, 12-15, 22, and one reason of row 18) against M5's 23. The phrase change uses rows 5, 7 and 8 and a done toast, which M5 does not count (M5:295 [m]), and its entry is one action on row 10 (X14). **10 concepts** (M5 D.1 rows 2-5, 7, 9, 12, 13, 15, plus "Your ID") against 18. Row 7 is the phrase change (LRI R56.1). Row 1, "Account login", is not counted, since I1 has no login screen and reads a developer credential (G14). The first scope counted row 1; with it the count is 11 (PLAN P12). Task 2's fixes add no surface and no concept: their sentences stand on rows 12, 13 and 15, and name acts that exist (PLAN P14, P15).

### S. The server, the tools and the C exports
| # | Feature | Source |
|---|---|---|
| S1 | **Arms 20-24 served for one kind, the link box.** Register; Open, which returns the sealed card; one Deposit of one fixed size, sized from T1's 4,667-octet two-member invite plus one identity extension [a; T1:198-202, F1:443]; Collect with push; Retire. TTL 10 minutes, depth 2, a global cap on live boxes, failing closed [a]. The tables `message_rendezvous` and `message_rendezvous_deposit` come as new appended migrations. R extends the same tables and handlers to inboxes and reply boxes. | proto:856-922; DESIGN:452-503, :747-751; migrations.go:29-35 |
| S2 | Nothing else changes at the server: self groups and link groups are ordinary groups. | F1:805 |
| S3 | `sdk/livepeer` and liveprobe gain an identity, so the lead's participant can play the other person; the developers' file road stays. | DESIGN:649 |
| S4 | **New C exports:** identity (JSON: account ID, device ID, devices, phrase mark, notices, alarm, the number of phrase changes); create identity and confirm words; check words; link offer, link enter code, emoji, confirm, cancel and state; remove devices (with words when needed); make phrase device; rename; change the phrase and confirm the new words. The group lists leave out system groups. | F1:779-793; exports_message.go:617-860 |

---

## 3. Where I1 departs from M5 H.7, OD or DESIGN: for the lead to rule

| # | The source says | I1 does | Why [c] | It gives up | To flip |
|---|---|---|---|---|---|
| X1 | OD §4: "default 24 hour" (OD:43). M5 H.7: "A removal then waits 24 hours on your devices' own clocks" (:416) | **D off.** A removal acts at once; off is one of OD's values | The delay record needs backup keys and the server's ordering (DL1, :175). Without the server's hold the wait binds honest devices only (M5:241). So it would make **your** removal of a stolen device let that device read a day longer, and would stop no altered app. It also follows the owner's own ship order: "phrase setup and the delay wait for the server" (OD:99 [m]; REDTEAM §5) | The reaction window against an unaltered app on a stolen phrase device | Build RM3-RM5 and the being-removed state on device clocks now |
| X2 | M5 H.7 and F1 §2.8: on Windows the link codes are pasted | The server carries the link: a code of about 12 characters, and a link box | The owner: "sending someone an encrypted string that long is highly unreasonable" (OWN:451). R needs arms 20-24 anyway (DESIGN:747-751). Matrix carries verification over its server (MB:41) | A server change and a deploy in I1; the server sees when a link happens | Paste two codes, of about 2.2K and 6.8K characters [c, from T1:196-202 and F1:443], for one build |
| X3 | OD:99 (line 19) and M5 H.7: the phrase change with the old phrase "ship[s] with the identity layer" | **Built in I1, as PLAN's slice 4.** This scope first proposed moving it to I2. The owner answered **"No, in phase 1"** (LRI R56.1; OWN:524 [m]), so the owner flipped this row | — | — | — |
| X4 | M5 H.7 puts T2's labels in the identity step | They move to R | Strangers first arrive in R, and DESIGN's surfaces stand on M5 SE1-SE3 (DESIGN:599, :671-674). Built now, they would be built twice | No safety number and no label in I1 | Build T2's four surfaces (M5 H.6) now |
| X5 | OD:64 and M5 TR12: up to 32 devices | 10 | A conversation holds 10 leaves per identity (G3, MASTER §11). A listed device that no conversation could hold would be a broken promise | 22 devices | Raise both numbers in one spec edit |
| X6 | M5 H.2: the entry carries `device_id` (:379) | The device ID is derived from the root and the key, as D2's DID1 is (B2; REDTEAM M10) | It cannot disagree with the key and needs no state; 17 octets fewer per entry [c] | None found | Keep the field, and check that it equals the derivation |
| X7 | L-v5-2 and M5 SE7: names and Verified follow the person (OD:121) | Names stay per device, as today | That is T2's contact store (T2 §2.5.2) | The same contact can carry two names on two of your devices | Comes with R |
| X8 | M5 TR9: the screen-lock prompt before approving, removing or changing the phrase (:143) | Not in I1. The owner: "Yes, alpha only (Recommended)" (LRI R56.2): for alpha test builds only | It guards the same adversary as sealing keys at rest; both land in I2, before any non-alpha build | M5 risks 2 and 4 grow (§7 R5) | One WinRT consent call |
| X9 | M5 AD2: a QR code first, emoji where nothing scans | The emoji always run, after a typed code | M5 AD2's own clause: "With no camera on either, both show the same seven emoji" (M5:153 [m]); MB:41. OWN:664 is T2's QR question (REDTEAM L6) | Typing the code | — |
| X10 | M5 RM8: "If this was not you, type your recovery phrase" on the removed device | The line sends you to a device still on your account | Without the server's hold (RM7), a removed device reaches no group of yours [c] | — | Comes with I3 |
| X11 | M5 PC1 to PC5 and H.4 lean on the server part: "on a registered device" (PC1, :184); "register the new backup and write its state ... retire the old backup" (H.4, :408); PC3 ends waits and the 7-day change, and carries D and the backup over (:186) [m] | PC1 runs on any device the newest list names. H.4's order keeps "Old words checked; new phrase shown and typed back; sign and store the move on this device first; publish". PC3 keeps its first sentence. PC5's label and dated page wait for T2 (X4) | I1 has no table, no backup, no delay, no wait and no 7-day change (X1, §4), so those steps have no object, and the rest of PC1 to PC5 needs none of them | Nothing I1 has | Build those steps with the server part (I3) |
| X12 | M5 H.2 (:383) and V4 F.0 (V4:1014-1016) [m]: a leaf carries one predecessor | Every leaf carries the chain, the steps from the root to its key, at most 4 [a] (D2 IL2) | Validity reads only the trees (F1:337 [m]). So a device that missed a change moves in place only by evidence in the tree. With one predecessor, a device two changes behind cannot link its old key to the newest, and the person splits in two in that conversation. D2's proof carries the chain from the root anyway (D2 PR1 :204) | About 100 octets per step [c: V4:1114 [m]]. A fifth change needs Start over [a] | One predecessor, and each device moves one step per commit |
| X13 | F1 §2.11 (F1:746) and its C12(b) (F1:51) [m]: "A phrase change founds a new self group" | The self group moves in place, as every conversation does: each device moves its own leaf there first, and R9 reads its root through the chain | M5 founds a self group only for a device that is in none (AD6, M5:157), and founds a new one only at the 7-day change (H.4, M5:409) [m]. M5 wins where it differs (M5:7), and the owner took M5 (OWN:286-293 [m]). One self group needs no second fan-out, no window with two self groups, and no new erase | None found | Found a new self group, and bring each device into it through the old one |
| X14 | M5 D.2 row 11 (:281) [m]: "Settings, Recovery and backup: change or check the phrase, the delay, the backup switch, start over" | "Change my recovery phrase" is one action on Settings → Account (H4, row 10), beside "Make this a phrase device" | Row 11's other three items are not in I1 (X1, §4), so a row for one action would be a fifteenth surface, over PLAN's budget of 14 | — | Build row 11 when the delay or the backup ships |

**Ruled** (LRI R49, R56): X1, X2, X4, X6, X7, X9 and X10 are taken; X3 is the owner's flip; X5 is a default the owner did not flip; X8 is the owner's "Yes, alpha only". X11 to X14 are new, for the lead, as are PLAN's P14 (the root stays at a change) and P15 (no device leaves its account holding a phrase secret), from Task 2.

**M5 H.10 items that I1 builds on, unreviewed** (M5:422): TR7's memory of marks; TR12's pool of 16; RM6's dialog; the shorter entry. With them, X1, X2, and the phrase change with X11 to X13, get the red team of PLAN Task 2 before any spec moves (the project's rule: red-team crypto designs first; LRI R53).

---

## 4. Deferred: what, why, and where it moves

**The phases.** The owner's order (OWN:485) runs: I1, then R, then the URnetwork name. I2 can run beside R. I3 is M5's "server part" and resets the alpha (M5 H.7). I4 is the 7-day change.

| Deferred | Why it is not in I1 | Moves to | Meanwhile, in I1 |
|---|---|---|---|
| The security delay (DL1-DL5), the being-removed state and its cancel (RM3-RM5) | X1 | I3 | A removal acts at once |
| Typing the phrase on a new device (AD3, AD4); the server's table, head and hold (RM7); "Not me" (M5 d9) | They need the server's clock and hold. OD:99: "phrase setup and the delay wait for the server". The lead's J12: "restore stays off until the phrase change ships" (OWN:1342) | I3 | Losing every device means starting over (§7 R2) |
| The phrase change's backup and delay steps (PC3's second half; H.4's backup steps) | X11 | I3 | A change carries only the list and the conversations |
| The 7-day change (PC6-PC11) and the account tie | The account service must attest a fresh login (OD:76-79, :99) | I4 | — |
| The backup and its import (BK1-BK7) | Backup keys, the vault and the server's backup; OD:89 "History store first" | F2's store, then I3 | A device keeps only what it receives |
| History from the approving device (BK4's transfer) | It is written in F2's store format | I2 | A new device starts empty |
| Contacts letting a device in (JN3-JN6) | The server's carrier, arm 30 (M5 H.5 :412), and the server's list (RM7) | I3 | Only your own devices bring a device in |
| Start over as its own act (PC12), with notices to the old devices | Without the tie nothing reaches the old devices | I3 | Remove your only device, then "This is my first device" |
| Identity-wide leave (F1 C7) | PLAN P1: the one I1 erase made on another device's word. The owner kept this default (OWN:529) | I2 | Leave on this computer (F3) |
| T2: Trusted and Verified, the safety number, the warning, names that follow you | X4, X7 | R | — |
| Keys sealed at rest (T3 §2.4, F2) and the screen-lock prompt (TR9) | X8 | I2 | File permissions only (G6), in alpha builds only |
| The yearly paper check (TR13's reminder) | There is nothing to check for a year | Any later phase | — |
| QR, shown and scanned | X9 | When a camera path or a phone app exists | A typed code, then the emoji |
| 32 devices | X5 | A spec edit, in any phase | 10 |
| The profile (PR1-PR7); the inbox and reply boxes; requests; Change my ID; the server's key-package stock | R's own scope (D2 §8; OWN:490-493) | R | "Your ID" is shown and copied, and nothing uses it yet |
| The conversation list, with Requests at its top | R's longest pole (D2:782 [m]). The lead flipped PLAN P11 (LRI R50) | Built by W-app during I1 (PLAN Task 6b); it lands with R | One conversation per device (H7) |

---

## 5. The interface I1 provides to IDs and requests

### 5.1 What R needs (D2 §2.0), and what I1 hands it (lib unless named)

The lead's reconcile (LRI R51; D2:145-159 [m]) decides each row. R writes the proof, `VerifyKeyPackageBinding`, `SignAsDevice`, `SignWithPhraseKey`, `DerivePhraseKeyed` and the events against D2 §2.0 (PLAN P10, taken).

| D2 | I1 provides |
|---|---|
| IL1 the root | `Identity{RootPub, CurrentKey, Chain, Salt, KeyNumber, SelfGroupId}`. The root is the first phrase's key, and a phrase change keeps it (K3; PLAN P14). `AccountId()` and `DeviceId()` over it, with known answers (PLAN Task 10) |
| IL2 the chain | The steps from the root to the current key, in every leaf and in the identity record (K4; X12). It is non-empty after a change, so VID2 has something to check |
| IL3 the certificate | `IskCert(g)` of the current key (A3) |
| IL4 the list | Base, additions and self-removals; `ListVersion{step, g, base, count}`; the two marks (C1) |
| IL5 the list check | `VerifyLeafBinding`, `VerifyDeviceList` and `VerifyIdentityChain`: pure functions in `messagegroup`, which a stranger can run with no store and no self group (PLAN Task 11; LRI R51). Across a root's chain, a list under a later key is newer |
| IL5b the newest list held | The heads, per root (C7). R adds the accessor (REDTEAM L7) |
| IL6 device signatures | The device key signs the leaves and key packages. `SignAsDevice` is R's |
| IL7 the phrase's key | The phrase key record on phrase devices (A4). `SignWithPhraseKey` and `DerivePhraseKeyed` are R's |
| IL8 the owner key | **The words-scoped hooks,** at AD1's `ConfirmWords`, AD5, RM2, RM6 and PC1, before the words are erased (PLAN Tasks 32, 33 and 43; LRI R51, R56.1). At PC1 they run once, after the move is stored, with both the old and the new key in scope, which D2 MD6 needs (D2:756 [m]). No hook is registered in I1: R registers `"inboxown/v1"`, and R's first build resets the alpha (LRI R51) |
| IL9 the leaf binding | 0xF005 in every leaf and key package (C4, C5). `VerifyKeyPackageBinding` is R's |
| IL10 the self group | The record channel (D3), authenticated per sending device, with a kind block kept for R. List changes keep the self group's commit order; records keep the server's delivery order, which a lying server may show differently to each device (REDTEAM M12). So R carries every "first in order" inside a self-group commit (LRI R51) |
| IL11 events | R's, on I1's removal and change paths. R raises "a removal finished" only after the removal's self-group commit is applied (LRI R51) |
| IL12 the device ID | DID1 (B2), on Settings → Account |
| IL13 joins that commit | Not built in I1. The 90-day refusal is risk R16. R builds T1b's `Group.Rekey` and ends every join with it, I1's fan-out joins included (LRI R51, R52) |
| Arms 20-24 | srv: served for link boxes, on the designed tables. lib: a rendezvous client (Register, Open, Deposit, Collect with push, Retire). R adds the inbox and reply-box kinds, the four sizes and the limiter |
| The conversation list | Built by W-app during I1, app-only (PLAN Task 6b); it lands with R (LRI R50). The library already holds many groups and leaves system groups out of every list |

### 5.2 Notes for D2 [c]
- **The per-computer ID is gone:** profile 1 and row T (DESIGN:105-107, :595) fall away. "No temporary per-computer ID" (OWN:499). D2 replaced the profile field with `u16(id_version = 1)` (D2:168 [m]), and I1 computes ID1 and DID1 as D2 states them, frozen in MASTER's registry before any known answer is written (B1, B2; PLAN P8; REDTEAM M10).
- **What changes an ID.** In I1, only Start over: a phrase change keeps it (K3), as D2 ID3 says. From R, also Change my ID (a new salt, carried in the self group). From I4, a 7-day change, which VID2 refuses as a step (D2:322 [m]).
- **A list's version needs the chain's step.** D2's `SenderRef` carries (g, base, count) (D2:205 [m]). After a change, two lists can share those numbers under two keys of one chain, so R compares the step too, which it can read off the chain it hashes.
- **Identities made in I1 have no owner key pinned.** No hook is registered in I1, and R's first build resets the alpha (LRI R51; OD:110-114).
- **There is no server device table before I3,** so ID6's premise, "The server holds identity keys in its device table", holds only from I3. In I1 the server is told no identity key: commits are sealed records (lib:messagegroup/seal.go:132), and every invite travels in a sealed deposit, a self-group record or today's paste.
- **Capacity:** with 10 devices per list, DESIGN §2.5's profile-2 figures (:255) take a 10-device worst case, not a 32-device one. Each step of the chain adds about 100 octets (X12).
- **For D2 §8's stage 1** (D2:770 [m]): it lists PC1 to PC5, which I1 now builds (X3), T2's labels, which move to R (X4), and the conversation list, which W-app builds in I1 and which lands with R (§4).

---

## 6. Migration: the alpha is reset

- **Server.** At the deploy the alpha's database is wiped (OD:32; OD:110-114: "disposible"). The link-box tables arrive as new appended migrations, since a landed migration is never edited (srv:store/migrations.go:29-35). No row carries over.
- **Library store.** The identity record and the heads are new kinds (C7). I1 reads no build-03 store, so there is no upgrade step and no "This version starts fresh" screen (M5 F17 :340; H.8 :418).
- **App.** The first run is "Set up this device". The build-03 data directory is not read. It is kept, and READ-ME-FIRST says how to delete it by hand (PLAN P6, taken; LRI R50). It holds plaintext keys (G6) of identities the reset server no longer knows (§7 R14).
- **Compatibility: none.** Every I1 group requires F004 and F005, so a build-03 app can neither join nor be joined (OWN:1011). Everyone in the session runs I1 builds, the lead's participant included (S3).
- **Ahead.**
  - R may reset again, which is allowed.
  - I3 does reset (M5 H.7: "the package that ships the server part resets").
  - The first build whose users' data must survive adds a store version and one upgrade step (M5 H.8; OD:114).

---

## 7. Risks I1 accepts until later phases

Each is stated as a person would feel it, with the phase that ends it.

| # | Risk | Ends with | Source |
|---|---|---|---|
| R1 | Whoever holds one of your phrase devices unlocked can remove your other devices **at once**, and nothing waits for you to stop it. If someone at an unlocked phrase device of yours removes your other devices before you lock it out, your phrase cannot win your account back in this build: a removed device reaches no group (X10), and no new device can be set up from the phrase (§4) (REDTEAM M9) | I3 (the delay; X1) | M5 risk 4 :485; M5:57 "With the delay off there is no window" |
| R2 | Your phrase cannot bring your account back yet. If you lose every device you start over, with a new ID, and your contacts add you again | I3 | M5 risk 19 :500 |
| R3 | **After you change your phrase, every earlier one, your first included, still counts, for good, in a conversation where none of your devices has run since it was replaced.** There, whoever holds that paper can drop your devices, or make a rival change that shuts yours out, if a device of yours is still in it or a member adds theirs; a copy of a phrase device made before can drop them. The way back there is an invitation. **Changing your phrase again does not undo that:** if a recovery phrase of yours leaked, start over with a new ID (R2). **A change also removes no device:** a lost device stays on your account until you remove it or lock it out | Narrowed by I3's server, which takes no list of a retired key | M5 PC3 :186; V4:318 (UM-18) [m]; K5; PLAN P14; Task 2's T2-H2, T2-M2 |
| R4 | Your keys, including a phrase device's key, are protected only by file permissions, in alpha builds only (X8). A copy of a phrase device's folder can remove your devices until you lock that device out. If that device removed itself, your other devices' notice offers the lock-out (G6; REDTEAM H2) | I2 (sealing) | M5 risk 9 :490; G6 |
| R5 | Anyone at your unlocked computer can add their device to your account, remove yours, or change your phrase if they also hold your paper: there is no Windows Hello prompt yet | I2 | M5 risks 2 and 4 (:483, :485); X8 |
| R6 | A device you add starts empty: it cannot read anything sent before it joined | I2 (with F2) | M5 m4 :113; F5 |
| R7 | If no device of yours is left in a conversation, nothing brings you back; someone in it must invite you again | I3 | M5 H.7 :416 |
| R8 | A device you removed, if its app was altered, can still act in a conversation until another device of yours runs there | — (it stays in the full model: L-v5-12) | M5 risk 8 :489; OD:159-162 |
| R9 | Nothing yet lets you check that a contact is who they say: no safety numbers and no labels | R (T2) | X4; G7 |
| R10 | If you confirm the seven emoji without comparing them while someone intercepts your code, their device joins your account | — (as in Matrix) | M5 risk 17 :498 |
| R11 | Your contacts see how many devices you have, and each time you add or remove one | — (owner: line 10) | M5 risk 13 :494; OD:84 |
| R12 | The server sees a group made of your devices, and a link group and a box each time you add a device, with the times. A server that finds a link code reads that box's card, which holds the new device's name. One client can fill the cap on live boxes and stop all linking for 10 minutes [a], since the endpoint authenticates no client (G9; REDTEAM L2) | — (disclosed) | F1:817-819 |
| R13 | A device removed while it is switched off learns it only when it next runs. Until another device of yours runs, its leaves stay in your conversations, and a server that withholds can stretch this | I3 narrows it (the server's list) | M5 risk 11 :492 |
| R14 | Names you give contacts stay on the device where you gave them. Build-03's plaintext folder stays on disk until you delete it as READ-ME-FIRST says (§6) | R; P6 | X7 |
| R15 | Ten devices at most | A spec edit | X5 |
| R16 | A conversation that holds a leaf made from a key package more than 90 days old refuses every new joiner, because a joiner checks each leaf's lifetime against its clock. I1's fan-out joins (JN2) and T1's pasted joins both leave such a leaf until that device commits. The alpha is reset every slice, so no alpha conversation reaches 90 days. Filed as MG-17 (PLAN Task 8) | R: T1b's `Group.Rekey` ends every join (LRI R52) | lib `mls/group.go:3633-3647` [m]; D2 F1, IL13 |
| R17 | If another program stops URmessage from erasing your phrase's key on a device that is leaving your account, nothing of that leaving is sent from it, and it says so each time it opens. The key stays on its disk until you fix the folder's access or delete the folder | The store track (LR R36, R39) | PLAN P15; Task 2's T2-H1 |

---

## 8. What the owner tests by hand

**Setup:** two Windows computers of the owner's, PC-1 and PC-2. One computer with two installs is possible for a developer, with `URMESSAGE_APP_ROOT` and `URMESSAGE_LIVE_JWT` set apart (LiveMesh.cpp:241-270). The lead's participant plays Bob. The alpha is freshly reset. PLAN splits these steps into four sessions, one per slice. Each slice's build opens a fresh folder, so each session starts from setup, with a new "Your ID" (REDTEAM M1).

| # | The owner does | Expected |
|---|---|---|
| 1 | Installs on PC-1; "Set up this device" → "This is my first device" | 25 words, once; typing them back; a wrong word is named and nothing is corrected |
| 2 | Opens Settings → Account | "Your ID" (36 characters) with Copy; Devices lists PC-1, "this device · phrase device", with its device ID |
| 3 | Starts a conversation with Bob by today's join code | As in build 03 (until R) |
| 4 | Installs on PC-2; "Set up this device" shows a code; on PC-1: Devices → Add a device, types the code | Both show the same seven emoji, with names; "They match" on both |
| 5 | Waits a few seconds on PC-2 | The conversation with Bob appears on PC-2 with no paste. PC-2 shows the **same** "Your ID" and a **different** device ID. Earlier messages show as one "sent before this device was added" line |
| 6 | Sends from PC-2; replies from PC-1 | Bob sees one person, "· 2 devices", and the line "⟨name⟩ added a device". PC-1 has the notice "PC-2 was added … by PC-1" |
| 7 | Starts another link and taps "They don't match" | "This device was not added: no match"; nothing changes |
| 8 | On PC-1, removes PC-2 (no phrase asked: PC-1 is a phrase device) | PC-2 shows "This device is no longer on your account" and can no longer send; Bob sees "removed a device" |
| 9 | Adds PC-2 again | A new device ID (a new device); same "Your ID" |
| 10 | On PC-2 (not a phrase device), removes PC-1 | The phrase is asked: this is a lock-out. PC-1 is removed, and PC-2 shows the phrase-device mark |
| 11 | Closes and reopens each app | Identity, devices and the conversation come back; nothing shows the self group |
| 12 | Adds PC-1 again from PC-2; on PC-1, "Make this a phrase device" and types the phrase | PC-1 gets a new device ID and shows the phrase-device mark |
| 13 | "Remove this device" on PC-1, then on PC-2 | PC-1 goes at once, and PC-2's notice says PC-1 held the phrase's key and removed itself, offering a lock-out (G6). On PC-2, the last device, the dialog warns "This ends this identity"; setting up again gives a **new** "Your ID" |
| 14 | With two linked PCs and a chat with Bob: on PC-1, Settings → Account → "Change my recovery phrase"; types the old phrase, writes down the 25 new words, types them back | "Recovery phrase changed". "Your ID" and both device IDs are the same |
| 15 | Sends from PC-2; Bob replies | Bob sees one person, "· 2 devices", and no line about a change |
| 16 | On PC-2, removes PC-1 and types the old paper | Refused, named as a phrase this account no longer uses; nothing changes |
| 17 | On PC-2, "Make this a phrase device" with the new paper; closes and reopens both apps | PC-2 shows the mark; everything comes back, with the same "Your ID" |

**Not to be expected in this build:** typing the phrase on a new computer to get back in; the security delay; history on a new device; starting a chat by ID or a request; a QR code; safety numbers. Each is in §4 with its phase.

---

## 9. Build order and gates [c]

1. **lib** (one writer, as the project requires): mls (C5), then messagegroup (codecs, derivations, the chain, binding, known-answer tests), then sdk/urmessage (A to G, then K), then the C exports.
2. **srv** (one writer, in parallel once the link-box format is fixed): the link box (S1).
3. **app**, last: H1 to H7, and K's screens. Screens are checked by looking at them, except the phrase screens, which capture black (H1); those are checked through their visible state in `--diagnose`.
4. **Tests, run two-phase, every mutant killed** (M5 H.9 :420). From M5's list: a phrase device removed with no new key number; no memory of marks; a base taken from a conversation; a longer set of additions that leaves one out; a self-removal refused. New for I1:
   - a leaf the newest list does not name, accepted;
   - a sibling removed while still listed (R8-SIB);
   - a stranger in the self group;
   - a profile-1 leaf outside a link group;
   - a key package without 0xF005 taken at Add;
   - an Update that drops 0xF005;
   - an emoji code computed before both reveals, or not at epoch 1;
   - a grant taken before this device's own "They match";
   - a system group in a conversation list;
   - JN2 re-adding into a conversation you left;
   - "mine" true for a sibling's message;
   - an addition signed with this device's key that it did not make, raising no alarm;
   - an own commit that receivers refuse, published (REDTEAM H1);
   - a removed or ended phrase device that keeps the phrase's key (H2);
   - words of another identity taken by RM2, RM6 or AD5 (H3);
   - the new device revealing its nonce before it has read the other's (H4);
   - a phrase device that leaves its account though its key's erase failed, or a locked-out one that keeps its key (Task 2's T2-H1); a list signature by a device key that is also an MLS one (T2-M1);
   - for the phrase change: a step not signed by the key before it; a list under a retired key taken; the roles left with the retired key; two successors of one key in one tree; a change that removes devices; the old key kept on a phrase device; the account ID moving with the current key, or the salt re-minted; a void change sent; one predecessor per leaf, so a device that missed two changes cannot move; the alias run after R8-CUR; the alarm offering a change where one cannot help (T2-L1, T2-L2, T2-H2).
5. **Simulations:**
   - two devices of one identity with a third person;
   - a stolen linked device that tries to evict its siblings, remove a device, or move the identity to its holder's key, refused;
   - a server that forks the self group, or withholds a phrase change from one device;
   - a copied device that signs an addition, raising the alarm;
   - the holder of an old phrase after a change: refused wherever the step stands, taken where none of your devices has run since (R3).
6. **Live, by the lead before each of the owner's sessions:** §8 end to end, on the reset alpha.

---

## 10. What was checked for this file, and what was not

- **The first round** read OD, M5, DESIGN and OWN A28-A30 in full; F1 §0-§2.15, F3 §2.0-2.2, §2.10 and §2.11, T2 §2.0-2.6.1, T1:190-202 and MB:41 at the cited lines; and the lib, srv and app code at the lines §1 cites.
- **This revision read** [m]:
  - LRI, LR, PLAN, SCOPE, FOR-OWNER, REDTEAM, M5 and OD whole; F1 :1-150 and :329-837; V4 :299-360 and :982-1166; F3 :300-381 and :800-905; D2 :1-224, :318-353 and :735-822; T2 :224-240; OWN :286-293 and :426-529;
  - lib: roles.go:1-135 and :186-275; mls/group_policy.go:97-105 and :480-497; mls/group.go:780-830 and :3630-3647; sdk/urmessage/group.go at :2783, :3054, :5049, :5600, :5664 and :5800; device.go:933; erasegate_test.go:1-70; messagegroup/OPENITEMS.md's item headings;
  - srv at `37dd710f`: the diff from `20fc48db`; app at `a832482`: the diff from `badf2e2c`, and LiveMesh.cpp:2992-2998, LiveWorld.cpp:288-292 and SettingsView.cpp:221, :377, which read as §1 says.
- **Not checked, and not run:**
  - every size marked [a] or [c] (the card, the deposit, the invite with 0xF005, the chain);
  - Argon2id's time on the owner's computers;
  - whether Windows' screen-capture exclusion holds on the owner's display setup;
  - the server's behaviour under a flood of link boxes.

  Nothing was built, tested or launched.
- **The red team's fixes:** the finalizer's checks for them are listed under PLAN.md's "What was verified", and each fix's disposition is in PLAN.md's "Review dispositions".
- **Task 2's dispositions** [m]: Task 2's finalizer read REDTEAM-TASK2, PLAN, SCOPE, FOR-OWNER, REDTEAM, OD and M5 whole; LRI (R48 to R60) and LR first and last; D2 :1-30 and :100-229; V4 :299-360 and :985-1069; F1 :340-379, :530-574 and :720-749; OWN :420-534. It applied them here at A4, G1, G5, G6, K5, K9, R3, R17, §9 and the counts. Each is in PLAN.md's "Task 2 dispositions".
