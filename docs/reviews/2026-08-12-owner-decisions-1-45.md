# Owner decisions — answered, pending application to the specs

Running record so nothing is lost between batches. Applied to the specs in one pass at the end,
then folded into `SPEC-LEDGER.md`.

## Batch 1

| # | Decision | Affects |
|---|---|---|
| 1 | **Seedphrase: show, require confirmation, no skip.** Re-enter randomly chosen words before reaching the app. | Spec C onboarding; already gated via `CanSend` reason `phrase_not_confirmed` |
| 2 | **Notifications: sender name only, no content preview.** Opt-in per conversation for more. | Spec C notifications |
| 3 | **Discovery: SSO directory opt-in, off by default.** Invite links always work. | MASTER §10, Spec C settings |
| 4 | **Accept `modernc.org/sqlite`** for the local store, behind the 14-method interface. Resolves A-ASSUME-1. | Spec A §8 |

## Batch 2

| # | Decision | Affects |
|---|---|---|
| 5 | **Local store: per-row encryption with a plaintext metadata index.** One `local_store_key` (32 B, random at first run), AEAD per message body; group id, timestamp and sender handle stay indexable; search decrypts a bounded window in memory. **Replaces A9's sealed-blob-per-group**, which contradicted A8's justification for taking the SQLite dependency at all. | Spec A A9, §8.3, §2474 table; Spec C |
| 6 | **PIN is optional and wraps the store key.** No PIN → DPAPI seal alone. PIN set → additional Argon2id-derived wrap, so the key cannot be unsealed without it. Auto-lock after configurable idle, **default 15 minutes**, plus manual lock. A genuine second factor, not a UI gate. Forgetting the PIN loses local history; the seedphrase still restores from the server. | Spec A §8 (new), Spec C (lock screen, settings) |
| 7 | **OVERRIDE: delivery receipts ARE in v1.** The fix passes deleted the `Delivered` state; the owner reinstated it. Needs a client-emitted ephemeral record when a device decrypts — a real signal rather than a server guess. **This is a wire-format addition and MUST land before slice 2 freezes the format.** Note the tradeoff accepted: it leaks per-device online patterns to the server that read receipts alone do not. | MASTER §2 and §8.2 event list, Spec A, Spec B, Spec C §5.3 |
| 8 | **Key transparency: confirmed as a GA gate.** Beta may ship while every key-change row and directory lookup renders `kt_unavailable` explicitly; MUST NOT be offered to any non-beta user until the log, its four client endpoints and its monitor role are live. | MASTER §15 item 6 — already ruled, now confirmed |

## Batch 3

| # | Decision | Affects |
|---|---|---|
| 9 | **URnetwork account is created in-app**, full signup flow inside URmessage. Login already lives in `URmessageSdk.dll` (decision A12), so the plumbing exists. **Watch the trap:** both the URnetwork account seedphrase and the URmessage seedphrase appear during onboarding and they are completely different secrets — the UI must not let them be confused. | Spec C onboarding, Spec A |
| 10 | **Attachments auto-download from known contacts only.** First-time senders and freshly joined groups show a placeholder until tapped. Closes unsolicited-attachment decoder exposure without making image-heavy groups feel broken. | Spec C, Spec A |
| 11 | **Owner must transfer ownership before leaving.** The leave action is blocked until a successor is nominated from current members. A group can never reach the unadministrable state. Does not replace the 30-day succession rule, which covers an owner who simply stops using the app. | MASTER §11, Spec C |
| 12 | **Disappearing timers are forward-only.** A timer change applies to messages sent after it; existing messages keep their class. Forced by the cryptography — a durable message is under the durable class key, and re-classing it would be a client-cooperation promise, not a guarantee. | MASTER §12, Spec C |

## Batch 4

| # | Decision | Affects |
|---|---|---|
| 13 | **URmessage traffic routes through the VPN tunnel when it is up.** Confirmed, and must not be "fixed" by excluding `URmessage.exe`. Consequence accepted: the health state machine must tolerate the VPN's control-plane starvation window while the tunnel is `Connecting` (Spec C §9.4 handles this by not calling a slow server a dead one). | Spec C §9.4 |
| 14 | **Key-change warnings block in DMs, warn in groups.** Confirmed. Plus the blocking condition on adding a changed-key member, which is where the real decision sits. Rationale: a blocking prompt in a 40-member group fires for people you cannot verify, training users to dismiss the warning that matters. | Spec C §7.1 |
| 15 | **Invite links: both kinds, one-time by default.** Explicit option for a reusable published group address. Revoking a published address never disturbs existing members. | Spec A §8.3, Spec C |
| 16 | **Messages display in server order, with the sender's timestamp shown as the label.** Order is what every client agrees on and no client can manipulate; `stream_index` is already gapless and server-assigned. `sent_at` is sender-claimed and must never determine order. | Spec A, Spec C |

## Batch 5

| # | Decision | Affects |
|---|---|---|
| 17 | **Per-epoch `read_key` with a 90-day server-side acceptance window.** Replaces the lifetime read key. An offline member can still catch up; a removed member's metadata access expires. Today a removed member keeps a live feed of record ids, sizes, timings and sender handles indefinitely. | Spec A, Spec B §5.3, MASTER |
| 18 | **Server key custody: all three fixes.** (a) Hardcode a fleet root public key in the client and verify the first fetch against it — nearly free now, impossible to retrofit onto shipped installs, and it closes the only unauthenticated moment in the design. (b) Resolve the Spec B / Spec C conflict toward **signed-silent rotation** with an inspectable security log; Spec C's app-wide blocking modal is deleted. (c) Signing key moves to an HSM or signing sidecar rather than sitting on every replica. | Spec B §4.3.1, Spec C §7.6 |
| 19 | **Register a second ciphersuite now; defer ReInit.** Proves the registry is not a hardcoded singleton, which is the part that breaks later. Directly relevant given the post-quantum MLS ciphersuites are still a draft. | Spec A profile |
| 20 | **TOPOLOGY CORRECTION — operators are plural and separate from message servers.** Two operator servers exist today. A message server chooses which compatible operator it uses, by user decision, and holds an account on it to forward traffic. **The specs currently assume ONE operator throughout and must be corrected.** v1 remains one *message* server, but nothing may hardcode a single operator. | MASTER §2/§4, Spec B, Spec A |

## Batch 6

| # | Decision | Affects |
|---|---|---|
| 21 | **Durability: nightly encrypted backups, a stated RPO, a named hosting jurisdiction** — required before any user beyond the two beta testers. Write down the honest consequence: **a backup is a copy that outlives a delete**, so this qualifies the deletion story rather than sitting beside it. | MASTER §13, Spec B ops |
| 22 | **Text retention defaults to 1 year, not forever.** No group override unless the message server permits one. **The server advertises three limits** — text storage cap, media/file deletion timeframe cap, and file size limit — and groups operate within them. Generalises the previous single-cap model. | MASTER §12.2, Spec B §7, Spec C |
| 23 | **Messaging identity and the paying URnetwork account stay cryptographically unlinked.** Only an explicit user opt-in to SSO creates a join. This is what makes "the operator cannot read your messages" structural rather than a policy statement — without the join a compromised operator holds a payment record and a traffic pattern, not a social graph. Accepted cost: no cross-boundary abuse tooling, and support cannot answer "which account is this". | MASTER §4.2, §10 |
| 24 | **Abuse: ship mute and leave; defer block and report.** Discovery being opt-in removes most exposure. Block stays cut (no SDK surface, and its device-sync carrier is unscoped); report needs a moderation process deliberately deferred. | Spec C, Spec A |

## Batch 7

| # | Decision | Affects |
|---|---|---|
| 25 | **External cryptographic audit: decision deferred to slice 5**, when there is working code to scope a quote against. **Risk accepted and worth restating:** audit firms book months out, so if the answer later is yes, the lead time lands on the critical path to GA rather than running alongside the build. | MASTER §14, ledger C7 |
| 26 | **Beta ships unsigned; code-signing decided before GA.** Accepted cost: SmartScreen warnings for early users, CI signing integration discovered late, and reputation starting from zero on release day. | Spec C §2 |
| 27 | **Accept that the server holds `write_key` and can forge `write_auth`.** It must hold it to verify. A forged record fails MLS verification at every client, so this is a denial-of-service and noise vector, not an authenticity break — invariant I5 is exactly what makes that true. **Must be stated in honest-limits** so nobody discovers it and assumes it is worse than it is. | MASTER §9.2, §13 |
| 28 | **Seed entropy stays sealed for the life of the install**, so `RevealSeedphrase()` can show the words again. Users lose the paper, and re-display is the difference between recovery and permanent loss. Sealed under DPAPI, and under the PIN wrap once one is set. Accepted cost: a compromised device with an unlocked session yields the phrase, and therefore all history in every group, forever. | Spec A §8, Spec C §6.5 |

## Batch 8

| # | Decision | Affects |
|---|---|---|
| 29 | **Internal-only build at A8; public beta at A9; multi-device reordered ahead of attachments.** Multi-device is the differentiator against Signal Desktop; attachments are table stakes. Text-only, single-device, no notifications is a demo, and calling it "beta" externally sets expectations that are hard to walk back. | MASTER §14 slice order |
| 30 | **Beta ships without push; working contentless WNS wake is a GA gate**, alongside key transparency. Spec C's copy stands: "URmessage can only notify you while it's running." Note Q38 is unresolved — the Azure AD application registration WNS needs has no owner. | Spec C, Spec A slice A11 |
| 31 | **Billing: operator servers exclusively set data pricing.** Messaging consumes the user's own URnetwork allowance — currently **40 GB/day free**, ample for messaging — rather than being operator-funded. Beta message servers get free data credit. **Out of credit → warn the user in-app** and direct them to the URnetwork website/app/VPN to buy more. | MASTER §4, Spec A, Spec C |
| 32 | **NEW v1 FEATURE — balance code redemption in URmessage.** Beta testers receive "balance codes" granting credit, redeemable through the existing API. Needs an SDK call and a redeem screen in the Windows client. Not currently in any spec. | Spec A (new API), Spec C (new screen) |
| 33 | **Multi-device is desktop-to-desktop for v1, and the pairing UX must improve.** Replace the 32-character typed code with a QR the second machine reads, or a short code plus numeric comparison — Spec C's onboarding section already describes the better pattern. Accepted: this is not the phone-plus-desktop pairing users mean by "multi-device". | Spec C §12, Spec A provisioning |

## Batch 9

| # | Decision | Affects |
|---|---|---|
| 34 | **Invite links carry an invitation a member already made.** Not a public door. A reusable published address means "requests land here for a member to approve", not "anyone with this joins". Works with the existing `Add` + `Welcome` model, needs no external commits, and keeps invite-only as a real anti-abuse property. **Reconciles decision 15 with the parse-refusal of external commits.** Spec C's `urmessage://` copy must describe this flow or be deleted — today it promises something that does not exist. | Spec A §8.3, Spec C |
| 35 | **DM policy is jointly controlled: either party may shorten retention or the disappearing timer, neither may lengthen unilaterally, and every change is announced in-thread.** Preserves "a DM is just a 2-member group" (no second code path) while removing the surprise that whoever opened the chat silently controls whether the other person's messages persist. | MASTER §11, Spec C |
| 36 | **Hard caps: 500 members, 10 devices per identity.** Both enforced, both stated in the UI. **Very large groups get a separate "Community Server" system** — a distinct flow needing its own design time, well beyond V2. Nothing in the v1 wire format should foreclose it. | MASTER §6, Spec A, Spec C |
| 37 | **`PastEpochWindow` raised from 8 to 32**, and gaps explained plainly in the UI. Eight epochs can elapse in a single day of churn in an active group, so a laptop closed over a weekend returned to permanent unfillable holes. That is a product promise about how long you may close your laptop, and it had been set by a memory-budget number nobody chose. Accepted cost: more stored state per group, and a slightly weaker deletion guarantee. | Spec A key schedule, Spec C |

## Batch 10

| # | Decision | Affects |
|---|---|---|
| 38 | **Delete-for-everyone ships, bounded to 24 hours, leaving a visible "message deleted" placeholder.** Matches Signal's window. Unbounded silent retraction would let someone rewrite a years-old shared conversation undetectably. The copy still admits it cannot claw back what was already read. | MASTER §12, Spec A, Spec C |
| 39 | **Disappearing-message placeholder rows keep `record_id` but `sender_handle` is ZEROED.** The gapless-id argument justifies keeping a row, not keeping the sender in it — otherwise "disappearing messages" leaves a permanent per-sender timestamped metadata trail. **Required copy: "the content disappears, the fact of the message does not."** | Spec B §7.2, MASTER §12, Spec C |
| 40 | **PITR window cut from 7 days to 48 hours; group reclaim grace stays 30 days.** The backup window is the real upper bound on how long after deletion the operator can still produce your ciphertext — a transparency-report number, not a database parameter. | Spec B ops, MASTER §12 |
| 41 | **Logging: aggregate-only metrics, stated explicitly, never per-identity, plus opt-in client-triggered diagnostics.** Replaces the absolute prohibition, which was aspirational — an on-call engineer meets it at 3 a.m. and quietly adds logging anyway. An explicit aggregate-only rule is enforceable, and therefore the stronger privacy position in practice. | Spec B §11.2, §13 |

## Batch 11

| # | Decision | Affects |
|---|---|---|
| 42 | **Owner succession ships in v1, with a raised bar.** Resolves a direct MASTER/Spec A contradiction — MASTER specifies `OWNER_SUCCESSOR_SET`, Spec A parse-refuses extension `0xF003`. Spec A must accept it. New threshold: **supermajority (or unanimity) of admins, a 90-day floor, escalating in-app warnings to the owner on every device, and an owner opt-out** for groups where succession is disabled. A 30-day majority timer was a governance coup mechanism; 90 days with warnings rescues dead owners while making displacement of a live one effectively impossible. Note: because v1 clients parse-refuse the extension today, shipping later would require updating the whole fleet first. | MASTER §11, Spec A profile |
| 43 | **Admins may remove members only. Only the OWNER may remove an ADMIN.** As written, one compromised admin could strip the entire admin set including the owner in a single commit with no undo — the removed owner's keys are gone from the very next epoch, so it is unrecoverable by construction. Two-line rule now, unfixable incident later. | MASTER §11, Spec A |
| 44 | **Fork detection: auto-resync first, surface the hard stop only if resync fails.** Keeps the security property — a genuine fork still stops sending — while removing a self-inflicted outage. A server fault produces the same signal as an attack, so as specified the blast radius of one bad deploy is "nobody in this group can send until every member individually clicks a button." | Spec C §9, Spec A |
| 45 | **No in-VPN promotion of URmessage in v1.** No "Get URmessage" row in the shipping VPN client. Keeps the release trains and support surfaces separate, and avoids pointing an entire VPN install base at one message server. Distribution is via its own download page. | Spec C §2, VPN client repo |

## Application notes

- Decision 5 supersedes Spec A decision A9 outright. The §2463 data table row "Decrypted display
  cache … sealed, one blob per group" changes to per-row AEAD.
- Decision 7 is the only wire-format change in this set. Sequence it into slice 1/2, not later.
- Decisions 1, 2, 3, 6 are Spec C surface; 4, 5, 6 are Spec A; 7 touches all four.
