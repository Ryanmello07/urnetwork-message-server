# Deleting a conversation: the design, for adversarial review

2026-10-02. Draft by the project lead. **Nothing here is built.** It is reviewed before any code is
written, because it adds content kinds and a consent rule, and this project's first protocol designs
drew critical findings on every pass.

## The ruling, verbatim

> "Yeah I think you should be able to delete your messages at any time, including deleting an entire
> DM (if both parties approve, or one party can just locally delete and leave)"

The owner gave this on 2026-10-02. It replaces the owner's same-day choice of "server time" as the
clock for MASTER §12.1's 24-hour bound, because there is now no bound at all.

## Three operations

1. **Delete one of your own messages for everyone, at any time.** No protocol change: `TOMBSTONE`
   (0x04) exists, `Group.Delete` seals it over this device's own message, and the window it never
   implemented is now ruled away. This one is spec text plus the app button (built,
   `message-windows 685b0a8`).
2. **Delete a conversation for me, and leave.** Any member of any group, DM or larger, acting alone.
3. **Delete a DM for everyone.** Exactly two member identities, and BOTH must agree.

## Constraints this must respect, from the corpus

- **T-b:** a tombstone applies only when its sender is the target's sender. Nobody can delete
  another person's message. (Spec A, `sdk/urmessage/group.go` `Group.Delete`, receive-side check.)
- **Ruling 48:** a leave request is PRODUCT SURFACE, not an MLS proposal. The MLS half of leaving is
  an admin-made Remove. **Ruling 11:** no identity's last leaf ever leaves in its own commit.
  **Ruling 48 also says:** "a durable, deliverable leave request is a new content kind at 1–2 weeks
  touching the A6 freeze". This design proposes that kind.
- **Ruling 19:** an OBSERVER may send none of the sendable kinds. `kindsAnObserverMaySend` is empty
  on purpose, so that the refusal is one sentence.
- **Spec B B6:** no client-initiated server-side erase in v1. **Spec B §7.5:** closing a group is an
  operator action in v1, and an owner-issued close record is V2.
- **The kind registry (`sdk/urmessage/kind.go`):** a new STORED kind is additive. An older build
  keeps the record's position and draws a placeholder. The next free stored codes are 0x0A, 0x0B
  and 0x0C.
- **Honesty (G4, MASTER §12.3 and §12.4):** a deletion reaches devices that are online and honest.
  Copies may exist, and the server's ciphertext stays until retention prunes it (one year by
  default for DURABLE).

## (2) Delete for me, and leave

**On the leaving device, in this order:**
1. If the group is open and this device may send, seal **`LEAVE` (0x0A, empty body)**, meaning "this
   identity has left this conversation". This is best effort. If it fails (offline, refused, or an
   observer's refusal under ruling 19), the person is told the others will not be told, and may
   continue.
2. Unsubscribe the group's push, and close the group handle.
3. **Erase the group locally:** its MLS state directory, its stream-store rows, its epoch secrets,
   and its local label (`local_names.json`). This needs a new SDK call, `Device.ForgetGroup(groupId)`.
   No such call exists today.
4. The conversation disappears from this device. A fresh invitation is the only way back in.

**On every other device, a `LEAVE` from identity X:**
- Draws a system line: "<X's label, or the placeholder> left this conversation."
- In a DM, the composer then says the other person has left, so nothing sent will be read.
- If the reader is an owner or admin, the roster already offers Remove for X's leaf. That is the
  MLS half, per ruling 48, and nothing does it automatically.
- A `LEAVE` from an identity that is not a member at the record's epoch is dropped.

**Open question (ruling 19):** should an OBSERVER be allowed to send `LEAVE`? The default here is no:
the observer leaves silently, and the app says the others will not be told. Allowing it would be the
first exception in `kindsAnObserverMaySend`, which ruling 19 calls "the shape".

## (3) Delete a DM for everyone, with both parties' consent

**Two new stored kinds:**
- **`DELETE_REQUEST` (0x0B):** body `request_id`, 16 random octets.
- **`DELETE_CONSENT` (0x0C):** body `request_id`, the 16 octets of the request it agrees to.

**The rule every receiving device applies.** A consent C from identity Y, naming request R from
identity X, **takes effect** if and only if all of these hold:
1. **Y ≠ X.**
2. **R is a request this device holds,** in this group. A consent that arrives first is held, as a
   tombstone whose target has not arrived is held.
3. **The group's member identities at C's sealing epoch are exactly {X, Y},** so the group is a DM.
   A third member admitted at any point before C voids it.
4. **R was not withdrawn before C,** in the server's record order. X withdraws R by tombstoning its
   own request record, which T-b already permits. If the tombstone's `record_id` is lower than C's,
   C is void.

**When C takes effect, every honest device of X and of Y:**
- erases EVERY record of the conversation from its local store, both parties' messages. Each party
  authorized the erase of its own lines by signing R or C.
- then performs (2)'s local erase. No `LEAVE` is sent, because both already know.

**A device provisioned later replays the log, meets R and C, and applies the same rule,** so history
sync cannot resurrect the conversation.

**The UI.** The requester presses "Delete for both of you…", confirms, and the request is sent. A
banner then reads "Waiting for <name> to agree", with Withdraw. The responder sees a banner, "<name>
asked to delete this conversation for both of you", with **Delete for both** and **Keep**. Keep
sends nothing, so the requester simply sees no answer, and the banner says so in those words.

**What the confirmation must say (honesty):** "Removed from both of your devices once each is
online. The server keeps its encrypted copy until it expires and cannot read it. Anyone who already
read a message may have kept a copy, and a modified app could ignore this."

## What this deliberately does not do

- Delete-for-everyone of a group of three or more. The ruling names DMs.
- Any server-side erase (B6), or an owner-issued close record (§7.5, V2). The group stays on the
  server. Nobody reads it, and the sweep prunes its records on their own schedule.
- Make a modified client comply. No deletion design can.

## Questions for the reviewer

1. Can any party, member or non-member, cause another party's messages to be erased without that
   party's consent? Consider replays across groups, request IDs that collide or are reused, consents
   from a removed member, and epoch races around admitting a third member.
2. Is the record-order rule for withdrawal sound under concurrent sends, re-fetch, and gaps that
   only open later?
3. Does `LEAVE` interact badly with rulings 11, 19, 42–45 or 48? Can it be used to impersonate
   someone or to confuse a roster?
4. Does a device that was offline through the whole exchange (a new device, or a restore) reach the
   same end state as every other device?
5. Is any sentence in the UI copy above false, or an overclaim?
6. What does an OLD build (today's alpha) do with each new kind, and is that safe?

---

## The adversarial review, 2026-10-02: UNSOUND as written

An independent reviewer read the design against `sdk ae13f53`, `connect 98b72dfa` and `msgrepo cd9751c`.
It ran nothing. Its verdict: **UNSOUND as written, SOUND WITH CHANGES if C1-C2 and H1-H6 are adopted.**
Its findings are recorded here, condensed, with the evidence it cited.

### Critical
- **C1. A consent is not bound to one request.** `request_id` is chosen by the requester. Nothing makes
  it unique, and nothing orders R before C. The hold machinery never discards an effect: `effectsOn`
  "only ever GROWS" (`group.go:5762`). So a void or premature consent can be cashed later by a request
  reusing its id. It also breaks rule R-c: `message_id` is THE one referent (`kind.go:108`;
  content-kinds report `:416`).
  **Change:** C's body is R's `message_id`; a void C stays void; requests lapse after seven days
  (MASTER §11 `:3072`).
- **C2. An irreversible erase is decided by an order rule the receive walk cannot evaluate.** The walk
  delivers past holes (`group.go:4033-4052`). Holes can be permanent: a record is abandoned after
  `maxRecordAttempts`. An own record with no answered submit has `record_id` 0 and sorts last
  (`group.go:5951-5956`). And `record_id` is "NEVER authenticated" (MASTER §8 `:1146`).
  **Change:** decide only on a hole-free view under R's sender; order by authenticated EPOCH, with a
  tie going to the withdrawal; a device that sealed a withdrawal never erases.

### High
- **H1.** "Members at C's epoch are exactly {X, Y}" is not computable. `RoleAt` reads one leaf;
  `leavesAtLocked` deliberately over-claims (`group.go:6619-6626`); `Members()` is current-epoch only.
  **Change:** capture the set at open, or anchor on Spec A's `IsDirect`.
- **H2.** An OWNER leaving a DM breaks MASTER §11 (`:3092`): an owner must hand the group over before
  leaving, and ruling 11 means nobody else removes an owner's leaf. The other party is then stranded:
  they can never Remove the leaver and never re-add them (R6a refuses an identity that still holds a
  leaf). **Change:** transfer ownership first; prompt the remaining party to Remove the leaver's leaf;
  a re-invite needs that Remove first.
- **H3.** Withdrawing by tombstone is not permitted. T-a refuses any target that is not TEXT or REPLY,
  on both sides (`group.go:2655`, `:5989`). **Change:** a dedicated withdraw kind.
- **H4. PRE-EXISTING, AND IT AFFECTS PER-MESSAGE DELETE TODAY.** T-b compares the leaf HANDLE
  (`group.go:5982`). A newcomer on a refilled leaf carries the previous occupant's handle (item 245),
  so it can delete-for-everyone that occupant's messages. The send-side `Mine` check stops only an
  honest client. Removing the time bound widens this. **Change:** require identity equality as well
  as handle equality.
- **H5.** The design never says whether an "identity" is a device or a person; both readings break
  something. D7 (deleting from another device of the same person) is unruled.
- **H6. The UI copy overclaimed.** Old builds, late devices and a withholding server all defeat "once
  each is online". The recovery wrap delivers each epoch's storage key to each member's recovery key
  permanently (MASTER §8.2), so either person could restore a "deleted" DM until it is pruned (that
  path is specified, not built). "Nothing sent will be read" is false while the leaver's leaf stays.

### Medium and low
- **M1.** Old builds show a sender-less gap ("A message is here that this build cannot show") rather
  than Spec C §5.1's update prompt. **M2.** Late, restored and recovered devices do not reach one end
  state. **M3.** LEAVE should mean "this device left"; the roster should say "left, not removed"; a
  crash between sealing LEAVE and erasing restores the group. **M4.** Observers: apply an observer's
  LEAVE or CONSENT, which only remove; refuse an observer's REQUEST.
- **L1.** The store half of a local erase exists (`DurableStateStore.DeleteGroupRecord`, no production
  caller); there is no SDK Unsubscribe. **L2.** Member labels are keyed across groups; say whether
  leaving erases them. **L3.** Owed spec text, including ruling 48's two unpaid amendments
  (Spec A §7.3, Spec C §12).

## What the lead decided, the same day

The parts every design needs are sound and are built first:
- **H4's identity check**;
- **per-message delete with no time limit**;
- **"delete all my messages for everyone"**, which is the per-message delete applied to every line
  of one's own;
- **"delete for me and leave"**, with H2's transfer-first rule, M3's device-level meaning, and
  L1's store half.

A pair who both do the last two have deleted the DM for both of them, with no consent artifact and so
no race. **The in-app request-and-approve protocol (DELETE_REQUEST / CONSENT / WITHDRAW) is held** until
the owner decides whether it is worth what C1, C2, H1, H5 and M2 cost.
