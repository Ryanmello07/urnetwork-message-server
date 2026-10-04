# Owner decisions 46–49, plus the three blockers from the first application pass

Applied on top of decisions 1–45 (`docs/reviews/2026-08-12-owner-decisions-1-45.md`, all landed).

---

## Blockers from the first pass — fix these first

### BL-1 — Decision 20 (plural operators) never reached Spec A

The owner's headline topology correction names Spec A as affected, and Spec A received **no operator
change at all**: `operator_host` appears nowhere, `MessageServerInfo` carries no operator field, and
the A-4 edit-log entry does not mention operators.

**Fix:** apply decision 20 to Spec A throughout. Operators are plural (two exist today) and separate
from message servers. A message server chooses a compatible operator and holds an account on it for
transport. `MessageServerInfo` must expose which operator a server uses;
`MessageClientSettings` must not assume one. v1 remains **one message server**, but nothing may
hardcode a single operator.

### BL-2 — Spec C hardcodes a single network space host

Spec C §1.1 states: "`network_space_host` and `message_server_id` are build-time constants in
`Common/ServerConfig.h` (`kNetworkSpaceHost`, `kMessageServerClientId`)." The network space host *is*
the operator, so this is the one-operator assumption surviving as a normative build instruction.

**Fix:** the operator must be configurable at runtime, not compiled in. A build-time default is fine;
a build-time **constant** is not.

### BL-3 — Directory resolution fails closed, contradicting decision 8

Spec A line 2545: "Resolution WITHOUT an inclusion proof fails closed: a result with `ProofState`
other than `included` MUST NOT…". Decision 8 explicitly permitted beta to ship "while every
key-change row **and every directory lookup** renders `kt_unavailable`". Key changes got that
treatment (`kt_unavailable` is the documented pre-slice-9 default); directory lookups did not.

**Fix:** directory resolution renders `kt_unavailable` and proceeds in beta, exactly as key changes
do. It fails closed only once the KT log is live — which is the general-availability gate, not the
beta gate. This is a misapplication of an existing ruling, not a new decision.

---

## Batch 12 — new decisions

| # | Decision | Affects |
|---|---|---|
| 46 | **Out-of-band contact exchange ships in v1.** A shareable contact card — QR code, or a copyable `urmessage://` link carrying the principal and identity key — that starts a DM with **no directory involved**. This is what makes the product bootstrappable: discovery is opt-in and off by default, and invite links need someone already in a group, so without this two people who have never met cannot start a conversation at all. Works when the directory is down, before KT is live, and for people who never want to be listed. **Accepted cost:** the link is a capability — anyone who obtains it can message you until you rotate it, so rotation must exist. | Spec A (new calls), Spec C (new screen), MASTER §10 |
| 47 | **Per-user install only for v1; no per-machine variant.** Accepted cost: no Intune, SCCM or GPO deployment, so no organisation can roll URmessage out centrally. The no-elevation property is load-bearing — it removed the privileged service, the WFP filters and the whole class of machinery behind most of the VPN client's hard bugs — and a per-machine installer would put a UAC prompt back in the update path. | Spec C §2 |
| 48 | **Read receipts and typing indicators are reciprocal.** Turning yours off also hides everyone else's from you. Matches Signal, WhatsApp and iMessage. Without reciprocity the setting becomes a one-way observation tool where the most privacy-conscious user gains the most information. | Spec C §5, Spec A |
| 49 | **Full emoji picker for reactions — NOT the eight fixed emoji.** Owner overrode the recommendation. **Consequences to state explicitly in the spec rather than discover later:** arbitrary Unicode on the wire brings font-coverage gaps, ZWJ sequence handling, and normalisation questions; and a reaction becomes user-authored *content*, which makes it a moderation surface — one the project has deliberately deferred. Skin-tone stripping should still be considered, since a reaction can otherwise carry an unintended signal about the reactor. | MASTER §8.2, Spec A, Spec B, Spec C |

## Application notes

- BL-1 and BL-2 are the same decision (20) reaching two documents it missed. Do them together.
- BL-3 is a correction to an existing ruling, not a new one — do not present it as a change of policy.
- Decision 46 needs new sections in Spec A and Spec C, plus a rotation mechanism for the contact link.
- Decision 49 is a wire-format widening: the reaction field must carry arbitrary emoji rather than an
  enum. Like delivery receipts, it must land **before slice 2 freezes the format**.
