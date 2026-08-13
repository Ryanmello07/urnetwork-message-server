# URmessage — Spec C: Windows Client UI

**Date:** 2026-08-12
**Revision:** 6 — the contact card gets the transport it was specified without: screen 32 renders `ContactCard().State` and refuses to hand out a card that cannot receive (§3, §12.7); a card request lands in a **waiting** state, because the conversation does not exist until the other side accepts (§3, §12.7, §16.2, §16.5.1); rotation says what it discards before it discards it (§12.7); the fallback to manual review under a firehose is written in the words v1 can honour (§12.7); §14.2 gains the contact-card and contact-request rows and moves the three operator values from screen 22 to screen 20; §14.3 records what C assumes of B's rendezvous; gate 8 splits into declaring and citing rows (§16.1); lint 6 drops a literal whose source does not exist and gains three whose sources do (§16.3)
**Status:** Design
**Scope:** the Windows messaging client — app shape, screens, copy, states, brand, accessibility
**Depends on:** [URmessage Protocol Design rev 9](../../../claude_sandbox_message/msgrepo/docs/specs/2026-08-12-urmessage-protocol-design.md) (the master spec, cited below as **§n**), [SPEC-LEDGER.md](../../../claude_sandbox_message/msgrepo/SPEC-LEDGER.md), Spec A (SDK / protocol client core), Spec B (message server)

---

## 0. Planning ledger

### 0.1 Current state

| Item | State |
|---|---|
| Master protocol design | Revision 9, contact rendezvous applied |
| Spec A — SDK / client core | Being written in parallel |
| Spec B — message server | Being written in parallel |
| This spec | Revision 6, contact rendezvous applied |
| `Ryanmello07/urnetwork-message-windows` | Not created |
| Code | None |

The VPN client (`Ryanmello07/urnetwork-windows`, branch `beta/custom-server`) is a shipping, live-tested WinUI 3 / C++/WinRT application with a proven brand kit, localization pipeline, native shell, installer, updater and release train. **This spec reuses that codebase's patterns and assets and shares none of its process model.** Every reuse below names the file it comes from so the team can read the working precedent rather than re-derive it.

### 0.2 Decisions specific to this component

| # | Decision | Why |
|---|---|---|
| **W1** | Separate executable `URmessage.exe`, not a page inside `URnetwork.exe` | The VPN app is a tray flyout sized 480×760 (`WindowShell.h`) whose one screen is a connect button. A messenger is a workspace app with a three-pane layout and a 20k-message virtualized list. Merging them makes `MainWindow.xaml.cpp` — already 2128 lines and already the collision point for parallel UI work — the collision point for two products. Separate binaries also mean a messaging defect can never take down a VPN tunnel. |
| **W2** | **User-mode only. No service, no driver, no elevation, ever.** | URmessage forwards message traffic through the SDK's own transport. It never captures packets, never rewrites routes, never touches DNS. Every mechanism the VPN client needs to do those things is a mechanism URmessage does not have and must not acquire. §0.3 states exactly what that removes. |
| **W3** | All plaintext, all key material, and the entire local message store live **in Go, inside `URmessageSdk.dll`** (Spec A). The C++ layer is a view. | One place holds plaintext, so one place is audited, one place seals to DPAPI, and one store serves the mobile clients that follow. The C++ side holds only what is currently on screen and never writes message content to disk. |
| **W4** | **Per-user install.** URmessage ships as its **own** `InstallScope="perUser"` MSI, `URmessage-<version>-<arch>.msi`, installed to `%LOCALAPPDATA%\Programs\URmessage\` with a per-user Start Menu shortcut (§2.1). It ships its **own** copy of the self-contained Windows App Runtime and its **own** copy of the four licensed brand faces. | A separate per-user package cannot reference the VPN package's per-machine `RuntimeFiles` components, so the shared payload of the original W4 is not available. The cost is roughly 60 MB of installed size. It is paid deliberately, to buy three things: an in-app rename-swap updater that works as a standard user (a `%ProgramFiles%` install cannot rename its own binaries without the LocalSystem service W2 removes); a truthful "URmessage installs and runs per-user" claim in §0.3; and **zero elevation anywhere in the product**: a per-user MSI needs none to install, and a `%LOCALAPPDATA%` install needs none to rename-swap itself on update. The accepted cost is that there is no per-machine variant and therefore no central deployment, which §2.1 states rather than leaves to be discovered by the first administrator who tries. |
| **W5** | The client's connection state is a **pure state machine in `Common/MessageHealth.h`** with a selftest-pinned transition table, in the exact shape of the VPN client's `Common/ConnectionHealth.h` (windows `1cfcf3c`). | That pattern was written because ad-hoc status text lied to users for weeks. The same class of lie is worse in a messenger, where "sent" is a claim about someone else's device. The state machine consumes `SyncState` (Spec A §7.2) and nothing else, so its transition table is testable against a fake `SyncState` rather than against the network. |
| **W6** | Seedphrase display uses `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`, clipboard writes use `Clipboard.SetContentWithOptions` with history and roaming disabled, and confirmation is a **typed** quiz over four random positions. | §6. This is the screen where the product can permanently destroy a user's data, and the failure mode is silent for months. |
| **W7** | The key-change warning is a **blocking modal that stops outbound sending** until resolved, plus a permanent, non-dismissible inline record in every shared conversation. **The blocking scope is a DM, not a group** — see §7.1 and MASTER §10.2. In a group, the blocking event is the `Add` of a member whose identity key differs from a pin the user holds. | §10.2 and §5.5 of the master spec require it. The exact copy is fixed in §7 of this document. |
| **W8** | Verified contacts get **no badge, no colour, no checkmark**. `kProGold` in particular is never reused — `UrColors.h` reserves it for the Pro entitlement across the whole product. | §10.2: "There is no verified badge." A badge implies the absence of one means something, and it does not. |
| **W9** | Contact and group avatars are **deterministic identicons derived from the pinned identity key** (contacts) or `group_id` (groups). No avatar upload in v1. | No media path, no storage, no moderation surface — and a contact's avatar visibly changes when their key changes, which is SSH randomart applied to the one event we most want a user to notice. |
| **W10** | The client's own log has a **field allowlist**. Message content, contact display names, group names and attachment filenames are never logged, at any verbosity, in any build. | The VPN client's `Log.cpp` writes one unbuffered `WriteFile` per line and its logs are routinely collected from testers and pasted into issues. A messenger log collected the same way must be safe to paste. |
| **W11** | **An optional PIN, and no app lock beyond it.** When set, the PIN wraps the local store key in the SDK (Spec A §8.6) — it is not a screen in front of unlocked data. Auto-lock defaults to **15 minutes** of inactivity; manual lock is always available. When unset, there is no lock screen and the app says what protects the store instead. | A lock screen that guards data the process has already decrypted teaches a user a protection they do not have. This one is real: without the PIN the store key cannot be unwrapped by this process or any other. The cost — forgetting the PIN loses local history, and the seedphrase is the way back — is stated on the screen that sets it, not discovered later. |
| **W12** | **The message server's key is verified against a fleet root compiled into `URmessageSdk.dll`. There is no accept-this-key modal, in either direction.** A key that chains is applied silently and appears in a Security log; a key that does not chain refuses the connection and offers no way to proceed. | The old app-wide blocking modal presented every user with a decision they had no way to make, at the exact moment its answer mattered most, and the correct answer was never "accept". With a root pin the correct answer is enforced instead of asked for. Spec A §7.6 deletes `AcceptServerKey`; §7.6 of this document deletes the modal that called it. |
| **W13** | **The beta ships unsigned. Code signing is decided before general availability.** | Accepted with its costs named rather than discovered: SmartScreen warns early users, CI signing integration is found late, and reputation starts from zero on the day the certificate first ships. §2.7 states what testers are told. |
| **W14** | **No promotion of URmessage from inside the VPN client in v1.** No "Get URmessage" row, no banner, no mention. | Distribution is its own download page. Keeping the release trains and the support surfaces separate is worth more than the install funnel, and pointing an entire VPN install base at a single message server is a capacity decision nobody has made. |

### 0.3 What "no privileged service" removes, concretely

Every row is a mechanism the VPN client has and URmessage does not.

| VPN client mechanism | Present in URmessage | What its absence removes |
|---|---|---|
| `urnetworkd.exe` running as LocalSystem | **No** | No SCM registration, no service restart budget, no Event 7031/7034 terminations, no `ServiceSetup` five-state classifier, no Connect banner driving an elevated install |
| UAC elevation, `urnetworkd install` verb | **No** | No admin prompt anywhere in the product, installer included. URmessage ships as its own per-user MSI (§2.1), installs to `%LOCALAPPDATA%\Programs\URmessage\`, and updates itself by rename-swap on files the running user owns |
| wintun adapter | **No** | No adapter lifecycle, no PnP surprise-removal path, no `WintunDeleteDriver` hazard (which detaches every wintun adapter machine-wide) |
| WFP filters / kill switch | **No** | No firewall state to arm, narrow or disarm; no "my internet is blocked" failure mode; no `RECOVERY.md`, no `revert` verb, no CrashRevert |
| `SplitTunnel.sys` clean-room driver | **No** | No WDK, no driver signing, no `INSTALLDRIVER` feature |
| mTLS loopback RPC (`DeviceLocal.SetRpcServer` / `DeviceRemote`) | **No** | No `rpc_session.json`, no instance-id pairing, and therefore **none of defect #40's reattach class** — there is no second process to reattach to |
| Named pipe lifecycle channel | **No** | No `PipeServer`, no `nlohmann::dump()` UTF-8 throw path |
| Two-phase teardown, budgeted abandonment worker | **No** | Nothing to revert. Closing the app is `ExitProcess` after the store flushes |
| Packet pump, egress monitor, route/DNS config | **No** | No dead-tunnel watchdog, no Modern Standby clock rebase, no carrying-veto evaluator |
| Machine state modified at all | **No** | The worst outcome of a URmessage crash is a closed window |

**What remains from the VPN client's runtime:** an in-process URnetwork `Api` (login, profile, account — Reachability class **A** in the VPN client's terms) and an in-process connect client for addressed transport — **both provided by `URmessageSdk.dll`, not by `URnetworkSdk.dll`, which is never loaded into this process** (Spec A decision A12). Both are class A: no service, no RPC, no elevation. This is the class of work the VPN project proved is fully parallelizable.

**One interaction to be aware of.** If the VPN tunnel is up, URmessage's traffic goes through it — `URmessage.exe` is a separate process and the tunnel's R1 self-exclusion covers only the service's own sockets. **That is the intended behaviour and it is not to be "fixed".** URmessage's traffic goes through the tunnel when the tunnel is up. Excluding `URmessage.exe` from it is prohibited: a VPN user would reasonably object to their messenger being the one application routed in the clear, and an exclusion list that grows one convenient entry at a time is how that happens. The accepted consequence is that URmessage's health state machine must tolerate the VPN's known control-plane starvation window while the tunnel is `Connecting` (windows spec `2026-08-11-connect-flow-reliability-design.md`), which §9.4 handles by not calling a slow server a dead one — and that is a requirement on §9.4, not licence to revisit this.

### 0.4 Interfaces to the other two components

Detailed in §14. Summary:

| Direction | Contract |
|---|---|
| **C → A** | Everything. The client's only dependency is `URmessageSdk.dll`. It calls the C ABI through a generated C++ wrapper (`urmessage_sdk.hpp`) in the `urmsg::` namespace, and receives events through subscription handles on Go threads which it marshals to the UI with `DispatcherQueue.TryEnqueue`. |
| **C → B** | **None directly.** The client never opens a socket to the message server. Everything about B reaches the UI as state or an event through A. What C *assumes* of B — retention semantics, the advertised attachment cap, single-commit retry, fetch attestation, prune-vs-failure distinguishability — is enumerated in §14.3 as requirements on B surfaced through A. |
| **A → C** | A must expose every state C renders as an explicit, enumerable value. C must never infer a state from the absence of data — the VPN client's `Disconnected`-looking-`Connected` bug (#40) came from exactly that inference. |

**Assumption to confirm:** this document reads "Spec A" as the SDK / `connect` protocol client core and "Spec B" as the message server. If the letters map the other way, §14's two halves swap and nothing else changes.

### 0.5 Open items

| # | Item | Resolution |
|---|---|---|
| C-1 | Seedphrase confirmation gates first send | **Gate.** Backed by A's `PhraseConfirmedAtMs()` in the sealed keyfile, surfaced as `CanSend` reason `phrase_not_confirmed` — not by a flag in `prefs.json`, which W3 forbids and which a user trying to skip the gate could edit. |
| C-2 | Notification content | **Sender name only, no content preview, everywhere by default.** A conversation may be opted **up** to include the message, one conversation at a time (§10.3). Plus §10.3's lock-session rule. |
| C-3 | Local search in v1 | **Yes**, local-only, A-backed via `Search(groupId, query, limit)`. The conversation-list filter (screen 9) is a **local filter over already-loaded rows** and does not touch the index. `Ctrl+F` is the group-scoped form. The index **excludes `EPH` records entirely** (§5.7). |
| C-4 | Windows Hello gate | **Six** actions (§6.6): show the phrase, accept a changed **contact** key, remove a device, leave a group or transfer ownership of one you own, remove this identity from this computer, and **change or clear the PIN**. Accepting a changed **server** key is no longer one of them, because there is no such action (§7.6). App lock **ships** as the optional PIN of §6.9. |
| C-5 | Retention floor conflict | **Warn and proceed, both directions** — RULED in MASTER §15 item 1. §8.4's copy covers both. The `retention_refused` send-failure reason is **deleted**. |
| C-6 | Push transport | **Beta ships without it**; a working contentless WNS wake is a general-availability gate alongside key transparency (MASTER §15 item 2). §10.2's copy stands: "URmessage can only notify you while it's running." **The Azure AD application registration still has no named owner**, and that remains the long pole. |
| C-7 | Disabling read receipts hides others' | **Yes**, resolved against the **user-scoped** preference (`SetUserPreference("read_receipts", …)`), and **reciprocally**: with yours off, nobody else's reach you. The same holds for typing indicators. Delivery receipts are not covered by this rule and remain independently disableable. |
| C-8 | EPH bucket numbering | **Closed by citing Spec A §7.3.** The wire EPH class number and `MessageGroupPolicy.DisappearingBucket` are different namespaces; policy `0` means disappearing off, never bucket 0. |
| C-9 | "Delete for me" copy | §8.2's string, signed off. |
| **C-10** | Contact blocking and reporting | **Neither in v1.** What ships is **mute and leave**, which covers most of the exposure because directory listing is opt-in (§12) and unsolicited contact mostly never starts. Blocking has no SDK surface and its cross-device carrier is unscoped; reporting without a moderation process behind it is a form that goes nowhere. Both are recorded in §15 against MASTER §15 item 4. |
| **C-11** *(new)* | Sign out semantics | **Split into two actions.** See §12. |
| **C-12** | Two Go runtimes (Spec A decision A12) | **Resolved: one runtime.** `URmessage.exe` loads `URmessageSdk.dll` only; login moves into it (Spec A §0.2 decision A12 and §9.1). §16.1 gate 6 checks the import table. |

### 0.6 Edit log

Append-only. Newest last. One entry per commit that changes this spec. Every change follows SPEC-LEDGER §6: edit, subagent reviews the **diff**, fix findings, commit with the ledger entry, append here.

| Rev | Change |
|---|---|
| 2 | **R4 review findings applied** (`docs/reviews/2026-08-12-r4-findings-full.json`, 148 findings). Revision 1 was **double-encoded UTF-8** — 305 mojibake runs, including all 131 `§` and every em dash — so the file was repaired first (decode each run via cp1252→UTF-8, BOM stripped, LF endings), and §8.1's three normative strings were then re-verified against MASTER §12.4 by codepoint. Substantive changes: per-user install with its own runtime and brand faces (W4, §2); one Go runtime, login inside `URmessageSdk.dll` (§0.3, §1.1, §14); the `Delivered` state **deleted** (§5.3); key-change blocking narrowed to DMs with a new blocking `Add` condition (§7.1); evidence classes replaced with Spec A's lowercase closed set and `self_signed_rotation` removed as a false security claim (§7.3); retention negotiation warn-and-proceed in both directions and `retention_refused` deleted (§8.4, §9.3); an eighth health state `StoreUnavailable` with its own full-screen stop and a `SyncState`-derived transition table (§9.2); seedphrase re-display backed by Spec A's sealed entropy (§6.5); four new screens, the §5.7 ephemeral-containment rule, §12.3 device removal, §14.4's mirror of Spec A's client obligations C1–C15, and three new DLL-boundary traps (§14.1). |
| 3 | **R5 convergence pass.** URmessage ships as its own `InstallScope="perUser"` MSI rather than a feature of the VPN package, which makes W4's "zero elevation anywhere" literally true and gives a second Windows account on a shared machine a working app (§2, §0.2 W4, §0.3, §16.1 gate 7, §16.5 criterion 10). Contact blocking is **cut from v1** — Spec A defines no call for it and MASTER §2 does not ship it — and the gap is recorded honestly in §15 against MASTER §15 item 5; screen 25 was removed and "Store unavailable" renumbered 26 → 25 (§0.5 C-10, §3, §9.1, §9.2, §9.3, §12, §14.2, §16.2). The typing indicator, which MASTER §2 ships and §16.5 tests, now has pixels, wording, a clearing rule and an accessibility rule (§5.8, §13.1, §16.2). §14.2 was regenerated symbol-for-symbol against the finished Spec A §7 and finally carries the per-datum → screen → field table it declared a build gate, with §16.1 gate 8 enforcing it. The v1 reaction set is closed at eight emoji, by codepoint, with a normalisation rule (§5.2a). The history-grant banner names its source call and event (§5.5). The retention notice is formatted from Spec A's `MessageRetentionApplied`, whose values are **seconds**, with `0` rendered as indefinite (§8.4, §14.3). Mute and per-conversation notification mode name their carriers (§10.3, §12). Lint 7 is expressed by codepoint so it no longer fails on its own text (§16.3). Ledger and MASTER invariant numbering are separated: an `I`, `P` or `T` citation in this document is the ledger's unless it says MASTER (§17, and the citations in §5.1, §8.3, §9.4, §12.1, §12.2, §14.1). |
| 4 | **Owner rulings applied.** Four new component decisions: the optional PIN (W11), fleet-root server-key verification with no accept modal (W12), an unsigned beta (W13), and no in-VPN promotion (W14). **Deleted:** §2.6's "Get URmessage" acquisition row and its state table, §7.6's server-key modal and its Hello gate, the "no delivered state" block in §5.3, §10.3's "Name and message" global position, and §15's app-lock and per-member-delivery rows. **Added:** §2.7 (unsigned beta), §6.9 (the PIN, auto-lock and screen 26), §9.8 (away longer than the 90-day read-authorization window), §9.9 (out of credit), §12.4 (redeeming a balance code), §12.5 (the 500-member and 10-device caps), §12.6 (the Security log), §12.3's short-code-plus-six-digit pairing, and screens 26–31. **Changed:** delivery receipts return as `MessageEntry.State == "delivered"` with `DeliveredTo` and their own glyph (§5.3, §10.1, §12); server order with the sender's timestamp as the label, and eight new system records (§5.1); attachments auto-download from known senders only (§5.4); seedphrase confirmation has no skip, and the two phrases are separated by three normative rules (§6.1, §6.3); the account is created in-app (screens 2 and 2a); delete-for-everyone is bounded to 24 hours with a permanent placeholder (§5.2a, §8.2); disappearing timers are forward-only and expired rows carry no sender (§8.3); retention gains a one-year text default and three advertised limits (§8.4, §12); two new health states, `Locked` and `OutOfCredit` (§9.2); fork detection resyncs before it stops (§9.5, §9.3's `fork_unresolved`); notifications are name-only with a per-conversation opt **up** (§10.3); directory listing is off by default and is the only link between the two identities (§12); the operator this server forwards through is shown alongside it (§12.2); two new verbatim strings (§8.1); §14.2, §14.3 and §14.4 regenerated against the new surface; three build gates, ten selftests, an eleventh acceptance criterion, and six more forbidden literals (§16). |
| 5 | **Operators are plural, and the rest of the owner's rulings applied.** The network space host is an **operator**, so it is per-user configuration with a build-time default and a runtime setter rather than a compiled-in constant; §1.1 states the operator model, §12.2 shows three read-only rows (server, your operator, the server's operator) where it showed two, §12's Advanced entry and §15's row follow, and §16.1 gate 12 fails a build that compiles a host in as its only source. **The contact card ships**: §12.7 and screen 32, reached from Settings → Account and screen 13, with rotation, safety digits, the receiving flow, and card requests in screen 23 — which is what makes the product usable while directory listing is off and before the transparency log exists. **Directory lookups no longer fail closed**: §7.3 distinguishes a proof that did not verify (refused) from no reachable log (proceeds, with `kt_unavailable` rendered), adds the `out_of_band` evidence row for a key that came from a person, and screen 13 gains the matching states. **Per-user install is stated with its cost** — no Intune, SCCM or GPO deployment (§2.1, W4, §15). **Read receipts and typing indicators are reciprocal** (§5.3, §12, C-7). **Reactions take any emoji**: §5.2a replaces the eight-emoji table with the full picker, the SDK-supplied grouping key and `EmojiRaw`, and the four consequences — font coverage, joined sequences, normalisation, and reactions as a moderation surface; a received record that fails validation renders as the new `malformed` gap (§5.1). **§9.10** gives the owner-succession warning its four stages. **An owner's leave opens the transfer flow rather than an error** (§12, §6.6, §16.2). §14.2's three closed vocabularies and the Ownership row were regenerated against Spec A, the contact-card and protocol-limit rows added, the duplicate screen-10 delivery row merged, and gate 8 raised from existence to **set equality**. Lint 6 was rewritten so every forbidden literal names the source it is formatted from, and §9.8, §9.9, §12 and §12.5 now read the read-key window, the free allowance and the two protocol caps from data. §16.5 splits into slice-5, beta and general-availability lists, because inclusion-proof discovery and multi-device cannot gate a build that has neither. |
| 6 | **The contact card gets its transport.** Revision 5 shipped screen 32 and a redemption flow over a rendezvous no document defined; MASTER §9.8, Spec A §5.14 and Spec B §4.3.11 now carry it, and this document's half follows. **The card's state is part of the contract**: `ContactCard().State` gains `registering`, `expired` and `unavailable` alongside `live` / `rotating` / `rotated`, and screen 32 shows no link and no QR — absent, not greyed — for a card that cannot receive, with a line for each reason (§3, §12.7). **The waiting state exists**: `[ Start chatting ]` deposits a request and does not open a conversation, because no group exists until the other side accepts, so screen 13 gains `card-sent` and `card-rate-limited` and the conversation list gains a waiting row (§3, §12.7). **Rotation states what it discards** — an uncollected request at the old link — and the client collects before it retires (§12.7). **The request-rate fallback is written down**: more than three requests at one card in an hour suspends automatic acceptance for the rest of it, holds requests for review, and says that making a new link is what v1 offers in place of blocking (§12.7, §14.2's `RefusedSinceLastCollect` and `"held_for_review"`). **§14.2** gains the screen-13 contact-request row, marks its five declaring vocabularies `CLOSED:`, and moves the three operator values from screen 22 to screen 20 per §12.2. **§14.3** records the two assumptions the rendezvous places on B. **Gate 8** splits into declaring rows asserted for set equality and citing rows asserted for membership, and fails the build on a braced list whose type Spec A never closes (§16.1). **Lint 6** drops `48 hours`, whose source does not exist, and gains `7 days`, `16 requests` and contact-card `90 days`, whose sources do (§16.3). §16.2's contact-card selftest and §16.5.1's first acceptance criterion were rewritten against the new flow. Parent revision corrected to MASTER rev 9. |

---

## 1. App shape

### 1.1 Process and identity

| Property | Value |
|---|---|
| Executable | `URmessage.exe` |
| Framework | WinUI 3 / C++/WinRT, Windows App SDK 2.2, **self-contained**, unpackaged |
| Architectures | x64, ARM64 — both, from the first CI run, matching the VPN client's matrix |
| Runtime dependency | `URmessageSdk.dll` (cgo `c-shared`), load-time import. **This is the only Go DLL in the process.** |
| Privilege | Standard user. The manifest requests `asInvoker` and the app **must fail to build** if any `requireAdministrator` or `highestAvailable` appears in it (CI check) |
| Single-instance key | `ids::kMessageSingleInstanceKey` — **must differ from the VPN app's `ids::kSingleInstanceKey`**, which is fixed. Reusing it redirects URmessage's activation into the VPN app's window |
| URI scheme | `urmessage://` (deep links, invite links, contact cards). An invite link carries an invitation a member already made: a one-time link admits its named holder, and a published address opens a **request to join** that a member approves (screen 28). It is never a door that admits anyone holding the URL. A **contact card** link is a different kind of thing and is bounded differently: it authorises a first hello with the person who made it and nothing else, it admits nobody to any group, and it is rotatable (§12.7). The VPN app owns `urnetwork://`; no collision |
| Data root | `%LOCALAPPDATA%\URmessage\` — `app\logs\`, `app\storage\` (owned by A), `app\prefs.json`. The **program** files live in `%LOCALAPPDATA%\Programs\URmessage\` |
| Min OS | Windows 10 21H2 (Mica degrades to the solid brand background, as in `WindowShell.h`) |

**Where every `settings_json` value comes from.** `urmsg_client_open(settings_json, out_error)` takes the schema in Spec A (`MessageClientSettings`):

```jsonc
// urmsg_client_open(settings_json, out_error). All keys required unless marked optional.
{
  "storage_dir":        "string",   // absolute path, per-user, writable. NOT %PROGRAMDATA%.
  "network_space_host": "string",   // e.g. "ur.network"; the operator this account is on.
                                    // Configuration with a build-time default, never a
                                    // compile-time constant — see below
  "message_server_id":  "string",   // the one server's URnetwork client id (UUID string),
                                    // from the build-time constant kMessageServerClientId
                                    // or, when set, from the operator discovery response
  "enable_cover":       false,      // optional, default false  (MASTER §9.5)
  "media_cache_bytes":  1073741824  // optional, default 1 GiB
}
```

> `storage_dir` = `%LOCALAPPDATA%\URmessage\app\storage`.
>
> `message_server_id` is the one server's URnetwork client id and comes from the build-time constant `kMessageServerClientId` in `Common/ServerConfig.h`. v1 has one message server, so a constant is the honest shape for it.
>
> `network_space_host` is **not** a constant. It is read from per-user configuration (`prefs.json`, key `network_space_host`), falling back to the value in `Common/ServerConfig.h` only when nothing is configured, and it is changeable at runtime through the SDK's `SetNetworkSpaceHost`. The reason is that this value names an **operator**, and URnetwork runs more than one — two are live today. An operator is a URnetwork platform instance that authorises transport, mints contracts, routes to providers, and runs its own discovery directory and its own key-transparency log. A message server is a different thing: it stores ciphertext and orders records, and it holds an account on one compatible operator chosen by whoever administers it. This client reaches its message server through the operator its **own** account is on, which need not be the operator the message server uses. A build that compiles one operator's host in as its only source cannot be pointed at a second one without shipping a new binary, which the master protocol design calls a defect in as many words (MASTER §2); §16.1's build gate enforces it here.
>
> There is **no ByJwt at construction**: the client opens first, then signs in through the `urmsg_auth_*` surface, and refreshes with `urmsg_client_set_by_jwt`. `message_server_id` is a URnetwork **client id**, which is not the same thing as the host string shown in §12.2 — say both.

### 1.2 Window shell

Reuse `urnw::shell::ApplyNativeShell` from `app/src/App/WindowShell.h` verbatim in behaviour — Mica backdrop with the brand background as `FallbackColor`, extended title bar with caption buttons tinted to the brand surface, placement restored and clamped to a monitor that exists, `SaveWindowPlacement` on hide and quit. Change only the constants:

```cpp
namespace urmsg::shell {
inline constexpr int kDefaultWidthDips  = 1100;   // a workspace, not a flyout
inline constexpr int kDefaultHeightDips = 760;
inline constexpr int kMinWidthDips      = 560;    // one pane + a readable thread
inline constexpr int kMinHeightDips     = 480;
}
```

`ApplyNativeShell` returns `true` when a saved placement was restored. URmessage has no tray-anchor move to suppress, but the return value is still load-bearing for the "open at the last size" behaviour and must be honoured.

### 1.3 Layout breakpoints

Three layouts, one decision point, at window level.

| Width (DIP) | Layout |
|---|---|
| < 1000 (`kWideBreakpointDip`) | **Single pane.** Conversation list *or* thread, with back navigation. Details open as a full-screen sheet |
| ≥ 1000 | **Two pane.** List (360 fixed) + thread (fills). Details open as a `ContentDialog` sheet on `UrSheetBrush` |
| ≥ 1500 (`kMessageThirdPaneDip`) | **Three pane.** List (360) + thread (fills) + details rail (360). The rail shows the current conversation's members, media, and retention |

**Do not use `AdaptiveTrigger` or `VisualStateManager`.** This is measured, not read in a doc, and is recorded in `UrComponents.h`: `AdaptiveTrigger` listens on `Window.Current`, which is `null` in a WinUI 3 desktop app; and `VisualStateGroup`s attached to a plain layout `Grid` are never processed even when the trigger goes active. Follow `MainWindow::ApplyBreakpoint` — one window-level function, named columns in markup, one place that decides what "wide" means.

### 1.4 Tray presence and lifecycle

| Behaviour | v1 |
|---|---|
| Tray icon | Yes. Own icon set, visually distinct from the VPN tray icons (`tray_*_provide_connect.ico` etc.), light and dark variants |
| Close button | Hides to tray by default; a Settings option makes it quit. First close shows a one-time flyout explaining it |
| Run at login | **Opt-in**, offered once after the first conversation is created. Not defaulted — the VPN client's D8 finding ("tunnel auto-starts on resume/login") ended in the owner's rule: **click-only** |
| Background receipt | While the process is running (tray or window), the connect session stays up and records are received and decrypted |
| Process not running | Records queue at the message server. They arrive on next launch. Once the contentless WNS wake lands — a general-availability gate, not a beta one — a contentless push COM-activates the app; §10.2 |
| Quit | Drain the UI's pending SDK calls, then stop the session, then exit. The VPN client's D3 (`0xc000027b` on tray-quit, an unobserved WinRT async surfacing during `DispatcherQueue` teardown) is the failure this drain prevents |

**Activation plumbing.** Without these three lines, "clicking the toast opens a second empty window" is the guaranteed first bug:

- Activation is read with `AppInstance::GetCurrent().GetActivatedEventArgs()` and redirected to the existing instance with `AppInstance::RedirectActivationToAsync` against `ids::kMessageSingleInstanceKey`.
- A **toast activation on a running instance restores and focuses** the existing window (and navigates to the deep-linked conversation); it never creates a second window.
- A **cold-start push COM activation fetches and raises the local toast without showing the window** — the app wakes, decrypts, notifies, and stays in the tray.

---

## 2. Installer relationship

### 2.1 Its own package

URmessage ships as its **own `InstallScope="perUser"` MSI**, `URmessage-<version>-<arch>.msi`, built from the same solution and stamped with the same version grammar as the VPN app. It is not a feature of `app/installer/Package.wxs`.

```xml
<Package Name="URmessage" Manufacturer="URnetwork" Scope="perUser"
         UpgradeCode="{…}" Version="$(var.Version)">
  <ComponentGroupRef Id="MessageAppFiles" />      <!-- URmessage.exe, URmessageSdk.dll, URmessage.pri -->
  <ComponentGroupRef Id="MessageRuntimeFiles" />  <!-- its own copy of the Windows App Runtime -->
  <ComponentGroupRef Id="MessageBrandFonts" />    <!-- ABC Gravity Extended, ABC Gravity Extra
                                                       Condensed, PP Neue Montreal, PP NeueBit Bold -->
  <ComponentRef Id="MessageUriScheme" />          <!-- HKCU\Software\Classes\urmessage -->
  <ComponentRef Id="MessageStartMenuShortcut" />  <!-- per-user, non-advertised -->
</Package>
```

A per-user package installs into `%LOCALAPPDATA%\Programs\URmessage\` with **no elevation at all**, and every Windows account on the machine installs it for itself. That is the only arrangement under which W4's "zero elevation anywhere in the product" is literally true and under which a second user on a shared PC gets a working app rather than a Start Menu entry pointing at nothing.

Why not a component set inside the VPN's per-machine MSI: per-user components in a per-machine package land in the profile of whichever account ran the elevated installer and in no other. A second user would have no binaries under their `%LOCALAPPDATA%\Programs\URmessage\`, no shortcut, and no `HKCU\Software\Classes\urmessage` handler, while the product would already record itself as installed — so no repair path would fire, and that user would be left with a Start Menu entry pointing at nothing.

**There is no per-machine variant, and there will not be one in v1.** URmessage installs for one Windows account at a time, into that account's own profile, with no elevation at any point. The accepted cost is that no organisation can deploy it centrally: it cannot be pushed through Intune, SCCM or Group Policy, and an administrator who wants it on fifty machines has fifty users to ask.

That cost is paid for a property that is doing real work. No elevation means no privileged service, no driver, no firewall filters, and none of the machinery behind most of the hard defects in the VPN client — the service-restart budget, the adapter lifecycle, the kill-switch states, the loopback RPC reattach class. §0.3 lists them one by one. A per-machine installer would put the binaries under `%ProgramFiles%`, which the running user cannot rename-swap, which means an updater that needs a privileged helper or a UAC prompt on every update — and the prompt is the part that matters, because a product that asks for administrator rights routinely is a product whose users click through administrator prompts.

A managed-deployment story is a later decision made deliberately, with a signing certificate and a support surface behind it. It is not a thing to acquire accidentally by making the installer a little more convenient.

### 2.2 Own payload, separate app

The install directory is `%LOCALAPPDATA%\Programs\URmessage\`, with per-user components, a per-user `Software\Classes\urmessage` key under `HKCU`, and a per-user Start Menu shortcut. Advertisement is not used and is not needed: nothing here is shared between accounts. The package carries:

| File | Notes |
|---|---|
| `URmessage.exe` | |
| `URmessageSdk.dll` | Separate from `URnetworkSdk.dll` so VPN builds are untouched. It is also the **only** Go DLL the process loads (Spec A decision A12) |
| `URmessage.pri` | **Not `resources.pri`.** `URmessage.exe` must construct `Microsoft.Windows.ApplicationModel.Resources.ResourceManager(L"URmessage.pri")` explicitly rather than relying on the default lookup |
| Its own copy of the self-contained Windows App Runtime | `MessageRuntimeFiles`. A per-user component set cannot reference the VPN feature's per-machine `RuntimeFiles` components (W4) |
| Its own copy of the four licensed brand faces | `MessageBrandFonts`. Without them §11 renders in system faces |
| `HKCU\Software\Classes\urmessage` registry key | Mirrors the existing `UriScheme` component, pointing at `URmessage.exe` |
| Per-user Start Menu shortcut | Non-advertised. Plus `ARPPRODUCTICON` parity |

### 2.3 Updater

`UpdateChecker` (VPN app) polls the fork's releases, verifies the GitHub per-asset `digest` field, extracts with `tar.exe`, and performs an allowlisted rename-swap. Two changes:

1. Add `URmessage.exe`, `URmessageSdk.dll`, `URmessage.pri` to the swap allowlist.
2. `URmessage.exe`, `URmessageSdk.dll` and `URmessage.pri` live under `%LOCALAPPDATA%`, which the running user owns, so the `UpdateChecker` rename-swap needs no elevation and no privileged helper. The mismatch banner already reads the **running** image, not `binPath`. URmessage has no service, so a swapped `URmessage.exe` is picked up on next launch and the banner says so: *"An update is ready. Restart URmessage to use it."* — one click, no elevation.

### 2.4 Portable zip

When URmessage is built, its files — including its own copy of the runtime and the brand faces — go into the same zip. No second zip, no second release, no second tag: the version grammar (`Common/Version.h`, `Common/VersionGrammar.h`, `kString`/`kCode`) is shared and both apps stamp the same tag. The zip is the same artefact for both apps; only the MSIs are separate.

### 2.5 Independence

**URmessage must run with the VPN service absent, stopped, or broken.** CI must install `URmessage-<version>-<arch>.msi` **as a standard user with no elevation available**, on a machine where neither `urnetworkd` nor the VPN app was ever installed, and assert that the app launches, reaches the login screen, signs in and renders in the brand faces. It must then repeat the install and launch **as a second, different standard user on the same machine** and assert the same. The old check tested only that the service was absent, which exercises neither the runtime, nor the fonts, nor the login path, nor the multi-user case.

### 2.6 Acquisition

URmessage is distributed from its own download page and installed from its own per-user MSI. **The shipping VPN client does not promote it**: there is no "Get URmessage" row, no banner and no mention, in v1.

Two reasons, both operational. The release trains and the support surfaces stay separate, so a messaging defect never arrives as a VPN support ticket and a VPN release never has to wait on a messaging one. And v1 has a single message server (§12.2): pointing an entire VPN install base at it is a capacity decision that nobody has made and that this document is not the place to make.

### 2.7 The beta ships unsigned

`URmessage.exe`, `URmessageSdk.dll` and the MSI are **not Authenticode-signed** for the beta. Code signing is decided before general availability and is not a beta blocker.

What that means concretely, said to testers on the download page and in the installer's first screen rather than discovered at a SmartScreen prompt:

> This build isn't signed yet. Windows will warn you before it runs — choose **More info**, then **Run anyway**. Check the download against the SHA-256 on the release page before you do.

Three costs, accepted:

1. Every early user sees a SmartScreen warning and learns to click through one, which is a habit this product spends §7 trying to break elsewhere.
2. CI signing integration is discovered late, and it always takes longer than the certificate does.
3. SmartScreen reputation accrues to a signed publisher over time, so reputation starts from zero on the first signed release rather than having been building through the beta.

The mitigation for the beta period is the per-asset digest the updater already verifies (§2.3) and the published hash on the release page. That is integrity, not provenance, and it is not the same thing — which is exactly why signing is decided before general availability and not after.

---

## 3. Screen inventory (v1)

The table is the contract; the sections that follow expand the four screens that carry real risk. Every screen's empty, loading, and error states are in §9.

| # | Screen | Shows | States |
|---|---|---|---|
| 1 | **Welcome** | Wordmark, one sentence, **three** buttons: *Set up URmessage* / **"Link this computer to a device I'm already using"** (visually **primary** over the recovery-phrase option, because it produces a sending-capable device) / *I already have a recovery phrase* | first-run only |
| 2 | **URnetwork account** | **Sign in or sign up, in full, without leaving the app** — email, password, SSO, verification code and password reset, reusing `LoginPage` / `LoginCarousel` / `AuthSheets` / `GoogleSignIn` from the VPN app against the `urmsg_auth_*` surface | signed-out, signing-up, awaiting-verification, submitting, error, signed-in |
| 2a | **Account phrase** | Shown by the URnetwork signup flow. **Explicitly labelled as the account phrase, not the message recovery phrase**, with the distinction stated on the screen itself | shown, confirmed |
| 3 | **Identity intro** | What the recovery phrase is, that it is generated here and never sent, that losing it loses history. One "Create my phrase" button | static |
| 4 | **Seedphrase display** | 24 words, 4×6 numbered grid, mono face. Copy / Save to file / Continue | capture-blocked, obscured (window inactive), dwell-locked, ready |
| 5 | **Seedphrase confirmation** | Four random positions, typed entry, BIP39 autocomplete | empty, partial, wrong (→ back to 4), confirmed |
| 6 | **Restore — phrase entry** | 24 fields, whole-phrase paste, per-word validity, checksum check | empty, partial, word-not-in-list, checksum-failed, valid |
| 7 | **Restore — progress** | Finding groups → restoring history, per-group rows | working, complete, partial, nothing-found, read-only-outcome (§6.7) |
| 8 | **Link a device** | Existing device: QR + typed pairing code + SAS. New device: code entry + SAS | waiting, paired, SAS-compare, approved, refused, timed-out |
| 9 | **Conversation list** | Rows: identicon, name, last-message preview, time, unread count, muted glyph, disappearing-timer glyph. Search box. New-conversation button | empty, loading, populated, filtered-no-results, waiting (a contact request sent and not yet accepted, §12.7), offline banner, server-unreachable banner |
| 10 | **Conversation view** | Virtualized message list, day separators, system records, composer, disappearing chip, attachment button | empty, loading-history, at-top (no more history), populated, read-only (observer / restored / removed), blocked-by-key-change, fork-resyncing, fork-unresolved, away-too-long |
| 11 | **Message context menu** | React, Reply, Copy, Save attachment, Message info, Delete for me, Delete for everyone | per-message; delete-for-everyone hidden when not the sender and outside the 24-hour window (§8.2) |
| 12 | **Message info** | Only what Spec A returns: sender, sent time, received time, epoch, sender leaf index, retention class, size bucket, attestation state, **delivered-by list and read-by list** — this is the one place per-member delivery is shown, never the thread (§5.3) | own messages and received |
| 13 | **New conversation** | **Show my contact card** (screen 32), **Scan or paste someone's contact card**, directory lookup by URnetwork name where the other person has turned listing on, recent contacts, "New group" | empty query, searching, results, no-results, lookup-failed, KT-proof-failed, log-unavailable, card-scanned, card-sent, card-retired, card-rate-limited |
| 14 | **Group creation** | Name, members picker, retention, disappearing default | drafting, creating, created, failed |
| 15 | **Group details** | Members with roles, invite, invite links and join requests (screen 28), ownership (screen 30), retention, disappearing, message previews in notifications, history-grant banner, leave | member view, admin view, owner view |
| 16 | **Member detail** | Identicon, principal, safety number, role controls, remove, device count | self, member, admin, owner, unpinned, pinned, key-changed |
| 17 | **Safety number** | 60 digits in 12 groups of 5, mono; QR; Copy; "Mark as verified locally" | unpinned, pinned, changed-unaccepted, changed-accepted |
| 18 | **Key-change warning** | The blocking sheet. Exact copy in §7 | blocking (modal), resolved, in-thread permanent record |
| 19 | **My devices** | This device + others: name, added date, last seen. Add device, Remove device (§12.3) | one device, several, removing (per-group progress), removed, **partially removed**, failed |
| 20 | **Settings** | Eight groups; §12. Account carries the two exit doors — **Sign out of URnetwork** (non-destructive) and **Remove this identity from this computer** (destructive, Hello-gated, hard-blocked before phrase confirmation) — and the new **Security** group renders `Sealer.Description()` verbatim | — |
| 21 | **Attachment viewer** | Image or file. Save as, Open with | loading, loaded, expired-by-policy, download-failed, too-large |
| 22 | **About** | Version, `kCode`, message server host, where the server is hosted (`ServerInfo().HostingJurisdiction`), licences, `THIRD-PARTY-NOTICES.txt` | static |
| 23 | **Invitations** | Pending group invites, pinned at the top of the conversation list (a modal on launch is hostile). Inviter, group name, member count, Accept / Decline, plus requests from people who used your contact card, with the sender's name, safety digits and `[ Start chatting ]` / `[ Ignore ]`, and the number of requests the server refused since this computer last looked (§12.7) | none, pending, accepting, accepted, declined, expired, held-for-review |
| 24 | **Reaction picker** | Full emoji picker with search, skin-tone selector, recents and a frequently-used row | closed, open, searching |
| 25 | **Store unavailable** | Full-screen stop, §9.2. Not a banner | `unseal_failed`, `corrupt`, `disk_full`, `locked_by_another_process` |
| 26 | **Locked** | Full-screen PIN entry over the brand background: app name, PIN field, `[ Unlock ]`, and "Forgot your PIN?" leading to §6.9's consequence copy. No message content, no conversation names, no counts | locked, entering, wrong-pin (with the delay shown), unlocking |
| 27 | **Redeem a code** | A single field for a balance code, `[ Redeem ]`, and the result. Reached from Settings → Account and from the out-of-credit banner (§9.9) | empty, submitting, redeemed, invalid, already-used, expired, rate-limited, offline |
| 28 | **Invite links** | Per group: create a one-time link or a published address, the list of live links, `[ Copy ]`, `[ Revoke ]`. And the **join requests** queue for a published address, with `[ Accept ]` / `[ Decline ]` per request | none, creating, live, revoked, requests-pending, request-accepting |
| 29 | **Security log** | Settings → Security. Append-only list from `SecurityLog()`: server key rotations, accepted contact key changes, devices added and removed, PIN set or cleared, diagnostic sessions | empty, populated |
| 30 | **Ownership** | Group details → Ownership. Transfer ownership; nominate or clear a successor; turn succession off; the successor's claim; an admin's countersignature; the owner's own countdown | owner view, admin view, successor view, disabled, eligible, claiming |
| 31 | **Diagnostics** | Settings → Advanced. Start a bounded diagnostic session, see when it ends, stop it early, read what was recorded | off, running, ended |
| 32 | **My contact card** | The QR code, the copyable link, the safety digits under it, `[ Copy link ]`, `[ Save QR ]`, `[ Make a new link ]` and what that does to the old one | registering, live, rotating, rotated, expired, unavailable |

Screens 26–32 are reached from Settings, from group details and from screen 13; none of them appears in the onboarding stack, and none of them is a modal that opens on launch.

Screens 1–8 are the onboarding stack and never appear again once complete (except 8 and the phrase re-display in Settings). Screens 9–10 are the app.

**The onboarding branches, explicitly**, so the team knows where the account gate sits in each:

```
Welcome (1) → URnetwork account (2) → { new identity (3 → 4 → 5)
                                      | link device (8, new-device half)
                                      | restore (6 → 7) }
```

Without screen 1's middle button, the new-device half of screen 8 is unreachable from a fresh install, and MASTER §5.4's *documented normal path* is inaccessible while §6.8 tells the user to use it.

---

## 4. Conversation list

### 4.1 Row anatomy

| Element | Token / style |
|---|---|
| Identicon, 40×40, rounded 8 | §11.5 |
| Display name | `UrRowTitleStyle` |
| Last-message preview, one line, ellipsized | `UrRowNoteStyle` |
| Timestamp, right, relative under 7 days | `UrCaptionTextStyle`, `UrTextMutedBrush` |
| Unread pill | `UrAccentBrush` fill, `UrInverseTextBrush` text |
| Muted glyph, disappearing-timer glyph | `UrRowIconStyle`, `UrTextMutedBrush` |
| Row container | `UrCardRowButtonStyle` (hover/press from `UrCardHoverBrush` / `UrCardPressedBrush`) |

**A row never shows a delivery-state colour.** Delivery is a glyph in the thread (§5.3), not a colour in the list — colour cannot carry state alone (§13.4).

### 4.2 Preview and the disappearing class

A conversation whose disappearing timer is on shows a **timer glyph in place of the preview text**, not the text. The message's plaintext is `EPH`-class and its key is destroyed on a timer; a preview cached in a list row that survives the timer would defeat §12.1's guarantee at the UI layer. The list stores no preview for `EPH` conversations — it re-reads from A, and A returns nothing once the key is gone.

### 4.3 Ordering, muting, unread

Ordered by last activity. Muted conversations stay in order but never raise a notification and never bold. Unread is per-conversation and clears on the thread becoming visible **and focused** for 1 second — not on scroll-into-view, which marks things read that a user glanced past.

---

## 5. Conversation view

### 5.1 The list

`ItemsRepeater` inside a `ScrollViewer`, virtualized, with incremental loading upward. A group of 500 people with two years of history is the design target (ledger P4); the list must never materialize more than a window of items. Anchoring: on new-item append, hold scroll position unless the user is within 80 DIP of the bottom, in which case follow.

**Order is the server's; the timestamp is the sender's.** The list is ordered by the server-assigned record order that Spec A's `History` and `MessageEvent` deliver — gapless, agreed by every client, and manipulable by none — and the time **shown** on a message is `MessageEntry.SentAtMs`, which is the sender's own claim. The two can disagree, and when they do the message stays where the server put it and displays the time its sender claimed. The client never re-sorts by `SentAtMs`, never hides a message whose claimed time looks wrong, and never adjusts a claimed time toward plausibility: a clock is a fact about a sender's machine, and order is the only thing everyone agrees on.

Day separators, and a system-record row type rendered as a centred, muted, non-bubble line. System records in v1:

| Record | Rendered |
|---|---|
| Member added / removed / left | "Ana added Bo." |
| Role changed | "Ana made Bo an admin." |
| Disappearing timer changed | "Ana set messages to disappear after 1 day." + the §8.1 string on the first change + **"This applies to messages sent from now on."** |
| Key change (`KEY_CHANGE_NOTICE`) | **Permanent, non-dismissible.** §7.4 |
| History grant | **Persistent banner**, not a row — §5.5 |
| Retention policy changed | "Ana set media to be kept for 1 month." |
| Observer message hidden | "A message from an observer was hidden." (§5.6) |
| Gap (`Kind == "gap"`) | Per reason: `expired` → §9.7's ephemeral line; `out_of_window` → *"A message here couldn't be decrypted — this computer was offline while the group's keys changed too many times."*, with the supporting line *"Linking another computer, or restoring from your phrase, brings the rest back."*; `not_a_member_yet` → reuse §9.1's "You joined here" boundary; `withheld` → §9.6's attestation copy; `no_wrap` → *"This device hasn't received its key for this part of the conversation yet."*; `malformed` → *"Something arrived here that this version couldn't read."* — no retry affordance and no error code; a record that fails validation is shown rather than hidden, because a messenger that silently drops what it cannot read cannot be trusted to have shown everything |
| Invite accepted / declined | "Bo joined." / "Bo declined the invitation." |
| Message deleted for everyone | "This message was deleted." — a permanent placeholder in place of the bubble, never a removed row |
| Ownership transferred | "Ana made Bo the owner of this group." |
| Successor nominated / cleared | "Ana nominated Bo to take over this group if she goes missing." / "Ana cancelled that." |
| Succession claimed | "Bo took over this group. Ana had not been seen here for 90 days and 3 of 4 admins agreed." |
| DM policy changed | "Ana set messages here to be kept for 30 days." |
| DM policy request pending | "Ana asked to keep messages here for 1 year. It takes effect when you set the same thing." |
| Join request accepted | "Bo asked to join with Ana's link, and Cass let them in." |
| Conversation started from a contact card | "This conversation started from your contact card." (§12.7) |
| Succession warning, 30 and 60 days | "You haven't posted here for 30 days. If that reaches 90, Bo can take over this group with most admins' agreement." — an in-thread system row, at 30 and again at 60 |
| Succession warning, 75 and 85 days | Not a row. A non-dismissible banner at 75 and a modal at 85 — §9.10 |

> **Incremental loading, concretely.** `History()` is synchronous and reads SQLite, and §14.1 forbids blocking the UI thread on any SDK call, so it runs on a dedicated background thread that fetches a page of **50** entries and `TryEnqueue`s the completed page. While a page is in flight the list shows a single muted "Loading older messages" row at the top. `at-top` is **not** inferred from a short result — it is `HistoryState().HasMoreLocal == false && HasMoreRemote == false`, per §14.2 requirement 1.
>
> **Dropped events.** On any event with `Dropped > 0`, discard the in-memory window for that group, re-read via `History()`, and re-evaluate unread. Never merge a post-drop event (§14.1 trap 6).

### 5.2 Bubbles

| | Incoming | Outgoing |
|---|---|---|
| Fill | `UrCardBrush` (#1C1C1C) | `UrCardHoverBrush` (#242424) |
| Border | none | 1px `UrBorderBrush` |
| Alignment | left | right |
| Text | `UrBodyTextStyle`, `UrTextBrush`, `UrBodyFontFamily` | same |
| Max width | 68% of the thread column, capped at 640 DIP | same |

`UrAccentBrush` (#EFF7BB) is **not** a bubble fill. It is the primary action colour — the send button, the primary button in every sheet — and a screen of pale-yellow bubbles would leave nothing for the action. Message text uses the body face, never `UrHeadingFontFamily`: ABC Gravity Extended is a display face and is unreadable at body size and length.

Sender name and identicon appear on the first bubble of a run in groups, never in DMs.

### 5.2a Bubble variants

The data model exists and the pixels do not. Seven variants, with layout and tokens:

| Variant | Layout |
|---|---|
| **Quoted reply** | Above the reply text, inside the bubble: 2px `UrBorderStrongBrush` left rule, sender name in `UrBodyStrongTextStyle`, one ellipsized line of the parent in `UrRowNoteStyle`. Tap scrolls to the parent. Renders by **live lookup**, never by copying the parent's text (§5.7) |
| **Inline image** | Thumbnail, max 320×320 DIP, aspect-preserving, rounded 8, click → screen 21 |
| **File card** | Icon, filename, formatted size, `[ Save ]` |
| **Caption line** | Under either attachment variant, `UrBodyTextStyle`, matching A's `SendAttachment(…, caption)`. Collapsed via `SetTextOrCollapse` when empty |
| **Reaction strip** | Below the bubble, grouped by emoji with counts, `UrCardHoverBrush` pills; tap for the member list. Bound to A's `React` / `Unreact` and `MessageEvent{Kind: "reactions_changed"}` |
| **Gap row** | Not a bubble — the centred muted system row, with per-reason copy from §5.1 |
| **Deleted placeholder** | Not a bubble: a centred, muted line reading *"This message was deleted."* with the original sender's name and the original time, occupying the message's place in the order. It is what `Kind == "tombstone"` renders, it is never collapsed away, and there is no affordance to see what was there |

**Any emoji, from the full picker.** Screen 24 is a real emoji picker: search, a skin-tone selector, a recently-used row, and the full set the system font provides. There is no approved list and no fallback list. The SDK validates what the picker returns and refuses anything that is not a single emoji cluster, which is the only rule the picker has to respect.

**Grouping.** Reactions collapse into pills with counts, and the SDK supplies the grouping key — `MessageReaction.Emoji`, already normalised with skin tones and variation selectors folded out — alongside `MessageReaction.EmojiRaw`, which is what a reactor actually sent. The client groups on the key and never on the raw form. It must not implement its own folding: two folds that disagree produce two pills for one emoji, and the SDK's is the one the counts are computed from.

Four consequences come with the full set, and each has a rendering rule rather than a hope.

**Font coverage.** Windows ships an emoji font that lags Unicode by a year or more, and a reaction composed on a phone can arrive here with no glyph. Render the replacement box the shaper produces, keep the count, and put the codepoint sequence in the pill's tooltip and its `AutomationProperties.Name`. Never substitute a different emoji and never hide the reaction: a box is a true statement about this computer's fonts, and a silent substitution is a lie about what someone said.

**Joined sequences.** Many emoji are several codepoints joined with zero-width joiners, and a shaper that does not know a sequence draws its parts. The SDK guarantees one cluster per reaction, so the pill is always one reaction even when it draws as three pictures; the count is never split.

**Normalisation.** Skin-tone modifiers are folded out before grouping and before display selection, which is deliberate and worth knowing: a reaction is a one-tap gesture, and a skin tone carried on it says something about the person tapping that they did not choose to say. Variation selectors fold out too, so the same emoji sent with and without one is one pill.

**A reaction is content now.** With a fixed set the worst a reaction could carry was one of eight approved meanings; with the full set it is something a person wrote, and it can be used to harass. There is no reporting route behind it — reporting and blocking are not in v1 (§15) — so the recourse the UI offers is the recourse that exists: mute the conversation, leave it, or remove the person if you administer the group. The context menu on a reaction pill therefore offers **Remove my reaction** and, in a group where the user is an admin or the owner, **Manage members**, and it offers nothing that implies a report will be read by anyone.

A refused emoji is a call error rather than a send state: Spec A delivers the error to the `SendCallback` and emits no record, and no value is added to Spec A's closed send-failure vocabulary for it. A **received** reaction record that fails validation renders as the `malformed` gap of §5.1, never as a dropped row.

### 5.3 Delivery state

Glyphs, right-aligned under the last outgoing bubble of a run. Never colour alone.

```
MessageEntry.State is a CLOSED set:
  "pending" | "sent" | "delivered" | "read" | "failed" | "expired"

  pending    in the local outbox; not yet accepted by the message server
  sent       accepted by the message server
  delivered  another member's device said it decrypted this message
  read       a read receipt was received (only when both sides have receipts on)
  failed     terminal; carries a Reason from the closed send-failure vocabulary
  expired    the disappearing timer elapsed and the key is gone

"Delivered" is a statement by a device, never by the server. The server does not know which
member a sender_handle belongs to (MASTER §9.5) and does not record who fetched what
(MASTER §9.7), so a server-side delivery claim would be a guess about someone else's
machine. The receipt is an ephemeral record the recipient's device emits when it opens the
message, and it is off for a user who turns delivery receipts off (§12).
```

| State | Glyph | Meaning |
|---|---|---|
| Queued | clock | In the local outbox; not yet accepted by the server |
| Sent | one check | Accepted by the message server |
| Delivered | two checks, outline | A device of another member decrypted it |
| Read | two checks, filled | Read receipt received (only if both sides have receipts on) |
| Failed | exclamation, `UrDangerBrush` | Tap for reason + `[ Try again ]`, which calls `Retry(gid, mid)` |

**Uploading.** An attachment send additionally renders a determinate progress ring bound to A's `UploadProgress`, with a cancel affordance mapped to `MessageSendTicket.Cancel()`. It precedes `Queued` and is not a `MessageEntry.State` value.

**What delivery means here, in the tooltip:** *"Delivered means a device belonging to someone in this conversation told us it decrypted your message. The server can't tell us that — it doesn't know who fetches what — so a message can sit read for hours before this appears, and it never appears at all for someone who has turned delivery receipts off."*

**Turning your read receipts off hides everyone else's from you.** A message you send stops at **delivered** and never reaches **read**, and screen 12's read-by list is empty, for as long as the setting is off. The same applies to typing indicators: with yours off, nobody else's appears. This is not a UI courtesy — the SDK drops inbound receipts before they reach the store, so a screen that forgot the rule could not leak them anyway.

In a group, `delivered` means **at least one** member's device reported it. Screen 12 lists which members, from `MessageEntry.DeliveredTo`, exactly as it lists who read it. There is no per-member glyph in the thread: a row of eleven checkmarks says less than one word does.

### 5.4 Composer

- `Enter` sends, `Shift+Enter` newline. Reversible in Settings; the setting is announced in the composer's `AutomationProperties.HelpText`.
- Multi-line, grows to 6 lines then scrolls.
- Attachment button, disappearing-timer chip, emoji button.
- Drag-and-drop onto the thread attaches. `Ctrl+V` of an image attaches it.
- **Disabled states** carry an inline reason above the composer, never a silently greyed box: read-only (observer, restored-without-leaf, removed from group), blocked by an unresolved key change, an unresolved fork (§9.5), a read authorization that has aged out (§9.8). An exhausted data allowance is not one of them — the composer stays live and queues (§9.9).

**The send path for an attachment**, which the composer bullets above leave out:

- **The cap check is pre-send.** Compare the file's size against `ServerInfo().MaxBlobBytes` at pick/drop time and refuse with the §9.3 `too_large` copy **before any bytes move**. When `ServerInfo().Advertised == false` the cap renders as "not known yet" and the picker warns rather than fabricating 100 MB (§14.2 requirement 7).
- **MIME type** is determined by content sniff **plus** extension, and travels **inside the encrypted body** (Spec A §5.13). It is never a server-visible field.
- **Caption.** v1 sends an **empty caption** unless the user typed one in the composer at attach time; the caption rides with the attachment, not as a separate message.
- **The cap is the server's file size limit**, read from `ServerInfo().MaxBlobBytes` and rendered as a formatted value. It is one of the three limits this server advertises; the other two are the media window and the text storage cap, and all three are shown together in Settings → Storage (§12).

**Receiving an attachment: it does not always download itself.** Spec A fetches an attachment's bytes automatically only when the sender is already a known contact and this device has been in the group for at least a day. Otherwise the entry arrives with `MessageAttachment.State == "not_downloaded"` and `AutoDownloadHeld == true`, and the client renders the file card with a `[ Download ]` button and this supporting line, which is the honest reason rather than an apology:

> *Files from someone you haven't messaged before don't download on their own.*

Tapping downloads it, and thereafter that contact is known and their files behave normally. The setting lives in Settings → Privacy & retention as **"Download photos and files automatically"** with three positions — **From people I've messaged** (default), **Always**, **Never** — writing Spec A's `"attachment_auto_download"` preference. The default exists because an image decoder parsing bytes from a stranger is the cheapest attack surface in any messenger, and because a group you joined an hour ago is exactly where those bytes arrive.

### 5.5 History grant banner

§11 requires this be persistent for the life of the group. A pinned banner above the composer, `UrCardBrush` with a `UrBorderStrongBrush` top edge, never dismissible:

> **Ana granted Bo access to messages from 3 March 2026 onward.**
> History grants cannot be undone and stay visible here for as long as this group exists.

The banner is rendered from `HistoryGrants(groupId)` (Spec A §7.3), one banner per `MessageHistoryGrant`: `GranteeDisplayName`, `GrantedByDisplayName` and `FromMs` produce the sentence, and `FromEpoch` is what screen 12 shows if the user asks where the boundary is. A grant is issued by an owner through `GrantHistory(groupId, memberId, fromEpoch, cb)` from screen 15, and the arrival of one is `GroupEvent{Kind: "history_granted"}`. There is no dismiss affordance and no client-side hide: MASTER §11 makes the grant non-erasable, and a banner the user can close is an erasure with extra steps.

### 5.6 Observers

`OBSERVER` is enforced in the UI and by MLS proposal rules, **not by the server** (§9.2, §11). An observer holds the group keys and a modified client could encrypt a valid application message. The client's behaviour and its copy must match that truth:

- An observer's composer is disabled with the reason *"You can read this group but not send to it."*
- Receiving clients **hide** application messages whose sender leaf holds `OBSERVER` in the transcript-covered group-context extension, collapsing them to the system row in §5.1. Expanding shows the content with a warning.
- Group settings, on the observer row: *"Observers are asked not to send. Someone who modifies their app can still send, and this version of URmessage cannot stop it at the server — it can only hide the result."*

`MessageEntry.SenderRoleAtSend` is the field this behaviour reads. It is the sender's role **as of the sending epoch**, from the transcript-covered group-context extension — `Members(groupId)` returns current roles, which is the wrong answer for a historical message.

### 5.7 What must not outlive the key

> **No `DURABLE`-class artefact may contain `EPH` plaintext.**
>
> 1. **Reply.** A reply to an ephemeral message carries `replyToId` only and renders the quote by live lookup, collapsing to *"Replying to a message that is no longer available"* once the key is gone. It never copies the parent's text into the reply, which would preserve an `EPH` parent's plaintext past the destruction of its key, forever, for the whole group.
> 2. **Copy.** Copy on an ephemeral message shows the same one-time confirmation §8.3 uses for saving an ephemeral attachment.
> 3. **Search.** The index excludes `EPH` records entirely (a requirement on A, §14.2).
> 4. **Message info.** Screen 12 on an expired record shows metadata only, never text.
>
> Each is a pinned selftest in §16.2, next to the existing toast-revocation assertions.

### 5.8 The typing indicator

A single row pinned between the last bubble and the composer, **outside** the `ItemsRepeater`, so it never enters the virtualized list and never perturbs §5.1's 80-DIP anchoring: a typing indicator that scrolls the thread is worse than no typing indicator.

- **Style.** `UrRowNoteStyle` on `UrTextFaintBrush`, one line, 24 DIP high, collapsed when nobody is typing. Collapsing changes the thread's height, so the composer is anchored to the bottom and the list is what resizes.
- **Wording**, resolved from `MessageEvent.TypingIds` through `Members(groupId)` and formatted with `Plural()`:

| Typers | String |
|---|---|
| 1 | *"Ana is typing…"* |
| 2 | *"Ana and Bo are typing…"* |
| 3 or more | *"3 people are typing…"* |

  In a DM the name is still used, not "typing…", because the conversation may be open in a window the user is not looking at and the name is the cheap disambiguator.
- **Clearing.** The row clears when an event arrives with an empty `TypingIds`. As a safety net against a lost event, the client drops any id it has not seen re-listed within **10 seconds** and clears the row when the set empties. The timeout is client-side; it places no obligation on Spec A.
- **Accessibility.** The row is **excluded from the live region** — `AutomationProperties.LiveSetting` is `Off` and the row is not a child of §13.1's polite region. Announcing every keystroke's worth of state change would make Narrator unusable in an active group. It remains reachable by navigation and carries the same sentence as its automation name.
- **Reduced motion.** No animated ellipsis when the system's reduced-motion setting is on; the text alone (§13.4).

---

## 6. The seedphrase

This is the highest-stakes surface in the product. A user who does not record the phrase loses every durable message in every group, permanently, and does not find out for months. Everything in this section is normative.

### 6.1 What the phrase is, stated before it is shown

Screen 3 comes **before** generation, is a single column, and says exactly this:

> ### Your recovery phrase
>
> URmessage is about to create 24 words on this computer. They are the only way to get your messages back if you lose this device.
>
> - The words are made here and are **never sent anywhere** — not to URnetwork, not to us.
> - They are **not** your URnetwork account phrase. That one is a password. This one is a key.
> - If you lose them, your message history is gone. Nobody can reset it or send you a copy.
> - Anyone who has them can read everything you have ever sent and can act as you.
>
> Have somewhere to write them down before you continue.
>
> `[ Create my phrase ]`

Two facts are load-bearing and both come from the master spec: the two phrases are separate secrets (§5.1) and the phrase cannot be recovered (§5.5, §13). Users conflate the two phrases if you do not say so on the screen where it matters.

**This screen exists partly to separate two secrets that appear minutes apart.** A user who has just created a URnetwork account has already been shown a phrase, and is about to be shown another one that is not the same and is not interchangeable. Three rules, all normative:

1. **Different titles, always.** The account one is *"Your URnetwork account phrase"*; this one is *"Your message recovery phrase"*. Neither is ever called just "your phrase".
2. **Different visual treatment.** The message recovery phrase is the only one shown in the capture-blocked grid of §6.2; the account phrase uses the VPN app's existing presentation.
3. **The restore field says which one it wants**, and detects the wrong one client-side before any network call — §6.7's fourth failure row already carries that copy, and it exists precisely because the operator receives the account phrase on every login (MASTER §5.1), so a user pasting it into the wrong field is pasting an operator-visible secret into a screen that promised nothing would be sent.

### 6.2 Display (screen 4)

**Layout.** 24 words in a 4-column × 6-row grid, each cell showing `nn` in `UrTextMutedBrush` and the word in `UrMonoFontFamily` at `UrBodyLargeTextStyle`. Column-major numbering (1–6 down the first column) so a user transcribing top-to-bottom on paper matches.

**Capture protection.**

| Mechanism | Rule |
|---|---|
| `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` on entering the screen, `WDA_NONE` on leaving | Blocks screenshots, screen recorders, shared-screen calls, **and Windows Recall**. It is the single highest-value line of code on this screen: a phrase screenshotted into OneDrive is a phrase in the cloud, and Recall's periodic snapshots on Copilot+ PCs — on for many users — would otherwise write the 24 words into a local searchable indexed store. Recall honours this same display-affinity flag, so the mechanism already chosen is the right one; say so, or a future reviewer weighing the "Show anyway" escape will underestimate what dropping the affinity costs |
| `GetSystemMetrics(SM_REMOTESESSION)` | If non-zero, **skip the affinity** (it would black the window for the only person who can read it) and show an inline warning instead: *"You are on a remote session. These words are travelling over that connection, and screenshots, screen sharing and Windows Recall on the far end can see them. Consider doing this on the machine itself."* |
| "Show anyway" escape | If a user reports a black window (some capture-adjacent drivers), one button drops the affinity for this session with a confirm: *"Screenshots, screen sharing, and Windows Recall will be able to see your phrase."* |
| Window deactivation | The grid **blurs and overlays** with "Click to show your phrase again". It does **not** navigate away — a user alt-tabbing to a password manager must not lose their place |

**Copy to clipboard.** Allowed, because forbidding it pushes users to photograph the screen, which is worse. But:

- `Clipboard.SetContentWithOptions` with `IsAllowedInHistory = false` and `IsRoamable = false`. Windows clipboard history syncs across devices through a Microsoft account; a phrase that lands there has been transmitted, which the screen just promised would not happen.
- The clipboard is cleared 60 seconds later (only if our content is still on it).
- A one-time confirm: *"Your phrase will be on the clipboard for 60 seconds. Paste it into your password manager now, not into a chat or a document."*

**Save to a file.** `FileSavePicker` — in an unpackaged WinUI 3 app this **must** be initialized with `IInitializeWithWindow::Initialize(hwnd)` or it throws; the same applies to the `FileOpenPicker` behind §5.4's attachment button. Default filename `URmessage recovery phrase.txt`, plain text, no encryption (an encrypted file needs a password the user will also lose). Confirm first: *"This writes your phrase to a file in plain text. Anyone who can read that file can read your messages. Put it somewhere you would put a passport."*

**Print.** Not in v1. `PrintManager` in an unpackaged app is disproportionate work for this screen. Save-to-file plus the user's own printer covers it.

**The dwell lock.** `[ I've written it down ]` is disabled for the first 15 seconds and shows a live reason beside it: *"Take a moment — you'll be asked for four of these words next."* A disabled button with no explanation reads as a broken app; a disabled button with a countdown reads as a deliberate pause, which is what it is.

### 6.3 Confirmation (screen 5)

**Typed, not multiple choice.** Multiple choice is defeated by clicking, teaches nothing, and passes for a user who never wrote anything down.

- Four positions chosen uniformly at random from 1–24, presented in ascending order, labelled by position ("Word 7").
- Text fields with BIP39 autocomplete over the full 2048-word list. **The dropdown must never be filtered to the correct answer** — it is a typing aid, not a hint.
- All four are checked on submit, not per-field: per-field checking turns the screen into an oracle.
- **A wrong answer returns the user to screen 4**, with a fresh set of four positions on the next attempt, and this line: *"That didn't match. Here are your words again — check what you wrote down against them, line by line."* Two failures in a row adds: *"If what you wrote down doesn't match, write it again now. There is no way to get these words back later."*
- On success: the local store records `phrase_confirmed_at`. **Per C-1, sending is gated on this flag** — surfaced as `CanSend` reason `phrase_not_confirmed`, backed by A's `PhraseConfirmedAtMs()` in the sealed keyfile, never a `prefs.json` flag.
- **There is no skip.** Screen 5 has no "Later", no "Skip for now" and no dismiss affordance, and `Esc` does not leave it. The only ways out are a correct confirmation or closing the app. A user who closes the app lands in §6.4's defined state — identity created, reading works, sending blocked, one non-dismissible banner — and is returned to the quiz on next launch. That state exists because a process can be killed, not because the product offers a way past this screen.

Three additions, all normative:

> (a) **"Type all 24"** as an equal-weight second button beside the four-word quiz. Record **which mode** set `phrase_confirmed_at`; the full path is the one that actually validates a transcript, and four positions out of 24 leaves 20 words unverified — a single silent transcription error is fatal and is not discovered until a restore, possibly years later, at which point §6.7's checksum message is the last thing the user ever sees.
>
> (b) **Delayed re-verification.** On the next launch at least **24 hours** later, run the four-word quiz again against a **fresh** set of positions before treating the phrase as confirmed for good. This is the check a user cannot pass from working memory, and it is cheap because the phrase is re-displayable (§6.5). The 15-second dwell lock is a floor far below the 60–120 seconds a 24-word transcription takes, so the immediate quiz records a fact that may not be true.
>
> (c) **"Check my recovery phrase"** in Settings → Account: the full 24-word comparison, non-destructive, so a user can find a transcription error while the correct words are still on screen.

### 6.4 Never confirmed

A user who quits during onboarding after generation but before confirmation lands in a defined state, not a hole:

- The identity exists and works for reading.
- A persistent, non-dismissible banner at the top of the conversation list: **"Back up your recovery phrase"** / *"You have not written down the 24 words for this account. Without them, everything here is lost if this computer is."* / `[ Show my phrase ]`
- Per C-1, the composer is disabled with that same reason until confirmed.

### 6.5 Re-display from Settings

Settings → Account → **Show my recovery phrase**. Gated by Windows Hello (§6.6), then the same screen 4 with the same protections, then the same confirmation quiz on exit. There is no path in the product that shows the phrase without also asking the user to prove they have it.

**The data source is `RevealSeedphrase()` (Spec A §7.2.1).** A retains the 256-bit BIP39 **entropy** — not the words — sealed under DPAPI with its own context label for the life of the install, deleted only by `RemoveIdentity()`. The **words** are never persisted; C holds the rendered string only for the life of this screen and never writes it to `prefs.json`, the clipboard history, or the log.

State the consequence on this screen: the phrase is recoverable from this machine as long as the Windows profile is intact and the store is unlocked — which is exactly what Settings → Security concedes in `Sealer.Description()`'s own words, *"It does not protect against software running as you"*, and exactly what the optional PIN of §6.9 narrows.

### 6.6 Windows Hello gate (C-4)

`IUserConsentVerifierInterop::RequestVerificationForWindowAsync(hwnd, ...)` — the plain `UserConsentVerifier` static throws in a desktop app without the interop cast. Gate exactly these actions, and no others (a gate on everything is a gate on nothing):

1. Show the recovery phrase.
2. Accept a changed identity key (§7).
3. Remove a device from your own device list.
4. Leave a group, or transfer ownership of one you own.
5. Change or clear the PIN (§6.9). Setting one for the first time is not gated — there is nothing to authorise yet — but changing or removing an existing one is, because both weaken a protection that is already in force.
6. **Remove this identity from this computer** (§12, Account) — the one destructive action that can lose history.

When Hello is unavailable (`UserConsentVerifierAvailability` ≠ `Available`), the action proceeds behind a typed confirmation instead — the word `REMOVE` for 3 and 6, the contact's display name for 2, and the current PIN for 5 — never silently unlocked.

**There is deliberately no gate for accepting a changed message-server key**, because there is no such action any more: a key that chains to the pinned fleet root is applied silently, and one that does not is refused with no way to proceed (§7.6).

### 6.7 Restore (screens 6 and 7)

**Entry.** 24 fields in the same 4×6 grid, `UrMonoFontFamily`. Whole-phrase paste into any field splits on whitespace and fills all 24. Normalization before every check: NFKD, lowercase, collapse internal whitespace. Per-field state: neutral, in-list (subtle), not-in-list (`UrDangerBrush` underline + the field's supporting line, via `urnw::kit::ValidationState`).

Four distinguishable failures, because "invalid phrase" tells a user nothing:

| Condition | Message |
|---|---|
| One or more words not in the BIP39 list | "Word 12 (**apricott**) isn't one of the 2048 words. Check the spelling." |
| All 24 in the list, checksum fails | "All of these are real words, but the phrase's built-in check failed — one of them is in the wrong place or is the wrong word. Compare against what you wrote down." |
| Fewer than 24 filled | "You need all 24 words." — Continue stays disabled |
| A valid BIP39 phrase of the wrong length, or one deriving an identity the account has never published | "This looks like your URnetwork account phrase, not your URmessage recovery phrase. The URmessage phrase is 24 words made on your computer and never sent anywhere." |

Detect the wrong-length case **client-side before any network call**, and **never transmit or log** the entered words on that path. §6.1 goes out of its way to warn that the two phrases are different, and MASTER §5.1 confirms the operator receives the account phrase on every login — so a user retyping it here is retyping an operator-visible secret.

**Progress.** Seed-only restore (§5.4) derives `recovery_handle`, asks the server for archive records indexed under it, and unwraps per-group. Show it as work being done, per group, because it can take minutes:

```
Finding your groups…                        done — 6 found
Restoring "Design"          ████████░░      1,204 of 1,540 messages
Restoring "Ana"             ██████████      done
Restoring "Weekend"         —               waiting
```

**Outcomes.** Four, all rendered explicitly:

| Outcome | Screen |
|---|---|
| Full | "Restored 6 conversations." → conversation list |
| Partial | Lists which groups restored fully and which are missing history, with the reason from A (pruned media, missing archive wrap, epoch gap). "Some history could not be restored. The messages below the marker are all this server still has." |
| Nothing found | "This phrase is valid, but the server has no history stored for it. If you meant to start fresh, you can — this identity works." |
| **Restored, read-only** | §6.8 |

**A successful restore sets `phrase_confirmed_at`** — the user just typed all 24 words, which is a stronger proof than the §6.3 quiz — so the C-1 send gate does not fire on a restored device.

### 6.8 The read-only restore state — surface this, do not hide it

A user who kept the phrase but lost **every** device is in a state the master spec implies and does not name. `recovery_root` reconstructs the recovery key and `archive_secret[n]` decrypts history (§8.2). But **every MLS leaf signature key was generated on-device and is not seed-derivable (I2)**, so the restored device has no valid leaf and cannot sign a `PrivateMessage`. It can read; it cannot send, and it cannot self-service its own leaf because self-service requires a live leaf to commit from (§11).

The client must render this, per group:

> **You can read this conversation but not send to it yet.**
> Your recovery phrase brought back the history, but the devices that could send here are gone. An admin needs to add this computer back to the group.
> `[ Ask an admin ]` `[ What does this mean? ]`

**The second line branches on the group's shape**, because in two of the three shapes the current copy names a role the conversation does not have and `[ Ask an admin ]` has no target:

| Shape | Copy |
|---|---|
| **DM** | *"Ask Ana to add this computer back — open the conversation and she'll see the request."* There is no admin in a DM. |
| **Group with admins** | The copy above, unchanged. |
| **Group you own with no other admin** | *"No one else can add this computer back to this group."* → a §9.4-style "What's happening?" explainer. MASTER §11 makes device self-service require a live leaf and owner succession require a supermajority of current admins countersigning; a supermajority of zero is unobtainable. |

**Prevent it upstream.** In screen 14 (Group creation) and screen 15 (Group details), a non-blocking prompt when a group has an owner and zero admins — *"If you lose every device, only an admin can add you back. This group has none."* — with an inline **"Make someone an admin"** action.

If the user still has **one** live device elsewhere, the correct path is device provisioning (screen 8) from that device, and the client must say so — as a **live button** into screen 8's new-device half, not a sentence the user cannot act on: `[ I have another device signed in ]`, with the supporting line *"Linking from it is faster and doesn't need an admin."*

**Resolved against Spec A:** this state is `CanSend(groupId)` returning `MessageSendability{Allowed, Reason, ReasonDetail}` with `Reason == "no_leaf_after_restore"` — one value of A's closed sendability vocabulary, which also covers `observer`, `not_a_member`, `key_change_unresolved` and `fork_unresolved` (§9.3). C must never infer this from a send failing.

### 6.9 The PIN, and what it actually protects

A PIN is **optional**, and when set it is a real second factor rather than a screen over data the process has already unlocked: it wraps the key the local store is encrypted under (Spec A §8.6), so nothing can be read without it — not by this app, not by another program running as this user.

**Setting one** — Settings → Security → "Require a PIN to open URmessage":

> Choose a PIN. URmessage will ask for it when you open the app and after it's been idle.
>
> This is not just a screen lock: your saved messages are encrypted with a key this PIN unlocks, so nobody can read them from this computer without it — including anyone who copies the files.
>
> **If you forget it, the messages saved on this computer are gone.** Your 24 words still bring your history back from the server.
>
> `[ Set PIN ]` `[ Cancel ]`

Six digits minimum, no maximum, digits or characters. Entry is a password box; the PIN is never written to `prefs.json`, the log, or the clipboard, and is passed straight to the SDK.

**Auto-lock** — Settings → Security, a picker: 1 minute, 5 minutes, **15 minutes (default)**, 1 hour, Never. Plus **Lock now** in the Settings header and on `Ctrl+L`. Idle is measured from the last user input to this window, not from the last network event; a conversation left open on a second monitor still locks.

**While locked** (screen 26): a full-screen stop over the brand background showing the app name, the PIN field and nothing else. **No conversation names, no unread counts, no previews, no notification content** — a lock screen that lists who messaged you is a lock screen that leaks what it locks. Toasts raised while locked follow §10.3's locked-session rule and carry no content and no reply action.

**Messages still arrive while locked.** The session stays up and records are stored as received; they are decrypted for display on unlock. The client says so on the lock screen only if the user waits — *"New messages are still arriving. They'll be here when you unlock."* — because saying it immediately invites a user to leave the app locked as a privacy feature it is not.

**A wrong PIN** shows the delay it imposes rather than a bare rejection: after five consecutive failures the wait doubles each time to a minute, and the field shows the countdown. **There is no wipe-after-N-attempts**, deliberately: the PIN protects a cache and a seed the user may hold on paper, and a counter that destroys local history would do more damage than the attack it imagines.

**When no PIN is set**, there is no lock screen and Settings → Security says what does protect the store, in Spec A's own words (§12).

---

## 7. The key-change warning

### 7.1 Behaviour

| Rule | |
|---|---|
| Trigger | A resolution of a contact's `identity` key differs from the pinned one (§10.2). A contact with no pin never triggers it |
| Modality | **Blocking modal** over the conversation. Not a toast, not a banner, not an inline row alone |
| Effect while unresolved | See the scope block below. Incoming messages still arrive and are shown, flagged |
| Dismissal | "Not now" closes the modal and leaves sending disabled. The conversation shows a persistent bar with `[ Review ]` |
| Acceptance | Requires the Windows Hello gate (§6.6) or the typed-name fallback. Never a single click |
| Auto-accept | **Prohibited.** No timeout, no "trust on next launch", no setting that disables the warning |
| Record | Permanent, non-dismissible in-thread record in every shared group (§10.2) |

**Scope of the block:**

> **In a DM with the changed contact:** blocking modal, outbound sending to that conversation disabled until resolved.
>
> **In a group containing them:** a permanent, non-dismissible in-thread record plus a non-blocking bar. **Sending stays enabled**, because the changed key is not in the group's ratchet tree and cannot read anything sent there.
>
> **New blocking condition:** an `Add` committing a member whose identity key differs from a pin the user holds. This is blocking for that group, with its own permanent record, and its own copy: *"Bo was added to this group with a different safety number than the one you have seen."*
>
> This split is settled and is not to be widened. A blocking prompt in a 40-member group fires about people the user cannot verify and cannot act on, and the only thing it reliably teaches is that these prompts get dismissed — which costs the two places where blocking is right: a two-party conversation, and the moment a key you have seen before is committed into a group by someone else.

A carries the two cases as `KeyChangeWarning.Kind` ∈ {`"key_changed"`, `"member_added_with_changed_key"`}; the second carries `GroupId`.

**Batching.** **Two or more unresolved key changes collapse into one review sheet** listing each contact with its evidence row and per-contact `[ Compare ]` / `[ Accept ]`, with the per-contact modal reachable from it. A KT resync, an operator-side reset wave, or the user's own restore can surface several at once, and a stack of modals is dismissed reflexively — which is the precise failure §7 exists to prevent and which no amount of correct copy survives. The §7.4 permanent record stays per conversation.

### 7.2 Exact copy

Field values come from A. Nothing here is paraphrasable; it goes into the localization store as one block with a translator note (§8.5).

> ## The safety number for **Ana** changed
>
> The identity key for this conversation is not the one you saw before.
>
> This happens when someone reinstalls URmessage, sets up a new computer, or resets their account. It also happens when someone is trying to read this conversation.
>
> | | |
> |---|---|
> | You first saw the old key | **3 March 2026** |
> | The key changed | **11 August 2026, 09:14** |
> | Who asserted the change | **the URnetwork operator** |
> | Signed by the old key | **No** |
>
> Until you accept this, messages you send to Ana **here** will not be sent. You share **3 groups** with Ana; sending in those is unaffected — the key that changed cannot read them — and a permanent note has been added to each.
>
> The safest thing is to reach Ana some other way and compare safety numbers.
>
> `[ Compare safety numbers ]`  `[ Accept the new key ]`  `[ Not now ]`

Every row is a rendered datum from Spec A, never a claim C composes:

| Row | Source |
|---|---|
| You first saw the old key | `KeyChangeWarning.FirstSeenMs` (A joins it from `MessagePin` so C never fetches two objects for one modal) |
| The key changed | `KeyChangeWarning.ChangedAtMs` |
| Who asserted the change | `KeyChangeWarning.EvidenceClass` → §7.3 |
| Signed by the old key | `KeyChangeWarning.SignedByOldKey` (a **boolean**, never derived from the class name) |
| "…and in **3 groups you share**" | `len(KeyChangeWarning.SharedGroupIds)` |

**The accept call is `AcceptKeyChange(principal, newKeyFingerprint)`.** Passing the fingerprint is what prevents accepting a key that changed **again** between the modal opening and the click. On mismatch A returns an error and C re-opens the modal with the new evidence rather than accepting a key nobody saw.

### 7.3 The evidence lines are data

`evidence_class` comes from A (§5.5 of the master spec records it). Render one line per row; never invent a claim the evidence does not support.

| `evidence_class` | "Who asserted the change" | "Signed by the old key" |
|---|---|---|
| `kt_inclusion` | the key transparency log | **No** |
| `operator_assertion` | the URnetwork operator | **No** |
| `operator_reset` | the URnetwork operator, after an account reset | **No** |
| `kt_unavailable` | *nobody — the transparency log could not be reached* | **No** |
| `out_of_band` | *you got this key from them directly* | **No** |
| `unknown` | *unknown* | **Unknown** |

The "Signed by the old key" cell renders `KeyChangeWarning.SignedByOldKey`, never the class name. No row gets a softening sentence in v1.

**`out_of_band` is the strongest row in this table, not the weakest.** It is the class a key carries when it came from a contact card the other person handed over (§12.7) rather than from any directory, and the copy says so plainly instead of dressing it as a missing-log warning. `kt_unavailable` is a different statement — the log could not be reached, or the identity has never been listed and therefore has no log leaf at all — and the two are never collapsed into one row, because folding the best provenance in the product into the weakest is a lie in the direction that costs a user something.

**A directory lookup with no reachable log still opens a conversation, and says so.** Spec A distinguishes a resolution answered with a proof that does not verify — which fails closed, starts nothing, and is the event this whole mechanism exists to catch — from a resolution made when no log was reachable at all, which proceeds and carries `kt_unavailable`. The client renders the second as its own row here, on the contact sheet and on the key-change sheet, rather than as an error or as nothing: until the transparency log is live every lookup lands in that state, and a lookup that refused to proceed would leave the product with no way to start a conversation at all. Screen 13's `KT-proof-failed` state is the first case and offers no way through; its `log-unavailable` state is the second and continues with the row shown.

**There is no self-signed-rotation row in v1.** `identity` is derived from the seedphrase and nothing else (MASTER §5.2), so a reinstall or a new computer from the same phrase produces the **same** key and raises no warning at all. The only v1 path to a changed key is a MASTER §5.5 operator reset. Claiming "Ana's old key signed this change" for a mechanism that does not exist would be a false security claim in the one screen where accuracy matters most. The identifier `self_signed_rotation` is reserved in Spec A for V2 and is never emitted.

### 7.4 The permanent record

Written into every shared conversation, non-dismissible, `UrDangerBrush` left rule at 2px. The unaccepted copy differs by conversation type, matching §7.1's scope:

Unaccepted, **in the DM**:
> **Ana's safety number changed on 11 August 2026.** You have not accepted it. Messages you send here are not being sent. `[ Review ]`

Unaccepted, **in a shared group**:
> **Ana's safety number changed on 11 August 2026.** You have not accepted it. Sending here still works — the key that changed cannot read this group. `[ Review ]`

Accepted (both):
> **Ana's safety number changed on 11 August 2026, and you accepted it on 11 August 2026.**

Added to this group with an unrecognised key (§7.1's new blocking condition), permanent, and blocking for **that group**:
> **Bo was added to this group with a different safety number than the one you have seen.** `[ Review ]`

### 7.5 Prohibited

- The word "verified" anywhere outside a safety-number comparison the user performed.
- Any badge, tick, shield or colour that marks a contact as trusted (W8).
- `kProGold` on this screen or any security surface. It means "Pro" and nothing else.
- A settings toggle that suppresses these warnings.
- Showing this warning for a contact with no prior pin. A first sighting is not a change (§10.2).
- Any claim that a key change was signed by the previous key, in v1.
- Blocking a group's sending on a key change that is not one of the two conditions in §7.1.

### 7.6 The message server's key is verified, not accepted

**There is no modal here, in either direction.** `URmessageSdk.dll` carries the fleet's root public key compiled in and verifies the message server's signing key against it on first contact and on every rotation (Spec A §7.6). The client's job is to render two outcomes and offer a decision in neither:

**A rotation that verifies is silent.** No banner, no prompt, no interruption. It is written to the Security log (screen 29) as one line — *"Message server key rotated — 11 August 2026, 09:14"* — with the range of history checks it invalidated named beneath it, because `FetchAttestation`s signed under the outgoing key are discarded rather than trusted:

> Checks that the server didn't leave messages out can no longer be verified for messages before **11 August 2026**.

**A key that does not verify stops the connection.** The client does not sync, does not send, and offers no way to proceed. Health state is `server_key_untrusted` and the banner is:

> **URmessage can't verify this message server.**
> The key it's presenting isn't one this app can trace back to the key built into it. That is what an impersonated server looks like, and it is also what a misconfigured one looks like. Either way, nothing is sent or fetched until it verifies.
> `[ Try again ]` `[ What's happening? ]`

**Why there is no "accept anyway".** The previous design showed an app-wide blocking modal with an accept button, which asked every user to adjudicate a cryptographic question at the exact moment its answer mattered most, and for which the correct answer was always "do not proceed". A button whose only correct use is not pressing it is a button that gets pressed. With the root pinned, the correct behaviour is enforced by the SDK instead of requested from the user, and the legitimate operation the old modal made unusable — rotating a compromised key — is now silent and auditable.

`[ What's happening? ]` says the true thing without alarm:

> URmessage recognises this server by a key that was built into the app when you installed it. The server can present a new key as long as the old one vouches for it, and that happens silently. What it can't do is present a key with nothing vouching for it, which is what's happening now.
>
> This doesn't mean anyone read your messages. The server can't read them either way. It means the app can't currently tell whether it's talking to the same server as before.

---

## 8. Required UI language

### 8.1 Verbatim strings from master §12.4

These are **normative in the master spec** and must appear character-for-character in the English store. A CI lint (§16.3 lint 1) fails the build if the key is missing or the English value drifts. The comparison is **by codepoint sequence**, after collapsing runs of whitespace on both sides — MASTER §12.4 is hard-wrapped, so a literal comparison fails on the line break even when the strings are identical, and that spurious failure would mask a real corruption.

| Key | String | Where it appears |
|---|---|---|
| `msg_disappearing_explainer` | "After the timer, this message can no longer be read by anyone — the key is destroyed on every device and on the server." | On the sheet that turns disappearing messages on, and in the first system record when a timer is set in a conversation |
| `msg_delete_for_everyone_explainer` | "Removed from this conversation on every device that is online and honest. Anyone who already read it may have kept a copy, and we cannot detect that." | On the Delete-for-everyone confirmation, before the destructive button |
| `msg_durable_default_explainer` | "Messages are kept so your new devices can see your history. That means the server holds a copy until it's deleted or expires." | Settings → Privacy & retention, at the top; and once during onboarding on the first conversation |
| `msg_delete_window_explainer` | "Messages can only be removed for everyone within 24 hours of sending." | On the Delete-for-everyone item when it is unavailable, and in the confirmation for one that is |
| `msg_expired_fact_explainer` | "The content disappears, the fact of the message does not." | On the sheet that turns disappearing messages on, and beneath the first expired-message placeholder in any conversation |

Both new keys are normative in MASTER §12.4 and are covered by the same codepoint comparison and the same translator note as the three above.

**Prohibited across the whole string store:** "gone forever", "deleted forever", "permanently deleted", "erased forever", "nobody can ever see this" — anywhere they could attach to the `DURABLE` class. Master §12.4: *"Never say 'gone forever' for the durable class."* The lint checks for these substrings and allowlists only the ephemeral-context keys. The substring check is **English only**; the other 27 locales are covered by the process gate in §16.3 lint 2, because an English substring list run against a translated store is vacuous while reporting green.

### 8.2 Delete for me (C-9 — signed off)

Master §12.4 does not cover it, and the honest thing must be said:

> **Delete for me**
> Removed from this computer only. Your other devices still have it, everyone else still has it, and the server still has its copy until it expires.
> `[ Cancel ]` `[ Delete for me ]`

**Delete for everyone is available for 24 hours.** Inside the window the context menu offers it on the user's own messages, with `msg_delete_for_everyone_explainer` above the destructive button. Outside it, the item is **absent, not greyed** (§15's rule), and the message's context menu carries one muted line instead:

> *Messages can only be removed for everyone within 24 hours of sending.*

A deleted message leaves a placeholder in the timeline reading *"This message was deleted."* — the row never disappears, in any conversation, for anyone. An unbounded silent retraction would let someone rewrite a years-old shared conversation with nobody able to see that they had.

### 8.3 Disappearing messages, on by choice

Off by default (ledger T6). The sheet that turns them on shows `msg_disappearing_explainer` above the bucket picker, and a second line about attachments (§12.2 of the master spec: an attachment on an ephemeral parent inherits the parent's key class):

> Photos and files sent here disappear with the message.

Buckets, per C-8:

| Bucket | Label |
|---|---|
| 1 | 1 hour |
| 2 | 8 hours |
| 3 | 1 day |
| 4 | 1 week |
| 5 | 4 weeks |

Saving an ephemeral attachment to disk shows a one-time confirmation, because the product otherwise implies the file will vanish from the user's own disk:

> Saving this keeps it after the timer. The copy on your disk is yours to manage — URmessage cannot delete it.

**A timer change applies from now on.** The sheet says so above the picker, and the system record that lands in the thread says it again:

> This applies to messages sent from now on. Messages already in this conversation keep the setting they were sent with.

This is not a product choice that could have gone the other way. A message already sent is encrypted under the key class it was sealed with, and re-classing it afterwards would be a promise about every client behaving, not a guarantee about keys — which is the distinction the whole disappearing feature rests on.

**What an expired message leaves.** The bubble is replaced by a centred muted line, in its original place in the conversation, with the original time and **no sender name**:

> *A message here expired. `msg_expired_fact_explainer`*

The sender is absent because the server no longer holds it either (Spec B §7.2). The required sentence is shown beneath the first such placeholder in a conversation, so a user learns once what the row means rather than being told nothing or told it every time.

### 8.4 Retention negotiation (C-5 — RULED, warn and proceed, both directions)

MASTER §15 item 1 rules warn-and-proceed in **both** directions: the server floors up or clamps down, accepts the commit, and returns `REASON_RETENTION_CLAMPED` with a `RetentionApplied`. The client warns and proceeds, and **shows the effective policy, not the requested one**:

This server publishes three limits, and a group's settings are fitted inside all three. Each notice names the **effective** value, never the requested one, and every number is formatted from `ServerInfo()` and `GroupEvent.RetentionApplied` — Spec A's `MessageRetentionApplied`, whose values are **seconds** and must be formatted here (§16.3 lint 6):

> **Text kept longer than this server allows:**
> *"This server keeps messages for at most **1 year**. Your setting of 3 years can't be applied here — the group's messages will be kept for **1 year**."* `[ Use 1 year ]` `[ Cancel ]`
>
> **Text kept shorter than this server allows:**
> *"This server keeps messages for at least **30 days**. Your setting of 7 days can't be applied here — the group's messages will be kept for **30 days**."* `[ Use 30 days ]` `[ Cancel ]`
>
> **Photos and files kept longer than this server allows:**
> *"This server keeps photos and files for at most **30 days**. Your setting of 90 days can't be applied here — they will be kept for **30 days**."* `[ Use 30 days ]` `[ Cancel ]`
>
> `MessageRetentionApplied.DurableTtlSeconds` is what the server **actually stored**. `4294967295` means indefinite and renders as *"kept until you delete them"*, never as a number of days, and it is only reachable on a server that publishes no text cap. `0` never appears in an applied value, because "the group set nothing" is a request and not an outcome. The group's own transcript-covered policy is unchanged in every case, so this is a notice, not a failure.
>
> **A default is not a clamp, and the two get different sentences.** When `DurableDefaulted` is true the group sent no text policy at all and the server supplied its own: *"This group keeps messages for **1 year** — that's this server's default."* When the group asked for longer and was clamped, the copy is the first notice above. Rendering both as a clamp tells a group it lost an argument it never had.

**The default for text is one year, not forever**, and the group sheet shows it as the starting value rather than as an empty field meaning "keep everything". Where the server does not permit groups to raise it (`ServerInfo().GroupDurableOverride == false`), the control is **absent** and one line stands in its place: *"This server keeps messages for **1 year** and groups can't change it."* A disabled control that silently does nothing is worse than no control.

### 8.5 Localization

Strings live in the shared store (`@urnetwork/localizations`, `npm run gen` → `Strings/<locale>/Resources.resw`, read through `urnw::Localized` / `Format` / `Plural`). 28 locales ship today and the VPN app already carries 916 English keys of which only 248 are used — **the string you need may already exist**; check before adding.

Three rules for this product's strings:

1. The §8.1 strings carry a translator note: *"Legal/security-critical. Translate meaning exactly. Do not soften, shorten, or add reassurance."*
2. Never build a security sentence by concatenating fragments — translations reorder, and a reordered warning can invert.
3. Every count uses `Plural()` with a CLDR rule, never `"%d messages"`.

---

## 9. Empty, error, offline, and unreachable

### 9.1 Empty states

Use `urnw::kit::MakeEmptyState(glyph, text)` — a large muted Segoe Fluent glyph over one sentence, centred. The header comment on that function records why it exists: a bare "–" cannot distinguish *nothing* from *not loaded* from *failed*, and both shipped in the VPN app. Never a bare dash, never an empty panel.

Also use `urnw::kit::SetTextOrCollapse` for every conditional line. A `StackPanel` gives every child its `Spacing` whether or not the child drew anything; four empty `TextBlock`s cost ~120px of blank card in the middle of a panel, indistinguishable from a broken layout.

| Where | Glyph | Sentence |
|---|---|---|
| Conversation list, no conversations | speech bubble | "No conversations yet. Start one to see it here." |
| Conversation list, search no match | search | "Nothing matches "kepler"." |
| Thread, no messages | speech bubble | "This is the beginning of your conversation with Ana." |
| Thread, joined mid-history | history | "You joined here. Messages sent before this aren't available to you." |
| Group members, only you | person | "It's just you here. Invite someone." |
| My devices, one device | laptop | "This is your only device." |
| Attachments in details rail | image | "No photos or files here yet." |
| Directory search, no query | search | "Search for someone by their URnetwork name." |
| Invitations, none (screen 23) | envelope | "No pending invitations." |
| Search in conversation, no match | search | "Nothing in this conversation matches "kepler"." |
| Group you own with no other admin (§6.8) | shield | "If you lose every device, only an admin can add you back. This group has none." + `[ Make someone an admin ]` |

### 9.2 The health state machine

`Common/MessageHealth.h` — pure, no WinRT, no I/O, unit-testable, with a **selftest-pinned transition table**, exactly as `Common/ConnectionHealth.h` is.

| State | Meaning | UI |
|---|---|---|
| `NoAccount` | No URnetwork account / `ByJwt` (§4.4) | Sign-in screen |
| `Offline` | No network on the machine | Banner: "You're offline." Composer works; sends queue |
| `Connecting` | Transport coming up | Thin indeterminate bar in the title area only. **No banner for the first 5 seconds** |
| `Reachable` | Session up, server responding | No chrome at all |
| `Degraded` | Session up, fetches slow or partially failing | Banner: "Messages are arriving slowly." Sends still attempted |
| `ServerUnreachable` | Server has failed the reachability rule (§9.4) | Banner, §9.4 copy |
| `Blocked` | An unresolved contact key change, a message server whose key does not verify, or a read authorization that has aged out | Banner + the modal (§7.1) for a contact; §7.6's banner and no modal for the server; §9.8's copy for the read authorization |
| `StoreUnavailable` | A could not open the local store: `unseal_failed`, `corrupt`, `disk_full`, `locked_by_another_process` | Not a banner. A full-screen stop (screen 25) |
| `Locked` | The local store is PIN-locked (§6.9) | **Not a banner.** The full-screen lock, screen 26 |
| `OutOfCredit` | The URnetwork account has no data allowance left | Banner + §9.9 |

`StoreUnavailable`'s copy:

> **This computer can no longer open your saved messages.**
> Nothing has been sent anywhere and nothing is lost on the server. Restore with your 24-word recovery phrase to get your history back on this computer.
> `[ Restore from my phrase ]` `[ Copy diagnostic ]`

A DPAPI unseal failure is not exotic — it is what a Windows profile reset, a domain account migration, or a restore of `%LOCALAPPDATA%` onto a different machine produces, and the file is present so nothing looks "empty". With no state defined, the app would do the one thing §14.2 requirement 1 forbids and show *"No conversations yet. Start one to see it here."* to a user whose entire history is intact on the server.

**The derivation, so the transition table is testable.** Every one of the ten states is a **pure function of `SyncState`** (Spec A §7.2): `TokenState` → `no_account`; `MachineOnline == false` → `offline`; `Transport == "connecting"` → `connecting`; `StoreState != "ok"` → `store_unavailable` or `locked`; `BlockedReason != "none"` → `blocked` or `out_of_credit`; `ConsecutiveFetchFailures ≥ 3 && now − LastSuccessMs ≥ 20 s && MachineOnline && now − LastRecordReceivedMs ≥ window` → `server_unreachable`; some-but-not-all failures → `degraded`; otherwise `reachable`. The carrying veto is `LastRecordReceivedMs`; the tick-gap rebase is `EvaluatedAtMs`. Both come from A, not from a getter that can block on a lock the data path never touches (VPN defect F1).

Two states are evaluated before all others because they make the rest meaningless: `store_unavailable` and `locked`. `SyncState.StoreState` carries `"locked"` alongside its existing values, and `BlockedReason` carries `read_authorization_expired`, `out_of_credit` and `server_key_untrusted`. Every one of the ten states remains a pure function of `SyncState`, and the selftest table grows two rows rather than acquiring a special case.

**Token expiry** maps to `no_account` with reason `token_expired`; no eleventh state is added. Queued sends survive it — the outbox is A's and is not torn down. The user sees the sign-in screen with *"Sign in again to keep sending."*

Rules taken from the VPN client's hard-won experience with this exact pattern:

- **Hysteresis is one-sided.** Entering a worse state takes 7 seconds of evidence; leaving it is immediate. A messenger that flashes "offline" on a 300 ms hiccup is worse than one that is 7 seconds late to say so.
- **Measure the evaluator's own tick gap.** Windows 11 Modern Standby freezes threads while `steady_clock` advances; a laptop closed overnight will otherwise resume straight into `ServerUnreachable`. If a tick arrives ≥5× late, rebase the session rather than judging it. This is defect F2 from the VPN watchdog, and it will recur here verbatim.
- **A carrying veto.** If any record was received within the window, the state cannot be worse than `Degraded`, regardless of what a getter says. F1 in the VPN client was a watchdog judging the SDK's health by a call that blocked on a lock the data path never touches.

### 9.3 Send failures

Every failure gets a reason and an action. Never a bare code, never a silent retry that never ends.

This table **cites** Spec A's closed send-failure vocabulary; it does not restate it. A value not in A's vocabulary is a build failure, not a new row here.

| Reason from A | Row copy | Action |
|---|---|---|
| `offline` | "Waiting for a connection" | auto, no button |
| `server_unreachable` | "Waiting for the message server" | auto |
| `key_change_unresolved` | "Blocked — Ana's safety number changed" | `[ Review ]` |
| `not_a_member` | "You're not in this group any more" | none |
| `observer` | "You can read this group but not send to it" | none |
| `no_leaf_after_restore` | "This computer needs to be added back to the group" | `[ Ask an admin ]` (§6.8 branches the button by group shape) |
| `phrase_not_confirmed` | "Write down your recovery phrase before you send your first message" | `[ Show my phrase ]` |
| `store_unavailable` | *(nothing here — §9.2's full-screen stop, screen 25, has already taken over)* | blocking |
| `group_closed` | "This group has been closed on the server" | none |
| `epoch_incomplete` | "Setting up the new group key…" | auto, no button |
| `too_large` | "That file is larger than this server accepts (**{cap}**)" | `[ Choose another ]` |
| `blob_incomplete` | "That file didn't finish uploading" | `[ Try again ]` |
| `rate_limited` | "Too many messages just now — retrying in **{RetryAfterMs}**" | auto |
| `oversize` | "That message is larger than this server accepts" | `[ Edit ]` |
| `quota_exceeded` | "This group has used all its storage on this server" | none |
| `internal` | "The message server couldn't accept this" | `[ Try again ]` |
| `fork_unresolved` | §9.5 | blocking |
| `locked` | *(nothing here — §6.9's lock screen has already taken over)* | blocking |
| `read_authorization_expired` | "This computer has been away too long to read this conversation" | `[ What can I do? ]` → §9.8 |
| `out_of_credit` | "Your URnetwork data allowance is used up" | `[ Add credit ]` → §9.9 |
| `delete_window_expired` | "Messages can only be removed for everyone within 24 hours" | none |

**Not values, and therefore not rows.** `commit_lost` — A retries internally and never surfaces it (see below). `retention_refused` — **deleted**; retention is warn-and-proceed in both directions (§8.4), so there is no send failure to render.

**`commit_lost` is invisible.** §9.3 of the master spec: the server accepts one commit per `(group_id, epoch)`, first valid wins, and returns the winner so the loser re-derives and retries. That is a normal race, several times a second in a busy group. It must never surface as an error, a spinner, or a re-ordered message. A user changing a group name at the same moment as someone else sees their change apply a beat later, and nothing else.

### 9.4 When the single server is unreachable

v1 has one message server (ledger T1) and, if it is lost, the groups are lost (ledger T3, MASTER §13). The client must not pretend a temporary outage is permanent, nor imply a permanent loss is temporary.

**The rule:** `ServerUnreachable` requires ≥3 consecutive failed fetch/send attempts spanning ≥20 seconds, with the machine online, *and* no record received in that window. This survives the VPN tunnel's `Connecting` starvation window (§0.3) without calling a slow server a dead one.

**Under 2 minutes** — a thin banner above the conversation list, no modal, composer fully enabled:

> Can't reach the message server. Messages you send will go out when it's back.

**Over 2 minutes** — the banner expands with a timestamp and a manual retry:

> **Can't reach the message server** — last contact 09:14, 6 minutes ago.
> You can keep reading and keep writing. Anything you send is held on this computer until the server answers.
> `[ Try again ]` `[ What's happening? ]`

**"What's happening?"** — a sheet that tells the truth from §13 without alarming a user during a 10-minute outage:

> URmessage v1 uses a single message server. While it's unreachable, nothing new arrives and nothing you send goes out. Everything already on this computer stays readable.
>
> Your messages are not readable by that server — that doesn't change whether it's up or down.
>
> Being able to choose or move between servers is planned for a later version.

**The outbox has a bound.** After 500 queued records or 7 days, the oldest queued items stop retrying and are shown as failed with `[ Retry ]`, rather than growing without limit and retrying forever.

### 9.5 Fork detection — resync first, stop only if that fails

§8.1 / §9.3: MLS gives fork *detection*. A mismatch means this client's view of the group and someone else's have diverged — and a server fault produces exactly the same signal as an attack, so a client that stops on detection hands one bad deploy the power to silence a group until every member individually clicks a button.

**So the client resyncs first, silently, and keeps sending.** While `IntegrityEvent{Kind: "fork_resyncing"}` is outstanding, the conversation shows a thin non-blocking line above the composer — *"Checking this conversation…"* — and nothing else changes. Three attempts, backing off.

**Only when resync fails** does the hard stop appear, unchanged in weight because a genuine fork is exactly what survives a refetch:

> ## This conversation could not be verified
>
> URmessage checks that everyone in **Design** is seeing the same history. That check failed, and trying again didn't fix it — which means your copy and someone else's have gone out of step.
>
> This can happen after a server problem. It can also happen if records were changed or withheld.
>
> Sending here is stopped until it's resolved. Nothing already on this computer is lost.
>
> `[ Try to resync ]`  `[ Copy diagnostic ]`

`[ Copy diagnostic ]` copies group id (8-hex truncated), epoch, both transcript hashes, the number of automatic attempts made, and the app version. No content, no names.

The security property is unchanged: a genuine fork still stops sending. What is removed is a self-inflicted outage on the day a deploy goes wrong.

### 9.6 Fetch attestation gap

§9.4: clients retain `FETCH_ATTESTATION`s over their high-water range and warn when a later-learned record falls inside a covering attestation that omitted it. Not blocking — the server may be misbehaving or may have raced — but permanent and in-thread:

> **A message dated 3 March arrived late, and an earlier check from this server said it wasn't there.**
> That can be a server fault. It can also mean the server held it back. URmessage records this so it can't happen quietly.

Attestations are compared only within an identical `(class_mask, heads_only)` filter — a filtered fetch is not a withholding one, and comparing across filters manufactures false warnings.

**A verified server-key rotation writes one line into the Security log** (screen 29) marking the boundary, and every attestation signed under the outgoing key is **discarded**, not silently trusted. `IntegrityEvent.CoveredSinceRecordId`…`CoveredUntilRecordId` is the range that stops being verifiable, and it is what that log line names. There is no modal and no user decision: the rotation was verified against the key built into the app, and the only thing left to do is record what it cost.

### 9.7 Media pruned by policy ≠ download failed

Master §12.2 prunes `MEDIA` on the group's media TTL. The client does not infer any of this from a failed download — it renders **`MessageAttachment.State`**, an explicit enumerable value from A:

| `MessageAttachment.State` | Rendered |
|---|---|
| `not_downloaded` | The file card with `[ Download ]`, size shown |
| `downloading` | The file card with a determinate progress ring bound to `DownloadProgress`, and a cancel |
| `pruned` | An inline card, muted, **no retry**: "Photo — no longer available. Photos and files on this server are kept for **{media_ttl}**." |
| `failed` | An inline card with `[ Try again ]`: "Couldn't download this photo." |
| `expired` | "This message is no longer readable. The key was destroyed on 11 August." — **never** "failed" |

`{media_ttl}` is formatted from `ServerInfo()`, never a literal (§14.2 requirement 7, §16.3 lint 6). Calling `pruned` and `failed` the same thing is the difference between a working product and a broken-looking one.

### 9.8 When this computer has been away too long

The message server keeps each group's read authorization for the window it advertises as `ServerInfo().ReadKeyWindowMs` — ninety days on a stock server. That window is what lets someone close a laptop for a season and come back, and it is also what finally cuts off a member who was removed. A device that has been away longer than the window holds only keys the server has discarded, and its reads are refused.

This is a named state, never a generic failure. Spec A reports sendability reason `read_authorization_expired`, and the conversation shows:

> **This computer has been away too long to open this conversation.**
> The message server stops recognising a device after **{read_key_window}** offline. Nothing is lost — your history is still on the server and still encrypted to you.
> `[ Link from another computer ]` `[ Restore from my phrase ]` `[ What's happening? ]`

`{read_key_window}` is formatted from `ServerInfo().ReadKeyWindowMs` and never written as a literal (§16.3 lint 6). While `ServerInfo().Advertised == false` the duration is not known, so the banner drops it entirely and reads *"The message server stops recognising a device that has been offline too long."* — an unadvertised window is a number this client does not have, and inventing one would be a claim about how long a user may be away.

Both buttons are live paths, not suggestions. `[ Link from another computer ]` opens screen 8's new-device half, which is the faster route if the user still has a signed-in machine. `[ Restore from my phrase ]` opens screen 6, which always works: seed-only restore is authorised by the recovery proof rather than by a read key, so the 90-day window does not apply to it.

`[ What's happening? ]`:

> URmessage asks the server for your messages with a key that changes as the group changes. The server keeps each of those keys for **{read_key_window}** so you can come back after being away. Past that, it stops recognising them — which is also how someone removed from a group eventually stops being able to see even that messages are being sent.

The last sentence is there on purpose: this is a cost the user is paying for a property that protects them, and saying so is cheaper than letting them conclude the app is broken.

### 9.9 When the data allowance runs out

URmessage sends through the user's own URnetwork data allowance — a free daily figure no amount of text will exhaust — and it does not sell data, set prices, or contain a purchase flow. Operators price data; this app spends it and can redeem a code against it. The figure itself is `Balance().FreeAllowanceBytesPerDay`, formatted at render time and never written as a literal (§16.3 lint 6).

`Balance().State == "exhausted"` gives health state `OutOfCredit`, a banner above the conversation list, and a composer that queues rather than sends:

> **Your URnetwork data allowance is used up.** Messages you write are held on this computer until there's credit again.
> `[ Add credit ]` `[ Redeem a code ]` `[ What's happening? ]`

`[ Add credit ]` opens the URnetwork website in the default browser — this app has no checkout and must not grow one. `[ Redeem a code ]` opens screen 27. `[ What's happening? ]`:

> Messaging uses the same URnetwork data allowance as everything else on your account, and the free allowance is **{free_allowance}** a day — far more than messages need. If it's gone, something else on this account used it. Add credit from the URnetwork website, app or VPN client, or redeem a code if you have one.

`{free_allowance}` is formatted from `Balance().FreeAllowanceBytesPerDay`. When that value is unknown the sentence drops the figure entirely — an operator sets this number and may change it, and a client that prints a literal is stating someone else's pricing decision as a fact about the product.

`"low"` shows the same banner in a muted, dismissible form. `"unknown"` shows nothing at all: the client has not reached the account API yet, and inventing a number there would be worse than silence.

### 9.10 When you are about to lose a group you own

A group's owner who stops using the app can be replaced by its admins after ninety days of silence (MASTER §11). That mechanism exists to rescue a group from an owner who is gone, and the thing that keeps it from displacing an owner who is merely busy is that the owner is warned, repeatedly, on every machine they use, and that any single message resets the clock.

The warnings are driven by `Succession(groupId)` — `MessageSuccessionState.IAmTheOwner` and `.OwnerWarningStage` — and the stage is computed from group state rather than from a per-device flag, which is what makes "on every device" true without any device having to coordinate with another. The successor's name comes from `.SuccessorDisplayName` and the date from `.EligibleAtMs`.

| Stage | Surface | Copy |
|---|---|---|
| 30 days | An in-thread system row, in that group | *"You haven't posted here for 30 days. If that reaches 90, Bo can take over this group with most admins' agreement."* |
| 60 days | The same row again | *"You haven't posted here for 60 days. Bo can take over this group in 30 days unless you post."* |
| 75 days | A **non-dismissible** banner above the composer, `UrCardBrush` with a `UrBorderStrongBrush` top edge | *"Bo can take over this group on 3 March. Anything you post here stops it."* `[ Turn this off ]` |
| 85 days | A **modal**, once per device per stage, on next launch or next focus of that conversation | *"Bo can take over **Design** on 3 March. Sending any message here stops it. If you'd rather this never happened, you can turn succession off for this group."* `[ Post now ]` `[ Turn succession off ]` `[ Not now ]` |

`[ Turn this off ]` and `[ Turn succession off ]` both call `SetSuccessionEnabled(groupId, false)` and both state the consequence before committing: *"If you stop using this account, nobody will be able to take this group over and it can't be administered again."* That is the owner's decision to make and the screen makes it with the cost visible.

None of these surfaces appears on a client where the local identity is not the owner. An admin sees the group's countdown on screen 30 and nothing in the thread: a warning aimed at the owner, rendered to everyone else, is a countdown to a coup posted publicly.

---

## 10. Notifications

### 10.1 Local toasts (v1, unconditional)

`Microsoft.Windows.AppNotifications.AppNotificationManager`, from the Windows App SDK. The VPN app does not use it today — the API surface is present via WASDK 2.2 but there are no call sites in `app/src` — so this is new code, and unpackaged apps need COM activation registered (`AppNotificationManager::Default().Register()` with a display name and icon, at startup, before the window shows).

| Property | Value |
|---|---|
| Group | `conversation:<group_id_8hex>` |
| Tag | `record:<record_id>` |
| Payload | Built from already-decrypted local state. **A notification is never built from an incoming payload** |
| Activation | Deep-links via `urmessage://c/<group_id>` to the conversation, scrolled to the record |
| Actions | Reply (inline text box), Mark read |
| Coalescing | One toast per conversation; subsequent messages update it in place with a count |
| Muted conversations | Never raise one |
| Own messages from another of your devices | Never raise one |
| Delivery receipts | Emitted by the SDK when a record is decrypted, including when the app is in the tray and no toast is raised. The client does not gate them on the window being visible — a message decrypted is a message delivered, and pretending otherwise to look better would be the server guess this product refuses to make |

**Revocation is a security requirement, not a nicety.** A toast that outlives its message defeats §12.1's guarantees at the shell layer. `RemoveByTagAsync` / `RemoveByGroupAsync` on:

- the message being read on this or any device;
- a `TOMBSTONE` arriving for it — a delete-for-everyone inside its 24-hour window (§8.2), which the `"tombstoned"` lifecycle kind already covers and which is named here so the case is not rediscovered;
- **an ephemeral message's timer expiring** — the key is destroyed on every device and on the server, and the Action Center copy must go with it;
- the app being signed out.

**All four are driven by A's client-wide `AddRecordLifecycleListener`**, delivering `RecordLifecycleEvent{Kind, GroupId, MessageId, Seq, Dropped}` with `Kind ∈ {"expired", "tombstoned", "read_elsewhere"}`. It is client-wide by name and by design: A raises it for **every** expiring record from the expiry sweep, regardless of whether any group listener is attached. A per-group listener would leave a toast for a conversation the user never opened this session sitting in the Action Center past its key's death — which is exactly the failure this rule exists to prevent.

### 10.2 WNS push (C-6)

MASTER §15 item 2: *"No push exists in any operator today."* **The beta ships without push**, and a working contentless wake is a general-availability gate. This spec defines the client half and its constraints so that the operator and server work can land against a fixed contract.

| | |
|---|---|
| Mechanism | `PushNotificationManager` (WASDK). For an unpackaged app this requires an Azure AD application registration and delivers a channel URI the client registers with the message server through A |
| Payload | **Contentless.** A wake signal, optionally carrying a group id **hashed under a per-install key** so the operator/Microsoft path cannot correlate it. No sender, no preview, no plaintext group id, no count |
| Behaviour | The push COM-activates the app if stopped; the app fetches from the server, decrypts locally, and raises a **local** toast (§10.1) with real content |
| Why contentless | WNS is Microsoft's infrastructure. Anything in the push payload has been handed to a third party. §4.2's operator boundary would mean nothing if the notification carried the message |
| Beta behaviour | The beta has no push, so the app delivers notifications only while running. Settings offers "Start URmessage when I sign in" with the plain reason: *"URmessage can only notify you while it's running."* |
| Owner | The **Azure AD application registration** needs a named owner. It is not in any of the three specs' schedules and is the long pole on this row (C-6, MASTER §15 item 2) |
| On restore | A restored device generates a **new** per-install hash key and a new channel. The old registration is explicitly unregistered via `UnregisterPushChannel()` if the device is still reachable, and otherwise expires |

### 10.3 Lock screen

Windows shows toast content on the lock screen when the user has enabled it system-wide; the app cannot force it off per-notification. So the app controls what it puts in the toast at all.

**Setting: "What notifications show" —** Settings → Notifications. The default is **Name only**, for every conversation, and it is the position this product recommends rather than a middle option between two equal ones:

| Position | Toast |
|---|---|
| **Name only** *(default)* | "**Ana** — new message" |
| Nothing | "**URmessage** — new message" |

**A message preview is opted into one conversation at a time**, not switched on globally. Screen 15 (and the conversation's own overflow menu) carries **"Show message previews in notifications"**, off by default, writing `SetGroupNotificationMode(groupId, "name_and_message")`. There is no global position that turns previews on everywhere: a lock screen showing the content of every conversation is a decision people make once, in a settings screen, and regret in a specific conversation they were not thinking about at the time.

The per-conversation control also reaches **Nothing**, so one conversation can be silenced further without changing the rest. Mute is separate and is `SetGroupMuted(groupId, muted)` (§12).

Directly under the global setting, the honest sentence:

> Windows decides whether notifications appear on your lock screen. URmessage decides what's in them.

**Fixed regardless of setting:** disappearing-message notifications **never** include content, at any setting, because the toast is a copy of the message living outside the key's lifetime. They read "**Ana** — new message".

**Inline reply and Mark read are omitted from the toast whenever the session is locked** (`WTSRegisterSessionNotification` / `SessionSwitch`; rebuild or suppress the actions on lock). An `AppNotificationManager` toast with an inline text box remains actionable on the lock screen, so without this anyone with physical access could **send a message as the user** without signing in — and could do it with the "Nothing" setting active, since that setting suppresses content, not the reply affordance. "Mark read" has the same shape: an unauthenticated action with a visible effect on someone else's read receipts.

---

## 11. Brand

### 11.1 Source of truth

`github.com/urnetwork/elements` `src/index.css` defines the tokens; `app/src/App/UrColors.h` is the C++ mirror the VPN app uses and `App.xaml` mirrors those again for markup. **URmessage takes `UrColors.h` and `App.xaml` unchanged** and adds nothing to the palette except one font token (§11.4).

### 11.2 Palette mapping

| URmessage use | Token (`UrColors.h`) | `App.xaml` key | Hex |
|---|---|---|---|
| Window background | `kBackground` | `UrBackgroundBrush` | `#101010` |
| Sheets, dialogs, the key-change modal | `kSheet` | `UrSheetBrush` | `#151515` |
| Cards, incoming bubbles, list rows | `kCard` | `UrCardBrush` | `#1C1C1C` |
| Outgoing bubbles, row hover | `kCardHover` | `UrCardHoverBrush` | `#242424` |
| Row pressed | `kCardPressed` | `UrCardPressedBrush` | `#2A2A2A` |
| Hairlines, bubble borders | `kBorder` | `UrBorderBrush` | white @ 12% — effectively `#333333` composited over `kBackground` `#101010`, and `#3C3C3C` over `kCard` `#1C1C1C`. It is decoration and never carries information (§13.3) |
| Emphasised rules: quoted-reply bar, history-grant banner top edge | `kBorderStrong` | `UrBorderStrongBrush` | white @ 24% — effectively `#4A4A4A` over `kBackground` |
| Message text, names | `kOffWhite` / `kText` | `UrTextBrush` | `#F8F8F8` |
| Timestamps, previews, secondary | `kTextMuted` | `UrTextMutedBrush` | `#989898` |
| Decoration only — never information | `kTextFaint` | `UrTextFaintBrush` | `#5A5A5A` |
| Key-change, fork, failed send, destructive | `kDanger` | `UrDangerBrush` | `#F8523B` |
| Send button, primary action, unread pill | `kAccent` | `UrAccentBrush` | `#EFF7BB` |
| Text on accent | `kInverseText` | `UrInverseTextBrush` | `#101010` |
| Toggles | `kToggleAccent` | — | `#638BFC` |
| **Never used in URmessage** | `kProGold`, `kProGoldLight` | `UrProGoldBrush` | reserved for the Pro entitlement, product-wide |
| Identicon ramp (6) | `kUrGreen` `#8FE388`, `kUrPink` `#F2A0D0`, `kUrCoral` `#FF8A6B`, `kUrElectricBlue` `#638BFC`, `kUrAmber` `#F5C451`, `kToggleAccent` `#638BFC` | — | §11.5 |

The `kStatusConnecting` / `kStatusIdle` dots belong to the VPN's connect status and are not reused here; message delivery state is glyphs (§5.3).

**Tokens inherited verbatim, not redefined here.** These are taken unchanged from the VPN app's `App.xaml` and `UrColors.h`; this document only names where it uses them, and a build that cannot resolve one of them is a build error, not a licence to invent a local brush:

| Token | Used by |
|---|---|
| `UrBorderStrongBrush` | §5.2a quoted-reply rule, §5.5 history-grant banner top edge |
| `UrRowTitleStyle`, `UrRowNoteStyle`, `UrRowIconStyle` | §4.1 conversation-row anatomy |
| `UrPaneStyle`, `UrPaneHeaderStyle`, `UrPaneRowStyle`, `UrPaneRowHeight`, `UrPaneRowTallHeight`, `UrPaneSectionStyle`, `UrPaneDividerStyle`, `UrGroupHeaderHeight` | §1.3's three-pane layout and §13.4's text-scaling rule (each height becomes a `MinHeight`) |

The identicon's ramp colours are **information-bearing** (§11.5), so each of the six must hold at least **3:1** against `kCard` `#1C1C1C`; the six above are chosen to clear it, and §16.3's contrast lint checks them against `kCard`, not only against `kBackground`.

### 11.3 Type

| Role | Key | Face |
|---|---|---|
| Screen titles, the wordmark's neighbours | `UrHeadingFontFamily` | ABC Gravity Extended |
| Dense headers where width is short | `UrHeadingCondensedFontFamily` | ABC Gravity Extra Condensed |
| **All body copy, all message text** | `UrBodyFontFamily` | PP Neue Montreal |
| Wordmark | `UrWordmarkFontFamily` | PP NeueBit Bold |
| Icons | `UrIconFontFamily` | Segoe Fluent Icons |

Ramp styles reused as-is: `UrCaptionTextStyle`, `UrBodyTextStyle`, `UrBodyStrongTextStyle`, `UrBodyLargeTextStyle`, `UrSubtitleTextStyle`, `UrTitleTextStyle`, `UrTitleLargeTextStyle`, plus `UrCardStyle`, `UrCardRowStyle`, `UrCardRowButtonStyle`, `UrSectionHeadingStyle`, `UrDividerStyle`, `UrPrimaryButtonStyle`, `UrSecondaryButtonStyle`, `UrTextInputStyle`, `UrSwitchToggleStyle`, `UrSnackbarStyle`, `UrEmptyGlyphStyle`, `UrPaneStyle` and the `UrPane*` family for the three-pane layout.

### 11.4 One new token

```xml
<FontFamily x:Key="UrMonoFontFamily">Cascadia Mono, Consolas, Courier New</FontFamily>
```

Required by two screens and nothing else: the seedphrase grid and the safety number. Both need unambiguous `0`/`O` and `1`/`l`/`I` and column alignment for transcription and read-aloud comparison. Cascadia Mono ships with Windows 11; Consolas covers Windows 10. This is the only addition to the kit; it is proposed for upstreaming into `App.xaml` so both apps share it.

### 11.5 Identicons (W9)

Deterministic, drawn locally, no network, no storage.

| Input | Contacts: the **pinned** identity public key. Groups: `group_id` |
|---|---|
| Derivation | `H(input)` → first byte selects one of the six ramp colours; the next 8 bytes drive a 5×5 vertically-mirrored cell grid |
| Rendering | Foreground cells in the ramp colour on `kCard`, rounded 8, drawn as a `Path` — no bitmaps, no cache invalidation |
| Property | **A contact's avatar changes visibly when their key changes.** This is deliberate: it is SSH randomart pointed at the one event the product most wants noticed, reinforcing §7 rather than replacing it |
| Accessibility | `AutomationProperties.Name` is the contact's name, never a description of the picture |

### 11.6 Native shell, brand content

The owner's rule for the VPN app applies unchanged: Windows chrome, Mica, standard WinUI metrics and controls; URnetwork palette, brand fonts, brand surfaces. Do not build a custom title bar, a custom scrollbar, or a custom context menu. `ContentDialog` on `UrSheetBrush` is the sheet. `InfoBar` via `UrSnackbarStyle` is the transient bar — note the kit's `Snackbar` helper exists because `InfoBar` has no timer of its own.

---

## 12. Settings

| Group | Contents |
|---|---|
| **Account** | URnetwork account, message identity (principal + short fingerprint), **My contact card** (screen 32, §12.7), **Show my recovery phrase** (Hello-gated), **Check my recovery phrase** (§6.3, addition c), **Redeem a code** (screen 27), **Data allowance** (from `Balance()`), **Sign out of URnetwork**, **Remove this identity from this computer** |
| **Security** | `Sealer.Description()`, rendered verbatim; **Require a PIN** and **auto-lock** (§6.9); **Lock now**; **Security log** (screen 29) |
| **Notifications** | On/off, what notifications show (§10.3), sound, per-conversation list of overrides and mutes — see the carriers below — "Start URmessage when I sign in" |
| **Privacy & retention** | `msg_durable_default_explainer` at the top; read receipts (on); **delivery receipts (on)**; typing indicators (on); disappearing default for new conversations (off); **Download photos and files automatically** (From people I've messaged); **Let people find me by my URnetwork name** (off); **Cover traffic (off)** — §12.1 |
| **Appearance** | Enter-to-send, message density, time format |
| **Storage** | Local store size, attachment cache, "Clear downloaded files" (local only, with copy saying so), and **this server's three limits, read-only**: file size, how long photos and files are kept, how long messages are kept |
| **Devices** | Screen 19 |
| **Advanced** | Message server host, **your own operator**, and **the operator the server forwards through** — all three read-only in v1 (§12.2); diagnostic log level; "Copy diagnostic"; **Diagnostics session** (screen 31); crash-report opt-in; version and `kCode` |

**Account — the two exit doors.** "Sign out" previously appeared exactly once, as a row label, with no defined semantics — one click from Settings, and potentially the most destructive action in the product. §6 goes to great lengths to make phrase loss survivable, so leaving the one action that can cause it undefined was the sharpest inconsistency in this document. It is now two rows:

> **"Sign out of URnetwork"** — drops the `ByJwt`, **keeps** the identity and the local store, returns to screen 2. No confirmation beyond a simple one.
>
> **"Remove this identity from this computer"** — destructive. Windows Hello gated (§6.6 action 6) with the typed-`REMOVE` fallback, and this copy: *"Your messages will be removed from this computer. You can get your history back only with your 24 words."* **Hard-blocked** when `PhraseConfirmedAtMs() == 0`, offering `[ Show my phrase first ]`. Calls `RemoveIdentity()`.

**An owner cannot leave a group without handing it over.** `LeaveGroup` returns `GroupResult.Reason == "owner_must_transfer"` and commits nothing, so the client never shows a failure: it opens the transfer flow of screen 30 inline, in place, with the member picker already open —

> **You own this group. Choose who takes it over before you leave.**
> `[ member picker ]` `[ Transfer and leave ]`

— and the leave completes automatically once the transfer commits. Spec A §7.3 keeps the transfer and the leave as two calls precisely so this screen can offer the way out instead of reporting a dead end, and the two-call shape is worthless if the UI renders the refusal as an error.

**Notifications — which carrier each control writes.** The per-conversation override is `SetGroupNotificationMode(groupId, mode)` with the closed set `default` / `name_and_message` / `name_only` / `nothing`, read back as `MessageGroup.NotificationMode`; mute is `SetGroupMuted(groupId, muted)`, read back as `MessageGroup.Muted`. Both are personal state and commit nothing to the group.

**Security group.** Renders `Sealer.Description()` **verbatim** (Spec A §12.2 C13), lint-checked like the §8.1 strings:

> *"Protected by Windows DPAPI for your user account. This protects your messages from other accounts on this PC and from someone reading the disk. It does not protect against software running as you."*

This is the factual statement A ties to MASTER §13's honesty standard, and when no PIN is set it is the whole of what protects the store — which is why §6.9's set-PIN copy is written as an addition to it rather than a correction of it.

**Privacy & retention — which layer each toggle writes.** Read receipts, delivery receipts, typing indicators and the disappearing default are **user preferences** (`SetUserPreference` / `UserPreference`). The group sheet's equivalents are **group policy** (`SetGroupPolicy`, ADMIN/OWNER only). The composition line goes directly under them: *"A receipt is sent only if both you and the group allow it."* And directly under **that**, on the read-receipt and typing rows: *"Turning this off also hides other people's from you."* Reciprocity is the same rule Signal, WhatsApp and iMessage use, and it exists because without it the setting becomes a one-way observation tool where the most privacy-conscious person in a conversation learns the most about everyone else. Without the composition line the team builds a user-level preference that silently writes to nothing, because in Spec A those fields live in `MessageGroupPolicy` and a MEMBER cannot commit group metadata.

**Directory listing is off, and turning it on is the only thing that links these two identities.** The control reads:

> **Let people find me by my URnetwork name**
> Off by default. While it's off, nobody can look you up — people reach you by your contact card (§12.7) or by a group invite link, both of which work with no directory at all.
>
> Turning it on publishes your messaging key against your URnetwork account, so the operator can answer "who is this account's messaging identity". That link doesn't exist until you create it.

**Group and device limits are stated, not discovered:** group details shows *"{max_members} members maximum"* beside the member count as it approaches, and screen 19 shows *"{max_devices} devices maximum"* — both formatted from `MessageProtocolLimitsValues()` and never written as literals (§12.5, §16.3 lint 6).

**Storage.** The attachment cache path is `%LOCALAPPDATA%\URmessage\app\storage\media\` and is **owned by A**. "Clear downloaded files" calls A and deletes decrypted materialised copies only, never records. The three advertised limits are `ServerInfo().MaxBlobBytes`, `.MediaTtlMaxMs` and `.DurableTtlMaxMs`, each rendered as "not known yet" when `ServerInfo().Advertised == false`. `MediaCacheBytes` is a live switch via `SetMediaCacheBytes`.

### 12.1 Cover traffic

Ledger T7: built into the format, exposed as a setting, **off by default**. The copy must state the cost, because the cost is the reason it is off:

> **Send cover traffic**
> URmessage sends occasional decoy records so the server can't tell when you're actually messaging. It runs on its own schedule whether or not you're sending — that's what makes it work, and it's also why it uses bandwidth and battery continuously. Takes effect on the next scheduling window.

It is a live switch backed by `SetCoverTraffic(enabled)`, not a construction-time setting; the schedule stays independent of real sending, which is why the change is not instantaneous and the copy says so.

### 12.2 Server, read-only

v1 has one server (ledger T1/T2). The row shows the host, is not editable, and carries the §13 line rather than a disabled dropdown that implies a choice:

> **Message server** — message.ur.network
> URmessage v1 uses one server. Choosing or moving servers is planned for a later version.

The host string shown here is **not** the `message_server_id` URnetwork client id from §1.1; both exist and this row shows the human one.

Beneath it, a second read-only row:

> **Your operator** — the URnetwork network your account is on, and the one carrying this computer's traffic.

Sourced from the SDK's `NetworkSpaceHost()`, which is a configured value rather than a compiled-in one (§1.1). Beneath **that**, a third read-only row, naming the operator the server itself uses:

> **Forwards through** — the operator this message server holds its account on.

**Forwards through** is sourced from `ServerInfo().OperatorHost` and renders "not known yet" until the server has advertised it.

URnetwork runs more than one operator — two are live today — and they are separate things from message servers. Your operator authorises and carries your traffic; the message server's operator carries the server's. The two need not be the same, and when they differ, both parties can see that a connection exists and neither can see what is in it. All three values are shown together because "who can see that I am connected" has three parts, and showing two of them answers a different question than the one the user asked.

### 12.3 Adding and removing a device (screen 19)

**Adding a device** uses a short code and a numeric comparison rather than a 32-character transcription. The existing machine shows a **pairing code** of two groups of four characters (`K7QM-3XB9`), valid for ten minutes, and a QR encoding the same payload for a machine that can read one. The new machine types the code. **Both machines then show the same six digits, and the user confirms they match** — that comparison is the authentication; the code is only how the two machines find each other.

Screen 8's copy states the split, because a user who thinks the code is the secret will read it aloud in a room:

> Type this code on the other computer. Then check that both screens show the same six numbers before you continue — that's the part that proves it's really your other computer.

Three failed code attempts burn the code and it must be regenerated, which the screen says before it happens rather than after.

**Removing a device.** A `Remove` is one MLS `Remove` plus a `Commit` in **every** group the user belongs to, each of which can lose the single-commit race. For a user in dozens of groups it takes real time and can partially succeed — leaving a stolen laptop still a member of some groups while the UI says "removed". So removal gets the §6.7 treatment: a per-group progress list bound to A's `DeviceRemovalProgress`.

```
Removing "Ana's laptop"…
Design            ██████████   removed
Weekend           ████████░░   committing
Ana                 —          waiting
```

| Outcome | Screen |
|---|---|
| Full | "Removed from 6 conversations. That device can no longer read or send." |
| **Partial** | Names the groups where removal has **not** committed: *"This device has been removed from 4 groups. It is still a member of **Weekend** and **Ana** — removal there hasn't been accepted by the server yet."* `[ Try again ]` |
| Failed | The §9.3 reason and `[ Try again ]` |

**Normative:** the device is not revoked anywhere until its group's commit is accepted, and the UI never renders "removed" until every group has committed.

### 12.4 Redeeming a code (screen 27)

Settings → Account → **Redeem a code**, and the second button on §9.9's out-of-credit banner. One field, one button, and a result that says which of the failure cases happened, because a beta tester retyping a code needs to know whether the code is wrong or already used:

| `BalanceRedeemResult.Reason` | Copy |
|---|---|
| `ok` | "Added **{GrantedBytes}** to your URnetwork account." |
| `invalid_code` | "That code isn't recognised. Check it and try again." |
| `already_redeemed` | "That code has already been used." |
| `expired` | "That code has expired." |
| `rate_limited` | "Too many attempts. Try again in **{Detail}**." |
| `offline` | "URmessage can't reach your account right now." with `[ Try again ]` |
| `internal` | "Something went wrong redeeming that code." with `[ Try again ]` |

The field trims whitespace and is case-insensitive on submission. The code is never written to the log, and the screen offers no history of previously redeemed codes.

### 12.5 The limits this product enforces

Three numbers appear in the UI before a user can hit them, because each of them is a wall and none of them has a graceful failure:

- **The group size cap**, from `MessageProtocolLimitsValues().MaxGroupMembers`. Shown in group details from 80% of the cap onward, and as a refusal naming the number when an invite would cross it. A group that needs more people than the cap allows is a different product surface and does not exist in v1.
- **The device cap per identity**, from `MessageProtocolLimitsValues().MaxDevicesPerIdentity`. Shown on screen 19 always, and as a refusal at the point of linking one too many, with the option to remove one first.
- **The message server's file size limit**, from `ServerInfo().MaxBlobBytes`, checked before the file picker returns (§5.4).

The first two are protocol constants enforced by the SDK and every receiving client, not values this server advertises, which is why they come from `MessageProtocolLimitsValues()` and not from `ServerInfo()`.

### 12.6 The Security log (screen 29)

Settings → Security → **Security log**. An append-only list rendered verbatim from `SecurityLog()` — server key rotations, contact key changes the user accepted, devices added and removed, the PIN being set or cleared, diagnostic sessions started and ended — oldest at the bottom, with no summary layer and no editorialising. It exists because a rotation that is applied silently still has to be **inspectable**: silence is the right default and the wrong permanent state.

Each row is a time, a kind and a subject. Nothing in it is message content, a group name, or a contact's display name for a contact the user has not pinned. There is no clear button: a security log a user can erase is a log an attacker can erase.

### 12.7 My contact card (screen 32)

Reached from Settings → Account and from screen 13.

Directory listing is off by default, and an invite link needs someone already inside a group. Two people who have never met would otherwise have no way to start a conversation at all. The contact card is that way: a QR code and a copyable link the user hands to someone in person, in a message on another app, or on a slide.

**Screen 32** shows, in this order: the QR code at a size that scans from across a desk; the link, in `UrMonoFontFamily`, with `[ Copy link ]`; the user's own safety digits underneath, in the same 12-groups-of-5 form as screen 17, so the two people can read them back to each other over a phone call and know the card was not swapped in transit; `[ Save QR ]`; and `[ Make a new link ]`.

Above the code, this copy:

> **Anyone with this link can start a conversation with you.** That's the point of it — but it also means a link you posted somewhere public is a link anyone can use. Making a new one stops the old one working. It doesn't remove anyone you're already talking to.

**The screen refuses to hand out a card that cannot receive.** `ContactCard().State` is `"registering"` until the card's rendezvous exists at the server, and until then the QR, the link and `[ Copy link ]` are absent — not greyed, per §15 — under one line: *"Setting up your link. This needs a connection the first time."* `"expired"` means no device of this identity has collected for the ninety days the server advertises, and offers `[ Make a new link ]` under *"This link lapsed because this computer hasn't checked in for a while. Make a new one."* `"unavailable"` means this computer has been offline across more rotations than it can catch up on, and says *"Another of your computers changed this link. Open URmessage there, or link this computer again."* A card that cannot receive is worse than no card at all, because the person you handed it to gets a refusal and no explanation.

`[ Make a new link ]` calls `RotateContactCard`, confirms once, and afterwards the screen states when the current link was made. Rotation appears in the Security log (screen 29). It commits nothing to any group and disturbs no conversation: the link authorises a first hello and nothing else. It does discard one thing, and the confirmation says so before the user commits: *"Anyone who used the old link but hasn't reached you yet won't get through. You'll see anything already waiting first."* The client collects everything outstanding at the current link before it retires it, so "already waiting" is a promise it keeps rather than a hope.

**Receiving one.** Screen 13's *Scan or paste someone's contact card* accepts a pasted link or an image of a QR code. The client shows the sender's name, their safety digits and this line before anything is sent —

> **Check these numbers with them if you can.** They came from the link, not from a directory, so they're only as trustworthy as the way you got the link.

— and `[ Start chatting ]` sends the request. The conversation does not exist yet and the screen does not pretend it does: the row appears in the conversation list in a **waiting** state, under *"Sent. You'll see this conversation when they accept."* It becomes an ordinary conversation when their client accepts and the group arrives, and the contact's evidence row (§7.3) then reads *"you got this key from them directly"*, which is a stronger statement than anything a directory can make and is rendered as such rather than as a missing-log warning. If the link has been rotated away, or was never live, the same answer comes back for both and the screen says *"This link is no longer live. Ask them for a new one."* If the card is being hammered, *"Too many people are using this link right now. Try again in a few minutes."*

**On the other side**, a request that arrives through a card appears in screen 23 alongside group invitations, with the requester's name, safety digits and `[ Start chatting ]` / `[ Ignore ]`. When the user has left card requests on automatic — the default, since handing out the link was already a decision — the conversation simply appears, with a system row saying it started from a contact card.

**When a card is being used more than it should be.** Screen 23 shows the number of requests the server refused since the last time this computer looked, formatted from the SDK rather than as a literal, and once more than three requests arrive at one card within an hour the client stops accepting automatically for the rest of that hour whatever the automatic setting says, holds them for review, and states why: *"A lot of people are using your link right now, so we're asking you about each one. Making a new link stops the old one working for everyone who has it."* That last sentence is the whole of what v1 offers in place of blocking, and it is written plainly rather than implied.

---

## 13. Accessibility and keyboard

### 13.1 Screen readers

- `AutomationProperties.Name` on **every** icon-only button. The VPN app already does this in 15 source files; match that standard.
- The message list is an `AutomationProperties.LiveSetting="Polite"` region so arriving messages are announced without interrupting.
- A message bubble's automation name is a single sentence: *"Ana, 09:14. See you at 6. Read."* Not four separate focusable fragments.
- System records announce as such: *"System message. Ana added Bo."*
- The **key-change modal** is `AutomationProperties.LiveSetting="Assertive"` and takes focus on open. This is the one place interruption is correct.
- The **seedphrase grid** must be fully readable by a screen reader, word by word with position: each cell's automation name is *"Word 7, absurd"*. A blind user has no other way to record the phrase; suppressing it here would lock them out of the product.
- The typing indicator row is `AutomationProperties.LiveSetting="Off"` and sits outside the message list's live region (§5.8).

### 13.2 Keyboard

Full operation without a mouse is a v1 requirement, not a stretch goal.

| Chord | Action |
|---|---|
| `Ctrl+N` | New conversation |
| `Ctrl+Shift+N` | New group |
| `Ctrl+F` | Search within the current conversation |
| `Ctrl+K` | Quick switcher (jump to conversation by typing) |
| `Ctrl+Tab` / `Ctrl+Shift+Tab` | Next / previous conversation |
| `Alt+↑` / `Alt+↓` | Move selection in the conversation list |
| `F6` / `Shift+F6` | Cycle panes: list → thread → details |
| `Enter` | Send (or newline, if reversed in Settings) |
| `Shift+Enter` | Newline (or send) |
| `Esc` | Close sheet; clear reply-to; clear search |
| `Ctrl+Shift+M` | Mark conversation read |
| `Ctrl+U` | Attach a file |
| `Ctrl+E` | Emoji picker |
| `Ctrl+,` | Settings |
| `Ctrl+L` | Lock now — only when a PIN is set (§6.9) |
| `Ctrl+Shift+D` | Toggle disappearing timer for this conversation |
| `↑` in an empty composer | Edit-target selection is **not** in v1 (no editing); reserved, does nothing |
| `Application` / `Shift+F10` | Message context menu on the focused message |

Rules: no chord may shadow a Windows system chord; focus never leaves the app on `Tab`; a modal traps focus and restores it on close; every focusable element has a visible focus rect (WinUI reveal focus, 2px, `UrAccentBrush`).

**Focus in the message list, and what it costs.** `ItemsRepeater` deliberately implements **no** focus management, no item keyboard navigation and no selection model — it is a layout panel, not a `ListView` — so §16.5.1 criterion 6 (full keyboard operation plus Narrator) needs hand-written focus code that this spec budgets for explicitly:

- `↑` / `↓` move message focus when the composer is empty and the list has focus; `Ctrl+Shift+↑` / `↓` do so regardless.
- `Tab` from the composer enters the list at the **last-read** message.
- Each realized bubble is a single focusable element (`IsTabStop` on the container, `TabFocusNavigation="Once"`) carrying the §13.1 single-sentence automation name.
- **Focus survives virtualization recycling by message id, not by index.** §16.2 asserts that focus-by-id survives a scroll that recycles the focused container.

### 13.3 Contrast

Computed from the token values (WCAG 2.1 relative luminance), against `#101010`:

| Pair | Ratio | Verdict |
|---|---|---|
| `kText` `#F8F8F8` on `kBackground` | ≈ 17.5:1 | AAA |
| `kTextMuted` `#989898` on `kBackground` | ≈ 6.6:1 | AA for all sizes |
| `kDanger` `#F8523B` on `kBackground` | ≈ 5.7:1 | AA |
| `kInverseText` `#101010` on `kAccent` `#EFF7BB` | ≈ 16.9:1 | AAA |
| **`kTextFaint` `#5A5A5A` on `kBackground`** | **≈ 2.8:1** | **Fails AA and fails 3:1** |

**Therefore: `kTextFaint` / `UrTextFaintBrush` may never carry information in URmessage.** Hairlines, disabled-state fills, decorative separators only. Never a timestamp, never a delivery state, never a warning, never a label. This is a CI-checkable rule (§16.3 lint 3) and it is the single most likely accessibility regression in a chat UI, where timestamps are always the first thing someone dims.

### 13.4 Other requirements

- **No colour-only signalling.** Every state that has a colour also has a glyph or a word: failed sends, key changes, unread, muted, observers.
- **High contrast.** A `HighContrast` `ResourceDictionary` maps every `Ur*Brush` to the corresponding `SystemColor*` resource. Hardcoded `SolidColorBrush` in code-behind is prohibited outside `UrColors.h`'s helpers, so this mapping is possible at all.
- **Text scaling to 200%.** Every row height in the kit (`UrPaneRowHeight`, `UrPaneRowTallHeight`, `UrGroupHeaderHeight`) becomes a `MinHeight`, not a `Height`. Bubbles grow; nothing clips.
- **Reduced motion.** Honour `UISettings.AnimationsEnabled`. The only motion in the product is the list's scroll-to-bottom and the typing indicator; both become instant.
- **DPI.** Per-monitor v2, and the test harness must call `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` or screenshots lie.

---

## 14. Interfaces

### 14.1 The DLL boundary

The client's entire dependency is `URmessageSdk.dll` (cgo `c-shared`), reached through a generated C++ wrapper `urmessage_sdk.hpp` in namespace `urmsg::`, mirroring the existing `urnet::` wrapper for `URnetworkSdk.dll`.

**Eight traps. The first five are paid for once already in this codebase; the last three come out of A's event contract. Do not rediscover any of them.**

| # | Trap | Rule |
|---|---|---|
| 1 | The C++ wrapper generator used the **C++ return type** for a callback trampoline's C signature, producing an uncompilable header for the one string-returning callback | Any string-returning callback in the URmessage surface must go through `detail::dupCString` (malloc, because Go frees with `urnet_free_string` → `free()`). Add a `cgo/smoke/compile_hpp.cpp`-style compile-only TU for `URmessageSdk` that assigns every trampoline to its C-ABI typedef, in CI, from day one |
| 2 | `manualExports()` scans for `//export` with an **anchored regex**; on a CRLF checkout the CR sits before the line end and every hand-written export silently vanishes from the `.def` | Add a link-time assertion, or a CI check that the `.def` export count matches the `//export` count |
| 3 | **Never call `.reset()` on a subscription handle.** `urnet::Sub` does not override `reset()`, so it hits `detail::Handle::reset()` — registry release without `urnet_sub_close`, then `h_=0` so the destructor skips the close too. A process-lifetime leak *and* a use-after-free when Go still holds the callback pointer | `sub_ = urmsg::Sub{}` — move-assign closes first. Applies to every subscription in the client |
| 4 | The Go runtime's `preventErrorDialogs()` runs at `DLL_PROCESS_ATTACH` (load-time import) and sets `SEM_NOGPFAULTERRORBOX` process-wide, so native faults produce **no WER report and no Event 1000** — indistinguishable from a clean exit | `SetErrorMode(GetErrorMode() & ~SEM_NOGPFAULTERRORBOX)` at `wmain` entry. Leave `SEM_FAILCRITICALERRORS` and `WER_FAULT_REPORTING_NO_UI` alone |
| 5 | MSVC's `std::set_terminate` is **per-thread** | Arm a `ThreadGuard` on every thread that calls into the SDK or receives a callback, using the `Common/ThreadGuard.h` pattern (`ArmThreadGuard` / `RunGuarded` / `StartGuardedThread`) |
| 6 | An event with `Dropped > 0` means the view of that group is **stale** | Discard the in-memory window, re-read via `History()`, re-evaluate unread. Never merge a post-drop event. A 500-member group backfilling two years of history — C's own ledger-P4 target — overflows A's 256-event per-`Sub` queue, and without this the `ItemsRepeater` is silently missing messages with no visible state. §16.2 injects a drop and asserts a full re-read |
| 7 | `void* user_data` lifetime | Allocate before register; free **only after `urmsg_release` returns**. Spec A §9.5 rule 5 calls this "the single most common crash in this class of binding", and trap 3 does not cover it — trap 3 is about the handle, not the payload. C++ pattern: a `shared_ptr` context kept alive until after the move-assign returns |
| 8 | Callback ordering and re-entrancy | Callbacks may fire **re-entrantly before the registering call returns**, so never hold a lock across `Add*Listener`. With one goroutine per `Sub` each doing its own `TryEnqueue`, a `MessageEvent{Kind: "appended"}` and a `MessageEvent{Kind: "state_changed"}` for the same record can land on the UI thread out of order — and §5.1's scroll anchoring and §5.3's glyphs both assume order. Use **one UI-side event applier** keyed by `(groupId, messageId)`, idempotent, using A's per-`Sub` `Seq` to detect reordering rather than assuming it away |

**Threading.** Every SDK callback arrives on a Go thread. Marshal to the UI with `DispatcherQueue.TryEnqueue` and never touch a XAML object from a callback thread. Never block the UI thread on an SDK call — the VPN client's D4 was `AppHangB1` kills from exactly that.

### 14.2 What C calls in Spec A

**This is a normative field contract, not an indicative sketch.** Spec A owns the signatures; this section names A's *actual* symbols, and every state C renders is an explicit value A returns, never an inference C makes.

| Area | Calls | Events (subscriptions) |
|---|---|---|
| Lifecycle | `urmsg_client_open(settings_json)` (§1.1), `Close()`, `SetByJwt(jwt)`, `ByJwtState()`, `Start()`, `SyncState()`, `Health()` | `AddHealthListener` → `MessageHealthEvent`; `AddSyncListener` → `SyncState` |
| Account | the `urmsg_auth_*` surface (login, signup, SSO, profile) — **in this DLL**, not `URnetworkSdk.dll` | — |
| Identity | `GenerateMessageSeedphrase()`, `ValidateMessageSeedphrase(phrase)`, `HasIdentity()`, `CreateIdentity(phrase)`, `RestoreIdentity(phrase, cb)`, `RevealSeedphrase()`, `RemoveIdentity()`, `MarkPhraseConfirmed()`, `PhraseConfirmedAtMs()`, `IdentitySafetyDigits()`, `IdentityShortFingerprint()` | `RestoreCallback` → `RestoreProgress{Phase, Outcome}` |
| Devices | `Devices()`, `ThisDeviceId()`, `BeginDeviceLink(cb)`, `JoinDeviceLink(offerPayload, cb)`, `JoinDeviceLinkWithCode(code, cb)`, session methods `PairingCode()` / `AuthString()` / `Confirm(matches)` / `Cancel()`, `RemoveDevice(deviceId, cb)` | `DeviceLinkCallback` → `DeviceLinkState`; `DeviceRemovalCallback` → `DeviceRemovalProgress` |
| Conversations | `Groups()`, `Group(gid)`, `Members(gid)`, `History(gid, beforeMessageId, limit)`, `HistoryState(gid)`, `Entry(gid, mid)`, `EntryDetail(gid, mid)`, `MarkRead(gid, throughMessageId)`, `Search(gid, query, limit)`, `RequestBackfill(gid, beforeMessageId, cb)` | `AddMessageListener("")` → CLOSED: `MessageEvent{Kind: "appended" \| "state_changed" \| "reactions_changed" \| "delivered_changed" \| "read_changed" \| "typing_changed" \| "removed" \| "gap"}`; `AddGroupListener` → `GroupEvent` (declared on the Groups row) |
| Send | `SendText(gid, text, replyToId, cb)`, `SendAttachment(gid, filePath, mimeType, caption, cb)`, `ResumeAttachment(gid, mid, cb)`, `Retry(gid, mid, cb)`, `CanSend(gid)` → `*MessageSendability`, `MessageSendTicket.Cancel()` | `MessageEvent{Kind: "state_changed"}`; `GroupEvent{Kind: "sendability_changed"}`; `UploadCallback` → `UploadProgress`; `DownloadCallback` → `DownloadProgress` |
| Reactions / typing | `React(gid, targetId, emoji, cb)`, `Unreact(gid, targetId, emoji, cb)`, `SetTyping(gid, typing)` | `MessageEvent{Kind: "reactions_changed"}`; `MessageEvent{Kind: "typing_changed", TypingIds}` |
| Delete / ephemeral | `DeleteLocal(gid, mid)`, `DeleteForEveryone(gid, mid, cb)`, `SetDisappearing(gid, bucket, cb)` | `AddRecordLifecycleListener` → CLOSED: `RecordLifecycleEvent{Kind: "expired" \| "tombstoned" \| "read_elsewhere"}` ← **drives toast revocation (§10.1)** |
| Groups | `CreateGroup(name, cb)`, `CreateGroupWithMembers(name, principals, policy, cb)`, `CreateDirect(principal, cb)`, `InviteMember(gid, principal, cb)`, `RemoveMember(gid, memberId, cb)`, `SetMemberRole(gid, memberId, role, cb)`, `LeaveGroup(gid, cb)`, `SetGroupPolicy(gid, policy, cb)`, `SetGroupMuted(gid, muted)`, `SetGroupNotificationMode(gid, mode)`, `ResyncGroup(gid, cb)` | `AddGroupListener` → CLOSED: `GroupEvent{Kind: "created" \| "changed" \| "members_changed" \| "policy_changed" \| "policy_pending" \| "sendability_changed" \| "invited" \| "left" \| "removed" \| "closed" \| "history_granted" \| "ownership_changed" \| "succession_changed" \| "join_request_changed"}` carrying `RetentionApplied` (§8.4) |
| Invitations | `PendingInvites()` → `*MessageInviteList`, `AcceptInvite(inviteId, cb)`, `DeclineInvite(inviteId)` | `GroupEvent{Kind: "invited"}` |
| History grants | `HistoryGrants(gid)` → `*MessageHistoryGrantList`, `GrantHistory(gid, memberId, fromEpoch, cb)` (owner only) | `GroupEvent{Kind: "history_granted"}` |
| Verification | `SafetyNumber(principal)`, `Pins()`, `PinFor(principal)`, `AcceptKeyChange(principal, newKeyFingerprint)`, `MarkVerified(principal, viaSafetyNumber)` | `AddKeyChangeListener` → `KeyChangeWarning`; `AddIntegrityListener` → CLOSED: `IntegrityEvent{Kind: "fork_resyncing" \| "fork_unresolved" \| "attestation_gap" \| "server_key_rotated" \| "server_key_untrusted"}` |
| Directory | `LookupPrincipal(query, cb)` → `MessageDirectoryResultList` (each with `ProofState` and `OperatorHost`) | — |
| Contact card | `ContactCard()`, `RotateContactCard(cb)`, `AddContactByCard(url)`, `StartDirectFromCard(url, cb)`, `ContactRequests()`, `AcceptContactRequest(requestId, cb)`, `DeclineContactRequest(requestId)` | `AddContactRequestListener` → `MessageContactRequest` |
| Protocol limits | `MessageProtocolLimitsValues()` → `MessageProtocolLimits` | — |
| Preferences | `SetUserPreference(key, value)`, `UserPreference(key)`, `SetCoverTraffic(enabled)`, `SetMediaCacheBytes(n)` | — |
| Server | `ServerInfo()` → `MessageServerInfo` — including `.OperatorHost`, `.KtGossipUsable`, `.HostingJurisdiction`, `.ReadKeyWindowMs` — plus `NetworkSpaceHost()` and `SetNetworkSpaceHost(host)` | `IntegrityEvent{Kind: "server_key_rotated"}`, `IntegrityEvent{Kind: "server_key_untrusted"}`, `IntegrityEvent{Kind: "attestation_gap"}` |
| Push | `RegisterPushChannel(uri)`, `UnregisterPushChannel()` | — |
| Lock | `HasPin()`, `SetPin(pin)`, `ChangePin(old, new)`, `Unlock(pin)`, `Lock()`, `IsLocked()`, `AutoLockMinutes()`, `SetAutoLockMinutes(n)` | health `Locked` via `AddHealthListener` |
| Invite links | `CreateInviteLink(gid, reusable, expiresInMs, cb)`, `InviteLinks(gid)`, `RevokeInviteLink(gid, linkId)`, `RedeemInviteLink(url, cb)`, `JoinRequests(gid)`, `AcceptJoinRequest(gid, requestId, cb)`, `DeclineJoinRequest(gid, requestId)` | `AddJoinRequestListener` → `MessageJoinRequest` |
| Ownership | `TransferOwnership(gid, memberId, cb)`, `NominateSuccessor(gid, memberId, cb)`, `ClearSuccessor(gid, cb)`, `SetSuccessionEnabled(gid, enabled, cb)`, `Succession(gid)`, `CountersignSuccession(gid, cb)`, `ClaimSuccession(gid, cb)` | `GroupEvent{Kind: "ownership_changed" \| "succession_changed"}` carrying `Succession *MessageSuccessionState` |
| Balance | `Balance()`, `RedeemBalanceCode(code, cb)` | `AddBalanceListener` → `MessageBalance`; `BalanceRedeemCallback` → `BalanceRedeemResult` |
| Directory listing | `DirectoryListed()`, `SetDirectoryListed(listed, cb)` | — |
| Diagnostics | `StartDiagnosticSession(minutes)`, `StopDiagnosticSession()`, `DiagnosticSessionEndsAtMs()` | — |
| Security log | `SecurityLog()` → `MessageSecurityLogEntryList` | `AddIntegrityListener` → `IntegrityEvent{Kind: "server_key_rotated" \| "server_key_untrusted"}` |

**The field contract.** Every rendered datum in this document resolves to one `A type.field`, and the mapping is normative: one row per datum → screen → `A type.field`, drawn from `MessageGroup`, `MessageMember`, `MessageEntry`, `MessageEntryDetail`, `MessageAttachment`, `MessageReaction`, `MessageReceipt`, `MessageInvite`, `MessageHistoryGrant`, `MessageServerInfo`, `MessageSendability`, `MessageHealthEvent`, `SyncState`, `MessagePin`, `KeyChangeWarning`, `IntegrityEvent`, `MessageDirectoryResult`, `MessageDevice`, `DeviceLinkState`, `DeviceRemovalProgress`, `UploadProgress`, `DownloadProgress`, `RestoreProgress`, `RecordLifecycleEvent`, `MessageSuccessionState`, `MessageInviteLink`, `MessageJoinRequest`, `MessagePendingPolicy`, `MessageBalance`, `BalanceRedeemResult`, `MessageSecurityLogEntry`, `MessageContactCard`, `MessageContactRequest` and `MessageProtocolLimits` — all of which Spec A §7 defines. Screens 9, 10, 12, 15, 16, 19, 23 and 24 could not be built from either document before this mapping existed; it is a build gate, not documentation, and §16.1 gate 8 is that gate. The mapping is:

| Screen | Rendered datum | Source |
|---|---|---|
| 9 Conversation list | identicon | `MessageMember.IdentityPublicKey` for a DM peer, `MessageGroup.GroupId` for a group (§11.5) |
| 9 | name | `MessageGroup.Name` |
| 9 | preview text / class | `MessageGroup.PreviewText`, `.PreviewClass`, `.PreviewSenderId` |
| 9 | time | `MessageGroup.LastActivityMs` |
| 9 | unread count | `MessageGroup.UnreadCount` |
| 9 | muted glyph | `MessageGroup.Muted` |
| 9 | disappearing glyph | `MessageGroup.DisappearingBucket` |
| 10 Conversation view | bubble text | `MessageEntry.Text` |
| 10 | quoted reply | `MessageEntry.ReplyToId`, resolved by `Entry(gid, replyToId)` |
| 10 | attachment card | `MessageAttachment{FileName, Bytes, Caption, State, LocalPath}` |
| 10 | reaction strip | `MessageEntry.Reactions` → `MessageReaction{Emoji, EmojiRaw, Count, MemberIds, MineSet}` |
| 10 | delivery glyph, delivered-by list | `MessageEntry.State`, `.Reason`, `.ReasonDetail`, `.DeliveredTo` |
| 10 | held attachment | `MessageAttachment.AutoDownloadHeld`, `.State == "not_downloaded"` |
| 10 | gap row | `MessageEntry.Kind == "gap"`, `.GapReason` |
| 10 | typing row | `MessageEvent.TypingIds` × `Members(gid)` (§5.8) |
| 10 | observer collapse | `MessageEntry.SenderRoleAtSend` |
| 12 Message info | sender, times, epoch, leaf | `MessageEntry.SenderId`, `.SentAtMs`, `.ReceivedAtMs`, `.Epoch`, `.SenderLeafIndex` |
| 12 | class, bucket | `MessageEntry.RetentionClass`, `.EphBucket`, `.SizeBucket` |
| 12 | attestation state | `MessageEntryDetail.AttestationState`, `.ServerRecordId` |
| 12 | read-by list | `MessageEntry.ReadBy` → `MessageReceipt{MemberId, ReadAtMs}` |
| 12 | delivered-by list | `MessageEntry.DeliveredTo` → `MessageReceipt{MemberId, ReadAtMs}` |
| 13 New conversation | contact-card send state | `MessageContactRequest{State}` — subscription reference, not the vocabulary |
| 15 Group details | members and roles | `Members(gid)` → `MessageMember{DisplayName, Role, DeviceCount, Pinned, ChangePending}` |
| 15 | retention | `MessageGroup.RetentionDurableMs`, `.RetentionMediaMs` |
| 15 | disappearing | `MessageGroup.DisappearingBucket` |
| 15 | receipts / typing policy | `MessageGroup.ReadReceipts`, `.TypingIndicators` |
| 15 | history-grant banner | `HistoryGrants(gid)` → `MessageHistoryGrant{GranteeDisplayName, GrantedByDisplayName, FromMs, FromEpoch}` |
| 15 | invite links | `InviteLinks(gid)` → `MessageInviteLink{Url, Reusable, ExpiresAtMs, Redeemed, Revoked}` |
| 15 | join requests | `JoinRequests(gid)` → `MessageJoinRequest{DisplayName, KeyFingerprint, RequestedAtMs, State}` |
| 16 Member detail | identicon, principal | `MessageMember.IdentityPublicKey`, `.Principal`, `.DisplayName` |
| 16 | safety number | `SafetyNumber(principal)` |
| 16 | pin state | `PinFor(principal)` → `MessagePin{KeyFingerprint, FirstSeenMs, EvidenceClass, ChangePending}` |
| 16 | role controls | `MessageMember.Role` + `SetMemberRole` |
| 19 My devices | rows | `Devices()` → `MessageDevice{Name, AddedAtMs, LastSeenMs, IsThisDevice}` |
| 19 | removal progress | `DeviceRemovalProgress{GroupName, State, Reason, GroupsDone, GroupsTotal}` |
| 23 Invitations | rows | `PendingInvites()` → `MessageInvite{GroupName, InviterDisplayName, MemberCount, CreatedAtMs, State}` |
| 23 Invitations | contact requests, and the refused-request count | `ContactRequests()` → `MessageContactRequest{DisplayName, KeyFingerprint, SafetyDigits, RequestedAtMs, State, RefusedSinceLastCollect}`, whose `State` takes `"held_for_review"` while the §12.7 rate fallback is suspending automatic acceptance |
| 24 Reaction picker | the emoji set | the system's own emoji set (§5.2a); `React(gid, targetId, emoji, cb)` validates what it returns |
| 26 Locked | nothing but the app name and the field | `IsLocked()` — **no** group, member or message field may be read while locked |
| 27 Redeem | result | `BalanceRedeemResult{Ok, GrantedBytes, Reason, Detail}` |
| 29 Security log | rows | `SecurityLog()` → `MessageSecurityLogEntry{AtMs, Kind, Subject, Detail}` |
| 30 Ownership | state | `Succession(gid)` → `MessageSuccessionState{Enabled, SuccessorDisplayName, EligibleAtMs, CountersignsHeld, CountersignsRequired, OwnerWarningStage}` |
| 31 Diagnostics | session end | `DiagnosticSessionEndsAtMs()` |
| 9, 12, 15 | this server's three limits | `MessageServerInfo.MaxBlobBytes`, `.MediaTtlMaxMs`, `.DurableTtlMaxMs`, `.DurableTtlDefaultMs`, `.GroupDurableOverride` |
| 9, 12, 15 | the read-key window, the group cap, the device cap, the free allowance | `MessageServerInfo.ReadKeyWindowMs`, `MessageProtocolLimitsValues()`, `MessageBalance.FreeAllowanceBytesPerDay` |
| 20 Settings → Advanced | message server host, your operator, the server's operator | `MessageServerInfo.Host`, `NetworkSpaceHost()`, `MessageServerInfo.OperatorHost` (§12.2) |
| 22 About | hosting jurisdiction | `MessageServerInfo.HostingJurisdiction` |
| 32 Contact card | link, QR, digits, rotation time, state, expiry | CLOSED: `MessageContactCard{Url, QrPayload, SafetyDigits, RotatedAtMs, State, ExpiresAtMs}` |

**The `gap` entry kind** is a first-class `MessageEntry.Kind` value with a reason of `expired` / `out_of_window` / `not_a_member_yet` / `withheld` / `no_wrap` / `malformed`, rendered per §5.1.

**Requirements C places on A:**

1. **Enumerable reasons, never inference.** `CanSend` returns `MessageSendability.Reason` from a closed vocabulary; `MessageEvent{Kind: "state_changed"}` carries a reason; health carries a reason. C must never conclude "not connected" from an empty getter — that inference is precisely what produced defect #40 in the VPN client.
2. **`AddRecordLifecycleListener` is client-wide and must fire with no user visible**, because a toast in the Action Center must be revoked when the key dies, including for a conversation never opened this session.
3. **A distinguishes pruned from failed** for media, as `MessageAttachment.State` (§9.7).
4. **A never returns plaintext for an expired ephemeral record**, under any code path, including history restore.
5. **A owns the local store and its DPAPI sealing.** C writes no message content to disk, ever.
6. **A exposes `commit_lost` as a non-event** or handles the retry internally and never surfaces it (§9.3).
7. **A exposes the advertised caps as data.** C hardcodes no size limit and no retention period; "100 MB" and "1 month" appear in copy only via formatted values.
8. **A excludes `EPH` records from the search index** (§5.7).
9. **A reports store-open failure as an explicit enumerable value on the health event**, never as an empty `Groups()` (§9.2).
10. **Every event carries `Seq` and `Dropped`** (§14.1 traps 6 and 8).
11. **A names the read-authorization window explicitly** rather than returning a generic refusal, so §9.8 can offer two working recoveries instead of a shrug.
12. **A enforces the PIN by wrapping the store key**, not by returning empty results. C renders the lock screen from `IsLocked()`; it never infers a lock from missing data.
13. **A refuses a message-server key that does not chain to the compiled-in fleet root, and exposes no call to accept one.** C must have no button for it because there is no call behind it.
14. **A resyncs a forked group automatically before surfacing a stop**, and distinguishes the two states so C can keep sending during the attempt.
15. **A exposes delivery receipts as `MessageEntry.State == "delivered"` and `DeliveredTo`**, both honouring the user preference and the group policy.
16. **A scopes every key-transparency artefact to the operator it came from**, and tells this client whether the message server's gossip is a second path for it. C renders the operator alongside the evidence rather than presenting one operator's answer as the system's answer.

### 14.3 What C assumes of Spec B

C never talks to B. These are requirements on B that reach the UI through A, listed here because the UI is where a violation becomes visible.

| Assumption | UI consequence if violated |
|---|---|
| B advertises **three** limits — file size, media window, text storage cap — plus whether groups may override the text default, all readable before a send | §8.4 and §12.5 show numbers this client would otherwise hardcode, a group is told a retention it does not get, and an oversize file is only refused after it has been uploaded |
| B accepts one commit per `(group_id, epoch)`, returns the winner, and rejects wrong-epoch records (§9.3) | Retry storms, reordered threads, or a user-visible error for a normal race |
| B distinguishes "pruned by retention" from "never existed" from "refused" in its responses | §9.7 collapses; every missing photo looks broken |
| B signs `FetchAttestation` with a stable long-term Ed25519 key (§9.4) | §9.6's attestation range is discarded constantly, or never |
| B presents a signing key that chains to the fleet root the SDK compiled in, and never presents one that does not | §7.6 either never fires or fires on every legitimate rotation |
| B enforces monotonic, not contiguous, `stream_index` per `(group_id, sender_handle)` (§8) | A refused write bricks a conversation's outbox |
| **B authorizes reads (`req_auth`)** | The metadata C renders is readable by any account that guesses a group id |
| **B's `record_id` is gapless including expired ephemerals**, which are kept as placeholder rows **whose `sender_handle` is zeroed** | Without the gapless row, every disappearing message manufactures a false withholding warning in §9.6; without the zeroing, "disappearing" leaves a permanent per-sender timestamped trail on the server, and §8.3's placeholder copy would be a lie |
| **B advertises `capability_version` and converges the fleet** | Two members of the same group are told different retention |
| B records nothing per identity except inside a diagnostic session the user started (MASTER §9.7) | §12's Diagnostics control implies a promise the rest of the product makes; if the server logs anyway, the promise is false, and the honest-limits page in MASTER §13 becomes false with it |
| B never sees plaintext and never needs group membership from the operator (MASTER §4.2) | Everything |
| Retention negotiation is warn-and-proceed in **both** directions, returning `RetentionApplied`, which reaches C as Spec A's `MessageRetentionApplied` in seconds (C-5, RULED) | §8.4's copy is wrong and a group's real retention is misstated to its members |
| B retains each epoch's read key for the window it advertises — **ninety days** on a stock server — and refuses reads authenticated under an older one | §9.8 has no window to name, and either an offline member is locked out far sooner than the copy says or a removed member never loses metadata access |
| B's backups are encrypted, its point-in-time window is **48 hours**, and its hosting jurisdiction is published | §15's honest-limits copy about deletion is unqualified and therefore wrong |
| B advertises its **hosting jurisdiction** and its **read-key window** as capability fields | §22's About screen has no answer to "where is this server", and §9.8 has to hardcode a duration that is a server configuration value |
| B applies its **own** advertised text default when a group sends the unset retention sentinel | Every group that never opens a retention screen keeps text forever, and MASTER §13's "one year for text" is false for exactly the users least likely to notice |
| **B carries a contact rendezvous** — registering a card, disclosing its KEM key to a token holder, accepting a bounded number of fixed-size deposits, and returning the same answer for a retired and an unknown id | §12.7 has no transport at all: the first acceptance criterion of the first testable build cannot pass, and with directory listing off by default there is no way to start a conversation |
| B bounds a card's mailbox by depth and a deposit by a short TTL, and stores no depositor identifier | §12.7's request-rate copy has nothing to render, and the one place in the product a stranger writes to becomes a durable record of who contacted whom |

### 14.4 What C supplies to A

Spec A §12.2 lists twenty obligations on this client. Each one has a named C-side implementation here, so none of them is a sentence in someone else's document:

| A's # | Obligation | Where C implements it |
|---|---|---|
| C1 | A writable per-user directory as `MessageClientSettings.StorageDir`, never `%PROGRAMDATA%` | §1.1: `%LOCALAPPDATA%\URmessage\app\storage`. The per-user install (W4, §2.2) is what makes this the natural path rather than an exception |
| C2 | Supply `settings_json` per A's schema — `storage_dir`, `network_space_host`, `message_server_id`; no ByJwt at construction, no handle from another DLL | §1.1's `settings_json` block — `storage_dir` from the per-user data root, `message_server_id` from `kMessageServerClientId`, and `network_space_host` from per-user configuration with a build-time default, never from a compiled-in constant as its only source (§1.1, §16.1 gate 12) |
| C3 | Marshal every callback to the UI dispatcher | §14.1 "Threading": `DispatcherQueue.TryEnqueue`, never a XAML touch on a callback thread |
| C4 | Free every returned `char*` with `urmsg_free_string`, never the CRT `free` | §14.1 trap 1's `detail::dupCString` rule and the `compile_hpp.cpp` compile-only TU (§16.1 gate 3) |
| C5 | Free `void* user_data` only after `urmsg_release(sub)` returns | §14.1 trap 7 |
| C6 | Call `urmsg_client_close` before process exit; assert `urmsg_live_handle_count() == 0` in debug builds | §1.4 "Quit" — drain, stop, exit — with the assert in the debug build's shutdown path |
| C7 / C13 | Render `Sealer.Description()` verbatim in a Security screen, lint-checked | §12's **Security** group; added to §16.3 lint 1's verbatim set |
| C8 | Render MASTER §12.4's three strings verbatim; never "gone forever" for the durable class | §8.1, plus §16.3 lints 1 and 2 |
| C9 | Render `Kind == "gap"` entries visibly, with the reason. Do not hide them | §5.1's gap row, six reasons; §16.2 pins all six |
| C10 | Treat `KeyChangeWarning` as blocking, SSH changed-host-key shape; no verified badge | §7 in full; W8 and §7.5 forbid the badge |
| C11 | Never persist the seedphrase **words** | §6.5: A holds the entropy, C holds the rendered words only for the life of the §6.2 screen. W6, W10 and §6.2's clipboard rules are the enforcement |
| C12 | No administrator tunnel, no privileged service, no WFP, no wintun, no LocalSystem, no mTLS loopback RPC | W2, §0.3's table, and §16.1 gates 4 and 5 |
| C14 | On any event with `Dropped > 0`, discard the window and re-read via `History()` | §14.1 trap 6, §5.1's loading rule, §16.2's injected-drop selftest |
| C15 | Render every closed vocabulary by switching on the value; never parse `out_error` | §9.2 (health), §9.3 (send failures), §9.7 (attachment state), §7.3 (evidence classes) — each cites A's vocabulary rather than restating it |
| C16 | Render the PIN as an optional second factor; never claim protection when it is unset | §6.9's set-PIN copy and §12's Security group, which renders `Sealer.Description()` verbatim when no PIN is set |
| C17 | Never present an accept affordance for a non-chaining server key | §7.6 in full; W12 |
| C18 | Render the three advertised limits from `ServerInfo()`, never as literals | §8.4, §12's Storage group, §12.5; §16.3 lint 6 already forbids the literals |
| C19 | Render the security log verbatim, with no summary layer | §12.6 |
| C20 | Start and stop diagnostic sessions only on explicit user action, showing when one ends | §12's Advanced group and screen 31 |

---

## 15. Not in v1

The rule: **absent, not disabled.** A greyed-out call button teaches a user the product has calling and is broken. Nothing greyed, nothing "coming soon" as a button.

| Deferred (master §2) | What the user sees in v1 |
|---|---|
| Voice and video | No call button anywhere. Not mentioned |
| Message editing | The context menu has Delete, not Edit. `↑` in an empty composer does nothing |
| Group migration between hosts | Not mentioned. The single-server honesty in §9.4's "What's happening?" covers the consequence |
| History export | Not offered. There is no export button to grey out |
| Public groups | Group creation has no visibility control |
| Stream digests (server-withholding detection) | Settings → Privacy carries one line: *"URmessage cannot yet prove this server didn't quietly drop a message. Detecting that is planned."* — because MASTER §12.3 says it is undetectable in v1, and silence would be a claim |
| Per-device write capabilities | The observer copy in §5.6 states the limit plainly |
| Mobile clients | No "Link a phone" entry. Device linking shows a code that another **desktop** can enter |
| App lock / local passcode | **Ships**, as the optional PIN of §6.9. With no PIN set, Settings → Security still says plainly what protects the store, in the SDK's own words. |
| Contact avatars / group photos | Identicons, with no upload affordance |
| Backups other than the recovery phrase | Not offered |
| Message forwarding, starring, pinning, drafts sync | Not offered |
| Per-member delivery state in the **thread** | The thread shows one delivery glyph for the message, not one per member. Who delivered and who read is screen 12 (§5.3) |
| Blocking a contact, and reporting one | Neither is offered and neither is mentioned in the UI. What ships is **mute and leave**. Directory listing is off by default (§12), so most unsolicited contact never starts; blocking has no SDK surface and its cross-device carrier is unscoped, and reporting without a moderation process behind it is a form that goes nowhere. Recorded against MASTER §15 item 4 |
| Local search (C-3) | **In v1.** Local-only, A-backed, `EPH` records excluded from the index (§5.7) |
| Signed binaries, during the beta | The download page and the installer's first screen say the build is unsigned and how to verify the hash (§2.7). Signing is decided before general availability |
| Any mention of URmessage inside the VPN client | Absent entirely — no row, no banner, no "coming soon" (§2.6) |
| Choosing a message server, or an operator | Settings shows all three values, read-only, with §12.2's sentences. The operator is configuration rather than a compiled-in constant (§1.1), so a build can be pointed at another one; choosing one **in the UI** is not offered in v1 |
| Per-machine or managed deployment (Intune, SCCM, Group Policy) | Not offered. URmessage installs per user, for the reasons in §2.1, and no organisation can roll it out centrally in v1 |

---

## 16. Verification and acceptance

### 16.1 Build gates

1. x64 and ARM64 both build in CI on every commit, `fail-fast: false`, msbuild log uploaded on failure. Runner **windows-2022** — `windows-latest` moved to Visual Studio 18 (toolset v180) which keeps v143 for x64 but **not** the v143 ARM64 cross tools.
2. `WindowsTargetPlatformVersion` pinned in `Directory.Build.props` for the real build box, overridden in CI via `/p:` (a global property beats the props file).
3. The `compile_hpp.cpp`-style compile-only TU for `URmessageSdk` (§14.1 trap 1).
4. Manifest check: no `requireAdministrator`, no `highestAvailable`, anywhere.
5. Solution check: no reference to `urnetworkd`, wintun, WFP, or `SplitTunnel` from the URmessage projects.
6. **Exactly one Go DLL is imported by `URmessage.exe`** — a CI check on the import table fails the build if `URnetworkSdk.dll` appears (A12, C-12).
7. **Per-user install:** the URmessage package declares `InstallScope="perUser"`, its components target `%LOCALAPPDATA%\Programs\URmessage\`, and no component targets `ProgramFiles64Folder` or writes under `HKLM`.
8. **Every symbol named in §14.2 exists in Spec A §7, and every closed set named in §14.2 matches Spec A's exactly.** A CI check extracts the identifiers from §14.2's Calls and Events columns and fails the build on any that does not appear as a declaration in Spec A §7. It then extracts every braced value list from §14.2 and treats it as one of two kinds. A list marked `CLOSED:` **declares** a vocabulary and is asserted for **set equality** against Spec A's matching `// CLOSED:` comment, failing on a missing value and on an extra one. Every other braced value is a **subscription reference** — a row citing the one or two members of a vocabulary that area listens for — and is asserted for **membership**, failing on a value Spec A does not define and never on an omission. Existence alone is what let a deleted event kind and four missing ones ship in the same table; equality on the declaring rows catches both, and membership elsewhere keeps a one-value citation legal. A braced list naming a type for which Spec A has **no** `// CLOSED:` comment **fails the build** rather than passing silently.

    The rows marked `CLOSED:` are exactly: Conversations for `MessageEvent.Kind`, Groups for `GroupEvent.Kind`, Verification for `IntegrityEvent.Kind`, Delete and ephemeral for `RecordLifecycleEvent.Kind`, and Contact card for `MessageContactCard`. Spec A's `RecordLifecycleEvent.Kind` comment gains a `CLOSED:` marker so the fourth has a counterpart.
9. **No "Get URmessage" entry point.** A CI check fails the build if the VPN client's solution contains a string resource, XAML row or handler referencing URmessage acquisition (§2.6).
10. **No accept-server-key affordance.** A CI check fails the build on any reference to a server-key accept call or command in the URmessage projects (§7.6).
11. **The unsigned-beta notice exists** while the signing property is off, and the build fails if the installer's first screen omits it (§2.7).
12. **No operator host is compiled in as its only source.** A CI check fails the build if `kNetworkSpaceHost` is referenced anywhere except in the one function that supplies a default for an unset configuration value, and fails it if any string literal matching an operator hostname appears in XAML, in a string resource, or in a source file outside that function. More than one operator exists, and a build that can reach only one of them cannot be pointed at a second without shipping a new binary.

### 16.2 Selftest

The VPN client's `selftest` grew from 167 to 463 assertions over the beta and is the reason its state machines can be trusted. URmessage carries the same discipline:

| Pinned | |
|---|---|
| `MessageHealth` transition table | Every (state, event) pair, including the tick-gap rebase and the carrying veto |
| BIP39 round-trip | Generate → display order → confirm positions → restore; plus all four distinguishable failure modes in §6.7, and the "type all 24" and delayed-re-verification paths of §6.3 |
| Identicon determinism | Same key → same 5×5 grid and colour, across runs and architectures |
| Copy lint | §16.3 |
| Contrast lint | §16.3 |
| Breakpoint decisions | Widths 560/999/1000/1499/1500/2400 → expected pane counts |
| Toast revocation | Every one of the four revocation triggers in §10.1 |
| `StoreUnavailable` transitions | All four store states (`unseal_failed`, `corrupt`, `disk_full`, `locked_by_another_process`) → screen 25, in and out |
| Batched key-change review sheet | Two and more unresolved changes collapse into one sheet; per-contact accept resolves only that contact (§7.1) |
| Gap rendering | All six gap reasons (§5.1) render their own copy; none is silently dropped |
| Ephemeral containment | The four §5.7 rules: reply-by-lookup, copy confirmation, search exclusion, metadata-only message info |
| Event-drop re-read | Inject `Dropped > 0`; assert the window is discarded and `History()` is re-read, not merged (§14.1 trap 6) |
| Focus by id | Focus survives a scroll that recycles the focused container (§13.2) |
| Observer collapse | `SenderRoleAtSend == "observer"` collapses to the system row and expands with the warning (§5.6) |
| Typing indicator | One, two and three-plus typers produce the §5.8 strings; an empty `TypingIds` clears the row; a typer not re-listed within the drop timeout is removed |
| PIN and auto-lock | Setting, changing, clearing; auto-lock at the configured idle; wrong-PIN delay escalation; the lock screen renders no conversation name, count or preview |
| Confirmation has no exit | Screen 5 has no skip affordance and `Esc` does not leave it; a quit-and-relaunch returns to it with the send gate still on (§6.3, §6.4) |
| Delivery glyphs | `pending` → `sent` → `delivered` → `read` renders four distinct glyphs and never regresses; a `delivered` receipt arriving after `read` does not move the state back (§5.3) |
| Held attachments | A first-time sender's attachment renders the held card with its reason; a known contact's downloads without interaction (§5.4) |
| Delete window | The delete-for-everyone item is present inside 24 hours and **absent** outside it; a tombstone leaves a placeholder that is never collapsed (§8.2) |
| Expired placeholder | An expired message renders with no sender name and shows the required sentence once per conversation (§8.3) |
| Fork resync | A recoverable divergence never disables the composer; an unrecoverable one shows the §9.5 stop (§9.5) |
| Server key | A chaining rotation raises no UI and writes one Security-log line; a non-chaining key shows §7.6's banner with no accept affordance |
| Notification default | A fresh install shows name-only for every conversation; opting one conversation up does not change any other (§10.3) |
| Reaction grouping | Two reactors sending the same emoji with different skin tones and different variation selectors produce one pill with a count of two; a ZWJ sequence is one reaction and not its components; an emoji with no glyph in the shipped fonts renders its replacement box and its codepoint tooltip rather than being dropped (§5.2a) |
| Receipt reciprocity | With read receipts off, an outgoing message stops at `delivered`, screen 12's read-by list is empty, and no typing row appears; turning them back on does not retroactively populate either (§5.3, §12) |
| Succession warnings | Stages 30, 60, 75 and 85 produce a row, a row, a banner and a modal respectively, on a client where the local identity is the owner, and none of them on a client where it is not (§9.10) |
| Contact card | A card in `registering` shows no link and no QR; a card in `live` shows both. A rotated card's old link produces "this link is no longer live", and a link that was never registered produces the same string from the same code path. A card link opens a request in the waiting state, and the conversation appears only when the other side accepts, with the evidence row reading that the key came from the person rather than from a log (§12.7). Existing conversations are untouched by a rotation, and a request that was waiting at the old link is shown to the owner before the rotation completes |
| Operator rows | Settings → Advanced shows three distinct values, and the two operator rows differ when the client's operator and the server's differ (§12.2) |
| Owner leave | An OWNER's leave never commits without a completed `TransferOwnership`; the refusal opens the transfer flow rather than an error dialog (§12) |

### 16.3 Copy and contrast lints (build-failing)

1. The five §8.1 keys — and `Sealer.Description()` (§12, Security) — exist and their English values match the source character-for-character.
2. No English string contains the prohibited phrases of §8.1 outside the allowlisted ephemeral keys.
3. No `Foreground` binding to `UrTextFaintBrush` on any `TextBlock` that is not in the decoration allowlist (§13.3).
4. No `SolidColorBrush` literal in `.xaml` or `.cpp` outside `UrColors.h` and `App.xaml` — otherwise the high-contrast dictionary cannot work.
5. Every `Button` / `ToggleButton` whose content is a `FontIcon` has an `AutomationProperties.Name`.
6. **No hardcoded limit, retention period, cap or allowance in the string store.** Every one of the following is formatted from a named source at render time, and the lint fails the build on the literal: `100 MB` / `100MB` and any file-size literal → `ServerInfo().MaxBlobBytes`; `1 month` and `30 days` → `ServerInfo().MediaTtlMaxMs`; `1 year` and `365 days` → `ServerInfo().DurableTtlDefaultMs` and `.DurableTtlMaxMs`; `90 days` → `ServerInfo().ReadKeyWindowMs`; `500 members` → `MessageProtocolLimitsValues().MaxGroupMembers`; `10 devices` → `MessageProtocolLimitsValues().MaxDevicesPerIdentity`; `40 GB` → `Balance().FreeAllowanceBytesPerDay`; `7 days` → `ServerInfo().RendezvousDepositTtlSeconds`, formatted; `16 requests` → `ServerInfo().RendezvousMailboxDepth`; `90 days` in any contact-card copy → `ServerInfo().RendezvousTtlSeconds`. Each literal is on this list **because** a source for it exists; a literal whose source does not exist does not belong on a lint that fails the build. The existing `90 days` carve-out for the read-key window and for succession stands; the contact-card entry is a third source for the same number, and the lint names which source each occurrence is formatted from rather than matching on the number alone. The succession durations of §5.1 and §9.10 are the one place a number that looks like this list's is not from it: they are formatted from `Succession(gid)`'s `FloorMs`, `EligibleAtMs`, `OwnerWarningStage`, `CountersignsHeld` and `CountersignsRequired`.
7. **No double-encoded UTF-8 in any spec or string file.** The gate fails on any occurrence of the four byte runs that double-encoding produces, expressed by codepoint so this rule cannot trip on its own text: U+00E2 U+20AC, U+00C2 U+00A7, U+00C3 U+00A2, U+00C3 U+201A. The repo also carries `*.md text working-tree-encoding=UTF-8 eol=lf` in `.gitattributes`. Double-encoded UTF-8 is undetectable by eye and corrupts the one sentence in the product that must be exact.

Both copy lints had defects that would have shipped:

> **Lint 1** compared to a **hard-wrapped** master file (`msg_disappearing_explainer` is split across two source lines with two leading spaces on the continuation), so a literal comparison fails on whitespace even when the strings are identical — and that failure would mask a real corruption. Collapse all runs of whitespace to a single space on **both** sides before comparing, compare by **codepoint sequence**, and assert the extraction is non-trivially anchored (fail if the extracted master string is empty).
>
> **Lint 2**'s prohibited phrases are English substrings; run against 28 locales it is **vacuous for 27 of them while reporting green**. Keep the substring check for English only. For the other locales substitute a process gate: the §8.5 translator note plus a **recorded human sign-off per locale** for the §8.1 keys, failing the build when a locale's translation of one of those keys changes without a new sign-off.

### 16.4 Runtime loop

The VPN project's ~40-second loop applies: kill → launch → drive → screenshot → read `%LOCALAPPDATA%\URmessage\app\logs\urmessage-app.log`. Three harness traps, all measured:

- `FindWindow` from a PowerShell P/Invoke harness silently returns 0 unless the `DllImport` sets `CharSet=CharSet.Unicode` — the default marshals ANSI into the `W` entry point. Use `EnumWindows` + `GetClassNameW`, which is immune.
- The harness must call `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` or every screenshot is wrong.
- `pwsh` does not exist on the build box; only `powershell`.

And one specific to this product: **the seedphrase screen cannot be screenshotted** while `WDA_EXCLUDEFROMCAPTURE` is set — that is the feature working. The harness verifies it by asserting the captured region is black, and exercises the screen's content through the automation tree instead.

### 16.5 Acceptance

#### 16.5.1 The first testable build (MASTER §14 slice 5, Spec A slice A8 — internal only)

Text-only, single-device, unnotified. Two people, on two Windows machines, each having created an identity and written down a phrase, can:

1. **Exchange contact cards** — one shows screen 32 with the card `live`, the other scans or pastes it, sends a request, and sees it waiting — and, when the first accepts, start a DM with no directory involved, with the evidence row reading that the key came from the person and not from a transparency log. Then rotate the card on the first machine and confirm the old link is refused on the second while the conversation just started is untouched.
2. Exchange text in that DM and in a 3-person group.
3. React with an emoji neither of them has used before, through the full picker, and see one pill with a count of two when both send the same one; see read receipts and see the typing indicator render and clear.
4. See the blocking key-change warning when one of them resets their identity, with the §7.2 copy and the §7.3 evidence rows populated correctly.
5. Read the §8.1 strings, verbatim, at the moments specified in §8.1.
6. Operate the whole flow with the keyboard alone, and hear it with Narrator.
7. Do all of it with no UAC prompt, no service installed, and the VPN app not present.
8. Send and accept a group invitation (screen 23) — criterion 2's three-person group cannot otherwise be formed.
9. Install the per-user MSI as a standard user on a machine with no VPN app, sign in, and render in the brand faces — then do it again as a second standard user on the same machine.

#### 16.5.2 Additional acceptance for the public beta (MASTER §14 slice 7, Spec A slice A9)

Multi-device lands here and not before, so these cannot gate the build above.

10. **Link a second computer** from screen 1's link button, with the short code and the six-digit comparison, and send from it.
11. The first machine shows that message as **delivered** and then as **read**, exercising pairing, multi-device and delivery receipts in one pass — the shape of the first thing a beta tester will try.

#### 16.5.3 Additional acceptance for general availability

12. **Find each other through the directory, with a valid inclusion proof**, and see the evidence row change from the out-of-band statement to the transparency-log one. This belongs here and not above because the log, its four client endpoints and its monitor role are a general-availability gate (MASTER §15 item 6), so a build in which it is guaranteed absent cannot be gated on it.

---

## 17. Cross-references

- **Master protocol design**, `docs/specs/2026-08-12-urmessage-protocol-design.md`: §3 invariants, §5 identity and custody, §8 storage and retention classes, §9 message server, §10 verification, §11 roles, §12 deletion and required UI language, §13 honest limits, §15 open items.
- **SPEC-LEDGER.md**: locked decisions P1–P5, I1–I6, T1–T9 (the ledger's own numbering); §6 change process, which this document follows. MASTER §3 carries a *different* invariant list, I1–I8 — where this document cites an `I`, `P` or `T` number it means the ledger's unless it says MASTER.
- **Spec A** (SDK / client core): the entire call and event surface of §14.2, the local store, DPAPI sealing, MLS, and the `URmessageSdk.dll` C ABI.
- **Spec B** (message server): everything in §14.3, plus master §9.
- **VPN client**, `Ryanmello07/urnetwork-windows`: `app/src/App/UrColors.h`, `App.xaml`, `UrComponents.h`, `WindowShell.h`, `Localization.h`, `Common/ConnectionHealth.h`, `Common/ThreadGuard.h`, `app/installer/Package.wxs`, and `docs/superpowers/specs/2026-08-06-ios-parity-native-shell.md` for the native-shell/brand-content rule.
