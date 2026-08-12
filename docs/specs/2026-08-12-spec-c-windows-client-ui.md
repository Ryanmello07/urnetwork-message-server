# URmessage â€” Spec C: Windows Client UI

**Date:** 2026-08-12
**Revision:** 1 â€” first draft, pending owner review
**Status:** Design
**Scope:** the Windows messaging client â€” app shape, screens, copy, states, brand, accessibility
**Depends on:** [URmessage Protocol Design rev 5](../../../claude_sandbox_message/msgrepo/docs/specs/2026-08-12-urmessage-protocol-design.md) (the master spec, cited below as **Â§n**), [SPEC-LEDGER.md](../../../claude_sandbox_message/msgrepo/SPEC-LEDGER.md), Spec A (SDK / protocol client core), Spec B (message server)

---

## 0. Planning ledger

### 0.1 Current state

| Item | State |
|---|---|
| Master protocol design | Revision 5, awaiting owner review |
| Spec A â€” SDK / client core | Being written in parallel |
| Spec B â€” message server | Being written in parallel |
| This spec | Revision 1, first draft |
| `Ryanmello07/urnetwork-message-windows` | Not created |
| Code | None |

The VPN client (`Ryanmello07/urnetwork-windows`, branch `beta/custom-server`) is a shipping, live-tested WinUI 3 / C++/WinRT application with a proven brand kit, localization pipeline, native shell, installer, updater and release train. **This spec reuses that codebase's patterns and assets and shares none of its process model.** Every reuse below names the file it comes from so the team can read the working precedent rather than re-derive it.

### 0.2 Decisions specific to this component

| # | Decision | Why |
|---|---|---|
| **W1** | Separate executable `URmessage.exe`, not a page inside `URnetwork.exe` | The VPN app is a tray flyout sized 480Ã—760 (`WindowShell.h`) whose one screen is a connect button. A messenger is a workspace app with a three-pane layout and a 20k-message virtualized list. Merging them makes `MainWindow.xaml.cpp` â€” already 2128 lines and already the collision point for parallel UI work â€” the collision point for two products. Separate binaries also mean a messaging defect can never take down a VPN tunnel. |
| **W2** | **User-mode only. No service, no driver, no elevation, ever.** | URmessage forwards message traffic through the SDK's own transport. It never captures packets, never rewrites routes, never touches DNS. Every mechanism the VPN client needs to do those things is a mechanism URmessage does not have and must not acquire. Â§0.3 states exactly what that removes. |
| **W3** | All plaintext, all key material, and the entire local message store live **in Go, inside `URmessageSdk.dll`** (Spec A). The C++ layer is a view. | One place holds plaintext, so one place is audited, one place seals to DPAPI, and one store serves the mobile clients that follow. The C++ side holds only what is currently on screen and never writes message content to disk. |
| **W4** | Optional component of the existing MSI, `Level="1000"`, **not installed by default**. Shares one copy of the Windows App Runtime with the VPN app. | Owner's decision, restated in Â§2. The shared runtime keeps the added install size to a few MB rather than the ~319 MB raw / 58 MB zipped a second self-contained WASDK app would cost. |
| **W5** | The client's connection state is a **pure state machine in `Common/MessageHealth.h`** with a selftest-pinned transition table, in the exact shape of the VPN client's `Common/ConnectionHealth.h` (windows `1cfcf3c`). | That pattern was written because ad-hoc status text lied to users for weeks. The same class of lie is worse in a messenger, where "sent" is a claim about someone else's device. |
| **W6** | Seedphrase display uses `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`, clipboard writes use `Clipboard.SetContentWithOptions` with history and roaming disabled, and confirmation is a **typed** quiz over four random positions. | Â§6. This is the screen where the product can permanently destroy a user's data, and the failure mode is silent for months. |
| **W7** | The key-change warning is a **blocking modal that stops outbound sending** until resolved, plus a permanent, non-dismissible inline record in every shared conversation. | Â§10.2 and Â§5.5 of the master spec require it. The exact copy is fixed in Â§7 of this document. |
| **W8** | Verified contacts get **no badge, no colour, no checkmark**. `kProGold` in particular is never reused â€” `UrColors.h` reserves it for the Pro entitlement across the whole product. | Â§10.2: "There is no verified badge." A badge implies the absence of one means something, and it does not. |
| **W9** | Contact and group avatars are **deterministic identicons derived from the pinned identity key** (contacts) or `group_id` (groups). No avatar upload in v1. | No media path, no storage, no moderation surface â€” and a contact's avatar visibly changes when their key changes, which is SSH randomart applied to the one event we most want a user to notice. |
| **W10** | The client's own log has a **field allowlist**. Message content, contact display names, group names and attachment filenames are never logged, at any verbosity, in any build. | The VPN client's `Log.cpp` writes one unbuffered `WriteFile` per line and its logs are routinely collected from testers and pasted into issues. A messenger log collected the same way must be safe to paste. |

### 0.3 What "no privileged service" removes, concretely

Every row is a mechanism the VPN client has and URmessage does not.

| VPN client mechanism | Present in URmessage | What its absence removes |
|---|---|---|
| `urnetworkd.exe` running as LocalSystem | **No** | No SCM registration, no service restart budget, no Event 7031/7034 terminations, no `ServiceSetup` five-state classifier, no Connect banner driving an elevated install |
| UAC elevation, `urnetworkd install` verb | **No** | No admin prompt anywhere in the product. URmessage installs and runs per-user |
| wintun adapter | **No** | No adapter lifecycle, no PnP surprise-removal path, no `WintunDeleteDriver` hazard (which detaches every wintun adapter machine-wide) |
| WFP filters / kill switch | **No** | No firewall state to arm, narrow or disarm; no "my internet is blocked" failure mode; no `RECOVERY.md`, no `revert` verb, no CrashRevert |
| `SplitTunnel.sys` clean-room driver | **No** | No WDK, no driver signing, no `INSTALLDRIVER` feature |
| mTLS loopback RPC (`DeviceLocal.SetRpcServer` / `DeviceRemote`) | **No** | No `rpc_session.json`, no instance-id pairing, and therefore **none of defect #40's reattach class** â€” there is no second process to reattach to |
| Named pipe lifecycle channel | **No** | No `PipeServer`, no `nlohmann::dump()` UTF-8 throw path |
| Two-phase teardown, budgeted abandonment worker | **No** | Nothing to revert. Closing the app is `ExitProcess` after the store flushes |
| Packet pump, egress monitor, route/DNS config | **No** | No dead-tunnel watchdog, no Modern Standby clock rebase, no carrying-veto evaluator |
| Machine state modified at all | **No** | The worst outcome of a URmessage crash is a closed window |

**What remains from the VPN client's runtime:** an in-process URnetwork `Api` (login, profile, account â€” Reachability class **A** in the VPN client's terms) and an in-process connect client for addressed transport. Both are class A: no service, no RPC, no elevation. This is the class of work the VPN project proved is fully parallelizable.

**One interaction to be aware of.** If the VPN tunnel is up, URmessage's traffic goes through it â€” `URmessage.exe` is a separate process and the tunnel's R1 self-exclusion covers only the service's own sockets. That is correct and must not be "fixed" by excluding URmessage from the tunnel: a VPN user would reasonably object to their messenger being the one app routed in the clear. The consequence is that URmessage's health state machine must tolerate the VPN's known control-plane starvation window while the tunnel is `Connecting` (windows spec `2026-08-11-connect-flow-reliability-design.md`), which Â§9.4 handles by not calling a slow server a dead one.

### 0.4 Interfaces to the other two components

Detailed in Â§14. Summary:

| Direction | Contract |
|---|---|
| **C â†’ A** | Everything. The client's only dependency is `URmessageSdk.dll`. It calls the C ABI through a generated C++ wrapper (`urmessage_sdk.hpp`) in the `urmsg::` namespace, and receives events through subscription handles on Go threads which it marshals to the UI with `DispatcherQueue.TryEnqueue`. |
| **C â†’ B** | **None directly.** The client never opens a socket to the message server. Everything about B reaches the UI as state or an event through A. What C *assumes* of B â€” retention semantics, the advertised attachment cap, single-commit retry, fetch attestation, prune-vs-failure distinguishability â€” is enumerated in Â§14.3 as requirements on B surfaced through A. |
| **A â†’ C** | A must expose every state C renders as an explicit, enumerable value. C must never infer a state from the absence of data â€” the VPN client's `Disconnected`-looking-`Connected` bug (#40) came from exactly that inference. |

**Assumption to confirm:** this document reads "Spec A" as the SDK / `connect` protocol client core and "Spec B" as the message server. If the letters map the other way, Â§14's two halves swap and nothing else changes.

### 0.5 Open items

| # | Item | Proposed resolution | Owner sign-off |
|---|---|---|---|
| C-1 | Does the seedphrase confirmation **gate first send**, or only raise a persistent banner? | Gate. A user who has not confirmed cannot send their first message. | Needed |
| C-2 | Lock-screen notification default: name+message, name only, or "New message"? | **Name only**, per-conversation override. | Needed |
| C-3 | Is local message **search** in v1? Not in the master spec's Â§2 list. | Yes â€” local-only, over the local store in A. A messenger without search is below the Signal bar. | Needed |
| C-4 | Windows Hello gate on destructive/revealing actions, and an optional app lock? | Hello gate in v1 for four actions (Â§6.6). App lock deferred. | Needed |
| C-5 | Master Â§15 open item 1 â€” retention floor exceeds the server's minimum: warn and proceed, or refuse? | **Warn and proceed**, with the group's effective policy shown as the server's, not the requested one. Copy in Â§8.4. | Needed (also blocks B) |
| C-6 | Master Â§15 open item 2 â€” push transport. WNS raw push requires operator-side work that does not exist. | Ship v1 with tray presence as the delivery mechanism; WNS raw wake behind the same renderer, enabled when the operator side lands. Â§10. | Needed (also blocks A and B) |
| C-7 | Disabling read receipts also hides others' receipts from you (Signal parity)? | Yes. | Needed |
| C-8 | EPH bucket numbering. Â§12.2 lists five durations and reserves bucket 0 for receipts. | User buckets 1â€“5 = 1h / 8h / 1d / 1w / 4w. Confirm with A. | Needed |
| C-9 | Copy for "Delete for me" â€” master Â§12.4 does not cover it and silence here would be dishonest. | Proposed string in Â§8.2. | Needed |

### 0.6 Edit log

Append-only. Newest last. One entry per commit that changes this spec. Every change follows SPEC-LEDGER Â§6: edit, subagent reviews the **diff**, fix findings, commit with the ledger entry, append here.

*(no entries yet)*

---

## 1. App shape

### 1.1 Process and identity

| Property | Value |
|---|---|
| Executable | `URmessage.exe` |
| Framework | WinUI 3 / C++/WinRT, Windows App SDK 2.2, **self-contained**, unpackaged |
| Architectures | x64, ARM64 â€” both, from the first CI run, matching the VPN client's matrix |
| Runtime dependency | `URmessageSdk.dll` (cgo `c-shared`), load-time import |
| Privilege | Standard user. The manifest requests `asInvoker` and the app **must fail to build** if any `requireAdministrator` or `highestAvailable` appears in it (CI check) |
| Single-instance key | `ids::kMessageSingleInstanceKey` â€” **must differ from the VPN app's `ids::kSingleInstanceKey`**, which is fixed. Reusing it redirects URmessage's activation into the VPN app's window |
| URI scheme | `urmessage://` (deep links, invite links). The VPN app owns `urnetwork://`; no collision |
| Data root | `%LOCALAPPDATA%\URmessage\` â€” `app\logs\`, `app\storage\` (owned by A), `app\prefs.json` |
| Min OS | Windows 10 21H2 (Mica degrades to the solid brand background, as in `WindowShell.h`) |

### 1.2 Window shell

Reuse `urnw::shell::ApplyNativeShell` from `app/src/App/WindowShell.h` verbatim in behaviour â€” Mica backdrop with the brand background as `FallbackColor`, extended title bar with caption buttons tinted to the brand surface, placement restored and clamped to a monitor that exists, `SaveWindowPlacement` on hide and quit. Change only the constants:

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
| â‰¥ 1000 | **Two pane.** List (360 fixed) + thread (fills). Details open as a `ContentDialog` sheet on `UrSheetBrush` |
| â‰¥ 1500 (`kMessageThirdPaneDip`) | **Three pane.** List (360) + thread (fills) + details rail (360). The rail shows the current conversation's members, media, and retention |

**Do not use `AdaptiveTrigger` or `VisualStateManager`.** This is measured, not read in a doc, and is recorded in `UrComponents.h`: `AdaptiveTrigger` listens on `Window.Current`, which is `null` in a WinUI 3 desktop app; and `VisualStateGroup`s attached to a plain layout `Grid` are never processed even when the trigger goes active. Follow `MainWindow::ApplyBreakpoint` â€” one window-level function, named columns in markup, one place that decides what "wide" means.

### 1.4 Tray presence and lifecycle

| Behaviour | v1 |
|---|---|
| Tray icon | Yes. Own icon set, visually distinct from the VPN tray icons (`tray_*_provide_connect.ico` etc.), light and dark variants |
| Close button | Hides to tray by default; a Settings option makes it quit. First close shows a one-time flyout explaining it |
| Run at login | **Opt-in**, offered once after the first conversation is created. Not defaulted â€” the VPN client's D8 finding ("tunnel auto-starts on resume/login") ended in the owner's rule: **click-only** |
| Background receipt | While the process is running (tray or window), the connect session stays up and records are received and decrypted |
| Process not running | Records queue at the message server. They arrive on next launch. If C-6 resolves in favour of WNS raw wake, a contentless push COM-activates the app; Â§10.2 |
| Quit | Drain the UI's pending SDK calls, then stop the session, then exit. The VPN client's D3 (`0xc000027b` on tray-quit, an unobserved WinRT async surfacing during `DispatcherQueue` teardown) is the failure this drain prevents |

---

## 2. Installer relationship

### 2.1 Feature

URmessage is an **optional feature of the existing `app/installer/Package.wxs`**, off by default:

```xml
<Feature Id="Messaging"
         Title="URmessage"
         Description="Private messaging on URnetwork. Installs a separate app; does not change your VPN."
         Level="1000"
         AllowAdvertise="no">
  <ComponentRef Id="MessageAppExe" />
  <ComponentRef Id="MessageSdkDll" />
  <ComponentRef Id="MessageResourcesPri" />
  <ComponentRef Id="MessageUriScheme" />
</Feature>
```

`Level="1000"` against the default `INSTALLLEVEL` of 1 is the mechanism: the feature is present in the package and absent from a default install. The package gains `WixUI_FeatureTree` (`WixToolset.UI.wixext`) so the feature is selectable, and `ADDLOCAL=Messaging` works for command-line and managed installs.

### 2.2 Shared payload, separate app

Both apps install into the same `INSTALLFOLDER` (`ProgramFiles64Folder\URnetwork`) and **share the one `RuntimeFiles` ComponentGroup** â€” the self-contained Windows App Runtime, which is the bulk of the payload. The Messaging feature adds only:

| File | Notes |
|---|---|
| `URmessage.exe` | |
| `URmessageSdk.dll` | Separate from `URnetworkSdk.dll` so VPN builds are untouched (shared context) |
| `URmessage.pri` | **Not `resources.pri`** â€” that name is taken by the VPN app in the same folder. `URmessage.exe` must construct `Microsoft.Windows.ApplicationModel.Resources.ResourceManager(L"URmessage.pri")` explicitly rather than relying on the default lookup |
| `Software\Classes\urmessage` registry key | Mirrors the existing `UriScheme` component, pointing at `URmessage.exe` |
| Advertised Start Menu shortcut | **Must be advertised** in a perMachine package â€” ICE43/ICE57 fail a non-advertised one. Child of the `MessageAppExe` component whose keypath is the exe. Plus `ARPPRODUCTICON` parity |

### 2.3 Updater

`UpdateChecker` (VPN app) polls the fork's releases, verifies the GitHub per-asset `digest` field, extracts with `tar.exe`, and performs an allowlisted rename-swap. Two changes:

1. Add `URmessage.exe`, `URmessageSdk.dll`, `URmessage.pri` to the swap allowlist.
2. The mismatch banner already reads the **running** image, not `binPath`. URmessage has no service, so a swapped `URmessage.exe` is picked up on next launch and the banner says so: *"An update is ready. Restart URmessage to use it."* â€” one click, no elevation.

### 2.4 Portable zip

The release zips already carry the runtime. When the messaging feature is built, its three files go into the same zip. No second zip, no second release, no second tag: the version grammar (`Common/Version.h`, `Common/VersionGrammar.h`, `kString`/`kCode`) is shared and both apps stamp the same tag.

### 2.5 Independence

**URmessage must run with the VPN service absent, stopped, or broken.** CI must include a check that `URmessage.exe` starts, reaches the login screen, and logs in on a machine where `urnetworkd` was never installed. This is the single most likely regression from sharing an installer, and it is the whole point of W2.

---

## 3. Screen inventory (v1)

The table is the contract; the sections that follow expand the four screens that carry real risk. Every screen's empty, loading, and error states are in Â§9.

| # | Screen | Shows | States |
|---|---|---|---|
| 1 | **Welcome** | Wordmark, one sentence, two buttons: *Set up URmessage* / *I already have a recovery phrase* | first-run only |
| 2 | **URnetwork account** | Sign in or create. Reuses `LoginPage` / `LoginCarousel` / `AuthSheets` / `GoogleSignIn` from the VPN app | signed-out, submitting, error, signed-in |
| 3 | **Identity intro** | What the recovery phrase is, that it is generated here and never sent, that losing it loses history. One "Create my phrase" button | static |
| 4 | **Seedphrase display** | 24 words, 4Ã—6 numbered grid, mono face. Copy / Save to file / Continue | capture-blocked, obscured (window inactive), dwell-locked, ready |
| 5 | **Seedphrase confirmation** | Four random positions, typed entry, BIP39 autocomplete | empty, partial, wrong (â†’ back to 4), confirmed |
| 6 | **Restore â€” phrase entry** | 24 fields, whole-phrase paste, per-word validity, checksum check | empty, partial, word-not-in-list, checksum-failed, valid |
| 7 | **Restore â€” progress** | Finding groups â†’ restoring history, per-group rows | working, complete, partial, nothing-found, read-only-outcome (Â§6.7) |
| 8 | **Link a device** | Existing device: QR + typed pairing code + SAS. New device: code entry + SAS | waiting, paired, SAS-compare, approved, refused, timed-out |
| 9 | **Conversation list** | Rows: identicon, name, last-message preview, time, unread count, muted glyph, disappearing-timer glyph. Search box. New-conversation button | empty, loading, populated, filtered-no-results, offline banner, server-unreachable banner |
| 10 | **Conversation view** | Virtualized message list, day separators, system records, composer, disappearing chip, attachment button | empty, loading-history, at-top (no more history), populated, read-only (observer / restored / removed), blocked-by-key-change, fork-detected |
| 11 | **Message context menu** | React, Reply, Copy, Save attachment, Message info, Delete for me, Delete for everyone | per-message; delete-for-everyone hidden when not the sender |
| 12 | **Message info** | Sent/delivered/read per member, size bucket, retention class, epoch, sender leaf | own messages and received |
| 13 | **New conversation** | Directory lookup by URnetwork principal, recent contacts, "New group" | empty query, searching, results, no-results, lookup-failed, KT-proof-failed |
| 14 | **Group creation** | Name, members picker, retention, disappearing default | drafting, creating, created, failed |
| 15 | **Group details** | Members with roles, invite, retention, disappearing, history-grant banner, leave | member view, admin view, owner view |
| 16 | **Member detail** | Identicon, principal, safety number, role controls, remove, device count | self, member, admin, owner, unpinned, pinned, key-changed |
| 17 | **Safety number** | 60 digits in 12 groups of 5, mono; QR; Copy; "Mark as verified locally" | unpinned, pinned, changed-unaccepted, changed-accepted |
| 18 | **Key-change warning** | The blocking sheet. Exact copy in Â§7 | blocking (modal), resolved, in-thread permanent record |
| 19 | **My devices** | This device + others: name, added date, last seen. Add device, Remove device | one device, several, removing, removed |
| 20 | **Settings** | Seven groups; Â§12 | â€” |
| 21 | **Attachment viewer** | Image or file. Save as, Open with | loading, loaded, expired-by-policy, download-failed, too-large |
| 22 | **About** | Version, `kCode`, message server host, licences, `THIRD-PARTY-NOTICES.txt` | static |

Screens 1â€“8 are the onboarding stack and never appear again once complete (except 8 and the phrase re-display in Settings). Screens 9â€“10 are the app.

---

## 4. Conversation list

### 4.1 Row anatomy

| Element | Token / style |
|---|---|
| Identicon, 40Ã—40, rounded 8 | Â§11.5 |
| Display name | `UrRowTitleStyle` |
| Last-message preview, one line, ellipsized | `UrRowNoteStyle` |
| Timestamp, right, relative under 7 days | `UrCaptionTextStyle`, `UrTextMutedBrush` |
| Unread pill | `UrAccentBrush` fill, `UrInverseTextBrush` text |
| Muted glyph, disappearing-timer glyph | `UrRowIconStyle`, `UrTextMutedBrush` |
| Row container | `UrCardRowButtonStyle` (hover/press from `UrCardHoverBrush` / `UrCardPressedBrush`) |

**A row never shows a delivery-state colour.** Delivery is a glyph in the thread (Â§5.3), not a colour in the list â€” colour cannot carry state alone (Â§13.4).

### 4.2 Preview and the disappearing class

A conversation whose disappearing timer is on shows a **timer glyph in place of the preview text**, not the text. The message's plaintext is `EPH`-class and its key is destroyed on a timer; a preview cached in a list row that survives the timer would defeat Â§12.1's guarantee at the UI layer. The list stores no preview for `EPH` conversations â€” it re-reads from A, and A returns nothing once the key is gone.

### 4.3 Ordering, muting, unread

Ordered by last activity. Muted conversations stay in order but never raise a notification and never bold. Unread is per-conversation and clears on the thread becoming visible **and focused** for 1 second â€” not on scroll-into-view, which marks things read that a user glanced past.

---

## 5. Conversation view

### 5.1 The list

`ItemsRepeater` inside a `ScrollViewer`, virtualized, with incremental loading upward. A group of 500 people with two years of history is the design target (P4); the list must never materialize more than a window of items. Anchoring: on new-item append, hold scroll position unless the user is within 80 DIP of the bottom, in which case follow.

Day separators, and a system-record row type rendered as a centred, muted, non-bubble line. System records in v1:

| Record | Rendered |
|---|---|
| Member added / removed / left | "Ana added Bo." |
| Role changed | "Ana made Bo an admin." |
| Disappearing timer changed | "Ana set messages to disappear after 1 day." + the Â§8.1 string on the first change |
| Key change (`KEY_CHANGE_NOTICE`) | **Permanent, non-dismissible.** Â§7.4 |
| History grant | **Persistent banner**, not a row â€” Â§5.5 |
| Retention policy changed | "Ana set media to be kept for 1 month." |
| Observer message hidden | "A message from an observer was hidden." (Â§5.6) |

### 5.2 Bubbles

| | Incoming | Outgoing |
|---|---|---|
| Fill | `UrCardBrush` (#1C1C1C) | `UrCardHoverBrush` (#242424) |
| Border | none | 1px `UrBorderBrush` |
| Alignment | left | right |
| Text | `UrBodyTextStyle`, `UrTextBrush`, `UrBodyFontFamily` | same |
| Max width | 68% of the thread column, capped at 640 DIP | same |

`UrAccentBrush` (#EFF7BB) is **not** a bubble fill. It is the primary action colour â€” the send button, the primary button in every sheet â€” and a screen of pale-yellow bubbles would leave nothing for the action. Message text uses the body face, never `UrHeadingFontFamily`: ABC Gravity Extended is a display face and is unreadable at body size and length.

Sender name and identicon appear on the first bubble of a run in groups, never in DMs.

### 5.3 Delivery state

Glyphs, right-aligned under the last outgoing bubble of a run. Never colour alone.

| State | Glyph | Meaning |
|---|---|---|
| Queued | clock | In the local outbox; not yet accepted by the server |
| Sent | one check | Accepted by the message server |
| Delivered | two checks | At least one device of every other member has fetched it |
| Read | two checks, filled | Read receipt received (only if both sides have receipts on) |
| Failed | exclamation, `UrDangerBrush` | Tap for reason + Retry |

"Delivered" is a claim about other people's devices. A tooltip and Message info (screen 12) say what it is derived from, so a user who cares can find out that it means *fetched*, not *seen*.

### 5.4 Composer

- `Enter` sends, `Shift+Enter` newline. Reversible in Settings; the setting is announced in the composer's `AutomationProperties.HelpText`.
- Multi-line, grows to 6 lines then scrolls.
- Attachment button, disappearing-timer chip, emoji button.
- Drag-and-drop onto the thread attaches. `Ctrl+V` of an image attaches it.
- **Disabled states** carry an inline reason above the composer, never a silently greyed box: read-only (observer, restored-without-leaf, removed from group), blocked by an unresolved key change, fork detected.

### 5.5 History grant banner

Â§11 requires this be persistent for the life of the group. A pinned banner above the composer, `UrCardBrush` with a `UrBorderStrongBrush` top edge, never dismissible:

> **Ana granted Bo access to messages from 3 March 2026 onward.**
> History grants cannot be undone and stay visible here for as long as this group exists.

### 5.6 Observers

`OBSERVER` is enforced in the UI and by MLS proposal rules, **not by the server** (Â§9.2, Â§11). An observer holds the group keys and a modified client could encrypt a valid application message. The client's behaviour and its copy must match that truth:

- An observer's composer is disabled with the reason *"You can read this group but not send to it."*
- Receiving clients **hide** application messages whose sender leaf holds `OBSERVER` in the transcript-covered group-context extension, collapsing them to the system row in Â§5.1. Expanding shows the content with a warning.
- Group settings, on the observer row: *"Observers are asked not to send. Someone who modifies their app can still send, and this version of URmessage cannot stop it at the server â€” it can only hide the result."*

---

## 6. The seedphrase

This is the highest-stakes surface in the product. A user who does not record the phrase loses every durable message in every group, permanently, and does not find out for months. Everything in this section is normative.

### 6.1 What the phrase is, stated before it is shown

Screen 3 comes **before** generation, is a single column, and says exactly this:

> ### Your recovery phrase
>
> URmessage is about to create 24 words on this computer. They are the only way to get your messages back if you lose this device.
>
> - The words are made here and are **never sent anywhere** â€” not to URnetwork, not to us.
> - They are **not** your URnetwork account phrase. That one is a password. This one is a key.
> - If you lose them, your message history is gone. Nobody can reset it or send you a copy.
> - Anyone who has them can read everything you have ever sent and can act as you.
>
> Have somewhere to write them down before you continue.
>
> `[ Create my phrase ]`

Two facts are load-bearing and both come from the master spec: the two phrases are separate secrets (Â§5.1) and the phrase cannot be recovered (Â§5.5, Â§13). Users conflate the two phrases if you do not say so on the screen where it matters.

### 6.2 Display (screen 4)

**Layout.** 24 words in a 4-column Ã— 6-row grid, each cell showing `nn` in `UrTextMutedBrush` and the word in `UrMonoFontFamily` at `UrBodyLargeTextStyle`. Column-major numbering (1â€“6 down the first column) so a user transcribing top-to-bottom on paper matches.

**Capture protection.**

| Mechanism | Rule |
|---|---|
| `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` on entering the screen, `WDA_NONE` on leaving | Blocks screenshots, screen recorders, and shared-screen calls. It is the single highest-value line of code on this screen: a phrase screenshotted into OneDrive is a phrase in the cloud |
| `GetSystemMetrics(SM_REMOTESESSION)` | If non-zero, **skip the affinity** (it would black the window for the only person who can read it) and show an inline warning instead: *"You are on a remote session. These words are travelling over that connection. Consider doing this on the machine itself."* |
| "Show anyway" escape | If a user reports a black window (some capture-adjacent drivers), one button drops the affinity for this session with a confirm: *"Screenshots and screen sharing will be able to see your phrase."* |
| Window deactivation | The grid **blurs and overlays** with "Click to show your phrase again". It does **not** navigate away â€” a user alt-tabbing to a password manager must not lose their place |

**Copy to clipboard.** Allowed, because forbidding it pushes users to photograph the screen, which is worse. But:

- `Clipboard.SetContentWithOptions` with `IsAllowedInHistory = false` and `IsRoamable = false`. Windows clipboard history syncs across devices through a Microsoft account; a phrase that lands there has been transmitted, which the screen just promised would not happen.
- The clipboard is cleared 60 seconds later (only if our content is still on it).
- A one-time confirm: *"Your phrase will be on the clipboard for 60 seconds. Paste it into your password manager now, not into a chat or a document."*

**Save to a file.** `FileSavePicker` â€” in an unpackaged WinUI 3 app this **must** be initialized with `IInitializeWithWindow::Initialize(hwnd)` or it throws; the same applies to `FileOpenPicker` in Â§12.6. Default filename `URmessage recovery phrase.txt`, plain text, no encryption (an encrypted file needs a password the user will also lose). Confirm first: *"This writes your phrase to a file in plain text. Anyone who can read that file can read your messages. Put it somewhere you would put a passport."*

**Print.** Not in v1. `PrintManager` in an unpackaged app is disproportionate work for this screen. Save-to-file plus the user's own printer covers it.

**The dwell lock.** `[ I've written it down ]` is disabled for the first 15 seconds and shows a live reason beside it: *"Take a moment â€” you'll be asked for four of these words next."* A disabled button with no explanation reads as a broken app; a disabled button with a countdown reads as a deliberate pause, which is what it is.

### 6.3 Confirmation (screen 5)

**Typed, not multiple choice.** Multiple choice is defeated by clicking, teaches nothing, and passes for a user who never wrote anything down.

- Four positions chosen uniformly at random from 1â€“24, presented in ascending order, labelled by position ("Word 7").
- Text fields with BIP39 autocomplete over the full 2048-word list. **The dropdown must never be filtered to the correct answer** â€” it is a typing aid, not a hint.
- All four are checked on submit, not per-field: per-field checking turns the screen into an oracle.
- **A wrong answer returns the user to screen 4**, with a fresh set of four positions on the next attempt, and this line: *"That didn't match. Here are your words again â€” check what you wrote down against them, line by line."* Two failures in a row adds: *"If what you wrote down doesn't match, write it again now. There is no way to get these words back later."*
- On success: the local store records `phrase_confirmed_at`. **Per C-1, sending is gated on this flag.**

### 6.4 Never confirmed

A user who quits during onboarding after generation but before confirmation lands in a defined state, not a hole:

- The identity exists and works for reading.
- A persistent, non-dismissible banner at the top of the conversation list: **"Back up your recovery phrase"** / *"You have not written down the 24 words for this account. Without them, everything here is lost if this computer is."* / `[ Show my phrase ]`
- Per C-1, the composer is disabled with that same reason until confirmed.

### 6.5 Re-display from Settings

Settings â†’ Account â†’ **Show my recovery phrase**. Gated by Windows Hello (Â§6.6), then the same screen 4 with the same protections, then the same confirmation quiz on exit. There is no path in the product that shows the phrase without also asking the user to prove they have it.

### 6.6 Windows Hello gate (C-4)

`IUserConsentVerifierInterop::RequestVerificationForWindowAsync(hwnd, ...)` â€” the plain `UserConsentVerifier` static throws in a desktop app without the interop cast. Gate exactly four actions, and no others (a gate on everything is a gate on nothing):

1. Show the recovery phrase.
2. Accept a changed identity key (Â§7).
3. Remove a device from your own device list.
4. Leave or delete a group you own.

When Hello is unavailable (`UserConsentVerifierAvailability` â‰  `Available`), the action proceeds behind a typed confirmation instead â€” the word `REMOVE` for 3, the contact's display name for 2 â€” never silently unlocked.

### 6.7 Restore (screens 6 and 7)

**Entry.** 24 fields in the same 4Ã—6 grid, `UrMonoFontFamily`. Whole-phrase paste into any field splits on whitespace and fills all 24. Normalization before every check: NFKD, lowercase, collapse internal whitespace. Per-field state: neutral, in-list (subtle), not-in-list (`UrDangerBrush` underline + the field's supporting line, via `urnw::kit::ValidationState`).

Three distinguishable failures, because "invalid phrase" tells a user nothing:

| Condition | Message |
|---|---|
| One or more words not in the BIP39 list | "Word 12 (**apricott**) isn't one of the 2048 words. Check the spelling." |
| All 24 in the list, checksum fails | "All of these are real words, but the phrase's built-in check failed â€” one of them is in the wrong place or is the wrong word. Compare against what you wrote down." |
| Fewer than 24 filled | "You need all 24 words." â€” Continue stays disabled |

**Progress.** Seed-only restore (Â§5.4) derives `recovery_handle`, asks the server for archive records indexed under it, and unwraps per-group. Show it as work being done, per group, because it can take minutes:

```
Finding your groupsâ€¦                        done â€” 6 found
Restoring "Design"          â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–‘â–‘      1,204 of 1,540 messages
Restoring "Ana"             â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ      done
Restoring "Weekend"         â€”               waiting
```

**Outcomes.** Four, all rendered explicitly:

| Outcome | Screen |
|---|---|
| Full | "Restored 6 conversations." â†’ conversation list |
| Partial | Lists which groups restored fully and which are missing history, with the reason from A (pruned media, missing archive wrap, epoch gap). "Some history could not be restored. The messages below the marker are all this server still has." |
| Nothing found | "This phrase is valid, but the server has no history stored for it. If you meant to start fresh, you can â€” this identity works." |
| **Restored, read-only** | Â§6.8 |

### 6.8 The read-only restore state â€” surface this, do not hide it

A user who kept the phrase but lost **every** device is in a state the master spec implies and does not name. `recovery_root` reconstructs the recovery key and `archive_secret[n]` decrypts history (Â§8.2). But **every MLS leaf signature key was generated on-device and is not seed-derivable (I2)**, so the restored device has no valid leaf and cannot sign a `PrivateMessage`. It can read; it cannot send, and it cannot self-service its own leaf because self-service requires a live leaf to commit from (Â§11).

The client must render this, per group:

> **You can read this conversation but not send to it yet.**
> Your recovery phrase brought back the history, but the devices that could send here are gone. An admin needs to add this computer back to the group.
> `[ Ask an admin ]` `[ What does this mean? ]`

If the user still has **one** live device elsewhere, the correct path is device provisioning (screen 8) from that device, and the client must say so instead: *"Do you still have another computer or phone signed in? Linking from it is faster and doesn't need an admin."*

**Flag to Spec A:** A must expose per-group `can_send` with a reason enum covering `no_leaf_after_restore`, `observer`, `removed`, `key_change_unresolved`, `fork_detected`. C must never infer this from a send failing.

---

## 7. The key-change warning

### 7.1 Behaviour

| Rule | |
|---|---|
| Trigger | A resolution of a contact's `identity` key differs from the pinned one (Â§10.2). A contact with no pin never triggers it |
| Modality | **Blocking modal** over the conversation. Not a toast, not a banner, not an inline row alone |
| Effect while unresolved | **Outbound sending to that contact, and to every group containing them, is disabled.** Incoming messages still arrive and are shown, flagged |
| Dismissal | "Not now" closes the modal and leaves sending disabled. The conversation shows a persistent bar with `[ Review ]` |
| Acceptance | Requires the Windows Hello gate (Â§6.6) or the typed-name fallback. Never a single click |
| Auto-accept | **Prohibited.** No timeout, no "trust on next launch", no setting that disables the warning |
| Record | Permanent, non-dismissible in-thread record in every shared group (Â§10.2) |

### 7.2 Exact copy

Field values come from A. Nothing here is paraphrasable; it goes into the localization store as one block with a translator note (Â§8.5).

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
> Until you accept this, messages you send to Ana â€” here and in **3 groups you share** â€” will not be sent.
>
> The safest thing is to reach Ana some other way and compare safety numbers.
>
> `[ Compare safety numbers ]`  `[ Accept the new key ]`  `[ Not now ]`

### 7.3 The evidence lines are data

`evidence_class` comes from A (Â§5.5 of the master spec records it). Render one line per row; never invent a claim the evidence does not support.

| `evidence_class` | "Who asserted the change" | "Signed by the old key" |
|---|---|---|
| `OPERATOR_ASSERTED` | the URnetwork operator | **No** |
| `SELF_SIGNED_ROTATION` | Ana's previous key | **Yes** |
| `OPERATOR_RESET` | the URnetwork operator, after an account reset | **No** |
| `KT_INCLUSION_ONLY` | the key transparency log, with no other evidence | **No** |
| `UNKNOWN` | *unknown* | **Unknown** |

`SELF_SIGNED_ROTATION` is the only row that gets a softening sentence, and even then the modal still blocks: *"Ana's old key signed this change, which is what an ordinary new-device setup looks like."*

### 7.4 The permanent record

Written into every shared conversation, non-dismissible, `UrDangerBrush` left rule at 2px:

Unaccepted:
> **Ana's safety number changed on 11 August 2026.** You have not accepted it. Messages you send here are not being sent. `[ Review ]`

Accepted:
> **Ana's safety number changed on 11 August 2026, and you accepted it on 11 August 2026.**

### 7.5 Prohibited

- The word "verified" anywhere outside a safety-number comparison the user performed.
- Any badge, tick, shield or colour that marks a contact as trusted (W8).
- `kProGold` on this screen or any security surface. It means "Pro" and nothing else.
- A settings toggle that suppresses these warnings.
- Showing this warning for a contact with no prior pin. A first sighting is not a change (Â§10.2).

### 7.6 The server key changes too

Â§9.4 pins the message server's long-term Ed25519 key on first contact. If it changes, the same shape of modal, app-wide rather than per-conversation, and blocking all sending:

> ## The message server's key changed
>
> URmessage pinned this server's key when it first connected. The key it is presenting now is different.
>
> This server cannot read your messages either way â€” that protection does not depend on this key. What this key proves is that you are talking to the same server as before, and right now that cannot be proven.
>
> | | |
> |---|---|
> | Server | **message.ur.network** |
> | Key first seen | **3 March 2026** |
> | Key changed | **11 August 2026, 09:14** |
>
> `[ Accept the new key ]`  `[ Stay disconnected ]`

---

## 8. Required UI language

### 8.1 Verbatim strings from master Â§12.4

These three are **normative in the master spec** and must appear character-for-character in the English store. A CI lint (Â§15.3) fails the build if the key is missing or the English value drifts.

| Key | String | Where it appears |
|---|---|---|
| `msg_disappearing_explainer` | "After the timer, this message can no longer be read by anyone â€” the key is destroyed on every device and on the server." | On the sheet that turns disappearing messages on, and in the first system record when a timer is set in a conversation |
| `msg_delete_for_everyone_explainer` | "Removed from this conversation on every device that is online and honest. Anyone who already read it may have kept a copy, and we cannot detect that." | On the Delete-for-everyone confirmation, before the destructive button |
| `msg_durable_default_explainer` | "Messages are kept so your new devices can see your history. That means the server holds a copy until it's deleted or expires." | Settings â†’ Privacy & retention, at the top; and once during onboarding on the first conversation |

**Prohibited across the whole string store:** "gone forever", "deleted forever", "permanently deleted", "erased forever", "nobody can ever see this" â€” anywhere they could attach to the `DURABLE` class. Master Â§12.4: *"Never say 'gone forever' for the durable class."* The lint checks for these substrings and allowlists only the ephemeral-context keys.

### 8.2 Delete for me (C-9 â€” proposed, needs sign-off)

Master Â§12.4 does not cover it, and the honest thing must be said:

> **Delete for me**
> Removed from this computer only. Your other devices still have it, everyone else still has it, and the server still has its copy until it expires.
> `[ Cancel ]` `[ Delete for me ]`

### 8.3 Disappearing messages, on by choice

Off by default (T6). The sheet that turns them on shows `msg_disappearing_explainer` above the bucket picker, and a second line about attachments (Â§12.2 of the master spec: an attachment on an ephemeral parent inherits the parent's key class):

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

> Saving this keeps it after the timer. The copy on your disk is yours to manage â€” URmessage cannot delete it.

### 8.4 Retention floor conflict (C-5 â€” proposed)

When a requested group retention is shorter than the server's advertised minimum, the client warns and proceeds, and **shows the effective policy, not the requested one**:

> This server keeps messages for at least **30 days**. Your setting of 7 days can't be applied here â€” the group's messages will be kept for 30 days.
> `[ Use 30 days ]` `[ Cancel ]`

### 8.5 Localization

Strings live in the shared store (`@urnetwork/localizations`, `npm run gen` â†’ `Strings/<locale>/Resources.resw`, read through `urnw::Localized` / `Format` / `Plural`). 28 locales ship today and the VPN app already carries 916 English keys of which only 248 are used â€” **the string you need may already exist**; check before adding.

Three rules for this product's strings:

1. The Â§8.1 strings carry a translator note: *"Legal/security-critical. Translate meaning exactly. Do not soften, shorten, or add reassurance."*
2. Never build a security sentence by concatenating fragments â€” translations reorder, and a reordered warning can invert.
3. Every count uses `Plural()` with a CLDR rule, never `"%d messages"`.

---

## 9. Empty, error, offline, and unreachable

### 9.1 Empty states

Use `urnw::kit::MakeEmptyState(glyph, text)` â€” a large muted Segoe Fluent glyph over one sentence, centred. The header comment on that function records why it exists: a bare "â€“" cannot distinguish *nothing* from *not loaded* from *failed*, and both shipped in the VPN app. Never a bare dash, never an empty panel.

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

### 9.2 The health state machine

`Common/MessageHealth.h` â€” pure, no WinRT, no I/O, unit-testable, with a **selftest-pinned transition table**, exactly as `Common/ConnectionHealth.h` is.

| State | Meaning | UI |
|---|---|---|
| `NoAccount` | No URnetwork account / `ByJwt` (Â§4.4) | Sign-in screen |
| `Offline` | No network on the machine | Banner: "You're offline." Composer works; sends queue |
| `Connecting` | Transport coming up | Thin indeterminate bar in the title area only. **No banner for the first 5 seconds** |
| `Reachable` | Session up, server responding | No chrome at all |
| `Degraded` | Session up, fetches slow or partially failing | Banner: "Messages are arriving slowly." Sends still attempted |
| `ServerUnreachable` | Server has failed the reachability rule (Â§9.4) | Banner, Â§9.4 copy |
| `Blocked` | Unresolved key change or server key change | Banner + the modal (Â§7) |

Rules taken from the VPN client's hard-won experience with this exact pattern:

- **Hysteresis is one-sided.** Entering a worse state takes 7 seconds of evidence; leaving it is immediate. A messenger that flashes "offline" on a 300 ms hiccup is worse than one that is 7 seconds late to say so.
- **Measure the evaluator's own tick gap.** Windows 11 Modern Standby freezes threads while `steady_clock` advances; a laptop closed overnight will otherwise resume straight into `ServerUnreachable`. If a tick arrives â‰¥5Ã— late, rebase the session rather than judging it. This is defect F2 from the VPN watchdog, and it will recur here verbatim.
- **A carrying veto.** If any record was received within the window, the state cannot be worse than `Degraded`, regardless of what a getter says. F1 in the VPN client was a watchdog judging the SDK's health by a call that blocked on a lock the data path never touches.

### 9.3 Send failures

Every failure gets a reason and an action. Never a bare code, never a silent retry that never ends.

| Reason from A | Row copy | Action |
|---|---|---|
| `offline` | "Waiting for a connection" | auto, no button |
| `server_unreachable` | "Waiting for the message server" | auto |
| `commit_lost` | *(nothing â€” see below)* | silent |
| `key_change_unresolved` | "Blocked â€” Ana's safety number changed" | `[ Review ]` |
| `not_a_member` | "You're not in this group any more" | none |
| `observer` | "You can read this group but not send to it" | none |
| `no_leaf_after_restore` | "This computer needs to be added back to the group" | `[ Ask an admin ]` |
| `too_large` | "That file is larger than this server accepts (100 MB)" | `[ Choose another ]` |
| `retention_refused` | Â§8.4 | `[ Use 30 days ]` |
| `fork_detected` | Â§9.5 | blocking |

**`commit_lost` is invisible.** Â§9.3 of the master spec: the server accepts one commit per `(group_id, epoch)`, first valid wins, and returns the winner so the loser re-derives and retries. That is a normal race, several times a second in a busy group. It must never surface as an error, a spinner, or a re-ordered message. A user changing a group name at the same moment as someone else sees their change apply a beat later, and nothing else.

### 9.4 When the single server is unreachable

v1 has one message server (T1) and, if it is lost, the groups are lost (T3, Â§13). The client must not pretend a temporary outage is permanent, nor imply a permanent loss is temporary.

**The rule:** `ServerUnreachable` requires â‰¥3 consecutive failed fetch/send attempts spanning â‰¥20 seconds, with the machine online, *and* no record received in that window. This survives the VPN tunnel's `Connecting` starvation window (Â§0.3) without calling a slow server a dead one.

**Under 2 minutes** â€” a thin banner above the conversation list, no modal, composer fully enabled:

> Can't reach the message server. Messages you send will go out when it's back.

**Over 2 minutes** â€” the banner expands with a timestamp and a manual retry:

> **Can't reach the message server** â€” last contact 09:14, 6 minutes ago.
> You can keep reading and keep writing. Anything you send is held on this computer until the server answers.
> `[ Try again ]` `[ What's happening? ]`

**"What's happening?"** â€” a sheet that tells the truth from Â§13 without alarming a user during a 10-minute outage:

> URmessage v1 uses a single message server. While it's unreachable, nothing new arrives and nothing you send goes out. Everything already on this computer stays readable.
>
> Your messages are not readable by that server â€” that doesn't change whether it's up or down.
>
> Being able to choose or move between servers is planned for a later version.

**The outbox has a bound.** After 500 queued records or 7 days, the oldest queued items stop retrying and are shown as failed with `[ Retry ]`, rather than growing without limit and retrying forever.

### 9.5 Fork detection â€” the one hard stop

Â§8.1 / Â§9.3: MLS gives fork *detection* via `confirmed_transcript_hash` and `confirmation_tag`. A mismatch means this client's view of the group and another's have diverged â€” the one condition where continuing would show messages that other members are not seeing, or vice versa. The client stops:

> ## This conversation could not be verified
>
> URmessage checks that everyone in **Design** is seeing the same history. That check just failed, which means your copy and someone else's have gone out of step.
>
> This can happen after a server problem. It can also happen if records were changed or withheld.
>
> Sending here is stopped until it's resolved. Nothing already on this computer is lost.
>
> `[ Try to resync ]`  `[ Copy diagnostic ]`

`[ Copy diagnostic]` copies group id (8-hex truncated), epoch, both transcript hashes, and the app version. No content, no names.

### 9.6 Fetch attestation gap

Â§9.4: clients retain `FETCH_ATTESTATION`s over their high-water range and warn when a later-learned record falls inside a covering attestation that omitted it. Not blocking â€” the server may be misbehaving or may have raced â€” but permanent and in-thread:

> **A message dated 3 March arrived late, and an earlier check from this server said it wasn't there.**
> That can be a server fault. It can also mean the server held it back. URmessage records this so it can't happen quietly.

### 9.7 Media pruned by policy â‰  download failed

Master Â§12.2 prunes `MEDIA` at 1 month. The client knows the record's `retention_class` and age, so it can and must distinguish the two:

| Condition | Rendered |
|---|---|
| Media pruned by retention | An inline card, muted, no retry: "Photo â€” no longer available. Photos and files on this server are kept for 1 month." |
| Download failed | An inline card with `[ Try again ]`: "Couldn't download this photo." |
| Ephemeral expired | "This message is no longer readable. The key was destroyed on 11 August." â€” never "failed" |

Calling the first two the same thing is the difference between a working product and a broken-looking one.

---

## 10. Notifications

### 10.1 Local toasts (v1, unconditional)

`Microsoft.Windows.AppNotifications.AppNotificationManager`, from the Windows App SDK. The VPN app does not use it today â€” the API surface is present via WASDK 2.2 but there are no call sites in `app/src` â€” so this is new code, and unpackaged apps need COM activation registered (`AppNotificationManager::Default().Register()` with a display name and icon, at startup, before the window shows).

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

**Revocation is a security requirement, not a nicety.** A toast that outlives its message defeats Â§12.1's guarantees at the shell layer. `RemoveByTagAsync` / `RemoveByGroupAsync` on:

- the message being read on this or any device;
- a `TOMBSTONE` arriving for it (delete for everyone);
- **an ephemeral message's timer expiring** â€” the key is destroyed on every device and on the server, and the Action Center copy must go with it;
- the app being signed out.

### 10.2 WNS push (C-6)

Master ledger open item 2: *"No push exists in the operator today."* This spec defines the client half and its constraints so that the operator and server work can land against a fixed contract.

| | |
|---|---|
| Mechanism | `PushNotificationManager` (WASDK). For an unpackaged app this requires an Azure AD application registration and delivers a channel URI the client registers with the message server through A |
| Payload | **Contentless.** A wake signal, optionally carrying a group id **hashed under a per-install key** so the operator/Microsoft path cannot correlate it. No sender, no preview, no plaintext group id, no count |
| Behaviour | The push COM-activates the app if stopped; the app fetches from the server, decrypts locally, and raises a **local** toast (Â§10.1) with real content |
| Why contentless | WNS is Microsoft's infrastructure. Anything in the push payload has been handed to a third party. Â§4.2's operator boundary would mean nothing if the notification carried the message |
| v1 fallback | If C-6 does not land, the app delivers notifications only while running. Settings then offers "Start URmessage when I sign in" with the plain reason: *"URmessage can only notify you while it's running."* |

### 10.3 Lock screen

Windows shows toast content on the lock screen when the user has enabled it system-wide; the app cannot force it off per-notification. So the app controls what it puts in the toast at all.

**Setting: "What notifications show" â€”** Settings â†’ Notifications, three positions:

| Position | Toast |
|---|---|
| Name and message | "**Ana** â€” see you at 6" |
| **Name only** *(default, C-2)* | "**Ana** â€” new message" |
| Nothing | "**URmessage** â€” new message" |

Per-conversation override, so a user can set one conversation to "Nothing" without changing the rest. Directly under the setting, the honest sentence:

> Windows decides whether notifications appear on your lock screen. URmessage decides what's in them.

**Fixed regardless of setting:** disappearing-message notifications **never** include content, at any setting, because the toast is a copy of the message living outside the key's lifetime. They read "**Ana** â€” new message".

---

## 11. Brand

### 11.1 Source of truth

`github.com/urnetwork/elements` `src/index.css` defines the tokens; `app/src/App/UrColors.h` is the C++ mirror the VPN app uses and `App.xaml` mirrors those again for markup. **URmessage takes `UrColors.h` and `App.xaml` unchanged** and adds nothing to the palette except one font token (Â§11.4).

### 11.2 Palette mapping

| URmessage use | Token (`UrColors.h`) | `App.xaml` key | Hex |
|---|---|---|---|
| Window background | `kBackground` | `UrBackgroundBrush` | `#101010` |
| Sheets, dialogs, the key-change modal | `kSheet` | `UrSheetBrush` | `#151515` |
| Cards, incoming bubbles, list rows | `kCard` | `UrCardBrush` | `#1C1C1C` |
| Outgoing bubbles, row hover | `kCardHover` | `UrCardHoverBrush` | `#242424` |
| Row pressed | `kCardPressed` | `UrCardPressedBrush` | `#2A2A2A` |
| Hairlines, bubble borders | `kBorder` | `UrBorderBrush` | white @ 12% |
| Message text, names | `kOffWhite` / `kText` | `UrTextBrush` | `#F8F8F8` |
| Timestamps, previews, secondary | `kTextMuted` | `UrTextMutedBrush` | `#989898` |
| Decoration only â€” never information | `kTextFaint` | `UrTextFaintBrush` | `#5A5A5A` |
| Key-change, fork, failed send, destructive | `kDanger` | `UrDangerBrush` | `#F8523B` |
| Send button, primary action, unread pill | `kAccent` | `UrAccentBrush` | `#EFF7BB` |
| Text on accent | `kInverseText` | `UrInverseTextBrush` | `#101010` |
| Toggles | `kToggleAccent` | â€” | `#638BFC` |
| **Never used in URmessage** | `kProGold`, `kProGoldLight` | `UrProGoldBrush` | reserved for the Pro entitlement, product-wide |
| Identicon ramp (6) | `kUrGreen`, `kUrPink`, `kUrCoral`, `kUrElectricBlue`, `kUrAmber`, `kToggleAccent` | â€” | Â§11.5 |

The `kStatusConnecting` / `kStatusIdle` dots belong to the VPN's connect status and are not reused here; message delivery state is glyphs (Â§5.3).

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
| Derivation | `H(input)` â†’ first byte selects one of the six ramp colours; the next 8 bytes drive a 5Ã—5 vertically-mirrored cell grid |
| Rendering | Foreground cells in the ramp colour on `kCard`, rounded 8, drawn as a `Path` â€” no bitmaps, no cache invalidation |
| Property | **A contact's avatar changes visibly when their key changes.** This is deliberate: it is SSH randomart pointed at the one event the product most wants noticed, reinforcing Â§7 rather than replacing it |
| Accessibility | `AutomationProperties.Name` is the contact's name, never a description of the picture |

### 11.6 Native shell, brand content

The owner's rule for the VPN app applies unchanged: Windows chrome, Mica, standard WinUI metrics and controls; URnetwork palette, brand fonts, brand surfaces. Do not build a custom title bar, a custom scrollbar, or a custom context menu. `ContentDialog` on `UrSheetBrush` is the sheet. `InfoBar` via `UrSnackbarStyle` is the transient bar â€” note the kit's `Snackbar` helper exists because `InfoBar` has no timer of its own.

---

## 12. Settings

| Group | Contents |
|---|---|
| **Account** | URnetwork account, message identity (principal + short fingerprint), **Show my recovery phrase** (Hello-gated), Sign out |
| **Notifications** | On/off, what notifications show (Â§10.3), sound, per-conversation list of overrides, "Start URmessage when I sign in" |
| **Privacy & retention** | `msg_durable_default_explainer` at the top; read receipts (on); typing indicators (on); disappearing default for new conversations (off); **Cover traffic (off)** â€” Â§12.1 below |
| **Appearance** | Enter-to-send, message density, time format |
| **Storage** | Local store size, attachment cache, "Clear downloaded files" (local only, with copy saying so), server-advertised attachment cap shown read-only |
| **Devices** | Screen 19 |
| **Advanced** | Message server host (read-only in v1, Â§12.2), diagnostic log level, "Copy diagnostic", crash-report opt-in, version and `kCode` |

### 12.1 Cover traffic

T7: built into the format, exposed as a setting, **off by default**. The copy must state the cost, because the cost is the reason it is off:

> **Send cover traffic**
> URmessage sends occasional decoy records so the server can't tell when you're actually messaging. It runs on its own schedule whether or not you're sending â€” that's what makes it work, and it's also why it uses bandwidth and battery continuously.

### 12.2 Server, read-only

v1 has one server (T1/T2). The row shows the host, is not editable, and carries the Â§13 line rather than a disabled dropdown that implies a choice:

> **Message server** â€” message.ur.network
> URmessage v1 uses one server. Choosing or moving servers is planned for a later version.

---

## 13. Accessibility and keyboard

### 13.1 Screen readers

- `AutomationProperties.Name` on **every** icon-only button. The VPN app already does this in 15 source files; match that standard.
- The message list is an `AutomationProperties.LiveSetting="Polite"` region so arriving messages are announced without interrupting.
- A message bubble's automation name is a single sentence: *"Ana, 09:14. See you at 6. Read."* Not four separate focusable fragments.
- System records announce as such: *"System message. Ana added Bo."*
- The **key-change modal** is `AutomationProperties.LiveSetting="Assertive"` and takes focus on open. This is the one place interruption is correct.
- The **seedphrase grid** must be fully readable by a screen reader, word by word with position: each cell's automation name is *"Word 7, absurd"*. A blind user has no other way to record the phrase; suppressing it here would lock them out of the product.

### 13.2 Keyboard

Full operation without a mouse is a v1 requirement, not a stretch goal.

| Chord | Action |
|---|---|
| `Ctrl+N` | New conversation |
| `Ctrl+Shift+N` | New group |
| `Ctrl+F` | Search within the current conversation |
| `Ctrl+K` | Quick switcher (jump to conversation by typing) |
| `Ctrl+Tab` / `Ctrl+Shift+Tab` | Next / previous conversation |
| `Alt+â†‘` / `Alt+â†“` | Move selection in the conversation list |
| `F6` / `Shift+F6` | Cycle panes: list â†’ thread â†’ details |
| `Enter` | Send (or newline, if reversed in Settings) |
| `Shift+Enter` | Newline (or send) |
| `Esc` | Close sheet; clear reply-to; clear search |
| `Ctrl+Shift+M` | Mark conversation read |
| `Ctrl+U` | Attach a file |
| `Ctrl+E` | Emoji picker |
| `Ctrl+,` | Settings |
| `Ctrl+Shift+D` | Toggle disappearing timer for this conversation |
| `â†‘` in an empty composer | Edit-target selection is **not** in v1 (no editing); reserved, does nothing |
| `Application` / `Shift+F10` | Message context menu on the focused message |

Rules: no chord may shadow a Windows system chord; focus never leaves the app on `Tab`; a modal traps focus and restores it on close; every focusable element has a visible focus rect (WinUI reveal focus, 2px, `UrAccentBrush`).

### 13.3 Contrast

Computed from the token values (WCAG 2.1 relative luminance), against `#101010`:

| Pair | Ratio | Verdict |
|---|---|---|
| `kText` `#F8F8F8` on `kBackground` | â‰ˆ 17.5:1 | AAA |
| `kTextMuted` `#989898` on `kBackground` | â‰ˆ 6.6:1 | AA for all sizes |
| `kDanger` `#F8523B` on `kBackground` | â‰ˆ 5.7:1 | AA |
| `kInverseText` `#101010` on `kAccent` `#EFF7BB` | â‰ˆ 16.9:1 | AAA |
| **`kTextFaint` `#5A5A5A` on `kBackground`** | **â‰ˆ 2.8:1** | **Fails AA and fails 3:1** |

**Therefore: `kTextFaint` / `UrTextFaintBrush` may never carry information in URmessage.** Hairlines, disabled-state fills, decorative separators only. Never a timestamp, never a delivery state, never a warning, never a label. This is a CI-checkable rule (Â§15.3) and it is the single most likely accessibility regression in a chat UI, where timestamps are always the first thing someone dims.

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

**Five traps, all paid for once already in this codebase. Do not rediscover them.**

| # | Trap | Rule |
|---|---|---|
| 1 | The C++ wrapper generator used the **C++ return type** for a callback trampoline's C signature, producing an uncompilable header for the one string-returning callback | Any string-returning callback in the URmessage surface must go through `detail::dupCString` (malloc, because Go frees with `urnet_free_string` â†’ `free()`). Add a `cgo/smoke/compile_hpp.cpp`-style compile-only TU for `URmessageSdk` that assigns every trampoline to its C-ABI typedef, in CI, from day one |
| 2 | `manualExports()` scans for `//export` with an **anchored regex**; on a CRLF checkout the CR sits before the line end and every hand-written export silently vanishes from the `.def` | Add a link-time assertion, or a CI check that the `.def` export count matches the `//export` count |
| 3 | **Never call `.reset()` on a subscription handle.** `urnet::Sub` does not override `reset()`, so it hits `detail::Handle::reset()` â€” registry release without `urnet_sub_close`, then `h_=0` so the destructor skips the close too. A process-lifetime leak *and* a use-after-free when Go still holds the callback pointer | `sub_ = urmsg::Sub{}` â€” move-assign closes first. Applies to every subscription in the client |
| 4 | The Go runtime's `preventErrorDialogs()` runs at `DLL_PROCESS_ATTACH` (load-time import) and sets `SEM_NOGPFAULTERRORBOX` process-wide, so native faults produce **no WER report and no Event 1000** â€” indistinguishable from a clean exit | `SetErrorMode(GetErrorMode() & ~SEM_NOGPFAULTERRORBOX)` at `wmain` entry. Leave `SEM_FAILCRITICALERRORS` and `WER_FAULT_REPORTING_NO_UI` alone |
| 5 | MSVC's `std::set_terminate` is **per-thread** | Arm a `ThreadGuard` on every thread that calls into the SDK or receives a callback, using the `Common/ThreadGuard.h` pattern (`ArmThreadGuard` / `RunGuarded` / `StartGuardedThread`) |

**Threading.** Every SDK callback arrives on a Go thread. Marshal to the UI with `DispatcherQueue.TryEnqueue` and never touch a XAML object from a callback thread. Never block the UI thread on an SDK call â€” the VPN client's D4 was `AppHangB1` kills from exactly that.

### 14.2 What C calls in Spec A

Indicative surface; A owns the signatures. The point is the shape: every state C renders is an explicit value A returns, never an inference C makes.

| Area | Calls | Events (subscriptions) |
|---|---|---|
| Lifecycle | `Init(dataDir)`, `Shutdown()`, `SetByJwt(jwt)` | `HealthChanged(MessageHealth, reason)` |
| Identity | `GenerateSeedphrase()`, `ConfirmSeedphrase(positions[], words[])`, `RestoreFromSeedphrase(words[])`, `IdentityFingerprint()`, `MarkPhraseConfirmed()` | `RestoreProgress(group, done, total)`, `RestoreComplete(outcome)` |
| Devices | `ListDevices()`, `BeginProvisioning()` â†’ QR + code + SAS, `JoinWithCode(code)`, `ApproveSas()`, `RemoveDevice(id)` | `ProvisioningStateChanged` |
| Conversations | `ListConversations()`, `OpenConversation(gid)`, `FetchOlder(gid, before, n)`, `MarkRead(gid, rid)` | `ConversationsChanged`, `MessagesAppended(gid, [])`, `MessageStateChanged(rid, state)` |
| Send | `SendText(gid, text, replyTo)`, `SendAttachment(gid, path)`, `Retry(rid)`, `CanSend(gid) â†’ (bool, reason)` | `SendStateChanged(rid, state, reason)`, `UploadProgress(rid, bytes, total)` |
| Delete / ephemeral | `DeleteForMe(rid)`, `DeleteForEveryone(rid)`, `SetDisappearing(gid, bucket)` | `RecordTombstoned(rid)`, `RecordExpired(rid)` â† **drives toast revocation (Â§10.1)** |
| Groups | `CreateGroup(name, members[])`, `AddMember`, `RemoveMember`, `SetRole`, `SetRetention`, `Leave`, `GroupDetails(gid)` | `GroupChanged(gid)` |
| Verification | `SafetyNumber(peer)`, `PinState(peer)`, `AcceptKeyChange(peer)`, `MarkVerifiedLocally(peer)` | `KeyChanged(peer, evidence_class, old_seen_at, changed_at)` |
| Directory | `LookupPrincipal(q)` (with KT inclusion proof) | `DirectoryLookupFailed(reason)` |
| Server | `ServerInfo()` â†’ host, pinned-key state, **advertised attachment cap**, **advertised retention minimum** | `ServerKeyChanged(...)`, `AttestationGap(gid, rid)` |
| Integrity | â€” | `ForkDetected(gid, epoch, ours, theirs)` |
| Push | `RegisterPushChannel(uri)` | â€” |

**Requirements C places on A:**

1. **Enumerable reasons, never inference.** `CanSend` returns a reason; `SendStateChanged` carries a reason; health carries a reason. C must never conclude "not connected" from an empty getter â€” that inference is precisely what produced defect #40 in the VPN client.
2. **`RecordExpired` must fire on the client even with no user visible**, because a toast in the Action Center must be revoked when the key dies.
3. **A distinguishes pruned from failed** for media (Â§9.7).
4. **A never returns plaintext for an expired ephemeral record**, under any code path, including history restore.
5. **A owns the local store and its DPAPI sealing.** C writes no message content to disk, ever.
6. **A exposes `commit_lost` as a non-event** or handles the retry internally and never surfaces it (Â§9.3).
7. **A exposes the advertised caps as data.** C hardcodes no size limit and no retention period; "100 MB" and "1 month" appear in copy only via formatted values.

### 14.3 What C assumes of Spec B

C never talks to B. These are requirements on B that reach the UI through A, listed here because the UI is where a violation becomes visible.

| Assumption | UI consequence if violated |
|---|---|
| B advertises a per-attachment size cap (default 100 MB) and a retention minimum, both readable before a send | The client either hardcodes a limit (wrong) or discovers a failure only after a 100 MB upload |
| B accepts one commit per `(group_id, epoch)`, returns the winner, and rejects wrong-epoch records (Â§9.3) | Retry storms, reordered threads, or a user-visible error for a normal race |
| B distinguishes "pruned by retention" from "never existed" from "refused" in its responses | Â§9.7 collapses; every missing photo looks broken |
| B signs `FETCH_ATTESTATION` with a stable long-term Ed25519 key (Â§9.4) | The server-key pin (Â§7.6) either never fires or fires constantly |
| B enforces monotonic, not contiguous, `stream_index` (Â§8) | A refused write bricks a conversation's outbox |
| B creates **no logs** of client commands or connections in production (Â§9.7) | The product's honest-limits page (Â§13 of the master spec) becomes false |
| B never sees plaintext and never needs group membership from the operator (Â§4.2) | Everything |
| C-5 resolves: retention floor conflict is warn-and-proceed | Â§8.4's copy is wrong and a group's real retention is misstated to its members |

---

## 15. Not in v1

The rule: **absent, not disabled.** A greyed-out call button teaches a user the product has calling and is broken. Nothing greyed, nothing "coming soon" as a button.

| Deferred (master Â§2) | What the user sees in v1 |
|---|---|
| Voice and video | No call button anywhere. Not mentioned |
| Message editing | The context menu has Delete, not Edit. `â†‘` in an empty composer does nothing |
| Multi-server / server choice | Settings shows one server, read-only, with Â§12.2's sentence |
| Group migration between hosts | Not mentioned. The single-server honesty in Â§9.4's "What's happening?" covers the consequence |
| History export | Not offered. There is no export button to grey out |
| Public groups | Group creation has no visibility control |
| Stream digests (server-withholding detection) | Settings â†’ Privacy carries one line: *"URmessage cannot yet prove this server didn't quietly drop a message. Detecting that is planned."* â€” because Â§12.3 says it is undetectable in v1, and silence would be a claim |
| Per-device write capabilities | The observer copy in Â§5.6 states the limit plainly |
| Mobile clients | No "Link a phone" entry. Device linking shows a code that another **desktop** can enter |
| App lock / local passcode (C-4) | Not offered. Settings â†’ Account says: *"Anyone who can sign in to Windows on this computer can read these messages."* |
| Contact avatars / group photos | Identicons, with no upload affordance |
| Backups other than the recovery phrase | Not offered |
| Message forwarding, starring, pinning, drafts sync | Not offered |
| Local search (C-3) | **Proposed for v1.** If the owner rules it out, `Ctrl+F` and the search box are removed rather than disabled |

---

## 16. Verification and acceptance

### 16.1 Build gates

1. x64 and ARM64 both build in CI on every commit, `fail-fast: false`, msbuild log uploaded on failure. Runner **windows-2022** â€” `windows-latest` moved to Visual Studio 18 (toolset v180) which keeps v143 for x64 but **not** the v143 ARM64 cross tools.
2. `WindowsTargetPlatformVersion` pinned in `Directory.Build.props` for the real build box, overridden in CI via `/p:` (a global property beats the props file).
3. The `compile_hpp.cpp`-style compile-only TU for `URmessageSdk` (Â§14.1 trap 1).
4. Manifest check: no `requireAdministrator`, no `highestAvailable`, anywhere.
5. Solution check: no reference to `urnetworkd`, wintun, WFP, or `SplitTunnel` from the URmessage projects.

### 16.2 Selftest

The VPN client's `selftest` grew from 167 to 463 assertions over the beta and is the reason its state machines can be trusted. URmessage carries the same discipline:

| Pinned | |
|---|---|
| `MessageHealth` transition table | Every (state, event) pair, including the tick-gap rebase and the carrying veto |
| BIP39 round-trip | Generate â†’ display order â†’ confirm positions â†’ restore; plus the three distinguishable failure modes in Â§6.7 |
| Identicon determinism | Same key â†’ same 5Ã—5 grid and colour, across runs and architectures |
| Copy lint | Â§16.3 |
| Contrast lint | Â§16.3 |
| Breakpoint decisions | Widths 560/999/1000/1499/1500/2400 â†’ expected pane counts |
| Toast revocation | Every one of the four revocation triggers in Â§10.1 |

### 16.3 Copy and contrast lints (build-failing)

1. The three Â§8.1 keys exist and their English values match the master spec character-for-character.
2. No string in any locale contains the prohibited phrases of Â§8.1 outside the allowlisted ephemeral keys.
3. No `Foreground` binding to `UrTextFaintBrush` on any `TextBlock` that is not in the decoration allowlist (Â§13.3).
4. No `SolidColorBrush` literal in `.xaml` or `.cpp` outside `UrColors.h` and `App.xaml` â€” otherwise the high-contrast dictionary cannot work.
5. Every `Button` / `ToggleButton` whose content is a `FontIcon` has an `AutomationProperties.Name`.

### 16.4 Runtime loop

The VPN project's ~40-second loop applies: kill â†’ launch â†’ drive â†’ screenshot â†’ read `%LOCALAPPDATA%\URmessage\app\logs\urmessage-app.log`. Three harness traps, all measured:

- `FindWindow` from a PowerShell P/Invoke harness silently returns 0 unless the `DllImport` sets `CharSet=CharSet.Unicode` â€” the default marshals ANSI into the `W` entry point. Use `EnumWindows` + `GetClassNameW`, which is immune.
- The harness must call `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` or every screenshot is wrong.
- `pwsh` does not exist on the build box; only `powershell`.

And one specific to this product: **the seedphrase screen cannot be screenshotted** while `WDA_EXCLUDEFROMCAPTURE` is set â€” that is the feature working. The harness verifies it by asserting the captured region is black, and exercises the screen's content through the automation tree instead.

### 16.5 Acceptance for the first testable build (master Â§14, slice 5)

Two people, on two Windows machines, each having created an identity and written down a phrase, can:

1. Find each other through the directory, with a KT inclusion proof.
2. Exchange text in a DM and in a 3-person group.
3. React, see read receipts and typing indicators.
4. See the blocking key-change warning when one of them resets their identity, with the Â§7.2 copy and the Â§7.3 evidence rows populated correctly.
5. Read the three Â§8.1 strings, verbatim, at the moments specified in Â§8.1.
6. Operate the whole flow with the keyboard alone, and hear it with Narrator.
7. Do all of it with no UAC prompt, no service installed, and the VPN app not present on the machine.

---

## 17. Cross-references

- **Master protocol design**, `docs/specs/2026-08-12-urmessage-protocol-design.md`: Â§3 invariants, Â§5 identity and custody, Â§8 storage and retention classes, Â§9 message server, Â§10 verification, Â§11 roles, Â§12 deletion and required UI language, Â§13 honest limits, Â§15 open items.
- **SPEC-LEDGER.md**: locked decisions P1â€“P5, I1â€“I6, T1â€“T8; Â§6 change process, which this document follows.
- **Spec A** (SDK / client core): the entire call and event surface of Â§14.2, the local store, DPAPI sealing, MLS, and the `URmessageSdk.dll` C ABI.
- **Spec B** (message server): everything in Â§14.3, plus master Â§9.
- **VPN client**, `Ryanmello07/urnetwork-windows`: `app/src/App/UrColors.h`, `App.xaml`, `UrComponents.h`, `WindowShell.h`, `Localization.h`, `Common/ConnectionHealth.h`, `Common/ThreadGuard.h`, `app/installer/Package.wxs`, and `docs/superpowers/specs/2026-08-06-ios-parity-native-shell.md` for the native-shell/brand-content rule.
