# URmessage — Spec C: Windows Client UI

**Date:** 2026-08-12
**Revision:** 2 — R4 review findings applied (file re-encoded from double-encoded UTF-8; per-user install; one Go runtime; "delivered" deleted; key-change scope narrowed to DMs; evidence classes replaced; §9/§12/§14 rewritten against Spec A's enumerable vocabularies)
**Status:** Design
**Scope:** the Windows messaging client — app shape, screens, copy, states, brand, accessibility
**Depends on:** [URmessage Protocol Design rev 5](../../../claude_sandbox_message/msgrepo/docs/specs/2026-08-12-urmessage-protocol-design.md) (the master spec, cited below as **§n**), [SPEC-LEDGER.md](../../../claude_sandbox_message/msgrepo/SPEC-LEDGER.md), Spec A (SDK / protocol client core), Spec B (message server)

---

## 0. Planning ledger

### 0.1 Current state

| Item | State |
|---|---|
| Master protocol design | Revision 5, awaiting owner review |
| Spec A — SDK / client core | Being written in parallel |
| Spec B — message server | Being written in parallel |
| This spec | Revision 2, R4 findings applied |
| `Ryanmello07/urnetwork-message-windows` | Not created |
| Code | None |

The VPN client (`Ryanmello07/urnetwork-windows`, branch `beta/custom-server`) is a shipping, live-tested WinUI 3 / C++/WinRT application with a proven brand kit, localization pipeline, native shell, installer, updater and release train. **This spec reuses that codebase's patterns and assets and shares none of its process model.** Every reuse below names the file it comes from so the team can read the working precedent rather than re-derive it.

### 0.2 Decisions specific to this component

| # | Decision | Why |
|---|---|---|
| **W1** | Separate executable `URmessage.exe`, not a page inside `URnetwork.exe` | The VPN app is a tray flyout sized 480×760 (`WindowShell.h`) whose one screen is a connect button. A messenger is a workspace app with a three-pane layout and a 20k-message virtualized list. Merging them makes `MainWindow.xaml.cpp` — already 2128 lines and already the collision point for parallel UI work — the collision point for two products. Separate binaries also mean a messaging defect can never take down a VPN tunnel. |
| **W2** | **User-mode only. No service, no driver, no elevation, ever.** | URmessage forwards message traffic through the SDK's own transport. It never captures packets, never rewrites routes, never touches DNS. Every mechanism the VPN client needs to do those things is a mechanism URmessage does not have and must not acquire. §0.3 states exactly what that removes. |
| **W3** | All plaintext, all key material, and the entire local message store live **in Go, inside `URmessageSdk.dll`** (Spec A). The C++ layer is a view. | One place holds plaintext, so one place is audited, one place seals to DPAPI, and one store serves the mobile clients that follow. The C++ side holds only what is currently on screen and never writes message content to disk. |
| **W4** | **Per-user install.** URmessage is an optional component of the existing MSI, `Level="1000"`, not installed by default, installed **per-user** to `%LOCALAPPDATA%\Programs\URmessage\` with a per-user Start Menu shortcut. It ships its **own** copy of the self-contained Windows App Runtime and its **own** copy of the four licensed brand faces. | A per-user component set cannot reference the VPN feature's per-machine `RuntimeFiles` components, so the shared payload of the original W4 is not available. The cost is roughly 60 MB of installed size. It is paid deliberately, to buy three things: an in-app rename-swap updater that works as a standard user (a `%ProgramFiles%` install cannot rename its own binaries without the LocalSystem service W2 removes); a truthful "URmessage installs and runs per-user" claim in §0.3; and **zero elevation anywhere in the product**. |
| **W5** | The client's connection state is a **pure state machine in `Common/MessageHealth.h`** with a selftest-pinned transition table, in the exact shape of the VPN client's `Common/ConnectionHealth.h` (windows `1cfcf3c`). | That pattern was written because ad-hoc status text lied to users for weeks. The same class of lie is worse in a messenger, where "sent" is a claim about someone else's device. The state machine consumes `SyncState` (Spec A §7.2) and nothing else, so its transition table is testable against a fake `SyncState` rather than against the network. |
| **W6** | Seedphrase display uses `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`, clipboard writes use `Clipboard.SetContentWithOptions` with history and roaming disabled, and confirmation is a **typed** quiz over four random positions. | §6. This is the screen where the product can permanently destroy a user's data, and the failure mode is silent for months. |
| **W7** | The key-change warning is a **blocking modal that stops outbound sending** until resolved, plus a permanent, non-dismissible inline record in every shared conversation. **The blocking scope is a DM, not a group** — see §7.1 and MASTER §10.2. In a group, the blocking event is the `Add` of a member whose identity key differs from a pin the user holds. | §10.2 and §5.5 of the master spec require it. The exact copy is fixed in §7 of this document. |
| **W8** | Verified contacts get **no badge, no colour, no checkmark**. `kProGold` in particular is never reused — `UrColors.h` reserves it for the Pro entitlement across the whole product. | §10.2: "There is no verified badge." A badge implies the absence of one means something, and it does not. |
| **W9** | Contact and group avatars are **deterministic identicons derived from the pinned identity key** (contacts) or `group_id` (groups). No avatar upload in v1. | No media path, no storage, no moderation surface — and a contact's avatar visibly changes when their key changes, which is SSH randomart applied to the one event we most want a user to notice. |
| **W10** | The client's own log has a **field allowlist**. Message content, contact display names, group names and attachment filenames are never logged, at any verbosity, in any build. | The VPN client's `Log.cpp` writes one unbuffered `WriteFile` per line and its logs are routinely collected from testers and pasted into issues. A messenger log collected the same way must be safe to paste. |

### 0.3 What "no privileged service" removes, concretely

Every row is a mechanism the VPN client has and URmessage does not.

| VPN client mechanism | Present in URmessage | What its absence removes |
|---|---|---|
| `urnetworkd.exe` running as LocalSystem | **No** | No SCM registration, no service restart budget, no Event 7031/7034 terminations, no `ServiceSetup` five-state classifier, no Connect banner driving an elevated install |
| UAC elevation, `urnetworkd install` verb | **No** | No admin prompt anywhere in the product. URmessage installs per-user to `%LOCALAPPDATA%\Programs\URmessage\` and updates itself by rename-swap, which a standard user can perform on files they own |
| wintun adapter | **No** | No adapter lifecycle, no PnP surprise-removal path, no `WintunDeleteDriver` hazard (which detaches every wintun adapter machine-wide) |
| WFP filters / kill switch | **No** | No firewall state to arm, narrow or disarm; no "my internet is blocked" failure mode; no `RECOVERY.md`, no `revert` verb, no CrashRevert |
| `SplitTunnel.sys` clean-room driver | **No** | No WDK, no driver signing, no `INSTALLDRIVER` feature |
| mTLS loopback RPC (`DeviceLocal.SetRpcServer` / `DeviceRemote`) | **No** | No `rpc_session.json`, no instance-id pairing, and therefore **none of defect #40's reattach class** — there is no second process to reattach to |
| Named pipe lifecycle channel | **No** | No `PipeServer`, no `nlohmann::dump()` UTF-8 throw path |
| Two-phase teardown, budgeted abandonment worker | **No** | Nothing to revert. Closing the app is `ExitProcess` after the store flushes |
| Packet pump, egress monitor, route/DNS config | **No** | No dead-tunnel watchdog, no Modern Standby clock rebase, no carrying-veto evaluator |
| Machine state modified at all | **No** | The worst outcome of a URmessage crash is a closed window |

**What remains from the VPN client's runtime:** an in-process URnetwork `Api` (login, profile, account — Reachability class **A** in the VPN client's terms) and an in-process connect client for addressed transport — **both provided by `URmessageSdk.dll`, not by `URnetworkSdk.dll`, which is never loaded into this process** (Spec A decision A12). Both are class A: no service, no RPC, no elevation. This is the class of work the VPN project proved is fully parallelizable.

**One interaction to be aware of.** If the VPN tunnel is up, URmessage's traffic goes through it — `URmessage.exe` is a separate process and the tunnel's R1 self-exclusion covers only the service's own sockets. That is correct and must not be "fixed" by excluding URmessage from the tunnel: a VPN user would reasonably object to their messenger being the one app routed in the clear. The consequence is that URmessage's health state machine must tolerate the VPN's known control-plane starvation window while the tunnel is `Connecting` (windows spec `2026-08-11-connect-flow-reliability-design.md`), which §9.4 handles by not calling a slow server a dead one.

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
| C-2 | Lock-screen notification default | **Name only**, per-conversation override. Plus §10.3's lock-session rule. |
| C-3 | Local search in v1 | **Yes**, local-only, A-backed via `Search(groupId, query, limit)`. The conversation-list filter (screen 9) is a **local filter over already-loaded rows** and does not touch the index. `Ctrl+F` is the group-scoped form. The index **excludes `EPH` records entirely** (§5.7). |
| C-4 | Windows Hello gate | **Six** actions, not four (§6.6): the original four, plus accepting a changed **server** key (§7.6), plus the destructive "Remove this identity from this computer" (§12). App lock deferred (§15). |
| C-5 | Retention floor conflict | **Warn and proceed, both directions** — RULED in MASTER §15 item 1. §8.4's copy covers both. The `retention_refused` send-failure reason is **deleted**. |
| C-6 | Push transport | Ship v1 with tray presence; WNS raw wake behind the same renderer. **Named owner required for the Azure AD application registration** — it is not in any of the three specs' schedules. Now also an item in Spec A §14. |
| C-7 | Disabling read receipts hides others' | **Yes**, resolved against the **user-scoped** preference (`SetUserPreference("read_receipts", …)`), not the group policy. |
| C-8 | EPH bucket numbering | **Closed by citing Spec A §7.3.** The wire EPH class number and `MessageGroupPolicy.DisappearingBucket` are different namespaces; policy `0` means disappearing off, never bucket 0. |
| C-9 | "Delete for me" copy | §8.2's string, signed off. |
| **C-10** *(new)* | Contact blocking | **In v1, client-side only.** See §12 and §16.5. |
| **C-11** *(new)* | Sign out semantics | **Split into two actions.** See §12. |
| **C-12** *(new)* | Two Go runtimes (Spec A A-ASSUME-2) | **Resolved: one runtime.** `URmessage.exe` loads `URmessageSdk.dll` only; login moves into it (Spec A A12). §16.1 gains a CI check that only one Go DLL is imported. |

### 0.6 Edit log

Append-only. Newest last. One entry per commit that changes this spec. Every change follows SPEC-LEDGER §6: edit, subagent reviews the **diff**, fix findings, commit with the ledger entry, append here.

| Rev | Change |
|---|---|
| 2 | **R4 review findings applied** (`docs/reviews/2026-08-12-r4-findings-full.json`, 148 findings; edit plan `research/r4-edit-plan.md`, Spec C edits C-0…C-20 plus the cross-cutting halves that name C). Rev 1 was **double-encoded UTF-8** — 305 mojibake runs, including all 131 `§` and every em dash — so the file was repaired first (decode each run via cp1252→UTF-8, BOM stripped, LF endings), and §8.1's three normative strings were then re-verified against MASTER §12.4 by codepoint. Substantive changes: per-user install with its own runtime and brand faces (W4, §2, X-28); one Go runtime, login inside `URmessageSdk.dll` (§0.3, §1.1, §14, X-20); the `Delivered` state **deleted** (§5.3, X-18); key-change blocking narrowed to DMs with a new blocking `Add` condition (§7.1, X-23); evidence classes replaced with A's lowercase closed set and `SELF_SIGNED_ROTATION` removed as a false security claim (§7.3, X-17); retention negotiation warn-and-proceed in both directions and `retention_refused` deleted (§8.4, §9.3, X-25); an eighth health state `StoreUnavailable` with screen 26 and a `SyncState`-derived transition table (§9.2, X-22); seedphrase re-display backed by A's sealed entropy (§6.5, X-19); four new screens (23–26), the §5.7 ephemeral-containment rule, §12.3 device removal, §14.4's mirror of Spec A's C1–C15, and three new DLL-boundary traps (§14.1, X-27). |

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
| URI scheme | `urmessage://` (deep links, invite links). The VPN app owns `urnetwork://`; no collision |
| Data root | `%LOCALAPPDATA%\URmessage\` — `app\logs\`, `app\storage\` (owned by A), `app\prefs.json`. The **program** files live in `%LOCALAPPDATA%\Programs\URmessage\` |
| Min OS | Windows 10 21H2 (Mica degrades to the solid brand background, as in `WindowShell.h`) |

**Where every `settings_json` value comes from.** `urmsg_client_open(settings_json, out_error)` takes the schema in Spec A (`MessageClientSettings`):

```jsonc
// urmsg_client_open(settings_json, out_error). All keys required unless marked optional.
{
  "storage_dir":        "string",   // absolute path, per-user, writable. NOT %PROGRAMDATA%.
  "network_space_host": "string",   // e.g. "ur.network"; the URnetwork network space
  "message_server_id":  "string",   // the one server's URnetwork client id (UUID string),
                                    // from the build-time constant kMessageServerClientId
                                    // or, when set, from the operator discovery response
  "enable_cover":       false,      // optional, default false  (MASTER §9.5)
  "media_cache_bytes":  1073741824  // optional, default 1 GiB
}
```

> `storage_dir` = `%LOCALAPPDATA%\URmessage\app\storage`. `network_space_host` and `message_server_id` are build-time constants in `Common/ServerConfig.h` (`kNetworkSpaceHost`, `kMessageServerClientId`). There is **no ByJwt at construction**: the client opens first, then signs in through the `urmsg_auth_*` surface, and refreshes with `urmsg_client_set_by_jwt`. `message_server_id` is a URnetwork **client id**, which is not the same thing as the host string shown in §12.2 — say both.

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
| Process not running | Records queue at the message server. They arrive on next launch. If C-6 resolves in favour of WNS raw wake, a contentless push COM-activates the app; §10.2 |
| Quit | Drain the UI's pending SDK calls, then stop the session, then exit. The VPN client's D3 (`0xc000027b` on tray-quit, an unobserved WinRT async surfacing during `DispatcherQueue` teardown) is the failure this drain prevents |

**Activation plumbing.** Without these three lines, "clicking the toast opens a second empty window" is the guaranteed first bug:

- Activation is read with `AppInstance::GetCurrent().GetActivatedEventArgs()` and redirected to the existing instance with `AppInstance::RedirectActivationToAsync` against `ids::kMessageSingleInstanceKey`.
- A **toast activation on a running instance restores and focuses** the existing window (and navigates to the deep-linked conversation); it never creates a second window.
- A **cold-start push COM activation fetches and raises the local toast without showing the window** — the app wakes, decrypts, notifies, and stays in the tray.

---

## 2. Installer relationship

### 2.1 Feature

URmessage is an **optional feature of the existing `app/installer/Package.wxs`**, off by default, **per-user, and self-sufficient**:

```xml
<Feature Id="Messaging"
         Title="URmessage"
         Description="Private messaging on URnetwork. Installs a separate app; does not change your VPN."
         Level="1000"
         AllowAdvertise="no">
  <ComponentGroupRef Id="MessageAppFiles" />      <!-- URmessage.exe, URmessageSdk.dll, URmessage.pri -->
  <ComponentGroupRef Id="MessageRuntimeFiles" />  <!-- its OWN copy of the Windows App Runtime -->
  <ComponentGroupRef Id="MessageBrandFonts" />    <!-- ABC Gravity Extended, ABC Gravity Extra
                                                       Condensed, PP Neue Montreal, PP NeueBit Bold -->
  <ComponentRef Id="MessageUriScheme" />
  <ComponentRef Id="MessageStartMenuShortcut" />
</Feature>
```

`Level="1000"` against the default `INSTALLLEVEL` of 1 is the mechanism: the feature is present in the package and absent from a default install. The package gains `WixUI_FeatureTree` (`WixToolset.UI.wixext`) so the feature is selectable, and `ADDLOCAL=Messaging` works for command-line and managed installs.

**Two failures this fixes.** The previous feature referenced **no** `RuntimeFiles`, and in WiX a component installs only if a feature referencing it is selected — so `ADDLOCAL=Messaging`, which this section explicitly requires to work, installed `URmessage.exe` with no Windows App Runtime and it would not start. It also referenced **no brand fonts**, so a Messaging-only install fell back to system faces and every brand surface in §11 was wrong.

### 2.2 Own payload, separate app

The install directory is `%LOCALAPPDATA%\Programs\URmessage\`, with **per-user components**, a per-user `Software\Classes\urmessage` key under `HKCU`, and a **non-advertised** per-user Start Menu shortcut — the ICE43/ICE57 advertised-shortcut requirement applies to perMachine packages, and a per-user component set does not need it. The feature carries:

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

When the messaging feature is built, its files — including its own copy of the runtime and the brand faces — go into the same zip. No second zip, no second release, no second tag: the version grammar (`Common/Version.h`, `Common/VersionGrammar.h`, `kString`/`kCode`) is shared and both apps stamp the same tag.

### 2.5 Independence

**URmessage must run with the VPN service absent, stopped, or broken.** CI must include a check that installs with `ADDLOCAL=Messaging` **only**, on a machine where **neither `urnetworkd` nor the VPN app feature** was ever installed, and asserts that the app launches, reaches the login screen, **signs in**, and renders in the brand faces. The old check tested only that the *service* was absent, which exercises neither the runtime nor the fonts nor the login path. This is the single most likely regression from sharing an installer, and it is the whole point of W2.

### 2.6 Acquisition from the VPN app

The flow that exists nowhere today. An existing VPN user reaches URmessage from **Settings → "Get URmessage"**, which launches the MSI with `ADDLOCAL=Messaging`. The MSI itself raises the standard UAC prompt for its per-machine bookkeeping; **the app never does**, and nothing URmessage installs or runs needs elevation (W2, W4).

| State | Screen |
|---|---|
| MSI present on disk | *"URmessage is private messaging on URnetwork. It installs as a separate app and does not change your VPN."* `[ Install URmessage ]` `[ Not now ]` |
| MSI not present on disk | Download from the release URL first, digest-verified exactly as §2.3 already does, with a determinate progress bar and a `[ Cancel ]`. Failure: *"Couldn't download the installer."* `[ Try again ]` |
| Already installed | The row becomes **"Open URmessage"** and launches it; the entry is never a greyed button (§15) |

---

## 3. Screen inventory (v1)

The table is the contract; the sections that follow expand the four screens that carry real risk. Every screen's empty, loading, and error states are in §9.

| # | Screen | Shows | States |
|---|---|---|---|
| 1 | **Welcome** | Wordmark, one sentence, **three** buttons: *Set up URmessage* / **"Link this computer to a device I'm already using"** (visually **primary** over the recovery-phrase option, because it produces a sending-capable device) / *I already have a recovery phrase* | first-run only |
| 2 | **URnetwork account** | Sign in or create. Reuses `LoginPage` / `LoginCarousel` / `AuthSheets` / `GoogleSignIn` from the VPN app | signed-out, submitting, error, signed-in |
| 3 | **Identity intro** | What the recovery phrase is, that it is generated here and never sent, that losing it loses history. One "Create my phrase" button | static |
| 4 | **Seedphrase display** | 24 words, 4×6 numbered grid, mono face. Copy / Save to file / Continue | capture-blocked, obscured (window inactive), dwell-locked, ready |
| 5 | **Seedphrase confirmation** | Four random positions, typed entry, BIP39 autocomplete | empty, partial, wrong (→ back to 4), confirmed |
| 6 | **Restore — phrase entry** | 24 fields, whole-phrase paste, per-word validity, checksum check | empty, partial, word-not-in-list, checksum-failed, valid |
| 7 | **Restore — progress** | Finding groups → restoring history, per-group rows | working, complete, partial, nothing-found, read-only-outcome (§6.7) |
| 8 | **Link a device** | Existing device: QR + typed pairing code + SAS. New device: code entry + SAS | waiting, paired, SAS-compare, approved, refused, timed-out |
| 9 | **Conversation list** | Rows: identicon, name, last-message preview, time, unread count, muted glyph, disappearing-timer glyph. Search box. New-conversation button | empty, loading, populated, filtered-no-results, offline banner, server-unreachable banner |
| 10 | **Conversation view** | Virtualized message list, day separators, system records, composer, disappearing chip, attachment button | empty, loading-history, at-top (no more history), populated, read-only (observer / restored / removed), blocked-by-key-change, fork-detected |
| 11 | **Message context menu** | React, Reply, Copy, Save attachment, Message info, Delete for me, Delete for everyone | per-message; delete-for-everyone hidden when not the sender |
| 12 | **Message info** | Only what Spec A returns: sender, sent time, received time, epoch, sender leaf index, retention class, size bucket, attestation state, read-by list. **No per-member delivery** (§5.3) | own messages and received |
| 13 | **New conversation** | Directory lookup by URnetwork principal, recent contacts, "New group" | empty query, searching, results, no-results, lookup-failed, KT-proof-failed |
| 14 | **Group creation** | Name, members picker, retention, disappearing default | drafting, creating, created, failed |
| 15 | **Group details** | Members with roles, invite, retention, disappearing, history-grant banner, leave | member view, admin view, owner view |
| 16 | **Member detail** | Identicon, principal, safety number, role controls, remove, device count | self, member, admin, owner, unpinned, pinned, key-changed |
| 17 | **Safety number** | 60 digits in 12 groups of 5, mono; QR; Copy; "Mark as verified locally" | unpinned, pinned, changed-unaccepted, changed-accepted |
| 18 | **Key-change warning** | The blocking sheet. Exact copy in §7 | blocking (modal), resolved, in-thread permanent record |
| 19 | **My devices** | This device + others: name, added date, last seen. Add device, Remove device (§12.3) | one device, several, removing (per-group progress), removed, **partially removed**, failed |
| 20 | **Settings** | Eight groups; §12. Account carries the two exit doors — **Sign out of URnetwork** (non-destructive) and **Remove this identity from this computer** (destructive, Hello-gated, hard-blocked before phrase confirmation) — and the new **Security** group renders `Sealer.Description()` verbatim | — |
| 21 | **Attachment viewer** | Image or file. Save as, Open with | loading, loaded, expired-by-policy, download-failed, too-large |
| 22 | **About** | Version, `kCode`, message server host, licences, `THIRD-PARTY-NOTICES.txt` | static |
| 23 | **Invitations** | Pending group invites, pinned at the top of the conversation list (a modal on launch is hostile). Inviter, group name, member count, Accept / Decline | none, pending, accepting, accepted, declined, expired |
| 24 | **Reaction picker** | The v1 emoji set, recents, search | closed, open, searching |
| 25 | **Blocked contacts** | Settings → Privacy → Blocked. List, Unblock | empty, populated |
| 26 | **Store unavailable** | Full-screen stop, §9.2. Not a banner | `unseal_failed`, `corrupt`, `disk_full`, `locked_by_another_process` |

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

`ItemsRepeater` inside a `ScrollViewer`, virtualized, with incremental loading upward. A group of 500 people with two years of history is the design target (P4); the list must never materialize more than a window of items. Anchoring: on new-item append, hold scroll position unless the user is within 80 DIP of the bottom, in which case follow.

Day separators, and a system-record row type rendered as a centred, muted, non-bubble line. System records in v1:

| Record | Rendered |
|---|---|
| Member added / removed / left | "Ana added Bo." |
| Role changed | "Ana made Bo an admin." |
| Disappearing timer changed | "Ana set messages to disappear after 1 day." + the §8.1 string on the first change |
| Key change (`KEY_CHANGE_NOTICE`) | **Permanent, non-dismissible.** §7.4 |
| History grant | **Persistent banner**, not a row — §5.5 |
| Retention policy changed | "Ana set media to be kept for 1 month." |
| Observer message hidden | "A message from an observer was hidden." (§5.6) |
| Gap (`Kind == "gap"`) | Per reason: `expired` → §9.7's ephemeral line; `out_of_window` → *"A message here couldn't be decrypted — this device joined after the key rotated."*; `not_a_member_yet` → reuse §9.1's "You joined here" boundary; `withheld` → §9.6's attestation copy; `no_wrap` → *"This device hasn't received its key for this part of the conversation yet."* |
| Invite accepted / declined | "Bo joined." / "Bo declined the invitation." |

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

The data model exists and the pixels do not. Six variants, with layout and tokens:

| Variant | Layout |
|---|---|
| **Quoted reply** | Above the reply text, inside the bubble: 2px `UrBorderStrongBrush` left rule, sender name in `UrBodyStrongTextStyle`, one ellipsized line of the parent in `UrRowNoteStyle`. Tap scrolls to the parent. Renders by **live lookup**, never by copying the parent's text (§5.7) |
| **Inline image** | Thumbnail, max 320×320 DIP, aspect-preserving, rounded 8, click → screen 21 |
| **File card** | Icon, filename, formatted size, `[ Save ]` |
| **Caption line** | Under either attachment variant, `UrBodyTextStyle`, matching A's `SendAttachment(…, caption)`. Collapsed via `SetTextOrCollapse` when empty |
| **Reaction strip** | Below the bubble, grouped by emoji with counts, `UrCardHoverBrush` pills; tap for the member list. Bound to A's `React` / `Unreact` and `ReactionsChanged` |
| **Gap row** | Not a bubble — the centred muted system row, with per-reason copy from §5.1 |

### 5.3 Delivery state

Glyphs, right-aligned under the last outgoing bubble of a run. Never colour alone.

```
MessageEntry.State is a CLOSED set:  "pending" | "sent" | "read" | "failed" | "expired"

  pending  in the local outbox; not yet accepted by the message server
  sent     accepted by the message server
  read     a read receipt was received (only when both sides have receipts on)
  failed   terminal; carries a Reason from the closed send-failure vocabulary
  expired  the disappearing timer elapsed and the key is gone

There is NO "delivered" state. URmessage does not claim delivery: the server does not know which
member a sender_handle belongs to (MASTER §9.5) and MUST NOT record which client fetched which
range (MASTER §9.7, Spec B §11.1). Per-member delivery is a V2 item gated on a client-emitted
delivery receipt.
```

| State | Glyph | Meaning |
|---|---|---|
| Queued | clock | In the local outbox; not yet accepted by the server |
| Sent | one check | Accepted by the message server |
| Read | two checks, filled | Read receipt received (only if both sides have receipts on) |
| Failed | exclamation, `UrDangerBrush` | Tap for reason + Retry |

**Uploading.** An attachment send additionally renders a determinate progress ring bound to A's `UploadProgress`, with a cancel affordance mapped to `MessageSendTicket.Cancel()`. It precedes `Queued` and is not a `MessageEntry.State` value.

**URmessage does not claim delivery.** The tooltip says so: *"URmessage can tell you a message reached the server, and whether someone said they read it. It can't tell you whether their device fetched it — the server does not track who reads what."*

### 5.4 Composer

- `Enter` sends, `Shift+Enter` newline. Reversible in Settings; the setting is announced in the composer's `AutomationProperties.HelpText`.
- Multi-line, grows to 6 lines then scrolls.
- Attachment button, disappearing-timer chip, emoji button.
- Drag-and-drop onto the thread attaches. `Ctrl+V` of an image attaches it.
- **Disabled states** carry an inline reason above the composer, never a silently greyed box: read-only (observer, restored-without-leaf, removed from group), blocked by an unresolved key change, fork detected.

**The send path for an attachment**, which the composer bullets above leave out:

- **The cap check is pre-send.** Compare the file's size against `ServerInfo().MaxBlobBytes` at pick/drop time and refuse with the §9.3 `too_large` copy **before any bytes move**. When `ServerInfo().Advertised == false` the cap renders as "not known yet" and the picker warns rather than fabricating 100 MB (§14.2 requirement 7).
- **MIME type** is determined by content sniff **plus** extension, and travels **inside the encrypted body** (Spec A §5.13). It is never a server-visible field.
- **Caption.** v1 sends an **empty caption** unless the user typed one in the composer at attach time; the caption rides with the attachment, not as a separate message.

### 5.5 History grant banner

§11 requires this be persistent for the life of the group. A pinned banner above the composer, `UrCardBrush` with a `UrBorderStrongBrush` top edge, never dismissible:

> **Ana granted Bo access to messages from 3 March 2026 onward.**
> History grants cannot be undone and stay visible here for as long as this group exists.

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

State the consequence on this screen and in §15: the phrase is recoverable from this machine as long as the Windows profile is intact — which is exactly what §15's *"Anyone who can sign in to Windows on this computer can read these messages"* already concedes.

### 6.6 Windows Hello gate (C-4)

`IUserConsentVerifierInterop::RequestVerificationForWindowAsync(hwnd, ...)` — the plain `UserConsentVerifier` static throws in a desktop app without the interop cast. Gate exactly these actions, and no others (a gate on everything is a gate on nothing):

1. Show the recovery phrase.
2. Accept a changed identity key (§7).
3. Remove a device from your own device list.
4. Leave or delete a group you own.
5. Accept a changed **server** key (§7.6).
6. **Remove this identity from this computer** (§12, Account) — the one destructive action that can lose history.

When Hello is unavailable (`UserConsentVerifierAvailability` ≠ `Available`), the action proceeds behind a typed confirmation instead — the word `REMOVE` for 3 and 6, the contact's display name for 2, and the **server host** (`message.ur.network`) for 5, since a server has no display name and the original fallback rule was undefined for it — never silently unlocked.

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
| **Group you own with no other admin** | *"No one else can add this computer back to this group."* → a §9.4-style "What's happening?" explainer. MASTER §11 makes device self-service require a live leaf and owner succession require a majority of current admins; a majority of zero is unobtainable. |

**Prevent it upstream.** In screen 14 (Group creation) and screen 15 (Group details), a non-blocking prompt when a group has an owner and zero admins — *"If you lose every device, only an admin can add you back. This group has none."* — with an inline **"Make someone an admin"** action.

If the user still has **one** live device elsewhere, the correct path is device provisioning (screen 8) from that device, and the client must say so — as a **live button** into screen 8's new-device half, not a sentence the user cannot act on: `[ I have another device signed in ]`, with the supporting line *"Linking from it is faster and doesn't need an admin."*

**Resolved against Spec A:** this state is `CanSend(groupId)` returning `MessageSendability{Allowed, Reason, ReasonDetail}` with `Reason == "no_leaf_after_restore"` — one value of A's closed sendability vocabulary, which also covers `observer`, `not_a_member`, `key_change_unresolved` and `fork_detected` (§9.3). C must never infer this from a send failing.

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
| `unknown` | *unknown* | **Unknown** |

The "Signed by the old key" cell renders `KeyChangeWarning.SignedByOldKey`, never the class name. No row gets a softening sentence in v1.

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

### 7.6 The server key changes too

§9.4 pins the message server's long-term Ed25519 key on first contact. If it changes, the same shape of modal, app-wide rather than per-conversation, and blocking all sending:

> ## The message server's key changed
>
> URmessage pinned this server's key when it first connected. The key it is presenting now is different.
>
> This server cannot read your messages either way — that protection does not depend on this key. What this key proves is that you are talking to the same server as before, and right now that cannot be proven.
>
> | | |
> |---|---|
> | Server | **message.ur.network** |
> | Key first seen | **3 March 2026** |
> | Key changed | **11 August 2026, 09:14** |
> | Checks that can no longer be verified | **every message before 11 August 2026** (`IntegrityEvent.CoveredSinceRecordId`…`CoveredUntilRecordId`) |
>
> Checks that this server did not leave messages out can no longer be verified for anything before today.
>
> `[ Accept the new key ]`  `[ Stay disconnected ]`

Three rules attach to this modal:

1. **The attestation range is the point.** "This server cannot read your messages either way" is true and beside the point; the point is that the withholding-detection mechanism §9.6 is built on stops covering the pre-change range, which is why that row is in the table.
2. **Accepting is gated** — §6.6 action 5 — with a typed fallback of the **server host** (`message.ur.network`), since a server has no display name.
3. **Accepting writes one permanent app-level record** marking the boundary, and every attestation signed under the old key is **discarded**, not silently trusted (§9.6).

---

## 8. Required UI language

### 8.1 Verbatim strings from master §12.4

These three are **normative in the master spec** and must appear character-for-character in the English store. A CI lint (§16.3 lint 1) fails the build if the key is missing or the English value drifts. The comparison is **by codepoint sequence**, after collapsing runs of whitespace on both sides — MASTER §12.4 is hard-wrapped, so a literal comparison fails on the line break even when the strings are identical, and that spurious failure would mask a real corruption.

| Key | String | Where it appears |
|---|---|---|
| `msg_disappearing_explainer` | "After the timer, this message can no longer be read by anyone — the key is destroyed on every device and on the server." | On the sheet that turns disappearing messages on, and in the first system record when a timer is set in a conversation |
| `msg_delete_for_everyone_explainer` | "Removed from this conversation on every device that is online and honest. Anyone who already read it may have kept a copy, and we cannot detect that." | On the Delete-for-everyone confirmation, before the destructive button |
| `msg_durable_default_explainer` | "Messages are kept so your new devices can see your history. That means the server holds a copy until it's deleted or expires." | Settings → Privacy & retention, at the top; and once during onboarding on the first conversation |

**Prohibited across the whole string store:** "gone forever", "deleted forever", "permanently deleted", "erased forever", "nobody can ever see this" — anywhere they could attach to the `DURABLE` class. Master §12.4: *"Never say 'gone forever' for the durable class."* The lint checks for these substrings and allowlists only the ephemeral-context keys. The substring check is **English only**; the other 27 locales are covered by the process gate in §16.3 lint 2, because an English substring list run against a translated store is vacuous while reporting green.

### 8.2 Delete for me (C-9 — signed off)

Master §12.4 does not cover it, and the honest thing must be said:

> **Delete for me**
> Removed from this computer only. Your other devices still have it, everyone else still has it, and the server still has its copy until it expires.
> `[ Cancel ]` `[ Delete for me ]`

### 8.3 Disappearing messages, on by choice

Off by default (T6). The sheet that turns them on shows `msg_disappearing_explainer` above the bucket picker, and a second line about attachments (§12.2 of the master spec: an attachment on an ephemeral parent inherits the parent's key class):

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

### 8.4 Retention negotiation (C-5 — RULED, warn and proceed, both directions)

MASTER §15 item 1 rules warn-and-proceed in **both** directions: the server floors up or clamps down, accepts the commit, and returns `REASON_RETENTION_CLAMPED` with a `RetentionApplied`. The client warns and proceeds, and **shows the effective policy, not the requested one**:

> **Shorter than the server allows:**
> *"This server keeps messages for at least **30 days**. Your setting of 7 days can't be applied here — the group's messages will be kept for **30 days**."* `[ Use 30 days ]` `[ Cancel ]`
>
> **Longer than the server allows:**
> *"This server keeps photos and files for at most **30 days**. Your setting of 90 days can't be applied here — they will be kept for **30 days**."* `[ Use 30 days ]` `[ Cancel ]`
>
> Both numbers are formatted from `RetentionApplied`, never literals (§14.2 requirement 7). The group's own transcript-covered policy is unchanged, so this is a notice, not a failure.

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
| Blocked contacts, none (screen 25) | person-block | "You haven't blocked anyone." |
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
| `Blocked` | Unresolved key change or server key change | Banner + the modal (§7) |
| `StoreUnavailable` | A could not open the local store: `unseal_failed`, `corrupt`, `disk_full`, `locked_by_another_process` | **The only state that is not a banner.** A full-screen stop (screen 26) |

`StoreUnavailable`'s copy:

> **This computer can no longer open your saved messages.**
> Nothing has been sent anywhere and nothing is lost on the server. Restore with your 24-word recovery phrase to get your history back on this computer.
> `[ Restore from my phrase ]` `[ Copy diagnostic ]`

A DPAPI unseal failure is not exotic — it is what a Windows profile reset, a domain account migration, or a restore of `%LOCALAPPDATA%` onto a different machine produces, and the file is present so nothing looks "empty". With no state defined, the app would do the one thing §14.2 requirement 1 forbids and show *"No conversations yet. Start one to see it here."* to a user whose entire history is intact on the server.

**The derivation, so the transition table is testable.** Every one of the eight states is a **pure function of `SyncState`** (Spec A §7.2): `TokenState` → `no_account`; `MachineOnline == false` → `offline`; `Transport == "connecting"` → `connecting`; `StoreState != "ok"` → `store_unavailable`; `BlockedReason != "none"` → `blocked`; `ConsecutiveFetchFailures ≥ 3 && now − LastSuccessMs ≥ 20 s && MachineOnline && now − LastRecordReceivedMs ≥ window` → `server_unreachable`; some-but-not-all failures → `degraded`; otherwise `reachable`. The carrying veto is `LastRecordReceivedMs`; the tick-gap rebase is `EvaluatedAtMs`. Both come from A, not from a getter that can block on a lock the data path never touches (VPN defect F1).

**Token expiry** maps to `no_account` with reason `token_expired`; no ninth state is added. Queued sends survive it — the outbox is A's and is not torn down. The user sees the sign-in screen with *"Sign in again to keep sending."*

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
| `store_unavailable` | *(nothing here — §9.2's full-screen stop, screen 26, has already taken over)* | blocking |
| `group_closed` | "This group has been closed on the server" | none |
| `epoch_incomplete` | "Setting up the new group key…" | auto, no button |
| `too_large` | "That file is larger than this server accepts (**{cap}**)" | `[ Choose another ]` |
| `blob_incomplete` | "That file didn't finish uploading" | `[ Try again ]` |
| `rate_limited` | "Too many messages just now — retrying in **{RetryAfterMs}**" | auto |
| `oversize` | "That message is larger than this server accepts" | `[ Edit ]` |
| `quota_exceeded` | "This group has used all its storage on this server" | none |
| `internal` | "The message server couldn't accept this" | `[ Try again ]` |
| `fork_detected` | §9.5 | blocking |

**Not values, and therefore not rows.** `commit_lost` — A retries internally and never surfaces it (see below). `retention_refused` — **deleted**; retention is warn-and-proceed in both directions (§8.4), so there is no send failure to render.

**`commit_lost` is invisible.** §9.3 of the master spec: the server accepts one commit per `(group_id, epoch)`, first valid wins, and returns the winner so the loser re-derives and retries. That is a normal race, several times a second in a busy group. It must never surface as an error, a spinner, or a re-ordered message. A user changing a group name at the same moment as someone else sees their change apply a beat later, and nothing else.

### 9.4 When the single server is unreachable

v1 has one message server (T1) and, if it is lost, the groups are lost (T3, §13). The client must not pretend a temporary outage is permanent, nor imply a permanent loss is temporary.

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

### 9.5 Fork detection — the one hard stop

§8.1 / §9.3: MLS gives fork *detection* via `confirmed_transcript_hash` and `confirmation_tag`. A mismatch means this client's view of the group and another's have diverged — the one condition where continuing would show messages that other members are not seeing, or vice versa. The client stops:

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

§9.4: clients retain `FETCH_ATTESTATION`s over their high-water range and warn when a later-learned record falls inside a covering attestation that omitted it. Not blocking — the server may be misbehaving or may have raced — but permanent and in-thread:

> **A message dated 3 March arrived late, and an earlier check from this server said it wasn't there.**
> That can be a server fault. It can also mean the server held it back. URmessage records this so it can't happen quietly.

Attestations are compared only within an identical `(class_mask, heads_only)` filter — a filtered fetch is not a withholding one, and comparing across filters manufactures false warnings.

**Accepting a server key change (§7.6) writes one permanent app-level record** marking the boundary, and every attestation signed under the old key is **discarded**, not silently trusted. `IntegrityEvent.CoveredSinceRecordId`…`CoveredUntilRecordId` is the range that stops being verifiable, and it is the row the §7.6 modal renders.

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

**Revocation is a security requirement, not a nicety.** A toast that outlives its message defeats §12.1's guarantees at the shell layer. `RemoveByTagAsync` / `RemoveByGroupAsync` on:

- the message being read on this or any device;
- a `TOMBSTONE` arriving for it (delete for everyone);
- **an ephemeral message's timer expiring** — the key is destroyed on every device and on the server, and the Action Center copy must go with it;
- the app being signed out.

**All four are driven by A's client-wide `AddRecordLifecycleListener`**, delivering `RecordLifecycleEvent{Kind, GroupId, MessageId, Seq, Dropped}` with `Kind ∈ {"expired", "tombstoned", "read_elsewhere"}`. It is client-wide by name and by design: A raises it for **every** expiring record from the expiry sweep, regardless of whether any group listener is attached. A per-group listener would leave a toast for a conversation the user never opened this session sitting in the Action Center past its key's death — which is exactly the failure this rule exists to prevent.

### 10.2 WNS push (C-6)

Master ledger open item 2: *"No push exists in the operator today."* This spec defines the client half and its constraints so that the operator and server work can land against a fixed contract.

| | |
|---|---|
| Mechanism | `PushNotificationManager` (WASDK). For an unpackaged app this requires an Azure AD application registration and delivers a channel URI the client registers with the message server through A |
| Payload | **Contentless.** A wake signal, optionally carrying a group id **hashed under a per-install key** so the operator/Microsoft path cannot correlate it. No sender, no preview, no plaintext group id, no count |
| Behaviour | The push COM-activates the app if stopped; the app fetches from the server, decrypts locally, and raises a **local** toast (§10.1) with real content |
| Why contentless | WNS is Microsoft's infrastructure. Anything in the push payload has been handed to a third party. §4.2's operator boundary would mean nothing if the notification carried the message |
| v1 fallback | If C-6 does not land, the app delivers notifications only while running. Settings then offers "Start URmessage when I sign in" with the plain reason: *"URmessage can only notify you while it's running."* |
| Owner | The **Azure AD application registration** needs a named owner. It is not in any of the three specs' schedules and is the long pole on this row (C-6, MASTER §15 item 2) |
| On restore | A restored device generates a **new** per-install hash key and a new channel. The old registration is explicitly unregistered via `UnregisterPushChannel()` if the device is still reachable, and otherwise expires |

### 10.3 Lock screen

Windows shows toast content on the lock screen when the user has enabled it system-wide; the app cannot force it off per-notification. So the app controls what it puts in the toast at all.

**Setting: "What notifications show" —** Settings → Notifications, three positions:

| Position | Toast |
|---|---|
| Name and message | "**Ana** — see you at 6" |
| **Name only** *(default, C-2)* | "**Ana** — new message" |
| Nothing | "**URmessage** — new message" |

Per-conversation override, so a user can set one conversation to "Nothing" without changing the rest. Directly under the setting, the honest sentence:

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
| **Account** | URnetwork account, message identity (principal + short fingerprint), **Show my recovery phrase** (Hello-gated), **Check my recovery phrase** (§6.3, addition c), **Sign out of URnetwork**, **Remove this identity from this computer** |
| **Security** | `Sealer.Description()`, rendered verbatim — see below |
| **Notifications** | On/off, what notifications show (§10.3), sound, per-conversation list of overrides, "Start URmessage when I sign in" |
| **Privacy & retention** | `msg_durable_default_explainer` at the top; read receipts (on); typing indicators (on); disappearing default for new conversations (off); **Blocked** (screen 25); **Cover traffic (off)** — §12.1 below |
| **Appearance** | Enter-to-send, message density, time format |
| **Storage** | Local store size, attachment cache, "Clear downloaded files" (local only, with copy saying so), server-advertised attachment cap shown read-only |
| **Devices** | Screen 19 |
| **Advanced** | Message server host (read-only in v1, §12.2), diagnostic log level, "Copy diagnostic", crash-report opt-in, version and `kCode` |

**Account — the two exit doors.** "Sign out" previously appeared exactly once, as a row label, with no defined semantics — one click from Settings, and potentially the most destructive action in the product. §6 goes to great lengths to make phrase loss survivable, so leaving the one action that can cause it undefined was the sharpest inconsistency in this document. It is now two rows:

> **"Sign out of URnetwork"** — drops the `ByJwt`, **keeps** the identity and the local store, returns to screen 2. No confirmation beyond a simple one.
>
> **"Remove this identity from this computer"** — destructive. Windows Hello gated (§6.6 action 6) with the typed-`REMOVE` fallback, and this copy: *"Your messages will be removed from this computer. You can get your history back only with your 24 words."* **Hard-blocked** when `PhraseConfirmedAtMs() == 0`, offering `[ Show my phrase first ]`. Calls `RemoveIdentity()`.

**Security group.** Renders `Sealer.Description()` **verbatim** (Spec A §12.2 C13), lint-checked like the §8.1 strings:

> *"Protected by Windows DPAPI for your user account. This protects your messages from other accounts on this PC and from someone reading the disk. It does not protect against software running as you."*

§15's weaker line stays where it is; this is the stronger, factual one A ties to MASTER §13's honesty standard.

**Privacy & retention — which layer each toggle writes.** Read receipts, typing indicators and the disappearing default are **user preferences** (`SetUserPreference` / `UserPreference`). The group sheet's equivalents are **group policy** (`SetGroupPolicy`, ADMIN/OWNER only). The composition line goes directly under them: *"A receipt is sent only if both you and the group allow it."* Without this the team builds a user-level preference that silently writes to nothing, because in Spec A those three fields live in `MessageGroupPolicy` and a MEMBER cannot commit group metadata.

**Privacy → Blocked (C-10).** Block is offered on screen 16 (Member detail) and in the conversation overflow, with honest semantics stated in the UI:

> *"Blocked people can still send. URmessage discards what they send before you see it, on this computer and your other devices. They are not told. Blocking does not remove them from groups you share."*

The Blocked list is screen 25; the calls are `Block` / `Unblock` / `IsBlocked` (§14.2). It ships in v1 because screen 13 makes any account reachable by directory lookup, and MASTER §9.2 states that with group-wide `write_auth` spam is attributable only to a group — so there is **no server-side lever**. A messenger with a directory and no block button is a moderation incident waiting to happen, and MASTER §15 item 5 already defers moderation recourse.

**Storage.** The attachment cache path is `%LOCALAPPDATA%\URmessage\app\storage\media\` and is **owned by A**. "Clear downloaded files" calls A and deletes decrypted materialised copies only, never records. The server-advertised cap is `ServerInfo().MaxBlobBytes`, rendered as "not known yet" when `ServerInfo().Advertised == false`. `MediaCacheBytes` is a live switch via `SetMediaCacheBytes`.

### 12.1 Cover traffic

T7: built into the format, exposed as a setting, **off by default**. The copy must state the cost, because the cost is the reason it is off:

> **Send cover traffic**
> URmessage sends occasional decoy records so the server can't tell when you're actually messaging. It runs on its own schedule whether or not you're sending — that's what makes it work, and it's also why it uses bandwidth and battery continuously. Takes effect on the next scheduling window.

It is a live switch backed by `SetCoverTraffic(enabled)`, not a construction-time setting; the schedule stays independent of real sending, which is why the change is not instantaneous and the copy says so.

### 12.2 Server, read-only

v1 has one server (T1/T2). The row shows the host, is not editable, and carries the §13 line rather than a disabled dropdown that implies a choice:

> **Message server** — message.ur.network
> URmessage v1 uses one server. Choosing or moving servers is planned for a later version.

The host string shown here is **not** the `message_server_id` URnetwork client id from §1.1; both exist and this row shows the human one.

### 12.3 Removing a device (screen 19)

A `Remove` is one MLS `Remove` plus a `Commit` in **every** group the user belongs to, each of which can lose the single-commit race. For a user in dozens of groups it takes real time and can partially succeed — leaving a stolen laptop still a member of some groups while the UI says "removed". So removal gets the §6.7 treatment: a per-group progress list bound to A's `DeviceRemovalProgress`.

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
| `Alt+↑` / `Alt+↓` | Move selection in the conversation list |
| `F6` / `Shift+F6` | Cycle panes: list → thread → details |
| `Enter` | Send (or newline, if reversed in Settings) |
| `Shift+Enter` | Newline (or send) |
| `Esc` | Close sheet; clear reply-to; clear search |
| `Ctrl+Shift+M` | Mark conversation read |
| `Ctrl+U` | Attach a file |
| `Ctrl+E` | Emoji picker |
| `Ctrl+,` | Settings |
| `Ctrl+Shift+D` | Toggle disappearing timer for this conversation |
| `↑` in an empty composer | Edit-target selection is **not** in v1 (no editing); reserved, does nothing |
| `Application` / `Shift+F10` | Message context menu on the focused message |

Rules: no chord may shadow a Windows system chord; focus never leaves the app on `Tab`; a modal traps focus and restores it on close; every focusable element has a visible focus rect (WinUI reveal focus, 2px, `UrAccentBrush`).

**Focus in the message list, and what it costs.** `ItemsRepeater` deliberately implements **no** focus management, no item keyboard navigation and no selection model — it is a layout panel, not a `ListView` — so §16.5 criterion 6 (full keyboard operation plus Narrator) needs hand-written focus code that this spec budgets for explicitly:

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
| 6 | An event with `Dropped > 0` means the view of that group is **stale** | Discard the in-memory window, re-read via `History()`, re-evaluate unread. Never merge a post-drop event. A 500-member group backfilling two years of history — C's own P4 target — overflows A's 256-event per-`Sub` queue, and without this the `ItemsRepeater` is silently missing messages with no visible state. §16.2 injects a drop and asserts a full re-read |
| 7 | `void* user_data` lifetime | Allocate before register; free **only after `urmsg_release` returns**. Spec A §9.5 rule 5 calls this "the single most common crash in this class of binding", and trap 3 does not cover it — trap 3 is about the handle, not the payload. C++ pattern: a `shared_ptr` context kept alive until after the move-assign returns |
| 8 | Callback ordering and re-entrancy | Callbacks may fire **re-entrantly before the registering call returns**, so never hold a lock across `Add*Listener`. With one goroutine per `Sub` each doing its own `TryEnqueue`, a `MessagesAppended` and a `MessageStateChanged` for the same record can land on the UI thread out of order — and §5.1's scroll anchoring and §5.3's glyphs both assume order. Use **one UI-side event applier** keyed by `(groupId, messageId)`, idempotent, using A's per-`Sub` `Seq` to detect reordering rather than assuming it away |

**Threading.** Every SDK callback arrives on a Go thread. Marshal to the UI with `DispatcherQueue.TryEnqueue` and never touch a XAML object from a callback thread. Never block the UI thread on an SDK call — the VPN client's D4 was `AppHangB1` kills from exactly that.

### 14.2 What C calls in Spec A

**This is a normative field contract, not an indicative sketch.** Spec A owns the signatures; this section names A's *actual* symbols, and every state C renders is an explicit value A returns, never an inference C makes.

| Area | Calls | Events (subscriptions) |
|---|---|---|
| Lifecycle | `urmsg_client_open(settings_json)` (§1.1), `Close()`, `SetByJwt(jwt)`, `ByJwtState()` | `AddHealthListener` → `MessageHealthEvent`, `SyncStateChanged` → `SyncState` |
| Account | the `urmsg_auth_*` surface (login, signup, SSO, profile) — **in this DLL**, not `URnetworkSdk.dll` | — |
| Identity | `GenerateMessageSeedphrase()`, `ValidateMessageSeedphrase()`, `CreateIdentity(phrase)`, `RestoreIdentity(phrase, cb)`, `RevealSeedphrase()`, `RemoveIdentity()`, `MarkPhraseConfirmed()`, `PhraseConfirmedAtMs()`, `IdentitySafetyDigits()`, `IdentityShortFingerprint()` | `RestoreProgress`, `RestoreComplete(outcome)` |
| Devices | `ListDevices()`, `PairingCode()`, `JoinDeviceLinkWithCode(code)`, `ApproveSas()`, `RemoveDevice(id)` | `DeviceLinkState`, `DeviceRemovalProgress` (§16 / screen 19) |
| Conversations | `ListConversations()`, `OpenConversation(gid)`, `History(gid, …)`, `HistoryState()`, `MarkRead(gid, mid)`, `Search(groupId, query, limit)` | `AddMessageListener("")` (all groups), `ConversationsChanged`, `MessagesAppended`, `MessageStateChanged` |
| Send | `SendText(gid, text, replyTo)`, `SendAttachment(gid, path, caption)`, `ResumeAttachment(...)`, `Retry(mid)`, `CanSend(gid) → *MessageSendability` | `SendStateChanged`, `SendabilityChanged(gid, *MessageSendability)`, `UploadProgress`, `DownloadProgress` |
| Reactions / typing | `React(mid, emoji)`, `Unreact(mid, emoji)`, `SetTyping(gid, bool)` | `ReactionsChanged`, `TypingChanged` |
| Delete / ephemeral | `DeleteForMe(mid)`, `DeleteForEveryone(mid)`, `SetDisappearing(gid, bucket)` | `AddRecordLifecycleListener` → `RecordLifecycleEvent{Kind ∈ "expired", "tombstoned", "read_elsewhere"}` ← **drives toast revocation (§10.1)** |
| Groups | `CreateGroupWithMembers(name, members[])`, `AddMember`, `RemoveMember`, `SetRole`, `SetGroupPolicy`, `Leave`, `GroupDetails(gid)`, `ResyncGroup(gid)` | `GroupChanged(gid)` carrying `RetentionApplied` (§8.4) |
| Verification | `SafetyNumber(peer)`, `PinState(peer)`, `AcceptKeyChange(principal, newKeyFingerprint)`, `MarkVerifiedLocally(peer)`, `AcceptServerKey()` | `KeyChangeWarning`, `AddIntegrityListener` → `IntegrityEvent` |
| Blocking | `Block(principal)`, `Unblock(principal)`, `IsBlocked(principal)` | — |
| Directory | `LookupPrincipal(q)` (with KT inclusion proof) → `MessageDirectoryResult` | — |
| Preferences | `SetUserPreference(key, value)`, `UserPreference(key)`, `SetCoverTraffic(bool)`, `SetMediaCacheBytes(n)` | — |
| Server | `ServerInfo()` → `MessageServerInfo` (host, pinned-key state, `MaxBlobBytes`, retention limits, `Advertised`) | `ServerKeyChanged`, `AttestationGap` (both via `IntegrityEvent`) |
| Push | `RegisterPushChannel(uri)`, `UnregisterPushChannel()` | — |

**The field contract.** Every rendered datum in this document resolves to one `A type.field`, and the mapping is normative: one row per datum → screen → `A type.field`, covering at minimum every field of `MessageGroup`, `MessageMember`, `MessageEntry`, `MessageEntryDetail`, `MessageAttachment`, `MessageServerInfo`, `MessageSendability`, `MessageHealthEvent`, `SyncState`, `MessagePin`, `KeyChangeWarning`, `IntegrityEvent`, `MessageDirectoryResult`, `DeviceLinkState`, `DeviceRemovalProgress`, `UploadProgress`, `DownloadProgress`, `RestoreProgress` and `RecordLifecycleEvent` — all of which Spec A §7 now defines. Screens 9, 12, 15, 16 and 19 could not be built from either document before this mapping existed; it is a build gate, not documentation.

**The `gap` entry kind** is a first-class `MessageEntry.Kind` value with a reason of `expired` / `out_of_window` / `not_a_member_yet` / `withheld` / `no_wrap`, rendered per §5.1.

**Requirements C places on A:**

1. **Enumerable reasons, never inference.** `CanSend` returns `MessageSendability.Reason` from a closed vocabulary; `SendStateChanged` carries a reason; health carries a reason. C must never conclude "not connected" from an empty getter — that inference is precisely what produced defect #40 in the VPN client.
2. **`AddRecordLifecycleListener` is client-wide and must fire with no user visible**, because a toast in the Action Center must be revoked when the key dies, including for a conversation never opened this session.
3. **A distinguishes pruned from failed** for media, as `MessageAttachment.State` (§9.7).
4. **A never returns plaintext for an expired ephemeral record**, under any code path, including history restore.
5. **A owns the local store and its DPAPI sealing.** C writes no message content to disk, ever.
6. **A exposes `commit_lost` as a non-event** or handles the retry internally and never surfaces it (§9.3).
7. **A exposes the advertised caps as data.** C hardcodes no size limit and no retention period; "100 MB" and "1 month" appear in copy only via formatted values.
8. **A excludes `EPH` records from the search index** (§5.7).
9. **A reports store-open failure as an explicit enumerable value on the health event**, never as an empty `ListConversations()` (§9.2).
10. **Every event carries `Seq` and `Dropped`** (§14.1 traps 6 and 8).

### 14.3 What C assumes of Spec B

C never talks to B. These are requirements on B that reach the UI through A, listed here because the UI is where a violation becomes visible.

| Assumption | UI consequence if violated |
|---|---|
| B advertises a per-attachment size cap (default 100 MB) and retention limits, both readable before a send | The client either hardcodes a limit (wrong) or discovers a failure only after a 100 MB upload |
| B accepts one commit per `(group_id, epoch)`, returns the winner, and rejects wrong-epoch records (§9.3) | Retry storms, reordered threads, or a user-visible error for a normal race |
| B distinguishes "pruned by retention" from "never existed" from "refused" in its responses | §9.7 collapses; every missing photo looks broken |
| B signs `FetchAttestation` with a stable long-term Ed25519 key (§9.4) | The server-key pin (§7.6) either never fires or fires constantly |
| B enforces monotonic, not contiguous, `stream_index` per `(group_id, sender_handle)` (§8) | A refused write bricks a conversation's outbox |
| **B authorizes reads (`req_auth`)** | The metadata C renders is readable by any account that guesses a group id |
| **B's `record_id` is gapless including expired ephemerals**, which are kept as placeholder rows | Every disappearing message manufactures a false withholding warning in §9.6 |
| **B advertises `capability_version` and converges the fleet** | Two members of the same group are told different retention |
| B creates **no logs** of client commands or connections in production (§9.7) | The product's honest-limits page (§13 of the master spec) becomes false |
| B never sees plaintext and never needs group membership from the operator (§4.2) | Everything |
| Retention negotiation is warn-and-proceed in **both** directions, returning `RetentionApplied` (C-5, RULED) | §8.4's copy is wrong and a group's real retention is misstated to its members |

### 14.4 What C supplies to A

Spec A §12.2 lists fifteen obligations on this client. Each one has a named C-side implementation here, so none of them is a sentence in someone else's document:

| A's # | Obligation | Where C implements it |
|---|---|---|
| C1 | A writable per-user directory as `MessageClientSettings.StorageDir`, never `%PROGRAMDATA%` | §1.1: `%LOCALAPPDATA%\URmessage\app\storage`. The per-user install (W4, §2.2) is what makes this the natural path rather than an exception |
| C2 | Supply `settings_json` per A's schema — `storage_dir`, `network_space_host`, `message_server_id`; no ByJwt at construction, no handle from another DLL | §1.1's `settings_json` block and the paragraph naming each value's origin (`Common/ServerConfig.h`) |
| C3 | Marshal every callback to the UI dispatcher | §14.1 "Threading": `DispatcherQueue.TryEnqueue`, never a XAML touch on a callback thread |
| C4 | Free every returned `char*` with `urmsg_free_string`, never the CRT `free` | §14.1 trap 1's `detail::dupCString` rule and the `compile_hpp.cpp` compile-only TU (§16.1 gate 3) |
| C5 | Free `void* user_data` only after `urmsg_release(sub)` returns | §14.1 trap 7 |
| C6 | Call `urmsg_client_close` before process exit; assert `urmsg_live_handle_count() == 0` in debug builds | §1.4 "Quit" — drain, stop, exit — with the assert in the debug build's shutdown path |
| C7 / C13 | Render `Sealer.Description()` verbatim in a Security screen, lint-checked | §12's **Security** group; added to §16.3 lint 1's verbatim set |
| C8 | Render MASTER §12.4's three strings verbatim; never "gone forever" for the durable class | §8.1, plus §16.3 lints 1 and 2 |
| C9 | Render `Kind == "gap"` entries visibly, with the reason. Do not hide them | §5.1's gap row, five reasons; §16.2 pins all five |
| C10 | Treat `KeyChangeWarning` as blocking, SSH changed-host-key shape; no verified badge | §7 in full; W8 and §7.5 forbid the badge |
| C11 | Never persist the seedphrase **words** | §6.5: A holds the entropy, C holds the rendered words only for the life of the §6.2 screen. W6, W10 and §6.2's clipboard rules are the enforcement |
| C12 | No administrator tunnel, no privileged service, no WFP, no wintun, no LocalSystem, no mTLS loopback RPC | W2, §0.3's table, and §16.1 gates 4 and 5 |
| C14 | On any event with `Dropped > 0`, discard the window and re-read via `History()` | §14.1 trap 6, §5.1's loading rule, §16.2's injected-drop selftest |
| C15 | Render every closed vocabulary by switching on the value; never parse `out_error` | §9.2 (health), §9.3 (send failures), §9.7 (attachment state), §7.3 (evidence classes) — each cites A's vocabulary rather than restating it |

---

## 15. Not in v1

The rule: **absent, not disabled.** A greyed-out call button teaches a user the product has calling and is broken. Nothing greyed, nothing "coming soon" as a button.

| Deferred (master §2) | What the user sees in v1 |
|---|---|
| Voice and video | No call button anywhere. Not mentioned |
| Message editing | The context menu has Delete, not Edit. `↑` in an empty composer does nothing |
| Multi-server / server choice | Settings shows one server, read-only, with §12.2's sentence |
| Group migration between hosts | Not mentioned. The single-server honesty in §9.4's "What's happening?" covers the consequence |
| History export | Not offered. There is no export button to grey out |
| Public groups | Group creation has no visibility control |
| Stream digests (server-withholding detection) | Settings → Privacy carries one line: *"URmessage cannot yet prove this server didn't quietly drop a message. Detecting that is planned."* — because §12.3 says it is undetectable in v1, and silence would be a claim |
| Per-device write capabilities | The observer copy in §5.6 states the limit plainly |
| Mobile clients | No "Link a phone" entry. Device linking shows a code that another **desktop** can enter |
| App lock / local passcode (C-4) | Not offered. Settings → Account says: *"Anyone who can sign in to Windows on this computer can read these messages — and, until the session is locked, notification actions are suppressed, so nobody can reply from the lock screen without signing in."* |
| Contact avatars / group photos | Identicons, with no upload affordance |
| Backups other than the recovery phrase | Not offered |
| Message forwarding, starring, pinning, drafts sync | Not offered |
| **Per-member delivery state** | The thread shows Queued / Sent / Read. The tooltip says URmessage cannot tell you whether a device fetched a message without the server tracking who reads what (§5.3) |
| Local search (C-3) | **In v1.** Local-only, A-backed, `EPH` records excluded from the index (§5.7) |

---

## 16. Verification and acceptance

### 16.1 Build gates

1. x64 and ARM64 both build in CI on every commit, `fail-fast: false`, msbuild log uploaded on failure. Runner **windows-2022** — `windows-latest` moved to Visual Studio 18 (toolset v180) which keeps v143 for x64 but **not** the v143 ARM64 cross tools.
2. `WindowsTargetPlatformVersion` pinned in `Directory.Build.props` for the real build box, overridden in CI via `/p:` (a global property beats the props file).
3. The `compile_hpp.cpp`-style compile-only TU for `URmessageSdk` (§14.1 trap 1).
4. Manifest check: no `requireAdministrator`, no `highestAvailable`, anywhere.
5. Solution check: no reference to `urnetworkd`, wintun, WFP, or `SplitTunnel` from the URmessage projects.
6. **Exactly one Go DLL is imported by `URmessage.exe`** — a CI check on the import table fails the build if `URnetworkSdk.dll` appears (A12, C-12).
7. **Per-user install location:** the MSI's Messaging components target `%LOCALAPPDATA%\Programs\URmessage\` and no component of that feature targets `ProgramFiles64Folder`.

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
| `StoreUnavailable` transitions | All four store states (`unseal_failed`, `corrupt`, `disk_full`, `locked_by_another_process`) → screen 26, in and out |
| Batched key-change review sheet | Two and more unresolved changes collapse into one sheet; per-contact accept resolves only that contact (§7.1) |
| Gap rendering | All five gap reasons (§5.1) render their own copy; none is silently dropped |
| Ephemeral containment | The four §5.7 rules: reply-by-lookup, copy confirmation, search exclusion, metadata-only message info |
| Event-drop re-read | Inject `Dropped > 0`; assert the window is discarded and `History()` is re-read, not merged (§14.1 trap 6) |
| Focus by id | Focus survives a scroll that recycles the focused container (§13.2) |
| Observer collapse | `SenderRoleAtSend == "observer"` collapses to the system row and expands with the warning (§5.6) |

### 16.3 Copy and contrast lints (build-failing)

1. The three §8.1 keys — and `Sealer.Description()` (§12, Security) — exist and their English values match the source character-for-character.
2. No English string contains the prohibited phrases of §8.1 outside the allowlisted ephemeral keys.
3. No `Foreground` binding to `UrTextFaintBrush` on any `TextBlock` that is not in the decoration allowlist (§13.3).
4. No `SolidColorBrush` literal in `.xaml` or `.cpp` outside `UrColors.h` and `App.xaml` — otherwise the high-contrast dictionary cannot work.
5. Every `Button` / `ToggleButton` whose content is a `FontIcon` has an `AutomationProperties.Name`.
6. **No literal `100 MB`, `100MB`, `1 month`, `30 days` in the string store** — those values are formatted from `ServerInfo()` (§14.2 requirement 7).
7. **No occurrence of `â€`, `Â§`, `Ã¢` or `Ã‚` in any spec or string file.** Double-encoded UTF-8 is undetectable by eye and corrupts the one sentence in the product that must be exact.

Both copy lints had defects that would have shipped:

> **Lint 1** compared to a **hard-wrapped** master file (`msg_disappearing_explainer` is split across two source lines with two leading spaces on the continuation), so a literal comparison fails on whitespace even when the strings are identical — and that failure would mask a real corruption. Collapse all runs of whitespace to a single space on **both** sides before comparing, compare by **codepoint sequence**, and assert the extraction is non-trivially anchored (fail if the extracted master string is empty).
>
> **Lint 2**'s prohibited phrases are English substrings; run against 28 locales it is **vacuous for 27 of them while reporting green**. Keep the substring check for English only. For the other locales substitute a process gate: the §8.5 translator note plus a **recorded human sign-off per locale** for the three §8.1 keys, failing the build when a locale's translation of one of those keys changes without a new sign-off.

### 16.4 Runtime loop

The VPN project's ~40-second loop applies: kill → launch → drive → screenshot → read `%LOCALAPPDATA%\URmessage\app\logs\urmessage-app.log`. Three harness traps, all measured:

- `FindWindow` from a PowerShell P/Invoke harness silently returns 0 unless the `DllImport` sets `CharSet=CharSet.Unicode` — the default marshals ANSI into the `W` entry point. Use `EnumWindows` + `GetClassNameW`, which is immune.
- The harness must call `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` or every screenshot is wrong.
- `pwsh` does not exist on the build box; only `powershell`.

And one specific to this product: **the seedphrase screen cannot be screenshotted** while `WDA_EXCLUDEFROMCAPTURE` is set — that is the feature working. The harness verifies it by asserting the captured region is black, and exercises the screen's content through the automation tree instead.

### 16.5 Acceptance for the first testable build (master §14, slice 5)

Two people, on two Windows machines, each having created an identity and written down a phrase, can:

1. Find each other through the directory, with a KT inclusion proof.
2. Exchange text in a DM and in a 3-person group.
3. React through the reaction picker (screen 24), see read receipts, and see the typing indicator render and clear.
4. See the blocking key-change warning when one of them resets their identity, with the §7.2 copy and the §7.3 evidence rows populated correctly.
5. Read the three §8.1 strings, verbatim, at the moments specified in §8.1.
6. Operate the whole flow with the keyboard alone, and hear it with Narrator.
7. Do all of it with no UAC prompt, no service installed, and the VPN app not present on the machine.
8. **Send and accept a group invitation (screen 23)** — criterion 2's three-person group cannot otherwise be formed, because the second and third members had no UI through which to join.
9. **Link a second computer** from screen 1's link button and send from it.
10. **Install with `ADDLOCAL=Messaging`** on a machine with no VPN feature, sign in, and render in the brand faces.

---

## 17. Cross-references

- **Master protocol design**, `docs/specs/2026-08-12-urmessage-protocol-design.md`: §3 invariants, §5 identity and custody, §8 storage and retention classes, §9 message server, §10 verification, §11 roles, §12 deletion and required UI language, §13 honest limits, §15 open items.
- **SPEC-LEDGER.md**: locked decisions P1–P5, I1–I6, T1–T8; §6 change process, which this document follows.
- **Spec A** (SDK / client core): the entire call and event surface of §14.2, the local store, DPAPI sealing, MLS, and the `URmessageSdk.dll` C ABI.
- **Spec B** (message server): everything in §14.3, plus master §9.
- **VPN client**, `Ryanmello07/urnetwork-windows`: `app/src/App/UrColors.h`, `App.xaml`, `UrComponents.h`, `WindowShell.h`, `Localization.h`, `Common/ConnectionHealth.h`, `Common/ThreadGuard.h`, `app/installer/Package.wxs`, and `docs/superpowers/specs/2026-08-06-ios-parity-native-shell.md` for the native-shell/brand-content rule.
