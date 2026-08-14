# URmessage Windows client — scaffold brief

Derived from a read-only survey of the URnetwork Windows VPN client, 2026-08-13. That app is the
brand and shell source; this brief is what a scaffolder needs so the new app inherits the look
without inheriting the tunnel.

**Brand source of truth:** `C:\Users\ryanm\Downloads\claude_sandbox_windows`, branch
**`beta/algorithm-dpi`** (HEAD `eacf4de`) — *not* `beta/custom-server`, which is an older ancestor
in a different clone at `claude_sandbox_windows_ui`. 66 files differ, including `WindowShell`,
`UrMotion`, `WindowReveal`, `TrayIcon`, `AppPrefs` and all 28 `Resources.resw`.

## Corrections to earlier notes — do not scaffold from the old ones

| Stale claim | Reality |
|---|---|
| Mica backdrop is part of the approved look | **Mica was removed 2026-08-07 and the removal is load-bearing.** `WindowShell.cpp:218-247` carries the reasoning: Mica draws *behind* XAML, so showing it means clearing the opaque `#101010` root — at which point the wallpaper *replaces* the brand colour rather than tinting it. The owner saw "bright pink-white while focused, black when not". **URmessage must not add Mica.** `WindowShell.h:28-36` still describes Mica and is stale against its own .cpp. |
| Never calls `AppWindow.Resize()`; opens ~1920×1094 | Fixed. `WindowShell.cpp:335` calls `MoveAndResize`; default 480×760 DIPs, min 400×480. |
| `MainWindow.xaml.cpp` ~2128 lines, monolithic | 1903 lines, and the page split already happened (`ConnectPage`, `AccountPage`, `SettingsPage`, `WalletPage`, `DeveloperPage`, `LoginPage`, `PageContext`). |
| ~916 localization keys, ~248 used | 1206 entries; 466 referenced in code, 39 of those are `Dev()` fallbacks that do not exist in the store yet. |
| vcpkg is used | `app/vcpkg.json` does not exist. nlohmann is vendored under `third_party/vendor-include`. Both `README.md` files still say vcpkg and are stale. |
| Spec at `docs/superpowers/specs/2026-08-06-ios-parity-native-shell.md` | Deleted from this branch by the `urnetwork:main` merge. Readable at `claude_sandbox_windows_ui\docs\superpowers\specs\...` or `git show fc46dde:docs/...`. |

## Two owner questions this raised

1. **Font licensing.** The four brand faces are commercial: ABC Gravity (Dinamo), PP Neue Montreal
   and PP NeueBit (Pangram Pangram). `app/src/App/Assets/README.md:3-9` states they ship inside the
   app and must not be redistributed on their own. **Whether that licence covers a second, separate
   product is not answerable from the repo.** Decision 53 already flagged the licence as
   assume-covered-for-beta / verify-before-GA for *one* app; a second app doubles the exposure.
   Does not block development — building is not distributing — but it blocks shipping.
2. **Non-Latin coverage, and it matters more here than for the VPN app.** All four faces are
   Latin-only (Montreal 596 codepoints, NeueBit 592, ABC Gravity 464). The 28 shipped locales
   include Arabic, Hebrew, Hindi, CJK and Cyrillic, all of which render through DirectWrite
   fallback. For a VPN client that affects chrome; **for a messenger it affects user-typed message
   content**, which is the product. A deliberate fallback-face choice is needed rather than
   whatever DirectWrite picks.

## Identity — the first edit, before anything compiles

`app/src/Common/Ids.h` must be rewritten. Five values collide, and the first one is sharp:

| Constant | VPN value | Why it must change |
|---|---|---|
| `kSingleInstanceKey` :37 | `URnetwork.Desktop` | `AppInstance::FindOrRegisterForKey`. Miss this and **launching URmessage redirects activation into the running VPN client's window.** |
| `kAppUserModelId` :30 | same string | taskbar/notification identity |
| `kTrayIconGuid` :25 | fixed GUID | bound to installed state; two apps would fight over one registration |
| `kUriScheme` :40 | `urnetwork` | deep links |
| tray window class | `URnetworkTrayWindow` (`TrayIcon.cpp:32`) | harnesses find windows by class name |

## The brand layer — copy wholesale

Two mirrored sources, deliberately duplicated, both required: **`app/src/App/UrColors.h`**
(`namespace urnw::colors`, ARGB `{A,R,G,B}`) for C++, and **`app/src/App/App.xaml`** (1123 lines,
`Ur*Brush` keys at :240-285) for markup. The header says "keep the two in sync".

**There is no light theme.** `App.xaml:11` pins `RequestedTheme="Dark"`; the single
`ThemeDictionaries` entry keyed `Default` *is* the dark dictionary. Light/dark exists only for tray
icons, switched off `HKCU\...\SystemUsesLightTheme` (`TrayIcon.cpp:34-42`).

Core tokens: page `#101010`, sheet `#151515`, card `#1C1C1C`, hover `#242424`, pressed `#2A2A2A`,
hairline `#1FFFFFFF`, text `#F8F8F8`, muted `#989898`, faint `#5A5A5A`, inverse `#101010`, danger
`#F8523B`, accent lime `#EFF7BB`, action blue `#638BFC`, Pro gold `#FFC400`.

Semantic rules to inherit: **Pro gold is reserved for the Pro entitlement and nothing else**;
**lime = earnings/brand, blue = action** (an explicit reversal, `App.xaml:1064-1071`); text on
`#638BFC` at ≤14px must be `#101010` (5.9:1), not white (3.0:1); sheets sit one Oklab step above
the page, never flush.

**Structural trap worth copying verbatim:** overrides of WinUI's *own* theme resources
(`AccentButtonBackground`, `NavigationView*`, `TextControl*`, …) must be a **merged dictionary
placed after `XamlControlsResources`** (`App.xaml:17-25`). Put them in the app dictionary's own
`ThemeDictionaries` and all ~45 are silently inert. Also: `NavigationViewContentBackground` defaults
to `#1C1C1C`, identical to `UrCardBrush`, so cards render invisible; and the NavigationView pane
defaults to **acrylic**, which samples the desktop. Both are overridden at `App.xaml:90-153`.

**Fonts** — `app/src/App/Assets/Fonts/`, copied to `$(OutDir)Assets\Fonts` by four
`CopyFileToFolders` items (`App.vcxproj:378-391`), because unpackaged apps resolve `ms-appx:///`
against the exe folder. Reference form is
`ms-appx:///Assets/Fonts/<file>#<OpenType name table id 1>` — the part after `#` is the *font's*
family name, not the file name, and getting it wrong produces **no error**, just silent fallback.
Families: `ABC Gravity Extended`, `ABC Gravity Extra Condensed`, `PP Neue Montreal`, `PP NeueBit`
(no space, Bold face only).

**Type ramp** (`App.xaml:184-238`): ABC Gravity Extended **only** for page titles, hero and
wordmark (Title 28/36, TitleLarge 40/52); everything below is Montreal — Caption 12/16, Body 14/20,
BodyStrong 14/20 SemiBold, BodyLarge 18/24, Subtitle 20/28 SemiBold. Section headers were moved
*out* of ABC Gravity to fix two clashing heading styles. Montreal ships one weight; SemiBold is
DirectWrite-synthesised. Icons: `Segoe Fluent Icons`, named explicitly because `FontIcon` defaults
to the older `Segoe MDL2 Assets` with different metrics.

**Layout — use the pane model, not the card model.** Two vocabularies coexist and `App.xaml:772-799`
says they are incompatible. The card model is rounded islands with margins; the **pane model (R3,
Portmaster idiom)** is floor-to-ceiling columns, no radius or shadow, 1px rules, with metrics at
`App.xaml:802-805`: pane header 40, group header 28, row 40, list row 36, tall row 44. Owner's
verdict driving it: *"Things need to fit in a fill… go with Portmaster looks, less random sized
modules and more fit in."* **A conversation list plus a thread is exactly the pane model**, and
`UrComponents`' `MakePaneTwoLineRowButton` + `MakePaneSearchRow` are almost literally a
conversation list.

**Motion** — `UrMotion.h`: 90/150/250/400/500/1000/1500ms, standard bezier `(.10,.90)(.20,1.0)`,
exit `(.70,0)(1.0,.50)`, `ShouldAnimate()` gates on the OS animation setting, **exits always one
step faster than entrances**. Every button template redefines `CommonStates` wholesale, discarding
the platform transition duration — one `<VisualTransition GeneratedDuration="0:0:0.15"/>` per
template restores it.

## Files to copy essentially unchanged

`UrColors.h`, `App.xaml`, `UrComponents.{h,cpp}` (503+925 lines of `namespace urnw::kit` — dividers,
section headers, metric cards, copy fields, pane rows, empty states, snackbar), `UrMotion.*`,
`WindowShell.*` (382 lines, the cleanest reusable file in the repo — zero VPN awareness),
`WindowReveal.*`, `Localization.*` + `Strings/`, `Startup.*` (minus `ServicePipeProbe`), `main.cpp`,
`App.xaml.*`, `pch.h`, `app.manifest`, `App.rc`, `resource.h`, Common's
`{Log,Paths,Strings,ThreadGuard,AppPrefs,CrashDumps,Version,VersionGrammar}`, `Assets/**` except the
8 VPN tray icons, plus `Directory.Build.props`, `App.vcxproj`, `Common.vcxproj`, `build-local.ps1`,
`package-portable.ps1`, `make-icons.py`.

**Rewrite against, do not copy:** `AppController.{h,cpp}` — its *shape* is right (tray↔window state
fan-out, `OnUi` marshalling, `ownPlacement_`/`applyingPlacement_` distinguishing user drags from
programmatic moves, debounced placement save, `quitting_` as an atomic shutdown gate for
cross-thread `TryEnqueue`) but it owns `SdkHost`, `SubscriptionBalanceStore` and `TunnelStatus`.
Same for `MainWindow.xaml.*`: the title bar, NavigationView and `ApplyBreakpoint` are reusable, the
~1700 lines of destination markup are not.

**Do not copy at all:** anything including `SdkHost.h`, `ServiceClient.h`, `ServiceSetup.h` or
`Protocol.h`; all of `app/src/Service/`, `app/driver/`, `third_party/wintun/`.

## Build skeleton — the hard-won parts

- **Windows App SDK 2.2.0, `WindowsAppSDKSelfContained=true` unconditionally.** With
  `WindowsPackageType=None` the bootstrapper runs from a **CRT initializer before `wWinMain`**, and
  with no options set defaults to show-UI-then-`exit(hr)` — a missing runtime produces no log line
  at all and the exit code *is* the HRESULT. Self-contained defuses this. Keep it.
- **`LanguageStandard` must sit in `ItemDefinitionGroup/ClCompile`, not a PropertyGroup** — as a
  property it is silently ignored and MSVC falls back to C++14.
- **Escaped string literals do not survive MSBuild command-line quoting on this toolchain.** Pass
  bare tokens and stringize in a header. Verified failure: `cl` sees the value end at `L` and
  reports C2065 `'L': undeclared identifier`.
- **Three hand-written targets make a classic C++ `.vcxproj` build XAML at all** (`App.vcxproj:419-487`):
  adding `MarkupCompilePass1;MarkupCompilePass2` to `BeforeClCompileTargets` (the WinUI targets
  define them but only auto-invoke for *managed* builds); populating `@(WinMDReferenceToCompile)`
  from `@(ReferencePath)` (nothing does it for hand-authored C++/WinRT, and the markup compiler
  fails `WMC1007`); and adding `$(IntDir)*.g.cpp` to `@(ClCompile)` while **excluding**
  `App.g.cpp`/`MainWindow.g.cpp`/`XamlMetaDataProvider.g.cpp`, which are include-fragments that
  C1010 if compiled standalone.
- **`resources.pri` needs three coupled settings**, and the failure mode is every string rendering
  as its key id: `ProjectPriFileName=resources.pri`, an **empty** `AppxPriInitialPath` placed
  immediately after `Microsoft.Cpp.props`, and `DefaultLanguage=en` naming a folder that exists.
- `DISABLE_XAML_GENERATED_MAIN` (the app ships its own `wWinMain`), `ResolveNuGetPackages=false`
  (the managed resolver dies on a native project), `#undef GetCurrentTime` in `pch.h` before the
  WinRT headers, and `void* winrt_make_URmessage_App() { return nullptr; }` because cppwinrt emits
  no factory for an `Application` subclass.
- CI must use **`windows-2022`**, not `windows-latest` — the latest image moved to VS18/v180 which
  lacks the v143 ARM64 cross tools. Upload the whole output dir, never a glob: a glob silently
  dropped `Assets\Fonts` once.

## Traps

1. **Add a top-level `.gitattributes` the VPN repo never got.** `core.autocrlf=true` on this box.
   The VPN repo has one *only* for `Assets/` binaries — a font that went through CRLF translation is
   corrupt with no diagnostic. CRLF has already cost this project twice elsewhere.
2. **`URNETWORK_APP_ROOT`** overrides the per-user root; set it per worktree or two builds corrupt
   each other's prefs and logs.
3. **DPI**: manifest is `PerMonitorV2` and the app works in physical pixels. A harness that is not
   DPI-aware reads 1536×875 where the app logs 1920×1094 — call
   `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` first.
4. **`FindWindow` silently returns 0** from a PowerShell P/Invoke harness unless `DllImport` sets
   `CharSet=CharSet.Unicode` — the default marshals ANSI into the `W` entry point. Use
   `EnumWindows` + `GetClassNameW`. Select processes by **executable path**, never by name or window
   title — those are identical across worktrees.
5. **A `/SUBSYSTEM:WINDOWS` process has no console.** `Startup.cpp:148-163`'s `WriteStdout` is the
   pattern: `GetConsoleMode` succeeds → `WriteConsoleW`; fails → UTF-8 bytes via `WriteFile`.
6. **`ResourceManager` must be a named local** that outlives the `ResourceContext` it produces
   (`Localization.cpp:44-62`). Chaining destroys it at end-of-statement; the next line reads a freed
   handle and MRM `abort()`s with `0xC0000409`, a fail-fast that walks past every catch.
7. **A mechanism with no observable signal does not exist.** PrintWindow does not composite acrylic
   or Mica, so a PrintWindow capture of a backdrop change is a lie — verify with `CopyFromScreen` of
   an *active* window. An API-level readback of `FallbackColor` once passed while the pixels were wrong.
8. **Signing**: OV Authenticode is sufficient (EV is only for the kernel-driver track, which this app
   does not have). Keep the signer identity stable — **the tray icon GUID registration is bound to
   exe path + signer.**
9. **Store policy 10.5.1 makes a privacy policy URL mandatory**, and for a messenger that is
   unavoidable rather than optional.
