# URmessage — build progress

Append-only. Newest section last. One entry per completed unit of work, with the evidence
that it is actually done rather than reported done.

Detail lives in the per-plan SDD ledgers (`connect/.superpowers/sdd/<plan>/progress.md`),
which are not committed. This file is the durable summary.

---

## Tracks

Three tracks run in parallel because they are **separate repositories**, which is what makes
parallelism safe here — a single checkout cannot take concurrent agents without the git index
colliding, and that has cost this project real work before.

| Track | Repo | State |
|---|---|---|
| **A — protocol core** | `Ryanmello07/connect`, branch `beta/message` | p1 complete; p2–p8 to go |
| **B — Windows client** | `Ryanmello07/urnetwork-windows` (brand source) → new `message-windows` | surveying the VPN app's brand and shell |
| **C — message server** | `Ryanmello07/urnetwork-message-server` | greenfield; specs written, no code yet |

## Checkpoints

The owner's goal is a testable build at each step, ending at "able to send messages".

- **CP1 — the app you can look at.** WinUI 3 client with the VPN app's brand, theme and shell.
  Real and safe to run: it is a UI shell, not a messenger yet.
- **CP2 — the protocol core.** MLS (RFC 9420) in pure Go: p2–p7.
- **CP3 — first message end to end.** Two clients, one group, one message through the server.
- **CP4 — the feature set** from Spec C.

**Deliberate sequencing note:** CP3 comes *after* the real MLS core, not before it. A quicker
vertical slice with placeholder crypto would reach "a message appeared on the other screen"
sooner, and was rejected: in a privacy product a build that sends unprotected traffic is a
hazard the moment it exists, because it looks exactly like the real thing to anyone testing it.
The early visible checkpoint is CP1, which is honest — it is a shell and cannot be mistaken for
a working messenger.

---

## 2026-08-13 — Plan p1 complete: the TLS presentation-language codec

`connect/mls/syntax`, 19 planned tasks plus one follow-up, **23 commits, 135 tests**, pushed to
`beta/message` at `6b7e440`. Every task: fresh implementer, adversarial review, fixes, ledger entry.

Shipped: RFC 9420 §2.1.2 varints (canonical, reserved and non-minimal forms rejected), `opaque<V>`,
`LP(x)` for record framing, capacity-clipped sub-readers, `optional<T>` with a strict presence
octet, byte-counted vectors, `Marshal`/`Unmarshal` with full-consumption enforcement,
`CheckRoundTrip`, a hand-derived golden table, allocation bounds, a structured generator, three
fuzz targets and a CI gate.

**Nine consecutive tasks found a test in the plan that could not fail.** The one that mattered
most: all three of the plan's `CheckRoundTrip` tests passed against a version that did all the
work, evaluated the comparison, discarded the result and returned `nil` — and since all nine of
p8's fuzz targets call it, that would have made every one of them vacuous while reporting green.
The habit that caught these was mutation testing every claim: patch the version you rejected in
an isolated copy, and confirm the test actually fails on it.

**Four API gaps closed that the plan did not have**, each with a silent failure mode:
`CheckRoundTripLimit` (without it a ratchet tree returns `nil` unchecked and cannot be fuzzed at
all), `ReadNested` and `WriteNested` (nesting silently accepted trailing bytes in one direction
and silently capped a nested field at the wrong limit in the other). All four are in the interface
registry, so p5–p8 inherit them rather than rediscovering them.

**Measured, and it changed p8's design:** uniform random bytes reach the round-trip property
**14 times in 4096 — 0.34%** — against the *simplest possible* type, while the structured
generator reaches it 4096/4096. So p8's seed corpus is load-bearing rather than an optimisation,
and every fuzz target must now count what it actually decoded and fail at zero reachability.

## 2026-08-13 — connect CI restored, and a silently disabled safety net repaired

`connect` had run **no CI at all since 2026-08-04**, on `main` included: merge `35ceb0f0`
resolved to the parent that had no `.github` directory. Verified it was a coherent merge
resolution rather than index corruption — exactly six files, all from one work stream.

- `test.yml` restored and now on **both** `main` (`7167f3d`) and `beta/message`. Two changes from
  the restored file: the trigger covers `main` and `beta/**` (the original fired on
  `beta/custom-server` alone, which is *why* its loss went unnoticed for nine days), and the
  toolchain is read from `go.mod` rather than `stable`.
- `provider-release.yml` restored retargeted, tag renamed `beta-message-latest` — leaving the old
  name would have force-pushed over the existing provider beta release the first time it ran.

**The find underneath it.** Nine root-package tests were failing. A nine-agent diagnosis (one per
test, each required to rule out the alternatives with cited evidence) returned **zero real
regressions** — two environmental causes, both Windows-only:

- Six anchor tests: `core.autocrlf=true` at *system* scope. `functionBody` delimits a function
  with a bare `"\n}\n"`, which occurs **zero** times in a CRLF checkout against 286 of the CRLF
  form, so it fell through to returning the whole rest of the file.
- Three queue tests: Windows advances `time.Now()` only every **~500µs** (measured), so thousands
  of `pumpQueue` adds share a timestamp and a strict `Before` leaves ties unordered.

The important part was not the nine failures. Because `functionBody` widened silently instead of
erroring, the failure was **asymmetric**: 6 anchors written as `strings.Count` failed loudly,
while **84 written as `strings.Contains` passed vacuously**, matching text from elsewhere in the
file. These anchors exist precisely because seam wiring turned out to be deletable with zero
behavioural test failures — so on Windows the net was not protecting anything. Fixed in `42c9035`
(and cherry-picked to `main`); 17 anchor tests pass afterwards, so nothing was hiding behind the
vacuous passes.

Second time `core.autocrlf` has bitten this project — it also smudged the 16 vendored IETF vector
files during p1, which would have invalidated the entire "our codec passes the IETF vectors"
argument.

## 2026-08-13 — CHECKPOINT 1: the Windows client builds, launches and renders

`Ryanmello07/urmessage-windows`, **private**, 61 files, 3 commits. WinUI 3 / C++/WinRT, x64 Release
clean in 41s with 0 errors. Opens at 480×760 DIPs; a second launch redirects under its own key
`URmessage.Desktop` rather than into the VPN client's window.

Brand, palette and pane model lifted from the VPN app: `#101010` page, `#151515` header strips, PP
NeueBit wordmark, ABC Gravity for page titles, and the conversation list built from the VPN's own
`kit::MakePaneTwoLineRowButton` + `MakePaneSearchRow` — no rounded islands, hairline separation,
uniform row heights. The pane model rather than the card model, per the owner's "less random sized
modules and more fit in".

**The repo is private because it carries the four commercial font binaries** (ABC Gravity from
Dinamo; PP Neue Montreal and PP NeueBit from Pangram Pangram), whose licence says they ship inside
the app and must not be redistributed on their own. Whether that licence covers a second product is
an open owner question. **Related and pre-existing: `Ryanmello07/urnetwork-windows` is public and
contains the same four files.**

Two corrections the scaffolder found in the brief, both worth keeping:

- **The identity list was incomplete.** Beyond the five constants in `Ids.h`, three more `URnetwork`
  values are hard-coded in files the survey called copy-clean — including
  `HKCU\Software\URnetwork\Window`, whose placement blob carries a magic and version, so URmessage
  would have *accepted the VPN app's saved window geometry*. Also the storage root and the log
  filename. All now route through `Ids.h`.
- **The font check cannot be done by eye, and the agent's first read of it was wrong.** It judged the
  wordmark a fallback because it did not look pixelated, then measured: rendered ink 111×19 at a 30px
  em, against PP NeueBit 114×19, Montreal 164×27, ABC Gravity 219×28, Segoe UI 160×28. A wrong font
  family name produces **no error**, only silent fallback, so measurement is the only check that
  works. Method recorded in the repo's `Assets/README.md`.

Honest gaps: **ARM64 does not build here** (`MSB8020` — this box's VS18 Build Tools has x64 cross
tools only; environment gap, unverified rather than known-good). Data is stubbed — ten sample rows,
search filters nothing, rows have no click handler, no tray icon, placement is never saved. The app
icon is still the VPN's globe.

## 2026-08-13 — connect CI is green, and the data path picked up two real fixes

All workflows pass on `beta/message` at `18e6bd7` and on `main` at `7167f3d`. `main` has had working
CI for the first time since 2026-08-04.

The `Test — connect` run passing on Linux with the same code that fails nine tests on this Windows
box **demonstrates** the environmental diagnosis that was previously only argued.

Four commits, two of them beyond what was briefed, each isolated so either can be dropped:

- **My diagnosis of the extender failure was wrong**, and acting on it would have turned CI red. I
  attributed it to the 1s listener race; the implementer pulled logs from four CI runs and found the
  failure lands 0.15–0.27s *after* the sleep expired, with `listen tcp 1442` already up. The real
  cause is the content server binding `:443` **inside** `ListenAndServeTLS` on a goroutine, which
  discards the bind error. Fixed with a checked ephemeral port; the destination travels in the
  extender header, so no production code changed. Now demonstrated by CI passing with extender
  folded into the gate and `continue-on-error` removed.
- **The `pumpQueue` tiebreak cannot fix two of the three trim tests**, because `combineQueue` has no
  `pumpItem` and no `seq`, and `RemoveOlder` never reads `seq`. Their cause is the strict `Before`
  cutoff: both queues stamp `updateTime` from the same coarse clock the caller samples the cutoff
  from, so an item stamped just before the cutoff is never *older* than it. Measured: of 4096 adds,
  1433 carried the cutoff's own timestamp and exactly 1433 were left behind. Fixed by making the
  boundary inclusive. Each fix verified independently load-bearing by reverting only that change.
