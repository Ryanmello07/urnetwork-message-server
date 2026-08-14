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
