# Owner decisions 64–65

Earlier rounds: `2026-08-12-owner-decisions-1-45.md`, `-46-49.md`,
`2026-08-13-owner-decisions-50-58.md`, `2026-08-25-owner-decisions-59-63.md`.

**64 is the owner's**, stated 2026-08-26. **65 was taken by the controller** under the standing
delegation, and is recorded with its reasoning so it can be overturned on sight.

| # | Decision | Affects |
|---|---|---|
| 64 | **Apps are coming for every device.** Stated by the owner while approving the key-schedule work: *"We will eventually be making apps for all devices."* This is not new information — Spec A §1 already carried a cross-platform obligation, and MASTER's choice of pure Go over a Rust MLS library was made for exactly this reason — but it changes the obligation's **status**. It was a sentence in a spec that nothing enforced; it is now a product commitment, and the code has to be held to it continuously rather than checked when someone remembers. **Accepted cost:** every future dependency decision in `connect/mls`, `connect/message` and `sdk` is now constrained by the weakest target, and a library that would have been fine for a desktop client is refused. That cost was already implicitly accepted when MLS was implemented in Go rather than linked from Rust; this makes it explicit and mechanical. | Spec A §1, §11.4; all of p4–p8; `sdk` |
| 65 | **The cross-platform obligation is a build gate, and it went in before p4 rather than after.** `mls/crossplatform_test.go` builds `./mls/...` and `./message/...` for **nine platforms with `CGO_ENABLED=0`** — android arm64 and arm, ios arm64, darwin arm64 and amd64, windows amd64, linux amd64 and arm64, and js/wasm — in about eleven seconds. Placed before the key schedule's thirty tasks because the cheapest moment to discover a package no longer builds for iOS is the commit that broke it. **The reason it is worth the eleven seconds was demonstrated rather than argued:** a single windows-only `syscall.NewLazyDLL` in `connect/message` builds clean on the development machine and passes the entire `message` suite green in 9.3 seconds, while failing **eight of the nine platforms** — every one an app would ship on. A developer would have seen nothing wrong. **`CGO_ENABLED=0` is the condition, not an incidental flag**: it is what lets one pure-Go tree serve all nine, and a dependency that needs cgo does not announce itself — it builds where cgo is available, which is the developer's machine, and fails only in the cross-compile nobody runs. **Accepted deviation from this project's own Rule 5:** the platform list is *typed out* rather than derived, which is wrong nearly everywhere else here and right in this one place, because which devices the product supports is a product decision with no source of truth to derive from. What *is* derived is that every entry names a platform `go tool dist list` recognises, so a typo fails rather than silently testing nothing — and the harness carries a control that building for `nosuchos/nosucharch` must FAIL, because a gate that shells out to a compiler and reports what it thinks the compiler said can report success having run nothing. | `connect/mls/crossplatform_test.go`, Spec A §11.4 |

## Application notes

- Decision 65 covers `connect/mls` and `connect/message` only. **`sdk` is a separate module and is
  not reachable from that gate**; Spec A §1 names it too, so `sdk` owes the same gate in its own
  repository and does not have it. That is the first thing to add when `sdk` work starts.
- `js/wasm` is on the list although nothing ships there. It is the strictest target of the set — no
  cgo, no syscalls, no assembly — so it catches a portability defect earlier and more loudly than the
  platforms that actually matter, for the cost of one build. If it ever becomes the reason a
  legitimate change is blocked, drop it deliberately rather than by exception.
- Decision 64 interacts with the font question left open in decision 62: Latin-only faces were a
  cosmetic concern for a desktop VPN dashboard, are a product concern for a messenger, and become a
  per-platform concern once the same brand has to render on Android and iOS system stacks.
