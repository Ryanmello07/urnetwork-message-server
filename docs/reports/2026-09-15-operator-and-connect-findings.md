# What the URmessage alpha needs from `connect` and from the operator

**2026-09-15.** Raised while deploying the first URmessage alpha against the beta operator
(`beta-test.net`) and exchanging real messages between two accounts through a deployed message
server. Everything here is **outside the URmessage repositories** and is reported rather than fixed.

Each item names the file and line it was read at, and says how it was established: **measured**
(reproduced by running something), **read** (established by reading the source), or **inferred**.

---

## 1. `connect/jwt.go:33` reads the wrong claim — BUG, correctness

```go
if networkIdStr, ok := claims["network_name"]; ok {   // means claims["network_id"]
    if networkId, err := ParseId(networkIdStr.(string)); err == nil {
        byJwt.NetworkId = networkId
```

`ByJwt.NetworkId` is parsed out of the **`network_name`** claim, and the **`network_id`** claim is
never read by this function at all.

**Established:** measured. A credential carrying two different ids in the two claims comes back with
`NetworkId` equal to the one from `network_name` (`network_name` claim `01a0a144-…-757fb316`,
`network_id` claim `01a0a144-…-092ca4d2`, `ByJwt.NetworkId` = `…757fb316`).

**Fix:** `claims["network_name"]` → `claims["network_id"]` on line 33 only.

**Blast radius:** this is a live behaviour change for anything reading `ByJwt.NetworkId` today. It
may be load-bearing somewhere that has silently adapted to the wrong value, so it wants a grep of
`NetworkId` across the platform before landing. URmessage reads only `ClientId` and does not depend
on it either way.

---

## 2. `connect/jwt.go` — five unchecked type assertions panic the calling process — BUG, availability

Lines 21, 26, 31, 34, 39. Each `if _, ok := claims[...]` checks **map presence, not type**, and the
value is then asserted to `string` unguarded. Line 21 asserts `token.Claims.(gojwt.MapClaims)`.

**Established:** measured. A JWT whose `network_name` claim is a number gives
`panic: interface conversion: interface {} is float64, not string` at `jwt.go:31`, raised from the
caller's goroutine.

**Why it matters here:** the message server reads its own credential from a config file at startup.
A malformed credential should be a refusal naming the file, not a panic.

**Fix:** fold the lookup and the assertion into one comma-ok at all five sites, e.g.

```go
if networkName, ok := claims["network_name"].(string); ok {
    byJwt.NetworkName = networkName
}
```

No behaviour change for a well-formed credential.

---

## 3. `connect/jwt.go` — an unreadable claim is silently dropped — BUG, design

A claim that is absent, or present but unparseable, leaves the field at its **zero value** and
`ParseByJwtUnverified` returns success. For `client_id` that means `Id{}` — sixteen zero bytes —
which `connect` would then use as that client's **routing address**.

**Established:** read, and defended against downstream. URmessage refuses it at its own boundary
(`errJwtNoClientId`), which is a local patch over an upstream contract that lets an unusable value
out.

**Fix, one of:** return an error when a claim is present and unreadable; or at minimum when
`client_id` is absent. Callers currently cannot distinguish "no client_id" from "client_id is all
zeroes".

---

## 4. The platform DOES authenticate source ids — NO ACTION, and worth recording

Spec B decision B1 delegates §5.1 check 2 to the operator transport: the message server cannot
verify from inside itself that a frame's `source.SourceId` is the client the platform authenticated.
Its startup log says so, and warns that if the platform does **not** authenticate it, a Hello naming
another `client_id` would destroy that client's live connection and `server_nonce`.

**Established:** read, in the operator's own source. Two checks, both dropping without delay and
incrementing `abuseDroppedCounter`:

- `server/connect/resident.go:3815`, forward path — *"clients are not allowed to forward from other
  clients"*
- `server/connect/resident.go:4035`, receive path — *"only messages from the resident client are
  processed by the resident"*

**So the dependency is discharged for this operator, at this commit.** Two caveats worth keeping:
the message server still cannot check it at runtime, so the guarantee travels with the operator
rather than with the protocol; and a different operator supporting URmessage needs the same
verification before it can be trusted with the same claim.

---

## 5. A reconnecting `client_id` is not routed to for ~60 seconds — BUG, and it blocks the alpha

**Measured**, on the beta operator, against the deployed alpha message server. One client, one
`client_id`, nothing else running:

    baseline, a fresh connection      Hello OK in 27ms
    close the connect.Client, then re-dial and Hello repeatedly:
      +12s   FAILED      +24s   FAILED      +37s  FAILED
      +49s   FAILED      +1m1s  FAILED      +1m1s  OK in 32ms

Attempts 5 and 6 fall in the **same second** — one fails, the next succeeds — so this is a hard
edge at ~60s, not a gradual recovery. Reproduced three times with different gaps; the pattern is
always "the first connection after a previous one for that `client_id` is not answered, until about
a minute has passed."

**What it looks like from the client:** the new connection attaches (`IsConnected()` is true, routes
registered), the Hello is sent, and **nothing comes back**. No error, no refusal — silence until the
transport's own deadline. The message server never sees the request: its log records no incoming
frame, and it sets no send contract to that `client_id` during the window.

**Why it blocks the alpha rather than merely annoying it:** every real client reconnects — app
resume, laptop lid, network flap, a restart. On this platform each of those costs **a minute of
total silence** before the first message can be sent. A messenger that cannot talk for 60s after
waking is not shippable, and no amount of client-side work removes the window; the client can only
retry into it.

**Candidates, named without asserting which** — I measured the behaviour, not the cause, and did not
change anything on the operator. In `server/connect/resident.go`'s settings block there are two
60-second values, `DrainStragglerSweepTimeout: 60 * time.Second` (:545) and `StreamPollTimeout:
60 * time.Second` (:549). `ExchangeResidentTtl` is 300s and `ForwardIdleTimeout` 15m, both too long
to be this. **Whether the fix is to invalidate the old route when a new connection for the same
`client_id` registers, rather than waiting for a sweep, is the operator team's call.**

**REFINED, and this is the part that decides what a client can do about it: a request sent into the
window is LOST, not queued.** Measured separately — one connection, one Hello, a **100-second**
timeout spanning the whole handover:

    attempt 1 at +1m40s   Hello FAILED in 1m40.003s     (one request, waiting throughout)
    attempt 2 at +1m41s   Hello OK in 257ms              (a new request, one second later)

The route demonstrably moved during attempt 1's wait, and attempt 1 was **still never answered**.
So the platform drops the frame rather than holding it for the connection that is about to own the
route. Two consequences: **a longer client timeout is not merely insufficient, it is the wrong
remedy** — it spends the entire window on a request that can never succeed; and **sleeping does not
substitute for retrying** — a client that waits 75 seconds and then sends once still fails, measured.
Only re-sending works.

Also worth knowing operationally: the window applies to **any** session that follows another within
a minute for the same `client_id`, not just to a deliberate reconnect. Two back-to-back runs of the
same tool fail on the second one's first Hello.

**What URmessage will do regardless**, so the two are not confused: `Device.Connect` currently sends
one Hello and fails after a single timeout, so a reconnecting client reports a hard error where the
truth is "not yet". That is URmessage's bug and is being fixed on our side — retry with backoff
across the window, and say "reconnecting" rather than "failed". **It does not close this item**: the
60 seconds remain, and the user waits them.

---

## Not operator work, recorded here so the list is not read as complete

`HelloResponse.server_keys` and `kt_gossip` are declared NOT BUILT by the message server itself —
the fleet key chain a client verifies against, and the operator STH. Those are URmessage's to build
and are tracked in `SPEC-LEDGER.md`, not here.
