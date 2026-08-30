# Re-orientation: what stands between here and a human typing a message

Written 2026-08-29 at the owner's request, after an extended run of protocol work, to check the
direction rather than the pace.

## The short version

**The protocol engine is deep and largely sound. The product around it barely exists.** Every one of
the three things a human actually touches — an app, a server to reach, an identity to be — is a shell,
a test double, or absent. Nothing built in the last stretch is visible to a human tester.

That is not an argument that the protocol work was wrong. It found three authentication bypasses,
three entropy substitutions, and a security hole in the plan itself, each of which passed every test
that existed at the time. It is an argument that **the sequencing has drifted**: three independent
workstreams have been idle for weeks, and two of them have no implementation plan at all.

## Where each component actually is

| Component | State | Blocked on |
|---|---|---|
| `connect/mls` — the protocol core | **92 of 170 plan tasks done.** p1, p3, p4, p5 complete | nothing |
| `connect/message` — record layer | complete and green | nothing |
| `connect/protocol` — the wire | complete, generated, gated | nothing |
| `message-server` — api + peer + store | **CP3a: a record travels over two real connect clients** | nothing |
| `message-server` — persistence | **absent.** 19 tables designed in Spec B; `pgx` is not in `go.mod` | nothing |
| `sdk` — `MessageClient` | **absent.** Spec A §7 declares ~135 symbols across 11 subsections; **no plan exists** | a plan |
| `urmessage-windows` | CP1 shell. **Untouched since 2026-08-13** | the sdk |

## What remains in the protocol core

| Plan | Tasks | Done | Left |
|---|---|---|---|
| p2 crypto primitives | 23 | ~17 | **6** (X-Wing: sizes, encap/decap, fuzz, the cross-package pin) |
| p6 framing | 20 | 8 | **12** |
| p7 group lifecycle | 24 | 0 | **24** |
| p8 validation and interop | 36 | 0 | **36** |

**Critical path to CP3b — "a message is private" — is p2(6) + p6(12) + p7(24) = 42 tasks.** At the
current rate of roughly three tasks per four-hour batch that is about fourteen batches.

**p8 is 36 more.** It is the interop and validation slice — the thing that proves this implementation
agrees with other MLS implementations. It is genuinely important and it is **not** on the critical
path to a first human test: a group of two of our own clients does not need to interoperate with
OpenMLS to prove a message arrives.

## The three unplanned things, which are the real risk

Estimates above are grounded because those plans exist and have been executed against. These are not:

1. **The `sdk` `MessageClient`.** Spec A §7 is 11 subsections and ~135 declarations — lifecycle,
   identity, groups, invite links, contact cards, messaging, devices, verification, listeners,
   gomobile constraints, balance. **There is no plan.** This is the single largest unestimated item in
   the project and it sits directly between the protocol and every client.
2. **Server persistence.** Spec B designs 19 tables. The `store` package has an interface, a memory
   implementation, and a **contract suite that both implementations must pass** — which is exactly the
   seam a pgx implementation slots into. Nothing blocks this work today.
3. **Windows client wiring.** Spec C is 13 sections. The shell builds and renders. It cannot be wired
   to anything until the sdk exists.

## What I would change about the order

**Start the pgx store now, in parallel.** It is blocked on nothing, its contract is already written
and executable, and it is the only item on the list whose risk is deployment rather than design.
PROGRESS's own "Ready A" note said the VPS and operator integration are what should not be discovered
late — and they are still undiscovered. A pgx implementation that passes the existing contract suite
turns the VPS from an unknown into a checklist.

**Write the sdk plan before finishing p7.** Not the code — the plan. 135 declarations with no
decomposition is the largest thing standing between the protocol and a human, and its size is
currently a guess. Writing the plan converts a guess into a number, and that number should inform
whether p8 happens before or after the first human test.

**Consider deferring p8 past the first human test.** Interop with OpenMLS proves correctness against
the world. Two of our own clients exchanging a message proves the product exists. The second is what
the owner asked for first, and p8 is 36 tasks of the former.

## What human testing actually requires, minimally

1. Two devices running a client that can create an identity, create a group, and send text.
2. A server they can both reach, whose state survives a restart.
3. The MLS core complete enough that the message is genuinely private — CP3b, not CP3a.

That is: **42 protocol tasks + the sdk + client wiring + a persistent server.** Three of those four
have plans. The sdk does not, and it is on the critical path for two of the three requirements.
