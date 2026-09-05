# [`connect/messagegroup` — the Record Layer's Crypto, in the Half the Server Cannot Link] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the CP3a/CP3b delta. `connect/message` today carries **opaque bytes** — its own
`doc.go` says the key schedule "lands beside them" in the future tense, and `grep -rn 'func
StorageRoot'` over the whole tree returns **0**. Since the 2026-09-06 ruling the key schedule does
not land beside them at all: it lands in a **second package, `connect/messagegroup`**, and the
message server links only the half left behind. The section after Global Constraints is that
ruling; read it before any Files line, because it decides every one of them. This plan builds what turns that record layer into
an encrypting one: Spec A §5.2's construction order as a type, §5.3's key schedule, §5.5's sender and
receiver ratchets, §5.6's durable `stream_index` reservation, and the client half of §5.11's epoch
fan-out — plus the parts of §5.7, §5.13 and §5.14 that are absent but off the CP3b path. §5.1, §5.4,
§5.7's MAC surface, §5.8 and §5.11's encoding are **landed and correct**; this plan does not touch
them, and says so file by file, because the defect this project has already paid for once is a second
implementation of a preimage that already exists.

**Architecture:** Four layers, and the ordering between them is forced rather than chosen. **The
schedule** (`keyschedule.go`, `handle.go`) turns one MLS exporter output and one PQ secret into every
key the record layer uses; it is pure arithmetic over byte slices, and every function in it is
package-level and stateless. **The ratchets** (`ratchet.go`, `streamindex.go`) turn a class key into
a sequence of per-record keys, and own the two pieces of state that must never rewind — the sender's
position, and the durable index reservation in front of it. **The session** (`engine.go`,
`session.go`, `seal.go`) is the only stateful exported type: one MLS group behind §6's narrow
interface, one command loop, and the two methods §5.2 makes the only door in and out. **The epoch
fan-out** (`epoch.go`, `wrap.go`) is the part that makes a *second* client able to compute the same
`storage_root`, and it is where this plan meets two gaps no spec has closed. **All four layers land
in `connect/messagegroup`,** not in `connect/message`; the next section is the ruling that says why,
and it changes every Files line, every gate scope and the Definition of done below.

**Tech Stack:** Go 1.26.5, standard library plus `golang.org/x/crypto/chacha20poly1305` (already a
direct dependency of `connect` at v0.54.0). No new module, no new dependency, no cgo. `connect/mls`
is imported as a peer for `syntax`, `CryptoProvider`, `X25519DH` and the group engine — **by
`connect/messagegroup` and never by `connect/message`**, which is the ruling the next section
states; nothing new is written in `connect/mls` except the gate amendments this plan owes it.

---

## The ruling this plan is now written under: `connect/message` is split in two

**The property, stated as a capability and not as a habit: the message server *cannot* link an MLS
parser.** Not "does not call one". The difference is the whole of the ruling, and it is the
difference between a gate that fails when somebody is wrong and a code review that catches it.

**The measurement that forced it, reproduced 2026-09-05 at `msgrepo` `c089bb3`.** `go test ./ -run
TestEveryDependencyOfThisModuleIsOneSpecB22Allows` in `msgrepo` **fails**:

> spec B §2.2 forbids these outright and this module reaches them:
>   github.com/urnetwork/connect/mls

`go list -deps -test ./...` over `msgrepo` names **exactly one** direct importer of
`github.com/urnetwork/connect/mls` in the whole closure, and it is `github.com/urnetwork/connect/message`.
Inside that package it is **`xwing.go` alone**: the four X25519 wrappers, `ErrNilRandomSource`, and
two compile-time pins against `mls.XwingPublicKeyLen` and `mls.AlgIdXwing`. `connect/mls/syntax` —
which `aad.go`, `codec.go`, `attachment.go` and `writeauth.go` use — is **explicitly allowed**
(`msgrepo/deps_test.go:146`, spec B revision 10), so those four files are not the problem and do not
move. And `msgrepo` uses X-Wing nowhere: `grep -rn 'Xwing' --include='*.go'` over the whole module,
tests included, returns **0**.

**The split.** `connect/message` keeps the **server-safe** half — the record layer the server
genuinely parses, plus the two published surfaces §12.1 puts on it. Everything a client alone needs
moves to a second package, **`connect/messagegroup`**, which `msgrepo` never imports and which is
free to import `connect/mls` because it *is* the client. The import edge that was
`connect/message → connect/mls` becomes `connect/messagegroup → connect/mls`, and a new one-way edge
`connect/messagegroup → connect/message` appears; nothing in `connect/message` may import
`connect/messagegroup`.

**Why a sibling and not `connect/message/group`, measured in both directions.** `msgrepo`'s allow
list carries `{path: "github.com/urnetwork/connect/message", subtree: true}` (`deps_test.go:145`).
Probed on the pinned toolchain against a working copy of `connect` with the split applied:

| the client half lives at | it imports `connect/mls` | `msgrepo` links it | the gate says |
|---|---|---|---|
| `connect/messagegroup` | no | yes | **FAIL** — "not in spec B §2.2's allow list" |
| `connect/message/group` | no | yes | **silence** — the subtree entry covers it |
| `connect/message/group` | yes | yes | FAIL — but only because `connect/mls` is separately forbidden |

So the sibling name is load-bearing and is not a matter of taste. Under a subtree child the server
could link the whole key schedule, both ratchets, the session and the sealer and the gate would say
nothing, which is the *"does not call one"* property this ruling rejects. Under the sibling, the day
any `msgrepo` package imports it the gate fails and a human looks. **Do not tidy
`connect/messagegroup` into `connect/message/group`.**

**What turns the red green, and what does not.** With `xwing.go` and `xwing_errors.go` moved to
`connect/messagegroup` and nothing else changed, the same gate passes — measured, against a working
copy, with **no edit to `allowedDependencies` and no edit to spec B**. `connect/mls` simply leaves
the closure. The gate's own message says *"either the import is wrong, or §2.2 has grown"*; the
import was wrong.

---

## Global Constraints

### The three rules this plan is written under

These come from this project's own ledger. They change how every task below is meant to be read.

**R1 — this plan supplies no test code, and neither may a task.** Across p1–p7 the implementers found
roughly **thirty** plan-supplied tests that could not fail: nine consecutive p1 tasks each carried
one; p6 Task 23's five plan tests **as a set** could not fail against 16 of 26 mutations; p6 Task
17's generator emitted a JSON object where the runner required an array, so that task's whole
direction could not execute at all. Every task below therefore states **the property**, **the refusal
that property owes**, and **the mutation set the implementer must run**. The implementer derives the
test. A plan that hands over a test hands over the illusion of coverage.

**R2 — every signature is read from source, never from this plan.** Ledger 25: `FindExtension`
changed shape and seven plan call sites still spelled the old one — ten references in p7, nine in p5,
three each in the registry and p8. Every Go fragment in this document is **illustrative of shape, not
of spelling.** Before writing a call, read the declaration out of the file that owns it. This applies
with particular force to `mls.CryptoProvider`, `mls.Group.Export`, `mls.X25519DH`, `message.AADHead`,
`message.AADBody`, `message.BodyBinding`, `message.ComputeWriteAuth`,
`message.EncodeServerAttachment` and everything in `connect/mls/syntax` — all of which this plan
describes and none of which it quotes normatively. A plan is authoritative about design and stale
about shapes within weeks.

**R3 — a rule is stated in as many conditions as its source states it.** p5's plan stated RFC 9420
§7.9.2's **three**-condition parent-hash rule as **one**, in two independent places, and the omitted
condition admitted a forged-subtree splice. Where a rule below is normative, the spec text is
**quoted**, not paraphrased, and the section is named. If a task's step disagrees with the quotation
beside it, the quotation wins and the disagreement is a defect in this plan to be reported, not
resolved silently.

**R3a, its corollary for gates — every gate derives its class AND its scope.** Ledger 21: five times
on this project a gate derived its class correctly and then wrote its scope down beside it — one file
name where the subject was a package, one root where the table was keyed for two. Every task below
that builds or amends a gate must answer the scope question separately from the class question, **in
the gate's own header comment**, and a reviewer must ask them separately.

### Repository, branch, toolchain

- Code lands in `connect`, branch **`beta/message`** (1,078 tracked files at the time of writing).
  `msgrepo` is on `main` and holds only this plan and the ledger entry beside it. `sdk` is on
  `beta/message`.
- Go **1.26.5**, pinned. The toolchain in this sandbox is not on `PATH`; set `GOROOT` and prepend
  `$GOROOT/bin` in every shell.
- `go build ./message/... ./messagegroup/... ./mls/...` is the floor, not the gate, and must be green
  at the end of every task. Before the code move lands it is `./message/... ./mls/...`; the day
  `connect/messagegroup` exists, every command in this plan gains it, including the `go test` in each
  task's step 4.
- Measured state of `connect/message` on 2026-09-04, so a later reader can tell what this plan added:
  **9 non-test files** (`aad.go`, `attachment.go`, `codec.go`, `doc.go`, `errors.go`, `record.go`,
  `writeauth.go`, `xwing.go`, `xwing_errors.go`), **9 test files**, **169 `Test` functions** and
  **2 `Fuzz` functions**. Of those nine, **two move to `connect/messagegroup`** — `xwing.go` and
  `xwing_errors.go`, the pair that carries the whole `connect/mls` edge — in a commit that is not
  this plan's; `entropy_test.go` moves with them, because Gate B resolves each row against the
  declaring package. The other seven stay.
- **`msgrepo`'s suite is red at `main` until that move lands**, for exactly the reason the ruling
  section states, and the fix is in the `connect` tree rather than in `msgrepo`. Do not add
  `connect/mls` to `msgrepo/deps_test.go`'s allow list, do not skip the gate, do not silence it.

### Dependency policy

- **New dependencies in `connect`: none.** `golang.org/x/crypto v0.54.0` is already a direct
  requirement (`connect/go.mod` line 20) and `chacha20poly1305.NewX` is in it. Nothing else is
  needed. `connect/messagegroup` is a **new package**, not a new module and not a new dependency.
- **The edge that is the whole ruling: `connect/message` must never import `connect/mls`.** It may
  import `connect/mls/syntax`, which spec B §2.2 allows by name and §13 item 8 argues is not an MLS
  implementation. `connect/messagegroup` **may and does** import `connect/mls`, and that import is
  correct rather than tolerated: `messagegroup` is the client half and the client holds the group.
- `connect/messagegroup` imports `connect/message`; **`connect/message` never imports
  `connect/messagegroup`**, and that direction is the one a refactor breaks by accident. It is worth
  one assertion in `connect/layering_test.go` beside the four §2.3 already carries.
- `connect/message` and `connect/messagegroup` must never import `sdk`. `connect` must never import
  either of them or `connect/mls`. `connect/mls` must never import either of them.
- `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, `crypto/sha256`, `crypto/ed25519` and
  `crypto/subtle` are the stdlib crypto this plan may reach. Every X25519 operation goes through
  `mls.X25519PrivateKey` / `mls.X25519PublicKey` / `mls.X25519GenerateKey` / `mls.X25519DH`
  (`connect/mls/crypto_x25519.go`), which is the one file guardrail G3's gate allows `.ECDH(` in.
  `messagegroup/xwing.go` (today `message/xwing.go`, and the file whose `connect/mls` import is the
  whole reason for the split) already does exactly this and is the model. **After the split that
  import stops being a tolerated exception and becomes the package's ordinary case** — see the
  ruling section, and M1-48 for the three shapes the follow-on commit could take instead.

### House style

Per `CODESTYLE.md` and the shape of the nine plans before this one (p1–p8 and s1): `self`
receivers; guarded state named `stateLock`; explicit struct field names at every literal; a doc
comment on every file, type
and function, saying **why** and not only what. `connect/mls` and `connect/message` have **no
timing-sensitive tests** and must keep it that way — a function that needs a clock takes an injected
`nowMs func() int64`, never `time.Now`.

### The gates already in the tree, which this plan's code must satisfy from its first commit

This is the most important part of the constraints, because five of these gates fail in a
**different package's** test suite than the code that breaks them, and one fails on *correct* code
the day a new function is declared. Every one was read out of source on 2026-09-04, and every scan
root below was re-read on 2026-09-05 against the split.

**The split moves four of these gates' scopes, and three of the four move silently if nobody does
it.** Every one of them derives a class over a *directory list*, and every new file this plan writes
now lands in a directory none of those lists names. A gate whose root is missing does not fail — it
reports clean having read nothing, which this tree calls its most expensive failure mode. The four,
with the one-line change each needs and the commit it belongs in:

| Gate | Today | After the split | Fails loudly if forgotten? |
|---|---|---|---|
| A — `mls/crypto_forbidden_test.go` | `forbiddenScanRoots = {".", "../message"}` | add `"../messagegroup"` | **no** — the hkdf and `.ECDH(` confinements simply stop covering the client half |
| B — `mls/crypto_test.go` | walks `forbiddenScanRoots` (Gate A's list, measured at `crypto_test.go:7781`) | fixed by the **same one-line change** | **yes**, once A is fixed: the two rows for `XwingGenerateKey` and `XwingEncapsulate` resolve against the declaring package, so the move forces `entropy_test.go` to move in the same commit |
| C — `message/writeauth_test.go` | `authScanDir = "."` | `connect/messagegroup` owes its **own** copy, or this one widens to both | **no** — the constant-time class over the client half goes empty |
| D — `message/record_test.go` | `joinScanRoots = {".", "../mls", sdk}` | add the `messagegroup` root; `joinAllowedPaths` stays `{"record.go"}` because `record.go` stays | **no** — a client file could join class and bucket unseen |

Gate A's is the load-bearing edit and it is **one line in one file**, so it is cheap; what makes it
worth a table is that three of the four are silent, and the ruling's whole point is that a property
must be held by something that fails. **Gate B is the one that forces the others**: because it walks
Gate A's list and resolves each row against the package that declares the function, the day
`XwingGenerateKey` moves, the `mls` suite goes red until `forbiddenScanRoots` names
`../messagegroup` *and* `entropy_test.go` is there to hold the refusal. Sequence the code move
accordingly: Gate A's root, the two files and `entropy_test.go`, in one commit.

Gate E is unaffected — `ComputeRequestAuth` stays in `connect/message`. Gate F is *strengthened*:
`SealRecord`/`OpenRecord` are now in a different package entirely, so `codec.go`'s claim that it
exports nothing beyond §12.1's three functions is held by the package boundary rather than by taste.

Every one below is stated as it reads **today**; apply the table above when you write the
amendment.

**Gate A — `connect/mls/crypto_forbidden_test.go` scans `../message`.**
`forbiddenScanRoots = []string{".", "../message"}` (line 46). It bans four primitive tokens
(`GenerateSharedSecret`, `box.Precompute`, `curve25519.ScalarMult`, `golang.org/x/crypto/nacl/box`)
across both trees; it confines the whole `crypto/hkdf` entry-point class to
`hkdfExtractAllowedPaths = []string{"crypto.go", "hpke.go"}` (line 83); it confines `.ECDH(` to
`ecdhAllowedPaths = []string{"crypto_x25519.go"}` (line 90); and it carries one reviewed exception,
`hkdfExtraCallSites = map[string][]string{"hkdf.Expand(": {"../message/writeauth.go"}}` (line 425).
Two properties of this gate decide how a task must be sequenced:

- It **refuses an allow-list entry whose file no longer makes the call**, so an entry cannot be added
  ahead of the code it excuses.
- `TestHkdfConfinementFlagsTheControlFixture` **builds one nested control twin per allow-list entry**
  and requires each to be reported, so a path added without its twin fails rather than arriving
  uncontrolled.

Consequence: the first `hkdf.Expand` in a **new** `messagegroup` file, and any `hkdf.Extract`
anywhere under either root, turns the **`mls`** suite red — *provided* `forbiddenScanRoots` names
`../messagegroup`. If it does not, the same code lands unexamined. The amendment and the code must
land in **one commit**, and the amendment is now two things: the root, and the path entry.

**Gate B — `connect/mls/crypto_test.go:7781`, `TestNoEntropyTakingFunctionLivesWhereThisGateCannotCallIt`.**
It derives, **by type**, every package-level function under `../message` taking an entropy source and
fails on any member `entropyRefusalsHeldOutsideThisPackage` (`crypto_test.go:7776`) has no row for —
and fails again if the test that row names does not resolve against a declaration in that package.
`connect/messagegroup/entropy_test.go` holds the other half: a probe table that **calls** each member with
a nil reader and with an exhausted reader, and requires the refusal to be `mls.ErrNilRandomSource`.
Today the class is two members (`XwingGenerateKey`, `XwingEncapsulate`).

Consequence: `NewEphRoot(rand io.Reader)` — and any `pq_secret` sampler that takes one — joins that
class **the moment it is declared**, and needs its row in `mls`, its probe in `messagegroup`, and
both refusals, in the same commit as the declaration. Both of today's members move with `xwing.go`,
so `entropy_test.go` moves with them and the rows' `holder` package changes underneath them; the
gate resolves each row against the declaring package and will say so.

**Gate C — `connect/message/writeauth_test.go`'s constant-time gate, which is guardrail G8 built
wider than G8's own text.** `authScanDir = "."`: it reads **every production file of the package**,
not the three file names §5.9 G8 lists — and after the split "the package" is `connect/message`
alone, which is where `writeauth.go`, `recovery.go` and `rendezvous.go`'s published half live and
where no other file of this plan does. Four rules run over it:

- `TestNoProductionFunctionComparesDataOutsideConstantTime` — no function anywhere in the package may
  call a comparator from the derived class (`bytes.Equal`, `bytes.Compare`, `slices.Equal`,
  `strings.Contains`, `reflect.DeepEqual` and the rest, derived from the files' own imports).
- `TestNoVerifierDecidesEqualityInVariableTime` — over the class **every function whose name begins
  with `Verify`**, derived from the tree rather than listed.
- `TestAVerifierReachesOutOfItsPackageOnlyForTheConstantTimeComparison` — a `Verify*` function's body
  may call **no** imported package's function other than `subtle.ConstantTimeCompare`.
- `TestEveryVerifierReachesAConstantTimeComparison` — and it must reach one, transitively.

Consequence, and this one is a genuine problem this plan files rather than works around:
**`VerifyRecoveryProof` and the five `VerifyRendezvous*` functions join that class by name the day
they are declared** — and all six are declared in `connect/message`, because §12.1 publishes them,
so M1-19 lands against *this* gate exactly where it always did, and an Ed25519 verifier satisfies neither the third rule (its body calls
`ed25519.Verify`) nor the fourth (it reaches no constant-time comparison, because Ed25519
verification is constant-time *inside the standard library* and compares nothing here). See
**Open item M1-19**. Do not exempt the function: the gate's class is right and its *property* is
stated for MAC verifiers only.

**Gate D — `connect/message/record_test.go`'s join gate.** `joinAllowedPaths = []string{"record.go"}`,
read off the syntax tree, scanning `connect/message`, `connect/mls` **and** the `sdk` repository
beside it (`joinScanRoots`, `record_test.go:673`). No new file may join or split a retention class
and an eph bucket; `RetentionClassOf` and `RetentionClassWire` are the only two places, and §5.1
says so. `record.go` stays in `connect/message`, so the allowance does not move; the **scan** must
gain `connect/messagegroup`, or every file this plan writes is outside it — including `seal.go`,
which is the one place a class and a bucket are naturally at hand together.

**Gate E — `TestReadAuthNeverUsesWriteKey`** (`writeauth_test.go:1904`) walks the call graph of
`ComputeRequestAuth` and asserts no path reaches the write key's label. Anything this plan adds
between a session and a request MAC is inside that walk.

**Gate F — `codec.go`'s own claim.** Its header comment states that the file "does not export
anything beyond the three functions spec A section 12.1 publishes", because §12.1's block is restated
character-for-character in Spec B §12.1. §5.2 puts `SealRecord`/`OpenRecord` in `codec.go`. **They do
not go there** — see the File Structure note — and the reason is this comment, not taste.

---

## Interfaces consumed from other plans

Read every one of these out of source before using it (R2). Shapes below, not spellings.

### From `connect/mls` — landed, and to be **called**, never reimplemented

```go
// connect/mls/crypto.go — the CryptoProvider interface (line 55) and its one implementation,
// reached through NewCryptoProvider(suite) / NewCryptoProviderWithRandom. Extract's own
// comment says it in as many words: "Extract takes the salt first, matching the spec text
// rather than the library." That is guardrail G1's fix, already written, already tested
// against RFC 5869's table, already inside one of the only two files Gate A allows.
Extract(salt []byte, ikm []byte) []byte                       // = HKDF-Extract(salt, ikm)
Expand(prk []byte, info []byte, length int) []byte            // = HKDF-Expand
Hash(data []byte) []byte
AeadSeal(key, nonce, aad, plaintext []byte) ([]byte, error)   // NOT the record AEAD; see below
```

```go
// connect/mls/group.go:821 — RFC 9420 §8.5 MLS-Exporter, complete and vector-tested.
// mls_secret[n] is ONE call: Export("URmessage/v1/storage", nil, 32).
// It returns ErrEpochErased for an aged-out epoch (key_schedule.go:486 refuses to export
// from a KDF.Nh-zero exporter secret), so its CALLER handles that error, one level above
// §5.3's error-free StorageRoot signature.
func (self *Group) Export(label string, context []byte, length int) ([]byte, error)
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error)  // the closed enum — G6 is landed
func (self *Group) ClearPendingCommit()                               // group.go:2475 — G10's MLS half
```

```go
// connect/mls/crypto_x25519.go — guardrail G3's confinement. The only file the ECDH gate
// allows. messagegroup/xwing.go routes through these; anything new does the same.
func X25519PrivateKey(b []byte) (*ecdh.PrivateKey, error)
func X25519PublicKey(b []byte) (*ecdh.PublicKey, error)
func X25519GenerateKey(random io.Reader) (*ecdh.PrivateKey, error)
func X25519DH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error)
```

```go
// connect/mls/syntax — the ONE length-prefix implementation. The record layer uses the LP
// form (WriteOpaqueLP / ReadOpaqueLP, a fixed 32-bit big-endian prefix, encode.go:160)
// everywhere and NEVER WriteOpaque, which is MLS's varint (encode.go:137). codec.go's
// header comment and encode.go:150-159 both say they are never interchangeable.
// MaxVectorLength = 1<<20.
```

```go
// connect/mls/secret_zeroize.go:42 — //go:noinline plus a plain byte loop. UNEXPORTED, so
// message needs its own. Its comment argues at length AGAINST adding anything further and
// explicitly rejects runtime.KeepAlive because importing runtime widens an import set
// another gate pins. connect/mls production code contains no `unsafe` at all.
func zeroizeSecret(secret []byte)
```

```go
// connect/mls/extension.go — the wrap target's public key lives here.
// ExtensionTypeUrmessageLeafKeys = 0xF002; LeafKeysExtension{AlgId uint16, DeviceXwingPub []byte}.
// A v1 group's RequiredCapabilities fix extension_types = [0xF001, 0xF002] (§3.4), so EVERY
// member carries one — which is what makes a per-leaf wrap fan-out total rather than
// best-effort, and is why §3.4 says a client that does not understand it "cannot be added".
```

**Design to be ported, code not to be imported — `connect/mls/secret_tree.go`.** It is §5.5 already
solved once, correctly: a forward hash ratchet (`ratchet.step`), a bounded skipped-key window
(`peekFor`, `keyFor`, `catchUpLocked`), `eraseKey`, `evictOldest`, `prune`, an exhaustion **refusal**
rather than a counter wrap, and `Zeroize`. Its constants are §5.5's own — `RatchetWindowSize = 1024`,
`MaxRetainedWindowKeys = RatchetWindowSize`, `MaxGenerationSkip = 1024` — and one of its comments
cites "spec A section 5.5" by name. It is **not** reusable as code: it is keyed by
`(LeafIndex, RatchetType)` over `uint32` generations, rooted in MLS's `encryption_secret`, using
`DeriveTreeSecret`/`ExpandWithLabel` labels, and the `ratchet` type is unexported; `connect/mls` may
not import `connect/message` or `connect/messagegroup`, so it cannot be lifted either. Port the **structure and the eviction
policy** and none of the derivation. Task 8 says why its policy is better than §5.5's and what
adopting it closes.

**Not reusable, stated because it looks like it should be — `mls`'s AEAD.** `hpkeNewAead`
(`hpke.go:326`) is `chacha20poly1305.New` (12-byte nonce) or AES-GCM, selected by `params.Nn`, and
`Group.Protect`/`Unprotect`/`SealPrivateMessage`/`MessageKeySource` are MLS's own application-message
AEAD keyed off `encryption_secret` through the secret tree. Records are sealed under `record_key[i]`
from `storage_root`, which is a **different** schedule with a PQ input MLS knows nothing about, and
§5.3's 56-octet expansion (32 key + **24** nonce) is XChaCha20-Poly1305's and no other v1 suite's.
Task 1 writes a new wrapper. Do not budget for a reuse here.

**Not reusable, and the trap is silent — `mls`'s Ed25519.** `crypto_labels.go` signs
`mlsSignContent(label, content)`, the RFC 9420 SignWithLabel framing. Every preimage in §5.7 and
§5.14 is a **raw** byte string with no MLS label prefix. Routing the recovery proof or any rendezvous
signature through the `mls` signer **compiles**, and produces a signature that verifies against
nothing any spec preimage describes. Only the seed→public-key helper shape transfers.

### From `connect/message` itself — landed, and this plan's first consumer

```go
// aad.go — the two record AEAD preimages of MASTER §8. G4 is built as a SIGNATURE: AADBody
// takes a six-field projection with no hash in reach, so body_hash cannot be put in AAD_body.
// SealRecord calls these; it does not rebuild them.
type BodyBinding struct{ /* six fields */ }
func (self *RecordHeader) BodyBinding() BodyBinding
func AADBody(algId uint16, binding BodyBinding) ([]byte, error)
func AADHead(algId uint16, h *RecordHeader, serverAttachment []byte) ([]byte, error)
```

```go
// writeauth.go — all eight of §5.7's MAC functions, 36 tests, constant-time throughout, G7
// and G8 honoured, the preimage field order matching §5.7's block character for character.
// WriteKey and ReadKey take a storageRoot that NOTHING IN THE TREE PRODUCES: the only
// storage roots in the package today are a KAT constant in a test file. Task 3 is the
// missing producer for 125 KB of already-tested code.
func WriteKey(storageRoot []byte) []byte
func ReadKey(storageRootEpoch []byte) []byte
func ComputeWriteAuth(writeKey, serverNonce []byte, h *RecordHeader, ctHead, serverAttachment []byte) [32]byte
func VerifyWriteAuth(writeKey, serverNonce []byte, r *Record) bool
```

```go
// record.go, codec.go, attachment.go — §5.1, §5.8 and §5.11's encoding, all landed and
// checked field-for-field against the spec blocks. RecordHeader's twelve fields, Record's
// five, both ladders, the one join/split pair, EncodeRecord/ParseRecord/ParseRecordHeader
// over mls/syntax, the five attachment kinds with their alg-id table and their width checks,
// and ErrServerAttachmentNoneEncoded. Nothing here is replanned by this document.
```

```go
// xwing.go — §5.4 COMPLETE and beyond the spec: all five spec constants plus four written
// for G9, every declared function at the spec's signature plus (*XwingPrivateKey).Seed(),
// and XwingAlgId/XwingPublicKeySize cross-checked against mls.AlgIdXwing / mls.XwingPublicKeyLen
// by zero-length-array assertions in BOTH directions (xwing.go:72-77), so drift across the
// package boundary fails to BUILD. All three of §5.4's mandatory-before-any-use tests exist,
// and the low-order-point negative is held in both directions where the spec asked for one.
// NOTHING IN §5.4 NEEDS BUILDING. It is on this plan's path only as the wrap's input.
```

### Pending pins — symbols this plan names that do not exist yet

| Symbol | Producer | Consumed by | State on 2026-09-04 |
|---|---|---|---|
| `pq_secret[n]`, as a value with a type and a sampler | **this plan, Task 13** | `StorageRoot`'s second argument | absent everywhere: no type, no file, no spec section |
| the device wrap's body encoding and its seal | **unruled — Open item M1-1** | Task 14 | `wrap.go` is named in §2.2 and has no section in any spec |
| the joiner's channel for `group_handle_key` | **unruled — Open item M1-2** | Task 16 | `grep -rn 'group_handle_key\|GroupHandleKey'` over `connect` returns **0** |
| `mls.CheckGroupSize`, `mls.CheckDeviceCount` | p7 Task 20 | nothing in this plan | absent; the two constants exist, the two checks do not |
| `SubmitResult.winning_commit` | Spec B / `msgrepo` | Task 21 (§5.12) | Spec B's type; `msgrepo/store` serves `Submit` today |
| `testdata/message-server-vectors.json` | §12.1 A-8, **unowned** | Tasks 15, 20, 23 | absent in both repositories |
| §6's `RatchetTreeSnapshot()`, `GroupContextBytes()` | **not pending — landed under other names** | Task 9's interface, Task 9a's adapter, Task 15's snapshot | `Group.RatchetTree()` at `group.go:891` and `Group.GroupContext()` at `:900`, both `([]byte, error)`, measured 2026-09-05; the divergence is §6's spelling and Task 9a closes it. O-4 withdrawn |

---

## Interfaces produced by this plan

Every consumer — s5, s7, Spec B's handlers, and this plan's own later tasks — writes its `Consumes`
block against these. Shapes, not spellings (R2). Each is restated inside the task that creates it.

```go
// connect/messagegroup/recordaead.go — the record AEAD, pinned. MASTER §8 line 722.
const RecordAeadAlgId uint16 = 0x0021        // XChaCha20-Poly1305
```

```go
// connect/messagegroup/keyschedule.go — §5.3
func StorageRoot(mlsSecret, pqSecret []byte) []byte
type ClassKeys struct{ Perm, Durable, Media []byte }   // Eph is DELIBERATELY absent — MASTER I4
func DeriveClassKeys(storageRoot []byte) *ClassKeys
func RecordKeyZero(classKey []byte, leaf uint32) []byte
func RecordKeyNext(recordKey []byte) []byte
func RecordAeadHead(recordKey []byte) (key, nonce []byte)
func RecordAeadBody(recordKey []byte) (key, nonce []byte)
```

```go
// connect/messagegroup/handle.go — §5.3 and §5.11
func GroupHandleKey(storageRootEpoch0 []byte) []byte
func SenderHandle(groupHandleKey []byte, leaf uint32) [16]byte
func WrapTargetHandle(groupHandleKey []byte, epoch uint64, leafIndex uint32) [16]byte
```

```go
// connect/messagegroup/streamindex.go — §5.6. The interface's KEYING is Open item M1-5.
type StreamIndexReserver interface{ /* Reserve, HighWater */ }
```

```go
// connect/messagegroup/ratchet.go — §5.5
type SenderRatchet struct{ /* stateLock-guarded */ }
type ReceiverRatchet struct{ /* stateLock-guarded */ }
```

```go
// connect/messagegroup/engine.go — §6's narrow swappable interface, declared HERE, not in
// sdk and no longer in connect/message: §12.1 gives the server "no MLS type", and an interface
// whose entire subject is an MLS group is one. §2.2's tree kept the interface and the adapter
// in one file and this plan keeps that; what changes is which package the file is in.
type GroupEngine interface{ /* four methods */ }
type GroupHandle interface{ /* 23 methods: the MLS surface the client half is allowed to see */ }
type EngineProcessed struct{ /* Raw and stagedRef opaque */ }

// the connect/mls adapter. *mls.Group does NOT satisfy GroupHandle — 13 of the 23 methods
// cannot match, measured; see Task 9 property 3. This is what does. stagedRef does NOT force
// its home: a keyed composite literal naming only exported fields is legal across packages,
// so a foreign type CAN implement Process — only POPULATING stagedRef is confined (M1-43).
// What the split DOES force is that EngineProcessed moves WITH the adapter: leaving the
// struct in connect/message and putting the adapter here would place stagedRef out of the
// adapter's own reach and cost §6's unforgeability argument outright. They travel together.
func NewConnectMlsEngine(...) (GroupEngine, error)
```

```go
// connect/messagegroup/session.go, seal.go — §5.2
type GroupSession struct{ /* one GroupHandle, one command loop */ }
func (self *GroupSession) SealRecord(...) (*Record, error)
func (self *GroupSession) OpenRecord(record *Record) (headPlain, bodyPlain []byte, err error)
```

```go
// connect/messagegroup/eph.go, blob.go, card.go, rendezvous.go — wave 3, the client side
func NewEphRoot(rand io.Reader) ([]byte, error)
func EphKey(ephRoot []byte, bucket uint8, window uint64) []byte
// ... blob_id and the object padder, §5.14's card derivations, the sealed deposit, the
// five §5.14 signers, and the client half of the losing-committer contract

// connect/message/recovery.go, rendezvous.go — wave 3, and these two files stay on the
// SERVER side: §12.1 publishes every name below and Spec B §12.1 restates that block
// character for character, so moving one of them is a two-document amendment.
func RecoveryProof(recoveryRoot, serverNonce, recoveryHandle []byte) ([]byte, error)
func VerifyRecoveryProof(recoveryVerifyPub, serverNonce, recoveryHandle, sig []byte) bool
func RendezvousId(token []byte) [32]byte
// ... and the rest of §12.1's rendezvous block
```

---

## File Structure

Every file created or modified by this plan, and its single responsibility. Paths are relative to the
`connect` checkout, and **the first path segment is now the ruling**: `messagegroup/` is the client
half, `message/` is the server-safe half, and every row below was derived rather than inherited. The
derivation, stated once so each row can be checked against it:

**A file stays in `connect/message` if and only if the server genuinely reaches it.** The authority
is §12.1's published block, which Spec B §12.1 restates character for character and which §5.2
summarises as *"Spec B's server-side code never seals or opens"*. Measured against `msgrepo` on
2026-09-05: every `message.X` symbol the module names, tests included, is **37 distinct symbols**,
and every one of them is declared in `record.go`, `codec.go`, `attachment.go`, `writeauth.go` or
`errors.go`. Not one is from `aad.go`. Nothing else of this plan's is reachable from the server at
all, and `msgrepo` names `Xwing` zero times.

**The two rows that are genuinely on both sides are marked, and they are findings rather than
defects.**

| File | Responsibility | Task |
|---|---|---|
| `messagegroup/recordaead.go` | `RecordAeadAlgId`, the XChaCha20-Poly1305 seal/open wrapper, its width refusals | 1 |
| `messagegroup/zeroize.go` | the package's own `//go:noinline` best-effort zeroization | 2 |
| `messagegroup/keyschedule.go` | `StorageRoot`, `ClassKeys`, `DeriveClassKeys`, the record-key ratchet's four derivations, and §5.11 E2's `K_snapshot` | 3, 5, 15 |
| `messagegroup/handle.go` | `GroupHandleKey`, `SenderHandle`, `WrapTargetHandle` | 4 |
| `messagegroup/streamindex.go` | `StreamIndexReserver`, the two sentinels, the resume rule — **not** a durable implementation, see Task 6 | 6 |
| `messagegroup/ratchet.go` | `SenderRatchet`, `ReceiverRatchet`, the skipped-key window and its eviction | 7, 8 |
| `messagegroup/engine.go` | §6's `GroupEngine`, `GroupHandle`, `EngineProcessed`, **and the `connect/mls` adapter that satisfies them** — one file per §2.2, and one **package** because `stagedRef` is unexported | 9, 9a |
| `messagegroup/session.go` | `GroupSession`: construction, the `run()` loop, epoch state, `Close` | 10 |
| `messagegroup/seal.go` | `SealRecord`, `OpenRecord`, the unexported `recordBuilder`, the body padder | 11, 12 |
| `messagegroup/epoch.go` | `pq_secret` sampling, the provisional epoch value and its destructor (G10) | 13 |
| `messagegroup/wrap.go` | the device wrap, the recovery wrap, the snapshot record, the fan-out | 14, 15, 19 |
| `messagegroup/eph.go` | `NewEphRoot`, `EphKey`, window expiry | 17 |
| `message/recovery.go` | the Ed25519 recovery proof and its verifier | 18 |
| `messagegroup/blob.go` | `blob_id`, the 256 KiB object padder, the MIME sniff | 20 |
| `messagegroup/commitretry.go` | §5.12's seven-step contract and its back-off | 21 |
| `messagegroup/card.go` | §5.14's card derivations and the 131-byte encoding | 22 |
| `message/rendezvous.go` | **both sides.** §12.1's nine published functions — `RendezvousId`, `DepositVerifyKey`, `RendezvousRegisterPreimage`, the five `VerifyRendezvous*`, `RendezvousDepositBytes` — plus `RendezvousRegistration` and `RendezvousCollectParams` | 23 |
| `messagegroup/rendezvous.go` | **both sides.** The client half §12.1 publishes none of: the 5,238-octet deposit sealed under X-Wing to the card's KEM key, and the five §5.14 signers over `message`'s preimages | 23 |
| `messagegroup/reaction.go` | §5.1's REACTION body validation | 24 |
| `messagegroup/errors.go` | **created** — the client half's sentinels, each in the commit that makes it reachable; `xwing_errors.go` arrives here with `xwing.go` in the code move | most |
| `message/errors.go` | **modified** — only where a §12.1-published function gains a refusal. A-9's rule decides which file a sentinel lives in and now decides which **package** too | 18, 23 |
| `message/doc.go` | **modified** — its header says the key schedule "lands beside them" in the future tense; after the split that is not merely stale but wrong about the package, and it must name `connect/messagegroup` | 12, 16 |
| `messagegroup/doc.go` | **created** — the package's own argument: why it exists, that it is the only half that may import `connect/mls`, and that nothing in `connect/message` may import it | 1 |
| `messagegroup/entropy_test.go` | **modified** — one probe row per new entropy-taking function | 13, 17 |
| `mls/crypto_forbidden_test.go` | **modified** — hkdf allow-list entries and their nested control twins | 3, 5, 22, 23 |
| `mls/crypto_test.go` | **modified** — `entropyRefusalsHeldOutsideThisPackage` rows | 13, 17 |

**This table does not "follow §2.2"; it diverges from it in fourteen places, and now in a
fifteenth that subsumes them.** Gate A's allow-lists are lists of **paths** and Gate C's scan is a
**directory**, so where a function lands changes which gate reads it — which is why the divergences
are enumerated rather than summarised. Measured against §2.2's `message/` tree as it stood before
A-12 (fifteen files in one block); the amended tree is at **spec lines 169–206**, `message/` from
169 and `messagegroup/` from 185. Every spec-line citation in this document was re-read against
source after A-12 moved these sections; the plan linter does not resolve them, so they are the one
class of reference here a machine does not check.

**The fifteenth divergence is the ruling itself: §2.2's tree gave `connect/message` one directory
and this plan gives it two.** §2.2 has been amended — its tree now carries a `messagegroup/` block
beside `message/` — so this is a recorded divergence and not a live one. Of the fifteen files
§2.2's `message/` block named, **seven stay** (`record.go`, `codec.go`, `writeauth.go`,
`attachment.go`, `recovery.go`, `pad.go`, `errors.go`) and **eight move** (`keyschedule.go`,
`ratchet.go`, `xwing.go`, `wrap.go`, `handle.go`, `engine.go`, `tombstone.go`, `eph.go`). Three of
the fifteen are worth a sentence each rather than a row:

- **`errors.go` is in both.** Each package owns its own sentinels, and A-9's rule — a sentinel a
  published function can return is owed a §12.1 line in the commit that makes it reachable — now
  decides which **package** as well as which file.
- **`pad.go` stays and its responsibility does not.** §2.2 gave it *"size buckets, COVER records"*.
  The ladder is authenticated and is already in `record.go` and `codec.go`; COVER and the body
  padder are done under a record key, so they are `messagegroup`'s (Task 24 and Task 11). The file
  name stays on the server side with the half that belongs there.
- **`recovery.go` stays because §12.1 publishes both of its functions**, which is the one place
  the surface test and the "client half" instinct disagree — see M1-47.

Neither `pad.go` nor `tombstone.go` is created by this plan at all, which is M1-36's own subject and
is unchanged by the split.

**Eleven files this plan adds that §2.2 does not name:** `recordaead.go`, `zeroize.go`,
`streamindex.go`, `session.go`, `seal.go`, `epoch.go`, `blob.go`, `commitretry.go`, `card.go`,
`rendezvous.go`, `reaction.go`. Each is a §2.2 responsibility split out rather than a new one, and
the four that matter to a gate are these:

- **`seal.go`** — `SealRecord`/`OpenRecord`, which §5.2's comment puts in `codec.go`. `codec.go`'s
  own header states it exports nothing beyond the three functions §12.1 publishes, *"because that
  block is restated character for character in spec B section 12.1 and a fourth name here breaks the
  claim that the two are the same list."* That claim is worth more than the spec's file annotation.
- **`streamindex.go`** — `StreamIndexReserver`, which **§5.6's own interface block writes
  `// ratchet.go` above**, and which §2.2 did not name at all. This plan splits it out because the
  reserver is not a ratchet and Task 6 is ordered before Task 7 for that reason. It was a silent
  divergence from a spec comment until this line, and A-12 closed it in the spec: §5.6's block now
  reads `// messagegroup/streamindex.go` (spec line 1314) and §2.2's tree names the file.
- **`recordaead.go`** and **`zeroize.go`** — both new surfaces with no §2.2 home, and both now in
  `connect/messagegroup`, which Gate C's directory scan **does not reach** until somebody widens it.
  That is the Gate C row of the table in the constraints section, and it is why these two are still
  listed here: before the split they were "inside Gate C from their first commit", and after it they
  are inside nothing.
- **`epoch.go`**, **`card.go`**, **`rendezvous.go`** — each an hkdf entry point's home, so each is a
  Gate A path question (Task 3(b)). Two of the three are now `../messagegroup/` paths and the third
  is on both sides, so each Gate A amendment names a root the gate does not walk today.

**Two files §2.2 names that this plan does not create,** and only one was accounted for:

- **`pad.go`** — accounted for. Task 24 records that its size-bucket ladder is already in `record.go`
  and `codec.go`, and the body padder M1-7 rules on goes in `seal.go` beside its unpadder.
- **`tombstone.go`** — **not** accounted for before this line. Task 24 absorbs *"tombstones and
  `COVER`"* into `reaction.go` in one clause. That is a file §2.2 names disappearing into a file
  §2.2 does not, for no stated reason. Either Task 24 creates `tombstone.go` as §2.2 says, or it
  says why one file holds three unrelated body validations. **This plan takes neither position**;
  it is recorded in **M1-36** with the rest.

**One function moved without the move being stated:** `SenderHandle` goes in **`handle.go`** and not
in `keyschedule.go` where §5.3's comment puts it, because §2.2's tree says `handle.go`. That one was
already argued; it is listed here so the count is complete.

**`aad.go` stays in `connect/message`, and the reason is not the one the ruling gave.** The ruling
lists it among "the record layer the server genuinely parses". Measured, it is not: `msgrepo` calls
`AADHead`, `AADBody` and `BodyBinding` **zero** times, and §12.1 A-9 says in as many words that
those three are *"deliberately on no line of §12.1 because the server never decrypts"*. By the
surface test alone it is a client file. It stays anyway, for two reasons worth more than the
symmetry:

- **`BodyBinding()` is a method on `RecordHeader`,** a §12.1-published type declared in
  `record.go`. Go permits a method only in its type's own package, so moving `aad.go` turns
  `h.BodyBinding()` into `messagegroup.BodyBindingOf(h)` — a shape change to landed,
  vector-tested code, for no gate benefit.
- **`aad.go` imports only `connect/mls/syntax`,** which spec B §2.2 allows by name, so it costs the
  server nothing to link. The property this ruling protects is *"the server cannot link an MLS
  parser"*, not *"the server links only §12.1"* — and §12.1 A-9 already states that §12.1 "was
  never the package's export set". The mechanism for the narrower property is the allowlist test
  ledger open item 7 and **O-3** ask for; it is a test, not a package boundary.

Recorded as **M1-46**, so a later reader who checks `aad.go` against the surface test finds the
argument rather than a hole.

**Open item M1-36** carries all of it. The rule this section is written under: a divergence a reader
can only find by diffing two tables is a divergence that gets re-litigated, and on a file-scoped gate
it gets re-litigated as a hole.

---

## Where the CP3b line falls, stated plainly

CP3b is `PROGRESS.md`'s: *"a message is private — the same path with the real MLS key schedule
underneath. This is the original CP3, and it is the bar for anything a human is invited to send a
real message through."* Concretely: **two clients, one group, one DURABLE text message, every key
real, no test-only key source anywhere on the path.**

**Tasks 1 through 16 are this plan's whole contribution to that path, in order. Nothing outside them
is on it — and they are not the whole path.** Tasks 1–12 and 9a are buildable today. Tasks 13–16 are
on the path and **two of them are blocked on rulings this plan files rather than makes** — that is
the single most important scheduling fact in this document, and it is stated here rather than
discovered at Task 14.

| Wave | Tasks | On CP3b? | Note |
|---|---|---|---|
| 1 | 1–12, and 9a | **yes** | unblocked: the schedule, the ratchets, the adapter, the session, seal and open |
| 2 | 13–16 | **yes** | the second client's half; Tasks 14 and 16 need rulings M1-1 and M1-2 |
| 3 | 17–24 | **no** | required before the A6 format freeze; none is required to put a message in front of a person |

**And the two legs this plan does not have.** CP3b's own words are *"through the message server"*. Every
task above stops at a `*Record` in memory. Measured on 2026-09-05: `grep -nE 'Submit|transport|
harness'` over this document finds **no task producing a submit path**; `msgrepo/store` and the api
layer serve `Submit` and `Fetch` and need nothing new (the 2026-09-02 chain review's leg 3, verified);
and the only client-side sealer-and-submitter in either tree is `msgrepo/harness`, which is
`msgrepo`-local, gated test-only by `TestTheHarnessIsReachedOnlyFromTests`, and *"does not encrypt"*
by its own doc comment. The chain review assigns the client leg to **s1 plus the two-to-four sdk
plans that do not exist** — *"the transport binding, a send path and a receive path"* — and this plan
does not touch `sdk`. **Open item M1-42** files that no written plan owns it, and the Definition of
done below names it in the external legs rather than implying tasks 1–16 reach the milestone alone.

**The second leg is the durable `stream_index` reserver, and it was made a leg by this plan's own
repair.** Task 6 declares `StreamIndexReserver` and — since 2026-09-05 — ships **no** production
implementation, only the interface and a file-backed fake confined to `streamindex_test.go`; §8.2
assigns the durable one to `sdk`'s `MessageStore`, whose plan is unwritten. §5.6 is explicit about
what the fake stands in for: a reused `stream_index` is a reused nonce under a reused `record_key`,
*"a total break of both AEADs for that record"*. So a CP3b run over the fake proves the record layer
and not the client, exactly as a run without the submit path does. It is **leg 5** of the Definition
of done, asked of the sdk store plan as **O-5**, and it is there because an exhaustive list that
silently lost a leg is the failure this section was written to stop.

**On the CP3b path and already done, so no task exists for it:** the whole of §5.4 (X-Wing), §5.1's
record types and both ladders, §5.8's codec, §5.7's `write_auth` and `req_auth`, and §5.11's
attachment encoding. The remaining work in §5.7 is not in §5.7 at all — it is **producing a
`storage_root` to call `WriteKey` with**, which is Task 3.

**Off the CP3b path, and named as a deferral rather than left silent:** the EPH class in every form
(`NewEphRoot`, `EphKey`, the eph ladder, tombstones); the recovery proof and the recovery wraps;
blobs beyond the record shape; §5.14's cards and rendezvous; reactions; COVER records and padding
beyond the size-bucket ladder; §5.12 steps 1, 2, 4, 5 and 6. Each has a task in wave 3 and each is
required before A6 freezes the wire format.

**The trap inside those deferrals — the one ledger item 47 names.** §5.11 defines
`expected_wrap_count` as *"device wraps + recovery wraps + 1 snapshot, for the epoch it opens"*, and
the server checks only that the `EpochComplete` marker's `wrap_count` equals the attachment's
`expected_wrap_count` — **it has no idea what the right number is.** A client that defers recovery
wraps therefore passes the server while diverging from the spec's own definition of the field. That
is a deferral the system cannot detect, which is the exact shape of defect this project keeps paying
for. Task 15 makes the count **derived from the fan-out it actually built**, and gates the deferral
with a failing test that names it. It is not a number an implementer picks.

**The same rule applies to any interim `pq_secret`.** `HKDF-Extract(mls_secret, 32 zero bytes)`
produces a perfectly good `storage_root`; both clients agree; every test passes; and the PQ half of
the design is silently gone. If a wave-1 task needs a `pq_secret` before Task 13 lands, it must be a
**named, single-call-site, test-only** value with a gate asserting it is unreachable from any
non-test build — the identical discipline that made CP3a's absent-not-placeholder key source safe.
The rule that made that work is worth repeating verbatim: *"a missing key schedule fails closed and
looks like what it is; a placeholder one fails open and looks like a working messenger."*

---

## How to read a task

Each task has **Files**, an **Interfaces** block naming exactly what it consumes and what it
produces, and numbered steps. The steps are always these six, and steps 1 and 5 are where the work
is:

1. **Derive the property and write the failing test.** The task states the property, the refusal that
   property owes, and — separately, per R3a — the scope any gate must derive. It does **not** state
   the test. Read every signature you call out of source (R2).
2. **Run it and watch it fail for the stated reason.** A test that fails to compile has not yet
   failed for the stated reason.
3. **Write the minimal implementation.**
4. **Run it and watch it pass.** Then `go build ./message/... ./mls/...` and
   `go test ./message/... ./mls/...`, because five of this plan's constraints fail in `mls`'s suite.
5. **Mutation-test.** Apply each numbered mutation, run the targeted `-run` first, then the full
   package. **A surviving mutation is a defect in the test, not a curiosity.** Record survivors and
   the reason any is accepted, in the commit message.
6. **Commit.** One task, one commit, with the gate amendments it owes in the same commit.

---

# Wave 1 — the CP3b prefix, unblocked

## Task 1: The record AEAD, and the `alg_id` nothing in the package can name

**Files:**
- Create: `connect/messagegroup/recordaead.go`
- Test: `connect/messagegroup/recordaead_test.go`
- Modify: `connect/messagegroup/errors.go`

**Interfaces:**
- Consumes: `golang.org/x/crypto/chacha20poly1305` (`NewX`, `NonceSizeX`, `KeySize`, `Overhead`);
  `message.AADHead`, `message.AADBody` — read their signatures out of `aad.go`.
- Produces:
```go
// the record AEAD's own identifier, inside BOTH record AAD preimages.
const RecordAeadAlgId uint16 = 0x0021

// the two halves of the record AEAD. Unexported: nothing outside this package seals or
// opens a record, and §12.1's block gives the server no decryption function at all.
func sealRecordAead(key, nonce, aad, plaintext []byte) ([]byte, error)
func openRecordAead(key, nonce, aad, ciphertext []byte) ([]byte, error)

var ErrRecordAeadKeyLength   error
var ErrRecordAeadNonceLength error
var ErrRecordAeadOpen        error
```

**Why this is first.** `AADHead` and `AADBody` already take `algId uint16` as a bare caller-supplied
argument and **there is no named constant in `connect/message` to pass** — `grep -rn 'AlgId'` over
the package finds only `XwingAlgId = 0x0014` and `attachment.go`'s per-kind map (`0x0031`, `0x0001`).
Until the value and the primitive are fixed, no KAT can be written, no cross-implementation vector
can be generated, and the landed AAD builders cannot be called with a defensible argument.

**The source, quoted, because Spec A §5 never restates it.** MASTER §8 line 722:

> **`alg_id` in both record AADs is `0x0021`, XChaCha20-Poly1305** (amended 2026-08-25, found by
> building the preimages). […] The derivation above settles which: it hands out
> `key_head ‖ nonce_head` as 56 octets, a 32-octet key and a **24-octet nonce**, and a 24-octet nonce
> is XChaCha20-Poly1305's and no other v1 suite's. `0x0031` (HKDF-SHA-256) names the function that
> produced that key, not the one that consumes it, and a client that wrote it here would build a
> preimage that round-trips against itself and fails the AEAD against every other implementation, on
> every record it sends.

MASTER §7.1's registry (line 612) carries `0x0021 | XChaCha20-Poly1305`. Spec A §5.1–§5.5 mention
neither — **Open item M1-10**, filed, not resolved: MASTER is normative here and the omission is
Spec A's to repair.

**One measured fact that makes this cheap and one that makes it dangerous.** `aad_test.go:70`
already declares `const aadKatAlgId uint16 = 0x0021` for its own vectors, so the value is already
pinned in a test and not in production. The danger: `chacha20poly1305.New` (12-byte nonce) and
`chacha20poly1305.NewX` (24-byte nonce) differ by two characters, and a build using the former
against a 56-octet expansion silently discards 12 octets of nonce and still round-trips against
itself.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the constant is `0x0021`, and it is one constant.** Assert the value against
  MASTER §8 line 722 and assert there is exactly one declaration of it in the package.

  **The call-site half of this property does not belong in this commit, and the split moved which
  directory it will read.** The scope question (R3a) would be *every call of `AADHead` or `AADBody`
  in production source passes it*, derived off the tree — and **that class is empty here**: measured
  2026-09-05, `connect/message`'s production source contains **no** call of either builder, and the
  first is Task 11's `SealRecord`, which now lands in `connect/messagegroup`. So the gate is a
  **two-directory** one from the start: the builders stay in `connect/message` and every caller is
  in `connect/messagegroup`, which means the class is derived over both roots and the members are
  all on one side. Answer the scope question in the gate's own header, as R3a requires, and say
  which root each half comes from — the same shape Gate A already uses with
  `forbiddenScanRoots`.
  The tree's house style **fatals on an empty derived class** rather than reporting clean over it —
  `aad_test.go:1293`, `:1432` and `:1539` and `writeauth_test.go:2451` all say *"reporting clean
  having read nothing"* — so a gate written here would either fail on arrival or, written without
  that guard, pass vacuously, which is R1's whole subject. **The call-site gate is Task 11
  Property 7's**, where the class first has a member; this task states the constant, and Task 11
  states that every caller passes it. Cross-reference both ways so neither is dropped. Note also
  that `RecordAeadAlgId` moves with the primitive rather than staying beside the builders it
  parameterises: `AADHead` and `AADBody` take `algId uint16` precisely so the AAD builder does not
  know which AEAD is in use, and this task's own argument — until the value and the primitive
  are fixed together no KAT can be written — is the argument for keeping them in one package.

  **Property 2 — the nonce is 24 octets and the construction is the extended one.** The wrapper
  refuses a key that is not `chacha20poly1305.KeySize` and a nonce that is not
  `chacha20poly1305.NonceSizeX`, **before** any arithmetic, with two distinct sentinels. *Refusal
  owed:* a 12-octet nonce is `ErrRecordAeadNonceLength` and never a silently truncated success.

  **Property 3 — a ciphertext is exactly `len(plaintext) + 16`,** so `SizeBucketCtBodyBytes`'s
  `+16` (`record.go:120`, `aeadTagBytes`) is the same 16 in both places. Derive it from the
  constants, do not write 16.

  **Property 4 — open refuses every single-bit mutation of key, nonce, AAD and ciphertext,** and
  returns `ErrRecordAeadOpen` with no plaintext, never a partial one.

  **Property 5 — the AAD is not optional.** Opening a ciphertext sealed under `AAD_head` with
  `AAD_body` fails. This is I7's distinct-AAD property at the primitive.

- [ ] **Step 2: Run it and watch it fail for the stated reason**
- [ ] **Step 3: Write the minimal implementation**
- [ ] **Step 4: Run it and watch it pass**
- [ ] **Step 5: Mutation-test.** Apply each and record the result:
  1. `NewX` → `New` (and adjust the nonce length constant to match) — the whole point of this task.
  2. `RecordAeadAlgId` → `0x0031`.
  3. `RecordAeadAlgId` → `0x0014`.
  4. Drop the key-length check.
  5. Drop the nonce-length check.
  6. Return the plaintext alongside the error on an open failure.
  7. Swap the `aad` and `plaintext` arguments at the `Seal` call.
  8. Return `ciphertext[:len(ciphertext)-16]` from open without verifying the tag.
- [ ] **Step 6: Commit**

---

## Task 2: This package's own zeroization

**Files:**
- Create: `connect/messagegroup/zeroize.go`
- Test: `connect/messagegroup/zeroize_test.go`

**Interfaces:**
- Consumes: nothing. `mls.zeroizeSecret` (`mls/secret_zeroize.go:42`) is **unexported** and cannot
  be called as it stands.
- Produces: `func zeroize(secret []byte)` — unexported, `//go:noinline`.

**The rejected alternative, named, because this plan's opening paragraph forbids second
implementations and this task is one.** The other shape is **one character**: export
`mls.zeroizeSecret` as `mls.ZeroizeSecret` and call it. It is import-legal today —
`messagegroup/xwing.go:36` already imports `github.com/urnetwork/connect/mls` in production, and
after the split that import is the package's declared normal rather than its one exception — and it
would leave the tree with one zeroizer instead of two. It is rejected here for a reason the
implementer must weigh rather than inherit: `connect/mls`'s exported surface is p2's, the file's own
comment argues **against additions** at length, and a second package's convenience is the weakest
argument there is for widening another package's API. Against that, the body is four lines and a
pragma, the two copies cannot drift in behaviour, and the duplication is visible.

**This is a judgement, not a measurement, and it is the kind this plan says to file.** If the
implementer reaches Task 2 and the export is available for the asking, take it and delete this task —
one zeroizer is better than two and the plan's own first paragraph says so. **Open item M1-44**
records the choice so it is made once, by somebody, on the record.

**The divergence this task takes deliberately, and files.** §5.5 specifies zeroization as *"a
`//go:noinline` helper writing through a `unsafe.Pointer`-derived slice"*. `connect/mls`'s answer
(`secret_zeroize.go:41-42`) is `//go:noinline` plus a plain byte loop, and its comment argues at
length against adding anything further — it explicitly rejects `runtime.KeepAlive` because importing
`runtime` widens an import set another gate pins. **`connect/mls` production code contains no
`unsafe` at all.** This task matches the tree, and **Open item M1-37** records the divergence from
§5.5 with the argument for it, so a reader of §5.5 does not "fix" it back.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — after the call, every octet of the backing array is zero,** inspected through a
  second slice header over the same array, so the check cannot be satisfied by reslicing.

  **Property 2 — a nil and an empty slice are both no-ops and neither panics.** A key that was
  already erased is erased again on every path that erases; a helper that panicked there would turn
  a double-erase into a crash on the receive path.

  **Property 3 — the helper is `//go:noinline`,** asserted off the source, not off behaviour. This
  is a claim about the build, and a behavioural test cannot make it.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Remove `//go:noinline`.
  2. Loop to `len(secret)-1`.
  3. Write `0x01` instead of `0x00`.
  4. Reassign `secret = make([]byte, len(secret))` instead of writing through it — the defect the
     second-slice-header reading exists to catch.
- [ ] **Step 6: Commit**

---

## Task 3: `StorageRoot`, the class keys, and guardrail G1

**Files:**
- Create: `connect/messagegroup/keyschedule.go`
- Test: `connect/messagegroup/keyschedule_test.go`
- Modify: `connect/mls/crypto_forbidden_test.go` — **in this commit**, see Gate A.

**Interfaces:**
- Consumes: `mls.CryptoProvider.Extract(salt, ikm)` and `.Expand(prk, info, length)` — read both out
  of `connect/mls/crypto.go` (R2), and read how a provider is obtained (`NewCryptoProvider`) rather
  than assuming.
- Produces:
```go
// storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n])   MASTER §7
func StorageRoot(mlsSecret, pqSecret []byte) []byte

type ClassKeys struct {
    Perm    []byte   // HKDF-Expand(storage_root, "perm/v1", 32)
    Durable []byte   // "durable/v1"
    Media   []byte   // "media/v1"
    // Eph is NOT here. MASTER I4.
}
func DeriveClassKeys(storageRoot []byte) *ClassKeys
```

**The rule, quoted in full, because the omitted half is the whole hazard.** Spec A §5.3:

> ```
> // storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n])   MASTER §7
> //
> // mls_secret[n] = MLS-Exporter("URmessage/v1/storage", "", 32)   RFC 9420 §8.5
> //
> // NOTE the argument order. crypto/hkdf.Extract takes (secret, salt) — ikm FIRST.
> // This wrapper takes (salt, ikm), matching the spec text. Never call
> // crypto/hkdf.Extract directly anywhere in this package. See §5.9.
> ```

and §5.9 G1:

> **`crypto/hkdf.Extract(h, secret, salt)` takes ikm first, salt second.** MASTER writes
> `HKDF-Extract(salt = mls_secret, ikm = pq_secret)`. Swapping them compiles, returns 32 bytes, and
> passes every test that does not compare against an independent implementation. […]
> `message.StorageRoot(mlsSecret, pqSecret)` is the only call site. A lint gate forbids
> `hkdf.Extract` anywhere else in `connect/message` and `connect/mls`. `TestStorageRootKAT` pins the
> output against a hand-computed vector recorded in the test file with its derivation shown.

*(G1's `message.StorageRoot` is `messagegroup.StorageRoot` after the split, and its "anywhere else in
`connect/message`" reads `connect/messagegroup` — where the whole key schedule is. The quotation is
left as G1 writes it; the reading is stated here rather than silently substituted, per R3.)*

`ClassKeys`'s shape is itself the second defence, and §5.3 says why: *"Eph is NOT here. eph_root is
32 B fresh CSPRNG at commit, never derived from `storage_root`. MASTER I4. Putting it in this struct
would make the wrong thing the easy thing."*

**The conflict this task must not resolve on its own.** G1 says `hkdf.Extract` is forbidden
"anywhere else in `connect/message` **and `connect/mls`**" — read `connect/messagegroup` for the
first of those, after the split. `connect/mls` cannot satisfy it either way — RFC 9420 needs
`Extract` in `crypto.go` and RFC 9180 needs it in `hpke.go` — and the landed gate allows exactly
those two paths and **no entry for a future `keyschedule.go`**, at any path. Two shapes satisfy "one
reviewed call site per package" and they are not equivalent:

- **(a)** `StorageRoot` delegates to `mls.CryptoProvider.Extract(mlsSecret, pqSecret)`, which already
  takes the arguments in the spec's order, is already reviewed and already vector-tested against RFC
  5869's table. The tree then holds **exactly one** `hkdf.Extract` in the whole crypto surface and
  Gate A needs no amendment at all for this task.
- **(b)** `keyschedule.go` calls `crypto/hkdf.Extract` directly and takes an allow-list entry, which
  is what §5.3's comment literally instructs and which widens the allow-list the guardrail exists to
  keep narrow. **If (b) is ruled, the entry goes in `hkdfExtraCallSites`, not in
  `hkdfExtractAllowedPaths`** — those are two different mechanisms and the plan named the wider one.
  Measured 2026-09-05: `hkdfExtractAllowedPaths` (`crypto_forbidden_test.go:83`) is **needle-blind**,
  and `hkdfAllowedPathsFor` at `:451` joins it into the allowed set for *every* entry point —
  `slices.Concat(hkdfExtractAllowedPaths, hkdfExtraCallSites[needle])` — so adding `keyschedule.go`
  there would excuse `hkdf.Extract`, `hkdf.Expand` **and `hkdf.Key`** in that file. The gate's own
  comment at `:266` calls `hkdf.Key` *"the worse of the two — it is Extract and Expand in one call,
  so a transposition there produces a whole key schedule that is internally consistent, 32 bytes
  long, and wrong"*, and notes at `:437` that it *"is in exactly that position"*: confined by nobody
  having thought of it, which is the safe default the entry would remove. `hkdfExtraCallSites`
  (`:444`) is keyed **by needle**, and its one row —
  `"hkdf.Expand(": {"../message/writeauth.go"}` — is the landed precedent, and it stays pointing at
  `../message/writeauth.go` because `writeauth.go` does not move. A new row for this task points at
  `../messagegroup/keyschedule.go`, which **the gate does not walk until `forbiddenScanRoots` names
  that root** — and Gate A refuses an allow-list entry whose file makes no such call, so the entry,
  the root and the code are one commit and not three. Either way the nested control twin is still
  owed. Tasks 5, 22 and 23 owe the same reading of the same choice, and 23 owes it on **both** sides
  of the split.

**Open item M1-16** files the choice. **Whichever is ruled, the implementer confines the extraction
to one unexported helper in `keyschedule.go`**, so the ruling is a change inside that helper and not
a change at every call site. Do not widen the allow-list without the ruling; do not delegate without
it either — write the helper, and take the shorter of the two paths only after M1-16 is answered.
Until then this task is buildable with the helper's body as the single open line.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the arguments are (salt, ikm) and the output is pinned.** `TestStorageRootKAT` is
  named by G1 and is not optional: a hand-computed vector, with its derivation shown in the test
  file, so a reader can re-derive it without running the code. *Refusal owed:* none — this is a pure
  function — but the KAT must be a value **no transposition produces**, which means the test author
  must also compute `HKDF-Extract(salt = pq, ikm = mls)` and assert the two differ. A KAT over
  equal-length equal-content inputs is a KAT that cannot fail the transposition, which is the one
  defect it exists for.

  **Property 2 — the transposition is caught in both directions.** Given `mls != pq`, swapping the
  two arguments changes the output. Stated separately from property 1 because a KAT pins one point
  and this pins the map.

  **Property 3 — `ClassKeys` has exactly three fields and none of them is eph.** The scope question
  (R3a): the class is **the struct's field set read off the syntax tree**, not a list of three names,
  so a fourth field of any name fails. *Refusal owed:* a field whose name or whose derivation label
  matches `eph` fails with a message naming MASTER I4.

  **Property 4 — the three labels are three distinct constants** and no two are built by
  concatenation from a shared stem. `writeauth.go` already sets this precedent for `write/v1` and
  `read/v1`, with a test asserting the two labels disagree *inside the shorter one*; the same shape
  applies here and the three-way version is stronger.

  **Property 5 — every class key is 32 octets and each differs from the other two and from the
  root.**

  **Property 6 — `StorageRoot` is the only extraction *on the key schedule's path*, and the scope of
  that word is the whole property.** The scope question, and the split changed its answer: every
  `hkdf.Extract` and every `CryptoProvider.Extract` call site in **`connect/messagegroup`'s**
  production source, derived off the tree — that is where the key schedule lands and where every
  extraction on its path is. **At this task's commit that class has exactly one member,
  `StorageRoot` itself**, so the gate has something to read on the day it lands and does not need a
  relocation. The scope is that one directory and not two, and the reason belongs in the gate's own
  header per R3a: `connect/message`'s only entry point in this family is `writeauth.go`'s
  `hkdf.Expand`, which Gate A already excuses by path and which is an expansion rather than an
  extraction, so widening the root would add a directory the class never draws from. This is the
  client-side half of Gate A, held where Gate A cannot express it.

  **Stated as "the only extraction, full stop", this property goes red at a commit inside this same
  plan.** §5.14 declares a **second** `Extract` —
  `deposit_sig_seed[k] = HKDF-Expand(HKDF-Extract("URmessage/v1/rendezvous", token[k]), "depsig/v1",
  32)`, spec line 1801 — in the same derivation block Task 22 produces
  (`messagegroup/card.go`), reached again by Task 23. Note where Task 23's half of it lands: the
  derivation is the **client's**, so it is in `messagegroup/rendezvous.go`, while
  `message/rendezvous.go` holds `DepositVerifyKey(token)`, which is the server-visible end of the
  same chain and is M1-29's subject. The exception table this property needs therefore has rows on
  one side and a cross-reference on the other. This plan already files that fact as **M1-16** and then wires it into
  neither task, so the gate Task 3 lands would go red the commit `card.go` lands and the cheapest way
  out of it would be to delete the gate.

  So the property is written with its exceptions **as a table, held in both directions**, in the
  `entropyRefusalsHeldOutsideThisPackage` shape (`mls/crypto_test.go:7776`): the class of extraction
  sites is derived, the table names each site with the reason it is one, and a row naming a site that
  no longer extracts fails just as a site with no row does. It has exactly one row when this task
  commits — `StorageRoot`, reason *"§5.3, guardrail G1's single reviewed call site"* — and Tasks 22
  and 23 each add theirs **in the commit that adds the call**, with §5.14's derivation quoted as the
  reason. Task 22's and Task 23's Gate A amendments and this table are the same obligation seen from
  two packages, and both are owed in one commit.

- [ ] **Step 2–4** as above. Run the **`mls`** suite too: Gate A fails there, not here.
- [ ] **Step 5: Mutation-test.**
  1. Swap `StorageRoot`'s two arguments at the extraction.
  2. `"perm/v1"` → `"perm/v2"`.
  3. `"durable/v1"` → `"perm/v1"` (two classes collapse onto one key).
  4. Build the three labels as `class + "/v1"` from a shared stem.
  5. Add an `Eph []byte` field to `ClassKeys` and populate it from `storage_root`.
  6. Return a 16-octet class key.
  7. Return the storage root itself as `Durable`.
- [ ] **Step 6: Commit**, with the Gate A amendment if M1-16 ruled toward (b).

---

## Task 4: `GroupHandleKey`, `SenderHandle`, `WrapTargetHandle`

**Files:**
- Create: `connect/messagegroup/handle.go`
- Test: `connect/messagegroup/handle_test.go`

**Interfaces:**
- Consumes: Task 3's expansion helper; `mls.CryptoProvider.Expand`.
- Produces:
```go
// group_handle_key = HKDF-Expand(storage_root[0], "gh/v1", 32)   — FIXED at group creation
func GroupHandleKey(storageRootEpoch0 []byte) []byte
// sender_handle = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)
func SenderHandle(groupHandleKey []byte, leaf uint32) [16]byte
// wrap_target_handle = HKDF-Expand(group_handle_key, "wt/v1" ‖ u64(epoch) ‖ u32(leaf_index), 16)
func WrapTargetHandle(groupHandleKey []byte, epoch uint64, leafIndex uint32) [16]byte
```

**`SenderHandle`'s derivation is in MASTER, not in Spec A, and that matters.** Spec A §5.3 declares
`func SenderHandle(groupHandleKey []byte, leaf uint32) [16]byte` and gives **no formula**; every
neighbouring handle in §5.3 and §5.11 has one. MASTER §8's RECORD listing does:

> ```
> sender_handle      16B  = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)
>                          stable per group; every member computes it; the server cannot invert it
> ```

Use MASTER's. **Open item M1-8** files the Spec A omission, because `sender_handle` is in
`RecordHeader`, in `AAD_head`, in `AAD_body`, in the `write_auth` preimage, and it is the column Spec
B keys `message_sender.last_stream_index` on — two implementations choosing differently disagree on
every AEAD and every MAC in the system, and each one's own tests stay green.

**`LP(leaf_index)` is the one place in this project where `LP` wraps an integer.** §5.11 defines
`LP(x)` as *"32-bit big-endian length prefix then `x`"* and every other use wraps a byte string.
`"sh/v1" ‖ LP(leaf_index)` and `record_key[0] = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index),
32)` both need a rule for what `x` is: the 4-octet big-endian encoding (giving 8 octets), or a
minimal encoding (giving 5 for small leaves). Note the asymmetry that makes this real rather than
pedantic: `wrap_target_handle`, in the same family, writes `u32(leaf_index)` **raw**, with no LP at
all. **Open item M1-8**, wire-visible, blocks the A6 freeze. Pending the ruling, implement one
reading in **one unexported helper** used by both call sites, so a re-ruling is a single edit and
cannot leave the two derivations disagreeing.

**The epoch-zero obligation, which is a persistence requirement and not a derivation.**
`GroupHandleKey` takes `storage_root[0]` specifically, so that — MASTER §8 —
*"`group_handle_key` is what makes `sender_handle` and `wrap_target_handle` survive an epoch change.
[…] A member that does not hold it cannot compute its own handle and therefore cannot write."* The
group's **first** storage root must therefore be computed and durably persisted at group creation,
separately from the current one, for the life of the group. No section of any spec says where that
lives. Task 10 gives it a home in `GroupSession`'s construction; **Open item M1-4** records that the
spec does not.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — three distinct labels, three distinct outputs**, at 32 / 16 / 16 octets. Same
  distinct-constants rule as Task 3 property 4.

  **Property 2 — `SenderHandle` depends on the leaf and on nothing else,** and two leaves never
  collide across the whole `uint32` range this group can reach (`MaxGroupMembers = 500`,
  `MaxDeviceLeavesPerIdentity = 10` — read both out of `connect/mls/errors_lifecycle.go`).

  **Property 3 — `WrapTargetHandle` depends on the epoch AND the leaf,** so the same leaf at two
  epochs gets two handles, and `leaf_index = 0xFFFFFFFF` (the snapshot's, per §5.11) is a value the
  function computes rather than special-cases.

  **Property 4 — the two `LP(leaf_index)` sites agree.** The scope question (R3a): derive the class
  of call sites off the tree — every function in the package expanding a label that ends in
  `leaf_index` — and assert they route through the one helper.

  **Property 5 — a `group_handle_key` that is not 32 octets is refused,** in the same shape
  `writeauth.go` already refuses a short auth key (`ErrAuthKeyLength`). A handle derived from a
  truncated key is a well-formed handle.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. `"sh/v1"` → `"wt/v1"`.
  2. Drop `LP` and concatenate the raw `u32` in `SenderHandle` — the interop defect M1-8 names.
  3. Add `LP` around `u32(leaf_index)` in `WrapTargetHandle` — the same defect in the other
     direction.
  4. Omit `epoch` from `WrapTargetHandle`'s info.
  5. Return 32 octets truncated to 16 by the caller rather than expanding to 16.
  6. Derive `GroupHandleKey` from the current epoch's root instead of epoch zero's — **this one is
     the most valuable mutation in the task**: it passes every single-epoch test and breaks every
     group at its first commit.
- [ ] **Step 6: Commit**

---

## Task 5: The record-key ratchet's four derivations

**Files:**
- Modify: `connect/messagegroup/keyschedule.go`, `connect/messagegroup/keyschedule_test.go`

**Interfaces:**
- Consumes: Task 3's expansion helper; Task 4's `LP(leaf_index)` helper; Task 1's
  `chacha20poly1305` size constants.
- Produces:
```go
// record_key[0]   = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)
// record_key[i+1] = HKDF-Expand(record_key[i], "ratchet/v1", 32)
func RecordKeyZero(classKey []byte, leaf uint32) []byte
func RecordKeyNext(recordKey []byte) []byte

// key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)
// key_body ‖ nonce_body = HKDF-Expand(record_key[i], "rec/v1/body", 56)
func RecordAeadHead(recordKey []byte) (key, nonce []byte)
func RecordAeadBody(recordKey []byte) (key, nonce []byte)
```

**The 56 is 32 + 24 and must be derived, not written.** MASTER §8's block gives 56; Task 1's
constants give `chacha20poly1305.KeySize` and `NonceSizeX`. Write `KeySize + NonceSizeX` and let the
compiler agree with the spec, so a suite change is a compile error rather than a silent 12-octet
truncation.

**The contradiction this task must not resolve.** MASTER §8.1 says, one line after the ratchet block:
*"`ct_head` is always under the **durable** class, since it is always retained."* Spec A §5.3 gives
`RecordAeadHead` and `RecordAeadBody` **the same `record_key[i]` argument**. For a `DURABLE` record
these coincide and CP3b cannot tell them apart; for a `PERMANENT`, `MEDIA` or `EPH` record they are
two different keys from two different class ratchets, and the spec never says how one record then has
one `stream_index`. **Open item M1-6.** This task builds the two derivations exactly as §5.3 declares
them — both taking a `recordKey` — and **Task 11 states which key it passes to each**, which is where
the ruling actually binds.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the chain is a chain.** `RecordKeyNext` applied *i* times to `RecordKeyZero` is
  reproducible, and no two positions in the first 2,048 collide.

  **Property 2 — it is one-way at the layer's boundary.** Given `record_key[i+1]`, nothing exported
  by this package returns `record_key[i]`. The scope question (R3a): the class is every exported
  function of the package taking a 32-octet secret and returning one; assert the property by
  construction over that derived class, not over the two names in this task.

  **Property 3 — head and body split 56 octets into 32 and 24, at the right offsets,** and the four
  outputs of the two functions over one `record_key` are pairwise distinct.

  **Property 4 — the two labels are two constants** and neither is built from the other by
  concatenation. `"rec/v1/head"` and `"rec/v1/body"` share an eleven-character prefix, which is the
  most concatenation-prone pair in the whole schedule.

  **Property 5 — `RecordKeyZero` binds the leaf.** Two leaves under one class key produce two
  chains, and the binding goes through Task 4's helper so the encoding cannot drift from
  `SenderHandle`'s.

  **Property 6 — a short `classKey` or `recordKey` is refused rather than expanded.** Same shape as
  `ErrAuthKeyLength`.

- [ ] **Step 2–4** as above. This is a second `hkdf.Expand` site in a new file if M1-16 ruled toward
  (b): amend Gate A **in this commit** and add its control twin.
- [ ] **Step 5: Mutation-test.**
  1. `"ratchet/v1"` → `"sender/v1"`.
  2. Expand 48 octets and take a 12-octet nonce — the `New`-versus-`NewX` defect from the key side.
  3. Return `expanded[24:56]` as the key and `expanded[0:24]` as the nonce.
  4. Make `RecordAeadBody` call `RecordAeadHead`.
  5. Return the same nonce for head and body.
  6. Have `RecordKeyNext` return its input.
  7. Drop the leaf from `RecordKeyZero`'s info.
- [ ] **Step 6: Commit**

---

## Task 6: `stream_index` is write-once, and durably so

**Files:**
- Create: `connect/messagegroup/streamindex.go`
- Test: `connect/messagegroup/streamindex_test.go`
- Modify: `connect/messagegroup/errors.go`

**Interfaces:**
- Consumes: nothing from this plan.
- Produces:
```go
// the reservation MUST be durable before the key is produced.
type StreamIndexReserver interface {
    // returns only after the reservation is durable (fsync'd or equivalent).
    Reserve(groupId []byte, index uint64) error
    HighWater(groupId []byte) (uint64, error)
}
var ErrStreamIndexRewound  error
var ErrStreamIndexConsumed error
```

**This task declares the interface and does not implement a file-backed store, and the earlier
version of it did.** Three measured facts, and together they are the argument:

1. **Neither half imports an I/O package at all.** Measured 2026-09-05 over the nine production
   files of `connect/message` as it stands before the split: the whole import set is
   `crypto/{sha256,subtle,hkdf,hmac,ecdh,mlkem,sha3}`, `fmt`, `io`, `mls` and `mls/syntax`. The
   heaviest is `io`, for an `io.Reader` parameter. The split does not change that: `mls` and the two
   KEM packages go to `connect/messagegroup` and the rest stays, and **neither** side gains `os`.
   Adding a file format to `messagegroup` makes the client half a storage engine, and it is a
   **record** layer with a group attached.
2. **§8.2 already assigns the persistence, to `sdk`.** `MessageStore` (`sdk/message_store.go`, spec
   line 3703) declares — among its fourteen methods — `ReserveStreamIndex(groupId []byte, index
   uint64) error` and `StreamHighWater(groupId []byte) (uint64, error)`. That is
   `StreamIndexReserver`, method for method and parameter for parameter, on the interface the
   sqlite implementation already owes. A second durable implementation here is the second
   implementation this plan's first paragraph forbids, and A8 makes the fourteen-method bound the
   thing that would have to be reimplemented if `modernc.org/sqlite` goes.
3. **§5.6 injects the sink for exactly this reason** — *"the constructor takes the sink to make it
   explicit"* — and Task 10 Property 3 already refuses a session built without one.

So: this task produces the **interface**, the two sentinels, the resume rule and the properties, plus
**one file-backed reference implementation confined to `_test.go`**, which is what the
crash-injection harness of Property 1 needs and is not a production key or storage source. The
shipping durable one is `sdk`'s. If the implementer finds a reason `connect/message` must own a durable store after all, that
reason belongs in a ledger entry against §8.2 before the file is written — not in this file.

**And the same measurement sharpens M1-5.** §8.2's two methods take `groupId` and no
`senderHandle`, exactly as §5.6's interface does. So M1-5's "the fix is one parameter" is one
parameter in **two** documents and on a fourteen-method interface A8 pins the size of; the item now
says so.

**The rule, quoted whole, because its two halves are usually collapsed into one.** Spec A §5.6:

> `stream_index` is a single `u64` counter per `(group_id, sender_handle)`, write-once, assigned
> locally. A device MUST durably record "index *k* consumed" **before** encrypting, and MUST NEVER
> encrypt a second record at a consumed index. The server enforces **monotonicity, not contiguity**,
> so a refused write, a crash between reserve and send, or a lost commit leaves a legal gap.
>
> […] Nonce reuse under a repeated `record_key` is a total break of both AEADs for that record, which
> is why the reservation is durable rather than best-effort.
>
> `SealRecord` calls `Reserve` and refuses to proceed on error. On startup, `HighWater` is read and
> the ratchet resumes at `highWater + 1`, never at a recomputed value.

**Why this task is before the ratchet and not after it.** A `SenderRatchet` shipped without the
reserver is a nonce-reuse machine that passes every round-trip test that exists. §5.6's own sentence
is the reason: a reused index is a reused nonce under a reused key.

**The keying question, which must be ruled before the on-disk format is written.** §5.6's first
sentence says the counter is per `(group_id, sender_handle)`. The interface it then declares takes
`groupId` and **not** `senderHandle`, in both methods. `sender_handle` is a function of the **leaf**
(MASTER §8), and `group_handle_key` is fixed at group creation, so a device removed and re-added at a
different leaf has a **different** `sender_handle` in the **same** group. A reserver keyed on
`group_id` alone either hands the new handle the old leaf's high water — burning indices, benign — or,
on any local state divergence, lets a fresh handle start at 1 while a stale row says otherwise. The
fix is one parameter. **Open item M1-5**, and it is the highest-priority of the non-blocking items,
because **this is the one piece of durable on-disk state that cannot be migrated by
recomputation.** Implement the interface with the parameter set the ruling gives; do not choose.

**The EPH(0) cost, filed rather than absorbed.** §5.6 states that `EPH(bucket 0)` transients *"do
consume an index locally (so the counter is never rewound)"*. Every typing indicator therefore costs
a synchronous flush and the transient send rate becomes the fsync rate. §5.5 has a memory budget
deferred to Spec C; §5.6 has no I/O budget and no §14 item. **Open item M1-25.** No EPH record is
sealed before wave 3, so this does not block, but the interface must not be shaped in a way that
forecloses a separate transient counter.

**Where the durability is tested, given that the implementation is not here.** The properties below
are the interface's **contract**, and every one of them is testable against a **file-backed reserver
that lives in `streamindex_test.go`** — a test fake, in the tree's own sense: it is not a key source,
it is not reachable from a non-test build, and it puts no I/O in the production import set. That fake
is what the crash injection restarts, and it is what makes §5.6's own named test writable here rather
than deferred to a package that does not exist. What it does **not** do is ship: the production
durable store is §8.2's `MessageStore`, whose plan is unwritten (s1 files that as **S1-9**, *"blocks
s2 entirely"*), and every property below is an obligation that plan inherits. Say so in the
interface's doc comment, so a reader who finds no implementation finds the reason instead of writing
one.

**And the deletion's consequence is now on the Definition of done, where it belongs.** Removing the
production implementation from this task removed a piece from CP3b's path, and the 2026-09-05 pass
that removed it did not add it to the external-leg list that same pass made exhaustive. It is
**leg 5** there now: a durable `StreamIndexReserver`, owned by the unwritten sdk store plan, asked of
it as **O-5**, and carrying M1-5's keying ruling and M1-25's fsync cost with it. A CP3b run over this
task's test fake proves the record layer and not the client, and the Definition of done says so
rather than leaving it to be discovered at the milestone.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — `Reserve` returns only after the reservation survives a process death.** The
  refusal owed: a `Reserve` that returns before the write is durable must be observable, which means
  the test needs an injected failure point between the write and the flush, not a `time.Sleep`. This
  is a property **of the contract**, asserted against the test fake and stated in the interface's
  doc comment as what an implementation owes.

  **Property 2 — `TestStreamIndexNeverReused`, named by §5.9 G5 and G11.** §5.6 states its shape:
  *"runs 10,000 seal operations with an injected crash after `Reserve` and before the AEAD, restarts
  the session from the persisted state, and asserts no `index` is ever produced twice."* Build the
  crash injection here even though `SealRecord` does not exist until Task 11 — the reserver plus the
  restart is what the property is about, and Task 11 extends the same test to the real seal.

  **Property 3 — `HighWater` never rewinds.** After a restart it is at least what it was, for every
  key, under every interleaving the test can produce. *Refusal owed:* `ErrStreamIndexRewound` when
  the persisted state is behind a reservation already handed out.

  **Property 4 — a consumed index is refused, not overwritten.** *Refusal owed:*
  `ErrStreamIndexConsumed`, a typed fatal error per G7, never a bool and never a log line.

  **Property 5 — the store is total over its key space.** A group never seen answers `HighWater` 0
  with no error, so `highWater + 1` is a well-defined start; §5.1 makes `record_id = 0` the
  "from the beginning" cursor by the same reasoning and the two should not disagree in shape.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.** Mutations 1 and 6 are applied to the test fake, which is what makes
  them mutations of the **contract** rather than of an implementation this package does not have.
  1. Return from `Reserve` before the flush.
  2. Resume at `HighWater()` rather than `HighWater()+1`.
  3. Resume at a recomputed value (the sender ratchet's own position) instead of the persisted one —
     §5.6 forbids this in as many words and it is invisible without a crash injection.
  4. Key the store on `group_id` when the ruling said `(group_id, sender_handle)`, or the reverse.
  5. Make `Reserve` idempotent for an index already reserved.
  6. Swallow the flush error and return nil.
  7. Move the fake out of `_test.go` into production source — the layering refusal above, asserted
     the way this tree asserts every other one: over the package's own production import set, which
     contains no I/O package today and must still contain none at the end of this task.
- [ ] **Step 6: Commit**

---

## Task 7: The sender ratchet

**Files:**
- Create: `connect/messagegroup/ratchet.go`
- Test: `connect/messagegroup/ratchet_test.go`

**Interfaces:**
- Consumes: Task 5's `RecordKeyZero`/`RecordKeyNext`; Task 6's `StreamIndexReserver`; Task 2's
  `zeroize`.
- Produces:
```go
type SenderRatchet struct {
    stateLock sync.Mutex
    // ...
}
func NewSenderRatchet(classKey []byte, leaf uint32, /* see the note on the reserver */) *SenderRatchet
func (self *SenderRatchet) Next() (index uint64, recordKey []byte /*, see M1-13 */)
```

**§5.5's text, quoted:**

> a real forward ratchet: the sender overwrites `record_key[i]` after use. […]
> `func (self *SenderRatchet) Next() (index uint64, recordKey []byte)` // advances and zeroes
>
> **Zeroization.** `Next()` overwrites the previous key with zeros before returning. Go gives no
> guarantee this survives the optimizer […] This is best-effort and documented as such; a Go program
> cannot promise a secret is gone from RAM. It is still worth doing, because the common case — a key
> still sitting in a live struct field — is entirely preventable.

**The signature contradiction, which this task must file and not paper over.** §5.5 gives `Next()`
**no error return**. §5.6 requires `Reserve(...) error` to complete **durably before the key is
produced**, and says `SealRecord` "refuses to proceed on error". A no-error `Next()` cannot report a
failed fsync. As declared, either the durable reservation happens outside the ratchet — and the
ordering guarantee is back to being a convention, which is exactly what §5.2 says this layer must not
do — or `Next()` panics on a disk error. Neither is written down. **Open item M1-13.** Two shapes
close it and they are a one-line difference at every call site: `Next() (uint64, []byte, error)`, or
the reserver moves into `SealRecord` between the index draw and the key draw. Implement whichever the
ruling gives; if the ruling has not landed when this task starts, implement the **three-valued**
form, because it is the one that can be narrowed later without losing information, and record the
choice as provisional in the type's doc comment.

**The keying contradiction, filed.** §5.5's prose scopes the window to `(sender_handle, retention
class)`; the constructor is keyed by `(class_key, leaf_index)` and `record_key[0]` binds the **leaf**.
`leaf_index` and `sender_handle` are different identifiers with different lifetimes — §5.3 makes the
handle deliberately epoch-stable and a leaf index is not. Which one keys the ratchet table decides
whether a member's stream survives an epoch change, and §5.5 states both. **Open item M1-11.**

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the reservation completes, and completes successfully, before the key exists.**
  Two claims, and they need two mechanisms, because the version of this property before the
  2026-09-06 pass named one that can only prove the first — and the version before *that* one named
  a mechanism whose class is empty at this task. Both corrections are stated below rather than
  silently applied, because the second is the fifth instance of a defect class this plan has now
  repaired five times.

  **The class the previous version derived is empty at this task's commit.** It said: *"every path
  from `Next` (or from `SealRecord`, per the M1-13 ruling) to a `RecordAeadHead` / `RecordAeadBody`
  call reaches `Reserve`"*, and then asked for an AST check *"on each member of that reached
  class"*. **Measured 2026-09-06, that class has zero members at Task 7.** `RecordAeadHead` and
  `RecordAeadBody` are declared by Task 5 and **called by nothing** until Task 11's `SealRecord`;
  `SealRecord` does not exist until Task 11; and `Next` itself is declared by this task and has no
  production caller yet. So a path from either root to either AEAD derivation does not exist, and
  the very shape the previous version named for the second mechanism — `aad_test.go`'s discard gate
  at `:1537-1541` — **fatals on an empty class**, which is what the tree's house style does rather
  than reporting clean over one (`aad_test.go:1293`, `:1432`, `:1539`; `writeauth_test.go:2451`).
  Written as stated, it fails on arrival; written without the guard, it passes vacuously. That is
  exactly what Task 1 Property 1 measured for the AAD builders three tasks earlier, and it is the
  same commit boundary: **the first production call of anything in `keyschedule.go` is Task 11's.**

  **So Property 1 splits, and the two halves land in two commits.**

  **Here, at Task 7, where the class has a member — the ratchet's own body.** Both mechanisms below
  derive over `SenderRatchet.Next`, which this task declares, so **the class is one member at this
  task's commit** and it is non-empty from this task's first commit:

  - an **AST check on `Next` itself**: the `Reserve` call's error result is bound, and the function
    returns on non-nil **before** any call into `keyschedule.go`. Both halves are decidable on the
    syntax tree within one function body, which is where they live; `aad_test.go`'s discard gate
    (`:1537-1541`) is the shape and it fatals on an empty class, which is safe here because the
    class is `Next` and `Next` exists. It refuses mutations 4 and 5;
  - a **behavioural** test with an injected failing reserver, asserting no key and no index is
    produced when `Reserve` returns an error — the property stated as behaviour, and the only
    mechanism that survives a refactor into a shape the AST check does not recognise. It refuses
    mutations 3, 4 and 5.

  **And at Task 11, where the path class first has a member — the reachability walk.** *"Every path
  from `SealRecord` to a `RecordAeadHead` / `RecordAeadBody` call reaches `Reserve`"* is the
  derived-class half of this property, and it **moves to Task 11 Property 3**, the commit that
  first has a path to walk. `writeauth_test.go`'s `TestReadAuthNeverUsesWriteKey` (`:1904`) is the
  shape: it walks edges read off the syntax tree, answers *does root X reach function Y*, carries a
  `reaches` list to prove it followed something, and has a positive control fixture under
  `testdata`. Task 11 Property 3 names this property back, so neither half is dropped between them.

  **What a reachability walk could never prove, wherever it lands.** *"Passes through a
  returned-nil `Reserve`"* is error handling and ordering, not reachability, and both are invisible
  to it: a body that calls `Reserve`, discards its error and computes the key is
  reachability-identical to one that checks it. Mutations 4 and 5 are therefore invisible to the
  walk at Task 11 as well, which is why the AST check and the behavioural test stay **here** rather
  than travelling with it. Do not collapse the three. Each catches something the other two do not,
  and the walk alone reads like coverage.

  **Property 2 — `TestRatchetZeroizes`, named by §5.5.** After `Next`, the previous key's backing
  array is zero, *inspected through a second slice header over the same array*. The struct field is
  the case §5.5 says is "entirely preventable" and is the one the test must actually reach.

  **Property 3 — indices are consecutive from `highWater + 1` and never repeat,** across a restart.

  **Property 4 — concurrent `Next` calls never hand out one index twice.** `stateLock` is in the
  declared struct and this is the property it exists for; run it under `-race`.

  **Property 5 — exhaustion is a refusal, not a wrap.** `mls/secret_tree.go` already chose this for
  the same class of counter (`generationsConsumed`); a `uint64` that wraps to zero re-issues every
  nonce the group has ever used.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Zeroize after the return instead of before it.
  2. Zeroize the returned slice rather than the retained one.
  3. Drop the `Reserve` call.
  4. Call `Reserve` after computing the key.
  5. Ignore `Reserve`'s error.
  6. Remove `stateLock` from `Next`.
  7. Start at `highWater` rather than `highWater + 1`.
  8. Wrap on `uint64` overflow instead of refusing.
- [ ] **Step 6: Commit**

---

## Task 8: The receiver ratchet and the skipped-key window

**Files:**
- Modify: `connect/messagegroup/ratchet.go`, `connect/messagegroup/ratchet_test.go`
- Modify: `connect/messagegroup/errors.go`

**Interfaces:**
- Consumes: Task 5's derivations; Task 2's `zeroize`.
- Produces:
```go
type ReceiverRatchet struct{ /* stateLock-guarded; keyed per M1-11's ruling */ }
func (self *ReceiverRatchet) KeyFor(index uint64) ([]byte, error)   // fills and prunes the window
var ErrOutOfWindow error   // see M1-15: the sentinel OpenRecord turns into a gap
```

**§5.5's numbers, quoted:**

> Window size: **1024 keys per (sender_handle, retention class)**, ~32 KB each, capped at 64 senders
> tracked per group before the oldest is evicted. For a 500-member group with two devices each this
> is a worst case of ~2 MB per group, which is why the cap on tracked senders exists. Needs a Spec C
> memory budget to finalize (§14 open item 7).
>
> Beyond the window, a record is undecryptable and surfaces as a `Kind == "gap"` entry with
> `GapReason == "out_of_window"` (§7.4) — **not as an error.** This is a deliberate, visible failure:
> silently skipping is how a message loss becomes invisible.

**Three problems in those four sentences, all filed.**

- **The arithmetic does not close.** 1024 keys × ~32 B is ~32 KB per window; 64 windows is ~2 MB,
  which is **one class**. With three non-EPH classes it is ~6 MB, and EPH buckets add more. Either
  the cap is per `(sender, class)` pair and the number is wrong, or the cap is per sender and the
  window is not per class. **Open item M1-12**, which is §14 open item 7 and is owned by Spec C and
  marked *blocks slice A6*.
- **A better answer is already in the tree.** `mls/secret_tree.go` solves the same problem with
  `MaxRetainedWindowKeys = RatchetWindowSize` — a **tree-wide** constant, so adding senders adds no
  memory at all — and evicts from the **fullest** window, so a member holding a handful of skipped
  keys never pays for a member holding a thousand. §5.5's "evict the oldest sender" starves whoever
  went quiet, which is the member most likely to need the window. `secret_tree.go`'s comment says the
  derived-not-restated form exists precisely so the per-ratchet and global bounds cannot drift.
  Adopting it closes §14 item 7 without a Spec C round trip. **Recommendation, labelled as one, in
  Open item M1-12.**
- **The window is a construction parameter, not a `const`.** Because §14 item 7 is open and blocks
  A6, a window baked in as a constant makes the finalisation a signature change. Take it in the
  constructor with the tree's constants as the default.

**The missing declarations, filed.** §5.5 gives `ReceiverRatchet` **no constructor**, no statement of
what it is keyed by, and no statement of who owns the 64-sender table. `KeyFor` is its only member.
**Open item M1-14.**

**The channel problem, filed and load-bearing on Task 12.** §5.5 requires an out-of-window record to
surface as a **gap**, not an error; §5.11 step 4 requires a member finding no wrap to surface a gap
with reason `no_wrap`. `KeyFor` returns an `error`, `OpenRecord` returns an `error`, and §5.9 G7
makes every error in this package fatal by construction. Nothing in §5 names the sentinels `sdk` must
`errors.Is` against to turn a refusal into a gap rather than a failure, and §12.1's refusals block
carries neither name. **Open item M1-15.** This task declares `ErrOutOfWindow` as a sentinel;
Task 12 decides how it crosses `OpenRecord`; and §12.1's block gains a line **only if** the ruling
makes it reachable from a published function, per amendment A-9's reachability rule.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — an in-order receipt costs one step and retains nothing.** The common case must not
  allocate a window.

  **Property 2 — a gap within the window is fillable, once.** Every skipped key between the head and
  the requested index is derived and retained; a second request for a retained index answers it and
  **erases** it; a third refuses. A window that hands the same key out twice is a window that
  survives a replay.

  **Property 3 — beyond the window is a refusal with `ErrOutOfWindow`,** and the head does **not**
  move. Note the contrast with `mls/secret_tree.go`'s `peekFor`, where a too-far-ahead refusal
  *does* move the head, argued in ledger 2026-09-04 on the grounds that the accepted in-bound path
  already grants the same advance. That argument rests on the generation reaching `peekFor` only
  after an AEAD opened under `sender_data_secret` — **this layer has no such gate**, because the
  index arrives in the record's cleartext header. Do not copy that behaviour here; copy the window
  and the eviction.

  **Property 4 — the global bound holds regardless of sender count.** The scope question (R3a): the
  bound is asserted over the **whole table**, derived from the structure, not over one ratchet.

  **Property 5 — eviction never evicts a window that another sender's traffic could have kept
  cheap.** State it as the policy property: the evicted key comes from the fullest window.

  **Property 6 — every erased key is zeroized,** at erase, at prune and at evict, through Task 2's
  helper.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Return a retained key without erasing it.
  2. Move the head on an out-of-window refusal.
  3. Evict the oldest window rather than the fullest.
  4. Make the retained-key bound per ratchet rather than tree-wide.
  5. Fill the window beyond `MaxGenerationSkip` in one call.
  6. Skip the zeroize on prune.
  7. Return a nil key and a nil error for an index below the head.
- [ ] **Step 6: Commit**

---

## Task 9: `GroupEngine` — §6's narrow swappable interface, declared here

**Files:**
- Create: `connect/messagegroup/engine.go`
- Test: `connect/messagegroup/engine_test.go`

**Interfaces:**
- Consumes: nothing at compile time — that is the point. Read `connect/mls/group.go`'s method set
  before writing each line, and read §6's own sentence for what it actually says: *"The interface is
  declared at each consumer (A3); Go's structural typing makes the `connect/mls` **adapter** satisfy
  both without an import edge."* **The satisfier is the adapter, not `*mls.Group`.** Task 9a builds
  it. Do **not** reshape this interface around `mls`'s own types to make `*mls.Group` fit — that is
  the one move that destroys the boundary Gate 5 exists to hold, and the measurement under Property 3
  is there to stop it.
- Produces: `GroupEngine`, `GroupHandle`, `EngineProcessed` — the block in Spec A §6 (spec lines
  1885–1939, re-read after A-12), transcribed **from the spec**, and deliberately **not** normalised against
  `group.go`'s signatures. Measured 2026-09-05: `GroupEngine` is 4 methods and `GroupHandle` is
  **23**.

**Why this is m1's and not s5's, and the correction it forces.** s1's registry records
`message.GroupEngine` and `message.GroupHandle` as **pending pins with s5 as producer** and
`connect/message/engine.go` as absent. Two things are wrong with that row and the split fixes the
second: §5.2's `SealRecord` is a method on `GroupSession`, `GroupSession` needs an exporter to
compute `mls_secret`, so the producer is m1 and not s5; and the **spelling** is now
`messagegroup.GroupEngine` and `messagegroup.GroupHandle`, in
`connect/messagegroup/engine.go`, because §12.1 gives the server no MLS type and this interface is
twenty-three of them. What s5 produces is the **factory** — §6's `NewConnectMlsEngineFactory` in
`sdk/message_mls.go`, whose return type moves with the interface — not the interface itself.
**Open ask O-1** asks s1's registry to change the producer row from s5 to m1 and the pin's spelling
with it.

**What is deliberately not on it,** quoted from §6, because the value of a narrow interface is
entirely in what it refuses:

> Note what is **not** on this interface: no tree, no node, no secret tree, no HPKE, no
> `epoch_secret`, no `confirmation_key`, no `membership_key`, no ciphersuite internals.
> `EngineProcessed.Raw` and `stagedRef` are deliberately opaque so a staged commit can be carried
> across a policy decision without `connect/message` being able to read or forge it.

**The §3.6 wording that reads like a contradiction and is not.** §3.6's concurrency table says
`message.GroupSession` *"Owns exactly one `mls.Group`"*. §4.5 Gate 5 and §6 put MLS behind this
interface. Both are satisfiable and only one is safe: `GroupSession` holds a **`GroupHandle`**, whose
one production implementation wraps one `mls.Group`. Naming `mls.Group` in `GroupSession`'s field set
would make Gate 5's swap a type change rather than a factory change. **Open item M1-4** records
§3.6's loose wording.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the interface is closed and the closure is derived.** The scope question (R3a): the
  class is the method set read off the syntax tree of `engine.go`, and the assertion is against
  §6's block. A method added here is a design decision, and the gate is what makes it one. *Refusal
  owed:* a method whose name matches the forbidden set above fails with the §6 sentence quoted.

  **Property 2 — `EngineProcessed.stagedRef` is unexported and `Raw` is never inspected.** The scope
  question: derive the class of functions in this package that read `EngineProcessed` and assert none
  of them indexes, parses or compares `Raw`. **That class is empty at this task's commit** — nothing
  reads `EngineProcessed` until Task 9a's adapter and Task 10's session — and the tree's house style
  **fatals on an empty derived class** rather than reporting clean over it (`aad_test.go:1293`,
  `:1432`, `:1539`; `writeauth_test.go:2451`, each phrased *"reporting clean having read nothing"*).
  So this property has two halves and they land in two commits: the **unexported-field** half is
  checkable here, off the syntax tree, and is asserted here; the **never-inspected** half moves to
  **Task 9a**, where the class first has a member — its Property 3 is that half, stated about the one
  function that reads an `EngineProcessed`. Do not write it here as a derived-class gate that
  passes vacuously — R1 exists because that is the shape thirty plan-supplied tests took.

  **Property 3 — no method on either interface names a type from `connect/mls`.** The scope
  question (R3a): the class is the method set of `GroupEngine` and `GroupHandle`, read off the
  syntax tree of `engine.go`. **That class is 27 members at this task's commit** — 4 and 23,
  counted off §6's block on 2026-09-05 — and every one is checked for a parameter or result type
  qualified by the `mls` package. *Refusal owed:* a method whose signature names `mls.LeafIndex`, `mls.Member`,
  `mls.Processed` or any other `connect/mls` type fails, naming Gate 5.

  **This is the property that holds the boundary, and it is the one an implementer will be pushed
  to break.** The cheap way out of any friction between §6's block and `group.go`'s method set is
  to change the **interface** until `mls` fits — mutation 6 below is exactly that move — and an
  interface that names `mls`'s types has stopped being a seam and become a re-export. The class is
  non-empty from this task's first commit, because this task declares all 27 methods.

  **What this property no longer says, and why.** Its previous form was *"the adapter satisfies
  `GroupHandle`, and `*mls.Group` does not"*, and the second half of that — the headline — was
  asserted by nothing. Its two stated teeth were (i) *"a test asserting
  `var _ GroupHandle = (*mls.Group)(nil)` must not exist"*, which **cannot fire in any state where
  the test binary builds**: if such a test existed the package would not compile, so the property
  was true exactly when it was unobservable, and (ii) a restatement of Property 4. A non-event is
  not an assertion, and a sentence that reads like a guarantee while resting on a non-event is
  worse than no sentence. **The half that is genuinely checkable is Task 9a's
  `var _ GroupHandle = (*connectMlsHandle)(nil)`, which is a build failure when it is violated —
  see Task 9a Property 1.** What survives here is the interface-shape gate above, which has a
  mechanism, a class and a member.

  **The measurement stays, as the argument for Task 9a rather than as a property.**
  `*mls.Group` is not supposed to satisfy this interface, and measured on 2026-09-05 it cannot —
  `grep -n '^func (self \*Group) [A-Z]' connect/mls/*.go` against §6's block puts **13 of the 23
  methods** out of reach, and no correct implementation of either side closes them:

  | §6's method | `*mls.Group` | why it can never match |
  |---|---|---|
  | `OwnLeafIndex() uint32` | `OwnLeafIndex() LeafIndex` | `mls/tree_math.go:27` makes `LeafIndex` a **defined type**; Go method sets are identical-type, not convertible-type |
  | `MemberAt(int) (uint32, []byte, []byte, error)` | `MemberAt(LeafIndex) (Member, bool)` | different parameter type, different arity, different result kinds |
  | `MemberCount() int` | — | absent |
  | `SenderDataSecret() ([]byte, error)` | — | absent; reachable only through `EpochSecret`, which §6 refuses |
  | `EncryptionSecret() ([]byte, error)` | — | absent, same |
  | `ProposeGroupPolicy([]byte) ([]byte, error)` | — | absent; `ProposeGroupContextExtensions([]Extension)` is the neighbour and takes another type |
  | `RatchetTreeSnapshot() ([]byte, error)` | `RatchetTree()` at `group.go:891` | name |
  | `GroupContextBytes() ([]byte, error)` | `GroupContext()` at `group.go:900` | name |
  | `ProposeRemove(uint32) ([]byte, error)` | `ProposeRemove(LeafIndex) ([]byte, error)` | defined type again |
  | `Commit([][]byte) (commit, welcome, ratchetTree []byte, err error)` | `CreateCommit([][]byte, []Proposal, *CommitOptions) (*CommitResult, error)` | name, arity, result |
  | `Process([]byte) (*EngineProcessed, error)` | `ProcessMessage([]byte) (*Processed, error)` | name, and a result type §6 declares **here** |
  | `ApplyCommit(*EngineProcessed) error` | `ApplyCommit(*Processed) error` | that same result type, from the other side |
  | `Unprotect([]byte) (aad, plaintext []byte, senderLeaf uint32, err error)` | `Unprotect([]byte) (*ApplicationMessage, error)` | different results |

  Two of those — `Process` and `ApplyCommit` — are **structurally unclosable by design**:
  `EngineProcessed` is declared in `connect/message` and carries an unexported field, so no method in
  `connect/mls` can ever name it. That is the interface working, not failing.

  That table is why Task 9a exists and why it is thirteen decisions rather than a delegation. It is
  not an assertion this task can make: *"a structural mismatch is absent"* is refuted by nothing a
  test can run, which is the correction Property 3 above records. An older draft went further still
  and told the implementer every method *"must be satisfiable by `*mls.Group`"* — red before a
  single mutation, and pushing toward the one reshape this section forbids.

  **Property 4 — nothing in this package's production source names `mls.Group` *outside the
  adapter's own file*.** Derived off the tree; this is Gate 5's actual content, and the exemption is
  by **scanned path**, never by base name — `crypto_forbidden_test.go:72-82` argues that distinction
  at length and calls a base-name exemption *"the exemption shape this project keeps rediscovering"*.
  The one allowed path is Task 9a's file, and the count of files taking it is asserted, so a second
  cannot quietly join.

  The earlier form of this property — *nothing in this package names `mls.Group`, full stop* —
  contradicted §2.2's own tree, which assigns *"engine.go — the GroupEngine interface (§6) **+ the
  connect/mls adapter**"* to one file (spec line 197 after A-12), and contradicted Task 9a, which has to exist
  for `GroupSession` to hold anything real. This plan follows §2.2's pairing (M1-36). **After the
  split the full-stop form becomes true of `connect/message` and stays false of
  `connect/messagegroup`,** and that is the ruling working: `mls.Group` is nameable in exactly one
  file of one package, and the package it is not nameable in is the one the server links.

  **The adapter's home is a choice, and the earlier reason given for it was false.** That reason
  was: *"`EngineProcessed.stagedRef` is unexported, so only package `message` can construct a
  populated one, so only package `message` can implement `Process`."* It is false as a matter of
  Go semantics, and the reviewer proved it by compiling on the pinned go1.26.5: a keyed composite
  literal naming only exported fields is legal across package boundaries, so a type in another
  package declaring `Process(...) (*msg.EngineProcessed, error)` and returning
  `&msg.EngineProcessed{Kind: 3, Raw: b}` builds green and satisfies `msg.GroupHandle`. What is
  confined is narrower and is the whole of it: **populating `stagedRef`**. Naming it in a literal
  from outside is *"cannot refer to unexported field stagedRef in struct literal"*, and an unkeyed
  literal is *"implicit assignment to unexported field stagedRef"*. Both are compile errors; the
  keyed-exported-fields form is not.

  So this file is the adapter's home because **§2.2's tree pairs them** — *"engine.go — the
  GroupEngine interface (§6) + the connect/mls adapter"* — and because this adapter is the one
  implementation that carries a staged `mls` commit through `stagedRef`, which only a member of
  the declaring package can populate. A replacement engine in another package satisfies the
  interface; what it cannot do is use `stagedRef`, so it must carry its staged state some other way
  and §6's unforgeability argument does not reach it. **Open item M1-43** states what that leaves
  of §6's swap claim, on the corrected premise.

  **What the split changes here, and it is the sharpest instance of the ruling.** The earlier text
  of this task read §2.2's tree as putting the adapter in `connect/message` — *the package the
  server imports*. It does not go there. §12.1 gives the server *"no decryption function, no
  key-schedule function, and no MLS type"*, and `GroupHandle` is twenty-three methods of MLS type;
  an adapter over `*mls.Group` in the package `msgrepo/api` links is the exact shape the ruling
  refuses. Interface, adapter and `EngineProcessed` all move to `connect/messagegroup`, **together**
  — and the togetherness is forced rather than tidy: `stagedRef` is unexported, so an adapter in
  `messagegroup` over an `EngineProcessed` left behind in `message` could not populate it at all,
  and §6's unforgeability argument would be lost to a file move. `messagegroup` still imports
  `connect/message` for `Record`, `RecordHeader` and the four preimages; the edge is one way.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Add `SecretTree()` to `GroupHandle`.
  2. Add `EpochSecret(name)` returning the raw epoch secret.
  3. Export `stagedRef`.
  4. Have a production function in `message` **outside the adapter's file** take an `*mls.Group`.
  5. Drop `Export` from the interface and reach the exporter another way.
  6. Change `OwnLeafIndex`'s result to `mls.LeafIndex` so `*mls.Group` fits — the reshape Property 3
     exists to refuse, and the first one an implementer reaches for.
  7. Add `var _ GroupHandle = (*mls.Group)(nil)` to a test file. **What refutes this one is the
     compiler**, not a gate: the assertion does not build, so `go test ./message/...` fails to
     compile and the mutation is refused before any test runs. Record it as a compile refusal;
     do not write a gate for it, because a gate that searches for a line which cannot exist in a
     buildable tree is the non-event Property 3 above was corrected for.
- [ ] **Step 6: Commit**

---

## Task 9a: The `connect/mls` adapter — the thing that actually satisfies `GroupHandle`

**Files:**
- Modify: `connect/messagegroup/engine.go` (§2.2's tree puts the interface and the adapter in one
  file, and this plan keeps that pairing; what the split changes is the package, not the file);
  `connect/messagegroup/errors.go`
- Test: `connect/messagegroup/engine_test.go`

**Interfaces:**
- Consumes: `*mls.Group`'s method set, read out of `connect/mls/group.go` at the time of writing
  (R2 — every one of the 13 mismatches in Task 9's table is a place a stale spelling would compile
  into the wrong call); `mls.LeafIndex`, `mls.Member`, `mls.Processed`, `mls.CommitResult`,
  `mls.ApplicationMessage`, `mls.EpochSecretName`.
- Produces:
```go
// unexported: the factory is the door, and §6's swap point is the factory's, not the type's.
type connectMlsEngine struct{ ... }   // satisfies GroupEngine
type connectMlsHandle struct{ ... }   // satisfies GroupHandle, wrapping exactly one *mls.Group
func NewConnectMlsEngine(...) (GroupEngine, error)

var _ GroupEngine = (*connectMlsEngine)(nil)
var _ GroupHandle = (*connectMlsHandle)(nil)
```

**Why this task exists, and why its absence was the other half of Task 9's defect.** Before this
repair **no task in this plan produced a `GroupHandle` implementation at all** — `grep -n 'adapter'`
over the plan returned **one** hit, inside §6's block quotation, and no task's Produces named it.
Task 10 hands `GroupSession` a `GroupHandle`; wave 1 therefore ended with a session that could hold
nothing real, and CP3b's *"no test-only key source anywhere on the path"* was unreachable from
waves 1 and 2 for a reason no open item named.

**The 13 mismatches Task 9 measured are this task's entire body of work**, and each is a decision the
adapter takes rather than a translation:

- `OwnLeafIndex`, `ProposeRemove` — `uint32(…)` / `mls.LeafIndex(…)` conversion at the boundary, in
  one direction only, so a raw `uint32` from the wire never reaches `mls` unconverted.
- `MemberCount`, `MemberAt` — over `Group.Members()` (`group.go:751`) and `Group.MemberAt`
  (`:797`), projecting `mls.Member` down to §6's three byte slices. `MemberAt`'s `bool` becomes the
  `error`, because §6's signature has one and dropping the distinction is how a missing member
  becomes a zero leaf.
- `SenderDataSecret`, `EncryptionSecret` — `Group.EpochSecret(name)` with the two closed-enum names.
  **This is the only place in the tree that names them**, and it is the whole of G6 seen from this
  side: `EpochSecret` is not on §6's interface precisely so `epoch_secret`, `confirmation_key` and
  `membership_key` cannot be reached from `connect/message`.
- `ProposeGroupPolicy` — over `Group.ProposeGroupContextExtensions` (`:1716`), building the
  `0xF001` extension from the policy bytes. This is the one method whose body is not a projection.
- `RatchetTreeSnapshot`, `GroupContextBytes` — `Group.RatchetTree()` (`:891`) and
  `Group.GroupContext()` (`:900`). Both exist; the divergence is naming, and it is **this plan's**
  (see the withdrawn ask O-4).
- `Commit` — over `Group.CreateCommit(byReference, nil, nil)` (`:1952`), projecting `*CommitResult`
  to §6's four returns.
- `Process`, `ApplyCommit` — `*mls.Processed` in, `*EngineProcessed` out, with the `mls` value
  carried in **`stagedRef`** and never in `Raw`. This is the pair that needs `stagedRef`, and
  needing it is what keeps *this* adapter in the same package as `EngineProcessed`: `stagedRef` is
  unexported, so only a member of the declaring package can populate one. It does **not** confine
  every implementation — a foreign type returning
  `&messagegroup.EngineProcessed{Kind: …, Raw: …}` from a keyed literal over the exported fields
  compiles and satisfies `GroupHandle`, measured on go1.26.5; it just has nowhere unforgeable to put
  the staged commit. What it *does* confine is the relocation: struct and adapter move together or
  the guarantee is lost. **Open item M1-43.**
- `Unprotect` — `*mls.ApplicationMessage` projected to three values.

**What this task must not do.** It must not widen `GroupHandle` to make any of the above cheaper.
Every line of the list above is a place where changing the interface is one edit and writing the
adapter is five, and §6's whole value is that the interface is the expensive side.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the two compile-time assertions hold, in production source.** `var _ GroupEngine`
  and `var _ GroupHandle`. This is the property Task 9 could not state about `*mls.Group`, stated
  about the type that is meant to have it. *Refusal owed:* none; a failure here is a build failure,
  which is the point.

  **Property 2 — one handle owns exactly one `*mls.Group`, and the group is reachable from nowhere
  else.** The scope question (R3a): derive the class of production declarations in this package whose
  type mentions `mls.Group` and assert it is exactly this file's, by scanned path (Task 9
  Property 4's other side).

  **Property 3 — no reader of an `EngineProcessed` inspects `Raw`, and `Raw` never carries the
  staged commit.** Two halves, and the first is **the derived-class half Task 9 Property 2
  relocated here**, because this is the commit where its class first has a member.

  **The relocated half — the derived-class gate over *readers*.** Task 9 Property 2 states that
  `stagedRef` is unexported and that `Raw` is never inspected, and measured at Task 9's commit the
  class of functions in this package that read an `EngineProcessed` was **empty**; the tree's house
  style fatals on an empty derived class rather than reporting clean over one, so the reader gate
  could not land there. The scope question (R3a): the class is every function in this package's
  production source whose body reads a field of an `EngineProcessed`, derived off the syntax tree
  and never listed. **At this task's commit that class has two members** — this adapter's `Process`
  and its `ApplyCommit` — and it grows by one at Task 10, when `GroupSession` reads one. *Refusal
  owed:* a member that indexes, parses, compares or length-checks `Raw` fails, naming Task 9
  Property 2 and quoting §6; the gate fatals if it finds no reader at all, in the house phrasing,
  so it cannot become vacuous again through a refactor.

  **The producer half — what this adapter writes.** After `Process`, the value `ApplyCommit` needs
  is in `stagedRef` and `Raw` is opaque bytes; an `ApplyCommit` handed an `EngineProcessed` this
  adapter did not build is a typed refusal, not a panic and not a silent no-op. §6: *"so a staged
  commit can be carried across a policy decision without `connect/message` being able to read or
  forge it."* Note the scope this buys and the scope it does not (M1-43): the guarantee is that
  **this package** cannot forge a staged commit an engine **in this package** staged. It is not a
  guarantee about an engine declared elsewhere, which can satisfy the interface and has no way to
  use `stagedRef` at all.

  **Property 4 — every projection is total.** For each of the 13, a case where the `mls` side
  reports absence — `MemberAt`'s `false`, `EpochSecret`'s error, an aged-out epoch's
  `ErrEpochErased` — reaches the caller as a typed error and never as a zero value. A projection that
  drops a `bool` is how a missing member becomes leaf 0.

  **Property 5 — the enum names are the closed ones.** `SenderDataSecret` and `EncryptionSecret`
  name `mls`'s `EpochSecretName` constants, read out of source, and no third name is reachable from
  this file. G6 is landed on the `mls` side; this asserts the `message` side does not route around it.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Return `mls.Member`'s fields in a different order from `MemberAt`.
  2. Drop `MemberAt`'s `bool` and return the zero `Member`.
  3. Carry the staged commit in `Raw` instead of `stagedRef`.
  4. Accept an `EngineProcessed` built elsewhere in `ApplyCommit`.
  5. Add `EpochSecret(name)` to the handle so the adapter's callers can reach `epoch_secret`.
  6. Widen `GroupHandle.OwnLeafIndex` to `mls.LeafIndex` and delete the conversion.
  7. Swap `RatchetTreeSnapshot` and `GroupContextBytes`'s bodies — both return opaque bytes and
     nothing downstream in wave 1 parses either, which is what makes this one worth running.
- [ ] **Step 6: Commit**

---

## Task 10: `GroupSession` — the type all of §5.2 hangs off, and which no spec declares

**Files:**
- Create: `connect/messagegroup/session.go`
- Test: `connect/messagegroup/session_test.go`

**Interfaces:**
- Consumes: Task 9's `GroupHandle` **and Task 9a's implementation of it** — the session holds the
  interface and is constructed with a value, and `NewConnectMlsEngine` is where a caller gets one;
  Task 3's `StorageRoot`/`DeriveClassKeys`; Task 4's three handle derivations; Task 6's
  `StreamIndexReserver`, **injected, because this package does not implement one** (Task 6);
  Tasks 7–8's two ratchets.
- Produces: `GroupSession`, its constructor, its `Close`, and the epoch-state value everything else
  reads.

**The gap this task closes by designing, and which the spec does not close.** Grepping the whole of
Spec A for `GroupSession` returns exactly three lines: §5.2's two method signatures, §3.6's
concurrency row, and §5.6's sentence that *"the constructor takes the sink to make it explicit"*.
There is no `type GroupSession struct`, no `func NewGroupSession(...)`, no statement of what it holds
or how it is closed — while §5.6 silently adds a `StreamIndexReserver` to its constructor and §5.3
adds an epoch-zero storage root it must have persisted since group creation. **Open item M1-4.** This
task designs it; the design is this plan's, not the spec's, and the doc comment must say so.

**The concurrency contract, quoted, because its shape is the reason it exists.** §3.6:

> `message.GroupSession` — Safe for concurrent use. Owns exactly one `mls.Group` and serializes
> access through a single-goroutine command loop (`run()`, started by the constructor, per CODESTYLE
> goroutine lifecycle).
>
> The command-loop shape matters: MLS commit construction, message ingest, and epoch rotation all
> mutate the same tree, and a lock around each public method would not prevent an interleaving where
> two goroutines both build a commit for epoch *n*. One goroutine per group, commands on a channel.

**What the session must hold, derived from what its consumers need:**

- one `GroupHandle` (Task 9), reached only from the loop goroutine;
- the **epoch-zero** storage root, or the `group_handle_key` derived from it — persisted at group
  creation and never recomputed from a later epoch (Task 4's property 6 mutation is why);
- the current epoch's `storage_root`, its `ClassKeys`, and its `write_key`/`read_key`;
- one `StreamIndexReserver`, injected — §5.6's "the constructor takes the sink to make it explicit";
- the sender ratchet table and the receiver ratchet table, keyed per M1-11's ruling;
- `own_leaf_index`, from `GroupHandle.OwnLeafIndex()`, and the `sender_handle` computed from it;
- an injected `nowMs func() int64`, because the house rule forbids a timing-sensitive test and
  `expire_at` is a clock read.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — every mutation of the handle happens on the loop goroutine.** The scope question
  (R3a): derive the class of methods that touch the handle off the tree and assert each posts a
  command rather than calling through. A `stateLock` around the public methods satisfies a race
  detector and **not** this property — §3.6 says so in as many words, and the property is the reason
  the loop exists.

  **Property 2 — `Close` is idempotent, stops the loop, and zeroizes every key the session holds.**
  Run it under `goleak`, or the equivalent goroutine accounting p4 already uses, so a leaked loop is
  a failure and not a slow test.

  **Property 3 — a session cannot be constructed without a reserver.** *Refusal owed:* a typed error
  naming §5.6. A nil reserver defaulting to an in-memory one is the exact placeholder hazard the CP3a
  rule forbids.

  **Property 4 — the epoch-zero root is persisted, not recomputed.** After an epoch advance,
  `group_handle_key` is unchanged and equals what it was at epoch 0. This property is worth more than
  it looks: it is the one that fails when somebody "simplifies" `GroupHandleKey`'s argument to the
  current root.

  **Property 5 — an aged-out epoch is reported, not silently zero.** `GroupHandle.Export` returns
  `mls.ErrEpochErased` for an epoch whose secrets are gone; the session propagates it as a typed
  refusal rather than computing a storage root over an empty exporter output.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Replace the loop with a `stateLock` around each public method.
  2. Make `Close` non-idempotent.
  3. Leave the loop goroutine running after `Close`.
  4. Default a nil reserver to an in-memory one.
  5. Recompute `group_handle_key` from the current epoch's root.
  6. Swallow `ErrEpochErased` and continue with a zero-length `mls_secret`.
- [ ] **Step 6: Commit**

---

## Task 11: `SealRecord` — the construction order as a type

**Files:**
- Create: `connect/messagegroup/seal.go`
- Test: `connect/messagegroup/seal_test.go`

**Interfaces:**
- Consumes: `message.AADHead`, `message.AADBody`, `(*RecordHeader).BodyBinding`,
  `message.ComputeWriteAuth`, `message.EncodeServerAttachment`, `message.RetentionClassWire`,
  `message.SizeBucketBytes`, `message.SizeBucketCtBodyBytes` — **all landed; read every signature out
  of source**; Task 1's AEAD; Task 5's derivations; Task 7's ratchet; Task 10's session.
- Produces:
```go
type recordBuilder struct{ ... }   // unexported; the private staging type
func (self *GroupSession) SealRecord(
    class RetentionClass, ephBucket uint8, isCommit bool,
    headPlain []byte, bodyPlain []byte, expireAt uint64,
    serverAttachment *ServerAttachment,
) (*Record, error)
```

**The order, quoted, and it is already encoded in the landed signatures.** §5.2:

> MASTER §8 gives the construction order: build `server_attachment` → encrypt `ct_body` → compute
> `body_hash` → encrypt `ct_head` → compute `write_auth`. Every dependency is acyclic, and getting it
> wrong produces a circular AAD that *appears* to work until two implementations disagree.

`SealRecord` calls four already-built functions in that sequence and **derives nothing**: `AADBody`
takes a `BodyBinding` with no hash in reach (that is G4, built as a signature), `AADHead` reads
`body_hash` off the header, `WriteAuthPreimage` takes `H(ct_head)`, `ComputeWriteAuth` closes it.
Do not re-derive the order; the signatures already carry it.

**Three decisions this task must take and say it is taking.**

**(a) Which `record_key` seals the head.** MASTER §8.1 says *"`ct_head` is always under the **durable**
class"* and §5.3 hands both AEAD derivations one `record_key[i]`. **Open item M1-6.** Pending the
ruling: for a `DURABLE` record the two readings coincide, and CP3b's text record is `DURABLE`.
`SealRecord` must therefore **refuse a non-`DURABLE` class** until M1-6 is ruled, with a typed error
naming the item — a refusal, not a guess. A `PERMANENT` record sealed under the wrong reading is
wire-visible and unrecoverable after the A6 freeze.

**And that refusal blocks a wave-2 task on this plan's own CP3b path, which is why M1-6 is filed
under *Blocking CP3b* and not under the A6 freeze.** Task 15 consumes this `SealRecord` and must emit
the ratchet-tree snapshot, which §5.11 step 2 fixes as *"one **PERMANENT**-class record"*. Property 6
below and mutation 9 are what hold this refusal in place, and Task 15 meets it at its own second
step. This is a wave-1 refusal blocking a wave-2 task, and it was invisible while M1-6 sat under a heading about a format freeze
months out. **Rule M1-6 before Task 15 starts.** What Task 15 does in the meantime is stated in
Task 15's own text; it is not this task's to weaken. Specifically: do **not** carve a `PERMANENT`
exemption into `SealRecord` for the snapshot. The refusal is the only thing standing between an
unruled reading and a wire-visible record, and one exemption is how a refusal becomes a sentence.

**(b) How the body is padded, and how the receiver recovers its length.** §5.1 fixes
`octet_length(ct_body)` at `size_bucket_bytes[b] + 16` exactly, so the plaintext is padded to
`SizeBucketBytes(b)` before the AEAD. **No document states the padding scheme, and `pad.go` is named
in §2.2's tree with no section anywhere.** MASTER §9.5 is "What the server sees" and is not it.
Without a stated scheme `OpenRecord` returns a 256-octet slice for a five-octet message and the
caller cannot tell the message from the padding. `msgrepo/harness/seal.go` pads with `byte(index*31)`
and never unpads, because CP3a's harness does not encrypt and never reads a body back. **Open item
M1-7**, wire-visible, blocks the A6 freeze. Pending the ruling, put the padder and the unpadder in
**one unexported pair in `seal.go`** so the ruling is one edit, and make `OpenRecord`'s round trip
the test that binds them.

**(c) The empty attachment.** §5.2 says `serverAttachment` *"is nil for an ordinary record and MUST
then encode zero-length (§5.11)"*; §5.11 says a parser MUST refuse an **encoded** kind `0x0000`.
Neither says what `SealRecord` does with a non-nil `&ServerAttachment{Kind: AttachmentNone}` — the
value a caller building attachments in a loop naturally produces. `attachment.go` already chose the
safe reading and documented it: a nil attachment and an `AttachmentNone` attachment both answer no
bytes at all, so both contribute the same `LP(H(server_attachment))`. **Call
`EncodeServerAttachment` and use its answer**; do not add a second nil check. **Open item M1-18**
asks for the reading to be promoted into §5.11.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the order is unrepresentable-otherwise.** The scope question (R3a): derive the
  dependency edges from the call graph of `SealRecord` — the class is every call into `aad.go` and
  `writeauth.go` — and assert the topological order. A test that only checks the output bytes cannot
  distinguish "computed in order" from "computed in any order and assembled".

  **Property 2 — `body_hash` is `H(ct_body)` over the padded ciphertext,** and it is never in
  `AAD_body`. G4 makes the second half unrepresentable; assert it anyway, because the assertion is
  what survives a refactor of `BodyBinding`.

  **Property 3 — the reservation precedes the first AEAD call,** extended from Task 6's Property 1
  to the real seal, and extended per G11 with an injected commit loss between reserve and re-seal.

  **This is also where Task 7 Property 1's derived-class half lands, and this is the commit where
  that class first has a member.** Task 7 Property 1 states the reservation-before-key property
  over `SenderRatchet.Next` — a one-member class at Task 7 — and relocates the **reachability
  walk** here, because *"every path from `SealRecord` to a `RecordAeadHead` / `RecordAeadBody` call
  reaches `Reserve`"* has no path to walk until `SealRecord` exists: measured 2026-09-06, nothing
  in `connect/message` calls either AEAD derivation before this task. The scope question (R3a): the
  class is the call paths read off the syntax tree from `SealRecord`, never a list, and **it has at
  least one member at this task's commit** — `SealRecord` itself. `writeauth_test.go`'s
  `TestReadAuthNeverUsesWriteKey` (`:1904`) is the shape, with its `reaches` list and its positive
  control under `testdata`, and the gate fatals if it finds no path at all, in the house phrasing,
  so it cannot go back to being vacuous if `SealRecord` is refactored. *Refusal owed:* a path that
  reaches an AEAD derivation without reaching `Reserve` fails, naming Task 7 Property 1.

  **What this walk cannot prove stays at Task 7 Property 1** — that the path passes through a
  *returned-nil* `Reserve`. Error handling and ordering are invisible to a reachability walk, so
  Task 7 keeps the AST check on `Next` and the behavioural failing-reserver test, and mutation 6
  below is refused by those rather than by this walk.

  **Property 4 — every header field the caller supplies reaches both preimages.**
  `writeauth_test.go` already has `TestEveryWriteAuthInputHasAMutator` and
  `TestEveryInputTheWriteAuthPreimageCoversChangesTheTag` over a **derived** input class; this task's
  version derives its class from `SealRecord`'s parameters plus the session's own state, so a field
  the session contributes silently (epoch, sender handle, stream index) is covered too.

  **Property 5 — `ct_body` is exactly its rung, or absent on the blob rung,** and the record
  `EncodeRecord` refuses is the record `SealRecord` refuses, through the same `checkRecord`.

  **Property 6 — a class other than `DURABLE` is refused with the M1-6 sentinel** until M1-6 is
  ruled, and the refusal names the item.

  **Property 7 — every call of `message.AADHead` and `message.AADBody` in production source, on
  either side of the split, passes `RecordAeadAlgId`.** This is the derived-class half of Task 1
  Property 1, landing here because **this is the commit where the class first has a member** —
  before `SealRecord` there is no production call of either builder, and a class gate over an empty
  class either fatals or passes vacuously (Task 1 says which, and why).

  **The scope question (R3a), answered separately from the class question, because the split
  separated them.** The class is the call sites read off the syntax tree, never a list. The
  **scope** is two directories — `connect/message` and `connect/messagegroup` — and it must be
  both, for a reason each root supplies on its own: `connect/message` is where the builders are
  declared and where a future server-side call would appear, and `connect/messagegroup` is where
  every call is today. A gate rooted at `connect/messagegroup` alone would report clean over a
  server-side call passing a literal; a gate rooted at `connect/message` alone reads an empty class
  and fatals. *Refusal owed:* a production call passing a literal, or `XwingAlgId`, or an attachment
  alg id, fails — and the gate fatals if it finds no call in **either** root, in the house
  phrasing, so it cannot go back to being vacuous if `SealRecord` is refactored or if the package
  boundary moves again.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Compute `body_hash` before padding.
  2. Compute `write_auth` before `ct_head`.
  3. Build `AAD_head` before `body_hash` exists (using a zero hash).
  4. Seal `ct_head` and `ct_body` under one AAD.
  5. Seal both under one key.
  6. Reserve after the first AEAD call.
  7. Pass `attachmentBytes` to `AADHead` while setting a different value on the header — the landed
     `ErrServerAttachmentMismatch` must catch this and the test must prove it does.
  8. Pad with a constant instead of the ruled scheme.
  9. Accept a `PERMANENT` class.
- [ ] **Step 6: Commit**

---

## Task 12: `OpenRecord` — the only consumer, and the two failures that are not errors

**Files:**
- Modify: `connect/messagegroup/seal.go`, `connect/messagegroup/seal_test.go`, and **both** doc
  comments: `connect/messagegroup/doc.go` gains the inventory, `connect/message/doc.go` loses the
  future-tense sentence that says the key schedule "lands beside them" and names the other package
  instead

**Interfaces:**
- Consumes: everything Task 11 consumes, plus Task 8's `ReceiverRatchet`.
- Produces:
```go
func (self *GroupSession) OpenRecord(record *Record) (headPlain, bodyPlain []byte, err error)
```

**The two outcomes the declared signature cannot express, quoted.** §5.5:

> Beyond the window, a record is undecryptable and surfaces as a `Kind == "gap"` entry with
> `GapReason == "out_of_window"` (§7.4) — **not as an error.** This is a deliberate, visible failure:
> silently skipping is how a message loss becomes invisible.

§5.11 step 4:

> A member or device that finds no wrap for its target at epoch `n+1` after the marker has landed
> surfaces a `gap` entry with reason `no_wrap`. It never fails silently.

`OpenRecord` has **one** error channel, and §5.9 G7 makes every error in this package fatal by
construction. Nothing in §5 names the sentinels `sdk` must `errors.Is` against to turn a refusal into
a gap rather than a failure. **Open item M1-15.** Two shapes close it: `OpenRecord` grows a third
return value, or §5 pins `ErrOutOfWindow` and `ErrNoWrap` as sentinels `sdk` matches — in which case
A-9's reachability rule applies and §12.1's refusals block gains two lines in the commit that makes
them reachable. Pending the ruling, declare both sentinels (Task 8 declared the first) and return
them; do not invent a third return value on the plan's own authority.

**`doc.go` must stop saying the key schedule is future tense.** Its header today reads *"The key
schedule lands beside them and reads the same types."* This task rewrites that paragraph to describe
what landed, in the file's existing voice, and names what is still absent — because the header's
value on this project has been that it is the honest inventory a reader meets first.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — round trip.** Seal then open returns the exact head and body plaintexts, for every
  rung of the size ladder and for a body of length 0 and of length `SizeBucketBytes(b)`. The two
  endpoints of the padding range are where an unpadder is wrong.

  **Property 2 — a two-session round trip.** A record sealed by one `GroupSession` opens in a second
  one constructed from the same epoch state and a different leaf. This is the property CP3b is, minus
  the transport and minus the real join, and it is reachable in wave 1 **only** by constructing both
  sessions from one storage root in a test. That is legitimate here and is **not** CP3b: state it in
  the test's own comment, because a passing two-session round trip is exactly the result somebody
  will mistake for the milestone. Task 16 Property 2 is the same warning at the next distance.

  **Property 3 — every single-bit mutation of the record fails to open,** across `ct_head`,
  `ct_body`, and every header field in both AADs. Derive the header-field class off the type, not off
  a list.

  **Property 4 — an out-of-window index is `ErrOutOfWindow`,** distinguishable by `errors.Is` from
  every other refusal, and it does not move the receiver's head (Task 8 property 3).

  **Property 5 — a partial plaintext is never returned beside an error.** On any failure both
  returned slices are nil. A caller that renders whatever came back renders attacker-chosen bytes.

  **Property 6 — `OpenRecord` never trusts `RecordId`.** It is server-assigned and authenticated by
  nothing (§5.1); derive the class of fields the open path reads and assert `RecordId` is not among
  them.

- [ ] **Step 2–4** as above.
- [ ] **Step 5: Mutation-test.**
  1. Return `bodyPlain` alongside a non-nil error.
  2. Open `ct_head` with `AAD_body`.
  3. Skip the `body_hash` check against the received `ct_body`.
  4. Derive the receive key from the header's `stream_index` without the window.
  5. Unpad to a length read from an unauthenticated place.
  6. Accept a record whose `sender_handle` is not the one the ratchet is keyed by.
  7. Return `ErrOutOfWindow` for an in-window gap.
- [ ] **Step 6: Commit**

---

# Wave 2 — the second client's half of CP3b

Everything below is on the CP3b path. **Tasks 14 and 16 cannot be written until the rulings they
name land.** They are written out here anyway, in the shape they will take, because a plan that
omitted them would make CP3b look nearer than it is.

## Task 13: `pq_secret`, and the provisional epoch state G10 destroys

**Files:**
- Create: `connect/messagegroup/epoch.go`
- Test: `connect/messagegroup/epoch_test.go`
- Modify: `connect/messagegroup/entropy_test.go`, `connect/mls/crypto_test.go` — **in this commit**, Gate B.

**Interfaces:**
- Consumes: `mls.ErrNilRandomSource`; `GroupHandle.ClearPendingCommit` (Task 9); Task 2's `zeroize`.
- Produces: a sampler for `pq_secret[n]` taking `io.Reader` and nothing else, and a provisional
  epoch value holding everything §5.12 step 1 discards, with a destructor that also calls
  `ClearPendingCommit`.

**The gap, stated at its real size.** `pq_secret[n]` is an argument to the root function of the whole
schedule and it has **no producer declared in section 5**: no sampling function, no type, no file, no
section. §5.12 says the committer samples it and must resample on any rejection; §5.10 E1 says the
device wrap carries it; MASTER §8.2's table says active device leaves receive *"`pq_secret[n]` **and**
`eph_root[n]`"*. **Open item M1-3.** This task supplies the sampler, because a 32-octet CSPRNG draw
is not an ambiguity — its **delivery** is, and that is M1-1.

**The sampler's signature is the defence, exactly as `NewEphRoot`'s is.** It takes an `io.Reader` and
nothing else: no group, no epoch, no storage root. A `pq_secret` derived from anything durable is the
same defect class as a derived `eph_root`, and the same reasoning applies — it would compile, pass
every test that does not look for it, and forfeit the PQ property silently.

**G10's split destructor, filed.** §5.9 G10 names `ClearPendingCommit` as *"a value that
`ClearPendingCommit` destroys"*, with no receiver and no signature. The landed one is
`func (self *mls.Group) ClearPendingCommit()` (`group.go:2475`), which erases the staged **MLS**
epoch. §5.12 step 1 requires discarding `storage_root[n+1]`, `write_key[n+1]`, `eph_root[n+1]`,
`pq_secret[n+1]` **and every X-Wing wrap it built** — none of which `mls` knows about, and none of
which has a declared home in `connect/message`. **Open item M1-20.** This task gives the message-side
half a home and puts the `mls` call **inside its destructor**, not beside it, so the two cannot be
destroyed apart.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the sampler refuses a nil reader with `mls.ErrNilRandomSource` and refuses an
  exhausted one.** This is Gate B's content and the probe row is not optional; the row must be added
  in this commit or the `mls` suite fails.

  **Property 2 — the only producer of a `pq_secret` is the sampler, and the sampler's only input is
  an `io.Reader`.** Two halves, and the second is the one an AST scan can decide.

  **Half A, decidable and worth a gate — the sampler's signature.** Its parameter list is exactly
  `(io.Reader)`: no group, no epoch, no storage root, no class key. Derived off the declaration, and
  refused as a signature rather than as a behaviour, which is the same defence `NewEphRoot` has and
  the same one G4 gives `AADBody`. *Refusal owed:* a second parameter of any type fails.

  **Half B, and the class the earlier version of this property named cannot be it.** That version
  said: *derive the class off the tree — every function returning 32 octets whose parameters include
  a storage root, a class key or an epoch — and assert the sampler is not among them and nothing
  else answers the description.* Its second clause convicts **five functions this plan itself
  specifies**, measured against this plan's own Produces blocks on 2026-09-05:

  | function | returns | takes | convicted by |
  |---|---|---|---|
  | `WriteKey(storageRoot []byte) []byte` | 32 | a storage root | landed, `writeauth.go` |
  | `ReadKey(storageRootEpoch []byte) []byte` | 32 | a storage root | landed, `writeauth.go` |
  | `GroupHandleKey(storageRootEpoch0 []byte) []byte` | 32 | a storage root | Task 4 |
  | `DeriveClassKeys(storageRoot []byte) *ClassKeys` | 3 × 32 | a storage root | Task 3 |
  | `RecordKeyZero(classKey []byte, leaf uint32) []byte` | 32 | a class key | Task 5 |

  Every one is correct, required, and specified by this document. The stated class is red against
  correct code, which is the same defect as a test that cannot fail seen from the other side. The
  only reading that spares them is **semantic** — *is the returned value a `pq_secret`?* — and no AST
  scan and no reflection decides that: Go reflection sees neither parameter names nor the meaning of
  returned bytes, which is M1-17's point about the sibling eph property.

  **And the class the 2026-09-05 pass replaced it with is undecidable too, in the same way.** That
  pass wrote half B as *"a derived class plus a required-row table, held in both directions"*, with
  the derived class being **every package-level function returning a 32-octet secret**. Measured
  2026-09-06 against source: `WriteKey` (`connect/message/writeauth.go:158`) and `ReadKey` (`:172`)
  both return **`[]byte`**, not `[32]byte`, and so does every derivation in `keyschedule.go` as this
  plan declares it. *"32-octet"* is therefore not a property any AST scan can read off a signature —
  it is a fact about what the function computes, which is the same semantic question one clause
  further along. An undecidable class replaced by an undecidable class is not a repair; it is the
  same defect in a second draft, and it is filed here rather than passed on a third time.

  **So half B is regrounded on something a syntax tree can decide: the sampler's body reaches no
  derivation.** The scope question (R3a): the class is the call graph of the sampler, read off the
  syntax tree from its declaration, in `TestReadAuthNeverUsesWriteKey`'s shape (`writeauth_test.go:1904`)
  with its `reaches` list and its positive control under `testdata`. **The class has one root and is
  non-empty at this task's commit**, because this task declares the sampler. Two assertions over it:

  - it **reaches** the entropy source it was handed — `Read` or `io.ReadFull` on the `io.Reader`
    parameter — so a body that ignores its argument and returns a constant fails;
  - it **reaches nothing** in `keyschedule.go`, `handle.go` or `writeauth.go`, and no `hkdf` entry
    point at all. A `pq_secret` computed from anything already in the schedule is the whole defect
    half B exists for, and *reaching a derivation* is decidable where *being a derived value* is
    not. This is what refuses **mutation 3**, deriving `pq_secret` from `storage_root[n]`, and it
    refuses it whatever the return type is.

  *Refusal owed:* an edge from the sampler into any of those files fails, naming this property and
  §5.10 E1; and the walk fatals if it followed no edge at all, in the house phrasing, so a sampler
  refactored into a shape the walk does not recognise reports rather than passes.

  **What is still not decidable, stated so the next author knows which half is theirs.** *Is the
  value this function returns a `pq_secret`?* is a question about meaning. No AST scan, no
  reflection and no gate in this tree answers it — Go reflection sees neither parameter names nor
  the meaning of returned bytes, which is M1-17's point about the sibling eph property. Half A pins
  the signature, half B pins the body's reachable set, and **the identity of the value stays with
  the author and with §5's text.** **Open item M1-17** covers the specification half.

  **Property 3 — the provisional value is destroyed as one thing.** After the destructor, every
  field is zeroized **and** `ClearPendingCommit` has been called. Assert both from one call.

  **Property 4 — nothing reads it afterwards.** G10's own words: *"there is no path that reads it
  afterwards."* Derive the class of readers off the tree and assert each checks the destroyed flag.

  **That class is empty at this task's commit**, measured against this plan's own dependency graph:
  the provisional epoch value's readers are Task 15's fan-out and Task 21's retry loop, and neither
  exists yet. The tree's house style fatals on an empty derived class rather than reporting clean
  over it (`aad_test.go:1293`, `:1432`, `:1539`; `writeauth_test.go:2451`). So what lands here is the
  half that has a member — **the value itself refuses every accessor after the destructor has run**,
  a typed refusal per G7, asserted behaviourally on the type this task creates — and the
  derived-class gate over *readers* moves to **Task 15 Property 6**, the first commit that has one.
  Note it in both tasks so it is not dropped between them: Task 15 Property 6 names this property
  back, and the 2026-09-05 pass that wrote this instruction is the pass that dropped it.

  **Property 5 — `TestLostCommitResamplesPqSecret`, named by §5.9 G10 and by §11.2.** Two commits at
  the same epoch produce two different `pq_secret` values, and the second is not the first. It can be
  written now against the provisional value even though Task 21 supplies the retry loop.

- [ ] **Step 2–4** as above; run the `mls` suite.
- [ ] **Step 5: Mutation-test.**
  1. Fall back to `crypto/rand` when the reader is nil.
  2. Fall back on a short read.
  3. Derive `pq_secret` from `storage_root[n]`.
  4. Zeroize the provisional state without calling `ClearPendingCommit`.
  5. Call `ClearPendingCommit` without zeroizing.
  6. Reuse the previous `pq_secret` on a retry.
- [ ] **Step 6: Commit**

---

## Task 14: The device wrap — **BLOCKED on Open item M1-1**

**Files:**
- Create: `connect/messagegroup/wrap.go`
- Test: `connect/messagegroup/wrap_test.go`

**Interfaces:**
- Consumes: `message.XwingEncapsulate`, `message.XwingDecapsulate`, `message.ParseXwingPublicKey`
  (all landed, §5.4 complete); `mls.LeafKeysExtension` and `ExtensionTypeUrmessageLeafKeys` for the
  target key; Task 4's `WrapTargetHandle`; Task 11's `SealRecord`; `message.WrapTag`,
  `message.EncodeServerAttachment` (landed).
- Produces: the device wrap builder and opener, and the target enumeration over a group's leaves.

**Why this is blocked, and it is the largest hole in front of CP3b.** `wrap.go` is named in §2.2's
package tree and **has no section in any spec.** What is missing is not a detail:

1. **The wrap body has no encoding.** §5.11 specifies the `WrapTag` — the server-visible attachment,
   `{wrap_target_handle, epoch}` — and says nothing about the bytes inside `ct_body`. MASTER §8.2
   says what the wrap *carries* (`pq_secret[n]` and `eph_root[n]` for a device leaf) and not how they
   are laid out, framed, or versioned.
2. **The wrap's own seal is circular as the sizing implies it.** §5.11 says a device wrap *"pads to
   `size_bucket 2`, a `ct_body` of exactly 4,112 bytes"*, i.e. it is an ordinary record whose body
   goes through the record AEAD. But the record AEAD's key comes from `storage_root[n+1]`, and
   `storage_root[n+1]` is **what the wrap delivers**. Either the wrap's record body is sealed under
   the *previous* epoch's class key — which a **newly joined** member does not have, so the join case
   is unserved — or the X-Wing ciphertext is the seal and the record AEAD is a second layer over it
   under some other key. No document says which.
3. **The joining member's case is unserved either way**, which is Open item M1-2.

**What a ruling must state, so it can be implemented in one pass:** the wrap body's field list and
its framing (with an `alg_id`, per MASTER §7.1's rule that every hybrid ciphertext carries one); the
key the wrap record's `ct_body` is sealed under, stated separately for a continuing member and for a
joining one; and whether the X-Wing ciphertext sits inside the record body or replaces it.

- [ ] **Step 1 (after M1-1 is ruled): Derive the property and write the failing test**

  **Property 1 — every active device leaf gets exactly one wrap.** The scope question (R3a): the
  class is the leaves the **group** reports, through `GroupHandle.MemberAt`, not a list the caller
  passes. A fan-out over a caller-supplied list is a fan-out that silently omits.
  *Refusal owed:* a leaf with no `LeafKeysExtension` is a typed refusal, not a skip — §3.4 puts
  `0xF002` in `RequiredCapabilities` precisely so this cannot happen, and a member with no X-Wing key
  *"would silently lose history at the next commit"*.

  **Property 2 — a member finds its own wrap by computing its handle,** and finds no other. The
  server cannot invert `wrap_target_handle`; the member computes it.

  **Property 3 — the wrap round-trips through X-Wing and yields the exact `pq_secret`,** and a wrap
  built for leaf *a* does not open under leaf *b*'s key.

  **Property 4 — the epoch is bound.** A wrap for epoch *n+1* does not open as a wrap for epoch *n*.
  `wrap_target_handle` binds the epoch; assert that the **body** does too, or the ruling must say why
  it need not.

  **Property 5 — an omitted wrap is visible.** §5.11 step 4's `no_wrap` gap. And see **Open item
  M1-22**: a committer that omits one member's wrap while matching `expected_wrap_count` produces a
  group that is writable, self-consistent to the server, and **permanently unreadable** for the
  omitted member — the victim stays a full MLS member with a `no_wrap` gap forever, and §5.11 step 5
  authorises repair only for a committer that *died*, not one that *lied*.

- [ ] **Steps 2–6** as above, with mutations including: encapsulate to the wrong leaf; reuse one
  X-Wing ciphertext for two targets; omit the epoch from the body; drop a leaf from the enumeration;
  seal the wrap under the new epoch's class key when the ruling said the old one.

---

## Task 15: The epoch fan-out, the snapshot, and `expected_wrap_count`

**Files:**
- Modify: `connect/messagegroup/wrap.go`, `connect/messagegroup/wrap_test.go`

**Interfaces:**
- Consumes: Task 14's wrap builder; `GroupHandle.RatchetTreeSnapshot`; `message.EpochAttachment`,
  `message.EpochComplete`, `message.WrapTag`, `message.EncodeServerAttachment` (all landed);
  Task 11's `SealRecord`; Task 3's `WriteKey`/`ReadKey` producers.
- Produces: the publication sequence of §5.11 as one ordered operation, and the derived
  `expected_wrap_count`.

**The sequence, quoted whole, because its five steps are usually collapsed to three.** §5.11:

> 1. The server accepts at most one commit per `(group_id, epoch)`. On acceptance it sets
>    `current_epoch := n+1` and installs `write_key[n+1]` from the attachment, in the same
>    transaction.
> 2. The committer then submits, **as ordinary records at epoch `n+1`, MAC'd under
>    `write_key[n+1]`**: one device wrap per active device leaf (`WrapTag`, indexed by
>    `wrap_target_handle`), one recovery wrap per member (`RecoveryTag`, indexed by
>    `recovery_handle`), and the ratchet-tree snapshot (one `PERMANENT`-class record, `WrapTag` with
>    `leaf_index = 0xFFFFFFFF`).
> 3. The committer closes the fan-out with one `EpochComplete` marker record whose `wrap_count` MUST
>    equal the attachment's `expected_wrap_count`. Until that marker is accepted, the group is
>    **readable-but-not-writable**: the server returns `REASON_EPOCH_INCOMPLETE` to any non-wrap
>    submit at epoch `n+1`.
> 4. A member or device that finds no wrap for its target at epoch `n+1` after the marker has landed
>    surfaces a `gap` entry with reason `no_wrap`. It never fails silently.
> 5. If the committer dies mid-fan-out, the marker never lands, the group stays non-writable, and any
>    member may re-publish the missing wraps for epoch `n+1` (they are all derivable from the epoch
>    state every member holds) and submit the marker.

The server half is **already built and already enforcing this**: `msgrepo/store/contract.go` carries
`TheMarkerIsTheOnlyThingThatOpensAnEpoch` and returns `REASON_EPOCH_INCOMPLETE` to a non-wrap submit.
A client that does not publish wraps cannot send a second record.

**What this task can and cannot emit before M1-6 is ruled, stated because Task 11 refuses.** §5.11
step 2's snapshot is *"one **PERMANENT**-class record"*, and Task 11(a) makes `SealRecord` refuse
every non-`DURABLE` class until M1-6 lands. So **this task cannot emit the snapshot at all** until
M1-6 is ruled, and the ruling is a precondition of the task rather than a note beside it. Until it
lands, this task builds the device-wrap fan-out, the `EpochAttachment`, the marker and the ordering,
and holds the snapshot in the same deferral register as the recovery wraps (below), naming M1-6 as
the reason. Do not seal it under `DURABLE` "for now": the retention class is on the wire, inside
`AAD_head` and inside the `write_auth` preimage, and a snapshot written at the wrong class is
unrecoverable after A6 exactly as Task 11(a) says.

**A second measured fact about the snapshot, so it is not derived from the class ratchet.** Spec A
§5.11 E2 (spec line 1553, re-read after A-12) puts the snapshot under its **own** key —
`K_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 32)`, *"not a copy inside every wrap"* —
which is neither `ClassKeys.Perm` nor any `record_key[i]`. Task 3 does not derive it and no task in
this plan does. It is one `Expand` away from Task 3's helper; add it here, in `keyschedule.go` beside
its siblings, in the commit that first needs it, with the same distinct-label property Task 3
Property 4 states.

**`expected_wrap_count` is derived from the fan-out actually built, and never typed.** This is ledger
item 47's named trap. The field is defined as *"device wraps + recovery wraps + 1 snapshot"*; the
server can only check the marker against the attachment, so a client that defers recovery wraps
passes while diverging from the spec. **The count is computed from the records the builder emitted,
and a test asserts the builder's own inventory against §5.11's definition.**

**How the deferral is held, and it is not a red test.** The earlier form of this instruction had the
inventory test *"failing that test by name until Task 19 lands"* — which leaves the suite red across
Tasks 16, 17 and 18, against a Definition of done that requires `go test ./message/... ./mls/...`
green, and makes CP3b reachable with a red suite in which nobody can tell intended red from
regression. The tree already solves this exact problem, and the shape is
`entropyRefusalsHeldOutsideThisPackage` (`mls/crypto_test.go:7776`): **the class is derived and only
the answers are written down**, and the table is held to the class in **both** directions, so there
are three ways to fail and none of them is a stale label — *"a member with no row, a row with no
member, and a row naming a test that package does not declare."* Build the deferral the same way:

- the **inventory** is derived from the records the builder emitted, never typed;
- a table of **deferred wrap kinds** is written down, one row per kind, each row naming the task that
  lands it (`RecoveryTag` → Task 19; the snapshot → M1-6, then this task);
- the conformance assertion is `inventory + deferrals == §5.11's definition`, so a deferral cannot be
  forgotten and cannot be quietly widened;
- and the table is held in both directions: **a row whose kind the builder now emits fails**, so
  Task 19 cannot land without deleting its row, and a kind the builder omits with no row fails too.

That keeps the suite green through Tasks 16–18 while making the deferral impossible to lose, which is
what "a deferral the system cannot detect" was asking for. The comment in the test says which is
which, in the tree's own voice.

**The snapshot's rung, filed.** §5.11 says *"The snapshot exceeds the 64 KiB inline ceiling and is
therefore written by `wrap.go` as a blob-ref record (`size_bucket = 5`)"*, stated unconditionally
from the 500-member sizing. It is false for a two-member group, where the ratchet-tree snapshot is a
few hundred octets and fits `size_bucket 0` — and as written it drags the whole object-store path
(blob grant, upload, the non-expiring rung) in front of a two-client message. **Open item M1-23**,
with the recommendation labelled as one: the snapshot takes the smallest rung that fits, blob-ref
only above 64 KiB. Until it is ruled, this task builds the snapshot at the smallest rung that fits
and **refuses** — a typed refusal naming M1-23, in the same commit — if that rung is 5, so the blob
path cannot be entered silently. (A refusal rather than a red test, for the reason given above: a
test that is red on purpose is indistinguishable from one that is red by regression.)

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the order is the spec's order,** and the marker is last. Assert over the emitted
  record sequence, not over the builder's internals.

  **Property 2 — `expected_wrap_count` equals the number of records the builder emitted before the
  marker,** derived, and equals §5.11's definition. Two assertions, not one: the first is
  self-consistency and the second is conformance, and only the second catches a deferral.

  **Property 3 — every wrap record is an ordinary record at epoch `n+1` under `write_key[n+1]`,**
  and the commit itself is at epoch `n` under `write_key[n]`. The two keys are one epoch apart and
  swapping them is the defect this property exists for.

  **Property 4 — the `EpochAttachment` carries `write_key[n+1]` and `read_key[n+1]`,** both from
  `storage_root[n+1]`, both exactly 32 octets, and the attachment's `epoch` field equals
  `current_epoch + 1`. `attachment.go`'s width and alg-id checks are landed; this asserts the
  producer feeds them right.

  **Property 5 — an interrupted fan-out leaves the group non-writable, and is resumable exactly as
  far as §5.11 step 5 is actually true.** Assert the non-writability, and assert that resumption
  re-derives what it can rather than replaying stored bytes.

  **Property 6 — every reader of the provisional epoch value checks the destroyed flag first.**
  This is **the derived-class half of Task 13 Property 4**, landing here because this is the commit
  where the class first has a member. G10's own words are *"there is no path that reads it
  afterwards"*; Task 13 states the behavioural half — the value refuses every accessor once its
  destructor has run — and could not state this half, because measured at Task 13's commit the
  class of readers was **empty** (the readers are this task's fan-out and Task 21's retry loop, and
  neither existed), and the tree's house style fatals on an empty derived class rather than
  reporting clean over one. The scope question (R3a): the class is every function in this package's
  production source that reads a field of the provisional epoch value, derived off the syntax tree
  and never listed. **At this task's commit that class has at least one member** — this task's
  fan-out builder, which reads `pq_secret[n+1]` to build the wraps — and it gains Task 21's retry
  loop later. *Refusal owed:* a member that reads a field without first checking the destroyed flag
  fails, naming Task 13 Property 4 and quoting G10; the gate fatals if it finds no reader at all,
  in the house phrasing, so it cannot become vacuous through a refactor.

  **Do not assert step 5's derivability claim, because this plan elsewhere files it as false.**
  §5.11 step 5 says the missing wraps are *"all derivable from the epoch state every member holds"*.
  **M1-22 says why they are not:** `pq_secret[n+1]` is a fresh CSPRNG draw taken by the committer
  (Task 13) and delivered **only inside the wrap**, so a fan-out interrupted **before the first
  device wrap lands** is unrecoverable by *any* member — every member can derive `mls_secret[n+1]`
  from its own MLS state and none of them can compute `storage_root[n+1]`. The derivability holds
  only from the point where some member has opened a wrap, and it holds for that member alone until
  it re-publishes. A plan must not instruct an implementer to assert what it files as broken twelve
  pages later, and the earlier form of this property did.

  So the property splits, and the split is the finding:

  - **resumable case** — at least one wrap for epoch *n+1* has landed and this member opened it: the
    remaining wraps are derivable and re-publication is asserted, which is step 5 at the scope where
    it is true;
  - **unrecoverable case** — the marker never landed and **no** wrap did: assert the group is
    non-writable and that this member **refuses**, with a typed error naming M1-22, rather than
    republishing a fan-out under a `pq_secret` it sampled itself. A member that resamples here forks
    the storage layer under a valid MLS epoch — the same silent fork M1-21 names on the other path,
    reached from a different direction.

  That second case is the one worth the test. It is also the strongest evidence for M1-22's
  recommendation, so record the measurement in the commit message.

- [ ] **Steps 2–6** as above, with mutations including: emit the marker before the last wrap; type
  the count as a literal; count the snapshot twice; MAC a wrap under `write_key[n]`; put the
  `EpochAttachment` on a non-commit record (the landed `attachment.go` must refuse it and the test
  must prove it does); set the attachment's epoch to `n`; read `pq_secret[n+1]` off the provisional
  epoch value without checking the destroyed flag, which Property 6 exists to refuse; and add a
  second reader of that value with no check, which the derived class must catch without being
  edited.

---

## Task 16: The joining member — **BLOCKED on Open item M1-2**

**Files:**
- Modify: `connect/messagegroup/session.go`, `connect/messagegroup/wrap.go`,
  `connect/messagegroup/doc.go`
- Test: `connect/messagegroup/join_test.go`

**Interfaces:**
- Consumes: Task 9's **`GroupEngine`**`.JoinFromWelcome(welcome, ratchetTree []byte) (GroupHandle,
  error)` — §6 puts it on `GroupEngine`, **not** on `GroupHandle`, which is where an earlier draft of
  this line spelled it; read the block at spec lines 1885–1896 before writing the call (R2, and this
  was an R2 failure inside the plan that states R2). Task 9a's `connectMlsEngine` is the
  implementation. Also: Task 15's fan-out; Task 4's handles.
- Produces: the joining path — a `GroupSession` constructed from a `Welcome` rather than from a
  founder's own state.

**Why this is blocked.** MASTER §8 and Spec A §5.7 both say the joiner receives `group_handle_key`
and its joining epoch's `read_key` *"in the `Welcome`"*:

> `group_handle_key` […] is delivered to a joining member in its `Welcome` alongside the
> group-context extension, and is not derivable from any later epoch's `storage_root`. A member that
> does not hold it cannot compute its own handle and therefore cannot write.

**No mechanism carries them.** Measured: `grep -rn 'group_handle_key\|GroupHandleKey'` over the whole
of `connect` returns **0**; `extension.go` declares three URmessage extension types (`0xF001`
group policy, `0xF002` leaf keys, `0xF003` owner successor) and none of them is this; RFC 9420's
`Welcome` carries a `GroupInfo` and a `GroupSecrets` and neither has a free-form slot for it. And the
joiner needs one thing more that neither sentence mentions: `group_handle_key` is
`HKDF-Expand(storage_root[0], "gh/v1", 32)` and `storage_root[0]` requires **epoch zero's**
`pq_secret`, which the joiner never had and which no wrap at its joining epoch carries.

**Open item M1-2.** A ruling must name the carrier (a `GroupInfo` extension is the only slot in the
v1 profile that is both authenticated and encrypted to the joiner), state what it carries
(`group_handle_key` and the joining epoch's `read_key` at minimum), and say how it is validated —
because a `group_handle_key` a joiner accepts from an unvalidated field is a `sender_handle` an
attacker chooses, and `sender_handle` is inside every AAD and every MAC in the system.

**And the second half of the same hole, already filed elsewhere.** CP3b also needs the founder to
hold the joiner's MLS `KeyPackage` before it can propose the `Add`, and needs the `Welcome` to reach
the joiner at all. Neither has a channel: ledger open items **44** and **44a**, written up as
proposal 1 in `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md`. That review also
names the legitimate short circuit for CP3b specifically — an **in-process, test-only, gated**
hand-off of a public `KeyPackage` and an already-sealed `Welcome` — and the discipline it must be
taken under: *"It is a deferral of first contact, not of privacy, and it must be named as such or
CP3b will be mistaken for a product."* This task takes that short circuit **only** if it is gated the
way CP3a's key source was, and the gate is part of the task.

- [ ] **Step 1 (after M1-2 is ruled): Derive the property and write the failing test**

  **Property 1 — a joined session computes the same `sender_handle` for a given leaf as the founder
  does.** This is the property the whole item is about, and it is one assertion.

  **Property 2 — a joined session opens a record the founder sealed,** at the joining epoch, and
  the founder opens one the joiner sealed.

  **This is not CP3b, and the previous version of this line said it was.** It is an in-process
  exchange between two `GroupSession`s over two real `mls.Group`s: real key schedule, real
  `Welcome`, no server. CP3b's own definition adds *"through the message server"*, and nothing in
  this plan submits — see the CP3b-line section above and **Open item M1-42**. Calling this the
  milestone here would be the identical error Task 12 Property 2 warns against, two tasks later and
  one leg short, and it is the error a reader is most likely to make because everything else on the
  path is real by this point. State the residue in the test's own comment: *what is missing is the
  transport, and the transport belongs to a plan that does not exist.*

  **Property 3 — the carrier is authenticated.** A modified `group_handle_key` in transit is
  refused, not accepted with a different handle.

  **Property 4 — the test-only first-contact path is unreachable from a non-test build,** asserted
  the way CP3a's key source is: a gate over the tree, with a positive control.

- [ ] **Steps 2–4** as above.
- [ ] **Step 5: Mutation-test.** This task stated four properties and **no mutation at all** until
  the 2026-09-06 pass, which is R1's own subject one layer up: four sentences that read like
  guarantees with nothing stated that would make any of them fail. Being blocked on M1-2 is not a
  reason to state no mutation — the mutation set is what the ruling gets implemented against.
  1. Compute the joiner's `sender_handle` from its own leaf and a locally derived
     `group_handle_key` rather than the one the carrier delivered — Property 1 must fail, and this
     is the mutation the whole task exists for.
  2. Accept the carrier's `group_handle_key` without validating it — Property 3 must fail.
  3. Truncate or pad a delivered `group_handle_key` of the wrong width instead of refusing it —
     Property 3 must fail.
  4. Open a record sealed at the joining epoch under the founder's epoch rather than the joiner's —
     Property 2 must fail.
  5. Reverse the direction: have only the joiner open the founder's record and not the founder the
     joiner's — Property 2 must fail, because a one-directional exchange is the half that hides a
     handle-derivation asymmetry.
  6. Remove the test-only gate from the first-contact short circuit, or reach it from a non-test
     build — Property 4 must fail, and it must fail the way CP3a's key-source gate fails, over the
     tree and with a positive control.
  7. Call this milestone CP3b in `PROGRESS.md` while no submit path and no durable reserver exist —
     Property 2's stated residue must refuse the claim; those are legs 4 and 5 of the Definition of
     done and both are outside this plan.
- [ ] **Step 6: Commit.** This task also rewrites `doc.go`'s inventory paragraph a second time, and
  updates `PROGRESS.md` in `msgrepo` — CP3b is a milestone and its claim belongs in the file that
  defines it.

---

# Wave 3 — off the CP3b path, required before the A6 format freeze

§13 puts the wire-format freeze at slice A6 and the README's slice table says slice 2 *"freezes the
wire format"*. Everything below is inside that freeze and outside CP3b. None of it is required to put
a message in front of a person; all of it is required before the format stops moving.

## Task 17: `eph_root`, `EphKey`, and the property that is easiest to break

**Files:** create `connect/messagegroup/eph.go`; test; modify `entropy_test.go` and
`mls/crypto_test.go` (Gate B, same commit).

**Interfaces:**
- Produces: `func NewEphRoot(rand io.Reader) ([]byte, error)`,
  `func EphKey(ephRoot []byte, bucket uint8, window uint64) []byte`.

**The formula is in MASTER, not in Spec A.** §5.3 declares `EphKey` with no derivation. MASTER §8.1:

> ```
> └─ eph_root[n]  = 32 B fresh CSPRNG at commit  ← NOT derived from storage_root (I4)
>      └─ K_eph[n][b][t] = HKDF-Expand(eph_root[n], "eph/v1" ‖ u8(b) ‖ u64(t), 32)
> ```

**`window` is still undefined and that is the gap.** MASTER writes `u64(t)` and says `eph_root` is
*"time-sliced by window `t`"* — and never gives `t`'s origin, its unit, whether it is
`floor(now / eph_bucket_seconds[b])`, or which clock. §2.2 assigns *"eph_root, buckets, window
expiry"* to `eph.go`. **Open item M1-27**, wire-visible, blocks A6.

**The properties this task owes** are §5.3's own, with one correction. §5.3 asks for
`TestEphRootHasNoDurableInput` to assert *"by reflection that no exported function in the package
returns eph key material from arguments that include a `storageRoot`"*. **Go reflection sees neither
parameter names nor the meaning of returned bytes.** Build it the way this tree has already built the
same class twice: an AST scan plus a required-row table with a positive control, exactly like
`entropy_test.go` and `crypto_forbidden_test.go`. It is a **named release gate for slice A6**
(§13), so it cannot be left vague. **Open item M1-17.**

Mutations include: derive `eph_root` from `storage_root`; add an `Eph` field to `ClassKeys`; drop the
bucket from `EphKey`'s info; drop the window; make `NewEphRoot` take a seed.

## Task 18: The recovery proof, and the gate it breaks

**Files:** create `connect/message/recovery.go`; test; modify `connect/message/writeauth_test.go`'s
gate header.

**This file stays on the server side and it is the one place the surface test and the "client half"
instinct disagree.** §12.1 publishes **both** `RecoveryProof` and `VerifyRecoveryProof`, and Spec B
§12.1 restates that block character for character, so `recovery.go` lands in `connect/message`
where a server held to the published surface can reach it — Task 18's own note that Spec B's
`RecoveryFetch` handler cannot compile until they land is the reason. It costs nothing: the file
imports `crypto/ed25519` and `crypto/hkdf` and never `connect/mls`. What it does surface is that
§12.1's own sentence *"The server gets verifiers and no signers"* is contradicted by
`RecoveryProof` being on the block beside it. That contradiction predates this ruling and the split
makes it visible rather than causing it: after the split the natural home for a signer is
`connect/messagegroup`. **Open item M1-47**, filed, not resolved.

**Interfaces:**
- Produces: `RecoveryProof`, `VerifyRecoveryProof` — both on §12.1's published surface, so Spec B's
  `RecoveryFetch` handler cannot compile against that surface until they land.

**The derivations, quoted from §5.7:**

> ```
> recovery_root      = HKDF-Expand(master_key, "recovery/v1", 32)              (unchanged)
> recovery_handle    = HKDF-Expand(recovery_root, "idx/v1", 16)                (unchanged)
> recovery_sig_seed  = HKDF-Expand(recovery_root, "idxsig/v1", 32)             (NEW)
> recovery_sig_sk    = Ed25519 private key from recovery_sig_seed
> recovery_verify_pub= Ed25519 public key of recovery_sig_sk                   (32 B)
>
> recovery_proof = Ed25519(recovery_sig_sk,
>                    "URmessage/v1/recovery" ‖ LP(server_nonce) ‖ LP(recovery_handle))
> ```

**Three things this task must handle rather than trip over.**

- **It is a raw preimage, not an MLS-labelled one.** Do not route it through `mls`'s signer.
- **`RecoveryProof` takes two sources for one value.** `recovery_handle` is derivable from
  `recovery_root`, which is already a parameter, and nothing requires the function to check they
  agree. This is the hazard `AADHead` and `WriteAuthPreimage` already refuse in the attachment case
  (`ErrServerAttachmentMismatch`, refused in **both** directions). Here the consequence is worse than
  a failed AEAD: §5.7 makes the server store `recovery_verify_pub` trust-on-first-use and *"REFUSE
  any later differing `recovery_verify_pub` for the same `recovery_handle` **within that group**"*, so
  a caller pairing one identity's handle with another's root writes a poisoned TOFU row and
  **permanently denies its own restore for that group**. **Open item M1-28**: either derive the
  handle inside and drop the parameter, or refuse the mismatch explicitly. Do not choose silently.
- **It breaks Gate C, and the gate is right.** `VerifyRecoveryProof` joins the derived `Verify*` class
  the day it is declared and fails two of Gate C's four rules — its body calls `ed25519.Verify`
  (rule 3) and it reaches no `subtle.ConstantTimeCompare` (rule 4). **Open item M1-19.** Amend the
  gate by **restating its property**, not by exempting a name: rules 3 and 4 are about *verifiers
  that decide equality themselves*, and a signature verifier delegates that decision to a
  constant-time primitive. Whatever shape the amendment takes, the class stays derived and the
  positive control stays.

## Task 19: The recovery wrap and the archive secret

**Files:** modify `wrap.go`, `wrap_test.go`; **delete this task's row from Task 15's deferral
table**, in this commit. Task 15's table is held to the derived inventory in both directions, so a
row whose kind the builder now emits fails — which is what makes the deletion an obligation rather
than a courtesy, and is why Task 15 holds the deferral in a table instead of in a red test.

**The correction, quoted from §5.10 E1**, because implementing the pre-correction variant is exactly
what §5.10 exists to prevent:

> The **recovery** wrap carries `storage_root[n]` and `archive_secret[n]`, not `pq_secret[n]`. A
> seed-only restorer has no MLS state and therefore no `mls_secret[n]`, so a wrap carrying
> `pq_secret` would open nothing. The **device** wrap is unchanged and still carries `pq_secret[n]`
> and `eph_root[n]`.

and MASTER §8.2: `archive_secret[n] = sender_data_secret[n] ‖ encryption_secret[n]` — *"Those two
named secrets — **not** the exporter output, which cannot regenerate its siblings, and **not**
`epoch_secret`, which would also expose `confirmation_key` and `membership_key`."*

**What `GroupHandle` actually exposes, corrected.** The earlier version of this paragraph said the
interface *"exposes exactly `SenderDataSecret()` and `EncryptionSecret()` and nothing else"*. It does
not: §6's block is **23 methods** (Task 9's table enumerates them), and four tasks' Consumes lines
depend on the others — Task 10 on `OwnLeafIndex` and `Export`, Task 14 on `MemberAt`, Task 15 on
`RatchetTreeSnapshot`, Task 16 on the join path. The true claim, which is the one G6 makes and the
one this task rests on, is narrower and survives: **of the epoch's secrets, `GroupHandle` exposes
exactly those two, and reaches no third** — `epoch_secret`, `confirmation_key`, `membership_key`,
`init_secret` and the whole of `EpochSecretName` are unreachable from `connect/message`, because
`EpochSecret(name)` is deliberately **not** on the interface and only Task 9a's adapter names it.
Task 9 Property 1's closure gate is what holds that, and this task's own property is that
`archive_secret` is built from those two methods and from no other source.

## Task 20: `blob_id`, the object padder, and the MIME authority

**Files:** create `connect/messagegroup/blob.go`; test.

**Interfaces:** produces `blob_id = HKDF-Expand(record_key[i], "blob/v1", 32)`, the 262,144-octet
padder, and the content sniffer.

**Gate C would read this file, and after the split it does not — which is worse, not better.**
`TestNoProductionFunctionComparesDataOutsideConstantTime` (`writeauth_test.go:2473`) runs over
**every function in the package** whose directory `authScanDir` names, and `authScanDir = "."` names
`connect/message` alone. `blob.go` is now in `connect/messagegroup`, so unless `messagegroup` gets
its own copy of Gate C (the Gate C row of the constraints table) this task's sniffer lands
**ungated**. The rest of this note is written as though the gate reads it, because it must. It runs
over — its own comment says the files are *"every production file of
the package, because the scan reads the directory rather than three names"* — and its comparator
class is derived from the files' own imports. A content sniffer is a comparison of magic-byte
prefixes against a table, which is exactly what that gate refuses, and this plan works Gate C's
consequence only for the `Verify*` class (M1-19). **This task and Task 24 are the other two
members**, and neither is a signature verifier, so M1-19's amendment does not cover them.

The property is right and the sniffer is not secret data: a MIME magic number is public, the input
is a plaintext body the caller already holds, and there is no tag and no key. But the gate cannot
know that, and the answer is **not** an exemption — the package already chose the other one, and
`crypto/subtle` is what its two attachment comparisons are spelled with, which is why the rule needs
no exemption today. Two shapes close it and the task must take one deliberately: spell the sniff's
comparisons with `subtle.ConstantTimeCompare` (correct, marginally slower, and keeps the gate with
zero exemptions), or restate the gate's class as *comparisons of secret-derived data* and derive
**that**, which is a harder derivation and the same repair M1-19 and M1-35 ask for on the other two
guardrails. **Open item M1-45**, filed rather than resolved; it should be ruled together with M1-19,
because a third separate answer to the same guardrail is how a gate becomes three sentences.

**§5.13's own claim is vacuous on the blob rung and this task must not pretend otherwise.** §5.1
defines `BodyHash` as `H(CtBody)`, and for `size_bucket = 5` `ct_body` is **absent** — enforced by
the landed `codec.go:checkRecord`. §5.13 nevertheless claims *"a record whose body was never
downloaded is still a complete, verifiable record: `ct_head`, `body_hash` and `blob_id` are retained
and checked exactly as for a downloaded one."* If `body_hash = H(nil)` it is a constant on every blob
record and binds nothing; if it is meant to be `H(blob_ciphertext)` no document says so. `write_auth`
covers `blob_id` and not one octet of the object. **Open item M1-24**, wire-visible, blocks A6.

Also: §5.13 makes `connect/message` the MIME authority — *"`connect/message` sniffs the content
itself and uses its own result whenever the two disagree; an empty hint is legal and means 'sniff
it'"* — and the type travels **inside** the encrypted body, never on the wire.

## Task 21: §5.12's losing committer, in full

**Files:** create `connect/messagegroup/commitretry.go`; test.

**The seven steps are quoted in §5.12 and are normative; transcribe them from the spec, not from
this plan.** Two things this task owes beyond transcription:

- **The back-off is fixed and stated:** *"full jitter, base 250 ms, cap 8 s, maximum 5 attempts, then
  surface a failure."* An injected clock, per the house rule.
- **The ambiguous outcome, which is the most expensive finding in this plan's Open items.** §5.12
  binds to *"any rejection of a commit submission"* and orders the committer to discard
  `storage_root[n+1]` and resample `pq_secret[n+1]`. **A connection drop or a timeout after the
  server committed is not a rejection** — but the implementer has no other rule, and step 7's
  back-off loop is exactly where a timeout lands. If the commit was in fact accepted,
  `pq_secret[n+1]` **is** epoch *n+1*'s real secret, it **is** inside the wraps every other member
  will open, and resampling produces a `storage_root[n+1]` that no other member computes — a silent
  per-member fork of the storage layer with a valid MLS epoch underneath. §5.7 leans on the §6.1 step
  (0) idempotency claim to make replay safe, but step 2 deliberately makes the retry a **different**
  commit, so idempotency cannot catch it. **Open item M1-21**: §5.12 needs an explicit step 0 — an
  unknown outcome is not a rejection, and is resolved with `GroupStatus` before steps 1 and 2 run.
  **Steps 3 and 7 are also the ordinary "the other client committed first" path and can land with
  CP3b; steps 1, 2, 4, 5 and 6 wait — but the ambiguous-outcome ruling should be taken first,
  because getting it wrong forks the schedule silently and no test in this plan would catch it.**

## Task 22: Contact cards

**Files:** create `connect/messagegroup/card.go`; test; Gate A amendment.

**Interfaces:** produces §5.14's card derivations (`card_root`, `card_seed[k]`, `token[k]`,
`card_xwing[k]`, `collect_sig_seed[k]`) and the 131-octet card encoding with its four-octet checksum.

Nothing here needs new KEM code: §5.14's `XWing.KeyGen` is `message.XwingKeyGenFromSeed`, landed.
This task is **the most separable workstream in the plan** — its only dependency is X-Wing and it
touches no group state at all. **Open items M1-31** (the unannotated `HKDF-Extract`), **M1-32** (the
client half has no declarations at all) and **M1-38** (`collect_verify_pub`'s derivation is never
stated) all bind here.

## Task 23: The rendezvous

**Files:** create `connect/message/rendezvous.go` **and** `connect/messagegroup/rendezvous.go`;
tests for both; Gate A amendment naming **both** paths; Gate C amendment in `connect/message` (five
more `Verify*` functions — see M1-19).

**This is the second of the plan's two genuinely both-sides files, and the line between them is
§12.1's, not taste.** `connect/message/rendezvous.go` holds exactly what §12.1 publishes and Spec
B §12.1 restates character for character: `RendezvousId`, `DepositVerifyKey`,
`RendezvousRegisterPreimage`, the five `VerifyRendezvous*`, `RendezvousDepositBytes`, and the two
types. `connect/messagegroup/rendezvous.go` holds what §12.1 publishes none of and what could not
live on the server side even if it did: the **sealed deposit**, which §5.14 seals under X-Wing to
the card's KEM key, and X-Wing is in `connect/messagegroup` because it is the file that carries the
`connect/mls` edge. The five signers go with it, over `connect/message`'s preimages, which they
call across the package boundary — that call is the point: one preimage builder, two callers, the
same shape the record codec already has.

**Interfaces:** `connect/message/rendezvous.go` produces §5.14's five signature preimages and
§12.1's nine published rendezvous functions plus `RendezvousRegistration` and
`RendezvousCollectParams`. `connect/messagegroup/rendezvous.go` produces the sealed deposit at
exactly 5,238 octets and the client's five signatures over the preimages above.

**Open items M1-29** (`DepositVerifyKey(token)` is on the server's surface in the block that ends
*"The server gets verifiers and no signers"*, and a token yields the deposit **signing** key one
label away), **M1-30** (every holder of a card shares one deposit signing key, so one holder can fill
the mailbox and the server cannot tell depositors apart), **M1-33** (the deposit's AEAD, its nonce
width and `H()` are never named), **M1-34** (the deposit body can overflow its own 4,094-octet
padding with no stated behaviour), **M1-35** (G7 enumerates three bool-returning verifiers and §12.1
publishes five more) and **M1-39** (`request_sig` is the only §5.14 signature not nonce-bound, and
the section does not say why) all bind here — six items, of which **M1-33 and M1-34 are
wire-visible** and the other four are surface or availability findings.

**§13 puts §5.14 in A6 explicitly**, with the reasoning that it uses existing classes and existing
transport paths so none of it is a format break, *"but all must land before the format freezes here
rather than with the client work that renders them"*. The flows themselves (§7.3b) land in A7.

## Task 24: The `REACTION` body, tombstones and `COVER`

**Files:** create `connect/messagegroup/reaction.go`; test.

**Gate C would read this file too, for the same reason Task 20's would, and after the split neither
is read — see M1-45 and the Gate C row of the constraints table.** Validating *"every
codepoint drawn from the emoji set of the pinned Unicode version"* is a membership test against a
table, and `TestNoProductionFunctionComparesDataOutsideConstantTime` derives its comparator class
from the file's own imports, so `slices.Contains`, `strings.Contains` and `bytes.Equal` are all in
it the moment they are imported. Take the same decision this plan asks Task 20 to take, and take the
same one — two different answers in two files is worse than either answer.

§5.1's `REACTION` requires *"exactly one extended grapheme cluster, and every codepoint drawn from
the emoji set of the pinned Unicode version"*, validated **on send and on receipt**, failing to a
gap with reason `"malformed"`. Go's standard library provides no UAX #29 segmentation, so this is a
dependency decision — a new module, or a hand-rolled subset plus the pinned Unicode version's tables
— that has nothing to do with the record layer. **Open item M1-41.** It is last for that reason.
Tombstones and `COVER` land here too; `pad.go`'s size-bucket ladder is already in `record.go` and
`codec.go`.

---

## Execution order

```
Wave 0  the split                                                  (not this plan's commit)
Wave 1  1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 9a → 10 → 11 → 12     (CP3b prefix, unblocked)
Wave 2  13 → [14: needs M1-1] → [15: needs M1-6] → [16: needs M1-2] (CP3b, blocked)
Wave 3  17, 18, 19, 20, 21 | 22 → 23 | 24                          (A6 freeze; the three groups are parallel)
```

**Wave 0 is one commit in the `connect` tree and it is not this plan's.** It creates
`connect/messagegroup`, moves `xwing.go`, `xwing_errors.go` and `entropy_test.go` into it, adds
`"../messagegroup"` to `mls/crypto_forbidden_test.go`'s `forbiddenScanRoots` (which fixes Gate B in
the same line), adds the root to `record_test.go`'s `joinScanRoots`, and gives `messagegroup` its
own `doc.go` and its own copy of Gate C. Nothing in wave 1 is blocked on it — every task below can
be written against either package layout, because the split changes which directory a file lands in
and not what it does — but **`msgrepo`'s suite stays red until it lands**, and a wave-1 task that
creates `keyschedule.go` in `connect/message` because `connect/messagegroup` does not exist yet has
put a key schedule in the package the server links, which is the whole thing the ruling forbids. So:
either wave 0 first, or wave 1 in a branch that rebases onto it.

Tasks 1 and 2 are independent of each other and of everything else; either can start first. Tasks 9
and 9a depend on nothing else in this plan and can be pulled forward as a pair if a second
implementer is free — they are the other separable start, and 9a must not be separated from 9,
because 9 without 9a is an interface nothing implements. Tasks 22–23 depend only on X-Wing, which is
landed, and are the largest block that can run entirely in parallel with waves 1 and 2.

**Three rulings gate the schedule and none is this plan's to make.** M1-1 (the wrap's encoding and
seal) and M1-2 (the joiner's channel) sit between Task 13 and CP3b. **M1-6 joins them**, because
Task 11(a)'s refusal of every non-`DURABLE` class blocks Task 15's `PERMANENT` snapshot — a wave-1
refusal blocking a wave-2 task, which is why M1-6 moved out of the A6-freeze section. Everything in
wave 1 is buildable and testable without any of the three, and a wave-1-complete tree is a
`connect/message` that seals and opens records under the real key schedule inside one process —
which is worth having and **is not CP3b**.

---

## Definition of done

**For the plan:** **25 tasks committed — the 24 numbered ones and Task 9a** — `go build
./message/... ./messagegroup/... ./mls/...` green, `go vet` clean, and
`go test ./message/... ./messagegroup/... ./mls/...` green — the last of those is not optional,
because five of this plan's constraints fail in `mls`'s suite and a `message`-only run reports clean
over them. **After the split a `messagegroup`-only run reports clean over the other four**, which is
the same failure one directory over, and it is why all three roots are named here rather than two.

**And one more thing has to be green, in the other repository:**
`go test ./ -run TestEveryDependencyOfThisModuleIsOneSpecB22Allows` in `msgrepo`. It is **red today**
and it is red for the reason the ruling section states, not for anything a task below does. What
turns it green is wave 0's commit in `connect` — measured, against a working copy with the split
applied, with no edit to `msgrepo/deps_test.go` and none to spec B. Until then, do not add
`connect/mls` to that allow list, do not skip the test, and do not mark it as a known failure: it is
the only place a new dependency of the message server is looked at, and this is exactly the
occasion it exists for.

**Green means green at every commit, and no task may leave an intentionally red test behind.** Task
15's deferral of the recovery wraps and of the snapshot is held by a required-row table rather than
by a failing assertion, for the reason stated there: a suite that is red on purpose across three
tasks is a suite in which nobody can tell an intended red from a regression, and CP3b would then be
reached over one.

**For CP3b, which is the milestone this plan exists to reach and is not the same as the plan being
done:** a test in which two `GroupSession`s, over two real `mls.Group`s joined by a real `Welcome`,
exchange one `DURABLE` text record **through the message server**, with `storage_root` computed from
`HKDF-Extract(mls_secret, pq_secret)` on both sides, with no test-only key source anywhere on the
path, and with the first-contact short circuit — if taken — named and gated.

**That is tasks 1–16 and 9a, plus six legs outside this plan, and two of the six are owned by a
plan that does not exist yet.** The list has been short three times. The first version named two,
both inside `connect/mls`, which left the words *"through the message server"* unserved by anything.
The 2026-09-05 repair named four — and in the same pass deleted Task 6's production
`StreamIndexReserver` implementation, leaving the interface and a test-only fake, **without adding
the implementation to this list**; that deletion's own consequence became leg 5. The 2026-09-06
ruling adds leg 6, which is the split itself: it is one commit in `connect`, it is not this plan's,
and until it lands `msgrepo`'s dependency gate is red. An exhaustive list that is not exhaustive is
worse than a list that does not claim to be.

**Two of the six now have an owner they did not have.** The owner has ruled that the client-side
submit leg is an **sdk plan, `s2`** — on the reasoning that `sdk` already owns transport and
storage, and that §8.2's `MessageStore` already declares `ReserveStreamIndex` and `StreamHighWater`,
which is `message.StreamIndexReserver` method for method. So legs 4 and 5 are both `s2`'s. **`s2`
does not exist yet, and it is now on the CP3b critical path** — it is the last unwritten thing
between a `*Record` in memory and a person reading a message.

1. `connect/mls` **p2 Tasks 19–20** — **landed**, verified in `message/xwing.go` (which becomes
   `messagegroup/xwing.go` at leg 6; the verification does not move with it).
2. `connect/mls` **p7 Tasks 7–13, 15, 16, 18, 19 and 22** — the group lifecycle the two real
   `mls.Group`s and the real `Welcome` come from.
3. **s1**, for the declarations CP3b's client half is written against, per the 2026-09-02 chain
   review's one-line chain: *"p2 Tasks 19–20 → p7 Tasks 7–13, 15, 16, 18, 19, 22 → m1 → s1 → two to
   four sdk plans that do not exist → CP3b."*
4. **The client-side submit leg — the transport binding, a send path and a receive path —
   **owned by `s2`**, an sdk plan that has not been written. This plan does not touch `sdk` and
   produces no `Submit` call; the server side needs nothing new (chain review, leg 3, verified
   against `msgrepo/store` and the api layer); and `msgrepo/harness` is `msgrepo`-local, gated
   test-only, and *"does not encrypt"* by its own doc comment. **M1-42 is closed as owned**, ruled
   2026-09-06: the owner assigned it to `s2` on the reasoning that `sdk` already owns transport and
   storage. What `s2` owes this leg: the `connect.Client` binding of §10, a send path that calls
   `messagegroup.GroupSession.SealRecord` and submits the `*Record` it returns, and a receive path
   that fetches and calls `OpenRecord`. It is no longer the largest open item here; it is a plan
   that has to be written, and it is on the CP3b critical path.
5. **A durable `StreamIndexReserver` implementation — also `s2`'s**, which Task 6 declares the
   interface for and deliberately does not build: neither half of the split imports an I/O package,
   §8.2 assigns the persistence to `sdk`'s `MessageStore` (`ReserveStreamIndex` /
   `StreamHighWater`, method for method), and what Task 6 ships is the interface plus a file-backed
   fake confined to `streamindex_test.go`. **O-5 is answered**: `s2` inherits Task 6's interface,
   its five properties and its mutation set whole, `TestStreamIndexNeverReused` included. **CP3b says *"no test-only key source anywhere on the path"*, and a
   test-only reserver is not a key source — but it is the thing standing between a reused
   `stream_index` and a reused nonce under a reused `record_key`, which §5.6 calls *"a total break
   of both AEADs for that record"*.** A CP3b run over the test fake proves the record layer and not
   the client. This leg is asked of the sdk store plan as **O-5**; s1 files that plan as **S1-9**,
   *"blocks s2 entirely"*, and it is unwritten. **M1-5**'s keying question must be ruled before it
   has rows on disk, because it is the one piece of durable state that cannot be migrated by
   recomputation.

   *The alternative, stated so the choice is visible rather than defaulted:* give Task 6 back a
   production implementation in `connect/messagegroup` and argue the layering — which means putting
   `os` and a file format into a package whose whole production import set is
   `crypto/{sha256,subtle,hkdf,hmac,ecdh,mlkem,sha3}`, `fmt`, `io`, `mls`, `mls/syntax` and
   `connect/message`, and accepting a second durable implementation beside §8.2's. **This plan does
   not take it**, and the 2026-09-06 ruling closed the question by naming `s2` the owner; Task 6
   states the reason and requires a ledger entry against §8.2 before anyone reopens it.
6. **The split itself** — one commit in the `connect` tree, described as wave 0 in the execution
   order above. Until it lands, `msgrepo`'s
   `TestEveryDependencyOfThisModuleIsOneSpecB22Allows` is red and the message server links an MLS
   parser. It is the only leg of the six that is red **today** rather than merely absent, and it is
   the cheapest: two files moved, one scan root added, one package created.

A wave-2-complete tree with legs 1–3 and leg 6 done reaches *two sessions exchange a private record
in one process over a real join, over a reserver that does not ship*. That is two legs short of
CP3b — the submit path and the durable reserver, both `s2`'s — and Task 16 Property 2 says so at
the point where somebody would otherwise declare it.

**Gate obligations, restated so they are checkable, and every one of them now has a *root* as well
as a rule:** every new file is inside Gate C's scan — which after the split means `connect/message`
alone unless `connect/messagegroup` gets its own copy, so "inside Gate C's scan" is an obligation on
wave 0 before it is an obligation on any task here — and must
contain no variable-time comparator; every new `hkdf` entry point has its Gate A allow-list entry and
its nested control twin in the same commit; every new entropy-taking function has its Gate B row, its
probe, and both refusals in the same commit; `doc.go`'s inventory paragraph is accurate at the end of
Tasks 12 and 16; and `SPEC-LEDGER.md` gains an edit-log entry per this repository's standing rule.

---

## What this plan does not close

- **It does not reach CP3b on its own.** Wave 1 ends with a package that encrypts; CP3b needs
  wave 2, and wave 2 needs two rulings. Saying so is the point of the wave boundary.
- **It does not close the first-contact hole.** Ledger items 44 and 44a — no key-package fetch by
  principal, and no channel for the `Welcome`. Task 16 takes a gated short circuit for a test; the
  product needs proposal 1's ruling.
- **It does not touch `sdk`.** `GroupEngine` is declared here — in `connect/messagegroup` after the
  ruling, and Task 9a's adapter with it, because §2.2's tree pairs the two in one file and because
  the adapter is the implementation that needs `stagedRef` (M1-43, whose earlier claim that
  `stagedRef` confines *every* implementation was false); its **factory** is s5's, and s5's return
  type changes from `message.GroupEngine` to `messagegroup.GroupEngine` with the split. The gap
  between "two `GroupSession`s exchange a record" and "a person types a message" is s2–s10 and Spec
  C's wiring — and the first step of that gap, the client-side submit path, is **inside CP3b**
  rather than beyond it. That was M1-42, which the 2026-09-06 ruling **closed as owned**: it is
  `s2`'s, `s2` is unwritten, and it is on the CP3b critical path. This plan's Definition of done
  names it as an external leg; and that distance is measured in
  `docs/reviews/2026-09-02-cp3b-chain-and-three-amendment-proposals.md`.
- **It does not perform the split it is now written against.** `connect/messagegroup` is created by
  one commit in the `connect` tree, wave 0 in the execution order, and this plan owns none of it.
  What this plan does own is being written for the tree that commit produces rather than the one it
  replaces, so that no task lands a key schedule in the package the server links.
- **It does not freeze the wire format.** **Six** of the 48 open items below are marked
  *wire-visible* — M1-6, M1-7, M1-8, M1-24, M1-27 and M1-33 — and each must be ruled before A6
  closes. That is a count of the items carrying the label, not a claim that the other 39 are
  format-safe: M1-1, M1-2 and M1-6 change bytes on the wire too, and the first two are labelled by
  what they block instead. This plan files all of them; it decides none. The three items added on
  2026-09-06 — M1-46, M1-47, M1-48 — are none of them wire-visible: all three are placement and
  surface questions the split raised.
- **It does not re-specify anything `connect/mls` already built.** The exporter, the secret tree's
  design, X-Wing, the syntax codec and the HKDF wrappers are consumed, not rewritten. Where a second
  implementation would have been the easy path — the record AEAD, the skipped-key window, Ed25519 —
  the reason it is not reuse is stated at the consumption site rather than left to be rediscovered.

---

## Open items

**None of these is resolved here.** Each states the problem, what it blocks, and — where there is
one — a recommendation **labelled as a recommendation**, with the rejected alternative named. This
project has twice had an implementer discover that a plan silently chose; every one below is filed.

**Forty-eight items, of which one is closed.** Four were added by the 2026-09-05 repair — M1-42
(the submit leg), M1-43 (the adapter's confinement), M1-44 (the second zeroizer) and M1-45 (Gate C's
wider class) — and M1-6 moved from the A6-freeze section to the CP3b section, where the plan's own
task graph puts it. The other forty-one are unchanged; they were the most valuable output of the
first draft and none of them was in question.

**The 2026-09-06 rulings closed one and added three.** **M1-42 is CLOSED — owned by `s2`**, and it
is left in place below with its ruling rather than deleted, because an item that vanishes is an item
somebody files again. The three new ones are the split's own findings, and none of them is a defect
in the ruling: **M1-46** (`aad.go` stays for a reason the ruling did not give), **M1-47**
(§12.1 publishes a signer in a block whose own sentence says it publishes none), and **M1-48** (the
X25519 wrappers, which the follow-on commit has to decide between three shapes for).

**The 2026-09-06 pass added none and rewrote one.** M1-43's premise was false as a matter of Go
semantics and is corrected there, along with the five other places that stated it. Everything else
that pass changed is a property, a leg or a relocation rather than an item — and the pass's real
output is not in this document at all: it is `msgrepo/planlint_test.go`, an ordinary `go test` over
`docs/plans/*.md` that derives the four defect classes this plan has now paid for five, five, four
and three times respectively. It found this plan's Task 16 stating four properties with no mutation
set, and both of the 2026-09-05 relocations that never landed. In plans this pass did not touch it
found two more, reported rather than repaired: p8 attributes `profile.go` in its prose to a task
number one lower than the heading p8 itself gives that file, and the citation of p6 in this
document's R1 paragraph — repeated verbatim in s1 and in `SPEC-LEDGER.md` — names a task number
higher than the twenty p6 declares. Neither is this plan's to decide, and both print on every run.
The linter's own doc comment states what it cannot see, which is the half that stays the author's.

Numbering is plan-local (`M1-n`). Where an item corresponds to a ledger open item, the number is
given.

### Blocking CP3b

**M1-1 — the device wrap has no body encoding and no stated seal.** `wrap.go` is named in §2.2's
package tree and has **no section in any spec**. §5.11 specifies the server-visible `WrapTag` and
nothing about `ct_body`'s contents. MASTER §8.2 says what a device wrap carries and not how it is
laid out, framed or versioned. Worse, §5.11's sizing implies the wrap is an ordinary record whose
body goes through the record AEAD — whose key comes from the `storage_root` **the wrap delivers**.
Either the wrap's body is sealed under the previous epoch's class key, which serves no joiner, or the
X-Wing ciphertext is the seal and the record AEAD is a second layer under some other key. *Blocks:*
Task 14, Task 16, and therefore CP3b. *A ruling must state:* the body's field list and framing with
its `alg_id`; the key the wrap record's `ct_body` is sealed under, separately for a continuing member
and a joining one; and whether the X-Wing ciphertext sits inside the record body or replaces it.

**M1-2 — `group_handle_key` and the joining epoch's `read_key` have no carrier.** MASTER §8 and Spec
A §5.7 both say "in the `Welcome`". `grep -rn 'group_handle_key\|GroupHandleKey'` over `connect`
returns **0**; there is no fourth URmessage extension type; RFC 9420's `Welcome` has no free-form
slot. And `group_handle_key` derives from **epoch zero's** `storage_root`, which needs epoch zero's
`pq_secret`, which no wrap at the joining epoch carries. *Blocks:* Task 16, and therefore CP3b —
a member that does not hold `group_handle_key` "cannot compute its own handle and therefore cannot
write". *A ruling must state:* the carrier (a `GroupInfo` extension is the only authenticated,
joiner-encrypted slot in the v1 profile), its contents, and its validation — an unvalidated
`group_handle_key` is an attacker-chosen `sender_handle`, and `sender_handle` is inside every AAD and
every MAC in the system.

**M1-3 — `pq_secret[n]` has no producer, no type, no file and no section.** §5.12 says the committer
samples it; §5.10 E1 says the device wrap carries it; §5.3 takes it as an argument. Nothing declares
it. *Blocks:* nothing after Task 13, which supplies the sampler — the **delivery** is M1-1. Filed
because the absence is what makes a zero-filled stand-in so easy: `HKDF-Extract(mls_secret, 32 zero
bytes)` produces a storage root both clients agree on, with every test green and the PQ half gone.

**M1-4 — `GroupSession` is declared nowhere.** Grepping Spec A for it returns three lines: §5.2's two
method signatures, §3.6's concurrency row, and §5.6's "the constructor takes the sink". No struct, no
constructor, no statement of what it holds — while §5.6 adds a reserver to its constructor and §5.3
adds an epoch-zero storage root it must have persisted since group creation. §3.6 also says it "owns
exactly one `mls.Group`" where §6 and Gate 5 require a `GroupHandle`. *Blocks:* Task 10 designs it,
so nothing is blocked — but the design is this plan's and not the spec's, and §5.6's write-once
guarantee has no other injection point.

**M1-6 — `ct_head`'s class contradicts §5.3's shared `record_key`, and the refusal that follows
blocks a wave-2 task.** MASTER §8.1: *"`ct_head` is always under the **durable** class, since it is
always retained."* §5.3 gives `RecordAeadHead` and `RecordAeadBody` the same `record_key[i]`. For a
`DURABLE` record the two readings coincide and CP3b's text record cannot tell them apart; for
`PERMANENT`, `MEDIA` and `EPH` they are two keys from two ratchets, and one record then has one
`stream_index` covering two ratchet positions. Wire-visible.

*Blocks:* sealing any non-`DURABLE` record, which Task 11(a) refuses until this is ruled — **and
therefore Task 15**, whose ratchet-tree snapshot §5.11 step 2 fixes as *"one **PERMANENT**-class
record"*. This item was filed under *Blocking the A6 wire-format freeze* until 2026-09-05, on the
reading that the freeze is months out; by this plan's own construction it blocks **CP3b**, three
tasks from the end of wave 2, and it is the third of the three rulings on the schedule alongside
M1-1 and M1-2. Rule it before Task 15 starts. Do **not** close it by carving a `PERMANENT` exemption
into `SealRecord`: the retention class is inside `AAD_head` and inside the `write_auth` preimage, so
a snapshot written at a guessed class is wire-visible and unrecoverable after A6.

**M1-42 — CLOSED, 2026-09-06: the client-side submit leg is owned by `s2`.** The item is kept
below with the problem it stated, because that statement is still what `s2` has to answer. **The
ruling:** the leg is an **sdk plan, `s2`**, on the reasoning that `sdk` already owns transport and
storage and that §8.2's `MessageStore` already declares `ReserveStreamIndex` and `StreamHighWater`
— which is `message.StreamIndexReserver` method for method, and which Task 6 now only interfaces.
Shape **(a)** of the two below is the one taken; shape (b), the `msgrepo`-side integration test, is
rejected because what it proves is the record half and not the client half. `s2` does not exist yet
and is now on the CP3b critical path: it owns **two** of the six external legs (the submit path and
the durable reserver), and **O-5 is answered by the same ruling** — Task 6's interface, its five
properties and its whole mutation set are inherited by `s2`. What remains open is not the ownership
but the plan: nobody has written it.

*The problem as it was filed, which is what `s2` has to close:*
CP3b is *"a message is private — the same path"* as CP3a, and CP3a's path ends at the message
server. This plan's tasks all end at a `*Record` in memory: measured 2026-09-05, `grep -nE
'Submit|transport|harness'` over this document finds **no task producing a submit path**, and no
task's Produces names one. The server half needs nothing new — `msgrepo/store` and the api layer
serve `Hello`, `CreateGroup`, `Submit` and `Fetch`, verified as leg 3 of the 2026-09-02 chain review.
The client half is `sdk`'s: *"the transport binding, a send path and a receive path"*, which the same
review assigns to **the two-to-four sdk plans that do not exist**, and this plan does not touch
`sdk`. The only other client-side sealer-and-submitter in either tree is `msgrepo/harness`, which is
`msgrepo`-local, held test-only by `TestTheHarnessIsReachedOnlyFromTests`, and whose own doc comment
says *"It does not encrypt."*

*Blocks:* CP3b, and nothing in this plan. *The ruling stated:* `s2` owns the leg. Two shapes were
available and they are not equivalent. **(a)** An sdk plan owns it, CP3b waits for s1 and for that
plan, and this plan's Definition of done names it as an external leg — which is what the Definition
of done now does, pending the ruling. **(b)** An `msgrepo`-side integration test owns it: two
`connect/message.GroupSession`s sealing, `msgrepo/harness` submitting and fetching, in `msgrepo`
where the import direction already allows it. (b) reaches the milestone sooner and reaches it
through a harness that is not the product's transport, so what it proves is the *record* half and
not the *client* half — and the harness would have to stop deriving nothing and start carrying a
real sealed record, which is a change to a package whose doc comment is an argument for the
absences it has. **(a) was chosen.** This was the largest item in this section while it was open;
what is left of it is a plan that has to be written, tracked as a leg rather than as an item.

**M1-43 — `EngineProcessed.stagedRef` confines the *carrier*, not the *implementation*, and the
earlier text of this item said the opposite in six places.** §6 declares `stagedRef any` unexported
so *"a staged commit can be carried across a policy decision without `connect/message` being able to
read or forge it"* — a property worth having. The consequence this item claimed was that only
package `message` can construct a populated `EngineProcessed`, so only package `message` can
implement `Process`, so **every** `GroupEngine` implementation must live in `connect/message`.

**That is false as a matter of Go semantics, and it was disproved by compiling on the pinned
go1.26.5.** A keyed composite literal naming only exported fields is legal across package
boundaries. A type declared outside `connect/message` with

```go
func (self *Other) Process(wire []byte) (*msg.EngineProcessed, error) {
    return &msg.EngineProcessed{Kind: 3, Raw: wire}, nil
}
```

builds green and satisfies `msg.GroupHandle`. What the compiler refuses is narrower and is exactly
the field: naming it in a keyed literal is *"cannot refer to unexported field stagedRef in struct
literal of type msg.EngineProcessed"*, and an unkeyed literal is *"implicit assignment to unexported
field stagedRef in struct literal"*. **Only populating `stagedRef` is confined.**

So the corrected reading, and it is better news for §6 than the wrong one was. Gate 5's swap is
**not** confined to one package's source tree: a replacement engine may live anywhere and satisfy
the interface. What it cannot do is put anything in `stagedRef`, so it must carry its staged commit
some other way — in `Raw`, where `connect/message` can read and forge it, or in state of its own
that `connect/message` never sees. The unforgeability §6 argues for therefore holds **for engines
that use `stagedRef`, which is engines inside `connect/message`**, and is a property of the carrier
rather than of the interface.

**The adapter's home is a choice this plan takes, and the reason is §2.2, not the compiler.** §2.2's
tree assigns *"engine.go — the GroupEngine interface (§6) + the connect/mls adapter"* to this package
(spec line 197 after A-12), and Task 9a's adapter is the one implementation that wants `stagedRef` for the
`*mls.Processed` it stages. Both reasons are real and neither is a forcing.

*Blocks:* nothing. *What is still owed:* one sentence in §6, because §6's own claim is now the loose
one. It puts `NewConnectMlsEngineFactory` in `sdk/message_mls.go` and calls replacing it *"a one-line
change"*; that is true of the factory, true of the implementation's *location*, and false only of
the unforgeability guarantee, which a foreign engine does not inherit. *Recommendation, labelled as
one:* say in §6 that `stagedRef` is unforgeable **only for engines declared in `connect/message`**,
and that a foreign engine trades that guarantee for its independence. *Rejected alternative:* give
`EngineProcessed` an exported opaque carrier so a foreign engine can stage unforgeably — it costs a
validation step at every `ApplyCommit` and buys a swap nobody has asked for.

*Recorded for the next reader:* this item is the reason the plan linter's own doc comment says it
cannot tell a true claim from a false one. All six statements of the wrong claim resolved, counted
and cross-referenced perfectly; what caught it was a reviewer compiling a five-line package.

**What the 2026-09-06 split does to this item, and it is the corrected premise doing useful work
for the first time.** Because only *populating* `stagedRef` is confined — to the package that
declares `EngineProcessed` — the split has to move the **struct** and the **adapter** together. Had
`EngineProcessed` stayed in `connect/message` while the adapter went to `connect/messagegroup`, the
adapter would have been a foreign engine by Go's rules: it could satisfy `GroupHandle` and could not
put anything in `stagedRef`, and §6's unforgeability argument would have been lost to a directory
change nobody would have read as a security decision. Under the wrong premise this consequence was
invisible, because the wrong premise said the adapter could not leave the package at all. Interface,
adapter and `EngineProcessed` are therefore one unit for relocation purposes, and the File Structure
table says so.

**M1-44 — two zeroizers, and the alternative is one character.** Task 2 writes
`message.zeroize` because `mls.zeroizeSecret` (`secret_zeroize.go:42`) is unexported. Exporting it is
a one-character change and `message/xwing.go:36` already imports `connect/mls` in production, so the
call site is free. Against it: `connect/mls`'s exported surface is p2's, and `secret_zeroize.go`'s
own comment argues against additions at length. *Blocks:* nothing; both shapes work. Filed because
this plan's opening paragraph names *"a second implementation of a preimage that already exists"* as
the defect this project has already paid for once, and a second implementation of a four-line
primitive is the same shape at a smaller size. Whoever answers it should answer M1-37 in the same
breath: the two are the same question about the same file.

**M1-45 — Gate C's comparator ban is package-wide, and this plan works only its `Verify*` half.**
`TestNoProductionFunctionComparesDataOutsideConstantTime` (`writeauth_test.go:2473`) runs over every
function in every production file of `connect/message` and derives its comparator class from the
files' own imports. M1-19 works the consequence for the derived `Verify*` class — the six signature
verifiers Tasks 18 and 23 declare. **Two more tasks are in the wider class and neither is a
verifier:** Task 20's MIME sniffer, which compares magic-byte prefixes against a table, and Task 24's
`REACTION` validator, which tests codepoint membership against the pinned Unicode emoji set. Neither
compares secret-derived data, and the gate cannot know that. *Blocks:* Tasks 20 and 24.
*Two shapes close it:* spell both in `crypto/subtle`, which keeps the gate at zero exemptions and is
what the package already did for its two attachment comparisons; or restate the gate's class as
*comparisons of secret-derived data* and derive **that**, which is the same repair M1-19 asks of G8
and M1-35 asks of G7. Rule it with M1-19: three separate answers to one guardrail is how a gate
becomes three sentences.

### Blocking the A6 wire-format freeze

**M1-5 — the `StreamIndexReserver` is keyed more coarsely than the counter it guards.** §5.6's first
sentence: *"`stream_index` is a single `u64` counter per `(group_id, sender_handle)`"*. Its interface
takes `groupId` and not `senderHandle`, in both methods. A device removed and re-added at a different
leaf has a different `sender_handle` in the same group; the reserver cannot tell them apart. §5.6
itself says nonce reuse under a repeated `record_key` is *"a total break of both AEADs for that
record"*. *Blocks:* Task 6's **on-disk format**, and this is the one piece of durable state that
cannot be migrated by recomputation. *Recommendation, labelled as one:* add the parameter —
`Reserve(groupId, senderHandle []byte, index uint64) error`. *Rejected alternative:* keying on
`group_id` and reconciling later, which is a migration of exactly the state that cannot be migrated.

**And the parameter is in two documents, not one.** §8.2's `MessageStore` (spec line 3703) already
declares `ReserveStreamIndex(groupId []byte, index uint64) error` and `StreamHighWater(groupId
[]byte) (uint64, error)` — `StreamIndexReserver` method for method, with the same coarse key, on the
interface `sdk`'s sqlite implementation owes. So the fix is one parameter **twice**, on a
fourteen-method interface whose size A8 makes load-bearing (*"if `modernc.org/sqlite` has to go,
this is what has to be reimplemented"*). Rule it before either implementation is written, not after
one of them has rows on disk. Task 6 declares only the interface, for the same reason.

**M1-7 — the body padding scheme has no length recovery.** §5.1 fixes `octet_length(ct_body)` at
`size_bucket_bytes[b] + 16`, so the plaintext is padded — and **no document says how the receiver
recovers the true length.** `pad.go` is named in §2.2 with no section anywhere; MASTER §9.5 is "What
the server sees" and is not it. `msgrepo/harness/seal.go` pads with `byte(index*31)` and never
unpads, because CP3a never reads a body back. *Blocks:* interoperable `SealRecord`/`OpenRecord`.
Wire-visible. *Candidates a ruling should choose among:* `u32(len) ‖ body ‖ zeros` inside the
plaintext, matching §5.14's own `u16(body_len) ‖ body ‖ zeros` deposit padding; ISO/IEC 7816-4
`0x80 ‖ 0x00*`; or the body's own §7.4 framing carrying its length, which pushes the decision into
`sdk` and out of the frozen format.

**M1-8 — `LP(leaf_index)` wraps an integer, and it is the only `LP` in the project that does.** §5.11
defines `LP(x)` as a 32-bit big-endian length prefix then `x`, and every other use wraps a byte
string. `sender_handle = HKDF-Expand(group_handle_key, "sh/v1" ‖ LP(leaf_index), 16)` (MASTER §8) and
`record_key[0] = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)` (§5.3) both need a rule
for what `x` is; `wrap_target_handle`, in the same family, writes `u32(leaf_index)` **raw** with no
`LP` at all. *Blocks:* interop on `sender_handle`, which is in every AAD and every MAC. Wire-visible.
**Related, and separate:** §5.3 declares `SenderHandle` with no formula at all — MASTER §8 has it, so
Spec A owes the restatement.

**M1-9 — §5.4's combiner table is wrong and is still uncorrected.** §5.4's stdlib-mapping row gives
`sha3.Sum256(XWingLabel ‖ ss_M ‖ ss_X ‖ ct_X ‖ pk_X)`, label **first**. The draft puts the label
**last**. `message/xwing.go:219 xwingCombine` writes it last and its comment says *"that is an error
in spec A"*; `TestXwingCombinerOrderMatchesTheDraft` holds it there. *Blocks:* nothing in code — the
implementation is right. *Blocks in practice:* a second implementer working from §5.4 builds a KEM
that round-trips against itself, matches none of the draft's three vectors, and interoperates with
nothing. This is the cheapest edit in the document.

**M1-10 — the record AEAD's `alg_id` appears in no line of Spec A §5.** MASTER §8 line 722 pins
`0x0021`, XChaCha20-Poly1305, and §7.1's registry carries it. Spec A §5.1, §5.3, §5.7 and §5.8 never
mention it, and the consequence is already visible: `AADHead` and `AADBody` take `algId uint16` as a
bare caller-supplied argument and no named constant exists in the package. A second implementation
reading only Spec A picks its own value; one that picks a 12-octet-nonce AEAD silently discards 12
octets of the 56-octet expansion and still round-trips against itself. Task 1 pins the constant from
MASTER. *Blocks:* nothing — MASTER is normative. Filed as a Spec A repair.

**M1-11 — §5.5 states the ratchet's keying two incompatible ways.** The prose scopes the window to
`(sender_handle, retention class)`; `NewSenderRatchet(classKey []byte, leaf uint32)` and
`record_key[0]`'s `LP(leaf_index)` bind the **leaf**. §5.3 makes the handle deliberately epoch-stable;
a leaf index is not. Which one keys the ratchet table decides whether a member's stream survives an
epoch change. *Blocks:* Tasks 7 and 8's table keying, and Task 10's session state.

**M1-12 — §5.5's memory arithmetic does not close, and a better answer is in the tree.** 1024 keys ×
~32 B × 64 senders is ~2 MB for **one** class; with three non-EPH classes it is ~6 MB and EPH buckets
add more. §5.5 says *"Needs a Spec C memory budget to finalize (§14 open item 7)"*, and §14 item 7 is
marked *blocks slice A6*. *Recommendation, labelled as one:* adopt `mls/secret_tree.go`'s policy —
`MaxRetainedWindowKeys` as a **tree-wide** constant, so sender count costs no memory, and eviction
from the **fullest** window rather than the oldest sender, so a quiet member is not starved. It
closes §14 item 7 without a Spec C round trip. *Rejected alternative:* §5.5's 64-sender cap as
written, which is O(senders) memory with a policy that evicts exactly the member most likely to need
the window.

**M1-13 — `Next()` cannot report the failure §5.6 requires it to have already survived.** §5.5 gives
`Next() (index uint64, recordKey []byte)`, no error. §5.6 requires `Reserve(...) error` to complete
durably **before the key is produced** and says `SealRecord` "refuses to proceed on error". As
declared, either the reservation happens outside the ratchet — and the ordering guarantee is a
convention again, which §5.2 forbids — or `Next()` panics on a disk error. *Blocks:* Task 7's
signature. *Two shapes close it:* a third return value, or the reserver moves into `SealRecord`
between the index draw and the key draw.

**M1-14 — `ReceiverRatchet` is declared with one method and nothing else.** No constructor, no
statement of what it is keyed by, no statement of who owns the 64-sender table. *Blocks:* Task 8's
construction, and Task 10's ownership of the table.

**M1-15 — `OpenRecord` has one error channel and §5 requires two non-error outcomes.** §5.5's
out-of-window record *"surfaces as a `Kind == "gap"` entry with `GapReason == "out_of_window"` — not
as an error"*; §5.11 step 4's `no_wrap` is the second. §5.9 G7 makes every error in this package
fatal by construction, and §12.1's refusals block — which A-9 makes an allowlist of what a **published**
function can return — carries neither name. *Blocks:* Task 12's signature, and `sdk`'s §7.4 gap
rendering. *Two shapes close it:* a third return value on `OpenRecord`, or two pinned sentinels `sdk`
matches with `errors.Is` — in which case A-9's reachability rule adds two lines to §12.1 in the same
commit.

**M1-16 — G1's "only call site" is contradicted by the tree and by §5.14.** G1 forbids `hkdf.Extract`
"anywhere else in `connect/message` **and `connect/mls`**". `connect/mls` cannot satisfy that: RFC
9420 needs it in `crypto.go` and RFC 9180 in `hpke.go`, and the landed gate allows exactly those two
paths with no entry for `keyschedule.go`. Separately, §5.14 introduces a **second** Extract inside
`connect/message`: `deposit_sig_seed[k] = HKDF-Expand(HKDF-Extract("URmessage/v1/rendezvous",
token[k]), "depsig/v1", 32)`. *Blocks:* Task 3's shape, and the Gate A amendment Tasks 3, 5, 22 and
23 each owe. *Recommendation, labelled as one:* `StorageRoot` delegates to
`mls.CryptoProvider.Extract(salt, ikm)`, which already takes the arguments in the spec's order, is
already the reviewed call site, and leaves the tree with exactly **one** `hkdf.Extract` in the whole
crypto surface. *Rejected alternative:* widening `hkdfExtractAllowedPaths`, which re-opens the hazard
the guardrail exists to close, once per new file.

**M1-17 — `TestEphRootHasNoDurableInput` is specified as something Go cannot do.** §5.3 asks it to
assert *"by reflection that no exported function in the package returns eph key material from
arguments that include a `storageRoot`"*. Go reflection sees neither parameter names nor the meaning
of returned bytes. This tree has solved the class twice with an AST scan plus a required-row table
and a positive control (`messagegroup/entropy_test.go`, `mls/crypto_forbidden_test.go`); specify it that
way. It is a **named release gate for slice A6** (§13), so it cannot stay vague. *Blocks:* Task 17's
gate, and A6's release gating.

**M1-18 — §5.2 and §2.4 disagree about whether a `Record` can be built by hand.** §5.2 says
`recordBuilder` is unexported and there is *"no way to construct a `Record` by hand"*. §2.4 requires
the **server** to rebuild `record_bytes` by calling `message.EncodeRecord` over stored columns, which
means Spec B must construct a `*Record` from exported fields — and `Record`'s fields are all exported
today (`record.go:105`). "No exported constructor" and "no way to construct by hand" are not the same
claim and only the first is compatible with §2.4. *Related:* §5.2 is also silent on what `SealRecord`
does with a non-nil `&ServerAttachment{Kind: AttachmentNone}`; `attachment.go` already chose the safe
reading (both answer no bytes, so both contribute the same `LP(H(server_attachment))`) and it is worth
promoting into §5.11 before a second implementation reads the refusal rule literally and rejects the
**value** as well as the encoded bytes.

**M1-19 — guardrail G8's text and the gate that shipped are two different rules, and the shipped one
refuses a correct signature verifier.** G8's text names a grep gate over `validation.go`,
`writeauth.go` and `framing.go`. `validation.go` exists in **neither** package (mls has
`validate_commit.go` and `validate_proposals.go`), and `framing.go` is an `mls` file while
`writeauth.go` is a `message` file, so the rule as written straddles two packages by base name — the
exact exemption shape `crypto_forbidden_test.go` documents at length as the one this project keeps
rediscovering. What actually shipped is **better**: a construct gate over the whole `message`
directory with the comparator class and the verifier class both derived. But its `Verify*` class will
refuse `VerifyRecoveryProof` and the five `VerifyRendezvous*` — an Ed25519 verifier calls
`ed25519.Verify` (rule 3) and reaches no `subtle.ConstantTimeCompare` (rule 4). *Blocks:* Tasks 18
and 23. *Recommendation, labelled as one:* restate G8 as a property over both packages, and amend
rules 3 and 4 so they read on verifiers that **decide equality themselves**, keeping the class
derived and the control in place. *Rejected alternative:* a name-based exemption, which is how a gate
becomes a sentence.

**M1-20 — G10's destructor covers half the provisional state.** It names `ClearPendingCommit` with no
receiver and no signature; the landed one erases the staged **MLS** epoch. §5.12 step 1 requires
discarding `storage_root[n+1]`, `write_key[n+1]`, `eph_root[n+1]`, `pq_secret[n+1]` and every X-Wing
wrap — none of which `mls` knows about and none of which has a declared home in `connect/message`.
`TestLostCommitResamplesPqSecret` cannot be written against anything that exists. *Blocks:* nothing
after Task 13, which gives it a home; filed because the spec does not.

**M1-21 — §5.12 forks the key schedule on an ambiguous outcome.** It binds to *"any rejection of a
commit submission"* and orders a resample; a timeout after the server committed is **not** a
rejection but lands in step 7's back-off loop, and resampling then produces a `storage_root[n+1]` no
other member computes — a silent per-member fork with a valid MLS epoch underneath. Idempotency
cannot catch it because step 2 deliberately makes the retry a different commit. *Blocks:* Task 21,
and it should be ruled **before** any retry code is written. *Recommendation, labelled as one:* an
explicit step 0 — an unknown outcome is not a rejection; resolve it with `GroupStatus` first.

**M1-22 — §5.11's wrap-omission repair is gated on the wrong condition.** Step 5 authorises
re-publication only *"if the committer dies mid-fan-out"* and the marker never lands. A committer
that instead sets `expected_wrap_count` low, omits one member's wrap, and submits a matching
`EpochComplete` produces a group that is writable, self-consistent to the server (which can only
check count equality, and `write_auth` is a group-wide MAC any member can compute) and **permanently
unreadable** for the omitted member — `pq_secret[n+1]` is sampled by the committer and delivered only
in the wrap, so the victim derives `mls_secret[n+1]` from its own state and still cannot compute
`storage_root[n+1]`. Step 4 makes it visible; nothing makes it repairable. *Blocks:* nothing in this
plan; it is a protocol availability defect. *Recommendation, labelled as one:* extend step 5's
authorisation to cover a landed marker with a missing wrap.

**M1-23 — §5.11 states the snapshot is a blob-ref record unconditionally.** *"The snapshot exceeds
the 64 KiB inline ceiling and is therefore written by `wrap.go` as a blob-ref record"* is true at the
500-member design target and false for a two-member group, where the snapshot is a few hundred octets.
As written it drags the whole object-store path in front of a two-client message. *Blocks:* Task 15's
rung choice. *Recommendation, labelled as one:* the snapshot takes the smallest rung that fits,
blob-ref only above 64 KiB.

**M1-24 — `body_hash` binds nothing on the blob rung.** §5.1 defines it as `H(CtBody)`; for
`size_bucket = 5` `ct_body` is absent, enforced by the landed `checkRecord`. §5.13 nevertheless
claims a never-downloaded record is fully verifiable. If it is `H(nil)` it is a constant on every
blob record; if it is meant to be `H(blob_ciphertext)` nothing says so. `write_auth` covers `blob_id`
and not one octet of the object, so the object store can return any bytes it likes. *Blocks:*
Task 20. Wire-visible.

**M1-25 — §5.6's durable reservation versus `EPH(bucket 0)`.** Every transient consumes an index and
therefore costs a synchronous flush, so the transient send rate becomes the fsync rate. §5.5 has a
memory budget deferred to Spec C; §5.6 has no I/O budget and no §14 item. *Blocks:* nothing before
wave 3. *Two shapes close it:* a separate counter for transients — nothing server-side checks them,
so nothing breaks — or the cost is stated and accepted.

**M1-26 — `write_auth`'s preimage covers no `alg_id` while both AADs do.** MASTER §7.1: *"Every
signature, authenticator, hybrid ciphertext, and published public key carries `alg_id` (u16)"*, and
`write_auth` is an authenticator. The omission is defensible — a downgrade fails the AEAD at every
client, and MASTER I5 makes `write_auth` access control rather than authenticity — but the asymmetry
is nowhere argued, and the next reader comparing §5.7 to §7.1 will read it as an omission and "fix"
it, changing every MAC in the system. *Blocks:* nothing. One sentence in §5.7 closes it.

**M1-27 — `EphKey`'s `window` has no unit, no origin and no clock.** MASTER §8.1 gives the formula
(`K_eph[n][b][t] = HKDF-Expand(eph_root[n], "eph/v1" ‖ u8(b) ‖ u64(t), 32)`) and calls `t` a
time-slice; nothing says whether it is `floor(now / eph_bucket_seconds[b])`, in what epoch, on whose
clock. §5.3 declares `EphKey` with no formula at all. *Blocks:* Task 17. Wire-visible.

**M1-28 — `RecoveryProof` takes two sources for one value, and the consequence is permanent.**
`recovery_handle` is derivable from `recovery_root`, already a parameter, and nothing requires the
function to check they agree. Under §5.7's per-group TOFU rule, a caller pairing one identity's handle
with another's root writes a poisoned row and permanently denies its own restore for that group.
`AADHead` and `WriteAuthPreimage` already refuse the analogous mismatch in both directions. *Blocks:*
Task 18's signature. *Two shapes close it:* derive the handle inside and drop the parameter, or refuse
the mismatch explicitly.

**M1-29 — §12.1 hands the server a function that maps a token to a signing key's sibling.**
`DepositVerifyKey(token []byte)` is on the block that ends *"The server gets verifiers and no
signers"*, and `deposit_sig_seed[k] = HKDF-Expand(HKDF-Extract("URmessage/v1/rendezvous", token[k]),
"depsig/v1", 32)` — the token yields the deposit **signing** key one label away. A function taking a
token is only callable by a party holding tokens, and a server holding a token can forge `open_auth`
and `deposit_auth`, which is the whole of the rendezvous's write authorization. The server never
needs it: it pins `deposit_verify_pub` from `register_auth`, and §5.14 says so. The same block also
calls it "no key-schedule function", which it is. *Blocks:* Task 23's published surface.

**M1-30 — one card holder can deny the card to every other holder.** `deposit_sig_sk` derives from
`token[k]` alone, so every holder of a published card shares one signing key; §12.1's requirement S18
makes the server *"Store no depositor identifier on the deposit row"* and bound each rendezvous to
`rendezvous_mailbox_depth` (16, per Spec B §4.3.11's `MessageServerInfo` field). One holder fills the
mailbox and the server cannot tell depositors apart to rate-limit them. §7.3b's
"auto-accept degrades to manual review after three requests in an hour" is a client rendering rule
and does not touch this. *Blocks:* nothing in code; it is a design finding on §5.14.

**M1-31 — §5.14's `HKDF-Extract` is written positionally with no `salt =` / `ikm =` annotation.**
Every other Extract in the project is annotated — §5.3 spells out `HKDF-Extract(salt = mls_secret,
ikm = pq_secret)` and then spends a paragraph on the transposition. Under the project convention the
label is the salt and the token the ikm, but the reader must infer it, and a transposition here
compiles, returns 32 octets, produces a valid Ed25519 key, and fails only against a second
implementation — which is precisely G1's stated failure mode. *Blocks:* Task 22. Annotate it, and pin
it with a KAT in `TestStorageRootKAT`'s shape.

**M1-32 — §5.14's client half has no declarations at all.** The section says `connect/message` *"owns
the card encoding, the rendezvous derivations, the five signature preimages and the sealed deposit"*,
§12.1 declares only the **server's** verifiers and preimage builders, and §5.14 declares no Go. No
signature exists for deriving `card_root`/`card_seed[k]`/`token[k]`/`card_xwing[k]`, encoding or
parsing the card, sealing a deposit, **opening** one, verifying the inner `request_sig`, or computing
the four client-side auth signatures — and §12.1 explicitly withholds an opening function from the
server, so it must exist somewhere and is declared nowhere. **Related:**
`RendezvousRegistration` and `RendezvousCollectParams` are named on §12.1's surface, are arguments to
three of its functions, and their **fields** appear nowhere; they are inferable from the two
preimages, and the 2026-08-26 amendment that gave `EpochAttachment` its field types exists precisely
because inferring them is how two implementations diverge silently. *Blocks:* sizing Tasks 22–23 —
a planner reading §12.1's nine functions misses roughly the same amount of code again.

**M1-33 — the deposit's AEAD, its nonce width and `H()` are never named.** §5.14 writes
`AEAD(deposit_key, nonce = 0, aad = ..., padded_body)` and the arithmetic `4096 + 16 = 4112` fixes
only the tag length; the record AEAD, the MLS suite's ChaCha20-Poly1305 and AES-256-GCM all fit. The
nonce is `0` with no stated width. `H()` is used for `rendezvous_id`, the card checksum,
`H(deposit_ct)` and `H(key_package)` and is defined nowhere in the span. *Blocks:* Task 23.
Wire-visible.

**M1-34 — the deposit body can overflow its own padding with no stated behaviour.**
`CONTACT_REQUEST` is padded to exactly 4096 as `u16(body_len) ‖ body ‖ zeros`, leaving 4,094 for the
body; the fixed fields cost 182, leaving 3,908 for `LP(key_package)`. A v1 KeyPackage carrying a
`LeafKeysExtension` with a 1,216-octet `DeviceXwingPub` lands around 1.5–1.6 KB and fits — but nothing
states the bound, nothing refuses an oversized one, and the natural fixed-width padder truncates or
panics. A second leaf extension eats the margin. *Blocks:* Task 23. State the cap and make it a typed
refusal.

**M1-35 — G7 enumerates three bool-returning verifiers and §12.1 publishes five more.** G7 pins the
closed set as `VerifyWriteAuth`, `VerifyRequestAuth`, `VerifyRecoveryProof`, *"and each caller is
asserted to `return` on false"*. §12.1 adds `VerifyRendezvousRegister`, `VerifyRendezvousOpen`,
`VerifyRendezvousDeposit`, `VerifyRendezvousCollect`, `VerifyRendezvousRetire`. Both are in the same
document. G7's enumeration would leave five of eight signature verifiers outside the guardrail that
exists to stop a mismatch being logged and continued — on exactly the surface where a bad signature
means an unauthenticated contact request. *Blocks:* Task 23. Restate G7 as a **property** — every
bool-returning verifier in the package — rather than a list. It is the same repair M1-19 asks for on
G8, and the two should be made together.

### Spec hygiene, blocking nothing

**M1-36 — file assignments conflict between §5.3 and §2.2, and since 2026-09-06 between §2.2 and
itself.** The split gives `connect/message`'s responsibilities two directories, and §2.2's tree has
been amended to carry both; every file annotation elsewhere in Spec A — §5.2's `// codec.go`,
§5.3's `// keyschedule.go`, §5.5's and §5.6's `// ratchet.go`, §6's
`// connect/message/engine.go` — has been amended with it, because a file annotation naming the
wrong **package** is worse than one naming the wrong file: it is the thing this ruling exists to
stop, written in the spec. The rest of this item stands as filed.

 §5.3's comments put
`GroupHandleKey`/`SenderHandle` and `NewEphRoot`/`EphKey` in `keyschedule.go`; §2.2's tree puts
`sender_handle` in `handle.go` and eph in `eph.go`. Normally cosmetic; here it is not, because
several guardrails are file-scoped — Gate A's allow-lists are lists of **paths** — so the gates must
name the files the code actually lands in. This plan follows §2.2 where it can and diverges
from it in **fourteen** places where it cannot; every one is now enumerated in the File Structure
section rather than summarised as *"follows §2.2"*, which is what the earlier version of this item
left it at. The fourteen: **eleven files added** that §2.2 does not name (`recordaead.go`,
`zeroize.go`, `streamindex.go`, `session.go`, `seal.go`, `epoch.go`, `blob.go`, `commitretry.go`,
`card.go`, `rendezvous.go`, `reaction.go`), **two files §2.2 names that this plan does not create**
(`pad.go`, accounted for by Task 24; `tombstone.go`, absorbed into `reaction.go` with no stated
reason — that one is a live question, not a recorded divergence), and **one function moved**
(`SenderHandle`, out of §5.3's `keyschedule.go` into §2.2's `handle.go`).

**Three of those are moves out of a file a spec comment names, and two were silent.** §5.2 puts
`SealRecord`/`OpenRecord` in `codec.go`, and `codec.go`'s own header comment says it exports nothing
beyond §12.1's three functions "because that block is restated character for character in spec B
§12.1"; this plan puts them in `seal.go` and keeps the codec's claim true — that one was argued.
**§5.6's own interface block wrote `// ratchet.go` above `StreamIndexReserver`** and this plan puts
it in `streamindex.go`, which §2.2 did not name at all — that one was silent. **Closed by A-12:**
§5.6's block now reads `// messagegroup/streamindex.go` (spec line 1314) and §2.2's tree names the
file, so the divergence is recorded in the spec rather than only here.
And `tombstone.go` — that one was silent too.

**M1-37 — §5.5 specifies `unsafe.Pointer` zeroization; the tree's answer is a plain loop.**
`mls/secret_zeroize.go` does the same job with `//go:noinline` and a byte loop, and its comment
argues against adding anything further — it rejected `runtime.KeepAlive` because importing `runtime`
would widen an import set another gate pins. `connect/mls` production code contains no `unsafe` at
all. Task 2 matches the tree. Either amend §5.5 or say why `message` is different.

**M1-38 — `collect_verify_pub`'s derivation is never stated.** It is used in the `register_auth`
preimage and is obviously the Ed25519 public half of `collect_sig_sk` — but `deposit_verify_pub` is
in the same position and §5.14 **does** name `deposit_sig_seed` explicitly, so the asymmetry reads as
an omission rather than an ellipsis.

**M1-39 — `request_sig` is the only §5.14 signature not bound to `server_nonce`,** and correctly so:
it is verified by the card owner, possibly days later, on a different connection. The section
introduces the five nonce-bound preimages under a heading about replay and leaves the reader to
notice that the sixth deliberately does not. Say why, or an implementer adds the nonce and breaks
deposit verification across connections.

**M1-40 — `expected_wrap_count` is a deferral the system cannot detect.** Ledger item 47. §5.11
defines it as *"device wraps + recovery wraps + 1 snapshot"* and the server checks only marker
against attachment. Task 15 derives it and gates the deferral with a red test rather than leaving it
a number an implementer picks; filed here because the **spec** should say the count is derived and
what happens when a client's inventory disagrees with the definition.

**M1-41 — `REACTION` validation needs segmentation Go does not have.** §5.1 requires *"exactly one
extended grapheme cluster, and every codepoint drawn from the emoji set of the pinned Unicode
version"*, validated on send and on receipt. Go's standard library provides no UAX #29 segmentation,
so this is a dependency decision — a new module, or a hand-rolled subset plus the pinned tables — and
the Unicode version is not pinned anywhere this plan could find. *Blocks:* Task 24, which is last for
this reason.

**M1-46 — `aad.go` stays in `connect/message`, and the surface test says it should not.** The
2026-09-06 ruling lists `aad.go` among "the record layer the server genuinely parses". Measured, it
is not: `msgrepo` calls `AADHead`, `AADBody` and `BodyBinding` **zero** times, and §12.1 A-9 says in
as many words that those three are *"deliberately on no line of §12.1 because the server never
decrypts"*. Two things keep it where it is, and both are worth more than the symmetry:
`BodyBinding()` is a **method** on `RecordHeader`, a §12.1-published type declared in `record.go`,
and Go permits a method only in its type's own package — so the move is a shape change to landed,
vector-tested code for no gate benefit; and `aad.go` imports only `connect/mls/syntax`, which spec B
§2.2 allows by name, so it costs the server nothing to link. *Blocks:* nothing. *What is owed:*
the narrower property — *the server links only §12.1* — is a **test**, not a package boundary,
and it is the one ledger open item 7 and **O-3** have been asking for since 2026-08-12. If that test
is ever written, `aad.go` is the first thing it will have an opinion about, and this item is where
that reader should look.

**M1-47 — §12.1 publishes a signer in the block whose own closing sentence says it publishes
none.** *"The server gets verifiers and no signers, and no function that opens a deposit"*, and four
lines above it `func RecoveryProof(recoveryRoot, serverNonce, recoveryHandle []byte) ([]byte, error)`
— an Ed25519 signature over a preimage keyed by `recovery_root`, which is a client secret. The
same shape appears once more: `DepositVerifyKey(token)` is on the surface and a token yields the
deposit **signing** key one label away, which is already **M1-29**. This item is the general case of
that one. The split makes it visible rather than causing it: `recovery.go` stays in
`connect/message` **because** §12.1 publishes both halves, and Spec B §12.1 restates the block
character for character, so removing one name is a two-document amendment nobody has asked for.
*Blocks:* nothing; Task 18 lands as written. *A ruling would state:* whether `RecoveryProof` belongs
on the imported surface at all, or whether the server needs only `VerifyRecoveryProof` and the
signer belongs in `connect/messagegroup` beside every other signer. *Recommendation, labelled as
one:* rule it together with M1-29, because both are the same question — what a **verifier-only**
surface means when the derivations are one HKDF label apart — and a second separate answer to it
is how a rule becomes two sentences.

**M1-48 — the four X25519 wrappers after the split, which is the follow-on commit's only real
choice.** `xwing.go` needs `mls.X25519PrivateKey`, `X25519PublicKey`, `X25519GenerateKey` and
`X25519DH`, plus `mls.ErrNilRandomSource` and two compile-time pins against `mls.XwingPublicKeyLen`
and `mls.AlgIdXwing`. Three shapes are available and they are not equivalent:

- **(a) `connect/messagegroup` imports `connect/mls` and the import is correct.** Nothing moves but
  the two files, `ecdhAllowedPaths` stays a one-element list, `connect/mls`'s exported surface is
  untouched, and §2.3's layering diagram keeps its shape with one node renamed.
- **(b) `crypto/ecdh` directly in `messagegroup/xwing.go`.** This is the shape that would let
  `xwing.go` stay in `connect/message` and close the whole thing with no new package at all — and
  it is the one to refuse. It requires a **second** entry in `ecdhAllowedPaths`, and guardrail G3
  exists because `sdk.GenerateSharedSecret` returned an all-zero secret on a low-order point; a
  second reviewed ECDH call site duplicating `mls.X25519PrivateKey`'s length and validity checks is
  the second implementation this plan's first paragraph forbids, in the one file where the cost of
  getting it wrong is a shared secret both ends agree on and neither chose.
- **(c) a shared low-level home** — a new `connect/x25519`, or `connect/mls/x25519`. It rewires
  `connect/mls/crypto_x25519.go` for one caller's convenience, which is the argument M1-44 already
  rehearses about `zeroizeSecret` and reaches the same answer to; and `connect/mls/x25519` would put
  a **second child of `connect/mls`** into the tree, which is the question `msgrepo/deps_test.go`'s
  own comment reserves.

*Recommendation, labelled as one:* **(a)**. `connect/messagegroup` is the client half and the client
holds the group; an MLS import there is the package's declared normal, not an exception, and
`xwing_errors.go`'s own header already argues the boundary from the other side — *"the server
never wraps, never unwraps and never holds an X-Wing key"*.

**And (a) does not answer the question `deps_test.go` reserves, which is stated here so nobody
reads it as having been answered.** That comment says *"a second child of `connect/mls` entering
this closure is a different question, and it should fail this gate and be looked at rather than
inherit an answer given to the codec."* The closure it means is **`msgrepo`'s**. Under (a) nothing
new enters it: `connect/messagegroup` is a sibling of `connect/message`, not a child of
`connect/mls`, and `msgrepo` does not import it — verified by probe, where making `msgrepo` import
`connect/messagegroup` fails the gate by name. So the reserved question stays reserved, and the day
somebody proposes `connect/mls/<anything>` for the server they will still have to answer it.

---

## Open asks on other plans

**O-1 — to s1's Task 16 registry: the producer of `GroupEngine` and `GroupHandle` is m1, not s5,
and since 2026-09-06 the package in both pins' spelling is wrong too.** s1 records both as pending
pins with **s5** as producer and `connect/message/engine.go` as absent. §5.2's `SealRecord` cannot be
a method on a `GroupSession` that has no exporter to reach, so the producer is m1. And the pins
should read **`messagegroup.GroupEngine`** and **`messagegroup.GroupHandle`**, in
`connect/messagegroup/engine.go`: §12.1 gives the server *"no MLS type"* and `GroupHandle` is
twenty-three of them, so the interface cannot live in the package `msgrepo/api` imports. What s5
produces is the **factory**, `NewConnectMlsEngineFactory` in `sdk/message_mls.go`, and its return
type moves with the interface — `s5`'s own signature changes, which is the second thing this ask
now carries. Task 9 lands the interface and Task 9a lands the `connect/mls` implementation of it, in
the same file because §2.2's tree pairs them and in the same **package** as `EngineProcessed`
because `stagedRef` is unexported and only a member of the declaring package can populate one
(M1-43; the claim that `stagedRef` confines *every* implementation is false and is corrected there).
s1's registry row should name m1, and spell the pin against `connect/messagegroup`, so the
pending-pin gate fails and asks for the pin on the day it lands.

**O-2 — to s1's Task 16 registry: `MessageProtocolLimits.DeleteForEveryoneWindowMs` is not produced
by this plan.** s1 records it as a pending pin with m1 as producer, citing "the `TOMBSTONE` body
table". Tombstones are Task 24 and the 24-hour window is stated in MASTER §13's product text
(*"Messages can only be removed for everyone within 24 …"*), not in any `connect/message` declaration.
Either Task 24 declares the constant and the pin resolves there, or the producer row should name the
plan that owns the tombstone body. Filed so the pin does not stay pending against a task that never
declares it.

**O-3 — to whoever owns §12.1's allowlist test.** Ledger open item 7: §12.1 says *"A test in the
message-server repo asserts the allowlist"* and no such test exists. This plan adds functions to
`connect/message` on **both** sides of that line — `RecoveryProof` and the nine rendezvous functions
are on the surface; `SealRecord`, `OpenRecord`, the whole key schedule and both ratchets are
deliberately not — and A-9's reachability rule means the refusals block changes too. The surface is
about to move more in this plan than in any before it, with nothing mechanical holding the two
documents and the code together.

**O-4 — withdrawn. p7 owes nothing here; the gap was this plan's own naming.** The earlier version
of this ask said `GroupHandle.RatchetTreeSnapshot()` and `GroupContextBytes()` should be read out of
`group.go` and, if absent, asked of p7. Both exist, under other names: `Group.RatchetTree()` at
`connect/mls/group.go:891` and `Group.GroupContext()` at `:900`, measured 2026-09-05, both returning
`([]byte, error)` as §6's do. Nothing is missing in `connect/mls`. The divergence is **§6's spelling
against the tree's**, it is one of the 13 mismatches in Task 9 Property 3's table, and it is closed
by Task 9a's adapter in two lines.

This ask was itself an R2 failure — a signature asked of another plan without being read out of the
file that owns it — filed in the section that states R2, which is the failure mode R2 names. It is
recorded here rather than deleted, because a withdrawn ask that leaves no trace is an ask somebody
files again.

**O-5 — ANSWERED, 2026-09-06: `s2` owns it, and inherits Task 6's interface whole.** The owner
ruled that both the client-side submit leg and the durable reserver are `s2`'s, on the reasoning
§8.2 already supplies: `MessageStore` declares `ReserveStreamIndex` and `StreamHighWater`, and that
is `message.StreamIndexReserver` method for method. What `s2` inherits is not a suggestion — it is
Task 6's five properties and its whole mutation set, `TestStreamIndexNeverReused` included, which
§5.9 names as G5's and G11's and which no other plan owns. `s2` is unwritten and is on the CP3b
critical path. The ask as originally filed, which is still the substance:

*To whoever writes the sdk store plan (s2 by s1's own reckoning).* §8.2's `MessageStore`
declares `ReserveStreamIndex(groupId []byte, index uint64) error` and `StreamHighWater(groupId
[]byte) (uint64, error)`, which is `message.StreamIndexReserver` method for method. Task 6 declares
the interface and its five properties and deliberately ships **no** durable implementation
(`connect/message` imports no I/O package and §8.2 assigns the persistence); the durable one is that
plan's, and it inherits Task 6's properties 1–5 and its mutation set whole — in particular
`TestStreamIndexNeverReused`, which §5.9 names as G5's and G11's and which no other plan owns. Two
further things travel with it: **M1-5**'s keying question is one parameter on **both** declarations,
and must be ruled before either has rows on disk; and **M1-25**'s fsync cost lands on that
implementation, not on this one.
