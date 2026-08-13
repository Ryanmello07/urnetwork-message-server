# [Syntax and Codec] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `connect/mls/syntax`, the byte-exact, round-trip-stable TLS presentation-language
codec that every other MLS package and `connect/message` encode and decode through.

**Architecture:** A `Writer` that accumulates bytes with a sticky error, and a `Reader` that is a
bounds-checked cursor over a byte slice, plus free generic functions for vectors and a top-level
`Marshal`/`Unmarshal` pair that enforces full consumption. The leaf writes are return-free and the
sticky error carries their failures; `MarshalMLS` and the two higher-order encode callbacks return
an `error`, because an MLS encoder also has semantic refusals that are not buffer errors, and
`Marshal` joins the two. Every variable-length read validates its declared length against both the
configured maximum and the bytes that remain **before** any allocation, and the RFC 9420 §2.1.2
varint accepts exactly one encoding per value. The package imports `bytes`, `encoding/binary`,
`encoding/hex`, `encoding/json`, `errors` and `testing` and nothing else — `testing` because the
family 16 runner is exported for the wave-4 vector registry — so it can be audited and fuzzed with
no transport, no crypto and no third-party code in the graph.

**Tech Stack:** Go 1.26.5 standard library only. Go native fuzzing (`testing.F`). The mlswg
`deserialization.json` test-vector family, vendored and pinned by the validation and interop plan
(p8 Task 6) and read from `connect/mls/testdata/vectors/`.

## Global Constraints

- Go 1.26.5, pinned. `connect/go.mod` gains `toolchain go1.26.5`; the `go` directive is not raised.
- `connect/mls/syntax` imports **stdlib only** — not `connect`, not `connect/mls`, not
  `golang.org/x/crypto`, not anything with a dot in its first path element (Spec A §2.3).
- `connect` (the parent package) must NEVER import `connect/mls` or `connect/message`. A package must
  not import its own subpackages (`connect/CODESTYLE.md`, Spec A decision A2).
- No cgo. No build tags. Everything here must build for `windows/{amd64,arm64}`,
  `linux/{amd64,arm64}`, `darwin/arm64`, `android/{arm64,arm,amd64}`, `ios/arm64` (Spec A §1).
- `CODESTYLE.md` house rules: `self` receivers; usage+type naming; explicit struct field names; a doc
  comment on every file, type and func; no name repetition in comments; no all-caps in comments;
  top-level `func TestXxx`, no `t.Run` for positive tests, plain table loops instead.
- Canonical encoding only. The varint has exactly one valid encoding per value; a non-minimal prefix
  is a decode error; prefix `0b11` is reserved and rejected (RFC 9420 §2.1.2).
- No allocation before validation. `MaxVectorLength = 1 << 20` (1 MiB) for everything but the ratchet
  tree, which uses `MaxRatchetTreeLength = 1 << 24` (16 MiB) (Spec A §5.8 rule 2).
- Full consumption. A top-level decode that leaves bytes unconsumed is `ErrTrailingBytes`
  (Spec A §5.8 rule 3).
- Round-trip byte-exact. `encode(decode(x)) == x` for every accepted `x` (Spec A §5.8 rule 4). MLS
  signs over serialized forms, so a decoder that accepts two encodings of one object is a
  signature-bypass primitive.
- One codec. `connect/message` uses this package for records too, so both the MLS `opaque<V>` varint
  prefix and MASTER's `LP(x)` 32-bit big-endian prefix live here and nowhere else.
- **All commands run with cwd = `C:\Users\ryanm\Downloads\claude_sandbox_message\connect`**, which is
  the `github.com/urnetwork/connect` module root. Package paths are therefore `./mls/syntax`, not
  `./connect/mls/syntax`.
- **Git index hazard on this box.** Before every `git commit`, run `git ls-files | wc -l` and confirm
  the count has not dropped. Always `git add <explicit paths>`, never `git add -A`.
- Branch: `beta/message` on `Ryanmello07/connect`, cut from `origin/main`. MLS is **not** proposed
  upstream in v1, so there is no paired `-upstream` branch for this work (Spec A §2.1).
- **`research/slice1-interface-registry.md` is normative.** Every symbol in this plan that crosses a
  plan boundary is the registry's spelling; where this plan and that file disagreed, that file won
  and this plan was amended. §2 is this package's block, and §2.5 records the one override against
  it (O-1), which is adopted below.
- **⚠ EVERY `Reader` CODE SAMPLE BELOW IS STALE ON ERROR HANDLING. `decode.go` GOVERNS, NOT THE
  SAMPLE.** The samples in this plan were written before commit `3486cc3`, and they return bare
  sentinels — `return 0, ErrTruncated` — with no `self.err` entry check and no `setErr`. The shipped
  `Reader` does the opposite: **every failure latches into the sticky error with first-error-wins,
  every method checks `self.err` first, and no failure path advances the cursor.** That retrofit was
  made after review found a real vulnerability in Task 4: an ignored truncated `ReadUint32` left the
  cursor unmoved, so a following smaller `ReadUint16` re-read the same bytes and **succeeded
  silently**, returning `0x102, nil` — a structurally valid decode of the wrong fields, invisible to
  round-trip tests, in a codec whose serialized forms MLS signs over.

  So: when a sample and `decode.go` disagree, implement against `decode.go` and say so in your
  report. Any new `Reader` method must check `self.err` on entry, route every failure through
  `setErr`, and return `self.err` rather than the bare sentinel. Task 6's implementer hit this and
  called it correctly; the sample was not amended in place because the samples are illustrative and
  the shipped contract is the authority.

- **⚠ THE TESTS IN THIS PLAN ARE STALE IN THE SAME WAY THE SAMPLES ARE, AND THAT IS THE MORE
  DANGEROUS HALF.** They were specified in the same pass, so they encode the pre-`3486cc3` contract's
  expectations too: they assert the returned sentinel and the cursor position, and nothing observes
  whether a failure latched or whether the entry guard exists. Task 9 proved the consequence by
  measurement — its implementer correctly rejected the plan's `ReadOpaqueLP` sample and implemented
  against `decode.go`, and the controller then reverted the shipped method to the sample verbatim in
  an isolated copy and ran the suite: **all 40 tests passed.** The correct implementation and the
  vulnerable one were indistinguishable. The reproduction on the vulnerable version:
  `ReadOpaqueLP` on `00 00 00 40 11` fails without latching, the following `ReadUint32` returns
  `0x40` with a nil error, and `Done` reports `ErrTrailingBytes` — masking the real failure. The
  Task 4 vulnerability, reborn in a new method, invisible to every test specified for it.

  **So the rule, for every remaining task in this plan and for p2-p8: a deviation made on security
  grounds requires a test that FAILS on the version you rejected. Otherwise it is a comment, not a
  contract, and the next refactor deletes it.** Do not merely confirm your tests pass on your code;
  confirm they fail on the code you refused to write. An isolated copy of the package is the
  instrument — never patch a known-vulnerable version into the tracked tree to measure it.

The registry's four conventions, carried here verbatim (registry §0):

**C1 — one codec, one method set.** Every wire type in `package mls` implements exactly:

```go
MarshalMLS(w *syntax.Writer) error
UnmarshalMLS(r *syntax.Reader) error
```

and nothing else. No `MarshalTo`, no `MarshalTLS`, no `Marshal() ([]byte, error)`, no
`Parse<Type>(data []byte)` free constructor, no `tls:` struct tags, no reflection. Byte-level access
is `syntax.Marshal(&v)` / `syntax.Unmarshal(bs, &v)`. Every wire type carries
`var _ syntax.Codec = (*T)(nil)` in its own file so drift fails at build rather than at Gate 4.

The two sanctioned exceptions, because they are a different operation rather than a second spelling
of the same one:
- **Extension bodies.** `Extension.ExtensionData` is opaque, so a concrete extension converts
  bytes↔struct: `func (self *X) Encode() (Extension, error)` and
  `func ParseXExtension(data []byte) (*X, error)`. Owned per-extension.
- **p8's codec table.** Five decode/encode closures over `syntax.Marshal`/`Unmarshal`, built inside
  p8 (§9.4). They export no new `Parse*`/`Encode*` names.

**C2 — the syntax Writer is sticky *and* `MarshalMLS` returns an error.** See §2 override O-1.

**C3 — counts are `LeafCount`, indices are `LeafIndex`/`NodeIndex`, and tree-math arithmetic that
can be out of range returns an error.** p3's block (§4) is normative for every caller. `TreeSize`
does not exist.

**C4 — the GroupContext crosses a plan boundary as bytes.** Every p6 entry point takes
`groupContext []byte`. Callers obtain them from `syntax.Marshal(gc)` or `(*Group).GroupContext()`.
This is p6's deliberate decision and it is upheld: the GroupContext is inlined into
`FramedContentTBS` with no length prefix, and taking bytes makes that impossible to get wrong.

C1 and C2 are what this package exists to serve: `Marshaler` is the `MarshalMLS(w *Writer) error`
half of C1, and `Marshal` returns `errors.Join(v.MarshalMLS(w), w.Err())` so a semantic encoder
refusal and a buffer error both surface. C3 and C4 name no symbol this package produces or consumes;
they are carried so every plan's constraints read the same.

---

## File Structure

| File | Single responsibility |
|---|---|
| `connect/go.mod` | modified: add `toolchain go1.26.5` |
| `connect/mls/syntax/doc.go` | package doc: what the presentation language is, what the four rules are |
| `connect/mls/syntax/errors.go` | every sentinel error the package returns; nothing else |
| `connect/mls/syntax/encode.go` | `Writer`: construction, sticky error, fixed-width integers, raw bytes, `opaque<V>`, `LP(x)` |
| `connect/mls/syntax/decode.go` | `Reader`: cursor, limits, fixed-width integers, raw bytes, `opaque<V>`, `LP(x)`, sub-readers, `Done` |
| `connect/mls/syntax/varint.go` | the RFC 9420 §2.1.2 variable-length integer, both directions, plus the length constants |
| `connect/mls/syntax/optional.go` | `optional<T>` presence octet, both directions |
| `connect/mls/syntax/vector.go` | `T items<V>` — byte-length-prefixed vectors of elements, both directions |
| `connect/mls/syntax/marshal.go` | `Marshaler`/`Unmarshaler`/`Codec`, `Marshal`/`Unmarshal` and their limit variants, `CheckRoundTrip` |
| `connect/mls/syntax/vectors.go` | `VerifyDeserializationVector` — the family 16 runner; a non-test file because p8's registry shim calls it from `package mls` |
| `connect/mls/syntax/layering_test.go` | asserts the package's dependency graph is stdlib only |
| `connect/mls/syntax/errors_test.go` | asserts the sentinels are distinct and survive `errors.Is` through a join |
| `connect/mls/syntax/encode_test.go` | `Writer` integer, raw, `opaque<V>` and `LP(x)` behaviour |
| `connect/mls/syntax/decode_test.go` | `Reader` integer, raw, `opaque<V>`, `LP(x)`, sub-reader and full-consumption behaviour |
| `connect/mls/syntax/varint_test.go` | varint positive boundary table and the negative table the vectors omit |
| `connect/mls/syntax/vectors_test.go` | drives `VerifyDeserializationVector` over every vector in the vendored family 16 file |
| `connect/mls/syntax/optional_test.go` | presence octet 0, 1 and malformed |
| `connect/mls/syntax/vector_test.go` | byte-length-not-element-count, zero-progress guard, misaligned elements |
| `connect/mls/syntax/marshal_test.go` | full consumption, limit variants, `CheckRoundTrip` behaviour |
| `connect/mls/syntax/kat_test.go` | the byte-exact golden table every downstream package's bytes rest on |
| `connect/mls/syntax/alloc_test.go` | a hostile length prefix allocates nothing |
| `connect/mls/syntax/roundtrip_test.go` | the deterministic seeded round-trip property test |
| `connect/mls/syntax/fuzzgen_test.go` | `testStruct`/`testItem` and the structured generator that seeds the fuzz targets |
| `connect/mls/syntax/fuzz_test.go` | `FuzzVarint`, `FuzzOpaque`, `FuzzSyntaxStruct` and the shared corpus loader |
| `connect/mls/testdata/vectors/deserialization.json` | read, not created: p8 Task 6 is the single vendoring task for all sixteen mlswg files, and the one pin file is `connect/mls/interop/PINS.md` |
| `connect/.github/workflows/mls-syntax.yml` | per-commit CI: vet, race test, 60 s of each of the three fuzz targets |

---

### Task 1: Branch, package skeleton and the stdlib-only layering gate

**Files:**
- Create: `connect/mls/syntax/doc.go`
- Modify: `connect/go.mod`
- Test: `connect/mls/syntax/layering_test.go`

**Interfaces:**
- Consumes: nothing. This is the first task of wave 1 and the first code on `beta/message`.
- Produces: the Go package `github.com/urnetwork/connect/mls/syntax`, and the guarantee — enforced by
  test — that its dependency graph is stdlib only, which is what lets every later wave import it from
  anywhere without creating a cycle. **The `go.mod` edit is this task's and only this task's**
  (registry §11): `go 1.26.3` kept, `toolchain go1.26.5` added. p2 Task 1 makes its identical step
  conditional behind a `git diff --exit-code go.mod` guard (registry §2.5 O-3).

- [ ] **Step 1: Cut the branch and write the failing test**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git fetch origin
git checkout -b beta/message origin/main
mkdir -p mls/syntax
```

`mls/testdata/vectors/` is not created here: p8 Task 6 vendors the sixteen mlswg files into it and
owns the pin at `connect/mls/interop/PINS.md`.

`connect/mls/syntax/layering_test.go`:

```go
// The one structural gate on this package: it must depend on nothing outside the
// standard library. Spec A section 2.3 makes connect/mls/syntax stdlib only so the
// codec can be audited and fuzzed with no transport, no crypto and no third party
// code in the graph, and so importing it from any wave creates no cycle.
package syntax

import (
	"os/exec"
	"strings"
	"testing"
)

const selfImportPath = "github.com/urnetwork/connect/mls/syntax"

// Fails if go list -deps reports a dependency whose first path element is not stdlib.
func TestSyntaxImportsStdlibOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if dep == "" || dep == selfImportPath {
			continue
		}
		// every standard library import path has a dot free first element
		first, _, _ := strings.Cut(dep, "/")
		if strings.Contains(first, ".") {
			t.Errorf("non stdlib dependency %s; this package is stdlib only per spec A section 2.3", dep)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestSyntaxImportsStdlibOnly -v`

Expected: **PASS, and that is correct here** — this gate is the one task in the plan whose test
cannot go red at its own scope, so do not spend time hunting for the failure. `go list -deps .`
resolves a directory holding only a `_test.go` file without complaint in go1.26.5, and once `doc.go`
exists it has no imports, so the dependency set is stdlib-only either way. `go build .` *would* fail
on the test-only directory, which is what an earlier draft of this step described, but the test does
not shell out to `go build`.

The assertion is still sound and still load-bearing: it fires the moment any file in this package
gains an import whose first path element contains a dot — `connect`, `connect/mls`,
`golang.org/x/crypto`. Verify that claim once, by hand, rather than trusting it: temporarily add
`_ "golang.org/x/crypto/chacha20poly1305"` to `doc.go`, re-run, confirm it fails naming that path,
then remove it. That is this task's real red step.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/doc.go`:

```go
// The TLS presentation language of RFC 8446 section 3 as MLS uses it: fixed width
// integers, opaque V with the RFC 9420 section 2.1.2 variable length prefix,
// optional T, and byte length prefixed vectors. The master protocol design's LP(x) 32 bit big endian
// prefix lives here too, because connect/message encodes records through this same
// package and one length prefix implementation means one place for a length prefix
// bug to be.
//
// Four rules, each with a fuzz property behind it (spec A section 5.8):
//
//  1. Canonical encoding only. The variable length prefix has exactly one valid
//     encoding per value; a non minimal prefix is a decode error.
//  2. No allocation before validation. A declared length is checked against the
//     configured maximum and against the bytes that remain before any make.
//  3. Full consumption. A top level decode fails if bytes remain.
//  4. Round trip byte exact. encode(decode(x)) equals x for every accepted x.
//
// Rule 4 is the load bearing one: MLS signs over serialized forms, so a decoder
// that accepts two encodings of one object is a signature bypass primitive.
//
// Writer carries a sticky error, so the leaf writes — WriteUint16, WriteOpaque and
// the rest — return nothing and one check at Bytes covers a whole encoder. Three
// things do return an error: MarshalMLS itself, and the two higher order callbacks
// WriteOptional and WriteVector. An MLS encoder has semantic refusals that are not
// buffer errors — a credential type outside the v1 profile, a content arm that
// disagrees with its discriminant — and a dropped encoder refusal produces wrong
// signed bytes rather than a failure, so those need a channel the sticky error does
// not give them. Marshal joins the two, so the semantic error and the buffer error
// both surface. Reader returns an error per read, because decoding is a branch per
// field and every one of them matters.
package syntax
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestSyntaxImportsStdlibOnly -v`
Expected: PASS

- [ ] **Step 5: Pin the toolchain and commit**

Edit `connect/go.mod` so its first three directives read exactly:

```
module github.com/urnetwork/connect

go 1.26.3

toolchain go1.26.5
```

The `go` directive is left at 1.26.3 — raising it would raise the language version floor for the
whole of `connect`, which is not this slice's change. `toolchain` pins the compiler.

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
go version && go build ./...
git ls-files | wc -l
git add go.mod mls/syntax/doc.go mls/syntax/layering_test.go && git commit -m "feat(mls): add connect/mls/syntax package skeleton with a stdlib only layering gate"
```

---

### Task 2: Typed errors and the length limits

**Files:**
- Create: `connect/mls/syntax/errors.go`, `connect/mls/syntax/varint.go`
- Test: `connect/mls/syntax/errors_test.go`

**Interfaces:**
- Consumes: the package from Task 1.
- Produces — registry §2.1 verbatim, arrows and all, so the consuming plans are visible at the
  declaration site:
```go
const MaxVarint uint32 = 1<<30 - 1        // 1073741823                     → p8
const MaxVectorLength int = 1 << 20       // 1 MiB, every field but the tree → p5,p6,p7,p8
const MaxRatchetTreeLength int = 1 << 24  // 16 MiB, the ratchet tree only   → p5,p7

var ErrTruncated error            // input ended before the value did          → p5,p6,p8
var ErrTrailingBytes error        // a top-level decode left bytes unconsumed  → p5,p6,p7,p8
var ErrVarintReserved error       // varint prefix 0b11                        → p8
var ErrVarintNotMinimal error     // more octets than the value needs          → p6,p8
var ErrVarintOverflow error       // encode side: value above MaxVarint        → p8
var ErrLengthExceedsInput error   // declared length exceeds bytes remaining   → p8
var ErrLengthExceedsMax error     // declared length exceeds the reader limit  → p5,p7,p8
var ErrOptionalPresence error     // presence octet neither 0 nor 1            → p5,p6
var ErrZeroLengthElement error    // a vector element decoder consumed 0 bytes → p8
var ErrNegativeLength error
var ErrRoundTripNotByteExact error                                          // → p8
var ErrRoundTripNotStable error                                             // → p8
```
  Every failure in this package returns one of these, possibly joined. Downstream plans compare with
  `errors.Is` and never parse an error string. Two renames the registry settles land here rather than
  in the consumers: `ErrNonMinimalLength` (p6) is `ErrVarintNotMinimal`, and `ErrVectorTooLong`
  (p7, p8) is `ErrLengthExceedsMax`. `MaxVectorLength` is `int` — not `uint64` and not untyped — so
  it passes to `UnmarshalLimit` with no conversion at the call site.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/errors_test.go`:

```go
// The sentinels are the package's whole error contract, so they are asserted to be
// distinct from each other and to survive the joins the package uses to add context.
package syntax

import (
	"errors"
	"testing"
)

func TestErrorSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrTruncated,
		ErrTrailingBytes,
		ErrVarintReserved,
		ErrVarintNotMinimal,
		ErrVarintOverflow,
		ErrLengthExceedsInput,
		ErrLengthExceedsMax,
		ErrOptionalPresence,
		ErrZeroLengthElement,
		ErrNegativeLength,
		ErrRoundTripNotByteExact,
		ErrRoundTripNotStable,
	}
	for i, a := range sentinels {
		if a == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		for j, b := range sentinels {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel %d and sentinel %d are not distinct: %v", i, j, a)
			}
		}
	}
}

func TestErrorSentinelsSurviveAJoin(t *testing.T) {
	joined := errors.Join(ErrLengthExceedsMax, ErrTruncated)
	if !errors.Is(joined, ErrLengthExceedsMax) {
		t.Errorf("join lost ErrLengthExceedsMax")
	}
	if !errors.Is(joined, ErrTruncated) {
		t.Errorf("join lost ErrTruncated")
	}
	if errors.Is(joined, ErrTrailingBytes) {
		t.Errorf("join matched an unrelated sentinel")
	}
}

func TestLengthLimits(t *testing.T) {
	if MaxVarint != 1073741823 {
		t.Errorf("MaxVarint is %d, want 1073741823 per rfc 9420 section 2.1.2", MaxVarint)
	}
	if MaxVectorLength != 1<<20 {
		t.Errorf("MaxVectorLength is %d, want 1 MiB per spec A section 5.8", MaxVectorLength)
	}
	if MaxRatchetTreeLength != 1<<24 {
		t.Errorf("MaxRatchetTreeLength is %d, want 16 MiB per spec A section 5.8", MaxRatchetTreeLength)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "TestError|TestLengthLimits" -v`
Expected: FAIL — build error `undefined: ErrTruncated`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/errors.go`:

```go
// The package's complete error contract. Every failure path returns one of these
// sentinels, possibly joined with another for context. Callers compare with
// errors.Is and never parse a string, so the messages are for humans only.
package syntax

import "errors"

var (
	ErrTruncated             = errors.New("mls syntax: input truncated")
	ErrTrailingBytes         = errors.New("mls syntax: trailing bytes after top level value")
	ErrVarintReserved        = errors.New("mls syntax: varint prefix 0b11 is reserved")
	ErrVarintNotMinimal      = errors.New("mls syntax: varint is not minimally encoded")
	ErrVarintOverflow        = errors.New("mls syntax: varint value exceeds 2^30-1")
	ErrLengthExceedsInput    = errors.New("mls syntax: declared length exceeds remaining input")
	ErrLengthExceedsMax      = errors.New("mls syntax: declared length exceeds the configured maximum")
	ErrOptionalPresence      = errors.New("mls syntax: optional presence octet is neither 0 nor 1")
	ErrZeroLengthElement     = errors.New("mls syntax: vector element consumed zero bytes")
	ErrNegativeLength        = errors.New("mls syntax: negative length")
	ErrRoundTripNotByteExact = errors.New("mls syntax: re-encoding an accepted value did not reproduce its bytes")
	ErrRoundTripNotStable    = errors.New("mls syntax: decoding a re-encoded value did not reproduce the value")
)
```

`connect/mls/syntax/varint.go` (constants only for now; the codec arrives in Tasks 5 and 6):

```go
// The RFC 9420 section 2.1.2 variable length integer, and the length limits every
// variable length read in this package is bounded by.
package syntax

const (
	// the largest value the two bit prefixed varint can carry
	MaxVarint uint32 = 1<<30 - 1
	// the default cap on any single variable length field, spec A section 5.8
	MaxVectorLength int = 1 << 20
	// the cap raised for the ratchet tree only; tree_sync and group decode through
	// UnmarshalLimit with this value, everything else uses the default
	MaxRatchetTreeLength int = 1 << 24
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "TestError|TestLengthLimits" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/errors.go mls/syntax/varint.go mls/syntax/errors_test.go && git commit -m "feat(mls/syntax): add the typed error sentinels and the length limits"
```

---

### Task 3: Writer — fixed-width integers and raw bytes

**Files:**
- Create: `connect/mls/syntax/encode.go`
- Test: `connect/mls/syntax/encode_test.go`

**Interfaces:**
- Consumes: `ErrLengthExceedsMax`, `MaxVectorLength` from Task 2.
- Produces — the construction, inspection and fixed-width half of registry §2.2, verbatim:
```go
type Writer struct{ ... }                        // not safe for concurrent use  → p2,p4,p5,p6,p7
func NewWriter() *Writer                                                      // → p2,p4,p5,p6,p7
func NewWriterLimit(maxVectorLength int) *Writer                              // → p5,p7
func (self *Writer) Bytes() ([]byte, error)      // undefined when err non-nil  → p2,p4,p5,p6,p7
func (self *Writer) Err() error
func (self *Writer) Len() int
func (self *Writer) MaxVectorLength() int
func (self *Writer) WriteUint8(v uint8)                                       // → p4,p5,p6,p7
func (self *Writer) WriteUint16(v uint16)                                     // → p2,p4,p5,p6,p7
func (self *Writer) WriteUint32(v uint32)                                     // → p2,p4,p5,p6,p7
func (self *Writer) WriteUint64(v uint64)                                     // → p4,p5,p6,p7
func (self *Writer) WriteRaw(bs []byte)          // opaque x[N], no prefix     → p4,p5,p6,p7
```
  All integers are big-endian. Every write after the first error is a no-op, so one check at
  `Bytes()` suffices. Tasks 5, 8, 9 and 11 add the remaining five methods of §2.2 —
  `WriteVarint`, `WriteOpaque`, `WriteOpaqueLP` and `WriteOptional` — and the method set is closed
  at that: `WriteBytes` (p4) is `WriteRaw`, `WriteOpaqueVec` (p5 task bodies) is `WriteOpaque`, and
  `Bytes() []byte` (p6) does not exist, because a caller that cannot see the error will ship a
  truncated encoding.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/encode_test.go`:

```go
// Writer behaviour: big endian integers, unprefixed raw bytes, and the sticky error
// that makes a single check at Bytes sufficient.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

func TestWriterIntegersAreBigEndian(t *testing.T) {
	w := NewWriter()
	w.WriteUint8(0x2a)
	w.WriteUint16(0x0102)
	w.WriteUint32(0x01020304)
	w.WriteUint64(0x0102030405060708)
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{
		0x2a,
		0x01, 0x02,
		0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	if !bytes.Equal(out, want) {
		t.Errorf("encoded %x, want %x", out, want)
	}
	if w.Len() != len(want) {
		t.Errorf("Len is %d, want %d", w.Len(), len(want))
	}
}

func TestWriterRawTakesNoPrefix(t *testing.T) {
	w := NewWriter()
	w.WriteRaw([]byte{0xaa, 0xbb, 0xcc})
	w.WriteRaw(nil)
	w.WriteRaw([]byte{})
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{0xaa, 0xbb, 0xcc}) {
		t.Errorf("encoded %x, want aabbcc", out)
	}
}

func TestWriterErrorIsStickyAndSuppressesLaterWrites(t *testing.T) {
	w := NewWriter()
	w.WriteUint8(0x01)
	w.setErr(ErrLengthExceedsMax)
	w.setErr(ErrTruncated)
	w.WriteUint64(0xffffffffffffffff)
	if !errors.Is(w.Err(), ErrLengthExceedsMax) {
		t.Errorf("Err is %v, want the first error ErrLengthExceedsMax", w.Err())
	}
	out, err := w.Bytes()
	if !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("Bytes returned %v, want ErrLengthExceedsMax", err)
	}
	if out != nil {
		t.Errorf("Bytes returned %x alongside an error, want nil", out)
	}
	if w.Len() != 1 {
		t.Errorf("Len is %d, want 1: writes after an error must be no ops", w.Len())
	}
}

func TestWriterLimitIsCarried(t *testing.T) {
	if NewWriter().MaxVectorLength() != MaxVectorLength {
		t.Errorf("NewWriter did not take the default limit")
	}
	if NewWriterLimit(MaxRatchetTreeLength).MaxVectorLength() != MaxRatchetTreeLength {
		t.Errorf("NewWriterLimit did not take the given limit")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestWriter -v`
Expected: FAIL — build error `undefined: NewWriter`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/encode.go`:

```go
// The encode half of the codec. Writer accumulates bytes and carries a sticky
// error: the first failure is retained, every write after it is a no op, and Bytes
// reports it. Encoding a value is a straight line of writes, so one check at the
// end is both sufficient and impossible to skip, because Bytes will not hand back
// the bytes without also handing back the error.
//
// Not safe for concurrent use.
package syntax

import "encoding/binary"

type Writer struct {
	bs              []byte
	err             error
	maxVectorLength int
}

// a writer bounded by the default limit, which is every case but the ratchet tree
func NewWriter() *Writer {
	return &Writer{
		bs:              nil,
		err:             nil,
		maxVectorLength: MaxVectorLength,
	}
}

// a writer bounded by a caller chosen limit; the ratchet tree paths pass
// MaxRatchetTreeLength and nothing else raises it
func NewWriterLimit(maxVectorLength int) *Writer {
	return &Writer{
		bs:              nil,
		err:             nil,
		maxVectorLength: maxVectorLength,
	}
}

// the accumulated bytes, or the first error seen; the bytes are nil when the error
// is non nil, so a caller cannot take a truncated encoding by accident
func (self *Writer) Bytes() ([]byte, error) {
	if self.err != nil {
		return nil, self.err
	}
	return self.bs, nil
}

func (self *Writer) Err() error {
	return self.err
}

func (self *Writer) Len() int {
	return len(self.bs)
}

func (self *Writer) MaxVectorLength() int {
	return self.maxVectorLength
}

// first error wins, so the reported failure is the cause rather than a downstream
// symptom of it
func (self *Writer) setErr(err error) {
	if self.err == nil {
		self.err = err
	}
}

func (self *Writer) WriteUint8(v uint8) {
	if self.err != nil {
		return
	}
	self.bs = append(self.bs, v)
}

func (self *Writer) WriteUint16(v uint16) {
	if self.err != nil {
		return
	}
	self.bs = binary.BigEndian.AppendUint16(self.bs, v)
}

func (self *Writer) WriteUint32(v uint32) {
	if self.err != nil {
		return
	}
	self.bs = binary.BigEndian.AppendUint32(self.bs, v)
}

func (self *Writer) WriteUint64(v uint64) {
	if self.err != nil {
		return
	}
	self.bs = binary.BigEndian.AppendUint64(self.bs, v)
}

// opaque x[N]: the bytes with no length prefix, for a field whose length the
// structure already fixes
func (self *Writer) WriteRaw(bs []byte) {
	if self.err != nil {
		return
	}
	self.bs = append(self.bs, bs...)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestWriter -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/encode.go mls/syntax/encode_test.go && git commit -m "feat(mls/syntax): add Writer with big endian integers, raw bytes and a sticky error"
```

---

### Task 4: Reader — cursor, fixed-width integers, raw bytes and full consumption

**Files:**
- Create: `connect/mls/syntax/decode.go`
- Test: `connect/mls/syntax/decode_test.go`

**Interfaces:**
- Consumes: `ErrTruncated`, `ErrTrailingBytes`, `ErrNegativeLength`, `MaxVectorLength` from Task 2.
- Produces — the cursor and fixed-width half of registry §2.3, verbatim:
```go
type Reader struct{ ... }                                    // not safe for concurrent use
func NewReader(bs []byte) *Reader                                             // → p2,p4,p5,p6,p7,p8
func NewReaderLimit(bs []byte, maxVectorLength int) *Reader                   // → p5,p7
func (self *Reader) Offset() int
func (self *Reader) Remaining() int                                           // → p6
func (self *Reader) Empty() bool                                              // → p5,p6
func (self *Reader) MaxVectorLength() int
func (self *Reader) Done() error             // ErrTrailingBytes when bytes remain → p4,p5,p6,p7
func (self *Reader) ReadUint8() (uint8, error)                                // → p4,p5,p6,p7
func (self *Reader) ReadUint16() (uint16, error)                              // → p4,p5,p6,p7
func (self *Reader) ReadUint32() (uint32, error)                              // → p4,p5,p6,p7
func (self *Reader) ReadUint64() (uint64, error)                              // → p4,p5,p6,p7
func (self *Reader) ReadRaw(n int) ([]byte, error)     // opaque x[N]; a COPY  → p4,p5,p6,p7
```
  A failed read never advances the cursor. `ReadRaw` returns a copy, never a view into the input, so
  a decoded field cannot be mutated through the buffer it came from and cannot pin it. Tasks 6, 8, 9,
  10 and 11 add the rest of §2.3 — `ReadVarint`, `ReadOpaque`, `ReadOpaqueLP`, `ReadSub`, `ReadSubLP`
  and `ReadOptional` — and the method set is closed at that: `Finish()` (p6) is `Done()`, and
  `Rest()` (p6) does not exist, because a decoder that wants the tail writes
  `r.ReadRaw(r.Remaining())`, which is explicit about consuming it.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/decode_test.go`:

```go
// Reader behaviour: big endian integers, copied raw bytes, a cursor that a failed
// read never advances, and the full consumption rule.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

func TestReaderIntegersAreBigEndian(t *testing.T) {
	r := NewReader([]byte{
		0x2a,
		0x01, 0x02,
		0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	})
	if v, err := r.ReadUint8(); err != nil || v != 0x2a {
		t.Fatalf("ReadUint8 gave %#x, %v", v, err)
	}
	if v, err := r.ReadUint16(); err != nil || v != 0x0102 {
		t.Fatalf("ReadUint16 gave %#x, %v", v, err)
	}
	if v, err := r.ReadUint32(); err != nil || v != 0x01020304 {
		t.Fatalf("ReadUint32 gave %#x, %v", v, err)
	}
	if v, err := r.ReadUint64(); err != nil || v != 0x0102030405060708 {
		t.Fatalf("ReadUint64 gave %#x, %v", v, err)
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v, want nil", err)
	}
}

func TestReaderTruncatedReadDoesNotAdvance(t *testing.T) {
	cases := []struct {
		input []byte
		read  func(*Reader) error
	}{
		{[]byte{}, func(r *Reader) error { _, err := r.ReadUint8(); return err }},
		{[]byte{0x01}, func(r *Reader) error { _, err := r.ReadUint16(); return err }},
		{[]byte{0x01, 0x02, 0x03}, func(r *Reader) error { _, err := r.ReadUint32(); return err }},
		{[]byte{0x01, 0x02, 0x03, 0x04}, func(r *Reader) error { _, err := r.ReadUint64(); return err }},
		{[]byte{0x01}, func(r *Reader) error { _, err := r.ReadRaw(2); return err }},
	}
	for i, c := range cases {
		r := NewReader(c.input)
		if err := c.read(r); !errors.Is(err, ErrTruncated) {
			t.Errorf("case %d gave %v, want ErrTruncated", i, err)
		}
		if r.Offset() != 0 {
			t.Errorf("case %d advanced the cursor to %d on a failed read", i, r.Offset())
		}
	}
}

func TestReaderRawReturnsACopy(t *testing.T) {
	input := []byte{0xaa, 0xbb, 0xcc}
	r := NewReader(input)
	out, err := r.ReadRaw(3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out[0] = 0xff
	if input[0] != 0xaa {
		t.Errorf("ReadRaw aliased the input; mutating the result changed the source buffer")
	}
	if !bytes.Equal(out, []byte{0xff, 0xbb, 0xcc}) {
		t.Errorf("copy is %x, want ffbbcc", out)
	}
}

func TestReaderRawRejectsANegativeLength(t *testing.T) {
	r := NewReader([]byte{0xaa})
	if _, err := r.ReadRaw(-1); !errors.Is(err, ErrNegativeLength) {
		t.Errorf("ReadRaw(-1) gave %v, want ErrNegativeLength", err)
	}
}

func TestReaderDoneRejectsTrailingBytes(t *testing.T) {
	r := NewReader([]byte{0x01, 0x02})
	if _, err := r.ReadUint8(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := r.Done(); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("Done gave %v, want ErrTrailingBytes", err)
	}
	if r.Remaining() != 1 || r.Empty() {
		t.Errorf("Remaining is %d and Empty is %v, want 1 and false", r.Remaining(), r.Empty())
	}
}

func TestReaderLimitIsCarried(t *testing.T) {
	if NewReader(nil).MaxVectorLength() != MaxVectorLength {
		t.Errorf("NewReader did not take the default limit")
	}
	if NewReaderLimit(nil, MaxRatchetTreeLength).MaxVectorLength() != MaxRatchetTreeLength {
		t.Errorf("NewReaderLimit did not take the given limit")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestReader -v`
Expected: FAIL — build error `undefined: NewReader`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/decode.go`:

```go
// The decode half of the codec. Reader is a cursor over a byte slice. Every read is
// bounds checked before it advances, so a failed read leaves the cursor where it
// was and the first error is always the cause. Every declared length is checked
// against the configured maximum and against the bytes that remain before any make,
// so a hostile length prefix can never size an allocation.
//
// Byte results are copies rather than views into the input: MLS verifies a
// signature over serialized bytes and then uses the decoded fields, so a field that
// aliases a buffer someone else may reuse is a correctness hazard as well as a way
// to pin a large buffer behind a small field. Sub readers are the one exception and
// are documented as views.
//
// Not safe for concurrent use.
package syntax

import "encoding/binary"

type Reader struct {
	bs              []byte
	pos             int
	maxVectorLength int
}

// a reader bounded by the default limit, which is every case but the ratchet tree
func NewReader(bs []byte) *Reader {
	return &Reader{
		bs:              bs,
		pos:             0,
		maxVectorLength: MaxVectorLength,
	}
}

// a reader bounded by a caller chosen limit; the ratchet tree paths pass
// MaxRatchetTreeLength and nothing else raises it
func NewReaderLimit(bs []byte, maxVectorLength int) *Reader {
	return &Reader{
		bs:              bs,
		pos:             0,
		maxVectorLength: maxVectorLength,
	}
}

func (self *Reader) Offset() int {
	return self.pos
}

func (self *Reader) Remaining() int {
	return len(self.bs) - self.pos
}

func (self *Reader) Empty() bool {
	return self.pos >= len(self.bs)
}

func (self *Reader) MaxVectorLength() int {
	return self.maxVectorLength
}

// the full consumption rule: a decoder that ignores a tail accepts two encodings of
// one object, and MLS signs over serialized forms
func (self *Reader) Done() error {
	if !self.Empty() {
		return ErrTrailingBytes
	}
	return nil
}

func (self *Reader) ReadUint8() (uint8, error) {
	if self.Remaining() < 1 {
		return 0, ErrTruncated
	}
	v := self.bs[self.pos]
	self.pos += 1
	return v, nil
}

func (self *Reader) ReadUint16() (uint16, error) {
	if self.Remaining() < 2 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint16(self.bs[self.pos:])
	self.pos += 2
	return v, nil
}

func (self *Reader) ReadUint32() (uint32, error) {
	if self.Remaining() < 4 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint32(self.bs[self.pos:])
	self.pos += 4
	return v, nil
}

func (self *Reader) ReadUint64() (uint64, error) {
	if self.Remaining() < 8 {
		return 0, ErrTruncated
	}
	v := binary.BigEndian.Uint64(self.bs[self.pos:])
	self.pos += 8
	return v, nil
}

// opaque x[N]: the result is a copy and is never nil
func (self *Reader) ReadRaw(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrNegativeLength
	}
	if n > self.Remaining() {
		return nil, ErrTruncated
	}
	out := make([]byte, n)
	copy(out, self.bs[self.pos:self.pos+n])
	self.pos += n
	return out, nil
}

// the common tail of every length prefixed read: the limit first, then the bytes
// that remain, then and only then may the caller allocate
func (self *Reader) takeLength(n uint32) (int, error) {
	if int64(n) > int64(self.maxVectorLength) {
		return 0, ErrLengthExceedsMax
	}
	if int64(n) > int64(self.Remaining()) {
		return 0, ErrLengthExceedsInput
	}
	return int(n), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestReader -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/decode.go mls/syntax/decode_test.go && git commit -m "feat(mls/syntax): add Reader with a non advancing failure path and copied byte results"
```

---

### Task 5: Varint encode

**Files:**
- Modify: `connect/mls/syntax/varint.go`
- Test: `connect/mls/syntax/varint_test.go`

**Interfaces:**
- Consumes: `Writer` from Task 3; `MaxVarint`, `ErrVarintOverflow` from Task 2.
- Produces:
```go
func (self *Writer) WriteVarint(v uint32)                                     // → p8
```
  Sets `ErrVarintOverflow` above `MaxVarint`. Always emits the minimal form: 1 octet for `0..63`, 2
  for `64..16383`, 4 for `16384..1073741823`. p8's only use is
  `syntax.NewWriter()` + `WriteVarint`; the append-style `syntax.WriteVarint(dst, v) []byte` its
  plan named does not exist here (registry §2.5 O-2).

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/varint_test.go`:

```go
// The RFC 9420 section 2.1.2 varint, both directions. The encoder emits exactly one
// form per value and the decoder accepts exactly that form, because a decoder that
// accepts a second encoding of one length turns a signed structure into a malleable
// one.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

// the boundary of every prefix width, from rfc 9420 section 2.1.2
var varintBoundaries = []struct {
	value   uint32
	encoded []byte
}{
	{0, []byte{0x00}},
	{13, []byte{0x0d}},
	{54, []byte{0x36}},
	{63, []byte{0x3f}},
	{64, []byte{0x40, 0x40}},
	{389, []byte{0x41, 0x85}},
	{2730, []byte{0x4a, 0xaa}},
	{4095, []byte{0x4f, 0xff}},
	{16383, []byte{0x7f, 0xff}},
	{16384, []byte{0x80, 0x00, 0x40, 0x00}},
	{48879, []byte{0x80, 0x00, 0xbe, 0xef}},
	{57005, []byte{0x80, 0x00, 0xde, 0xad}},
	{1073741823, []byte{0xbf, 0xff, 0xff, 0xff}},
}

func TestWriteVarintIsMinimal(t *testing.T) {
	for _, c := range varintBoundaries {
		w := NewWriter()
		w.WriteVarint(c.value)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("value %d: unexpected error %v", c.value, err)
		}
		if !bytes.Equal(out, c.encoded) {
			t.Errorf("value %d encoded to %x, want %x", c.value, out, c.encoded)
		}
	}
}

func TestWriteVarintRejectsValuesAboveTheRange(t *testing.T) {
	for _, v := range []uint32{MaxVarint + 1, 0x40000000, 0x7fffffff, 0xffffffff} {
		w := NewWriter()
		w.WriteVarint(v)
		if _, err := w.Bytes(); !errors.Is(err, ErrVarintOverflow) {
			t.Errorf("value %d gave %v, want ErrVarintOverflow", v, err)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestWriteVarint -v`
Expected: FAIL — build error `w.WriteVarint undefined (type *Writer has no field or method WriteVarint)`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/syntax/varint.go`:

```go
// The minimal form and nothing else: one octet below 64, two below 16384, four up
// to MaxVarint. The prefix is the base 2 logarithm of the octet count in the two
// most significant bits of the first octet.
func (self *Writer) WriteVarint(v uint32) {
	if self.err != nil {
		return
	}
	switch {
	case v <= 0x3f:
		self.bs = append(self.bs, byte(v))
	case v <= 0x3fff:
		self.bs = append(self.bs, byte(v>>8)|0x40, byte(v))
	case v <= MaxVarint:
		self.bs = append(self.bs, byte(v>>24)|0x80, byte(v>>16), byte(v>>8), byte(v))
	default:
		self.setErr(ErrVarintOverflow)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestWriteVarint -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/varint.go mls/syntax/varint_test.go && git commit -m "feat(mls/syntax): add the minimal form varint encoder"
```

---

### Task 6: Varint decode

**Files:**
- Modify: `connect/mls/syntax/varint.go`
- Test: `connect/mls/syntax/varint_test.go`

**Interfaces:**
- Consumes: `Reader` from Task 4; `ErrVarintReserved`, `ErrVarintNotMinimal`, `ErrTruncated` from Task 2.
- Produces:
```go
func (self *Reader) ReadVarint() (uint32, error)                              // → p8
```
  Rejects prefix `0b11` with `ErrVarintReserved`, a non-minimal encoding with `ErrVarintNotMinimal`,
  and a short input with `ErrTruncated`. A failed read does not advance the cursor. It is
  `uint32`-valued and reached as `syntax.NewReader(b).ReadVarint()`; p8's
  `syntax.ReadVarint(b) (uint64, int, error)` does not exist here (registry §2.5 O-2).

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/syntax/varint_test.go`:

```go
func TestReadVarintAcceptsTheMinimalForm(t *testing.T) {
	for _, c := range varintBoundaries {
		r := NewReader(c.encoded)
		got, err := r.ReadVarint()
		if err != nil {
			t.Fatalf("%x: unexpected error %v", c.encoded, err)
		}
		if got != c.value {
			t.Errorf("%x decoded to %d, want %d", c.encoded, got, c.value)
		}
		if err := r.Done(); err != nil {
			t.Errorf("%x left %d bytes unconsumed", c.encoded, r.Remaining())
		}
	}
}

// deserialization.json carries only well formed headers, so the rejection half of
// rule 1 is ours to write. Every row here is a length that has a shorter encoding,
// a reserved prefix, or no body at all.
func TestReadVarintRejectsEverythingButTheMinimalForm(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"two octet form carrying zero", []byte{0x40, 0x00}, ErrVarintNotMinimal},
		{"two octet form carrying 63", []byte{0x40, 0x3f}, ErrVarintNotMinimal},
		{"four octet form carrying zero", []byte{0x80, 0x00, 0x00, 0x00}, ErrVarintNotMinimal},
		{"four octet form carrying 63", []byte{0x80, 0x00, 0x00, 0x3f}, ErrVarintNotMinimal},
		{"four octet form carrying 16383", []byte{0x80, 0x00, 0x3f, 0xff}, ErrVarintNotMinimal},
		{"reserved prefix, low", []byte{0xc0}, ErrVarintReserved},
		{"reserved prefix, high", []byte{0xff, 0xff, 0xff, 0xff}, ErrVarintReserved},
		{"empty input", []byte{}, ErrTruncated},
		{"two octet form missing its second octet", []byte{0x40}, ErrTruncated},
		{"four octet form missing its last octet", []byte{0x80, 0x00, 0x40}, ErrTruncated},
	}
	for _, c := range cases {
		r := NewReader(c.input)
		got, err := r.ReadVarint()
		if !errors.Is(err, c.wantErr) {
			t.Errorf("%s (%x) gave %d, %v; want %v", c.name, c.input, got, err, c.wantErr)
		}
		if r.Offset() != 0 {
			t.Errorf("%s advanced the cursor to %d on a failed read", c.name, r.Offset())
		}
	}
}

// a varint never reads past its own octets, so it composes with whatever follows
func TestReadVarintConsumesOnlyItsOwnOctets(t *testing.T) {
	r := NewReader([]byte{0x40, 0x40, 0xde, 0xad})
	v, err := r.ReadVarint()
	if err != nil || v != 64 {
		t.Fatalf("ReadVarint gave %d, %v; want 64, nil", v, err)
	}
	if r.Offset() != 2 {
		t.Fatalf("consumed %d octets, want 2", r.Offset())
	}
	rest, err := r.ReadRaw(2)
	if err != nil || !bytes.Equal(rest, []byte{0xde, 0xad}) {
		t.Errorf("tail is %x, %v; want dead, nil", rest, err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestReadVarint -v`
Expected: FAIL — build error `r.ReadVarint undefined (type *Reader has no field or method ReadVarint)`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/syntax/varint.go`:

```go
// The first octet's two most significant bits give the width, so the width is known
// before anything is consumed and the whole varint is taken atomically: a failure
// leaves the cursor untouched. The minimality check is the range check for the
// width below, which is what makes the encoding canonical.
func (self *Reader) ReadVarint() (uint32, error) {
	if self.Remaining() < 1 {
		return 0, ErrTruncated
	}
	b0 := self.bs[self.pos]
	switch b0 >> 6 {
	case 0:
		self.pos += 1
		return uint32(b0 & 0x3f), nil
	case 1:
		if self.Remaining() < 2 {
			return 0, ErrTruncated
		}
		v := uint32(b0&0x3f)<<8 | uint32(self.bs[self.pos+1])
		if v < 0x40 {
			return 0, ErrVarintNotMinimal
		}
		self.pos += 2
		return v, nil
	case 2:
		if self.Remaining() < 4 {
			return 0, ErrTruncated
		}
		v := uint32(b0&0x3f)<<24 |
			uint32(self.bs[self.pos+1])<<16 |
			uint32(self.bs[self.pos+2])<<8 |
			uint32(self.bs[self.pos+3])
		if v < 0x4000 {
			return 0, ErrVarintNotMinimal
		}
		self.pos += 4
		return v, nil
	default:
		return 0, ErrVarintReserved
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestReadVarint -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/varint.go mls/syntax/varint_test.go && git commit -m "feat(mls/syntax): add the canonical varint decoder rejecting reserved and non minimal forms"
```

---

### Task 7: Test-vector family 16 — `VerifyDeserializationVector`, both directions

**Files:**
- Create: `connect/mls/syntax/vectors.go`
- Test: `connect/mls/syntax/vectors_test.go`
- Read, not created: `connect/mls/testdata/vectors/deserialization.json`

**Interfaces:**
- Consumes: `ReadVarint` from Task 6, `WriteVarint` from Task 5, `NewReader`/`NewWriter`/`Done` from
  Tasks 3 and 4, and the vendored corpus file. **p8 Task 6 is the single vendoring task** for all
  sixteen mlswg files plus `testdata/vectors/VECTORS.sha256`, and the one pin file is
  `connect/mls/interop/PINS.md` (Spec A §4.2.4) with machine-readable `mlswg=<sha>` and
  `openmls=<sha>` lines. This plan vendors nothing, pins nothing and asserts nothing about pins:
  `connect/mls/PINS.md` and `connect/mls/testdata/vectors/PINS.md` do not exist. p8 Task 6 is wave 1
  like this plan, and this task sequences after it.
- Produces:
```go
func VerifyDeserializationVector(t *testing.T, raw json.RawMessage)           // → p8
```
  **Family 16 is implemented once, here**, against the `Reader.ReadVarint` / `Writer.WriteVarint`
  methods this package actually ships. p8 Task 8 is a three-line shim that registers
  `VectorFamily{Number: 16, ..., Verify: <this>}`; its own runner, written against free functions
  that do not exist, is deleted. The function lives in a **non-test file** because a symbol declared
  in a `_test.go` file is visible only inside its own test binary, and that shim is in `package mls`
  — a `_test.go` home would leave family 16 with no owner able to reach it. The signature is the
  registry's `Verify func(t *testing.T, raw json.RawMessage)` field type exactly, so the shim is an
  assignment rather than a wrapper.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/vectors_test.go`:

```go
// Family 16 driven over every vector in the file p8 task 6 vendors and pins. The
// runner itself is exported from vectors.go and is what the wave 4 vector registry
// calls; it is exercised here as well so a varint defect is red in this package's own
// suite rather than only in a later wave.
package syntax

import (
	"encoding/json"
	"os"
	"testing"
)

const deserializationVectorFile = "../testdata/vectors/deserialization.json"

func TestVectorDeserialization(t *testing.T) {
	raw, err := os.ReadFile(deserializationVectorFile)
	if err != nil {
		t.Fatalf("reading the vendored family 16 vectors: %v", err)
	}
	vectors := []json.RawMessage{}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parsing the vendored family 16 vectors: %v", err)
	}
	if len(vectors) < 14 {
		t.Fatalf("family 16 has %d vectors, want at least the 14 in the pinned corpus", len(vectors))
	}
	for _, vector := range vectors {
		VerifyDeserializationVector(t, vector)
	}
}

// the runner must reject a header that carries a different length than its vector
// claims, or family 16 is a no op that passes against any corpus. The probe runs on
// its own goroutine so a t.Fatalf inside the runner ends the probe rather than this
// test.
func TestVerifyDeserializationVectorRejectsAMismatch(t *testing.T) {
	probe := &testing.T{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		VerifyDeserializationVector(probe, json.RawMessage(`{"vlbytes_header":"3f","length":62}`))
	}()
	<-done
	if !probe.Failed() {
		t.Errorf("a header carrying 63 was accepted against a claimed length of 62")
	}
}

// a non minimal header must fail the vector rather than pass it: the decoder rejects
// it outright, and if it ever stopped doing so the generate direction would catch it
// anyway, because our encoder emits 4040 for 64 and never the four octet form
func TestVerifyDeserializationVectorRejectsANonCanonicalHeader(t *testing.T) {
	probe := &testing.T{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		VerifyDeserializationVector(probe, json.RawMessage(`{"vlbytes_header":"80000040","length":64}`))
	}()
	<-done
	if !probe.Failed() {
		t.Errorf("a non minimal header was accepted for the length it carries")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "Deserialization" -v`
Expected: FAIL — build error `undefined: VerifyDeserializationVector`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/vectors.go`:

```go
// Test vector family 16, vector deserialization, from the mlswg corpus that the
// validation and interop plan vendors and pins. Both directions per spec A section
// 4.2.1: the supplied header must decode to the supplied length, and encoding that
// length with our own encoder must reproduce the supplied header. Verification alone
// cannot see an encoder and a decoder that are wrong in the same direction.
//
// This is the only implementation of family 16 in the system. The vector registry
// entry in package mls is a shim that assigns this function to VectorFamily.Verify,
// so the family runs against the ReadVarint and WriteVarint methods this package
// ships rather than against a second copy of the length prefix.
//
// It is a non test file on purpose: a symbol declared in a _test.go file is visible
// only inside its own test binary, and the shim that registers this family is in
// package mls. The only cost is testing in this package's import graph, which is
// still standard library and so leaves the layering gate green.
package syntax

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// one row of deserialization.json: an encoded vlbytes header and the length it
// carries
type deserializationVector struct {
	VlbytesHeader string `json:"vlbytes_header"`
	Length        uint32 `json:"length"`
}

// Verifies one family 16 vector in both directions. The corpus carries well formed
// headers only, so it exercises acceptance; rejection of a reserved prefix and of a
// non minimal encoding is rule 1 of spec A section 5.8 and lives in
// TestReadVarintRejectsEverythingButTheMinimalForm.
func VerifyDeserializationVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	vector := deserializationVector{}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("family 16 vector %s does not parse: %v", raw, err)
	}
	header, err := hex.DecodeString(vector.VlbytesHeader)
	if err != nil {
		t.Fatalf("family 16 header %q is not hex: %v", vector.VlbytesHeader, err)
	}
	// verify direction
	r := NewReader(header)
	got, err := r.ReadVarint()
	if err != nil {
		t.Errorf("header %s: decode gave %v", vector.VlbytesHeader, err)
		return
	}
	if got != vector.Length {
		t.Errorf("header %s: decoded %d, want %d", vector.VlbytesHeader, got, vector.Length)
	}
	if err := r.Done(); err != nil {
		t.Errorf("header %s: %d octets left unconsumed", vector.VlbytesHeader, r.Remaining())
	}
	// generate direction
	w := NewWriter()
	w.WriteVarint(vector.Length)
	out, err := w.Bytes()
	if err != nil {
		t.Errorf("encoding %d gave %v", vector.Length, err)
		return
	}
	if !bytes.Equal(out, header) {
		t.Errorf("encoding %d gave %x, want %s", vector.Length, out, vector.VlbytesHeader)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "Deserialization" -v`
Expected: PASS, with `TestSyntaxImportsStdlibOnly` still green — `testing`, `encoding/json` and
`encoding/hex` are all standard library.

Then confirm the driver is bound to the corpus rather than vacuous:

```bash
mv mls/testdata/vectors/deserialization.json mls/testdata/vectors/deserialization.json.bak
go test ./mls/syntax/... -run TestVectorDeserialization -v
mv mls/testdata/vectors/deserialization.json.bak mls/testdata/vectors/deserialization.json
```

Expected: FAIL while the file is absent — `reading the vendored family 16 vectors: open
../testdata/vectors/deserialization.json: The system cannot find the file specified.` — then PASS
again once it is restored.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/vectors.go mls/syntax/vectors_test.go && git commit -m "test(mls/syntax): add the family 16 runner the vector registry calls"
```

---

### Task 8: `opaque<V>` — the MLS variable-length byte string

**Files:**
- Modify: `connect/mls/syntax/encode.go`, `connect/mls/syntax/decode.go`
- Test: `connect/mls/syntax/encode_test.go`, `connect/mls/syntax/decode_test.go`

**Interfaces:**
- Consumes: `WriteVarint`/`ReadVarint` from Tasks 5 and 6, `takeLength` from Task 4.
- Produces:
```go
func (self *Writer) WriteOpaque(bs []byte)       // opaque x<V>; nil == empty  → p2,p4,p5,p6,p7
func (self *Reader) ReadOpaque() ([]byte, error) // a COPY, never nil          → p2,p4,p5,p6,p7
```
  Every MLS `opaque x<V>` field in every later wave goes through exactly these two. p2's four label
  encoders — the bytes MLS signs over — are built as
  `w := syntax.NewWriter(); w.WriteOpaque(...); bs, err := w.Bytes()`; the append-style
  `syntax.WriteVarVec(dst, v) []byte` its plan named is a second implementation of the §2.1.2 length
  prefix and does not exist here (registry §2.5 O-2).

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/syntax/encode_test.go`:

```go
func TestWriteOpaqueTreatsNilAndEmptyAlike(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		w := NewWriter()
		w.WriteOpaque(in)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(out, []byte{0x00}) {
			t.Errorf("empty opaque encoded to %x, want 00", out)
		}
	}
}

func TestWriteOpaqueUsesTheVarintPrefix(t *testing.T) {
	cases := []struct {
		length int
		prefix []byte
	}{
		{1, []byte{0x01}},
		{63, []byte{0x3f}},
		{64, []byte{0x40, 0x40}},
		{16383, []byte{0x7f, 0xff}},
		{16384, []byte{0x80, 0x00, 0x40, 0x00}},
	}
	for _, c := range cases {
		body := bytes.Repeat([]byte{0x11}, c.length)
		w := NewWriter()
		w.WriteOpaque(body)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", c.length, err)
		}
		want := append(append([]byte{}, c.prefix...), body...)
		if !bytes.Equal(out, want) {
			t.Errorf("length %d encoded to %x..., want prefix %x", c.length, out[:len(c.prefix)+1], c.prefix)
		}
	}
}

func TestWriteOpaqueRefusesToExceedTheLimit(t *testing.T) {
	w := NewWriterLimit(16)
	w.WriteOpaque(bytes.Repeat([]byte{0x11}, 17))
	if _, err := w.Bytes(); !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("over limit write gave %v, want ErrLengthExceedsMax", err)
	}
}
```

Append to `connect/mls/syntax/decode_test.go`:

```go
func TestReadOpaqueRoundTripsAndCopies(t *testing.T) {
	body := bytes.Repeat([]byte{0x11}, 100)
	w := NewWriter()
	w.WriteOpaque(body)
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReader(encoded)
	got, err := r.ReadOpaque()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("decoded %x, want %x", got, body)
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v", err)
	}
	got[0] = 0xff
	if encoded[2] != 0x11 {
		t.Errorf("ReadOpaque aliased the input")
	}
}

func TestReadOpaqueEmptyIsNonNil(t *testing.T) {
	r := NewReader([]byte{0x00})
	got, err := r.ReadOpaque()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Errorf("empty opaque decoded to nil, want a zero length non nil slice")
	}
	if len(got) != 0 {
		t.Errorf("empty opaque decoded to %x", got)
	}
}

func TestReadOpaqueChecksTheLimitThenTheInput(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"length above the limit", []byte{0xbf, 0xff, 0xff, 0xff}, ErrLengthExceedsMax},
		{"length above the remaining input", []byte{0x40, 0x40, 0x11, 0x11}, ErrLengthExceedsInput},
		{"prefix only", []byte{0x05}, ErrLengthExceedsInput},
		{"non minimal prefix", []byte{0x40, 0x00}, ErrVarintNotMinimal},
	}
	for _, c := range cases {
		r := NewReader(c.input)
		if _, err := r.ReadOpaque(); !errors.Is(err, c.wantErr) {
			t.Errorf("%s gave %v, want %v", c.name, err, c.wantErr)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "Opaque" -v`
Expected: FAIL — build error `w.WriteOpaque undefined (type *Writer has no field or method WriteOpaque)`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/syntax/encode.go`:

```go
// opaque x<V>: the RFC 9420 section 2.1.2 varint length prefix, then the bytes. A
// nil and an empty slice are the same value on the wire, which is what makes the
// round trip byte exact in both directions.
func (self *Writer) WriteOpaque(bs []byte) {
	if self.err != nil {
		return
	}
	if len(bs) > self.maxVectorLength {
		self.setErr(ErrLengthExceedsMax)
		return
	}
	self.WriteVarint(uint32(len(bs)))
	self.WriteRaw(bs)
}
```

Append to `connect/mls/syntax/decode.go`:

```go
// opaque x<V>: the result is a copy and is never nil, so an empty vector and an
// absent one stay distinguishable in Go while encoding identically on the wire
func (self *Reader) ReadOpaque() ([]byte, error) {
	mark := self.pos
	n, err := self.ReadVarint()
	if err != nil {
		return nil, err
	}
	length, err := self.takeLength(n)
	if err != nil {
		self.pos = mark
		return nil, err
	}
	out := make([]byte, length)
	copy(out, self.bs[self.pos:self.pos+length])
	self.pos += length
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "Opaque" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/encode.go mls/syntax/decode.go mls/syntax/encode_test.go mls/syntax/decode_test.go && git commit -m "feat(mls/syntax): add the opaque<V> variable length byte string"
```

---

### Task 9: `LP(x)` — the 32-bit big-endian prefix `connect/message` records use

**Files:**
- Modify: `connect/mls/syntax/encode.go`, `connect/mls/syntax/decode.go`
- Test: `connect/mls/syntax/encode_test.go`, `connect/mls/syntax/decode_test.go`

**Interfaces:**
- Consumes: `takeLength` from Task 4, `WriteUint32` from Task 3.
- Produces:
```go
func (self *Writer) WriteOpaqueLP(bs []byte)      // LP(x) per the master protocol design
func (self *Reader) ReadOpaqueLP() ([]byte, error) // a COPY, never nil
```
  **For the storage-layer plan (`connect/message`), not for any MLS structure.** MASTER writes every
  record field, AAD preimage and `write_auth` preimage as `LP(x)` = 32-bit big-endian length then `x`.
  MLS structures use `WriteOpaque`/`ReadOpaque`. The two are never interchangeable, and this task adds
  the test that says so.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/syntax/encode_test.go`:

```go
func TestWriteOpaqueLPUsesAFixedThirtyTwoBitPrefix(t *testing.T) {
	cases := []struct {
		body []byte
		want []byte
	}{
		{nil, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{}, []byte{0x00, 0x00, 0x00, 0x00}},
		{[]byte{0xaa}, []byte{0x00, 0x00, 0x00, 0x01, 0xaa}},
		{[]byte{0xaa, 0xbb}, []byte{0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb}},
	}
	for _, c := range cases {
		w := NewWriter()
		w.WriteOpaqueLP(c.body)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("body %x: unexpected error %v", c.body, err)
		}
		if !bytes.Equal(out, c.want) {
			t.Errorf("body %x encoded to %x, want %x", c.body, out, c.want)
		}
	}
}

// the two prefix forms must never be confusable, because connect/message uses LP
// for records and connect/mls uses <V> for MLS structures and one codec serves both
func TestLPAndVarintPrefixesAreDistinct(t *testing.T) {
	for _, body := range [][]byte{nil, {0xaa}, bytes.Repeat([]byte{0x11}, 200)} {
		lp := NewWriter()
		lp.WriteOpaqueLP(body)
		lpBytes, err := lp.Bytes()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		v := NewWriter()
		v.WriteOpaque(body)
		vBytes, err := v.Bytes()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if bytes.Equal(lpBytes, vBytes) {
			t.Errorf("body %x encoded identically under both prefix forms: %x", body, lpBytes)
		}
	}
}
```

Append to `connect/mls/syntax/decode_test.go`:

```go
func TestReadOpaqueLPRoundTrips(t *testing.T) {
	body := bytes.Repeat([]byte{0x11}, 70000)
	w := NewWriter()
	w.WriteOpaqueLP(body)
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReader(encoded)
	got, err := r.ReadOpaqueLP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("decoded %d bytes, want %d", len(got), len(body))
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v", err)
	}
}

func TestReadOpaqueLPChecksTheLimitThenTheInput(t *testing.T) {
	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"length above the limit", []byte{0xff, 0xff, 0xff, 0xff}, ErrLengthExceedsMax},
		{"length above the remaining input", []byte{0x00, 0x00, 0x00, 0x40, 0x11}, ErrLengthExceedsInput},
		{"prefix truncated", []byte{0x00, 0x00, 0x00}, ErrTruncated},
	}
	for _, c := range cases {
		r := NewReader(c.input)
		if _, err := r.ReadOpaqueLP(); !errors.Is(err, c.wantErr) {
			t.Errorf("%s gave %v, want %v", c.name, err, c.wantErr)
		}
		if r.Offset() != 0 {
			t.Errorf("%s advanced the cursor to %d on a failed read", c.name, r.Offset())
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "LP" -v`
Expected: FAIL — build error `w.WriteOpaqueLP undefined (type *Writer has no field or method WriteOpaqueLP)`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/syntax/encode.go`:

```go
// LP(x) in the master protocol design's notation: a 32 bit big endian length, then the bytes. This is
// the record layer's prefix, not MLS's — connect/message builds every record field
// and every AAD and write_auth preimage with it. It never appears inside an MLS
// structure, where the form is WriteOpaque.
func (self *Writer) WriteOpaqueLP(bs []byte) {
	if self.err != nil {
		return
	}
	if len(bs) > self.maxVectorLength {
		self.setErr(ErrLengthExceedsMax)
		return
	}
	self.WriteUint32(uint32(len(bs)))
	self.WriteRaw(bs)
}
```

Append to `connect/mls/syntax/decode.go`:

```go
// LP(x): the result is a copy and is never nil. The prefix is read without
// advancing, so a rejected length leaves the cursor where it was.
func (self *Reader) ReadOpaqueLP() ([]byte, error) {
	if self.Remaining() < 4 {
		return nil, ErrTruncated
	}
	n := binary.BigEndian.Uint32(self.bs[self.pos:])
	if int64(n) > int64(self.maxVectorLength) {
		return nil, ErrLengthExceedsMax
	}
	if int64(n) > int64(self.Remaining()-4) {
		return nil, ErrLengthExceedsInput
	}
	length := int(n)
	out := make([]byte, length)
	copy(out, self.bs[self.pos+4:self.pos+4+length])
	self.pos += 4 + length
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "LP" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/encode.go mls/syntax/decode.go mls/syntax/encode_test.go mls/syntax/decode_test.go && git commit -m "feat(mls/syntax): add the LP(x) 32 bit prefix form for connect/message records"
```

---

### Task 10: Sub-readers

**Files:**
- Modify: `connect/mls/syntax/decode.go`
- Test: `connect/mls/syntax/decode_test.go`

**Interfaces:**
- Consumes: `ReadVarint` from Task 6, `takeLength` from Task 4.
- Produces:
```go
func (self *Reader) ReadSub() (*Reader, error)         // bounded view of the next opaque<V> → p5,p6,p7
func (self *Reader) ReadSubLP() (*Reader, error)
```
  The sub-reader inherits the parent's `maxVectorLength` and is capacity-clipped so it can never see
  past its region. The parent advances past the whole region regardless of how much of it the
  sub-reader consumes. **Use this for a nested structure carried inside an opaque field** — the
  extension-body and `GroupInfo` paths in later waves, and `ReadVector` below.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/syntax/decode_test.go`:

```go
func TestReadSubIsBoundedAndAdvancesTheParent(t *testing.T) {
	w := NewWriter()
	w.WriteOpaque([]byte{0xaa, 0xbb, 0xcc})
	w.WriteUint16(0xbeef)
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReader(encoded)
	sub, err := r.ReadSub()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub.Remaining() != 3 {
		t.Fatalf("sub reader sees %d bytes, want 3", sub.Remaining())
	}
	if _, err := sub.ReadRaw(4); !errors.Is(err, ErrTruncated) {
		t.Errorf("sub reader read past its region")
	}
	if v, err := r.ReadUint16(); err != nil || v != 0xbeef {
		t.Errorf("parent gave %#x, %v after ReadSub; want beef, nil", v, err)
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v", err)
	}
}

func TestReadSubInheritsTheLimit(t *testing.T) {
	w := NewWriterLimit(MaxRatchetTreeLength)
	w.WriteOpaque(bytes.Repeat([]byte{0x11}, 8))
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReaderLimit(encoded, MaxRatchetTreeLength)
	sub, err := r.ReadSub()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub.MaxVectorLength() != MaxRatchetTreeLength {
		t.Errorf("sub reader limit is %d, want the parent's %d", sub.MaxVectorLength(), MaxRatchetTreeLength)
	}
}

func TestReadSubLPIsBounded(t *testing.T) {
	w := NewWriter()
	w.WriteOpaqueLP([]byte{0xaa, 0xbb})
	w.WriteUint8(0x77)
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReader(encoded)
	sub, err := r.ReadSubLP()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub.Remaining() != 2 {
		t.Errorf("sub reader sees %d bytes, want 2", sub.Remaining())
	}
	if v, err := r.ReadUint8(); err != nil || v != 0x77 {
		t.Errorf("parent gave %#x, %v; want 77, nil", v, err)
	}
}

// a sub reader is a view, so an append inside it must never reach the parent's bytes
func TestReadSubCannotGrowIntoTheParent(t *testing.T) {
	r := NewReader([]byte{0x01, 0xaa, 0xbb, 0xcc})
	sub, err := r.ReadSub()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	grown := append(sub.bs, 0xff)
	if len(r.bs) < 4 || r.bs[2] != 0xbb {
		t.Errorf("appending to the sub reader's slice overwrote the parent's bytes: %x", r.bs)
	}
	if grown[1] != 0xff {
		t.Errorf("append did not produce the expected value")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "ReadSub" -v`
Expected: FAIL — build error `r.ReadSub undefined (type *Reader has no field or method ReadSub)`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/syntax/decode.go`:

```go
// a view over the next opaque<V> region, for a structure nested inside an opaque
// field. The parent advances past the whole region however much of it the sub
// reader consumes, so a caller that stops early cannot desynchronise the parent.
// The view is deliberately not a copy — it is read only — and its capacity is
// clipped so an append inside it can never reach the parent's bytes.
func (self *Reader) ReadSub() (*Reader, error) {
	mark := self.pos
	n, err := self.ReadVarint()
	if err != nil {
		return nil, err
	}
	length, err := self.takeLength(n)
	if err != nil {
		self.pos = mark
		return nil, err
	}
	sub := &Reader{
		bs:              self.bs[self.pos : self.pos+length : self.pos+length],
		pos:             0,
		maxVectorLength: self.maxVectorLength,
	}
	self.pos += length
	return sub, nil
}

// as ReadSub, over an LP(x) region, for a record field that carries a structure
func (self *Reader) ReadSubLP() (*Reader, error) {
	if self.Remaining() < 4 {
		return nil, ErrTruncated
	}
	n := binary.BigEndian.Uint32(self.bs[self.pos:])
	if int64(n) > int64(self.maxVectorLength) {
		return nil, ErrLengthExceedsMax
	}
	if int64(n) > int64(self.Remaining()-4) {
		return nil, ErrLengthExceedsInput
	}
	length := int(n)
	start := self.pos + 4
	sub := &Reader{
		bs:              self.bs[start : start+length : start+length],
		pos:             0,
		maxVectorLength: self.maxVectorLength,
	}
	self.pos = start + length
	return sub, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "ReadSub" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/decode.go mls/syntax/decode_test.go && git commit -m "feat(mls/syntax): add capacity clipped sub readers for nested structures"
```

---

### Task 11: `optional<T>`

**Files:**
- Create: `connect/mls/syntax/optional.go`
- Test: `connect/mls/syntax/optional_test.go`

**Interfaces:**
- Consumes: `Writer`, `Reader`, `ErrOptionalPresence`, `ErrTruncated`.
- Produces:
```go
func (self *Writer) WriteOptional(present bool, encodeOne func(w *Writer) error) error  // → p5,p6
func (self *Reader) ReadOptional(decodeOne func(r *Reader) error) (present bool, err error) // → p5,p6
```
  RFC 9420 §2.1.1: a presence octet, then the value when present. A presence octet other than `0` or
  `1` is `ErrOptionalPresence`. The ratchet tree's `optional<Node>` and every `optional<...>` in
  later waves goes through these.

  **The encode callback returns an `error` and so does `WriteOptional`** — registry §2.5 O-2, the
  consequence of O-1. A nested encoder must be able to propagate a semantic refusal
  (`ErrProfileCredentialType` from a credential, `ErrContentArmMismatch` from a framed content) that
  is not a buffer error and that the sticky error has no exported way to carry. The refusal is also
  set on the Writer, so a caller that drops the return still fails at `Bytes()`: a dropped encoder
  refusal produces wrong signed bytes rather than a failure, and that is the one outcome this
  package must not allow. `errors.Join` in `Marshal` deduplicates nothing, but `errors.Is` holds
  either way.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/optional_test.go`:

```go
// optional<T> per rfc 9420 section 2.1.1: a presence octet, then the value when
// present. Any octet but 0 or 1 is malformed and must be rejected rather than
// treated as present, because "any non zero means present" would make two encodings
// of one value.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

func TestWriteOptionalAbsentIsASingleZero(t *testing.T) {
	w := NewWriter()
	if err := w.WriteOptional(false, func(w *Writer) error {
		t.Errorf("the value encoder ran for an absent optional")
		return nil
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{0x00}) {
		t.Errorf("absent optional encoded to %x, want 00", out)
	}
}

func TestWriteOptionalPresentCarriesItsValue(t *testing.T) {
	w := NewWriter()
	if err := w.WriteOptional(true, func(w *Writer) error {
		w.WriteUint16(0xbeef)
		return nil
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{0x01, 0xbe, 0xef}) {
		t.Errorf("present optional encoded to %x, want 01beef", out)
	}
}

// a semantic refusal from a nested encoder — the reason the callback returns an error
// at all — must reach the caller and must also stick to the writer, so a caller that
// drops the return cannot walk away with a truncated encoding
func TestWriteOptionalPropagatesAndSticksAnEncoderRefusal(t *testing.T) {
	refusal := errors.New("mls syntax: probe refusal")
	w := NewWriter()
	w.WriteUint8(0x01)
	err := w.WriteOptional(true, func(w *Writer) error {
		return refusal
	})
	if !errors.Is(err, refusal) {
		t.Errorf("WriteOptional returned %v, want the callback's refusal", err)
	}
	if !errors.Is(w.Err(), refusal) {
		t.Errorf("the writer's sticky error is %v, want the callback's refusal", w.Err())
	}
	if _, err := w.Bytes(); !errors.Is(err, refusal) {
		t.Errorf("Bytes returned %v, want the callback's refusal", err)
	}
}

func TestReadOptionalRoundTrips(t *testing.T) {
	r := NewReader([]byte{0x01, 0xbe, 0xef})
	value := uint16(0)
	present, err := r.ReadOptional(func(r *Reader) error {
		v, err := r.ReadUint16()
		if err != nil {
			return err
		}
		value = v
		return nil
	})
	if err != nil || !present || value != 0xbeef {
		t.Fatalf("gave present=%v value=%#x err=%v; want true, beef, nil", present, value, err)
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v", err)
	}
}

func TestReadOptionalAbsentSkipsTheValueDecoder(t *testing.T) {
	r := NewReader([]byte{0x00})
	present, err := r.ReadOptional(func(r *Reader) error {
		t.Errorf("the value decoder ran for an absent optional")
		return nil
	})
	if err != nil || present {
		t.Fatalf("gave present=%v err=%v; want false, nil", present, err)
	}
}

func TestReadOptionalRejectsAMalformedPresenceOctet(t *testing.T) {
	for _, b := range []byte{0x02, 0x7f, 0x80, 0xff} {
		r := NewReader([]byte{b, 0xbe, 0xef})
		if _, err := r.ReadOptional(func(r *Reader) error { return nil }); !errors.Is(err, ErrOptionalPresence) {
			t.Errorf("presence octet %#x gave %v, want ErrOptionalPresence", b, err)
		}
		if r.Offset() != 0 {
			t.Errorf("presence octet %#x advanced the cursor on a failed read", b)
		}
	}
	r := NewReader([]byte{})
	if _, err := r.ReadOptional(func(r *Reader) error { return nil }); !errors.Is(err, ErrTruncated) {
		t.Errorf("empty input gave %v, want ErrTruncated", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "Optional" -v`
Expected: FAIL — build error `w.WriteOptional undefined (type *Writer has no field or method WriteOptional)`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/optional.go`:

```go
// optional<T> per rfc 9420 section 2.1.1. The presence octet is 0 or 1 and nothing
// else: reading "any non zero means present" would give a value two encodings, and
// the rfc says a presence octet other than 0 or 1 must be rejected as malformed.
//
// The encode callback returns an error because a nested MLS encoder has semantic
// refusals that are not buffer errors. The refusal is returned and set sticky, so it
// surfaces whether the caller checks the return or only checks Bytes.
package syntax

func (self *Writer) WriteOptional(present bool, encodeOne func(w *Writer) error) error {
	if self.err != nil {
		return self.err
	}
	if !present {
		self.WriteUint8(0)
		return nil
	}
	self.WriteUint8(1)
	if err := encodeOne(self); err != nil {
		self.setErr(err)
		return err
	}
	return nil
}

// reports whether the value was present; decodeOne runs only when it was, and the
// presence octet is validated before the cursor moves
func (self *Reader) ReadOptional(decodeOne func(r *Reader) error) (bool, error) {
	if self.Remaining() < 1 {
		return false, ErrTruncated
	}
	b := self.bs[self.pos]
	if b > 1 {
		return false, ErrOptionalPresence
	}
	self.pos += 1
	if b == 0 {
		return false, nil
	}
	if err := decodeOne(self); err != nil {
		return false, err
	}
	return true, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "Optional" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/optional.go mls/syntax/optional_test.go && git commit -m "feat(mls/syntax): add optional<T> with a strict presence octet"
```

---

### Task 12: Vectors of elements

**Files:**
- Create: `connect/mls/syntax/vector.go`
- Test: `connect/mls/syntax/vector_test.go`

**Interfaces:**
- Consumes: `Writer`, `Reader`, `ReadSub` from Task 10, `WriteOpaque` from Task 8,
  `ErrZeroLengthElement` from Task 2.
- Produces:
```go
func WriteVector[T any](w *Writer, items []T, encodeOne func(w *Writer, item T) error) error  // → p5,p6,p7
func ReadVector[T any](r *Reader, decodeOne func(r *Reader) (T, error)) ([]T, error)          // → p5,p6,p7
```
  **The length prefix counts BYTES, not elements.** This is the single most common way to get an MLS
  codec wrong, so decoding runs `decodeOne` against a sub-reader until that sub-reader is empty rather
  than counting down an element count. `ReadVector` returns a non-nil zero-length slice for an empty
  vector; a nil slice and an empty slice encode identically. An element decoder that consumes zero
  bytes is `ErrZeroLengthElement` rather than an infinite loop.

  These stay **free generics over a typed slice**. p6's method form,
  `(*Writer).WriteVector(n int, each func(w, i) error)`, is an untyped index loop and loses the
  element type that makes `ReadVector` safe; where the element type is genuinely heterogeneous the
  caller uses `ReadSub()` directly. The encode callback and `WriteVector` itself return an `error`
  for the same reason as `WriteOptional` — registry §2.5 O-2 — and an element encoder's refusal is
  both returned and set sticky on the outer writer.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/vector_test.go`:

```go
// T items<V>: a byte length prefix, then the concatenated elements. The prefix
// counts bytes rather than elements, which is the single most common way to get an
// MLS codec wrong, so these tests pin the byte count explicitly.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

func writeUint16Item(w *Writer, item uint16) error {
	w.WriteUint16(item)
	return nil
}

func readUint16Item(r *Reader) (uint16, error) {
	return r.ReadUint16()
}

func TestWriteVectorPrefixesBytesNotElements(t *testing.T) {
	cases := []struct {
		items []uint16
		want  []byte
	}{
		{nil, []byte{0x00}},
		{[]uint16{}, []byte{0x00}},
		{[]uint16{0x0001}, []byte{0x02, 0x00, 0x01}},
		{[]uint16{0x0001, 0x0002}, []byte{0x04, 0x00, 0x01, 0x00, 0x02}},
	}
	for _, c := range cases {
		w := NewWriter()
		if err := WriteVector(w, c.items, writeUint16Item); err != nil {
			t.Fatalf("items %v: unexpected error %v", c.items, err)
		}
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("items %v: unexpected error %v", c.items, err)
		}
		if !bytes.Equal(out, c.want) {
			t.Errorf("items %v encoded to %x, want %x", c.items, out, c.want)
		}
	}
}

// an element encoder's semantic refusal must reach the caller and stick to the outer
// writer, for the same reason WriteOptional's does
func TestWriteVectorPropagatesAndSticksAnElementRefusal(t *testing.T) {
	refusal := errors.New("mls syntax: probe refusal")
	w := NewWriter()
	err := WriteVector(w, []uint16{1, 2, 3}, func(w *Writer, item uint16) error {
		if item == 2 {
			return refusal
		}
		w.WriteUint16(item)
		return nil
	})
	if !errors.Is(err, refusal) {
		t.Errorf("WriteVector returned %v, want the element encoder's refusal", err)
	}
	if _, err := w.Bytes(); !errors.Is(err, refusal) {
		t.Errorf("Bytes returned %v, want the element encoder's refusal", err)
	}
}

func TestWriteVectorCrossesIntoTheTwoOctetPrefix(t *testing.T) {
	items := make([]uint16, 32)
	w := NewWriter()
	if err := WriteVector(w, items, writeUint16Item); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 32 elements is 64 bytes, which is the first length needing the two octet form
	if !bytes.Equal(out[:2], []byte{0x40, 0x40}) {
		t.Errorf("prefix is %x, want 4040 for a 64 byte vector", out[:2])
	}
	if len(out) != 2+64 {
		t.Errorf("encoded %d bytes, want 66", len(out))
	}
}

func TestReadVectorRoundTrips(t *testing.T) {
	items := []uint16{0x1111, 0x2222, 0x3333}
	w := NewWriter()
	if err := WriteVector(w, items, writeUint16Item); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := NewReader(encoded)
	got, err := ReadVector(r, readUint16Item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(items) {
		t.Fatalf("decoded %d elements, want %d", len(got), len(items))
	}
	for i := range items {
		if got[i] != items[i] {
			t.Errorf("element %d is %#x, want %#x", i, got[i], items[i])
		}
	}
	if err := r.Done(); err != nil {
		t.Errorf("Done gave %v", err)
	}
}

func TestReadVectorEmptyIsNonNil(t *testing.T) {
	r := NewReader([]byte{0x00})
	got, err := ReadVector(r, readUint16Item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Errorf("empty vector decoded to nil, want a zero length non nil slice")
	}
	if len(got) != 0 {
		t.Errorf("empty vector decoded to %v", got)
	}
}

// a declared byte length that does not land on an element boundary is malformed
func TestReadVectorRejectsMisalignedElements(t *testing.T) {
	r := NewReader([]byte{0x03, 0x11, 0x11, 0x22})
	if _, err := ReadVector(r, readUint16Item); !errors.Is(err, ErrTruncated) {
		t.Errorf("misaligned vector gave %v, want ErrTruncated", err)
	}
}

// an element decoder that consumes nothing would loop forever, so it is an error
func TestReadVectorRejectsAZeroLengthElement(t *testing.T) {
	r := NewReader([]byte{0x04, 0x11, 0x22, 0x33, 0x44})
	consumeNothing := func(r *Reader) (struct{}, error) {
		return struct{}{}, nil
	}
	if _, err := ReadVector(r, consumeNothing); !errors.Is(err, ErrZeroLengthElement) {
		t.Errorf("zero length element gave %v, want ErrZeroLengthElement", err)
	}
}

func TestReadVectorPropagatesAnElementError(t *testing.T) {
	r := NewReader([]byte{0x02, 0x11, 0x22})
	failing := func(r *Reader) (uint16, error) {
		return 0, ErrOptionalPresence
	}
	if _, err := ReadVector(r, failing); !errors.Is(err, ErrOptionalPresence) {
		t.Errorf("gave %v, want the element decoder's error", err)
	}
}

// the element count is bounded by the declared byte length, which is bounded by the
// limit, so a hostile input cannot make the slice grow without bound
func TestReadVectorAllocationIsBoundedByInput(t *testing.T) {
	r := NewReader([]byte{0x08, 0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44})
	got, err := ReadVector(r, readUint16Item)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("decoded %d elements from 8 bytes of uint16, want 4", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "Vector" -v`
Expected: FAIL — build error `undefined: WriteVector`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/vector.go`:

```go
// T items<V>: a byte length prefix, then the concatenated elements.
//
// The prefix counts BYTES, not elements. That is the single most common way to get
// an MLS codec wrong, so decoding never counts down an element count: it takes a
// sub reader over exactly the declared region and runs the element decoder until
// that sub reader is empty. A declared length that does not land on an element
// boundary therefore surfaces as a truncated final element rather than as a silently
// accepted short vector.
//
// The element count is bounded: every element must consume at least one byte, so the
// count cannot exceed the declared byte length, which cannot exceed the reader's
// limit, which cannot exceed the input. An element decoder that consumes nothing is
// rejected rather than allowed to loop.
//
// These are free generics over a typed slice rather than methods over an index loop,
// because the element type is what makes the decode side safe. The element encoder
// returns an error so a nested MLS encoder can propagate a semantic refusal; that
// refusal is returned and set sticky on the outer writer both.
package syntax

func WriteVector[T any](w *Writer, items []T, encodeOne func(w *Writer, item T) error) error {
	if w.err != nil {
		return w.err
	}
	scratch := NewWriterLimit(w.maxVectorLength)
	for _, item := range items {
		if err := encodeOne(scratch, item); err != nil {
			w.setErr(err)
			return err
		}
	}
	bs, err := scratch.Bytes()
	if err != nil {
		w.setErr(err)
		return err
	}
	w.WriteOpaque(bs)
	return nil
}

func ReadVector[T any](r *Reader, decodeOne func(r *Reader) (T, error)) ([]T, error) {
	sub, err := r.ReadSub()
	if err != nil {
		return nil, err
	}
	items := make([]T, 0, min(sub.Remaining(), 64))
	for !sub.Empty() {
		before := sub.Offset()
		item, err := decodeOne(sub)
		if err != nil {
			return nil, err
		}
		if sub.Offset() == before {
			return nil, ErrZeroLengthElement
		}
		items = append(items, item)
	}
	return items, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "Vector" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/vector.go mls/syntax/vector_test.go && git commit -m "feat(mls/syntax): add byte length prefixed vectors with a zero progress guard"
```

---

### Task 13: `Marshaler`, `Unmarshaler` and the top-level entry points

**Files:**
- Create: `connect/mls/syntax/marshal.go`
- Test: `connect/mls/syntax/marshal_test.go`

**Interfaces:**
- Consumes: `Writer`, `Reader`, `Done`, the limit constants.
- Produces — **this is the block every other plan writes its Consumes against**, registry §2.4
  verbatim:
```go
type Marshaler interface {
	MarshalMLS(w *Writer) error
}
type Unmarshaler interface {
	UnmarshalMLS(r *Reader) error
}
type Codec interface {
	Marshaler
	Unmarshaler
}

func Marshal(v Marshaler) ([]byte, error)                                     // → p4,p5,p6,p7,p8
func MarshalLimit(v Marshaler, maxVectorLength int) ([]byte, error)           // → p7
func Unmarshal(bs []byte, v Unmarshaler) error         // enforces full consumption → p4,p5,p6,p7,p8
func UnmarshalLimit(bs []byte, v Unmarshaler, maxVectorLength int) error      // → p5,p7
```
  Every MLS structure in every later wave implements `Codec` and carries
  `var _ syntax.Codec = (*T)(nil)` in its own file (**C1**), so drift fails at build rather than at
  Gate 4. `Unmarshal` uses `MaxVectorLength`; the ratchet-tree paths — `tree_sync.go`,
  `UnmarshalRatchetTree` and any `GroupInfo`/`Welcome` decode that may carry a tree — use
  `UnmarshalLimit(bs, v, MaxRatchetTreeLength)`.

  **`MarshalMLS` returns an `error` — registry §2.5 override O-1, adopted here.** This plan
  originally specified `MarshalMLS(w *Writer)` with no return, routing every failure into the
  Writer's sticky error. The reason the return is right: an MLS encoder has **semantic** refusals
  that are not buffer errors — `Credential.MarshalMLS` must refuse an x509 credential with
  `ErrProfileCredentialType`, `FramedContent.MarshalMLS` must refuse a mismatched arm with
  `ErrContentArmMismatch` — and this package exports no way to inject those into the sticky error,
  so under the original signature they would have to panic or be dropped. A dropped encoder refusal
  produces wrong signed bytes rather than a failure. `Marshal` therefore returns
  `errors.Join(v.MarshalMLS(w), w.Err())`, so the semantic error and the buffer error both surface.
  The sticky Writer stays: it is what keeps the leaf writes return-free, and that is 90% of the call
  sites. `MarshalTo(w) error` (p5) and `MarshalTLS() ([]byte, error)` (p7) are this, spelled the
  registry's way; `Marshal() ([]byte, error)` and `Parse<Type>(data)` free constructors on wire
  types do not exist anywhere (**C1**).

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/marshal_test.go`:

```go
// The top level entry points. Unmarshal enforces full consumption, because a
// decoder that ignores a tail accepts two encodings of one object and MLS signs
// over serialized forms.
package syntax

import (
	"bytes"
	"errors"
	"testing"
)

type marshalProbe struct {
	Value uint16
	Body  []byte
}

var _ Codec = (*marshalProbe)(nil)

func (self *marshalProbe) MarshalMLS(w *Writer) error {
	w.WriteUint16(self.Value)
	w.WriteOpaque(self.Body)
	return nil
}

func (self *marshalProbe) UnmarshalMLS(r *Reader) error {
	value, err := r.ReadUint16()
	if err != nil {
		return err
	}
	body, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	self.Value = value
	self.Body = body
	return nil
}

func TestMarshalUnmarshalRoundTrips(t *testing.T) {
	in := marshalProbe{Value: 0xbeef, Body: []byte{0xaa, 0xbb}}
	bs, err := Marshal(&in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(bs, []byte{0xbe, 0xef, 0x02, 0xaa, 0xbb}) {
		t.Errorf("encoded %x, want beef02aabb", bs)
	}
	out := marshalProbe{}
	if err := Unmarshal(bs, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Value != in.Value || !bytes.Equal(out.Body, in.Body) {
		t.Errorf("decoded %#x %x, want %#x %x", out.Value, out.Body, in.Value, in.Body)
	}
}

func TestUnmarshalRejectsATrailingByte(t *testing.T) {
	out := marshalProbe{}
	err := Unmarshal([]byte{0xbe, 0xef, 0x02, 0xaa, 0xbb, 0x99}, &out)
	if !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("gave %v, want ErrTrailingBytes", err)
	}
}

func TestUnmarshalPropagatesADecodeError(t *testing.T) {
	out := marshalProbe{}
	if err := Unmarshal([]byte{0xbe}, &out); !errors.Is(err, ErrTruncated) {
		t.Errorf("gave %v, want ErrTruncated", err)
	}
}

// the whole reason MarshalMLS returns an error rather than routing everything into
// the sticky error: an encoder refusal that is not a buffer error — a credential type
// outside the v1 profile, a content arm that disagrees with its discriminant — must
// reach the caller, because dropping it produces wrong signed bytes rather than a
// failure
type refusingProbe struct{}

var _ Codec = (*refusingProbe)(nil)

var errProbeRefusal = errors.New("mls syntax: probe refuses to encode")

func (self *refusingProbe) MarshalMLS(w *Writer) error {
	w.WriteUint16(0xbeef)
	return errProbeRefusal
}

func (self *refusingProbe) UnmarshalMLS(r *Reader) error {
	_, err := r.ReadUint16()
	return err
}

func TestMarshalSurfacesASemanticRefusal(t *testing.T) {
	bs, err := Marshal(&refusingProbe{})
	if !errors.Is(err, errProbeRefusal) {
		t.Errorf("Marshal gave %v, want the encoder's refusal", err)
	}
	if bs != nil {
		t.Errorf("Marshal returned %x alongside a refusal, want nil", bs)
	}
	if _, err := MarshalLimit(&refusingProbe{}, MaxRatchetTreeLength); !errors.Is(err, errProbeRefusal) {
		t.Errorf("MarshalLimit gave %v, want the encoder's refusal", err)
	}
}

func TestMarshalLimitBoundsTheEncoder(t *testing.T) {
	in := marshalProbe{Value: 1, Body: bytes.Repeat([]byte{0x11}, 64)}
	if _, err := MarshalLimit(&in, 32); !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("gave %v, want ErrLengthExceedsMax", err)
	}
	if _, err := MarshalLimit(&in, 128); err != nil {
		t.Errorf("gave %v under a sufficient limit, want nil", err)
	}
}

func TestUnmarshalLimitRaisesTheDecoderBound(t *testing.T) {
	in := marshalProbe{Value: 1, Body: bytes.Repeat([]byte{0x11}, 64)}
	bs, err := Marshal(&in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := marshalProbe{}
	if err := UnmarshalLimit(bs, &out, 32); !errors.Is(err, ErrLengthExceedsMax) {
		t.Errorf("gave %v under a low limit, want ErrLengthExceedsMax", err)
	}
	if err := UnmarshalLimit(bs, &out, MaxRatchetTreeLength); err != nil {
		t.Errorf("gave %v under the ratchet tree limit, want nil", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run "TestMarshal|TestUnmarshal" -v`
Expected: FAIL — build error `undefined: Marshal`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/syntax/marshal.go`:

```go
// The top level entry points every MLS structure and every record is encoded and
// decoded through.
//
// MarshalMLS returns an error and the Writer also carries a sticky one, and Marshal
// joins them. The two carry different things: the sticky error is a buffer failure —
// an over long vector, a varint out of range — and the returned error is a semantic
// refusal, which is an encoder declining to serialize a value the profile forbids.
// Only the leaf writes are return free. UnmarshalMLS returns an error per call,
// because decoding is a branch per field and every branch matters.
//
// Unmarshal enforces full consumption. A decoder that ignores a tail accepts two
// encodings of one object, and MLS signs over serialized forms, so that is a
// signature bypass primitive rather than a leniency.
package syntax

import "errors"

type Marshaler interface {
	MarshalMLS(w *Writer) error
}

type Unmarshaler interface {
	UnmarshalMLS(r *Reader) error
}

type Codec interface {
	Marshaler
	Unmarshaler
}

// the join is the point: a semantic refusal from the encoder and a buffer failure
// from the writer are different failures and either one alone must fail the encode
func Marshal(v Marshaler) ([]byte, error) {
	w := NewWriter()
	marshalErr := v.MarshalMLS(w)
	bs, writerErr := w.Bytes()
	if err := errors.Join(marshalErr, writerErr); err != nil {
		return nil, err
	}
	return bs, nil
}

// the ratchet tree paths pass MaxRatchetTreeLength; nothing else raises the bound
func MarshalLimit(v Marshaler, maxVectorLength int) ([]byte, error) {
	w := NewWriterLimit(maxVectorLength)
	marshalErr := v.MarshalMLS(w)
	bs, writerErr := w.Bytes()
	if err := errors.Join(marshalErr, writerErr); err != nil {
		return nil, err
	}
	return bs, nil
}

func Unmarshal(bs []byte, v Unmarshaler) error {
	r := NewReader(bs)
	if err := v.UnmarshalMLS(r); err != nil {
		return err
	}
	return r.Done()
}

// the ratchet tree paths pass MaxRatchetTreeLength; nothing else raises the bound
func UnmarshalLimit(bs []byte, v Unmarshaler, maxVectorLength int) error {
	r := NewReaderLimit(bs, maxVectorLength)
	if err := v.UnmarshalMLS(r); err != nil {
		return err
	}
	return r.Done()
}
```

`marshal.go` imports `errors` at this step, for the join. Task 14 adds `bytes` to it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "TestMarshal|TestUnmarshal" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/marshal.go mls/syntax/marshal_test.go && git commit -m "feat(mls/syntax): add Marshaler, Unmarshaler and the full consumption entry points"
```

---

### Task 14: `CheckRoundTrip` — the shared property every downstream fuzz target calls

**Files:**
- Modify: `connect/mls/syntax/marshal.go`
- Test: `connect/mls/syntax/marshal_test.go`

**Interfaces:**
- Consumes: `Marshal`, `Unmarshal` from Task 13; `ErrRoundTripNotByteExact`, `ErrRoundTripNotStable`
  from Task 2.
- Produces:
```go
func CheckRoundTrip[T any, PT interface {
	*T
	Codec
}](bs []byte) error                                                            // → p8
```
  Asserts Gate 4 property 2 (Spec A §4.4) against one input: if `bs` decodes, `encode(decode(bs))`
  must equal `bs`, and `decode(encode(decode(bs)))` must re-encode identically. Returns `nil` when
  `bs` does not decode — a rejected input carries no round-trip obligation. **All nine fuzz targets
  in the validation and interop plan (`FuzzExtensionDecode`, `FuzzKeyPackageDecode`,
  `FuzzMlsMessageDecode`, …) call this rather than reimplementing the property**, and so does the
  record-codec fuzz target in the `connect/message` plan. Call it as
  `CheckRoundTrip[KeyPackage, *KeyPackage](bs)`.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/syntax/marshal_test.go`:

```go
func TestCheckRoundTripAcceptsAValidEncoding(t *testing.T) {
	in := marshalProbe{Value: 0xbeef, Body: []byte{0xaa, 0xbb}}
	bs, err := Marshal(&in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := CheckRoundTrip[marshalProbe, *marshalProbe](bs); err != nil {
		t.Errorf("gave %v on a valid encoding, want nil", err)
	}
}

func TestCheckRoundTripIgnoresARejectedInput(t *testing.T) {
	// a truncated input has no round trip obligation
	if err := CheckRoundTrip[marshalProbe, *marshalProbe]([]byte{0xbe}); err != nil {
		t.Errorf("gave %v on a rejected input, want nil", err)
	}
	if err := CheckRoundTrip[marshalProbe, *marshalProbe](nil); err != nil {
		t.Errorf("gave %v on empty input, want nil", err)
	}
}

// the property that catches the real bug: a decoder that accepts a non canonical
// encoding will decode it, re-encode to the canonical form, and disagree
func TestCheckRoundTripCatchesANonCanonicalEncoding(t *testing.T) {
	// 0x4002 is the two octet varint form of 2, which the decoder must already
	// reject; this asserts the property would catch it if the decoder did not
	nonCanonical := []byte{0xbe, 0xef, 0x40, 0x02, 0xaa, 0xbb}
	probe := marshalProbe{}
	if err := Unmarshal(nonCanonical, &probe); err == nil {
		t.Fatalf("the decoder accepted a non minimal length prefix; rule 1 is broken")
	}
	if err := CheckRoundTrip[marshalProbe, *marshalProbe](nonCanonical); err != nil {
		t.Errorf("gave %v for an input the decoder rejects, want nil", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestCheckRoundTrip -v`
Expected: FAIL — build error `undefined: CheckRoundTrip`.

- [ ] **Step 3: Write minimal implementation**

Widen the import block at the top of `connect/mls/syntax/marshal.go` — Task 13 left it at
`import "errors"` — so it reads:

```go
import (
	"bytes"
	"errors"
)
```

Then append:

```go
// Gate 4 property 2 (spec A section 4.4) against one input: if bs decodes, then
// encode(decode(bs)) must equal bs and decode(encode(decode(bs))) must re-encode
// identically. An input that does not decode carries no obligation and returns nil,
// because rejection is a legitimate outcome and the differential oracle compares
// accept and reject separately.
//
// Every fuzz target in connect/mls and connect/message calls this rather than
// writing the property again, so there is one definition of "round trips" in the
// system. Call it as CheckRoundTrip[KeyPackage, *KeyPackage](bs).
func CheckRoundTrip[T any, PT interface {
	*T
	Codec
}](bs []byte) error {
	first := PT(new(T))
	if err := Unmarshal(bs, first); err != nil {
		return nil
	}
	reencoded, err := Marshal(first)
	if err != nil {
		return errors.Join(ErrRoundTripNotByteExact, err)
	}
	if !bytes.Equal(reencoded, bs) {
		return ErrRoundTripNotByteExact
	}
	second := PT(new(T))
	if err := Unmarshal(reencoded, second); err != nil {
		return errors.Join(ErrRoundTripNotStable, err)
	}
	again, err := Marshal(second)
	if err != nil {
		return errors.Join(ErrRoundTripNotStable, err)
	}
	if !bytes.Equal(again, reencoded) {
		return ErrRoundTripNotStable
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestCheckRoundTrip -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/marshal.go mls/syntax/marshal_test.go && git commit -m "feat(mls/syntax): add CheckRoundTrip, the shared gate 4 property 2 assertion"
```

---

### Task 15: The byte-exact golden table

**Files:**
- Test: `connect/mls/syntax/kat_test.go`

**Interfaces:**
- Consumes: every encoder from Tasks 3, 5, 8, 9, 11, 12.
- Produces: no code. It produces the frozen byte-level meaning of every primitive, which is what the
  message server (Spec B, linking this same code) and every later wave's signature preimage rest on.
  A change here is a wire break and must be argued as one.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/kat_test.go`:

```go
// The byte exact golden table. Every other test in this package asserts a behaviour;
// this one asserts the bytes. MLS signs over serialized forms and the message server
// rebuilds records through this same encoder, so a change to any row here is a wire
// break rather than a refactor.
package syntax

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// the leaf writes are return free, so this adapts one into the table's row type
// without a four line closure per row
func kat(write func(w *Writer)) func(w *Writer) error {
	return func(w *Writer) error {
		write(w)
		return nil
	}
}

func TestEncodingKAT(t *testing.T) {
	cases := []struct {
		name  string
		write func(w *Writer) error
		want  string
	}{
		{"uint8", kat(func(w *Writer) { w.WriteUint8(0x2a) }), "2a"},
		{"uint16", kat(func(w *Writer) { w.WriteUint16(0x0102) }), "0102"},
		{"uint32", kat(func(w *Writer) { w.WriteUint32(0x01020304) }), "01020304"},
		{"uint64", kat(func(w *Writer) { w.WriteUint64(0x0102030405060708) }), "0102030405060708"},
		{"raw", kat(func(w *Writer) { w.WriteRaw([]byte{0xaa, 0xbb}) }), "aabb"},
		{"varint 0", kat(func(w *Writer) { w.WriteVarint(0) }), "00"},
		{"varint 63", kat(func(w *Writer) { w.WriteVarint(63) }), "3f"},
		{"varint 64", kat(func(w *Writer) { w.WriteVarint(64) }), "4040"},
		{"varint 16383", kat(func(w *Writer) { w.WriteVarint(16383) }), "7fff"},
		{"varint 16384", kat(func(w *Writer) { w.WriteVarint(16384) }), "80004000"},
		{"varint max", kat(func(w *Writer) { w.WriteVarint(MaxVarint) }), "bfffffff"},
		{"opaque nil", kat(func(w *Writer) { w.WriteOpaque(nil) }), "00"},
		{"opaque empty", kat(func(w *Writer) { w.WriteOpaque([]byte{}) }), "00"},
		{"opaque one byte", kat(func(w *Writer) { w.WriteOpaque([]byte{0xaa}) }), "01aa"},
		{"opaque three bytes", kat(func(w *Writer) { w.WriteOpaque([]byte{0xaa, 0xbb, 0xcc}) }), "03aabbcc"},
		{"lp nil", kat(func(w *Writer) { w.WriteOpaqueLP(nil) }), "00000000"},
		{"lp empty", kat(func(w *Writer) { w.WriteOpaqueLP([]byte{}) }), "00000000"},
		{"lp one byte", kat(func(w *Writer) { w.WriteOpaqueLP([]byte{0xaa}) }), "00000001aa"},
		{
			"optional absent",
			func(w *Writer) error {
				return w.WriteOptional(false, func(w *Writer) error { return nil })
			},
			"00",
		},
		{
			"optional present uint16",
			func(w *Writer) error {
				return w.WriteOptional(true, func(w *Writer) error {
					w.WriteUint16(0xbeef)
					return nil
				})
			},
			"01beef",
		},
		{
			"vector empty",
			func(w *Writer) error { return WriteVector(w, []uint16{}, writeUint16Item) },
			"00",
		},
		{
			"vector two uint16 prefixed by four bytes not two elements",
			func(w *Writer) error { return WriteVector(w, []uint16{0x0001, 0x0002}, writeUint16Item) },
			"0400010002",
		},
		{
			"nested vector of opaque",
			func(w *Writer) error {
				return WriteVector(w, [][]byte{{0xaa}, {0xbb, 0xcc}}, func(w *Writer, item []byte) error {
					w.WriteOpaque(item)
					return nil
				})
			},
			"0501aa02bbcc",
		},
	}
	for _, c := range cases {
		w := NewWriter()
		if err := c.write(w); err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		out, err := w.Bytes()
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		want, err := hex.DecodeString(c.want)
		if err != nil {
			t.Fatalf("%s: the golden value %q is not hex", c.name, c.want)
		}
		if !bytes.Equal(out, want) {
			t.Errorf("%s encoded to %x, want %s", c.name, out, c.want)
		}
	}
}

// 63 bytes takes the one octet prefix and 64 takes the two octet form; this is the
// boundary every later wave's opaque field crosses
func TestEncodingKATAtThePrefixBoundary(t *testing.T) {
	sixtyThree := bytes.Repeat([]byte{0x11}, 63)
	w := NewWriter()
	w.WriteOpaque(sixtyThree)
	out, err := w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 64 || out[0] != 0x3f {
		t.Errorf("63 byte opaque encoded to %d bytes with prefix %#x, want 64 and 0x3f", len(out), out[0])
	}
	sixtyFour := bytes.Repeat([]byte{0x11}, 64)
	w = NewWriter()
	w.WriteOpaque(sixtyFour)
	out, err = w.Bytes()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 66 || out[0] != 0x40 || out[1] != 0x40 {
		t.Errorf("64 byte opaque encoded to %d bytes with prefix %x, want 66 and 4040", len(out), out[:2])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Temporarily change the `"varint 64"` golden from `"4040"` to `"0040"` and run:

Run: `go test ./mls/syntax/... -run TestEncodingKAT -v`
Expected: FAIL — `varint 64 encoded to 4040, want 0040`. Restore the golden value.

- [ ] **Step 3: Write minimal implementation**

No production code changes. This task pins bytes already produced by Tasks 3, 5, 8, 9, 11 and 12.
Restore the golden value changed in step 2.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestEncodingKAT -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/kat_test.go && git commit -m "test(mls/syntax): pin the byte exact encoding of every primitive"
```

---

### Task 16: A hostile length prefix allocates nothing

**Files:**
- Test: `connect/mls/syntax/alloc_test.go`

**Interfaces:**
- Consumes: `ReadOpaque`, `ReadOpaqueLP`, `ReadSub`, `ReadVector`.
- Produces: no code. It produces the evidence for Gate 4 property 1 (Spec A §4.4): "a length prefix
  must never be used to size an allocation before the remaining input is checked."

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/alloc_test.go`:

```go
// Gate 4 property 1: a length prefix must never size an allocation before the
// remaining input is checked. Each case declares roughly a gigabyte over an input of
// four bytes, so a decoder that allocated first would move the measured total by six
// orders of magnitude rather than by the slack this bound allows.
package syntax

import (
	"errors"
	"runtime"
	"testing"
)

const allocProbeRuns = 1000
const allocProbeBudget = 1 << 18

func measureAllocs(t *testing.T, run func() error, wantErr error) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < allocProbeRuns; i += 1 {
		if err := run(); !errors.Is(err, wantErr) {
			t.Fatalf("run %d gave %v, want %v", i, err, wantErr)
		}
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestHostileVarintLengthAllocatesNothing(t *testing.T) {
	// bfffffff is the varint for 1073741823 over a four byte input
	hostile := []byte{0xbf, 0xff, 0xff, 0xff}
	grown := measureAllocs(t, func() error {
		r := NewReader(hostile)
		_, err := r.ReadOpaque()
		return err
	}, ErrLengthExceedsMax)
	if grown > allocProbeBudget {
		t.Errorf("%d hostile ReadOpaque calls allocated %d bytes; the length prefix sized a make", allocProbeRuns, grown)
	}
}

func TestHostileLPLengthAllocatesNothing(t *testing.T) {
	hostile := []byte{0xff, 0xff, 0xff, 0xff}
	grown := measureAllocs(t, func() error {
		r := NewReader(hostile)
		_, err := r.ReadOpaqueLP()
		return err
	}, ErrLengthExceedsMax)
	if grown > allocProbeBudget {
		t.Errorf("%d hostile ReadOpaqueLP calls allocated %d bytes; the length prefix sized a make", allocProbeRuns, grown)
	}
}

func TestHostileSubLengthAllocatesNothing(t *testing.T) {
	hostile := []byte{0xbf, 0xff, 0xff, 0xff}
	grown := measureAllocs(t, func() error {
		r := NewReader(hostile)
		_, err := r.ReadSub()
		return err
	}, ErrLengthExceedsMax)
	if grown > allocProbeBudget {
		t.Errorf("%d hostile ReadSub calls allocated %d bytes; the length prefix sized a make", allocProbeRuns, grown)
	}
}

func TestHostileVectorLengthAllocatesNothing(t *testing.T) {
	hostile := []byte{0xbf, 0xff, 0xff, 0xff}
	grown := measureAllocs(t, func() error {
		r := NewReader(hostile)
		_, err := ReadVector(r, readUint16Item)
		return err
	}, ErrLengthExceedsMax)
	if grown > allocProbeBudget {
		t.Errorf("%d hostile ReadVector calls allocated %d bytes; the length prefix sized a make", allocProbeRuns, grown)
	}
}

// a length inside the limit but past the input must also allocate nothing
func TestLengthPastTheInputAllocatesNothing(t *testing.T) {
	// 4040 declares 64 bytes over an input of two
	hostile := []byte{0x40, 0x40}
	grown := measureAllocs(t, func() error {
		r := NewReader(hostile)
		_, err := r.ReadOpaque()
		return err
	}, ErrLengthExceedsInput)
	if grown > allocProbeBudget {
		t.Errorf("%d over declaring ReadOpaque calls allocated %d bytes", allocProbeRuns, grown)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Temporarily reorder `takeLength` in `decode.go` so it allocates before validating — insert
`_ = make([]byte, n)` as the first statement — and run:

Run: `go test ./mls/syntax/... -run "Allocates" -v`
Expected: FAIL — `1000 hostile ReadOpaque calls allocated 1073741824000 bytes; the length prefix
sized a make` (or an out-of-memory kill, which is the same finding). Revert the temporary line.

- [ ] **Step 3: Write minimal implementation**

No production code changes. `takeLength`, `ReadOpaqueLP` and `ReadSubLP` already validate before
allocating. Revert the temporary `make` inserted in step 2 and confirm `git diff` shows no change to
`decode.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run "Allocates" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git diff --stat mls/syntax/decode.go
git add mls/syntax/alloc_test.go && git commit -m "test(mls/syntax): assert a hostile length prefix sizes no allocation"
```

---

### Task 17: The structured generator and the deterministic round-trip property test

**Files:**
- Test: `connect/mls/syntax/fuzzgen_test.go`, `connect/mls/syntax/roundtrip_test.go`

**Interfaces:**
- Consumes: everything from Tasks 3 through 14.
- Produces: no exported code — `testStruct`, `testItem` and `generateTestStruct` are test-only.
  Spec A §4.4 names `syntax/fuzzgen_test.go` as the home of the structured generator that seeds the
  byte-string fuzz targets, and that is what this is. **The nine OpenMLS-mirroring targets in the
  validation and interop plan need their own generators over their own types** (`Extension`,
  `KeyPackage`, `MLSMessage`, `Proposal`, `Welcome`); they cannot import this one across a package
  boundary, and they should not try.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/fuzzgen_test.go`:

```go
// A structure exercising every primitive the package offers, and a seeded generator
// for it. Spec A section 4.4 puts the structured generator here: go's native fuzzer
// takes byte strings only, so the structured variants of the OpenMLS targets are
// implemented as byte string targets seeded from a generator like this one.
package syntax

import "math/rand"

type testItem struct {
	Kind uint16
	Data []byte
}

var _ Codec = (*testItem)(nil)

func (self *testItem) MarshalMLS(w *Writer) error {
	w.WriteUint16(self.Kind)
	w.WriteOpaque(self.Data)
	return nil
}

func (self *testItem) UnmarshalMLS(r *Reader) error {
	kind, err := r.ReadUint16()
	if err != nil {
		return err
	}
	data, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	self.Kind = kind
	self.Data = data
	return nil
}

type testStruct struct {
	Version  uint16
	Flags    uint8
	Counter  uint64
	Fixed    [4]byte
	Body     []byte
	Tail     []byte
	HasExtra bool
	Extra    uint32
	Items    []testItem
}

var _ Codec = (*testStruct)(nil)

func (self *testStruct) MarshalMLS(w *Writer) error {
	w.WriteUint16(self.Version)
	w.WriteUint8(self.Flags)
	w.WriteUint64(self.Counter)
	w.WriteRaw(self.Fixed[:])
	w.WriteOpaque(self.Body)
	w.WriteOpaqueLP(self.Tail)
	err := w.WriteOptional(self.HasExtra, func(w *Writer) error {
		w.WriteUint32(self.Extra)
		return nil
	})
	if err != nil {
		return err
	}
	return WriteVector(w, self.Items, func(w *Writer, item testItem) error {
		return item.MarshalMLS(w)
	})
}

func (self *testStruct) UnmarshalMLS(r *Reader) error {
	version, err := r.ReadUint16()
	if err != nil {
		return err
	}
	flags, err := r.ReadUint8()
	if err != nil {
		return err
	}
	counter, err := r.ReadUint64()
	if err != nil {
		return err
	}
	fixed, err := r.ReadRaw(4)
	if err != nil {
		return err
	}
	body, err := r.ReadOpaque()
	if err != nil {
		return err
	}
	tail, err := r.ReadOpaqueLP()
	if err != nil {
		return err
	}
	extra := uint32(0)
	hasExtra, err := r.ReadOptional(func(r *Reader) error {
		v, err := r.ReadUint32()
		if err != nil {
			return err
		}
		extra = v
		return nil
	})
	if err != nil {
		return err
	}
	items, err := ReadVector(r, func(r *Reader) (testItem, error) {
		item := testItem{}
		if err := item.UnmarshalMLS(r); err != nil {
			return testItem{}, err
		}
		return item, nil
	})
	if err != nil {
		return err
	}
	self.Version = version
	self.Flags = flags
	self.Counter = counter
	copy(self.Fixed[:], fixed)
	self.Body = body
	self.Tail = tail
	self.HasExtra = hasExtra
	self.Extra = extra
	self.Items = items
	return nil
}

// one in twenty structures carries a body past 16383 bytes, so the four octet varint
// form is exercised rather than only the one and two octet forms
func generateTestStruct(rng *rand.Rand) testStruct {
	randomBytes := func(maxLen int) []byte {
		bs := make([]byte, rng.Intn(maxLen+1))
		rng.Read(bs)
		return bs
	}
	bodyMax := 300
	if rng.Intn(20) == 0 {
		bodyMax = 20000
	}
	items := make([]testItem, rng.Intn(5))
	for i := range items {
		items[i] = testItem{
			Kind: uint16(rng.Uint32()),
			Data: randomBytes(80),
		}
	}
	s := testStruct{
		Version:  uint16(rng.Uint32()),
		Flags:    uint8(rng.Uint32()),
		Counter:  rng.Uint64(),
		Fixed:    [4]byte{},
		Body:     randomBytes(bodyMax),
		Tail:     randomBytes(300),
		HasExtra: rng.Intn(2) == 1,
		Extra:    rng.Uint32(),
		Items:    items,
	}
	rng.Read(s.Fixed[:])
	return s
}
```

`connect/mls/syntax/roundtrip_test.go`:

```go
// Rule 4 as a deterministic property, run on every commit rather than only under
// the fuzzer: twenty thousand generated structures must each encode, decode and
// re-encode to the same bytes. The seed is fixed so a failure is reproducible from
// the test name alone.
package syntax

import (
	"bytes"
	"math/rand"
	"testing"
)

const roundTripSeed = 20260812
const roundTripRuns = 20000

func TestRoundTripProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(roundTripSeed))
	for i := 0; i < roundTripRuns; i += 1 {
		in := generateTestStruct(rng)
		encoded, err := Marshal(&in)
		if err != nil {
			t.Fatalf("run %d: encode gave %v", i, err)
		}
		out := testStruct{}
		if err := Unmarshal(encoded, &out); err != nil {
			t.Fatalf("run %d: decode of %d bytes gave %v", i, len(encoded), err)
		}
		again, err := Marshal(&out)
		if err != nil {
			t.Fatalf("run %d: re-encode gave %v", i, err)
		}
		if !bytes.Equal(encoded, again) {
			t.Fatalf("run %d: re-encode produced %d bytes, want the original %d", i, len(again), len(encoded))
		}
		if err := CheckRoundTrip[testStruct, *testStruct](encoded); err != nil {
			t.Fatalf("run %d: CheckRoundTrip gave %v", i, err)
		}
	}
}

// nil and empty are the same value on the wire, in every container, which is what
// makes the round trip byte exact rather than merely value preserving
func TestRoundTripTreatsNilAndEmptyAlike(t *testing.T) {
	nilled := testStruct{Body: nil, Tail: nil, Items: nil}
	emptied := testStruct{Body: []byte{}, Tail: []byte{}, Items: []testItem{}}
	a, err := Marshal(&nilled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := Marshal(&emptied)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("nil encoded to %x and empty to %x; they must be one value on the wire", a, b)
	}
	if err := CheckRoundTrip[testStruct, *testStruct](a); err != nil {
		t.Errorf("CheckRoundTrip gave %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestRoundTrip -v`
Expected: FAIL — build error `undefined: generateTestStruct` before `fuzzgen_test.go` is written; once
both files exist the test compiles and passes, so verify the failure by first creating
`roundtrip_test.go` alone.

- [ ] **Step 3: Write minimal implementation**

No production code changes — add `fuzzgen_test.go` as written in step 1. If `TestRoundTripProperty`
fails at this point, the defect is in Tasks 3 to 14 and is exactly what this task exists to find;
fix it there rather than weakening the property.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/syntax/... -run TestRoundTrip -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/fuzzgen_test.go mls/syntax/roundtrip_test.go && git commit -m "test(mls/syntax): add the structured generator and the seeded round trip property"
```

---

### Task 18: The three fuzz targets and the shared corpus loader

**Files:**
- Test: `connect/mls/syntax/fuzz_test.go`

**Interfaces:**
- Consumes: `ReadVarint`, `WriteVarint`, `ReadOpaque`, `WriteOpaque`, `CheckRoundTrip`, and
  `connect/mls/testdata/corpus/` if it is present. **The committed corpus and `interop/cmd/seedgen`
  that fills it are p8's** (registry §12, Gate 4), so this plan neither creates nor commits that
  directory; the loader below treats its absence as a normal fresh checkout.
- Produces: `FuzzVarint`, `FuzzOpaque`, `FuzzSyntaxStruct` — the three targets slice A1's done-when
  requires clean for 60 s each (Spec A §13). They assert Gate 4 properties 1 and 2 only; property 3,
  differential agreement with OpenMLS, belongs to the validation and interop plan and runs nightly.
  The nine OpenMLS-mirroring `Fuzz*Decode` targets over `Extension`, `KeyPackage`, `MLSMessage`,
  `Proposal` and `Welcome` are p8's and are not duplicated here.

- [ ] **Step 1: Write the failing test**

`connect/mls/syntax/fuzz_test.go`:

```go
// Gate 4 properties 1 and 2 for the codec: no panic on any input, and byte exact
// round tripping of every input that decodes. Property 3, differential agreement
// with OpenMLS, is the interop plan's and runs nightly against the out of process
// oracle; nothing here links or invokes it.
//
// The canonical encoding property is what FuzzVarint and FuzzOpaque actually assert:
// any input the decoder accepts must re-encode to exactly the bytes it consumed. A
// decoder that accepted a second encoding of one length would give a signed
// structure two serializations, which is a signature bypass primitive.
package syntax

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

const sharedCorpusDir = "../testdata/corpus"

// the shared corpus is committed and filled by the validation and interop plan's
// seed generator; it is legitimately absent on a fresh checkout of this wave, so its
// absence is not a failure
func addSharedCorpus(f *testing.F) {
	f.Helper()
	entries, err := os.ReadDir(sharedCorpusDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		bs, err := os.ReadFile(filepath.Join(sharedCorpusDir, entry.Name()))
		if err != nil {
			continue
		}
		f.Add(bs)
	}
}

func FuzzVarint(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x00}, {0x3f}, {0x40, 0x40}, {0x7f, 0xff},
		{0x80, 0x00, 0x40, 0x00}, {0xbf, 0xff, 0xff, 0xff},
		{0x40, 0x00}, {0x40, 0x3f}, {0x80, 0x00, 0x00, 0x00}, {0x80, 0x00, 0x3f, 0xff},
		{0xc0}, {0xff, 0xff, 0xff, 0xff},
		{0x40}, {0x80, 0x00, 0x40},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	addSharedCorpus(f)
	f.Fuzz(func(t *testing.T, bs []byte) {
		r := NewReader(bs)
		v, err := r.ReadVarint()
		if err != nil {
			return
		}
		if v > MaxVarint {
			t.Fatalf("decoded %d above MaxVarint from %x", v, bs)
		}
		consumed := r.Offset()
		if consumed < 1 || consumed > 4 {
			t.Fatalf("consumed %d octets decoding %d from %x", consumed, v, bs)
		}
		w := NewWriter()
		w.WriteVarint(v)
		out, err := w.Bytes()
		if err != nil {
			t.Fatalf("re-encoding %d gave %v", v, err)
		}
		if !bytes.Equal(out, bs[:consumed]) {
			t.Fatalf("%x decoded to %d but re-encoded to %x; the encoding is not canonical", bs[:consumed], v, out)
		}
	})
}

func FuzzOpaque(f *testing.F) {
	seeds := [][]byte{
		{}, {0x00}, {0x01, 0xaa}, {0x03, 0xaa, 0xbb, 0xcc},
		{0x40, 0x40}, {0xbf, 0xff, 0xff, 0xff}, {0xc0, 0x00},
		{0x00, 0x00, 0x00, 0x00}, {0x00, 0x00, 0x00, 0x01, 0xaa},
		{0xff, 0xff, 0xff, 0xff},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	addSharedCorpus(f)
	f.Fuzz(func(t *testing.T, bs []byte) {
		r := NewReader(bs)
		if body, err := r.ReadOpaque(); err == nil {
			consumed := r.Offset()
			w := NewWriter()
			w.WriteOpaque(body)
			out, err := w.Bytes()
			if err != nil {
				t.Fatalf("re-encoding a %d byte opaque gave %v", len(body), err)
			}
			if !bytes.Equal(out, bs[:consumed]) {
				t.Fatalf("%x decoded and re-encoded to %x; the encoding is not canonical", bs[:consumed], out)
			}
		}
		rlp := NewReader(bs)
		if body, err := rlp.ReadOpaqueLP(); err == nil {
			consumed := rlp.Offset()
			w := NewWriter()
			w.WriteOpaqueLP(body)
			out, err := w.Bytes()
			if err != nil {
				t.Fatalf("re-encoding a %d byte LP opaque gave %v", len(body), err)
			}
			if !bytes.Equal(out, bs[:consumed]) {
				t.Fatalf("%x decoded and re-encoded to %x under LP; the encoding is not canonical", bs[:consumed], out)
			}
		}
	})
}

func FuzzSyntaxStruct(f *testing.F) {
	rng := rand.New(rand.NewSource(roundTripSeed))
	for i := 0; i < 64; i += 1 {
		in := generateTestStruct(rng)
		encoded, err := Marshal(&in)
		if err != nil {
			f.Fatalf("seed %d: encode gave %v", i, err)
		}
		f.Add(encoded)
	}
	f.Add([]byte{})
	addSharedCorpus(f)
	f.Fuzz(func(t *testing.T, bs []byte) {
		if err := CheckRoundTrip[testStruct, *testStruct](bs); err != nil {
			t.Fatalf("round trip failed on %x: %v", bs, err)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Temporarily relax the varint decoder — change `if v < 0x40` in the two-octet branch of
`ReadVarint` to `if false` — and run:

Run: `go test ./mls/syntax -run=NONE -fuzz=FuzzVarint -fuzztime=30s`
Expected: FAIL — `4000 decoded to 0 but re-encoded to 00; the encoding is not canonical`, with the
reproducer written to `mls/syntax/testdata/fuzz/FuzzVarint/`. Restore the check and delete the
generated reproducer.

- [ ] **Step 3: Write minimal implementation**

No production code changes. Restore `if v < 0x40` in `ReadVarint` and remove the reproducer file the
fuzzer wrote:

```bash
git checkout -- mls/syntax/varint.go
rm -rf mls/syntax/testdata/fuzz
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./mls/syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s
go test ./mls/syntax -run=NONE -fuzz=FuzzOpaque -fuzztime=60s
go test ./mls/syntax -run=NONE -fuzz=FuzzSyntaxStruct -fuzztime=60s
```
Expected: each PASS, reporting `elapsed: 60s` with no new interesting inputs escalating to a failure.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/syntax/fuzz_test.go && git commit -m "test(mls/syntax): add the three fuzz targets and the shared corpus loader"
```

---

### Task 19: CI wiring for the per-commit gate

**Files:**
- Create: `connect/.github/workflows/mls-syntax.yml`
- Test: `connect/mls/syntax/layering_test.go` (extended)

**Interfaces:**
- Consumes: every test in this plan.
- Produces: the per-commit CI job that makes slice A1's done-when — "family 16 passes; fuzz properties
  1–2 clean for 60 s × 3 targets" (Spec A §13) — a gate rather than a note. The interop plan owns
  `mls-interop.yml` and the nightly differential job; they do not collide.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/syntax/layering_test.go`:

```go
// The per commit gate is only a gate if it exists and names every target, so the
// workflow is asserted from the test suite rather than trusted to review.
func TestSyntaxWorkflowRunsEveryFuzzTarget(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/mls-syntax.yml")
	if err != nil {
		t.Fatalf("reading the syntax workflow: %v", err)
	}
	workflow := string(raw)
	for _, needle := range []string{
		"go-version: '1.26.5'",
		"go vet ./mls/syntax",
		"go test ./mls/syntax/... -count=1 -race",
		"-fuzz=FuzzVarint -fuzztime=60s",
		"-fuzz=FuzzOpaque -fuzztime=60s",
		"-fuzz=FuzzSyntaxStruct -fuzztime=60s",
	} {
		if !strings.Contains(workflow, needle) {
			t.Errorf("the syntax workflow does not run %q", needle)
		}
	}
}
```

Add `"os"` to the file's imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/syntax/... -run TestSyntaxWorkflow -v`
Expected: FAIL — `reading the syntax workflow: open ../../.github/workflows/mls-syntax.yml: The
system cannot find the file specified.`

- [ ] **Step 3: Write minimal implementation**

`connect/.github/workflows/mls-syntax.yml`:

```yaml
# The per commit gate for connect/mls/syntax. Slice A1 is done when family 16 passes
# and fuzz properties 1 and 2 are clean for 60 seconds on each of the three targets.
# The differential property against OpenMLS is property 3 and runs in the nightly
# job the interop plan owns; nothing here builds or links Rust.
name: mls-syntax

on:
  push:
    branches: [beta/message]
  pull_request:
    branches: [beta/message]

jobs:
  syntax:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.26.5'
      - name: vet
        run: go vet ./mls/syntax/...
      - name: unit and vector tests
        run: go test ./mls/syntax/... -count=1 -race
      - name: fuzz varint
        run: go test ./mls/syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s
      - name: fuzz opaque
        run: go test ./mls/syntax -run=NONE -fuzz=FuzzOpaque -fuzztime=60s
      - name: fuzz struct
        run: go test ./mls/syntax -run=NONE -fuzz=FuzzSyntaxStruct -fuzztime=60s
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: syntax-fuzz-reproducers
          path: mls/syntax/testdata/fuzz/**
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./mls/syntax/... -count=1 -race
go vet ./mls/syntax/...
```
Expected: PASS, with `TestSyntaxWorkflowRunsEveryFuzzTarget` among the passing tests and the whole
package green.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add .github/workflows/mls-syntax.yml mls/syntax/layering_test.go && git commit -m "ci(mls/syntax): gate every commit on family 16 and 60s of each fuzz target"
git push -u origin beta/message
```

---

## Done when

- `go test ./mls/syntax/... -count=1 -race` is green, including `TestVectorDeserialization` driving
  `VerifyDeserializationVector` over the family 16 file p8 Task 6 vendors, in both the verify and
  generate directions.
- The package's exported surface is registry §2 exactly — `Marshaler.MarshalMLS(w *Writer) error`,
  the error-returning `WriteOptional` and `WriteVector`, `WriteRaw`/`WriteOpaque` rather than
  `WriteBytes`/`WriteOpaqueVec`, `Done()` rather than `Finish()`, no `Rest()`, no append-style free
  functions — so p2 through p8 compile against it without a shim.
- `VerifyDeserializationVector` is exported from a non-test file, so p8 Task 8's registry shim can
  reach it.
- `go test ./mls/syntax -run=NONE -fuzz=<target> -fuzztime=60s` is clean for `FuzzVarint`,
  `FuzzOpaque` and `FuzzSyntaxStruct` — Spec A §13's A1 done-when.
- `TestSyntaxImportsStdlibOnly` passes, so the package can be imported from any wave.
- `mls-syntax.yml` is green on `beta/message`.
