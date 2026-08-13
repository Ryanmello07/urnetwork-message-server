# Tree Math Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the complete array-based ratchet-tree index arithmetic of RFC 9420 (Appendix C
and §4.1) in `connect/mls/tree_math.go`, with no cryptography and no node contents, so that every
later MLS plan computes tree structure through one audited, exhaustively tested file.

**Architecture:** One non-test file, `mls/tree_math.go`, holding three index types and twenty
exported operations that are pure functions of an index and a leaf count. The two operations that
depend on which nodes are blank — `Resolution` and `FilteredDirectPath` — take a three-method
`NodeShape` interface that `tree.go` (TreeKEM plan) implements over the real ratchet tree, so this
file never sees a public key. Imports are `errors` and `math/bits` and nothing else, ever.

**Tech Stack:** Go 1.26.5, `math/bits`, `errors`, `encoding/json` (tests only), Go native fuzzing.

## Global Constraints

- Go 1.26.5, pinned. `connect/go.mod` declares `go 1.26.3`; this plan does not change it. The
  Syntax and codec plan owns the single edit, in the form the canonical interface registry fixes
  (override O-3): leave the `go` directive at `1.26.3` and add `toolchain go1.26.5`. Raising the
  directive would raise the language floor for all of `connect`, which is out of this slice's scope.
- Standard library only for crypto: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, plus `chacha20poly1305` from the already-pinned `golang.org/x/crypto`. This plan uses none of them.
- NO cgo, NO Rust, NO new third-party crypto dependency. `sdk` must stay gomobile-buildable.
- OpenMLS (Rust) is a READ-ONLY differential oracle used out of process in CI. It is never in go.mod, never linked, never in a shipped artifact.
- Ciphersuite: exactly `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003). A second suite id is registered but unimplemented. Tree math is ciphersuite-independent and must contain no suite reference.
- Narrow v1 profile: BasicCredential only, no external commits, no external senders, no PSKs, no ReInit, no branching, no subgroups. All parse-refused with typed errors.
- `connect` (the parent package) must NEVER import `connect/mls` or `connect/message`. A package must not import its own subpackages. Enforced with a CI test.
- `connect/mls` must never import `connect` or `connect/message`.
- `sdk.GenerateSharedSecret`, `box.Precompute` and `curve25519.ScalarMult` MUST NOT be used. All X25519 goes through `crypto/ecdh` or `curve25519.X25519`, and a returned error is a hard validation failure — never logged and continued.
- MLS signs over serialized forms, so the TLS presentation-language codec must be byte-exact and round-trip stable. One codec, one fuzz corpus.
- `connect/CODESTYLE.md` applies: `self` receivers, usage+type naming, explicit struct field names, doc comment on every file, type and function, no name repetition in comments, no all-caps in comments.
- Per `CODESTYLE.md` §Tests: top-level `func TestXxx`, no `t.Run` for positive tests, plain table loops reporting with `t.Errorf`/`t.Fatalf`.
- Package-level functions are assumed safe for concurrent use. Every function in this file is pure and allocates only its own result, so the whole file is safe for concurrent use with no lock.
- `connect/mls` and `connect/message` have no timing-sensitive tests and must keep it that way.
- Max group size is 500 members and 10 device leaves per identity. Those are v1 product policy enforced in `commit.go`, **not** here. Tree math must carry no product limit.

### The four slice-wide conventions

Stated once in the canonical interface registry (§0) and carried verbatim by every plan.

**C1 — one codec, one method set.** Every wire type in `package mls` implements exactly:

```go
MarshalMLS(w *syntax.Writer) error
UnmarshalMLS(r *syntax.Reader) error
```

and nothing else. No `MarshalTo`, no `MarshalTLS`, no `Marshal() ([]byte, error)`, no
`Parse<Type>(data []byte)` free constructor, no `tls:` struct tags, no reflection. Byte-level access
is `syntax.Marshal(&v)` / `syntax.Unmarshal(bs, &v)`. Every wire type carries
`var _ syntax.Codec = (*T)(nil)` in its own file so drift fails at build rather than at Gate 4. The
two sanctioned exceptions are a concrete extension body's `Encode()` / `ParseXExtension(data)` pair,
and the validation plan's five codec-table closures.

**C2 — the syntax Writer is sticky *and* `MarshalMLS` returns an error.** Registry override O-1: the
leaf writes stay return-free and the sticky error is checked once at `Bytes()`, but the encoder must
be able to return a semantic refusal that is not a buffer error.

**C3 — counts are `LeafCount`, indices are `LeafIndex`/`NodeIndex`, and tree-math arithmetic that
can be out of range returns an error.** This plan's block (registry §4) is normative for every
caller. `TreeSize` does not exist.

**C4 — the GroupContext crosses a plan boundary as bytes.** Every framing entry point takes
`groupContext []byte`, obtained from `syntax.Marshal(gc)` or `(*Group).GroupContext()`.

C1, C2 and C4 bind nothing inside `tree_math.go`: this plan declares no wire type, imports no codec
and touches no group context. They are carried because the registry states them for every plan. C3
is this plan's own surface, and the four consuming plans are amended to it rather than the reverse.

## Repository and paths

All paths in this plan are relative to the `connect` repo root:

```
C:\Users\ryanm\Downloads\claude_sandbox_message\connect
```

Module `github.com/urnetwork/connect`. Spec A writes these paths as `connect/mls/...`; on disk the
same file is `mls/...`. All `go test` commands run from the repo root.

**Branch.** `beta/message` is cut once from `origin/main` by whichever wave-1 plan executes first.
Task 1 creates it only if it does not already exist, then branches `feat/mls-tree-math` from it.

**The git index hazard.** On this machine `.git/index` has twice disappeared mid-session, and
`git add` against a missing index silently rebuilds a partial index, so the next commit records that
partial index as the entire tree — a commit that deletes tracked files while claiming to add one.
Every commit step in this plan therefore counts tracked files before and after staging and refuses to
commit on an unexpected delta. Do not skip it. If the index is gone, rebuild with
`git read-tree HEAD`, never `git read-tree --empty && git add -A`.

---

## Why the vector family is necessary and nowhere near sufficient

Measured from `tree-math.json` at mlswg commit `cfd450286d1bfd9cd2519b95c80f9771f94a5b1a` — the file
the Validation and interop harness plan vendors into `mls/testdata/vectors/` as part of its single
sixteen-file vendoring task. This plan reads it and never writes it:

| Property | Measured |
|---|---|
| Entries in `tree-math.json` | 10 |
| Tree sizes covered | 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 — every one a power of two |
| Fields per entry | 7 (`n_leaves`, `n_nodes`, `root`, `left`, `right`, `parent`, `sibling`) |
| Nodes across all entries | 2036 |
| Relation assertions the family can make | 8144 |
| Exported callables in this plan | 24 |
| Exported callables the family exercises | 6 — `NodeWidth`, `Root`, `Left`, `Right`, `Parent`, `Sibling` |

The family tests **none** of `DirectPath`, `Copath`, `CommonAncestor`, `SubtreeSpan`,
`SubtreeLeaves`, `InSubtree`, `Resolution`, `FilteredDirectPath`, `FullLeafCount`, `TreeDepth`,
`LeafCountFromNodeWidth`, `ExtendedLeafCount` or `TruncatedLeafCount`. `Resolution` and
`FilteredDirectPath` are the only two operations here whose answer depends on which nodes are blank,
and they are precisely the two that decide **what an UpdatePath encrypts to and how long it is** —
ValSem202, ValSem203 and ValSem204 all sit downstream of them. A bug in either is a silent
confidentiality or interop failure that passes 100% of family 1.

The gate for this plan is therefore family 1 **plus** four things the family cannot provide:

1. The RFC's own worked examples reproduced exactly — Figure 10 (resolution with blanks and unmerged
   leaves) and Table 2 / Figure 11 (direct path, copath and filtered direct path for five members in
   an eight-leaf tree). These are the only published expected outputs for the blank-node rules.
2. A self-differential test: RFC 9420 gives two independent definitions of the common ancestor
   (`common_ancestor_semantic`, built from direct paths, and `common_ancestor_direct`, pure bit
   arithmetic). The semantic one lives in the test file as an oracle and the two must agree on every
   pair, at every tree size.
3. An exhaustive structural invariant sweep over every node of every tree size from 1 to 512 leaves.
4. A fuzz target over the whole `(NodeIndex, LeafCount)` domain asserting no panic, no unbounded
   allocation, no unbounded loop, and that every returned index is inside the tree.

---

## File Structure

| File | Created or modified | Single responsibility |
|---|---|---|
| `mls/tree_math.go` | Create | Every array-based ratchet-tree index computation and the two blank-node shape rules. Imports `errors` and `math/bits` only. No crypto, no node contents, no product limits. |
| `mls/tree_math_test.go` | Create | Unit tests: RFC Figure 10 and Table 2 fixtures, the semantic common-ancestor oracle, the exhaustive invariant sweep. |
| `mls/tree_math_kat_test.go` | Create | The family-1 runner: the corpus tripwire, `verifyTreeMathVector`, `generateTreeMathVectors`, the `RegisterVectorFamily` `init()` and the `TestTreeMathVectors` gate test. |
| `mls/tree_math_fuzz_test.go` | Create | `FuzzTreeMath` — properties 1 and 2 of Gate 4 for the tree-math surface. |
| `mls/vectors_test.go` | Modify, one line | Delete `1` from `expectedPendingFamilies` in the same commit that registers family 1. The file itself is the Validation and interop harness plan's. |

**Files this plan must NOT create**, because another plan owns them:

- `mls/doc.go` or any `// Package mls ...` comment — owned by the Crypto primitives and HPKE plan,
  whose `suite.go` is the natural package header. `tree_math.go` gets a file doc comment, not a
  package doc comment.
- `mls/errors.go` and `mls/profile.go` — owned by the Validation and interop harness plan, which
  holds one typed error per ValSem code and the whole narrow-profile gate. The nine structural
  errors this plan defines are not ValSem codes and live in `tree_math.go`.
- `mls/vectors_test.go` — owned by the Validation and interop harness plan: `VectorFamily`,
  `RegisterVectorFamily`, `LoadVectorFile`, `MustHex`, `HexOf` and `expectedPendingFamilies` are all
  declared there. This plan calls them and deletes exactly one entry from
  `expectedPendingFamilies`; it declares none of them and writes no second hex decoder or second
  corpus reader.
- `mls/testdata/vectors/tree-math.json`, any other vendored vector file, `testdata/vectors/VECTORS.sha256`,
  and any `PINS.md` — the Validation and interop harness plan has the single vendoring task for all
  sixteen mlswg files, and the one pin file in the slice is `mls/interop/PINS.md`. Earlier drafts of
  this plan created `mls/testdata/vectors/PINS.md`; that file does not exist and must not be
  recreated, because three plans writing three pin formats to three paths is how the pin greps in the
  framing and lifecycle plans expand to an empty commit.
- Any CI workflow file — owned by the Validation and interop harness plan. See "Definition of done"
  for the exact gate commands it must call.

---

### Task 1: Branch, the family-1 loader, and the vector-shape tripwire

**Files:**
- Create: `mls/tree_math.go` (package clause and file doc comment only)
- Test: `mls/tree_math_kat_test.go`

**Interfaces:**
- Consumes, from the Validation and interop harness plan (wave 1, and its vendoring task and vector
  registry land before this task runs):

```go
func LoadVectorFile(t *testing.T, file string) []json.RawMessage
```

- Produces: no exported package API. `mls/tree_math.go` with its file doc comment, the
  `treeMathVector` entry type, `loadTreeMathVectors` and `TestTreeMathVectorFileShape`.

**Sequencing.** `tree_math.go` itself consumes nothing and could be written on day one. The runner
cannot: `tree-math.json` and `LoadVectorFile` both belong to the Validation and interop harness
plan, which vendors all sixteen mlswg files in one task and declares the loader, the family registry
and `MustHex` in `mls/vectors_test.go`. Both are wave-1, phase-A items, so the only ordering this
adds is "that plan's vendoring and registry tasks first". Nothing in this plan vendors, pins or
re-reads the corpus by hand.

- [ ] **Step 1: Write the failing test**

Create `mls/tree_math_kat_test.go`:

```go
// the RFC 9420 tree-math test-vector family, family 1 of the sixteen the
// validation and interop harness plan vendors into testdata/vectors.
//
// the entries are plain integers, so this file decodes them itself, but the
// bytes come from the shared loader: one reader of the vendored corpus, one
// place a vendoring mistake surfaces. families whose fields are hex-encoded
// also call MustHex; this one has no hex field.
package mls

import (
	"encoding/json"
	"testing"
)

// one entry of the family. every relation column is optional: null means the
// function is undefined at that node, which is as much a part of the vector as
// an index is.
type treeMathVector struct {
	NLeaves uint32    `json:"n_leaves"`
	NNodes  uint32    `json:"n_nodes"`
	Root    uint32    `json:"root"`
	Left    []*uint32 `json:"left"`
	Right   []*uint32 `json:"right"`
	Parent  []*uint32 `json:"parent"`
	Sibling []*uint32 `json:"sibling"`
}

// the family file, named relative to testdata/vectors exactly as
// VectorFamily.File is.
const treeMathVectorFile = "tree-math.json"

// decodes the vendored family through the shared loader, failing the test
// rather than returning an error so every caller is a one-liner.
func loadTreeMathVectors(t *testing.T) []treeMathVector {
	t.Helper()
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	vectors := make([]treeMathVector, 0, len(rawEntries))
	for i, rawEntry := range rawEntries {
		var vector treeMathVector
		if err := json.Unmarshal(rawEntry, &vector); err != nil {
			t.Fatalf("decode %s entry %d: %v", treeMathVectorFile, i, err)
		}
		vectors = append(vectors, vector)
	}
	return vectors
}

// a tripwire on the corpus itself. the mlswg format is not versioned in the
// file, so a field added upstream would otherwise be vendored and silently
// ignored, and a bump that dropped entries would shrink the gate without
// failing anything.
func TestTreeMathVectorFileShape(t *testing.T) {
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	if len(rawEntries) != 10 {
		t.Fatalf("entries: %d, want 10", len(rawEntries))
	}

	wantFields := []string{"n_leaves", "n_nodes", "root", "left", "right", "parent", "sibling"}
	for i, rawEntry := range rawEntries {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(rawEntry, &entry); err != nil {
			t.Fatalf("decode %s entry %d: %v", treeMathVectorFile, i, err)
		}
		if len(entry) != len(wantFields) {
			t.Fatalf("entry %d: %d fields, want %d — the upstream format changed and the runner must be extended", i, len(entry), len(wantFields))
		}
		for _, field := range wantFields {
			if _, ok := entry[field]; !ok {
				t.Fatalf("entry %d: missing field %s", i, field)
			}
		}
	}

	vectors := loadTreeMathVectors(t)
	wantLeaves := []uint32{1, 2, 4, 8, 16, 32, 64, 128, 256, 512}
	totalNodes := uint32(0)
	for i, v := range vectors {
		if v.NLeaves != wantLeaves[i] {
			t.Fatalf("entry %d: n_leaves %d, want %d", i, v.NLeaves, wantLeaves[i])
		}
		if v.NLeaves&(v.NLeaves-1) != 0 {
			t.Fatalf("entry %d: n_leaves %d is not a power of two", i, v.NLeaves)
		}
		columns := map[string]int{
			"left":    len(v.Left),
			"right":   len(v.Right),
			"parent":  len(v.Parent),
			"sibling": len(v.Sibling),
		}
		for name, length := range columns {
			if uint32(length) != v.NNodes {
				t.Fatalf("entry %d: %s has %d entries, want n_nodes %d", i, name, length, v.NNodes)
			}
		}
		totalNodes += v.NNodes
	}
	if totalNodes != 2036 {
		t.Fatalf("nodes across the family: %d, want 2036", totalNodes)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

This task produces a tripwire on a corpus another plan vendors, so the way to see it red is to trip
it. Move the vendored file aside and run:

```bash
mv mls/testdata/vectors/tree-math.json mls/testdata/vectors/tree-math.json.away
go test ./mls/... -run TestTreeMathVectorFileShape -v
```

Expected: FAIL inside `LoadVectorFile`, reporting that `testdata/vectors/tree-math.json` could not
be read. A PASS here means the runner is not reading the corpus at all, which is the one failure
mode a vector runner must never have.

Restore it before step 3:

```bash
mv mls/testdata/vectors/tree-math.json.away mls/testdata/vectors/tree-math.json
git status --porcelain mls/testdata/vectors
```

The `git status` line must come back empty — the corpus belongs to another plan's commit and this
plan leaves it byte-identical.

- [ ] **Step 3: Cut the branch and create the stub**

Run from the repo root (Git Bash):

```bash
git rev-parse --verify beta/message >/dev/null 2>&1 || git branch beta/message origin/main
git checkout beta/message
git checkout -b feat/mls-tree-math
test -f mls/testdata/vectors/tree-math.json || { echo "family 1 is not vendored yet: run the validation plan's vendoring task first"; exit 1; }
```

Create `mls/tree_math.go`:

```go
// array-based ratchet-tree index arithmetic, per RFC 9420 appendix C and
// section 4.1.
//
// nothing in this file is cryptographic and nothing in it reads a node's
// contents, so it is deterministic, exhaustively testable, and safe to call
// from any goroutine. leaves are even-numbered nodes, with leaf L at node 2*L,
// and intermediate nodes are odd-numbered.
//
// the tree is always full: RFC 9420 section 7.7 states that adding or removing
// leaves doubles or halves the tree, so a valid leaf count is always a power of
// two. every function here that takes a leaf count enforces that, which is
// stricter than the appendix C pseudocode and deliberately so — appendix C with
// a non-power-of-two count silently answers for the enclosing full tree and can
// return an index past the end of the node array.
//
// no group-size policy lives here. the 500-member and 10-device caps are v1
// product rules enforced in commit.go.
package mls
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeMathVectorFileShape -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_kat_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 2 ] || { echo "git index anomaly: $before -> $after, expected +2"; exit 1; }
git commit -m "feat(mls): tree-math file skeleton and a corpus-shape tripwire on vector family 1"
```

---

### Task 2: Index types, level, and node width

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type LeafIndex uint32`
  - `type NodeIndex uint32`
  - `type LeafCount uint32`
  - `const MaxLeafCount LeafCount = 1 << 31`
  - `func (self LeafIndex) NodeIndex() NodeIndex`
  - `func (self NodeIndex) IsLeaf() bool`
  - `func (self NodeIndex) LeafIndex() (LeafIndex, error)`
  - `func (self NodeIndex) Level() uint32`
  - `func NodeWidth(n LeafCount) uint32`
  - `var ErrLeafCountRange, ErrLeafCountNotFull, ErrNodeOutOfRange, ErrLeafOutOfRange, ErrNodeIsParent, ErrLeafHasNoChildren, ErrRootHasNoParent, ErrRootHasNoSibling, ErrNodeWidthNotOdd error`

- [ ] **Step 1: Write the failing test**

Create `mls/tree_math_test.go`:

```go
// unit tests for the array-based ratchet-tree arithmetic.
//
// the mlswg tree-math vector family covers six of this file's twenty-four
// exported callables and only at power-of-two sizes, so the tests here carry
// the rest: the two worked examples RFC 9420 publishes, a differential against
// the RFC's own second definition of the common ancestor, and an exhaustive
// sweep of every node of every tree size up to 512 leaves.
package mls

import (
	"errors"
	"testing"
)

func TestNodeIndexLevelAndLeafMapping(t *testing.T) {
	// RFC 9420 figure 32, the eight-leaf tree drawn as an array.
	levelCases := []struct {
		nodeIndex NodeIndex
		level     uint32
	}{
		{nodeIndex: 0, level: 0},
		{nodeIndex: 1, level: 1},
		{nodeIndex: 2, level: 0},
		{nodeIndex: 3, level: 2},
		{nodeIndex: 4, level: 0},
		{nodeIndex: 5, level: 1},
		{nodeIndex: 6, level: 0},
		{nodeIndex: 7, level: 3},
		{nodeIndex: 8, level: 0},
		{nodeIndex: 9, level: 1},
		{nodeIndex: 10, level: 0},
		{nodeIndex: 11, level: 2},
		{nodeIndex: 12, level: 0},
		{nodeIndex: 13, level: 1},
		{nodeIndex: 14, level: 0},
	}
	for _, c := range levelCases {
		if got := c.nodeIndex.Level(); got != c.level {
			t.Errorf("node %d level: %d, want %d", c.nodeIndex, got, c.level)
		}
		wantLeaf := c.level == 0
		if got := c.nodeIndex.IsLeaf(); got != wantLeaf {
			t.Errorf("node %d is leaf: %v, want %v", c.nodeIndex, got, wantLeaf)
		}
	}

	for leaf := LeafIndex(0); leaf < 8; leaf += 1 {
		nodeIndex := leaf.NodeIndex()
		if nodeIndex != NodeIndex(2*leaf) {
			t.Errorf("leaf %d node index: %d, want %d", leaf, nodeIndex, 2*leaf)
		}
		back, err := nodeIndex.LeafIndex()
		if err != nil {
			t.Errorf("node %d leaf index: %v", nodeIndex, err)
			continue
		}
		if back != leaf {
			t.Errorf("node %d leaf index: %d, want %d", nodeIndex, back, leaf)
		}
	}

	if _, err := NodeIndex(1).LeafIndex(); !errors.Is(err, ErrNodeIsParent) {
		t.Errorf("node 1 leaf index error: %v, want %v", err, ErrNodeIsParent)
	}
}

func TestNodeWidth(t *testing.T) {
	widthCases := []struct {
		leafCount LeafCount
		nodeWidth uint32
	}{
		{leafCount: 0, nodeWidth: 0},
		{leafCount: 1, nodeWidth: 1},
		{leafCount: 2, nodeWidth: 3},
		{leafCount: 3, nodeWidth: 5},
		{leafCount: 4, nodeWidth: 7},
		{leafCount: 6, nodeWidth: 11},
		{leafCount: 8, nodeWidth: 15},
		{leafCount: 512, nodeWidth: 1023},
		{leafCount: MaxLeafCount, nodeWidth: 0xFFFFFFFF},
		{leafCount: MaxLeafCount + 1, nodeWidth: 0},
	}
	for _, c := range widthCases {
		if got := NodeWidth(c.leafCount); got != c.nodeWidth {
			t.Errorf("node width of %d leaves: %d, want %d", c.leafCount, got, c.nodeWidth)
		}
	}
}
```

Note the two deliberate non-power-of-two rows: `NodeWidth` is the one sizing function that follows
appendix C exactly for any count, because the `ratchet_tree` group-context extension carries an array
whose trailing blanks are stripped and whose width is `node_width` of a non-power-of-two count.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run 'TestNodeIndexLevelAndLeafMapping|TestNodeWidth' -v`

Expected: FAIL to build with `undefined: NodeIndex`, `undefined: LeafIndex`, `undefined: LeafCount`,
`undefined: NodeWidth`, `undefined: ErrNodeIsParent`, `undefined: MaxLeafCount`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
import (
	"errors"
	"math/bits"
)

// the index of a leaf, counted from zero at the left. a member of the group
// occupies exactly one leaf.
type LeafIndex uint32

// the index of any node in the flat array, leaf or parent.
type NodeIndex uint32

// the number of leaves in a tree, always a power of two for a valid tree
// (RFC 9420 section 7.7).
type LeafCount uint32

// the largest representable tree. node width of this count is 2^32-1, the
// largest value a node index can hold, so every index computation in this file
// stays inside uint32 without a carry.
const MaxLeafCount LeafCount = 1 << 31

var (
	ErrLeafCountRange    = errors.New("mls: leaf count out of range")
	ErrLeafCountNotFull  = errors.New("mls: leaf count is not a power of two")
	ErrNodeOutOfRange    = errors.New("mls: node index outside the tree")
	ErrLeafOutOfRange    = errors.New("mls: leaf index outside the tree")
	ErrNodeIsParent      = errors.New("mls: node index is a parent, not a leaf")
	ErrLeafHasNoChildren = errors.New("mls: leaf node has no children")
	ErrRootHasNoParent   = errors.New("mls: root node has no parent")
	ErrRootHasNoSibling  = errors.New("mls: root node has no sibling")
	ErrNodeWidthNotOdd   = errors.New("mls: node array width is not odd")
)

// the exponent of the largest power of two not greater than x. zero for x == 0,
// matching the appendix C special case rather than being undefined there.
func log2(x uint32) uint32 {
	if x == 0 {
		return 0
	}
	return uint32(bits.Len32(x) - 1)
}

// the array position of a leaf: leaf L sits at node 2*L.
func (self LeafIndex) NodeIndex() NodeIndex {
	return NodeIndex(2 * uint32(self))
}

// even node indices are leaves, odd ones are parents.
func (self NodeIndex) IsLeaf() bool {
	return self&0x01 == 0
}

// the inverse of LeafIndex.NodeIndex, refused for a parent rather than
// silently truncating.
func (self NodeIndex) LeafIndex() (LeafIndex, error) {
	if !self.IsLeaf() {
		return 0, ErrNodeIsParent
	}
	return LeafIndex(uint32(self) / 2), nil
}

// leaves are level zero, their parents level one, and so on. the level of an
// odd index is its count of trailing one bits.
//
// the only index whose level is 32 is 0xFFFFFFFF, which is one past the last
// node of the largest representable tree and therefore never inside one; the
// value is returned rather than special-cased so this stays a total function.
func (self NodeIndex) Level() uint32 {
	if self.IsLeaf() {
		return 0
	}
	return uint32(bits.TrailingZeros32(^uint32(self)))
}

// the number of nodes in the flat array for a tree with n leaves.
//
// deliberately total and deliberately not restricted to full leaf counts: the
// ratchet_tree extension carries an array with its trailing blank nodes
// stripped, so a width of node_width(6) = 11 is a legal thing to reason about
// even though a tree never has six leaves. a count past MaxLeafCount returns
// zero so that every downstream range check fails closed.
func NodeWidth(n LeafCount) uint32 {
	if n == 0 || n > MaxLeafCount {
		return 0
	}
	return 2*(uint32(n)-1) + 1
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run 'TestNodeIndexLevelAndLeafMapping|TestNodeWidth' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 1 ] || { echo "git index anomaly: $before -> $after, expected +1"; exit 1; }
git commit -m "feat(mls): index types, node level and node width"
```

---

### Task 3: Full-tree sizing, extension and truncation

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: `NodeWidth`, `MaxLeafCount`, `log2`, the error set (Task 2).
- Produces:
  - `func IsFullLeafCount(n LeafCount) bool`
  - `func TreeDepth(n LeafCount) uint32`
  - `func FullLeafCount(n LeafCount) LeafCount`
  - `func LeafCountFromNodeWidth(w uint32) (LeafCount, error)`
  - `func ExtendedLeafCount(n LeafCount) (LeafCount, error)`
  - `func TruncatedLeafCount(rightmostNonBlankLeaf LeafIndex) (LeafCount, error)`

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_test.go`:

```go
func TestFullLeafCountAndDepth(t *testing.T) {
	sizeCases := []struct {
		leafCount     LeafCount
		full          bool
		depth         uint32
		fullLeafCount LeafCount
	}{
		{leafCount: 0, full: false, depth: 0, fullLeafCount: 0},
		{leafCount: 1, full: true, depth: 0, fullLeafCount: 1},
		{leafCount: 2, full: true, depth: 1, fullLeafCount: 2},
		{leafCount: 3, full: false, depth: 2, fullLeafCount: 4},
		{leafCount: 4, full: true, depth: 2, fullLeafCount: 4},
		{leafCount: 5, full: false, depth: 3, fullLeafCount: 8},
		{leafCount: 6, full: false, depth: 3, fullLeafCount: 8},
		{leafCount: 8, full: true, depth: 3, fullLeafCount: 8},
		{leafCount: 512, full: true, depth: 9, fullLeafCount: 512},
		{leafCount: MaxLeafCount, full: true, depth: 31, fullLeafCount: MaxLeafCount},
		{leafCount: MaxLeafCount + 1, full: false, depth: 31, fullLeafCount: 0},
	}
	for _, c := range sizeCases {
		if got := IsFullLeafCount(c.leafCount); got != c.full {
			t.Errorf("%d leaves full: %v, want %v", c.leafCount, got, c.full)
		}
		if got := TreeDepth(c.leafCount); got != c.depth {
			t.Errorf("%d leaves depth: %d, want %d", c.leafCount, got, c.depth)
		}
		if got := FullLeafCount(c.leafCount); got != c.fullLeafCount {
			t.Errorf("%d leaves full count: %d, want %d", c.leafCount, got, c.fullLeafCount)
		}
	}
}

func TestLeafCountFromNodeWidth(t *testing.T) {
	// the ratchet_tree extension strips trailing blank nodes, so a legal
	// encoded array can be any odd width. six non-blank leaves encode as
	// eleven nodes, and the receiver extends that to the enclosing full tree
	// of eight leaves (RFC 9420 section 12.4.3.1).
	widthCases := []struct {
		nodeWidth uint32
		leafCount LeafCount
	}{
		{nodeWidth: 1, leafCount: 1},
		{nodeWidth: 3, leafCount: 2},
		{nodeWidth: 5, leafCount: 3},
		{nodeWidth: 11, leafCount: 6},
		{nodeWidth: 1023, leafCount: 512},
		{nodeWidth: 0xFFFFFFFF, leafCount: MaxLeafCount},
	}
	for _, c := range widthCases {
		got, err := LeafCountFromNodeWidth(c.nodeWidth)
		if err != nil {
			t.Errorf("width %d: %v", c.nodeWidth, err)
			continue
		}
		if got != c.leafCount {
			t.Errorf("width %d: %d leaves, want %d", c.nodeWidth, got, c.leafCount)
		}
		if roundTrip := NodeWidth(got); roundTrip != c.nodeWidth {
			t.Errorf("width %d round trip: %d", c.nodeWidth, roundTrip)
		}
	}

	if _, err := LeafCountFromNodeWidth(0); !errors.Is(err, ErrNodeWidthNotOdd) {
		t.Errorf("width 0: %v, want %v", err, ErrNodeWidthNotOdd)
	}
	if _, err := LeafCountFromNodeWidth(10); !errors.Is(err, ErrNodeWidthNotOdd) {
		t.Errorf("width 10: %v, want %v", err, ErrNodeWidthNotOdd)
	}

	if got := FullLeafCount(6); got != 8 {
		t.Errorf("full count containing 6 leaves: %d, want 8", got)
	}
}

func TestExtendAndTruncate(t *testing.T) {
	// RFC 9420 section 7.7: extending doubles the tree.
	extendCases := []struct {
		leafCount LeafCount
		extended  LeafCount
	}{
		{leafCount: 0, extended: 1},
		{leafCount: 1, extended: 2},
		{leafCount: 2, extended: 4},
		{leafCount: 512, extended: 1024},
	}
	for _, c := range extendCases {
		got, err := ExtendedLeafCount(c.leafCount)
		if err != nil {
			t.Errorf("extend %d: %v", c.leafCount, err)
			continue
		}
		if got != c.extended {
			t.Errorf("extend %d: %d, want %d", c.leafCount, got, c.extended)
		}
	}
	if _, err := ExtendedLeafCount(3); !errors.Is(err, ErrLeafCountNotFull) {
		t.Errorf("extend 3: %v, want %v", err, ErrLeafCountNotFull)
	}
	if _, err := ExtendedLeafCount(MaxLeafCount); !errors.Is(err, ErrLeafCountRange) {
		t.Errorf("extend MaxLeafCount: %v, want %v", err, ErrLeafCountRange)
	}

	// RFC 9420 section 12.1.3: after a remove, the tree is truncated to 2^d
	// leaves where d is the smallest value with 2^d greater than the index of
	// the rightmost non-blank leaf.
	truncateCases := []struct {
		rightmostNonBlankLeaf LeafIndex
		leafCount             LeafCount
	}{
		{rightmostNonBlankLeaf: 0, leafCount: 1},
		{rightmostNonBlankLeaf: 1, leafCount: 2},
		{rightmostNonBlankLeaf: 2, leafCount: 4},
		{rightmostNonBlankLeaf: 3, leafCount: 4},
		{rightmostNonBlankLeaf: 4, leafCount: 8},
		{rightmostNonBlankLeaf: 7, leafCount: 8},
		{rightmostNonBlankLeaf: 8, leafCount: 16},
		{rightmostNonBlankLeaf: 499, leafCount: 512},
	}
	for _, c := range truncateCases {
		got, err := TruncatedLeafCount(c.rightmostNonBlankLeaf)
		if err != nil {
			t.Errorf("truncate to leaf %d: %v", c.rightmostNonBlankLeaf, err)
			continue
		}
		if got != c.leafCount {
			t.Errorf("truncate to leaf %d: %d leaves, want %d", c.rightmostNonBlankLeaf, got, c.leafCount)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run 'TestFullLeafCountAndDepth|TestLeafCountFromNodeWidth|TestExtendAndTruncate' -v`

Expected: FAIL to build with `undefined: IsFullLeafCount`, `undefined: TreeDepth`,
`undefined: FullLeafCount`, `undefined: LeafCountFromNodeWidth`, `undefined: ExtendedLeafCount`,
`undefined: TruncatedLeafCount`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// whether n is a leaf count a valid tree can actually have: non-zero, in range,
// and a power of two.
func IsFullLeafCount(n LeafCount) bool {
	return n > 0 && n <= MaxLeafCount && n&(n-1) == 0
}

// the depth of the full tree that contains n leaves, which is the length of any
// leaf's direct path in that tree. one leaf is depth zero.
func TreeDepth(n LeafCount) uint32 {
	if n <= 1 {
		return 0
	}
	return uint32(bits.Len32(uint32(n) - 1))
}

// the smallest full leaf count that contains n leaves. zero for n == 0 and for
// n past MaxLeafCount, so an out-of-range count fails closed.
func FullLeafCount(n LeafCount) LeafCount {
	if n == 0 || n > MaxLeafCount {
		return 0
	}
	return LeafCount(1) << TreeDepth(n)
}

// the leaf count an array of w nodes describes. every node array has an odd
// width, and a truncated ratchet_tree array yields a count that is not a power
// of two — pass the result through FullLeafCount to get the tree it belongs to.
func LeafCountFromNodeWidth(w uint32) (LeafCount, error) {
	if w == 0 || w%2 == 0 {
		return 0, ErrNodeWidthNotOdd
	}
	return LeafCount((uint64(w) + 1) / 2), nil
}

// the leaf count after adding a blank root whose left subtree is the existing
// tree (RFC 9420 section 7.7). an empty tree extends to one leaf.
func ExtendedLeafCount(n LeafCount) (LeafCount, error) {
	if n == 0 {
		return 1, nil
	}
	if !IsFullLeafCount(n) {
		return 0, ErrLeafCountNotFull
	}
	if n == MaxLeafCount {
		return 0, ErrLeafCountRange
	}
	return n * 2, nil
}

// the leaf count after removing right subtrees until one holds a non-blank leaf
// (RFC 9420 section 12.1.3): 2^d for the smallest d with 2^d greater than the
// index of the rightmost non-blank leaf.
//
// which leaf that is depends on node contents and is decided by the caller;
// only the arithmetic lives here.
func TruncatedLeafCount(rightmostNonBlankLeaf LeafIndex) (LeafCount, error) {
	if LeafCount(rightmostNonBlankLeaf) >= MaxLeafCount {
		return 0, ErrLeafOutOfRange
	}
	return LeafCount(1) << TreeDepth(LeafCount(rightmostNonBlankLeaf)+1), nil
}

// the shared entry check for every function that takes a leaf count and answers
// about a real tree.
func checkLeafCount(n LeafCount) error {
	if n == 0 || n > MaxLeafCount {
		return ErrLeafCountRange
	}
	if !IsFullLeafCount(n) {
		return ErrLeafCountNotFull
	}
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run 'TestFullLeafCountAndDepth|TestLeafCountFromNodeWidth|TestExtendAndTruncate' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): full-tree sizing, extension and truncation arithmetic"
```

---

### Task 4: Root, against the vector family

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_kat_test.go`

**Interfaces:**
- Consumes: `NodeWidth`, `log2`, `checkLeafCount`, `FullLeafCount` (Tasks 2 and 3).
- Produces: `func Root(n LeafCount) (NodeIndex, error)`

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_kat_test.go`:

```go
func TestTreeMathVectorRoot(t *testing.T) {
	vectors := loadTreeMathVectors(t)
	for _, v := range vectors {
		leafCount := LeafCount(v.NLeaves)
		if got := NodeWidth(leafCount); got != v.NNodes {
			t.Errorf("n_leaves %d: node width %d, want %d", v.NLeaves, got, v.NNodes)
		}
		root, err := Root(leafCount)
		if err != nil {
			t.Errorf("n_leaves %d: root: %v", v.NLeaves, err)
			continue
		}
		if uint32(root) != v.Root {
			t.Errorf("n_leaves %d: root %d, want %d", v.NLeaves, root, v.Root)
		}
	}

	// a leaf count that is not a power of two is refused rather than answered
	// for the enclosing full tree, which is what the appendix C pseudocode
	// silently does.
	if _, err := Root(3); !errors.Is(err, ErrLeafCountNotFull) {
		t.Errorf("root of 3 leaves: %v, want %v", err, ErrLeafCountNotFull)
	}
	if _, err := Root(0); !errors.Is(err, ErrLeafCountRange) {
		t.Errorf("root of 0 leaves: %v, want %v", err, ErrLeafCountRange)
	}
	if _, err := Root(MaxLeafCount + 1); !errors.Is(err, ErrLeafCountRange) {
		t.Errorf("root past MaxLeafCount: %v, want %v", err, ErrLeafCountRange)
	}

	root, err := Root(MaxLeafCount)
	if err != nil {
		t.Fatalf("root of MaxLeafCount: %v", err)
	}
	if root != NodeIndex(1<<31)-1 {
		t.Errorf("root of MaxLeafCount: %d, want %d", root, NodeIndex(1<<31)-1)
	}
}
```

Add `"errors"` to the import block of `mls/tree_math_kat_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestTreeMathVectorRoot -v`

Expected: FAIL to build with `undefined: Root`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// the index of the root of a tree with n leaves.
//
// the root sits at 2^d - 1 for a tree of depth d, so it is the one index that
// is the same for every count in a doubling band — which is exactly why a
// non-power-of-two count is refused here rather than quietly answered.
func Root(n LeafCount) (NodeIndex, error) {
	if err := checkLeafCount(n); err != nil {
		return 0, err
	}
	w := NodeWidth(n)
	return NodeIndex((uint32(1) << log2(w)) - 1), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeMathVectorRoot -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_kat_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): tree root index, checked against vector family 1"
```

---

### Task 5: Left and Right, against the vector family

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_kat_test.go`

**Interfaces:**
- Consumes: `NodeIndex.Level`, `ErrLeafHasNoChildren`, `ErrNodeOutOfRange` (Task 2).
- Produces:
  - `func Left(x NodeIndex) (NodeIndex, error)`
  - `func Right(x NodeIndex) (NodeIndex, error)`

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_kat_test.go`:

```go
func TestTreeMathVectorChildren(t *testing.T) {
	vectors := loadTreeMathVectors(t)
	for _, v := range vectors {
		for i := uint32(0); i < v.NNodes; i += 1 {
			nodeIndex := NodeIndex(i)

			gotLeft, leftErr := Left(nodeIndex)
			if want := v.Left[i]; want == nil {
				if leftErr == nil {
					t.Errorf("n_leaves %d node %d: left %d, want undefined", v.NLeaves, i, gotLeft)
				} else if !errors.Is(leftErr, ErrLeafHasNoChildren) {
					t.Errorf("n_leaves %d node %d: left: %v, want %v", v.NLeaves, i, leftErr, ErrLeafHasNoChildren)
				}
			} else {
				if leftErr != nil {
					t.Errorf("n_leaves %d node %d: left: %v, want %d", v.NLeaves, i, leftErr, *want)
				} else if uint32(gotLeft) != *want {
					t.Errorf("n_leaves %d node %d: left %d, want %d", v.NLeaves, i, gotLeft, *want)
				}
			}

			gotRight, rightErr := Right(nodeIndex)
			if want := v.Right[i]; want == nil {
				if rightErr == nil {
					t.Errorf("n_leaves %d node %d: right %d, want undefined", v.NLeaves, i, gotRight)
				} else if !errors.Is(rightErr, ErrLeafHasNoChildren) {
					t.Errorf("n_leaves %d node %d: right: %v, want %v", v.NLeaves, i, rightErr, ErrLeafHasNoChildren)
				}
			} else {
				if rightErr != nil {
					t.Errorf("n_leaves %d node %d: right: %v, want %d", v.NLeaves, i, rightErr, *want)
				} else if uint32(gotRight) != *want {
					t.Errorf("n_leaves %d node %d: right %d, want %d", v.NLeaves, i, gotRight, *want)
				}
			}
		}
	}

	// 0xFFFFFFFF is one past the last node of the largest representable tree,
	// and its level of 32 would shift a child computation off the end of a
	// uint32. it is refused rather than answered with a truncated index.
	if _, err := Left(NodeIndex(0xFFFFFFFF)); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("left of 0xFFFFFFFF: %v, want %v", err, ErrNodeOutOfRange)
	}
	if _, err := Right(NodeIndex(0xFFFFFFFF)); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("right of 0xFFFFFFFF: %v, want %v", err, ErrNodeOutOfRange)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestTreeMathVectorChildren -v`

Expected: FAIL to build with `undefined: Left`, `undefined: Right`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// the left child of a parent node. children are computed from the index alone,
// so no leaf count is needed and the answer is the same in every tree that
// contains x.
func Left(x NodeIndex) (NodeIndex, error) {
	k := x.Level()
	if k == 0 {
		return 0, ErrLeafHasNoChildren
	}
	if k > 31 {
		return 0, ErrNodeOutOfRange
	}
	return x ^ NodeIndex(uint32(0x01)<<(k-1)), nil
}

// the right child of a parent node.
func Right(x NodeIndex) (NodeIndex, error) {
	k := x.Level()
	if k == 0 {
		return 0, ErrLeafHasNoChildren
	}
	if k > 31 {
		return 0, ErrNodeOutOfRange
	}
	return x ^ NodeIndex(uint32(0x03)<<(k-1)), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeMathVectorChildren -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_kat_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): left and right children, checked against vector family 1"
```

---

### Task 6: Parent and Sibling, against the vector family

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_kat_test.go`

**Interfaces:**
- Consumes: `Root`, `NodeWidth`, `Left`, `Right`, `NodeIndex.Level` (Tasks 2, 4, 5).
- Produces:
  - `func Parent(x NodeIndex, n LeafCount) (NodeIndex, error)`
  - `func Sibling(x NodeIndex, n LeafCount) (NodeIndex, error)`

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_kat_test.go`:

```go
func TestTreeMathVectorParentAndSibling(t *testing.T) {
	vectors := loadTreeMathVectors(t)
	for _, v := range vectors {
		leafCount := LeafCount(v.NLeaves)
		for i := uint32(0); i < v.NNodes; i += 1 {
			nodeIndex := NodeIndex(i)

			gotParent, parentErr := Parent(nodeIndex, leafCount)
			if want := v.Parent[i]; want == nil {
				if parentErr == nil {
					t.Errorf("n_leaves %d node %d: parent %d, want undefined", v.NLeaves, i, gotParent)
				} else if !errors.Is(parentErr, ErrRootHasNoParent) {
					t.Errorf("n_leaves %d node %d: parent: %v, want %v", v.NLeaves, i, parentErr, ErrRootHasNoParent)
				}
			} else {
				if parentErr != nil {
					t.Errorf("n_leaves %d node %d: parent: %v, want %d", v.NLeaves, i, parentErr, *want)
				} else if uint32(gotParent) != *want {
					t.Errorf("n_leaves %d node %d: parent %d, want %d", v.NLeaves, i, gotParent, *want)
				}
			}

			gotSibling, siblingErr := Sibling(nodeIndex, leafCount)
			if want := v.Sibling[i]; want == nil {
				if siblingErr == nil {
					t.Errorf("n_leaves %d node %d: sibling %d, want undefined", v.NLeaves, i, gotSibling)
				} else if !errors.Is(siblingErr, ErrRootHasNoSibling) {
					t.Errorf("n_leaves %d node %d: sibling: %v, want %v", v.NLeaves, i, siblingErr, ErrRootHasNoSibling)
				}
			} else {
				if siblingErr != nil {
					t.Errorf("n_leaves %d node %d: sibling: %v, want %d", v.NLeaves, i, siblingErr, *want)
				} else if uint32(gotSibling) != *want {
					t.Errorf("n_leaves %d node %d: sibling %d, want %d", v.NLeaves, i, gotSibling, *want)
				}
			}
		}

		// a node past the end of the array is refused, not answered. the
		// appendix C pseudocode answers, which is how an index decoded from a
		// message reaches arithmetic it has no business reaching.
		if _, err := Parent(NodeIndex(v.NNodes), leafCount); !errors.Is(err, ErrNodeOutOfRange) {
			t.Errorf("n_leaves %d: parent of node %d: %v, want %v", v.NLeaves, v.NNodes, err, ErrNodeOutOfRange)
		}
		if _, err := Sibling(NodeIndex(v.NNodes), leafCount); !errors.Is(err, ErrNodeOutOfRange) {
			t.Errorf("n_leaves %d: sibling of node %d: %v, want %v", v.NLeaves, v.NNodes, err, ErrNodeOutOfRange)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestTreeMathVectorParentAndSibling -v`

Expected: FAIL to build with `undefined: Parent`, `undefined: Sibling`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// the parent of a node in a tree with n leaves.
//
// the leaf count is used only to locate the root, exactly as in appendix C; the
// arithmetic itself is index-only. it is done in uint64 so the shift by k+1 is
// obviously in range without an argument about the maximum level of a non-root
// node.
func Parent(x NodeIndex, n LeafCount) (NodeIndex, error) {
	r, err := Root(n)
	if err != nil {
		return 0, err
	}
	if uint32(x) >= NodeWidth(n) {
		return 0, ErrNodeOutOfRange
	}
	if x == r {
		return 0, ErrRootHasNoParent
	}
	k := uint64(x.Level())
	b := (uint64(x) >> (k + 1)) & 0x01
	return NodeIndex((uint64(x) | (uint64(1) << k)) ^ (b << (k + 1))), nil
}

// the other child of the node's parent.
func Sibling(x NodeIndex, n LeafCount) (NodeIndex, error) {
	p, err := Parent(x, n)
	if err != nil {
		if errors.Is(err, ErrRootHasNoParent) {
			return 0, ErrRootHasNoSibling
		}
		return 0, err
	}
	if x < p {
		return Right(p)
	}
	return Left(p)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeMathVectorParentAndSibling -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_kat_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): parent and sibling, checked against vector family 1"
```

---

### Task 7: The family-1 gate test and its registration

**Files:**
- Test: `mls/tree_math_kat_test.go`
- Modify, one line: `mls/vectors_test.go` (the Validation and interop harness plan's file)

**Interfaces:**
- Consumes, from this plan: `NodeWidth`, `Root`, `Left`, `Right`, `Parent`, `Sibling`
  (Tasks 2, 4, 5, 6).
- Consumes, from the Validation and interop harness plan:

```go
type VectorFamily struct {
    Number   int                                       // 1..16, the Spec A §4.2.1 row
    Name     string
    File     string                                    // under testdata/vectors
    Slice    string                                    // "A1".."A4"
    Verify   func(t *testing.T, raw json.RawMessage)   // nil == not yet implemented
    Generate func(t *testing.T) json.RawMessage        // nil == format has no generate direction
}
func RegisterVectorFamily(family VectorFamily)
func LoadVectorFile(t *testing.T, file string) []json.RawMessage
```

- Produces: `verifyTreeMathVector`, `generateTreeMathVectors`, the `init()` that registers family 1,
  and `TestTreeMathVectors` — the named test Spec A §4.2.1 family 1 gates on. No new package API.

**Why the registration is not optional.** The harness runs `TestVectorFamiliesVerify` over the
registered families and asserts `expectedPendingFamilies` shrinks to empty. A standalone
`TestTreeMathVectors` that never registers leaves family 1 pending forever: `TestVectorFamiliesVerify`
skips it, `TestVectorManifestIsComplete` passes vacuously, and acceptance criterion 1 goes green in
CI with the runner that exists never executed by the job that claims to gate on it. Registering and
deleting the number from `expectedPendingFamilies` happen in **one commit**, so neither half can land
without the other.

**On `Verify` and `Generate` arity.** `Verify` takes one entry's raw JSON — the element shape
`LoadVectorFile` yields — and `Generate` returns the whole family file as one `json.RawMessage`
array, which is what the corpus on disk is. `TestTreeMathVectorGenerateThenVerify` below proves the
pair composes inside this plan, so the family is green whichever way the harness splits the generated
array.

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_kat_test.go`:

```go
// registers family 1 with the shared vector harness. the standalone gate test
// below is the developer-facing entry point; this is the one the vectors CI job
// reaches, and without it family 1 stays in expectedPendingFamilies and is
// never run by the job that gates on it.
func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   1,
		Name:     "tree-math",
		File:     treeMathVectorFile,
		Slice:    "A1",
		Verify:   verifyTreeMathVector,
		Generate: generateTreeMathVectors,
	})
}

// checks one optional relation column against one function. a wrong error is
// as much a failure as a wrong index, because "undefined here" is part of what
// the vector asserts.
func checkTreeMathRelation(t *testing.T, nLeaves uint32, nodeIndex uint32, name string, want *uint32, got NodeIndex, err error) {
	t.Helper()
	if want == nil {
		if err == nil {
			t.Fatalf("n_leaves %d node %d %s: %d, want undefined", nLeaves, nodeIndex, name, got)
		}
		return
	}
	if err != nil {
		t.Fatalf("n_leaves %d node %d %s: %v, want %d", nLeaves, nodeIndex, name, err, *want)
	}
	if uint32(got) != *want {
		t.Fatalf("n_leaves %d node %d %s: %d, want %d", nLeaves, nodeIndex, name, got, *want)
	}
}

// checks one decoded entry and returns how many relations it asserted, so the
// caller can gate on the total. every relation of every node is checked; there
// is no sampling.
func checkTreeMathEntry(t *testing.T, v treeMathVector) int {
	t.Helper()
	leafCount := LeafCount(v.NLeaves)

	if got := NodeWidth(leafCount); got != v.NNodes {
		t.Fatalf("n_leaves %d: node width %d, want %d", v.NLeaves, got, v.NNodes)
	}
	root, err := Root(leafCount)
	if err != nil {
		t.Fatalf("n_leaves %d: root: %v", v.NLeaves, err)
	}
	if uint32(root) != v.Root {
		t.Fatalf("n_leaves %d: root %d, want %d", v.NLeaves, root, v.Root)
	}

	checked := 0
	for i := uint32(0); i < v.NNodes; i += 1 {
		nodeIndex := NodeIndex(i)

		gotLeft, leftErr := Left(nodeIndex)
		checkTreeMathRelation(t, v.NLeaves, i, "left", v.Left[i], gotLeft, leftErr)

		gotRight, rightErr := Right(nodeIndex)
		checkTreeMathRelation(t, v.NLeaves, i, "right", v.Right[i], gotRight, rightErr)

		gotParent, parentErr := Parent(nodeIndex, leafCount)
		checkTreeMathRelation(t, v.NLeaves, i, "parent", v.Parent[i], gotParent, parentErr)

		gotSibling, siblingErr := Sibling(nodeIndex, leafCount)
		checkTreeMathRelation(t, v.NLeaves, i, "sibling", v.Sibling[i], gotSibling, siblingErr)

		checked += 4
	}
	return checked
}

// the VectorFamily.Verify half of family 1: one entry of the corpus, decoded
// and checked. an entry with no nodes is refused rather than passed, because a
// truncated entry is the shape a bad vendoring produces.
func verifyTreeMathVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var v treeMathVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode tree-math entry: %v", err)
	}
	checked := checkTreeMathEntry(t, v)
	if checked != int(4*v.NNodes) || checked == 0 {
		t.Fatalf("n_leaves %d: relations checked: %d, want %d", v.NLeaves, checked, 4*v.NNodes)
	}
}

// the VectorFamily.Generate half: the whole family recomputed from this file's
// arithmetic, at the ten sizes upstream publishes, in the upstream field order
// and with null for every undefined relation.
func generateTreeMathVectors(t *testing.T) json.RawMessage {
	t.Helper()

	optional := func(x NodeIndex, err error) *uint32 {
		if err != nil {
			return nil
		}
		value := uint32(x)
		return &value
	}

	vectors := make([]treeMathVector, 0, 10)
	for depth := uint32(0); depth <= 9; depth += 1 {
		leafCount := LeafCount(1) << depth
		nodeWidth := NodeWidth(leafCount)
		root, err := Root(leafCount)
		if err != nil {
			t.Fatalf("%d leaves: root: %v", leafCount, err)
		}

		v := treeMathVector{
			NLeaves: uint32(leafCount),
			NNodes:  nodeWidth,
			Root:    uint32(root),
			Left:    make([]*uint32, 0, nodeWidth),
			Right:   make([]*uint32, 0, nodeWidth),
			Parent:  make([]*uint32, 0, nodeWidth),
			Sibling: make([]*uint32, 0, nodeWidth),
		}
		for i := uint32(0); i < nodeWidth; i += 1 {
			nodeIndex := NodeIndex(i)
			v.Left = append(v.Left, optional(Left(nodeIndex)))
			v.Right = append(v.Right, optional(Right(nodeIndex)))
			v.Parent = append(v.Parent, optional(Parent(nodeIndex, leafCount)))
			v.Sibling = append(v.Sibling, optional(Sibling(nodeIndex, leafCount)))
		}
		vectors = append(vectors, v)
	}

	generated, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("encode tree-math family: %v", err)
	}
	return json.RawMessage(generated)
}

// vector family 1. this is the gate Spec A section 4.2.1 names, and the
// assertion count is checked so that a runner which silently iterates zero
// entries — the failure mode a vendoring mistake produces — fails instead of
// passing.
func TestTreeMathVectors(t *testing.T) {
	rawEntries := LoadVectorFile(t, treeMathVectorFile)
	if len(rawEntries) != 10 {
		t.Fatalf("entries: %d, want 10", len(rawEntries))
	}

	checked := 0
	for _, rawEntry := range rawEntries {
		var v treeMathVector
		if err := json.Unmarshal(rawEntry, &v); err != nil {
			t.Fatalf("decode tree-math entry: %v", err)
		}
		checked += checkTreeMathEntry(t, v)
	}

	// 2036 nodes across the ten entries, four relations each.
	if checked != 8144 {
		t.Fatalf("relations checked: %d, want 8144", checked)
	}
}

// the generate direction against the verify direction. the harness runs this
// pairing across every registered family; running it here as well means a
// generator that emits the wrong field names or drops the null encoding fails
// in this plan rather than in the plan that owns the harness.
func TestTreeMathVectorGenerateThenVerify(t *testing.T) {
	var rawEntries []json.RawMessage
	if err := json.Unmarshal(generateTreeMathVectors(t), &rawEntries); err != nil {
		t.Fatalf("decode the generated family: %v", err)
	}
	if len(rawEntries) != 10 {
		t.Fatalf("generated entries: %d, want 10", len(rawEntries))
	}
	for _, rawEntry := range rawEntries {
		verifyTreeMathVector(t, rawEntry)
	}

	// and the generated family must agree with the vendored one field by field,
	// which is the assertion that makes generating worth doing at all.
	vendored := LoadVectorFile(t, treeMathVectorFile)
	if len(vendored) != len(rawEntries) {
		t.Fatalf("generated %d entries, vendored %d", len(rawEntries), len(vendored))
	}
	for i := range vendored {
		var want, got treeMathVector
		if err := json.Unmarshal(vendored[i], &want); err != nil {
			t.Fatalf("decode vendored entry %d: %v", i, err)
		}
		if err := json.Unmarshal(rawEntries[i], &got); err != nil {
			t.Fatalf("decode generated entry %d: %v", i, err)
		}
		if got.NLeaves != want.NLeaves || got.NNodes != want.NNodes || got.Root != want.Root {
			t.Fatalf("entry %d: generated (%d, %d, %d), vendored (%d, %d, %d)", i,
				got.NLeaves, got.NNodes, got.Root, want.NLeaves, want.NNodes, want.Root)
		}
		columns := []struct {
			name string
			got  []*uint32
			want []*uint32
		}{
			{name: "left", got: got.Left, want: want.Left},
			{name: "right", got: got.Right, want: want.Right},
			{name: "parent", got: got.Parent, want: want.Parent},
			{name: "sibling", got: got.Sibling, want: want.Sibling},
		}
		for _, column := range columns {
			if len(column.got) != len(column.want) {
				t.Fatalf("entry %d %s: %d entries, want %d", i, column.name, len(column.got), len(column.want))
			}
			for j := range column.want {
				if (column.got[j] == nil) != (column.want[j] == nil) {
					t.Fatalf("entry %d %s node %d: presence differs", i, column.name, j)
				}
				if column.got[j] != nil && *column.got[j] != *column.want[j] {
					t.Fatalf("entry %d %s node %d: %d, want %d", i, column.name, j, *column.got[j], *column.want[j])
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Temporarily change the constant `8144` to `8145`, then run:
`go test ./mls/... -run 'TestTreeMathVectors|TestTreeMathVectorGenerateThenVerify' -v`

Expected: FAIL with `relations checked: 8144, want 8145` — which proves the runner really visited
every node of every entry rather than passing vacuously. Restore `8144` before step 3.

Then, with `8144` restored, confirm the registration half is red too:
`go test ./mls/... -run TestVectorManifestIsComplete -v`

Expected: FAIL, reporting that family 1 is registered while still listed in
`expectedPendingFamilies`. If it passes, the harness is not seeing the `init()` and the registration
is decorative.

- [ ] **Step 3: Write minimal implementation**

No new tree-math implementation is needed: Tasks 4 to 6 already produced every function this gate
calls. Two edits close the task:

1. Restore the constant to `8144` if it is still `8145`.
2. In `mls/vectors_test.go`, delete `1` from `expectedPendingFamilies` — the single line this plan
   changes in another plan's file, and it must land in the same commit as the `init()` above. Leave
   every other number alone; each belongs to the plan that lands its own runner.

Then run `gofmt -l mls` to confirm both files are clean.

- [ ] **Step 4: Run test to verify it passes**

```
go test ./mls/... -run 'TestTreeMathVectors|TestTreeMathVectorGenerateThenVerify' -v
go test ./mls/... -run 'TestVectorManifestIsComplete|TestVectorFamiliesVerify|TestVectorGenerateThenVerify' -v
```

Expected: PASS, and the harness run must name family 1 rather than skipping it.

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math_kat_test.go mls/vectors_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "test(mls): vector family 1 gate, registered with the shared vector harness"
```

---

### Task 8: Direct path and copath, against RFC 9420 Table 2

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: `Root`, `NodeWidth`, `Parent`, `Sibling`, `TreeDepth`, `checkLeafCount` (Tasks 2 to 6).
- Produces:
  - `func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)`
  - `func Copath(x NodeIndex, n LeafCount) ([]NodeIndex, error)`

Both return a slice ordered leaf to root. `DirectPath` excludes `x` and includes the root; `Copath`
excludes the root and has exactly the same length as `DirectPath`.

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_test.go`:

```go
// compares two node slices and reports the whole slice on a mismatch, because
// a path bug is almost never at the element the first difference lands on.
func assertNodeIndexes(t *testing.T, label string, got []NodeIndex, want []NodeIndex) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %v, want %v", label, got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s: %v, want %v", label, got, want)
			return
		}
	}
}

// RFC 9420 figure 11 and table 2: an eight-leaf tree with members at leaves
// 0, 1, 4, 5 and 6. the figure labels the blank parents U, V, Z and the blank
// leaf H, and table 2 publishes the direct path and copath of every member.
//
// node indices for the figure's labels:
//
//	A = 0   B = 2   E = 8   F = 10  G = 12  H = 14 (blank leaf 7)
//	T = 1   V = 5 (blank)   X = 9   Z = 13 (blank)
//	U = 3 (blank)           Y = 11
//	W = 7 (root)
func TestDirectPathAndCopathRfcTable2(t *testing.T) {
	pathCases := []struct {
		label      string
		leafIndex  LeafIndex
		directPath []NodeIndex
		copath     []NodeIndex
	}{
		{label: "A", leafIndex: 0, directPath: []NodeIndex{1, 3, 7}, copath: []NodeIndex{2, 5, 11}},
		{label: "B", leafIndex: 1, directPath: []NodeIndex{1, 3, 7}, copath: []NodeIndex{0, 5, 11}},
		{label: "E", leafIndex: 4, directPath: []NodeIndex{9, 11, 7}, copath: []NodeIndex{10, 13, 3}},
		{label: "F", leafIndex: 5, directPath: []NodeIndex{9, 11, 7}, copath: []NodeIndex{8, 13, 3}},
		{label: "G", leafIndex: 6, directPath: []NodeIndex{13, 11, 7}, copath: []NodeIndex{14, 9, 3}},
	}
	for _, c := range pathCases {
		gotDirect, err := DirectPath(c.leafIndex.NodeIndex(), 8)
		if err != nil {
			t.Errorf("%s direct path: %v", c.label, err)
			continue
		}
		assertNodeIndexes(t, c.label+" direct path", gotDirect, c.directPath)

		gotCopath, err := Copath(c.leafIndex.NodeIndex(), 8)
		if err != nil {
			t.Errorf("%s copath: %v", c.label, err)
			continue
		}
		assertNodeIndexes(t, c.label+" copath", gotCopath, c.copath)
	}
}

func TestDirectPathAndCopathEdges(t *testing.T) {
	// the root has an empty direct path and an empty copath, and the empty
	// slice is not nil so a caller ranging over it needs no nil check.
	root, err := Root(8)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	rootPath, err := DirectPath(root, 8)
	if err != nil {
		t.Fatalf("root direct path: %v", err)
	}
	if len(rootPath) != 0 {
		t.Errorf("root direct path: %v, want empty", rootPath)
	}
	rootCopath, err := Copath(root, 8)
	if err != nil {
		t.Fatalf("root copath: %v", err)
	}
	if len(rootCopath) != 0 {
		t.Errorf("root copath: %v, want empty", rootCopath)
	}

	// a single-leaf tree: the only node is the root.
	solePath, err := DirectPath(0, 1)
	if err != nil {
		t.Fatalf("sole leaf direct path: %v", err)
	}
	if len(solePath) != 0 {
		t.Errorf("sole leaf direct path: %v, want empty", solePath)
	}

	if _, err := DirectPath(15, 8); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("direct path of node 15 in an eight-leaf tree: %v, want %v", err, ErrNodeOutOfRange)
	}
	if _, err := Copath(15, 8); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("copath of node 15 in an eight-leaf tree: %v, want %v", err, ErrNodeOutOfRange)
	}
	if _, err := DirectPath(0, 6); !errors.Is(err, ErrLeafCountNotFull) {
		t.Errorf("direct path in a six-leaf tree: %v, want %v", err, ErrLeafCountNotFull)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run 'TestDirectPathAndCopathRfcTable2|TestDirectPathAndCopathEdges' -v`

Expected: FAIL to build with `undefined: DirectPath`, `undefined: Copath`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// the path from x to the root, ordered leaf to root, excluding x and including
// the root. the root's direct path is empty.
//
// the loop is bounded explicitly. it cannot run away for a validated index —
// each step strictly increases the level and the root holds the maximum — but a
// structural bound makes that a property of the code rather than of an argument
// about the code.
func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error) {
	r, err := Root(n)
	if err != nil {
		return nil, err
	}
	if uint32(x) >= NodeWidth(n) {
		return nil, ErrNodeOutOfRange
	}

	pathNodes := make([]NodeIndex, 0, TreeDepth(n))
	for steps := uint32(0); x != r; steps += 1 {
		if steps > 32 {
			return nil, ErrNodeOutOfRange
		}
		x, err = Parent(x, n)
		if err != nil {
			return nil, err
		}
		pathNodes = append(pathNodes, x)
	}
	return pathNodes, nil
}

// the sibling of x followed by the sibling of every node on x's direct path
// except the root, ordered leaf to root. always the same length as the direct
// path, and every entry is the child of the direct-path entry at the same
// position that x does not descend from.
func Copath(x NodeIndex, n LeafCount) ([]NodeIndex, error) {
	r, err := Root(n)
	if err != nil {
		return nil, err
	}
	if uint32(x) >= NodeWidth(n) {
		return nil, ErrNodeOutOfRange
	}
	if x == r {
		return []NodeIndex{}, nil
	}

	pathNodes, err := DirectPath(x, n)
	if err != nil {
		return nil, err
	}

	// the siblings wanted are those of x and of every direct-path node below
	// the root, which is the direct path shifted down by one with x in front.
	copathNodes := make([]NodeIndex, 0, len(pathNodes))
	child := x
	for _, pathNode := range pathNodes {
		sibling, err := Sibling(child, n)
		if err != nil {
			return nil, err
		}
		copathNodes = append(copathNodes, sibling)
		child = pathNode
	}
	return copathNodes, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run 'TestDirectPathAndCopathRfcTable2|TestDirectPathAndCopathEdges' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): direct path and copath, against the RFC 9420 table 2 worked example"
```

---

### Task 9: Common ancestor, differential against the RFC's semantic definition

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: `NodeIndex.Level`, `DirectPath` (Tasks 2, 8).
- Produces: `func CommonAncestor(x NodeIndex, y NodeIndex) NodeIndex`

The result is independent of the leaf count, which is why no count is taken: any tree containing both
x and y contains their common ancestor at the same index.

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_test.go`:

```go
// the second of the two definitions RFC 9420 appendix C gives: the lowest node
// that is in the direct paths of both. it lives here rather than in the
// implementation because its only job is to disagree with the fast one.
func commonAncestorSemantic(t *testing.T, x NodeIndex, y NodeIndex, n LeafCount) NodeIndex {
	t.Helper()
	ancestorsOfX := map[NodeIndex]bool{x: true}
	pathOfX, err := DirectPath(x, n)
	if err != nil {
		t.Fatalf("direct path of %d: %v", x, err)
	}
	for _, node := range pathOfX {
		ancestorsOfX[node] = true
	}

	ancestorsOfY := map[NodeIndex]bool{y: true}
	pathOfY, err := DirectPath(y, n)
	if err != nil {
		t.Fatalf("direct path of %d: %v", y, err)
	}
	for _, node := range pathOfY {
		ancestorsOfY[node] = true
	}

	lowest := NodeIndex(0)
	found := false
	for node := range ancestorsOfX {
		if !ancestorsOfY[node] {
			continue
		}
		if !found || node.Level() < lowest.Level() {
			lowest = node
			found = true
		}
	}
	if !found {
		t.Fatalf("no common ancestor of %d and %d in a %d-leaf tree", x, y, n)
	}
	return lowest
}

func TestCommonAncestorKnownValues(t *testing.T) {
	ancestorCases := []struct {
		x        NodeIndex
		y        NodeIndex
		ancestor NodeIndex
	}{
		{x: 0, y: 0, ancestor: 0},
		{x: 0, y: 2, ancestor: 1},
		{x: 0, y: 4, ancestor: 3},
		{x: 2, y: 6, ancestor: 3},
		{x: 0, y: 14, ancestor: 7},
		{x: 1, y: 0, ancestor: 1},
		{x: 0, y: 1, ancestor: 1},
		{x: 3, y: 11, ancestor: 7},
		{x: 9, y: 13, ancestor: 11},
	}
	for _, c := range ancestorCases {
		if got := CommonAncestor(c.x, c.y); got != c.ancestor {
			t.Errorf("common ancestor of %d and %d: %d, want %d", c.x, c.y, got, c.ancestor)
		}
		// the relation is symmetric.
		if got := CommonAncestor(c.y, c.x); got != c.ancestor {
			t.Errorf("common ancestor of %d and %d: %d, want %d", c.y, c.x, got, c.ancestor)
		}
	}
}

// RFC 9420 gives two independent definitions and the whole value of having both
// is that they can be run against each other. every node pair of every tree up
// to 64 leaves, then every leaf pair up to 512.
func TestCommonAncestorMatchesSemanticDefinition(t *testing.T) {
	for depth := uint32(0); depth <= 6; depth += 1 {
		leafCount := LeafCount(1) << depth
		nodeWidth := NodeWidth(leafCount)
		for i := uint32(0); i < nodeWidth; i += 1 {
			for j := uint32(0); j < nodeWidth; j += 1 {
				x, y := NodeIndex(i), NodeIndex(j)
				want := commonAncestorSemantic(t, x, y, leafCount)
				if got := CommonAncestor(x, y); got != want {
					t.Fatalf("%d leaves: common ancestor of %d and %d: %d, want %d", leafCount, x, y, got, want)
				}
			}
		}
	}

	for depth := uint32(7); depth <= 9; depth += 1 {
		leafCount := LeafCount(1) << depth
		for i := LeafIndex(0); LeafCount(i) < leafCount; i += 1 {
			for j := LeafIndex(0); LeafCount(j) < leafCount; j += 1 {
				x, y := i.NodeIndex(), j.NodeIndex()
				want := commonAncestorSemantic(t, x, y, leafCount)
				if got := CommonAncestor(x, y); got != want {
					t.Fatalf("%d leaves: common ancestor of leaves %d and %d: %d, want %d", leafCount, i, j, got, want)
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run 'TestCommonAncestorKnownValues|TestCommonAncestorMatchesSemanticDefinition' -v`

Expected: FAIL to build with `undefined: CommonAncestor`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// the lowest node that is an ancestor of both x and y, where a node counts as
// an ancestor of itself.
//
// the answer does not depend on the leaf count: any tree containing both nodes
// contains this node at this index, which is why no count is taken. the
// arithmetic runs in uint64 so a shift by a level derived from an arbitrary
// index cannot be an out-of-range shift.
func CommonAncestor(x NodeIndex, y NodeIndex) NodeIndex {
	// one may be an ancestor of the other, in which case it is the answer.
	levelOfX := uint64(x.Level()) + 1
	levelOfY := uint64(y.Level()) + 1
	if levelOfX <= levelOfY && uint64(x)>>levelOfY == uint64(y)>>levelOfY {
		return y
	}
	if levelOfY <= levelOfX && uint64(x)>>levelOfX == uint64(y)>>levelOfX {
		return x
	}

	// otherwise shift both right until they agree; the number of shifts is the
	// level of the node where the two subtrees join.
	shiftedX, shiftedY := uint64(x), uint64(y)
	shifts := uint64(0)
	for shiftedX != shiftedY {
		shiftedX >>= 1
		shiftedY >>= 1
		shifts += 1
	}
	return NodeIndex((shiftedX << shifts) + (uint64(1) << (shifts - 1)) - 1)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run 'TestCommonAncestorKnownValues|TestCommonAncestorMatchesSemanticDefinition' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): common ancestor, differential against the RFC semantic definition"
```

---

### Task 10: Subtree spans

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: `NodeIndex.Level` (Task 2).
- Produces:
  - `func SubtreeSpan(x NodeIndex) (firstNode NodeIndex, lastNode NodeIndex)`
  - `func SubtreeLeaves(x NodeIndex) (firstLeaf LeafIndex, lastLeaf LeafIndex)`
  - `func InSubtree(head NodeIndex, x NodeIndex) bool`

These exist for the parent-hash check of RFC 9420 §7.9, which intersects a node's unmerged leaves
with the leaves under one of its children; `tree_hash.go` consumes them.

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_test.go`:

```go
func TestSubtreeSpanAndLeaves(t *testing.T) {
	spanCases := []struct {
		nodeIndex NodeIndex
		firstNode NodeIndex
		lastNode  NodeIndex
		firstLeaf LeafIndex
		lastLeaf  LeafIndex
	}{
		{nodeIndex: 0, firstNode: 0, lastNode: 0, firstLeaf: 0, lastLeaf: 0},
		{nodeIndex: 4, firstNode: 4, lastNode: 4, firstLeaf: 2, lastLeaf: 2},
		{nodeIndex: 1, firstNode: 0, lastNode: 2, firstLeaf: 0, lastLeaf: 1},
		{nodeIndex: 5, firstNode: 4, lastNode: 6, firstLeaf: 2, lastLeaf: 3},
		{nodeIndex: 3, firstNode: 0, lastNode: 6, firstLeaf: 0, lastLeaf: 3},
		{nodeIndex: 11, firstNode: 8, lastNode: 14, firstLeaf: 4, lastLeaf: 7},
		{nodeIndex: 7, firstNode: 0, lastNode: 14, firstLeaf: 0, lastLeaf: 7},
	}
	for _, c := range spanCases {
		firstNode, lastNode := SubtreeSpan(c.nodeIndex)
		if firstNode != c.firstNode || lastNode != c.lastNode {
			t.Errorf("node %d span: [%d, %d], want [%d, %d]", c.nodeIndex, firstNode, lastNode, c.firstNode, c.lastNode)
		}
		firstLeaf, lastLeaf := SubtreeLeaves(c.nodeIndex)
		if firstLeaf != c.firstLeaf || lastLeaf != c.lastLeaf {
			t.Errorf("node %d leaves: [%d, %d], want [%d, %d]", c.nodeIndex, firstLeaf, lastLeaf, c.firstLeaf, c.lastLeaf)
		}
	}
}

func TestInSubtree(t *testing.T) {
	// every node of an eight-leaf tree is inside the root's subtree, and a node
	// is inside its own.
	for i := uint32(0); i < NodeWidth(8); i += 1 {
		nodeIndex := NodeIndex(i)
		if !InSubtree(7, nodeIndex) {
			t.Errorf("node %d not in the root subtree", nodeIndex)
		}
		if !InSubtree(nodeIndex, nodeIndex) {
			t.Errorf("node %d not in its own subtree", nodeIndex)
		}
	}

	membershipCases := []struct {
		head      NodeIndex
		nodeIndex NodeIndex
		inSubtree bool
	}{
		{head: 1, nodeIndex: 0, inSubtree: true},
		{head: 1, nodeIndex: 2, inSubtree: true},
		{head: 1, nodeIndex: 4, inSubtree: false},
		{head: 3, nodeIndex: 5, inSubtree: true},
		{head: 3, nodeIndex: 8, inSubtree: false},
		{head: 11, nodeIndex: 8, inSubtree: true},
		{head: 11, nodeIndex: 6, inSubtree: false},
		{head: 0, nodeIndex: 1, inSubtree: false},
	}
	for _, c := range membershipCases {
		if got := InSubtree(c.head, c.nodeIndex); got != c.inSubtree {
			t.Errorf("node %d in subtree of %d: %v, want %v", c.nodeIndex, c.head, got, c.inSubtree)
		}
	}

	// the span of a node agrees with the direct path: x is in the subtree of
	// every node on its direct path and of no other node.
	for i := uint32(0); i < NodeWidth(8); i += 1 {
		nodeIndex := NodeIndex(i)
		pathNodes, err := DirectPath(nodeIndex, 8)
		if err != nil {
			t.Fatalf("direct path of %d: %v", nodeIndex, err)
		}
		onPath := map[NodeIndex]bool{nodeIndex: true}
		for _, pathNode := range pathNodes {
			onPath[pathNode] = true
		}
		for j := uint32(0); j < NodeWidth(8); j += 1 {
			head := NodeIndex(j)
			if got := InSubtree(head, nodeIndex); got != onPath[head] {
				t.Errorf("node %d in subtree of %d: %v, want %v", nodeIndex, head, got, onPath[head])
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run 'TestSubtreeSpanAndLeaves|TestInSubtree' -v`

Expected: FAIL to build with `undefined: SubtreeSpan`, `undefined: SubtreeLeaves`,
`undefined: InSubtree`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// the first and last node indices of the subtree headed by x, inclusive.
//
// a node at level k has exactly k trailing one bits, so it is never smaller
// than its own half-span and the subtraction cannot underflow for any index.
// the index one past the largest representable tree has level 32 and no
// meaningful span, so it spans only itself.
func SubtreeSpan(x NodeIndex) (firstNode NodeIndex, lastNode NodeIndex) {
	k := x.Level()
	if k > 31 {
		return x, x
	}
	halfSpan := NodeIndex((uint64(1) << k) - 1)
	return x - halfSpan, x + halfSpan
}

// the first and last leaf indices under x, inclusive. both ends of a subtree
// span are even, so both convert to a leaf exactly.
func SubtreeLeaves(x NodeIndex) (firstLeaf LeafIndex, lastLeaf LeafIndex) {
	firstNode, lastNode := SubtreeSpan(x)
	return LeafIndex(uint32(firstNode) / 2), LeafIndex(uint32(lastNode) / 2)
}

// whether x is head or a descendant of head.
func InSubtree(head NodeIndex, x NodeIndex) bool {
	firstNode, lastNode := SubtreeSpan(head)
	return firstNode <= x && x <= lastNode
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run 'TestSubtreeSpanAndLeaves|TestInSubtree' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): subtree spans, leaf ranges and subtree membership"
```

---

### Task 11: NodeShape and Resolution, against RFC 9420 Figure 10

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: `checkLeafCount`, `NodeWidth`, `NodeIndex.IsLeaf`, `Left`, `Right`, `LeafIndex.NodeIndex`
  (Tasks 2, 3, 5).
- Produces:
  - `type NodeShape interface { LeafCount() LeafCount; IsBlank(x NodeIndex) bool; UnmergedLeaves(x NodeIndex) []LeafIndex }`
  - `func Resolution(shape NodeShape, x NodeIndex) ([]NodeIndex, error)`

**Obligation this places on the TreeKEM plan:** the ratchet tree type in `tree.go` must satisfy
`mls.NodeShape`. `UnmergedLeaves` returns the node's stored list in stored order; this file does not
sort it and does not check that its entries are non-blank leaves inside the subtree — those are the
RFC §7.9 tree-validation checks and they belong to `tree_sync.go`.

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_test.go`:

```go
// a NodeShape backed by two explicit maps, so the worked examples RFC 9420
// publishes can be written down node by node.
type fixtureShape struct {
	fixtureLeafCount   LeafCount
	blankNodes         map[NodeIndex]bool
	unmergedNodeLeaves map[NodeIndex][]LeafIndex
}

func (self *fixtureShape) LeafCount() LeafCount {
	return self.fixtureLeafCount
}

func (self *fixtureShape) IsBlank(x NodeIndex) bool {
	return self.blankNodes[x]
}

func (self *fixtureShape) UnmergedLeaves(x NodeIndex) []LeafIndex {
	return self.unmergedNodeLeaves[x]
}

// RFC 9420 figure 10: an eight-leaf subtree with blanks and one unmerged leaf.
//
//	leaves A=0 B=2 _=4 D=6 E=8 F=10 _=12 H=14
//	level one: _=1 _=5 Y=9 _=13
//	level two: X=3 with unmerged leaf B, _=11
//	level three: the top node = 7, blank
func rfcFigure10Shape() *fixtureShape {
	return &fixtureShape{
		fixtureLeafCount: 8,
		blankNodes: map[NodeIndex]bool{
			1: true, 4: true, 5: true, 7: true, 11: true, 12: true, 13: true,
		},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{
			3: {1},
		},
	}
}

func TestResolutionRfcFigure10(t *testing.T) {
	shape := rfcFigure10Shape()
	resolutionCases := []struct {
		label      string
		nodeIndex  NodeIndex
		resolution []NodeIndex
	}{
		// the resolution of a non-blank node is itself followed by its
		// unmerged leaves.
		{label: "X", nodeIndex: 3, resolution: []NodeIndex{3, 2}},
		// the resolution of a blank leaf is empty.
		{label: "leaf 2", nodeIndex: 4, resolution: []NodeIndex{}},
		{label: "leaf 6", nodeIndex: 12, resolution: []NodeIndex{}},
		// the resolution of a blank intermediate node concatenates its
		// children, left first.
		{label: "top node", nodeIndex: 7, resolution: []NodeIndex{3, 2, 9, 14}},
		{label: "Y", nodeIndex: 9, resolution: []NodeIndex{9}},
		{label: "node 13", nodeIndex: 13, resolution: []NodeIndex{14}},
		{label: "node 11", nodeIndex: 11, resolution: []NodeIndex{9, 14}},
		{label: "node 1", nodeIndex: 1, resolution: []NodeIndex{0, 2}},
	}
	for _, c := range resolutionCases {
		got, err := Resolution(shape, c.nodeIndex)
		if err != nil {
			t.Errorf("%s resolution: %v", c.label, err)
			continue
		}
		assertNodeIndexes(t, c.label+" resolution", got, c.resolution)
	}
}

func TestResolutionEdges(t *testing.T) {
	// a fully populated tree resolves to its root.
	populated := &fixtureShape{
		fixtureLeafCount:   8,
		blankNodes:         map[NodeIndex]bool{},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
	}
	got, err := Resolution(populated, 7)
	if err != nil {
		t.Fatalf("populated root resolution: %v", err)
	}
	assertNodeIndexes(t, "populated root resolution", got, []NodeIndex{7})

	// blank every parent and the resolution of the root is exactly the leaves,
	// left to right.
	blankParents := &fixtureShape{
		fixtureLeafCount:   8,
		blankNodes:         map[NodeIndex]bool{1: true, 3: true, 5: true, 7: true, 9: true, 11: true, 13: true},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
	}
	got, err = Resolution(blankParents, 7)
	if err != nil {
		t.Fatalf("blank-parent root resolution: %v", err)
	}
	assertNodeIndexes(t, "blank-parent root resolution", got, []NodeIndex{0, 2, 4, 6, 8, 10, 12, 14})

	// an entirely blank tree resolves to nothing.
	allBlank := &fixtureShape{
		fixtureLeafCount:   8,
		blankNodes:         map[NodeIndex]bool{},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
	}
	for i := uint32(0); i < NodeWidth(8); i += 1 {
		allBlank.blankNodes[NodeIndex(i)] = true
	}
	got, err = Resolution(allBlank, 7)
	if err != nil {
		t.Fatalf("all-blank root resolution: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("all-blank root resolution: %v, want empty", got)
	}

	if _, err := Resolution(rfcFigure10Shape(), 15); !errors.Is(err, ErrNodeOutOfRange) {
		t.Errorf("resolution of node 15: %v, want %v", err, ErrNodeOutOfRange)
	}

	// an unmerged leaf outside the tree is a malformed shape, not a panic.
	malformed := &fixtureShape{
		fixtureLeafCount:   8,
		blankNodes:         map[NodeIndex]bool{},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{7: {99}},
	}
	if _, err := Resolution(malformed, 7); !errors.Is(err, ErrLeafOutOfRange) {
		t.Errorf("resolution with an out-of-range unmerged leaf: %v, want %v", err, ErrLeafOutOfRange)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run 'TestResolutionRfcFigure10|TestResolutionEdges' -v`

Expected: FAIL to build with `undefined: Resolution` and `undefined: NodeShape` (the fixture's method
set is unused until the interface exists, so the first error reported is on the `Resolution` call).

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// the minimal view of node contents the two shape rules need.
//
// tree.go implements this over the real ratchet tree, which keeps every public
// key and credential out of this file. UnmergedLeaves returns the node's stored
// list in stored order: that the list is sorted and that its entries are
// non-blank leaves inside the node's subtree are RFC 9420 section 7.9
// tree-validation checks and belong to tree_sync.go, not here.
type NodeShape interface {
	LeafCount() LeafCount
	IsBlank(x NodeIndex) bool
	UnmergedLeaves(x NodeIndex) []LeafIndex
}

// the ordered list of non-blank nodes that collectively cover every non-blank
// descendant of x: a depth-first, left-first enumeration of the nearest
// non-blank nodes below it.
//
// a non-blank node resolves to itself followed by its unmerged leaves, a blank
// leaf to nothing, and a blank parent to its left child's resolution followed
// by its right child's. the traversal uses an explicit stack so a deep tree
// cannot become deep go stack.
func Resolution(shape NodeShape, x NodeIndex) ([]NodeIndex, error) {
	n := shape.LeafCount()
	if err := checkLeafCount(n); err != nil {
		return nil, err
	}
	if uint32(x) >= NodeWidth(n) {
		return nil, ErrNodeOutOfRange
	}

	resolvedNodes := make([]NodeIndex, 0, 8)
	pendingNodes := make([]NodeIndex, 0, 32)
	pendingNodes = append(pendingNodes, x)
	for len(pendingNodes) > 0 {
		node := pendingNodes[len(pendingNodes)-1]
		pendingNodes = pendingNodes[:len(pendingNodes)-1]

		if !shape.IsBlank(node) {
			resolvedNodes = append(resolvedNodes, node)
			for _, leaf := range shape.UnmergedLeaves(node) {
				if LeafCount(leaf) >= n {
					return nil, ErrLeafOutOfRange
				}
				resolvedNodes = append(resolvedNodes, leaf.NodeIndex())
			}
			continue
		}
		if node.IsLeaf() {
			continue
		}

		leftChild, err := Left(node)
		if err != nil {
			return nil, err
		}
		rightChild, err := Right(node)
		if err != nil {
			return nil, err
		}
		// pushed right first so the left child is popped first
		pendingNodes = append(pendingNodes, rightChild, leftChild)
	}
	return resolvedNodes, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run 'TestResolutionRfcFigure10|TestResolutionEdges' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): NodeShape and node resolution, against the RFC 9420 figure 10 example"
```

---

### Task 12: FilteredDirectPath and PathStep, against RFC 9420 Table 2

**Files:**
- Modify: `mls/tree_math.go`
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: `NodeShape`, `Resolution`, `DirectPath`, `Sibling`, `checkLeafCount` (Tasks 8, 11).
- Produces:
  - `type PathStep struct { Node NodeIndex; CopathChild NodeIndex }`
  - `func FilteredDirectPath(shape NodeShape, leaf LeafIndex) ([]PathStep, error)`

Each step pairs a node that needs its own key pair with the child of that node on the leaf's copath —
the node whose resolution the path secret is encrypted to. `len(FilteredDirectPath(...))` is the
required `UpdatePath.nodes` length that ValSem202 checks.

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_test.go`:

```go
// RFC 9420 figure 11: an eight-leaf tree with members at leaves 0, 1, 4, 5, 6.
// leaves 2, 3 and 7 are blank, as are parents U=3, V=5 and Z=13.
func rfcFigure11Shape() *fixtureShape {
	return &fixtureShape{
		fixtureLeafCount: 8,
		blankNodes: map[NodeIndex]bool{
			3: true, 4: true, 5: true, 6: true, 13: true, 14: true,
		},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
	}
}

func TestFilteredDirectPathRfcTable2(t *testing.T) {
	shape := rfcFigure11Shape()
	filteredCases := []struct {
		label        string
		leafIndex    LeafIndex
		filteredPath []PathStep
	}{
		// A: U is dropped because V's subtree is entirely blank.
		{label: "A", leafIndex: 0, filteredPath: []PathStep{
			{Node: 1, CopathChild: 2},
			{Node: 7, CopathChild: 11},
		}},
		{label: "B", leafIndex: 1, filteredPath: []PathStep{
			{Node: 1, CopathChild: 0},
			{Node: 7, CopathChild: 11},
		}},
		// E and F keep the whole direct path: Z resolves to G.
		{label: "E", leafIndex: 4, filteredPath: []PathStep{
			{Node: 9, CopathChild: 10},
			{Node: 11, CopathChild: 13},
			{Node: 7, CopathChild: 3},
		}},
		{label: "F", leafIndex: 5, filteredPath: []PathStep{
			{Node: 9, CopathChild: 8},
			{Node: 11, CopathChild: 13},
			{Node: 7, CopathChild: 3},
		}},
		// G: Z is dropped because H is a blank leaf.
		{label: "G", leafIndex: 6, filteredPath: []PathStep{
			{Node: 11, CopathChild: 9},
			{Node: 7, CopathChild: 3},
		}},
	}
	for _, c := range filteredCases {
		got, err := FilteredDirectPath(shape, c.leafIndex)
		if err != nil {
			t.Errorf("%s filtered direct path: %v", c.label, err)
			continue
		}
		if len(got) != len(c.filteredPath) {
			t.Errorf("%s filtered direct path: %v, want %v", c.label, got, c.filteredPath)
			continue
		}
		for i := range got {
			if got[i] != c.filteredPath[i] {
				t.Errorf("%s filtered direct path: %v, want %v", c.label, got, c.filteredPath)
				break
			}
		}
	}
}

func TestFilteredDirectPathEdges(t *testing.T) {
	// with every leaf populated and every parent blank, nothing filters out and
	// the filtered path is the full direct path.
	populatedLeaves := &fixtureShape{
		fixtureLeafCount:   8,
		blankNodes:         map[NodeIndex]bool{1: true, 3: true, 5: true, 7: true, 9: true, 11: true, 13: true},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
	}
	got, err := FilteredDirectPath(populatedLeaves, 0)
	if err != nil {
		t.Fatalf("filtered direct path: %v", err)
	}
	if len(got) != int(TreeDepth(8)) {
		t.Errorf("filtered direct path length: %d, want %d", len(got), TreeDepth(8))
	}

	// a lone member has no path node to key: every copath child is blank, so
	// there is nobody to encrypt to.
	loneMember := &fixtureShape{
		fixtureLeafCount:   8,
		blankNodes:         map[NodeIndex]bool{},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
	}
	for i := uint32(0); i < NodeWidth(8); i += 1 {
		loneMember.blankNodes[NodeIndex(i)] = true
	}
	loneMember.blankNodes[0] = false
	got, err = FilteredDirectPath(loneMember, 0)
	if err != nil {
		t.Fatalf("lone member filtered direct path: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("lone member filtered direct path: %v, want empty", got)
	}

	// an unmerged leaf on a copath child keeps a node that would otherwise
	// filter out: unmerged leaves count toward the child's resolution.
	unmergedOnly := &fixtureShape{
		fixtureLeafCount:   8,
		blankNodes:         map[NodeIndex]bool{},
		unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
	}
	for i := uint32(0); i < NodeWidth(8); i += 1 {
		unmergedOnly.blankNodes[NodeIndex(i)] = true
	}
	unmergedOnly.blankNodes[0] = false
	unmergedOnly.blankNodes[11] = false
	unmergedOnly.unmergedNodeLeaves[11] = []LeafIndex{4}
	got, err = FilteredDirectPath(unmergedOnly, 0)
	if err != nil {
		t.Fatalf("unmerged filtered direct path: %v", err)
	}
	wantStep := PathStep{Node: 7, CopathChild: 11}
	if len(got) != 1 || got[0] != wantStep {
		t.Errorf("unmerged filtered direct path: %v, want [%v]", got, wantStep)
	}

	if _, err := FilteredDirectPath(rfcFigure11Shape(), 8); !errors.Is(err, ErrLeafOutOfRange) {
		t.Errorf("filtered direct path of leaf 8: %v, want %v", err, ErrLeafOutOfRange)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run 'TestFilteredDirectPathRfcTable2|TestFilteredDirectPathEdges' -v`

Expected: FAIL to build with `undefined: FilteredDirectPath`, `undefined: PathStep`.

- [ ] **Step 3: Write minimal implementation**

Append to `mls/tree_math.go`:

```go
// one node of a filtered direct path together with the child of that node the
// source leaf does not descend from.
//
// the pair is returned rather than the node alone because every caller needs
// both and computing the second from the first is the step that gets written
// backwards: a path secret for Node is encrypted to the resolution of
// CopathChild.
type PathStep struct {
	Node        NodeIndex
	CopathChild NodeIndex
}

// the leaf's direct path with every node removed whose copath child has an
// empty resolution, ordered leaf to root.
//
// a removed node needs no key pair of its own, because encrypting to it would
// be the same as encrypting to its non-copath child. the length of the result
// is the required UpdatePath node count.
func FilteredDirectPath(shape NodeShape, leaf LeafIndex) ([]PathStep, error) {
	n := shape.LeafCount()
	if err := checkLeafCount(n); err != nil {
		return nil, err
	}
	if LeafCount(leaf) >= n {
		return nil, ErrLeafOutOfRange
	}

	leafNode := leaf.NodeIndex()
	pathNodes, err := DirectPath(leafNode, n)
	if err != nil {
		return nil, err
	}

	pathSteps := make([]PathStep, 0, len(pathNodes))
	child := leafNode
	for _, pathNode := range pathNodes {
		copathChild, err := Sibling(child, n)
		if err != nil {
			return nil, err
		}
		copathResolution, err := Resolution(shape, copathChild)
		if err != nil {
			return nil, err
		}
		if len(copathResolution) > 0 {
			pathSteps = append(pathSteps, PathStep{
				Node:        pathNode,
				CopathChild: copathChild,
			})
		}
		child = pathNode
	}
	return pathSteps, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run 'TestFilteredDirectPathRfcTable2|TestFilteredDirectPathEdges' -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math.go mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "feat(mls): filtered direct path with copath children, against RFC 9420 table 2"
```

---

### Task 13: The exhaustive structural invariant sweep

**Files:**
- Test: `mls/tree_math_test.go`

**Interfaces:**
- Consumes: every function produced by Tasks 2 to 12.
- Produces: `TestTreeMathInvariants`. No new package API.

This is the test that covers what family 1 does not: every node of every tree size from 1 to 512
leaves, against algebraic laws rather than against a recorded answer.

- [ ] **Step 1: Write the failing test**

Append to `mls/tree_math_test.go`:

```go
// every node of every tree size from one to 512 leaves, against the structural
// laws the array representation has to satisfy. vector family 1 records answers
// for four relations at ten sizes; these are the laws those answers are
// supposed to obey, checked everywhere.
func TestTreeMathInvariants(t *testing.T) {
	for depth := uint32(0); depth <= 9; depth += 1 {
		leafCount := LeafCount(1) << depth
		nodeWidth := NodeWidth(leafCount)
		root, err := Root(leafCount)
		if err != nil {
			t.Fatalf("%d leaves: root: %v", leafCount, err)
		}
		if uint32(root) >= nodeWidth {
			t.Fatalf("%d leaves: root %d outside width %d", leafCount, root, nodeWidth)
		}
		if root.Level() != depth {
			t.Fatalf("%d leaves: root level %d, want %d", leafCount, root.Level(), depth)
		}

		for i := uint32(0); i < nodeWidth; i += 1 {
			nodeIndex := NodeIndex(i)
			level := nodeIndex.Level()
			if level > depth {
				t.Fatalf("%d leaves: node %d level %d exceeds depth %d", leafCount, nodeIndex, level, depth)
			}

			// children: a parent's children are one level down, straddle it,
			// and both name it as their parent.
			if nodeIndex.IsLeaf() {
				if _, err := Left(nodeIndex); !errors.Is(err, ErrLeafHasNoChildren) {
					t.Fatalf("%d leaves: left of leaf %d: %v", leafCount, nodeIndex, err)
				}
				if _, err := Right(nodeIndex); !errors.Is(err, ErrLeafHasNoChildren) {
					t.Fatalf("%d leaves: right of leaf %d: %v", leafCount, nodeIndex, err)
				}
			} else {
				leftChild, err := Left(nodeIndex)
				if err != nil {
					t.Fatalf("%d leaves: left of %d: %v", leafCount, nodeIndex, err)
				}
				rightChild, err := Right(nodeIndex)
				if err != nil {
					t.Fatalf("%d leaves: right of %d: %v", leafCount, nodeIndex, err)
				}
				if !(leftChild < nodeIndex && nodeIndex < rightChild) {
					t.Fatalf("%d leaves: node %d children %d and %d do not straddle it", leafCount, nodeIndex, leftChild, rightChild)
				}
				if leftChild.Level() != level-1 || rightChild.Level() != level-1 {
					t.Fatalf("%d leaves: node %d children at levels %d and %d, want %d", leafCount, nodeIndex, leftChild.Level(), rightChild.Level(), level-1)
				}
				for _, child := range []NodeIndex{leftChild, rightChild} {
					parent, err := Parent(child, leafCount)
					if err != nil {
						t.Fatalf("%d leaves: parent of %d: %v", leafCount, child, err)
					}
					if parent != nodeIndex {
						t.Fatalf("%d leaves: parent of %d: %d, want %d", leafCount, child, parent, nodeIndex)
					}
				}
			}

			// parent and sibling: defined for every node but the root, and the
			// sibling relation is an involution.
			if nodeIndex == root {
				if _, err := Parent(nodeIndex, leafCount); !errors.Is(err, ErrRootHasNoParent) {
					t.Fatalf("%d leaves: parent of root: %v", leafCount, err)
				}
				if _, err := Sibling(nodeIndex, leafCount); !errors.Is(err, ErrRootHasNoSibling) {
					t.Fatalf("%d leaves: sibling of root: %v", leafCount, err)
				}
			} else {
				parent, err := Parent(nodeIndex, leafCount)
				if err != nil {
					t.Fatalf("%d leaves: parent of %d: %v", leafCount, nodeIndex, err)
				}
				if uint32(parent) >= nodeWidth {
					t.Fatalf("%d leaves: parent of %d is %d, outside width %d", leafCount, nodeIndex, parent, nodeWidth)
				}
				if parent.Level() != level+1 {
					t.Fatalf("%d leaves: parent of %d at level %d, want %d", leafCount, nodeIndex, parent.Level(), level+1)
				}
				sibling, err := Sibling(nodeIndex, leafCount)
				if err != nil {
					t.Fatalf("%d leaves: sibling of %d: %v", leafCount, nodeIndex, err)
				}
				back, err := Sibling(sibling, leafCount)
				if err != nil {
					t.Fatalf("%d leaves: sibling of %d: %v", leafCount, sibling, err)
				}
				if back != nodeIndex {
					t.Fatalf("%d leaves: sibling of sibling of %d: %d", leafCount, nodeIndex, back)
				}
				if sibling.Level() != level {
					t.Fatalf("%d leaves: sibling of %d at level %d, want %d", leafCount, nodeIndex, sibling.Level(), level)
				}
				if CommonAncestor(nodeIndex, sibling) != parent {
					t.Fatalf("%d leaves: common ancestor of %d and its sibling: %d, want %d", leafCount, nodeIndex, CommonAncestor(nodeIndex, sibling), parent)
				}
			}

			// direct path: strictly ascending levels, ending at the root, of
			// the length the depth predicts.
			pathNodes, err := DirectPath(nodeIndex, leafCount)
			if err != nil {
				t.Fatalf("%d leaves: direct path of %d: %v", leafCount, nodeIndex, err)
			}
			if uint32(len(pathNodes)) != depth-level {
				t.Fatalf("%d leaves: direct path of %d has %d nodes, want %d", leafCount, nodeIndex, len(pathNodes), depth-level)
			}
			previousLevel := level
			for _, pathNode := range pathNodes {
				if uint32(pathNode) >= nodeWidth {
					t.Fatalf("%d leaves: direct path of %d contains %d, outside width %d", leafCount, nodeIndex, pathNode, nodeWidth)
				}
				if pathNode.Level() != previousLevel+1 {
					t.Fatalf("%d leaves: direct path of %d is not strictly ascending: %v", leafCount, nodeIndex, pathNodes)
				}
				previousLevel = pathNode.Level()
				if !InSubtree(pathNode, nodeIndex) {
					t.Fatalf("%d leaves: %d is on the direct path of %d but does not contain it", leafCount, pathNode, nodeIndex)
				}
				if CommonAncestor(nodeIndex, pathNode) != pathNode {
					t.Fatalf("%d leaves: common ancestor of %d and its ancestor %d is not the ancestor", leafCount, nodeIndex, pathNode)
				}
			}
			if len(pathNodes) > 0 && pathNodes[len(pathNodes)-1] != root {
				t.Fatalf("%d leaves: direct path of %d ends at %d, want the root %d", leafCount, nodeIndex, pathNodes[len(pathNodes)-1], root)
			}

			// copath: same length as the direct path, in range, and disjoint
			// from the direct path and from the node itself.
			copathNodes, err := Copath(nodeIndex, leafCount)
			if err != nil {
				t.Fatalf("%d leaves: copath of %d: %v", leafCount, nodeIndex, err)
			}
			if len(copathNodes) != len(pathNodes) {
				t.Fatalf("%d leaves: copath of %d has %d nodes, direct path has %d", leafCount, nodeIndex, len(copathNodes), len(pathNodes))
			}
			onPath := map[NodeIndex]bool{nodeIndex: true}
			for _, pathNode := range pathNodes {
				onPath[pathNode] = true
			}
			for j, copathNode := range copathNodes {
				if uint32(copathNode) >= nodeWidth {
					t.Fatalf("%d leaves: copath of %d contains %d, outside width %d", leafCount, nodeIndex, copathNode, nodeWidth)
				}
				if onPath[copathNode] {
					t.Fatalf("%d leaves: copath of %d intersects its direct path at %d", leafCount, nodeIndex, copathNode)
				}
				if InSubtree(copathNode, nodeIndex) {
					t.Fatalf("%d leaves: copath node %d contains %d", leafCount, copathNode, nodeIndex)
				}
				// each copath node is a child of the direct-path node at the
				// same position.
				copathParent, err := Parent(copathNode, leafCount)
				if err != nil {
					t.Fatalf("%d leaves: parent of copath node %d: %v", leafCount, copathNode, err)
				}
				if copathParent != pathNodes[j] {
					t.Fatalf("%d leaves: copath node %d has parent %d, want direct-path node %d", leafCount, copathNode, copathParent, pathNodes[j])
				}
			}

			// subtree span: contiguous, even at both ends, and exactly the set
			// of nodes this node is an ancestor of.
			firstNode, lastNode := SubtreeSpan(nodeIndex)
			if firstNode > nodeIndex || lastNode < nodeIndex {
				t.Fatalf("%d leaves: span of %d is [%d, %d]", leafCount, nodeIndex, firstNode, lastNode)
			}
			if uint32(lastNode) >= nodeWidth {
				t.Fatalf("%d leaves: span of %d ends at %d, outside width %d", leafCount, nodeIndex, lastNode, nodeWidth)
			}
			if !firstNode.IsLeaf() || !lastNode.IsLeaf() {
				t.Fatalf("%d leaves: span of %d is [%d, %d], want both ends on leaves", leafCount, nodeIndex, firstNode, lastNode)
			}
			firstLeaf, lastLeaf := SubtreeLeaves(nodeIndex)
			if uint32(lastLeaf-firstLeaf+1) != uint32(1)<<level {
				t.Fatalf("%d leaves: node %d covers leaves %d..%d at level %d", leafCount, nodeIndex, firstLeaf, lastLeaf, level)
			}
		}

		// the shape rules on a tree with every leaf populated and every parent
		// blank: the root resolves to the leaves in order, and every leaf's
		// filtered direct path is its whole direct path.
		blankParents := &fixtureShape{
			fixtureLeafCount:   leafCount,
			blankNodes:         map[NodeIndex]bool{},
			unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
		}
		for i := uint32(1); i < nodeWidth; i += 2 {
			blankParents.blankNodes[NodeIndex(i)] = true
		}
		rootResolution, err := Resolution(blankParents, root)
		if err != nil {
			t.Fatalf("%d leaves: root resolution: %v", leafCount, err)
		}
		if LeafCount(len(rootResolution)) != leafCount {
			t.Fatalf("%d leaves: root resolution has %d nodes", leafCount, len(rootResolution))
		}
		for i, resolvedNode := range rootResolution {
			if resolvedNode != LeafIndex(i).NodeIndex() {
				t.Fatalf("%d leaves: root resolution position %d is %d, want %d", leafCount, i, resolvedNode, LeafIndex(i).NodeIndex())
			}
		}
		for leaf := LeafIndex(0); LeafCount(leaf) < leafCount; leaf += 1 {
			pathSteps, err := FilteredDirectPath(blankParents, leaf)
			if err != nil {
				t.Fatalf("%d leaves: filtered direct path of leaf %d: %v", leafCount, leaf, err)
			}
			if uint32(len(pathSteps)) != depth {
				t.Fatalf("%d leaves: filtered direct path of leaf %d has %d steps, want %d", leafCount, leaf, len(pathSteps), depth)
			}
			for _, pathStep := range pathSteps {
				parent, err := Parent(pathStep.CopathChild, leafCount)
				if err != nil {
					t.Fatalf("%d leaves: parent of copath child %d: %v", leafCount, pathStep.CopathChild, err)
				}
				if parent != pathStep.Node {
					t.Fatalf("%d leaves: copath child %d is not a child of %d", leafCount, pathStep.CopathChild, pathStep.Node)
				}
				if InSubtree(pathStep.CopathChild, leaf.NodeIndex()) {
					t.Fatalf("%d leaves: copath child %d contains leaf %d", leafCount, pathStep.CopathChild, leaf)
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Temporarily change `if uint32(len(pathNodes)) != depth-level {` to `!= depth-level+1`, then run:
`go test ./mls/... -run TestTreeMathInvariants -v`

Expected: FAIL with `1 leaves: direct path of 0 has 0 nodes, want 1`. Restore the line before step 3.

- [ ] **Step 3: Write minimal implementation**

No implementation is needed: this task asserts laws over functions Tasks 2 to 12 already produced.
Restore the line changed in step 2 and run `gofmt -l mls` to confirm the files are clean.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeMathInvariants -v`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 0 ] || { echo "git index anomaly: $before -> $after, expected +0"; exit 1; }
git commit -m "test(mls): exhaustive tree-math invariant sweep to 512 leaves"
```

---

### Task 14: The fuzz target

**Files:**
- Create: `mls/tree_math_fuzz_test.go`

**Interfaces:**
- Consumes: every function produced by Tasks 2 to 12.
- Produces: `FuzzTreeMath`. No new package API. This is the tree-math share of Spec A §4.4 Gate 4
  properties 1 and 2 (no panic, no unbounded allocation, no unbounded loop, every returned index
  inside the tree). Property 3, differential agreement with OpenMLS, does not apply: OpenMLS exposes
  no tree-math oracle over the stdio protocol and the RFC's semantic definitions already serve as an
  in-process differential in Task 9.

- [ ] **Step 1: Write the failing test**

Create `mls/tree_math_fuzz_test.go`:

```go
// the tree-math share of gate 4 properties 1 and 2.
//
// indices reach this code from decoded messages — a Sender's leaf index, an
// UpdatePath length, a ratchet_tree array width — so every function has to be
// total over the whole uint32 domain: no panic, no shift past the width of the
// type, no loop whose bound comes from the input, and no returned index outside
// the tree that was asked about.
package mls

import (
	"testing"
)

func FuzzTreeMath(f *testing.F) {
	f.Add(uint32(0), uint32(1))
	f.Add(uint32(0), uint32(0))
	f.Add(uint32(6), uint32(8))
	f.Add(uint32(1022), uint32(512))
	f.Add(uint32(0xFFFFFFFF), uint32(0xFFFFFFFF))
	f.Add(uint32(0xFFFFFFFE), uint32(1<<31))
	f.Add(uint32(5), uint32(3))
	f.Add(uint32(0x7FFFFFFF), uint32(1<<31))

	f.Fuzz(func(t *testing.T, rawNode uint32, rawLeafCount uint32) {
		nodeIndex := NodeIndex(rawNode)
		leafCount := LeafCount(rawLeafCount)

		// total functions answer for every input.
		level := nodeIndex.Level()
		if level > 32 {
			t.Fatalf("node %d level %d", nodeIndex, level)
		}
		_ = nodeIndex.IsLeaf()
		_, _ = nodeIndex.LeafIndex()
		_ = IsFullLeafCount(leafCount)
		_ = TreeDepth(leafCount)
		_ = FullLeafCount(leafCount)
		_, _ = LeafCountFromNodeWidth(rawNode)
		_, _ = ExtendedLeafCount(leafCount)
		_, _ = TruncatedLeafCount(LeafIndex(rawNode))

		firstNode, lastNode := SubtreeSpan(nodeIndex)
		if firstNode > nodeIndex || lastNode < nodeIndex {
			t.Fatalf("node %d span [%d, %d] excludes it", nodeIndex, firstNode, lastNode)
		}
		if !InSubtree(nodeIndex, nodeIndex) {
			t.Fatalf("node %d not in its own subtree", nodeIndex)
		}

		other := NodeIndex(rawLeafCount)
		ancestor := CommonAncestor(nodeIndex, other)
		if !InSubtree(ancestor, nodeIndex) || !InSubtree(ancestor, other) {
			t.Fatalf("common ancestor %d of %d and %d contains neither", ancestor, nodeIndex, other)
		}
		if CommonAncestor(other, nodeIndex) != ancestor {
			t.Fatalf("common ancestor of %d and %d is not symmetric", nodeIndex, other)
		}

		// beyond here the leaf count has to describe a real tree.
		root, err := Root(leafCount)
		if err != nil {
			return
		}
		nodeWidth := NodeWidth(leafCount)
		if uint32(root) >= nodeWidth {
			t.Fatalf("%d leaves: root %d outside width %d", leafCount, root, nodeWidth)
		}

		if uint32(nodeIndex) >= nodeWidth {
			// an index past the end is refused by every function that takes a
			// leaf count, never answered.
			if _, err := Parent(nodeIndex, leafCount); err == nil {
				t.Fatalf("%d leaves: parent of out-of-range node %d answered", leafCount, nodeIndex)
			}
			if _, err := DirectPath(nodeIndex, leafCount); err == nil {
				t.Fatalf("%d leaves: direct path of out-of-range node %d answered", leafCount, nodeIndex)
			}
			return
		}

		pathNodes, err := DirectPath(nodeIndex, leafCount)
		if err != nil {
			t.Fatalf("%d leaves: direct path of %d: %v", leafCount, nodeIndex, err)
		}
		// the depth of the largest representable tree bounds every path, so a
		// path longer than this is a runaway loop rather than a wrong answer.
		if len(pathNodes) > 32 {
			t.Fatalf("%d leaves: direct path of %d has %d nodes", leafCount, nodeIndex, len(pathNodes))
		}
		for _, pathNode := range pathNodes {
			if uint32(pathNode) >= nodeWidth {
				t.Fatalf("%d leaves: direct path of %d contains %d", leafCount, nodeIndex, pathNode)
			}
		}

		copathNodes, err := Copath(nodeIndex, leafCount)
		if err != nil {
			t.Fatalf("%d leaves: copath of %d: %v", leafCount, nodeIndex, err)
		}
		if len(copathNodes) != len(pathNodes) {
			t.Fatalf("%d leaves: copath of %d has %d nodes, direct path has %d", leafCount, nodeIndex, len(copathNodes), len(pathNodes))
		}
		for _, copathNode := range copathNodes {
			if uint32(copathNode) >= nodeWidth {
				t.Fatalf("%d leaves: copath of %d contains %d", leafCount, nodeIndex, copathNode)
			}
		}

		// the shape rules, over a shape derived from the input so the blank set
		// is not always the same one.
		fuzzShape := &fixtureShape{
			fixtureLeafCount:   leafCount,
			blankNodes:         map[NodeIndex]bool{},
			unmergedNodeLeaves: map[NodeIndex][]LeafIndex{},
		}
		for i := uint32(0); i < nodeWidth; i += 1 {
			if (i^rawNode)&0x03 == 0 {
				fuzzShape.blankNodes[NodeIndex(i)] = true
			}
		}
		resolvedNodes, err := Resolution(fuzzShape, root)
		if err != nil {
			t.Fatalf("%d leaves: root resolution: %v", leafCount, err)
		}
		if uint32(len(resolvedNodes)) > nodeWidth {
			t.Fatalf("%d leaves: root resolution has %d nodes, width is %d", leafCount, len(resolvedNodes), nodeWidth)
		}
		for _, resolvedNode := range resolvedNodes {
			if uint32(resolvedNode) >= nodeWidth {
				t.Fatalf("%d leaves: root resolution contains %d", leafCount, resolvedNode)
			}
			if fuzzShape.IsBlank(resolvedNode) {
				t.Fatalf("%d leaves: root resolution contains blank node %d", leafCount, resolvedNode)
			}
		}

		leafIndex, err := nodeIndex.LeafIndex()
		if err != nil {
			return
		}
		pathSteps, err := FilteredDirectPath(fuzzShape, leafIndex)
		if err != nil {
			t.Fatalf("%d leaves: filtered direct path of leaf %d: %v", leafCount, leafIndex, err)
		}
		if len(pathSteps) > len(pathNodes) {
			t.Fatalf("%d leaves: filtered direct path of leaf %d has %d steps, direct path has %d", leafCount, leafIndex, len(pathSteps), len(pathNodes))
		}
		for _, pathStep := range pathSteps {
			if uint32(pathStep.Node) >= nodeWidth || uint32(pathStep.CopathChild) >= nodeWidth {
				t.Fatalf("%d leaves: filtered direct path step %v out of range", leafCount, pathStep)
			}
			parent, err := Parent(pathStep.CopathChild, leafCount)
			if err != nil || parent != pathStep.Node {
				t.Fatalf("%d leaves: copath child %d is not a child of %d", leafCount, pathStep.CopathChild, pathStep.Node)
			}
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Temporarily change `if len(pathSteps) > len(pathNodes) {` to `if len(pathSteps) >= 0 {`, then run:
`go test ./mls/... -run FuzzTreeMath -v`

Expected: FAIL on the first seed with `1 leaves: filtered direct path of leaf 0 has 0 steps, direct
path has 0` — which proves the seed corpus really reaches the shape rules rather than returning early.
Restore the line before step 3.

- [ ] **Step 3: Write minimal implementation**

No implementation is needed: the target asserts properties of functions Tasks 2 to 12 already
produced. Restore the line changed in step 2.

- [ ] **Step 4: Run test to verify it passes**

Run the seeds, then a real fuzz run:

```
go test ./mls/... -run FuzzTreeMath -v
go test ./mls/... -run xxx -fuzz FuzzTreeMath -fuzztime 60s
```

Expected: PASS, then `elapsed: 60s, execs: ... new interesting: ...` with no crashers and no file
written under `mls/testdata/fuzz/`.

- [ ] **Step 5: Commit**

```bash
before=$(git ls-files | wc -l)
git add mls/tree_math_fuzz_test.go
after=$(git ls-files | wc -l)
[ $((after - before)) -eq 1 ] || { echo "git index anomaly: $before -> $after, expected +1"; exit 1; }
git commit -m "test(mls): fuzz the tree-math surface over the whole index domain"
```

---

## Definition of done

Run from the `connect` repo root. All four must be green before this plan is closed.

```
gofmt -l mls
go vet ./mls/...
go test ./mls/... -race -timeout 0 -run 'TestTreeMath|TestNodeIndex|TestNodeWidth|TestFullLeafCount|TestLeafCountFromNodeWidth|TestExtendAndTruncate|TestDirectPath|TestCommonAncestor|TestSubtree|TestInSubtree|TestResolution|TestFilteredDirectPath' -v
go test ./mls/... -run xxx -fuzz FuzzTreeMath -fuzztime 60s
```

Plus the layering assertion, once `connect/layering_test.go` exists (Validation plan): the import set
of `github.com/urnetwork/connect/mls` attributable to `tree_math.go` is exactly `errors` and
`math/bits`.

**Gate commands for the CI `vectors` and `fuzz-short` jobs**, which the Validation and interop
harness plan owns and must wire:

| Gate | Command |
|---|---|
| Spec A §4.2.1 family 1, through the registry | `go test ./mls/... -run 'TestVectorFamiliesVerify\|TestVectorManifestIsComplete\|TestVectorGenerateThenVerify'` |
| Spec A §4.2.1 family 1, directly | `go test ./mls/... -run TestTreeMathVectors` |
| Corpus tripwire | `go test ./mls/... -run TestTreeMathVectorFileShape` |
| Structural sweep | `go test ./mls/... -run TestTreeMathInvariants` |
| Gate 4 properties 1–2 | `go test ./mls/... -run xxx -fuzz FuzzTreeMath -fuzztime 60s` |

`FuzzTreeMath` must appear as a row in that plan's `fuzz-short` matrix. A fuzz target that no
workflow names is a target that runs only when someone remembers to run it.

---

## Boundaries with the plans running in parallel

**The implementation file consumes nothing.** `tree_math.go` imports `errors` and `math/bits`, and
it can be written before, during or after the Syntax and Crypto plans with no ordering constraint.
It names no `CipherSuite`, no `CryptoProvider` and no `syntax` symbol, and it must stay that way:
tree math is ciphersuite-independent by construction.

**The test files consume exactly three symbols**, all from the Validation and interop harness plan's
`mls/vectors_test.go`, which is wave 1 alongside this plan:

```go
type VectorFamily struct {
    Number   int                                       // 1..16, the Spec A §4.2.1 row
    Name     string
    File     string                                    // under testdata/vectors
    Slice    string                                    // "A1".."A4"
    Verify   func(t *testing.T, raw json.RawMessage)   // nil == not yet implemented
    Generate func(t *testing.T) json.RawMessage        // nil == format has no generate direction
}
func RegisterVectorFamily(family VectorFamily)
func LoadVectorFile(t *testing.T, file string) []json.RawMessage
```

`MustHex` and `HexOf` are on that plan's list of symbols this one may call; family 1 has no
hex-encoded field, so this plan calls neither, and it defines no local hex decoder or corpus reader
that would become a second one.

The ordering this creates is narrow and entirely inside wave 1: that plan's vendoring task
(all sixteen mlswg files, `testdata/vectors/VECTORS.sha256`, `mls/interop/PINS.md`) and its vector
registry task run before Task 1 of this plan. Tasks 2, 3 and 8 to 14 touch neither and can run at
any time.

**What downstream plans consume from this plan** — the complete produced surface, which is the
contract to write a Consumes block against:

```go
package mls

type LeafIndex uint32
type NodeIndex uint32
type LeafCount uint32

const MaxLeafCount LeafCount = 1 << 31

var ErrLeafCountRange, ErrLeafCountNotFull, ErrNodeOutOfRange, ErrLeafOutOfRange,
    ErrNodeIsParent, ErrLeafHasNoChildren, ErrRootHasNoParent, ErrRootHasNoSibling,
    ErrNodeWidthNotOdd error

func (self LeafIndex) NodeIndex() NodeIndex
func (self NodeIndex) IsLeaf() bool
func (self NodeIndex) LeafIndex() (LeafIndex, error)
func (self NodeIndex) Level() uint32

func NodeWidth(n LeafCount) uint32
func LeafCountFromNodeWidth(w uint32) (LeafCount, error)
func IsFullLeafCount(n LeafCount) bool
func TreeDepth(n LeafCount) uint32
func FullLeafCount(n LeafCount) LeafCount
func ExtendedLeafCount(n LeafCount) (LeafCount, error)
func TruncatedLeafCount(rightmostNonBlankLeaf LeafIndex) (LeafCount, error)

func Root(n LeafCount) (NodeIndex, error)
func Left(x NodeIndex) (NodeIndex, error)
func Right(x NodeIndex) (NodeIndex, error)
func Parent(x NodeIndex, n LeafCount) (NodeIndex, error)
func Sibling(x NodeIndex, n LeafCount) (NodeIndex, error)
func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)
func Copath(x NodeIndex, n LeafCount) ([]NodeIndex, error)
func CommonAncestor(x NodeIndex, y NodeIndex) NodeIndex

func SubtreeSpan(x NodeIndex) (firstNode NodeIndex, lastNode NodeIndex)
func SubtreeLeaves(x NodeIndex) (firstLeaf LeafIndex, lastLeaf LeafIndex)
func InSubtree(head NodeIndex, x NodeIndex) bool

type NodeShape interface {
    LeafCount() LeafCount
    IsBlank(x NodeIndex) bool
    UnmergedLeaves(x NodeIndex) []LeafIndex
}

type PathStep struct {
    Node        NodeIndex
    CopathChild NodeIndex
}

func Resolution(shape NodeShape, x NodeIndex) ([]NodeIndex, error)
func FilteredDirectPath(shape NodeShape, leaf LeafIndex) ([]PathStep, error)
```

Semantics a consumer must not have to read the implementation to know:

- `DirectPath` is ordered leaf to root, excludes the node, includes the root; the root's is empty.
- `Copath` is ordered leaf to root, excludes the root, and is always the same length as `DirectPath`.
  `Copath(x, n)[i]` is a child of `DirectPath(x, n)[i]`.
- `FilteredDirectPath` is ordered leaf to root and its length is the required `UpdatePath.nodes`
  count. A path secret for `PathStep.Node` is encrypted to `Resolution(shape, PathStep.CopathChild)`.
- `Resolution` is a depth-first left-first enumeration; a non-blank node contributes itself followed
  by its unmerged leaves as node indices.
- Every function that takes a `LeafCount` requires a power of two and returns `ErrLeafCountNotFull`
  otherwise. `NodeWidth` and `LeafCountFromNodeWidth` are the two exceptions, because the
  `ratchet_tree` extension carries a truncated array.
- Empty results are empty non-nil slices.

**Obligations this plan places on other plans:**

| Plan | Obligation |
|---|---|
| TreeKEM (wave 2) | The ratchet tree type in `tree.go` must implement `mls.NodeShape`. Its `UnmergedLeaves` returns the stored list in stored order. |
| TreeKEM (wave 2) | `tree_sync.go` owns the RFC §7.9 checks this file deliberately does not make: unmerged-leaf lists sorted and strictly increasing, each entry a non-blank leaf inside the node's subtree, and ValSem300's no-trailing-blank-nodes rule. |
| TreeKEM (wave 2) | Tree extension and truncation call `ExtendedLeafCount` and `TruncatedLeafCount` rather than open-coding `2*n` and a bit scan. |
| Crypto primitives and HPKE (wave 1) | Owns the `// Package mls ...` doc comment, in `suite.go` or `doc.go`. This plan adds a file doc comment only. |
| Validation and interop harness (wave 1) | Owns `mls/errors.go` (one typed error per ValSem code), `mls/profile.go`, `mls/vectors_test.go` and every CI workflow file, and must wire the gate commands above into the `vectors` and `fuzz-short` jobs — including a `FuzzTreeMath` row in the `fuzz-short` matrix. The nine structural errors here are not ValSem codes and stay in `tree_math.go`. |
| Validation and interop harness (wave 1) | Its vendoring task must land `mls/testdata/vectors/tree-math.json` before Task 1 of this plan runs, and its vector-registry task must land `VectorFamily`, `RegisterVectorFamily` and `LoadVectorFile` before Task 1 and `expectedPendingFamilies` before Task 7. This plan vendors nothing and writes no pin file. |
| Group lifecycle (wave 4) | `commit.go` owns the 500-member and 10-device caps. No product limit belongs in `tree_math.go`. |
| Key schedule, TreeKEM, framing, group lifecycle, validation | The produced surface above is normative. Every count parameter is `LeafCount`, never `LeafIndex`, `uint32` or a `TreeSize` alias; `Root`, `Left`, `Right`, `Parent`, `Sibling`, `DirectPath` and `Copath` are two-valued and the error is handled, never discarded; `Level` and `LeafIndex` are methods on `NodeIndex`, not free functions; `CommonAncestor` takes two `NodeIndex` values. A shim that folds one of these errors into `false` is how the trailing-blank case of ValSem300 gets silently accepted, so there are no shims outside TreeKEM's own file. |

**Settled elsewhere, recorded here so nobody re-opens it:**

1. **The vendored-vector pin.** One pin file for the whole slice, `connect/mls/interop/PINS.md`, with
   machine-readable `mlswg=<sha>` and `openmls=<sha>` lines, written by the Validation and interop
   harness plan's vendoring task alongside `testdata/vectors/VECTORS.sha256`. Family 1 is pinned at
   mlswg commit `cfd450286d1bfd9cd2519b95c80f9771f94a5b1a`. Neither `connect/mls/PINS.md` nor
   `connect/mls/testdata/vectors/PINS.md` exists; earlier drafts of this plan and of three others
   each created one, which is why two of the pin greps in the framing and lifecycle plans expanded to
   an empty commit.
2. **The `vectors` CI job.** Owned by the Validation and interop harness plan. Family 1 reaches it
   through `RegisterVectorFamily` (Task 7), not through a job-level `-run TestTreeMathVectors`
   filter — a filter is a list somebody has to remember to extend, and the registry is not.
3. **`connect/go.mod`.** Decided: the `go` directive stays at `1.26.3` and `toolchain go1.26.5` is
   added, by the Syntax and codec plan and nobody else. This plan does not touch the file.
