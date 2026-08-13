# TreeKEM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the RFC 9420 ratchet tree in pure Go — LeafNode and ParentNode, tree and parent
hashes, blank nodes and unmerged leaves, UpdatePath generation and processing, path secrets, and full
tree validation — so the `treekem` and `tree-validation` vector families pass and the tree survives
the mlswg interop harness in both roles.

**Architecture:** One `RatchetTree` value type over a flat `[]*Node` array in RFC 9420 §4.2 node-index
order, with all index arithmetic delegated to `tree_math.go` (wave 1). Public tree state (node keys,
parent hashes, unmerged leaves) is separated from the per-member private state (`TreeKEMPrivate`:
path secrets and derived HPKE private keys), so a receiver can merge an UpdatePath's public half and
verify parent hashes before it holds any secret. UpdatePath generation is split into a secret/public
phase and an encryption phase, because the HPKE encryption context is the *new* GroupContext, whose
`tree_hash` is only computable after the path's public keys are already in the tree.

**Tech Stack:** Go 1.26.5 (pinned), `connect/mls` package, `connect/mls/syntax` codec, stdlib crypto
only (`crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`) plus `chacha20poly1305` from the pinned
`golang.org/x/crypto`. No cgo, no Rust, no new third-party dependency.

## Global Constraints

- Go 1.26.5, pinned. Standard library only for crypto: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, plus `chacha20poly1305` from the already-pinned `golang.org/x/crypto`.
- NO cgo, NO Rust, NO new third-party crypto dependency. `sdk` must stay gomobile-buildable.
- OpenMLS (Rust) is a READ-ONLY differential oracle used out of process in CI. It is never in go.mod, never linked, never in a shipped artifact.
- Ciphersuite: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003) for every group; `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) is registered and implemented, so no code in this plan may assume a singleton suite.
- Narrow v1 profile: BasicCredential only, no external commits, no external senders, no PSKs, no ReInit, no branching, no subgroups. All parse-refused with typed errors.
- `connect` (the parent package) must NEVER import `connect/mls` or `connect/message`. A package must not import its own subpackages. Enforced by `connect/layering_test.go`.
- `connect/mls` imports only stdlib, `golang.org/x/crypto`, and `connect/mls/syntax`. Nothing in this plan may import `connect` or `connect/message`.
- `sdk.GenerateSharedSecret`, `box.Precompute` and `curve25519.ScalarMult` MUST NOT be used. All X25519 goes through `crypto/ecdh` or `curve25519.X25519`, and a returned error is a hard validation failure — never logged and continued.
- MLS signs over serialized forms, so the TLS presentation-language codec must be byte-exact and round-trip stable. One codec (`connect/mls/syntax`), one fuzz corpus.
- Every tag/hash comparison in this plan uses `crypto/subtle.ConstantTimeCompare`, never `bytes.Equal` (Spec A §5.9 G8).
- Max group size 500 members and 10 leaves per identity are enforced in `commit.go` (group lifecycle plan), not here. Nothing in this plan may hardcode either bound.
- `mls.Group` is not safe for concurrent use; `RatchetTree` and `TreeKEMPrivate` are likewise value-ish types with no internal locking. The caller serializes.
- All commands run from the root of the `connect` repo, module `github.com/urnetwork/connect`, on branch `beta/message`. Package path is `./mls/...`.
- **Windows git hazard:** this workspace has lost its git index before. Before every `git commit`, run `git ls-files | wc -l` and confirm the count has not dropped. A dropped count means the index vanished — re-`git add` the whole tree before committing.

---

## File Structure

| File | Single responsibility |
|---|---|
| `mls/tree_errors.go` | **Create.** The typed errors raised by tree and TreeKEM code that are *not* ValSem-numbered. ValSem-numbered errors come from `errors.go` (validation plan). |
| `mls/extension.go` | **Create.** `ExtensionType`, `Extension`, `Capabilities`, `RequiredCapabilities`, `ProtocolVersion`, `CredentialType`, `ProposalType`, and the `urmessage_leaf_keys` (0xF002) extension body. Wire codec for each. |
| `mls/extension_test.go` | **Create.** Round-trip and rejection tests for the above. |
| `mls/leaf_node.go` | **Create.** `LeafNodeSource`, `Lifetime`, `LeafNode`, `LeafNodeTBS`, leaf signing and signature verification, RFC 9420 §7.3 leaf validation including erratum 8745. |
| `mls/leaf_node_test.go` | **Create.** LeafNode codec, signing, and §7.3 validation tests. |
| `mls/tree.go` | **Create.** `NodeType`, `ParentNode`, `Node`, `RatchetTree` storage and accessors, blanking, resolution, add/update/remove, truncation, filtered direct path, copath encryption targets, and the `ratchet_tree` extension codec. |
| `mls/tree_test.go` | **Create.** Structure, resolution, tree-operation and codec tests. |
| `mls/tree_hash.go` | **Create.** `TreeHashInput`/`LeafNodeHashInput`/`ParentNodeHashInput`, the tree hash, the original tree hash under an exclusion set, `ParentHashInput`, and parent-hash verification (§7.9.2). |
| `mls/tree_hash_test.go` | **Create.** Tree hash, original tree hash and parent-hash-validity tests. |
| `mls/tree_sync.go` | **Create.** Whole-tree validation: structure, leaf validation across the tree, key uniqueness, unmerged-leaf consistency, parent hashes, tree hash against a GroupContext value. |
| `mls/tree_sync_test.go` | **Create.** Tree validation tests, including the negative ValSem cases owned here. |
| `mls/treekem.go` | **Create.** `HpkeCiphertext`, `UpdatePathNode`, `UpdatePath` and their codec; path-secret ladder; `TreeKEMPrivate`; UpdatePath creation, encryption, merge and decryption. |
| `mls/treekem_test.go` | **Create.** Path secret, create/encrypt/merge/decrypt and negative tests. |
| `mls/tree_testutil_test.go` | **Create.** The n-member test tree builder shared by every test file in this plan. |
| `mls/tree_vectors_test.go` | **Create.** Harnesses for vector families 9 (tree-operations), 10 (tree-validation) and 11 (TreeKEM). |
| `mls/tree_fuzz_test.go` | **Create.** `FuzzRatchetTreeDecode` and `FuzzUpdatePathDecode`: no-panic and round-trip-stability properties (Gate 4 properties 1 and 2). |
| `mls/tree_bench_test.go` | **Create.** Tree hash, parent-hash verification and UpdatePath benchmarks at the 500-member design target. |
| `mls/testdata/vectors/tree-operations.json` | **Create.** Vendored family 9 vector, pinned. |
| `mls/testdata/vectors/tree-validation.json` | **Create.** Vendored family 10 vector, pinned. |
| `mls/testdata/vectors/treekem.json` | **Create.** Vendored family 11 vector, pinned. |
| `mls/testdata/vectors/PINS.md` | **Create.** The mlswg commit the three files came from and their SHA-256 digests. |
| `mls/testdata/corpus/ratchet_tree/`, `mls/testdata/corpus/update_path/` | **Create.** Seed corpora for the two fuzz targets. |

---

## Interfaces consumed from other plans

Every symbol below is in package `mls` (or `mls/syntax`) and is written by another plan in this
slice. This plan does not define any of them.

```go
// mls/syntax — Syntax and codec plan (wave 1)
package syntax

const MaxVectorLength = 1 << 20        // 1 MiB
const MaxRatchetTreeLength = 16 << 20  // 16 MiB

type Writer struct{ /* opaque */ }
func NewWriter() *Writer
func (self *Writer) WriteUint8(v uint8)
func (self *Writer) WriteUint16(v uint16)
func (self *Writer) WriteUint32(v uint32)
func (self *Writer) WriteUint64(v uint64)
func (self *Writer) WriteBytes(b []byte)      // raw, no length prefix
func (self *Writer) WriteOpaqueVec(b []byte)  // MLS variable-length prefix then b
func (self *Writer) Bytes() []byte

type Reader struct{ /* opaque */ }
func NewReader(data []byte) *Reader
func (self *Reader) ReadUint8() (uint8, error)
func (self *Reader) ReadUint16() (uint16, error)
func (self *Reader) ReadUint32() (uint32, error)
func (self *Reader) ReadUint64() (uint64, error)
func (self *Reader) ReadOpaqueVec() ([]byte, error)
func (self *Reader) ReadVecReader() (*Reader, error) // sub-Reader over one length-prefixed region
func (self *Reader) Empty() bool

var ErrTruncated error
var ErrTrailingBytes error
var ErrNonMinimalLength error
var ErrVectorTooLong error
```

```go
// mls/crypto.go, mls/hpke.go, mls/suite.go — Crypto primitives and HPKE plan (wave 1)
package mls

type CipherSuite uint16
const CipherSuiteX25519ChaCha20SHA256Ed25519 CipherSuite = 0x0003

type HpkePublicKey []byte
type HpkePrivateKey []byte
type SignaturePublicKey []byte
type SignaturePrivateKey []byte

type CryptoProvider interface { /* full surface in Spec A §3.3 */
    Suite() CipherSuite
    HashSize() int
    Hash(data []byte) []byte
    DeriveSecret(secret []byte, label string) []byte
    ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte
    DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error)
    SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error)
    VerifyWithLabel(pub SignaturePublicKey, label string, content, sig []byte) error
    SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error)
    Random(n int) []byte
}
func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)

// RFC 9420 §5.1.3, wrapping RFC 9180 SealBase/OpenBase with the MLS EncryptContext struct.
func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string,
    context, plaintext []byte) (kemOutput, ciphertext []byte, err error)
func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string,
    context, kemOutput, ciphertext []byte) ([]byte, error)
```

```go
// mls/tree_math.go — Tree math plan (wave 1)
package mls

type LeafIndex uint32
type NodeIndex uint32

func (self LeafIndex) NodeIndex() NodeIndex
func (self NodeIndex) LeafIndex() (LeafIndex, bool)
func (self NodeIndex) IsLeaf() bool
func Level(x NodeIndex) uint32
func NodeWidth(nLeaves uint32) uint32           // 2*nLeaves - 1, 0 for nLeaves == 0
func Root(nLeaves uint32) NodeIndex
func Left(x NodeIndex) (NodeIndex, bool)        // false when x is a leaf
func Right(x NodeIndex) (NodeIndex, bool)
func Parent(x NodeIndex, nLeaves uint32) (NodeIndex, bool)   // false at the root
func Sibling(x NodeIndex, nLeaves uint32) (NodeIndex, bool)
func DirectPath(x NodeIndex, nLeaves uint32) []NodeIndex     // excludes x, includes the root
func CoPath(x NodeIndex, nLeaves uint32) []NodeIndex
func CommonAncestor(x, y NodeIndex) NodeIndex
```

```go
// mls/credential.go — Syntax and codec plan (wave 1)
package mls

type Credential struct {
    CredentialType CredentialType // 0x0001 basic only in v1
    Identity       []byte         // BasicCredential.identity
}
func (self *Credential) MarshalTo(w *syntax.Writer) error
func UnmarshalCredential(r *syntax.Reader) (Credential, error)
```

```go
// mls/errors.go — Validation and interop harness plan (wave 1). One value per ValSem code.
package mls

var ErrBadSignature error                // ValSem010
var ErrDuplicateSignatureKey error       // ValSem101
var ErrDuplicateEncryptionKey error      // ValSem103 / 110 / 206 / 207
var ErrMissingRequiredCapability error   // ValSem106 / 109
var ErrPathLength error                  // ValSem202
var ErrPathDecrypt error                 // ValSem203
var ErrPathKeyMismatch error             // ValSem204
var ErrTrailingBlankNodes error          // ValSem300
```

```go
// mls/key_schedule.go — Key schedule and secret tree plan (wave 2)
package mls

// Consumed only by tree_sync.go, to check a tree hash against the context that pinned it.
type GroupContext struct {
    Version                 ProtocolVersion
    CipherSuite             CipherSuite
    GroupId                 []byte
    Epoch                   uint64
    TreeHash                []byte
    ConfirmedTranscriptHash []byte
    Extensions              []Extension    // the Extension type is Produced by THIS plan
}
func (self *GroupContext) Marshal() ([]byte, error)
```

```go
// mls/proposal.go, mls/key_package.go — Group lifecycle plan (wave 4).
// Consumed by Task 28 only. No other task in this plan depends on wave 4.
package mls

type ProposalKind uint16
const (
    ProposalKindAdd    ProposalKind = 0x0001
    ProposalKindUpdate ProposalKind = 0x0002
    ProposalKindRemove ProposalKind = 0x0003
)
type KeyPackage struct {
    Version     ProtocolVersion
    CipherSuite CipherSuite
    InitKey     HpkePublicKey
    LeafNode    LeafNode      // the LeafNode type is Produced by THIS plan
    Extensions  []Extension
    Signature   []byte
}
type Proposal struct {
    Kind    ProposalKind
    Add     *KeyPackage
    Update  *LeafNode
    Remove  *LeafIndex
}
func ParseProposal(data []byte) (*Proposal, error)
```

---

## Interfaces produced by this plan

The complete contract other plans write their Consumes blocks against. Nothing else in `mls/tree*.go`,
`mls/leaf_node.go` or `mls/extension.go` is exported.

```go
package mls

// ---- extension.go ----
type ProtocolVersion uint16
type CredentialType uint16
type ProposalType uint16
type ExtensionType uint16

const ProtocolVersionMLS10 ProtocolVersion = 0x0001
const CredentialTypeBasic CredentialType = 0x0001
const (
    ExtensionTypeRatchetTree         ExtensionType = 0x0002
    ExtensionTypeRequiredCapabilities ExtensionType = 0x0003
    ExtensionTypeUrmessageGroupPolicy ExtensionType = 0xF001
    ExtensionTypeUrmessageLeafKeys    ExtensionType = 0xF002
    ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003
)

type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}
func (self *Extension) MarshalTo(w *syntax.Writer) error
func UnmarshalExtension(r *syntax.Reader) (Extension, error)
func MarshalExtensions(exts []Extension) ([]byte, error)
func UnmarshalExtensions(r *syntax.Reader) ([]Extension, error)
func FindExtension(exts []Extension, t ExtensionType) ([]byte, bool)

type Capabilities struct {
    Versions     []ProtocolVersion
    CipherSuites []CipherSuite
    Extensions   []ExtensionType
    Proposals    []ProposalType
    Credentials  []CredentialType
}
func (self *Capabilities) MarshalTo(w *syntax.Writer) error
func UnmarshalCapabilities(r *syntax.Reader) (Capabilities, error)
func (self *Capabilities) SupportsExtension(t ExtensionType) bool
func (self *Capabilities) SupportsCredential(t CredentialType) bool
func (self *Capabilities) SupportsProposal(t ProposalType) bool
func (self *Capabilities) SupportsVersion(v ProtocolVersion) bool
func (self *Capabilities) SupportsCipherSuite(s CipherSuite) bool

type RequiredCapabilities struct {
    ExtensionTypes  []ExtensionType
    ProposalTypes   []ProposalType
    CredentialTypes []CredentialType
}
func (self *RequiredCapabilities) Marshal() ([]byte, error)
func UnmarshalRequiredCapabilities(data []byte) (RequiredCapabilities, error)

// urmessage_leaf_keys, 0xF002. MASTER §5.3, Spec A §3.4.
type LeafKeysExtension struct {
    AlgId          uint16 // 0x0014 = X-Wing (X25519 + ML-KEM-768)
    DeviceXwingPub []byte // exactly XwingPublicKeyLen bytes for alg 0x0014
}
const AlgIdXwing uint16 = 0x0014
const XwingPublicKeyLen = 1216
func (self *LeafKeysExtension) Marshal() ([]byte, error)
func UnmarshalLeafKeysExtension(data []byte) (LeafKeysExtension, error)

// ---- leaf_node.go ----
type LeafNodeSource uint8
const (
    LeafNodeSourceKeyPackage LeafNodeSource = 1
    LeafNodeSourceUpdate     LeafNodeSource = 2
    LeafNodeSourceCommit     LeafNodeSource = 3
)

type Lifetime struct {
    NotBefore uint64
    NotAfter  uint64
}

type LeafNode struct {
    EncryptionKey  HpkePublicKey
    SignatureKey   SignaturePublicKey
    Credential     Credential
    Capabilities   Capabilities
    LeafNodeSource LeafNodeSource
    Lifetime       Lifetime   // source == key_package
    ParentHash     []byte     // source == commit
    Extensions     []Extension
    Signature      []byte
}
func (self *LeafNode) MarshalTo(w *syntax.Writer) error
func (self *LeafNode) Marshal() ([]byte, error)
func UnmarshalLeafNode(r *syntax.Reader) (*LeafNode, error)
func ParseLeafNode(data []byte) (*LeafNode, error)
func (self *LeafNode) Clone() *LeafNode

func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey,
    groupId []byte, leafIndex LeafIndex) error
func (self *LeafNode) VerifySignature(crypto CryptoProvider,
    groupId []byte, leafIndex LeafIndex) error

type LeafValidationContext struct {
    Crypto            CryptoProvider
    Suite             CipherSuite
    GroupId           []byte
    LeafIndex         LeafIndex
    ExpectedSource    LeafNodeSource
    RequiredCaps      *RequiredCapabilities
    GroupExtensions   []Extension
    NowMs             uint64  // 0 skips the lifetime check
    ClockSkewMs       uint64
}
func (self *LeafNode) Validate(ctx *LeafValidationContext) error

// ---- tree.go ----
type NodeType uint8
const (
    NodeTypeLeaf   NodeType = 1
    NodeTypeParent NodeType = 2
)

type ParentNode struct {
    EncryptionKey  HpkePublicKey
    ParentHash     []byte
    UnmergedLeaves []LeafIndex
}
func (self *ParentNode) MarshalTo(w *syntax.Writer) error
func UnmarshalParentNode(r *syntax.Reader) (*ParentNode, error)
func (self *ParentNode) Clone() *ParentNode

type Node struct {
    NodeType NodeType
    Leaf     *LeafNode
    Parent   *ParentNode
}

type RatchetTree struct{ /* opaque: nodes []*Node */ }

func NewRatchetTree() *RatchetTree
func (self *RatchetTree) LeafWidth() uint32     // leaf slots; always a power of two
func (self *RatchetTree) NodeWidth() uint32     // 2*LeafWidth - 1
func (self *RatchetTree) Get(x NodeIndex) *Node // nil when blank or out of range
func (self *RatchetTree) Leaf(i LeafIndex) *LeafNode
func (self *RatchetTree) ParentAt(x NodeIndex) *ParentNode
func (self *RatchetTree) SetLeaf(i LeafIndex, leaf *LeafNode) error
func (self *RatchetTree) SetParent(x NodeIndex, parent *ParentNode) error
func (self *RatchetTree) Blank(x NodeIndex) error
func (self *RatchetTree) BlankDirectPath(i LeafIndex) error
func (self *RatchetTree) Clone() *RatchetTree
func (self *RatchetTree) Members() []LeafIndex
func (self *RatchetTree) MemberCount() uint32
func (self *RatchetTree) FindLeafBySignatureKey(key SignaturePublicKey) (LeafIndex, bool)
func (self *RatchetTree) Resolution(x NodeIndex) []NodeIndex
func (self *RatchetTree) AddLeaf(leaf *LeafNode) (LeafIndex, error)
func (self *RatchetTree) UpdateLeaf(i LeafIndex, leaf *LeafNode) error
func (self *RatchetTree) RemoveLeaf(i LeafIndex) error
func (self *RatchetTree) FilteredDirectPath(i LeafIndex) ([]NodeIndex, error)
func (self *RatchetTree) EncryptionTargets(sender LeafIndex, exclude []LeafIndex) ([][]NodeIndex, error)
func (self *RatchetTree) Marshal() ([]byte, error)
func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)

// ---- tree_hash.go ----
func (self *RatchetTree) TreeHash(crypto CryptoProvider) ([]byte, error)
func (self *RatchetTree) NodeTreeHash(crypto CryptoProvider, x NodeIndex) ([]byte, error)
func (self *RatchetTree) TreeHashes(crypto CryptoProvider) ([][]byte, error)
func (self *RatchetTree) ParentHash(crypto CryptoProvider, parent, copathChild NodeIndex) ([]byte, error)
func (self *RatchetTree) VerifyParentHashes(crypto CryptoProvider) error

// ---- tree_sync.go ----
type TreeValidationContext struct {
    Crypto          CryptoProvider
    Suite           CipherSuite
    GroupId         []byte
    RequiredCaps    *RequiredCapabilities
    GroupExtensions []Extension
    NowMs           uint64
    ClockSkewMs     uint64
}
func (self *RatchetTree) Validate(ctx *TreeValidationContext) error
func (self *RatchetTree) ValidateAgainstContext(ctx *TreeValidationContext, gc *GroupContext) error

// ---- treekem.go ----
type HpkeCiphertext struct {
    KemOutput  []byte
    Ciphertext []byte
}
type UpdatePathNode struct {
    EncryptionKey       HpkePublicKey
    EncryptedPathSecret []HpkeCiphertext
}
type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode
}
func (self *UpdatePath) MarshalTo(w *syntax.Writer) error
func (self *UpdatePath) Marshal() ([]byte, error)
func UnmarshalUpdatePath(r *syntax.Reader) (*UpdatePath, error)
func ParseUpdatePath(data []byte) (*UpdatePath, error)

type TreeKEMPrivate struct {
    LeafIndex      LeafIndex
    EncryptionPriv HpkePrivateKey
    PathSecrets    map[NodeIndex][]byte
}
func NewTreeKEMPrivate(i LeafIndex, encryptionPriv HpkePrivateKey) *TreeKEMPrivate
func (self *TreeKEMPrivate) Clone() *TreeKEMPrivate
func (self *TreeKEMPrivate) NodePrivateKey(crypto CryptoProvider, x NodeIndex) (HpkePrivateKey, bool, error)
func (self *TreeKEMPrivate) Consistent(crypto CryptoProvider, tree *RatchetTree) error

func DerivePathSecrets(crypto CryptoProvider, initial []byte, count int) [][]byte
func DeriveNodeKeyPair(crypto CryptoProvider, pathSecret []byte) (HpkePrivateKey, HpkePublicKey, error)

type UpdatePathPlan struct {
    Path         []NodeIndex
    PathSecrets  [][]byte
    PublicKeys   []HpkePublicKey
    LeafNode     *LeafNode
    CommitSecret []byte
    Private      *TreeKEMPrivate
}
func (self *RatchetTree) CreateUpdatePathSecrets(crypto CryptoProvider, sender LeafIndex,
    signer SignaturePrivateKey, groupId []byte) (*UpdatePathPlan, error)
func (self *RatchetTree) EncryptUpdatePath(crypto CryptoProvider, plan *UpdatePathPlan,
    sender LeafIndex, groupContext []byte, exclude []LeafIndex) (*UpdatePath, error)
func (self *RatchetTree) MergeUpdatePath(crypto CryptoProvider, sender LeafIndex, path *UpdatePath) error

type PathDecryptResult struct {
    CommitSecret []byte
    Private      *TreeKEMPrivate
}
func (self *RatchetTree) DecryptUpdatePath(crypto CryptoProvider, sender LeafIndex,
    path *UpdatePath, groupContext []byte, priv *TreeKEMPrivate,
    exclude []LeafIndex) (*PathDecryptResult, error)

// ---- tree_errors.go ----
var ErrLeafIndexOutOfRange error
var ErrNodeIndexOutOfRange error
var ErrTreeMalformed error
var ErrNodeTypeMismatch error
var ErrUnmergedLeavesNotSorted error
var ErrUnmergedLeafInconsistent error
var ErrParentHashMismatch error
var ErrTreeHashMismatch error
var ErrLeafNodeSourceMismatch error
var ErrLeafNodeLifetime error
var ErrLeafKeysExtensionInvalid error
var ErrNoPathSecret error
var ErrPathSecretMismatch error
```

**Ordering note for callers.** The three TreeKEM entry points must be called in this order, because
the HPKE context is the new epoch's GroupContext and its `tree_hash` covers the path's own public
keys:

1. `CreateUpdatePathSecrets` — mutates the tree (new keys, parent hashes, signed leaf), returns the plan.
2. `TreeHash` — now reflects the applied path; the caller builds the new `GroupContext` from it.
3. `EncryptUpdatePath` — encrypts the plan's path secrets under that serialized GroupContext.

and on the receiving side:

1. `MergeUpdatePath` — public state only; recomputes and checks parent hashes, checks ValSem202.
2. `TreeHash` → caller builds the new `GroupContext`.
3. `DecryptUpdatePath` — recovers the path secrets and the commit secret, checks ValSem203/204.

---

## Tasks

### Task 1: Vendor and pin the three vector families

**Files:**
- Create: `mls/testdata/vectors/tree-operations.json`, `mls/testdata/vectors/tree-validation.json`, `mls/testdata/vectors/treekem.json`, `mls/testdata/vectors/PINS.md`
- Test: `mls/tree_vectors_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `mls/testdata/vectors/PINS.md` recording the mlswg commit and per-file SHA-256; test helpers `treeVectorFile(t *testing.T, name string) []byte` and `treeHex(t *testing.T, s string) []byte` used by every later vector task in this plan.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_vectors_test.go
package mls

import (
    "crypto/sha256"
    "encoding/hex"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

// the mlswg files this plan verifies. the digests live in PINS.md, so bumping a
// vector is a reviewable diff rather than a silent re-download.
var treeVectorFiles = []string{
    "tree-operations.json",
    "tree-validation.json",
    "treekem.json",
}

func treeVectorFile(t *testing.T, name string) []byte {
    t.Helper()
    data, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
    if err != nil {
        t.Fatalf("read vector %s: %v", name, err)
    }
    return data
}

func treeHex(t *testing.T, s string) []byte {
    t.Helper()
    b, err := hex.DecodeString(s)
    if err != nil {
        t.Fatalf("bad hex %q: %v", s, err)
    }
    return b
}

func TestTreeVectorsArePinned(t *testing.T) {
    pins, err := os.ReadFile(filepath.Join("testdata", "vectors", "PINS.md"))
    if err != nil {
        t.Fatalf("read PINS.md: %v", err)
    }
    for _, name := range treeVectorFiles {
        sum := sha256.Sum256(treeVectorFile(t, name))
        digest := hex.EncodeToString(sum[:])
        if !strings.Contains(string(pins), name) {
            t.Fatalf("%s is not named in PINS.md", name)
        }
        if !strings.Contains(string(pins), digest) {
            t.Fatalf("%s digest %s is not recorded in PINS.md", name, digest)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestTreeVectorsArePinned -v`
Expected: FAIL with `read PINS.md: open testdata/vectors/PINS.md: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

Fetch the three files at the mlswg commit already recorded in `mls/interop/PINS.md` if that file
exists; otherwise pin `mlswg/mls-implementations` at the current `main` and record it. The files
live under `test-vectors/` in that repository.

```bash
MLSWG_COMMIT=$(git ls-remote https://github.com/mlswg/mls-implementations.git main | cut -f1)
mkdir -p mls/testdata/vectors
for f in tree-operations tree-validation treekem; do
  curl -fsSL "https://raw.githubusercontent.com/mlswg/mls-implementations/$MLSWG_COMMIT/test-vectors/$f.json" \
    -o "mls/testdata/vectors/$f.json"
done
{
  echo "# Vendored mlswg test vectors"
  echo
  echo "Source: https://github.com/mlswg/mls-implementations"
  echo "Commit: $MLSWG_COMMIT"
  echo
  echo "| File | SHA-256 |"
  echo "|---|---|"
  for f in tree-operations tree-validation treekem; do
    echo "| $f.json | $(sha256sum mls/testdata/vectors/$f.json | cut -d" " -f1) |"
  done
} > mls/testdata/vectors/PINS.md
```

If the Syntax-and-codec plan or the Validation plan already vendored these three files at a
different commit, keep theirs and regenerate `PINS.md` from the files on disk instead of
re-downloading. One pinned mlswg commit per repository, never two.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeVectorsArePinned -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/testdata/vectors mls/tree_vectors_test.go
git commit -m "test(mls): vendor and pin the tree-operations, tree-validation and treekem vectors"
```

---

### Task 2: Typed errors for the tree and TreeKEM

**Files:**
- Create: `mls/tree_errors.go`
- Test: `mls/tree_errors_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: the thirteen `error` values listed under `tree_errors.go` in the Produces block. These names are reserved by this plan; `errors.go` (Validation plan) must not redefine them.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_errors_test.go
package mls

import (
    "errors"
    "testing"
)

func TestTreeErrorsAreDistinctAndNamed(t *testing.T) {
    all := map[string]error{
        "ErrLeafIndexOutOfRange":      ErrLeafIndexOutOfRange,
        "ErrNodeIndexOutOfRange":      ErrNodeIndexOutOfRange,
        "ErrTreeMalformed":            ErrTreeMalformed,
        "ErrNodeTypeMismatch":         ErrNodeTypeMismatch,
        "ErrUnmergedLeavesNotSorted":  ErrUnmergedLeavesNotSorted,
        "ErrUnmergedLeafInconsistent": ErrUnmergedLeafInconsistent,
        "ErrParentHashMismatch":       ErrParentHashMismatch,
        "ErrTreeHashMismatch":         ErrTreeHashMismatch,
        "ErrLeafNodeSourceMismatch":   ErrLeafNodeSourceMismatch,
        "ErrLeafNodeLifetime":         ErrLeafNodeLifetime,
        "ErrLeafKeysExtensionInvalid": ErrLeafKeysExtensionInvalid,
        "ErrNoPathSecret":             ErrNoPathSecret,
        "ErrPathSecretMismatch":       ErrPathSecretMismatch,
    }
    seen := map[string]string{}
    for name, err := range all {
        if err == nil {
            t.Fatalf("%s is nil", name)
        }
        if prior, ok := seen[err.Error()]; ok {
            t.Fatalf("%s and %s share the message %q", name, prior, err.Error())
        }
        seen[err.Error()] = name
        wrapped := errors.Join(err, errors.New("context"))
        if !errors.Is(wrapped, err) {
            t.Fatalf("%s does not survive errors.Join", name)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestTreeErrorsAreDistinctAndNamed -v`
Expected: FAIL to compile with `undefined: ErrLeafIndexOutOfRange`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree_errors.go
package mls

import "errors"

// the ratchet tree and TreeKEM failures that carry no ValSem number. every
// ValSem-numbered error is defined once, in errors.go, and consumed here.
var (
    ErrLeafIndexOutOfRange      = errors.New("mls: leaf index out of range")
    ErrNodeIndexOutOfRange      = errors.New("mls: node index out of range")
    ErrTreeMalformed            = errors.New("mls: ratchet tree is malformed")
    ErrNodeTypeMismatch         = errors.New("mls: node type does not match its position in the tree")
    ErrUnmergedLeavesNotSorted  = errors.New("mls: unmerged leaves are not sorted and unique")
    ErrUnmergedLeafInconsistent = errors.New("mls: unmerged leaf is not consistent with the path to its parent")
    ErrParentHashMismatch       = errors.New("mls: parent hash does not verify")
    ErrTreeHashMismatch         = errors.New("mls: tree hash does not match the group context")
    ErrLeafNodeSourceMismatch   = errors.New("mls: leaf node source is wrong for this context")
    ErrLeafNodeLifetime         = errors.New("mls: leaf node lifetime is not current")
    ErrLeafKeysExtensionInvalid = errors.New("mls: urmessage_leaf_keys extension is invalid")
    ErrNoPathSecret             = errors.New("mls: no path secret is available for this node")
    ErrPathSecretMismatch       = errors.New("mls: path secret does not derive the node public key in the tree")
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeErrorsAreDistinctAndNamed -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_errors.go mls/tree_errors_test.go
git commit -m "feat(mls): typed errors for ratchet tree and TreeKEM failures"
```

---

### Task 3: Extension, Capabilities and RequiredCapabilities wire types

**Files:**
- Create: `mls/extension.go`
- Test: `mls/extension_test.go`

**Interfaces:**
- Consumes: `syntax.Writer`, `syntax.Reader`, `syntax.NewWriter`, `syntax.NewReader`, `syntax.ErrTrailingBytes` (Syntax and codec plan, wave 1); `CipherSuite`, `CipherSuiteX25519ChaCha20SHA256Ed25519` (Crypto plan, wave 1).
- Produces: `ProtocolVersion`, `CredentialType`, `ProposalType`, `ExtensionType` and their constants; `Extension`, `UnmarshalExtension`, `MarshalExtensions`, `UnmarshalExtensions`, `FindExtension`; `Capabilities` with `MarshalTo`, `UnmarshalCapabilities` and the five `Supports*` predicates; `RequiredCapabilities` with `Marshal` and `UnmarshalRequiredCapabilities`.

- [ ] **Step 1: Write the failing test**

```go
// mls/extension_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func TestExtensionRoundTrip(t *testing.T) {
    in := []Extension{
        {ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: []byte{0x00, 0x00, 0x00}},
        {ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: []byte("policy")},
        {ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: nil},
    }
    encoded, err := MarshalExtensions(in)
    if err != nil {
        t.Fatalf("MarshalExtensions: %v", err)
    }
    out, err := UnmarshalExtensions(syntax.NewReader(encoded))
    if err != nil {
        t.Fatalf("UnmarshalExtensions: %v", err)
    }
    if len(out) != len(in) {
        t.Fatalf("got %d extensions, want %d", len(out), len(in))
    }
    for i := range in {
        if out[i].ExtensionType != in[i].ExtensionType {
            t.Fatalf("extension %d type = %#x, want %#x", i, out[i].ExtensionType, in[i].ExtensionType)
        }
        if !bytes.Equal(out[i].ExtensionData, in[i].ExtensionData) {
            t.Fatalf("extension %d data = %x, want %x", i, out[i].ExtensionData, in[i].ExtensionData)
        }
    }
    reencoded, err := MarshalExtensions(out)
    if err != nil {
        t.Fatalf("re-MarshalExtensions: %v", err)
    }
    if !bytes.Equal(reencoded, encoded) {
        t.Fatalf("re-encode = %x, want %x", reencoded, encoded)
    }
    if _, ok := FindExtension(out, ExtensionTypeUrmessageGroupPolicy); !ok {
        t.Fatalf("FindExtension did not find urmessage_group_policy")
    }
    if _, ok := FindExtension(out, ExtensionTypeRatchetTree); ok {
        t.Fatalf("FindExtension found ratchet_tree, which is absent")
    }
}

func TestCapabilitiesRoundTripAndPredicates(t *testing.T) {
    in := Capabilities{
        Versions:     []ProtocolVersion{ProtocolVersionMLS10},
        CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20SHA256Ed25519},
        Extensions:   []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
        Proposals:    []ProposalType{},
        Credentials:  []CredentialType{CredentialTypeBasic},
    }
    w := syntax.NewWriter()
    if err := in.MarshalTo(w); err != nil {
        t.Fatalf("MarshalTo: %v", err)
    }
    out, err := UnmarshalCapabilities(syntax.NewReader(w.Bytes()))
    if err != nil {
        t.Fatalf("UnmarshalCapabilities: %v", err)
    }
    if !out.SupportsVersion(ProtocolVersionMLS10) {
        t.Fatalf("SupportsVersion(mls10) = false")
    }
    if !out.SupportsCipherSuite(CipherSuiteX25519ChaCha20SHA256Ed25519) {
        t.Fatalf("SupportsCipherSuite(0x0003) = false")
    }
    if !out.SupportsExtension(ExtensionTypeUrmessageLeafKeys) {
        t.Fatalf("SupportsExtension(0xF002) = false")
    }
    if out.SupportsExtension(ExtensionTypeUrmessageOwnerSuccessor) {
        t.Fatalf("SupportsExtension(0xF003) = true, want false")
    }
    if !out.SupportsCredential(CredentialTypeBasic) {
        t.Fatalf("SupportsCredential(basic) = false")
    }
}

func TestRequiredCapabilitiesRoundTrip(t *testing.T) {
    in := RequiredCapabilities{
        ExtensionTypes:  []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
        ProposalTypes:   nil,
        CredentialTypes: []CredentialType{CredentialTypeBasic},
    }
    encoded, err := in.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out, err := UnmarshalRequiredCapabilities(encoded)
    if err != nil {
        t.Fatalf("UnmarshalRequiredCapabilities: %v", err)
    }
    if len(out.ExtensionTypes) != 2 || out.ExtensionTypes[1] != ExtensionTypeUrmessageLeafKeys {
        t.Fatalf("extension types = %v", out.ExtensionTypes)
    }
    if len(out.ProposalTypes) != 0 {
        t.Fatalf("proposal types = %v, want empty", out.ProposalTypes)
    }
    if len(out.CredentialTypes) != 1 || out.CredentialTypes[0] != CredentialTypeBasic {
        t.Fatalf("credential types = %v", out.CredentialTypes)
    }
    if _, err := UnmarshalRequiredCapabilities(append(encoded, 0x00)); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestExtensionRoundTrip|TestCapabilities|TestRequiredCapabilities" -v`
Expected: FAIL to compile with `undefined: Extension`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/extension.go
package mls

import "github.com/urnetwork/connect/mls/syntax"

// RFC 9420 §7.2 and §12.4.3 registries. every one is uint16 and none is a closed
// set: GREASE values must parse and be ignored, never error.
type ProtocolVersion uint16
type CredentialType uint16
type ProposalType uint16
type ExtensionType uint16

const ProtocolVersionMLS10 ProtocolVersion = 0x0001

const CredentialTypeBasic CredentialType = 0x0001

const (
    ExtensionTypeRatchetTree             ExtensionType = 0x0002
    ExtensionTypeRequiredCapabilities    ExtensionType = 0x0003
    ExtensionTypeUrmessageGroupPolicy    ExtensionType = 0xF001
    ExtensionTypeUrmessageLeafKeys       ExtensionType = 0xF002
    ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003
)

// one entry of an extensions vector.
type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}

func (self *Extension) MarshalTo(w *syntax.Writer) error {
    w.WriteUint16(uint16(self.ExtensionType))
    w.WriteOpaqueVec(self.ExtensionData)
    return nil
}

func UnmarshalExtension(r *syntax.Reader) (Extension, error) {
    t, err := r.ReadUint16()
    if err != nil {
        return Extension{}, err
    }
    data, err := r.ReadOpaqueVec()
    if err != nil {
        return Extension{}, err
    }
    return Extension{ExtensionType: ExtensionType(t), ExtensionData: data}, nil
}

// the whole length-prefixed extensions vector, as it appears inside a LeafNode, a
// KeyPackage or a GroupContext.
func MarshalExtensions(exts []Extension) ([]byte, error) {
    inner := syntax.NewWriter()
    for i := range exts {
        if err := exts[i].MarshalTo(inner); err != nil {
            return nil, err
        }
    }
    w := syntax.NewWriter()
    w.WriteOpaqueVec(inner.Bytes())
    return w.Bytes(), nil
}

func UnmarshalExtensions(r *syntax.Reader) ([]Extension, error) {
    sub, err := r.ReadVecReader()
    if err != nil {
        return nil, err
    }
    exts := []Extension{}
    for !sub.Empty() {
        ext, err := UnmarshalExtension(sub)
        if err != nil {
            return nil, err
        }
        exts = append(exts, ext)
    }
    return exts, nil
}

func FindExtension(exts []Extension, t ExtensionType) ([]byte, bool) {
    for i := range exts {
        if exts[i].ExtensionType == t {
            return exts[i].ExtensionData, true
        }
    }
    return nil, false
}

// RFC 9420 §7.2. what the client behind a leaf node understands.
type Capabilities struct {
    Versions     []ProtocolVersion
    CipherSuites []CipherSuite
    Extensions   []ExtensionType
    Proposals    []ProposalType
    Credentials  []CredentialType
}

func writeUint16Vec[T ~uint16](w *syntax.Writer, values []T) {
    inner := syntax.NewWriter()
    for _, v := range values {
        inner.WriteUint16(uint16(v))
    }
    w.WriteOpaqueVec(inner.Bytes())
}

func readUint16Vec[T ~uint16](r *syntax.Reader) ([]T, error) {
    sub, err := r.ReadVecReader()
    if err != nil {
        return nil, err
    }
    out := []T{}
    for !sub.Empty() {
        v, err := sub.ReadUint16()
        if err != nil {
            return nil, err
        }
        out = append(out, T(v))
    }
    return out, nil
}

func (self *Capabilities) MarshalTo(w *syntax.Writer) error {
    writeUint16Vec(w, self.Versions)
    writeUint16Vec(w, self.CipherSuites)
    writeUint16Vec(w, self.Extensions)
    writeUint16Vec(w, self.Proposals)
    writeUint16Vec(w, self.Credentials)
    return nil
}

func UnmarshalCapabilities(r *syntax.Reader) (Capabilities, error) {
    var self Capabilities
    var err error
    if self.Versions, err = readUint16Vec[ProtocolVersion](r); err != nil {
        return Capabilities{}, err
    }
    if self.CipherSuites, err = readUint16Vec[CipherSuite](r); err != nil {
        return Capabilities{}, err
    }
    if self.Extensions, err = readUint16Vec[ExtensionType](r); err != nil {
        return Capabilities{}, err
    }
    if self.Proposals, err = readUint16Vec[ProposalType](r); err != nil {
        return Capabilities{}, err
    }
    if self.Credentials, err = readUint16Vec[CredentialType](r); err != nil {
        return Capabilities{}, err
    }
    return self, nil
}

func (self *Capabilities) SupportsVersion(v ProtocolVersion) bool {
    for _, x := range self.Versions {
        if x == v {
            return true
        }
    }
    return false
}

func (self *Capabilities) SupportsCipherSuite(s CipherSuite) bool {
    for _, x := range self.CipherSuites {
        if x == s {
            return true
        }
    }
    return false
}

// used for both the leaf's own extensions and the group's required ones.
func (self *Capabilities) SupportsExtension(t ExtensionType) bool {
    for _, x := range self.Extensions {
        if x == t {
            return true
        }
    }
    return false
}

func (self *Capabilities) SupportsProposal(t ProposalType) bool {
    for _, x := range self.Proposals {
        if x == t {
            return true
        }
    }
    return false
}

// the basic credential type is mandatory to implement, so it counts as supported
// whether or not the leaf lists it. RFC 9420 §7.2.
func (self *Capabilities) SupportsCredential(t CredentialType) bool {
    if t == CredentialTypeBasic {
        return true
    }
    for _, x := range self.Credentials {
        if x == t {
            return true
        }
    }
    return false
}

// required_capabilities, extension type 0x0003, carried in the group context.
type RequiredCapabilities struct {
    ExtensionTypes  []ExtensionType
    ProposalTypes   []ProposalType
    CredentialTypes []CredentialType
}

func (self *RequiredCapabilities) Marshal() ([]byte, error) {
    w := syntax.NewWriter()
    writeUint16Vec(w, self.ExtensionTypes)
    writeUint16Vec(w, self.ProposalTypes)
    writeUint16Vec(w, self.CredentialTypes)
    return w.Bytes(), nil
}

func UnmarshalRequiredCapabilities(data []byte) (RequiredCapabilities, error) {
    r := syntax.NewReader(data)
    var self RequiredCapabilities
    var err error
    if self.ExtensionTypes, err = readUint16Vec[ExtensionType](r); err != nil {
        return RequiredCapabilities{}, err
    }
    if self.ProposalTypes, err = readUint16Vec[ProposalType](r); err != nil {
        return RequiredCapabilities{}, err
    }
    if self.CredentialTypes, err = readUint16Vec[CredentialType](r); err != nil {
        return RequiredCapabilities{}, err
    }
    if !r.Empty() {
        return RequiredCapabilities{}, syntax.ErrTrailingBytes
    }
    return self, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestExtensionRoundTrip|TestCapabilities|TestRequiredCapabilities" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/extension.go mls/extension_test.go
git commit -m "feat(mls): Extension, Capabilities and RequiredCapabilities wire types"
```

---

### Task 4: The urmessage_leaf_keys extension (0xF002)

**Files:**
- Modify: `mls/extension.go`
- Test: `mls/extension_test.go`

**Interfaces:**
- Consumes: `syntax.Writer`, `syntax.Reader`, `syntax.ErrTrailingBytes` (Syntax plan); `ErrLeafKeysExtensionInvalid` (Task 2).
- Produces: `const AlgIdXwing uint16 = 0x0014`, `const XwingPublicKeyLen = 1216`, `LeafKeysExtension{AlgId uint16; DeviceXwingPub []byte}`, `func (self *LeafKeysExtension) Marshal() ([]byte, error)`, `func UnmarshalLeafKeysExtension(data []byte) (LeafKeysExtension, error)`. `connect/message`'s `wrap.go` reads this off every leaf to find each device's X-Wing wrap target.

- [ ] **Step 1: Write the failing test**

```go
// mls/extension_test.go (append)

func TestLeafKeysExtensionRoundTrip(t *testing.T) {
    pub := make([]byte, XwingPublicKeyLen)
    for i := range pub {
        pub[i] = byte(i)
    }
    in := LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: pub}
    encoded, err := in.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out, err := UnmarshalLeafKeysExtension(encoded)
    if err != nil {
        t.Fatalf("UnmarshalLeafKeysExtension: %v", err)
    }
    if out.AlgId != AlgIdXwing {
        t.Fatalf("alg_id = %#x, want %#x", out.AlgId, AlgIdXwing)
    }
    if !bytes.Equal(out.DeviceXwingPub, pub) {
        t.Fatalf("device_xwing_pub mismatch")
    }
}

func TestLeafKeysExtensionRejectsWrongLength(t *testing.T) {
    short := LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: make([]byte, XwingPublicKeyLen-1)}
    if _, err := short.Marshal(); !errors.Is(err, ErrLeafKeysExtensionInvalid) {
        t.Fatalf("Marshal short key err = %v, want ErrLeafKeysExtensionInvalid", err)
    }
    good := LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: make([]byte, XwingPublicKeyLen)}
    encoded, err := good.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if _, err := UnmarshalLeafKeysExtension(encoded[:len(encoded)-1]); err == nil {
        t.Fatalf("UnmarshalLeafKeysExtension(truncated) = nil error, want failure")
    }
    trailing := append(append([]byte{}, encoded...), 0x00)
    if _, err := UnmarshalLeafKeysExtension(trailing); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("UnmarshalLeafKeysExtension(trailing) err = %v, want ErrTrailingBytes", err)
    }
}

func TestLeafKeysExtensionRejectsUnimplementedAlg(t *testing.T) {
    // 0x0013 is reserved for hybrid X25519 + ML-KEM-1024 and is not implemented in
    // v1. MASTER §7.1. it must be refused, not carried.
    in := LeafKeysExtension{AlgId: 0x0013, DeviceXwingPub: make([]byte, XwingPublicKeyLen)}
    if _, err := in.Marshal(); !errors.Is(err, ErrLeafKeysExtensionInvalid) {
        t.Fatalf("Marshal alg 0x0013 err = %v, want ErrLeafKeysExtensionInvalid", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestLeafKeysExtension -v`
Expected: FAIL to compile with `undefined: XwingPublicKeyLen`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/extension.go (append)

// MASTER §7.1: alg_id 0x0014 is X-Wing (X25519 + ML-KEM-768), the v1 wrap KEM.
// 0x0012 and 0x0013 are reserved and unimplemented, so they are refused here.
const AlgIdXwing uint16 = 0x0014

// the X-Wing public key length at ML-KEM-768: 1184 bytes of ML-KEM plus 32 of X25519.
const XwingPublicKeyLen = 1216

// urmessage_leaf_keys, extension type 0xF002. MASTER §5.3. it rides in the LeafNode
// so it is covered by the leaf signature and the tree hash, is validated by
// RFC 9420 §7.3, and is removed by Remove along with the rest of the leaf.
type LeafKeysExtension struct {
    AlgId          uint16
    DeviceXwingPub []byte
}

func (self *LeafKeysExtension) Marshal() ([]byte, error) {
    if self.AlgId != AlgIdXwing {
        return nil, ErrLeafKeysExtensionInvalid
    }
    if len(self.DeviceXwingPub) != XwingPublicKeyLen {
        return nil, ErrLeafKeysExtensionInvalid
    }
    w := syntax.NewWriter()
    w.WriteUint16(self.AlgId)
    w.WriteOpaqueVec(self.DeviceXwingPub)
    return w.Bytes(), nil
}

func UnmarshalLeafKeysExtension(data []byte) (LeafKeysExtension, error) {
    r := syntax.NewReader(data)
    algId, err := r.ReadUint16()
    if err != nil {
        return LeafKeysExtension{}, err
    }
    pub, err := r.ReadOpaqueVec()
    if err != nil {
        return LeafKeysExtension{}, err
    }
    if !r.Empty() {
        return LeafKeysExtension{}, syntax.ErrTrailingBytes
    }
    if algId != AlgIdXwing || len(pub) != XwingPublicKeyLen {
        return LeafKeysExtension{}, ErrLeafKeysExtensionInvalid
    }
    return LeafKeysExtension{AlgId: algId, DeviceXwingPub: pub}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestLeafKeysExtension -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/extension.go mls/extension_test.go
git commit -m "feat(mls): urmessage_leaf_keys leaf extension carrying the X-Wing device key"
```

---

### Task 5: LeafNode structure and codec

**Files:**
- Create: `mls/leaf_node.go`
- Test: `mls/leaf_node_test.go`

**Interfaces:**
- Consumes: `syntax.*` (Syntax plan); `Credential`, `UnmarshalCredential` (Syntax plan, `credential.go`); `HpkePublicKey`, `SignaturePublicKey` (Crypto plan); `Extension`, `Capabilities` (Task 3); `ErrTreeMalformed` (Task 2).
- Produces: `LeafNodeSource` with `LeafNodeSourceKeyPackage/Update/Commit`; `Lifetime`; `LeafNode`; `func (self *LeafNode) MarshalTo(w *syntax.Writer) error`; `func (self *LeafNode) Marshal() ([]byte, error)`; `func UnmarshalLeafNode(r *syntax.Reader) (*LeafNode, error)`; `func ParseLeafNode(data []byte) (*LeafNode, error)`; `func (self *LeafNode) Clone() *LeafNode`.

- [ ] **Step 1: Write the failing test**

```go
// mls/leaf_node_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func testLeafNodeTemplate() *LeafNode {
    return &LeafNode{
        EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0x11}, 32)),
        SignatureKey:  SignaturePublicKey(bytes.Repeat([]byte{0x22}, 32)),
        Credential:    Credential{CredentialType: CredentialTypeBasic, Identity: []byte("alice")},
        Capabilities: Capabilities{
            Versions:     []ProtocolVersion{ProtocolVersionMLS10},
            CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20SHA256Ed25519},
            Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
            Credentials:  []CredentialType{CredentialTypeBasic},
        },
        Extensions: []Extension{{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: []byte("k")}},
        Signature:  bytes.Repeat([]byte{0x33}, 64),
    }
}

func TestLeafNodeRoundTripEverySource(t *testing.T) {
    cases := []struct {
        name  string
        build func() *LeafNode
    }{
        {"key_package", func() *LeafNode {
            leaf := testLeafNodeTemplate()
            leaf.LeafNodeSource = LeafNodeSourceKeyPackage
            leaf.Lifetime = Lifetime{NotBefore: 1000, NotAfter: 2000}
            return leaf
        }},
        {"update", func() *LeafNode {
            leaf := testLeafNodeTemplate()
            leaf.LeafNodeSource = LeafNodeSourceUpdate
            return leaf
        }},
        {"commit", func() *LeafNode {
            leaf := testLeafNodeTemplate()
            leaf.LeafNodeSource = LeafNodeSourceCommit
            leaf.ParentHash = bytes.Repeat([]byte{0x44}, 32)
            return leaf
        }},
    }
    for _, c := range cases {
        in := c.build()
        encoded, err := in.Marshal()
        if err != nil {
            t.Fatalf("%s Marshal: %v", c.name, err)
        }
        out, err := ParseLeafNode(encoded)
        if err != nil {
            t.Fatalf("%s ParseLeafNode: %v", c.name, err)
        }
        reencoded, err := out.Marshal()
        if err != nil {
            t.Fatalf("%s re-Marshal: %v", c.name, err)
        }
        if !bytes.Equal(reencoded, encoded) {
            t.Fatalf("%s re-encode = %x, want %x", c.name, reencoded, encoded)
        }
        if out.LeafNodeSource != in.LeafNodeSource {
            t.Fatalf("%s source = %d, want %d", c.name, out.LeafNodeSource, in.LeafNodeSource)
        }
        if !bytes.Equal(out.ParentHash, in.ParentHash) {
            t.Fatalf("%s parent hash = %x, want %x", c.name, out.ParentHash, in.ParentHash)
        }
        if out.Lifetime != in.Lifetime {
            t.Fatalf("%s lifetime = %+v, want %+v", c.name, out.Lifetime, in.Lifetime)
        }
    }
}

func TestLeafNodeRejectsUnknownSourceAndTrailingBytes(t *testing.T) {
    leaf := testLeafNodeTemplate()
    leaf.LeafNodeSource = LeafNodeSourceUpdate
    encoded, err := leaf.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if _, err := ParseLeafNode(append(encoded, 0x00)); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
    leaf.LeafNodeSource = LeafNodeSource(9)
    if _, err := leaf.Marshal(); !errors.Is(err, ErrTreeMalformed) {
        t.Fatalf("Marshal unknown source err = %v, want ErrTreeMalformed", err)
    }
}

func TestLeafNodeCloneIsDeep(t *testing.T) {
    in := testLeafNodeTemplate()
    in.LeafNodeSource = LeafNodeSourceCommit
    in.ParentHash = bytes.Repeat([]byte{0x44}, 32)
    out := in.Clone()
    out.ParentHash[0] = 0xFF
    out.Extensions[0].ExtensionData[0] = 0xFF
    out.Capabilities.Extensions[0] = ExtensionTypeRatchetTree
    if in.ParentHash[0] == 0xFF {
        t.Fatalf("Clone shares the parent hash backing array")
    }
    if in.Extensions[0].ExtensionData[0] == 0xFF {
        t.Fatalf("Clone shares extension data")
    }
    if in.Capabilities.Extensions[0] == ExtensionTypeRatchetTree {
        t.Fatalf("Clone shares the capabilities extension slice")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestLeafNode -v`
Expected: FAIL to compile with `undefined: LeafNode`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/leaf_node.go
package mls

import "github.com/urnetwork/connect/mls/syntax"

// RFC 9420 §7.2. which of the three ways this leaf entered the tree, and therefore
// which variant fields are present and what the signature covers.
type LeafNodeSource uint8

const (
    LeafNodeSourceKeyPackage LeafNodeSource = 1
    LeafNodeSourceUpdate     LeafNodeSource = 2
    LeafNodeSourceCommit     LeafNodeSource = 3
)

// present only when the source is key_package. seconds since the unix epoch.
type Lifetime struct {
    NotBefore uint64
    NotAfter  uint64
}

// RFC 9420 §7.2. one device's presence in the ratchet tree.
type LeafNode struct {
    EncryptionKey  HpkePublicKey
    SignatureKey   SignaturePublicKey
    Credential     Credential
    Capabilities   Capabilities
    LeafNodeSource LeafNodeSource
    Lifetime       Lifetime
    ParentHash     []byte
    Extensions     []Extension
    Signature      []byte
}

// the fields common to LeafNode and LeafNodeTBS, up to and including extensions.
func (self *LeafNode) marshalCore(w *syntax.Writer) error {
    w.WriteOpaqueVec(self.EncryptionKey)
    w.WriteOpaqueVec(self.SignatureKey)
    if err := self.Credential.MarshalTo(w); err != nil {
        return err
    }
    if err := self.Capabilities.MarshalTo(w); err != nil {
        return err
    }
    w.WriteUint8(uint8(self.LeafNodeSource))
    switch self.LeafNodeSource {
    case LeafNodeSourceKeyPackage:
        w.WriteUint64(self.Lifetime.NotBefore)
        w.WriteUint64(self.Lifetime.NotAfter)
    case LeafNodeSourceUpdate:
        // empty struct
    case LeafNodeSourceCommit:
        w.WriteOpaqueVec(self.ParentHash)
    default:
        return ErrTreeMalformed
    }
    exts, err := MarshalExtensions(self.Extensions)
    if err != nil {
        return err
    }
    w.WriteBytes(exts)
    return nil
}

func (self *LeafNode) MarshalTo(w *syntax.Writer) error {
    if err := self.marshalCore(w); err != nil {
        return err
    }
    w.WriteOpaqueVec(self.Signature)
    return nil
}

func (self *LeafNode) Marshal() ([]byte, error) {
    w := syntax.NewWriter()
    if err := self.MarshalTo(w); err != nil {
        return nil, err
    }
    return w.Bytes(), nil
}

func unmarshalLeafNodeCore(r *syntax.Reader, self *LeafNode) error {
    encryptionKey, err := r.ReadOpaqueVec()
    if err != nil {
        return err
    }
    signatureKey, err := r.ReadOpaqueVec()
    if err != nil {
        return err
    }
    credential, err := UnmarshalCredential(r)
    if err != nil {
        return err
    }
    capabilities, err := UnmarshalCapabilities(r)
    if err != nil {
        return err
    }
    source, err := r.ReadUint8()
    if err != nil {
        return err
    }
    self.EncryptionKey = HpkePublicKey(encryptionKey)
    self.SignatureKey = SignaturePublicKey(signatureKey)
    self.Credential = credential
    self.Capabilities = capabilities
    self.LeafNodeSource = LeafNodeSource(source)
    switch self.LeafNodeSource {
    case LeafNodeSourceKeyPackage:
        if self.Lifetime.NotBefore, err = r.ReadUint64(); err != nil {
            return err
        }
        if self.Lifetime.NotAfter, err = r.ReadUint64(); err != nil {
            return err
        }
    case LeafNodeSourceUpdate:
        // empty struct
    case LeafNodeSourceCommit:
        if self.ParentHash, err = r.ReadOpaqueVec(); err != nil {
            return err
        }
    default:
        return ErrTreeMalformed
    }
    if self.Extensions, err = UnmarshalExtensions(r); err != nil {
        return err
    }
    return nil
}

func UnmarshalLeafNode(r *syntax.Reader) (*LeafNode, error) {
    self := &LeafNode{}
    if err := unmarshalLeafNodeCore(r, self); err != nil {
        return nil, err
    }
    signature, err := r.ReadOpaqueVec()
    if err != nil {
        return nil, err
    }
    self.Signature = signature
    return self, nil
}

func ParseLeafNode(data []byte) (*LeafNode, error) {
    r := syntax.NewReader(data)
    self, err := UnmarshalLeafNode(r)
    if err != nil {
        return nil, err
    }
    if !r.Empty() {
        return nil, syntax.ErrTrailingBytes
    }
    return self, nil
}

func cloneBytes(b []byte) []byte {
    if b == nil {
        return nil
    }
    out := make([]byte, len(b))
    copy(out, b)
    return out
}

func cloneSlice[T any](in []T) []T {
    if in == nil {
        return nil
    }
    out := make([]T, len(in))
    copy(out, in)
    return out
}

// a leaf is copied whenever it is re-signed or installed in a provisional tree, so
// nothing may alias between two epochs' trees.
func (self *LeafNode) Clone() *LeafNode {
    out := *self
    out.EncryptionKey = HpkePublicKey(cloneBytes(self.EncryptionKey))
    out.SignatureKey = SignaturePublicKey(cloneBytes(self.SignatureKey))
    out.Credential.Identity = cloneBytes(self.Credential.Identity)
    out.Capabilities.Versions = cloneSlice(self.Capabilities.Versions)
    out.Capabilities.CipherSuites = cloneSlice(self.Capabilities.CipherSuites)
    out.Capabilities.Extensions = cloneSlice(self.Capabilities.Extensions)
    out.Capabilities.Proposals = cloneSlice(self.Capabilities.Proposals)
    out.Capabilities.Credentials = cloneSlice(self.Capabilities.Credentials)
    out.ParentHash = cloneBytes(self.ParentHash)
    out.Signature = cloneBytes(self.Signature)
    out.Extensions = cloneSlice(self.Extensions)
    for i := range out.Extensions {
        out.Extensions[i].ExtensionData = cloneBytes(self.Extensions[i].ExtensionData)
    }
    return &out
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestLeafNode -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/leaf_node.go mls/leaf_node_test.go
git commit -m "feat(mls): LeafNode structure and byte-exact codec for all three sources"
```

---

### Task 6: LeafNodeTBS, signing and signature verification

**Files:**
- Modify: `mls/leaf_node.go`
- Test: `mls/leaf_node_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.SignWithLabel`, `CryptoProvider.VerifyWithLabel`, `CryptoProvider.SignatureKeyPair`, `NewCryptoProvider` (Crypto plan); `ErrBadSignature` (Validation plan, `errors.go`).
- Produces: `func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey, groupId []byte, leafIndex LeafIndex) error` and `func (self *LeafNode) VerifySignature(crypto CryptoProvider, groupId []byte, leafIndex LeafIndex) error`. `groupId` and `leafIndex` are ignored for `key_package`-source leaves and are covered by the signature for `update` and `commit` sources, per RFC 9420 §7.2.

- [ ] **Step 1: Write the failing test**

```go
// mls/leaf_node_test.go (append)

func TestLeafNodeSignVerifyKeyPackageSourceIgnoresIndex(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    signerPriv, signerPub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("SignatureKeyPair: %v", err)
    }
    leaf := testLeafNodeTemplate()
    leaf.SignatureKey = signerPub
    leaf.LeafNodeSource = LeafNodeSourceKeyPackage
    leaf.Lifetime = Lifetime{NotBefore: 0, NotAfter: 1 << 40}
    if err := leaf.Sign(crypto, signerPriv, []byte("group"), LeafIndex(3)); err != nil {
        t.Fatalf("Sign: %v", err)
    }
    // a key_package leaf is not bound to a group or a position, so a different
    // group id and index still verify.
    if err := leaf.VerifySignature(crypto, []byte("other"), LeafIndex(7)); err != nil {
        t.Fatalf("VerifySignature with other context: %v", err)
    }
}

func TestLeafNodeCommitSourceBindsGroupIdAndLeafIndex(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    signerPriv, signerPub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("SignatureKeyPair: %v", err)
    }
    leaf := testLeafNodeTemplate()
    leaf.SignatureKey = signerPub
    leaf.LeafNodeSource = LeafNodeSourceCommit
    leaf.ParentHash = bytes.Repeat([]byte{0x44}, 32)
    if err := leaf.Sign(crypto, signerPriv, []byte("group"), LeafIndex(3)); err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := leaf.VerifySignature(crypto, []byte("group"), LeafIndex(3)); err != nil {
        t.Fatalf("VerifySignature: %v", err)
    }
    if err := leaf.VerifySignature(crypto, []byte("group"), LeafIndex(4)); !errors.Is(err, ErrBadSignature) {
        t.Fatalf("wrong leaf index err = %v, want ErrBadSignature", err)
    }
    if err := leaf.VerifySignature(crypto, []byte("other"), LeafIndex(3)); !errors.Is(err, ErrBadSignature) {
        t.Fatalf("wrong group id err = %v, want ErrBadSignature", err)
    }
}

func TestLeafNodeSignatureCoversEveryField(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    signerPriv, signerPub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("SignatureKeyPair: %v", err)
    }
    mutations := map[string]func(leaf *LeafNode){
        "encryption_key": func(leaf *LeafNode) { leaf.EncryptionKey[0] ^= 0xFF },
        "credential":     func(leaf *LeafNode) { leaf.Credential.Identity = []byte("mallory") },
        "capabilities":   func(leaf *LeafNode) { leaf.Capabilities.Extensions = nil },
        "parent_hash":    func(leaf *LeafNode) { leaf.ParentHash[0] ^= 0xFF },
        "extensions":     func(leaf *LeafNode) { leaf.Extensions = nil },
    }
    for name, mutate := range mutations {
        leaf := testLeafNodeTemplate()
        leaf.SignatureKey = signerPub
        leaf.LeafNodeSource = LeafNodeSourceCommit
        leaf.ParentHash = bytes.Repeat([]byte{0x44}, 32)
        if err := leaf.Sign(crypto, signerPriv, []byte("group"), LeafIndex(1)); err != nil {
            t.Fatalf("%s Sign: %v", name, err)
        }
        mutate(leaf)
        if err := leaf.VerifySignature(crypto, []byte("group"), LeafIndex(1)); !errors.Is(err, ErrBadSignature) {
            t.Fatalf("mutating %s: err = %v, want ErrBadSignature", name, err)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestLeafNodeSign|TestLeafNodeCommitSource|TestLeafNodeSignature" -v`
Expected: FAIL to compile with `leaf.Sign undefined (type *LeafNode has no field or method Sign)`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/leaf_node.go (append)

// RFC 9420 §7.2. the signature label for every leaf node.
const leafNodeSignatureLabel = "LeafNodeTBS"

// LeafNodeTBS is the leaf's core fields, followed by the group id and leaf index for
// update and commit sources only. binding the index is what stops a leaf being
// replayed into a different position in the tree.
func (self *LeafNode) signatureContent(groupId []byte, leafIndex LeafIndex) ([]byte, error) {
    w := syntax.NewWriter()
    if err := self.marshalCore(w); err != nil {
        return nil, err
    }
    switch self.LeafNodeSource {
    case LeafNodeSourceKeyPackage:
        // no context: a KeyPackage is not yet bound to a group or a position
    case LeafNodeSourceUpdate, LeafNodeSourceCommit:
        w.WriteOpaqueVec(groupId)
        w.WriteUint32(uint32(leafIndex))
    default:
        return nil, ErrTreeMalformed
    }
    return w.Bytes(), nil
}

func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey,
    groupId []byte, leafIndex LeafIndex) error {
    content, err := self.signatureContent(groupId, leafIndex)
    if err != nil {
        return err
    }
    signature, err := crypto.SignWithLabel(signer, leafNodeSignatureLabel, content)
    if err != nil {
        return err
    }
    self.Signature = signature
    return nil
}

func (self *LeafNode) VerifySignature(crypto CryptoProvider,
    groupId []byte, leafIndex LeafIndex) error {
    content, err := self.signatureContent(groupId, leafIndex)
    if err != nil {
        return err
    }
    if err := crypto.VerifyWithLabel(self.SignatureKey, leafNodeSignatureLabel,
        content, self.Signature); err != nil {
        return ErrBadSignature
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestLeafNodeSign|TestLeafNodeCommitSource|TestLeafNodeSignature" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/leaf_node.go mls/leaf_node_test.go
git commit -m "feat(mls): LeafNodeTBS signing and verification bound to group id and leaf index"
```

---

### Task 7: LeafNode validation (RFC 9420 §7.3) and erratum 8745

**Files:**
- Modify: `mls/leaf_node.go`, `mls/ERRATA.md`
- Test: `mls/leaf_node_test.go`

**Interfaces:**
- Consumes: `ErrBadSignature`, `ErrMissingRequiredCapability` (Validation plan, `errors.go`); `ErrLeafNodeSourceMismatch`, `ErrLeafNodeLifetime` (Task 2).
- Produces: `LeafValidationContext{Crypto, Suite, GroupId, LeafIndex, ExpectedSource, RequiredCaps, GroupExtensions, NowMs, ClockSkewMs}` and `func (self *LeafNode) Validate(ctx *LeafValidationContext) error`. `tree_sync.go` (Task 23) calls it once per non-blank leaf; `key_package.go` (Group lifecycle plan) calls it with `ExpectedSource = LeafNodeSourceKeyPackage`; `proposal.go` calls it with `LeafNodeSourceUpdate`.

Erratum 8745 (RFC 9420 §13.4) adds the requirement that a leaf replaced by an Update proposal or by
a commit's update path is checked for group-extension support, not only a leaf arriving in an Add.
The pre-erratum reading checks it on `key_package` sources alone. `Validate` applies the check on
all three sources; `TestErrata8745` asserts both halves.

- [ ] **Step 1: Write the failing test**

```go
// mls/leaf_node_test.go (append)

func signedTestLeaf(t *testing.T, crypto CryptoProvider, source LeafNodeSource,
    mutate func(leaf *LeafNode)) (*LeafNode, SignaturePrivateKey) {
    t.Helper()
    signerPriv, signerPub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("SignatureKeyPair: %v", err)
    }
    leaf := testLeafNodeTemplate()
    leaf.SignatureKey = signerPub
    leaf.LeafNodeSource = source
    switch source {
    case LeafNodeSourceKeyPackage:
        leaf.Lifetime = Lifetime{NotBefore: 0, NotAfter: 1 << 40}
    case LeafNodeSourceCommit:
        leaf.ParentHash = bytes.Repeat([]byte{0x44}, 32)
    }
    if mutate != nil {
        mutate(leaf)
    }
    if err := leaf.Sign(crypto, signerPriv, []byte("group"), LeafIndex(1)); err != nil {
        t.Fatalf("Sign: %v", err)
    }
    return leaf, signerPriv
}

func testLeafValidationContext(crypto CryptoProvider, source LeafNodeSource) *LeafValidationContext {
    return &LeafValidationContext{
        Crypto:         crypto,
        Suite:          CipherSuiteX25519ChaCha20SHA256Ed25519,
        GroupId:        []byte("group"),
        LeafIndex:      LeafIndex(1),
        ExpectedSource: source,
        RequiredCaps: &RequiredCapabilities{
            ExtensionTypes:  []ExtensionType{ExtensionTypeUrmessageLeafKeys},
            CredentialTypes: []CredentialType{CredentialTypeBasic},
        },
        GroupExtensions: []Extension{
            {ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: []byte("x")},
        },
        NowMs:       1000,
        ClockSkewMs: 3600000,
    }
}

func TestLeafNodeValidateAcceptsAGoodLeaf(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    leaf, _ := signedTestLeaf(t, crypto, LeafNodeSourceCommit, nil)
    if err := leaf.Validate(testLeafValidationContext(crypto, LeafNodeSourceCommit)); err != nil {
        t.Fatalf("Validate: %v", err)
    }
}

func TestLeafNodeValidateRejectsWrongSource(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    leaf, _ := signedTestLeaf(t, crypto, LeafNodeSourceUpdate, nil)
    ctx := testLeafValidationContext(crypto, LeafNodeSourceCommit)
    if err := leaf.Validate(ctx); !errors.Is(err, ErrLeafNodeSourceMismatch) {
        t.Fatalf("err = %v, want ErrLeafNodeSourceMismatch", err)
    }
}

func TestLeafNodeValidateRejectsExpiredLifetime(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    leaf, _ := signedTestLeaf(t, crypto, LeafNodeSourceKeyPackage, func(leaf *LeafNode) {
        leaf.Lifetime = Lifetime{NotBefore: 0, NotAfter: 10}
    })
    ctx := testLeafValidationContext(crypto, LeafNodeSourceKeyPackage)
    ctx.NowMs = 100_000_000
    if err := leaf.Validate(ctx); !errors.Is(err, ErrLeafNodeLifetime) {
        t.Fatalf("err = %v, want ErrLeafNodeLifetime", err)
    }
    // within the one-hour skew tolerance the same leaf is accepted. Spec A §3.1.
    ctx.NowMs = 10_000 + 1_000
    if err := leaf.Validate(ctx); err != nil {
        t.Fatalf("Validate inside skew: %v", err)
    }
}

func TestLeafNodeValidateRejectsMissingRequiredCapability(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    leaf, _ := signedTestLeaf(t, crypto, LeafNodeSourceCommit, func(leaf *LeafNode) {
        leaf.Capabilities.Extensions = nil
        leaf.Extensions = nil
    })
    ctx := testLeafValidationContext(crypto, LeafNodeSourceCommit)
    ctx.GroupExtensions = nil
    if err := leaf.Validate(ctx); !errors.Is(err, ErrMissingRequiredCapability) {
        t.Fatalf("err = %v, want ErrMissingRequiredCapability", err)
    }
}

func TestLeafNodeValidateRejectsUnsupportedOwnExtension(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    // the leaf carries 0xF003 but does not claim to support it.
    leaf, _ := signedTestLeaf(t, crypto, LeafNodeSourceCommit, func(leaf *LeafNode) {
        leaf.Extensions = append(leaf.Extensions,
            Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: []byte("s")})
    })
    ctx := testLeafValidationContext(crypto, LeafNodeSourceCommit)
    if err := leaf.Validate(ctx); !errors.Is(err, ErrMissingRequiredCapability) {
        t.Fatalf("err = %v, want ErrMissingRequiredCapability", err)
    }
}

func TestErrata8745(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    // the corrected behaviour: a leaf arriving by Update or by a commit path is
    // checked against the group context extensions, not only a leaf arriving by Add.
    for _, source := range []LeafNodeSource{
        LeafNodeSourceKeyPackage, LeafNodeSourceUpdate, LeafNodeSourceCommit,
    } {
        leaf, _ := signedTestLeaf(t, crypto, source, func(leaf *LeafNode) {
            leaf.Capabilities.Extensions = []ExtensionType{ExtensionTypeUrmessageLeafKeys}
        })
        ctx := testLeafValidationContext(crypto, source)
        ctx.RequiredCaps = nil
        ctx.GroupExtensions = []Extension{
            {ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: []byte("p")},
        }
        if err := leaf.Validate(ctx); !errors.Is(err, ErrMissingRequiredCapability) {
            t.Fatalf("source %d: err = %v, want ErrMissingRequiredCapability "+
                "(erratum 8745: the pre-erratum reading skipped this for update and commit)", source, err)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestLeafNodeValidate|TestErrata8745" -v`
Expected: FAIL to compile with `undefined: LeafValidationContext`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/leaf_node.go (append)

// everything RFC 9420 §7.3 checks about a single leaf. the tree-wide checks —
// duplicate keys and parent hashes — are in tree_sync.go, because they are
// properties of the tree rather than of the leaf.
type LeafValidationContext struct {
    Crypto          CryptoProvider
    Suite           CipherSuite
    GroupId         []byte
    LeafIndex       LeafIndex
    ExpectedSource  LeafNodeSource
    RequiredCaps    *RequiredCapabilities
    GroupExtensions []Extension
    NowMs           uint64
    ClockSkewMs     uint64
}

func (self *LeafNode) Validate(ctx *LeafValidationContext) error {
    if self.LeafNodeSource != ctx.ExpectedSource {
        return ErrLeafNodeSourceMismatch
    }
    if err := self.VerifySignature(ctx.Crypto, ctx.GroupId, ctx.LeafIndex); err != nil {
        return err
    }
    if !self.Capabilities.SupportsCredential(self.Credential.CredentialType) {
        return ErrMissingRequiredCapability
    }
    // a leaf must claim support for every extension it carries.
    for i := range self.Extensions {
        if !self.Capabilities.SupportsExtension(self.Extensions[i].ExtensionType) {
            return ErrMissingRequiredCapability
        }
    }
    // RFC 9420 errata 8745: the same check applies to a leaf that arrives by Update
    // or in a commit's update path, not only to one that arrives in an Add.
    for i := range ctx.GroupExtensions {
        t := ctx.GroupExtensions[i].ExtensionType
        if t == ExtensionTypeRatchetTree || t == ExtensionTypeRequiredCapabilities {
            continue
        }
        if !self.Capabilities.SupportsExtension(t) {
            return ErrMissingRequiredCapability
        }
    }
    if ctx.RequiredCaps != nil {
        for _, t := range ctx.RequiredCaps.ExtensionTypes {
            if !self.Capabilities.SupportsExtension(t) {
                return ErrMissingRequiredCapability
            }
        }
        for _, t := range ctx.RequiredCaps.ProposalTypes {
            if !self.Capabilities.SupportsProposal(t) {
                return ErrMissingRequiredCapability
            }
        }
        for _, t := range ctx.RequiredCaps.CredentialTypes {
            if !self.Capabilities.SupportsCredential(t) {
                return ErrMissingRequiredCapability
            }
        }
    }
    if self.LeafNodeSource == LeafNodeSourceKeyPackage && ctx.NowMs != 0 {
        nowSeconds := ctx.NowMs / 1000
        skewSeconds := ctx.ClockSkewMs / 1000
        if nowSeconds+skewSeconds < self.Lifetime.NotBefore {
            return ErrLeafNodeLifetime
        }
        if self.Lifetime.NotAfter+skewSeconds < nowSeconds {
            return ErrLeafNodeLifetime
        }
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestLeafNodeValidate|TestErrata8745" -v`
Expected: PASS

Then append the erratum to `mls/ERRATA.md`, quoting it verbatim from
`https://errata.rfc-editor.org/rfc9420` (Spec A §4.3 open item 11 requires the verbatim
transcription, and the diff review verifies it against the errata page). Record the errata-page
retrieval date alongside the quote. Erratum 8815 belongs to the Group lifecycle plan, not here.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/leaf_node.go mls/leaf_node_test.go mls/ERRATA.md
git commit -m "feat(mls): RFC 9420 section 7.3 leaf node validation with erratum 8745"
```

---

### Task 8: ParentNode, Node and the RatchetTree container

**Files:**
- Create: `mls/tree.go`
- Test: `mls/tree_test.go`

**Interfaces:**
- Consumes: `LeafIndex`, `NodeIndex`, `NodeWidth`, `Root`, `Left`, `Right`, `Parent`, `Sibling`, `DirectPath`, `Level`, `NodeIndex.IsLeaf`, `LeafIndex.NodeIndex`, `NodeIndex.LeafIndex` (Tree math plan, wave 1); `syntax.*`; `HpkePublicKey`, `SignaturePublicKey` (Crypto plan); `LeafNode` (Task 5); `ErrLeafIndexOutOfRange`, `ErrNodeIndexOutOfRange`, `ErrTreeMalformed`, `ErrNodeTypeMismatch` (Task 2).
- Produces: `NodeType` with `NodeTypeLeaf`/`NodeTypeParent`; `ParentNode` with `MarshalTo`, `UnmarshalParentNode`, `Clone`; `Node`; `RatchetTree` with `NewRatchetTree`, `LeafWidth`, `NodeWidth`, `Get`, `Leaf`, `ParentAt`, `SetLeaf`, `SetParent`, `Blank`, `BlankDirectPath`, `Clone`, `Members`, `MemberCount`, `FindLeafBySignatureKey`.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"
)

func TestRatchetTreeGrowsByDoubling(t *testing.T) {
    tree := NewRatchetTree()
    if tree.LeafWidth() != 1 || tree.NodeWidth() != 1 {
        t.Fatalf("empty tree width = (%d, %d), want (1, 1)", tree.LeafWidth(), tree.NodeWidth())
    }
    for i := uint32(0); i < 5; i++ {
        leaf := testLeafNodeTemplate()
        leaf.LeafNodeSource = LeafNodeSourceUpdate
        if err := tree.SetLeaf(LeafIndex(i), leaf); err != nil {
            t.Fatalf("SetLeaf(%d): %v", i, err)
        }
    }
    if tree.LeafWidth() != 8 {
        t.Fatalf("leaf width = %d, want 8", tree.LeafWidth())
    }
    if tree.NodeWidth() != 15 {
        t.Fatalf("node width = %d, want 15", tree.NodeWidth())
    }
    if tree.MemberCount() != 5 {
        t.Fatalf("member count = %d, want 5", tree.MemberCount())
    }
    members := tree.Members()
    if len(members) != 5 || members[4] != LeafIndex(4) {
        t.Fatalf("members = %v", members)
    }
}

func TestRatchetTreeSetAndBlank(t *testing.T) {
    tree := NewRatchetTree()
    leaf := testLeafNodeTemplate()
    leaf.LeafNodeSource = LeafNodeSourceUpdate
    for i := uint32(0); i < 4; i++ {
        if err := tree.SetLeaf(LeafIndex(i), leaf.Clone()); err != nil {
            t.Fatalf("SetLeaf(%d): %v", i, err)
        }
    }
    parent := &ParentNode{
        EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x55}, 32)),
        ParentHash:     bytes.Repeat([]byte{0x66}, 32),
        UnmergedLeaves: []LeafIndex{2, 3},
    }
    if err := tree.SetParent(NodeIndex(3), parent); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    if got := tree.ParentAt(NodeIndex(3)); got == nil || len(got.UnmergedLeaves) != 2 {
        t.Fatalf("ParentAt(3) = %+v", got)
    }
    if tree.ParentAt(NodeIndex(0)) != nil {
        t.Fatalf("ParentAt(0) on a leaf index returned a parent node")
    }
    if err := tree.SetParent(NodeIndex(2), parent); !errors.Is(err, ErrNodeTypeMismatch) {
        t.Fatalf("SetParent on an even index err = %v, want ErrNodeTypeMismatch", err)
    }
    if err := tree.SetLeaf(LeafIndex(99), leaf.Clone()); err != nil {
        t.Fatalf("SetLeaf(99) should grow the tree: %v", err)
    }
    if err := tree.Blank(NodeIndex(3)); err != nil {
        t.Fatalf("Blank: %v", err)
    }
    if tree.Get(NodeIndex(3)) != nil {
        t.Fatalf("node 3 is not blank after Blank")
    }
}

func TestRatchetTreeBlankDirectPath(t *testing.T) {
    tree := NewRatchetTree()
    leaf := testLeafNodeTemplate()
    leaf.LeafNodeSource = LeafNodeSourceUpdate
    for i := uint32(0); i < 4; i++ {
        if err := tree.SetLeaf(LeafIndex(i), leaf.Clone()); err != nil {
            t.Fatalf("SetLeaf(%d): %v", i, err)
        }
    }
    for _, x := range []NodeIndex{1, 3, 5} {
        if err := tree.SetParent(x, &ParentNode{
            EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{byte(x)}, 32)),
        }); err != nil {
            t.Fatalf("SetParent(%d): %v", x, err)
        }
    }
    if err := tree.BlankDirectPath(LeafIndex(0)); err != nil {
        t.Fatalf("BlankDirectPath: %v", err)
    }
    for _, x := range []NodeIndex{1, 3} {
        if tree.Get(x) != nil {
            t.Fatalf("node %d is not blank after BlankDirectPath(0)", x)
        }
    }
    if tree.Get(NodeIndex(5)) == nil {
        t.Fatalf("node 5 is not on the direct path of leaf 0 and must survive")
    }
    if tree.Leaf(LeafIndex(0)) == nil {
        t.Fatalf("BlankDirectPath must not blank the leaf itself")
    }
}

func TestRatchetTreeCloneIsIndependent(t *testing.T) {
    tree := NewRatchetTree()
    leaf := testLeafNodeTemplate()
    leaf.LeafNodeSource = LeafNodeSourceUpdate
    if err := tree.SetLeaf(LeafIndex(0), leaf); err != nil {
        t.Fatalf("SetLeaf: %v", err)
    }
    clone := tree.Clone()
    if err := clone.Blank(NodeIndex(0)); err != nil {
        t.Fatalf("Blank: %v", err)
    }
    if tree.Leaf(LeafIndex(0)) == nil {
        t.Fatalf("blanking the clone blanked the original")
    }
    clone2 := tree.Clone()
    clone2.Leaf(LeafIndex(0)).EncryptionKey[0] ^= 0xFF
    if tree.Leaf(LeafIndex(0)).EncryptionKey[0] == clone2.Leaf(LeafIndex(0)).EncryptionKey[0] {
        t.Fatalf("Clone shares leaf key material with the original")
    }
}

func TestRatchetTreeFindLeafBySignatureKey(t *testing.T) {
    tree := NewRatchetTree()
    for i := uint32(0); i < 3; i++ {
        leaf := testLeafNodeTemplate()
        leaf.LeafNodeSource = LeafNodeSourceUpdate
        leaf.SignatureKey = SignaturePublicKey(bytes.Repeat([]byte{byte(i)}, 32))
        if err := tree.SetLeaf(LeafIndex(i), leaf); err != nil {
            t.Fatalf("SetLeaf(%d): %v", i, err)
        }
    }
    got, ok := tree.FindLeafBySignatureKey(SignaturePublicKey(bytes.Repeat([]byte{0x02}, 32)))
    if !ok || got != LeafIndex(2) {
        t.Fatalf("FindLeafBySignatureKey = (%d, %v), want (2, true)", got, ok)
    }
    if _, ok := tree.FindLeafBySignatureKey(SignaturePublicKey(bytes.Repeat([]byte{0x09}, 32))); ok {
        t.Fatalf("FindLeafBySignatureKey found an absent key")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestRatchetTree -v`
Expected: FAIL to compile with `undefined: NewRatchetTree`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree.go
package mls

import (
    "crypto/subtle"

    "github.com/urnetwork/connect/mls/syntax"
)

// RFC 9420 §7. leaf nodes sit at even node indices, parent nodes at odd ones.
type NodeType uint8

const (
    NodeTypeLeaf   NodeType = 1
    NodeTypeParent NodeType = 2
)

// RFC 9420 §7.1.
type ParentNode struct {
    EncryptionKey  HpkePublicKey
    ParentHash     []byte
    UnmergedLeaves []LeafIndex
}

func (self *ParentNode) MarshalTo(w *syntax.Writer) error {
    w.WriteOpaqueVec(self.EncryptionKey)
    w.WriteOpaqueVec(self.ParentHash)
    inner := syntax.NewWriter()
    for _, leaf := range self.UnmergedLeaves {
        inner.WriteUint32(uint32(leaf))
    }
    w.WriteOpaqueVec(inner.Bytes())
    return nil
}

func UnmarshalParentNode(r *syntax.Reader) (*ParentNode, error) {
    encryptionKey, err := r.ReadOpaqueVec()
    if err != nil {
        return nil, err
    }
    parentHash, err := r.ReadOpaqueVec()
    if err != nil {
        return nil, err
    }
    sub, err := r.ReadVecReader()
    if err != nil {
        return nil, err
    }
    unmerged := []LeafIndex{}
    for !sub.Empty() {
        v, err := sub.ReadUint32()
        if err != nil {
            return nil, err
        }
        unmerged = append(unmerged, LeafIndex(v))
    }
    return &ParentNode{
        EncryptionKey:  HpkePublicKey(encryptionKey),
        ParentHash:     parentHash,
        UnmergedLeaves: unmerged,
    }, nil
}

func (self *ParentNode) Clone() *ParentNode {
    return &ParentNode{
        EncryptionKey:  HpkePublicKey(cloneBytes(self.EncryptionKey)),
        ParentHash:     cloneBytes(self.ParentHash),
        UnmergedLeaves: cloneSlice(self.UnmergedLeaves),
    }
}

// one occupied position in the tree. exactly one of Leaf and Parent is set.
type Node struct {
    NodeType NodeType
    Leaf     *LeafNode
    Parent   *ParentNode
}

func (self *Node) Clone() *Node {
    out := &Node{NodeType: self.NodeType}
    if self.Leaf != nil {
        out.Leaf = self.Leaf.Clone()
    }
    if self.Parent != nil {
        out.Parent = self.Parent.Clone()
    }
    return out
}

// the ratchet tree in RFC 9420 §4.2 array order. nil entries are blank nodes. the
// leaf width is always a power of two, so the array is always a complete tree.
// NOT safe for concurrent use.
type RatchetTree struct {
    nodes []*Node
}

func NewRatchetTree() *RatchetTree {
    return &RatchetTree{nodes: make([]*Node, 1)}
}

func (self *RatchetTree) NodeWidth() uint32 {
    return uint32(len(self.nodes))
}

func (self *RatchetTree) LeafWidth() uint32 {
    return (self.NodeWidth() + 1) / 2
}

// grow to at least the given leaf width, doubling. existing node indices are
// unchanged, because doubling only appends a new root and a blank right subtree.
func (self *RatchetTree) growTo(leafWidth uint32) {
    width := self.LeafWidth()
    for width < leafWidth {
        width *= 2
    }
    if width == self.LeafWidth() {
        return
    }
    grown := make([]*Node, NodeWidth(width))
    copy(grown, self.nodes)
    self.nodes = grown
}

func (self *RatchetTree) Get(x NodeIndex) *Node {
    if uint32(x) >= self.NodeWidth() {
        return nil
    }
    return self.nodes[x]
}

func (self *RatchetTree) Leaf(i LeafIndex) *LeafNode {
    node := self.Get(i.NodeIndex())
    if node == nil {
        return nil
    }
    return node.Leaf
}

func (self *RatchetTree) ParentAt(x NodeIndex) *ParentNode {
    node := self.Get(x)
    if node == nil {
        return nil
    }
    return node.Parent
}

func (self *RatchetTree) SetLeaf(i LeafIndex, leaf *LeafNode) error {
    if uint32(i) == ^uint32(0) {
        return ErrLeafIndexOutOfRange
    }
    self.growTo(uint32(i) + 1)
    self.nodes[i.NodeIndex()] = &Node{NodeType: NodeTypeLeaf, Leaf: leaf}
    return nil
}

func (self *RatchetTree) SetParent(x NodeIndex, parent *ParentNode) error {
    if x.IsLeaf() {
        return ErrNodeTypeMismatch
    }
    if uint32(x) >= self.NodeWidth() {
        return ErrNodeIndexOutOfRange
    }
    self.nodes[x] = &Node{NodeType: NodeTypeParent, Parent: parent}
    return nil
}

func (self *RatchetTree) Blank(x NodeIndex) error {
    if uint32(x) >= self.NodeWidth() {
        return ErrNodeIndexOutOfRange
    }
    self.nodes[x] = nil
    return nil
}

// blanks every parent node between the leaf and the root. the leaf itself is left
// alone, because Update and Remove differ only in what they put back there.
func (self *RatchetTree) BlankDirectPath(i LeafIndex) error {
    if uint32(i) >= self.LeafWidth() {
        return ErrLeafIndexOutOfRange
    }
    for _, x := range DirectPath(i.NodeIndex(), self.LeafWidth()) {
        if err := self.Blank(x); err != nil {
            return err
        }
    }
    return nil
}

func (self *RatchetTree) Clone() *RatchetTree {
    out := &RatchetTree{nodes: make([]*Node, len(self.nodes))}
    for i, node := range self.nodes {
        if node != nil {
            out.nodes[i] = node.Clone()
        }
    }
    return out
}

func (self *RatchetTree) Members() []LeafIndex {
    out := []LeafIndex{}
    for i := uint32(0); i < self.LeafWidth(); i++ {
        if self.Leaf(LeafIndex(i)) != nil {
            out = append(out, LeafIndex(i))
        }
    }
    return out
}

func (self *RatchetTree) MemberCount() uint32 {
    return uint32(len(self.Members()))
}

func (self *RatchetTree) FindLeafBySignatureKey(key SignaturePublicKey) (LeafIndex, bool) {
    for i := uint32(0); i < self.LeafWidth(); i++ {
        leaf := self.Leaf(LeafIndex(i))
        if leaf == nil {
            continue
        }
        if subtle.ConstantTimeCompare(leaf.SignatureKey, key) == 1 {
            return LeafIndex(i), true
        }
    }
    return 0, false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestRatchetTree -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree.go mls/tree_test.go
git commit -m "feat(mls): ratchet tree container with ParentNode, blanking and doubling"
```

---

### Task 9: The shared test tree builder

**Files:**
- Create: `mls/tree_testutil_test.go`
- Test: `mls/tree_testutil_test.go`

**Interfaces:**
- Consumes: `NewCryptoProvider`, `CryptoProvider.SignatureKeyPair`, `CryptoProvider.DeriveKeyPair`, `CryptoProvider.Random` (Crypto plan); `RatchetTree`, `LeafNode` (Tasks 5, 8).
- Produces (test-only, used by every later task in this plan): `type testMember struct { LeafIndex LeafIndex; SignaturePriv SignaturePrivateKey; EncryptionPriv HpkePrivateKey }` and `func newTestTree(t testing.TB, crypto CryptoProvider, n uint32) (*RatchetTree, []*testMember)`. It takes `testing.TB` rather than `*testing.T` so the Task 28 benchmarks can build trees without faking a `testing.T`.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_testutil_test.go
package mls

import (
    "fmt"
    "testing"
)

// one member of a test tree, with the private halves a real client would hold.
type testMember struct {
    LeafIndex      LeafIndex
    SignaturePriv  SignaturePrivateKey
    EncryptionPriv HpkePrivateKey
}

const testGroupIdString = "urmessage-test-group"

func testGroupId() []byte {
    return []byte(testGroupIdString)
}

// an n-member tree whose parent nodes are all blank, which is the shape a group has
// immediately after every member has been added and nobody has committed a path.
func newTestTree(t testing.TB, crypto CryptoProvider, n uint32) (*RatchetTree, []*testMember) {
    t.Helper()
    tree := NewRatchetTree()
    members := make([]*testMember, 0, n)
    for i := uint32(0); i < n; i++ {
        signaturePriv, signaturePub, err := crypto.SignatureKeyPair()
        if err != nil {
            t.Fatalf("SignatureKeyPair(%d): %v", i, err)
        }
        encryptionPriv, encryptionPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
        if err != nil {
            t.Fatalf("DeriveKeyPair(%d): %v", i, err)
        }
        leafKeys := LeafKeysExtension{
            AlgId:          AlgIdXwing,
            DeviceXwingPub: crypto.Random(XwingPublicKeyLen),
        }
        leafKeysData, err := leafKeys.Marshal()
        if err != nil {
            t.Fatalf("LeafKeysExtension.Marshal(%d): %v", i, err)
        }
        leaf := &LeafNode{
            EncryptionKey: encryptionPub,
            SignatureKey:  signaturePub,
            Credential: Credential{
                CredentialType: CredentialTypeBasic,
                Identity:       []byte(fmt.Sprintf("member-%d", i)),
            },
            Capabilities: Capabilities{
                Versions:     []ProtocolVersion{ProtocolVersionMLS10},
                CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20SHA256Ed25519},
                Extensions: []ExtensionType{
                    ExtensionTypeUrmessageGroupPolicy,
                    ExtensionTypeUrmessageLeafKeys,
                    ExtensionTypeUrmessageOwnerSuccessor,
                },
                Credentials: []CredentialType{CredentialTypeBasic},
            },
            LeafNodeSource: LeafNodeSourceUpdate,
            Extensions: []Extension{
                {ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: leafKeysData},
            },
        }
        if err := leaf.Sign(crypto, signaturePriv, testGroupId(), LeafIndex(i)); err != nil {
            t.Fatalf("Sign(%d): %v", i, err)
        }
        if err := tree.SetLeaf(LeafIndex(i), leaf); err != nil {
            t.Fatalf("SetLeaf(%d): %v", i, err)
        }
        members = append(members, &testMember{
            LeafIndex:      LeafIndex(i),
            SignaturePriv:  signaturePriv,
            EncryptionPriv: encryptionPriv,
        })
    }
    return tree, members
}

func TestNewTestTreeShape(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    for _, n := range []uint32{1, 2, 3, 5, 8, 9} {
        tree, members := newTestTree(t, crypto, n)
        if tree.MemberCount() != n {
            t.Fatalf("n=%d member count = %d", n, tree.MemberCount())
        }
        if uint32(len(members)) != n {
            t.Fatalf("n=%d members = %d", n, len(members))
        }
        for x := uint32(1); x < tree.NodeWidth(); x += 2 {
            if tree.ParentAt(NodeIndex(x)) != nil {
                t.Fatalf("n=%d parent %d is not blank in a fresh test tree", n, x)
            }
        }
        for _, member := range members {
            leaf := tree.Leaf(member.LeafIndex)
            if leaf == nil {
                t.Fatalf("n=%d leaf %d is blank", n, member.LeafIndex)
            }
            if err := leaf.VerifySignature(crypto, testGroupId(), member.LeafIndex); err != nil {
                t.Fatalf("n=%d leaf %d signature: %v", n, member.LeafIndex, err)
            }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestNewTestTreeShape -v`
Expected: FAIL to compile with `undefined: HpkePrivateKey` if the Crypto plan has not landed, otherwise FAIL with `n=1 member count = 0` before the builder body is filled in

- [ ] **Step 3: Write minimal implementation**

The builder above is the implementation; this task's step 3 is to make it compile and pass by
supplying anything the test file still lacks. If `crypto.Random(XwingPublicKeyLen)` is refused by
the provider's length cap, allocate the buffer directly with `make([]byte, XwingPublicKeyLen)` and
fill it from `crypto.Random(32)` repeated — the X-Wing public key here is opaque filler, never used
as a key in this package.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestNewTestTreeShape -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_testutil_test.go
git commit -m "test(mls): shared n-member ratchet tree builder"
```

---

### Task 10: Node resolution

**Files:**
- Modify: `mls/tree.go`
- Test: `mls/tree_test.go`

**Interfaces:**
- Consumes: `Left`, `Right`, `NodeIndex.IsLeaf` (Tree math plan).
- Produces: `func (self *RatchetTree) Resolution(x NodeIndex) []NodeIndex` — RFC 9420 §7.1: a non-blank node resolves to itself followed by its unmerged leaves; a blank leaf resolves to the empty list; a blank parent resolves to its left child's resolution concatenated with its right child's. Consumed by `treekem.go` and by the tree-validation vector.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go (append)

func TestResolutionRules(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)

    // all parents blank: the root resolves to the four leaves, left to right.
    got := tree.Resolution(Root(tree.LeafWidth()))
    want := []NodeIndex{0, 2, 4, 6}
    if !equalNodeIndices(got, want) {
        t.Fatalf("blank-parent root resolution = %v, want %v", got, want)
    }

    // a blank leaf contributes nothing.
    if err := tree.Blank(NodeIndex(2)); err != nil {
        t.Fatalf("Blank: %v", err)
    }
    got = tree.Resolution(Root(tree.LeafWidth()))
    want = []NodeIndex{0, 4, 6}
    if !equalNodeIndices(got, want) {
        t.Fatalf("with leaf 1 blank, root resolution = %v, want %v", got, want)
    }
    if len(tree.Resolution(NodeIndex(2))) != 0 {
        t.Fatalf("a blank leaf must resolve to the empty list")
    }

    // a non-blank parent resolves to itself, then its unmerged leaves in order.
    if err := tree.SetParent(NodeIndex(1), &ParentNode{
        EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x77}, 32)),
        UnmergedLeaves: []LeafIndex{0},
    }); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    got = tree.Resolution(NodeIndex(1))
    want = []NodeIndex{1, 0}
    if !equalNodeIndices(got, want) {
        t.Fatalf("non-blank parent resolution = %v, want %v", got, want)
    }
    got = tree.Resolution(Root(tree.LeafWidth()))
    want = []NodeIndex{1, 0, 4, 6}
    if !equalNodeIndices(got, want) {
        t.Fatalf("root resolution = %v, want %v", got, want)
    }
}

func equalNodeIndices(a, b []NodeIndex) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestResolutionRules -v`
Expected: FAIL to compile with `tree.Resolution undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree.go (append)

// RFC 9420 §7.1. the ordered list of non-blank nodes that collectively cover every
// non-blank descendant. an unmerged leaf counts toward its ancestors' resolutions,
// which is what makes a freshly added member reachable before anyone commits a path.
func (self *RatchetTree) Resolution(x NodeIndex) []NodeIndex {
    if uint32(x) >= self.NodeWidth() {
        return []NodeIndex{}
    }
    node := self.nodes[x]
    if node != nil {
        out := []NodeIndex{x}
        if node.Parent != nil {
            for _, leaf := range node.Parent.UnmergedLeaves {
                out = append(out, leaf.NodeIndex())
            }
        }
        return out
    }
    if x.IsLeaf() {
        return []NodeIndex{}
    }
    left, ok := Left(x)
    if !ok {
        return []NodeIndex{}
    }
    right, ok := Right(x)
    if !ok {
        return []NodeIndex{}
    }
    return append(self.Resolution(left), self.Resolution(right)...)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestResolutionRules -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree.go mls/tree_test.go
git commit -m "feat(mls): node resolution including unmerged leaves"
```

---

### Task 11: The ratchet_tree extension codec and ValSem300

**Files:**
- Modify: `mls/tree.go`
- Test: `mls/tree_test.go`

**Interfaces:**
- Consumes: `syntax.*`, `syntax.MaxRatchetTreeLength` (Syntax plan); `ErrTrailingBlankNodes` (Validation plan, ValSem300); `ErrTreeMalformed`, `ErrNodeTypeMismatch` (Task 2).
- Produces: `func (self *RatchetTree) Marshal() ([]byte, error)` and `func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)`. The encoding is `optional<Node> ratchet_tree<V>` with trailing blanks stripped; the decoder refuses a trailing blank (ValSem300), refuses a node whose type contradicts its position, and pads to the next complete tree width.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go (append)

func TestRatchetTreeMarshalRoundTrip(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    for _, n := range []uint32{1, 2, 3, 5, 8} {
        tree, _ := newTestTree(t, crypto, n)
        if err := tree.SetParent(NodeIndex(1), &ParentNode{
            EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x88}, 32)),
            ParentHash:     bytes.Repeat([]byte{0x99}, 32),
            UnmergedLeaves: []LeafIndex{1},
        }); n >= 2 && err != nil {
            t.Fatalf("n=%d SetParent: %v", n, err)
        }
        encoded, err := tree.Marshal()
        if err != nil {
            t.Fatalf("n=%d Marshal: %v", n, err)
        }
        out, err := UnmarshalRatchetTree(encoded)
        if err != nil {
            t.Fatalf("n=%d UnmarshalRatchetTree: %v", n, err)
        }
        if out.MemberCount() != n {
            t.Fatalf("n=%d decoded member count = %d", n, out.MemberCount())
        }
        reencoded, err := out.Marshal()
        if err != nil {
            t.Fatalf("n=%d re-Marshal: %v", n, err)
        }
        if !bytes.Equal(reencoded, encoded) {
            t.Fatalf("n=%d re-encode differs", n)
        }
    }
}

func TestValSem300_TrailingBlankNodes(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 3)
    encoded, err := tree.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    // append one more optional<Node> that is absent. the length prefix moves, so
    // rebuild it rather than patching bytes.
    padded, err := marshalRatchetTreeWithTrailingBlank(tree)
    if err != nil {
        t.Fatalf("marshalRatchetTreeWithTrailingBlank: %v", err)
    }
    if bytes.Equal(padded, encoded) {
        t.Fatalf("the padded encoding is identical to the canonical one")
    }
    if _, err := UnmarshalRatchetTree(padded); !errors.Is(err, ErrTrailingBlankNodes) {
        t.Fatalf("err = %v, want ErrTrailingBlankNodes", err)
    }
}

func TestRatchetTreeRejectsNodeTypeInWrongPosition(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 2)
    // put a parent node at node index 0, which is a leaf position.
    tree.nodes[0] = &Node{NodeType: NodeTypeParent, Parent: &ParentNode{
        EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0xAA}, 32)),
    }}
    encoded, err := tree.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if _, err := UnmarshalRatchetTree(encoded); !errors.Is(err, ErrNodeTypeMismatch) {
        t.Fatalf("err = %v, want ErrNodeTypeMismatch", err)
    }
}
```

Add this helper to `mls/tree_test.go`:

```go
// the same encoding as RatchetTree.Marshal but with one absent node appended, which
// is exactly what ValSem300 forbids.
func marshalRatchetTreeWithTrailingBlank(tree *RatchetTree) ([]byte, error) {
    inner := syntax.NewWriter()
    canonical, err := tree.Marshal()
    if err != nil {
        return nil, err
    }
    r := syntax.NewReader(canonical)
    body, err := r.ReadVecReader()
    if err != nil {
        return nil, err
    }
    for !body.Empty() {
        present, err := body.ReadUint8()
        if err != nil {
            return nil, err
        }
        inner.WriteUint8(present)
        if present == 0 {
            continue
        }
        nodeType, err := body.ReadUint8()
        if err != nil {
            return nil, err
        }
        inner.WriteUint8(nodeType)
        if NodeType(nodeType) == NodeTypeLeaf {
            leaf, err := UnmarshalLeafNode(body)
            if err != nil {
                return nil, err
            }
            if err := leaf.MarshalTo(inner); err != nil {
                return nil, err
            }
        } else {
            parent, err := UnmarshalParentNode(body)
            if err != nil {
                return nil, err
            }
            if err := parent.MarshalTo(inner); err != nil {
                return nil, err
            }
        }
    }
    inner.WriteUint8(0)
    w := syntax.NewWriter()
    w.WriteOpaqueVec(inner.Bytes())
    return w.Bytes(), nil
}
```

and add `"github.com/urnetwork/connect/mls/syntax"` to the imports of `mls/tree_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestRatchetTreeMarshal|TestValSem300|TestRatchetTreeRejectsNodeType" -v`
Expected: FAIL to compile with `tree.Marshal undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree.go (append)

func (self *Node) marshalTo(w *syntax.Writer) error {
    w.WriteUint8(uint8(self.NodeType))
    switch self.NodeType {
    case NodeTypeLeaf:
        if self.Leaf == nil {
            return ErrTreeMalformed
        }
        return self.Leaf.MarshalTo(w)
    case NodeTypeParent:
        if self.Parent == nil {
            return ErrTreeMalformed
        }
        return self.Parent.MarshalTo(w)
    default:
        return ErrTreeMalformed
    }
}

// the ratchet_tree extension body, RFC 9420 §12.4.3.1: optional<Node> ratchet_tree<V>
// with every trailing blank stripped.
func (self *RatchetTree) Marshal() ([]byte, error) {
    end := len(self.nodes)
    for end > 0 && self.nodes[end-1] == nil {
        end--
    }
    inner := syntax.NewWriter()
    for _, node := range self.nodes[:end] {
        if node == nil {
            inner.WriteUint8(0)
            continue
        }
        inner.WriteUint8(1)
        if err := node.marshalTo(inner); err != nil {
            return nil, err
        }
    }
    w := syntax.NewWriter()
    w.WriteOpaqueVec(inner.Bytes())
    return w.Bytes(), nil
}

func UnmarshalRatchetTree(data []byte) (*RatchetTree, error) {
    if len(data) > syntax.MaxRatchetTreeLength {
        return nil, syntax.ErrVectorTooLong
    }
    r := syntax.NewReader(data)
    body, err := r.ReadVecReader()
    if err != nil {
        return nil, err
    }
    if !r.Empty() {
        return nil, syntax.ErrTrailingBytes
    }
    nodes := []*Node{}
    for !body.Empty() {
        present, err := body.ReadUint8()
        if err != nil {
            return nil, err
        }
        switch present {
        case 0:
            nodes = append(nodes, nil)
            continue
        case 1:
        default:
            return nil, ErrTreeMalformed
        }
        nodeType, err := body.ReadUint8()
        if err != nil {
            return nil, err
        }
        x := NodeIndex(len(nodes))
        switch NodeType(nodeType) {
        case NodeTypeLeaf:
            if !x.IsLeaf() {
                return nil, ErrNodeTypeMismatch
            }
            leaf, err := UnmarshalLeafNode(body)
            if err != nil {
                return nil, err
            }
            nodes = append(nodes, &Node{NodeType: NodeTypeLeaf, Leaf: leaf})
        case NodeTypeParent:
            if x.IsLeaf() {
                return nil, ErrNodeTypeMismatch
            }
            parent, err := UnmarshalParentNode(body)
            if err != nil {
                return nil, err
            }
            nodes = append(nodes, &Node{NodeType: NodeTypeParent, Parent: parent})
        default:
            return nil, ErrTreeMalformed
        }
    }
    // ValSem300: an exported ratchet tree carries no trailing blank nodes.
    if len(nodes) > 0 && nodes[len(nodes)-1] == nil {
        return nil, ErrTrailingBlankNodes
    }
    tree := &RatchetTree{nodes: nodes}
    if len(nodes) == 0 {
        tree.nodes = make([]*Node, 1)
        return tree, nil
    }
    // pad up to the next complete tree.
    leafWidth := uint32(1)
    for NodeWidth(leafWidth) < uint32(len(nodes)) {
        leafWidth *= 2
    }
    padded := make([]*Node, NodeWidth(leafWidth))
    copy(padded, nodes)
    tree.nodes = padded
    return tree, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestRatchetTreeMarshal|TestValSem300|TestRatchetTreeRejectsNodeType" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree.go mls/tree_test.go
git commit -m "feat(mls): ratchet_tree extension codec refusing trailing blank nodes (ValSem300)"
```

---

### Task 12: The tree hash

**Files:**
- Create: `mls/tree_hash.go`
- Test: `mls/tree_hash_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Hash` (Crypto plan); `Left`, `Right`, `Root`, `NodeIndex.IsLeaf`, `NodeIndex.LeafIndex` (Tree math plan); `syntax.*`.
- Produces: `func (self *RatchetTree) NodeTreeHash(crypto CryptoProvider, x NodeIndex) ([]byte, error)`, `func (self *RatchetTree) TreeHash(crypto CryptoProvider) ([]byte, error)`, `func (self *RatchetTree) TreeHashes(crypto CryptoProvider) ([][]byte, error)`. `TreeHash` is what `GroupContext.TreeHash` is set from; `TreeHashes` is indexed by node index and is what the tree-validation vector checks.

The hash inputs are RFC 9420 §7.8:

```
struct { NodeType node_type;
         select { case leaf: LeafNodeHashInput; case parent: ParentNodeHashInput; } } TreeHashInput;
struct { uint32 leaf_index; optional<LeafNode> leaf_node; } LeafNodeHashInput;
struct { optional<ParentNode> parent_node; opaque left_hash<V>; opaque right_hash<V>; } ParentNodeHashInput;
```

A blank leaf still hashes, as an absent `optional<LeafNode>` at its own index — which is why a blank
position is distinguishable from a missing one.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_hash_test.go
package mls

import (
    "bytes"
    "testing"
)

func TestTreeHashChangesWithEveryObservableChange(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    base, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    if len(base) != crypto.HashSize() {
        t.Fatalf("tree hash length = %d, want %d", len(base), crypto.HashSize())
    }

    mutations := map[string]func(tree *RatchetTree){
        "blank a leaf":       func(tree *RatchetTree) { _ = tree.Blank(NodeIndex(2)) },
        "swap two leaves":    func(tree *RatchetTree) { tree.nodes[0], tree.nodes[2] = tree.nodes[2], tree.nodes[0] },
        "set a parent":       func(tree *RatchetTree) { _ = tree.SetParent(NodeIndex(1), &ParentNode{EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0x01}, 32))}) },
        "add an unmerged":    func(tree *RatchetTree) { _ = tree.SetParent(NodeIndex(1), &ParentNode{EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0x01}, 32)), UnmergedLeaves: []LeafIndex{1}}) },
        "grow the tree":      func(tree *RatchetTree) { _ = tree.SetLeaf(LeafIndex(4), tree.Leaf(LeafIndex(0)).Clone()) },
    }
    seen := map[string]string{string(base): "base"}
    for name, mutate := range mutations {
        clone := tree.Clone()
        mutate(clone)
        got, err := clone.TreeHash(crypto)
        if err != nil {
            t.Fatalf("%s TreeHash: %v", name, err)
        }
        if prior, ok := seen[string(got)]; ok {
            t.Fatalf("%s produced the same tree hash as %s", name, prior)
        }
        seen[string(got)] = name
    }
}

func TestTreeHashesIndexedByNode(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 5)
    hashes, err := tree.TreeHashes(crypto)
    if err != nil {
        t.Fatalf("TreeHashes: %v", err)
    }
    if uint32(len(hashes)) != tree.NodeWidth() {
        t.Fatalf("len(TreeHashes) = %d, want %d", len(hashes), tree.NodeWidth())
    }
    for x := uint32(0); x < tree.NodeWidth(); x++ {
        one, err := tree.NodeTreeHash(crypto, NodeIndex(x))
        if err != nil {
            t.Fatalf("NodeTreeHash(%d): %v", x, err)
        }
        if !bytes.Equal(one, hashes[x]) {
            t.Fatalf("node %d: TreeHashes disagrees with NodeTreeHash", x)
        }
    }
    root, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    if !bytes.Equal(root, hashes[Root(tree.LeafWidth())]) {
        t.Fatalf("TreeHash is not the root entry of TreeHashes")
    }
}

func TestBlankLeafStillHashesAtItsIndex(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    if err := tree.Blank(NodeIndex(0)); err != nil {
        t.Fatalf("Blank(0): %v", err)
    }
    a, err := tree.NodeTreeHash(crypto, NodeIndex(0))
    if err != nil {
        t.Fatalf("NodeTreeHash(0): %v", err)
    }
    if err := tree.Blank(NodeIndex(2)); err != nil {
        t.Fatalf("Blank(2): %v", err)
    }
    b, err := tree.NodeTreeHash(crypto, NodeIndex(2))
    if err != nil {
        t.Fatalf("NodeTreeHash(2): %v", err)
    }
    if bytes.Equal(a, b) {
        t.Fatalf("two blank leaves at different indices hash the same")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestTreeHash|TestBlankLeaf" -v`
Expected: FAIL to compile with `tree.TreeHash undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree_hash.go
package mls

import "github.com/urnetwork/connect/mls/syntax"

// RFC 9420 §7.8. the leaf index is inside the hash input, so a blank position is
// distinguishable from every other blank position.
func (self *RatchetTree) leafHashInput(w *syntax.Writer, i LeafIndex, leaf *LeafNode) error {
    w.WriteUint8(uint8(NodeTypeLeaf))
    w.WriteUint32(uint32(i))
    if leaf == nil {
        w.WriteUint8(0)
        return nil
    }
    w.WriteUint8(1)
    return leaf.MarshalTo(w)
}

func (self *RatchetTree) parentHashInput(w *syntax.Writer, parent *ParentNode,
    leftHash, rightHash []byte) error {
    w.WriteUint8(uint8(NodeTypeParent))
    if parent == nil {
        w.WriteUint8(0)
    } else {
        w.WriteUint8(1)
        if err := parent.MarshalTo(w); err != nil {
            return err
        }
    }
    w.WriteOpaqueVec(leftHash)
    w.WriteOpaqueVec(rightHash)
    return nil
}

// the tree hash of the subtree rooted at x, with the leaves in exclude treated as
// blank and every descendant parent node's unmerged_leaves filtered by the same set.
// exclude is nil for an ordinary tree hash and is the parent's unmerged_leaves when
// computing an original tree hash for a parent hash (RFC 9420 §7.9).
func (self *RatchetTree) treeHash(crypto CryptoProvider, x NodeIndex,
    exclude map[LeafIndex]bool) ([]byte, error) {
    if uint32(x) >= self.NodeWidth() {
        return nil, ErrNodeIndexOutOfRange
    }
    w := syntax.NewWriter()
    if x.IsLeaf() {
        i, ok := x.LeafIndex()
        if !ok {
            return nil, ErrTreeMalformed
        }
        leaf := self.Leaf(i)
        if exclude != nil && exclude[i] {
            leaf = nil
        }
        if err := self.leafHashInput(w, i, leaf); err != nil {
            return nil, err
        }
        return crypto.Hash(w.Bytes()), nil
    }
    left, ok := Left(x)
    if !ok {
        return nil, ErrTreeMalformed
    }
    right, ok := Right(x)
    if !ok {
        return nil, ErrTreeMalformed
    }
    leftHash, err := self.treeHash(crypto, left, exclude)
    if err != nil {
        return nil, err
    }
    rightHash, err := self.treeHash(crypto, right, exclude)
    if err != nil {
        return nil, err
    }
    parent := self.ParentAt(x)
    if parent != nil && exclude != nil && len(parent.UnmergedLeaves) > 0 {
        filtered := parent.Clone()
        kept := filtered.UnmergedLeaves[:0]
        for _, leaf := range parent.UnmergedLeaves {
            if !exclude[leaf] {
                kept = append(kept, leaf)
            }
        }
        filtered.UnmergedLeaves = kept
        parent = filtered
    }
    if err := self.parentHashInput(w, parent, leftHash, rightHash); err != nil {
        return nil, err
    }
    return crypto.Hash(w.Bytes()), nil
}

func (self *RatchetTree) NodeTreeHash(crypto CryptoProvider, x NodeIndex) ([]byte, error) {
    return self.treeHash(crypto, x, nil)
}

func (self *RatchetTree) TreeHash(crypto CryptoProvider) ([]byte, error) {
    return self.treeHash(crypto, Root(self.LeafWidth()), nil)
}

// every node's tree hash, indexed by node index. the tree-validation vector checks
// all of them, and a whole-tree walk costs the same as the root alone.
func (self *RatchetTree) TreeHashes(crypto CryptoProvider) ([][]byte, error) {
    out := make([][]byte, self.NodeWidth())
    for x := uint32(0); x < self.NodeWidth(); x++ {
        hash, err := self.treeHash(crypto, NodeIndex(x), nil)
        if err != nil {
            return nil, err
        }
        out[x] = hash
    }
    return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestTreeHash|TestBlankLeaf" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_hash.go mls/tree_hash_test.go
git commit -m "feat(mls): RFC 9420 section 7.8 tree hash over the ratchet tree"
```

---

### Task 13: The original tree hash and the parent hash

**Files:**
- Modify: `mls/tree_hash.go`
- Test: `mls/tree_hash_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Hash`; `Left`, `Right`, `Sibling`, `CommonAncestor` (Tree math plan).
- Produces: `func (self *RatchetTree) ParentHash(crypto CryptoProvider, parent, copathChild NodeIndex) ([]byte, error)` — the parent hash of node `parent` taken with respect to the copath child `copathChild`, per RFC 9420 §7.9:

```
struct { HPKEPublicKey encryption_key;
         opaque parent_hash<V>;
         opaque original_sibling_tree_hash<V>; } ParentHashInput;
```

where `original_sibling_tree_hash` is the tree hash of the subtree rooted at `copathChild`, computed
with `parent`'s unmerged leaves blanked and removed from every descendant's `unmerged_leaves`. This
is exactly `treeHash(crypto, copathChild, exclude)` from Task 12 with `exclude = parent.UnmergedLeaves`.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_hash_test.go (append)

func TestParentHashDependsOnUnmergedLeaves(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    parent := &ParentNode{
        EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0xC0}, 32)),
        ParentHash:    bytes.Repeat([]byte{0xC1}, 32),
    }
    if err := tree.SetParent(NodeIndex(3), parent); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    // node 3 is the root of leaves 0..3; its children are 1 (leaves 0,1) and 5 (leaves 2,3).
    withoutUnmerged, err := tree.ParentHash(crypto, NodeIndex(3), NodeIndex(5))
    if err != nil {
        t.Fatalf("ParentHash: %v", err)
    }
    withUnmerged := parent.Clone()
    withUnmerged.UnmergedLeaves = []LeafIndex{3}
    if err := tree.SetParent(NodeIndex(3), withUnmerged); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    withUnmergedHash, err := tree.ParentHash(crypto, NodeIndex(3), NodeIndex(5))
    if err != nil {
        t.Fatalf("ParentHash: %v", err)
    }
    if bytes.Equal(withoutUnmerged, withUnmergedHash) {
        t.Fatalf("an unmerged leaf in the copath subtree did not change the original sibling tree hash")
    }
    // blanking leaf 3 by hand must produce the same original sibling tree hash as
    // listing it unmerged, which is the whole point of the exclusion rule.
    blanked := tree.Clone()
    if err := blanked.SetParent(NodeIndex(3), parent); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    if err := blanked.Blank(NodeIndex(6)); err != nil {
        t.Fatalf("Blank: %v", err)
    }
    blankedHash, err := blanked.ParentHash(crypto, NodeIndex(3), NodeIndex(5))
    if err != nil {
        t.Fatalf("ParentHash: %v", err)
    }
    if !bytes.Equal(blankedHash, withUnmergedHash) {
        t.Fatalf("unmerged-leaf exclusion is not equivalent to blanking that leaf")
    }
}

func TestParentHashCoversTheParentsOwnFields(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    base := &ParentNode{
        EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0xD0}, 32)),
        ParentHash:    bytes.Repeat([]byte{0xD1}, 32),
    }
    if err := tree.SetParent(NodeIndex(3), base); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    reference, err := tree.ParentHash(crypto, NodeIndex(3), NodeIndex(5))
    if err != nil {
        t.Fatalf("ParentHash: %v", err)
    }
    mutations := map[string]func(parent *ParentNode){
        "encryption_key": func(parent *ParentNode) { parent.EncryptionKey[0] ^= 0xFF },
        "parent_hash":    func(parent *ParentNode) { parent.ParentHash[0] ^= 0xFF },
    }
    for name, mutate := range mutations {
        mutated := base.Clone()
        mutate(mutated)
        if err := tree.SetParent(NodeIndex(3), mutated); err != nil {
            t.Fatalf("%s SetParent: %v", name, err)
        }
        got, err := tree.ParentHash(crypto, NodeIndex(3), NodeIndex(5))
        if err != nil {
            t.Fatalf("%s ParentHash: %v", name, err)
        }
        if bytes.Equal(got, reference) {
            t.Fatalf("mutating %s did not change the parent hash", name)
        }
    }
    // the two children give different parent hashes, so a node cannot be replayed
    // from one side of its parent to the other.
    if err := tree.SetParent(NodeIndex(3), base); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    other, err := tree.ParentHash(crypto, NodeIndex(3), NodeIndex(1))
    if err != nil {
        t.Fatalf("ParentHash: %v", err)
    }
    if bytes.Equal(other, reference) {
        t.Fatalf("the parent hash is the same for both copath children")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestParentHash -v`
Expected: FAIL to compile with `tree.ParentHash undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree_hash.go (append)

// RFC 9420 §7.9. the parent hash of the node at parent, taken with respect to the
// child of parent that is NOT on the path being updated. the original sibling tree
// hash is the copath subtree's tree hash with the parent's unmerged leaves removed,
// which is what lets a member that was added but never merged still verify the chain.
func (self *RatchetTree) ParentHash(crypto CryptoProvider,
    parent, copathChild NodeIndex) ([]byte, error) {
    node := self.ParentAt(parent)
    if node == nil {
        return nil, ErrParentHashMismatch
    }
    exclude := map[LeafIndex]bool{}
    for _, leaf := range node.UnmergedLeaves {
        exclude[leaf] = true
    }
    siblingHash, err := self.treeHash(crypto, copathChild, exclude)
    if err != nil {
        return nil, err
    }
    w := syntax.NewWriter()
    w.WriteOpaqueVec(node.EncryptionKey)
    w.WriteOpaqueVec(node.ParentHash)
    w.WriteOpaqueVec(siblingHash)
    return crypto.Hash(w.Bytes()), nil
}

// the parent_hash field a node carries, whatever kind of node it is. a leaf carries
// one only when it entered the tree through a commit.
func nodeParentHashField(node *Node) ([]byte, bool) {
    if node == nil {
        return nil, false
    }
    if node.Parent != nil {
        return node.Parent.ParentHash, true
    }
    if node.Leaf != nil && node.Leaf.LeafNodeSource == LeafNodeSourceCommit {
        return node.Leaf.ParentHash, true
    }
    return nil, false
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestParentHash -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_hash.go mls/tree_hash_test.go
git commit -m "feat(mls): parent hash over the original sibling tree hash (RFC 9420 section 7.9)"
```

---

### Task 14: Parent-hash validity for the whole tree

**Files:**
- Modify: `mls/tree_hash.go`
- Test: `mls/tree_hash_test.go`

**Interfaces:**
- Consumes: `Left`, `Right` (Tree math plan); `ErrParentHashMismatch` (Task 2); `Resolution` (Task 10); `ParentHash` (Task 13).
- Produces: `func (self *RatchetTree) VerifyParentHashes(crypto CryptoProvider) error`. RFC 9420 §7.9.2: for every non-blank parent P with children L and R, exactly one of "some node in `Resolution(L)` carries the parent hash of P taken with copath child R" and the mirrored statement for R must hold. Exactly one — both, or neither, is a failure.

A tree whose parent nodes are all blank is trivially parent-hash valid, which is why the Task 9
builder produces one and why every UpdatePath test starts from there.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_hash_test.go (append)

// installs a hand-built two-node chain: parent 1 with a child leaf 0 whose
// parent_hash field is the parent hash of node 1 with copath child 2.
func buildParentHashChain(t *testing.T, crypto CryptoProvider) (*RatchetTree, []*testMember) {
    t.Helper()
    tree, members := newTestTree(t, crypto, 2)
    parent := &ParentNode{
        EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0xE0}, 32)),
        ParentHash:    []byte{},
    }
    if err := tree.SetParent(NodeIndex(1), parent); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    hash, err := tree.ParentHash(crypto, NodeIndex(1), NodeIndex(2))
    if err != nil {
        t.Fatalf("ParentHash: %v", err)
    }
    leaf := tree.Leaf(LeafIndex(0)).Clone()
    leaf.LeafNodeSource = LeafNodeSourceCommit
    leaf.ParentHash = hash
    if err := leaf.Sign(crypto, members[0].SignaturePriv, testGroupId(), LeafIndex(0)); err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := tree.SetLeaf(LeafIndex(0), leaf); err != nil {
        t.Fatalf("SetLeaf: %v", err)
    }
    return tree, members
}

func TestVerifyParentHashesAcceptsAllBlankParents(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    for _, n := range []uint32{1, 2, 3, 7, 8} {
        tree, _ := newTestTree(t, crypto, n)
        if err := tree.VerifyParentHashes(crypto); err != nil {
            t.Fatalf("n=%d VerifyParentHashes: %v", n, err)
        }
    }
}

func TestVerifyParentHashesAcceptsAValidChain(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := buildParentHashChain(t, crypto)
    if err := tree.VerifyParentHashes(crypto); err != nil {
        t.Fatalf("VerifyParentHashes: %v", err)
    }
}

func TestVerifyParentHashesRejectsATamperedChain(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := buildParentHashChain(t, crypto)
    parent := tree.ParentAt(NodeIndex(1)).Clone()
    parent.EncryptionKey[0] ^= 0xFF
    if err := tree.SetParent(NodeIndex(1), parent); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    if err := tree.VerifyParentHashes(crypto); !errors.Is(err, ErrParentHashMismatch) {
        t.Fatalf("err = %v, want ErrParentHashMismatch", err)
    }
}

func TestVerifyParentHashesRejectsBothChildrenClaimingTheSameParent(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := buildParentHashChain(t, crypto)
    // give leaf 1 the mirrored parent hash as well: now both children resolve to a
    // node claiming node 1 as its parent, which RFC 9420 §7.9.2 forbids.
    hash, err := tree.ParentHash(crypto, NodeIndex(1), NodeIndex(0))
    if err != nil {
        t.Fatalf("ParentHash: %v", err)
    }
    leaf := tree.Leaf(LeafIndex(1)).Clone()
    leaf.LeafNodeSource = LeafNodeSourceCommit
    leaf.ParentHash = hash
    if err := leaf.Sign(crypto, members[1].SignaturePriv, testGroupId(), LeafIndex(1)); err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := tree.SetLeaf(LeafIndex(1), leaf); err != nil {
        t.Fatalf("SetLeaf: %v", err)
    }
    if err := tree.VerifyParentHashes(crypto); !errors.Is(err, ErrParentHashMismatch) {
        t.Fatalf("err = %v, want ErrParentHashMismatch", err)
    }
}
```

Add `"errors"` to the imports of `mls/tree_hash_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestVerifyParentHashes -v`
Expected: FAIL to compile with `tree.VerifyParentHashes undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree_hash.go (append)

import "crypto/subtle"   // add to the existing import block

// does any node in the resolution carry this parent hash in its own parent_hash
// field? intermediate blanks resolve down to the node that actually holds it,
// which is why a filtered direct path still chains.
func (self *RatchetTree) resolutionCarriesParentHash(x NodeIndex, hash []byte) bool {
    for _, y := range self.Resolution(x) {
        field, ok := nodeParentHashField(self.Get(y))
        if !ok {
            continue
        }
        if subtle.ConstantTimeCompare(field, hash) == 1 {
            return true
        }
    }
    return false
}

// RFC 9420 §7.9.2. every non-blank parent node must be claimed as parent by exactly
// one of its two subtrees. neither means the node was never legitimately written;
// both means two update paths were spliced together.
func (self *RatchetTree) VerifyParentHashes(crypto CryptoProvider) error {
    for x := uint32(1); x < self.NodeWidth(); x += 2 {
        node := NodeIndex(x)
        if self.ParentAt(node) == nil {
            continue
        }
        left, ok := Left(node)
        if !ok {
            return ErrTreeMalformed
        }
        right, ok := Right(node)
        if !ok {
            return ErrTreeMalformed
        }
        // a descendant in the left subtree carries the parent hash taken with the
        // right child as copath, and vice versa.
        leftClaim, err := self.ParentHash(crypto, node, right)
        if err != nil {
            return err
        }
        rightClaim, err := self.ParentHash(crypto, node, left)
        if err != nil {
            return err
        }
        fromLeft := self.resolutionCarriesParentHash(left, leftClaim)
        fromRight := self.resolutionCarriesParentHash(right, rightClaim)
        if fromLeft == fromRight {
            return ErrParentHashMismatch
        }
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestVerifyParentHashes -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_hash.go mls/tree_hash_test.go
git commit -m "feat(mls): parent hash validity for the whole tree (RFC 9420 section 7.9.2)"
```

---

### Task 15: Add, Update and Remove on the tree

**Files:**
- Modify: `mls/tree.go`
- Test: `mls/tree_test.go`

**Interfaces:**
- Consumes: `DirectPath`, `Root` (Tree math plan); `ErrLeafIndexOutOfRange`, `ErrUnmergedLeavesNotSorted` (Task 2).
- Produces: `func (self *RatchetTree) AddLeaf(leaf *LeafNode) (LeafIndex, error)`, `func (self *RatchetTree) UpdateLeaf(i LeafIndex, leaf *LeafNode) error`, `func (self *RatchetTree) RemoveLeaf(i LeafIndex) error`. These are what `commit.go` (Group lifecycle plan) calls when it applies a proposal list, in RFC 9420 §12.3 order: GroupContextExtensions, Update, Remove, Add.

RFC 9420 §7.7 semantics, each of which has a distinct failure mode if got wrong:

- **Add** fills the leftmost blank leaf, growing the tree when there is none, and appends the new
  leaf index to `unmerged_leaves` of every non-blank node on its direct path. It never blanks.
- **Update** replaces the leaf and blanks its whole direct path.
- **Remove** blanks the leaf and its direct path, then truncates the tree while the right half holds
  only blank leaves.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go (append)

func TestAddLeafFillsTheLeftmostBlankAndMarksUnmerged(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    for _, x := range []NodeIndex{1, 3, 5} {
        if err := tree.SetParent(x, &ParentNode{
            EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{byte(x)}, 32)),
        }); err != nil {
            t.Fatalf("SetParent(%d): %v", x, err)
        }
    }
    if err := tree.Blank(NodeIndex(2)); err != nil {
        t.Fatalf("Blank: %v", err)
    }
    newLeaf := tree.Leaf(LeafIndex(0)).Clone()
    got, err := tree.AddLeaf(newLeaf)
    if err != nil {
        t.Fatalf("AddLeaf: %v", err)
    }
    if got != LeafIndex(1) {
        t.Fatalf("AddLeaf = %d, want the leftmost blank leaf 1", got)
    }
    for _, x := range []NodeIndex{1, 3} {
        parent := tree.ParentAt(x)
        if parent == nil {
            t.Fatalf("AddLeaf blanked node %d; Add must never blank", x)
        }
        if len(parent.UnmergedLeaves) != 1 || parent.UnmergedLeaves[0] != LeafIndex(1) {
            t.Fatalf("node %d unmerged = %v, want [1]", x, parent.UnmergedLeaves)
        }
    }
    if parent := tree.ParentAt(NodeIndex(5)); len(parent.UnmergedLeaves) != 0 {
        t.Fatalf("node 5 is off the direct path and must not be marked unmerged")
    }
    // with no blank left, Add grows the tree.
    if _, err := tree.AddLeaf(newLeaf.Clone()); err != nil {
        t.Fatalf("AddLeaf into a full tree: %v", err)
    }
    if tree.LeafWidth() != 8 {
        t.Fatalf("leaf width = %d, want 8", tree.LeafWidth())
    }
}

func TestUpdateLeafBlanksTheDirectPath(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    for _, x := range []NodeIndex{1, 3, 5} {
        if err := tree.SetParent(x, &ParentNode{
            EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{byte(x)}, 32)),
            UnmergedLeaves: []LeafIndex{2},
        }); err != nil {
            t.Fatalf("SetParent(%d): %v", x, err)
        }
    }
    replacement := tree.Leaf(LeafIndex(0)).Clone()
    replacement.EncryptionKey = HpkePublicKey(bytes.Repeat([]byte{0xAB}, 32))
    if err := tree.UpdateLeaf(LeafIndex(0), replacement); err != nil {
        t.Fatalf("UpdateLeaf: %v", err)
    }
    if !bytes.Equal(tree.Leaf(LeafIndex(0)).EncryptionKey, replacement.EncryptionKey) {
        t.Fatalf("UpdateLeaf did not install the replacement")
    }
    for _, x := range []NodeIndex{1, 3} {
        if tree.ParentAt(x) != nil {
            t.Fatalf("node %d survived UpdateLeaf", x)
        }
    }
    if tree.ParentAt(NodeIndex(5)) == nil {
        t.Fatalf("node 5 is off the direct path and must survive")
    }
}

func TestRemoveLeafBlanksAndTruncates(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 5)
    if tree.LeafWidth() != 8 {
        t.Fatalf("leaf width = %d, want 8", tree.LeafWidth())
    }
    if err := tree.RemoveLeaf(LeafIndex(4)); err != nil {
        t.Fatalf("RemoveLeaf: %v", err)
    }
    if tree.Leaf(LeafIndex(4)) != nil {
        t.Fatalf("leaf 4 is still present")
    }
    // the whole right half is blank now, so the tree halves.
    if tree.LeafWidth() != 4 {
        t.Fatalf("leaf width after remove = %d, want 4", tree.LeafWidth())
    }
    if tree.MemberCount() != 4 {
        t.Fatalf("member count = %d, want 4", tree.MemberCount())
    }
    if err := tree.RemoveLeaf(LeafIndex(4)); !errors.Is(err, ErrLeafIndexOutOfRange) {
        t.Fatalf("removing past the width err = %v, want ErrLeafIndexOutOfRange", err)
    }
    // removing an interior leaf leaves the width alone.
    if err := tree.RemoveLeaf(LeafIndex(1)); err != nil {
        t.Fatalf("RemoveLeaf(1): %v", err)
    }
    if tree.LeafWidth() != 4 {
        t.Fatalf("leaf width = %d, want 4 after an interior removal", tree.LeafWidth())
    }
}

func TestRemoveLeafDropsItFromUnmergedLeaves(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    // node 5 covers leaves 2 and 3 and is off leaf 3's... it is ON leaf 3's direct
    // path, so use the root, which is also on it, and node 1, which is not.
    if err := tree.SetParent(NodeIndex(1), &ParentNode{
        EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x01}, 32)),
        UnmergedLeaves: []LeafIndex{0, 3},
    }); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    if err := tree.RemoveLeaf(LeafIndex(3)); err != nil {
        t.Fatalf("RemoveLeaf: %v", err)
    }
    parent := tree.ParentAt(NodeIndex(1))
    if parent == nil {
        t.Fatalf("node 1 is off leaf 3's direct path and must survive")
    }
    for _, leaf := range parent.UnmergedLeaves {
        if leaf == LeafIndex(3) {
            t.Fatalf("removed leaf 3 is still listed unmerged on node 1")
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestAddLeaf|TestUpdateLeaf|TestRemoveLeaf" -v`
Expected: FAIL to compile with `tree.AddLeaf undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree.go (append)

// RFC 9420 §7.7. the new member takes the leftmost blank leaf, and every non-blank
// node above it records the new leaf as unmerged — the node's key predates the
// member, so the member cannot use it until someone commits a path through it.
func (self *RatchetTree) AddLeaf(leaf *LeafNode) (LeafIndex, error) {
    target := LeafIndex(0)
    found := false
    for i := uint32(0); i < self.LeafWidth(); i++ {
        if self.Leaf(LeafIndex(i)) == nil {
            target = LeafIndex(i)
            found = true
            break
        }
    }
    if !found {
        target = LeafIndex(self.LeafWidth())
    }
    if err := self.SetLeaf(target, leaf); err != nil {
        return 0, err
    }
    for _, x := range DirectPath(target.NodeIndex(), self.LeafWidth()) {
        parent := self.ParentAt(x)
        if parent == nil {
            continue
        }
        parent.UnmergedLeaves = append(parent.UnmergedLeaves, target)
    }
    return target, nil
}

// RFC 9420 §7.7. replacing a leaf invalidates every node above it, so they are blanked.
func (self *RatchetTree) UpdateLeaf(i LeafIndex, leaf *LeafNode) error {
    if uint32(i) >= self.LeafWidth() || self.Leaf(i) == nil {
        return ErrLeafIndexOutOfRange
    }
    if err := self.SetLeaf(i, leaf); err != nil {
        return err
    }
    return self.BlankDirectPath(i)
}

// RFC 9420 §7.7. blank the leaf and its direct path, drop it from any surviving
// unmerged list, then shrink while the right half holds only blanks.
func (self *RatchetTree) RemoveLeaf(i LeafIndex) error {
    if uint32(i) >= self.LeafWidth() || self.Leaf(i) == nil {
        return ErrLeafIndexOutOfRange
    }
    if err := self.BlankDirectPath(i); err != nil {
        return err
    }
    if err := self.Blank(i.NodeIndex()); err != nil {
        return err
    }
    for x := uint32(1); x < self.NodeWidth(); x += 2 {
        parent := self.ParentAt(NodeIndex(x))
        if parent == nil {
            continue
        }
        kept := parent.UnmergedLeaves[:0]
        for _, leaf := range parent.UnmergedLeaves {
            if leaf != i {
                kept = append(kept, leaf)
            }
        }
        parent.UnmergedLeaves = kept
    }
    self.truncate()
    return nil
}

// halve the tree while every leaf in the right half is blank.
func (self *RatchetTree) truncate() {
    for self.LeafWidth() > 1 {
        half := self.LeafWidth() / 2
        occupied := false
        for i := half; i < self.LeafWidth(); i++ {
            if self.Leaf(LeafIndex(i)) != nil {
                occupied = true
                break
            }
        }
        if occupied {
            return
        }
        self.nodes = self.nodes[:NodeWidth(half)]
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestAddLeaf|TestUpdateLeaf|TestRemoveLeaf" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree.go mls/tree_test.go
git commit -m "feat(mls): Add, Update and Remove on the ratchet tree with truncation"
```

---

### Task 16: The filtered direct path and the copath encryption targets

**Files:**
- Modify: `mls/tree.go`
- Test: `mls/tree_test.go`

**Interfaces:**
- Consumes: `DirectPath`, `Left`, `Right`, `Sibling`, `CommonAncestor` (Tree math plan); `Resolution` (Task 10).
- Produces:
  - `func (self *RatchetTree) FilteredDirectPath(i LeafIndex) ([]NodeIndex, error)` — the direct path of leaf `i`, bottom-up, with every node removed whose copath child has an empty resolution.
  - `func (self *RatchetTree) EncryptionTargets(sender LeafIndex, exclude []LeafIndex) ([][]NodeIndex, error)` — one entry per filtered-direct-path node, in the same order, each the resolution of that node's copath child with the leaves in `exclude` removed. `exclude` is the set of leaves added by the same commit: they receive the path secret in the Welcome, never in the UpdatePath.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go (append)

func TestFilteredDirectPathSkipsEmptyCopathResolutions(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    full, err := tree.FilteredDirectPath(LeafIndex(0))
    if err != nil {
        t.Fatalf("FilteredDirectPath: %v", err)
    }
    if !equalNodeIndices(full, []NodeIndex{1, 3}) {
        t.Fatalf("filtered direct path = %v, want [1 3]", full)
    }
    // blank leaf 1: node 1's copath child (node 2) now resolves to nothing, so node 1
    // drops out of the filtered path.
    if err := tree.Blank(NodeIndex(2)); err != nil {
        t.Fatalf("Blank: %v", err)
    }
    got, err := tree.FilteredDirectPath(LeafIndex(0))
    if err != nil {
        t.Fatalf("FilteredDirectPath: %v", err)
    }
    if !equalNodeIndices(got, []NodeIndex{3}) {
        t.Fatalf("filtered direct path = %v, want [3]", got)
    }
    // an only member has an empty filtered direct path.
    lone, _ := newTestTree(t, crypto, 1)
    got, err = lone.FilteredDirectPath(LeafIndex(0))
    if err != nil {
        t.Fatalf("FilteredDirectPath: %v", err)
    }
    if len(got) != 0 {
        t.Fatalf("single-member filtered direct path = %v, want empty", got)
    }
}

func TestEncryptionTargetsExcludeNewlyAddedLeaves(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    targets, err := tree.EncryptionTargets(LeafIndex(0), nil)
    if err != nil {
        t.Fatalf("EncryptionTargets: %v", err)
    }
    if len(targets) != 2 {
        t.Fatalf("targets = %v, want one entry per filtered path node", targets)
    }
    if !equalNodeIndices(targets[0], []NodeIndex{2}) {
        t.Fatalf("targets[0] = %v, want [2]", targets[0])
    }
    if !equalNodeIndices(targets[1], []NodeIndex{4, 6}) {
        t.Fatalf("targets[1] = %v, want [4 6]", targets[1])
    }
    // leaf 3 was added by this commit: it gets the path secret in the Welcome, so it
    // is not an encryption target here.
    targets, err = tree.EncryptionTargets(LeafIndex(0), []LeafIndex{3})
    if err != nil {
        t.Fatalf("EncryptionTargets: %v", err)
    }
    if !equalNodeIndices(targets[1], []NodeIndex{4}) {
        t.Fatalf("targets[1] with leaf 3 excluded = %v, want [4]", targets[1])
    }
}

func TestEncryptionTargetsExcludeUnmergedNewLeaves(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    // node 5 is non-blank and lists leaf 3 unmerged, so leaf 3 appears in the
    // resolution both as itself and via node 5's unmerged list.
    if err := tree.SetParent(NodeIndex(5), &ParentNode{
        EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x05}, 32)),
        UnmergedLeaves: []LeafIndex{3},
    }); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    targets, err := tree.EncryptionTargets(LeafIndex(0), []LeafIndex{3})
    if err != nil {
        t.Fatalf("EncryptionTargets: %v", err)
    }
    if !equalNodeIndices(targets[1], []NodeIndex{5}) {
        t.Fatalf("targets[1] = %v, want [5] with the unmerged new leaf removed", targets[1])
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestFilteredDirectPath|TestEncryptionTargets" -v`
Expected: FAIL to compile with `tree.FilteredDirectPath undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree.go (append)

// the child of x that lies on the path from x down to leaf i, and the other child.
func (self *RatchetTree) pathChildren(x NodeIndex, i LeafIndex) (onPath, copath NodeIndex, err error) {
    left, ok := Left(x)
    if !ok {
        return 0, 0, ErrTreeMalformed
    }
    right, ok := Right(x)
    if !ok {
        return 0, 0, ErrTreeMalformed
    }
    if CommonAncestor(left, i.NodeIndex()) == left {
        return left, right, nil
    }
    return right, left, nil
}

// RFC 9420 §7.6. the direct path with every node removed whose copath child has an
// empty resolution: there is nobody under that child to encrypt to, so the node
// carries no key at all and stays blank.
func (self *RatchetTree) FilteredDirectPath(i LeafIndex) ([]NodeIndex, error) {
    if uint32(i) >= self.LeafWidth() {
        return nil, ErrLeafIndexOutOfRange
    }
    out := []NodeIndex{}
    for _, x := range DirectPath(i.NodeIndex(), self.LeafWidth()) {
        _, copath, err := self.pathChildren(x, i)
        if err != nil {
            return nil, err
        }
        if len(self.Resolution(copath)) == 0 {
            continue
        }
        out = append(out, x)
    }
    return out, nil
}

// one resolution per filtered-direct-path node, in the same order, each already
// stripped of the leaves added by this commit. RFC 9420 §7.6: a member added in the
// same commit receives the path secret in its Welcome, never in the UpdatePath.
func (self *RatchetTree) EncryptionTargets(sender LeafIndex,
    exclude []LeafIndex) ([][]NodeIndex, error) {
    path, err := self.FilteredDirectPath(sender)
    if err != nil {
        return nil, err
    }
    excluded := map[NodeIndex]bool{}
    for _, leaf := range exclude {
        excluded[leaf.NodeIndex()] = true
    }
    out := make([][]NodeIndex, 0, len(path))
    for _, x := range path {
        _, copath, err := self.pathChildren(x, sender)
        if err != nil {
            return nil, err
        }
        resolution := self.Resolution(copath)
        kept := make([]NodeIndex, 0, len(resolution))
        for _, y := range resolution {
            if excluded[y] {
                continue
            }
            kept = append(kept, y)
        }
        out = append(out, kept)
    }
    return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestFilteredDirectPath|TestEncryptionTargets" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree.go mls/tree_test.go
git commit -m "feat(mls): filtered direct path and copath encryption targets"
```

---

### Task 17: Path secrets and the private TreeKEM state

**Files:**
- Create: `mls/treekem.go`
- Test: `mls/treekem_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.DeriveSecret`, `CryptoProvider.DeriveKeyPair`, `CryptoProvider.HashSize` (Crypto plan); `ErrNoPathSecret`, `ErrPathSecretMismatch` (Task 2).
- Produces:
  - `func DerivePathSecrets(crypto CryptoProvider, initial []byte, count int) [][]byte` — `path_secret[0] = initial`, `path_secret[n] = DeriveSecret(path_secret[n-1], "path")`, returning `count+1` values so the caller has the one beyond the root that becomes the commit secret.
  - `func DeriveNodeKeyPair(crypto CryptoProvider, pathSecret []byte) (HpkePrivateKey, HpkePublicKey, error)` — `node_secret = DeriveSecret(path_secret, "node")`, then `KEM.DeriveKeyPair(node_secret)`.
  - `TreeKEMPrivate` with `NewTreeKEMPrivate`, `Clone`, `NodePrivateKey`, `Consistent`.

The leaf's own HPKE key pair is **not** derived from `path_secret[0]`: everyone who decrypts
`path_secret[0]` would then hold the sender's leaf private key. It is sampled independently in
Task 19.

- [ ] **Step 1: Write the failing test**

```go
// mls/treekem_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"
)

func TestDerivePathSecretsIsALadder(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    initial := crypto.Random(crypto.HashSize())
    secrets := DerivePathSecrets(crypto, initial, 3)
    if len(secrets) != 4 {
        t.Fatalf("len = %d, want count+1", len(secrets))
    }
    if !bytes.Equal(secrets[0], initial) {
        t.Fatalf("path_secret[0] is not the initial secret")
    }
    for i := 1; i < len(secrets); i++ {
        want := crypto.DeriveSecret(secrets[i-1], "path")
        if !bytes.Equal(secrets[i], want) {
            t.Fatalf("path_secret[%d] is not DeriveSecret(path_secret[%d], \"path\")", i, i-1)
        }
        if bytes.Equal(secrets[i], secrets[i-1]) {
            t.Fatalf("path_secret[%d] equals its predecessor", i)
        }
    }
}

func TestDeriveNodeKeyPairIsDeterministicAndDistinctFromThePathSecret(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    pathSecret := crypto.Random(crypto.HashSize())
    priv1, pub1, err := DeriveNodeKeyPair(crypto, pathSecret)
    if err != nil {
        t.Fatalf("DeriveNodeKeyPair: %v", err)
    }
    priv2, pub2, err := DeriveNodeKeyPair(crypto, pathSecret)
    if err != nil {
        t.Fatalf("DeriveNodeKeyPair: %v", err)
    }
    if !bytes.Equal(pub1, pub2) || !bytes.Equal(priv1, priv2) {
        t.Fatalf("DeriveNodeKeyPair is not deterministic")
    }
    _, otherPub, err := DeriveNodeKeyPair(crypto, crypto.DeriveSecret(pathSecret, "path"))
    if err != nil {
        t.Fatalf("DeriveNodeKeyPair: %v", err)
    }
    if bytes.Equal(pub1, otherPub) {
        t.Fatalf("two rungs of the ladder derive the same key pair")
    }
}

func TestTreeKEMPrivateNodePrivateKeyAndConsistency(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    priv := NewTreeKEMPrivate(members[0].LeafIndex, members[0].EncryptionPriv)

    // the leaf's own key is always available.
    got, ok, err := priv.NodePrivateKey(crypto, members[0].LeafIndex.NodeIndex())
    if err != nil || !ok {
        t.Fatalf("NodePrivateKey(own leaf) = (_, %v, %v)", ok, err)
    }
    if !bytes.Equal(got, members[0].EncryptionPriv) {
        t.Fatalf("NodePrivateKey(own leaf) is not the leaf private key")
    }
    if _, ok, _ := priv.NodePrivateKey(crypto, NodeIndex(1)); ok {
        t.Fatalf("NodePrivateKey(1) is available with no path secret held")
    }

    // holding a path secret for node 1 makes node 1's key available, and Consistent
    // agrees with the tree only when the tree carries the derived public key.
    pathSecret := crypto.Random(crypto.HashSize())
    _, pub, err := DeriveNodeKeyPair(crypto, pathSecret)
    if err != nil {
        t.Fatalf("DeriveNodeKeyPair: %v", err)
    }
    priv.PathSecrets[NodeIndex(1)] = pathSecret
    if err := priv.Consistent(crypto, tree); !errors.Is(err, ErrPathSecretMismatch) {
        t.Fatalf("Consistent with a blank node 1 err = %v, want ErrPathSecretMismatch", err)
    }
    if err := tree.SetParent(NodeIndex(1), &ParentNode{EncryptionKey: pub}); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    if err := priv.Consistent(crypto, tree); err != nil {
        t.Fatalf("Consistent: %v", err)
    }
    clone := priv.Clone()
    clone.PathSecrets[NodeIndex(1)][0] ^= 0xFF
    if bytes.Equal(clone.PathSecrets[NodeIndex(1)], priv.PathSecrets[NodeIndex(1)]) {
        t.Fatalf("Clone shares path secret backing arrays")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestDerivePathSecrets|TestDeriveNodeKeyPair|TestTreeKEMPrivate" -v`
Expected: FAIL to compile with `undefined: DerivePathSecrets`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go
package mls

import (
    "crypto/subtle"

    "github.com/urnetwork/connect/mls/syntax"
)

// RFC 9420 §7.4. one rung per node in the filtered direct path, plus one beyond the
// root, which §8.1 makes the commit secret.
func DerivePathSecrets(crypto CryptoProvider, initial []byte, count int) [][]byte {
    out := make([][]byte, 0, count+1)
    out = append(out, cloneBytes(initial))
    for i := 0; i < count; i++ {
        out = append(out, crypto.DeriveSecret(out[len(out)-1], "path"))
    }
    return out
}

// RFC 9420 §7.4: node_secret = DeriveSecret(path_secret, "node"), then the KEM key
// pair is derived from it. deterministic, so every member that learns a path secret
// derives the identical node key.
func DeriveNodeKeyPair(crypto CryptoProvider, pathSecret []byte) (HpkePrivateKey, HpkePublicKey, error) {
    return crypto.DeriveKeyPair(crypto.DeriveSecret(pathSecret, "node"))
}

// what one member holds privately about the tree: its own leaf HPKE key and the path
// secrets it has learned, keyed by the node each secret belongs to. never serialized
// by this package — the state store seals it (Spec A §3.5).
type TreeKEMPrivate struct {
    LeafIndex      LeafIndex
    EncryptionPriv HpkePrivateKey
    PathSecrets    map[NodeIndex][]byte
}

func NewTreeKEMPrivate(i LeafIndex, encryptionPriv HpkePrivateKey) *TreeKEMPrivate {
    return &TreeKEMPrivate{
        LeafIndex:      i,
        EncryptionPriv: cloneBytes(encryptionPriv),
        PathSecrets:    map[NodeIndex][]byte{},
    }
}

func (self *TreeKEMPrivate) Clone() *TreeKEMPrivate {
    out := NewTreeKEMPrivate(self.LeafIndex, self.EncryptionPriv)
    for x, secret := range self.PathSecrets {
        out.PathSecrets[x] = cloneBytes(secret)
    }
    return out
}

// the HPKE private key for a node, if this member can derive one: its own leaf, or
// any node it holds a path secret for.
func (self *TreeKEMPrivate) NodePrivateKey(crypto CryptoProvider,
    x NodeIndex) (HpkePrivateKey, bool, error) {
    if x == self.LeafIndex.NodeIndex() {
        return self.EncryptionPriv, true, nil
    }
    secret, ok := self.PathSecrets[x]
    if !ok {
        return nil, false, nil
    }
    priv, _, err := DeriveNodeKeyPair(crypto, secret)
    if err != nil {
        return nil, false, err
    }
    return priv, true, nil
}

// every path secret held must derive the public key the tree carries at that node,
// and the leaf private key must match the leaf. this is the check the TreeKEM vector
// makes on the private state it supplies, and it catches a tree and a private state
// that have drifted an epoch apart.
func (self *TreeKEMPrivate) Consistent(crypto CryptoProvider, tree *RatchetTree) error {
    if tree.Leaf(self.LeafIndex) == nil {
        return ErrPathSecretMismatch
    }
    for x, secret := range self.PathSecrets {
        parent := tree.ParentAt(x)
        if parent == nil {
            return ErrPathSecretMismatch
        }
        _, pub, err := DeriveNodeKeyPair(crypto, secret)
        if err != nil {
            return err
        }
        if subtle.ConstantTimeCompare(pub, parent.EncryptionKey) != 1 {
            return ErrPathSecretMismatch
        }
    }
    return nil
}
```

`Consistent` deliberately does not re-derive the leaf public key from `EncryptionPriv`: the
`CryptoProvider` surface has no private-to-public operation, and the leaf key pair is checked where
both halves exist — in `DecryptUpdatePath` (Task 22), which compares each derived public key against
the one in the `UpdatePath`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestDerivePathSecrets|TestDeriveNodeKeyPair|TestTreeKEMPrivate" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/treekem.go mls/treekem_test.go
git commit -m "feat(mls): path secret ladder, node key derivation and private TreeKEM state"
```

---

### Task 18: Creating an UpdatePath's secrets, keys and parent hashes

**Files:**
- Modify: `mls/treekem.go`
- Test: `mls/treekem_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Random`, `CryptoProvider.HashSize`, `CryptoProvider.DeriveKeyPair` (Crypto plan); `FilteredDirectPath`, `BlankDirectPath`, `SetParent`, `SetLeaf`, `pathChildren` (Tasks 8, 15, 16); `ParentHash` (Task 13); `LeafNode.Sign` (Task 6).
- Produces: `UpdatePathPlan{Path []NodeIndex; PathSecrets [][]byte; PublicKeys []HpkePublicKey; LeafNode *LeafNode; CommitSecret []byte; Private *TreeKEMPrivate}` and
  `func (self *RatchetTree) CreateUpdatePathSecrets(crypto CryptoProvider, sender LeafIndex, signer SignaturePrivateKey, groupId []byte) (*UpdatePathPlan, error)`.

The method **mutates the tree**: it blanks the sender's direct path, installs the fresh public keys
and the parent-hash chain on the filtered path, and installs the re-signed leaf. After it returns,
`TreeHash` is the new epoch's tree hash and the caller can build the GroupContext that Task 20 needs.
`CommitSecret` is `DeriveSecret(path_secret[last], "path")` — the rung past the root, RFC 9420 §8.1.

Parent hashes are assigned top-down: the root's `parent_hash` is zero-length, each lower filtered
node carries the parent hash of the node above it taken with that node's copath child, and the leaf
carries the parent hash of the lowest filtered node. The receiver in Task 21 recomputes exactly this
chain, which is why nothing but the encryption keys travels on the wire.

- [ ] **Step 1: Write the failing test**

```go
// mls/treekem_test.go (append)

func TestCreateUpdatePathSecretsInstallsAChainThatVerifies(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    for _, n := range []uint32{2, 3, 4, 7, 8} {
        tree, members := newTestTree(t, crypto, n)
        plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
            members[0].SignaturePriv, testGroupId())
        if err != nil {
            t.Fatalf("n=%d CreateUpdatePathSecrets: %v", n, err)
        }
        if len(plan.Path) == 0 {
            t.Fatalf("n=%d the filtered direct path is empty in a group of more than one", n)
        }
        if len(plan.PathSecrets) != len(plan.Path) {
            t.Fatalf("n=%d %d path secrets for %d nodes", n, len(plan.PathSecrets), len(plan.Path))
        }
        if len(plan.PublicKeys) != len(plan.Path) {
            t.Fatalf("n=%d %d public keys for %d nodes", n, len(plan.PublicKeys), len(plan.Path))
        }
        if len(plan.CommitSecret) != crypto.HashSize() {
            t.Fatalf("n=%d commit secret length = %d", n, len(plan.CommitSecret))
        }
        want := crypto.DeriveSecret(plan.PathSecrets[len(plan.PathSecrets)-1], "path")
        if !bytes.Equal(plan.CommitSecret, want) {
            t.Fatalf("n=%d commit secret is not the rung past the root", n)
        }
        for i, x := range plan.Path {
            parent := tree.ParentAt(x)
            if parent == nil {
                t.Fatalf("n=%d node %d was not installed", n, x)
            }
            if !bytes.Equal(parent.EncryptionKey, plan.PublicKeys[i]) {
                t.Fatalf("n=%d node %d carries a different key from the plan", n, x)
            }
            if len(parent.UnmergedLeaves) != 0 {
                t.Fatalf("n=%d node %d kept unmerged leaves across a fresh path", n, x)
            }
            _, derived, err := DeriveNodeKeyPair(crypto, plan.PathSecrets[i])
            if err != nil {
                t.Fatalf("n=%d DeriveNodeKeyPair: %v", n, err)
            }
            if !bytes.Equal(derived, plan.PublicKeys[i]) {
                t.Fatalf("n=%d node %d public key is not derived from its path secret", n, x)
            }
        }
        leaf := tree.Leaf(members[0].LeafIndex)
        if leaf.LeafNodeSource != LeafNodeSourceCommit {
            t.Fatalf("n=%d leaf source = %d, want commit", n, leaf.LeafNodeSource)
        }
        if len(leaf.ParentHash) != crypto.HashSize() {
            t.Fatalf("n=%d leaf parent hash length = %d", n, len(leaf.ParentHash))
        }
        if err := leaf.VerifySignature(crypto, testGroupId(), members[0].LeafIndex); err != nil {
            t.Fatalf("n=%d the re-signed leaf does not verify: %v", n, err)
        }
        if err := tree.VerifyParentHashes(crypto); err != nil {
            t.Fatalf("n=%d VerifyParentHashes after a fresh path: %v", n, err)
        }
    }
}

func TestCreateUpdatePathSecretsGivesTheLeafAnIndependentKey(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    before := cloneBytes(tree.Leaf(members[0].LeafIndex).EncryptionKey)
    plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, testGroupId())
    if err != nil {
        t.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    after := tree.Leaf(members[0].LeafIndex).EncryptionKey
    if bytes.Equal(before, after) {
        t.Fatalf("the leaf encryption key was not rotated")
    }
    // the leaf key must NOT be derivable from path_secret[0]: everyone who decrypts
    // that secret would otherwise hold the sender's leaf private key.
    _, fromPathSecret, err := DeriveNodeKeyPair(crypto, plan.PathSecrets[0])
    if err != nil {
        t.Fatalf("DeriveNodeKeyPair: %v", err)
    }
    if bytes.Equal(after, fromPathSecret) {
        t.Fatalf("the leaf key is derived from path_secret[0]")
    }
    if len(plan.Private.EncryptionPriv) == 0 {
        t.Fatalf("the plan's private state carries no leaf private key")
    }
    if plan.Private.LeafIndex != members[0].LeafIndex {
        t.Fatalf("private state leaf index = %d", plan.Private.LeafIndex)
    }
    for i, x := range plan.Path {
        if !bytes.Equal(plan.Private.PathSecrets[x], plan.PathSecrets[i]) {
            t.Fatalf("private state is missing the path secret for node %d", x)
        }
    }
    if err := plan.Private.Consistent(crypto, tree); err != nil {
        t.Fatalf("Consistent: %v", err)
    }
}

func TestCreateUpdatePathSecretsInASingleMemberGroup(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 1)
    plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, testGroupId())
    if err != nil {
        t.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    if len(plan.Path) != 0 {
        t.Fatalf("path = %v, want empty", plan.Path)
    }
    if len(plan.CommitSecret) != crypto.HashSize() {
        t.Fatalf("commit secret length = %d", len(plan.CommitSecret))
    }
    leaf := tree.Leaf(members[0].LeafIndex)
    if leaf.LeafNodeSource != LeafNodeSourceCommit || len(leaf.ParentHash) != 0 {
        t.Fatalf("a lone member's leaf must be a commit leaf with a zero-length parent hash, got source %d and %d bytes",
            leaf.LeafNodeSource, len(leaf.ParentHash))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestCreateUpdatePathSecrets -v`
Expected: FAIL to compile with `tree.CreateUpdatePathSecrets undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go (append)

// everything the sender computed before any encryption happened. the tree already
// carries the public half; the caller now computes the new tree hash, builds the new
// GroupContext, and calls EncryptUpdatePath with this plan.
type UpdatePathPlan struct {
    Path         []NodeIndex
    PathSecrets  [][]byte
    PublicKeys   []HpkePublicKey
    LeafNode     *LeafNode
    CommitSecret []byte
    Private      *TreeKEMPrivate
}

func (self *RatchetTree) CreateUpdatePathSecrets(crypto CryptoProvider, sender LeafIndex,
    signer SignaturePrivateKey, groupId []byte) (*UpdatePathPlan, error) {
    current := self.Leaf(sender)
    if current == nil {
        return nil, ErrLeafIndexOutOfRange
    }
    path, err := self.FilteredDirectPath(sender)
    if err != nil {
        return nil, err
    }
    // the ladder: one secret per filtered node, plus the rung past the root.
    ladder := DerivePathSecrets(crypto, crypto.Random(crypto.HashSize()), len(path))
    pathSecrets := ladder[:len(path)]
    commitSecret := ladder[len(ladder)-1]

    publicKeys := make([]HpkePublicKey, len(path))
    private := NewTreeKEMPrivate(sender, nil)
    for i := range path {
        _, pub, err := DeriveNodeKeyPair(crypto, pathSecrets[i])
        if err != nil {
            return nil, err
        }
        publicKeys[i] = pub
        private.PathSecrets[path[i]] = cloneBytes(pathSecrets[i])
    }

    // the leaf key pair is sampled independently: deriving it from path_secret[0]
    // would hand the sender's leaf private key to everyone who decrypts that secret.
    leafPriv, leafPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
    if err != nil {
        return nil, err
    }
    private.EncryptionPriv = cloneBytes(leafPriv)

    if err := self.BlankDirectPath(sender); err != nil {
        return nil, err
    }
    for i, x := range path {
        if err := self.SetParent(x, &ParentNode{EncryptionKey: publicKeys[i]}); err != nil {
            return nil, err
        }
    }

    // parent hashes, top-down: the root carries a zero-length parent hash, and every
    // node below carries the parent hash of the node above it.
    carried := []byte{}
    for i := len(path) - 1; i >= 0; i-- {
        _, copath, err := self.pathChildren(path[i], sender)
        if err != nil {
            return nil, err
        }
        parent := self.ParentAt(path[i])
        parent.ParentHash = carried
        hash, err := self.ParentHash(crypto, path[i], copath)
        if err != nil {
            return nil, err
        }
        carried = hash
    }

    leaf := current.Clone()
    leaf.EncryptionKey = leafPub
    leaf.LeafNodeSource = LeafNodeSourceCommit
    leaf.ParentHash = carried
    if err := leaf.Sign(crypto, signer, groupId, sender); err != nil {
        return nil, err
    }
    if err := self.SetLeaf(sender, leaf); err != nil {
        return nil, err
    }

    return &UpdatePathPlan{
        Path:         path,
        PathSecrets:  pathSecrets,
        PublicKeys:   publicKeys,
        LeafNode:     leaf,
        CommitSecret: commitSecret,
        Private:      private,
    }, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestCreateUpdatePathSecrets -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/treekem.go mls/treekem_test.go
git commit -m "feat(mls): UpdatePath secret and parent hash generation"
```

---

### Task 19: The UpdatePath wire types

**Files:**
- Modify: `mls/treekem.go`
- Test: `mls/treekem_test.go`

**Interfaces:**
- Consumes: `syntax.*` (Syntax plan); `LeafNode` codec (Task 5).
- Produces: `HpkeCiphertext{KemOutput, Ciphertext []byte}`, `UpdatePathNode{EncryptionKey HpkePublicKey; EncryptedPathSecret []HpkeCiphertext}`, `UpdatePath{LeafNode LeafNode; Nodes []UpdatePathNode}`, and `MarshalTo` / `Marshal` / `UnmarshalUpdatePath` / `ParseUpdatePath`. `HpkeCiphertext` is also what `Welcome`'s `EncryptedGroupSecrets` uses, so the Group lifecycle plan consumes it from here rather than defining a second copy.

```
struct { opaque kem_output<V>; opaque ciphertext<V>; } HPKECiphertext;
struct { HPKEPublicKey encryption_key; HPKECiphertext encrypted_path_secret<V>; } UpdatePathNode;
struct { LeafNode leaf_node; UpdatePathNode nodes<V>; } UpdatePath;
```

- [ ] **Step 1: Write the failing test**

```go
// mls/treekem_test.go (append)

func TestUpdatePathRoundTrip(t *testing.T) {
    leaf := testLeafNodeTemplate()
    leaf.LeafNodeSource = LeafNodeSourceCommit
    leaf.ParentHash = bytes.Repeat([]byte{0x44}, 32)
    in := &UpdatePath{
        LeafNode: *leaf,
        Nodes: []UpdatePathNode{
            {
                EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0x01}, 32)),
                EncryptedPathSecret: []HpkeCiphertext{
                    {KemOutput: bytes.Repeat([]byte{0x02}, 32), Ciphertext: bytes.Repeat([]byte{0x03}, 48)},
                    {KemOutput: bytes.Repeat([]byte{0x04}, 32), Ciphertext: bytes.Repeat([]byte{0x05}, 48)},
                },
            },
            {
                EncryptionKey:       HpkePublicKey(bytes.Repeat([]byte{0x06}, 32)),
                EncryptedPathSecret: []HpkeCiphertext{},
            },
        },
    }
    encoded, err := in.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out, err := ParseUpdatePath(encoded)
    if err != nil {
        t.Fatalf("ParseUpdatePath: %v", err)
    }
    reencoded, err := out.Marshal()
    if err != nil {
        t.Fatalf("re-Marshal: %v", err)
    }
    if !bytes.Equal(reencoded, encoded) {
        t.Fatalf("re-encode differs")
    }
    if len(out.Nodes) != 2 {
        t.Fatalf("nodes = %d, want 2", len(out.Nodes))
    }
    if len(out.Nodes[0].EncryptedPathSecret) != 2 || len(out.Nodes[1].EncryptedPathSecret) != 0 {
        t.Fatalf("ciphertext counts = (%d, %d), want (2, 0)",
            len(out.Nodes[0].EncryptedPathSecret), len(out.Nodes[1].EncryptedPathSecret))
    }
    if !bytes.Equal(out.LeafNode.ParentHash, in.LeafNode.ParentHash) {
        t.Fatalf("leaf parent hash did not survive the round trip")
    }
}

func TestUpdatePathRejectsTrailingBytes(t *testing.T) {
    leaf := testLeafNodeTemplate()
    leaf.LeafNodeSource = LeafNodeSourceCommit
    leaf.ParentHash = bytes.Repeat([]byte{0x44}, 32)
    in := &UpdatePath{LeafNode: *leaf, Nodes: []UpdatePathNode{}}
    encoded, err := in.Marshal()
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if _, err := ParseUpdatePath(append(encoded, 0x00)); err == nil {
        t.Fatalf("ParseUpdatePath(trailing) = nil error, want failure")
    }
    if _, err := ParseUpdatePath(encoded[:len(encoded)-1]); err == nil {
        t.Fatalf("ParseUpdatePath(truncated) = nil error, want failure")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestUpdatePath -v`
Expected: FAIL to compile with `undefined: UpdatePath`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go (append)

// RFC 9420 §6.1. one HPKE encryption: the KEM output and the AEAD ciphertext.
type HpkeCiphertext struct {
    KemOutput  []byte
    Ciphertext []byte
}

func (self *HpkeCiphertext) MarshalTo(w *syntax.Writer) error {
    w.WriteOpaqueVec(self.KemOutput)
    w.WriteOpaqueVec(self.Ciphertext)
    return nil
}

func UnmarshalHpkeCiphertext(r *syntax.Reader) (HpkeCiphertext, error) {
    kemOutput, err := r.ReadOpaqueVec()
    if err != nil {
        return HpkeCiphertext{}, err
    }
    ciphertext, err := r.ReadOpaqueVec()
    if err != nil {
        return HpkeCiphertext{}, err
    }
    return HpkeCiphertext{KemOutput: kemOutput, Ciphertext: ciphertext}, nil
}

// RFC 9420 §7.6. one node of the sender's filtered direct path: its new public key
// and the path secret encrypted once per node in the copath child's resolution.
type UpdatePathNode struct {
    EncryptionKey       HpkePublicKey
    EncryptedPathSecret []HpkeCiphertext
}

func (self *UpdatePathNode) MarshalTo(w *syntax.Writer) error {
    w.WriteOpaqueVec(self.EncryptionKey)
    inner := syntax.NewWriter()
    for i := range self.EncryptedPathSecret {
        if err := self.EncryptedPathSecret[i].MarshalTo(inner); err != nil {
            return err
        }
    }
    w.WriteOpaqueVec(inner.Bytes())
    return nil
}

func UnmarshalUpdatePathNode(r *syntax.Reader) (UpdatePathNode, error) {
    encryptionKey, err := r.ReadOpaqueVec()
    if err != nil {
        return UpdatePathNode{}, err
    }
    sub, err := r.ReadVecReader()
    if err != nil {
        return UpdatePathNode{}, err
    }
    ciphertexts := []HpkeCiphertext{}
    for !sub.Empty() {
        ct, err := UnmarshalHpkeCiphertext(sub)
        if err != nil {
            return UpdatePathNode{}, err
        }
        ciphertexts = append(ciphertexts, ct)
    }
    return UpdatePathNode{
        EncryptionKey:       HpkePublicKey(encryptionKey),
        EncryptedPathSecret: ciphertexts,
    }, nil
}

// RFC 9420 §7.6.
type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode
}

func (self *UpdatePath) MarshalTo(w *syntax.Writer) error {
    if err := self.LeafNode.MarshalTo(w); err != nil {
        return err
    }
    inner := syntax.NewWriter()
    for i := range self.Nodes {
        if err := self.Nodes[i].MarshalTo(inner); err != nil {
            return err
        }
    }
    w.WriteOpaqueVec(inner.Bytes())
    return nil
}

func (self *UpdatePath) Marshal() ([]byte, error) {
    w := syntax.NewWriter()
    if err := self.MarshalTo(w); err != nil {
        return nil, err
    }
    return w.Bytes(), nil
}

func UnmarshalUpdatePath(r *syntax.Reader) (*UpdatePath, error) {
    leaf, err := UnmarshalLeafNode(r)
    if err != nil {
        return nil, err
    }
    sub, err := r.ReadVecReader()
    if err != nil {
        return nil, err
    }
    nodes := []UpdatePathNode{}
    for !sub.Empty() {
        node, err := UnmarshalUpdatePathNode(sub)
        if err != nil {
            return nil, err
        }
        nodes = append(nodes, node)
    }
    return &UpdatePath{LeafNode: *leaf, Nodes: nodes}, nil
}

func ParseUpdatePath(data []byte) (*UpdatePath, error) {
    r := syntax.NewReader(data)
    path, err := UnmarshalUpdatePath(r)
    if err != nil {
        return nil, err
    }
    if !r.Empty() {
        return nil, syntax.ErrTrailingBytes
    }
    return path, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestUpdatePath -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/treekem.go mls/treekem_test.go
git commit -m "feat(mls): UpdatePath, UpdatePathNode and HpkeCiphertext wire types"
```

---

### Task 20: Encrypting the path secrets to the copath resolutions

**Files:**
- Modify: `mls/treekem.go`
- Test: `mls/treekem_test.go`

**Interfaces:**
- Consumes: `EncryptWithLabel` (Crypto/HPKE plan); `EncryptionTargets` (Task 16); `UpdatePathPlan` (Task 18); `UpdatePath` (Task 19).
- Produces: `func (self *RatchetTree) EncryptUpdatePath(crypto CryptoProvider, plan *UpdatePathPlan, sender LeafIndex, groupContext []byte, exclude []LeafIndex) (*UpdatePath, error)`.

Each path secret is sealed with `EncryptWithLabel(pub, "UpdatePathNode", groupContext, path_secret)`,
once per node of the copath child's resolution, **in resolution order** — the receiver locates its
ciphertext by index into the same resolution, so the ordering is load-bearing. `groupContext` is the
serialized GroupContext of the epoch the commit opens, whose `tree_hash` is the tree hash **after**
Task 18 mutated the tree.

- [ ] **Step 1: Write the failing test**

```go
// mls/treekem_test.go (append)

func TestEncryptUpdatePathProducesOneCiphertextPerResolutionNode(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    targets, err := tree.EncryptionTargets(members[0].LeafIndex, nil)
    if err != nil {
        t.Fatalf("EncryptionTargets: %v", err)
    }
    plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, testGroupId())
    if err != nil {
        t.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    treeHash, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    groupContext := append([]byte("test-group-context"), treeHash...)
    path, err := tree.EncryptUpdatePath(crypto, plan, members[0].LeafIndex, groupContext, nil)
    if err != nil {
        t.Fatalf("EncryptUpdatePath: %v", err)
    }
    if len(path.Nodes) != len(plan.Path) {
        t.Fatalf("nodes = %d, want %d", len(path.Nodes), len(plan.Path))
    }
    for i := range path.Nodes {
        if !bytes.Equal(path.Nodes[i].EncryptionKey, plan.PublicKeys[i]) {
            t.Fatalf("node %d key differs from the plan", i)
        }
        if len(path.Nodes[i].EncryptedPathSecret) != len(targets[i]) {
            t.Fatalf("node %d has %d ciphertexts for %d resolution entries",
                i, len(path.Nodes[i].EncryptedPathSecret), len(targets[i]))
        }
        for j, ct := range path.Nodes[i].EncryptedPathSecret {
            if len(ct.KemOutput) == 0 || len(ct.Ciphertext) == 0 {
                t.Fatalf("node %d ciphertext %d is empty", i, j)
            }
        }
    }
    if !bytes.Equal(path.LeafNode.ParentHash, plan.LeafNode.ParentHash) {
        t.Fatalf("the update path carries a different leaf from the plan")
    }
}

func TestEncryptUpdatePathIsDecryptableByAResolutionMember(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, testGroupId())
    if err != nil {
        t.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    groupContext := []byte("context")
    path, err := tree.EncryptUpdatePath(crypto, plan, members[0].LeafIndex, groupContext, nil)
    if err != nil {
        t.Fatalf("EncryptUpdatePath: %v", err)
    }
    // leaf 1 is the whole resolution of node 1's copath child, so its ciphertext is
    // the only one at index 0 and it must open with leaf 1's private key.
    ct := path.Nodes[0].EncryptedPathSecret[0]
    got, err := DecryptWithLabel(crypto, members[1].EncryptionPriv, "UpdatePathNode",
        groupContext, ct.KemOutput, ct.Ciphertext)
    if err != nil {
        t.Fatalf("DecryptWithLabel: %v", err)
    }
    if !bytes.Equal(got, plan.PathSecrets[0]) {
        t.Fatalf("decrypted secret is not path_secret[0]")
    }
    // a different context must not open it.
    if _, err := DecryptWithLabel(crypto, members[1].EncryptionPriv, "UpdatePathNode",
        []byte("other"), ct.KemOutput, ct.Ciphertext); err == nil {
        t.Fatalf("the ciphertext opened under a different group context")
    }
}

func TestEncryptUpdatePathSkipsExcludedLeaves(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    plan, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, testGroupId())
    if err != nil {
        t.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    path, err := tree.EncryptUpdatePath(crypto, plan, members[0].LeafIndex,
        []byte("context"), []LeafIndex{3})
    if err != nil {
        t.Fatalf("EncryptUpdatePath: %v", err)
    }
    if len(path.Nodes[1].EncryptedPathSecret) != 1 {
        t.Fatalf("node 1 has %d ciphertexts, want 1 with leaf 3 excluded",
            len(path.Nodes[1].EncryptedPathSecret))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestEncryptUpdatePath -v`
Expected: FAIL to compile with `tree.EncryptUpdatePath undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go (append)

// RFC 9420 §7.6 label for every path secret encryption.
const updatePathNodeLabel = "UpdatePathNode"

// seal each path secret to the resolution of the corresponding copath child, in
// resolution order. the receiver finds its ciphertext by index into the same
// resolution, so the order is part of the contract, not an implementation detail.
func (self *RatchetTree) EncryptUpdatePath(crypto CryptoProvider, plan *UpdatePathPlan,
    sender LeafIndex, groupContext []byte, exclude []LeafIndex) (*UpdatePath, error) {
    targets, err := self.EncryptionTargets(sender, exclude)
    if err != nil {
        return nil, err
    }
    if len(targets) != len(plan.Path) {
        return nil, ErrPathLength
    }
    nodes := make([]UpdatePathNode, 0, len(plan.Path))
    for i := range plan.Path {
        ciphertexts := make([]HpkeCiphertext, 0, len(targets[i]))
        for _, y := range targets[i] {
            pub, err := self.nodeEncryptionKey(y)
            if err != nil {
                return nil, err
            }
            kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, updatePathNodeLabel,
                groupContext, plan.PathSecrets[i])
            if err != nil {
                return nil, err
            }
            ciphertexts = append(ciphertexts, HpkeCiphertext{
                KemOutput:  kemOutput,
                Ciphertext: ciphertext,
            })
        }
        nodes = append(nodes, UpdatePathNode{
            EncryptionKey:       plan.PublicKeys[i],
            EncryptedPathSecret: ciphertexts,
        })
    }
    return &UpdatePath{LeafNode: *plan.LeafNode, Nodes: nodes}, nil
}

// the HPKE public key at a node, whichever kind of node it is.
func (self *RatchetTree) nodeEncryptionKey(x NodeIndex) (HpkePublicKey, error) {
    node := self.Get(x)
    if node == nil {
        return nil, ErrNodeIndexOutOfRange
    }
    if node.Leaf != nil {
        return node.Leaf.EncryptionKey, nil
    }
    if node.Parent != nil {
        return node.Parent.EncryptionKey, nil
    }
    return nil, ErrTreeMalformed
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestEncryptUpdatePath -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/treekem.go mls/treekem_test.go
git commit -m "feat(mls): encrypt UpdatePath secrets to each copath resolution"
```

---

### Task 21: Merging a received UpdatePath into the public tree

**Files:**
- Modify: `mls/treekem.go`
- Test: `mls/treekem_test.go`

**Interfaces:**
- Consumes: `FilteredDirectPath`, `BlankDirectPath`, `SetParent`, `SetLeaf`, `pathChildren` (Tasks 8, 15, 16); `ParentHash` (Task 13); `ErrPathLength` (ValSem202, Validation plan); `ErrParentHashMismatch` (Task 2).
- Produces: `func (self *RatchetTree) MergeUpdatePath(crypto CryptoProvider, sender LeafIndex, path *UpdatePath) error`.

The receiver gets only the encryption keys on the wire, so it **recomputes** the parent-hash chain
exactly as Task 18 built it and compares the result to the leaf's `parent_hash` field. A mismatch is
`ErrParentHashMismatch`; a path of the wrong length is `ErrPathLength` (ValSem202). On failure the
tree is left untouched, because the caller may still be processing other proposals against it — the
method works on a clone and swaps it in only on success.

- [ ] **Step 1: Write the failing test**

```go
// mls/treekem_test.go (append)

// the sender's half of one commit, ready for a receiver.
func createAndEncryptPath(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
    member *testMember, exclude []LeafIndex) (*RatchetTree, *UpdatePath, *UpdatePathPlan, []byte) {
    t.Helper()
    senderTree := tree.Clone()
    plan, err := senderTree.CreateUpdatePathSecrets(crypto, member.LeafIndex,
        member.SignaturePriv, testGroupId())
    if err != nil {
        t.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    treeHash, err := senderTree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    groupContext := append([]byte("urmessage/treekem-test/"), treeHash...)
    path, err := senderTree.EncryptUpdatePath(crypto, plan, member.LeafIndex, groupContext, exclude)
    if err != nil {
        t.Fatalf("EncryptUpdatePath: %v", err)
    }
    return senderTree, path, plan, groupContext
}

func TestMergeUpdatePathReproducesTheSendersTree(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    for _, n := range []uint32{2, 3, 4, 7, 8} {
        tree, members := newTestTree(t, crypto, n)
        senderTree, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
        receiverTree := tree.Clone()
        if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, path); err != nil {
            t.Fatalf("n=%d MergeUpdatePath: %v", n, err)
        }
        wantHash, err := senderTree.TreeHash(crypto)
        if err != nil {
            t.Fatalf("n=%d sender TreeHash: %v", n, err)
        }
        gotHash, err := receiverTree.TreeHash(crypto)
        if err != nil {
            t.Fatalf("n=%d receiver TreeHash: %v", n, err)
        }
        if !bytes.Equal(gotHash, wantHash) {
            t.Fatalf("n=%d the merged tree hash differs from the sender's", n)
        }
        if err := receiverTree.VerifyParentHashes(crypto); err != nil {
            t.Fatalf("n=%d VerifyParentHashes: %v", n, err)
        }
    }
}

func TestValSem202_PathLength(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
    short := &UpdatePath{LeafNode: path.LeafNode, Nodes: path.Nodes[:len(path.Nodes)-1]}
    receiverTree := tree.Clone()
    if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, short); !errors.Is(err, ErrPathLength) {
        t.Fatalf("short path err = %v, want ErrPathLength", err)
    }
    long := &UpdatePath{LeafNode: path.LeafNode, Nodes: append(append([]UpdatePathNode{}, path.Nodes...), path.Nodes[0])}
    if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, long); !errors.Is(err, ErrPathLength) {
        t.Fatalf("long path err = %v, want ErrPathLength", err)
    }
}

func TestMergeUpdatePathRejectsATamperedNodeKey(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
    tampered := &UpdatePath{LeafNode: path.LeafNode, Nodes: append([]UpdatePathNode{}, path.Nodes...)}
    tampered.Nodes[len(tampered.Nodes)-1].EncryptionKey =
        HpkePublicKey(bytes.Repeat([]byte{0xEE}, len(path.Nodes[0].EncryptionKey)))
    receiverTree := tree.Clone()
    if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, tampered); !errors.Is(err, ErrParentHashMismatch) {
        t.Fatalf("err = %v, want ErrParentHashMismatch", err)
    }
    // and the tree is untouched on failure.
    before, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    after, err := receiverTree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    if !bytes.Equal(before, after) {
        t.Fatalf("a failed MergeUpdatePath mutated the tree")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestMergeUpdatePath|TestValSem202" -v`
Expected: FAIL to compile with `receiverTree.MergeUpdatePath undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go (append)

// install a received UpdatePath's public half. only the encryption keys travel, so
// the parent hash chain is recomputed here and checked against the leaf's own
// parent_hash field — which is signed, so a tampered node key cannot be made to fit.
// the tree is mutated only when every check has passed.
func (self *RatchetTree) MergeUpdatePath(crypto CryptoProvider, sender LeafIndex,
    path *UpdatePath) error {
    if self.Leaf(sender) == nil {
        return ErrLeafIndexOutOfRange
    }
    filtered, err := self.FilteredDirectPath(sender)
    if err != nil {
        return err
    }
    // ValSem202: the path covers exactly the filtered direct path.
    if len(path.Nodes) != len(filtered) {
        return ErrPathLength
    }
    provisional := self.Clone()
    if err := provisional.BlankDirectPath(sender); err != nil {
        return err
    }
    for i, x := range filtered {
        if err := provisional.SetParent(x, &ParentNode{
            EncryptionKey: cloneBytes(path.Nodes[i].EncryptionKey),
        }); err != nil {
            return err
        }
    }
    carried := []byte{}
    for i := len(filtered) - 1; i >= 0; i-- {
        _, copath, err := provisional.pathChildren(filtered[i], sender)
        if err != nil {
            return err
        }
        parent := provisional.ParentAt(filtered[i])
        parent.ParentHash = carried
        hash, err := provisional.ParentHash(crypto, filtered[i], copath)
        if err != nil {
            return err
        }
        carried = hash
    }
    if subtle.ConstantTimeCompare(carried, path.LeafNode.ParentHash) != 1 {
        return ErrParentHashMismatch
    }
    if err := provisional.SetLeaf(sender, path.LeafNode.Clone()); err != nil {
        return err
    }
    self.nodes = provisional.nodes
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestMergeUpdatePath|TestValSem202" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/treekem.go mls/treekem_test.go
git commit -m "feat(mls): merge a received UpdatePath and recompute its parent hash chain"
```

---

### Task 22: Decrypting a received UpdatePath

**Files:**
- Modify: `mls/treekem.go`
- Test: `mls/treekem_test.go`

**Interfaces:**
- Consumes: `DecryptWithLabel` (Crypto/HPKE plan); `EncryptionTargets`, `FilteredDirectPath` (Task 16); `CommonAncestor` (Tree math plan); `TreeKEMPrivate` (Task 17); `ErrPathDecrypt` (ValSem203), `ErrPathKeyMismatch` (ValSem204), `ErrPathLength` (ValSem202) from the Validation plan; `ErrNoPathSecret` (Task 2).
- Produces: `PathDecryptResult{CommitSecret []byte; Private *TreeKEMPrivate}` and
  `func (self *RatchetTree) DecryptUpdatePath(crypto CryptoProvider, sender LeafIndex, path *UpdatePath, groupContext []byte, priv *TreeKEMPrivate, exclude []LeafIndex) (*PathDecryptResult, error)`.

Called **after** `MergeUpdatePath`, on the merged tree. The receiver's own ciphertext is found
structurally, not by trial decryption: the lowest node of the sender's filtered direct path that is
an ancestor of the receiver is `CommonAncestor(senderLeafNode, receiverLeafNode)`, and it is always
present in the filtered path, because the receiver's own non-blank leaf makes the relevant copath
resolution non-empty. Within that copath resolution the receiver takes the first entry it holds a
private key for. Every derived public key is compared to the one in the `UpdatePath` (ValSem204).

- [ ] **Step 1: Write the failing test**

```go
// mls/treekem_test.go (append)

func TestDecryptUpdatePathAgreesOnTheCommitSecret(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    for _, n := range []uint32{2, 3, 4, 7, 8} {
        tree, members := newTestTree(t, crypto, n)
        _, path, plan, groupContext := createAndEncryptPath(t, crypto, tree, members[0], nil)
        for _, receiver := range members[1:] {
            receiverTree := tree.Clone()
            if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, path); err != nil {
                t.Fatalf("n=%d receiver %d MergeUpdatePath: %v", n, receiver.LeafIndex, err)
            }
            priv := NewTreeKEMPrivate(receiver.LeafIndex, receiver.EncryptionPriv)
            got, err := receiverTree.DecryptUpdatePath(crypto, members[0].LeafIndex, path,
                groupContext, priv, nil)
            if err != nil {
                t.Fatalf("n=%d receiver %d DecryptUpdatePath: %v", n, receiver.LeafIndex, err)
            }
            if !bytes.Equal(got.CommitSecret, plan.CommitSecret) {
                t.Fatalf("n=%d receiver %d commit secret differs from the sender's", n, receiver.LeafIndex)
            }
            if err := got.Private.Consistent(crypto, receiverTree); err != nil {
                t.Fatalf("n=%d receiver %d private state: %v", n, receiver.LeafIndex, err)
            }
            // the receiver learns the secrets from its own entry point up to the root
            // and nothing below it.
            lowest := CommonAncestor(members[0].LeafIndex.NodeIndex(), receiver.LeafIndex.NodeIndex())
            if _, ok := got.Private.PathSecrets[lowest]; !ok {
                t.Fatalf("n=%d receiver %d did not learn the secret for node %d",
                    n, receiver.LeafIndex, lowest)
            }
        }
    }
}

func TestValSem203_PathDecrypt(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, groupContext := createAndEncryptPath(t, crypto, tree, members[0], nil)
    tampered := &UpdatePath{LeafNode: path.LeafNode, Nodes: append([]UpdatePathNode{}, path.Nodes...)}
    tampered.Nodes[0].EncryptedPathSecret = append([]HpkeCiphertext{},
        tampered.Nodes[0].EncryptedPathSecret...)
    corrupt := tampered.Nodes[0].EncryptedPathSecret[0]
    corrupt.Ciphertext = cloneBytes(corrupt.Ciphertext)
    corrupt.Ciphertext[0] ^= 0xFF
    tampered.Nodes[0].EncryptedPathSecret[0] = corrupt

    receiverTree := tree.Clone()
    if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, path); err != nil {
        t.Fatalf("MergeUpdatePath: %v", err)
    }
    priv := NewTreeKEMPrivate(members[1].LeafIndex, members[1].EncryptionPriv)
    _, err = receiverTree.DecryptUpdatePath(crypto, members[0].LeafIndex, tampered,
        groupContext, priv, nil)
    if !errors.Is(err, ErrPathDecrypt) {
        t.Fatalf("err = %v, want ErrPathDecrypt", err)
    }
    // the same ciphertext under a different group context also fails to open.
    priv = NewTreeKEMPrivate(members[1].LeafIndex, members[1].EncryptionPriv)
    _, err = receiverTree.DecryptUpdatePath(crypto, members[0].LeafIndex, path,
        []byte("wrong context"), priv, nil)
    if !errors.Is(err, ErrPathDecrypt) {
        t.Fatalf("wrong context err = %v, want ErrPathDecrypt", err)
    }
}

func TestValSem204_PathKeyMismatch(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, groupContext := createAndEncryptPath(t, crypto, tree, members[0], nil)
    receiverTree := tree.Clone()
    if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, path); err != nil {
        t.Fatalf("MergeUpdatePath: %v", err)
    }
    // swap the announced public key of the topmost node for an unrelated one. the
    // ciphertexts still open, so only the derived-key comparison catches it.
    _, unrelated, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
    if err != nil {
        t.Fatalf("DeriveKeyPair: %v", err)
    }
    tampered := &UpdatePath{LeafNode: path.LeafNode, Nodes: append([]UpdatePathNode{}, path.Nodes...)}
    tampered.Nodes[len(tampered.Nodes)-1].EncryptionKey = unrelated
    priv := NewTreeKEMPrivate(members[1].LeafIndex, members[1].EncryptionPriv)
    _, err = receiverTree.DecryptUpdatePath(crypto, members[0].LeafIndex, tampered,
        groupContext, priv, nil)
    if !errors.Is(err, ErrPathKeyMismatch) {
        t.Fatalf("err = %v, want ErrPathKeyMismatch", err)
    }
}

func TestDecryptUpdatePathRefusesWhenNoCiphertextIsAddressedToUs(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    // leaf 3 is treated as added by this commit, so nothing is encrypted to it.
    _, path, _, groupContext := createAndEncryptPath(t, crypto, tree, members[0], []LeafIndex{3})
    receiverTree := tree.Clone()
    if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, path); err != nil {
        t.Fatalf("MergeUpdatePath: %v", err)
    }
    priv := NewTreeKEMPrivate(members[3].LeafIndex, members[3].EncryptionPriv)
    _, err = receiverTree.DecryptUpdatePath(crypto, members[0].LeafIndex, path,
        groupContext, priv, []LeafIndex{3})
    if !errors.Is(err, ErrNoPathSecret) {
        t.Fatalf("err = %v, want ErrNoPathSecret", err)
    }
}

func TestDecryptUpdatePathUsesAHeldPathSecretWhenItHasOne(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 8)
    // member 4 commits first, so members 5, 6 and 7 hold path secrets above them.
    _, firstPath, _, firstContext := createAndEncryptPath(t, crypto, tree, members[4], nil)
    receiverTree := tree.Clone()
    if err := receiverTree.MergeUpdatePath(crypto, members[4].LeafIndex, firstPath); err != nil {
        t.Fatalf("MergeUpdatePath: %v", err)
    }
    priv := NewTreeKEMPrivate(members[5].LeafIndex, members[5].EncryptionPriv)
    first, err := receiverTree.DecryptUpdatePath(crypto, members[4].LeafIndex, firstPath,
        firstContext, priv, nil)
    if err != nil {
        t.Fatalf("first DecryptUpdatePath: %v", err)
    }
    if len(first.Private.PathSecrets) == 0 {
        t.Fatalf("the receiver learned no path secrets")
    }
    // now member 0 commits: member 5 must open the ciphertext addressed to the
    // subtree node it now holds a secret for, not to its own leaf.
    _, secondPath, secondPlan, secondContext := createAndEncryptPath(t, crypto, receiverTree, members[0], nil)
    if err := receiverTree.MergeUpdatePath(crypto, members[0].LeafIndex, secondPath); err != nil {
        t.Fatalf("second MergeUpdatePath: %v", err)
    }
    second, err := receiverTree.DecryptUpdatePath(crypto, members[0].LeafIndex, secondPath,
        secondContext, first.Private, nil)
    if err != nil {
        t.Fatalf("second DecryptUpdatePath: %v", err)
    }
    if !bytes.Equal(second.CommitSecret, secondPlan.CommitSecret) {
        t.Fatalf("commit secret differs from the sender's")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestDecryptUpdatePath|TestValSem203|TestValSem204" -v`
Expected: FAIL to compile with `receiverTree.DecryptUpdatePath undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go (append)

// what a receiver ends up with after opening one UpdatePath.
type PathDecryptResult struct {
    CommitSecret []byte
    Private      *TreeKEMPrivate
}

func indexOfNode(path []NodeIndex, x NodeIndex) (int, bool) {
    for i, y := range path {
        if y == x {
            return i, true
        }
    }
    return 0, false
}

// open the one ciphertext addressed to us and ratchet the rest of the way to the
// root. call after MergeUpdatePath, on the merged tree: the copath resolutions are
// unchanged by the merge, because the merge only touches the sender's direct path.
func (self *RatchetTree) DecryptUpdatePath(crypto CryptoProvider, sender LeafIndex,
    path *UpdatePath, groupContext []byte, priv *TreeKEMPrivate,
    exclude []LeafIndex) (*PathDecryptResult, error) {
    filtered, err := self.FilteredDirectPath(sender)
    if err != nil {
        return nil, err
    }
    if len(path.Nodes) != len(filtered) {
        return nil, ErrPathLength
    }
    targets, err := self.EncryptionTargets(sender, exclude)
    if err != nil {
        return nil, err
    }
    // the lowest node of the sender's path that covers us. it is always in the
    // filtered path, because our own non-blank leaf keeps that copath resolution
    // non-empty.
    lowest := CommonAncestor(sender.NodeIndex(), priv.LeafIndex.NodeIndex())
    start, ok := indexOfNode(filtered, lowest)
    if !ok {
        return nil, ErrNoPathSecret
    }
    if len(path.Nodes[start].EncryptedPathSecret) != len(targets[start]) {
        return nil, ErrPathLength
    }
    var secret []byte
    for j, y := range targets[start] {
        nodePriv, held, err := priv.NodePrivateKey(crypto, y)
        if err != nil {
            return nil, err
        }
        if !held {
            continue
        }
        ct := path.Nodes[start].EncryptedPathSecret[j]
        opened, err := DecryptWithLabel(crypto, nodePriv, updatePathNodeLabel,
            groupContext, ct.KemOutput, ct.Ciphertext)
        if err != nil {
            return nil, ErrPathDecrypt
        }
        secret = opened
        break
    }
    if secret == nil {
        return nil, ErrNoPathSecret
    }
    out := priv.Clone()
    for i := start; i < len(filtered); i++ {
        _, derivedPub, err := DeriveNodeKeyPair(crypto, secret)
        if err != nil {
            return nil, err
        }
        // ValSem204: the announced public key must be the one this secret derives.
        if subtle.ConstantTimeCompare(derivedPub, path.Nodes[i].EncryptionKey) != 1 {
            return nil, ErrPathKeyMismatch
        }
        out.PathSecrets[filtered[i]] = cloneBytes(secret)
        secret = crypto.DeriveSecret(secret, "path")
    }
    return &PathDecryptResult{CommitSecret: secret, Private: out}, nil
}
```

The loop keeps only the public half: the node private keys are re-derived on demand by
`TreeKEMPrivate.NodePrivateKey`, so no private key for a node above us is materialised and left on
the heap after the check.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestDecryptUpdatePath|TestValSem203|TestValSem204" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/treekem.go mls/treekem_test.go
git commit -m "feat(mls): decrypt a received UpdatePath and ratchet to the commit secret"
```

---

### Task 23: Whole-tree validation

**Files:**
- Create: `mls/tree_sync.go`
- Test: `mls/tree_sync_test.go`

**Interfaces:**
- Consumes: `LeafNode.Validate`, `LeafValidationContext` (Task 7); `VerifyParentHashes` (Task 14); `TreeHash` (Task 12); `GroupContext` (Key schedule plan, wave 2); `ErrDuplicateEncryptionKey`, `ErrDuplicateSignatureKey` (Validation plan); `ErrUnmergedLeavesNotSorted`, `ErrUnmergedLeafInconsistent`, `ErrTreeHashMismatch`, `ErrNodeTypeMismatch`, `ErrTreeMalformed` (Task 2).
- Produces: `TreeValidationContext{Crypto, Suite, GroupId, RequiredCaps, GroupExtensions, NowMs, ClockSkewMs}`,
  `func (self *RatchetTree) Validate(ctx *TreeValidationContext) error`,
  `func (self *RatchetTree) ValidateAgainstContext(ctx *TreeValidationContext, gc *GroupContext) error`.
  `group.go` calls `ValidateAgainstContext` on every tree that arrives out of band — from a `Welcome`,
  from the `ratchet_tree` extension, or from a `connect/message` epoch snapshot record.

The checks, in order, each with its own failure:

1. Structure: the node array is `2*n-1` for a power-of-two `n`, and every node's type matches its position.
2. Every non-blank leaf passes RFC 9420 §7.3 at its own index (`ExpectedSource` is inferred: a leaf may hold any of the three sources in a settled tree, so the leaf's own source is used and only the signature binding is enforced).
3. Encryption keys are unique across every node, leaf and parent alike; signature keys are unique across leaves.
4. Every `unmerged_leaves` list is strictly ascending, in range, and points at a non-blank descendant leaf; and for every intermediate node between that leaf and the node listing it, the intermediate is blank or lists the same leaf.
5. Parent hashes verify (Task 14).
6. For `ValidateAgainstContext`, the tree hash equals `gc.TreeHash`.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_sync_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"
)

func testTreeValidationContext(crypto CryptoProvider) *TreeValidationContext {
    return &TreeValidationContext{
        Crypto:  crypto,
        Suite:   CipherSuiteX25519ChaCha20SHA256Ed25519,
        GroupId: testGroupId(),
        RequiredCaps: &RequiredCapabilities{
            ExtensionTypes:  []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
            CredentialTypes: []CredentialType{CredentialTypeBasic},
        },
        GroupExtensions: []Extension{
            {ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: []byte("policy")},
        },
        NowMs:       1_000_000,
        ClockSkewMs: 3_600_000,
    }
}

func TestValidateAcceptsAFreshAndACommittedTree(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    for _, n := range []uint32{1, 2, 3, 5, 8} {
        tree, members := newTestTree(t, crypto, n)
        if err := tree.Validate(testTreeValidationContext(crypto)); err != nil {
            t.Fatalf("n=%d Validate on a fresh tree: %v", n, err)
        }
        if n < 2 {
            continue
        }
        senderTree, _, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
        if err := senderTree.Validate(testTreeValidationContext(crypto)); err != nil {
            t.Fatalf("n=%d Validate after a commit: %v", n, err)
        }
    }
}

func TestValidateRejectsDuplicateKeys(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    duplicate := tree.Leaf(LeafIndex(1)).Clone()
    duplicate.EncryptionKey = cloneBytes(tree.Leaf(LeafIndex(0)).EncryptionKey)
    if err := duplicate.Sign(crypto, members[1].SignaturePriv, testGroupId(), LeafIndex(1)); err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := tree.SetLeaf(LeafIndex(1), duplicate); err != nil {
        t.Fatalf("SetLeaf: %v", err)
    }
    if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("err = %v, want ErrDuplicateEncryptionKey", err)
    }

    tree, members = newTestTree(t, crypto, 4)
    duplicate = tree.Leaf(LeafIndex(1)).Clone()
    duplicate.SignatureKey = cloneBytes(tree.Leaf(LeafIndex(0)).SignatureKey)
    if err := duplicate.Sign(crypto, members[0].SignaturePriv, testGroupId(), LeafIndex(1)); err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := tree.SetLeaf(LeafIndex(1), duplicate); err != nil {
        t.Fatalf("SetLeaf: %v", err)
    }
    if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrDuplicateSignatureKey) {
        t.Fatalf("err = %v, want ErrDuplicateSignatureKey", err)
    }
}

func TestValidateRejectsBadUnmergedLeaves(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    cases := []struct {
        name     string
        unmerged []LeafIndex
        want     error
    }{
        {"descending", []LeafIndex{1, 0}, ErrUnmergedLeavesNotSorted},
        {"duplicated", []LeafIndex{1, 1}, ErrUnmergedLeavesNotSorted},
        {"out of range", []LeafIndex{99}, ErrUnmergedLeafInconsistent},
        {"not a descendant", []LeafIndex{3}, ErrUnmergedLeafInconsistent},
    }
    for _, c := range cases {
        tree, _ := newTestTree(t, crypto, 4)
        if err := tree.SetParent(NodeIndex(1), &ParentNode{
            EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x5A}, 32)),
            UnmergedLeaves: c.unmerged,
        }); err != nil {
            t.Fatalf("%s SetParent: %v", c.name, err)
        }
        if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, c.want) {
            t.Fatalf("%s: err = %v, want %v", c.name, err, c.want)
        }
    }
}

func TestValidateRejectsAnUnmergedLeafThatAnIntermediateDoesNotCarry(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 8)
    // the root lists leaf 0 unmerged, but node 1 between them does not.
    if err := tree.SetParent(NodeIndex(1), &ParentNode{
        EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0x01}, 32)),
    }); err != nil {
        t.Fatalf("SetParent(1): %v", err)
    }
    if err := tree.SetParent(NodeIndex(3), &ParentNode{
        EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x03}, 32)),
        UnmergedLeaves: []LeafIndex{0},
    }); err != nil {
        t.Fatalf("SetParent(3): %v", err)
    }
    if err := tree.Validate(testTreeValidationContext(crypto)); !errors.Is(err, ErrUnmergedLeafInconsistent) {
        t.Fatalf("err = %v, want ErrUnmergedLeafInconsistent", err)
    }
}

func TestValidateAgainstContextChecksTheTreeHash(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    treeHash, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    gc := &GroupContext{
        Version:     ProtocolVersionMLS10,
        CipherSuite: CipherSuiteX25519ChaCha20SHA256Ed25519,
        GroupId:     testGroupId(),
        Epoch:       1,
        TreeHash:    treeHash,
    }
    if err := tree.ValidateAgainstContext(testTreeValidationContext(crypto), gc); err != nil {
        t.Fatalf("ValidateAgainstContext: %v", err)
    }
    gc.TreeHash = cloneBytes(treeHash)
    gc.TreeHash[0] ^= 0xFF
    if err := tree.ValidateAgainstContext(testTreeValidationContext(crypto), gc); !errors.Is(err, ErrTreeHashMismatch) {
        t.Fatalf("err = %v, want ErrTreeHashMismatch", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestValidate" -v`
Expected: FAIL to compile with `undefined: TreeValidationContext`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree_sync.go
package mls

import "crypto/subtle"

// everything needed to validate a tree that arrived from somewhere else: a Welcome,
// the ratchet_tree extension, or a connect/message epoch snapshot record.
type TreeValidationContext struct {
    Crypto          CryptoProvider
    Suite           CipherSuite
    GroupId         []byte
    RequiredCaps    *RequiredCapabilities
    GroupExtensions []Extension
    NowMs           uint64
    ClockSkewMs     uint64
}

func (self *RatchetTree) validateStructure() error {
    width := self.NodeWidth()
    if width == 0 || width%2 == 0 {
        return ErrTreeMalformed
    }
    leafWidth := self.LeafWidth()
    if leafWidth&(leafWidth-1) != 0 {
        return ErrTreeMalformed
    }
    for x := uint32(0); x < width; x++ {
        node := self.nodes[x]
        if node == nil {
            continue
        }
        if NodeIndex(x).IsLeaf() {
            if node.NodeType != NodeTypeLeaf || node.Leaf == nil {
                return ErrNodeTypeMismatch
            }
            continue
        }
        if node.NodeType != NodeTypeParent || node.Parent == nil {
            return ErrNodeTypeMismatch
        }
    }
    return nil
}

func (self *RatchetTree) validateLeaves(ctx *TreeValidationContext) error {
    for i := uint32(0); i < self.LeafWidth(); i++ {
        leaf := self.Leaf(LeafIndex(i))
        if leaf == nil {
            continue
        }
        err := leaf.Validate(&LeafValidationContext{
            Crypto:          ctx.Crypto,
            Suite:           ctx.Suite,
            GroupId:         ctx.GroupId,
            LeafIndex:       LeafIndex(i),
            ExpectedSource:  leaf.LeafNodeSource,
            RequiredCaps:    ctx.RequiredCaps,
            GroupExtensions: ctx.GroupExtensions,
            NowMs:           ctx.NowMs,
            ClockSkewMs:     ctx.ClockSkewMs,
        })
        if err != nil {
            return err
        }
    }
    return nil
}

// every encryption key in the tree is unique, and every leaf signature key is
// unique. a repeat means two members would derive the same secrets from one commit.
func (self *RatchetTree) validateKeyUniqueness() error {
    encryptionKeys := map[string]bool{}
    signatureKeys := map[string]bool{}
    for x := uint32(0); x < self.NodeWidth(); x++ {
        node := self.nodes[x]
        if node == nil {
            continue
        }
        var encryptionKey []byte
        if node.Leaf != nil {
            encryptionKey = node.Leaf.EncryptionKey
            if signatureKeys[string(node.Leaf.SignatureKey)] {
                return ErrDuplicateSignatureKey
            }
            signatureKeys[string(node.Leaf.SignatureKey)] = true
        } else {
            encryptionKey = node.Parent.EncryptionKey
        }
        if encryptionKeys[string(encryptionKey)] {
            return ErrDuplicateEncryptionKey
        }
        encryptionKeys[string(encryptionKey)] = true
    }
    return nil
}

// RFC 9420 §7.9.2. an unmerged leaf must be a live descendant, and every node
// between it and the node listing it must be blank or list it too — otherwise the
// intermediate's key would be one the unmerged member is assumed not to hold.
func (self *RatchetTree) validateUnmergedLeaves() error {
    for x := uint32(1); x < self.NodeWidth(); x += 2 {
        node := NodeIndex(x)
        parent := self.ParentAt(node)
        if parent == nil {
            continue
        }
        for i, leaf := range parent.UnmergedLeaves {
            if i > 0 && parent.UnmergedLeaves[i-1] >= leaf {
                return ErrUnmergedLeavesNotSorted
            }
            if uint32(leaf) >= self.LeafWidth() {
                return ErrUnmergedLeafInconsistent
            }
            if self.Leaf(leaf) == nil {
                return ErrUnmergedLeafInconsistent
            }
            if CommonAncestor(leaf.NodeIndex(), node) != node {
                return ErrUnmergedLeafInconsistent
            }
            for _, intermediate := range DirectPath(leaf.NodeIndex(), self.LeafWidth()) {
                if intermediate == node {
                    break
                }
                between := self.ParentAt(intermediate)
                if between == nil {
                    continue
                }
                listed := false
                for _, candidate := range between.UnmergedLeaves {
                    if candidate == leaf {
                        listed = true
                        break
                    }
                }
                if !listed {
                    return ErrUnmergedLeafInconsistent
                }
            }
        }
    }
    return nil
}

func (self *RatchetTree) Validate(ctx *TreeValidationContext) error {
    if err := self.validateStructure(); err != nil {
        return err
    }
    if err := self.validateLeaves(ctx); err != nil {
        return err
    }
    if err := self.validateKeyUniqueness(); err != nil {
        return err
    }
    if err := self.validateUnmergedLeaves(); err != nil {
        return err
    }
    return self.VerifyParentHashes(ctx.Crypto)
}

// the same checks, plus the binding to the epoch that pinned this tree.
func (self *RatchetTree) ValidateAgainstContext(ctx *TreeValidationContext, gc *GroupContext) error {
    if err := self.Validate(ctx); err != nil {
        return err
    }
    treeHash, err := self.TreeHash(ctx.Crypto)
    if err != nil {
        return err
    }
    if subtle.ConstantTimeCompare(treeHash, gc.TreeHash) != 1 {
        return ErrTreeHashMismatch
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestValidate" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_sync.go mls/tree_sync_test.go
git commit -m "feat(mls): whole-tree validation for out-of-band ratchet trees"
```

---

### Task 24: The tree-validation vector family (family 10)

**Files:**
- Modify: `mls/tree_vectors_test.go`
- Test: `mls/tree_vectors_test.go`

**Interfaces:**
- Consumes: `treeVectorFile`, `treeHex` (Task 1); `UnmarshalRatchetTree` (Task 11); `Resolution` (Task 10); `TreeHashes` (Task 12); `VerifyParentHashes` (Task 14); `LeafNode.VerifySignature` (Task 6); `NewCryptoProvider` (Crypto plan).
- Produces: `TestVectorTreeValidation`, the gate named `tree-validation` in this plan's scope.

Vector fields, verified in this order: `cipher_suite`, `tree` (a serialized ratchet tree), `group_id`,
`resolutions` (one list of node indices per node index), `tree_hashes` (one hash per node index).
Every leaf signature is verified against `group_id` at its own index, and the whole tree is checked
for parent-hash validity.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_vectors_test.go (append)

type treeValidationVector struct {
    CipherSuite uint16     `json:"cipher_suite"`
    Tree        string     `json:"tree"`
    GroupId     string     `json:"group_id"`
    Resolutions [][]uint32 `json:"resolutions"`
    TreeHashes  []string   `json:"tree_hashes"`
}

func TestVectorTreeValidation(t *testing.T) {
    var vectors []treeValidationVector
    if err := json.Unmarshal(treeVectorFile(t, "tree-validation.json"), &vectors); err != nil {
        t.Fatalf("decode tree-validation.json: %v", err)
    }
    if len(vectors) == 0 {
        t.Fatalf("tree-validation.json is empty")
    }
    ran := 0
    for i, vector := range vectors {
        if CipherSuite(vector.CipherSuite) != CipherSuiteX25519ChaCha20SHA256Ed25519 {
            continue
        }
        ran++
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d NewCryptoProvider: %v", i, err)
        }
        tree, err := UnmarshalRatchetTree(treeHex(t, vector.Tree))
        if err != nil {
            t.Fatalf("vector %d UnmarshalRatchetTree: %v", i, err)
        }
        groupId := treeHex(t, vector.GroupId)

        if uint32(len(vector.Resolutions)) != tree.NodeWidth() {
            t.Fatalf("vector %d has %d resolutions for %d nodes",
                i, len(vector.Resolutions), tree.NodeWidth())
        }
        for x, want := range vector.Resolutions {
            got := tree.Resolution(NodeIndex(x))
            if len(got) != len(want) {
                t.Fatalf("vector %d node %d resolution = %v, want %v", i, x, got, want)
            }
            for j := range want {
                if uint32(got[j]) != want[j] {
                    t.Fatalf("vector %d node %d resolution = %v, want %v", i, x, got, want)
                }
            }
        }

        hashes, err := tree.TreeHashes(crypto)
        if err != nil {
            t.Fatalf("vector %d TreeHashes: %v", i, err)
        }
        if len(vector.TreeHashes) != len(hashes) {
            t.Fatalf("vector %d has %d tree hashes for %d nodes",
                i, len(vector.TreeHashes), len(hashes))
        }
        for x, want := range vector.TreeHashes {
            if !bytes.Equal(hashes[x], treeHex(t, want)) {
                t.Fatalf("vector %d node %d tree hash = %x, want %s", i, x, hashes[x], want)
            }
        }

        if err := tree.VerifyParentHashes(crypto); err != nil {
            t.Fatalf("vector %d VerifyParentHashes: %v", i, err)
        }

        for x := uint32(0); x < tree.LeafWidth(); x++ {
            leaf := tree.Leaf(LeafIndex(x))
            if leaf == nil {
                continue
            }
            if err := leaf.VerifySignature(crypto, groupId, LeafIndex(x)); err != nil {
                t.Fatalf("vector %d leaf %d signature: %v", i, x, err)
            }
        }
    }
    if ran == 0 {
        t.Fatalf("no tree-validation vector used ciphersuite 0x0003")
    }
}
```

Add `"bytes"` and `"encoding/json"` to the imports of `mls/tree_vectors_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestVectorTreeValidation -v`
Expected: FAIL — either `decode tree-validation.json` if Task 1 has not run, or a concrete
`node N resolution = ... want ...` mismatch

- [ ] **Step 3: Write minimal implementation**

No new production code. If the vector fails, the defect is in `Resolution`, `TreeHashes`,
`VerifyParentHashes` or `UnmarshalRatchetTree`, and the fix belongs to that function's own task.
Two failures are expected here and are real bugs, not vector quirks:

- A resolution mismatch on a node with unmerged leaves means `Resolution` is emitting the unmerged
  leaves in the wrong place or the wrong order — they follow the node itself, in the order stored.
- A tree-hash mismatch on a blank leaf means `leafHashInput` omitted the leaf index.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestVectorTreeValidation -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_vectors_test.go
git commit -m "test(mls): tree-validation vector family passes"
```

---

### Task 25: The TreeKEM vector family (family 11), both directions

**Files:**
- Modify: `mls/tree_vectors_test.go`
- Test: `mls/tree_vectors_test.go`

**Interfaces:**
- Consumes: `treeVectorFile`, `treeHex` (Task 1); `UnmarshalRatchetTree` (Task 11); `ParseUpdatePath` (Task 19); `MergeUpdatePath` (Task 21); `DecryptUpdatePath` (Task 22); `CreateUpdatePathSecrets`, `EncryptUpdatePath` (Tasks 18, 20); `TreeKEMPrivate` (Task 17); `GroupContext` and `GroupContext.Marshal` (Key schedule plan, wave 2); `CommonAncestor` (Tree math plan).
- Produces: `TestVectorTreeKEM` (verify direction) and `TestVectorTreeKEMGenerate` (generate direction), the gate named `treekem` in this plan's scope.

Vector fields: `cipher_suite`, `group_id`, `epoch`, `confirmed_transcript_hash`, `ratchet_tree`,
`leaves_private[]{index, encryption_priv, signature_priv, path_secrets[]{node, path_secret}}`, and
`update_paths[]{sender, update_path, path_secrets[] (one per leaf index, null where that leaf cannot
decrypt), commit_secret, tree_hash_after}`.

The GroupContext used as the HPKE context for each update path has `tree_hash = tree_hash_after` of
that path — which is why generation and encryption are two separate calls in this package.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_vectors_test.go (append)

type treeKemPathSecret struct {
    Node       uint32 `json:"node"`
    PathSecret string `json:"path_secret"`
}

type treeKemLeafPrivate struct {
    Index         uint32              `json:"index"`
    EncryptionPriv string             `json:"encryption_priv"`
    SignaturePriv  string             `json:"signature_priv"`
    PathSecrets    []treeKemPathSecret `json:"path_secrets"`
}

type treeKemUpdatePath struct {
    Sender        uint32    `json:"sender"`
    UpdatePath    string    `json:"update_path"`
    PathSecrets   []*string `json:"path_secrets"`
    CommitSecret  string    `json:"commit_secret"`
    TreeHashAfter string    `json:"tree_hash_after"`
}

type treeKemVector struct {
    CipherSuite             uint16               `json:"cipher_suite"`
    GroupId                 string               `json:"group_id"`
    Epoch                   uint64               `json:"epoch"`
    ConfirmedTranscriptHash string               `json:"confirmed_transcript_hash"`
    RatchetTree             string               `json:"ratchet_tree"`
    LeavesPrivate           []treeKemLeafPrivate `json:"leaves_private"`
    UpdatePaths             []treeKemUpdatePath  `json:"update_paths"`
}

func (self *treeKemVector) groupContext(t *testing.T, treeHash []byte) []byte {
    t.Helper()
    gc := &GroupContext{
        Version:                 ProtocolVersionMLS10,
        CipherSuite:             CipherSuite(self.CipherSuite),
        GroupId:                 treeHex(t, self.GroupId),
        Epoch:                   self.Epoch,
        TreeHash:                treeHash,
        ConfirmedTranscriptHash: treeHex(t, self.ConfirmedTranscriptHash),
    }
    encoded, err := gc.Marshal()
    if err != nil {
        t.Fatalf("GroupContext.Marshal: %v", err)
    }
    return encoded
}

func (self *treeKemVector) private(t *testing.T, index uint32) (*TreeKEMPrivate, bool) {
    t.Helper()
    for _, entry := range self.LeavesPrivate {
        if entry.Index != index {
            continue
        }
        priv := NewTreeKEMPrivate(LeafIndex(entry.Index),
            HpkePrivateKey(treeHex(t, entry.EncryptionPriv)))
        for _, secret := range entry.PathSecrets {
            priv.PathSecrets[NodeIndex(secret.Node)] = treeHex(t, secret.PathSecret)
        }
        return priv, true
    }
    return nil, false
}

func TestVectorTreeKEM(t *testing.T) {
    var vectors []treeKemVector
    if err := json.Unmarshal(treeVectorFile(t, "treekem.json"), &vectors); err != nil {
        t.Fatalf("decode treekem.json: %v", err)
    }
    if len(vectors) == 0 {
        t.Fatalf("treekem.json is empty")
    }
    ran := 0
    for i, vector := range vectors {
        if CipherSuite(vector.CipherSuite) != CipherSuiteX25519ChaCha20SHA256Ed25519 {
            continue
        }
        ran++
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d NewCryptoProvider: %v", i, err)
        }
        base, err := UnmarshalRatchetTree(treeHex(t, vector.RatchetTree))
        if err != nil {
            t.Fatalf("vector %d UnmarshalRatchetTree: %v", i, err)
        }
        // the supplied private state must already agree with the supplied tree.
        for _, entry := range vector.LeavesPrivate {
            priv, _ := vector.private(t, entry.Index)
            if err := priv.Consistent(crypto, base); err != nil {
                t.Fatalf("vector %d leaf %d private state: %v", i, entry.Index, err)
            }
        }
        for j, update := range vector.UpdatePaths {
            path, err := ParseUpdatePath(treeHex(t, update.UpdatePath))
            if err != nil {
                t.Fatalf("vector %d path %d ParseUpdatePath: %v", i, j, err)
            }
            merged := base.Clone()
            if err := merged.MergeUpdatePath(crypto, LeafIndex(update.Sender), path); err != nil {
                t.Fatalf("vector %d path %d MergeUpdatePath: %v", i, j, err)
            }
            treeHash, err := merged.TreeHash(crypto)
            if err != nil {
                t.Fatalf("vector %d path %d TreeHash: %v", i, j, err)
            }
            if !bytes.Equal(treeHash, treeHex(t, update.TreeHashAfter)) {
                t.Fatalf("vector %d path %d tree hash = %x, want %s",
                    i, j, treeHash, update.TreeHashAfter)
            }
            if err := merged.VerifyParentHashes(crypto); err != nil {
                t.Fatalf("vector %d path %d VerifyParentHashes: %v", i, j, err)
            }
            groupContext := vector.groupContext(t, treeHash)
            wantCommitSecret := treeHex(t, update.CommitSecret)
            for leafIndex, wantSecret := range update.PathSecrets {
                if wantSecret == nil {
                    continue
                }
                priv, ok := vector.private(t, uint32(leafIndex))
                if !ok {
                    continue
                }
                got, err := merged.DecryptUpdatePath(crypto, LeafIndex(update.Sender), path,
                    groupContext, priv, nil)
                if err != nil {
                    t.Fatalf("vector %d path %d leaf %d DecryptUpdatePath: %v", i, j, leafIndex, err)
                }
                lowest := CommonAncestor(LeafIndex(update.Sender).NodeIndex(),
                    LeafIndex(leafIndex).NodeIndex())
                if !bytes.Equal(got.Private.PathSecrets[lowest], treeHex(t, *wantSecret)) {
                    t.Fatalf("vector %d path %d leaf %d path secret at node %d differs",
                        i, j, leafIndex, lowest)
                }
                if !bytes.Equal(got.CommitSecret, wantCommitSecret) {
                    t.Fatalf("vector %d path %d leaf %d commit secret = %x, want %s",
                        i, j, leafIndex, got.CommitSecret, update.CommitSecret)
                }
            }
        }
    }
    if ran == 0 {
        t.Fatalf("no treekem vector used ciphersuite 0x0003")
    }
}

func TestVectorTreeKEMGenerate(t *testing.T) {
    var vectors []treeKemVector
    if err := json.Unmarshal(treeVectorFile(t, "treekem.json"), &vectors); err != nil {
        t.Fatalf("decode treekem.json: %v", err)
    }
    ran := 0
    for i, vector := range vectors {
        if CipherSuite(vector.CipherSuite) != CipherSuiteX25519ChaCha20SHA256Ed25519 {
            continue
        }
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d NewCryptoProvider: %v", i, err)
        }
        base, err := UnmarshalRatchetTree(treeHex(t, vector.RatchetTree))
        if err != nil {
            t.Fatalf("vector %d UnmarshalRatchetTree: %v", i, err)
        }
        groupId := treeHex(t, vector.GroupId)
        for _, entry := range vector.LeavesPrivate {
            sender := LeafIndex(entry.Index)
            senderTree := base.Clone()
            plan, err := senderTree.CreateUpdatePathSecrets(crypto, sender,
                SignaturePrivateKey(treeHex(t, entry.SignaturePriv)), groupId)
            if err != nil {
                t.Fatalf("vector %d sender %d CreateUpdatePathSecrets: %v", i, sender, err)
            }
            treeHash, err := senderTree.TreeHash(crypto)
            if err != nil {
                t.Fatalf("vector %d sender %d TreeHash: %v", i, sender, err)
            }
            groupContext := vector.groupContext(t, treeHash)
            path, err := senderTree.EncryptUpdatePath(crypto, plan, sender, groupContext, nil)
            if err != nil {
                t.Fatalf("vector %d sender %d EncryptUpdatePath: %v", i, sender, err)
            }
            if err := senderTree.VerifyParentHashes(crypto); err != nil {
                t.Fatalf("vector %d sender %d VerifyParentHashes: %v", i, sender, err)
            }
            // every other member with a supplied private state must reach the same
            // commit secret through the independent receive path.
            for _, other := range vector.LeavesPrivate {
                if other.Index == entry.Index {
                    continue
                }
                receiverTree := base.Clone()
                if err := receiverTree.MergeUpdatePath(crypto, sender, path); err != nil {
                    t.Fatalf("vector %d sender %d receiver %d MergeUpdatePath: %v",
                        i, sender, other.Index, err)
                }
                priv, _ := vector.private(t, other.Index)
                got, err := receiverTree.DecryptUpdatePath(crypto, sender, path, groupContext, priv, nil)
                if err != nil {
                    t.Fatalf("vector %d sender %d receiver %d DecryptUpdatePath: %v",
                        i, sender, other.Index, err)
                }
                if !bytes.Equal(got.CommitSecret, plan.CommitSecret) {
                    t.Fatalf("vector %d sender %d receiver %d commit secret differs",
                        i, sender, other.Index)
                }
                ran++
            }
        }
    }
    if ran == 0 {
        t.Fatalf("no generated update path was verified by a second member")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestVectorTreeKEM -v`
Expected: FAIL — `decode treekem.json` before Task 1, or a concrete `tree hash = ... want ...` or
`commit secret = ... want ...` mismatch

- [ ] **Step 3: Write minimal implementation**

No new production code. The three failures worth naming, because each has a wrong fix that also
makes the vector pass in one direction only:

- A `tree_hash_after` mismatch after `MergeUpdatePath` means the receiver's recomputed parent-hash
  chain differs from the sender's. Fix the chain in `MergeUpdatePath`, never the tree hash.
- A commit-secret mismatch with correct path secrets means the commit secret was taken as
  `path_secret[last]` rather than `DeriveSecret(path_secret[last], "path")`.
- A path secret that decrypts for one leaf and not another means the ciphertext index was found by
  trial rather than by position in the copath resolution — `DecryptUpdatePath` must index, not search.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestVectorTreeKEM -v`
Expected: PASS (both `TestVectorTreeKEM` and `TestVectorTreeKEMGenerate`)

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_vectors_test.go
git commit -m "test(mls): TreeKEM vector family passes in both directions"
```

---

### Task 26: The remaining tree ValSem codes

**Files:**
- Modify: `mls/tree_sync.go`, `mls/tree_sync_test.go`
- Test: `mls/tree_sync_test.go`

**Interfaces:**
- Consumes: `ErrDuplicateEncryptionKey` (Validation plan, used for ValSem206 and ValSem207); `MergeUpdatePath` (Task 21).
- Produces: `func (self *RatchetTree) CheckUpdatePathKeyUniqueness(sender LeafIndex, path *UpdatePath) error` — ValSem206 (the path's leaf-node encryption key is unique against every key already in the tree) and ValSem207 (each path node's encryption key is unique the same way). `commit.go` (Group lifecycle plan) calls it before `MergeUpdatePath`, because the check is against the pre-merge tree.

Spec A §4.3 requires one test function per code, named `TestValSemNNN_<slug>`, as a top-level
function. ValSem202, 203, 204 and 300 already have theirs (Tasks 11, 21, 22). This task adds 206 and
207 and a coverage assertion that fails if a tree-owned code loses its test.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_sync_test.go (append)

func TestValSem206_PathLeafKeyUnique(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
    if err := tree.CheckUpdatePathKeyUniqueness(members[0].LeafIndex, path); err != nil {
        t.Fatalf("a fresh path must be unique: %v", err)
    }
    tampered := &UpdatePath{LeafNode: *path.LeafNode.Clone(), Nodes: path.Nodes}
    tampered.LeafNode.EncryptionKey = cloneBytes(tree.Leaf(LeafIndex(2)).EncryptionKey)
    if err := tree.CheckUpdatePathKeyUniqueness(members[0].LeafIndex, tampered); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("err = %v, want ErrDuplicateEncryptionKey", err)
    }
}

func TestValSem207_PathNodeKeysUnique(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)

    // a path node reusing a leaf's key that is already in the tree.
    tampered := &UpdatePath{LeafNode: path.LeafNode, Nodes: append([]UpdatePathNode{}, path.Nodes...)}
    tampered.Nodes[0].EncryptionKey = cloneBytes(tree.Leaf(LeafIndex(2)).EncryptionKey)
    if err := tree.CheckUpdatePathKeyUniqueness(members[0].LeafIndex, tampered); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("reused tree key: err = %v, want ErrDuplicateEncryptionKey", err)
    }

    // two nodes of the same path sharing a key.
    tampered = &UpdatePath{LeafNode: path.LeafNode, Nodes: append([]UpdatePathNode{}, path.Nodes...)}
    tampered.Nodes[1].EncryptionKey = cloneBytes(tampered.Nodes[0].EncryptionKey)
    if err := tree.CheckUpdatePathKeyUniqueness(members[0].LeafIndex, tampered); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("repeated path key: err = %v, want ErrDuplicateEncryptionKey", err)
    }

    // the sender's own outgoing leaf key is being replaced, so it does not count.
    reused := &UpdatePath{LeafNode: *path.LeafNode.Clone(), Nodes: path.Nodes}
    reused.LeafNode.EncryptionKey = cloneBytes(tree.Leaf(members[0].LeafIndex).EncryptionKey)
    if err := tree.CheckUpdatePathKeyUniqueness(members[0].LeafIndex, reused); err != nil {
        t.Fatalf("the sender's own leaf key must not collide with itself: %v", err)
    }
}

// Spec A §4.3 requires one named test per ValSem code. this asserts the tree-owned
// set is present, so deleting one shows up here rather than in a coverage report.
func TestTreeValSemCoverage(t *testing.T) {
    required := []string{
        "TestValSem202_PathLength",
        "TestValSem203_PathDecrypt",
        "TestValSem204_PathKeyMismatch",
        "TestValSem206_PathLeafKeyUnique",
        "TestValSem207_PathNodeKeysUnique",
        "TestValSem300_TrailingBlankNodes",
    }
    source, err := os.ReadDir(".")
    if err != nil {
        t.Fatalf("ReadDir: %v", err)
    }
    found := map[string]bool{}
    for _, entry := range source {
        if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
            continue
        }
        data, err := os.ReadFile(entry.Name())
        if err != nil {
            t.Fatalf("ReadFile %s: %v", entry.Name(), err)
        }
        for _, name := range required {
            if strings.Contains(string(data), "func "+name+"(") {
                found[name] = true
            }
        }
    }
    for _, name := range required {
        if !found[name] {
            t.Fatalf("%s is missing; every tree-owned ValSem code needs its own named test", name)
        }
    }
}
```

Add `"os"` and `"strings"` to the imports of `mls/tree_sync_test.go`, and rename the existing
`TestValSem202_PathLength`, `TestValSem203_PathDecrypt`, `TestValSem204_PathKeyMismatch` and
`TestValSem300_TrailingBlankNodes` to exactly those names if any of them differs.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestValSem206|TestValSem207|TestTreeValSemCoverage" -v`
Expected: FAIL to compile with `tree.CheckUpdatePathKeyUniqueness undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree_sync.go (append)

// ValSem206 and ValSem207. every encryption key an UpdatePath introduces must be new
// to the tree, and new within the path. the sender's own outgoing leaf key is skipped:
// it is the one key the path is replacing. run this against the PRE-merge tree.
func (self *RatchetTree) CheckUpdatePathKeyUniqueness(sender LeafIndex, path *UpdatePath) error {
    existing := map[string]bool{}
    for x := uint32(0); x < self.NodeWidth(); x++ {
        node := self.nodes[x]
        if node == nil {
            continue
        }
        if node.Leaf != nil {
            if NodeIndex(x) == sender.NodeIndex() {
                continue
            }
            existing[string(node.Leaf.EncryptionKey)] = true
            continue
        }
        existing[string(node.Parent.EncryptionKey)] = true
    }
    introduced := map[string]bool{}
    keys := make([][]byte, 0, len(path.Nodes)+1)
    keys = append(keys, path.LeafNode.EncryptionKey)
    for i := range path.Nodes {
        keys = append(keys, path.Nodes[i].EncryptionKey)
    }
    for _, key := range keys {
        if existing[string(key)] || introduced[string(key)] {
            return ErrDuplicateEncryptionKey
        }
        introduced[string(key)] = true
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestValSem|TestTreeValSemCoverage" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_sync.go mls/tree_sync_test.go
git commit -m "feat(mls): UpdatePath encryption key uniqueness (ValSem206, ValSem207)"
```

---

### Task 27: Fuzz targets for the tree and UpdatePath decoders

**Files:**
- Create: `mls/tree_fuzz_test.go`, `mls/testdata/corpus/ratchet_tree/`, `mls/testdata/corpus/update_path/`
- Test: `mls/tree_fuzz_test.go`

**Interfaces:**
- Consumes: `UnmarshalRatchetTree`, `RatchetTree.Marshal` (Task 11); `ParseUpdatePath`, `UpdatePath.Marshal` (Task 19).
- Produces: `FuzzRatchetTreeDecode` and `FuzzUpdatePathDecode`, asserting Gate 4 properties 1 (no panic, no unbounded allocation) and 2 (round-trip stability). These feed the same corpus directory the differential job in Spec A §4.4 reads, and they extend `FuzzExtensionDecodeBytes` — a ratchet tree arrives as an extension body, so a tree decoder bug is reachable from the extension target too.

Round-trip stability is the property that matters most here: MLS signs over serialized forms, so a
decoder that accepts two encodings of one tree is a signature-bypass primitive. `encode(decode(x))`
must equal the canonical re-serialization, and `decode(encode(decode(x)))` must equal `decode(x)`.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_fuzz_test.go
package mls

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"
)

func seedCorpus(f *testing.F, dir string) {
    f.Helper()
    entries, err := os.ReadDir(filepath.Join("testdata", "corpus", dir))
    if err != nil {
        f.Fatalf("read corpus %s: %v", dir, err)
    }
    if len(entries) == 0 {
        f.Fatalf("corpus %s is empty", dir)
    }
    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        data, err := os.ReadFile(filepath.Join("testdata", "corpus", dir, entry.Name()))
        if err != nil {
            f.Fatalf("read %s: %v", entry.Name(), err)
        }
        f.Add(data)
    }
}

func FuzzRatchetTreeDecode(f *testing.F) {
    seedCorpus(f, "ratchet_tree")
    f.Fuzz(func(t *testing.T, data []byte) {
        tree, err := UnmarshalRatchetTree(data)
        if err != nil {
            return
        }
        encoded, err := tree.Marshal()
        if err != nil {
            t.Fatalf("a decoded tree failed to re-encode: %v", err)
        }
        again, err := UnmarshalRatchetTree(encoded)
        if err != nil {
            t.Fatalf("the canonical re-encoding failed to decode: %v", err)
        }
        reencoded, err := again.Marshal()
        if err != nil {
            t.Fatalf("re-encode: %v", err)
        }
        if !bytes.Equal(encoded, reencoded) {
            t.Fatalf("encoding is not stable across a second round trip")
        }
        if again.NodeWidth() != tree.NodeWidth() {
            t.Fatalf("node width changed across a round trip: %d then %d",
                tree.NodeWidth(), again.NodeWidth())
        }
    })
}

func FuzzUpdatePathDecode(f *testing.F) {
    seedCorpus(f, "update_path")
    f.Fuzz(func(t *testing.T, data []byte) {
        path, err := ParseUpdatePath(data)
        if err != nil {
            return
        }
        encoded, err := path.Marshal()
        if err != nil {
            t.Fatalf("a decoded update path failed to re-encode: %v", err)
        }
        if !bytes.Equal(encoded, data) {
            t.Fatalf("ParseUpdatePath accepted a non-canonical encoding")
        }
        again, err := ParseUpdatePath(encoded)
        if err != nil {
            t.Fatalf("the canonical re-encoding failed to decode: %v", err)
        }
        if len(again.Nodes) != len(path.Nodes) {
            t.Fatalf("node count changed across a round trip")
        }
    })
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "FuzzRatchetTreeDecode|FuzzUpdatePathDecode" -v`
Expected: FAIL with `read corpus ratchet_tree: open testdata/corpus/ratchet_tree: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

Seed both corpora from material that already exists, so the corpus is derived rather than invented:

```bash
mkdir -p mls/testdata/corpus/ratchet_tree mls/testdata/corpus/update_path
cat > /tmp/seed_corpus_test.go <<'GOEOF'
package mls

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
)

// TestSeedTreeCorpus writes the ratchet trees and update paths carried by the
// vendored vectors into the fuzz corpora. run once, then deleted.
func TestSeedTreeCorpus(t *testing.T) {
    write := func(dir string, data []byte) {
        sum := sha256.Sum256(data)
        name := filepath.Join("testdata", "corpus", dir, hex.EncodeToString(sum[:8]))
        if err := os.WriteFile(name, data, 0o644); err != nil {
            t.Fatalf("write %s: %v", name, err)
        }
    }
    var validation []treeValidationVector
    if err := json.Unmarshal(treeVectorFile(t, "tree-validation.json"), &validation); err != nil {
        t.Fatalf("decode: %v", err)
    }
    for _, vector := range validation {
        write("ratchet_tree", treeHex(t, vector.Tree))
    }
    var treekem []treeKemVector
    if err := json.Unmarshal(treeVectorFile(t, "treekem.json"), &treekem); err != nil {
        t.Fatalf("decode: %v", err)
    }
    for _, vector := range treekem {
        write("ratchet_tree", treeHex(t, vector.RatchetTree))
        for _, update := range vector.UpdatePaths {
            write("update_path", treeHex(t, update.UpdatePath))
        }
    }
}
GOEOF
cp /tmp/seed_corpus_test.go mls/seed_corpus_test.go
go test ./mls/... -run TestSeedTreeCorpus -v
rm mls/seed_corpus_test.go
```

The corpus is a set of files under `mls/testdata/corpus/`, checked in, and the nightly differential
job in Spec A §4.4 adds to it from interop wire dumps. If the tree fuzz target finds a
round-trip instability, the reproducing input lands in `testdata/fuzz/` and is committed with the
fix, exactly like any other regression input.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "FuzzRatchetTreeDecode|FuzzUpdatePathDecode" -v`
Expected: PASS (seed corpus only)

Then the per-commit budget from Spec A §4.4:

Run: `go test ./mls/ -fuzz FuzzRatchetTreeDecode -fuzztime 60s`
Expected: `elapsed: 60s ... no failures`

Run: `go test ./mls/ -fuzz FuzzUpdatePathDecode -fuzztime 60s`
Expected: `elapsed: 60s ... no failures`

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_fuzz_test.go mls/testdata/corpus
git commit -m "test(mls): fuzz the ratchet tree and UpdatePath decoders for round-trip stability"
```

---

### Task 28: Benchmarks at the 500-member design target

**Files:**
- Create: `mls/tree_bench_test.go`
- Test: `mls/tree_bench_test.go`

**Interfaces:**
- Consumes: `newTestTree` (Task 9); `TreeHash` (Task 12); `VerifyParentHashes` (Task 14); `CreateUpdatePathSecrets`, `EncryptUpdatePath`, `MergeUpdatePath`, `DecryptUpdatePath` (Tasks 18, 20, 21, 22).
- Produces: `BenchmarkTreeHash500`, `BenchmarkVerifyParentHashes500`, `BenchmarkCreateAndEncryptUpdatePath500`, `BenchmarkMergeAndDecryptUpdatePath500`, and `TestJoinCostAt500MembersIsBounded`.

MASTER §6 fixes the group cap at 500 members. Whole-tree parent-hash verification is the one
operation in this plan that is superlinear — it computes an original tree hash per non-blank parent,
so it is O(n log n) hashes — and it runs on every join and on every out-of-band tree. A regression
there is felt as a join that takes seconds, which is the kind of thing that gets discovered by a
user rather than by CI.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_bench_test.go
package mls

import (
    "testing"
    "time"
)

func benchmarkTree(b *testing.B, n uint32) (*RatchetTree, []*testMember, CryptoProvider) {
    b.Helper()
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        b.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(b, crypto, n)
    return tree, members, crypto
}

func BenchmarkTreeHash500(b *testing.B) {
    tree, _, crypto := benchmarkTree(b, 500)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        if _, err := tree.TreeHash(crypto); err != nil {
            b.Fatalf("TreeHash: %v", err)
        }
    }
}

func BenchmarkVerifyParentHashes500(b *testing.B) {
    tree, members, crypto := benchmarkTree(b, 500)
    // a committed path gives the tree non-blank parents, which is what makes
    // verification cost anything at all.
    if _, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, []byte("bench")); err != nil {
        b.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        if err := tree.VerifyParentHashes(crypto); err != nil {
            b.Fatalf("VerifyParentHashes: %v", err)
        }
    }
}

func BenchmarkCreateAndEncryptUpdatePath500(b *testing.B) {
    tree, members, crypto := benchmarkTree(b, 500)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        working := tree.Clone()
        plan, err := working.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
            members[0].SignaturePriv, []byte("bench"))
        if err != nil {
            b.Fatalf("CreateUpdatePathSecrets: %v", err)
        }
        treeHash, err := working.TreeHash(crypto)
        if err != nil {
            b.Fatalf("TreeHash: %v", err)
        }
        if _, err := working.EncryptUpdatePath(crypto, plan, members[0].LeafIndex, treeHash, nil); err != nil {
            b.Fatalf("EncryptUpdatePath: %v", err)
        }
    }
}

func BenchmarkMergeAndDecryptUpdatePath500(b *testing.B) {
    tree, members, crypto := benchmarkTree(b, 500)
    sender := tree.Clone()
    plan, err := sender.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, []byte("bench"))
    if err != nil {
        b.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    treeHash, err := sender.TreeHash(crypto)
    if err != nil {
        b.Fatalf("TreeHash: %v", err)
    }
    path, err := sender.EncryptUpdatePath(crypto, plan, members[0].LeafIndex, treeHash, nil)
    if err != nil {
        b.Fatalf("EncryptUpdatePath: %v", err)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        receiver := tree.Clone()
        if err := receiver.MergeUpdatePath(crypto, members[0].LeafIndex, path); err != nil {
            b.Fatalf("MergeUpdatePath: %v", err)
        }
        priv := NewTreeKEMPrivate(members[1].LeafIndex, members[1].EncryptionPriv)
        if _, err := receiver.DecryptUpdatePath(crypto, members[0].LeafIndex, path,
            treeHash, priv, nil); err != nil {
            b.Fatalf("DecryptUpdatePath: %v", err)
        }
    }
}

// the join path — validate a tree that arrived out of band — must stay well inside
// a second at the 500-member cap, because it runs before the first message renders.
func TestJoinCostAt500MembersIsBounded(t *testing.T) {
    if testing.Short() {
        t.Skip("500-member tree construction is slow under -short")
    }
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 500)
    if _, err := tree.CreateUpdatePathSecrets(crypto, members[0].LeafIndex,
        members[0].SignaturePriv, testGroupId()); err != nil {
        t.Fatalf("CreateUpdatePathSecrets: %v", err)
    }
    start := time.Now()
    if err := tree.Validate(testTreeValidationContext(crypto)); err != nil {
        t.Fatalf("Validate: %v", err)
    }
    elapsed := time.Since(start)
    if elapsed > 2*time.Second {
        t.Fatalf("validating a 500-member tree took %s, want under 2s", elapsed)
    }
    t.Logf("500-member tree validation took %s", elapsed)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestJoinCostAt500MembersIsBounded -v`
Expected: FAIL with `validating a 500-member tree took Ns, want under 2s` — the un-memoised
`VerifyParentHashes` recomputes a subtree tree hash per non-blank parent, and at 500 members that is
the dominant cost of a join

- [ ] **Step 3: Write minimal implementation**

Memoise the plain tree hash for the length of one `VerifyParentHashes` call. When a parent has no
unmerged leaves, its original sibling tree hash *is* the plain tree hash of that sibling, so one
`TreeHashes` pass answers almost every query. The memo is a local, never a field on `RatchetTree`: a
cache that outlives a mutation is a hash that verifies when it should not.

Replace `ParentHash` and `VerifyParentHashes` in `mls/tree_hash.go` with:

```go
// the parent hash of parent taken with respect to copathChild. memo, when non-nil,
// supplies the plain tree hash per node index and is used only where the parent has
// no unmerged leaves and the two values therefore coincide.
func (self *RatchetTree) parentHashWithMemo(crypto CryptoProvider,
    parent, copathChild NodeIndex, memo [][]byte) ([]byte, error) {
    node := self.ParentAt(parent)
    if node == nil {
        return nil, ErrParentHashMismatch
    }
    var siblingHash []byte
    if len(node.UnmergedLeaves) == 0 && memo != nil && uint32(copathChild) < uint32(len(memo)) {
        siblingHash = memo[copathChild]
    } else {
        exclude := map[LeafIndex]bool{}
        for _, leaf := range node.UnmergedLeaves {
            exclude[leaf] = true
        }
        hash, err := self.treeHash(crypto, copathChild, exclude)
        if err != nil {
            return nil, err
        }
        siblingHash = hash
    }
    w := syntax.NewWriter()
    w.WriteOpaqueVec(node.EncryptionKey)
    w.WriteOpaqueVec(node.ParentHash)
    w.WriteOpaqueVec(siblingHash)
    return crypto.Hash(w.Bytes()), nil
}

func (self *RatchetTree) ParentHash(crypto CryptoProvider,
    parent, copathChild NodeIndex) ([]byte, error) {
    return self.parentHashWithMemo(crypto, parent, copathChild, nil)
}

func (self *RatchetTree) VerifyParentHashes(crypto CryptoProvider) error {
    memo, err := self.TreeHashes(crypto)
    if err != nil {
        return err
    }
    for x := uint32(1); x < self.NodeWidth(); x += 2 {
        node := NodeIndex(x)
        if self.ParentAt(node) == nil {
            continue
        }
        left, ok := Left(node)
        if !ok {
            return ErrTreeMalformed
        }
        right, ok := Right(node)
        if !ok {
            return ErrTreeMalformed
        }
        leftClaim, err := self.parentHashWithMemo(crypto, node, right, memo)
        if err != nil {
            return err
        }
        rightClaim, err := self.parentHashWithMemo(crypto, node, left, memo)
        if err != nil {
            return err
        }
        fromLeft := self.resolutionCarriesParentHash(left, leftClaim)
        fromRight := self.resolutionCarriesParentHash(right, rightClaim)
        if fromLeft == fromRight {
            return ErrParentHashMismatch
        }
    }
    return nil
}
```

Every Task 14 test must still pass unchanged — the memo changes no hash input, only how often each
one is computed.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestJoinCostAt500MembersIsBounded -v`
Expected: PASS, with the measured time logged

Run: `go test ./mls/ -bench 'Benchmark.*500' -benchtime 10x -run '^$'`
Expected: four benchmark lines, recorded in the commit message so a later regression has a baseline

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_bench_test.go mls/tree_hash.go
git commit -m "test(mls): tree and TreeKEM benchmarks at the 500-member cap"
```

---

### Task 29: The tree-operations vector family (family 9)

**Files:**
- Modify: `mls/tree_vectors_test.go`
- Test: `mls/tree_vectors_test.go`

**Interfaces:**
- Consumes: `ParseProposal`, `Proposal`, `ProposalKind`, `KeyPackage` (**Group lifecycle plan, wave 4**); `AddLeaf`, `UpdateLeaf`, `RemoveLeaf` (Task 15); `TreeHash` (Task 12); `RatchetTree.Marshal`, `UnmarshalRatchetTree` (Task 11).
- Produces: `TestVectorTreeOperations`.

**This is the only task in this plan that depends on wave 4.** The vector supplies a serialized
`Proposal`, and `Proposal` carries a `KeyPackage`, which `key_package.go` owns. Nothing else here is
blocked: the two gates this plan is measured on (`treekem`, `tree-validation`) are green at Task 26.
Run this task when `ParseProposal` exists; until then it is the one unchecked box.

Vector fields: `cipher_suite`, `tree_before`, `proposal`, `proposal_sender`, `tree_hash_before`,
`tree_after`, `tree_hash_after`.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_vectors_test.go (append)

type treeOperationsVector struct {
    CipherSuite    uint16 `json:"cipher_suite"`
    TreeBefore     string `json:"tree_before"`
    Proposal       string `json:"proposal"`
    ProposalSender uint32 `json:"proposal_sender"`
    TreeHashBefore string `json:"tree_hash_before"`
    TreeAfter      string `json:"tree_after"`
    TreeHashAfter  string `json:"tree_hash_after"`
}

func TestVectorTreeOperations(t *testing.T) {
    var vectors []treeOperationsVector
    if err := json.Unmarshal(treeVectorFile(t, "tree-operations.json"), &vectors); err != nil {
        t.Fatalf("decode tree-operations.json: %v", err)
    }
    if len(vectors) == 0 {
        t.Fatalf("tree-operations.json is empty")
    }
    ran := 0
    for i, vector := range vectors {
        if CipherSuite(vector.CipherSuite) != CipherSuiteX25519ChaCha20SHA256Ed25519 {
            continue
        }
        ran++
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d NewCryptoProvider: %v", i, err)
        }
        tree, err := UnmarshalRatchetTree(treeHex(t, vector.TreeBefore))
        if err != nil {
            t.Fatalf("vector %d UnmarshalRatchetTree: %v", i, err)
        }
        before, err := tree.TreeHash(crypto)
        if err != nil {
            t.Fatalf("vector %d TreeHash: %v", i, err)
        }
        if !bytes.Equal(before, treeHex(t, vector.TreeHashBefore)) {
            t.Fatalf("vector %d tree_hash_before = %x, want %s", i, before, vector.TreeHashBefore)
        }
        proposal, err := ParseProposal(treeHex(t, vector.Proposal))
        if err != nil {
            t.Fatalf("vector %d ParseProposal: %v", i, err)
        }
        switch proposal.Kind {
        case ProposalKindAdd:
            if _, err := tree.AddLeaf(proposal.Add.LeafNode.Clone()); err != nil {
                t.Fatalf("vector %d AddLeaf: %v", i, err)
            }
        case ProposalKindUpdate:
            if err := tree.UpdateLeaf(LeafIndex(vector.ProposalSender), proposal.Update.Clone()); err != nil {
                t.Fatalf("vector %d UpdateLeaf: %v", i, err)
            }
        case ProposalKindRemove:
            if err := tree.RemoveLeaf(*proposal.Remove); err != nil {
                t.Fatalf("vector %d RemoveLeaf: %v", i, err)
            }
        default:
            t.Fatalf("vector %d carries proposal kind %#x, which tree operations does not cover",
                i, proposal.Kind)
        }
        encoded, err := tree.Marshal()
        if err != nil {
            t.Fatalf("vector %d Marshal: %v", i, err)
        }
        if !bytes.Equal(encoded, treeHex(t, vector.TreeAfter)) {
            t.Fatalf("vector %d tree_after differs", i)
        }
        after, err := tree.TreeHash(crypto)
        if err != nil {
            t.Fatalf("vector %d TreeHash: %v", i, err)
        }
        if !bytes.Equal(after, treeHex(t, vector.TreeHashAfter)) {
            t.Fatalf("vector %d tree_hash_after = %x, want %s", i, after, vector.TreeHashAfter)
        }
    }
    if ran == 0 {
        t.Fatalf("no tree-operations vector used ciphersuite 0x0003")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestVectorTreeOperations -v`
Expected: FAIL to compile with `undefined: ParseProposal` until the Group lifecycle plan lands, then
a concrete `tree_after differs`

- [ ] **Step 3: Write minimal implementation**

No new production code. The two failures with a wrong fix available:

- `tree_after` differing only in trailing bytes means `Marshal` is not stripping trailing blanks, or
  `RemoveLeaf` is not truncating. Fix the operation, never the comparison.
- `tree_after` differing at a parent node after an Add means `AddLeaf` blanked the direct path
  instead of appending to `unmerged_leaves`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestVectorTreeOperations -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_vectors_test.go
git commit -m "test(mls): tree-operations vector family passes"
```

---

## Execution order and gates

Tasks 1 through 26 are strictly sequential: each depends on the one before it. Tasks 27 and 28 depend
only on Task 26. Task 29 additionally depends on the Group lifecycle plan.

| Gate | Green after |
|---|---|
| `tree-validation` (vector family 10) | Task 24 |
| `treekem` (vector family 11), both directions | Task 25 |
| Spec A Gate 3, the tree-owned ValSem codes 202, 203, 204, 206, 207, 300 | Task 26 |
| Spec A Gate 3, erratum 8745 | Task 7 |
| Spec A Gate 4 properties 1 and 2, tree decoders | Task 27 |
| `tree-operations` (vector family 9) | Task 29, after the Group lifecycle plan |

## What this plan does not own

Named here so no other plan waits on it:

- `key_package.go`, `proposal.go`, `commit.go`, `group.go`, `welcome` — Group lifecycle plan. The
  500-member and 10-device caps, the removal-authority rule and owner succession are all commit-level
  and live there, not in the tree.
- `credential.go` — Syntax and codec plan. This plan consumes `Credential` and `UnmarshalCredential`.
- `errors.go` and the other 37 ValSem codes — Validation and interop harness plan.
- `GroupContext` and its serialization — Key schedule and secret tree plan. This plan takes the
  serialized group context as `[]byte` everywhere except `ValidateAgainstContext`, which is the one
  place a `*GroupContext` is needed and the only source of a compile dependency on that plan.
- Erratum 8815 (§12.2, proposal references in a Commit) — Group lifecycle plan.
- The mlswg gRPC interop client — Validation and interop harness plan. It drives this package through
  `mls.Group`, so nothing here is exported for its benefit.


---

## Amendment A — reconciliation with the wave-1 plans as written

The wave-1 plans landed while this one was being written. Four contracts differ from the ones the
task bodies above assume. **Apply this amendment before Task 3**; it is mechanical, and every
difference is named here so no task body has to be re-read to find it.

### A.1 `connect/mls/syntax` — the landed names

| This plan's task bodies | The Syntax and codec plan's actual API |
|---|---|
| `w.WriteOpaqueVec(b)` | `w.WriteOpaque(b)` |
| `w.WriteBytes(b)` | `w.WriteRaw(b)` |
| `w.Bytes() []byte` | `w.Bytes() ([]byte, error)` — the `Writer` carries a sticky error |
| `r.ReadOpaqueVec()` | `r.ReadOpaque()` |
| `r.ReadVecReader()` | `r.ReadSub()` |
| `!r.Empty()` as a trailing-bytes check | `r.Done() error`, which returns `ErrTrailingBytes` |
| `syntax.ErrVectorTooLong` | `syntax.ErrLengthExceedsMax` |
| `syntax.MaxRatchetTreeLength` | unchanged; it is `int`, value `1 << 24` |

`r.Empty()` still exists and is still the right loop condition when iterating a sub-reader; only the
top-level "nothing left over" assertion becomes `r.Done()`.

The sticky-error `Writer` is the one difference that changes shape rather than spelling. Two helpers
absorb it, and they are the only place in the tree code that touches `Writer.Bytes`:

```go
// mls/tree_adapt.go — created by Task 3, before mls/extension.go
package mls

import "github.com/urnetwork/connect/mls/syntax"

// run an encoder against a fresh Writer and yield its bytes, surfacing the sticky
// error. every Marshal in this plan is one call to this.
func marshalBytes(encode func(w *syntax.Writer) error) ([]byte, error) {
    w := syntax.NewWriter()
    if err := encode(w); err != nil {
        return nil, err
    }
    return w.Bytes()
}

// opaque<V> whose body is a sequence of structs: encode into a sub-Writer, then
// write the result as one length-prefixed region.
func writeVec(w *syntax.Writer, encode func(inner *syntax.Writer) error) error {
    inner := syntax.NewWriter()
    if err := encode(inner); err != nil {
        return err
    }
    body, err := inner.Bytes()
    if err != nil {
        return err
    }
    w.WriteOpaque(body)
    return nil
}
```

Rewrite rule for every task body above. A block of the form

```go
inner := syntax.NewWriter()
for i := range items {
    if err := items[i].MarshalTo(inner); err != nil { return err }
}
w.WriteOpaqueVec(inner.Bytes())
```

becomes

```go
if err := writeVec(w, func(inner *syntax.Writer) error {
    for i := range items {
        if err := items[i].MarshalTo(inner); err != nil {
            return err
        }
    }
    return nil
}); err != nil {
    return err
}
```

and a block of the form

```go
w := syntax.NewWriter()
if err := self.MarshalTo(w); err != nil { return nil, err }
return w.Bytes(), nil
```

becomes `return marshalBytes(self.MarshalTo)`.

This affects exactly these functions: `Extension.MarshalTo`, `MarshalExtensions`, `writeUint16Vec`,
`Capabilities.MarshalTo`, `RequiredCapabilities.Marshal`, `LeafKeysExtension.Marshal`,
`LeafNode.marshalCore`, `LeafNode.Marshal`, `LeafNode.signatureContent`, `ParentNode.MarshalTo`,
`RatchetTree.Marshal`, `RatchetTree.leafHashInput`, `RatchetTree.parentHashInput`,
`RatchetTree.ParentHash` and `parentHashWithMemo`, `HpkeCiphertext.MarshalTo`,
`UpdatePathNode.MarshalTo`, `UpdatePath.MarshalTo`, `UpdatePath.Marshal`, and the test helper
`marshalRatchetTreeWithTrailingBlank`.

`writeUint16Vec` becomes:

```go
func writeUint16Vec[T ~uint16](w *syntax.Writer, values []T) error {
    return writeVec(w, func(inner *syntax.Writer) error {
        for _, v := range values {
            inner.WriteUint16(uint16(v))
        }
        return nil
    })
}
```

and every call site gains an `if err := ...; err != nil { return err }`.

### A.2 `connect/mls/tree_math.go` — the landed names

| This plan's task bodies | The Tree math plan's actual API |
|---|---|
| `NodeWidth(n uint32) uint32` | `NodeWidth(n LeafCount) uint32` |
| `Root(n uint32) NodeIndex` | `Root(n LeafCount) (NodeIndex, error)` |
| `Left(x) (NodeIndex, bool)` | `Left(x NodeIndex) (NodeIndex, error)` |
| `Right(x) (NodeIndex, bool)` | `Right(x NodeIndex) (NodeIndex, error)` |
| `Parent(x, n uint32) (NodeIndex, bool)` | `Parent(x NodeIndex, n LeafCount) (NodeIndex, error)` |
| `Sibling(x, n uint32) (NodeIndex, bool)` | `Sibling(x NodeIndex, n LeafCount) (NodeIndex, error)` |
| `DirectPath(x, n uint32) []NodeIndex` | `DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)` |
| `CoPath(...)` | `Copath(x NodeIndex, n LeafCount) ([]NodeIndex, error)` — lower-case p |
| `Level(x NodeIndex) uint32` | `x.Level() uint32`, a method |
| `x.LeafIndex() (LeafIndex, bool)` | `x.LeafIndex() (LeafIndex, error)` |
| `CommonAncestor(x, y)` | unchanged |

Shims, added to `mls/tree_adapt.go` in the same Task 3 step, keep the `(value, ok)` shape the task
bodies use. They convert an error to `false`, and every call site above already returns
`ErrTreeMalformed` on `false`, so no error is swallowed — it is re-raised with this package's own
type:

```go
func leftOf(x NodeIndex) (NodeIndex, bool)  { y, err := Left(x); return y, err == nil }
func rightOf(x NodeIndex) (NodeIndex, bool) { y, err := Right(x); return y, err == nil }

func siblingOf(x NodeIndex, leafWidth uint32) (NodeIndex, bool) {
    y, err := Sibling(x, LeafCount(leafWidth))
    return y, err == nil
}

func leafIndexOf(x NodeIndex) (LeafIndex, bool) {
    i, err := x.LeafIndex()
    return i, err == nil
}

// the RatchetTree invariant is a leaf width of at least one, so neither of these can
// fail through any path this package has. the guard is here so a future change to
// that invariant fails loudly rather than returning node zero.
func rootOf(leafWidth uint32) (NodeIndex, error) {
    if leafWidth == 0 {
        return 0, ErrTreeMalformed
    }
    return Root(LeafCount(leafWidth))
}

func directPathOf(x NodeIndex, leafWidth uint32) ([]NodeIndex, error) {
    if leafWidth == 0 {
        return nil, ErrTreeMalformed
    }
    return DirectPath(x, LeafCount(leafWidth))
}

func nodeWidthOf(leafWidth uint32) uint32 { return NodeWidth(LeafCount(leafWidth)) }
```

Substitutions in the task bodies: `Left(` → `leftOf(`, `Right(` → `rightOf(`,
`Sibling(x, self.LeafWidth())` → `siblingOf(x, self.LeafWidth())`, `x.LeafIndex()` → `leafIndexOf(x)`,
`NodeWidth(width)` → `nodeWidthOf(width)`, and `Level(x)` → `x.Level()`.

`Root(...)` and `DirectPath(...)` appear in single-value position in `RatchetTree.TreeHash`,
`BlankDirectPath`, `AddLeaf`, `RemoveLeaf`, `FilteredDirectPath`, `validateUnmergedLeaves`, and in
the resolution and tree-hash tests. Each becomes a two-value call with the error returned:

```go
root, err := rootOf(self.LeafWidth())
if err != nil {
    return nil, err
}
return self.treeHash(crypto, root, nil)
```

and in tests, `root, err := rootOf(tree.LeafWidth())` with a `t.Fatalf` on error.

### A.3 `Credential` is produced here, not consumed

The Group lifecycle plan (wave 4) lists `Credential` among the types it consumes **from this plan**,
and no wave-1 plan produces it. This plan therefore owns `mls/credential.go`, and the Consumes block
above is corrected: `Credential` and `UnmarshalCredential` are **Produces**, not Consumes.

Add to Task 3, as a sixth step before its commit:

```go
// mls/credential.go
package mls

import "github.com/urnetwork/connect/mls/syntax"

// RFC 9420 §5.3. BasicCredential only in v1. x509 is refused at parse rather than
// by a later check, so no x509 bytes are ever carried inside a LeafNode this
// package accepted. Spec A §3.2.
type Credential struct {
    CredentialType CredentialType
    Identity       []byte
}

func (self *Credential) MarshalTo(w *syntax.Writer) error {
    if self.CredentialType != CredentialTypeBasic {
        return ErrProfileCredentialType
    }
    w.WriteUint16(uint16(self.CredentialType))
    w.WriteOpaque(self.Identity)
    return nil
}

func UnmarshalCredential(r *syntax.Reader) (Credential, error) {
    credentialType, err := r.ReadUint16()
    if err != nil {
        return Credential{}, err
    }
    if CredentialType(credentialType) != CredentialTypeBasic {
        return Credential{}, ErrProfileCredentialType
    }
    identity, err := r.ReadOpaque()
    if err != nil {
        return Credential{}, err
    }
    return Credential{CredentialType: CredentialTypeBasic, Identity: identity}, nil
}
```

`ErrProfileCredentialType` comes from `errors.go` (Validation plan), per Spec A §3.2. Its test, added
to `mls/extension_test.go` in the same step:

```go
func TestCredentialRefusesX509(t *testing.T) {
    w := syntax.NewWriter()
    w.WriteUint16(0x0002) // x509
    w.WriteOpaque([]byte("cert"))
    encoded, err := w.Bytes()
    if err != nil {
        t.Fatalf("Bytes: %v", err)
    }
    if _, err := UnmarshalCredential(syntax.NewReader(encoded)); !errors.Is(err, ErrProfileCredentialType) {
        t.Fatalf("err = %v, want ErrProfileCredentialType", err)
    }
    basic := Credential{CredentialType: CredentialTypeBasic, Identity: []byte("alice")}
    out, err := marshalBytes(basic.MarshalTo)
    if err != nil {
        t.Fatalf("MarshalTo: %v", err)
    }
    got, err := UnmarshalCredential(syntax.NewReader(out))
    if err != nil {
        t.Fatalf("UnmarshalCredential: %v", err)
    }
    if got.CredentialType != CredentialTypeBasic || string(got.Identity) != "alice" {
        t.Fatalf("round trip = %+v", got)
    }
}
```

### A.4 The ValSem-named tests belong to the Validation plan

The Validation and interop harness plan owns Gate 3 and declares, by name,
`TestValSem202_PathLength`, `TestValSem203_PathDecrypt`, `TestValSem204_PathKeyMismatch`,
`TestValSem206_PathLeafDuplicateEncryptionKey`, `TestValSem207_PathNodeDuplicateEncryptionKey` and
`TestValSem300_TrailingBlankNodes`. Four of those names are also used by Tasks 11, 21, 22 and 26
here, and two test functions with the same name in one package do not compile.

**Rename every ValSem-named test in this plan**, keeping the assertions exactly as written:

| Task | This plan's name becomes | The Validation plan's name it must not collide with |
|---|---|---|
| 11 | `TestRatchetTreeRefusesTrailingBlankNodes` | `TestValSem300_TrailingBlankNodes` |
| 21 | `TestMergeUpdatePathRejectsAWrongLengthPath` | `TestValSem202_PathLength` |
| 22 | `TestDecryptUpdatePathRejectsATamperedCiphertext` | `TestValSem203_PathDecrypt` |
| 22 | `TestDecryptUpdatePathRejectsAnAnnouncedKeyMismatch` | `TestValSem204_PathKeyMismatch` |
| 26 | `TestUpdatePathLeafKeyUniqueness` | `TestValSem206_PathLeafDuplicateEncryptionKey` |
| 26 | `TestUpdatePathNodeKeyUniqueness` | `TestValSem207_PathNodeDuplicateEncryptionKey` |

Task 26's `TestTreeValSemCoverage` is deleted along with them: coverage of the ValSem set is asserted
once, in the Validation plan, and asserting it twice against two name lists is how the two lists
drift apart. What this plan keeps is the production surface those tests drive —
`CheckUpdatePathKeyUniqueness`, `MergeUpdatePath`, `DecryptUpdatePath`, `UnmarshalRatchetTree` — plus
the renamed tests above, which are this package's own regression net and are named for the behaviour
rather than for the code.

The `Run:` lines in Tasks 11, 21, 22 and 26 change to match the new names, and the gate table's
Gate 3 row now reads: green when the Validation plan's `validation_commit_test.go` runs against
Task 26's `CheckUpdatePathKeyUniqueness`.

