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

The four slice-wide conventions from the canonical interface registry, verbatim:

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

**C2 — the syntax Writer is sticky *and* `MarshalMLS` returns an error.** Leaf writes
(`WriteUint16`, `WriteOpaque`, …) return nothing and route buffer failures into the Writer's sticky
error, checked once at `Bytes() ([]byte, error)`. `MarshalMLS` returns an `error` so an encoder can
raise a *semantic* refusal that is not a buffer error — `Credential.MarshalMLS` returning
`ErrProfileCredentialType` on an x509 credential is the case in this plan. `syntax.Marshal` returns
`errors.Join(v.MarshalMLS(w), w.Err())`, so both surface. Higher-order encode callbacks
(`syntax.WriteVector`, `(*Writer).WriteOptional`) return `error` for the same reason.

**C3 — counts are `LeafCount`, indices are `LeafIndex`/`NodeIndex`, and tree-math arithmetic that
can be out of range returns an error.** The tree-math plan's block is normative for every caller.
`TreeSize` does not exist.

**C4 — the GroupContext crosses a plan boundary as bytes.** Every framing entry point takes
`groupContext []byte`. Callers obtain them from `syntax.Marshal(gc)` or `(*Group).GroupContext()`.
This plan takes `groupContext []byte` in `EncryptUpdatePath` and `DecryptUpdatePath` for the same
reason.

---

## File Structure

| File | Single responsibility |
|---|---|
| `mls/tree_errors.go` | **Create.** The typed errors raised by tree and TreeKEM code that are *not* ValSem-numbered. ValSem-numbered errors and every `ErrProfile*` come from `errors.go` (validation plan). |
| `mls/tree_adapt.go` | **Create.** The private helpers this package uses against the wave-1 surfaces: `marshalBytes` for the preimages that are not `syntax.Codec` values, and the `leftOf`/`rightOf`/`leafIndexOf`/`rootOf`/`directPathOf` tree-math shims. Internal to this plan; no other plan gets them. |
| `mls/extension.go` | **Create.** The IANA registry enums — `ProtocolVersion`, `CredentialType`, `ProposalType`, `ExtensionType` and their constants — plus `Extension`, `WriteExtensions`/`ReadExtensions`/`FindExtension`, `Capabilities`, `RequiredCapabilities`, and the `urmessage_leaf_keys` (0xF002) extension body. Wire codec for each. |
| `mls/extension_test.go` | **Create.** Round-trip and rejection tests for the above. |
| `mls/credential.go` | **Create.** `Credential` and `BasicCredential`, refusing every non-basic credential type at parse. |
| `mls/leaf_node.go` | **Create.** `LeafNodeSource`, `Lifetime`, `LeafNode`, `NewLeafNode`, LeafNodeTBS signing and signature verification, RFC 9420 §7.3 leaf validation including erratum 8745. |
| `mls/leaf_node_test.go` | **Create.** LeafNode codec, construction, signing, and §7.3 validation tests. |
| `mls/key_package.go` | **Create.** `KeyPackage`, `NewKeyPackage`, `(*KeyPackage).Ref`, `(*KeyPackage).Validate` and the KeyPackageTBS signature. |
| `mls/key_package_test.go` | **Create.** KeyPackage codec, construction, ref and validation tests. |
| `mls/tree.go` | **Create.** `NodeType`, `ParentNode`, `Node`, `OptionalNode`, `RatchetTree` storage and accessors, the `NodeShape` implementation, blanking, resolution, add/update/remove, truncation, filtered direct path, copath encryption targets, and the `ratchet_tree` extension codec. |
| `mls/tree_test.go` | **Create.** Structure, resolution, tree-operation and codec tests. |
| `mls/tree_hash.go` | **Create.** `TreeHashInput`/`LeafNodeHashInput`/`ParentNodeHashInput`, the tree hash, the original tree hash under an exclusion set, `ParentHashInput`, and parent-hash verification (§7.9.2). |
| `mls/tree_hash_test.go` | **Create.** Tree hash, original tree hash and parent-hash-validity tests. |
| `mls/tree_sync.go` | **Create.** Whole-tree validation: structure, leaf validation across the tree, key uniqueness, unmerged-leaf consistency, parent hashes, tree hash against a GroupContext value, and `CheckUpdatePathKeyUniqueness`. |
| `mls/tree_sync_test.go` | **Create.** Tree validation tests, including the negative cases owned here. |
| `mls/treekem.go` | **Create.** `HpkeCiphertext`, `SealWithLabel`/`OpenWithLabel`, `UpdatePathNode`, `UpdatePath` and their codec; path-secret ladder; `TreeKEMPrivate`; UpdatePath creation, encryption, merge and decryption. |
| `mls/treekem_test.go` | **Create.** Path secret, create/encrypt/merge/decrypt and negative tests. |
| `mls/tree_testutil_test.go` | **Create.** The n-member test tree builder shared by every test file in this plan. |
| `mls/tree_kat_test.go` | **Create.** Runners for vector families 10 (tree-validation) and 11 (TreeKEM), each registering itself through `RegisterVectorFamily`. Family 9 (tree-operations) is the group lifecycle plan's. |
| `mls/tree_roundtrip_test.go` | **Create.** The corpus-driven no-panic and round-trip-stability regression tests for the ratchet tree and UpdatePath decoders. The `Fuzz*` targets themselves are the validation plan's (§9.5); this file contributes the seed corpus and the deterministic regression net. |
| `mls/tree_bench_test.go` | **Create.** Tree hash, parent-hash verification and UpdatePath benchmarks at the 500-member design target. |
| `mls/interop/testdata/corpus/ratchet_tree/`, `mls/interop/testdata/corpus/update_path/` | **Create.** Seed corpus contributions to the corpus directory the validation plan's fuzz targets and the nightly differential job read. |

Vendoring is **not** in this plan. `mls/testdata/vectors/*.json`, `testdata/vectors/VECTORS.sha256`
and `mls/interop/PINS.md` are all produced by the validation plan's single vendoring task; this plan
keeps only its runners and reads the files through `LoadVectorFile`.

---

## Interfaces consumed from other plans

Every symbol below is in package `mls` (or `mls/syntax`) and is written by another plan in this
slice. This plan does not define any of them.

```go
// mls/syntax — Syntax and codec plan (wave 1)
package syntax

const MaxVectorLength int = 1 << 20       // 1 MiB, every field but the tree
const MaxRatchetTreeLength int = 1 << 24  // 16 MiB, the ratchet tree only

var ErrTruncated error
var ErrTrailingBytes error
var ErrLengthExceedsMax error
var ErrOptionalPresence error

type Writer struct{ ... }                        // not safe for concurrent use
func NewWriter() *Writer
func NewWriterLimit(maxVectorLength int) *Writer
func (self *Writer) Bytes() ([]byte, error)      // undefined when err non-nil
func (self *Writer) Err() error
func (self *Writer) Len() int
func (self *Writer) MaxVectorLength() int
func (self *Writer) WriteUint8(v uint8)
func (self *Writer) WriteUint16(v uint16)
func (self *Writer) WriteUint32(v uint32)
func (self *Writer) WriteUint64(v uint64)
func (self *Writer) WriteRaw(bs []byte)          // opaque x[N], no prefix
func (self *Writer) WriteOpaque(bs []byte)       // opaque x<V>; nil == empty
func (self *Writer) WriteOptional(present bool, encodeOne func(w *Writer) error) error

type Reader struct{ ... }                                    // not safe for concurrent use
func NewReader(bs []byte) *Reader
func NewReaderLimit(bs []byte, maxVectorLength int) *Reader
func (self *Reader) Offset() int
func (self *Reader) Remaining() int
func (self *Reader) Empty() bool
func (self *Reader) MaxVectorLength() int
func (self *Reader) Done() error             // ErrTrailingBytes when bytes remain
func (self *Reader) ReadUint8() (uint8, error)
func (self *Reader) ReadUint16() (uint16, error)
func (self *Reader) ReadUint32() (uint32, error)
func (self *Reader) ReadUint64() (uint64, error)
func (self *Reader) ReadRaw(n int) ([]byte, error)     // opaque x[N]; a COPY
func (self *Reader) ReadOpaque() ([]byte, error)       // a COPY, never nil
func (self *Reader) ReadSub() (*Reader, error)         // bounded view of the next opaque<V>
func (self *Reader) ReadOptional(decodeOne func(r *Reader) error) (present bool, err error)

func WriteVector[T any](w *Writer, items []T, encodeOne func(w *Writer, item T) error) error
func ReadVector[T any](r *Reader, decodeOne func(r *Reader) (T, error)) ([]T, error)

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

func Marshal(v Marshaler) ([]byte, error)
func Unmarshal(bs []byte, v Unmarshaler) error         // enforces full consumption
func UnmarshalLimit(bs []byte, v Unmarshaler, maxVectorLength int) error
```

```go
// mls/suite.go, mls/crypto*.go, mls/hpke.go — Crypto primitives and HPKE plan (wave 1)
package mls

type CipherSuite uint16
const CipherSuiteX25519ChaCha20Sha256Ed25519 CipherSuite = 0x0003

type SuiteParams struct {
    Suite       CipherSuite
    Name        string
    KemId       uint16
    KdfId       uint16
    AeadId      uint16
    SignatureId uint16
    Nh          int
    Nk          int
    Nn          int
    Nt          int
    Nsecret     int
    Nenc        int
    Npk         int
    Nsk         int
    NsigPub     int
    NsigPriv    int
}
func LookupSuite(suite CipherSuite) (*SuiteParams, error)

type HpkePublicKey []byte
type HpkePrivateKey []byte
type SignaturePublicKey []byte
type SignaturePrivateKey []byte    // Ed25519 32-byte seed

type CryptoProvider interface {                     // exactly Spec A §3.3
    Suite() CipherSuite
    HashSize() int
    KeySize() int
    NonceSize() int
    Hash(data []byte) []byte
    Mac(key []byte, data []byte) []byte
    MacVerify(key []byte, data []byte, tag []byte) bool
    Extract(salt []byte, ikm []byte) []byte
    Expand(prk []byte, info []byte, length int) []byte
    ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte
    DeriveSecret(secret []byte, label string) []byte
    DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte
    AeadSeal(key []byte, nonce []byte, aad []byte, plaintext []byte) ([]byte, error)
    AeadOpen(key []byte, nonce []byte, aad []byte, ciphertext []byte) ([]byte, error)
    SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error)
    VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error
    HpkeSeal(pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)
    HpkeOpen(priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error)
    DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error)
    SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error)
    Random(n int) []byte
}
func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)

func RefHash(crypto CryptoProvider, label string, value []byte) []byte
func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte

// RFC 9420 §5.1.3, wrapping RFC 9180 SealBase/OpenBase with the MLS EncryptContext struct.
// The flat byte-slice form is normative; the HpkeCiphertext-shaped convenience over it is
// SealWithLabel/OpenWithLabel, Produced by THIS plan.
func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)
func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error)
```

```go
// mls/tree_math.go — Tree math plan (wave 1). Normative in full; every arithmetic that
// can be out of range returns an error (C3).
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

```go
// mls/errors.go — Validation and interop harness plan (wave 1). The single declaration
// site for every ValSem-numbered sentinel and every v1-profile refusal.
package mls

type ValSemCode uint16
func ValSem(code ValSemCode, detail error) error

var ErrBadSignature error                // ValSem010
var ErrDuplicateSignatureKey error       // ValSem101
var ErrDuplicateEncryptionKey error      // ValSem103 / 110 / 206 / 207
var ErrMissingRequiredCapability error   // ValSem106 / 109
var ErrMissingPath error                 // ValSem201
var ErrPathLength error                  // ValSem202
var ErrPathDecrypt error                 // ValSem203
var ErrPathKeyMismatch error             // ValSem204
var ErrUnsupportedGroupExtension error   // ValSem209
var ErrTrailingBlankNodes error          // ValSem300
var ErrProfileCredentialType error       // the v1 BasicCredential-only refusal
var ErrProfileCiphersuite error          // the v1 single-suite refusal
```

```go
// mls/profile.go — Validation and interop harness plan (wave 1)
package mls

type Profile struct{ ... }
func (self *Profile) CheckCredentialType(t CredentialType) error
```

```go
// mls/key_schedule.go, mls/group_context.go — Key schedule and secret tree plan (wave 2)
package mls

// Consumed only by tree_sync.go and the family-11 runner, to check a tree hash against
// the context that pinned it and to build the HPKE context bytes.
type GroupContext struct {
    Version                 ProtocolVersion   // the ProtocolVersion type is Produced by THIS plan
    CipherSuite             CipherSuite
    GroupId                 []byte
    Epoch                   uint64
    TreeHash                []byte
    ConfirmedTranscriptHash []byte
    Extensions              []Extension       // the Extension type is Produced by THIS plan
}
func (self *GroupContext) MarshalMLS(w *syntax.Writer) error
func (self *GroupContext) UnmarshalMLS(r *syntax.Reader) error
// bytes come from syntax.Marshal(gc); GroupContext has no Marshal method of its own (C1).
```

```go
// mls/vectors_test.go — Validation and interop harness plan (wave 1). The one vector
// registry, the one hex decoder, the one loader. This plan defines none of them.
package mls

type VectorFamily struct {
    Number   int
    Name     string
    File     string
    Slice    string
    Verify   func(t *testing.T, raw json.RawMessage)
    Generate func(t *testing.T) json.RawMessage
}
func RegisterVectorFamily(family VectorFamily)
func LoadVectorFile(t *testing.T, file string) []json.RawMessage
func MustHex(t *testing.T, s string) []byte
func HexOf(b []byte) string
```

---

## Interfaces produced by this plan

The complete contract other plans write their Consumes blocks against, taken verbatim from the
canonical interface registry §6. Nothing else in these files is exported.

```go
package mls

// ---- extension.go: the IANA registry enums ----
type ProtocolVersion uint16
const ProtocolVersionMls10 ProtocolVersion = 0x0001

type CredentialType uint16
const CredentialTypeBasic CredentialType = 0x0001

type ProposalType uint16
const (
    ProposalTypeReserved               ProposalType = 0x0000
    ProposalTypeAdd                    ProposalType = 0x0001
    ProposalTypeUpdate                 ProposalType = 0x0002
    ProposalTypeRemove                 ProposalType = 0x0003
    ProposalTypePreSharedKey           ProposalType = 0x0004
    ProposalTypeReInit                 ProposalType = 0x0005
    ProposalTypeExternalInit           ProposalType = 0x0006
    ProposalTypeGroupContextExtensions ProposalType = 0x0007
)

type ExtensionType uint16
const (
    ExtensionTypeRatchetTree             ExtensionType = 0x0002
    ExtensionTypeRequiredCapabilities    ExtensionType = 0x0003
    ExtensionTypeExternalSenders         ExtensionType = 0x0004
    ExtensionTypeUrmessageGroupPolicy    ExtensionType = 0xF001
    ExtensionTypeUrmessageLeafKeys       ExtensionType = 0xF002
    ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003
)

// ---- extension.go: Extension ----
type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}
func (self *Extension) MarshalMLS(w *syntax.Writer) error
func (self *Extension) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*Extension)(nil)

func WriteExtensions(w *syntax.Writer, exts []Extension) error
func ReadExtensions(r *syntax.Reader) ([]Extension, error)
func FindExtension(exts []Extension, t ExtensionType) ([]byte, bool)

// ---- extension.go: Capabilities and RequiredCapabilities ----
type Capabilities struct {
    Versions     []ProtocolVersion
    CipherSuites []CipherSuite
    Extensions   []ExtensionType
    Proposals    []ProposalType
    Credentials  []CredentialType
}
func (self *Capabilities) MarshalMLS(w *syntax.Writer) error
func (self *Capabilities) UnmarshalMLS(r *syntax.Reader) error
func (self *Capabilities) SupportsVersion(v ProtocolVersion) bool
func (self *Capabilities) SupportsCipherSuite(s CipherSuite) bool
func (self *Capabilities) SupportsExtension(t ExtensionType) bool
func (self *Capabilities) SupportsProposal(t ProposalType) bool
func (self *Capabilities) SupportsCredential(t CredentialType) bool
func (self *Capabilities) Supports(rc *RequiredCapabilities) error
var _ syntax.Codec = (*Capabilities)(nil)

type RequiredCapabilities struct {
    ExtensionTypes  []ExtensionType
    ProposalTypes   []ProposalType
    CredentialTypes []CredentialType
}
func (self *RequiredCapabilities) MarshalMLS(w *syntax.Writer) error
func (self *RequiredCapabilities) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*RequiredCapabilities)(nil)

// ---- extension.go: the X-Wing constants and urmessage_leaf_keys, 0xF002 ----
// MASTER §5.3, Spec A §3.4. The 1216 is duplicated across the mls/message package
// boundary on purpose: mls must not import message. The crypto plan carries the
// compile assertion that message.XwingPublicKeySize and this agree.
const AlgIdXwing uint16 = 0x0014
const XwingPublicKeyLen = 1216
type LeafKeysExtension struct {
    AlgId          uint16      // 0x0014 = X-Wing (X25519 + ML-KEM-768)
    DeviceXwingPub []byte      // exactly XwingPublicKeyLen bytes for alg 0x0014
}
func (self *LeafKeysExtension) Encode() (Extension, error)
func ParseLeafKeysExtension(data []byte) (*LeafKeysExtension, error)

// ---- credential.go ----
type Credential struct {
    CredentialType CredentialType   // 0x0001 basic only in v1
    Identity       []byte           // BasicCredential.identity
}
func (self *Credential) MarshalMLS(w *syntax.Writer) error   // ErrProfileCredentialType on x509
func (self *Credential) UnmarshalMLS(r *syntax.Reader) error // ErrProfileCredentialType on x509
func BasicCredential(identity []byte) Credential
var _ syntax.Codec = (*Credential)(nil)

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
    Lifetime       Lifetime     // source == key_package
    ParentHash     []byte       // source == commit
    Extensions     []Extension
    Signature      []byte
}
func (self *LeafNode) MarshalMLS(w *syntax.Writer) error
func (self *LeafNode) UnmarshalMLS(r *syntax.Reader) error
func (self *LeafNode) Clone() *LeafNode
var _ syntax.Codec = (*LeafNode)(nil)

func NewLeafNode(crypto CryptoProvider, signer SignaturePrivateKey, cred Credential,
    encKey HpkePublicKey, caps Capabilities, exts []Extension) (*LeafNode, error)
func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey, groupId []byte, leafIndex LeafIndex) error
func (self *LeafNode) VerifySignature(crypto CryptoProvider, groupId []byte, leafIndex LeafIndex) error

type LeafValidationContext struct {
    Crypto          CryptoProvider
    Suite           CipherSuite
    GroupId         []byte
    LeafIndex       LeafIndex
    ExpectedSource  LeafNodeSource
    RequiredCaps    *RequiredCapabilities
    GroupExtensions []Extension
    NowMs           uint64        // 0 skips the lifetime check
    ClockSkewMs     uint64
}
func (self *LeafNode) Validate(ctx *LeafValidationContext) error

// ---- key_package.go ----
type KeyPackage struct {
    Version     ProtocolVersion
    CipherSuite CipherSuite
    InitKey     HpkePublicKey
    LeafNode    LeafNode
    Extensions  []Extension
    Signature   []byte
}
func (self *KeyPackage) MarshalMLS(w *syntax.Writer) error
func (self *KeyPackage) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*KeyPackage)(nil)

func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,
    caps Capabilities, exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
    encPriv HpkePrivateKey, err error)
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error)
func (self *KeyPackage) Validate(crypto CryptoProvider, suite CipherSuite, now time.Time) error

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
func (self *ParentNode) MarshalMLS(w *syntax.Writer) error
func (self *ParentNode) UnmarshalMLS(r *syntax.Reader) error
func (self *ParentNode) Clone() *ParentNode
type Node struct {
    NodeType NodeType
    Leaf     *LeafNode
    Parent   *ParentNode
}
type OptionalNode struct {
    Present bool
    Node    Node
}

type RatchetTree struct{ /* opaque: nodes []*Node */ }
func NewRatchetTree() *RatchetTree
func (self *RatchetTree) MarshalMLS(w *syntax.Writer) error
func (self *RatchetTree) UnmarshalMLS(r *syntax.Reader) error
func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)   // UnmarshalLimit(MaxRatchetTreeLength)
var _ syntax.Codec = (*RatchetTree)(nil)

func (self *RatchetTree) LeafWidth() LeafCount        // leaf slots; a power of two
func (self *RatchetTree) NodeWidth() uint32
func (self *RatchetTree) Get(x NodeIndex) *Node       // nil when blank or out of range
func (self *RatchetTree) Leaf(i LeafIndex) *LeafNode
func (self *RatchetTree) ParentAt(x NodeIndex) *ParentNode
func (self *RatchetTree) SetLeaf(i LeafIndex, leaf *LeafNode) error
func (self *RatchetTree) SetParent(x NodeIndex, parent *ParentNode) error
func (self *RatchetTree) Blank(x NodeIndex) error
func (self *RatchetTree) BlankDirectPath(i LeafIndex) error
func (self *RatchetTree) Clone() *RatchetTree
func (self *RatchetTree) Members() []LeafIndex
func (self *RatchetTree) MemberCount() uint32
func (self *RatchetTree) NonBlankLeaves() []LeafIndex
func (self *RatchetTree) FindLeafBySignatureKey(key SignaturePublicKey) (LeafIndex, bool)
func (self *RatchetTree) EncryptionKeyInUse(key HpkePublicKey) bool
func (self *RatchetTree) HasTrailingBlankNodes() bool
func (self *RatchetTree) Resolution(x NodeIndex) []NodeIndex
func (self *RatchetTree) AddLeaf(leaf *LeafNode) (LeafIndex, error)
func (self *RatchetTree) UpdateLeaf(i LeafIndex, leaf *LeafNode) error
func (self *RatchetTree) RemoveLeaf(i LeafIndex) error
func (self *RatchetTree) FilteredDirectPath(i LeafIndex) ([]NodeIndex, error)
func (self *RatchetTree) EncryptionTargets(sender LeafIndex, exclude []LeafIndex) ([][]NodeIndex, error)

// RatchetTree implements the tree math plan's NodeShape, with UnmergedLeaves returning
// the stored list in stored order.
func (self *RatchetTree) LeafCount() LeafCount
func (self *RatchetTree) IsBlank(x NodeIndex) bool
func (self *RatchetTree) UnmergedLeaves(x NodeIndex) []LeafIndex
var _ NodeShape = (*RatchetTree)(nil)

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
func CheckUpdatePathKeyUniqueness(tree *RatchetTree, path *UpdatePath) error

// ---- treekem.go ----
type HpkeCiphertext struct {
    KemOutput  []byte
    Ciphertext []byte
}
func (self *HpkeCiphertext) MarshalMLS(w *syntax.Writer) error
func (self *HpkeCiphertext) UnmarshalMLS(r *syntax.Reader) error

// the HpkeCiphertext-shaped convenience over the crypto plan's flat pair — it lives
// here, next to the type it returns, so the crypto plan stays free of TreeKEM types.
func SealWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string,
    context []byte, plaintext []byte) (*HpkeCiphertext, error)
func OpenWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string,
    context []byte, ct *HpkeCiphertext) ([]byte, error)

type UpdatePathNode struct {
    EncryptionKey       HpkePublicKey
    EncryptedPathSecret []HpkeCiphertext
}
type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode
}
func (self *UpdatePath) MarshalMLS(w *syntax.Writer) error
func (self *UpdatePath) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*UpdatePath)(nil)

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

**Ownership notes carried over from the registry, so no other plan waits on this one.**

- `KeyPackage` was consumed by four plans and produced by none. It lands here, in wave 2, beside
  `leaf_node.go`: it is a `LeafNode` plus an init key plus a signature, it depends only on the
  crypto plan and this plan's own types, and putting it in wave 4 is what would make the framing
  plan's wave-3 `MLSMessage` uncompilable, since `package mls` is one package.
- `Credential` and `BasicCredential` land here: no wave-1 plan produces any MLS type.
- `NewLeafNode`, `(*Capabilities).Supports`, `NonBlankLeaves`, `EncryptionKeyInUse`,
  `HasTrailingBlankNodes`, `OptionalNode`, `SealWithLabel` and `OpenWithLabel` are symbols the group
  lifecycle and validation plans call and nobody produced. They are all reads of, or thin wrappers
  over, this plan's own types, so they land here rather than being open-coded elsewhere.
- `LeafKeysExtension`, `AlgIdXwing` and the 1216 constant are this plan's, not the group lifecycle
  plan's: the leaf node carries the extension and `LeafNode.Validate` range-checks it. That plan
  keeps only the `LeafKeysOf(leaf)` accessor.
- The registry enums — `ProtocolVersion`, `ProposalType`, `ExtensionType` and their constants — are
  this plan's. The framing plan declares none of them; it owns the wire structs that use them.
  **This plan's Task 3 sequences first in wave 2**, before the key schedule plan's Task 3, because
  that plan consumes `Extension` and `WriteExtensions`/`ReadExtensions` from here.

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

### Task 1: The tree vector runner file, wired to the shared registry

**Files:**
- Create: `mls/tree_kat_test.go`
- Test: `mls/tree_kat_test.go`

**Interfaces:**
- Consumes: `LoadVectorFile(t *testing.T, file string) []json.RawMessage`, `MustHex(t *testing.T, s string) []byte`, `HexOf(b []byte) string`, `RegisterVectorFamily(family VectorFamily)`, `VectorFamily` (Validation and interop harness plan, wave 1); `CipherSuite`, `CipherSuiteX25519ChaCha20Sha256Ed25519` (Crypto plan, wave 1).
- Produces: nothing exported. This task creates the file the family-10 and family-11 runners live in and the one private helper they share, `treeVectorsOfSuite`.

**Vendoring is not this plan's.** The validation plan has the single vendoring task for all sixteen
mlswg files, `testdata/vectors/VECTORS.sha256` and `mls/interop/PINS.md`. Three parallel hex
decoders and three pin files over one corpus is how two of them end up disagreeing about the empty
string, so this plan defines no `treeVectorFile`, no `treeHex` and no `PINS.md`, and calls
`LoadVectorFile`/`MustHex`/`HexOf` instead. If `testdata/vectors/tree-validation.json` is missing
when this task runs, the fix is to run the validation plan's vendoring task, not to download it here.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_kat_test.go
package mls

import (
    "encoding/json"
    "testing"
)

// the three mlswg files whose contents this package's code is exercised against.
// family 9 (tree-operations) is verified by the group lifecycle plan, because its
// vector carries a serialized Proposal; the two families this plan gates on are 10
// and 11.
var treeVectorFiles = []string{
    "tree-validation.json",
    "treekem.json",
}

// decode every entry of a vendored vector file into T and keep only the entries for
// the implemented ciphersuite. every runner in this file starts with one call to it.
func treeVectorsOfSuite[T any](t *testing.T, file string, suiteOf func(v *T) CipherSuite) []T {
    t.Helper()
    raws := LoadVectorFile(t, file)
    if len(raws) == 0 {
        t.Fatalf("%s is empty", file)
    }
    out := []T{}
    for i, raw := range raws {
        var v T
        if err := json.Unmarshal(raw, &v); err != nil {
            t.Fatalf("%s entry %d: %v", file, i, err)
        }
        if suiteOf(&v) != CipherSuiteX25519ChaCha20Sha256Ed25519 {
            continue
        }
        out = append(out, v)
    }
    if len(out) == 0 {
        t.Fatalf("no entry of %s used ciphersuite 0x0003", file)
    }
    return out
}

func TestTreeVectorFilesAreVendored(t *testing.T) {
    for _, file := range treeVectorFiles {
        if raws := LoadVectorFile(t, file); len(raws) == 0 {
            t.Fatalf("%s decoded to zero entries", file)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestTreeVectorFilesAreVendored -v`
Expected: FAIL to compile with `undefined: LoadVectorFile` until the validation plan's wave-1 tasks
land; once they have, FAIL with the loader's own "no such file" until its vendoring task has run

- [ ] **Step 3: Write minimal implementation**

No production code. The file above *is* the deliverable; the failure is resolved by the validation
plan's wave-1 registry task (`LoadVectorFile`, `MustHex`, `HexOf`, `RegisterVectorFamily`) and its
vendoring task (the sixteen files plus `VECTORS.sha256`), both of which precede this plan.

If `LoadVectorFile` exists but the two files do not, run the validation plan's vendoring task. Do
not add a second download step here and do not add `mls/testdata/vectors/PINS.md`: the one pin file
is `mls/interop/PINS.md`, and two pin files at two paths is exactly the drift the single vendoring
task exists to prevent.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestTreeVectorFilesAreVendored -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_kat_test.go
git commit -m "test(mls): tree vector runner file wired to the shared vector registry"
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

### Task 3: The registry enums, Extension, Capabilities and RequiredCapabilities

**Files:**
- Create: `mls/tree_adapt.go`, `mls/extension.go`
- Test: `mls/extension_test.go`

**This task sequences first in wave 2**, ahead of the key schedule plan's Task 3, which consumes
`Extension` and `WriteExtensions`/`ReadExtensions` from here. The registry enums live here and
nowhere else: the framing and group lifecycle plans declare none of them, because two declarations
of `ProposalType` in one Go package is a redeclaration error rather than a difference of opinion.

**Interfaces:**
- Consumes: `syntax.Writer`, `syntax.Reader`, `syntax.NewWriter`, `syntax.NewReader`, `func (self *Writer) WriteUint16(v uint16)`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Writer) Bytes() ([]byte, error)`, `func (self *Reader) ReadUint16() (uint16, error)`, `func (self *Reader) ReadOpaque() ([]byte, error)`, `func WriteVector[T any](w *Writer, items []T, encodeOne func(w *Writer, item T) error) error`, `func ReadVector[T any](r *Reader, decodeOne func(r *Reader) (T, error)) ([]T, error)`, `func Marshal(v Marshaler) ([]byte, error)`, `func Unmarshal(bs []byte, v Unmarshaler) error`, `syntax.Codec`, `syntax.ErrTrailingBytes` (Syntax and codec plan, wave 1); `type LeafIndex uint32`, `type NodeIndex uint32`, `type LeafCount uint32`, `func (self NodeIndex) LeafIndex() (LeafIndex, error)`, `func Left(x NodeIndex) (NodeIndex, error)`, `func Right(x NodeIndex) (NodeIndex, error)`, `func Root(n LeafCount) (NodeIndex, error)`, `func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)` (Tree math plan, wave 1); `type CipherSuite uint16`, `CipherSuiteX25519ChaCha20Sha256Ed25519` (Crypto plan, wave 1); `ErrMissingRequiredCapability` (Validation plan, `errors.go`); `ErrTreeMalformed` (Task 2).
- Produces: `ProtocolVersion` + `ProtocolVersionMls10`; `CredentialType` + `CredentialTypeBasic`; `ProposalType` + its eight constants; `ExtensionType` + its six constants; `Extension` with `MarshalMLS`/`UnmarshalMLS`; `WriteExtensions`, `ReadExtensions`, `FindExtension`; `Capabilities` with `MarshalMLS`/`UnmarshalMLS`, the five `Supports*` predicates and `Supports(rc)`; `RequiredCapabilities` with `MarshalMLS`/`UnmarshalMLS`. Also the private `mls/tree_adapt.go` helpers — `marshalBytes`, `leftOf`, `rightOf`, `leafIndexOf`, `rootOf`, `directPathOf` — which are internal to this plan and exported to nobody.

The tree-math shims exist because this package's own invariant (a leaf width of at least one, and
every node index it forms already in range) makes the error arm unreachable, and a `(value, ok)`
shape reads better at those call sites. They convert an error to `false`, and **every** call site
turns `false` into this package's `ErrTreeMalformed`, so no error is swallowed. `rootOf` and
`directPathOf` keep the error, because those two are the ones a future change to the width
invariant would break silently.

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
    w := syntax.NewWriter()
    if err := WriteExtensions(w, in); err != nil {
        t.Fatalf("WriteExtensions: %v", err)
    }
    encoded, err := w.Bytes()
    if err != nil {
        t.Fatalf("Bytes: %v", err)
    }
    out, err := ReadExtensions(syntax.NewReader(encoded))
    if err != nil {
        t.Fatalf("ReadExtensions: %v", err)
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
    again := syntax.NewWriter()
    if err := WriteExtensions(again, out); err != nil {
        t.Fatalf("re-WriteExtensions: %v", err)
    }
    reencoded, err := again.Bytes()
    if err != nil {
        t.Fatalf("Bytes: %v", err)
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

// one Extension on its own is a syntax.Codec, so the whole-corpus round-trip
// property has an instantiation path for it.
func TestExtensionIsACodec(t *testing.T) {
    in := &Extension{ExtensionType: ExtensionTypeExternalSenders, ExtensionData: []byte("s")}
    encoded, err := syntax.Marshal(in)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out := &Extension{}
    if err := syntax.Unmarshal(encoded, out); err != nil {
        t.Fatalf("Unmarshal: %v", err)
    }
    if out.ExtensionType != in.ExtensionType || !bytes.Equal(out.ExtensionData, in.ExtensionData) {
        t.Fatalf("round trip = %+v, want %+v", out, in)
    }
    if err := syntax.Unmarshal(append(encoded, 0x00), &Extension{}); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
}

func TestCapabilitiesRoundTripAndPredicates(t *testing.T) {
    in := &Capabilities{
        Versions:     []ProtocolVersion{ProtocolVersionMls10},
        CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
        Extensions:   []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
        Proposals:    []ProposalType{ProposalTypeAdd, ProposalTypeRemove},
        Credentials:  []CredentialType{CredentialTypeBasic},
    }
    encoded, err := syntax.Marshal(in)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out := &Capabilities{}
    if err := syntax.Unmarshal(encoded, out); err != nil {
        t.Fatalf("Unmarshal: %v", err)
    }
    if !out.SupportsVersion(ProtocolVersionMls10) {
        t.Fatalf("SupportsVersion(mls10) = false")
    }
    if !out.SupportsCipherSuite(CipherSuiteX25519ChaCha20Sha256Ed25519) {
        t.Fatalf("SupportsCipherSuite(0x0003) = false")
    }
    if !out.SupportsExtension(ExtensionTypeUrmessageLeafKeys) {
        t.Fatalf("SupportsExtension(0xF002) = false")
    }
    if out.SupportsExtension(ExtensionTypeUrmessageOwnerSuccessor) {
        t.Fatalf("SupportsExtension(0xF003) = true, want false")
    }
    if !out.SupportsProposal(ProposalTypeRemove) {
        t.Fatalf("SupportsProposal(remove) = false")
    }
    if out.SupportsProposal(ProposalTypeGroupContextExtensions) {
        t.Fatalf("SupportsProposal(gce) = true, want false")
    }
    if !out.SupportsCredential(CredentialTypeBasic) {
        t.Fatalf("SupportsCredential(basic) = false")
    }
}

func TestCapabilitiesSupportsRequiredCapabilities(t *testing.T) {
    caps := &Capabilities{
        Versions:     []ProtocolVersion{ProtocolVersionMls10},
        CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
        Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
        Proposals:    []ProposalType{ProposalTypeAdd},
        Credentials:  []CredentialType{CredentialTypeBasic},
    }
    if err := caps.Supports(nil); err != nil {
        t.Fatalf("Supports(nil): %v", err)
    }
    ok := &RequiredCapabilities{
        ExtensionTypes:  []ExtensionType{ExtensionTypeUrmessageLeafKeys},
        ProposalTypes:   []ProposalType{ProposalTypeAdd},
        CredentialTypes: []CredentialType{CredentialTypeBasic},
    }
    if err := caps.Supports(ok); err != nil {
        t.Fatalf("Supports(satisfied): %v", err)
    }
    for name, rc := range map[string]*RequiredCapabilities{
        "extension": {ExtensionTypes: []ExtensionType{ExtensionTypeUrmessageOwnerSuccessor}},
        "proposal":  {ProposalTypes: []ProposalType{ProposalTypeGroupContextExtensions}},
        "credential": {CredentialTypes: []CredentialType{CredentialType(0x0002)}},
    } {
        if err := caps.Supports(rc); !errors.Is(err, ErrMissingRequiredCapability) {
            t.Fatalf("%s: err = %v, want ErrMissingRequiredCapability", name, err)
        }
    }
}

func TestRequiredCapabilitiesRoundTrip(t *testing.T) {
    in := &RequiredCapabilities{
        ExtensionTypes:  []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
        ProposalTypes:   nil,
        CredentialTypes: []CredentialType{CredentialTypeBasic},
    }
    encoded, err := syntax.Marshal(in)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out := &RequiredCapabilities{}
    if err := syntax.Unmarshal(encoded, out); err != nil {
        t.Fatalf("Unmarshal: %v", err)
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
    if err := syntax.Unmarshal(append(encoded, 0x00), &RequiredCapabilities{}); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestExtension|TestCapabilities|TestRequiredCapabilities" -v`
Expected: FAIL to compile with `undefined: Extension`

- [ ] **Step 3: Write minimal implementation**

First the two private adapters, because `mls/extension.go` and every later file in this plan use
`marshalBytes`:

```go
// mls/tree_adapt.go
package mls

import "github.com/urnetwork/connect/mls/syntax"

// run an encoder against a fresh Writer and yield its bytes, surfacing the Writer's
// sticky error. used ONLY for the preimages that are not themselves syntax.Codec
// values: the LeafNodeTBS signature content, the KeyPackageTBS signature content and
// the three §7.8/§7.9 hash inputs. Every wire type goes through syntax.Marshal.
func marshalBytes(encode func(w *syntax.Writer) error) ([]byte, error) {
    w := syntax.NewWriter()
    if err := encode(w); err != nil {
        return nil, err
    }
    return w.Bytes()
}

// The tree-math plan returns an error from every arithmetic that can be out of range.
// Inside a RatchetTree the leaf width is at least one and every node index this
// package forms is already in range, so the error arm is unreachable; these shims
// keep the (value, ok) shape at those call sites. They are internal to this plan —
// no other plan gets them, because a shim that turns an error into false is how a
// trailing-blank tree gets silently accepted somewhere that has no such invariant.
// Every call site below turns false into ErrTreeMalformed.
func leftOf(x NodeIndex) (NodeIndex, bool) {
    y, err := Left(x)
    return y, err == nil
}

func rightOf(x NodeIndex) (NodeIndex, bool) {
    y, err := Right(x)
    return y, err == nil
}

func leafIndexOf(x NodeIndex) (LeafIndex, bool) {
    i, err := x.LeafIndex()
    return i, err == nil
}

// these two keep the error: they are the pair a future change to the width
// invariant would otherwise break by returning node zero.
func rootOf(n LeafCount) (NodeIndex, error) {
    if n == 0 {
        return 0, ErrTreeMalformed
    }
    return Root(n)
}

func directPathOf(x NodeIndex, n LeafCount) ([]NodeIndex, error) {
    if n == 0 {
        return nil, ErrTreeMalformed
    }
    return DirectPath(x, n)
}
```

```go
// mls/extension.go
package mls

import "github.com/urnetwork/connect/mls/syntax"

// The IANA registries of RFC 9420 §17. Every one is uint16 and none is a closed set:
// a GREASE value must parse and be carried, never error. They live in one file
// because that is what the registries are; the wire structs that use them live in
// the framing and group lifecycle plans.
type ProtocolVersion uint16

const ProtocolVersionMls10 ProtocolVersion = 0x0001

type CredentialType uint16

const CredentialTypeBasic CredentialType = 0x0001

type ProposalType uint16

const (
    ProposalTypeReserved               ProposalType = 0x0000
    ProposalTypeAdd                    ProposalType = 0x0001
    ProposalTypeUpdate                 ProposalType = 0x0002
    ProposalTypeRemove                 ProposalType = 0x0003
    ProposalTypePreSharedKey           ProposalType = 0x0004
    ProposalTypeReInit                 ProposalType = 0x0005
    ProposalTypeExternalInit           ProposalType = 0x0006
    ProposalTypeGroupContextExtensions ProposalType = 0x0007
)

type ExtensionType uint16

const (
    ExtensionTypeRatchetTree             ExtensionType = 0x0002
    ExtensionTypeRequiredCapabilities    ExtensionType = 0x0003
    ExtensionTypeExternalSenders         ExtensionType = 0x0004
    ExtensionTypeUrmessageGroupPolicy    ExtensionType = 0xF001
    ExtensionTypeUrmessageLeafKeys       ExtensionType = 0xF002
    ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003
)

// one entry of an extensions vector.
type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}

func (self *Extension) MarshalMLS(w *syntax.Writer) error {
    w.WriteUint16(uint16(self.ExtensionType))
    w.WriteOpaque(self.ExtensionData)
    return nil
}

func (self *Extension) UnmarshalMLS(r *syntax.Reader) error {
    extensionType, err := r.ReadUint16()
    if err != nil {
        return err
    }
    data, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    self.ExtensionType = ExtensionType(extensionType)
    self.ExtensionData = data
    return nil
}

var _ syntax.Codec = (*Extension)(nil)

// extensions<V> is never a standalone message: it is always an inline field of
// GroupContext, LeafNode, KeyPackage, GroupInfo or ReInit. So the pair is
// writer-taking and reader-taking, and the length prefix is written by
// syntax.WriteVector rather than by hand at five call sites.
func WriteExtensions(w *syntax.Writer, exts []Extension) error {
    return syntax.WriteVector(w, exts, func(w *syntax.Writer, ext Extension) error {
        return ext.MarshalMLS(w)
    })
}

func ReadExtensions(r *syntax.Reader) ([]Extension, error) {
    return syntax.ReadVector(r, func(r *syntax.Reader) (Extension, error) {
        var ext Extension
        err := ext.UnmarshalMLS(r)
        return ext, err
    })
}

func FindExtension(exts []Extension, t ExtensionType) ([]byte, bool) {
    for i := range exts {
        if exts[i].ExtensionType == t {
            return exts[i].ExtensionData, true
        }
    }
    return nil, false
}

// the four uint16 registries all encode as one length-prefixed vector of uint16.
func writeUint16Vec[T ~uint16](w *syntax.Writer, values []T) error {
    return syntax.WriteVector(w, values, func(w *syntax.Writer, v T) error {
        w.WriteUint16(uint16(v))
        return nil
    })
}

func readUint16Vec[T ~uint16](r *syntax.Reader) ([]T, error) {
    return syntax.ReadVector(r, func(r *syntax.Reader) (T, error) {
        v, err := r.ReadUint16()
        return T(v), err
    })
}

// RFC 9420 §7.2. what the client behind a leaf node understands.
type Capabilities struct {
    Versions     []ProtocolVersion
    CipherSuites []CipherSuite
    Extensions   []ExtensionType
    Proposals    []ProposalType
    Credentials  []CredentialType
}

func (self *Capabilities) MarshalMLS(w *syntax.Writer) error {
    if err := writeUint16Vec(w, self.Versions); err != nil {
        return err
    }
    if err := writeUint16Vec(w, self.CipherSuites); err != nil {
        return err
    }
    if err := writeUint16Vec(w, self.Extensions); err != nil {
        return err
    }
    if err := writeUint16Vec(w, self.Proposals); err != nil {
        return err
    }
    return writeUint16Vec(w, self.Credentials)
}

func (self *Capabilities) UnmarshalMLS(r *syntax.Reader) error {
    var err error
    if self.Versions, err = readUint16Vec[ProtocolVersion](r); err != nil {
        return err
    }
    if self.CipherSuites, err = readUint16Vec[CipherSuite](r); err != nil {
        return err
    }
    if self.Extensions, err = readUint16Vec[ExtensionType](r); err != nil {
        return err
    }
    if self.Proposals, err = readUint16Vec[ProposalType](r); err != nil {
        return err
    }
    self.Credentials, err = readUint16Vec[CredentialType](r)
    return err
}

var _ syntax.Codec = (*Capabilities)(nil)

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

// the whole required_capabilities check in one call, so the group lifecycle plan's
// ValSem106 and ValSem109 sites cannot each spell the three loops differently.
// A nil rc is "no requirement" and is satisfied by anything.
func (self *Capabilities) Supports(rc *RequiredCapabilities) error {
    if rc == nil {
        return nil
    }
    for _, t := range rc.ExtensionTypes {
        if !self.SupportsExtension(t) {
            return ErrMissingRequiredCapability
        }
    }
    for _, t := range rc.ProposalTypes {
        if !self.SupportsProposal(t) {
            return ErrMissingRequiredCapability
        }
    }
    for _, t := range rc.CredentialTypes {
        if !self.SupportsCredential(t) {
            return ErrMissingRequiredCapability
        }
    }
    return nil
}

// required_capabilities, extension type 0x0003, carried in the group context.
type RequiredCapabilities struct {
    ExtensionTypes  []ExtensionType
    ProposalTypes   []ProposalType
    CredentialTypes []CredentialType
}

func (self *RequiredCapabilities) MarshalMLS(w *syntax.Writer) error {
    if err := writeUint16Vec(w, self.ExtensionTypes); err != nil {
        return err
    }
    if err := writeUint16Vec(w, self.ProposalTypes); err != nil {
        return err
    }
    return writeUint16Vec(w, self.CredentialTypes)
}

func (self *RequiredCapabilities) UnmarshalMLS(r *syntax.Reader) error {
    var err error
    if self.ExtensionTypes, err = readUint16Vec[ExtensionType](r); err != nil {
        return err
    }
    if self.ProposalTypes, err = readUint16Vec[ProposalType](r); err != nil {
        return err
    }
    self.CredentialTypes, err = readUint16Vec[CredentialType](r)
    return err
}

var _ syntax.Codec = (*RequiredCapabilities)(nil)
```

Nothing here declares a `Marshal()` or a `Parse*` of its own: `syntax.Marshal`/`syntax.Unmarshal`
are the byte-level entry points, and `syntax.Unmarshal` is what raises `ErrTrailingBytes` — which is
why `RequiredCapabilities` needs no trailing-bytes check in its own decoder.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestExtension|TestCapabilities|TestRequiredCapabilities" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_adapt.go mls/extension.go mls/extension_test.go
git commit -m "feat(mls): registry enums, Extension, Capabilities and RequiredCapabilities"
```

---

### Task 4: The urmessage_leaf_keys extension (0xF002)

**Files:**
- Modify: `mls/extension.go`
- Test: `mls/extension_test.go`

**Interfaces:**
- Consumes: `syntax.NewWriter`, `syntax.NewReader`, `func (self *Writer) WriteUint16(v uint16)`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Writer) Bytes() ([]byte, error)`, `func (self *Reader) ReadUint16() (uint16, error)`, `func (self *Reader) ReadOpaque() ([]byte, error)`, `func (self *Reader) Done() error`, `syntax.ErrTrailingBytes` (Syntax plan); `Extension`, `ExtensionTypeUrmessageLeafKeys` (Task 3); `ErrLeafKeysExtensionInvalid` (Task 2).
- Produces: `const AlgIdXwing uint16 = 0x0014`, `const XwingPublicKeyLen = 1216`, `LeafKeysExtension{AlgId uint16; DeviceXwingPub []byte}`, `func (self *LeafKeysExtension) Encode() (Extension, error)`, `func ParseLeafKeysExtension(data []byte) (*LeafKeysExtension, error)`. `connect/message`'s `wrap.go` reads this off every leaf to find each device's X-Wing wrap target; the group lifecycle plan keeps only the `LeafKeysOf(leaf)` accessor over it.

`Extension.ExtensionData` is opaque, so a concrete extension body converts bytes↔struct rather than
implementing `MarshalMLS`/`UnmarshalMLS`. That is one of the two sanctioned exceptions to C1, and
the sanctioned spelling is exactly `Encode() (Extension, error)` / `ParseXExtension(data []byte)` —
`Encode` returns the whole `Extension`, tag and all, so no call site can pair the body with the
wrong extension type.

- [ ] **Step 1: Write the failing test**

```go
// mls/extension_test.go (append)

func TestLeafKeysExtensionRoundTrip(t *testing.T) {
    pub := make([]byte, XwingPublicKeyLen)
    for i := range pub {
        pub[i] = byte(i)
    }
    in := &LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: pub}
    ext, err := in.Encode()
    if err != nil {
        t.Fatalf("Encode: %v", err)
    }
    if ext.ExtensionType != ExtensionTypeUrmessageLeafKeys {
        t.Fatalf("Encode tagged %#x, want %#x", ext.ExtensionType, ExtensionTypeUrmessageLeafKeys)
    }
    out, err := ParseLeafKeysExtension(ext.ExtensionData)
    if err != nil {
        t.Fatalf("ParseLeafKeysExtension: %v", err)
    }
    if out.AlgId != AlgIdXwing {
        t.Fatalf("alg_id = %#x, want %#x", out.AlgId, AlgIdXwing)
    }
    if !bytes.Equal(out.DeviceXwingPub, pub) {
        t.Fatalf("device_xwing_pub mismatch")
    }
    again, err := out.Encode()
    if err != nil {
        t.Fatalf("re-Encode: %v", err)
    }
    if !bytes.Equal(again.ExtensionData, ext.ExtensionData) {
        t.Fatalf("re-encode differs")
    }
}

func TestLeafKeysExtensionRejectsWrongLength(t *testing.T) {
    short := &LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: make([]byte, XwingPublicKeyLen-1)}
    if _, err := short.Encode(); !errors.Is(err, ErrLeafKeysExtensionInvalid) {
        t.Fatalf("Encode short key err = %v, want ErrLeafKeysExtensionInvalid", err)
    }
    good := &LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: make([]byte, XwingPublicKeyLen)}
    ext, err := good.Encode()
    if err != nil {
        t.Fatalf("Encode: %v", err)
    }
    encoded := ext.ExtensionData
    if _, err := ParseLeafKeysExtension(encoded[:len(encoded)-1]); err == nil {
        t.Fatalf("ParseLeafKeysExtension(truncated) = nil error, want failure")
    }
    trailing := append(append([]byte{}, encoded...), 0x00)
    if _, err := ParseLeafKeysExtension(trailing); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("ParseLeafKeysExtension(trailing) err = %v, want ErrTrailingBytes", err)
    }
}

func TestLeafKeysExtensionRejectsUnimplementedAlg(t *testing.T) {
    // 0x0013 is reserved for hybrid X25519 + ML-KEM-1024 and is not implemented in
    // v1. MASTER §7.1. it must be refused, not carried.
    in := &LeafKeysExtension{AlgId: 0x0013, DeviceXwingPub: make([]byte, XwingPublicKeyLen)}
    if _, err := in.Encode(); !errors.Is(err, ErrLeafKeysExtensionInvalid) {
        t.Fatalf("Encode alg 0x0013 err = %v, want ErrLeafKeysExtensionInvalid", err)
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
// this is duplicated from message.XwingPublicKeySize on purpose and in one direction
// only, because mls must not import message. The crypto plan carries the compile
// assertion that the two agree.
const XwingPublicKeyLen = 1216

// urmessage_leaf_keys, extension type 0xF002. MASTER §5.3. it rides in the LeafNode
// so it is covered by the leaf signature and the tree hash, is validated by
// RFC 9420 §7.3, and is removed by Remove along with the rest of the leaf.
type LeafKeysExtension struct {
    AlgId          uint16
    DeviceXwingPub []byte
}

func (self *LeafKeysExtension) Encode() (Extension, error) {
    if self.AlgId != AlgIdXwing {
        return Extension{}, ErrLeafKeysExtensionInvalid
    }
    if len(self.DeviceXwingPub) != XwingPublicKeyLen {
        return Extension{}, ErrLeafKeysExtensionInvalid
    }
    body, err := marshalBytes(func(w *syntax.Writer) error {
        w.WriteUint16(self.AlgId)
        w.WriteOpaque(self.DeviceXwingPub)
        return nil
    })
    if err != nil {
        return Extension{}, err
    }
    return Extension{
        ExtensionType: ExtensionTypeUrmessageLeafKeys,
        ExtensionData: body,
    }, nil
}

func ParseLeafKeysExtension(data []byte) (*LeafKeysExtension, error) {
    r := syntax.NewReader(data)
    algId, err := r.ReadUint16()
    if err != nil {
        return nil, err
    }
    pub, err := r.ReadOpaque()
    if err != nil {
        return nil, err
    }
    if err := r.Done(); err != nil {
        return nil, err
    }
    if algId != AlgIdXwing || len(pub) != XwingPublicKeyLen {
        return nil, ErrLeafKeysExtensionInvalid
    }
    return &LeafKeysExtension{AlgId: algId, DeviceXwingPub: pub}, nil
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

### Task 4A: Credential

**Files:**
- Create: `mls/credential.go`
- Test: `mls/credential_test.go`

**Interfaces:**
- Consumes: `syntax.Writer`, `syntax.Reader`, `func (self *Writer) WriteUint16(v uint16)`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Reader) ReadUint16() (uint16, error)`, `func (self *Reader) ReadOpaque() ([]byte, error)`, `func Marshal(v Marshaler) ([]byte, error)`, `func Unmarshal(bs []byte, v Unmarshaler) error`, `syntax.Codec` (Syntax plan); `CredentialType`, `CredentialTypeBasic` (Task 3); `ErrProfileCredentialType` (Validation plan, `errors.go`).
- Produces: `Credential` with `MarshalMLS`/`UnmarshalMLS`, and `func BasicCredential(identity []byte) Credential`.

**`Credential` is produced here.** No wave-1 plan produces any MLS type, so the original attribution
to the syntax plan had no owner; the group lifecycle and validation plans both consume it and
neither produces it. It lands here because `LeafNode` embeds it by value and this is the file family
that validates it.

Refusing a non-basic credential type **at parse** rather than by a later check is what keeps x509
bytes from ever being carried inside a `LeafNode` this package accepted (Spec A §3.2). That refusal
is a *semantic* one, not a buffer error, which is the reason `MarshalMLS` returns an `error` at all
(C2): under a return-free encoder it would have to panic or be dropped, and a dropped encoder
refusal produces wrong signed bytes rather than a failure. The group lifecycle plan calls
`(*Profile).CheckCredentialType` at its own parse boundary for the same decision at the policy
layer; this one is the codec-layer floor and is not negotiable by profile.

- [ ] **Step 1: Write the failing test**

```go
// mls/credential_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func TestBasicCredentialRoundTrip(t *testing.T) {
    in := BasicCredential([]byte("alice"))
    if in.CredentialType != CredentialTypeBasic {
        t.Fatalf("credential type = %#x, want basic", in.CredentialType)
    }
    encoded, err := syntax.Marshal(&in)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out := &Credential{}
    if err := syntax.Unmarshal(encoded, out); err != nil {
        t.Fatalf("Unmarshal: %v", err)
    }
    if out.CredentialType != CredentialTypeBasic || !bytes.Equal(out.Identity, []byte("alice")) {
        t.Fatalf("round trip = %+v", out)
    }
    if err := syntax.Unmarshal(append(encoded, 0x00), &Credential{}); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
}

func TestCredentialRefusesX509OnBothSides(t *testing.T) {
    // decode side: x509 bytes must never reach a LeafNode this package accepted.
    x509 := syntax.NewWriter()
    x509.WriteUint16(0x0002)
    x509.WriteOpaque([]byte("cert"))
    encoded, err := x509.Bytes()
    if err != nil {
        t.Fatalf("Bytes: %v", err)
    }
    if err := syntax.Unmarshal(encoded, &Credential{}); !errors.Is(err, ErrProfileCredentialType) {
        t.Fatalf("decode err = %v, want ErrProfileCredentialType", err)
    }
    // encode side: the same refusal, surfaced as a returned error rather than
    // dropped into the Writer, so no wrong bytes are ever signed.
    bad := &Credential{CredentialType: CredentialType(0x0002), Identity: []byte("cert")}
    if _, err := syntax.Marshal(bad); !errors.Is(err, ErrProfileCredentialType) {
        t.Fatalf("encode err = %v, want ErrProfileCredentialType", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestBasicCredential|TestCredentialRefusesX509" -v`
Expected: FAIL to compile with `undefined: BasicCredential`

- [ ] **Step 3: Write minimal implementation**

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

func BasicCredential(identity []byte) Credential {
    return Credential{CredentialType: CredentialTypeBasic, Identity: identity}
}

func (self *Credential) MarshalMLS(w *syntax.Writer) error {
    if self.CredentialType != CredentialTypeBasic {
        return ErrProfileCredentialType
    }
    w.WriteUint16(uint16(self.CredentialType))
    w.WriteOpaque(self.Identity)
    return nil
}

func (self *Credential) UnmarshalMLS(r *syntax.Reader) error {
    credentialType, err := r.ReadUint16()
    if err != nil {
        return err
    }
    if CredentialType(credentialType) != CredentialTypeBasic {
        return ErrProfileCredentialType
    }
    identity, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    self.CredentialType = CredentialTypeBasic
    self.Identity = identity
    return nil
}

var _ syntax.Codec = (*Credential)(nil)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestBasicCredential|TestCredentialRefusesX509" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/credential.go mls/credential_test.go
git commit -m "feat(mls): BasicCredential-only Credential refusing x509 at parse"
```

---

### Task 5: LeafNode structure and codec

**Files:**
- Create: `mls/leaf_node.go`
- Test: `mls/leaf_node_test.go`

**Interfaces:**
- Consumes: `syntax.Writer`, `syntax.Reader`, `func (self *Writer) WriteUint8(v uint8)`, `func (self *Writer) WriteUint64(v uint64)`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Reader) ReadUint8() (uint8, error)`, `func (self *Reader) ReadUint64() (uint64, error)`, `func (self *Reader) ReadOpaque() ([]byte, error)`, `func Marshal(v Marshaler) ([]byte, error)`, `func Unmarshal(bs []byte, v Unmarshaler) error`, `syntax.Codec`, `syntax.ErrTrailingBytes` (Syntax plan); `type HpkePublicKey []byte`, `type SignaturePublicKey []byte` (Crypto plan); `Extension`, `Capabilities`, `WriteExtensions`, `ReadExtensions` (Task 3); `Credential` (Task 4A); `ErrTreeMalformed` (Task 2).
- Produces: `LeafNodeSource` with `LeafNodeSourceKeyPackage/Update/Commit`; `Lifetime`; `LeafNode`; `func (self *LeafNode) MarshalMLS(w *syntax.Writer) error`; `func (self *LeafNode) UnmarshalMLS(r *syntax.Reader) error`; `var _ syntax.Codec = (*LeafNode)(nil)`; `func (self *LeafNode) Clone() *LeafNode`. Byte-level access is `syntax.Marshal(leaf)` / `syntax.Unmarshal(bs, leaf)`; this type declares no `Marshal()` and no `ParseLeafNode` (C1).

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
            Versions:     []ProtocolVersion{ProtocolVersionMls10},
            CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
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
        encoded, err := syntax.Marshal(in)
        if err != nil {
            t.Fatalf("%s Marshal: %v", c.name, err)
        }
        out := &LeafNode{}
        if err := syntax.Unmarshal(encoded, out); err != nil {
            t.Fatalf("%s Unmarshal: %v", c.name, err)
        }
        reencoded, err := syntax.Marshal(out)
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
    encoded, err := syntax.Marshal(leaf)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if err := syntax.Unmarshal(append(encoded, 0x00), &LeafNode{}); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
    leaf.LeafNodeSource = LeafNodeSource(9)
    if _, err := syntax.Marshal(leaf); !errors.Is(err, ErrTreeMalformed) {
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
    w.WriteOpaque(self.EncryptionKey)
    w.WriteOpaque(self.SignatureKey)
    if err := self.Credential.MarshalMLS(w); err != nil {
        return err
    }
    if err := self.Capabilities.MarshalMLS(w); err != nil {
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
        w.WriteOpaque(self.ParentHash)
    default:
        return ErrTreeMalformed
    }
    return WriteExtensions(w, self.Extensions)
}

func (self *LeafNode) MarshalMLS(w *syntax.Writer) error {
    if err := self.marshalCore(w); err != nil {
        return err
    }
    w.WriteOpaque(self.Signature)
    return nil
}

// the same fields in the same order as marshalCore, so LeafNodeTBS and LeafNode
// cannot drift apart.
func (self *LeafNode) unmarshalCore(r *syntax.Reader) error {
    encryptionKey, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    signatureKey, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    if err := self.Credential.UnmarshalMLS(r); err != nil {
        return err
    }
    if err := self.Capabilities.UnmarshalMLS(r); err != nil {
        return err
    }
    source, err := r.ReadUint8()
    if err != nil {
        return err
    }
    self.EncryptionKey = HpkePublicKey(encryptionKey)
    self.SignatureKey = SignaturePublicKey(signatureKey)
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
        if self.ParentHash, err = r.ReadOpaque(); err != nil {
            return err
        }
    default:
        return ErrTreeMalformed
    }
    self.Extensions, err = ReadExtensions(r)
    return err
}

func (self *LeafNode) UnmarshalMLS(r *syntax.Reader) error {
    if err := self.unmarshalCore(r); err != nil {
        return err
    }
    signature, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    self.Signature = signature
    return nil
}

var _ syntax.Codec = (*LeafNode)(nil)

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
- Consumes: `SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error)`, `VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error`, `SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error)` on `CryptoProvider`, `func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)` (Crypto plan); `ErrBadSignature` (Validation plan, `errors.go`); `marshalBytes` (Task 3); `Credential` (Task 4A).
- Produces: `func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey, groupId []byte, leafIndex LeafIndex) error`, `func (self *LeafNode) VerifySignature(crypto CryptoProvider, groupId []byte, leafIndex LeafIndex) error`, and `func NewLeafNode(crypto CryptoProvider, signer SignaturePrivateKey, cred Credential, encKey HpkePublicKey, caps Capabilities, exts []Extension) (*LeafNode, error)`. `groupId` and `leafIndex` are ignored for `key_package`-source leaves and are covered by the signature for `update` and `commit` sources, per RFC 9420 §7.2.

`NewLeafNode` is a symbol the group lifecycle plan calls at four sites and nobody produced. It builds
the `key_package`-source leaf — the only source a leaf can have before it is in a tree — and signs it
with no group id and no index, which is why it needs neither argument.

- [ ] **Step 1: Write the failing test**

```go
// mls/leaf_node_test.go (append)

func TestLeafNodeSignVerifyKeyPackageSourceIgnoresIndex(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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

func TestNewLeafNodeSignsAKeyPackageSourceLeaf(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    signerPriv, signerPub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("SignatureKeyPair: %v", err)
    }
    _, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
    if err != nil {
        t.Fatalf("DeriveKeyPair: %v", err)
    }
    caps := Capabilities{
        Versions:     []ProtocolVersion{ProtocolVersionMls10},
        CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
        Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
        Credentials:  []CredentialType{CredentialTypeBasic},
    }
    exts := []Extension{{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: []byte("k")}}
    leaf, err := NewLeafNode(crypto, signerPriv, BasicCredential([]byte("alice")), encPub, caps, exts)
    if err != nil {
        t.Fatalf("NewLeafNode: %v", err)
    }
    if leaf.LeafNodeSource != LeafNodeSourceKeyPackage {
        t.Fatalf("source = %d, want key_package", leaf.LeafNodeSource)
    }
    if !bytes.Equal(leaf.SignatureKey, signerPub) {
        t.Fatalf("NewLeafNode did not install the signer's public key")
    }
    if leaf.Lifetime.NotAfter <= leaf.Lifetime.NotBefore {
        t.Fatalf("lifetime = %+v, want a non-empty window", leaf.Lifetime)
    }
    // a key_package leaf is bound to no group and no position, so any context verifies.
    if err := leaf.VerifySignature(crypto, []byte("any group"), LeafIndex(9)); err != nil {
        t.Fatalf("VerifySignature: %v", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestLeafNodeSign|TestLeafNodeCommitSource|TestLeafNodeSignature|TestNewLeafNode" -v`
Expected: FAIL to compile with `leaf.Sign undefined (type *LeafNode has no field or method Sign)`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/leaf_node.go (append)

// RFC 9420 §7.2. the signature label for every leaf node.
const leafNodeSignatureLabel = "LeafNodeTBS"

// LeafNodeTBS is the leaf's core fields, followed by the group id and leaf index for
// update and commit sources only. binding the index is what stops a leaf being
// replayed into a different position in the tree.
// LeafNodeTBS is not a syntax.Codec — it is a preimage, never a message — so it is
// built with marshalBytes rather than syntax.Marshal.
func (self *LeafNode) signatureContent(groupId []byte, leafIndex LeafIndex) ([]byte, error) {
    return marshalBytes(func(w *syntax.Writer) error {
        if err := self.marshalCore(w); err != nil {
            return err
        }
        switch self.LeafNodeSource {
        case LeafNodeSourceKeyPackage:
            // no context: a KeyPackage is not yet bound to a group or a position
        case LeafNodeSourceUpdate, LeafNodeSourceCommit:
            w.WriteOpaque(groupId)
            w.WriteUint32(uint32(leafIndex))
        default:
            return ErrTreeMalformed
        }
        return nil
    })
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

// Spec A §3.1: a fresh KeyPackage leaf is valid from now, back-dated by the clock
// skew allowance, for the default lifetime.
const (
    leafLifetimeSkewSeconds    uint64 = 3600
    leafLifetimeDefaultSeconds uint64 = 90 * 24 * 3600
)

// SignaturePrivateKey is an Ed25519 32-byte seed, so its public half is a derivation
// rather than a fresh generation. NewLeafNode must never call SignatureKeyPair: it
// was handed a key pair, and generating a second one inside the constructor is how a
// leaf ends up signed by a key nobody holds.
func signaturePublicKeyOf(priv SignaturePrivateKey) SignaturePublicKey {
    return SignaturePublicKey(ed25519.NewKeyFromSeed(priv).Public().(ed25519.PublicKey))
}

// the key_package-source leaf, signed with no group id and no leaf index because it
// is not yet bound to either. The group lifecycle plan calls this wherever it needs
// a leaf before there is a tree to put it in.
func NewLeafNode(crypto CryptoProvider, signer SignaturePrivateKey, cred Credential,
    encKey HpkePublicKey, caps Capabilities, exts []Extension) (*LeafNode, error) {
    now := uint64(time.Now().Unix())
    leaf := &LeafNode{
        EncryptionKey:  encKey,
        SignatureKey:   signaturePublicKeyOf(signer),
        Credential:     cred,
        Capabilities:   caps,
        LeafNodeSource: LeafNodeSourceKeyPackage,
        Lifetime: Lifetime{
            NotBefore: now - leafLifetimeSkewSeconds,
            NotAfter:  now + leafLifetimeDefaultSeconds,
        },
        Extensions: exts,
    }
    if err := leaf.Sign(crypto, signer, nil, 0); err != nil {
        return nil, err
    }
    // signing and then verifying costs one Ed25519 verify per key package and turns a
    // mismatched key pair into an error here rather than a rejected Add later.
    if err := leaf.VerifySignature(crypto, nil, 0); err != nil {
        return nil, err
    }
    return leaf, nil
}
```

Add `"crypto/ed25519"` and `"time"` to the imports of `mls/leaf_node.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestLeafNodeSign|TestLeafNodeCommitSource|TestLeafNodeSignature|TestNewLeafNode" -v`
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
- Consumes: `ErrBadSignature`, `ErrMissingRequiredCapability` (Validation plan, `errors.go`); `(*Capabilities).Supports`, `ParseLeafKeysExtension`, `ExtensionTypeUrmessageLeafKeys` (Tasks 3, 4); `ErrLeafNodeSourceMismatch`, `ErrLeafNodeLifetime`, `ErrLeafKeysExtensionInvalid` (Task 2).
- Produces: `LeafValidationContext{Crypto, Suite, GroupId, LeafIndex, ExpectedSource, RequiredCaps, GroupExtensions, NowMs, ClockSkewMs}` and `func (self *LeafNode) Validate(ctx *LeafValidationContext) error`. `tree_sync.go` (Task 23) calls it once per non-blank leaf; `key_package.go` (Task 7A) calls it with `ExpectedSource = LeafNodeSourceKeyPackage`; the group lifecycle plan's proposal validation calls it with `LeafNodeSourceUpdate`.

The context struct is deliberate rather than a positional call: there are eight inputs, two of them
optional, and two adjacent `uint64` time arguments in a positional signature is a defect waiting to
happen.

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
        Suite:          CipherSuiteX25519ChaCha20Sha256Ed25519,
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    leaf, _ := signedTestLeaf(t, crypto, LeafNodeSourceCommit, nil)
    if err := leaf.Validate(testLeafValidationContext(crypto, LeafNodeSourceCommit)); err != nil {
        t.Fatalf("Validate: %v", err)
    }
}

func TestLeafNodeValidateRejectsWrongSource(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    if err := self.Capabilities.Supports(ctx.RequiredCaps); err != nil {
        return err
    }
    // MASTER §5.3: the urmessage_leaf_keys body is range-checked here, because this
    // is the last point before the leaf is trusted by the tree and by
    // connect/message's wrap path.
    if body, ok := FindExtension(self.Extensions, ExtensionTypeUrmessageLeafKeys); ok {
        if _, err := ParseLeafKeysExtension(body); err != nil {
            return ErrLeafKeysExtensionInvalid
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

### Task 7A: KeyPackage

**Files:**
- Create: `mls/key_package.go`
- Test: `mls/key_package_test.go`

**Interfaces:**
- Consumes: `syntax.Writer`, `syntax.Reader`, `func (self *Writer) WriteUint16(v uint16)`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Reader) ReadUint16() (uint16, error)`, `func (self *Reader) ReadOpaque() ([]byte, error)`, `func Marshal(v Marshaler) ([]byte, error)`, `func Unmarshal(bs []byte, v Unmarshaler) error`, `syntax.Codec` (Syntax plan); `func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte`, `SignWithLabel`, `VerifyWithLabel`, `SignatureKeyPair`, `DeriveKeyPair`, `Random`, `HashSize` on `CryptoProvider` (Crypto plan); `ErrBadSignature`, `ErrProfileCiphersuite` (Validation plan, `errors.go`); `Extension`, `Capabilities`, `WriteExtensions`, `ReadExtensions`, `ProtocolVersion`, `ProtocolVersionMls10` (Task 3); `Credential` (Task 4A); `LeafNode`, `NewLeafNode`, `(*LeafNode).Validate`, `LeafValidationContext`, `marshalBytes` (Tasks 3, 5, 6, 7).
- Produces: `KeyPackage` with `MarshalMLS`/`UnmarshalMLS` and `var _ syntax.Codec = (*KeyPackage)(nil)`; `func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential, caps Capabilities, exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey, encPriv HpkePrivateKey, err error)`; `func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error)`; `func (self *KeyPackage) Validate(crypto CryptoProvider, suite CipherSuite, now time.Time) error`.

**`KeyPackage` lands here, in wave 2.** It was consumed by four plans and produced by none: the
framing plan's `MLSMessage` names it by direct type in wave 3, the group lifecycle plan's file
structure has no `key_package.go`, and the validation plan's codec table decodes it. It belongs
beside `leaf_node.go` because it is a `LeafNode` plus an init key plus a signature and shares that
file family's validation code, and its only dependencies are the crypto plan (wave 1) and this
plan's own types. The group lifecycle plan keeps only the `StateStore` key-package persistence.

`Validate` delegates the whole of §7.3 to `LeafNode.Validate` with
`ExpectedSource = LeafNodeSourceKeyPackage`, and `Ref` delegates to the crypto plan's
`MakeKeyPackageRef`. Neither reimplements anything. The `init_key != leaf.encryption_key` check is
**not** here — it is ValSem104, and the group lifecycle plan owns the 100-series.

`NewKeyPackage` generates the signature key pair as well as the two HPKE pairs, and keeps the seed
on an unexported `signPriv` field. `package mls` is one package, so the group lifecycle plan reads
it directly when it assembles `JoinKeyMaterial`; the field is zero on any `KeyPackage` that arrived
off the wire, and it is not part of the encoding.

- [ ] **Step 1: Write the failing test**

```go
// mls/key_package_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"
    "time"

    "github.com/urnetwork/connect/mls/syntax"
)

func testKeyPackageCapabilities() Capabilities {
    return Capabilities{
        Versions:     []ProtocolVersion{ProtocolVersionMls10},
        CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
        Extensions:   []ExtensionType{ExtensionTypeUrmessageLeafKeys},
        Proposals:    []ProposalType{ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove},
        Credentials:  []CredentialType{CredentialTypeBasic},
    }
}

func TestNewKeyPackageRoundTripsAndValidates(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    leafKeys := &LeafKeysExtension{
        AlgId:          AlgIdXwing,
        DeviceXwingPub: make([]byte, XwingPublicKeyLen),
    }
    ext, err := leafKeys.Encode()
    if err != nil {
        t.Fatalf("Encode: %v", err)
    }
    kp, initPriv, encPriv, err := NewKeyPackage(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519,
        BasicCredential([]byte("alice")), testKeyPackageCapabilities(), []Extension{ext})
    if err != nil {
        t.Fatalf("NewKeyPackage: %v", err)
    }
    if len(initPriv) == 0 || len(encPriv) == 0 {
        t.Fatalf("NewKeyPackage returned empty private keys")
    }
    if bytes.Equal(initPriv, encPriv) {
        t.Fatalf("the init and encryption key pairs are the same")
    }
    if bytes.Equal(kp.InitKey, kp.LeafNode.EncryptionKey) {
        t.Fatalf("init_key equals the leaf encryption key")
    }
    if err := kp.Validate(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519, time.Now()); err != nil {
        t.Fatalf("Validate: %v", err)
    }

    encoded, err := syntax.Marshal(kp)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out := &KeyPackage{}
    if err := syntax.Unmarshal(encoded, out); err != nil {
        t.Fatalf("Unmarshal: %v", err)
    }
    reencoded, err := syntax.Marshal(out)
    if err != nil {
        t.Fatalf("re-Marshal: %v", err)
    }
    if !bytes.Equal(reencoded, encoded) {
        t.Fatalf("re-encode differs")
    }
    if err := out.Validate(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519, time.Now()); err != nil {
        t.Fatalf("decoded Validate: %v", err)
    }
    if err := syntax.Unmarshal(append(encoded, 0x00), &KeyPackage{}); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
}

func TestKeyPackageRefIsStableAndBindsEveryField(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    kp, _, _, err := NewKeyPackage(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519,
        BasicCredential([]byte("alice")), testKeyPackageCapabilities(), nil)
    if err != nil {
        t.Fatalf("NewKeyPackage: %v", err)
    }
    ref, err := kp.Ref(crypto)
    if err != nil {
        t.Fatalf("Ref: %v", err)
    }
    if len(ref) != crypto.HashSize() {
        t.Fatalf("ref length = %d, want %d", len(ref), crypto.HashSize())
    }
    again, err := kp.Ref(crypto)
    if err != nil {
        t.Fatalf("Ref: %v", err)
    }
    if !bytes.Equal(ref, again) {
        t.Fatalf("Ref is not deterministic")
    }
    other, _, _, err := NewKeyPackage(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519,
        BasicCredential([]byte("alice")), testKeyPackageCapabilities(), nil)
    if err != nil {
        t.Fatalf("NewKeyPackage: %v", err)
    }
    otherRef, err := other.Ref(crypto)
    if err != nil {
        t.Fatalf("Ref: %v", err)
    }
    if bytes.Equal(ref, otherRef) {
        t.Fatalf("two key packages with fresh keys share a ref")
    }
}

func TestKeyPackageValidateRejects(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    build := func(t *testing.T) *KeyPackage {
        t.Helper()
        kp, _, _, err := NewKeyPackage(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519,
            BasicCredential([]byte("alice")), testKeyPackageCapabilities(), nil)
        if err != nil {
            t.Fatalf("NewKeyPackage: %v", err)
        }
        return kp
    }

    wrongSuite := build(t)
    if err := wrongSuite.Validate(crypto, CipherSuite(0x0001), time.Now()); !errors.Is(err, ErrProfileCiphersuite) {
        t.Fatalf("suite mismatch err = %v, want ErrProfileCiphersuite", err)
    }

    tampered := build(t)
    tampered.InitKey = HpkePublicKey(bytes.Repeat([]byte{0xEE}, len(tampered.InitKey)))
    if err := tampered.Validate(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519, time.Now()); !errors.Is(err, ErrBadSignature) {
        t.Fatalf("tampered init key err = %v, want ErrBadSignature", err)
    }

    wrongSource := build(t)
    wrongSource.LeafNode.LeafNodeSource = LeafNodeSourceUpdate
    if err := wrongSource.Validate(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519, time.Now()); err == nil {
        t.Fatalf("an update-source leaf inside a KeyPackage was accepted")
    }

    expired := build(t)
    far := time.Unix(int64(expired.LeafNode.Lifetime.NotAfter)+2*3600, 0)
    if err := expired.Validate(crypto, CipherSuiteX25519ChaCha20Sha256Ed25519, far); !errors.Is(err, ErrLeafNodeLifetime) {
        t.Fatalf("expired err = %v, want ErrLeafNodeLifetime", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestNewKeyPackage|TestKeyPackage" -v`
Expected: FAIL to compile with `undefined: NewKeyPackage`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/key_package.go
package mls

import (
    "time"

    "github.com/urnetwork/connect/mls/syntax"
)

// RFC 9420 §10. one joiner's advertised init key and leaf node, signed as a unit.
type KeyPackage struct {
    Version     ProtocolVersion
    CipherSuite CipherSuite
    InitKey     HpkePublicKey
    LeafNode    LeafNode
    Extensions  []Extension
    Signature   []byte

    // set by NewKeyPackage only, never encoded, zero on anything off the wire.
    // package mls is one package, so the group lifecycle plan reads this when it
    // assembles JoinKeyMaterial.
    signPriv SignaturePrivateKey
}

// RFC 9420 §10. the signature label for a key package.
const keyPackageSignatureLabel = "KeyPackageTBS"

// KeyPackageTBS: everything but the signature.
func (self *KeyPackage) marshalCore(w *syntax.Writer) error {
    w.WriteUint16(uint16(self.Version))
    w.WriteUint16(uint16(self.CipherSuite))
    w.WriteOpaque(self.InitKey)
    if err := self.LeafNode.MarshalMLS(w); err != nil {
        return err
    }
    return WriteExtensions(w, self.Extensions)
}

func (self *KeyPackage) MarshalMLS(w *syntax.Writer) error {
    if err := self.marshalCore(w); err != nil {
        return err
    }
    w.WriteOpaque(self.Signature)
    return nil
}

func (self *KeyPackage) UnmarshalMLS(r *syntax.Reader) error {
    version, err := r.ReadUint16()
    if err != nil {
        return err
    }
    suite, err := r.ReadUint16()
    if err != nil {
        return err
    }
    initKey, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    if err := self.LeafNode.UnmarshalMLS(r); err != nil {
        return err
    }
    exts, err := ReadExtensions(r)
    if err != nil {
        return err
    }
    signature, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    self.Version = ProtocolVersion(version)
    self.CipherSuite = CipherSuite(suite)
    self.InitKey = HpkePublicKey(initKey)
    self.Extensions = exts
    self.Signature = signature
    self.signPriv = nil
    return nil
}

var _ syntax.Codec = (*KeyPackage)(nil)

func (self *KeyPackage) signatureContent() ([]byte, error) {
    return marshalBytes(self.marshalCore)
}

// a fresh key package with three fresh key pairs: the init pair, the leaf encryption
// pair and the signature pair. The two HPKE private halves are returned so the caller
// can persist them against the ref; the signature seed rides on signPriv.
func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,
    caps Capabilities, exts []Extension) (*KeyPackage, HpkePrivateKey, HpkePrivateKey, error) {
    signPriv, _, err := crypto.SignatureKeyPair()
    if err != nil {
        return nil, nil, nil, err
    }
    initPriv, initPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
    if err != nil {
        return nil, nil, nil, err
    }
    encPriv, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
    if err != nil {
        return nil, nil, nil, err
    }
    leaf, err := NewLeafNode(crypto, signPriv, cred, encPub, caps, exts)
    if err != nil {
        return nil, nil, nil, err
    }
    kp := &KeyPackage{
        Version:     ProtocolVersionMls10,
        CipherSuite: suite,
        InitKey:     initPub,
        LeafNode:    *leaf,
        Extensions:  nil,
        signPriv:    signPriv,
    }
    content, err := kp.signatureContent()
    if err != nil {
        return nil, nil, nil, err
    }
    signature, err := crypto.SignWithLabel(signPriv, keyPackageSignatureLabel, content)
    if err != nil {
        return nil, nil, nil, err
    }
    kp.Signature = signature
    return kp, initPriv, encPriv, nil
}

// RFC 9420 §5.2. the ref is the hash of the whole encoded key package, so it changes
// with every field including the signature.
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error) {
    encoded, err := syntax.Marshal(self)
    if err != nil {
        return nil, err
    }
    return MakeKeyPackageRef(crypto, encoded), nil
}

// RFC 9420 §10.1, minus the 100-series proposal checks. ValSem104
// (init_key != leaf encryption key) is the group lifecycle plan's, because it is a
// property of the proposal list rather than of one key package.
func (self *KeyPackage) Validate(crypto CryptoProvider, suite CipherSuite, now time.Time) error {
    if self.Version != ProtocolVersionMls10 {
        return ErrProfileCiphersuite
    }
    if self.CipherSuite != suite {
        return ErrProfileCiphersuite
    }
    content, err := self.signatureContent()
    if err != nil {
        return err
    }
    if err := crypto.VerifyWithLabel(self.LeafNode.SignatureKey, keyPackageSignatureLabel,
        content, self.Signature); err != nil {
        return ErrBadSignature
    }
    return self.LeafNode.Validate(&LeafValidationContext{
        Crypto:         crypto,
        Suite:          suite,
        GroupId:        nil,
        LeafIndex:      0,
        ExpectedSource: LeafNodeSourceKeyPackage,
        NowMs:          uint64(now.UnixMilli()),
        ClockSkewMs:    leafLifetimeSkewSeconds * 1000,
    })
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestNewKeyPackage|TestKeyPackage" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/key_package.go mls/key_package_test.go
git commit -m "feat(mls): KeyPackage with construction, ref and validation"
```

---

### Task 8: ParentNode, Node and the RatchetTree container

**Files:**
- Create: `mls/tree.go`
- Test: `mls/tree_test.go`

**Interfaces:**
- Consumes: `type LeafIndex uint32`, `type NodeIndex uint32`, `type LeafCount uint32`, `const MaxLeafCount LeafCount = 1 << 31`, `func NodeWidth(n LeafCount) uint32`, `func ExtendedLeafCount(n LeafCount) (LeafCount, error)`, `func (self NodeIndex) IsLeaf() bool`, `func (self LeafIndex) NodeIndex() NodeIndex`, `type NodeShape interface{ LeafCount() LeafCount; IsBlank(x NodeIndex) bool; UnmergedLeaves(x NodeIndex) []LeafIndex }` (Tree math plan, wave 1); `syntax.Writer`, `syntax.Reader`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Writer) WriteUint32(v uint32)`, `func (self *Reader) ReadOpaque() ([]byte, error)`, `func (self *Reader) ReadUint32() (uint32, error)`, `func WriteVector[T any](...) error`, `func ReadVector[T any](...) ([]T, error)` (Syntax plan); `type HpkePublicKey []byte`, `type SignaturePublicKey []byte` (Crypto plan); `LeafNode` (Task 5); `directPathOf` (Task 3); `ErrLeafIndexOutOfRange`, `ErrNodeIndexOutOfRange`, `ErrTreeMalformed`, `ErrNodeTypeMismatch` (Task 2).
- Produces: `NodeType` with `NodeTypeLeaf`/`NodeTypeParent`; `ParentNode` with `MarshalMLS`/`UnmarshalMLS`/`Clone`; `Node`; `OptionalNode`; `RatchetTree` with `NewRatchetTree`, `LeafWidth() LeafCount`, `NodeWidth() uint32`, `Get`, `Leaf`, `ParentAt`, `SetLeaf`, `SetParent`, `Blank`, `BlankDirectPath`, `Clone`, `Members`, `MemberCount`, `NonBlankLeaves`, `FindLeafBySignatureKey`, `EncryptionKeyInUse`, `HasTrailingBlankNodes`, and the three `NodeShape` methods `LeafCount`/`IsBlank`/`UnmergedLeaves` with `var _ NodeShape = (*RatchetTree)(nil)`.

**`LeafWidth` returns `LeafCount`, not `uint32`** (C3): it is a count, and every tree-math entry
point it feeds takes a count. `NodeWidth()` stays `uint32` because that is what the tree-math
`NodeWidth(n LeafCount) uint32` returns and what indexes the node array.

`NonBlankLeaves`, `EncryptionKeyInUse` and `HasTrailingBlankNodes` are three accessors the group
lifecycle and validation plans call and nobody produced. They are reads of the private node array,
so they belong here rather than open-coded against `Get` in two other plans.

Implementing `NodeShape` is what lets the tree-math plan's `Resolution` and `FilteredDirectPath`
work on a real tree, which is why this plan has no resolution algorithm of its own.

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

func TestRatchetTreeAccessorsAndNodeShape(t *testing.T) {
    tree := NewRatchetTree()
    for i := uint32(0); i < 3; i++ {
        leaf := testLeafNodeTemplate()
        leaf.LeafNodeSource = LeafNodeSourceUpdate
        leaf.EncryptionKey = HpkePublicKey(bytes.Repeat([]byte{byte(0x40 + i)}, 32))
        if err := tree.SetLeaf(LeafIndex(i), leaf); err != nil {
            t.Fatalf("SetLeaf(%d): %v", i, err)
        }
    }
    if got := tree.NonBlankLeaves(); len(got) != 3 || got[2] != LeafIndex(2) {
        t.Fatalf("NonBlankLeaves = %v", got)
    }
    if !tree.EncryptionKeyInUse(HpkePublicKey(bytes.Repeat([]byte{0x41}, 32))) {
        t.Fatalf("EncryptionKeyInUse missed leaf 1's key")
    }
    if tree.EncryptionKeyInUse(HpkePublicKey(bytes.Repeat([]byte{0x99}, 32))) {
        t.Fatalf("EncryptionKeyInUse found an absent key")
    }
    if err := tree.SetParent(NodeIndex(1), &ParentNode{
        EncryptionKey:  HpkePublicKey(bytes.Repeat([]byte{0x50}, 32)),
        UnmergedLeaves: []LeafIndex{1},
    }); err != nil {
        t.Fatalf("SetParent: %v", err)
    }
    if !tree.EncryptionKeyInUse(HpkePublicKey(bytes.Repeat([]byte{0x50}, 32))) {
        t.Fatalf("EncryptionKeyInUse ignored a parent node key")
    }

    // NodeShape: the three methods the tree math plan's Resolution walks.
    var shape NodeShape = tree
    if shape.LeafCount() != tree.LeafWidth() {
        t.Fatalf("NodeShape.LeafCount = %d, want %d", shape.LeafCount(), tree.LeafWidth())
    }
    if shape.IsBlank(NodeIndex(0)) {
        t.Fatalf("leaf 0 reported blank")
    }
    if !shape.IsBlank(NodeIndex(6)) {
        t.Fatalf("leaf 3 is unoccupied and must report blank")
    }
    if got := shape.UnmergedLeaves(NodeIndex(1)); len(got) != 1 || got[0] != LeafIndex(1) {
        t.Fatalf("NodeShape.UnmergedLeaves(1) = %v, want [1]", got)
    }
    if got := shape.UnmergedLeaves(NodeIndex(3)); len(got) != 0 {
        t.Fatalf("a blank parent has no unmerged leaves, got %v", got)
    }

    // trailing blanks: leaf 3 and the nodes above it are empty in a width-4 tree.
    if !tree.HasTrailingBlankNodes() {
        t.Fatalf("a tree whose last node is blank must report trailing blanks")
    }
    full := NewRatchetTree()
    if err := full.SetLeaf(LeafIndex(0), testLeafNodeTemplate()); err != nil {
        t.Fatalf("SetLeaf: %v", err)
    }
    if full.HasTrailingBlankNodes() {
        t.Fatalf("a one-leaf tree has no trailing blank")
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

func (self *ParentNode) MarshalMLS(w *syntax.Writer) error {
    w.WriteOpaque(self.EncryptionKey)
    w.WriteOpaque(self.ParentHash)
    return syntax.WriteVector(w, self.UnmergedLeaves,
        func(w *syntax.Writer, leaf LeafIndex) error {
            w.WriteUint32(uint32(leaf))
            return nil
        })
}

func (self *ParentNode) UnmarshalMLS(r *syntax.Reader) error {
    encryptionKey, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    parentHash, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    unmerged, err := syntax.ReadVector(r, func(r *syntax.Reader) (LeafIndex, error) {
        v, err := r.ReadUint32()
        return LeafIndex(v), err
    })
    if err != nil {
        return err
    }
    self.EncryptionKey = HpkePublicKey(encryptionKey)
    self.ParentHash = parentHash
    self.UnmergedLeaves = unmerged
    return nil
}

var _ syntax.Codec = (*ParentNode)(nil)

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

// one element of the ratchet_tree vector: optional<Node>. it is a named type rather
// than a bare *Node so the validation plan's codec table and fuzz corpus have a
// decodable unit for a single position.
type OptionalNode struct {
    Present bool
    Node    Node
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

// a count, not an index: this feeds NodeWidth, DirectPath, Root and Resolution, all
// of which take LeafCount.
func (self *RatchetTree) LeafWidth() LeafCount {
    return LeafCount((self.NodeWidth() + 1) / 2)
}

// grow to at least the given leaf count, doubling. existing node indices are
// unchanged, because doubling only appends a new root and a blank right subtree.
// ExtendedLeafCount is the doubling, and it is what refuses to pass MaxLeafCount.
func (self *RatchetTree) growTo(target LeafCount) error {
    width := self.LeafWidth()
    for width < target {
        extended, err := ExtendedLeafCount(width)
        if err != nil {
            return err
        }
        width = extended
    }
    if width == self.LeafWidth() {
        return nil
    }
    grown := make([]*Node, NodeWidth(width))
    copy(grown, self.nodes)
    self.nodes = grown
    return nil
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
    if LeafCount(i) >= MaxLeafCount {
        return ErrLeafIndexOutOfRange
    }
    if err := self.growTo(LeafCount(i) + 1); err != nil {
        return err
    }
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
    if LeafCount(i) >= self.LeafWidth() {
        return ErrLeafIndexOutOfRange
    }
    path, err := directPathOf(i.NodeIndex(), self.LeafWidth())
    if err != nil {
        return err
    }
    for _, x := range path {
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

// every occupied leaf slot, ascending. Members is the same list under the name the
// group lifecycle plan uses for it; there is one implementation.
func (self *RatchetTree) NonBlankLeaves() []LeafIndex {
    out := []LeafIndex{}
    for i := uint32(0); i < uint32(self.LeafWidth()); i++ {
        if self.Leaf(LeafIndex(i)) != nil {
            out = append(out, LeafIndex(i))
        }
    }
    return out
}

func (self *RatchetTree) Members() []LeafIndex {
    return self.NonBlankLeaves()
}

func (self *RatchetTree) MemberCount() uint32 {
    return uint32(len(self.NonBlankLeaves()))
}

func (self *RatchetTree) FindLeafBySignatureKey(key SignaturePublicKey) (LeafIndex, bool) {
    for i := uint32(0); i < uint32(self.LeafWidth()); i++ {
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

// is this HPKE public key already at some node, leaf or parent? the group lifecycle
// plan's ValSem103 and ValSem110 ask exactly this, once per proposal.
func (self *RatchetTree) EncryptionKeyInUse(key HpkePublicKey) bool {
    for x := uint32(0); x < self.NodeWidth(); x++ {
        node := self.nodes[x]
        if node == nil {
            continue
        }
        if node.Leaf != nil && subtle.ConstantTimeCompare(node.Leaf.EncryptionKey, key) == 1 {
            return true
        }
        if node.Parent != nil && subtle.ConstantTimeCompare(node.Parent.EncryptionKey, key) == 1 {
            return true
        }
    }
    return false
}

// ValSem300 asks this of an exported tree. it is a read of the node array, so it
// lives here rather than being re-derived from the encoding in two other plans.
func (self *RatchetTree) HasTrailingBlankNodes() bool {
    return len(self.nodes) > 0 && self.nodes[len(self.nodes)-1] == nil
}

// ---- NodeShape, so the tree math plan's Resolution and FilteredDirectPath run
// against a real tree. UnmergedLeaves returns the stored list in stored order.

func (self *RatchetTree) LeafCount() LeafCount {
    return self.LeafWidth()
}

func (self *RatchetTree) IsBlank(x NodeIndex) bool {
    return self.Get(x) == nil
}

func (self *RatchetTree) UnmergedLeaves(x NodeIndex) []LeafIndex {
    parent := self.ParentAt(x)
    if parent == nil {
        return nil
    }
    return parent.UnmergedLeaves
}

var _ NodeShape = (*RatchetTree)(nil)
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
- Consumes: `func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)`, `SignatureKeyPair`, `DeriveKeyPair`, `Random`, `HashSize` on `CryptoProvider` (Crypto plan); `BasicCredential` (Task 4A); `(*LeafKeysExtension).Encode` (Task 4); `RatchetTree`, `LeafNode` (Tasks 5, 8).
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
        leafKeys := &LeafKeysExtension{
            AlgId:          AlgIdXwing,
            DeviceXwingPub: crypto.Random(XwingPublicKeyLen),
        }
        leafKeysExt, err := leafKeys.Encode()
        if err != nil {
            t.Fatalf("LeafKeysExtension.Encode(%d): %v", i, err)
        }
        leaf := &LeafNode{
            EncryptionKey: encryptionPub,
            SignatureKey:  signaturePub,
            Credential:    BasicCredential([]byte(fmt.Sprintf("member-%d", i))),
            Capabilities: Capabilities{
                Versions:     []ProtocolVersion{ProtocolVersionMls10},
                CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
                Extensions: []ExtensionType{
                    ExtensionTypeUrmessageGroupPolicy,
                    ExtensionTypeUrmessageLeafKeys,
                    ExtensionTypeUrmessageOwnerSuccessor,
                },
                Proposals:   []ProposalType{ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove},
                Credentials: []CredentialType{CredentialTypeBasic},
            },
            LeafNodeSource: LeafNodeSourceUpdate,
            Extensions:     []Extension{leafKeysExt},
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
- Consumes: `func Resolution(shape NodeShape, x NodeIndex) ([]NodeIndex, error)`, `type NodeShape interface{...}`, `func Root(n LeafCount) (NodeIndex, error)` (Tree math plan); the `NodeShape` implementation and `rootOf` (Tasks 8, 3).
- Produces: `func (self *RatchetTree) Resolution(x NodeIndex) []NodeIndex` — a thin, error-free delegation to the tree math plan's `Resolution(shape, x)`, for the call sites that already know `x` is in range. RFC 9420 §7.1: a non-blank node resolves to itself followed by its unmerged leaves; a blank leaf resolves to the empty list; a blank parent resolves to its left child's resolution concatenated with its right child's.

**There is no resolution algorithm in this plan.** The tree math plan owns it, this plan supplies
the `NodeShape` (Task 8), and the only thing added here is the convenience method the registry
pins. The method drops the error because its single failure mode is an out-of-range `x`, which
every internal caller has already bounded; the two places that have not — `EncryptionTargets` and
`FilteredDirectPath` — call the free `Resolution(self, x)` and `FilteredDirectPath(self, i)` and
return the error.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go (append)

func TestResolutionRules(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    root, err := rootOf(tree.LeafWidth())
    if err != nil {
        t.Fatalf("rootOf: %v", err)
    }

    // all parents blank: the root resolves to the four leaves, left to right.
    got := tree.Resolution(root)
    want := []NodeIndex{0, 2, 4, 6}
    if !equalNodeIndices(got, want) {
        t.Fatalf("blank-parent root resolution = %v, want %v", got, want)
    }

    // a blank leaf contributes nothing.
    if err := tree.Blank(NodeIndex(2)); err != nil {
        t.Fatalf("Blank: %v", err)
    }
    got = tree.Resolution(root)
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
    got = tree.Resolution(root)
    want = []NodeIndex{1, 0, 4, 6}
    if !equalNodeIndices(got, want) {
        t.Fatalf("root resolution = %v, want %v", got, want)
    }

    // the method and the free function the tree math plan owns agree, and the free
    // one is where an out-of-range node index is an error rather than an empty list.
    free, err := Resolution(tree, root)
    if err != nil {
        t.Fatalf("Resolution(tree, root): %v", err)
    }
    if !equalNodeIndices(free, got) {
        t.Fatalf("the method and the free function disagree: %v vs %v", got, free)
    }
    if _, err := Resolution(tree, NodeIndex(tree.NodeWidth())); err == nil {
        t.Fatalf("Resolution past the node width returned no error")
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

// RFC 9420 §7.1, delegated to the tree math plan against this tree's NodeShape.
// The only failure Resolution has is an out-of-range x, and every call site of this
// method has already bounded x, so the convenience form drops it. Anywhere x is not
// already bounded, call Resolution(self, x) directly and return the error.
func (self *RatchetTree) Resolution(x NodeIndex) []NodeIndex {
    out, err := Resolution(self, x)
    if err != nil {
        return []NodeIndex{}
    }
    return out
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
- Consumes: `func (self *Writer) WriteOptional(present bool, encodeOne func(w *Writer) error) error`, `func (self *Reader) ReadOptional(decodeOne func(r *Reader) error) (present bool, err error)`, `func (self *Reader) ReadSub() (*Reader, error)`, `func WriteVector[T any](...) error`, `func Marshal(v Marshaler) ([]byte, error)`, `func UnmarshalLimit(bs []byte, v Unmarshaler, maxVectorLength int) error`, `func (self *Reader) Remaining() int` (the presence-octet test only), `const MaxRatchetTreeLength int = 1 << 24`, `syntax.ErrOptionalPresence`, `syntax.ErrLengthExceedsMax`, `syntax.Codec` (Syntax plan); `func NodeWidth(n LeafCount) uint32`, `func ExtendedLeafCount(n LeafCount) (LeafCount, error)`, `func (self NodeIndex) IsLeaf() bool` (Tree math plan); `ErrTrailingBlankNodes` (Validation plan, ValSem300); `ErrTreeMalformed`, `ErrNodeTypeMismatch` (Task 2).
- Produces: `func (self *Node) MarshalMLS(w *syntax.Writer) error` / `UnmarshalMLS`; `func (self *OptionalNode) MarshalMLS(w *syntax.Writer) error` / `UnmarshalMLS`; `func (self *RatchetTree) MarshalMLS(w *syntax.Writer) error` / `UnmarshalMLS`; `var _ syntax.Codec = (*RatchetTree)(nil)`; and `func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)`.

The encoding is `optional<Node> ratchet_tree<V>` with trailing blanks stripped; the decoder refuses
a trailing blank (ValSem300), refuses a node whose type contradicts its position, and pads to the
next complete tree width.

**`UnmarshalRatchetTree` is the one place in this package that raises the vector limit.** It is
`syntax.UnmarshalLimit(data, tree, syntax.MaxRatchetTreeLength)` — 16 MiB, not the 1 MiB default
every other field gets. The syntax plan names the tree as the exception and this is the only
producer that wires it; a tree decoded through plain `syntax.Unmarshal` refuses a large group at
`ErrLengthExceedsMax`, which reads as a corrupt Welcome rather than as a limit. It is a free
function rather than a method because the limit is not something a caller should have to remember.

`RatchetTree` still implements `syntax.Codec`, so it is a `CheckRoundTrip` target and an entry in
the validation plan's codec table; the plain `UnmarshalMLS` simply carries the default limit.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go (append)

func TestRatchetTreeMarshalRoundTrip(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
        encoded, err := syntax.Marshal(tree)
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
        reencoded, err := syntax.Marshal(out)
        if err != nil {
            t.Fatalf("n=%d re-Marshal: %v", n, err)
        }
        if !bytes.Equal(reencoded, encoded) {
            t.Fatalf("n=%d re-encode differs", n)
        }
    }
}

func TestRatchetTreeRefusesTrailingBlankNodes(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 3)
    encoded, err := syntax.Marshal(tree)
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
    // the same fact through the accessor the group lifecycle and validation plans
    // call, so a tree that was built rather than decoded is caught too.
    if !tree.HasTrailingBlankNodes() {
        t.Fatalf("a width-4 tree holding three leaves has trailing blank nodes")
    }
}

func TestRatchetTreeRejectsNodeTypeInWrongPosition(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 2)
    // put a parent node at node index 0, which is a leaf position.
    tree.nodes[0] = &Node{NodeType: NodeTypeParent, Parent: &ParentNode{
        EncryptionKey: HpkePublicKey(bytes.Repeat([]byte{0xAA}, 32)),
    }}
    encoded, err := syntax.Marshal(tree)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if _, err := UnmarshalRatchetTree(encoded); !errors.Is(err, ErrNodeTypeMismatch) {
        t.Fatalf("err = %v, want ErrNodeTypeMismatch", err)
    }
}

func TestRatchetTreeRejectsABadPresenceOctet(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 2)
    encoded, err := syntax.Marshal(tree)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    // the first octet of the vector body is the first node's presence octet. the
    // length prefix is variable-width, so find its length by decoding rather than
    // by assuming an offset.
    body, err := syntax.NewReader(encoded).ReadSub()
    if err != nil {
        t.Fatalf("ReadSub: %v", err)
    }
    prefixLen := len(encoded) - body.Remaining()
    mutated := append([]byte{}, encoded...)
    mutated[prefixLen] = 0x02
    if _, err := UnmarshalRatchetTree(mutated); !errors.Is(err, syntax.ErrOptionalPresence) {
        t.Fatalf("err = %v, want ErrOptionalPresence", err)
    }
}
```

Add this helper to `mls/tree_test.go`:

```go
// the same encoding as syntax.Marshal(tree) but with one absent node appended,
// which is exactly what ValSem300 forbids.
func marshalRatchetTreeWithTrailingBlank(tree *RatchetTree) ([]byte, error) {
    canonical, err := syntax.Marshal(tree)
    if err != nil {
        return nil, err
    }
    body, err := syntax.NewReader(canonical).ReadSub()
    if err != nil {
        return nil, err
    }
    inner := syntax.NewWriter()
    for !body.Empty() {
        node := &OptionalNode{}
        if err := node.UnmarshalMLS(body); err != nil {
            return nil, err
        }
        if err := node.MarshalMLS(inner); err != nil {
            return nil, err
        }
    }
    if err := (&OptionalNode{}).MarshalMLS(inner); err != nil {
        return nil, err
    }
    payload, err := inner.Bytes()
    if err != nil {
        return nil, err
    }
    w := syntax.NewWriter()
    w.WriteOpaque(payload)
    return w.Bytes()
}
```

and add `"github.com/urnetwork/connect/mls/syntax"` to the imports of `mls/tree_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestRatchetTreeMarshal|TestRatchetTreeRefuses|TestRatchetTreeRejects" -v`
Expected: FAIL to compile with `undefined: UnmarshalRatchetTree`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree.go (append)

func (self *Node) MarshalMLS(w *syntax.Writer) error {
    w.WriteUint8(uint8(self.NodeType))
    switch self.NodeType {
    case NodeTypeLeaf:
        if self.Leaf == nil {
            return ErrTreeMalformed
        }
        return self.Leaf.MarshalMLS(w)
    case NodeTypeParent:
        if self.Parent == nil {
            return ErrTreeMalformed
        }
        return self.Parent.MarshalMLS(w)
    default:
        return ErrTreeMalformed
    }
}

// position-agnostic: whether this node type is legal at the index it was read from
// is the tree decoder's check, because only the tree knows the index.
func (self *Node) UnmarshalMLS(r *syntax.Reader) error {
    nodeType, err := r.ReadUint8()
    if err != nil {
        return err
    }
    switch NodeType(nodeType) {
    case NodeTypeLeaf:
        leaf := &LeafNode{}
        if err := leaf.UnmarshalMLS(r); err != nil {
            return err
        }
        self.NodeType, self.Leaf, self.Parent = NodeTypeLeaf, leaf, nil
    case NodeTypeParent:
        parent := &ParentNode{}
        if err := parent.UnmarshalMLS(r); err != nil {
            return err
        }
        self.NodeType, self.Leaf, self.Parent = NodeTypeParent, nil, parent
    default:
        return ErrTreeMalformed
    }
    return nil
}

var _ syntax.Codec = (*Node)(nil)

// the presence octet plus the node. WriteOptional/ReadOptional own the octet, so a
// value that is neither 0 nor 1 is syntax.ErrOptionalPresence and never has to be
// re-spelled in this package's own error set.
func (self *OptionalNode) MarshalMLS(w *syntax.Writer) error {
    return w.WriteOptional(self.Present, func(w *syntax.Writer) error {
        return self.Node.MarshalMLS(w)
    })
}

func (self *OptionalNode) UnmarshalMLS(r *syntax.Reader) error {
    present, err := r.ReadOptional(func(r *syntax.Reader) error {
        return self.Node.UnmarshalMLS(r)
    })
    if err != nil {
        return err
    }
    self.Present = present
    return nil
}

var _ syntax.Codec = (*OptionalNode)(nil)

// the ratchet_tree extension body, RFC 9420 §12.4.3.1: optional<Node> ratchet_tree<V>
// with every trailing blank stripped.
func (self *RatchetTree) MarshalMLS(w *syntax.Writer) error {
    end := len(self.nodes)
    for end > 0 && self.nodes[end-1] == nil {
        end--
    }
    return syntax.WriteVector(w, self.nodes[:end],
        func(w *syntax.Writer, node *Node) error {
            optional := OptionalNode{Present: node != nil}
            if node != nil {
                optional.Node = *node
            }
            return optional.MarshalMLS(w)
        })
}

// the element decoder needs the node index to check type against position, and that
// is what ReadVector's element callback does not carry, so this reads the sub-reader
// directly — the sanctioned form for a heterogeneous vector.
func (self *RatchetTree) UnmarshalMLS(r *syntax.Reader) error {
    body, err := r.ReadSub()
    if err != nil {
        return err
    }
    nodes := []*Node{}
    for !body.Empty() {
        x := NodeIndex(len(nodes))
        optional := &OptionalNode{}
        if err := optional.UnmarshalMLS(body); err != nil {
            return err
        }
        if !optional.Present {
            nodes = append(nodes, nil)
            continue
        }
        node := optional.Node
        switch node.NodeType {
        case NodeTypeLeaf:
            if !x.IsLeaf() {
                return ErrNodeTypeMismatch
            }
        case NodeTypeParent:
            if x.IsLeaf() {
                return ErrNodeTypeMismatch
            }
        default:
            return ErrTreeMalformed
        }
        nodes = append(nodes, &node)
    }
    // ValSem300: an exported ratchet tree carries no trailing blank nodes.
    if len(nodes) > 0 && nodes[len(nodes)-1] == nil {
        return ErrTrailingBlankNodes
    }
    if len(nodes) == 0 {
        self.nodes = make([]*Node, 1)
        return nil
    }
    // pad up to the next complete tree. ExtendedLeafCount is the doubling, and it is
    // what refuses to run past MaxLeafCount on a hostile length.
    leafWidth := LeafCount(1)
    for NodeWidth(leafWidth) < uint32(len(nodes)) {
        extended, err := ExtendedLeafCount(leafWidth)
        if err != nil {
            return err
        }
        leafWidth = extended
    }
    padded := make([]*Node, NodeWidth(leafWidth))
    copy(padded, nodes)
    self.nodes = padded
    return nil
}

var _ syntax.Codec = (*RatchetTree)(nil)

// the ratchet tree is the one field in this slice that gets the 16 MiB limit rather
// than the 1 MiB default. Decoding through plain syntax.Unmarshal would refuse a
// large group at ErrLengthExceedsMax, which reads as a corrupt Welcome rather than
// as a limit, so the raised limit is wired here once and no caller has to remember
// it. syntax.UnmarshalLimit also enforces full consumption, so there is no separate
// trailing-bytes check.
func UnmarshalRatchetTree(data []byte) (*RatchetTree, error) {
    tree := &RatchetTree{}
    if err := syntax.UnmarshalLimit(data, tree, syntax.MaxRatchetTreeLength); err != nil {
        return nil, err
    }
    return tree, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestRatchetTreeMarshal|TestRatchetTreeRefuses|TestRatchetTreeRejects" -v`
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
- Consumes: `Hash(data []byte) []byte` on `CryptoProvider` (Crypto plan); `func Left(x NodeIndex) (NodeIndex, error)`, `func Right(x NodeIndex) (NodeIndex, error)`, `func Root(n LeafCount) (NodeIndex, error)`, `func (self NodeIndex) IsLeaf() bool`, `func (self NodeIndex) LeafIndex() (LeafIndex, error)` (Tree math plan), reached through the `leftOf`/`rightOf`/`rootOf`/`leafIndexOf` shims of Task 3; `syntax.Writer`, `func (self *Writer) WriteUint8(v uint8)`, `func (self *Writer) WriteUint32(v uint32)`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Writer) WriteOptional(present bool, encodeOne func(w *Writer) error) error` (Syntax plan); `marshalBytes` (Task 3).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    rootHash, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    root, err := rootOf(tree.LeafWidth())
    if err != nil {
        t.Fatalf("rootOf: %v", err)
    }
    if !bytes.Equal(rootHash, hashes[root]) {
        t.Fatalf("TreeHash is not the root entry of TreeHashes")
    }
}

func TestBlankLeafStillHashesAtItsIndex(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
// distinguishable from every other blank position. optional<LeafNode> is written
// through WriteOptional, so the presence octet has one implementation.
func (self *RatchetTree) leafHashInput(w *syntax.Writer, i LeafIndex, leaf *LeafNode) error {
    w.WriteUint8(uint8(NodeTypeLeaf))
    w.WriteUint32(uint32(i))
    return w.WriteOptional(leaf != nil, func(w *syntax.Writer) error {
        return leaf.MarshalMLS(w)
    })
}

func (self *RatchetTree) parentHashInput(w *syntax.Writer, parent *ParentNode,
    leftHash, rightHash []byte) error {
    w.WriteUint8(uint8(NodeTypeParent))
    if err := w.WriteOptional(parent != nil, func(w *syntax.Writer) error {
        return parent.MarshalMLS(w)
    }); err != nil {
        return err
    }
    w.WriteOpaque(leftHash)
    w.WriteOpaque(rightHash)
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
    if x.IsLeaf() {
        i, ok := leafIndexOf(x)
        if !ok {
            return nil, ErrTreeMalformed
        }
        leaf := self.Leaf(i)
        if exclude != nil && exclude[i] {
            leaf = nil
        }
        input, err := marshalBytes(func(w *syntax.Writer) error {
            return self.leafHashInput(w, i, leaf)
        })
        if err != nil {
            return nil, err
        }
        return crypto.Hash(input), nil
    }
    left, ok := leftOf(x)
    if !ok {
        return nil, ErrTreeMalformed
    }
    right, ok := rightOf(x)
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
    input, err := marshalBytes(func(w *syntax.Writer) error {
        return self.parentHashInput(w, parent, leftHash, rightHash)
    })
    if err != nil {
        return nil, err
    }
    return crypto.Hash(input), nil
}

func (self *RatchetTree) NodeTreeHash(crypto CryptoProvider, x NodeIndex) ([]byte, error) {
    return self.treeHash(crypto, x, nil)
}

func (self *RatchetTree) TreeHash(crypto CryptoProvider) ([]byte, error) {
    root, err := rootOf(self.LeafWidth())
    if err != nil {
        return nil, err
    }
    return self.treeHash(crypto, root, nil)
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
- Consumes: `Hash(data []byte) []byte` on `CryptoProvider`; `func Left(x NodeIndex) (NodeIndex, error)`, `func Right(x NodeIndex) (NodeIndex, error)` (Tree math plan), through the `leftOf`/`rightOf` shims of Task 3; `marshalBytes` (Task 3); `treeHash` (Task 12); `ErrParentHashMismatch` (Task 2).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    input, err := marshalBytes(func(w *syntax.Writer) error {
        w.WriteOpaque(node.EncryptionKey)
        w.WriteOpaque(node.ParentHash)
        w.WriteOpaque(siblingHash)
        return nil
    })
    if err != nil {
        return nil, err
    }
    return crypto.Hash(input), nil
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
- Consumes: `func Left(x NodeIndex) (NodeIndex, error)`, `func Right(x NodeIndex) (NodeIndex, error)` (Tree math plan), through the `leftOf`/`rightOf` shims of Task 3; `ErrParentHashMismatch`, `ErrTreeMalformed` (Task 2); `(*RatchetTree).Resolution` (Task 10); `(*RatchetTree).ParentHash` (Task 13).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := buildParentHashChain(t, crypto)
    if err := tree.VerifyParentHashes(crypto); err != nil {
        t.Fatalf("VerifyParentHashes: %v", err)
    }
}

func TestVerifyParentHashesRejectsATamperedChain(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
        left, ok := leftOf(node)
        if !ok {
            return ErrTreeMalformed
        }
        right, ok := rightOf(node)
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
- Consumes: `func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)` (through the `directPathOf` shim of Task 3), `func NodeWidth(n LeafCount) uint32`, `func TruncatedLeafCount(rightmostNonBlankLeaf LeafIndex) (LeafCount, error)` (Tree math plan); `ErrLeafIndexOutOfRange` (Task 2).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    // no blank leaf means the tree grows, and SetLeaf is what grows it.
    target := LeafIndex(self.LeafWidth())
    for i := uint32(0); i < uint32(self.LeafWidth()); i++ {
        if self.Leaf(LeafIndex(i)) == nil {
            target = LeafIndex(i)
            break
        }
    }
    if err := self.SetLeaf(target, leaf); err != nil {
        return 0, err
    }
    path, err := directPathOf(target.NodeIndex(), self.LeafWidth())
    if err != nil {
        return 0, err
    }
    for _, x := range path {
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
    if LeafCount(i) >= self.LeafWidth() || self.Leaf(i) == nil {
        return ErrLeafIndexOutOfRange
    }
    if err := self.SetLeaf(i, leaf); err != nil {
        return err
    }
    return self.BlankDirectPath(i)
}

// RFC 9420 §7.7. blank the leaf and its direct path, drop it from any surviving
// unmerged list, then shrink to the smallest full width that still holds a member.
func (self *RatchetTree) RemoveLeaf(i LeafIndex) error {
    if LeafCount(i) >= self.LeafWidth() || self.Leaf(i) == nil {
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
    return self.truncate()
}

// shrink to the smallest full leaf count that still contains the rightmost occupied
// leaf. TruncatedLeafCount is that computation, so this does not re-derive it by
// halving — the halving loop and the tree math would then be two answers to one
// question, and the tree hash only agrees with one of them.
func (self *RatchetTree) truncate() error {
    leaves := self.NonBlankLeaves()
    if len(leaves) == 0 {
        self.nodes = make([]*Node, 1)
        return nil
    }
    target, err := TruncatedLeafCount(leaves[len(leaves)-1])
    if err != nil {
        return err
    }
    if target >= self.LeafWidth() {
        return nil
    }
    self.nodes = self.nodes[:NodeWidth(target)]
    return nil
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
- Consumes: `func FilteredDirectPath(shape NodeShape, leaf LeafIndex) ([]PathStep, error)`, `type PathStep struct{ Node NodeIndex; CopathChild NodeIndex }`, `func Resolution(shape NodeShape, x NodeIndex) ([]NodeIndex, error)` (Tree math plan); the `NodeShape` implementation (Task 8); `ErrLeafIndexOutOfRange` (Task 2).
- Produces:
  - private `func (self *RatchetTree) filteredPathSteps(i LeafIndex) ([]PathStep, error)` — the tree math plan's `[]PathStep` with a leaf-range guard, used by Tasks 18, 20, 21 and 22, which all need the copath child as well as the node.
  - `func (self *RatchetTree) FilteredDirectPath(i LeafIndex) ([]NodeIndex, error)` — the same path with the copath children dropped: the direct path of leaf `i`, bottom-up, with every node removed whose copath child has an empty resolution.
  - `func (self *RatchetTree) EncryptionTargets(sender LeafIndex, exclude []LeafIndex) ([][]NodeIndex, error)` — one entry per filtered-direct-path node, in the same order, each the resolution of that node's copath child with the leaves in `exclude` removed. `exclude` is the set of leaves added by the same commit: they receive the path secret in the Welcome, never in the UpdatePath.

**The filtering rule lives in the tree math plan, not here.** `PathStep.CopathChild` is what removes
this plan's private `pathChildren` helper: the copath child of a node with respect to a leaf is pure
structure, so re-deriving it from `CommonAncestor` at four call sites was four chances to derive it
differently.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_test.go (append)

func TestFilteredDirectPathSkipsEmptyCopathResolutions(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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

// RFC 9420 §7.6, delegated to the tree math plan: the direct path with every node
// removed whose copath child has an empty resolution — there is nobody under that
// child to encrypt to, so the node carries no key at all and stays blank. Each step
// carries the copath child, which is what the encryption and parent-hash passes need.
func (self *RatchetTree) filteredPathSteps(i LeafIndex) ([]PathStep, error) {
    if LeafCount(i) >= self.LeafWidth() {
        return nil, ErrLeafIndexOutOfRange
    }
    return FilteredDirectPath(self, i)
}

func (self *RatchetTree) FilteredDirectPath(i LeafIndex) ([]NodeIndex, error) {
    steps, err := self.filteredPathSteps(i)
    if err != nil {
        return nil, err
    }
    out := make([]NodeIndex, 0, len(steps))
    for _, step := range steps {
        out = append(out, step.Node)
    }
    return out, nil
}

// one resolution per filtered-direct-path node, in the same order, each already
// stripped of the leaves added by this commit. RFC 9420 §7.6: a member added in the
// same commit receives the path secret in its Welcome, never in the UpdatePath.
func (self *RatchetTree) EncryptionTargets(sender LeafIndex,
    exclude []LeafIndex) ([][]NodeIndex, error) {
    steps, err := self.filteredPathSteps(sender)
    if err != nil {
        return nil, err
    }
    excluded := map[NodeIndex]bool{}
    for _, leaf := range exclude {
        excluded[leaf.NodeIndex()] = true
    }
    out := make([][]NodeIndex, 0, len(steps))
    for _, step := range steps {
        // the free form, not the method: this x is the tree math plan's own output
        // rather than one this package bounded, so its error is returned.
        resolution, err := Resolution(self, step.CopathChild)
        if err != nil {
            return nil, err
        }
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
- Consumes: `DeriveSecret(secret []byte, label string) []byte`, `DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error)`, `HashSize() int` on `CryptoProvider`; `type HpkePrivateKey []byte`, `type HpkePublicKey []byte` (Crypto plan); `ErrNoPathSecret`, `ErrPathSecretMismatch` (Task 2).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
- Consumes: `Random(n int) []byte`, `HashSize() int`, `DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error)` on `CryptoProvider` (Crypto plan); `type PathStep struct{ Node NodeIndex; CopathChild NodeIndex }` (Tree math plan); `filteredPathSteps`, `BlankDirectPath`, `SetParent`, `SetLeaf` (Tasks 8, 16); `(*RatchetTree).ParentHash` (Task 13); `(*LeafNode).Sign` (Task 6).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    // computed before the direct path is blanked: blanking the sender's own direct
    // path cannot change any copath child's resolution, so the filtered path is the
    // same either way, and computing it first keeps the failure ahead of the mutation.
    steps, err := self.filteredPathSteps(sender)
    if err != nil {
        return nil, err
    }
    path := make([]NodeIndex, 0, len(steps))
    for _, step := range steps {
        path = append(path, step.Node)
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
    // node below carries the parent hash of the node above it. the copath child comes
    // from the PathStep rather than being re-derived, so the sender and the receiver
    // in Task 21 are provably walking the same chain.
    carried := []byte{}
    for i := len(steps) - 1; i >= 0; i-- {
        parent := self.ParentAt(steps[i].Node)
        parent.ParentHash = carried
        hash, err := self.ParentHash(crypto, steps[i].Node, steps[i].CopathChild)
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
- Consumes: `syntax.Writer`, `syntax.Reader`, `func (self *Writer) WriteOpaque(bs []byte)`, `func (self *Reader) ReadOpaque() ([]byte, error)`, `func WriteVector[T any](...) error`, `func ReadVector[T any](...) ([]T, error)`, `func Marshal(v Marshaler) ([]byte, error)`, `func Unmarshal(bs []byte, v Unmarshaler) error`, `syntax.Codec` (Syntax plan); `func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)`, `func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error)` (Crypto plan); `LeafNode` codec (Task 5).
- Produces: `HpkeCiphertext{KemOutput, Ciphertext []byte}` with `MarshalMLS`/`UnmarshalMLS`; `SealWithLabel` and `OpenWithLabel`; `UpdatePathNode{EncryptionKey HpkePublicKey; EncryptedPathSecret []HpkeCiphertext}` with `MarshalMLS`/`UnmarshalMLS`; `UpdatePath{LeafNode LeafNode; Nodes []UpdatePathNode}` with `MarshalMLS`/`UnmarshalMLS` and `var _ syntax.Codec = (*UpdatePath)(nil)`. Byte-level access is `syntax.Marshal` / `syntax.Unmarshal`; there is no `Marshal()` and no `ParseUpdatePath` (C1).

`HpkeCiphertext` is also what `Welcome`'s `EncryptedGroupSecrets` uses, so the framing plan consumes
it from here rather than defining a second copy.

**`SealWithLabel`/`OpenWithLabel` land here, next to the type they return.** The crypto plan's
`EncryptWithLabel`/`DecryptWithLabel` keep their flat `(kemOutput, ciphertext)` form, because that
plan must stay free of TreeKEM types; the group lifecycle plan's `BuildWelcome` and
`JoinFromWelcome` want the struct-shaped pair, and this is the file that owns the struct. They are a
two-line adaptation, not a second HPKE implementation.

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
    encoded, err := syntax.Marshal(in)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    out := &UpdatePath{}
    if err := syntax.Unmarshal(encoded, out); err != nil {
        t.Fatalf("Unmarshal: %v", err)
    }
    reencoded, err := syntax.Marshal(out)
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
    encoded, err := syntax.Marshal(in)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if err := syntax.Unmarshal(append(encoded, 0x00), &UpdatePath{}); !errors.Is(err, syntax.ErrTrailingBytes) {
        t.Fatalf("trailing byte err = %v, want ErrTrailingBytes", err)
    }
    if err := syntax.Unmarshal(encoded[:len(encoded)-1], &UpdatePath{}); err == nil {
        t.Fatalf("Unmarshal(truncated) = nil error, want failure")
    }
}

func TestSealAndOpenWithLabelRoundTrip(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    priv, pub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
    if err != nil {
        t.Fatalf("DeriveKeyPair: %v", err)
    }
    ct, err := SealWithLabel(crypto, pub, "Welcome", []byte("context"), []byte("secret"))
    if err != nil {
        t.Fatalf("SealWithLabel: %v", err)
    }
    if len(ct.KemOutput) == 0 || len(ct.Ciphertext) == 0 {
        t.Fatalf("SealWithLabel produced an empty ciphertext")
    }
    got, err := OpenWithLabel(crypto, priv, "Welcome", []byte("context"), ct)
    if err != nil {
        t.Fatalf("OpenWithLabel: %v", err)
    }
    if !bytes.Equal(got, []byte("secret")) {
        t.Fatalf("OpenWithLabel = %q, want %q", got, "secret")
    }
    if _, err := OpenWithLabel(crypto, priv, "Welcome", []byte("other"), ct); err == nil {
        t.Fatalf("the ciphertext opened under a different context")
    }
    if _, err := OpenWithLabel(crypto, priv, "GroupSecrets", []byte("context"), ct); err == nil {
        t.Fatalf("the ciphertext opened under a different label")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestUpdatePath|TestSealAndOpenWithLabel" -v`
Expected: FAIL to compile with `undefined: UpdatePath`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go (append)

// RFC 9420 §6.1. one HPKE encryption: the KEM output and the AEAD ciphertext.
type HpkeCiphertext struct {
    KemOutput  []byte
    Ciphertext []byte
}

func (self *HpkeCiphertext) MarshalMLS(w *syntax.Writer) error {
    w.WriteOpaque(self.KemOutput)
    w.WriteOpaque(self.Ciphertext)
    return nil
}

func (self *HpkeCiphertext) UnmarshalMLS(r *syntax.Reader) error {
    kemOutput, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    ciphertext, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    self.KemOutput = kemOutput
    self.Ciphertext = ciphertext
    return nil
}

var _ syntax.Codec = (*HpkeCiphertext)(nil)

// the HpkeCiphertext-shaped form of the crypto plan's flat pair. it lives here
// rather than there because the crypto plan must not name a TreeKEM type, and it is
// an adaptation rather than a second HPKE implementation.
func SealWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string,
    context []byte, plaintext []byte) (*HpkeCiphertext, error) {
    kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, label, context, plaintext)
    if err != nil {
        return nil, err
    }
    return &HpkeCiphertext{KemOutput: kemOutput, Ciphertext: ciphertext}, nil
}

func OpenWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string,
    context []byte, ct *HpkeCiphertext) ([]byte, error) {
    return DecryptWithLabel(crypto, priv, label, context, ct.KemOutput, ct.Ciphertext)
}

// RFC 9420 §7.6. one node of the sender's filtered direct path: its new public key
// and the path secret encrypted once per node in the copath child's resolution.
type UpdatePathNode struct {
    EncryptionKey       HpkePublicKey
    EncryptedPathSecret []HpkeCiphertext
}

func (self *UpdatePathNode) MarshalMLS(w *syntax.Writer) error {
    w.WriteOpaque(self.EncryptionKey)
    return syntax.WriteVector(w, self.EncryptedPathSecret,
        func(w *syntax.Writer, ct HpkeCiphertext) error {
            return ct.MarshalMLS(w)
        })
}

func (self *UpdatePathNode) UnmarshalMLS(r *syntax.Reader) error {
    encryptionKey, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    ciphertexts, err := syntax.ReadVector(r, func(r *syntax.Reader) (HpkeCiphertext, error) {
        var ct HpkeCiphertext
        err := ct.UnmarshalMLS(r)
        return ct, err
    })
    if err != nil {
        return err
    }
    self.EncryptionKey = HpkePublicKey(encryptionKey)
    self.EncryptedPathSecret = ciphertexts
    return nil
}

var _ syntax.Codec = (*UpdatePathNode)(nil)

// RFC 9420 §7.6.
type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode
}

func (self *UpdatePath) MarshalMLS(w *syntax.Writer) error {
    if err := self.LeafNode.MarshalMLS(w); err != nil {
        return err
    }
    return syntax.WriteVector(w, self.Nodes,
        func(w *syntax.Writer, node UpdatePathNode) error {
            return node.MarshalMLS(w)
        })
}

func (self *UpdatePath) UnmarshalMLS(r *syntax.Reader) error {
    if err := self.LeafNode.UnmarshalMLS(r); err != nil {
        return err
    }
    nodes, err := syntax.ReadVector(r, func(r *syntax.Reader) (UpdatePathNode, error) {
        var node UpdatePathNode
        err := node.UnmarshalMLS(r)
        return node, err
    })
    if err != nil {
        return err
    }
    self.Nodes = nodes
    return nil
}

var _ syntax.Codec = (*UpdatePath)(nil)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestUpdatePath|TestSealAndOpenWithLabel" -v`
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
- Consumes: `func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)` (Crypto/HPKE plan), through `SealWithLabel` (Task 19); `EncryptionTargets` (Task 16); `UpdatePathPlan` (Task 18); `UpdatePath`, `HpkeCiphertext` (Task 19); `ErrPathLength` (Validation plan, ValSem202).
- Produces: `func (self *RatchetTree) EncryptUpdatePath(crypto CryptoProvider, plan *UpdatePathPlan, sender LeafIndex, groupContext []byte, exclude []LeafIndex) (*UpdatePath, error)`.

`groupContext` is `[]byte`, not a `*GroupContext`: the serialized form is what goes into the HPKE
`info`, and taking bytes is what keeps this call from having to know how the key schedule plan
encodes a GroupContext. Callers obtain them from `syntax.Marshal(gc)` (C4).

Each path secret is sealed with
`SealWithLabel(crypto, pub, "UpdatePathNode", groupContext, pathSecret)` — the HpkeCiphertext-shaped
form of the crypto plan's `EncryptWithLabel` — once per node of the copath child's resolution,
**in resolution order**; the receiver locates its
ciphertext by index into the same resolution, so the ordering is load-bearing. `groupContext` is the
serialized GroupContext of the epoch the commit opens, whose `tree_hash` is the tree hash **after**
Task 18 mutated the tree.

- [ ] **Step 1: Write the failing test**

```go
// mls/treekem_test.go (append)

func TestEncryptUpdatePathProducesOneCiphertextPerResolutionNode(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
            ct, err := SealWithLabel(crypto, pub, updatePathNodeLabel,
                groupContext, plan.PathSecrets[i])
            if err != nil {
                return nil, err
            }
            ciphertexts = append(ciphertexts, *ct)
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
- Consumes: `type PathStep struct{ Node NodeIndex; CopathChild NodeIndex }` (Tree math plan); `filteredPathSteps`, `BlankDirectPath`, `SetParent`, `SetLeaf` (Tasks 8, 16); `(*RatchetTree).ParentHash` (Task 13); `ErrPathLength` (ValSem202, Validation plan); `ErrParentHashMismatch`, `ErrLeafIndexOutOfRange` (Task 2).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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

func TestMergeUpdatePathRejectsAWrongLengthPath(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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

Run: `go test ./mls/... -run TestMergeUpdatePath -v`
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
    steps, err := self.filteredPathSteps(sender)
    if err != nil {
        return err
    }
    // ValSem202: the path covers exactly the filtered direct path.
    if len(path.Nodes) != len(steps) {
        return ErrPathLength
    }
    provisional := self.Clone()
    if err := provisional.BlankDirectPath(sender); err != nil {
        return err
    }
    for i, step := range steps {
        if err := provisional.SetParent(step.Node, &ParentNode{
            EncryptionKey: cloneBytes(path.Nodes[i].EncryptionKey),
        }); err != nil {
            return err
        }
    }
    // the same walk the sender did in Task 18, over the same PathStep list, so the
    // two chains cannot differ by a copath child derived two different ways.
    carried := []byte{}
    for i := len(steps) - 1; i >= 0; i-- {
        parent := provisional.ParentAt(steps[i].Node)
        parent.ParentHash = carried
        hash, err := provisional.ParentHash(crypto, steps[i].Node, steps[i].CopathChild)
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

Run: `go test ./mls/... -run TestMergeUpdatePath -v`
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
- Consumes: `func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error)` (Crypto/HPKE plan), through `OpenWithLabel` (Task 19); `EncryptionTargets`, `filteredPathSteps` (Task 16); `func CommonAncestor(x NodeIndex, y NodeIndex) NodeIndex` (Tree math plan); `TreeKEMPrivate` (Task 17); `ErrPathDecrypt` (ValSem203), `ErrPathKeyMismatch` (ValSem204), `ErrPathLength` (ValSem202) from the Validation plan; `ErrNoPathSecret` (Task 2).
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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

func TestDecryptUpdatePathRejectsATamperedCiphertext(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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

func TestDecryptUpdatePathRejectsAnAnnouncedKeyMismatch(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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

Run: `go test ./mls/... -run TestDecryptUpdatePath -v`
Expected: FAIL to compile with `receiverTree.DecryptUpdatePath undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/treekem.go (append)

// what a receiver ends up with after opening one UpdatePath.
type PathDecryptResult struct {
    CommitSecret []byte
    Private      *TreeKEMPrivate
}

func indexOfStep(steps []PathStep, x NodeIndex) (int, bool) {
    for i, step := range steps {
        if step.Node == x {
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
    steps, err := self.filteredPathSteps(sender)
    if err != nil {
        return nil, err
    }
    if len(path.Nodes) != len(steps) {
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
    start, ok := indexOfStep(steps, lowest)
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
        opened, err := OpenWithLabel(crypto, nodePriv, updatePathNodeLabel, groupContext, &ct)
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
    for i := start; i < len(steps); i++ {
        _, derivedPub, err := DeriveNodeKeyPair(crypto, secret)
        if err != nil {
            return nil, err
        }
        // ValSem204: the announced public key must be the one this secret derives.
        if subtle.ConstantTimeCompare(derivedPub, path.Nodes[i].EncryptionKey) != 1 {
            return nil, ErrPathKeyMismatch
        }
        out.PathSecrets[steps[i].Node] = cloneBytes(secret)
        secret = crypto.DeriveSecret(secret, "path")
    }
    return &PathDecryptResult{CommitSecret: secret, Private: out}, nil
}
```

The loop keeps only the public half: the node private keys are re-derived on demand by
`TreeKEMPrivate.NodePrivateKey`, so no private key for a node above us is materialised and left on
the heap after the check.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestDecryptUpdatePath -v`
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
- Consumes: `(*LeafNode).Validate`, `LeafValidationContext` (Task 7); `VerifyParentHashes` (Task 14); `TreeHash` (Task 12); `func LeafCountFromNodeWidth(w uint32) (LeafCount, error)`, `func IsFullLeafCount(n LeafCount) bool`, `func InSubtree(head NodeIndex, x NodeIndex) bool`, `func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)` (Tree math plan, the last through `directPathOf`); `type GroupContext struct{...}` (Key schedule plan, wave 2); `ErrDuplicateEncryptionKey`, `ErrDuplicateSignatureKey` (Validation plan); `ErrUnmergedLeavesNotSorted`, `ErrUnmergedLeafInconsistent`, `ErrTreeHashMismatch`, `ErrNodeTypeMismatch`, `ErrTreeMalformed` (Task 2).
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
        Suite:   CipherSuiteX25519ChaCha20Sha256Ed25519,
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, _ := newTestTree(t, crypto, 4)
    treeHash, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    gc := &GroupContext{
        Version:     ProtocolVersionMls10,
        CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
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
    if width == 0 {
        return ErrTreeMalformed
    }
    // LeafCountFromNodeWidth is the tree math plan's own inverse, so an even node
    // width surfaces as ErrNodeWidthNotOdd there rather than as a local %2 check
    // that could disagree with it.
    leafWidth, err := LeafCountFromNodeWidth(width)
    if err != nil {
        return ErrTreeMalformed
    }
    if leafWidth != self.LeafWidth() || !IsFullLeafCount(leafWidth) {
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
    for i := uint32(0); i < uint32(self.LeafWidth()); i++ {
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
            if LeafCount(leaf) >= self.LeafWidth() {
                return ErrUnmergedLeafInconsistent
            }
            if self.Leaf(leaf) == nil {
                return ErrUnmergedLeafInconsistent
            }
            if !InSubtree(node, leaf.NodeIndex()) {
                return ErrUnmergedLeafInconsistent
            }
            path, err := directPathOf(leaf.NodeIndex(), self.LeafWidth())
            if err != nil {
                return err
            }
            for _, intermediate := range path {
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
- Modify: `mls/tree_kat_test.go`
- Test: `mls/tree_kat_test.go`

**Interfaces:**
- Consumes: `func LoadVectorFile(t *testing.T, file string) []json.RawMessage`, `func MustHex(t *testing.T, s string) []byte`, `func HexOf(b []byte) string`, `func RegisterVectorFamily(family VectorFamily)`, `type VectorFamily struct{...}` (Validation plan, wave 1); `treeVectorsOfSuite` (Task 1); `UnmarshalRatchetTree` (Task 11); `(*RatchetTree).Resolution` (Task 10); `TreeHashes` (Task 12); `VerifyParentHashes` (Task 14); `(*LeafNode).VerifySignature` (Task 6); `func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)` (Crypto plan).
- Produces: `TestVectorTreeValidation`, the gate named `tree-validation` in this plan's scope, plus the `init()` that registers family 10 with the shared registry.

Vector fields, verified in this order: `cipher_suite`, `tree` (a serialized ratchet tree), `group_id`,
`resolutions` (one list of node indices per node index), `tree_hashes` (one hash per node index).
Every leaf signature is verified against `group_id` at its own index, and the whole tree is checked
for parent-hash validity.

**Registering the family is part of this task, not an afterthought.** The validation plan's
`TestVectorFamiliesVerify` walks the registry, so a family that never calls `RegisterVectorFamily`
is a family that never runs, and Gate 1 goes green with it silently skipped.
`expectedPendingFamilies` loses the number `10` in the same commit.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_kat_test.go (append)

type treeValidationVector struct {
    CipherSuite uint16     `json:"cipher_suite"`
    Tree        string     `json:"tree"`
    GroupId     string     `json:"group_id"`
    Resolutions [][]uint32 `json:"resolutions"`
    TreeHashes  []string   `json:"tree_hashes"`
}

func init() {
    RegisterVectorFamily(VectorFamily{
        Number: 10,
        Name:   "tree-validation",
        File:   "tree-validation.json",
        Slice:  "A1",
        Verify: verifyTreeValidationVector,
    })
}

func verifyTreeValidationVector(t *testing.T, raw json.RawMessage) {
    t.Helper()
    var vector treeValidationVector
    if err := json.Unmarshal(raw, &vector); err != nil {
        t.Fatalf("decode tree-validation entry: %v", err)
    }
    if CipherSuite(vector.CipherSuite) != CipherSuiteX25519ChaCha20Sha256Ed25519 {
        return
    }
    crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, err := UnmarshalRatchetTree(MustHex(t, vector.Tree))
    if err != nil {
        t.Fatalf("UnmarshalRatchetTree: %v", err)
    }
    groupId := MustHex(t, vector.GroupId)

    if uint32(len(vector.Resolutions)) != tree.NodeWidth() {
        t.Fatalf("%d resolutions for %d nodes", len(vector.Resolutions), tree.NodeWidth())
    }
    for x, want := range vector.Resolutions {
        got := tree.Resolution(NodeIndex(x))
        if len(got) != len(want) {
            t.Fatalf("node %d resolution = %v, want %v", x, got, want)
        }
        for j := range want {
            if uint32(got[j]) != want[j] {
                t.Fatalf("node %d resolution = %v, want %v", x, got, want)
            }
        }
    }

    hashes, err := tree.TreeHashes(crypto)
    if err != nil {
        t.Fatalf("TreeHashes: %v", err)
    }
    if len(vector.TreeHashes) != len(hashes) {
        t.Fatalf("%d tree hashes for %d nodes", len(vector.TreeHashes), len(hashes))
    }
    for x, want := range vector.TreeHashes {
        if !bytes.Equal(hashes[x], MustHex(t, want)) {
            t.Fatalf("node %d tree hash = %s, want %s", x, HexOf(hashes[x]), want)
        }
    }

    if err := tree.VerifyParentHashes(crypto); err != nil {
        t.Fatalf("VerifyParentHashes: %v", err)
    }

    for x := uint32(0); x < uint32(tree.LeafWidth()); x++ {
        leaf := tree.Leaf(LeafIndex(x))
        if leaf == nil {
            continue
        }
        if err := leaf.VerifySignature(crypto, groupId, LeafIndex(x)); err != nil {
            t.Fatalf("leaf %d signature: %v", x, err)
        }
    }
}

func TestVectorTreeValidation(t *testing.T) {
    for i, raw := range LoadVectorFile(t, "tree-validation.json") {
        raw := raw
        t.Run(fmt.Sprintf("vector-%d", i), func(t *testing.T) {
            verifyTreeValidationVector(t, raw)
        })
    }
    // treeVectorsOfSuite fails if not one entry used 0x0003, which is what stops a
    // wholly-skipped family from reading as a pass.
    treeVectorsOfSuite(t, "tree-validation.json",
        func(v *treeValidationVector) CipherSuite { return CipherSuite(v.CipherSuite) })
}
```

Add `"bytes"` and `"fmt"` to the imports of `mls/tree_kat_test.go` (`encoding/json` and `testing`
are already there from Task 1).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestVectorTreeValidation -v`
Expected: FAIL — the loader's "no such file" if the validation plan's vendoring task has not run, or
a concrete `node N resolution = ... want ...` mismatch

- [ ] **Step 3: Write minimal implementation**

No new production code. If the vector fails, the defect is in `Resolution`, `TreeHashes`,
`VerifyParentHashes` or `UnmarshalRatchetTree`, and the fix belongs to that function's own task —
except `Resolution`, which is the tree math plan's, so a resolution mismatch is a defect there or in
this plan's `NodeShape` (Task 8), never in the vector. Three failures are expected here and are real
bugs:

- A resolution mismatch on a node with unmerged leaves means `UnmergedLeaves` is not returning the
  stored list in stored order — the resolution puts them after the node itself, in that order.
- A tree-hash mismatch on a blank leaf means `leafHashInput` omitted the leaf index.
- A `LeafCount`/`NodeWidth` disagreement means `LeafWidth` was computed rather than taken from the
  tree math plan's inverse; `validateStructure` is where that surfaces.

Delete `10` from `expectedPendingFamilies` in the validation plan's registry test in this same
commit — the family is no longer pending.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestVectorTreeValidation|TestVectorFamiliesVerify" -v`
Expected: PASS, with `TestVectorFamiliesVerify` now running family 10

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_kat_test.go
git commit -m "test(mls): tree-validation vector family passes and registers as family 10"
```

---

### Task 25: The TreeKEM vector family (family 11), both directions

**Files:**
- Modify: `mls/tree_kat_test.go`
- Test: `mls/tree_kat_test.go`

**Interfaces:**
- Consumes: `func LoadVectorFile(t *testing.T, file string) []json.RawMessage`, `func MustHex(t *testing.T, s string) []byte`, `func HexOf(b []byte) string`, `func RegisterVectorFamily(family VectorFamily)`, `type VectorFamily struct{...}` (Validation plan, wave 1); `treeVectorsOfSuite` (Task 1); `UnmarshalRatchetTree` (Task 11); `UpdatePath` codec (Task 19); `MergeUpdatePath` (Task 21); `DecryptUpdatePath` (Task 22); `CreateUpdatePathSecrets`, `EncryptUpdatePath` (Tasks 18, 20); `TreeKEMPrivate` (Task 17); `type GroupContext struct{...}` and `func (self *GroupContext) MarshalMLS(w *syntax.Writer) error` (Key schedule plan, wave 2), through `syntax.Marshal`; `func CommonAncestor(x NodeIndex, y NodeIndex) NodeIndex` (Tree math plan).
- Produces: `TestVectorTreeKEM` (verify direction) and `TestVectorTreeKEMGenerate` (generate direction), the gate named `treekem` in this plan's scope, plus the `init()` that registers family 11.

`expectedPendingFamilies` loses the number `11` in this task's commit, for the same reason family 10
loses its number in Task 24's.

Vector fields: `cipher_suite`, `group_id`, `epoch`, `confirmed_transcript_hash`, `ratchet_tree`,
`leaves_private[]{index, encryption_priv, signature_priv, path_secrets[]{node, path_secret}}`, and
`update_paths[]{sender, update_path, path_secrets[] (one per leaf index, null where that leaf cannot
decrypt), commit_secret, tree_hash_after}`.

The GroupContext used as the HPKE context for each update path has `tree_hash = tree_hash_after` of
that path — which is why generation and encryption are two separate calls in this package.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_kat_test.go (append)

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
        Version:                 ProtocolVersionMls10,
        CipherSuite:             CipherSuite(self.CipherSuite),
        GroupId:                 MustHex(t, self.GroupId),
        Epoch:                   self.Epoch,
        TreeHash:                treeHash,
        ConfirmedTranscriptHash: MustHex(t, self.ConfirmedTranscriptHash),
    }
    // GroupContext has no Marshal of its own (C1); syntax.Marshal is the byte-level
    // entry point, and it is what the framing plan's callers use too, so the HPKE
    // info here is byte-identical to the one a real commit builds.
    encoded, err := syntax.Marshal(gc)
    if err != nil {
        t.Fatalf("Marshal(GroupContext): %v", err)
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
            HpkePrivateKey(MustHex(t, entry.EncryptionPriv)))
        for _, secret := range entry.PathSecrets {
            priv.PathSecrets[NodeIndex(secret.Node)] = MustHex(t, secret.PathSecret)
        }
        return priv, true
    }
    return nil, false
}

func init() {
    RegisterVectorFamily(VectorFamily{
        Number: 11,
        Name:   "treekem",
        File:   "treekem.json",
        Slice:  "A1",
        Verify: verifyTreeKemVector,
    })
}

func verifyTreeKemVector(t *testing.T, raw json.RawMessage) {
    t.Helper()
    var vector treeKemVector
    if err := json.Unmarshal(raw, &vector); err != nil {
        t.Fatalf("decode treekem entry: %v", err)
    }
    if CipherSuite(vector.CipherSuite) != CipherSuiteX25519ChaCha20Sha256Ed25519 {
        return
    }
    crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    base, err := UnmarshalRatchetTree(MustHex(t, vector.RatchetTree))
    if err != nil {
        t.Fatalf("UnmarshalRatchetTree: %v", err)
    }
    // the supplied private state must already agree with the supplied tree.
    for _, entry := range vector.LeavesPrivate {
        priv, _ := vector.private(t, entry.Index)
        if err := priv.Consistent(crypto, base); err != nil {
            t.Fatalf("leaf %d private state: %v", entry.Index, err)
        }
    }
    for j, update := range vector.UpdatePaths {
        path := &UpdatePath{}
        if err := syntax.Unmarshal(MustHex(t, update.UpdatePath), path); err != nil {
            t.Fatalf("path %d Unmarshal(UpdatePath): %v", j, err)
        }
        merged := base.Clone()
        if err := merged.MergeUpdatePath(crypto, LeafIndex(update.Sender), path); err != nil {
            t.Fatalf("path %d MergeUpdatePath: %v", j, err)
        }
        treeHash, err := merged.TreeHash(crypto)
        if err != nil {
            t.Fatalf("path %d TreeHash: %v", j, err)
        }
        if !bytes.Equal(treeHash, MustHex(t, update.TreeHashAfter)) {
            t.Fatalf("path %d tree hash = %s, want %s", j, HexOf(treeHash), update.TreeHashAfter)
        }
        if err := merged.VerifyParentHashes(crypto); err != nil {
            t.Fatalf("path %d VerifyParentHashes: %v", j, err)
        }
        groupContext := vector.groupContext(t, treeHash)
        wantCommitSecret := MustHex(t, update.CommitSecret)
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
                t.Fatalf("path %d leaf %d DecryptUpdatePath: %v", j, leafIndex, err)
            }
            lowest := CommonAncestor(LeafIndex(update.Sender).NodeIndex(),
                LeafIndex(leafIndex).NodeIndex())
            if !bytes.Equal(got.Private.PathSecrets[lowest], MustHex(t, *wantSecret)) {
                t.Fatalf("path %d leaf %d path secret at node %d differs", j, leafIndex, lowest)
            }
            if !bytes.Equal(got.CommitSecret, wantCommitSecret) {
                t.Fatalf("path %d leaf %d commit secret = %s, want %s",
                    j, leafIndex, HexOf(got.CommitSecret), update.CommitSecret)
            }
        }
    }
}

func TestVectorTreeKEM(t *testing.T) {
    for i, raw := range LoadVectorFile(t, "treekem.json") {
        raw := raw
        t.Run(fmt.Sprintf("vector-%d", i), func(t *testing.T) {
            verifyTreeKemVector(t, raw)
        })
    }
    treeVectorsOfSuite(t, "treekem.json",
        func(v *treeKemVector) CipherSuite { return CipherSuite(v.CipherSuite) })
}

func TestVectorTreeKEMGenerate(t *testing.T) {
    vectors := treeVectorsOfSuite(t, "treekem.json",
        func(v *treeKemVector) CipherSuite { return CipherSuite(v.CipherSuite) })
    ran := 0
    for i, vector := range vectors {
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d NewCryptoProvider: %v", i, err)
        }
        base, err := UnmarshalRatchetTree(MustHex(t, vector.RatchetTree))
        if err != nil {
            t.Fatalf("vector %d UnmarshalRatchetTree: %v", i, err)
        }
        groupId := MustHex(t, vector.GroupId)
        for _, entry := range vector.LeavesPrivate {
            sender := LeafIndex(entry.Index)
            senderTree := base.Clone()
            plan, err := senderTree.CreateUpdatePathSecrets(crypto, sender,
                SignaturePrivateKey(MustHex(t, entry.SignaturePriv)), groupId)
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

`treeKemVector.groupContext` and `treeKemVector.private` are methods on the vector rather than free
helpers so `syntax` is imported once in this file; add `"github.com/urnetwork/connect/mls/syntax"`
to `mls/tree_kat_test.go`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestVectorTreeKEM -v`
Expected: FAIL — the loader's "no such file" if the validation plan's vendoring task has not run, or
a concrete `tree hash = ... want ...` or `commit secret = ... want ...` mismatch

- [ ] **Step 3: Write minimal implementation**

No new production code. The three failures worth naming, because each has a wrong fix that also
makes the vector pass in one direction only:

- A `tree_hash_after` mismatch after `MergeUpdatePath` means the receiver's recomputed parent-hash
  chain differs from the sender's. Fix the chain in `MergeUpdatePath`, never the tree hash.
- A commit-secret mismatch with correct path secrets means the commit secret was taken as
  `path_secret[last]` rather than `DeriveSecret(path_secret[last], "path")`.
- A path secret that decrypts for one leaf and not another means the ciphertext index was found by
  trial rather than by position in the copath resolution — `DecryptUpdatePath` must index, not search.

Delete `11` from `expectedPendingFamilies` in the validation plan's registry test in this same
commit.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestVectorTreeKEM|TestVectorFamiliesVerify" -v`
Expected: PASS (`TestVectorTreeKEM`, `TestVectorTreeKEMGenerate`, and `TestVectorFamiliesVerify`
now running families 10 and 11)

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_kat_test.go
git commit -m "test(mls): TreeKEM vector family passes in both directions and registers as family 11"
```

---

### Task 26: The remaining tree ValSem codes

**Files:**
- Modify: `mls/tree_sync.go`, `mls/tree_sync_test.go`
- Test: `mls/tree_sync_test.go`

**Interfaces:**
- Consumes: `ErrDuplicateEncryptionKey` (Validation plan, used for ValSem206 and ValSem207); `FindLeafBySignatureKey`, `Leaf` (Task 8); `UpdatePath` (Task 19); `MergeUpdatePath` (Task 21).
- Produces: `func CheckUpdatePathKeyUniqueness(tree *RatchetTree, path *UpdatePath) error` — ValSem206 (the path's leaf-node encryption key is unique against every key already in the tree) and ValSem207 (each path node's encryption key is unique the same way). The group lifecycle plan calls it before `MergeUpdatePath`, because the check is against the pre-merge tree; the validation plan calls it from its Gate 3 rows.

**It is a free function taking the tree, and it takes no `sender`.** The sender's own outgoing leaf
key is the one key the path is *replacing*, so it must not count as a collision — and the path
already identifies that leaf, because a commit does not change the committer's signature key. So the
sender is recovered with `FindLeafBySignatureKey(path.LeafNode.SignatureKey)` rather than passed in,
which removes the one argument a caller could get wrong and turn a real ValSem206 into a pass.

**The ValSem-numbered test names are the validation plan's, exclusively** (Spec A §4.3). That plan
declares `TestValSem202_PathLength`, `TestValSem203_PathDecrypt`, `TestValSem204_PathKeyMismatch`,
`TestValSem206_PathLeafDuplicateEncryptionKey`, `TestValSem207_PathNodeDuplicateEncryptionKey` and
`TestValSem300_TrailingBlankNodes`, and two functions of one name in one Go package do not compile.
What this plan keeps is the production surface those tests drive — `CheckUpdatePathKeyUniqueness`,
`MergeUpdatePath`, `DecryptUpdatePath`, `UnmarshalRatchetTree` — plus behaviour-named regression
tests of its own. There is no `TestTreeValSemCoverage` here either: ValSem coverage is asserted once,
in the validation plan, and asserting it twice against two name lists is how the two lists drift.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_sync_test.go (append)

func TestUpdatePathLeafKeyUniqueness(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
    if err := CheckUpdatePathKeyUniqueness(tree, path); err != nil {
        t.Fatalf("a fresh path must be unique: %v", err)
    }
    tampered := &UpdatePath{LeafNode: *path.LeafNode.Clone(), Nodes: path.Nodes}
    tampered.LeafNode.EncryptionKey = cloneBytes(tree.Leaf(LeafIndex(2)).EncryptionKey)
    if err := CheckUpdatePathKeyUniqueness(tree, tampered); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("err = %v, want ErrDuplicateEncryptionKey", err)
    }
}

func TestUpdatePathNodeKeyUniqueness(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)

    // a path node reusing a leaf's key that is already in the tree.
    tampered := &UpdatePath{LeafNode: path.LeafNode, Nodes: append([]UpdatePathNode{}, path.Nodes...)}
    tampered.Nodes[0].EncryptionKey = cloneBytes(tree.Leaf(LeafIndex(2)).EncryptionKey)
    if err := CheckUpdatePathKeyUniqueness(tree, tampered); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("reused tree key: err = %v, want ErrDuplicateEncryptionKey", err)
    }

    // two nodes of the same path sharing a key.
    tampered = &UpdatePath{LeafNode: path.LeafNode, Nodes: append([]UpdatePathNode{}, path.Nodes...)}
    tampered.Nodes[1].EncryptionKey = cloneBytes(tampered.Nodes[0].EncryptionKey)
    if err := CheckUpdatePathKeyUniqueness(tree, tampered); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("repeated path key: err = %v, want ErrDuplicateEncryptionKey", err)
    }

    // the sender's own outgoing leaf key is being replaced, so it does not count.
    // this is the case that fails if the sender is guessed rather than recovered
    // from the path's own signature key.
    reused := &UpdatePath{LeafNode: *path.LeafNode.Clone(), Nodes: path.Nodes}
    reused.LeafNode.EncryptionKey = cloneBytes(tree.Leaf(members[0].LeafIndex).EncryptionKey)
    if err := CheckUpdatePathKeyUniqueness(tree, reused); err != nil {
        t.Fatalf("the sender's own leaf key must not collide with itself: %v", err)
    }
}

// a path whose leaf signature key is in no leaf of the tree is not from a member, so
// nothing is being replaced and every key in it must be new.
func TestUpdatePathKeyUniquenessWithAnUnknownSender(t *testing.T) {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, members := newTestTree(t, crypto, 4)
    _, path, _, _ := createAndEncryptPath(t, crypto, tree, members[0], nil)
    stranger := &UpdatePath{LeafNode: *path.LeafNode.Clone(), Nodes: path.Nodes}
    stranger.LeafNode.SignatureKey = SignaturePublicKey(bytes.Repeat([]byte{0x7E}, 32))
    stranger.LeafNode.EncryptionKey = cloneBytes(tree.Leaf(members[0].LeafIndex).EncryptionKey)
    if err := CheckUpdatePathKeyUniqueness(tree, stranger); !errors.Is(err, ErrDuplicateEncryptionKey) {
        t.Fatalf("err = %v, want ErrDuplicateEncryptionKey", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestUpdatePath.*Uniqueness -v`
Expected: FAIL to compile with `undefined: CheckUpdatePathKeyUniqueness`

- [ ] **Step 3: Write minimal implementation**

```go
// mls/tree_sync.go (append)

// ValSem206 and ValSem207. every encryption key an UpdatePath introduces must be new
// to the tree, and new within the path. the committer's own outgoing leaf key is
// skipped: it is the one key the path is replacing. Run this against the PRE-merge
// tree.
//
// The committer is recovered from the path rather than passed in. A commit never
// changes the committer's signature key, so the leaf carrying that key is the leaf
// being replaced; taking it as an argument would let one wrong call site turn a real
// duplicate into a pass. A path whose signature key matches no leaf is not from a
// member, and then nothing is being replaced.
func CheckUpdatePathKeyUniqueness(tree *RatchetTree, path *UpdatePath) error {
    replaced, isMember := tree.FindLeafBySignatureKey(path.LeafNode.SignatureKey)
    existing := map[string]bool{}
    for x := uint32(0); x < tree.NodeWidth(); x++ {
        node := tree.Get(NodeIndex(x))
        if node == nil {
            continue
        }
        if node.Leaf != nil {
            if isMember && NodeIndex(x) == replaced.NodeIndex() {
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

Run: `go test ./mls/... -run TestUpdatePath.*Uniqueness -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_sync.go mls/tree_sync_test.go
git commit -m "feat(mls): UpdatePath encryption key uniqueness (ValSem206, ValSem207)"
```

---

### Task 27: Seed corpus and the round-trip stability regression net

**Files:**
- Create: `mls/tree_roundtrip_test.go`, `mls/interop/testdata/corpus/ratchet_tree/`, `mls/interop/testdata/corpus/update_path/`
- Test: `mls/tree_roundtrip_test.go`

**Interfaces:**
- Consumes: `func Marshal(v Marshaler) ([]byte, error)`, `func Unmarshal(bs []byte, v Unmarshaler) error` (Syntax plan); `LoadVectorFile`, `MustHex`, `HexOf` (Validation plan); `UnmarshalRatchetTree`, `(*RatchetTree).MarshalMLS` (Task 11); `UpdatePath` codec (Task 19).
- Produces: the two committed seed corpora, plus `TestRatchetTreeDecodeIsRoundTripStable` and `TestUpdatePathDecodeIsRoundTripStable` — the deterministic regression net over that corpus.

**The `Fuzz*` targets are the validation plan's, not this plan's.** That plan owns all nine Gate-4
fuzz targets, because it owns the codec table and the differential-oracle hook they call, and
`TestFuzzTargetsCoverEveryKind` parses the target file with `go/ast` so a deleted target turns it
red. A tenth and eleventh target declared here would be outside that count and outside that check.
What this plan contributes is the two things the validation plan cannot derive on its own: the seed
corpus, which comes from this plan's own vectors, and a deterministic table-driven assertion of the
same two properties over that corpus, which runs in every `go test` rather than only under `-fuzz`.

Round-trip stability is the property that matters most here: MLS signs over serialized forms, so a
decoder that accepts two encodings of one tree is a signature-bypass primitive. `encode(decode(x))`
must equal the canonical re-serialization, and `decode(encode(decode(x)))` must equal `decode(x)`.

- [ ] **Step 1: Write the failing test**

```go
// mls/tree_roundtrip_test.go
package mls

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

// the committed corpus the validation plan's fuzz targets seed from and the nightly
// differential job in Spec A §4.4 adds to. One directory per decoder.
func corpusInputs(t testing.TB, kind string) [][]byte {
    t.Helper()
    dir := filepath.Join("interop", "testdata", "corpus", kind)
    entries, err := os.ReadDir(dir)
    if err != nil {
        t.Fatalf("read corpus %s: %v", kind, err)
    }
    out := [][]byte{}
    for _, entry := range entries {
        if entry.IsDir() {
            continue
        }
        data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
        if err != nil {
            t.Fatalf("read %s: %v", entry.Name(), err)
        }
        out = append(out, data)
    }
    if len(out) == 0 {
        t.Fatalf("corpus %s is empty", kind)
    }
    return out
}

func TestRatchetTreeDecodeIsRoundTripStable(t *testing.T) {
    for i, data := range corpusInputs(t, "ratchet_tree") {
        tree, err := UnmarshalRatchetTree(data)
        if err != nil {
            t.Fatalf("input %d: the corpus holds only accepted inputs: %v", i, err)
        }
        encoded, err := syntax.Marshal(tree)
        if err != nil {
            t.Fatalf("input %d: a decoded tree failed to re-encode: %v", i, err)
        }
        again, err := UnmarshalRatchetTree(encoded)
        if err != nil {
            t.Fatalf("input %d: the canonical re-encoding failed to decode: %v", i, err)
        }
        reencoded, err := syntax.Marshal(again)
        if err != nil {
            t.Fatalf("input %d: re-encode: %v", i, err)
        }
        if !bytes.Equal(encoded, reencoded) {
            t.Fatalf("input %d: encoding is not stable across a second round trip", i)
        }
        if again.NodeWidth() != tree.NodeWidth() {
            t.Fatalf("input %d: node width changed across a round trip: %d then %d",
                i, tree.NodeWidth(), again.NodeWidth())
        }
    }
}

func TestUpdatePathDecodeIsRoundTripStable(t *testing.T) {
    for i, data := range corpusInputs(t, "update_path") {
        path := &UpdatePath{}
        if err := syntax.Unmarshal(data, path); err != nil {
            t.Fatalf("input %d: the corpus holds only accepted inputs: %v", i, err)
        }
        encoded, err := syntax.Marshal(path)
        if err != nil {
            t.Fatalf("input %d: a decoded update path failed to re-encode: %v", i, err)
        }
        if !bytes.Equal(encoded, data) {
            t.Fatalf("input %d: the decoder accepted a non-canonical encoding: %s vs %s",
                i, HexOf(encoded), HexOf(data))
        }
        again := &UpdatePath{}
        if err := syntax.Unmarshal(encoded, again); err != nil {
            t.Fatalf("input %d: the canonical re-encoding failed to decode: %v", i, err)
        }
        if len(again.Nodes) != len(path.Nodes) {
            t.Fatalf("input %d: node count changed across a round trip", i)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestRatchetTreeDecodeIsRoundTripStable|TestUpdatePathDecodeIsRoundTripStable" -v`
Expected: FAIL with `read corpus ratchet_tree: open interop/testdata/corpus/ratchet_tree: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

Seed both corpora from material that already exists, so the corpus is derived rather than invented:

```bash
mkdir -p mls/interop/testdata/corpus/ratchet_tree mls/interop/testdata/corpus/update_path
cat > mls/seed_corpus_test.go <<'GOEOF'
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
// vendored vectors into the committed corpus. Run once, then deleted.
func TestSeedTreeCorpus(t *testing.T) {
    write := func(kind string, data []byte) {
        sum := sha256.Sum256(data)
        name := filepath.Join("interop", "testdata", "corpus", kind, hex.EncodeToString(sum[:8]))
        if err := os.WriteFile(name, data, 0o644); err != nil {
            t.Fatalf("write %s: %v", name, err)
        }
    }
    for _, raw := range LoadVectorFile(t, "tree-validation.json") {
        var vector treeValidationVector
        if err := json.Unmarshal(raw, &vector); err != nil {
            t.Fatalf("decode tree-validation entry: %v", err)
        }
        write("ratchet_tree", MustHex(t, vector.Tree))
    }
    for _, raw := range LoadVectorFile(t, "treekem.json") {
        var vector treeKemVector
        if err := json.Unmarshal(raw, &vector); err != nil {
            t.Fatalf("decode treekem entry: %v", err)
        }
        write("ratchet_tree", MustHex(t, vector.RatchetTree))
        for _, update := range vector.UpdatePaths {
            write("update_path", MustHex(t, update.UpdatePath))
        }
    }
}
GOEOF
go test ./mls/... -run TestSeedTreeCorpus -v
rm mls/seed_corpus_test.go
```

Then tell the validation plan's fuzz targets about the two directories: its `seedCorpus(f, kind)`
helper reads `interop/testdata/corpus/<kind>`, and `ratchet_tree` and `update_path` join the kinds
it already seeds. Nothing else in this plan declares an `f.Fuzz`.

The corpus is checked in, and the nightly differential job in Spec A §4.4 adds to it from interop
wire dumps. If a fuzz target finds a round-trip instability, the reproducing input lands in
`testdata/fuzz/` next to the target and is committed with the fix, exactly like any other regression
input — and it is added to this corpus, so the deterministic tests above catch a recurrence without
waiting for the fuzzer to rediscover it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestRatchetTreeDecodeIsRoundTripStable|TestUpdatePathDecodeIsRoundTripStable" -v`
Expected: PASS

Then the per-commit budget from Spec A §4.4, against the validation plan's targets now that they
have this corpus:

Run: `go test ./mls/ -fuzz FuzzRatchetTreeDecode -fuzztime 60s`
Expected: `elapsed: 60s ... no failures`

Run: `go test ./mls/ -fuzz FuzzUpdatePathDecode -fuzztime 60s`
Expected: `elapsed: 60s ... no failures`

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add mls/tree_roundtrip_test.go mls/interop/testdata/corpus
git commit -m "test(mls): seed corpus and round-trip stability net for the tree decoders"
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
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
    input, err := marshalBytes(func(w *syntax.Writer) error {
        w.WriteOpaque(node.EncryptionKey)
        w.WriteOpaque(node.ParentHash)
        w.WriteOpaque(siblingHash)
        return nil
    })
    if err != nil {
        return nil, err
    }
    return crypto.Hash(input), nil
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
        left, ok := leftOf(node)
        if !ok {
            return ErrTreeMalformed
        }
        right, ok := rightOf(node)
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

### Task 29: (moved out) The tree-operations vector family, family 9

**This task is not in this plan.** Family 9's vector supplies a serialized `Proposal`, which the
framing plan owns and the group lifecycle plan drives, so the runner moves to the group lifecycle
plan alongside families 8, 13, 14 and 15. It was this plan's only wave-4 dependency, and a family
whose owner cannot execute in the wave it needs is a family that never runs.

What this plan still owes it is the production surface it exercises — `AddLeaf`, `UpdateLeaf`,
`RemoveLeaf` (Task 15), `TreeHash` (Task 12), `RatchetTree`'s codec and `UnmarshalRatchetTree`
(Task 11) — all of which are green at Task 26. The runner there reads
`Proposal.Add.KeyPackage.LeafNode`, `Proposal.Update.LeafNode` and `Proposal.Remove.Removed` from
the framing plan's permissive `Proposal` shape, and registers family 9 through
`RegisterVectorFamily`.

The task body below is retained **only** as the reference the group lifecycle plan's runner is
written from, and its checkbox is not this plan's to tick.

<details>
<summary>Reference body, now owned by the group lifecycle plan</summary>

**Interfaces (as they land in the group lifecycle plan):**
- Consumes: `Proposal`, `ProposalTypeAdd`/`ProposalTypeUpdate`/`ProposalTypeRemove`, `Add`, `Update`, `Remove` (framing plan, wave 3); `KeyPackage` (Task 7A here); `AddLeaf`, `UpdateLeaf`, `RemoveLeaf` (Task 15 here); `TreeHash` (Task 12 here); `RatchetTree` codec and `UnmarshalRatchetTree` (Task 11 here); `LoadVectorFile`, `MustHex`, `HexOf`, `RegisterVectorFamily` (validation plan).
- Produces: `TestVectorTreeOperations` and the `init()` registering family 9.

Vector fields: `cipher_suite`, `tree_before`, `proposal`, `proposal_sender`, `tree_hash_before`,
`tree_after`, `tree_hash_after`.

Vector fields: `cipher_suite`, `tree_before`, `proposal`, `proposal_sender`, `tree_hash_before`,
`tree_after`, `tree_hash_after`.

```go
// mls/tree_operations_kat_test.go, in the group lifecycle plan

type treeOperationsVector struct {
    CipherSuite    uint16 `json:"cipher_suite"`
    TreeBefore     string `json:"tree_before"`
    Proposal       string `json:"proposal"`
    ProposalSender uint32 `json:"proposal_sender"`
    TreeHashBefore string `json:"tree_hash_before"`
    TreeAfter      string `json:"tree_after"`
    TreeHashAfter  string `json:"tree_hash_after"`
}

func init() {
    RegisterVectorFamily(VectorFamily{
        Number: 9,
        Name:   "tree-operations",
        File:   "tree-operations.json",
        Slice:  "A1",
        Verify: verifyTreeOperationsVector,
    })
}

func verifyTreeOperationsVector(t *testing.T, raw json.RawMessage) {
    t.Helper()
    var vector treeOperationsVector
    if err := json.Unmarshal(raw, &vector); err != nil {
        t.Fatalf("decode tree-operations entry: %v", err)
    }
    if CipherSuite(vector.CipherSuite) != CipherSuiteX25519ChaCha20Sha256Ed25519 {
        return
    }
    crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
    if err != nil {
        t.Fatalf("NewCryptoProvider: %v", err)
    }
    tree, err := UnmarshalRatchetTree(MustHex(t, vector.TreeBefore))
    if err != nil {
        t.Fatalf("UnmarshalRatchetTree: %v", err)
    }
    before, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    if !bytes.Equal(before, MustHex(t, vector.TreeHashBefore)) {
        t.Fatalf("tree_hash_before = %s, want %s", HexOf(before), vector.TreeHashBefore)
    }
    proposal := &Proposal{}
    if err := syntax.Unmarshal(MustHex(t, vector.Proposal), proposal); err != nil {
        t.Fatalf("Unmarshal(Proposal): %v", err)
    }
    switch proposal.ProposalType {
    case ProposalTypeAdd:
        if _, err := tree.AddLeaf(proposal.Add.KeyPackage.LeafNode.Clone()); err != nil {
            t.Fatalf("AddLeaf: %v", err)
        }
    case ProposalTypeUpdate:
        if err := tree.UpdateLeaf(LeafIndex(vector.ProposalSender),
            proposal.Update.LeafNode.Clone()); err != nil {
            t.Fatalf("UpdateLeaf: %v", err)
        }
    case ProposalTypeRemove:
        if err := tree.RemoveLeaf(proposal.Remove.Removed); err != nil {
            t.Fatalf("RemoveLeaf: %v", err)
        }
    default:
        t.Fatalf("proposal type %#x is outside what tree operations covers", proposal.ProposalType)
    }
    encoded, err := syntax.Marshal(tree)
    if err != nil {
        t.Fatalf("Marshal: %v", err)
    }
    if !bytes.Equal(encoded, MustHex(t, vector.TreeAfter)) {
        t.Fatalf("tree_after differs")
    }
    after, err := tree.TreeHash(crypto)
    if err != nil {
        t.Fatalf("TreeHash: %v", err)
    }
    if !bytes.Equal(after, MustHex(t, vector.TreeHashAfter)) {
        t.Fatalf("tree_hash_after = %s, want %s", HexOf(after), vector.TreeHashAfter)
    }
}

func TestVectorTreeOperations(t *testing.T) {
    for i, raw := range LoadVectorFile(t, "tree-operations.json") {
        raw := raw
        t.Run(fmt.Sprintf("vector-%d", i), func(t *testing.T) {
            verifyTreeOperationsVector(t, raw)
        })
    }
}
```

The two failures with a wrong fix available, both of which land in **this** plan's code:

- `tree_after` differing only in trailing bytes means `RatchetTree.MarshalMLS` is not stripping
  trailing blanks, or `RemoveLeaf`/`truncate` is not shrinking. Fix the operation, never the
  comparison.
- `tree_after` differing at a parent node after an Add means `AddLeaf` blanked the direct path
  instead of appending to `unmerged_leaves`.

</details>

---

## Execution order and gates

Tasks 1 through 26 are strictly sequential: each depends on the one before it, and **Task 3 is this
plan's wave-2 entry point**, ahead of the key schedule plan's Task 3. Tasks 27 and 28 depend only on
Task 26.

| Gate | Green after |
|---|---|
| `tree-validation` (vector family 10) | Task 24 |
| `treekem` (vector family 11), both directions | Task 25 |
| Spec A Gate 3, the tree-owned rows 202, 203, 204, 206, 207, 300 — asserted by the validation plan's `TestValSemNNN_*` against this plan's `CheckUpdatePathKeyUniqueness`, `MergeUpdatePath`, `DecryptUpdatePath` and `UnmarshalRatchetTree` | Task 26 |
| Spec A Gate 3, erratum 8745 | Task 7 |
| Spec A Gate 4 properties 1 and 2, tree decoders — the validation plan's `FuzzRatchetTreeDecode` and `FuzzUpdatePathDecode` over this plan's seed corpus | Task 27 |
| `tree-operations` (vector family 9) | the group lifecycle plan, once the framing plan's `Proposal` lands |

## What this plan does not own

Named here so no other plan waits on it:

- `key_package.go`, `proposal.go`, `commit.go`, `group.go`, `welcome` — Group lifecycle plan. The
  500-member and 10-device caps, the removal-authority rule and owner succession are all commit-level
  and live there, not in the tree.
- `Proposal`, `ProposalOrRef` and `Commit` and their codecs — Framing plan. This plan declares none
  of them; it declares only the `ProposalType` enum they are keyed on (Task 3). Refusing a proposal
  type is a *profile* decision, taken by `(*Profile).CheckProposalType` in the validation plan, not
  a codec decision taken here.
- `Welcome`, `GroupInfo`, `GroupSecrets` and their codecs — Framing plan. This plan produces
  `HpkeCiphertext` and `SealWithLabel`/`OpenWithLabel`, which is everything they need from here.
- `Profile`, `DefaultProfile` and the seven `Check*` — Validation plan. This plan consumes
  `CheckCredentialType`; the codec-layer BasicCredential-only refusal in Task 4A is a floor beneath
  it, not a duplicate of it.
- `errors.go`, every `ValSemNNN` sentinel, every `ErrProfile*`, and every `TestValSemNNN_*` test
  name — Validation plan. This plan raises those errors and never declares them.
- The vector registry (`RegisterVectorFamily`, `LoadVectorFile`, `MustHex`, `HexOf`), the vendoring
  of all sixteen mlswg files, `testdata/vectors/VECTORS.sha256` and the one pin file at
  `mls/interop/PINS.md` — Validation plan. This plan defines no hex decoder, no vector loader and no
  pin file; it registers families 10 and 11 and reads the two files it needs.
- All nine Gate-4 `Fuzz*` targets — Validation plan. This plan contributes the two seed corpora and
  the deterministic round-trip regression tests over them (Task 27).
- Vector family 9, `tree-operations` — Group lifecycle plan (see the moved Task 29).
- `group.go`, `commit.go`, `welcome.go`, `succession.go`, the proposal cache, the ValSem 100- and
  200-series checks — Group lifecycle plan. The 500-member and 10-device caps, the removal-authority
  rule and owner succession are all commit-level and live there, not in the tree.
- `GroupContext` and its codec — Key schedule and secret tree plan. This plan takes the serialized
  group context as `[]byte` everywhere except `ValidateAgainstContext`, which is the one place a
  `*GroupContext` is needed and the only source of a compile dependency on that plan.
- Erratum 8815 (§12.2, proposal references in a Commit), and `CheckErrata8745` — Group lifecycle
  plan. This plan implements erratum 8745's *substance* inside `LeafNode.Validate` (Task 7); the
  commit-level `CheckErrata8745(path, context)` entry point is that plan's.
- The mlswg gRPC interop client — Validation plan. It drives this package through `mls.Group`, so
  nothing here is exported for its benefit.


---

## Amendment A — record of the reconciliation against the canonical interface registry

This plan and the other seven were written in parallel, and the registry is the file that settled
every symbol crossing a boundary between them. **Everything below is already folded into the task
bodies above** — there is no rewrite rule left to apply, and no task body calls a signature the
registry does not contain. This section exists so a reviewer can see what moved and why, not so an
implementer has to patch anything.

### A.1 Where the registry overrode this plan

| This plan had | The registry says | Folded into |
|---|---|---|
| `MarshalTo(w) error` + `UnmarshalX(r)` + `Marshal()` + `ParseX(data)` | `MarshalMLS(w) error` / `UnmarshalMLS(r) error` only, with `syntax.Marshal` / `syntax.Unmarshal` for bytes (**C1**) | every codec task: 3, 4, 4A, 5, 7A, 8, 11, 19 |
| `MarshalExtensions(exts) ([]byte, error)` / `UnmarshalExtensions(r)` | `WriteExtensions(w, exts) error` / `ReadExtensions(r) ([]Extension, error)` | Task 3 |
| `(*LeafKeysExtension).Marshal` / `UnmarshalLeafKeysExtension` | `Encode() (Extension, error)` / `ParseLeafKeysExtension(data)` — the sanctioned extension-body exception to C1 | Task 4 |
| `(*RatchetTree).LeafWidth() uint32` | `LeafWidth() LeafCount` (**C3**) | Tasks 8, 11, 15, 16, 23 |
| `UnmarshalRatchetTree` with a hand-rolled length check | `syntax.UnmarshalLimit(data, tree, syntax.MaxRatchetTreeLength)` | Task 11 |
| `(*RatchetTree).CheckUpdatePathKeyUniqueness(sender, path)` | free `CheckUpdatePathKeyUniqueness(tree, path)`, no `sender` | Task 26 |
| `ProtocolVersionMLS10`, `CipherSuiteX25519ChaCha20SHA256Ed25519` | `ProtocolVersionMls10`, `CipherSuiteX25519ChaCha20Sha256Ed25519` — `CODESTYLE.md`, no all-caps initialisms | everywhere |
| `Resolution` implemented here | the tree math plan's `Resolution(shape, x)`; this plan supplies `NodeShape` and keeps a one-line convenience method | Tasks 8, 10 |
| a private `pathChildren` helper | the tree math plan's `FilteredDirectPath(shape, leaf) ([]PathStep, error)`, whose `PathStep.CopathChild` is the same fact derived once | Tasks 16, 18, 21, 22 |

### A.2 The tree-math shims that survive, and why

The tree math plan returns an error from every arithmetic that can be out of range. Inside a
`RatchetTree` the leaf width is at least one and every node index this package forms is already in
range, so `mls/tree_adapt.go` (Task 3) keeps five private shims — `leftOf`, `rightOf`, `leafIndexOf`,
`rootOf`, `directPathOf` — that restore the `(value, ok)` shape at those call sites. **They are
internal to this plan.** No other plan gets them, and no exported surface exposes them: a shim that
turns an error into `false` somewhere without that width invariant is exactly how a malformed tree
gets silently accepted. `rootOf` and `directPathOf` keep the error for the same reason.

`nodeWidthOf` and `siblingOf` are gone: with `LeafWidth()` returning `LeafCount`, `NodeWidth(n)` and
`Sibling(x, n)` take the value directly and the conversion wrapper has nothing left to do.

### A.3 Symbols that moved in, and symbols that moved out

**In** — gaps the registry assigned here because they are this plan's own types or thin reads of
them, with the task that now produces each:

| Symbol | Task |
|---|---|
| `KeyPackage`, `NewKeyPackage`, `Ref`, `Validate`, codec | 7A |
| `Credential`, `BasicCredential` | 4A |
| `NewLeafNode` | 6 |
| `(*Capabilities).Supports(rc)` | 3 |
| `NonBlankLeaves`, `EncryptionKeyInUse`, `HasTrailingBlankNodes`, `OptionalNode` | 8, 11 |
| `SealWithLabel`, `OpenWithLabel` | 19 |
| the eight `ProposalType` constants and `ExtensionTypeExternalSenders` | 3 |
| the three `NodeShape` methods | 8 |

**Out** — things this plan used to carry that belong elsewhere:

- vendoring, `PINS.md`, `treeVectorFile`, `treeHex`, `TestTreeVectorsArePinned` → validation plan
  (Task 1 keeps only the runner file and calls `LoadVectorFile`/`MustHex`/`HexOf`);
- `FuzzRatchetTreeDecode`, `FuzzUpdatePathDecode` → validation plan, which owns all nine Gate-4
  targets; Task 27 contributes the seed corpus and a deterministic regression net over it;
- vector family 9, `tree-operations` → group lifecycle plan (Task 29 is a reference body only);
- `Proposal`/`ProposalKind`/`ParseProposal`, which this plan consumed from a wave-4 file that never
  existed → the framing plan's `Proposal` with `ProposalType`, `Add.KeyPackage`, `Update.LeafNode`
  and `Remove.Removed`.

### A.4 The ValSem-named tests belong to the validation plan

That plan owns Gate 3 and declares, by name, `TestValSem202_PathLength`,
`TestValSem203_PathDecrypt`, `TestValSem204_PathKeyMismatch`,
`TestValSem206_PathLeafDuplicateEncryptionKey`, `TestValSem207_PathNodeDuplicateEncryptionKey` and
`TestValSem300_TrailingBlankNodes`. Two test functions of one name in one Go package do not compile,
so the tests here are named for the behaviour instead — already applied in Tasks 11, 21, 22 and 26:

| Task | This plan's name | The validation plan's name it must not collide with |
|---|---|---|
| 11 | `TestRatchetTreeRefusesTrailingBlankNodes` | `TestValSem300_TrailingBlankNodes` |
| 21 | `TestMergeUpdatePathRejectsAWrongLengthPath` | `TestValSem202_PathLength` |
| 22 | `TestDecryptUpdatePathRejectsATamperedCiphertext` | `TestValSem203_PathDecrypt` |
| 22 | `TestDecryptUpdatePathRejectsAnAnnouncedKeyMismatch` | `TestValSem204_PathKeyMismatch` |
| 26 | `TestUpdatePathLeafKeyUniqueness` | `TestValSem206_PathLeafDuplicateEncryptionKey` |
| 26 | `TestUpdatePathNodeKeyUniqueness` | `TestValSem207_PathNodeDuplicateEncryptionKey` |

`TestTreeValSemCoverage` is gone with them: ValSem coverage is asserted once, in the validation
plan, and asserting it twice against two name lists is how the two lists drift apart. What this plan
keeps is the production surface those tests drive — `CheckUpdatePathKeyUniqueness`,
`MergeUpdatePath`, `DecryptUpdatePath`, `UnmarshalRatchetTree`.

