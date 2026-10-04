# Framing and Message Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 9420 §6 message framing in `connect/mls` — `FramedContent`,
`AuthenticatedContent`, `PublicMessage` and `PrivateMessage`, with byte-exact signature preimages,
membership tags, sender-data encryption, AAD construction and padding — and pass the
`message-protection` and `messages` test-vector families in both directions.

**Architecture:** Framing is a pure, stateless layer between the TLS-presentation codec
(`connect/mls/syntax`) and the group state machine (`group.go`). Every authenticated byte string is
produced by exactly one function that takes already-serialized inputs (the GroupContext arrives as
bytes, not as a struct), so a preimage cannot be assembled two different ways in two different call
sites. Sealing and opening are split into a sign step and a seal step, because a commit's
`confirmation_tag` must exist before the membership tag covers it; every `Open*` function takes a
`SignatureKeyResolver` so signature verification cannot be forgotten by a caller.

**Tech Stack:** Go 1.26.5, `package mls` (`github.com/urnetwork/connect/mls`), `connect/mls/syntax`
for all wire encoding, standard library crypto only via the `CryptoProvider` interface.

## Global Constraints

- Go 1.26.5, pinned. Per registry override O-3 the `go` directive in `connect/go.mod` stays at
  `1.26.3` and the wave-1 codec plan adds `toolchain go1.26.5`; raising the directive would raise
  the language floor for all of `connect`. This plan assumes that edit has already landed.
- Standard library only for crypto: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, plus
  `chacha20poly1305` from the already-pinned `golang.org/x/crypto`. NO cgo, NO Rust, NO new
  third-party crypto dependency. New dependencies permitted in `connect` on `beta/message`: **none.**
- `sdk` must stay gomobile-buildable. Everything here builds for `windows/{amd64,arm64}`,
  `linux/{amd64,arm64}`, `darwin/arm64`, `android/{arm64,arm,amd64}`, `ios/arm64`.
- OpenMLS (Rust) is a READ-ONLY differential oracle used out of process in CI. Never in `go.mod`,
  never linked, never in a shipped artifact.
- Ciphersuite: exactly `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003) for v1 groups.
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) is registered and implemented but refused
  at group creation by policy. Framing code MUST read `KDF.Nh`, `AEAD.Nk` and `AEAD.Nn` from
  `CryptoProvider`, never from a constant, so the second suite passes the same vectors.
- Narrow v1 profile: BasicCredential only, no external commits, no external senders, no PSKs, no
  ReInit, no branching, no subgroups. All parse-refused with typed errors — **at the profile gate,
  not at the codec.** See "The codec/profile split" below.
- `connect` (the parent package) must NEVER import `connect/mls` or `connect/message`.
  `connect/mls` must never import `connect` or `connect/message`. `connect/mls/syntax` imports
  nothing but stdlib. Enforced by `connect/layering_test.go` (wave-1 plan).
- `sdk.GenerateSharedSecret`, `box.Precompute` and `curve25519.ScalarMult` MUST NOT be used. All
  X25519 goes through `crypto/ecdh` or `curve25519.X25519`, and a returned error is a hard
  validation failure — never logged and continued. No framing code performs key agreement directly;
  it all goes through `CryptoProvider`.
- MLS signs over serialized forms, so the codec must be byte-exact and round-trip stable. One codec,
  one fuzz corpus: every byte this plan emits goes through `connect/mls/syntax`.
- Guardrail G7 (Spec A §5.9): a signature or MAC mismatch MUST return an error. No verification
  helper in this plan returns `bool`.
- Guardrail G8 (Spec A §5.9): every tag comparison goes through `crypto/subtle.ConstantTimeCompare`
  or `CryptoProvider.MacVerify`. `bytes.Equal` is forbidden in `framing.go` and
  `framing_protect.go`; Task 19 enforces it with a test rather than a shell grep.
- Padding: `PaddingSizeV1 = 0`. `connect/message` pads `ct_body` to a size bucket
  (`octet_length(ct_body) MUST equal size_bucket_bytes[b] + 16 exactly`, MASTER §8), so MLS-level
  padding would be padding inside padding. The decoder still accepts any all-zero padding length,
  because peers in the interop harness emit non-zero padding.
- **Windows git hazard (project memory):** the git index vanishes on this box. Every commit step
  runs `git ls-files | wc -l` first and compares against the previous count, or the commit silently
  truncates the tree.
- Repo root for every command in this plan: `C:\Users\ryanm\Downloads\claude_sandbox_message\connect`,
  branch `beta/message`. Test commands are written from the workspace root
  (`C:\Users\ryanm\Downloads\claude_sandbox_message`) in the house form `go test ./connect/mls/...`.

### The four cross-plan conventions (canonical interface registry §0, verbatim)

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

`ParseMLSMessage`/`MarshalMLSMessage` (§7.2) are the one sanctioned pair of byte-level free
functions outside p8's table, because `ParseMLSMessage` is the single entry point every byte off
the wire passes through and the whole system names it.

**C2 — the syntax Writer is sticky *and* `MarshalMLS` returns an error** (registry override O-1).
Leaf writes (`WriteUint16`, `WriteOpaque`, `WriteRaw`, …) return nothing and route buffer failures
into the Writer's sticky error, checked once at `Bytes() ([]byte, error)`. The `error` return on
`MarshalMLS` carries **semantic** refusals the sticky Writer cannot express —
`FramedContent.MarshalMLS` returning `ErrContentArmMismatch` is the example this plan contributes.
Higher-order encode callbacks (`syntax.WriteVector`, `(*Writer).WriteOptional`) return `error` for
the same reason.

**C3 — counts are `LeafCount`, indices are `LeafIndex`/`NodeIndex`, and tree-math arithmetic that
can be out of range returns an error.** p3's block is normative for every caller. `TreeSize` does
not exist.

**C4 — the GroupContext crosses a plan boundary as bytes.** Every entry point in this plan takes
`groupContext []byte`. Callers obtain them from `syntax.Marshal(gc)` or `(*Group).GroupContext()`.
This is this plan's decision and the registry upholds it: the GroupContext is inlined into
`FramedContentTBS` with no length prefix, and taking bytes makes that impossible to get wrong.

### The codec/profile split (settled by registry §7.4, carried by every task below)

Spec A §3.2 says PSK proposals are refused with `ErrProfilePsk` "at proposal parse". The `messages`
vector family requires `pre_shared_key_proposal`, `re_init_proposal` and `external_init_proposal` to
**decode successfully and re-encode byte-exactly**. Both cannot be true of one function.

Resolution:

- `Proposal.UnmarshalMLS` / `MarshalMLS` (this plan, `proposal_wire.go`) are **pure codec**. They
  accept all seven registered proposal types and any unknown 16-bit type as an opaque body. They
  never consult the profile.
- The profile gate is `func (self *Profile) CheckProposalType(t ProposalType) error`, owned by p8
  (§9.3) and called by p7 at the parse boundary, where `ErrProfilePsk`, `ErrProfileReInit` and
  `ErrProfileExternalCommit` surface. ValSem401–403 test that function, not the codec.
- Nothing outside `proposal_wire.go` and the vector harness calls the codec directly; p7's
  lifecycle code goes through the profile gate first.

---

## File Structure

| File | Single responsibility |
|---|---|
| `connect/mls/framing.go` | RFC 9420 §6 wire types and their codecs: `WireFormat`, `ContentType`, `SenderType`, `Sender`, `FramedContent`, `FramedContentAuthData`, `AuthenticatedContent`, `PublicMessage`, `PrivateMessage`, `SenderData`, `MLSMessage`. No crypto. |
| `connect/mls/framing_preimage.go` | The authenticated byte strings and nothing else: `FramedContentTBSBytes`, `AuthenticatedContentTBMBytes`, `(*AuthenticatedContent).ConfirmedTranscriptHashInput`, `(*AuthenticatedContent).ProposalRef`, and the two AADs. Isolated so a preimage change is a one-file diff an auditor can read. |
| `connect/mls/framing_protect.go` | Sign/verify, membership tag, sender-data seal/open, `PrivateMessageContent` with padding, content encrypt/decrypt, the `MessageKeySource` and `SignatureKeyResolver` contracts, and the four `Seal*`/`Open*` entry points. |
| `connect/mls/framing_errors.go` | The ten **structural** framing errors of registry §7.6. The ten ValSem002–011 sentinels are **not** here — they are p8's `errors.go` (§9.1), wave 1. |
| `connect/mls/framing_group_seams.go` | `sealFramedContentForTest` and `sealFramedContentWithPaddingForTest` — the two unexported construction-bypass seams p8's ValSem002–011 tests drive (registry §7.3, gap assigned here). |
| `connect/mls/proposal_wire.go` | `Proposal` and its seven arms, `ProposalOrRefType`, `ProposalRef`, `ProposalOrRef` — codec only, no validation. `ProposalType` and its constants are p5's. |
| `connect/mls/commit_wire.go` | `Commit` — codec only, no application logic. |
| `connect/mls/welcome_wire.go` | `GroupInfo`, `GroupInfoTBS`, `PathSecret`, `GroupSecrets`, `EncryptedGroupSecrets`, `Welcome` — **codecs only** (registry §7.5); generation and processing stay in p7. |
| `connect/mls/framing_test.go` | Unit tests for `framing.go` and `framing_preimage.go`. |
| `connect/mls/framing_protect_test.go` | Unit tests for `framing_protect.go`, including the fixed-key `MessageKeySource` stub. |
| `connect/mls/proposal_wire_test.go` | Round-trip and width tests for the proposal codec. |
| `connect/mls/commit_wire_test.go` | Round-trip tests for the commit codec. |
| `connect/mls/welcome_wire_test.go` | Round-trip tests for the Welcome/GroupInfo/GroupSecrets codecs. |
| `connect/mls/validation_framing_test.go` | One behaviour-named test per framing refusal, plus the sentinel-coverage roster test. |
| `connect/mls/message_protection_kat_test.go` | Vector family 4, verify direction and generate direction, registered through `RegisterVectorFamily`. |
| `connect/mls/messages_kat_test.go` | Vector family 12, decode/re-encode for every field, registered the same way. |
| `connect/mls/framing_guard_test.go` | `TestFramingUsesConstantTimeComparison` (Spec A §5.9 G8) and the seed-corpus contribution for p8's fuzz targets. |
| `connect/mls/testdata/vectors/message-protection.json` | Vendored and pinned by p8 Task 6, the single vendoring task; this plan asserts the file is present. |
| `connect/mls/testdata/vectors/messages.json` | Same. |

**Deviation from Spec A §2.2, stated deliberately:** Spec A lists `framing.go` as one file and puts
`Proposal`/`Commit` in `proposal.go`/`commit.go`. This plan splits framing across four files
(types / preimages / protection / errors) and puts the proposal, commit and welcome **wire types**
in `proposal_wire.go`, `commit_wire.go` and `welcome_wire.go`, leaving `proposal.go` (list
validation), `commit.go` (commit application) and `welcome.go` (welcome generation and join)
entirely to the wave-4 plan. Reason: the `messages` gate is this plan's and cannot be green without
byte-exact `Proposal`, `Commit`, `Welcome` and `GroupInfo` codecs, and `MLSMessage` — a wave-3
struct — names `*Welcome`, `*GroupInfo` and `*KeyPackage` by direct type, so those types cannot land
in wave 4 without making wave 3 uncompilable. All files are `package mls`, so there is no import
edge and no cycle.

**No `vectors_hex_test.go` and no `hexBytes`.** Registry §9.2 gives `MustHex`, `HexOf` and
`LoadVectorFile` to p8, wave 1. Three parallel hex decoders over one corpus is how two of them end
up disagreeing about the empty string.

**No fuzz targets here.** Registry §9.5 gives all nine Gate-4 targets to p8, which owns the codec
table and the oracle hook. This plan keeps the G8 constant-time gate and contributes seed corpus.

---

## Interfaces consumed from other plans

Every signature below is copied verbatim from the canonical interface registry. Every symbol is
`package mls` unless a package is named. If an implementation disagrees with a signature here, fix
the implementation — do not add an adapter layer.

**From p1, "Syntax and codec" (wave 1), package `github.com/urnetwork/connect/mls/syntax`:**

```go
const MaxVectorLength int = 1 << 20       // 1 MiB, every field but the tree

var ErrTruncated error            // input ended before the value did
var ErrTrailingBytes error        // a top-level decode left bytes unconsumed
var ErrVarintNotMinimal error     // more octets than the value needs
var ErrOptionalPresence error     // presence octet neither 0 nor 1

type Writer struct{ ... }                        // not safe for concurrent use
func NewWriter() *Writer
func (self *Writer) Bytes() ([]byte, error)      // undefined when err non-nil
func (self *Writer) Err() error
func (self *Writer) Len() int
func (self *Writer) WriteUint8(v uint8)
func (self *Writer) WriteUint16(v uint16)
func (self *Writer) WriteUint32(v uint32)
func (self *Writer) WriteUint64(v uint64)
func (self *Writer) WriteRaw(bs []byte)          // opaque x[N], no prefix
func (self *Writer) WriteOpaque(bs []byte)       // opaque x<V>; nil == empty
func (self *Writer) WriteOptional(present bool, encodeOne func(w *Writer) error) error

type Reader struct{ ... }                                    // not safe for concurrent use
func NewReader(bs []byte) *Reader
func (self *Reader) Remaining() int
func (self *Reader) Empty() bool
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
func CheckRoundTrip[T any, PT interface {
	*T
	Codec
}](bs []byte) error
```

The length prefix on a vector counts **bytes, not elements**; `ReadVector` runs `decodeOne` against
a sub-reader until that sub-reader is empty. `WriteVector`/`ReadVector` are free generics over a
typed slice, not methods on `Writer`/`Reader`. `Finish()` is `Done()`. There is no `Rest()`: a
decoder that wants the tail writes `r.ReadRaw(r.Remaining())`, which is explicit about consuming it.
There is no `Bytes() []byte`: take the error.

**From p2, "Crypto primitives and HPKE" (wave 1):**

```go
type CipherSuite uint16
const CipherSuiteX25519ChaCha20Sha256Ed25519 CipherSuite = 0x0003

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
func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte

var ErrAeadOpen = errors.New("mls: aead open failed")
```

Used here: `HashSize`, `KeySize`, `NonceSize`, `Mac`, `MacVerify`, `ExpandWithLabel`, `AeadSeal`,
`AeadOpen`, `SignWithLabel`, `VerifyWithLabel`, `Random`, `SignatureKeyPair`. The suite constant is
`CipherSuiteX25519ChaCha20Sha256Ed25519` — `Sha`, not `SHA`, per `CODESTYLE.md`, and the producer
wins on the spelling.

**From p3, "Tree math" (wave 1):**

```go
type LeafIndex uint32
type LeafCount uint32
```

**From p4, "Key schedule and secret tree" (wave 2):**

```go
type GroupContext struct {
    Version                 ProtocolVersion
    CipherSuite             CipherSuite
    GroupId                 []byte
    Epoch                   uint64
    TreeHash                []byte
    ConfirmedTranscriptHash []byte
    Extensions              []Extension
}
func (self *GroupContext) MarshalMLS(w *syntax.Writer) error
func (self *GroupContext) UnmarshalMLS(r *syntax.Reader) error

type PreSharedKeyId struct {
    PskType    PskType
    PskId      []byte
    Usage      ResumptionPskUsage
    PskGroupId []byte
    PskEpoch   uint64
    PskNonce   []byte
}
func (self *PreSharedKeyId) MarshalMLS(w *syntax.Writer) error
func (self *PreSharedKeyId) UnmarshalMLS(r *syntax.Reader) error

type KeySchedule struct{ /* unexported */ }
type EpochSecrets struct {
    SenderData         []byte
    Encryption         []byte
    Exporter           []byte
    External           []byte
    Confirmation       []byte
    Membership         []byte
    ResumptionPsk      []byte
    EpochAuthenticator []byte
    InitSecret         []byte
}
func (self *KeySchedule) Secrets() *EpochSecrets

type SecretTree struct{ /* unexported, guarded by stateLock */ }
func NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error)

// p4 implements the MessageKeySource interface this plan declares (Task 11)
func (self *SecretTree) NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
func (self *SecretTree) MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
func (self *SecretTree) EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)

func SenderDataKeyNonce(crypto CryptoProvider, senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error)
```

`ContentTypeApplication` selects the application ratchet; `ContentTypeProposal` and
`ContentTypeCommit` select the handshake ratchet. The secret tree owns the skipped-key window.
**`SenderDataKeyNonce` is p4's, exported, and returns an error** — registry §5.5: two
implementations of one §6.3.2 derivation, only one of which is vector-tested, is precisely how the
`ciphertext_sample` short-ciphertext trap gets got wrong. This plan's own unexported
`senderDataKeyNonce` is deleted and its two short-ciphertext tests become regression tests against
p4's implementation.

**From p5, "Registry enums, extensions, tree, TreeKEM" (wave 2):**

```go
type ProtocolVersion uint16
const ProtocolVersionMls10 ProtocolVersion = 0x0001

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
type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}
func (self *Extension) MarshalMLS(w *syntax.Writer) error
func (self *Extension) UnmarshalMLS(r *syntax.Reader) error
func WriteExtensions(w *syntax.Writer, exts []Extension) error
func ReadExtensions(r *syntax.Reader) ([]Extension, error)

type LeafNode struct{ ... }
func (self *LeafNode) MarshalMLS(w *syntax.Writer) error
func (self *LeafNode) UnmarshalMLS(r *syntax.Reader) error

type KeyPackage struct{ ... }
func (self *KeyPackage) MarshalMLS(w *syntax.Writer) error
func (self *KeyPackage) UnmarshalMLS(r *syntax.Reader) error
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error)

type HpkeCiphertext struct {
    KemOutput  []byte
    Ciphertext []byte
}
func (self *HpkeCiphertext) MarshalMLS(w *syntax.Writer) error
func (self *HpkeCiphertext) UnmarshalMLS(r *syntax.Reader) error

type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode
}
func (self *UpdatePath) MarshalMLS(w *syntax.Writer) error
func (self *UpdatePath) UnmarshalMLS(r *syntax.Reader) error

type RatchetTree struct{ /* opaque: nodes []*Node */ }
func (self *RatchetTree) MarshalMLS(w *syntax.Writer) error
func (self *RatchetTree) UnmarshalMLS(r *syntax.Reader) error
func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)   // UnmarshalLimit(MaxRatchetTreeLength)
```

**`ProtocolVersion`, `ProtocolVersionMls10`, `ProposalType` and its eight constants are p5's, not
this plan's** (registry §6.1 and §11). Three plans declared `ProposalType` and two declared
`ProtocolVersion`; `package mls` is one package, so that is a redeclaration compile error. The
registry enums go to p5 — the earliest wave that needs them for `Capabilities` — and the wire
structs that use them stay here. `ProtocolVersionMLS10` becomes `ProtocolVersionMls10`.

**`MarshalExtensions`/`unmarshalExtensions` do not exist.** Registry override O-4 renames the
extension-vector codec to `WriteExtensions(w, exts) error` / `ReadExtensions(r) ([]Extension, error)`
and puts it in p5. This plan's private `marshalExtensions`/`unmarshalExtensions` helpers are deleted
and every call site uses p5's pair.

**From p7, "Group lifecycle" (wave 4) — Task 20 only:**

```go
type Group struct{ /* stateLock-guarded, not safe for concurrent use */ }
func (self *Group) GroupContext() ([]byte, error)
```

**From p8, "Validation, profile, harness" (wave 1):**

```go
type ValSemCode uint16
func ValSem(code ValSemCode, detail error) error
// codes named here: ValSem002 … ValSem011

// the ten framing sentinels — p8's errors.go is their single declaration site
var ErrWrongGroupId, ErrWrongEpoch, ErrBlankSenderLeaf error
var ErrApplicationMustBeCiphertext, ErrDecryptFailed error
var ErrMissingMembershipTag, ErrBadMembershipTag error
var ErrMissingConfirmationTag, ErrBadSignature, ErrNonZeroPadding error

type Profile struct{ ... }
func (self *Profile) CheckProposalType(t ProposalType) error   // p7 calls it at the parse boundary

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
func MustHex(t *testing.T, s string) []byte
func HexOf(b []byte) string
```

**The ten ValSem002–011 sentinels are p8's, not this plan's** (registry §7.6 and §9.1). They are
wave 1 and therefore already available when this plan starts. `ErrBadSignature` in particular is
declared three times across the eight plans; p8 keeps it because it is ValSem010 and Gate 3 asserts
it, and p2's crypto-layer error is renamed `ErrCryptoBadSignature`. Every refusal in this plan
returns `ValSem(ValSemNNN, ErrX)`, so `CodeOf` finds the code and `errors.Is` still finds the
sentinel through `(*ValidationError).Unwrap`.

**GroupContext crosses as bytes (C4).** Every entry point in this plan takes `groupContext []byte`.
Callers build them with `syntax.Marshal(gc)` over p4's `*GroupContext`, or take them from
`(*Group).GroupContext()`. The GroupContext is inlined into `FramedContentTBS` with **no length
prefix**, and taking bytes makes that impossible to get wrong by accident.

---

## Interfaces produced for other plans

```go
// framing.go
type WireFormat uint16
const (
    WireFormatReserved       WireFormat = 0x0000
    WireFormatPublicMessage  WireFormat = 0x0001
    WireFormatPrivateMessage WireFormat = 0x0002
    WireFormatWelcome        WireFormat = 0x0003
    WireFormatGroupInfo      WireFormat = 0x0004
    WireFormatKeyPackage     WireFormat = 0x0005
)

type ContentType uint8
const (
    ContentTypeReserved    ContentType = 0
    ContentTypeApplication ContentType = 1
    ContentTypeProposal    ContentType = 2
    ContentTypeCommit      ContentType = 3
)

type SenderType uint8
const (
    SenderTypeReserved          SenderType = 0
    SenderTypeMember            SenderType = 1
    SenderTypeExternal          SenderType = 2
    SenderTypeNewMemberProposal SenderType = 3
    SenderTypeNewMemberCommit   SenderType = 4
)

type Sender struct {
    SenderType  SenderType
    LeafIndex   LeafIndex
    SenderIndex uint32
}
func (self *Sender) MarshalMLS(w *syntax.Writer) error
func (self *Sender) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*Sender)(nil)

type FramedContent struct {
    GroupId           []byte
    Epoch             uint64
    Sender            Sender
    AuthenticatedData []byte
    ContentType       ContentType
    ApplicationData   []byte
    Proposal          *Proposal
    Commit            *Commit
}
func (self *FramedContent) MarshalMLS(w *syntax.Writer) error
func (self *FramedContent) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*FramedContent)(nil)

// the one sanctioned departure from C1's exact method set: FramedContentAuthData
// is a select() on the enclosing FramedContent.content_type and carries no
// discriminant of its own, so the content type is a parameter and this type is
// deliberately not a syntax.Codec.
type FramedContentAuthData struct {
    Signature       []byte
    ConfirmationTag []byte
}
func (self *FramedContentAuthData) MarshalMLS(w *syntax.Writer, contentType ContentType) error
func (self *FramedContentAuthData) UnmarshalMLS(r *syntax.Reader, contentType ContentType) error

type AuthenticatedContent struct {
    WireFormat WireFormat
    Content    FramedContent
    Auth       FramedContentAuthData
}
func (self *AuthenticatedContent) MarshalMLS(w *syntax.Writer) error
func (self *AuthenticatedContent) UnmarshalMLS(r *syntax.Reader) error
func (self *AuthenticatedContent) ConfirmedTranscriptHashInput() ([]byte, error)
func (self *AuthenticatedContent) ProposalRef(crypto CryptoProvider) (ProposalRef, error)
var _ syntax.Codec = (*AuthenticatedContent)(nil)

type PublicMessage struct {
    Content       FramedContent
    Auth          FramedContentAuthData
    MembershipTag []byte
}
func (self *PublicMessage) MarshalMLS(w *syntax.Writer) error
func (self *PublicMessage) UnmarshalMLS(r *syntax.Reader) error
func (self *PublicMessage) AuthenticatedContent() *AuthenticatedContent
var _ syntax.Codec = (*PublicMessage)(nil)

type PrivateMessage struct {
    GroupId             []byte
    Epoch               uint64
    ContentType         ContentType
    AuthenticatedData   []byte
    EncryptedSenderData []byte
    Ciphertext          []byte
}
func (self *PrivateMessage) MarshalMLS(w *syntax.Writer) error
func (self *PrivateMessage) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*PrivateMessage)(nil)

type SenderData struct {
    LeafIndex  LeafIndex
    Generation uint32
    ReuseGuard [4]byte
}
func (self *SenderData) MarshalMLS(w *syntax.Writer) error
func (self *SenderData) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*SenderData)(nil)

type MLSMessage struct {
    Version        ProtocolVersion
    WireFormat     WireFormat
    PublicMessage  *PublicMessage
    PrivateMessage *PrivateMessage
    Welcome        *Welcome
    GroupInfo      *GroupInfo
    KeyPackage     *KeyPackage
}
func (self *MLSMessage) MarshalMLS(w *syntax.Writer) error
func (self *MLSMessage) UnmarshalMLS(r *syntax.Reader) error
func MarshalMLSMessage(message *MLSMessage) ([]byte, error)
func ParseMLSMessage(data []byte) (*MLSMessage, error)
var _ syntax.Codec = (*MLSMessage)(nil)

// framing_preimage.go
func FramedContentTBSBytes(wireFormat WireFormat, content *FramedContent, groupContext []byte) ([]byte, error)
func AuthenticatedContentTBMBytes(authContent *AuthenticatedContent, groupContext []byte) ([]byte, error)

// framing_protect.go
type MessageKeySource interface {                    // implemented by p4's *SecretTree
    NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
    MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
    EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
}
var _ MessageKeySource = (*SecretTree)(nil)

type SignatureKeyResolver func(sender Sender) (SignaturePublicKey, error)
func StaticSignatureKey(pub SignaturePublicKey) SignatureKeyResolver

const PaddingSizeV1 = 0

func SignAuthenticatedContent(crypto CryptoProvider, priv SignaturePrivateKey,
    wireFormat WireFormat, content *FramedContent, groupContext []byte) (*AuthenticatedContent, error)
func VerifyAuthenticatedContent(crypto CryptoProvider, pub SignaturePublicKey,
    authContent *AuthenticatedContent, groupContext []byte) error

func ComputeMembershipTag(crypto CryptoProvider, membershipKey []byte,
    authContent *AuthenticatedContent, groupContext []byte) ([]byte, error)

func SealPublicMessage(crypto CryptoProvider, membershipKey []byte,
    authContent *AuthenticatedContent, groupContext []byte) (*PublicMessage, error)
func OpenPublicMessage(crypto CryptoProvider, membershipKey []byte, message *PublicMessage,
    resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error)

func SealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
    authContent *AuthenticatedContent, paddingSize int) (*PrivateMessage, error)
func OpenPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
    message *PrivateMessage, resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error)

func CheckFramedContentContext(content *FramedContent, groupId []byte, epoch uint64) error
func CheckSenderLeaf(sender Sender, leafOccupied func(LeafIndex) bool) error

// framing_group_seams.go — unexported construction-bypass seams for p8's forge
func (self *Group) sealFramedContentForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey) ([]byte, error)
func (self *Group) sealFramedContentWithPaddingForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey, padding []byte) ([]byte, error)

// proposal_wire.go — ProposalType and its constants are p5's; this file declares neither
type Add struct{ KeyPackage KeyPackage }
type Update struct{ LeafNode LeafNode }
type Remove struct{ Removed LeafIndex }
type PreSharedKey struct{ Psk PreSharedKeyId }
type ReInit struct {
    GroupId     []byte
    Version     ProtocolVersion
    CipherSuite CipherSuite
    Extensions  []Extension
}
type ExternalInit struct{ KemOutput []byte }
type GroupContextExtensions struct{ Extensions []Extension }

type Proposal struct {
    ProposalType           ProposalType
    Add                    *Add
    Update                 *Update
    Remove                 *Remove
    PreSharedKey           *PreSharedKey
    ReInit                 *ReInit
    ExternalInit           *ExternalInit
    GroupContextExtensions *GroupContextExtensions
    UnknownType            ProposalType    // GREASE; the forge's malformed arm
    UnknownBody            []byte
}
func (self *Proposal) MarshalMLS(w *syntax.Writer) error
func (self *Proposal) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*Proposal)(nil)

type ProposalOrRefType uint8
const (
    ProposalOrRefTypeReserved  ProposalOrRefType = 0
    ProposalOrRefTypeProposal  ProposalOrRefType = 1
    ProposalOrRefTypeReference ProposalOrRefType = 2
)
type ProposalRef []byte
type ProposalOrRef struct {
    Type      ProposalOrRefType
    Proposal  *Proposal
    Reference ProposalRef
}
func (self *ProposalOrRef) MarshalMLS(w *syntax.Writer) error
func (self *ProposalOrRef) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*ProposalOrRef)(nil)

// commit_wire.go
type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}
func (self *Commit) MarshalMLS(w *syntax.Writer) error
func (self *Commit) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*Commit)(nil)

// welcome_wire.go — codecs only; generation and processing stay in p7
type GroupInfo struct {
    GroupContext    GroupContext
    Extensions      []Extension
    ConfirmationTag []byte
    Signer          LeafIndex
    Signature       []byte
}
func (self *GroupInfo) MarshalMLS(w *syntax.Writer) error
func (self *GroupInfo) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*GroupInfo)(nil)

type GroupInfoTBS struct {
    GroupContext    GroupContext
    Extensions      []Extension
    ConfirmationTag []byte
    Signer          LeafIndex
}
func (self *GroupInfoTBS) MarshalMLS(w *syntax.Writer) error

type PathSecret struct{ PathSecret []byte }
func (self *PathSecret) MarshalMLS(w *syntax.Writer) error
func (self *PathSecret) UnmarshalMLS(r *syntax.Reader) error

type GroupSecrets struct {
    JoinerSecret []byte
    PathSecret   *PathSecret        // optional<PathSecret>
    Psks         []PreSharedKeyId   // always empty in v1
}
func (self *GroupSecrets) MarshalMLS(w *syntax.Writer) error
func (self *GroupSecrets) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*GroupSecrets)(nil)

type EncryptedGroupSecrets struct {
    NewMember             []byte           // KeyPackageRef
    EncryptedGroupSecrets HpkeCiphertext
}
func (self *EncryptedGroupSecrets) MarshalMLS(w *syntax.Writer) error
func (self *EncryptedGroupSecrets) UnmarshalMLS(r *syntax.Reader) error

type Welcome struct {
    CipherSuite        CipherSuite
    Secrets            []EncryptedGroupSecrets
    EncryptedGroupInfo []byte
}
func (self *Welcome) MarshalMLS(w *syntax.Writer) error
func (self *Welcome) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*Welcome)(nil)

// framing_errors.go — structural only; the ten ValSem002-011 sentinels are p8's
var ErrUnknownWireFormat error
var ErrUnsupportedVersion error
var ErrUnknownContentType error
var ErrUnknownSenderType error
var ErrContentArmMismatch error
var ErrMissingGroupContext error
var ErrUnexpectedGroupContext error
var ErrWireFormatMismatch error
var ErrSenderNotMember error
var ErrInvalidPaddingSize error
var ErrUnknownProposalOrRefType error   // p6-private; no sibling plan names it
```

**What this plan stopped producing, and who owns it now.** `ProtocolVersion`/`ProtocolVersionMls10`
and `ProposalType` + its eight constants → p5 (§6.1). The ten ValSem002–011 sentinels →
p8 (§9.1). `ErrOptionalPresence` → p1's `syntax` package (§2.1). `senderDataKeyNonce` →
p4's exported `SenderDataKeyNonce` (§5.5). `hexBytes` → p8's `MustHex`/`HexOf`/`LoadVectorFile`
(§9.2). `FuzzMlsMessageDecode`, `FuzzMlsMessageDecodeBytes`, `FuzzProposalDecode`,
`FuzzProposalDecodeBytes` → p8 (§9.5). `marshalExtensions`/`unmarshalExtensions` → p5's
`WriteExtensions`/`ReadExtensions` (O-4).

**What this plan started producing.** `(*AuthenticatedContent).ProposalRef` (§7.2 gap),
the two `*ForTest` seams (§7.3 gap), and the `GroupInfo`/`GroupInfoTBS`/`PathSecret`/`GroupSecrets`/
`EncryptedGroupSecrets`/`Welcome` codecs moved here from p7 (§7.5).

---

### Task 1: Framing enums, `Sender` codec and the structural framing errors

**Files:**
- Create: `connect/mls/framing.go`
- Create: `connect/mls/framing_errors.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: `syntax.NewWriter() *syntax.Writer`; `(*syntax.Writer).WriteUint8(v uint8)`,
  `(*syntax.Writer).WriteUint32(v uint32)`, `(*syntax.Writer).Bytes() ([]byte, error)`;
  `syntax.NewReader(bs []byte) *syntax.Reader`; `(*syntax.Reader).ReadUint8() (uint8, error)`,
  `(*syntax.Reader).ReadUint32() (uint32, error)`, `(*syntax.Reader).Done() error`;
  `syntax.Marshal(v syntax.Marshaler) ([]byte, error)`,
  `syntax.Unmarshal(bs []byte, v syntax.Unmarshaler) error`; `syntax.Codec`;
  `type LeafIndex uint32` (p3, wave 1).
- Produces: `WireFormat` and its six constants, `ContentType` and its four constants, `SenderType`
  and its five constants, `Sender`, `(*Sender).MarshalMLS(w *syntax.Writer) error`,
  `(*Sender).UnmarshalMLS(r *syntax.Reader) error`, `var _ syntax.Codec = (*Sender)(nil)`, and the
  ten **structural** error variables `ErrUnknownWireFormat`, `ErrUnsupportedVersion`,
  `ErrUnknownContentType`, `ErrUnknownSenderType`, `ErrContentArmMismatch`, `ErrMissingGroupContext`,
  `ErrUnexpectedGroupContext`, `ErrWireFormatMismatch`, `ErrSenderNotMember`,
  `ErrInvalidPaddingSize`, plus the p6-private `ErrUnknownProposalOrRefType`.

**Two declarations this task does not make.** `ProtocolVersion`/`ProtocolVersionMls10` are p5's
registry enums (§6.1) — `package mls` is one package and a second declaration is a compile error.
The ten ValSem002–011 sentinels (`ErrWrongGroupId` … `ErrNonZeroPadding`) are p8's `errors.go`
(§9.1), wave 1, and are already available; this task consumes them and declares none of them.

- [ ] **Step 1: Write the failing test**

```go
// framing_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func TestSenderRoundTrip(t *testing.T) {
    cases := []struct {
        name    string
        sender  Sender
        encoded []byte
    }{
        {"member", Sender{SenderType: SenderTypeMember, LeafIndex: 1},
            []byte{0x01, 0x00, 0x00, 0x00, 0x01}},
        {"external", Sender{SenderType: SenderTypeExternal, SenderIndex: 7},
            []byte{0x02, 0x00, 0x00, 0x00, 0x07}},
        {"newMemberProposal", Sender{SenderType: SenderTypeNewMemberProposal}, []byte{0x03}},
        {"newMemberCommit", Sender{SenderType: SenderTypeNewMemberCommit}, []byte{0x04}},
    }
    for _, c := range cases {
        encoded, err := syntax.Marshal(&c.sender)
        if err != nil {
            t.Fatalf("%s: marshal: %v", c.name, err)
        }
        if !bytes.Equal(encoded, c.encoded) {
            t.Fatalf("%s: encoded %x, want %x", c.name, encoded, c.encoded)
        }
        var decoded Sender
        if err := syntax.Unmarshal(c.encoded, &decoded); err != nil {
            t.Fatalf("%s: unmarshal: %v", c.name, err)
        }
        if decoded != c.sender {
            t.Fatalf("%s: decoded %+v, want %+v", c.name, decoded, c.sender)
        }
    }
}

func TestSenderRejectsReservedAndUnknownType(t *testing.T) {
    for _, encoded := range [][]byte{{0x00}, {0x05}, {0xff}} {
        var decoded Sender
        err := syntax.Unmarshal(encoded, &decoded)
        if !errors.Is(err, ErrUnknownSenderType) {
            t.Fatalf("sender_type %x: got %v, want ErrUnknownSenderType", encoded, err)
        }
    }
}
```

The C1 compile assertion is the `var _ syntax.Codec = (*Sender)(nil)` line in `framing.go` below,
not a test: a method-set drift must fail at build, before any test runs.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestSender' -v`
Expected: FAIL — `undefined: Sender`, `undefined: SenderTypeMember`, `undefined: ErrUnknownSenderType`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_errors.go
// the STRUCTURAL errors RFC 9420 §6 framing can produce: a malformed
// discriminant, an arm that disagrees with its content type, a group context
// supplied where the sender type forbids it. the ten ValSem002-011 sentinels
// are NOT here — they live once, in the validation plan's errors.go, because
// they are the codes Gate 3 asserts and a second declaration in this package
// is a compile error.
package mls

import "errors"

var (
    ErrUnknownWireFormat      = errors.New("mls: unknown wire format")
    ErrUnsupportedVersion     = errors.New("mls: unsupported protocol version")
    ErrUnknownContentType     = errors.New("mls: unknown content type")
    ErrUnknownSenderType      = errors.New("mls: unknown sender type")
    ErrContentArmMismatch     = errors.New("mls: framed content arm does not match content type")
    ErrMissingGroupContext    = errors.New("mls: group context required for this sender type")
    ErrUnexpectedGroupContext = errors.New("mls: group context supplied for a sender type that forbids it")
    ErrWireFormatMismatch     = errors.New("mls: wire format does not match the message being sealed")
    ErrSenderNotMember        = errors.New("mls: sender type must be member")
    ErrInvalidPaddingSize     = errors.New("mls: negative padding size")

    // the ProposalOrRef discriminant. no sibling plan names this, so it stays
    // here rather than moving to the shared catalogue.
    ErrUnknownProposalOrRefType = errors.New("mls: unknown ProposalOrRef type")
)
```

```go
// framing.go
// RFC 9420 §6 message framing wire types and their codecs. no crypto lives
// here: the signed and MACed byte strings are framing_preimage.go and the
// sealing operations are framing_protect.go. ProtocolVersion and
// ProtocolVersionMls10 are the registry-enum file's, not this file's.
package mls

import (
    "fmt"

    "github.com/urnetwork/connect/mls/syntax"
)

// which of the five MLSMessage arms a message carries. 16 bits per the IANA
// MLS Wire Formats registry.
type WireFormat uint16

const (
    WireFormatReserved       WireFormat = 0x0000
    WireFormatPublicMessage  WireFormat = 0x0001
    WireFormatPrivateMessage WireFormat = 0x0002
    WireFormatWelcome        WireFormat = 0x0003
    WireFormatGroupInfo      WireFormat = 0x0004
    WireFormatKeyPackage     WireFormat = 0x0005
)

// which arm of FramedContent is populated. 8 bits.
type ContentType uint8

const (
    ContentTypeReserved    ContentType = 0
    ContentTypeApplication ContentType = 1
    ContentTypeProposal    ContentType = 2
    ContentTypeCommit      ContentType = 3
)

// who sent a FramedContent, which selects both the signature key and whether
// the GroupContext is part of the signature preimage. 8 bits.
type SenderType uint8

const (
    SenderTypeReserved          SenderType = 0
    SenderTypeMember            SenderType = 1
    SenderTypeExternal          SenderType = 2
    SenderTypeNewMemberProposal SenderType = 3
    SenderTypeNewMemberCommit   SenderType = 4
)

// the sender of a FramedContent. LeafIndex is meaningful only for member and
// SenderIndex only for external; the other two carry no payload at all.
type Sender struct {
    SenderType  SenderType
    LeafIndex   LeafIndex
    SenderIndex uint32
}

func (self *Sender) MarshalMLS(w *syntax.Writer) error {
    switch self.SenderType {
    case SenderTypeMember:
        w.WriteUint8(uint8(self.SenderType))
        w.WriteUint32(uint32(self.LeafIndex))
    case SenderTypeExternal:
        w.WriteUint8(uint8(self.SenderType))
        w.WriteUint32(self.SenderIndex)
    case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
        w.WriteUint8(uint8(self.SenderType))
    default:
        return fmt.Errorf("%w: %d", ErrUnknownSenderType, self.SenderType)
    }
    return nil
}

func (self *Sender) UnmarshalMLS(r *syntax.Reader) error {
    senderType, err := r.ReadUint8()
    if err != nil {
        return err
    }
    *self = Sender{SenderType: SenderType(senderType)}
    switch self.SenderType {
    case SenderTypeMember:
        leafIndex, err := r.ReadUint32()
        if err != nil {
            return err
        }
        self.LeafIndex = LeafIndex(leafIndex)
    case SenderTypeExternal:
        senderIndex, err := r.ReadUint32()
        if err != nil {
            return err
        }
        self.SenderIndex = senderIndex
    case SenderTypeNewMemberProposal, SenderTypeNewMemberCommit:
    default:
        return fmt.Errorf("%w: %d", ErrUnknownSenderType, self.SenderType)
    }
    return nil
}

var _ syntax.Codec = (*Sender)(nil)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestSender' -v`
Expected: PASS — `TestSenderRoundTrip` and `TestSenderRejectsReservedAndUnknownType`.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l   # record this number; compare after `git add`
git add mls/framing.go mls/framing_errors.go mls/framing_test.go
git ls-files | wc -l   # MUST be the previous number + 3
git commit -m "feat(mls): framing enums, Sender codec and the structural framing errors"
```

---

### Task 2: `FramedContent` codec

**Files:**
- Modify: `connect/mls/framing.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: Task 1's `Sender`, `ContentType`; `(*syntax.Writer).WriteOpaque(bs []byte)` —
  **no error return**, failures land in the sticky Writer and surface at `Bytes()`;
  `(*syntax.Writer).WriteUint64(v uint64)`; `(*syntax.Reader).ReadOpaque() ([]byte, error)`,
  `(*syntax.Reader).ReadUint64() (uint64, error)`; `syntax.Marshal`, `syntax.Unmarshal`;
  `Proposal` and `Commit` from Tasks 12 and 13 — **implement those two tasks first if the codec does
  not yet exist**; this task is blocked, not stubbed.
- Produces: `FramedContent`, `(*FramedContent).MarshalMLS(w *syntax.Writer) error`,
  `(*FramedContent).UnmarshalMLS(r *syntax.Reader) error`,
  `var _ syntax.Codec = (*FramedContent)(nil)`.

> **Ordering note:** Tasks 12 and 13 (`proposal_wire.go`, `commit_wire.go`) are listed later
> because they are large and self-contained, but Task 2 does not compile without them. Execute
> 1 → 12 → 13 → 2 → 3 … if you are running strictly sequentially; the numbering is the reading
> order, not a dependency order, and this is the only place they differ.

- [ ] **Step 1: Write the failing test**

```go
// framing_test.go (append)
func TestFramedContentRoundTripApplication(t *testing.T) {
    content := FramedContent{
        GroupId:           []byte{0xaa, 0xbb},
        Epoch:             5,
        Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: 1},
        AuthenticatedData: []byte{0x01, 0x02, 0x03},
        ContentType:       ContentTypeApplication,
        ApplicationData:   []byte("hello"),
    }
    encoded, err := syntax.Marshal(&content)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }

    var decoded FramedContent
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
    if !bytes.Equal(decoded.ApplicationData, []byte("hello")) {
        t.Fatalf("application data %q", decoded.ApplicationData)
    }
}

func TestFramedContentRoundTripProposal(t *testing.T) {
    content := FramedContent{
        GroupId:     []byte{0x01},
        Epoch:       0,
        Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 3},
        ContentType: ContentTypeProposal,
        Proposal: &Proposal{
            ProposalType: ProposalTypeRemove,
            Remove:       &Remove{Removed: 2},
        },
    }
    encoded, err := syntax.Marshal(&content)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded FramedContent
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded.Proposal == nil || decoded.Proposal.Remove == nil ||
        decoded.Proposal.Remove.Removed != 2 {
        t.Fatalf("decoded proposal %+v", decoded.Proposal)
    }
}

func TestFramedContentRejectsArmMismatch(t *testing.T) {
    content := FramedContent{
        GroupId:         []byte{0x01},
        Sender:          Sender{SenderType: SenderTypeMember},
        ContentType:     ContentTypeApplication,
        ApplicationData: []byte("x"),
        Commit:          &Commit{},
    }
    // the refusal must survive syntax.Marshal, which joins the semantic error
    // from MarshalMLS with the Writer's sticky error (registry O-1)
    if _, err := syntax.Marshal(&content); !errors.Is(err, ErrContentArmMismatch) {
        t.Fatalf("got %v, want ErrContentArmMismatch", err)
    }
}

func TestFramedContentRejectsUnknownContentType(t *testing.T) {
    content := FramedContent{
        GroupId:     []byte{0x01},
        Sender:      Sender{SenderType: SenderTypeMember},
        ContentType: ContentType(9),
    }
    if _, err := syntax.Marshal(&content); !errors.Is(err, ErrUnknownContentType) {
        t.Fatalf("got %v, want ErrUnknownContentType", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestFramedContent' -v`
Expected: FAIL — `undefined: FramedContent`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing.go (append)

// the body of a group message before it is authenticated. exactly one of
// ApplicationData, Proposal and Commit is populated, selected by ContentType.
type FramedContent struct {
    GroupId           []byte
    Epoch             uint64
    Sender            Sender
    AuthenticatedData []byte
    ContentType       ContentType
    ApplicationData   []byte
    Proposal          *Proposal
    Commit            *Commit
}

// reports whether exactly the arm ContentType names is populated. an arm set
// on the wrong content type would encode without complaint and change nothing
// on the wire, so a receiver would verify a signature over bytes that do not
// describe the struct the sender believed it sent.
func (self *FramedContent) checkArms() error {
    populated := 0
    if self.ApplicationData != nil {
        populated += 1
    }
    if self.Proposal != nil {
        populated += 1
    }
    if self.Commit != nil {
        populated += 1
    }
    switch self.ContentType {
    case ContentTypeApplication:
        if self.Proposal != nil || self.Commit != nil {
            return ErrContentArmMismatch
        }
    case ContentTypeProposal:
        if self.Proposal == nil || populated != 1 {
            return ErrContentArmMismatch
        }
    case ContentTypeCommit:
        if self.Commit == nil || populated != 1 {
            return ErrContentArmMismatch
        }
    default:
        return fmt.Errorf("%w: %d", ErrUnknownContentType, self.ContentType)
    }
    return nil
}

func (self *FramedContent) MarshalMLS(w *syntax.Writer) error {
    if err := self.checkArms(); err != nil {
        return err
    }
    w.WriteOpaque(self.GroupId)
    w.WriteUint64(self.Epoch)
    if err := self.Sender.MarshalMLS(w); err != nil {
        return err
    }
    w.WriteOpaque(self.AuthenticatedData)
    w.WriteUint8(uint8(self.ContentType))
    switch self.ContentType {
    case ContentTypeApplication:
        w.WriteOpaque(self.ApplicationData)
        return nil
    case ContentTypeProposal:
        return self.Proposal.MarshalMLS(w)
    case ContentTypeCommit:
        return self.Commit.MarshalMLS(w)
    }
    return fmt.Errorf("%w: %d", ErrUnknownContentType, self.ContentType)
}

func (self *FramedContent) UnmarshalMLS(r *syntax.Reader) error {
    groupId, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    epoch, err := r.ReadUint64()
    if err != nil {
        return err
    }
    var sender Sender
    if err := sender.UnmarshalMLS(r); err != nil {
        return err
    }
    authenticatedData, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    contentType, err := r.ReadUint8()
    if err != nil {
        return err
    }
    *self = FramedContent{
        GroupId:           groupId,
        Epoch:             epoch,
        Sender:            sender,
        AuthenticatedData: authenticatedData,
        ContentType:       ContentType(contentType),
    }
    switch self.ContentType {
    case ContentTypeApplication:
        applicationData, err := r.ReadOpaque()
        if err != nil {
            return err
        }
        self.ApplicationData = applicationData
        return nil
    case ContentTypeProposal:
        self.Proposal = &Proposal{}
        return self.Proposal.UnmarshalMLS(r)
    case ContentTypeCommit:
        self.Commit = &Commit{}
        return self.Commit.UnmarshalMLS(r)
    }
    return fmt.Errorf("%w: %d", ErrUnknownContentType, self.ContentType)
}

var _ syntax.Codec = (*FramedContent)(nil)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestFramedContent' -v`
Expected: PASS — four tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_test.go
git ls-files | wc -l   # MUST be unchanged (both files already tracked)
git commit -m "feat(mls): FramedContent codec with an arm-consistency check"
```

---

### Task 3: `FramedContentAuthData` codec

**Files:**
- Modify: `connect/mls/framing.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: Task 1's `ContentType`; `(*syntax.Writer).WriteOpaque(bs []byte)`,
  `(*syntax.Reader).ReadOpaque() ([]byte, error)`, `(*syntax.Writer).Bytes() ([]byte, error)`,
  `(*syntax.Reader).Done() error`; from p8 (wave 1) `func ValSem(code ValSemCode, detail error) error`,
  `func CodeOf(err error) (ValSemCode, bool)`, the code `ValSem009` and
  `var ErrMissingConfirmationTag error`.
- Produces: `FramedContentAuthData`,
  `(*FramedContentAuthData).MarshalMLS(w *syntax.Writer, contentType ContentType) error`,
  `(*FramedContentAuthData).UnmarshalMLS(r *syntax.Reader, contentType ContentType) error`.

The content type is a **parameter**, not a struct field: `FramedContentAuthData` is a `select()` on
the enclosing `FramedContent.content_type` and carries no discriminant of its own on the wire.
Storing a copy in the struct would let the two disagree. This is why the type is deliberately not a
`syntax.Codec` and carries no `var _` assertion — registry §7.2 fixes exactly these two signatures,
and it also **rejects** the `MembershipTag` and `HasConfirmationTag` fields p8 asked for: the
membership tag lives on `PublicMessage` where RFC 9420 puts it, and tag presence is derived from
`ContentType`.

The two refusals are ValSem009, so they return `ValSem(ValSem009, ErrMissingConfirmationTag)`
rather than the bare sentinel — `CodeOf` then finds the code and `errors.Is` still finds the
sentinel through `(*ValidationError).Unwrap`.

- [ ] **Step 1: Write the failing test**

```go
// framing_test.go (append)
func TestFramedContentAuthDataRoundTrip(t *testing.T) {
    signature := []byte{0x11, 0x22, 0x33}
    tag := []byte{0x44, 0x55}

    // application and proposal carry a signature only
    for _, contentType := range []ContentType{ContentTypeApplication, ContentTypeProposal} {
        auth := FramedContentAuthData{Signature: signature}
        w := syntax.NewWriter()
        if err := auth.MarshalMLS(w, contentType); err != nil {
            t.Fatalf("contentType %d: marshal: %v", contentType, err)
        }
        encoded, err := w.Bytes()
        if err != nil {
            t.Fatalf("contentType %d: bytes: %v", contentType, err)
        }
        want := []byte{0x03, 0x11, 0x22, 0x33} // opaque<V> length 3 encodes as one byte 0x03
        if !bytes.Equal(encoded, want) {
            t.Fatalf("contentType %d: encoded %x, want %x", contentType, encoded, want)
        }
        var decoded FramedContentAuthData
        r := syntax.NewReader(encoded)
        if err := decoded.UnmarshalMLS(r, contentType); err != nil {
            t.Fatalf("contentType %d: unmarshal: %v", contentType, err)
        }
        if err := r.Done(); err != nil {
            t.Fatalf("contentType %d: trailing bytes: %v", contentType, err)
        }
        if decoded.ConfirmationTag != nil {
            t.Fatalf("contentType %d: confirmation tag decoded on a non-commit", contentType)
        }
    }

    // commit carries both
    auth := FramedContentAuthData{Signature: signature, ConfirmationTag: tag}
    w := syntax.NewWriter()
    if err := auth.MarshalMLS(w, ContentTypeCommit); err != nil {
        t.Fatalf("commit marshal: %v", err)
    }
    encoded, err := w.Bytes()
    if err != nil {
        t.Fatalf("commit bytes: %v", err)
    }
    want := []byte{0x03, 0x11, 0x22, 0x33, 0x02, 0x44, 0x55}
    if !bytes.Equal(encoded, want) {
        t.Fatalf("commit encoded %x, want %x", encoded, want)
    }
    var decoded FramedContentAuthData
    r := syntax.NewReader(encoded)
    if err := decoded.UnmarshalMLS(r, ContentTypeCommit); err != nil {
        t.Fatalf("commit unmarshal: %v", err)
    }
    if err := r.Done(); err != nil {
        t.Fatalf("commit trailing bytes: %v", err)
    }
    if !bytes.Equal(decoded.ConfirmationTag, tag) {
        t.Fatalf("confirmation tag %x, want %x", decoded.ConfirmationTag, tag)
    }
}

func TestFramedContentAuthDataCommitRequiresConfirmationTag(t *testing.T) {
    auth := FramedContentAuthData{Signature: []byte{0x01}}
    err := auth.MarshalMLS(syntax.NewWriter(), ContentTypeCommit)
    if !errors.Is(err, ErrMissingConfirmationTag) {
        t.Fatalf("got %v, want ErrMissingConfirmationTag", err)
    }
    code, ok := CodeOf(err)
    if !ok || code != ValSem009 {
        t.Fatalf("code %v ok %v, want ValSem009", code, ok)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestFramedContentAuthData' -v`
Expected: FAIL — `undefined: FramedContentAuthData`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing.go (append)

// the authenticators over a FramedContent. ConfirmationTag is present exactly
// when the enclosing content type is commit; the content type is passed in
// because this struct carries no discriminant of its own on the wire.
type FramedContentAuthData struct {
    Signature       []byte
    ConfirmationTag []byte
}

func (self *FramedContentAuthData) MarshalMLS(w *syntax.Writer, contentType ContentType) error {
    w.WriteOpaque(self.Signature)
    switch contentType {
    case ContentTypeCommit:
        if len(self.ConfirmationTag) == 0 {
            return ValSem(ValSem009, ErrMissingConfirmationTag)
        }
        w.WriteOpaque(self.ConfirmationTag)
        return nil
    case ContentTypeApplication, ContentTypeProposal:
        return nil
    }
    return fmt.Errorf("%w: %d", ErrUnknownContentType, contentType)
}

func (self *FramedContentAuthData) UnmarshalMLS(r *syntax.Reader, contentType ContentType) error {
    signature, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    *self = FramedContentAuthData{Signature: signature}
    switch contentType {
    case ContentTypeCommit:
        confirmationTag, err := r.ReadOpaque()
        if err != nil {
            return err
        }
        if len(confirmationTag) == 0 {
            return ValSem(ValSem009, ErrMissingConfirmationTag)
        }
        self.ConfirmationTag = confirmationTag
        return nil
    case ContentTypeApplication, ContentTypeProposal:
        return nil
    }
    return fmt.Errorf("%w: %d", ErrUnknownContentType, contentType)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestFramedContentAuthData' -v`
Expected: PASS — two tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_test.go
git ls-files | wc -l
git commit -m "feat(mls): FramedContentAuthData codec, confirmation tag on commits only"
```

---

### Task 4: `AuthenticatedContent` codec, the transcript-hash input and `ProposalRef`

**Files:**
- Modify: `connect/mls/framing.go`
- Create: `connect/mls/framing_preimage.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: Tasks 1–3; `syntax.Marshal(v syntax.Marshaler) ([]byte, error)`;
  `func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte` (p2, wave 1);
  `type CryptoProvider interface{ ... }` (p2).
- Produces: `AuthenticatedContent`, `(*AuthenticatedContent).MarshalMLS(w *syntax.Writer) error`,
  `(*AuthenticatedContent).UnmarshalMLS(r *syntax.Reader) error`,
  `var _ syntax.Codec = (*AuthenticatedContent)(nil)`,
  `(*AuthenticatedContent).ConfirmedTranscriptHashInput() ([]byte, error)`,
  `(*AuthenticatedContent).ProposalRef(crypto CryptoProvider) (ProposalRef, error)`.

`ConfirmedTranscriptHashInput` is produced here rather than in `transcript.go` because it is a
serialization of framing types (`wire_format ‖ FramedContent ‖ opaque signature<V>`). **p4's
transcript code consumes it** through
`ConfirmedTranscriptHash(crypto, interimBefore, authContent.ConfirmedTranscriptHashInput())` —
p4 deliberately takes `confirmedTranscriptHashInput []byte` so no framing type crosses into
`transcript.go`, and `ConfirmedTranscriptHash`/`InterimTranscriptHash` are p4's, not this plan's.

`(*AuthenticatedContent).ProposalRef` is registry §7.2's gap assigned here: p7 names it at every
by-reference proposal site and nothing produced it. It hashes the **serialized
`AuthenticatedContent`**, so the ref covers the wire format, the sender and the signature, and it
delegates the label and hash to p2's `MakeProposalRef`.

- [ ] **Step 1: Write the failing test**

```go
// framing_test.go (append)
func TestAuthenticatedContentRoundTrip(t *testing.T) {
    authContent := AuthenticatedContent{
        WireFormat: WireFormatPublicMessage,
        Content: FramedContent{
            GroupId:     []byte{0x07},
            Epoch:       2,
            Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 1},
            ContentType: ContentTypeCommit,
            Commit:      &Commit{},
        },
        Auth: FramedContentAuthData{
            Signature:       []byte{0xde, 0xad},
            ConfirmationTag: []byte{0xbe, 0xef},
        },
    }
    encoded, err := syntax.Marshal(&authContent)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if encoded[0] != 0x00 || encoded[1] != 0x01 {
        t.Fatalf("wire format prefix %x, want 0001", encoded[0:2])
    }

    var decoded AuthenticatedContent
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

func TestConfirmedTranscriptHashInputOmitsConfirmationTag(t *testing.T) {
    authContent := AuthenticatedContent{
        WireFormat: WireFormatPrivateMessage,
        Content: FramedContent{
            GroupId:     []byte{0x07},
            Epoch:       2,
            Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 1},
            ContentType: ContentTypeCommit,
            Commit:      &Commit{},
        },
        Auth: FramedContentAuthData{
            Signature:       []byte{0xde, 0xad},
            ConfirmationTag: []byte{0xbe, 0xef},
        },
    }
    input, err := authContent.ConfirmedTranscriptHashInput()
    if err != nil {
        t.Fatalf("input: %v", err)
    }

    w := syntax.NewWriter()
    w.WriteUint16(uint16(WireFormatPrivateMessage))
    if err := authContent.Content.MarshalMLS(w); err != nil {
        t.Fatalf("content: %v", err)
    }
    w.WriteOpaque(authContent.Auth.Signature)
    want, err := w.Bytes()
    if err != nil {
        t.Fatalf("bytes: %v", err)
    }
    if !bytes.Equal(input, want) {
        t.Fatalf("input %x, want %x", input, want)
    }
    if bytes.Contains(input, []byte{0xbe, 0xef}) {
        t.Fatal("confirmation tag leaked into ConfirmedTranscriptHashInput")
    }
}

func TestConfirmedTranscriptHashInputRefusesNonCommit(t *testing.T) {
    authContent := AuthenticatedContent{
        WireFormat: WireFormatPrivateMessage,
        Content: FramedContent{
            GroupId:         []byte{0x07},
            Sender:          Sender{SenderType: SenderTypeMember},
            ContentType:     ContentTypeApplication,
            ApplicationData: []byte("x"),
        },
        Auth: FramedContentAuthData{Signature: []byte{0x01}},
    }
    if _, err := authContent.ConfirmedTranscriptHashInput(); !errors.Is(err, ErrContentArmMismatch) {
        t.Fatalf("got %v, want ErrContentArmMismatch", err)
    }
}

// one crypto provider constructor for the whole package's framing tests. the
// suite constant is the crypto plan's spelling: Sha, not SHA.
func newTestCrypto(t *testing.T) CryptoProvider {
    t.Helper()
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("crypto provider: %v", err)
    }
    return crypto
}

func TestProposalRefCoversTheWholeAuthenticatedContent(t *testing.T) {
    crypto := newTestCrypto(t)
    authContent := AuthenticatedContent{
        WireFormat: WireFormatPublicMessage,
        Content: FramedContent{
            GroupId:     []byte{0x07},
            Epoch:       2,
            Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 1},
            ContentType: ContentTypeProposal,
            Proposal:    &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}},
        },
        Auth: FramedContentAuthData{Signature: []byte{0xde, 0xad}},
    }

    ref, err := authContent.ProposalRef(crypto)
    if err != nil {
        t.Fatalf("ref: %v", err)
    }
    if len(ref) != crypto.HashSize() {
        t.Fatalf("ref length %d, want %d", len(ref), crypto.HashSize())
    }
    encoded, err := syntax.Marshal(&authContent)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if !bytes.Equal(ref, MakeProposalRef(crypto, encoded)) {
        t.Fatal("ProposalRef is not MakeProposalRef over the serialized AuthenticatedContent")
    }

    // the signature is inside the ref, so re-signing changes it
    resigned := authContent
    resigned.Auth.Signature = []byte{0xde, 0xae}
    other, err := resigned.ProposalRef(crypto)
    if err != nil {
        t.Fatalf("ref: %v", err)
    }
    if bytes.Equal(ref, other) {
        t.Fatal("ProposalRef does not cover the signature")
    }
}

func TestProposalRefRefusesNonProposal(t *testing.T) {
    crypto := newTestCrypto(t)
    authContent := AuthenticatedContent{
        WireFormat: WireFormatPrivateMessage,
        Content: FramedContent{
            GroupId:         []byte{0x07},
            Sender:          Sender{SenderType: SenderTypeMember},
            ContentType:     ContentTypeApplication,
            ApplicationData: []byte("x"),
        },
        Auth: FramedContentAuthData{Signature: []byte{0x01}},
    }
    if _, err := authContent.ProposalRef(crypto); !errors.Is(err, ErrContentArmMismatch) {
        t.Fatalf("got %v, want ErrContentArmMismatch", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestAuthenticatedContentRoundTrip|TestConfirmedTranscriptHashInput|TestProposalRef' -v`
Expected: FAIL — `undefined: AuthenticatedContent`, `undefined: newTestCrypto`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing.go (append)

// a FramedContent together with the authenticators over it, independent of
// which wire format carried it. this is the object every validation path
// works on, and the object a staged commit holds.
type AuthenticatedContent struct {
    WireFormat WireFormat
    Content    FramedContent
    Auth       FramedContentAuthData
}

func (self *AuthenticatedContent) MarshalMLS(w *syntax.Writer) error {
    w.WriteUint16(uint16(self.WireFormat))
    if err := self.Content.MarshalMLS(w); err != nil {
        return err
    }
    return self.Auth.MarshalMLS(w, self.Content.ContentType)
}

func (self *AuthenticatedContent) UnmarshalMLS(r *syntax.Reader) error {
    wireFormat, err := r.ReadUint16()
    if err != nil {
        return err
    }
    *self = AuthenticatedContent{WireFormat: WireFormat(wireFormat)}
    if err := self.Content.UnmarshalMLS(r); err != nil {
        return err
    }
    return self.Auth.UnmarshalMLS(r, self.Content.ContentType)
}

var _ syntax.Codec = (*AuthenticatedContent)(nil)
```

```go
// framing_preimage.go
// the byte strings RFC 9420 §6 authenticates or hashes. one function each, one
// file, no key material: an auditor reading this file sees every preimage in
// the implementation and nothing else.
package mls

import (
    "fmt"

    "github.com/urnetwork/connect/mls/syntax"
)

// the input to the confirmed transcript hash, RFC 9420 §8.2. carries the
// signature but NOT the confirmation tag, which is what makes the transcript
// hash and the confirmation tag mutually recursive rather than circular. p4's
// transcript.go consumes these bytes and computes the hash chain.
func (self *AuthenticatedContent) ConfirmedTranscriptHashInput() ([]byte, error) {
    if self.Content.ContentType != ContentTypeCommit {
        return nil, fmt.Errorf("%w: transcript hash input requires a commit", ErrContentArmMismatch)
    }
    w := syntax.NewWriter()
    w.WriteUint16(uint16(self.WireFormat))
    if err := self.Content.MarshalMLS(w); err != nil {
        return nil, err
    }
    w.WriteOpaque(self.Auth.Signature)
    return w.Bytes()
}

// the HashReference a Commit uses to name a by-reference proposal, RFC 9420
// §5.2. the hash is over the SERIALIZED AuthenticatedContent, so the ref covers
// the wire format, the sender and the signature; two members proposing the same
// removal therefore produce different refs, which is what stops one member's
// proposal being committed under another's name.
func (self *AuthenticatedContent) ProposalRef(crypto CryptoProvider) (ProposalRef, error) {
    if self.Content.ContentType != ContentTypeProposal {
        return nil, fmt.Errorf("%w: a proposal ref requires a proposal", ErrContentArmMismatch)
    }
    encoded, err := syntax.Marshal(self)
    if err != nil {
        return nil, err
    }
    return ProposalRef(MakeProposalRef(crypto, encoded)), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestAuthenticatedContentRoundTrip|TestConfirmedTranscriptHashInput|TestProposalRef' -v`
Expected: PASS — five tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_preimage.go mls/framing_test.go
git ls-files | wc -l   # MUST be previous + 1
git commit -m "feat(mls): AuthenticatedContent codec, ConfirmedTranscriptHashInput and ProposalRef"
```

---

### Task 5: `FramedContentTBS` preimage, sign and verify (ValSem010, ValSem009)

**Files:**
- Modify: `connect/mls/framing_preimage.go`
- Create: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: `SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error)`,
  `VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error`,
  `SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error)` — all methods on p2's
  `CryptoProvider`; `func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)` and
  `const CipherSuiteX25519ChaCha20Sha256Ed25519 CipherSuite = 0x0003` (p2, wave 1);
  `const ProtocolVersionMls10 ProtocolVersion = 0x0001` (p5, wave 2);
  `func ValSem(code ValSemCode, detail error) error`, the codes `ValSem009`/`ValSem010` and the
  sentinels `ErrBadSignature`, `ErrMissingConfirmationTag` (p8, wave 1). Tasks 1–4.
- Produces:
  `FramedContentTBSBytes(wireFormat WireFormat, content *FramedContent, groupContext []byte) ([]byte, error)`,
  `SignAuthenticatedContent(crypto CryptoProvider, priv SignaturePrivateKey, wireFormat WireFormat, content *FramedContent, groupContext []byte) (*AuthenticatedContent, error)`,
  `VerifyAuthenticatedContent(crypto CryptoProvider, pub SignaturePublicKey, authContent *AuthenticatedContent, groupContext []byte) error`.

**The two traps this task exists for.** (1) The GroupContext is inlined into the preimage with **no
length prefix** — it is a struct field in the presentation language, not an `opaque<V>`. (2) It is
present for `member` and `new_member_commit` and **absent** for `external` and
`new_member_proposal`; emitting it unconditionally produces a signature every other implementation
rejects, and omitting it unconditionally produces one that verifies across epochs.

- [ ] **Step 1: Write the failing test**

```go
// framing_protect_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

// a real serialized GroupContext, built the way every caller must build one
// (C4): syntax.Marshal over the key-schedule plan's struct. the preimage inlines
// these bytes verbatim, with no length prefix.
func testGroupContext(t *testing.T) []byte {
    t.Helper()
    groupContext := &GroupContext{
        Version:                 ProtocolVersionMls10,
        CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
        GroupId:                 []byte{0x01, 0x02},
        Epoch:                   4,
        TreeHash:                bytes.Repeat([]byte{0xc0}, 32),
        ConfirmedTranscriptHash: bytes.Repeat([]byte{0xee}, 32),
    }
    encoded, err := syntax.Marshal(groupContext)
    if err != nil {
        t.Fatalf("group context: %v", err)
    }
    return encoded
}

func testMemberContent() *FramedContent {
    return &FramedContent{
        GroupId:           []byte{0x01, 0x02},
        Epoch:             4,
        Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: 1},
        AuthenticatedData: []byte{0x09},
        ContentType:       ContentTypeApplication,
        ApplicationData:   []byte("payload"),
    }
}

func testProposalContent() *FramedContent {
    content := testMemberContent()
    content.ContentType = ContentTypeProposal
    content.ApplicationData = nil
    content.Proposal = &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 3}}
    return content
}

func TestFramedContentTBSInlinesGroupContextWithoutLengthPrefix(t *testing.T) {
    content := testMemberContent()
    groupContext := testGroupContext(t)

    tbs, err := FramedContentTBSBytes(WireFormatPrivateMessage, content, groupContext)
    if err != nil {
        t.Fatalf("tbs: %v", err)
    }

    w := syntax.NewWriter()
    w.WriteUint16(uint16(ProtocolVersionMls10))
    w.WriteUint16(uint16(WireFormatPrivateMessage))
    if err := content.MarshalMLS(w); err != nil {
        t.Fatalf("content: %v", err)
    }
    w.WriteRaw(groupContext)
    want, err := w.Bytes()
    if err != nil {
        t.Fatalf("bytes: %v", err)
    }
    if !bytes.Equal(tbs, want) {
        t.Fatalf("tbs %x, want %x", tbs, want)
    }
    if !bytes.HasSuffix(tbs, groupContext) {
        t.Fatal("group context is not the trailing bytes of the preimage")
    }
}

func TestFramedContentTBSOmitsGroupContextForExternalSender(t *testing.T) {
    content := testProposalContent()
    content.Sender = Sender{SenderType: SenderTypeExternal, SenderIndex: 0}

    tbs, err := FramedContentTBSBytes(WireFormatPublicMessage, content, nil)
    if err != nil {
        t.Fatalf("tbs: %v", err)
    }
    if bytes.Contains(tbs, testGroupContext(t)) {
        t.Fatal("group context present for an external sender")
    }
    _, err = FramedContentTBSBytes(WireFormatPublicMessage, content, testGroupContext(t))
    if !errors.Is(err, ErrUnexpectedGroupContext) {
        t.Fatalf("got %v, want ErrUnexpectedGroupContext", err)
    }
}

func TestFramedContentTBSRequiresGroupContextForMember(t *testing.T) {
    _, err := FramedContentTBSBytes(WireFormatPrivateMessage, testMemberContent(), nil)
    if !errors.Is(err, ErrMissingGroupContext) {
        t.Fatalf("got %v, want ErrMissingGroupContext", err)
    }
}

func TestSignAndVerifyAuthenticatedContent(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage,
        testMemberContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); err != nil {
        t.Fatalf("verify: %v", err)
    }
}

func TestAuthenticatedContentRefusesForgedSignature(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage,
        testMemberContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }

    tampered := *authContent
    tampered.Auth.Signature = append([]byte(nil), authContent.Auth.Signature...)
    tampered.Auth.Signature[0] ^= 0x01
    if err := VerifyAuthenticatedContent(crypto, pub, &tampered, groupContext); !errors.Is(err, ErrBadSignature) {
        t.Fatalf("flipped signature: got %v, want ErrBadSignature", err)
    }

    empty := *authContent
    empty.Auth.Signature = nil
    if err := VerifyAuthenticatedContent(crypto, pub, &empty, groupContext); !errors.Is(err, ErrBadSignature) {
        t.Fatalf("empty signature: got %v, want ErrBadSignature", err)
    }

    otherContext := append([]byte(nil), groupContext...)
    otherContext[0] ^= 0xff
    if err := VerifyAuthenticatedContent(crypto, pub, authContent, otherContext); !errors.Is(err, ErrBadSignature) {
        t.Fatalf("wrong group context: got %v, want ErrBadSignature", err)
    }

    rewired := *authContent
    rewired.WireFormat = WireFormatPublicMessage
    if err := VerifyAuthenticatedContent(crypto, pub, &rewired, groupContext); !errors.Is(err, ErrBadSignature) {
        t.Fatalf("rewired wire format: got %v, want ErrBadSignature", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestFramedContentTBS|TestSignAndVerifyAuthenticatedContent|TestAuthenticatedContentRefusesForgedSignature' -v`
Expected: FAIL — `undefined: FramedContentTBSBytes`, `undefined: SignAuthenticatedContent`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_preimage.go (append)

// the bytes SignWithLabel signs under the label "FramedContentTBS", RFC 9420
// §6.1. groupContext is an ALREADY-SERIALIZED GroupContext and is inlined with
// no length prefix, present only for the two sender types whose signatures are
// bound to an epoch.
func FramedContentTBSBytes(wireFormat WireFormat, content *FramedContent, groupContext []byte) ([]byte, error) {
    w := syntax.NewWriter()
    w.WriteUint16(uint16(ProtocolVersionMls10))
    w.WriteUint16(uint16(wireFormat))
    if err := content.MarshalMLS(w); err != nil {
        return nil, err
    }
    switch content.Sender.SenderType {
    case SenderTypeMember, SenderTypeNewMemberCommit:
        if len(groupContext) == 0 {
            return nil, ErrMissingGroupContext
        }
        w.WriteRaw(groupContext)
    case SenderTypeExternal, SenderTypeNewMemberProposal:
        if len(groupContext) != 0 {
            return nil, ErrUnexpectedGroupContext
        }
    default:
        return nil, fmt.Errorf("%w: %d", ErrUnknownSenderType, content.Sender.SenderType)
    }
    return w.Bytes()
}
```

```go
// framing_protect.go
// signing, MACing, encrypting and their inverses for RFC 9420 §6. every Open*
// function verifies the signature itself rather than returning an unverified
// object, per Spec A §5.9 guardrail G7.
package mls

import (
    "github.com/urnetwork/connect/mls/syntax"
)

// the label RFC 9420 §6.1 signs a FramedContentTBS under.
const framedContentTBSLabel = "FramedContentTBS"

// signs a FramedContent, producing an AuthenticatedContent with an empty
// confirmation tag. a commit's caller sets Auth.ConfirmationTag afterwards,
// because the tag depends on a transcript hash that depends on this signature.
func SignAuthenticatedContent(crypto CryptoProvider, priv SignaturePrivateKey,
    wireFormat WireFormat, content *FramedContent, groupContext []byte) (*AuthenticatedContent, error) {

    tbs, err := FramedContentTBSBytes(wireFormat, content, groupContext)
    if err != nil {
        return nil, err
    }
    signature, err := crypto.SignWithLabel(priv, framedContentTBSLabel, tbs)
    if err != nil {
        return nil, err
    }
    return &AuthenticatedContent{
        WireFormat: wireFormat,
        Content:    *content,
        Auth:       FramedContentAuthData{Signature: signature},
    }, nil
}

// ValSem010, and ValSem009 for commits. any failure is an error; nothing here
// returns a bool a caller could ignore.
func VerifyAuthenticatedContent(crypto CryptoProvider, pub SignaturePublicKey,
    authContent *AuthenticatedContent, groupContext []byte) error {

    if len(authContent.Auth.Signature) == 0 {
        return ValSem(ValSem010, ErrBadSignature)
    }
    tbs, err := FramedContentTBSBytes(authContent.WireFormat, &authContent.Content, groupContext)
    if err != nil {
        return err
    }
    if err := crypto.VerifyWithLabel(pub, framedContentTBSLabel, tbs, authContent.Auth.Signature); err != nil {
        return ValSem(ValSem010, ErrBadSignature)
    }
    if authContent.Content.ContentType == ContentTypeCommit && len(authContent.Auth.ConfirmationTag) == 0 {
        return ValSem(ValSem009, ErrMissingConfirmationTag)
    }
    return nil
}
```

`crypto.VerifyWithLabel` already returns an error rather than a bool (guardrail G7); it is
collapsed to ValSem010 here so a caller cannot distinguish a malformed signature from a wrong key,
and p2's own `ErrCryptoBadSignature` never escapes the crypto layer.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestFramedContentTBS|TestSignAndVerifyAuthenticatedContent|TestAuthenticatedContentRefusesForgedSignature' -v`
Expected: PASS — five tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_preimage.go mls/framing_protect.go mls/framing_protect_test.go
git ls-files | wc -l   # MUST be previous + 2
git commit -m "feat(mls): FramedContentTBS preimage, sign and verify (ValSem010)"
```

---

### Task 6: `AuthenticatedContentTBM` and the membership tag (ValSem007, ValSem008)

**Files:**
- Modify: `connect/mls/framing_preimage.go`
- Modify: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: `Mac(key []byte, data []byte) []byte`, `MacVerify(key []byte, data []byte, tag []byte) bool`,
  `HashSize() int` — methods on p2's `CryptoProvider` (wave 1);
  `func ValSem(code ValSemCode, detail error) error`, the codes `ValSem007`/`ValSem008` and the
  sentinels `ErrMissingMembershipTag`, `ErrBadMembershipTag` (p8, wave 1). Tasks 1–5.
- Produces:
  `AuthenticatedContentTBMBytes(authContent *AuthenticatedContent, groupContext []byte) ([]byte, error)`,
  `ComputeMembershipTag(crypto CryptoProvider, membershipKey []byte, authContent *AuthenticatedContent, groupContext []byte) ([]byte, error)`,
  and the unexported `verifyMembershipTag`.

`MacVerify` returns `bool` — it is one of the constant-time primitives, and its result is converted
to `ErrBadMembershipTag` in the same expression. No caller outside this file ever sees a bool (G7).

- [ ] **Step 1: Write the failing test**

```go
// framing_protect_test.go (append)
func TestAuthenticatedContentTBMIsTBSPlusAuth(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, _, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    content := testProposalContent()

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage, content, groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    tbm, err := AuthenticatedContentTBMBytes(authContent, groupContext)
    if err != nil {
        t.Fatalf("tbm: %v", err)
    }
    tbs, err := FramedContentTBSBytes(WireFormatPublicMessage, content, groupContext)
    if err != nil {
        t.Fatalf("tbs: %v", err)
    }
    w := syntax.NewWriter()
    w.WriteRaw(tbs)
    if err := authContent.Auth.MarshalMLS(w, content.ContentType); err != nil {
        t.Fatalf("auth: %v", err)
    }
    want, err := w.Bytes()
    if err != nil {
        t.Fatalf("bytes: %v", err)
    }
    if !bytes.Equal(tbm, want) {
        t.Fatalf("tbm %x, want %x", tbm, want)
    }
}

func TestMembershipTagCoversTheConfirmationTag(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, _, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    membershipKey := bytes.Repeat([]byte{0x5a}, crypto.HashSize())

    content := testMemberContent()
    content.ContentType = ContentTypeCommit
    content.ApplicationData = nil
    content.Commit = &Commit{}
    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage, content, groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }

    authContent.Auth.ConfirmationTag = bytes.Repeat([]byte{0x01}, crypto.HashSize())
    first, err := ComputeMembershipTag(crypto, membershipKey, authContent, groupContext)
    if err != nil {
        t.Fatalf("tag: %v", err)
    }
    authContent.Auth.ConfirmationTag = bytes.Repeat([]byte{0x02}, crypto.HashSize())
    second, err := ComputeMembershipTag(crypto, membershipKey, authContent, groupContext)
    if err != nil {
        t.Fatalf("tag: %v", err)
    }
    if bytes.Equal(first, second) {
        t.Fatal("membership tag does not cover the confirmation tag")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestAuthenticatedContentTBM|TestMembershipTagCovers' -v`
Expected: FAIL — `undefined: AuthenticatedContentTBMBytes`, `undefined: ComputeMembershipTag`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_preimage.go (append)

// the bytes the membership tag MACs, RFC 9420 §6.2: the signature preimage
// followed by the auth data, so a membership tag over a commit covers that
// commit's confirmation tag.
func AuthenticatedContentTBMBytes(authContent *AuthenticatedContent, groupContext []byte) ([]byte, error) {
    tbs, err := FramedContentTBSBytes(authContent.WireFormat, &authContent.Content, groupContext)
    if err != nil {
        return nil, err
    }
    w := syntax.NewWriter()
    w.WriteRaw(tbs)
    if err := authContent.Auth.MarshalMLS(w, authContent.Content.ContentType); err != nil {
        return nil, err
    }
    return w.Bytes()
}
```

```go
// framing_protect.go (append)

// MAC(membership_key, AuthenticatedContentTBM), RFC 9420 §6.2.
func ComputeMembershipTag(crypto CryptoProvider, membershipKey []byte,
    authContent *AuthenticatedContent, groupContext []byte) ([]byte, error) {

    tbm, err := AuthenticatedContentTBMBytes(authContent, groupContext)
    if err != nil {
        return nil, err
    }
    return crypto.Mac(membershipKey, tbm), nil
}

// ValSem007 and ValSem008. constant time through CryptoProvider.MacVerify;
// the bool never escapes this function.
func verifyMembershipTag(crypto CryptoProvider, membershipKey []byte,
    authContent *AuthenticatedContent, groupContext []byte, tag []byte) error {

    if len(tag) == 0 {
        return ValSem(ValSem007, ErrMissingMembershipTag)
    }
    tbm, err := AuthenticatedContentTBMBytes(authContent, groupContext)
    if err != nil {
        return err
    }
    if !crypto.MacVerify(membershipKey, tbm, tag) {
        return ValSem(ValSem008, ErrBadMembershipTag)
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestAuthenticatedContentTBM|TestMembershipTagCovers' -v`
Expected: PASS — two tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_preimage.go mls/framing_protect.go mls/framing_protect_test.go
git ls-files | wc -l
git commit -m "feat(mls): AuthenticatedContentTBM and the membership tag (ValSem007, ValSem008)"
```

---

### Task 7: `PublicMessage` codec, seal and open (ValSem005)

**Files:**
- Modify: `connect/mls/framing.go`
- Modify: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: Tasks 1–6; `func ValSem(code ValSemCode, detail error) error`, the code `ValSem005` and
  the sentinel `ErrApplicationMustBeCiphertext` (p8, wave 1).
- Produces: `PublicMessage`, `(*PublicMessage).MarshalMLS(w *syntax.Writer) error`,
  `(*PublicMessage).UnmarshalMLS(r *syntax.Reader) error`,
  `var _ syntax.Codec = (*PublicMessage)(nil)`,
  `(*PublicMessage).AuthenticatedContent() *AuthenticatedContent`,
  `type SignatureKeyResolver func(sender Sender) (SignaturePublicKey, error)`,
  `StaticSignatureKey(pub SignaturePublicKey) SignatureKeyResolver`,
  `SealPublicMessage(crypto CryptoProvider, membershipKey []byte, authContent *AuthenticatedContent, groupContext []byte) (*PublicMessage, error)`,
  `OpenPublicMessage(crypto CryptoProvider, membershipKey []byte, message *PublicMessage, resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error)`.

**A-ASSUME-4:** v1 puts all handshake traffic in `PrivateMessage` and `group.go:policyCheck` refuses
`PublicMessage` at the group config. This path is implemented in full anyway, because the interop
harness's nightly `-public` matrix and ValSem007/008 require it. It is not dead code; it is code the
product policy does not reach.

- [ ] **Step 1: Write the failing test**

```go
// framing_protect_test.go (append)
func TestPublicMessageSealOpenRoundTrip(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    membershipKey := bytes.Repeat([]byte{0x5a}, crypto.HashSize())

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
        testProposalContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    message, err := SealPublicMessage(crypto, membershipKey, authContent, groupContext)
    if err != nil {
        t.Fatalf("seal: %v", err)
    }

    encoded, err := syntax.Marshal(message)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded PublicMessage
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }

    opened, err := OpenPublicMessage(crypto, membershipKey, &decoded, StaticSignatureKey(pub), groupContext)
    if err != nil {
        t.Fatalf("open: %v", err)
    }
    if opened.Content.Proposal.Remove.Removed != 3 {
        t.Fatalf("opened %+v", opened.Content.Proposal)
    }
}

func TestPublicMessageRefusesApplicationContent(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    membershipKey := bytes.Repeat([]byte{0x5a}, crypto.HashSize())

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
        testMemberContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    _, err = SealPublicMessage(crypto, membershipKey, authContent, groupContext)
    if !errors.Is(err, ErrApplicationMustBeCiphertext) {
        t.Fatalf("seal: got %v, want ErrApplicationMustBeCiphertext", err)
    }

    // a hostile peer that hands us one anyway is refused on receipt
    hostile := &PublicMessage{
        Content:       *testMemberContent(),
        Auth:          authContent.Auth,
        MembershipTag: bytes.Repeat([]byte{0x00}, crypto.HashSize()),
    }
    _, err = OpenPublicMessage(crypto, membershipKey, hostile, StaticSignatureKey(pub), groupContext)
    if !errors.Is(err, ErrApplicationMustBeCiphertext) {
        t.Fatalf("open: got %v, want ErrApplicationMustBeCiphertext", err)
    }
}

func TestPublicMessageRefusesMissingMembershipTag(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    membershipKey := bytes.Repeat([]byte{0x5a}, crypto.HashSize())

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
        testProposalContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    message, err := SealPublicMessage(crypto, membershipKey, authContent, groupContext)
    if err != nil {
        t.Fatalf("seal: %v", err)
    }
    stripped := *message
    stripped.MembershipTag = nil
    _, err = OpenPublicMessage(crypto, membershipKey, &stripped, StaticSignatureKey(pub), groupContext)
    if !errors.Is(err, ErrMissingMembershipTag) {
        t.Fatalf("got %v, want ErrMissingMembershipTag", err)
    }
}

func TestPublicMessageRefusesForgedMembershipTag(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    membershipKey := bytes.Repeat([]byte{0x5a}, crypto.HashSize())

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
        testProposalContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    message, err := SealPublicMessage(crypto, membershipKey, authContent, groupContext)
    if err != nil {
        t.Fatalf("seal: %v", err)
    }

    tampered := *message
    tampered.MembershipTag = append([]byte(nil), message.MembershipTag...)
    tampered.MembershipTag[0] ^= 0x01
    _, err = OpenPublicMessage(crypto, membershipKey, &tampered, StaticSignatureKey(pub), groupContext)
    if !errors.Is(err, ErrBadMembershipTag) {
        t.Fatalf("tampered tag: got %v, want ErrBadMembershipTag", err)
    }

    wrongKey := bytes.Repeat([]byte{0x5b}, crypto.HashSize())
    _, err = OpenPublicMessage(crypto, wrongKey, message, StaticSignatureKey(pub), groupContext)
    if !errors.Is(err, ErrBadMembershipTag) {
        t.Fatalf("wrong key: got %v, want ErrBadMembershipTag", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestPublicMessage' -v`
Expected: FAIL — `undefined: PublicMessage`, `undefined: SealPublicMessage`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing.go (append)

// the cleartext wire format. v1 refuses it by group policy (A-ASSUME-4) but
// implements it in full: the interop harness's -public matrix and ValSem007
// and ValSem008 all live on this path.
type PublicMessage struct {
    Content       FramedContent
    Auth          FramedContentAuthData
    MembershipTag []byte
}

func (self *PublicMessage) MarshalMLS(w *syntax.Writer) error {
    if err := self.Content.MarshalMLS(w); err != nil {
        return err
    }
    if err := self.Auth.MarshalMLS(w, self.Content.ContentType); err != nil {
        return err
    }
    if self.Content.Sender.SenderType == SenderTypeMember {
        if len(self.MembershipTag) == 0 {
            return ValSem(ValSem007, ErrMissingMembershipTag)
        }
        w.WriteOpaque(self.MembershipTag)
    }
    return nil
}

func (self *PublicMessage) UnmarshalMLS(r *syntax.Reader) error {
    *self = PublicMessage{}
    if err := self.Content.UnmarshalMLS(r); err != nil {
        return err
    }
    if err := self.Auth.UnmarshalMLS(r, self.Content.ContentType); err != nil {
        return err
    }
    if self.Content.Sender.SenderType == SenderTypeMember {
        membershipTag, err := r.ReadOpaque()
        if err != nil {
            return err
        }
        self.MembershipTag = membershipTag
    }
    return nil
}

// the wire-format-independent view, for validation and staging.
func (self *PublicMessage) AuthenticatedContent() *AuthenticatedContent {
    return &AuthenticatedContent{
        WireFormat: WireFormatPublicMessage,
        Content:    self.Content,
        Auth:       self.Auth,
    }
}

var _ syntax.Codec = (*PublicMessage)(nil)
```

```go
// framing_protect.go (append)

// resolves the signature public key for a message's sender. a PrivateMessage
// hides its sender until the sender data is decrypted, so the key cannot be
// chosen by the caller in advance; passing a resolver rather than a key is
// what lets Open* verify the signature itself instead of handing back an
// unverified object a caller might act on (G7).
type SignatureKeyResolver func(sender Sender) (SignaturePublicKey, error)

// a resolver that answers with one key regardless of sender. for the test
// vectors, which supply a single signature_pub, and for two-party tests.
func StaticSignatureKey(pub SignaturePublicKey) SignatureKeyResolver {
    return func(sender Sender) (SignaturePublicKey, error) {
        return pub, nil
    }
}

// wraps a signed AuthenticatedContent as a PublicMessage, adding the
// membership tag for member senders. ValSem005.
func SealPublicMessage(crypto CryptoProvider, membershipKey []byte,
    authContent *AuthenticatedContent, groupContext []byte) (*PublicMessage, error) {

    if authContent.Content.ContentType == ContentTypeApplication {
        return nil, ValSem(ValSem005, ErrApplicationMustBeCiphertext)
    }
    if authContent.WireFormat != WireFormatPublicMessage {
        return nil, ErrWireFormatMismatch
    }
    message := &PublicMessage{Content: authContent.Content, Auth: authContent.Auth}
    if authContent.Content.Sender.SenderType == SenderTypeMember {
        tag, err := ComputeMembershipTag(crypto, membershipKey, authContent, groupContext)
        if err != nil {
            return nil, err
        }
        message.MembershipTag = tag
    }
    return message, nil
}

// verifies the membership tag and then the signature. ValSem005, ValSem007,
// ValSem008, ValSem009, ValSem010.
func OpenPublicMessage(crypto CryptoProvider, membershipKey []byte, message *PublicMessage,
    resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error) {

    if message.Content.ContentType == ContentTypeApplication {
        return nil, ValSem(ValSem005, ErrApplicationMustBeCiphertext)
    }
    authContent := message.AuthenticatedContent()
    if message.Content.Sender.SenderType == SenderTypeMember {
        err := verifyMembershipTag(crypto, membershipKey, authContent, groupContext, message.MembershipTag)
        if err != nil {
            return nil, err
        }
    }
    pub, err := resolve(message.Content.Sender)
    if err != nil {
        return nil, err
    }
    if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); err != nil {
        return nil, err
    }
    return authContent, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestPublicMessage' -v`
Expected: PASS — four tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_protect.go mls/framing_protect_test.go
git ls-files | wc -l
git commit -m "feat(mls): PublicMessage codec, seal and open (ValSem005, ValSem007, ValSem008)"
```

---

### Task 8: `PrivateMessage` codec and the two AAD constructions

**Files:**
- Modify: `connect/mls/framing.go`
- Modify: `connect/mls/framing_preimage.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: Tasks 1–3; `(*syntax.Writer).WriteOpaque(bs []byte)`,
  `(*syntax.Reader).ReadOpaque() ([]byte, error)`, `(*syntax.Writer).Bytes() ([]byte, error)`.
- Produces: `PrivateMessage`, `(*PrivateMessage).MarshalMLS(w *syntax.Writer) error`,
  `(*PrivateMessage).UnmarshalMLS(r *syntax.Reader) error`,
  `var _ syntax.Codec = (*PrivateMessage)(nil)`, and the two unexported preimages
  `privateContentAAD(groupId []byte, epoch uint64, contentType ContentType, authenticatedData []byte) ([]byte, error)`
  and `senderDataAAD(groupId []byte, epoch uint64, contentType ContentType) ([]byte, error)`.

The two AADs differ by exactly one field. `SenderDataAAD` **must not** include
`authenticated_data`: the sender data is decrypted before the content, and an AAD that covered a
field the sender-data step has not yet reached would make the two steps mutually dependent. The test
asserts the prefix relationship so the difference cannot be introduced by a copy-paste.

- [ ] **Step 1: Write the failing test**

```go
// framing_test.go (append)
func TestPrivateMessageRoundTrip(t *testing.T) {
    message := PrivateMessage{
        GroupId:             []byte{0x01, 0x02},
        Epoch:               9,
        ContentType:         ContentTypeApplication,
        AuthenticatedData:   []byte{0xaa},
        EncryptedSenderData: []byte{0xbb, 0xcc},
        Ciphertext:          []byte{0xdd, 0xee, 0xff},
    }
    encoded, err := syntax.Marshal(&message)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }

    var decoded PrivateMessage
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

func TestPrivateMessageRejectsReservedContentType(t *testing.T) {
    message := PrivateMessage{GroupId: []byte{0x01}, ContentType: ContentTypeReserved}
    if _, err := syntax.Marshal(&message); !errors.Is(err, ErrUnknownContentType) {
        t.Fatalf("got %v, want ErrUnknownContentType", err)
    }
}

func TestSenderDataAADIsPrivateContentAADWithoutAuthenticatedData(t *testing.T) {
    groupId := []byte{0x01, 0x02}
    authenticatedData := []byte{0xaa, 0xbb}

    senderAAD, err := senderDataAAD(groupId, 9, ContentTypeApplication)
    if err != nil {
        t.Fatalf("sender aad: %v", err)
    }
    contentAAD, err := privateContentAAD(groupId, 9, ContentTypeApplication, authenticatedData)
    if err != nil {
        t.Fatalf("content aad: %v", err)
    }
    if !bytes.HasPrefix(contentAAD, senderAAD) {
        t.Fatalf("content aad %x does not start with sender aad %x", contentAAD, senderAAD)
    }
    if bytes.Contains(senderAAD, authenticatedData) {
        t.Fatal("authenticated_data leaked into SenderDataAAD")
    }
    if len(contentAAD) <= len(senderAAD) {
        t.Fatal("content aad does not extend sender aad")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestPrivateMessageRoundTrip|TestPrivateMessageRejectsReserved|TestSenderDataAADIs' -v`
Expected: FAIL — `undefined: PrivateMessage`, `undefined: senderDataAAD`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing.go (append)

// the encrypted wire format, and the only one v1 puts on the wire
// (A-ASSUME-4). the header fields are cleartext because the message server
// orders and prunes on them; they are covered by the content AAD so they
// cannot be altered without breaking decryption.
type PrivateMessage struct {
    GroupId             []byte
    Epoch               uint64
    ContentType         ContentType
    AuthenticatedData   []byte
    EncryptedSenderData []byte
    Ciphertext          []byte
}

func (self *PrivateMessage) MarshalMLS(w *syntax.Writer) error {
    switch self.ContentType {
    case ContentTypeApplication, ContentTypeProposal, ContentTypeCommit:
    default:
        return fmt.Errorf("%w: %d", ErrUnknownContentType, self.ContentType)
    }
    w.WriteOpaque(self.GroupId)
    w.WriteUint64(self.Epoch)
    w.WriteUint8(uint8(self.ContentType))
    w.WriteOpaque(self.AuthenticatedData)
    w.WriteOpaque(self.EncryptedSenderData)
    w.WriteOpaque(self.Ciphertext)
    return nil
}

func (self *PrivateMessage) UnmarshalMLS(r *syntax.Reader) error {
    groupId, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    epoch, err := r.ReadUint64()
    if err != nil {
        return err
    }
    contentType, err := r.ReadUint8()
    if err != nil {
        return err
    }
    switch ContentType(contentType) {
    case ContentTypeApplication, ContentTypeProposal, ContentTypeCommit:
    default:
        return fmt.Errorf("%w: %d", ErrUnknownContentType, contentType)
    }
    authenticatedData, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    encryptedSenderData, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    ciphertext, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    *self = PrivateMessage{
        GroupId:             groupId,
        Epoch:               epoch,
        ContentType:         ContentType(contentType),
        AuthenticatedData:   authenticatedData,
        EncryptedSenderData: encryptedSenderData,
        Ciphertext:          ciphertext,
    }
    return nil
}

var _ syntax.Codec = (*PrivateMessage)(nil)
```

```go
// framing_preimage.go (append)

// SenderDataAAD, RFC 9420 §6.3.2. deliberately WITHOUT authenticated_data:
// sender data is opened before the content, so its AAD cannot depend on a
// field the content step has not reached yet.
func senderDataAAD(groupId []byte, epoch uint64, contentType ContentType) ([]byte, error) {
    w := syntax.NewWriter()
    w.WriteOpaque(groupId)
    w.WriteUint64(epoch)
    w.WriteUint8(uint8(contentType))
    return w.Bytes()
}

// PrivateContentAAD, RFC 9420 §6.3.1. SenderDataAAD plus authenticated_data,
// which is why the two are written next to each other.
func privateContentAAD(groupId []byte, epoch uint64, contentType ContentType,
    authenticatedData []byte) ([]byte, error) {

    w := syntax.NewWriter()
    w.WriteOpaque(groupId)
    w.WriteUint64(epoch)
    w.WriteUint8(uint8(contentType))
    w.WriteOpaque(authenticatedData)
    return w.Bytes()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestPrivateMessageRoundTrip|TestPrivateMessageRejectsReserved|TestSenderDataAADIs' -v`
Expected: PASS — three tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_preimage.go mls/framing_test.go
git ls-files | wc -l
git commit -m "feat(mls): PrivateMessage codec and the SenderData/PrivateContent AADs"
```

---

### Task 9: `SenderData` codec and sender-data encryption (ValSem006)

**Files:**
- Modify: `connect/mls/framing.go`
- Modify: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: `HashSize() int`, `KeySize() int`, `NonceSize() int`,
  `ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte`,
  `AeadSeal(key []byte, nonce []byte, aad []byte, plaintext []byte) ([]byte, error)`,
  `AeadOpen(key []byte, nonce []byte, aad []byte, ciphertext []byte) ([]byte, error)` — methods on
  p2's `CryptoProvider` (wave 1);
  **`func SenderDataKeyNonce(crypto CryptoProvider, senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error)`**
  from p4 (wave 2); `syntax.Marshal`, `syntax.Unmarshal`;
  `func ValSem(code ValSemCode, detail error) error`, the code `ValSem006` and the sentinel
  `ErrDecryptFailed` (p8, wave 1). Tasks 1, 8.
- Produces: `SenderData`, `(*SenderData).MarshalMLS(w *syntax.Writer) error`,
  `(*SenderData).UnmarshalMLS(r *syntax.Reader) error`, `var _ syntax.Codec = (*SenderData)(nil)`,
  and the unexported `sealSenderData(...)`, `openSenderData(...)`.

**The §6.3.2 derivation is p4's, and this task deletes its own copy.** Registry §5.5 assigns
`SenderDataKeyNonce` to p4, exported and with an error return, because `secret-tree.json` is its
only vector coverage and the untested duplicate was the one this plan's encrypt path called. The
private `senderDataKeyNonce` that used to live here is gone; `sealSenderData` and `openSenderData`
call p4's exported form.

**The trap this task still owns, as a regression test against p4's implementation:**
`ciphertext_sample = ciphertext[0..KDF.Nh-1]`, and when the ciphertext is **shorter** than `KDF.Nh`
the whole ciphertext is the sample. An implementation that slices unconditionally panics on a short
message; one that pads to `Nh` derives a different key from every peer. Both cases stay tested here
even though the code under test is p4's — this plan is the caller that gets it wrong if p4 drifts.

- [ ] **Step 1: Write the failing test**

```go
// framing_protect_test.go (append)
func TestSenderDataRoundTrip(t *testing.T) {
    senderData := SenderData{
        LeafIndex:  1,
        Generation: 7,
        ReuseGuard: [4]byte{0xde, 0xad, 0xbe, 0xef},
    }
    encoded, err := syntax.Marshal(&senderData)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    want := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xef}
    if !bytes.Equal(encoded, want) {
        t.Fatalf("encoded %x, want %x", encoded, want)
    }
    var decoded SenderData
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded != senderData {
        t.Fatalf("decoded %+v, want %+v", decoded, senderData)
    }
}

// a regression test against the key-schedule plan's SenderDataKeyNonce, not
// against code in this plan. this is the caller that breaks if it drifts.
func TestCiphertextSampleIsBoundedByHashSize(t *testing.T) {
    crypto := newTestCrypto(t)
    secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())

    long := bytes.Repeat([]byte{0xab}, crypto.HashSize()+40)
    keyLong, nonceLong, err := SenderDataKeyNonce(crypto, secret, long)
    if err != nil {
        t.Fatalf("long ciphertext: %v", err)
    }
    keyTrunc, nonceTrunc, err := SenderDataKeyNonce(crypto, secret, long[:crypto.HashSize()])
    if err != nil {
        t.Fatalf("truncated ciphertext: %v", err)
    }
    if !bytes.Equal(keyLong, keyTrunc) || !bytes.Equal(nonceLong, nonceTrunc) {
        t.Fatal("sample is not truncated to KDF.Nh")
    }

    // a ciphertext shorter than KDF.Nh must not panic and must use the whole thing
    short := []byte{0x01, 0x02, 0x03}
    keyShort, nonceShort, err := SenderDataKeyNonce(crypto, secret, short)
    if err != nil {
        t.Fatalf("short ciphertext: %v", err)
    }
    if len(keyShort) != crypto.KeySize() || len(nonceShort) != crypto.NonceSize() {
        t.Fatalf("short sample produced key %d nonce %d", len(keyShort), len(nonceShort))
    }
    keyWhole := crypto.ExpandWithLabel(secret, "key", short, crypto.KeySize())
    if !bytes.Equal(keyShort, keyWhole) {
        t.Fatal("short ciphertext sample was padded or truncated")
    }
}

func TestSenderDataSealOpen(t *testing.T) {
    crypto := newTestCrypto(t)
    secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())
    ciphertext := bytes.Repeat([]byte{0xab}, 64)
    header := &PrivateMessage{
        GroupId:     []byte{0x01, 0x02},
        Epoch:       9,
        ContentType: ContentTypeApplication,
    }
    senderData := SenderData{LeafIndex: 1, Generation: 7, ReuseGuard: [4]byte{1, 2, 3, 4}}

    sealed, err := sealSenderData(crypto, secret, &senderData, header, ciphertext)
    if err != nil {
        t.Fatalf("seal: %v", err)
    }
    opened, err := openSenderData(crypto, secret, sealed, header, ciphertext)
    if err != nil {
        t.Fatalf("open: %v", err)
    }
    if *opened != senderData {
        t.Fatalf("opened %+v, want %+v", *opened, senderData)
    }

    // the epoch is in the AAD, so a rewritten header fails to open
    rewritten := *header
    rewritten.Epoch = 10
    if _, err := openSenderData(crypto, secret, sealed, &rewritten, ciphertext); !errors.Is(err, ErrDecryptFailed) {
        t.Fatalf("rewritten epoch: got %v, want ErrDecryptFailed", err)
    }

    // the ciphertext keys the sender data, so a rewritten ciphertext fails too
    other := bytes.Repeat([]byte{0xcd}, 64)
    if _, err := openSenderData(crypto, secret, sealed, header, other); !errors.Is(err, ErrDecryptFailed) {
        t.Fatalf("rewritten ciphertext: got %v, want ErrDecryptFailed", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestSenderData|TestCiphertextSample' -v`
Expected: FAIL — `undefined: SenderData`, `undefined: sealSenderData`. If it instead fails with
`undefined: SenderDataKeyNonce`, the key-schedule plan has not merged §5.5 yet and this task is
blocked, not stubbed: a second copy of the derivation is exactly what the registry deleted.

- [ ] **Step 3: Write minimal implementation**

```go
// framing.go (append)

// who sent a PrivateMessage and at which ratchet generation, encrypted under a
// key derived from the content ciphertext so that an observer who does not
// hold sender_data_secret cannot link messages to a leaf.
type SenderData struct {
    LeafIndex  LeafIndex
    Generation uint32
    ReuseGuard [4]byte
}

func (self *SenderData) MarshalMLS(w *syntax.Writer) error {
    w.WriteUint32(uint32(self.LeafIndex))
    w.WriteUint32(self.Generation)
    w.WriteRaw(self.ReuseGuard[:])
    return nil
}

func (self *SenderData) UnmarshalMLS(r *syntax.Reader) error {
    leafIndex, err := r.ReadUint32()
    if err != nil {
        return err
    }
    generation, err := r.ReadUint32()
    if err != nil {
        return err
    }
    reuseGuard, err := r.ReadRaw(4)
    if err != nil {
        return err
    }
    *self = SenderData{LeafIndex: LeafIndex(leafIndex), Generation: generation}
    copy(self.ReuseGuard[:], reuseGuard)
    return nil
}

var _ syntax.Codec = (*SenderData)(nil)
```

```go
// framing_protect.go (append)

// RFC 9420 §6.3.2. the key and nonce come from the key-schedule plan's
// SenderDataKeyNonce, which is the copy secret-tree.json covers; there is no
// second derivation in this package.
func sealSenderData(crypto CryptoProvider, senderDataSecret []byte, senderData *SenderData,
    header *PrivateMessage, ciphertext []byte) ([]byte, error) {

    plaintext, err := syntax.Marshal(senderData)
    if err != nil {
        return nil, err
    }
    aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
    if err != nil {
        return nil, err
    }
    key, nonce, err := SenderDataKeyNonce(crypto, senderDataSecret, ciphertext)
    if err != nil {
        return nil, err
    }
    return crypto.AeadSeal(key, nonce, aad, plaintext)
}

func openSenderData(crypto CryptoProvider, senderDataSecret []byte, encryptedSenderData []byte,
    header *PrivateMessage, ciphertext []byte) (*SenderData, error) {

    aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
    if err != nil {
        return nil, err
    }
    key, nonce, err := SenderDataKeyNonce(crypto, senderDataSecret, ciphertext)
    if err != nil {
        return nil, err
    }
    plaintext, err := crypto.AeadOpen(key, nonce, aad, encryptedSenderData)
    if err != nil {
        // p2's ErrAeadOpen never escapes: every open failure on this path is
        // ValSem006, and distinguishing them would be a decryption oracle.
        return nil, ValSem(ValSem006, ErrDecryptFailed)
    }
    senderData := &SenderData{}
    if err := syntax.Unmarshal(plaintext, senderData); err != nil {
        return nil, err
    }
    return senderData, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestSenderData|TestCiphertextSample' -v`
Expected: PASS — three tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_protect.go mls/framing_protect_test.go
git ls-files | wc -l
git commit -m "feat(mls): SenderData codec and sender-data encryption over the shared key derivation"
```

---

### Task 10: `PrivateMessageContent` and padding (ValSem011)

**Files:**
- Modify: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: Tasks 1–3, 8; `(*syntax.Reader).Remaining() int`,
  `(*syntax.Reader).ReadRaw(n int) ([]byte, error)` — there is no `(*Reader).Rest()`, so the
  padding tail is consumed explicitly; `func ValSem(code ValSemCode, detail error) error`, the code
  `ValSem011` and the sentinel `ErrNonZeroPadding` (p8, wave 1).
- Produces: `const PaddingSizeV1 = 0`, and the unexported
  `marshalPrivateMessageContent(content *FramedContent, auth *FramedContentAuthData, paddingSize int) ([]byte, error)`,
  `marshalPrivateMessageContentWithPadding(content *FramedContent, auth *FramedContentAuthData, padding []byte) ([]byte, error)`,
  `unmarshalPrivateMessageContent(plaintext []byte, header *PrivateMessage, sender Sender) (*FramedContent, *FramedContentAuthData, error)`.

The `WithPadding` variant exists so Task 20's `sealFramedContentWithPaddingForTest` seam can emit
the **non-zero** padding p8's ValSem011 test needs. The zero-padding entry point delegates to it, so
there is one serializer, not two.

**Padding policy.** `PaddingSizeV1 = 0`, because `connect/message` already pads `ct_body` to a size
bucket (MASTER §8: `octet_length(ct_body) MUST equal size_bucket_bytes[b] + 16 exactly`). MLS-level
padding would be padding inside padding and would push wraps up a rung on a ladder MASTER
deliberately did not renumber. The **decoder** still accepts any all-zero padding length, because
peers in the interop harness emit non-zero padding, and rejecting it would fail the harness.

The `padding` field has no length prefix — it is whatever remains after the content and the auth
data. That is why full-consumption is not asserted here and the remainder is checked for zeros
instead.

- [ ] **Step 1: Write the failing test**

```go
// framing_protect_test.go (append)
func TestPrivateMessageContentRoundTripWithPadding(t *testing.T) {
    content := testMemberContent()
    auth := &FramedContentAuthData{Signature: []byte{0x01, 0x02}}
    header := &PrivateMessage{
        GroupId:           content.GroupId,
        Epoch:             content.Epoch,
        ContentType:       content.ContentType,
        AuthenticatedData: content.AuthenticatedData,
    }

    for _, paddingSize := range []int{0, 1, 64} {
        plaintext, err := marshalPrivateMessageContent(content, auth, paddingSize)
        if err != nil {
            t.Fatalf("padding %d: marshal: %v", paddingSize, err)
        }
        unpadded, err := marshalPrivateMessageContent(content, auth, 0)
        if err != nil {
            t.Fatalf("padding %d: marshal unpadded: %v", paddingSize, err)
        }
        if len(plaintext) != len(unpadded)+paddingSize {
            t.Fatalf("padding %d: length %d, want %d", paddingSize, len(plaintext), len(unpadded)+paddingSize)
        }

        decodedContent, decodedAuth, err := unmarshalPrivateMessageContent(plaintext, header, content.Sender)
        if err != nil {
            t.Fatalf("padding %d: unmarshal: %v", paddingSize, err)
        }
        if !bytes.Equal(decodedContent.ApplicationData, content.ApplicationData) {
            t.Fatalf("padding %d: application data %q", paddingSize, decodedContent.ApplicationData)
        }
        if !bytes.Equal(decodedAuth.Signature, auth.Signature) {
            t.Fatalf("padding %d: signature %x", paddingSize, decodedAuth.Signature)
        }
        if decodedContent.Sender != content.Sender {
            t.Fatalf("padding %d: sender %+v", paddingSize, decodedContent.Sender)
        }
    }
}

func TestPrivateMessageContentRefusesNonZeroPadding(t *testing.T) {
    content := testMemberContent()
    auth := &FramedContentAuthData{Signature: []byte{0x01, 0x02}}
    header := &PrivateMessage{
        GroupId:           content.GroupId,
        Epoch:             content.Epoch,
        ContentType:       content.ContentType,
        AuthenticatedData: content.AuthenticatedData,
    }
    plaintext, err := marshalPrivateMessageContent(content, auth, 16)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }

    // any non-zero byte anywhere in the padding is a rejection
    for _, offset := range []int{0, 7, 15} {
        tampered := append([]byte(nil), plaintext...)
        tampered[len(tampered)-16+offset] = 0x01
        _, _, err := unmarshalPrivateMessageContent(tampered, header, content.Sender)
        if !errors.Is(err, ErrNonZeroPadding) {
            t.Fatalf("offset %d: got %v, want ErrNonZeroPadding", offset, err)
        }
    }
}

func TestPrivateMessageContentRejectsNegativePadding(t *testing.T) {
    content := testMemberContent()
    auth := &FramedContentAuthData{Signature: []byte{0x01}}
    _, err := marshalPrivateMessageContent(content, auth, -1)
    if !errors.Is(err, ErrInvalidPaddingSize) {
        t.Fatalf("got %v, want ErrInvalidPaddingSize", err)
    }
}

func TestPaddingSizeV1IsZeroBecauseTheRecordLayerPads(t *testing.T) {
    if PaddingSizeV1 != 0 {
        t.Fatalf("PaddingSizeV1 = %d; connect/message pads ct_body to a size bucket, so MLS padding must be 0", PaddingSizeV1)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestPrivateMessageContent|TestPaddingSizeV1' -v`
Expected: FAIL — `undefined: marshalPrivateMessageContent`, `undefined: PaddingSizeV1`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_protect.go (append)

// v1 emits no MLS-level padding: connect/message pads ct_body to a size bucket
// (MASTER §8), so padding here would be padding inside padding and would push
// every epoch wrap up a rung on a ladder MASTER deliberately did not renumber.
// the decoder still accepts any all-zero padding a peer sends.
const PaddingSizeV1 = 0

// PrivateMessageContent, RFC 9420 §6.3.1: the content arm, the auth data, then
// zero padding with no length prefix of its own.
func marshalPrivateMessageContent(content *FramedContent, auth *FramedContentAuthData,
    paddingSize int) ([]byte, error) {

    if paddingSize < 0 {
        return nil, ErrInvalidPaddingSize
    }
    return marshalPrivateMessageContentWithPadding(content, auth, make([]byte, paddingSize))
}

// the same serializer with caller-supplied padding bytes. only the test seams
// in framing_group_seams.go pass anything but zeros; nothing on the production
// path can reach a non-zero tail.
func marshalPrivateMessageContentWithPadding(content *FramedContent,
    auth *FramedContentAuthData, padding []byte) ([]byte, error) {

    if err := content.checkArms(); err != nil {
        return nil, err
    }
    w := syntax.NewWriter()
    switch content.ContentType {
    case ContentTypeApplication:
        w.WriteOpaque(content.ApplicationData)
    case ContentTypeProposal:
        if err := content.Proposal.MarshalMLS(w); err != nil {
            return nil, err
        }
    case ContentTypeCommit:
        if err := content.Commit.MarshalMLS(w); err != nil {
            return nil, err
        }
    }
    if err := auth.MarshalMLS(w, content.ContentType); err != nil {
        return nil, err
    }
    w.WriteRaw(padding)
    return w.Bytes()
}

// rebuilds the FramedContent from the cleartext header plus the decrypted
// body. ValSem011: everything after the auth data is padding and MUST be zero.
func unmarshalPrivateMessageContent(plaintext []byte, header *PrivateMessage,
    sender Sender) (*FramedContent, *FramedContentAuthData, error) {

    content := &FramedContent{
        GroupId:           header.GroupId,
        Epoch:             header.Epoch,
        Sender:            sender,
        AuthenticatedData: header.AuthenticatedData,
        ContentType:       header.ContentType,
    }
    r := syntax.NewReader(plaintext)
    switch header.ContentType {
    case ContentTypeApplication:
        applicationData, err := r.ReadOpaque()
        if err != nil {
            return nil, nil, err
        }
        content.ApplicationData = applicationData
    case ContentTypeProposal:
        content.Proposal = &Proposal{}
        if err := content.Proposal.UnmarshalMLS(r); err != nil {
            return nil, nil, err
        }
    case ContentTypeCommit:
        content.Commit = &Commit{}
        if err := content.Commit.UnmarshalMLS(r); err != nil {
            return nil, nil, err
        }
    default:
        return nil, nil, fmt.Errorf("%w: %d", ErrUnknownContentType, header.ContentType)
    }

    auth := &FramedContentAuthData{}
    if err := auth.UnmarshalMLS(r, header.ContentType); err != nil {
        return nil, nil, err
    }

    // the padding is whatever remains; ReadRaw(Remaining()) consumes it
    // explicitly, and accumulating rather than early-returning keeps the check
    // from leaking the position of the first non-zero byte.
    padding, err := r.ReadRaw(r.Remaining())
    if err != nil {
        return nil, nil, err
    }
    var accumulated byte
    for _, b := range padding {
        accumulated |= b
    }
    if accumulated != 0 {
        return nil, nil, ValSem(ValSem011, ErrNonZeroPadding)
    }
    return content, auth, nil
}
```

`framing_protect.go` now needs `"fmt"` in its import block alongside `syntax`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestPrivateMessageContent|TestPaddingSizeV1' -v`
Expected: PASS — four tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_protect.go mls/framing_protect_test.go
git ls-files | wc -l
git commit -m "feat(mls): PrivateMessageContent and zero-padding enforcement (ValSem011)"
```

---

### Task 11: `MessageKeySource`, the reuse guard, and `PrivateMessage` seal/open (ValSem006)

**Files:**
- Modify: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: from p4 (wave 2) the `*SecretTree` methods
  `NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)`,
  `MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)`,
  `EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)`;
  `Random(n int) []byte`, `AeadSeal`, `AeadOpen` on p2's `CryptoProvider`;
  `func ValSem(code ValSemCode, detail error) error`, the code `ValSem006` and the sentinel
  `ErrDecryptFailed` (p8, wave 1). Tasks 1–10.
- Produces:
  ```go
  type MessageKeySource interface {
      NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
      MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
      EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
  }
  var _ MessageKeySource = (*SecretTree)(nil)

  func SealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
      authContent *AuthenticatedContent, paddingSize int) (*PrivateMessage, error)
  func OpenPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
      message *PrivateMessage, resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error)
  ```
  plus the unexported `applyReuseGuard` and
  `sealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte, authContent *AuthenticatedContent, padding []byte) (*PrivateMessage, error)`.

**`var _ MessageKeySource = (*SecretTree)(nil)` is the point of this task's contract.** Registry
§5.5 assigns the three methods to p4 and requires this assertion here, so a mismatch between the
interface this plan declares and the implementation p4 ships fails at build rather than at the
message-protection vector family.

**The trap:** the reuse guard XORs the **first four bytes** of the ratchet nonce, and the guarded
nonce must not be written back into the secret tree's storage. `applyReuseGuard` copies.

- [ ] **Step 1: Write the failing test**

```go
// framing_protect_test.go (append)

// a MessageKeySource that hands out one deterministic key per (contentType,
// leaf, generation) and records erasures. the real one is the secret tree.
type fixedKeySource struct {
    crypto     CryptoProvider
    generation map[ContentType]uint32
    erased     map[string]bool
}

func newFixedKeySource(crypto CryptoProvider) *fixedKeySource {
    return &fixedKeySource{
        crypto:     crypto,
        generation: map[ContentType]uint32{},
        erased:     map[string]bool{},
    }
}

func (self *fixedKeySource) derive(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte) {
    seed := []byte{byte(contentType), byte(leaf), byte(generation)}
    key = self.crypto.ExpandWithLabel(bytes.Repeat([]byte{0x77}, self.crypto.HashSize()),
        "test-key", seed, self.crypto.KeySize())
    nonce = self.crypto.ExpandWithLabel(bytes.Repeat([]byte{0x77}, self.crypto.HashSize()),
        "test-nonce", seed, self.crypto.NonceSize())
    return key, nonce
}

func (self *fixedKeySource) NextMessageKey(contentType ContentType, leaf LeafIndex) ([]byte, []byte, uint32, error) {
    generation := self.generation[contentType]
    self.generation[contentType] = generation + 1
    key, nonce := self.derive(contentType, leaf, generation)
    return key, nonce, generation, nil
}

func (self *fixedKeySource) MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) ([]byte, []byte, error) {
    key, nonce := self.derive(contentType, leaf, generation)
    return key, nonce, nil
}

func (self *fixedKeySource) EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32) {
    self.erased[fmt.Sprintf("%d/%d/%d", contentType, leaf, generation)] = true
}

func TestApplyReuseGuardXorsFirstFourBytesAndCopies(t *testing.T) {
    nonce := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
    original := append([]byte(nil), nonce...)
    guarded := applyReuseGuard(nonce, [4]byte{0xff, 0xff, 0xff, 0xff})

    if !bytes.Equal(nonce, original) {
        t.Fatal("applyReuseGuard mutated the ratchet nonce in place")
    }
    want := []byte{0xff, 0xfe, 0xfd, 0xfc, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
    if !bytes.Equal(guarded, want) {
        t.Fatalf("guarded %x, want %x", guarded, want)
    }
}

func TestPrivateMessageSealOpenRoundTrip(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    senderDataSecret := bytes.Repeat([]byte{0x33}, crypto.HashSize())

    for _, content := range []*FramedContent{testMemberContent(), testProposalContent()} {
        authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage, content, groupContext)
        if err != nil {
            t.Fatalf("sign: %v", err)
        }
        sealKeys := newFixedKeySource(crypto)
        message, err := SealPrivateMessage(crypto, sealKeys, senderDataSecret, authContent, PaddingSizeV1)
        if err != nil {
            t.Fatalf("seal: %v", err)
        }
        if len(sealKeys.erased) != 1 {
            t.Fatalf("erased %d keys, want 1", len(sealKeys.erased))
        }
        if bytes.Contains(message.Ciphertext, content.ApplicationData) && content.ApplicationData != nil {
            t.Fatal("plaintext visible in the ciphertext")
        }

        encoded, err := syntax.Marshal(message)
        if err != nil {
            t.Fatalf("marshal: %v", err)
        }
        var decoded PrivateMessage
        if err := syntax.Unmarshal(encoded, &decoded); err != nil {
            t.Fatalf("unmarshal: %v", err)
        }

        opened, err := OpenPrivateMessage(crypto, newFixedKeySource(crypto), senderDataSecret,
            &decoded, StaticSignatureKey(pub), groupContext)
        if err != nil {
            t.Fatalf("open: %v", err)
        }
        if opened.Content.Sender != content.Sender {
            t.Fatalf("sender %+v, want %+v", opened.Content.Sender, content.Sender)
        }
        if !bytes.Equal(opened.Content.ApplicationData, content.ApplicationData) {
            t.Fatalf("application data %q, want %q", opened.Content.ApplicationData, content.ApplicationData)
        }
    }
}

func TestSealPrivateMessageRefusesNonMemberSender(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, _, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    content := testProposalContent()
    content.Sender = Sender{SenderType: SenderTypeNewMemberProposal}
    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage, content, nil)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    _, err = SealPrivateMessage(crypto, newFixedKeySource(crypto),
        bytes.Repeat([]byte{0x33}, crypto.HashSize()), authContent, PaddingSizeV1)
    if !errors.Is(err, ErrSenderNotMember) {
        t.Fatalf("got %v, want ErrSenderNotMember", err)
    }
}

func TestPrivateMessageRefusesTamperedCiphertext(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)
    senderDataSecret := bytes.Repeat([]byte{0x33}, crypto.HashSize())

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage,
        testMemberContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    message, err := SealPrivateMessage(crypto, newFixedKeySource(crypto), senderDataSecret,
        authContent, PaddingSizeV1)
    if err != nil {
        t.Fatalf("seal: %v", err)
    }

    // a flipped ciphertext byte: the sender data keys off the ciphertext, so
    // this fails at the sender-data step
    tampered := *message
    tampered.Ciphertext = append([]byte(nil), message.Ciphertext...)
    tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0x01
    _, err = OpenPrivateMessage(crypto, newFixedKeySource(crypto), senderDataSecret,
        &tampered, StaticSignatureKey(pub), groupContext)
    if !errors.Is(err, ErrDecryptFailed) {
        t.Fatalf("flipped ciphertext: got %v, want ErrDecryptFailed", err)
    }

    // a rewritten authenticated_data is in the content AAD only, so it passes
    // the sender-data step and fails the content step. both are ValSem006.
    rewritten := *message
    rewritten.AuthenticatedData = []byte{0xff}
    _, err = OpenPrivateMessage(crypto, newFixedKeySource(crypto), senderDataSecret,
        &rewritten, StaticSignatureKey(pub), groupContext)
    if !errors.Is(err, ErrDecryptFailed) {
        t.Fatalf("rewritten authenticated_data: got %v, want ErrDecryptFailed", err)
    }

    // the wrong sender_data_secret
    _, err = OpenPrivateMessage(crypto, newFixedKeySource(crypto),
        bytes.Repeat([]byte{0x34}, crypto.HashSize()), message, StaticSignatureKey(pub), groupContext)
    if !errors.Is(err, ErrDecryptFailed) {
        t.Fatalf("wrong sender_data_secret: got %v, want ErrDecryptFailed", err)
    }
}
```

`framing_protect_test.go` now needs `"fmt"` in its import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestApplyReuseGuard|TestPrivateMessageSealOpen|TestSealPrivateMessageRefuses|TestPrivateMessageRefusesTamperedCiphertext' -v`
Expected: FAIL — `undefined: applyReuseGuard`, `undefined: SealPrivateMessage`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_protect.go (append)

// the per-sender message keys of RFC 9420 §9. ContentTypeApplication selects
// the application ratchet; proposal and commit select the handshake ratchet.
// the secret tree implements this and owns the skipped-key window; framing
// never holds a key beyond the call it was handed in.
type MessageKeySource interface {
    NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
    MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
    EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
}

// the secret tree is the production implementation. this assertion is why the
// interface and the implementation cannot drift apart silently.
var _ MessageKeySource = (*SecretTree)(nil)

// RFC 9420 §6.3.1. returns a copy: writing the guarded nonce back over the
// ratchet's nonce would make the generation undecryptable by anyone else.
func applyReuseGuard(nonce []byte, reuseGuard [4]byte) []byte {
    guarded := make([]byte, len(nonce))
    copy(guarded, nonce)
    for i := 0; i < len(reuseGuard) && i < len(guarded); i += 1 {
        guarded[i] ^= reuseGuard[i]
    }
    return guarded
}

// encrypts a signed AuthenticatedContent as a PrivateMessage. the content is
// encrypted first because the sender data is keyed off the content ciphertext.
func SealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
    authContent *AuthenticatedContent, paddingSize int) (*PrivateMessage, error) {

    if paddingSize < 0 {
        return nil, ErrInvalidPaddingSize
    }
    return sealPrivateMessage(crypto, keys, senderDataSecret, authContent, make([]byte, paddingSize))
}

// the same seal with caller-supplied padding bytes, so the test seams in
// framing_group_seams.go can emit the non-zero padding ValSem011 needs without
// a second copy of the §6.3.1 encrypt path.
func sealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
    authContent *AuthenticatedContent, padding []byte) (*PrivateMessage, error) {

    if authContent.WireFormat != WireFormatPrivateMessage {
        return nil, ErrWireFormatMismatch
    }
    content := &authContent.Content
    if content.Sender.SenderType != SenderTypeMember {
        return nil, ErrSenderNotMember
    }

    plaintext, err := marshalPrivateMessageContentWithPadding(content, &authContent.Auth, padding)
    if err != nil {
        return nil, err
    }
    key, nonce, generation, err := keys.NextMessageKey(content.ContentType, content.Sender.LeafIndex)
    if err != nil {
        return nil, err
    }

    var reuseGuard [4]byte
    copy(reuseGuard[:], crypto.Random(len(reuseGuard)))

    aad, err := privateContentAAD(content.GroupId, content.Epoch, content.ContentType,
        content.AuthenticatedData)
    if err != nil {
        return nil, err
    }
    ciphertext, err := crypto.AeadSeal(key, applyReuseGuard(nonce, reuseGuard), aad, plaintext)
    if err != nil {
        return nil, err
    }
    keys.EraseMessageKey(content.ContentType, content.Sender.LeafIndex, generation)

    message := &PrivateMessage{
        GroupId:           content.GroupId,
        Epoch:             content.Epoch,
        ContentType:       content.ContentType,
        AuthenticatedData: content.AuthenticatedData,
        Ciphertext:        ciphertext,
    }
    senderData := &SenderData{
        LeafIndex:  content.Sender.LeafIndex,
        Generation: generation,
        ReuseGuard: reuseGuard,
    }
    encryptedSenderData, err := sealSenderData(crypto, senderDataSecret, senderData, message, ciphertext)
    if err != nil {
        return nil, err
    }
    message.EncryptedSenderData = encryptedSenderData
    return message, nil
}

// decrypts a PrivateMessage and verifies the sender's signature. ValSem006,
// ValSem010, ValSem011. the signature is verified here rather than by the
// caller because the sender is not known until the sender data is opened.
func OpenPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
    message *PrivateMessage, resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error) {

    senderData, err := openSenderData(crypto, senderDataSecret, message.EncryptedSenderData,
        message, message.Ciphertext)
    if err != nil {
        return nil, err
    }
    sender := Sender{SenderType: SenderTypeMember, LeafIndex: senderData.LeafIndex}

    key, nonce, err := keys.MessageKey(message.ContentType, senderData.LeafIndex, senderData.Generation)
    if err != nil {
        return nil, err
    }
    aad, err := privateContentAAD(message.GroupId, message.Epoch, message.ContentType,
        message.AuthenticatedData)
    if err != nil {
        return nil, err
    }
    plaintext, err := crypto.AeadOpen(key, applyReuseGuard(nonce, senderData.ReuseGuard),
        aad, message.Ciphertext)
    if err != nil {
        return nil, ValSem(ValSem006, ErrDecryptFailed)
    }
    keys.EraseMessageKey(message.ContentType, senderData.LeafIndex, senderData.Generation)

    content, auth, err := unmarshalPrivateMessageContent(plaintext, message, sender)
    if err != nil {
        return nil, err
    }
    authContent := &AuthenticatedContent{
        WireFormat: WireFormatPrivateMessage,
        Content:    *content,
        Auth:       *auth,
    }
    pub, err := resolve(sender)
    if err != nil {
        return nil, err
    }
    if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); err != nil {
        return nil, err
    }
    return authContent, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestApplyReuseGuard|TestPrivateMessageSealOpen|TestSealPrivateMessageRefuses|TestPrivateMessageRefusesTamperedCiphertext' -v`
Expected: PASS — four tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_protect.go mls/framing_protect_test.go
git ls-files | wc -l
git commit -m "feat(mls): MessageKeySource, reuse guard and PrivateMessage seal/open (ValSem006)"
```

---

### Task 12: `Proposal` wire types and `ProposalOrRef`

**Files:**
- Create: `connect/mls/proposal_wire.go`
- Test: `connect/mls/proposal_wire_test.go`

**Interfaces:**
- Consumes, all with `MarshalMLS(w *syntax.Writer) error` / `UnmarshalMLS(r *syntax.Reader) error`:
  `KeyPackage`, `LeafNode`, `Extension` (p5, wave 2) and `PreSharedKeyId` (p4, wave 2). Also
  `type ProposalType uint16` **and its eight constants** (p5 §6.1),
  `func WriteExtensions(w *syntax.Writer, exts []Extension) error`,
  `func ReadExtensions(r *syntax.Reader) ([]Extension, error)` (p5 §6.2),
  `type ProtocolVersion uint16` (p5), `type CipherSuite uint16` (p2), `type LeafIndex uint32` (p3),
  `(*syntax.Reader).Remaining() int`, `(*syntax.Reader).ReadRaw(n int) ([]byte, error)`. Task 1.
- Produces: `Add`, `Update`, `Remove`, `PreSharedKey`, `ReInit`, `ExternalInit`,
  `GroupContextExtensions`, `Proposal` with `MarshalMLS`/`UnmarshalMLS` and
  `var _ syntax.Codec = (*Proposal)(nil)`, `ProposalOrRefType` and its three constants,
  `ProposalRef`, `ProposalOrRef` with `MarshalMLS`/`UnmarshalMLS` and
  `var _ syntax.Codec = (*ProposalOrRef)(nil)`.

**This file declares neither `ProposalType` nor its constants.** They are p5's registry-enum file
(§6.1): three plans declared them independently, and `package mls` is one package, so a second
declaration is a compile error. p5's wave-2 `Capabilities.Proposals []ProposalType` is why they
land there rather than here.

`ProposalType` is **uint16** — the IANA MLS Proposal Types registry is 0x0000–0xFFFF and GREASE
values for proposal types are 0x0A0A…0xEAEA. An 8-bit implementation encodes every proposal one
byte short and fails every vector; the width test is first for that reason, and it now guards p5's
declaration rather than this file's.

**This file is codec only.** It accepts every registered proposal type, including the four the v1
profile refuses, because the `messages` vector family requires `pre_shared_key_proposal`,
`re_init_proposal` and `external_init_proposal` to decode and re-encode byte-exactly. Profile
refusal is `(*Profile).CheckProposalType(t ProposalType) error` (p8 §9.3), called by p7 at the
parse boundary; ValSem401–403 test that function.

**`UnknownType` and `UnknownBody` together are the forge's malformed arm** (registry §7.4). On
decode of an unregistered type both `ProposalType` and `UnknownType` carry the wire value and
`UnknownBody` holds the remaining bytes, so the object re-encodes verbatim and GREASE is "parsed
and ignored, never generated" (Spec A §3.2) at the codec layer. On encode, a non-zero `UnknownType`
overrides the discriminant that goes on the wire, which is how p8's forge emits a registered body
under an unregistered type without a second encoder. This pair is also why p8's request for a
`FramedContent.RawProposal` field was refused: it already exists here.

- [ ] **Step 1: Write the failing test**

```go
// proposal_wire_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func TestProposalTypeIsSixteenBitsOnTheWire(t *testing.T) {
    proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 3}}
    encoded, err := syntax.Marshal(&proposal)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    want := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x03}
    if !bytes.Equal(encoded, want) {
        t.Fatalf("encoded %x, want %x — ProposalType must be uint16", encoded, want)
    }
}

func TestProposalRoundTripRemove(t *testing.T) {
    proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 7}}
    encoded, err := syntax.Marshal(&proposal)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }

    var decoded Proposal
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded.Remove == nil || decoded.Remove.Removed != 7 {
        t.Fatalf("decoded %+v", decoded.Remove)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

func TestProposalCodecAcceptsProfileRefusedTypes(t *testing.T) {
    // the codec is not the profile gate: (*Profile).CheckProposalType refuses
    // these, the codec must round-trip them or the `messages` family fails
    proposal := Proposal{
        ProposalType: ProposalTypeExternalInit,
        ExternalInit: &ExternalInit{KemOutput: []byte{0x01, 0x02, 0x03}},
    }
    encoded, err := syntax.Marshal(&proposal)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded Proposal
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded.ExternalInit == nil || !bytes.Equal(decoded.ExternalInit.KemOutput, []byte{0x01, 0x02, 0x03}) {
        t.Fatalf("decoded %+v", decoded.ExternalInit)
    }
}

func TestProposalPreservesUnknownTypeVerbatim(t *testing.T) {
    // GREASE: parsed and ignored, never generated
    encoded := []byte{0x0a, 0x0a, 0xde, 0xad, 0xbe, 0xef}
    var decoded Proposal
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded.ProposalType != ProposalType(0x0a0a) {
        t.Fatalf("proposal type %04x", decoded.ProposalType)
    }
    if decoded.UnknownType != ProposalType(0x0a0a) {
        t.Fatalf("unknown type %04x", decoded.UnknownType)
    }
    if !bytes.Equal(decoded.UnknownBody, []byte{0xde, 0xad, 0xbe, 0xef}) {
        t.Fatalf("unknown body %x", decoded.UnknownBody)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(reencoded, encoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

// the forge's malformed arm: a registered body under an unregistered
// discriminant, which is what p8's ValSem tests need and what stops a second
// encoder being written to produce it.
func TestProposalUnknownTypeOverridesTheDiscriminant(t *testing.T) {
    proposal := Proposal{
        ProposalType: ProposalTypeRemove,
        Remove:       &Remove{Removed: 3},
        UnknownType:  ProposalType(0x0a0a),
    }
    encoded, err := syntax.Marshal(&proposal)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    want := []byte{0x0a, 0x0a, 0x00, 0x00, 0x00, 0x03}
    if !bytes.Equal(encoded, want) {
        t.Fatalf("encoded %x, want %x", encoded, want)
    }
}

func TestProposalRejectsArmMismatch(t *testing.T) {
    proposal := Proposal{ProposalType: ProposalTypeRemove}
    if _, err := syntax.Marshal(&proposal); !errors.Is(err, ErrContentArmMismatch) {
        t.Fatalf("got %v, want ErrContentArmMismatch", err)
    }
}

func TestProposalOrRefRoundTrip(t *testing.T) {
    cases := []ProposalOrRef{
        {Type: ProposalOrRefTypeProposal, Proposal: &Proposal{
            ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}},
        {Type: ProposalOrRefTypeReference, Reference: ProposalRef{0xaa, 0xbb, 0xcc}},
    }
    for i := range cases {
        encoded, err := syntax.Marshal(&cases[i])
        if err != nil {
            t.Fatalf("case %d: marshal: %v", i, err)
        }
        var decoded ProposalOrRef
        if err := syntax.Unmarshal(encoded, &decoded); err != nil {
            t.Fatalf("case %d: unmarshal: %v", i, err)
        }
        reencoded, err := syntax.Marshal(&decoded)
        if err != nil {
            t.Fatalf("case %d: re-marshal: %v", i, err)
        }
        if !bytes.Equal(encoded, reencoded) {
            t.Fatalf("case %d: re-encoded %x, want %x", i, reencoded, encoded)
        }
    }
}

func TestProposalOrRefRejectsReservedType(t *testing.T) {
    var decoded ProposalOrRef
    err := syntax.Unmarshal([]byte{0x00}, &decoded)
    if !errors.Is(err, ErrUnknownProposalOrRefType) {
        t.Fatalf("got %v, want ErrUnknownProposalOrRefType", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestProposal' -v`
Expected: FAIL — `undefined: Proposal`, `undefined: ProposalTypeRemove`.

- [ ] **Step 3: Write minimal implementation**

```go
// proposal_wire.go
// the RFC 9420 §12.1 proposal wire types and their codecs. codec only: the v1
// profile gate that refuses psk, reinit and external_init is
// (*Profile).CheckProposalType, called at the parse boundary by the group
// lifecycle. this file must round-trip every registered type, because the
// `messages` vector family carries all seven. ProposalType and its constants
// are the registry-enum file's, not this file's.
package mls

import (
    "fmt"

    "github.com/urnetwork/connect/mls/syntax"
)

type Add struct {
    KeyPackage KeyPackage
}

type Update struct {
    LeafNode LeafNode
}

type Remove struct {
    Removed LeafIndex
}

type PreSharedKey struct {
    Psk PreSharedKeyId
}

type ReInit struct {
    GroupId     []byte
    Version     ProtocolVersion
    CipherSuite CipherSuite
    Extensions  []Extension
}

type ExternalInit struct {
    KemOutput []byte
}

type GroupContextExtensions struct {
    Extensions []Extension
}

// exactly one arm is populated, selected by ProposalType. an unrecognised
// type keeps its body in UnknownBody and its discriminant in UnknownType and
// re-encodes verbatim, which is what makes GREASE round-trip; setting
// UnknownType alongside a populated arm is the forge's malformed-arm seam.
type Proposal struct {
    ProposalType           ProposalType
    Add                    *Add
    Update                 *Update
    Remove                 *Remove
    PreSharedKey           *PreSharedKey
    ReInit                 *ReInit
    ExternalInit           *ExternalInit
    GroupContextExtensions *GroupContextExtensions
    UnknownType            ProposalType
    UnknownBody            []byte
}

func (self *Proposal) MarshalMLS(w *syntax.Writer) error {
    // the discriminant on the wire; UnknownType wins when set, so a caller can
    // emit a well-formed body under a GREASE or reserved type without a second
    // encoder existing anywhere in the package.
    proposalType := self.ProposalType
    if self.UnknownType != ProposalTypeReserved {
        proposalType = self.UnknownType
    }
    w.WriteUint16(uint16(proposalType))
    switch self.ProposalType {
    case ProposalTypeAdd:
        if self.Add == nil {
            return ErrContentArmMismatch
        }
        return self.Add.KeyPackage.MarshalMLS(w)
    case ProposalTypeUpdate:
        if self.Update == nil {
            return ErrContentArmMismatch
        }
        return self.Update.LeafNode.MarshalMLS(w)
    case ProposalTypeRemove:
        if self.Remove == nil {
            return ErrContentArmMismatch
        }
        w.WriteUint32(uint32(self.Remove.Removed))
        return nil
    case ProposalTypePreSharedKey:
        if self.PreSharedKey == nil {
            return ErrContentArmMismatch
        }
        return self.PreSharedKey.Psk.MarshalMLS(w)
    case ProposalTypeReInit:
        if self.ReInit == nil {
            return ErrContentArmMismatch
        }
        w.WriteOpaque(self.ReInit.GroupId)
        w.WriteUint16(uint16(self.ReInit.Version))
        w.WriteUint16(uint16(self.ReInit.CipherSuite))
        return WriteExtensions(w, self.ReInit.Extensions)
    case ProposalTypeExternalInit:
        if self.ExternalInit == nil {
            return ErrContentArmMismatch
        }
        w.WriteOpaque(self.ExternalInit.KemOutput)
        return nil
    case ProposalTypeGroupContextExtensions:
        if self.GroupContextExtensions == nil {
            return ErrContentArmMismatch
        }
        return WriteExtensions(w, self.GroupContextExtensions.Extensions)
    }
    if self.UnknownBody == nil {
        return fmt.Errorf("%w: %04x", ErrContentArmMismatch, self.ProposalType)
    }
    w.WriteRaw(self.UnknownBody)
    return nil
}

func (self *Proposal) UnmarshalMLS(r *syntax.Reader) error {
    proposalType, err := r.ReadUint16()
    if err != nil {
        return err
    }
    *self = Proposal{ProposalType: ProposalType(proposalType)}
    switch self.ProposalType {
    case ProposalTypeAdd:
        self.Add = &Add{}
        return self.Add.KeyPackage.UnmarshalMLS(r)
    case ProposalTypeUpdate:
        self.Update = &Update{}
        return self.Update.LeafNode.UnmarshalMLS(r)
    case ProposalTypeRemove:
        removed, err := r.ReadUint32()
        if err != nil {
            return err
        }
        self.Remove = &Remove{Removed: LeafIndex(removed)}
        return nil
    case ProposalTypePreSharedKey:
        self.PreSharedKey = &PreSharedKey{}
        return self.PreSharedKey.Psk.UnmarshalMLS(r)
    case ProposalTypeReInit:
        groupId, err := r.ReadOpaque()
        if err != nil {
            return err
        }
        version, err := r.ReadUint16()
        if err != nil {
            return err
        }
        suite, err := r.ReadUint16()
        if err != nil {
            return err
        }
        extensions, err := ReadExtensions(r)
        if err != nil {
            return err
        }
        self.ReInit = &ReInit{
            GroupId:     groupId,
            Version:     ProtocolVersion(version),
            CipherSuite: CipherSuite(suite),
            Extensions:  extensions,
        }
        return nil
    case ProposalTypeExternalInit:
        kemOutput, err := r.ReadOpaque()
        if err != nil {
            return err
        }
        self.ExternalInit = &ExternalInit{KemOutput: kemOutput}
        return nil
    case ProposalTypeGroupContextExtensions:
        extensions, err := ReadExtensions(r)
        if err != nil {
            return err
        }
        self.GroupContextExtensions = &GroupContextExtensions{Extensions: extensions}
        return nil
    }
    // unknown type: keep the discriminant and the remaining bytes so the object
    // re-encodes verbatim. ReadRaw(Remaining()) rather than a Rest() accessor,
    // because consuming the tail must be explicit.
    self.UnknownType = self.ProposalType
    body, err := r.ReadRaw(r.Remaining())
    if err != nil {
        return err
    }
    self.UnknownBody = body
    return nil
}

var _ syntax.Codec = (*Proposal)(nil)

// 8 bits; not an extensible registry.
type ProposalOrRefType uint8

const (
    ProposalOrRefTypeReserved  ProposalOrRefType = 0
    ProposalOrRefTypeProposal  ProposalOrRefType = 1
    ProposalOrRefTypeReference ProposalOrRefType = 2
)

// a HashReference over an AuthenticatedContent carrying a proposal.
type ProposalRef []byte

type ProposalOrRef struct {
    Type      ProposalOrRefType
    Proposal  *Proposal
    Reference ProposalRef
}

func (self *ProposalOrRef) MarshalMLS(w *syntax.Writer) error {
    switch self.Type {
    case ProposalOrRefTypeProposal:
        if self.Proposal == nil {
            return ErrContentArmMismatch
        }
        w.WriteUint8(uint8(self.Type))
        return self.Proposal.MarshalMLS(w)
    case ProposalOrRefTypeReference:
        if len(self.Reference) == 0 {
            return ErrContentArmMismatch
        }
        w.WriteUint8(uint8(self.Type))
        w.WriteOpaque(self.Reference)
        return nil
    }
    return fmt.Errorf("%w: %d", ErrUnknownProposalOrRefType, self.Type)
}

func (self *ProposalOrRef) UnmarshalMLS(r *syntax.Reader) error {
    proposalOrRefType, err := r.ReadUint8()
    if err != nil {
        return err
    }
    *self = ProposalOrRef{Type: ProposalOrRefType(proposalOrRefType)}
    switch self.Type {
    case ProposalOrRefTypeProposal:
        self.Proposal = &Proposal{}
        return self.Proposal.UnmarshalMLS(r)
    case ProposalOrRefTypeReference:
        reference, err := r.ReadOpaque()
        if err != nil {
            return err
        }
        self.Reference = ProposalRef(reference)
        return nil
    }
    return fmt.Errorf("%w: %d", ErrUnknownProposalOrRefType, self.Type)
}

var _ syntax.Codec = (*ProposalOrRef)(nil)
```

`ErrUnknownProposalOrRefType` was declared in `framing_errors.go` in Task 1; nothing is added to
that file here.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestProposal' -v`
Expected: PASS — eight tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/proposal_wire.go mls/proposal_wire_test.go
git ls-files | wc -l   # MUST be previous + 2
git commit -m "feat(mls): Proposal and ProposalOrRef wire codecs over the shared proposal enum"
```

---

### Task 13: `Commit` wire type

**Files:**
- Create: `connect/mls/commit_wire.go`
- Test: `connect/mls/commit_wire_test.go`

**Interfaces:**
- Consumes: `type UpdatePath struct{ ... }` with
  `MarshalMLS(w *syntax.Writer) error` / `UnmarshalMLS(r *syntax.Reader) error` (p5 §6.7, wave 2);
  `func WriteVector[T any](w *syntax.Writer, items []T, encodeOne func(w *syntax.Writer, item T) error) error`,
  `func ReadVector[T any](r *syntax.Reader, decodeOne func(r *syntax.Reader) (T, error)) ([]T, error)`,
  `(*syntax.Writer).WriteOptional(present bool, encodeOne func(w *syntax.Writer) error) error`,
  `(*syntax.Reader).ReadOptional(decodeOne func(r *syntax.Reader) error) (present bool, err error)`,
  `var syntax.ErrOptionalPresence error` (p1 §2.1–2.4). Task 12.
- Produces: `Commit`, `(*Commit).MarshalMLS(w *syntax.Writer) error`,
  `(*Commit).UnmarshalMLS(r *syntax.Reader) error`, `var _ syntax.Codec = (*Commit)(nil)`.

`path` is `optional<UpdatePath>`: a `u8` presence byte, then the value when present. A commit with
no path encodes to a two-byte empty proposals vector plus `0x00`. **`ErrOptionalPresence` is p1's,
in `package syntax`** — this plan declared a second copy and it is deleted; `WriteOptional` and
`ReadOptional` are the codec's own presence-byte handling and returning that error is their job.
The RFC's `optional<T>` has exactly two encodings and a third would be a second encoding of the
same object, which is the signature-bypass primitive Gate 4 property 2 exists to prevent.

The proposals vector uses p1's **free generic** `syntax.WriteVector`/`syntax.ReadVector` over a
typed slice, not a method on the Writer: an untyped index loop loses the element type that makes
`ReadVector` safe.

- [ ] **Step 1: Write the failing test**

```go
// commit_wire_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func TestCommitRoundTripWithoutPath(t *testing.T) {
    commit := Commit{
        Proposals: []ProposalOrRef{
            {Type: ProposalOrRefTypeReference, Reference: ProposalRef{0x01, 0x02}},
        },
    }
    encoded, err := syntax.Marshal(&commit)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if encoded[len(encoded)-1] != 0x00 {
        t.Fatalf("absent path encoded as %02x, want 00", encoded[len(encoded)-1])
    }

    var decoded Commit
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded.Path != nil {
        t.Fatal("path decoded as present")
    }
    if len(decoded.Proposals) != 1 || decoded.Proposals[0].Type != ProposalOrRefTypeReference {
        t.Fatalf("proposals %+v", decoded.Proposals)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

func TestCommitRoundTripEmptyProposals(t *testing.T) {
    commit := Commit{}
    encoded, err := syntax.Marshal(&commit)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded Commit
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if len(decoded.Proposals) != 0 || decoded.Path != nil {
        t.Fatalf("decoded %+v", decoded)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

func TestCommitRejectsInvalidOptionalPresenceByte(t *testing.T) {
    commit := Commit{}
    valid, err := syntax.Marshal(&commit)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    encoded := append([]byte(nil), valid...)
    encoded[len(encoded)-1] = 0x02

    var decoded Commit
    // the sentinel is the syntax package's: optional<T> presence is the codec's
    // concern, not framing's
    if err := syntax.Unmarshal(encoded, &decoded); !errors.Is(err, syntax.ErrOptionalPresence) {
        t.Fatalf("got %v, want syntax.ErrOptionalPresence", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestCommit' -v`
Expected: FAIL — `undefined: Commit`.

- [ ] **Step 3: Write minimal implementation**

```go
// commit_wire.go
// the RFC 9420 §12.4 Commit wire type and its codec. codec only: proposal-list
// validation and commit application are the group lifecycle's commit.go.
package mls

import (
    "github.com/urnetwork/connect/mls/syntax"
)

type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}

func (self *Commit) MarshalMLS(w *syntax.Writer) error {
    err := syntax.WriteVector(w, self.Proposals,
        func(w *syntax.Writer, item ProposalOrRef) error {
            return item.MarshalMLS(w)
        })
    if err != nil {
        return err
    }
    return w.WriteOptional(self.Path != nil, func(w *syntax.Writer) error {
        return self.Path.MarshalMLS(w)
    })
}

func (self *Commit) UnmarshalMLS(r *syntax.Reader) error {
    proposals, err := syntax.ReadVector(r, func(r *syntax.Reader) (ProposalOrRef, error) {
        proposalOrRef := ProposalOrRef{}
        if err := proposalOrRef.UnmarshalMLS(r); err != nil {
            return ProposalOrRef{}, err
        }
        return proposalOrRef, nil
    })
    if err != nil {
        return err
    }
    *self = Commit{Proposals: proposals}

    path := &UpdatePath{}
    present, err := r.ReadOptional(func(r *syntax.Reader) error {
        return path.UnmarshalMLS(r)
    })
    if err != nil {
        return err
    }
    if present {
        self.Path = path
    }
    return nil
}

var _ syntax.Codec = (*Commit)(nil)
```

Nothing is added to `framing_errors.go`: the presence-byte refusal is `syntax.ErrOptionalPresence`,
returned by `ReadOptional`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestCommit' -v`
Expected: PASS — three tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/commit_wire.go mls/commit_wire_test.go
git ls-files | wc -l   # MUST be previous + 2
git commit -m "feat(mls): Commit wire codec over the shared optional and vector helpers"
```

---

### Task 14: `GroupInfo`, `GroupSecrets` and `Welcome` codecs

**Files:**
- Create: `connect/mls/welcome_wire.go`
- Test: `connect/mls/welcome_wire_test.go`

**Interfaces:**
- Consumes: `type GroupContext struct{ ... }` with
  `MarshalMLS(w *syntax.Writer) error` / `UnmarshalMLS(r *syntax.Reader) error`, and
  `type PreSharedKeyId struct{ ... }` with the same pair (p4 §5.1, §5.3, wave 2);
  `func WriteExtensions(w *syntax.Writer, exts []Extension) error`,
  `func ReadExtensions(r *syntax.Reader) ([]Extension, error)`, and
  `type HpkeCiphertext struct{ KemOutput []byte; Ciphertext []byte }` with its codec
  (p5 §6.2, §6.7, wave 2); `type CipherSuite uint16` (p2); `type LeafIndex uint32` (p3);
  `syntax.WriteVector`, `syntax.ReadVector`, `(*syntax.Writer).WriteOptional`,
  `(*syntax.Reader).ReadOptional` (p1). Task 1.
- Produces: `GroupInfo`, `GroupInfoTBS`, `PathSecret`, `GroupSecrets`, `EncryptedGroupSecrets`,
  `Welcome`, each with `MarshalMLS`/`UnmarshalMLS` (`GroupInfoTBS` encode-only), plus
  `var _ syntax.Codec = (*GroupInfo)(nil)`, `var _ syntax.Codec = (*GroupSecrets)(nil)` and
  `var _ syntax.Codec = (*Welcome)(nil)`.

**Why these codecs are here and not in the group-lifecycle plan.** Registry §7.5 moves them:
`MLSMessage` (Task 15, wave 3) names `*Welcome`, `*GroupInfo` and `*KeyPackage` by direct type, and
`package mls` is one package — if those types land in wave 4, nothing in wave 3 compiles, including
this plan's own message-protection vector gate and `ParseMLSMessage`. This is exactly the split
already applied to `Proposal`/`Commit`, applied consistently. The **generation and processing
logic stays in p7**: `(*GroupInfo).Sign`, `(*GroupInfo).Verify`, `BuildWelcome`, `WelcomeJoiner` and
`JoinFromWelcome` are p7's (§8.4) and are not written here. `GroupInfoTBS` is encode-only because
nothing ever decodes a to-be-signed structure; p7's `Sign`/`Verify` are its only callers.

`Psks []PreSharedKeyId` is always empty in the v1 profile, but the codec still round-trips a
populated vector — refusing a PSK is the profile's job, not the codec's, and the `messages` vector
family carries `group_secrets` with the field present.

- [ ] **Step 1: Write the failing test**

```go
// welcome_wire_test.go
package mls

import (
    "bytes"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func testGroupInfo() GroupInfo {
    return GroupInfo{
        GroupContext: GroupContext{
            Version:                 ProtocolVersionMls10,
            CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
            GroupId:                 []byte{0x01, 0x02},
            Epoch:                   4,
            TreeHash:                bytes.Repeat([]byte{0xc0}, 32),
            ConfirmedTranscriptHash: bytes.Repeat([]byte{0xee}, 32),
        },
        Extensions:      []Extension{{ExtensionType: ExtensionTypeRatchetTree, ExtensionData: []byte{0x01}}},
        ConfirmationTag: bytes.Repeat([]byte{0x0a}, 32),
        Signer:          1,
        Signature:       []byte{0xde, 0xad, 0xbe, 0xef},
    }
}

func TestGroupInfoRoundTrip(t *testing.T) {
    groupInfo := testGroupInfo()
    encoded, err := syntax.Marshal(&groupInfo)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded GroupInfo
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded.Signer != 1 || !bytes.Equal(decoded.Signature, groupInfo.Signature) {
        t.Fatalf("decoded %+v", decoded)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

// the signed bytes are the GroupInfo minus its own signature, and nothing more:
// a GroupInfoTBS that accidentally included the signature would be unsignable.
func TestGroupInfoTBSIsGroupInfoWithoutTheSignature(t *testing.T) {
    groupInfo := testGroupInfo()
    tbs := GroupInfoTBS{
        GroupContext:    groupInfo.GroupContext,
        Extensions:      groupInfo.Extensions,
        ConfirmationTag: groupInfo.ConfirmationTag,
        Signer:          groupInfo.Signer,
    }
    tbsBytes, err := syntax.Marshal(&tbs)
    if err != nil {
        t.Fatalf("tbs: %v", err)
    }
    full, err := syntax.Marshal(&groupInfo)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if !bytes.HasPrefix(full, tbsBytes) {
        t.Fatal("GroupInfo does not begin with its own GroupInfoTBS")
    }
    if bytes.Contains(tbsBytes, groupInfo.Signature) {
        t.Fatal("signature leaked into GroupInfoTBS")
    }
}

func TestGroupSecretsRoundTripWithAndWithoutPathSecret(t *testing.T) {
    cases := []GroupSecrets{
        {JoinerSecret: bytes.Repeat([]byte{0x11}, 32)},
        {
            JoinerSecret: bytes.Repeat([]byte{0x11}, 32),
            PathSecret:   &PathSecret{PathSecret: bytes.Repeat([]byte{0x22}, 32)},
        },
        {
            JoinerSecret: bytes.Repeat([]byte{0x11}, 32),
            Psks: []PreSharedKeyId{{
                PskType:  PskTypeExternal,
                PskId:    []byte{0x01, 0x02},
                PskNonce: bytes.Repeat([]byte{0x33}, 32),
            }},
        },
    }
    for i := range cases {
        encoded, err := syntax.Marshal(&cases[i])
        if err != nil {
            t.Fatalf("case %d: marshal: %v", i, err)
        }
        var decoded GroupSecrets
        if err := syntax.Unmarshal(encoded, &decoded); err != nil {
            t.Fatalf("case %d: unmarshal: %v", i, err)
        }
        if (decoded.PathSecret == nil) != (cases[i].PathSecret == nil) {
            t.Fatalf("case %d: path secret presence flipped", i)
        }
        reencoded, err := syntax.Marshal(&decoded)
        if err != nil {
            t.Fatalf("case %d: re-marshal: %v", i, err)
        }
        if !bytes.Equal(encoded, reencoded) {
            t.Fatalf("case %d: re-encoded %x, want %x", i, reencoded, encoded)
        }
    }
}

func TestWelcomeRoundTrip(t *testing.T) {
    welcome := Welcome{
        CipherSuite: CipherSuiteX25519ChaCha20Sha256Ed25519,
        Secrets: []EncryptedGroupSecrets{{
            NewMember: bytes.Repeat([]byte{0x44}, 32),
            EncryptedGroupSecrets: HpkeCiphertext{
                KemOutput:  bytes.Repeat([]byte{0x55}, 32),
                Ciphertext: bytes.Repeat([]byte{0x66}, 48),
            },
        }},
        EncryptedGroupInfo: bytes.Repeat([]byte{0x77}, 64),
    }
    encoded, err := syntax.Marshal(&welcome)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded Welcome
    if err := syntax.Unmarshal(encoded, &decoded); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if len(decoded.Secrets) != 1 ||
        !bytes.Equal(decoded.Secrets[0].NewMember, welcome.Secrets[0].NewMember) {
        t.Fatalf("decoded %+v", decoded.Secrets)
    }
    reencoded, err := syntax.Marshal(&decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestGroupInfo|TestGroupSecrets|TestWelcome' -v`
Expected: FAIL — `undefined: GroupInfo`, `undefined: Welcome`.

- [ ] **Step 3: Write minimal implementation**

```go
// welcome_wire.go
// the RFC 9420 §12.4.3 GroupInfo and §12.4.3.1 Welcome wire types and their
// codecs. codecs ONLY: signing a GroupInfo, building a Welcome and joining from
// one are the group lifecycle's. they live here because MLSMessage names
// *Welcome and *GroupInfo by direct type and package mls is one package.
package mls

import (
    "github.com/urnetwork/connect/mls/syntax"
)

type GroupInfo struct {
    GroupContext    GroupContext
    Extensions      []Extension
    ConfirmationTag []byte
    Signer          LeafIndex
    Signature       []byte
}

func (self *GroupInfo) MarshalMLS(w *syntax.Writer) error {
    if err := self.GroupContext.MarshalMLS(w); err != nil {
        return err
    }
    if err := WriteExtensions(w, self.Extensions); err != nil {
        return err
    }
    w.WriteOpaque(self.ConfirmationTag)
    w.WriteUint32(uint32(self.Signer))
    w.WriteOpaque(self.Signature)
    return nil
}

func (self *GroupInfo) UnmarshalMLS(r *syntax.Reader) error {
    *self = GroupInfo{}
    if err := self.GroupContext.UnmarshalMLS(r); err != nil {
        return err
    }
    extensions, err := ReadExtensions(r)
    if err != nil {
        return err
    }
    self.Extensions = extensions
    confirmationTag, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    self.ConfirmationTag = confirmationTag
    signer, err := r.ReadUint32()
    if err != nil {
        return err
    }
    self.Signer = LeafIndex(signer)
    signature, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    self.Signature = signature
    return nil
}

var _ syntax.Codec = (*GroupInfo)(nil)

// the bytes SignWithLabel signs under "GroupInfoTBS". encode-only: nothing
// decodes a to-be-signed structure, and offering an UnmarshalMLS would invite a
// caller to reconstruct one instead of re-serializing the object it verified.
type GroupInfoTBS struct {
    GroupContext    GroupContext
    Extensions      []Extension
    ConfirmationTag []byte
    Signer          LeafIndex
}

func (self *GroupInfoTBS) MarshalMLS(w *syntax.Writer) error {
    if err := self.GroupContext.MarshalMLS(w); err != nil {
        return err
    }
    if err := WriteExtensions(w, self.Extensions); err != nil {
        return err
    }
    w.WriteOpaque(self.ConfirmationTag)
    w.WriteUint32(uint32(self.Signer))
    return nil
}

var _ syntax.Marshaler = (*GroupInfoTBS)(nil)

type PathSecret struct {
    PathSecret []byte
}

func (self *PathSecret) MarshalMLS(w *syntax.Writer) error {
    w.WriteOpaque(self.PathSecret)
    return nil
}

func (self *PathSecret) UnmarshalMLS(r *syntax.Reader) error {
    pathSecret, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    *self = PathSecret{PathSecret: pathSecret}
    return nil
}

var _ syntax.Codec = (*PathSecret)(nil)

// the per-joiner secrets, encrypted to a joiner's init key. Psks is always
// empty under the v1 profile, but the codec round-trips a populated vector:
// refusing a PSK is the profile's decision, not the codec's.
type GroupSecrets struct {
    JoinerSecret []byte
    PathSecret   *PathSecret
    Psks         []PreSharedKeyId
}

func (self *GroupSecrets) MarshalMLS(w *syntax.Writer) error {
    w.WriteOpaque(self.JoinerSecret)
    err := w.WriteOptional(self.PathSecret != nil, func(w *syntax.Writer) error {
        return self.PathSecret.MarshalMLS(w)
    })
    if err != nil {
        return err
    }
    return syntax.WriteVector(w, self.Psks, func(w *syntax.Writer, item PreSharedKeyId) error {
        return item.MarshalMLS(w)
    })
}

func (self *GroupSecrets) UnmarshalMLS(r *syntax.Reader) error {
    joinerSecret, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    *self = GroupSecrets{JoinerSecret: joinerSecret}

    pathSecret := &PathSecret{}
    present, err := r.ReadOptional(func(r *syntax.Reader) error {
        return pathSecret.UnmarshalMLS(r)
    })
    if err != nil {
        return err
    }
    if present {
        self.PathSecret = pathSecret
    }

    psks, err := syntax.ReadVector(r, func(r *syntax.Reader) (PreSharedKeyId, error) {
        psk := PreSharedKeyId{}
        if err := psk.UnmarshalMLS(r); err != nil {
            return PreSharedKeyId{}, err
        }
        return psk, nil
    })
    if err != nil {
        return err
    }
    self.Psks = psks
    return nil
}

var _ syntax.Codec = (*GroupSecrets)(nil)

type EncryptedGroupSecrets struct {
    NewMember             []byte
    EncryptedGroupSecrets HpkeCiphertext
}

func (self *EncryptedGroupSecrets) MarshalMLS(w *syntax.Writer) error {
    w.WriteOpaque(self.NewMember)
    return self.EncryptedGroupSecrets.MarshalMLS(w)
}

func (self *EncryptedGroupSecrets) UnmarshalMLS(r *syntax.Reader) error {
    newMember, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    *self = EncryptedGroupSecrets{NewMember: newMember}
    return self.EncryptedGroupSecrets.UnmarshalMLS(r)
}

var _ syntax.Codec = (*EncryptedGroupSecrets)(nil)

type Welcome struct {
    CipherSuite        CipherSuite
    Secrets            []EncryptedGroupSecrets
    EncryptedGroupInfo []byte
}

func (self *Welcome) MarshalMLS(w *syntax.Writer) error {
    w.WriteUint16(uint16(self.CipherSuite))
    err := syntax.WriteVector(w, self.Secrets,
        func(w *syntax.Writer, item EncryptedGroupSecrets) error {
            return item.MarshalMLS(w)
        })
    if err != nil {
        return err
    }
    w.WriteOpaque(self.EncryptedGroupInfo)
    return nil
}

func (self *Welcome) UnmarshalMLS(r *syntax.Reader) error {
    cipherSuite, err := r.ReadUint16()
    if err != nil {
        return err
    }
    secrets, err := syntax.ReadVector(r, func(r *syntax.Reader) (EncryptedGroupSecrets, error) {
        encrypted := EncryptedGroupSecrets{}
        if err := encrypted.UnmarshalMLS(r); err != nil {
            return EncryptedGroupSecrets{}, err
        }
        return encrypted, nil
    })
    if err != nil {
        return err
    }
    encryptedGroupInfo, err := r.ReadOpaque()
    if err != nil {
        return err
    }
    *self = Welcome{
        CipherSuite:        CipherSuite(cipherSuite),
        Secrets:            secrets,
        EncryptedGroupInfo: encryptedGroupInfo,
    }
    return nil
}

var _ syntax.Codec = (*Welcome)(nil)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestGroupInfo|TestGroupSecrets|TestWelcome' -v`
Expected: PASS — four tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/welcome_wire.go mls/welcome_wire_test.go
git ls-files | wc -l   # MUST be previous + 2
git commit -m "feat(mls): GroupInfo, GroupSecrets and Welcome wire codecs"
```

---

### Task 15: `MLSMessage` wrapper

**Files:**
- Modify: `connect/mls/framing.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: `Welcome` and `GroupInfo` from Task 14; `type KeyPackage struct{ ... }` with
  `MarshalMLS(w *syntax.Writer) error` / `UnmarshalMLS(r *syntax.Reader) error` (**p5** §6.5, wave 2
  — the registry assigns `KeyPackage` to the TreeKEM/leaf-node plan, not to the lifecycle plan, so
  it is available in wave 2 and this wave-3 struct can name it);
  `const ProtocolVersionMls10 ProtocolVersion = 0x0001` (p5 §6.1). Tasks 1–8, 14.
- Produces: `MLSMessage`, `(*MLSMessage).MarshalMLS(w *syntax.Writer) error`,
  `(*MLSMessage).UnmarshalMLS(r *syntax.Reader) error`,
  `var _ syntax.Codec = (*MLSMessage)(nil)`,
  `MarshalMLSMessage(message *MLSMessage) ([]byte, error)`,
  `ParseMLSMessage(data []byte) (*MLSMessage, error)`.

`ParseMLSMessage`/`MarshalMLSMessage` are the **one sanctioned pair of byte-level free functions**
outside the validation plan's codec table (registry C1, §7.2). `EncodeMLSMessage` and
`(*MLSMessage).Marshal` do not exist; the validation plan's `KindMlsMessage` codec row calls this
pair.

`ParseMLSMessage` is the single entry point every byte off the wire passes through: it enforces
full consumption (`syntax` rule 3) and the version check. `group.go`, `connect/message` and the
interop client all call it.

The arms are referenced by direct type, not through a registry with `init()`, because all of these
types live in `package mls` — there is no import edge to break and a registry would hide which
plan owns which type.

- [ ] **Step 1: Write the failing test**

```go
// framing_test.go (append)
func TestMLSMessageRoundTripPrivate(t *testing.T) {
    message := MLSMessage{
        Version:    ProtocolVersionMls10,
        WireFormat: WireFormatPrivateMessage,
        PrivateMessage: &PrivateMessage{
            GroupId:             []byte{0x01},
            Epoch:               1,
            ContentType:         ContentTypeApplication,
            AuthenticatedData:   []byte{},
            EncryptedSenderData: []byte{0x01, 0x02},
            Ciphertext:          []byte{0x03, 0x04},
        },
    }
    encoded, err := MarshalMLSMessage(&message)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if !bytes.HasPrefix(encoded, []byte{0x00, 0x01, 0x00, 0x02}) {
        t.Fatalf("prefix %x, want 00010002", encoded[0:4])
    }
    decoded, err := ParseMLSMessage(encoded)
    if err != nil {
        t.Fatalf("parse: %v", err)
    }
    if decoded.PrivateMessage == nil || decoded.PublicMessage != nil {
        t.Fatalf("decoded %+v", decoded)
    }
    reencoded, err := MarshalMLSMessage(decoded)
    if err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, reencoded) {
        t.Fatalf("re-encoded %x, want %x", reencoded, encoded)
    }
}

func TestParseMLSMessageRejectsTrailingBytes(t *testing.T) {
    message := MLSMessage{
        Version:    ProtocolVersionMls10,
        WireFormat: WireFormatPrivateMessage,
        PrivateMessage: &PrivateMessage{
            GroupId: []byte{0x01}, Epoch: 1, ContentType: ContentTypeApplication,
            AuthenticatedData: []byte{}, EncryptedSenderData: []byte{0x01}, Ciphertext: []byte{0x02},
        },
    }
    encoded, err := MarshalMLSMessage(&message)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if _, err := ParseMLSMessage(append(encoded, 0x00)); err == nil {
        t.Fatal("trailing byte accepted")
    }
}

func TestParseMLSMessageRejectsWrongVersionAndUnknownWireFormat(t *testing.T) {
    if _, err := ParseMLSMessage([]byte{0x00, 0x02, 0x00, 0x02}); !errors.Is(err, ErrUnsupportedVersion) {
        t.Fatalf("version: got %v, want ErrUnsupportedVersion", err)
    }
    if _, err := ParseMLSMessage([]byte{0x00, 0x01, 0x00, 0x63}); !errors.Is(err, ErrUnknownWireFormat) {
        t.Fatalf("wire format: got %v, want ErrUnknownWireFormat", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestMLSMessage|TestParseMLSMessage' -v`
Expected: FAIL — `undefined: MLSMessage`, `undefined: ParseMLSMessage`.

- [ ] **Step 3: Write minimal implementation**

```go
// framing.go (append)

// the outermost object on the wire. exactly one arm is populated, selected by
// WireFormat. the arms are direct type references rather than a registry
// because every one of them is package mls.
type MLSMessage struct {
    Version        ProtocolVersion
    WireFormat     WireFormat
    PublicMessage  *PublicMessage
    PrivateMessage *PrivateMessage
    Welcome        *Welcome
    GroupInfo      *GroupInfo
    KeyPackage     *KeyPackage
}

func (self *MLSMessage) MarshalMLS(w *syntax.Writer) error {
    if self.Version != ProtocolVersionMls10 {
        return fmt.Errorf("%w: %04x", ErrUnsupportedVersion, self.Version)
    }
    w.WriteUint16(uint16(self.Version))
    w.WriteUint16(uint16(self.WireFormat))
    switch self.WireFormat {
    case WireFormatPublicMessage:
        if self.PublicMessage == nil {
            return ErrContentArmMismatch
        }
        return self.PublicMessage.MarshalMLS(w)
    case WireFormatPrivateMessage:
        if self.PrivateMessage == nil {
            return ErrContentArmMismatch
        }
        return self.PrivateMessage.MarshalMLS(w)
    case WireFormatWelcome:
        if self.Welcome == nil {
            return ErrContentArmMismatch
        }
        return self.Welcome.MarshalMLS(w)
    case WireFormatGroupInfo:
        if self.GroupInfo == nil {
            return ErrContentArmMismatch
        }
        return self.GroupInfo.MarshalMLS(w)
    case WireFormatKeyPackage:
        if self.KeyPackage == nil {
            return ErrContentArmMismatch
        }
        return self.KeyPackage.MarshalMLS(w)
    }
    return fmt.Errorf("%w: %04x", ErrUnknownWireFormat, self.WireFormat)
}

func (self *MLSMessage) UnmarshalMLS(r *syntax.Reader) error {
    version, err := r.ReadUint16()
    if err != nil {
        return err
    }
    if ProtocolVersion(version) != ProtocolVersionMls10 {
        return fmt.Errorf("%w: %04x", ErrUnsupportedVersion, version)
    }
    wireFormat, err := r.ReadUint16()
    if err != nil {
        return err
    }
    *self = MLSMessage{Version: ProtocolVersion(version), WireFormat: WireFormat(wireFormat)}
    switch self.WireFormat {
    case WireFormatPublicMessage:
        self.PublicMessage = &PublicMessage{}
        return self.PublicMessage.UnmarshalMLS(r)
    case WireFormatPrivateMessage:
        self.PrivateMessage = &PrivateMessage{}
        return self.PrivateMessage.UnmarshalMLS(r)
    case WireFormatWelcome:
        self.Welcome = &Welcome{}
        return self.Welcome.UnmarshalMLS(r)
    case WireFormatGroupInfo:
        self.GroupInfo = &GroupInfo{}
        return self.GroupInfo.UnmarshalMLS(r)
    case WireFormatKeyPackage:
        self.KeyPackage = &KeyPackage{}
        return self.KeyPackage.UnmarshalMLS(r)
    }
    return fmt.Errorf("%w: %04x", ErrUnknownWireFormat, self.WireFormat)
}

var _ syntax.Codec = (*MLSMessage)(nil)

// the one sanctioned byte-level pair outside the codec table: every byte on the
// wire passes through these two names and the whole system calls them.
func MarshalMLSMessage(message *MLSMessage) ([]byte, error) {
    return syntax.Marshal(message)
}

// the single entry point for every byte that arrives from the network or the
// store. syntax.Unmarshal enforces full consumption, so a message with trailing
// bytes is a decode error rather than a silently truncated object.
func ParseMLSMessage(data []byte) (*MLSMessage, error) {
    message := &MLSMessage{}
    if err := syntax.Unmarshal(data, message); err != nil {
        return nil, err
    }
    return message, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestMLSMessage|TestParseMLSMessage' -v`
Expected: PASS — three tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_test.go
git ls-files | wc -l
git commit -m "feat(mls): MLSMessage wrapper and ParseMLSMessage full-consumption entry point"
```

---

### Task 16: ValSem002, ValSem003, ValSem004 and the framing refusal roster

**Files:**
- Modify: `connect/mls/framing_protect.go`
- Create: `connect/mls/validation_framing_test.go`
- Modify: `connect/mls/framing_protect_test.go` (move the refusal tests written in Tasks 5–11)

**Interfaces:**
- Consumes: Tasks 1–15; `func ValSem(code ValSemCode, detail error) error`, the codes
  `ValSem002`/`ValSem003`/`ValSem004` and the sentinels `ErrWrongGroupId`, `ErrWrongEpoch`,
  `ErrBlankSenderLeaf` (p8, wave 1); `crypto/subtle`.
- Produces:
  `CheckFramedContentContext(content *FramedContent, groupId []byte, epoch uint64) error`,
  `CheckSenderLeaf(sender Sender, leafOccupied func(LeafIndex) bool) error`.

`CheckSenderLeaf` takes a predicate rather than a tree so the framing layer stays free of tree
types and the test needs no group. The group lifecycle passes its ratchet tree's occupancy test.

**The `TestValSemNNN_<slug>` names are p8's, exclusively** (registry §9.5, Spec A §4.3). This plan's
ten refusal tests are therefore **behaviour-named**, with the registry's own rename applied to the
005 case: `TestPublicMessageRefusesApplicationContent`. The roster test changes shape to match —
instead of asserting that a naming convention was followed, it asserts that **every one of the ten
framing sentinels is named by at least one test function in the package**, which is the property
the old test was reaching for and the one that survives p8 owning the names.

Tasks 5–11 wrote those tests into `framing_protect_test.go` where they belonged next to the code
under test; this task **moves** them into `validation_framing_test.go`, adds 002/003/004, and adds
the roster test.

- [ ] **Step 1: Write the failing test**

```go
// validation_framing_test.go
package mls

import (
    "bytes"
    "errors"
    "go/ast"
    "go/parser"
    "go/token"
    "io/fs"
    "strings"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func TestFramedContentContextRefusesWrongGroupId(t *testing.T) {
    content := testMemberContent()
    if err := CheckFramedContentContext(content, content.GroupId, content.Epoch); err != nil {
        t.Fatalf("matching context: %v", err)
    }
    other := append([]byte(nil), content.GroupId...)
    other[0] ^= 0xff
    if err := CheckFramedContentContext(content, other, content.Epoch); !errors.Is(err, ErrWrongGroupId) {
        t.Fatalf("got %v, want ErrWrongGroupId", err)
    }
    if err := CheckFramedContentContext(content, nil, content.Epoch); !errors.Is(err, ErrWrongGroupId) {
        t.Fatalf("empty group id: got %v, want ErrWrongGroupId", err)
    }
    if err := CheckFramedContentContext(content, append(other, 0x00), content.Epoch); !errors.Is(err, ErrWrongGroupId) {
        t.Fatalf("longer group id: got %v, want ErrWrongGroupId", err)
    }
}

func TestFramedContentContextRefusesWrongEpoch(t *testing.T) {
    content := testMemberContent()
    if err := CheckFramedContentContext(content, content.GroupId, content.Epoch+1); !errors.Is(err, ErrWrongEpoch) {
        t.Fatalf("got %v, want ErrWrongEpoch", err)
    }
    if err := CheckFramedContentContext(content, content.GroupId, content.Epoch-1); !errors.Is(err, ErrWrongEpoch) {
        t.Fatalf("older epoch: got %v, want ErrWrongEpoch", err)
    }
}

func TestSenderLeafRefusesBlankLeaf(t *testing.T) {
    occupied := func(leaf LeafIndex) bool { return leaf == 1 }

    if err := CheckSenderLeaf(Sender{SenderType: SenderTypeMember, LeafIndex: 1}, occupied); err != nil {
        t.Fatalf("occupied leaf: %v", err)
    }
    err := CheckSenderLeaf(Sender{SenderType: SenderTypeMember, LeafIndex: 2}, occupied)
    if !errors.Is(err, ErrBlankSenderLeaf) {
        t.Fatalf("blank leaf: got %v, want ErrBlankSenderLeaf", err)
    }
    // a non-member sender has no leaf to check and must not be rejected here
    if err := CheckSenderLeaf(Sender{SenderType: SenderTypeNewMemberCommit}, occupied); err != nil {
        t.Fatalf("new_member_commit: %v", err)
    }
}

// the TestValSemNNN_<slug> names belong to the validation plan's catalogue, so
// this roster asserts the property those names were standing in for: every one
// of the ten framing refusals is exercised by some test in this package. it
// fails when a refusal loses its test, which is the failure mode a coverage
// percentage does not catch.
func TestFramingRefusalsEachHaveATest(t *testing.T) {
    want := []string{
        "ErrWrongGroupId",                // ValSem002
        "ErrWrongEpoch",                  // ValSem003
        "ErrBlankSenderLeaf",             // ValSem004
        "ErrApplicationMustBeCiphertext", // ValSem005
        "ErrDecryptFailed",               // ValSem006
        "ErrMissingMembershipTag",        // ValSem007
        "ErrBadMembershipTag",            // ValSem008
        "ErrMissingConfirmationTag",      // ValSem009
        "ErrBadSignature",                // ValSem010
        "ErrNonZeroPadding",              // ValSem011
    }
    fileSet := token.NewFileSet()
    packages, err := parser.ParseDir(fileSet, ".", func(info fs.FileInfo) bool {
        return strings.HasSuffix(info.Name(), "_test.go")
    }, 0)
    if err != nil {
        t.Fatalf("parse: %v", err)
    }
    named := map[string]bool{}
    for _, pkg := range packages {
        for _, file := range pkg.Files {
            for _, decl := range file.Decls {
                funcDecl, ok := decl.(*ast.FuncDecl)
                if !ok || funcDecl.Recv != nil || !strings.HasPrefix(funcDecl.Name.Name, "Test") {
                    continue
                }
                ast.Inspect(funcDecl, func(node ast.Node) bool {
                    if ident, ok := node.(*ast.Ident); ok {
                        named[ident.Name] = true
                    }
                    return true
                })
            }
        }
    }
    for _, sentinel := range want {
        if !named[sentinel] {
            t.Errorf("no test function names %s; the refusal has lost its test", sentinel)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestFramedContentContextRefuses|TestSenderLeafRefusesBlankLeaf|TestFramingRefusalsEachHaveATest' -v`
Expected: FAIL — `undefined: CheckFramedContentContext`, `undefined: CheckSenderLeaf`, and the
roster test reporting the three sentinels no test names yet.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_protect.go (append)

// ValSem002 and ValSem003. the group id comparison is constant time not
// because a group id is secret but because framing.go and framing_protect.go
// are under the G8 gate and one exception is how a gate stops being a gate.
func CheckFramedContentContext(content *FramedContent, groupId []byte, epoch uint64) error {
    if subtle.ConstantTimeCompare(content.GroupId, groupId) != 1 {
        return ValSem(ValSem002, ErrWrongGroupId)
    }
    if content.Epoch != epoch {
        return ValSem(ValSem003, ErrWrongEpoch)
    }
    return nil
}

// ValSem004. takes a predicate rather than a tree so framing carries no tree
// types; the group lifecycle passes the ratchet tree's occupancy test.
func CheckSenderLeaf(sender Sender, leafOccupied func(LeafIndex) bool) error {
    if sender.SenderType != SenderTypeMember {
        return nil
    }
    if !leafOccupied(sender.LeafIndex) {
        return ValSem(ValSem004, ErrBlankSenderLeaf)
    }
    return nil
}
```

`framing_protect.go` now needs `"crypto/subtle"` in its import block.

- [ ] **Step 4: Move the refusal tests written in earlier tasks**

Cut `TestPublicMessageRefusesApplicationContent`, `TestPrivateMessageRefusesTamperedCiphertext`,
`TestPublicMessageRefusesMissingMembershipTag`, `TestPublicMessageRefusesForgedMembershipTag`,
`TestAuthenticatedContentRefusesForgedSignature` and
`TestPrivateMessageContentRefusesNonZeroPadding` from `framing_protect_test.go` and paste them
unchanged into `validation_framing_test.go`. Add the ValSem009 case, which no earlier task covered
on its own:

```go
// validation_framing_test.go (append)
func TestCommitRefusesMissingConfirmationTag(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext(t)

    content := testMemberContent()
    content.ContentType = ContentTypeCommit
    content.ApplicationData = nil
    content.Commit = &Commit{}
    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage, content, groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }

    // a commit whose confirmation tag was never set
    if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); !errors.Is(err, ErrMissingConfirmationTag) {
        t.Fatalf("verify: got %v, want ErrMissingConfirmationTag", err)
    }
    // and one that cannot even be serialized without it
    err = authContent.Auth.MarshalMLS(syntax.NewWriter(), ContentTypeCommit)
    if !errors.Is(err, ErrMissingConfirmationTag) {
        t.Fatalf("marshal: got %v, want ErrMissingConfirmationTag", err)
    }
    // and a decoder that is handed a commit with a zero-length tag
    authContent.Auth.ConfirmationTag = bytes.Repeat([]byte{0x01}, crypto.HashSize())
    w := syntax.NewWriter()
    if err := authContent.Auth.MarshalMLS(w, ContentTypeCommit); err != nil {
        t.Fatalf("marshal with tag: %v", err)
    }
    withTag, err := w.Bytes()
    if err != nil {
        t.Fatalf("bytes: %v", err)
    }
    truncated := append([]byte(nil), withTag...)
    truncated[len(authContent.Auth.Signature)+1] = 0x00 // the tag's length prefix
    truncated = truncated[:len(authContent.Auth.Signature)+2]
    var decoded FramedContentAuthData
    if err := decoded.UnmarshalMLS(syntax.NewReader(truncated), ContentTypeCommit); !errors.Is(err, ErrMissingConfirmationTag) {
        t.Fatalf("unmarshal: got %v, want ErrMissingConfirmationTag", err)
    }
}
```

`validation_framing_test.go`'s import block, listed in Step 1, already carries
`"github.com/urnetwork/connect/mls/syntax"`, `"io/fs"` and `"strings"` for this and for the roster
test.

- [ ] **Step 5: Run the whole framing ValSem set to verify it passes**

Run: `go test ./connect/mls/... -run 'Refuses|TestFramingRefusalsEachHaveATest' -v`
Expected: PASS — the ten framing refusal tests plus the roster test.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_protect.go mls/framing_protect_test.go mls/validation_framing_test.go
git ls-files | wc -l   # MUST be previous + 1
git commit -m "test(mls): the ten framing refusals in one roster-checked file"
```

---

### Task 17: The `message-protection` vector family, both directions

**Files:**
- Create: `connect/mls/message_protection_kat_test.go`
- Test data: `connect/mls/testdata/vectors/message-protection.json` (vendored by p8 Task 6, the
  single vendoring task, at the pinned mlswg commit recorded in `connect/mls/interop/PINS.md`)

**Interfaces:**
- Consumes: everything above, plus
  `type VectorFamily struct{ Number int; Name string; File string; Slice string; Verify func(t *testing.T, raw json.RawMessage); Generate func(t *testing.T) json.RawMessage }`,
  `func RegisterVectorFamily(family VectorFamily)`,
  `func LoadVectorFile(t *testing.T, file string) []json.RawMessage`,
  `func MustHex(t *testing.T, s string) []byte`, `func HexOf(b []byte) string` (p8 §9.2, wave 1);
  `type GroupContext struct{ ... }` with its codec (p4 §5.1) — the harness builds the serialized
  GroupContext with `syntax.Marshal(gc)`, which is what C4 tells every caller to do;
  `func NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error)`
  (p4 §5.5) — the second parameter is a `LeafCount`, not a `uint32` group size;
  `func NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error)`
  is **not** used here; the generate direction takes its randomness from `crypto.Random`.
- Produces: nothing exported. `MarshalGroupContext` is not asked for and does not exist —
  `syntax.Marshal` over p4's struct is the one GroupContext serializer in the system.

**No `hexBytes` and no `vectors_hex_test.go`.** Registry §9.2 deletes `hexBytes` (this plan),
`ksHex`/`ksLoadVectors` (p4) and `mustHex` (p7) in favour of p8's wave-1
`MustHex`/`HexOf`/`LoadVectorFile`. The vector structs below therefore carry `string` fields and
decode through `MustHex`.

**Registration is part of this task, not a follow-up.** `init()` calls `RegisterVectorFamily` for
family 4, and the same commit deletes `4` from p8's `expectedPendingFamilies`. Without both,
`TestVectorFamiliesVerify` runs one family and Gate 1 is green with fifteen of sixteen never
executed.

The vector's verification procedure, followed exactly:

1. Build a GroupContext from `cipher_suite`, `group_id`, `epoch`, `tree_hash`,
   `confirmed_transcript_hash`, empty extensions.
2. For each of `proposal`, `commit`, `application`: initialize a secret tree for **2 members** with
   `encryption_secret`, and use **LeafIndex 1** as the sender.
3. The `pub` message verifies with `membership_key` and `signature_pub` and produces the raw value.
4. Protecting the raw value with `membership_key` and `signature_priv` produces a `PublicMessage`
   that verifies — **except for application, where protecting as a PublicMessage must fail**.
5. The `priv` message unprotects with the secret tree and `signature_pub`.
6. Protecting the raw value with the secret tree, `sender_data_secret` and `signature_priv`
   produces a `PrivateMessage` that unprotects with the same inputs.

Step 6 is the generate direction. It is not a byte comparison against the vector — a `PrivateMessage`
carries a fresh random reuse guard, so two encryptions of the same content never match — it is a
round-trip through an independently constructed secret tree, which is what §4.2.1 means by
generating a fresh vector and verifying it on an independent code path.

- [ ] **Step 1: Write the failing test**

```go
// message_protection_kat_test.go
package mls

import (
    "bytes"
    "encoding/json"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func init() {
    RegisterVectorFamily(VectorFamily{
        Number:   4,
        Name:     "message-protection",
        File:     "message-protection.json",
        Slice:    "A1",
        Verify:   verifyMessageProtectionVector,
        Generate: generateMessageProtectionVector,
    })
}

// hex strings, decoded with the validation plan's MustHex. one hex decoder in
// the package, not one per harness.
type messageProtectionVector struct {
    CipherSuite             uint16 `json:"cipher_suite"`
    GroupId                 string `json:"group_id"`
    Epoch                   uint64 `json:"epoch"`
    TreeHash                string `json:"tree_hash"`
    ConfirmedTranscriptHash string `json:"confirmed_transcript_hash"`
    SignaturePriv           string `json:"signature_priv"`
    SignaturePub            string `json:"signature_pub"`
    EncryptionSecret        string `json:"encryption_secret"`
    SenderDataSecret        string `json:"sender_data_secret"`
    MembershipKey           string `json:"membership_key"`
    Proposal                string `json:"proposal"`
    ProposalPub             string `json:"proposal_pub"`
    ProposalPriv            string `json:"proposal_priv"`
    Commit                  string `json:"commit"`
    CommitPub               string `json:"commit_pub"`
    CommitPriv              string `json:"commit_priv"`
    Application             string `json:"application"`
    ApplicationPriv         string `json:"application_priv"`
}

// the serialized GroupContext the vector describes. C4: callers build these
// with syntax.Marshal over the key-schedule plan's struct, so the harness and
// the production path use one serializer.
func (self *messageProtectionVector) groupContextBytes(t *testing.T) []byte {
    t.Helper()
    groupContext := &GroupContext{
        Version:                 ProtocolVersionMls10,
        CipherSuite:             CipherSuite(self.CipherSuite),
        GroupId:                 MustHex(t, self.GroupId),
        Epoch:                   self.Epoch,
        TreeHash:                MustHex(t, self.TreeHash),
        ConfirmedTranscriptHash: MustHex(t, self.ConfirmedTranscriptHash),
    }
    encoded, err := syntax.Marshal(groupContext)
    if err != nil {
        t.Fatalf("group context: %v", err)
    }
    return encoded
}

// the whole of §4.2.1's procedure for one vector. registered as the family's
// Verify hook, so the vector runner and the local test drive the same code.
func verifyMessageProtectionVector(t *testing.T, raw json.RawMessage) {
    vector := messageProtectionVector{}
    if err := json.Unmarshal(raw, &vector); err != nil {
        t.Fatalf("parse vector: %v", err)
    }
    crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
    if err != nil {
        t.Fatalf("crypto: %v", err)
    }
    groupContext := vector.groupContextBytes(t)
    membershipKey := MustHex(t, vector.MembershipKey)
    senderDataSecret := MustHex(t, vector.SenderDataSecret)
    encryptionSecret := MustHex(t, vector.EncryptionSecret)
    signPriv := SignaturePrivateKey(MustHex(t, vector.SignaturePriv))
    resolve := StaticSignatureKey(SignaturePublicKey(MustHex(t, vector.SignaturePub)))

    // steps 3 and 4: the pub messages verify and re-encode to the raw value
    for _, c := range []struct {
        name string
        pub  []byte
        raw  []byte
    }{
        {"proposal", MustHex(t, vector.ProposalPub), MustHex(t, vector.Proposal)},
        {"commit", MustHex(t, vector.CommitPub), MustHex(t, vector.Commit)},
    } {
        message, err := ParseMLSMessage(c.pub)
        if err != nil {
            t.Fatalf("%s: parse: %v", c.name, err)
        }
        if message.PublicMessage == nil {
            t.Fatalf("%s: not a PublicMessage", c.name)
        }
        opened, err := OpenPublicMessage(crypto, membershipKey, message.PublicMessage,
            resolve, groupContext)
        if err != nil {
            t.Fatalf("%s: open: %v", c.name, err)
        }
        var reencoded []byte
        switch c.name {
        case "proposal":
            reencoded, err = syntax.Marshal(opened.Content.Proposal)
        case "commit":
            reencoded, err = syntax.Marshal(opened.Content.Commit)
        }
        if err != nil {
            t.Fatalf("%s: re-marshal: %v", c.name, err)
        }
        if !bytes.Equal(reencoded, c.raw) {
            t.Fatalf("%s: raw %x, want %x", c.name, reencoded, c.raw)
        }

        // re-protect the raw value and re-verify it
        resealed, err := SealPublicMessage(crypto, membershipKey, opened, groupContext)
        if err != nil {
            t.Fatalf("%s: reseal: %v", c.name, err)
        }
        if _, err := OpenPublicMessage(crypto, membershipKey, resealed, resolve, groupContext); err != nil {
            t.Fatalf("%s: re-open: %v", c.name, err)
        }
    }

    // step 4's exception: an application message MUST NOT protect as a PublicMessage
    applicationContent := &FramedContent{
        GroupId:         MustHex(t, vector.GroupId),
        Epoch:           vector.Epoch,
        Sender:          Sender{SenderType: SenderTypeMember, LeafIndex: 1},
        ContentType:     ContentTypeApplication,
        ApplicationData: MustHex(t, vector.Application),
    }
    applicationAuth, err := SignAuthenticatedContent(crypto, signPriv, WireFormatPublicMessage,
        applicationContent, groupContext)
    if err != nil {
        t.Fatalf("application sign: %v", err)
    }
    if _, err := SealPublicMessage(crypto, membershipKey, applicationAuth, groupContext); !errors.Is(err, ErrApplicationMustBeCiphertext) {
        t.Fatalf("application sealed as a PublicMessage: %v", err)
    }

    // steps 5 and 6: the priv messages unprotect, and re-protecting through an
    // independently constructed secret tree round-trips
    for _, encoded := range [][]byte{
        MustHex(t, vector.ProposalPriv),
        MustHex(t, vector.CommitPriv),
        MustHex(t, vector.ApplicationPriv),
    } {
        message, err := ParseMLSMessage(encoded)
        if err != nil {
            t.Fatalf("parse: %v", err)
        }
        if message.PrivateMessage == nil {
            t.Fatal("not a PrivateMessage")
        }
        // a fresh secret tree per message: the vector's messages are each at
        // generation 0 of their own ratchet. LeafCount, not a uint32 size.
        secretTree, err := NewSecretTree(crypto, LeafCount(2), encryptionSecret)
        if err != nil {
            t.Fatalf("secret tree: %v", err)
        }
        opened, err := OpenPrivateMessage(crypto, secretTree, senderDataSecret,
            message.PrivateMessage, resolve, groupContext)
        if err != nil {
            t.Fatalf("open: %v", err)
        }
        if opened.Content.Sender.LeafIndex != 1 {
            t.Fatalf("sender leaf %d, want 1", opened.Content.Sender.LeafIndex)
        }

        sealTree, err := NewSecretTree(crypto, LeafCount(2), encryptionSecret)
        if err != nil {
            t.Fatalf("seal tree: %v", err)
        }
        resealed, err := SealPrivateMessage(crypto, sealTree, senderDataSecret, opened, PaddingSizeV1)
        if err != nil {
            t.Fatalf("reseal: %v", err)
        }
        openTree, err := NewSecretTree(crypto, LeafCount(2), encryptionSecret)
        if err != nil {
            t.Fatalf("reopen tree: %v", err)
        }
        reopened, err := OpenPrivateMessage(crypto, openTree, senderDataSecret,
            resealed, resolve, groupContext)
        if err != nil {
            t.Fatalf("reopen: %v", err)
        }
        if !bytes.Equal(reopened.Content.ApplicationData, opened.Content.ApplicationData) {
            t.Fatal("application data diverged")
        }
    }
}

// the generate direction: build a fresh vector from freshly sampled keys and
// secrets, in the vector file's own JSON shape. the runner feeds it straight
// back to Verify, which is what §4.2.1 means by an independent code path.
func generateMessageProtectionVector(t *testing.T) json.RawMessage {
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
    if err != nil {
        t.Fatalf("crypto: %v", err)
    }
    signPriv, signPub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    encryptionSecret := crypto.Random(crypto.HashSize())
    senderDataSecret := crypto.Random(crypto.HashSize())
    membershipKey := crypto.Random(crypto.HashSize())

    vector := messageProtectionVector{
        CipherSuite:             uint16(CipherSuiteX25519ChaCha20Sha256Ed25519),
        GroupId:                 HexOf([]byte{0x01, 0x02, 0x03, 0x04}),
        Epoch:                   3,
        TreeHash:                HexOf(crypto.Random(crypto.HashSize())),
        ConfirmedTranscriptHash: HexOf(crypto.Random(crypto.HashSize())),
        SignaturePriv:           HexOf(signPriv),
        SignaturePub:            HexOf(signPub),
        EncryptionSecret:        HexOf(encryptionSecret),
        SenderDataSecret:        HexOf(senderDataSecret),
        MembershipKey:           HexOf(membershipKey),
        Application:             HexOf([]byte("generated application payload")),
    }
    groupContext := vector.groupContextBytes(t)
    groupId := MustHex(t, vector.GroupId)
    sender := Sender{SenderType: SenderTypeMember, LeafIndex: 1}

    proposal := &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 0}}
    proposalBytes, err := syntax.Marshal(proposal)
    if err != nil {
        t.Fatalf("proposal: %v", err)
    }
    vector.Proposal = HexOf(proposalBytes)

    commit := &Commit{}
    commitBytes, err := syntax.Marshal(commit)
    if err != nil {
        t.Fatalf("commit: %v", err)
    }
    vector.Commit = HexOf(commitBytes)

    confirmationTag := crypto.Random(crypto.HashSize())
    contents := []*FramedContent{
        {GroupId: groupId, Epoch: vector.Epoch, Sender: sender,
            ContentType: ContentTypeProposal, Proposal: proposal},
        {GroupId: groupId, Epoch: vector.Epoch, Sender: sender,
            ContentType: ContentTypeCommit, Commit: commit},
        {GroupId: groupId, Epoch: vector.Epoch, Sender: sender,
            ContentType: ContentTypeApplication, ApplicationData: MustHex(t, vector.Application)},
    }

    // the two public arms
    for i, content := range contents[:2] {
        authContent, err := SignAuthenticatedContent(crypto, signPriv, WireFormatPublicMessage,
            content, groupContext)
        if err != nil {
            t.Fatalf("public sign: %v", err)
        }
        if content.ContentType == ContentTypeCommit {
            authContent.Auth.ConfirmationTag = confirmationTag
        }
        message, err := SealPublicMessage(crypto, membershipKey, authContent, groupContext)
        if err != nil {
            t.Fatalf("public seal: %v", err)
        }
        encoded, err := MarshalMLSMessage(&MLSMessage{
            Version:       ProtocolVersionMls10,
            WireFormat:    WireFormatPublicMessage,
            PublicMessage: message,
        })
        if err != nil {
            t.Fatalf("public marshal: %v", err)
        }
        if i == 0 {
            vector.ProposalPub = HexOf(encoded)
        } else {
            vector.CommitPub = HexOf(encoded)
        }
    }

    // the three private arms, each from its own generation-0 secret tree
    for i, content := range contents {
        authContent, err := SignAuthenticatedContent(crypto, signPriv, WireFormatPrivateMessage,
            content, groupContext)
        if err != nil {
            t.Fatalf("private sign: %v", err)
        }
        if content.ContentType == ContentTypeCommit {
            authContent.Auth.ConfirmationTag = confirmationTag
        }
        secretTree, err := NewSecretTree(crypto, LeafCount(2), encryptionSecret)
        if err != nil {
            t.Fatalf("secret tree: %v", err)
        }
        message, err := SealPrivateMessage(crypto, secretTree, senderDataSecret,
            authContent, PaddingSizeV1)
        if err != nil {
            t.Fatalf("private seal: %v", err)
        }
        encoded, err := MarshalMLSMessage(&MLSMessage{
            Version:        ProtocolVersionMls10,
            WireFormat:     WireFormatPrivateMessage,
            PrivateMessage: message,
        })
        if err != nil {
            t.Fatalf("private marshal: %v", err)
        }
        switch i {
        case 0:
            vector.ProposalPriv = HexOf(encoded)
        case 1:
            vector.CommitPriv = HexOf(encoded)
        case 2:
            vector.ApplicationPriv = HexOf(encoded)
        }
    }

    raw, err := json.Marshal(&vector)
    if err != nil {
        t.Fatalf("encode vector: %v", err)
    }
    return json.RawMessage(raw)
}

func TestMessageProtectionVectors(t *testing.T) {
    for i, raw := range LoadVectorFile(t, "message-protection.json") {
        t.Run(fmt.Sprintf("vector%d", i), func(t *testing.T) {
            verifyMessageProtectionVector(t, raw)
        })
    }
}

// the generate direction, verified on the same path the vendored vectors take.
func TestMessageProtectionVectorsGenerate(t *testing.T) {
    verifyMessageProtectionVector(t, generateMessageProtectionVector(t))
}
```

`message_protection_kat_test.go` needs `"errors"` and `"fmt"` in its import block alongside
`"bytes"`, `"encoding/json"`, `"testing"` and `syntax`.

The generate direction is not a byte comparison against the vendored file — a `PrivateMessage`
carries a fresh random reuse guard, so two encryptions of the same content never match. It is a
freshly generated vector fed back through the verify path, which is what §4.2.1 asks for.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestMessageProtectionVectors' -v`
Expected: FAIL — `undefined: verifyMessageProtectionVector`, then a `LoadVectorFile` failure on the
missing `testdata/vectors/message-protection.json` before it fails on anything interesting.

- [ ] **Step 3: Confirm the vendored file and deregister the pending family**

`connect/mls/testdata/vectors/message-protection.json` is vendored by the validation plan's single
vendoring task, at the commit recorded in `connect/mls/interop/PINS.md` (not
`connect/mls/PINS.md`, which does not exist, and not
`connect/mls/testdata/vectors/PINS.md`, which does not either). This plan does **not** re-vendor
it: one vendoring task, one `VECTORS.sha256`, one pin file.

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect/mls
test -f testdata/vectors/message-protection.json || echo "blocked: the vendoring task has not run"
grep -n '^mlswg=' interop/PINS.md
```

Then delete `4` from `expectedPendingFamilies` in the validation plan's vector registry, in this
same commit. The `init()` registration and that deletion are one change: without the deletion the
registry still reports family 4 as unimplemented, and with the deletion but no registration
`TestVectorFamiliesVerify` fails naming it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestMessageProtectionVectors|TestVectorFamilies' -v`
Expected: PASS — one subtest per vector in the file, the generate direction, and the registry's own
family sweep now including family 4.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/message_protection_kat_test.go mls/vectors_test.go
git ls-files | wc -l   # MUST be previous + 1
git commit -m "test(mls): message-protection vector family, verify and generate directions"
```

---

### Task 18: The `messages` vector family

**Files:**
- Create: `connect/mls/messages_kat_test.go`
- Test data: `connect/mls/testdata/vectors/messages.json` (vendored by p8 Task 6)

**Interfaces:**
- Consumes: `Welcome`, `GroupInfo`, `GroupSecrets`, `Commit`, `Proposal` (Tasks 12–15);
  `type KeyPackage struct{ ... }` and `type LeafNode struct{ ... }` with their codecs,
  `func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)`,
  `func (self *RatchetTree) MarshalMLS(w *syntax.Writer) error`,
  `func WriteExtensions(w *syntax.Writer, exts []Extension) error`,
  `func ReadExtensions(r *syntax.Reader) ([]Extension, error)` (p5, wave 2);
  `type PreSharedKeyId struct{ ... }` with its codec (p4, wave 2);
  `func CheckRoundTrip[T any, PT interface{ *T; syntax.Codec }](bs []byte) error`,
  `syntax.Marshal`, `syntax.Unmarshal` (p1);
  `RegisterVectorFamily`, `VectorFamily`, `LoadVectorFile`, `MustHex` (p8, wave 1).
- Produces: nothing exported; this is the gate. `init()` registers family 12 and the same commit
  deletes `12` from `expectedPendingFamilies`.

The procedure is one rule applied to seventeen fields: **decode with the corresponding structure,
re-encode, and the bytes must be identical.** Objects must be syntactically valid; a MAC inside one
may be arbitrary and is not verified.

Where the field is a standalone `syntax.Codec`, the check is literally `syntax.CheckRoundTrip` —
the same property Gate 4 asserts, on the same code path, rather than a hand-rolled comparison. The
five fields that are a bare arm body rather than a whole wire type (`remove_proposal`,
`re_init_proposal`, `external_init_proposal`, `group_context_extensions_proposal`, and
`ratchet_tree`, which needs the 16 MiB limit) go through explicit reader/writer closures.

The table is written as data so a field that has no decoder is a compile error naming the field,
not a silent skip. If a type this table names has not merged yet, comment out **that row only** and
open an issue — never the whole test; the row count assertion turns red and says which.

- [ ] **Step 1: Write the failing test**

```go
// messages_kat_test.go
package mls

import (
    "bytes"
    "encoding/json"
    "fmt"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func init() {
    RegisterVectorFamily(VectorFamily{
        Number: 12,
        Name:   "messages",
        File:   "messages.json",
        Slice:  "A1",
        Verify: verifyMessagesVector,
        // no generate direction: the family is a corpus of foreign encodings,
        // and re-emitting our own would test nothing the round trip does not
    })
}

type messagesVector struct {
    MlsWelcome                     string `json:"mls_welcome"`
    MlsGroupInfo                   string `json:"mls_group_info"`
    MlsKeyPackage                  string `json:"mls_key_package"`
    RatchetTree                    string `json:"ratchet_tree"`
    GroupSecrets                   string `json:"group_secrets"`
    AddProposal                    string `json:"add_proposal"`
    UpdateProposal                 string `json:"update_proposal"`
    RemoveProposal                 string `json:"remove_proposal"`
    PreSharedKeyProposal           string `json:"pre_shared_key_proposal"`
    ReInitProposal                 string `json:"re_init_proposal"`
    ExternalInitProposal           string `json:"external_init_proposal"`
    GroupContextExtensionsProposal string `json:"group_context_extensions_proposal"`
    Commit                         string `json:"commit"`
    PublicMessageApplication       string `json:"public_message_application"`
    PublicMessageProposal          string `json:"public_message_proposal"`
    PublicMessageCommit            string `json:"public_message_commit"`
    PrivateMessage                 string `json:"private_message"`
}

// one row per field. a field with no checker does not compile, and the row
// count assertion below names the shortfall.
type messagesCodec struct {
    name  string
    field func(v *messagesVector) string
    check func(data []byte) error
}

// the explicit form, for the five fields that are a bare arm body rather than a
// standalone wire type.
func checkReEncode(data []byte, decode func(r *syntax.Reader) error,
    encode func(w *syntax.Writer) error) error {

    r := syntax.NewReader(data)
    if err := decode(r); err != nil {
        return err
    }
    if err := r.Done(); err != nil {
        return err
    }
    w := syntax.NewWriter()
    if err := encode(w); err != nil {
        return err
    }
    encoded, err := w.Bytes()
    if err != nil {
        return err
    }
    if !bytes.Equal(encoded, data) {
        return fmt.Errorf("re-encoded %x, want %x", encoded, data)
    }
    return nil
}

// every byte of an MLSMessage goes through the one entry point the whole system
// names, not through a second decode path invented for the harness.
func checkMLSMessageReEncode(data []byte) error {
    message, err := ParseMLSMessage(data)
    if err != nil {
        return err
    }
    encoded, err := MarshalMLSMessage(message)
    if err != nil {
        return err
    }
    if !bytes.Equal(encoded, data) {
        return fmt.Errorf("re-encoded %x, want %x", encoded, data)
    }
    return nil
}

func messagesCodecs() []messagesCodec {
    return []messagesCodec{
        // produced by this plan
        {"commit", func(v *messagesVector) string { return v.Commit },
            syntax.CheckRoundTrip[Commit, *Commit]},
        {"mls_welcome", func(v *messagesVector) string { return v.MlsWelcome },
            checkMLSMessageReEncode},
        {"mls_group_info", func(v *messagesVector) string { return v.MlsGroupInfo },
            checkMLSMessageReEncode},
        {"group_secrets", func(v *messagesVector) string { return v.GroupSecrets },
            syntax.CheckRoundTrip[GroupSecrets, *GroupSecrets]},
        {"public_message_application", func(v *messagesVector) string { return v.PublicMessageApplication },
            checkMLSMessageReEncode},
        {"public_message_proposal", func(v *messagesVector) string { return v.PublicMessageProposal },
            checkMLSMessageReEncode},
        {"public_message_commit", func(v *messagesVector) string { return v.PublicMessageCommit },
            checkMLSMessageReEncode},
        {"private_message", func(v *messagesVector) string { return v.PrivateMessage },
            checkMLSMessageReEncode},

        // the proposal arm bodies. the vector carries the BODY, not a framed
        // Proposal, so the two whole-type arms decode as their own types and
        // the rest go through explicit closures.
        {"add_proposal", func(v *messagesVector) string { return v.AddProposal },
            syntax.CheckRoundTrip[KeyPackage, *KeyPackage]},
        {"update_proposal", func(v *messagesVector) string { return v.UpdateProposal },
            syntax.CheckRoundTrip[LeafNode, *LeafNode]},
        {"pre_shared_key_proposal", func(v *messagesVector) string { return v.PreSharedKeyProposal },
            syntax.CheckRoundTrip[PreSharedKeyId, *PreSharedKeyId]},
        {"remove_proposal", func(v *messagesVector) string { return v.RemoveProposal },
            func(data []byte) error {
                value := Remove{}
                return checkReEncode(data,
                    func(r *syntax.Reader) error {
                        removed, err := r.ReadUint32()
                        if err != nil {
                            return err
                        }
                        value.Removed = LeafIndex(removed)
                        return nil
                    },
                    func(w *syntax.Writer) error {
                        w.WriteUint32(uint32(value.Removed))
                        return nil
                    })
            }},
        {"re_init_proposal", func(v *messagesVector) string { return v.ReInitProposal },
            func(data []byte) error {
                value := ReInit{}
                return checkReEncode(data,
                    func(r *syntax.Reader) error {
                        groupId, err := r.ReadOpaque()
                        if err != nil {
                            return err
                        }
                        version, err := r.ReadUint16()
                        if err != nil {
                            return err
                        }
                        suite, err := r.ReadUint16()
                        if err != nil {
                            return err
                        }
                        extensions, err := ReadExtensions(r)
                        if err != nil {
                            return err
                        }
                        value = ReInit{
                            GroupId:     groupId,
                            Version:     ProtocolVersion(version),
                            CipherSuite: CipherSuite(suite),
                            Extensions:  extensions,
                        }
                        return nil
                    },
                    func(w *syntax.Writer) error {
                        w.WriteOpaque(value.GroupId)
                        w.WriteUint16(uint16(value.Version))
                        w.WriteUint16(uint16(value.CipherSuite))
                        return WriteExtensions(w, value.Extensions)
                    })
            }},
        {"external_init_proposal", func(v *messagesVector) string { return v.ExternalInitProposal },
            func(data []byte) error {
                value := ExternalInit{}
                return checkReEncode(data,
                    func(r *syntax.Reader) error {
                        kemOutput, err := r.ReadOpaque()
                        if err != nil {
                            return err
                        }
                        value.KemOutput = kemOutput
                        return nil
                    },
                    func(w *syntax.Writer) error {
                        w.WriteOpaque(value.KemOutput)
                        return nil
                    })
            }},
        {"group_context_extensions_proposal", func(v *messagesVector) string {
            return v.GroupContextExtensionsProposal
        },
            func(data []byte) error {
                value := GroupContextExtensions{}
                return checkReEncode(data,
                    func(r *syntax.Reader) error {
                        extensions, err := ReadExtensions(r)
                        if err != nil {
                            return err
                        }
                        value.Extensions = extensions
                        return nil
                    },
                    func(w *syntax.Writer) error {
                        return WriteExtensions(w, value.Extensions)
                    })
            }},

        // produced by other plans, decoded through their types
        {"mls_key_package", func(v *messagesVector) string { return v.MlsKeyPackage },
            checkMLSMessageReEncode},
        {"ratchet_tree", func(v *messagesVector) string { return v.RatchetTree },
            func(data []byte) error {
                // the tree is the one field that must NOT use the 1 MiB default
                // vector limit; UnmarshalRatchetTree carries the 16 MiB one
                tree, err := UnmarshalRatchetTree(data)
                if err != nil {
                    return err
                }
                encoded, err := syntax.Marshal(tree)
                if err != nil {
                    return err
                }
                if !bytes.Equal(encoded, data) {
                    return fmt.Errorf("re-encoded %x, want %x", encoded, data)
                }
                return nil
            }},
    }
}

func verifyMessagesVector(t *testing.T, raw json.RawMessage) {
    vector := messagesVector{}
    if err := json.Unmarshal(raw, &vector); err != nil {
        t.Fatalf("parse vector: %v", err)
    }
    codecs := messagesCodecs()
    if len(codecs) != 17 {
        t.Fatalf("%d codecs, want 17 — every field in the vector needs one", len(codecs))
    }
    for _, codec := range codecs {
        encoded := codec.field(&vector)
        if encoded == "" {
            t.Errorf("%s: empty", codec.name)
            continue
        }
        if err := codec.check(MustHex(t, encoded)); err != nil {
            t.Errorf("%s: %v", codec.name, err)
        }
    }
}

func TestMessagesVectorsRoundTripByteExact(t *testing.T) {
    for i, raw := range LoadVectorFile(t, "messages.json") {
        t.Run(fmt.Sprintf("vector%d", i), func(t *testing.T) {
            verifyMessagesVector(t, raw)
        })
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestMessagesVectors' -v`
Expected: FAIL — a `LoadVectorFile` failure on the missing `testdata/vectors/messages.json`, then
compile errors naming whichever of `KeyPackage`, `LeafNode`, `RatchetTree`, `PreSharedKeyId` are
not yet merged.

- [ ] **Step 3: Confirm the vendored file and deregister the pending family**

The file is vendored by the validation plan's single vendoring task; this plan does not re-vendor
it.

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect/mls
test -f testdata/vectors/messages.json || echo "blocked: the vendoring task has not run"
```

Delete `12` from `expectedPendingFamilies` in the vector registry, in this same commit.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestMessagesVectors|TestVectorFamilies' -v`
Expected: PASS — one subtest per vector, 17 fields each, and the registry sweep now including
family 12.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/messages_kat_test.go mls/vectors_test.go
git ls-files | wc -l   # MUST be previous + 1
git commit -m "test(mls): messages vector family, byte-exact re-encoding for all 17 fields"
```

---

### Task 19: The constant-time comparison gate and the fuzz seed corpus

**Files:**
- Create: `connect/mls/framing_guard_test.go`
- Test data: `connect/mls/testdata/corpus/` (owned by the validation plan; this task contributes
  four seeds)

**Interfaces:**
- Consumes: Tasks 1–18; `func LoadVectorFile(t *testing.T, file string) []json.RawMessage`,
  `func MustHex(t *testing.T, s string) []byte` (p8, wave 1).
- Produces: `TestFramingUsesConstantTimeComparison` and `TestWriteFramingCorpusSeeds`. **No fuzz
  targets.**

**All nine Gate-4 fuzz targets are p8's** (registry §9.5). `FuzzMlsMessageDecode`,
`FuzzMlsMessageDecodeBytes`, `FuzzProposalDecode` and `FuzzProposalDecodeBytes` were declared here
and are deleted: p8 owns the codec table and the oracle hook that property 3 needs, and its
`TestFuzzTargetsCoverEveryKind` parses the target file with `go/ast` so a deleted target turns red.
This plan contributes **seed corpus only**, which is the part that actually needs the vector
knowledge that lives here.

`TestFramingUsesConstantTimeComparison` replaces the `bytes.Equal` grep gate of Spec A §5.9 G8 with
a test, so the gate cannot be defeated by a shell script that stops being run.

- [ ] **Step 1: Write the failing test**

```go
// framing_guard_test.go
package mls

import (
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

// Spec A §5.9 G8, as a test rather than a shell grep: a grep gate stops being
// a gate the first time someone runs the suite without the script.
func TestFramingUsesConstantTimeComparison(t *testing.T) {
    sources := []string{
        "framing.go", "framing_preimage.go", "framing_protect.go",
        "framing_errors.go", "proposal_wire.go", "commit_wire.go", "welcome_wire.go",
    }
    for _, name := range sources {
        source, err := os.ReadFile(name)
        if err != nil {
            t.Fatalf("%s: %v", name, err)
        }
        for _, forbidden := range []string{"bytes.Equal", "bytes.Compare", "reflect.DeepEqual"} {
            if strings.Contains(string(source), forbidden) {
                t.Errorf("%s uses %s; tag and key comparisons must go through subtle.ConstantTimeCompare or CryptoProvider.MacVerify", name, forbidden)
            }
        }
    }
}

// the seed-corpus contribution to the validation plan's nine Gate-4 targets.
// this plan owns no fuzz target; it owns the knowledge of which vector fields
// make good seeds, which is what this writes out. guarded by an env var so a
// normal test run never touches the tracked corpus.
func TestWriteFramingCorpusSeeds(t *testing.T) {
    outDir := os.Getenv("URMSG_MLS_WRITE_CORPUS")
    if outDir == "" {
        t.Skip("set URMSG_MLS_WRITE_CORPUS=<dir> to regenerate the framing seed corpus")
    }
    if err := os.MkdirAll(outDir, 0o755); err != nil {
        t.Fatalf("mkdir: %v", err)
    }

    raws := LoadVectorFile(t, "messages.json")
    vector := messagesVector{}
    if err := json.Unmarshal(raws[0], &vector); err != nil {
        t.Fatalf("parse vector: %v", err)
    }

    // a Proposal seed is the arm body framed with its uint16 discriminant,
    // because the fuzz target decodes a whole Proposal
    framedRemove, err := syntax.Marshal(&Proposal{
        ProposalType: ProposalTypeRemove,
        Remove:       &Remove{Removed: 0},
    })
    if err != nil {
        t.Fatalf("remove proposal: %v", err)
    }

    seeds := map[string][]byte{
        "mls_message_public.bin":  MustHex(t, vector.PublicMessageProposal),
        "mls_message_private.bin": MustHex(t, vector.PrivateMessage),
        "mls_message_welcome.bin": MustHex(t, vector.MlsWelcome),
        "proposal_remove.bin":     framedRemove,
    }
    for name, data := range seeds {
        if err := os.WriteFile(filepath.Join(outDir, name), data, 0o644); err != nil {
            t.Fatalf("%s: %v", name, err)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestFramingUsesConstantTimeComparison|TestWriteFramingCorpusSeeds' -v`
Expected: FAIL — the guard test reports a missing file until `welcome_wire.go` and the other six
sources exist, and the seed test is skipped. It turns green once Tasks 1–18 have landed.

- [ ] **Step 3: Write the seed corpus into the validation plan's corpus directory**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect/mls
URMSG_MLS_WRITE_CORPUS=testdata/corpus \
  go test ./... -run 'TestWriteFramingCorpusSeeds' -v
```

`testdata/corpus/` is committed and owned by the validation plan alongside `interop/cmd/seedgen`;
this task adds four files to it and nothing else. A missing seed weakens a fuzz run rather than
breaking it, so this step is not a gate.

- [ ] **Step 4: Run the guard test and the package once**

Run:
```
go test ./connect/mls/... -run 'TestFramingUsesConstantTimeComparison' -v
go test ./connect/mls/... -race -timeout 0
```
Expected: PASS — the guard test green, and every test in this plan plus everything waves 1 and 2
merged. The nine fuzz targets are run by the validation plan's own gate, not from here.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_guard_test.go mls/testdata/corpus
git ls-files | wc -l   # MUST be previous + 1 + the number of new corpus files
git commit -m "test(mls): the constant-time comparison gate and the framing fuzz seed corpus"
```

---

### Task 20: The two construction-bypass seams for the validation forge

**Files:**
- Create: `connect/mls/framing_group_seams.go`

**Interfaces:**
- Consumes: `type Group struct{ ... }` and `func (self *Group) GroupContext() ([]byte, error)`
  (p7 §8.3, **wave 4**); `func (self *KeySchedule) Secrets() *EpochSecrets` with the
  `EpochSecrets.Membership` and `EpochSecrets.SenderData` fields (p4 §5.2);
  `type SecretTree struct{ ... }` as a `MessageKeySource` (p4 §5.5). Tasks 1–15.
- Produces:
  ```go
  func (self *Group) sealFramedContentForTest(c *FramedContent, auth *FramedContentAuthData,
      wf WireFormat, signer SignaturePrivateKey) ([]byte, error)
  func (self *Group) sealFramedContentWithPaddingForTest(c *FramedContent, auth *FramedContentAuthData,
      wf WireFormat, signer SignaturePrivateKey, padding []byte) ([]byte, error)
  ```

**These are this plan's, with the validation plan's exact signatures** (registry §7.3 and §12). All
ten of that plan's ValSem002–011 tests depend on them; it flagged them as "an ask on that plan" and
no task here took the ask, so nothing would have failed until integration. They are methods on
`*Group` because a forged message must carry the group's real epoch keys — only the sender-chosen
fields are overridden.

**Sequencing.** `*Group` is the lifecycle plan's type and lands in wave 4, so this task executes
after it, even though the file is owned here. That is a scheduling fact, not a dependency inversion:
the seams are framing operations and belong beside the framing code that performs them.

**The one coupling this task carries** is three unexported `Group` fields: `crypto CryptoProvider`,
`keySchedule *KeySchedule` and `secretTree *SecretTree`. Everything reached through them —
`(*KeySchedule).Secrets()`, `EpochSecrets.Membership`, `EpochSecrets.SenderData`, and `*SecretTree`
satisfying `MessageKeySource` — is a registry symbol.

- [ ] **Step 1: Write the failing test**

This task's tests are the ten ValSem002–011 tests in the validation plan, which already exist and
already call these two names. The failing state is therefore that plan's suite:

Run: `go test ./connect/mls/... -run 'TestValSem0(0[2-9]|1[01])' -v`
Expected: FAIL — `self.sealFramedContentForTest undefined (type *Group has no field or method
sealFramedContentForTest)`, at every one of the ten.

Do **not** add a duplicate test here: two tests over one seam is how the seam and the tests drift
into disagreeing about which fields the caller controls.

- [ ] **Step 2: Confirm the failure is the missing seam and not a missing Group**

Run: `go build ./connect/mls/...`
Expected: the package builds. If it does not, the lifecycle plan has not landed `Group` yet and this
task is blocked, not stubbed.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_group_seams.go
// construction-bypass seams for the validation plan's forge. every one of the
// ValSem002-011 negative tests needs to put a message on the wire that a
// correct sender would never produce - a stripped membership tag, a commit
// without a confirmation tag, non-zero padding - while keeping the group's real
// epoch keys, so the receiver fails for the reason under test rather than
// because the ciphertext was nonsense. unexported: nothing outside package mls
// can reach them, and the production Seal* entry points cannot express them.
package mls

func (self *Group) sealFramedContentForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey) ([]byte, error) {

    return self.sealFramedContentWithPaddingForTest(c, auth, wf, signer, nil)
}

func (self *Group) sealFramedContentWithPaddingForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey, padding []byte) ([]byte, error) {

    groupContext, err := self.GroupContext()
    if err != nil {
        return nil, err
    }
    // sign normally first, so the signature is over the caller's content and
    // only the auth data is forged
    authContent, err := SignAuthenticatedContent(self.crypto, signer, wf, c, groupContext)
    if err != nil {
        return nil, err
    }
    if auth != nil {
        authContent.Auth = *auth
    }

    secrets := self.keySchedule.Secrets()
    message := &MLSMessage{Version: ProtocolVersionMls10, WireFormat: wf}
    switch wf {
    case WireFormatPublicMessage:
        publicMessage, err := SealPublicMessage(self.crypto, secrets.Membership,
            authContent, groupContext)
        if err != nil {
            return nil, err
        }
        message.PublicMessage = publicMessage
    case WireFormatPrivateMessage:
        privateMessage, err := sealPrivateMessage(self.crypto, self.secretTree,
            secrets.SenderData, authContent, padding)
        if err != nil {
            return nil, err
        }
        message.PrivateMessage = privateMessage
    default:
        return nil, ErrWireFormatMismatch
    }
    return MarshalMLSMessage(message)
}
```

The seams return a whole encoded `MLSMessage`, through the same `MarshalMLSMessage` every sender
uses, so the forge hands the receiver exactly what the network would.

A forged `PublicMessage` carrying application content is still refused by `SealPublicMessage` with
ValSem005 — that refusal is the sender-side half of the code under test, and the forge exercises the
receiver-side half by hand-assembling the message instead. A forged commit with no confirmation tag
is likewise refused at `FramedContentAuthData.MarshalMLS`; the validation plan's
`CommitOptions.dropConfirmationTag` seam is the path for that case, and it is its own.

- [ ] **Step 4: Run the validation plan's framing ValSem suite**

Run: `go test ./connect/mls/... -run 'TestValSem0(0[2-9]|1[01])' -v`
Expected: PASS — all ten.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_group_seams.go
git ls-files | wc -l   # MUST be previous + 1
git commit -m "feat(mls): construction-bypass framing seams for the validation forge"
```

---

## Execution order

The task numbers are reading order. The dependency order, which is what an executor follows:

```
1  enums, Sender, structural errors
12 proposal wire types      (Task 2 does not compile without Proposal)
13 commit wire type         (Task 2 does not compile without Commit)
2  FramedContent
3  FramedContentAuthData
4  AuthenticatedContent + ConfirmedTranscriptHashInput + ProposalRef
5  FramedContentTBS, sign, verify
6  AuthenticatedContentTBM, membership tag
7  PublicMessage
8  PrivateMessage + AADs
9  SenderData + sender-data seal/open
10 PrivateMessageContent + padding
11 MessageKeySource, reuse guard, seal/open
14 GroupInfo / GroupSecrets / Welcome codecs
15 MLSMessage               (needs Welcome and GroupInfo from Task 14, KeyPackage from wave 2)
16 framing refusal roster
17 message-protection vectors  (family 4)
18 messages vectors            (family 12)
19 G8 gate + fuzz seed corpus
20 the two *ForTest seams      (WAVE 4: needs the lifecycle plan's *Group)
```

Tasks 1–14 depend on wave 1 (`syntax`, `CryptoProvider`, `LeafIndex`, the ValSem catalogue) and
wave 2 (`ProtocolVersion`, `ProposalType`, `Extension`, `WriteExtensions`/`ReadExtensions`,
`LeafNode`, `KeyPackage`, `HpkeCiphertext`, `UpdatePath`, `GroupContext`, `PreSharedKeyId`,
`SecretTree`). Task 15 additionally needs `KeyPackage` — which the registry assigns to the TreeKEM
plan in **wave 2**, precisely so this wave-3 struct can name it. Tasks 17–19 need the vector
registry and the vendored files. **Task 20 is the only wave-4 task in this plan**, because `*Group`
does not exist before then.

## What this plan deliberately does not cover

| Thing | Owner |
|---|---|
| `ConfirmedTranscriptHash` / `InterimTranscriptHash` chaining | key schedule (`transcript.go`); it consumes `(*AuthenticatedContent).ConfirmedTranscriptHashInput()` as **bytes**, so no framing type crosses into `transcript.go` |
| Computing `confirmation_tag` from `confirmation_key` | key schedule (wave 2); framing carries the tag and MACs over it, never derives it |
| `SenderDataKeyNonce`, the §6.3.2 derivation | key schedule (wave 2); this plan calls it and keeps the two short-ciphertext regression tests |
| The secret tree's ratchet, generation window and skipped-key store, including `EraseMessageKey` | key schedule and secret tree (wave 2), behind `MessageKeySource` |
| `ProtocolVersion`, `ProtocolVersionMls10`, `ProposalType` and its constants, `ExtensionType`, `CredentialType` | registry enums (wave 2) |
| `WriteExtensions` / `ReadExtensions` | extension file (wave 2) |
| `KeyPackage`, `LeafNode`, `UpdatePath`, `HpkeCiphertext`, `RatchetTree`, `Node`, `Extension` codecs | TreeKEM / leaf-node plan (wave 2) |
| `GroupContext` and `PreSharedKeyId` codecs | key schedule (wave 2) |
| `(*GroupInfo).Sign`, `(*GroupInfo).Verify`, `BuildWelcome`, `WelcomeJoiner`, `JoinFromWelcome` | group lifecycle (wave 4); this plan owns only the **codecs** for those types |
| The profile refusals — `(*Profile).CheckProposalType` and the six other `Check*` — and ValSem401–403 | validation plan (`profile.go`, wave 1), called by the lifecycle plan at the parse boundary |
| ValSem101–113, ValSem200–209, ValSem240–246, ValSem300, ValSem400 | proposal, commit and tree plans |
| The ten ValSem002–011 **sentinels** and the `TestValSemNNN_<slug>` test names | validation plan (`errors.go`, wave 1); this plan returns `ValSem(code, sentinel)` and names its own tests for behaviour |
| RFC 9420 errata 8745 and 8815 | group lifecycle, as `CheckErrata8745` / `CheckErrata8815` — **neither is a framing erratum** |
| All nine Gate 4 fuzz targets and the nightly OpenMLS differential | validation and interop plan; this plan contributes seed corpus |
| `MustHex`, `HexOf`, `LoadVectorFile`, `RegisterVectorFamily`, vendoring, `interop/PINS.md` | validation plan (wave 1) |
| `(*Group).Protect`/`Unprotect` and `ProcessMessage` | group lifecycle (wave 4), calling this plan's `SealPrivateMessage` / `OpenPrivateMessage` |

## Settled coordination items

Every item this plan previously raised as unsettled has been decided by the canonical interface
registry. They are recorded here as decisions, not as questions.

1. **`Proposal`, `ProposalOrRef` and `Commit` ownership** — settled in this plan's favour (§7.4).
   This plan owns the structs and codecs; the lifecycle plan keeps `proposal.go` (list validation),
   `commit.go` (application) and calls `(*Profile).CheckProposalType` at the parse boundary. The
   deciding argument is the one this plan made: the `messages` family cannot be green without all
   seven arms, and refusing a proposal type is a *profile* decision, not a *codec* one.
2. **`Welcome`, `GroupInfo`, `GroupInfoTBS`, `PathSecret`, `GroupSecrets`, `EncryptedGroupSecrets`
   codecs** — moved **into** this plan from the lifecycle plan (§7.5), because `MLSMessage` names
   `*Welcome` and `*GroupInfo` by direct type and one Go package cannot compile otherwise. Task 14.
3. **`hexBytes`** — deleted. The validation plan's wave-1 `MustHex`/`HexOf`/`LoadVectorFile` are the
   package's only hex path (§9.2).
4. **The `syntax` API shape** — confirmed as an explicit `Writer`/`Reader`, no reflection and no
   struct tags (C1). Two consequences this plan absorbed: `MarshalMLS` returns an `error` (O-1, and
   `FramedContent.MarshalMLS` returning `ErrContentArmMismatch` is one of the three cases that
   decided it), and `Bytes()` returns `([]byte, error)` rather than a bare slice.
5. **`NewSecretTree`** — `(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte)`.
   The second parameter is a `LeafCount`, not the `uint32` group size this plan assumed (C3, O-4).
   The three `MessageKeySource` methods and `EraseMessageKey` are gaps assigned to the key-schedule
   plan, and Task 11's `var _ MessageKeySource = (*SecretTree)(nil)` is what makes a mismatch fail
   at build.
6. **`MarshalGroupContext`** — not needed and not added. `syntax.Marshal` over the key-schedule
   plan's `*GroupContext` is the one GroupContext serializer in the system, and C4 keeps every entry
   point here taking `groupContext []byte`.
7. **`(*AuthenticatedContent).ProposalRef` and the two `*ForTest` seams** — gaps that four other
   plans called and nobody produced, now assigned here (§12). Tasks 4 and 20.
