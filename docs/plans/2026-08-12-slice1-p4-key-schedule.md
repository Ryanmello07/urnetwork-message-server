# Key Schedule and Secret Tree Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 9420 §8 (epoch key schedule, GroupContext binding, PSK secret, exporter,
confirmation and membership tags, transcript hashes) and §9 (secret tree, per-sender per-generation
handshake and application keys) in pure Go, passing the `key-schedule`, `psk_secret`,
`transcript-hashes` and `secret-tree` vector families in both directions.

**Architecture:** Five self-contained files in `connect/mls` — `group_context.go`, `key_schedule.go`,
`psk.go`, `transcript.go`, `secret_tree.go` — that consume only the `CryptoProvider` interface, the
tree-math index functions, the registry enums and `Extension`, and the `syntax` reader/writer.
Nothing here touches HPKE (except `DeriveKeyPair` for `external_pub`), the ratchet tree, framing, or
the group state machine, so the whole key schedule can be audited and fuzzed as arithmetic over byte
slices. The one exception is deliberate: `SecretTree` implements the `MessageKeySource` interface p6
declares, which means it names p6's `ContentType` — and only that. Secrets are consumed and
zeroized on use: a secret-tree node secret is deleted once its two children exist, a ratchet secret is
deleted once it has produced its generation's key, nonce and successor.

**Tech Stack:** Go 1.26.5, `crypto/hkdf` and `crypto/sha3` via the wave-1 `CryptoProvider` only,
`crypto/subtle` for tag comparison, `encoding/json` in tests, `testing`. The Gate-4 `Fuzz*` targets
are p8's; this plan contributes their seed corpus.

## Global Constraints

- Go 1.26.5, pinned, through the toolchain line. `connect/go.mod` keeps its `go 1.26.3` directive and gains `toolchain go1.26.5`; raising the directive would raise the language floor for all of `connect`, which is out of this slice's scope. The edit is p1 Task 1's and is made exactly once — nothing here touches `go.mod`.
- Standard library only for crypto: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, plus `chacha20poly1305` from the already-pinned `golang.org/x/crypto`.
- NO cgo, NO Rust, NO new third-party crypto dependency. `sdk` must stay gomobile-buildable.
- New dependencies permitted in `connect` on `beta/message`: **none.**
- OpenMLS is a READ-ONLY differential oracle used out of process in CI. Never in `go.mod`, never linked, never in a shipped artifact.
- Ciphersuite: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003) for real groups. `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) is implemented and vector-tested so the registry is not a hardcoded singleton. Every vector runner in this plan runs both and skips the other five.
- Narrow v1 profile: BasicCredential only, no external commits, no external senders, no PSKs, no ReInit, no branching, no subgroups. All parse-refused with typed errors.
- `connect` must NEVER import `connect/mls` or `connect/message`. A package must not import its own subpackages. `connect/mls` imports only stdlib, `golang.org/x/crypto` and `connect/mls/syntax`.
- `sdk.GenerateSharedSecret`, `box.Precompute` and `curve25519.ScalarMult` MUST NOT be used. All X25519 goes through `crypto/ecdh` or `curve25519.X25519`, and a returned error is a hard validation failure — never logged and continued.
- `crypto/hkdf.Extract` takes ikm first, salt second. RFC 9420 writes `KDF.Extract(salt, ikm)`. Only `CryptoProvider.Extract(salt, ikm)` from the wave-1 crypto plan may be called; `hkdf.Extract` appears nowhere in this package (G1, asserted by Task 27).
- Every tag comparison goes through `crypto/subtle.ConstantTimeCompare`, reached only via `CryptoProvider.MacVerify`. `bytes.Equal` on a tag is forbidden (G8, asserted by Task 27).
- `epoch_secret` is never returned by any exported symbol. `EpochSecretName` on `mls.Group` stays a closed two-value enum (G6, asserted by Task 12).
- MLS signs over serialized forms, so the codec must be byte-exact and round-trip stable. `GroupContext` and `PreSharedKeyId` round-trip properties are fuzzed (Task 26).
- Windows git hazard: this repo's index has silently truncated before. Run `git ls-files | wc -l` before and after every `git add` in this plan and confirm the count did not drop.
- Branch: `beta/message` on `Ryanmello07/urnetwork-connect`. Not proposed upstream.
- CODESTYLE: `self` receivers, `stateLock` for guarded state, explicit struct field names, doc comment on every file/type/func, `Id` not `ID`. Tests are top-level functions, never `t.Run` subtests.

### The four registry conventions (C1–C4)

Verbatim from `research/slice1-interface-registry.md`, which is normative: where it and this plan
disagree, it wins and this plan is amended.

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
  `func ParseXExtension(data []byte) (*X, error)`. Owned per-extension. **This plan owns no
  extension body**, so it uses neither form.
- **p8's codec table.** Five decode/encode closures over `syntax.Marshal`/`Unmarshal`, built inside
  p8 (§9.4). They export no new `Parse*`/`Encode*` names.

**C2 — the syntax Writer is sticky *and* `MarshalMLS` returns an error.** The leaf writes
(`WriteUint8`, `WriteUint16`, `WriteUint64`, `WriteRaw`, `WriteOpaque`) return nothing and are
no-ops after the first error; one check at `Bytes()` suffices. `MarshalMLS` returns `error` so a
*semantic* refusal — `PreSharedKeyId.MarshalMLS` on an unknown `psktype` — can surface instead of
being silently dropped into wrong signed bytes. `syntax.Marshal` returns
`errors.Join(v.MarshalMLS(w), w.Err())`, so both the semantic and the buffer error reach the caller.

**C3 — counts are `LeafCount`, indices are `LeafIndex`/`NodeIndex`, and tree-math arithmetic that
can be out of range returns an error.** p3's block is normative for every caller. `TreeSize` does
not exist, `Level` is a method on `NodeIndex` and not a free function, `NodeWidth` returns `uint32`,
and `Root` is two-valued. **This plan gets no shims**: it calls the two-valued form and handles the
error, because a shim that turns an error into `false` is exactly how ValSem300's trailing-blank
case gets silently accepted.

**C4 — the GroupContext crosses a plan boundary as bytes.** Every p6 entry point takes
`groupContext []byte`, obtained from `syntax.Marshal(gc)`. This plan is on the other side of that
line: its own entry points take `*GroupContext` and serialize internally with `syntax.Marshal`, and
`(*KeySchedule).GroupContextBytes()` is what hands the bytes onward.

---

## File Structure

| File | Single responsibility |
|---|---|
| `connect/mls/errors_key_schedule.go` | **Create.** Typed errors owned by this plan. A separate file from `errors.go` so the wave-1 validation plan and this plan never edit the same file during parallel waves. |
| `connect/mls/secret_zeroize.go` | **Create.** `zeroizeSecret`, the best-effort `//go:noinline` overwrite used by every file in this plan. |
| `connect/mls/group_context.go` | **Create.** The `GroupContext` struct and its byte-exact `MarshalMLS`/`UnmarshalMLS` pair, plus `Clone` and the `var _ syntax.Codec` pin. The single definition of the epoch binding every other file hashes or expands over. |
| `connect/mls/key_schedule.go` | **Create.** RFC 9420 §8 — joiner secret, welcome secret, epoch secret, the nine derived epoch secrets, exporter, external key pair, confirmation and membership tags, welcome key/nonce. |
| `connect/mls/psk.go` | **Create.** RFC 9420 §8.4 — `PreSharedKeyId`, `PSKLabel`, `PskSecret`, `EmptyPskSecret`, and the ValSem401/402/403 checks the computation itself enforces. |
| `connect/mls/transcript.go` | **Create.** RFC 9420 §8.2 — confirmed and interim transcript hash chaining, the group-creation base case, and the joiner's seed from a GroupInfo. |
| `connect/mls/secret_tree.go` | **Create.** RFC 9420 §9 — the secret tree, the per-leaf handshake and application ratchets, the generation window, the `MessageKeySource` implementation p6 declares, and the sender-data key/nonce derivation. |
| `connect/mls/key_schedule_deps_test.go` | **Create.** Compile-time pins on every wave-1 symbol this plan consumes. Fails to build the moment a signature drifts. |
| `connect/mls/group_context_test.go` | **Create.** GroupContext KAT, round-trip, trailing-byte rejection. |
| `connect/mls/key_schedule_test.go` | **Create.** Key-schedule KATs against the suite-3 epoch-0 vector, tag tests, unreachability test. |
| `connect/mls/psk_test.go` | **Create.** PSK label encoding, `PskSecret` KAT, ValSem401/402/403 negatives. |
| `connect/mls/transcript_test.go` | **Create.** Transcript arithmetic, base case, GroupInfo seed. |
| `connect/mls/secret_tree_test.go` | **Create.** Secret tree descent, deletion, ratchet stepping, window behaviour, forward secrecy. |
| `connect/mls/key_schedule_kat_test.go` | **Create.** `implementedSuite`, the `key-schedule` and `psk_secret` runners, their `RegisterVectorFamily` `init()`, and the key-schedule generator. |
| `connect/mls/transcript_kat_test.go` | **Create.** The `transcript-hashes` runner, its `RegisterVectorFamily` `init()`, and its self-validating AuthenticatedContent split. |
| `connect/mls/secret_tree_kat_test.go` | **Create.** The `secret-tree` runner and generator plus their `RegisterVectorFamily` `init()`. |
| `connect/mls/key_schedule_roundtrip_test.go` | **Create.** Deterministic byte-exact round-trip properties for `GroupContext` and `PreSharedKeyId`, and the seed corpus this plan contributes to p8's Gate 4 fuzz targets. |
| `connect/mls/key_schedule_guard_test.go` | **Create.** Source-scanning guardrail test for G1 (`hkdf.Extract`), G8 (`bytes.Equal` on tags) and the banned X25519 helpers. |
| `connect/mls/testdata/vectors/key-schedule.json` | **Consume.** Vendored by p8 Task 6, the single vendoring task for all sixteen families. This plan reads it and never writes it. |
| `connect/mls/testdata/vectors/psk_secret.json` | **Consume.** Vendored by p8 Task 6. |
| `connect/mls/testdata/vectors/transcript-hashes.json` | **Consume.** Vendored by p8 Task 6. |
| `connect/mls/testdata/vectors/secret-tree.json` | **Consume.** Vendored by p8 Task 6. |
| `connect/mls/testdata/corpus/FuzzGroupContextRoundTrip/` | **Create.** Seed corpus only; the `Fuzz*` target itself is p8's. |
| `connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip/` | **Create.** Seed corpus only; the `Fuzz*` target itself is p8's. |

### What this plan does NOT own

`crypto.go`, `suite.go`, `hpke.go`, `tree_math.go`, `syntax/`, `extension.go`, `credential.go`,
`leaf_node.go`, `key_package.go`, `tree.go`, `treekem.go`, `framing*.go`, `group.go`,
`validate_*.go`, `errors.go`, `profile.go`, `codec_table.go`, `interop/`. `commit_secret` comes
from TreeKEM (p5). `ConfirmedTranscriptHashInput` bytes and the membership TBM bytes come from
framing (p6). `GroupInfo` and `Welcome` construction come from group lifecycle (p7).

Four things this plan previously declared and no longer does, because the registry assigns them
elsewhere:

- **`ErrPskNonceLength`, `ErrPskType`, `ErrDuplicatePsk`** — they are ValSem401/402/403 and belong
  to p8's catalogue (registry §9.1). This plan **consumes** them from p8's `errors.go` and returns
  `ValSem(ValSem401, detail)` / `ValSem(ValSem402, detail)` / `ValSem(ValSem403, detail)` with the
  sentinel wrapped in `detail`, so `errors.Is` and `CodeOf` both hold.
- **`ksHex` and `ksLoadVectors`** — deleted in favour of p8's `MustHex`, `HexOf` and
  `LoadVectorFile` (registry §9.2). Three parallel hex decoders over one corpus is how two of them
  end up disagreeing about the empty string. `ksImplementedSuite` survives, renamed
  `implementedSuite`. This plan's own `mustHex` is deleted too — p7 declares the same name in the
  same package, so keeping it is a redeclaration compile error, not a style question.
- **The `Fuzz*` targets** — p8 owns all nine Gate-4 fuzz targets (registry §9.5). This plan
  contributes seed corpus and keeps the same round-trip assertions as ordinary deterministic tests.
- **Vendoring the four vector files** — p8 Task 6 is the single vendoring task for all sixteen
  mlswg families plus `VECTORS.sha256` and `interop/PINS.md` (registry §9.2). This plan keeps only
  its runners.

---

## Interface summary — what other plans consume from here

This is registry §5, transcribed. It is normative and every code body below calls exactly these
spellings.

```go
package mls

// group_context.go
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
func (self *GroupContext) Clone() *GroupContext
var _ syntax.Codec = (*GroupContext)(nil)

// key_schedule.go
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
type KeySchedule struct{ /* unexported */ }

const PastEpochWindow uint64 = 32

func ZeroSecret(crypto CryptoProvider) []byte
func DeriveJoinerSecret(crypto CryptoProvider, initSecretPrev []byte, commitSecret []byte, groupContext *GroupContext) ([]byte, error)
func NewKeySchedule(crypto CryptoProvider, initSecretPrev []byte, commitSecret []byte, pskSecret []byte, groupContext *GroupContext) (*KeySchedule, error)
func NewKeyScheduleFromJoiner(crypto CryptoProvider, joinerSecret []byte, pskSecret []byte, groupContext *GroupContext) (*KeySchedule, error)
func NewKeyScheduleFromEpochSecret(crypto CryptoProvider, epochSecret []byte, groupContext *GroupContext) (*KeySchedule, error)
func WelcomeKeyNonce(crypto CryptoProvider, welcomeSecret []byte) (key []byte, nonce []byte, err error)
func EmptyPskSecret(crypto CryptoProvider) []byte     // == PskSecret(crypto, nil)

func (self *KeySchedule) JoinerSecret() []byte
func (self *KeySchedule) WelcomeSecret() []byte
func (self *KeySchedule) Secrets() *EpochSecrets
func (self *KeySchedule) GroupContextBytes() []byte
func (self *KeySchedule) Export(label string, context []byte, length int) ([]byte, error)
func (self *KeySchedule) ExternalKeyPair() (HpkePrivateKey, HpkePublicKey, error)
func (self *KeySchedule) ConfirmationTag(confirmedTranscriptHash []byte) []byte
func (self *KeySchedule) VerifyConfirmationTag(confirmedTranscriptHash []byte, tag []byte) bool
func (self *KeySchedule) MembershipTag(authenticatedContentTbm []byte) []byte
func (self *KeySchedule) VerifyMembershipTag(authenticatedContentTbm []byte, tag []byte) bool
func (self *KeySchedule) Zeroize()

// psk.go
type PskType uint8
const (
    PskTypeExternal   PskType = 1
    PskTypeResumption PskType = 2
)
type ResumptionPskUsage uint8
const (
    ResumptionPskUsageApplication ResumptionPskUsage = 1
    ResumptionPskUsageReInit      ResumptionPskUsage = 2
    ResumptionPskUsageBranch      ResumptionPskUsage = 3
)
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
func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error
var _ syntax.Codec = (*PreSharedKeyId)(nil)

type PreSharedKeyInput struct {
    Id     PreSharedKeyId
    Secret []byte
}
func CheckNoDuplicatePsks(ids []PreSharedKeyId) error
func PskSecret(crypto CryptoProvider, psks []PreSharedKeyInput) ([]byte, error)

// transcript.go
type TranscriptHashes struct {
    Confirmed []byte
    Interim   []byte
}
func InitialTranscriptHashes() *TranscriptHashes
func (self *TranscriptHashes) Clone() *TranscriptHashes
func (self *TranscriptHashes) Update(crypto CryptoProvider, confirmedTranscriptHashInput []byte, confirmationTag []byte) error
func (self *TranscriptHashes) SetFromGroupInfo(crypto CryptoProvider, confirmedTranscriptHash []byte, confirmationTag []byte) error
func ConfirmedTranscriptHash(crypto CryptoProvider, interimBefore []byte, confirmedTranscriptHashInput []byte) []byte
func InterimTranscriptHash(crypto CryptoProvider, confirmedAfter []byte, confirmationTag []byte) ([]byte, error)

// secret_tree.go
type RatchetType uint8
const (
    RatchetHandshake RatchetType = iota + 1
    RatchetApplication
)
const (
    MaxGenerationSkip uint32 = 1024
    RatchetWindowSize int    = 1024
)
type SecretTree struct{ /* unexported, guarded by stateLock */ }
func NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error)
func (self *SecretTree) LeafCount() LeafCount
func (self *SecretTree) Zeroize()

// the internal form, addressed by secret-tree.json
func (self *SecretTree) NextSenderKey(leaf LeafIndex, kind RatchetType) (generation uint32, key []byte, nonce []byte, err error)
func (self *SecretTree) ReceiverKey(leaf LeafIndex, kind RatchetType, generation uint32) (key []byte, nonce []byte, err error)
func (self *SecretTree) SenderGeneration(leaf LeafIndex, kind RatchetType) (uint32, error)

// the MessageKeySource implementation p6 declares — p6's exact signatures
func (self *SecretTree) NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
func (self *SecretTree) MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
func (self *SecretTree) EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)

func SenderDataKeyNonce(crypto CryptoProvider, senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error)

// errors_key_schedule.go — exactly registry §5.6, ten values.
// ErrPskNonceLength, ErrPskType and ErrDuplicatePsk are NOT here: they are
// ValSem401/402/403 and are declared once, in p8's errors.go.
var (
    ErrSecretLength                 = errors.New("mls: secret has the wrong length")
    ErrExportLength                 = errors.New("mls: exporter length out of range")
    ErrGroupContextTrailingBytes    = errors.New("mls: group context has trailing bytes")
    ErrTranscriptHashLength         = errors.New("mls: transcript hash has the wrong length")
    ErrPskCount                     = errors.New("mls: too many psks for a uint16 count")
    ErrSecretTreeLeafOutOfRange     = errors.New("mls: leaf index outside the secret tree")
    ErrSecretTreeConsumed           = errors.New("mls: secret tree node already consumed")
    ErrRatchetGenerationConsumed    = errors.New("mls: ratchet generation already consumed")
    ErrRatchetGenerationTooFarAhead = errors.New("mls: ratchet generation too far ahead")
    ErrRatchetExhausted             = errors.New("mls: ratchet generation space exhausted")
)
```

Three registry gaps land here and each has a task below: `NewKeyScheduleFromEpochSecret` (Task 6a),
`EmptyPskSecret` (Task 15), and `NextMessageKey`/`MessageKey`/`EraseMessageKey` (Task 23a).

---

## Interface summary — what this plan consumes

Every signature below is copied from the canonical interface registry, which is normative. Task 1
pins them as compile-time assertions: if a producing plan names any of them differently, Task 1
fails to build, which is the intended detection mechanism.

**From "Syntax and codec" (wave 1), package `mls/syntax` — registry §2:**

```go
const MaxVectorLength int = 1 << 20

var ErrTrailingBytes error         // a top-level decode left bytes unconsumed
var ErrLengthExceedsMax error

func NewWriter() *Writer
func (self *Writer) Bytes() ([]byte, error)      // undefined when err non-nil
func (self *Writer) Err() error
func (self *Writer) WriteUint8(v uint8)
func (self *Writer) WriteUint16(v uint16)
func (self *Writer) WriteUint32(v uint32)
func (self *Writer) WriteUint64(v uint64)
func (self *Writer) WriteRaw(bs []byte)          // opaque x[N], no prefix
func (self *Writer) WriteOpaque(bs []byte)       // opaque x<V>; nil == empty

func NewReader(bs []byte) *Reader
func (self *Reader) Done() error                 // ErrTrailingBytes when bytes remain
func (self *Reader) ReadUint8() (uint8, error)
func (self *Reader) ReadUint16() (uint16, error)
func (self *Reader) ReadUint32() (uint32, error)
func (self *Reader) ReadUint64() (uint64, error)
func (self *Reader) ReadRaw(n int) ([]byte, error)   // opaque x[N]; a COPY
func (self *Reader) ReadOpaque() ([]byte, error)     // a COPY, never nil

type Marshaler interface{ MarshalMLS(w *Writer) error }
type Unmarshaler interface{ UnmarshalMLS(r *Reader) error }
type Codec interface { Marshaler; Unmarshaler }

func Marshal(v Marshaler) ([]byte, error)
func Unmarshal(bs []byte, v Unmarshaler) error       // enforces full consumption
```

Every leaf write returns nothing and is a no-op after the first error (**C2**), so this plan checks
once at `Bytes()`. `WriteBytes` — the name the first draft of this plan used — is `WriteRaw`. There
is no `syntax.WriteVarVec`, no append-style free function, and no `Bytes() []byte` without the
error.

**From "Crypto primitives and HPKE" (wave 1), package `mls` — registry §3:**

```go
type CipherSuite uint16
const (
    CipherSuiteX25519AesGcm128Sha256Ed25519 CipherSuite = 0x0001
    CipherSuiteX25519ChaCha20Sha256Ed25519  CipherSuite = 0x0003
)
type HpkePublicKey []byte
type HpkePrivateKey []byte

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
```

**`HpkePublicKey` has no `Bytes()` method.** It is a `[]byte`, so the vector's `external_pub` is
compared against the slice directly. The pin the first draft carried is deleted (registry §3.2).
The spellings `CipherSuiteX25519ChaCha20SHA256Ed25519` and `CipherSuiteX25519AES128SHA256Ed25519`
do not exist; `CODESTYLE.md` decides against the initialisms and the producer's spelling stands.

**From "Tree math" (wave 1), package `mls` — registry §4, normative in full:**

```go
type LeafIndex uint32
type NodeIndex uint32
type LeafCount uint32

func (self LeafIndex) NodeIndex() NodeIndex
func (self NodeIndex) Level() uint32
func NodeWidth(n LeafCount) uint32
func Root(n LeafCount) (NodeIndex, error)
func Left(x NodeIndex) (NodeIndex, error)
func Right(x NodeIndex) (NodeIndex, error)
```

`Level(x)` as a free function does not exist; `Root` in single-value position does not exist;
`NodeWidth` returns `uint32`, not `NodeIndex`. This plan takes **no shims** for the two-valued forms
(**C3**).

**From "Registry enums, extensions, tree, TreeKEM" (wave 2, p5), package `mls` — registry §6.1/§6.2:**

```go
type ProtocolVersion uint16
const ProtocolVersionMls10 ProtocolVersion = 0x0001

type ExtensionType uint16
type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}
func WriteExtensions(w *syntax.Writer, exts []Extension) error
func ReadExtensions(r *syntax.Reader) ([]Extension, error)
```

**Wave note.** p1 produces no `Extension` type at all, so this block moved out of the syntax section
where the first draft put it. p5 is wave 2 and so is this plan: **p5 Task 3 sequences before Task 3
here.** `MarshalExtensions`/`ParseExtensions` — the names the first draft consumed — are
`WriteExtensions`/`ReadExtensions` (registry override O-3), renamed to match p1's
`WriteVector`/`ReadVector` since that is what they are built on.

**From "Framing and message protection" (wave 3, p6), package `mls` — registry §7.1:**

```go
type ContentType uint8
const (
    ContentTypeApplication ContentType = 1
    ContentTypeProposal    ContentType = 2
    ContentTypeCommit      ContentType = 3
)
```

Consumed by Task 23a only, which implements the `MessageKeySource` interface p6 declares. That task
therefore sequences after p6 Task 1; every other task here is wave 2 and depends on nothing from p6.

**From "Validation and interop" (wave 1, p8), package `mls` — registry §9.1/§9.2:**

```go
type ValSemCode uint16
func ValSem(code ValSemCode, detail error) error
const ( ValSem401 ValSemCode = 401; ValSem402 ValSemCode = 402; ValSem403 ValSemCode = 403 )
var ErrPskNonceLength, ErrPskType, ErrDuplicatePsk error   // the ValSem401/402/403 sentinels

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

p8 is wave 1, so all of this is available before Task 2 runs. `LoadVectorFile` also means p8 Task 6
has already vendored the four families this plan gates; nothing here copies a vector file.

Errata 8745 (§13.4, LeafNode capability validation in Update proposals and update paths) and errata
8815 (§12.2, commit proposal references must have been previously received) are **both validation
errata and neither touches the key schedule**. They are `CheckErrata8745`/`CheckErrata8815` in p7
(registry §8.2), tested by p8; nothing in this plan implements or calls them.

---

## Reference values used as KATs

Transcribed from the pinned mlswg vectors, ciphersuite 0x0003, first vector, epoch 0. Every hex
string below appears literally in a test in this plan.

| Name | Value |
|---|---|
| `group_id` / `initial_init_secret` | `a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e` |
| `tree_hash` | `9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818` |
| `confirmed_transcript_hash` | `5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f` |
| `commit_secret` | `a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509` |
| `psk_secret` | `e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b` |
| `group_context` (112 B) | `0001000320a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00` |
| `joiner_secret` | `3e28da76edc09fb9ad59fae258839c7dc46e3c092a125499959c7413a60250b2` |
| `welcome_secret` | `b0defbdd2232224b0c0427e8efa80f011f7813291dca783433f2da1431620bbc` |
| `sender_data_secret` | `de1df3a74bbcfc7fcc631213a20c1b1842860eab8e6f0c864dcfb541cd42cf24` |
| `encryption_secret` | `ffcc3d4a757224eaf62c124f8e7def12c0db74740cf494c9f56fa7dd07214947` |
| `exporter_secret` | `27518b380b39834affecb08780ee9709627859d5f6f37994e8783791004485cb` |
| `external_secret` | `46f51f54ce4c3457ee5681925b9d1a282de166f04e28a4a316404bd14dda3138` |
| `external_pub` | `8206ea1eb4d8d5730a2737f7470718b9d00c2276d24a98ac4e6d7ef52cba0631` |
| `confirmation_key` | `e8bdff522e2675c7e0582321fbeb7e61763b1f88e7ded3c57ea78c691e1d0b93` |
| `membership_key` | `6839abba79aaeb82385397612fb90cbea3bf8d427806cb3f0bfe5793c1a42fc9` |
| `resumption_psk` | `244b05004ced1a7d1dc3da6a7541e9b180b6ffe41cc6e24d63c5c9c0742b4870` |
| `epoch_authenticator` | `f68f6735aeeb97331d674ef4f580e11352beff543b3b6688a01a1bab97d42f26` |
| `init_secret` (epoch 0 output) | `418b197eafd925ebbf4bfd94d650aa83b1a11d6d02f33c2cc81631c6734f69d9` |
| `exporter.label` | `9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4` (**a 64-character ASCII string, NOT hex**) |
| `exporter.context` | `884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785` (hex, 32 B) |
| `exporter.secret` (length 32) | `623c858acd2728c5b860a77ae0cde77fa8aef14e9ac124464cab06bbc3cf3635` |

Secret tree, ciphersuite 0x0003, the one-leaf vector:

| Name | Value |
|---|---|
| `encryption_secret` | `59227ed552e4a6db0779d43aea694fd1b2c2540e605a099b95cf852b41e8ea66` |
| `sender_data.sender_data_secret` | `d61204c27f29de53d30ff54a6ebb53e9908d044f55b9e726fa5736d4246b7b36` |
| `sender_data.ciphertext` | `d0f75d5b691dbff35cafe226adad83aa5076c85035fef7d7fac489ad63f10828266b44ea366961509e8c9c24474abb6066c5a350aeb2b05415facb7ac2aa1b1efcf75a0c700bfdc93c705e352c` |
| `sender_data.key` | `674a0c3e1500d068aae5d50f57a14648a63de2c246f8178382a150df8031f4cf` |
| `sender_data.nonce` | `56b73cca00eac6cc5080be8d` |
| leaf 0 gen 0 `application_key` | `3f57aae38cbe6eaf31e4c05bd4a6aeba50c6878fa6fc2443bb8f3e57870fe712` |
| leaf 0 gen 0 `application_nonce` | `4b2599c99b38c18775c85008` |
| leaf 0 gen 0 `handshake_key` | `2ef3c21ad150b59cc78b21bd96e5dc0bd2579e19c7a46b7581fb1969103389d2` |
| leaf 0 gen 0 `handshake_nonce` | `5794013a45e0563de4d35ce0` |
| leaf 0 gen 15 `application_key` | `bd44b39e16d4d59750469719cd330e4a52ecf5a1c9060254fac3e8ef73f4cf9b` |
| leaf 0 gen 15 `application_nonce` | `82f8881240b93d1611b34e8c` |
| leaf 0 gen 15 `handshake_key` | `488400e9d1a4a1d48e94da89dbc6c306d6479004e26aaade4101dd2fd86f2c21` |
| leaf 0 gen 15 `handshake_nonce` | `424c2809d87242ecbb1da91f` |

PSK secret, ciphersuite 0x0003, the two-PSK vector (external type, `psk_nonce` 32 B):

| Name | Value |
|---|---|
| psk[0].psk_id | `c4e57766aa00414135b98e60b8e897896565af0f3d746c32d04dd4cda21d2299` |
| psk[0].psk | `4031689beb1bc9408e50f3ddbc04f7390e38afcbe88d8090c1a5a3e7469a8fc0` |
| psk[0].psk_nonce | `daeccb5a5522ee2578427727a6091194ad0d5a83ea4e0a9318ac27758d03574f` |
| psk[1].psk_id | `2ed6e6c554f046664d1e370fccbd64f6a9ba0f4163fd2785a8eb1bcf865e8b8e` |
| psk[1].psk | `787e4bfaf0f4f73624ae0f9f012e7cb554f4dfff31c8c57df7b091d4cd8be903` |
| psk[1].psk_nonce | `d3ae0fea4056bf88ff37ebd6efed07cdb41f2f306de9d88ac5762c2a245a8545` |
| `psk_secret` | `4137e7535a749ef9c6055be84e2850168d64fddf843efc210e199701d088174b` |

---

## Tasks

### Task 1: Pin the consumed interfaces and confirm the four vector families are vendored

**Files:**
- Test: `connect/mls/key_schedule_deps_test.go`

**Interfaces:**
- Consumes: everything in the "what this plan consumes" section above, at the registry's exact
  signatures.
- Produces: nothing at runtime. Produces the build-time guarantee that the consumed signatures exist
  and that no shim is silently absorbing a two-valued tree-math result.

This block is rewritten from the registry before anything else in this plan runs; its entire purpose
is to catch drift, and pinning the wrong shape catches it by failing.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_deps_test.go
// compile-time pins on every cross-plan symbol the key schedule and secret tree
// consume, at the signatures in the canonical interface registry. A signature change
// in another plan breaks the build here rather than three tasks later.
package mls

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// pinned free functions from the crypto, tree-math, extension and validation plans.
var (
	_ func(CipherSuite) (CryptoProvider, error) = NewCryptoProvider

	// registry §4 — counts are LeafCount, NodeWidth is uint32-valued, Root is
	// two-valued, and Level is a method. No shims: this plan handles the error.
	_ func(LeafCount) uint32             = NodeWidth
	_ func(LeafCount) (NodeIndex, error) = Root
	_ func(NodeIndex) (NodeIndex, error) = Left
	_ func(NodeIndex) (NodeIndex, error) = Right
	_ func(LeafIndex) NodeIndex          = LeafIndex.NodeIndex
	_ func(NodeIndex) uint32             = NodeIndex.Level

	// registry §2 — the syntax entry points, not append-style free functions.
	_ func() *syntax.Writer                       = syntax.NewWriter
	_ func([]byte) *syntax.Reader                 = syntax.NewReader
	_ func(syntax.Marshaler) ([]byte, error)      = syntax.Marshal
	_ func([]byte, syntax.Unmarshaler) error      = syntax.Unmarshal

	// registry §6.2 — produced by p5 in wave 2, not by p1.
	_ func(*syntax.Writer, []Extension) error   = WriteExtensions
	_ func(*syntax.Reader) ([]Extension, error) = ReadExtensions

	// registry §9.1/§9.2 — p8, wave 1.
	_ func(ValSemCode, error) error                  = ValSem
	_ func(*testing.T, string) []byte                = MustHex
	_ func([]byte) string                            = HexOf
	_ func(*testing.T, string) []json.RawMessage     = LoadVectorFile
	_ func(VectorFamily)                             = RegisterVectorFamily
)

// the two types this plan produces are syntax.Codec implementations under C1.
// These two lines are the whole reason CheckRoundTrip has an instantiation path.
var (
	_ syntax.Codec = (*GroupContext)(nil)
	_ syntax.Codec = (*PreSharedKeyId)(nil)
)

// TestConsumedCryptoProviderShape pins the CryptoProvider method set this plan calls.
func TestConsumedCryptoProviderShape(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	var (
		_ func([]byte, []byte) []byte                         = crypto.Extract
		_ func([]byte, []byte, int) []byte                    = crypto.Expand
		_ func([]byte, string, []byte, int) []byte            = crypto.ExpandWithLabel
		_ func([]byte, string) []byte                         = crypto.DeriveSecret
		_ func([]byte, string, uint32, int) []byte            = crypto.DeriveTreeSecret
		_ func([]byte) []byte                                 = crypto.Hash
		_ func([]byte, []byte) []byte                         = crypto.Mac
		_ func([]byte, []byte, []byte) bool                   = crypto.MacVerify
		_ func() int                                          = crypto.HashSize
		_ func() int                                          = crypto.KeySize
		_ func() int                                          = crypto.NonceSize
		_ func(int) []byte                                    = crypto.Random
		_ func([]byte) (HpkePrivateKey, HpkePublicKey, error) = crypto.DeriveKeyPair
	)
	if crypto.HashSize() != 32 {
		t.Fatalf("HashSize = %d, want 32", crypto.HashSize())
	}
	if crypto.KeySize() != 32 {
		t.Fatalf("KeySize = %d, want 32", crypto.KeySize())
	}
	if crypto.NonceSize() != 12 {
		t.Fatalf("NonceSize = %d, want 12", crypto.NonceSize())
	}
}

// TestConsumedHpkePublicKeyIsASlice pins that HpkePublicKey carries no Bytes method
// and is compared against the vector's external_pub as a slice. The Bytes() pin the
// first draft of this plan carried does not exist and never did.
func TestConsumedHpkePublicKeyIsASlice(t *testing.T) {
	var pub HpkePublicKey = []byte{0x01, 0x02}
	if len(pub) != 2 {
		t.Fatalf("len(HpkePublicKey) = %d, want 2", len(pub))
	}
	if !bytes.Equal(pub, []byte{0x01, 0x02}) {
		t.Fatal("HpkePublicKey does not compare as a byte slice")
	}
}

// TestConsumedSyntaxWriterShape pins the syntax reader and writer surface. Every leaf
// write returns nothing (C2): the sticky error is collected once, at Bytes().
func TestConsumedSyntaxWriterShape(t *testing.T) {
	w := syntax.NewWriter()
	var (
		_ func(uint8)            = w.WriteUint8
		_ func(uint16)           = w.WriteUint16
		_ func(uint32)           = w.WriteUint32
		_ func(uint64)           = w.WriteUint64
		_ func([]byte)           = w.WriteOpaque
		_ func([]byte)           = w.WriteRaw
		_ func() ([]byte, error) = w.Bytes
		_ func() error           = w.Err
	)
	w.WriteUint16(0x0001)
	w.WriteOpaque([]byte{0x02, 0x03})
	b, err := w.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if len(b) != 5 {
		t.Fatalf("encoded %d bytes, want 5", len(b))
	}
	r := syntax.NewReader(b)
	var (
		_ func() (uint8, error)     = r.ReadUint8
		_ func() (uint16, error)    = r.ReadUint16
		_ func() (uint32, error)    = r.ReadUint32
		_ func() (uint64, error)    = r.ReadUint64
		_ func() ([]byte, error)    = r.ReadOpaque
		_ func(int) ([]byte, error) = r.ReadRaw
		_ func() error              = r.Done
	)
	if _, err := r.ReadUint16(); err != nil {
		t.Fatalf("ReadUint16: %v", err)
	}
	if _, err := r.ReadOpaque(); err != nil {
		t.Fatalf("ReadOpaque: %v", err)
	}
	if err := r.Done(); err != nil {
		t.Fatalf("Done: %v", err)
	}
}

// TestVectorFilesPresent asserts the four vector families this plan gates were
// vendored by p8 Task 6, which is the single vendoring task for all sixteen families.
// This plan reads them and never writes them.
func TestVectorFilesPresent(t *testing.T) {
	for _, name := range []string{
		"key-schedule.json",
		"psk_secret.json",
		"transcript-hashes.json",
		"secret-tree.json",
	} {
		info, err := os.Stat(filepath.Join("testdata", "vectors", name))
		if err != nil {
			t.Fatalf("vector %s: %v — p8 Task 6 vendors these; it has not landed", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("vector %s is empty", name)
		}
	}
}
```

Add `"bytes"` and `"encoding/json"` to the import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestConsumed|TestVectorFilesPresent' -v`
Expected: FAIL to compile with `undefined: GroupContext` and `undefined: PreSharedKeyId` — this file
pins the two codecs this plan has not written yet. If instead it names a *consumed* symbol
(`WriteExtensions`, `Root`, `MustHex`, …), the producing plan is not merged and this task blocks on
it; if it names one at the *wrong signature*, the registry decides and the producer is amended, not
this file.

- [ ] **Step 3: Confirm the vectors are in place**

```bash
ls -l connect/mls/testdata/vectors/{key-schedule,psk_secret,transcript-hashes,secret-tree}.json
grep -E '^(mlswg|openmls)=' connect/mls/interop/PINS.md
```

All four files are vendored by p8 Task 6 and pinned in `connect/mls/interop/PINS.md`. If they are
missing, the fix is to land p8 Task 6 — do not copy them in from a local mlswg checkout here, or the
corpus has two provenances and `VECTORS.sha256` stops meaning anything.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestConsumed|TestVectorFilesPresent' -v`
Expected: PASS once Tasks 3 and 13 have landed the two codecs. Until then, comment nothing out —
land this file together with Task 3 if the two-codec pin is inconvenient to carry red.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_deps_test.go
git ls-files | wc -l
git commit -m "test(mls): pin the consumed cross-plan interfaces at their registry signatures"
```

---

### Task 2: Typed errors and the zeroize helper

**Files:**
- Create: `connect/mls/errors_key_schedule.go`, `connect/mls/secret_zeroize.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `syntax.ErrTrailingBytes` (registry §2.1). Nothing else.
- Produces: `zeroizeSecret(b []byte)` (unexported), and the **ten** error values of registry §5.6.
  `ErrPskNonceLength`, `ErrPskType` and `ErrDuplicatePsk` are **not** produced here — they are
  ValSem401/402/403 and are declared once, in p8's `errors.go`.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_test.go
// tests for the RFC 9420 section 8 key schedule.
package mls

import (
	"errors"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// TestZeroizeSecretOverwrites asserts the helper clears the caller's backing array.
func TestZeroizeSecretOverwrites(t *testing.T) {
	secret := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	alias := secret[:]
	zeroizeSecret(secret)
	for i, b := range alias {
		if b != 0 {
			t.Fatalf("byte %d = %d, want 0", i, b)
		}
	}
}

// TestZeroizeSecretAcceptsNil asserts a nil secret is not a panic.
func TestZeroizeSecretAcceptsNil(t *testing.T) {
	zeroizeSecret(nil)
}

// TestKeyScheduleErrorsAreDistinct asserts no two typed errors alias each other,
// so a test asserting a specific failure cannot pass on the wrong one.
func TestKeyScheduleErrorsAreDistinct(t *testing.T) {
	all := []error{
		ErrSecretLength,
		ErrExportLength,
		ErrGroupContextTrailingBytes,
		ErrTranscriptHashLength,
		ErrPskCount,
		ErrSecretTreeLeafOutOfRange,
		ErrSecretTreeConsumed,
		ErrRatchetGenerationConsumed,
		ErrRatchetGenerationTooFarAhead,
		ErrRatchetExhausted,
	}
	if len(all) != 10 {
		t.Fatalf("this plan owns %d errors, want the 10 of registry section 5.6", len(all))
	}
	for i := range all {
		for j := range all {
			if i == j {
				continue
			}
			if errors.Is(all[i], all[j]) {
				t.Fatalf("error %d aliases error %d: %v", i, j, all[i])
			}
		}
	}
}

// TestGroupContextTrailingBytesWrapsTheSyntaxError asserts the group-context trailing
// byte condition is reachable through the syntax package's own sentinel, so a caller
// that only knows syntax.ErrTrailingBytes still matches it. The two names exist
// because syntax.Unmarshal is what enforces full consumption while this value is what
// names the condition for the group context specifically.
func TestGroupContextTrailingBytesWrapsTheSyntaxError(t *testing.T) {
	if !errors.Is(ErrGroupContextTrailingBytes, syntax.ErrTrailingBytes) {
		t.Fatal("ErrGroupContextTrailingBytes does not wrap syntax.ErrTrailingBytes")
	}
}

// TestPskSentinelsBelongToTheValidationPlan asserts the three ValSem401/402/403
// sentinels resolve to p8's declarations and are not redeclared here. Two declarations
// of one name in package mls is a compile error; two declarations that compiled would
// mean an errors.Is check in the commit path silently stopped matching.
func TestPskSentinelsBelongToTheValidationPlan(t *testing.T) {
	for i, sentinel := range []error{ErrPskNonceLength, ErrPskType, ErrDuplicatePsk} {
		if sentinel == nil {
			t.Fatalf("sentinel %d is nil; p8 errors.go declares these", i)
		}
	}
	err := ValSem(ValSem401, ErrPskNonceLength)
	if !errors.Is(err, ErrPskNonceLength) {
		t.Fatal("ValSem does not preserve its detail under errors.Is")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestZeroizeSecret|TestKeyScheduleErrors|TestGroupContextTrailingBytes|TestPskSentinels' -v`
Expected: FAIL to compile with `undefined: zeroizeSecret` and `undefined: ErrSecretLength`.

- [ ] **Step 3: Write minimal implementation**

```go
// secret_zeroize.go
// best-effort erasure of key material.
package mls

import "runtime"

// zeroizeSecret overwrites a secret in place. Go gives no guarantee this survives
// the optimizer or that no copy was made by the garbage collector, so this is
// documented as best effort: it removes the obvious copy, not every copy.
//
//go:noinline
func zeroizeSecret(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
	runtime.KeepAlive(secret)
}
```

```go
// errors_key_schedule.go
// typed errors raised by the key schedule, the psk secret, the transcript hashes
// and the secret tree. kept out of errors.go so the validation plan and this plan
// do not edit one file during parallel waves.
//
// The three PSK errors this plan once declared are absent on purpose: ValSem401,
// ValSem402 and ValSem403 live in p8's errors.go, which is the single declaration
// site for every ValSem sentinel. This file must never grow one of them back —
// package mls is one package and the second declaration is a compile error.
package mls

import (
	"errors"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

var (
	// ErrSecretLength is returned when a secret supplied to the key schedule is
	// not KDF.Nh bytes. A short secret would otherwise expand into a valid-looking
	// epoch that no peer agrees with.
	ErrSecretLength = errors.New("mls: secret has the wrong length")

	// ErrExportLength is returned when an exporter length exceeds 255*KDF.Nh,
	// which HKDF-Expand cannot produce.
	ErrExportLength = errors.New("mls: exporter length out of range")

	// ErrGroupContextTrailingBytes names the condition where a serialized
	// GroupContext has bytes after the extensions vector. syntax.Unmarshal is what
	// enforces full consumption, so this wraps its sentinel: a caller matching
	// either name matches the same failure. MLS signs over serialized forms, so a
	// decoder that tolerated trailing bytes would accept two encodings of one object.
	ErrGroupContextTrailingBytes = fmt.Errorf(
		"mls: group context has trailing bytes: %w", syntax.ErrTrailingBytes)

	// ErrTranscriptHashLength is returned when a transcript hash is not KDF.Nh bytes.
	ErrTranscriptHashLength = errors.New("mls: transcript hash has the wrong length")

	// ErrPskCount is returned when a psk list cannot be indexed by the uint16
	// index and count fields of PSKLabel.
	ErrPskCount = errors.New("mls: too many psks for a uint16 count")

	// ErrSecretTreeLeafOutOfRange is returned for a leaf index outside the tree.
	ErrSecretTreeLeafOutOfRange = errors.New("mls: leaf index outside the secret tree")

	// ErrSecretTreeConsumed is returned when the node secrets covering a leaf have
	// already been deleted, which is the forward-secrecy property working.
	ErrSecretTreeConsumed = errors.New("mls: secret tree node already consumed")

	// ErrRatchetGenerationConsumed is returned for a generation already used and erased.
	ErrRatchetGenerationConsumed = errors.New("mls: ratchet generation already consumed")

	// ErrRatchetGenerationTooFarAhead is returned when a generation is more than
	// MaxGenerationSkip beyond the ratchet head. Without this bound a forged
	// generation number is an unbounded KDF loop.
	ErrRatchetGenerationTooFarAhead = errors.New("mls: ratchet generation too far ahead")

	// ErrRatchetExhausted is returned when a ratchet has produced generation 2^32-1.
	ErrRatchetExhausted = errors.New("mls: ratchet generation space exhausted")
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestZeroizeSecret|TestKeyScheduleErrors|TestGroupContextTrailingBytes|TestPskSentinels' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/errors_key_schedule.go connect/mls/secret_zeroize.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): typed key schedule errors and best-effort secret zeroization"
```

---

### Task 3: GroupContext and its byte-exact MarshalMLS

**Files:**
- Create: `connect/mls/group_context.go`
- Test: `connect/mls/group_context_test.go`

**Interfaces:**
- Consumes: `syntax.NewWriter`, `(*syntax.Writer).WriteUint16(v uint16)`,
  `(*syntax.Writer).WriteUint64(v uint64)`, `(*syntax.Writer).WriteOpaque(bs []byte)`,
  `syntax.Marshal(v syntax.Marshaler) ([]byte, error)`,
  `WriteExtensions(w *syntax.Writer, exts []Extension) error`, `ProtocolVersion`,
  `ProtocolVersionMls10`, `CipherSuite`, `Extension`. **`WriteExtensions` is p5's and p5 is wave 2:
  p5 Task 3 sequences before this task.**
- Produces:
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
  func (self *GroupContext) Clone() *GroupContext
  var _ syntax.Codec = (*GroupContext)(nil)
  ```

  Under **C1** there is no `(*GroupContext).Marshal() ([]byte, error)` and no
  `ParseGroupContext(data)`; byte-level access is `syntax.Marshal(gc)` / `syntax.Unmarshal(bs, gc)`.
  That is what lets `GroupContext` satisfy `syntax.Codec` and therefore be a `CheckRoundTrip`
  target. `UnmarshalMLS` lands in Task 4, and the `var _ syntax.Codec` line only compiles once both
  halves exist — write it in Task 4 or carry Task 3 and Task 4 in one commit.

- [ ] **Step 1: Write the failing test**

```go
// group_context_test.go
// tests for the RFC 9420 section 8.1 GroupContext.
package mls

import (
	"bytes"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ksVectorGroupContext is the 112-byte epoch-0 GroupContext of the ciphersuite
// 0x0003 key-schedule vector, transcribed from the pinned mlswg file.
const ksVectorGroupContext = "0001000320a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39" +
	"cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818" +
	"205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00"

const (
	ksVectorGroupId  = "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"
	ksVectorTreeHash = "9769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818"
	ksVectorCth      = "5e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f"
)

// ksVectorEpoch0GroupContext builds the struct the vector describes.
func ksVectorEpoch0GroupContext(t *testing.T) *GroupContext {
	t.Helper()
	return &GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
		GroupId:                 MustHex(t, ksVectorGroupId),
		Epoch:                   0,
		TreeHash:                MustHex(t, ksVectorTreeHash),
		ConfirmedTranscriptHash: MustHex(t, ksVectorCth),
		Extensions:              nil,
	}
}

// TestGroupContextMarshalKAT pins the field order and the varint prefixes against
// the vector's own group_context bytes. A reordered field or a missing length
// prefix changes every epoch secret, so this is the cheapest place to catch it.
func TestGroupContextMarshalKAT(t *testing.T) {
	encoded, err := syntax.Marshal(ksVectorEpoch0GroupContext(t))
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	want := MustHex(t, ksVectorGroupContext)
	if len(encoded) != 112 {
		t.Fatalf("encoded %d bytes, want 112", len(encoded))
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("syntax.Marshal =\n %x\nwant\n %x", encoded, want)
	}
}

// TestGroupContextMarshalEmptyExtensions asserts an empty extension vector encodes
// as the single byte 0x00 and not as an omitted field.
func TestGroupContextMarshalEmptyExtensions(t *testing.T) {
	encoded, err := syntax.Marshal(ksVectorEpoch0GroupContext(t))
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	if encoded[len(encoded)-1] != 0x00 {
		t.Fatalf("last byte = %#x, want 0x00", encoded[len(encoded)-1])
	}
}

// TestGroupContextWriteIntoASharedWriter asserts MarshalMLS appends into a writer the
// caller already owns and adds no framing of its own. GroupInfo and every p6 preimage
// inline the group context this way, so a stray length prefix here would be invisible
// to a byte-level test and fatal to every signature.
func TestGroupContextWriteIntoASharedWriter(t *testing.T) {
	w := syntax.NewWriter()
	w.WriteUint8(0xff)
	if err := ksVectorEpoch0GroupContext(t).MarshalMLS(w); err != nil {
		t.Fatalf("MarshalMLS: %v", err)
	}
	encoded, err := w.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if encoded[0] != 0xff {
		t.Fatalf("the caller's leading byte was overwritten: %#x", encoded[0])
	}
	if !bytes.Equal(encoded[1:], MustHex(t, ksVectorGroupContext)) {
		t.Fatalf("inline encoding =\n %x\nwant\n %x", encoded[1:], MustHex(t, ksVectorGroupContext))
	}
}

// TestGroupContextCloneIsDeep asserts a cloned context does not alias the original,
// so an epoch held for out-of-order receipt cannot be mutated by the live epoch.
func TestGroupContextCloneIsDeep(t *testing.T) {
	original := ksVectorEpoch0GroupContext(t)
	clone := original.Clone()
	clone.GroupId[0] ^= 0xff
	clone.TreeHash[0] ^= 0xff
	clone.ConfirmedTranscriptHash[0] ^= 0xff
	if bytes.Equal(clone.GroupId, original.GroupId) {
		t.Fatal("GroupId is shared")
	}
	if bytes.Equal(clone.TreeHash, original.TreeHash) {
		t.Fatal("TreeHash is shared")
	}
	if bytes.Equal(clone.ConfirmedTranscriptHash, original.ConfirmedTranscriptHash) {
		t.Fatal("ConfirmedTranscriptHash is shared")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestGroupContext -v`
Expected: FAIL to compile with `undefined: GroupContext`.

- [ ] **Step 3: Write minimal implementation**

```go
// group_context.go
// the RFC 9420 section 8.1 GroupContext: the epoch binding that the key schedule
// expands over and that framing signs under.
package mls

import (
	"github.com/urnetwork/connect/mls/syntax"
)

// GroupContext binds a set of epoch secrets to one group, epoch, tree and transcript.
// Every field is covered by the joiner and epoch derivations, so two members that
// disagree on any one of them derive different secrets and stop being able to talk,
// which is the intended failure mode.
type GroupContext struct {
	Version                 ProtocolVersion
	CipherSuite             CipherSuite
	GroupId                 []byte
	Epoch                   uint64
	TreeHash                []byte
	ConfirmedTranscriptHash []byte
	Extensions              []Extension
}

// MarshalMLS encodes the context in the RFC 9420 section 8.1 field order, inline,
// into a writer the caller owns. The leaf writes return nothing and are no-ops after
// the first error (C2); the buffer error is collected by syntax.Marshal at Bytes().
// The error return exists for semantic refusals, and WriteExtensions is the only call
// here that can raise one.
func (self *GroupContext) MarshalMLS(w *syntax.Writer) error {
	w.WriteUint16(uint16(self.Version))
	w.WriteUint16(uint16(self.CipherSuite))
	w.WriteOpaque(self.GroupId)
	w.WriteUint64(self.Epoch)
	w.WriteOpaque(self.TreeHash)
	w.WriteOpaque(self.ConfirmedTranscriptHash)
	return WriteExtensions(w, self.Extensions)
}

// Clone returns a deep copy, so a retained past epoch cannot alias the live one.
func (self *GroupContext) Clone() *GroupContext {
	clone := &GroupContext{
		Version:                 self.Version,
		CipherSuite:             self.CipherSuite,
		GroupId:                 append([]byte(nil), self.GroupId...),
		Epoch:                   self.Epoch,
		TreeHash:                append([]byte(nil), self.TreeHash...),
		ConfirmedTranscriptHash: append([]byte(nil), self.ConfirmedTranscriptHash...),
	}
	if self.Extensions != nil {
		clone.Extensions = make([]Extension, 0, len(self.Extensions))
		for _, extension := range self.Extensions {
			clone.Extensions = append(clone.Extensions, Extension{
				ExtensionType: extension.ExtensionType,
				ExtensionData: append([]byte(nil), extension.ExtensionData...),
			})
		}
	}
	return clone
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestGroupContext -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/group_context.go connect/mls/group_context_test.go
git ls-files | wc -l
git commit -m "feat(mls): GroupContext MarshalMLS pinned byte-exact to the vector"
```

---

### Task 4: GroupContext.UnmarshalMLS, round-trip and trailing-byte rejection

**Files:**
- Modify: `connect/mls/group_context.go`
- Test: `connect/mls/group_context_test.go`

**Interfaces:**
- Consumes: `syntax.NewReader`, `(*syntax.Reader).ReadUint16() (uint16, error)`,
  `(*syntax.Reader).ReadUint64() (uint64, error)`, `(*syntax.Reader).ReadOpaque() ([]byte, error)`,
  `syntax.Unmarshal(bs []byte, v syntax.Unmarshaler) error`,
  `ReadExtensions(r *syntax.Reader) ([]Extension, error)`, `syntax.ErrTrailingBytes`.
- Produces:
  ```go
  func (self *GroupContext) UnmarshalMLS(r *syntax.Reader) error
  var _ syntax.Codec = (*GroupContext)(nil)
  ```

  `UnmarshalMLS` consumes exactly its own fields and no more, because p6 and p7 decode a
  GroupContext inline out of a `GroupInfo`. Full consumption of a standalone encoding is
  `syntax.Unmarshal`'s job and it returns `syntax.ErrTrailingBytes`, which
  `ErrGroupContextTrailingBytes` wraps.

- [ ] **Step 1: Write the failing test**

```go
// append to group_context_test.go

// TestGroupContextRoundTrip asserts decode(encode(x)) == x and that the re-encoding
// is byte-identical. MLS signs over serialized forms, so a decoder that accepts two
// encodings of one object is a signature-bypass primitive.
func TestGroupContextRoundTrip(t *testing.T) {
	want := MustHex(t, ksVectorGroupContext)
	parsed := &GroupContext{}
	if err := syntax.Unmarshal(want, parsed); err != nil {
		t.Fatalf("syntax.Unmarshal: %v", err)
	}
	if parsed.Version != ProtocolVersionMls10 {
		t.Fatalf("Version = %#x, want %#x", parsed.Version, ProtocolVersionMls10)
	}
	if parsed.CipherSuite != CipherSuiteX25519ChaCha20Sha256Ed25519 {
		t.Fatalf("CipherSuite = %#x, want 0x0003", parsed.CipherSuite)
	}
	if parsed.Epoch != 0 {
		t.Fatalf("Epoch = %d, want 0", parsed.Epoch)
	}
	if len(parsed.Extensions) != 0 {
		t.Fatalf("Extensions = %d, want 0", len(parsed.Extensions))
	}
	reencoded, err := syntax.Marshal(parsed)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	if !bytes.Equal(reencoded, want) {
		t.Fatalf("round trip =\n %x\nwant\n %x", reencoded, want)
	}
}

// TestGroupContextRejectsTrailingBytes asserts a full-consumption failure. The error
// matches both syntax.ErrTrailingBytes and this plan's ErrGroupContextTrailingBytes,
// which wraps it, so neither caller has to know which layer refused.
func TestGroupContextRejectsTrailingBytes(t *testing.T) {
	data := append(MustHex(t, ksVectorGroupContext), 0x00)
	err := syntax.Unmarshal(data, &GroupContext{})
	if !errors.Is(err, syntax.ErrTrailingBytes) {
		t.Fatalf("err = %v, want syntax.ErrTrailingBytes", err)
	}
	if !errors.Is(ErrGroupContextTrailingBytes, syntax.ErrTrailingBytes) {
		t.Fatal("ErrGroupContextTrailingBytes no longer names the same condition")
	}
}

// TestGroupContextRejectsTruncation asserts every prefix of a valid context is
// refused rather than yielding a partly-populated struct.
func TestGroupContextRejectsTruncation(t *testing.T) {
	full := MustHex(t, ksVectorGroupContext)
	for n := 0; n < len(full); n++ {
		if err := syntax.Unmarshal(full[:n], &GroupContext{}); err == nil {
			t.Fatalf("prefix of %d bytes parsed, want an error", n)
		}
	}
}

// TestGroupContextUnmarshalLeavesTheTailAlone asserts UnmarshalMLS consumes exactly
// its own fields, which is what lets p6 and p7 decode a group context inline out of a
// GroupInfo. A decoder that ate the tail would take the confirmation tag with it.
func TestGroupContextUnmarshalLeavesTheTailAlone(t *testing.T) {
	data := append(MustHex(t, ksVectorGroupContext), 0xde, 0xad)
	r := syntax.NewReader(data)
	parsed := &GroupContext{}
	if err := parsed.UnmarshalMLS(r); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	tail, err := r.ReadRaw(2)
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if !bytes.Equal(tail, []byte{0xde, 0xad}) {
		t.Fatalf("tail = %x, want dead", tail)
	}
	if err := r.Done(); err != nil {
		t.Fatalf("Done: %v", err)
	}
}
```

Add `"errors"` to the `group_context_test.go` import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestGroupContext -v`
Expected: FAIL to compile with `*GroupContext does not implement syntax.Unmarshaler`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to group_context.go

import "fmt"   // add to the existing import block

// UnmarshalMLS decodes the context from a reader, consuming exactly its own fields
// and no more: GroupInfo carries a GroupContext inline, so eating the tail here would
// eat the confirmation tag. Full consumption of a standalone encoding is enforced by
// syntax.Unmarshal, whose ErrTrailingBytes is what ErrGroupContextTrailingBytes wraps.
func (self *GroupContext) UnmarshalMLS(r *syntax.Reader) error {
	version, err := r.ReadUint16()
	if err != nil {
		return fmt.Errorf("mls: group context version: %w", err)
	}
	suite, err := r.ReadUint16()
	if err != nil {
		return fmt.Errorf("mls: group context cipher suite: %w", err)
	}
	groupId, err := r.ReadOpaque()
	if err != nil {
		return fmt.Errorf("mls: group context group id: %w", err)
	}
	epoch, err := r.ReadUint64()
	if err != nil {
		return fmt.Errorf("mls: group context epoch: %w", err)
	}
	treeHash, err := r.ReadOpaque()
	if err != nil {
		return fmt.Errorf("mls: group context tree hash: %w", err)
	}
	confirmedTranscriptHash, err := r.ReadOpaque()
	if err != nil {
		return fmt.Errorf("mls: group context confirmed transcript hash: %w", err)
	}
	extensions, err := ReadExtensions(r)
	if err != nil {
		return fmt.Errorf("mls: group context extensions: %w", err)
	}
	self.Version = ProtocolVersion(version)
	self.CipherSuite = CipherSuite(suite)
	self.GroupId = groupId
	self.Epoch = epoch
	self.TreeHash = treeHash
	self.ConfirmedTranscriptHash = confirmedTranscriptHash
	self.Extensions = extensions
	return nil
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*GroupContext)(nil)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestGroupContext -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/group_context.go connect/mls/group_context_test.go
git ls-files | wc -l
git commit -m "feat(mls): GroupContext UnmarshalMLS with full consumption and round-trip stability"
```

---

### Task 5: ZeroSecret and DeriveJoinerSecret

**Files:**
- Create: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Extract(salt []byte, ikm []byte) []byte`,
  `CryptoProvider.ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte`,
  `CryptoProvider.HashSize() int`, `syntax.Marshal(v syntax.Marshaler) ([]byte, error)`.
- Produces:
  ```go
  func ZeroSecret(crypto CryptoProvider) []byte
  func DeriveJoinerSecret(crypto CryptoProvider, initSecretPrev []byte, commitSecret []byte, groupContext *GroupContext) ([]byte, error)
  ```

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

const (
	ksVectorInitialInitSecret = "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"
	ksVectorCommitSecret      = "a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509"
	ksVectorJoinerSecret      = "3e28da76edc09fb9ad59fae258839c7dc46e3c092a125499959c7413a60250b2"
)

// ksTestCrypto returns the ciphersuite 0x0003 provider the KATs are pinned against.
func ksTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

// TestZeroSecretIsNhZeroBytes asserts the empty commit secret and the empty psk
// secret are both KDF.Nh zero bytes and not a nil slice.
func TestZeroSecretIsNhZeroBytes(t *testing.T) {
	crypto := ksTestCrypto(t)
	zero := ZeroSecret(crypto)
	if len(zero) != crypto.HashSize() {
		t.Fatalf("len = %d, want %d", len(zero), crypto.HashSize())
	}
	for i, b := range zero {
		if b != 0 {
			t.Fatalf("byte %d = %d, want 0", i, b)
		}
	}
	zero[0] = 1
	if ZeroSecret(crypto)[0] != 0 {
		t.Fatal("ZeroSecret returns a shared slice")
	}
}

// TestDeriveJoinerSecretKAT pins joiner_secret against the vector. This is also the
// argument-order test for Extract: init_secret is the salt and commit_secret is the
// ikm, and swapping them produces a different 32-byte value that nothing else catches.
func TestDeriveJoinerSecretKAT(t *testing.T) {
	crypto := ksTestCrypto(t)
	joiner, err := DeriveJoinerSecret(
		crypto,
		MustHex(t, ksVectorInitialInitSecret),
		MustHex(t, ksVectorCommitSecret),
		ksVectorEpoch0GroupContext(t),
	)
	if err != nil {
		t.Fatalf("DeriveJoinerSecret: %v", err)
	}
	want := MustHex(t, ksVectorJoinerSecret)
	if !bytes.Equal(joiner, want) {
		t.Fatalf("joiner_secret = %x, want %x", joiner, want)
	}
}

// TestDeriveJoinerSecretExtractOrderIsNotSymmetric asserts the swapped call does not
// coincidentally produce the same value, so the KAT above is a real order test.
func TestDeriveJoinerSecretExtractOrderIsNotSymmetric(t *testing.T) {
	crypto := ksTestCrypto(t)
	initSecret := MustHex(t, ksVectorInitialInitSecret)
	commitSecret := MustHex(t, ksVectorCommitSecret)
	forward := crypto.Extract(initSecret, commitSecret)
	swapped := crypto.Extract(commitSecret, initSecret)
	if bytes.Equal(forward, swapped) {
		t.Fatal("Extract is symmetric in its arguments, which cannot be right")
	}
}

// TestDeriveJoinerSecretRejectsShortSecrets asserts a wrong-length input is a hard
// error rather than a silently valid epoch.
func TestDeriveJoinerSecretRejectsShortSecrets(t *testing.T) {
	crypto := ksTestCrypto(t)
	groupContext := ksVectorEpoch0GroupContext(t)
	good := MustHex(t, ksVectorInitialInitSecret)
	if _, err := DeriveJoinerSecret(crypto, good[:31], good, groupContext); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short init secret err = %v, want ErrSecretLength", err)
	}
	if _, err := DeriveJoinerSecret(crypto, good, good[:31], groupContext); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short commit secret err = %v, want ErrSecretLength", err)
	}
}
```

Add `"bytes"` to the `key_schedule_test.go` import block. `"github.com/urnetwork/connect/mls/syntax"`
is already there from Task 2.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestZeroSecret|TestDeriveJoinerSecret' -v`
Expected: FAIL to compile with `undefined: ZeroSecret` and `undefined: DeriveJoinerSecret`.

- [ ] **Step 3: Write minimal implementation**

```go
// key_schedule.go
// the RFC 9420 section 8 epoch key schedule.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// PastEpochWindow bounds how many past epochs of state, and therefore how many
// past resumption_psk values and eph_root values, a client retains. RFC 9420
// ValSem400 makes bounding this a SHOULD and OpenMLS does not implement it at all
// (openmls#1122); here it is a hard bound. Thirty-two rather than eight because the
// window is a product promise about how long a laptop may stay closed, and an active
// group can burn eight epochs in a day.
const PastEpochWindow uint64 = 32

// ZeroSecret returns the KDF.Nh all-zero secret RFC 9420 writes as 0. It is the
// commit_secret of a commit with no UpdatePath and the psk_secret of an epoch with
// no PSKs. Returning a fresh slice each call keeps a caller that zeroizes its inputs
// from clearing a shared constant.
func ZeroSecret(crypto CryptoProvider) []byte {
	return make([]byte, crypto.HashSize())
}

// DeriveJoinerSecret computes joiner_secret for the epoch being entered:
//
//	joiner_secret = ExpandWithLabel(
//	    KDF.Extract(init_secret_[n-1], commit_secret),
//	    "joiner", GroupContext_[n], KDF.Nh)
//
// The GroupContext is the one for the epoch being entered, not the one being left.
func DeriveJoinerSecret(
	crypto CryptoProvider,
	initSecretPrev []byte,
	commitSecret []byte,
	groupContext *GroupContext,
) ([]byte, error) {
	nh := crypto.HashSize()
	if len(initSecretPrev) != nh {
		return nil, fmt.Errorf("%w: init secret is %d bytes, want %d", ErrSecretLength, len(initSecretPrev), nh)
	}
	if len(commitSecret) != nh {
		return nil, fmt.Errorf("%w: commit secret is %d bytes, want %d", ErrSecretLength, len(commitSecret), nh)
	}
	encodedGroupContext, err := syntax.Marshal(groupContext)
	if err != nil {
		return nil, err
	}
	// Extract takes (salt, ikm). init_secret is the salt.
	prk := crypto.Extract(initSecretPrev, commitSecret)
	joinerSecret := crypto.ExpandWithLabel(prk, "joiner", encodedGroupContext, nh)
	zeroizeSecret(prk)
	return joinerSecret, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestZeroSecret|TestDeriveJoinerSecret' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): joiner secret derivation with the Extract argument order pinned"
```

---

### Task 6: KeySchedule, welcome secret and the nine epoch secrets

**Files:**
- Modify: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Extract(salt []byte, ikm []byte) []byte`,
  `CryptoProvider.DeriveSecret(secret []byte, label string) []byte`,
  `CryptoProvider.ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte`,
  `syntax.Marshal(v syntax.Marshaler) ([]byte, error)`, `DeriveJoinerSecret` (Task 5),
  `ZeroSecret` (Task 5).
- Produces:
  ```go
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
  type KeySchedule struct{ /* unexported */ }
  func NewKeySchedule(crypto CryptoProvider, initSecretPrev []byte, commitSecret []byte, pskSecret []byte, groupContext *GroupContext) (*KeySchedule, error)
  func NewKeyScheduleFromJoiner(crypto CryptoProvider, joinerSecret []byte, pskSecret []byte, groupContext *GroupContext) (*KeySchedule, error)
  func (self *KeySchedule) JoinerSecret() []byte
  func (self *KeySchedule) WelcomeSecret() []byte
  func (self *KeySchedule) Secrets() *EpochSecrets
  func (self *KeySchedule) GroupContextBytes() []byte
  ```

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

const (
	ksVectorPskSecret          = "e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b"
	ksVectorWelcomeSecret      = "b0defbdd2232224b0c0427e8efa80f011f7813291dca783433f2da1431620bbc"
	ksVectorSenderDataSecret   = "de1df3a74bbcfc7fcc631213a20c1b1842860eab8e6f0c864dcfb541cd42cf24"
	ksVectorEncryptionSecret   = "ffcc3d4a757224eaf62c124f8e7def12c0db74740cf494c9f56fa7dd07214947"
	ksVectorExporterSecret     = "27518b380b39834affecb08780ee9709627859d5f6f37994e8783791004485cb"
	ksVectorExternalSecret     = "46f51f54ce4c3457ee5681925b9d1a282de166f04e28a4a316404bd14dda3138"
	ksVectorConfirmationKey    = "e8bdff522e2675c7e0582321fbeb7e61763b1f88e7ded3c57ea78c691e1d0b93"
	ksVectorMembershipKey      = "6839abba79aaeb82385397612fb90cbea3bf8d427806cb3f0bfe5793c1a42fc9"
	ksVectorResumptionPsk      = "244b05004ced1a7d1dc3da6a7541e9b180b6ffe41cc6e24d63c5c9c0742b4870"
	ksVectorEpochAuthenticator = "f68f6735aeeb97331d674ef4f580e11352beff543b3b6688a01a1bab97d42f26"
	ksVectorInitSecret         = "418b197eafd925ebbf4bfd94d650aa83b1a11d6d02f33c2cc81631c6734f69d9"
)

// ksVectorEpoch0Schedule builds the epoch-0 key schedule of the ciphersuite 0x0003
// key-schedule vector.
func ksVectorEpoch0Schedule(t *testing.T) *KeySchedule {
	t.Helper()
	schedule, err := NewKeySchedule(
		ksTestCrypto(t),
		MustHex(t, ksVectorInitialInitSecret),
		MustHex(t, ksVectorCommitSecret),
		MustHex(t, ksVectorPskSecret),
		ksVectorEpoch0GroupContext(t),
	)
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	return schedule
}

// TestNewKeyScheduleKAT pins every secret RFC 9420 section 8 derives for one epoch.
// A wrong DeriveSecret label produces a plausible 32-byte value that only a KAT sees.
func TestNewKeyScheduleKAT(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	if !bytes.Equal(schedule.JoinerSecret(), MustHex(t, ksVectorJoinerSecret)) {
		t.Fatalf("joiner_secret = %x", schedule.JoinerSecret())
	}
	if !bytes.Equal(schedule.WelcomeSecret(), MustHex(t, ksVectorWelcomeSecret)) {
		t.Fatalf("welcome_secret = %x", schedule.WelcomeSecret())
	}
	secrets := schedule.Secrets()
	for _, check := range []struct {
		name string
		got  []byte
		want string
	}{
		{"sender_data_secret", secrets.SenderData, ksVectorSenderDataSecret},
		{"encryption_secret", secrets.Encryption, ksVectorEncryptionSecret},
		{"exporter_secret", secrets.Exporter, ksVectorExporterSecret},
		{"external_secret", secrets.External, ksVectorExternalSecret},
		{"confirmation_key", secrets.Confirmation, ksVectorConfirmationKey},
		{"membership_key", secrets.Membership, ksVectorMembershipKey},
		{"resumption_psk", secrets.ResumptionPsk, ksVectorResumptionPsk},
		{"epoch_authenticator", secrets.EpochAuthenticator, ksVectorEpochAuthenticator},
		{"init_secret", secrets.InitSecret, ksVectorInitSecret},
	} {
		if !bytes.Equal(check.got, MustHex(t, check.want)) {
			t.Fatalf("%s = %x, want %s", check.name, check.got, check.want)
		}
	}
}

// TestKeyScheduleGroupContextBytesMatchMarshal asserts the schedule expanded over the
// same bytes the caller would sign over.
func TestKeyScheduleGroupContextBytesMatchMarshal(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	if !bytes.Equal(schedule.GroupContextBytes(), MustHex(t, ksVectorGroupContext)) {
		t.Fatalf("GroupContextBytes = %x", schedule.GroupContextBytes())
	}
}

// TestKeyScheduleSecretsDoNotAlias asserts each derived secret is its own allocation,
// so zeroizing one does not silently clear another.
func TestKeyScheduleSecretsDoNotAlias(t *testing.T) {
	secrets := ksVectorEpoch0Schedule(t).Secrets()
	all := [][]byte{
		secrets.SenderData, secrets.Encryption, secrets.Exporter, secrets.External,
		secrets.Confirmation, secrets.Membership, secrets.ResumptionPsk,
		secrets.EpochAuthenticator, secrets.InitSecret,
	}
	for i := range all {
		for j := range all {
			if i == j {
				continue
			}
			if &all[i][0] == &all[j][0] {
				t.Fatalf("secret %d aliases secret %d", i, j)
			}
		}
	}
}

// TestNewKeyScheduleRejectsShortPskSecret asserts a wrong-length psk_secret is fatal.
func TestNewKeyScheduleRejectsShortPskSecret(t *testing.T) {
	_, err := NewKeySchedule(
		ksTestCrypto(t),
		MustHex(t, ksVectorInitialInitSecret),
		MustHex(t, ksVectorCommitSecret),
		MustHex(t, ksVectorPskSecret)[:31],
		ksVectorEpoch0GroupContext(t),
	)
	if !errors.Is(err, ErrSecretLength) {
		t.Fatalf("err = %v, want ErrSecretLength", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestNewKeySchedule|TestKeyScheduleGroupContextBytes|TestKeyScheduleSecretsDoNotAlias' -v`
Expected: FAIL to compile with `undefined: NewKeySchedule`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to key_schedule.go

// EpochSecrets is every secret RFC 9420 section 8 derives from epoch_secret.
// epoch_secret itself is deliberately absent: MASTER section 8.2 records that
// exporting it would also expose confirmation_key and membership_key, so it never
// leaves the KeySchedule that produced it.
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

// KeySchedule is one epoch of the RFC 9420 section 8 key schedule.
// Not safe for concurrent use; the owning Group serializes access.
type KeySchedule struct {
	crypto              CryptoProvider
	groupContextBytes   []byte
	joinerSecret        []byte
	welcomeSecret       []byte
	epochSecret         []byte
	secrets             EpochSecrets
}

// NewKeySchedule advances the schedule from the previous epoch's init_secret.
func NewKeySchedule(
	crypto CryptoProvider,
	initSecretPrev []byte,
	commitSecret []byte,
	pskSecret []byte,
	groupContext *GroupContext,
) (*KeySchedule, error) {
	joinerSecret, err := DeriveJoinerSecret(crypto, initSecretPrev, commitSecret, groupContext)
	if err != nil {
		return nil, err
	}
	return NewKeyScheduleFromJoiner(crypto, joinerSecret, pskSecret, groupContext)
}

// NewKeyScheduleFromJoiner builds the schedule a joiner reaches from the
// joiner_secret carried in its GroupSecrets, which is the only path a member added
// by Welcome has: it never sees init_secret_[n-1] or commit_secret.
func NewKeyScheduleFromJoiner(
	crypto CryptoProvider,
	joinerSecret []byte,
	pskSecret []byte,
	groupContext *GroupContext,
) (*KeySchedule, error) {
	nh := crypto.HashSize()
	if len(joinerSecret) != nh {
		return nil, fmt.Errorf("%w: joiner secret is %d bytes, want %d", ErrSecretLength, len(joinerSecret), nh)
	}
	if len(pskSecret) != nh {
		return nil, fmt.Errorf("%w: psk secret is %d bytes, want %d", ErrSecretLength, len(pskSecret), nh)
	}
	encodedGroupContext, err := syntax.Marshal(groupContext)
	if err != nil {
		return nil, err
	}
	// Extract takes (salt, ikm). joiner_secret is the salt, psk_secret the ikm.
	memberSecret := crypto.Extract(joinerSecret, pskSecret)
	welcomeSecret := crypto.DeriveSecret(memberSecret, "welcome")
	epochSecret := crypto.ExpandWithLabel(memberSecret, "epoch", encodedGroupContext, nh)
	zeroizeSecret(memberSecret)

	self := &KeySchedule{
		crypto:            crypto,
		groupContextBytes: encodedGroupContext,
		joinerSecret:      joinerSecret,
		welcomeSecret:     welcomeSecret,
		epochSecret:       epochSecret,
		secrets: EpochSecrets{
			SenderData:         crypto.DeriveSecret(epochSecret, "sender data"),
			Encryption:         crypto.DeriveSecret(epochSecret, "encryption"),
			Exporter:           crypto.DeriveSecret(epochSecret, "exporter"),
			External:           crypto.DeriveSecret(epochSecret, "external"),
			Confirmation:       crypto.DeriveSecret(epochSecret, "confirm"),
			Membership:         crypto.DeriveSecret(epochSecret, "membership"),
			ResumptionPsk:      crypto.DeriveSecret(epochSecret, "resumption"),
			EpochAuthenticator: crypto.DeriveSecret(epochSecret, "authentication"),
			InitSecret:         crypto.DeriveSecret(epochSecret, "init"),
		},
	}
	return self, nil
}

// JoinerSecret is the joiner_secret a Welcome carries to a new member.
func (self *KeySchedule) JoinerSecret() []byte {
	return self.joinerSecret
}

// WelcomeSecret is the input to the Welcome AEAD key and nonce.
func (self *KeySchedule) WelcomeSecret() []byte {
	return self.welcomeSecret
}

// Secrets is the epoch's derived secrets.
func (self *KeySchedule) Secrets() *EpochSecrets {
	return &self.secrets
}

// GroupContextBytes is the serialized GroupContext this epoch expanded over.
func (self *KeySchedule) GroupContextBytes() []byte {
	return self.groupContextBytes
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestNewKeySchedule|TestKeyScheduleGroupContextBytes|TestKeyScheduleSecretsDoNotAlias' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): epoch key schedule with all nine derived secrets pinned to the vector"
```

---

### Task 6a: NewKeyScheduleFromEpochSecret — the group-creation entry point

**Files:**
- Modify: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.DeriveSecret`, `CryptoProvider.HashSize`,
  `syntax.Marshal(v syntax.Marshaler) ([]byte, error)`.
- Produces:
  ```go
  func NewKeyScheduleFromEpochSecret(crypto CryptoProvider, epochSecret []byte, groupContext *GroupContext) (*KeySchedule, error)
  ```

  This is a registry gap, not a rename. RFC 9420 §11 group creation samples a fresh `epoch_secret`
  of size `KDF.Nh`; Tasks 5 and 6 offer entry points only from `init_secret + commit_secret` and
  from `joiner_secret`, so p7's `NewGroup` had nothing to call and the entry point of the whole
  slice could not be written. `joiner_secret` and `welcome_secret` are **undefined** on this path:
  the accessors keep the `[]byte`-returning signatures the registry fixes and return nil, and the
  test below pins that so a caller cannot mistake nil for a derived secret it may seal a Welcome
  with. A group created this way adds its first member by committing, which produces a real
  `joiner_secret` through Task 5.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

// TestNewKeyScheduleFromEpochSecretDerivesTheSameNineSecrets asserts the creation
// path reaches the same nine secrets as the commit path, given the epoch_secret the
// commit path computed. Anything else would mean a group's creator and its first
// joiner are in different epochs from the first message.
func TestNewKeyScheduleFromEpochSecretDerivesTheSameNineSecrets(t *testing.T) {
	crypto := ksTestCrypto(t)
	groupContext := ksVectorEpoch0GroupContext(t)
	fromCommit := ksVectorEpoch0Schedule(t)

	// the epoch_secret the commit path derived, recomputed here from the vector's
	// own inputs, because the type deliberately never exports it (G6).
	encodedGroupContext, err := syntax.Marshal(groupContext)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	joiner := MustHex(t, ksVectorJoinerSecret)
	member := crypto.Extract(joiner, MustHex(t, ksVectorPskSecret))
	epochSecret := crypto.ExpandWithLabel(member, "epoch", encodedGroupContext, crypto.HashSize())

	fromEpoch, err := NewKeyScheduleFromEpochSecret(crypto, epochSecret, groupContext)
	if err != nil {
		t.Fatalf("NewKeyScheduleFromEpochSecret: %v", err)
	}
	a, b := fromCommit.Secrets(), fromEpoch.Secrets()
	for _, check := range []struct {
		name string
		a    []byte
		b    []byte
	}{
		{"sender_data", a.SenderData, b.SenderData},
		{"encryption", a.Encryption, b.Encryption},
		{"exporter", a.Exporter, b.Exporter},
		{"external", a.External, b.External},
		{"confirmation", a.Confirmation, b.Confirmation},
		{"membership", a.Membership, b.Membership},
		{"resumption_psk", a.ResumptionPsk, b.ResumptionPsk},
		{"epoch_authenticator", a.EpochAuthenticator, b.EpochAuthenticator},
		{"init", a.InitSecret, b.InitSecret},
	} {
		if !bytes.Equal(check.a, check.b) {
			t.Fatalf("%s differs: %x vs %x", check.name, check.a, check.b)
		}
	}
}

// TestNewKeyScheduleFromEpochSecretHasNoJoinerOrWelcomeSecret asserts the two secrets
// that are undefined on this path read as nil. A group created from a sampled
// epoch_secret was never joined, so sealing a Welcome with what these return would
// seal it under a 32-byte run of zeros or a nil key, depending on the AEAD.
func TestNewKeyScheduleFromEpochSecretHasNoJoinerOrWelcomeSecret(t *testing.T) {
	crypto := ksTestCrypto(t)
	schedule, err := NewKeyScheduleFromEpochSecret(
		crypto, crypto.Random(crypto.HashSize()), ksVectorEpoch0GroupContext(t))
	if err != nil {
		t.Fatalf("NewKeyScheduleFromEpochSecret: %v", err)
	}
	if schedule.JoinerSecret() != nil {
		t.Fatalf("JoinerSecret = %x, want nil on the creation path", schedule.JoinerSecret())
	}
	if schedule.WelcomeSecret() != nil {
		t.Fatalf("WelcomeSecret = %x, want nil on the creation path", schedule.WelcomeSecret())
	}
	if _, _, err := WelcomeKeyNonce(crypto, schedule.WelcomeSecret()); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("WelcomeKeyNonce(nil) err = %v, want ErrSecretLength", err)
	}
}

// TestNewKeyScheduleFromEpochSecretRejectsShortSecret asserts a wrong-length sample is
// fatal rather than a silently valid group nobody else can join.
func TestNewKeyScheduleFromEpochSecretRejectsShortSecret(t *testing.T) {
	crypto := ksTestCrypto(t)
	_, err := NewKeyScheduleFromEpochSecret(
		crypto, crypto.Random(crypto.HashSize())[:31], ksVectorEpoch0GroupContext(t))
	if !errors.Is(err, ErrSecretLength) {
		t.Fatalf("err = %v, want ErrSecretLength", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestNewKeyScheduleFromEpochSecret -v`
Expected: FAIL to compile with `undefined: NewKeyScheduleFromEpochSecret`.

- [ ] **Step 3: Write minimal implementation**

Factor the nine derivations out of `NewKeyScheduleFromJoiner` so both entry points expand the same
epoch secret with the same labels, then add the new constructor:

```go
// replace the tail of NewKeyScheduleFromJoiner in key_schedule.go with:

	memberSecret := crypto.Extract(joinerSecret, pskSecret)
	welcomeSecret := crypto.DeriveSecret(memberSecret, "welcome")
	epochSecret := crypto.ExpandWithLabel(memberSecret, "epoch", encodedGroupContext, nh)
	zeroizeSecret(memberSecret)
	return newKeyScheduleFromParts(crypto, encodedGroupContext, joinerSecret, welcomeSecret, epochSecret), nil
}

// newKeyScheduleFromParts expands one epoch_secret into the nine derived secrets.
// Both exported constructors route through here so a label can only ever be wrong in
// one place. joinerSecret and welcomeSecret are nil on the group-creation path.
func newKeyScheduleFromParts(
	crypto CryptoProvider,
	encodedGroupContext []byte,
	joinerSecret []byte,
	welcomeSecret []byte,
	epochSecret []byte,
) *KeySchedule {
	return &KeySchedule{
		crypto:            crypto,
		groupContextBytes: encodedGroupContext,
		joinerSecret:      joinerSecret,
		welcomeSecret:     welcomeSecret,
		epochSecret:       epochSecret,
		secrets: EpochSecrets{
			SenderData:         crypto.DeriveSecret(epochSecret, "sender data"),
			Encryption:         crypto.DeriveSecret(epochSecret, "encryption"),
			Exporter:           crypto.DeriveSecret(epochSecret, "exporter"),
			External:           crypto.DeriveSecret(epochSecret, "external"),
			Confirmation:       crypto.DeriveSecret(epochSecret, "confirm"),
			Membership:         crypto.DeriveSecret(epochSecret, "membership"),
			ResumptionPsk:      crypto.DeriveSecret(epochSecret, "resumption"),
			EpochAuthenticator: crypto.DeriveSecret(epochSecret, "authentication"),
			InitSecret:         crypto.DeriveSecret(epochSecret, "init"),
		},
	}
}

// NewKeyScheduleFromEpochSecret builds the schedule of a group being created, from
// the fresh epoch_secret of KDF.Nh bytes RFC 9420 section 11 says to sample. This is
// the only entry point NewGroup can use: there is no previous init_secret to advance
// from and no joiner_secret to be handed.
//
// joiner_secret and welcome_secret are undefined here and the accessors return nil.
// The creator obtains real ones by committing the first Add, which runs the section 8
// derivation in NewKeySchedule.
func NewKeyScheduleFromEpochSecret(
	crypto CryptoProvider,
	epochSecret []byte,
	groupContext *GroupContext,
) (*KeySchedule, error) {
	nh := crypto.HashSize()
	if len(epochSecret) != nh {
		return nil, fmt.Errorf("%w: epoch secret is %d bytes, want %d", ErrSecretLength, len(epochSecret), nh)
	}
	encodedGroupContext, err := syntax.Marshal(groupContext)
	if err != nil {
		return nil, err
	}
	return newKeyScheduleFromParts(
		crypto, encodedGroupContext, nil, nil, append([]byte(nil), epochSecret...)), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestNewKeySchedule|TestKeySchedule' -v`
Expected: PASS, including every Task 6 test — the refactor must not move a single byte.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): NewKeyScheduleFromEpochSecret, the group-creation entry point"
```

---

### Task 7: The joiner path produces the same epoch

**Files:**
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `NewKeySchedule`, `NewKeyScheduleFromJoiner` (Task 6).
- Produces: nothing new. Produces the guarantee the committer and the joiner reach one epoch.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

// TestKeyScheduleJoinerPathAgreesWithCommitterPath asserts a member who only ever
// sees joiner_secret derives byte-identical epoch secrets to the committer who
// derived it from init_secret and commit_secret. A divergence here is the failure
// where a newly added member can read nothing and the group looks broken to them
// alone, which is expensive to diagnose from logs.
func TestKeyScheduleJoinerPathAgreesWithCommitterPath(t *testing.T) {
	crypto := ksTestCrypto(t)
	groupContext := ksVectorEpoch0GroupContext(t)
	pskSecret := MustHex(t, ksVectorPskSecret)

	committer, err := NewKeySchedule(
		crypto,
		MustHex(t, ksVectorInitialInitSecret),
		MustHex(t, ksVectorCommitSecret),
		pskSecret,
		groupContext,
	)
	if err != nil {
		t.Fatalf("NewKeySchedule: %v", err)
	}
	joiner, err := NewKeyScheduleFromJoiner(crypto, committer.JoinerSecret(), pskSecret, groupContext)
	if err != nil {
		t.Fatalf("NewKeyScheduleFromJoiner: %v", err)
	}

	if !bytes.Equal(committer.WelcomeSecret(), joiner.WelcomeSecret()) {
		t.Fatal("welcome_secret differs between the committer and joiner paths")
	}
	c, j := committer.Secrets(), joiner.Secrets()
	for _, check := range []struct {
		name string
		a    []byte
		b    []byte
	}{
		{"sender_data", c.SenderData, j.SenderData},
		{"encryption", c.Encryption, j.Encryption},
		{"exporter", c.Exporter, j.Exporter},
		{"external", c.External, j.External},
		{"confirmation", c.Confirmation, j.Confirmation},
		{"membership", c.Membership, j.Membership},
		{"resumption_psk", c.ResumptionPsk, j.ResumptionPsk},
		{"epoch_authenticator", c.EpochAuthenticator, j.EpochAuthenticator},
		{"init", c.InitSecret, j.InitSecret},
	} {
		if !bytes.Equal(check.a, check.b) {
			t.Fatalf("%s differs: %x vs %x", check.name, check.a, check.b)
		}
	}
}

// TestKeyScheduleJoinerPathIsBoundToTheGroupContext asserts a joiner given the right
// joiner_secret but the wrong GroupContext derives different secrets, so a swapped
// tree hash or epoch cannot go unnoticed.
func TestKeyScheduleJoinerPathIsBoundToTheGroupContext(t *testing.T) {
	crypto := ksTestCrypto(t)
	pskSecret := MustHex(t, ksVectorPskSecret)
	good := ksVectorEpoch0GroupContext(t)
	bad := good.Clone()
	bad.Epoch = 1

	right, err := NewKeyScheduleFromJoiner(crypto, MustHex(t, ksVectorJoinerSecret), pskSecret, good)
	if err != nil {
		t.Fatalf("NewKeyScheduleFromJoiner: %v", err)
	}
	wrong, err := NewKeyScheduleFromJoiner(crypto, MustHex(t, ksVectorJoinerSecret), pskSecret, bad)
	if err != nil {
		t.Fatalf("NewKeyScheduleFromJoiner: %v", err)
	}
	if bytes.Equal(right.Secrets().Encryption, wrong.Secrets().Encryption) {
		t.Fatal("encryption_secret is not bound to the group context epoch")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestKeyScheduleJoinerPath -v`
Expected: PASS immediately if Task 6 is correct. If it FAILs, the failure message names the first
secret that differs and Task 6's implementation is wrong; fix Task 6 rather than this test.

- [ ] **Step 3: Write minimal implementation**

No implementation change is expected. If Step 2 failed, the cause is a `welcomeSecret` derived from
`joinerSecret` instead of the extracted member secret; correct `NewKeyScheduleFromJoiner` in
`key_schedule.go` so both paths run through the identical `crypto.Extract(joinerSecret, pskSecret)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestKeyScheduleJoinerPath -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_test.go connect/mls/key_schedule.go
git ls-files | wc -l
git commit -m "test(mls): committer and joiner key schedule paths agree on every epoch secret"
```

---

### Task 8: The exporter

**Files:**
- Modify: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.DeriveSecret`, `CryptoProvider.ExpandWithLabel`, `CryptoProvider.Hash`.
- Produces: `func (self *KeySchedule) Export(label string, context []byte, length int) ([]byte, error)`

  This is the function `connect/message` reaches through `GroupHandle.Export` to compute
  `mls_secret[n] = MLS-Exporter("URmessage/v1/storage", "", 32)` (MASTER section 7).

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

const (
	// the vector's exporter label is a 64-character ASCII string that happens to be
	// made of hex characters. It is NOT hex-encoded: the mlswg format documents this
	// field as a string while every sibling field is hex. Decoding it would produce a
	// 32-byte label and a wrong exporter output.
	ksVectorExporterLabel   = "9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4"
	ksVectorExporterContext = "884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785"
	ksVectorExporterSecretOut = "623c858acd2728c5b860a77ae0cde77fa8aef14e9ac124464cab06bbc3cf3635"
)

// TestKeyScheduleExportKAT pins MLS-Exporter, including the inner "exported" label
// and the hashing of the caller's context.
func TestKeyScheduleExportKAT(t *testing.T) {
	exported, err := ksVectorEpoch0Schedule(t).Export(
		ksVectorExporterLabel,
		MustHex(t, ksVectorExporterContext),
		32,
	)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	want := MustHex(t, ksVectorExporterSecretOut)
	if !bytes.Equal(exported, want) {
		t.Fatalf("Export = %x, want %x", exported, want)
	}
}

// TestKeyScheduleExportLabelIsNotHexDecoded asserts that treating the vector's label
// as hex produces a different answer, which is what makes the KAT above meaningful.
func TestKeyScheduleExportLabelIsNotHexDecoded(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	asString, err := schedule.Export(ksVectorExporterLabel, MustHex(t, ksVectorExporterContext), 32)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	asHex, err := schedule.Export(string(MustHex(t, ksVectorExporterLabel)), MustHex(t, ksVectorExporterContext), 32)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bytes.Equal(asString, asHex) {
		t.Fatal("the label is being ignored: string and hex-decoded forms agree")
	}
}

// TestKeyScheduleExportEmptyContextIsHashed asserts an empty context is hashed rather
// than passed through, which is the MASTER section 7 storage call.
func TestKeyScheduleExportEmptyContextIsHashed(t *testing.T) {
	crypto := ksTestCrypto(t)
	schedule := ksVectorEpoch0Schedule(t)
	exported, err := schedule.Export("URmessage/v1/storage", nil, 32)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	derived := crypto.DeriveSecret(schedule.Secrets().Exporter, "URmessage/v1/storage")
	want := crypto.ExpandWithLabel(derived, "exported", crypto.Hash(nil), 32)
	if !bytes.Equal(exported, want) {
		t.Fatalf("Export = %x, want %x", exported, want)
	}
}

// TestKeyScheduleExportRejectsOverlongLength asserts HKDF's 255*Nh ceiling is a typed
// error rather than a silent truncation.
func TestKeyScheduleExportRejectsOverlongLength(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	if _, err := schedule.Export("x", nil, 255*32+1); !errors.Is(err, ErrExportLength) {
		t.Fatalf("err = %v, want ErrExportLength", err)
	}
	if _, err := schedule.Export("x", nil, -1); !errors.Is(err, ErrExportLength) {
		t.Fatalf("err = %v, want ErrExportLength", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestKeyScheduleExport -v`
Expected: FAIL to compile with `schedule.Export undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to key_schedule.go

// Export is MLS-Exporter of RFC 9420 section 8.5:
//
//	MLS-Exporter(Label, Context, Length) =
//	    ExpandWithLabel(DeriveSecret(exporter_secret, Label),
//	                    "exported", Hash(Context), Length)
//
// The caller's context is hashed, so a caller may pass any length. This is the only
// way connect/message obtains epoch-bound key material; the named epoch secrets it
// also needs are reached through the closed EpochSecretName enum on Group.
func (self *KeySchedule) Export(label string, context []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*self.crypto.HashSize() {
		return nil, fmt.Errorf("%w: %d", ErrExportLength, length)
	}
	derived := self.crypto.DeriveSecret(self.secrets.Exporter, label)
	exported := self.crypto.ExpandWithLabel(derived, "exported", self.crypto.Hash(context), length)
	zeroizeSecret(derived)
	return exported, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestKeyScheduleExport -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): MLS-Exporter with the exported label and hashed context pinned"
```

---

### Task 9: The external key pair

**Files:**
- Modify: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error)`,
  `type HpkePublicKey []byte`. **`HpkePublicKey` has no `Bytes()` method** (registry §3.2): it is a
  byte slice, so `external_pub` is compared against it directly with `bytes.Equal`.
- Produces: `func (self *KeySchedule) ExternalKeyPair() (HpkePrivateKey, HpkePublicKey, error)`

  **Boundary note for p7:** v1 refuses external commits, so `external_pub` MUST NOT be published in
  a `GroupInfo` extension. This function exists so `key-schedule.json` passes and so V2 is a policy
  change rather than a key-schedule change. `TestExternalPubIsNotAdvertised` in p7 is the
  counterpart assertion.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

const ksVectorExternalPub = "8206ea1eb4d8d5730a2737f7470718b9d00c2276d24a98ac4e6d7ef52cba0631"

// TestKeyScheduleExternalKeyPairKAT pins external_pub = DeriveKeyPair(external_secret).
// The key-schedule vector family checks this field even though v1 refuses external
// commits, so the derivation has to be right regardless of whether it is ever used.
func TestKeyScheduleExternalKeyPairKAT(t *testing.T) {
	_, pub, err := ksVectorEpoch0Schedule(t).ExternalKeyPair()
	if err != nil {
		t.Fatalf("ExternalKeyPair: %v", err)
	}
	want := MustHex(t, ksVectorExternalPub)
	if !bytes.Equal(pub, want) {
		t.Fatalf("external_pub = %x, want %x", pub, want)
	}
}

// TestKeyScheduleExternalKeyPairIsDeterministic asserts two calls agree, so nothing
// in the derivation reads entropy.
func TestKeyScheduleExternalKeyPairIsDeterministic(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	_, first, err := schedule.ExternalKeyPair()
	if err != nil {
		t.Fatalf("ExternalKeyPair: %v", err)
	}
	_, second, err := schedule.ExternalKeyPair()
	if err != nil {
		t.Fatalf("ExternalKeyPair: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("ExternalKeyPair is not deterministic")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestKeyScheduleExternalKeyPair -v`
Expected: FAIL to compile with `schedule.ExternalKeyPair undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to key_schedule.go

// ExternalKeyPair derives the epoch's external HPKE key pair from external_secret.
//
// v1 refuses external commits (Spec A section 3.2), so this key pair is never
// advertised in a GroupInfo and never used to accept an ExternalInit. It exists
// because key-schedule.json checks external_pub, and because a suite whose
// DeriveKeyPair is wrong here is wrong everywhere else too.
func (self *KeySchedule) ExternalKeyPair() (HpkePrivateKey, HpkePublicKey, error) {
	return self.crypto.DeriveKeyPair(self.secrets.External)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestKeyScheduleExternalKeyPair -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): external key pair derivation for key-schedule vector conformance"
```

---

### Task 10: Confirmation tag and membership tag

**Files:**
- Modify: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Mac(key, data)`, `CryptoProvider.MacVerify(key, data, tag) bool`.
- Produces:
  ```go
  func (self *KeySchedule) ConfirmationTag(confirmedTranscriptHash []byte) []byte
  func (self *KeySchedule) VerifyConfirmationTag(confirmedTranscriptHash []byte, tag []byte) bool
  func (self *KeySchedule) MembershipTag(authenticatedContentTbm []byte) []byte
  func (self *KeySchedule) VerifyMembershipTag(authenticatedContentTbm []byte, tag []byte) bool
  ```

  p6 builds `authenticatedContentTbm` with
  `AuthenticatedContentTBMBytes(authContent, groupContext)` (registry §7.3) and passes the bytes;
  this plan never sees framing types. p7 calls `VerifyConfirmationTag` for ValSem205 and
  `VerifyMembershipTag` for ValSem008, and MUST `return` on false rather than logging
  (guardrail G7).

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

// TestConfirmationTagKAT pins the tag as MAC(confirmation_key, confirmed_transcript_hash).
// The confirmation tag is the fork detector: two members whose transcripts diverged
// produce different tags, and every commit carries one.
func TestConfirmationTagKAT(t *testing.T) {
	crypto := ksTestCrypto(t)
	schedule := ksVectorEpoch0Schedule(t)
	confirmedTranscriptHash := MustHex(t, ksVectorCth)
	want := crypto.Mac(MustHex(t, ksVectorConfirmationKey), confirmedTranscriptHash)
	got := schedule.ConfirmationTag(confirmedTranscriptHash)
	if !bytes.Equal(got, want) {
		t.Fatalf("ConfirmationTag = %x, want %x", got, want)
	}
	if len(got) != crypto.HashSize() {
		t.Fatalf("tag is %d bytes, want %d", len(got), crypto.HashSize())
	}
}

// TestVerifyConfirmationTagAcceptsAndRejects asserts the happy path and that a single
// flipped bit in the transcript hash or in the tag is refused.
func TestVerifyConfirmationTagAcceptsAndRejects(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	confirmedTranscriptHash := MustHex(t, ksVectorCth)
	tag := schedule.ConfirmationTag(confirmedTranscriptHash)
	if !schedule.VerifyConfirmationTag(confirmedTranscriptHash, tag) {
		t.Fatal("a freshly computed tag did not verify")
	}
	flippedTag := append([]byte(nil), tag...)
	flippedTag[0] ^= 0x01
	if schedule.VerifyConfirmationTag(confirmedTranscriptHash, flippedTag) {
		t.Fatal("a tag with one flipped bit verified")
	}
	flippedHash := append([]byte(nil), confirmedTranscriptHash...)
	flippedHash[31] ^= 0x80
	if schedule.VerifyConfirmationTag(flippedHash, tag) {
		t.Fatal("a transcript hash with one flipped bit verified")
	}
	if schedule.VerifyConfirmationTag(confirmedTranscriptHash, nil) {
		t.Fatal("a nil tag verified")
	}
	if schedule.VerifyConfirmationTag(confirmedTranscriptHash, tag[:16]) {
		t.Fatal("a truncated tag verified")
	}
}

// TestMembershipTagUsesTheMembershipKey asserts the membership tag is keyed by
// membership_key and not by confirmation_key. The two are adjacent DeriveSecret calls
// and swapping them still produces a 32-byte tag that both sides would accept if the
// same bug existed on both sides, so this pins it against the vector's own key.
func TestMembershipTagUsesTheMembershipKey(t *testing.T) {
	crypto := ksTestCrypto(t)
	schedule := ksVectorEpoch0Schedule(t)
	tbm := []byte("AuthenticatedContentTBM placeholder bytes")
	want := crypto.Mac(MustHex(t, ksVectorMembershipKey), tbm)
	got := schedule.MembershipTag(tbm)
	if !bytes.Equal(got, want) {
		t.Fatalf("MembershipTag = %x, want %x", got, want)
	}
	if !schedule.VerifyMembershipTag(tbm, got) {
		t.Fatal("a freshly computed membership tag did not verify")
	}
	if schedule.VerifyMembershipTag(append(tbm, 'x'), got) {
		t.Fatal("a membership tag verified over different content")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestConfirmationTag|TestVerifyConfirmationTag|TestMembershipTag' -v`
Expected: FAIL to compile with `schedule.ConfirmationTag undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to key_schedule.go

// ConfirmationTag is MAC(confirmation_key, confirmed_transcript_hash), the value
// every Commit carries and every receiver recomputes. Two members whose transcripts
// diverged produce different tags, so this is the fork detector.
func (self *KeySchedule) ConfirmationTag(confirmedTranscriptHash []byte) []byte {
	return self.crypto.Mac(self.secrets.Confirmation, confirmedTranscriptHash)
}

// VerifyConfirmationTag is ValSem205. The comparison is constant time inside
// MacVerify. A false result is fatal to the message: the caller returns, it does
// not log and continue.
func (self *KeySchedule) VerifyConfirmationTag(confirmedTranscriptHash []byte, tag []byte) bool {
	return self.crypto.MacVerify(self.secrets.Confirmation, confirmedTranscriptHash, tag)
}

// MembershipTag is MAC(membership_key, AuthenticatedContentTBM). The caller
// serializes the TBM structure; this package never sees framing types.
func (self *KeySchedule) MembershipTag(authenticatedContentTbm []byte) []byte {
	return self.crypto.Mac(self.secrets.Membership, authenticatedContentTbm)
}

// VerifyMembershipTag is ValSem008. A false result is fatal to the message.
func (self *KeySchedule) VerifyMembershipTag(authenticatedContentTbm []byte, tag []byte) bool {
	return self.crypto.MacVerify(self.secrets.Membership, authenticatedContentTbm, tag)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestConfirmationTag|TestVerifyConfirmationTag|TestMembershipTag' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): confirmation and membership tags with constant-time verification"
```

---

### Task 11: Welcome key and nonce

**Files:**
- Modify: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.ExpandWithLabel`, `CryptoProvider.KeySize`, `CryptoProvider.NonceSize`.
- Produces:
  ```go
  func WelcomeKeyNonce(crypto CryptoProvider, welcomeSecret []byte) (key []byte, nonce []byte, err error)
  ```

  p7's `BuildWelcome` and `JoinFromWelcome` (registry §8.4) use this to seal and open
  `Welcome.EncryptedGroupInfo`. The end-to-end check is the `welcome.json` vector family, which
  lives in p7; what is pinned here is the derivation shape and the output lengths. The error return
  is load-bearing on the group-creation path, where `(*KeySchedule).WelcomeSecret()` is nil
  (Task 6a).

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

// TestWelcomeKeyNonceShape pins welcome_key and welcome_nonce as ExpandWithLabel over
// welcome_secret with an empty context, at the suite's AEAD key and nonce sizes.
func TestWelcomeKeyNonceShape(t *testing.T) {
	crypto := ksTestCrypto(t)
	welcomeSecret := MustHex(t, ksVectorWelcomeSecret)
	key, nonce, err := WelcomeKeyNonce(crypto, welcomeSecret)
	if err != nil {
		t.Fatalf("WelcomeKeyNonce: %v", err)
	}
	wantKey := crypto.ExpandWithLabel(welcomeSecret, "key", nil, crypto.KeySize())
	wantNonce := crypto.ExpandWithLabel(welcomeSecret, "nonce", nil, crypto.NonceSize())
	if !bytes.Equal(key, wantKey) {
		t.Fatalf("welcome key = %x, want %x", key, wantKey)
	}
	if !bytes.Equal(nonce, wantNonce) {
		t.Fatalf("welcome nonce = %x, want %x", nonce, wantNonce)
	}
	if len(key) != 32 {
		t.Fatalf("welcome key is %d bytes, want 32", len(key))
	}
	if len(nonce) != 12 {
		t.Fatalf("welcome nonce is %d bytes, want 12", len(nonce))
	}
}

// TestWelcomeKeyNonceDiffersFromEachOther asserts the key and the nonce are not the
// same expansion truncated differently, which would be an AEAD key/nonce collision.
func TestWelcomeKeyNonceDiffersFromEachOther(t *testing.T) {
	key, nonce, err := WelcomeKeyNonce(ksTestCrypto(t), MustHex(t, ksVectorWelcomeSecret))
	if err != nil {
		t.Fatalf("WelcomeKeyNonce: %v", err)
	}
	if bytes.Equal(key[:len(nonce)], nonce) {
		t.Fatal("welcome key and nonce share a prefix")
	}
}

// TestWelcomeKeyNonceRejectsShortSecret asserts a wrong-length welcome_secret is fatal.
func TestWelcomeKeyNonceRejectsShortSecret(t *testing.T) {
	_, _, err := WelcomeKeyNonce(ksTestCrypto(t), MustHex(t, ksVectorWelcomeSecret)[:16])
	if !errors.Is(err, ErrSecretLength) {
		t.Fatalf("err = %v, want ErrSecretLength", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestWelcomeKeyNonce -v`
Expected: FAIL to compile with `undefined: WelcomeKeyNonce`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to key_schedule.go

// WelcomeKeyNonce derives the AEAD key and nonce that protect a Welcome's
// encrypted_group_info, per RFC 9420 section 12.4.3.1:
//
//	welcome_key   = ExpandWithLabel(welcome_secret, "key", "", AEAD.Nk)
//	welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", AEAD.Nn)
func WelcomeKeyNonce(crypto CryptoProvider, welcomeSecret []byte) (key []byte, nonce []byte, err error) {
	nh := crypto.HashSize()
	if len(welcomeSecret) != nh {
		return nil, nil, fmt.Errorf("%w: welcome secret is %d bytes, want %d", ErrSecretLength, len(welcomeSecret), nh)
	}
	key = crypto.ExpandWithLabel(welcomeSecret, "key", nil, crypto.KeySize())
	nonce = crypto.ExpandWithLabel(welcomeSecret, "nonce", nil, crypto.NonceSize())
	return key, nonce, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestWelcomeKeyNonce -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): welcome key and nonce derivation"
```

---

### Task 12: epoch_secret is unreachable, and Zeroize

**Files:**
- Modify: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `zeroizeSecret` (Task 2).
- Produces: `func (self *KeySchedule) Zeroize()`

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

// TestKeyScheduleDoesNotExportEpochSecret is guardrail G6 as a test rather than a
// convention. MASTER's revision-3 correction records that exporting epoch_secret
// instead of the two named secrets would also expose confirmation_key and
// membership_key. Reflection over the type catches an exported field or method added
// later by someone who did not read that correction.
func TestKeyScheduleDoesNotExportEpochSecret(t *testing.T) {
	scheduleType := reflect.TypeOf(KeySchedule{})
	for i := 0; i < scheduleType.NumField(); i++ {
		field := scheduleType.Field(i)
		if field.IsExported() {
			t.Fatalf("KeySchedule has exported field %s; every field must stay unexported", field.Name)
		}
	}
	pointerType := reflect.TypeOf(&KeySchedule{})
	allowed := map[string]bool{
		"JoinerSecret":          true,
		"WelcomeSecret":         true,
		"Secrets":               true,
		"GroupContextBytes":     true,
		"Export":                true,
		"ExternalKeyPair":       true,
		"ConfirmationTag":       true,
		"VerifyConfirmationTag": true,
		"MembershipTag":         true,
		"VerifyMembershipTag":   true,
		"Zeroize":               true,
	}
	for i := 0; i < pointerType.NumMethod(); i++ {
		name := pointerType.Method(i).Name
		if !allowed[name] {
			t.Fatalf("KeySchedule has unexpected exported method %s; add it to this list only "+
				"after checking it does not surface epoch_secret", name)
		}
	}
	secretsType := reflect.TypeOf(EpochSecrets{})
	for i := 0; i < secretsType.NumField(); i++ {
		if secretsType.Field(i).Name == "EpochSecret" {
			t.Fatal("EpochSecrets must not carry epoch_secret")
		}
	}
}

// TestKeyScheduleZeroize asserts every retained secret is cleared, so a group state
// dropped from the past-epoch window leaves nothing behind in the live heap.
func TestKeyScheduleZeroize(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	secrets := schedule.Secrets()
	retained := [][]byte{
		schedule.JoinerSecret(), schedule.WelcomeSecret(),
		secrets.SenderData, secrets.Encryption, secrets.Exporter, secrets.External,
		secrets.Confirmation, secrets.Membership, secrets.ResumptionPsk,
		secrets.EpochAuthenticator, secrets.InitSecret,
	}
	schedule.Zeroize()
	for i, secret := range retained {
		for j, b := range secret {
			if b != 0 {
				t.Fatalf("secret %d byte %d = %d after Zeroize, want 0", i, j, b)
			}
		}
	}
}

// TestPastEpochWindowIsThirtyTwo pins the ValSem400 bound. Spec A section 4.3 records
// why it is 32 and not 8: eight epochs is not a weekend.
func TestPastEpochWindowIsThirtyTwo(t *testing.T) {
	if PastEpochWindow != 32 {
		t.Fatalf("PastEpochWindow = %d, want 32", PastEpochWindow)
	}
}
```

Add `"reflect"` to the `key_schedule_test.go` import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestKeyScheduleDoesNotExportEpochSecret|TestKeyScheduleZeroize|TestPastEpochWindow' -v`
Expected: FAIL to compile with `schedule.Zeroize undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to key_schedule.go

// Zeroize clears every secret this epoch retains. Called when the epoch leaves the
// PastEpochWindow. Best effort, as documented on zeroizeSecret.
func (self *KeySchedule) Zeroize() {
	zeroizeSecret(self.joinerSecret)
	zeroizeSecret(self.welcomeSecret)
	zeroizeSecret(self.epochSecret)
	zeroizeSecret(self.secrets.SenderData)
	zeroizeSecret(self.secrets.Encryption)
	zeroizeSecret(self.secrets.Exporter)
	zeroizeSecret(self.secrets.External)
	zeroizeSecret(self.secrets.Confirmation)
	zeroizeSecret(self.secrets.Membership)
	zeroizeSecret(self.secrets.ResumptionPsk)
	zeroizeSecret(self.secrets.EpochAuthenticator)
	zeroizeSecret(self.secrets.InitSecret)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestKeyScheduleDoesNotExportEpochSecret|TestKeyScheduleZeroize|TestPastEpochWindow' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): key schedule zeroization and a reflection guard on epoch_secret"
```

---

### Task 13: PreSharedKeyId, its codec, and ValSem401/402

**Files:**
- Create: `connect/mls/psk.go`
- Test: `connect/mls/psk_test.go`

**Interfaces:**
- Consumes: `syntax.NewWriter`, `syntax.NewReader`, `syntax.Marshal`, `syntax.Unmarshal`, the writer
  and reader methods pinned in Task 1, `CryptoProvider.HashSize() int`,
  `ValSem(code ValSemCode, detail error) error` with `ValSem401` and `ValSem402`, and p8's
  `ErrPskNonceLength` / `ErrPskType` sentinels.
- Produces:
  ```go
  type PskType uint8
  const (
      PskTypeExternal   PskType = 1
      PskTypeResumption PskType = 2
  )
  type ResumptionPskUsage uint8
  const (
      ResumptionPskUsageApplication ResumptionPskUsage = 1
      ResumptionPskUsageReInit      ResumptionPskUsage = 2
      ResumptionPskUsageBranch      ResumptionPskUsage = 3
  )
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
  func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error
  var _ syntax.Codec = (*PreSharedKeyId)(nil)
  ```

  Under **C1** there is no `(*PreSharedKeyId).Marshal()` and no `ParsePreSharedKeyId(r)`. The name is
  `PreSharedKeyId`, not `PreSharedKeyID`, per `CODESTYLE.md` — p6 and p8 consume this type and adopt
  the same spelling. `MarshalMLS` writes inline, which is exactly what PSKLabel needs, so the private
  `marshalTo` helper the first draft carried is deleted: it was a second spelling of the same method.

  **Refusals are ValSem codes, not local sentinels.** ValSem401 (nonce length) and ValSem402 (type
  and usage) are p8's catalogue entries; this plan returns `ValSem(ValSem401, detail)` with the
  sentinel wrapped in `detail`, so `errors.Is(err, ErrPskNonceLength)` and `CodeOf(err)` both hold
  and Gate 3 can assert the code.

  **Boundary note for the framing and lifecycle plans:** p7 refuses the `psk` proposal type through
  `(*Profile).CheckProposalType` before any `PreSharedKeyId` reaches the key schedule, so p6 needs
  only the codec (it embeds one in `PreSharedKey` and in `GroupSecrets.Psks`) and p7 needs only
  `Validate`. Neither redefines the type.

- [ ] **Step 1: Write the failing test**

```go
// psk_test.go
// tests for the RFC 9420 section 8.4 pre-shared key secret.
package mls

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// pskTestCrypto returns the ciphersuite 0x0003 provider the psk KATs are pinned against.
func pskTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

// TestPreSharedKeyIdMarshalExternal pins the external arm: psktype, psk_id, psk_nonce.
func TestPreSharedKeyIdMarshalExternal(t *testing.T) {
	id := &PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte{0xaa, 0xbb},
		PskNonce: []byte{0x01, 0x02, 0x03},
	}
	encoded, err := syntax.Marshal(id)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	want := []byte{
		0x01, // psktype = external
		0x02, 0xaa, 0xbb, // psk_id<V>
		0x03, 0x01, 0x02, 0x03, // psk_nonce<V>
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("syntax.Marshal = %x, want %x", encoded, want)
	}
}

// TestPreSharedKeyIdMarshalResumption pins the resumption arm, including the usage
// byte and the uint64 epoch that sit between the type and the nonce.
func TestPreSharedKeyIdMarshalResumption(t *testing.T) {
	id := &PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageApplication,
		PskGroupId: []byte{0xcc},
		PskEpoch:   7,
		PskNonce:   []byte{0x09},
	}
	encoded, err := syntax.Marshal(id)
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	want := []byte{
		0x02,             // psktype = resumption
		0x01,             // usage = application
		0x01, 0xcc,       // psk_group_id<V>
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // psk_epoch
		0x01, 0x09, // psk_nonce<V>
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("syntax.Marshal = %x, want %x", encoded, want)
	}
}

// TestPreSharedKeyIdRoundTrip asserts decode(encode(x)) reproduces every field, for
// both arms. MLS derives psk_input over these bytes, so an asymmetric codec silently
// changes psk_secret.
func TestPreSharedKeyIdRoundTrip(t *testing.T) {
	for _, id := range []*PreSharedKeyId{
		{PskType: PskTypeExternal, PskId: []byte{1, 2, 3}, PskNonce: []byte{4, 5}},
		{PskType: PskTypeResumption, Usage: ResumptionPskUsageBranch, PskGroupId: []byte{6}, PskEpoch: 1 << 40, PskNonce: []byte{7}},
	} {
		encoded, err := syntax.Marshal(id)
		if err != nil {
			t.Fatalf("syntax.Marshal: %v", err)
		}
		parsed := &PreSharedKeyId{}
		if err := syntax.Unmarshal(encoded, parsed); err != nil {
			t.Fatalf("syntax.Unmarshal: %v", err)
		}
		reencoded, err := syntax.Marshal(parsed)
		if err != nil {
			t.Fatalf("syntax.Marshal: %v", err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("round trip = %x, want %x", reencoded, encoded)
		}
	}
}

// TestPreSharedKeyIdUnmarshalLeavesTheTailAlone asserts UnmarshalMLS consumes exactly
// one id, which is what PSKLabel and GroupSecrets.psks<V> both depend on.
func TestPreSharedKeyIdUnmarshalLeavesTheTailAlone(t *testing.T) {
	encoded, err := syntax.Marshal(&PreSharedKeyId{
		PskType: PskTypeExternal, PskId: []byte{1, 2, 3}, PskNonce: []byte{4, 5}})
	if err != nil {
		t.Fatalf("syntax.Marshal: %v", err)
	}
	r := syntax.NewReader(append(encoded, 0xde, 0xad))
	if err := (&PreSharedKeyId{}).UnmarshalMLS(r); err != nil {
		t.Fatalf("UnmarshalMLS: %v", err)
	}
	tail, err := r.ReadRaw(2)
	if err != nil {
		t.Fatalf("ReadRaw: %v", err)
	}
	if !bytes.Equal(tail, []byte{0xde, 0xad}) {
		t.Fatalf("tail = %x, want dead", tail)
	}
}

// TestPreSharedKeyIdUnmarshalRejectsUnknownType asserts an unknown psktype byte is
// refused as ValSem402 rather than parsed as an empty external id.
func TestPreSharedKeyIdUnmarshalRejectsUnknownType(t *testing.T) {
	err := syntax.Unmarshal([]byte{0x07, 0x00}, &PreSharedKeyId{})
	if !errors.Is(err, ErrPskType) {
		t.Fatalf("err = %v, want ErrPskType", err)
	}
}

// TestPreSharedKeyIdMarshalRefusesUnknownType asserts the encoder refuses the same arm
// it cannot decode. This is the semantic refusal MarshalMLS returns an error for (C2):
// dropping it would emit a one-byte id that hashes into psk_input as if it were whole.
func TestPreSharedKeyIdMarshalRefusesUnknownType(t *testing.T) {
	_, err := syntax.Marshal(&PreSharedKeyId{PskType: PskType(9), PskNonce: make([]byte, 32)})
	if !errors.Is(err, ErrPskType) {
		t.Fatalf("err = %v, want ErrPskType", err)
	}
}

// TestPreSharedKeyIdValidateNonceLength is ValSem401.
func TestPreSharedKeyIdValidateNonceLength(t *testing.T) {
	crypto := pskTestCrypto(t)
	id := &PreSharedKeyId{PskType: PskTypeExternal, PskId: []byte{1}, PskNonce: make([]byte, 31)}
	// the error is ValSem(ValSem401, ...), so it matches the sentinel through Unwrap.
	// Asserting the code itself is p8's TestValSem401_* — CodeOf is p8-internal and
	// this plan does not reach for it.
	if err := id.Validate(crypto); !errors.Is(err, ErrPskNonceLength) {
		t.Fatalf("err = %v, want ErrPskNonceLength", err)
	}
	id.PskNonce = make([]byte, 32)
	if err := id.Validate(crypto); err != nil {
		t.Fatalf("a 32-byte nonce was refused: %v", err)
	}
}

// TestPreSharedKeyIdValidateUsage is ValSem402: only Resumption(Application) and
// External are acceptable. ReInit and Branch usages belong to features v1 does not
// implement, and accepting one here would let them in through the key schedule.
func TestPreSharedKeyIdValidateUsage(t *testing.T) {
	crypto := pskTestCrypto(t)
	for _, usage := range []ResumptionPskUsage{ResumptionPskUsageReInit, ResumptionPskUsageBranch} {
		id := &PreSharedKeyId{
			PskType:    PskTypeResumption,
			Usage:      usage,
			PskGroupId: []byte{1},
			PskNonce:   make([]byte, 32),
		}
		if err := id.Validate(crypto); !errors.Is(err, ErrPskType) {
			t.Fatalf("usage %d err = %v, want ErrPskType", usage, err)
		}
	}
	ok := &PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageApplication,
		PskGroupId: []byte{1},
		PskNonce:   make([]byte, 32),
	}
	if err := ok.Validate(crypto); err != nil {
		t.Fatalf("Resumption(Application) was refused: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestPreSharedKeyId -v`
Expected: FAIL to compile with `undefined: PreSharedKeyId`.

- [ ] **Step 3: Write minimal implementation**

```go
// psk.go
// the RFC 9420 section 8.4 pre-shared key secret.
//
// v1 refuses PreSharedKey proposals at parse (Spec A section 3.2), so nothing in the
// product ever supplies a non-empty psk list. The computation is still implemented
// and vector-tested, because psk_secret is an input to every epoch as the all-zero
// case and getting the empty case wrong diverges every epoch secret silently.
package mls

import (
	"crypto/subtle"
	"fmt"
	"math"

	"github.com/urnetwork/connect/mls/syntax"
)

// PskType is the RFC 9420 PSKType enum.
type PskType uint8

const (
	PskTypeExternal   PskType = 1
	PskTypeResumption PskType = 2
)

// ResumptionPskUsage is the RFC 9420 ResumptionPSKUsage enum.
type ResumptionPskUsage uint8

const (
	ResumptionPskUsageApplication ResumptionPskUsage = 1
	ResumptionPskUsageReInit      ResumptionPskUsage = 2
	ResumptionPskUsageBranch      ResumptionPskUsage = 3
)

// PreSharedKeyId identifies one pre-shared key. The union arms are flattened into
// one struct because the encoding is only ever produced and consumed here.
type PreSharedKeyId struct {
	PskType    PskType
	PskId      []byte
	Usage      ResumptionPskUsage
	PskGroupId []byte
	PskEpoch   uint64
	PskNonce   []byte
}

// MarshalMLS writes the id inline into a writer the caller owns, which is exactly
// what PSKLabel and GroupSecrets.psks<V> need. The leaf writes return nothing (C2);
// the error return carries the one semantic refusal this encoder has, an arm it
// cannot represent. Dropping that refusal would emit a truncated id that still hashes
// into psk_input as though it were whole.
func (self *PreSharedKeyId) MarshalMLS(w *syntax.Writer) error {
	w.WriteUint8(uint8(self.PskType))
	switch self.PskType {
	case PskTypeExternal:
		w.WriteOpaque(self.PskId)
	case PskTypeResumption:
		w.WriteUint8(uint8(self.Usage))
		w.WriteOpaque(self.PskGroupId)
		w.WriteUint64(self.PskEpoch)
	default:
		return ValSem(ValSem402, fmt.Errorf("%w: psktype %d", ErrPskType, self.PskType))
	}
	w.WriteOpaque(self.PskNonce)
	return nil
}

// UnmarshalMLS decodes exactly one id and leaves the rest of the reader alone.
func (self *PreSharedKeyId) UnmarshalMLS(r *syntax.Reader) error {
	pskType, err := r.ReadUint8()
	if err != nil {
		return fmt.Errorf("mls: psk type: %w", err)
	}
	self.PskType = PskType(pskType)
	switch self.PskType {
	case PskTypeExternal:
		if self.PskId, err = r.ReadOpaque(); err != nil {
			return fmt.Errorf("mls: psk id: %w", err)
		}
	case PskTypeResumption:
		usage, err := r.ReadUint8()
		if err != nil {
			return fmt.Errorf("mls: psk usage: %w", err)
		}
		self.Usage = ResumptionPskUsage(usage)
		if self.PskGroupId, err = r.ReadOpaque(); err != nil {
			return fmt.Errorf("mls: psk group id: %w", err)
		}
		if self.PskEpoch, err = r.ReadUint64(); err != nil {
			return fmt.Errorf("mls: psk epoch: %w", err)
		}
	default:
		return ValSem(ValSem402, fmt.Errorf("%w: psktype %d", ErrPskType, self.PskType))
	}
	if self.PskNonce, err = r.ReadOpaque(); err != nil {
		return fmt.Errorf("mls: psk nonce: %w", err)
	}
	return nil
}

// the C1 pin: drift between this type and the one codec convention fails at build.
var _ syntax.Codec = (*PreSharedKeyId)(nil)

// Validate is ValSem401 (nonce length) and ValSem402 (type and usage). Both codes and
// both sentinels belong to the validation plan's catalogue; this returns them through
// ValSem so Gate 3 can assert the code and a caller can still match the sentinel.
func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error {
	if len(self.PskNonce) != crypto.HashSize() {
		return ValSem(ValSem401, fmt.Errorf("%w: %d bytes, want %d",
			ErrPskNonceLength, len(self.PskNonce), crypto.HashSize()))
	}
	switch self.PskType {
	case PskTypeExternal:
		return nil
	case PskTypeResumption:
		if self.Usage != ResumptionPskUsageApplication {
			return ValSem(ValSem402, fmt.Errorf("%w: resumption usage %d", ErrPskType, self.Usage))
		}
		return nil
	}
	return ValSem(ValSem402, fmt.Errorf("%w: psktype %d", ErrPskType, self.PskType))
}
```

The `crypto/subtle` and `math` imports are used by Task 14 and Task 15; add them when those tasks
land rather than leaving an unused import now.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestPreSharedKeyId -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/psk.go connect/mls/psk_test.go
git ls-files | wc -l
git commit -m "feat(mls): PreSharedKeyId codec and the ValSem401/402 checks"
```

---

### Task 14: CheckNoDuplicatePsks — ValSem403

**Files:**
- Modify: `connect/mls/psk.go`
- Test: `connect/mls/psk_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal(v syntax.Marshaler) ([]byte, error)` over `(*PreSharedKeyId).MarshalMLS`
  (Task 13), `ValSem(ValSem403, detail)` and p8's `ErrDuplicatePsk`, `crypto/subtle.ConstantTimeCompare`.
- Produces: `func CheckNoDuplicatePsks(ids []PreSharedKeyId) error`

  ValSem403 is untested in OpenMLS (openmls#1335), so differential agreement proves nothing here and
  the RFC text is the only authority.

  The four tests below are **behaviour-named, not `TestValSem403_*`**: p8 owns every
  `TestValSemNNN_<slug>` name exclusively (registry §9.5, Spec A §4.3), so its Gate 3 negative for
  this code and these unit tests cannot collide.

- [ ] **Step 1: Write the failing test**

```go
// append to psk_test.go

// pskTestId builds an external id with a distinguishable nonce.
func pskTestId(idByte byte, nonceByte byte) PreSharedKeyId {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = nonceByte
	}
	return PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte{idByte},
		PskNonce: nonce,
	}
}

// TestCheckNoDuplicatePsksRefusesARepeatedId asserts an exactly repeated id is refused.
func TestCheckNoDuplicatePsksRefusesARepeatedId(t *testing.T) {
	ids := []PreSharedKeyId{pskTestId(1, 0xa1), pskTestId(2, 0xa2), pskTestId(1, 0xa1)}
	if err := CheckNoDuplicatePsks(ids); !errors.Is(err, ErrDuplicatePsk) {
		t.Fatalf("err = %v, want ErrDuplicatePsk", err)
	}
}

// TestCheckNoDuplicatePsksAcceptsDistinctIds asserts the check does not over-reject. Two ids
// that share a psk_id but carry different nonces are different PreSharedKeyIDs by the
// RFC's own definition, and refusing them would be a V2 interop break.
func TestCheckNoDuplicatePsksAcceptsDistinctIds(t *testing.T) {
	ids := []PreSharedKeyId{pskTestId(1, 0xa1), pskTestId(1, 0xa2), pskTestId(2, 0xa1)}
	if err := CheckNoDuplicatePsks(ids); err != nil {
		t.Fatalf("distinct ids were refused: %v", err)
	}
}

// TestCheckNoDuplicatePsksAcceptsEmptyAndSingleton asserts the degenerate cases are accepted.
func TestCheckNoDuplicatePsksAcceptsEmptyAndSingleton(t *testing.T) {
	if err := CheckNoDuplicatePsks(nil); err != nil {
		t.Fatalf("empty list refused: %v", err)
	}
	if err := CheckNoDuplicatePsks([]PreSharedKeyId{pskTestId(1, 0xa1)}); err != nil {
		t.Fatalf("singleton refused: %v", err)
	}
}

// TestCheckNoDuplicatePsksBindsTheEpochField asserts the epoch field participates,
// so the same group id at two epochs is not a duplicate.
func TestCheckNoDuplicatePsksBindsTheEpochField(t *testing.T) {
	nonce := make([]byte, 32)
	first := PreSharedKeyId{PskType: PskTypeResumption, Usage: ResumptionPskUsageApplication, PskGroupId: []byte{9}, PskEpoch: 1, PskNonce: nonce}
	second := first
	second.PskEpoch = 2
	if err := CheckNoDuplicatePsks([]PreSharedKeyId{first, second}); err != nil {
		t.Fatalf("different epochs refused: %v", err)
	}
	if err := CheckNoDuplicatePsks([]PreSharedKeyId{first, first}); !errors.Is(err, ErrDuplicatePsk) {
		t.Fatalf("err = %v, want ErrDuplicatePsk", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestCheckNoDuplicatePsks -v`
Expected: FAIL to compile with `undefined: CheckNoDuplicatePsks`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to psk.go

// CheckNoDuplicatePsks is ValSem403. Duplication is decided over the full serialized
// PreSharedKeyID, nonce included, which is the RFC's literal definition: two ids that
// share a psk_id but differ in nonce are different ids. Comparing only the identity
// portion would be stricter than the RFC and would refuse something a V2 peer may
// legitimately send.
//
// Untested in OpenMLS (openmls#1335), so this is written against the spec text.
func CheckNoDuplicatePsks(ids []PreSharedKeyId) error {
	encoded := make([][]byte, 0, len(ids))
	for i := range ids {
		b, err := syntax.Marshal(&ids[i])
		if err != nil {
			return err
		}
		for j, previous := range encoded {
			if len(previous) == len(b) && subtle.ConstantTimeCompare(previous, b) == 1 {
				return ValSem(ValSem403, fmt.Errorf("%w: entries %d and %d", ErrDuplicatePsk, j, i))
			}
		}
		encoded = append(encoded, b)
	}
	return nil
}
```

Add `"crypto/subtle"` to the `psk.go` import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestCheckNoDuplicatePsks -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/psk.go connect/mls/psk_test.go
git ls-files | wc -l
git commit -m "feat(mls): ValSem403 duplicate PreSharedKeyID check, untested upstream"
```

---

### Task 15: PSKLabel, PskSecret and EmptyPskSecret

**Files:**
- Modify: `connect/mls/psk.go`
- Test: `connect/mls/psk_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Extract(salt []byte, ikm []byte) []byte`,
  `CryptoProvider.ExpandWithLabel`, `CryptoProvider.HashSize`, `syntax.NewWriter`,
  `(*syntax.Writer).WriteUint16(v uint16)`, `(*syntax.Writer).Bytes() ([]byte, error)`,
  `(*PreSharedKeyId).MarshalMLS` (Task 13), `ZeroSecret` (Task 5),
  `(*PreSharedKeyId).Validate` (Task 13), `CheckNoDuplicatePsks` (Task 14).
- Produces:
  ```go
  type PreSharedKeyInput struct {
      Id     PreSharedKeyId
      Secret []byte
  }
  func PskSecret(crypto CryptoProvider, psks []PreSharedKeyInput) ([]byte, error)
  func EmptyPskSecret(crypto CryptoProvider) []byte     // == PskSecret(crypto, nil)
  ```

  `EmptyPskSecret` is a registry gap p7 calls: every v1 epoch has no PSKs, so `NewGroup`,
  `Commit` and `JoinFromWelcome` all need the empty case and none of them wants to handle an error
  that cannot occur. It is the total form of `PskSecret(crypto, nil)` and the test below pins the
  two against each other so they can never drift.

- [ ] **Step 1: Write the failing test**

```go
// append to psk_test.go

const (
	pskVectorId0     = "c4e57766aa00414135b98e60b8e897896565af0f3d746c32d04dd4cda21d2299"
	pskVectorSecret0 = "4031689beb1bc9408e50f3ddbc04f7390e38afcbe88d8090c1a5a3e7469a8fc0"
	pskVectorNonce0  = "daeccb5a5522ee2578427727a6091194ad0d5a83ea4e0a9318ac27758d03574f"
	pskVectorId1     = "2ed6e6c554f046664d1e370fccbd64f6a9ba0f4163fd2785a8eb1bcf865e8b8e"
	pskVectorSecret1 = "787e4bfaf0f4f73624ae0f9f012e7cb554f4dfff31c8c57df7b091d4cd8be903"
	pskVectorNonce1  = "d3ae0fea4056bf88ff37ebd6efed07cdb41f2f306de9d88ac5762c2a245a8545"
	pskVectorSecret  = "4137e7535a749ef9c6055be84e2850168d64fddf843efc210e199701d088174b"
)

// TestPskSecretKAT pins the whole section 8.4 recurrence against the two-PSK vector:
// the "derived psk" label, the PSKLabel index and count fields, and the Extract
// argument order at each step. Every one of those is invisible to any test that does
// not compare against an independent implementation.
func TestPskSecretKAT(t *testing.T) {
	crypto := pskTestCrypto(t)
	psks := []PreSharedKeyInput{
		{
			Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: MustHex(t, pskVectorId0), PskNonce: MustHex(t, pskVectorNonce0)},
			Secret: MustHex(t, pskVectorSecret0),
		},
		{
			Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: MustHex(t, pskVectorId1), PskNonce: MustHex(t, pskVectorNonce1)},
			Secret: MustHex(t, pskVectorSecret1),
		},
	}
	got, err := PskSecret(crypto, psks)
	if err != nil {
		t.Fatalf("PskSecret: %v", err)
	}
	want := MustHex(t, pskVectorSecret)
	if !bytes.Equal(got, want) {
		t.Fatalf("psk_secret = %x, want %x", got, want)
	}
}

// TestPskSecretEmptyIsZero asserts the case every epoch actually takes: no PSKs gives
// KDF.Nh zero bytes, not a hash of nothing.
func TestPskSecretEmptyIsZero(t *testing.T) {
	crypto := pskTestCrypto(t)
	got, err := PskSecret(crypto, nil)
	if err != nil {
		t.Fatalf("PskSecret: %v", err)
	}
	if !bytes.Equal(got, make([]byte, crypto.HashSize())) {
		t.Fatalf("psk_secret = %x, want all zero", got)
	}
}

// TestEmptyPskSecretMatchesPskSecretOfNil pins the convenience form against the
// general one. The lifecycle plan calls EmptyPskSecret at every epoch boundary, so a
// divergence between the two would be a group whose members disagree from epoch 0 and
// whose only symptom is that nothing decrypts.
func TestEmptyPskSecretMatchesPskSecretOfNil(t *testing.T) {
	crypto := pskTestCrypto(t)
	general, err := PskSecret(crypto, nil)
	if err != nil {
		t.Fatalf("PskSecret: %v", err)
	}
	empty := EmptyPskSecret(crypto)
	if !bytes.Equal(empty, general) {
		t.Fatalf("EmptyPskSecret = %x, PskSecret(nil) = %x", empty, general)
	}
	if len(empty) != crypto.HashSize() {
		t.Fatalf("len = %d, want %d", len(empty), crypto.HashSize())
	}
	empty[0] = 1
	if EmptyPskSecret(crypto)[0] != 0 {
		t.Fatal("EmptyPskSecret returns a shared slice")
	}
}

// TestPskSecretOrderMatters asserts the index and count fields bind position, so a
// reordered list is a different psk_secret and a reordering attack is detectable.
func TestPskSecretOrderMatters(t *testing.T) {
	crypto := pskTestCrypto(t)
	first := PreSharedKeyInput{
		Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: MustHex(t, pskVectorId0), PskNonce: MustHex(t, pskVectorNonce0)},
		Secret: MustHex(t, pskVectorSecret0),
	}
	second := PreSharedKeyInput{
		Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: MustHex(t, pskVectorId1), PskNonce: MustHex(t, pskVectorNonce1)},
		Secret: MustHex(t, pskVectorSecret1),
	}
	forward, err := PskSecret(crypto, []PreSharedKeyInput{first, second})
	if err != nil {
		t.Fatalf("PskSecret: %v", err)
	}
	reversed, err := PskSecret(crypto, []PreSharedKeyInput{second, first})
	if err != nil {
		t.Fatalf("PskSecret: %v", err)
	}
	if bytes.Equal(forward, reversed) {
		t.Fatal("psk_secret is order independent, so PSKLabel.index is not bound")
	}
}

// TestPskSecretRejectsInvalidEntries asserts ValSem401, ValSem402 and ValSem403 all
// fire from inside the computation, so no caller can reach a psk_secret over an
// invalid list by skipping a separate validation step.
func TestPskSecretRejectsInvalidEntries(t *testing.T) {
	crypto := pskTestCrypto(t)
	base := PreSharedKeyInput{
		Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: MustHex(t, pskVectorId0), PskNonce: MustHex(t, pskVectorNonce0)},
		Secret: MustHex(t, pskVectorSecret0),
	}

	shortNonce := base
	shortNonce.Id.PskNonce = base.Id.PskNonce[:16]
	if _, err := PskSecret(crypto, []PreSharedKeyInput{shortNonce}); !errors.Is(err, ErrPskNonceLength) {
		t.Fatalf("short nonce err = %v, want ErrPskNonceLength", err)
	}

	badUsage := base
	badUsage.Id = PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageReInit,
		PskGroupId: []byte{1},
		PskNonce:   base.Id.PskNonce,
	}
	if _, err := PskSecret(crypto, []PreSharedKeyInput{badUsage}); !errors.Is(err, ErrPskType) {
		t.Fatalf("reinit usage err = %v, want ErrPskType", err)
	}

	if _, err := PskSecret(crypto, []PreSharedKeyInput{base, base}); !errors.Is(err, ErrDuplicatePsk) {
		t.Fatalf("duplicate err = %v, want ErrDuplicatePsk", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestPskSecret -v`
Expected: FAIL to compile with `undefined: PskSecret`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to psk.go

// PreSharedKeyInput pairs an id with the secret bytes it names.
type PreSharedKeyInput struct {
	Id     PreSharedKeyId
	Secret []byte
}

// marshalPskLabel encodes PSKLabel { PreSharedKeyID id; uint16 index; uint16 count; }.
// The id is written inline through its own MarshalMLS, with no length prefix of its
// own — which is why that method takes a writer rather than returning bytes.
func marshalPskLabel(id *PreSharedKeyId, index uint16, count uint16) ([]byte, error) {
	w := syntax.NewWriter()
	if err := id.MarshalMLS(w); err != nil {
		return nil, err
	}
	w.WriteUint16(index)
	w.WriteUint16(count)
	return w.Bytes()
}

// PskSecret is the RFC 9420 section 8.4 recurrence:
//
//	psk_extracted_[i] = KDF.Extract(0, psk_[i])
//	psk_input_[i]     = ExpandWithLabel(psk_extracted_[i], "derived psk", PSKLabel_[i], KDF.Nh)
//	psk_secret_[0]    = 0
//	psk_secret_[i]    = KDF.Extract(psk_input_[i-1], psk_secret_[i-1])
//
// with 0 the KDF.Nh all-zero string. Extract takes (salt, ikm): the zero string is
// the salt in the first line, and psk_input is the salt in the last.
func PskSecret(crypto CryptoProvider, psks []PreSharedKeyInput) ([]byte, error) {
	pskSecret := ZeroSecret(crypto)
	if len(psks) == 0 {
		return pskSecret, nil
	}
	if len(psks) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: %d", ErrPskCount, len(psks))
	}
	ids := make([]PreSharedKeyId, 0, len(psks))
	for i := range psks {
		ids = append(ids, psks[i].Id)
	}
	if err := CheckNoDuplicatePsks(ids); err != nil {
		return nil, err
	}
	count := uint16(len(psks))
	for i := range psks {
		if err := psks[i].Id.Validate(crypto); err != nil {
			return nil, fmt.Errorf("psk %d: %w", i, err)
		}
		label, err := marshalPskLabel(&psks[i].Id, uint16(i), count)
		if err != nil {
			return nil, err
		}
		zero := ZeroSecret(crypto)
		extracted := crypto.Extract(zero, psks[i].Secret)
		input := crypto.ExpandWithLabel(extracted, "derived psk", label, crypto.HashSize())
		next := crypto.Extract(input, pskSecret)
		zeroizeSecret(extracted)
		zeroizeSecret(input)
		zeroizeSecret(pskSecret)
		pskSecret = next
	}
	return pskSecret, nil
}

// EmptyPskSecret is psk_secret for an epoch with no PSKs: KDF.Nh zero bytes. It is
// PskSecret(crypto, nil) with the impossible error removed, because every v1 epoch
// takes this path and a caller that has to handle an error that cannot occur will
// eventually handle it wrongly.
func EmptyPskSecret(crypto CryptoProvider) []byte {
	return ZeroSecret(crypto)
}
```

Add `"math"` to the `psk.go` import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestPskSecret|TestEmptyPskSecret' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/psk.go connect/mls/psk_test.go
git ls-files | wc -l
git commit -m "feat(mls): psk_secret recurrence with PSKLabel index and count binding"
```

---

### Task 16: The suite filter, the psk_secret runner, and family registration

**Files:**
- Create: `connect/mls/key_schedule_kat_test.go`

**Interfaces:**
- Consumes: `PskSecret` (Task 15), `NewCryptoProvider`, and p8's vector surface —
  `LoadVectorFile(t *testing.T, file string) []json.RawMessage`,
  `MustHex(t *testing.T, s string) []byte`, `HexOf(b []byte) string`,
  `RegisterVectorFamily(family VectorFamily)` — over the `testdata/vectors/psk_secret.json` that
  p8 Task 6 vendored.
- Produces (test-only, used by Tasks 17, 18, 20, 25):
  ```go
  func implementedSuite(suite uint16) (CipherSuite, bool)
  ```

  `ksHex` and `ksLoadVectors` are **deleted**: p8 owns `MustHex`, `HexOf` and `LoadVectorFile`, they
  land in wave 1, and three parallel hex decoders over one corpus is how two of them end up
  disagreeing about the empty string (registry §9.2). Every hex field in every vector struct below is
  therefore a `string`, decoded with `MustHex` and re-encoded with `HexOf`. `ksImplementedSuite`
  survives under its registry name, `implementedSuite`.

  **Family registration is not optional.** Each of the four runners registers its family from an
  `init()` in its own `*_kat_test.go` and deletes its number from p8's `expectedPendingFamilies` in
  the same commit. Without that, `TestVectorFamiliesVerify` runs one family and Gate 1 is green with
  fifteen of sixteen never executed. This task registers family 6.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_kat_test.go
// runners for the mlswg key-schedule and psk_secret vector families.
package mls

import (
	"bytes"
	"encoding/json"
	"testing"
)

// implementedSuite maps a vector's cipher_suite to a provider we implement.
// The vector files cover suites 1 through 7; v1 implements 0x0001 and 0x0003, so the
// other five are skipped. Every runner counts what it ran and what it skipped, so a
// registry regression that made both suites unavailable fails instead of passing
// vacuously with zero cases.
func implementedSuite(suite uint16) (CipherSuite, bool) {
	switch CipherSuite(suite) {
	case CipherSuiteX25519AesGcm128Sha256Ed25519:
		return CipherSuiteX25519AesGcm128Sha256Ed25519, true
	case CipherSuiteX25519ChaCha20Sha256Ed25519:
		return CipherSuiteX25519ChaCha20Sha256Ed25519, true
	}
	return 0, false
}

// pskSecretVector is one entry of psk_secret.json. Binary fields are hex strings in
// the file and stay strings here; MustHex is the single decoder.
type pskSecretVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	Psks        []struct {
		PskId    string `json:"psk_id"`
		Psk      string `json:"psk"`
		PskNonce string `json:"psk_nonce"`
	} `json:"psks"`
	PskSecret string `json:"psk_secret"`
}

func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   6,
		Name:     "psk_secret",
		File:     "psk_secret.json",
		Slice:    "A2",
		Verify:   verifyPskSecretVector,
		Generate: nil, // the mlswg format for this family has no generate direction
	})
}

// verifyPskSecretVector checks one entry of psk_secret.json. A vector at a suite v1
// does not implement is a silent no-op here; the accounting in TestVectorPskSecret is
// what makes sure that is not every vector.
func verifyPskSecretVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var vector pskSecretVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse psk_secret entry: %v", err)
	}
	suite, ok := implementedSuite(vector.CipherSuite)
	if !ok {
		return
	}
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
	}
	psks := make([]PreSharedKeyInput, 0, len(vector.Psks))
	for _, entry := range vector.Psks {
		psks = append(psks, PreSharedKeyInput{
			Id: PreSharedKeyId{
				PskType:  PskTypeExternal,
				PskId:    MustHex(t, entry.PskId),
				PskNonce: MustHex(t, entry.PskNonce),
			},
			Secret: MustHex(t, entry.Psk),
		})
	}
	got, err := PskSecret(crypto, psks)
	if err != nil {
		t.Fatalf("%d psks: PskSecret: %v", len(psks), err)
	}
	if want := MustHex(t, vector.PskSecret); !bytes.Equal(got, want) {
		t.Fatalf("%d psks: psk_secret = %s, want %s", len(psks), HexOf(got), vector.PskSecret)
	}
}

// TestVectorPskSecret is vector family 6. Retained even though PSK proposals are
// profile-refused: psk_secret is computed on every epoch as the empty case, and the
// non-empty cases are the only check on the PSKLabel encoding.
func TestVectorPskSecret(t *testing.T) {
	entries := LoadVectorFile(t, "psk_secret.json")
	if len(entries) == 0 {
		t.Fatal("psk_secret.json is empty")
	}

	ran, skipped := 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, raw := range entries {
		var header struct {
			CipherSuite uint16 `json:"cipher_suite"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		suite, ok := implementedSuite(header.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		verifyPskSecretVector(t, raw)
		ran++
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no psk_secret vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AesGcm128Sha256Ed25519] == 0 {
		t.Fatal("no psk_secret vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20Sha256Ed25519] == 0 {
		t.Fatal("no psk_secret vector ran at ciphersuite 0x0003")
	}
	t.Logf("psk_secret: ran %d, skipped %d unimplemented suites", ran, skipped)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorPskSecret -v`
Expected: FAIL. Before Task 15 is merged, a compile error `undefined: PskSecret`; with Task 15 merged
this should pass on the first run — if it does not, the failure names the vector index and the psk
count, and the smallest failing count localizes the bug (count 0 is `ZeroSecret`, count 1 is the
`derived psk` label, count ≥ 2 is the recurrence).

- [ ] **Step 3: Write minimal implementation**

No production change. If Step 2 failed at count 1, the `psk_extracted` step has the Extract arguments
reversed; correct `PskSecret` in `psk.go` so the zero string is the salt.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestVectorPskSecret|TestVectorFamilies' -v`
Expected: PASS, with a log line reporting 22 vectors run and 55 skipped, and family 6 no longer
listed as pending by p8's registry test.

- [ ] **Step 5: Commit**

Delete `6` from p8's `expectedPendingFamilies` in the same commit, or the registry test stays green
while claiming this family is unimplemented.

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_kat_test.go connect/mls/vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): psk_secret vector family, registered, with per-suite coverage accounting"
```

---

### Task 17: The key-schedule vector runner

**Files:**
- Modify: `connect/mls/key_schedule_kat_test.go`

**Interfaces:**
- Consumes: `NewKeySchedule`, `(*KeySchedule).Export`, `(*KeySchedule).ExternalKeyPair`,
  `syntax.Marshal(v syntax.Marshaler) ([]byte, error)`, `LoadVectorFile`, `MustHex`, `HexOf`,
  `RegisterVectorFamily`, `implementedSuite` (Task 16).
- Produces: nothing at runtime. Registers family 5 and closes gate `key-schedule`.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_kat_test.go

// keyScheduleVector is one entry of key-schedule.json.
type keyScheduleVector struct {
	CipherSuite       uint16             `json:"cipher_suite"`
	GroupId           string             `json:"group_id"`
	InitialInitSecret string             `json:"initial_init_secret"`
	Epochs            []keyScheduleEpoch `json:"epochs"`
}

// keyScheduleEpoch is one epoch of a key-schedule vector.
type keyScheduleEpoch struct {
	TreeHash                string `json:"tree_hash"`
	CommitSecret            string `json:"commit_secret"`
	PskSecret               string `json:"psk_secret"`
	ConfirmedTranscriptHash string `json:"confirmed_transcript_hash"`
	GroupContext            string `json:"group_context"`
	JoinerSecret            string `json:"joiner_secret"`
	WelcomeSecret           string `json:"welcome_secret"`
	InitSecret              string `json:"init_secret"`
	SenderDataSecret        string `json:"sender_data_secret"`
	EncryptionSecret        string `json:"encryption_secret"`
	ExporterSecret          string `json:"exporter_secret"`
	EpochAuthenticator      string `json:"epoch_authenticator"`
	ExternalSecret          string `json:"external_secret"`
	ConfirmationKey         string `json:"confirmation_key"`
	MembershipKey           string `json:"membership_key"`
	ResumptionPsk           string `json:"resumption_psk"`
	ExternalPub             string `json:"external_pub"`
	Exporter                struct {
		// label is a string in the mlswg format while every sibling field is hex.
		// It is NOT hex-decoded; see Task 8.
		Label   string `json:"label"`
		Context string `json:"context"`
		Length  int    `json:"length"`
		Secret  string `json:"secret"`
	} `json:"exporter"`
}

func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   5,
		Name:     "key-schedule",
		File:     "key-schedule.json",
		Slice:    "A2",
		Verify:   verifyKeyScheduleVector,
		Generate: generateKeyScheduleVector,
	})
}

// verifyKeyScheduleVector checks one entry of key-schedule.json. The chain is carried
// forward with OUR init_secret rather than re-seeded from the vector at each epoch, so
// a divergence surfaces at the epoch that caused it instead of being masked by the
// next reseed.
func verifyKeyScheduleVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var vector keyScheduleVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse key-schedule entry: %v", err)
	}
	suite, ok := implementedSuite(vector.CipherSuite)
	if !ok {
		return
	}
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
	}

	initSecret := MustHex(t, vector.InitialInitSecret)
	for n, epoch := range vector.Epochs {
		groupContext := &GroupContext{
			Version:                 ProtocolVersionMls10,
			CipherSuite:             suite,
			GroupId:                 MustHex(t, vector.GroupId),
			Epoch:                   uint64(n),
			TreeHash:                MustHex(t, epoch.TreeHash),
			ConfirmedTranscriptHash: MustHex(t, epoch.ConfirmedTranscriptHash),
			Extensions:              nil,
		}
		encoded, err := syntax.Marshal(groupContext)
		if err != nil {
			t.Fatalf("epoch %d: syntax.Marshal: %v", n, err)
		}
		if !bytes.Equal(encoded, MustHex(t, epoch.GroupContext)) {
			t.Fatalf("epoch %d: group_context = %s, want %s", n, HexOf(encoded), epoch.GroupContext)
		}

		schedule, err := NewKeySchedule(
			crypto, initSecret, MustHex(t, epoch.CommitSecret), MustHex(t, epoch.PskSecret), groupContext)
		if err != nil {
			t.Fatalf("epoch %d: NewKeySchedule: %v", n, err)
		}
		secrets := schedule.Secrets()
		for _, check := range []struct {
			name string
			got  []byte
			want string
		}{
			{"joiner_secret", schedule.JoinerSecret(), epoch.JoinerSecret},
			{"welcome_secret", schedule.WelcomeSecret(), epoch.WelcomeSecret},
			{"sender_data_secret", secrets.SenderData, epoch.SenderDataSecret},
			{"encryption_secret", secrets.Encryption, epoch.EncryptionSecret},
			{"exporter_secret", secrets.Exporter, epoch.ExporterSecret},
			{"external_secret", secrets.External, epoch.ExternalSecret},
			{"confirmation_key", secrets.Confirmation, epoch.ConfirmationKey},
			{"membership_key", secrets.Membership, epoch.MembershipKey},
			{"resumption_psk", secrets.ResumptionPsk, epoch.ResumptionPsk},
			{"epoch_authenticator", secrets.EpochAuthenticator, epoch.EpochAuthenticator},
			{"init_secret", secrets.InitSecret, epoch.InitSecret},
		} {
			if !bytes.Equal(check.got, MustHex(t, check.want)) {
				t.Fatalf("epoch %d: %s = %s, want %s", n, check.name, HexOf(check.got), check.want)
			}
		}

		// HpkePublicKey is a []byte, so external_pub compares directly.
		_, externalPub, err := schedule.ExternalKeyPair()
		if err != nil {
			t.Fatalf("epoch %d: ExternalKeyPair: %v", n, err)
		}
		if !bytes.Equal(externalPub, MustHex(t, epoch.ExternalPub)) {
			t.Fatalf("epoch %d: external_pub = %s, want %s", n, HexOf(externalPub), epoch.ExternalPub)
		}

		exported, err := schedule.Export(
			epoch.Exporter.Label, MustHex(t, epoch.Exporter.Context), epoch.Exporter.Length)
		if err != nil {
			t.Fatalf("epoch %d: Export: %v", n, err)
		}
		if !bytes.Equal(exported, MustHex(t, epoch.Exporter.Secret)) {
			t.Fatalf("epoch %d: exporter = %s, want %s", n, HexOf(exported), epoch.Exporter.Secret)
		}

		// carry our own init_secret forward, not the vector's
		initSecret = append([]byte(nil), secrets.InitSecret...)
	}
}

// TestVectorKeySchedule is vector family 5.
func TestVectorKeySchedule(t *testing.T) {
	entries := LoadVectorFile(t, "key-schedule.json")
	if len(entries) == 0 {
		t.Fatal("key-schedule.json is empty")
	}

	ran, skipped, epochs := 0, 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, raw := range entries {
		var vector keyScheduleVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		suite, ok := implementedSuite(vector.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		verifyKeyScheduleVector(t, raw)
		ran++
		epochs += len(vector.Epochs)
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no key-schedule vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AesGcm128Sha256Ed25519] == 0 {
		t.Fatal("no key-schedule vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20Sha256Ed25519] == 0 {
		t.Fatal("no key-schedule vector ran at ciphersuite 0x0003")
	}
	t.Logf("key-schedule: ran %d vectors covering %d epochs, skipped %d unimplemented suites", ran, epochs, skipped)
}
```

Add `"github.com/urnetwork/connect/mls/syntax"` to the `key_schedule_kat_test.go` import block.
`generateKeyScheduleVector` lands in Task 18; write the two tasks as one commit, or register
`Generate: nil` here and change it there.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorKeySchedule -v`
Expected: PASS if Tasks 3–9 are correct. If it FAILs, the message names the vector, the epoch and the
first secret that diverged. `group_context` failing first means the codec, not the schedule.

- [ ] **Step 3: Write minimal implementation**

No production change expected. If the exporter check is the only failure, the label is being
hex-decoded somewhere — the field is a string, and Task 8's `TestKeyScheduleExportLabelIsNotHexDecoded`
is the unit-level version of the same assertion.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestVectorKeySchedule|TestVectorFamilies' -v`
Expected: PASS, with a log line reporting 2 vectors covering 10 epochs and 5 skipped suites.

- [ ] **Step 5: Commit**

Delete `5` from p8's `expectedPendingFamilies` in the same commit.

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_kat_test.go connect/mls/vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): key-schedule vector family, registered, chained on our own init_secret"
```

---

### Task 18: The generate direction, verified through an independent KDFLabel encoder

**Files:**
- Modify: `connect/mls/key_schedule_kat_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Expand(prk []byte, info []byte, length int) []byte`,
  `CryptoProvider.Extract(salt []byte, ikm []byte) []byte`, `CryptoProvider.Random(n int) []byte`,
  `syntax.Marshal`, `HexOf`, `MustHex`, `NewKeySchedule`.
- Produces: `func generateKeyScheduleVector(t *testing.T) json.RawMessage`, the `Generate` half of
  the family 5 registration. Satisfies Spec A section 4.2.1's "both directions" requirement.

  The independent path is a second KDFLabel encoder written in the test file with
  `encoding/binary` and a hand-written MLS varint, so a bug where `ExpandWithLabel` and the vector
  reader agree on a wrong encoding is visible. Verification against the vendored file alone cannot
  see that class, because the vector never round-trips through our encoder.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_kat_test.go

// ksIndependentVarint writes the MLS variable-length prefix by hand. Deliberately
// not the syntax package: this is the second implementation.
func ksIndependentVarint(t *testing.T, n int) []byte {
	t.Helper()
	switch {
	case n < 1<<6:
		return []byte{byte(n)}
	case n < 1<<14:
		return []byte{byte(0x40 | (n >> 8)), byte(n)}
	case n < 1<<30:
		return []byte{byte(0x80 | (n >> 24)), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	t.Fatalf("length %d does not fit an MLS varint", n)
	return nil
}

// ksIndependentExpandWithLabel is a second implementation of RFC 9420's
// ExpandWithLabel, built from crypto.Expand and a hand-encoded KDFLabel.
func ksIndependentExpandWithLabel(t *testing.T, crypto CryptoProvider, secret []byte, label string, context []byte, length int) []byte {
	t.Helper()
	full := "MLS 1.0 " + label
	var kdfLabel []byte
	kdfLabel = binary.BigEndian.AppendUint16(kdfLabel, uint16(length))
	kdfLabel = append(kdfLabel, ksIndependentVarint(t, len(full))...)
	kdfLabel = append(kdfLabel, full...)
	kdfLabel = append(kdfLabel, ksIndependentVarint(t, len(context))...)
	kdfLabel = append(kdfLabel, context...)
	return crypto.Expand(secret, kdfLabel, length)
}

// ksIndependentDeriveSecret mirrors DeriveSecret through the independent encoder.
func ksIndependentDeriveSecret(t *testing.T, crypto CryptoProvider, secret []byte, label string) []byte {
	t.Helper()
	return ksIndependentExpandWithLabel(t, crypto, secret, label, nil, crypto.HashSize())
}

// generateKeyScheduleVector is the Generate half of family 5: build fresh epochs from
// random inputs at both implemented suites and emit them in the mlswg format. It is
// registered on the family so p8's generate pass and this test drive one code path.
func generateKeyScheduleVector(t *testing.T) json.RawMessage {
	t.Helper()
	vectors := []keyScheduleVector{}
	for _, suite := range []CipherSuite{
		CipherSuiteX25519AesGcm128Sha256Ed25519,
		CipherSuiteX25519ChaCha20Sha256Ed25519,
	} {
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
		}
		nh := crypto.HashSize()
		groupId := crypto.Random(16)
		initSecret := crypto.Random(nh)
		vector := keyScheduleVector{
			CipherSuite:       uint16(suite),
			GroupId:           HexOf(groupId),
			InitialInitSecret: HexOf(initSecret),
		}
		for n := 0; n < 3; n++ {
			treeHash := crypto.Random(nh)
			commitSecret := crypto.Random(nh)
			pskSecret := crypto.Random(nh)
			confirmedTranscriptHash := crypto.Random(nh)
			groupContext := &GroupContext{
				Version:                 ProtocolVersionMls10,
				CipherSuite:             suite,
				GroupId:                 groupId,
				Epoch:                   uint64(n),
				TreeHash:                treeHash,
				ConfirmedTranscriptHash: confirmedTranscriptHash,
			}
			encoded, err := syntax.Marshal(groupContext)
			if err != nil {
				t.Fatalf("syntax.Marshal: %v", err)
			}
			schedule, err := NewKeySchedule(crypto, initSecret, commitSecret, pskSecret, groupContext)
			if err != nil {
				t.Fatalf("NewKeySchedule: %v", err)
			}
			secrets := schedule.Secrets()
			epoch := keyScheduleEpoch{
				TreeHash:                HexOf(treeHash),
				CommitSecret:            HexOf(commitSecret),
				PskSecret:               HexOf(pskSecret),
				ConfirmedTranscriptHash: HexOf(confirmedTranscriptHash),
				GroupContext:            HexOf(encoded),
				JoinerSecret:            HexOf(schedule.JoinerSecret()),
				WelcomeSecret:           HexOf(schedule.WelcomeSecret()),
				SenderDataSecret:        HexOf(secrets.SenderData),
				EncryptionSecret:        HexOf(secrets.Encryption),
				ExporterSecret:          HexOf(secrets.Exporter),
				ExternalSecret:          HexOf(secrets.External),
				ConfirmationKey:         HexOf(secrets.Confirmation),
				MembershipKey:           HexOf(secrets.Membership),
				ResumptionPsk:           HexOf(secrets.ResumptionPsk),
				EpochAuthenticator:      HexOf(secrets.EpochAuthenticator),
				InitSecret:              HexOf(secrets.InitSecret),
			}
			vector.Epochs = append(vector.Epochs, epoch)
			initSecret = append([]byte(nil), secrets.InitSecret...)
		}
		vectors = append(vectors, vector)
	}
	serialized, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return json.RawMessage(serialized)
}

// TestVectorKeyScheduleGenerate is the generate direction of family 5: build a fresh
// epoch from random inputs, serialize it in the mlswg format, read it back, and verify
// it through a second KDFLabel encoder. If our ExpandWithLabel encodes the label
// wrongly, the two paths disagree here even though the vendored vector passes.
func TestVectorKeyScheduleGenerate(t *testing.T) {
	serialized := generateKeyScheduleVector(t)
	var readBack []keyScheduleVector
	if err := json.Unmarshal(serialized, &readBack); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(readBack) != 2 {
		t.Fatalf("generated %d suites, want 2", len(readBack))
	}

	for _, vector := range readBack {
		suite, ok := implementedSuite(vector.CipherSuite)
		if !ok {
			t.Fatalf("generated a vector at unimplemented suite %#x", vector.CipherSuite)
		}
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
		}
		nh := crypto.HashSize()
		if len(vector.Epochs) != 3 {
			t.Fatalf("suite %#x: round trip lost epochs: %d", suite, len(vector.Epochs))
		}

		// verify through the independent encoder
		independentInit := MustHex(t, vector.InitialInitSecret)
		for n, epoch := range vector.Epochs {
			groupContext := MustHex(t, epoch.GroupContext)
			prk := crypto.Extract(independentInit, MustHex(t, epoch.CommitSecret))
			joiner := ksIndependentExpandWithLabel(t, crypto, prk, "joiner", groupContext, nh)
			if !bytes.Equal(joiner, MustHex(t, epoch.JoinerSecret)) {
				t.Fatalf("suite %#x epoch %d: independent joiner_secret = %s, want %s",
					suite, n, HexOf(joiner), epoch.JoinerSecret)
			}
			member := crypto.Extract(joiner, MustHex(t, epoch.PskSecret))
			welcome := ksIndependentDeriveSecret(t, crypto, member, "welcome")
			if !bytes.Equal(welcome, MustHex(t, epoch.WelcomeSecret)) {
				t.Fatalf("suite %#x epoch %d: independent welcome_secret = %s, want %s",
					suite, n, HexOf(welcome), epoch.WelcomeSecret)
			}
			epochSecret := ksIndependentExpandWithLabel(t, crypto, member, "epoch", groupContext, nh)
			for _, check := range []struct {
				label string
				want  string
			}{
				{"sender data", epoch.SenderDataSecret},
				{"encryption", epoch.EncryptionSecret},
				{"exporter", epoch.ExporterSecret},
				{"external", epoch.ExternalSecret},
				{"confirm", epoch.ConfirmationKey},
				{"membership", epoch.MembershipKey},
				{"resumption", epoch.ResumptionPsk},
				{"authentication", epoch.EpochAuthenticator},
				{"init", epoch.InitSecret},
			} {
				got := ksIndependentDeriveSecret(t, crypto, epochSecret, check.label)
				if !bytes.Equal(got, MustHex(t, check.want)) {
					t.Fatalf("suite %#x epoch %d: independent %q = %s, want %s",
						suite, n, check.label, HexOf(got), check.want)
				}
			}
			independentInit = MustHex(t, epoch.InitSecret)
		}
	}

	if out := os.Getenv("URMESSAGE_MLS_VECTOR_OUT"); out != "" {
		path := filepath.Join(out, "key-schedule-generated.json")
		if err := os.WriteFile(path, serialized, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s for the OpenMLS cross-check job", path)
	}
}
```

Add `"encoding/binary"`, `"os"` and `"path/filepath"` to the `key_schedule_kat_test.go` import
block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorKeyScheduleGenerate -v`
Expected: FAIL to compile with `undefined: ksIndependentExpandWithLabel` before Step 1 is saved; after
saving, it should pass. A failure at `independent joiner_secret` means `CryptoProvider.ExpandWithLabel`
and this hand encoder disagree, and the vendored vector passing does not settle which is wrong — check
the KDFLabel layout against RFC 9420 section 8 before changing either.

- [ ] **Step 3: Write minimal implementation**

No production change expected.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestVectorKeyScheduleGenerate -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_kat_test.go
git ls-files | wc -l
git commit -m "test(mls): key-schedule generate direction with a second KDFLabel encoder"
```

---

### Task 19: Transcript hashes

**Files:**
- Create: `connect/mls/transcript.go`
- Test: `connect/mls/transcript_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Hash(data []byte) []byte`, `CryptoProvider.HashSize() int`,
  `syntax.NewWriter() *syntax.Writer`, `(*syntax.Writer).WriteOpaque(bs []byte)` — which returns
  nothing under **C2** — and `(*syntax.Writer).Bytes() ([]byte, error)`.
- Produces:
  ```go
  type TranscriptHashes struct {
      Confirmed []byte
      Interim   []byte
  }
  func InitialTranscriptHashes() *TranscriptHashes
  func (self *TranscriptHashes) Clone() *TranscriptHashes
  func (self *TranscriptHashes) Update(crypto CryptoProvider, confirmedTranscriptHashInput []byte, confirmationTag []byte) error
  func (self *TranscriptHashes) SetFromGroupInfo(crypto CryptoProvider, confirmedTranscriptHash []byte, confirmationTag []byte) error
  func ConfirmedTranscriptHash(crypto CryptoProvider, interimBefore []byte, confirmedTranscriptHashInput []byte) []byte
  func InterimTranscriptHash(crypto CryptoProvider, confirmedAfter []byte, confirmationTag []byte) ([]byte, error)
  ```

  **Boundary note for p6 and p7.** `confirmedTranscriptHashInput` is the serialized
  `ConfirmedTranscriptHashInput { WireFormat wire_format; FramedContent content; opaque signature<V>; }`.
  These functions take it as bytes deliberately, so no framing type crosses into `transcript.go` and
  the transcript arithmetic can be audited on its own. p7 bridges with
  `ConfirmedTranscriptHash(crypto, interimBefore, authContent.ConfirmedTranscriptHashInput())` —
  p6's accessor, registry §7.2 — and passes the confirmation tag it computed from
  `(*KeySchedule).ConfirmationTag`. These four functions are **this plan's, not p6's**: p7's draft
  attributed them to the framing plan and passed an `*AuthenticatedContent`; the registry puts them
  here, at the byte-taking signatures above.

- [ ] **Step 1: Write the failing test**

```go
// transcript_test.go
// tests for the RFC 9420 section 8.2 transcript hashes.
package mls

import (
	"bytes"
	"errors"
	"testing"
)

// trTestCrypto returns the ciphersuite 0x0003 provider.
func trTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

// TestInitialTranscriptHashesAreEmpty asserts the group-creation base case: both
// hashes are the zero-length octet string, not a hash of nothing.
func TestInitialTranscriptHashesAreEmpty(t *testing.T) {
	hashes := InitialTranscriptHashes()
	if len(hashes.Confirmed) != 0 {
		t.Fatalf("Confirmed = %x, want empty", hashes.Confirmed)
	}
	if len(hashes.Interim) != 0 {
		t.Fatalf("Interim = %x, want empty", hashes.Interim)
	}
}

// TestConfirmedTranscriptHashShape asserts the confirmed hash is
// Hash(interim_before || ConfirmedTranscriptHashInput) with no length prefix between
// the two, which is what makes the chain a transcript rather than a set.
func TestConfirmedTranscriptHashShape(t *testing.T) {
	crypto := trTestCrypto(t)
	interimBefore := crypto.Hash([]byte("previous epoch"))
	input := []byte("serialized ConfirmedTranscriptHashInput")
	got := ConfirmedTranscriptHash(crypto, interimBefore, input)
	want := crypto.Hash(append(append([]byte(nil), interimBefore...), input...))
	if !bytes.Equal(got, want) {
		t.Fatalf("ConfirmedTranscriptHash = %x, want %x", got, want)
	}
}

// TestInterimTranscriptHashLengthPrefixesTheTag asserts the confirmation tag enters
// the hash as InterimTranscriptHashInput { MAC confirmation_tag; }, which is an
// opaque<V>. Concatenating the raw tag instead would agree with itself on both sides
// and diverge from every other implementation.
func TestInterimTranscriptHashLengthPrefixesTheTag(t *testing.T) {
	crypto := trTestCrypto(t)
	confirmedAfter := crypto.Hash([]byte("confirmed"))
	tag := crypto.Mac(make([]byte, 32), confirmedAfter)

	got, err := InterimTranscriptHash(crypto, confirmedAfter, tag)
	if err != nil {
		t.Fatalf("InterimTranscriptHash: %v", err)
	}
	withPrefix := append([]byte(nil), confirmedAfter...)
	withPrefix = append(withPrefix, byte(len(tag)))
	withPrefix = append(withPrefix, tag...)
	if !bytes.Equal(got, crypto.Hash(withPrefix)) {
		t.Fatalf("InterimTranscriptHash = %x, want the length-prefixed form", got)
	}
	raw := append(append([]byte(nil), confirmedAfter...), tag...)
	if bytes.Equal(got, crypto.Hash(raw)) {
		t.Fatal("the confirmation tag is being concatenated without its length prefix")
	}
}

// TestTranscriptHashesUpdateChains asserts two commits produce a chain in which the
// second confirmed hash depends on the first interim hash, which is the property that
// makes a fork detectable.
func TestTranscriptHashesUpdateChains(t *testing.T) {
	crypto := trTestCrypto(t)
	hashes := InitialTranscriptHashes()
	firstTag := crypto.Mac(make([]byte, 32), []byte("one"))
	if err := hashes.Update(crypto, []byte("commit one"), firstTag); err != nil {
		t.Fatalf("Update: %v", err)
	}
	afterFirst := hashes.Clone()
	secondTag := crypto.Mac(make([]byte, 32), []byte("two"))
	if err := hashes.Update(crypto, []byte("commit two"), secondTag); err != nil {
		t.Fatalf("Update: %v", err)
	}

	want := ConfirmedTranscriptHash(crypto, afterFirst.Interim, []byte("commit two"))
	if !bytes.Equal(hashes.Confirmed, want) {
		t.Fatalf("second confirmed hash does not chain from the first interim hash")
	}

	forked := afterFirst.Clone()
	if err := forked.Update(crypto, []byte("commit two prime"), secondTag); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if bytes.Equal(forked.Confirmed, hashes.Confirmed) {
		t.Fatal("two different commits produced the same confirmed transcript hash")
	}
}

// TestTranscriptHashesCloneIsDeep asserts a retained past epoch cannot be mutated.
func TestTranscriptHashesCloneIsDeep(t *testing.T) {
	crypto := trTestCrypto(t)
	hashes := InitialTranscriptHashes()
	if err := hashes.Update(crypto, []byte("commit"), crypto.Mac(make([]byte, 32), nil)); err != nil {
		t.Fatalf("Update: %v", err)
	}
	clone := hashes.Clone()
	clone.Confirmed[0] ^= 0xff
	clone.Interim[0] ^= 0xff
	if bytes.Equal(clone.Confirmed, hashes.Confirmed) {
		t.Fatal("Confirmed is shared")
	}
	if bytes.Equal(clone.Interim, hashes.Interim) {
		t.Fatal("Interim is shared")
	}
}

// TestSetFromGroupInfoSeedsAJoiner asserts a member added by Welcome reaches the same
// interim hash the existing members hold, which it must to process the next commit.
func TestSetFromGroupInfoSeedsAJoiner(t *testing.T) {
	crypto := trTestCrypto(t)
	member := InitialTranscriptHashes()
	tag := crypto.Mac(make([]byte, 32), []byte("epoch one"))
	if err := member.Update(crypto, []byte("commit one"), tag); err != nil {
		t.Fatalf("Update: %v", err)
	}

	joiner := InitialTranscriptHashes()
	if err := joiner.SetFromGroupInfo(crypto, member.Confirmed, tag); err != nil {
		t.Fatalf("SetFromGroupInfo: %v", err)
	}
	if !bytes.Equal(joiner.Confirmed, member.Confirmed) {
		t.Fatal("joiner confirmed hash differs")
	}
	if !bytes.Equal(joiner.Interim, member.Interim) {
		t.Fatal("joiner interim hash differs")
	}
}

// TestSetFromGroupInfoRejectsWrongLengths asserts a malformed GroupInfo is refused
// rather than seeding a member with a hash no peer agrees with.
func TestSetFromGroupInfoRejectsWrongLengths(t *testing.T) {
	crypto := trTestCrypto(t)
	joiner := InitialTranscriptHashes()
	if err := joiner.SetFromGroupInfo(crypto, make([]byte, 31), make([]byte, 32)); !errors.Is(err, ErrTranscriptHashLength) {
		t.Fatalf("short confirmed hash err = %v, want ErrTranscriptHashLength", err)
	}
	if err := joiner.SetFromGroupInfo(crypto, make([]byte, 32), nil); !errors.Is(err, ErrTranscriptHashLength) {
		t.Fatalf("empty tag err = %v, want ErrTranscriptHashLength", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestInitialTranscriptHashes|TestConfirmedTranscriptHash|TestInterimTranscriptHash|TestTranscriptHashes|TestSetFromGroupInfo' -v`
Expected: FAIL to compile with `undefined: InitialTranscriptHashes`.

- [ ] **Step 3: Write minimal implementation**

```go
// transcript.go
// the RFC 9420 section 8.2 confirmed and interim transcript hashes.
//
// The transcript is what makes a fork visible: two members who applied different
// commits hold different confirmed hashes, so their confirmation tags differ and the
// next commit each sends is rejected by the other.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// TranscriptHashes is the pair a group carries across epochs.
type TranscriptHashes struct {
	Confirmed []byte
	Interim   []byte
}

// InitialTranscriptHashes is the group-creation base case: both hashes are the
// zero-length octet string. The creator's own epoch-0 confirmation tag is folded in
// by SetFromGroupInfo or by the first Update, depending on which side it is.
func InitialTranscriptHashes() *TranscriptHashes {
	return &TranscriptHashes{
		Confirmed: []byte{},
		Interim:   []byte{},
	}
}

// Clone returns a deep copy so a retained past epoch cannot alias the live one.
func (self *TranscriptHashes) Clone() *TranscriptHashes {
	return &TranscriptHashes{
		Confirmed: append([]byte(nil), self.Confirmed...),
		Interim:   append([]byte(nil), self.Interim...),
	}
}

// ConfirmedTranscriptHash is
// Hash(interim_transcript_hash_[n-1] || ConfirmedTranscriptHashInput_[n]).
// The caller supplies the serialized input; this package never sees framing types.
func ConfirmedTranscriptHash(crypto CryptoProvider, interimBefore []byte, confirmedTranscriptHashInput []byte) []byte {
	buffer := make([]byte, 0, len(interimBefore)+len(confirmedTranscriptHashInput))
	buffer = append(buffer, interimBefore...)
	buffer = append(buffer, confirmedTranscriptHashInput...)
	return crypto.Hash(buffer)
}

// InterimTranscriptHash is
// Hash(confirmed_transcript_hash_[n] || InterimTranscriptHashInput_[n]),
// where InterimTranscriptHashInput is the single field MAC confirmation_tag, and a
// MAC is an opaque<V>. The length prefix is not optional.
func InterimTranscriptHash(crypto CryptoProvider, confirmedAfter []byte, confirmationTag []byte) ([]byte, error) {
	w := syntax.NewWriter()
	w.WriteOpaque(confirmationTag)
	input, err := w.Bytes()
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 0, len(confirmedAfter)+len(input))
	buffer = append(buffer, confirmedAfter...)
	buffer = append(buffer, input...)
	return crypto.Hash(buffer), nil
}

// Update advances both hashes for one commit.
func (self *TranscriptHashes) Update(crypto CryptoProvider, confirmedTranscriptHashInput []byte, confirmationTag []byte) error {
	confirmed := ConfirmedTranscriptHash(crypto, self.Interim, confirmedTranscriptHashInput)
	interim, err := InterimTranscriptHash(crypto, confirmed, confirmationTag)
	if err != nil {
		return err
	}
	self.Confirmed = confirmed
	self.Interim = interim
	return nil
}

// SetFromGroupInfo seeds a joiner from the GroupContext and confirmation tag carried
// in a Welcome's GroupInfo. Without this a new member holds no interim hash and
// cannot compute the confirmed hash of the next commit.
func (self *TranscriptHashes) SetFromGroupInfo(crypto CryptoProvider, confirmedTranscriptHash []byte, confirmationTag []byte) error {
	nh := crypto.HashSize()
	if len(confirmedTranscriptHash) != nh {
		return fmt.Errorf("%w: confirmed transcript hash is %d bytes, want %d",
			ErrTranscriptHashLength, len(confirmedTranscriptHash), nh)
	}
	if len(confirmationTag) != nh {
		return fmt.Errorf("%w: confirmation tag is %d bytes, want %d",
			ErrTranscriptHashLength, len(confirmationTag), nh)
	}
	interim, err := InterimTranscriptHash(crypto, confirmedTranscriptHash, confirmationTag)
	if err != nil {
		return err
	}
	self.Confirmed = append([]byte(nil), confirmedTranscriptHash...)
	self.Interim = interim
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestInitialTranscriptHashes|TestConfirmedTranscriptHash|TestInterimTranscriptHash|TestTranscriptHashes|TestSetFromGroupInfo' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/transcript.go connect/mls/transcript_test.go
git ls-files | wc -l
git commit -m "feat(mls): confirmed and interim transcript hash chaining"
```

---

### Task 20: The transcript-hashes vector runner

**Files:**
- Create: `connect/mls/transcript_kat_test.go`

**Interfaces:**
- Consumes: `ConfirmedTranscriptHash`, `InterimTranscriptHash` (Task 19), `LoadVectorFile`,
  `MustHex`, `HexOf`, `RegisterVectorFamily`, `implementedSuite` (Task 16),
  `CryptoProvider.MacVerify(key []byte, data []byte, tag []byte) bool`.
- Produces: nothing at runtime. Registers family 7 and closes gate `transcript-hashes`.

  The vector supplies a serialized `AuthenticatedContent`. For a commit that is
  `wire_format || FramedContent || signature || confirmation_tag`, so
  `ConfirmedTranscriptHashInput` is the prefix and `InterimTranscriptHashInput` is the trailing
  `opaque<V>` MAC. The split is taken at `len(ac) - (1 + KDF.Nh)` and then **checked**: the recovered
  tag must verify as `MAC(confirmation_key, confirmed_transcript_hash_after)`, which is the vector's
  own stated verification step. A wrong split fails that MAC, so the split is self-validating rather
  than assumed. When p6 lands `(*AuthenticatedContent).UnmarshalMLS`, this helper is replaced by
  `syntax.Unmarshal(raw, &authContent)` plus `authContent.ConfirmedTranscriptHashInput()` — both
  registry §7.2 — and the MAC check stays.

- [ ] **Step 1: Write the failing test**

```go
// transcript_kat_test.go
// runner for the mlswg transcript-hashes vector family.
package mls

import (
	"bytes"
	"encoding/json"
	"testing"
)

// transcriptHashVector is one entry of transcript-hashes.json.
type transcriptHashVector struct {
	CipherSuite                  uint16 `json:"cipher_suite"`
	ConfirmationKey              string `json:"confirmation_key"`
	AuthenticatedContent         string `json:"authenticated_content"`
	InterimTranscriptHashBefore  string `json:"interim_transcript_hash_before"`
	ConfirmedTranscriptHashAfter string `json:"confirmed_transcript_hash_after"`
	InterimTranscriptHashAfter   string `json:"interim_transcript_hash_after"`
}

func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   7,
		Name:     "transcript-hashes",
		File:     "transcript-hashes.json",
		Slice:    "A2",
		Verify:   verifyTranscriptHashVector,
		Generate: nil, // this family has no generate direction in the mlswg format
	})
}

// trSplitCommitAuthenticatedContent splits a serialized AuthenticatedContent carrying
// a Commit into its ConfirmedTranscriptHashInput prefix and its confirmation tag.
//
// For a commit the last field of FramedContentAuthData is the confirmation_tag, a MAC,
// which serializes as an opaque<V> of exactly KDF.Nh bytes. For every suite this build
// implements KDF.Nh is 32, so the prefix is one byte and the suffix is 33 bytes. The
// caller checks the recovered tag against the confirmation key, so a wrong split is a
// test failure rather than a silently different answer.
func trSplitCommitAuthenticatedContent(t *testing.T, crypto CryptoProvider, authenticatedContent []byte) (confirmedInput []byte, confirmationTag []byte) {
	t.Helper()
	nh := crypto.HashSize()
	if nh >= 64 {
		t.Fatalf("KDF.Nh is %d; the one-byte varint assumption in this split no longer holds", nh)
	}
	suffix := 1 + nh
	if len(authenticatedContent) <= suffix {
		t.Fatalf("authenticated_content is %d bytes, too short to carry a %d-byte tag", len(authenticatedContent), nh)
	}
	split := len(authenticatedContent) - suffix
	if authenticatedContent[split] != byte(nh) {
		t.Fatalf("expected an opaque<V> prefix of %#x at offset %d, found %#x", nh, split, authenticatedContent[split])
	}
	return authenticatedContent[:split], authenticatedContent[split+1:]
}

// verifyTranscriptHashVector checks one entry of transcript-hashes.json, both through
// the two free functions and through the stateful API the group actually uses.
func verifyTranscriptHashVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var vector transcriptHashVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse transcript-hashes entry: %v", err)
	}
	suite, ok := implementedSuite(vector.CipherSuite)
	if !ok {
		return
	}
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
	}

	confirmationKey := MustHex(t, vector.ConfirmationKey)
	interimBefore := MustHex(t, vector.InterimTranscriptHashBefore)
	confirmedAfter := MustHex(t, vector.ConfirmedTranscriptHashAfter)
	interimAfter := MustHex(t, vector.InterimTranscriptHashAfter)

	confirmedInput, confirmationTag := trSplitCommitAuthenticatedContent(
		t, crypto, MustHex(t, vector.AuthenticatedContent))

	// the vector's own verification step, and the check that makes the split honest
	if !crypto.MacVerify(confirmationKey, confirmedAfter, confirmationTag) {
		t.Fatal("the recovered confirmation tag does not verify against confirmed_transcript_hash_after")
	}

	confirmed := ConfirmedTranscriptHash(crypto, interimBefore, confirmedInput)
	if !bytes.Equal(confirmed, confirmedAfter) {
		t.Fatalf("confirmed_transcript_hash_after = %s, want %s", HexOf(confirmed), vector.ConfirmedTranscriptHashAfter)
	}
	interim, err := InterimTranscriptHash(crypto, confirmed, confirmationTag)
	if err != nil {
		t.Fatalf("InterimTranscriptHash: %v", err)
	}
	if !bytes.Equal(interim, interimAfter) {
		t.Fatalf("interim_transcript_hash_after = %s, want %s", HexOf(interim), vector.InterimTranscriptHashAfter)
	}

	// the same result through the stateful API the group uses
	hashes := &TranscriptHashes{
		Confirmed: nil,
		Interim:   interimBefore,
	}
	if err := hashes.Update(crypto, confirmedInput, confirmationTag); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !bytes.Equal(hashes.Confirmed, confirmedAfter) {
		t.Fatal("Update produced a different confirmed hash")
	}
	if !bytes.Equal(hashes.Interim, interimAfter) {
		t.Fatal("Update produced a different interim hash")
	}
}

// TestVectorTranscriptHashes is vector family 7.
func TestVectorTranscriptHashes(t *testing.T) {
	entries := LoadVectorFile(t, "transcript-hashes.json")
	if len(entries) == 0 {
		t.Fatal("transcript-hashes.json is empty")
	}

	ran, skipped := 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, raw := range entries {
		var header struct {
			CipherSuite uint16 `json:"cipher_suite"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		suite, ok := implementedSuite(header.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		verifyTranscriptHashVector(t, raw)
		ran++
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no transcript-hashes vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AesGcm128Sha256Ed25519] == 0 {
		t.Fatal("no transcript-hashes vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20Sha256Ed25519] == 0 {
		t.Fatal("no transcript-hashes vector ran at ciphersuite 0x0003")
	}
	t.Logf("transcript-hashes: ran %d, skipped %d unimplemented suites", ran, skipped)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorTranscriptHashes -v`
Expected: FAIL to compile before Step 1 is saved. After saving: PASS. A failure at "the recovered
confirmation tag does not verify" means the split assumption is wrong for this vector — do not adjust
the offset by trial and error; wait for `(*AuthenticatedContent).UnmarshalMLS` from p6 and use it.

- [ ] **Step 3: Write minimal implementation**

No production change expected. A mismatch on `confirmed_transcript_hash_after` while the MAC check
passed means `ConfirmedTranscriptHash` inserted a separator between the two inputs; remove it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestVectorTranscriptHashes|TestVectorFamilies' -v`
Expected: PASS, with a log line reporting 2 run and 5 skipped.

- [ ] **Step 5: Commit**

Delete `7` from p8's `expectedPendingFamilies` in the same commit.

```bash
git ls-files | wc -l
git add connect/mls/transcript_kat_test.go connect/mls/vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): transcript-hashes vector family, registered, with a self-validating split"
```

---

### Task 21: The secret tree, its descent and its deletions

**Files:**
- Create: `connect/mls/secret_tree.go`
- Test: `connect/mls/secret_tree_test.go`

**Interfaces:**
- Consumes, at registry §4's exact shapes — **counts are `LeafCount`, `NodeWidth` is `uint32`-valued,
  `Root` is two-valued, and `Level` is a method** (**C3**):
  ```go
  type LeafCount uint32
  func Root(n LeafCount) (NodeIndex, error)
  func Left(x NodeIndex) (NodeIndex, error)
  func Right(x NodeIndex) (NodeIndex, error)
  func NodeWidth(n LeafCount) uint32
  func (self NodeIndex) Level() uint32
  func (self LeafIndex) NodeIndex() NodeIndex
  ```
  plus `CryptoProvider.ExpandWithLabel`, `CryptoProvider.HashSize`, `zeroizeSecret` (Task 2).
- Produces:
  ```go
  type SecretTree struct{ /* unexported, guarded by stateLock */ }
  func NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error)
  func (self *SecretTree) LeafCount() LeafCount
  ```
  plus the unexported `takeLeafSecret` this task's tests reach through the exported surface of Task 22.

  The constructor takes `LeafCount`, not `LeafIndex` (registry override O-4): an index is not a
  count, and the two were the same underlying `uint32` in the first draft only because tree math had
  not landed yet. `Root` returning an error is handled, never shimmed away — a shim that turns the
  error into a zero node is how a zero-leaf tree gets built and every leaf reads as consumed.

- [ ] **Step 1: Write the failing test**

```go
// secret_tree_test.go
// tests for the RFC 9420 section 9 secret tree.
package mls

import (
	"bytes"
	"errors"
	"testing"
)

// stTestCrypto returns the ciphersuite 0x0003 provider the secret tree KATs use.
func stTestCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

const stVectorEncryptionSecret = "59227ed552e4a6db0779d43aea694fd1b2c2540e605a099b95cf852b41e8ea66"

// TestNewSecretTreeRejectsBadInput asserts a wrong-length root secret and a zero leaf
// count are refused, so a tree can never exist in a shape no leaf can be reached in.
func TestNewSecretTreeRejectsBadInput(t *testing.T) {
	crypto := stTestCrypto(t)
	good := MustHex(t, stVectorEncryptionSecret)
	if _, err := NewSecretTree(crypto, 8, good[:31]); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 0, good); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
		t.Fatalf("zero leaf count err = %v, want ErrSecretTreeLeafOutOfRange", err)
	}
}

// TestSecretTreeLeafCount asserts the accessor reports what was built, at the count
// type tree math defines. A LeafIndex here would compile and be wrong.
func TestSecretTreeLeafCount(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), LeafCount(8), MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	var got LeafCount = tree.LeafCount()
	if got != LeafCount(8) {
		t.Fatalf("LeafCount = %d, want 8", got)
	}
}

// TestSecretTreeSingleLeafRootIsTheLeaf asserts that in a one-leaf tree the root node
// and leaf 0 are the same node, so the encryption secret is the leaf secret with no
// intervening "tree"/"left" derivation.
func TestSecretTreeSingleLeafRootIsTheLeaf(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 1, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	leafSecret, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	if !bytes.Equal(leafSecret, encryptionSecret) {
		t.Fatalf("leaf secret = %x, want the encryption secret %x", leafSecret, encryptionSecret)
	}
}

// TestSecretTreeDescentDerivesBothChildren asserts a descent toward leaf 0 in an
// eight-leaf tree produces exactly the RFC's "tree"/"left" and "tree"/"right"
// expansions, and that leaf 7 is still reachable afterwards because the sibling
// subtree secret was retained.
func TestSecretTreeDescentDerivesBothChildren(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}

	nh := crypto.HashSize()
	left := crypto.ExpandWithLabel(encryptionSecret, "tree", []byte("left"), nh)
	leftLeft := crypto.ExpandWithLabel(left, "tree", []byte("left"), nh)
	wantLeaf0 := crypto.ExpandWithLabel(leftLeft, "tree", []byte("left"), nh)

	got, err := tree.takeLeafSecret(0)
	if err != nil {
		t.Fatalf("takeLeafSecret(0): %v", err)
	}
	if !bytes.Equal(got, wantLeaf0) {
		t.Fatalf("leaf 0 secret = %x, want %x", got, wantLeaf0)
	}

	if _, err := tree.takeLeafSecret(7); err != nil {
		t.Fatalf("leaf 7 became unreachable after descending to leaf 0: %v", err)
	}
}

// TestSecretTreeLeafSecretIsTakenOnce asserts the second call for one leaf fails.
// Retaining it would keep a secret alive that has already produced both ratchet roots,
// which is exactly the forward secrecy RFC 9420 section 9 is for.
func TestSecretTreeLeafSecretIsTakenOnce(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, err := tree.takeLeafSecret(3); err != nil {
		t.Fatalf("takeLeafSecret: %v", err)
	}
	if _, err := tree.takeLeafSecret(3); !errors.Is(err, ErrSecretTreeConsumed) {
		t.Fatalf("second take err = %v, want ErrSecretTreeConsumed", err)
	}
}

// TestSecretTreeRejectsOutOfRangeLeaf asserts a leaf beyond the tree is a typed error
// and not an index panic on a message from a peer.
func TestSecretTreeRejectsOutOfRangeLeaf(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, err := tree.takeLeafSecret(8); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
		t.Fatalf("err = %v, want ErrSecretTreeLeafOutOfRange", err)
	}
	if _, err := tree.takeLeafSecret(1 << 20); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
		t.Fatalf("err = %v, want ErrSecretTreeLeafOutOfRange", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestNewSecretTree|TestSecretTree' -v`
Expected: FAIL to compile with `undefined: NewSecretTree`.

- [ ] **Step 3: Write minimal implementation**

```go
// secret_tree.go
// the RFC 9420 section 9 secret tree: per-sender, per-generation message keys.
//
// The tree is walked lazily and destructively. A node secret is expanded into its two
// children and then erased, so the secret that could regenerate a whole subtree stops
// existing as soon as any leaf under it has been reached. That is the forward secrecy
// the section is for, and keeping the parent "just in case" quietly removes it.
package mls

import (
	"fmt"
	"sync"
)

// SecretTree holds the undelivered node secrets of one epoch.
// Not safe for concurrent use; stateLock makes misuse fail loudly rather than corrupt.
type SecretTree struct {
	stateLock sync.Mutex
	crypto    CryptoProvider
	leafCount LeafCount
	width     uint32
	root      NodeIndex
	nodes     map[NodeIndex][]byte
	ratchets  map[ratchetKey]*ratchet
}

// ratchetKey identifies one leaf's handshake or application ratchet.
type ratchetKey struct {
	leaf LeafIndex
	kind RatchetType
}

// NewSecretTree seeds the tree with encryption_secret at the root. leafCount is a
// LeafCount, not a LeafIndex: the two are both uint32 underneath, and passing an
// index where a count belongs is the off-by-one that makes the last member of the
// group unreachable.
func NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error) {
	if leafCount == 0 {
		return nil, fmt.Errorf("%w: leaf count is zero", ErrSecretTreeLeafOutOfRange)
	}
	if len(encryptionSecret) != crypto.HashSize() {
		return nil, fmt.Errorf("%w: encryption secret is %d bytes, want %d",
			ErrSecretLength, len(encryptionSecret), crypto.HashSize())
	}
	// Root is two-valued and the error is handled here rather than shimmed away:
	// a shim returning node 0 would build a tree whose descent never terminates.
	root, err := Root(leafCount)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSecretTreeLeafOutOfRange, err)
	}
	self := &SecretTree{
		crypto:    crypto,
		leafCount: leafCount,
		width:     NodeWidth(leafCount),
		root:      root,
		nodes:     map[NodeIndex][]byte{root: append([]byte(nil), encryptionSecret...)},
		ratchets:  map[ratchetKey]*ratchet{},
	}
	return self, nil
}

// LeafCount is the number of leaves the tree was built for.
func (self *SecretTree) LeafCount() LeafCount {
	return self.leafCount
}

// pathToLeaf returns the node indices from the root down to the leaf, inclusive.
// The array representation is in-order, so a target index below the current node is
// in the left subtree. That is the whole descent rule and it needs no parent lookups.
func (self *SecretTree) pathToLeaf(leaf LeafIndex) ([]NodeIndex, error) {
	if LeafCount(leaf) >= self.leafCount {
		return nil, fmt.Errorf("%w: leaf %d of %d", ErrSecretTreeLeafOutOfRange, leaf, self.leafCount)
	}
	target := leaf.NodeIndex()
	if uint32(target) >= self.width {
		return nil, fmt.Errorf("%w: node %d of width %d", ErrSecretTreeLeafOutOfRange, target, self.width)
	}
	path := []NodeIndex{self.root}
	current := self.root
	// Level is a method on NodeIndex, not a free function.
	for current.Level() > 0 {
		var next NodeIndex
		var err error
		if target < current {
			next, err = Left(current)
		} else {
			next, err = Right(current)
		}
		if err != nil {
			return nil, err
		}
		current = next
		path = append(path, current)
	}
	if current != target {
		return nil, fmt.Errorf("%w: descent reached node %d, want %d", ErrSecretTreeLeafOutOfRange, current, target)
	}
	return path, nil
}

// takeLeafSecret derives and removes the node secret of one leaf, expanding and
// erasing every ancestor still held along the way. The caller owns the returned slice
// and is expected to erase it once both ratchet roots exist.
func (self *SecretTree) takeLeafSecret(leaf LeafIndex) ([]byte, error) {
	path, err := self.pathToLeaf(leaf)
	if err != nil {
		return nil, err
	}
	deepest := -1
	for i, node := range path {
		if _, ok := self.nodes[node]; ok {
			deepest = i
		}
	}
	if deepest < 0 {
		return nil, fmt.Errorf("%w: leaf %d", ErrSecretTreeConsumed, leaf)
	}
	nh := self.crypto.HashSize()
	for i := deepest; i < len(path)-1; i++ {
		parent := path[i]
		parentSecret := self.nodes[parent]
		left, err := Left(parent)
		if err != nil {
			return nil, err
		}
		right, err := Right(parent)
		if err != nil {
			return nil, err
		}
		if uint32(left) < self.width {
			self.nodes[left] = self.crypto.ExpandWithLabel(parentSecret, "tree", []byte("left"), nh)
		}
		if uint32(right) < self.width {
			self.nodes[right] = self.crypto.ExpandWithLabel(parentSecret, "tree", []byte("right"), nh)
		}
		zeroizeSecret(parentSecret)
		delete(self.nodes, parent)
	}
	target := path[len(path)-1]
	secret, ok := self.nodes[target]
	if !ok {
		return nil, fmt.Errorf("%w: leaf %d", ErrSecretTreeConsumed, leaf)
	}
	delete(self.nodes, target)
	return secret, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestNewSecretTree|TestSecretTree' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/secret_tree.go connect/mls/secret_tree_test.go
git ls-files | wc -l
git commit -m "feat(mls): secret tree descent that erases each parent as it expands"
```

---

### Task 22: Ratchet roots and the per-generation key, nonce and successor

**Files:**
- Modify: `connect/mls/secret_tree.go`
- Test: `connect/mls/secret_tree_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.DeriveTreeSecret`, `CryptoProvider.KeySize`, `CryptoProvider.NonceSize`,
  `takeLeafSecret` (Task 21).
- Produces:
  ```go
  type RatchetType uint8
  const (
      RatchetHandshake RatchetType = iota + 1
      RatchetApplication
  )
  ```
  plus the unexported `ratchet` type with `step()`.

- [ ] **Step 1: Write the failing test**

```go
// append to secret_tree_test.go

// TestRatchetRootsUseDistinctLabels asserts the handshake and application ratchets
// are separate expansions of the same leaf secret. Sharing one ratchet between
// handshake and application messages would reuse an AEAD key and nonce pair.
func TestRatchetRootsUseDistinctLabels(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)
	tree, err := NewSecretTree(crypto, 1, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	handshake, err := tree.ratchetFor(0, RatchetHandshake)
	if err != nil {
		t.Fatalf("ratchetFor handshake: %v", err)
	}
	application, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor application: %v", err)
	}
	nh := crypto.HashSize()
	wantHandshake := crypto.ExpandWithLabel(encryptionSecret, "handshake", nil, nh)
	wantApplication := crypto.ExpandWithLabel(encryptionSecret, "application", nil, nh)
	if !bytes.Equal(handshake.secret, wantHandshake) {
		t.Fatalf("handshake root = %x, want %x", handshake.secret, wantHandshake)
	}
	if !bytes.Equal(application.secret, wantApplication) {
		t.Fatalf("application root = %x, want %x", application.secret, wantApplication)
	}
}

// TestRatchetStepDerivesKeyNonceAndSuccessor pins the three DeriveTreeSecret calls of
// RFC 9420 section 9.1 and asserts the ratchet advances by exactly one generation.
func TestRatchetStepDerivesKeyNonceAndSuccessor(t *testing.T) {
	crypto := stTestCrypto(t)
	tree, err := NewSecretTree(crypto, 1, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	root := append([]byte(nil), r.secret...)
	wantKey := crypto.DeriveTreeSecret(root, "key", 0, crypto.KeySize())
	wantNonce := crypto.DeriveTreeSecret(root, "nonce", 0, crypto.NonceSize())
	wantNext := crypto.DeriveTreeSecret(root, "secret", 0, crypto.HashSize())

	generation, keys, err := r.step()
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	if generation != 0 {
		t.Fatalf("generation = %d, want 0", generation)
	}
	if !bytes.Equal(keys.key, wantKey) {
		t.Fatalf("key = %x, want %x", keys.key, wantKey)
	}
	if !bytes.Equal(keys.nonce, wantNonce) {
		t.Fatalf("nonce = %x, want %x", keys.nonce, wantNonce)
	}
	if !bytes.Equal(r.secret, wantNext) {
		t.Fatalf("successor secret = %x, want %x", r.secret, wantNext)
	}
	if r.head != 1 {
		t.Fatalf("head = %d, want 1", r.head)
	}
}

// TestRatchetStepBindsTheGeneration asserts generation 1 uses generation 1 in the
// DeriveTreeSecret context and not 0, so a copy-paste of the previous call is caught.
func TestRatchetStepBindsTheGeneration(t *testing.T) {
	crypto := stTestCrypto(t)
	tree, err := NewSecretTree(crypto, 1, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	if _, _, err := r.step(); err != nil {
		t.Fatalf("step: %v", err)
	}
	secondRoot := append([]byte(nil), r.secret...)
	wantKey := crypto.DeriveTreeSecret(secondRoot, "key", 1, crypto.KeySize())
	generation, keys, err := r.step()
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	if generation != 1 {
		t.Fatalf("generation = %d, want 1", generation)
	}
	if !bytes.Equal(keys.key, wantKey) {
		t.Fatalf("generation 1 key is not bound to generation 1")
	}
}

// TestRatchetKeysAreNeverRepeated asserts the first two hundred generations produce
// two hundred distinct key and nonce pairs, which is the AEAD safety property.
func TestRatchetKeysAreNeverRepeated(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 1, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	seen := map[string]uint32{}
	for i := 0; i < 200; i++ {
		generation, keys, err := r.step()
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		fingerprint := string(keys.key) + "|" + string(keys.nonce)
		if previous, ok := seen[fingerprint]; ok {
			t.Fatalf("generation %d repeats the key and nonce of generation %d", generation, previous)
		}
		seen[fingerprint] = generation
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestRatchet -v`
Expected: FAIL to compile with `tree.ratchetFor undefined` and `undefined: RatchetHandshake`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to secret_tree.go

// RatchetType selects a leaf's handshake or application ratchet. The two are separate
// expansions of one leaf secret so a handshake message and an application message can
// never share an AEAD key and nonce.
type RatchetType uint8

const (
	RatchetHandshake RatchetType = iota + 1
	RatchetApplication
)

// generationKeys is one generation's AEAD key and nonce.
type generationKeys struct {
	key   []byte
	nonce []byte
}

// ratchet is one leaf's hash ratchet for one RatchetType.
type ratchet struct {
	crypto    CryptoProvider
	secret    []byte
	head      uint32
	exhausted bool
	window    map[uint32]*generationKeys
}

// newRatchet takes ownership of the root secret.
func newRatchet(crypto CryptoProvider, rootSecret []byte) *ratchet {
	return &ratchet{
		crypto: crypto,
		secret: rootSecret,
		head:   0,
		window: map[uint32]*generationKeys{},
	}
}

// step derives the head generation's key and nonce, replaces the ratchet secret with
// its successor, erases the old secret and advances the head.
func (self *ratchet) step() (uint32, *generationKeys, error) {
	if self.exhausted {
		return 0, nil, ErrRatchetExhausted
	}
	generation := self.head
	keys := &generationKeys{
		key:   self.crypto.DeriveTreeSecret(self.secret, "key", generation, self.crypto.KeySize()),
		nonce: self.crypto.DeriveTreeSecret(self.secret, "nonce", generation, self.crypto.NonceSize()),
	}
	next := self.crypto.DeriveTreeSecret(self.secret, "secret", generation, self.crypto.HashSize())
	zeroizeSecret(self.secret)
	self.secret = next
	if generation == ^uint32(0) {
		self.exhausted = true
	} else {
		self.head = generation + 1
	}
	return generation, keys, nil
}

// zeroize clears the ratchet secret and every retained window entry.
func (self *ratchet) zeroize() {
	zeroizeSecret(self.secret)
	for generation, keys := range self.window {
		zeroizeSecret(keys.key)
		zeroizeSecret(keys.nonce)
		delete(self.window, generation)
	}
}

// ratchetFor returns the leaf's ratchet, creating both of a leaf's ratchets together
// so the leaf node secret is taken from the tree exactly once and erased immediately.
func (self *SecretTree) ratchetFor(leaf LeafIndex, kind RatchetType) (*ratchet, error) {
	if kind != RatchetHandshake && kind != RatchetApplication {
		return nil, fmt.Errorf("mls: unknown ratchet type %d", kind)
	}
	key := ratchetKey{leaf: leaf, kind: kind}
	if existing, ok := self.ratchets[key]; ok {
		return existing, nil
	}
	leafSecret, err := self.takeLeafSecret(leaf)
	if err != nil {
		return nil, err
	}
	nh := self.crypto.HashSize()
	self.ratchets[ratchetKey{leaf: leaf, kind: RatchetHandshake}] =
		newRatchet(self.crypto, self.crypto.ExpandWithLabel(leafSecret, "handshake", nil, nh))
	self.ratchets[ratchetKey{leaf: leaf, kind: RatchetApplication}] =
		newRatchet(self.crypto, self.crypto.ExpandWithLabel(leafSecret, "application", nil, nh))
	zeroizeSecret(leafSecret)
	return self.ratchets[key], nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestRatchet -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/secret_tree.go connect/mls/secret_tree_test.go
git ls-files | wc -l
git commit -m "feat(mls): handshake and application ratchets with per-generation key derivation"
```

---

### Task 23: NextSenderKey, ReceiverKey and the generation window

**Files:**
- Modify: `connect/mls/secret_tree.go`
- Test: `connect/mls/secret_tree_test.go`

**Interfaces:**
- Consumes: `ratchetFor`, `(*ratchet).step` (Task 22).
- Produces:
  ```go
  const (
      MaxGenerationSkip uint32 = 1024
      RatchetWindowSize int    = 1024
  )
  func (self *SecretTree) NextSenderKey(leaf LeafIndex, kind RatchetType) (generation uint32, key []byte, nonce []byte, err error)
  func (self *SecretTree) ReceiverKey(leaf LeafIndex, kind RatchetType, generation uint32) (key []byte, nonce []byte, err error)
  func (self *SecretTree) SenderGeneration(leaf LeafIndex, kind RatchetType) (uint32, error)
  func (self *SecretTree) Zeroize()
  ```

  **Boundary note.** `NextSenderKey` is the encrypt path for our own leaf; `ReceiverKey` is the
  decrypt path for every other leaf. These two are the internal, vector-tested form that
  `secret-tree.json` addresses; the `ContentType`-keyed surface p6 actually calls wraps them in
  Task 23a. `ErrRatchetGenerationTooFarAhead` and
  `ErrRatchetGenerationConsumed` are surfaced to the product as a visible gap, never swallowed —
  the equivalent of `connect/message`'s `Kind == "gap"` (Spec A section 5.5). They are not ValSem006:
  ValSem006 is the AEAD failing, this is the key never having existed.

- [ ] **Step 1: Write the failing test**

```go
// append to secret_tree_test.go

// TestNextSenderKeyAdvances asserts the sender path hands out consecutive generations
// and never repeats one.
func TestNextSenderKeyAdvances(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	for want := uint32(0); want < 5; want++ {
		generation, key, nonce, err := tree.NextSenderKey(2, RatchetApplication)
		if err != nil {
			t.Fatalf("NextSenderKey: %v", err)
		}
		if generation != want {
			t.Fatalf("generation = %d, want %d", generation, want)
		}
		if len(key) != 32 || len(nonce) != 12 {
			t.Fatalf("key %d bytes, nonce %d bytes", len(key), len(nonce))
		}
	}
	generation, err := tree.SenderGeneration(2, RatchetApplication)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if generation != 5 {
		t.Fatalf("SenderGeneration = %d, want 5", generation)
	}
}

// TestReceiverKeyOutOfOrderUsesTheWindow asserts a message that arrives at generation
// 3 before generations 0 to 2 does not destroy them, which is what makes an out-of-
// order delivery a delay rather than three lost messages.
func TestReceiverKeyOutOfOrderUsesTheWindow(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)

	sender, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	expected := map[uint32][]byte{}
	for i := 0; i < 4; i++ {
		generation, key, _, err := sender.NextSenderKey(5, RatchetHandshake)
		if err != nil {
			t.Fatalf("NextSenderKey: %v", err)
		}
		expected[generation] = key
	}

	receiver, err := NewSecretTree(crypto, 8, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	got3, _, err := receiver.ReceiverKey(5, RatchetHandshake, 3)
	if err != nil {
		t.Fatalf("ReceiverKey(3): %v", err)
	}
	if !bytes.Equal(got3, expected[3]) {
		t.Fatalf("generation 3 key mismatch")
	}
	for _, generation := range []uint32{0, 1, 2} {
		got, _, err := receiver.ReceiverKey(5, RatchetHandshake, generation)
		if err != nil {
			t.Fatalf("ReceiverKey(%d): %v", generation, err)
		}
		if !bytes.Equal(got, expected[generation]) {
			t.Fatalf("generation %d key mismatch", generation)
		}
	}
}

// TestReceiverKeyIsSingleUse asserts a generation cannot be fetched twice, so a
// replayed message cannot be decrypted a second time from the window.
func TestReceiverKeyIsSingleUse(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 0); err != nil {
		t.Fatalf("ReceiverKey: %v", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 0); !errors.Is(err, ErrRatchetGenerationConsumed) {
		t.Fatalf("err = %v, want ErrRatchetGenerationConsumed", err)
	}
}

// TestReceiverKeyRefusesUnboundedSkip asserts a forged generation number cannot force
// an unbounded KDF loop. Without this bound a single 32-bit field is a denial of
// service that costs the sender nothing.
func TestReceiverKeyRefusesUnboundedSkip(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	_, _, err = tree.ReceiverKey(1, RatchetApplication, MaxGenerationSkip+1)
	if !errors.Is(err, ErrRatchetGenerationTooFarAhead) {
		t.Fatalf("err = %v, want ErrRatchetGenerationTooFarAhead", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, ^uint32(0)); !errors.Is(err, ErrRatchetGenerationTooFarAhead) {
		t.Fatalf("err = %v, want ErrRatchetGenerationTooFarAhead", err)
	}
	// the ratchet must be untouched by a refused request
	generation, err := tree.SenderGeneration(1, RatchetApplication)
	if err != nil {
		t.Fatalf("SenderGeneration: %v", err)
	}
	if generation != 0 {
		t.Fatalf("a refused request advanced the ratchet to %d", generation)
	}
}

// TestReceiverKeyWindowIsBounded asserts the retained skipped keys are capped, so one
// silent sender cannot grow a receiver's memory without limit.
func TestReceiverKeyWindowIsBounded(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, MaxGenerationSkip); err != nil {
		t.Fatalf("ReceiverKey: %v", err)
	}
	r, err := tree.ratchetFor(1, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	if len(r.window) > RatchetWindowSize {
		t.Fatalf("window holds %d entries, want at most %d", len(r.window), RatchetWindowSize)
	}
	// the oldest entry was evicted, so it now reads as consumed rather than available
	if _, _, err := tree.ReceiverKey(1, RatchetApplication, 0); err == nil {
		t.Fatal("generation 0 survived a full window; eviction is not happening")
	}
}

// TestSecretTreeZeroize asserts every retained node secret and ratchet secret is
// cleared when the epoch is dropped.
func TestSecretTreeZeroize(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, _, _, err := tree.NextSenderKey(0, RatchetApplication); err != nil {
		t.Fatalf("NextSenderKey: %v", err)
	}
	r, err := tree.ratchetFor(0, RatchetApplication)
	if err != nil {
		t.Fatalf("ratchetFor: %v", err)
	}
	retained := append([]byte(nil), r.secret...)
	tree.Zeroize()
	if bytes.Equal(r.secret, retained) {
		t.Fatal("the ratchet secret survived Zeroize")
	}
	for node, secret := range tree.nodes {
		for _, b := range secret {
			if b != 0 {
				t.Fatalf("node %d secret survived Zeroize", node)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestNextSenderKey|TestReceiverKey|TestSecretTreeZeroize' -v`
Expected: FAIL to compile with `tree.NextSenderKey undefined`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to secret_tree.go

const (
	// MaxGenerationSkip bounds how far ahead of the current head a receiver will
	// ratchet in one step. A generation number is attacker-supplied, and without a
	// bound a single uint32 buys 4 billion KDF calls.
	MaxGenerationSkip uint32 = 1024

	// RatchetWindowSize bounds the skipped keys retained for out-of-order receipt.
	// A sender that misses more than this many consecutive messages produces a
	// visible gap, which is the same trade Spec A section 5.5 makes for records.
	RatchetWindowSize int = 1024
)

// keyFor returns the keys for one generation, ratcheting forward and retaining the
// generations it passes. Single use: a generation already returned is gone.
func (self *ratchet) keyFor(generation uint32) (*generationKeys, error) {
	if keys, ok := self.window[generation]; ok {
		delete(self.window, generation)
		return keys, nil
	}
	if generation < self.head {
		return nil, fmt.Errorf("%w: generation %d, head %d", ErrRatchetGenerationConsumed, generation, self.head)
	}
	if generation-self.head > MaxGenerationSkip {
		return nil, fmt.Errorf("%w: generation %d, head %d, bound %d",
			ErrRatchetGenerationTooFarAhead, generation, self.head, MaxGenerationSkip)
	}
	for {
		stepped, keys, err := self.step()
		if err != nil {
			return nil, err
		}
		if stepped == generation {
			return keys, nil
		}
		self.window[stepped] = keys
		self.prune()
	}
}

// prune evicts the oldest retained generation once the window is full.
func (self *ratchet) prune() {
	for len(self.window) > RatchetWindowSize {
		oldest := ^uint32(0)
		for generation := range self.window {
			if generation < oldest {
				oldest = generation
			}
		}
		keys := self.window[oldest]
		zeroizeSecret(keys.key)
		zeroizeSecret(keys.nonce)
		delete(self.window, oldest)
	}
}

// NextSenderKey returns the next generation's key and nonce for our own leaf.
func (self *SecretTree) NextSenderKey(leaf LeafIndex, kind RatchetType) (generation uint32, key []byte, nonce []byte, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	r, err := self.ratchetFor(leaf, kind)
	if err != nil {
		return 0, nil, nil, err
	}
	generation, keys, err := r.step()
	if err != nil {
		return 0, nil, nil, err
	}
	return generation, keys.key, keys.nonce, nil
}

// ReceiverKey returns one generation's key and nonce for another member's leaf.
// A returned error is a visible gap for the product, never a silent skip.
func (self *SecretTree) ReceiverKey(leaf LeafIndex, kind RatchetType, generation uint32) (key []byte, nonce []byte, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	r, err := self.ratchetFor(leaf, kind)
	if err != nil {
		return nil, nil, err
	}
	keys, err := r.keyFor(generation)
	if err != nil {
		return nil, nil, err
	}
	return keys.key, keys.nonce, nil
}

// SenderGeneration is the next generation this leaf's ratchet will hand out.
func (self *SecretTree) SenderGeneration(leaf LeafIndex, kind RatchetType) (uint32, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	r, err := self.ratchetFor(leaf, kind)
	if err != nil {
		return 0, err
	}
	return r.head, nil
}

// Zeroize clears every secret the tree still holds. Called when the epoch leaves the
// PastEpochWindow.
func (self *SecretTree) Zeroize() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, secret := range self.nodes {
		zeroizeSecret(secret)
	}
	for _, r := range self.ratchets {
		r.zeroize()
	}
}
```

`ratchetFor` and `takeLeafSecret` are called with `stateLock` already held; they must not take it
themselves. Add a doc line on each saying so.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestNextSenderKey|TestReceiverKey|TestSecretTreeZeroize' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/secret_tree.go connect/mls/secret_tree_test.go
git ls-files | wc -l
git commit -m "feat(mls): sender and receiver key paths with a bounded generation window"
```

---

### Task 23a: The MessageKeySource implementation the framing plan declares

**Files:**
- Modify: `connect/mls/secret_tree.go`
- Test: `connect/mls/secret_tree_test.go`

**Interfaces:**
- Consumes, from p6 (registry §7.1):
  ```go
  type ContentType uint8
  const (
      ContentTypeApplication ContentType = 1
      ContentTypeProposal    ContentType = 2
      ContentTypeCommit      ContentType = 3
  )
  ```
  plus `ratchetFor` and `(*ratchet).step` (Task 22) and `(*ratchet).keyFor` (Task 23).
- Produces, at p6's exact signatures (registry §5.5):
  ```go
  func (self *SecretTree) NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
  func (self *SecretTree) MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
  func (self *SecretTree) EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
  ```

  **This plan implements the interface p6 declares.** p6 is the only consumer of the message-key
  surface and its shape is the right one for the framing path: it is keyed on `ContentType`, which
  is what the `PrivateMessage` header actually carries, so no caller has to remember the
  `ContentType → RatchetType` mapping. `NextSenderKey`/`ReceiverKey` stay as the internal,
  vector-tested form that `secret-tree.json` addresses; these three are the wrapper p6 calls.
  p6 Task 11 carries `var _ MessageKeySource = (*SecretTree)(nil)`, so a mismatch fails at build
  rather than at the message-protection vector family — this plan does not declare that interface
  or that assertion, because both are p6's.

  **`EraseMessageKey` had no producer anywhere**, and it is the forward-secrecy erase p6's ValSem006
  reuse guard is built on. It is implemented here against the skipped-key window this plan already
  owns. It follows that `MessageKey` must *not* consume: p6 calls `MessageKey`, opens the AEAD, and
  erases on success. A `MessageKey` that consumed would make `EraseMessageKey` a no-op and would
  burn a key on every forged ciphertext, turning one bad packet into a permanently lost message.
  `ReceiverKey` keeps its single-use semantics because it has no erase counterpart.

  **Ordering.** `ContentType` is p6's and p6 is wave 3, so this task alone sequences after p6 Task 1.
  Every other task in this plan is wave 2 and depends on nothing from p6.

- [ ] **Step 1: Write the failing test**

```go
// append to secret_tree_test.go

// TestNextMessageKeyMapsContentTypeToRatchet asserts application content reaches the
// application ratchet and both handshake content types reach the handshake ratchet.
// Getting this mapping wrong would encrypt a commit under an application key that a
// receiver looks up in the other ratchet, and the failure would read as a bad tag.
func TestNextMessageKeyMapsContentTypeToRatchet(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := MustHex(t, stVectorEncryptionSecret)

	viaContentType, err := NewSecretTree(crypto, LeafCount(8), encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	viaRatchetType, err := NewSecretTree(crypto, LeafCount(8), encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}

	for _, check := range []struct {
		contentType ContentType
		kind        RatchetType
		leaf        LeafIndex
	}{
		{ContentTypeApplication, RatchetApplication, 0},
		{ContentTypeProposal, RatchetHandshake, 1},
		{ContentTypeCommit, RatchetHandshake, 2},
	} {
		gotKey, gotNonce, gotGeneration, err := viaContentType.NextMessageKey(check.contentType, check.leaf)
		if err != nil {
			t.Fatalf("NextMessageKey(%d): %v", check.contentType, err)
		}
		wantGeneration, wantKey, wantNonce, err := viaRatchetType.NextSenderKey(check.leaf, check.kind)
		if err != nil {
			t.Fatalf("NextSenderKey: %v", err)
		}
		if gotGeneration != wantGeneration {
			t.Fatalf("content type %d: generation = %d, want %d", check.contentType, gotGeneration, wantGeneration)
		}
		if !bytes.Equal(gotKey, wantKey) || !bytes.Equal(gotNonce, wantNonce) {
			t.Fatalf("content type %d does not map to ratchet type %d", check.contentType, check.kind)
		}
	}
}

// TestNextMessageKeyRejectsUnknownContentType asserts the reserved content type is a
// typed error and not generation 0 of the handshake ratchet.
func TestNextMessageKeyRejectsUnknownContentType(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), LeafCount(8), MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if _, _, _, err := tree.NextMessageKey(ContentType(0), 0); err == nil {
		t.Fatal("content type 0 produced a key")
	}
	if _, _, err := tree.MessageKey(ContentType(9), 0, 0); err == nil {
		t.Fatal("content type 9 produced a key")
	}
}

// TestMessageKeyDoesNotConsumeUntilErased asserts a lookup can be repeated until the
// caller erases it. p6 opens the AEAD between the two calls, so a MessageKey that
// consumed would lose a real message every time a forged one arrived first.
func TestMessageKeyDoesNotConsumeUntilErased(t *testing.T) {
	crypto := stTestCrypto(t)
	tree, err := NewSecretTree(crypto, LeafCount(8), MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	first, firstNonce, err := tree.MessageKey(ContentTypeApplication, 3, 2)
	if err != nil {
		t.Fatalf("MessageKey: %v", err)
	}
	second, secondNonce, err := tree.MessageKey(ContentTypeApplication, 3, 2)
	if err != nil {
		t.Fatalf("second MessageKey: %v", err)
	}
	if !bytes.Equal(first, second) || !bytes.Equal(firstNonce, secondNonce) {
		t.Fatal("two lookups of one generation disagreed")
	}

	tree.EraseMessageKey(ContentTypeApplication, 3, 2)
	if _, _, err := tree.MessageKey(ContentTypeApplication, 3, 2); !errors.Is(err, ErrRatchetGenerationConsumed) {
		t.Fatalf("err after erase = %v, want ErrRatchetGenerationConsumed", err)
	}
}

// TestEraseMessageKeyZeroizesTheEntry asserts the erase actually clears the bytes
// rather than only dropping the map entry, which is the whole point of it existing.
func TestEraseMessageKeyZeroizesTheEntry(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), LeafCount(8), MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	key, nonce, err := tree.MessageKey(ContentTypeCommit, 4, 1)
	if err != nil {
		t.Fatalf("MessageKey: %v", err)
	}
	tree.EraseMessageKey(ContentTypeCommit, 4, 1)
	for i, b := range key {
		if b != 0 {
			t.Fatalf("key byte %d = %d after erase, want 0", i, b)
		}
	}
	for i, b := range nonce {
		if b != 0 {
			t.Fatalf("nonce byte %d = %d after erase, want 0", i, b)
		}
	}
}

// TestEraseMessageKeyIsTotal asserts erasing something that was never derived, or a
// content type that does not exist, is a no-op. p6 calls this on every open path
// including the failing ones, so it must never panic and must never build a ratchet.
func TestEraseMessageKeyIsTotal(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), LeafCount(8), MustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	tree.EraseMessageKey(ContentTypeApplication, 5, 7)
	tree.EraseMessageKey(ContentType(0), 5, 7)
	tree.EraseMessageKey(ContentTypeApplication, 1<<20, 0)
	if len(tree.ratchets) != 0 {
		t.Fatalf("erase built %d ratchets; it must not touch the tree", len(tree.ratchets))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestNextMessageKey|TestMessageKey|TestEraseMessageKey' -v`
Expected: FAIL to compile with `tree.NextMessageKey undefined`. If it instead fails with
`undefined: ContentTypeApplication`, p6 Task 1 has not landed and this task blocks on it.

- [ ] **Step 3: Write minimal implementation**

Split the retention out of `keyFor` so a lookup and a consumption are separate operations, then add
the three wrappers:

```go
// replace keyFor in secret_tree.go with the pair:

// peekFor returns the keys for one generation, ratcheting forward and retaining every
// generation it passes — including the target. It does not consume: the caller decides
// whether to erase. Called with stateLock held.
func (self *ratchet) peekFor(generation uint32) (*generationKeys, error) {
	if keys, ok := self.window[generation]; ok {
		return keys, nil
	}
	if generation < self.head {
		return nil, fmt.Errorf("%w: generation %d, head %d", ErrRatchetGenerationConsumed, generation, self.head)
	}
	if generation-self.head > MaxGenerationSkip {
		return nil, fmt.Errorf("%w: generation %d, head %d, bound %d",
			ErrRatchetGenerationTooFarAhead, generation, self.head, MaxGenerationSkip)
	}
	for {
		stepped, keys, err := self.step()
		if err != nil {
			return nil, err
		}
		self.window[stepped] = keys
		self.prune()
		if stepped == generation {
			return keys, nil
		}
	}
}

// keyFor is peekFor plus consumption: a generation already returned is gone. This is
// what ReceiverKey uses, because it has no erase counterpart. Called with stateLock held.
func (self *ratchet) keyFor(generation uint32) (*generationKeys, error) {
	keys, err := self.peekFor(generation)
	if err != nil {
		return nil, err
	}
	delete(self.window, generation)
	return keys, nil
}

// eraseKey zeroizes and drops one retained generation. Total: erasing a generation
// that was never derived is a no-op. Called with stateLock held.
func (self *ratchet) eraseKey(generation uint32) {
	keys, ok := self.window[generation]
	if !ok {
		return
	}
	zeroizeSecret(keys.key)
	zeroizeSecret(keys.nonce)
	delete(self.window, generation)
}
```

```go
// append to secret_tree.go

// ratchetTypeOf maps the wire ContentType a PrivateMessage carries to the ratchet it
// draws from. RFC 9420 section 9.1: application content uses the application ratchet,
// proposals and commits share the handshake ratchet.
func ratchetTypeOf(contentType ContentType) (RatchetType, error) {
	switch contentType {
	case ContentTypeApplication:
		return RatchetApplication, nil
	case ContentTypeProposal, ContentTypeCommit:
		return RatchetHandshake, nil
	}
	return 0, fmt.Errorf("mls: no ratchet for content type %d", contentType)
}

// NextMessageKey is the MessageKeySource encrypt path: the next generation's key and
// nonce for our own leaf, keyed on the ContentType the header carries.
func (self *SecretTree) NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error) {
	kind, err := ratchetTypeOf(contentType)
	if err != nil {
		return nil, nil, 0, err
	}
	generation, key, nonce, err = self.NextSenderKey(leaf, kind)
	if err != nil {
		return nil, nil, 0, err
	}
	return key, nonce, generation, nil
}

// MessageKey is the MessageKeySource decrypt path. It does NOT consume the generation:
// the caller opens the AEAD and then calls EraseMessageKey, so a forged ciphertext
// cannot destroy the key the real message needs.
func (self *SecretTree) MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error) {
	kind, err := ratchetTypeOf(contentType)
	if err != nil {
		return nil, nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	r, err := self.ratchetFor(leaf, kind)
	if err != nil {
		return nil, nil, err
	}
	keys, err := r.peekFor(generation)
	if err != nil {
		return nil, nil, err
	}
	return keys.key, keys.nonce, nil
}

// EraseMessageKey is the forward-secrecy erase the framing plan's replay guard is
// built on: once a message at this generation has been opened, its key stops existing.
// Total by design — it is called on paths that never derived a key, so an unknown
// content type, an out-of-range leaf and an unseen generation are all no-ops, and none
// of them builds a ratchet.
func (self *SecretTree) EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32) {
	kind, err := ratchetTypeOf(contentType)
	if err != nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	r, ok := self.ratchets[ratchetKey{leaf: leaf, kind: kind}]
	if !ok {
		return
	}
	r.eraseKey(generation)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestNextMessageKey|TestMessageKey|TestEraseMessageKey|TestReceiverKey|TestNextSenderKey' -v`
Expected: PASS, including every Task 23 test — `ReceiverKey` must still be single use after the
`keyFor` refactor, and `TestReceiverKeyIsSingleUse` is what proves it.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/secret_tree.go connect/mls/secret_tree_test.go
git ls-files | wc -l
git commit -m "feat(mls): MessageKeySource on SecretTree, with the erase the reuse guard needs"
```

---

### Task 24: SenderDataKeyNonce

**Files:**
- Modify: `connect/mls/secret_tree.go`
- Test: `connect/mls/secret_tree_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.ExpandWithLabel`, `CryptoProvider.HashSize`, `CryptoProvider.KeySize`,
  `CryptoProvider.NonceSize`.
- Produces:
  ```go
  func SenderDataKeyNonce(crypto CryptoProvider, senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error)
  ```

  p6's `sealSenderData`/`openSenderData` call this to protect
  `PrivateMessage.EncryptedSenderData`. **It is implemented once, here** (registry §5.5): p6's
  unexported `senderDataKeyNonce` — same derivation, no error return, no vector coverage — is
  deleted, because two implementations of one §6.3.2 derivation with only one of them vector-tested,
  and the untested one being the one the encrypt path calls, is precisely how the
  `ciphertext_sample` short-ciphertext trap both plans separately documented gets got wrong. p6
  keeps its two short-ciphertext tests as regression tests against this implementation, which is
  what `TestSenderDataKeyNonceSamplesFirstNhBytes` below covers from this side.

- [ ] **Step 1: Write the failing test**

```go
// append to secret_tree_test.go

const (
	stVectorSenderDataSecret = "d61204c27f29de53d30ff54a6ebb53e9908d044f55b9e726fa5736d4246b7b36"
	stVectorSenderDataCt     = "d0f75d5b691dbff35cafe226adad83aa5076c85035fef7d7fac489ad63f10828" +
		"266b44ea366961509e8c9c24474abb6066c5a350aeb2b05415facb7ac2aa1b1efcf75a0c700bfdc93c705e352c"
	stVectorSenderDataKey   = "674a0c3e1500d068aae5d50f57a14648a63de2c246f8178382a150df8031f4cf"
	stVectorSenderDataNonce = "56b73cca00eac6cc5080be8d"
)

// TestSenderDataKeyNonceKAT pins the derivation and the ciphertext_sample rule.
func TestSenderDataKeyNonceKAT(t *testing.T) {
	key, nonce, err := SenderDataKeyNonce(
		stTestCrypto(t),
		MustHex(t, stVectorSenderDataSecret),
		MustHex(t, stVectorSenderDataCt),
	)
	if err != nil {
		t.Fatalf("SenderDataKeyNonce: %v", err)
	}
	if !bytes.Equal(key, MustHex(t, stVectorSenderDataKey)) {
		t.Fatalf("sender_data_key = %x", key)
	}
	if !bytes.Equal(nonce, MustHex(t, stVectorSenderDataNonce)) {
		t.Fatalf("sender_data_nonce = %x", nonce)
	}
}

// TestSenderDataKeyNonceSamplesFirstNhBytes asserts only the first KDF.Nh bytes of the
// ciphertext enter the derivation, so appending to a long ciphertext changes nothing.
func TestSenderDataKeyNonceSamplesFirstNhBytes(t *testing.T) {
	crypto := stTestCrypto(t)
	secret := MustHex(t, stVectorSenderDataSecret)
	full := MustHex(t, stVectorSenderDataCt)
	key, _, err := SenderDataKeyNonce(crypto, secret, full)
	if err != nil {
		t.Fatalf("SenderDataKeyNonce: %v", err)
	}
	truncated, _, err := SenderDataKeyNonce(crypto, secret, full[:crypto.HashSize()])
	if err != nil {
		t.Fatalf("SenderDataKeyNonce: %v", err)
	}
	if !bytes.Equal(key, truncated) {
		t.Fatal("bytes beyond the first KDF.Nh changed the sender data key")
	}
	shorter, _, err := SenderDataKeyNonce(crypto, secret, full[:16])
	if err != nil {
		t.Fatalf("SenderDataKeyNonce: %v", err)
	}
	if bytes.Equal(key, shorter) {
		t.Fatal("a short ciphertext is being padded rather than used whole")
	}
}

// TestSenderDataKeyNonceRejectsShortSecret asserts a wrong-length secret is fatal.
func TestSenderDataKeyNonceRejectsShortSecret(t *testing.T) {
	_, _, err := SenderDataKeyNonce(stTestCrypto(t), MustHex(t, stVectorSenderDataSecret)[:16], []byte{1})
	if !errors.Is(err, ErrSecretLength) {
		t.Fatalf("err = %v, want ErrSecretLength", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestSenderDataKeyNonce -v`
Expected: FAIL to compile with `undefined: SenderDataKeyNonce`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to secret_tree.go

// SenderDataKeyNonce derives the AEAD key and nonce protecting a PrivateMessage's
// sender data, per RFC 9420 section 6.3.2:
//
//	ciphertext_sample = ciphertext[0..KDF.Nh-1]   (all of it when shorter)
//	sender_data_key   = ExpandWithLabel(sender_data_secret, "key", ciphertext_sample, AEAD.Nk)
//	sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, AEAD.Nn)
//
// Sampling the ciphertext is what stops one sender_data_secret from producing one key
// and nonce for every message in the epoch.
func SenderDataKeyNonce(crypto CryptoProvider, senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error) {
	nh := crypto.HashSize()
	if len(senderDataSecret) != nh {
		return nil, nil, fmt.Errorf("%w: sender data secret is %d bytes, want %d",
			ErrSecretLength, len(senderDataSecret), nh)
	}
	sample := ciphertext
	if len(sample) > nh {
		sample = sample[:nh]
	}
	key = crypto.ExpandWithLabel(senderDataSecret, "key", sample, crypto.KeySize())
	nonce = crypto.ExpandWithLabel(senderDataSecret, "nonce", sample, crypto.NonceSize())
	return key, nonce, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestSenderDataKeyNonce -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/secret_tree.go connect/mls/secret_tree_test.go
git ls-files | wc -l
git commit -m "feat(mls): sender data key and nonce derivation from the ciphertext sample"
```

---

### Task 25: The secret-tree vector runner and its generate direction

**Files:**
- Create: `connect/mls/secret_tree_kat_test.go`

**Interfaces:**
- Consumes: `NewSecretTree`, `(*SecretTree).ReceiverKey`, `(*SecretTree).NextSenderKey`,
  `SenderDataKeyNonce` (Tasks 21–24), `LoadVectorFile`, `MustHex`, `HexOf`,
  `RegisterVectorFamily`, `implementedSuite` (Task 16).
- Produces: nothing at runtime. Registers family 3 and closes gate `secret-tree`.

- [ ] **Step 1: Write the failing test**

```go
// secret_tree_kat_test.go
// runner for the mlswg secret-tree vector family.
package mls

import (
	"bytes"
	"encoding/json"
	"testing"
)

// secretTreeVector is one entry of secret-tree.json.
type secretTreeVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	SenderData  struct {
		SenderDataSecret string `json:"sender_data_secret"`
		Ciphertext       string `json:"ciphertext"`
		Key              string `json:"key"`
		Nonce            string `json:"nonce"`
	} `json:"sender_data"`
	EncryptionSecret string                   `json:"encryption_secret"`
	Leaves           [][]secretTreeGeneration `json:"leaves"`
}

// secretTreeGeneration is one generation of one leaf.
type secretTreeGeneration struct {
	Generation       uint32 `json:"generation"`
	HandshakeKey     string `json:"handshake_key"`
	HandshakeNonce   string `json:"handshake_nonce"`
	ApplicationKey   string `json:"application_key"`
	ApplicationNonce string `json:"application_nonce"`
}

func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   3,
		Name:     "secret-tree",
		File:     "secret-tree.json",
		Slice:    "A2",
		Verify:   verifySecretTreeVector,
		Generate: generateSecretTreeVector,
	})
}

// verifySecretTreeVector checks one entry of secret-tree.json. The generations in each
// leaf are 0 and 15, so the receiver path's forward skip is exercised as well as the
// base case.
func verifySecretTreeVector(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var vector secretTreeVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse secret-tree entry: %v", err)
	}
	suite, ok := implementedSuite(vector.CipherSuite)
	if !ok {
		return
	}
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
	}

	key, nonce, err := SenderDataKeyNonce(
		crypto, MustHex(t, vector.SenderData.SenderDataSecret), MustHex(t, vector.SenderData.Ciphertext))
	if err != nil {
		t.Fatalf("SenderDataKeyNonce: %v", err)
	}
	if !bytes.Equal(key, MustHex(t, vector.SenderData.Key)) {
		t.Fatalf("sender_data key = %s, want %s", HexOf(key), vector.SenderData.Key)
	}
	if !bytes.Equal(nonce, MustHex(t, vector.SenderData.Nonce)) {
		t.Fatalf("sender_data nonce = %s, want %s", HexOf(nonce), vector.SenderData.Nonce)
	}

	encryptionSecret := MustHex(t, vector.EncryptionSecret)
	leafCount := LeafCount(len(vector.Leaves))
	// each ratchet type gets its own tree, because ReceiverKey consumes a generation
	// and the vector asks for the same generations of both types
	handshakeTree, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	applicationTree, err := NewSecretTree(crypto, leafCount, encryptionSecret)
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}

	for leaf, generations := range vector.Leaves {
		for _, want := range generations {
			gotKey, gotNonce, err := handshakeTree.ReceiverKey(LeafIndex(leaf), RatchetHandshake, want.Generation)
			if err != nil {
				t.Fatalf("leaf %d generation %d: handshake: %v", leaf, want.Generation, err)
			}
			if !bytes.Equal(gotKey, MustHex(t, want.HandshakeKey)) {
				t.Fatalf("leaf %d generation %d: handshake_key = %s, want %s",
					leaf, want.Generation, HexOf(gotKey), want.HandshakeKey)
			}
			if !bytes.Equal(gotNonce, MustHex(t, want.HandshakeNonce)) {
				t.Fatalf("leaf %d generation %d: handshake_nonce = %s, want %s",
					leaf, want.Generation, HexOf(gotNonce), want.HandshakeNonce)
			}

			gotKey, gotNonce, err = applicationTree.ReceiverKey(LeafIndex(leaf), RatchetApplication, want.Generation)
			if err != nil {
				t.Fatalf("leaf %d generation %d: application: %v", leaf, want.Generation, err)
			}
			if !bytes.Equal(gotKey, MustHex(t, want.ApplicationKey)) {
				t.Fatalf("leaf %d generation %d: application_key = %s, want %s",
					leaf, want.Generation, HexOf(gotKey), want.ApplicationKey)
			}
			if !bytes.Equal(gotNonce, MustHex(t, want.ApplicationNonce)) {
				t.Fatalf("leaf %d generation %d: application_nonce = %s, want %s",
					leaf, want.Generation, HexOf(gotNonce), want.ApplicationNonce)
			}
		}
	}
}

// TestVectorSecretTree is vector family 3.
func TestVectorSecretTree(t *testing.T) {
	entries := LoadVectorFile(t, "secret-tree.json")
	if len(entries) == 0 {
		t.Fatal("secret-tree.json is empty")
	}

	ran, skipped, leaves := 0, 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, raw := range entries {
		var vector secretTreeVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		suite, ok := implementedSuite(vector.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		verifySecretTreeVector(t, raw)
		ran++
		leaves += len(vector.Leaves)
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no secret-tree vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AesGcm128Sha256Ed25519] == 0 {
		t.Fatal("no secret-tree vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20Sha256Ed25519] == 0 {
		t.Fatal("no secret-tree vector ran at ciphersuite 0x0003")
	}
	t.Logf("secret-tree: ran %d vectors covering %d leaves, skipped %d unimplemented suites", ran, leaves, skipped)
}

// generateSecretTreeVector is the Generate half of family 3: build fresh vectors from
// a random encryption secret at both implemented suites.
func generateSecretTreeVector(t *testing.T) json.RawMessage {
	t.Helper()
	vectors := []secretTreeVector{}
	for _, suite := range []CipherSuite{
		CipherSuiteX25519AesGcm128Sha256Ed25519,
		CipherSuiteX25519ChaCha20Sha256Ed25519,
	} {
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
		}
		encryptionSecret := crypto.Random(crypto.HashSize())
		const leafCount = LeafCount(8)

		producer, err := NewSecretTree(crypto, leafCount, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree: %v", err)
		}
		vector := secretTreeVector{
			CipherSuite:      uint16(suite),
			EncryptionSecret: HexOf(encryptionSecret),
		}
		senderDataSecret := crypto.Random(crypto.HashSize())
		senderDataCiphertext := crypto.Random(64)
		senderKey, senderNonce, err := SenderDataKeyNonce(crypto, senderDataSecret, senderDataCiphertext)
		if err != nil {
			t.Fatalf("SenderDataKeyNonce: %v", err)
		}
		vector.SenderData.SenderDataSecret = HexOf(senderDataSecret)
		vector.SenderData.Ciphertext = HexOf(senderDataCiphertext)
		vector.SenderData.Key = HexOf(senderKey)
		vector.SenderData.Nonce = HexOf(senderNonce)

		for leaf := LeafIndex(0); LeafCount(leaf) < leafCount; leaf++ {
			var generations []secretTreeGeneration
			for want := uint32(0); want < 3; want++ {
				generation, handshakeKey, handshakeNonce, err := producer.NextSenderKey(leaf, RatchetHandshake)
				if err != nil {
					t.Fatalf("NextSenderKey handshake: %v", err)
				}
				if generation != want {
					t.Fatalf("generation = %d, want %d", generation, want)
				}
				_, applicationKey, applicationNonce, err := producer.NextSenderKey(leaf, RatchetApplication)
				if err != nil {
					t.Fatalf("NextSenderKey application: %v", err)
				}
				generations = append(generations, secretTreeGeneration{
					Generation:       generation,
					HandshakeKey:     HexOf(handshakeKey),
					HandshakeNonce:   HexOf(handshakeNonce),
					ApplicationKey:   HexOf(applicationKey),
					ApplicationNonce: HexOf(applicationNonce),
				})
			}
			vector.Leaves = append(vector.Leaves, generations)
		}
		vectors = append(vectors, vector)
	}
	serialized, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return json.RawMessage(serialized)
}

// TestVectorSecretTreeGenerate verifies the generated vector with a second secret
// tree, so an asymmetry between how a key is produced and how it is looked up cannot
// hide.
func TestVectorSecretTreeGenerate(t *testing.T) {
	var readBack []secretTreeVector
	if err := json.Unmarshal(generateSecretTreeVector(t), &readBack); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(readBack) != 2 {
		t.Fatalf("generated %d suites, want 2", len(readBack))
	}
	for _, vector := range readBack {
		suite, ok := implementedSuite(vector.CipherSuite)
		if !ok {
			t.Fatalf("generated a vector at unimplemented suite %#x", vector.CipherSuite)
		}
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
		}
		verifier, err := NewSecretTree(crypto, LeafCount(len(vector.Leaves)), MustHex(t, vector.EncryptionSecret))
		if err != nil {
			t.Fatalf("NewSecretTree: %v", err)
		}
		for leaf, generations := range vector.Leaves {
			for _, want := range generations {
				gotKey, gotNonce, err := verifier.ReceiverKey(LeafIndex(leaf), RatchetHandshake, want.Generation)
				if err != nil {
					t.Fatalf("suite %#x leaf %d generation %d: %v", suite, leaf, want.Generation, err)
				}
				if !bytes.Equal(gotKey, MustHex(t, want.HandshakeKey)) ||
					!bytes.Equal(gotNonce, MustHex(t, want.HandshakeNonce)) {
					t.Fatalf("suite %#x leaf %d generation %d: receiver path disagrees with the sender path",
						suite, leaf, want.Generation)
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorSecretTree -v`
Expected: FAIL to compile before Step 1 is saved. After saving: a failure at leaf 0 generation 0 in
the eight-leaf vector means the descent picked the wrong child; a failure only at generation 15 means
`keyFor` is deriving each generation from the root rather than from the running secret.

- [ ] **Step 3: Write minimal implementation**

No production change expected.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestVectorSecretTree|TestVectorFamilies' -v`
Expected: PASS, with a log line reporting 6 vectors covering 82 leaves and 15 skipped.

- [ ] **Step 5: Commit**

Delete `3` from p8's `expectedPendingFamilies` in the same commit. That is the last of this plan's
four; families 3, 5, 6 and 7 are then all registered and executing.

```bash
git ls-files | wc -l
git add connect/mls/secret_tree_kat_test.go connect/mls/vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): secret-tree vector family, registered, verify and generate directions"
```

---

### Task 26: Round-trip properties and the seed corpus for the two structures this plan encodes

**Files:**
- Create: `connect/mls/key_schedule_roundtrip_test.go`
- Create: `connect/mls/testdata/corpus/FuzzGroupContextRoundTrip/seed001`
- Create: `connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip/seed001`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal`, `(*GroupContext).MarshalMLS`/`UnmarshalMLS`
  (Tasks 3–4), `(*PreSharedKeyId).MarshalMLS`/`UnmarshalMLS` (Task 13).
- Produces: the seed corpus for two of p8's nine Gate-4 fuzz targets, and the deterministic form of
  the same two properties.

  **p8 owns all nine Gate-4 fuzz targets** (registry §9.5), including
  `FuzzGroupContextRoundTrip` and `FuzzPreSharedKeyIdRoundTrip` over the codec table, and it owns
  the committed `testdata/corpus/` tree. Declaring a `Fuzz*` function here would be a second
  declaration of a name p8 already has in `package mls`. What this plan contributes is the part only
  it can: seeds that are known-good encodings of both structures, and a deterministic table test
  asserting the same two properties on every commit rather than only when the fuzzer runs.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_roundtrip_test.go
// Gate 4 properties 1 and 2, deterministically, for the two structures the key
// schedule owns: no panic on adversarial input, and byte-exact round-trip stability.
// MLS signs over serialized forms, so a decoder that accepts two encodings of one
// object is a signature-bypass primitive. The randomized form of these properties is
// p8's FuzzGroupContextRoundTrip and FuzzPreSharedKeyIdRoundTrip; this file seeds them.
package mls

import (
	"bytes"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// ksRoundTripSeeds are the encodings this plan contributes to p8's fuzz corpus. Every
// entry is emitted by our own encoder, so a change to either codec that these do not
// survive is caught here before the fuzzer ever runs.
func ksRoundTripSeeds(t *testing.T) (groupContexts [][]byte, pskIds [][]byte) {
	t.Helper()
	for _, gc := range []*GroupContext{
		{
			Version:                 ProtocolVersionMls10,
			CipherSuite:             CipherSuiteX25519ChaCha20Sha256Ed25519,
			GroupId:                 []byte("group"),
			Epoch:                   3,
			TreeHash:                make([]byte, 32),
			ConfirmedTranscriptHash: make([]byte, 32),
		},
		{
			Version:                 ProtocolVersionMls10,
			CipherSuite:             CipherSuiteX25519AesGcm128Sha256Ed25519,
			GroupId:                 nil,
			Epoch:                   0,
			TreeHash:                make([]byte, 32),
			ConfirmedTranscriptHash: make([]byte, 32),
			Extensions: []Extension{
				{ExtensionType: ExtensionType(0xF001), ExtensionData: []byte{1, 2, 3}},
			},
		},
	} {
		encoded, err := syntax.Marshal(gc)
		if err != nil {
			t.Fatalf("syntax.Marshal(GroupContext): %v", err)
		}
		groupContexts = append(groupContexts, encoded)
	}
	for _, id := range []*PreSharedKeyId{
		{PskType: PskTypeExternal, PskId: []byte("id"), PskNonce: make([]byte, 32)},
		{PskType: PskTypeExternal, PskId: nil, PskNonce: nil},
		{
			PskType:    PskTypeResumption,
			Usage:      ResumptionPskUsageApplication,
			PskGroupId: []byte("g"),
			PskEpoch:   1 << 40,
			PskNonce:   make([]byte, 32),
		},
	} {
		encoded, err := syntax.Marshal(id)
		if err != nil {
			t.Fatalf("syntax.Marshal(PreSharedKeyId): %v", err)
		}
		pskIds = append(pskIds, encoded)
	}
	return groupContexts, pskIds
}

// TestGroupContextRoundTripIsByteExact asserts encode(decode(x)) == x for every seed,
// and that decoding the re-encoding is stable.
func TestGroupContextRoundTripIsByteExact(t *testing.T) {
	groupContexts, _ := ksRoundTripSeeds(t)
	for i, data := range groupContexts {
		parsed := &GroupContext{}
		if err := syntax.Unmarshal(data, parsed); err != nil {
			t.Fatalf("seed %d: syntax.Unmarshal: %v", i, err)
		}
		reencoded, err := syntax.Marshal(parsed)
		if err != nil {
			t.Fatalf("seed %d: a parsed group context failed to re-encode: %v", i, err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("seed %d: round trip changed the bytes:\n got %x\nwant %x", i, reencoded, data)
		}
		again := &GroupContext{}
		if err := syntax.Unmarshal(reencoded, again); err != nil {
			t.Fatalf("seed %d: re-encoded group context failed to parse: %v", i, err)
		}
		if again.Epoch != parsed.Epoch || !bytes.Equal(again.GroupId, parsed.GroupId) {
			t.Fatalf("seed %d: decode(encode(decode(x))) differs from decode(x)", i)
		}
	}
}

// TestPreSharedKeyIdRoundTripIsByteExact asserts the same for PreSharedKeyId, whose
// bytes are hashed into psk_input and therefore into every epoch secret when PSKs are
// in use.
func TestPreSharedKeyIdRoundTripIsByteExact(t *testing.T) {
	_, pskIds := ksRoundTripSeeds(t)
	for i, data := range pskIds {
		parsed := &PreSharedKeyId{}
		if err := syntax.Unmarshal(data, parsed); err != nil {
			t.Fatalf("seed %d: syntax.Unmarshal: %v", i, err)
		}
		reencoded, err := syntax.Marshal(parsed)
		if err != nil {
			t.Fatalf("seed %d: a parsed PreSharedKeyId failed to re-encode: %v", i, err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("seed %d: round trip changed the bytes:\n got %x\nwant %x", i, reencoded, data)
		}
	}
}

// TestCodecsRefuseTruncatedAndExtendedInput asserts every prefix and every one-byte
// extension of a valid encoding is refused rather than panicking or yielding a
// partly-populated struct. This is Gate 4 property 1 over a bounded input set, on
// every run, without waiting for the fuzzer.
func TestCodecsRefuseTruncatedAndExtendedInput(t *testing.T) {
	groupContexts, pskIds := ksRoundTripSeeds(t)
	for i, data := range groupContexts {
		for n := 0; n < len(data); n++ {
			if err := syntax.Unmarshal(data[:n], &GroupContext{}); err == nil {
				t.Fatalf("group context seed %d: prefix of %d bytes parsed", i, n)
			}
		}
		if err := syntax.Unmarshal(append(append([]byte(nil), data...), 0x00), &GroupContext{}); err == nil {
			t.Fatalf("group context seed %d: a trailing byte was accepted", i)
		}
	}
	for i, data := range pskIds {
		for n := 0; n < len(data); n++ {
			if err := syntax.Unmarshal(data[:n], &PreSharedKeyId{}); err == nil {
				t.Fatalf("psk id seed %d: prefix of %d bytes parsed", i, n)
			}
		}
		if err := syntax.Unmarshal(append(append([]byte(nil), data...), 0x00), &PreSharedKeyId{}); err == nil {
			t.Fatalf("psk id seed %d: a trailing byte was accepted", i)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestGroupContextRoundTripIsByteExact|TestPreSharedKeyIdRoundTripIsByteExact|TestCodecsRefuse' -v`
Expected: FAIL to compile before Step 1 is saved. After saving it passes if Tasks 3, 4 and 13 are
correct; a byte-exactness failure is a bug in the codec, never in the test — a non-canonical
encoding that survives a round trip is the defect.

- [ ] **Step 3: Write the seed corpus for p8's targets**

```bash
mkdir -p connect/mls/testdata/corpus/FuzzGroupContextRoundTrip
mkdir -p connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip
printf 'go test fuzz v1\n[]byte("\\x00\\x01\\x00\\x03\\x05group\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x03\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00")\n' \
  > connect/mls/testdata/corpus/FuzzGroupContextRoundTrip/seed001
printf 'go test fuzz v1\n[]byte("\\x01\\x02id\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00")\n' \
  > connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip/seed001
```

Both seeds are the first entry of `ksRoundTripSeeds` written out by hand, so if the codec changes,
`TestGroupContextRoundTripIsByteExact` goes red in the same commit that would otherwise leave a
stale seed behind. The corpus directory itself belongs to p8's Gate-4 task; this plan only adds
files under the two target names.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestGroupContextRoundTripIsByteExact|TestPreSharedKeyIdRoundTripIsByteExact|TestCodecsRefuse' -count=1 -v`
Then, once p8's Gate-4 targets exist, confirm the seeds are picked up and survive:
`go test ./connect/mls/... -run FuzzGroupContextRoundTrip -fuzz FuzzGroupContextRoundTrip -fuzztime 60s`
Expected: PASS, no new corpus entries reported as failures.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_roundtrip_test.go connect/mls/testdata/corpus
git ls-files | wc -l
git commit -m "test(mls): byte-exact round-trip properties and Gate 4 seed corpus for the two codecs"
```

---

### Task 27: The guardrail source scan

**Files:**
- Create: `connect/mls/key_schedule_guard_test.go`

**Interfaces:**
- Consumes: nothing beyond the standard library.
- Produces: nothing. Enforces G1, G3, G7 and G8 for the files this plan owns, and turns the six
  registry corrections that are invisible to the type checker — a redeclared ValSem sentinel, a
  resurrected `Parse*`/`Marshal()` wrapper, `WriteBytes`, `MarshalExtensions` — into a red test on
  the machine where the mistake is made rather than a merge conflict two waves later.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_guard_test.go
// mechanical defences for the Spec A section 5.9 guardrails, over the files this
// plan owns. A grep in CI would catch the same thing, but a test catches it on the
// machine where the mistake is made.
package mls

import (
	"os"
	"strings"
	"testing"
)

// ksGuardedFiles are the production files this plan owns.
var ksGuardedFiles = []string{
	"group_context.go",
	"key_schedule.go",
	"psk.go",
	"transcript.go",
	"secret_tree.go",
	"errors_key_schedule.go",
	"secret_zeroize.go",
}

// TestKeyScheduleGuardrails asserts the banned constructs appear in none of them.
func TestKeyScheduleGuardrails(t *testing.T) {
	banned := []struct {
		needle string
		reason string
	}{
		{"hkdf.Extract", "G1: crypto/hkdf.Extract takes ikm first; only CryptoProvider.Extract(salt, ikm) may be called"},
		{"hkdf.Expand", "G1: expansion goes through CryptoProvider so the KDFLabel encoding has one implementation"},
		{"curve25519.ScalarMult", "banned: returns a zero secret on a low-order point"},
		{"box.Precompute", "banned: reaches ScalarMult"},
		{"GenerateSharedSecret", "banned: sdk.GenerateSharedSecret length-checks only"},
		{"bytes.Equal", "G8: every tag comparison goes through CryptoProvider.MacVerify"},
		{"math/rand", "banned: key material never comes from math/rand"},
		{"ErrPskNonceLength =", "ValSem401 is declared once, in the validation plan's errors.go"},
		{"ErrPskType =", "ValSem402 is declared once, in the validation plan's errors.go"},
		{"ErrDuplicatePsk =", "ValSem403 is declared once, in the validation plan's errors.go"},
		{"func ParseGroupContext", "C1: byte-level decode is syntax.Unmarshal, not a free constructor"},
		{"func ParsePreSharedKeyId", "C1: byte-level decode is syntax.Unmarshal, not a free constructor"},
		{") Marshal()", "C1: byte-level encode is syntax.Marshal, not a per-type wrapper"},
		{"w.WriteBytes", "the raw, unprefixed write is WriteRaw; WriteBytes does not exist"},
		{"MarshalExtensions", "the extension vector codec is WriteExtensions/ReadExtensions"},
		{"ParseExtensions", "the extension vector codec is WriteExtensions/ReadExtensions"},
	}
	for _, name := range ksGuardedFiles {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(source)
		for _, ban := range banned {
			if strings.Contains(text, ban.needle) {
				t.Fatalf("%s contains %q — %s", name, ban.needle, ban.reason)
			}
		}
	}
}

// TestKeyScheduleImportsAreNarrow asserts these files import nothing outside the
// standard library and connect/mls/syntax. connect/mls must stay auditable and
// fuzzable without the transport, so an import of connect here is a layering break.
func TestKeyScheduleImportsAreNarrow(t *testing.T) {
	allowed := map[string]bool{
		"\"crypto/subtle\"":                           true,
		"\"errors\"":                                  true,
		"\"fmt\"":                                     true,
		"\"math\"":                                    true,
		"\"runtime\"":                                 true,
		"\"sync\"":                                    true,
		"\"github.com/urnetwork/connect/mls/syntax\"": true,
	}
	for _, name := range ksGuardedFiles {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, line := range strings.Split(string(source), "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "\"") || !strings.HasSuffix(trimmed, "\"") {
				continue
			}
			if strings.Contains(trimmed, " ") {
				continue
			}
			if !allowed[trimmed] {
				t.Fatalf("%s imports %s, which is not on the allowed list", name, trimmed)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestKeyScheduleGuardrails -v`
Expected: FAIL to compile before Step 1 is saved. After saving it should pass; if it reports
`bytes.Equal` in a production file, replace that comparison with `CryptoProvider.MacVerify` or, for a
non-secret comparison, move the comparison into the test that needs it.

- [ ] **Step 3: Write minimal implementation**

No production change expected. If `TestKeyScheduleImportsAreNarrow` reports a legitimate new stdlib
import, add it to the allowed map in the same commit that introduces it, so the addition is reviewed.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestKeyScheduleGuardrails|TestKeyScheduleImportsAreNarrow' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_guard_test.go
git ls-files | wc -l
git commit -m "test(mls): guardrail scan for hkdf.Extract, bytes.Equal and banned X25519 helpers"
```

---

### Task 28: Full-package green run and the coverage note

**Files:**
- Modify: none.

**Interfaces:**
- Consumes: everything above.
- Produces: the evidence that this plan's four gates are closed.

- [ ] **Step 1: Write the failing test**

No new test. This task verifies the whole set together, which is where an ordering assumption between
two tests first shows up.

- [ ] **Step 2: Run the full package**

Run: `go test ./connect/mls/... -count=1 -v 2>&1 | tail -40`
Expected: PASS. Record the four vector log lines:
- `key-schedule: ran 2 vectors covering 10 epochs, skipped 5 unimplemented suites`
- `psk_secret: ran 22, skipped 55 unimplemented suites`
- `transcript-hashes: ran 2, skipped 5 unimplemented suites`
- `secret-tree: ran 6 vectors covering 82 leaves, skipped 15 unimplemented suites`

If any "ran" count is zero the runner skipped everything and the gate is not closed, however green
the output looks.

- [ ] **Step 3: Run with the race detector and with shuffled ordering**

Run: `go test ./connect/mls/... -count=1 -race -shuffle=on`
Expected: PASS. `-shuffle=on` catches a test that only passes because an earlier test left a ratchet
in a particular state.

- [ ] **Step 4: Confirm the cross-platform obligation**

Run:
```bash
for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/arm64 android/arm64 ios/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} go build ./connect/mls/... || echo "FAILED $target"
done
```
Expected: no `FAILED` lines. Nothing in this plan is platform specific, so a failure here means an
import crept in that is.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add -A connect/mls
git ls-files | wc -l
git commit -m "chore(mls): key schedule and secret tree green across the seven build targets

Closes the key-schedule, psk_secret, transcript-hashes and secret-tree vector gates."
```

---

## Acceptance mapping

| Spec A gate | What this plan closes | What it does not |
|---|---|---|
| Gate 1, family registration | Families 3, 5, 6 and 7 registered with `RegisterVectorFamily` and struck from `expectedPendingFamilies` (Tasks 16, 17, 20, 25) | The other twelve families |
| Gate 2, family 3 `secret-tree` | Task 25, verify and generate | — |
| Gate 2, family 5 `key-schedule` | Tasks 17 and 18, verify and generate | — |
| Gate 2, family 6 `psk_secret` | Task 16 | — |
| Gate 2, family 7 `transcript-hashes` | Task 20 | The AuthenticatedContent parse is a self-validating byte split until p6 lands `AuthenticatedContent.UnmarshalMLS` |
| Gate 2, family 8 `welcome` | The `welcome_secret` to key/nonce derivation (Task 11) | The end-to-end Welcome decrypt, which is p7 |
| Gate 3, ValSem401/402/403 | The RFC-level checks, returned as `ValSem(ValSem401\|402\|403, detail)`, and their negative tests (Tasks 13–15) | The three sentinels themselves and the `TestValSemNNN_*` names, which are p8's; the v1 `ErrProfilePsk` parse refusal, which is p8's `Profile` called by p7 |
| Gate 3, ValSem400 | `PastEpochWindow = 32` and its test (Task 12) | `TestValSem400_PastEpochBound` over the StateStore, which is p7 and p8 |
| Gate 3, ValSem205 / ValSem008 | `VerifyConfirmationTag` / `VerifyMembershipTag` (Task 10) | The commit and framing call sites |
| Gate 3, errata 8745 and 8815 | nothing — both are validation errata (§13.4 and §12.2), implemented as `CheckErrata8745`/`CheckErrata8815` in p7 | p7 and p8 |
| Gate 4, properties 1 and 2 | The deterministic round-trip properties and the seed corpus for `FuzzGroupContextRoundTrip` and `FuzzPreSharedKeyIdRoundTrip` (Task 26) | All nine `Fuzz*` targets themselves, which are p8's |
| p6's `MessageKeySource` | `NextMessageKey`, `MessageKey`, `EraseMessageKey` on `*SecretTree` (Task 23a) | The interface declaration and `var _ MessageKeySource = (*SecretTree)(nil)`, which are p6 Task 11 |
| Guardrails G1, G6, G7, G8 | Tasks 12 and 27 | G2, G3, G5, G9, G10, G11, which belong to `connect/message` |

## Risks carried by this plan

1. **`Extension`, `ExtensionType`, `ProtocolVersion` and `WriteExtensions`/`ReadExtensions` are p5's,
   and p5 is wave 2 — the same wave as this plan.** `group_context.go` cannot compile until p5
   Task 3 lands, so **p5 Task 3 sequences before Task 3 here**, and that is the one hard ordering
   constraint inside wave 2. Nothing in this plan may work around it by declaring `Extension`
   locally: `package mls` is one package and the second declaration is a compile error.
2. **`ContentType` is p6's and p6 is wave 3.** Task 23a is the only task here that consumes it, so
   it is the only task that cannot run in wave 2. Everything else — including the whole secret tree
   and all four vector families — completes without it. If wave 3 slips, Task 23a slips alone and
   the four gates this plan owns still close.
3. **The three PSK sentinels now come from p8.** `ErrPskNonceLength`, `ErrPskType` and
   `ErrDuplicatePsk` are ValSem401/402/403 in p8's `errors.go`, which is wave 1 and lands before
   anything here. If p8's names drift, Task 13 fails to compile — which is the intended detection —
   and the fix is in p8, not a local redeclaration. Task 27's source scan bans the redeclaration
   explicitly, because a redeclaration is the tempting fix at 2am.
4. **The transcript vector's content split** is correct for KDF.Nh below 64 and is checked by a MAC,
   so it cannot silently produce a wrong answer — but it will need replacing with
   `AuthenticatedContent.UnmarshalMLS` when p6 lands, and Task 20 says so in the code comment.
5. **`MaxGenerationSkip = 1024`** is a judgement call, not an RFC value. A sender that emits more than
   1024 messages in one epoch while a receiver is offline produces a visible gap for that receiver.
   Spec A section 5.5 makes the same trade for records and section 14 open item 7 already carries a
   memory-budget review; this constant belongs in that review.
6. **`MessageKey` is non-consuming and `EraseMessageKey` is what consumes.** That split is forced by
   p6 declaring an erase at all, but it means a caller that looks a key up and never erases it
   leaves it in the window until `RatchetWindowSize` evicts it. p6 Task 11's
   `var _ MessageKeySource = (*SecretTree)(nil)` catches a signature mismatch; nothing catches a
   missing erase call except p6's own ValSem006 reuse test, and that test is the reason to keep it.
