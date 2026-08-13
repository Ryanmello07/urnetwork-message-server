# Key Schedule and Secret Tree Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 9420 §8 (epoch key schedule, GroupContext binding, PSK secret, exporter,
confirmation and membership tags, transcript hashes) and §9 (secret tree, per-sender per-generation
handshake and application keys) in pure Go, passing the `key-schedule`, `psk_secret`,
`transcript-hashes` and `secret-tree` vector families in both directions.

**Architecture:** Four self-contained files in `connect/mls` — `group_context.go`, `key_schedule.go`,
`psk.go`, `transcript.go`, `secret_tree.go` — that consume only the `CryptoProvider` interface, the
tree-math index functions, and the `syntax` reader/writer. Nothing here touches HPKE (except
`DeriveKeyPair` for `external_pub`), the ratchet tree, framing, or the group state machine, so the
whole key schedule can be audited and fuzzed as arithmetic over byte slices. Secrets are consumed and
zeroized on use: a secret-tree node secret is deleted once its two children exist, a ratchet secret is
deleted once it has produced its generation's key, nonce and successor.

**Tech Stack:** Go 1.26.5, `crypto/hkdf` and `crypto/sha3` via the wave-1 `CryptoProvider` only,
`crypto/subtle` for tag comparison, `encoding/json` in tests, `testing` and `testing/fuzz`.

## Global Constraints

- Go 1.26.5, pinned. `connect/go.mod` says `go 1.26.3`; bump to `1.26.5` in wave 1 and do not change it here.
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

---

## File Structure

| File | Single responsibility |
|---|---|
| `connect/mls/errors_key_schedule.go` | **Create.** Typed errors owned by this plan. A separate file from `errors.go` so the wave-1 validation plan and this plan never edit the same file during parallel waves. |
| `connect/mls/secret_zeroize.go` | **Create.** `zeroizeSecret`, the best-effort `//go:noinline` overwrite used by every file in this plan. |
| `connect/mls/group_context.go` | **Create.** The `GroupContext` struct, its byte-exact `Marshal`, and `ParseGroupContext`. The single definition of the epoch binding every other file hashes or expands over. |
| `connect/mls/key_schedule.go` | **Create.** RFC 9420 §8 — joiner secret, welcome secret, epoch secret, the nine derived epoch secrets, exporter, external key pair, confirmation and membership tags, welcome key/nonce. |
| `connect/mls/psk.go` | **Create.** RFC 9420 §8.4 — `PreSharedKeyId`, `PSKLabel`, `PskSecret`, and the ValSem401/402/403 checks the computation itself enforces. |
| `connect/mls/transcript.go` | **Create.** RFC 9420 §8.2 — confirmed and interim transcript hash chaining, the group-creation base case, and the joiner's seed from a GroupInfo. |
| `connect/mls/secret_tree.go` | **Create.** RFC 9420 §9 — the secret tree, the per-leaf handshake and application ratchets, the generation window, and the sender-data key/nonce derivation. |
| `connect/mls/key_schedule_deps_test.go` | **Create.** Compile-time pins on every wave-1 symbol this plan consumes. Fails to build the moment a signature drifts. |
| `connect/mls/group_context_test.go` | **Create.** GroupContext KAT, round-trip, trailing-byte rejection. |
| `connect/mls/key_schedule_test.go` | **Create.** Key-schedule KATs against the suite-3 epoch-0 vector, tag tests, unreachability test. |
| `connect/mls/psk_test.go` | **Create.** PSK label encoding, `PskSecret` KAT, ValSem401/402/403 negatives. |
| `connect/mls/transcript_test.go` | **Create.** Transcript arithmetic, base case, GroupInfo seed. |
| `connect/mls/secret_tree_test.go` | **Create.** Secret tree descent, deletion, ratchet stepping, window behaviour, forward secrecy. |
| `connect/mls/key_schedule_vectors_test.go` | **Create.** The shared vector-loading helpers (`ksHex`, `ksLoadVectors`, `ksImplementedSuite`) plus the `key-schedule` and `psk_secret` runners and the key-schedule generator. |
| `connect/mls/transcript_vectors_test.go` | **Create.** The `transcript-hashes` runner and its self-validating AuthenticatedContent split. |
| `connect/mls/secret_tree_vectors_test.go` | **Create.** The `secret-tree` runner and generator. |
| `connect/mls/key_schedule_fuzz_test.go` | **Create.** Round-trip fuzz targets for `GroupContext` and `PreSharedKeyId`, feeding the Gate 4 corpus. |
| `connect/mls/key_schedule_guard_test.go` | **Create.** Source-scanning guardrail test for G1 (`hkdf.Extract`), G8 (`bytes.Equal` on tags) and the banned X25519 helpers. |
| `connect/mls/testdata/vectors/key-schedule.json` | **Create (vendor).** Pinned mlswg vector. |
| `connect/mls/testdata/vectors/psk_secret.json` | **Create (vendor).** Pinned mlswg vector. |
| `connect/mls/testdata/vectors/transcript-hashes.json` | **Create (vendor).** Pinned mlswg vector. |
| `connect/mls/testdata/vectors/secret-tree.json` | **Create (vendor).** Pinned mlswg vector. |
| `connect/mls/testdata/corpus/FuzzGroupContextRoundTrip/` | **Create.** Seed corpus. |
| `connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip/` | **Create.** Seed corpus. |

### What this plan does NOT own

`crypto.go`, `suite.go`, `hpke.go`, `tree_math.go`, `syntax/`, `extension.go`, `framing.go`,
`treekem.go`, `group.go`, `validation.go`, `errors.go`, `profile.go`, `interop/`. `commit_secret`
comes from TreeKEM. `ConfirmedTranscriptHashInput` bytes and the membership TBM bytes come from
framing. `GroupInfo` and `Welcome` construction come from group lifecycle.

---

## Interface summary — what other plans consume from here

Copy these into your Consumes block verbatim.

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
func (self *GroupContext) Marshal() ([]byte, error)
func (self *GroupContext) Clone() *GroupContext
func ParseGroupContext(data []byte) (*GroupContext, error)

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
func WelcomeKeyNonce(crypto CryptoProvider, welcomeSecret []byte) (key []byte, nonce []byte, err error)

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
type PreSharedKeyInput struct {
    Id     PreSharedKeyId
    Secret []byte
}
func (self *PreSharedKeyId) Marshal() ([]byte, error)
func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error
func ParsePreSharedKeyId(r *syntax.Reader) (*PreSharedKeyId, error)
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
func NewSecretTree(crypto CryptoProvider, leafCount LeafIndex, encryptionSecret []byte) (*SecretTree, error)
func (self *SecretTree) LeafCount() LeafIndex
func (self *SecretTree) NextSenderKey(leaf LeafIndex, kind RatchetType) (generation uint32, key []byte, nonce []byte, err error)
func (self *SecretTree) ReceiverKey(leaf LeafIndex, kind RatchetType, generation uint32) (key []byte, nonce []byte, err error)
func (self *SecretTree) SenderGeneration(leaf LeafIndex, kind RatchetType) (uint32, error)
func (self *SecretTree) Zeroize()
func SenderDataKeyNonce(crypto CryptoProvider, senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error)

// errors_key_schedule.go
var (
    ErrSecretLength                 = errors.New("mls: secret has the wrong length")
    ErrExportLength                 = errors.New("mls: exporter length out of range")
    ErrGroupContextTrailingBytes    = errors.New("mls: group context has trailing bytes")
    ErrTranscriptHashLength         = errors.New("mls: transcript hash has the wrong length")
    ErrPskNonceLength               = errors.New("mls: psk nonce is not KDF.Nh bytes")     // ValSem401
    ErrPskType                      = errors.New("mls: unsupported psk type or usage")     // ValSem402
    ErrDuplicatePsk                 = errors.New("mls: duplicate PreSharedKeyID")          // ValSem403
    ErrPskCount                     = errors.New("mls: too many psks for a uint16 count")
    ErrSecretTreeLeafOutOfRange     = errors.New("mls: leaf index outside the secret tree")
    ErrSecretTreeConsumed           = errors.New("mls: secret tree node already consumed")
    ErrRatchetGenerationConsumed    = errors.New("mls: ratchet generation already consumed")
    ErrRatchetGenerationTooFarAhead = errors.New("mls: ratchet generation too far ahead")
    ErrRatchetExhausted             = errors.New("mls: ratchet generation space exhausted")
)
```

---

## Interface summary — what this plan consumes

Every symbol below is pinned by the compile-time assertions in Task 1. If a wave-1 plan names any of
them differently, Task 1 fails to compile, which is the intended detection mechanism.

**From "Crypto primitives and HPKE" (wave 1), package `mls`:**

```go
type CipherSuite uint16
const CipherSuiteX25519AES128SHA256Ed25519   CipherSuite = 0x0001
const CipherSuiteX25519ChaCha20SHA256Ed25519 CipherSuite = 0x0003
type ProtocolVersion uint16
const ProtocolVersionMls10 ProtocolVersion = 0x0001
func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)
type CryptoProvider interface {   // exactly Spec A §3.3
    Suite() CipherSuite
    HashSize() int
    KeySize() int
    NonceSize() int
    Hash(data []byte) []byte
    Mac(key, data []byte) []byte
    MacVerify(key, data, tag []byte) bool
    Extract(salt, ikm []byte) []byte
    Expand(prk []byte, info []byte, length int) []byte
    ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte
    DeriveSecret(secret []byte, label string) []byte
    DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte
    AeadSeal(key, nonce, aad, plaintext []byte) ([]byte, error)
    AeadOpen(key, nonce, aad, ciphertext []byte) ([]byte, error)
    SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error)
    VerifyWithLabel(pub SignaturePublicKey, label string, content, sig []byte) error
    HpkeSeal(pub HpkePublicKey, info, aad, plaintext []byte) (kemOutput, ciphertext []byte, err error)
    HpkeOpen(priv HpkePrivateKey, kemOutput, info, aad, ciphertext []byte) ([]byte, error)
    DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error)
    SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error)
    Random(n int) []byte
}
type HpkePrivateKey ...
type HpkePublicKey ...
func (self HpkePublicKey) Bytes() []byte   // needed to compare against the vector's external_pub
```

**From "Tree math" (wave 1), package `mls`:**

```go
type LeafIndex uint32
type NodeIndex uint32
func NodeWidth(leafCount LeafIndex) NodeIndex
func Root(leafCount LeafIndex) NodeIndex
func Left(x NodeIndex) (NodeIndex, error)
func Right(x NodeIndex) (NodeIndex, error)
func Level(x NodeIndex) uint32
func (self LeafIndex) NodeIndex() NodeIndex
```

**From "Syntax and codec" (wave 1), package `mls/syntax` and package `mls`:**

```go
func syntax.NewWriter() *syntax.Writer
func (self *syntax.Writer) WriteUint8(v uint8)
func (self *syntax.Writer) WriteUint16(v uint16)
func (self *syntax.Writer) WriteUint32(v uint32)
func (self *syntax.Writer) WriteUint64(v uint64)
func (self *syntax.Writer) WriteOpaque(v []byte) error   // MLS varint length prefix
func (self *syntax.Writer) WriteBytes(v []byte)          // raw, no prefix
func (self *syntax.Writer) Bytes() ([]byte, error)

func syntax.NewReader(data []byte) *syntax.Reader
func (self *syntax.Reader) ReadUint8() (uint8, error)
func (self *syntax.Reader) ReadUint16() (uint16, error)
func (self *syntax.Reader) ReadUint32() (uint32, error)
func (self *syntax.Reader) ReadUint64() (uint64, error)
func (self *syntax.Reader) ReadOpaque() ([]byte, error)
func (self *syntax.Reader) Done() error                  // errors when bytes remain

type ExtensionType uint16
type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}
func MarshalExtensions(w *syntax.Writer, extensions []Extension) error
func ParseExtensions(r *syntax.Reader) ([]Extension, error)
```

**From "Validation and interop harness" (wave 1):** the pinned mlswg checkout used to vendor the four
vector files in Task 1, and the `connect/mls/ERRATA.md` transcription. Errata 8745 (§13.4, LeafNode
capability validation in Update proposals and update paths) and errata 8815 (§12.2, commit proposal
references must have been previously received) are **both validation errata and neither touches the
key schedule** — they are tested by that plan, not this one.

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

### Task 1: Pin the wave-1 interfaces and vendor the four vector files

**Files:**
- Create: `connect/mls/testdata/vectors/key-schedule.json`, `psk_secret.json`, `transcript-hashes.json`, `secret-tree.json`
- Test: `connect/mls/key_schedule_deps_test.go`

**Interfaces:**
- Consumes: everything in the "what this plan consumes" section above.
- Produces: nothing at runtime. Produces the build-time guarantee that the consumed signatures exist.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_deps_test.go
// compile-time pins on every wave-1 symbol the key schedule and secret tree consume.
// a signature change in another wave breaks the build here rather than three tasks later.
package mls

import (
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// pinned free functions from the tree math and syntax plans.
var (
	_ func(CipherSuite) (CryptoProvider, error) = NewCryptoProvider
	_ func(LeafIndex) NodeIndex                 = NodeWidth
	_ func(LeafIndex) NodeIndex                 = Root
	_ func(NodeIndex) (NodeIndex, error)        = Left
	_ func(NodeIndex) (NodeIndex, error)        = Right
	_ func(NodeIndex) uint32                    = Level
	_ func(LeafIndex) NodeIndex                 = LeafIndex.NodeIndex
	_ func(HpkePublicKey) []byte                = HpkePublicKey.Bytes
	_ func() *syntax.Writer                     = syntax.NewWriter
	_ func([]byte) *syntax.Reader               = syntax.NewReader
	_ func(*syntax.Writer, []Extension) error   = MarshalExtensions
	_ func(*syntax.Reader) ([]Extension, error) = ParseExtensions
)

// TestConsumedCryptoProviderShape pins the CryptoProvider method set this plan calls.
func TestConsumedCryptoProviderShape(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	var (
		_ func([]byte, []byte) []byte                              = crypto.Extract
		_ func([]byte, []byte, int) []byte                         = crypto.Expand
		_ func([]byte, string, []byte, int) []byte                 = crypto.ExpandWithLabel
		_ func([]byte, string) []byte                              = crypto.DeriveSecret
		_ func([]byte, string, uint32, int) []byte                 = crypto.DeriveTreeSecret
		_ func([]byte) []byte                                      = crypto.Hash
		_ func([]byte, []byte) []byte                              = crypto.Mac
		_ func([]byte, []byte, []byte) bool                        = crypto.MacVerify
		_ func() int                                               = crypto.HashSize
		_ func() int                                               = crypto.KeySize
		_ func() int                                               = crypto.NonceSize
		_ func([]byte) (HpkePrivateKey, HpkePublicKey, error)      = crypto.DeriveKeyPair
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

// TestConsumedSyntaxWriterShape pins the syntax reader and writer surface.
func TestConsumedSyntaxWriterShape(t *testing.T) {
	w := syntax.NewWriter()
	var (
		_ func(uint8)          = w.WriteUint8
		_ func(uint16)         = w.WriteUint16
		_ func(uint32)         = w.WriteUint32
		_ func(uint64)         = w.WriteUint64
		_ func([]byte) error   = w.WriteOpaque
		_ func([]byte)         = w.WriteBytes
		_ func() ([]byte, error) = w.Bytes
	)
	w.WriteUint16(0x0001)
	if err := w.WriteOpaque([]byte{0x02, 0x03}); err != nil {
		t.Fatalf("WriteOpaque: %v", err)
	}
	b, err := w.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if len(b) != 5 {
		t.Fatalf("encoded %d bytes, want 5", len(b))
	}
	r := syntax.NewReader(b)
	var (
		_ func() (uint8, error)  = r.ReadUint8
		_ func() (uint16, error) = r.ReadUint16
		_ func() (uint32, error) = r.ReadUint32
		_ func() (uint64, error) = r.ReadUint64
		_ func() ([]byte, error) = r.ReadOpaque
		_ func() error           = r.Done
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

// TestVectorFilesPresent asserts the four vector families this plan gates are vendored.
func TestVectorFilesPresent(t *testing.T) {
	for _, name := range []string{
		"key-schedule.json",
		"psk_secret.json",
		"transcript-hashes.json",
		"secret-tree.json",
	} {
		info, err := os.Stat(filepath.Join("testdata", "vectors", name))
		if err != nil {
			t.Fatalf("vector %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("vector %s is empty", name)
		}
	}
}
```

Add `"os"` and `"path/filepath"` to the import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestConsumed|TestVectorFilesPresent' -v`
Expected: FAIL with `no such file or directory: testdata/vectors/key-schedule.json` (or a compile
error naming the first wave-1 symbol that does not yet exist — in that case the wave-1 plan for that
symbol is not merged yet and this task blocks on it).

- [ ] **Step 3: Vendor the vectors**

```bash
MLSWG=../mls_measure/mls-impl
mkdir -p connect/mls/testdata/vectors
for f in key-schedule.json psk_secret.json transcript-hashes.json secret-tree.json; do
  cp "$MLSWG/test-vectors/$f" "connect/mls/testdata/vectors/$f"
done
git -C "$MLSWG" rev-parse HEAD > /tmp/mlswg-pin.txt
cat /tmp/mlswg-pin.txt
```

If the validation plan has already vendored all sixteen families, this copies identical bytes over
identical files and `git status` shows nothing. That is the intended outcome, not a conflict.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestConsumed|TestVectorFilesPresent' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_deps_test.go connect/mls/testdata/vectors
git ls-files | wc -l
git commit -m "test(mls): pin consumed wave-1 interfaces and vendor key-schedule vector families

mlswg/mls-implementations pinned at $(cat /tmp/mlswg-pin.txt)"
```

---

### Task 2: Typed errors and the zeroize helper

**Files:**
- Create: `connect/mls/errors_key_schedule.go`, `connect/mls/secret_zeroize.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `zeroizeSecret(b []byte)` (unexported), and the fourteen error values listed in the
  interface summary.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_test.go
// tests for the RFC 9420 section 8 key schedule.
package mls

import (
	"encoding/hex"
	"errors"
	"testing"
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
		ErrPskNonceLength,
		ErrPskType,
		ErrDuplicatePsk,
		ErrPskCount,
		ErrSecretTreeLeafOutOfRange,
		ErrSecretTreeConsumed,
		ErrRatchetGenerationConsumed,
		ErrRatchetGenerationTooFarAhead,
		ErrRatchetExhausted,
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

// mustHex decodes a KAT constant transcribed from the pinned mlswg vectors.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestZeroizeSecret|TestKeyScheduleErrorsAreDistinct' -v`
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
package mls

import "errors"

var (
	// ErrSecretLength is returned when a secret supplied to the key schedule is
	// not KDF.Nh bytes. A short secret would otherwise expand into a valid-looking
	// epoch that no peer agrees with.
	ErrSecretLength = errors.New("mls: secret has the wrong length")

	// ErrExportLength is returned when an exporter length exceeds 255*KDF.Nh,
	// which HKDF-Expand cannot produce.
	ErrExportLength = errors.New("mls: exporter length out of range")

	// ErrGroupContextTrailingBytes is returned when a serialized GroupContext has
	// bytes after the extensions vector. MLS signs over serialized forms, so a
	// decoder that tolerated trailing bytes would accept two encodings of one object.
	ErrGroupContextTrailingBytes = errors.New("mls: group context has trailing bytes")

	// ErrTranscriptHashLength is returned when a transcript hash is not KDF.Nh bytes.
	ErrTranscriptHashLength = errors.New("mls: transcript hash has the wrong length")

	// ErrPskNonceLength is RFC 9420 ValSem401.
	ErrPskNonceLength = errors.New("mls: psk nonce is not KDF.Nh bytes")

	// ErrPskType is RFC 9420 ValSem402.
	ErrPskType = errors.New("mls: unsupported psk type or usage")

	// ErrDuplicatePsk is RFC 9420 ValSem403, untested in OpenMLS (openmls#1335).
	ErrDuplicatePsk = errors.New("mls: duplicate PreSharedKeyID")

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

Run: `go test ./connect/mls/... -run 'TestZeroizeSecret|TestKeyScheduleErrorsAreDistinct' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/errors_key_schedule.go connect/mls/secret_zeroize.go connect/mls/key_schedule_test.go
git ls-files | wc -l
git commit -m "feat(mls): typed key schedule errors and best-effort secret zeroization"
```

---

### Task 3: GroupContext and byte-exact Marshal

**Files:**
- Create: `connect/mls/group_context.go`
- Test: `connect/mls/group_context_test.go`

**Interfaces:**
- Consumes: `syntax.NewWriter`, `(*syntax.Writer).WriteUint16/WriteUint64/WriteOpaque/Bytes`,
  `MarshalExtensions(*syntax.Writer, []Extension) error`, `ProtocolVersion`, `ProtocolVersionMls10`,
  `CipherSuite`, `Extension`.
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
  func (self *GroupContext) Marshal() ([]byte, error)
  func (self *GroupContext) Clone() *GroupContext
  ```

- [ ] **Step 1: Write the failing test**

```go
// group_context_test.go
// tests for the RFC 9420 section 8.1 GroupContext.
package mls

import (
	"bytes"
	"testing"
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
		CipherSuite:             CipherSuiteX25519ChaCha20SHA256Ed25519,
		GroupId:                 mustHex(t, ksVectorGroupId),
		Epoch:                   0,
		TreeHash:                mustHex(t, ksVectorTreeHash),
		ConfirmedTranscriptHash: mustHex(t, ksVectorCth),
		Extensions:              nil,
	}
}

// TestGroupContextMarshalKAT pins the field order and the varint prefixes against
// the vector's own group_context bytes. A reordered field or a missing length
// prefix changes every epoch secret, so this is the cheapest place to catch it.
func TestGroupContextMarshalKAT(t *testing.T) {
	encoded, err := ksVectorEpoch0GroupContext(t).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := mustHex(t, ksVectorGroupContext)
	if len(encoded) != 112 {
		t.Fatalf("encoded %d bytes, want 112", len(encoded))
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("Marshal =\n %x\nwant\n %x", encoded, want)
	}
}

// TestGroupContextMarshalEmptyExtensions asserts an empty extension vector encodes
// as the single byte 0x00 and not as an omitted field.
func TestGroupContextMarshalEmptyExtensions(t *testing.T) {
	encoded, err := ksVectorEpoch0GroupContext(t).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if encoded[len(encoded)-1] != 0x00 {
		t.Fatalf("last byte = %#x, want 0x00", encoded[len(encoded)-1])
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

// Marshal encodes the context in the RFC 9420 section 8.1 field order.
func (self *GroupContext) Marshal() ([]byte, error) {
	w := syntax.NewWriter()
	w.WriteUint16(uint16(self.Version))
	w.WriteUint16(uint16(self.CipherSuite))
	if err := w.WriteOpaque(self.GroupId); err != nil {
		return nil, err
	}
	w.WriteUint64(self.Epoch)
	if err := w.WriteOpaque(self.TreeHash); err != nil {
		return nil, err
	}
	if err := w.WriteOpaque(self.ConfirmedTranscriptHash); err != nil {
		return nil, err
	}
	if err := MarshalExtensions(w, self.Extensions); err != nil {
		return nil, err
	}
	return w.Bytes()
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
git commit -m "feat(mls): GroupContext with byte-exact marshalling pinned to the vector"
```

---

### Task 4: ParseGroupContext, round-trip and trailing-byte rejection

**Files:**
- Modify: `connect/mls/group_context.go`
- Test: `connect/mls/group_context_test.go`

**Interfaces:**
- Consumes: `syntax.NewReader`, `(*syntax.Reader).ReadUint16/ReadUint64/ReadOpaque/Done`,
  `ParseExtensions(*syntax.Reader) ([]Extension, error)`.
- Produces: `func ParseGroupContext(data []byte) (*GroupContext, error)`

- [ ] **Step 1: Write the failing test**

```go
// append to group_context_test.go

// TestParseGroupContextRoundTrip asserts decode(encode(x)) == x and that the
// re-encoding is byte-identical. MLS signs over serialized forms, so a decoder
// that accepts two encodings of one object is a signature-bypass primitive.
func TestParseGroupContextRoundTrip(t *testing.T) {
	want := mustHex(t, ksVectorGroupContext)
	parsed, err := ParseGroupContext(want)
	if err != nil {
		t.Fatalf("ParseGroupContext: %v", err)
	}
	if parsed.Version != ProtocolVersionMls10 {
		t.Fatalf("Version = %#x, want %#x", parsed.Version, ProtocolVersionMls10)
	}
	if parsed.CipherSuite != CipherSuiteX25519ChaCha20SHA256Ed25519 {
		t.Fatalf("CipherSuite = %#x, want 0x0003", parsed.CipherSuite)
	}
	if parsed.Epoch != 0 {
		t.Fatalf("Epoch = %d, want 0", parsed.Epoch)
	}
	if len(parsed.Extensions) != 0 {
		t.Fatalf("Extensions = %d, want 0", len(parsed.Extensions))
	}
	reencoded, err := parsed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(reencoded, want) {
		t.Fatalf("round trip =\n %x\nwant\n %x", reencoded, want)
	}
}

// TestParseGroupContextRejectsTrailingBytes asserts a full-consumption failure.
func TestParseGroupContextRejectsTrailingBytes(t *testing.T) {
	data := append(mustHex(t, ksVectorGroupContext), 0x00)
	_, err := ParseGroupContext(data)
	if !errors.Is(err, ErrGroupContextTrailingBytes) {
		t.Fatalf("err = %v, want ErrGroupContextTrailingBytes", err)
	}
}

// TestParseGroupContextRejectsTruncation asserts every prefix of a valid context
// is refused rather than yielding a partly-populated struct.
func TestParseGroupContextRejectsTruncation(t *testing.T) {
	full := mustHex(t, ksVectorGroupContext)
	for n := 0; n < len(full); n++ {
		if _, err := ParseGroupContext(full[:n]); err == nil {
			t.Fatalf("prefix of %d bytes parsed, want an error", n)
		}
	}
}
```

Add `"errors"` to the `group_context_test.go` import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestParseGroupContext -v`
Expected: FAIL to compile with `undefined: ParseGroupContext`.

- [ ] **Step 3: Write minimal implementation**

```go
// append to group_context.go

import "fmt"   // add to the existing import block

// ParseGroupContext decodes a serialized GroupContext and refuses trailing bytes.
func ParseGroupContext(data []byte) (*GroupContext, error) {
	r := syntax.NewReader(data)
	version, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("mls: group context version: %w", err)
	}
	suite, err := r.ReadUint16()
	if err != nil {
		return nil, fmt.Errorf("mls: group context cipher suite: %w", err)
	}
	groupId, err := r.ReadOpaque()
	if err != nil {
		return nil, fmt.Errorf("mls: group context group id: %w", err)
	}
	epoch, err := r.ReadUint64()
	if err != nil {
		return nil, fmt.Errorf("mls: group context epoch: %w", err)
	}
	treeHash, err := r.ReadOpaque()
	if err != nil {
		return nil, fmt.Errorf("mls: group context tree hash: %w", err)
	}
	confirmedTranscriptHash, err := r.ReadOpaque()
	if err != nil {
		return nil, fmt.Errorf("mls: group context confirmed transcript hash: %w", err)
	}
	extensions, err := ParseExtensions(r)
	if err != nil {
		return nil, fmt.Errorf("mls: group context extensions: %w", err)
	}
	if err := r.Done(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGroupContextTrailingBytes, err)
	}
	return &GroupContext{
		Version:                 ProtocolVersion(version),
		CipherSuite:             CipherSuite(suite),
		GroupId:                 groupId,
		Epoch:                   epoch,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedTranscriptHash,
		Extensions:              extensions,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestParseGroupContext -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/group_context.go connect/mls/group_context_test.go
git ls-files | wc -l
git commit -m "feat(mls): ParseGroupContext with full consumption and round-trip stability"
```

---

### Task 5: ZeroSecret and DeriveJoinerSecret

**Files:**
- Create: `connect/mls/key_schedule.go`
- Test: `connect/mls/key_schedule_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Extract(salt, ikm)`, `CryptoProvider.ExpandWithLabel`,
  `CryptoProvider.HashSize`, `(*GroupContext).Marshal`.
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
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
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
		mustHex(t, ksVectorInitialInitSecret),
		mustHex(t, ksVectorCommitSecret),
		ksVectorEpoch0GroupContext(t),
	)
	if err != nil {
		t.Fatalf("DeriveJoinerSecret: %v", err)
	}
	want := mustHex(t, ksVectorJoinerSecret)
	if !bytes.Equal(joiner, want) {
		t.Fatalf("joiner_secret = %x, want %x", joiner, want)
	}
}

// TestDeriveJoinerSecretExtractOrderIsNotSymmetric asserts the swapped call does not
// coincidentally produce the same value, so the KAT above is a real order test.
func TestDeriveJoinerSecretExtractOrderIsNotSymmetric(t *testing.T) {
	crypto := ksTestCrypto(t)
	initSecret := mustHex(t, ksVectorInitialInitSecret)
	commitSecret := mustHex(t, ksVectorCommitSecret)
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
	good := mustHex(t, ksVectorInitialInitSecret)
	if _, err := DeriveJoinerSecret(crypto, good[:31], good, groupContext); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short init secret err = %v, want ErrSecretLength", err)
	}
	if _, err := DeriveJoinerSecret(crypto, good, good[:31], groupContext); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short commit secret err = %v, want ErrSecretLength", err)
	}
}
```

Add `"bytes"` to the `key_schedule_test.go` import block.

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
	encodedGroupContext, err := groupContext.Marshal()
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
- Consumes: `CryptoProvider.Extract`, `CryptoProvider.DeriveSecret`, `CryptoProvider.ExpandWithLabel`,
  `DeriveJoinerSecret` (Task 5), `ZeroSecret` (Task 5).
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
		mustHex(t, ksVectorInitialInitSecret),
		mustHex(t, ksVectorCommitSecret),
		mustHex(t, ksVectorPskSecret),
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
	if !bytes.Equal(schedule.JoinerSecret(), mustHex(t, ksVectorJoinerSecret)) {
		t.Fatalf("joiner_secret = %x", schedule.JoinerSecret())
	}
	if !bytes.Equal(schedule.WelcomeSecret(), mustHex(t, ksVectorWelcomeSecret)) {
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
		if !bytes.Equal(check.got, mustHex(t, check.want)) {
			t.Fatalf("%s = %x, want %s", check.name, check.got, check.want)
		}
	}
}

// TestKeyScheduleGroupContextBytesMatchMarshal asserts the schedule expanded over the
// same bytes the caller would sign over.
func TestKeyScheduleGroupContextBytesMatchMarshal(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	if !bytes.Equal(schedule.GroupContextBytes(), mustHex(t, ksVectorGroupContext)) {
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
		mustHex(t, ksVectorInitialInitSecret),
		mustHex(t, ksVectorCommitSecret),
		mustHex(t, ksVectorPskSecret)[:31],
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
	encodedGroupContext, err := groupContext.Marshal()
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
	pskSecret := mustHex(t, ksVectorPskSecret)

	committer, err := NewKeySchedule(
		crypto,
		mustHex(t, ksVectorInitialInitSecret),
		mustHex(t, ksVectorCommitSecret),
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
	pskSecret := mustHex(t, ksVectorPskSecret)
	good := ksVectorEpoch0GroupContext(t)
	bad := good.Clone()
	bad.Epoch = 1

	right, err := NewKeyScheduleFromJoiner(crypto, mustHex(t, ksVectorJoinerSecret), pskSecret, good)
	if err != nil {
		t.Fatalf("NewKeyScheduleFromJoiner: %v", err)
	}
	wrong, err := NewKeyScheduleFromJoiner(crypto, mustHex(t, ksVectorJoinerSecret), pskSecret, bad)
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
		mustHex(t, ksVectorExporterContext),
		32,
	)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	want := mustHex(t, ksVectorExporterSecretOut)
	if !bytes.Equal(exported, want) {
		t.Fatalf("Export = %x, want %x", exported, want)
	}
}

// TestKeyScheduleExportLabelIsNotHexDecoded asserts that treating the vector's label
// as hex produces a different answer, which is what makes the KAT above meaningful.
func TestKeyScheduleExportLabelIsNotHexDecoded(t *testing.T) {
	schedule := ksVectorEpoch0Schedule(t)
	asString, err := schedule.Export(ksVectorExporterLabel, mustHex(t, ksVectorExporterContext), 32)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	asHex, err := schedule.Export(string(mustHex(t, ksVectorExporterLabel)), mustHex(t, ksVectorExporterContext), 32)
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
  `(HpkePublicKey).Bytes() []byte`.
- Produces: `func (self *KeySchedule) ExternalKeyPair() (HpkePrivateKey, HpkePublicKey, error)`

  **Boundary note for the Group lifecycle plan:** v1 refuses external commits, so `external_pub` MUST
  NOT be published in a `GroupInfo` extension. This function exists so `key-schedule.json` passes and
  so V2 is a policy change rather than a key-schedule change. `TestExternalPubIsNotAdvertised` in the
  lifecycle plan is the counterpart assertion.

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
	want := mustHex(t, ksVectorExternalPub)
	if !bytes.Equal(pub.Bytes(), want) {
		t.Fatalf("external_pub = %x, want %x", pub.Bytes(), want)
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
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
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

  The Framing plan builds `authenticatedContentTbm` (the `AuthenticatedContentTBM` serialization of
  RFC 9420 section 6.1) and passes the bytes; this plan never sees framing types. The Commit plan
  calls `VerifyConfirmationTag` for ValSem205 and `VerifyMembershipTag` for ValSem008, and MUST
  `return` on false rather than logging (guardrail G7).

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

// TestConfirmationTagKAT pins the tag as MAC(confirmation_key, confirmed_transcript_hash).
// The confirmation tag is the fork detector: two members whose transcripts diverged
// produce different tags, and every commit carries one.
func TestConfirmationTagKAT(t *testing.T) {
	crypto := ksTestCrypto(t)
	schedule := ksVectorEpoch0Schedule(t)
	confirmedTranscriptHash := mustHex(t, ksVectorCth)
	want := crypto.Mac(mustHex(t, ksVectorConfirmationKey), confirmedTranscriptHash)
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
	confirmedTranscriptHash := mustHex(t, ksVectorCth)
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
	want := crypto.Mac(mustHex(t, ksVectorMembershipKey), tbm)
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

  The Group lifecycle plan uses this to seal and open `Welcome.encrypted_group_info`. The end-to-end
  check is the `welcome.json` vector family, which lives in that plan; what is pinned here is the
  derivation shape and the output lengths.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_test.go

// TestWelcomeKeyNonceShape pins welcome_key and welcome_nonce as ExpandWithLabel over
// welcome_secret with an empty context, at the suite's AEAD key and nonce sizes.
func TestWelcomeKeyNonceShape(t *testing.T) {
	crypto := ksTestCrypto(t)
	welcomeSecret := mustHex(t, ksVectorWelcomeSecret)
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
	key, nonce, err := WelcomeKeyNonce(ksTestCrypto(t), mustHex(t, ksVectorWelcomeSecret))
	if err != nil {
		t.Fatalf("WelcomeKeyNonce: %v", err)
	}
	if bytes.Equal(key[:len(nonce)], nonce) {
		t.Fatal("welcome key and nonce share a prefix")
	}
}

// TestWelcomeKeyNonceRejectsShortSecret asserts a wrong-length welcome_secret is fatal.
func TestWelcomeKeyNonceRejectsShortSecret(t *testing.T) {
	_, _, err := WelcomeKeyNonce(ksTestCrypto(t), mustHex(t, ksVectorWelcomeSecret)[:16])
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

### Task 13: PreSharedKeyId, its encoding, and ValSem401/402

**Files:**
- Create: `connect/mls/psk.go`
- Test: `connect/mls/psk_test.go`

**Interfaces:**
- Consumes: `syntax.NewWriter`, `syntax.NewReader`, the writer and reader methods pinned in Task 1,
  `CryptoProvider.HashSize`.
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
  func (self *PreSharedKeyId) Marshal() ([]byte, error)
  func ParsePreSharedKeyId(r *syntax.Reader) (*PreSharedKeyId, error)
  func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error
  ```

  **Boundary note for the Proposal and Validation plans:** `proposal.go` refuses the `psk` proposal
  type at parse with `ErrProfilePSK` before any `PreSharedKeyId` is constructed, so those plans need
  only the type name for their commented-out V2 assertions. They must not redefine this type.

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
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
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
	encoded, err := id.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x01, // psktype = external
		0x02, 0xaa, 0xbb, // psk_id<V>
		0x03, 0x01, 0x02, 0x03, // psk_nonce<V>
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("Marshal = %x, want %x", encoded, want)
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
	encoded, err := id.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x02,             // psktype = resumption
		0x01,             // usage = application
		0x01, 0xcc,       // psk_group_id<V>
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // psk_epoch
		0x01, 0x09, // psk_nonce<V>
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("Marshal = %x, want %x", encoded, want)
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
		encoded, err := id.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		r := syntax.NewReader(encoded)
		parsed, err := ParsePreSharedKeyId(r)
		if err != nil {
			t.Fatalf("ParsePreSharedKeyId: %v", err)
		}
		if err := r.Done(); err != nil {
			t.Fatalf("trailing bytes after PreSharedKeyID: %v", err)
		}
		reencoded, err := parsed.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("round trip = %x, want %x", reencoded, encoded)
		}
	}
}

// TestPreSharedKeyIdParseRejectsUnknownType asserts an unknown psktype byte is refused
// rather than parsed as an empty external id.
func TestPreSharedKeyIdParseRejectsUnknownType(t *testing.T) {
	_, err := ParsePreSharedKeyId(syntax.NewReader([]byte{0x07, 0x00}))
	if !errors.Is(err, ErrPskType) {
		t.Fatalf("err = %v, want ErrPskType", err)
	}
}

// TestPreSharedKeyIdValidateNonceLength is ValSem401.
func TestPreSharedKeyIdValidateNonceLength(t *testing.T) {
	crypto := pskTestCrypto(t)
	id := &PreSharedKeyId{PskType: PskTypeExternal, PskId: []byte{1}, PskNonce: make([]byte, 31)}
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

// marshalTo writes the id into an existing writer, so PSKLabel can prefix it.
func (self *PreSharedKeyId) marshalTo(w *syntax.Writer) error {
	w.WriteUint8(uint8(self.PskType))
	switch self.PskType {
	case PskTypeExternal:
		if err := w.WriteOpaque(self.PskId); err != nil {
			return err
		}
	case PskTypeResumption:
		w.WriteUint8(uint8(self.Usage))
		if err := w.WriteOpaque(self.PskGroupId); err != nil {
			return err
		}
		w.WriteUint64(self.PskEpoch)
	default:
		return fmt.Errorf("%w: psktype %d", ErrPskType, self.PskType)
	}
	return w.WriteOpaque(self.PskNonce)
}

// Marshal encodes the id on its own.
func (self *PreSharedKeyId) Marshal() ([]byte, error) {
	w := syntax.NewWriter()
	if err := self.marshalTo(w); err != nil {
		return nil, err
	}
	return w.Bytes()
}

// ParsePreSharedKeyId decodes one id from a reader without consuming what follows.
func ParsePreSharedKeyId(r *syntax.Reader) (*PreSharedKeyId, error) {
	pskType, err := r.ReadUint8()
	if err != nil {
		return nil, fmt.Errorf("mls: psk type: %w", err)
	}
	self := &PreSharedKeyId{PskType: PskType(pskType)}
	switch self.PskType {
	case PskTypeExternal:
		if self.PskId, err = r.ReadOpaque(); err != nil {
			return nil, fmt.Errorf("mls: psk id: %w", err)
		}
	case PskTypeResumption:
		usage, err := r.ReadUint8()
		if err != nil {
			return nil, fmt.Errorf("mls: psk usage: %w", err)
		}
		self.Usage = ResumptionPskUsage(usage)
		if self.PskGroupId, err = r.ReadOpaque(); err != nil {
			return nil, fmt.Errorf("mls: psk group id: %w", err)
		}
		if self.PskEpoch, err = r.ReadUint64(); err != nil {
			return nil, fmt.Errorf("mls: psk epoch: %w", err)
		}
	default:
		return nil, fmt.Errorf("%w: psktype %d", ErrPskType, self.PskType)
	}
	if self.PskNonce, err = r.ReadOpaque(); err != nil {
		return nil, fmt.Errorf("mls: psk nonce: %w", err)
	}
	return self, nil
}

// Validate is ValSem401 (nonce length) and ValSem402 (type and usage).
func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error {
	if len(self.PskNonce) != crypto.HashSize() {
		return fmt.Errorf("%w: %d bytes, want %d", ErrPskNonceLength, len(self.PskNonce), crypto.HashSize())
	}
	switch self.PskType {
	case PskTypeExternal:
		return nil
	case PskTypeResumption:
		if self.Usage != ResumptionPskUsageApplication {
			return fmt.Errorf("%w: resumption usage %d", ErrPskType, self.Usage)
		}
		return nil
	}
	return fmt.Errorf("%w: psktype %d", ErrPskType, self.PskType)
}
```

The `crypto/subtle`, `math` imports are used by Task 14 and Task 15; add them when those tasks land
rather than leaving an unused import now.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestPreSharedKeyId -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/psk.go connect/mls/psk_test.go
git ls-files | wc -l
git commit -m "feat(mls): PreSharedKeyID encoding and the ValSem401/402 checks"
```

---

### Task 14: CheckNoDuplicatePsks — ValSem403

**Files:**
- Modify: `connect/mls/psk.go`
- Test: `connect/mls/psk_test.go`

**Interfaces:**
- Consumes: `(*PreSharedKeyId).Marshal` (Task 13), `crypto/subtle.ConstantTimeCompare`.
- Produces: `func CheckNoDuplicatePsks(ids []PreSharedKeyId) error`

  ValSem403 is untested in OpenMLS (openmls#1335), so differential agreement proves nothing here and
  the RFC text is the only authority.

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

// TestValSem403_NoDuplicatePreSharedKeyIds asserts an exactly repeated id is refused.
func TestValSem403_NoDuplicatePreSharedKeyIds(t *testing.T) {
	ids := []PreSharedKeyId{pskTestId(1, 0xa1), pskTestId(2, 0xa2), pskTestId(1, 0xa1)}
	if err := CheckNoDuplicatePsks(ids); !errors.Is(err, ErrDuplicatePsk) {
		t.Fatalf("err = %v, want ErrDuplicatePsk", err)
	}
}

// TestValSem403_DistinctIdsAreAccepted asserts the check does not over-reject. Two ids
// that share a psk_id but carry different nonces are different PreSharedKeyIDs by the
// RFC's own definition, and refusing them would be a V2 interop break.
func TestValSem403_DistinctIdsAreAccepted(t *testing.T) {
	ids := []PreSharedKeyId{pskTestId(1, 0xa1), pskTestId(1, 0xa2), pskTestId(2, 0xa1)}
	if err := CheckNoDuplicatePsks(ids); err != nil {
		t.Fatalf("distinct ids were refused: %v", err)
	}
}

// TestValSem403_EmptyAndSingleton asserts the degenerate cases are accepted.
func TestValSem403_EmptyAndSingleton(t *testing.T) {
	if err := CheckNoDuplicatePsks(nil); err != nil {
		t.Fatalf("empty list refused: %v", err)
	}
	if err := CheckNoDuplicatePsks([]PreSharedKeyId{pskTestId(1, 0xa1)}); err != nil {
		t.Fatalf("singleton refused: %v", err)
	}
}

// TestValSem403_ResumptionDuplicatesAcrossEpochs asserts the epoch field participates,
// so the same group id at two epochs is not a duplicate.
func TestValSem403_ResumptionDuplicatesAcrossEpochs(t *testing.T) {
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

Run: `go test ./connect/mls/... -run TestValSem403 -v`
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
		b, err := ids[i].Marshal()
		if err != nil {
			return err
		}
		for j, previous := range encoded {
			if len(previous) == len(b) && subtle.ConstantTimeCompare(previous, b) == 1 {
				return fmt.Errorf("%w: entries %d and %d", ErrDuplicatePsk, j, i)
			}
		}
		encoded = append(encoded, b)
	}
	return nil
}
```

Add `"crypto/subtle"` to the `psk.go` import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestValSem403 -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/psk.go connect/mls/psk_test.go
git ls-files | wc -l
git commit -m "feat(mls): ValSem403 duplicate PreSharedKeyID check, untested upstream"
```

---

### Task 15: PSKLabel and PskSecret

**Files:**
- Modify: `connect/mls/psk.go`
- Test: `connect/mls/psk_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Extract`, `CryptoProvider.ExpandWithLabel`, `CryptoProvider.HashSize`,
  `ZeroSecret` (Task 5), `(*PreSharedKeyId).Validate` (Task 13), `CheckNoDuplicatePsks` (Task 14).
- Produces:
  ```go
  type PreSharedKeyInput struct {
      Id     PreSharedKeyId
      Secret []byte
  }
  func PskSecret(crypto CryptoProvider, psks []PreSharedKeyInput) ([]byte, error)
  ```

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
			Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: mustHex(t, pskVectorId0), PskNonce: mustHex(t, pskVectorNonce0)},
			Secret: mustHex(t, pskVectorSecret0),
		},
		{
			Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: mustHex(t, pskVectorId1), PskNonce: mustHex(t, pskVectorNonce1)},
			Secret: mustHex(t, pskVectorSecret1),
		},
	}
	got, err := PskSecret(crypto, psks)
	if err != nil {
		t.Fatalf("PskSecret: %v", err)
	}
	want := mustHex(t, pskVectorSecret)
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

// TestPskSecretOrderMatters asserts the index and count fields bind position, so a
// reordered list is a different psk_secret and a reordering attack is detectable.
func TestPskSecretOrderMatters(t *testing.T) {
	crypto := pskTestCrypto(t)
	first := PreSharedKeyInput{
		Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: mustHex(t, pskVectorId0), PskNonce: mustHex(t, pskVectorNonce0)},
		Secret: mustHex(t, pskVectorSecret0),
	}
	second := PreSharedKeyInput{
		Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: mustHex(t, pskVectorId1), PskNonce: mustHex(t, pskVectorNonce1)},
		Secret: mustHex(t, pskVectorSecret1),
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
		Id:     PreSharedKeyId{PskType: PskTypeExternal, PskId: mustHex(t, pskVectorId0), PskNonce: mustHex(t, pskVectorNonce0)},
		Secret: mustHex(t, pskVectorSecret0),
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
func marshalPskLabel(id *PreSharedKeyId, index uint16, count uint16) ([]byte, error) {
	w := syntax.NewWriter()
	if err := id.marshalTo(w); err != nil {
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
```

Add `"math"` to the `psk.go` import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestPskSecret -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/psk.go connect/mls/psk_test.go
git ls-files | wc -l
git commit -m "feat(mls): psk_secret recurrence with PSKLabel index and count binding"
```

---

### Task 16: The vector-loading helpers and the psk_secret runner

**Files:**
- Create: `connect/mls/key_schedule_vectors_test.go`

**Interfaces:**
- Consumes: `PskSecret` (Task 15), `NewCryptoProvider`, the vendored `testdata/vectors/psk_secret.json`.
- Produces (test-only, used by Tasks 17, 19, 20, 25):
  ```go
  type ksHex []byte
  func (self *ksHex) UnmarshalJSON(data []byte) error
  func (self ksHex) MarshalJSON() ([]byte, error)
  func ksLoadVectors(t *testing.T, family string, out any)
  func ksImplementedSuite(suite uint16) (CipherSuite, bool)
  ```

  These are prefixed `ks` so they cannot collide with equivalents the Validation and interop plan
  defines in the same package during parallel waves. Collapsing them into one shared helper is a
  follow-up after both waves land, not a blocker for either.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_vectors_test.go
// runners for the mlswg key-schedule and psk_secret vector families.
package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ksHex decodes the hex strings the mlswg vector files use for binary fields.
type ksHex []byte

func (self *ksHex) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*self = b
	return nil
}

func (self ksHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(self))
}

// ksLoadVectors reads one vendored vector family.
func ksLoadVectors(t *testing.T, family string, out any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors", family))
	if err != nil {
		t.Fatalf("read %s: %v", family, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("parse %s: %v", family, err)
	}
}

// ksImplementedSuite maps a vector's cipher_suite to a provider we implement.
// The vector files cover suites 1 through 7; v1 implements 0x0001 and 0x0003, so the
// other five are skipped. Every runner counts what it ran and what it skipped, so a
// registry regression that made both suites unavailable fails instead of passing
// vacuously with zero cases.
func ksImplementedSuite(suite uint16) (CipherSuite, bool) {
	switch CipherSuite(suite) {
	case CipherSuiteX25519AES128SHA256Ed25519:
		return CipherSuiteX25519AES128SHA256Ed25519, true
	case CipherSuiteX25519ChaCha20SHA256Ed25519:
		return CipherSuiteX25519ChaCha20SHA256Ed25519, true
	}
	return 0, false
}

// pskSecretVector is one entry of psk_secret.json.
type pskSecretVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	Psks        []struct {
		PskId    ksHex `json:"psk_id"`
		Psk      ksHex `json:"psk"`
		PskNonce ksHex `json:"psk_nonce"`
	} `json:"psks"`
	PskSecret ksHex `json:"psk_secret"`
}

// TestVectorPskSecret is vector family 6. Retained even though PSK proposals are
// profile-refused: psk_secret is computed on every epoch as the empty case, and the
// non-empty cases are the only check on the PSKLabel encoding.
func TestVectorPskSecret(t *testing.T) {
	var vectors []pskSecretVector
	ksLoadVectors(t, "psk_secret.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("psk_secret.json is empty")
	}

	ran, skipped := 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, vector := range vectors {
		suite, ok := ksImplementedSuite(vector.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("vector %d: NewCryptoProvider(%#x): %v", i, suite, err)
		}
		psks := make([]PreSharedKeyInput, 0, len(vector.Psks))
		for _, entry := range vector.Psks {
			psks = append(psks, PreSharedKeyInput{
				Id: PreSharedKeyId{
					PskType:  PskTypeExternal,
					PskId:    entry.PskId,
					PskNonce: entry.PskNonce,
				},
				Secret: entry.Psk,
			})
		}
		got, err := PskSecret(crypto, psks)
		if err != nil {
			t.Fatalf("vector %d (%d psks): PskSecret: %v", i, len(psks), err)
		}
		if !bytes.Equal(got, vector.PskSecret) {
			t.Fatalf("vector %d (%d psks): psk_secret = %x, want %x", i, len(psks), got, []byte(vector.PskSecret))
		}
		ran++
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no psk_secret vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AES128SHA256Ed25519] == 0 {
		t.Fatal("no psk_secret vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20SHA256Ed25519] == 0 {
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

Run: `go test ./connect/mls/... -run TestVectorPskSecret -v`
Expected: PASS, with a log line reporting 22 vectors run and 55 skipped.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): psk_secret vector family with per-suite coverage accounting"
```

---

### Task 17: The key-schedule vector runner

**Files:**
- Modify: `connect/mls/key_schedule_vectors_test.go`

**Interfaces:**
- Consumes: `NewKeySchedule`, `(*KeySchedule).Export`, `(*KeySchedule).ExternalKeyPair`,
  `(*GroupContext).Marshal`, `ksLoadVectors`, `ksImplementedSuite` (Task 16).
- Produces: nothing. Closes gate `key-schedule`.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_vectors_test.go

// keyScheduleVector is one entry of key-schedule.json.
type keyScheduleVector struct {
	CipherSuite       uint16              `json:"cipher_suite"`
	GroupId           ksHex               `json:"group_id"`
	InitialInitSecret ksHex               `json:"initial_init_secret"`
	Epochs            []keyScheduleEpoch  `json:"epochs"`
}

// keyScheduleEpoch is one epoch of a key-schedule vector.
type keyScheduleEpoch struct {
	TreeHash                ksHex `json:"tree_hash"`
	CommitSecret            ksHex `json:"commit_secret"`
	PskSecret               ksHex `json:"psk_secret"`
	ConfirmedTranscriptHash ksHex `json:"confirmed_transcript_hash"`
	GroupContext            ksHex `json:"group_context"`
	JoinerSecret            ksHex `json:"joiner_secret"`
	WelcomeSecret           ksHex `json:"welcome_secret"`
	InitSecret              ksHex `json:"init_secret"`
	SenderDataSecret        ksHex `json:"sender_data_secret"`
	EncryptionSecret        ksHex `json:"encryption_secret"`
	ExporterSecret          ksHex `json:"exporter_secret"`
	EpochAuthenticator      ksHex `json:"epoch_authenticator"`
	ExternalSecret          ksHex `json:"external_secret"`
	ConfirmationKey         ksHex `json:"confirmation_key"`
	MembershipKey           ksHex `json:"membership_key"`
	ResumptionPsk           ksHex `json:"resumption_psk"`
	ExternalPub             ksHex `json:"external_pub"`
	Exporter                struct {
		Label   string `json:"label"`
		Context ksHex  `json:"context"`
		Length  int    `json:"length"`
		Secret  ksHex  `json:"secret"`
	} `json:"exporter"`
}

// TestVectorKeySchedule is vector family 5. The chain is carried forward with OUR
// init_secret rather than re-seeded from the vector at each epoch, so a divergence
// surfaces at the epoch that caused it instead of being masked by the next reseed.
func TestVectorKeySchedule(t *testing.T) {
	var vectors []keyScheduleVector
	ksLoadVectors(t, "key-schedule.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("key-schedule.json is empty")
	}

	ran, skipped, epochs := 0, 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, vector := range vectors {
		suite, ok := ksImplementedSuite(vector.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("vector %d: NewCryptoProvider(%#x): %v", i, suite, err)
		}

		initSecret := []byte(vector.InitialInitSecret)
		for n, epoch := range vector.Epochs {
			groupContext := &GroupContext{
				Version:                 ProtocolVersionMls10,
				CipherSuite:             suite,
				GroupId:                 vector.GroupId,
				Epoch:                   uint64(n),
				TreeHash:                epoch.TreeHash,
				ConfirmedTranscriptHash: epoch.ConfirmedTranscriptHash,
				Extensions:              nil,
			}
			encoded, err := groupContext.Marshal()
			if err != nil {
				t.Fatalf("vector %d epoch %d: Marshal: %v", i, n, err)
			}
			if !bytes.Equal(encoded, epoch.GroupContext) {
				t.Fatalf("vector %d epoch %d: group_context = %x, want %x", i, n, encoded, []byte(epoch.GroupContext))
			}

			schedule, err := NewKeySchedule(crypto, initSecret, epoch.CommitSecret, epoch.PskSecret, groupContext)
			if err != nil {
				t.Fatalf("vector %d epoch %d: NewKeySchedule: %v", i, n, err)
			}
			secrets := schedule.Secrets()
			for _, check := range []struct {
				name string
				got  []byte
				want []byte
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
				if !bytes.Equal(check.got, check.want) {
					t.Fatalf("vector %d epoch %d: %s = %x, want %x", i, n, check.name, check.got, check.want)
				}
			}

			_, externalPub, err := schedule.ExternalKeyPair()
			if err != nil {
				t.Fatalf("vector %d epoch %d: ExternalKeyPair: %v", i, n, err)
			}
			if !bytes.Equal(externalPub.Bytes(), epoch.ExternalPub) {
				t.Fatalf("vector %d epoch %d: external_pub = %x, want %x", i, n, externalPub.Bytes(), []byte(epoch.ExternalPub))
			}

			exported, err := schedule.Export(epoch.Exporter.Label, epoch.Exporter.Context, epoch.Exporter.Length)
			if err != nil {
				t.Fatalf("vector %d epoch %d: Export: %v", i, n, err)
			}
			if !bytes.Equal(exported, epoch.Exporter.Secret) {
				t.Fatalf("vector %d epoch %d: exporter = %x, want %x", i, n, exported, []byte(epoch.Exporter.Secret))
			}

			// carry our own init_secret forward, not the vector's
			initSecret = append([]byte(nil), secrets.InitSecret...)
			epochs++
		}
		ran++
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no key-schedule vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AES128SHA256Ed25519] == 0 {
		t.Fatal("no key-schedule vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20SHA256Ed25519] == 0 {
		t.Fatal("no key-schedule vector ran at ciphersuite 0x0003")
	}
	t.Logf("key-schedule: ran %d vectors covering %d epochs, skipped %d unimplemented suites", ran, epochs, skipped)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorKeySchedule -v`
Expected: PASS if Tasks 3–9 are correct. If it FAILs, the message names the vector, the epoch and the
first secret that diverged. `group_context` failing first means the codec, not the schedule.

- [ ] **Step 3: Write minimal implementation**

No production change expected. If the exporter check is the only failure, the label is being
hex-decoded somewhere — the field is a string, and Task 8's `TestKeyScheduleExportLabelIsNotHexDecoded`
is the unit-level version of the same assertion.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestVectorKeySchedule -v`
Expected: PASS, with a log line reporting 2 vectors covering 10 epochs and 5 skipped suites.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): key-schedule vector family, chained on our own init_secret"
```

---

### Task 18: The generate direction, verified through an independent KDFLabel encoder

**Files:**
- Modify: `connect/mls/key_schedule_vectors_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Expand`, `CryptoProvider.Extract`, `CryptoProvider.Random`,
  `NewKeySchedule`.
- Produces: nothing. Satisfies Spec A section 4.2.1's "both directions" requirement for family 5.

  The independent path is a second KDFLabel encoder written in the test file with
  `encoding/binary` and a hand-written MLS varint, so a bug where `ExpandWithLabel` and the vector
  reader agree on a wrong encoding is visible. Verification against the vendored file alone cannot
  see that class, because the vector never round-trips through our encoder.

- [ ] **Step 1: Write the failing test**

```go
// append to key_schedule_vectors_test.go

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

// TestVectorKeyScheduleGenerate is the generate direction of family 5: build a fresh
// epoch from random inputs, serialize it in the mlswg format, read it back, and verify
// it through a second KDFLabel encoder. If our ExpandWithLabel encodes the label
// wrongly, the two paths disagree here even though the vendored vector passes.
func TestVectorKeyScheduleGenerate(t *testing.T) {
	for _, suite := range []CipherSuite{
		CipherSuiteX25519AES128SHA256Ed25519,
		CipherSuiteX25519ChaCha20SHA256Ed25519,
	} {
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
		}
		nh := crypto.HashSize()
		vector := keyScheduleVector{
			CipherSuite:       uint16(suite),
			GroupId:           crypto.Random(16),
			InitialInitSecret: crypto.Random(nh),
		}
		initSecret := []byte(vector.InitialInitSecret)
		for n := 0; n < 3; n++ {
			epoch := keyScheduleEpoch{
				TreeHash:                crypto.Random(nh),
				CommitSecret:            crypto.Random(nh),
				PskSecret:               crypto.Random(nh),
				ConfirmedTranscriptHash: crypto.Random(nh),
			}
			groupContext := &GroupContext{
				Version:                 ProtocolVersionMls10,
				CipherSuite:             suite,
				GroupId:                 vector.GroupId,
				Epoch:                   uint64(n),
				TreeHash:                epoch.TreeHash,
				ConfirmedTranscriptHash: epoch.ConfirmedTranscriptHash,
			}
			encoded, err := groupContext.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			schedule, err := NewKeySchedule(crypto, initSecret, epoch.CommitSecret, epoch.PskSecret, groupContext)
			if err != nil {
				t.Fatalf("NewKeySchedule: %v", err)
			}
			secrets := schedule.Secrets()
			epoch.GroupContext = encoded
			epoch.JoinerSecret = schedule.JoinerSecret()
			epoch.WelcomeSecret = schedule.WelcomeSecret()
			epoch.SenderDataSecret = secrets.SenderData
			epoch.EncryptionSecret = secrets.Encryption
			epoch.ExporterSecret = secrets.Exporter
			epoch.ExternalSecret = secrets.External
			epoch.ConfirmationKey = secrets.Confirmation
			epoch.MembershipKey = secrets.Membership
			epoch.ResumptionPsk = secrets.ResumptionPsk
			epoch.EpochAuthenticator = secrets.EpochAuthenticator
			epoch.InitSecret = secrets.InitSecret
			vector.Epochs = append(vector.Epochs, epoch)
			initSecret = append([]byte(nil), secrets.InitSecret...)
		}

		serialized, err := json.Marshal([]keyScheduleVector{vector})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		var readBack []keyScheduleVector
		if err := json.Unmarshal(serialized, &readBack); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if len(readBack) != 1 || len(readBack[0].Epochs) != 3 {
			t.Fatalf("round trip lost epochs: %d", len(readBack))
		}

		// verify through the independent encoder
		independentInit := []byte(readBack[0].InitialInitSecret)
		for n, epoch := range readBack[0].Epochs {
			prk := crypto.Extract(independentInit, epoch.CommitSecret)
			joiner := ksIndependentExpandWithLabel(t, crypto, prk, "joiner", epoch.GroupContext, nh)
			if !bytes.Equal(joiner, epoch.JoinerSecret) {
				t.Fatalf("suite %#x epoch %d: independent joiner_secret = %x, want %x", suite, n, joiner, []byte(epoch.JoinerSecret))
			}
			member := crypto.Extract(joiner, epoch.PskSecret)
			welcome := ksIndependentDeriveSecret(t, crypto, member, "welcome")
			if !bytes.Equal(welcome, epoch.WelcomeSecret) {
				t.Fatalf("suite %#x epoch %d: independent welcome_secret = %x, want %x", suite, n, welcome, []byte(epoch.WelcomeSecret))
			}
			epochSecret := ksIndependentExpandWithLabel(t, crypto, member, "epoch", epoch.GroupContext, nh)
			for _, check := range []struct {
				label string
				want  []byte
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
				if !bytes.Equal(got, check.want) {
					t.Fatalf("suite %#x epoch %d: independent %q = %x, want %x", suite, n, check.label, got, check.want)
				}
			}
			independentInit = append([]byte(nil), epoch.InitSecret...)
		}

		if out := os.Getenv("URMESSAGE_MLS_VECTOR_OUT"); out != "" {
			path := filepath.Join(out, fmt.Sprintf("key-schedule-generated-%04x.json", uint16(suite)))
			if err := os.WriteFile(path, serialized, 0o644); err != nil {
				t.Fatalf("write %s: %v", path, err)
			}
			t.Logf("wrote %s for the OpenMLS cross-check job", path)
		}
	}
}
```

Add `"encoding/binary"` and `"fmt"` to the `key_schedule_vectors_test.go` import block.

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
git add connect/mls/key_schedule_vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): key-schedule generate direction with a second KDFLabel encoder"
```

---

### Task 19: Transcript hashes

**Files:**
- Create: `connect/mls/transcript.go`
- Test: `connect/mls/transcript_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.Hash`, `CryptoProvider.HashSize`, `syntax.NewWriter`,
  `(*syntax.Writer).WriteOpaque`, `(*syntax.Writer).Bytes`.
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

  **Boundary note for the Framing plan:** `confirmedTranscriptHashInput` is the serialized
  `ConfirmedTranscriptHashInput { WireFormat wire_format; FramedContent content; opaque signature<V>; }`.
  This package deliberately takes it as bytes so no framing type crosses the boundary and the
  transcript arithmetic can be audited on its own. Framing produces those bytes; group lifecycle
  passes the confirmation tag it computed from `KeySchedule.ConfirmationTag`.

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
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
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
	if err := w.WriteOpaque(confirmationTag); err != nil {
		return nil, err
	}
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
- Create: `connect/mls/transcript_vectors_test.go`

**Interfaces:**
- Consumes: `ConfirmedTranscriptHash`, `InterimTranscriptHash` (Task 19), `ksHex`, `ksLoadVectors`,
  `ksImplementedSuite` (Task 16), `CryptoProvider.MacVerify`.
- Produces: nothing. Closes gate `transcript-hashes`.

  The vector supplies a serialized `AuthenticatedContent`. For a commit that is
  `wire_format || FramedContent || signature || confirmation_tag`, so
  `ConfirmedTranscriptHashInput` is the prefix and `InterimTranscriptHashInput` is the trailing
  `opaque<V>` MAC. The split is taken at `len(ac) - (1 + KDF.Nh)` and then **checked**: the recovered
  tag must verify as `MAC(confirmation_key, confirmed_transcript_hash_after)`, which is the vector's
  own stated verification step. A wrong split fails that MAC, so the split is self-validating rather
  than assumed. When the Framing plan lands `ParseAuthenticatedContent`, this helper is replaced by a
  call to it and the MAC check stays.

- [ ] **Step 1: Write the failing test**

```go
// transcript_vectors_test.go
// runner for the mlswg transcript-hashes vector family.
package mls

import (
	"bytes"
	"testing"
)

// transcriptHashVector is one entry of transcript-hashes.json.
type transcriptHashVector struct {
	CipherSuite                  uint16 `json:"cipher_suite"`
	ConfirmationKey              ksHex  `json:"confirmation_key"`
	AuthenticatedContent         ksHex  `json:"authenticated_content"`
	InterimTranscriptHashBefore  ksHex  `json:"interim_transcript_hash_before"`
	ConfirmedTranscriptHashAfter ksHex  `json:"confirmed_transcript_hash_after"`
	InterimTranscriptHashAfter   ksHex  `json:"interim_transcript_hash_after"`
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

// TestVectorTranscriptHashes is vector family 7.
func TestVectorTranscriptHashes(t *testing.T) {
	var vectors []transcriptHashVector
	ksLoadVectors(t, "transcript-hashes.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("transcript-hashes.json is empty")
	}

	ran, skipped := 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, vector := range vectors {
		suite, ok := ksImplementedSuite(vector.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("vector %d: NewCryptoProvider(%#x): %v", i, suite, err)
		}

		confirmedInput, confirmationTag := trSplitCommitAuthenticatedContent(t, crypto, vector.AuthenticatedContent)

		// the vector's own verification step, and the check that makes the split honest
		if !crypto.MacVerify(vector.ConfirmationKey, vector.ConfirmedTranscriptHashAfter, confirmationTag) {
			t.Fatalf("vector %d: the recovered confirmation tag does not verify against confirmed_transcript_hash_after", i)
		}

		confirmed := ConfirmedTranscriptHash(crypto, vector.InterimTranscriptHashBefore, confirmedInput)
		if !bytes.Equal(confirmed, vector.ConfirmedTranscriptHashAfter) {
			t.Fatalf("vector %d: confirmed_transcript_hash_after = %x, want %x", i, confirmed, []byte(vector.ConfirmedTranscriptHashAfter))
		}
		interim, err := InterimTranscriptHash(crypto, confirmed, confirmationTag)
		if err != nil {
			t.Fatalf("vector %d: InterimTranscriptHash: %v", i, err)
		}
		if !bytes.Equal(interim, vector.InterimTranscriptHashAfter) {
			t.Fatalf("vector %d: interim_transcript_hash_after = %x, want %x", i, interim, []byte(vector.InterimTranscriptHashAfter))
		}

		// the same result through the stateful API the group uses
		hashes := &TranscriptHashes{
			Confirmed: nil,
			Interim:   vector.InterimTranscriptHashBefore,
		}
		if err := hashes.Update(crypto, confirmedInput, confirmationTag); err != nil {
			t.Fatalf("vector %d: Update: %v", i, err)
		}
		if !bytes.Equal(hashes.Confirmed, vector.ConfirmedTranscriptHashAfter) {
			t.Fatalf("vector %d: Update produced a different confirmed hash", i)
		}
		if !bytes.Equal(hashes.Interim, vector.InterimTranscriptHashAfter) {
			t.Fatalf("vector %d: Update produced a different interim hash", i)
		}

		ran++
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no transcript-hashes vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AES128SHA256Ed25519] == 0 {
		t.Fatal("no transcript-hashes vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20SHA256Ed25519] == 0 {
		t.Fatal("no transcript-hashes vector ran at ciphersuite 0x0003")
	}
	t.Logf("transcript-hashes: ran %d, skipped %d unimplemented suites", ran, skipped)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorTranscriptHashes -v`
Expected: FAIL to compile before Step 1 is saved. After saving: PASS. A failure at "the recovered
confirmation tag does not verify" means the split assumption is wrong for this vector — do not adjust
the offset by trial and error; wait for `ParseAuthenticatedContent` from the Framing plan and use it.

- [ ] **Step 3: Write minimal implementation**

No production change expected. A mismatch on `confirmed_transcript_hash_after` while the MAC check
passed means `ConfirmedTranscriptHash` inserted a separator between the two inputs; remove it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestVectorTranscriptHashes -v`
Expected: PASS, with a log line reporting 2 run and 5 skipped.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/transcript_vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): transcript-hashes vector family with a self-validating content split"
```

---

### Task 21: The secret tree, its descent and its deletions

**Files:**
- Create: `connect/mls/secret_tree.go`
- Test: `connect/mls/secret_tree_test.go`

**Interfaces:**
- Consumes: `Root(LeafIndex) NodeIndex`, `Left(NodeIndex) (NodeIndex, error)`,
  `Right(NodeIndex) (NodeIndex, error)`, `Level(NodeIndex) uint32`, `NodeWidth(LeafIndex) NodeIndex`,
  `LeafIndex.NodeIndex()`, `CryptoProvider.ExpandWithLabel`, `CryptoProvider.HashSize`,
  `zeroizeSecret` (Task 2).
- Produces:
  ```go
  type SecretTree struct{ /* unexported, guarded by stateLock */ }
  func NewSecretTree(crypto CryptoProvider, leafCount LeafIndex, encryptionSecret []byte) (*SecretTree, error)
  func (self *SecretTree) LeafCount() LeafIndex
  ```
  plus the unexported `takeLeafSecret` this task's tests reach through the exported surface of Task 22.

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
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
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
	good := mustHex(t, stVectorEncryptionSecret)
	if _, err := NewSecretTree(crypto, 8, good[:31]); !errors.Is(err, ErrSecretLength) {
		t.Fatalf("short encryption secret err = %v, want ErrSecretLength", err)
	}
	if _, err := NewSecretTree(crypto, 0, good); !errors.Is(err, ErrSecretTreeLeafOutOfRange) {
		t.Fatalf("zero leaf count err = %v, want ErrSecretTreeLeafOutOfRange", err)
	}
}

// TestSecretTreeLeafCount asserts the accessor reports what was built.
func TestSecretTreeLeafCount(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
	if err != nil {
		t.Fatalf("NewSecretTree: %v", err)
	}
	if tree.LeafCount() != 8 {
		t.Fatalf("LeafCount = %d, want 8", tree.LeafCount())
	}
}

// TestSecretTreeSingleLeafRootIsTheLeaf asserts that in a one-leaf tree the root node
// and leaf 0 are the same node, so the encryption secret is the leaf secret with no
// intervening "tree"/"left" derivation.
func TestSecretTreeSingleLeafRootIsTheLeaf(t *testing.T) {
	crypto := stTestCrypto(t)
	encryptionSecret := mustHex(t, stVectorEncryptionSecret)
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
	encryptionSecret := mustHex(t, stVectorEncryptionSecret)
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
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
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
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
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
	leafCount LeafIndex
	width     NodeIndex
	root      NodeIndex
	nodes     map[NodeIndex][]byte
	ratchets  map[ratchetKey]*ratchet
}

// ratchetKey identifies one leaf's handshake or application ratchet.
type ratchetKey struct {
	leaf LeafIndex
	kind RatchetType
}

// NewSecretTree seeds the tree with encryption_secret at the root.
func NewSecretTree(crypto CryptoProvider, leafCount LeafIndex, encryptionSecret []byte) (*SecretTree, error) {
	if leafCount == 0 {
		return nil, fmt.Errorf("%w: leaf count is zero", ErrSecretTreeLeafOutOfRange)
	}
	if len(encryptionSecret) != crypto.HashSize() {
		return nil, fmt.Errorf("%w: encryption secret is %d bytes, want %d",
			ErrSecretLength, len(encryptionSecret), crypto.HashSize())
	}
	root := Root(leafCount)
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
func (self *SecretTree) LeafCount() LeafIndex {
	return self.leafCount
}

// pathToLeaf returns the node indices from the root down to the leaf, inclusive.
// The array representation is in-order, so a target index below the current node is
// in the left subtree. That is the whole descent rule and it needs no parent lookups.
func (self *SecretTree) pathToLeaf(leaf LeafIndex) ([]NodeIndex, error) {
	if leaf >= self.leafCount {
		return nil, fmt.Errorf("%w: leaf %d of %d", ErrSecretTreeLeafOutOfRange, leaf, self.leafCount)
	}
	target := leaf.NodeIndex()
	if target >= self.width {
		return nil, fmt.Errorf("%w: node %d of width %d", ErrSecretTreeLeafOutOfRange, target, self.width)
	}
	path := []NodeIndex{self.root}
	current := self.root
	for Level(current) > 0 {
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
		if left < self.width {
			self.nodes[left] = self.crypto.ExpandWithLabel(parentSecret, "tree", []byte("left"), nh)
		}
		if right < self.width {
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
	encryptionSecret := mustHex(t, stVectorEncryptionSecret)
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
	tree, err := NewSecretTree(crypto, 1, mustHex(t, stVectorEncryptionSecret))
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
	tree, err := NewSecretTree(crypto, 1, mustHex(t, stVectorEncryptionSecret))
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
	tree, err := NewSecretTree(stTestCrypto(t), 1, mustHex(t, stVectorEncryptionSecret))
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

  **Boundary note for the Framing plan:** `NextSenderKey` is the encrypt path for our own leaf;
  `ReceiverKey` is the decrypt path for every other leaf. `ErrRatchetGenerationTooFarAhead` and
  `ErrRatchetGenerationConsumed` are surfaced to the product as a visible gap, never swallowed —
  the equivalent of `connect/message`'s `Kind == "gap"` (Spec A section 5.5). They are not ValSem006:
  ValSem006 is the AEAD failing, this is the key never having existed.

- [ ] **Step 1: Write the failing test**

```go
// append to secret_tree_test.go

// TestNextSenderKeyAdvances asserts the sender path hands out consecutive generations
// and never repeats one.
func TestNextSenderKeyAdvances(t *testing.T) {
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
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
	encryptionSecret := mustHex(t, stVectorEncryptionSecret)

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
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
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
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
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
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
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
	tree, err := NewSecretTree(stTestCrypto(t), 8, mustHex(t, stVectorEncryptionSecret))
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

  The Framing plan calls this to seal and open `PrivateMessage.encrypted_sender_data`. It lives here
  rather than in `framing.go` because `secret-tree.json` checks it and because it is a key-schedule
  derivation, not a message structure.

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
		mustHex(t, stVectorSenderDataSecret),
		mustHex(t, stVectorSenderDataCt),
	)
	if err != nil {
		t.Fatalf("SenderDataKeyNonce: %v", err)
	}
	if !bytes.Equal(key, mustHex(t, stVectorSenderDataKey)) {
		t.Fatalf("sender_data_key = %x", key)
	}
	if !bytes.Equal(nonce, mustHex(t, stVectorSenderDataNonce)) {
		t.Fatalf("sender_data_nonce = %x", nonce)
	}
}

// TestSenderDataKeyNonceSamplesFirstNhBytes asserts only the first KDF.Nh bytes of the
// ciphertext enter the derivation, so appending to a long ciphertext changes nothing.
func TestSenderDataKeyNonceSamplesFirstNhBytes(t *testing.T) {
	crypto := stTestCrypto(t)
	secret := mustHex(t, stVectorSenderDataSecret)
	full := mustHex(t, stVectorSenderDataCt)
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
	_, _, err := SenderDataKeyNonce(stTestCrypto(t), mustHex(t, stVectorSenderDataSecret)[:16], []byte{1})
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
- Create: `connect/mls/secret_tree_vectors_test.go`

**Interfaces:**
- Consumes: `NewSecretTree`, `ReceiverKey`, `SenderDataKeyNonce` (Tasks 21–24), `ksHex`,
  `ksLoadVectors`, `ksImplementedSuite` (Task 16).
- Produces: nothing. Closes gate `secret-tree`.

- [ ] **Step 1: Write the failing test**

```go
// secret_tree_vectors_test.go
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
		SenderDataSecret ksHex `json:"sender_data_secret"`
		Ciphertext       ksHex `json:"ciphertext"`
		Key              ksHex `json:"key"`
		Nonce            ksHex `json:"nonce"`
	} `json:"sender_data"`
	EncryptionSecret ksHex                    `json:"encryption_secret"`
	Leaves           [][]secretTreeGeneration `json:"leaves"`
}

// secretTreeGeneration is one generation of one leaf.
type secretTreeGeneration struct {
	Generation      uint32 `json:"generation"`
	HandshakeKey    ksHex  `json:"handshake_key"`
	HandshakeNonce  ksHex  `json:"handshake_nonce"`
	ApplicationKey  ksHex  `json:"application_key"`
	ApplicationNonce ksHex `json:"application_nonce"`
}

// TestVectorSecretTree is vector family 3. The generations in each leaf are 0 and 15,
// so the receiver path's forward skip is exercised as well as the base case.
func TestVectorSecretTree(t *testing.T) {
	var vectors []secretTreeVector
	ksLoadVectors(t, "secret-tree.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("secret-tree.json is empty")
	}

	ran, skipped, leaves := 0, 0, 0
	suitesSeen := map[CipherSuite]int{}
	for i, vector := range vectors {
		suite, ok := ksImplementedSuite(vector.CipherSuite)
		if !ok {
			skipped++
			continue
		}
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("vector %d: NewCryptoProvider(%#x): %v", i, suite, err)
		}

		key, nonce, err := SenderDataKeyNonce(crypto, vector.SenderData.SenderDataSecret, vector.SenderData.Ciphertext)
		if err != nil {
			t.Fatalf("vector %d: SenderDataKeyNonce: %v", i, err)
		}
		if !bytes.Equal(key, vector.SenderData.Key) {
			t.Fatalf("vector %d: sender_data key = %x, want %x", i, key, []byte(vector.SenderData.Key))
		}
		if !bytes.Equal(nonce, vector.SenderData.Nonce) {
			t.Fatalf("vector %d: sender_data nonce = %x, want %x", i, nonce, []byte(vector.SenderData.Nonce))
		}

		leafCount := LeafIndex(len(vector.Leaves))
		// each ratchet type gets its own tree, because ReceiverKey consumes a
		// generation and the vector asks for the same generations of both types
		handshakeTree, err := NewSecretTree(crypto, leafCount, vector.EncryptionSecret)
		if err != nil {
			t.Fatalf("vector %d: NewSecretTree: %v", i, err)
		}
		applicationTree, err := NewSecretTree(crypto, leafCount, vector.EncryptionSecret)
		if err != nil {
			t.Fatalf("vector %d: NewSecretTree: %v", i, err)
		}

		for leaf, generations := range vector.Leaves {
			for _, want := range generations {
				gotKey, gotNonce, err := handshakeTree.ReceiverKey(LeafIndex(leaf), RatchetHandshake, want.Generation)
				if err != nil {
					t.Fatalf("vector %d leaf %d generation %d: handshake: %v", i, leaf, want.Generation, err)
				}
				if !bytes.Equal(gotKey, want.HandshakeKey) {
					t.Fatalf("vector %d leaf %d generation %d: handshake_key = %x, want %x",
						i, leaf, want.Generation, gotKey, []byte(want.HandshakeKey))
				}
				if !bytes.Equal(gotNonce, want.HandshakeNonce) {
					t.Fatalf("vector %d leaf %d generation %d: handshake_nonce = %x, want %x",
						i, leaf, want.Generation, gotNonce, []byte(want.HandshakeNonce))
				}

				gotKey, gotNonce, err = applicationTree.ReceiverKey(LeafIndex(leaf), RatchetApplication, want.Generation)
				if err != nil {
					t.Fatalf("vector %d leaf %d generation %d: application: %v", i, leaf, want.Generation, err)
				}
				if !bytes.Equal(gotKey, want.ApplicationKey) {
					t.Fatalf("vector %d leaf %d generation %d: application_key = %x, want %x",
						i, leaf, want.Generation, gotKey, []byte(want.ApplicationKey))
				}
				if !bytes.Equal(gotNonce, want.ApplicationNonce) {
					t.Fatalf("vector %d leaf %d generation %d: application_nonce = %x, want %x",
						i, leaf, want.Generation, gotNonce, []byte(want.ApplicationNonce))
				}
			}
			leaves++
		}
		ran++
		suitesSeen[suite]++
	}

	if ran == 0 {
		t.Fatalf("ran no secret-tree vectors (%d skipped)", skipped)
	}
	if suitesSeen[CipherSuiteX25519AES128SHA256Ed25519] == 0 {
		t.Fatal("no secret-tree vector ran at ciphersuite 0x0001")
	}
	if suitesSeen[CipherSuiteX25519ChaCha20SHA256Ed25519] == 0 {
		t.Fatal("no secret-tree vector ran at ciphersuite 0x0003")
	}
	t.Logf("secret-tree: ran %d vectors covering %d leaves, skipped %d unimplemented suites", ran, leaves, skipped)
}

// TestVectorSecretTreeGenerate is the generate direction of family 3: build a fresh
// vector from a random encryption secret and verify it with a second secret tree, so
// an asymmetry between how a key is produced and how it is looked up cannot hide.
func TestVectorSecretTreeGenerate(t *testing.T) {
	for _, suite := range []CipherSuite{
		CipherSuiteX25519AES128SHA256Ed25519,
		CipherSuiteX25519ChaCha20SHA256Ed25519,
	} {
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider(%#x): %v", suite, err)
		}
		encryptionSecret := crypto.Random(crypto.HashSize())
		const leafCount = LeafIndex(8)

		producer, err := NewSecretTree(crypto, leafCount, encryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree: %v", err)
		}
		vector := secretTreeVector{CipherSuite: uint16(suite), EncryptionSecret: encryptionSecret}
		vector.SenderData.SenderDataSecret = crypto.Random(crypto.HashSize())
		vector.SenderData.Ciphertext = crypto.Random(64)
		senderKey, senderNonce, err := SenderDataKeyNonce(crypto, vector.SenderData.SenderDataSecret, vector.SenderData.Ciphertext)
		if err != nil {
			t.Fatalf("SenderDataKeyNonce: %v", err)
		}
		vector.SenderData.Key = senderKey
		vector.SenderData.Nonce = senderNonce

		for leaf := LeafIndex(0); leaf < leafCount; leaf++ {
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
					HandshakeKey:     handshakeKey,
					HandshakeNonce:   handshakeNonce,
					ApplicationKey:   applicationKey,
					ApplicationNonce: applicationNonce,
				})
			}
			vector.Leaves = append(vector.Leaves, generations)
		}

		serialized, err := json.Marshal([]secretTreeVector{vector})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		var readBack []secretTreeVector
		if err := json.Unmarshal(serialized, &readBack); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}

		verifier, err := NewSecretTree(crypto, leafCount, readBack[0].EncryptionSecret)
		if err != nil {
			t.Fatalf("NewSecretTree: %v", err)
		}
		for leaf, generations := range readBack[0].Leaves {
			for _, want := range generations {
				gotKey, gotNonce, err := verifier.ReceiverKey(LeafIndex(leaf), RatchetHandshake, want.Generation)
				if err != nil {
					t.Fatalf("suite %#x leaf %d generation %d: %v", suite, leaf, want.Generation, err)
				}
				if !bytes.Equal(gotKey, want.HandshakeKey) || !bytes.Equal(gotNonce, want.HandshakeNonce) {
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

Run: `go test ./connect/mls/... -run TestVectorSecretTree -v`
Expected: PASS, with a log line reporting 6 vectors covering 82 leaves and 15 skipped.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/secret_tree_vectors_test.go
git ls-files | wc -l
git commit -m "test(mls): secret-tree vector family, verify and generate directions"
```

---

### Task 26: Round-trip fuzz targets for the two structures this plan encodes

**Files:**
- Create: `connect/mls/key_schedule_fuzz_test.go`
- Create: `connect/mls/testdata/corpus/FuzzGroupContextRoundTrip/seed001`
- Create: `connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip/seed001`

**Interfaces:**
- Consumes: `ParseGroupContext`, `(*GroupContext).Marshal` (Tasks 3–4), `ParsePreSharedKeyId`,
  `(*PreSharedKeyId).Marshal` (Task 13).
- Produces: nothing. Feeds Gate 4 properties 1 and 2 for the two structures this plan owns.

- [ ] **Step 1: Write the failing test**

```go
// key_schedule_fuzz_test.go
// Gate 4 properties 1 and 2 for the structures the key schedule owns: no panic, no
// unbounded allocation, and round-trip stability. MLS signs over serialized forms, so
// a decoder that accepts two encodings of one object is a signature-bypass primitive.
package mls

import (
	"bytes"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// FuzzGroupContextRoundTrip asserts encode(decode(x)) == x for every accepted input.
func FuzzGroupContextRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	seed, err := (&GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             CipherSuiteX25519ChaCha20SHA256Ed25519,
		GroupId:                 []byte("group"),
		Epoch:                   3,
		TreeHash:                make([]byte, 32),
		ConfirmedTranscriptHash: make([]byte, 32),
	}).Marshal()
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseGroupContext(data)
		if err != nil {
			return
		}
		reencoded, err := parsed.Marshal()
		if err != nil {
			t.Fatalf("a parsed group context failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("round trip changed the bytes:\n got %x\nwant %x", reencoded, data)
		}
		again, err := ParseGroupContext(reencoded)
		if err != nil {
			t.Fatalf("re-encoded group context failed to parse: %v", err)
		}
		if again.Epoch != parsed.Epoch || !bytes.Equal(again.GroupId, parsed.GroupId) {
			t.Fatal("decode(encode(decode(x))) differs from decode(x)")
		}
	})
}

// FuzzPreSharedKeyIdRoundTrip asserts the same for PreSharedKeyID, whose bytes are
// hashed into psk_input and therefore into every epoch secret when PSKs are in use.
func FuzzPreSharedKeyIdRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00})
	seed, err := (&PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    []byte("id"),
		PskNonce: make([]byte, 32),
	}).Marshal()
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}
	f.Add(seed)

	f.Fuzz(func(t *testing.T, data []byte) {
		r := syntax.NewReader(data)
		parsed, err := ParsePreSharedKeyId(r)
		if err != nil {
			return
		}
		if err := r.Done(); err != nil {
			return
		}
		reencoded, err := parsed.Marshal()
		if err != nil {
			t.Fatalf("a parsed PreSharedKeyID failed to re-encode: %v", err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("round trip changed the bytes:\n got %x\nwant %x", reencoded, data)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'FuzzGroupContextRoundTrip|FuzzPreSharedKeyIdRoundTrip' -v`
Expected: FAIL to compile before Step 1 is saved. After saving, the seed corpus alone should pass;
run the fuzzer for real in Step 4.

- [ ] **Step 3: Write minimal implementation**

Write the seed corpus files:

```bash
mkdir -p connect/mls/testdata/corpus/FuzzGroupContextRoundTrip
mkdir -p connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip
printf 'go test fuzz v1\n[]byte("\\x00\\x01\\x00\\x03\\x05group\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x03\\x00\\x00\\x00")\n' \
  > connect/mls/testdata/corpus/FuzzGroupContextRoundTrip/seed001
printf 'go test fuzz v1\n[]byte("\\x01\\x02id\\x00")\n' \
  > connect/mls/testdata/corpus/FuzzPreSharedKeyIdRoundTrip/seed001
```

If either fuzz target reports a round-trip failure, the fix belongs in `Marshal` or in the parser,
never in the test: a non-canonical encoding that survives a round trip is the bug.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run FuzzGroupContextRoundTrip -fuzz FuzzGroupContextRoundTrip -fuzztime 60s`
Then: `go test ./connect/mls/... -run FuzzPreSharedKeyIdRoundTrip -fuzz FuzzPreSharedKeyIdRoundTrip -fuzztime 60s`
Expected: PASS, no new corpus entries in `testdata/corpus` reported as failures.

- [ ] **Step 5: Commit**

```bash
git ls-files | wc -l
git add connect/mls/key_schedule_fuzz_test.go connect/mls/testdata/corpus
git ls-files | wc -l
git commit -m "test(mls): round-trip fuzz targets for GroupContext and PreSharedKeyID"
```

---

### Task 27: The guardrail source scan

**Files:**
- Create: `connect/mls/key_schedule_guard_test.go`

**Interfaces:**
- Consumes: nothing beyond the standard library.
- Produces: nothing. Enforces G1, G3, G7 and G8 for the files this plan owns.

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
		"\"crypto/subtle\"":                          true,
		"\"errors\"":                                 true,
		"\"fmt\"":                                    true,
		"\"math\"":                                   true,
		"\"runtime\"":                                true,
		"\"sync\"":                                   true,
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
| Gate 2, family 3 `secret-tree` | Task 25, verify and generate | — |
| Gate 2, family 5 `key-schedule` | Tasks 17 and 18, verify and generate | — |
| Gate 2, family 6 `psk_secret` | Task 16 | — |
| Gate 2, family 7 `transcript-hashes` | Task 20 | The AuthenticatedContent parse is a self-validating byte split until the Framing plan lands `ParseAuthenticatedContent` |
| Gate 2, family 8 `welcome` | The `welcome_secret` to key/nonce derivation (Task 11) | The end-to-end Welcome decrypt, which is the Group lifecycle plan |
| Gate 3, ValSem401/402/403 | The RFC-level checks and their negative tests (Tasks 13–15) | The v1 `ErrProfilePSK` parse refusal, which is the Proposal and Validation plans |
| Gate 3, ValSem400 | `PastEpochWindow = 32` and its test (Task 12) | `TestValSem400_PastEpochBound` over the StateStore, which is the Group lifecycle plan |
| Gate 3, ValSem205 / ValSem008 | `VerifyConfirmationTag` / `VerifyMembershipTag` (Task 10) | The commit and framing call sites |
| Gate 3, errata 8745 and 8815 | nothing — both are validation errata (§13.4 and §12.2) | Validation and interop harness plan |
| Gate 4, properties 1 and 2 | `GroupContext` and `PreSharedKeyID` round-trip fuzz (Task 26) | The seven other fuzz targets, which are the Syntax and Validation plans |
| Guardrails G1, G6, G7, G8 | Tasks 12 and 27 | G2, G3, G5, G9, G10, G11, which belong to `connect/message` |

## Risks carried by this plan

1. **The consumed `syntax` API shape is an assumption.** Task 1 turns a mismatch into a compile error
   on the first run rather than a silent divergence, but if the Syntax plan chose a reflection-driven
   `Marshal(any)` instead of a reader and writer, Tasks 3, 4, 13, 15 and 19 need their encoding steps
   rewritten. The arithmetic and every KAT stay valid.
2. **`Extension` and `ProtocolVersion` ownership.** This plan consumes both and defines neither. If no
   wave-1 plan defines them, `group_context.go` does not compile and the first plan to notice should
   add them to `connect/mls/extension.go` rather than duplicating them locally.
3. **`HpkePublicKey.Bytes()`** is required by Task 9 only. If the crypto plan models `HpkePublicKey`
   as a bare `[]byte`, it still needs that one-line method for Task 1 to compile.
4. **The transcript vector's content split** is correct for KDF.Nh below 64 and is checked by a MAC,
   so it cannot silently produce a wrong answer — but it will need replacing with the real parser
   when the Framing plan lands, and Task 20 says so in the code comment.
5. **`MaxGenerationSkip = 1024`** is a judgement call, not an RFC value. A sender that emits more than
   1024 messages in one epoch while a receiver is offline produces a visible gap for that receiver.
   Spec A section 5.5 makes the same trade for records and section 14 open item 7 already carries a
   memory-budget review; this constant belongs in that review.
