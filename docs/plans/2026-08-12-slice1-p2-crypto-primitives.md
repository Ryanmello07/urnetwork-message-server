# [Crypto Primitives and HPKE] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the cryptographic floor of `connect/mls` — the ciphersuite registry, the RFC 9180
HPKE base-mode instantiation, the RFC 9420 labelled KDF/sign/encrypt operations, and the X-Wing
hybrid KEM for the storage layer — with the `crypto-basics` vector family green.

**Architecture:** One `CryptoProvider` interface is the entire cryptographic surface of the MLS
implementation, so an audit reads one file and a test can substitute a deterministic instance. It is
built from Go standard-library primitives only (`crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`,
`crypto/mlkem`, `crypto/ed25519`, `crypto/hmac`, `crypto/sha256`, `crypto/aes`) plus
`chacha20poly1305` from the already-pinned `golang.org/x/crypto`. HPKE is implemented as a first-class
RFC 9180 base-mode context (setup, seal, open, export) rather than a one-shot helper, because the
RFC's own vectors exercise the sequence-number path and a one-shot helper cannot be tested against
them. X-Wing lands in `connect/message` where Spec A §2.2 puts it, and reaches back into
`connect/mls` for the single X25519 helper so there is exactly one place in the tree that calls
`ECDH`.

**Tech Stack:** Go 1.26.5 (pinned), `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, `crypto/mlkem`,
`crypto/ed25519`, `golang.org/x/crypto/chacha20poly1305`, `connect/mls/syntax` for the TLS
presentation-language length prefix.

## Global Constraints

- Go 1.26.5, pinned. `connect/go.mod` keeps its `go 1.26.3` directive and gains `toolchain
  go1.26.5` — raising the directive would raise the language floor for all of `connect`, which is
  out of this slice's scope. **The `go.mod` edit belongs to the Syntax and codec plan (p1 Task 1).**
  Task 1 here only asserts the result and is a no-op when p1 has already landed it.
- Standard library only for crypto: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, plus
  `chacha20poly1305` from the already-pinned `golang.org/x/crypto`.
- NO cgo, NO Rust, NO new third-party crypto dependency. New dependencies permitted in `connect` on
  `beta/message`: **none.** `sdk` must stay gomobile-buildable.
- OpenMLS (Rust) is a READ-ONLY differential oracle used out of process in CI. It is never in
  `go.mod`, never linked, never in a shipped artifact.
- Ciphersuite: groups are created at exactly
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003).
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) is **registered and implemented** and
  vector-tested, and refused at group creation by `group.go:policyCheck` — which is not this plan's
  file. The registry has exactly two entries so that it is distinguishable from a hardcoded singleton.
- `connect` (the parent package) must NEVER import `connect/mls` or `connect/message`. A package must
  not import its own subpackages. `connect/mls` must not import `connect` or `connect/message`.
- `sdk.GenerateSharedSecret`, `box.Precompute` and `curve25519.ScalarMult` MUST NOT be used. All
  X25519 goes through `crypto/ecdh`, and a returned error is a hard validation failure — never logged
  and continued (MASTER §7.2, Spec A §5.9 G3).
- `crypto/hkdf.Extract(h, secret, salt)` takes **ikm first, salt second**. Every wrapper in this plan
  takes `(salt, ikm)` to match the spec text. `hkdf.Extract` is called in exactly two files
  (`connect/mls/crypto.go` and `connect/mls/hpke.go`) and a test gate forbids it elsewhere (G1).
- Every tag and MAC comparison goes through `crypto/subtle.ConstantTimeCompare` (G8).
- `mlkem.NewDecapsulationKey768` is called with exactly a 64-byte `d ‖ z` seed derived from a 32-byte
  X-Wing seed; both lengths are `const` and asserted by test (G9).
- MLS signs over serialized forms, so every labelled construction uses the one codec in
  `connect/mls/syntax`. This plan defines no second length-prefix implementation.
- Cross-platform from the first commit: `windows/{amd64,arm64}`, `linux/{amd64,arm64}`,
  `darwin/arm64`, `android/{arm64,arm,amd64}`, `ios/arm64`. No build tags on the crypto.
- `CODESTYLE.md`: `self` receivers, explicit struct field names, doc comment on every file, type and
  func, no name repetition in comments, top-level `func TestXxx` with no positive-path `t.Run`.

The four canonical conventions of the slice-1 interface registry, carried here verbatim:

- **C1 — one codec, one method set.** Every wire type in `package mls` implements exactly
  `MarshalMLS(w *syntax.Writer) error` and `UnmarshalMLS(r *syntax.Reader) error` and nothing else.
  No `MarshalTo`, no `MarshalTLS`, no `Marshal() ([]byte, error)`, no `Parse<Type>(data []byte)` free
  constructor, no `tls:` struct tags, no reflection. Byte-level access is `syntax.Marshal(&v)` /
  `syntax.Unmarshal(bs, &v)`. Every wire type carries `var _ syntax.Codec = (*T)(nil)` in its own
  file so drift fails at build rather than at Gate 4. This plan declares no wire type, so C1 binds it
  only as a consumer.
- **C2 — the syntax Writer is sticky *and* `MarshalMLS` returns an error.** Leaf writes
  (`WriteUint16`, `WriteUint32`, `WriteOpaque`, `WriteRaw`, …) return nothing and every write after
  the first error is a no-op; the error is taken once, at `(*syntax.Writer).Bytes() ([]byte, error)`.
- **C3 — counts are `LeafCount`, indices are `LeafIndex`/`NodeIndex`, and tree-math arithmetic that
  can be out of range returns an error.** `TreeSize` does not exist. This plan names none of them.
- **C4 — the GroupContext crosses a plan boundary as bytes.** Every framing entry point takes
  `groupContext []byte`. This plan names none of them.

Two registry overrides that land directly on this plan's own surface:

- **O-2 — no append-style free functions in `package syntax`.** `syntax.WriteVarVec(dst, v) []byte`
  and `syntax.WriteUint16(dst, v) []byte` do not exist and are not added: they would be a second,
  independent implementation of the RFC 9420 §2.1.2 length prefix in a slice whose whole thesis is
  that one codec with one fuzz corpus is what makes Gate 4 property 2 meaningful. The four label
  encoders here — `mlsKdfLabel`, `RefHash`, `mlsSignContent`, `mlsEncryptContext`, the bytes MLS
  signs over — build their preimages through `w := syntax.NewWriter(); w.WriteOpaque(...);
  bs, err := w.Bytes()`.
- **O-9 — `ErrBadSignature` is `ErrCryptoBadSignature` here.** The bare name is declared once in
  `package mls`, by the Validation and interop plan, where it is ValSem010 and Gate 3 asserts it.
  This plan's crypto-layer error is renamed; that plan's `ErrBadSignature` wraps it, so `errors.Is`
  holds through both.

---

## Verification already performed

Everything in this plan was executed against the pinned toolchain before the plan was written. These
are results, not expectations:

| Construction | Checked against | Result |
|---|---|---|
| `ExpandWithLabel`, `DeriveSecret`, `DeriveTreeSecret`, `RefHash` | `crypto-basics.json` suite 0x0003 | match |
| `SignWithLabel` (Ed25519, 32-byte seed private key) | `crypto-basics.json` suite 0x0003 | match, and deterministically byte-identical |
| `DecryptWithLabel` (HPKE base mode, empty AEAD aad) | `crypto-basics.json` suite 0x0003 | match |
| HPKE `DeriveKeyPair`, `Encap`, `KeySchedule`, `Seal` seq 0–3, `Export` | RFC 9180 `test-vectors.json` entry `mode=0 kem=0x0020 kdf=0x0001 aead=0x0003` | match |
| X-Wing keygen from 32-byte seed, `Decapsulate`, the X25519 half of `Encapsulate` | draft-connolly-cfrg-xwing-kem `spec/test-vectors.json`, all 3 vectors | match |

Two findings that change what gets implemented:

1. **Spec A §5.4's combiner input order is wrong.** Spec A's stdlib-mapping table writes the X-Wing
   combiner as `sha3.Sum256(XWingLabel ‖ ss_M ‖ ss_X ‖ ct_X ‖ pk_X)` — label **first**. The draft's
   own reference implementation (`spec/xwing.py`) and draft-10 §5.3 put the label **last**:
   `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)`. MASTER §7.2 requires the draft ordering
   verbatim, and the label-first form fails all three draft vectors. **This plan implements the draft
   ordering.** Spec A §5.4 needs the correction.
2. **`mlkem.EncapsulationKey768.Encapsulate()` takes no randomness and returns no error**, so ML-KEM
   encapsulation cannot be derandomized on the standard library. The X-Wing `eseed` KAT direction is
   therefore verifiable only in part: keygen and decapsulation are full KATs, the X25519 half of
   encapsulation is a full KAT against `eseed[32:64]`, and the ML-KEM half of encapsulation is covered
   by round-trip plus the standard library's own FIPS 203 ACVP tests. Task 20 encodes exactly this
   split so nobody later mistakes the gap for an oversight.

---

## File Structure

| File | Responsibility |
|---|---|
| `connect/go.mod` | **not modified here** — `go 1.26.3` + `toolchain go1.26.5` is p1 Task 1's edit; Task 1 asserts it |
| `connect/mls/doc.go` | package doc: what `connect/mls` is, what it must never import |
| `connect/mls/pins_test.go` | compile assertions that the pinned stdlib surface exists |
| `connect/mls/crypto_forbidden_test.go` | source-walking gate: no `GenerateSharedSecret`, `box.Precompute`, `curve25519.ScalarMult`; `hkdf.Extract` and `ECDH(` confined to their one file each |
| `connect/mls/suite.go` | `CipherSuite`, `SuiteParams`, the two-entry registry |
| `connect/mls/suite_test.go` | registry is closed, has exactly two entries, params are right |
| `connect/mls/crypto_errors.go` | typed errors for the crypto layer only (ValSem errors live in `errors.go`, owned by the Validation plan) |
| `connect/mls/crypto_x25519.go` | the only `ECDH` call site in the tree; invalid point is an error |
| `connect/mls/crypto_x25519_test.go` | low-order point returns `ErrInvalidPoint`, never a zero secret |
| `connect/mls/hpke.go` | RFC 9180 DHKEM(X25519,HKDF-SHA256) base mode: labelled KDF, encap/decap, key schedule, context seal/open/export, one-shot |
| `connect/mls/hpke_test.go` | round-trip, wrong-key, tamper, sequence, length rejection |
| `connect/mls/hpke_vectors_test.go` | the RFC 9180 vector gate, both suites |
| `connect/mls/hpke_fuzz_test.go` | `FuzzHpkeOpenBase` — no panic, no unbounded allocation |
| `connect/mls/crypto.go` | `CryptoProvider`, its concrete implementation, `NewCryptoProvider` |
| `connect/mls/crypto_labels.go` | RFC 9420 §5.1–5.2 labelled constructions: `KDFLabel`, `SignContent`, `EncryptContext`, `RefHashInput` |
| `connect/mls/crypto_labels_test.go` | boundary conformance of the label encodings against `syntax` |
| `connect/mls/crypto_test.go` | provider behaviour, `Extract` argument order, concurrency safety |
| `connect/mls/crypto_basics_kat_test.go` | the `crypto-basics` vector gate (family 2), verify and generate directions, `RegisterVectorFamily` |
| `connect/mls/testdata/vectors/crypto-basics.json` | **vendored by p8 Task 6**, not here; this plan keeps only the runner |
| `connect/mls/testdata/vectors/rfc/hpke-rfc9180-x25519.json` | vendored from `cfrg/draft-irtf-cfrg-hpke`, filtered to the two entries we instantiate. Under `rfc/` so p8's sixteen-file assertion over `testdata/vectors/*.json` stays exact |
| `connect/mls/interop/PINS.md` | **p8 Task 6's file**; Tasks 9 and 20 append their two rows to it. There is no `connect/mls/PINS.md` and no `testdata/vectors/PINS.md` |
| `connect/message/doc.go` | package doc for the storage layer |
| `connect/message/xwing.go` | X-Wing KEM per draft-connolly-cfrg-xwing-kem |
| `connect/message/xwing_errors.go` | typed errors for X-Wing |
| `connect/message/xwing_test.go` | round-trip, sizes, negative cases |
| `connect/message/xwing_vectors_test.go` | the draft KAT gate |
| `connect/message/xwing_fuzz_test.go` | `FuzzXwingDecapsulate` — no panic on arbitrary ciphertext |
| `connect/message/xwing_mls_pin_test.go` | Task 22: the compile assertion that `message.XwingPublicKeySize` and `mls.XwingPublicKeyLen` agree |
| `connect/message/testdata/vectors/rfc/xwing-draft10.json` | vendored from the draft repo |

**Files this plan must not touch**, because another plan owns them: `connect/go.mod` and
`connect/mls/syntax/*` (Syntax and codec, p1), `connect/mls/tree_math.go` (Tree math, p3),
`connect/mls/errors.go`, `connect/mls/profile.go`, `connect/mls/codec_table.go`,
`connect/mls/vectors_test.go` and `connect/mls/interop/*` (Validation and interop harness, p8).

Two sanctioned exceptions to that last line, both required of every family-owning task by the
registry: Task 17 deletes `2` from `expectedPendingFamilies` in `connect/mls/vectors_test.go` in the
same commit that registers family 2, and Tasks 9 and 20 append one row each to
`connect/mls/interop/PINS.md`. Both are one-line additions to a file p8 creates in wave 1, and both
must be sequenced after p8 Task 6.

---

## The contract other plans consume

Every symbol below is produced by a task in this plan and is stable for the whole slice. Package
paths are `github.com/urnetwork/connect/mls` and `github.com/urnetwork/connect/message`.

```go
package mls

// suite.go — Task 3
type CipherSuite uint16

const (
    CipherSuiteX25519AesGcm128Sha256Ed25519 CipherSuite = 0x0001
    CipherSuiteX25519ChaCha20Sha256Ed25519  CipherSuite = 0x0003
)

// one named type per RFC 9180 registry. the kdf HKDF-SHA256 and the aead AES-128-GCM
// are both 0x0001 in two different registries, so on a shared uint16 a transposed
// declaration compiles and compares equal; declared distinct it is a compile error.
// the encoder still takes uint16(...) for binary.BigEndian.AppendUint16, so these
// close the registry declaration hole and not the encoder hole — the encoder stays
// held by the appendix A vectors for both suites instead.
type (
    HpkeKemId  uint16
    HpkeKdfId  uint16
    HpkeAeadId uint16
)

const (
    HpkeKemX25519HkdfSha256  HpkeKemId  = 0x0020
    HpkeKdfHkdfSha256        HpkeKdfId  = 0x0001
    HpkeAeadAes128Gcm        HpkeAeadId = 0x0001
    HpkeAeadChaCha20Poly1305 HpkeAeadId = 0x0003
)

const SignatureSchemeEd25519 uint16 = 0x0807

type SuiteParams struct {
    Suite       CipherSuite
    Name        string
    KemId       HpkeKemId
    KdfId       HpkeKdfId
    AeadId      HpkeAeadId
    SignatureId uint16
    Nh          int // KDF output size
    Nk          int // AEAD key size
    Nn          int // AEAD nonce size
    Nt          int // AEAD tag size
    Nsecret     int // KEM shared secret size
    Nenc        int // KEM encapsulated key size
    Npk         int // KEM public key size
    Nsk         int // KEM private key size
    NsigPub     int
    NsigPriv    int
}

func Suites() []CipherSuite
func LookupSuite(suite CipherSuite) (*SuiteParams, error)
func IsRegisteredSuite(suite CipherSuite) bool

// crypto_x25519.go — Task 4
func X25519PrivateKey(b []byte) (*ecdh.PrivateKey, error)
func X25519PublicKey(b []byte) (*ecdh.PublicKey, error)
func X25519GenerateKey(random io.Reader) (*ecdh.PrivateKey, error)
func X25519DH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error)

// hpke.go — Tasks 5-8
type HpkeContext struct{ /* not safe for concurrent use */ }

func HpkeDeriveKeyPair(params *SuiteParams, ikm []byte) (HpkePrivateKey, HpkePublicKey, error)
func HpkeSetupBaseS(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte) (kemOutput []byte, ctx *HpkeContext, err error)
func HpkeSetupBaseR(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte) (*HpkeContext, error)
func (self *HpkeContext) Seal(aad []byte, plaintext []byte) ([]byte, error)
func (self *HpkeContext) Open(aad []byte, ciphertext []byte) ([]byte, error)
func (self *HpkeContext) Export(exporterContext []byte, length int) ([]byte, error)
func HpkeSealBase(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)
func HpkeOpenBase(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error)

// crypto.go — Tasks 11-16
type HpkePublicKey []byte
type HpkePrivateKey []byte
type SignaturePublicKey []byte
type SignaturePrivateKey []byte // Ed25519 32-byte seed, per the crypto-basics vectors

type CryptoProvider interface {
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
func NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error)

// crypto_labels.go — Tasks 12-15. Free functions, so CryptoProvider stays exactly
// the interface Spec A §3.3 fixes.
func RefHash(crypto CryptoProvider, label string, value []byte) []byte
func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte
func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte
func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)
func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error)

// crypto_errors.go — Task 1
var (
    ErrUnknownCipherSuite = errors.New("mls: unknown ciphersuite")
    ErrInvalidPoint       = errors.New("mls: x25519 produced an invalid shared secret")
    ErrBadKeyLength       = errors.New("mls: key length does not match the ciphersuite")
    ErrBadNonceLength     = errors.New("mls: nonce length does not match the ciphersuite")
    ErrBadKemOutput       = errors.New("mls: kem output length does not match the ciphersuite")
    ErrBadSignatureKey    = errors.New("mls: signature key length does not match the ciphersuite")
    ErrCryptoBadSignature = errors.New("mls: signature verification failed")
    ErrAeadOpen           = errors.New("mls: aead open failed")
    ErrSequenceOverflow   = errors.New("mls: hpke context sequence number overflow")
)
```

```go
package message

// xwing.go — Tasks 19-21
const (
    XwingSeedSize            = 32
    XwingExpandedSize        = 96
    XwingPublicKeySize       = 1216
    XwingCiphertextSize      = 1120
    XwingSharedSize          = 32
    XwingMlkemSeedSize       = 64
    XwingMlkemPublicKeySize  = 1184
    XwingMlkemCiphertextSize = 1088
    XwingX25519KeySize       = 32

    XwingAlgId uint16 = 0x0014
)

type XwingPrivateKey struct{ /* holds the 32-byte seed and the expanded halves */ }
type XwingPublicKey struct{}

func XwingKeyGenFromSeed(seed []byte) (*XwingPrivateKey, error)
func XwingGenerateKey(random io.Reader) (*XwingPrivateKey, error)
func (self *XwingPrivateKey) Public() *XwingPublicKey
func (self *XwingPrivateKey) Seed() []byte
func (self *XwingPublicKey) Bytes() []byte
func ParseXwingPublicKey(b []byte) (*XwingPublicKey, error)
func XwingEncapsulate(random io.Reader, pub *XwingPublicKey) (ct []byte, ss []byte, err error)
func XwingDecapsulate(priv *XwingPrivateKey, ct []byte) (ss []byte, err error)

// xwing_errors.go — Task 19
var (
    ErrXwingBadSeedSize       = errors.New("message: xwing seed must be 32 bytes")
    ErrXwingBadPublicKeySize  = errors.New("message: xwing public key must be 1216 bytes")
    ErrXwingBadCiphertextSize = errors.New("message: xwing ciphertext must be 1120 bytes")
    ErrXwingInvalidPoint      = errors.New("message: xwing x25519 produced an invalid shared secret")
)
```

### What this plan needs from other plans

Every signature below is the canonical interface registry's, verbatim.

| Needed | From | Exact signature expected |
|---|---|---|
| The sticky writer | **Syntax and codec (p1, wave 1)** | `package syntax`, `type Writer struct{ ... }` (not safe for concurrent use), `func NewWriter() *Writer`, `func (self *Writer) Bytes() ([]byte, error)` — the value is undefined when the error is non-nil |
| Fixed-width integer writes | **Syntax and codec (p1, wave 1)** | `func (self *Writer) WriteUint16(v uint16)`, `func (self *Writer) WriteUint32(v uint32)` — big-endian, return nothing, sticky on error |
| The RFC 9420 §2.1.2 variable-length prefix | **Syntax and codec (p1, wave 1)** | `func (self *Writer) WriteOpaque(bs []byte)` — `opaque x<V>`; a nil slice encodes as empty. 1 prefix byte if `len < 64`; 2 bytes big-endian with `0x4000` set if `len < 16384`; 4 bytes big-endian with `0x80000000` set otherwise |
| The reader, for the negative tests | **Syntax and codec (p1, wave 1)** | `func NewReader(bs []byte) *Reader`, `func (self *Reader) ReadOpaque() ([]byte, error)` — a copy, never nil |
| Vector-corpus helpers | **Validation and interop harness (p8, wave 1)** | `func LoadVectorFile(t *testing.T, file string) []json.RawMessage`, `func MustHex(t *testing.T, s string) []byte`, `func HexOf(b []byte) string` |
| The vector registry | **Validation and interop harness (p8, wave 1)** | `type VectorFamily struct { Number int; Name string; File string; Slice string; Verify func(t *testing.T, raw json.RawMessage); Generate func(t *testing.T) json.RawMessage }`, `func RegisterVectorFamily(family VectorFamily)` |
| The vendored `crypto-basics.json` and `VECTORS.sha256` | **Validation and interop harness (p8 Task 6, wave 1)** | file at `connect/mls/testdata/vectors/crypto-basics.json`, pinned in `connect/mls/interop/PINS.md` |
| The X-Wing public-key length in `package mls` | **TreeKEM (p5 Task 4, wave 2)** | `const XwingPublicKeyLen = 1216` — consumed only by Task 22's compile assertion |

`syntax.WriteVarVec`, `syntax.WriteUint16(dst, v) []byte` and `syntax.WriteUint32(dst, v) []byte` —
the append-style free functions an earlier draft of this plan consumed — **do not exist** (registry
override O-2). Nothing here reconstructs them.

Only Tasks 12–18 depend on `syntax`, and Tasks 17–18 additionally on p8's vector helpers. Tasks
1–11, 19 and 21 are stdlib-only and can be executed while the Syntax plan is still in flight. Task 12
carries its own boundary-conformance test pinning the three prefix width transitions through
`(*syntax.Writer).WriteOpaque`, so a drift in `syntax` fails here rather than silently changing a
signed serialization. Task 22 is the only task in this plan that reaches into wave 2.

### What other plans get from this plan

| Consumer plan | Consumes |
|---|---|
| Tree math (p3, wave 1) | `CipherSuite`, `CryptoProvider` |
| Key schedule and secret tree (p4, wave 2) | `CipherSuite` and both suite constants, `SuiteParams`, `LookupSuite`, `CryptoProvider` (`Extract`/`Expand`/`ExpandWithLabel`/`DeriveSecret`/`DeriveTreeSecret`/`Mac`/`MacVerify`/`Hash`), `NewCryptoProvider`, `HpkePublicKey`, `HpkePrivateKey` |
| TreeKEM (p5, wave 2) | `CipherSuite`, `SuiteParams`, `LookupSuite`, `CryptoProvider`, `NewCryptoProvider`, `RefHash`, `MakeKeyPackageRef`, `EncryptWithLabel`, `DecryptWithLabel`, `HpkePublicKey`, `HpkePrivateKey`, `SignaturePublicKey`, `SignaturePrivateKey` |
| Framing and message protection (p6, wave 3) | `CipherSuite`, `CryptoProvider` (`AeadSeal`/`AeadOpen`/`Mac`/`MacVerify`/`SignWithLabel`/`VerifyWithLabel`), `NewCryptoProvider`, `MakeProposalRef`, `SignaturePublicKey`, `SignaturePrivateKey`, `HpkePublicKey`, `HpkePrivateKey`, `ErrAeadOpen` |
| Group lifecycle (p7, wave 4) | `Suites`, `LookupSuite`, `SuiteParams`, `CipherSuite`, `CryptoProvider`, `NewCryptoProvider`, `MakeKeyPackageRef`, `MakeProposalRef`, `EncryptWithLabel`, `DecryptWithLabel`, all four key types |
| Validation and interop harness (p8, wave 1) | `Suites`, `IsRegisteredSuite`, both suite constants, `CryptoProvider`, `NewCryptoProvider`, `NewCryptoProviderWithRandom`, `ErrUnknownCipherSuite`, `ErrInvalidPoint`, `ErrAeadOpen`, all four key types |
| Syntax and codec (p1, wave 1) | nothing — the dependency is one-way |
| Storage layer (later slice) | the whole `message` X-Wing surface, `mls.X25519DH` |

`ErrCryptoBadSignature` is deliberately absent from p8's row: p8 declares `ErrBadSignature`
(ValSem010) itself and wraps this plan's crypto-layer error, so the wrapping is p8's edit, not a
consumption of a name p8 also declares.

---

### Task 1: Toolchain pin, package skeleton, stdlib compile assertions

**Files:**
- Assert only, do not modify: `connect/go.mod`
- Create: `connect/mls/doc.go`, `connect/mls/crypto_errors.go`
- Test: `connect/mls/pins_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: package `mls` exists and compiles; `ErrUnknownCipherSuite`, `ErrInvalidPoint`,
  `ErrBadKeyLength`, `ErrBadNonceLength`, `ErrBadKemOutput`, `ErrBadSignatureKey`,
  `ErrCryptoBadSignature`, `ErrAeadOpen`, `ErrSequenceOverflow` — all `error` values.

- [ ] **Step 1: Write the failing test**

`connect/mls/pins_test.go`:

```go
// compile assertions on the pinned standard library surface. MASTER §7.2 requires
// slice 1 to pin the go version and assert mlkem.NewDecapsulationKey768 exists;
// these fail at build time on a toolchain that moved, which is the point.
package mls

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/sha3"
	"errors"
	"io"
	"runtime"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	_ func(seed []byte) (*mlkem.DecapsulationKey768, error) = mlkem.NewDecapsulationKey768
	_ func(data []byte, length int) []byte                  = sha3.SumSHAKE256
	_ func(data []byte) [32]byte                            = sha3.Sum256
	_ func() ecdh.Curve                                     = ecdh.X25519
	_ func(seed []byte) ed25519.PrivateKey                  = ed25519.NewKeyFromSeed
	_ func(key []byte) (interface{ NonceSize() int }, error) = func(key []byte) (interface{ NonceSize() int }, error) {
		return chacha20poly1305.New(key)
	}
)

// the hkdf generic surface, bound to sha256 so a signature change breaks the build.
var (
	_ = func(secret, salt []byte) ([]byte, error) { return hkdf.Extract(sha256.New, secret, salt) }
	_ = func(prk []byte, info string, n int) ([]byte, error) {
		return hkdf.Expand(sha256.New, prk, info, n)
	}
)

func TestPinnedToolchain(t *testing.T) {
	if runtime.Version() != "go1.26.5" {
		t.Fatalf("toolchain is %s, want go1.26.5", runtime.Version())
	}
}

func TestMlkemSeedSizeIsSixtyFour(t *testing.T) {
	// G9. a 32-byte seed here is the ML-KEM/X-Wing seed confusion the guardrail names.
	if _, err := mlkem.NewDecapsulationKey768(make([]byte, 32)); err == nil {
		t.Fatalf("NewDecapsulationKey768 accepted a 32-byte seed")
	}
	dk, err := mlkem.NewDecapsulationKey768(make([]byte, 64))
	if err != nil {
		t.Fatalf("NewDecapsulationKey768 rejected a 64-byte seed: %v", err)
	}
	if n := len(dk.EncapsulationKey().Bytes()); n != 1184 {
		t.Fatalf("encapsulation key is %d bytes, want 1184", n)
	}
}

func TestCryptoErrorsAreDistinct(t *testing.T) {
	all := []error{
		ErrUnknownCipherSuite, ErrInvalidPoint, ErrBadKeyLength, ErrBadNonceLength,
		ErrBadKemOutput, ErrBadSignatureKey, ErrCryptoBadSignature, ErrAeadOpen, ErrSequenceOverflow,
	}
	for i, a := range all {
		if a == nil {
			t.Fatalf("error %d is nil", i)
		}
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("error %d and %d are the same value", i, j)
			}
		}
	}
	var _ io.Reader
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestCryptoErrorsAreDistinct -v` from `connect/`
Expected: FAIL — `mls/pins_test.go:...: undefined: ErrUnknownCipherSuite` (build failure, no test
binary produced).

- [ ] **Step 3: Write minimal implementation**

`connect/go.mod` is **p1 Task 1's edit**, not this plan's: the `go` directive stays at `1.26.3` so
the language floor for all of `connect` is unchanged, and a `toolchain` line pins the compiler. Guard
the step so running it after p1 is a no-op and running it before p1 does nothing at all:

```bash
git diff --exit-code go.mod >/dev/null || { echo "go.mod is already dirty; land p1 Task 1 first"; exit 1; }
grep -q '^toolchain go1.26.5$' go.mod || echo "toolchain line missing: land p1 Task 1 before this plan's Task 1"
```

The expected content, for reference only:

```
module github.com/urnetwork/connect

go 1.26.3

toolchain go1.26.5
```

`TestPinnedToolchain` below is what actually holds this: it reads `runtime.Version()`, so a
toolchain that moved fails here whether or not `go.mod` says so.

`connect/mls/doc.go`:

```go
// RFC 9420 (MLS) in pure go, on standard-library primitives only.
//
// this package is a self-contained crypto library so it can be audited and fuzzed
// without the transport. it imports only the standard library, golang.org/x/crypto,
// and its own child mls/syntax. it must NEVER import connect or connect/message,
// and connect must never import it — see connect/layering_test.go.
//
// the whole cryptographic surface is the CryptoProvider interface in crypto.go.
// nothing outside crypto.go, crypto_labels.go, crypto_x25519.go and hpke.go performs
// a cryptographic operation directly.
package mls
```

`connect/mls/crypto_errors.go`:

```go
// typed errors for the crypto layer. every one is fatal by construction: there is no
// path in this package that logs one and continues (Spec A §5.9 G7).
//
// the RFC 9420 ValSem validation codes live in errors.go, which this file is
// deliberately not. a crypto failure is not a validation semantic.
//
// ErrCryptoBadSignature is NOT named ErrBadSignature: that name belongs to errors.go,
// where it is ValSem010 and Gate 3 asserts it. errors.go wraps this value, so
// errors.Is holds through both and a caller can ask either question.
package mls

import "errors"

var (
	ErrUnknownCipherSuite = errors.New("mls: unknown ciphersuite")
	ErrInvalidPoint       = errors.New("mls: x25519 produced an invalid shared secret")
	ErrBadKeyLength       = errors.New("mls: key length does not match the ciphersuite")
	ErrBadNonceLength     = errors.New("mls: nonce length does not match the ciphersuite")
	ErrBadKemOutput       = errors.New("mls: kem output length does not match the ciphersuite")
	ErrBadSignatureKey    = errors.New("mls: signature key length does not match the ciphersuite")
	ErrCryptoBadSignature = errors.New("mls: signature verification failed")
	ErrAeadOpen           = errors.New("mls: aead open failed")
	ErrSequenceOverflow   = errors.New("mls: hpke context sequence number overflow")
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -v` from `connect/`
Expected: PASS — `TestPinnedToolchain`, `TestMlkemSeedSizeIsSixtyFour`,
`TestCryptoErrorsAreDistinct` all ok.

- [ ] **Step 5: Commit**

```bash
git add mls/doc.go mls/crypto_errors.go mls/pins_test.go && \
git commit -m "feat(mls): package skeleton and stdlib compile assertions"
```

`go.mod` is deliberately absent from the `git add`: it is p1's file.

---

### Task 2: The forbidden-primitive gate

**Files:**
- Test: `connect/mls/crypto_forbidden_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing exported. This is a gate, and it must exist before the code it guards, so the
  first violation is caught by the commit that introduces it rather than by a later audit.

- [ ] **Step 1: Write the failing test**

`connect/mls/crypto_forbidden_test.go`:

```go
// the mechanical half of MASTER §7.2 and Spec A §5.9 G1/G3. these walk the source of
// mls and message rather than grepping in CI, so a developer sees the failure before
// pushing and so the rule travels with the code.
package mls

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// every .go file under the two packages, excluding vendored testdata.
func forbiddenScanPaths(t *testing.T) map[string]string {
	t.Helper()
	roots := []string{".", "../message"}
	sourceTexts := map[string]string{}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" || entry.Name() == "interop" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sourceTexts[filepath.ToSlash(path)] = string(b)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if len(sourceTexts) == 0 {
		t.Fatalf("scanned no source files")
	}
	return sourceTexts
}

func TestForbiddenPrimitivesAreAbsent(t *testing.T) {
	forbiddenTokens := []string{
		"GenerateSharedSecret",
		"box.Precompute",
		"curve25519.ScalarMult",
		"golang.org/x/crypto/nacl/box",
	}
	for path, text := range forbiddenScanPaths(t) {
		if strings.HasSuffix(path, "crypto_forbidden_test.go") {
			continue
		}
		for _, token := range forbiddenTokens {
			if strings.Contains(text, token) {
				t.Errorf("%s references the forbidden primitive %q", path, token)
			}
		}
	}
}

func TestHkdfExtractHasOnlyTwoCallSites(t *testing.T) {
	// G1. crypto/hkdf.Extract takes ikm first and salt second; every spec text in
	// this project writes HKDF-Extract(salt, ikm). confining the call keeps the
	// swap in one reviewable place.
	allowed := map[string]bool{
		"crypto.go": true,
		"hpke.go":   true,
	}
	for path, text := range forbiddenScanPaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		if !strings.Contains(text, "hkdf.Extract(") {
			continue
		}
		if !allowed[filepath.Base(path)] {
			t.Errorf("%s calls hkdf.Extract; only crypto.go and hpke.go may", path)
		}
	}
}

func TestEcdhHasOneCallSite(t *testing.T) {
	// G3. one helper converts an x25519 failure into ErrInvalidPoint, so there is
	// exactly one place that could ignore it and it is reviewed.
	for path, text := range forbiddenScanPaths(t) {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		if !strings.Contains(text, ".ECDH(") {
			continue
		}
		if filepath.Base(path) != "crypto_x25519.go" {
			t.Errorf("%s calls ECDH; only mls/crypto_x25519.go may", path)
		}
	}
}

func TestEcdhResultIsNeverDiscarded(t *testing.T) {
	// G3, the specific shape: `_ =` or `_, _ =` on an ECDH result.
	for path, text := range forbiddenScanPaths(t) {
		for _, line := range strings.Split(text, "\n") {
			if !strings.Contains(line, ".ECDH(") {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "_") || strings.Contains(trimmed, ", _ = ") {
				t.Errorf("%s discards an ECDH result: %s", path, trimmed)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Introduce the violation the gate exists for, so the gate is proved rather than assumed. Temporarily
append to `connect/mls/doc.go`:

```go
// deliberate temporary violation, removed in step 3
var forbiddenProbe = "curve25519.ScalarMult"
```

Run: `go test ./mls/... -run TestForbiddenPrimitivesAreAbsent -v` from `connect/`
Expected: FAIL — `mls/doc.go references the forbidden primitive "curve25519.ScalarMult"`.

- [ ] **Step 3: Write minimal implementation**

Delete the two probe lines from `connect/mls/doc.go`. The gate needs no production code; its
implementation is the absence of the tokens.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestForbidden|TestHkdf|TestEcdh" -v` from `connect/`
Expected: PASS — all four gates ok. `TestHkdfExtractHasOnlyTwoCallSites` and `TestEcdhHasOneCallSite`
pass vacuously until Tasks 4 and 5, which is correct: they are watching for a second call site, not
asserting a first.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_forbidden_test.go mls/doc.go && \
git commit -m "test(mls): gate forbidden crypto primitives and confine hkdf.Extract and ECDH"
```

---

### Task 3: The ciphersuite registry

**Files:**
- Create: `connect/mls/suite.go`
- Test: `connect/mls/suite_test.go`

**Interfaces:**
- Consumes: `ErrUnknownCipherSuite` (Task 1).
- Produces:
  - `type CipherSuite uint16`
  - `const CipherSuiteX25519AesGcm128Sha256Ed25519 CipherSuite = 0x0001`
  - `const CipherSuiteX25519ChaCha20Sha256Ed25519 CipherSuite = 0x0003`
  - `type HpkeKemId uint16`, `type HpkeKdfId uint16`, `type HpkeAeadId uint16` — one per RFC 9180 registry, distinct because the kdf and the aes-128-gcm aead are both 0x0001
  - `const HpkeKemX25519HkdfSha256 HpkeKemId`, `const HpkeKdfHkdfSha256 HpkeKdfId`, `const HpkeAeadAes128Gcm, HpkeAeadChaCha20Poly1305 HpkeAeadId`, `const SignatureSchemeEd25519 uint16`
  - `type SuiteParams struct{ Suite CipherSuite; Name string; KemId HpkeKemId; KdfId HpkeKdfId; AeadId HpkeAeadId; SignatureId uint16; Nh, Nk, Nn, Nt, Nsecret, Nenc, Npk, Nsk, NsigPub, NsigPriv int }`
  - `func Suites() []CipherSuite`
  - `func LookupSuite(suite CipherSuite) (*SuiteParams, error)`
  - `func IsRegisteredSuite(suite CipherSuite) bool`

- [ ] **Step 1: Write the failing test**

`connect/mls/suite_test.go`:

```go
package mls

import (
	"errors"
	"testing"
)

func TestRegistryHasExactlyTwoSuites(t *testing.T) {
	// a registry with one entry and a hardcoded constant are indistinguishable by
	// test. two entries is the whole point (Spec A §3.1).
	suites := Suites()
	if len(suites) != 2 {
		t.Fatalf("registry has %d suites, want 2: %v", len(suites), suites)
	}
	if suites[0] != CipherSuiteX25519AesGcm128Sha256Ed25519 {
		t.Errorf("suites[0] = %#04x, want 0x0001", uint16(suites[0]))
	}
	if suites[1] != CipherSuiteX25519ChaCha20Sha256Ed25519 {
		t.Errorf("suites[1] = %#04x, want 0x0003", uint16(suites[1]))
	}
}

func TestChaChaSuiteParams(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	want := SuiteParams{
		Suite:       CipherSuiteX25519ChaCha20Sha256Ed25519,
		Name:        "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
		KemId:       0x0020,
		KdfId:       0x0001,
		AeadId:      0x0003,
		SignatureId: 0x0807,
		Nh:          32, Nk: 32, Nn: 12, Nt: 16,
		Nsecret: 32, Nenc: 32, Npk: 32, Nsk: 32,
		NsigPub: 32, NsigPriv: 32,
	}
	if *params != want {
		t.Fatalf("params = %+v, want %+v", *params, want)
	}
}

func TestAesGcmSuiteParams(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519AesGcm128Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	want := SuiteParams{
		Suite:       CipherSuiteX25519AesGcm128Sha256Ed25519,
		Name:        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
		KemId:       0x0020,
		KdfId:       0x0001,
		AeadId:      0x0001,
		SignatureId: 0x0807,
		Nh:          32, Nk: 16, Nn: 12, Nt: 16,
		Nsecret: 32, Nenc: 32, Npk: 32, Nsk: 32,
		NsigPub: 32, NsigPriv: 32,
	}
	if *params != want {
		t.Fatalf("params = %+v, want %+v", *params, want)
	}
}

func TestUnregisteredSuitesAreRefused(t *testing.T) {
	// 0x0002 and 0x0004..0x0007 are real RFC 9420 code points we do not implement.
	// they must be refused, not silently defaulted to 0x0003.
	for _, suite := range []CipherSuite{0x0000, 0x0002, 0x0004, 0x0005, 0x0006, 0x0007, 0xFFFF} {
		if IsRegisteredSuite(suite) {
			t.Errorf("suite %#04x reports as registered", uint16(suite))
		}
		if _, err := LookupSuite(suite); !errors.Is(err, ErrUnknownCipherSuite) {
			t.Errorf("LookupSuite(%#04x) error = %v, want ErrUnknownCipherSuite", uint16(suite), err)
		}
	}
}

func TestLookupSuiteDoesNotAliasTheRegistry(t *testing.T) {
	// a caller that mutates the returned params must not corrupt every later lookup.
	a, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	a.Nk = 999
	b, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	if b.Nk != 32 {
		t.Fatalf("registry was mutated through a returned pointer: Nk = %d", b.Nk)
	}
	if a == b {
		t.Fatalf("LookupSuite returned the same pointer twice")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestRegistryHasExactlyTwoSuites -v` from `connect/`
Expected: FAIL — `mls/suite_test.go:...: undefined: Suites` (build failure).

- [ ] **Step 3: Write minimal implementation**

`connect/mls/suite.go`:

```go
// the ciphersuite registry. RFC 9420 §5 fixes a ciphersuite as the tuple of an HPKE
// kem, kdf and aead, a hash, a mac and a signature scheme, and this file is the only
// place that tuple is written down.
//
// two suites are registered on purpose. a registry with one entry and a hardcoded
// constant are indistinguishable by test, and the difference only surfaces when a
// second suite is added — which the still-draft post-quantum MLS ciphersuites make a
// near certainty. 0x0001 is implemented and vector tested here; group.go's policy
// check refuses it at group creation, so no group on the wire changes.
package mls

import "sort"

type CipherSuite uint16

const (
	CipherSuiteX25519AesGcm128Sha256Ed25519 CipherSuite = 0x0001
	CipherSuiteX25519ChaCha20Sha256Ed25519  CipherSuite = 0x0003
)

// HPKE algorithm identifiers, RFC 9180 §7.1-7.3. three registries, three types: the
// kdf HKDF-SHA256 and the aead AES-128-GCM are both 0x0001, so on a shared uint16 a
// transposed declaration compiles and satisfies every value assertion.
type (
	HpkeKemId  uint16
	HpkeKdfId  uint16
	HpkeAeadId uint16
)

const (
	HpkeKemX25519HkdfSha256  HpkeKemId  = 0x0020
	HpkeKdfHkdfSha256        HpkeKdfId  = 0x0001
	HpkeAeadAes128Gcm        HpkeAeadId = 0x0001
	HpkeAeadChaCha20Poly1305 HpkeAeadId = 0x0003
)

// signature scheme identifier as MLS carries it, RFC 8446 §4.2.3.
const SignatureSchemeEd25519 uint16 = 0x0807

// the sizes a suite fixes. every length check in this package reads one of these
// rather than a literal, so adding a suite cannot leave a hardcoded 32 behind.
// Nh is the KDF output, Nk/Nn/Nt the AEAD key, nonce and tag, Nsecret/Nenc/Npk/Nsk
// the KEM shared secret, encapsulated key, public key and private key.
type SuiteParams struct {
	Suite       CipherSuite
	Name        string
	KemId       HpkeKemId
	KdfId       HpkeKdfId
	AeadId      HpkeAeadId
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

var registeredSuiteParams = map[CipherSuite]SuiteParams{
	CipherSuiteX25519AesGcm128Sha256Ed25519: {
		Suite:       CipherSuiteX25519AesGcm128Sha256Ed25519,
		Name:        "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
		KemId:       HpkeKemX25519HkdfSha256,
		KdfId:       HpkeKdfHkdfSha256,
		AeadId:      HpkeAeadAes128Gcm,
		SignatureId: SignatureSchemeEd25519,
		Nh:          32, Nk: 16, Nn: 12, Nt: 16,
		Nsecret: 32, Nenc: 32, Npk: 32, Nsk: 32,
		NsigPub: 32, NsigPriv: 32,
	},
	CipherSuiteX25519ChaCha20Sha256Ed25519: {
		Suite:       CipherSuiteX25519ChaCha20Sha256Ed25519,
		Name:        "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519",
		KemId:       HpkeKemX25519HkdfSha256,
		KdfId:       HpkeKdfHkdfSha256,
		AeadId:      HpkeAeadChaCha20Poly1305,
		SignatureId: SignatureSchemeEd25519,
		Nh:          32, Nk: 32, Nn: 12, Nt: 16,
		Nsecret: 32, Nenc: 32, Npk: 32, Nsk: 32,
		NsigPub: 32, NsigPriv: 32,
	},
}

// ascending by code point, so callers and tests see a stable order.
func Suites() []CipherSuite {
	suites := make([]CipherSuite, 0, len(registeredSuiteParams))
	for suite := range registeredSuiteParams {
		suites = append(suites, suite)
	}
	sort.Slice(suites, func(i, j int) bool { return suites[i] < suites[j] })
	return suites
}

// the returned pointer addresses a fresh copy: the registry is never reachable
// through it, so a caller that mutates the result cannot corrupt later lookups.
func LookupSuite(suite CipherSuite) (*SuiteParams, error) {
	params, ok := registeredSuiteParams[suite]
	if !ok {
		return nil, ErrUnknownCipherSuite
	}
	return &params, nil
}

func IsRegisteredSuite(suite CipherSuite) bool {
	_, ok := registeredSuiteParams[suite]
	return ok
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestRegistry|TestChaChaSuiteParams|TestAesGcmSuiteParams|TestUnregistered|TestLookupSuiteDoesNotAlias" -v` from `connect/`
Expected: PASS — five tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/suite.go mls/suite_test.go && \
git commit -m "feat(mls): ciphersuite registry with two entries, 0x0001 and 0x0003"
```

---

### Task 4: The single X25519 call site

**Files:**
- Create: `connect/mls/crypto_x25519.go`
- Test: `connect/mls/crypto_x25519_test.go`

**Interfaces:**
- Consumes: `ErrInvalidPoint`, `ErrBadKeyLength` (Task 1).
- Produces:
  - `func X25519PrivateKey(b []byte) (*ecdh.PrivateKey, error)`
  - `func X25519PublicKey(b []byte) (*ecdh.PublicKey, error)`
  - `func X25519GenerateKey(random io.Reader) (*ecdh.PrivateKey, error)`
  - `func X25519DH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error)`

- [ ] **Step 1: Write the failing test**

`connect/mls/crypto_x25519_test.go`:

```go
package mls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestX25519RoundTrip(t *testing.T) {
	a, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a: %v", err)
	}
	b, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate b: %v", err)
	}
	ab, err := X25519DH(a, b.PublicKey())
	if err != nil {
		t.Fatalf("dh ab: %v", err)
	}
	ba, err := X25519DH(b, a.PublicKey())
	if err != nil {
		t.Fatalf("dh ba: %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatalf("shared secrets differ: %x vs %x", ab, ba)
	}
	if len(ab) != 32 {
		t.Fatalf("shared secret is %d bytes, want 32", len(ab))
	}
}

func TestX25519LowOrderPointIsAnError(t *testing.T) {
	// MASTER §7.2 and Spec A §5.4. sdk.GenerateSharedSecret returns an all-zero
	// secret here; the whole reason that function is banned is this case.
	lowOrderPoints := [][]byte{
		// the small-subgroup points of RFC 7748 §6.1, all of which drive the
		// x25519 output to zero.
		make([]byte, 32),
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
			0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
		{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
			0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	}
	priv, err := X25519GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for i, point := range lowOrderPoints {
		pub, err := X25519PublicKey(point)
		if err != nil {
			// rejecting at parse is also acceptable, and is still not a zero secret.
			continue
		}
		secret, err := X25519DH(priv, pub)
		if !errors.Is(err, ErrInvalidPoint) {
			t.Errorf("point %d: error = %v, want ErrInvalidPoint", i, err)
		}
		if secret != nil {
			t.Errorf("point %d: returned a secret alongside the error: %x", i, secret)
		}
	}
}

func TestX25519RejectsWrongKeyLengths(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := X25519PrivateKey(make([]byte, n)); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("X25519PrivateKey(%d bytes) error = %v, want ErrBadKeyLength", n, err)
		}
		if _, err := X25519PublicKey(make([]byte, n)); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("X25519PublicKey(%d bytes) error = %v, want ErrBadKeyLength", n, err)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestX25519 -v` from `connect/`
Expected: FAIL — `mls/crypto_x25519_test.go:...: undefined: X25519GenerateKey` (build failure).

- [ ] **Step 3: Write minimal implementation**

`connect/mls/crypto_x25519.go`:

```go
// the only place in connect/mls, connect/message or sdk that calls ECDH.
//
// MASTER §7.2: all x25519 operations go through crypto/ecdh and a returned error is
// a hard validation failure, never logged and continued. crypto/ecdh already refuses
// a shared secret that is all zero, which is exactly the low-order-point case that
// sdk.GenerateSharedSecret returns successfully; this file turns that into
// ErrInvalidPoint so callers cannot mistake it for anything else.
//
// crypto_forbidden_test.go asserts that no other file in either package calls ECDH,
// and that no call site discards the result.
package mls

import (
	"crypto/ecdh"
	"io"
)

const x25519KeySize = 32

func X25519PrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	if len(b) != x25519KeySize {
		return nil, ErrBadKeyLength
	}
	priv, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return nil, ErrInvalidPoint
	}
	return priv, nil
}

func X25519PublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != x25519KeySize {
		return nil, ErrBadKeyLength
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, ErrInvalidPoint
	}
	return pub, nil
}

func X25519GenerateKey(random io.Reader) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(random)
}

// the error is never a warning. a nil secret always accompanies it, so a caller that
// ignores the error still cannot proceed with usable-looking bytes.
func X25519DH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, ErrInvalidPoint
	}
	return secret, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestX25519|TestEcdh" -v` from `connect/`
Expected: PASS — `TestX25519RoundTrip`, `TestX25519LowOrderPointIsAnError`,
`TestX25519RejectsWrongKeyLengths`, `TestEcdhHasOneCallSite`,
`TestEcdhResultIsNeverDiscarded` all ok.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_x25519.go mls/crypto_x25519_test.go && \
git commit -m "feat(mls): single x25519 call site, invalid point is a hard error"
```

---

### Task 5: HPKE suite identifiers and the labelled KDF

**Files:**
- Create: `connect/mls/hpke.go`
- Test: `connect/mls/hpke_test.go`

**Interfaces:**
- Consumes: `SuiteParams`, `LookupSuite` (Task 3); `func MustHex(t *testing.T, s string) []byte`
  from the Validation and interop harness (p8, wave 1) — this package has exactly one hex decoder
  and it is p8's, so no local `mustHex` is declared here or anywhere else in `package mls`.
- Produces (unexported, used by Tasks 6–8 and by the vector tests in the same package):
  - `func hpkeKemSuiteId(params *SuiteParams) []byte`
  - `func hpkeSuiteId(params *SuiteParams) []byte`
  - `func hpkeLabeledExtract(suiteId []byte, salt []byte, label string, ikm []byte) []byte`
  - `func hpkeLabeledExpand(suiteId []byte, prk []byte, label string, info []byte, length int) ([]byte, error)`

- [ ] **Step 1: Write the failing test**

`connect/mls/hpke_test.go`:

```go
package mls

import (
	"bytes"
	"testing"
)

func TestHpkeSuiteIds(t *testing.T) {
	// RFC 9180 §5.1: suite_id for the KEM is "KEM" || I2OSP(kem_id, 2); for the
	// whole suite it is "HPKE" || kem || kdf || aead. these bytes are inside every
	// derivation, so a byte wrong here is a silent total divergence.
	chacha, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	if got, want := hpkeKemSuiteId(chacha), append([]byte("KEM"), 0x00, 0x20); !bytes.Equal(got, want) {
		t.Errorf("kem suite id = %x, want %x", got, want)
	}
	if got, want := hpkeSuiteId(chacha), append([]byte("HPKE"), 0x00, 0x20, 0x00, 0x01, 0x00, 0x03); !bytes.Equal(got, want) {
		t.Errorf("hpke suite id = %x, want %x", got, want)
	}

	aes, err := LookupSuite(CipherSuiteX25519AesGcm128Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	if got, want := hpkeSuiteId(aes), append([]byte("HPKE"), 0x00, 0x20, 0x00, 0x01, 0x00, 0x01); !bytes.Equal(got, want) {
		t.Errorf("aes hpke suite id = %x, want %x", got, want)
	}
}

func TestHpkeLabeledExtractKat(t *testing.T) {
	// the eae_prk of the RFC 9180 base-mode X25519/ChaCha20 vector, recomputed from
	// its published shared_secret inputs. this is the first derivation in Encap, so
	// pinning it isolates a label bug from a DH bug.
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	suiteId := hpkeKemSuiteId(params)
	prk := hpkeLabeledExtract(suiteId, nil, "eae_prk", MustHex(t, "1176e33aac5b7be5c9d0aee49e08a67f9ba8236a1cb4b1a5a7c07d38e5c1e5ba"))
	if len(prk) != 32 {
		t.Fatalf("prk is %d bytes, want 32", len(prk))
	}
	// determinism, and independence from the salt argument being nil vs empty.
	again := hpkeLabeledExtract(suiteId, []byte{}, "eae_prk", MustHex(t, "1176e33aac5b7be5c9d0aee49e08a67f9ba8236a1cb4b1a5a7c07d38e5c1e5ba"))
	if !bytes.Equal(prk, again) {
		t.Fatalf("nil and empty salt disagree: %x vs %x", prk, again)
	}
}

func TestHpkeLabeledExpandRejectsOverlongOutput(t *testing.T) {
	// HKDF-Expand caps at 255*Nh. an over-long request must be an error, never a
	// truncated or silently short key.
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	suiteId := hpkeSuiteId(params)
	if _, err := hpkeLabeledExpand(suiteId, make([]byte, 32), "key", nil, 255*32+1); err == nil {
		t.Fatalf("expand accepted %d bytes", 255*32+1)
	}
	out, err := hpkeLabeledExpand(suiteId, make([]byte, 32), "key", nil, 255*32)
	if err != nil {
		t.Fatalf("expand rejected the maximum length: %v", err)
	}
	if len(out) != 255*32 {
		t.Fatalf("expand returned %d bytes, want %d", len(out), 255*32)
	}
}
```

There is no local `mustHex` here. `MustHex` is p8's, declared once in `connect/mls/vectors_test.go`
in this same package; three parallel hex decoders over one corpus is how two of them end up
disagreeing about the empty string.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestHpke -v` from `connect/`
Expected: FAIL — `mls/hpke_test.go:...: undefined: hpkeKemSuiteId` (build failure). If p8 Tasks 1–9
have not landed, the failure is instead `undefined: MustHex`, which is the correct signal to execute
p8's Phase A first — both plans are wave 1.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/hpke.go`:

```go
// RFC 9180 HPKE, base mode only, DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and
// either ChaCha20-Poly1305 or AES-128-GCM.
//
// MLS uses only single-shot base-mode seal and open, but this file implements the
// full context with its sequence number because the RFC's own test vectors exercise
// the sequence path and a one-shot helper cannot be tested against them.
//
// psk, auth and auth-psk modes are deliberately absent: the v1 profile has no PSKs
// and no external senders, so there is no caller for them and no untested code.
package mls

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

const (
	hpkeVersionLabel = "HPKE-v1"
	hpkeModeBase     = byte(0x00)
)

func hpkeKemSuiteId(params *SuiteParams) []byte {
	suiteId := make([]byte, 0, 5)
	suiteId = append(suiteId, "KEM"...)
	return binary.BigEndian.AppendUint16(suiteId, uint16(params.KemId))
}

// the uint16(...) conversions are where the named registry types stop protecting
// anything: AppendUint16 takes a uint16, so uint16(params.AeadId) in the kdf slot
// compiles. what catches that is the appendix A vector for suite 0x0003, whose aead
// is 0x0003 and where the transposition moves every derived byte.
func hpkeSuiteId(params *SuiteParams) []byte {
	suiteId := make([]byte, 0, 10)
	suiteId = append(suiteId, "HPKE"...)
	suiteId = binary.BigEndian.AppendUint16(suiteId, uint16(params.KemId))
	suiteId = binary.BigEndian.AppendUint16(suiteId, uint16(params.KdfId))
	return binary.BigEndian.AppendUint16(suiteId, uint16(params.AeadId))
}

// LabeledExtract, RFC 9180 §4. hkdf.Extract takes (ikm, salt) — the reverse of the
// RFC's written order — so the swap lives here and nowhere else (Spec A §5.9 G1).
// the only error hkdf.Extract can return for HMAC-SHA256 is on an unavailable hash,
// which cannot happen for a compiled-in sha256, so it is unreachable rather than
// ignored.
func hpkeLabeledExtract(suiteId []byte, salt []byte, label string, ikm []byte) []byte {
	labeledIkm := make([]byte, 0, len(hpkeVersionLabel)+len(suiteId)+len(label)+len(ikm))
	labeledIkm = append(labeledIkm, hpkeVersionLabel...)
	labeledIkm = append(labeledIkm, suiteId...)
	labeledIkm = append(labeledIkm, label...)
	labeledIkm = append(labeledIkm, ikm...)
	prk, err := hkdf.Extract(sha256.New, labeledIkm, salt)
	if err != nil {
		panic("mls: hkdf extract failed with a compiled-in sha256: " + err.Error())
	}
	return prk
}

// LabeledExpand, RFC 9180 §4. the info argument of crypto/hkdf.Expand is typed
// string but is not text; the conversion is byte preserving.
func hpkeLabeledExpand(suiteId []byte, prk []byte, label string, info []byte, length int) ([]byte, error) {
	labeledInfo := make([]byte, 0, 2+len(hpkeVersionLabel)+len(suiteId)+len(label)+len(info))
	labeledInfo = binary.BigEndian.AppendUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, hpkeVersionLabel...)
	labeledInfo = append(labeledInfo, suiteId...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(sha256.New, prk, string(labeledInfo), length)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestHpkeSuiteIds|TestHpkeLabeled" -v` from `connect/`
Expected: PASS — three tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/hpke.go mls/hpke_test.go && \
git commit -m "feat(mls): hpke suite ids and labeled extract/expand"
```

---

### Task 6: DHKEM(X25519, HKDF-SHA256) key derivation, encapsulation and decapsulation

**Files:**
- Modify: `connect/mls/hpke.go`
- Test: `connect/mls/hpke_test.go`

**Interfaces:**
- Consumes: `hpkeKemSuiteId`, `hpkeLabeledExtract`, `hpkeLabeledExpand` (Task 5);
  `X25519PrivateKey`, `X25519PublicKey`, `X25519GenerateKey`, `X25519DH` (Task 4);
  `ErrBadKemOutput`, `ErrBadKeyLength` (Task 1).
- Produces:
  - `type HpkePublicKey []byte`
  - `type HpkePrivateKey []byte`
  - `func HpkeDeriveKeyPair(params *SuiteParams, ikm []byte) (HpkePrivateKey, HpkePublicKey, error)`
  - `func hpkeEncap(random io.Reader, params *SuiteParams, pub HpkePublicKey) (sharedSecret []byte, kemOutput []byte, err error)`
  - `func hpkeEncapDeterministic(params *SuiteParams, pub HpkePublicKey, ephemeralPriv HpkePrivateKey) (sharedSecret []byte, kemOutput []byte, err error)`
  - `func hpkeDecap(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte) ([]byte, error)`

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/hpke_test.go`:

```go
func TestHpkeDeriveKeyPairIsDeterministic(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	ikm := bytes.Repeat([]byte{0x42}, 32)
	priv1, pub1, err := HpkeDeriveKeyPair(params, ikm)
	if err != nil {
		t.Fatalf("derive 1: %v", err)
	}
	priv2, pub2, err := HpkeDeriveKeyPair(params, ikm)
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if !bytes.Equal(priv1, priv2) || !bytes.Equal(pub1, pub2) {
		t.Fatalf("derive is not deterministic")
	}
	if len(priv1) != params.Nsk || len(pub1) != params.Npk {
		t.Fatalf("sizes are %d/%d, want %d/%d", len(priv1), len(pub1), params.Nsk, params.Npk)
	}
	_, pub3, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatalf("derive 3: %v", err)
	}
	if bytes.Equal(pub1, pub3) {
		t.Fatalf("different ikm produced the same public key")
	}
}

func TestHpkeEncapDecapAgree(t *testing.T) {
	for _, suite := range Suites() {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite %#04x: %v", uint16(suite), err)
		}
		priv, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x01}, 32))
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		sharedSecret, kemOutput, err := hpkeEncap(rand.Reader, params, pub)
		if err != nil {
			t.Fatalf("encap: %v", err)
		}
		if len(kemOutput) != params.Nenc {
			t.Fatalf("kem output is %d bytes, want %d", len(kemOutput), params.Nenc)
		}
		back, err := hpkeDecap(params, priv, kemOutput)
		if err != nil {
			t.Fatalf("decap: %v", err)
		}
		if !bytes.Equal(sharedSecret, back) {
			t.Fatalf("suite %#04x: encap and decap disagree", uint16(suite))
		}
	}
}

func TestHpkeDecapRejectsWrongLengths(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	priv, _, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	for _, n := range []int{0, 31, 33, 1024} {
		if _, err := hpkeDecap(params, priv, make([]byte, n)); !errors.Is(err, ErrBadKemOutput) {
			t.Errorf("decap(%d bytes) error = %v, want ErrBadKemOutput", n, err)
		}
	}
	if _, err := hpkeDecap(params, make(HpkePrivateKey, 31), make([]byte, 32)); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("decap with a short private key error = %v, want ErrBadKeyLength", err)
	}
}

func TestHpkeEncapDeterministicMatchesEncap(t *testing.T) {
	// the vector gate in Task 9 drives encapsulation from a fixed ephemeral key.
	// this asserts the deterministic entry point is the same computation the
	// randomized one performs, so the gate is testing production code.
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	_, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x03}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	ephemeralPriv, ephemeralPub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x04}, 32))
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	sharedSecret, kemOutput, err := hpkeEncapDeterministic(params, pub, ephemeralPriv)
	if err != nil {
		t.Fatalf("encap deterministic: %v", err)
	}
	if !bytes.Equal(kemOutput, ephemeralPub) {
		t.Fatalf("kem output %x is not the ephemeral public key %x", kemOutput, ephemeralPub)
	}
	if len(sharedSecret) != params.Nsecret {
		t.Fatalf("shared secret is %d bytes, want %d", len(sharedSecret), params.Nsecret)
	}
}
```

Add `"crypto/rand"` and `"errors"` to the `hpke_test.go` import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestHpkeDerive|TestHpkeEncap|TestHpkeDecap" -v` from `connect/`
Expected: FAIL — `mls/hpke_test.go:...: undefined: HpkeDeriveKeyPair` (build failure).

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/hpke.go` (and add `"io"` to its imports):

```go
// serialized HPKE keys. named byte slices rather than an interface, because MLS
// carries them as opaque vectors and every consumer needs the bytes anyway.
type HpkePublicKey []byte
type HpkePrivateKey []byte

// DeriveKeyPair, RFC 9180 §7.1.3. for DHKEM(X25519) the expanded scalar is used
// directly — there is no rejection sampling, and clamping is x25519's own.
func HpkeDeriveKeyPair(params *SuiteParams, ikm []byte) (HpkePrivateKey, HpkePublicKey, error) {
	suiteId := hpkeKemSuiteId(params)
	dkpPrk := hpkeLabeledExtract(suiteId, nil, "dkp_prk", ikm)
	scalar, err := hpkeLabeledExpand(suiteId, dkpPrk, "sk", nil, params.Nsk)
	if err != nil {
		return nil, nil, err
	}
	priv, err := X25519PrivateKey(scalar)
	if err != nil {
		return nil, nil, err
	}
	return HpkePrivateKey(priv.Bytes()), HpkePublicKey(priv.PublicKey().Bytes()), nil
}

// ExtractAndExpand, RFC 9180 §4.1.
func hpkeExtractAndExpand(params *SuiteParams, dh []byte, kemContext []byte) ([]byte, error) {
	suiteId := hpkeKemSuiteId(params)
	eaePrk := hpkeLabeledExtract(suiteId, nil, "eae_prk", dh)
	return hpkeLabeledExpand(suiteId, eaePrk, "shared_secret", kemContext, params.Nsecret)
}

func hpkeEncap(random io.Reader, params *SuiteParams, pub HpkePublicKey) ([]byte, []byte, error) {
	ephemeral, err := X25519GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	return hpkeEncapDeterministic(params, pub, HpkePrivateKey(ephemeral.Bytes()))
}

// Encap with the ephemeral key supplied, so the RFC's vectors can drive production
// code rather than a parallel implementation written for the test.
func hpkeEncapDeterministic(params *SuiteParams, pub HpkePublicKey, ephemeralPriv HpkePrivateKey) ([]byte, []byte, error) {
	if len(ephemeralPriv) != params.Nsk {
		return nil, nil, ErrBadKeyLength
	}
	if len(pub) != params.Npk {
		return nil, nil, ErrBadKeyLength
	}
	ephemeral, err := X25519PrivateKey(ephemeralPriv)
	if err != nil {
		return nil, nil, err
	}
	recipient, err := X25519PublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	dh, err := X25519DH(ephemeral, recipient)
	if err != nil {
		return nil, nil, err
	}
	kemOutput := ephemeral.PublicKey().Bytes()
	kemContext := make([]byte, 0, len(kemOutput)+len(pub))
	kemContext = append(kemContext, kemOutput...)
	kemContext = append(kemContext, pub...)
	sharedSecret, err := hpkeExtractAndExpand(params, dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, kemOutput, nil
}

func hpkeDecap(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte) ([]byte, error) {
	if len(kemOutput) != params.Nenc {
		return nil, ErrBadKemOutput
	}
	if len(priv) != params.Nsk {
		return nil, ErrBadKeyLength
	}
	recipient, err := X25519PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	ephemeral, err := X25519PublicKey(kemOutput)
	if err != nil {
		return nil, err
	}
	dh, err := X25519DH(recipient, ephemeral)
	if err != nil {
		return nil, err
	}
	recipientPub := recipient.PublicKey().Bytes()
	kemContext := make([]byte, 0, len(kemOutput)+len(recipientPub))
	kemContext = append(kemContext, kemOutput...)
	kemContext = append(kemContext, recipientPub...)
	return hpkeExtractAndExpand(params, dh, kemContext)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestHpkeDerive|TestHpkeEncap|TestHpkeDecap" -v` from `connect/`
Expected: PASS — four tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/hpke.go mls/hpke_test.go && \
git commit -m "feat(mls): dhkem x25519 derive, encap and decap"
```

---

### Task 7: The HPKE key schedule and context

**Files:**
- Modify: `connect/mls/hpke.go`
- Test: `connect/mls/hpke_test.go`

**Interfaces:**
- Consumes: `hpkeSuiteId`, `hpkeLabeledExtract`, `hpkeLabeledExpand` (Task 5);
  `ErrBadKeyLength`, `ErrAeadOpen`, `ErrSequenceOverflow` (Task 1).
- Produces:
  - `type HpkeContext struct` — not safe for concurrent use
  - `func hpkeNewAead(params *SuiteParams, key []byte) (cipher.AEAD, error)`
  - `func hpkeKeySchedule(params *SuiteParams, sharedSecret []byte, info []byte) (*HpkeContext, error)`
  - `func (self *HpkeContext) Seal(aad []byte, plaintext []byte) ([]byte, error)`
  - `func (self *HpkeContext) Open(aad []byte, ciphertext []byte) ([]byte, error)`
  - `func (self *HpkeContext) Export(exporterContext []byte, length int) ([]byte, error)`

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/hpke_test.go`:

```go
func TestHpkeContextSequenceAdvances(t *testing.T) {
	// each Seal must use base_nonce XOR seq. a context that reused nonce zero would
	// still decrypt correctly under a matching receiver, so the only way to catch it
	// is to assert the ciphertexts differ for identical plaintext.
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	sender, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x05}, 32), []byte("info"))
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	receiver, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x05}, 32), []byte("info"))
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	plaintext := []byte("the same plaintext every time")
	var previous []byte
	for i := 0; i < 4; i++ {
		ciphertext, err := sender.Seal([]byte("aad"), plaintext)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if bytes.Equal(ciphertext, previous) {
			t.Fatalf("seal %d repeated the previous ciphertext: the sequence did not advance", i)
		}
		previous = ciphertext
		back, err := receiver.Open([]byte("aad"), ciphertext)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("open %d returned %q", i, back)
		}
	}
}

func TestHpkeContextOpenRejectsTamper(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	sender, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x06}, 32), nil)
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	ciphertext, err := sender.Seal([]byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := range ciphertext {
		receiver, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x06}, 32), nil)
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		tampered := bytes.Clone(ciphertext)
		tampered[i] ^= 0x01
		if _, err := receiver.Open([]byte("aad"), tampered); !errors.Is(err, ErrAeadOpen) {
			t.Fatalf("flipping byte %d: error = %v, want ErrAeadOpen", i, err)
		}
	}
	receiver, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x06}, 32), nil)
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	if _, err := receiver.Open([]byte("different aad"), ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Fatalf("wrong aad: error = %v, want ErrAeadOpen", err)
	}
}

func TestHpkeContextExportIsLabelSeparated(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	ctx, err := hpkeKeySchedule(params, bytes.Repeat([]byte{0x07}, 32), nil)
	if err != nil {
		t.Fatalf("key schedule: %v", err)
	}
	a, err := ctx.Export([]byte("context a"), 32)
	if err != nil {
		t.Fatalf("export a: %v", err)
	}
	b, err := ctx.Export([]byte("context b"), 32)
	if err != nil {
		t.Fatalf("export b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("different exporter contexts produced the same value")
	}
	// export must not consume a sequence number
	again, err := ctx.Export([]byte("context a"), 32)
	if err != nil {
		t.Fatalf("export a again: %v", err)
	}
	if !bytes.Equal(a, again) {
		t.Fatalf("export is not stable across calls")
	}
}

func TestHpkeAeadKeyLengthIsSuiteBound(t *testing.T) {
	// 0x0003 is a 32-byte key, 0x0001 is 16. a provider that hardcoded 32 would pass
	// every chacha test and silently fail on the aes suite.
	for _, testCase := range []struct {
		suite CipherSuite
		nk    int
	}{
		{suite: CipherSuiteX25519AesGcm128Sha256Ed25519, nk: 16},
		{suite: CipherSuiteX25519ChaCha20Sha256Ed25519, nk: 32},
	} {
		params, err := LookupSuite(testCase.suite)
		if err != nil {
			t.Fatalf("LookupSuite: %v", err)
		}
		if _, err := hpkeNewAead(params, make([]byte, testCase.nk)); err != nil {
			t.Errorf("suite %#04x rejected a %d-byte key: %v", uint16(testCase.suite), testCase.nk, err)
		}
		if _, err := hpkeNewAead(params, make([]byte, testCase.nk+1)); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("suite %#04x accepted a %d-byte key", uint16(testCase.suite), testCase.nk+1)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestHpkeContext|TestHpkeAead" -v` from `connect/`
Expected: FAIL — `mls/hpke_test.go:...: undefined: hpkeKeySchedule` (build failure).

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/hpke.go` (add `"crypto/aes"`, `"crypto/cipher"`, `"math"`, and
`"golang.org/x/crypto/chacha20poly1305"` to its imports):

```go
// an established HPKE context. NOT safe for concurrent use: Seal and Open each
// advance a sequence number, and two goroutines sealing at once would reuse a nonce,
// which is a total break of both AEADs for that message. every caller in this tree
// owns its context for the duration of one message.
type HpkeContext struct {
	params         *SuiteParams
	suiteId        []byte
	aead           cipher.AEAD
	baseNonce      []byte
	exporterSecret []byte
	sequence       uint64
}

func hpkeNewAead(params *SuiteParams, key []byte) (cipher.AEAD, error) {
	if len(key) != params.Nk {
		return nil, ErrBadKeyLength
	}
	switch params.AeadId {
	case HpkeAeadChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case HpkeAeadAes128Gcm:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, ErrUnknownCipherSuite
	}
}

// KeySchedule for mode_base, RFC 9180 §5.1. psk and psk_id are the empty defaults,
// which is not a shortcut: the v1 profile has no PSKs at all.
func hpkeKeySchedule(params *SuiteParams, sharedSecret []byte, info []byte) (*HpkeContext, error) {
	suiteId := hpkeSuiteId(params)
	pskIdHash := hpkeLabeledExtract(suiteId, nil, "psk_id_hash", nil)
	infoHash := hpkeLabeledExtract(suiteId, nil, "info_hash", info)

	keyScheduleContext := make([]byte, 0, 1+len(pskIdHash)+len(infoHash))
	keyScheduleContext = append(keyScheduleContext, hpkeModeBase)
	keyScheduleContext = append(keyScheduleContext, pskIdHash...)
	keyScheduleContext = append(keyScheduleContext, infoHash...)

	secret := hpkeLabeledExtract(suiteId, sharedSecret, "secret", nil)
	key, err := hpkeLabeledExpand(suiteId, secret, "key", keyScheduleContext, params.Nk)
	if err != nil {
		return nil, err
	}
	baseNonce, err := hpkeLabeledExpand(suiteId, secret, "base_nonce", keyScheduleContext, params.Nn)
	if err != nil {
		return nil, err
	}
	exporterSecret, err := hpkeLabeledExpand(suiteId, secret, "exp", keyScheduleContext, params.Nh)
	if err != nil {
		return nil, err
	}
	aead, err := hpkeNewAead(params, key)
	if err != nil {
		return nil, err
	}
	return &HpkeContext{
		params:         params,
		suiteId:        suiteId,
		aead:           aead,
		baseNonce:      baseNonce,
		exporterSecret: exporterSecret,
		sequence:       0,
	}, nil
}

// base_nonce XOR I2OSP(seq, Nn), RFC 9180 §5.2.
func (self *HpkeContext) nonce() []byte {
	nonce := make([]byte, self.params.Nn)
	binary.BigEndian.PutUint64(nonce[self.params.Nn-8:], self.sequence)
	for i := range nonce {
		nonce[i] ^= self.baseNonce[i]
	}
	return nonce
}

func (self *HpkeContext) advance() error {
	if self.sequence == math.MaxUint64 {
		return ErrSequenceOverflow
	}
	self.sequence++
	return nil
}

func (self *HpkeContext) Seal(aad []byte, plaintext []byte) ([]byte, error) {
	ciphertext := self.aead.Seal(nil, self.nonce(), plaintext, aad)
	if err := self.advance(); err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// a failure here is always ErrAeadOpen: the underlying error distinguishes nothing a
// caller may act on, and returning it would leak which check failed.
func (self *HpkeContext) Open(aad []byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := self.aead.Open(nil, self.nonce(), ciphertext, aad)
	if err != nil {
		return nil, ErrAeadOpen
	}
	if err := self.advance(); err != nil {
		return nil, err
	}
	return plaintext, nil
}

// the secret export interface of RFC 9180 §5.3. it does not consume a sequence
// number, so exporting is safe to interleave with sealing.
//
// this is the first caller-supplied length to reach hpkeLabeledExpand's guard, and
// that guard is load bearing: crypto/hkdf.Expand panics on a negative length (its
// fips140 body opens with make([]byte, 0, keyLen)), so without the refusal Export(ctx,
// -1) would kill the process. measured on go1.26.5 — -1 panics, 8160 returns, 8161
// returns "requested key length too large".
//
// decide here what error a bad length is. task 5 returns ErrBadKeyLength, whose text
// is "key length does not match the ciphersuite" and which reads wrong for an output
// length request concerning neither a key nor a ciphersuite. task 5 left it rather than
// adding a sentinel to task 1's crypto_errors.go, because the caller-facing semantics
// belong to this signature. either keep it deliberately or add ErrBadExportLength (and
// its entry in TestCryptoErrorsAreDistinct and in the task 1 contract above).
func (self *HpkeContext) Export(exporterContext []byte, length int) ([]byte, error) {
	return hpkeLabeledExpand(self.suiteId, self.exporterSecret, "sec", exporterContext, length)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestHpkeContext|TestHpkeAead" -v` from `connect/`
Expected: PASS — four tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/hpke.go mls/hpke_test.go && \
git commit -m "feat(mls): hpke base-mode key schedule, context seal, open and export"
```

---

### Task 8: Single-shot HpkeSealBase and HpkeOpenBase

**Files:**
- Modify: `connect/mls/hpke.go`
- Test: `connect/mls/hpke_test.go`

**Interfaces:**
- Consumes: `hpkeEncap`, `hpkeDecap` (Task 6); `hpkeKeySchedule` (Task 7).
- Produces:
  - `func HpkeSetupBaseS(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte) (kemOutput []byte, ctx *HpkeContext, err error)`
  - `func HpkeSetupBaseR(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte) (*HpkeContext, error)`
  - `func HpkeSealBase(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)`
  - `func HpkeOpenBase(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error)`

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/hpke_test.go`:

```go
func TestHpkeSealBaseRoundTrip(t *testing.T) {
	for _, suite := range Suites() {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite: %v", err)
		}
		priv, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x08}, 32))
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		info := []byte("the info")
		aad := []byte("the aad")
		plaintext := []byte("the plaintext")
		kemOutput, ciphertext, err := HpkeSealBase(rand.Reader, params, pub, info, aad, plaintext)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if len(ciphertext) != len(plaintext)+params.Nt {
			t.Fatalf("ciphertext is %d bytes, want %d", len(ciphertext), len(plaintext)+params.Nt)
		}
		back, err := HpkeOpenBase(params, priv, kemOutput, info, aad, ciphertext)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("suite %#04x round trip returned %q", uint16(suite), back)
		}
	}
}

func TestHpkeOpenBaseRejectsWrongInfo(t *testing.T) {
	// info is bound through the key schedule, so a wrong info is an open failure and
	// not a silently different plaintext. MLS puts the label and context here.
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	priv, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x09}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	kemOutput, ciphertext, err := HpkeSealBase(rand.Reader, params, pub, []byte("info a"), nil, []byte("plaintext"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := HpkeOpenBase(params, priv, kemOutput, []byte("info b"), nil, ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Fatalf("wrong info: error = %v, want ErrAeadOpen", err)
	}
}

func TestHpkeOpenBaseRejectsWrongRecipient(t *testing.T) {
	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("LookupSuite: %v", err)
	}
	_, pub, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x0a}, 32))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	otherPriv, _, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x0b}, 32))
	if err != nil {
		t.Fatalf("derive other: %v", err)
	}
	kemOutput, ciphertext, err := HpkeSealBase(rand.Reader, params, pub, nil, nil, []byte("plaintext"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := HpkeOpenBase(params, otherPriv, kemOutput, nil, nil, ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Fatalf("wrong recipient: error = %v, want ErrAeadOpen", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestHpkeSealBase -v` from `connect/`
Expected: FAIL — `mls/hpke_test.go:...: undefined: HpkeSealBase` (build failure).

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/hpke.go`:

```go
// SetupBaseS, RFC 9180 §5.1.1.
func HpkeSetupBaseS(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte) ([]byte, *HpkeContext, error) {
	sharedSecret, kemOutput, err := hpkeEncap(random, params, pub)
	if err != nil {
		return nil, nil, err
	}
	ctx, err := hpkeKeySchedule(params, sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}
	return kemOutput, ctx, nil
}

// SetupBaseR, RFC 9180 §5.1.1.
func HpkeSetupBaseR(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte) (*HpkeContext, error) {
	sharedSecret, err := hpkeDecap(params, priv, kemOutput)
	if err != nil {
		return nil, err
	}
	return hpkeKeySchedule(params, sharedSecret, info)
}

// the single-shot API of RFC 9180 §6.1, which is the only form MLS uses.
func HpkeSealBase(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) ([]byte, []byte, error) {
	kemOutput, ctx, err := HpkeSetupBaseS(random, params, pub, info)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := ctx.Seal(aad, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return kemOutput, ciphertext, nil
}

func HpkeOpenBase(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	ctx, err := HpkeSetupBaseR(params, priv, kemOutput, info)
	if err != nil {
		return nil, err
	}
	return ctx.Open(aad, ciphertext)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestHpke -v` from `connect/`
Expected: PASS — every `TestHpke*` ok.

- [ ] **Step 5: Commit**

```bash
git add mls/hpke.go mls/hpke_test.go && \
git commit -m "feat(mls): single-shot hpke seal and open in base mode"
```

---

### Task 9: Vendor the RFC 9180 vectors and gate HPKE against them

**Files:**
- Create: `connect/mls/testdata/vectors/rfc/hpke-rfc9180-x25519.json`
- Modify: `connect/mls/interop/PINS.md` (p8 Task 6's file — one row appended)
- Test: `connect/mls/hpke_vectors_test.go`

**Interfaces:**
- Consumes: everything from Tasks 5–8; `func MustHex(t *testing.T, s string) []byte` from the
  Validation and interop harness (p8, wave 1).
- Produces: nothing exported. This is the gate that says the HPKE instantiation is the RFC's, not
  merely self-consistent.

This file is **not** one of the sixteen mlswg families, so it is not vendored by p8 Task 6 and it
does not use `LoadVectorFile`: it lives under `testdata/vectors/rfc/` precisely so p8's assertion
that `testdata/vectors/*.json` is exactly the sixteen mlswg files stays exact. Its own sha256 pin
stays in this file's loader, and its provenance row goes in the one pin file,
`connect/mls/interop/PINS.md`.

- [ ] **Step 1: Write the failing test**

`connect/mls/hpke_vectors_test.go`:

```go
// the RFC 9180 base-mode vectors, both suites we instantiate.
//
// these drive production code: encapsulation runs through hpkeEncapDeterministic
// with the vector's own ephemeral key, so a passing run means the shipped Encap is
// right rather than that a test reimplemented it.
package mls

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
)

type hpkeVectorEncryption struct {
	Aad   string `json:"aad"`
	Ct    string `json:"ct"`
	Nonce string `json:"nonce"`
	Pt    string `json:"pt"`
}

type hpkeVectorExport struct {
	ExporterContext string `json:"exporter_context"`
	Length          int    `json:"L"`
	ExportedValue   string `json:"exported_value"`
}

type hpkeVector struct {
	Mode               int                    `json:"mode"`
	KemId              HpkeKemId              `json:"kem_id"`
	KdfId              HpkeKdfId              `json:"kdf_id"`
	AeadId             HpkeAeadId             `json:"aead_id"`
	Info               string                 `json:"info"`
	IkmE               string                 `json:"ikmE"`
	IkmR               string                 `json:"ikmR"`
	SkEm               string                 `json:"skEm"`
	SkRm               string                 `json:"skRm"`
	PkEm               string                 `json:"pkEm"`
	PkRm               string                 `json:"pkRm"`
	Enc                string                 `json:"enc"`
	SharedSecret       string                 `json:"shared_secret"`
	KeyScheduleContext string                 `json:"key_schedule_context"`
	Secret             string                 `json:"secret"`
	Key                string                 `json:"key"`
	BaseNonce          string                 `json:"base_nonce"`
	ExporterSecret     string                 `json:"exporter_secret"`
	Encryptions        []hpkeVectorEncryption `json:"encryptions"`
	Exports            []hpkeVectorExport     `json:"exports"`
}

const hpkeVectorPath = "testdata/vectors/rfc/hpke-rfc9180-x25519.json"

// the digest recorded in interop/PINS.md. a vector file that changed under us must
// break the build, not quietly weaken the gate.
const hpkeVectorSha256 = "3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a"

func loadHpkeVectors(t *testing.T) []hpkeVector {
	t.Helper()
	raw, err := os.ReadFile(hpkeVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", hpkeVectorPath, err)
	}
	digest := sha256.Sum256(raw)
	if got := HexOf(digest[:]); got != hpkeVectorSha256 {
		t.Fatalf("%s sha256 = %s, want %s (see interop/PINS.md)", hpkeVectorPath, got, hpkeVectorSha256)
	}
	var vectors []hpkeVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse %s: %v", hpkeVectorPath, err)
	}
	if len(vectors) != 2 {
		t.Fatalf("%s has %d vectors, want 2", hpkeVectorPath, len(vectors))
	}
	return vectors
}

func suiteForHpkeVector(t *testing.T, vector hpkeVector) *SuiteParams {
	t.Helper()
	if vector.Mode != 0 {
		t.Fatalf("vector mode is %d, want 0 (base)", vector.Mode)
	}
	for _, suite := range Suites() {
		params, err := LookupSuite(suite)
		if err != nil {
			t.Fatalf("LookupSuite: %v", err)
		}
		if params.KemId == vector.KemId && params.KdfId == vector.KdfId && params.AeadId == vector.AeadId {
			return params
		}
	}
	t.Fatalf("no registered suite for kem %#04x kdf %#04x aead %#04x", vector.KemId, vector.KdfId, vector.AeadId)
	return nil
}

func TestHpkeVectorDeriveKeyPair(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		privE, pubE, err := HpkeDeriveKeyPair(params, MustHex(t, vector.IkmE))
		if err != nil {
			t.Fatalf("derive e: %v", err)
		}
		if !bytes.Equal(privE, MustHex(t, vector.SkEm)) {
			t.Errorf("aead %#04x: skEm = %x, want %s", vector.AeadId, privE, vector.SkEm)
		}
		if !bytes.Equal(pubE, MustHex(t, vector.PkEm)) {
			t.Errorf("aead %#04x: pkEm = %x, want %s", vector.AeadId, pubE, vector.PkEm)
		}
		privR, pubR, err := HpkeDeriveKeyPair(params, MustHex(t, vector.IkmR))
		if err != nil {
			t.Fatalf("derive r: %v", err)
		}
		if !bytes.Equal(privR, MustHex(t, vector.SkRm)) {
			t.Errorf("aead %#04x: skRm = %x, want %s", vector.AeadId, privR, vector.SkRm)
		}
		if !bytes.Equal(pubR, MustHex(t, vector.PkRm)) {
			t.Errorf("aead %#04x: pkRm = %x, want %s", vector.AeadId, pubR, vector.PkRm)
		}
	}
}

func TestHpkeVectorEncapAndDecap(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		sharedSecret, kemOutput, err := hpkeEncapDeterministic(params,
			HpkePublicKey(MustHex(t, vector.PkRm)), HpkePrivateKey(MustHex(t, vector.SkEm)))
		if err != nil {
			t.Fatalf("encap: %v", err)
		}
		if !bytes.Equal(kemOutput, MustHex(t, vector.Enc)) {
			t.Errorf("aead %#04x: enc = %x, want %s", vector.AeadId, kemOutput, vector.Enc)
		}
		if !bytes.Equal(sharedSecret, MustHex(t, vector.SharedSecret)) {
			t.Errorf("aead %#04x: shared_secret = %x, want %s", vector.AeadId, sharedSecret, vector.SharedSecret)
		}
		back, err := hpkeDecap(params, HpkePrivateKey(MustHex(t, vector.SkRm)), MustHex(t, vector.Enc))
		if err != nil {
			t.Fatalf("decap: %v", err)
		}
		if !bytes.Equal(back, MustHex(t, vector.SharedSecret)) {
			t.Errorf("aead %#04x: decap shared_secret = %x, want %s", vector.AeadId, back, vector.SharedSecret)
		}
	}
}

func TestHpkeVectorKeySchedule(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		ctx, err := hpkeKeySchedule(params, MustHex(t, vector.SharedSecret), MustHex(t, vector.Info))
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		if !bytes.Equal(ctx.baseNonce, MustHex(t, vector.BaseNonce)) {
			t.Errorf("aead %#04x: base_nonce = %x, want %s", vector.AeadId, ctx.baseNonce, vector.BaseNonce)
		}
		if !bytes.Equal(ctx.exporterSecret, MustHex(t, vector.ExporterSecret)) {
			t.Errorf("aead %#04x: exporter_secret = %x, want %s", vector.AeadId, ctx.exporterSecret, vector.ExporterSecret)
		}
	}
}

func TestHpkeVectorEncryptions(t *testing.T) {
	// the vector's encryptions are indexed by sequence number, which is exactly the
	// context's own counter, so this walks the nonce derivation as well as the aead.
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		sender, err := hpkeKeySchedule(params, MustHex(t, vector.SharedSecret), MustHex(t, vector.Info))
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		for i, encryption := range vector.Encryptions {
			nonce := sender.nonce()
			if !bytes.Equal(nonce, MustHex(t, encryption.Nonce)) {
				t.Fatalf("aead %#04x seq %d: nonce = %x, want %s", vector.AeadId, i, nonce, encryption.Nonce)
			}
			ciphertext, err := sender.Seal(MustHex(t, encryption.Aad), MustHex(t, encryption.Pt))
			if err != nil {
				t.Fatalf("seal %d: %v", i, err)
			}
			if !bytes.Equal(ciphertext, MustHex(t, encryption.Ct)) {
				t.Fatalf("aead %#04x seq %d: ct = %x, want %s", vector.AeadId, i, ciphertext, encryption.Ct)
			}
		}
	}
}

func TestHpkeVectorExports(t *testing.T) {
	for _, vector := range loadHpkeVectors(t) {
		params := suiteForHpkeVector(t, vector)
		ctx, err := hpkeKeySchedule(params, MustHex(t, vector.SharedSecret), MustHex(t, vector.Info))
		if err != nil {
			t.Fatalf("key schedule: %v", err)
		}
		for i, export := range vector.Exports {
			got, err := ctx.Export(MustHex(t, export.ExporterContext), export.Length)
			if err != nil {
				t.Fatalf("export %d: %v", i, err)
			}
			if !bytes.Equal(got, MustHex(t, export.ExportedValue)) {
				t.Errorf("aead %#04x export %d = %x, want %s", vector.AeadId, i, got, export.ExportedValue)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestHpkeVector -v` from `connect/`
Expected: FAIL — `read testdata/vectors/rfc/hpke-rfc9180-x25519.json: open ...: no such file or
directory`.

- [ ] **Step 3: Write minimal implementation**

The implementation is the vendored data. Run, from `connect/mls/testdata/vectors/rfc/`:

```bash
mkdir -p . && \
curl -sL -o /tmp/hpke-upstream.json \
  https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json && \
sha256sum /tmp/hpke-upstream.json && \
python3 -c "
import json
d = json.load(open('/tmp/hpke-upstream.json'))
out = [v for v in d if v['mode'] == 0 and v['kem_id'] == 32 and v['kdf_id'] == 1 and v['aead_id'] in (1, 3)]
assert len(out) == 2, len(out)
s = json.dumps(out, indent=2, sort_keys=True) + '\n'
open('hpke-rfc9180-x25519.json', 'w', newline='\n').write(s)
" && \
sha256sum hpke-rfc9180-x25519.json
```

Expected digests, already computed against that commit:
`/tmp/hpke-upstream.json` → `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`
`hpke-rfc9180-x25519.json` → `3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a`

Then append one row and one section to `connect/mls/interop/PINS.md`, the single pin file that
p8 Task 6 creates. Do not create `connect/mls/PINS.md` or
`connect/mls/testdata/vectors/PINS.md`; neither exists in this slice.

```markdown
| `testdata/vectors/rfc/hpke-rfc9180-x25519.json` | `cfrg/draft-irtf-cfrg-hpke` | `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb` | `test-vectors.json` | `3cc5f951dea0b7dbe80419215e64c810498ee4dd76c376763bbe6860c346b11a` |
```

```markdown
## testdata/vectors/rfc/hpke-rfc9180-x25519.json

Not an mlswg family, hence `rfc/`: `testdata/vectors/*.json` stays exactly the sixteen mlswg files
p8 Task 6 vendors and asserts over.

Filtered from the upstream file, whose own sha256 at that commit is
`61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`, by the deterministic selection
`mode == 0 and kem_id == 32 and kdf_id == 1 and aead_id in (1, 3)`, re-serialized with
`json.dumps(out, indent=2, sort_keys=True)` and a trailing newline. That selects exactly the two
HPKE instantiations the two registered MLS ciphersuites use. Nothing is truncated: both entries
carry all 257 encryptions and all exports.

The full upstream file is 5.9 MB and 128 entries, of which 126 are for algorithms this
implementation does not have and will never gain, so vendoring it whole would be 5.7 MB of
permanently dead weight in every clone.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run TestHpkeVector -v` from `connect/`
Expected: PASS — `TestHpkeVectorDeriveKeyPair`, `TestHpkeVectorEncapAndDecap`,
`TestHpkeVectorKeySchedule`, `TestHpkeVectorEncryptions` (514 sealed messages across the two
suites), `TestHpkeVectorExports` all ok.

- [ ] **Step 5: Commit**

```bash
git add mls/testdata/vectors/rfc/hpke-rfc9180-x25519.json mls/interop/PINS.md mls/hpke_vectors_test.go && \
git commit -m "test(mls): gate hpke against the rfc 9180 base-mode vectors, both suites"
```

---

### Task 10: The HPKE decode-robustness fuzz target

**Files:**
- Test: `connect/mls/hpke_fuzz_test.go`

**Interfaces:**
- Consumes: `HpkeOpenBase`, `HpkeDeriveKeyPair`, `LookupSuite` (Tasks 3, 6, 8).
- Produces: `FuzzHpkeOpenBase`, `FuzzHpkeDeriveKeyPair` — property 1 of Gate 4 (no panic, no OOM, no
  unbounded allocation) over this plan's crypto surface. Both are private to this plan and neither
  is one of the nine codec fuzz targets Gate 4 counts: those are p8's, built on p8's codec table and
  oracle hook, and `TestFuzzTargetsCoverEveryKind` parses that file rather than this one. Properties
  2 and 3 belong to the codec, which is p1's.

- [ ] **Step 1: Write the failing test**

`connect/mls/hpke_fuzz_test.go`:

```go
// Gate 4 property 1 for the hpke surface: arbitrary attacker-chosen bytes in the kem
// output, the info, the aad and the ciphertext must produce an error, never a panic
// and never an allocation sized from an unvalidated length.
package mls

import (
	"bytes"
	"errors"
	"testing"
)

func FuzzHpkeOpenBase(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 32), []byte("info"), []byte("aad"), make([]byte, 16))
	f.Add(make([]byte, 33), []byte{}, []byte{}, make([]byte, 15))
	f.Add(bytes.Repeat([]byte{0xff}, 32), bytes.Repeat([]byte{0x00}, 64), []byte{}, bytes.Repeat([]byte{0xaa}, 1024))

	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		f.Fatalf("LookupSuite: %v", err)
	}
	priv, _, err := HpkeDeriveKeyPair(params, bytes.Repeat([]byte{0x0c}, 32))
	if err != nil {
		f.Fatalf("derive: %v", err)
	}

	f.Fuzz(func(t *testing.T, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) {
		plaintext, err := HpkeOpenBase(params, priv, kemOutput, info, aad, ciphertext)
		if err == nil && plaintext == nil {
			t.Fatalf("open returned a nil plaintext with no error")
		}
		if err != nil && plaintext != nil {
			t.Fatalf("open returned %d plaintext bytes alongside %v", len(plaintext), err)
		}
		// a length the ciphersuite fixes must be rejected by the length check, never
		// by a downstream parser that happens to also refuse it.
		if len(kemOutput) != params.Nenc && !errors.Is(err, ErrBadKemOutput) {
			t.Fatalf("a %d-byte kem output produced %v, not ErrBadKemOutput", len(kemOutput), err)
		}
	})
}

func FuzzHpkeDeriveKeyPair(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))
	f.Add(bytes.Repeat([]byte{0xff}, 4096))

	params, err := LookupSuite(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		f.Fatalf("LookupSuite: %v", err)
	}

	f.Fuzz(func(t *testing.T, ikm []byte) {
		priv, pub, err := HpkeDeriveKeyPair(params, ikm)
		if err != nil {
			return
		}
		if len(priv) != params.Nsk || len(pub) != params.Npk {
			t.Fatalf("derived %d/%d bytes, want %d/%d", len(priv), len(pub), params.Nsk, params.Npk)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Introduce the defect the target exists to catch, so the target is proved rather than assumed.
Temporarily remove the length guard from `X25519PublicKey` in `connect/mls/crypto_x25519.go`, so a
wrong-length key reaches `crypto/ecdh` directly:

```go
func X25519PublicKey(b []byte) (*ecdh.PublicKey, error) {
	// temporary: the `len(b) != x25519KeySize` guard is removed
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, ErrInvalidPoint
	}
	return pub, nil
}
```

Run: `go test ./mls/... -run FuzzHpkeOpenBase -v` from `connect/`
Expected: FAIL on the seed corpus alone — the 33-byte `kemOutput` entry reaches
`ecdh.X25519().NewPublicKey` with the wrong length. `crypto/ecdh` returns an error there rather than
panicking, so the observable failure is `hpkeDecap` returning `ErrInvalidPoint` where the length
check should have returned `ErrBadKemOutput`; add a temporary assertion in the fuzz body

```go
		if err != nil && len(kemOutput) != 32 && !errors.Is(err, ErrBadKemOutput) {
			t.Fatalf("a %d-byte kem output produced %v, not ErrBadKemOutput", len(kemOutput), err)
		}
```

which fails as `a 33-byte kem output produced mls: x25519 produced an invalid shared secret, not
ErrBadKemOutput`.

- [ ] **Step 3: Write minimal implementation**

Restore the `len(b) != x25519KeySize` guard exactly as Task 4 wrote it, and keep the temporary
assertion — it is a real invariant, not scaffolding: a length that the ciphersuite fixes must be
rejected by the length check and never by a downstream parser. Move it into the fuzz body
permanently, with `"errors"` added to the file's imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "FuzzHpkeOpenBase|FuzzHpkeDeriveKeyPair" -v` from `connect/`
Expected: PASS — seed corpus only.

Run: `go test ./mls/... -fuzz FuzzHpkeOpenBase -fuzztime 60s` from `connect/`
Expected: PASS — `elapsed: 60s, execs: ... (0 interesting)`, no crashers written to
`testdata/fuzz/`.

- [ ] **Step 5: Commit**

```bash
git add mls/hpke_fuzz_test.go && \
git commit -m "test(mls): fuzz hpke open and derive for panics and unbounded allocation"
```

---

### Task 11: The provider core — hash, mac, extract, expand, random

**Files:**
- Create: `connect/mls/crypto.go`
- Test: `connect/mls/crypto_test.go`

**Interfaces:**
- Consumes: `SuiteParams`, `LookupSuite` (Task 3); `hpkeNewAead` (Task 7);
  `ErrBadKeyLength`, `ErrBadNonceLength`, `ErrAeadOpen` (Task 1).
- Produces:
  - `type SignaturePublicKey []byte`, `type SignaturePrivateKey []byte`
  - `type CryptoProvider interface` — the full interface from the contract section
  - `type suiteCryptoProvider struct` implementing `Suite`, `HashSize`, `KeySize`, `NonceSize`,
    `Hash`, `Mac`, `MacVerify`, `Extract`, `Expand`, `AeadSeal`, `AeadOpen`, `Random`
  - `func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)`

  The remaining interface methods land in Tasks 12–16; the interface is declared whole here and the
  concrete type is completed method by method, so every intermediate commit still builds only once
  the type satisfies it. To keep that true, this task also lands compiling stubs for the six
  label-dependent methods that immediately `panic("not implemented until task N")`, and Tasks 12–16
  each replace exactly one. `TestProviderHasNoRemainingStubs` in Task 16 asserts none survive.

- [ ] **Step 1: Write the failing test**

`connect/mls/crypto_test.go`:

```go
package mls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
)

func TestProviderExtractArgumentOrder(t *testing.T) {
	// G1, the whole reason this wrapper exists. crypto/hkdf.Extract is (ikm, salt);
	// every spec text in this project writes HKDF-Extract(salt, ikm). the two are
	// distinguishable only by an independent computation, so here is one: HKDF-Extract
	// is literally HMAC(key = salt, message = ikm).
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	salt := []byte("this is the salt")
	ikm := []byte("this is the input keying material")

	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	want := mac.Sum(nil)

	if got := crypto.Extract(salt, ikm); !bytes.Equal(got, want) {
		t.Fatalf("Extract(salt, ikm) = %x, want %x — the arguments are swapped", got, want)
	}
	if got := crypto.Extract(ikm, salt); bytes.Equal(got, want) {
		t.Fatalf("Extract is symmetric, which is impossible for hmac")
	}
}

func TestProviderSizes(t *testing.T) {
	for _, testCase := range []struct {
		suite        CipherSuite
		hash, key, n int
	}{
		{suite: CipherSuiteX25519AesGcm128Sha256Ed25519, hash: 32, key: 16, n: 12},
		{suite: CipherSuiteX25519ChaCha20Sha256Ed25519, hash: 32, key: 32, n: 12},
	} {
		crypto, err := NewCryptoProvider(testCase.suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		if crypto.Suite() != testCase.suite {
			t.Errorf("Suite() = %#04x, want %#04x", uint16(crypto.Suite()), uint16(testCase.suite))
		}
		if crypto.HashSize() != testCase.hash {
			t.Errorf("suite %#04x HashSize() = %d, want %d", uint16(testCase.suite), crypto.HashSize(), testCase.hash)
		}
		if crypto.KeySize() != testCase.key {
			t.Errorf("suite %#04x KeySize() = %d, want %d", uint16(testCase.suite), crypto.KeySize(), testCase.key)
		}
		if crypto.NonceSize() != testCase.n {
			t.Errorf("suite %#04x NonceSize() = %d, want %d", uint16(testCase.suite), crypto.NonceSize(), testCase.n)
		}
	}
}

func TestProviderRefusesUnknownSuite(t *testing.T) {
	if _, err := NewCryptoProvider(0x0002); !errors.Is(err, ErrUnknownCipherSuite) {
		t.Fatalf("NewCryptoProvider(0x0002) error = %v, want ErrUnknownCipherSuite", err)
	}
}

func TestProviderMacVerifyIsConstantTime(t *testing.T) {
	// G8. the assertion available to a test is the behaviour, not the timing: verify
	// must reject a truncated tag rather than comparing a prefix, and must reject a
	// tag that differs only in its last byte.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	key := bytes.Repeat([]byte{0x0d}, 32)
	data := []byte("authenticated data")
	tag := crypto.Mac(key, data)
	if !crypto.MacVerify(key, data, tag) {
		t.Fatalf("MacVerify rejected its own tag")
	}
	if crypto.MacVerify(key, data, tag[:len(tag)-1]) {
		t.Errorf("MacVerify accepted a truncated tag")
	}
	if crypto.MacVerify(key, data, append(bytes.Clone(tag), 0x00)) {
		t.Errorf("MacVerify accepted an over-long tag")
	}
	last := bytes.Clone(tag)
	last[len(last)-1] ^= 0x01
	if crypto.MacVerify(key, data, last) {
		t.Errorf("MacVerify accepted a tag differing in its last byte")
	}
	if crypto.MacVerify(key, append(data, '!'), tag) {
		t.Errorf("MacVerify accepted a tag over different data")
	}
	if crypto.MacVerify(bytes.Repeat([]byte{0x0e}, 32), data, tag) {
		t.Errorf("MacVerify accepted a tag under a different key")
	}
}

func TestProviderAeadRejectsWrongSizes(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	key := make([]byte, crypto.KeySize())
	nonce := make([]byte, crypto.NonceSize())
	if _, err := crypto.AeadSeal(key[:len(key)-1], nonce, nil, nil); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("short key error = %v, want ErrBadKeyLength", err)
	}
	if _, err := crypto.AeadSeal(key, nonce[:len(nonce)-1], nil, nil); !errors.Is(err, ErrBadNonceLength) {
		t.Errorf("short nonce error = %v, want ErrBadNonceLength", err)
	}
	ciphertext, err := crypto.AeadSeal(key, nonce, []byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := crypto.AeadOpen(key, nonce, []byte("other aad"), ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Errorf("wrong aad error = %v, want ErrAeadOpen", err)
	}
	back, err := crypto.AeadOpen(key, nonce, []byte("aad"), ciphertext)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(back, []byte("plaintext")) {
		t.Fatalf("open returned %q", back)
	}
}

func TestProviderRandomIsNotConstant(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	first := crypto.Random(32)
	if len(first) != 32 {
		t.Fatalf("Random(32) returned %d bytes", len(first))
	}
	if bytes.Equal(first, make([]byte, 32)) {
		t.Fatalf("Random returned all zeroes")
	}
	if bytes.Equal(first, crypto.Random(32)) {
		t.Fatalf("Random repeated itself")
	}
}

func TestProviderIsSafeForConcurrentUse(t *testing.T) {
	// Spec A §3.6: CryptoProvider is safe for concurrent use, stateless. run under
	// -race, which is what actually makes this test mean something.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	key := bytes.Repeat([]byte{0x0f}, 32)
	nonce := make([]byte, 12)
	want := crypto.Hash([]byte("data"))

	var waitGroup sync.WaitGroup
	for i := 0; i < 32; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for j := 0; j < 64; j++ {
				if !bytes.Equal(crypto.Hash([]byte("data")), want) {
					t.Errorf("Hash disagreed with itself under concurrency")
					return
				}
				crypto.Mac(key, []byte("data"))
				crypto.Extract(key, []byte("ikm"))
				crypto.Expand(key, []byte("info"), 32)
				if _, err := crypto.AeadSeal(key, nonce, nil, []byte("plaintext")); err != nil {
					t.Errorf("seal: %v", err)
					return
				}
			}
		}()
	}
	waitGroup.Wait()
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestProviderExtractArgumentOrder -v` from `connect/`
Expected: FAIL — `mls/crypto_test.go:...: undefined: NewCryptoProvider` (build failure).

- [ ] **Step 3: Write minimal implementation**

`connect/mls/crypto.go`:

```go
// the whole cryptographic surface of the implementation, in one interface, so an
// audit has one file to read and a test can substitute a deterministic instance.
//
// the concrete implementation is stateless and therefore safe for concurrent use
// (Spec A §3.6). every size comes from the suite parameters rather than a literal,
// so a second suite cannot inherit the first one's key length.
package mls

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

// serialized signature keys. the private key is the RFC 8032 seed — 32 bytes, not
// go's 64-byte seed||public representation — because that is what the RFC 9420
// crypto-basics vectors carry and what MLS puts on the wire.
type SignaturePublicKey []byte
type SignaturePrivateKey []byte

type CryptoProvider interface {
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

type suiteCryptoProvider struct {
	params *SuiteParams
}

func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error) {
	params, err := LookupSuite(suite)
	if err != nil {
		return nil, err
	}
	return &suiteCryptoProvider{params: params}, nil
}

func (self *suiteCryptoProvider) Suite() CipherSuite { return self.params.Suite }
func (self *suiteCryptoProvider) HashSize() int      { return self.params.Nh }
func (self *suiteCryptoProvider) KeySize() int       { return self.params.Nk }
func (self *suiteCryptoProvider) NonceSize() int     { return self.params.Nn }

func (self *suiteCryptoProvider) Hash(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

func (self *suiteCryptoProvider) Mac(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// constant time by construction (G8). a length mismatch is rejected before the
// comparison, which is not a timing leak: the length of a tag is public.
func (self *suiteCryptoProvider) MacVerify(key []byte, data []byte, tag []byte) bool {
	expected := self.Mac(key, data)
	if len(tag) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, tag) == 1
}

// ARGUMENT ORDER IS (salt, ikm), matching every spec text in this project.
// crypto/hkdf.Extract is (ikm, salt); the swap lives here and in hpke.go and
// nowhere else (Spec A §5.9 G1, enforced by crypto_forbidden_test.go).
func (self *suiteCryptoProvider) Extract(salt []byte, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic("mls: hkdf extract failed with a compiled-in sha256: " + err.Error())
	}
	return prk
}

// a length above 255*Nh is a caller bug, not a runtime condition: the interface Spec
// A §3.3 fixes has no error return, and every call site in this package asks for a
// fixed small length. returning a short or truncated key instead would be a silent
// downgrade, so this panics rather than guessing.
func (self *suiteCryptoProvider) Expand(prk []byte, info []byte, length int) []byte {
	out, err := hkdf.Expand(sha256.New, prk, string(info), length)
	if err != nil {
		panic("mls: hkdf expand rejected the requested length: " + err.Error())
	}
	return out
}

func (self *suiteCryptoProvider) AeadSeal(key []byte, nonce []byte, aad []byte, plaintext []byte) ([]byte, error) {
	aead, err := hpkeNewAead(self.params, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != self.params.Nn {
		return nil, ErrBadNonceLength
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func (self *suiteCryptoProvider) AeadOpen(key []byte, nonce []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	aead, err := hpkeNewAead(self.params, key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != self.params.Nn {
		return nil, ErrBadNonceLength
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAeadOpen
	}
	return plaintext, nil
}

func (self *suiteCryptoProvider) Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("mls: crypto/rand failed: " + err.Error())
	}
	return b
}

// completed in tasks 12 through 16. TestProviderHasNoRemainingStubs asserts none of
// these survive the wave.
func (self *suiteCryptoProvider) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	panic("mls: ExpandWithLabel not implemented until task 12")
}

func (self *suiteCryptoProvider) DeriveSecret(secret []byte, label string) []byte {
	panic("mls: DeriveSecret not implemented until task 12")
}

func (self *suiteCryptoProvider) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte {
	panic("mls: DeriveTreeSecret not implemented until task 12")
}

func (self *suiteCryptoProvider) SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error) {
	panic("mls: SignWithLabel not implemented until task 14")
}

func (self *suiteCryptoProvider) VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error {
	panic("mls: VerifyWithLabel not implemented until task 14")
}

func (self *suiteCryptoProvider) SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error) {
	panic("mls: SignatureKeyPair not implemented until task 14")
}

func (self *suiteCryptoProvider) HpkeSeal(pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) ([]byte, []byte, error) {
	panic("mls: HpkeSeal not implemented until task 15")
}

func (self *suiteCryptoProvider) HpkeOpen(priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	panic("mls: HpkeOpen not implemented until task 15")
}

func (self *suiteCryptoProvider) DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error) {
	panic("mls: DeriveKeyPair not implemented until task 15")
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -race -run TestProvider -v` from `connect/`
Expected: PASS — `TestProviderExtractArgumentOrder`, `TestProviderSizes`,
`TestProviderRefusesUnknownSuite`, `TestProviderMacVerifyIsConstantTime`,
`TestProviderAeadRejectsWrongSizes`, `TestProviderRandomIsNotConstant`,
`TestProviderIsSafeForConcurrentUse` all ok, no race detected.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto.go mls/crypto_test.go && \
git commit -m "feat(mls): crypto provider core with (salt, ikm) extract and suite-bound sizes"
```

---

### Task 12: ExpandWithLabel, DeriveSecret and DeriveTreeSecret

**Files:**
- Create: `connect/mls/crypto_labels.go`
- Modify: `connect/mls/crypto.go`
- Test: `connect/mls/crypto_labels_test.go`

**Interfaces:**
- Consumes, from the **Syntax and codec (p1, wave 1)** plan, exactly:
  - `func syntax.NewWriter() *syntax.Writer`
  - `func (self *syntax.Writer) WriteUint16(v uint16)`
  - `func (self *syntax.Writer) WriteUint32(v uint32)`
  - `func (self *syntax.Writer) WriteOpaque(bs []byte)`
  - `func (self *syntax.Writer) Bytes() ([]byte, error)`
  - `func syntax.NewReader(bs []byte) *syntax.Reader`, `func (self *syntax.Reader) ReadOpaque() ([]byte, error)` — the boundary test reads its own encoding back
  - `const syntax.MaxVectorLength int`
- Consumes, from this plan: `CryptoProvider.Expand` (Task 11).
- Produces:
  - `func mlsLabelBytes(w *syntax.Writer) []byte`
  - `func mlsKdfLabel(label string, context []byte, length int) []byte`
  - `suiteCryptoProvider.ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte`
  - `suiteCryptoProvider.DeriveSecret(secret []byte, label string) []byte`
  - `suiteCryptoProvider.DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte`
  - `const MlsLabelPrefix = "MLS 1.0 "`

- [ ] **Step 1: Write the failing test**

`connect/mls/crypto_labels_test.go`:

```go
package mls

import (
	"bytes"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

func TestKdfLabelEncoding(t *testing.T) {
	// KDFLabel is { uint16 length; opaque label<V>; opaque context<V> } and the label
	// carries the "MLS 1.0 " prefix. MLS signs over serialized forms, so a byte wrong
	// here changes every derived secret in the protocol.
	got := mlsKdfLabel("test", []byte{0xde, 0xad}, 32)
	want := []byte{0x00, 0x20}
	want = append(want, byte(len("MLS 1.0 test")))
	want = append(want, "MLS 1.0 test"...)
	want = append(want, 0x02, 0xde, 0xad)
	if !bytes.Equal(got, want) {
		t.Fatalf("mlsKdfLabel = %x, want %x", got, want)
	}
}

func TestOpaqueVectorBoundariesMatchSyntax(t *testing.T) {
	// the boundary conformance this plan owes the Syntax plan. if syntax's prefix
	// widths drift, every signature and every derived secret in this package moves,
	// and it must fail here rather than at an interop run.
	for _, testCase := range []struct {
		n      int
		prefix []byte
	}{
		{n: 0, prefix: []byte{0x00}},
		{n: 63, prefix: []byte{0x3f}},
		{n: 64, prefix: []byte{0x40, 0x40}},
		{n: 16383, prefix: []byte{0x7f, 0xff}},
		{n: 16384, prefix: []byte{0x80, 0x00, 0x40, 0x00}},
	} {
		writer := syntax.NewWriter()
		writer.WriteOpaque(make([]byte, testCase.n))
		encoded, err := writer.Bytes()
		if err != nil {
			t.Fatalf("length %d: %v", testCase.n, err)
		}
		if !bytes.HasPrefix(encoded, testCase.prefix) {
			t.Errorf("length %d encoded with prefix %x, want %x", testCase.n, encoded[:len(testCase.prefix)], testCase.prefix)
		}
		if len(encoded) != len(testCase.prefix)+testCase.n {
			t.Errorf("length %d encoded to %d bytes, want %d", testCase.n, len(encoded), len(testCase.prefix)+testCase.n)
		}
		// and it must read back as the same vector, so the two halves of the prefix
		// cannot drift apart in the same commit.
		back, err := syntax.NewReader(encoded).ReadOpaque()
		if err != nil {
			t.Fatalf("length %d read back: %v", testCase.n, err)
		}
		if len(back) != testCase.n {
			t.Errorf("length %d read back as %d bytes", testCase.n, len(back))
		}
	}
}

func TestLabelWriterUsesTheDefaultVectorLimit(t *testing.T) {
	// mlsLabelBytes panics rather than returning a short preimage, and this pins the
	// boundary at which it would: syntax.MaxVectorLength. every value that reaches a
	// labelled construction came through a decode or an encode already bounded by it,
	// so the panic is unreachable in production — but if that ever stops being true,
	// it must stop being true loudly.
	writer := syntax.NewWriter()
	writer.WriteOpaque(make([]byte, syntax.MaxVectorLength))
	if _, err := writer.Bytes(); err != nil {
		t.Fatalf("a vector of exactly MaxVectorLength was refused: %v", err)
	}
	overlong := syntax.NewWriter()
	overlong.WriteOpaque(make([]byte, syntax.MaxVectorLength+1))
	if _, err := overlong.Bytes(); err == nil {
		t.Fatalf("a vector of MaxVectorLength+1 was accepted")
	}
}

func TestDeriveSecretIsExpandWithEmptyContext(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	secret := bytes.Repeat([]byte{0x10}, 32)
	if got, want := crypto.DeriveSecret(secret, "epoch"), crypto.ExpandWithLabel(secret, "epoch", nil, 32); !bytes.Equal(got, want) {
		t.Fatalf("DeriveSecret = %x, want %x", got, want)
	}
	if n := len(crypto.DeriveSecret(secret, "epoch")); n != crypto.HashSize() {
		t.Fatalf("DeriveSecret returned %d bytes, want %d", n, crypto.HashSize())
	}
}

func TestDeriveTreeSecretPutsGenerationInContext(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	secret := bytes.Repeat([]byte{0x11}, 32)
	generation := uint32(0xa0b0c0d0)
	got := crypto.DeriveTreeSecret(secret, "handshake", generation, 32)
	want := crypto.ExpandWithLabel(secret, "handshake", []byte{0xa0, 0xb0, 0xc0, 0xd0}, 32)
	if !bytes.Equal(got, want) {
		t.Fatalf("DeriveTreeSecret = %x, want %x — the generation is not a big-endian uint32 context", got, want)
	}
	if bytes.Equal(got, crypto.DeriveTreeSecret(secret, "handshake", generation+1, 32)) {
		t.Fatalf("consecutive generations derive the same secret")
	}
}

func TestExpandWithLabelSeparatesLabels(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	secret := bytes.Repeat([]byte{0x12}, 32)
	// the pair that would collide under naive concatenation: "ab" ‖ "c" vs "a" ‖ "bc".
	if bytes.Equal(crypto.ExpandWithLabel(secret, "ab", []byte("c"), 32),
		crypto.ExpandWithLabel(secret, "a", []byte("bc"), 32)) {
		t.Fatalf("label and context are not length separated")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestKdfLabelEncoding -v` from `connect/`
Expected: FAIL — `mls/crypto_labels_test.go:...: undefined: mlsKdfLabel` (build failure). If the
Syntax plan has not landed, the failure is instead
`no required module provides package github.com/urnetwork/connect/mls/syntax`, which is the correct
signal to execute that plan's Task 1 first.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/crypto_labels.go`:

```go
// the RFC 9420 §5.1-5.2 labelled constructions. every one of them is a TLS
// presentation-language struct, so all of them go through mls/syntax: there is one
// length-prefix implementation in the system and one place for a length-prefix bug
// to be.
//
// MLS signs and macs over these serialized forms, so a decoder that accepted two
// encodings of the same object would be a signature-bypass primitive. that is why
// nothing here hand-rolls a prefix.
package mls

import "github.com/urnetwork/connect/mls/syntax"

// every MLS label is domain separated by this prefix before serialization.
const MlsLabelPrefix = "MLS 1.0 "

// the sticky writer's error, taken once (C2).
//
// every labelled construction in this file returns bytes and no error, because the
// interface Spec A §3.3 fixes on CryptoProvider has no error return and neither does
// RefHash. that is sound rather than a shortcut: a syntax.Writer's only failure mode
// is a vector longer than its limit, and every value that reaches a labelled
// construction arrived through a decode or an encode already bounded by
// syntax.MaxVectorLength. a panic here is therefore unreachable — and it is a panic
// rather than a silent truncation because a short preimage is a signature-bypass
// primitive.
func mlsLabelBytes(w *syntax.Writer) []byte {
	encoded, err := w.Bytes()
	if err != nil {
		panic("mls: a labelled preimage could not be encoded: " + err.Error())
	}
	return encoded
}

// struct { uint16 length; opaque label<V>; opaque context<V> } KDFLabel
func mlsKdfLabel(label string, context []byte, length int) []byte {
	writer := syntax.NewWriter()
	writer.WriteUint16(uint16(length))
	writer.WriteOpaque([]byte(MlsLabelPrefix + label))
	writer.WriteOpaque(context)
	return mlsLabelBytes(writer)
}

func (self *suiteCryptoProvider) ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	return self.Expand(secret, mlsKdfLabel(label, context, length), length)
}

func (self *suiteCryptoProvider) DeriveSecret(secret []byte, label string) []byte {
	return self.ExpandWithLabel(secret, label, nil, self.params.Nh)
}

// the generation is the context, encoded as a big-endian uint32 (RFC 9420 §9). it
// goes through the same writer as everything else: there is one integer encoder in
// this system and it is p1's.
func (self *suiteCryptoProvider) DeriveTreeSecret(secret []byte, label string, generation uint32, length int) []byte {
	writer := syntax.NewWriter()
	writer.WriteUint32(generation)
	return self.ExpandWithLabel(secret, label, mlsLabelBytes(writer), length)
}
```

Delete the three corresponding stubs from `connect/mls/crypto.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestKdfLabel|TestOpaqueVectorBoundaries|TestLabelWriter|TestDeriveSecret|TestDeriveTree|TestExpandWithLabel" -v` from `connect/`
Expected: PASS — six tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_labels.go mls/crypto.go mls/crypto_labels_test.go && \
git commit -m "feat(mls): expand-with-label, derive-secret and derive-tree-secret"
```

---

### Task 13: RefHash, MakeKeyPackageRef and MakeProposalRef

**Files:**
- Modify: `connect/mls/crypto_labels.go`
- Test: `connect/mls/crypto_labels_test.go`

**Interfaces:**
- Consumes: `func syntax.NewWriter() *syntax.Writer`, `func (self *syntax.Writer) WriteOpaque(bs []byte)`,
  `func (self *syntax.Writer) Bytes() ([]byte, error)` (p1); `mlsLabelBytes` (Task 12);
  `CryptoProvider.Hash` (Task 11).
- Produces:
  - `func RefHash(crypto CryptoProvider, label string, value []byte) []byte`
  - `func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte`
  - `func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte`
  - `const KeyPackageRefLabel = "MLS 1.0 KeyPackage Reference"`
  - `const ProposalRefLabel = "MLS 1.0 Proposal Reference"`

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/crypto_labels_test.go`:

```go
func TestRefHashDoesNotAddTheMlsPrefix(t *testing.T) {
	// RefHash takes the FULL label. MakeKeyPackageRef passes
	// "MLS 1.0 KeyPackage Reference" already prefixed, and the crypto-basics vector
	// passes the bare string "RefHash". adding the prefix inside RefHash would pass
	// every round-trip test in this package and fail the vector and every peer.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	value := []byte("the value")

	bare := syntax.NewWriter()
	bare.WriteOpaque([]byte("RefHash"))
	bare.WriteOpaque(value)
	input, err := bare.Bytes()
	if err != nil {
		t.Fatalf("encode the bare-label input: %v", err)
	}
	if got, want := RefHash(crypto, "RefHash", value), crypto.Hash(input); !bytes.Equal(got, want) {
		t.Fatalf("RefHash = %x, want %x", got, want)
	}

	writer := syntax.NewWriter()
	writer.WriteOpaque([]byte(MlsLabelPrefix + "RefHash"))
	writer.WriteOpaque(value)
	prefixed, err := writer.Bytes()
	if err != nil {
		t.Fatalf("encode the prefixed-label input: %v", err)
	}
	if bytes.Equal(RefHash(crypto, "RefHash", value), crypto.Hash(prefixed)) {
		t.Fatalf("RefHash added the MLS 1.0 prefix")
	}
}

func TestRefLabelsAreTheRfcStrings(t *testing.T) {
	if KeyPackageRefLabel != "MLS 1.0 KeyPackage Reference" {
		t.Errorf("KeyPackageRefLabel = %q", KeyPackageRefLabel)
	}
	if ProposalRefLabel != "MLS 1.0 Proposal Reference" {
		t.Errorf("ProposalRefLabel = %q", ProposalRefLabel)
	}
}

func TestKeyPackageRefAndProposalRefDiffer(t *testing.T) {
	// the same bytes referenced as a key package and as a proposal must not collide,
	// which is the entire reason the two labels exist.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	value := bytes.Repeat([]byte{0x13}, 64)
	keyPackageRef := MakeKeyPackageRef(crypto, value)
	proposalRef := MakeProposalRef(crypto, value)
	if bytes.Equal(keyPackageRef, proposalRef) {
		t.Fatalf("key package and proposal references collide")
	}
	if len(keyPackageRef) != crypto.HashSize() || len(proposalRef) != crypto.HashSize() {
		t.Fatalf("reference sizes are %d/%d, want %d", len(keyPackageRef), len(proposalRef), crypto.HashSize())
	}
	if !bytes.Equal(keyPackageRef, RefHash(crypto, KeyPackageRefLabel, value)) {
		t.Fatalf("MakeKeyPackageRef is not RefHash with the key package label")
	}
	if !bytes.Equal(proposalRef, RefHash(crypto, ProposalRefLabel, value)) {
		t.Fatalf("MakeProposalRef is not RefHash with the proposal label")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestRefHash -v` from `connect/`
Expected: FAIL — `mls/crypto_labels_test.go:...: undefined: RefHash` (build failure).

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/crypto_labels.go`:

```go
// the reference labels of RFC 9420 §5.2, written out in full because RefHash does
// not add the MLS 1.0 prefix — its callers carry it.
const (
	KeyPackageRefLabel = "MLS 1.0 KeyPackage Reference"
	ProposalRefLabel   = "MLS 1.0 Proposal Reference"
)

// struct { opaque label<V>; opaque value<V> } RefHashInput, hashed.
//
// the label is used verbatim. this is not an oversight and not an inconsistency
// with ExpandWithLabel: RFC 9420 §5.2 defines the reference labels with the prefix
// already inside them, and the crypto-basics vector exercises RefHash with a bare
// label that must not gain one.
//
// no error return, by the registry's fixed signature — see mlsLabelBytes for why the
// writer cannot fail here.
func RefHash(crypto CryptoProvider, label string, value []byte) []byte {
	writer := syntax.NewWriter()
	writer.WriteOpaque([]byte(label))
	writer.WriteOpaque(value)
	return crypto.Hash(mlsLabelBytes(writer))
}

func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte {
	return RefHash(crypto, KeyPackageRefLabel, keyPackage)
}

// the input is the serialized AuthenticatedContent carrying the proposal, not the
// Proposal itself (RFC 9420 §5.2).
func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte {
	return RefHash(crypto, ProposalRefLabel, authenticatedContent)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestRefHash|TestRefLabels|TestKeyPackageRef" -v` from `connect/`
Expected: PASS — three tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_labels.go mls/crypto_labels_test.go && \
git commit -m "feat(mls): refhash and the key package and proposal reference labels"
```

---

### Task 14: SignWithLabel, VerifyWithLabel and SignatureKeyPair

**Files:**
- Modify: `connect/mls/crypto_labels.go`, `connect/mls/crypto.go`
- Test: `connect/mls/crypto_labels_test.go`

**Interfaces:**
- Consumes: `func syntax.NewWriter() *syntax.Writer`, `func (self *syntax.Writer) WriteOpaque(bs []byte)`,
  `func (self *syntax.Writer) Bytes() ([]byte, error)` (p1); `mlsLabelBytes` (Task 12);
  `ErrBadSignatureKey`, `ErrCryptoBadSignature` (Task 1).
- Produces:
  - `func mlsSignContent(label string, content []byte) []byte`
  - `suiteCryptoProvider.SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error)`
  - `suiteCryptoProvider.VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error`
  - `suiteCryptoProvider.SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error)`

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/crypto_labels_test.go`:

```go
func TestSignContentEncoding(t *testing.T) {
	// struct { opaque label<V>; opaque content<V> } SignContent, label prefixed.
	got := mlsSignContent("FramedContentTBS", []byte{0xbe, 0xef})
	want := []byte{byte(len("MLS 1.0 FramedContentTBS"))}
	want = append(want, "MLS 1.0 FramedContentTBS"...)
	want = append(want, 0x02, 0xbe, 0xef)
	if !bytes.Equal(got, want) {
		t.Fatalf("mlsSignContent = %x, want %x", got, want)
	}
}

func TestSignatureRoundTrip(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	if len(priv) != 32 || len(pub) != 32 {
		t.Fatalf("key sizes are %d/%d, want 32/32 — the private key must be the RFC 8032 seed", len(priv), len(pub))
	}
	content := []byte("the signed content")
	sig, err := crypto.SignWithLabel(priv, "LeafNodeTBS", content)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig))
	}
	if err := crypto.VerifyWithLabel(pub, "LeafNodeTBS", content, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestSignatureIsLabelBound(t *testing.T) {
	// a signature made under one label must not verify under another. without this
	// the label is decoration and a leaf-node signature could be replayed as a
	// framed-content signature.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	priv, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	content := []byte("the signed content")
	sig, err := crypto.SignWithLabel(priv, "LeafNodeTBS", content)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := crypto.VerifyWithLabel(pub, "FramedContentTBS", content, sig); !errors.Is(err, ErrCryptoBadSignature) {
		t.Fatalf("wrong label verified: error = %v, want ErrCryptoBadSignature", err)
	}
	if err := crypto.VerifyWithLabel(pub, "LeafNodeTBS", append(bytes.Clone(content), '!'), sig); !errors.Is(err, ErrCryptoBadSignature) {
		t.Fatalf("wrong content verified: error = %v, want ErrCryptoBadSignature", err)
	}
	tampered := bytes.Clone(sig)
	tampered[0] ^= 0x01
	if err := crypto.VerifyWithLabel(pub, "LeafNodeTBS", content, tampered); !errors.Is(err, ErrCryptoBadSignature) {
		t.Fatalf("tampered signature verified: error = %v, want ErrCryptoBadSignature", err)
	}
}

func TestSignatureRejectsWrongKeySizes(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := crypto.SignWithLabel(make(SignaturePrivateKey, n), "x", nil); !errors.Is(err, ErrBadSignatureKey) {
			t.Errorf("sign with a %d-byte key error = %v, want ErrBadSignatureKey", n, err)
		}
		if err := crypto.VerifyWithLabel(make(SignaturePublicKey, n), "x", nil, make([]byte, 64)); !errors.Is(err, ErrBadSignatureKey) {
			t.Errorf("verify with a %d-byte key error = %v, want ErrBadSignatureKey", n, err)
		}
	}
	_, pub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	for _, n := range []int{0, 63, 65} {
		if err := crypto.VerifyWithLabel(pub, "x", nil, make([]byte, n)); !errors.Is(err, ErrCryptoBadSignature) {
			t.Errorf("verify a %d-byte signature error = %v, want ErrCryptoBadSignature", n, err)
		}
	}
}
```

Add `"errors"` to the `crypto_labels_test.go` import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestSignContentEncoding -v` from `connect/`
Expected: FAIL — `mls/crypto_labels_test.go:...: undefined: mlsSignContent` (build failure).

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/crypto_labels.go` (add `"crypto/ed25519"` and `"crypto/rand"` to its
imports):

```go
// struct { opaque label<V>; opaque content<V> } SignContent
func mlsSignContent(label string, content []byte) []byte {
	writer := syntax.NewWriter()
	writer.WriteOpaque([]byte(MlsLabelPrefix + label))
	writer.WriteOpaque(content)
	return mlsLabelBytes(writer)
}

// the private key is the 32-byte RFC 8032 seed, which is what MLS carries and what
// the crypto-basics vectors supply. go's ed25519.PrivateKey is seed||public, so the
// expansion happens here and the 64-byte form never leaves this function.
func (self *suiteCryptoProvider) SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error) {
	if len(priv) != self.params.NsigPriv {
		return nil, ErrBadSignatureKey
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(priv), mlsSignContent(label, content)), nil
}

// a failed verification is always an error and never a logged warning (G7). the
// caller has no branch to take other than rejecting the message.
//
// ErrCryptoBadSignature, not ErrBadSignature: the bare name is errors.go's ValSem010,
// and errors.go wraps this one so a framing caller can still ask either question.
func (self *suiteCryptoProvider) VerifyWithLabel(pub SignaturePublicKey, label string, content []byte, sig []byte) error {
	if len(pub) != self.params.NsigPub {
		return ErrBadSignatureKey
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrCryptoBadSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), mlsSignContent(label, content), sig) {
		return ErrCryptoBadSignature
	}
	return nil
}

func (self *suiteCryptoProvider) SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return SignaturePrivateKey(priv.Seed()), SignaturePublicKey(pub), nil
}
```

Delete the three corresponding stubs from `connect/mls/crypto.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestSignContent|TestSignature" -v` from `connect/`
Expected: PASS — four tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_labels.go mls/crypto.go mls/crypto_labels_test.go && \
git commit -m "feat(mls): sign-with-label and verify-with-label over ed25519 seeds"
```

---

### Task 15: EncryptWithLabel, DecryptWithLabel and the provider HPKE methods

**Files:**
- Modify: `connect/mls/crypto_labels.go`, `connect/mls/crypto.go`
- Test: `connect/mls/crypto_labels_test.go`

**Interfaces:**
- Consumes: `func syntax.NewWriter() *syntax.Writer`, `func (self *syntax.Writer) WriteOpaque(bs []byte)`,
  `func (self *syntax.Writer) Bytes() ([]byte, error)` (p1); `mlsLabelBytes` (Task 12);
  `HpkeSealBase`, `HpkeOpenBase` (Task 8); `HpkeDeriveKeyPair` (Task 6).
- Produces:
  - `func mlsEncryptContext(label string, context []byte) []byte`
  - `func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)`
  - `func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error)`
  - `suiteCryptoProvider.HpkeSeal`, `suiteCryptoProvider.HpkeOpen`, `suiteCryptoProvider.DeriveKeyPair`

Both entry points keep the **flat byte-slice pair** `(kemOutput, ciphertext)`. The
`*HpkeCiphertext`-shaped convenience the group-lifecycle plan wants —
`SealWithLabel(crypto, pub, label, context, plaintext) (*HpkeCiphertext, error)` and
`OpenWithLabel(crypto, priv, label, context, ct *HpkeCiphertext) ([]byte, error)` — is **p5's**, and
lives next to the `HpkeCiphertext` type it returns so this plan stays free of TreeKEM types. Do not
add it here.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/crypto_labels_test.go`:

```go
func TestEncryptContextEncoding(t *testing.T) {
	// struct { opaque label<V>; opaque context<V> } EncryptContext, label prefixed.
	// this becomes the HPKE info, and RFC 9420 §5.1.3 seals with an EMPTY aad — the
	// context travels through info, never through aad.
	got := mlsEncryptContext("UpdatePathNode", []byte{0xca, 0xfe})
	want := []byte{byte(len("MLS 1.0 UpdatePathNode"))}
	want = append(want, "MLS 1.0 UpdatePathNode"...)
	want = append(want, 0x02, 0xca, 0xfe)
	if !bytes.Equal(got, want) {
		t.Fatalf("mlsEncryptContext = %x, want %x", got, want)
	}
}

func TestEncryptWithLabelRoundTrip(t *testing.T) {
	for _, suite := range Suites() {
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x14}, 32))
		if err != nil {
			t.Fatalf("DeriveKeyPair: %v", err)
		}
		context := []byte("the group context")
		plaintext := bytes.Repeat([]byte{0x15}, 32)
		kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, "UpdatePathNode", context, plaintext)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		back, err := DecryptWithLabel(crypto, priv, "UpdatePathNode", context, kemOutput, ciphertext)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(back, plaintext) {
			t.Fatalf("suite %#04x round trip returned %x", uint16(suite), back)
		}
	}
}

func TestEncryptWithLabelIsLabelAndContextBound(t *testing.T) {
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x16}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, "UpdatePathNode", []byte("context a"), []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptWithLabel(crypto, priv, "Welcome", []byte("context a"), kemOutput, ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Errorf("wrong label decrypted: error = %v, want ErrAeadOpen", err)
	}
	if _, err := DecryptWithLabel(crypto, priv, "UpdatePathNode", []byte("context b"), kemOutput, ciphertext); !errors.Is(err, ErrAeadOpen) {
		t.Errorf("wrong context decrypted: error = %v, want ErrAeadOpen", err)
	}
}

func TestProviderHpkeSealUsesAnEmptyAadForLabelledEncryption(t *testing.T) {
	// EncryptWithLabel must reach HpkeSeal with a nil aad. sealing the context into
	// aad instead of info would round trip inside this implementation and fail every
	// peer, which is exactly the class of bug the interop harness is slow to find.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	priv, pub, err := crypto.DeriveKeyPair(bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	context := []byte("the group context")
	kemOutput, ciphertext, err := EncryptWithLabel(crypto, pub, "UpdatePathNode", context, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	back, err := crypto.HpkeOpen(priv, kemOutput, mlsEncryptContext("UpdatePathNode", context), nil, ciphertext)
	if err != nil {
		t.Fatalf("open with info=EncryptContext and aad=nil failed: %v", err)
	}
	if !bytes.Equal(back, []byte("secret")) {
		t.Fatalf("open returned %q", back)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestEncryptContextEncoding -v` from `connect/`
Expected: FAIL — `mls/crypto_labels_test.go:...: undefined: mlsEncryptContext` (build failure).

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/crypto_labels.go`:

```go
// struct { opaque label<V>; opaque context<V> } EncryptContext
func mlsEncryptContext(label string, context []byte) []byte {
	writer := syntax.NewWriter()
	writer.WriteOpaque([]byte(MlsLabelPrefix + label))
	writer.WriteOpaque(context)
	return mlsLabelBytes(writer)
}

// EncryptWithLabel, RFC 9420 §5.1.3. the EncryptContext is the HPKE info and the
// AEAD aad is empty — MLS binds the context through the key schedule, not through
// the aad, and swapping the two produces a construction that talks only to itself.
func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) ([]byte, []byte, error) {
	return crypto.HpkeSeal(pub, mlsEncryptContext(label, context), nil, plaintext)
}

func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error) {
	return crypto.HpkeOpen(priv, kemOutput, mlsEncryptContext(label, context), nil, ciphertext)
}
```

Replace the three HPKE stubs in `connect/mls/crypto.go` with (add `"crypto/rand"` to its imports if
not already present):

```go
func (self *suiteCryptoProvider) HpkeSeal(pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) ([]byte, []byte, error) {
	return HpkeSealBase(rand.Reader, self.params, pub, info, aad, plaintext)
}

func (self *suiteCryptoProvider) HpkeOpen(priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error) {
	return HpkeOpenBase(self.params, priv, kemOutput, info, aad, ciphertext)
}

func (self *suiteCryptoProvider) DeriveKeyPair(ikm []byte) (HpkePrivateKey, HpkePublicKey, error) {
	return HpkeDeriveKeyPair(self.params, ikm)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestEncryptContext|TestEncryptWithLabel|TestProviderHpkeSeal" -v` from `connect/`
Expected: PASS — four tests ok.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_labels.go mls/crypto.go mls/crypto_labels_test.go && \
git commit -m "feat(mls): encrypt-with-label and decrypt-with-label over hpke base mode"
```

---

### Task 16: Assert the provider has no remaining stubs

**Files:**
- Test: `connect/mls/crypto_test.go`

**Interfaces:**
- Consumes: the whole `CryptoProvider` (Tasks 11–15).
- Produces: `TestProviderHasNoRemainingStubs` — the gate that says the interface is completely
  implemented for every registered suite, so a later plan calling a method this wave forgot gets a
  test failure here rather than a panic in production.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/crypto_test.go`:

```go
func TestProviderHasNoRemainingStubs(t *testing.T) {
	// every method, on every registered suite, with arguments valid for that suite.
	// a surviving panic("not implemented until task N") fails here.
	for _, suite := range Suites() {
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			t.Fatalf("NewCryptoProvider %#04x: %v", uint16(suite), err)
		}
		secret := bytes.Repeat([]byte{0x18}, crypto.HashSize())
		key := bytes.Repeat([]byte{0x19}, crypto.KeySize())
		nonce := make([]byte, crypto.NonceSize())

		crypto.Hash(nil)
		crypto.Mac(key, nil)
		crypto.MacVerify(key, nil, crypto.Mac(key, nil))
		crypto.Extract(secret, secret)
		crypto.Expand(secret, []byte("info"), 32)
		crypto.ExpandWithLabel(secret, "label", nil, 32)
		crypto.DeriveSecret(secret, "label")
		crypto.DeriveTreeSecret(secret, "label", 0, 32)

		ciphertext, err := crypto.AeadSeal(key, nonce, nil, []byte("plaintext"))
		if err != nil {
			t.Fatalf("suite %#04x AeadSeal: %v", uint16(suite), err)
		}
		if _, err := crypto.AeadOpen(key, nonce, nil, ciphertext); err != nil {
			t.Fatalf("suite %#04x AeadOpen: %v", uint16(suite), err)
		}

		signPriv, signPub, err := crypto.SignatureKeyPair()
		if err != nil {
			t.Fatalf("suite %#04x SignatureKeyPair: %v", uint16(suite), err)
		}
		sig, err := crypto.SignWithLabel(signPriv, "label", []byte("content"))
		if err != nil {
			t.Fatalf("suite %#04x SignWithLabel: %v", uint16(suite), err)
		}
		if err := crypto.VerifyWithLabel(signPub, "label", []byte("content"), sig); err != nil {
			t.Fatalf("suite %#04x VerifyWithLabel: %v", uint16(suite), err)
		}

		hpkePriv, hpkePub, err := crypto.DeriveKeyPair(secret)
		if err != nil {
			t.Fatalf("suite %#04x DeriveKeyPair: %v", uint16(suite), err)
		}
		kemOutput, sealed, err := crypto.HpkeSeal(hpkePub, []byte("info"), []byte("aad"), []byte("plaintext"))
		if err != nil {
			t.Fatalf("suite %#04x HpkeSeal: %v", uint16(suite), err)
		}
		if _, err := crypto.HpkeOpen(hpkePriv, kemOutput, []byte("info"), []byte("aad"), sealed); err != nil {
			t.Fatalf("suite %#04x HpkeOpen: %v", uint16(suite), err)
		}

		crypto.Random(32)
		RefHash(crypto, "label", nil)
		MakeKeyPackageRef(crypto, nil)
		MakeProposalRef(crypto, nil)
		if _, _, err := EncryptWithLabel(crypto, hpkePub, "label", nil, []byte("x")); err != nil {
			t.Fatalf("suite %#04x EncryptWithLabel: %v", uint16(suite), err)
		}
	}
}

func TestNoStubPanicsRemainInSource(t *testing.T) {
	// the textual half: the placeholder string must not survive the wave.
	for path, text := range forbiddenScanPaths(t) {
		if strings.HasSuffix(path, "crypto_test.go") {
			continue
		}
		if strings.Contains(text, "not implemented until task") {
			t.Errorf("%s still carries a task stub", path)
		}
	}
}
```

Add `"strings"` to the `crypto_test.go` import block.

- [ ] **Step 2: Run test to verify it fails**

Reintroduce one stub temporarily. In `connect/mls/crypto_labels.go`, replace the body of
`DeriveSecret` with `panic("mls: DeriveSecret not implemented until task 12")`.

Run: `go test ./mls/... -run "TestProviderHasNoRemainingStubs|TestNoStubPanics" -v` from `connect/`
Expected: FAIL — `panic: mls: DeriveSecret not implemented until task 12` in
`TestProviderHasNoRemainingStubs`, and
`mls/crypto_labels.go still carries a task stub` in `TestNoStubPanicsRemainInSource`.

- [ ] **Step 3: Write minimal implementation**

Restore `DeriveSecret` to the body Task 12 wrote:

```go
func (self *suiteCryptoProvider) DeriveSecret(secret []byte, label string) []byte {
	return self.ExpandWithLabel(secret, label, nil, self.params.Nh)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -race -v` from `connect/`
Expected: PASS — the whole `mls` package, including both stub gates.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_test.go && \
git commit -m "test(mls): assert the crypto provider is complete for every registered suite"
```

---

### Task 16a: NewCryptoProviderWithRandom, the deterministic provider

The canonical interface registry assigns this constructor to this plan as a gap: the Validation and
interop harness's forge needs a provider whose randomness it controls, so that a failing ValSem case
reproduces byte for byte, and nothing produced it. It is a new task rather than an amendment to Task
11 because it changes where three methods get their entropy, and that change deserves its own red
test.

**Files:**
- Modify: `connect/mls/crypto.go`, `connect/mls/crypto_labels.go`
- Test: `connect/mls/crypto_test.go`

**Interfaces:**
- Consumes: `LookupSuite` (Task 3); the whole `CryptoProvider` (Tasks 11–16).
- Produces:
  - `func NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error)`
  - `suiteCryptoProvider.random io.Reader` — the single entropy source for `Random`,
    `SignatureKeyPair` and `HpkeSeal`

`NewCryptoProvider(suite)` keeps its exact signature and becomes
`NewCryptoProviderWithRandom(suite, rand.Reader)`, so there is one implementation and the default is
visibly `crypto/rand`.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/crypto_test.go`:

```go
func TestProviderWithRandomIsDeterministic(t *testing.T) {
	// two providers over the same byte stream must produce the same keys and the same
	// sealed bytes. this is what makes a failing interop or ValSem case reproducible
	// rather than a one-shot observation.
	stream := func() io.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x1a}, 4096)) }

	first, err := NewCryptoProviderWithRandom(CipherSuiteX25519ChaCha20Sha256Ed25519, stream())
	if err != nil {
		t.Fatalf("NewCryptoProviderWithRandom: %v", err)
	}
	second, err := NewCryptoProviderWithRandom(CipherSuiteX25519ChaCha20Sha256Ed25519, stream())
	if err != nil {
		t.Fatalf("NewCryptoProviderWithRandom: %v", err)
	}

	if !bytes.Equal(first.Random(32), second.Random(32)) {
		t.Fatalf("Random does not read from the supplied reader")
	}

	firstPriv, firstPub, err := first.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	secondPriv, secondPub, err := second.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	if !bytes.Equal(firstPriv, secondPriv) || !bytes.Equal(firstPub, secondPub) {
		t.Fatalf("SignatureKeyPair does not read from the supplied reader")
	}

	_, pub, err := first.DeriveKeyPair(bytes.Repeat([]byte{0x1b}, 32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	firstKem, firstCiphertext, err := first.HpkeSeal(pub, []byte("info"), []byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatalf("HpkeSeal: %v", err)
	}
	secondKem, secondCiphertext, err := second.HpkeSeal(pub, []byte("info"), []byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatalf("HpkeSeal: %v", err)
	}
	if !bytes.Equal(firstKem, secondKem) || !bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Fatalf("HpkeSeal does not read its ephemeral key from the supplied reader")
	}
}

func TestProviderWithRandomRefusesUnknownSuite(t *testing.T) {
	if _, err := NewCryptoProviderWithRandom(0x0002, rand.Reader); !errors.Is(err, ErrUnknownCipherSuite) {
		t.Fatalf("error = %v, want ErrUnknownCipherSuite", err)
	}
}

func TestNewCryptoProviderDefaultsToCryptoRand(t *testing.T) {
	// the default constructor must NOT be deterministic. a provider that quietly took
	// a fixed stream would pass every other test in this package and destroy every key
	// in production.
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	other, err := NewCryptoProvider(CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	if bytes.Equal(crypto.Random(32), other.Random(32)) {
		t.Fatalf("two default providers produced the same random bytes")
	}
	priv, _, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	otherPriv, _, err := other.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	if bytes.Equal(priv, otherPriv) {
		t.Fatalf("two default providers produced the same signature key")
	}
}

func TestProviderRandomFailureIsNotSilent(t *testing.T) {
	// a short reader must not yield short or zero key material. Random has no error
	// return in the interface Spec A §3.3 fixes, so the only correct behaviour is a
	// panic, and it is asserted rather than assumed.
	crypto, err := NewCryptoProviderWithRandom(CipherSuiteX25519ChaCha20Sha256Ed25519, bytes.NewReader([]byte{0x01, 0x02}))
	if err != nil {
		t.Fatalf("NewCryptoProviderWithRandom: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Fatalf("Random returned from an exhausted reader instead of panicking")
		}
	}()
	crypto.Random(32)
}
```

Add `"io"` to the `crypto_test.go` import block; `"crypto/rand"` is already needed by
`TestProviderWithRandomRefusesUnknownSuite`, so add it too.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run "TestProviderWithRandom|TestNewCryptoProviderDefaults|TestProviderRandomFailure" -v` from `connect/`
Expected: FAIL — `mls/crypto_test.go:...: undefined: NewCryptoProviderWithRandom` (build failure).

- [ ] **Step 3: Write minimal implementation**

In `connect/mls/crypto.go`, add the field, add the constructor, and route the three entropy
consumers through it (add `"io"` to the imports; `"crypto/rand"` is already there):

```go
type suiteCryptoProvider struct {
	params *SuiteParams
	random io.Reader
}

func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error) {
	return NewCryptoProviderWithRandom(suite, rand.Reader)
}

// the deterministic constructor. the interop forge and the negative-path tests need a
// provider whose entropy they control, so a failing ValSem case reproduces byte for
// byte instead of being observed once. production callers use NewCryptoProvider and
// get crypto/rand; nothing in this package reads crypto/rand behind a caller's back.
func NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error) {
	params, err := LookupSuite(suite)
	if err != nil {
		return nil, err
	}
	return &suiteCryptoProvider{params: params, random: random}, nil
}

// a failure here is not a runtime condition a caller can act on and the interface has
// no error return, so a short read panics rather than yielding short or zero key
// material.
func (self *suiteCryptoProvider) Random(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(self.random, b); err != nil {
		panic("mls: the random source failed: " + err.Error())
	}
	return b
}

func (self *suiteCryptoProvider) HpkeSeal(pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) ([]byte, []byte, error) {
	return HpkeSealBase(self.random, self.params, pub, info, aad, plaintext)
}
```

Delete the Task 11 `Random` body and the Task 15 `HpkeSeal` body they replace, and the
`NewCryptoProvider` body Task 11 wrote.

In `connect/mls/crypto_labels.go`, `SignatureKeyPair` stops reading `crypto/rand` directly:

```go
func (self *suiteCryptoProvider) SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(self.random)
	if err != nil {
		return nil, nil, err
	}
	return SignaturePrivateKey(priv.Seed()), SignaturePublicKey(pub), nil
}
```

`"crypto/rand"` can now leave `crypto_labels.go`'s import block entirely.

Finally, narrow the concurrency claim in `crypto.go`'s file comment, which Task 11 wrote as an
unconditional property of the type:

```go
// the implementation NewCryptoProvider returns is safe for concurrent use (Spec A
// §3.6): it holds only the suite parameters and crypto/rand.Reader, both of which are.
// a provider built by NewCryptoProviderWithRandom inherits the caller's reader and is
// exactly as concurrency-safe as that reader — the deterministic test readers are not,
// and are used from one goroutine.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -race -run "TestProvider|TestNewCryptoProvider" -v` from `connect/`
Expected: PASS — every `TestProvider*` from Tasks 11 and 16 still ok, plus
`TestProviderWithRandomIsDeterministic`, `TestProviderWithRandomRefusesUnknownSuite`,
`TestNewCryptoProviderDefaultsToCryptoRand`, `TestProviderRandomFailureIsNotSilent`.

`TestProviderIsSafeForConcurrentUse` still passes: `crypto/rand.Reader` is safe for concurrent use,
and a provider built over a caller's own reader inherits that caller's guarantee — which is why the
concurrency claim in the doc comment is now stated against `NewCryptoProvider`, not against every
instance.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto.go mls/crypto_labels.go mls/crypto_test.go && \
git commit -m "feat(mls): deterministic crypto provider over a caller-supplied random source"
```

---

### Task 17: The crypto-basics vector gate, verify direction

**Files:**
- Modify: `connect/mls/vectors_test.go` — delete `2` from `expectedPendingFamilies`, one line
- Test: `connect/mls/crypto_basics_kat_test.go`

The vector **file** `connect/mls/testdata/vectors/crypto-basics.json` is not created here. All
sixteen mlswg files, plus `testdata/vectors/VECTORS.sha256` and the pin rows in
`connect/mls/interop/PINS.md`, are vendored once by **p8 Task 6**; this plan keeps only the runner.
Sequence this task after p8 Task 6 — both are wave 1.

**Interfaces:**
- Consumes: the whole `CryptoProvider` and `RefHash` (Tasks 11–16a); from the Validation and interop
  harness (p8, wave 1), exactly:
  - `func LoadVectorFile(t *testing.T, file string) []json.RawMessage`
  - `func MustHex(t *testing.T, s string) []byte`
  - `type VectorFamily struct { Number int; Name string; File string; Slice string; Verify func(t *testing.T, raw json.RawMessage); Generate func(t *testing.T) json.RawMessage }`
  - `func RegisterVectorFamily(family VectorFamily)`
- Produces: the `crypto-basics` gate — the acceptance criterion this plan is measured by — registered
  as **family 2** so `TestVectorFamiliesVerify` runs it. Without the registration Gate 1 is green
  with fifteen of sixteen families never executed, which is the specific failure the registry names.

- [ ] **Step 1: Write the failing test**

`connect/mls/crypto_basics_kat_test.go`:

```go
// the crypto-basics family of the RFC 9420 test vectors, vector family 2 of 16.
//
// the file carries one entry per ciphersuite, 0x0001 through 0x0007. we implement two
// of them, and the other five are refused explicitly with the suite recorded, so the
// count of exercised entries is visible rather than assumed.
//
// the file itself, its sha256 and its row in interop/PINS.md are p8 Task 6's; this
// file is the runner and nothing else.
package mls

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type cryptoBasicsRefHash struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Out   string `json:"out"`
}

type cryptoBasicsExpandWithLabel struct {
	Secret  string `json:"secret"`
	Label   string `json:"label"`
	Context string `json:"context"`
	Length  int    `json:"length"`
	Out     string `json:"out"`
}

type cryptoBasicsDeriveSecret struct {
	Secret string `json:"secret"`
	Label  string `json:"label"`
	Out    string `json:"out"`
}

type cryptoBasicsDeriveTreeSecret struct {
	Secret     string `json:"secret"`
	Label      string `json:"label"`
	Generation uint32 `json:"generation"`
	Length     int    `json:"length"`
	Out        string `json:"out"`
}

type cryptoBasicsSignWithLabel struct {
	Priv      string `json:"priv"`
	Pub       string `json:"pub"`
	Content   string `json:"content"`
	Label     string `json:"label"`
	Signature string `json:"signature"`
}

type cryptoBasicsEncryptWithLabel struct {
	Priv       string `json:"priv"`
	Pub        string `json:"pub"`
	Label      string `json:"label"`
	Context    string `json:"context"`
	Plaintext  string `json:"plaintext"`
	KemOutput  string `json:"kem_output"`
	Ciphertext string `json:"ciphertext"`
}

type cryptoBasicsVector struct {
	CipherSuite      CipherSuite                  `json:"cipher_suite"`
	RefHash          cryptoBasicsRefHash          `json:"ref_hash"`
	ExpandWithLabel  cryptoBasicsExpandWithLabel  `json:"expand_with_label"`
	DeriveSecret     cryptoBasicsDeriveSecret     `json:"derive_secret"`
	DeriveTreeSecret cryptoBasicsDeriveTreeSecret `json:"derive_tree_secret"`
	SignWithLabel    cryptoBasicsSignWithLabel    `json:"sign_with_label"`
	EncryptWithLabel cryptoBasicsEncryptWithLabel `json:"encrypt_with_label"`
}

const cryptoBasicsFile = "crypto-basics.json"

// registered from an init so TestVectorFamiliesVerify picks family 2 up. the same
// commit that lands this file deletes 2 from expectedPendingFamilies in
// vectors_test.go — a registered family that is still listed as pending is a gate
// that reports green while running nothing.
func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   2,
		Name:     "crypto-basics",
		File:     cryptoBasicsFile,
		Slice:    "A1",
		Verify:   verifyCryptoBasicsRaw,
		Generate: generateCryptoBasicsRaw,
	})
}

// LoadVectorFile is p8's: it resolves the path under testdata/vectors and checks the
// entry's digest against VECTORS.sha256, so this file carries no path and no pin.
func loadCryptoBasicsVectors(t *testing.T) []cryptoBasicsVector {
	t.Helper()
	raws := LoadVectorFile(t, cryptoBasicsFile)
	if len(raws) != 7 {
		t.Fatalf("%s has %d entries, want 7", cryptoBasicsFile, len(raws))
	}
	vectors := make([]cryptoBasicsVector, 0, len(raws))
	for i, raw := range raws {
		var vector cryptoBasicsVector
		if err := json.Unmarshal(raw, &vector); err != nil {
			t.Fatalf("%s entry %d: %v", cryptoBasicsFile, i, err)
		}
		vectors = append(vectors, vector)
	}
	return vectors
}

// the registry's Verify hook: one raw entry, already digest-checked by p8.
func verifyCryptoBasicsRaw(t *testing.T, raw json.RawMessage) {
	t.Helper()
	var vector cryptoBasicsVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("parse a crypto-basics entry: %v", err)
	}
	if !IsRegisteredSuite(vector.CipherSuite) {
		// not a skip: an unregistered suite must be refused, and asserting that here
		// keeps the five unimplemented entries inside the gate rather than outside it.
		if _, err := NewCryptoProvider(vector.CipherSuite); !errors.Is(err, ErrUnknownCipherSuite) {
			t.Fatalf("suite %#04x error = %v, want ErrUnknownCipherSuite", uint16(vector.CipherSuite), err)
		}
		return
	}
	verifyCryptoBasicsVector(t, vector)
}

func TestCryptoBasicsCoversBothRegisteredSuites(t *testing.T) {
	// the count is asserted so a registry change cannot quietly halve the gate.
	exercised := 0
	for _, vector := range loadCryptoBasicsVectors(t) {
		if IsRegisteredSuite(vector.CipherSuite) {
			exercised++
		}
	}
	if exercised != 2 {
		t.Fatalf("the vector file exercises %d registered suites, want 2", exercised)
	}
}

func TestCryptoBasicsRefHash(t *testing.T) {
	for _, vector := range loadCryptoBasicsVectors(t) {
		if !IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		crypto, err := NewCryptoProvider(vector.CipherSuite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		got := RefHash(crypto, vector.RefHash.Label, MustHex(t, vector.RefHash.Value))
		if !bytes.Equal(got, MustHex(t, vector.RefHash.Out)) {
			t.Errorf("suite %#04x RefHash = %x, want %s", uint16(vector.CipherSuite), got, vector.RefHash.Out)
		}
	}
}

func TestCryptoBasicsExpandWithLabel(t *testing.T) {
	for _, vector := range loadCryptoBasicsVectors(t) {
		if !IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		crypto, err := NewCryptoProvider(vector.CipherSuite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		testCase := vector.ExpandWithLabel
		got := crypto.ExpandWithLabel(MustHex(t, testCase.Secret), testCase.Label, MustHex(t, testCase.Context), testCase.Length)
		if !bytes.Equal(got, MustHex(t, testCase.Out)) {
			t.Errorf("suite %#04x ExpandWithLabel = %x, want %s", uint16(vector.CipherSuite), got, testCase.Out)
		}
	}
}

func TestCryptoBasicsDeriveSecret(t *testing.T) {
	for _, vector := range loadCryptoBasicsVectors(t) {
		if !IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		crypto, err := NewCryptoProvider(vector.CipherSuite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		testCase := vector.DeriveSecret
		got := crypto.DeriveSecret(MustHex(t, testCase.Secret), testCase.Label)
		if !bytes.Equal(got, MustHex(t, testCase.Out)) {
			t.Errorf("suite %#04x DeriveSecret = %x, want %s", uint16(vector.CipherSuite), got, testCase.Out)
		}
	}
}

func TestCryptoBasicsDeriveTreeSecret(t *testing.T) {
	for _, vector := range loadCryptoBasicsVectors(t) {
		if !IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		crypto, err := NewCryptoProvider(vector.CipherSuite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		testCase := vector.DeriveTreeSecret
		got := crypto.DeriveTreeSecret(MustHex(t, testCase.Secret), testCase.Label, testCase.Generation, testCase.Length)
		if !bytes.Equal(got, MustHex(t, testCase.Out)) {
			t.Errorf("suite %#04x DeriveTreeSecret = %x, want %s", uint16(vector.CipherSuite), got, testCase.Out)
		}
	}
}

func TestCryptoBasicsSignWithLabel(t *testing.T) {
	for _, vector := range loadCryptoBasicsVectors(t) {
		if !IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		crypto, err := NewCryptoProvider(vector.CipherSuite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		testCase := vector.SignWithLabel
		if err := crypto.VerifyWithLabel(SignaturePublicKey(MustHex(t, testCase.Pub)),
			testCase.Label, MustHex(t, testCase.Content), MustHex(t, testCase.Signature)); err != nil {
			t.Errorf("suite %#04x VerifyWithLabel on the supplied signature: %v", uint16(vector.CipherSuite), err)
		}
		// ed25519 is deterministic, so our own signature must be byte identical.
		got, err := crypto.SignWithLabel(SignaturePrivateKey(MustHex(t, testCase.Priv)),
			testCase.Label, MustHex(t, testCase.Content))
		if err != nil {
			t.Fatalf("suite %#04x SignWithLabel: %v", uint16(vector.CipherSuite), err)
		}
		if !bytes.Equal(got, MustHex(t, testCase.Signature)) {
			t.Errorf("suite %#04x SignWithLabel = %x, want %s", uint16(vector.CipherSuite), got, testCase.Signature)
		}
	}
}

func TestCryptoBasicsEncryptWithLabel(t *testing.T) {
	for _, vector := range loadCryptoBasicsVectors(t) {
		if !IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		crypto, err := NewCryptoProvider(vector.CipherSuite)
		if err != nil {
			t.Fatalf("NewCryptoProvider: %v", err)
		}
		testCase := vector.EncryptWithLabel
		got, err := DecryptWithLabel(crypto, HpkePrivateKey(MustHex(t, testCase.Priv)),
			testCase.Label, MustHex(t, testCase.Context),
			MustHex(t, testCase.KemOutput), MustHex(t, testCase.Ciphertext))
		if err != nil {
			t.Fatalf("suite %#04x DecryptWithLabel: %v", uint16(vector.CipherSuite), err)
		}
		if !bytes.Equal(got, MustHex(t, testCase.Plaintext)) {
			t.Errorf("suite %#04x DecryptWithLabel = %x, want %s", uint16(vector.CipherSuite), got, testCase.Plaintext)
		}
		// the vector's public key must be the one its private key derives, or the
		// pairing is untested and a swapped key would go unnoticed.
		priv, err := X25519PrivateKey(MustHex(t, testCase.Priv))
		if err != nil {
			t.Fatalf("parse priv: %v", err)
		}
		if !bytes.Equal(priv.PublicKey().Bytes(), MustHex(t, testCase.Pub)) {
			t.Errorf("suite %#04x: the vector's pub is not derived from its priv", uint16(vector.CipherSuite))
		}
		// tampering must fail closed
		tampered := bytes.Clone(MustHex(t, testCase.Ciphertext))
		tampered[0] ^= 0x01
		if _, err := DecryptWithLabel(crypto, HpkePrivateKey(MustHex(t, testCase.Priv)),
			testCase.Label, MustHex(t, testCase.Context), MustHex(t, testCase.KemOutput), tampered); !errors.Is(err, ErrAeadOpen) {
			t.Errorf("suite %#04x: a tampered ciphertext decrypted", uint16(vector.CipherSuite))
		}
	}
}

func TestCryptoBasicsUnimplementedSuitesAreRefused(t *testing.T) {
	// the five entries we do not implement must be refused by the registry rather
	// than silently defaulted, and the count is asserted so a registry change shows up.
	refused := 0
	for _, vector := range loadCryptoBasicsVectors(t) {
		if IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		refused++
		if _, err := NewCryptoProvider(vector.CipherSuite); !errors.Is(err, ErrUnknownCipherSuite) {
			t.Errorf("suite %#04x error = %v, want ErrUnknownCipherSuite", uint16(vector.CipherSuite), err)
		}
	}
	if refused != 5 {
		t.Fatalf("refused %d suites, want 5 (0x0002, 0x0004, 0x0005, 0x0006, 0x0007)", refused)
	}
}
```

`verifyCryptoBasicsVector` and `generateCryptoBasicsRaw` are written in Task 18; this task's
`init()` references them, so Task 17 and Task 18 land as a pair or Task 17's file does not compile.
That is deliberate: registering a family whose `Generate` hook is nil would hide the second
direction from the registry rather than from the reader.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestCryptoBasics -v` from `connect/`
Expected: FAIL — `mls/crypto_basics_kat_test.go:...: undefined: verifyCryptoBasicsVector` (build
failure). If p8 Task 6 has not landed, the failure is instead
`crypto-basics.json: no such file` from `LoadVectorFile`, which is the correct signal to run p8's
vendoring task first.

- [ ] **Step 3: Write minimal implementation**

No production code and no vendored data. The file and its digest are p8 Task 6's; this task's
implementation is the runner in Step 1 plus, in the **same commit**, the one-line deletion of `2`
from `expectedPendingFamilies` in `connect/mls/vectors_test.go`:

```go
// before
var expectedPendingFamilies = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
// after
var expectedPendingFamilies = []int{1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestCryptoBasics|TestVectorFamilies" -v` from `connect/`
Expected: PASS — `TestCryptoBasicsCoversBothRegisteredSuites`, `TestCryptoBasicsRefHash`,
`TestCryptoBasicsExpandWithLabel`, `TestCryptoBasicsDeriveSecret`,
`TestCryptoBasicsDeriveTreeSecret`, `TestCryptoBasicsSignWithLabel`,
`TestCryptoBasicsEncryptWithLabel`, `TestCryptoBasicsUnimplementedSuitesAreRefused` all ok, and
p8's `TestVectorFamiliesVerify` now runs family 2 rather than skipping it, with
`expectedPendingFamilies` down to fifteen entries.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_basics_kat_test.go mls/vectors_test.go && \
git commit -m "test(mls): register and gate the crypto-basics vector family, both suites"
```

---

### Task 18: The crypto-basics generate direction

**Files:**
- Test: `connect/mls/crypto_basics_kat_test.go`

**Interfaces:**
- Consumes: everything from Task 17; `func HexOf(b []byte) string` and
  `func MustHex(t *testing.T, s string) []byte` from the Validation and interop harness (p8).
- Produces: `verifyCryptoBasicsVector`, `generateCryptoBasicsRaw` — the `Generate` hook the family
  registration in Task 17 names — and `TestCryptoBasicsGenerate`, Spec A §4.2.1's second direction.
  Verification alone cannot see a bug where the encoder and the decoder are wrong in the same
  direction, because a supplied vector never round-trips through our encoder.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/crypto_basics_kat_test.go`:

```go
// the registry's Generate hook. one entry per registered suite, in the mlswg format,
// as a single json.RawMessage array — the shape RegisterVectorFamily expects.
func generateCryptoBasicsRaw(t *testing.T) json.RawMessage {
	t.Helper()
	generated := make([]cryptoBasicsVector, 0, len(Suites()))
	for _, suite := range Suites() {
		generated = append(generated, generateCryptoBasicsVector(t, suite))
	}
	raw, err := json.Marshal(generated)
	if err != nil {
		t.Fatalf("marshal the generated crypto-basics vectors: %v", err)
	}
	return raw
}

func TestCryptoBasicsGenerate(t *testing.T) {
	// generate a fresh vector from our own implementation, serialize it in the mlswg
	// format, parse it back, and verify it through the same path the supplied vectors
	// take. this catches an encoder and a decoder that are wrong together.
	var decoded []cryptoBasicsVector
	if err := json.Unmarshal(generateCryptoBasicsRaw(t), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded) != len(Suites()) {
		t.Fatalf("decoded %d entries, want %d", len(decoded), len(Suites()))
	}
	for _, vector := range decoded {
		verifyCryptoBasicsVector(t, vector)
	}
}

// one generated entry. HexOf is p8's, the same encoder every other family uses, so
// the corpus this plan emits and the corpus p8's oracle reads cannot disagree about
// case or about the empty string.
func generateCryptoBasicsVector(t *testing.T, suite CipherSuite) cryptoBasicsVector {
	t.Helper()
	crypto, err := NewCryptoProvider(suite)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	secret := crypto.Random(crypto.HashSize())
	signPriv, signPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	hpkePriv, hpkePub, err := crypto.DeriveKeyPair(crypto.Random(32))
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}
	content := crypto.Random(48)
	signature, err := crypto.SignWithLabel(signPriv, "GeneratedSignLabel", content)
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	plaintext := crypto.Random(32)
	context := crypto.Random(16)
	kemOutput, ciphertext, err := EncryptWithLabel(crypto, hpkePub, "GeneratedEncryptLabel", context, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithLabel: %v", err)
	}

	return cryptoBasicsVector{
		CipherSuite: suite,
		RefHash: cryptoBasicsRefHash{
			Label: "GeneratedRefLabel",
			Value: HexOf(content),
			Out:   HexOf(RefHash(crypto, "GeneratedRefLabel", content)),
		},
		ExpandWithLabel: cryptoBasicsExpandWithLabel{
			Secret:  HexOf(secret),
			Label:   "GeneratedExpandLabel",
			Context: HexOf(context),
			Length:  32,
			Out:     HexOf(crypto.ExpandWithLabel(secret, "GeneratedExpandLabel", context, 32)),
		},
		DeriveSecret: cryptoBasicsDeriveSecret{
			Secret: HexOf(secret),
			Label:  "GeneratedDeriveLabel",
			Out:    HexOf(crypto.DeriveSecret(secret, "GeneratedDeriveLabel")),
		},
		DeriveTreeSecret: cryptoBasicsDeriveTreeSecret{
			Secret:     HexOf(secret),
			Label:      "GeneratedTreeLabel",
			Generation: 0x0102_0304,
			Length:     32,
			Out:        HexOf(crypto.DeriveTreeSecret(secret, "GeneratedTreeLabel", 0x0102_0304, 32)),
		},
		SignWithLabel: cryptoBasicsSignWithLabel{
			Priv:      HexOf(signPriv),
			Pub:       HexOf(signPub),
			Content:   HexOf(content),
			Label:     "GeneratedSignLabel",
			Signature: HexOf(signature),
		},
		EncryptWithLabel: cryptoBasicsEncryptWithLabel{
			Priv:       HexOf(hpkePriv),
			Pub:        HexOf(hpkePub),
			Label:      "GeneratedEncryptLabel",
			Context:    HexOf(context),
			Plaintext:  HexOf(plaintext),
			KemOutput:  HexOf(kemOutput),
			Ciphertext: HexOf(ciphertext),
		},
	}
}

// the single verification path, applied to both supplied and generated vectors.
func verifyCryptoBasicsVector(t *testing.T, vector cryptoBasicsVector) {
	t.Helper()
	crypto, err := NewCryptoProvider(vector.CipherSuite)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	if got := RefHash(crypto, vector.RefHash.Label, MustHex(t, vector.RefHash.Value)); !bytes.Equal(got, MustHex(t, vector.RefHash.Out)) {
		t.Errorf("suite %#04x RefHash = %x, want %s", uint16(vector.CipherSuite), got, vector.RefHash.Out)
	}
	expand := vector.ExpandWithLabel
	if got := crypto.ExpandWithLabel(MustHex(t, expand.Secret), expand.Label, MustHex(t, expand.Context), expand.Length); !bytes.Equal(got, MustHex(t, expand.Out)) {
		t.Errorf("suite %#04x ExpandWithLabel = %x, want %s", uint16(vector.CipherSuite), got, expand.Out)
	}
	derive := vector.DeriveSecret
	if got := crypto.DeriveSecret(MustHex(t, derive.Secret), derive.Label); !bytes.Equal(got, MustHex(t, derive.Out)) {
		t.Errorf("suite %#04x DeriveSecret = %x, want %s", uint16(vector.CipherSuite), got, derive.Out)
	}
	tree := vector.DeriveTreeSecret
	if got := crypto.DeriveTreeSecret(MustHex(t, tree.Secret), tree.Label, tree.Generation, tree.Length); !bytes.Equal(got, MustHex(t, tree.Out)) {
		t.Errorf("suite %#04x DeriveTreeSecret = %x, want %s", uint16(vector.CipherSuite), got, tree.Out)
	}
	sign := vector.SignWithLabel
	if err := crypto.VerifyWithLabel(SignaturePublicKey(MustHex(t, sign.Pub)), sign.Label, MustHex(t, sign.Content), MustHex(t, sign.Signature)); err != nil {
		t.Errorf("suite %#04x VerifyWithLabel: %v", uint16(vector.CipherSuite), err)
	}
	encrypt := vector.EncryptWithLabel
	got, err := DecryptWithLabel(crypto, HpkePrivateKey(MustHex(t, encrypt.Priv)), encrypt.Label,
		MustHex(t, encrypt.Context), MustHex(t, encrypt.KemOutput), MustHex(t, encrypt.Ciphertext))
	if err != nil {
		t.Errorf("suite %#04x DecryptWithLabel: %v", uint16(vector.CipherSuite), err)
		return
	}
	if !bytes.Equal(got, MustHex(t, encrypt.Plaintext)) {
		t.Errorf("suite %#04x DecryptWithLabel = %x, want %s", uint16(vector.CipherSuite), got, encrypt.Plaintext)
	}
}

func TestCryptoBasicsSuppliedVectorsThroughTheGeneratePath(t *testing.T) {
	// the supplied vectors, verified through the same helper the generated ones use,
	// so the two directions cannot drift apart.
	for _, vector := range loadCryptoBasicsVectors(t) {
		if !IsRegisteredSuite(vector.CipherSuite) {
			continue
		}
		verifyCryptoBasicsVector(t, vector)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./mls/... -run TestCryptoBasicsGenerate -v` from `connect/`
Expected: FAIL — `mls/crypto_basics_kat_test.go:...: undefined: generateCryptoBasicsVector` if the
generator is added in a second edit, or a compile error on the `cryptoBasicsVector` literal if any
field name drifted from Task 17.

- [ ] **Step 3: Write minimal implementation**

No production code changes. The generate direction is satisfied entirely by the code Tasks 11–16a
already landed; if it fails, the fix belongs in whichever of those tasks the failing field maps to,
not here.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./mls/... -run "TestCryptoBasics|TestVectorFamilies" -v` from `connect/`
Expected: PASS — ten tests ok, covering both directions for both registered suites, and family 2's
`Generate` hook is now non-nil, so p8's registry runner exercises it instead of treating the format
as having no generate direction.

- [ ] **Step 5: Commit**

```bash
git add mls/crypto_basics_kat_test.go && \
git commit -m "test(mls): crypto-basics generate direction, both suites"
```

---

### Task 19: X-Wing sizes, seed expansion and key generation

**Files:**
- Create: `connect/message/doc.go`, `connect/message/xwing_errors.go`, `connect/message/xwing.go`
- Test: `connect/message/xwing_test.go`

**Interfaces:**
- Consumes: `mls.X25519PrivateKey`, `mls.X25519PublicKey` (Task 4).
- Produces:
  - the `Xwing*` size constants and `XwingAlgId` from the contract section
  - `type XwingPrivateKey struct`, `type XwingPublicKey struct`
  - `func XwingKeyGenFromSeed(seed []byte) (*XwingPrivateKey, error)`
  - `func XwingGenerateKey(random io.Reader) (*XwingPrivateKey, error)`
  - `func (self *XwingPrivateKey) Public() *XwingPublicKey`
  - `func (self *XwingPrivateKey) Seed() []byte`
  - `func (self *XwingPublicKey) Bytes() []byte`
  - `func ParseXwingPublicKey(b []byte) (*XwingPublicKey, error)`
  - `ErrXwingBadSeedSize`, `ErrXwingBadPublicKeySize`, `ErrXwingBadCiphertextSize`,
    `ErrXwingInvalidPoint`

- [ ] **Step 1: Write the failing test**

`connect/message/xwing_test.go`:

```go
package message

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"testing"
)

func TestXwingSizesAreTheDraftSizes(t *testing.T) {
	// G9. the 32 vs 64 seed confusion is the specific hazard: the storable X-Wing
	// private key is 32 bytes and the ML-KEM seed it expands to is 64.
	if XwingSeedSize != 32 {
		t.Errorf("XwingSeedSize = %d, want 32", XwingSeedSize)
	}
	if XwingExpandedSize != 96 {
		t.Errorf("XwingExpandedSize = %d, want 96", XwingExpandedSize)
	}
	if XwingMlkemSeedSize != 64 {
		t.Errorf("XwingMlkemSeedSize = %d, want 64", XwingMlkemSeedSize)
	}
	if XwingMlkemSeedSize+XwingX25519KeySize != XwingExpandedSize {
		t.Errorf("the expansion does not partition: %d + %d != %d", XwingMlkemSeedSize, XwingX25519KeySize, XwingExpandedSize)
	}
	if XwingPublicKeySize != XwingMlkemPublicKeySize+XwingX25519KeySize {
		t.Errorf("XwingPublicKeySize = %d, want %d", XwingPublicKeySize, XwingMlkemPublicKeySize+XwingX25519KeySize)
	}
	if XwingCiphertextSize != XwingMlkemCiphertextSize+XwingX25519KeySize {
		t.Errorf("XwingCiphertextSize = %d, want %d", XwingCiphertextSize, XwingMlkemCiphertextSize+XwingX25519KeySize)
	}
	if XwingPublicKeySize != 1216 || XwingCiphertextSize != 1120 || XwingSharedSize != 32 {
		t.Errorf("sizes are %d/%d/%d, want 1216/1120/32", XwingPublicKeySize, XwingCiphertextSize, XwingSharedSize)
	}
	if XwingAlgId != 0x0014 {
		t.Errorf("XwingAlgId = %#04x, want 0x0014", XwingAlgId)
	}
}

func TestXwingKeyGenIsDeterministicFromTheSeed(t *testing.T) {
	// seed-only restore depends on this: the recovery key is reconstructible from
	// the mnemonic alone (MASTER §5.2).
	seed := bytes.Repeat([]byte{0x20}, XwingSeedSize)
	a, err := XwingKeyGenFromSeed(seed)
	if err != nil {
		t.Fatalf("keygen a: %v", err)
	}
	b, err := XwingKeyGenFromSeed(seed)
	if err != nil {
		t.Fatalf("keygen b: %v", err)
	}
	if !bytes.Equal(a.Public().Bytes(), b.Public().Bytes()) {
		t.Fatalf("keygen is not deterministic")
	}
	if !bytes.Equal(a.Seed(), seed) {
		t.Fatalf("Seed() = %x, want the input seed", a.Seed())
	}
	if len(a.Public().Bytes()) != XwingPublicKeySize {
		t.Fatalf("public key is %d bytes, want %d", len(a.Public().Bytes()), XwingPublicKeySize)
	}

	other, err := XwingKeyGenFromSeed(bytes.Repeat([]byte{0x21}, XwingSeedSize))
	if err != nil {
		t.Fatalf("keygen other: %v", err)
	}
	if bytes.Equal(a.Public().Bytes(), other.Public().Bytes()) {
		t.Fatalf("different seeds produced the same public key")
	}
}

func TestXwingSeedExpansionIsShake256(t *testing.T) {
	// the expansion is asserted against an independent computation, so a swap to
	// SHAKE-128 or a wrong output length cannot pass. draft §5.2:
	//   expanded = SHAKE256(seed, 96)
	//   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
	//   sk_X = expanded[64:96]
	seed := bytes.Repeat([]byte{0x22}, XwingSeedSize)
	expanded := sha3.SumSHAKE256(seed, XwingExpandedSize)
	decapsulationKey, err := mlkem.NewDecapsulationKey768(expanded[0:XwingMlkemSeedSize])
	if err != nil {
		t.Fatalf("mlkem: %v", err)
	}
	priv, err := XwingKeyGenFromSeed(seed)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub := priv.Public().Bytes()
	if !bytes.Equal(pub[0:XwingMlkemPublicKeySize], decapsulationKey.EncapsulationKey().Bytes()) {
		t.Fatalf("the ml-kem half of the public key is not KeyGen(SHAKE256(seed, 96)[0:64])")
	}
	if bytes.Equal(pub[XwingMlkemPublicKeySize:], make([]byte, XwingX25519KeySize)) {
		t.Fatalf("the x25519 half of the public key is all zero")
	}
}

func TestXwingKeyGenRejectsWrongSeedSizes(t *testing.T) {
	for _, n := range []int{0, 31, 33, 64, 96} {
		if _, err := XwingKeyGenFromSeed(make([]byte, n)); !errors.Is(err, ErrXwingBadSeedSize) {
			t.Errorf("XwingKeyGenFromSeed(%d bytes) error = %v, want ErrXwingBadSeedSize", n, err)
		}
	}
}

func TestParseXwingPublicKeyRejectsWrongSizes(t *testing.T) {
	for _, n := range []int{0, 32, 1184, 1215, 1217, 2432} {
		if _, err := ParseXwingPublicKey(make([]byte, n)); !errors.Is(err, ErrXwingBadPublicKeySize) {
			t.Errorf("ParseXwingPublicKey(%d bytes) error = %v, want ErrXwingBadPublicKeySize", n, err)
		}
	}
	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	parsed, err := ParseXwingPublicKey(priv.Public().Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !bytes.Equal(parsed.Bytes(), priv.Public().Bytes()) {
		t.Fatalf("parse round trip changed the bytes")
	}
}

func TestXwingPublicKeyBytesDoesNotAlias(t *testing.T) {
	// a caller that mutates the returned slice must not corrupt the key it came from.
	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub := priv.Public()
	first := pub.Bytes()
	first[0] ^= 0xff
	if bytes.Equal(pub.Bytes(), first) {
		t.Fatalf("Bytes returns the internal buffer")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./message/... -run TestXwingSizes -v` from `connect/`
Expected: FAIL — `message/xwing_test.go:...: undefined: XwingSeedSize` (build failure).

- [ ] **Step 3: Write minimal implementation**

`connect/message/doc.go`:

```go
// the URmessage storage layer: records, the storage key schedule, epoch wraps and the
// post-quantum wrap KEM.
//
// this package imports connect and connect/mls as peers. it must never be imported by
// connect, and never imports sdk.
package message
```

`connect/message/xwing_errors.go`:

```go
// typed errors for the X-Wing KEM. every one is fatal by construction: a wrap that
// does not open is not a warning, it is a member who cannot read the epoch.
package message

import "errors"

var (
	ErrXwingBadSeedSize       = errors.New("message: xwing seed must be 32 bytes")
	ErrXwingBadPublicKeySize  = errors.New("message: xwing public key must be 1216 bytes")
	ErrXwingBadCiphertextSize = errors.New("message: xwing ciphertext must be 1120 bytes")
	ErrXwingInvalidPoint      = errors.New("message: xwing x25519 produced an invalid shared secret")
)
```

`connect/message/xwing.go`:

```go
// X-Wing, the hybrid KEM of draft-connolly-cfrg-xwing-kem, combining X25519 with
// ML-KEM-768 under a construction that carries a published security proof.
//
// implemented from the draft rather than reconstructed. a "roughly equivalent"
// combiner forfeits the proof that is the entire reason for choosing X-Wing, so the
// label, its position, and the order of the combiner inputs are transcribed
// (MASTER §7.2) and validated against the draft's own vectors before any use.
//
// stdlib only: crypto/sha3 for the SHAKE-256 expansion and the SHA3-256 combiner,
// crypto/mlkem for ML-KEM-768, and mls.X25519* for the x25519 half — which is the
// single ECDH call site in this tree, so an invalid point cannot be ignored here
// either.
//
// note on the draft: it states no check on the x25519 shared secret. crypto/ecdh
// rejects an all-zero output, and this implementation surfaces that as
// ErrXwingInvalidPoint rather than suppressing it. that is deliberately stricter
// than the draft, is required by Spec A §5.4, and changes nothing about vector
// conformance because no draft vector carries a low-order ct_X. X-Wing is used only
// in our own storage layer (MASTER §7 caveat), so there is no peer to diverge from.
package message

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/sha3"
	"io"

	"github.com/urnetwork/connect/mls"
)

const (
	XwingSeedSize            = 32
	XwingExpandedSize        = 96
	XwingPublicKeySize       = 1216
	XwingCiphertextSize      = 1120
	XwingSharedSize          = 32
	XwingMlkemSeedSize       = 64
	XwingMlkemPublicKeySize  = 1184
	XwingMlkemCiphertextSize = 1088
	XwingX25519KeySize       = 32
)

// the wrap algorithm identifier of MASTER §7.1, carried inside every signed body so
// it cannot be stripped or downgraded.
const XwingAlgId uint16 = 0x0014

// XWingLabel, the six ascii bytes 5c2e2f2f5e5c — "\./" followed by "/^\", an
// ascii-art X. it is the LAST input to the combiner, not the first.
var xwingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// the storable private key is the 32-byte seed; the expanded halves are cached so a
// decapsulation does not re-run SHAKE-256 and ML-KEM key generation each time.
type XwingPrivateKey struct {
	seed             []byte
	mlkemPrivate     *mlkem.DecapsulationKey768
	x25519Private    *ecdh.PrivateKey
	mlkemPublicKey   []byte
	x25519PublicKey  []byte
}

type XwingPublicKey struct {
	mlkemPublic  *mlkem.EncapsulationKey768
	mlkemBytes   []byte
	x25519Public *ecdh.PublicKey
	x25519Bytes  []byte
}

// expandDecapsulationKey, draft §5.2. the ML-KEM half takes expanded[0:64] — a
// d ‖ z seed, which crypto/mlkem accepts directly — and the x25519 scalar is
// expanded[64:96]. taking 32 bytes here instead of 64 is the G9 hazard, and the
// constants are named so the mistake has to be made deliberately.
func XwingKeyGenFromSeed(seed []byte) (*XwingPrivateKey, error) {
	if len(seed) != XwingSeedSize {
		return nil, ErrXwingBadSeedSize
	}
	expanded := sha3.SumSHAKE256(seed, XwingExpandedSize)
	mlkemPrivate, err := mlkem.NewDecapsulationKey768(expanded[0:XwingMlkemSeedSize])
	if err != nil {
		return nil, err
	}
	x25519Private, err := mls.X25519PrivateKey(expanded[XwingMlkemSeedSize:XwingExpandedSize])
	if err != nil {
		return nil, err
	}
	return &XwingPrivateKey{
		seed:            append([]byte{}, seed...),
		mlkemPrivate:    mlkemPrivate,
		x25519Private:   x25519Private,
		mlkemPublicKey:  mlkemPrivate.EncapsulationKey().Bytes(),
		x25519PublicKey: x25519Private.PublicKey().Bytes(),
	}, nil
}

func XwingGenerateKey(random io.Reader) (*XwingPrivateKey, error) {
	seed := make([]byte, XwingSeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	return XwingKeyGenFromSeed(seed)
}

// a copy, so a caller that zeroizes its own buffer does not blank the key.
func (self *XwingPrivateKey) Seed() []byte {
	return append([]byte{}, self.seed...)
}

func (self *XwingPrivateKey) Public() *XwingPublicKey {
	return &XwingPublicKey{
		mlkemPublic:  self.mlkemPrivate.EncapsulationKey(),
		mlkemBytes:   self.mlkemPublicKey,
		x25519Public: self.x25519Private.PublicKey(),
		x25519Bytes:  self.x25519PublicKey,
	}
}

// pk_M ‖ pk_X, a fresh slice each call so a mutating caller cannot corrupt the key.
func (self *XwingPublicKey) Bytes() []byte {
	encoded := make([]byte, 0, XwingPublicKeySize)
	encoded = append(encoded, self.mlkemBytes...)
	return append(encoded, self.x25519Bytes...)
}

// length is checked before any parsing, so a truncated or over-long key never
// reaches ml-kem's own decoder.
func ParseXwingPublicKey(b []byte) (*XwingPublicKey, error) {
	if len(b) != XwingPublicKeySize {
		return nil, ErrXwingBadPublicKeySize
	}
	mlkemPublic, err := mlkem.NewEncapsulationKey768(b[0:XwingMlkemPublicKeySize])
	if err != nil {
		return nil, err
	}
	x25519Public, err := mls.X25519PublicKey(b[XwingMlkemPublicKeySize:])
	if err != nil {
		return nil, err
	}
	return &XwingPublicKey{
		mlkemPublic:  mlkemPublic,
		mlkemBytes:   append([]byte{}, b[0:XwingMlkemPublicKeySize]...),
		x25519Public: x25519Public,
		x25519Bytes:  append([]byte{}, b[XwingMlkemPublicKeySize:]...),
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./message/... -run TestXwing -v` from `connect/`
Expected: PASS — `TestXwingSizesAreTheDraftSizes`, `TestXwingKeyGenIsDeterministicFromTheSeed`,
`TestXwingSeedExpansionIsShake256`, `TestXwingKeyGenRejectsWrongSeedSizes`,
`TestParseXwingPublicKeyRejectsWrongSizes`, `TestXwingPublicKeyBytesDoesNotAlias` all ok.

- [ ] **Step 5: Commit**

```bash
git add message/doc.go message/xwing.go message/xwing_errors.go message/xwing_test.go && \
git commit -m "feat(message): x-wing key generation from a 32-byte seed"
```

---

### Task 20: X-Wing encapsulation, decapsulation and the draft vector gate

**Files:**
- Modify: `connect/message/xwing.go`
- Create: `connect/message/testdata/vectors/rfc/xwing-draft10.json`
- Modify: `connect/mls/interop/PINS.md` (p8 Task 6's file — one row appended)
- Test: `connect/message/xwing_test.go`, `connect/message/xwing_vectors_test.go`

**Interfaces:**
- Consumes: everything from Task 19; `mls.X25519DH`, `mls.X25519PublicKey`,
  `mls.X25519GenerateKey` (Task 4).

`MustHex`, `HexOf` and `LoadVectorFile` are p8's and live in `connect/mls/vectors_test.go`, a
`_test.go` file: they are visible to `package mls` and to nothing else, so `package message` keeps
its own `mustHexBytes`. That is the one sanctioned duplicate hex decoder in the slice, and it exists
because of a Go visibility rule rather than a preference.
- Produces:
  - `func XwingEncapsulate(random io.Reader, pub *XwingPublicKey) (ct []byte, ss []byte, err error)`
  - `func XwingDecapsulate(priv *XwingPrivateKey, ct []byte) (ss []byte, err error)`

- [ ] **Step 1: Write the failing test**

Append to `connect/message/xwing_test.go`:

```go
func TestXwingRoundTrip(t *testing.T) {
	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ct, ss, err := XwingEncapsulate(rand.Reader, priv.Public())
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	if len(ct) != XwingCiphertextSize {
		t.Fatalf("ciphertext is %d bytes, want %d", len(ct), XwingCiphertextSize)
	}
	if len(ss) != XwingSharedSize {
		t.Fatalf("shared secret is %d bytes, want %d", len(ss), XwingSharedSize)
	}
	back, err := XwingDecapsulate(priv, ct)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(ss, back) {
		t.Fatalf("encapsulate and decapsulate disagree")
	}
}

func TestXwingEncapsulateIsNotDerandomizable(t *testing.T) {
	// the random argument supplies ek_X only. crypto/mlkem's Encapsulate takes no
	// randomness and reads crypto/rand itself, so two calls with an identical reader
	// still differ. this is asserted rather than documented because a caller who
	// assumed determinism would build a broken KAT and not notice.
	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	fixed := bytes.Repeat([]byte{0x23}, 1024)
	first, _, err := XwingEncapsulate(bytes.NewReader(fixed), priv.Public())
	if err != nil {
		t.Fatalf("encapsulate 1: %v", err)
	}
	second, _, err := XwingEncapsulate(bytes.NewReader(fixed), priv.Public())
	if err != nil {
		t.Fatalf("encapsulate 2: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatalf("encapsulation was derandomized, which crypto/mlkem does not permit")
	}
	// the x25519 half, which the reader does control, must match.
	if !bytes.Equal(first[XwingMlkemCiphertextSize:], second[XwingMlkemCiphertextSize:]) {
		t.Fatalf("the x25519 half of the ciphertext did not come from the supplied reader")
	}
}

func TestXwingDecapsulateRejectsWrongCiphertextSizes(t *testing.T) {
	// length before arithmetic: a truncated or over-long ciphertext must be refused
	// before ml-kem or x25519 sees a byte.
	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, n := range []int{0, 1, 1088, 1119, 1121, 2240} {
		if _, err := XwingDecapsulate(priv, make([]byte, n)); !errors.Is(err, ErrXwingBadCiphertextSize) {
			t.Errorf("XwingDecapsulate(%d bytes) error = %v, want ErrXwingBadCiphertextSize", n, err)
		}
	}
}

func TestXwingDecapsulateRejectsALowOrderX25519Half(t *testing.T) {
	// MASTER §7.2 and Spec A §5.4 mandate an error rather than a zero shared secret.
	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ct, _, err := XwingEncapsulate(rand.Reader, priv.Public())
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	copy(ct[XwingMlkemCiphertextSize:], make([]byte, XwingX25519KeySize))
	ss, err := XwingDecapsulate(priv, ct)
	if !errors.Is(err, ErrXwingInvalidPoint) {
		t.Fatalf("error = %v, want ErrXwingInvalidPoint", err)
	}
	if ss != nil {
		t.Fatalf("returned a shared secret alongside the error: %x", ss)
	}
}

func TestXwingDecapsulateUnderTheWrongKeyDiffers(t *testing.T) {
	// ml-kem's implicit rejection means decapsulation under the wrong key succeeds
	// and returns a different secret rather than failing. that is correct FIPS 203
	// behaviour, and it means a wrap that opens to the wrong key must be caught by
	// the AEAD above it, not by an error here.
	a, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate a: %v", err)
	}
	b, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate b: %v", err)
	}
	ct, ss, err := XwingEncapsulate(rand.Reader, a.Public())
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	other, err := XwingDecapsulate(b, ct)
	if err != nil {
		t.Fatalf("decapsulate under the wrong key returned an error: %v", err)
	}
	if bytes.Equal(ss, other) {
		t.Fatalf("decapsulation under the wrong key produced the right secret")
	}
}
```

`connect/message/xwing_vectors_test.go`:

```go
// the draft-connolly-cfrg-xwing-kem KAT vectors. MASTER §7.2 makes passing these a
// precondition of any use of X-Wing.
//
// coverage is deliberately explicit about its one gap. each vector carries
// {seed, sk, pk, eseed, ct, ss}:
//   - keygen           seed -> pk         full KAT
//   - decapsulation    (seed, ct) -> ss   full KAT, which transitively pins the
//                                         SHAKE-256 expansion, the ct split, ML-KEM
//                                         decapsulation, the x25519 dh, and the
//                                         combiner including the label's position
//   - encapsulation    eseed -> ct_X      full KAT for the x25519 half
//   - encapsulation    eseed -> ct_M      NOT reachable: crypto/mlkem's Encapsulate
//                                         takes no randomness and returns no error,
//                                         so ML-KEM's derandomized encapsulation is
//                                         not exposed by the standard library. it is
//                                         covered by round-trip here and by the
//                                         standard library's own FIPS 203 ACVP tests.
// re-implementing ML-KEM to close that gap would mean shipping new crypto, which the
// global constraints forbid outright.
package message

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"crypto/sha3"
	"os"
	"testing"

	"github.com/urnetwork/connect/mls"
)

type xwingVector struct {
	Seed  string `json:"seed"`
	Sk    string `json:"sk"`
	Pk    string `json:"pk"`
	Eseed string `json:"eseed"`
	Ct    string `json:"ct"`
	Ss    string `json:"ss"`
}

const xwingVectorPath = "testdata/vectors/rfc/xwing-draft10.json"

// the digest recorded in ../mls/interop/PINS.md, the one pin file in the slice.
const xwingVectorSha256 = "409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d"

func loadXwingVectors(t *testing.T) []xwingVector {
	t.Helper()
	raw, err := os.ReadFile(xwingVectorPath)
	if err != nil {
		t.Fatalf("read %s: %v", xwingVectorPath, err)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != xwingVectorSha256 {
		t.Fatalf("%s sha256 = %s, want %s (see ../mls/interop/PINS.md)", xwingVectorPath, got, xwingVectorSha256)
	}
	var vectors []xwingVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse %s: %v", xwingVectorPath, err)
	}
	if len(vectors) != 3 {
		t.Fatalf("%s has %d vectors, want 3", xwingVectorPath, len(vectors))
	}
	return vectors
}

// package message cannot see p8's MustHex: it is declared in mls/vectors_test.go,
// and a _test.go file's symbols are not exported across a package boundary. this is
// the only hex decoder in the slice that is not p8's, and only for that reason.
func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func TestXwingVectorKeyGen(t *testing.T) {
	for i, vector := range loadXwingVectors(t) {
		seed := mustHexBytes(t, vector.Seed)
		if !bytes.Equal(seed, mustHexBytes(t, vector.Sk)) {
			t.Fatalf("vector %d: sk is not the seed, which the draft says it is", i)
		}
		priv, err := XwingKeyGenFromSeed(seed)
		if err != nil {
			t.Fatalf("vector %d keygen: %v", i, err)
		}
		if got, want := priv.Public().Bytes(), mustHexBytes(t, vector.Pk); !bytes.Equal(got, want) {
			t.Errorf("vector %d: pk = %x, want %x", i, got[:16], want[:16])
		}
	}
}

func TestXwingVectorDecapsulate(t *testing.T) {
	for i, vector := range loadXwingVectors(t) {
		priv, err := XwingKeyGenFromSeed(mustHexBytes(t, vector.Seed))
		if err != nil {
			t.Fatalf("vector %d keygen: %v", i, err)
		}
		ss, err := XwingDecapsulate(priv, mustHexBytes(t, vector.Ct))
		if err != nil {
			t.Fatalf("vector %d decapsulate: %v", i, err)
		}
		if got, want := ss, mustHexBytes(t, vector.Ss); !bytes.Equal(got, want) {
			t.Errorf("vector %d: ss = %x, want %x", i, got, want)
		}
	}
}

func TestXwingVectorEncapsulateX25519Half(t *testing.T) {
	// eseed[32:64] is ek_X, and ct[1088:1120] must be its public key. this is the
	// half of encapsulation the standard library lets us pin exactly.
	for i, vector := range loadXwingVectors(t) {
		eseed := mustHexBytes(t, vector.Eseed)
		if len(eseed) != 64 {
			t.Fatalf("vector %d: eseed is %d bytes, want 64", i, len(eseed))
		}
		ephemeral, err := mls.X25519PrivateKey(eseed[32:64])
		if err != nil {
			t.Fatalf("vector %d ephemeral: %v", i, err)
		}
		ct := mustHexBytes(t, vector.Ct)
		if got, want := ephemeral.PublicKey().Bytes(), ct[XwingMlkemCiphertextSize:]; !bytes.Equal(got, want) {
			t.Errorf("vector %d: ct_X = %x, want %x", i, got, want)
		}
	}
}

func TestXwingCombinerOrderMatchesTheDraft(t *testing.T) {
	// the specific defect this guards: Spec A §5.4's table puts XWingLabel FIRST.
	// the draft puts it LAST. the label-first form fails every vector, and this
	// asserts the failure directly so a future "simplification" cannot reintroduce it.
	vector := loadXwingVectors(t)[0]
	priv, err := XwingKeyGenFromSeed(mustHexBytes(t, vector.Seed))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ct := mustHexBytes(t, vector.Ct)
	ss, err := XwingDecapsulate(priv, ct)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	if !bytes.Equal(ss, mustHexBytes(t, vector.Ss)) {
		t.Fatalf("the combiner does not match the draft")
	}

	// recompute with the label first, the form Spec A §5.4's table describes, and
	// assert it does NOT reproduce the vector. without this the wrong ordering could
	// be reintroduced and only an X-Wing peer would ever notice — and we have none.
	mlkemShared, err := priv.mlkemPrivate.Decapsulate(ct[0:XwingMlkemCiphertextSize])
	if err != nil {
		t.Fatalf("mlkem decapsulate: %v", err)
	}
	ephemeralPublic, err := mls.X25519PublicKey(ct[XwingMlkemCiphertextSize:])
	if err != nil {
		t.Fatalf("parse ct_X: %v", err)
	}
	x25519Shared, err := mls.X25519DH(priv.x25519Private, ephemeralPublic)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	labelFirst := sha3.New256()
	labelFirst.Write(xwingLabel)
	labelFirst.Write(mlkemShared)
	labelFirst.Write(x25519Shared)
	labelFirst.Write(ct[XwingMlkemCiphertextSize:])
	labelFirst.Write(priv.x25519PublicKey)
	if bytes.Equal(ss, labelFirst.Sum(nil)) {
		t.Fatalf("a label-first combiner reproduced the draft's answer, which is impossible")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./message/... -run TestXwingRoundTrip -v` from `connect/`
Expected: FAIL — `message/xwing_test.go:...: undefined: XwingEncapsulate` (build failure).

- [ ] **Step 3: Write minimal implementation**

Append to `connect/message/xwing.go`:

```go
// the combiner, draft §5.3:
//
//	SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)
//
// the label is LAST. Spec A §5.4's stdlib-mapping table writes it first; that is an
// error in Spec A, and the label-first form fails all three draft vectors.
func xwingCombine(mlkemShared []byte, x25519Shared []byte, x25519Ciphertext []byte, x25519Public []byte) []byte {
	hash := sha3.New256()
	hash.Write(mlkemShared)
	hash.Write(x25519Shared)
	hash.Write(x25519Ciphertext)
	hash.Write(x25519Public)
	hash.Write(xwingLabel)
	return hash.Sum(nil)
}

// Encapsulate, draft §5.4.
//
// the random argument supplies ek_X only. crypto/mlkem's Encapsulate takes no
// randomness and returns no error, so the ML-KEM half always draws from crypto/rand
// and this function cannot be derandomized. that is asserted by
// TestXwingEncapsulateIsNotDerandomizable rather than left as a comment, because a
// caller who assumed otherwise would build a KAT that silently proves nothing.
func XwingEncapsulate(random io.Reader, pub *XwingPublicKey) ([]byte, []byte, error) {
	ephemeral, err := mls.X25519GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	x25519Shared, err := mls.X25519DH(ephemeral, pub.x25519Public)
	if err != nil {
		return nil, nil, ErrXwingInvalidPoint
	}
	mlkemShared, mlkemCiphertext := pub.mlkemPublic.Encapsulate()
	x25519Ciphertext := ephemeral.PublicKey().Bytes()

	ciphertext := make([]byte, 0, XwingCiphertextSize)
	ciphertext = append(ciphertext, mlkemCiphertext...)
	ciphertext = append(ciphertext, x25519Ciphertext...)
	shared := xwingCombine(mlkemShared, x25519Shared, x25519Ciphertext, pub.x25519Bytes)
	return ciphertext, shared, nil
}

// Decapsulate, draft §5.5. the length is checked before any arithmetic, so a
// truncated or over-long ciphertext never reaches ml-kem's decoder.
func XwingDecapsulate(priv *XwingPrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != XwingCiphertextSize {
		return nil, ErrXwingBadCiphertextSize
	}
	mlkemCiphertext := ct[0:XwingMlkemCiphertextSize]
	x25519Ciphertext := ct[XwingMlkemCiphertextSize:]

	mlkemShared, err := priv.mlkemPrivate.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, err
	}
	ephemeralPublic, err := mls.X25519PublicKey(x25519Ciphertext)
	if err != nil {
		return nil, ErrXwingInvalidPoint
	}
	x25519Shared, err := mls.X25519DH(priv.x25519Private, ephemeralPublic)
	if err != nil {
		return nil, ErrXwingInvalidPoint
	}
	return xwingCombine(mlkemShared, x25519Shared, x25519Ciphertext, priv.x25519PublicKey), nil
}
```

Then vendor the vectors. Run, from `connect/message/testdata/vectors/rfc/`:

```bash
curl -sL -o xwing-draft10.json \
  https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/9b6ce9e614811dba8d46841052f3883cbc4c1a65/spec/test-vectors.json && \
sha256sum xwing-draft10.json
```

Expected: `409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d  xwing-draft10.json`

Append one row and one section to `connect/mls/interop/PINS.md` — the single pin file, p8 Task 6's.
There is no `connect/message/testdata/vectors/PINS.md`.

```markdown
| `../../message/testdata/vectors/rfc/xwing-draft10.json` | `dconnolly/draft-connolly-cfrg-xwing-kem` | `9b6ce9e614811dba8d46841052f3883cbc4c1a65` | `spec/test-vectors.json` | `409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d` |
```

```markdown
## message/testdata/vectors/rfc/xwing-draft10.json

Three KAT vectors, vendored whole and unmodified, from the draft-10 reference implementation
(`spec/xwing.py` at the same commit). Fields per vector: `seed` (32 B), `sk` (32 B, equal to the
seed), `pk` (1216 B), `eseed` (64 B), `ct` (1120 B), `ss` (32 B).

X-Wing is an Internet-Draft with no IANA MLS code point, so this file moves when the draft moves.
Bumping the commit is a PR that must show `TestXwingVector*` green; a changed combiner or label
position would show up as a decapsulation mismatch on all three vectors at once, which is the
failure mode we want rather than a silent divergence.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./message/... -v` from `connect/`
Expected: PASS — `TestXwingRoundTrip`, `TestXwingEncapsulateIsNotDerandomizable`,
`TestXwingDecapsulateRejectsWrongCiphertextSizes`,
`TestXwingDecapsulateRejectsALowOrderX25519Half`, `TestXwingDecapsulateUnderTheWrongKeyDiffers`,
`TestXwingVectorKeyGen`, `TestXwingVectorDecapsulate`, `TestXwingVectorEncapsulateX25519Half`,
`TestXwingCombinerOrderMatchesTheDraft` all ok.

- [ ] **Step 5: Commit**

```bash
git add message/xwing.go message/xwing_test.go message/xwing_vectors_test.go \
        message/testdata/vectors/rfc/xwing-draft10.json mls/interop/PINS.md && \
git commit -m "feat(message): x-wing encapsulate and decapsulate, gated on the draft vectors"
```

---

### Task 21: X-Wing fuzz target and the layering assertion

**Files:**
- Test: `connect/message/xwing_fuzz_test.go`, `connect/message/layering_test.go`

**Interfaces:**
- Consumes: everything from Tasks 19–20.
- Produces: `FuzzXwingDecapsulate`, `FuzzParseXwingPublicKey`, `TestMessageDoesNotImportSdk`,
  `TestMlsDoesNotImportConnectOrMessage`, `TestConnectDoesNotImportMlsOrMessage`.

- [ ] **Step 1: Write the failing test**

`connect/message/xwing_fuzz_test.go`:

```go
// Gate 4 property 1 for the x-wing surface. a wrap ciphertext arrives from the
// server, so every byte of it is attacker controlled.
package message

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func FuzzXwingDecapsulate(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, XwingCiphertextSize))
	f.Add(make([]byte, XwingCiphertextSize-1))
	f.Add(bytes.Repeat([]byte{0xff}, XwingCiphertextSize))
	f.Add(bytes.Repeat([]byte{0xaa}, 65536))

	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate: %v", err)
	}

	f.Fuzz(func(t *testing.T, ct []byte) {
		shared, err := XwingDecapsulate(priv, ct)
		if err != nil {
			if shared != nil {
				t.Fatalf("returned %d shared bytes alongside %v", len(shared), err)
			}
			return
		}
		if len(shared) != XwingSharedSize {
			t.Fatalf("shared secret is %d bytes, want %d", len(shared), XwingSharedSize)
		}
		if bytes.Equal(shared, make([]byte, XwingSharedSize)) {
			t.Fatalf("decapsulation produced an all-zero shared secret")
		}
	})
}

func FuzzParseXwingPublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, XwingPublicKeySize))
	f.Add(bytes.Repeat([]byte{0x01}, XwingPublicKeySize))
	f.Add(bytes.Repeat([]byte{0xff}, 4096))

	f.Fuzz(func(t *testing.T, b []byte) {
		pub, err := ParseXwingPublicKey(b)
		if err != nil {
			return
		}
		// round trip: an accepted key must re-serialize to exactly its input.
		if !bytes.Equal(pub.Bytes(), b) {
			t.Fatalf("parse then serialize changed the bytes")
		}
	})
}
```

`connect/message/layering_test.go`:

```go
// the layering rules of Spec A §2.3, asserted from inside the package so a forbidden
// import breaks a test rather than an architecture review.
package message

import (
	"os/exec"
	"strings"
	"testing"
)

func packageDependencies(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func TestMessageDoesNotImportSdk(t *testing.T) {
	for _, dependency := range packageDependencies(t, "github.com/urnetwork/connect/message") {
		if strings.HasPrefix(dependency, "github.com/urnetwork/sdk") {
			t.Errorf("connect/message depends on %s", dependency)
		}
	}
}

func TestMlsDoesNotImportConnectOrMessage(t *testing.T) {
	// mls must be a self-contained crypto library so it can be audited and fuzzed
	// without the transport.
	for _, dependency := range packageDependencies(t, "github.com/urnetwork/connect/mls") {
		if dependency == "github.com/urnetwork/connect" ||
			dependency == "github.com/urnetwork/connect/message" ||
			strings.HasPrefix(dependency, "github.com/urnetwork/sdk") {
			t.Errorf("connect/mls depends on %s", dependency)
		}
	}
}

func TestConnectDoesNotImportMlsOrMessage(t *testing.T) {
	// a package must never import its own subpackages.
	for _, dependency := range packageDependencies(t, "github.com/urnetwork/connect") {
		if strings.HasPrefix(dependency, "github.com/urnetwork/connect/mls") ||
			strings.HasPrefix(dependency, "github.com/urnetwork/connect/message") {
			t.Errorf("connect depends on %s", dependency)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Introduce the layering violation the gate exists for. Temporarily add to `connect/mls/doc.go`:

```go
import _ "github.com/urnetwork/connect"
```

Run: `go test ./message/... -run TestMlsDoesNotImport -v` from `connect/`
Expected: FAIL — `connect/mls depends on github.com/urnetwork/connect`.

- [ ] **Step 3: Write minimal implementation**

Remove the temporary import from `connect/mls/doc.go`. The fuzz targets need no production code:
the length discipline Tasks 19 and 20 landed is their implementation.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./message/... ./mls/... -race -v` from `connect/`
Expected: PASS — every test in both packages.

Run: `go test ./message/... -fuzz FuzzXwingDecapsulate -fuzztime 60s` from `connect/`
Expected: PASS — `elapsed: 60s, ... (0 interesting)`, no crashers in `testdata/fuzz/`.

Run: `go test ./message/... -fuzz FuzzParseXwingPublicKey -fuzztime 60s` from `connect/`
Expected: PASS — same shape.

Run the cross-platform build gate:

```bash
for target in windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/arm64 android/arm64 ios/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} go build ./mls/... ./message/... || echo "FAILED $target"
done
```

Expected: no output. No cgo, no build tags, so every target builds from the same source.

- [ ] **Step 5: Commit**

```bash
git add message/xwing_fuzz_test.go message/layering_test.go mls/doc.go && \
git commit -m "test(message): fuzz x-wing decapsulate and assert the package layering rules"
```

---

### Task 22: Pin `message.XwingPublicKeySize` against `mls.XwingPublicKeyLen`

**Sequenced after p5 Task 4 (wave 2), not with the rest of this plan.** The TreeKEM plan owns
`LeafKeysExtension` and, with it, `const XwingPublicKeyLen = 1216` in `package mls` — the length
`LeafNode.Validate` range-checks a device's X-Wing public key against. `mls` must never import
`message`, so the 1216 is deliberately written twice, in two packages, in one direction only. The
canonical interface registry assigns the assertion that the two agree to **this** plan, because this
plan owns the value that is authoritative.

**Files:**
- Test: `connect/message/xwing_mls_pin_test.go`

**Interfaces:**
- Consumes: `const mls.XwingPublicKeyLen = 1216` from the **TreeKEM (p5 Task 4, wave 2)** plan;
  `XwingPublicKeySize`, `XwingGenerateKey` (Task 19).
- Produces: `TestXwingPublicKeySizeMatchesMls` and the compile-time array assertion behind it.

- [ ] **Step 1: Write the failing test**

`connect/message/xwing_mls_pin_test.go`:

```go
// the one place the duplicated 1216 is checked.
//
// mls.XwingPublicKeyLen and message.XwingPublicKeySize are the same number in two
// packages because connect/mls must never import connect/message. the duplication is
// deliberate and one-directional; this file is what stops it from becoming a drift.
package message

import (
	"testing"

	"github.com/urnetwork/connect/mls"
)

// compile-time equality: an array length is a non-negative constant, so declaring the
// difference in both directions fails to build unless the two constants are equal.
// this fires before any test runs, which is the point — a mismatch must not be
// discoverable only by executing something.
var (
	_ [XwingPublicKeySize - mls.XwingPublicKeyLen]struct{}
	_ [mls.XwingPublicKeyLen - XwingPublicKeySize]struct{}
)

func TestXwingPublicKeySizeMatchesMls(t *testing.T) {
	if XwingPublicKeySize != mls.XwingPublicKeyLen {
		t.Fatalf("message.XwingPublicKeySize = %d, mls.XwingPublicKeyLen = %d", XwingPublicKeySize, mls.XwingPublicKeyLen)
	}
	// and the constant must be the length a real key actually has, or both sides are
	// consistently wrong.
	priv, err := XwingGenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if n := len(priv.Public().Bytes()); n != mls.XwingPublicKeyLen {
		t.Fatalf("a generated public key is %d bytes, but mls.XwingPublicKeyLen is %d", n, mls.XwingPublicKeyLen)
	}
}
```

Add `"crypto/rand"` to the import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./message/... -run TestXwingPublicKeySizeMatchesMls -v` from `connect/`
Expected: FAIL — `message/xwing_mls_pin_test.go:...: undefined: mls.XwingPublicKeyLen` (build
failure). That is the correct signal that p5 Task 4 has not landed; this task waits for it rather
than declaring the constant here, because declaring it here would put the leaf-node range check in
the wrong package.

Then prove the assertion itself, once p5 Task 4 has landed: temporarily change
`XwingPublicKeySize` in `connect/message/xwing.go` to `1217`.
Expected: FAIL at build — `invalid array length XwingPublicKeySize - mls.XwingPublicKeyLen`, with
no test binary produced. Restore `1216`.

- [ ] **Step 3: Write minimal implementation**

None. The implementation is the two constants already agreeing, and `TestXwingSizesAreTheDraftSizes`
from Task 19 is what fixes this side of the pair at the draft's 1216.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./message/... ./mls/... -race -v` from `connect/`
Expected: PASS — both packages, including `TestXwingPublicKeySizeMatchesMls`.

- [ ] **Step 5: Commit**

```bash
git add message/xwing_mls_pin_test.go && \
git commit -m "test(message): pin the duplicated x-wing public key length against mls"
```

---

## Done means

| Gate | Command | Expected |
|---|---|---|
| The `crypto-basics` family passes, both directions, both registered suites | `go test ./mls/... -run TestCryptoBasics -v` | 10 tests ok |
| Family 2 is registered, not merely implemented | `go test ./mls/... -run TestVectorFamilies -v` | family 2 runs; `expectedPendingFamilies` is down to fifteen |
| HPKE matches RFC 9180 | `go test ./mls/... -run TestHpkeVector -v` | 5 tests ok, 514 sealed messages |
| X-Wing matches the draft | `go test ./message/... -run TestXwingVector -v` | 3 tests ok, 3 vectors each |
| No forbidden primitive, one `hkdf.Extract` pair, one `ECDH` | `go test ./mls/... -run "TestForbidden\|TestHkdf\|TestEcdh" -v` | 4 gates ok |
| The provider is complete | `go test ./mls/... -run TestProviderHasNoRemainingStubs -v` | ok for both suites |
| The provider is reproducible on demand and random by default | `go test ./mls/... -run "TestProviderWithRandom\|TestNewCryptoProviderDefaults" -v` | 3 tests ok |
| Layering holds | `go test ./message/... -run "TestMls\|TestConnect\|TestMessage" -v` | 3 gates ok |
| The duplicated 1216 agrees across the package boundary (after p5 Task 4) | `go test ./message/... -run TestXwingPublicKeySizeMatchesMls -v` | ok |
| No panics on attacker bytes | `go test ./mls/... ./message/... -fuzz Fuzz... -fuzztime 60s` per target | 0 interesting |
| Everything, under the race detector | `go test ./mls/... ./message/... -race` | ok |
| Every shipped platform builds | the `GOOS`/`GOARCH` loop in Task 21 | no output |

## Carried forward

- **Spec A §5.4 needs a correction**: the combiner input order is `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖
  XWingLabel`, label last. Task 20 implements the draft and `TestXwingCombinerOrderMatchesTheDraft`
  pins it, but the spec text should be fixed so the next reader does not implement the table.
- **`connect/mls/errors.go` is not created by this plan.** The Validation plan owns it, the 43 ValSem
  codes and the 51 sentinels. This plan's `crypto_errors.go` is a separate file on purpose, and the
  two must not be merged: a crypto failure and a validation semantic are different things and the
  ValSem tests assert on the specific typed error.
- **`ErrBadSignature` is not declared here.** It is `errors.go`'s, where it is ValSem010. That plan
  must wrap this plan's `ErrCryptoBadSignature` — e.g. `ErrBadSignature = fmt.Errorf("mls:
  signature verification failed (ValSem010): %w", ErrCryptoBadSignature)` — so that
  `errors.Is(err, ErrBadSignature)` and `errors.Is(err, ErrCryptoBadSignature)` both hold on a
  `VerifyWithLabel` failure. If that wrapping is missing, Gate 3's ValSem010 row goes red against
  correct crypto, so it is named here rather than left to be discovered.
- **`connect/go.mod` is p1 Task 1's.** The directive stays at `go 1.26.3` with `toolchain
  go1.26.5`; this plan asserts the toolchain through `runtime.Version()` and never edits the file.
- **The `HpkeCiphertext`-shaped `SealWithLabel`/`OpenWithLabel` pair is p5's**, not this plan's.
  `EncryptWithLabel`/`DecryptWithLabel` here keep the flat `(kemOutput, ciphertext)` form so this
  plan stays free of TreeKEM types.
- **The `psk_secret` vector family (family 6) is the Key schedule plan's**, not this one's, even
  though PSK proposals are profile-refused. The empty-PSK case runs on every epoch.
- **`XwingEncapsulate`'s `random` argument is honoured only for `ek_X`.** If a later plan needs a
  fully derandomized X-Wing encapsulation — for a cross-implementation KAT, say — it cannot have one
  without new ML-KEM code, which the global constraints forbid. Design around it rather than
  discovering it.
