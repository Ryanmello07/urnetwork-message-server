# Slice 1 — canonical interface registry

**Status:** normative. Where this file and a plan disagree, this file wins and the plan is amended.
**Scope:** every symbol that crosses a plan boundary in `connect/mls`, `connect/mls/syntax` and the
X-Wing corner of `connect/message`. Symbols private to one plan are out of scope.

Date: 2026-08-12. Built from p1–p8 plus `2026-08-12-slice1-compose-findings.json` (65 findings).

---

## 0. How to read this

Each entry is the exact Go signature, in a code block owned by exactly one plan. The trailing
comment on each line names the consuming plans:

```go
func Example(a int) error      // → p4,p6,p7
```

`→` lists consumers only; the owning plan is the block header. A line with no `→` is produced but
consumed only inside its owning plan, and is listed because a sibling plan currently names it and
must stop.

Four conventions decide most of the drift. They are stated once, here, and every plan's Global
Constraints gains them verbatim.

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

---

## 1. Ownership map

| Package / file | Owner | What lives here |
|---|---|---|
| `mls/syntax/*` | **p1** | Reader, Writer, varint, opaque, optional, vector, Marshal entry points, `CheckRoundTrip` |
| `mls/suite.go` `crypto*.go` `hpke.go` | **p2** | CipherSuite, SuiteParams, CryptoProvider, HPKE, labelled crypto, crypto errors |
| `message/xwing*.go` | **p2** | X-Wing (package `message`, not `mls`) |
| `mls/tree_math.go` | **p3** | LeafIndex/NodeIndex/LeafCount, path arithmetic, Resolution, FilteredDirectPath |
| `mls/group_context.go` `key_schedule.go` `psk.go` `transcript.go` `secret_tree.go` | **p4** | GroupContext, KeySchedule, EpochSecrets, PSK, transcript hashes, SecretTree |
| `mls/extension.go` `credential.go` `leaf_node.go` `key_package.go` `tree.go` `tree_hash.go` `tree_sync.go` `treekem.go` | **p5** | registry enums, Extension, Credential, Capabilities, LeafNode, **KeyPackage**, RatchetTree, UpdatePath, HpkeCiphertext |
| `mls/framing*.go` `proposal_wire.go` `commit_wire.go` `welcome_wire.go` | **p6** | all framing types, Proposal/ProposalOrRef/Commit structs+codecs, GroupInfo/GroupSecrets/Welcome **codecs**, MLSMessage |
| `mls/leaf_keys.go` `group_policy.go` `owner_successor.go` `proposal_list.go` `validate_*.go` `apply_proposals.go` `commit.go` `welcome.go` `succession.go` `group.go` | **p7** | URmessage extensions, proposal cache, ValSem101–113 / 200–209 / 300 checks, Group and the whole lifecycle |
| `mls/errors.go` `profile.go` `codec_table.go` `vectors_test.go` `interop/` | **p8** | ValSemCode, ValidationError, the 51 sentinels, **Profile**, codec table, vector registry, fuzz targets, Gate 2/3/4 |

Three ownership decisions differ from what the plans say and are the highest-value entries in this
file: **`KeyPackage` → p5** (§6.5), **`Profile` → p8** (§9.3), **the Welcome/GroupInfo codecs → p6**
(§7.5). Each is argued at its section.

---

## 2. `package syntax` — p1

p1 wins its own package against five incompatible consumer spellings, with exactly one override.

### 2.1 Errors and limits

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

Renames that die here: `ErrNonMinimalLength` (p6) → `ErrVarintNotMinimal`; `ErrVectorTooLong`
(p7,p8) → `ErrLengthExceedsMax`. `MaxVectorLength` is `int`, not `uint64` (p7) and not untyped
(p8), so it passes to `UnmarshalLimit` without a conversion.

### 2.2 Writer

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
func (self *Writer) WriteVarint(v uint32)                                     // → p8
func (self *Writer) WriteOpaque(bs []byte)       // opaque x<V>; nil == empty  → p2,p4,p5,p6,p7
func (self *Writer) WriteOpaqueLP(bs []byte)     // 32-bit prefix; connect/message only
func (self *Writer) WriteOptional(present bool, encodeOne func(w *Writer) error) error  // → p5,p6
func (self *Writer) WriteNested(encodeOne func(w *Writer) error) error   // → p5,p6,p7; see below
func (self *Writer) WriteNestedLP(encodeOne func(w *Writer) error) error // connect/message records
```

Every write after the first error is a no-op; one check at `Bytes()` suffices. `WriteBytes` (p4) is
`WriteRaw`. `WriteOpaqueVec` (p5 task bodies) is `WriteOpaque`. `Bytes() []byte` (p6) does not
exist — take the error.

**⚠ p5-p8: encode a nested structure with `WriteNested`, never by hand-rolling a scratch writer.**
Added in p1 Task 17b; the `Writer` previously had no counterpart to the `Reader`'s `ReadSub`, so
nesting meant writing this out at every call site:

```go
scratch := NewWriterLimit(w.MaxVectorLength())   // ← the load-bearing line
... encode into scratch ...
nested, err := scratch.Bytes()
w.WriteOpaque(nested)
```

**`NewWriter()` in place of that first line silently caps a nested field at `MaxVectorLength` even
inside a ratchet-tree encode running at `MaxRatchetTreeLength`** — invisible on small inputs,
appearing only on a large tree, which is the case hardest to test and likeliest to reach production.
Measured in Task 17b: an outer writer at `MaxRatchetTreeLength` encoding a nested body of
`MaxVectorLength+1` succeeds when the limit is inherited and gives `ErrLengthExceedsMax` when it is
not. Note the asymmetry — **only a *raised* outer limit can separate the two**, for every input, not
merely the ones tried, because the assembled region is never shorter than a field inside it, so the
outer `WriteOpaque` check always fires first and masks the difference.

The other hand-rolling hazard: **dropping the scratch `Bytes()` error frames `nil` as a zero-length
region** — one prefix octet, or four LP zeros — a well-formed, canonical-looking encoding of a
structure that was never encoded. `WriteNested` surfaces that error instead.

### 2.3 Reader

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
func (self *Reader) ReadVarint() (uint32, error)                              // → p8
func (self *Reader) ReadOpaque() ([]byte, error)       // a COPY, never nil    → p2,p4,p5,p6,p7
func (self *Reader) ReadOpaqueLP() ([]byte, error)     // connect/message only
func (self *Reader) ReadSub() (*Reader, error)         // RAW escape hatch — see the warning below
func (self *Reader) ReadSubLP() (*Reader, error)       // RAW escape hatch — see the warning below
func (self *Reader) ReadNested(decodeOne func(r *Reader) error) error   // PREFER THIS → p5,p6,p7
func (self *Reader) ReadNestedLP(decodeOne func(r *Reader) error) error // PREFER THIS
func (self *Reader) ReadOptional(decodeOne func(r *Reader) error) (present bool, err error) // → p5,p6
```

**⚠ p5-p7: call `ReadNested`/`ReadNestedLP`, not `ReadSub` plus a remembered `Done`.** Added in p1
Task 13; this block previously listed only the raw forms, and that was a trap. `ReadSub` hands back a
bounded sub-reader while **the parent advances past the whole region regardless of how much of it the
sub consumes**, so any bytes a nested decoder leaves behind are *silently accepted* unless the caller
remembers `sub.Done()` — and nothing obliges them to. That is a second valid encoding of one object,
invisible to round-trip tests, in a codec whose serialized forms MLS signs over: the same class the
minimal-varint rule exists to prevent. `ReadNested` calls `sub.Done()` itself and latches either
failure on the **parent**, so a dropped return cannot leave a clean parent sitting at the next field.

`ReadSub`/`ReadSubLP` remain for a caller that genuinely needs the raw view — chiefly a heterogeneous
element sequence — and deliberately do **not** latch the parent. If you reach for them, you own the
`Done` call, and say why in the code.

`Finish()` (p6) is `Done()`. `Rest()` (p6) does not exist and is not added — a decoder that wants
the tail writes `r.ReadRaw(r.Remaining())`, which is explicit about consuming it.

### 2.4 Vectors, the codec interfaces and the round-trip property

```go
func WriteVector[T any](w *Writer, items []T, encodeOne func(w *Writer, item T) error) error  // → p5,p6,p7
func ReadVector[T any](r *Reader, decodeOne func(r *Reader) (T, error)) ([]T, error)          // → p5,p6,p7

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

func CheckRoundTrip[T any, PT interface {
	*T
	Codec
}](bs []byte) error                                                            // → p8

func CheckRoundTripLimit[T any, PT interface {
	*T
	Codec
}](bs []byte, maxVectorLength int) error        // → p8; REQUIRED for any tree-bearing type
```

**⚠ p8: `CheckRoundTrip` is `CheckRoundTripLimit` at `MaxVectorLength`, and picking the bound too
low fails SILENTLY.** A target that calls the default form on a tree-bearing type — a ratchet tree,
or any `GroupInfo`/`Welcome` that may carry one — gets `nil` on every input, because input the bound
rejects carries no round-trip obligation and is indistinguishable from input that passed. The target
reports green having never once evaluated the property. Tree-bearing targets **must** call
`CheckRoundTripLimit(bs, MaxRatchetTreeLength)`.

**⚠ p8: the seed corpus is load-bearing, not an optimisation, and every target must fail at zero
reachability.** Measured in p1 Task 14 against the *simplest possible* type (two octets and one
opaque field): valid encodings reach the property 6/6, truncated encodings **0/450**, and uniform
random bytes **14/4096 — 0.34%**. Full consumption leaves no slack, so a random input must get the
varint prefix and an exact length right simultaneously. Real targets add a version, a cipher suite,
nested vectors and an enumerated arm, each multiplying in another factor, so 0.34% is a generous
upper bound and for `FuzzKeyPackageDecode` the realistic figure is indistinguishable from zero.
Therefore every fuzz target: seeds `f.Add` with valid encodings **of its own type** covering the
structural neighbourhood (empty, all-optionals-present, vectors at 0/63/64 for the varint octet
boundary, one nested), **counts how many inputs `CheckRoundTrip` actually decoded, and fails the
seed run at zero.** A target that has never reached its own property must not be able to report
success — which is also the only defence against the silent-limit failure above.

**`Marshal` never returns bytes alongside an error.** Whenever either half of
`errors.Join(v.MarshalMLS(w), w.Err())` fires, the byte slice is dropped and the return is
`nil, err` — a partial encoding is never handed back. Downstream may rely on that; it was left
implicit here until p1 Task 13 and is stated now so no caller invents a "bytes may still be usable"
path. `Unmarshal` is symmetric: it returns `errors.Join(v.UnmarshalMLS(r), r.Done())`, so a decoder
that refuses semantically **and** leaves a tail surfaces both, rather than the tail vanishing behind
an early return.

The length prefix on a vector counts **bytes, not elements**; `ReadVector` runs `decodeOne` against
a sub-reader until that sub-reader is empty. `WriteVector`/`ReadVector` stay free generics over a
typed slice — p6's method form (`(*Writer).WriteVector(n int, each func(w, i) error)`) is an
untyped index loop and loses the element type that makes `ReadVector` safe. Where the element type
is heterogeneous, use `ReadSub()` directly.

### 2.5 Overrides against p1

**O-1 (the important one) — `MarshalMLS` returns an `error`.** p1 specified
`MarshalMLS(w *Writer)` with no return, routing every failure into the Writer's sticky error. p5,
p6 and p7 independently wrote an error return (p6 on ~200 signatures, p5 as `MarshalTo(w) error`,
p7 as `MarshalTLS() ([]byte, error)`). Three consumers reaching for the same shape is the signal
this file is meant to act on, and there is a concrete reason behind it: MLS encoders have
**semantic** refusals that are not buffer errors — `Credential.MarshalMLS` must return
`ErrProfileCredentialType` on an x509 credential, `FramedContent.MarshalMLS` must return
`ErrContentArmMismatch` when the arm and the discriminant disagree. p1 exported no way to inject
those into the sticky error, so under the original signature they would have to panic or be
silently dropped, and a dropped encoder refusal produces wrong signed bytes rather than a failure.

Consequence: `Marshal` returns `errors.Join(v.MarshalMLS(w) error, w.Err())`, so both the semantic
and the buffer error surface. Higher-order encode callbacks (`WriteVector`, `WriteOptional`) return
`error` for the same reason. The sticky Writer stays — it is what keeps the leaf writes
(`WriteUint16`, `WriteOpaque`, …) return-free, and that is 90% of the call sites.

**O-2 — no append-style free functions.** p2 consumes
`syntax.WriteVarVec(dst, v) []byte`, `syntax.WriteUint16(dst, v) []byte`; p8 consumes
`syntax.ReadVarint(b) (uint64, int, error)` / `syntax.WriteVarint(dst, v) []byte`. These are a
second, independent implementation of the §2.1.2 length prefix, in a slice whose whole thesis is
that one codec with one fuzz corpus is what makes Gate 4 property 2 meaningful. Rejected: p2's four
label encoders (`mlsKdfLabel`, `RefHash`, `mlsSignContent`, `mlsEncryptContext` — the bytes MLS
signs over) are rewritten as
`w := syntax.NewWriter(); w.WriteOpaque(...); bs, err := w.Bytes()`. p8's varint is
`syntax.NewReader(b).ReadVarint()`, and note it is `uint32`-valued, not `uint64`.

**O-3 — `go.mod`.** p1's form: leave the `go` directive at `1.26.3`, add `toolchain go1.26.5`.
Raising the directive raises the language floor for all of `connect`, which is out of this slice's
scope. p2 Task 1's step becomes conditional with a `git diff --exit-code go.mod` guard.

---

## 3. `package mls` — crypto and HPKE — p2

### 3.1 Ciphersuites

```go
type CipherSuite uint16                                                       // → p3,p4,p5,p6,p7,p8

const (
    CipherSuiteX25519AesGcm128Sha256Ed25519 CipherSuite = 0x0001              // → p4,p8
    CipherSuiteX25519ChaCha20Sha256Ed25519  CipherSuite = 0x0003              // → p4,p5,p6,p7,p8
)

const (
    HpkeKemX25519HkdfSha256  uint16 = 0x0020
    HpkeKdfHkdfSha256        uint16 = 0x0001
    HpkeAeadAes128Gcm        uint16 = 0x0001
    HpkeAeadChaCha20Poly1305 uint16 = 0x0003
    SignatureSchemeEd25519   uint16 = 0x0807
)

type SuiteParams struct {
    Suite       CipherSuite
    Name        string
    KemId       uint16
    KdfId       uint16
    AeadId      uint16
    SignatureId uint16
    Nh          int   // KDF output size
    Nk          int   // AEAD key size
    Nn          int   // AEAD nonce size
    Nt          int   // AEAD tag size
    Nsecret     int
    Nenc        int
    Npk         int
    Nsk         int
    NsigPub     int
    NsigPriv    int
}                                                                             // → p4,p5,p7

func Suites() []CipherSuite                                                   // → p7,p8
func LookupSuite(suite CipherSuite) (*SuiteParams, error)                     // → p4,p5,p7
func IsRegisteredSuite(suite CipherSuite) bool                                // → p8
```

**Producer wins on the spelling.** Five plans wrote `CipherSuiteX25519ChaCha20SHA256Ed25519` (108
combined uses) and three mutually exclusive spellings of the 0x0001 constant. A headcount of plans
written in parallel with no coordination is not evidence about which name is better; the project's
own `CODESTYLE.md` rule — no all-caps initialisms, `Id` not `ID` — is, and it is the same rule that
settles `PreSharedKeyId` in §5.3. p2's spelling stands and p4/p5/p6/p7/p8 do a literal
find-and-replace. p8's `RegisteredSuites()` is dropped: `Suites()` plus `IsRegisteredSuite()` is
the sharper pair and p8 wanted the predicate anyway.

### 3.2 Key types, provider, labelled crypto

```go
type HpkePublicKey []byte                                                     // → p4,p5,p6,p7,p8
type HpkePrivateKey []byte                                                    // → p4,p5,p6,p7,p8
type SignaturePublicKey []byte                                                // → p5,p6,p7,p8
type SignaturePrivateKey []byte    // Ed25519 32-byte seed                    → p5,p6,p7,p8

type CryptoProvider interface {                     // exactly Spec A §3.3    → p3,p4,p5,p6,p7,p8
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

func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)             // → p4,p5,p6,p7,p8
func NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error) // → p8  [GAP → p2]

func RefHash(crypto CryptoProvider, label string, value []byte) []byte        // → p5
func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte       // → p5,p7
func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte // → p6,p7
func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)  // → p5,p7
func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, kemOutput []byte, ciphertext []byte) ([]byte, error)              // → p5,p7
```

**`HpkePublicKey` has no `Bytes()` method.** p4 pinned `HpkePublicKey.Bytes` as a compile assertion;
it is a `[]byte`, so `external_pub` is compared against the slice directly. Delete the pin.

**`EncryptWithLabel`/`DecryptWithLabel` keep their flat byte-slice form.** p7 consumes a
`*HPKECiphertext`-shaped pair. p2 must stay free of TreeKEM types, so the struct-shaped convenience
lives next to the type it returns, in p5 (§6.7).

### 3.3 X25519, raw HPKE, crypto errors

```go
func X25519PrivateKey(b []byte) (*ecdh.PrivateKey, error)
func X25519PublicKey(b []byte) (*ecdh.PublicKey, error)
func X25519GenerateKey(random io.Reader) (*ecdh.PrivateKey, error)
func X25519DH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error)     // → connect/message

type HpkeContext struct{ ... }                     // not safe for concurrent use
func HpkeDeriveKeyPair(params *SuiteParams, ikm []byte) (HpkePrivateKey, HpkePublicKey, error)
func HpkeSetupBaseS(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte) (kemOutput []byte, ctx *HpkeContext, err error)
func HpkeSetupBaseR(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte) (*HpkeContext, error)
func (self *HpkeContext) Seal(aad []byte, plaintext []byte) ([]byte, error)
func (self *HpkeContext) Open(aad []byte, ciphertext []byte) ([]byte, error)
func (self *HpkeContext) Export(exporterContext []byte, length int) ([]byte, error)
func HpkeSealBase(random io.Reader, params *SuiteParams, pub HpkePublicKey, info []byte, aad []byte, plaintext []byte) (kemOutput []byte, ciphertext []byte, err error)
func HpkeOpenBase(params *SuiteParams, priv HpkePrivateKey, kemOutput []byte, info []byte, aad []byte, ciphertext []byte) ([]byte, error)

var (
    ErrUnknownCipherSuite  = errors.New("mls: unknown ciphersuite")           // → p8
    ErrInvalidPoint        = errors.New("mls: x25519 produced an invalid shared secret") // → p8
    ErrBadKeyLength        = errors.New("mls: key length does not match the ciphersuite")
    ErrBadNonceLength      = errors.New("mls: nonce length does not match the ciphersuite")
    ErrBadKemOutput        = errors.New("mls: kem output length does not match the ciphersuite")
    ErrBadSignatureKey     = errors.New("mls: signature key length does not match the ciphersuite")
    ErrCryptoBadSignature  = errors.New("mls: signature verification failed") // renamed, see below
    ErrAeadOpen            = errors.New("mls: aead open failed")              // → p6,p8
    ErrSequenceOverflow    = errors.New("mls: hpke context sequence number overflow")
)
```

**`ErrBadSignature` → `ErrCryptoBadSignature`.** The name `ErrBadSignature` is declared three times
in `package mls` (p2 `crypto_errors.go`, p6 `errors_framing.go`, p8 `errors.go`). p8 keeps it — it
is ValSem010, the code Gate 3 asserts. p2's crypto-layer error is renamed, and p8's `ErrBadSignature`
wraps it so `errors.Is` holds through both.

---

## 4. `package mls` — tree math — p3

p3's block is normative in full. It is the only wave-1 plan whose surface three other plans pinned
and all three pinned wrong.

```go
type LeafIndex uint32                                                         // → p4,p5,p6,p7,p8
type NodeIndex uint32                                                         // → p4,p5,p7,p8
type LeafCount uint32                                                         // → p4,p5,p7

const MaxLeafCount LeafCount = 1 << 31

var ErrLeafCountRange, ErrLeafCountNotFull, ErrNodeOutOfRange, ErrLeafOutOfRange,
    ErrNodeIsParent, ErrLeafHasNoChildren, ErrRootHasNoParent, ErrRootHasNoSibling,
    ErrNodeWidthNotOdd error                                                  // → p5

func (self LeafIndex) NodeIndex() NodeIndex                                   // → p4,p5,p7
func (self NodeIndex) IsLeaf() bool                                           // → p5
func (self NodeIndex) LeafIndex() (LeafIndex, error)                          // → p5
func (self NodeIndex) Level() uint32                                          // → p4,p5

func NodeWidth(n LeafCount) uint32                                            // → p4,p5
func LeafCountFromNodeWidth(w uint32) (LeafCount, error)                      // → p5
func IsFullLeafCount(n LeafCount) bool                                        // → p5
func TreeDepth(n LeafCount) uint32
func FullLeafCount(n LeafCount) LeafCount                                     // → p5
func ExtendedLeafCount(n LeafCount) (LeafCount, error)                        // → p5
func TruncatedLeafCount(rightmostNonBlankLeaf LeafIndex) (LeafCount, error)   // → p5

func Root(n LeafCount) (NodeIndex, error)                                     // → p4,p5,p7,p8
func Left(x NodeIndex) (NodeIndex, error)                                     // → p4,p5
func Right(x NodeIndex) (NodeIndex, error)                                    // → p4,p5
func Parent(x NodeIndex, n LeafCount) (NodeIndex, error)                      // → p5
func Sibling(x NodeIndex, n LeafCount) (NodeIndex, error)                     // → p5
func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)                // → p5,p7,p8
func Copath(x NodeIndex, n LeafCount) ([]NodeIndex, error)                    // → p5,p8
func CommonAncestor(x NodeIndex, y NodeIndex) NodeIndex                       // → p5,p7

func SubtreeSpan(x NodeIndex) (firstNode NodeIndex, lastNode NodeIndex)       // → p5
func SubtreeLeaves(x NodeIndex) (firstLeaf LeafIndex, lastLeaf LeafIndex)     // → p5
func InSubtree(head NodeIndex, x NodeIndex) bool                              // → p5

type NodeShape interface {                                                    // → p5
    LeafCount() LeafCount
    IsBlank(x NodeIndex) bool
    UnmergedLeaves(x NodeIndex) []LeafIndex
}
type PathStep struct {
    Node        NodeIndex
    CopathChild NodeIndex
}                                                                             // → p5
func Resolution(shape NodeShape, x NodeIndex) ([]NodeIndex, error)            // → p5
func FilteredDirectPath(shape NodeShape, leaf LeafIndex) ([]PathStep, error)  // → p5
```

What dies: `type TreeSize uint32` and `(self TreeSize) Root() NodeIndex` (p7) — no alias, no method
form; `Level(x)` as a free function (p4); every `Root`/`DirectPath`/`Copath` in single-value
position (p4,p7,p8); `CommonAncestor(x, y LeafIndex)` (p7) — it takes `NodeIndex`; `NodeWidth`
returning `NodeIndex` (p4). p5's Amendment A.2 already carries the corrected table and its
`leftOf`/`rightOf`/`rootOf`/`directPathOf` shims stay internal to p5; **p4, p7 and p8 do not get
shims** — they call the two-valued form and handle the error, because a shim that turns an error
into `false` is exactly how ValSem300's trailing-blank case gets silently accepted.

p4 Task 1's compile-assertion block is rewritten from this section before anything else in p4 runs;
its entire purpose is to catch this drift and as written it catches it by failing.

---

## 5. `package mls` — key schedule, transcript, secret tree — p4

### 5.1 GroupContext

```go
type GroupContext struct {
    Version                 ProtocolVersion
    CipherSuite             CipherSuite
    GroupId                 []byte
    Epoch                   uint64
    TreeHash                []byte
    ConfirmedTranscriptHash []byte
    Extensions              []Extension
}                                                                             // → p5,p6,p7,p8
func (self *GroupContext) MarshalMLS(w *syntax.Writer) error                  // → p6,p7
func (self *GroupContext) UnmarshalMLS(r *syntax.Reader) error                // → p6,p7
func (self *GroupContext) Clone() *GroupContext                               // → p7
var _ syntax.Codec = (*GroupContext)(nil)
```

`Marshal() ([]byte, error)` and `ParseGroupContext(data)` are deleted under **C1**; call sites use
`syntax.Marshal(gc)` / `syntax.Unmarshal(bs, gc)`. This is the change that lets `GroupContext` be a
`syntax.Codec` and therefore a `CheckRoundTrip` target.

### 5.2 Key schedule

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
}                                                                             // → p7
type KeySchedule struct{ /* unexported */ }                                   // → p7

const PastEpochWindow uint64 = 32                                             // → p7,p8

func ZeroSecret(crypto CryptoProvider) []byte                                 // → p7
func DeriveJoinerSecret(crypto CryptoProvider, initSecretPrev []byte, commitSecret []byte, groupContext *GroupContext) ([]byte, error) // → p7
func NewKeySchedule(crypto CryptoProvider, initSecretPrev []byte, commitSecret []byte, pskSecret []byte, groupContext *GroupContext) (*KeySchedule, error)  // → p7
func NewKeyScheduleFromJoiner(crypto CryptoProvider, joinerSecret []byte, pskSecret []byte, groupContext *GroupContext) (*KeySchedule, error)               // → p7
func NewKeyScheduleFromEpochSecret(crypto CryptoProvider, epochSecret []byte, groupContext *GroupContext) (*KeySchedule, error)  // → p7   [GAP → p4]
func WelcomeKeyNonce(crypto CryptoProvider, welcomeSecret []byte) (key []byte, nonce []byte, err error) // → p7
func EmptyPskSecret(crypto CryptoProvider) []byte     // == PskSecret(crypto, nil)  → p7  [GAP → p4]

func (self *KeySchedule) JoinerSecret() []byte                                // → p7
func (self *KeySchedule) WelcomeSecret() []byte                               // → p7
func (self *KeySchedule) Secrets() *EpochSecrets                              // → p7
func (self *KeySchedule) GroupContextBytes() []byte                           // → p7
func (self *KeySchedule) Export(label string, context []byte, length int) ([]byte, error) // → p7
func (self *KeySchedule) ExternalKeyPair() (HpkePrivateKey, HpkePublicKey, error)
func (self *KeySchedule) ConfirmationTag(confirmedTranscriptHash []byte) []byte           // → p7
func (self *KeySchedule) VerifyConfirmationTag(confirmedTranscriptHash []byte, tag []byte) bool // → p7
func (self *KeySchedule) MembershipTag(authenticatedContentTbm []byte) []byte             // → p6,p7
func (self *KeySchedule) VerifyMembershipTag(authenticatedContentTbm []byte, tag []byte) bool
func (self *KeySchedule) Zeroize()                                            // → p7
```

**`NewKeyScheduleFromEpochSecret` is a genuine gap, not a rename, and it is assigned to p4.** RFC
9420 §11 group creation samples a fresh `epoch_secret` of size `KDF.Nh`; p4 offered entry points
only from `init_secret + commit_secret` and from `joiner_secret`, so `NewGroup` had nothing to
call. `joiner_secret` and `welcome_secret` are undefined on this path and the accessors return an
error if asked.

Everything p7 names on this surface is dropped: `DeriveEpochSecrets`,
`DeriveEpochSecretsFromJoiner`, `DeriveEpochSecretsFromEpochSecret`, `(*EpochSecrets).Export`, an
`EpochSecrets` with eleven differently-named fields, and `WelcomeKeyNonce` without an error.

### 5.3 PSK

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
}                                                                             // → p6,p8
func (self *PreSharedKeyId) MarshalMLS(w *syntax.Writer) error                // → p6
func (self *PreSharedKeyId) UnmarshalMLS(r *syntax.Reader) error              // → p6
func (self *PreSharedKeyId) Validate(crypto CryptoProvider) error             // → p7
var _ syntax.Codec = (*PreSharedKeyId)(nil)

type PreSharedKeyInput struct {
    Id     PreSharedKeyId
    Secret []byte
}
func CheckNoDuplicatePsks(ids []PreSharedKeyId) error
func PskSecret(crypto CryptoProvider, psks []PreSharedKeyInput) ([]byte, error)
```

`PreSharedKeyID` (p6,p8) → `PreSharedKeyId`, per `CODESTYLE.md`. `ParsePreSharedKeyId(r)` and
`(*PreSharedKeyId).Marshal()` are deleted under **C1**.

### 5.4 Transcript hashes

```go
type TranscriptHashes struct {
    Confirmed []byte
    Interim   []byte
}                                                                             // → p7
func InitialTranscriptHashes() *TranscriptHashes                              // → p7
func (self *TranscriptHashes) Clone() *TranscriptHashes                       // → p7
func (self *TranscriptHashes) Update(crypto CryptoProvider, confirmedTranscriptHashInput []byte, confirmationTag []byte) error       // → p7
func (self *TranscriptHashes) SetFromGroupInfo(crypto CryptoProvider, confirmedTranscriptHash []byte, confirmationTag []byte) error   // → p7
func ConfirmedTranscriptHash(crypto CryptoProvider, interimBefore []byte, confirmedTranscriptHashInput []byte) []byte                 // → p7
func InterimTranscriptHash(crypto CryptoProvider, confirmedAfter []byte, confirmationTag []byte) ([]byte, error)                      // → p7
```

**These are p4's, not p6's.** p7 attributes `ConfirmedTranscriptHash`/`InterimTranscriptHash` to the
framing plan and passes an `*AuthenticatedContent`. They take `confirmedTranscriptHashInput []byte`
deliberately, so no framing type crosses into `transcript.go`; p7 bridges with
`ConfirmedTranscriptHash(crypto, interimBefore, authContent.ConfirmedTranscriptHashInput())`.

### 5.5 Secret tree and the `MessageKeySource` implementation

```go
type RatchetType uint8
const (
    RatchetHandshake RatchetType = iota + 1
    RatchetApplication
)
const (
    MaxGenerationSkip uint32 = 1024
    RatchetWindowSize int    = 1024
)
type SecretTree struct{ /* unexported, guarded by stateLock */ }              // → p6,p7
func NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error) // → p6,p7
func (self *SecretTree) LeafCount() LeafCount                                 // → p7
func (self *SecretTree) Zeroize()                                             // → p7

// the internal form
func (self *SecretTree) NextSenderKey(leaf LeafIndex, kind RatchetType) (generation uint32, key []byte, nonce []byte, err error)
func (self *SecretTree) ReceiverKey(leaf LeafIndex, kind RatchetType, generation uint32) (key []byte, nonce []byte, err error)
func (self *SecretTree) SenderGeneration(leaf LeafIndex, kind RatchetType) (uint32, error)

// the MessageKeySource implementation p6 declares — p6's exact signatures        [GAP → p4]
func (self *SecretTree) NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error) // → p6
func (self *SecretTree) MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)     // → p6
func (self *SecretTree) EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)                                // → p6

func SenderDataKeyNonce(crypto CryptoProvider, senderDataSecret []byte, ciphertext []byte) (key []byte, nonce []byte, err error)   // → p6
```

**p4 implements the interface p6 declares.** p6 is the only consumer of the message-key surface and
its shape is the right one for the framing path: it is keyed on `ContentType`, which is what the
`PrivateMessage` header actually carries, so no caller has to remember the `ContentType→RatchetType`
mapping. `NextSenderKey`/`ReceiverKey` stay as the internal, vector-tested form
(`secret-tree.json` addresses them). `ContentTypeApplication → RatchetApplication`;
`ContentTypeProposal` and `ContentTypeCommit → RatchetHandshake`.

**`EraseMessageKey` is a gap with no producer anywhere**, and it is the forward-secrecy erase that
p6's ValSem006 reuse guard is built on. Assigned to p4, implemented against the skipped-key window
p4 already owns. p6 Task 11 carries `var _ MessageKeySource = (*SecretTree)(nil)` so the mismatch
fails at build, not at the message-protection vector family.

**`SenderDataKeyNonce` is implemented once, in p4.** p6 Task 9's unexported `senderDataKeyNonce`
(no error return) is deleted and `sealSenderData`/`openSenderData` call p4's exported form. Two
implementations of one §6.3.2 derivation, only one of which is vector-tested, and the untested one
being the one the encrypt path calls, is precisely how the `ciphertext_sample` short-ciphertext trap
both plans separately document gets got wrong. p6 keeps its two short-ciphertext tests as
regression tests against p4's implementation.

**Constructor:** `LeafCount`, one signature. p6 expected `groupSize uint32`; p7 expected
`(crypto, size TreeSize, encryptionSecret) *SecretTree` with no error. p4's shape wins with p3's
count type substituted (§C3) — that substitution is a type correction, not an API change.

### 5.6 p4's error set

```go
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

`ErrPskNonceLength`, `ErrPskType` and `ErrDuplicatePsk` are **deleted from p4** — they are
ValSem401/402/403 and belong to p8's catalogue (§9.1). p4's PSK validation returns
`ValSem(ValSem401, detail)` and so on.

---

## 6. `package mls` — registry enums, extensions, tree, TreeKEM — p5

### 6.1 Registry enums (all IANA-registry enums live here, wave 2, earliest need)

```go
type ProtocolVersion uint16                                                   // → p4,p6,p7,p8
const ProtocolVersionMls10 ProtocolVersion = 0x0001                           // → p4,p6,p7

type CredentialType uint16                                                    // → p6,p7
const CredentialTypeBasic CredentialType = 0x0001                             // → p7

type ProposalType uint16                                                      // → p6,p7,p8
const (
    ProposalTypeReserved               ProposalType = 0x0000
    ProposalTypeAdd                    ProposalType = 0x0001                  // → p6,p7,p8
    ProposalTypeUpdate                 ProposalType = 0x0002                  // → p6,p7,p8
    ProposalTypeRemove                 ProposalType = 0x0003                  // → p6,p7,p8
    ProposalTypePreSharedKey           ProposalType = 0x0004                  // → p6,p7,p8
    ProposalTypeReInit                 ProposalType = 0x0005                  // → p6,p7,p8
    ProposalTypeExternalInit           ProposalType = 0x0006                  // → p6,p7,p8
    ProposalTypeGroupContextExtensions ProposalType = 0x0007                  // → p6,p7,p8
)

type ExtensionType uint16                                                     // → p4,p6,p7,p8
const (
    ExtensionTypeRatchetTree             ExtensionType = 0x0002               // → p7,p8
    ExtensionTypeRequiredCapabilities    ExtensionType = 0x0003               // → p7
    ExtensionTypeExternalSenders         ExtensionType = 0x0004               // → p7,p8
    ExtensionTypeUrmessageGroupPolicy    ExtensionType = 0xF001               // → p7
    ExtensionTypeUrmessageLeafKeys       ExtensionType = 0xF002               // → p7
    ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003               // → p7
)
```

**Three plans declared `ProposalType` and its constants** (p5 Task 3, p6 Task 12, p7 Task 5) and two
declared `ProtocolVersion`/`ProtocolVersionMLS10` (p5 Task 3, p6 Task 1). Same package, so this is a
redeclaration compile error. Rule applied: **the registry enums go to p5, the wire structs that use
them go to p6.** p5 is the earliest wave that needs the enum (`Capabilities.Proposals
[]ProposalType`, `Capabilities.Versions []ProtocolVersion`), and grouping the enums into one file
mirrors what the IANA registries actually are. `ProtocolVersionMLS10` (p6 spelling) →
`ProtocolVersionMls10`, per `CODESTYLE.md`. `ProposalTypePSK` (p7) → `ProposalTypePreSharedKey`.

### 6.2 Extension

```go
type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}                                                                             // → p4,p6,p7,p8
func (self *Extension) MarshalMLS(w *syntax.Writer) error                     // → p6,p7,p8
func (self *Extension) UnmarshalMLS(r *syntax.Reader) error                   // → p6,p7,p8
var _ syntax.Codec = (*Extension)(nil)

func WriteExtensions(w *syntax.Writer, exts []Extension) error                // → p4,p6,p7
func ReadExtensions(r *syntax.Reader) ([]Extension, error)                    // → p4,p6,p7
func FindExtension(exts []Extension, t ExtensionType) ([]byte, bool)          // → p7,p8
```

**Override on the extension-vector codec (O-4).** p5 produced `MarshalExtensions(exts) ([]byte,
error)` / `UnmarshalExtensions(r *syntax.Reader)` — an asymmetric pair, one byte-returning and one
reader-taking. p4 independently asked for `MarshalExtensions(w *syntax.Writer, exts) error` /
`ParseExtensions(r)`, and p6 needs the same inline shape. The consumers are right: `extensions<V>`
is never a standalone message, it is always an inline field of `GroupContext`, `LeafNode`,
`KeyPackage`, `GroupInfo` and `ReInit`, so the byte-returning half forces an extra allocation plus a
manual `WriteOpaque` at every site — and getting that `WriteOpaque` wrong is exactly the
byte-count-versus-element-count error the whole codec design is built to prevent. Renamed
`WriteExtensions`/`ReadExtensions` to match p1's `WriteVector`/`ReadVector` naming, since that is
what they are built on.

**Wave note.** p4 is wave 2 and consumes this from p5, also wave 2. **p5 Task 3 sequences before p4
Task 3.** p4's consumed block moves this from its "From Syntax and codec (wave 1)" section — p1
produces no `Extension` type at all — into a "From TreeKEM (wave 2)" section.

### 6.3 Capabilities, RequiredCapabilities, Credential

```go
type Capabilities struct {
    Versions     []ProtocolVersion
    CipherSuites []CipherSuite
    Extensions   []ExtensionType
    Proposals    []ProposalType
    Credentials  []CredentialType
}                                                                             // → p7,p8
func (self *Capabilities) MarshalMLS(w *syntax.Writer) error
func (self *Capabilities) UnmarshalMLS(r *syntax.Reader) error
func (self *Capabilities) SupportsVersion(v ProtocolVersion) bool             // → p7
func (self *Capabilities) SupportsCipherSuite(s CipherSuite) bool             // → p7
func (self *Capabilities) SupportsExtension(t ExtensionType) bool             // → p7
func (self *Capabilities) SupportsProposal(t ProposalType) bool               // → p7
func (self *Capabilities) SupportsCredential(t CredentialType) bool           // → p7
func (self *Capabilities) Supports(rc *RequiredCapabilities) error            // → p7  [GAP → p5]
var _ syntax.Codec = (*Capabilities)(nil)

type RequiredCapabilities struct {
    ExtensionTypes  []ExtensionType
    ProposalTypes   []ProposalType
    CredentialTypes []CredentialType
}                                                                             // → p7
func (self *RequiredCapabilities) MarshalMLS(w *syntax.Writer) error
func (self *RequiredCapabilities) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*RequiredCapabilities)(nil)

type Credential struct {
    CredentialType CredentialType   // 0x0001 basic only in v1
    Identity       []byte           // BasicCredential.identity
}                                                                             // → p6,p7,p8
func (self *Credential) MarshalMLS(w *syntax.Writer) error   // ErrProfileCredentialType on x509
func (self *Credential) UnmarshalMLS(r *syntax.Reader) error // ErrProfileCredentialType on x509
func BasicCredential(identity []byte) Credential                              // → p7,p8  [GAP → p5]
var _ syntax.Codec = (*Credential)(nil)
```

`Credential` is **produced by p5**, per its own Amendment A.3 — p5's original Consumes block
attributed it to p1, which produces no MLS types at all. `(*Capabilities).Supports(rc)` and
`BasicCredential` are gaps p7 and p8 call and nobody produced; both go to p5, which owns the types.

### 6.4 LeafNode

```go
type LeafNodeSource uint8
const (
    LeafNodeSourceKeyPackage LeafNodeSource = 1                               // → p7
    LeafNodeSourceUpdate     LeafNodeSource = 2                               // → p7
    LeafNodeSourceCommit     LeafNodeSource = 3                               // → p7
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
}                                                                             // → p6,p7,p8
func (self *LeafNode) MarshalMLS(w *syntax.Writer) error                      // → p6,p7
func (self *LeafNode) UnmarshalMLS(r *syntax.Reader) error                    // → p6,p7
func (self *LeafNode) Clone() *LeafNode                                       // → p7
var _ syntax.Codec = (*LeafNode)(nil)

func NewLeafNode(crypto CryptoProvider, signer SignaturePrivateKey, cred Credential,
    encKey HpkePublicKey, caps Capabilities, exts []Extension) (*LeafNode, error)  // → p7  [GAP → p5]
func (self *LeafNode) Sign(crypto CryptoProvider, signer SignaturePrivateKey, groupId []byte, leafIndex LeafIndex) error   // → p7
func (self *LeafNode) VerifySignature(crypto CryptoProvider, groupId []byte, leafIndex LeafIndex) error                     // → p7

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
}                                                                             // → p7
func (self *LeafNode) Validate(ctx *LeafValidationContext) error              // → p7
```

`LeafNode.Validate(crypto, groupId, leaf, source, exts, now)` (p7's six-arg positional form) is
dropped for the context struct: it has eight inputs, two of them optional, and a positional call
with two `uint64` time arguments adjacent is a defect waiting to happen. `NewLeafNode` is a gap p7
calls at four sites; assigned to p5.

### 6.5 KeyPackage — **gap, assigned to p5**

```go
type KeyPackage struct {
    Version     ProtocolVersion
    CipherSuite CipherSuite
    InitKey     HpkePublicKey
    LeafNode    LeafNode
    Extensions  []Extension
    Signature   []byte
}                                                                             // → p6,p7,p8
func (self *KeyPackage) MarshalMLS(w *syntax.Writer) error                    // → p6,p7,p8
func (self *KeyPackage) UnmarshalMLS(r *syntax.Reader) error                  // → p6,p7,p8
var _ syntax.Codec = (*KeyPackage)(nil)

func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,
    caps Capabilities, exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
    encPriv HpkePrivateKey, err error)                                        // → p7,p8
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error)            // → p6,p7,p8
func (self *KeyPackage) Validate(crypto CryptoProvider, suite CipherSuite, now time.Time) error // → p7
```

**`KeyPackage` was consumed by four plans and produced by none** — p5 attributed it to p7, p7
attributed it to p5, p6 to "the key-package / leaf-node / extension / key-schedule plans", p8 to
p7. p7's file structure has no `key_package.go` row and none of its 21 Produces blocks names it.
This is the worst kind of gap: nothing fails until integration, and the type carries every joiner's
init key.

**Assigned to p5, not p7** (the findings suggest p7). Reasons: it is `LeafNode` plus an init key
plus a signature, so it belongs beside `leaf_node.go` in the same file family and the same
validation code; its only dependencies are `CryptoProvider` (p2, wave 1) and p5's own types, so it
can land in wave 2; and putting it in wave 4 is what makes p6's `MLSMessage` (wave 3) uncompilable,
since `package mls` is one package and a wave-3 struct cannot name a wave-4 type. p7 keeps only the
`StateStore` key-package persistence. `Validate` delegates to `LeafNode.Validate` with
`ExpectedSource = LeafNodeSourceKeyPackage`; `Ref` delegates to p2's `MakeKeyPackageRef`.

### 6.6 Ratchet tree

```go
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
}                                                                             // → p6,p8
type OptionalNode struct {
    Present bool
    Node    Node
}                                                                             // → p8  [GAP → p5]

type RatchetTree struct{ /* opaque: nodes []*Node */ }                        // → p4,p6,p7,p8
func NewRatchetTree() *RatchetTree                                            // → p7
func (self *RatchetTree) MarshalMLS(w *syntax.Writer) error                   // → p6,p7,p8
func (self *RatchetTree) UnmarshalMLS(r *syntax.Reader) error                 // → p6,p7,p8
func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)   // UnmarshalLimit(MaxRatchetTreeLength) → p7,p8
var _ syntax.Codec = (*RatchetTree)(nil)

func (self *RatchetTree) LeafWidth() LeafCount        // leaf slots; a power of two  → p4,p7
func (self *RatchetTree) NodeWidth() uint32                                   // → p7
func (self *RatchetTree) Get(x NodeIndex) *Node       // nil when blank or out of range
func (self *RatchetTree) Leaf(i LeafIndex) *LeafNode                          // → p7
func (self *RatchetTree) ParentAt(x NodeIndex) *ParentNode
func (self *RatchetTree) SetLeaf(i LeafIndex, leaf *LeafNode) error
func (self *RatchetTree) SetParent(x NodeIndex, parent *ParentNode) error
func (self *RatchetTree) Blank(x NodeIndex) error
func (self *RatchetTree) BlankDirectPath(i LeafIndex) error
func (self *RatchetTree) Clone() *RatchetTree                                 // → p7
func (self *RatchetTree) Members() []LeafIndex                                // → p7
func (self *RatchetTree) MemberCount() uint32                                 // → p7
func (self *RatchetTree) NonBlankLeaves() []LeafIndex                         // → p7  [GAP → p5]
func (self *RatchetTree) FindLeafBySignatureKey(key SignaturePublicKey) (LeafIndex, bool)  // → p7
func (self *RatchetTree) EncryptionKeyInUse(key HpkePublicKey) bool           // → p7  [GAP → p5]
func (self *RatchetTree) HasTrailingBlankNodes() bool                         // → p7,p8  [GAP → p5]
func (self *RatchetTree) Resolution(x NodeIndex) []NodeIndex
func (self *RatchetTree) AddLeaf(leaf *LeafNode) (LeafIndex, error)           // → p7
func (self *RatchetTree) UpdateLeaf(i LeafIndex, leaf *LeafNode) error        // → p7
func (self *RatchetTree) RemoveLeaf(i LeafIndex) error                        // → p7
func (self *RatchetTree) FilteredDirectPath(i LeafIndex) ([]NodeIndex, error) // → p7
func (self *RatchetTree) EncryptionTargets(sender LeafIndex, exclude []LeafIndex) ([][]NodeIndex, error)

func (self *RatchetTree) TreeHash(crypto CryptoProvider) ([]byte, error)      // → p4,p7
func (self *RatchetTree) NodeTreeHash(crypto CryptoProvider, x NodeIndex) ([]byte, error)
func (self *RatchetTree) TreeHashes(crypto CryptoProvider) ([][]byte, error)
func (self *RatchetTree) ParentHash(crypto CryptoProvider, parent, copathChild NodeIndex) ([]byte, error)
func (self *RatchetTree) VerifyParentHashes(crypto CryptoProvider) error

type TreeValidationContext struct {
    Crypto          CryptoProvider
    Suite           CipherSuite
    GroupId         []byte
    RequiredCaps    *RequiredCapabilities
    GroupExtensions []Extension
    NowMs           uint64
    ClockSkewMs     uint64
}                                                                             // → p7,p8
func (self *RatchetTree) Validate(ctx *TreeValidationContext) error           // → p7,p8
func (self *RatchetTree) ValidateAgainstContext(ctx *TreeValidationContext, gc *GroupContext) error // → p7
```

Dead names: `ParseRatchetTree(crypto, data)` (p7,p8) → `UnmarshalRatchetTree(data)`, with the crypto
parameter dropped — parsing a tree needs no crypto, validating it does;
`EncodeRatchetTree`/`ValidateRatchetTree` (p8) → `syntax.Marshal` / `Validate(ctx)`;
`(*RatchetTree).LeafNode(i) (*LeafNode, bool)` (p7) → `Leaf(i)`; `RootHash` (p7) → `TreeHash`;
`Encode` (p7) → `syntax.Marshal`; `Size() TreeSize` (p7) → `LeafWidth() LeafCount`;
`NewRatchetTree(crypto)` (p7) → `NewRatchetTree()`;
`Validate(groupId, exts, now)` (p7) → `Validate(ctx)`;
`RatchetTreeExtension` (p8) does not exist — use
`FindExtension(exts, ExtensionTypeRatchetTree)` then `UnmarshalRatchetTree`.

`RatchetTree` implements `NodeShape` (§4) with `UnmergedLeaves` returning the stored list in stored
order. Four accessors p7 needs and p5 did not offer (`NonBlankLeaves`, `EncryptionKeyInUse`,
`HasTrailingBlankNodes`, `OptionalNode`) are added to p5 rather than open-coded in p7 — they are all
reads of p5's private node array.

### 6.7 TreeKEM

```go
type HpkeCiphertext struct {
    KemOutput  []byte
    Ciphertext []byte
}                                                                             // → p6,p7,p8
func (self *HpkeCiphertext) MarshalMLS(w *syntax.Writer) error
func (self *HpkeCiphertext) UnmarshalMLS(r *syntax.Reader) error

type UpdatePathNode struct {
    EncryptionKey       HpkePublicKey
    EncryptedPathSecret []HpkeCiphertext
}                                                                             // → p6,p8
type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode
}                                                                             // → p6,p7,p8
func (self *UpdatePath) MarshalMLS(w *syntax.Writer) error                    // → p6,p7
func (self *UpdatePath) UnmarshalMLS(r *syntax.Reader) error                  // → p6,p7
var _ syntax.Codec = (*UpdatePath)(nil)

type TreeKEMPrivate struct {
    LeafIndex      LeafIndex
    EncryptionPriv HpkePrivateKey
    PathSecrets    map[NodeIndex][]byte
}                                                                             // → p7
func NewTreeKEMPrivate(i LeafIndex, encryptionPriv HpkePrivateKey) *TreeKEMPrivate   // → p7
func (self *TreeKEMPrivate) Clone() *TreeKEMPrivate                           // → p7
func (self *TreeKEMPrivate) NodePrivateKey(crypto CryptoProvider, x NodeIndex) (HpkePrivateKey, bool, error) // → p7
func (self *TreeKEMPrivate) Consistent(crypto CryptoProvider, tree *RatchetTree) error // → p7

func DerivePathSecrets(crypto CryptoProvider, initial []byte, count int) [][]byte     // → p7
func DeriveNodeKeyPair(crypto CryptoProvider, pathSecret []byte) (HpkePrivateKey, HpkePublicKey, error) // → p7

type UpdatePathPlan struct {
    Path         []NodeIndex
    PathSecrets  [][]byte
    PublicKeys   []HpkePublicKey
    LeafNode     *LeafNode
    CommitSecret []byte
    Private      *TreeKEMPrivate
}                                                                             // → p7
func (self *RatchetTree) CreateUpdatePathSecrets(crypto CryptoProvider, sender LeafIndex,
    signer SignaturePrivateKey, groupId []byte) (*UpdatePathPlan, error)      // → p7
func (self *RatchetTree) EncryptUpdatePath(crypto CryptoProvider, plan *UpdatePathPlan,
    sender LeafIndex, groupContext []byte, exclude []LeafIndex) (*UpdatePath, error)  // → p7
func (self *RatchetTree) MergeUpdatePath(crypto CryptoProvider, sender LeafIndex, path *UpdatePath) error // → p7

type PathDecryptResult struct {
    CommitSecret []byte
    Private      *TreeKEMPrivate
}                                                                             // → p7
func (self *RatchetTree) DecryptUpdatePath(crypto CryptoProvider, sender LeafIndex,
    path *UpdatePath, groupContext []byte, priv *TreeKEMPrivate,
    exclude []LeafIndex) (*PathDecryptResult, error)                          // → p7
func CheckUpdatePathKeyUniqueness(tree *RatchetTree, path *UpdatePath) error  // → p7,p8

// the HpkeCiphertext-shaped convenience over p2's flat pair — lives here, next to
// the type it returns, so p2 stays free of TreeKEM types.
func SealWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string,
    context []byte, plaintext []byte) (*HpkeCiphertext, error)                // → p7  [GAP → p5]
func OpenWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string,
    context []byte, ct *HpkeCiphertext) ([]byte, error)                       // → p7  [GAP → p5]
```

**The ordering contract is normative** and p7 Task 13 is restructured around it, because the HPKE
context is the *new* epoch's GroupContext and its `tree_hash` covers the path's own public keys:

1. `CreateUpdatePathSecrets` — mutates the tree, returns the plan
2. `TreeHash` — now reflects the applied path; caller builds the new `GroupContext`
3. `EncryptUpdatePath` — encrypts under that serialized GroupContext

receiving side: `MergeUpdatePath` → `TreeHash` → build GroupContext → `DecryptUpdatePath`.

p7's single-call `CreateUpdatePath(...) (*UpdatePath, *PathSecrets, HpkePrivateKey, error)` and
`ApplyUpdatePath(...)` cannot express that ordering and are dropped, along with `type PathSecrets`,
`SecretAt`, `CommitSecret`, `PathSecretToNodeKeyPair`, `DerivePathSecretNext` and
`MergeUpdatePathPublic` — all of which have no producer. `HPKECiphertext` (p7, 7 uses) →
`HpkeCiphertext`.

### 6.8 X-Wing constants in `package mls`

```go
const AlgIdXwing uint16 = 0x0014                                              // → p7
const XwingPublicKeyLen = 1216                                                // → p7
type LeafKeysExtension struct {
    AlgId          uint16
    DeviceXwingPub []byte      // exactly XwingPublicKeyLen bytes for alg 0x0014
}                                                                             // → p7
func (self *LeafKeysExtension) Encode() (Extension, error)                    // → p7
func ParseLeafKeysExtension(data []byte) (*LeafKeysExtension, error)          // → p7
```

Both p5 and p7 declare `AlgIdXwing`, the 1216 constant (as `XwingPublicKeyLen` and
`XwingPublicKeySize`) and `LeafKeysExtension`. p5 wins on wave — the leaf node carries the
extension, and `LeafNode.Validate` must range-check it. p7 Task 2 is reduced to the
`LeafKeysOf(leaf)` accessor (§8.1). The constant is duplicated across the `mls`/`message` package
boundary on purpose: `message.XwingPublicKeySize` (§10) is p2's and `mls` must not import
`message`. p2 carries a compile assertion that the two agree.

### 6.9 p5's error set

```go
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

---

## 7. `package mls` — framing and wire structs — p6

### 7.1 Framing enums

```go
type WireFormat uint16
const (
    WireFormatReserved       WireFormat = 0x0000
    WireFormatPublicMessage  WireFormat = 0x0001                              // → p7,p8
    WireFormatPrivateMessage WireFormat = 0x0002                              // → p7,p8
    WireFormatWelcome        WireFormat = 0x0003                              // → p7
    WireFormatGroupInfo      WireFormat = 0x0004                              // → p7
    WireFormatKeyPackage     WireFormat = 0x0005                              // → p7,p8
)
type ContentType uint8
const (
    ContentTypeReserved    ContentType = 0
    ContentTypeApplication ContentType = 1                                    // → p4,p7,p8
    ContentTypeProposal    ContentType = 2                                    // → p4,p7,p8
    ContentTypeCommit      ContentType = 3                                    // → p4,p7,p8
)
type SenderType uint8
const (
    SenderTypeReserved          SenderType = 0
    SenderTypeMember            SenderType = 1                                // → p7,p8
    SenderTypeExternal          SenderType = 2                                // → p7,p8
    SenderTypeNewMemberProposal SenderType = 3                                // → p7,p8
    SenderTypeNewMemberCommit   SenderType = 4                                // → p7,p8
)
```

p8's `SenderMember`/`SenderExternal`/… → `SenderTypeMember`/… `ProtocolVersion` is p5's (§6.1);
p6 Task 1 deletes its copy.

### 7.2 Framing structs

```go
type Sender struct {
    SenderType  SenderType
    LeafIndex   LeafIndex
    SenderIndex uint32
}                                                                             // → p7,p8
func (self *Sender) MarshalMLS(w *syntax.Writer) error
func (self *Sender) UnmarshalMLS(r *syntax.Reader) error

type FramedContent struct {
    GroupId           []byte
    Epoch             uint64
    Sender            Sender
    AuthenticatedData []byte
    ContentType       ContentType
    ApplicationData   []byte
    Proposal          *Proposal
    Commit            *Commit
}                                                                             // → p7,p8
func (self *FramedContent) MarshalMLS(w *syntax.Writer) error
func (self *FramedContent) UnmarshalMLS(r *syntax.Reader) error

type FramedContentAuthData struct {
    Signature       []byte
    ConfirmationTag []byte
}                                                                             // → p7,p8
func (self *FramedContentAuthData) MarshalMLS(w *syntax.Writer, contentType ContentType) error
func (self *FramedContentAuthData) UnmarshalMLS(r *syntax.Reader, contentType ContentType) error

type AuthenticatedContent struct {
    WireFormat WireFormat
    Content    FramedContent
    Auth       FramedContentAuthData
}                                                                             // → p7,p8
func (self *AuthenticatedContent) MarshalMLS(w *syntax.Writer) error
func (self *AuthenticatedContent) UnmarshalMLS(r *syntax.Reader) error
func (self *AuthenticatedContent) ConfirmedTranscriptHashInput() ([]byte, error) // → p7
func (self *AuthenticatedContent) ProposalRef(crypto CryptoProvider) (ProposalRef, error) // → p7  [GAP → p6]

type PublicMessage struct {
    Content       FramedContent
    Auth          FramedContentAuthData
    MembershipTag []byte
}                                                                             // → p7,p8
func (self *PublicMessage) MarshalMLS(w *syntax.Writer) error
func (self *PublicMessage) UnmarshalMLS(r *syntax.Reader) error
func (self *PublicMessage) AuthenticatedContent() *AuthenticatedContent        // → p7

type PrivateMessage struct {
    GroupId             []byte
    Epoch               uint64
    ContentType         ContentType
    AuthenticatedData   []byte
    EncryptedSenderData []byte
    Ciphertext          []byte
}                                                                             // → p7,p8
func (self *PrivateMessage) MarshalMLS(w *syntax.Writer) error
func (self *PrivateMessage) UnmarshalMLS(r *syntax.Reader) error

type MLSMessage struct {
    Version        ProtocolVersion
    WireFormat     WireFormat
    PublicMessage  *PublicMessage
    PrivateMessage *PrivateMessage
    Welcome        *Welcome
    GroupInfo      *GroupInfo
    KeyPackage     *KeyPackage
}                                                                             // → p7,p8
func (self *MLSMessage) MarshalMLS(w *syntax.Writer) error
func (self *MLSMessage) UnmarshalMLS(r *syntax.Reader) error
func MarshalMLSMessage(message *MLSMessage) ([]byte, error)                   // → p7,p8
func ParseMLSMessage(data []byte) (*MLSMessage, error)                        // → p7,p8
```

`ParseMLSMessage`/`MarshalMLSMessage` are the one sanctioned pair of byte-level free functions
outside p8's table, because p6 correctly identifies `ParseMLSMessage` as the single entry point
every byte off the wire passes through and the whole system names it. `EncodeMLSMessage` (p8) and
`(*MLSMessage).Marshal` (p7) are dropped. p8's `FramedContentAuthData.MembershipTag` and
`FramedContentAuthData.HasConfirmationTag` fields are **rejected**: the membership tag lives on
`PublicMessage` where RFC 9420 puts it, and confirmation-tag presence is derived from
`ContentType`. p8's `FramedContent.RawProposal` is **rejected**: `Proposal.ProposalType` plus
`Proposal.UnknownBody` (§7.4) already gives the forge an unparsed arm.

### 7.3 Preimages and message protection

```go
func FramedContentTBSBytes(wireFormat WireFormat, content *FramedContent, groupContext []byte) ([]byte, error)  // → p7
func AuthenticatedContentTBMBytes(authContent *AuthenticatedContent, groupContext []byte) ([]byte, error)       // → p7

type MessageKeySource interface {                                             // implemented by p4
    NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
    MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
    EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
}
var _ MessageKeySource = (*SecretTree)(nil)

type SignatureKeyResolver func(sender Sender) (SignaturePublicKey, error)     // → p7
func StaticSignatureKey(pub SignaturePublicKey) SignatureKeyResolver          // → p7,p8
const PaddingSizeV1 = 0                                                       // → p7

func SignAuthenticatedContent(crypto CryptoProvider, priv SignaturePrivateKey,
    wireFormat WireFormat, content *FramedContent, groupContext []byte) (*AuthenticatedContent, error)  // → p7
func VerifyAuthenticatedContent(crypto CryptoProvider, pub SignaturePublicKey,
    authContent *AuthenticatedContent, groupContext []byte) error             // → p7
func ComputeMembershipTag(crypto CryptoProvider, membershipKey []byte,
    authContent *AuthenticatedContent, groupContext []byte) ([]byte, error)   // → p7
func SealPublicMessage(crypto CryptoProvider, membershipKey []byte,
    authContent *AuthenticatedContent, groupContext []byte) (*PublicMessage, error)  // → p7
func OpenPublicMessage(crypto CryptoProvider, membershipKey []byte, message *PublicMessage,
    resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error) // → p7
func SealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
    authContent *AuthenticatedContent, paddingSize int) (*PrivateMessage, error)      // → p7
func OpenPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
    message *PrivateMessage, resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error) // → p7
func CheckFramedContentContext(content *FramedContent, groupId []byte, epoch uint64) error  // → p7
func CheckSenderLeaf(sender Sender, leafOccupied func(LeafIndex) bool) error  // → p7

// unexported construction-bypass seams for the forge — framing.go, package mls    [GAP → p6]
func (self *Group) sealFramedContentForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey) ([]byte, error)                // → p8
func (self *Group) sealFramedContentWithPaddingForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey, padding []byte) ([]byte, error) // → p8
```

p7's names all die: `SignFramedContent` → `SignAuthenticatedContent`; `ProtectPrivate` →
`SealPrivateMessage`; `UnprotectPrivate` → `OpenPrivateMessage`;
`(*AuthenticatedContent).VerifySignature` → free `VerifyAuthenticatedContent`. Every entry point
takes `groupContext []byte` (**C4**), so p7's call sites in Tasks 12, 13 and 18 obtain them from
`syntax.Marshal(gc)`.

The two `*ForTest` seams are gaps that all ten framing ValSem tests (002–011) depend on. p8 flagged
them as "an ask on that plan" and no p6 task took the ask; they are now p6's, with p8's exact
signatures.

### 7.4 Proposal, ProposalOrRef, Commit — **p6 owns the structs and codecs**

```go
type Add struct{ KeyPackage KeyPackage }                                      // → p7,p8
type Update struct{ LeafNode LeafNode }                                       // → p7,p8
type Remove struct{ Removed LeafIndex }                                       // → p7,p8
type PreSharedKey struct{ Psk PreSharedKeyId }                                // → p8
type ReInit struct {
    GroupId     []byte
    Version     ProtocolVersion
    CipherSuite CipherSuite
    Extensions  []Extension
}
type ExternalInit struct{ KemOutput []byte }
type GroupContextExtensions struct{ Extensions []Extension }                  // → p7

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
}                                                                             // → p5,p7,p8
func (self *Proposal) MarshalMLS(w *syntax.Writer) error                      // → p7,p8
func (self *Proposal) UnmarshalMLS(r *syntax.Reader) error                    // → p7,p8
var _ syntax.Codec = (*Proposal)(nil)

type ProposalOrRefType uint8
const (
    ProposalOrRefTypeReserved  ProposalOrRefType = 0
    ProposalOrRefTypeProposal  ProposalOrRefType = 1                          // → p7
    ProposalOrRefTypeReference ProposalOrRefType = 2                          // → p7
)
type ProposalRef []byte                                                       // → p7,p8
type ProposalOrRef struct {
    Type      ProposalOrRefType
    Proposal  *Proposal
    Reference ProposalRef
}                                                                             // → p7,p8
func (self *ProposalOrRef) MarshalMLS(w *syntax.Writer) error
func (self *ProposalOrRef) UnmarshalMLS(r *syntax.Reader) error

type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}                                                                             // → p7,p8
func (self *Commit) MarshalMLS(w *syntax.Writer) error
func (self *Commit) UnmarshalMLS(r *syntax.Reader) error
var _ syntax.Codec = (*Commit)(nil)
```

**p6 keeps these; p7 deletes its declarations.** Both plans declare `Proposal`, `ProposalOrRef` and
`Commit` in `package mls`, with incompatible shapes: p6's is permissive (all seven arms plus
`UnknownBody` for GREASE), p7's has no arm for psk/reinit/external_init and refuses them at parse.
p6 wins because its `messages` vector family (family 12) cannot be green without decoding all seven
arms, and because refusing a proposal type is a *profile* decision, not a *codec* decision — the two
must not be fused, or the codec becomes untestable against the corpus. The v1 refusal moves to
`(*Profile).CheckProposalType` (§9.3), called by p7 at the parse boundary. p6's own Coordination
item 1 flagged this as unsettled; it is settled here.

p7 Task 5 is reduced to calling the profile gate; Task 6 keeps `CachedProposal`, `ProposalList`,
`ProposalCache`; Task 9 keeps `CommitPathRequired` and `StagedCommit`. p5 Task 28 (family 9,
tree-operations) is rewritten against this shape — `Proposal.Add.KeyPackage`,
`Proposal.Update.LeafNode`, `Proposal.Remove.Removed` — and **moves out of p5 into p7**, since it is
p5's only wave-4 dependency and a family with no owner in the wave it can execute in is a family
that never runs.

`ProposalType` and its constants are p5's (§6.1); p6 declares neither.

### 7.5 Welcome / GroupInfo codecs — **moved from p7 to p6**

```go
type GroupInfo struct {
    GroupContext    GroupContext
    Extensions      []Extension
    ConfirmationTag []byte
    Signer          LeafIndex
    Signature       []byte
}                                                                             // → p7,p8
func (self *GroupInfo) MarshalMLS(w *syntax.Writer) error                     // → p7
func (self *GroupInfo) UnmarshalMLS(r *syntax.Reader) error                   // → p7
type GroupInfoTBS struct {
    GroupContext    GroupContext
    Extensions      []Extension
    ConfirmationTag []byte
    Signer          LeafIndex
}                                                                             // → p7
func (self *GroupInfoTBS) MarshalMLS(w *syntax.Writer) error                  // → p7

type PathSecret struct{ PathSecret []byte }                                   // → p7
type GroupSecrets struct {
    JoinerSecret []byte
    PathSecret   *PathSecret        // optional<PathSecret>
    Psks         []PreSharedKeyId   // always empty in v1
}                                                                             // → p7
func (self *GroupSecrets) MarshalMLS(w *syntax.Writer) error                  // → p7
func (self *GroupSecrets) UnmarshalMLS(r *syntax.Reader) error                // → p7

type EncryptedGroupSecrets struct {
    NewMember             []byte           // KeyPackageRef
    EncryptedGroupSecrets HpkeCiphertext
}                                                                             // → p7
type Welcome struct {
    CipherSuite        CipherSuite
    Secrets            []EncryptedGroupSecrets
    EncryptedGroupInfo []byte
}                                                                             // → p7,p8
func (self *Welcome) MarshalMLS(w *syntax.Writer) error                       // → p7,p8
func (self *Welcome) UnmarshalMLS(r *syntax.Reader) error                     // → p7,p8
var _ syntax.Codec = (*Welcome)(nil)
var _ syntax.Codec = (*GroupInfo)(nil)
```

**The codecs move to p6 (wave 3); the generation and processing logic stays in p7 (wave 4).** p6's
`MLSMessage` names `*Welcome`, `*GroupInfo` and `*KeyPackage` by direct type, and `package mls` is
one package: if those types land in wave 4, nothing in wave 3 compiles, including p6's own
message-protection vector gate and `ParseMLSMessage`. This is exactly the split p6 already applies
to `Proposal`/`Commit`, applied consistently. p7 keeps `(*GroupInfo).Sign`, `(*GroupInfo).Verify`,
`BuildWelcome`, `WelcomeJoiner` and `JoinFromWelcome` (§8.4).

### 7.6 p6's error set — structural only

```go
var ErrUnknownWireFormat error                                                // → p7
var ErrUnsupportedVersion error                                               // → p7
var ErrUnknownContentType error
var ErrUnknownSenderType error
var ErrContentArmMismatch error
var ErrMissingGroupContext error
var ErrUnexpectedGroupContext error
var ErrWireFormatMismatch error                                               // → p7
var ErrSenderNotMember error                                                  // → p7
var ErrInvalidPaddingSize error
```

Ten further names p6 Task 1 declared — `ErrWrongGroupId`, `ErrWrongEpoch`, `ErrBlankSenderLeaf`,
`ErrApplicationMustBeCiphertext`, `ErrDecryptFailed`, `ErrMissingMembershipTag`,
`ErrBadMembershipTag`, `ErrMissingConfirmationTag`, `ErrBadSignature`, `ErrNonZeroPadding` — are
**deleted from p6**. They are ValSem002–011 and belong to p8's `errors.go` (§9.1), which is wave 1
and therefore already available. p6's justification for a separate file ("so this plan and the
wave-1 validation plan never edit the same file") avoids a merge conflict by guaranteeing a
redeclaration compile error instead.

---

## 8. `package mls` — group lifecycle — p7

### 8.1 URmessage extensions

```go
func LeafKeysOf(leaf *LeafNode) (*LeafKeysExtension, error)                   // (type is p5's, §6.8)

const ExtensionTypeUrmessageGroupPolicy ExtensionType = 0xF001                // declared by p5, §6.1
type Role uint8
const (
    RoleObserver Role = 0
    RoleMember   Role = 1
    RoleAdmin    Role = 2
    RoleOwner    Role = 3
)
func (self Role) String() string
func ParseRole(name string) (Role, error)
type RoleEntry struct {
    MemberId []byte      // the member's Ed25519 identity public key
    Role     Role
}
type RetentionPolicy struct {
    DurableMs uint64
    MediaMs   uint64
}
type GroupPolicyExtension struct {
    Roles               []RoleEntry
    RetentionPolicy     RetentionPolicy
    DisappearingBuckets []uint8
    ServerId            []byte
}
func (self *GroupPolicyExtension) MarshalMLS(w *syntax.Writer) error
func (self *GroupPolicyExtension) UnmarshalMLS(r *syntax.Reader) error
func (self *GroupPolicyExtension) Canonicalize() error
func (self *GroupPolicyExtension) Validate() error
func (self *GroupPolicyExtension) Encode() (Extension, error)
func ParseGroupPolicyExtension(data []byte) (*GroupPolicyExtension, error)
func (self *GroupPolicyExtension) RoleOf(memberId []byte) (Role, bool)
func (self *GroupPolicyExtension) SetRole(memberId []byte, role Role)
func (self *GroupPolicyExtension) RemoveRole(memberId []byte)
func (self *GroupPolicyExtension) AdminCount() int
func (self *GroupPolicyExtension) OwnerId() ([]byte, bool)
func (self *GroupPolicyExtension) Clone() *GroupPolicyExtension
func GroupPolicyOf(exts []Extension) (*GroupPolicyExtension, error)

const SuccessionFloorMinMs uint64 = 7776000000   // 90 days
type OwnerSuccessorExtension struct {
    Enabled           bool
    SuccessorMemberId []byte
    NominatedAtMs     uint64
    FloorMs           uint64
}
func (self *OwnerSuccessorExtension) MarshalMLS(w *syntax.Writer) error
func (self *OwnerSuccessorExtension) UnmarshalMLS(r *syntax.Reader) error
func (self *OwnerSuccessorExtension) Validate() error
func (self *OwnerSuccessorExtension) Encode() (Extension, error)
func ParseOwnerSuccessorExtension(data []byte) (*OwnerSuccessorExtension, error)
func OwnerSuccessorOf(exts []Extension) (*OwnerSuccessorExtension, bool, error)
```

All 82 `tls:` tags and all `MarshalTLS`/`UnmarshalTLS` pairs in p7 are deleted and rewritten as
explicit `MarshalMLS`/`UnmarshalMLS` bodies (**C1**). `appendLengthPrefixed` is deleted — a fourth
private length-prefix implementation; `successionPreimage` builds its bytes through a
`syntax.Writer`.

### 8.2 Proposal cache and validation

```go
type CachedProposal struct {
    Ref      ProposalRef
    Proposal Proposal
    Sender   LeafIndex
    ByValue  bool
}
type ProposalList struct {
    Adds    []CachedProposal
    Updates []CachedProposal
    Removes []CachedProposal
    GCE     []CachedProposal
    All     []CachedProposal
}
func (self *ProposalList) Len() int
func (self *ProposalList) PathRequired() bool
func (self *ProposalList) Extensions() ([]Extension, bool)
func (self *ProposalList) Refs() []ProposalOrRef
type ProposalCache struct{ /* opaque */ }
func NewProposalCache() *ProposalCache
func (self *ProposalCache) Store(crypto CryptoProvider, content *AuthenticatedContent) (ProposalRef, error)
func (self *ProposalCache) Get(ref ProposalRef) (CachedProposal, bool)
func (self *ProposalCache) Resolve(crypto CryptoProvider, committer LeafIndex, refs []ProposalOrRef) (*ProposalList, error)
func (self *ProposalCache) Clear()
func (self *ProposalCache) Pending() []ProposalOrRef

type ProposalValidationInput struct {
    Crypto     CryptoProvider
    Tree       *RatchetTree    // PRE-commit
    Context    *GroupContext   // PRE-commit
    Extensions []Extension     // POST-GCE, RFC 9420 §12.3 first step
    Committer  LeafIndex
    List       *ProposalList
    Now        time.Time
}
func ValidateProposalList(in *ProposalValidationInput) error
func ValSem101UniqueSignatureKey(in *ProposalValidationInput) error
func ValSem102UniqueInitKey(in *ProposalValidationInput) error
func ValSem103UniqueEncryptionKey(in *ProposalValidationInput) error
func ValSem104InitNotEqualEncryptionKey(in *ProposalValidationInput) error
func ValSem105SuiteAndVersionMatch(in *ProposalValidationInput) error
func ValSem106RequiredCapabilitiesSatisfied(in *ProposalValidationInput) error
func ValSem107UniqueRemove(in *ProposalValidationInput) error
func ValSem108RemoveExists(in *ProposalValidationInput) error
func ValSem109UpdateRequiredCapabilities(in *ProposalValidationInput) error
func ValSem110UpdateUniqueEncryptionKey(in *ProposalValidationInput) error
func ValSem111NoCommitterUpdate(in *ProposalValidationInput) error
func ValSem112UpdateSenderIsMember(in *ProposalValidationInput) error
func ValSem113ProposalTypeSupported(in *ProposalValidationInput) error

type ApplyResult struct {
    Tree          *RatchetTree
    Extensions    []Extension
    AddedLeaves   []LeafIndex
    RemovedLeaves []LeafIndex
    UpdatedLeaves []LeafIndex
    SelfRemoved   bool
}
func ApplyProposals(crypto CryptoProvider, tree *RatchetTree, ctx *GroupContext,
    own LeafIndex, list *ProposalList) (*ApplyResult, error)

type CommitValidationInput struct {
    Crypto          CryptoProvider
    PreTree         *RatchetTree
    PostTree        *RatchetTree     // after ApplyProposals, before the path merge
    Context         *GroupContext
    Extensions      []Extension
    Committer       LeafIndex
    Own             LeafIndex
    List            *ProposalList
    Commit          *Commit
    ConfirmationKey []byte
    ConfirmedHash   []byte
    ConfirmationTag []byte
    Now             time.Time
}
func ValidateCommit(in *CommitValidationInput) error
func ValSem200NoSelfRemove(in *CommitValidationInput) error
func ValSem201PathPresentWhenRequired(in *CommitValidationInput) error
func ValSem202PathLength(in *CommitValidationInput) error
func ValSem203PathDecrypt(in *CommitValidationInput) error
func ValSem204PathKeyMismatch(in *CommitValidationInput) error
func ValSem205ConfirmationTag(in *CommitValidationInput) error
func ValSem206PathLeafEncryptionKeyUnique(in *CommitValidationInput) error
func ValSem207PathEncryptionKeysUnique(in *CommitValidationInput) error
func ValSem208SingleGroupContextExtensions(in *CommitValidationInput) error
func ValSem209GroupExtensionsSupported(in *CommitValidationInput) error
func ValSem300NoTrailingBlankNodes(tree *RatchetTree) error
func CommitPathRequired(list *ProposalList) bool

// errata, named in acceptance criterion 3 — implemented here, not "by whichever plan lands second"
func CheckErrata8745(path *UpdatePath, context *GroupContext) error           // → p8  [GAP → p7]
func CheckErrata8815(commit *Commit, pending *ProposalCache) error            // → p8  [GAP → p7]
```

p7's list omitted `ValSem203`; it is restored, so the 200-series is 200–209 with no hole. The two
errata functions are a gap p8's Task 23 specifies tests for and then disclaims ownership of; they
are p7's, called from commit processing.

### 8.3 Group

```go
type StateStore interface {
    PutGroupState(groupId []byte, epoch uint64, state []byte) error
    GetGroupState(groupId []byte, epoch uint64) ([]byte, error)
    DeleteGroupStateBefore(groupId []byte, epoch uint64) error
    PutPrivateKey(pub []byte, priv []byte) error
    GetPrivateKey(pub []byte) ([]byte, error)
    DeletePrivateKey(pub []byte) error
    PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error
    TakeKeyPackage(ref []byte) (kp, initPriv, encPriv []byte, err error)
}                                                                             // → p8, connect/message

type GroupConfig struct {
    Suite        CipherSuite
    GroupId      []byte
    Extensions   []Extension
    RequiredCaps RequiredCapabilities
    Crypto       CryptoProvider
    Store        StateStore
    Profile      *Profile
    LeafKeys     LeafKeysExtension
}                                                                             // → p8
type Member struct {
    LeafIndex    LeafIndex
    IdentityPub  []byte
    SignatureKey SignaturePublicKey
    LeafKeys     *LeafKeysExtension
    Role         Role
}                                                                             // → p8
type EpochSecretName uint8
const (
    EpochSecretSenderData EpochSecretName = iota + 1
    EpochSecretEncryption
)                                                                             // → p8
type Group struct{ /* stateLock-guarded, not safe for concurrent use */ }     // → p8, connect/message

func NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error)  // → p8
func LoadGroup(cfg *GroupConfig, epoch uint64, signer SignaturePrivateKey) (*Group, error)
func (self *Group) GroupId() []byte                                           // → p8
func (self *Group) Epoch() uint64                                             // → p8
func (self *Group) OwnLeafIndex() LeafIndex                                   // → p8
func (self *Group) OwnLeafNodeCopy() *LeafNode                                // → p8  [GAP → p7]
func (self *Group) Members() []Member                                         // → p8
func (self *Group) MemberAt(leafIndex LeafIndex) (Member, bool)               // → p8
func (self *Group) EpochAuthenticator() []byte                                // → p8
func (self *Group) Export(label string, context []byte, length int) ([]byte, error) // → p8
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error)          // → p8
func (self *Group) RatchetTree() ([]byte, error)                              // → p8
func (self *Group) GroupContext() ([]byte, error)                             // → p6,p8
func (self *Group) GroupPolicy() (*GroupPolicyExtension, error)
func (self *Group) Close() error                                              // → p8

func (self *Group) ProposeAdd(keyPackage []byte) (proposalMessage []byte, err error)  // → p8
func (self *Group) ProposeRemove(leaf LeafIndex) ([]byte, error)              // → p8
func (self *Group) ProposeUpdate() ([]byte, error)                            // → p8
func (self *Group) ProposeGroupContextExtensions(exts []Extension) ([]byte, error)    // → p8

type CommitOptions struct {
    Force          bool          // build a path even when the list does not require one
    ExtraProposals []Proposal    // by-value, appended after the by-reference ones

    // test seams, unexported — p8's tests are in package mls. They are fields of
    // CommitOptions, NOT of Commit: a test flag must never touch a wire type.
    skipValidation                        bool
    dropConfirmationTag                   bool
    confirmationTagOverPreCommitTranscript bool
}                                                                             // → p8
type CommitResult struct {
    Commit      []byte   // MLSMessage(PrivateMessage) carrying the Commit
    Welcome     []byte   // MLSMessage(Welcome), nil when the commit adds nobody
    RatchetTree []byte   // the post-commit tree, for out-of-band Welcome delivery
}                                                                             // → p8
type StagedCommit struct{ /* opaque */ }                                      // → p8
func (self *StagedCommit) Epoch() uint64
func (self *StagedCommit) Committer() LeafIndex
func (self *StagedCommit) AddedLeaves() []LeafIndex
func (self *StagedCommit) RemovedLeaves() []LeafIndex
func (self *StagedCommit) UpdatedLeaves() []LeafIndex
func (self *StagedCommit) RemovesSelf() bool
func (self *StagedCommit) GroupContextExtensions() []Extension
func (self *StagedCommit) EpochAuthenticator() []byte

func (self *Group) Commit(byReference [][]byte, byValue []Proposal, opts *CommitOptions) (*CommitResult, error) // → p8

type ProcessedKind uint8
const (
    ProcessedApplication ProcessedKind = 1
    ProcessedProposal    ProcessedKind = 2
    ProcessedCommit      ProcessedKind = 3
)
type ApplicationMessage struct {
    SenderLeaf        LeafIndex
    AuthenticatedData []byte
    Plaintext         []byte
}
type Processed struct {
    Kind        ProcessedKind
    Sender      Sender
    Application *ApplicationMessage
    Proposal    *Proposal
    Commit      *StagedCommit
}                                                                             // → p8
func (self *Group) ProcessMessage(message []byte) (*Processed, error)         // → p8
func (self *Group) ApplyCommit(processed *Processed) error                    // → p8
func (self *Group) MergePendingCommit() error                                 // → p8
func (self *Group) ClearPendingCommit()                                       // → p8  [GAP → p7]
func (self *Group) Protect(aad, plaintext []byte) ([]byte, error)             // → p8
func (self *Group) Unprotect(privateMessage []byte) (*ApplicationMessage, error) // → p8

const MaxGroupMembers = 500
const MaxDeviceLeavesPerIdentity = 10
func CheckGroupSize(tree *RatchetTree) error
func CheckDeviceCount(tree *RatchetTree) error
func CheckRemovalAuthority(policy *GroupPolicyExtension, tree *RatchetTree,
    list *ProposalList, committer LeafIndex) error
```

`PastEpochWindow` is declared **once**, in p4 (§5.2); p7 references it. `Commit.DropConfirmationTag`
and `Commit.ConfirmationTagOverPreCommitTranscript` (p8's asks) are moved onto `CommitOptions` as
unexported fields — adding a test flag to the `Commit` wire struct would change what
`syntax.Marshal(commit)` emits.

`stateKey` in p7's test store is `string(groupId) + "/" + strconv.FormatUint(epoch, 10)`, not
`string(rune(epoch))`: epochs in 0xD800–0xDFFF or above 0x10FFFF all convert to U+FFFD and collide,
and that fixture backs p8's `TestValSem400_PastEpochBound`, where a silent collision reads as a
correct deletion.

### 8.4 Welcome generation and join

```go
func (self *GroupInfo) Sign(crypto CryptoProvider, priv SignaturePrivateKey) error
func (self *GroupInfo) Verify(crypto CryptoProvider, tree *RatchetTree) error
type WelcomeJoiner struct {
    KeyPackage KeyPackage
    LeafIndex  LeafIndex
    PathSecret []byte   // nil when the commit carried no path
}
func BuildWelcome(crypto CryptoProvider, suite CipherSuite, info *GroupInfo, joinerSecret []byte,
    welcomeSecret []byte, joiners []WelcomeJoiner) (*Welcome, error)
type JoinKeyMaterial struct {
    KeyPackage     KeyPackage
    InitPrivate    HpkePrivateKey
    EncryptPrivate HpkePrivateKey
    SignPrivate    SignaturePrivateKey
}                                                                             // → p8
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte,
    keys *JoinKeyMaterial) (*Group, error)                                    // → p8

type SuccessionCountersignature struct {
    AdminMemberId []byte
    Signature     []byte
}
type SuccessionClaim struct {
    SuccessorMemberId []byte
    NominatedAtMs     uint64
    Countersignatures []SuccessionCountersignature
}
func SuccessionQuorum(adminCount int) int
func SignSuccessionCountersignature(crypto CryptoProvider, priv SignaturePrivateKey,
    adminMemberId, groupId []byte, epoch uint64, successorMemberId []byte,
    nominatedAtMs uint64) (SuccessionCountersignature, error)
func ValidateSuccession(crypto CryptoProvider, groupId []byte, epoch uint64,
    prePolicy *GroupPolicyExtension, nomination *OwnerSuccessorExtension,
    committerMemberId []byte, claim *SuccessionClaim, lastOwnerRecordMs uint64, nowMs uint64) error
func (self *Group) SetSuccessionClaim(claim *SuccessionClaim, lastOwnerRecordMs uint64)
```

`BuildWelcome`/`JoinFromWelcome` call p5's `SealWithLabel`/`OpenWithLabel` (§6.7), not a
`*HPKECiphertext`-shaped `EncryptWithLabel` that never existed.

### 8.5 p7's error set — lifecycle only

```go
var ErrGroupSizeExceeded, ErrDeviceLimitExceeded, ErrAdminRemovedByNonOwner error
var ErrSuccessionDisabled, ErrSuccessionNotNominee, ErrSuccessionQuorum error
var ErrSuccessionFloor, ErrSuccessionFloorTooShort error
var ErrNoGroupPolicy, ErrMalformedExtension error
var ErrDuplicateRoleEntry, ErrRolesNotCanonical, ErrNoOwner, ErrMultipleOwners error
var ErrWelcomeNoMatchingKeyPackage, ErrWelcomeGroupInfoDecrypt error
var ErrWelcomeGroupInfoSignature, ErrWelcomeTreeHashMismatch error
var ErrWelcomeLeafNotFound, ErrWelcomeSuiteMismatch error
var ErrGroupIdInUse, ErrPendingCommitExists, ErrNoPendingCommit error
var ErrEpochStale, ErrRemovedFromGroup error                                  // → p8
```

---

## 9. `package mls` — validation, profile, harness — p8

### 9.1 The ValSem catalogue

```go
type ValSemCode uint16                                                        // → p5,p6,p7
type ValidationError struct {
    Code   ValSemCode
    Reason string
    Detail error
}
func (self *ValidationError) Error() string
func (self *ValidationError) Unwrap() error
func (self *ValidationError) Is(target error) bool
func ValSem(code ValSemCode, detail error) error                              // → p4,p5,p6,p7
func CodeOf(err error) (ValSemCode, bool)
func ValSemCatalogue() []ValSemCode          // sorted, exactly 51 entries
func ReasonFor(code ValSemCode) string
```

Codes: `ValSem002`–`ValSem011`, `ValSem101`–`ValSem113`, `ValSem200`–`ValSem209`, `ValSem240`–`242`,
`ValSem244`–`246`, `ValSem300`, `ValSem400`–`ValSem403`, `ValSemErrata8745`, `ValSemErrata8815`.

Sentinels — **the single declaration site for every one of these names**:

```go
// framing, ValSem002-011 — moved here from p6 Task 1
var ErrWrongGroupId, ErrWrongEpoch, ErrBlankSenderLeaf error                  // → p6,p7
var ErrApplicationMustBeCiphertext, ErrDecryptFailed error                    // → p6,p7
var ErrMissingMembershipTag, ErrBadMembershipTag error                        // → p6
var ErrMissingConfirmationTag, ErrBadSignature, ErrNonZeroPadding error       // → p6,p7

// proposals and commits, ValSem101-113 / 200-209 / 300
var ErrDuplicateSignatureKey, ErrDuplicateInitKey, ErrDuplicateEncryptionKey error   // → p7
var ErrInitEqualsEncryptionKey, ErrSuiteMismatch, ErrMissingRequiredCapability error // → p7
var ErrDuplicateRemove, ErrRemoveNonMember, ErrSelfUpdateInCommit error       // → p7
var ErrUpdateSenderNotMember, ErrUnsupportedProposalType error                // → p7
var ErrSelfRemoveInCommit, ErrMissingPath, ErrPathLength, ErrPathDecrypt error // → p5,p7
var ErrPathKeyMismatch, ErrBadConfirmationTag, ErrMultipleGCE error           // → p5,p7
var ErrUnsupportedGroupExtension, ErrTrailingBlankNodes error                 // → p5,p7

// past-epoch window and PSK, ValSem400-403 — moved here from p4
var ErrPastEpochRetained, ErrPskNonceLength, ErrPskType, ErrDuplicatePsk error // → p4,p7

// the v1 narrow profile — five names the 46-sentinel list omitted        [GAP → p8]
var ErrProfileExternalCommit, ErrProfileExternalSender, ErrProfilePsk error   // → p6,p7
var ErrProfileReInit, ErrProfileBranch error                                  // → p6,p7
var ErrProfileCredentialType, ErrProfileCiphersuite error                     // → p5,p7
```

p8's list was "the 46 sentinels" and five profile refusals consumed by p5, p6 and p7 were absent —
including `ErrProfileCredentialType`, which is the only thing enforcing BasicCredential-only at
parse. The list is 51 and the Task 3 closure test's expected count changes with it.
`ErrProfilePSK` (p7) → `ErrProfilePsk`.

### 9.2 Vector registry

```go
type VectorFamily struct {
    Number   int                                       // 1..16, the Spec A §4.2.1 row
    Name     string
    File     string                                    // under testdata/vectors
    Slice    string                                    // "A1".."A4"
    Verify   func(t *testing.T, raw json.RawMessage)   // nil == not yet implemented
    Generate func(t *testing.T) json.RawMessage        // nil == format has no generate direction
}
func RegisterVectorFamily(family VectorFamily)                                // → p1,p2,p3,p4,p5,p6,p7
func LoadVectorFile(t *testing.T, file string) []json.RawMessage              // → p2,p3,p4,p5,p6,p7
func MustHex(t *testing.T, s string) []byte                                   // → p2,p3,p4,p5,p6,p7
func HexOf(b []byte) string                                                   // → p2,p4,p5,p6,p7
```

Every family-owning task calls `RegisterVectorFamily` from an `init()` in its own `*_kat_test.go`
and deletes its number from `expectedPendingFamilies` in the same commit: p3 T7 (family 1), p2 T17
(2), p4 T16/17/20/25 (3, 5, 6, 7), p6 T16/17 (4, 12), p5 T24/25 (10, 11), p7 (8, 9, 13, 14, 15),
p8 T8 (16). Without this, `TestVectorFamiliesVerify` runs one family and Gate 1 is green with 15 of
16 never executed.

`ksHex`/`ksLoadVectors` (p4), `hexBytes` (p6) and `mustHex` (p7) are deleted — three parallel hex
decoders over one corpus is how two of them end up disagreeing about the empty string. p4's
`ksImplementedSuite` survives as `implementedSuite`.

**Family 16 is implemented once, in p1**, in `package syntax` against the `Reader.ReadVarint` /
`Writer.WriteVarint` methods it actually ships. p1 exports
`func VerifyDeserializationVector(t *testing.T, raw json.RawMessage)` and p8 Task 8 becomes a
three-line registry shim that calls it. p8's own runner — written against free functions that do
not exist — is deleted, along with its duplicate vendoring step.

**Vendoring and pins.** p8 Task 6 is the single vendoring task for all sixteen mlswg files plus
`testdata/vectors/VECTORS.sha256`; p1, p3, p5 and p7 keep only their runners. The one pin file is
`connect/mls/interop/PINS.md` (Spec A §4.2.4) with machine-readable `mlswg=<sha>` and
`openmls=<sha>` lines, which is what p6 and p7 grep for. `connect/mls/PINS.md` and
`connect/mls/testdata/vectors/PINS.md` are both deleted. p2's separately-sourced
`hpke-rfc9180-x25519.json` and `xwing-draft10.json` move to `testdata/vectors/rfc/` so the
sixteen-file assertion over `testdata/vectors/*.json` stays exact.

### 9.3 Profile — **gap, assigned to p8**

```go
type Profile struct {
    AllowPublicMessage bool     // false in DefaultProfile; the passive-client vectors set it
    /* unexported allow-sets */
}                                                                             // → p7
func DefaultProfile() *Profile                                                // → p7
func (self *Profile) CheckVersion(v ProtocolVersion) error                    // → p7
func (self *Profile) CheckCiphersuiteForCreate(s CipherSuite) error           // → p7
func (self *Profile) CheckProposalType(t ProposalType) error                  // → p6,p7
func (self *Profile) CheckCredentialType(t CredentialType) error              // → p5,p7
func (self *Profile) CheckGroupExtension(t ExtensionType) error               // → p7
func (self *Profile) CheckLeafExtension(t ExtensionType) error                // → p7
func (self *Profile) CheckWireFormat(w WireFormat) error                      // → p7
```

**`profile.go` was attributed circularly and created by nobody.** p2, p3, p4 and p7 all say the
validation plan owns it; p8 lists `Profile` in its *consumed* block attributed to p7; p8's file
structure has no `profile.go` row. Meanwhile `GroupConfig.Profile` is required by `NewGroup`,
`DefaultProfile()` is called at eight p7 sites and two p8 sites, and the v1 refusals behind Gate 3's
240–246 and 401–403 rows all run through it. Group creation — the entry point of the whole slice —
could not be written.

**Assigned to p8**, which already owns `errors.go` (the `ErrProfile*` values the checks return) and
which Spec A §2.2 names alongside `profile.go`. It is a Phase A (wave 1) task with
`profile_test.go` and `TestProfileIsClosed` asserting the allow-set tables equal Spec A §3.1/§3.2
exactly. p7 Task 23 sets `AllowPublicMessage` through a `vectorProfile()` helper and **calls it** —
as written it defines the helper and then passes `DefaultProfile()`, so families 13–15 fail.

### 9.4 Codec table — **moves to a non-test file**

```go
// connect/mls/codec_table.go — NOT _test.go
type CodecKind uint8
const (
    KindExtension  CodecKind = 1
    KindKeyPackage CodecKind = 2
    KindMlsMessage CodecKind = 3
    KindProposal   CodecKind = 4
    KindWelcome    CodecKind = 5
)
type CodecPair struct {
    Name   string
    Decode func(b []byte) (any, error)
    Encode func(v any) ([]byte, error)
}
func CodecFor(kind CodecKind) (CodecPair, bool)
func CodecKinds() []CodecKind
```

The ten `Parse*`/`Encode*` names p8's table asked other plans for — `ParseExtension`,
`EncodeExtension`, `ParseKeyPackage`, `EncodeKeyPackage`, `EncodeMLSMessage`, `ParseProposal`,
`EncodeProposal`, `ParseWelcome`, `EncodeWelcome` — **are not added anywhere.** Under **C1** every
one of them is one line inside the table:

```go
KindWelcome: {Name: "welcome",
    Decode: func(b []byte) (any, error) { v := &Welcome{}; return v, syntax.Unmarshal(b, v) },
    Encode: func(v any) ([]byte, error) { return syntax.Marshal(v.(*Welcome)) }},
```

That keeps the naming contract inside one plan and removes ten cross-plan asks. `KindMlsMessage`
uses p6's existing `ParseMLSMessage`/`MarshalMLSMessage`.

The declarations move out of `codec_table_test.go` into `codec_table.go` because the Go oracle
client and the separate `connect/mls/interop/` module cannot see symbols in a `_test.go` file — the
shared kind-id contract that stops Go and Rust drifting about which decoder a divergence concerns
does not otherwise exist across that boundary. Only `TestCodecTableIsClosed` and
`TestCodecTableRejectsEmptyInput` stay in the test file.

### 9.5 Test-only surface

```go
type forge struct{ /* unexported */ }
func newForge(t *testing.T, members int) *forge
func (self *forge) g(i int) *Group
func (self *forge) signer(i int) SignaturePrivateKey
func (self *forge) newKeyPackage(t *testing.T) (kp *KeyPackage, initPriv HpkePrivateKey, encPriv HpkePrivateKey)
func (self *forge) content(i int, contentType ContentType, body []byte) *FramedContent
func (self *forge) contentFrom(sender Sender, contentType ContentType, body []byte) *FramedContent
func (self *forge) sealPrivate(i int, c *FramedContent, mutate func(*FramedContentAuthData)) []byte
func (self *forge) sealPublic(i int, c *FramedContent, mutate func(*FramedContentAuthData)) []byte
func (self *forge) proposalBytes(i int, p Proposal) []byte
func (self *forge) commitBytes(i int, byValue []Proposal, byRef []ProposalRef, mutate func(*Commit, *UpdatePath)) []byte
func (self *forge) deliver(to int, raw []byte) error
func (self *forge) store(i int) *memStore
func requireValSem(t *testing.T, err error, want ValSemCode)

type memStore struct{ /* unexported; implements StateStore */ }
func newMemStore() *memStore
func (self *memStore) EpochsHeld(groupId []byte) []uint64
func (self *memStore) PrivateKeyCount() int

type oracleResult struct {
    Accept       bool   `json:"accept"`
    Reserialized []byte `json:"reserialized"`
    Error        string `json:"error"`
}
func newOracle(t *testing.T) *oracle    // t.Skip when URMSG_MLS_ORACLE is unset
func (self *oracle) decode(kind CodecKind, input []byte) (oracleResult, error)
func (self *oracle) close() error
```

**p8 owns all `TestValSemNNN_<slug>` names exclusively** (Spec A §4.3). p5 renames its four
(`TestValSem202_PathLength`, `_203`, `_204`, `TestValSem300_TrailingBlankNodes`) to
behaviour-named tests per its Amendment A.4 — which its task bodies still contradict — and p6
renames `TestValSem005_ApplicationMustBeCiphertext` to
`TestPublicMessageRefusesApplicationContent`.

**p8 owns all nine Gate-4 fuzz targets.** p6 Task 18's `FuzzMlsMessageDecode`,
`FuzzMlsMessageDecodeBytes`, `FuzzProposalDecode` and `FuzzProposalDecodeBytes` are deleted; p6
keeps `TestFramingUsesConstantTimeComparison` and contributes seed corpus only.
`TestFuzzTargetsCoverEveryKind` parses the file with `go/ast` rather than counting a hand-written
literal slice, so deleting a target turns it red.

p8's Phase A splits: Tasks 1–9 and 13 stay wave 1; Tasks 10 (`memStore`, implements p7's
`StateStore`), 11 (codec table) and 12 (fuzz targets) move to a Phase A′ marked wave 4, so
`fuzz-short` is not red from wave 1 to wave 4.

---

## 10. `package message` — X-Wing — p2

```go
const (
    XwingSeedSize            = 32
    XwingExpandedSize        = 96
    XwingPublicKeySize       = 1216      // == mls.XwingPublicKeyLen; asserted at compile time
    XwingCiphertextSize      = 1120
    XwingSharedSize          = 32
    XwingMlkemSeedSize       = 64
    XwingMlkemPublicKeySize  = 1184
    XwingMlkemCiphertextSize = 1088
    XwingX25519KeySize       = 32
    XwingAlgId uint16 = 0x0014
)
type XwingPrivateKey struct{ /* the 32-byte seed and the expanded halves */ }
type XwingPublicKey struct{}
func XwingKeyGenFromSeed(seed []byte) (*XwingPrivateKey, error)
func XwingGenerateKey(random io.Reader) (*XwingPrivateKey, error)
func (self *XwingPrivateKey) Public() *XwingPublicKey
func (self *XwingPrivateKey) Seed() []byte
func (self *XwingPublicKey) Bytes() []byte
func ParseXwingPublicKey(b []byte) (*XwingPublicKey, error)
func XwingEncapsulate(random io.Reader, pub *XwingPublicKey) (ct []byte, ss []byte, err error)
func XwingDecapsulate(priv *XwingPrivateKey, ct []byte) (ss []byte, err error)
var (
    ErrXwingBadSeedSize       = errors.New("message: xwing seed must be 32 bytes")
    ErrXwingBadPublicKeySize  = errors.New("message: xwing public key must be 1216 bytes")
    ErrXwingBadCiphertextSize = errors.New("message: xwing ciphertext must be 1120 bytes")
    ErrXwingInvalidPoint      = errors.New("message: xwing x25519 produced an invalid shared secret")
)
```

Consumed by slice 2 (`connect/message`) only. `mls` never imports `message`; §6.8 duplicates the
1216 constant deliberately, one direction only.

---

## 11. Two plans, one implementation — who keeps it

| Thing | Declared by | **Keeps it** | Why |
|---|---|---|---|
| `ProtocolVersion`, `ProtocolVersionMls10` | p5 T3, p6 T1 | **p5** | registry enum; `Capabilities.Versions` needs it in wave 2 |
| `ProposalType` + its 8 constants | p5 T3, p6 T12, p7 T5 | **p5** | same; three declarations in one package is a compile error |
| `ExtensionType` constants | p5 T3, p7 T2–T4 | **p5** | registry enum in one file |
| `Proposal`, `ProposalOrRef`, `Commit` + codecs | p6 T12–13, p7 T5/6/9 | **p6** | family-12 `messages` needs all seven arms; refusal is a *profile* decision, not a codec one |
| `GroupInfo`, `GroupInfoTBS`, `PathSecret`, `GroupSecrets`, `EncryptedGroupSecrets`, `Welcome` codecs | p7 T13–14 | **p6** | p6's wave-3 `MLSMessage` names them by direct type; one Go package cannot compile otherwise |
| `KeyPackage` | nobody | **p5** | see §6.5 |
| `Profile`, `DefaultProfile`, 7 `Check*` | nobody | **p8** | see §9.3 |
| `LeafKeysExtension`, `AlgIdXwing`, 1216 | p5 T4, p7 T2 | **p5** | `LeafNode.Validate` range-checks it; p7 keeps `LeafKeysOf` only |
| `Credential`, `UnmarshalCredential` | attributed to p1, produced by p5 A.3 | **p5** | p1 produces no MLS types |
| `SenderDataKeyNonce` §6.3.2 | p4 T24, p6 T9 | **p4** | `secret-tree.json` is its only vector coverage; the untested copy was the one the encrypt path called |
| `PastEpochWindow` | p4, p7 | **p4** | key-schedule constant |
| `ErrBadSignature` | p2 T1, p6 T1, p8 T2 | **p8** | it is ValSem010; p2's becomes `ErrCryptoBadSignature` |
| 10 framing ValSem sentinels | p6 T1, p8 T2 | **p8** | ValSem002–011 |
| `ErrPskNonceLength`/`ErrPskType`/`ErrDuplicatePsk` | p4, p8 | **p8** | ValSem401–403 |
| family 16 runner | p1 T7, p8 T8 | **p1** | p8's copy is written against free functions that do not exist |
| `MustHex`/`HexOf`/`LoadVectorFile` | p4, p6, p7, p8 | **p8** | wave 1, lands first |
| 4 `Fuzz*Decode` targets | p6 T18, p8 T12 | **p8** | it has the codec table and the oracle hook |
| 5 `TestValSemNNN_*` names | p5, p6, p8 | **p8** | Spec A §4.3 fixes the names and the files |
| `TestVectorFilesArePinned` / PINS.md | p1, p2, p3, p5, p7, p8 | **p8 T6**, pin file at `interop/PINS.md` | three paths, three formats, two greps that match none of them |
| `go.mod` edit | p1 T1, p2 T1 | **p1** | `go 1.26.3` + `toolchain go1.26.5` |

---

## 12. Gaps — symbols a consumer invented that nothing produced

A gap is worse than a mismatch: nothing fails until integration. Each is assigned an owner here.

| Symbol | Wanted by | **Owner** |
|---|---|---|
| `KeyPackage` + `NewKeyPackage` + `Ref` + `Validate` + codec | p5,p6,p7,p8 | **p5** §6.5 |
| `Profile`, `DefaultProfile`, 7 `Check*`, `AllowPublicMessage` | p7,p8 | **p8** §9.3 |
| `NewKeyScheduleFromEpochSecret` | p7 (`NewGroup`) | **p4** §5.2 |
| `EmptyPskSecret` | p7 | **p4** §5.2 |
| `NextMessageKey`/`MessageKey`/`EraseMessageKey` on `*SecretTree` | p6 | **p4** §5.5 |
| `NewLeafNode` | p7 | **p5** §6.4 |
| `(*Capabilities).Supports(rc)` | p7 | **p5** §6.3 |
| `BasicCredential(identity)` | p7,p8 | **p5** §6.3 |
| `NonBlankLeaves`, `EncryptionKeyInUse`, `HasTrailingBlankNodes`, `OptionalNode` | p7,p8 | **p5** §6.6 |
| `SealWithLabel`/`OpenWithLabel` (HpkeCiphertext-shaped) | p7 | **p5** §6.7 |
| `NewCryptoProviderWithRandom` | p8 (the forge) | **p2** §3.2 |
| `(*AuthenticatedContent).ProposalRef(crypto)` | p7 | **p6** §7.2 |
| `sealFramedContentForTest`, `sealFramedContentWithPaddingForTest` | p8 (ValSem002–011) | **p6** §7.3 |
| `(*Group).ClearPendingCommit`, `(*Group).OwnLeafNodeCopy` | p8 | **p7** §8.3 |
| `CommitOptions.skipValidation` / `dropConfirmationTag` / `confirmationTagOverPreCommitTranscript` | p8 | **p7** §8.3 |
| `CheckErrata8745`, `CheckErrata8815` | p8 (criterion 3) | **p7** §8.2 |
| `ValSem203PathDecrypt` (hole in p7's 200-series) | — | **p7** §8.2 |
| 5 `ErrProfile*` sentinels | p5,p6,p7 | **p8** §9.1 |
| `syntax.VerifyDeserializationVector` (family 16 shim) | p8 | **p1** §9.2 |
| mlswg `interop/test-runner/` + its 8 config JSONs, `cmd/merge-runner-output` | Gate 2 | **p8**, new task 25a |
| `interop/cmd/seedgen` + committed `testdata/corpus/` | Gate 4 | **p8**, new task |

Four asks are **refused** rather than assigned, with the substitute named:
`FramedContentAuthData.MembershipTag` → use `PublicMessage.MembershipTag`;
`FramedContent.RawProposal` → use `Proposal.UnknownType`/`UnknownBody`;
`RatchetTreeExtension` → `FindExtension(exts, ExtensionTypeRatchetTree)` + `UnmarshalRatchetTree`;
`(*Reader).Rest()` → `r.ReadRaw(r.Remaining())`.

---

## 13. Where a producer was overridden

| # | Symbol | Producer had | Registry says | Why |
|---|---|---|---|---|
| O-1 | `syntax.Marshaler` | `MarshalMLS(w *Writer)` | `MarshalMLS(w *Writer) error` | p5, p6, p7 independently needed to return a *semantic* refusal (`ErrProfileCredentialType`, `ErrContentArmMismatch`) that the sticky Writer had no exported way to carry; silently dropping an encoder refusal produces wrong signed bytes |
| O-2 | `syntax.WriteVector` / `WriteOptional` | callbacks return nothing | callbacks return `error` | consequence of O-1: a nested encoder must be able to propagate the same refusal |
| O-3 | p5 `MarshalExtensions([]Extension) ([]byte, error)` / `UnmarshalExtensions(r)` | asymmetric byte/reader pair | `WriteExtensions(w, exts) error` / `ReadExtensions(r) ([]Extension, error)` | p4 and p6 both independently asked for the writer form; `extensions<V>` is always an inline field, and the byte-returning half forces a hand-written `WriteOpaque` at every site — the exact byte-vs-element-count error the codec exists to prevent |
| O-4 | p4 `NewSecretTree(..., leafCount LeafIndex, ...)` | `LeafIndex` | `LeafCount` | type correction against p3's normative block (C3); an index is not a count |
| O-5 | p4 `GroupContext.Marshal()` / `ParseGroupContext`, p4 `PreSharedKeyId.Marshal()` / `ParsePreSharedKeyId`, p5 `Marshal()` + `UnmarshalX(r)` free constructors, p7 `Encode()`/`Parse*` | per-type byte wrappers | `syntax.Marshal` / `syntax.Unmarshal` only (C1) | four codec conventions in one package meant no type satisfied `syntax.Codec`, so `CheckRoundTrip` — the whole of Gate 4 property 2 — had no instantiation path |
| O-6 | p5 `RatchetTree.LeafWidth() uint32` | `uint32` | `LeafCount` | same as O-4 |
| O-7 | p5 `LeafNode.Validate(ctx)` kept, but p5's `UnmarshalRatchetTree` gains the limit | — | `UnmarshalLimit(bs, v, MaxRatchetTreeLength)` | p1 names the tree paths as the ones that must not use the 1 MiB default, and no plan wired it |
| O-8 | p2 `Suites()` retained over p8's `RegisteredSuites()` | — | `Suites()` + `IsRegisteredSuite()` | producer wins; the pair is sharper than a third name |
| O-9 | p2 `ErrBadSignature` | `ErrBadSignature` | `ErrCryptoBadSignature` | three declarations in one package; p8's is ValSem010 and Gate 3 asserts it |
| O-10 | p7's whole framing/TreeKEM/key-schedule consumption block | ~40 invented names | p4/p5/p6's actual names | p7 itself states "that plan wins"; this file does the rewrite it never did |

Two producer decisions were **upheld against a numerical majority of consumers**, which is worth
recording because the majority argument was available and rejected:

- **`CipherSuiteX25519ChaCha20Sha256Ed25519`** (p2) over the five-plan
  `...ChaCha20SHA256Ed25519`. Plans written in parallel with no coordination are not five
  independent votes; `CODESTYLE.md` is a real constraint and it decides.
- **`groupContext []byte`** (p6) over p7's `*GroupContext`. p6 documented the reason at length: the
  GroupContext is inlined into `FramedContentTBS` with no length prefix, and taking bytes makes
  that impossible to get wrong while removing a cross-plan type dependency from the hottest
  preimage in the system.

---

## 14. Execution order this implies

1. **wave 1** — p1 (syntax), p3 (tree math), p2 (crypto), p8 Phase A tasks 1–9 and 13
   (`errors.go`, **`profile.go`**, catalogue, vendoring+`VECTORS.sha256`+`interop/PINS.md`,
   registry, family-16 shim, CI).
2. **wave 2** — **p5 Task 3 first** (registry enums + `Extension` + `WriteExtensions`/`ReadExtensions`),
   then p4 Task 3 onward and the rest of p5. `KeyPackage` lands here.
3. **wave 3** — p6, including the `Proposal`/`Commit` and `Welcome`/`GroupInfo` codecs moved in from
   p7, and the two `*ForTest` seams.
4. **wave 4** — p7, then p8 Phase A′ (memStore, codec table, fuzz targets) and Phases B–D.

The two cross-wave dependencies that were wave-order violations — p6 (wave 3) naming `Welcome`,
`GroupInfo` and `KeyPackage` (wave 4), and p8 Phase A (wave 1) consuming `StateStore` and the codec
pairs (waves 3–4) — are both resolved by the ownership moves above rather than by relabelling waves.
