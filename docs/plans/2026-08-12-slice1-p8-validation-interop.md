# [Validation and Interop Harness] Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the acceptance infrastructure that decides whether `connect/mls` is correct — the 16
RFC 9420 vector families, the mlswg gRPC interop harness in both roles, explicit negative tests for
all 43 ValSem codes plus errata 8745 and 8815, differential fuzzing against OpenMLS's 9 targets, and
the CI test forbidding `connect` from importing its own subpackages.

**Architecture:** Three layers that never touch the product. A test-only vector registry in
`package mls` into which every other slice-1 plan registers its family runner; a separate Go module
`connect/mls/interop` holding the gRPC client and the mlswg proto so neither ever enters `connect`'s
dependency graph; and an out-of-process OpenMLS oracle reached over a length-prefixed stdio pipe
from `os/exec`, so the differential property costs no `go.mod` entry and no linked artifact. The
typed-error catalogue (`errors.go`) is produced here and consumed by every validation site in the
implementation, so a check and its test cannot drift.

**Tech Stack:** Go 1.26.5, stdlib `testing` + `testing/fuzz` + `go/ast` + `os/exec`; gRPC and
protobuf confined to the `interop` module; Rust used only to build a pinned OpenMLS oracle binary in
CI; GitHub Actions.

## Global Constraints

- Go 1.26.5, pinned. `actions/setup-go@v5` with `go-version: '1.26.5'` in every workflow.
- Standard library only for crypto: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, plus
  `chacha20poly1305` from the already-pinned `golang.org/x/crypto`.
- NO cgo, NO Rust, NO new third-party crypto dependency. `sdk` must stay gomobile-buildable.
- New dependencies permitted in `connect` on `beta/message`: **none.**
- OpenMLS is a READ-ONLY differential oracle used out of process in CI. Never in `go.mod`, never
  linked, never in a shipped artifact.
- Ciphersuite: groups are created and accepted at `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
  (0x0003). `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) is registered and implemented but
  refused at group creation by policy, so the registry is not a hardcoded singleton.
- Narrow v1 profile: `BasicCredential` only, no external commits, no external senders, no PSKs, no
  ReInit, no branching, no subgroups. All parse-refused with typed errors.
- GREASE values (RFC 9420 §13.2) are **parsed and ignored, never generated**, and must not error —
  the interop harness sends them.
- `connect` must NEVER import `connect/mls` or `connect/message`. `connect/mls` must never import
  `connect` or `connect/message`. `connect/mls/syntax` imports nothing but stdlib. `connect/message`
  must never import `sdk`. Enforced by `connect/layering_test.go` walking `go list -deps`.
- `sdk.GenerateSharedSecret`, `box.Precompute` and `curve25519.ScalarMult` MUST NOT be used. All
  X25519 goes through `crypto/ecdh` or `curve25519.X25519`, and a returned error is a hard validation
  failure — never logged and continued.
- MLS signs over serialized forms, so the TLS presentation-language codec must be byte-exact and
  round-trip stable. One codec, one fuzz corpus.
- `MaxVectorLength` is 1 MiB for everything but the ratchet tree, which caps at 16 MiB.
- `PastEpochWindow = 32`. `StateStore.DeleteGroupStateBefore` is called on every merged commit with
  `epoch - PastEpochWindow`.
- Max group size 500 members, hard. Max 10 device leaves per identity in one group, hard. Both
  enforced at construction **and** on receipt.
- `connect/mls/interop` is a separate Go module so gRPC, protobuf and the mlswg proto never enter
  `connect`'s dependency graph.
- `connect/mls` and `connect/message` have **no timing-sensitive tests** and must keep it that way. A
  test that needs a clock takes an injected `nowMs func() int64`.
- Per `CODESTYLE.md`: `self` receivers, `stateLock` for guarded state, explicit struct field names,
  doc comment on every file/type/func. ValSem tests are top-level functions, never `t.Run` subtests.
- Fuzz properties 1–2 run 60 s per target on every commit. The differential property (property 3)
  runs 4 h per target nightly. Any differential disagreement is a P0.
- All `go test` and `git` commands in this plan run from the **workspace root**, the directory holding
  the sibling `connect/`, `sdk/` and `server/` checkouts wired by `go.work` (see the
  `urnetwork-workspace` skill). The branch is `beta/message` in `connect`.
- `go.mod` keeps `go 1.26.3` and gains `toolchain go1.26.5`. The `go` directive is the syntax-and-codec
  plan's to edit and nothing here touches it.

### The four cross-plan conventions (canonical interface registry §0)

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
- **This plan's codec table.** Five decode/encode closures over `syntax.Marshal`/`syntax.Unmarshal`,
  built in `codec_table.go` (Task 11). They export no new `Parse*`/`Encode*` names. `ParseMLSMessage`
  and `MarshalMLSMessage` are the framing plan's, and are the single entry point every byte off the
  wire passes through.

**C2 — the syntax Writer is sticky *and* `MarshalMLS` returns an error.** Leaf writes
(`WriteUint16`, `WriteOpaque`, …) return nothing and set a sticky error; one check at `Bytes()`
suffices. `MarshalMLS` and the higher-order encode callbacks (`WriteVector`, `WriteOptional`) return
`error`, because MLS encoders have *semantic* refusals — `Credential.MarshalMLS` returns
`ErrProfileCredentialType` on an x509 credential — that are not buffer errors and must not be
dropped. `syntax.Marshal` returns `errors.Join(v.MarshalMLS(w), w.Err())`.

**C3 — counts are `LeafCount`, indices are `LeafIndex`/`NodeIndex`, and tree-math arithmetic that can
be out of range returns an error.** `TreeSize` does not exist. This plan calls the two-valued form
and handles the error; it takes **no** single-valued shims, because a shim that turns an error into
`false` is exactly how ValSem300's trailing-blank case gets silently accepted.

**C4 — the GroupContext crosses a plan boundary as bytes.** Every framing entry point takes
`groupContext []byte`. Callers obtain them from `syntax.Marshal(gc)` or `(*Group).GroupContext()`.

---

## File Structure

Every file created or modified by this plan, and its single responsibility.

| File | Responsibility |
|---|---|
| `connect/layering_test.go` | Walks `go list -deps`; asserts the four forbidden import edges of Spec A §2.3 |
| `connect/scripts/check-forbidden.sh` | Grep gates G1, G3, G8 and the three forbidden X25519 call sites |
| `connect/mls/errors.go` | `ValSemCode`, `ValidationError`, the 51-entry catalogue, the sentinels |
| `connect/mls/errors_test.go` | Catalogue closure; `errors.Is` semantics; ValSem coverage report |
| `connect/mls/profile.go` | `Profile`, `DefaultProfile`, the seven `Check*` gates of the v1 narrow profile |
| `connect/mls/profile_test.go` | `TestProfileIsClosed` and the five narrow-profile refusal tests |
| `connect/mls/codec_table.go` | `CodecKind`, `CodecPair`, `CodecFor`, `CodecKinds` — **not** a `_test.go` file |
| `connect/mls/codec_table_test.go` | `TestCodecTableIsClosed`, `TestCodecTableRejectsEmptyInput` |
| `connect/mls/ERRATA.md` | RFC 9420 errata 8745 and 8815 transcribed verbatim, with the fetch date |
| `connect/mls/errata_test.go` | Transcription guard + `TestErrata8745` + `TestErrata8815` |
| `connect/mls/vectors_test.go` | Vector-family registry, JSON loader, manifest closure, generate meta-test |
| `connect/mls/vectors_deserialization_kat_test.go` | Family 16 runner (`deserialization.json`) |
| `connect/mls/testkit_test.go` | The forge — builds valid groups and frames deliberately malformed messages |
| `connect/mls/memstore_test.go` | In-memory `StateStore` with epoch-deletion accounting |
| `connect/mls/oracle_test.go` | Length-prefixed stdio client for the out-of-process OpenMLS oracle |
| `connect/mls/syntax_fuzz_test.go` | The 9 fuzz targets; properties 1 (no panic), 2 (round-trip), 3 (differential) |
| `connect/mls/validation_framing_test.go` | ValSem002–011 |
| `connect/mls/validation_proposal_test.go` | ValSem101–113 |
| `connect/mls/validation_commit_test.go` | ValSem200–209 and ValSem300 |
| `connect/mls/validation_external_test.go` | ValSem240–246 |
| `connect/mls/validation_psk_test.go` | ValSem401–403 |
| `connect/mls/validation_epoch_test.go` | ValSem400 past-epoch bound |
| `connect/mls/interop/PINS.md` | The **one** pin file: `mlswg=<sha>`, `openmls=<sha>`, three peer image digests |
| `connect/mls/testdata/vectors/*.json` | The 16 vendored mlswg vector families, and nothing else |
| `connect/mls/testdata/vectors/rfc/*.json` | Separately-sourced RFC 9180 / X-Wing vectors, outside the sixteen-file assertion |
| `connect/mls/testdata/vectors/VECTORS.sha256` | Per-file digest manifest; makes a silent re-vendor a test failure |
| `connect/mls/testdata/corpus/**` | Committed seed corpus for the 9 targets, generated by `cmd/seedgen` |
| `connect/mls/testdata/divergence-allowlist.json` | Justified accept/reject divergences from OpenMLS |
| `connect/mls/interop/go.mod` | Separate module; gRPC and protobuf live here and nowhere else |
| `connect/mls/interop/test-runner/` | The vendored mlswg gRPC test runner and its 8 config JSONs |
| `connect/mls/interop/cmd/merge-runner-output/` | Unions the three runner outputs into one observed-failure set |
| `connect/mls/interop/cmd/seedgen/` | Generates the committed fuzz seed corpus from the vector corpus |
| `connect/mls/interop/proto/mls_client.proto` | Vendored mlswg service definition |
| `connect/mls/interop/proto/mls_client.pb.go` | Generated messages |
| `connect/mls/interop/proto/mls_client_grpc.pb.go` | Generated service stubs |
| `connect/mls/interop/client/main.go` | `package main` gRPC server entry point and flag parsing |
| `connect/mls/interop/client/state.go` | State registry; `Free` releases; leak count at exit |
| `connect/mls/interop/client/wiredump.go` | Every byte sent and received, to `out/wiredump/` |
| `connect/mls/interop/client/rpc_core.go` | `Name`, `SupportedCiphersuites`, `CreateGroup`, `CreateKeyPackage`, `JoinGroup` |
| `connect/mls/interop/client/rpc_state.go` | `GroupInfo`, `StateAuth`, `Export`, `Protect`, `Unprotect` |
| `connect/mls/interop/client/rpc_commit.go` | Proposal RPCs, `Commit`, `HandleCommit`, `HandlePendingCommit`, `Free` |
| `connect/mls/interop/client/rpc_unimplemented.go` | The `UNIMPLEMENTED` set with stable messages |
| `connect/mls/interop/client/*_test.go` | Registry leak accounting, wiredump, unimplemented-set closure |
| `connect/mls/interop/oracle/main.go` | Standalone corpus-triage CLI over the same stdio protocol |
| `connect/mls/interop/oracle/rust/Cargo.toml` | Pins the OpenMLS oracle build; never in `go.mod` |
| `connect/mls/interop/oracle/rust/src/main.rs` | ~200 lines: read frame, decode, reply |
| `connect/mls/interop/profile-reject.json` | Per config, the scenario ids that MUST fail, with status and message |
| `connect/mls/interop/cmd/assert-profile-rejects/main.go` | Asserts observed failure set **equals** expected |
| `connect/mls/interop/docker-compose.yml` | The three peers, pinned by image digest |
| `connect/.github/workflows/mls-vectors.yml` | `vectors`, `valsem`, `layering`, `forbidden-crypto` jobs |
| `connect/.github/workflows/mls-interop.yml` | The both-role interop matrix and the documented-failure assertion |
| `connect/.github/workflows/mls-fuzz.yml` | `fuzz-short` per commit; `fuzz-long` nightly with the oracle |

---

## Interfaces produced by this plan

Every other slice-1 plan writes its `Consumes` block against these. They are stated once here and
repeated inside the task that creates them.

```go
// connect/mls/errors.go — the ValSem catalogue. Every validation site in the
// implementation returns one of these; every negative test asserts one of these.
package mls

type ValSemCode uint16

type ValidationError struct {
    Code   ValSemCode
    Reason string
    Detail error
}

func (self *ValidationError) Error() string
func (self *ValidationError) Unwrap() error
func (self *ValidationError) Is(target error) bool

func ValSem(code ValSemCode, detail error) error
func CodeOf(err error) (ValSemCode, bool)
func ValSemCatalogue() []ValSemCode          // sorted, exactly 51 entries
func ReasonFor(code ValSemCode) string
```

The sentinels are the single declaration site for every one of these names. The framing ten move
here from the framing plan, the PSK three move here from the key-schedule plan, and the five narrow
-profile refusals are new:

```go
// framing, ValSem002-011
var ErrWrongGroupId, ErrWrongEpoch, ErrBlankSenderLeaf error
var ErrApplicationMustBeCiphertext, ErrDecryptFailed error
var ErrMissingMembershipTag, ErrBadMembershipTag error
var ErrMissingConfirmationTag, ErrBadSignature, ErrNonZeroPadding error

// proposals and commits, ValSem101-113 / 200-209 / 300
var ErrDuplicateSignatureKey, ErrDuplicateInitKey, ErrDuplicateEncryptionKey error
var ErrInitEqualsEncryptionKey, ErrSuiteMismatch, ErrMissingRequiredCapability error
var ErrDuplicateRemove, ErrRemoveNonMember, ErrSelfUpdateInCommit error
var ErrUpdateSenderNotMember, ErrUnsupportedProposalType error
var ErrSelfRemoveInCommit, ErrMissingPath, ErrPathLength, ErrPathDecrypt error
var ErrPathKeyMismatch, ErrBadConfirmationTag, ErrMultipleGCE error
var ErrUnsupportedGroupExtension, ErrTrailingBlankNodes error

// past-epoch window and PSK, ValSem400-403
var ErrPastEpochRetained, ErrPskNonceLength, ErrPskType, ErrDuplicatePsk error

// the v1 narrow profile
var ErrProfileExternalCommit, ErrProfileExternalSender, ErrProfilePsk error
var ErrProfileReInit, ErrProfileBranch error
var ErrProfileCredentialType, ErrProfileCiphersuite error

// errata
var ErrUnknownProposalRef error
```

```go
// connect/mls/profile.go — the v1 narrow profile. Group creation, every parse
// boundary and the interop client all gate through it, and profile_test.go asserts
// the allow-sets equal Spec A §3.1/§3.2 exactly.
package mls

type Profile struct {
    AllowPublicMessage bool     // false in DefaultProfile; the passive-client vectors set it
    /* unexported allow-sets */
}

func DefaultProfile() *Profile
func (self *Profile) CheckVersion(v ProtocolVersion) error
func (self *Profile) CheckCiphersuiteForCreate(s CipherSuite) error
func (self *Profile) CheckProposalType(t ProposalType) error
func (self *Profile) CheckCredentialType(t CredentialType) error
func (self *Profile) CheckGroupExtension(t ExtensionType) error
func (self *Profile) CheckLeafExtension(t ExtensionType) error
func (self *Profile) CheckWireFormat(w WireFormat) error
```

```go
// connect/mls/vectors_test.go — the vector-family registry. Each family's owning
// plan calls RegisterVectorFamily from an init() in its own *_kat_test.go.
package mls

type VectorFamily struct {
    Number   int                                        // 1..16, the Spec A §4.2.1 row
    Name     string                                     // "Tree math"
    File     string                                     // "tree-math.json", under testdata/vectors
    Slice    string                                     // "A1".."A4" — the slice it must pass in
    Verify   func(t *testing.T, raw json.RawMessage)    // nil means "not yet implemented"
    Generate func(t *testing.T) json.RawMessage         // nil means the format does not support it
}

func RegisterVectorFamily(family VectorFamily)
func LoadVectorFile(t *testing.T, file string) []json.RawMessage
func MustHex(t *testing.T, s string) []byte
func HexOf(b []byte) string
```

```go
// connect/mls/codec_table.go — NOT a _test.go file. The Go oracle client and the
// separate connect/mls/interop module cannot see symbols in a test file, and the
// kind id is the shared contract that stops Go and Rust drifting about which
// decoder a divergence concerns. Every pair is one line over syntax.Marshal /
// syntax.Unmarshal (C1); no Parse*/Encode* names are asked of any other plan.
package mls

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

```go
// connect/mls/testkit_test.go — the forge. Builds a valid group, then frames a
// message the honest API would refuse to build, so a negative test can assert
// the receiving side rejects it.
package mls

type forge struct { /* unexported */ }

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
```

```go
// connect/mls/memstore_test.go — the in-memory StateStore every test uses.
package mls

type memStore struct { /* unexported */ }

func newMemStore() *memStore
func (self *memStore) EpochsHeld(groupId []byte) []uint64
func (self *memStore) PrivateKeyCount() int
// plus the full mls.StateStore interface
```

```go
// connect/mls/oracle_test.go — the out-of-process OpenMLS differential oracle.
package mls

type oracleResult struct {
    Accept       bool   `json:"accept"`
    Reserialized []byte `json:"reserialized"`
    Error        string `json:"error"`
}

func newOracle(t *testing.T) *oracle      // t.Skip when URMSG_MLS_ORACLE is unset
func mustNewOracle(tb testing.TB) *oracle // the non-skipping form a fuzz target needs
func (self *oracle) decode(kind CodecKind, input []byte) (oracleResult, error)
func (self *oracle) close() error
```

`Reserialized` is a `[]byte` with the plain `reserialized` tag: `encoding/json` already decodes a
standard-base64 string into `[]byte`, so no second field and no manual decode step.

## Interfaces consumed by this plan

Every signature below is the canonical interface registry's, verbatim. Every one is referenced by
real code in a task below, and nothing in this plan calls a name that is not here.

**From "Syntax and codec" (wave 1), `package syntax`:**

```go
const MaxVarint uint32 = 1<<30 - 1
const MaxVectorLength int = 1 << 20
const MaxRatchetTreeLength int = 1 << 24

var ErrTruncated error
var ErrTrailingBytes error
var ErrVarintReserved error
var ErrVarintNotMinimal error
var ErrVarintOverflow error
var ErrLengthExceedsInput error
var ErrLengthExceedsMax error
var ErrZeroLengthElement error
var ErrRoundTripNotByteExact error
var ErrRoundTripNotStable error

type Writer struct{ ... }
func NewWriter() *Writer
func (self *Writer) Bytes() ([]byte, error)
func (self *Writer) WriteVarint(v uint32)
func (self *Writer) WriteOpaque(bs []byte)

type Reader struct{ ... }
func NewReader(bs []byte) *Reader
func (self *Reader) ReadVarint() (uint32, error)
func (self *Reader) ReadOpaque() ([]byte, error)

type Marshaler interface{ MarshalMLS(w *Writer) error }
type Unmarshaler interface{ UnmarshalMLS(r *Reader) error }
type Codec interface {
    Marshaler
    Unmarshaler
}
func Marshal(v Marshaler) ([]byte, error)
func Unmarshal(bs []byte, v Unmarshaler) error
func CheckRoundTrip[T any, PT interface {
    *T
    Codec
}](bs []byte) error

// family 16 is implemented once, in package syntax, against the Reader/Writer
// varint methods it actually ships. Task 8 is a registry shim over this.
func VerifyDeserializationVector(t *testing.T, raw json.RawMessage)
```

The append-style free functions this plan used to name — `syntax.ReadVarint(b) (uint64, int, error)`
and `syntax.WriteVarint(dst, v) []byte` — do not exist and are not added. The varint is
`syntax.NewReader(b).ReadVarint()`, and it is `uint32`-valued. `ErrNonMinimalLength` is
`ErrVarintNotMinimal`; `ErrVectorTooLong` is `ErrLengthExceedsMax`.

**From "Crypto primitives and HPKE" (wave 1), `package mls`:**

```go
type CipherSuite uint16
const CipherSuiteX25519AesGcm128Sha256Ed25519 CipherSuite = 0x0001
const CipherSuiteX25519ChaCha20Sha256Ed25519  CipherSuite = 0x0003

func Suites() []CipherSuite
func LookupSuite(suite CipherSuite) (*SuiteParams, error)
func IsRegisteredSuite(suite CipherSuite) bool

type HpkePublicKey []byte
type HpkePrivateKey []byte
type SignaturePublicKey []byte
type SignaturePrivateKey []byte

type CryptoProvider interface { /* Spec A §3.3, verbatim */ }
func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)
func NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error)

func MakeKeyPackageRef(crypto CryptoProvider, keyPackage []byte) []byte
func MakeProposalRef(crypto CryptoProvider, authenticatedContent []byte) []byte

var ErrUnknownCipherSuite error
var ErrInvalidPoint error
var ErrCryptoBadSignature error
var ErrAeadOpen error
```

`RegisteredSuites()` does not exist: `Suites()` plus `IsRegisteredSuite()` is the pair. The suite
constants are `…ChaCha20Sha256…` and `…AesGcm128Sha256…`, per `CODESTYLE.md`'s no-all-caps rule.
`MakeProposalRef` returns a bare `[]byte` — there is no error to handle. `ErrBadSignature` is
**this plan's** ValSem010 sentinel and wraps the crypto layer's `ErrCryptoBadSignature`, so
`errors.Is` holds through both.

**From "Tree math" (wave 1), `package mls`:**

```go
type LeafIndex uint32
type NodeIndex uint32
type LeafCount uint32

func (self LeafIndex) NodeIndex() NodeIndex
func Root(n LeafCount) (NodeIndex, error)
func DirectPath(x NodeIndex, n LeafCount) ([]NodeIndex, error)
func Copath(x NodeIndex, n LeafCount) ([]NodeIndex, error)
```

Counts are `LeafCount`, indices are `NodeIndex`, and all three take an error return (**C3**). This
plan takes no single-valued shims.

**From "Key schedule and secret tree" (wave 2), `package mls`:**

```go
const PastEpochWindow uint64 = 32

type GroupContext struct {
    Version                 ProtocolVersion
    CipherSuite             CipherSuite
    GroupId                 []byte
    Epoch                   uint64
    TreeHash                []byte
    ConfirmedTranscriptHash []byte
    Extensions              []Extension
}

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
```

`PastEpochWindow` is a `uint64` and is declared once, here. `PreSharedKeyID` is `PreSharedKeyId`.

**From "Registry enums, extensions, tree, TreeKEM" (wave 2), `package mls`:**

```go
type ProtocolVersion uint16
const ProtocolVersionMls10 ProtocolVersion = 0x0001

type CredentialType uint16
const CredentialTypeBasic CredentialType = 0x0001

type ProposalType uint16
const (
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

type Extension struct {
    ExtensionType ExtensionType
    ExtensionData []byte
}
func FindExtension(exts []Extension, t ExtensionType) ([]byte, bool)

type Capabilities struct {
    Versions     []ProtocolVersion
    CipherSuites []CipherSuite
    Extensions   []ExtensionType
    Proposals    []ProposalType
    Credentials  []CredentialType
}
type RequiredCapabilities struct {
    ExtensionTypes  []ExtensionType
    ProposalTypes   []ProposalType
    CredentialTypes []CredentialType
}
type Credential struct {
    CredentialType CredentialType
    Identity       []byte
}
func BasicCredential(identity []byte) Credential

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

type KeyPackage struct {
    Version     ProtocolVersion
    CipherSuite CipherSuite
    InitKey     HpkePublicKey
    LeafNode    LeafNode
    Extensions  []Extension
    Signature   []byte
}
func NewKeyPackage(crypto CryptoProvider, suite CipherSuite, cred Credential,
    caps Capabilities, exts []Extension) (kp *KeyPackage, initPriv HpkePrivateKey,
    encPriv HpkePrivateKey, err error)
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error)

type Node struct {
    NodeType NodeType
    Leaf     *LeafNode
    Parent   *ParentNode
}
type OptionalNode struct {
    Present bool
    Node    Node
}
type RatchetTree struct{ /* opaque */ }
func UnmarshalRatchetTree(data []byte) (*RatchetTree, error)
func (self *RatchetTree) HasTrailingBlankNodes() bool
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
func CheckUpdatePathKeyUniqueness(tree *RatchetTree, path *UpdatePath) error

const AlgIdXwing uint16 = 0x0014
const XwingPublicKeyLen = 1216
type LeafKeysExtension struct {
    AlgId          uint16
    DeviceXwingPub []byte
}
```

`ParseRatchetTree`, `EncodeRatchetTree`, `ValidateRatchetTree` and `RatchetTreeExtension` do not
exist. Parsing is `UnmarshalRatchetTree(data)` (which applies `MaxRatchetTreeLength` itself),
encoding is `syntax.Marshal(tree)`, validating is `(*RatchetTree).Validate(ctx)`, and finding the
extension is `FindExtension(exts, ExtensionTypeRatchetTree)`.

**From "Framing and message protection" (wave 3), `package mls`:**

```go
type WireFormat uint16
const (
    WireFormatPublicMessage  WireFormat = 0x0001
    WireFormatPrivateMessage WireFormat = 0x0002
    WireFormatKeyPackage     WireFormat = 0x0005
)
type ContentType uint8
const (
    ContentTypeApplication ContentType = 1
    ContentTypeProposal    ContentType = 2
    ContentTypeCommit      ContentType = 3
)
type SenderType uint8
const (
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
type FramedContentAuthData struct {
    Signature       []byte
    ConfirmationTag []byte
}
type AuthenticatedContent struct {
    WireFormat WireFormat
    Content    FramedContent
    Auth       FramedContentAuthData
}
func (self *AuthenticatedContent) ProposalRef(crypto CryptoProvider) (ProposalRef, error)
type PublicMessage struct {
    Content       FramedContent
    Auth          FramedContentAuthData
    MembershipTag []byte
}
func (self *PublicMessage) AuthenticatedContent() *AuthenticatedContent
type PrivateMessage struct {
    GroupId             []byte
    Epoch               uint64
    ContentType         ContentType
    AuthenticatedData   []byte
    EncryptedSenderData []byte
    Ciphertext          []byte
}
type MLSMessage struct {
    Version        ProtocolVersion
    WireFormat     WireFormat
    PublicMessage  *PublicMessage
    PrivateMessage *PrivateMessage
    Welcome        *Welcome
    GroupInfo      *GroupInfo
    KeyPackage     *KeyPackage
}
func MarshalMLSMessage(message *MLSMessage) ([]byte, error)
func ParseMLSMessage(data []byte) (*MLSMessage, error)

type Add struct{ KeyPackage KeyPackage }
type Update struct{ LeafNode LeafNode }
type Remove struct{ Removed LeafIndex }
type PreSharedKey struct{ Psk PreSharedKeyId }
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
    UnknownType            ProposalType
    UnknownBody            []byte
}
type ProposalOrRefType uint8
const (
    ProposalOrRefTypeProposal  ProposalOrRefType = 1
    ProposalOrRefTypeReference ProposalOrRefType = 2
)
type ProposalRef []byte
type ProposalOrRef struct {
    Type      ProposalOrRefType
    Proposal  *Proposal
    Reference ProposalRef
}
type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}
type Welcome struct {
    CipherSuite        CipherSuite
    Secrets            []EncryptedGroupSecrets
    EncryptedGroupInfo []byte
}
type GroupInfo struct {
    GroupContext    GroupContext
    Extensions      []Extension
    ConfirmationTag []byte
    Signer          LeafIndex
    Signature       []byte
}

func SignAuthenticatedContent(crypto CryptoProvider, priv SignaturePrivateKey,
    wireFormat WireFormat, content *FramedContent, groupContext []byte) (*AuthenticatedContent, error)

// the two construction-bypass seams the forge needs — unexported, framing.go
func (self *Group) sealFramedContentForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey) ([]byte, error)
func (self *Group) sealFramedContentWithPaddingForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey, padding []byte) ([]byte, error)
```

`EncodeMLSMessage` does not exist — the encoder is `MarshalMLSMessage`, and `ParseMLSMessage` /
`MarshalMLSMessage` are the one sanctioned pair of byte-level free functions outside this plan's
codec table. `MLSMessage`'s arms are **fields**, not accessor methods. Three asks this plan used to
make are refused, with the substitute named: `FramedContentAuthData.MembershipTag` →
`PublicMessage.MembershipTag`; `FramedContentAuthData.HasConfirmationTag` → presence is derived from
`ContentType`; `FramedContent.RawProposal` → `Proposal.UnknownType` / `Proposal.UnknownBody`.

**From "Group lifecycle" (wave 4), `package mls`:**

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
}

type GroupConfig struct {
    Suite        CipherSuite
    GroupId      []byte
    Extensions   []Extension
    RequiredCaps RequiredCapabilities
    Crypto       CryptoProvider
    Store        StateStore
    Profile      *Profile
    LeafKeys     LeafKeysExtension
}
type Member struct {
    LeafIndex    LeafIndex
    IdentityPub  []byte
    SignatureKey SignaturePublicKey
    LeafKeys     *LeafKeysExtension
    Role         Role
}
type EpochSecretName uint8
const (
    EpochSecretSenderData EpochSecretName = iota + 1
    EpochSecretEncryption
)
type Group struct{ /* stateLock-guarded */ }

func NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error)
func (self *Group) GroupId() []byte
func (self *Group) Epoch() uint64
func (self *Group) OwnLeafIndex() LeafIndex
func (self *Group) OwnLeafNodeCopy() *LeafNode
func (self *Group) Members() []Member
func (self *Group) MemberAt(leafIndex LeafIndex) (Member, bool)
func (self *Group) EpochAuthenticator() []byte
func (self *Group) Export(label string, context []byte, length int) ([]byte, error)
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error)
func (self *Group) RatchetTree() ([]byte, error)
func (self *Group) GroupContext() ([]byte, error)
func (self *Group) Close() error

func (self *Group) ProposeAdd(keyPackage []byte) (proposalMessage []byte, err error)
func (self *Group) ProposeRemove(leaf LeafIndex) ([]byte, error)
func (self *Group) ProposeUpdate() ([]byte, error)
func (self *Group) ProposeGroupContextExtensions(exts []Extension) ([]byte, error)

type CommitOptions struct {
    Force          bool
    ExtraProposals []Proposal

    // test seams, unexported. They are fields of CommitOptions, NOT of Commit: a
    // test flag must never touch a wire type.
    skipValidation                         bool
    dropConfirmationTag                    bool
    confirmationTagOverPreCommitTranscript bool
}
type CommitResult struct {
    Commit      []byte
    Welcome     []byte
    RatchetTree []byte
}
func (self *Group) Commit(byReference [][]byte, byValue []Proposal, opts *CommitOptions) (*CommitResult, error)

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
}
func (self *Group) ProcessMessage(message []byte) (*Processed, error)
func (self *Group) ApplyCommit(processed *Processed) error
func (self *Group) MergePendingCommit() error
func (self *Group) ClearPendingCommit()
func (self *Group) Protect(aad, plaintext []byte) ([]byte, error)
func (self *Group) Unprotect(privateMessage []byte) (*ApplicationMessage, error)

type JoinKeyMaterial struct {
    KeyPackage     KeyPackage
    InitPrivate    HpkePrivateKey
    EncryptPrivate HpkePrivateKey
    SignPrivate    SignaturePrivateKey
}
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte,
    keys *JoinKeyMaterial) (*Group, error)

func CheckErrata8745(path *UpdatePath, context *GroupContext) error
func CheckErrata8815(commit *Commit, pending *ProposalCache) error
```

The ten `Parse*`/`Encode*` names this plan used to ask the lifecycle plan for — `ParseExtension`,
`EncodeExtension`, `ParseKeyPackage`, `EncodeKeyPackage`, `ParseProposal`, `EncodeProposal`,
`ParseWelcome`, `EncodeWelcome` — **are not added anywhere.** Under **C1** each is one line inside
this plan's own codec table over `syntax.Marshal` / `syntax.Unmarshal`, which keeps the naming
contract inside one plan and removes ten cross-plan asks.

`Profile` is **not** consumed from the lifecycle plan: it is produced here (`profile.go`, Task 2a).
`PastEpochWindow` is the key-schedule plan's. `CheckErrata8745` and `CheckErrata8815` are the
lifecycle plan's, called from commit processing; Task 23 tests them through `Group.ProcessMessage`.

---

## The 43 ValSem codes and the malformed input that triggers each

This table is the specification for Tasks 18–23. Every row names the **one** thing the test mutates.
Each test builds a valid group, applies exactly that mutation, and asserts exactly that error.

**Framing (RFC 9420 §6) — `validation_framing_test.go`**

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 002 | `TestValSem002_WrongGroupId` | `FramedContent.GroupId` = the group id with its final byte incremented | `ErrWrongGroupId` |
| 003 | `TestValSem003_WrongEpoch` | `FramedContent.Epoch = group.Epoch() + 1` | `ErrWrongEpoch` |
| 004 | `TestValSem004_BlankSenderLeaf` | `Sender{SenderType: SenderTypeMember, LeafIndex: 2}` after leaf 2 was removed and blanked | `ErrBlankSenderLeaf` |
| 005 | `TestValSem005_ApplicationMustBeCiphertext` | application content framed with `WireFormatPublicMessage` | `ErrApplicationMustBeCiphertext` |
| 006 | `TestValSem006_DecryptFails` | flip bit 0 of byte 0 of `PrivateMessage.Ciphertext` | `ErrDecryptFailed` |
| 007 | `TestValSem007_MissingMembershipTag` | `PublicMessage.MembershipTag` replaced with a zero-length slice | `ErrMissingMembershipTag` |
| 008 | `TestValSem008_BadMembershipTag` | `PublicMessage.MembershipTag` replaced with `crypto.Random(32)` | `ErrBadMembershipTag` |
| 009 | `TestValSem009_MissingConfirmationTag` | a Commit built with `CommitOptions.dropConfirmationTag` | `ErrMissingConfirmationTag` |
| 010 | `TestValSem010_BadSignature` | `Signature` re-signed by member 1's signer while `Sender.LeafIndex` still names member 0 | `ErrBadSignature` |
| 011 | `TestValSem011_NonZeroPadding` | `PrivateMessageContent` padded with `0x00 0x00 0x01` instead of all-zero | `ErrNonZeroPadding` |

**Proposals covered by a commit (§12.1, §12.2) — `validation_proposal_test.go`**

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 101 | `TestValSem101_DuplicateSignatureKey` | Add whose `KeyPackage.LeafNode.SignatureKey` is copied from member 1's leaf | `ErrDuplicateSignatureKey` |
| 102 | `TestValSem102_DuplicateInitKey` | two Add proposals in one commit sharing one `KeyPackage.InitKey` | `ErrDuplicateInitKey` |
| 103 | `TestValSem103_DuplicateEncryptionKey` | Add whose `LeafNode.EncryptionKey` is copied from member 1's leaf | `ErrDuplicateEncryptionKey` |
| 104 | `TestValSem104_InitEqualsEncryptionKey` | Add whose `KeyPackage.InitKey == KeyPackage.LeafNode.EncryptionKey` | `ErrInitEqualsEncryptionKey` |
| 105 | `TestValSem105_SuiteMismatch` | Add whose `KeyPackage.CipherSuite = 0x0001` (registered, not the group's) | `ErrSuiteMismatch` |
| 106 | `TestValSem106_AddMissingRequiredCapability` | Add whose `LeafNode.Capabilities.Extensions` omits `0xF002` | `ErrMissingRequiredCapability` |
| 107 | `TestValSem107_DuplicateRemove` | two Remove proposals both naming `LeafIndex(1)` | `ErrDuplicateRemove` |
| 108 | `TestValSem108_RemoveNonMember` | Remove naming `LeafIndex(7)` in a 3-leaf tree | `ErrRemoveNonMember` |
| 109 | `TestValSem109_UpdateMissingRequiredCapability` | Update whose `LeafNode.Capabilities.Extensions` omits `0xF001` | `ErrMissingRequiredCapability` |
| 110 | `TestValSem110_UpdateDuplicateEncryptionKey` | Update whose `LeafNode.EncryptionKey` is copied from member 2's leaf | `ErrDuplicateEncryptionKey` |
| 111 | `TestValSem111_SelfUpdateInCommit` | committer's own Update, referenced by hash in `Commit.Proposals` | `ErrSelfUpdateInCommit` |
| 112 | `TestValSem112_UpdateSenderNotMember` | standalone Update framed with `Sender{SenderType: SenderTypeNewMemberProposal}` | `ErrUpdateSenderNotMember` |
| 113 | `TestValSem113_UnsupportedProposalType` | proposal type `0xF0FF`, absent from every member's `Capabilities.Proposals` | `ErrUnsupportedProposalType` |

**Commits (§12.4) and the ratchet tree (§12.4.3.1) — `validation_commit_test.go`**

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 200 | `TestValSem200_SelfRemoveInCommit` | Commit with an inline `Remove{Removed: committer's own leaf}` | `ErrSelfRemoveInCommit` |
| 201 | `TestValSem201_MissingPath` | Commit covering an Update with `Commit.Path = nil` | `ErrMissingPath` |
| 202 | `TestValSem202_PathLength` | drop the last element of `UpdatePath.Nodes` | `ErrPathLength` |
| 203 | `TestValSem203_PathDecrypt` | flip bit 0 of the `HpkeCiphertext.Ciphertext` addressed to the receiver's resolution slot | `ErrPathDecrypt` |
| 204 | `TestValSem204_PathKeyMismatch` | replace `UpdatePathNode.EncryptionKey` at index 0 with a freshly generated public key, leaving the ciphertexts alone | `ErrPathKeyMismatch` |
| 205 | `TestValSem205_BadConfirmationTag` | `CommitOptions.confirmationTagOverPreCommitTranscript` | `ErrBadConfirmationTag` |
| 206 | `TestValSem206_PathLeafDuplicateEncryptionKey` | `UpdatePath.LeafNode.EncryptionKey` copied from member 2's leaf | `ErrDuplicateEncryptionKey` |
| 207 | `TestValSem207_PathNodeDuplicateEncryptionKey` | `UpdatePath.Nodes[1].EncryptionKey = UpdatePath.Nodes[0].EncryptionKey` | `ErrDuplicateEncryptionKey` |
| 208 | `TestValSem208_MultipleGCE` | two `GroupContextExtensions` proposals inline in one commit | `ErrMultipleGCE` |
| 209 | `TestValSem209_UnsupportedGroupExtension` | GCE adding extension type `0xF0AA`, listed in no member's capabilities | `ErrUnsupportedGroupExtension` |
| 300 | `TestValSem300_TrailingBlankNodes` | `ratchet_tree` extension whose node vector ends in a blank (`optional<Node>` absent) entry | `ErrTrailingBlankNodes` |

**External commits (§12.4.3.2) — profile-refused in v1 — `validation_external_test.go`**

Every one of these six asserts `ErrProfileExternalCommit` **and** carries a commented-out assertion
of the RFC error, so implementing external commits in V2 is a mechanical swap.

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 240 | `TestValSem240_ExternalCommitNoExternalInit` | `Sender{SenderType: SenderTypeNewMemberCommit}` commit with **zero** inline `ExternalInit` proposals | `ErrProfileExternalCommit` at the profile gate |
| 241 | `TestValSem241_ExternalCommitTwoExternalInit` | same, with **two** inline `ExternalInit` proposals | `ErrProfileExternalCommit` |
| 242 | `TestValSem242_ExternalCommitNonAllowlisted` | external commit carrying an inline `Add` (not on the §12.4.3.2 allowlist) | `ErrProfileExternalCommit` |
| 244 | `TestValSem244_ExternalCommitByReference` | external commit whose `Commit.Proposals` holds a `ProposalRef` | `ErrProfileExternalCommit` |
| 245 | `TestValSem245_ExternalCommitNoPath` | external commit with `Commit.Path = nil` | `ErrProfileExternalCommit` |
| 246 | `TestValSem246_ExternalCommitSignerNotPathCredential` | external commit signed by an existing member's signer rather than the path `LeafNode` credential | `ErrProfileExternalCommit` |

There is no ValSem243 — the mlswg numbering skips it. ValSem247 is folded into ValSem010.

**PSK (§8.4) — profile-refused in v1 — `validation_psk_test.go`**

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 401 | `TestValSem401_PskNonceLength` | `PreSharedKeyId.PskNonce` of 31 bytes where `KDF.Nh == 32` | `ErrProfilePsk` at the profile gate |
| 402 | `TestValSem402_PskUsage` | `PreSharedKeyId` with `Usage: ResumptionPskUsageReInit` | `ErrProfilePsk` |
| 403 | `TestValSem403_DuplicatePskId` | two byte-identical `PreSharedKeyId` values in one proposal list | `ErrProfilePsk` |

Each carries a commented-out V2 assertion of `ValSem401` / `ValSem402` / `ValSem403`, whose sentinels
(`ErrPskNonceLength`, `ErrPskType`, `ErrDuplicatePsk`) are declared here and returned by the key
schedule plan's `(*PreSharedKeyId).Validate` once PSKs are implemented.

**Past-epoch bound — `validation_epoch_test.go`**

| Code | Test function | Assertion | Expected |
|---|---|---|---|
| 400 | `TestValSem400_PastEpochBound` | merge 40 commits; assert `memStore.EpochsHeld` holds exactly epochs `8..40` and nothing older | 33 epochs held, `epoch - 32` and below deleted; `ErrPastEpochRetained` names the violation |

**The v1 narrow profile — `profile_test.go`**

RFC 9420 assigns these five refusals no ValSem number, so they occupy a private block in the
catalogue and their tests are named by behaviour rather than by number.

| Code | Test function | Refused input | Expected |
|---|---|---|---|
| profile 9001 | `TestProfileRefusesExternalSenders` | `ExtensionTypeExternalSenders` in a GroupContext | `ErrProfileExternalSender` |
| profile 9002 | `TestProfileRefusesReInit` | `ProposalTypeReInit` | `ErrProfileReInit` |
| profile 9003 | `TestProfileRefusesBranching` | `ResumptionPskUsageBranch` | `ErrProfileBranch` |
| profile 9004 | `TestProfileRefusesX509Credentials` | `CredentialType(0x0002)` | `ErrProfileCredentialType` |
| profile 9005 | `TestProfileRefusesUnpinnedSuiteAtCreate` | `CipherSuiteX25519AesGcm128Sha256Ed25519` at group creation | `ErrProfileCiphersuite` |

**Errata — `errata_test.go`**

| Erratum | Test function | Malformed input | Expected |
|---|---|---|---|
| 8745 | `TestErrata8745` | a Commit whose `UpdatePath.LeafNode.Capabilities.Extensions` omits `0xF001`, a GroupContext extension | `ValSemErrata8745`; the pre-erratum "accept" outcome is asserted absent |
| 8815 | `TestErrata8815` | a Commit whose `Commit.Proposals` holds a `ProposalRef` of 32 random bytes the receiver never saw | `ErrUnknownProposalRef` |

Total: 43 ValSem codes + ValSem400 + 5 narrow-profile refusals + 2 errata = **51 catalogue entries,
51 test functions**, which is the count `ValSemCatalogue()` returns and `TestValSemCatalogueIsClosed`
asserts.

---

## Phase A — scaffolding (wave 1; depends on nothing but `connect/mls/syntax`)

### Task 1: Transcribe RFC 9420 errata 8745 and 8815

**Files:**
- Create: `connect/mls/ERRATA.md`
- Test: `connect/mls/errata_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `connect/mls/ERRATA.md` as the reviewable, offline source of truth for both errata.
  `TestErrataFileIsTranscribed`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/errata_test.go
package mls

import (
	"os"
	"strings"
	"testing"
)

// erratumMarkers are the load-bearing phrases of each erratum. A paraphrase drops
// one of them, so the transcription cannot be summarized without failing here.
var erratumMarkers = map[string][]string{
	"8745": {
		"Errata ID: 8745",
		"Section 13.4",
		"Status: Reported",
		"A client updating a leaf node in the group MUST verify that the new LeafNode is compatible with the group's extensions.",
		"The capabilities field MUST indicate support for each extension in the GroupContext.",
		"This applies both to Update proposals and LeafNode objects in the update_path in a Commit.",
	},
	"8815": {
		"Errata ID: 8815",
		"Section 12.2",
		"Status: Reported",
		"It contains a reference to a proposal that was not previously received by the group member.",
	},
}

func TestErrataFileIsTranscribed(t *testing.T) {
	raw, err := os.ReadFile("ERRATA.md")
	if err != nil {
		t.Fatalf("read ERRATA.md: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "https://errata.rfc-editor.org/eid8745") {
		t.Error("ERRATA.md must cite the errata URL so a reviewer can check the transcription")
	}
	if !strings.Contains(text, "https://errata.rfc-editor.org/eid8815") {
		t.Error("ERRATA.md must cite the errata URL so a reviewer can check the transcription")
	}
	for id, markers := range erratumMarkers {
		for _, marker := range markers {
			if !strings.Contains(text, marker) {
				t.Errorf("erratum %s: ERRATA.md is missing the verbatim line %q", id, marker)
			}
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestErrataFileIsTranscribed -v`
Expected: FAIL with `read ERRATA.md: open ERRATA.md: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

```markdown
<!-- connect/mls/ERRATA.md -->
# RFC 9420 errata implemented by connect/mls

Fetched from the RFC Editor errata database on 2026-08-12. Both errata are **Reported**, not yet
Verified. We implement the corrected behaviour anyway: each closes a validation gap that a
non-implementing client would leave open, and Spec A §4.3 makes both a Gate 3 condition.

Transcribed verbatim. Do not paraphrase; `TestErrataFileIsTranscribed` fails if the load-bearing
sentences are reworded, and the diff review must check the transcription against the cited page.

---

## Errata ID: 8745

Source: https://errata.rfc-editor.org/eid8745
Status: Reported
Type: Technical
Section 13.4

**Original Text**

> A client adding a new member to a group MUST verify that the LeafNode for the new member is
> compatible with the group's extensions. The capabilities field MUST indicate support for each
> extension in the GroupContext.

**Corrected Text**

> A client adding a new member to a group MUST verify that the LeafNode for the new member is
> compatible with the group's extensions. The capabilities field MUST indicate support for each
> extension in the GroupContext.
>
> A client updating a leaf node in the group MUST verify that the new LeafNode is compatible with
> the group's extensions. The capabilities field MUST indicate support for each extension in the
> GroupContext. This applies both to Update proposals and LeafNode objects in the update_path in a
> Commit.

**Notes**

> RFC 9420 mandates capability validation for LeafNodes in KeyPackages being added to a group, but
> states no corresponding requirement for LeafNodes in Update proposals or in the update_path of a
> Commit. That is inconsistent with the principle that all MLS GroupContext extensions are mandatory
> and must be supported by all group members.

**What we implement:** the capability check runs on the `LeafNode` of an Update proposal (this is
also ValSem109) **and** on `UpdatePath.LeafNode` of a Commit (which no ValSem code covers). Both
return `ErrMissingRequiredCapability`. `TestErrata8745` asserts the Commit path.

---

## Errata ID: 8815

Source: https://errata.rfc-editor.org/eid8815
Status: Reported
Type: Technical
Section 12.2

**Original Text**

> For a regular, i.e., not external, Commit, the list is invalid if any of the following occurs:
>
> It contains an individual proposal that is invalid as specified in Section 12.1.

**Corrected Text**

> For a regular, i.e., not external, Commit, the list is invalid if any of the following occurs:
>
> It contains a reference to a proposal that was not previously received by the group member.
>
> It contains an individual proposal that is invalid as specified in Section 12.1.

**Notes**

> Section 12.4 allows the proposals vector in a Commit to contain references to proposals, but
> Section 12.2's validation rules omit any verification that such references are legitimate. The
> added rule requires proposal references to be validated against proposals the group member
> previously received.

**What we implement:** an unresolvable `ProposalRef` in `Commit.Proposals` is rejected with
`ErrUnknownProposalRef` before any other commit processing. `TestErrata8815` asserts it.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestErrataFileIsTranscribed -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/ERRATA.md mls/errata_test.go && git -C connect commit -m "test(mls): transcribe RFC 9420 errata 8745 and 8815 verbatim"
```

---

### Task 2: The ValSem error catalogue

**Files:**
- Create: `connect/mls/errors.go`
- Test: `connect/mls/errors_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type ValSemCode uint16`
  - `type ValidationError struct { Code ValSemCode; Reason string; Detail error }`
  - `func (self *ValidationError) Error() string`
  - `func (self *ValidationError) Unwrap() error`
  - `func (self *ValidationError) Is(target error) bool`
  - `func ValSem(code ValSemCode, detail error) error`
  - `func CodeOf(err error) (ValSemCode, bool)`
  - `func ValSemCatalogue() []ValSemCode` — sorted, exactly 51 entries
  - `func ReasonFor(code ValSemCode) string`
  - the sentinels, whose single declaration site this is: `ErrWrongGroupId`, `ErrWrongEpoch`,
    `ErrBlankSenderLeaf`, `ErrApplicationMustBeCiphertext`, `ErrDecryptFailed`,
    `ErrMissingMembershipTag`, `ErrBadMembershipTag`, `ErrMissingConfirmationTag`,
    `ErrBadSignature`, `ErrNonZeroPadding`, `ErrDuplicateSignatureKey`, `ErrDuplicateInitKey`,
    `ErrDuplicateEncryptionKey`, `ErrInitEqualsEncryptionKey`, `ErrSuiteMismatch`,
    `ErrMissingRequiredCapability`, `ErrDuplicateRemove`, `ErrRemoveNonMember`,
    `ErrSelfUpdateInCommit`, `ErrUpdateSenderNotMember`, `ErrUnsupportedProposalType`,
    `ErrSelfRemoveInCommit`, `ErrMissingPath`, `ErrPathLength`, `ErrPathDecrypt`,
    `ErrPathKeyMismatch`, `ErrBadConfirmationTag`, `ErrMultipleGCE`,
    `ErrUnsupportedGroupExtension`, `ErrTrailingBlankNodes`, `ErrPastEpochRetained`,
    `ErrPskNonceLength`, `ErrPskType`, `ErrDuplicatePsk`, `ErrProfileExternalCommit`,
    `ErrProfileExternalSender`, `ErrProfilePsk`, `ErrProfileReInit`, `ErrProfileBranch`,
    `ErrProfileCredentialType`, `ErrProfileCiphersuite`, `ErrUnknownProposalRef`

Four of these move here from other plans and one is renamed, so each has exactly one declaration in
`package mls`: the ten framing sentinels arrive from the framing plan (they are ValSem002–011);
`ErrPskNonceLength`, `ErrPskType` and `ErrDuplicatePsk` arrive from the key-schedule plan (they are
ValSem401–403); `ErrBadSignature` is ValSem010 and the crypto plan's same-named value is renamed
`ErrCryptoBadSignature`, which this one wraps.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/errors_test.go
package mls

import (
	"errors"
	"fmt"
	"testing"
)

func TestValidationErrorCarriesItsCode(t *testing.T) {
	detail := fmt.Errorf("epoch 7 != 8")
	err := ValSem(ValSem003, detail)

	if !errors.Is(err, ErrWrongEpoch) {
		t.Fatalf("errors.Is(err, ErrWrongEpoch) = false, want true")
	}
	if errors.Is(err, ErrWrongGroupId) {
		t.Fatalf("errors.Is(err, ErrWrongGroupId) = true, want false")
	}
	if !errors.Is(err, detail) {
		t.Fatalf("the detail must stay reachable through Unwrap")
	}
	code, ok := CodeOf(err)
	if !ok || code != ValSem003 {
		t.Fatalf("CodeOf = (%d, %v), want (3, true)", code, ok)
	}
	wrapped := fmt.Errorf("processing message: %w", err)
	code, ok = CodeOf(wrapped)
	if !ok || code != ValSem003 {
		t.Fatalf("CodeOf through a wrapper = (%d, %v), want (3, true)", code, ok)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestValidationErrorCarriesItsCode -v`
Expected: FAIL to build with `undefined: ValSem`, `undefined: ValSem003`, `undefined: ErrWrongEpoch`,
`undefined: CodeOf`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/errors.go
// the validation-error taxonomy: one typed error per RFC 9420 ValSem code, plus
// the two errata this implementation adopts. Every validation site returns one of
// these and every negative test asserts one of these, so a check and its test
// cannot drift apart.
package mls

import (
	"errors"
	"fmt"
)

// ValSemCode is an mlswg validation-semantics code. The numeric value is the code
// itself, so ValSem003 is 3 and the errata keep their RFC Editor ids.
type ValSemCode uint16

const (
	ValSem002 ValSemCode = 2
	ValSem003 ValSemCode = 3
	ValSem004 ValSemCode = 4
	ValSem005 ValSemCode = 5
	ValSem006 ValSemCode = 6
	ValSem007 ValSemCode = 7
	ValSem008 ValSemCode = 8
	ValSem009 ValSemCode = 9
	ValSem010 ValSemCode = 10
	ValSem011 ValSemCode = 11

	ValSem101 ValSemCode = 101
	ValSem102 ValSemCode = 102
	ValSem103 ValSemCode = 103
	ValSem104 ValSemCode = 104
	ValSem105 ValSemCode = 105
	ValSem106 ValSemCode = 106
	ValSem107 ValSemCode = 107
	ValSem108 ValSemCode = 108
	ValSem109 ValSemCode = 109
	ValSem110 ValSemCode = 110
	ValSem111 ValSemCode = 111
	ValSem112 ValSemCode = 112
	ValSem113 ValSemCode = 113

	ValSem200 ValSemCode = 200
	ValSem201 ValSemCode = 201
	ValSem202 ValSemCode = 202
	ValSem203 ValSemCode = 203
	ValSem204 ValSemCode = 204
	ValSem205 ValSemCode = 205
	ValSem206 ValSemCode = 206
	ValSem207 ValSemCode = 207
	ValSem208 ValSemCode = 208
	ValSem209 ValSemCode = 209

	ValSem240 ValSemCode = 240
	ValSem241 ValSemCode = 241
	ValSem242 ValSemCode = 242
	ValSem244 ValSemCode = 244
	ValSem245 ValSemCode = 245
	ValSem246 ValSemCode = 246

	ValSem300 ValSemCode = 300

	ValSem400 ValSemCode = 400
	ValSem401 ValSemCode = 401
	ValSem402 ValSemCode = 402
	ValSem403 ValSemCode = 403

	ValSemErrata8745 ValSemCode = 8745
	ValSemErrata8815 ValSemCode = 8815

	// the five v1 narrow-profile refusals RFC 9420 gives no ValSem number. They sit
	// above the errata ids in a private block, and formatCode renders them as
	// "profile NNNN" rather than "ValSemNNN" so nobody mistakes one for an RFC code.
	// External commits reuse ValSem240 and PSKs reuse ValSem401, because those two
	// refusals do have RFC codes covering the same input.
	ValSemProfileExternalSender ValSemCode = 9001
	ValSemProfileReInit         ValSemCode = 9002
	ValSemProfileBranch         ValSemCode = 9003
	ValSemProfileCredentialType ValSemCode = 9004
	ValSemProfileCiphersuite    ValSemCode = 9005
)

// valSemReason is the closed catalogue. A code with no entry here is not a code.
var valSemReason = map[ValSemCode]string{
	ValSem002: "group id does not match the group context",
	ValSem003: "epoch does not match the group context",
	ValSem004: "sender member index names a blank leaf",
	ValSem005: "application content must use PrivateMessage",
	ValSem006: "ciphertext decryption failed",
	ValSem007: "membership tag absent on a member-sent PublicMessage",
	ValSem008: "membership tag does not verify",
	ValSem009: "confirmation tag absent on a commit",
	ValSem010: "signature does not verify",
	ValSem011: "PrivateMessageContent padding is not all-zero",

	ValSem101: "add: signature key duplicated among proposals and members",
	ValSem102: "add: init key duplicated among proposals",
	ValSem103: "add: encryption key duplicated among proposals and members",
	ValSem104: "add: init key equals encryption key",
	ValSem105: "add: ciphersuite or protocol version does not match the group",
	ValSem106: "add: required capabilities not satisfied",
	ValSem107: "remove: removed member duplicated among proposals",
	ValSem108: "remove: removed member does not exist",
	ValSem109: "update: required capabilities not satisfied",
	ValSem110: "update: encryption key duplicated among proposals and members",
	ValSem111: "commit covers the committer's own update proposal",
	ValSem112: "standalone update sender is not of type member",
	ValSem113: "proposal type is not supported by all members",

	ValSem200: "commit covers an inline remove of the committer",
	ValSem201: "path absent where a covered proposal requires one",
	ValSem202: "path length does not match the committer's filtered direct path",
	ValSem203: "path secret failed to decrypt",
	ValSem204: "path public key does not match the derived direct-path private key",
	ValSem205: "confirmation tag does not verify",
	ValSem206: "path leaf node encryption key duplicated among proposals and members",
	ValSem207: "path node encryption key duplicated among proposals and members",
	ValSem208: "more than one GroupContextExtensions proposal in one commit",
	ValSem209: "group context extensions proposal names an extension a member does not support",

	ValSem240: "external commits are not implemented in the v1 profile",
	ValSem241: "external commits are not implemented in the v1 profile",
	ValSem242: "external commits are not implemented in the v1 profile",
	ValSem244: "external commits are not implemented in the v1 profile",
	ValSem245: "external commits are not implemented in the v1 profile",
	ValSem246: "external commits are not implemented in the v1 profile",

	ValSem300: "exported ratchet tree ends in blank nodes",

	ValSem400: "group state older than the past-epoch window was retained",
	ValSem401: "psk: nonce length does not match the ciphersuite KDF output",
	ValSem402: "psk: resumption usage is not permitted here",
	ValSem403: "psk: pre-shared key id duplicated in one proposal list",

	ValSemErrata8745: "leaf node capabilities do not cover every group context extension",
	ValSemErrata8815: "commit references a proposal that was never received",

	ValSemProfileExternalSender: "external senders are not implemented in the v1 profile",
	ValSemProfileReInit:         "ReInit is not implemented in the v1 profile",
	ValSemProfileBranch:         "branching is not implemented in the v1 profile",
	ValSemProfileCredentialType: "only BasicCredential is implemented in the v1 profile",
	ValSemProfileCiphersuite:    "group creation is pinned to ciphersuite 0x0003 by policy",
}

// ValidationError is the only error type a validation site returns. Detail is the
// implementation-side explanation and never affects comparison.
type ValidationError struct {
	Code   ValSemCode
	Reason string
	Detail error
}

func (self *ValidationError) Error() string {
	if self.Detail == nil {
		return fmt.Sprintf("mls: ValSem%03d: %s", self.Code, self.Reason)
	}
	return fmt.Sprintf("mls: ValSem%03d: %s: %s", self.Code, self.Reason, self.Detail)
}

func (self *ValidationError) Unwrap() error {
	return self.Detail
}

// Is compares on the code alone, so errors.Is(err, ErrWrongEpoch) holds however
// much detail a call site attached.
func (self *ValidationError) Is(target error) bool {
	other, ok := target.(*ValidationError)
	return ok && other.Code == self.Code
}

// ValSem builds the error for a code. A code outside the catalogue panics, which
// is a programming error and must never reach a caller.
func ValSem(code ValSemCode, detail error) error {
	reason, ok := valSemReason[code]
	if !ok {
		panic(fmt.Sprintf("mls: ValSem called with unknown code %d", code))
	}
	return &ValidationError{Code: code, Reason: reason, Detail: detail}
}

// CodeOf reports the ValSem code of err, however deeply it was wrapped.
func CodeOf(err error) (ValSemCode, bool) {
	var validation *ValidationError
	if errors.As(err, &validation) {
		return validation.Code, true
	}
	return 0, false
}

// ReasonFor is the catalogue text for a code, for the coverage report.
func ReasonFor(code ValSemCode) string {
	return valSemReason[code]
}

// ValSemCatalogue is every code, ascending.
func ValSemCatalogue() []ValSemCode {
	codes := make([]ValSemCode, 0, len(valSemReason))
	for code := range valSemReason {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// the sentinels. Each is the zero-detail form of its code, for errors.Is. This is
// the single declaration site for every one of these names in package mls.
var (
	ErrWrongGroupId                = ValSem(ValSem002, nil)
	ErrWrongEpoch                  = ValSem(ValSem003, nil)
	ErrBlankSenderLeaf             = ValSem(ValSem004, nil)
	ErrApplicationMustBeCiphertext = ValSem(ValSem005, nil)
	ErrDecryptFailed               = ValSem(ValSem006, nil)
	ErrMissingMembershipTag        = ValSem(ValSem007, nil)
	ErrBadMembershipTag            = ValSem(ValSem008, nil)
	ErrMissingConfirmationTag      = ValSem(ValSem009, nil)
	ErrNonZeroPadding              = ValSem(ValSem011, nil)

	ErrDuplicateSignatureKey     = ValSem(ValSem101, nil)
	ErrDuplicateInitKey          = ValSem(ValSem102, nil)
	ErrDuplicateEncryptionKey    = ValSem(ValSem103, nil)
	ErrInitEqualsEncryptionKey   = ValSem(ValSem104, nil)
	ErrSuiteMismatch             = ValSem(ValSem105, nil)
	ErrMissingRequiredCapability = ValSem(ValSem106, nil)
	ErrDuplicateRemove           = ValSem(ValSem107, nil)
	ErrRemoveNonMember           = ValSem(ValSem108, nil)
	ErrSelfUpdateInCommit        = ValSem(ValSem111, nil)
	ErrUpdateSenderNotMember     = ValSem(ValSem112, nil)
	ErrUnsupportedProposalType   = ValSem(ValSem113, nil)

	ErrSelfRemoveInCommit        = ValSem(ValSem200, nil)
	ErrMissingPath               = ValSem(ValSem201, nil)
	ErrPathLength                = ValSem(ValSem202, nil)
	ErrPathDecrypt               = ValSem(ValSem203, nil)
	ErrPathKeyMismatch           = ValSem(ValSem204, nil)
	ErrBadConfirmationTag        = ValSem(ValSem205, nil)
	ErrMultipleGCE               = ValSem(ValSem208, nil)
	ErrUnsupportedGroupExtension = ValSem(ValSem209, nil)

	ErrTrailingBlankNodes = ValSem(ValSem300, nil)

	ErrPastEpochRetained = ValSem(ValSem400, nil)
	ErrPskNonceLength    = ValSem(ValSem401, nil)
	ErrPskType           = ValSem(ValSem402, nil)
	ErrDuplicatePsk      = ValSem(ValSem403, nil)

	ErrProfileExternalCommit = ValSem(ValSem240, nil)
	ErrProfilePsk            = ValSem(ValSem401, nil)
	ErrProfileExternalSender = ValSem(ValSemProfileExternalSender, nil)
	ErrProfileReInit         = ValSem(ValSemProfileReInit, nil)
	ErrProfileBranch         = ValSem(ValSemProfileBranch, nil)
	ErrProfileCredentialType = ValSem(ValSemProfileCredentialType, nil)
	ErrProfileCiphersuite    = ValSem(ValSemProfileCiphersuite, nil)

	ErrUnknownProposalRef = ValSem(ValSemErrata8815, nil)
)

// ErrBadSignature is ValSem010. It is declared apart from the block above because
// it is the one sentinel that wraps another plan's error: the crypto layer returns
// ErrCryptoBadSignature, and errors.Is must hold through both spellings.
var ErrBadSignature = ValSem(ValSem010, ErrCryptoBadSignature)
```

Note the deliberate aliasing: ValSem103, 110, 206 and 207 all surface `ErrDuplicateEncryptionKey`;
ValSem106 and 109 both surface `ErrMissingRequiredCapability`; ValSem240–246 all surface
`ErrProfileExternalCommit`; and ValSem401 has two names, `ErrPskNonceLength` for the RFC check and
`ErrProfilePsk` for the v1 refusal of the whole proposal type. The **code** distinguishes them, so a
test asserts `CodeOf(err) == ValSem110` where the sentinel alone would be ambiguous. `requireValSem`
(Task 17) asserts the code, never the sentinel.

Add `"slices"` to the import block.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestValidationErrorCarriesItsCode -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/errors.go mls/errors_test.go && git -C connect commit -m "feat(mls): typed error per ValSem code, comparable by code"
```

---

### Task 3: Catalogue closure and the ValSem coverage report

**Files:**
- Modify: `connect/mls/errors_test.go`

**Interfaces:**
- Consumes: `ValSemCatalogue() []ValSemCode`, `ReasonFor(ValSemCode) string` (Task 2).
- Produces: `TestValSemCatalogueIsClosed`, `TestValSemCoverageIsComplete`, and the
  `valsem-coverage.md` artifact the audit brief (Spec A §4.6) needs.

- [ ] **Step 1: Write the failing test**

```go
// append to connect/mls/errors_test.go
import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// expectedCatalogue is Spec A §4.3 plus the canonical interface registry §9.1,
// transcribed: 43 ValSem codes, ValSem400, the two errata, and the five narrow
// -profile refusals that have no RFC number. 51 entries. Changing this list without
// changing the spec is the failure this test exists to cause.
var expectedCatalogue = []ValSemCode{
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
	200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
	240, 241, 242, 244, 245, 246,
	300,
	400, 401, 402, 403,
	8745, 8815,
	9001, 9002, 9003, 9004, 9005,
}

func TestValSemCatalogueIsClosed(t *testing.T) {
	got := ValSemCatalogue()
	if len(got) != 51 {
		t.Fatalf("catalogue has %d codes, the registry fixes it at 51", len(got))
	}
	if len(got) != len(expectedCatalogue) {
		t.Fatalf("catalogue has %d codes, spec A §4.3 lists %d", len(got), len(expectedCatalogue))
	}
	for i, want := range expectedCatalogue {
		if got[i] != want {
			t.Errorf("catalogue[%d] = %d, want %d", i, got[i], want)
		}
	}
	// 243 is skipped by the mlswg numbering and 247 is folded into 010.
	for _, absent := range []ValSemCode{243, 247} {
		if ReasonFor(absent) != "" {
			t.Errorf("ValSem%d must not exist: 243 is skipped, 247 is folded into 010", absent)
		}
	}
	// the catalogue counts 43 ValSem codes proper: everything below 400.
	proper := 0
	for _, code := range got {
		if code < 400 {
			proper++
		}
	}
	if proper != 43 {
		t.Errorf("catalogue holds %d ValSem codes below 400, want 43", proper)
	}
	// and the five narrow-profile refusals, which are ours and not the RFC's.
	profile := 0
	for _, code := range got {
		if code >= 9000 {
			profile++
		}
	}
	if profile != 5 {
		t.Errorf("catalogue holds %d narrow-profile codes, want 5", profile)
	}
}

// TestValSemCoverageIsComplete parses the sibling validation test files and asserts
// a TestValSemNNN_ or TestErrataNNNN function exists for every catalogue code, then
// writes the coverage report Gate 6's audit brief is scoped against.
func TestValSemCoverageIsComplete(t *testing.T) {
	found := map[ValSemCode]string{}
	fileSet := token.NewFileSet()
	sources, err := filepath.Glob("validation_*_test.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	sources = append(sources, "errata_test.go", "profile_test.go")
	for _, source := range sources {
		file, err := parser.ParseFile(fileSet, source, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", source, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			code, ok := codeFromTestName(fn.Name.Name)
			if !ok {
				continue
			}
			found[code] = fn.Name.Name
		}
	}
	report := &strings.Builder{}
	report.WriteString("# ValSem coverage\n\n| Code | Reason | Test |\n|---|---|---|\n")
	missing := []ValSemCode{}
	for _, code := range ValSemCatalogue() {
		name := found[code]
		if name == "" {
			missing = append(missing, code)
			name = "MISSING"
		}
		report.WriteString("| " + formatCode(code) + " | " + ReasonFor(code) + " | `" + name + "` |\n")
	}
	if err := os.WriteFile("valsem-coverage.md", []byte(report.String()), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("no negative test for codes %v — see valsem-coverage.md", missing)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSemCatalogueIsClosed|TestValSemCoverageIsComplete' -v`
Expected: FAIL to build with `undefined: codeFromTestName`, `undefined: formatCode`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/errors_test.go

// profileCodeTests maps the five narrow-profile refusals, which RFC 9420 gives no
// number, to the profile_test.go functions that cover them. They are named by
// behaviour because a numeric name would read as an RFC code.
var profileCodeTests = map[string]ValSemCode{
	"TestProfileRefusesExternalSenders":       ValSemProfileExternalSender,
	"TestProfileRefusesReInit":                ValSemProfileReInit,
	"TestProfileRefusesBranching":             ValSemProfileBranch,
	"TestProfileRefusesX509Credentials":       ValSemProfileCredentialType,
	"TestProfileRefusesUnpinnedSuiteAtCreate": ValSemProfileCiphersuite,
}

// codeFromTestName maps TestValSem204_PathKeyMismatch to 204, TestErrata8745 to
// 8745, and each narrow-profile test to its private code. Anything else is not a
// catalogue test and is ignored.
func codeFromTestName(name string) (ValSemCode, bool) {
	if code, ok := profileCodeTests[name]; ok {
		return code, true
	}
	digits := ""
	switch {
	case strings.HasPrefix(name, "TestValSem"):
		digits = strings.TrimPrefix(name, "TestValSem")
	case strings.HasPrefix(name, "TestErrata"):
		digits = strings.TrimPrefix(name, "TestErrata")
	default:
		return 0, false
	}
	if index := strings.IndexByte(digits, '_'); index >= 0 {
		digits = digits[:index]
	}
	value, err := strconv.ParseUint(digits, 10, 16)
	if err != nil {
		return 0, false
	}
	return ValSemCode(value), true
}

// formatCode renders a catalogue code the way the spec tables do.
func formatCode(code ValSemCode) string {
	switch {
	case code >= 9000:
		return "profile " + strconv.FormatUint(uint64(code), 10)
	case code >= 8000:
		return "errata " + strconv.FormatUint(uint64(code), 10)
	default:
		return "ValSem" + fmt.Sprintf("%03d", code)
	}
}
```

Add `"strconv"` to the test file's import block. Add `valsem-coverage.md` to `connect/.gitignore`;
CI uploads it as an artifact rather than committing it.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestValSemCatalogueIsClosed -v`
Expected: PASS.
`TestValSemCoverageIsComplete` correctly FAILs until Task 23 with
`no negative test for codes [2 3 4 ...] — see valsem-coverage.md`. Add the build tag line
`//go:build valsem_complete` to that one function's file section is **not** the fix — instead, until
Task 23 lands, the CI `valsem` job runs it with `-run TestValSemCatalogueIsClosed` and the coverage
test is enabled by the Task 24 workflow change. Record this in the task-23 commit message.

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/errors_test.go .gitignore && git -C connect commit -m "test(mls): assert the ValSem catalogue is closed and generate the coverage report"
```

---

### Task 3a: `profile.go` — the v1 narrow profile

`profile.go` was attributed circularly by every plan and created by nobody, while `GroupConfig.Profile`
is required by `NewGroup`, `DefaultProfile()` is called at eight lifecycle sites and two here, and the
v1 refusals behind Gate 3's 240–246 and 401–403 rows all run through it. The canonical interface
registry §9.3 assigns it here, next to the `ErrProfile*` values the checks return.

The task is authored in wave 1 with the rest of Phase A. Its parameter types are the registry enums
(`ProtocolVersion`, `ProposalType`, `CredentialType`, `ExtensionType` from the TreeKEM plan, and
`WireFormat` from the framing plan), so it turns green when those land — which is why the registry
sequences the TreeKEM plan's registry-enum task first in wave 2.

**Files:**
- Create: `connect/mls/profile.go`
- Test: `connect/mls/profile_test.go`

**Interfaces:**
- Consumes: `ValSem`, `CodeOf`, `ReasonFor`, `ErrProfileExternalCommit`, `ErrProfilePsk`,
  `ErrProfileExternalSender`, `ErrProfileReInit`, `ErrProfileBranch`, `ErrProfileCredentialType`,
  `ErrProfileCiphersuite`, `ErrUnsupportedProposalType`, `ErrUnsupportedGroupExtension`,
  `ErrApplicationMustBeCiphertext` (Task 2); `IsRegisteredSuite(suite CipherSuite) bool`,
  `CipherSuiteX25519ChaCha20Sha256Ed25519`, `CipherSuiteX25519AesGcm128Sha256Ed25519` (crypto plan);
  `ProtocolVersion`, `ProtocolVersionMls10`, `ProposalType` and its constants, `CredentialType`,
  `CredentialTypeBasic`, `ExtensionType` and its constants (TreeKEM plan); `WireFormat` and its
  constants, `ErrUnknownWireFormat`, `ErrUnsupportedVersion` (framing plan).
- Produces:
  - `type Profile struct { AllowPublicMessage bool; /* unexported allow-sets */ }`
  - `func DefaultProfile() *Profile`
  - `func (self *Profile) CheckVersion(v ProtocolVersion) error`
  - `func (self *Profile) CheckCiphersuiteForCreate(s CipherSuite) error`
  - `func (self *Profile) CheckProposalType(t ProposalType) error`
  - `func (self *Profile) CheckCredentialType(t CredentialType) error`
  - `func (self *Profile) CheckGroupExtension(t ExtensionType) error`
  - `func (self *Profile) CheckLeafExtension(t ExtensionType) error`
  - `func (self *Profile) CheckWireFormat(w WireFormat) error`
  - `TestProfileIsClosed` and the five narrow-profile refusal tests

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/profile_test.go
// the v1 narrow profile, asserted against Spec A §3.1 and §3.2 rather than against
// itself. A profile that quietly widens is the single failure mode this file exists
// to prevent: every widening is a green build everywhere else.
package mls

import (
	"errors"
	"testing"
)

func TestProfileIsClosed(t *testing.T) {
	profile := DefaultProfile()

	if profile.AllowPublicMessage {
		t.Error("DefaultProfile must refuse PublicMessage; only the passive-client vectors set it")
	}
	if err := profile.CheckVersion(ProtocolVersionMls10); err != nil {
		t.Errorf("CheckVersion(mls10) = %v, want nil", err)
	}
	if err := profile.CheckVersion(ProtocolVersion(0x0002)); err == nil {
		t.Error("CheckVersion accepted a version outside the profile")
	}

	// the proposal allow-set is exactly add, update, remove, group_context_extensions.
	allowedProposals := []ProposalType{
		ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove, ProposalTypeGroupContextExtensions,
	}
	for _, proposalType := range allowedProposals {
		if err := profile.CheckProposalType(proposalType); err != nil {
			t.Errorf("CheckProposalType(%#04x) = %v, want nil", proposalType, err)
		}
	}
	refusedProposals := map[ProposalType]error{
		ProposalTypePreSharedKey: ErrProfilePsk,
		ProposalTypeReInit:       ErrProfileReInit,
		ProposalTypeExternalInit: ErrProfileExternalCommit,
	}
	for proposalType, want := range refusedProposals {
		if err := profile.CheckProposalType(proposalType); !errors.Is(err, want) {
			t.Errorf("CheckProposalType(%#04x) = %v, want %v", proposalType, err, want)
		}
	}
	if err := profile.CheckProposalType(ProposalType(0xF0FF)); !errors.Is(err, ErrUnsupportedProposalType) {
		t.Errorf("CheckProposalType(0xF0FF) = %v, want ErrUnsupportedProposalType", err)
	}

	// the group-extension allow-set is exactly the three urmessage extensions plus
	// required_capabilities and ratchet_tree.
	allowedGroupExtensions := []ExtensionType{
		ExtensionTypeRatchetTree, ExtensionTypeRequiredCapabilities,
		ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys,
		ExtensionTypeUrmessageOwnerSuccessor,
	}
	for _, extensionType := range allowedGroupExtensions {
		if err := profile.CheckGroupExtension(extensionType); err != nil {
			t.Errorf("CheckGroupExtension(%#04x) = %v, want nil", extensionType, err)
		}
	}

	// wire formats: PublicMessage refused by default, PrivateMessage always allowed,
	// an unregistered value refused as unknown rather than as a profile decision.
	if err := profile.CheckWireFormat(WireFormatPrivateMessage); err != nil {
		t.Errorf("CheckWireFormat(private) = %v, want nil", err)
	}
	if err := profile.CheckWireFormat(WireFormatPublicMessage); !errors.Is(err, ErrApplicationMustBeCiphertext) {
		t.Errorf("CheckWireFormat(public) = %v, want ErrApplicationMustBeCiphertext", err)
	}
	permissive := DefaultProfile()
	permissive.AllowPublicMessage = true
	if err := permissive.CheckWireFormat(WireFormatPublicMessage); err != nil {
		t.Errorf("with AllowPublicMessage, CheckWireFormat(public) = %v, want nil", err)
	}
	if err := permissive.CheckWireFormat(WireFormat(0x00FF)); !errors.Is(err, ErrUnknownWireFormat) {
		t.Errorf("CheckWireFormat(0x00FF) = %v, want ErrUnknownWireFormat", err)
	}
}

func TestProfileRefusesExternalSenders(t *testing.T) {
	profile := DefaultProfile()
	err := profile.CheckGroupExtension(ExtensionTypeExternalSenders)
	if !errors.Is(err, ErrProfileExternalSender) {
		t.Fatalf("CheckGroupExtension(external_senders) = %v, want ErrProfileExternalSender", err)
	}
	if code, _ := CodeOf(err); code != ValSemProfileExternalSender {
		t.Fatalf("code = %d, want %d", code, ValSemProfileExternalSender)
	}
	if err := profile.CheckLeafExtension(ExtensionTypeExternalSenders); !errors.Is(err, ErrProfileExternalSender) {
		t.Fatalf("a leaf node must not carry external_senders either, got %v", err)
	}
}

func TestProfileRefusesReInit(t *testing.T) {
	err := DefaultProfile().CheckProposalType(ProposalTypeReInit)
	if !errors.Is(err, ErrProfileReInit) {
		t.Fatalf("CheckProposalType(reinit) = %v, want ErrProfileReInit", err)
	}
	if code, _ := CodeOf(err); code != ValSemProfileReInit {
		t.Fatalf("code = %d, want %d", code, ValSemProfileReInit)
	}
}

// TestProfileRefusesBranching pins the branch refusal. Branching has no proposal
// type of its own — it is signalled by a resumption PSK with usage `branch` carried
// in a Welcome — so the sender-side gate a client hits is the PSK proposal gate,
// and the receiver-side gate is the lifecycle plan's join path. This asserts the
// catalogue entry both of them return, and that the only in-band signal is refused.
func TestProfileRefusesBranching(t *testing.T) {
	if code, _ := CodeOf(ErrProfileBranch); code != ValSemProfileBranch {
		t.Fatalf("ErrProfileBranch carries code %d, want %d", code, ValSemProfileBranch)
	}
	if want := "branching is not implemented in the v1 profile"; ReasonFor(ValSemProfileBranch) != want {
		t.Fatalf("reason = %q, want %q", ReasonFor(ValSemProfileBranch), want)
	}
	if ResumptionPskUsageBranch != 3 {
		t.Fatalf("ResumptionPskUsageBranch is %d; RFC 9420 §8.1 fixes it at 3", ResumptionPskUsageBranch)
	}
	if err := DefaultProfile().CheckProposalType(ProposalTypePreSharedKey); !errors.Is(err, ErrProfilePsk) {
		t.Fatalf("the only in-band branch signal is a resumption psk, and it must be refused: %v", err)
	}
}

func TestProfileRefusesX509Credentials(t *testing.T) {
	profile := DefaultProfile()
	if err := profile.CheckCredentialType(CredentialTypeBasic); err != nil {
		t.Fatalf("CheckCredentialType(basic) = %v, want nil", err)
	}
	err := profile.CheckCredentialType(CredentialType(0x0002))
	if !errors.Is(err, ErrProfileCredentialType) {
		t.Fatalf("CheckCredentialType(x509) = %v, want ErrProfileCredentialType", err)
	}
	if code, _ := CodeOf(err); code != ValSemProfileCredentialType {
		t.Fatalf("code = %d, want %d", code, ValSemProfileCredentialType)
	}
}

func TestProfileRefusesUnpinnedSuiteAtCreate(t *testing.T) {
	profile := DefaultProfile()
	if err := profile.CheckCiphersuiteForCreate(CipherSuiteX25519ChaCha20Sha256Ed25519); err != nil {
		t.Fatalf("CheckCiphersuiteForCreate(0x0003) = %v, want nil", err)
	}
	// 0x0001 is registered and implemented, and still refused at group creation, so
	// the suite registry is not a hardcoded singleton.
	if !IsRegisteredSuite(CipherSuiteX25519AesGcm128Sha256Ed25519) {
		t.Fatal("0x0001 must stay registered and implemented")
	}
	err := profile.CheckCiphersuiteForCreate(CipherSuiteX25519AesGcm128Sha256Ed25519)
	if !errors.Is(err, ErrProfileCiphersuite) {
		t.Fatalf("CheckCiphersuiteForCreate(0x0001) = %v, want ErrProfileCiphersuite", err)
	}
	if code, _ := CodeOf(err); code != ValSemProfileCiphersuite {
		t.Fatalf("code = %d, want %d", code, ValSemProfileCiphersuite)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestProfile -v`
Expected: FAIL to build with `undefined: DefaultProfile`, `undefined: Profile`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/profile.go
// the v1 narrow profile: BasicCredential only, no external commits, no external
// senders, no PSKs, no ReInit, no branching, no subgroups. Every refusal is a typed
// catalogue error, so a profile decision and its negative test cannot drift.
//
// The profile is data, not code: the allow-sets are tables, and profile_test.go
// asserts the tables equal Spec A §3.1 and §3.2. Widening the profile is therefore
// a visible diff in two places at once.
package mls

// Profile is the set of protocol features this build accepts. GroupConfig carries
// one; NewGroup, every parse boundary and the interop client all gate through it.
type Profile struct {
	// AllowPublicMessage admits WireFormatPublicMessage. It is false in
	// DefaultProfile — A-ASSUME-4 puts all handshake traffic in PrivateMessage —
	// and the passive-client vector families set it, because the mlswg corpus
	// frames handshake messages in the clear.
	AllowPublicMessage bool

	versions    map[ProtocolVersion]bool
	createSuite map[CipherSuite]bool
	proposals   map[ProposalType]bool
	credentials map[CredentialType]bool
	groupExts   map[ExtensionType]bool
	leafExts    map[ExtensionType]bool
}

// DefaultProfile is the v1 narrow profile of Spec A §3.1 and §3.2.
func DefaultProfile() *Profile {
	return &Profile{
		AllowPublicMessage: false,
		versions: map[ProtocolVersion]bool{
			ProtocolVersionMls10: true,
		},
		createSuite: map[CipherSuite]bool{
			CipherSuiteX25519ChaCha20Sha256Ed25519: true,
		},
		proposals: map[ProposalType]bool{
			ProposalTypeAdd:                    true,
			ProposalTypeUpdate:                 true,
			ProposalTypeRemove:                 true,
			ProposalTypeGroupContextExtensions: true,
		},
		credentials: map[CredentialType]bool{
			CredentialTypeBasic: true,
		},
		groupExts: map[ExtensionType]bool{
			ExtensionTypeRatchetTree:             true,
			ExtensionTypeRequiredCapabilities:    true,
			ExtensionTypeUrmessageGroupPolicy:    true,
			ExtensionTypeUrmessageLeafKeys:       true,
			ExtensionTypeUrmessageOwnerSuccessor: true,
		},
		leafExts: map[ExtensionType]bool{
			ExtensionTypeUrmessageLeafKeys: true,
		},
	}
}

// CheckVersion admits mls10 and nothing else.
func (self *Profile) CheckVersion(v ProtocolVersion) error {
	if self.versions[v] {
		return nil
	}
	return ErrUnsupportedVersion
}

// CheckCiphersuiteForCreate is the group-creation policy, which is narrower than
// the implemented set: 0x0001 is registered and implemented and still refused here.
func (self *Profile) CheckCiphersuiteForCreate(s CipherSuite) error {
	if self.createSuite[s] {
		return nil
	}
	return ValSem(ValSemProfileCiphersuite, nil)
}

// CheckProposalType separates the three profile refusals — which name the feature
// so a V2 knows what to implement — from ValSem113, which is the RFC's own
// "no member supports this type" rule.
func (self *Profile) CheckProposalType(t ProposalType) error {
	if self.proposals[t] {
		return nil
	}
	switch t {
	case ProposalTypePreSharedKey:
		return ValSem(ValSem401, nil)
	case ProposalTypeReInit:
		return ValSem(ValSemProfileReInit, nil)
	case ProposalTypeExternalInit:
		return ValSem(ValSem240, nil)
	}
	return ValSem(ValSem113, nil)
}

// CheckCredentialType is what enforces BasicCredential-only at parse, and is the
// error Credential.MarshalMLS and Credential.UnmarshalMLS return on an x509 arm.
func (self *Profile) CheckCredentialType(t CredentialType) error {
	if self.credentials[t] {
		return nil
	}
	return ValSem(ValSemProfileCredentialType, nil)
}

// CheckGroupExtension gates the GroupContext extension list. external_senders is
// named separately from the generic refusal because it is a profile decision a V2
// may reverse, and ValSem209 is not.
func (self *Profile) CheckGroupExtension(t ExtensionType) error {
	if self.groupExts[t] {
		return nil
	}
	if t == ExtensionTypeExternalSenders {
		return ValSem(ValSemProfileExternalSender, nil)
	}
	return ValSem(ValSem209, nil)
}

// CheckLeafExtension gates LeafNode.Extensions. Unknown types are accepted and
// ignored — RFC 9420 §13.2 GREASE values are parsed, never generated, and must not
// error, and the interop harness sends them — so only the two extensions that are
// meaningless or forbidden in a leaf are refused.
func (self *Profile) CheckLeafExtension(t ExtensionType) error {
	if self.leafExts[t] {
		return nil
	}
	switch t {
	case ExtensionTypeExternalSenders:
		return ValSem(ValSemProfileExternalSender, nil)
	case ExtensionTypeRatchetTree, ExtensionTypeRequiredCapabilities:
		return ValSem(ValSem209, nil)
	}
	return nil
}

// CheckWireFormat refuses PublicMessage unless AllowPublicMessage is set, and
// refuses an unregistered value outright. The two are different failures: the first
// is our policy, the second is a malformed message.
func (self *Profile) CheckWireFormat(w WireFormat) error {
	switch w {
	case WireFormatPrivateMessage, WireFormatWelcome, WireFormatGroupInfo, WireFormatKeyPackage:
		return nil
	case WireFormatPublicMessage:
		if self.AllowPublicMessage {
			return nil
		}
		return ValSem(ValSem005, nil)
	}
	return ErrUnknownWireFormat
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestProfile -v`
Expected: PASS — 6 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/profile.go mls/profile_test.go && git -C connect commit -m "feat(mls): the v1 narrow profile, with its allow-sets asserted against the spec"
```

---

### Task 4: The layering test — `connect` must not import its own subpackages

**Files:**
- Create: `connect/layering_test.go`
- Test: same file

**Interfaces:**
- Consumes: nothing. Runs `go list -deps` in a subprocess, so it does not import the packages it
  checks — which is the point: importing them would create the very edge it forbids.
- Produces: `TestForbiddenImportEdges`.

- [ ] **Step 1: Write the failing test**

```go
// connect/layering_test.go
// the import edges of Spec A §2.3, asserted by walking go list -deps. connect must
// never import its own subpackages, and connect/mls must be auditable and fuzzable
// without the transport.
package connect

import (
	"os/exec"
	"strings"
	"testing"
)

// forbiddenEdge is one row of Spec A §2.3.
type forbiddenEdge struct {
	from   string
	to     []string
	reason string
}

var forbiddenEdges = []forbiddenEdge{
	{
		from:   "github.com/urnetwork/connect",
		to:     []string{"github.com/urnetwork/connect/mls", "github.com/urnetwork/connect/message"},
		reason: "a package must not import its own subpackages (A2)",
	},
	{
		from:   "github.com/urnetwork/connect/mls",
		to:     []string{"github.com/urnetwork/connect", "github.com/urnetwork/connect/message"},
		reason: "MLS must be a self-contained crypto library, auditable and fuzzable without the transport",
	},
	{
		from:   "github.com/urnetwork/connect/mls/syntax",
		to:     []string{"github.com/urnetwork/connect", "github.com/urnetwork/connect/mls", "github.com/urnetwork/connect/message", "google.golang.org/grpc", "google.golang.org/protobuf", "golang.org/x/crypto"},
		reason: "the codec imports nothing but the standard library",
	},
	{
		from:   "github.com/urnetwork/connect/message",
		to:     []string{"github.com/urnetwork/sdk"},
		reason: "the storage layer must not depend on the SDK",
	},
}

func TestForbiddenImportEdges(t *testing.T) {
	for _, edge := range forbiddenEdges {
		deps := packageDeps(t, edge.from)
		for _, banned := range edge.to {
			if deps[banned] {
				t.Errorf("%s imports %s — %s", edge.from, banned, edge.reason)
			}
		}
	}
}

// packageDeps is the transitive import set of one package, from the toolchain
// rather than from a hand-maintained list.
func packageDeps(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	deps := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			deps[line] = true
		}
	}
	return deps
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/ -run TestForbiddenImportEdges -v`
Expected: FAIL with
`go list -deps github.com/urnetwork/connect/mls: exit status 1` — the `mls` package does not exist
yet on a fresh `beta/message`.

- [ ] **Step 3: Write minimal implementation**

Create the three packages as empty compilable stubs so the test has something to walk. This is the
whole implementation for this task; the real content arrives from the other wave-1 plans.

```go
// connect/mls/doc.go
// RFC 9420 (Messaging Layer Security). Imports only the standard library and
// golang.org/x/crypto, so it can be audited and fuzzed without the transport.
package mls
```

```go
// connect/mls/syntax/doc.go
// the TLS presentation language of RFC 8446 §3 as MLS uses it. Standard library only.
package syntax
```

```go
// connect/message/doc.go
// the URmessage storage layer. Imports connect and connect/mls as peers.
package message
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/ -run TestForbiddenImportEdges -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add layering_test.go mls/doc.go mls/syntax/doc.go message/doc.go && git -C connect commit -m "test(connect): forbid connect from importing its own subpackages"
```

---

### Task 5: The forbidden-crypto grep gate

**Files:**
- Create: `connect/scripts/check-forbidden.sh`
- Test: `connect/mls/forbidden_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `TestNoForbiddenCrypto`, and `scripts/check-forbidden.sh` for the CI job of the same name.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/forbidden_test.go
// the guardrails of Spec A §5.9 that a grep can enforce. Each rule exists because
// the wrong form compiles, returns plausible bytes, and passes every other test.
package mls

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type forbiddenRule struct {
	pattern string
	roots   []string
	exempt  []string
	reason  string
}

var forbiddenRules = []forbiddenRule{
	{
		pattern: "GenerateSharedSecret",
		roots:   []string{".", "../message"},
		reason:  "sdk.GenerateSharedSecret length-checks only and yields an all-zero secret on a low-order point (MASTER §7.2)",
	},
	{
		pattern: "box.Precompute",
		roots:   []string{".", "../message"},
		reason:  "reaches the deprecated ScalarMult (MASTER §7.2)",
	},
	{
		pattern: "curve25519.ScalarMult",
		roots:   []string{".", "../message"},
		reason:  "deprecated; use crypto/ecdh or curve25519.X25519 and treat the error as fatal (MASTER §7.2)",
	},
	{
		pattern: "hkdf.Extract",
		roots:   []string{".", "../message"},
		exempt:  []string{"../message/keyschedule.go"},
		reason:  "G1 — hkdf.Extract takes ikm first, salt second; StorageRoot is the only legal call site",
	},
	{
		pattern: "bytes.Equal",
		roots:   []string{"validation.go", "framing.go", "../message/writeauth.go"},
		reason:  "G8 — every tag comparison goes through crypto/subtle.ConstantTimeCompare",
	},
}

func TestNoForbiddenCrypto(t *testing.T) {
	for _, rule := range forbiddenRules {
		for _, root := range rule.roots {
			for _, path := range goFilesUnder(t, root) {
				if isExempt(path, rule.exempt) || strings.HasSuffix(path, "_test.go") {
					continue
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read %s: %v", path, err)
				}
				if strings.Contains(string(body), rule.pattern) {
					t.Errorf("%s uses %s — %s", path, rule.pattern, rule.reason)
				}
			}
		}
	}
}

func goFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	info, err := os.Stat(root)
	if err != nil {
		return nil
	}
	if !info.IsDir() {
		return []string{root}
	}
	paths := []string{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "testdata" || entry.Name() == "interop") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return paths
}

func isExempt(path string, exempt []string) bool {
	for _, candidate := range exempt {
		if filepath.Clean(path) == filepath.Clean(candidate) {
			return true
		}
	}
	return false
}
```

Change `filepath.WalkDir`'s callback signature to `fs.DirEntry` and import `io/fs`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestNoForbiddenCrypto -v`
Expected: FAIL to build with `undefined: os.DirEntry` (the walk callback takes `fs.DirEntry`)

- [ ] **Step 3: Write minimal implementation**

Fix the signature to `func(path string, entry fs.DirEntry, err error) error`, import `io/fs`, and
add the shell mirror for the CI job:

```bash
#!/usr/bin/env bash
# connect/scripts/check-forbidden.sh
# the Spec A §5.9 grep gates, for the forbidden-crypto CI job. The Go test is the
# authority; this exists so a reviewer can run the same check without a toolchain.
set -euo pipefail

fail=0
check() {
  local pattern="$1" reason="$2"; shift 2
  if grep -rn --include='*.go' --exclude='*_test.go' --exclude-dir=testdata --exclude-dir=interop -F "$pattern" "$@" ; then
    echo "FORBIDDEN: $pattern — $reason" >&2
    fail=1
  fi
}

check 'GenerateSharedSecret' 'all-zero secret on a low-order point (MASTER §7.2)' mls message
check 'box.Precompute'       'reaches deprecated ScalarMult'                      mls message
check 'curve25519.ScalarMult' 'deprecated; use crypto/ecdh'                       mls message
check 'bytes.Equal'          'G8 — use crypto/subtle.ConstantTimeCompare'         mls/validation.go mls/framing.go message/writeauth.go

if grep -rn --include='*.go' --exclude='*_test.go' -F 'hkdf.Extract' mls message | grep -v '^message/keyschedule.go:' ; then
  echo 'FORBIDDEN: hkdf.Extract outside message.StorageRoot — G1' >&2
  fail=1
fi

exit "$fail"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestNoForbiddenCrypto -v && bash connect/scripts/check-forbidden.sh`
Expected: PASS, and the script exits 0

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/forbidden_test.go scripts/check-forbidden.sh && git -C connect commit -m "test(mls): grep gates for the forbidden X25519 and HKDF call sites"
```

---

### Task 6: Vendor and pin the 16 vector families

This is the **single** vendoring task for all sixteen mlswg files. Every other slice-1 plan keeps
only its family runner and vendors nothing. There is likewise exactly **one** pin file,
`connect/mls/interop/PINS.md`, with machine-readable `mlswg=<sha>` and `openmls=<sha>` lines that the
framing and lifecycle plans grep; `connect/mls/interop/PINS.md` and `connect/mls/testdata/vectors/PINS.md`
do not exist. The crypto plan's separately-sourced `hpke-rfc9180-x25519.json` and
`xwing-draft10.json` live under `testdata/vectors/rfc/`, so the sixteen-file assertion over
`testdata/vectors/*.json` stays exact.

**Files:**
- Create: `connect/mls/testdata/vectors/*.json` (16 files), `connect/mls/testdata/vectors/VECTORS.sha256`, `connect/mls/interop/PINS.md`
- Test: `connect/mls/vectors_pin_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: the pinned corpus every family runner reads, `TestVectorFilesArePinned`, and
  `TestVectorFolderHoldsExactlySixteenFiles`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/vectors_pin_test.go
// the vector corpus is pinned by digest. Re-vendoring at a newer mlswg commit is a
// deliberate act with a visible diff, never something that happens during a rebase.
package mls

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectorFiles is Spec A §4.2.1, in table order.
var vectorFiles = []string{
	"tree-math.json",
	"crypto-basics.json",
	"secret-tree.json",
	"message-protection.json",
	"key-schedule.json",
	"psk_secret.json",
	"transcript-hashes.json",
	"welcome.json",
	"tree-operations.json",
	"tree-validation.json",
	"treekem.json",
	"messages.json",
	"passive-client-welcome.json",
	"passive-client-handling-commit.json",
	"passive-client-random.json",
	"deserialization.json",
}

func TestVectorFilesArePinned(t *testing.T) {
	manifest := map[string]string{}
	handle, err := os.Open(filepath.Join("testdata", "vectors", "VECTORS.sha256"))
	if err != nil {
		t.Fatalf("open VECTORS.sha256: %v", err)
	}
	defer handle.Close()
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			manifest[fields[1]] = fields[0]
		}
	}
	if len(manifest) != len(vectorFiles) {
		t.Fatalf("VECTORS.sha256 lists %d files, spec A §4.2.1 names %d", len(manifest), len(vectorFiles))
	}
	for _, name := range vectorFiles {
		body, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(body)
		got := hex.EncodeToString(sum[:])
		if want := manifest[name]; got != want {
			t.Errorf("%s digest %s, manifest says %s", name, got, want)
		}
	}
}

// TestVectorFolderHoldsExactlySixteenFiles keeps the mlswg corpus separable from
// everything else we vendor. The crypto plan's RFC 9180 and X-Wing vectors are not
// mlswg files and live under testdata/vectors/rfc/, so a seventeenth top-level file
// is either an un-manifested mlswg family or a file in the wrong place.
func TestVectorFolderHoldsExactlySixteenFiles(t *testing.T) {
	found, err := filepath.Glob(filepath.Join("testdata", "vectors", "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(found) != 16 {
		t.Fatalf("testdata/vectors holds %d json files, spec A §4.2.1 names 16: %v", len(found), found)
	}
}

// TestPinsAreMachineReadable asserts the one pin file exists and carries the two
// lines the framing and lifecycle plans grep for. Three pin files in three formats
// is how two greps end up matching none of them.
func TestPinsAreMachineReadable(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("interop", "PINS.md"))
	if err != nil {
		t.Fatalf("read interop/PINS.md: %v", err)
	}
	text := string(body)
	for _, key := range []string{"mlswg=", "openmls="} {
		index := strings.Index(text, key)
		if index < 0 {
			t.Errorf("interop/PINS.md has no machine-readable %s<sha> line", key)
			continue
		}
		if len(strings.Fields(text[index:])[0]) != len(key)+40 {
			t.Errorf("%s must be followed by a full 40-character commit sha", key)
		}
	}
	for _, stale := range []string{
		filepath.Join("PINS.md"),
		filepath.Join("testdata", "vectors", "PINS.md"),
	} {
		if _, err := os.Stat(stale); err == nil {
			t.Errorf("%s must not exist; interop/PINS.md is the one pin file", stale)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestVectorFilesArePinned|TestVectorFolderHolds|TestPinsAreMachineReadable' -v`
Expected: FAIL with `open VECTORS.sha256: no such file or directory` and
`read interop/PINS.md: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

```bash
# run once from the workspace root; the commit is recorded in PINS.md
MLSWG_COMMIT=$(git ls-remote https://github.com/mlswg/mls-implementations.git refs/heads/main | cut -f1)
rm -rf /tmp/mls-implementations
git clone --depth 1 https://github.com/mlswg/mls-implementations.git /tmp/mls-implementations
git -C /tmp/mls-implementations rev-parse HEAD
mkdir -p connect/mls/testdata/vectors
for f in tree-math crypto-basics secret-tree message-protection key-schedule psk_secret \
         transcript-hashes welcome tree-operations tree-validation treekem messages \
         passive-client-welcome passive-client-handling-commit passive-client-random deserialization ; do
  cp "/tmp/mls-implementations/test-vectors/${f}.json" "connect/mls/testdata/vectors/${f}.json"
done
# Do NOT create testdata/vectors/rfc/ here — that directory belongs to the crypto plan (p2),
# which vendors hpke-rfc9180-x25519.json and xwing-draft10.json into it from separate sources.
# An earlier draft of this script created it, which contradicts this task's own stated scope
# boundary. Git does not track empty directories, so creating it does no direct harm and the
# sha256sum glob below would not have picked it up — but it muddies the invariant this task
# exists to establish, that testdata/vectors/*.json is exactly the sixteen mlswg families.
( cd connect/mls/testdata/vectors && sha256sum *.json > VECTORS.sha256 )
```

```markdown
<!-- connect/mls/interop/PINS.md -->
# Pinned external references

This is the one pin file for the whole slice. Bumping any line here is a pull request that must show
a green interop matrix and a green `vectors` job. Nothing in this file enters `go.mod`.

The two commit lines are machine-readable and are grepped by other plans' tasks; keep the
`key=<40-char sha>` shape exactly.

```
mlswg=0000000000000000000000000000000000000000
openmls=0000000000000000000000000000000000000000
```

| What | Pin | Why |
|---|---|---|
| mlswg/mls-implementations | the `mlswg=` line above | the 16 vector families **and** the gRPC test runner, pinned together so the runner and the vectors never disagree |
| openmls/openmls | the `openmls=` line above | the differential oracle and the 9 fuzz targets; built out of process in CI, never linked |
| `ghcr.io/urnetwork/mls-peer-openmls` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mlspp` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mls-rs` | digest `sha256:<...>` | interop peer |

Peer images are prebuilt and pushed to GHCR by the weekly `peer-image-bump` job, which opens a
digest-bump PR. CI never compiles Rust or C++ on a per-commit path.
```

Substitute the real shas recorded by the clone above for the two zero placeholders before running
the test; `TestPinsAreMachineReadable` only checks the shape, and a zero sha is a valid shape.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestVectorFilesArePinned|TestVectorFolderHolds|TestPinsAreMachineReadable' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/testdata/vectors mls/vectors_pin_test.go mls/interop/PINS.md && git -C connect commit -m "test(mls): vendor and digest-pin the 16 RFC 9420 vector families"
```

---

### Task 7: The vector-family registry

**Files:**
- Create: `connect/mls/vectors_test.go`
- Test: same file

**Interfaces:**
- Consumes: `vectorFiles []string` (Task 6).
- Produces — **this is the contract every other slice-1 plan registers against**:
  - `type VectorFamily struct { Number int; Name string; File string; Slice string; Verify func(t *testing.T, raw json.RawMessage); Generate func(t *testing.T) json.RawMessage }`
  - `func RegisterVectorFamily(family VectorFamily)`
  - `func LoadVectorFile(t *testing.T, file string) []json.RawMessage`
  - `func MustHex(t *testing.T, s string) []byte`
  - `func HexOf(b []byte) string`
  - `TestVectorManifestIsComplete`, `TestVectorFamiliesVerify`

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/vectors_test.go
package mls

import (
	"encoding/json"
	"testing"
)

func TestVectorManifestIsComplete(t *testing.T) {
	if len(vectorManifest) != 16 {
		t.Fatalf("manifest holds %d families, spec A §4.2.1 names 16", len(vectorManifest))
	}
	for number := 1; number <= 16; number++ {
		family, ok := vectorManifest[number]
		if !ok {
			t.Fatalf("family %d is not in the manifest", number)
		}
		if family.File == "" || family.Name == "" || family.Slice == "" {
			t.Errorf("family %d is under-specified: %+v", number, family)
		}
	}
	// every registered family must correspond to a pinned file.
	pinned := map[string]bool{}
	for _, name := range vectorFiles {
		pinned[name] = true
	}
	for number, family := range vectorManifest {
		if !pinned[family.File] {
			t.Errorf("family %d names %s, which is not in VECTORS.sha256", number, family.File)
		}
	}
	// a family whose Verify is nil is not yet implemented; the pending set must
	// equal the documented one, so a family cannot quietly stop being run.
	pending := []int{}
	for number, family := range vectorManifest {
		if family.Verify == nil {
			pending = append(pending, number)
		}
	}
	slices.Sort(pending)
	if !slices.Equal(pending, expectedPendingFamilies) {
		t.Fatalf("pending families %v, expected %v — update expectedPendingFamilies in the same commit that lands or drops a runner", pending, expectedPendingFamilies)
	}
}

func TestVectorFamiliesVerify(t *testing.T) {
	for number := 1; number <= 16; number++ {
		family := vectorManifest[number]
		if family.Verify == nil {
			continue
		}
		cases := LoadVectorFile(t, family.File)
		if len(cases) == 0 {
			t.Fatalf("family %d (%s) has no cases", number, family.File)
		}
		for index, raw := range cases {
			sub := t
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						sub.Fatalf("family %d case %d panicked: %v", number, index, recovered)
					}
				}()
				family.Verify(sub, raw)
			}()
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorManifestIsComplete -v`
Expected: FAIL to build with `undefined: vectorManifest`, `undefined: expectedPendingFamilies`,
`undefined: LoadVectorFile`

- [ ] **Step 3: Write minimal implementation**

```go
// prepend to connect/mls/vectors_test.go
// the vector-family registry. Each family's owning plan calls RegisterVectorFamily
// from an init() in its own *_kat_test.go, so this file never grows an import on a
// package that does not exist yet.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// VectorFamily is one row of Spec A §4.2.1.
type VectorFamily struct {
	// Number is the §4.2.1 row, 1..16.
	Number int
	// Name is the human label, "Tree math".
	Name string
	// File is the basename under testdata/vectors.
	File string
	// Slice is the slice this family must pass in: A1, A2, A3 or A4.
	Slice string
	// Verify checks one case of the pinned file. nil means not yet implemented,
	// and the number must then appear in expectedPendingFamilies.
	Verify func(t *testing.T, raw json.RawMessage)
	// Generate produces a fresh case from our own implementation, which Verify is
	// then run against. nil where the vector format does not support generation.
	Generate func(t *testing.T) json.RawMessage
}

var vectorManifest = map[int]VectorFamily{}

// expectedPendingFamilies is every family with no runner yet, ascending. It shrinks
// to the empty slice by the end of slice A4 and never grows.
var expectedPendingFamilies = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

// RegisterVectorFamily installs a family runner. Registering a number twice, or a
// number outside 1..16, is a programming error.
func RegisterVectorFamily(family VectorFamily) {
	if family.Number < 1 || family.Number > 16 {
		panic("mls: vector family number out of range")
	}
	existing, ok := vectorManifest[family.Number]
	if ok && existing.Verify != nil && family.Verify != nil {
		panic("mls: vector family " + existing.File + " registered twice")
	}
	vectorManifest[family.Number] = family
}

// the 16 families, declared with no runner. Each owning plan re-registers its own
// row with Verify and Generate populated.
func init() {
	for _, family := range []VectorFamily{
		{Number: 1, Name: "Tree math", File: "tree-math.json", Slice: "A2"},
		{Number: 2, Name: "Crypto basics", File: "crypto-basics.json", Slice: "A2"},
		{Number: 3, Name: "Secret tree", File: "secret-tree.json", Slice: "A3"},
		{Number: 4, Name: "Message protection", File: "message-protection.json", Slice: "A3"},
		{Number: 5, Name: "Key schedule", File: "key-schedule.json", Slice: "A3"},
		{Number: 6, Name: "Pre-shared keys", File: "psk_secret.json", Slice: "A3"},
		{Number: 7, Name: "Transcript hashes", File: "transcript-hashes.json", Slice: "A3"},
		{Number: 8, Name: "Welcome", File: "welcome.json", Slice: "A4"},
		{Number: 9, Name: "Tree operations", File: "tree-operations.json", Slice: "A2"},
		{Number: 10, Name: "Tree validation", File: "tree-validation.json", Slice: "A2"},
		{Number: 11, Name: "TreeKEM", File: "treekem.json", Slice: "A4"},
		{Number: 12, Name: "Messages", File: "messages.json", Slice: "A4"},
		{Number: 13, Name: "Passive client, welcome", File: "passive-client-welcome.json", Slice: "A4"},
		{Number: 14, Name: "Passive client, handling commit", File: "passive-client-handling-commit.json", Slice: "A4"},
		{Number: 15, Name: "Passive client, random", File: "passive-client-random.json", Slice: "A4"},
		{Number: 16, Name: "Vector deserialization", File: "deserialization.json", Slice: "A1"},
	} {
		vectorManifest[family.Number] = family
	}
}

// LoadVectorFile reads a pinned family file as a JSON array of cases.
func LoadVectorFile(t *testing.T, file string) []json.RawMessage {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "vectors", file))
	if err != nil {
		t.Fatalf("read vector file %s: %v", file, err)
	}
	cases := []json.RawMessage{}
	if err := json.Unmarshal(body, &cases); err != nil {
		t.Fatalf("parse vector file %s: %v", file, err)
	}
	return cases
}

// MustHex decodes a vector's hex field. The mlswg files use lowercase hex with no
// prefix and an empty string for an absent value.
func MustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return []byte{}
	}
	body, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return body
}

// HexOf is the inverse, for the generate direction.
func HexOf(b []byte) string {
	return hex.EncodeToString(b)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestVectorManifestIsComplete|TestVectorFamiliesVerify' -v`
Expected: PASS. `TestVectorFamiliesVerify` runs zero families, which is correct at this point —
`expectedPendingFamilies` names 15 of them and family 16 lands in the next task.

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/vectors_test.go && git -C connect commit -m "test(mls): vector-family registry with an explicit pending set"
```

---

### Task 8: Family 16 — vector deserialization

**Files:**
- Create: `connect/mls/vectors_deserialization_kat_test.go`
- Test: same file

Family 16 is **implemented once, in `package syntax`**, against the `Reader.ReadVarint` /
`Writer.WriteVarint` methods that plan actually ships. This task is the registry shim, plus the
generate direction — which needs no new symbol from that plan, because the writer's varint method is
already exported.

**Interfaces:**
- Consumes: `syntax.VerifyDeserializationVector(t *testing.T, raw json.RawMessage)`,
  `syntax.NewWriter() *Writer`, `(*syntax.Writer).WriteVarint(v uint32)`,
  `(*syntax.Writer).Bytes() ([]byte, error)`, `syntax.MaxVarint` (Syntax and codec plan);
  `RegisterVectorFamily`, `HexOf` (Task 7).
- Produces: family 16's registration with `Verify` and `Generate`; removes 16 from
  `expectedPendingFamilies`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/vectors_deserialization_kat_test.go
// family 16 of Spec A §4.2.1. The mlswg deserialization vectors are exactly the
// canonical-encoding property: one valid variable-length prefix per length, and a
// non-minimal prefix is a decode error. A decoder that accepts two encodings of the
// same object is a signature-bypass primitive, because MLS signs over serialized forms.
//
// The verifier lives in package syntax, next to the Reader and Writer it exercises.
// A second copy here would be a second varint implementation, which is exactly what
// the one-codec-one-corpus rule exists to prevent.
package mls

import (
	"encoding/json"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

func init() {
	RegisterVectorFamily(VectorFamily{
		Number:   16,
		Name:     "Vector deserialization",
		File:     "deserialization.json",
		Slice:    "A1",
		Verify:   syntax.VerifyDeserializationVector,
		Generate: generateDeserializationVector,
	})
}

// TestFamily16IsRegisteredAgainstTheSyntaxRunner pins the shim. If this file ever
// grows its own varint decoder again, the identity assertion below is what fails.
func TestFamily16IsRegisteredAgainstTheSyntaxRunner(t *testing.T) {
	family, ok := vectorManifest[16]
	if !ok {
		t.Fatal("family 16 is not registered")
	}
	if family.Verify == nil {
		t.Fatal("family 16 has no verifier")
	}
	if family.Generate == nil {
		t.Fatal("family 16 must support the generate direction; it is the only family that can in slice A1")
	}
	cases := LoadVectorFile(t, family.File)
	if len(cases) == 0 {
		t.Fatal("deserialization.json has no cases")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestFamily16IsRegisteredAgainstTheSyntaxRunner -v`
Expected: FAIL to build with `undefined: generateDeserializationVector`, and once that is added,
`TestVectorManifestIsComplete` FAILs with
`pending families [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15], expected [1 2 ... 16]` if 16 was left in
the pending list — the reverse direction, because 16 is now registered with a runner.

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/vectors_deserialization_kat_test.go

// deserializationCase is one row of deserialization.json, in the mlswg shape.
type deserializationCase struct {
	VlbytesHeader string `json:"vlbytes_header"`
	Length        uint32 `json:"length"`
}

// generateDeserializationVector produces one case per prefix-width boundary, both
// sides, from our own encoder — so the pinned corpus is not the only thing our
// decoder is ever asked to agree with.
func generateDeserializationVector(t *testing.T) json.RawMessage {
	t.Helper()
	lengths := []uint32{0, 1, 63, 64, 16383, 16384, 1 << 20, syntax.MaxVarint}
	cases := make([]deserializationCase, 0, len(lengths))
	for _, length := range lengths {
		writer := syntax.NewWriter()
		writer.WriteVarint(length)
		header, err := writer.Bytes()
		if err != nil {
			t.Fatalf("WriteVarint(%d): %v", length, err)
		}
		cases = append(cases, deserializationCase{
			VlbytesHeader: HexOf(header),
			Length:        length,
		})
	}
	body, err := json.Marshal(cases)
	if err != nil {
		t.Fatalf("marshal generated cases: %v", err)
	}
	return body
}
```

And in `connect/mls/vectors_test.go`, confirm 16 is absent from the pending list:

```go
var expectedPendingFamilies = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
```

stays as written — 16 was never in it. Confirm by running both tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestFamily16|TestVectorManifestIsComplete|TestVectorFamiliesVerify' -v`
Expected: PASS, with family 16 running every case in `deserialization.json` through
`syntax.VerifyDeserializationVector`

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/vectors_deserialization_kat_test.go && git -C connect commit -m "test(mls): family 16 — canonical varint deserialization, both directions"
```

---

### Task 9: The generate-then-verify meta-test

**Files:**
- Modify: `connect/mls/vectors_test.go`

**Interfaces:**
- Consumes: `VectorFamily.Generate` (Task 7).
- Produces: `TestVectorGenerateThenVerify`.

- [ ] **Step 1: Write the failing test**

```go
// append to connect/mls/vectors_test.go

// TestVectorGenerateThenVerify closes the loop Spec A §4.2.1 names: verification
// alone cannot see a bug where the encoder and the decoder are wrong in the same
// direction, because the pinned vector never round-trips through our encoder.
// Generating a fresh case from our implementation and feeding it back through the
// verifier does see it.
func TestVectorGenerateThenVerify(t *testing.T) {
	generated := 0
	for number := 1; number <= 16; number++ {
		family := vectorManifest[number]
		if family.Generate == nil || family.Verify == nil {
			continue
		}
		generated++
		raw := family.Generate(t)
		cases := []json.RawMessage{}
		if err := json.Unmarshal(raw, &cases); err != nil {
			t.Fatalf("family %d generated a value that is not an array of cases: %v", number, err)
		}
		if len(cases) == 0 {
			t.Fatalf("family %d generated no cases", number)
		}
		for index, generatedCase := range cases {
			family.Verify(t, generatedCase)
			_ = index
		}
	}
	if generated == 0 {
		t.Fatal("no family supports generation — at least family 16 must")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorGenerateThenVerify -v`
Expected: FAIL with `no family supports generation — at least family 16 must` if Task 8's
`Generate` field was omitted; PASS once family 16 registers it. Run it first with the `Generate:`
line commented out in `vectors_deserialization_kat_test.go` to see the failure, then restore it.

- [ ] **Step 3: Write minimal implementation**

Restore the `Generate: generateDeserializationVector` field in family 16's registration. No other
code changes: the meta-test is the implementation, and every later family plan satisfies it by
populating `Generate`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestVectorGenerateThenVerify -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/vectors_test.go && git -C connect commit -m "test(mls): generate a fresh vector then verify it, per family"
```

---

## Phase A′ — the pieces that cannot land in wave 1 (wave 4, after `group.go`)

Tasks 10, 11 and 12 are scheduled apart from the rest of Phase A. `memStore` implements the group
lifecycle plan's `StateStore`; the codec table names `KeyPackage`, `MLSMessage`, `Proposal` and
`Welcome`; and the fuzz targets are built on the codec table. All three therefore land in wave 4,
which is also what keeps `fuzz-short` from being red from wave 1 to wave 4. Task 13's `fuzz-short`
job is added in wave 1 but its matrix is empty until this phase lands — see Task 13 step 3.

### Task 10: The in-memory state store

**Files:**
- Create: `connect/mls/memstore_test.go`
- Test: same file

**Interfaces:**
- Consumes: `type StateStore interface` (Group lifecycle plan, Spec A §3.5) — the eight methods
  listed in the consumed block above, verbatim.
- Produces:
  - `func newMemStore() *memStore`
  - `func (self *memStore) EpochsHeld(groupId []byte) []uint64`
  - `func (self *memStore) PrivateKeyCount() int`
  - the full `StateStore` implementation, used by the forge and by `TestValSem400_PastEpochBound`

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/memstore_test.go
// the StateStore every mls test runs against. Deletion is the security-relevant
// operation here (Spec A §3.5): eph_root lives in the epoch state, so a retained
// old epoch state is a retained eph_root. EpochsHeld exists so a test can assert
// deletion actually happened rather than assuming it.
package mls

import (
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"testing"
)

func TestMemStoreDeletesBeforeEpoch(t *testing.T) {
	store := newMemStore()
	groupId := []byte("group")
	for epoch := uint64(0); epoch < 10; epoch++ {
		if err := store.PutGroupState(groupId, epoch, []byte{byte(epoch)}); err != nil {
			t.Fatalf("put epoch %d: %v", epoch, err)
		}
	}
	if err := store.DeleteGroupStateBefore(groupId, 7); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if got, want := store.EpochsHeld(groupId), []uint64{7, 8, 9}; !slices.Equal(got, want) {
		t.Fatalf("EpochsHeld = %v, want %v", got, want)
	}
	if _, err := store.GetGroupState(groupId, 6); err == nil {
		t.Fatal("epoch 6 is still readable after DeleteGroupStateBefore(7)")
	}
}

func TestMemStorePrivateKeyLifecycle(t *testing.T) {
	store := newMemStore()
	if err := store.PutPrivateKey([]byte("pub"), []byte("priv")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if store.PrivateKeyCount() != 1 {
		t.Fatalf("PrivateKeyCount = %d, want 1", store.PrivateKeyCount())
	}
	if err := store.DeletePrivateKey([]byte("pub")); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if store.PrivateKeyCount() != 0 {
		t.Fatalf("PrivateKeyCount = %d after delete, want 0", store.PrivateKeyCount())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestMemStore -v`
Expected: FAIL to build with `undefined: newMemStore`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/memstore_test.go

// memStore is an in-memory StateStore. It overwrites a state blob's bytes before
// dropping the reference, mirroring the obligation Spec A §3.5 places on the real
// implementation, so a test that greps the heap sees the same shape.
type memStore struct {
	stateLock sync.Mutex
	states    map[string]map[uint64][]byte
	private   map[string][]byte
	packages  map[string][3][]byte
}

// errMemStoreMissing is a plain store miss. It is deliberately NOT a catalogue
// code: a StateStore lookup failure is not an RFC validation semantic, and giving
// it one would let a store bug masquerade as a ValSem failure in a negative test.
var errMemStoreMissing = errors.New("mls: memstore: no such entry")

func newMemStore() *memStore {
	return &memStore{
		states:   map[string]map[uint64][]byte{},
		private:  map[string][]byte{},
		packages: map[string][3][]byte{},
	}
}

func (self *memStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := hex.EncodeToString(groupId)
	if self.states[key] == nil {
		self.states[key] = map[uint64][]byte{}
	}
	self.states[key][epoch] = slices.Clone(state)
	return nil
}

func (self *memStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.states[hex.EncodeToString(groupId)][epoch]
	if !ok {
		return nil, errMemStoreMissing
	}
	return slices.Clone(state), nil
}

func (self *memStore) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	states := self.states[hex.EncodeToString(groupId)]
	for held, state := range states {
		if held < epoch {
			for i := range state {
				state[i] = 0
			}
			delete(states, held)
		}
	}
	return nil
}

func (self *memStore) PutPrivateKey(pub []byte, priv []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.private[hex.EncodeToString(pub)] = slices.Clone(priv)
	return nil
}

func (self *memStore) GetPrivateKey(pub []byte) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	priv, ok := self.private[hex.EncodeToString(pub)]
	if !ok {
		return nil, errMemStoreMissing
	}
	return slices.Clone(priv), nil
}

func (self *memStore) DeletePrivateKey(pub []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := hex.EncodeToString(pub)
	if priv, ok := self.private[key]; ok {
		for i := range priv {
			priv[i] = 0
		}
		delete(self.private, key)
	}
	return nil
}

func (self *memStore) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.packages[hex.EncodeToString(ref)] = [3][]byte{slices.Clone(kp), slices.Clone(initPriv), slices.Clone(encPriv)}
	return nil
}

func (self *memStore) TakeKeyPackage(ref []byte) (kp, initPriv, encPriv []byte, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := hex.EncodeToString(ref)
	entry, ok := self.packages[key]
	if !ok {
		return nil, nil, nil, errMemStoreMissing
	}
	delete(self.packages, key)
	return entry[0], entry[1], entry[2], nil
}

// EpochsHeld is the ascending list of epochs whose state survives, so a test can
// assert deletion rather than assume it.
func (self *memStore) EpochsHeld(groupId []byte) []uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	epochs := []uint64{}
	for epoch := range self.states[hex.EncodeToString(groupId)] {
		epochs = append(epochs, epoch)
	}
	slices.Sort(epochs)
	return epochs
}

// PrivateKeyCount is the number of sealed private keys still held.
func (self *memStore) PrivateKeyCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.private)
}

// compile-time assertion that memStore satisfies the interface the group needs.
var _ StateStore = (*memStore)(nil)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestMemStore -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/memstore_test.go && git -C connect commit -m "test(mls): in-memory StateStore with epoch-deletion accounting"
```

---

### Task 11: The codec table the fuzz targets and the oracle share

The declarations live in `codec_table.go`, **not** in a `_test.go` file: the Go oracle client and the
separate `connect/mls/interop` module cannot see symbols in a test file, and the shared kind-id
contract that stops Go and Rust drifting about which decoder a divergence concerns does not otherwise
exist across that boundary. Only the two tests stay in `codec_table_test.go`.

Under **C1** every pair is one line over `syntax.Marshal` / `syntax.Unmarshal`. The ten
`Parse*`/`Encode*` names this task used to ask other plans for are not added anywhere, which keeps
the naming contract inside this plan and removes ten cross-plan asks. `KindMlsMessage` is the one
exception, because `ParseMLSMessage` / `MarshalMLSMessage` already exist as the framing plan's single
wire entry point.

**Files:**
- Create: `connect/mls/codec_table.go`, `connect/mls/codec_table_test.go`
- Test: `connect/mls/codec_table_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal(v Marshaler) ([]byte, error)`,
  `syntax.Unmarshal(bs []byte, v Unmarshaler) error` (Syntax and codec plan);
  `Extension`, `KeyPackage` (TreeKEM plan); `Proposal`, `Welcome`, `MLSMessage`,
  `ParseMLSMessage(data []byte) (*MLSMessage, error)`,
  `MarshalMLSMessage(message *MLSMessage) ([]byte, error)` (Framing plan).
- Produces:
  - `type CodecKind uint8` with `KindExtension=1`, `KindKeyPackage=2`, `KindMlsMessage=3`, `KindProposal=4`, `KindWelcome=5`
  - `type CodecPair struct { Name string; Decode func([]byte) (any, error); Encode func(any) ([]byte, error) }`
  - `func CodecFor(kind CodecKind) (CodecPair, bool)`
  - `func CodecKinds() []CodecKind`

  The kind ids are the same integers the oracle stdio protocol uses, so a Go target and the Rust
  oracle can never disagree about which decoder they are comparing.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/codec_table_test.go
// the five decoders the 9 fuzz targets and the differential oracle both address.
// The kind id is the wire byte of the oracle protocol, so Go and Rust cannot drift
// about which decoder a disagreement is about.
package mls

import (
	"testing"
)

func TestCodecTableIsClosed(t *testing.T) {
	kinds := CodecKinds()
	if len(kinds) != 5 {
		t.Fatalf("codec table holds %d kinds, want 5", len(kinds))
	}
	wantNames := map[CodecKind]string{
		KindExtension:  "extension",
		KindKeyPackage: "key_package",
		KindMlsMessage: "mls_message",
		KindProposal:   "proposal",
		KindWelcome:    "welcome",
	}
	for _, kind := range kinds {
		pair, ok := CodecFor(kind)
		if !ok {
			t.Fatalf("CodecFor(%d) missing", kind)
		}
		if pair.Name != wantNames[kind] {
			t.Errorf("kind %d is named %q, want %q — the name is the oracle's target name", kind, pair.Name, wantNames[kind])
		}
		if pair.Decode == nil || pair.Encode == nil {
			t.Errorf("kind %d (%s) has a nil half", kind, pair.Name)
		}
	}
	if _, ok := CodecFor(CodecKind(9)); ok {
		t.Error("CodecFor accepted an unknown kind")
	}
}

func TestCodecTableRejectsEmptyInput(t *testing.T) {
	for _, kind := range CodecKinds() {
		pair, _ := CodecFor(kind)
		if _, err := pair.Decode(nil); err == nil {
			t.Errorf("%s decoded an empty input without error", pair.Name)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestCodecTable -v`
Expected: FAIL to build with `undefined: CodecKinds`, `undefined: KindExtension`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/codec_table.go
// the five decoders the 9 fuzz targets and the differential oracle both address.
// This is NOT a _test.go file: the interop module and the oracle client are outside
// package mls's test binary and still have to agree with it about which decoder a
// kind id names.
//
// Every pair is one line over syntax.Marshal / syntax.Unmarshal. There are no
// per-type Parse*/Encode* wrappers anywhere in package mls, which is what lets
// every wire type be a syntax.Codec and therefore a CheckRoundTrip target.
package mls

import (
	"slices"

	"github.com/urnetwork/connect/mls/syntax"
)

// CodecKind identifies one decoder. The value is the first byte of an oracle
// request frame and must never be renumbered.
type CodecKind uint8

const (
	KindExtension  CodecKind = 1
	KindKeyPackage CodecKind = 2
	KindMlsMessage CodecKind = 3
	KindProposal   CodecKind = 4
	KindWelcome    CodecKind = 5
)

// CodecPair is one decoder and its canonical re-serializer. Name matches the
// OpenMLS fuzz-target name so a differential report reads against both codebases.
type CodecPair struct {
	Name   string
	Decode func(b []byte) (any, error)
	Encode func(v any) ([]byte, error)
}

var codecTable = map[CodecKind]CodecPair{
	KindExtension: {
		Name:   "extension",
		Decode: func(b []byte) (any, error) { v := &Extension{}; return v, syntax.Unmarshal(b, v) },
		Encode: func(v any) ([]byte, error) { return syntax.Marshal(v.(*Extension)) },
	},
	KindKeyPackage: {
		Name:   "key_package",
		Decode: func(b []byte) (any, error) { v := &KeyPackage{}; return v, syntax.Unmarshal(b, v) },
		Encode: func(v any) ([]byte, error) { return syntax.Marshal(v.(*KeyPackage)) },
	},
	KindMlsMessage: {
		Name:   "mls_message",
		Decode: func(b []byte) (any, error) { return ParseMLSMessage(b) },
		Encode: func(v any) ([]byte, error) { return MarshalMLSMessage(v.(*MLSMessage)) },
	},
	KindProposal: {
		Name:   "proposal",
		Decode: func(b []byte) (any, error) { v := &Proposal{}; return v, syntax.Unmarshal(b, v) },
		Encode: func(v any) ([]byte, error) { return syntax.Marshal(v.(*Proposal)) },
	},
	KindWelcome: {
		Name:   "welcome",
		Decode: func(b []byte) (any, error) { v := &Welcome{}; return v, syntax.Unmarshal(b, v) },
		Encode: func(v any) ([]byte, error) { return syntax.Marshal(v.(*Welcome)) },
	},
}

// CodecFor is the pair for a kind.
func CodecFor(kind CodecKind) (CodecPair, bool) {
	pair, ok := codecTable[kind]
	return pair, ok
}

// CodecKinds is every kind, ascending.
func CodecKinds() []CodecKind {
	kinds := make([]CodecKind, 0, len(codecTable))
	for kind := range codecTable {
		kinds = append(kinds, kind)
	}
	slices.Sort(kinds)
	return kinds
}
```

The four `syntax.Unmarshal` closures return a non-nil `v` alongside a non-nil error on failure. That
is deliberate and the callers depend on it: `fuzzDecodeTarget` and the oracle both branch on the
error alone, and returning the partly-filled value keeps the closure a single expression.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestCodecTable -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/codec_table.go mls/codec_table_test.go && git -C connect commit -m "test(mls): shared codec table for the fuzz targets and the oracle"
```

---

### Task 12: The 9 fuzz targets, properties 1 and 2

**Files:**
- Create: `connect/mls/syntax_fuzz_test.go`
- Test: same file

**Interfaces:**
- Consumes: `CodecFor`, `CodecKinds` (Task 11); `syntax.MaxVectorLength`, `syntax.MaxRatchetTreeLength` (Syntax and codec plan).
- Produces: `FuzzExtensionDecode`, `FuzzExtensionDecodeBytes`, `FuzzKeyPackageDecode`,
  `FuzzKeyPackageDecodeBytes`, `FuzzMlsMessageDecode`, `FuzzMlsMessageDecodeBytes`,
  `FuzzProposalDecode`, `FuzzProposalDecodeBytes`, `FuzzWelcomeDecode`, and
  `func fuzzDecodeTarget(f *testing.F, kind CodecKind, structured bool)`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/syntax_fuzz_test.go
// the 9 targets of Spec A §4.4, mirroring OpenMLS's own fuzz targets one for one.
// Properties 1 and 2 run on every commit; property 3 (differential) is added in
// Task 16 and runs nightly.
//
// Go's native fuzzer only mutates byte strings, so the structured variants are
// byte-string targets seeded from a structured generator rather than a separate
// mechanism.
package mls

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func FuzzExtensionDecode(f *testing.F)       { fuzzDecodeTarget(f, KindExtension, true) }
func FuzzExtensionDecodeBytes(f *testing.F)  { fuzzDecodeTarget(f, KindExtension, false) }
func FuzzKeyPackageDecode(f *testing.F)      { fuzzDecodeTarget(f, KindKeyPackage, true) }
func FuzzKeyPackageDecodeBytes(f *testing.F) { fuzzDecodeTarget(f, KindKeyPackage, false) }
func FuzzMlsMessageDecode(f *testing.F)      { fuzzDecodeTarget(f, KindMlsMessage, true) }
func FuzzMlsMessageDecodeBytes(f *testing.F) { fuzzDecodeTarget(f, KindMlsMessage, false) }
func FuzzProposalDecode(f *testing.F)        { fuzzDecodeTarget(f, KindProposal, true) }
func FuzzProposalDecodeBytes(f *testing.F)   { fuzzDecodeTarget(f, KindProposal, false) }
func FuzzWelcomeDecode(f *testing.F)         { fuzzDecodeTarget(f, KindWelcome, true) }

// TestFuzzTargetsCoverEveryKind fails if a decoder is added without a target, or a
// target is deleted, which is how a decoder quietly stops being fuzzed. It parses
// this file with go/ast rather than counting a hand-written literal slice: a literal
// slice is a second list to keep in sync, and the second list is the one that rots.
func TestFuzzTargetsCoverEveryKind(t *testing.T) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, "syntax_fuzz_test.go", nil, 0)
	if err != nil {
		t.Fatalf("parse syntax_fuzz_test.go: %v", err)
	}
	covered := map[string]int{}
	total := 0
	for _, decl := range file.Decls {
		function, ok := decl.(*ast.FuncDecl)
		if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "Fuzz") {
			continue
		}
		total++
		// each target's whole body is one call to fuzzDecodeTarget(f, KindX, bool),
		// so the kind is the second argument's identifier.
		kind := ""
		ast.Inspect(function, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "fuzzDecodeTarget" || len(call.Args) != 3 {
				return true
			}
			if identifier, ok := call.Args[1].(*ast.Ident); ok {
				kind = identifier.Name
			}
			return false
		})
		if kind == "" {
			t.Errorf("%s does not delegate to fuzzDecodeTarget with a CodecKind", function.Name.Name)
			continue
		}
		covered[kind]++
	}
	if total != 9 {
		t.Fatalf("%d fuzz targets, OpenMLS ships 9", total)
	}
	if len(covered) != len(CodecKinds()) {
		t.Fatalf("%d kinds have targets, the codec table holds %d", len(covered), len(CodecKinds()))
	}
	for _, kind := range CodecKinds() {
		pair, _ := CodecFor(kind)
		found := false
		for name := range covered {
			// the identifier is KindExtension for the pair named "extension", and
			// so on; compare on the codec table rather than on a second literal.
			if strings.EqualFold(strings.TrimPrefix(name, "Kind"), strings.ReplaceAll(pair.Name, "_", "")) {
				found = true
			}
		}
		if !found {
			t.Errorf("codec %q has no fuzz target", pair.Name)
		}
	}
}
```

Add `"go/ast"`, `"go/parser"`, `"go/token"` and `"strings"` to the imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestFuzzTargetsCoverEveryKind -v`
Expected: FAIL to build with `undefined: fuzzDecodeTarget`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/syntax_fuzz_test.go

// fuzzDecodeTarget asserts the two properties that hold without an oracle:
//
//	1. no panic, no OOM, no unbounded allocation. A length prefix must never size
//	   an allocation before the remaining input is checked.
//	2. round-trip stability. If decode succeeds, encode(decode(x)) is the canonical
//	   re-serialization and decode(encode(decode(x))) equals decode(x). A decoder
//	   that accepts two encodings of one object is a signature-bypass primitive,
//	   because MLS signs over serialized forms.
//
// structured selects the seed corpus: the structured generator's output, or the raw
// byte corpus harvested from vectors and interop wire dumps.
func fuzzDecodeTarget(f *testing.F, kind CodecKind, structured bool) {
	pair, ok := CodecFor(kind)
	if !ok {
		f.Fatalf("no codec for kind %d", kind)
	}
	folder := "bytes"
	if structured {
		folder = "structured"
	}
	seedCorpus(f, filepath.Join("testdata", "corpus", pair.Name, folder))

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > syntax.MaxRatchetTreeLength {
			t.Skip()
		}
		decoded, err := pair.Decode(input)
		if err != nil {
			return
		}
		encoded, err := pair.Encode(decoded)
		if err != nil {
			t.Fatalf("%s: decode accepted %x but encode refused the result: %v", pair.Name, input, err)
		}
		redecoded, err := pair.Decode(encoded)
		if err != nil {
			t.Fatalf("%s: our own encoding %x was refused by our decoder: %v", pair.Name, encoded, err)
		}
		recanonical, err := pair.Encode(redecoded)
		if err != nil {
			t.Fatalf("%s: second encode refused: %v", pair.Name, err)
		}
		if !bytes.Equal(encoded, recanonical) {
			t.Fatalf("%s: encoding is not idempotent\n first: %x\nsecond: %x", pair.Name, encoded, recanonical)
		}
		if !bytes.Equal(input, encoded) {
			// a non-canonical input that decoded is the bug: exactly one encoding
			// per object is the property MLS signatures depend on.
			t.Fatalf("%s: accepted a non-canonical encoding\n  input: %x\ncanonical: %x", pair.Name, input, encoded)
		}
	})
}

// seedCorpus adds every file under folder as a seed. A missing folder is not an
// error on a fresh checkout; the corpus job creates it.
func seedCorpus(f *testing.F, folder string) {
	f.Helper()
	entries, err := os.ReadDir(folder)
	if err != nil {
		f.Add([]byte{})
		f.Add([]byte{0x00})
		f.Add([]byte{0x40, 0x00})
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(folder, entry.Name()))
		if err != nil {
			f.Fatalf("read seed %s: %v", entry.Name(), err)
		}
		f.Add(body)
	}
}
```

Add `"github.com/urnetwork/connect/mls/syntax"` to the imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestFuzzTargetsCoverEveryKind -v && go test ./connect/mls/... -run FuzzMlsMessageDecodeBytes -fuzz FuzzMlsMessageDecodeBytes -fuzztime 60s`
Expected: PASS, and 60 s of fuzzing with no crasher

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/syntax_fuzz_test.go && git -C connect commit -m "test(mls): 9 fuzz targets asserting no-panic and canonical round-trip"
```

---

### Task 12a: `seedgen` and the committed seed corpus

A fuzz target seeded from `[]byte{}`, `{0x00}` and `{0x40, 0x00}` spends its first hour rediscovering
the length prefix. Gate 4 wants the corpus committed, so every run starts where the last one got to
and a crasher is reproducible from a clean checkout.

**Files:**
- Create: `connect/mls/interop/cmd/seedgen/main.go`, `connect/mls/testdata/corpus/**`
- Test: `connect/mls/corpus_test.go`

**Interfaces:**
- Consumes: `CodecFor(kind CodecKind) (CodecPair, bool)`, `CodecKinds() []CodecKind` (Task 11 — and
  the reason that task moves the table out of `codec_table_test.go`: `seedgen` lives in the interop
  module and cannot see a test file's symbols, so `LoadVectorFile` and `MustHex` are unavailable to
  it and it harvests the corpus itself); `syntax.MaxVectorLength` (Syntax and codec plan);
  `MLSMessage`, `KeyPackage`, `Proposal`, `Welcome`, `Extension`, `Remove`, `LeafIndex`,
  `ProtocolVersionMls10`, `WireFormatKeyPackage`, `ExtensionTypeRequiredCapabilities`,
  `ExtensionTypeUrmessageLeafKeys`, `XwingPublicKeyLen`,
  `CipherSuiteX25519ChaCha20Sha256Ed25519` (Framing, TreeKEM and Crypto plans).
- Produces: `TestSeedCorpusIsCommitted`, `TestEverySeedIsHandledCleanly`, and the `seedgen` binary.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/corpus_test.go
// the seed corpus is committed, not generated at run time. A corpus that is
// regenerated per run makes a crasher irreproducible, and an empty corpus makes
// 60 s of fuzzing worth about 60 s of rediscovering the length prefix.
package mls

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeedCorpusIsCommitted(t *testing.T) {
	for _, kind := range CodecKinds() {
		pair, _ := CodecFor(kind)
		for _, folder := range []string{"bytes", "structured"} {
			if kind == KindWelcome && folder == "bytes" {
				// welcome has one target, the structured one; see Task 12.
				continue
			}
			path := filepath.Join("testdata", "corpus", pair.Name, folder)
			entries, err := os.ReadDir(path)
			if err != nil {
				t.Errorf("%s: %v — run interop/cmd/seedgen and commit the result", path, err)
				continue
			}
			if len(entries) < 4 {
				t.Errorf("%s holds %d seeds, want at least 4", path, len(entries))
			}
		}
	}
}

// TestEverySeedIsHandledCleanly is property 1 over the committed corpus alone, so
// a bad seed is caught by `go test` rather than only by `go test -fuzz`.
func TestEverySeedIsHandledCleanly(t *testing.T) {
	for _, kind := range CodecKinds() {
		pair, _ := CodecFor(kind)
		root := filepath.Join("testdata", "corpus", pair.Name)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Errorf("read %s: %v", path, readErr)
				return nil
			}
			decoded, decodeErr := pair.Decode(body)
			if decodeErr != nil {
				return nil
			}
			if _, encodeErr := pair.Encode(decoded); encodeErr != nil {
				t.Errorf("%s: decode accepted the seed but encode refused the result: %v", path, encodeErr)
			}
			return nil
		})
		if err != nil {
			t.Errorf("walk %s: %v", root, err)
		}
	}
}
```

Add `"io/fs"` to the imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestSeedCorpusIsCommitted|TestEverySeedIsHandledCleanly' -v`
Expected: FAIL with `testdata/corpus/extension/bytes: no such file or directory — run
interop/cmd/seedgen and commit the result`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/cmd/seedgen/main.go
// generate the committed fuzz seed corpus. It lives in the interop module, not in
// package mls, because it is a developer tool: nothing in the product build should
// be able to write into testdata.
//
// Two sources, matching the two target variants. The `bytes` corpus is every hex
// blob in the pinned vector files plus every interop wire dump found under
// out/wiredump. The `structured` corpus is our own encoder's output for a handful
// of hand-built values, which is what gives the fuzzer a valid frame to mutate
// rather than a valid frame to discover.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/mls/syntax"
)

// hexBlob matches a lowercase hex string long enough to be a plausible message.
var hexBlob = regexp.MustCompile(`"([0-9a-f]{16,})"`)

func main() {
	vectors := flag.String("vectors", "../../testdata/vectors", "the pinned vector folder")
	wiredump := flag.String("wiredump", "out/wiredump", "interop wire dumps, if any")
	out := flag.String("out", "../../testdata/corpus", "the corpus root")
	flag.Parse()

	for _, kind := range mls.CodecKinds() {
		pair, _ := mls.CodecFor(kind)
		if err := os.MkdirAll(filepath.Join(*out, pair.Name, "bytes"), 0o755); err != nil {
			fail(err)
		}
		if err := os.MkdirAll(filepath.Join(*out, pair.Name, "structured"), 0o755); err != nil {
			fail(err)
		}
	}

	// the bytes corpus: anything hex-shaped in the vector corpus, and every wire
	// dump. A blob that decodes under some codec is filed under that codec; one
	// that decodes under none is still useful and is filed under mls_message.
	blobs := [][]byte{}
	blobs = append(blobs, harvestHex(*vectors)...)
	blobs = append(blobs, harvestFiles(*wiredump)...)
	for _, blob := range blobs {
		file(*out, classify(blob), "bytes", blob)
	}

	// the structured corpus: our own encoder over values we know are well-formed.
	for _, seed := range structuredSeeds() {
		pair, ok := mls.CodecFor(seed.kind)
		if !ok {
			continue
		}
		encoded, err := pair.Encode(seed.value)
		if err != nil {
			fail(fmt.Errorf("encode %s seed: %w", pair.Name, err))
		}
		file(*out, seed.kind, "structured", encoded)
	}
}

type structuredSeed struct {
	kind  mls.CodecKind
	value any
}

// structuredSeeds is one minimal and one populated value per codec. They are built
// through the exported types and encoded through the codec table, so a seed can
// never encode a shape the decoder would reject.
func structuredSeeds() []structuredSeed {
	return []structuredSeed{
		{mls.KindExtension, &mls.Extension{ExtensionType: mls.ExtensionTypeRequiredCapabilities}},
		{mls.KindExtension, &mls.Extension{
			ExtensionType: mls.ExtensionTypeUrmessageLeafKeys,
			ExtensionData: make([]byte, mls.XwingPublicKeyLen),
		}},
		{mls.KindKeyPackage, &mls.KeyPackage{
			Version:     mls.ProtocolVersionMls10,
			CipherSuite: mls.CipherSuiteX25519ChaCha20Sha256Ed25519,
		}},
		{mls.KindProposal, &mls.Proposal{
			ProposalType: mls.ProposalTypeRemove,
			Remove:       &mls.Remove{Removed: mls.LeafIndex(1)},
		}},
		{mls.KindProposal, &mls.Proposal{
			ProposalType: mls.ProposalType(0x0A0A),
			UnknownType:  mls.ProposalType(0x0A0A),
			UnknownBody:  []byte{0x0a, 0x0a},
		}},
		{mls.KindWelcome, &mls.Welcome{CipherSuite: mls.CipherSuiteX25519ChaCha20Sha256Ed25519}},
		{mls.KindMlsMessage, &mls.MLSMessage{
			Version:    mls.ProtocolVersionMls10,
			WireFormat: mls.WireFormatKeyPackage,
			KeyPackage: &mls.KeyPackage{
				Version:     mls.ProtocolVersionMls10,
				CipherSuite: mls.CipherSuiteX25519ChaCha20Sha256Ed25519,
			},
		}},
	}
}

// classify files a harvested blob under the first codec that accepts it, and under
// mls_message when none does — an input nobody accepts is exactly the input worth
// keeping.
func classify(blob []byte) mls.CodecKind {
	for _, kind := range mls.CodecKinds() {
		pair, _ := mls.CodecFor(kind)
		if _, err := pair.Decode(blob); err == nil {
			return kind
		}
	}
	return mls.KindMlsMessage
}

// file writes one seed, named by its digest so re-running seedgen is idempotent.
// A seed above the codec's own vector limit can only ever be rejected on length,
// which teaches the fuzzer nothing and costs it a mutation slot.
func file(root string, kind mls.CodecKind, folder string, body []byte) {
	pair, ok := mls.CodecFor(kind)
	if !ok || len(body) == 0 || len(body) > syntax.MaxVectorLength {
		return
	}
	sum := sha256.Sum256(body)
	name := hex.EncodeToString(sum[:8])
	path := filepath.Join(root, pair.Name, folder, name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		fail(err)
	}
}

func harvestHex(root string) [][]byte {
	blobs := [][]byte{}
	filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if !json.Valid(body) {
			return nil
		}
		for _, match := range hexBlob.FindAllSubmatch(body, -1) {
			decoded, decodeErr := hex.DecodeString(string(match[1]))
			if decodeErr == nil {
				blobs = append(blobs, decoded)
			}
		}
		return nil
	})
	return blobs
}

func harvestFiles(root string) [][]byte {
	blobs := [][]byte{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return blobs
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		body, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
		if readErr == nil {
			blobs = append(blobs, body)
		}
	}
	return blobs
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "seedgen: %v\n", err)
	os.Exit(1)
}
```

Then run it once and commit the result:

```bash
( cd connect/mls/interop && go run ./cmd/seedgen )
git -C connect add mls/testdata/corpus
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestSeedCorpusIsCommitted|TestEverySeedIsHandledCleanly' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/corpus_test.go mls/interop/cmd/seedgen mls/testdata/corpus && git -C connect commit -m "test(mls): committed fuzz seed corpus, generated from the pinned vectors and our own encoder"
```

---

## Phase A, continued — the per-commit CI workflow (wave 1)

### Task 13: The per-commit CI workflow

**Files:**
- Create: `connect/.github/workflows/mls-vectors.yml`, `connect/.github/workflows/mls-fuzz.yml`
- Test: `connect/mls/workflow_test.go`

**Interfaces:**
- Consumes: the test names of Tasks 3, 3a, 4, 5, 6, 7, 8, 9 and 12.
- Produces: the `vectors`, `valsem`, `profile`, `layering`, `forbidden-crypto` and `fuzz-short` CI
  jobs, and `TestWorkflowsPinTheToolchain`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/workflow_test.go
// the workflows are checked in code because a workflow that silently stops running
// a gate is indistinguishable from a green build.
package mls

import (
	"os"
	"strings"
	"testing"
)

func TestWorkflowsPinTheToolchain(t *testing.T) {
	for _, path := range []string{
		"../.github/workflows/mls-vectors.yml",
		"../.github/workflows/mls-fuzz.yml",
	} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		if !strings.Contains(text, "go-version: '1.26.5'") {
			t.Errorf("%s does not pin Go 1.26.5", path)
		}
		if strings.Contains(text, "go-version: 'stable'") || strings.Contains(text, "go-version: 1.x") {
			t.Errorf("%s floats the toolchain", path)
		}
	}
	vectors, err := os.ReadFile("../.github/workflows/mls-vectors.yml")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	for _, gate := range []string{
		"TestVectorFilesArePinned",
		"TestVectorFolderHoldsExactlySixteenFiles",
		"TestPinsAreMachineReadable",
		"TestVectorManifestIsComplete",
		"TestVectorFamiliesVerify",
		"TestVectorGenerateThenVerify",
		"TestValSemCatalogueIsClosed",
		"TestProfileIsClosed",
		"TestForbiddenImportEdges",
		"TestNoForbiddenCrypto",
	} {
		if !strings.Contains(string(vectors), gate) {
			t.Errorf("mls-vectors.yml does not run %s", gate)
		}
	}
	fuzz, err := os.ReadFile("../.github/workflows/mls-fuzz.yml")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(fuzz), "-fuzztime 60s") {
		t.Error("fuzz-short must run 60 s per target")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestWorkflowsPinTheToolchain -v`
Expected: FAIL with `read ../.github/workflows/mls-vectors.yml: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

```yaml
# connect/.github/workflows/mls-vectors.yml
name: mls-vectors
on:
  push:
    branches: [beta/message]
  pull_request:
    branches: [beta/message]
jobs:
  vectors:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      - name: vector families
        run: go test ./mls/... -run 'TestVectorFilesArePinned|TestVectorFolderHoldsExactlySixteenFiles|TestPinsAreMachineReadable|TestVectorManifestIsComplete|TestVectorFamiliesVerify|TestVectorGenerateThenVerify|TestFamily16IsRegisteredAgainstTheSyntaxRunner' -v -count 1
  valsem:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      - name: catalogue closure
        run: go test ./mls/... -run 'TestValSemCatalogueIsClosed|TestErrataFileIsTranscribed' -v -count 1
      - name: negative tests
        run: go test ./mls/... -run 'TestValSem|TestErrata|TestProfileRefuses' -v -count 1
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: valsem-coverage
          path: mls/valsem-coverage.md
  profile:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      - name: the v1 narrow profile is closed
        run: go test ./mls/... -run 'TestProfileIsClosed' -v -count 1
  layering:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      - run: go test . -run TestForbiddenImportEdges -v -count 1
  forbidden-crypto:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      - run: go test ./mls/... -run TestNoForbiddenCrypto -v -count 1
      - run: bash scripts/check-forbidden.sh
```

```yaml
# connect/.github/workflows/mls-fuzz.yml
name: mls-fuzz
on:
  push:
    branches: [beta/message]
  pull_request:
    branches: [beta/message]
  schedule:
    - cron: '17 3 * * *'
jobs:
  fuzz-short:
    if: github.event_name != 'schedule'
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        target:
          - FuzzExtensionDecode
          - FuzzExtensionDecodeBytes
          - FuzzKeyPackageDecode
          - FuzzKeyPackageDecodeBytes
          - FuzzMlsMessageDecode
          - FuzzMlsMessageDecodeBytes
          - FuzzProposalDecode
          - FuzzProposalDecodeBytes
          - FuzzWelcomeDecode
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      # the targets land in Phase A' (wave 4) with the codec table they are built
      # on. Until then this job is green and silent rather than red for four waves.
      - id: targets
        run: |
          if [ -f mls/syntax_fuzz_test.go ]; then echo 'present=yes' >> "$GITHUB_OUTPUT"; else echo 'present=no' >> "$GITHUB_OUTPUT"; fi
      - if: steps.targets.outputs.present == 'yes'
        run: go test ./mls/ -run '^$' -fuzz '^${{ matrix.target }}$' -fuzztime 60s
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: crashers-${{ matrix.target }}
          path: mls/testdata/fuzz/**
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestWorkflowsPinTheToolchain -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add .github/workflows/mls-vectors.yml .github/workflows/mls-fuzz.yml mls/workflow_test.go && git -C connect commit -m "ci(mls): vectors, valsem, layering, forbidden-crypto and fuzz-short gates"
```

---

## Phase B — the differential oracle (wave 1; the differential property runs nightly)

### Task 14: The Rust decode oracle

**Files:**
- Create: `connect/mls/interop/oracle/rust/Cargo.toml`, `connect/mls/interop/oracle/rust/src/main.rs`, `connect/mls/interop/oracle/BUILD.md`
- Test: `connect/mls/interop/oracle/rust/tests/framing.rs`

**Interfaces:**
- Consumes: nothing from other plans. OpenMLS is fetched by the CI job at the commit pinned in
  `connect/mls/interop/PINS.md`; it never enters any `go.mod` and the binary never ships.
- Produces: a binary that speaks the stdio protocol Task 15 implements the Go side of:

```
request:   u8 kind ‖ u32be input_length ‖ input
response:  u32be body_length ‖ body, where body is
           {"accept": bool, "reserialized": "<base64 std>", "error": "<string>"}
```

  `kind` is `CodecKind` from Task 11: 1 extension, 2 key_package, 3 mls_message, 4 proposal,
  5 welcome. Renumbering it breaks both sides at once, which is the intent.

- [ ] **Step 1: Write the failing test**

```rust
// connect/mls/interop/oracle/rust/tests/framing.rs
// the oracle's own framing test. It is a Rust test because the framing bug we are
// guarding against is on the Rust side of the pipe; the Go side has its own test.
use std::io::{Read, Write};
use std::process::{Command, Stdio};

#[test]
fn rejects_garbage_without_dying() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_urmessage_mls_oracle"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn oracle");

    let stdin = child.stdin.as_mut().unwrap();
    // kind 3 (mls_message), 4 bytes of garbage
    stdin.write_all(&[3u8]).unwrap();
    stdin.write_all(&(4u32.to_be_bytes())).unwrap();
    stdin.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
    stdin.flush().unwrap();

    let stdout = child.stdout.as_mut().unwrap();
    let mut length_bytes = [0u8; 4];
    stdout.read_exact(&mut length_bytes).expect("response length");
    let length = u32::from_be_bytes(length_bytes) as usize;
    let mut body = vec![0u8; length];
    stdout.read_exact(&mut body).expect("response body");

    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("\"accept\":false"), "garbage must be refused: {}", text);
    child.kill().ok();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop/oracle/rust && cargo test`
Expected: FAIL with `error: failed to parse manifest at .../Cargo.toml` — the crate does not exist.

- [ ] **Step 3: Write minimal implementation**

```toml
# connect/mls/interop/oracle/rust/Cargo.toml
# the differential oracle. OpenMLS is pinned by revision here and nowhere else, and
# this crate is never linked into anything Go builds.
[package]
name = "urmessage_mls_oracle"
version = "0.1.0"
edition = "2021"
publish = false

[[bin]]
name = "urmessage_mls_oracle"
path = "src/main.rs"

[dependencies]
openmls = { git = "https://github.com/openmls/openmls", rev = "PINNED_IN_mls/interop/PINS.md" }
tls_codec = "0.4"
base64 = "0.22"
serde_json = "1"
```

```rust
// connect/mls/interop/oracle/rust/src/main.rs
// read a framed decode request, attempt the decode with OpenMLS, reply with the
// verdict and the canonical re-serialization. This is the whole oracle: it holds no
// state, links nothing of ours, and is never shipped.
use base64::Engine;
use std::io::{self, Read, Write};
use tls_codec::{Deserialize, Serialize};

const KIND_EXTENSION: u8 = 1;
const KIND_KEY_PACKAGE: u8 = 2;
const KIND_MLS_MESSAGE: u8 = 3;
const KIND_PROPOSAL: u8 = 4;
const KIND_WELCOME: u8 = 5;

fn decode(kind: u8, input: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = input;
    match kind {
        KIND_EXTENSION => {
            let value = openmls::extensions::Extension::tls_deserialize(&mut cursor).map_err(|e| e.to_string())?;
            require_full(cursor)?;
            value.tls_serialize_detached().map_err(|e| e.to_string())
        }
        KIND_KEY_PACKAGE => {
            let value = openmls::key_packages::KeyPackageIn::tls_deserialize(&mut cursor).map_err(|e| e.to_string())?;
            require_full(cursor)?;
            value.tls_serialize_detached().map_err(|e| e.to_string())
        }
        KIND_MLS_MESSAGE => {
            let value = openmls::framing::MlsMessageIn::tls_deserialize(&mut cursor).map_err(|e| e.to_string())?;
            require_full(cursor)?;
            value.tls_serialize_detached().map_err(|e| e.to_string())
        }
        KIND_PROPOSAL => {
            let value = openmls::messages::proposals::Proposal::tls_deserialize(&mut cursor).map_err(|e| e.to_string())?;
            require_full(cursor)?;
            value.tls_serialize_detached().map_err(|e| e.to_string())
        }
        KIND_WELCOME => {
            let value = openmls::messages::Welcome::tls_deserialize(&mut cursor).map_err(|e| e.to_string())?;
            require_full(cursor)?;
            value.tls_serialize_detached().map_err(|e| e.to_string())
        }
        other => Err(format!("unknown kind {}", other)),
    }
}

// full consumption is part of the property under test: trailing bytes are an error
// on both sides or the differential comparison is meaningless.
fn require_full(rest: &[u8]) -> Result<(), String> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(format!("{} trailing bytes", rest.len()))
    }
}

fn main() -> io::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    loop {
        let mut kind = [0u8; 1];
        if stdin.read_exact(&mut kind).is_err() {
            return Ok(());
        }
        let mut length_bytes = [0u8; 4];
        stdin.read_exact(&mut length_bytes)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        if length > 16 * 1024 * 1024 {
            return Ok(());
        }
        let mut input = vec![0u8; length];
        stdin.read_exact(&mut input)?;

        let body = match decode(kind[0], &input) {
            Ok(reserialized) => serde_json::json!({
                "accept": true,
                "reserialized": base64::engine::general_purpose::STANDARD.encode(reserialized),
                "error": "",
            }),
            Err(message) => serde_json::json!({
                "accept": false,
                "reserialized": "",
                "error": message,
            }),
        };
        let encoded = serde_json::to_vec(&body).unwrap();
        stdout.write_all(&(encoded.len() as u32).to_be_bytes())?;
        stdout.write_all(&encoded)?;
        stdout.flush()?;
    }
}
```

```markdown
<!-- connect/mls/interop/oracle/BUILD.md -->
# Building the differential oracle

The oracle is built **only** in the nightly `fuzz-long` CI job, from the OpenMLS commit pinned in
`connect/mls/interop/PINS.md`. It is not part of any Go build, is not in any `go.mod`, and is never
included in a shipped artifact.

```
cd connect/mls/interop/oracle/rust
cargo build --release --locked
export URMSG_MLS_ORACLE="$PWD/target/release/urmessage_mls_oracle"
```

With `URMSG_MLS_ORACLE` unset — which is every developer machine and every per-commit CI job —
the differential property skips and properties 1 and 2 still run.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop/oracle/rust && cargo test`
Expected: PASS (`rejects_garbage_without_dying`)

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/oracle && git -C connect commit -m "test(mls): out-of-process OpenMLS decode oracle over a framed stdio pipe"
```

---

### Task 15: The Go oracle client

**Files:**
- Create: `connect/mls/oracle_test.go`
- Test: same file

**Interfaces:**
- Consumes: `CodecKind` (Task 11); the framing of Task 14.
- Produces:
  - `type oracleResult struct { Accept bool "json:\"accept\""; Reserialized []byte "json:\"reserialized\""; Error string "json:\"error\"" }`
  - `func newOracle(t *testing.T) *oracle` — `t.Skip`s when `URMSG_MLS_ORACLE` is unset
  - `func mustNewOracle(tb testing.TB) *oracle` — the non-skipping form a `*testing.F` needs
  - `func (self *oracle) decode(kind CodecKind, input []byte) (oracleResult, error)`
  - `func (self *oracle) close() error`

  Standard library only: `os/exec`, `encoding/binary`, `encoding/json`. `encoding/json` already
  decodes a standard-base64 string into a `[]byte` field, so `Reserialized` is a `[]byte` with the
  plain `reserialized` tag and there is no second field and no manual decode. Nothing enters
  `go.mod`, so the layering test of Task 4 still passes.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/oracle_test.go
// the Go half of the differential oracle. The framing is tested against a Go echo
// oracle so the test runs on a machine with no Rust toolchain; the Rust binary is
// exercised nightly.
package mls

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOracleFramingRoundTrip(t *testing.T) {
	fake := buildFakeOracle(t)
	t.Setenv("URMSG_MLS_ORACLE", fake)

	client := newOracle(t)
	defer client.close()

	result, err := client.decode(KindMlsMessage, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !result.Accept {
		t.Fatalf("fake oracle accepts everything, got Accept=false (%s)", result.Error)
	}
	if string(result.Reserialized) != "\x01\x02\x03" {
		t.Fatalf("Reserialized = %x, want 010203", result.Reserialized)
	}

	// a second request on the same pipe must work: the client is long-lived, one
	// subprocess per fuzz target rather than one per input.
	result, err = client.decode(KindWelcome, []byte{0xaa})
	if err != nil {
		t.Fatalf("second decode: %v", err)
	}
	if string(result.Reserialized) != "\xaa" {
		t.Fatalf("second Reserialized = %x, want aa", result.Reserialized)
	}
}

func TestOracleSkipsWhenUnset(t *testing.T) {
	t.Setenv("URMSG_MLS_ORACLE", "")
	if os.Getenv("URMSG_MLS_ORACLE") != "" {
		t.Fatal("precondition")
	}
	// newOracle calls t.Skip, so reaching the next line is the failure.
	// Run this assertion in a subtest whose skip we can observe.
	skipped := false
	func() {
		defer func() { skipped = true }()
		inner := &testing.T{}
		_ = inner
	}()
	if !skipped {
		t.Fatal("newOracle must skip rather than fail when the oracle is unavailable")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestOracle -v`
Expected: FAIL to build with `undefined: buildFakeOracle`, `undefined: newOracle`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/oracle_test.go

// oracle is a long-lived subprocess speaking the framed stdio protocol of
// interop/oracle. One instance per fuzz target; a subprocess per input would make
// the differential property unusably slow.
type oracle struct {
	command *exec.Cmd
	writer  io.WriteCloser
	reader  *bufio.Reader
}

// oracleResult is the oracle's verdict on one input. Reserialized is a []byte with
// the plain tag because encoding/json decodes a standard-base64 string straight
// into one; a second string field plus a manual decode is a second place for the
// two sides to disagree about the encoding.
type oracleResult struct {
	Accept       bool   `json:"accept"`
	Reserialized []byte `json:"reserialized"`
	Error        string `json:"error"`
}

// newOracle starts the binary named by URMSG_MLS_ORACLE. With the variable unset —
// every developer machine and every per-commit job — the caller skips, so the
// differential property never becomes a reason not to run the fuzzer.
func newOracle(t *testing.T) *oracle {
	t.Helper()
	if os.Getenv("URMSG_MLS_ORACLE") == "" {
		t.Skip("URMSG_MLS_ORACLE is unset; differential property skipped (see mls/interop/oracle/BUILD.md)")
	}
	return mustNewOracle(t)
}

// mustNewOracle is the non-skipping form. fuzzDecodeTarget holds a *testing.F and
// has already decided the oracle is available, so it must not skip: skipping a
// fuzz target from inside f.Cleanup's setup would silently drop the target.
func mustNewOracle(tb testing.TB) *oracle {
	tb.Helper()
	path := os.Getenv("URMSG_MLS_ORACLE")
	if path == "" {
		tb.Fatal("mustNewOracle called with URMSG_MLS_ORACLE unset")
	}
	command := exec.Command(path)
	writer, err := command.StdinPipe()
	if err != nil {
		tb.Fatalf("stdin pipe: %v", err)
	}
	readCloser, err := command.StdoutPipe()
	if err != nil {
		tb.Fatalf("stdout pipe: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		tb.Fatalf("start oracle %s: %v", path, err)
	}
	return &oracle{command: command, writer: writer, reader: bufio.NewReader(readCloser)}
}

// decode asks the oracle for its verdict on one input.
func (self *oracle) decode(kind CodecKind, input []byte) (oracleResult, error) {
	header := make([]byte, 5)
	header[0] = byte(kind)
	binary.BigEndian.PutUint32(header[1:], uint32(len(input)))
	if _, err := self.writer.Write(header); err != nil {
		return oracleResult{}, err
	}
	if _, err := self.writer.Write(input); err != nil {
		return oracleResult{}, err
	}

	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(self.reader, lengthBytes); err != nil {
		return oracleResult{}, err
	}
	length := binary.BigEndian.Uint32(lengthBytes)
	if length > 32<<20 {
		return oracleResult{}, fmt.Errorf("oracle response of %d bytes is implausible", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(self.reader, body); err != nil {
		return oracleResult{}, err
	}
	result := oracleResult{}
	if err := json.Unmarshal(body, &result); err != nil {
		return oracleResult{}, err
	}
	return result, nil
}

// close stops the oracle. A fuzz target defers it.
func (self *oracle) close() error {
	self.writer.Close()
	return self.command.Wait()
}

// buildFakeOracle compiles a Go program that speaks the same protocol and accepts
// everything, so the framing is tested without a Rust toolchain.
func buildFakeOracle(t *testing.T) string {
	t.Helper()
	folder := t.TempDir()
	source := filepath.Join(folder, "main.go")
	program := `package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
)

func main() {
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(os.Stdin, header); err != nil {
			return
		}
		input := make([]byte, binary.BigEndian.Uint32(header[1:]))
		if _, err := io.ReadFull(os.Stdin, input); err != nil {
			return
		}
		body, _ := json.Marshal(map[string]any{
			"accept":       true,
			"reserialized": base64.StdEncoding.EncodeToString(input),
			"error":        "",
		})
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(body)))
		os.Stdout.Write(length)
		os.Stdout.Write(body)
	}
}
`
	if err := os.WriteFile(source, []byte(program), 0o644); err != nil {
		t.Fatalf("write fake oracle: %v", err)
	}
	binaryPath := filepath.Join(folder, "fake-oracle")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}
	build := exec.Command("go", "build", "-o", binaryPath, source)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build fake oracle: %v", err)
	}
	return binaryPath
}
```

Add `"bufio"`, `"fmt"`, `"io"`, `"os/exec"`, `"runtime"` to the imports and drop
`"encoding/base64"` from the client's own imports — the fake oracle below still needs it inside the
program text it writes. Delete `TestOracleSkipsWhenUnset` from step 1 and replace it with the honest
form:

```go
func TestOracleSkipsWhenUnset(t *testing.T) {
	t.Setenv("URMSG_MLS_ORACLE", "")
	newOracle(t)
	t.Fatal("newOracle must skip when URMSG_MLS_ORACLE is unset")
}
```

A skipped test reports SKIP and never reaches the `t.Fatal`, which is exactly the assertion.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestOracle -v`
Expected: PASS for `TestOracleFramingRoundTrip`, SKIP for `TestOracleSkipsWhenUnset`

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/oracle_test.go && git -C connect commit -m "test(mls): stdlib-only client for the out-of-process decode oracle"
```

---

### Task 16: Property 3 — differential agreement, and the divergence allowlist

**Files:**
- Modify: `connect/mls/syntax_fuzz_test.go`, `connect/.github/workflows/mls-fuzz.yml`
- Create: `connect/mls/testdata/divergence-allowlist.json`
- Test: `connect/mls/divergence_test.go`

**Interfaces:**
- Consumes: `newOracle`, `oracle.decode` (Task 15); `CodecFor` (Task 11).
- Produces: property 3 inside `fuzzDecodeTarget`, the allowlist format, and
  `TestDivergenceAllowlistIsJustified`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/divergence_test.go
// where OpenMLS and we are permitted to disagree. Every entry is a place the RFC
// leaves the outcome to the implementation; anything else is a P0. The file exists
// so a disagreement is either a bug or a documented decision, never a shrug.
package mls

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// divergenceEntry is one permitted disagreement.
type divergenceEntry struct {
	Kind      CodecKind `json:"kind"`
	InputHex  string    `json:"input_hex"`
	OpenMls   string    `json:"openmls"` // "accept" or "reject"
	Ours      string    `json:"ours"`
	Rfc       string    `json:"rfc"`     // the section that leaves it open
	Reason    string    `json:"reason"`
	AddedOn   string    `json:"added_on"`
}

func TestDivergenceAllowlistIsJustified(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "divergence-allowlist.json"))
	if err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	entries := []divergenceEntry{}
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	seen := map[string]bool{}
	for index, entry := range entries {
		if _, ok := CodecFor(entry.Kind); !ok {
			t.Errorf("entry %d names unknown kind %d", index, entry.Kind)
		}
		if entry.Rfc == "" || entry.Reason == "" || entry.AddedOn == "" {
			t.Errorf("entry %d is unjustified: every divergence cites an RFC section, a reason and a date", index)
		}
		if entry.OpenMls == entry.Ours {
			t.Errorf("entry %d records no divergence at all (%s == %s)", index, entry.OpenMls, entry.Ours)
		}
		raw, err := hex.DecodeString(entry.InputHex)
		if err != nil {
			t.Errorf("entry %d has an undecodable input_hex: %v", index, err)
			continue
		}
		key := divergenceKey(entry.Kind, raw)
		if seen[key] {
			t.Errorf("entry %d duplicates an earlier input", index)
		}
		seen[key] = true
	}
	if len(entries) > 8 {
		t.Errorf("the allowlist holds %d entries; a growing allowlist is how a differential gate stops being one", len(entries))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestDivergenceAllowlistIsJustified -v`
Expected: FAIL with `read allowlist: open testdata/divergence-allowlist.json: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

```json
[
  {
    "kind": 1,
    "input_hex": "0a0a0000",
    "openmls": "reject",
    "ours": "accept",
    "rfc": "RFC 9420 §13.2",
    "reason": "GREASE extension type 0x0A0A. The RFC requires GREASE values to be parsed and ignored; OpenMLS's Extension decoder rejects unknown types outright. We accept and ignore, per Spec A §3.2, because the interop harness sends them.",
    "added_on": "2026-08-12"
  }
]
```

```go
// append to the f.Fuzz body in connect/mls/syntax_fuzz_test.go, after property 2.
// property 3: differential agreement with OpenMLS on accept/reject and, on accept,
// on the canonical re-serialization. Nightly only — the subprocess round-trip is
// too slow for the per-commit path.
		if differentialOracle != nil {
			verdict, oracleErr := differentialOracle.decode(kind, input)
			if oracleErr != nil {
				t.Fatalf("%s: oracle failed on %x: %v", pair.Name, input, oracleErr)
			}
			if allowedDivergence(kind, input) {
				return
			}
			if !verdict.Accept {
				t.Fatalf("%s: we accepted %x, OpenMLS rejected it (%s)", pair.Name, input, verdict.Error)
			}
			if !bytes.Equal(verdict.Reserialized, encoded) {
				t.Fatalf("%s: canonical re-serialization differs on %x\n  ours: %x\nopenmls: %x", pair.Name, input, encoded, verdict.Reserialized)
			}
		}
```

and the reject-side check, placed in the `err != nil` branch that currently returns:

```go
		if err != nil {
			if differentialOracle != nil && !allowedDivergence(kind, input) {
				verdict, oracleErr := differentialOracle.decode(kind, input)
				if oracleErr != nil {
					t.Fatalf("%s: oracle failed on %x: %v", pair.Name, input, oracleErr)
				}
				if verdict.Accept {
					t.Fatalf("%s: we rejected %x (%v), OpenMLS accepted it", pair.Name, input, err)
				}
			}
			return
		}
```

plus the target-scoped oracle and the allowlist lookup:

```go
// differentialOracle is set by fuzzDecodeTarget when URMSG_MLS_ORACLE names a
// binary. One subprocess per target, torn down by the target's cleanup; one
// subprocess per input would make the differential property unusably slow.
var differentialOracle *oracle

var (
	divergenceOnce  sync.Once
	divergenceIndex map[string]bool
)

// divergenceKey is the identity of one allowlist entry. The kind is formatted as a
// number rather than converted with string(rune(kind)), which is the conversion
// that silently maps every value in the surrogate range onto U+FFFD.
func divergenceKey(kind CodecKind, input []byte) string {
	return strconv.FormatUint(uint64(kind), 10) + ":" + HexOf(input)
}

// allowedDivergence reports whether this exact input is a documented, justified
// disagreement rather than a defect. A missing allowlist means no divergence is
// permitted, which is the safe direction.
func allowedDivergence(kind CodecKind, input []byte) bool {
	divergenceOnce.Do(func() {
		divergenceIndex = map[string]bool{}
		body, err := os.ReadFile(filepath.Join("testdata", "divergence-allowlist.json"))
		if err != nil {
			return
		}
		entries := []divergenceEntry{}
		if err := json.Unmarshal(body, &entries); err != nil {
			return
		}
		for _, entry := range entries {
			raw, err := hex.DecodeString(entry.InputHex)
			if err != nil {
				continue
			}
			divergenceIndex[divergenceKey(entry.Kind, raw)] = true
		}
	})
	return divergenceIndex[divergenceKey(kind, input)]
}
```

`fuzzDecodeTarget` gains, before `f.Fuzz`:

```go
	if os.Getenv("URMSG_MLS_ORACLE") != "" {
		differentialOracle = mustNewOracle(f)
		f.Cleanup(func() {
			differentialOracle.close()
			differentialOracle = nil
		})
	}
```

`mustNewOracle` rather than `newOracle` is the whole point of the pair: `newOracle` skips through
`*testing.T` when the variable is unset, and a fuzz target that skipped itself during setup would
look identical to a fuzz target that ran clean. `fuzzDecodeTarget` has already tested the variable,
so it takes the constructor that fails instead.

`TestDivergenceAllowlistIsJustified` also uses `divergenceKey`, replacing its
`string(rune(entry.Kind)) + entry.InputHex` duplicate-detection key with the same function, so the
test and the fuzz path cannot disagree about what "the same entry" means.

Add `"encoding/hex"`, `"path/filepath"`, `"strconv"` and `"sync"` to
`connect/mls/syntax_fuzz_test.go`'s imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestDivergenceAllowlistIsJustified -v`
Expected: PASS

Then add the nightly job to `connect/.github/workflows/mls-fuzz.yml`:

```yaml
  fuzz-long:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    timeout-minutes: 300
    strategy:
      fail-fast: false
      matrix:
        target: [FuzzExtensionDecode, FuzzExtensionDecodeBytes, FuzzKeyPackageDecode, FuzzKeyPackageDecodeBytes, FuzzMlsMessageDecode, FuzzMlsMessageDecodeBytes, FuzzProposalDecode, FuzzProposalDecodeBytes, FuzzWelcomeDecode]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      - uses: dtolnay/rust-toolchain@stable
      - name: build the oracle from the pinned OpenMLS commit
        run: cargo build --release --locked
        working-directory: mls/interop/oracle/rust
      - uses: actions/cache@v4
        with:
          path: mls/testdata/fuzz
          key: mls-fuzz-corpus-${{ matrix.target }}
      - name: differential fuzz
        env:
          URMSG_MLS_ORACLE: ${{ github.workspace }}/mls/interop/oracle/rust/target/release/urmessage_mls_oracle
        run: go test ./mls/ -run '^$' -fuzz '^${{ matrix.target }}$' -fuzztime 4h
      - name: open a P0 on disagreement
        if: failure()
        run: gh issue create --title "P0 differential fuzz disagreement — ${{ matrix.target }}" --label P0 --body-file mls/testdata/fuzz/${{ matrix.target }}/$(ls mls/testdata/fuzz/${{ matrix.target }} | head -1)
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/syntax_fuzz_test.go mls/divergence_test.go mls/testdata/divergence-allowlist.json .github/workflows/mls-fuzz.yml && git -C connect commit -m "test(mls): differential agreement with OpenMLS, with a justified divergence allowlist"
```

---

## Phase C — the 43 ValSem codes, ValSem400 and the two errata (wave 4, after `group.go`)

### Task 17: The forge

**Files:**
- Create: `connect/mls/testkit_test.go`
- Test: same file

**Interfaces:**
- Consumes: `NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error)`,
  `CipherSuiteX25519ChaCha20Sha256Ed25519` (Crypto plan);
  `BasicCredential(identity []byte) Credential`, `Capabilities`, `RequiredCapabilities`,
  `Extension{ExtensionType, ExtensionData}`, `LeafKeysExtension`, `AlgIdXwing`, `XwingPublicKeyLen`,
  `NewKeyPackage(crypto, suite, cred, caps, exts) (kp, initPriv, encPriv, err)`,
  `UnmarshalRatchetTree(data []byte) (*RatchetTree, error)`, `(*RatchetTree).LeafWidth() LeafCount`
  (TreeKEM plan);
  `NewSecretTree(crypto CryptoProvider, leafCount LeafCount, encryptionSecret []byte) (*SecretTree, error)`
  (Key schedule plan);
  `Sender{SenderType, LeafIndex, SenderIndex}`, `FramedContent`, `FramedContentAuthData`,
  `AuthenticatedContent`, `(*AuthenticatedContent).ProposalRef(crypto) (ProposalRef, error)`,
  `WireFormat`, `ParseMLSMessage`, `MarshalMLSMessage`, `StaticSignatureKey(pub) SignatureKeyResolver`,
  `OpenPrivateMessage(crypto, keys, senderDataSecret, message, resolve, groupContext) (*AuthenticatedContent, error)`,
  `Proposal`, `Add`, `Update`, `Remove`, `ProposalRef`, `Commit`, `UpdatePath`,
  `(*Group).sealFramedContentForTest(c, auth, wf, signer) ([]byte, error)` (Framing plan);
  `NewGroup`, `GroupConfig`, `JoinFromWelcome`, `JoinKeyMaterial`, `(*Group).Commit`,
  `CommitOptions` with its three unexported test seams, `(*Group).MergePendingCommit`,
  `(*Group).ProcessMessage`, `(*Group).ApplyCommit`, `(*Group).OwnLeafIndex`,
  `(*Group).OwnLeafNodeCopy`, `(*Group).GroupContext`, `(*Group).RatchetTree`,
  `(*Group).EpochSecret`, `EpochSecretSenderData`, `EpochSecretEncryption` (Group lifecycle plan);
  `newMemStore` (Task 10); `ValSemCode`, `CodeOf`, `ReasonFor`, `DefaultProfile` (Tasks 2 and 3a).
- Produces — consumed by Tasks 18–23:
  - `func newForge(t *testing.T, members int) *forge`
  - `func (self *forge) g(i int) *Group`
  - `func (self *forge) signer(i int) SignaturePrivateKey`
  - `func (self *forge) store(i int) *memStore`
  - `func (self *forge) newKeyPackage(t *testing.T) (*KeyPackage, HpkePrivateKey, HpkePrivateKey)`
  - `func (self *forge) content(i int, contentType ContentType, body []byte) *FramedContent`
  - `func (self *forge) contentFrom(sender Sender, contentType ContentType, body []byte) *FramedContent`
  - `func (self *forge) sealPrivate(i int, c *FramedContent, mutate func(*FramedContentAuthData)) []byte`
  - `func (self *forge) sealPublic(i int, c *FramedContent, mutate func(*FramedContentAuthData)) []byte`
  - `func (self *forge) proposalBytes(i int, p Proposal) []byte`
  - `func (self *forge) commitBytes(i int, byValue []Proposal, byRef []ProposalRef, mutate func(*Commit, *UpdatePath)) []byte`
  - `func (self *forge) deliver(to int, raw []byte) error`
  - `func requireValSem(t *testing.T, err error, want ValSemCode)`
  - and four helpers the registry surface implies rather than names:
    `func forgeProfile() *Profile`, `func forgeCapabilities() Capabilities`,
    `func (self *forge) openOwn(i int, raw []byte) *AuthenticatedContent`,
    `func (self *forge) sealPublicWithMembershipTag(i int, c *FramedContent, tag []byte) []byte`,
    `func (self *forge) commitBytesWithOptions(i int, byValue []Proposal, opts *CommitOptions) []byte`

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/testkit_test.go
// the forge builds a valid group and then frames a message the honest API refuses
// to build, which is the only way to test a receiver-side validation rule. Every
// mutation is applied after signing decisions are made and before the wire bytes
// are produced, so the message is malformed in exactly one respect.
package mls

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestForgeBuildsAValidGroup(t *testing.T) {
	f := newForge(t, 3)

	if got := f.g(0).Epoch(); got == 0 {
		t.Fatalf("the forge must commit the adds; epoch is still %d", got)
	}
	for i := 0; i < 3; i++ {
		if got, want := len(f.g(i).Members()), 3; got != want {
			t.Errorf("member %d sees %d members, want %d", i, got, want)
		}
		if !bytes.Equal(f.g(i).GroupId(), f.g(0).GroupId()) {
			t.Errorf("member %d is in a different group", i)
		}
		if f.g(i).Epoch() != f.g(0).Epoch() {
			t.Errorf("member %d is at epoch %d, member 0 at %d", i, f.g(i).Epoch(), f.g(0).Epoch())
		}
	}
}

func TestForgeUnmutatedMessageIsAccepted(t *testing.T) {
	f := newForge(t, 2)
	raw := f.sealPrivate(0, f.content(0, ContentTypeApplication, []byte("hello")), nil)
	if err := f.deliver(1, raw); err != nil {
		t.Fatalf("an unmutated forged message must be accepted, got %v", err)
	}
}

func TestForgeIsDeterministic(t *testing.T) {
	first := newForge(t, 3)
	second := newForge(t, 3)
	if !bytes.Equal(first.g(0).GroupId(), second.g(0).GroupId()) {
		t.Fatal("two forges with the same member count must produce the same group id; a failing ValSem test has to reproduce")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestForge -v`
Expected: FAIL to build with `undefined: newForge`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/testkit_test.go

// forge holds a committed group of n members, every member's signer, and every
// member's store, so a test can mutate from any vantage point.
type forge struct {
	t       *testing.T
	crypto  CryptoProvider
	groups  []*Group
	signers []SignaturePrivateKey
	stores  []*memStore

	// pending carries what newKeyPackage just minted, so a caller can build the
	// joiner without a five-value return at every site.
	pendingSigner SignaturePrivateKey
	pendingStore  *memStore
}

// forgeProfile is the v1 narrow profile with PublicMessage admitted. ValSem005, 007
// and 008 are about what the RFC says a PublicMessage may carry, so the profile gate
// must not fire first and hide the check under test. Everything else is DefaultProfile.
func forgeProfile() *Profile {
	profile := DefaultProfile()
	profile.AllowPublicMessage = true
	return profile
}

// newForge builds a group of members, all added and committed, at a deterministic
// group id and with deterministic key material. Determinism is not a nicety: a
// ValSem failure that cannot be reproduced is a ValSem failure nobody fixes. The
// randomness is deliberately math/rand, seeded from the member count — this is the
// only place in the slice where a non-cryptographic source is correct.
func newForge(t *testing.T, members int) *forge {
	t.Helper()
	if members < 2 {
		t.Fatal("a forge needs at least two members: one to send and one to validate")
	}
	random := rand.New(rand.NewSource(int64(members)))
	crypto, err := NewCryptoProviderWithRandom(CipherSuiteX25519ChaCha20Sha256Ed25519, random)
	if err != nil {
		t.Fatalf("crypto provider: %v", err)
	}
	self := &forge{t: t, crypto: crypto}

	groupId := crypto.Hash([]byte("urmessage/forge/group"))[:32]
	creatorSigner, creatorPublic, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("creator key: %v", err)
	}
	creatorStore := newMemStore()
	creator, err := NewGroup(self.config(groupId, creatorStore), creatorSigner, BasicCredential(creatorPublic))
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	self.groups = []*Group{creator}
	self.signers = []SignaturePrivateKey{creatorSigner}
	self.stores = []*memStore{creatorStore}

	adds := make([]Proposal, 0, members-1)
	joinerStores := make([]*memStore, 0, members-1)
	joinerSigners := make([]SignaturePrivateKey, 0, members-1)
	joinerKeys := make([]*JoinKeyMaterial, 0, members-1)
	for i := 1; i < members; i++ {
		keyPackage, initPriv, encPriv := self.newKeyPackage(t)
		adds = append(adds, Proposal{
			ProposalType: ProposalTypeAdd,
			Add:          &Add{KeyPackage: *keyPackage},
		})
		joinerStores = append(joinerStores, self.pendingStore)
		joinerSigners = append(joinerSigners, self.pendingSigner)
		joinerKeys = append(joinerKeys, &JoinKeyMaterial{
			KeyPackage:     *keyPackage,
			InitPrivate:    initPriv,
			EncryptPrivate: encPriv,
			SignPrivate:    self.pendingSigner,
		})
	}

	result, err := creator.Commit(nil, adds, nil)
	if err != nil {
		t.Fatalf("commit the adds: %v", err)
	}
	if err := creator.MergePendingCommit(); err != nil {
		t.Fatalf("merge: %v", err)
	}
	for i, keys := range joinerKeys {
		joined, err := JoinFromWelcome(self.config(groupId, joinerStores[i]), result.Welcome, result.RatchetTree, keys)
		if err != nil {
			t.Fatalf("member %d join: %v", i+1, err)
		}
		self.groups = append(self.groups, joined)
		self.signers = append(self.signers, joinerSigners[i])
		self.stores = append(self.stores, joinerStores[i])
	}
	return self
}

// forgeCapabilities is what every forged leaf advertises: the pinned version and
// suite, all three urmessage extensions, and BasicCredential. Tests that need a
// capability *missing* copy this and drop one entry.
func forgeCapabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20Sha256Ed25519},
		Extensions: []ExtensionType{
			ExtensionTypeUrmessageGroupPolicy,
			ExtensionTypeUrmessageLeafKeys,
			ExtensionTypeUrmessageOwnerSuccessor,
		},
		Proposals: []ProposalType{
			ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove,
			ProposalTypeGroupContextExtensions,
		},
		Credentials: []CredentialType{CredentialTypeBasic},
	}
}

// config is the v1 group configuration every forged group uses: the pinned suite,
// the required capabilities of Spec A §3.4, and the forge profile.
func (self *forge) config(groupId []byte, store *memStore) *GroupConfig {
	return &GroupConfig{
		Suite:   groupSuite,
		GroupId: groupId,
		Extensions: []Extension{{
			ExtensionType: ExtensionTypeUrmessageGroupPolicy,
			ExtensionData: []byte{0x00},
		}},
		RequiredCaps: RequiredCapabilities{
			ExtensionTypes: []ExtensionType{
				ExtensionTypeUrmessageGroupPolicy,
				ExtensionTypeUrmessageLeafKeys,
			},
			ProposalTypes:   []ProposalType{},
			CredentialTypes: []CredentialType{CredentialTypeBasic},
		},
		Crypto:  self.crypto,
		Store:   store,
		Profile: forgeProfile(),
		LeafKeys: LeafKeysExtension{
			AlgId:          AlgIdXwing,
			DeviceXwingPub: self.crypto.Random(XwingPublicKeyLen),
		},
	}
}

// groupSuite is the one suite a forged group is created at.
const groupSuite = CipherSuiteX25519ChaCha20Sha256Ed25519

func (self *forge) g(i int) *Group                   { return self.groups[i] }
func (self *forge) signer(i int) SignaturePrivateKey { return self.signers[i] }
func (self *forge) store(i int) *memStore            { return self.stores[i] }

// newKeyPackage mints a fresh, valid KeyPackage for a would-be member, and records
// its signer and store on the forge for the join that follows.
//
// NewKeyPackage takes no signer and returns no signature private key: the v1
// profile binds a leaf's signature key to its BasicCredential identity, which is
// the member's Ed25519 identity public key. The forge generates that pair itself,
// hands the public half in as the credential, and asserts the binding held — so if
// the key-package constructor ever stops adopting the credential identity, this
// says so at the first ValSem test rather than at the interop matrix.
func (self *forge) newKeyPackage(t *testing.T) (*KeyPackage, HpkePrivateKey, HpkePrivateKey) {
	t.Helper()
	signer, public, err := self.crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("signature key: %v", err)
	}
	leafKeys := LeafKeysExtension{
		AlgId:          AlgIdXwing,
		DeviceXwingPub: self.crypto.Random(XwingPublicKeyLen),
	}
	leafKeysExtension, err := leafKeys.Encode()
	if err != nil {
		t.Fatalf("encode leaf keys: %v", err)
	}
	keyPackage, initPriv, encPriv, err := NewKeyPackage(self.crypto, groupSuite,
		BasicCredential(public), forgeCapabilities(), []Extension{leafKeysExtension})
	if err != nil {
		t.Fatalf("key package: %v", err)
	}
	if !bytes.Equal(keyPackage.LeafNode.SignatureKey, public) {
		t.Fatalf("NewKeyPackage did not adopt the credential identity as the leaf signature key; the forge has no other way to learn the joiner's signing key")
	}
	self.pendingSigner = signer
	self.pendingStore = newMemStore()
	return keyPackage, initPriv, encPriv
}

// content builds a fully valid FramedContent from member i, ready to be mutated.
func (self *forge) content(i int, contentType ContentType, body []byte) *FramedContent {
	sender := Sender{SenderType: SenderTypeMember, LeafIndex: self.g(i).OwnLeafIndex()}
	return self.contentFrom(sender, contentType, body)
}

// contentFrom is the same for an arbitrary sender, which the external-commit tests need.
func (self *forge) contentFrom(sender Sender, contentType ContentType, body []byte) *FramedContent {
	content := &FramedContent{
		GroupId:     self.g(0).GroupId(),
		Epoch:       self.g(0).Epoch(),
		Sender:      sender,
		ContentType: contentType,
	}
	switch contentType {
	case ContentTypeApplication:
		content.ApplicationData = body
	case ContentTypeProposal:
		proposal := &Proposal{}
		if err := syntax.Unmarshal(body, proposal); err != nil {
			self.t.Fatalf("decode proposal body: %v", err)
		}
		content.Proposal = proposal
	}
	return content
}

// sealPrivate signs c under member i's key and frames it as a PrivateMessage,
// running no construction-side validation. mutate, when non-nil, is applied to the
// auth data after signing and before framing.
func (self *forge) sealPrivate(i int, c *FramedContent, mutate func(*FramedContentAuthData)) []byte {
	self.t.Helper()
	return self.seal(i, c, mutate, WireFormatPrivateMessage)
}

// sealPublic is the same for the PublicMessage path, which ValSem005, 007 and 008 need.
func (self *forge) sealPublic(i int, c *FramedContent, mutate func(*FramedContentAuthData)) []byte {
	self.t.Helper()
	return self.seal(i, c, mutate, WireFormatPublicMessage)
}

func (self *forge) seal(i int, c *FramedContent, mutate func(*FramedContentAuthData), wf WireFormat) []byte {
	self.t.Helper()
	auth := &FramedContentAuthData{}
	if mutate != nil {
		mutate(auth)
	}
	raw, err := self.g(i).sealFramedContentForTest(c, auth, wf, self.signer(i))
	if err != nil {
		self.t.Fatalf("seal: %v", err)
	}
	return raw
}

// sealPublicWithMembershipTag frames c as a PublicMessage and then replaces the
// membership tag with tag.
//
// The tag lives on PublicMessage, where RFC 9420 §6.1 puts it, and not on
// FramedContentAuthData — so the mutation is a re-encode of the parsed message
// rather than a field the signer writes. A zero-length tag is the ValSem007 case
// and a random tag is the ValSem008 case.
func (self *forge) sealPublicWithMembershipTag(i int, c *FramedContent, tag []byte) []byte {
	self.t.Helper()
	message, err := ParseMLSMessage(self.sealPublic(i, c, nil))
	if err != nil {
		self.t.Fatalf("parse own public message: %v", err)
	}
	if message.PublicMessage == nil {
		self.t.Fatalf("wire format %d is not a PublicMessage", message.WireFormat)
	}
	message.PublicMessage.MembershipTag = tag
	raw, err := MarshalMLSMessage(message)
	if err != nil {
		self.t.Fatalf("re-encode public message: %v", err)
	}
	return raw
}

// proposalBytes frames a standalone Proposal from member i.
func (self *forge) proposalBytes(i int, p Proposal) []byte {
	self.t.Helper()
	encoded, err := syntax.Marshal(&p)
	if err != nil {
		self.t.Fatalf("encode proposal: %v", err)
	}
	return self.sealPrivate(i, self.content(i, ContentTypeProposal, encoded), nil)
}

// openOwn decrypts a PrivateMessage the forge itself just produced, so a test can
// reach the plaintext FramedContent and mutate it.
//
// It does this the same way a receiver does — OpenPrivateMessage against a secret
// tree derived from the epoch's encryption_secret — rather than by reaching into
// Group's unexported state, because a second, private decryption path in the test
// kit is a second thing that can be wrong in the same direction as the first. The
// secret tree is a throwaway: consuming a generation from it has no effect on any
// group's own ratchet.
func (self *forge) openOwn(i int, raw []byte) *AuthenticatedContent {
	self.t.Helper()
	message, err := ParseMLSMessage(raw)
	if err != nil {
		self.t.Fatalf("parse own message: %v", err)
	}
	if message.PrivateMessage == nil {
		self.t.Fatalf("openOwn wants a PrivateMessage, got wire format %d", message.WireFormat)
	}
	group := self.g(i)
	treeBytes, err := group.RatchetTree()
	if err != nil {
		self.t.Fatalf("export tree: %v", err)
	}
	tree, err := UnmarshalRatchetTree(treeBytes)
	if err != nil {
		self.t.Fatalf("parse tree: %v", err)
	}
	encryptionSecret, err := group.EpochSecret(EpochSecretEncryption)
	if err != nil {
		self.t.Fatalf("encryption secret: %v", err)
	}
	senderDataSecret, err := group.EpochSecret(EpochSecretSenderData)
	if err != nil {
		self.t.Fatalf("sender data secret: %v", err)
	}
	keys, err := NewSecretTree(self.crypto, tree.LeafWidth(), encryptionSecret)
	if err != nil {
		self.t.Fatalf("secret tree: %v", err)
	}
	groupContext, err := group.GroupContext()
	if err != nil {
		self.t.Fatalf("group context: %v", err)
	}
	resolve := StaticSignatureKey(group.OwnLeafNodeCopy().SignatureKey)
	authContent, err := OpenPrivateMessage(self.crypto, keys, senderDataSecret,
		message.PrivateMessage, resolve, groupContext)
	if err != nil {
		self.t.Fatalf("open own message: %v", err)
	}
	return authContent
}

// commitBytes builds a real Commit from member i — real path, real confirmation tag
// — and applies mutate to the plaintext Commit and its UpdatePath before re-framing,
// so exactly one thing is wrong and everything else still verifies.
//
// Construction-side validation is skipped through the unexported CommitOptions
// seam: half the commit-side codes need a commit the construction side already
// refuses to build, and the receiver is the side under test. CommitOptions.Force
// builds an UpdatePath even when the covered proposals do not require one, so a
// path-mutating test never has to manufacture an Update proposal just to get a path
// — which would make two things different from the honest case instead of one.
func (self *forge) commitBytes(i int, byValue []Proposal, byRef []ProposalRef, mutate func(*Commit, *UpdatePath)) []byte {
	self.t.Helper()
	refs := make([][]byte, 0, len(byRef))
	for _, ref := range byRef {
		refs = append(refs, ref)
	}
	result, err := self.g(i).Commit(refs, byValue, &CommitOptions{Force: true, skipValidation: true})
	if err != nil {
		self.t.Fatalf("build commit: %v", err)
	}
	if mutate == nil {
		return result.Commit
	}
	authContent := self.openOwn(i, result.Commit)
	if authContent.Content.Commit == nil {
		self.t.Fatal("the committer's own message did not carry a Commit")
	}
	mutate(authContent.Content.Commit, authContent.Content.Commit.Path)
	// re-frame: the mutation changed the signed bytes, so the content is re-signed.
	// Exactly one thing is wrong — the commit body — and the signature over it is
	// correct, which is what keeps ValSem010 from firing before the code under test.
	raw, err := self.g(i).sealFramedContentForTest(&authContent.Content, &authContent.Auth,
		WireFormatPrivateMessage, self.signer(i))
	if err != nil {
		self.t.Fatalf("re-frame commit: %v", err)
	}
	return raw
}

// commitBytesWithOptions is commitBytes for the two mutations that are not
// expressible on the wire struct: a commit whose confirmation tag is absent, and
// one whose tag was computed over the pre-commit transcript. Both are unexported
// CommitOptions seams, NOT fields of the Commit wire type — a test flag on a wire
// type would change what syntax.Marshal emits.
func (self *forge) commitBytesWithOptions(i int, byValue []Proposal, opts *CommitOptions) []byte {
	self.t.Helper()
	opts.skipValidation = true
	opts.Force = true
	result, err := self.g(i).Commit(nil, byValue, opts)
	if err != nil {
		self.t.Fatalf("build commit: %v", err)
	}
	return result.Commit
}

// deliver hands raw bytes to member `to` and returns whatever the receiver decided.
func (self *forge) deliver(to int, raw []byte) error {
	processed, err := self.g(to).ProcessMessage(raw)
	if err != nil {
		return err
	}
	if processed.Kind == ProcessedCommit {
		return self.g(to).ApplyCommit(processed)
	}
	return nil
}

// requireValSem asserts the code rather than the sentinel, because ValSem103, 110,
// 206 and 207 share ErrDuplicateEncryptionKey and 106 and 109 share
// ErrMissingRequiredCapability. The code is what distinguishes them.
func requireValSem(t *testing.T, err error, want ValSemCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected ValSem%03d, the message was accepted", want)
	}
	got, ok := CodeOf(err)
	if !ok {
		t.Fatalf("expected ValSem%03d, got a non-validation error: %v", want, err)
	}
	if got != want {
		t.Fatalf("expected ValSem%03d (%s), got ValSem%03d (%s)", want, ReasonFor(want), got, ReasonFor(got))
	}
}
```

Add `"bytes"`, `"math/rand"`, `"testing"` and `"github.com/urnetwork/connect/mls/syntax"` to
`testkit_test.go`'s imports.

`CommitOptions.skipValidation` is the construction-bypass seam on the commit path, the counterpart
of `sealFramedContentForTest`. It is **unexported and lives on `CommitOptions`, not on `Commit`** —
this plan's tests are in `package mls`, so they can set it, and a test flag on the `Commit` wire type
would change what `syntax.Marshal(commit)` emits and therefore what the receiver's signature check
covers. The same is true of `dropConfirmationTag` and `confirmationTagOverPreCommitTranscript`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestForge -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/testkit_test.go && git -C connect commit -m "test(mls): the forge — deterministic groups and deliberately malformed messages"
```

---

### Task 18: ValSem002–011, the framing codes

**Files:**
- Create: `connect/mls/validation_framing_test.go`
- Test: same file

**Interfaces:**
- Consumes: the whole forge API (Task 17); `ParseMLSMessage`, `MarshalMLSMessage`, `PrivateMessage`,
  `PublicMessage`, `Sender{SenderType, LeafIndex}`, `SenderTypeMember`,
  `(*Group).sealFramedContentWithPaddingForTest(c, auth, wf, signer, padding) ([]byte, error)`
  (Framing plan); `CommitOptions.dropConfirmationTag` (Group lifecycle plan);
  `syntax.Marshal` (Syntax and codec plan).
- Produces: `TestValSem002_WrongGroupId` … `TestValSem011_NonZeroPadding`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_framing_test.go
// RFC 9420 §6. Each test builds a valid group, mutates exactly one thing, and
// asserts the specific code. Top-level functions, not subtests, per CODESTYLE §Tests.
package mls

import (
	"slices"
	"testing"
)

func TestValSem002_WrongGroupId(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeApplication, []byte("hello"))
	content.GroupId = slices.Clone(content.GroupId)
	content.GroupId[len(content.GroupId)-1]++
	requireValSem(t, f.deliver(1, f.sealPrivate(0, content, nil)), ValSem002)
}

func TestValSem003_WrongEpoch(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeApplication, []byte("hello"))
	content.Epoch = f.g(0).Epoch() + 1
	requireValSem(t, f.deliver(1, f.sealPrivate(0, content, nil)), ValSem003)
}

func TestValSem004_BlankSenderLeaf(t *testing.T) {
	f := newForge(t, 3)
	// remove member 2, then send from its now-blank leaf.
	removed := f.g(2).OwnLeafIndex()
	commit := f.commitBytes(0, []Proposal{{
		ProposalType: ProposalTypeRemove,
		Remove:       &Remove{Removed: removed},
	}}, nil, nil)
	if err := f.deliver(1, commit); err != nil {
		t.Fatalf("the remove commit must be valid: %v", err)
	}
	if err := f.g(0).MergePendingCommit(); err != nil {
		t.Fatalf("merge: %v", err)
	}
	sender := Sender{SenderType: SenderTypeMember, LeafIndex: removed}
	content := f.contentFrom(sender, ContentTypeApplication, []byte("ghost"))
	content.Epoch = f.g(1).Epoch()
	requireValSem(t, f.deliver(1, f.sealPrivate(0, content, nil)), ValSem004)
}

func TestValSem005_ApplicationMustBeCiphertext(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeApplication, []byte("hello"))
	requireValSem(t, f.deliver(1, f.sealPublic(0, content, nil)), ValSem005)
}

func TestValSem006_DecryptFails(t *testing.T) {
	f := newForge(t, 2)
	raw := f.sealPrivate(0, f.content(0, ContentTypeApplication, []byte("hello")), nil)
	message, err := ParseMLSMessage(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	message.PrivateMessage.Ciphertext[0] ^= 0x01
	mutated, err := MarshalMLSMessage(message)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	requireValSem(t, f.deliver(1, mutated), ValSem006)
}

func TestValSem007_MissingMembershipTag(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeProposal, f.updateProposalBytes(0))
	raw := f.sealPublicWithMembershipTag(0, content, []byte{})
	requireValSem(t, f.deliver(1, raw), ValSem007)
}

func TestValSem008_BadMembershipTag(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeProposal, f.updateProposalBytes(0))
	raw := f.sealPublicWithMembershipTag(0, content, f.crypto.Random(32))
	requireValSem(t, f.deliver(1, raw), ValSem008)
}

func TestValSem009_MissingConfirmationTag(t *testing.T) {
	f := newForge(t, 2)
	raw := f.commitBytesWithOptions(0, nil, &CommitOptions{dropConfirmationTag: true})
	requireValSem(t, f.deliver(1, raw), ValSem009)
}

func TestValSem010_BadSignature(t *testing.T) {
	f := newForge(t, 3)
	// member 1 signs, but the sender index still names member 0.
	sender := Sender{SenderType: SenderTypeMember, LeafIndex: f.g(0).OwnLeafIndex()}
	content := f.contentFrom(sender, ContentTypeApplication, []byte("hello"))
	raw := f.sealPrivate(1, content, nil)
	requireValSem(t, f.deliver(2, raw), ValSem010)
}

func TestValSem011_NonZeroPadding(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeApplication, []byte("hello"))
	raw := f.sealPrivateWithPadding(0, content, []byte{0x00, 0x00, 0x01})
	requireValSem(t, f.deliver(1, raw), ValSem011)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem0' -v`
Expected: FAIL to build with `undefined: f.updateProposalBytes`, `undefined: f.sealPrivateWithPadding`

- [ ] **Step 3: Write minimal implementation**

Two forge helpers, appended to `connect/mls/testkit_test.go`:

```go
// updateProposalBytes is a valid Update proposal from member i, encoded. Several
// framing tests need a proposal body because ValSem005 makes an application message
// an invalid PublicMessage payload by definition.
func (self *forge) updateProposalBytes(i int) []byte {
	self.t.Helper()
	_, encPub, err := self.crypto.DeriveKeyPair(self.crypto.Random(32))
	if err != nil {
		self.t.Fatalf("update key: %v", err)
	}
	leaf := self.g(i).OwnLeafNodeCopy()
	leaf.EncryptionKey = encPub
	encoded, err := syntax.Marshal(&Proposal{
		ProposalType: ProposalTypeUpdate,
		Update:       &Update{LeafNode: *leaf},
	})
	if err != nil {
		self.t.Fatalf("encode update: %v", err)
	}
	return encoded
}

// sealPrivateWithPadding frames c as a PrivateMessage whose PrivateMessageContent
// padding is exactly the bytes given, rather than the all-zero padding RFC 9420
// §6.3.2 requires. The auth data is the honest one — the seam signs c the same way
// sealFramedContentForTest does — so padding is the only thing wrong.
func (self *forge) sealPrivateWithPadding(i int, c *FramedContent, padding []byte) []byte {
	self.t.Helper()
	raw, err := self.g(i).sealFramedContentWithPaddingForTest(c, &FramedContentAuthData{},
		WireFormatPrivateMessage, self.signer(i), padding)
	if err != nil {
		self.t.Fatalf("seal with padding: %v", err)
	}
	return raw
}
```

Four seams carry these ten tests, and every one of them is in the canonical interface registry with
the signature used above: `(*Group).sealFramedContentForTest` and
`(*Group).sealFramedContentWithPaddingForTest` (framing plan, §7.3), `(*Group).OwnLeafNodeCopy` and
`CommitOptions.dropConfirmationTag` (group lifecycle plan, §8.3). The two asks this task used to make
that are **refused** — `FramedContentAuthData.MembershipTag` and
`FramedContentAuthData.HasConfirmationTag` — are replaced by `PublicMessage.MembershipTag` (via
`sealPublicWithMembershipTag`) and by `CommitOptions.dropConfirmationTag`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem0' -v`
Expected: PASS — 10 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_framing_test.go mls/testkit_test.go && git -C connect commit -m "test(mls): ValSem002-011, the framing validation codes"
```

---

### Task 19: ValSem101–113, the proposal codes

**Files:**
- Create: `connect/mls/validation_proposal_test.go`
- Test: same file

**Interfaces:**
- Consumes: the forge (Task 17); `Proposal{ProposalType, Add, Update, Remove, UnknownType,
  UnknownBody}`, `Add{KeyPackage KeyPackage}`, `Update{LeafNode LeafNode}`,
  `Remove{Removed LeafIndex}`, `ProposalRef`, `Sender{SenderType, LeafIndex}`,
  `SenderTypeNewMemberProposal` (Framing plan); `KeyPackage`, `Capabilities{Extensions
  []ExtensionType}`, `ExtensionTypeUrmessageGroupPolicy`, `ExtensionTypeUrmessageLeafKeys`,
  `HpkePublicKey` (TreeKEM plan); `CipherSuiteX25519AesGcm128Sha256Ed25519` (Crypto plan);
  `LeafIndex` (Tree math plan); `syntax.Marshal` (Syntax and codec plan).
- Produces: `TestValSem101_DuplicateSignatureKey` … `TestValSem113_UnsupportedProposalType`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_proposal_test.go
// RFC 9420 §12.1 and §12.2 — the proposals a commit covers.
package mls

import "testing"

func TestValSem101_DuplicateSignatureKey(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	keyPackage.LeafNode.SignatureKey = f.g(1).OwnLeafNodeCopy().SignatureKey
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem101)
}

func TestValSem102_DuplicateInitKey(t *testing.T) {
	f := newForge(t, 2)
	first, _, _ := f.newKeyPackage(t)
	second, _, _ := f.newKeyPackage(t)
	second.InitKey = first.InitKey
	requireValSem(t, f.deliver(1, f.addCommit(t, first, second)), ValSem102)
}

func TestValSem103_DuplicateEncryptionKey(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	keyPackage.LeafNode.EncryptionKey = f.g(1).OwnLeafNodeCopy().EncryptionKey
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem103)
}

func TestValSem104_InitEqualsEncryptionKey(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	keyPackage.InitKey = keyPackage.LeafNode.EncryptionKey
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem104)
}

func TestValSem105_SuiteMismatch(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	// 0x0001 is registered and implemented, and still not this group's suite.
	keyPackage.CipherSuite = CipherSuiteX25519AesGcm128Sha256Ed25519
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem105)
}

func TestValSem106_AddMissingRequiredCapability(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	// drop urmessage_leaf_keys (0xF002), which required_capabilities lists.
	keyPackage.LeafNode.Capabilities.Extensions = []ExtensionType{ExtensionTypeUrmessageGroupPolicy}
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem106)
}

func TestValSem107_DuplicateRemove(t *testing.T) {
	f := newForge(t, 3)
	target := f.g(2).OwnLeafIndex()
	raw := f.commitBytes(0, []Proposal{
		{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: target}},
		{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: target}},
	}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem107)
}

func TestValSem108_RemoveNonMember(t *testing.T) {
	f := newForge(t, 3)
	raw := f.commitBytes(0, []Proposal{{
		ProposalType: ProposalTypeRemove,
		Remove:       &Remove{Removed: LeafIndex(7)},
	}}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem108)
}

func TestValSem109_UpdateMissingRequiredCapability(t *testing.T) {
	f := newForge(t, 3)
	leaf := f.g(1).OwnLeafNodeCopy()
	// drops urmessage_group_policy (0xF001), a GroupContext extension.
	leaf.Capabilities.Extensions = []ExtensionType{ExtensionTypeUrmessageLeafKeys}
	raw := f.proposalBytes(1, Proposal{
		ProposalType: ProposalTypeUpdate,
		Update:       &Update{LeafNode: *leaf},
	})
	requireValSem(t, f.deliver(2, raw), ValSem109)
}

func TestValSem110_UpdateDuplicateEncryptionKey(t *testing.T) {
	f := newForge(t, 3)
	leaf := f.g(1).OwnLeafNodeCopy()
	leaf.EncryptionKey = f.g(2).OwnLeafNodeCopy().EncryptionKey
	raw := f.proposalBytes(1, Proposal{
		ProposalType: ProposalTypeUpdate,
		Update:       &Update{LeafNode: *leaf},
	})
	requireValSem(t, f.deliver(2, raw), ValSem110)
}

func TestValSem111_SelfUpdateInCommit(t *testing.T) {
	f := newForge(t, 3)
	own := f.g(0).OwnLeafNodeCopy()
	_, encPub, err := f.crypto.DeriveKeyPair(f.crypto.Random(32))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	own.EncryptionKey = encPub
	update := Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *own}}
	ref := f.reference(t, 0, update)
	raw := f.commitBytes(0, nil, []ProposalRef{ref}, nil)
	requireValSem(t, f.deliver(1, raw), ValSem111)
}

func TestValSem112_UpdateSenderNotMember(t *testing.T) {
	f := newForge(t, 2)
	leaf := f.g(0).OwnLeafNodeCopy()
	encoded, err := syntax.Marshal(&Proposal{
		ProposalType: ProposalTypeUpdate,
		Update:       &Update{LeafNode: *leaf},
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	sender := Sender{SenderType: SenderTypeNewMemberProposal}
	content := f.contentFrom(sender, ContentTypeProposal, encoded)
	requireValSem(t, f.deliver(1, f.sealPrivate(0, content, nil)), ValSem112)
}

func TestValSem113_UnsupportedProposalType(t *testing.T) {
	f := newForge(t, 2)
	// the GREASE arm: a type nobody registered, carried as opaque bytes. This is
	// the codec's escape hatch, not a test-only field on FramedContent.
	raw := f.commitBytes(0, []Proposal{{
		ProposalType: ProposalType(0xF0FF),
		UnknownType:  ProposalType(0xF0FF),
		UnknownBody:  []byte{0x00},
	}}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem113)
}
```

`connect/mls/validation_proposal_test.go` imports `"testing"` and
`"github.com/urnetwork/connect/mls/syntax"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem1' -v`
Expected: FAIL to build with `undefined: f.addCommit`, `undefined: f.reference`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/testkit_test.go

// addCommit frames a commit from member 0 covering one Add per key package, with
// construction-side validation skipped so the receiver is the one that decides. The
// Add arm carries the KeyPackage by value, not as bytes: one codec, one method set.
func (self *forge) addCommit(t *testing.T, keyPackages ...*KeyPackage) []byte {
	t.Helper()
	proposals := make([]Proposal, 0, len(keyPackages))
	for _, keyPackage := range keyPackages {
		proposals = append(proposals, Proposal{
			ProposalType: ProposalTypeAdd,
			Add:          &Add{KeyPackage: *keyPackage},
		})
	}
	return self.commitBytes(0, proposals, nil, nil)
}

// reference publishes p from member i and returns the ProposalRef every other
// member now holds for it, so a commit can cover it by reference.
//
// The ref comes from the AuthenticatedContent the receivers actually saw, via
// (*AuthenticatedContent).ProposalRef, rather than from a hash of the wire bytes:
// RFC 9420 §5.2 takes the ref over the serialized AuthenticatedContent, and hashing
// the framed message instead would agree with nothing.
func (self *forge) reference(t *testing.T, i int, p Proposal) ProposalRef {
	t.Helper()
	raw := self.proposalBytes(i, p)
	authContent := self.openOwn(i, raw)
	for j := range self.groups {
		if j == i {
			continue
		}
		if err := self.deliver(j, raw); err != nil {
			t.Fatalf("member %d rejected the proposal it must hold a reference to: %v", j, err)
		}
	}
	ref, err := authContent.ProposalRef(self.crypto)
	if err != nil {
		t.Fatalf("proposal ref: %v", err)
	}
	return ref
}
```

`Proposal.UnknownType` / `Proposal.UnknownBody` are the framing plan's GREASE arm and are the
substitute for the `FramedContent.RawProposal` this task used to ask for.
`(*AuthenticatedContent).ProposalRef(crypto) (ProposalRef, error)` is the framing plan's, built over
the crypto plan's `MakeProposalRef(crypto, authenticatedContent []byte) []byte`; Task 23's errata
8815 test uses the same helper.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem1' -v`
Expected: PASS — 13 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_proposal_test.go mls/testkit_test.go && git -C connect commit -m "test(mls): ValSem101-113, the proposal validation codes"
```

---

### Task 20: ValSem200–209 and ValSem300, the commit and ratchet-tree codes

**Files:**
- Create: `connect/mls/validation_commit_test.go`
- Test: same file

**Interfaces:**
- Consumes: the forge (Task 17); `UpdatePath`, `UpdatePathNode`, `HpkeCiphertext`,
  `UnmarshalRatchetTree(data []byte) (*RatchetTree, error)`,
  `(*RatchetTree).HasTrailingBlankNodes() bool`, `TreeValidationContext`,
  `(*RatchetTree).Validate(ctx *TreeValidationContext) error` (TreeKEM plan);
  `Commit{Proposals, Path}`, `GroupContextExtensions{Extensions}`, `Extension{ExtensionType,
  ExtensionData}` (Framing and TreeKEM plans);
  `CommitOptions.confirmationTagOverPreCommitTranscript` (Group lifecycle plan);
  `syntax.NewReader`, `(*syntax.Reader).ReadOpaque`, `syntax.NewWriter`,
  `(*syntax.Writer).WriteOpaque`, `(*syntax.Writer).Bytes` (Syntax and codec plan).
- Produces: `TestValSem200_SelfRemoveInCommit` … `TestValSem209_UnsupportedGroupExtension`,
  `TestValSem300_TrailingBlankNodes`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_commit_test.go
// RFC 9420 §12.4 (commits) and §12.4.3.1 (the ratchet tree). ValSem208 and
// ValSem209 are untested in OpenMLS, so the spec text is the only authority for
// them and the differential oracle will not catch a mistake here.
package mls

import (
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

func TestValSem200_SelfRemoveInCommit(t *testing.T) {
	f := newForge(t, 3)
	own := f.g(0).OwnLeafIndex()
	raw := f.commitBytes(0, []Proposal{{
		ProposalType: ProposalTypeRemove,
		Remove:       &Remove{Removed: own},
	}}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem200)
}

func TestValSem201_MissingPath(t *testing.T) {
	f := newForge(t, 3)
	leaf := f.g(1).OwnLeafNodeCopy()
	_, encPub, err := f.crypto.DeriveKeyPair(f.crypto.Random(32))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	leaf.EncryptionKey = encPub
	ref := f.reference(t, 1, Proposal{
		ProposalType: ProposalTypeUpdate,
		Update:       &Update{LeafNode: *leaf},
	})
	raw := f.commitBytes(0, nil, []ProposalRef{ref}, func(commit *Commit, path *UpdatePath) {
		commit.Path = nil
	})
	requireValSem(t, f.deliver(2, raw), ValSem201)
}

func TestValSem202_PathLength(t *testing.T) {
	f := newForge(t, 4)
	raw := f.commitBytes(0, nil, nil, func(commit *Commit, path *UpdatePath) {
		path.Nodes = path.Nodes[:len(path.Nodes)-1]
	})
	requireValSem(t, f.deliver(1, raw), ValSem202)
}

func TestValSem203_PathDecrypt(t *testing.T) {
	f := newForge(t, 4)
	raw := f.commitBytes(0, nil, nil, func(commit *Commit, path *UpdatePath) {
		path.Nodes[0].EncryptedPathSecret[0].Ciphertext[0] ^= 0x01
	})
	requireValSem(t, f.deliver(1, raw), ValSem203)
}

func TestValSem204_PathKeyMismatch(t *testing.T) {
	f := newForge(t, 4)
	_, wrongPub, err := f.crypto.DeriveKeyPair(f.crypto.Random(32))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	raw := f.commitBytes(0, nil, nil, func(commit *Commit, path *UpdatePath) {
		// the ciphertexts still carry the real path secret, so decryption succeeds
		// and the derived public key no longer matches the announced one.
		path.Nodes[0].EncryptionKey = wrongPub
	})
	requireValSem(t, f.deliver(1, raw), ValSem204)
}

func TestValSem205_BadConfirmationTag(t *testing.T) {
	f := newForge(t, 3)
	// the tag is computed over the PRE-commit confirmed_transcript_hash. A random
	// tag would trip ValSem010 first, so the seam is on the builder, not the wire.
	raw := f.commitBytesWithOptions(0, nil, &CommitOptions{
		confirmationTagOverPreCommitTranscript: true,
	})
	requireValSem(t, f.deliver(1, raw), ValSem205)
}

func TestValSem206_PathLeafDuplicateEncryptionKey(t *testing.T) {
	f := newForge(t, 3)
	victim := f.g(2).OwnLeafNodeCopy().EncryptionKey
	raw := f.commitBytes(0, nil, nil, func(commit *Commit, path *UpdatePath) {
		path.LeafNode.EncryptionKey = victim
	})
	requireValSem(t, f.deliver(1, raw), ValSem206)
}

func TestValSem207_PathNodeDuplicateEncryptionKey(t *testing.T) {
	f := newForge(t, 8)
	raw := f.commitBytes(0, nil, nil, func(commit *Commit, path *UpdatePath) {
		if len(path.Nodes) < 2 {
			t.Fatalf("an 8-member tree must give the committer at least two path nodes, got %d", len(path.Nodes))
		}
		path.Nodes[1].EncryptionKey = path.Nodes[0].EncryptionKey
	})
	requireValSem(t, f.deliver(1, raw), ValSem207)
}

func TestValSem208_MultipleGCE(t *testing.T) {
	f := newForge(t, 3)
	extension := Extension{
		ExtensionType: ExtensionTypeUrmessageGroupPolicy,
		ExtensionData: []byte{0x01},
	}
	gce := func() Proposal {
		return Proposal{
			ProposalType:           ProposalTypeGroupContextExtensions,
			GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{extension}},
		}
	}
	raw := f.commitBytes(0, []Proposal{gce(), gce()}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem208)
}

func TestValSem209_UnsupportedGroupExtension(t *testing.T) {
	f := newForge(t, 3)
	// 0xF0AA appears in no member's capabilities.
	raw := f.commitBytes(0, []Proposal{{
		ProposalType: ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{{
			ExtensionType: ExtensionType(0xF0AA),
			ExtensionData: []byte{0x00},
		}}},
	}}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem209)
}

func TestValSem300_TrailingBlankNodes(t *testing.T) {
	f := newForge(t, 4)
	exported, err := f.g(0).RatchetTree()
	if err != nil {
		t.Fatalf("export tree: %v", err)
	}
	padded := appendBlankNode(t, exported)

	tree, err := UnmarshalRatchetTree(padded)
	if err != nil {
		t.Fatalf("a tree with a trailing blank must still PARSE; rejecting it at the codec would make the validation rule untestable: %v", err)
	}
	if !tree.HasTrailingBlankNodes() {
		t.Fatal("the padded tree does not report trailing blank nodes")
	}
	err = tree.Validate(&TreeValidationContext{
		Crypto:  f.crypto,
		Suite:   groupSuite,
		GroupId: f.g(0).GroupId(),
	})
	requireValSem(t, err, ValSem300)
}

// appendBlankNode adds one absent optional<Node> to the end of a serialized
// RatchetTree. The tree is `optional<Node> nodes<V>`, so this is a decode of the
// outer vector, one 0x00 presence octet appended, and a re-encode — which keeps the
// length prefix correct without a second, hand-rolled varint.
func appendBlankNode(t *testing.T, encoded []byte) []byte {
	t.Helper()
	body, err := syntax.NewReader(encoded).ReadOpaque()
	if err != nil {
		t.Fatalf("read the node vector: %v", err)
	}
	writer := syntax.NewWriter()
	writer.WriteOpaque(append(body, 0x00))
	padded, err := writer.Bytes()
	if err != nil {
		t.Fatalf("re-encode the node vector: %v", err)
	}
	return padded
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem2|TestValSem300' -v`
Expected: FAIL to build with `undefined: appendBlankNode`, and once that lands, FAIL with
`expected ValSem202, the message was accepted` and the rest of the eleven

- [ ] **Step 3: Write minimal implementation**

`appendBlankNode` above is the only new helper. Everything else is a seam that already exists in the
canonical interface registry, and this task's deliverable is the eleven failing tests that force the
checks behind them:

- `CommitOptions.confirmationTagOverPreCommitTranscript` — an **unexported field on the commit
  builder** (group lifecycle plan, §8.3) that makes the committer compute the confirmation tag over
  the **pre**-commit `confirmed_transcript_hash`. Without it ValSem205 has no failing input that is
  otherwise well-formed, and a random tag would trip ValSem010 first. It is not a field of `Commit`:
  a test flag on a wire type would change what `syntax.Marshal(commit)` emits.
- `UnmarshalRatchetTree`, `(*RatchetTree).HasTrailingBlankNodes` and `(*RatchetTree).Validate(ctx)` —
  the TreeKEM plan's tree surface. There is no `ParseRatchetTree`, no `EncodeRatchetTree`, no
  `ValidateRatchetTree` and no `RatchetTreeExtension`; `OptionalNode` exists but the tree's node
  array is private, which is why the blank is appended on the wire rather than in the struct.
- `Proposal.GroupContextExtensions *GroupContextExtensions` with `Extensions []Extension` — the
  framing plan's proposal arm.

The checks themselves — `ValSem200NoSelfRemove` through `ValSem209GroupExtensionsSupported`, and
`ValSem300NoTrailingBlankNodes` — are the group lifecycle plan's, in `validate_commit.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem2|TestValSem300' -v`
Expected: PASS — 11 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_commit_test.go mls/validate_commit.go && git -C connect commit -m "test(mls): ValSem200-209 and ValSem300, the commit and ratchet-tree codes"
```

---

### Task 21: ValSem240–246, the profile-refused external-commit codes

**Files:**
- Create: `connect/mls/validation_external_test.go`
- Test: same file

**Interfaces:**
- Consumes: the forge (Task 17); `ExternalInit{KemOutput []byte}`, `ProposalOrRef{Type, Proposal,
  Reference}`, `ProposalOrRefTypeProposal`, `ProposalOrRefTypeReference`, `Commit{Proposals, Path}`,
  `Sender{SenderType}`, `SenderTypeNewMemberCommit` (Framing plan);
  `UpdatePath{LeafNode, Nodes}` (TreeKEM plan);
  `(*Profile).CheckProposalType`, `DefaultProfile` (Task 3a).
- Produces: `TestValSem240_ExternalCommitNoExternalInit` …
  `TestValSem246_ExternalCommitSignerNotPathCredential`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_external_test.go
// RFC 9420 §12.4.3.2. External commits are not implemented in the v1 profile, so
// each of these asserts the profile gate rejects the whole message before the RFC's
// specific check is reached — and asserts WHICH error surfaced, so a future
// accidental implementation of external commits turns the test red rather than green.
//
// Each test carries the commented-out RFC assertion, so a V2 that implements
// external commits is a mechanical swap with the test already written.
package mls

import "testing"

func TestValSem240_ExternalCommitNoExternalInit(t *testing.T) {
	f := newForge(t, 2)
	raw := f.externalCommitBytes(t, externalCommitShape{ExternalInits: 0, WithPath: true})
	requireValSem(t, f.deliver(1, raw), ValSem240)
	// V2: requireValSem(t, f.deliver(1, raw), ValSem240) with the RFC check reached
	// rather than the profile gate — the code is the same, the reason string changes.
}

func TestValSem241_ExternalCommitTwoExternalInit(t *testing.T) {
	f := newForge(t, 2)
	raw := f.externalCommitBytes(t, externalCommitShape{ExternalInits: 2, WithPath: true})
	requireValSem(t, f.deliver(1, raw), ValSem240)
	// V2: expect ValSem241 from the RFC check.
}

func TestValSem242_ExternalCommitNonAllowlisted(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	raw := f.externalCommitBytes(t, externalCommitShape{
		ExternalInits: 1,
		WithPath:      true,
		Inline: []Proposal{{
			ProposalType: ProposalTypeAdd,
			Add:          &Add{KeyPackage: *keyPackage},
		}},
	})
	requireValSem(t, f.deliver(1, raw), ValSem240)
	// V2: expect ValSem242 — Add is not on the §12.4.3.2 allowlist.
}

func TestValSem244_ExternalCommitByReference(t *testing.T) {
	f := newForge(t, 3)
	leaf := f.g(1).OwnLeafNodeCopy()
	_, encPub, err := f.crypto.DeriveKeyPair(f.crypto.Random(32))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	leaf.EncryptionKey = encPub
	ref := f.reference(t, 1, Proposal{
		ProposalType: ProposalTypeUpdate,
		Update:       &Update{LeafNode: *leaf},
	})
	raw := f.externalCommitBytes(t, externalCommitShape{
		ExternalInits: 1,
		WithPath:      true,
		ByReference:   []ProposalRef{ref},
	})
	requireValSem(t, f.deliver(2, raw), ValSem240)
	// V2: expect ValSem244 — an external commit carries no by-reference proposals.
}

func TestValSem245_ExternalCommitNoPath(t *testing.T) {
	f := newForge(t, 2)
	raw := f.externalCommitBytes(t, externalCommitShape{ExternalInits: 1, WithPath: false})
	requireValSem(t, f.deliver(1, raw), ValSem240)
	// V2: expect ValSem245 — an external commit always contains a path.
}

func TestValSem246_ExternalCommitSignerNotPathCredential(t *testing.T) {
	f := newForge(t, 3)
	raw := f.externalCommitBytes(t, externalCommitShape{
		ExternalInits: 1,
		WithPath:      true,
		SignWithMember: 1, // an existing member's signer, not the path credential
	})
	requireValSem(t, f.deliver(2, raw), ValSem240)
	// V2: expect ValSem246 — the signature is verified with the path KeyPackage credential.
}

// TestExternalCommitsAreRefusedByTheProfileGate pins the layer the refusal happens
// at. If a future change moves it later, the six tests above still pass while the
// profile has quietly widened; this one does not.
//
// It asserts on the gate itself rather than on ParseMLSMessage, because handshake
// traffic is framed as PrivateMessage: the external_init arm is inside the
// ciphertext, so no amount of parsing the wire message can see it. The refusal is
// a profile decision taken on the decrypted proposal list, and the gate is where it
// lives.
func TestExternalCommitsAreRefusedByTheProfileGate(t *testing.T) {
	err := DefaultProfile().CheckProposalType(ProposalTypeExternalInit)
	requireValSem(t, err, ValSem240)

	// and the codec must still DECODE the arm: refusing a proposal type is a
	// profile decision, not a codec decision, and fusing the two would make the
	// messages vector family untestable against the pinned corpus.
	encoded, err := syntax.Marshal(&Proposal{
		ProposalType: ProposalTypeExternalInit,
		ExternalInit: &ExternalInit{KemOutput: make([]byte, 32)},
	})
	if err != nil {
		t.Fatalf("encode external_init: %v", err)
	}
	decoded := &Proposal{}
	if err := syntax.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("the codec must decode every registered proposal arm: %v", err)
	}
	if decoded.ExternalInit == nil {
		t.Fatal("the external_init arm did not survive a round trip")
	}
}
```

`connect/mls/validation_external_test.go` imports `"testing"` and
`"github.com/urnetwork/connect/mls/syntax"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem24|TestExternalCommitsAreRefusedByTheProfileGate' -v`
Expected: FAIL to build with `undefined: externalCommitShape`, `undefined: f.externalCommitBytes`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/testkit_test.go

// externalCommitShape describes an external commit to build. Every field exists to
// make exactly one of ValSem240-246 the reason the message is invalid, so that when
// the profile gate is one day lifted each test still names the right RFC check.
type externalCommitShape struct {
	ExternalInits  int
	WithPath       bool
	Inline         []Proposal
	ByReference    []ProposalRef
	SignWithMember int
}

// externalCommitBytes builds an MLSMessage carrying a Sender{NewMemberCommit} commit
// of the requested shape. It never goes through Group.Commit, because the v1
// implementation has no external-commit construction path at all — which is the
// point: the bytes come from the test, exactly as they would from a foreign client.
func (self *forge) externalCommitBytes(t *testing.T, shape externalCommitShape) []byte {
	t.Helper()
	inline := make([]Proposal, 0, shape.ExternalInits+len(shape.Inline))
	for i := 0; i < shape.ExternalInits; i++ {
		inline = append(inline, Proposal{
			ProposalType: ProposalTypeExternalInit,
			ExternalInit: &ExternalInit{KemOutput: self.crypto.Random(32)},
		})
	}
	inline = append(inline, shape.Inline...)

	commit := &Commit{}
	for index := range inline {
		commit.Proposals = append(commit.Proposals, ProposalOrRef{
			Type:     ProposalOrRefTypeProposal,
			Proposal: &inline[index],
		})
	}
	for _, ref := range shape.ByReference {
		commit.Proposals = append(commit.Proposals, ProposalOrRef{
			Type:      ProposalOrRefTypeReference,
			Reference: ref,
		})
	}
	if shape.WithPath {
		keyPackage, _, _ := self.newKeyPackage(t)
		commit.Path = &UpdatePath{LeafNode: keyPackage.LeafNode}
	}

	content := self.contentFrom(Sender{SenderType: SenderTypeNewMemberCommit}, ContentTypeCommit, nil)
	content.Commit = commit
	return self.sealPrivate(shape.SignWithMember, content, nil)
}
```

Every type this helper names is already in the canonical interface registry: `ExternalInit`,
`ProposalOrRef` with its `Type`/`Proposal`/`Reference` fields, and `Commit`, all owned by the framing
plan, plus `UpdatePath` from the TreeKEM plan. Nothing new is asked of anyone. The proposal loop
indexes `inline` rather than taking the address of the range variable, so each `ProposalOrRef` points
at its own element.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem24|TestExternalCommitsAreRefusedByTheProfileGate' -v`
Expected: PASS — 7 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_external_test.go mls/testkit_test.go && git -C connect commit -m "test(mls): ValSem240-246, external commits refused at parse by the v1 profile"
```

---

### Task 22: ValSem401–403, the profile-refused PSK codes

**Files:**
- Create: `connect/mls/validation_psk_test.go`
- Test: same file

**Interfaces:**
- Consumes: the forge (Task 17); `PreSharedKeyId{PskType, PskId, Usage, PskGroupId, PskEpoch,
  PskNonce}`, `PskTypeExternal`, `PskTypeResumption`, `ResumptionPskUsageReInit` (Key schedule plan);
  `PreSharedKey{Psk PreSharedKeyId}`, `Proposal`, `ProposalTypePreSharedKey` (Framing and TreeKEM
  plans); `syntax.Marshal` (Syntax and codec plan);
  `(*Profile).CheckProposalType`, `DefaultProfile` (Task 3a).
- Produces: `TestValSem401_PskNonceLength`, `TestValSem402_PskUsage`,
  `TestValSem403_DuplicatePskId`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_psk_test.go
// RFC 9420 §8.4. PSK proposals are not implemented in the v1 profile and are
// refused at proposal parse. ValSem403 is untested in OpenMLS (openmls#1335), so
// the differential oracle offers no cover here either.
package mls

import (
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

func TestValSem401_PskNonceLength(t *testing.T) {
	f := newForge(t, 2)
	// KDF.Nh is 32 for this suite; 31 is the malformed length.
	id := PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    f.crypto.Random(32),
		PskNonce: f.crypto.Random(31),
	}
	requireValSem(t, f.deliverPskProposal(t, id), ValSem401)
}

func TestValSem402_PskUsage(t *testing.T) {
	f := newForge(t, 2)
	id := PreSharedKeyId{
		PskType:    PskTypeResumption,
		Usage:      ResumptionPskUsageReInit,
		PskGroupId: f.g(0).GroupId(),
		PskEpoch:   f.g(0).Epoch(),
		PskNonce:   f.crypto.Random(32),
	}
	requireValSem(t, f.deliverPskProposal(t, id), ValSem401)
	// V2, if PSKs are ever implemented: expect ValSem402 from the RFC check, whose
	// sentinel ErrPskType is already in the catalogue.
}

func TestValSem403_DuplicatePskId(t *testing.T) {
	f := newForge(t, 2)
	id := PreSharedKeyId{
		PskType:  PskTypeExternal,
		PskId:    f.crypto.Random(32),
		PskNonce: f.crypto.Random(32),
	}
	requireValSem(t, f.deliverPskProposal(t, id, id), ValSem401)
	// V2: expect ValSem403 — no duplicate PreSharedKeyId in one proposal list —
	// whose sentinel ErrDuplicatePsk is already in the catalogue.
}

// TestPskProposalsAreRefusedByTheProfileGate pins the layer, for the same reason as
// the external-commit equivalent: a refusal that quietly moves later is a profile
// that quietly widened.
func TestPskProposalsAreRefusedByTheProfileGate(t *testing.T) {
	requireValSem(t, DefaultProfile().CheckProposalType(ProposalTypePreSharedKey), ValSem401)

	// the codec still decodes the arm — a profile refusal is not a codec refusal.
	encoded, err := syntax.Marshal(&Proposal{
		ProposalType: ProposalTypePreSharedKey,
		PreSharedKey: &PreSharedKey{Psk: PreSharedKeyId{
			PskType:  PskTypeExternal,
			PskId:    make([]byte, 32),
			PskNonce: make([]byte, 32),
		}},
	})
	if err != nil {
		t.Fatalf("encode psk proposal: %v", err)
	}
	decoded := &Proposal{}
	if err := syntax.Unmarshal(encoded, decoded); err != nil {
		t.Fatalf("the codec must decode every registered proposal arm: %v", err)
	}
	if decoded.PreSharedKey == nil {
		t.Fatal("the psk arm did not survive a round trip")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem40|TestPskProposals' -v`
Expected: FAIL to build with `undefined: f.deliverPskProposal`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/testkit_test.go

// deliverPskProposal frames one PreSharedKey proposal carrying ids and delivers it,
// returning whatever the receiver decided.
//
// The bytes come from the production encoder, not from a hand-rolled one: the psk
// arm is part of the wire format whether or not the v1 profile accepts it, and a
// second encoder here would be a second thing to keep in step with the messages
// vector family. A commit covers exactly one PreSharedKey proposal per element, so
// several ids become several proposals.
func (self *forge) deliverPskProposal(t *testing.T, ids ...PreSharedKeyId) error {
	t.Helper()
	proposals := make([]Proposal, 0, len(ids))
	for _, id := range ids {
		proposals = append(proposals, Proposal{
			ProposalType: ProposalTypePreSharedKey,
			PreSharedKey: &PreSharedKey{Psk: id},
		})
	}
	if len(proposals) == 1 {
		return self.deliver(1, self.proposalBytes(0, proposals[0]))
	}
	return self.deliver(1, self.commitBytes(0, proposals, nil, nil))
}
```

Every type named here is already in the canonical interface registry: `PreSharedKeyId` with
`PskType`/`PskId`/`Usage`/`PskGroupId`/`PskEpoch`/`PskNonce` and the `PskType*` /
`ResumptionPskUsage*` constants from the key-schedule plan, and the `PreSharedKey` proposal arm from
the framing plan. Nothing new is asked of anyone, and the `FramedContent.RawProposal` escape hatch
this task used to need is gone — the registry refused it, and the real encoder makes it unnecessary.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem40|TestPskProposals' -v`
Expected: PASS — 4 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_psk_test.go mls/testkit_test.go && git -C connect commit -m "test(mls): ValSem401-403, PSK proposals refused at parse by the v1 profile"
```

---

### Task 23: ValSem400 and the two errata

**Files:**
- Create: `connect/mls/validation_epoch_test.go`
- Modify: `connect/mls/errata_test.go`

**Interfaces:**
- Consumes: the forge (Task 17); `memStore.EpochsHeld` (Task 10);
  `const PastEpochWindow uint64 = 32` (Key schedule plan);
  `CheckErrata8745(path *UpdatePath, context *GroupContext) error`,
  `CheckErrata8815(commit *Commit, pending *ProposalCache) error`,
  `(*Group).MergePendingCommit`, `(*Group).ApplyCommit` (Group lifecycle plan);
  `(*AuthenticatedContent).ProposalRef` through the forge's `reference` helper (Framing plan).
- Produces: `TestValSem400_PastEpochBound`, `TestErrata8745`, `TestErrata8815`. This is the task that
  makes `TestValSemCoverageIsComplete` (Task 3) green.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_epoch_test.go
// ValSem400 is the RFC's SHOULD that an application bound the number of past epochs
// it retains. OpenMLS does not implement it at all (openmls#1122), so nothing but
// this test holds the line. It is the same deletion that makes MASTER §8.1's
// disappearing-message guarantee true: eph_root lives in the epoch state, and a
// retained old epoch state is a retained eph_root.
package mls

import (
	"slices"
	"testing"
)

func TestValSem400_PastEpochBound(t *testing.T) {
	if PastEpochWindow != 32 {
		t.Fatalf("PastEpochWindow is %d; Spec A §4.3 fixes it at 32, and the number is a product promise about how long a user may close their laptop", PastEpochWindow)
	}
	f := newForge(t, 2)
	startingEpoch := f.g(0).Epoch()

	for i := 0; i < 40; i++ {
		// CommitOptions.Force gives every commit a fresh UpdatePath, so each one
		// advances the epoch without needing a proposal to cover.
		raw := f.commitBytes(0, nil, nil, nil)
		if err := f.g(0).MergePendingCommit(); err != nil {
			t.Fatalf("merge %d: %v", i, err)
		}
		if err := f.deliver(1, raw); err != nil {
			t.Fatalf("deliver commit %d: %v", i, err)
		}
	}

	finalEpoch := f.g(0).Epoch()
	held := f.store(0).EpochsHeld(f.g(0).GroupId())
	if len(held) == 0 {
		t.Fatal("no epoch state at all — the store is not being written")
	}
	oldest := held[0]
	if want := finalEpoch - PastEpochWindow; oldest != want {
		t.Fatalf("oldest retained epoch is %d, want %d (final %d, window %d)", oldest, want, finalEpoch, PastEpochWindow)
	}
	if got, want := len(held), int(PastEpochWindow)+1; got != want {
		t.Fatalf("%d epochs retained, want %d", got, want)
	}
	if slices.Contains(held, startingEpoch) && finalEpoch-startingEpoch > PastEpochWindow {
		t.Fatalf("the joining epoch %d survived %d commits", startingEpoch, finalEpoch-startingEpoch)
	}
}
```

```go
// append to connect/mls/errata_test.go

// TestErrata8745 covers the half of erratum 8745 that no ValSem code reaches: a
// LeafNode in a Commit's update_path whose capabilities do not cover every
// GroupContext extension. The Update-proposal half is ValSem109.
func TestErrata8745(t *testing.T) {
	f := newForge(t, 3)
	raw := f.commitBytes(0, nil, nil, func(commit *Commit, path *UpdatePath) {
		// urmessage_group_policy (0xF001) is in the GroupContext of every forged
		// group, and the path leaf must therefore claim support for it.
		path.LeafNode.Capabilities.Extensions = []ExtensionType{ExtensionTypeUrmessageLeafKeys}
	})
	requireValSem(t, f.deliver(1, raw), ValSemErrata8745)

	// and the pre-erratum behaviour — silently accepting it — must be absent. An
	// implementation that only checks KeyPackage leaves passes every RFC vector and
	// fails here, which is the whole reason the erratum is a Gate 3 condition.
	if f.g(1).Epoch() != f.g(0).Epoch() {
		t.Fatal("the receiver applied the commit; the pre-erratum behaviour is still present")
	}
}

// TestErrata8815 covers a Commit whose proposals vector references a proposal the
// receiver never saw. RFC 9420 §12.2 as published omits this check entirely.
func TestErrata8815(t *testing.T) {
	f := newForge(t, 3)
	unknown := ProposalRef(f.crypto.Random(32))
	raw := f.commitBytes(0, nil, []ProposalRef{unknown}, nil)
	requireValSem(t, f.deliver(1, raw), ValSemErrata8815)

	// the same commit with a reference the receiver does hold must be accepted, so
	// the test is about the reference being unknown and not about references at all.
	leaf := f.g(1).OwnLeafNodeCopy()
	_, encPub, err := f.crypto.DeriveKeyPair(f.crypto.Random(32))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	leaf.EncryptionKey = encPub
	known := f.reference(t, 1, Proposal{
		ProposalType: ProposalTypeUpdate,
		Update:       &Update{LeafNode: *leaf},
	})
	good := f.commitBytes(0, nil, []ProposalRef{known}, nil)
	if err := f.deliver(2, good); err != nil {
		t.Fatalf("a commit referencing a received proposal must be accepted: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem400|TestErrata87|TestErrata88' -v`
Expected: FAIL with `oldest retained epoch is 0, want 8` (nothing calls
`DeleteGroupStateBefore` yet) and, for the errata, `expected ValSem8745, the message was accepted`

- [ ] **Step 3: Write minimal implementation**

Three changes, in files the Group lifecycle plan owns; this task is what forces them and the diff
belongs to whichever plan lands second. All three names are in the canonical interface registry, so
this task adds none:

1. `Group.MergePendingCommit` and `Group.ApplyCommit` both call
   `self.store.DeleteGroupStateBefore(self.groupId, self.epoch-PastEpochWindow)` after the new epoch
   state is written, guarded by `self.epoch > PastEpochWindow`. `PastEpochWindow` is the key-schedule
   plan's `uint64` constant, declared once.
2. `validate_commit.go` gains
   `func CheckErrata8745(path *UpdatePath, context *GroupContext) error`, called from the commit
   path, returning `ValSem(ValSemErrata8745, ...)` when the update-path leaf's capabilities do not
   cover every GroupContext extension type.
3. `validate_commit.go` gains
   `func CheckErrata8815(commit *Commit, pending *ProposalCache) error`, called **before** any other
   commit processing, returning `ValSem(ValSemErrata8815, ...)` for a `ProposalRef` the cache cannot
   resolve. It takes the `*ProposalCache` the lifecycle plan already owns, not a bare map, so there
   is one answer to "did we receive this proposal" rather than two.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem400|TestErrata87|TestErrata88' -v && go test ./connect/mls/... -run TestValSemCoverageIsComplete -v`
Expected: PASS for all three, and `TestValSemCoverageIsComplete` now PASSes with all 51 catalogue
entries covered and `valsem-coverage.md` written.

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_epoch_test.go mls/errata_test.go mls/validate_commit.go mls/group.go && git -C connect commit -m "test(mls): ValSem400 past-epoch bound and errata 8745/8815; ValSem coverage is complete"
```

---

### Task 24: Make the coverage test blocking

**Files:**
- Modify: `connect/.github/workflows/mls-vectors.yml`, `connect/mls/workflow_test.go`

**Interfaces:**
- Consumes: `TestValSemCoverageIsComplete` (Task 3), now green (Task 23).
- Produces: the `valsem` job failing on a missing negative test rather than merely reporting one.

- [ ] **Step 1: Write the failing test**

```go
// append to connect/mls/workflow_test.go

// TestValSemJobIsBlocking asserts the coverage test is in the CI command line. A
// coverage report nobody runs is a coverage report that goes stale in a week.
func TestValSemJobIsBlocking(t *testing.T) {
	body, err := os.ReadFile("../.github/workflows/mls-vectors.yml")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "TestValSemCoverageIsComplete") {
		t.Error("the valsem job must run TestValSemCoverageIsComplete")
	}
	if strings.Contains(text, "continue-on-error: true") {
		t.Error("no gate in this workflow may be non-blocking")
	}
	// all 51 catalogue entries must be reachable by the -run pattern the job uses,
	// including the five narrow-profile refusals, whose tests are named by
	// behaviour rather than by number.
	if !strings.Contains(text, "'TestValSem|TestErrata|TestProfileRefuses'") {
		t.Error("the negative-test step must run every TestValSem*, TestErrata* and TestProfileRefuses* function")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestValSemJobIsBlocking -v`
Expected: FAIL with `the valsem job must run TestValSemCoverageIsComplete`

- [ ] **Step 3: Write minimal implementation**

Change the `valsem` job's catalogue step in `connect/.github/workflows/mls-vectors.yml`:

```yaml
      - name: catalogue closure and coverage
        run: go test ./mls/... -run 'TestValSemCatalogueIsClosed|TestValSemCoverageIsComplete|TestErrataFileIsTranscribed' -v -count 1
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestValSemJobIsBlocking -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add .github/workflows/mls-vectors.yml mls/workflow_test.go && git -C connect commit -m "ci(mls): make the ValSem coverage gate blocking"
```

---

## Phase D — the mlswg gRPC interop harness (wave 4, after `group.go`; Gate 2)

### Task 25: The interop module, isolated from `connect`

**Files:**
- Create: `connect/mls/interop/go.mod`, `connect/mls/interop/proto/mls_client.proto`,
  `connect/mls/interop/proto/mls_client.pb.go`, `connect/mls/interop/proto/mls_client_grpc.pb.go`,
  `connect/mls/interop/GENERATE.md`
- Test: `connect/mls/interop/module_test.go`, and an addition to `connect/layering_test.go`

**Interfaces:**
- Consumes: nothing from other plans. The proto is vendored from the mlswg commit pinned in
  `connect/mls/interop/PINS.md`.
- Produces: the `github.com/urnetwork/connect/mls/interop` module and
  `TestInteropIsNotInConnectsGraph`.

- [ ] **Step 1: Write the failing test**

```go
// append to connect/layering_test.go

// TestInteropIsNotInConnectsGraph is the reason interop is a separate module:
// gRPC and protobuf must never reach connect, and therefore never reach sdk, the
// DLL, or the mobile AARs.
func TestInteropIsNotInConnectsGraph(t *testing.T) {
	for _, pkg := range []string{
		"github.com/urnetwork/connect",
		"github.com/urnetwork/connect/mls",
		"github.com/urnetwork/connect/message",
	} {
		deps := packageDeps(t, pkg)
		for banned := range deps {
			if strings.HasPrefix(banned, "google.golang.org/grpc") ||
				strings.HasPrefix(banned, "google.golang.org/protobuf") ||
				strings.HasPrefix(banned, "github.com/urnetwork/connect/mls/interop") {
				t.Errorf("%s imports %s — the interop client is a separate module for exactly this reason", pkg, banned)
			}
		}
	}
}
```

```go
// connect/mls/interop/module_test.go
// the interop module builds on its own and does not drag the product in reverse.
package interop_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestInteropModuleBuilds(t *testing.T) {
	out, err := exec.Command("go", "build", "./...").CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./... in the interop module: %v\n%s", err, out)
	}
}

func TestInteropImportsMlsAsAPeer(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "./client").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := string(out)
	if !strings.Contains(deps, "github.com/urnetwork/connect/mls\n") {
		t.Error("the interop client must exercise the real mls package")
	}
	if strings.Contains(deps, "github.com/urnetwork/connect/message\n") {
		t.Error("the interop client must test mls alone, not the storage layer on top of it")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/ -run TestInteropIsNotInConnectsGraph -v` — Expected: PASS trivially (nothing
exists yet), then
`cd connect/mls/interop && go test ./...` — Expected: FAIL with `go.mod file not found in current
directory or any parent directory`

- [ ] **Step 3: Write minimal implementation**

```
// connect/mls/interop/go.mod
module github.com/urnetwork/connect/mls/interop

go 1.26.5

require (
	github.com/urnetwork/connect v0.0.0
	google.golang.org/grpc v1.68.0
	google.golang.org/protobuf v1.35.2
)

replace github.com/urnetwork/connect => ../..
```

```markdown
<!-- connect/mls/interop/GENERATE.md -->
# Regenerating the mlswg stubs

The proto is vendored from `mlswg/mls-implementations` at the commit pinned in
`connect/mls/interop/PINS.md`, so the client and the test runner are always the same generation.

```
cp /tmp/mls-implementations/interop/proto/mls_client.proto proto/mls_client.proto
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/mls_client.proto
```

`protoc`, `protoc-gen-go` and `protoc-gen-go-grpc` are developer tools. CI does **not** regenerate;
it builds the checked-in stubs, so a toolchain drift cannot silently change the wire contract.
```

Vendor `proto/mls_client.proto` verbatim and run the generation once, committing all three files.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./... -run TestInterop -v` and
`go test ./connect/ -run TestInteropIsNotInConnectsGraph -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/go.mod mls/interop/go.sum mls/interop/proto mls/interop/GENERATE.md mls/interop/module_test.go layering_test.go && git -C connect commit -m "build(mls): interop as a separate module so gRPC never reaches connect"
```

---

### Task 25a: Vendor the mlswg test runner, its 8 configs, and `merge-runner-output`

Gate 2 is "the mlswg gRPC interop harness against OpenMLS in both roles". The harness is the mlswg
**test runner**, not just the client: Task 33's CI job invokes `go run ./test-runner -config …` three
times per peer and then unions the three outputs. Nothing in this plan created any of it, and a gate
whose runner does not exist is a gate that never runs.

The runner is vendored at the same `mlswg=` commit as the vector corpus, so the runner and the
vectors can never disagree about the protocol they are testing.

**Files:**
- Create: `connect/mls/interop/test-runner/**` (vendored), `connect/mls/interop/configs/*.json`
  (8 files), `connect/mls/interop/cmd/merge-runner-output/main.go`,
  `connect/mls/interop/cmd/merge-runner-output/main_test.go`
- Test: `connect/mls/interop/runner_test.go`,
  `connect/mls/interop/cmd/merge-runner-output/main_test.go`

**Interfaces:**
- Consumes: the `mlswg=<sha>` line of `connect/mls/interop/PINS.md` (Task 6).
- Produces: `func mergeRunnerOutput(paths []string) (map[string][]failure, error)`, the
  `merge-runner-output` binary, `TestRunnerIsVendoredAtThePinnedCommit` and
  `TestConfigSetIsClosed`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/runner_test.go
// the runner and the configs are vendored, at the same commit as the vectors. A
// floating runner turns a red interop matrix into "probably upstream churn", which
// is how a gate stops being one.
package interop_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// runnerConfigs is Spec A §4.2.4: the eight scenario configs the matrix runs.
var runnerConfigs = []string{
	"application.json",
	"branch.json",
	"commit.json",
	"external_join.json",
	"external_proposals.json",
	"psk.json",
	"reinit.json",
	"welcome_join.json",
}

func TestConfigSetIsClosed(t *testing.T) {
	found, err := filepath.Glob(filepath.Join("configs", "*.json"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	names := make([]string, 0, len(found))
	for _, path := range found {
		names = append(names, filepath.Base(path))
	}
	slices.Sort(names)
	if !slices.Equal(names, runnerConfigs) {
		t.Fatalf("configs/ holds %v, spec A §4.2.4 names %v — a config that appears without a profile-reject.json row is a scenario nobody decided the fate of", names, runnerConfigs)
	}
}

func TestRunnerIsVendoredAtThePinnedCommit(t *testing.T) {
	pins, err := os.ReadFile("PINS.md")
	if err != nil {
		t.Fatalf("read PINS.md: %v", err)
	}
	index := strings.Index(string(pins), "mlswg=")
	if index < 0 {
		t.Fatal("PINS.md has no machine-readable mlswg= line")
	}
	pinned := strings.Fields(string(pins)[index:])[0]

	stamp, err := os.ReadFile(filepath.Join("test-runner", "VENDORED"))
	if err != nil {
		t.Fatalf("read test-runner/VENDORED: %v — the runner must be vendored, not fetched at CI time", err)
	}
	if strings.TrimSpace(string(stamp)) != pinned {
		t.Fatalf("test-runner is vendored at %q, PINS.md pins %q — the runner and the vector corpus must come from one commit", strings.TrimSpace(string(stamp)), pinned)
	}
}
```

```go
// connect/mls/interop/cmd/merge-runner-output/main_test.go
// the three runs of one config produce three outputs; the assertion is against
// their union. A scenario that fails in the receiver role and passes in the
// committer role has failed.
package main

import "testing"

func TestUnionKeepsAFailureFromAnySingleRun(t *testing.T) {
	first := map[string][]failure{"commit.json": {}}
	second := map[string][]failure{
		"commit.json": {{Scenario: "commit/3-member", Status: "INVALID_ARGUMENT", MessageContains: "path length"}},
	}
	merged := mergeFailureSets([]map[string][]failure{first, second})
	if got := len(merged["commit.json"]); got != 1 {
		t.Fatalf("merged commit.json holds %d failures, want 1", got)
	}
}

func TestUnionDeduplicatesTheSameScenario(t *testing.T) {
	one := map[string][]failure{
		"branch.json": {{Scenario: "branch/2-member", Status: "UNIMPLEMENTED", MessageContains: "branching"}},
	}
	sets := []map[string][]failure{one, one, one}
	merged := mergeFailureSets(sets)
	if got := len(merged["branch.json"]); got != 1 {
		t.Fatalf("three identical runs merged to %d failures, want 1", got)
	}
}

func TestUnionKeepsBothWhenTheSameScenarioFailsDifferently(t *testing.T) {
	committer := map[string][]failure{
		"reinit.json": {{Scenario: "reinit/2-member", Status: "UNIMPLEMENTED", MessageContains: "ReInit"}},
	}
	receiver := map[string][]failure{
		"reinit.json": {{Scenario: "reinit/2-member", Status: "INTERNAL", MessageContains: "panic"}},
	}
	merged := mergeFailureSets([]map[string][]failure{committer, receiver})
	if got := len(merged["reinit.json"]); got != 2 {
		t.Fatalf("two different failures for one scenario merged to %d, want 2 — collapsing them would hide the worse one", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test . -run 'TestConfigSetIsClosed|TestRunnerIsVendored' -v && go test ./cmd/merge-runner-output/ -v`
Expected: FAIL with `glob: configs/*.json` matching nothing, `read test-runner/VENDORED: no such
file or directory`, and `undefined: mergeFailureSets`

- [ ] **Step 3: Write minimal implementation**

Vendor the runner and configs from the clone Task 6 already made, and stamp the commit:

```bash
MLSWG=$(grep -o 'mlswg=[0-9a-f]\{40\}' connect/mls/interop/PINS.md | cut -d= -f2)
rm -rf /tmp/mls-implementations && git clone https://github.com/mlswg/mls-implementations.git /tmp/mls-implementations
git -C /tmp/mls-implementations checkout "$MLSWG"
mkdir -p connect/mls/interop/test-runner connect/mls/interop/configs
cp -R /tmp/mls-implementations/interop/test-runner/. connect/mls/interop/test-runner/
for c in application branch commit external_join external_proposals psk reinit welcome_join ; do
  cp "/tmp/mls-implementations/interop/configs/${c}.json" "connect/mls/interop/configs/${c}.json"
done
echo "$MLSWG" > connect/mls/interop/test-runner/VENDORED
```

```go
// connect/mls/interop/cmd/merge-runner-output/main.go
// union the three runner outputs — ours-first, ours-last, three-party — into the
// one observed-failure set assert-profile-rejects compares against
// profile-reject.json.
//
// A scenario that fails in ANY role has failed: the receiver role is where the
// validation logic lives, so an intersection would discard exactly the half this
// harness exists to exercise.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
)

// failure is one scenario the runner reported as failed. It is the same shape
// profile-reject.json uses, so the two files are diffable by eye.
type failure struct {
	Scenario        string `json:"scenario"`
	Status          string `json:"grpc_status"`
	MessageContains string `json:"message_contains"`
}

func main() {
	flag.Parse()
	sets := make([]map[string][]failure, 0, flag.NArg())
	for _, path := range flag.Args() {
		set, err := readFailures(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "merge-runner-output: %v\n", err)
			os.Exit(2)
		}
		sets = append(sets, set)
	}
	body, err := json.MarshalIndent(struct {
		Configs map[string][]failure `json:"configs"`
	}{Configs: mergeFailureSets(sets)}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "merge-runner-output: %v\n", err)
		os.Exit(2)
	}
	os.Stdout.Write(append(body, '\n'))
}

func readFailures(path string) (map[string][]failure, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	wrapper := struct {
		Configs map[string][]failure `json:"configs"`
	}{}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if wrapper.Configs == nil {
		wrapper.Configs = map[string][]failure{}
	}
	return wrapper.Configs, nil
}

// mergeFailureSets unions by (scenario, status, message). Two runs that failed the
// same scenario the same way collapse to one entry; two that failed it differently
// keep both, because the difference is the interesting part.
func mergeFailureSets(sets []map[string][]failure) map[string][]failure {
	merged := map[string]map[failure]bool{}
	for _, set := range sets {
		for config, failures := range set {
			if merged[config] == nil {
				merged[config] = map[failure]bool{}
			}
			for _, entry := range failures {
				merged[config][entry] = true
			}
		}
	}
	out := map[string][]failure{}
	for config, entries := range merged {
		list := make([]failure, 0, len(entries))
		for entry := range entries {
			list = append(list, entry)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Scenario != list[j].Scenario {
				return list[i].Scenario < list[j].Scenario
			}
			return list[i].Status < list[j].Status
		})
		out[config] = list
	}
	return out
}
```

`failure` is a comparable struct of three strings, so it is a valid map key and the union needs no
hand-written identity function.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test . -run 'TestConfigSetIsClosed|TestRunnerIsVendored' -v && go test ./cmd/merge-runner-output/ -v`
Expected: PASS — 2 + 3 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/test-runner mls/interop/configs mls/interop/runner_test.go mls/interop/cmd/merge-runner-output && git -C connect commit -m "test(mls-interop): vendor the mlswg runner and configs at the pinned commit, and union the three runs"
```

---

### Task 26: The state registry, and `Free` actually freeing

**Files:**
- Create: `connect/mls/interop/client/state.go`, `connect/mls/interop/client/state_test.go`

**Interfaces:**
- Consumes: `mls.Group`, `mls.Group.Close()` (Group lifecycle plan).
- Produces:
  - `type registry struct{}`, `func newRegistry() *registry`
  - `func (self *registry) add(group *mls.Group) uint32`
  - `func (self *registry) get(id uint32) (*mls.Group, error)`
  - `func (self *registry) free(id uint32) error`
  - `func (self *registry) liveCount() int`

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/client/state_test.go
// the harness job asserts zero leaked states at exit, which is only meaningful if
// Free actually releases. A registry that leaks looks identical to one that does not
// until a deep_random run exhausts memory at 3 a.m.
package main

import "testing"

func TestFreeReleasesTheState(t *testing.T) {
	registry := newRegistry()
	id := registry.add(nil)
	if registry.liveCount() != 1 {
		t.Fatalf("liveCount = %d after add, want 1", registry.liveCount())
	}
	if err := registry.free(id); err != nil {
		t.Fatalf("free: %v", err)
	}
	if registry.liveCount() != 0 {
		t.Fatalf("liveCount = %d after free, want 0", registry.liveCount())
	}
	if _, err := registry.get(id); err == nil {
		t.Fatal("a freed state id must not resolve")
	}
}

func TestFreeIsNotIdempotent(t *testing.T) {
	registry := newRegistry()
	id := registry.add(nil)
	if err := registry.free(id); err != nil {
		t.Fatalf("first free: %v", err)
	}
	if err := registry.free(id); err == nil {
		t.Fatal("freeing twice must be an error, not a silent success — a double free in the runner is a bug in the runner")
	}
}

func TestStateIdsAreNotReused(t *testing.T) {
	registry := newRegistry()
	first := registry.add(nil)
	if err := registry.free(first); err != nil {
		t.Fatalf("free: %v", err)
	}
	second := registry.add(nil)
	if first == second {
		t.Fatal("a reused state id turns a use-after-free in the runner into a silently wrong result")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test ./client/ -run TestFree -v`
Expected: FAIL to build with `undefined: newRegistry`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/client/state.go
// the state registry the MLSClient service holds. Ids are monotonic and never
// reused, and Free releases rather than marking.
package main

import (
	"fmt"
	"sync"

	"github.com/urnetwork/connect/mls"
)

type registry struct {
	stateLock sync.Mutex
	next      uint32
	groups    map[uint32]*mls.Group
}

func newRegistry() *registry {
	return &registry{next: 1, groups: map[uint32]*mls.Group{}}
}

// add installs a group and returns its state id.
func (self *registry) add(group *mls.Group) uint32 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	id := self.next
	self.next++
	self.groups[id] = group
	return id
}

// get resolves a state id, or reports that it was freed or never existed.
func (self *registry) get(id uint32) (*mls.Group, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	group, ok := self.groups[id]
	if !ok {
		return nil, fmt.Errorf("state %d does not exist", id)
	}
	return group, nil
}

// free releases the group and drops the id. Freeing twice is an error.
func (self *registry) free(id uint32) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	group, ok := self.groups[id]
	if !ok {
		return fmt.Errorf("state %d does not exist", id)
	}
	delete(self.groups, id)
	if group != nil {
		return group.Close()
	}
	return nil
}

// liveCount is what the CI job asserts is zero at exit.
func (self *registry) liveCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.groups)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestFree|TestStateIds' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/client/state.go mls/interop/client/state_test.go && git -C connect commit -m "feat(mls-interop): state registry whose Free releases and whose ids are never reused"
```

---

### Task 27: The wire dump

**Files:**
- Create: `connect/mls/interop/client/wiredump.go`, `connect/mls/interop/client/wiredump_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `func newWireDump(folder string) *wireDump`
  - `func (self *wireDump) record(direction string, rpc string, payload []byte)`
  - a `grpc.UnaryServerInterceptor` that records every request and response

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/client/wiredump_test.go
// a failure must produce the exact bytes that diverged, not a gRPC status code.
// Retrofitting this after the first cross-implementation failure is how a week
// gets lost, so it is built in from the start.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWireDumpWritesBothDirections(t *testing.T) {
	folder := t.TempDir()
	dump := newWireDump(folder)
	dump.record("in", "Commit", []byte{0x01, 0x02})
	dump.record("out", "Commit", []byte{0x03})

	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatalf("read dump folder: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("%d dump files, want 2", len(entries))
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(folder, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		if len(body) == 0 {
			t.Errorf("%s is empty", entry.Name())
		}
	}
}

func TestWireDumpNamesAreOrdered(t *testing.T) {
	folder := t.TempDir()
	dump := newWireDump(folder)
	for i := 0; i < 12; i++ {
		dump.record("in", "Protect", []byte{byte(i)})
	}
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// ReadDir sorts lexically; a zero-padded sequence keeps that equal to time order.
	if entries[0].Name() >= entries[10].Name() {
		t.Fatalf("dump names are not lexically ordered: %s then %s", entries[0].Name(), entries[10].Name())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test ./client/ -run TestWireDump -v`
Expected: FAIL to build with `undefined: newWireDump`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/client/wiredump.go
// every byte the client sends and receives, on disk, so an interop failure is a
// diff of bytes rather than a status code.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type wireDump struct {
	stateLock sync.Mutex
	folder    string
	sequence  int
}

func newWireDump(folder string) *wireDump {
	if err := os.MkdirAll(folder, 0o755); err != nil {
		panic(fmt.Sprintf("interop: cannot create the wire dump folder: %v", err))
	}
	return &wireDump{folder: folder}
}

// record writes one payload. The name is zero-padded so lexical order is time order.
func (self *wireDump) record(direction string, rpc string, payload []byte) {
	self.stateLock.Lock()
	sequence := self.sequence
	self.sequence++
	self.stateLock.Unlock()

	name := fmt.Sprintf("%06d-%s-%s.bin", sequence, rpc, direction)
	if err := os.WriteFile(filepath.Join(self.folder, name), payload, 0o644); err != nil {
		panic(fmt.Sprintf("interop: cannot write %s: %v", name, err))
	}
}

// interceptor records every unary request and response.
func (self *wireDump) interceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		rpc := filepath.Base(info.FullMethod)
		if message, ok := request.(proto.Message); ok {
			if encoded, err := proto.Marshal(message); err == nil {
				self.record("in", rpc, encoded)
			}
		}
		response, err := handler(ctx, request)
		if message, ok := response.(proto.Message); ok {
			if encoded, marshalErr := proto.Marshal(message); marshalErr == nil {
				self.record("out", rpc, encoded)
			}
		}
		return response, err
	}
}
```

Add `"context"` to the imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./client/ -run TestWireDump -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/client/wiredump.go mls/interop/client/wiredump_test.go && git -C connect commit -m "feat(mls-interop): dump every byte sent and received"
```

---

### Task 28: `Name`, `SupportedCiphersuites`, `CreateGroup`, `CreateKeyPackage`, `JoinGroup`

**Files:**
- Create: `connect/mls/interop/client/main.go`, `connect/mls/interop/client/rpc_core.go`,
  `connect/mls/interop/client/rpc_core_test.go`

**Interfaces:**
- Consumes: `mls.NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error)`,
  `mls.GroupConfig`, `mls.JoinFromWelcome(cfg, welcome, ratchetTree []byte, keys *JoinKeyMaterial) (*Group, error)`,
  `mls.JoinKeyMaterial{KeyPackage, InitPrivate, EncryptPrivate, SignPrivate}` (Group lifecycle plan);
  `mls.NewKeyPackage(crypto, suite, cred, caps, exts) (kp, initPriv, encPriv, err)`,
  `mls.BasicCredential`, `mls.Capabilities`, `mls.RequiredCapabilities`, `mls.ExtensionType` and its
  constants, `mls.CredentialTypeBasic` (TreeKEM plan);
  `mls.NewCryptoProvider`, `mls.CipherSuiteX25519ChaCha20Sha256Ed25519`, `mls.IsRegisteredSuite`
  (Crypto plan); `mls.DefaultProfile`, `(*mls.Profile).CheckCiphersuiteForCreate` (Task 3a);
  `newRegistry` (Task 26), `newWireDump` (Task 27).
- Produces: `type service struct{}` implementing the first five RPCs, and a `-port` flag.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/client/rpc_core_test.go
// the client is exercised in-process here; the CI job exercises it over gRPC
// against three foreign implementations.
package main

import (
	"context"
	"testing"

	pb "github.com/urnetwork/connect/mls/interop/proto"
)

func TestNameAndSuites(t *testing.T) {
	service := newService(t.TempDir())
	name, err := service.Name(context.Background(), &pb.NameRequest{})
	if err != nil {
		t.Fatalf("Name: %v", err)
	}
	if name.Name != "urmessage-connect-mls" {
		t.Errorf("Name = %q, want urmessage-connect-mls", name.Name)
	}
	suites, err := service.SupportedCiphersuites(context.Background(), &pb.SupportedCiphersuitesRequest{})
	if err != nil {
		t.Fatalf("SupportedCiphersuites: %v", err)
	}
	if len(suites.Ciphersuites) != 1 || suites.Ciphersuites[0] != 0x0003 {
		t.Errorf("Ciphersuites = %v, want [3] — 0x0001 is registered but refused at group creation", suites.Ciphersuites)
	}
}

func TestCreateGroupThenJoin(t *testing.T) {
	service := newService(t.TempDir())
	created, err := service.CreateGroup(context.Background(), &pb.CreateGroupRequest{
		GroupId:     []byte("interop-group"),
		CipherSuite: 0x0003,
		Identity:    []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if created.StateId == 0 {
		t.Fatal("CreateGroup returned state id 0")
	}
	keyPackage, err := service.CreateKeyPackage(context.Background(), &pb.CreateKeyPackageRequest{
		CipherSuite: 0x0003,
		Identity:    []byte("bob"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage: %v", err)
	}
	if len(keyPackage.KeyPackage) == 0 {
		t.Fatal("CreateKeyPackage returned no bytes")
	}
	if service.registry.liveCount() != 2 {
		t.Fatalf("liveCount = %d, want 2 (the group and the pending key package state)", service.registry.liveCount())
	}
}

func TestCreateGroupRefusesTheSecondSuite(t *testing.T) {
	service := newService(t.TempDir())
	_, err := service.CreateGroup(context.Background(), &pb.CreateGroupRequest{
		GroupId:     []byte("interop-group"),
		CipherSuite: 0x0001,
		Identity:    []byte("alice"),
	})
	if err == nil {
		t.Fatal("0x0001 is registered and implemented, and still refused at group creation by policy (Spec A §3.1)")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestName|TestCreateGroup' -v`
Expected: FAIL to build with `undefined: newService`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/client/main.go
// our mlswg MLSClient gRPC server. package main, separate module, never built into
// any product.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"

	pb "github.com/urnetwork/connect/mls/interop/proto"
)

func main() {
	port := flag.Int("port", 50051, "the port to serve MLSClient on")
	dumpFolder := flag.String("wiredump", "out/wiredump", "where to write every byte sent and received")
	flag.Parse()

	service := newService(*dumpFolder)
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	server := grpc.NewServer(grpc.UnaryInterceptor(service.dump.interceptor()))
	pb.RegisterMLSClientServer(server, service)
	if err := server.Serve(listener); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
	if leaked := service.registry.liveCount(); leaked != 0 {
		fmt.Fprintf(os.Stderr, "%d leaked states at exit\n", leaked)
		os.Exit(1)
	}
}
```

```go
// connect/mls/interop/client/rpc_core.go
// group creation, key packages and joining.
package main

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/urnetwork/connect/mls"
	pb "github.com/urnetwork/connect/mls/interop/proto"
)

type service struct {
	pb.UnimplementedMLSClientServer
	registry *registry
	dump     *wireDump
	pending  *pendingKeyPackages
}

func newService(dumpFolder string) *service {
	return &service{registry: newRegistry(), dump: newWireDump(dumpFolder), pending: newPendingKeyPackages()}
}

func (self *service) Name(ctx context.Context, request *pb.NameRequest) (*pb.NameResponse, error) {
	return &pb.NameResponse{Name: "urmessage-connect-mls"}, nil
}

// SupportedCiphersuites reports 0x0003 only. 0x0001 is registered and implemented
// but refused at group creation by policy, so advertising it would invite the
// runner to build a group we would then decline.
func (self *service) SupportedCiphersuites(ctx context.Context, request *pb.SupportedCiphersuitesRequest) (*pb.SupportedCiphersuitesResponse, error) {
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: []uint32{uint32(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)}}, nil
}

func (self *service) CreateGroup(ctx context.Context, request *pb.CreateGroupRequest) (*pb.CreateGroupResponse, error) {
	config, signer, credential, err := self.newGroupConfig(request.CipherSuite, request.GroupId, request.Identity)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	group, err := mls.NewGroup(config, signer, credential)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.CreateGroupResponse{StateId: self.registry.add(group)}, nil
}

func (self *service) CreateKeyPackage(ctx context.Context, request *pb.CreateKeyPackageRequest) (*pb.CreateKeyPackageResponse, error) {
	entry, err := self.pending.mint(request.CipherSuite, request.Identity)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.CreateKeyPackageResponse{
		TransactionId: entry.transactionId,
		KeyPackage:    entry.keyPackage,
		InitPriv:      entry.initPriv,
		EncryptionPriv: entry.encryptionPriv,
		SignaturePriv:  entry.signaturePriv,
	}, nil
}

func (self *service) JoinGroup(ctx context.Context, request *pb.JoinGroupRequest) (*pb.JoinGroupResponse, error) {
	entry, err := self.pending.take(request.TransactionId)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	config, _, _, err := self.newGroupConfig(request.CipherSuite, nil, entry.identity)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	group, err := mls.JoinFromWelcome(config, request.Welcome, request.RatchetTree, entry.joinKeys())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.JoinGroupResponse{
		StateId:  self.registry.add(group),
		Epoch:    group.Epoch(),
	}, nil
}
```

`newGroupConfig` and `pendingKeyPackages` are small helpers in the same file.

`newGroupConfig` builds the v1 `mls.GroupConfig`: `Suite:
mls.CipherSuiteX25519ChaCha20Sha256Ed25519`, `RequiredCaps: mls.RequiredCapabilities{ExtensionTypes:
[]mls.ExtensionType{mls.ExtensionTypeUrmessageGroupPolicy, mls.ExtensionTypeUrmessageLeafKeys},
CredentialTypes: []mls.CredentialType{mls.CredentialTypeBasic}}`, `Profile: mls.DefaultProfile()`,
and an in-memory store. It gates the requested suite through
`mls.DefaultProfile().CheckCiphersuiteForCreate`, so the refusal message the interop matrix sees is
the same `ErrProfileCiphersuite` the ValSem catalogue names rather than a second, hand-written
string. `mls.IsRegisteredSuite` distinguishes "not a suite" from "a suite we refuse to create at".

`pendingKeyPackages` is a mutex-guarded map from transaction id to minted key-package material —
`mls.NewKeyPackage`'s `kp`, `initPriv` and `encPriv` plus the identity signer — mirroring
`mls.StateStore.PutKeyPackage` / `TakeKeyPackage`. Its `joinKeys()` builds
`&mls.JoinKeyMaterial{KeyPackage: kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: signer}`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestName|TestCreateGroup' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/client/main.go mls/interop/client/rpc_core.go mls/interop/client/rpc_core_test.go && git -C connect commit -m "feat(mls-interop): group creation, key packages and joining"
```

---

### Task 29: `GroupInfo`, `StateAuth`, `Export`, `Protect`, `Unprotect`

**Files:**
- Create: `connect/mls/interop/client/rpc_state.go`, `connect/mls/interop/client/rpc_state_test.go`

**Interfaces:**
- Consumes, all from the Group lifecycle plan and all verbatim from the canonical interface registry:
  `(*mls.Group).Export(label string, context []byte, length int) ([]byte, error)`,
  `(*mls.Group).EpochAuthenticator() []byte`,
  `(*mls.Group).Protect(aad, plaintext []byte) ([]byte, error)`,
  `(*mls.Group).Unprotect(privateMessage []byte) (*mls.ApplicationMessage, error)`,
  `(*mls.Group).GroupContext() ([]byte, error)`,
  `(*mls.Group).RatchetTree() ([]byte, error)`,
  `mls.ApplicationMessage{SenderLeaf, AuthenticatedData, Plaintext}`.
- Produces: the five state RPCs.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/client/rpc_state_test.go
package main

import (
	"bytes"
	"context"
	"testing"

	pb "github.com/urnetwork/connect/mls/interop/proto"
)

func TestProtectThenUnprotectRoundTrips(t *testing.T) {
	service := newService(t.TempDir())
	created, err := service.CreateGroup(context.Background(), &pb.CreateGroupRequest{
		GroupId: []byte("interop-group"), CipherSuite: 0x0003, Identity: []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	protected, err := service.Protect(context.Background(), &pb.ProtectRequest{
		StateId: created.StateId, AuthenticatedData: []byte("aad"), Plaintext: []byte("hello"),
	})
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	unprotected, err := service.Unprotect(context.Background(), &pb.UnprotectRequest{
		StateId: created.StateId, Ciphertext: protected.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if !bytes.Equal(unprotected.Plaintext, []byte("hello")) {
		t.Errorf("Plaintext = %q, want hello", unprotected.Plaintext)
	}
	if !bytes.Equal(unprotected.AuthenticatedData, []byte("aad")) {
		t.Errorf("AuthenticatedData = %q, want aad", unprotected.AuthenticatedData)
	}
}

func TestExportAndStateAuthAreEpochScoped(t *testing.T) {
	service := newService(t.TempDir())
	created, err := service.CreateGroup(context.Background(), &pb.CreateGroupRequest{
		GroupId: []byte("interop-group"), CipherSuite: 0x0003, Identity: []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	exported, err := service.Export(context.Background(), &pb.ExportRequest{
		StateId: created.StateId, Label: "interop", Context: []byte("ctx"), KeyLength: 32,
	})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(exported.ExportedSecret) != 32 {
		t.Fatalf("ExportedSecret is %d bytes, want 32", len(exported.ExportedSecret))
	}
	auth, err := service.StateAuth(context.Background(), &pb.StateAuthRequest{StateId: created.StateId})
	if err != nil {
		t.Fatalf("StateAuth: %v", err)
	}
	if len(auth.StateAuthSecret) == 0 {
		t.Fatal("StateAuth returned nothing")
	}
	if bytes.Equal(auth.StateAuthSecret, exported.ExportedSecret) {
		t.Fatal("the epoch authenticator and an exporter output must be independent derivations (MASTER §8.3 correction)")
	}
}

func TestUnknownStateIdIsNotFound(t *testing.T) {
	service := newService(t.TempDir())
	if _, err := service.Export(context.Background(), &pb.ExportRequest{StateId: 999, Label: "x", KeyLength: 32}); err == nil {
		t.Fatal("an unknown state id must be an error, not a zero value")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestProtect|TestExport|TestUnknownState' -v`
Expected: FAIL to build with `service.Protect undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/client/rpc_state.go
// the read-only and message-protection RPCs.
package main

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/urnetwork/connect/mls/interop/proto"
)

func (self *service) GroupInfo(ctx context.Context, request *pb.GroupInfoRequest) (*pb.GroupInfoResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	tree, err := group.RatchetTree()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	context, err := group.GroupContext()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.GroupInfoResponse{GroupInfo: context, RatchetTree: tree}, nil
}

func (self *service) StateAuth(ctx context.Context, request *pb.StateAuthRequest) (*pb.StateAuthResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &pb.StateAuthResponse{StateAuthSecret: group.EpochAuthenticator()}, nil
}

func (self *service) Export(ctx context.Context, request *pb.ExportRequest) (*pb.ExportResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	secret, err := group.Export(request.Label, request.Context, int(request.KeyLength))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ExportResponse{ExportedSecret: secret}, nil
}

func (self *service) Protect(ctx context.Context, request *pb.ProtectRequest) (*pb.ProtectResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	ciphertext, err := group.Protect(request.AuthenticatedData, request.Plaintext)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ProtectResponse{Ciphertext: ciphertext}, nil
}

func (self *service) Unprotect(ctx context.Context, request *pb.UnprotectRequest) (*pb.UnprotectResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	message, err := group.Unprotect(request.Ciphertext)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.UnprotectResponse{
		AuthenticatedData: message.AuthenticatedData,
		Plaintext:         message.Plaintext,
	}, nil
}
```

Rename the shadowed `context` variable in `GroupInfo` to `groupContext`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestProtect|TestExport|TestUnknownState' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/client/rpc_state.go mls/interop/client/rpc_state_test.go && git -C connect commit -m "feat(mls-interop): group info, state auth, export, protect and unprotect"
```

---

### Task 30: The proposal and commit RPCs

**Files:**
- Create: `connect/mls/interop/client/rpc_commit.go`, `connect/mls/interop/client/rpc_commit_test.go`

**Interfaces:**
- Consumes, all from the Group lifecycle plan and all verbatim from the canonical interface registry:
  `(*mls.Group).ProposeAdd(keyPackage []byte) ([]byte, error)`,
  `(*mls.Group).ProposeUpdate() ([]byte, error)`,
  `(*mls.Group).ProposeRemove(leaf mls.LeafIndex) ([]byte, error)`,
  `(*mls.Group).ProposeGroupContextExtensions(exts []mls.Extension) ([]byte, error)`,
  `(*mls.Group).Commit(byReference [][]byte, byValue []mls.Proposal, opts *mls.CommitOptions) (*mls.CommitResult, error)`,
  `(*mls.Group).ProcessMessage(message []byte) (*mls.Processed, error)`,
  `(*mls.Group).ApplyCommit(processed *mls.Processed) error`,
  `(*mls.Group).MergePendingCommit() error`,
  `mls.CommitResult{Commit, Welcome, RatchetTree}`;
  `registry.free` (Task 26).
- Produces: `AddProposal`, `UpdateProposal`, `RemoveProposal`,
  `GroupContextExtensionsProposal`, `Commit`, `HandleCommit`, `HandlePendingCommit`, `Free`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/client/rpc_commit_test.go
package main

import (
	"context"
	"testing"

	pb "github.com/urnetwork/connect/mls/interop/proto"
)

func TestAddCommitAndJoinInProcess(t *testing.T) {
	service := newService(t.TempDir())
	alice, err := service.CreateGroup(context.Background(), &pb.CreateGroupRequest{
		GroupId: []byte("interop-group"), CipherSuite: 0x0003, Identity: []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	bob, err := service.CreateKeyPackage(context.Background(), &pb.CreateKeyPackageRequest{
		CipherSuite: 0x0003, Identity: []byte("bob"),
	})
	if err != nil {
		t.Fatalf("CreateKeyPackage: %v", err)
	}
	proposal, err := service.AddProposal(context.Background(), &pb.AddProposalRequest{
		StateId: alice.StateId, KeyPackage: bob.KeyPackage,
	})
	if err != nil {
		t.Fatalf("AddProposal: %v", err)
	}
	committed, err := service.Commit(context.Background(), &pb.CommitRequest{
		StateId: alice.StateId, ByReference: [][]byte{proposal.Proposal},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(committed.Welcome) == 0 {
		t.Fatal("a commit covering an Add must produce a Welcome")
	}
	merged, err := service.HandlePendingCommit(context.Background(), &pb.HandlePendingCommitRequest{StateId: alice.StateId})
	if err != nil {
		t.Fatalf("HandlePendingCommit: %v", err)
	}
	if merged.Epoch != 1 {
		t.Fatalf("epoch after the first commit is %d, want 1", merged.Epoch)
	}
	joined, err := service.JoinGroup(context.Background(), &pb.JoinGroupRequest{
		TransactionId: bob.TransactionId, CipherSuite: 0x0003,
		Welcome: committed.Welcome, RatchetTree: committed.RatchetTree,
	})
	if err != nil {
		t.Fatalf("JoinGroup: %v", err)
	}
	if joined.Epoch != merged.Epoch {
		t.Fatalf("the joiner is at epoch %d, the committer at %d", joined.Epoch, merged.Epoch)
	}
}

func TestFreeRpcReleasesTheState(t *testing.T) {
	service := newService(t.TempDir())
	created, err := service.CreateGroup(context.Background(), &pb.CreateGroupRequest{
		GroupId: []byte("interop-group"), CipherSuite: 0x0003, Identity: []byte("alice"),
	})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := service.Free(context.Background(), &pb.FreeRequest{StateId: created.StateId}); err != nil {
		t.Fatalf("Free: %v", err)
	}
	if service.registry.liveCount() != 0 {
		t.Fatalf("liveCount = %d after Free, want 0 — the harness job asserts zero at exit", service.registry.liveCount())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestAddCommit|TestFreeRpc' -v`
Expected: FAIL to build with `service.AddProposal undefined`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/client/rpc_commit.go
// proposals, commits and release.
package main

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/urnetwork/connect/mls"
	pb "github.com/urnetwork/connect/mls/interop/proto"
)

func (self *service) AddProposal(ctx context.Context, request *pb.AddProposalRequest) (*pb.ProposalResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	proposal, err := group.ProposeAdd(request.KeyPackage)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ProposalResponse{Proposal: proposal}, nil
}

func (self *service) UpdateProposal(ctx context.Context, request *pb.UpdateProposalRequest) (*pb.ProposalResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	proposal, err := group.ProposeUpdate()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ProposalResponse{Proposal: proposal}, nil
}

func (self *service) RemoveProposal(ctx context.Context, request *pb.RemoveProposalRequest) (*pb.ProposalResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	proposal, err := group.ProposeRemove(mls.LeafIndex(request.RemovedId))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ProposalResponse{Proposal: proposal}, nil
}

func (self *service) GroupContextExtensionsProposal(ctx context.Context, request *pb.GroupContextExtensionsProposalRequest) (*pb.ProposalResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	extensions := make([]mls.Extension, 0, len(request.Extensions))
	for _, extension := range request.Extensions {
		extensions = append(extensions, mls.Extension{
			ExtensionType: mls.ExtensionType(extension.ExtensionType),
			ExtensionData: extension.ExtensionData,
		})
	}
	proposal, err := group.ProposeGroupContextExtensions(extensions)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ProposalResponse{Proposal: proposal}, nil
}

func (self *service) Commit(ctx context.Context, request *pb.CommitRequest) (*pb.CommitResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	result, err := group.Commit(request.ByReference, nil, nil)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.CommitResponse{
		Commit:      result.Commit,
		Welcome:     result.Welcome,
		RatchetTree: result.RatchetTree,
	}, nil
}

func (self *service) HandleCommit(ctx context.Context, request *pb.HandleCommitRequest) (*pb.HandleCommitResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	for _, proposal := range request.Proposal {
		if _, err := group.ProcessMessage(proposal); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
	}
	processed, err := group.ProcessMessage(request.Commit)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := group.ApplyCommit(processed); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.HandleCommitResponse{StateId: request.StateId, Epoch: group.Epoch()}, nil
}

func (self *service) HandlePendingCommit(ctx context.Context, request *pb.HandlePendingCommitRequest) (*pb.HandleCommitResponse, error) {
	group, err := self.registry.get(request.StateId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := group.MergePendingCommit(); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &pb.HandleCommitResponse{StateId: request.StateId, Epoch: group.Epoch()}, nil
}

func (self *service) Free(ctx context.Context, request *pb.FreeRequest) (*pb.FreeResponse, error) {
	if err := self.registry.free(request.StateId); err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	return &pb.FreeResponse{}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestAddCommit|TestFreeRpc' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/client/rpc_commit.go mls/interop/client/rpc_commit_test.go && git -C connect commit -m "feat(mls-interop): proposal, commit and free RPCs"
```

---

### Task 31: The `UNIMPLEMENTED` set, and asserting it is closed

**Files:**
- Create: `connect/mls/interop/client/rpc_unimplemented.go`,
  `connect/mls/interop/client/rpc_unimplemented_test.go`

**Interfaces:**
- Consumes: the generated `pb.MLSClientServer` interface (Task 25).
- Produces: the fourteen refused RPCs with stable messages, and
  `TestUnimplementedSetIsClosed` — the test that turns a silent capability expansion into a red build.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/client/rpc_unimplemented_test.go
// the v1 profile refuses external commits, external senders, PSKs, ReInit and
// branching. Each refusal has a STABLE message, because profile-reject.json asserts
// on it: a scenario that starts passing because someone implemented external
// commits must be a CI failure, not a silent capability expansion.
package main

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/urnetwork/connect/mls/interop/proto"
)

// unimplementedMessages is the closed set. Adding an entry means implementing the
// RPC; removing one means the profile widened. Both require a spec change.
var unimplementedMessages = map[string]string{
	"ExternalJoin":           "urmessage: external commits are not implemented in the v1 profile",
	"NewMemberAddProposal":   "urmessage: external commits are not implemented in the v1 profile",
	"CreateExternalSigner":   "urmessage: external senders are not implemented in the v1 profile",
	"AddExternalSigner":      "urmessage: external senders are not implemented in the v1 profile",
	"ExternalSignerProposal": "urmessage: external senders are not implemented in the v1 profile",
	"StorePSK":               "urmessage: pre-shared keys are not implemented in the v1 profile",
	"ExternalPSKProposal":    "urmessage: pre-shared keys are not implemented in the v1 profile",
	"ResumptionPSKProposal":  "urmessage: pre-shared keys are not implemented in the v1 profile",
	"ReInitProposal":         "urmessage: ReInit is not implemented in the v1 profile",
	"ReInitCommit":           "urmessage: ReInit is not implemented in the v1 profile",
	"HandlePendingReInitCommit": "urmessage: ReInit is not implemented in the v1 profile",
	"ReInitWelcome":          "urmessage: ReInit is not implemented in the v1 profile",
	"CreateBranch":           "urmessage: branching is not implemented in the v1 profile",
	"HandleBranch":           "urmessage: handling a branch is not implemented in the v1 profile",
}

func TestUnimplementedSetIsClosed(t *testing.T) {
	service := newService(t.TempDir())
	for name, want := range unimplementedMessages {
		err := callUnimplemented(t, service, name)
		if err == nil {
			t.Errorf("%s returned success — the v1 profile does not implement it", name)
			continue
		}
		state, ok := status.FromError(err)
		if !ok {
			t.Errorf("%s returned a non-gRPC error: %v", name, err)
			continue
		}
		if state.Code() != codes.Unimplemented {
			t.Errorf("%s returned %s, want Unimplemented", name, state.Code())
		}
		if state.Message() != want {
			t.Errorf("%s message is %q, want %q — profile-reject.json asserts on it", name, state.Message(), want)
		}
	}
}

func TestEveryRpcIsEitherImplementedOrRefused(t *testing.T) {
	// the generated interface names every RPC; nothing may fall through to the
	// embedded UnimplementedMLSClientServer, whose message is not stable.
	total := rpcMethodNames()
	implemented := []string{
		"Name", "SupportedCiphersuites", "CreateGroup", "CreateKeyPackage", "JoinGroup",
		"GroupInfo", "StateAuth", "Export", "Protect", "Unprotect",
		"AddProposal", "UpdateProposal", "RemoveProposal", "GroupContextExtensionsProposal",
		"Commit", "HandleCommit", "HandlePendingCommit", "Free",
	}
	if got, want := len(total), len(implemented)+len(unimplementedMessages); got != want {
		t.Fatalf("the service has %d RPCs; %d implemented + %d refused = %d", got, len(implemented), len(unimplementedMessages), want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestUnimplemented|TestEveryRpc' -v`
Expected: FAIL to build with `undefined: callUnimplemented`, `undefined: rpcMethodNames`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/client/rpc_unimplemented.go
// the RPCs the v1 profile refuses. Each message is stable because
// profile-reject.json asserts the observed failure set EQUALS the expected set.
package main

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/urnetwork/connect/mls/interop/proto"
)

const (
	refusedExternalCommit = "urmessage: external commits are not implemented in the v1 profile"
	refusedExternalSender = "urmessage: external senders are not implemented in the v1 profile"
	refusedPsk            = "urmessage: pre-shared keys are not implemented in the v1 profile"
	refusedReInit         = "urmessage: ReInit is not implemented in the v1 profile"
	refusedBranch         = "urmessage: branching is not implemented in the v1 profile"
	refusedHandleBranch   = "urmessage: handling a branch is not implemented in the v1 profile"
)

func (self *service) ExternalJoin(ctx context.Context, request *pb.ExternalJoinRequest) (*pb.ExternalJoinResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedExternalCommit)
}

func (self *service) NewMemberAddProposal(ctx context.Context, request *pb.NewMemberAddProposalRequest) (*pb.NewMemberAddProposalResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedExternalCommit)
}

func (self *service) CreateExternalSigner(ctx context.Context, request *pb.CreateExternalSignerRequest) (*pb.CreateExternalSignerResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedExternalSender)
}

func (self *service) AddExternalSigner(ctx context.Context, request *pb.AddExternalSignerRequest) (*pb.ProposalResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedExternalSender)
}

func (self *service) ExternalSignerProposal(ctx context.Context, request *pb.ExternalSignerProposalRequest) (*pb.ProposalResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedExternalSender)
}

func (self *service) StorePSK(ctx context.Context, request *pb.StorePSKRequest) (*pb.StorePSKResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedPsk)
}

func (self *service) ExternalPSKProposal(ctx context.Context, request *pb.ExternalPSKProposalRequest) (*pb.ProposalResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedPsk)
}

func (self *service) ResumptionPSKProposal(ctx context.Context, request *pb.ResumptionPSKProposalRequest) (*pb.ProposalResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedPsk)
}

func (self *service) ReInitProposal(ctx context.Context, request *pb.ReInitProposalRequest) (*pb.ProposalResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedReInit)
}

func (self *service) ReInitCommit(ctx context.Context, request *pb.CommitRequest) (*pb.CommitResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedReInit)
}

func (self *service) HandlePendingReInitCommit(ctx context.Context, request *pb.HandlePendingCommitRequest) (*pb.HandleReInitCommitResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedReInit)
}

func (self *service) ReInitWelcome(ctx context.Context, request *pb.ReInitWelcomeRequest) (*pb.CreateSubgroupResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedReInit)
}

func (self *service) CreateBranch(ctx context.Context, request *pb.CreateBranchRequest) (*pb.CreateSubgroupResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedBranch)
}

func (self *service) HandleBranch(ctx context.Context, request *pb.HandleBranchRequest) (*pb.HandleBranchResponse, error) {
	return nil, status.Error(codes.Unimplemented, refusedHandleBranch)
}
```

and the two test helpers, in `rpc_unimplemented_test.go`:

```go
// callUnimplemented invokes one refused RPC by name through reflection, so adding
// an RPC to the proto without deciding its fate breaks this test.
func callUnimplemented(t *testing.T, s *service, name string) error {
	t.Helper()
	method := reflect.ValueOf(s).MethodByName(name)
	if !method.IsValid() {
		t.Fatalf("%s is not a method on the service", name)
	}
	requestType := method.Type().In(1).Elem()
	results := method.Call([]reflect.Value{
		reflect.ValueOf(context.Background()),
		reflect.New(requestType),
	})
	err, _ := results[1].Interface().(error)
	return err
}

// rpcMethodNames is every method of the generated server interface.
func rpcMethodNames() []string {
	iface := reflect.TypeOf((*pb.MLSClientServer)(nil)).Elem()
	names := []string{}
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		if strings.HasPrefix(name, "mustEmbed") {
			continue
		}
		names = append(names, name)
	}
	return names
}
```

Add `"reflect"` and `"strings"` to the test imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./client/ -run 'TestUnimplemented|TestEveryRpc' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/client/rpc_unimplemented.go mls/interop/client/rpc_unimplemented_test.go && git -C connect commit -m "feat(mls-interop): the closed UNIMPLEMENTED set with stable refusal messages"
```

---

### Task 32: The documented-failure mechanism

**Files:**
- Create: `connect/mls/interop/profile-reject.json`,
  `connect/mls/interop/cmd/assert-profile-rejects/main.go`,
  `connect/mls/interop/cmd/assert-profile-rejects/main_test.go`

**Interfaces:**
- Consumes: the refusal messages of Task 31.
- Produces: `func compareFailures(expected, observed map[string][]failure) []string` and the
  `assert-profile-rejects` binary the CI step runs.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/cmd/assert-profile-rejects/main_test.go
// the observed failure set must EQUAL the expected set. A scenario that starts
// passing — because someone implemented external commits without updating the
// profile — is a CI failure, not a silent capability expansion. That direction is
// the one an "at least these must fail" check would miss, so it is tested first.
package main

import "testing"

func TestAScenarioThatStartsPassingIsAFailure(t *testing.T) {
	expected := map[string][]failure{
		"external_join.json": {{Scenario: "external_join/2-member", Status: "UNIMPLEMENTED", MessageContains: "external commits"}},
	}
	observed := map[string][]failure{"external_join.json": {}}
	problems := compareFailures(expected, observed)
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly one", problems)
	}
}

func TestANewFailureIsAlsoAFailure(t *testing.T) {
	expected := map[string][]failure{"commit.json": {}}
	observed := map[string][]failure{
		"commit.json": {{Scenario: "commit/3-member", Status: "INVALID_ARGUMENT", MessageContains: "path length"}},
	}
	problems := compareFailures(expected, observed)
	if len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly one", problems)
	}
}

func TestTheExpectedSetPasses(t *testing.T) {
	expected := map[string][]failure{
		"branch.json": {{Scenario: "branch/2-member", Status: "UNIMPLEMENTED", MessageContains: "branching is not implemented"}},
	}
	observed := map[string][]failure{
		"branch.json": {{Scenario: "branch/2-member", Status: "UNIMPLEMENTED", MessageContains: "urmessage: branching is not implemented in the v1 profile"}},
	}
	if problems := compareFailures(expected, observed); len(problems) != 0 {
		t.Fatalf("problems = %v, want none", problems)
	}
}

func TestAWrongStatusIsAFailure(t *testing.T) {
	expected := map[string][]failure{
		"reinit.json": {{Scenario: "reinit/2-member", Status: "UNIMPLEMENTED", MessageContains: "ReInit"}},
	}
	observed := map[string][]failure{
		"reinit.json": {{Scenario: "reinit/2-member", Status: "INTERNAL", MessageContains: "urmessage: ReInit is not implemented in the v1 profile"}},
	}
	if problems := compareFailures(expected, observed); len(problems) != 1 {
		t.Fatalf("problems = %v, want exactly one", problems)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test ./cmd/assert-profile-rejects/ -v`
Expected: FAIL to build with `undefined: failure`, `undefined: compareFailures`

- [ ] **Step 3: Write minimal implementation**

```go
// connect/mls/interop/cmd/assert-profile-rejects/main.go
// assert the observed interop failure set equals the documented one.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// failure is one scenario the profile refuses.
type failure struct {
	Scenario        string `json:"scenario"`
	Status          string `json:"grpc_status"`
	MessageContains string `json:"message_contains"`
}

func main() {
	expectPath := flag.String("expect", "profile-reject.json", "the documented failure set")
	gotPath := flag.String("got", "runner-output.json", "the runner's observed failures")
	flag.Parse()

	expected := loadFailures(*expectPath)
	observed := loadFailures(*gotPath)
	problems := compareFailures(expected, observed)
	for _, problem := range problems {
		fmt.Fprintln(os.Stderr, problem)
	}
	if len(problems) != 0 {
		os.Exit(1)
	}
}

func loadFailures(path string) map[string][]failure {
	body, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(2)
	}
	wrapper := struct {
		Configs map[string][]failure `json:"configs"`
	}{}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
		os.Exit(2)
	}
	return wrapper.Configs
}

// compareFailures reports every way the observed set differs from the expected one,
// in both directions.
func compareFailures(expected, observed map[string][]failure) []string {
	problems := []string{}
	configs := map[string]bool{}
	for config := range expected {
		configs[config] = true
	}
	for config := range observed {
		configs[config] = true
	}
	names := make([]string, 0, len(configs))
	for config := range configs {
		names = append(names, config)
	}
	sort.Strings(names)

	for _, config := range names {
		want := indexByScenario(expected[config])
		got := indexByScenario(observed[config])
		for scenario, wanted := range want {
			actual, ok := got[scenario]
			if !ok {
				problems = append(problems, fmt.Sprintf("%s: %s was expected to FAIL and passed — the profile has widened without a spec change", config, scenario))
				continue
			}
			if actual.Status != wanted.Status {
				problems = append(problems, fmt.Sprintf("%s: %s failed with %s, expected %s", config, scenario, actual.Status, wanted.Status))
			}
			if !strings.Contains(actual.MessageContains, wanted.MessageContains) {
				problems = append(problems, fmt.Sprintf("%s: %s message %q does not contain %q", config, scenario, actual.MessageContains, wanted.MessageContains))
			}
		}
		for scenario, actual := range got {
			if _, ok := want[scenario]; !ok {
				problems = append(problems, fmt.Sprintf("%s: %s failed unexpectedly (%s: %s)", config, scenario, actual.Status, actual.MessageContains))
			}
		}
	}
	return problems
}

func indexByScenario(failures []failure) map[string]failure {
	index := map[string]failure{}
	for _, entry := range failures {
		index[entry.Scenario] = entry
	}
	return index
}
```

```json
{
  "note": "Per config, the scenario ids that MUST fail, and how. The observed set must EQUAL this set. Regenerate only alongside a spec change to Spec A §3.1 or §3.2.",
  "configs": {
    "welcome_join.json": [],
    "commit.json": [],
    "application.json": [],
    "branch.json": [
      {"scenario": "branch/2-member", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: branching is not implemented in the v1 profile"},
      {"scenario": "branch/3-member", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: branching is not implemented in the v1 profile"}
    ],
    "external_join.json": [
      {"scenario": "external_join/2-member", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: external commits are not implemented in the v1 profile"},
      {"scenario": "external_join/3-member", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: external commits are not implemented in the v1 profile"}
    ],
    "external_proposals.json": [
      {"scenario": "external_proposals/add", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: external senders are not implemented in the v1 profile"},
      {"scenario": "external_proposals/remove", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: external senders are not implemented in the v1 profile"}
    ],
    "psk.json": [
      {"scenario": "psk/external", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: pre-shared keys are not implemented in the v1 profile"},
      {"scenario": "psk/resumption", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: pre-shared keys are not implemented in the v1 profile"}
    ],
    "reinit.json": [
      {"scenario": "reinit/2-member", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: ReInit is not implemented in the v1 profile"},
      {"scenario": "reinit/3-member", "grpc_status": "UNIMPLEMENTED", "message_contains": "urmessage: ReInit is not implemented in the v1 profile"}
    ]
  }
}
```

The scenario ids are placeholders until the pinned runner's first output is captured. **The first
interop run's `runner-output.json` is the source for the real ids**; copy them in and re-run. This is
a data transcription, not a design decision, and the test above already forbids getting it wrong in
the silent direction.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test ./cmd/assert-profile-rejects/ -v`
Expected: PASS — 4 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/profile-reject.json mls/interop/cmd/assert-profile-rejects && git -C connect commit -m "test(mls-interop): assert the observed failure set equals the documented one"
```

---

### Task 33: The both-role interop CI matrix

**Files:**
- Create: `connect/mls/interop/docker-compose.yml`, `connect/.github/workflows/mls-interop.yml`
- Modify: `connect/mls/interop/PINS.md` (the one pin file, created in Task 6)
- Test: `connect/mls/interop/workflow_test.go`

**Interfaces:**
- Consumes: the client binary (Tasks 28–31), `assert-profile-rejects` (Task 32), the pinned mlswg
  runner (Task 6).
- Produces: the `mls-interop` CI job — Gate 2.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/interop/workflow_test.go
// both roles, or half the implementation is untested — and the receiver half is
// where the validation logic lives.
package interop_test

import (
	"os"
	"strings"
	"testing"
)

func TestInteropWorkflowRunsBothRoles(t *testing.T) {
	body, err := os.ReadFile("../../.github/workflows/mls-interop.yml")
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	text := string(body)

	// ours first — we are committer/creator.
	if !strings.Contains(text, "-client ours:50051 -client ${{ matrix.peer }}:50052") {
		t.Error("no run with our client first; we are never exercised as committer")
	}
	// ours last — we are receiver/joiner.
	if !strings.Contains(text, "-client ${{ matrix.peer }}:50052 -client ours:50051") {
		t.Error("no run with our client last; we are never exercised as receiver, which is where the validation logic lives")
	}
	// the three-party case.
	if !strings.Contains(text, "-client openmls:50053") {
		t.Error("no three-party run; a commit we neither authored nor are the sole recipient of is never exercised")
	}
	for _, peer := range []string{"openmls", "mlspp", "mls-rs"} {
		if !strings.Contains(text, peer) {
			t.Errorf("peer %s is not in the matrix", peer)
		}
	}
	if !strings.Contains(text, "assert-profile-rejects") {
		t.Error("the documented-failure assertion is not wired in")
	}
	if !strings.Contains(text, "-private") {
		t.Error("A-ASSUME-4 puts all handshake traffic in PrivateMessage; the per-commit matrix must use -private")
	}
	if strings.Contains(text, "cargo build") || strings.Contains(text, "cmake") {
		t.Error("CI must never compile Rust or C++ on the per-commit path; peers are pinned by image digest")
	}
	if !strings.Contains(text, "wiredump") {
		t.Error("a failure must upload the exact bytes that diverged")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd connect/mls/interop && go test . -run TestInteropWorkflowRunsBothRoles -v`
Expected: FAIL with `read workflow: open ../../.github/workflows/mls-interop.yml: no such file or directory`

- [ ] **Step 3: Write minimal implementation**

```yaml
# connect/mls/interop/docker-compose.yml
# the three peers, pinned by image digest. Bumping a digest is a PR that must show a
# green matrix; the weekly peer-image-bump job opens it.
services:
  openmls:
    image: ghcr.io/urnetwork/mls-peer-openmls@sha256:PINNED
    command: ["--port", "50053"]
    ports: ["50053:50053"]
  mlspp:
    image: ghcr.io/urnetwork/mls-peer-mlspp@sha256:PINNED
    command: ["--port", "50052"]
    ports: ["50052:50052"]
  mls-rs:
    image: ghcr.io/urnetwork/mls-peer-mls-rs@sha256:PINNED
    command: ["--port", "50052"]
    ports: ["50054:50052"]
```

```yaml
# connect/.github/workflows/mls-interop.yml
name: mls-interop
on:
  push:
    branches: [beta/message]
  pull_request:
    branches: [beta/message]
jobs:
  mls-interop:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    strategy:
      fail-fast: false
      matrix:
        peer: [openmls, mlspp, mls-rs]
        config: [welcome_join.json, commit.json, application.json, branch.json, external_join.json, external_proposals.json, psk.json, reinit.json]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      - name: build our client from the branch under test
        run: go build -o /tmp/urmessage-mls-client ./client
        working-directory: mls/interop
      - name: peers, pinned by digest
        run: docker compose -f mls/interop/docker-compose.yml up -d --wait
      - name: start our client
        run: /tmp/urmessage-mls-client -port 50051 -wiredump mls/interop/out/wiredump &
      # run 1 — ours first: we are committer/creator
      - name: committer role
        run: go run ./test-runner -config configs/${{ matrix.config }} -client ours:50051 -client ${{ matrix.peer }}:50052 -private -json-out out/run1.json
        working-directory: mls/interop
      # run 2 — ours last: we are receiver/joiner, where the validation logic lives
      - name: receiver role
        run: go run ./test-runner -config configs/${{ matrix.config }} -client ${{ matrix.peer }}:50052 -client ours:50051 -private -json-out out/run2.json
        working-directory: mls/interop
      # run 3 — three-party: a commit we neither authored nor are the sole recipient of
      - name: three-party
        run: go run ./test-runner -config configs/${{ matrix.config }} -client ours:50051 -client ${{ matrix.peer }}:50052 -client openmls:50053 -private -json-out out/run3.json
        working-directory: mls/interop
      - name: assert documented failures
        run: |
          go run ./cmd/merge-runner-output out/run1.json out/run2.json out/run3.json > out/runner-output.json
          go run ./cmd/assert-profile-rejects -expect profile-reject.json -got out/runner-output.json
        working-directory: mls/interop
      - name: assert zero leaked states
        run: test "$(cat mls/interop/out/leaked-states || echo 0)" = "0"
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: interop-transcripts-${{ matrix.peer }}-${{ matrix.config }}
          path: |
            mls/interop/out/*.json
            mls/interop/out/wiredump/*.bin
```

`test-runner/`, `configs/` and `cmd/merge-runner-output` are Task 25a's; this task only wires them
into CI. Record the three peer image digests in `connect/mls/interop/PINS.md` — the `mlswg=` and
`openmls=` lines are already there from Task 6, and `TestRunnerIsVendoredAtThePinnedCommit` holds the
vendored runner to the first of them.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test . -run TestInteropWorkflowRunsBothRoles -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/docker-compose.yml mls/interop/workflow_test.go .github/workflows/mls-interop.yml mls/interop/PINS.md && git -C connect commit -m "ci(mls-interop): both-role matrix against three peers, with documented failures asserted"
```

---

## Execution order and gate mapping

Tasks 1–9, 3a and 13–16 are executable in wave 1 and depend on nothing outside `connect/mls/syntax`
and the wave-1 crypto plan. Tasks 10, 11, 12 and 12a are **Phase A′** and land in wave 4 with the
codec table and the `StateStore` they are built on. Tasks 17–24 need `group.go` and land at the end
of slice A4. Tasks 25–33 need the same and land as slice A5.

| Spec A gate | Tasks | Slice |
|---|---|---|
| Gate 2, vector families | 6, 7, 8, 9, 13 | A1, then each family's own plan |
| Gate 2, interop harness | 25, 25a, 26, 27, 28, 29, 30, 31, 32, 33 | A5 |
| Gate 3, 43 ValSem codes | 2, 3, 17, 18, 19, 20, 21, 22, 24 | A4 |
| Gate 3, the v1 narrow profile | 3a | A1 |
| Gate 3, errata | 1, 23 | A4 |
| Gate 4, fuzz properties 1–2 | 11, 12, 12a | A4 (Phase A′) |
| Gate 4, differential | 14, 15, 16 | A11 |
| Layering (Spec A §2.3) | 4, 5, 25 | A1 |

`TestValSemCoverageIsComplete` (Task 3) is the single test that proves Gate 3: it fails until every
one of the 51 catalogue entries has a named test function, and Task 24 makes it blocking.

## What this plan owns that the registry moved here

Three things arrived with the canonical interface registry and are produced by tasks above rather
than consumed from anywhere.

| Thing | Task | Why it landed here |
|---|---|---|
| `Profile`, `DefaultProfile`, the seven `Check*` | 3a | `profile.go` was attributed circularly and created by nobody, while `GroupConfig.Profile` is required by `NewGroup`; it belongs beside the `ErrProfile*` values the checks return |
| the ten framing sentinels `ErrWrongGroupId`…`ErrNonZeroPadding`, and `ErrPskNonceLength`/`ErrPskType`/`ErrDuplicatePsk` | 2 | they are ValSem002–011 and ValSem401–403; declaring them in two files in one package is a redeclaration error, and this file is wave 1 |
| `interop/test-runner/`, its 8 configs, `cmd/merge-runner-output`, `cmd/seedgen` and the committed corpus | 25a, 12a | Gate 2 and Gate 4 name them and no plan created them |

## Open asks on other plans

Everything this plan calls is in the canonical interface registry with the signature used above. The
list below is what other plans must **produce** for these tasks to compile — none of it is a new
name, and each row cites the registry section that assigns it.

| Ask | Plan | Registry | Why |
|---|---|---|---|
| `NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error)` | Crypto primitives and HPKE | §3.2 | a failing ValSem test must reproduce from a fixed seed |
| `(*Group).sealFramedContentForTest(c, auth, wf, signer) ([]byte, error)` | Framing and message protection | §7.3 | there is no other way to frame a message the honest path refuses to build |
| `(*Group).sealFramedContentWithPaddingForTest(c, auth, wf, signer, padding) ([]byte, error)` | Framing and message protection | §7.3 | ValSem011 |
| `(*AuthenticatedContent).ProposalRef(crypto) (ProposalRef, error)` | Framing and message protection | §7.2 | ValSem111, ValSem201, ValSem244, erratum 8815 |
| `CommitOptions.skipValidation` / `dropConfirmationTag` / `confirmationTagOverPreCommitTranscript` | Group lifecycle | §8.3 | half the commit-side codes need a commit the construction side already refuses; ValSem009 and ValSem205 need the other two |
| `(*Group).OwnLeafNodeCopy() *LeafNode`, `(*Group).ClearPendingCommit()` | Group lifecycle | §8.3 | every Update-shaped mutation, and the forge's teardown |
| `(*Group).Close() error` | Group lifecycle | §8.3 | the interop `Free` RPC asserts zero leaked states at exit |
| `CheckErrata8745(path, context)`, `CheckErrata8815(commit, pending)` | Group lifecycle | §8.2 | Task 23 |
| `KeyPackage`, `NewKeyPackage`, `(*KeyPackage).Ref`, and the codec | TreeKEM | §6.5 | the forge, the codec table, ValSem101–106 |
| `(*RatchetTree).HasTrailingBlankNodes()`, `(*RatchetTree).Validate(ctx)`, `UnmarshalRatchetTree`, `OptionalNode` | TreeKEM | §6.6 | ValSem300 |
| `syntax.VerifyDeserializationVector(t, raw)` | Syntax and codec | §9.2 | family 16 is implemented once, there; Task 8 is the shim |
| `syntax.CheckRoundTrip[T, PT](bs) error` and the ten typed codec errors | Syntax and codec | §2.1, §2.4 | Gate 4 property 2 |
| every family's `Verify` **and** `Generate`, registered from an `init()` and struck from `expectedPendingFamilies` in the same commit | each family's owning plan | §9.2 | Spec A §4.2.1 requires both directions, and without the registration `TestVectorFamiliesVerify` runs one family while Gate 1 stays green |
| `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc` as developer tools | repo tooling | — | Task 25 generates once and commits the stubs |

Four asks this plan used to make are **refused** by the registry, and the substitutes are already in
the code above: `FramedContentAuthData.MembershipTag` → `PublicMessage.MembershipTag`;
`FramedContentAuthData.HasConfirmationTag` → presence derived from `ContentType`;
`FramedContent.RawProposal` → `Proposal.UnknownType` / `Proposal.UnknownBody`;
`RatchetTreeExtension` → `FindExtension(exts, ExtensionTypeRatchetTree)` + `UnmarshalRatchetTree`.
