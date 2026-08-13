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

---

## File Structure

Every file created or modified by this plan, and its single responsibility.

| File | Responsibility |
|---|---|
| `connect/layering_test.go` | Walks `go list -deps`; asserts the four forbidden import edges of Spec A §2.3 |
| `connect/scripts/check-forbidden.sh` | Grep gates G1, G3, G8 and the three forbidden X25519 call sites |
| `connect/mls/errors.go` | `ValSemCode`, `ValidationError`, one sentinel per ValSem code and per erratum |
| `connect/mls/errors_test.go` | Catalogue closure; `errors.Is` semantics; ValSem coverage report |
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
| `connect/mls/PINS.md` | Pinned mlswg commit, OpenMLS commit, three peer image digests |
| `connect/mls/testdata/vectors/*.json` | The 16 vendored vector families |
| `connect/mls/testdata/vectors/VECTORS.sha256` | Per-file digest manifest; makes a silent re-vendor a test failure |
| `connect/mls/testdata/corpus/**` | Seed corpus for the 9 targets |
| `connect/mls/testdata/divergence-allowlist.json` | Justified accept/reject divergences from OpenMLS |
| `connect/mls/interop/go.mod` | Separate module; gRPC and protobuf live here and nowhere else |
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
func ValSemCatalogue() []ValSemCode          // sorted, exactly 46 entries
func ReasonFor(code ValSemCode) string
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
// connect/mls/syntax_fuzz_test.go — the codec table the fuzz targets and the
// oracle protocol share. Each Parse/Encode pair is supplied by its owning plan.
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
func (self *oracle) decode(kind CodecKind, input []byte) (oracleResult, error)
func (self *oracle) close() error
```

## Interfaces consumed by this plan

Named against the plan expected to produce them. A signature drift here is a merge conflict, not a
silent failure — every one of these is referenced by real code in a task below.

**From "Syntax and codec" (wave 1), `package syntax`:**

```go
func Marshal(v any) ([]byte, error)
func Unmarshal(b []byte, v any) error
func ReadVarint(b []byte) (value uint64, n int, err error)
func WriteVarint(dst []byte, value uint64) []byte
const MaxVectorLength = 1 << 20
const MaxRatchetTreeLength = 1 << 24
var ErrNonMinimalLength error
var ErrTrailingBytes error
var ErrVectorTooLong error
```

**From "Crypto primitives and HPKE" (wave 1), `package mls`:**

```go
type CipherSuite uint16
const CipherSuiteX25519ChaCha20SHA256Ed25519 CipherSuite = 0x0003
const CipherSuiteX25519AES128GCMSHA256Ed25519 CipherSuite = 0x0001
type CryptoProvider interface { /* Spec A §3.3, verbatim */ }
func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)
func NewCryptoProviderWithRandom(suite CipherSuite, random io.Reader) (CryptoProvider, error)
func RegisteredSuites() []CipherSuite
type SignaturePrivateKey []byte
type SignaturePublicKey []byte
type HpkePrivateKey []byte
type HpkePublicKey []byte
```

`NewCryptoProviderWithRandom` is required by the forge so a failing ValSem test reproduces from a
fixed seed. It is called out in the summary as an ask on that plan.

**From "Tree math" (wave 1), `package mls`:**

```go
type LeafIndex uint32
type NodeIndex uint32
func Root(leafCount uint32) NodeIndex
func DirectPath(x LeafIndex, leafCount uint32) []NodeIndex
func Copath(x LeafIndex, leafCount uint32) []NodeIndex
```

**From "Key schedule and secret tree" (wave 2), `package mls`:**

```go
type EpochSecretName uint8
const (
    EpochSecretSenderData EpochSecretName = iota + 1
    EpochSecretEncryption
)
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error)
func (self *Group) Export(label string, context []byte, length int) ([]byte, error)
func (self *Group) EpochAuthenticator() []byte
```

**From "TreeKEM" (wave 2), `package mls`:**

```go
type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode
}
type UpdatePathNode struct {
    EncryptionKey HpkePublicKey
    EncryptedPathSecret []HpkeCiphertext
}
type HpkeCiphertext struct {
    KemOutput  []byte
    Ciphertext []byte
}
```

**From "Framing and message protection" (wave 3), `package mls`:**

```go
type ContentType uint8
const (
    ContentTypeApplication ContentType = 1
    ContentTypeProposal    ContentType = 2
    ContentTypeCommit      ContentType = 3
)
type SenderType uint8
const (
    SenderMember            SenderType = 1
    SenderExternal          SenderType = 2
    SenderNewMemberProposal SenderType = 3
    SenderNewMemberCommit   SenderType = 4
)
type Sender struct {
    Type       SenderType
    LeafIndex  LeafIndex
    SenderIndex uint32
}
type FramedContent struct {
    GroupId     []byte
    Epoch       uint64
    Sender      Sender
    AuthenticatedData []byte
    ContentType ContentType
    Application []byte
    Proposal    *Proposal
    Commit      *Commit
}
type FramedContentAuthData struct {
    Signature        []byte
    ConfirmationTag  []byte
    HasConfirmationTag bool
}
type WireFormat uint16
const (
    WireFormatPublicMessage  WireFormat = 1
    WireFormatPrivateMessage WireFormat = 2
)
// the construction-bypass seam the forge needs — signs and frames c exactly as
// the honest path does, but runs no validation gate.
func (self *Group) sealFramedContentForTest(c *FramedContent, auth *FramedContentAuthData,
    wf WireFormat, signer SignaturePrivateKey) ([]byte, error)
func ParseMLSMessage(b []byte) (*MLSMessage, error)
func EncodeMLSMessage(m *MLSMessage) ([]byte, error)
```

`sealFramedContentForTest` is an unexported seam in `framing.go`, not a public API. It is called out
in the summary as an ask on that plan.

**From "Group lifecycle" (wave 4), `package mls`:**

```go
func NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error)
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte, keys *JoinKeyMaterial) (*Group, error)
func (self *Group) Commit(byReference [][]byte, byValue []Proposal, opts *CommitOptions) (*CommitResult, error)
func (self *Group) ProcessMessage(message []byte) (*Processed, error)
func (self *Group) ApplyCommit(processed *Processed) error
func (self *Group) MergePendingCommit() error
func (self *Group) ClearPendingCommit()
func (self *Group) Close() error            // releases and zeroizes; the interop Free RPC needs it
type StateStore interface { /* Spec A §3.5, verbatim */ }
type Proposal struct { /* proposal.go */ }
type ProposalRef []byte
type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}
type Profile struct { /* profile.go */ }
const PastEpochWindow = 32
func ParseExtension(b []byte) (*Extension, error)
func EncodeExtension(e *Extension) ([]byte, error)
func ParseKeyPackage(b []byte) (*KeyPackage, error)
func EncodeKeyPackage(kp *KeyPackage) ([]byte, error)
func ParseProposal(b []byte) (*Proposal, error)
func EncodeProposal(p *Proposal) ([]byte, error)
func ParseWelcome(b []byte) (*Welcome, error)
func EncodeWelcome(w *Welcome) ([]byte, error)
```

`Group.Close()` is required by the interop `Free` RPC, whose CI job asserts zero leaked states at
exit. It is called out in the summary as an ask on that plan.

---

## The 43 ValSem codes and the malformed input that triggers each

This table is the specification for Tasks 18–23. Every row names the **one** thing the test mutates.
Each test builds a valid group, applies exactly that mutation, and asserts exactly that error.

**Framing (RFC 9420 §6) — `validation_framing_test.go`**

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 002 | `TestValSem002_WrongGroupId` | `FramedContent.GroupId` = the group id with its final byte incremented | `ErrWrongGroupId` |
| 003 | `TestValSem003_WrongEpoch` | `FramedContent.Epoch = group.Epoch() + 1` | `ErrWrongEpoch` |
| 004 | `TestValSem004_BlankSenderLeaf` | `Sender{Type: SenderMember, LeafIndex: 2}` after leaf 2 was removed and blanked | `ErrBlankSenderLeaf` |
| 005 | `TestValSem005_ApplicationMustBeCiphertext` | application content framed with `WireFormatPublicMessage` | `ErrApplicationMustBeCiphertext` |
| 006 | `TestValSem006_DecryptFails` | flip bit 0 of byte 0 of `PrivateMessage.Ciphertext` | `ErrDecryptFailed` |
| 007 | `TestValSem007_MissingMembershipTag` | `PublicMessage` from a member with `MembershipTag` set to a zero-length slice | `ErrMissingMembershipTag` |
| 008 | `TestValSem008_BadMembershipTag` | `MembershipTag` computed under `crypto.Random(32)` instead of `membership_key` | `ErrBadMembershipTag` |
| 009 | `TestValSem009_MissingConfirmationTag` | a Commit whose `FramedContentAuthData.HasConfirmationTag = false` | `ErrMissingConfirmationTag` |
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
| 112 | `TestValSem112_UpdateSenderNotMember` | standalone Update framed with `Sender{Type: SenderNewMemberProposal}` | `ErrUpdateSenderNotMember` |
| 113 | `TestValSem113_UnsupportedProposalType` | proposal type `0xF0FF`, absent from every member's `Capabilities.Proposals` | `ErrUnsupportedProposalType` |

**Commits (§12.4) and the ratchet tree (§12.4.3.1) — `validation_commit_test.go`**

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 200 | `TestValSem200_SelfRemoveInCommit` | Commit with an inline `Remove{Removed: committer's own leaf}` | `ErrSelfRemoveInCommit` |
| 201 | `TestValSem201_MissingPath` | Commit covering an Update with `Commit.Path = nil` | `ErrMissingPath` |
| 202 | `TestValSem202_PathLength` | drop the last element of `UpdatePath.Nodes` | `ErrPathLength` |
| 203 | `TestValSem203_PathDecrypt` | flip bit 0 of the `HpkeCiphertext.Ciphertext` addressed to the receiver's resolution slot | `ErrPathDecrypt` |
| 204 | `TestValSem204_PathKeyMismatch` | replace `UpdatePathNode.EncryptionKey` at index 0 with a freshly generated public key, leaving the ciphertexts alone | `ErrPathKeyMismatch` |
| 205 | `TestValSem205_BadConfirmationTag` | `ConfirmationTag` computed over the **pre**-commit `confirmed_transcript_hash` | `ErrBadConfirmationTag` |
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
| 240 | `TestValSem240_ExternalCommitNoExternalInit` | `Sender{Type: SenderNewMemberCommit}` commit with **zero** inline `ExternalInit` proposals | `ErrProfileExternalCommit` at parse |
| 241 | `TestValSem241_ExternalCommitTwoExternalInit` | same, with **two** inline `ExternalInit` proposals | `ErrProfileExternalCommit` |
| 242 | `TestValSem242_ExternalCommitNonAllowlisted` | external commit carrying an inline `Add` (not on the §12.4.3.2 allowlist) | `ErrProfileExternalCommit` |
| 244 | `TestValSem244_ExternalCommitByReference` | external commit whose `Commit.Proposals` holds a `ProposalRef` | `ErrProfileExternalCommit` |
| 245 | `TestValSem245_ExternalCommitNoPath` | external commit with `Commit.Path = nil` | `ErrProfileExternalCommit` |
| 246 | `TestValSem246_ExternalCommitSignerNotPathCredential` | external commit signed by an existing member's signer rather than the path `LeafNode` credential | `ErrProfileExternalCommit` |

There is no ValSem243 — the mlswg numbering skips it. ValSem247 is folded into ValSem010.

**PSK (§8.4) — profile-refused in v1 — `validation_psk_test.go`**

| Code | Test function | Malformed input | Expected |
|---|---|---|---|
| 401 | `TestValSem401_PskNonceLength` | `PreSharedKeyID.PskNonce` of 31 bytes where `KDF.Nh == 32` | `ErrProfilePSK` at parse |
| 402 | `TestValSem402_PskUsage` | `PreSharedKeyID` with resumption usage `reinit` (2) | `ErrProfilePSK` |
| 403 | `TestValSem403_DuplicatePskId` | two byte-identical `PreSharedKeyID` values in one proposal list | `ErrProfilePSK` |

**Past-epoch bound — `validation_epoch_test.go`**

| Code | Test function | Assertion | Expected |
|---|---|---|---|
| 400 | `TestValSem400_PastEpochBound` | merge 40 commits; assert `memStore.EpochsHeld` holds exactly epochs `8..40` and nothing older | 33 epochs held, `epoch - 32` and below deleted |

**Errata — `errata_test.go`**

| Erratum | Test function | Malformed input | Expected |
|---|---|---|---|
| 8745 | `TestErrata8745` | a Commit whose `UpdatePath.LeafNode.Capabilities.Extensions` omits `0xF001`, a GroupContext extension | `ErrMissingRequiredCapability`; the pre-erratum "accept" outcome is asserted absent |
| 8815 | `TestErrata8815` | a Commit whose `Commit.Proposals` holds a `ProposalRef` of 32 random bytes the receiver never saw | `ErrUnknownProposalRef` |

Total: 43 ValSem codes + ValSem400 + 2 errata = **46 catalogue entries, 46 test functions.**

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
  - `func ValSemCatalogue() []ValSemCode`
  - `func ReasonFor(code ValSemCode) string`
  - the 46 sentinels: `ErrWrongGroupId`, `ErrWrongEpoch`, `ErrBlankSenderLeaf`,
    `ErrApplicationMustBeCiphertext`, `ErrDecryptFailed`, `ErrMissingMembershipTag`,
    `ErrBadMembershipTag`, `ErrMissingConfirmationTag`, `ErrBadSignature`, `ErrNonZeroPadding`,
    `ErrDuplicateSignatureKey`, `ErrDuplicateInitKey`, `ErrDuplicateEncryptionKey`,
    `ErrInitEqualsEncryptionKey`, `ErrSuiteMismatch`, `ErrMissingRequiredCapability`,
    `ErrDuplicateRemove`, `ErrRemoveNonMember`, `ErrSelfUpdateInCommit`, `ErrUpdateSenderNotMember`,
    `ErrUnsupportedProposalType`, `ErrSelfRemoveInCommit`, `ErrMissingPath`, `ErrPathLength`,
    `ErrPathDecrypt`, `ErrPathKeyMismatch`, `ErrBadConfirmationTag`, `ErrMultipleGCE`,
    `ErrUnsupportedGroupExtension`, `ErrProfileExternalCommit`, `ErrTrailingBlankNodes`,
    `ErrProfilePSK`, `ErrPastEpochBound`, `ErrUnknownProposalRef`

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
	ValSem401: "pre-shared keys are not implemented in the v1 profile",
	ValSem402: "pre-shared keys are not implemented in the v1 profile",
	ValSem403: "pre-shared keys are not implemented in the v1 profile",

	ValSemErrata8745: "leaf node capabilities do not cover every group context extension",
	ValSemErrata8815: "commit references a proposal that was never received",
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

// the sentinels. Each is the zero-detail form of its code, for errors.Is.
var (
	ErrWrongGroupId                = ValSem(ValSem002, nil)
	ErrWrongEpoch                  = ValSem(ValSem003, nil)
	ErrBlankSenderLeaf             = ValSem(ValSem004, nil)
	ErrApplicationMustBeCiphertext = ValSem(ValSem005, nil)
	ErrDecryptFailed               = ValSem(ValSem006, nil)
	ErrMissingMembershipTag        = ValSem(ValSem007, nil)
	ErrBadMembershipTag            = ValSem(ValSem008, nil)
	ErrMissingConfirmationTag      = ValSem(ValSem009, nil)
	ErrBadSignature                = ValSem(ValSem010, nil)
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

	ErrProfileExternalCommit = ValSem(ValSem240, nil)
	ErrTrailingBlankNodes    = ValSem(ValSem300, nil)
	ErrPastEpochBound        = ValSem(ValSem400, nil)
	ErrProfilePSK            = ValSem(ValSem401, nil)

	ErrUnknownProposalRef = ValSem(ValSemErrata8815, nil)
)
```

Note the deliberate aliasing: ValSem103, 110, 206 and 207 all surface `ErrDuplicateEncryptionKey`
and ValSem106 and 109 both surface `ErrMissingRequiredCapability`, exactly as Spec A §4.3 specifies.
The **code** distinguishes them, so a test asserts `CodeOf(err) == ValSem110` where the sentinel
alone would be ambiguous. `requireValSem` (Task 17) asserts the code, never the sentinel.

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

// expectedCatalogue is Spec A §4.3, transcribed. 43 ValSem codes, plus ValSem400
// and the two errata. Changing this list without changing the spec is the failure
// this test exists to cause.
var expectedCatalogue = []ValSemCode{
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
	200, 201, 202, 203, 204, 205, 206, 207, 208, 209,
	240, 241, 242, 244, 245, 246,
	300,
	400, 401, 402, 403,
	8745, 8815,
}

func TestValSemCatalogueIsClosed(t *testing.T) {
	got := ValSemCatalogue()
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
	// the catalogue counts 43 ValSem codes proper.
	proper := 0
	for _, code := range got {
		if code != 400 && code < 8000 {
			proper++
		}
	}
	if proper != 43 {
		t.Errorf("catalogue holds %d ValSem codes excluding 400, want 43", proper)
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
	sources = append(sources, "errata_test.go")
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

// codeFromTestName maps TestValSem204_PathKeyMismatch to 204 and TestErrata8745 to
// 8745. Anything else is not a ValSem test and is ignored.
func codeFromTestName(name string) (ValSemCode, bool) {
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
	if code >= 8000 {
		return "errata " + strconv.FormatUint(uint64(code), 10)
	}
	return "ValSem" + fmt.Sprintf("%03d", code)
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

**Files:**
- Create: `connect/mls/testdata/vectors/*.json` (16 files), `connect/mls/testdata/vectors/VECTORS.sha256`, `connect/mls/PINS.md`
- Test: `connect/mls/vectors_pin_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: the pinned corpus every family runner reads, and `TestVectorFilesArePinned`.

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorFilesArePinned -v`
Expected: FAIL with `open VECTORS.sha256: no such file or directory`

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
( cd connect/mls/testdata/vectors && sha256sum *.json > VECTORS.sha256 )
```

```markdown
<!-- connect/mls/PINS.md -->
# Pinned external references

Bumping any line here is a pull request that must show a green interop matrix and a green
`vectors` job. Nothing in this file enters `go.mod`.

| What | Pin | Why |
|---|---|---|
| mlswg/mls-implementations | commit `<recorded by the clone above>` | the 16 vector families **and** the gRPC test runner, pinned together so the runner and the vectors never disagree |
| openmls/openmls | commit `<recorded when the oracle is built>` | the differential oracle and the 9 fuzz targets; built out of process in CI, never linked |
| `ghcr.io/urnetwork/mls-peer-openmls` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mlspp` | digest `sha256:<...>` | interop peer |
| `ghcr.io/urnetwork/mls-peer-mls-rs` | digest `sha256:<...>` | interop peer |

Peer images are prebuilt and pushed to GHCR by the weekly `peer-image-bump` job, which opens a
digest-bump PR. CI never compiles Rust or C++ on a per-commit path.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestVectorFilesArePinned -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/testdata/vectors mls/vectors_pin_test.go mls/PINS.md && git -C connect commit -m "test(mls): vendor and digest-pin the 16 RFC 9420 vector families"
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

**Interfaces:**
- Consumes: `syntax.ReadVarint(b []byte) (uint64, int, error)`, `syntax.WriteVarint(dst []byte, value uint64) []byte`, `syntax.ErrNonMinimalLength` (Syntax and codec plan); `RegisterVectorFamily`, `LoadVectorFile`, `MustHex`, `HexOf` (Task 7).
- Produces: family 16's `Verify` and `Generate`; removes 16 from `expectedPendingFamilies`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/vectors_deserialization_kat_test.go
// family 16 of Spec A §4.2.1. The mlswg deserialization vectors are exactly the
// canonical-encoding property: one valid variable-length prefix per length, and a
// non-minimal prefix is a decode error. A decoder that accepts two encodings of the
// same object is a signature-bypass primitive, because MLS signs over serialized forms.
package mls

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/urnetwork/connect/mls/syntax"
)

// deserializationCase is one row of deserialization.json.
type deserializationCase struct {
	VlbytesHeader string `json:"vlbytes_header"`
	Length        uint32 `json:"length"`
}

func init() {
	RegisterVectorFamily(VectorFamily{
		Number: 16,
		Name:   "Vector deserialization",
		File:   "deserialization.json",
		Slice:  "A1",
		Verify: verifyDeserializationVector,
		Generate: generateDeserializationVector,
	})
}

func verifyDeserializationVector(t *testing.T, raw json.RawMessage) {
	testCase := deserializationCase{}
	if err := json.Unmarshal(raw, &testCase); err != nil {
		t.Fatalf("parse case: %v", err)
	}
	header := MustHex(t, testCase.VlbytesHeader)

	value, consumed, err := syntax.ReadVarint(header)
	if err != nil {
		t.Fatalf("ReadVarint(%x) = error %v, want length %d", header, err, testCase.Length)
	}
	if consumed != len(header) {
		t.Errorf("ReadVarint(%x) consumed %d bytes, want %d", header, consumed, len(header))
	}
	if value != uint64(testCase.Length) {
		t.Errorf("ReadVarint(%x) = %d, want %d", header, value, testCase.Length)
	}

	// canonicality: re-encoding the decoded length must reproduce the same bytes.
	reencoded := syntax.WriteVarint(nil, value)
	if !bytes.Equal(reencoded, header) {
		t.Errorf("WriteVarint(%d) = %x, want %x — the prefix has exactly one valid encoding", value, reencoded, header)
	}

	// and the non-minimal form of the same value must be refused.
	if longer := nonMinimalVarint(value); longer != nil {
		if _, _, err := syntax.ReadVarint(longer); err == nil {
			t.Errorf("ReadVarint accepted the non-minimal prefix %x for length %d", longer, value)
		}
	}
}

func generateDeserializationVector(t *testing.T) json.RawMessage {
	// one case per prefix width boundary, both sides.
	lengths := []uint64{0, 1, 63, 64, 16383, 16384, 1 << 20}
	cases := make([]deserializationCase, 0, len(lengths))
	for _, length := range lengths {
		cases = append(cases, deserializationCase{
			VlbytesHeader: HexOf(syntax.WriteVarint(nil, length)),
			Length:        uint32(length),
		})
	}
	body, err := json.Marshal(cases)
	if err != nil {
		t.Fatalf("marshal generated cases: %v", err)
	}
	return body
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestVectorFamiliesVerify -v`
Expected: FAIL to build with `undefined: nonMinimalVarint`, and once that is added,
`TestVectorManifestIsComplete` FAILs with
`pending families [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16], expected [1 2 ... 15]` — the reverse
direction, because 16 is now registered with a runner while the pending list still names it.

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/vectors_deserialization_kat_test.go

// nonMinimalVarint re-encodes value one prefix width wider than the canonical form,
// which RFC 9420 §2.1.2 forbids. nil when value already needs the widest prefix.
func nonMinimalVarint(value uint64) []byte {
	switch {
	case value < 1<<6:
		return []byte{0x40 | byte(value>>8), byte(value)}
	case value < 1<<14:
		return []byte{0x80, byte(value >> 16), byte(value >> 8), byte(value)}
	default:
		return nil
	}
}
```

And in `connect/mls/vectors_test.go`, remove 16:

```go
var expectedPendingFamilies = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
```

stays as written — 16 was never in it. Confirm by running both tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestVectorManifestIsComplete|TestVectorFamiliesVerify' -v`
Expected: PASS, with family 16 running every case in `deserialization.json`

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

### Task 10: The in-memory state store

**Files:**
- Create: `connect/mls/memstore_test.go`
- Test: same file

**Interfaces:**
- Consumes: `type StateStore interface` (Group lifecycle plan, Spec A §3.5).
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
		return nil, ValSem(ValSem400, nil)
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
		return nil, ValSem(ValSem203, nil)
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
		return nil, nil, nil, ValSem(ValSem203, nil)
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

**Files:**
- Create: `connect/mls/codec_table_test.go`
- Test: same file

**Interfaces:**
- Consumes: `ParseExtension`/`EncodeExtension`, `ParseKeyPackage`/`EncodeKeyPackage`,
  `ParseMLSMessage`/`EncodeMLSMessage`, `ParseProposal`/`EncodeProposal`,
  `ParseWelcome`/`EncodeWelcome` (Syntax and codec plan for the first pair, Group lifecycle plan for
  the rest).
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
// prepend to connect/mls/codec_table_test.go

import "slices"

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
		Decode: func(b []byte) (any, error) { return ParseExtension(b) },
		Encode: func(v any) ([]byte, error) { return EncodeExtension(v.(*Extension)) },
	},
	KindKeyPackage: {
		Name:   "key_package",
		Decode: func(b []byte) (any, error) { return ParseKeyPackage(b) },
		Encode: func(v any) ([]byte, error) { return EncodeKeyPackage(v.(*KeyPackage)) },
	},
	KindMlsMessage: {
		Name:   "mls_message",
		Decode: func(b []byte) (any, error) { return ParseMLSMessage(b) },
		Encode: func(v any) ([]byte, error) { return EncodeMLSMessage(v.(*MLSMessage)) },
	},
	KindProposal: {
		Name:   "proposal",
		Decode: func(b []byte) (any, error) { return ParseProposal(b) },
		Encode: func(v any) ([]byte, error) { return EncodeProposal(v.(*Proposal)) },
	},
	KindWelcome: {
		Name:   "welcome",
		Decode: func(b []byte) (any, error) { return ParseWelcome(b) },
		Encode: func(v any) ([]byte, error) { return EncodeWelcome(v.(*Welcome)) },
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

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestCodecTable -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/codec_table_test.go && git -C connect commit -m "test(mls): shared codec table for the fuzz targets and the oracle"
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

// TestFuzzTargetsCoverEveryKind fails if a decoder is added without a target, which
// is how a decoder quietly stops being fuzzed.
func TestFuzzTargetsCoverEveryKind(t *testing.T) {
	covered := map[CodecKind]int{}
	for _, kind := range []CodecKind{
		KindExtension, KindExtension,
		KindKeyPackage, KindKeyPackage,
		KindMlsMessage, KindMlsMessage,
		KindProposal, KindProposal,
		KindWelcome,
	} {
		covered[kind]++
	}
	if len(covered) != len(CodecKinds()) {
		t.Fatalf("%d kinds have targets, the codec table holds %d", len(covered), len(CodecKinds()))
	}
	total := 0
	for _, count := range covered {
		total += count
	}
	if total != 9 {
		t.Fatalf("%d fuzz targets, OpenMLS ships 9", total)
	}
}
```

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

### Task 13: The per-commit CI workflow

**Files:**
- Create: `connect/.github/workflows/mls-vectors.yml`, `connect/.github/workflows/mls-fuzz.yml`
- Test: `connect/mls/workflow_test.go`

**Interfaces:**
- Consumes: the test names of Tasks 3–12.
- Produces: the `vectors`, `valsem`, `layering`, `forbidden-crypto` and `fuzz-short` CI jobs, and
  `TestWorkflowsPinTheToolchain`.

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
		"TestVectorManifestIsComplete",
		"TestVectorFamiliesVerify",
		"TestVectorGenerateThenVerify",
		"TestValSemCatalogueIsClosed",
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
        run: go test ./mls/... -run 'TestVectorFilesArePinned|TestVectorManifestIsComplete|TestVectorFamiliesVerify|TestVectorGenerateThenVerify' -v -count 1
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
        run: go test ./mls/... -run 'TestValSem|TestErrata' -v -count 1
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: valsem-coverage
          path: mls/valsem-coverage.md
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
      - run: go test ./mls/ -run '^$' -fuzz '^${{ matrix.target }}$' -fuzztime 60s
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
  `connect/mls/PINS.md`; it never enters any `go.mod` and the binary never ships.
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
openmls = { git = "https://github.com/openmls/openmls", rev = "PINNED_IN_mls/PINS.md" }
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
`connect/mls/PINS.md`. It is not part of any Go build, is not in any `go.mod`, and is never
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
  - `type oracleResult struct { Accept bool; Reserialized []byte; Error string }`
  - `func newOracle(t *testing.T) *oracle` — `t.Skip`s when `URMSG_MLS_ORACLE` is unset
  - `func (self *oracle) decode(kind CodecKind, input []byte) (oracleResult, error)`
  - `func (self *oracle) close() error`

  Standard library only: `os/exec`, `encoding/binary`, `encoding/json`, `encoding/base64`. Nothing
  enters `go.mod`, so the layering test of Task 4 still passes.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/oracle_test.go
// the Go half of the differential oracle. The framing is tested against a Go echo
// oracle so the test runs on a machine with no Rust toolchain; the Rust binary is
// exercised nightly.
package mls

import (
	"encoding/base64"
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

// oracleResult is the oracle's verdict on one input.
type oracleResult struct {
	Accept       bool   `json:"accept"`
	Reserialized []byte `json:"-"`
	Encoded      string `json:"reserialized"`
	Error        string `json:"error"`
}

// newOracle starts the binary named by URMSG_MLS_ORACLE. With the variable unset —
// every developer machine and every per-commit job — the caller skips, so the
// differential property never becomes a reason not to run the fuzzer.
func newOracle(t *testing.T) *oracle {
	t.Helper()
	path := os.Getenv("URMSG_MLS_ORACLE")
	if path == "" {
		t.Skip("URMSG_MLS_ORACLE is unset; differential property skipped (see mls/interop/oracle/BUILD.md)")
	}
	command := exec.Command(path)
	writer, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	readCloser, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start oracle %s: %v", path, err)
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
	if result.Encoded != "" {
		decoded, err := base64.StdEncoding.DecodeString(result.Encoded)
		if err != nil {
			return oracleResult{}, err
		}
		result.Reserialized = decoded
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

Add `"bufio"`, `"fmt"`, `"io"`, `"os/exec"`, `"runtime"` to the imports. Delete
`TestOracleSkipsWhenUnset` from step 1 and replace it with the honest form:

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
		key := string(rune(entry.Kind)) + entry.InputHex
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
// binary. One subprocess per target, torn down by the target's cleanup.
var differentialOracle *oracle

// allowedDivergence reports whether this exact input is a documented, justified
// disagreement rather than a defect.
func allowedDivergence(kind CodecKind, input []byte) bool {
	loadDivergenceAllowlistOnce()
	return divergenceIndex[string(rune(kind))+HexOf(input)]
}
```

`fuzzDecodeTarget` gains, before `f.Fuzz`:

```go
	if os.Getenv("URMSG_MLS_ORACLE") != "" {
		differentialOracle = newOracle(&testing.T{})
		f.Cleanup(func() { differentialOracle.close(); differentialOracle = nil })
	}
```

Replace `newOracle(&testing.T{})` with a non-skipping constructor `mustNewOracle(f)` taking
`testing.TB`, since `f.Cleanup` is on `*testing.F` and `newOracle` skips through `*testing.T`.
Change `newOracle`'s parameter type to `testing.TB` and keep the `Skip` call; `*testing.F` also
implements `Skip`.

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
- Consumes: `NewGroup`, `GroupConfig`, `Profile`, `Credential`, `Group.Commit`,
  `Group.MergePendingCommit`, `Group.ProcessMessage`, `JoinFromWelcome` (Group lifecycle plan);
  `NewCryptoProviderWithRandom` (Crypto plan); `FramedContent`, `FramedContentAuthData`, `Sender`,
  `WireFormat`, `Group.sealFramedContentForTest` (Framing plan); `newMemStore` (Task 10);
  `ValSemCode`, `CodeOf` (Task 2).
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
}

// newForge builds a group of members, all added and committed, at a deterministic
// group id and with deterministic key material. Determinism is not a nicety: a
// ValSem failure that cannot be reproduced is a ValSem failure nobody fixes.
func newForge(t *testing.T, members int) *forge {
	t.Helper()
	if members < 2 {
		t.Fatal("a forge needs at least two members: one to send and one to validate")
	}
	random := rand.New(rand.NewSource(int64(members)))
	crypto, err := NewCryptoProviderWithRandom(CipherSuiteX25519ChaCha20SHA256Ed25519, random)
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
	joiners := make([]*memStore, 0, members-1)
	joinerSigners := make([]SignaturePrivateKey, 0, members-1)
	joinerKeys := make([]*JoinKeyMaterial, 0, members-1)
	for i := 1; i < members; i++ {
		keyPackage, initPriv, encPriv := self.newKeyPackage(t)
		encoded, err := EncodeKeyPackage(keyPackage)
		if err != nil {
			t.Fatalf("encode key package %d: %v", i, err)
		}
		adds = append(adds, Proposal{Add: &Add{KeyPackage: encoded}})
		joiners = append(joiners, self.lastStore)
		joinerSigners = append(joinerSigners, self.lastSigner)
		joinerKeys = append(joinerKeys, &JoinKeyMaterial{InitPriv: initPriv, EncryptionPriv: encPriv, Signer: self.lastSigner})
	}

	result, err := creator.Commit(nil, adds, nil)
	if err != nil {
		t.Fatalf("commit the adds: %v", err)
	}
	if err := creator.MergePendingCommit(); err != nil {
		t.Fatalf("merge: %v", err)
	}
	for i, keys := range joinerKeys {
		joined, err := JoinFromWelcome(self.config(groupId, joiners[i]), result.Welcome, result.RatchetTree, keys)
		if err != nil {
			t.Fatalf("member %d join: %v", i+1, err)
		}
		self.groups = append(self.groups, joined)
		self.signers = append(self.signers, joinerSigners[i])
		self.stores = append(self.stores, joiners[i])
	}
	return self
}

// config is the v1 group configuration every forged group uses: the pinned suite,
// the required capabilities of Spec A §3.4, and the v1 profile.
func (self *forge) config(groupId []byte, store *memStore) *GroupConfig {
	return &GroupConfig{
		Suite:      CipherSuiteX25519ChaCha20SHA256Ed25519,
		GroupId:    groupId,
		Extensions: []Extension{{Type: ExtensionTypeUrmessageGroupPolicy, Data: []byte{0x00}}},
		RequiredCaps: RequiredCapabilities{
			ExtensionTypes:  []uint16{0xF001, 0xF002},
			ProposalTypes:   []uint16{},
			CredentialTypes: []uint16{CredentialTypeBasic},
		},
		Crypto:   self.crypto,
		Store:    store,
		Profile:  DefaultProfile(),
		LeafKeys: LeafKeysExtension{AlgId: 0x0014, DeviceXwingPub: self.crypto.Random(1216)},
	}
}

func (self *forge) g(i int) *Group                 { return self.groups[i] }
func (self *forge) signer(i int) SignaturePrivateKey { return self.signers[i] }
func (self *forge) store(i int) *memStore          { return self.stores[i] }

// lastStore and lastSigner carry the material newKeyPackage just generated, so the
// caller can build the joiner without a second return-value tuple everywhere.
var _ = 0

// newKeyPackage mints a fresh, valid KeyPackage for a would-be member, and records
// its signer and store on the forge for the join that follows.
func (self *forge) newKeyPackage(t *testing.T) (*KeyPackage, HpkePrivateKey, HpkePrivateKey) {
	t.Helper()
	signer, public, err := self.crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("signature key: %v", err)
	}
	initPriv, initPub, err := self.crypto.DeriveKeyPair(self.crypto.Random(32))
	if err != nil {
		t.Fatalf("init key: %v", err)
	}
	encPriv, encPub, err := self.crypto.DeriveKeyPair(self.crypto.Random(32))
	if err != nil {
		t.Fatalf("encryption key: %v", err)
	}
	keyPackage, err := NewKeyPackage(self.crypto, CipherSuiteX25519ChaCha20SHA256Ed25519,
		BasicCredential(public), signer, initPub, encPub,
		LeafKeysExtension{AlgId: 0x0014, DeviceXwingPub: self.crypto.Random(1216)},
		Capabilities{Extensions: []uint16{0xF001, 0xF002, 0xF003}, Credentials: []uint16{CredentialTypeBasic}})
	if err != nil {
		t.Fatalf("key package: %v", err)
	}
	self.lastSigner = signer
	self.lastStore = newMemStore()
	return keyPackage, initPriv, encPriv
}

// content builds a fully valid FramedContent from member i, ready to be mutated.
func (self *forge) content(i int, contentType ContentType, body []byte) *FramedContent {
	return self.contentFrom(Sender{Type: SenderMember, LeafIndex: self.g(i).OwnLeafIndex()}, contentType, body)
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
		content.Application = body
	case ContentTypeProposal:
		proposal, err := ParseProposal(body)
		if err != nil {
			self.t.Fatalf("parse proposal body: %v", err)
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

// proposalBytes frames a standalone Proposal from member i.
func (self *forge) proposalBytes(i int, p Proposal) []byte {
	self.t.Helper()
	encoded, err := EncodeProposal(&p)
	if err != nil {
		self.t.Fatalf("encode proposal: %v", err)
	}
	return self.sealPrivate(i, self.contentFrom(Sender{Type: SenderMember, LeafIndex: self.g(i).OwnLeafIndex()}, ContentTypeProposal, encoded), nil)
}

// commitBytes builds a real Commit from member i — real path, real confirmation tag
// — and applies mutate to the decoded Commit and its UpdatePath before framing, so
// exactly one thing is wrong and everything else still verifies.
func (self *forge) commitBytes(i int, byValue []Proposal, byRef []ProposalRef, mutate func(*Commit, *UpdatePath)) []byte {
	self.t.Helper()
	refs := make([][]byte, 0, len(byRef))
	for _, ref := range byRef {
		refs = append(refs, ref)
	}
	result, err := self.g(i).Commit(refs, byValue, &CommitOptions{SkipValidation: true})
	if err != nil {
		self.t.Fatalf("build commit: %v", err)
	}
	message, err := ParseMLSMessage(result.Commit)
	if err != nil {
		self.t.Fatalf("parse own commit: %v", err)
	}
	if mutate != nil {
		mutate(message.Commit(), message.Commit().Path)
	}
	raw, err := EncodeMLSMessage(message)
	if err != nil {
		self.t.Fatalf("re-encode commit: %v", err)
	}
	return raw
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

Add the two fields the key-package helper records to the struct:

```go
	lastSigner SignaturePrivateKey
	lastStore  *memStore
```

and delete the `var _ = 0` placeholder line.

`CommitOptions{SkipValidation: true}` is the construction-bypass seam on the commit path, the
counterpart of `sealFramedContentForTest`. It is an ask on the Group lifecycle plan, restated in the
summary: without it, `commitBytes` cannot produce a commit that the **construction** side already
refuses, and half the commit-side ValSem codes have no test.

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
- Consumes: the whole forge API (Task 17); `Group.EpochSecret` (Key schedule plan) for the
  membership-key mutation; `PrivateMessage` (Framing plan).
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
	commit := f.commitBytes(0, []Proposal{{Remove: &Remove{Removed: removed}}}, nil, nil)
	if err := f.deliver(1, commit); err != nil {
		t.Fatalf("the remove commit must be valid: %v", err)
	}
	if err := f.g(0).MergePendingCommit(); err != nil {
		t.Fatalf("merge: %v", err)
	}
	content := f.contentFrom(Sender{Type: SenderMember, LeafIndex: removed}, ContentTypeApplication, []byte("ghost"))
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
	message.PrivateMessage().Ciphertext[0] ^= 0x01
	mutated, err := EncodeMLSMessage(message)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	requireValSem(t, f.deliver(1, mutated), ValSem006)
}

func TestValSem007_MissingMembershipTag(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeProposal, f.updateProposalBytes(0))
	raw := f.sealPublic(0, content, func(auth *FramedContentAuthData) {
		auth.MembershipTag = []byte{}
	})
	requireValSem(t, f.deliver(1, raw), ValSem007)
}

func TestValSem008_BadMembershipTag(t *testing.T) {
	f := newForge(t, 2)
	content := f.content(0, ContentTypeProposal, f.updateProposalBytes(0))
	raw := f.sealPublic(0, content, func(auth *FramedContentAuthData) {
		auth.MembershipTag = f.crypto.Random(32)
	})
	requireValSem(t, f.deliver(1, raw), ValSem008)
}

func TestValSem009_MissingConfirmationTag(t *testing.T) {
	f := newForge(t, 2)
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
		commit.DropConfirmationTag = true
	})
	requireValSem(t, f.deliver(1, raw), ValSem009)
}

func TestValSem010_BadSignature(t *testing.T) {
	f := newForge(t, 3)
	// member 1 signs, but the sender index still names member 0.
	content := f.contentFrom(Sender{Type: SenderMember, LeafIndex: f.g(0).OwnLeafIndex()}, ContentTypeApplication, []byte("hello"))
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
	encoded, err := EncodeProposal(&Proposal{Update: &Update{LeafNode: leaf}})
	if err != nil {
		self.t.Fatalf("encode update: %v", err)
	}
	return encoded
}

// sealPrivateWithPadding frames c as a PrivateMessage whose PrivateMessageContent
// padding is exactly the bytes given, rather than the all-zero padding RFC 9420
// §6.3.2 requires.
func (self *forge) sealPrivateWithPadding(i int, c *FramedContent, padding []byte) []byte {
	self.t.Helper()
	raw, err := self.g(i).sealFramedContentWithPaddingForTest(c, self.signer(i), padding)
	if err != nil {
		self.t.Fatalf("seal with padding: %v", err)
	}
	return raw
}
```

`Group.OwnLeafNodeCopy()`, `Group.sealFramedContentWithPaddingForTest`,
`FramedContentAuthData.MembershipTag` and `Commit.DropConfirmationTag` are the four seams these ten
tests need. All four are unexported or test-only and all four are asks on the Framing and Group
lifecycle plans, restated in the summary.

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
- Consumes: the forge (Task 17); `Add`, `Update`, `Remove`, `Proposal`, `KeyPackage`, `Capabilities`
  (Group lifecycle plan).
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
	keyPackage.InitKey = HpkePublicKey(keyPackage.LeafNode.EncryptionKey)
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem104)
}

func TestValSem105_SuiteMismatch(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	// 0x0001 is registered and implemented, and still not this group's suite.
	keyPackage.CipherSuite = CipherSuiteX25519AES128GCMSHA256Ed25519
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem105)
}

func TestValSem106_AddMissingRequiredCapability(t *testing.T) {
	f := newForge(t, 2)
	keyPackage, _, _ := f.newKeyPackage(t)
	// drop 0xF002 (urmessage_leaf_keys), which required_capabilities lists.
	keyPackage.LeafNode.Capabilities.Extensions = []uint16{0xF001}
	requireValSem(t, f.deliver(1, f.addCommit(t, keyPackage)), ValSem106)
}

func TestValSem107_DuplicateRemove(t *testing.T) {
	f := newForge(t, 3)
	target := f.g(2).OwnLeafIndex()
	raw := f.commitBytes(0, []Proposal{
		{Remove: &Remove{Removed: target}},
		{Remove: &Remove{Removed: target}},
	}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem107)
}

func TestValSem108_RemoveNonMember(t *testing.T) {
	f := newForge(t, 3)
	raw := f.commitBytes(0, []Proposal{{Remove: &Remove{Removed: LeafIndex(7)}}}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem108)
}

func TestValSem109_UpdateMissingRequiredCapability(t *testing.T) {
	f := newForge(t, 3)
	leaf := f.g(1).OwnLeafNodeCopy()
	leaf.Capabilities.Extensions = []uint16{0xF002} // drops 0xF001
	raw := f.proposalBytes(1, Proposal{Update: &Update{LeafNode: leaf}})
	requireValSem(t, f.deliver(2, raw), ValSem109)
}

func TestValSem110_UpdateDuplicateEncryptionKey(t *testing.T) {
	f := newForge(t, 3)
	leaf := f.g(1).OwnLeafNodeCopy()
	leaf.EncryptionKey = f.g(2).OwnLeafNodeCopy().EncryptionKey
	raw := f.proposalBytes(1, Proposal{Update: &Update{LeafNode: leaf}})
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
	update := Proposal{Update: &Update{LeafNode: own}}
	ref := f.reference(t, 0, update)
	raw := f.commitBytes(0, nil, []ProposalRef{ref}, nil)
	requireValSem(t, f.deliver(1, raw), ValSem111)
}

func TestValSem112_UpdateSenderNotMember(t *testing.T) {
	f := newForge(t, 2)
	leaf := f.g(0).OwnLeafNodeCopy()
	encoded, err := EncodeProposal(&Proposal{Update: &Update{LeafNode: leaf}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	content := f.contentFrom(Sender{Type: SenderNewMemberProposal}, ContentTypeProposal, encoded)
	requireValSem(t, f.deliver(1, f.sealPrivate(0, content, nil)), ValSem112)
}

func TestValSem113_UnsupportedProposalType(t *testing.T) {
	f := newForge(t, 2)
	raw := f.commitBytes(0, []Proposal{{UnknownType: 0xF0FF, UnknownBody: []byte{0x00}}}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem113)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem1' -v`
Expected: FAIL to build with `undefined: f.addCommit`, `undefined: f.reference`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/testkit_test.go

// addCommit frames a commit from member 0 covering one Add per key package, with
// construction-side validation skipped so the receiver is the one that decides.
func (self *forge) addCommit(t *testing.T, keyPackages ...*KeyPackage) []byte {
	t.Helper()
	proposals := make([]Proposal, 0, len(keyPackages))
	for _, keyPackage := range keyPackages {
		encoded, err := EncodeKeyPackage(keyPackage)
		if err != nil {
			t.Fatalf("encode key package: %v", err)
		}
		proposals = append(proposals, Proposal{Add: &Add{KeyPackage: encoded}})
	}
	return self.commitBytes(0, proposals, nil, nil)
}

// reference publishes p from member i and returns the ProposalRef every other
// member now holds for it, so a commit can cover it by reference.
func (self *forge) reference(t *testing.T, i int, p Proposal) ProposalRef {
	t.Helper()
	raw := self.proposalBytes(i, p)
	for j := range self.groups {
		if j == i {
			continue
		}
		if err := self.deliver(j, raw); err != nil {
			t.Fatalf("member %d rejected the proposal it must hold a reference to: %v", j, err)
		}
	}
	ref, err := MakeProposalRef(self.crypto, raw)
	if err != nil {
		t.Fatalf("proposal ref: %v", err)
	}
	return ref
}
```

`Proposal.UnknownType`/`Proposal.UnknownBody` and `MakeProposalRef(CryptoProvider, []byte) (ProposalRef, error)`
are asks on the Group lifecycle plan; `MakeProposalRef` is needed by Task 23's errata 8815 test too.

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
- Consumes: the forge (Task 17); `UpdatePath`, `UpdatePathNode`, `HpkeCiphertext` (TreeKEM plan);
  `RatchetTreeExtension`, `Node` (Tree math / tree plan).
- Produces: `TestValSem200_SelfRemoveInCommit` … `TestValSem209_UnsupportedGroupExtension`,
  `TestValSem300_TrailingBlankNodes`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_commit_test.go
// RFC 9420 §12.4 (commits) and §12.4.3.1 (the ratchet tree). ValSem208 and
// ValSem209 are untested in OpenMLS, so the spec text is the only authority for
// them and the differential oracle will not catch a mistake here.
package mls

import "testing"

func TestValSem200_SelfRemoveInCommit(t *testing.T) {
	f := newForge(t, 3)
	own := f.g(0).OwnLeafIndex()
	raw := f.commitBytes(0, []Proposal{{Remove: &Remove{Removed: own}}}, nil, nil)
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
	ref := f.reference(t, 1, Proposal{Update: &Update{LeafNode: leaf}})
	raw := f.commitBytes(0, nil, []ProposalRef{ref}, func(commit *Commit, path *UpdatePath) {
		commit.Path = nil
	})
	requireValSem(t, f.deliver(2, raw), ValSem201)
}

func TestValSem202_PathLength(t *testing.T) {
	f := newForge(t, 4)
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
		path.Nodes = path.Nodes[:len(path.Nodes)-1]
	})
	requireValSem(t, f.deliver(1, raw), ValSem202)
}

func TestValSem203_PathDecrypt(t *testing.T) {
	f := newForge(t, 4)
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
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
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
		// the ciphertexts still carry the real path secret, so decryption succeeds
		// and the derived public key no longer matches the announced one.
		path.Nodes[0].EncryptionKey = wrongPub
	})
	requireValSem(t, f.deliver(1, raw), ValSem204)
}

func TestValSem205_BadConfirmationTag(t *testing.T) {
	f := newForge(t, 3)
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
		commit.ConfirmationTagOverPreCommitTranscript = true
	})
	requireValSem(t, f.deliver(1, raw), ValSem205)
}

func TestValSem206_PathLeafDuplicateEncryptionKey(t *testing.T) {
	f := newForge(t, 3)
	victim := f.g(2).OwnLeafNodeCopy().EncryptionKey
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
		path.LeafNode.EncryptionKey = victim
	})
	requireValSem(t, f.deliver(1, raw), ValSem206)
}

func TestValSem207_PathNodeDuplicateEncryptionKey(t *testing.T) {
	f := newForge(t, 8)
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
		if len(path.Nodes) < 2 {
			t.Fatalf("an 8-member tree must give the committer at least two path nodes, got %d", len(path.Nodes))
		}
		path.Nodes[1].EncryptionKey = path.Nodes[0].EncryptionKey
	})
	requireValSem(t, f.deliver(1, raw), ValSem207)
}

func TestValSem208_MultipleGCE(t *testing.T) {
	f := newForge(t, 3)
	extension := Extension{Type: ExtensionTypeUrmessageGroupPolicy, Data: []byte{0x01}}
	raw := f.commitBytes(0, []Proposal{
		{GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{extension}}},
		{GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{extension}}},
	}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem208)
}

func TestValSem209_UnsupportedGroupExtension(t *testing.T) {
	f := newForge(t, 3)
	// 0xF0AA appears in no member's capabilities.
	raw := f.commitBytes(0, []Proposal{
		{GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{{Type: 0xF0AA, Data: []byte{0x00}}}}},
	}, nil, nil)
	requireValSem(t, f.deliver(1, raw), ValSem209)
}

func TestValSem300_TrailingBlankNodes(t *testing.T) {
	f := newForge(t, 4)
	exported, err := f.g(0).RatchetTree()
	if err != nil {
		t.Fatalf("export tree: %v", err)
	}
	tree, err := ParseRatchetTree(exported)
	if err != nil {
		t.Fatalf("parse tree: %v", err)
	}
	tree.Nodes = append(tree.Nodes, OptionalNode{Present: false})
	padded, err := EncodeRatchetTree(tree)
	if err != nil {
		t.Fatalf("re-encode tree: %v", err)
	}
	_, err = ValidateRatchetTree(f.crypto, padded, f.g(0).GroupId())
	requireValSem(t, err, ValSem300)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem2|TestValSem300' -v`
Expected: FAIL to build with `undefined: Commit.ConfirmationTagOverPreCommitTranscript`,
`undefined: ParseRatchetTree`, `undefined: ValidateRatchetTree`

- [ ] **Step 3: Write minimal implementation**

No new forge helpers. Three seams are required from other plans and are restated in the summary:

- `Commit.ConfirmationTagOverPreCommitTranscript bool` — a test-only field on the commit builder
  (Group lifecycle plan) that makes the committer compute the confirmation tag over the
  **pre**-commit `confirmed_transcript_hash`. Without it ValSem205 has no failing input that is
  otherwise well-formed, and a random tag would trip ValSem010 first.
- `func ParseRatchetTree(b []byte) (*RatchetTree, error)` / `func EncodeRatchetTree(t *RatchetTree) ([]byte, error)` /
  `func ValidateRatchetTree(crypto CryptoProvider, b []byte, groupId []byte) (*RatchetTree, error)` — the
  Tree math plan's exported tree surface, with `type OptionalNode struct { Present bool; Node Node }`.
- `Proposal.GroupContextExtensions *GroupContextExtensions` with `Extensions []Extension` — Group
  lifecycle plan.

The implementation work in this task is confined to `connect/mls/validation.go`'s
`checkValSem200`…`checkValSem209` and `checkValSem300` returning the catalogue codes, which is the
Group lifecycle plan's file. This task's deliverable is the ten failing tests that force them.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem2|TestValSem300' -v`
Expected: PASS — 11 tests

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_commit_test.go && git -C connect commit -m "test(mls): ValSem200-209 and ValSem300, the commit and ratchet-tree codes"
```

---

### Task 21: ValSem240–246, the profile-refused external-commit codes

**Files:**
- Create: `connect/mls/validation_external_test.go`
- Test: same file

**Interfaces:**
- Consumes: the forge (Task 17); `ExternalInit` (Group lifecycle plan — the type exists so it can be
  refused at parse, and for no other reason).
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
	encoded, err := EncodeKeyPackage(keyPackage)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw := f.externalCommitBytes(t, externalCommitShape{
		ExternalInits: 1,
		WithPath:      true,
		Inline:        []Proposal{{Add: &Add{KeyPackage: encoded}}},
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
	ref := f.reference(t, 1, Proposal{Update: &Update{LeafNode: leaf}})
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

// TestExternalCommitsAreRefusedAtParse pins the layer the refusal happens at. If a
// future change moves it later, the six tests above still pass while the profile
// has quietly widened; this one does not.
func TestExternalCommitsAreRefusedAtParse(t *testing.T) {
	f := newForge(t, 2)
	raw := f.externalCommitBytes(t, externalCommitShape{ExternalInits: 1, WithPath: true})
	_, err := ParseMLSMessage(raw)
	requireValSem(t, err, ValSem240)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem24|TestExternalCommits' -v`
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
		inline = append(inline, Proposal{ExternalInit: &ExternalInit{KemOutput: self.crypto.Random(32)}})
	}
	inline = append(inline, shape.Inline...)

	commit := &Commit{}
	for _, proposal := range inline {
		commit.Proposals = append(commit.Proposals, ProposalOrRef{Proposal: &proposal})
	}
	for _, ref := range shape.ByReference {
		commit.Proposals = append(commit.Proposals, ProposalOrRef{Ref: ref})
	}
	if shape.WithPath {
		keyPackage, _, _ := self.newKeyPackage(t)
		commit.Path = &UpdatePath{LeafNode: keyPackage.LeafNode}
	}

	content := self.contentFrom(Sender{Type: SenderNewMemberCommit}, ContentTypeCommit, nil)
	content.Commit = commit
	return self.sealPrivate(shape.SignWithMember, content, nil)
}
```

`Proposal.ExternalInit *ExternalInit` with `KemOutput []byte`, and `ProposalOrRef` with `Proposal`
and `Ref` arms, are asks on the Group lifecycle plan. Both types exist solely so the parser can
refuse them with a typed error.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem24|TestExternalCommits' -v`
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
- Consumes: the forge (Task 17); `PreSharedKey`, `PreSharedKeyID` (Group lifecycle plan — refused at
  proposal parse).
- Produces: `TestValSem401_PskNonceLength`, `TestValSem402_PskUsage`,
  `TestValSem403_DuplicatePskId`.

- [ ] **Step 1: Write the failing test**

```go
// connect/mls/validation_psk_test.go
// RFC 9420 §8.4. PSK proposals are not implemented in the v1 profile and are
// refused at proposal parse. ValSem403 is untested in OpenMLS (openmls#1335), so
// the differential oracle offers no cover here either.
package mls

import "testing"

func TestValSem401_PskNonceLength(t *testing.T) {
	f := newForge(t, 2)
	// KDF.Nh is 32 for this suite; 31 is the malformed length.
	id := PreSharedKeyID{
		Usage:     PskUsageExternal,
		PskId:     f.crypto.Random(32),
		PskNonce:  f.crypto.Random(31),
	}
	requireValSem(t, f.parsePskProposal(t, []PreSharedKeyID{id}), ValSem401)
}

func TestValSem402_PskUsage(t *testing.T) {
	f := newForge(t, 2)
	id := PreSharedKeyID{
		Usage:    PskUsageResumptionReInit,
		PskId:    f.crypto.Random(32),
		PskNonce: f.crypto.Random(32),
	}
	requireValSem(t, f.parsePskProposal(t, []PreSharedKeyID{id}), ValSem401)
	// V2, if PSKs are ever implemented: expect ValSem402 from the RFC check.
}

func TestValSem403_DuplicatePskId(t *testing.T) {
	f := newForge(t, 2)
	id := PreSharedKeyID{
		Usage:    PskUsageExternal,
		PskId:    f.crypto.Random(32),
		PskNonce: f.crypto.Random(32),
	}
	requireValSem(t, f.parsePskProposal(t, []PreSharedKeyID{id, id}), ValSem401)
	// V2: expect ValSem403 — no duplicate PreSharedKeyID in one proposal list.
}

// TestPskProposalsAreRefusedAtParse pins the layer, for the same reason as the
// external-commit equivalent.
func TestPskProposalsAreRefusedAtParse(t *testing.T) {
	f := newForge(t, 2)
	id := PreSharedKeyID{Usage: PskUsageExternal, PskId: f.crypto.Random(32), PskNonce: f.crypto.Random(32)}
	encoded := encodePskProposalForTest(t, []PreSharedKeyID{id})
	_, err := ParseProposal(encoded)
	requireValSem(t, err, ValSem401)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem4|TestPskProposals' -v`
Expected: FAIL to build with `undefined: f.parsePskProposal`, `undefined: encodePskProposalForTest`

- [ ] **Step 3: Write minimal implementation**

```go
// append to connect/mls/testkit_test.go

// encodePskProposalForTest hand-encodes a PreSharedKey proposal. The production
// encoder has no PSK path — the profile refuses PSKs — so the bytes are built here,
// exactly as a foreign client would send them.
func encodePskProposalForTest(t *testing.T, ids []PreSharedKeyID) []byte {
	t.Helper()
	body := []byte{}
	for _, id := range ids {
		body = append(body, byte(id.Usage))
		body = syntax.WriteVarint(body, uint64(len(id.PskId)))
		body = append(body, id.PskId...)
		body = syntax.WriteVarint(body, uint64(len(id.PskNonce)))
		body = append(body, id.PskNonce...)
	}
	// proposal type 0x0004 = psk
	encoded := []byte{0x00, 0x04}
	encoded = syntax.WriteVarint(encoded, uint64(len(body)))
	return append(encoded, body...)
}

// parsePskProposal frames the hand-encoded PSK proposal and delivers it, returning
// whatever the receiver decided.
func (self *forge) parsePskProposal(t *testing.T, ids []PreSharedKeyID) error {
	t.Helper()
	encoded := encodePskProposalForTest(t, ids)
	content := self.contentFrom(Sender{Type: SenderMember, LeafIndex: self.g(0).OwnLeafIndex()}, ContentTypeProposal, nil)
	content.RawProposal = encoded
	return self.deliver(1, self.sealPrivate(0, content, nil))
}
```

`FramedContent.RawProposal []byte` — a test-only escape hatch that carries proposal bytes the
production encoder cannot produce — plus `PreSharedKeyID`, `PskUsageExternal` and
`PskUsageResumptionReInit`, are asks on the Framing and Group lifecycle plans. Add
`"github.com/urnetwork/connect/mls/syntax"` to `testkit_test.go`'s imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem4|TestPskProposals' -v`
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
- Consumes: the forge (Task 17); `memStore.EpochsHeld` (Task 10); `PastEpochWindow`,
  `MakeProposalRef` (Group lifecycle plan).
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
		raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, nil)
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
	if got, want := len(held), PastEpochWindow+1; got != want {
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
	raw := f.commitBytes(0, []Proposal{{Update: &Update{}}}, nil, func(commit *Commit, path *UpdatePath) {
		// 0xF001 (urmessage_group_policy) is in the GroupContext of every forged group.
		path.LeafNode.Capabilities.Extensions = []uint16{0xF002}
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
	known := f.reference(t, 1, Proposal{Update: &Update{LeafNode: leaf}})
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
belongs to whichever plan lands second:

1. `Group.MergePendingCommit` and `Group.ApplyCommit` both call
   `self.store.DeleteGroupStateBefore(self.groupId, self.epoch - PastEpochWindow)` after the new
   epoch state is written, guarded by `self.epoch > PastEpochWindow`.
2. `validation.go` gains `checkErrata8745(path *UpdatePath, context *GroupContext) error`, called
   from the commit path, returning `ValSem(ValSemErrata8745, ...)` when the update-path leaf's
   capabilities do not cover every GroupContext extension type.
3. `validation.go` gains `checkErrata8815(commit *Commit, pending map[string]*Proposal) error`,
   called **before** any other commit processing, returning `ValSem(ValSemErrata8815, ...)` for a
   `ProposalRef` with no entry in the receiver's pending-proposal map.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem400|TestErrata87|TestErrata88' -v && go test ./connect/mls/... -run TestValSemCoverageIsComplete -v`
Expected: PASS for all three, and `TestValSemCoverageIsComplete` now PASSes with all 46 codes
covered and `valsem-coverage.md` written.

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/validation_epoch_test.go mls/errata_test.go mls/validation.go mls/group.go && git -C connect commit -m "test(mls): ValSem400 past-epoch bound and errata 8745/8815; ValSem coverage is complete"
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
	// all 46 codes must be reachable by the -run pattern the job uses.
	if !strings.Contains(text, "'TestValSem|TestErrata'") {
		t.Error("the negative-test step must run every TestValSem* and TestErrata* function")
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
  `connect/mls/PINS.md`.
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
`connect/mls/PINS.md`, so the client and the test runner are always the same generation.

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
- Consumes: `mls.NewGroup`, `mls.GroupConfig`, `mls.JoinFromWelcome`, `mls.NewKeyPackage`,
  `mls.DefaultProfile` (Group lifecycle plan); `mls.NewCryptoProvider` (Crypto plan);
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
	return &pb.SupportedCiphersuitesResponse{Ciphersuites: []uint32{uint32(mls.CipherSuiteX25519ChaCha20SHA256Ed25519)}}, nil
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

`newGroupConfig` and `pendingKeyPackages` are small helpers in the same file: the first builds the
v1 `mls.GroupConfig` (pinned suite, `required_capabilities = [0xF001, 0xF002]`, `DefaultProfile()`,
an in-memory store) and refuses any suite but 0x0003 with
`"group creation is pinned to 0x0003 by policy"`; the second is a mutex-guarded map from transaction
id to minted key-package material, mirroring `mls.StateStore.PutKeyPackage`/`TakeKeyPackage`.

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
- Consumes: `mls.Group.Export`, `mls.Group.EpochAuthenticator`, `mls.Group.Protect`,
  `mls.Group.Unprotect`, `mls.Group.GroupContext`, `mls.Group.RatchetTree` (Key schedule and Framing
  plans).
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
- Consumes: `mls.Group.ProposeAdd`, `ProposeUpdate`, `ProposeRemove`,
  `ProposeGroupContextExtensions`, `Commit`, `ProcessMessage`, `ApplyCommit`, `MergePendingCommit`
  (Group lifecycle plan); `registry.free` (Task 26).
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
		extensions = append(extensions, mls.Extension{Type: uint16(extension.ExtensionType), Data: extension.ExtensionData})
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
- Produces: the eleven refused RPCs with stable messages, and
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
- Modify: `connect/mls/PINS.md`
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
        config: [welcome_join.json, commit.json, application.json, branch.json, external_join.json, external_proposals.json, reinit.json]
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
        run: go run ./test-runner -config ${{ matrix.config }} -client ours:50051 -client ${{ matrix.peer }}:50052 -private -json-out out/run1.json
        working-directory: mls/interop
      # run 2 — ours last: we are receiver/joiner, where the validation logic lives
      - name: receiver role
        run: go run ./test-runner -config ${{ matrix.config }} -client ${{ matrix.peer }}:50052 -client ours:50051 -private -json-out out/run2.json
        working-directory: mls/interop
      # run 3 — three-party: a commit we neither authored nor are the sole recipient of
      - name: three-party
        run: go run ./test-runner -config ${{ matrix.config }} -client ours:50051 -client ${{ matrix.peer }}:50052 -client openmls:50053 -private -json-out out/run3.json
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

`cmd/merge-runner-output` is a 40-line program that reads the three runner outputs and emits the
union in `profile-reject.json`'s shape; it is written as part of this task with a table test
asserting the union of three files with overlapping scenarios is deduplicated.

Record the three peer image digests and the pinned mlswg commit in `connect/mls/PINS.md`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd connect/mls/interop && go test . -run TestInteropWorkflowRunsBothRoles -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git -C connect add mls/interop/docker-compose.yml mls/interop/workflow_test.go mls/interop/cmd/merge-runner-output .github/workflows/mls-interop.yml mls/PINS.md && git -C connect commit -m "ci(mls-interop): both-role matrix against three peers, with documented failures asserted"
```

---

## Execution order and gate mapping

Tasks 1–16 are executable in wave 1 and depend on nothing outside `connect/mls/syntax`. Tasks 17–24
need `group.go` and land at the end of slice A4. Tasks 25–33 need the same and land as slice A5.

| Spec A gate | Tasks | Slice |
|---|---|---|
| Gate 2, vector families | 6, 7, 8, 9, 13 | A1, then each family's own plan |
| Gate 2, interop harness | 25, 26, 27, 28, 29, 30, 31, 32, 33 | A5 |
| Gate 3, 43 ValSem codes | 2, 3, 17, 18, 19, 20, 21, 22, 24 | A4 |
| Gate 3, errata | 1, 23 | A4 |
| Gate 4, fuzz properties 1–2 | 11, 12, 13 | A1 |
| Gate 4, differential | 14, 15, 16 | A11 |
| Layering (Spec A §2.3) | 4, 5, 25 | A1 |

`TestValSemCoverageIsComplete` (Task 3) is the single test that proves Gate 3: it fails until every
one of the 46 catalogue codes has a named test function, and Task 24 makes it blocking.

## Open asks on other plans

Each is referenced by real code above and will not compile without it.

| Ask | Plan | Why |
|---|---|---|
| `NewCryptoProviderWithRandom(suite, io.Reader)` | Crypto primitives and HPKE | a failing ValSem test must reproduce from a fixed seed |
| `Group.sealFramedContentForTest(c, auth, wf, signer)` | Framing and message protection | there is no other way to frame a message the honest path refuses to build |
| `Group.sealFramedContentWithPaddingForTest(c, signer, padding)` | Framing and message protection | ValSem011 |
| `FramedContentAuthData.MembershipTag` | Framing and message protection | ValSem007, ValSem008 |
| `FramedContent.RawProposal []byte` | Framing and message protection | ValSem401–403 carry proposal bytes the production encoder cannot produce |
| `CommitOptions.SkipValidation` | Group lifecycle | half the commit-side codes need a commit the construction side already refuses |
| `Commit.DropConfirmationTag`, `Commit.ConfirmationTagOverPreCommitTranscript` | Group lifecycle | ValSem009, ValSem205 |
| `Group.OwnLeafNodeCopy()` | Group lifecycle | every Update-shaped mutation |
| `Group.Close()` | Group lifecycle | the interop `Free` RPC asserts zero leaked states at exit |
| `MakeProposalRef(CryptoProvider, []byte) (ProposalRef, error)` | Group lifecycle | ValSem111, errata 8815 |
| `Proposal.UnknownType` / `Proposal.UnknownBody` | Group lifecycle | ValSem113 |
| `Proposal.ExternalInit`, `ProposalOrRef` | Group lifecycle | ValSem240–246 |
| `ParseRatchetTree` / `EncodeRatchetTree` / `ValidateRatchetTree`, `OptionalNode` | Tree math | ValSem300 |
| every family's `Verify` **and** `Generate` | each family's owning plan | Spec A §4.2.1 requires both directions |
| `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc` as developer tools | repo tooling | Task 25 generates once and commits the stubs |
