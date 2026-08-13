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

- Go 1.26.5, pinned. `connect/go.mod` says `go 1.26.3` today and MUST be bumped to `1.26.5` by the
  wave-1 codec plan; this plan assumes it is already done.
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
  `framing_protect.go`; Task 18 enforces it with a test rather than a shell grep.
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

### The codec/profile split (a decision this plan makes, because two gates disagree without it)

Spec A §3.2 says PSK proposals are refused with `ErrProfilePSK` "at proposal parse". The `messages`
vector family requires `pre_shared_key_proposal`, `re_init_proposal` and `external_init_proposal` to
**decode successfully and re-encode byte-exactly**. Both cannot be true of one function.

Resolution, carried by every task below:

- `Proposal.UnmarshalMLS` / `MarshalMLS` (this plan, `proposal_types.go`) are **pure codec**. They
  accept all seven registered proposal types and any unknown 16-bit type as an opaque body. They
  never consult the profile.
- `ParseProposal` (the wave-4 proposals plan, `proposal.go`) is the **profile gate** and is where
  `ErrProfilePSK`, `ErrProfileReInit` and `ErrProfileExternalCommit` surface. ValSem401–403 test that
  function, not the codec.
- Nothing outside `proposal_types.go` and the vector harness calls the codec directly; `group.go`
  goes through `ParseProposal`.

---

## File Structure

| File | Single responsibility |
|---|---|
| `connect/mls/framing.go` | RFC 9420 §6 wire types and their codecs: `ProtocolVersion`, `WireFormat`, `ContentType`, `SenderType`, `Sender`, `FramedContent`, `FramedContentAuthData`, `AuthenticatedContent`, `PublicMessage`, `PrivateMessage`, `MLSMessage`. No crypto. |
| `connect/mls/framing_preimage.go` | The three authenticated byte strings and nothing else: `FramedContentTBSBytes`, `AuthenticatedContentTBMBytes`, `(*AuthenticatedContent).ConfirmedTranscriptHashInput`. Isolated so a preimage change is a one-file diff an auditor can read. |
| `connect/mls/framing_protect.go` | Sign/verify, membership tag, sender-data seal/open, `PrivateMessageContent` with padding, content encrypt/decrypt, the `MessageKeySource` and `SignatureKeyResolver` contracts, and the four `Seal*`/`Open*` entry points. |
| `connect/mls/errors_framing.go` | Typed errors for framing, one per ValSem code plus the structural ones. Separate from `errors.go` so this plan and the wave-1 validation plan never edit the same file. |
| `connect/mls/proposal_types.go` | `ProposalType`, `Proposal` and its seven arms, `ProposalOrRefType`, `ProposalRef`, `ProposalOrRef` — codec only, no validation. |
| `connect/mls/commit_types.go` | `Commit` — codec only, no application logic. |
| `connect/mls/framing_test.go` | Unit tests for `framing.go` and `framing_preimage.go`. |
| `connect/mls/framing_protect_test.go` | Unit tests for `framing_protect.go`, including the fixed-key `MessageKeySource` stub. |
| `connect/mls/proposal_types_test.go` | Round-trip and width tests for the proposal codec. |
| `connect/mls/commit_types_test.go` | Round-trip tests for the commit codec. |
| `connect/mls/validation_framing_test.go` | `TestValSem002`…`TestValSem011`, one top-level func per code, plus the roster completeness test. |
| `connect/mls/message_protection_kat_test.go` | Vector family 4, verify direction and generate direction. |
| `connect/mls/messages_kat_test.go` | Vector family 12, decode/re-encode for every field. |
| `connect/mls/framing_fuzz_test.go` | `FuzzMlsMessageDecode`, `FuzzMlsMessageDecodeBytes`, `FuzzProposalDecode`, `FuzzProposalDecodeBytes` — Gate 4 properties 1 and 2. |
| `connect/mls/vectors_hex_test.go` | `hexBytes`, the shared JSON hex-decoding helper for every vector harness in `package mls`. |
| `connect/mls/testdata/vectors/message-protection.json` | Vendored, pinned (wave-1 validation plan vendors the directory; this plan asserts the file is present). |
| `connect/mls/testdata/vectors/messages.json` | Same. |

**Deviation from Spec A §2.2, stated deliberately:** Spec A lists `framing.go` as one file and puts
`Proposal`/`Commit` in `proposal.go`/`commit.go`. This plan splits framing across three files
(types / preimages / protection) and puts the proposal and commit **wire types** in
`proposal_types.go` and `commit_types.go`, leaving `proposal.go` (list validation) and `commit.go`
(commit application) entirely to the wave-4 plan. Reason: the `messages` gate is this plan's, and it
cannot be green without a byte-exact `Proposal` and `Commit` codec; two plans editing one file in
parallel is the failure mode this split exists to avoid. All files are `package mls`, so there is no
import edge and no cycle.

---

## Interfaces consumed from other plans

Every symbol below is `package mls` unless a package is named. If a signature here does not match
what the other plan shipped, fix the call site — do not add an adapter layer.

**From "Syntax and codec" (wave 1), package `github.com/urnetwork/connect/mls/syntax`:**

```go
type Writer struct{ /* ... */ }
func NewWriter() *Writer
func (self *Writer) WriteUint8(v uint8)
func (self *Writer) WriteUint16(v uint16)
func (self *Writer) WriteUint32(v uint32)
func (self *Writer) WriteUint64(v uint64)
func (self *Writer) WriteRaw(b []byte)                    // fixed-length, no length prefix
func (self *Writer) WriteOpaque(b []byte) error           // opaque V<> — MLS varint length prefix
func (self *Writer) WriteVector(n int, each func(w *Writer, i int) error) error
func (self *Writer) Bytes() []byte

type Reader struct{ /* ... */ }
func NewReader(data []byte) *Reader
func (self *Reader) ReadUint8() (uint8, error)
func (self *Reader) ReadUint16() (uint16, error)
func (self *Reader) ReadUint32() (uint32, error)
func (self *Reader) ReadUint64() (uint64, error)
func (self *Reader) ReadRaw(n int) ([]byte, error)
func (self *Reader) ReadOpaque() ([]byte, error)          // rejects a non-minimal length prefix
func (self *Reader) ReadVector(each func(r *Reader) error) error
func (self *Reader) Rest() []byte                         // remaining bytes, no prefix consumed
func (self *Reader) Remaining() int
func (self *Reader) Finish() error                        // errors unless fully consumed

var ErrTruncated error
var ErrNonMinimalLength error
var ErrTrailingBytes error
```

`WriteVector` writes the MLS variable-length byte count then each element; `ReadVector` reads the
byte count, bounds a sub-reader to exactly that many bytes, calls `each` until the sub-reader is
empty, and errors on a partial trailing element.

**From "Crypto primitives and HPKE" (wave 1):** `CryptoProvider` exactly as Spec A §3.3, plus

```go
type SignaturePrivateKey []byte
type SignaturePublicKey []byte
type CipherSuite uint16
const CipherSuiteX25519ChaCha20SHA256Ed25519 CipherSuite = 0x0003
func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)
```

Used here: `HashSize`, `KeySize`, `NonceSize`, `Mac`, `MacVerify`, `ExpandWithLabel`, `AeadSeal`,
`AeadOpen`, `SignWithLabel`, `VerifyWithLabel`, `Random`.

**From "Tree math" (wave 1):** `type LeafIndex uint32`.

**From "Key schedule and secret tree" (wave 2):** a `*SecretTree` that satisfies this plan's
`MessageKeySource` interface (Task 11) with exactly these three methods:

```go
func (self *SecretTree) NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
func (self *SecretTree) MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
func (self *SecretTree) EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
```

`ContentTypeApplication` selects the application ratchet; `ContentTypeProposal` and
`ContentTypeCommit` select the handshake ratchet. The secret tree owns the skipped-key window.

**From the tree / leaf-node / key-package plans (waves 1–2), each with
`MarshalMLS(w *syntax.Writer) error` and `UnmarshalMLS(r *syntax.Reader) error`:** `KeyPackage`,
`LeafNode`, `UpdatePath`, `Extension`, `PreSharedKeyID`, `Node`.

**From the key-schedule / group-lifecycle plans, same two methods:** `Welcome`, `GroupInfo`,
`GroupSecrets`.

**Not consumed:** `GroupContext`. Every function in this plan takes the GroupContext as
**already-serialized bytes** (`groupContext []byte`, matching `(*Group).GroupContext() ([]byte, error)`
in Spec A §3.3). This is deliberate: the GroupContext is inlined into `FramedContentTBS` with **no
length prefix**, and taking bytes makes that impossible to get wrong by accident and removes a
cross-plan type dependency from the hottest preimage in the system.

---

## Interfaces produced for other plans

```go
// framing.go
type ProtocolVersion uint16
const ProtocolVersionMLS10 ProtocolVersion = 0x0001

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

type PublicMessage struct {
    Content       FramedContent
    Auth          FramedContentAuthData
    MembershipTag []byte
}
func (self *PublicMessage) MarshalMLS(w *syntax.Writer) error
func (self *PublicMessage) UnmarshalMLS(r *syntax.Reader) error
func (self *PublicMessage) AuthenticatedContent() *AuthenticatedContent

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

// framing_preimage.go
func FramedContentTBSBytes(wireFormat WireFormat, content *FramedContent, groupContext []byte) ([]byte, error)
func AuthenticatedContentTBMBytes(authContent *AuthenticatedContent, groupContext []byte) ([]byte, error)
func (self *AuthenticatedContent) ConfirmedTranscriptHashInput() ([]byte, error)

// framing_protect.go
type MessageKeySource interface {
    NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
    MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
    EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
}

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

// proposal_types.go
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

type Add struct{ KeyPackage KeyPackage }
type Update struct{ LeafNode LeafNode }
type Remove struct{ Removed LeafIndex }
type PreSharedKey struct{ PSK PreSharedKeyID }
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
    UnknownBody            []byte
}
func (self *Proposal) MarshalMLS(w *syntax.Writer) error
func (self *Proposal) UnmarshalMLS(r *syntax.Reader) error

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

// commit_types.go
type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}
func (self *Commit) MarshalMLS(w *syntax.Writer) error
func (self *Commit) UnmarshalMLS(r *syntax.Reader) error
```

---

### Task 1: Framing enums, `Sender` codec and the framing error set

**Files:**
- Create: `connect/mls/framing.go`
- Create: `connect/mls/errors_framing.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: `syntax.NewWriter() *syntax.Writer`, `(*syntax.Writer).WriteUint8`, `WriteUint32`,
  `Bytes`; `syntax.NewReader([]byte) *syntax.Reader`, `(*syntax.Reader).ReadUint8`, `ReadUint32`,
  `Finish`; `type LeafIndex uint32` (tree math, wave 1).
- Produces: `ProtocolVersion`, `ProtocolVersionMLS10`, `WireFormat` and its six constants,
  `ContentType` and its four constants, `SenderType` and its five constants,
  `Sender`, `(*Sender).MarshalMLS(w *syntax.Writer) error`,
  `(*Sender).UnmarshalMLS(r *syntax.Reader) error`, and the error variables
  `ErrUnknownWireFormat`, `ErrUnsupportedVersion`, `ErrUnknownContentType`, `ErrUnknownSenderType`,
  `ErrContentArmMismatch`, `ErrMissingGroupContext`, `ErrUnexpectedGroupContext`,
  `ErrWireFormatMismatch`, `ErrSenderNotMember`, `ErrInvalidPaddingSize`, `ErrWrongGroupId`,
  `ErrWrongEpoch`, `ErrBlankSenderLeaf`, `ErrApplicationMustBeCiphertext`, `ErrDecryptFailed`,
  `ErrMissingMembershipTag`, `ErrBadMembershipTag`, `ErrMissingConfirmationTag`, `ErrBadSignature`,
  `ErrNonZeroPadding`.

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
        w := syntax.NewWriter()
        if err := c.sender.MarshalMLS(w); err != nil {
            t.Fatalf("%s: marshal: %v", c.name, err)
        }
        if !bytes.Equal(w.Bytes(), c.encoded) {
            t.Fatalf("%s: encoded %x, want %x", c.name, w.Bytes(), c.encoded)
        }
        var decoded Sender
        r := syntax.NewReader(c.encoded)
        if err := decoded.UnmarshalMLS(r); err != nil {
            t.Fatalf("%s: unmarshal: %v", c.name, err)
        }
        if err := r.Finish(); err != nil {
            t.Fatalf("%s: trailing bytes: %v", c.name, err)
        }
        if decoded != c.sender {
            t.Fatalf("%s: decoded %+v, want %+v", c.name, decoded, c.sender)
        }
    }
}

func TestSenderRejectsReservedAndUnknownType(t *testing.T) {
    for _, encoded := range [][]byte{{0x00}, {0x05}, {0xff}} {
        var decoded Sender
        err := decoded.UnmarshalMLS(syntax.NewReader(encoded))
        if !errors.Is(err, ErrUnknownSenderType) {
            t.Fatalf("sender_type %x: got %v, want ErrUnknownSenderType", encoded, err)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestSender' -v`
Expected: FAIL — `undefined: Sender`, `undefined: SenderTypeMember`, `undefined: ErrUnknownSenderType`.

- [ ] **Step 3: Write minimal implementation**

```go
// errors_framing.go
// typed errors for RFC 9420 §6 framing. one variable per ValSem code plus the
// structural failures the codec can produce. kept out of errors.go so the
// framing plan and the validation plan never edit the same file.
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

    ErrWrongGroupId                = errors.New("mls: ValSem002 group id mismatch")
    ErrWrongEpoch                  = errors.New("mls: ValSem003 epoch mismatch")
    ErrBlankSenderLeaf             = errors.New("mls: ValSem004 sender leaf is blank")
    ErrApplicationMustBeCiphertext = errors.New("mls: ValSem005 application message must be a PrivateMessage")
    ErrDecryptFailed               = errors.New("mls: ValSem006 message decryption failed")
    ErrMissingMembershipTag        = errors.New("mls: ValSem007 membership tag missing")
    ErrBadMembershipTag            = errors.New("mls: ValSem008 membership tag does not verify")
    ErrMissingConfirmationTag      = errors.New("mls: ValSem009 confirmation tag missing")
    ErrBadSignature                = errors.New("mls: ValSem010 signature does not verify")
    ErrNonZeroPadding              = errors.New("mls: ValSem011 PrivateMessageContent padding is not all zero")
)
```

```go
// framing.go
// RFC 9420 §6 message framing wire types and their codecs. no crypto lives
// here: the signed and MACed byte strings are framing_preimage.go and the
// sealing operations are framing_protect.go.
package mls

import (
    "fmt"

    "github.com/urnetwork/connect/mls/syntax"
)

// the only protocol version this implementation speaks.
type ProtocolVersion uint16

const ProtocolVersionMLS10 ProtocolVersion = 0x0001

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestSender' -v`
Expected: PASS — `TestSenderRoundTrip` and `TestSenderRejectsReservedAndUnknownType`.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l   # record this number; compare after `git add`
git add mls/framing.go mls/errors_framing.go mls/framing_test.go
git ls-files | wc -l   # MUST be the previous number + 3
git commit -m "feat(mls): framing enums, Sender codec and the framing error set"
```

---

### Task 2: `FramedContent` codec

**Files:**
- Modify: `connect/mls/framing.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: Task 1's `Sender`, `ContentType`; `(*syntax.Writer).WriteOpaque`,
  `(*syntax.Reader).ReadOpaque`; `Proposal` and `Commit` from Tasks 12 and 13 — **implement those
  two tasks first if the codec does not yet exist**, or stub `Proposal`/`Commit` only if Task 12/13
  have not been merged, in which case this task is blocked, not stubbed.
- Produces: `FramedContent`, `(*FramedContent).MarshalMLS(w *syntax.Writer) error`,
  `(*FramedContent).UnmarshalMLS(r *syntax.Reader) error`.

> **Ordering note:** Tasks 12 and 13 (`proposal_types.go`, `commit_types.go`) are listed later
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
    w := syntax.NewWriter()
    if err := content.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    encoded := w.Bytes()

    var decoded FramedContent
    r := syntax.NewReader(encoded)
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }

    w2 := syntax.NewWriter()
    if err := decoded.MarshalMLS(w2); err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, w2.Bytes()) {
        t.Fatalf("re-encoded %x, want %x", w2.Bytes(), encoded)
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
    w := syntax.NewWriter()
    if err := content.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded FramedContent
    r := syntax.NewReader(w.Bytes())
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
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
    err := content.MarshalMLS(syntax.NewWriter())
    if !errors.Is(err, ErrContentArmMismatch) {
        t.Fatalf("got %v, want ErrContentArmMismatch", err)
    }
}

func TestFramedContentRejectsUnknownContentType(t *testing.T) {
    content := FramedContent{
        GroupId:     []byte{0x01},
        Sender:      Sender{SenderType: SenderTypeMember},
        ContentType: ContentType(9),
    }
    err := content.MarshalMLS(syntax.NewWriter())
    if !errors.Is(err, ErrUnknownContentType) {
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
    if err := w.WriteOpaque(self.GroupId); err != nil {
        return err
    }
    w.WriteUint64(self.Epoch)
    if err := self.Sender.MarshalMLS(w); err != nil {
        return err
    }
    if err := w.WriteOpaque(self.AuthenticatedData); err != nil {
        return err
    }
    w.WriteUint8(uint8(self.ContentType))
    switch self.ContentType {
    case ContentTypeApplication:
        return w.WriteOpaque(self.ApplicationData)
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
- Consumes: Task 1's `ContentType`, `ErrMissingConfirmationTag`; `syntax` writer/reader opaque
  methods.
- Produces: `FramedContentAuthData`,
  `(*FramedContentAuthData).MarshalMLS(w *syntax.Writer, contentType ContentType) error`,
  `(*FramedContentAuthData).UnmarshalMLS(r *syntax.Reader, contentType ContentType) error`.

The content type is a **parameter**, not a struct field: `FramedContentAuthData` is a `select()` on
the enclosing `FramedContent.content_type` and carries no discriminant of its own on the wire.
Storing a copy in the struct would let the two disagree.

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
        want := []byte{0x03, 0x11, 0x22, 0x33} // opaque<V> length 3 encodes as one byte 0x03
        if !bytes.Equal(w.Bytes(), want) {
            t.Fatalf("contentType %d: encoded %x, want %x", contentType, w.Bytes(), want)
        }
        var decoded FramedContentAuthData
        r := syntax.NewReader(w.Bytes())
        if err := decoded.UnmarshalMLS(r, contentType); err != nil {
            t.Fatalf("contentType %d: unmarshal: %v", contentType, err)
        }
        if err := r.Finish(); err != nil {
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
    want := []byte{0x03, 0x11, 0x22, 0x33, 0x02, 0x44, 0x55}
    if !bytes.Equal(w.Bytes(), want) {
        t.Fatalf("commit encoded %x, want %x", w.Bytes(), want)
    }
    var decoded FramedContentAuthData
    r := syntax.NewReader(w.Bytes())
    if err := decoded.UnmarshalMLS(r, ContentTypeCommit); err != nil {
        t.Fatalf("commit unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
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
    if err := w.WriteOpaque(self.Signature); err != nil {
        return err
    }
    switch contentType {
    case ContentTypeCommit:
        if len(self.ConfirmationTag) == 0 {
            return ErrMissingConfirmationTag
        }
        return w.WriteOpaque(self.ConfirmationTag)
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
            return ErrMissingConfirmationTag
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

### Task 4: `AuthenticatedContent` codec and the transcript-hash input

**Files:**
- Modify: `connect/mls/framing.go`
- Create: `connect/mls/framing_preimage.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `AuthenticatedContent`, `(*AuthenticatedContent).MarshalMLS(w *syntax.Writer) error`,
  `(*AuthenticatedContent).UnmarshalMLS(r *syntax.Reader) error`,
  `(*AuthenticatedContent).ConfirmedTranscriptHashInput() ([]byte, error)`.

`ConfirmedTranscriptHashInput` is produced here rather than in `transcript.go` because it is a
serialization of framing types (`wire_format ‖ FramedContent ‖ opaque signature<V>`) and no other
plan's scope names it. **The transcript plan consumes it** and is responsible for
`confirmed_transcript_hash[n] = Hash(interim_transcript_hash[n-1] ‖ ConfirmedTranscriptHashInput[n])`
and for `InterimTranscriptHashInput`.

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
    w := syntax.NewWriter()
    if err := authContent.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    encoded := w.Bytes()
    if encoded[0] != 0x00 || encoded[1] != 0x01 {
        t.Fatalf("wire format prefix %x, want 0001", encoded[0:2])
    }

    var decoded AuthenticatedContent
    r := syntax.NewReader(encoded)
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }
    w2 := syntax.NewWriter()
    if err := decoded.MarshalMLS(w2); err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, w2.Bytes()) {
        t.Fatalf("re-encoded %x, want %x", w2.Bytes(), encoded)
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
    if err := w.WriteOpaque(authContent.Auth.Signature); err != nil {
        t.Fatalf("signature: %v", err)
    }
    if !bytes.Equal(input, w.Bytes()) {
        t.Fatalf("input %x, want %x", input, w.Bytes())
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestAuthenticatedContentRoundTrip|TestConfirmedTranscriptHashInput' -v`
Expected: FAIL — `undefined: AuthenticatedContent`.

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
```

```go
// framing_preimage.go
// the three byte strings RFC 9420 §6 authenticates. one function each, one
// file, no crypto: an auditor reading this file sees every preimage in the
// implementation and nothing else.
package mls

import (
    "fmt"

    "github.com/urnetwork/connect/mls/syntax"
)

// the input to the confirmed transcript hash, RFC 9420 §8.2. carries the
// signature but NOT the confirmation tag, which is what makes the transcript
// hash and the confirmation tag mutually recursive rather than circular.
// transcript.go consumes this and computes the hash chain.
func (self *AuthenticatedContent) ConfirmedTranscriptHashInput() ([]byte, error) {
    if self.Content.ContentType != ContentTypeCommit {
        return nil, fmt.Errorf("%w: transcript hash input requires a commit", ErrContentArmMismatch)
    }
    w := syntax.NewWriter()
    w.WriteUint16(uint16(self.WireFormat))
    if err := self.Content.MarshalMLS(w); err != nil {
        return nil, err
    }
    if err := w.WriteOpaque(self.Auth.Signature); err != nil {
        return nil, err
    }
    return w.Bytes(), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestAuthenticatedContentRoundTrip|TestConfirmedTranscriptHashInput' -v`
Expected: PASS — three tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing.go mls/framing_preimage.go mls/framing_test.go
git ls-files | wc -l   # MUST be previous + 1
git commit -m "feat(mls): AuthenticatedContent codec and ConfirmedTranscriptHashInput"
```

---

### Task 5: `FramedContentTBS` preimage, sign and verify (ValSem010)

**Files:**
- Modify: `connect/mls/framing_preimage.go`
- Create: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.SignWithLabel(priv SignaturePrivateKey, label string, content []byte) ([]byte, error)`,
  `CryptoProvider.VerifyWithLabel(pub SignaturePublicKey, label string, content, sig []byte) error`,
  `NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)`,
  `CryptoProvider.SignatureKeyPair() (SignaturePrivateKey, SignaturePublicKey, error)` — all from the
  crypto plan (wave 1). Tasks 1–4.
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

func newTestCrypto(t *testing.T) CryptoProvider {
    t.Helper()
    crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
    if err != nil {
        t.Fatalf("crypto provider: %v", err)
    }
    return crypto
}

func testGroupContext() []byte {
    // stands in for a serialized GroupContext; the preimage inlines it verbatim
    return []byte{0xc0, 0xff, 0xee, 0x00, 0x11}
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
    groupContext := testGroupContext()

    tbs, err := FramedContentTBSBytes(WireFormatPrivateMessage, content, groupContext)
    if err != nil {
        t.Fatalf("tbs: %v", err)
    }

    w := syntax.NewWriter()
    w.WriteUint16(uint16(ProtocolVersionMLS10))
    w.WriteUint16(uint16(WireFormatPrivateMessage))
    if err := content.MarshalMLS(w); err != nil {
        t.Fatalf("content: %v", err)
    }
    w.WriteRaw(groupContext)
    if !bytes.Equal(tbs, w.Bytes()) {
        t.Fatalf("tbs %x, want %x", tbs, w.Bytes())
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
    if bytes.Contains(tbs, testGroupContext()) {
        t.Fatal("group context present for an external sender")
    }
    _, err = FramedContentTBSBytes(WireFormatPublicMessage, content, testGroupContext())
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
    groupContext := testGroupContext()

    authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPrivateMessage,
        testMemberContent(), groupContext)
    if err != nil {
        t.Fatalf("sign: %v", err)
    }
    if err := VerifyAuthenticatedContent(crypto, pub, authContent, groupContext); err != nil {
        t.Fatalf("verify: %v", err)
    }
}

func TestValSem010_SignatureVerifies(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext()
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

Run: `go test ./connect/mls/... -run 'TestFramedContentTBS|TestSignAndVerifyAuthenticatedContent|TestValSem010' -v`
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
    w.WriteUint16(uint16(ProtocolVersionMLS10))
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
    return w.Bytes(), nil
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
        return ErrBadSignature
    }
    tbs, err := FramedContentTBSBytes(authContent.WireFormat, &authContent.Content, groupContext)
    if err != nil {
        return err
    }
    if err := crypto.VerifyWithLabel(pub, framedContentTBSLabel, tbs, authContent.Auth.Signature); err != nil {
        return ErrBadSignature
    }
    if authContent.Content.ContentType == ContentTypeCommit && len(authContent.Auth.ConfirmationTag) == 0 {
        return ErrMissingConfirmationTag
    }
    return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestFramedContentTBS|TestSignAndVerifyAuthenticatedContent|TestValSem010' -v`
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
- Consumes: `CryptoProvider.Mac(key, data []byte) []byte`,
  `CryptoProvider.MacVerify(key, data, tag []byte) bool`, `CryptoProvider.HashSize() int`
  (crypto plan, wave 1). Tasks 1–5.
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
    groupContext := testGroupContext()
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
    if !bytes.Equal(tbm, w.Bytes()) {
        t.Fatalf("tbm %x, want %x", tbm, w.Bytes())
    }
}

func TestMembershipTagCoversTheConfirmationTag(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, _, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext()
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
    return w.Bytes(), nil
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
        return ErrMissingMembershipTag
    }
    tbm, err := AuthenticatedContentTBMBytes(authContent, groupContext)
    if err != nil {
        return err
    }
    if !crypto.MacVerify(membershipKey, tbm, tag) {
        return ErrBadMembershipTag
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
- Consumes: Tasks 1–6.
- Produces: `PublicMessage`, `(*PublicMessage).MarshalMLS(w *syntax.Writer) error`,
  `(*PublicMessage).UnmarshalMLS(r *syntax.Reader) error`,
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
    groupContext := testGroupContext()
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

    w := syntax.NewWriter()
    if err := message.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded PublicMessage
    r := syntax.NewReader(w.Bytes())
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }

    opened, err := OpenPublicMessage(crypto, membershipKey, &decoded, StaticSignatureKey(pub), groupContext)
    if err != nil {
        t.Fatalf("open: %v", err)
    }
    if opened.Content.Proposal.Remove.Removed != 3 {
        t.Fatalf("opened %+v", opened.Content.Proposal)
    }
}

func TestValSem005_ApplicationMustBeCiphertext(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext()
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

func TestValSem007_MembershipTagPresent(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext()
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

func TestValSem008_MembershipTagVerifies(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext()
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

Run: `go test ./connect/mls/... -run 'TestPublicMessageSealOpen|TestValSem005|TestValSem007|TestValSem008' -v`
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
            return ErrMissingMembershipTag
        }
        return w.WriteOpaque(self.MembershipTag)
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
        return nil, ErrApplicationMustBeCiphertext
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
        return nil, ErrApplicationMustBeCiphertext
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

Run: `go test ./connect/mls/... -run 'TestPublicMessageSealOpen|TestValSem005|TestValSem007|TestValSem008' -v`
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
- Consumes: Tasks 1–3.
- Produces: `PrivateMessage`, `(*PrivateMessage).MarshalMLS(w *syntax.Writer) error`,
  `(*PrivateMessage).UnmarshalMLS(r *syntax.Reader) error`, and the two unexported preimages
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
    w := syntax.NewWriter()
    if err := message.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    encoded := w.Bytes()

    var decoded PrivateMessage
    r := syntax.NewReader(encoded)
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }
    w2 := syntax.NewWriter()
    if err := decoded.MarshalMLS(w2); err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, w2.Bytes()) {
        t.Fatalf("re-encoded %x, want %x", w2.Bytes(), encoded)
    }
}

func TestPrivateMessageRejectsReservedContentType(t *testing.T) {
    message := PrivateMessage{GroupId: []byte{0x01}, ContentType: ContentTypeReserved}
    if err := message.MarshalMLS(syntax.NewWriter()); !errors.Is(err, ErrUnknownContentType) {
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
    if err := w.WriteOpaque(self.GroupId); err != nil {
        return err
    }
    w.WriteUint64(self.Epoch)
    w.WriteUint8(uint8(self.ContentType))
    if err := w.WriteOpaque(self.AuthenticatedData); err != nil {
        return err
    }
    if err := w.WriteOpaque(self.EncryptedSenderData); err != nil {
        return err
    }
    return w.WriteOpaque(self.Ciphertext)
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
```

```go
// framing_preimage.go (append)

// SenderDataAAD, RFC 9420 §6.3.2. deliberately WITHOUT authenticated_data:
// sender data is opened before the content, so its AAD cannot depend on a
// field the content step has not reached yet.
func senderDataAAD(groupId []byte, epoch uint64, contentType ContentType) ([]byte, error) {
    w := syntax.NewWriter()
    if err := w.WriteOpaque(groupId); err != nil {
        return nil, err
    }
    w.WriteUint64(epoch)
    w.WriteUint8(uint8(contentType))
    return w.Bytes(), nil
}

// PrivateContentAAD, RFC 9420 §6.3.1. SenderDataAAD plus authenticated_data,
// which is why the two are written next to each other.
func privateContentAAD(groupId []byte, epoch uint64, contentType ContentType,
    authenticatedData []byte) ([]byte, error) {

    w := syntax.NewWriter()
    if err := w.WriteOpaque(groupId); err != nil {
        return nil, err
    }
    w.WriteUint64(epoch)
    w.WriteUint8(uint8(contentType))
    if err := w.WriteOpaque(authenticatedData); err != nil {
        return nil, err
    }
    return w.Bytes(), nil
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

### Task 9: `SenderData`, the ciphertext sample, and sender-data encryption

**Files:**
- Modify: `connect/mls/framing.go`
- Modify: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: `CryptoProvider.HashSize() int`, `KeySize() int`, `NonceSize() int`,
  `ExpandWithLabel(secret []byte, label string, context []byte, length int) []byte`,
  `AeadSeal(key, nonce, aad, plaintext []byte) ([]byte, error)`,
  `AeadOpen(key, nonce, aad, ciphertext []byte) ([]byte, error)` (crypto plan, wave 1). Tasks 1, 8.
- Produces: `SenderData`, `(*SenderData).MarshalMLS(w *syntax.Writer) error`,
  `(*SenderData).UnmarshalMLS(r *syntax.Reader) error`, and the unexported
  `senderDataKeyNonce(crypto CryptoProvider, senderDataSecret, ciphertext []byte) (key, nonce []byte)`,
  `sealSenderData(...)`, `openSenderData(...)`.

**The trap:** `ciphertext_sample = ciphertext[0..KDF.Nh-1]`, and when the ciphertext is **shorter**
than `KDF.Nh` the whole ciphertext is the sample. An implementation that slices unconditionally
panics on a short message; one that pads to `Nh` derives a different key from every peer. Both are
tested.

- [ ] **Step 1: Write the failing test**

```go
// framing_protect_test.go (append)
func TestSenderDataRoundTrip(t *testing.T) {
    senderData := SenderData{
        LeafIndex:  1,
        Generation: 7,
        ReuseGuard: [4]byte{0xde, 0xad, 0xbe, 0xef},
    }
    w := syntax.NewWriter()
    if err := senderData.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    want := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0xde, 0xad, 0xbe, 0xef}
    if !bytes.Equal(w.Bytes(), want) {
        t.Fatalf("encoded %x, want %x", w.Bytes(), want)
    }
    var decoded SenderData
    r := syntax.NewReader(w.Bytes())
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }
    if decoded != senderData {
        t.Fatalf("decoded %+v, want %+v", decoded, senderData)
    }
}

func TestCiphertextSampleIsBoundedByHashSize(t *testing.T) {
    crypto := newTestCrypto(t)
    secret := bytes.Repeat([]byte{0x11}, crypto.HashSize())

    long := bytes.Repeat([]byte{0xab}, crypto.HashSize()+40)
    keyLong, nonceLong := senderDataKeyNonce(crypto, secret, long)
    keyTrunc, nonceTrunc := senderDataKeyNonce(crypto, secret, long[:crypto.HashSize()])
    if !bytes.Equal(keyLong, keyTrunc) || !bytes.Equal(nonceLong, nonceTrunc) {
        t.Fatal("sample is not truncated to KDF.Nh")
    }

    // a ciphertext shorter than KDF.Nh must not panic and must use the whole thing
    short := []byte{0x01, 0x02, 0x03}
    keyShort, nonceShort := senderDataKeyNonce(crypto, secret, short)
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
Expected: FAIL — `undefined: SenderData`, `undefined: senderDataKeyNonce`.

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
```

```go
// framing_protect.go (append)

// RFC 9420 §6.3.2. the sample is the first KDF.Nh bytes of the content
// ciphertext, or the whole ciphertext when it is shorter than that.
func senderDataKeyNonce(crypto CryptoProvider, senderDataSecret, ciphertext []byte) (key, nonce []byte) {
    sample := ciphertext
    if len(sample) > crypto.HashSize() {
        sample = sample[:crypto.HashSize()]
    }
    key = crypto.ExpandWithLabel(senderDataSecret, "key", sample, crypto.KeySize())
    nonce = crypto.ExpandWithLabel(senderDataSecret, "nonce", sample, crypto.NonceSize())
    return key, nonce
}

func sealSenderData(crypto CryptoProvider, senderDataSecret []byte, senderData *SenderData,
    header *PrivateMessage, ciphertext []byte) ([]byte, error) {

    w := syntax.NewWriter()
    if err := senderData.MarshalMLS(w); err != nil {
        return nil, err
    }
    aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
    if err != nil {
        return nil, err
    }
    key, nonce := senderDataKeyNonce(crypto, senderDataSecret, ciphertext)
    return crypto.AeadSeal(key, nonce, aad, w.Bytes())
}

func openSenderData(crypto CryptoProvider, senderDataSecret []byte, encryptedSenderData []byte,
    header *PrivateMessage, ciphertext []byte) (*SenderData, error) {

    aad, err := senderDataAAD(header.GroupId, header.Epoch, header.ContentType)
    if err != nil {
        return nil, err
    }
    key, nonce := senderDataKeyNonce(crypto, senderDataSecret, ciphertext)
    plaintext, err := crypto.AeadOpen(key, nonce, aad, encryptedSenderData)
    if err != nil {
        return nil, ErrDecryptFailed
    }
    senderData := &SenderData{}
    r := syntax.NewReader(plaintext)
    if err := senderData.UnmarshalMLS(r); err != nil {
        return nil, err
    }
    if err := r.Finish(); err != nil {
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
git commit -m "feat(mls): SenderData codec, ciphertext sample and sender-data encryption"
```

---

### Task 10: `PrivateMessageContent` and padding (ValSem011)

**Files:**
- Modify: `connect/mls/framing_protect.go`
- Test: `connect/mls/framing_protect_test.go`

**Interfaces:**
- Consumes: Tasks 1–3, 8.
- Produces: `const PaddingSizeV1 = 0`, and the unexported
  `marshalPrivateMessageContent(content *FramedContent, auth *FramedContentAuthData, paddingSize int) ([]byte, error)`,
  `unmarshalPrivateMessageContent(plaintext []byte, header *PrivateMessage, sender Sender) (*FramedContent, *FramedContentAuthData, error)`.

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

func TestValSem011_PaddingIsAllZero(t *testing.T) {
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

Run: `go test ./connect/mls/... -run 'TestPrivateMessageContent|TestValSem011|TestPaddingSizeV1' -v`
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
    if err := content.checkArms(); err != nil {
        return nil, err
    }
    w := syntax.NewWriter()
    switch content.ContentType {
    case ContentTypeApplication:
        if err := w.WriteOpaque(content.ApplicationData); err != nil {
            return nil, err
        }
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
    w.WriteRaw(make([]byte, paddingSize))
    return w.Bytes(), nil
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

    // the padding is whatever remains; accumulate rather than early-return so
    // the check does not leak the position of the first non-zero byte.
    var accumulated byte
    for _, b := range r.Rest() {
        accumulated |= b
    }
    if accumulated != 0 {
        return nil, nil, ErrNonZeroPadding
    }
    return content, auth, nil
}
```

`framing_protect.go` now needs `"fmt"` in its import block alongside `syntax`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestPrivateMessageContent|TestValSem011|TestPaddingSizeV1' -v`
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
- Consumes: from the **key schedule and secret tree plan (wave 2)**, a `*SecretTree` with the three
  methods listed in "Interfaces consumed" above; `CryptoProvider.Random(n int) []byte`,
  `AeadSeal`, `AeadOpen`. Tasks 1–10.
- Produces:
  ```go
  type MessageKeySource interface {
      NextMessageKey(contentType ContentType, leaf LeafIndex) (key, nonce []byte, generation uint32, err error)
      MessageKey(contentType ContentType, leaf LeafIndex, generation uint32) (key, nonce []byte, err error)
      EraseMessageKey(contentType ContentType, leaf LeafIndex, generation uint32)
  }
  func SealPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
      authContent *AuthenticatedContent, paddingSize int) (*PrivateMessage, error)
  func OpenPrivateMessage(crypto CryptoProvider, keys MessageKeySource, senderDataSecret []byte,
      message *PrivateMessage, resolve SignatureKeyResolver, groupContext []byte) (*AuthenticatedContent, error)
  ```

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
    groupContext := testGroupContext()
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

        w := syntax.NewWriter()
        if err := message.MarshalMLS(w); err != nil {
            t.Fatalf("marshal: %v", err)
        }
        var decoded PrivateMessage
        r := syntax.NewReader(w.Bytes())
        if err := decoded.UnmarshalMLS(r); err != nil {
            t.Fatalf("unmarshal: %v", err)
        }
        if err := r.Finish(); err != nil {
            t.Fatalf("trailing bytes: %v", err)
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

func TestValSem006_CiphertextDecryptionMustSucceed(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext()
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

Run: `go test ./connect/mls/... -run 'TestApplyReuseGuard|TestPrivateMessageSealOpen|TestSealPrivateMessageRefuses|TestValSem006' -v`
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

    if authContent.WireFormat != WireFormatPrivateMessage {
        return nil, ErrWireFormatMismatch
    }
    content := &authContent.Content
    if content.Sender.SenderType != SenderTypeMember {
        return nil, ErrSenderNotMember
    }

    plaintext, err := marshalPrivateMessageContent(content, &authContent.Auth, paddingSize)
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
        return nil, ErrDecryptFailed
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

Run: `go test ./connect/mls/... -run 'TestApplyReuseGuard|TestPrivateMessageSealOpen|TestSealPrivateMessageRefuses|TestValSem006' -v`
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
- Create: `connect/mls/proposal_types.go`
- Test: `connect/mls/proposal_types_test.go`

**Interfaces:**
- Consumes: `KeyPackage`, `LeafNode`, `Extension`, `PreSharedKeyID` — each with
  `MarshalMLS(w *syntax.Writer) error` and `UnmarshalMLS(r *syntax.Reader) error`, from the
  key-package / leaf-node / extension / key-schedule plans. `LeafIndex`, `CipherSuite`. Task 1.
- Produces: `ProposalType` and its eight constants, `Add`, `Update`, `Remove`, `PreSharedKey`,
  `ReInit`, `ExternalInit`, `GroupContextExtensions`, `Proposal` with
  `MarshalMLS`/`UnmarshalMLS`, `ProposalOrRefType` and its three constants, `ProposalRef`,
  `ProposalOrRef` with `MarshalMLS`/`UnmarshalMLS`.

**This file is codec only.** It accepts every registered proposal type, including the four the v1
profile refuses, because the `messages` vector family requires `pre_shared_key_proposal`,
`re_init_proposal` and `external_init_proposal` to decode and re-encode byte-exactly. Profile
refusal is `ParseProposal` in `proposal.go` (wave 4); ValSem401–403 test that function.

`ProposalType` is **uint16** — the IANA MLS Proposal Types registry is 0x0000–0xFFFF and GREASE
values for proposal types are 0x0A0A…0xEAEA. An 8-bit implementation encodes every proposal one
byte short and fails every vector; the width test is first for that reason.

An unknown proposal type is preserved in `UnknownBody` as the remaining bytes and re-encoded
verbatim, which is what makes GREASE "parsed and ignored, never generated" (Spec A §3.2) true at
the codec layer. `ParseProposal` refuses unknown types; the codec does not lose them.

- [ ] **Step 1: Write the failing test**

```go
// proposal_types_test.go
package mls

import (
    "bytes"
    "errors"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func TestProposalTypeIsSixteenBitsOnTheWire(t *testing.T) {
    proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 3}}
    w := syntax.NewWriter()
    if err := proposal.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    want := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x03}
    if !bytes.Equal(w.Bytes(), want) {
        t.Fatalf("encoded %x, want %x — ProposalType must be uint16", w.Bytes(), want)
    }
}

func TestProposalRoundTripRemove(t *testing.T) {
    proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 7}}
    w := syntax.NewWriter()
    if err := proposal.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    encoded := w.Bytes()

    var decoded Proposal
    r := syntax.NewReader(encoded)
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }
    if decoded.Remove == nil || decoded.Remove.Removed != 7 {
        t.Fatalf("decoded %+v", decoded.Remove)
    }
    w2 := syntax.NewWriter()
    if err := decoded.MarshalMLS(w2); err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, w2.Bytes()) {
        t.Fatalf("re-encoded %x, want %x", w2.Bytes(), encoded)
    }
}

func TestProposalCodecAcceptsProfileRefusedTypes(t *testing.T) {
    // the codec is not the profile gate: ParseProposal refuses these, the
    // codec must round-trip them or the `messages` vector family fails
    proposal := Proposal{
        ProposalType: ProposalTypeExternalInit,
        ExternalInit: &ExternalInit{KemOutput: []byte{0x01, 0x02, 0x03}},
    }
    w := syntax.NewWriter()
    if err := proposal.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded Proposal
    r := syntax.NewReader(w.Bytes())
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }
    if decoded.ExternalInit == nil || !bytes.Equal(decoded.ExternalInit.KemOutput, []byte{0x01, 0x02, 0x03}) {
        t.Fatalf("decoded %+v", decoded.ExternalInit)
    }
}

func TestProposalPreservesUnknownTypeVerbatim(t *testing.T) {
    // GREASE: parsed and ignored, never generated
    encoded := []byte{0x0a, 0x0a, 0xde, 0xad, 0xbe, 0xef}
    var decoded Proposal
    r := syntax.NewReader(encoded)
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if decoded.ProposalType != ProposalType(0x0a0a) {
        t.Fatalf("proposal type %04x", decoded.ProposalType)
    }
    w := syntax.NewWriter()
    if err := decoded.MarshalMLS(w); err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(w.Bytes(), encoded) {
        t.Fatalf("re-encoded %x, want %x", w.Bytes(), encoded)
    }
}

func TestProposalRejectsArmMismatch(t *testing.T) {
    proposal := Proposal{ProposalType: ProposalTypeRemove}
    if err := proposal.MarshalMLS(syntax.NewWriter()); !errors.Is(err, ErrContentArmMismatch) {
        t.Fatalf("got %v, want ErrContentArmMismatch", err)
    }
}

func TestProposalOrRefRoundTrip(t *testing.T) {
    cases := []ProposalOrRef{
        {Type: ProposalOrRefTypeProposal, Proposal: &Proposal{
            ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}},
        {Type: ProposalOrRefTypeReference, Reference: ProposalRef{0xaa, 0xbb, 0xcc}},
    }
    for i, proposalOrRef := range cases {
        w := syntax.NewWriter()
        if err := proposalOrRef.MarshalMLS(w); err != nil {
            t.Fatalf("case %d: marshal: %v", i, err)
        }
        encoded := w.Bytes()
        var decoded ProposalOrRef
        r := syntax.NewReader(encoded)
        if err := decoded.UnmarshalMLS(r); err != nil {
            t.Fatalf("case %d: unmarshal: %v", i, err)
        }
        if err := r.Finish(); err != nil {
            t.Fatalf("case %d: trailing bytes: %v", i, err)
        }
        w2 := syntax.NewWriter()
        if err := decoded.MarshalMLS(w2); err != nil {
            t.Fatalf("case %d: re-marshal: %v", i, err)
        }
        if !bytes.Equal(encoded, w2.Bytes()) {
            t.Fatalf("case %d: re-encoded %x, want %x", i, w2.Bytes(), encoded)
        }
    }
}

func TestProposalOrRefRejectsReservedType(t *testing.T) {
    var decoded ProposalOrRef
    err := decoded.UnmarshalMLS(syntax.NewReader([]byte{0x00}))
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
// proposal_types.go
// the RFC 9420 §12.1 proposal wire types and their codecs. codec only: the v1
// profile gate that refuses psk, reinit and external_init is ParseProposal in
// proposal.go. this file must round-trip every registered type, because the
// `messages` vector family carries all seven.
package mls

import (
    "fmt"

    "github.com/urnetwork/connect/mls/syntax"
)

// 16 bits, per the IANA MLS Proposal Types registry (0x0000-0xFFFF).
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
    PSK PreSharedKeyID
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
// type keeps its body in UnknownBody and re-encodes verbatim, which is what
// makes GREASE round-trip.
type Proposal struct {
    ProposalType           ProposalType
    Add                    *Add
    Update                 *Update
    Remove                 *Remove
    PreSharedKey           *PreSharedKey
    ReInit                 *ReInit
    ExternalInit           *ExternalInit
    GroupContextExtensions *GroupContextExtensions
    UnknownBody            []byte
}

func (self *Proposal) MarshalMLS(w *syntax.Writer) error {
    w.WriteUint16(uint16(self.ProposalType))
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
        return self.PreSharedKey.PSK.MarshalMLS(w)
    case ProposalTypeReInit:
        if self.ReInit == nil {
            return ErrContentArmMismatch
        }
        if err := w.WriteOpaque(self.ReInit.GroupId); err != nil {
            return err
        }
        w.WriteUint16(uint16(self.ReInit.Version))
        w.WriteUint16(uint16(self.ReInit.CipherSuite))
        return marshalExtensions(w, self.ReInit.Extensions)
    case ProposalTypeExternalInit:
        if self.ExternalInit == nil {
            return ErrContentArmMismatch
        }
        return w.WriteOpaque(self.ExternalInit.KemOutput)
    case ProposalTypeGroupContextExtensions:
        if self.GroupContextExtensions == nil {
            return ErrContentArmMismatch
        }
        return marshalExtensions(w, self.GroupContextExtensions.Extensions)
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
        return self.PreSharedKey.PSK.UnmarshalMLS(r)
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
        extensions, err := unmarshalExtensions(r)
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
        extensions, err := unmarshalExtensions(r)
        if err != nil {
            return err
        }
        self.GroupContextExtensions = &GroupContextExtensions{Extensions: extensions}
        return nil
    }
    // unknown type: keep the remaining bytes so the object re-encodes verbatim
    self.UnknownBody = r.Rest()
    return nil
}

// Extension vectors appear in three proposal arms and in the GroupContext; one
// helper so the length prefix has one implementation.
func marshalExtensions(w *syntax.Writer, extensions []Extension) error {
    return w.WriteVector(len(extensions), func(w *syntax.Writer, i int) error {
        return extensions[i].MarshalMLS(w)
    })
}

func unmarshalExtensions(r *syntax.Reader) ([]Extension, error) {
    extensions := []Extension{}
    err := r.ReadVector(func(r *syntax.Reader) error {
        extension := Extension{}
        if err := extension.UnmarshalMLS(r); err != nil {
            return err
        }
        extensions = append(extensions, extension)
        return nil
    })
    if err != nil {
        return nil, err
    }
    return extensions, nil
}

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
        return w.WriteOpaque(self.Reference)
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
```

Add to `errors_framing.go`:

```go
var ErrUnknownProposalOrRefType = errors.New("mls: unknown ProposalOrRef type")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestProposal' -v`
Expected: PASS — seven tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/proposal_types.go mls/proposal_types_test.go mls/errors_framing.go
git ls-files | wc -l   # MUST be previous + 2
git commit -m "feat(mls): Proposal and ProposalOrRef wire codecs, uint16 proposal type"
```

---

### Task 13: `Commit` wire type

**Files:**
- Create: `connect/mls/commit_types.go`
- Test: `connect/mls/commit_types_test.go`

**Interfaces:**
- Consumes: `UpdatePath` with `MarshalMLS`/`UnmarshalMLS` (TreeKEM plan, wave 2). Task 12.
- Produces: `Commit`, `(*Commit).MarshalMLS(w *syntax.Writer) error`,
  `(*Commit).UnmarshalMLS(r *syntax.Reader) error`.

`path` is `optional<UpdatePath>`: a `u8` presence byte, then the value when present. A commit with
no path encodes to a two-byte empty proposals vector plus `0x00`. `ErrOptionalPresence` covers a
presence byte that is neither 0 nor 1 — the RFC's `optional<T>` has exactly two encodings and a
third would be a second encoding of the same object, which is the signature-bypass primitive
Gate 4 property 2 exists to prevent.

- [ ] **Step 1: Write the failing test**

```go
// commit_types_test.go
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
    w := syntax.NewWriter()
    if err := commit.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    encoded := w.Bytes()
    if encoded[len(encoded)-1] != 0x00 {
        t.Fatalf("absent path encoded as %02x, want 00", encoded[len(encoded)-1])
    }

    var decoded Commit
    r := syntax.NewReader(encoded)
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }
    if decoded.Path != nil {
        t.Fatal("path decoded as present")
    }
    if len(decoded.Proposals) != 1 || decoded.Proposals[0].Type != ProposalOrRefTypeReference {
        t.Fatalf("proposals %+v", decoded.Proposals)
    }
    w2 := syntax.NewWriter()
    if err := decoded.MarshalMLS(w2); err != nil {
        t.Fatalf("re-marshal: %v", err)
    }
    if !bytes.Equal(encoded, w2.Bytes()) {
        t.Fatalf("re-encoded %x, want %x", w2.Bytes(), encoded)
    }
}

func TestCommitRoundTripEmptyProposals(t *testing.T) {
    commit := Commit{}
    w := syntax.NewWriter()
    if err := commit.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    var decoded Commit
    r := syntax.NewReader(w.Bytes())
    if err := decoded.UnmarshalMLS(r); err != nil {
        t.Fatalf("unmarshal: %v", err)
    }
    if err := r.Finish(); err != nil {
        t.Fatalf("trailing bytes: %v", err)
    }
    if len(decoded.Proposals) != 0 || decoded.Path != nil {
        t.Fatalf("decoded %+v", decoded)
    }
}

func TestCommitRejectsInvalidOptionalPresenceByte(t *testing.T) {
    commit := Commit{}
    w := syntax.NewWriter()
    if err := commit.MarshalMLS(w); err != nil {
        t.Fatalf("marshal: %v", err)
    }
    encoded := append([]byte(nil), w.Bytes()...)
    encoded[len(encoded)-1] = 0x02

    var decoded Commit
    err := decoded.UnmarshalMLS(syntax.NewReader(encoded))
    if !errors.Is(err, ErrOptionalPresence) {
        t.Fatalf("got %v, want ErrOptionalPresence", err)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestCommit' -v`
Expected: FAIL — `undefined: Commit`, `undefined: ErrOptionalPresence`.

- [ ] **Step 3: Write minimal implementation**

```go
// commit_types.go
// the RFC 9420 §12.4 Commit wire type and its codec. codec only: proposal-list
// validation and commit application are commit.go.
package mls

import (
    "fmt"

    "github.com/urnetwork/connect/mls/syntax"
)

type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}

func (self *Commit) MarshalMLS(w *syntax.Writer) error {
    err := w.WriteVector(len(self.Proposals), func(w *syntax.Writer, i int) error {
        return self.Proposals[i].MarshalMLS(w)
    })
    if err != nil {
        return err
    }
    if self.Path == nil {
        w.WriteUint8(0)
        return nil
    }
    w.WriteUint8(1)
    return self.Path.MarshalMLS(w)
}

func (self *Commit) UnmarshalMLS(r *syntax.Reader) error {
    *self = Commit{Proposals: []ProposalOrRef{}}
    err := r.ReadVector(func(r *syntax.Reader) error {
        proposalOrRef := ProposalOrRef{}
        if err := proposalOrRef.UnmarshalMLS(r); err != nil {
            return err
        }
        self.Proposals = append(self.Proposals, proposalOrRef)
        return nil
    })
    if err != nil {
        return err
    }
    present, err := r.ReadUint8()
    if err != nil {
        return err
    }
    switch present {
    case 0:
        return nil
    case 1:
        self.Path = &UpdatePath{}
        return self.Path.UnmarshalMLS(r)
    }
    return fmt.Errorf("%w: %d", ErrOptionalPresence, present)
}
```

Add to `errors_framing.go`:

```go
var ErrOptionalPresence = errors.New("mls: optional presence byte is neither 0 nor 1")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestCommit' -v`
Expected: PASS — three tests.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/commit_types.go mls/commit_types_test.go mls/errors_framing.go
git ls-files | wc -l   # MUST be previous + 2
git commit -m "feat(mls): Commit wire codec with a strict optional<UpdatePath> presence byte"
```

---

### Task 14: `MLSMessage` wrapper

**Files:**
- Modify: `connect/mls/framing.go`
- Test: `connect/mls/framing_test.go`

**Interfaces:**
- Consumes: `Welcome`, `GroupInfo`, `KeyPackage`, each with `MarshalMLS`/`UnmarshalMLS`. Tasks 1–8.
- Produces: `MLSMessage`, `(*MLSMessage).MarshalMLS(w *syntax.Writer) error`,
  `(*MLSMessage).UnmarshalMLS(r *syntax.Reader) error`,
  `MarshalMLSMessage(message *MLSMessage) ([]byte, error)`,
  `ParseMLSMessage(data []byte) (*MLSMessage, error)`.

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
        Version:    ProtocolVersionMLS10,
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
        Version:    ProtocolVersionMLS10,
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
    if self.Version != ProtocolVersionMLS10 {
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
    if ProtocolVersion(version) != ProtocolVersionMLS10 {
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

func MarshalMLSMessage(message *MLSMessage) ([]byte, error) {
    w := syntax.NewWriter()
    if err := message.MarshalMLS(w); err != nil {
        return nil, err
    }
    return w.Bytes(), nil
}

// the single entry point for every byte that arrives from the network or the
// store. enforces full consumption, so a message with trailing bytes is a
// decode error rather than a silently truncated object.
func ParseMLSMessage(data []byte) (*MLSMessage, error) {
    message := &MLSMessage{}
    r := syntax.NewReader(data)
    if err := message.UnmarshalMLS(r); err != nil {
        return nil, err
    }
    if err := r.Finish(); err != nil {
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

### Task 15: ValSem002, ValSem003, ValSem004 and the framing ValSem roster

**Files:**
- Modify: `connect/mls/framing_protect.go`
- Create: `connect/mls/validation_framing_test.go`
- Modify: `connect/mls/framing_protect_test.go` (move the ValSem tests written in Tasks 5–11)

**Interfaces:**
- Consumes: Tasks 1–14.
- Produces:
  `CheckFramedContentContext(content *FramedContent, groupId []byte, epoch uint64) error`,
  `CheckSenderLeaf(sender Sender, leafOccupied func(LeafIndex) bool) error`.

`CheckSenderLeaf` takes a predicate rather than a tree so the framing layer stays free of tree
types and the test needs no group. `group.go` passes `self.tree.LeafOccupied`.

Spec A §4.3 requires one top-level `TestValSemNNN_<slug>` per code in
`validation_framing_test.go`. Tasks 5–11 wrote `TestValSem005`…`TestValSem011` into
`framing_protect_test.go` where they belonged next to the code under test; this task **moves** them
into `validation_framing_test.go`, adds 002/003/004, and adds the roster test that fails when a code
has no test function.

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
    "testing"
)

func TestValSem002_GroupIdMatches(t *testing.T) {
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

func TestValSem003_EpochMatches(t *testing.T) {
    content := testMemberContent()
    if err := CheckFramedContentContext(content, content.GroupId, content.Epoch+1); !errors.Is(err, ErrWrongEpoch) {
        t.Fatalf("got %v, want ErrWrongEpoch", err)
    }
    if err := CheckFramedContentContext(content, content.GroupId, content.Epoch-1); !errors.Is(err, ErrWrongEpoch) {
        t.Fatalf("older epoch: got %v, want ErrWrongEpoch", err)
    }
}

func TestValSem004_SenderLeafIsNotBlank(t *testing.T) {
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

// Spec A §4.3: one top-level TestValSemNNN_<slug> per framing code. this test
// fails when a code loses its test, which is the failure mode a coverage
// percentage does not catch.
func TestFramingValSemRosterIsComplete(t *testing.T) {
    want := []string{
        "TestValSem002_", "TestValSem003_", "TestValSem004_", "TestValSem005_",
        "TestValSem006_", "TestValSem007_", "TestValSem008_", "TestValSem009_",
        "TestValSem010_", "TestValSem011_",
    }
    fileSet := token.NewFileSet()
    packages, err := parser.ParseDir(fileSet, ".", nil, 0)
    if err != nil {
        t.Fatalf("parse: %v", err)
    }
    found := map[string]bool{}
    for _, pkg := range packages {
        for _, file := range pkg.Files {
            for _, decl := range file.Decls {
                funcDecl, ok := decl.(*ast.FuncDecl)
                if !ok || funcDecl.Recv != nil {
                    continue
                }
                for _, prefix := range want {
                    if len(funcDecl.Name.Name) > len(prefix) && funcDecl.Name.Name[:len(prefix)] == prefix {
                        found[prefix] = true
                    }
                }
            }
        }
    }
    for _, prefix := range want {
        if !found[prefix] {
            t.Errorf("no top-level test function named %s<slug>", prefix)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem002|TestValSem003|TestValSem004|TestFramingValSemRoster' -v`
Expected: FAIL — `undefined: CheckFramedContentContext`, `undefined: CheckSenderLeaf`, and the
roster test reporting the three missing prefixes.

- [ ] **Step 3: Write minimal implementation**

```go
// framing_protect.go (append)

// ValSem002 and ValSem003. the group id comparison is constant time not
// because a group id is secret but because framing.go and framing_protect.go
// are under the G8 gate and one exception is how a gate stops being a gate.
func CheckFramedContentContext(content *FramedContent, groupId []byte, epoch uint64) error {
    if subtle.ConstantTimeCompare(content.GroupId, groupId) != 1 {
        return ErrWrongGroupId
    }
    if content.Epoch != epoch {
        return ErrWrongEpoch
    }
    return nil
}

// ValSem004. takes a predicate rather than a tree so framing carries no tree
// types; group.go passes the ratchet tree's occupancy test.
func CheckSenderLeaf(sender Sender, leafOccupied func(LeafIndex) bool) error {
    if sender.SenderType != SenderTypeMember {
        return nil
    }
    if !leafOccupied(sender.LeafIndex) {
        return ErrBlankSenderLeaf
    }
    return nil
}
```

`framing_protect.go` now needs `"crypto/subtle"` in its import block.

- [ ] **Step 4: Move the ValSem tests written in earlier tasks**

Cut `TestValSem005_ApplicationMustBeCiphertext`, `TestValSem006_CiphertextDecryptionMustSucceed`,
`TestValSem007_MembershipTagPresent`, `TestValSem008_MembershipTagVerifies`,
`TestValSem010_SignatureVerifies` and `TestValSem011_PaddingIsAllZero` from
`framing_protect_test.go` and paste them unchanged into `validation_framing_test.go`. Add
ValSem009, which no earlier task covered on its own:

```go
// validation_framing_test.go (append)
func TestValSem009_ConfirmationTagPresent(t *testing.T) {
    crypto := newTestCrypto(t)
    priv, pub, err := crypto.SignatureKeyPair()
    if err != nil {
        t.Fatalf("key pair: %v", err)
    }
    groupContext := testGroupContext()

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
    truncated := append([]byte(nil), w.Bytes()...)
    truncated[len(authContent.Auth.Signature)+1] = 0x00 // the tag's length prefix
    truncated = truncated[:len(authContent.Auth.Signature)+2]
    var decoded FramedContentAuthData
    if err := decoded.UnmarshalMLS(syntax.NewReader(truncated), ContentTypeCommit); !errors.Is(err, ErrMissingConfirmationTag) {
        t.Fatalf("unmarshal: got %v, want ErrMissingConfirmationTag", err)
    }
}
```

`validation_framing_test.go` now needs `"github.com/urnetwork/connect/mls/syntax"` in its import
block.

- [ ] **Step 5: Run the whole framing ValSem set to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem0(0[2-9]|1[01])|TestFramingValSemRoster' -v`
Expected: PASS — ten ValSem tests plus the roster test.

- [ ] **Step 6: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_protect.go mls/framing_protect_test.go mls/validation_framing_test.go
git ls-files | wc -l   # MUST be previous + 1
git commit -m "test(mls): the ten framing ValSem codes in one roster-checked file"
```

---

### Task 16: The `message-protection` vector family, both directions

**Files:**
- Create: `connect/mls/message_protection_kat_test.go`
- Create: `connect/mls/vectors_hex_test.go`
- Test data: `connect/mls/testdata/vectors/message-protection.json` (vendored by the wave-1
  validation plan at the pinned mlswg commit recorded in `connect/mls/interop/PINS.md`)

**Interfaces:**
- Consumes: everything above; `GroupContext` **as bytes** — the harness builds the serialized
  GroupContext itself from the vector fields, so it needs
  `MarshalGroupContext(suite CipherSuite, groupId []byte, epoch uint64, treeHash, confirmedTranscriptHash []byte, extensions []Extension) ([]byte, error)` from the key-schedule plan (wave 2). If that
  helper does not exist, build the bytes inline with `syntax` — the struct is
  `version ‖ cipher_suite ‖ opaque group_id<V> ‖ epoch ‖ opaque tree_hash<V> ‖ opaque
  confirmed_transcript_hash<V> ‖ Extension extensions<V>` and the harness is the only caller.
  Also consumes a `SecretTree` constructor from the key-schedule plan:
  `NewSecretTree(crypto CryptoProvider, groupSize uint32, encryptionSecret []byte) (*SecretTree, error)`.
- Produces: `type hexBytes []byte` with `UnmarshalJSON`, shared by every vector harness in
  `package mls`. **If the wave-1 harnesses already declare it, delete this declaration and use
  theirs** — the compiler says `hexBytes redeclared in this block`, which is an unambiguous signal.

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
// vectors_hex_test.go
package mls

import (
    "encoding/hex"
    "encoding/json"
)

// a []byte that decodes from a JSON hex string, as every mlswg vector file
// encodes binary. one declaration for the whole package.
type hexBytes []byte

func (self *hexBytes) UnmarshalJSON(data []byte) error {
    var encoded string
    if err := json.Unmarshal(data, &encoded); err != nil {
        return err
    }
    decoded, err := hex.DecodeString(encoded)
    if err != nil {
        return err
    }
    *self = hexBytes(decoded)
    return nil
}

func (self hexBytes) MarshalJSON() ([]byte, error) {
    return json.Marshal(hex.EncodeToString(self))
}
```

```go
// message_protection_kat_test.go
package mls

import (
    "bytes"
    "encoding/json"
    "os"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

type messageProtectionVector struct {
    CipherSuite             uint16   `json:"cipher_suite"`
    GroupId                 hexBytes `json:"group_id"`
    Epoch                   uint64   `json:"epoch"`
    TreeHash                hexBytes `json:"tree_hash"`
    ConfirmedTranscriptHash hexBytes `json:"confirmed_transcript_hash"`
    SignaturePriv           hexBytes `json:"signature_priv"`
    SignaturePub            hexBytes `json:"signature_pub"`
    EncryptionSecret        hexBytes `json:"encryption_secret"`
    SenderDataSecret        hexBytes `json:"sender_data_secret"`
    MembershipKey           hexBytes `json:"membership_key"`
    Proposal                hexBytes `json:"proposal"`
    ProposalPub             hexBytes `json:"proposal_pub"`
    ProposalPriv            hexBytes `json:"proposal_priv"`
    Commit                  hexBytes `json:"commit"`
    CommitPub               hexBytes `json:"commit_pub"`
    CommitPriv              hexBytes `json:"commit_priv"`
    Application             hexBytes `json:"application"`
    ApplicationPriv         hexBytes `json:"application_priv"`
}

func loadMessageProtectionVectors(t *testing.T) []messageProtectionVector {
    t.Helper()
    data, err := os.ReadFile("testdata/vectors/message-protection.json")
    if err != nil {
        t.Fatalf("read vectors: %v", err)
    }
    vectors := []messageProtectionVector{}
    if err := json.Unmarshal(data, &vectors); err != nil {
        t.Fatalf("parse vectors: %v", err)
    }
    if len(vectors) == 0 {
        t.Fatal("no vectors")
    }
    return vectors
}

// the serialized GroupContext the vector describes, built here because the
// preimage functions take bytes.
func (self *messageProtectionVector) groupContextBytes(t *testing.T) []byte {
    t.Helper()
    w := syntax.NewWriter()
    w.WriteUint16(uint16(ProtocolVersionMLS10))
    w.WriteUint16(self.CipherSuite)
    if err := w.WriteOpaque(self.GroupId); err != nil {
        t.Fatalf("group id: %v", err)
    }
    w.WriteUint64(self.Epoch)
    if err := w.WriteOpaque(self.TreeHash); err != nil {
        t.Fatalf("tree hash: %v", err)
    }
    if err := w.WriteOpaque(self.ConfirmedTranscriptHash); err != nil {
        t.Fatalf("confirmed transcript hash: %v", err)
    }
    if err := w.WriteVector(0, func(w *syntax.Writer, i int) error { return nil }); err != nil {
        t.Fatalf("extensions: %v", err)
    }
    return w.Bytes()
}

func TestMessageProtectionVectorsPublicVerify(t *testing.T) {
    for i, vector := range loadMessageProtectionVectors(t) {
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d: crypto: %v", i, err)
        }
        groupContext := vector.groupContextBytes(t)
        resolve := StaticSignatureKey(SignaturePublicKey(vector.SignaturePub))

        for _, c := range []struct {
            name string
            pub  []byte
            raw  []byte
        }{
            {"proposal", vector.ProposalPub, vector.Proposal},
            {"commit", vector.CommitPub, vector.Commit},
        } {
            message, err := ParseMLSMessage(c.pub)
            if err != nil {
                t.Fatalf("vector %d %s: parse: %v", i, c.name, err)
            }
            if message.PublicMessage == nil {
                t.Fatalf("vector %d %s: not a PublicMessage", i, c.name)
            }
            opened, err := OpenPublicMessage(crypto, vector.MembershipKey, message.PublicMessage,
                resolve, groupContext)
            if err != nil {
                t.Fatalf("vector %d %s: open: %v", i, c.name, err)
            }
            w := syntax.NewWriter()
            switch c.name {
            case "proposal":
                err = opened.Content.Proposal.MarshalMLS(w)
            case "commit":
                err = opened.Content.Commit.MarshalMLS(w)
            }
            if err != nil {
                t.Fatalf("vector %d %s: re-marshal: %v", i, c.name, err)
            }
            if !bytes.Equal(w.Bytes(), c.raw) {
                t.Fatalf("vector %d %s: raw %x, want %x", i, c.name, w.Bytes(), c.raw)
            }
        }
    }
}

func TestMessageProtectionVectorsPublicGenerate(t *testing.T) {
    for i, vector := range loadMessageProtectionVectors(t) {
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d: crypto: %v", i, err)
        }
        groupContext := vector.groupContextBytes(t)
        priv := SignaturePrivateKey(vector.SignaturePriv)
        resolve := StaticSignatureKey(SignaturePublicKey(vector.SignaturePub))

        // proposal: protect and re-verify
        proposal := &Proposal{}
        r := syntax.NewReader(vector.Proposal)
        if err := proposal.UnmarshalMLS(r); err != nil {
            t.Fatalf("vector %d: proposal decode: %v", i, err)
        }
        if err := r.Finish(); err != nil {
            t.Fatalf("vector %d: proposal trailing: %v", i, err)
        }
        content := &FramedContent{
            GroupId:     vector.GroupId,
            Epoch:       vector.Epoch,
            Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: 1},
            ContentType: ContentTypeProposal,
            Proposal:    proposal,
        }
        authContent, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage, content, groupContext)
        if err != nil {
            t.Fatalf("vector %d: sign: %v", i, err)
        }
        message, err := SealPublicMessage(crypto, vector.MembershipKey, authContent, groupContext)
        if err != nil {
            t.Fatalf("vector %d: seal: %v", i, err)
        }
        if _, err := OpenPublicMessage(crypto, vector.MembershipKey, message, resolve, groupContext); err != nil {
            t.Fatalf("vector %d: re-open: %v", i, err)
        }

        // application: protecting as a PublicMessage MUST fail
        applicationContent := &FramedContent{
            GroupId:         vector.GroupId,
            Epoch:           vector.Epoch,
            Sender:          Sender{SenderType: SenderTypeMember, LeafIndex: 1},
            ContentType:     ContentTypeApplication,
            ApplicationData: vector.Application,
        }
        applicationAuth, err := SignAuthenticatedContent(crypto, priv, WireFormatPublicMessage,
            applicationContent, groupContext)
        if err != nil {
            t.Fatalf("vector %d: application sign: %v", i, err)
        }
        if _, err := SealPublicMessage(crypto, vector.MembershipKey, applicationAuth, groupContext); err == nil {
            t.Fatalf("vector %d: application protected as a PublicMessage", i)
        }
    }
}

func TestMessageProtectionVectorsPrivateVerifyAndGenerate(t *testing.T) {
    for i, vector := range loadMessageProtectionVectors(t) {
        crypto, err := NewCryptoProvider(CipherSuite(vector.CipherSuite))
        if err != nil {
            t.Fatalf("vector %d: crypto: %v", i, err)
        }
        groupContext := vector.groupContextBytes(t)
        resolve := StaticSignatureKey(SignaturePublicKey(vector.SignaturePub))

        for _, priv := range [][]byte{vector.ProposalPriv, vector.CommitPriv, vector.ApplicationPriv} {
            message, err := ParseMLSMessage(priv)
            if err != nil {
                t.Fatalf("vector %d: parse: %v", i, err)
            }
            if message.PrivateMessage == nil {
                t.Fatalf("vector %d: not a PrivateMessage", i)
            }
            // a fresh secret tree per message: the vector's messages are each
            // at generation 0 of their own ratchet
            secretTree, err := NewSecretTree(crypto, 2, vector.EncryptionSecret)
            if err != nil {
                t.Fatalf("vector %d: secret tree: %v", i, err)
            }
            opened, err := OpenPrivateMessage(crypto, secretTree, vector.SenderDataSecret,
                message.PrivateMessage, resolve, groupContext)
            if err != nil {
                t.Fatalf("vector %d: open: %v", i, err)
            }
            if opened.Content.Sender.LeafIndex != 1 {
                t.Fatalf("vector %d: sender leaf %d, want 1", i, opened.Content.Sender.LeafIndex)
            }

            // generate: re-protect the same content and unprotect it again
            sealTree, err := NewSecretTree(crypto, 2, vector.EncryptionSecret)
            if err != nil {
                t.Fatalf("vector %d: seal tree: %v", i, err)
            }
            resealed, err := SealPrivateMessage(crypto, sealTree, vector.SenderDataSecret,
                opened, PaddingSizeV1)
            if err != nil {
                t.Fatalf("vector %d: reseal: %v", i, err)
            }
            openTree, err := NewSecretTree(crypto, 2, vector.EncryptionSecret)
            if err != nil {
                t.Fatalf("vector %d: reopen tree: %v", i, err)
            }
            reopened, err := OpenPrivateMessage(crypto, openTree, vector.SenderDataSecret,
                resealed, resolve, groupContext)
            if err != nil {
                t.Fatalf("vector %d: reopen: %v", i, err)
            }
            if !bytes.Equal(reopened.Content.ApplicationData, opened.Content.ApplicationData) {
                t.Fatalf("vector %d: application data diverged", i)
            }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestMessageProtectionVectors' -v`
Expected: FAIL — `read vectors: open testdata/vectors/message-protection.json: no such file or
directory` before the vectors are vendored, then `undefined: NewSecretTree` once they are.

- [ ] **Step 3: Vendor the vector file and wire the secret tree**

Confirm `connect/mls/testdata/vectors/message-protection.json` exists at the commit recorded in
`connect/mls/interop/PINS.md`. If the wave-1 validation plan has not vendored it yet:

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect/mls/testdata/vectors
curl -fsSL -o message-protection.json \
  "https://raw.githubusercontent.com/mlswg/mls-implementations/$(grep '^mlswg_commit:' ../../interop/PINS.md | awk '{print $2}')/test-vectors/message-protection.json"
```

No code changes are needed beyond what Tasks 1–14 produced; this step exists because the harness
fails on a missing file before it fails on anything interesting.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestMessageProtectionVectors' -v`
Expected: PASS — three tests, each iterating every vector in the file.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/message_protection_kat_test.go mls/vectors_hex_test.go mls/testdata/vectors/message-protection.json
git ls-files | wc -l   # MUST be previous + 3, or + 2 if the vectors were already vendored
git commit -m "test(mls): message-protection vector family, verify and generate directions"
```

---

### Task 17: The `messages` vector family

**Files:**
- Create: `connect/mls/messages_kat_test.go`
- Test data: `connect/mls/testdata/vectors/messages.json`

**Interfaces:**
- Consumes: `Welcome`, `GroupInfo`, `KeyPackage`, `GroupSecrets`, `Node`, `Extension` — each with
  `MarshalMLS`/`UnmarshalMLS`. Tasks 1–14.
- Produces: nothing exported; this is the gate.

The procedure is one rule applied to seventeen fields: **decode with the corresponding structure,
re-encode, and the bytes must be identical.** Objects must be syntactically valid; a MAC inside one
may be arbitrary and is not verified.

The table is written as data so a field that has no decoder is a compile error naming the field,
not a silent skip. Fields owned by other plans are marked; if one of those types is not merged yet,
comment out **that row only** and open an issue — never the whole test.

- [ ] **Step 1: Write the failing test**

```go
// messages_kat_test.go
package mls

import (
    "bytes"
    "encoding/json"
    "os"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

type messagesVector struct {
    MlsWelcome                     hexBytes `json:"mls_welcome"`
    MlsGroupInfo                   hexBytes `json:"mls_group_info"`
    MlsKeyPackage                  hexBytes `json:"mls_key_package"`
    RatchetTree                    hexBytes `json:"ratchet_tree"`
    GroupSecrets                   hexBytes `json:"group_secrets"`
    AddProposal                    hexBytes `json:"add_proposal"`
    UpdateProposal                 hexBytes `json:"update_proposal"`
    RemoveProposal                 hexBytes `json:"remove_proposal"`
    PreSharedKeyProposal           hexBytes `json:"pre_shared_key_proposal"`
    ReInitProposal                 hexBytes `json:"re_init_proposal"`
    ExternalInitProposal           hexBytes `json:"external_init_proposal"`
    GroupContextExtensionsProposal hexBytes `json:"group_context_extensions_proposal"`
    Commit                         hexBytes `json:"commit"`
    PublicMessageApplication       hexBytes `json:"public_message_application"`
    PublicMessageProposal          hexBytes `json:"public_message_proposal"`
    PublicMessageCommit            hexBytes `json:"public_message_commit"`
    PrivateMessage                 hexBytes `json:"private_message"`
}

// decodes into a fresh object and re-encodes it. one function per field type,
// so a field with no decoder does not compile.
type messagesCodec struct {
    name  string
    bytes func(v *messagesVector) []byte
    round func(data []byte) ([]byte, error)
}

func roundTrip(data []byte, unmarshal func(r *syntax.Reader) error,
    marshal func(w *syntax.Writer) error) ([]byte, error) {

    r := syntax.NewReader(data)
    if err := unmarshal(r); err != nil {
        return nil, err
    }
    if err := r.Finish(); err != nil {
        return nil, err
    }
    w := syntax.NewWriter()
    if err := marshal(w); err != nil {
        return nil, err
    }
    return w.Bytes(), nil
}

func messagesCodecs() []messagesCodec {
    return []messagesCodec{
        // owned by this plan
        {"add_proposal", func(v *messagesVector) []byte { return v.AddProposal },
            func(data []byte) ([]byte, error) {
                value := Add{}
                return roundTrip(data, value.KeyPackage.UnmarshalMLS, value.KeyPackage.MarshalMLS)
            }},
        {"update_proposal", func(v *messagesVector) []byte { return v.UpdateProposal },
            func(data []byte) ([]byte, error) {
                value := Update{}
                return roundTrip(data, value.LeafNode.UnmarshalMLS, value.LeafNode.MarshalMLS)
            }},
        {"remove_proposal", func(v *messagesVector) []byte { return v.RemoveProposal },
            func(data []byte) ([]byte, error) {
                proposal := Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{}}
                return roundTrip(data,
                    func(r *syntax.Reader) error {
                        removed, err := r.ReadUint32()
                        if err != nil {
                            return err
                        }
                        proposal.Remove.Removed = LeafIndex(removed)
                        return nil
                    },
                    func(w *syntax.Writer) error {
                        w.WriteUint32(uint32(proposal.Remove.Removed))
                        return nil
                    })
            }},
        {"pre_shared_key_proposal", func(v *messagesVector) []byte { return v.PreSharedKeyProposal },
            func(data []byte) ([]byte, error) {
                value := PreSharedKey{}
                return roundTrip(data, value.PSK.UnmarshalMLS, value.PSK.MarshalMLS)
            }},
        {"re_init_proposal", func(v *messagesVector) []byte { return v.ReInitProposal },
            func(data []byte) ([]byte, error) {
                proposal := Proposal{ProposalType: ProposalTypeReInit}
                w := syntax.NewWriter()
                w.WriteUint16(uint16(ProposalTypeReInit))
                framed := append(w.Bytes(), data...)
                r := syntax.NewReader(framed)
                if err := proposal.UnmarshalMLS(r); err != nil {
                    return nil, err
                }
                if err := r.Finish(); err != nil {
                    return nil, err
                }
                out := syntax.NewWriter()
                if err := proposal.MarshalMLS(out); err != nil {
                    return nil, err
                }
                return out.Bytes()[2:], nil
            }},
        {"external_init_proposal", func(v *messagesVector) []byte { return v.ExternalInitProposal },
            func(data []byte) ([]byte, error) {
                value := ExternalInit{}
                return roundTrip(data,
                    func(r *syntax.Reader) error {
                        kemOutput, err := r.ReadOpaque()
                        if err != nil {
                            return err
                        }
                        value.KemOutput = kemOutput
                        return nil
                    },
                    func(w *syntax.Writer) error { return w.WriteOpaque(value.KemOutput) })
            }},
        {"group_context_extensions_proposal", func(v *messagesVector) []byte {
            return v.GroupContextExtensionsProposal
        },
            func(data []byte) ([]byte, error) {
                value := GroupContextExtensions{}
                return roundTrip(data,
                    func(r *syntax.Reader) error {
                        extensions, err := unmarshalExtensions(r)
                        if err != nil {
                            return err
                        }
                        value.Extensions = extensions
                        return nil
                    },
                    func(w *syntax.Writer) error { return marshalExtensions(w, value.Extensions) })
            }},
        {"commit", func(v *messagesVector) []byte { return v.Commit },
            func(data []byte) ([]byte, error) {
                value := Commit{}
                return roundTrip(data, value.UnmarshalMLS, value.MarshalMLS)
            }},
        {"public_message_application", func(v *messagesVector) []byte { return v.PublicMessageApplication },
            roundTripMLSMessage},
        {"public_message_proposal", func(v *messagesVector) []byte { return v.PublicMessageProposal },
            roundTripMLSMessage},
        {"public_message_commit", func(v *messagesVector) []byte { return v.PublicMessageCommit },
            roundTripMLSMessage},
        {"private_message", func(v *messagesVector) []byte { return v.PrivateMessage },
            roundTripMLSMessage},

        // owned by other plans; decoded through their types
        {"mls_welcome", func(v *messagesVector) []byte { return v.MlsWelcome }, roundTripMLSMessage},
        {"mls_group_info", func(v *messagesVector) []byte { return v.MlsGroupInfo }, roundTripMLSMessage},
        {"mls_key_package", func(v *messagesVector) []byte { return v.MlsKeyPackage }, roundTripMLSMessage},
        {"group_secrets", func(v *messagesVector) []byte { return v.GroupSecrets },
            func(data []byte) ([]byte, error) {
                value := GroupSecrets{}
                return roundTrip(data, value.UnmarshalMLS, value.MarshalMLS)
            }},
        {"ratchet_tree", func(v *messagesVector) []byte { return v.RatchetTree },
            func(data []byte) ([]byte, error) {
                nodes := []*Node{}
                return roundTrip(data,
                    func(r *syntax.Reader) error {
                        return r.ReadVector(func(r *syntax.Reader) error {
                            present, err := r.ReadUint8()
                            if err != nil {
                                return err
                            }
                            switch present {
                            case 0:
                                nodes = append(nodes, nil)
                                return nil
                            case 1:
                                node := &Node{}
                                if err := node.UnmarshalMLS(r); err != nil {
                                    return err
                                }
                                nodes = append(nodes, node)
                                return nil
                            }
                            return ErrOptionalPresence
                        })
                    },
                    func(w *syntax.Writer) error {
                        return w.WriteVector(len(nodes), func(w *syntax.Writer, i int) error {
                            if nodes[i] == nil {
                                w.WriteUint8(0)
                                return nil
                            }
                            w.WriteUint8(1)
                            return nodes[i].MarshalMLS(w)
                        })
                    })
            }},
    }
}

func roundTripMLSMessage(data []byte) ([]byte, error) {
    message, err := ParseMLSMessage(data)
    if err != nil {
        return nil, err
    }
    return MarshalMLSMessage(message)
}

func TestMessagesVectorsRoundTripByteExact(t *testing.T) {
    data, err := os.ReadFile("testdata/vectors/messages.json")
    if err != nil {
        t.Fatalf("read vectors: %v", err)
    }
    vectors := []messagesVector{}
    if err := json.Unmarshal(data, &vectors); err != nil {
        t.Fatalf("parse vectors: %v", err)
    }
    if len(vectors) == 0 {
        t.Fatal("no vectors")
    }

    codecs := messagesCodecs()
    if len(codecs) != 17 {
        t.Fatalf("%d codecs, want 17 — every field in the vector needs one", len(codecs))
    }
    for i := range vectors {
        for _, codec := range codecs {
            input := codec.bytes(&vectors[i])
            if len(input) == 0 {
                t.Errorf("vector %d %s: empty", i, codec.name)
                continue
            }
            output, err := codec.round(input)
            if err != nil {
                t.Errorf("vector %d %s: %v", i, codec.name, err)
                continue
            }
            if !bytes.Equal(input, output) {
                t.Errorf("vector %d %s: re-encoded %x, want %x", i, codec.name, output, input)
            }
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestMessagesVectors' -v`
Expected: FAIL — `read vectors: open testdata/vectors/messages.json: no such file or directory`,
then compile errors naming whichever of `Welcome`, `GroupInfo`, `GroupSecrets`, `Node` are not yet
merged.

- [ ] **Step 3: Vendor the vector file**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect/mls/testdata/vectors
curl -fsSL -o messages.json \
  "https://raw.githubusercontent.com/mlswg/mls-implementations/$(grep '^mlswg_commit:' ../../interop/PINS.md | awk '{print $2}')/test-vectors/messages.json"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestMessagesVectors' -v`
Expected: PASS — one test, 17 fields per vector.

- [ ] **Step 5: Commit**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/messages_kat_test.go mls/testdata/vectors/messages.json
git ls-files | wc -l   # MUST be previous + 2
git commit -m "test(mls): messages vector family, byte-exact re-encoding for all 17 fields"
```

---

### Task 18: Fuzz targets and the constant-time comparison gate

**Files:**
- Create: `connect/mls/framing_fuzz_test.go`
- Test data: `connect/mls/testdata/corpus/` (seeded from the two vector files)

**Interfaces:**
- Consumes: Tasks 1–17.
- Produces: `FuzzMlsMessageDecode`, `FuzzMlsMessageDecodeBytes`, `FuzzProposalDecode`,
  `FuzzProposalDecodeBytes` — four of the nine Gate 4 targets (Spec A §4.4). The other five
  (`extension_decode`, `extension_decode_bytes`, `key_package_decode`, `key_package_decode_bytes`,
  `welcome_decode`) belong to the extension, key-package and welcome plans.

Gate 4 properties 1 and 2 run on every commit for 60 seconds per target and are asserted here.
Property 3 — differential agreement with OpenMLS — is the nightly job owned by the wave-1
validation and interop plan; this task only guarantees the targets exist with the names that job
invokes.

`TestFramingUsesConstantTimeComparison` replaces the `bytes.Equal` grep gate of Spec A §5.9 G8 with
a test, so the gate cannot be defeated by a shell script that stops being run.

- [ ] **Step 1: Write the failing test**

```go
// framing_fuzz_test.go
package mls

import (
    "bytes"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/urnetwork/connect/mls/syntax"
)

func seedFromCorpus(f *testing.F, names ...string) {
    f.Helper()
    for _, name := range names {
        data, err := os.ReadFile(filepath.Join("testdata", "corpus", name))
        if err != nil {
            continue
        }
        f.Add(data)
    }
}

// Gate 4 properties 1 and 2: no panic and no over-allocation on any input, and
// canonical round-trip stability on every input that decodes. a decoder that
// accepts two encodings of one object is a signature-bypass primitive, because
// MLS signs serialized forms.
func FuzzMlsMessageDecode(f *testing.F) {
    seedFromCorpus(f, "mls_message_public.bin", "mls_message_private.bin")
    f.Add([]byte{0x00, 0x01, 0x00, 0x02})
    f.Fuzz(func(t *testing.T, data []byte) {
        message, err := ParseMLSMessage(data)
        if err != nil {
            return
        }
        encoded, err := MarshalMLSMessage(message)
        if err != nil {
            t.Fatalf("decoded object failed to re-encode: %v", err)
        }
        if !bytes.Equal(encoded, data) {
            t.Fatalf("non-canonical accept: re-encoded %x, input %x", encoded, data)
        }
        again, err := ParseMLSMessage(encoded)
        if err != nil {
            t.Fatalf("re-encoded object failed to decode: %v", err)
        }
        againEncoded, err := MarshalMLSMessage(again)
        if err != nil {
            t.Fatalf("second re-encode: %v", err)
        }
        if !bytes.Equal(againEncoded, encoded) {
            t.Fatal("decode/encode is not idempotent")
        }
    })
}

// the structured variant. Go's fuzzer only mutates byte strings, so the
// structured target is seeded from a generator and is otherwise identical
// (Spec A §4.4).
func FuzzMlsMessageDecodeBytes(f *testing.F) {
    for _, wireFormat := range []WireFormat{WireFormatPublicMessage, WireFormatPrivateMessage} {
        w := syntax.NewWriter()
        w.WriteUint16(uint16(ProtocolVersionMLS10))
        w.WriteUint16(uint16(wireFormat))
        f.Add(w.Bytes())
    }
    f.Fuzz(func(t *testing.T, data []byte) {
        message, err := ParseMLSMessage(data)
        if err != nil {
            return
        }
        encoded, err := MarshalMLSMessage(message)
        if err != nil {
            t.Fatalf("re-encode: %v", err)
        }
        if !bytes.Equal(encoded, data) {
            t.Fatalf("non-canonical accept: %x vs %x", encoded, data)
        }
    })
}

func FuzzProposalDecode(f *testing.F) {
    seedFromCorpus(f, "proposal_add.bin", "proposal_remove.bin")
    f.Add([]byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x01})
    f.Fuzz(func(t *testing.T, data []byte) {
        proposal := &Proposal{}
        r := syntax.NewReader(data)
        if err := proposal.UnmarshalMLS(r); err != nil {
            return
        }
        if err := r.Finish(); err != nil {
            return
        }
        w := syntax.NewWriter()
        if err := proposal.MarshalMLS(w); err != nil {
            t.Fatalf("re-encode: %v", err)
        }
        if !bytes.Equal(w.Bytes(), data) {
            t.Fatalf("non-canonical accept: %x vs %x", w.Bytes(), data)
        }
    })
}

func FuzzProposalDecodeBytes(f *testing.F) {
    f.Add([]byte{0x0a, 0x0a})
    f.Add([]byte{0x00, 0x07, 0x00, 0x00, 0x00, 0x00})
    f.Fuzz(func(t *testing.T, data []byte) {
        proposalOrRef := &ProposalOrRef{}
        r := syntax.NewReader(data)
        if err := proposalOrRef.UnmarshalMLS(r); err != nil {
            return
        }
        if err := r.Finish(); err != nil {
            return
        }
        w := syntax.NewWriter()
        if err := proposalOrRef.MarshalMLS(w); err != nil {
            t.Fatalf("re-encode: %v", err)
        }
        if !bytes.Equal(w.Bytes(), data) {
            t.Fatalf("non-canonical accept: %x vs %x", w.Bytes(), data)
        }
    })
}

// Spec A §5.9 G8, as a test rather than a shell grep: a grep gate stops being
// a gate the first time someone runs the suite without the script.
func TestFramingUsesConstantTimeComparison(t *testing.T) {
    for _, name := range []string{"framing.go", "framing_preimage.go", "framing_protect.go"} {
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestFramingUsesConstantTimeComparison' -v && go test ./connect/mls/... -run 'FuzzMlsMessageDecode' -fuzz 'FuzzMlsMessageDecode$' -fuzztime 10s`
Expected: FAIL — the fuzz targets do not exist yet, so `-fuzz` reports
`no fuzz test FuzzMlsMessageDecode`. Once the file is added, expect the round-trip property to fail
on any decoder that accepts non-minimal length prefixes.

- [ ] **Step 3: Seed the corpus**

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect/mls
mkdir -p testdata/corpus
go run ./interop/oracle/seedgen \
  -vectors testdata/vectors/messages.json \
  -out testdata/corpus
```

If `interop/oracle/seedgen` does not exist yet (it is the wave-1 validation plan's tool), extract
the seeds with a one-off Go test instead: add `TestWriteCorpusSeeds` to `messages_kat_test.go`
guarded by `if os.Getenv("WRITE_CORPUS") == ""` { t.Skip(...) }, writing
`vectors[0].PublicMessageProposal` to `testdata/corpus/mls_message_public.bin`,
`vectors[0].PrivateMessage` to `mls_message_private.bin`, `vectors[0].AddProposal` framed with its
uint16 type to `proposal_add.bin`, and `vectors[0].RemoveProposal` framed the same way to
`proposal_remove.bin`. `seedFromCorpus` skips missing files, so an unseeded corpus is a weaker
fuzz run rather than a broken one.

- [ ] **Step 4: Run test to verify it passes**

Run:
```
go test ./connect/mls/... -run 'TestFramingUsesConstantTimeComparison' -v
go test ./connect/mls/... -fuzz 'FuzzMlsMessageDecode$' -fuzztime 60s
go test ./connect/mls/... -fuzz 'FuzzMlsMessageDecodeBytes$' -fuzztime 60s
go test ./connect/mls/... -fuzz 'FuzzProposalDecode$' -fuzztime 60s
go test ./connect/mls/... -fuzz 'FuzzProposalDecodeBytes$' -fuzztime 60s
```
Expected: PASS — the guard test green, and each fuzz run reporting `elapsed: 60s` with no new
failing inputs written to `testdata/fuzz/`.

- [ ] **Step 5: Run the whole package once, then commit**

Run: `go test ./connect/mls/... -race -timeout 0`
Expected: PASS — every test in this plan plus everything waves 1 and 2 merged.

```bash
cd /c/Users/ryanm/Downloads/claude_sandbox_message/connect
git ls-files | wc -l
git add mls/framing_fuzz_test.go mls/testdata/corpus
git ls-files | wc -l   # MUST be previous + 1 + the number of corpus files
git commit -m "test(mls): framing fuzz targets and the constant-time comparison gate"
```

---

## Execution order

The task numbers are reading order. The dependency order, which is what an executor follows:

```
1  enums, Sender, errors
12 proposal wire types      (Task 2 does not compile without Proposal)
13 commit wire type         (Task 2 does not compile without Commit)
2  FramedContent
3  FramedContentAuthData
4  AuthenticatedContent + ConfirmedTranscriptHashInput
5  FramedContentTBS, sign, verify
6  AuthenticatedContentTBM, membership tag
7  PublicMessage
8  PrivateMessage + AADs
9  SenderData
10 PrivateMessageContent + padding
11 MessageKeySource, reuse guard, seal/open
14 MLSMessage               (needs Welcome, GroupInfo, KeyPackage from other waves)
15 ValSem roster
16 message-protection vectors
17 messages vectors
18 fuzz targets + G8 gate
```

Tasks 1–13 depend on wave 1 only (`syntax`, `CryptoProvider`, `LeafIndex`) plus `KeyPackage`,
`LeafNode`, `Extension`, `PreSharedKeyID`. Tasks 14, 16 and 17 additionally need wave-2 and
wave-4 types and are the ones that will block if another plan slips.

## What this plan deliberately does not cover

| Thing | Owner |
|---|---|
| `confirmed_transcript_hash` / `interim_transcript_hash` chaining | the transcript plan; it consumes `(*AuthenticatedContent).ConfirmedTranscriptHashInput()` |
| Computing `confirmation_tag` from `confirmation_key` | key schedule (wave 2); framing carries the tag and MACs over it, never derives it |
| The secret tree's ratchet, generation window and skipped-key store | key schedule and secret tree (wave 2), behind `MessageKeySource` |
| `ParseProposal` and the profile refusals ValSem401–403 | proposals plan (wave 4) |
| ValSem101–113, ValSem200–209, ValSem240–246, ValSem300, ValSem400 | proposals, commit and tree plans |
| RFC 9420 errata 8745 (LeafNode capability validation on Update) and 8815 (commit references an unreceived proposal) | leaf-node plan and commit plan respectively — **neither is a framing erratum** |
| `Welcome`, `GroupInfo`, `KeyPackage`, `GroupSecrets`, `Node`, `UpdatePath`, `Extension`, `PreSharedKeyID`, `LeafNode` codecs | their own plans |
| The five other Gate 4 fuzz targets and the nightly OpenMLS differential | validation and interop harness plan (wave 1) |
| `group.go`'s `Protect`/`Unprotect` and `ProcessMessage` | group lifecycle (wave 4), calling this plan's `SealPrivateMessage` / `OpenPrivateMessage` |

## Coordination items to raise before execution

1. **`Proposal` and `Commit` ownership.** This plan claims their **wire codecs** because the
   `messages` gate cannot be green without them. The wave-4 plan must claim only `proposal.go`
   (list validation, `ParseProposal`, the profile refusals) and `commit.go` (application). If both
   plans declare `type Proposal`, the package will not compile and the collision is immediate and
   obvious — but it should be settled on paper first.
2. **`hexBytes`.** One declaration per package. This plan puts it in `vectors_hex_test.go`; the
   wave-1 vector harnesses should use it rather than redeclare it.
3. **The `syntax` API shape.** This plan assumes an explicit `Writer`/`Reader` rather than a
   reflection-and-struct-tag codec. MLS's `select()` variants and the unprefixed `padding` and
   GroupContext fields are the reason. If wave 1 shipped reflection, every `MarshalMLS` body here
   changes, and the preimage functions change most.
4. **`NewSecretTree(crypto, groupSize, encryptionSecret)`** and the three `MessageKeySource`
   methods on `*SecretTree`. Task 16 cannot run without them.
5. **`MarshalGroupContext`.** Task 16 builds the GroupContext bytes inline. If the key-schedule
   plan exports a helper, use it, and delete the inline version so there is one GroupContext
   serializer in the system.
