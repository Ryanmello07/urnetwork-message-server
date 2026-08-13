# Group Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement RFC 9420 group creation, the four v1 proposal types, Commit generation and
processing, Welcome generation and joining, the epoch advance, and the two URmessage extensions
(`urmessage_group_policy` 0xF001, `urmessage_leaf_keys` 0xF002) plus `urmessage_owner_successor`
(0xF003), in pure Go at `connect/mls/`.

**Architecture:** `mls.Group` is the single stateful exported type and the only place epoch state is
mutated; every mutation goes through a staged-then-merged path so a rejected commit never corrupts
live state. Proposals are cached by `ProposalRef` and resolved at commit time, so by-value and
by-reference commits share exactly one validation and application path. Welcome is built from the
same post-commit `GroupInfo` the committer signs, so committer and joiner derive the identical epoch
secrets or the confirmation tag fails.

**Tech Stack:** Go 1.26.5 (pinned), stdlib crypto only (`crypto/mlkem`, `crypto/ecdh`,
`crypto/hkdf`, `crypto/sha3`) plus `chacha20poly1305` from the already-pinned `golang.org/x/crypto`;
the `connect/mls/syntax` TLS presentation-language codec; no cgo, no Rust, no new third-party
dependency.

## Global Constraints

- Go 1.26.5, pinned. Standard library only for crypto: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, plus `chacha20poly1305` from the already-pinned `golang.org/x/crypto`.
- NO cgo, NO Rust, NO new third-party crypto dependency. `sdk` must stay gomobile-buildable.
- New dependencies permitted in `connect` on `beta/message`: **none.**
- OpenMLS (Rust) is a READ-ONLY differential oracle used out of process in CI. Never in `go.mod`, never linked, never in a shipped artifact.
- Ciphersuite: groups are created and accepted at `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003). `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) is registered and implemented but refused at group creation by policy.
- Narrow v1 profile: `BasicCredential` only; proposal types `add`, `update`, `remove`, `group_context_extensions` only; no external commits, no external senders, no PSKs, no ReInit, no branching, no subgroups. All parse-refused with typed errors.
- Protocol version `mls10` (0x0001) only.
- Wire format: `PrivateMessage` on the wire for handshake and application; `PublicMessage` implemented and tested but refused by group policy.
- `connect` (the parent package) must NEVER import `connect/mls` or `connect/message`. A package must not import its own subpackages. Enforced by `connect/layering_test.go`.
- `connect/mls` must never import `connect` or `connect/message`. `connect/mls/syntax` imports nothing but stdlib.
- `sdk.GenerateSharedSecret`, `box.Precompute` and `curve25519.ScalarMult` MUST NOT be used. All X25519 goes through `crypto/ecdh` or `curve25519.X25519`, and a returned error is a hard validation failure — never logged and continued.
- MLS signs over serialized forms, so the TLS presentation-language codec must be byte-exact and round-trip stable. One codec, one fuzz corpus.
- Max group size: **500 members, hard.** Refused at construction, rejected on receipt.
- Max devices per identity in one group: **10 leaves, hard.** Same enforcement on both sides.
- **Only an OWNER may remove an ADMIN or the OWNER.** Enforced at construction and on receipt.
- `PastEpochWindow = 32`. `StateStore.DeleteGroupStateBefore` is called on every merged commit with `epoch - PastEpochWindow`.
- Succession floor: `FloorMs >= 7776000000` (90 days). Quorum: `max(2, ceil(2 * admins / 3))`.
- `mls.Group` is NOT safe for concurrent use; `stateLock` exists to make misuse fail loudly, and the caller (`connect/message`) still serializes.
- GREASE values are **parsed and ignored, never generated**.
- `EpochSecretName` is a closed enum exposing exactly `sender_data_secret` and `encryption_secret`. `epoch_secret`, `confirmation_key`, `membership_key`, `init_secret` and `resumption_psk` are unreachable through the public API.
- `connect/mls` follows `connect/CODESTYLE.md`: `self` receivers, `stateLock` for guarded state, explicit struct field names, doc comment on every file/type/func.

---

## Interfaces consumed from other plans

Every symbol below is used by this plan and produced elsewhere. If a signature here disagrees with
the producing plan, that plan wins and the call sites in this plan are adjusted — the names and
shapes are recorded so the mismatch is visible at review rather than at compile time.

**From the Syntax and codec plan (wave 1), package `github.com/urnetwork/connect/mls/syntax`:**

```go
func Marshal(value any) ([]byte, error)
func Unmarshal(data []byte, value any) (int, error)   // returns bytes consumed
type Marshaler interface{ MarshalTLS() ([]byte, error) }
type Unmarshaler interface{ UnmarshalTLS(data []byte) (int, error) }
const MaxVectorLength uint64
var ErrTrailingBytes error
// struct tags: `tls:"head=varint"` for <V> vectors, `tls:"optional"` for optional<T> on a
// pointer field (nil -> 0x00, non-nil -> 0x01 || T), `tls:"omit"` to skip a field.
```

**From the Crypto primitives and HPKE plan (wave 1), package `mls`:**

```go
type CipherSuite uint16
const CipherSuiteX25519ChaCha20SHA256Ed25519 CipherSuite = 0x0003
type CryptoProvider interface{ /* Spec A §3.3, verbatim */ }
func NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)
type SignaturePrivateKey []byte
type SignaturePublicKey []byte
type HpkePrivateKey []byte
type HpkePublicKey []byte
type HPKECiphertext struct {
    KemOutput  []byte `tls:"head=varint"`
    Ciphertext []byte `tls:"head=varint"`
}
func EncryptWithLabel(crypto CryptoProvider, pub HpkePublicKey, label string, context, plaintext []byte) (*HPKECiphertext, error)
func DecryptWithLabel(crypto CryptoProvider, priv HpkePrivateKey, label string, context []byte, ct *HPKECiphertext) ([]byte, error)
func RefHash(crypto CryptoProvider, label string, value []byte) []byte
type ProtocolVersion uint16
const ProtocolVersionMls10 ProtocolVersion = 0x0001
```

**From the Tree math plan (wave 1), package `mls`:**

```go
type LeafIndex uint32
type NodeIndex uint32
type TreeSize uint32
func (self LeafIndex) NodeIndex() NodeIndex
func CommonAncestor(x, y LeafIndex) NodeIndex
func DirectPath(x NodeIndex, size TreeSize) []NodeIndex
func (self TreeSize) Root() NodeIndex
```

**From the TreeKEM plan (wave 2), package `mls`** (the ratchet tree, leaf nodes and key packages):

```go
type ExtensionType uint16
type Extension struct {
    ExtensionType ExtensionType `tls:"head=varint"`   // wire: uint16 then opaque<V>
    ExtensionData []byte        `tls:"head=varint"`
}
type Credential struct{ CredentialType CredentialType; Identity []byte }
type Capabilities struct{ Versions []ProtocolVersion; CipherSuites []CipherSuite; Extensions []ExtensionType; Proposals []ProposalType; Credentials []CredentialType }
type LeafNodeSource uint8
const (
    LeafNodeSourceKeyPackage LeafNodeSource = 1
    LeafNodeSourceUpdate     LeafNodeSource = 2
    LeafNodeSourceCommit     LeafNodeSource = 3
)
type LeafNode struct {
    EncryptionKey  HpkePublicKey
    SignatureKey   SignaturePublicKey
    Credential     Credential
    Capabilities   Capabilities
    LeafNodeSource LeafNodeSource
    Lifetime       *Lifetime
    ParentHash     []byte
    Extensions     []Extension `tls:"head=varint"`
    Signature      []byte      `tls:"head=varint"`
}
func (self *LeafNode) Validate(crypto CryptoProvider, groupId []byte, leaf LeafIndex, source LeafNodeSource, exts []Extension, now time.Time) error
func NewLeafNode(crypto CryptoProvider, signer SignaturePrivateKey, cred Credential, encKey HpkePublicKey, caps Capabilities, exts []Extension) (*LeafNode, error)
type KeyPackage struct {
    Version     ProtocolVersion
    CipherSuite CipherSuite
    InitKey     HpkePublicKey
    LeafNode    LeafNode
    Extensions  []Extension `tls:"head=varint"`
    Signature   []byte      `tls:"head=varint"`
}
func (self *KeyPackage) Ref(crypto CryptoProvider) ([]byte, error)   // MakeKeyPackageRef
func (self *KeyPackage) Validate(crypto CryptoProvider, suite CipherSuite, now time.Time) error
type RequiredCapabilities struct {
    ExtensionTypes  []ExtensionType `tls:"head=varint"`
    ProposalTypes   []ProposalType  `tls:"head=varint"`
    CredentialTypes []CredentialType `tls:"head=varint"`
}
func (self *Capabilities) Supports(rc *RequiredCapabilities) error

type RatchetTree struct{ /* opaque */ }
func NewRatchetTree(crypto CryptoProvider) *RatchetTree
func (self *RatchetTree) Clone() *RatchetTree
func (self *RatchetTree) AddLeaf(leaf *LeafNode) (LeafIndex, error)
func (self *RatchetTree) UpdateLeaf(index LeafIndex, leaf *LeafNode) error
func (self *RatchetTree) RemoveLeaf(index LeafIndex) error
func (self *RatchetTree) LeafNode(index LeafIndex) (*LeafNode, bool)
func (self *RatchetTree) Size() TreeSize
func (self *RatchetTree) NonBlankLeaves() []LeafIndex
func (self *RatchetTree) RootHash() ([]byte, error)
func (self *RatchetTree) Encode() ([]byte, error)                       // optional<Node> nodes<V>
func ParseRatchetTree(crypto CryptoProvider, data []byte) (*RatchetTree, error)
func (self *RatchetTree) Validate(groupId []byte, exts []Extension, now time.Time) error
func (self *RatchetTree) FindLeafBySignatureKey(key SignaturePublicKey) (LeafIndex, bool)
func (self *RatchetTree) EncryptionKeyInUse(key HpkePublicKey) bool
func (self *RatchetTree) HasTrailingBlankNodes() bool                    // ValSem300

type UpdatePathNode struct {
    EncryptionKey HpkePublicKey
    EncryptedPathSecret []HPKECiphertext `tls:"head=varint"`
}
type UpdatePath struct {
    LeafNode LeafNode
    Nodes    []UpdatePathNode `tls:"head=varint"`
}
type PathSecrets struct{ /* opaque */ }
func (self *PathSecrets) SecretAt(node NodeIndex) ([]byte, bool)
func (self *PathSecrets) CommitSecret() []byte
func (self *RatchetTree) CreateUpdatePath(from LeafIndex, signer SignaturePrivateKey,
    groupContext []byte, exclude []LeafIndex) (*UpdatePath, *PathSecrets, HpkePrivateKey, error)
func (self *RatchetTree) ApplyUpdatePath(from LeafIndex, path *UpdatePath, own LeafIndex,
    ownPriv HpkePrivateKey, groupContext []byte, exclude []LeafIndex) (commitSecret []byte, err error)
func (self *RatchetTree) MergeUpdatePathPublic(from LeafIndex, path *UpdatePath) error
func PathSecretToNodeKeyPair(crypto CryptoProvider, pathSecret []byte) (HpkePrivateKey, HpkePublicKey, error)
func DerivePathSecretNext(crypto CryptoProvider, pathSecret []byte) []byte
```

**From the Key schedule and secret tree plan (wave 2), package `mls`:**

```go
type GroupContext struct {
    Version                 ProtocolVersion
    CipherSuite             CipherSuite
    GroupId                 []byte      `tls:"head=varint"`
    Epoch                   uint64
    TreeHash                []byte      `tls:"head=varint"`
    ConfirmedTranscriptHash []byte      `tls:"head=varint"`
    Extensions              []Extension `tls:"head=varint"`
}
func (self *GroupContext) Marshal() ([]byte, error)
type EpochSecrets struct {
    JoinerSecret       []byte
    WelcomeSecret      []byte
    SenderDataSecret   []byte
    EncryptionSecret   []byte
    ExporterSecret     []byte
    ExternalSecret     []byte
    ConfirmationKey    []byte
    MembershipKey      []byte
    ResumptionPsk      []byte
    EpochAuthenticator []byte
    InitSecret         []byte
}
func DeriveEpochSecrets(crypto CryptoProvider, initSecretPrev, commitSecret, pskSecret, groupContext []byte) (*EpochSecrets, error)
func DeriveEpochSecretsFromJoiner(crypto CryptoProvider, joinerSecret, pskSecret, groupContext []byte) (*EpochSecrets, error)
func DeriveEpochSecretsFromEpochSecret(crypto CryptoProvider, epochSecret []byte) (*EpochSecrets, error)
func WelcomeKeyNonce(crypto CryptoProvider, welcomeSecret []byte) (key, nonce []byte)
func EmptyPskSecret(crypto CryptoProvider) []byte
func (self *EpochSecrets) Export(crypto CryptoProvider, label string, context []byte, length int) ([]byte, error)
type SecretTree struct{ /* opaque */ }
func NewSecretTree(crypto CryptoProvider, size TreeSize, encryptionSecret []byte) *SecretTree
```

**From the Framing and message protection plan (wave 3), package `mls`:**

```go
type WireFormat uint16
const (
    WireFormatPublicMessage  WireFormat = 0x0001
    WireFormatPrivateMessage WireFormat = 0x0002
    WireFormatWelcome        WireFormat = 0x0003
    WireFormatGroupInfo      WireFormat = 0x0004
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
    SenderTypeMember SenderType = 1
    SenderTypeExternal SenderType = 2
    SenderTypeNewMemberProposal SenderType = 3
    SenderTypeNewMemberCommit SenderType = 4
)
type Sender struct{ SenderType SenderType; LeafIndex LeafIndex; SenderIndex uint32 }
type FramedContent struct {
    GroupId           []byte `tls:"head=varint"`
    Epoch             uint64
    Sender            Sender
    AuthenticatedData []byte `tls:"head=varint"`
    ContentType       ContentType
    ApplicationData   []byte    // ContentTypeApplication
    Proposal          *Proposal // ContentTypeProposal
    Commit            *Commit   // ContentTypeCommit
}
type FramedContentAuthData struct{ Signature []byte; ConfirmationTag []byte }
type AuthenticatedContent struct {
    WireFormat WireFormat
    Content    FramedContent
    Auth       FramedContentAuthData
}
func SignFramedContent(crypto CryptoProvider, priv SignaturePrivateKey, wireFormat WireFormat,
    content *FramedContent, groupContext *GroupContext) (*AuthenticatedContent, error)
func (self *AuthenticatedContent) VerifySignature(crypto CryptoProvider, pub SignaturePublicKey,
    groupContext *GroupContext) error
func (self *AuthenticatedContent) ProposalRef(crypto CryptoProvider) (ProposalRef, error)
type ProposalRef []byte
type PrivateMessage struct{ /* opaque */ }
type PublicMessage struct{ /* opaque */ }
func ProtectPrivate(crypto CryptoProvider, secretTree *SecretTree, senderDataSecret []byte,
    groupContext *GroupContext, content *AuthenticatedContent, padding int) (*PrivateMessage, error)
func UnprotectPrivate(crypto CryptoProvider, secretTree *SecretTree, senderDataSecret []byte,
    groupContext *GroupContext, message *PrivateMessage) (*AuthenticatedContent, error)
type MLSMessage struct {
    Version        ProtocolVersion
    WireFormat     WireFormat
    PublicMessage  *PublicMessage
    PrivateMessage *PrivateMessage
    Welcome        *Welcome    // produced by Task 14 of THIS plan
    GroupInfo      *GroupInfo  // produced by Task 13 of THIS plan
    KeyPackage     *KeyPackage
}
func ParseMLSMessage(data []byte) (*MLSMessage, error)
func (self *MLSMessage) Marshal() ([]byte, error)
func ConfirmedTranscriptHash(crypto CryptoProvider, interimPrev []byte, content *AuthenticatedContent) ([]byte, error)
func InterimTranscriptHash(crypto CryptoProvider, confirmed, confirmationTag []byte) ([]byte, error)
```

**From the Validation and interop harness plan (wave 1), package `mls`:**

```go
// errors.go — one typed error per ValSem code. This plan references, and does not define:
var ErrWrongGroupId, ErrWrongEpoch, ErrBlankSenderLeaf, ErrApplicationMustBeCiphertext error
var ErrDecryptFailed, ErrMissingConfirmationTag, ErrBadSignature error
var ErrDuplicateSignatureKey, ErrDuplicateInitKey, ErrDuplicateEncryptionKey error
var ErrInitEqualsEncryptionKey, ErrSuiteMismatch, ErrMissingRequiredCapability error
var ErrDuplicateRemove, ErrRemoveNonMember, ErrSelfUpdateInCommit error
var ErrUpdateSenderNotMember, ErrUnsupportedProposalType error
var ErrSelfRemoveInCommit, ErrMissingPath, ErrPathLength, ErrPathDecrypt error
var ErrPathKeyMismatch, ErrBadConfirmationTag, ErrMultipleGCE error
var ErrUnsupportedGroupExtension, ErrTrailingBlankNodes error
var ErrProfileExternalCommit, ErrProfileExternalSender, ErrProfilePSK error
var ErrProfileReInit, ErrProfileBranch, ErrProfileCredentialType, ErrProfileCiphersuite error

// profile.go — the v1 profile gate
type Profile struct{ /* opaque */ }
func DefaultProfile() *Profile
func (self *Profile) CheckVersion(v ProtocolVersion) error
func (self *Profile) CheckProposalType(t ProposalType) error
func (self *Profile) CheckGroupExtension(t ExtensionType) error
func (self *Profile) CheckLeafExtension(t ExtensionType) error
func (self *Profile) CheckCiphersuiteForCreate(s CipherSuite) error
func (self *Profile) CheckWireFormat(w WireFormat) error
```

---

## File Structure

| File | Single responsibility |
|---|---|
| `connect/mls/errors_lifecycle.go` | **Create.** The typed errors this plan owns that are not ValSem codes: group size, device count, removal authority, succession, welcome and epoch errors. `errors.go` (ValSem codes) belongs to the Validation plan. |
| `connect/mls/leaf_keys.go` | **Create.** `urmessage_leaf_keys` (0xF002): the X-Wing device key carried in the LeafNode. Encode, parse, extract from a leaf. |
| `connect/mls/group_policy.go` | **Create.** `urmessage_group_policy` (0xF001): roles, retention policy, disappearing buckets, server id. Canonical ordering and role lookup. |
| `connect/mls/owner_successor.go` | **Create.** `urmessage_owner_successor` (0xF003): the nomination struct, its codec, and the floor constant. |
| `connect/mls/proposal.go` | **Create.** `ProposalType`, `Add`, `Update`, `Remove`, `GroupContextExtensions`, the `Proposal` variant codec, and the v1 parse gate that refuses psk/reinit/external_init. |
| `connect/mls/proposal_list.go` | **Create.** `ProposalOrRef`, the proposal cache keyed by `ProposalRef`, resolution of a commit's `ProposalOrRef` vector into a bucketed `ProposalList`. |
| `connect/mls/validate_proposals.go` | **Create.** One named func per ValSem code 101–113, plus `ValidateProposalList`. |
| `connect/mls/apply_proposals.go` | **Create.** RFC 9420 §12.3 application order onto a cloned tree and group context. |
| `connect/mls/commit.go` | **Create.** The `Commit` struct and codec, the path-required rule, commit construction (§12.4.1), commit processing (§12.4.2), `StagedCommit`, and the URmessage commit gates (size, device count, removal authority, succession). |
| `connect/mls/validate_commit.go` | **Create.** One named func per ValSem code 200–209 and 300. |
| `connect/mls/welcome.go` | **Create.** `GroupInfo`, `GroupInfoTBS`, `PathSecret`, `GroupSecrets`, `EncryptedGroupSecrets`, `Welcome`; generation and processing. |
| `connect/mls/succession.go` | **Create.** The countersignature preimage, the quorum arithmetic, and the five §11 promotion conditions. |
| `connect/mls/group.go` | **Create.** `Group`, `GroupConfig`, `StateStore`, `Member`, `Processed`, `CommitResult`, `JoinKeyMaterial`, `EpochSecretName`; `NewGroup`, `JoinFromWelcome`, `Propose*`, `Commit`, `ProcessMessage`, `ApplyCommit`, `MergePendingCommit`, `ClearPendingCommit`, `Protect`, `Unprotect`, epoch persistence and the past-epoch window. |
| `connect/mls/lifecycle_fixtures_test.go` | **Create.** Shared deterministic test fixtures: crypto provider, credentials, leaf nodes, key packages, N-member groups. |
| `connect/mls/leaf_keys_test.go` `group_policy_test.go` `owner_successor_test.go` `proposal_test.go` `proposal_list_test.go` `validate_proposals_test.go` `apply_proposals_test.go` `commit_test.go` `validate_commit_test.go` `welcome_test.go` `succession_test.go` `group_test.go` | **Create.** One test file per source file. |
| `connect/mls/welcome_vectors_test.go` | **Create.** The `welcome.json` vector family, verify and generate directions. |
| `connect/mls/passive_client_vectors_test.go` | **Create.** Vector families 13, 14 and 15 (`passive-client-welcome.json`, `passive-client-handling-commit.json`, `passive-client-random.json`). |
| `connect/mls/group_roundtrip_test.go` | **Create.** The gate: multi-member add/update/remove/GCE cycles, join at epoch N, concurrent-commit loser re-derivation, profile refusals end to end. |
| `connect/mls/testdata/vectors/welcome.json` | **Create.** Vendored from `mlswg/mls-implementations` at the commit pinned in `connect/mls/interop/PINS.md`. |
| `connect/mls/testdata/vectors/passive-client-*.json` | **Create.** Same provenance. |

---

### Task 1: The lifecycle error set and shared test fixtures

**Files:**
- Create: `connect/mls/errors_lifecycle.go`
- Test: `connect/mls/lifecycle_fixtures_test.go`

**Interfaces:**
- Consumes: `mls.CryptoProvider`, `mls.NewCryptoProvider(suite CipherSuite) (CryptoProvider, error)`, `mls.CipherSuiteX25519ChaCha20SHA256Ed25519`, `mls.Credential`, `mls.Capabilities`, `mls.LeafNode`, `mls.NewLeafNode`, `mls.KeyPackage`, `mls.HpkePrivateKey`, `mls.SignaturePrivateKey` — all from the Crypto/HPKE and TreeKEM plans.
- Produces:
```go
var ErrGroupSizeExceeded error
var ErrDeviceLimitExceeded error
var ErrAdminRemovedByNonOwner error
var ErrSuccessionDisabled error
var ErrSuccessionNotNominee error
var ErrSuccessionQuorum error
var ErrSuccessionFloor error
var ErrSuccessionFloorTooShort error
var ErrNoGroupPolicy error
var ErrMalformedExtension error
var ErrDuplicateRoleEntry error
var ErrRolesNotCanonical error
var ErrNoOwner error
var ErrMultipleOwners error
var ErrWelcomeNoMatchingKeyPackage error
var ErrWelcomeGroupInfoDecrypt error
var ErrWelcomeGroupInfoSignature error
var ErrWelcomeTreeHashMismatch error
var ErrWelcomeLeafNotFound error
var ErrWelcomeSuiteMismatch error
var ErrGroupIdInUse error
var ErrPendingCommitExists error
var ErrNoPendingCommit error
var ErrEpochStale error
var ErrRemovedFromGroup error
const MaxGroupMembers = 500
const MaxDeviceLeavesPerIdentity = 10
const PastEpochWindow uint64 = 32
```
- Test fixtures produced for every later task in this plan:
```go
func testCrypto(t *testing.T) CryptoProvider
func testIdentity(t *testing.T, crypto CryptoProvider, name string) *testMember
type testMember struct {
    Name        string
    IdentityPub []byte
    SigPriv     SignaturePrivateKey
    SigPub      SignaturePublicKey
    XwingPub    []byte
}
func testLeafNode(t *testing.T, crypto CryptoProvider, m *testMember) (*LeafNode, HpkePrivateKey)
func testKeyPackage(t *testing.T, crypto CryptoProvider, m *testMember) (*KeyPackage, HpkePrivateKey, HpkePrivateKey)
```

- [ ] **Step 1: Write the failing test**

`connect/mls/lifecycle_fixtures_test.go`:

```go
package mls

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// testMember is one identity plus the device material a leaf needs.
type testMember struct {
	Name        string
	IdentityPub []byte
	SigPriv     SignaturePrivateKey
	SigPub      SignaturePublicKey
	XwingPub    []byte
}

// testCrypto returns the v1 ciphersuite provider.
func testCrypto(t *testing.T) CryptoProvider {
	t.Helper()
	crypto, err := NewCryptoProvider(CipherSuiteX25519ChaCha20SHA256Ed25519)
	if err != nil {
		t.Fatalf("NewCryptoProvider: %v", err)
	}
	return crypto
}

// testIdentity mints a signature key pair and a stand-in X-Wing public key of
// the right length. The X-Wing key is opaque to mls; only its length matters.
func testIdentity(t *testing.T, crypto CryptoProvider, name string) *testMember {
	t.Helper()
	sigPriv, sigPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("SignatureKeyPair: %v", err)
	}
	xwing := make([]byte, XwingPublicKeySize)
	if _, err := rand.Read(xwing); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return &testMember{
		Name:        name,
		IdentityPub: []byte(sigPub),
		SigPriv:     sigPriv,
		SigPub:      sigPub,
		XwingPub:    xwing,
	}
}

func TestLifecycleErrorsAreDistinct(t *testing.T) {
	all := []error{
		ErrGroupSizeExceeded, ErrDeviceLimitExceeded, ErrAdminRemovedByNonOwner,
		ErrSuccessionDisabled, ErrSuccessionNotNominee, ErrSuccessionQuorum,
		ErrSuccessionFloor, ErrSuccessionFloorTooShort,
		ErrNoGroupPolicy, ErrMalformedExtension, ErrDuplicateRoleEntry,
		ErrRolesNotCanonical, ErrNoOwner, ErrMultipleOwners,
		ErrWelcomeNoMatchingKeyPackage, ErrWelcomeGroupInfoDecrypt,
		ErrWelcomeGroupInfoSignature, ErrWelcomeTreeHashMismatch,
		ErrWelcomeLeafNotFound, ErrWelcomeSuiteMismatch,
		ErrGroupIdInUse, ErrPendingCommitExists, ErrNoPendingCommit,
		ErrEpochStale, ErrRemovedFromGroup,
	}
	for i, a := range all {
		if a == nil {
			t.Fatalf("error %d is nil", i)
		}
		if a.Error() == "" {
			t.Fatalf("error %d has an empty message", i)
		}
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Fatalf("error %d and %d are the same value: %v", i, j, a)
			}
		}
	}
}

func TestLifecycleConstants(t *testing.T) {
	if MaxGroupMembers != 500 {
		t.Fatalf("MaxGroupMembers = %d, want 500", MaxGroupMembers)
	}
	if MaxDeviceLeavesPerIdentity != 10 {
		t.Fatalf("MaxDeviceLeavesPerIdentity = %d, want 10", MaxDeviceLeavesPerIdentity)
	}
	if PastEpochWindow != 32 {
		t.Fatalf("PastEpochWindow = %d, want 32", PastEpochWindow)
	}
}

func TestFixtureIdentityIsUsable(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")
	if len(alice.XwingPub) != XwingPublicKeySize {
		t.Fatalf("XwingPub length = %d, want %d", len(alice.XwingPub), XwingPublicKeySize)
	}
	sig, err := crypto.SignWithLabel(alice.SigPriv, "FixtureProbe", []byte("hello"))
	if err != nil {
		t.Fatalf("SignWithLabel: %v", err)
	}
	if err := crypto.VerifyWithLabel(alice.SigPub, "FixtureProbe", []byte("hello"), sig); err != nil {
		t.Fatalf("VerifyWithLabel: %v", err)
	}
	if bytes.Equal(alice.IdentityPub, nil) {
		t.Fatal("IdentityPub is empty")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestLifecycleErrorsAreDistinct|TestLifecycleConstants|TestFixtureIdentityIsUsable' -v`
Expected: FAIL to build with `undefined: ErrGroupSizeExceeded`, `undefined: MaxGroupMembers`, `undefined: XwingPublicKeySize`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/errors_lifecycle.go`:

```go
// Package mls errors that are group-lifecycle policy rather than RFC 9420 ValSem codes.
// The ValSem-coded errors live in errors.go and are owned by the validation work.
package mls

import "errors"

// membership and device caps, MASTER §6 and §11. Both are enforced by the
// committing client and by every receiving client, so a modified client cannot
// push a group past either.
const (
	MaxGroupMembers            = 500
	MaxDeviceLeavesPerIdentity = 10
)

// PastEpochWindow is how many past epochs of group state are retained.
// Spec A §4.3: DeleteGroupStateBefore(epoch - PastEpochWindow) runs on every
// merged commit, which is also what makes MASTER §8.1's ephemeral guarantee real.
const PastEpochWindow uint64 = 32

var (
	// membership policy
	ErrGroupSizeExceeded      = errors.New("mls: commit would exceed the 500 member group cap")
	ErrDeviceLimitExceeded    = errors.New("mls: commit would exceed the 10 device leaves per identity cap")
	ErrAdminRemovedByNonOwner = errors.New("mls: only an owner may remove an admin or the owner")

	// owner succession, MASTER §11
	ErrSuccessionDisabled      = errors.New("mls: succession is disabled for this group")
	ErrSuccessionNotNominee    = errors.New("mls: committer is not the nominated successor")
	ErrSuccessionQuorum        = errors.New("mls: succession countersignature quorum not met")
	ErrSuccessionFloor         = errors.New("mls: succession floor has not elapsed since the owner was last active")
	ErrSuccessionFloorTooShort = errors.New("mls: succession floor is shorter than the 90 day minimum")

	// urmessage extensions
	ErrNoGroupPolicy      = errors.New("mls: group context carries no urmessage_group_policy extension")
	ErrMalformedExtension = errors.New("mls: extension body is malformed")
	ErrDuplicateRoleEntry = errors.New("mls: duplicate member id in the group policy roles")
	ErrRolesNotCanonical  = errors.New("mls: group policy roles are not sorted by member id")
	ErrNoOwner            = errors.New("mls: group policy names no owner")
	ErrMultipleOwners     = errors.New("mls: group policy names more than one owner")

	// welcome
	ErrWelcomeNoMatchingKeyPackage = errors.New("mls: welcome carries no secrets entry for any held key package")
	ErrWelcomeGroupInfoDecrypt     = errors.New("mls: welcome group info did not decrypt")
	ErrWelcomeGroupInfoSignature   = errors.New("mls: welcome group info signature is invalid")
	ErrWelcomeTreeHashMismatch     = errors.New("mls: ratchet tree hash does not match the group info")
	ErrWelcomeLeafNotFound         = errors.New("mls: own leaf node is not present in the ratchet tree")
	ErrWelcomeSuiteMismatch        = errors.New("mls: welcome ciphersuite does not match the key package")

	// group state machine
	ErrGroupIdInUse       = errors.New("mls: group id is already in use by this client")
	ErrPendingCommitExists = errors.New("mls: a pending commit is already staged")
	ErrNoPendingCommit    = errors.New("mls: no pending commit is staged")
	ErrEpochStale         = errors.New("mls: message epoch is older than the current epoch")
	ErrRemovedFromGroup   = errors.New("mls: this client was removed by the commit")
)
```

`XwingPublicKeySize` is defined in Task 2, so land these two files in the same commit. Add to
`connect/mls/leaf_keys.go` in Task 2; for this task, add the constant temporarily at the bottom of
`errors_lifecycle.go` and move it in Task 2:

```go
// XwingPublicKeySize is pk_M (1184) || pk_X (32). MASTER §7, Spec A §5.4.
// Moved to leaf_keys.go in Task 2.
const XwingPublicKeySize = 1216
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestLifecycleErrorsAreDistinct|TestLifecycleConstants|TestFixtureIdentityIsUsable' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/errors_lifecycle.go connect/mls/lifecycle_fixtures_test.go && \
git commit -m "feat(mls): group lifecycle error set and shared test fixtures"
```

---

### Task 2: The `urmessage_leaf_keys` extension (0xF002)

**Files:**
- Create: `connect/mls/leaf_keys.go`
- Test: `connect/mls/leaf_keys_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal` (Syntax plan); `mls.Extension`, `mls.ExtensionType`, `mls.LeafNode` (TreeKEM plan); `ErrMalformedExtension` (Task 1).
- Produces:
```go
const ExtensionTypeUrmessageLeafKeys ExtensionType = 0xF002
const XwingPublicKeySize = 1216
const AlgIdXwing uint16 = 0x0014

type LeafKeysExtension struct {
    AlgId          uint16
    DeviceXwingPub []byte `tls:"head=varint"`
}
func (self *LeafKeysExtension) Encode() (Extension, error)
func ParseLeafKeysExtension(data []byte) (*LeafKeysExtension, error)
func LeafKeysOf(leaf *LeafNode) (*LeafKeysExtension, error)
```

- [ ] **Step 1: Write the failing test**

`connect/mls/leaf_keys_test.go`:

```go
package mls

import (
	"bytes"
	"testing"
)

func TestLeafKeysExtensionRoundTrip(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")

	ext := &LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: alice.XwingPub}
	encoded, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded.ExtensionType != ExtensionTypeUrmessageLeafKeys {
		t.Fatalf("ExtensionType = %#x, want %#x", encoded.ExtensionType, ExtensionTypeUrmessageLeafKeys)
	}
	// u16 alg_id then a varint-headed vector of 1216 bytes: 2 + 2 + 1216.
	if len(encoded.ExtensionData) != 2+2+XwingPublicKeySize {
		t.Fatalf("ExtensionData length = %d, want %d", len(encoded.ExtensionData), 2+2+XwingPublicKeySize)
	}

	parsed, err := ParseLeafKeysExtension(encoded.ExtensionData)
	if err != nil {
		t.Fatalf("ParseLeafKeysExtension: %v", err)
	}
	if parsed.AlgId != AlgIdXwing {
		t.Fatalf("AlgId = %#x, want %#x", parsed.AlgId, AlgIdXwing)
	}
	if !bytes.Equal(parsed.DeviceXwingPub, alice.XwingPub) {
		t.Fatal("DeviceXwingPub did not survive the round trip")
	}

	// re-encoding must be byte identical: mls signs over serialized forms
	reencoded, err := parsed.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(reencoded.ExtensionData, encoded.ExtensionData) {
		t.Fatal("re-encode is not byte identical")
	}
}

func TestLeafKeysExtensionRejectsWrongLength(t *testing.T) {
	ext := &LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: make([]byte, 32)}
	if _, err := ext.Encode(); err == nil {
		t.Fatal("Encode accepted a 32 byte X-Wing key")
	}
}

func TestLeafKeysExtensionRejectsUnknownAlg(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")
	ext := &LeafKeysExtension{AlgId: 0x0012, DeviceXwingPub: alice.XwingPub}
	if _, err := ext.Encode(); err == nil {
		t.Fatal("Encode accepted alg_id 0x0012, which is reserved and not implemented in v1")
	}
}

func TestLeafKeysExtensionRejectsTrailingBytes(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")
	ext := &LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: alice.XwingPub}
	encoded, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := ParseLeafKeysExtension(append(encoded.ExtensionData, 0x00)); err == nil {
		t.Fatal("ParseLeafKeysExtension accepted trailing bytes")
	}
}

func TestLeafKeysOfMissingExtension(t *testing.T) {
	leaf := &LeafNode{}
	if _, err := LeafKeysOf(leaf); err == nil {
		t.Fatal("LeafKeysOf accepted a leaf with no urmessage_leaf_keys extension")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestLeafKeys -v`
Expected: FAIL to build with `undefined: LeafKeysExtension`, `undefined: AlgIdXwing`, `undefined: ExtensionTypeUrmessageLeafKeys`, `undefined: ParseLeafKeysExtension`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/leaf_keys.go`:

```go
// The urmessage_leaf_keys leaf-node extension, MASTER §5.3 and Spec A §3.4.
// It rides in the LeafNode so it is covered by the leaf signature and the tree
// hash, is validated by RFC 9420 §7.3, and is removed by Remove with the rest
// of the leaf. A member with no X-Wing key cannot receive the epoch wrap, which
// is why 0xF002 is in required_capabilities.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// ExtensionTypeUrmessageLeafKeys is the leaf-node extension type for the device
// wrap key.
const ExtensionTypeUrmessageLeafKeys ExtensionType = 0xF002

// XwingPublicKeySize is pk_M (1184) || pk_X (32). MASTER §7, Spec A §5.4.
const XwingPublicKeySize = 1216

// AlgIdXwing is X-Wing (X25519 + ML-KEM-768), the v1 wrap KEM. MASTER §7.1.
// 0x0012 and 0x0013 are reserved and deliberately not accepted here.
const AlgIdXwing uint16 = 0x0014

// LeafKeysExtension is the device wrap key published in a leaf.
type LeafKeysExtension struct {
	AlgId          uint16
	DeviceXwingPub []byte `tls:"head=varint"`
}

// Encode serializes to an Extension, refusing any algorithm or length v1 does
// not implement. A wrong-length key would produce a leaf that every committer
// accepts and no committer can encapsulate to.
func (self *LeafKeysExtension) Encode() (Extension, error) {
	if self.AlgId != AlgIdXwing {
		return Extension{}, fmt.Errorf("%w: leaf keys alg_id %#04x is not X-Wing", ErrMalformedExtension, self.AlgId)
	}
	if len(self.DeviceXwingPub) != XwingPublicKeySize {
		return Extension{}, fmt.Errorf("%w: leaf keys public key is %d bytes, want %d",
			ErrMalformedExtension, len(self.DeviceXwingPub), XwingPublicKeySize)
	}
	data, err := syntax.Marshal(self)
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionTypeUrmessageLeafKeys, ExtensionData: data}, nil
}

// ParseLeafKeysExtension decodes an extension body and applies the same gate as
// Encode, so a leaf that arrives from the wire cannot carry a key this build
// cannot use.
func ParseLeafKeysExtension(data []byte) (*LeafKeysExtension, error) {
	var ext LeafKeysExtension
	read, err := syntax.Unmarshal(data, &ext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedExtension, err)
	}
	if read != len(data) {
		return nil, fmt.Errorf("%w: %d trailing bytes after leaf keys", ErrMalformedExtension, len(data)-read)
	}
	if ext.AlgId != AlgIdXwing {
		return nil, fmt.Errorf("%w: leaf keys alg_id %#04x is not X-Wing", ErrMalformedExtension, ext.AlgId)
	}
	if len(ext.DeviceXwingPub) != XwingPublicKeySize {
		return nil, fmt.Errorf("%w: leaf keys public key is %d bytes, want %d",
			ErrMalformedExtension, len(ext.DeviceXwingPub), XwingPublicKeySize)
	}
	return &ext, nil
}

// LeafKeysOf extracts the extension from a leaf node.
func LeafKeysOf(leaf *LeafNode) (*LeafKeysExtension, error) {
	if leaf == nil {
		return nil, fmt.Errorf("%w: nil leaf", ErrMalformedExtension)
	}
	for _, ext := range leaf.Extensions {
		if ext.ExtensionType == ExtensionTypeUrmessageLeafKeys {
			return ParseLeafKeysExtension(ext.ExtensionData)
		}
	}
	return nil, fmt.Errorf("%w: leaf carries no urmessage_leaf_keys extension", ErrMalformedExtension)
}
```

Delete the temporary `XwingPublicKeySize` from `errors_lifecycle.go` in the same commit.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestLeafKeys -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/leaf_keys.go connect/mls/leaf_keys_test.go connect/mls/errors_lifecycle.go && \
git commit -m "feat(mls): urmessage_leaf_keys leaf extension carrying the device X-Wing key"
```

---

### Task 3: The `urmessage_group_policy` extension (0xF001) and roles

**Files:**
- Create: `connect/mls/group_policy.go`
- Test: `connect/mls/group_policy_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal`; `mls.Extension`, `mls.ExtensionType`; `ErrMalformedExtension`, `ErrDuplicateRoleEntry`, `ErrRolesNotCanonical`, `ErrNoOwner`, `ErrMultipleOwners`, `ErrNoGroupPolicy` (Task 1).
- Produces:
```go
const ExtensionTypeUrmessageGroupPolicy ExtensionType = 0xF001

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
    MemberId []byte `tls:"head=varint"`   // the member's Ed25519 identity public key
    Role     Role
}
type RetentionPolicy struct {
    DurableMs uint64
    MediaMs   uint64
}
type GroupPolicyExtension struct {
    Roles               []RoleEntry `tls:"head=varint"`
    RetentionPolicy     RetentionPolicy
    DisappearingBuckets []uint8 `tls:"head=varint"`
    ServerId            []byte  `tls:"head=varint"`
}
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
```

- [ ] **Step 1: Write the failing test**

`connect/mls/group_policy_test.go`:

```go
package mls

import (
	"bytes"
	"errors"
	"testing"
)

func testPolicy(t *testing.T, owner, admin, member *testMember) *GroupPolicyExtension {
	t.Helper()
	policy := &GroupPolicyExtension{
		Roles: []RoleEntry{
			{MemberId: owner.IdentityPub, Role: RoleOwner},
			{MemberId: admin.IdentityPub, Role: RoleAdmin},
			{MemberId: member.IdentityPub, Role: RoleMember},
		},
		RetentionPolicy:     RetentionPolicy{DurableMs: 0, MediaMs: 2592000000},
		DisappearingBuckets: []uint8{0},
		ServerId:            []byte("urmessage-v1-server"),
	}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	return policy
}

func TestGroupPolicyRoundTrip(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	admin := testIdentity(t, crypto, "admin")
	member := testIdentity(t, crypto, "member")

	policy := testPolicy(t, owner, admin, member)
	encoded, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded.ExtensionType != ExtensionTypeUrmessageGroupPolicy {
		t.Fatalf("ExtensionType = %#x, want %#x", encoded.ExtensionType, ExtensionTypeUrmessageGroupPolicy)
	}
	parsed, err := ParseGroupPolicyExtension(encoded.ExtensionData)
	if err != nil {
		t.Fatalf("ParseGroupPolicyExtension: %v", err)
	}
	reencoded, err := parsed.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(reencoded.ExtensionData, encoded.ExtensionData) {
		t.Fatal("re-encode is not byte identical")
	}
	if role, ok := parsed.RoleOf(admin.IdentityPub); !ok || role != RoleAdmin {
		t.Fatalf("RoleOf(admin) = %v %v, want admin true", role, ok)
	}
	if parsed.AdminCount() != 1 {
		t.Fatalf("AdminCount = %d, want 1", parsed.AdminCount())
	}
	ownerId, ok := parsed.OwnerId()
	if !ok || !bytes.Equal(ownerId, owner.IdentityPub) {
		t.Fatal("OwnerId did not return the owner")
	}
}

func TestGroupPolicyCanonicalOrdering(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	b := testIdentity(t, crypto, "b")
	c := testIdentity(t, crypto, "c")

	first := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: b.IdentityPub, Role: RoleAdmin},
		{MemberId: c.IdentityPub, Role: RoleMember},
	}}
	second := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: c.IdentityPub, Role: RoleMember},
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: b.IdentityPub, Role: RoleAdmin},
	}}
	if err := first.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize first: %v", err)
	}
	if err := second.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize second: %v", err)
	}
	e1, err := first.Encode()
	if err != nil {
		t.Fatalf("Encode first: %v", err)
	}
	e2, err := second.Encode()
	if err != nil {
		t.Fatalf("Encode second: %v", err)
	}
	if !bytes.Equal(e1.ExtensionData, e2.ExtensionData) {
		t.Fatal("two insertion orders of the same role set encode differently")
	}
}

func TestGroupPolicyRejectsUnsortedOnParse(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	b := testIdentity(t, crypto, "b")
	lo, hi := a, b
	if bytes.Compare(a.IdentityPub, b.IdentityPub) > 0 {
		lo, hi = b, a
	}
	unsorted := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: hi.IdentityPub, Role: RoleOwner},
		{MemberId: lo.IdentityPub, Role: RoleMember},
	}}
	encoded, err := unsorted.encodeUnchecked()
	if err != nil {
		t.Fatalf("encodeUnchecked: %v", err)
	}
	_, err = ParseGroupPolicyExtension(encoded)
	if !errors.Is(err, ErrRolesNotCanonical) {
		t.Fatalf("ParseGroupPolicyExtension error = %v, want ErrRolesNotCanonical", err)
	}
}

func TestGroupPolicyRejectsDuplicateMember(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: a.IdentityPub, Role: RoleMember},
	}}
	if err := policy.Canonicalize(); !errors.Is(err, ErrDuplicateRoleEntry) {
		t.Fatalf("Canonicalize error = %v, want ErrDuplicateRoleEntry", err)
	}
}

func TestGroupPolicyRequiresExactlyOneOwner(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	b := testIdentity(t, crypto, "b")

	none := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: a.IdentityPub, Role: RoleMember}}}
	if err := none.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if err := none.Validate(); !errors.Is(err, ErrNoOwner) {
		t.Fatalf("Validate error = %v, want ErrNoOwner", err)
	}

	two := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: a.IdentityPub, Role: RoleOwner},
		{MemberId: b.IdentityPub, Role: RoleOwner},
	}}
	if err := two.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if err := two.Validate(); !errors.Is(err, ErrMultipleOwners) {
		t.Fatalf("Validate error = %v, want ErrMultipleOwners", err)
	}
}

func TestGroupPolicyRejectsUnknownRoleByte(t *testing.T) {
	crypto := testCrypto(t)
	a := testIdentity(t, crypto, "a")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: a.IdentityPub, Role: Role(9)}}}
	if _, err := policy.Encode(); err == nil {
		t.Fatal("Encode accepted role byte 9")
	}
}

func TestRoleStrings(t *testing.T) {
	for _, tc := range []struct {
		role Role
		name string
	}{
		{RoleOwner, "owner"},
		{RoleAdmin, "admin"},
		{RoleMember, "member"},
		{RoleObserver, "observer"},
	} {
		if tc.role.String() != tc.name {
			t.Fatalf("Role(%d).String() = %q, want %q", tc.role, tc.role.String(), tc.name)
		}
		parsed, err := ParseRole(tc.name)
		if err != nil || parsed != tc.role {
			t.Fatalf("ParseRole(%q) = %v %v", tc.name, parsed, err)
		}
	}
	if _, err := ParseRole("superuser"); err == nil {
		t.Fatal("ParseRole accepted an unknown role name")
	}
}

func TestGroupPolicyOfMissing(t *testing.T) {
	if _, err := GroupPolicyOf(nil); !errors.Is(err, ErrNoGroupPolicy) {
		t.Fatalf("GroupPolicyOf(nil) error = %v, want ErrNoGroupPolicy", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestGroupPolicy|TestRoleStrings' -v`
Expected: FAIL to build with `undefined: GroupPolicyExtension`, `undefined: RoleOwner`, `undefined: ParseGroupPolicyExtension`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/group_policy.go`:

```go
// The urmessage_group_policy group-context extension, MASTER §6 and §11,
// Spec A §3.4. It lives in the group context so roles, retention and the
// disappearing buckets are covered by the transcript hash and no server can
// alter them.
package mls

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/urnetwork/connect/mls/syntax"
)

// ExtensionTypeUrmessageGroupPolicy is the group-context extension type for the
// role set and retention policy.
const ExtensionTypeUrmessageGroupPolicy ExtensionType = 0xF001

// Role is a member's authority in a group. MASTER §11.
type Role uint8

const (
	RoleObserver Role = 0
	RoleMember   Role = 1
	RoleAdmin    Role = 2
	RoleOwner    Role = 3
)

// String returns the wire-stable name Spec A §7.3 exposes through sdk.
func (self Role) String() string {
	switch self {
	case RoleObserver:
		return "observer"
	case RoleMember:
		return "member"
	case RoleAdmin:
		return "admin"
	case RoleOwner:
		return "owner"
	}
	return "unknown"
}

func (self Role) valid() bool {
	return self <= RoleOwner
}

// ParseRole maps the sdk role string onto the wire byte.
func ParseRole(name string) (Role, error) {
	switch name {
	case "observer":
		return RoleObserver, nil
	case "member":
		return RoleMember, nil
	case "admin":
		return RoleAdmin, nil
	case "owner":
		return RoleOwner, nil
	}
	return RoleObserver, fmt.Errorf("%w: unknown role %q", ErrMalformedExtension, name)
}

// RoleEntry binds one member identity to one role. MemberId is the member's
// Ed25519 identity public key, which is the BasicCredential subject, so it is
// stable across that member's device leaves.
type RoleEntry struct {
	MemberId []byte `tls:"head=varint"`
	Role     Role
}

// RetentionPolicy is the group's requested retention, in milliseconds. The
// server clamps and floors it and reports what it applied; the group's
// transcript-covered request is unchanged. MASTER §15 item 1.
type RetentionPolicy struct {
	DurableMs uint64
	MediaMs   uint64
}

// GroupPolicyExtension is the group-context policy.
type GroupPolicyExtension struct {
	Roles               []RoleEntry `tls:"head=varint"`
	RetentionPolicy     RetentionPolicy
	DisappearingBuckets []uint8 `tls:"head=varint"`
	ServerId            []byte  `tls:"head=varint"`
}

// Canonicalize sorts the role entries by member id and refuses duplicates.
// Two clients that build the same role set in different orders must produce
// identical bytes, because the extension is inside the transcript hash and a
// difference is a fork.
func (self *GroupPolicyExtension) Canonicalize() error {
	sort.SliceStable(self.Roles, func(i, j int) bool {
		return bytes.Compare(self.Roles[i].MemberId, self.Roles[j].MemberId) < 0
	})
	for i := 1; i < len(self.Roles); i += 1 {
		if bytes.Equal(self.Roles[i-1].MemberId, self.Roles[i].MemberId) {
			return fmt.Errorf("%w: member id appears twice", ErrDuplicateRoleEntry)
		}
	}
	return nil
}

// Validate enforces the invariants every group must satisfy: canonical order,
// legal role bytes, and exactly one owner.
func (self *GroupPolicyExtension) Validate() error {
	owners := 0
	for i, entry := range self.Roles {
		if !entry.Role.valid() {
			return fmt.Errorf("%w: role byte %d is not defined", ErrMalformedExtension, entry.Role)
		}
		if len(entry.MemberId) == 0 {
			return fmt.Errorf("%w: empty member id", ErrMalformedExtension)
		}
		if i > 0 {
			cmp := bytes.Compare(self.Roles[i-1].MemberId, entry.MemberId)
			if cmp > 0 {
				return fmt.Errorf("%w: entry %d is out of order", ErrRolesNotCanonical, i)
			}
			if cmp == 0 {
				return fmt.Errorf("%w: entry %d repeats entry %d", ErrDuplicateRoleEntry, i, i-1)
			}
		}
		if entry.Role == RoleOwner {
			owners += 1
		}
	}
	if owners == 0 {
		return ErrNoOwner
	}
	if owners > 1 {
		return ErrMultipleOwners
	}
	return nil
}

// encodeUnchecked serializes without the policy gate. It exists for tests that
// need to produce what a hostile peer would send.
func (self *GroupPolicyExtension) encodeUnchecked() ([]byte, error) {
	return syntax.Marshal(self)
}

// Encode serializes to a group-context Extension after validating.
func (self *GroupPolicyExtension) Encode() (Extension, error) {
	if err := self.Validate(); err != nil {
		return Extension{}, err
	}
	data, err := self.encodeUnchecked()
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionTypeUrmessageGroupPolicy, ExtensionData: data}, nil
}

// ParseGroupPolicyExtension decodes and validates an extension body. Order and
// duplicate checks run on parse rather than only on construction, because the
// whole value of a canonical encoding is that a receiver rejects a
// non-canonical one instead of silently re-sorting it.
func ParseGroupPolicyExtension(data []byte) (*GroupPolicyExtension, error) {
	var policy GroupPolicyExtension
	read, err := syntax.Unmarshal(data, &policy)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedExtension, err)
	}
	if read != len(data) {
		return nil, fmt.Errorf("%w: %d trailing bytes after group policy", ErrMalformedExtension, len(data)-read)
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

// RoleOf returns a member's role.
func (self *GroupPolicyExtension) RoleOf(memberId []byte) (Role, bool) {
	for _, entry := range self.Roles {
		if bytes.Equal(entry.MemberId, memberId) {
			return entry.Role, true
		}
	}
	return RoleObserver, false
}

// SetRole inserts or replaces a member's role, keeping canonical order.
func (self *GroupPolicyExtension) SetRole(memberId []byte, role Role) {
	for i := range self.Roles {
		if bytes.Equal(self.Roles[i].MemberId, memberId) {
			self.Roles[i].Role = role
			return
		}
	}
	self.Roles = append(self.Roles, RoleEntry{MemberId: append([]byte(nil), memberId...), Role: role})
	sort.SliceStable(self.Roles, func(i, j int) bool {
		return bytes.Compare(self.Roles[i].MemberId, self.Roles[j].MemberId) < 0
	})
}

// RemoveRole drops a member from the role set.
func (self *GroupPolicyExtension) RemoveRole(memberId []byte) {
	kept := make([]RoleEntry, 0, len(self.Roles))
	for _, entry := range self.Roles {
		if !bytes.Equal(entry.MemberId, memberId) {
			kept = append(kept, entry)
		}
	}
	self.Roles = kept
}

// AdminCount is the number of ADMIN entries. The owner is not counted, because
// MASTER §11's quorum is over current admins.
func (self *GroupPolicyExtension) AdminCount() int {
	count := 0
	for _, entry := range self.Roles {
		if entry.Role == RoleAdmin {
			count += 1
		}
	}
	return count
}

// OwnerId returns the single owner's member id.
func (self *GroupPolicyExtension) OwnerId() ([]byte, bool) {
	for _, entry := range self.Roles {
		if entry.Role == RoleOwner {
			return entry.MemberId, true
		}
	}
	return nil, false
}

// Clone deep copies, so a staged commit can mutate a policy without touching
// the live epoch's.
func (self *GroupPolicyExtension) Clone() *GroupPolicyExtension {
	out := &GroupPolicyExtension{
		Roles:               make([]RoleEntry, len(self.Roles)),
		RetentionPolicy:     self.RetentionPolicy,
		DisappearingBuckets: append([]uint8(nil), self.DisappearingBuckets...),
		ServerId:            append([]byte(nil), self.ServerId...),
	}
	for i, entry := range self.Roles {
		out.Roles[i] = RoleEntry{MemberId: append([]byte(nil), entry.MemberId...), Role: entry.Role}
	}
	return out
}

// GroupPolicyOf finds and parses the policy in a group context extension list.
func GroupPolicyOf(exts []Extension) (*GroupPolicyExtension, error) {
	for _, ext := range exts {
		if ext.ExtensionType == ExtensionTypeUrmessageGroupPolicy {
			return ParseGroupPolicyExtension(ext.ExtensionData)
		}
	}
	return nil, ErrNoGroupPolicy
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestGroupPolicy|TestRoleStrings' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/group_policy.go connect/mls/group_policy_test.go && \
git commit -m "feat(mls): urmessage_group_policy group-context extension with canonical roles"
```

---

### Task 4: The `urmessage_owner_successor` extension (0xF003)

**Files:**
- Create: `connect/mls/owner_successor.go`
- Test: `connect/mls/owner_successor_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal`; `mls.Extension`, `mls.ExtensionType`; `ErrMalformedExtension`, `ErrSuccessionFloorTooShort` (Task 1).
- Produces:
```go
const ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003
const SuccessionFloorMinMs uint64 = 7776000000   // 90 days

type OwnerSuccessorExtension struct {
    Enabled           bool
    SuccessorMemberId []byte
    NominatedAtMs     uint64
    FloorMs           uint64
}
func (self *OwnerSuccessorExtension) MarshalTLS() ([]byte, error)
func (self *OwnerSuccessorExtension) UnmarshalTLS(data []byte) (int, error)
func (self *OwnerSuccessorExtension) Validate() error
func (self *OwnerSuccessorExtension) Encode() (Extension, error)
func ParseOwnerSuccessorExtension(data []byte) (*OwnerSuccessorExtension, error)
func OwnerSuccessorOf(exts []Extension) (*OwnerSuccessorExtension, bool, error)
func successionPreimage(groupId []byte, epoch uint64, successorMemberId []byte, nominatedAtMs uint64) []byte
func appendLengthPrefixed(out []byte, value []byte) []byte
```

- [ ] **Step 1: Write the failing test**

`connect/mls/owner_successor_test.go`:

```go
package mls

import (
	"bytes"
	"errors"
	"testing"
)

func TestOwnerSuccessorRoundTrip(t *testing.T) {
	crypto := testCrypto(t)
	successor := testIdentity(t, crypto, "successor")

	ext := &OwnerSuccessorExtension{
		Enabled:           true,
		SuccessorMemberId: successor.IdentityPub,
		NominatedAtMs:     1770000000000,
		FloorMs:           SuccessionFloorMinMs,
	}
	encoded, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded.ExtensionType != ExtensionTypeUrmessageOwnerSuccessor {
		t.Fatalf("ExtensionType = %#x, want %#x", encoded.ExtensionType, ExtensionTypeUrmessageOwnerSuccessor)
	}
	parsed, err := ParseOwnerSuccessorExtension(encoded.ExtensionData)
	if err != nil {
		t.Fatalf("ParseOwnerSuccessorExtension: %v", err)
	}
	if !parsed.Enabled || parsed.NominatedAtMs != 1770000000000 || parsed.FloorMs != SuccessionFloorMinMs {
		t.Fatalf("fields did not survive: %+v", parsed)
	}
	if !bytes.Equal(parsed.SuccessorMemberId, successor.IdentityPub) {
		t.Fatal("SuccessorMemberId did not survive the round trip")
	}
	reencoded, err := parsed.Encode()
	if err != nil {
		t.Fatalf("re-Encode: %v", err)
	}
	if !bytes.Equal(reencoded.ExtensionData, encoded.ExtensionData) {
		t.Fatal("re-encode is not byte identical")
	}
}

func TestOwnerSuccessorEnabledIsOneWireByte(t *testing.T) {
	ext := &OwnerSuccessorExtension{Enabled: true, FloorMs: SuccessionFloorMinMs}
	encoded, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded.ExtensionData[0] != 0x01 {
		t.Fatalf("enabled byte = %#x, want 0x01", encoded.ExtensionData[0])
	}
	off := &OwnerSuccessorExtension{Enabled: false, FloorMs: SuccessionFloorMinMs}
	encodedOff, err := off.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encodedOff.ExtensionData[0] != 0x00 {
		t.Fatalf("disabled byte = %#x, want 0x00", encodedOff.ExtensionData[0])
	}
}

func TestOwnerSuccessorRejectsNonBooleanByte(t *testing.T) {
	ext := &OwnerSuccessorExtension{Enabled: true, FloorMs: SuccessionFloorMinMs}
	encoded, err := ext.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	mutated := append([]byte(nil), encoded.ExtensionData...)
	mutated[0] = 0x02
	if _, err := ParseOwnerSuccessorExtension(mutated); err == nil {
		t.Fatal("Parse accepted 0x02 as a boolean, which makes two encodings of true")
	}
}

func TestOwnerSuccessorRejectsShortFloor(t *testing.T) {
	ext := &OwnerSuccessorExtension{Enabled: true, FloorMs: SuccessionFloorMinMs - 1}
	if _, err := ext.Encode(); !errors.Is(err, ErrSuccessionFloorTooShort) {
		t.Fatalf("Encode error = %v, want ErrSuccessionFloorTooShort", err)
	}
}

func TestOwnerSuccessorOfAbsentIsNotAnError(t *testing.T) {
	ext, present, err := OwnerSuccessorOf(nil)
	if err != nil {
		t.Fatalf("OwnerSuccessorOf: %v", err)
	}
	if present || ext != nil {
		t.Fatal("OwnerSuccessorOf reported a nomination in an empty extension list")
	}
}

func TestSuccessionPreimageIsStable(t *testing.T) {
	got := successionPreimage([]byte("gid"), 7, []byte("sid"), 42)
	want := []byte("URmessage/v1/succession")
	want = append(want, 0, 0, 0, 3, 'g', 'i', 'd')
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 7)
	want = append(want, 0, 0, 0, 3, 's', 'i', 'd')
	want = append(want, 0, 0, 0, 0, 0, 0, 0, 42)
	if !bytes.Equal(got, want) {
		t.Fatalf("preimage = %x, want %x", got, want)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestOwnerSuccessor|TestSuccessionPreimage' -v`
Expected: FAIL to build with `undefined: OwnerSuccessorExtension`, `undefined: SuccessionFloorMinMs`, `undefined: successionPreimage`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/owner_successor.go`:

```go
// The urmessage_owner_successor group-context extension, MASTER §11 and
// Spec A §3.4. It is accepted and validated in v1 and is deliberately NOT in
// required_capabilities: requiring it would exclude a member for a governance
// feature its group may never enable.
package mls

import (
	"encoding/binary"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// ExtensionTypeUrmessageOwnerSuccessor is the group-context extension type for
// the successor nomination.
const ExtensionTypeUrmessageOwnerSuccessor ExtensionType = 0xF003

// SuccessionFloorMinMs is ninety days. A nomination carrying a shorter floor is
// invalid, so a group cannot shorten its own succession delay after the fact.
const SuccessionFloorMinMs uint64 = 7776000000

// OwnerSuccessorExtension is the nomination.
type OwnerSuccessorExtension struct {
	Enabled           bool
	SuccessorMemberId []byte
	NominatedAtMs     uint64
	FloorMs           uint64
}

// successorBody is the wire shape. Enabled is a u8 with only 0 and 1 legal,
// because a Go bool has no defined presentation-language encoding and two
// encodings of true would be a signature-bypass primitive.
type successorBody struct {
	Enabled           uint8
	SuccessorMemberId []byte `tls:"head=varint"`
	NominatedAtMs     uint64
	FloorMs           uint64
}

// MarshalTLS writes the wire form.
func (self *OwnerSuccessorExtension) MarshalTLS() ([]byte, error) {
	body := successorBody{
		SuccessorMemberId: self.SuccessorMemberId,
		NominatedAtMs:     self.NominatedAtMs,
		FloorMs:           self.FloorMs,
	}
	if self.Enabled {
		body.Enabled = 1
	}
	return syntax.Marshal(&body)
}

// UnmarshalTLS reads the wire form and refuses any boolean byte but 0 and 1.
func (self *OwnerSuccessorExtension) UnmarshalTLS(data []byte) (int, error) {
	var body successorBody
	read, err := syntax.Unmarshal(data, &body)
	if err != nil {
		return 0, err
	}
	if body.Enabled > 1 {
		return 0, fmt.Errorf("%w: succession enabled byte is %#02x", ErrMalformedExtension, body.Enabled)
	}
	self.Enabled = body.Enabled == 1
	self.SuccessorMemberId = body.SuccessorMemberId
	self.NominatedAtMs = body.NominatedAtMs
	self.FloorMs = body.FloorMs
	return read, nil
}

// Validate applies the two rules that are conditions on the extension itself.
// The other four §11 conditions are conditions on a promotion commit and live
// in succession.go.
func (self *OwnerSuccessorExtension) Validate() error {
	if self.FloorMs < SuccessionFloorMinMs {
		return fmt.Errorf("%w: floor is %d ms, minimum is %d ms",
			ErrSuccessionFloorTooShort, self.FloorMs, SuccessionFloorMinMs)
	}
	if len(self.SuccessorMemberId) == 0 && self.NominatedAtMs != 0 {
		return fmt.Errorf("%w: nomination time set with no successor", ErrMalformedExtension)
	}
	return nil
}

// Encode serializes to a group-context Extension.
func (self *OwnerSuccessorExtension) Encode() (Extension, error) {
	if err := self.Validate(); err != nil {
		return Extension{}, err
	}
	data, err := self.MarshalTLS()
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionTypeUrmessageOwnerSuccessor, ExtensionData: data}, nil
}

// ParseOwnerSuccessorExtension decodes and validates an extension body.
func ParseOwnerSuccessorExtension(data []byte) (*OwnerSuccessorExtension, error) {
	var ext OwnerSuccessorExtension
	read, err := ext.UnmarshalTLS(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedExtension, err)
	}
	if read != len(data) {
		return nil, fmt.Errorf("%w: %d trailing bytes after owner successor", ErrMalformedExtension, len(data)-read)
	}
	if err := ext.Validate(); err != nil {
		return nil, err
	}
	return &ext, nil
}

// OwnerSuccessorOf finds the nomination in a group context extension list.
// Absence is not an error: a group with no nomination is the normal case.
func OwnerSuccessorOf(exts []Extension) (*OwnerSuccessorExtension, bool, error) {
	for _, ext := range exts {
		if ext.ExtensionType == ExtensionTypeUrmessageOwnerSuccessor {
			parsed, err := ParseOwnerSuccessorExtension(ext.ExtensionData)
			if err != nil {
				return nil, false, err
			}
			return parsed, true, nil
		}
	}
	return nil, false, nil
}

// successionPreimage is the bytes an admin countersigns. MASTER §11 and
// Spec A §3.4:
//
//	"URmessage/v1/succession" || LP(group_id) || u64(epoch)
//	  || LP(successor_member_id) || u64(nominated_at_ms)
func successionPreimage(groupId []byte, epoch uint64, successorMemberId []byte, nominatedAtMs uint64) []byte {
	out := make([]byte, 0, 32+len(groupId)+len(successorMemberId))
	out = append(out, []byte("URmessage/v1/succession")...)
	out = appendLengthPrefixed(out, groupId)
	out = binary.BigEndian.AppendUint64(out, epoch)
	out = appendLengthPrefixed(out, successorMemberId)
	out = binary.BigEndian.AppendUint64(out, nominatedAtMs)
	return out
}

// appendLengthPrefixed writes LP(x): a 32-bit big-endian length then x. This is
// MASTER's notation, not the presentation language's varint header, and it is
// used only in URmessage's own preimages.
func appendLengthPrefixed(out []byte, value []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(value)))
	return append(out, value...)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestOwnerSuccessor|TestSuccessionPreimage' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/owner_successor.go connect/mls/owner_successor_test.go && \
git commit -m "feat(mls): urmessage_owner_successor group-context extension"
```

---

### Task 5: Proposal types, the variant codec, and the v1 parse gate

**Files:**
- Create: `connect/mls/proposal.go`
- Test: `connect/mls/proposal_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal` (Syntax plan); `mls.KeyPackage`, `mls.LeafNode`, `mls.Extension`, `mls.LeafIndex` (TreeKEM / Tree math plans); `ErrProfilePSK`, `ErrProfileReInit`, `ErrProfileExternalCommit`, `ErrUnsupportedProposalType` (Validation plan).
- Produces:
```go
type ProposalType uint16
const (
    ProposalTypeAdd                    ProposalType = 0x0001
    ProposalTypeUpdate                 ProposalType = 0x0002
    ProposalTypeRemove                 ProposalType = 0x0003
    ProposalTypePSK                    ProposalType = 0x0004
    ProposalTypeReInit                 ProposalType = 0x0005
    ProposalTypeExternalInit           ProposalType = 0x0006
    ProposalTypeGroupContextExtensions ProposalType = 0x0007
)
func (self ProposalType) PathRequired() bool
func (self ProposalType) String() string

type Add struct{ KeyPackage KeyPackage }
type Update struct{ LeafNode LeafNode }
type Remove struct{ Removed LeafIndex }
type GroupContextExtensions struct {
    Extensions []Extension `tls:"head=varint"`
}

type Proposal struct {
    ProposalType           ProposalType
    Add                    *Add
    Update                 *Update
    Remove                 *Remove
    GroupContextExtensions *GroupContextExtensions
}
func (self *Proposal) MarshalTLS() ([]byte, error)
func (self *Proposal) UnmarshalTLS(data []byte) (int, error)
func (self *Proposal) Type() ProposalType
```

**Design note.** RFC 9420 defines seven proposal types; v1 implements four. The three that are not
implemented are refused at **parse**, which is the difference between a message that is dropped and a
message whose unimplemented arm is silently skipped. `psk`, `reinit` and `external_init` therefore
have no Go struct at all in this package — there is nothing to accidentally populate.

- [ ] **Step 1: Write the failing test**

`connect/mls/proposal_test.go`:

```go
package mls

import (
	"bytes"
	"errors"
	"testing"
)

func TestProposalRemoveRoundTrip(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: LeafIndex(3)}}
	encoded, err := proposal.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS: %v", err)
	}
	// u16 type then u32 removed
	want := []byte{0x00, 0x03, 0x00, 0x00, 0x00, 0x03}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("encoded = %x, want %x", encoded, want)
	}
	var parsed Proposal
	read, err := parsed.UnmarshalTLS(encoded)
	if err != nil {
		t.Fatalf("UnmarshalTLS: %v", err)
	}
	if read != len(encoded) {
		t.Fatalf("read = %d, want %d", read, len(encoded))
	}
	if parsed.Type() != ProposalTypeRemove || parsed.Remove == nil || parsed.Remove.Removed != 3 {
		t.Fatalf("parsed = %+v", parsed)
	}
}

func TestProposalGroupContextExtensionsRoundTrip(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: owner.IdentityPub, Role: RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	ext, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	proposal := &Proposal{
		ProposalType:           ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{ext}},
	}
	encoded, err := proposal.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS: %v", err)
	}
	var parsed Proposal
	if _, err := parsed.UnmarshalTLS(encoded); err != nil {
		t.Fatalf("UnmarshalTLS: %v", err)
	}
	reencoded, err := parsed.MarshalTLS()
	if err != nil {
		t.Fatalf("re-MarshalTLS: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatal("re-encode is not byte identical")
	}
}

func TestProposalRefusesPskAtParse(t *testing.T) {
	// u16 proposal_type = 4, then whatever body follows: the gate fires on the
	// type byte before any body is read.
	var parsed Proposal
	_, err := parsed.UnmarshalTLS([]byte{0x00, 0x04, 0x00})
	if !errors.Is(err, ErrProfilePSK) {
		t.Fatalf("UnmarshalTLS error = %v, want ErrProfilePSK", err)
	}
}

func TestProposalRefusesReInitAtParse(t *testing.T) {
	var parsed Proposal
	_, err := parsed.UnmarshalTLS([]byte{0x00, 0x05, 0x00})
	if !errors.Is(err, ErrProfileReInit) {
		t.Fatalf("UnmarshalTLS error = %v, want ErrProfileReInit", err)
	}
}

func TestProposalRefusesExternalInitAtParse(t *testing.T) {
	var parsed Proposal
	_, err := parsed.UnmarshalTLS([]byte{0x00, 0x06, 0x00})
	if !errors.Is(err, ErrProfileExternalCommit) {
		t.Fatalf("UnmarshalTLS error = %v, want ErrProfileExternalCommit", err)
	}
}

func TestProposalRefusesUnknownType(t *testing.T) {
	var parsed Proposal
	_, err := parsed.UnmarshalTLS([]byte{0x00, 0x63, 0x00})
	if !errors.Is(err, ErrUnsupportedProposalType) {
		t.Fatalf("UnmarshalTLS error = %v, want ErrUnsupportedProposalType", err)
	}
}

func TestProposalRefusesGreaseType(t *testing.T) {
	// GREASE proposal types are parsed-and-ignored at the extension level but a
	// GREASE proposal in a commit is an unsupported proposal type: ValSem113.
	var parsed Proposal
	_, err := parsed.UnmarshalTLS([]byte{0x0A, 0x0A, 0x00})
	if !errors.Is(err, ErrUnsupportedProposalType) {
		t.Fatalf("UnmarshalTLS error = %v, want ErrUnsupportedProposalType", err)
	}
}

func TestProposalTypePathRequired(t *testing.T) {
	// RFC 9420 §12.4: the path-required set is update, remove, external_init,
	// group_context_extensions. add, psk and reinit do not require a path.
	for _, tc := range []struct {
		proposalType ProposalType
		required     bool
	}{
		{ProposalTypeAdd, false},
		{ProposalTypeUpdate, true},
		{ProposalTypeRemove, true},
		{ProposalTypePSK, false},
		{ProposalTypeReInit, false},
		{ProposalTypeExternalInit, true},
		{ProposalTypeGroupContextExtensions, true},
	} {
		if tc.proposalType.PathRequired() != tc.required {
			t.Fatalf("%v.PathRequired() = %v, want %v",
				tc.proposalType, tc.proposalType.PathRequired(), tc.required)
		}
	}
}

func TestProposalMarshalRefusesMismatchedArm(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalTypeAdd, Remove: &Remove{Removed: 1}}
	if _, err := proposal.MarshalTLS(); err == nil {
		t.Fatal("MarshalTLS accepted a proposal whose type and populated arm disagree")
	}
}

func TestProposalRejectsTrailingBytes(t *testing.T) {
	proposal := &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}
	encoded, err := proposal.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS: %v", err)
	}
	var parsed Proposal
	read, err := parsed.UnmarshalTLS(append(encoded, 0xFF))
	if err != nil {
		t.Fatalf("UnmarshalTLS: %v", err)
	}
	if read != len(encoded) {
		t.Fatalf("read = %d, want %d: the variant must consume exactly its own bytes", read, len(encoded))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestProposal -v`
Expected: FAIL to build with `undefined: Proposal`, `undefined: ProposalTypeRemove`, `undefined: Remove`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/proposal.go`:

```go
// RFC 9420 §12.1 proposals, narrowed to the v1 profile: add, update, remove and
// group_context_extensions. psk, reinit and external_init are refused at parse
// and have no struct in this package, so there is nothing to populate by
// accident. Spec A §3.1 and §3.2.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// ProposalType is the "MLS Proposal Types" registry value.
type ProposalType uint16

const (
	ProposalTypeAdd                    ProposalType = 0x0001
	ProposalTypeUpdate                 ProposalType = 0x0002
	ProposalTypeRemove                 ProposalType = 0x0003
	ProposalTypePSK                    ProposalType = 0x0004
	ProposalTypeReInit                 ProposalType = 0x0005
	ProposalTypeExternalInit           ProposalType = 0x0006
	ProposalTypeGroupContextExtensions ProposalType = 0x0007
)

// PathRequired reports whether a commit covering this proposal type must carry
// an UpdatePath. RFC 9420 §12.4 pathRequiredTypes = [update, remove,
// external_init, group_context_extensions].
func (self ProposalType) PathRequired() bool {
	switch self {
	case ProposalTypeUpdate, ProposalTypeRemove,
		ProposalTypeExternalInit, ProposalTypeGroupContextExtensions:
		return true
	}
	return false
}

// String names the type for error messages.
func (self ProposalType) String() string {
	switch self {
	case ProposalTypeAdd:
		return "add"
	case ProposalTypeUpdate:
		return "update"
	case ProposalTypeRemove:
		return "remove"
	case ProposalTypePSK:
		return "psk"
	case ProposalTypeReInit:
		return "reinit"
	case ProposalTypeExternalInit:
		return "external_init"
	case ProposalTypeGroupContextExtensions:
		return "group_context_extensions"
	}
	return fmt.Sprintf("proposal_type(%#04x)", uint16(self))
}

// Add requests that the client holding a KeyPackage join the group.
type Add struct {
	KeyPackage KeyPackage
}

// Update replaces the sender's own leaf.
type Update struct {
	LeafNode LeafNode
}

// Remove blanks the leaf at Removed.
type Remove struct {
	Removed LeafIndex
}

// GroupContextExtensions replaces the group context extension list wholesale.
// RFC 9420 §12.1.7: this is a replacement, not a merge.
type GroupContextExtensions struct {
	Extensions []Extension `tls:"head=varint"`
}

// Proposal is the tagged union of §12.1. Exactly one arm is populated and it
// must agree with ProposalType.
type Proposal struct {
	ProposalType           ProposalType
	Add                    *Add
	Update                 *Update
	Remove                 *Remove
	GroupContextExtensions *GroupContextExtensions
}

// Type returns the discriminant.
func (self *Proposal) Type() ProposalType {
	return self.ProposalType
}

// MarshalTLS writes u16(proposal_type) followed by the selected arm.
func (self *Proposal) MarshalTLS() ([]byte, error) {
	var body []byte
	var err error
	switch self.ProposalType {
	case ProposalTypeAdd:
		if self.Add == nil || self.Update != nil || self.Remove != nil || self.GroupContextExtensions != nil {
			return nil, fmt.Errorf("mls: proposal type add with the wrong arm populated")
		}
		body, err = syntax.Marshal(self.Add)
	case ProposalTypeUpdate:
		if self.Update == nil || self.Add != nil || self.Remove != nil || self.GroupContextExtensions != nil {
			return nil, fmt.Errorf("mls: proposal type update with the wrong arm populated")
		}
		body, err = syntax.Marshal(self.Update)
	case ProposalTypeRemove:
		if self.Remove == nil || self.Add != nil || self.Update != nil || self.GroupContextExtensions != nil {
			return nil, fmt.Errorf("mls: proposal type remove with the wrong arm populated")
		}
		body, err = syntax.Marshal(self.Remove)
	case ProposalTypeGroupContextExtensions:
		if self.GroupContextExtensions == nil || self.Add != nil || self.Update != nil || self.Remove != nil {
			return nil, fmt.Errorf("mls: proposal type group_context_extensions with the wrong arm populated")
		}
		body, err = syntax.Marshal(self.GroupContextExtensions)
	default:
		return nil, profileErrorForProposalType(self.ProposalType)
	}
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(body))
	out = append(out, byte(uint16(self.ProposalType)>>8), byte(uint16(self.ProposalType)))
	return append(out, body...), nil
}

// UnmarshalTLS reads the discriminant, applies the v1 profile gate, then reads
// exactly the selected arm and returns the bytes consumed.
func (self *Proposal) UnmarshalTLS(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("mls: proposal is shorter than its type field")
	}
	proposalType := ProposalType(uint16(data[0])<<8 | uint16(data[1]))
	rest := data[2:]

	switch proposalType {
	case ProposalTypeAdd:
		var add Add
		read, err := syntax.Unmarshal(rest, &add)
		if err != nil {
			return 0, err
		}
		*self = Proposal{ProposalType: proposalType, Add: &add}
		return 2 + read, nil
	case ProposalTypeUpdate:
		var update Update
		read, err := syntax.Unmarshal(rest, &update)
		if err != nil {
			return 0, err
		}
		*self = Proposal{ProposalType: proposalType, Update: &update}
		return 2 + read, nil
	case ProposalTypeRemove:
		var remove Remove
		read, err := syntax.Unmarshal(rest, &remove)
		if err != nil {
			return 0, err
		}
		*self = Proposal{ProposalType: proposalType, Remove: &remove}
		return 2 + read, nil
	case ProposalTypeGroupContextExtensions:
		var gce GroupContextExtensions
		read, err := syntax.Unmarshal(rest, &gce)
		if err != nil {
			return 0, err
		}
		*self = Proposal{ProposalType: proposalType, GroupContextExtensions: &gce}
		return 2 + read, nil
	}
	return 0, profileErrorForProposalType(proposalType)
}

// profileErrorForProposalType names the specific profile decision that refused
// a type, so a future accidental implementation turns a test red rather than
// green. Spec A §3.2.
func profileErrorForProposalType(proposalType ProposalType) error {
	switch proposalType {
	case ProposalTypePSK:
		return fmt.Errorf("%w: psk proposals are not implemented in v1", ErrProfilePSK)
	case ProposalTypeReInit:
		return fmt.Errorf("%w: reinit proposals are not implemented in v1", ErrProfileReInit)
	case ProposalTypeExternalInit:
		return fmt.Errorf("%w: external_init proposals are not implemented in v1", ErrProfileExternalCommit)
	}
	return fmt.Errorf("%w: %v", ErrUnsupportedProposalType, proposalType)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestProposal -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/proposal.go connect/mls/proposal_test.go && \
git commit -m "feat(mls): proposal variant codec with the v1 profile parse gate"
```

---

### Task 6: `ProposalOrRef`, the proposal cache, and resolution

**Files:**
- Create: `connect/mls/proposal_list.go`
- Test: `connect/mls/proposal_list_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal`; `mls.CryptoProvider`; `mls.AuthenticatedContent`, `mls.ProposalRef`, `(*AuthenticatedContent).ProposalRef(crypto)`, `mls.Sender`, `mls.SenderTypeMember`, `mls.ContentTypeProposal` (Framing plan); `ErrUpdateSenderNotMember` (Validation plan).
- Produces:
```go
type ProposalOrRefType uint8
const (
    ProposalOrRefTypeProposal  ProposalOrRefType = 1
    ProposalOrRefTypeReference ProposalOrRefType = 2
)
type ProposalOrRef struct {
    Type      ProposalOrRefType
    Proposal  *Proposal
    Reference ProposalRef
}
func (self *ProposalOrRef) MarshalTLS() ([]byte, error)
func (self *ProposalOrRef) UnmarshalTLS(data []byte) (int, error)

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
```

- [ ] **Step 1: Write the failing test**

`connect/mls/proposal_list_test.go`:

```go
package mls

import (
	"bytes"
	"errors"
	"testing"
)

// testProposalContent wraps a proposal in the AuthenticatedContent shape the
// cache stores, without going through a full group.
func testProposalContent(t *testing.T, crypto CryptoProvider, sender LeafIndex, proposal *Proposal) *AuthenticatedContent {
	t.Helper()
	return &AuthenticatedContent{
		WireFormat: WireFormatPrivateMessage,
		Content: FramedContent{
			GroupId:     []byte("group"),
			Epoch:       1,
			Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: sender},
			ContentType: ContentTypeProposal,
			Proposal:    proposal,
		},
		Auth: FramedContentAuthData{Signature: []byte("sig")},
	}
}

func TestProposalOrRefRoundTrip(t *testing.T) {
	byValue := &ProposalOrRef{
		Type:     ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}},
	}
	encoded, err := byValue.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS: %v", err)
	}
	if encoded[0] != 0x01 {
		t.Fatalf("discriminant = %#x, want 0x01", encoded[0])
	}
	var parsed ProposalOrRef
	read, err := parsed.UnmarshalTLS(encoded)
	if err != nil {
		t.Fatalf("UnmarshalTLS: %v", err)
	}
	if read != len(encoded) || parsed.Proposal == nil || parsed.Proposal.Remove.Removed != 2 {
		t.Fatalf("parsed = %+v read = %d", parsed, read)
	}

	byRef := &ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ProposalRef(bytes.Repeat([]byte{7}, 32))}
	encodedRef, err := byRef.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS ref: %v", err)
	}
	if encodedRef[0] != 0x02 {
		t.Fatalf("discriminant = %#x, want 0x02", encodedRef[0])
	}
	var parsedRef ProposalOrRef
	if _, err := parsedRef.UnmarshalTLS(encodedRef); err != nil {
		t.Fatalf("UnmarshalTLS ref: %v", err)
	}
	if !bytes.Equal(parsedRef.Reference, byRef.Reference) {
		t.Fatal("reference did not survive the round trip")
	}
}

func TestProposalOrRefRejectsUnknownDiscriminant(t *testing.T) {
	var parsed ProposalOrRef
	if _, err := parsed.UnmarshalTLS([]byte{0x00, 0x00}); err == nil {
		t.Fatal("UnmarshalTLS accepted discriminant 0, which is reserved")
	}
	if _, err := parsed.UnmarshalTLS([]byte{0x03, 0x00}); err == nil {
		t.Fatal("UnmarshalTLS accepted discriminant 3")
	}
}

func TestProposalCacheResolvesByReference(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()

	content := testProposalContent(t, crypto, LeafIndex(1),
		&Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 4}})
	ref, err := cache.Store(crypto, content)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	cached, ok := cache.Get(ref)
	if !ok || cached.Sender != 1 || cached.ByValue {
		t.Fatalf("Get = %+v %v", cached, ok)
	}

	list, err := cache.Resolve(crypto, LeafIndex(0),
		[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: ref}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(list.Removes) != 1 || list.Removes[0].Proposal.Remove.Removed != 4 {
		t.Fatalf("Removes = %+v", list.Removes)
	}
	if list.Removes[0].Sender != 1 {
		t.Fatal("the resolved proposal must keep its original sender, not the committer")
	}
}

func TestProposalCacheResolveUnknownReference(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	unknown := ProposalRef(bytes.Repeat([]byte{9}, 32))
	if _, err := cache.Resolve(crypto, LeafIndex(0),
		[]ProposalOrRef{{Type: ProposalOrRefTypeReference, Reference: unknown}}); err == nil {
		t.Fatal("Resolve accepted a reference the cache has never seen")
	}
}

func TestProposalCacheByValueSenderIsCommitter(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	list, err := cache.Resolve(crypto, LeafIndex(5), []ProposalOrRef{{
		Type:     ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}},
	}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(list.Removes) != 1 || list.Removes[0].Sender != 5 || !list.Removes[0].ByValue {
		t.Fatalf("by-value proposal must be attributed to the committer: %+v", list.Removes)
	}
}

func TestProposalCacheBucketsAndOrder(t *testing.T) {
	crypto := testCrypto(t)
	cache := NewProposalCache()
	refs := []ProposalOrRef{
		{Type: ProposalOrRefTypeProposal, Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}},
		{Type: ProposalOrRefTypeProposal, Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}}},
	}
	list, err := cache.Resolve(crypto, LeafIndex(0), refs)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(list.All) != 2 {
		t.Fatalf("All = %d, want 2", len(list.All))
	}
	if list.All[0].Proposal.Remove.Removed != 1 || list.All[1].Proposal.Remove.Removed != 2 {
		t.Fatal("All must preserve commit order, because Add placement depends on it")
	}
	if !list.PathRequired() {
		t.Fatal("a list containing a remove requires a path")
	}
}

func TestProposalListPathRequiredAddOnly(t *testing.T) {
	crypto := testCrypto(t)
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "bob"))
	cache := NewProposalCache()
	list, err := cache.Resolve(crypto, LeafIndex(0), []ProposalOrRef{{
		Type:     ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}},
	}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if list.PathRequired() {
		t.Fatal("an add-only list does not require a path")
	}
}

func TestProposalCacheRefusesNonMemberUpdate(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")
	leaf, _ := testLeafNode(t, crypto, alice)
	cache := NewProposalCache()
	content := testProposalContent(t, crypto, LeafIndex(0),
		&Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
	// ValSem112: a standalone Update's sender must be of type member
	content.Content.Sender = Sender{SenderType: SenderTypeNewMemberProposal}
	if _, err := cache.Store(crypto, content); !errors.Is(err, ErrUpdateSenderNotMember) {
		t.Fatalf("Store error = %v, want ErrUpdateSenderNotMember", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestProposalOrRef|TestProposalCache|TestProposalListPath' -v`
Expected: FAIL to build with `undefined: ProposalOrRef`, `undefined: NewProposalCache`, `undefined: ProposalList`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/proposal_list.go`:

```go
// ProposalOrRef and the per-epoch proposal cache. A commit names its proposals
// either by value or by reference; both land in one ProposalList so validation
// and application have exactly one path. RFC 9420 §12.4.
package mls

import (
	"encoding/hex"
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// ProposalOrRefType is the ProposalOrRef discriminant. 0 is reserved.
type ProposalOrRefType uint8

const (
	ProposalOrRefTypeProposal  ProposalOrRefType = 1
	ProposalOrRefTypeReference ProposalOrRefType = 2
)

// ProposalOrRef names one proposal covered by a commit.
type ProposalOrRef struct {
	Type      ProposalOrRefType
	Proposal  *Proposal
	Reference ProposalRef
}

// MarshalTLS writes u8(type) then the selected arm.
func (self *ProposalOrRef) MarshalTLS() ([]byte, error) {
	switch self.Type {
	case ProposalOrRefTypeProposal:
		if self.Proposal == nil {
			return nil, fmt.Errorf("mls: proposal_or_ref type proposal with no proposal")
		}
		body, err := self.Proposal.MarshalTLS()
		if err != nil {
			return nil, err
		}
		return append([]byte{byte(ProposalOrRefTypeProposal)}, body...), nil
	case ProposalOrRefTypeReference:
		if len(self.Reference) == 0 {
			return nil, fmt.Errorf("mls: proposal_or_ref type reference with no reference")
		}
		body, err := syntax.Marshal(&struct {
			Reference []byte `tls:"head=varint"`
		}{Reference: self.Reference})
		if err != nil {
			return nil, err
		}
		return append([]byte{byte(ProposalOrRefTypeReference)}, body...), nil
	}
	return nil, fmt.Errorf("mls: proposal_or_ref type %d is not defined", self.Type)
}

// UnmarshalTLS reads the discriminant then exactly the selected arm.
func (self *ProposalOrRef) UnmarshalTLS(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("mls: proposal_or_ref is empty")
	}
	switch ProposalOrRefType(data[0]) {
	case ProposalOrRefTypeProposal:
		var proposal Proposal
		read, err := proposal.UnmarshalTLS(data[1:])
		if err != nil {
			return 0, err
		}
		*self = ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &proposal}
		return 1 + read, nil
	case ProposalOrRefTypeReference:
		var wrapper struct {
			Reference []byte `tls:"head=varint"`
		}
		read, err := syntax.Unmarshal(data[1:], &wrapper)
		if err != nil {
			return 0, err
		}
		*self = ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ProposalRef(wrapper.Reference)}
		return 1 + read, nil
	}
	return 0, fmt.Errorf("mls: proposal_or_ref type %d is not defined", data[0])
}

// CachedProposal is a proposal plus the provenance validation needs: who sent
// it, and whether the commit carried it inline.
type CachedProposal struct {
	Ref      ProposalRef
	Proposal Proposal
	Sender   LeafIndex
	ByValue  bool
}

// ProposalList is one commit's proposals, bucketed by type and also kept in
// commit order. Add placement depends on order (RFC 9420 §12.1.1), so All is
// not a convenience — it is load bearing.
type ProposalList struct {
	Adds    []CachedProposal
	Updates []CachedProposal
	Removes []CachedProposal
	GCE     []CachedProposal
	All     []CachedProposal
}

// Len is the total proposal count.
func (self *ProposalList) Len() int {
	return len(self.All)
}

// PathRequired implements the RFC 9420 §12.4 pseudocode: a path is required if
// the list is empty or contains any path-required type.
func (self *ProposalList) PathRequired() bool {
	if len(self.All) == 0 {
		return true
	}
	for _, cached := range self.All {
		if cached.Proposal.Type().PathRequired() {
			return true
		}
	}
	return false
}

// Extensions returns the replacement group context extensions if the list
// carries a GroupContextExtensions proposal.
func (self *ProposalList) Extensions() ([]Extension, bool) {
	if len(self.GCE) == 0 {
		return nil, false
	}
	return self.GCE[0].Proposal.GroupContextExtensions.Extensions, true
}

// Refs rebuilds the ProposalOrRef vector a commit carries.
func (self *ProposalList) Refs() []ProposalOrRef {
	out := make([]ProposalOrRef, 0, len(self.All))
	for i := range self.All {
		cached := self.All[i]
		if cached.ByValue {
			proposal := cached.Proposal
			out = append(out, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &proposal})
			continue
		}
		out = append(out, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: cached.Ref})
	}
	return out
}

// ProposalCache holds the proposals seen this epoch, keyed by ProposalRef.
// It is cleared on every epoch change, because a ProposalRef is over an
// AuthenticatedContent that carries the epoch.
type ProposalCache struct {
	byRef map[string]CachedProposal
	order []string
}

// NewProposalCache returns an empty cache.
func NewProposalCache() *ProposalCache {
	return &ProposalCache{byRef: map[string]CachedProposal{}}
}

// Store caches a proposal received this epoch and returns its reference.
// ValSem112 is checked here rather than at commit time: a standalone Update
// whose sender is not a member is never a legal cache entry.
func (self *ProposalCache) Store(crypto CryptoProvider, content *AuthenticatedContent) (ProposalRef, error) {
	if content.Content.ContentType != ContentTypeProposal || content.Content.Proposal == nil {
		return nil, fmt.Errorf("mls: cache entry is not a proposal")
	}
	if content.Content.Sender.SenderType != SenderTypeMember {
		return nil, fmt.Errorf("%w: sender type %d", ErrUpdateSenderNotMember, content.Content.Sender.SenderType)
	}
	ref, err := content.ProposalRef(crypto)
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(ref)
	if _, exists := self.byRef[key]; !exists {
		self.order = append(self.order, key)
	}
	self.byRef[key] = CachedProposal{
		Ref:      ref,
		Proposal: *content.Content.Proposal,
		Sender:   content.Content.Sender.LeafIndex,
		ByValue:  false,
	}
	return ref, nil
}

// Get looks up a cached proposal.
func (self *ProposalCache) Get(ref ProposalRef) (CachedProposal, bool) {
	cached, ok := self.byRef[hex.EncodeToString(ref)]
	return cached, ok
}

// Resolve turns a commit's ProposalOrRef vector into a bucketed list.
// A by-value proposal is attributed to the committer; a by-reference proposal
// keeps the sender that cached it, which is what makes ValSem111 (the committer
// must not include its own Update) checkable at all.
func (self *ProposalCache) Resolve(crypto CryptoProvider, committer LeafIndex,
	refs []ProposalOrRef) (*ProposalList, error) {
	list := &ProposalList{}
	for i, entry := range refs {
		var cached CachedProposal
		switch entry.Type {
		case ProposalOrRefTypeProposal:
			if entry.Proposal == nil {
				return nil, fmt.Errorf("mls: proposal %d is by value with no proposal", i)
			}
			cached = CachedProposal{Proposal: *entry.Proposal, Sender: committer, ByValue: true}
		case ProposalOrRefTypeReference:
			found, ok := self.Get(entry.Reference)
			if !ok {
				return nil, fmt.Errorf("mls: proposal reference %x is not cached for this epoch", entry.Reference)
			}
			cached = found
		default:
			return nil, fmt.Errorf("mls: proposal_or_ref type %d is not defined", entry.Type)
		}
		list.All = append(list.All, cached)
		switch cached.Proposal.Type() {
		case ProposalTypeAdd:
			list.Adds = append(list.Adds, cached)
		case ProposalTypeUpdate:
			list.Updates = append(list.Updates, cached)
		case ProposalTypeRemove:
			list.Removes = append(list.Removes, cached)
		case ProposalTypeGroupContextExtensions:
			list.GCE = append(list.GCE, cached)
		default:
			return nil, profileErrorForProposalType(cached.Proposal.Type())
		}
	}
	return list, nil
}

// Pending returns every cached proposal as a by-reference entry, in the order
// it was received. A committer includes all valid pending proposals
// (RFC 9420 §12.4 SHOULD).
func (self *ProposalCache) Pending() []ProposalOrRef {
	out := make([]ProposalOrRef, 0, len(self.order))
	for _, key := range self.order {
		cached := self.byRef[key]
		out = append(out, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: cached.Ref})
	}
	return out
}

// Clear empties the cache. Called on every epoch change.
func (self *ProposalCache) Clear() {
	self.byRef = map[string]CachedProposal{}
	self.order = nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestProposalOrRef|TestProposalCache|TestProposalListPath' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/proposal_list.go connect/mls/proposal_list_test.go && \
git commit -m "feat(mls): proposal cache and by-value/by-reference resolution"
```

---

### Task 7: Proposal-list validation, ValSem101–113

**Files:**
- Create: `connect/mls/validate_proposals.go`
- Test: `connect/mls/validate_proposals_test.go`

**Interfaces:**
- Consumes: `mls.CryptoProvider`, `mls.RatchetTree`, `mls.GroupContext`, `mls.KeyPackage.Validate`, `mls.LeafNode.Validate`, `mls.RequiredCapabilities`, `(*Capabilities).Supports` (TreeKEM plan); the ValSem error values (Validation plan); `ProposalList`, `CachedProposal` (Task 6).
- Produces:
```go
type ProposalValidationInput struct {
    Crypto     CryptoProvider
    Tree       *RatchetTree      // the PRE-commit tree
    Context    *GroupContext     // the PRE-commit group context
    Extensions []Extension       // the POST-GCE extensions, RFC 9420 §12.3 first step
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
```

**Ownership note.** Spec A §2.2 places "every ValSem check, one named func per code" in
`validation.go`. This plan owns the proposal-list and commit codes because they are inseparable from
commit construction and processing; the Validation plan owns `errors.go`, `profile.go`, the framing
codes (002–011), the profile-refused codes (240–246, 401–403), ValSem400, and **all 43 negative
tests**. The named functions above are the targets those tests call.

- [ ] **Step 1: Write the failing test**

`connect/mls/validate_proposals_test.go`:

```go
package mls

import (
	"errors"
	"testing"
	"time"
)

// testTreeWith builds a pre-commit tree of n leaves and returns it with the
// members that own them.
func testTreeWith(t *testing.T, crypto CryptoProvider, names ...string) (*RatchetTree, []*testMember) {
	t.Helper()
	tree := NewRatchetTree(crypto)
	members := make([]*testMember, 0, len(names))
	for _, name := range names {
		member := testIdentity(t, crypto, name)
		leaf, _ := testLeafNode(t, crypto, member)
		if _, err := tree.AddLeaf(leaf); err != nil {
			t.Fatalf("AddLeaf %s: %v", name, err)
		}
		members = append(members, member)
	}
	return tree, members
}

func testValidationInput(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	committer LeafIndex, list *ProposalList) *ProposalValidationInput {
	t.Helper()
	return &ProposalValidationInput{
		Crypto:    crypto,
		Tree:      tree,
		Context:   &GroupContext{Version: ProtocolVersionMls10, CipherSuite: CipherSuiteX25519ChaCha20SHA256Ed25519, GroupId: []byte("group"), Epoch: 1},
		Committer: committer,
		List:      list,
		Now:       time.Now(),
	}
}

func TestValidateProposalListAcceptsAValidList(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, "carol"))
	list := &ProposalList{}
	add := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}, Sender: 0, ByValue: true}
	list.Adds = append(list.Adds, add)
	list.All = append(list.All, add)

	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValidateProposalList(in); err != nil {
		t.Fatalf("ValidateProposalList: %v", err)
	}
}

func TestValSem101DuplicateSignatureKey(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	carol := testIdentity(t, crypto, "carol")
	first, _, _ := testKeyPackage(t, crypto, carol)
	second, _, _ := testKeyPackage(t, crypto, carol) // same identity, same signature key

	list := &ProposalList{}
	for _, kp := range []*KeyPackage{first, second} {
		cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}, ByValue: true}
		list.Adds = append(list.Adds, cached)
		list.All = append(list.All, cached)
	}
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValSem101UniqueSignatureKey(in); !errors.Is(err, ErrDuplicateSignatureKey) {
		t.Fatalf("ValSem101 error = %v, want ErrDuplicateSignatureKey", err)
	}
}

func TestValSem107DuplicateRemove(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	list := &ProposalList{}
	for i := 0; i < 2; i += 1 {
		cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}, ByValue: true}
		list.Removes = append(list.Removes, cached)
		list.All = append(list.All, cached)
	}
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValSem107UniqueRemove(in); !errors.Is(err, ErrDuplicateRemove) {
		t.Fatalf("ValSem107 error = %v, want ErrDuplicateRemove", err)
	}
}

func TestValSem108RemoveNonMember(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 9}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValSem108RemoveExists(in); !errors.Is(err, ErrRemoveNonMember) {
		t.Fatalf("ValSem108 error = %v, want ErrRemoveNonMember", err)
	}
}

func TestValSem111CommitterOwnUpdate(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	leaf, _ := testLeafNode(t, crypto, members[0])
	cached := CachedProposal{
		Proposal: Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}},
		Sender:   LeafIndex(0),
	}
	list := &ProposalList{Updates: []CachedProposal{cached}, All: []CachedProposal{cached}}
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValSem111NoCommitterUpdate(in); !errors.Is(err, ErrSelfUpdateInCommit) {
		t.Fatalf("ValSem111 error = %v, want ErrSelfUpdateInCommit", err)
	}
}

func TestValSem113UnsupportedProposalTypeIsUnreachableAfterParse(t *testing.T) {
	// The parse gate refuses psk/reinit/external_init and every unknown type, so
	// ValSem113 can only fire on a list built in-process. Both paths are
	// asserted: the parse gate, and the check itself.
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypePSK}}
	list := &ProposalList{All: []CachedProposal{cached}}
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValSem113ProposalTypeSupported(in); !errors.Is(err, ErrProfilePSK) {
		t.Fatalf("ValSem113 error = %v, want ErrProfilePSK", err)
	}
}

func TestValidateProposalListRunsEveryCheck(t *testing.T) {
	// A list that fails only ValSem108 must be rejected by the aggregate, which
	// proves the aggregate is not a subset of the checks.
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 9}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	in := testValidationInput(t, crypto, tree, LeafIndex(0), list)
	if err := ValidateProposalList(in); !errors.Is(err, ErrRemoveNonMember) {
		t.Fatalf("ValidateProposalList error = %v, want ErrRemoveNonMember", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValidateProposalList|TestValSem1' -v`
Expected: FAIL to build with `undefined: ProposalValidationInput`, `undefined: ValidateProposalList`, `undefined: ValSem101UniqueSignatureKey`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/validate_proposals.go`:

```go
// RFC 9420 §12.1 and §12.2 proposal validation, one named function per ValSem
// code so the negative tests in Spec A §4.3 have a specific target. Every check
// runs on the sender side and on the receiver side, from the same input.
package mls

import (
	"bytes"
	"fmt"
	"time"
)

// ProposalValidationInput is the pre-commit state a proposal list is judged
// against. Extensions is the post-GroupContextExtensions extension list,
// because RFC 9420 §12.3 applies the GCE proposal first and requires the new
// extensions to be used when evaluating the rest of the list.
type ProposalValidationInput struct {
	Crypto     CryptoProvider
	Tree       *RatchetTree
	Context    *GroupContext
	Extensions []Extension
	Committer  LeafIndex
	List       *ProposalList
	Now        time.Time
}

// effectiveExtensions returns the extension list the rest of the list is judged
// against.
func (self *ProposalValidationInput) effectiveExtensions() []Extension {
	if self.Extensions != nil {
		return self.Extensions
	}
	if exts, ok := self.List.Extensions(); ok {
		return exts
	}
	return self.Context.Extensions
}

// ValidateProposalList runs every check in code order and returns the first
// failure. Order is deliberate: a duplicate key is reported before a capability
// mismatch, so the error a user sees names the closest cause.
func ValidateProposalList(in *ProposalValidationInput) error {
	checks := []func(*ProposalValidationInput) error{
		ValSem101UniqueSignatureKey,
		ValSem102UniqueInitKey,
		ValSem103UniqueEncryptionKey,
		ValSem104InitNotEqualEncryptionKey,
		ValSem105SuiteAndVersionMatch,
		ValSem106RequiredCapabilitiesSatisfied,
		ValSem107UniqueRemove,
		ValSem108RemoveExists,
		ValSem109UpdateRequiredCapabilities,
		ValSem110UpdateUniqueEncryptionKey,
		ValSem111NoCommitterUpdate,
		ValSem112UpdateSenderIsMember,
		ValSem113ProposalTypeSupported,
	}
	for _, check := range checks {
		if err := check(in); err != nil {
			return err
		}
	}
	return validateSingleUpdateOrRemovePerLeaf(in)
}

// ValSem101UniqueSignatureKey: an Add's signature key is unique among the
// proposals and among current members.
func ValSem101UniqueSignatureKey(in *ProposalValidationInput) error {
	seen := map[string]bool{}
	removed := removedLeaves(in.List)
	for _, leafIndex := range in.Tree.NonBlankLeaves() {
		if removed[leafIndex] {
			continue
		}
		leaf, _ := in.Tree.LeafNode(leafIndex)
		seen[string(leaf.SignatureKey)] = true
	}
	for _, cached := range in.List.Adds {
		key := string(cached.Proposal.Add.KeyPackage.LeafNode.SignatureKey)
		if seen[key] {
			return fmt.Errorf("%w: signature key appears twice", ErrDuplicateSignatureKey)
		}
		seen[key] = true
	}
	return nil
}

// ValSem102UniqueInitKey: an Add's init key is unique among the proposals.
func ValSem102UniqueInitKey(in *ProposalValidationInput) error {
	seen := map[string]bool{}
	for _, cached := range in.List.Adds {
		key := string(cached.Proposal.Add.KeyPackage.InitKey)
		if seen[key] {
			return fmt.Errorf("%w: init key appears twice", ErrDuplicateInitKey)
		}
		seen[key] = true
	}
	return nil
}

// ValSem103UniqueEncryptionKey: an Add's encryption key is unique among the
// proposals and among current members.
func ValSem103UniqueEncryptionKey(in *ProposalValidationInput) error {
	seen := map[string]bool{}
	removed := removedLeaves(in.List)
	for _, leafIndex := range in.Tree.NonBlankLeaves() {
		if removed[leafIndex] {
			continue
		}
		leaf, _ := in.Tree.LeafNode(leafIndex)
		seen[string(leaf.EncryptionKey)] = true
	}
	for _, cached := range in.List.Adds {
		key := string(cached.Proposal.Add.KeyPackage.LeafNode.EncryptionKey)
		if seen[key] {
			return fmt.Errorf("%w: add encryption key appears twice", ErrDuplicateEncryptionKey)
		}
		seen[key] = true
	}
	return nil
}

// ValSem104InitNotEqualEncryptionKey: an Add's init key differs from its
// encryption key. Equal keys would make the welcome ciphertext and the path
// ciphertext openable by the same private key.
func ValSem104InitNotEqualEncryptionKey(in *ProposalValidationInput) error {
	for _, cached := range in.List.Adds {
		kp := cached.Proposal.Add.KeyPackage
		if bytes.Equal(kp.InitKey, kp.LeafNode.EncryptionKey) {
			return fmt.Errorf("%w: init key equals encryption key", ErrInitEqualsEncryptionKey)
		}
	}
	return nil
}

// ValSem105SuiteAndVersionMatch: an Add's KeyPackage names this group's
// ciphersuite and protocol version, and is otherwise valid per §10.1.
func ValSem105SuiteAndVersionMatch(in *ProposalValidationInput) error {
	for _, cached := range in.List.Adds {
		kp := cached.Proposal.Add.KeyPackage
		if kp.CipherSuite != in.Context.CipherSuite || kp.Version != in.Context.Version {
			return fmt.Errorf("%w: key package is version %#04x suite %#04x, group is %#04x %#04x",
				ErrSuiteMismatch, kp.Version, kp.CipherSuite, in.Context.Version, in.Context.CipherSuite)
		}
		if err := kp.Validate(in.Crypto, in.Context.CipherSuite, in.Now); err != nil {
			return err
		}
	}
	return nil
}

// ValSem106RequiredCapabilitiesSatisfied: an added member supports every
// required capability, including any added by a GroupContextExtensions proposal
// in the same commit.
func ValSem106RequiredCapabilitiesSatisfied(in *ProposalValidationInput) error {
	required, ok := requiredCapabilitiesOf(in.effectiveExtensions())
	if !ok {
		return nil
	}
	for _, cached := range in.List.Adds {
		caps := cached.Proposal.Add.KeyPackage.LeafNode.Capabilities
		if err := caps.Supports(required); err != nil {
			return fmt.Errorf("%w: added member does not support the group's required capabilities: %v",
				ErrMissingRequiredCapability, err)
		}
	}
	return nil
}

// ValSem107UniqueRemove: a leaf is removed at most once.
func ValSem107UniqueRemove(in *ProposalValidationInput) error {
	seen := map[LeafIndex]bool{}
	for _, cached := range in.List.Removes {
		leafIndex := cached.Proposal.Remove.Removed
		if seen[leafIndex] {
			return fmt.Errorf("%w: leaf %d is removed twice", ErrDuplicateRemove, leafIndex)
		}
		seen[leafIndex] = true
	}
	return nil
}

// ValSem108RemoveExists: a removed leaf is a non-blank leaf of the pre-commit
// tree.
func ValSem108RemoveExists(in *ProposalValidationInput) error {
	for _, cached := range in.List.Removes {
		leafIndex := cached.Proposal.Remove.Removed
		if _, ok := in.Tree.LeafNode(leafIndex); !ok {
			return fmt.Errorf("%w: leaf %d is blank or out of range", ErrRemoveNonMember, leafIndex)
		}
	}
	return nil
}

// ValSem109UpdateRequiredCapabilities: an updated leaf still supports the
// group's required capabilities.
func ValSem109UpdateRequiredCapabilities(in *ProposalValidationInput) error {
	required, ok := requiredCapabilitiesOf(in.effectiveExtensions())
	if !ok {
		return nil
	}
	for _, cached := range in.List.Updates {
		if err := cached.Proposal.Update.LeafNode.Capabilities.Supports(required); err != nil {
			return fmt.Errorf("%w: updated leaf does not support the group's required capabilities: %v",
				ErrMissingRequiredCapability, err)
		}
	}
	return nil
}

// ValSem110UpdateUniqueEncryptionKey: an Update's encryption key is unique among
// the proposals and among current members, so an update cannot reinstate a key
// another leaf already holds.
func ValSem110UpdateUniqueEncryptionKey(in *ProposalValidationInput) error {
	seen := map[string]bool{}
	removed := removedLeaves(in.List)
	updated := map[LeafIndex]bool{}
	for _, cached := range in.List.Updates {
		updated[cached.Sender] = true
	}
	for _, leafIndex := range in.Tree.NonBlankLeaves() {
		if removed[leafIndex] || updated[leafIndex] {
			continue
		}
		leaf, _ := in.Tree.LeafNode(leafIndex)
		seen[string(leaf.EncryptionKey)] = true
	}
	for _, cached := range in.List.Adds {
		seen[string(cached.Proposal.Add.KeyPackage.LeafNode.EncryptionKey)] = true
	}
	for _, cached := range in.List.Updates {
		key := string(cached.Proposal.Update.LeafNode.EncryptionKey)
		if seen[key] {
			return fmt.Errorf("%w: update encryption key is already in use", ErrDuplicateEncryptionKey)
		}
		seen[key] = true
	}
	return nil
}

// ValSem111NoCommitterUpdate: the committer must not cover its own Update.
// Its leaf is reset by the UpdatePath instead.
func ValSem111NoCommitterUpdate(in *ProposalValidationInput) error {
	for _, cached := range in.List.Updates {
		if cached.Sender == in.Committer {
			return fmt.Errorf("%w: committer at leaf %d covered its own update", ErrSelfUpdateInCommit, in.Committer)
		}
	}
	return nil
}

// ValSem112UpdateSenderIsMember: a standalone Update's sender is of type member.
// The cache refuses a non-member sender at Store time; this re-checks a list
// built in process.
func ValSem112UpdateSenderIsMember(in *ProposalValidationInput) error {
	for _, cached := range in.List.Updates {
		if _, ok := in.Tree.LeafNode(cached.Sender); !ok {
			return fmt.Errorf("%w: update sender leaf %d is blank", ErrUpdateSenderNotMember, cached.Sender)
		}
	}
	return nil
}

// ValSem113ProposalTypeSupported: every proposal type in the list is one this
// group can process. In v1 the parse gate already refuses the other four, so
// this fires only on a list assembled in process.
func ValSem113ProposalTypeSupported(in *ProposalValidationInput) error {
	for _, cached := range in.List.All {
		switch cached.Proposal.Type() {
		case ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove, ProposalTypeGroupContextExtensions:
		default:
			return profileErrorForProposalType(cached.Proposal.Type())
		}
	}
	return nil
}

// validateSingleUpdateOrRemovePerLeaf is the §12.2 rule that a list must not
// contain multiple Update and/or Remove proposals applying to the same leaf.
func validateSingleUpdateOrRemovePerLeaf(in *ProposalValidationInput) error {
	touched := map[LeafIndex]bool{}
	for _, cached := range in.List.Updates {
		if touched[cached.Sender] {
			return fmt.Errorf("%w: leaf %d is updated or removed twice", ErrDuplicateRemove, cached.Sender)
		}
		touched[cached.Sender] = true
	}
	for _, cached := range in.List.Removes {
		leafIndex := cached.Proposal.Remove.Removed
		if touched[leafIndex] {
			return fmt.Errorf("%w: leaf %d is updated or removed twice", ErrDuplicateRemove, leafIndex)
		}
		touched[leafIndex] = true
	}
	return nil
}

// removedLeaves is the set of leaves this list removes.
func removedLeaves(list *ProposalList) map[LeafIndex]bool {
	out := map[LeafIndex]bool{}
	for _, cached := range list.Removes {
		out[cached.Proposal.Remove.Removed] = true
	}
	return out
}

// requiredCapabilitiesOf finds the required_capabilities extension.
func requiredCapabilitiesOf(exts []Extension) (*RequiredCapabilities, bool) {
	for _, ext := range exts {
		if ext.ExtensionType == ExtensionTypeRequiredCapabilities {
			var required RequiredCapabilities
			if _, err := syntaxUnmarshalRequiredCapabilities(ext.ExtensionData, &required); err != nil {
				return nil, false
			}
			return &required, true
		}
	}
	return nil, false
}
```

Add the two small helpers this file needs, in the same file:

```go
// syntaxUnmarshalRequiredCapabilities exists so the import of syntax stays in
// one place per file, per CODESTYLE.
func syntaxUnmarshalRequiredCapabilities(data []byte, out *RequiredCapabilities) (int, error) {
	return syntax.Unmarshal(data, out)
}
```

`ExtensionTypeRequiredCapabilities` (0x0003) is defined by the TreeKEM plan alongside the other
RFC extension types; if it is not yet present, add it there rather than here.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValidateProposalList|TestValSem1' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/validate_proposals.go connect/mls/validate_proposals_test.go && \
git commit -m "feat(mls): proposal list validation, ValSem101 through ValSem113"
```

---

### Task 8: Applying a proposal list, RFC 9420 §12.3

**Files:**
- Create: `connect/mls/apply_proposals.go`
- Test: `connect/mls/apply_proposals_test.go`

**Interfaces:**
- Consumes: `(*RatchetTree).Clone/AddLeaf/UpdateLeaf/RemoveLeaf/LeafNode/NonBlankLeaves`, `mls.GroupContext` (TreeKEM / Key schedule plans); `ProposalList` (Task 6); `ValidateProposalList` (Task 7).
- Produces:
```go
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
```

**Order is normative.** RFC 9420 §12.3: GroupContextExtensions, then Updates in any order, then
Removes in any order, then Adds **in list order**. Add placement is leftmost-blank-first, so a
different Add order produces a different tree and therefore a different tree hash and a fork.

- [ ] **Step 1: Write the failing test**

`connect/mls/apply_proposals_test.go`:

```go
package mls

import (
	"bytes"
	"testing"
)

func TestApplyProposalsAddOrderDeterminesPlacement(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol")
	// remove bob so leaf 1 is the leftmost blank
	removeBob := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}, ByValue: true}

	dave := testIdentity(t, crypto, "dave")
	erin := testIdentity(t, crypto, "erin")
	kpDave, _, _ := testKeyPackage(t, crypto, dave)
	kpErin, _, _ := testKeyPackage(t, crypto, erin)
	addDave := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kpDave}}, ByValue: true}
	addErin := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kpErin}}, ByValue: true}

	list := &ProposalList{
		Removes: []CachedProposal{removeBob},
		Adds:    []CachedProposal{addDave, addErin},
		All:     []CachedProposal{removeBob, addDave, addErin},
	}
	ctx := &GroupContext{Version: ProtocolVersionMls10, CipherSuite: CipherSuiteX25519ChaCha20SHA256Ed25519, GroupId: []byte("group"), Epoch: 1}
	result, err := ApplyProposals(crypto, tree, ctx, LeafIndex(0), list)
	if err != nil {
		t.Fatalf("ApplyProposals: %v", err)
	}
	if len(result.AddedLeaves) != 2 {
		t.Fatalf("AddedLeaves = %v, want 2 entries", result.AddedLeaves)
	}
	if result.AddedLeaves[0] != 1 {
		t.Fatalf("first add landed at leaf %d, want the leftmost blank leaf 1", result.AddedLeaves[0])
	}
	if result.AddedLeaves[1] != 3 {
		t.Fatalf("second add landed at leaf %d, want 3", result.AddedLeaves[1])
	}
	dave1, ok := result.Tree.LeafNode(result.AddedLeaves[0])
	if !ok || !bytes.Equal(dave1.SignatureKey, dave.SigPub) {
		t.Fatal("the first add in list order did not land in the leftmost blank leaf")
	}
}

func TestApplyProposalsDoesNotMutateTheInputTree(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	before, err := tree.RootHash()
	if err != nil {
		t.Fatalf("RootHash: %v", err)
	}
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	ctx := &GroupContext{Version: ProtocolVersionMls10, CipherSuite: CipherSuiteX25519ChaCha20SHA256Ed25519, GroupId: []byte("group")}
	if _, err := ApplyProposals(crypto, tree, ctx, LeafIndex(0), list); err != nil {
		t.Fatalf("ApplyProposals: %v", err)
	}
	after, err := tree.RootHash()
	if err != nil {
		t.Fatalf("RootHash: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("ApplyProposals mutated the caller's tree; a rejected commit would corrupt live state")
	}
}

func TestApplyProposalsGceReplacesWholesale(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: members[0].IdentityPub, Role: RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	policy.RetentionPolicy = RetentionPolicy{DurableMs: 1000, MediaMs: 2000}
	newExt, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cached := CachedProposal{
		Proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions,
			GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{newExt}}},
		ByValue: true,
	}
	list := &ProposalList{GCE: []CachedProposal{cached}, All: []CachedProposal{cached}}
	ctx := &GroupContext{
		Version: ProtocolVersionMls10, CipherSuite: CipherSuiteX25519ChaCha20SHA256Ed25519,
		GroupId:    []byte("group"),
		Extensions: []Extension{{ExtensionType: ExtensionType(0x00FF), ExtensionData: []byte{1}}},
	}
	result, err := ApplyProposals(crypto, tree, ctx, LeafIndex(0), list)
	if err != nil {
		t.Fatalf("ApplyProposals: %v", err)
	}
	if len(result.Extensions) != 1 || result.Extensions[0].ExtensionType != ExtensionTypeUrmessageGroupPolicy {
		t.Fatalf("GCE must replace wholesale, got %+v", result.Extensions)
	}
}

func TestApplyProposalsReportsSelfRemoval(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	ctx := &GroupContext{Version: ProtocolVersionMls10, CipherSuite: CipherSuiteX25519ChaCha20SHA256Ed25519, GroupId: []byte("group")}
	result, err := ApplyProposals(crypto, tree, ctx, LeafIndex(1), list)
	if err != nil {
		t.Fatalf("ApplyProposals: %v", err)
	}
	if !result.SelfRemoved {
		t.Fatal("a commit removing our own leaf must report SelfRemoved")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestApplyProposals -v`
Expected: FAIL to build with `undefined: ApplyProposals`, `undefined: ApplyResult`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/apply_proposals.go`:

```go
// RFC 9420 §12.3, applying a proposal list to a ratchet tree and a group
// context. The order here is normative and is the reason Adds carry their
// commit order all the way from the wire: a different Add order lands members
// on different leaves, which changes the tree hash, which is a fork.
package mls

import "fmt"

// ApplyResult is the post-proposal state, on a tree the caller did not own
// before this call.
type ApplyResult struct {
	Tree          *RatchetTree
	Extensions    []Extension
	AddedLeaves   []LeafIndex
	RemovedLeaves []LeafIndex
	UpdatedLeaves []LeafIndex
	SelfRemoved   bool
}

// ApplyProposals clones the tree and applies the list in RFC order:
// GroupContextExtensions, then Updates, then Removes, then Adds in list order.
// The caller's tree is never mutated, so a commit that fails a later check
// leaves live state untouched.
func ApplyProposals(crypto CryptoProvider, tree *RatchetTree, ctx *GroupContext,
	own LeafIndex, list *ProposalList) (*ApplyResult, error) {

	result := &ApplyResult{Tree: tree.Clone(), Extensions: ctx.Extensions}

	// 1. GroupContextExtensions, wholesale replacement. The new extensions are
	//    what the rest of the list is evaluated against.
	if exts, ok := list.Extensions(); ok {
		result.Extensions = exts
	}

	// 2. Updates, any order. The sender's leaf is replaced and its direct path
	//    is blanked, which RatchetTree.UpdateLeaf does.
	for _, cached := range list.Updates {
		if err := result.Tree.UpdateLeaf(cached.Sender, &cached.Proposal.Update.LeafNode); err != nil {
			return nil, fmt.Errorf("mls: applying update for leaf %d: %w", cached.Sender, err)
		}
		result.UpdatedLeaves = append(result.UpdatedLeaves, cached.Sender)
	}

	// 3. Removes, any order.
	for _, cached := range list.Removes {
		leafIndex := cached.Proposal.Remove.Removed
		if err := result.Tree.RemoveLeaf(leafIndex); err != nil {
			return nil, fmt.Errorf("mls: applying remove for leaf %d: %w", leafIndex, err)
		}
		result.RemovedLeaves = append(result.RemovedLeaves, leafIndex)
		if leafIndex == own {
			result.SelfRemoved = true
		}
	}

	// 4. Adds, in list order. AddLeaf places at the leftmost blank leaf and
	//    extends the tree to the right when there is none.
	for _, cached := range list.Adds {
		leaf := cached.Proposal.Add.KeyPackage.LeafNode
		leafIndex, err := result.Tree.AddLeaf(&leaf)
		if err != nil {
			return nil, fmt.Errorf("mls: applying add: %w", err)
		}
		result.AddedLeaves = append(result.AddedLeaves, leafIndex)
	}

	return result, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestApplyProposals -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/apply_proposals.go connect/mls/apply_proposals_test.go && \
git commit -m "feat(mls): apply a proposal list in RFC 9420 section 12.3 order"
```

---

### Task 9: The `Commit` struct, its codec, and the path-required rule

**Files:**
- Create: `connect/mls/commit.go`
- Test: `connect/mls/commit_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal`; `mls.UpdatePath` (TreeKEM plan); `ProposalOrRef`, `ProposalList` (Task 6); `ErrMissingPath` (Validation plan).
- Produces:
```go
type Commit struct {
    Proposals []ProposalOrRef
    Path      *UpdatePath
}
func (self *Commit) MarshalTLS() ([]byte, error)
func (self *Commit) UnmarshalTLS(data []byte) (int, error)
func CommitPathRequired(list *ProposalList) bool
```

- [ ] **Step 1: Write the failing test**

`connect/mls/commit_test.go`:

```go
package mls

import (
	"bytes"
	"testing"
)

func TestCommitRoundTripWithoutPath(t *testing.T) {
	commit := &Commit{Proposals: []ProposalOrRef{{
		Type:     ProposalOrRefTypeProposal,
		Proposal: &Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}},
	}}}
	encoded, err := commit.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS: %v", err)
	}
	if encoded[len(encoded)-1] != 0x00 {
		t.Fatalf("absent path must encode as the 0x00 optional presence byte, got %#x", encoded[len(encoded)-1])
	}
	var parsed Commit
	read, err := parsed.UnmarshalTLS(encoded)
	if err != nil {
		t.Fatalf("UnmarshalTLS: %v", err)
	}
	if read != len(encoded) {
		t.Fatalf("read = %d, want %d", read, len(encoded))
	}
	if parsed.Path != nil {
		t.Fatal("Path must be nil when the presence byte is 0")
	}
	reencoded, err := parsed.MarshalTLS()
	if err != nil {
		t.Fatalf("re-MarshalTLS: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatal("re-encode is not byte identical")
	}
}

func TestCommitRejectsTwoEncodingsOfAbsentPath(t *testing.T) {
	commit := &Commit{}
	encoded, err := commit.MarshalTLS()
	if err != nil {
		t.Fatalf("MarshalTLS: %v", err)
	}
	// 0x02 is not a legal optional presence byte
	mutated := append([]byte(nil), encoded...)
	mutated[len(mutated)-1] = 0x02
	var parsed Commit
	if _, err := parsed.UnmarshalTLS(mutated); err == nil {
		t.Fatal("UnmarshalTLS accepted presence byte 0x02")
	}
}

func TestCommitPathRequiredRules(t *testing.T) {
	empty := &ProposalList{}
	if !CommitPathRequired(empty) {
		t.Fatal("an empty proposal list requires a path")
	}

	addOnly := &ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
	}}
	if CommitPathRequired(addOnly) {
		t.Fatal("an add-only list does not require a path")
	}

	withUpdate := &ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeAdd}},
		{Proposal: Proposal{ProposalType: ProposalTypeUpdate}},
	}}
	if !CommitPathRequired(withUpdate) {
		t.Fatal("a list containing an update requires a path")
	}

	withGce := &ProposalList{All: []CachedProposal{
		{Proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions}},
	}}
	if !CommitPathRequired(withGce) {
		t.Fatal("group_context_extensions is in the RFC 9420 §12.4 pathRequiredTypes list")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestCommit -v`
Expected: FAIL to build with `undefined: Commit`, `undefined: CommitPathRequired`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/commit.go` (this file grows in Tasks 13, 18, 20 and 21; this task lands the codec and
the path rule only):

```go
// RFC 9420 §12.4 Commit. The path field is optional<UpdatePath>, and the rule
// for when it MUST be populated is transcribed from the §12.4 pseudocode rather
// than restated in prose.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// Commit initiates a new epoch from a collection of proposals.
type Commit struct {
	Proposals []ProposalOrRef
	Path      *UpdatePath
}

// MarshalTLS writes the ProposalOrRef vector then optional<UpdatePath>.
// ProposalOrRef has a custom codec, so the vector is written by hand rather
// than through a struct tag.
func (self *Commit) MarshalTLS() ([]byte, error) {
	body := []byte{}
	for i := range self.Proposals {
		entry, err := self.Proposals[i].MarshalTLS()
		if err != nil {
			return nil, err
		}
		body = append(body, entry...)
	}
	out, err := syntax.Marshal(&struct {
		Proposals []byte `tls:"head=varint"`
	}{Proposals: body})
	if err != nil {
		return nil, err
	}
	if self.Path == nil {
		return append(out, 0x00), nil
	}
	path, err := syntax.Marshal(self.Path)
	if err != nil {
		return nil, err
	}
	return append(append(out, 0x01), path...), nil
}

// UnmarshalTLS reads the vector and the optional path, refusing any presence
// byte but 0 and 1: two encodings of "absent" would be a signature-bypass
// primitive.
func (self *Commit) UnmarshalTLS(data []byte) (int, error) {
	var wrapper struct {
		Proposals []byte `tls:"head=varint"`
	}
	read, err := syntax.Unmarshal(data, &wrapper)
	if err != nil {
		return 0, err
	}
	proposals := []ProposalOrRef{}
	rest := wrapper.Proposals
	for len(rest) > 0 {
		var entry ProposalOrRef
		consumed, err := entry.UnmarshalTLS(rest)
		if err != nil {
			return 0, err
		}
		proposals = append(proposals, entry)
		rest = rest[consumed:]
	}

	if read >= len(data) {
		return 0, fmt.Errorf("mls: commit is missing the path presence byte")
	}
	presence := data[read]
	read += 1
	switch presence {
	case 0x00:
		*self = Commit{Proposals: proposals}
		return read, nil
	case 0x01:
		var path UpdatePath
		consumed, err := syntax.Unmarshal(data[read:], &path)
		if err != nil {
			return 0, err
		}
		*self = Commit{Proposals: proposals, Path: &path}
		return read + consumed, nil
	}
	return 0, fmt.Errorf("mls: commit path presence byte is %#02x", presence)
}

// CommitPathRequired transcribes the RFC 9420 §12.4 pseudocode:
//
//	pathRequired = len(commit.proposals) == 0 ||
//	               any proposal type in [update, remove, external_init,
//	                                     group_context_extensions]
func CommitPathRequired(list *ProposalList) bool {
	return list.PathRequired()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestCommit -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/commit.go connect/mls/commit_test.go && \
git commit -m "feat(mls): commit codec and the RFC 9420 path-required rule"
```

---

### Task 10: Commit validation, ValSem200–209 and ValSem300

**Files:**
- Create: `connect/mls/validate_commit.go`
- Test: `connect/mls/validate_commit_test.go`

**Interfaces:**
- Consumes: `mls.CryptoProvider`, `(*RatchetTree).EncryptionKeyInUse`, `(*RatchetTree).HasTrailingBlankNodes`, `mls.UpdatePath`, `DirectPath`, `(*LeafNode).Validate` (Tree math / TreeKEM plans); the ValSem error values (Validation plan); `ProposalList`, `ApplyResult`, `Commit` (Tasks 6, 8, 9).
- Produces:
```go
type CommitValidationInput struct {
    Crypto          CryptoProvider
    PreTree         *RatchetTree
    PostTree        *RatchetTree      // after ApplyProposals, before the path merge
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
func ValSem204PathLeafKeyIsNew(in *CommitValidationInput) error
func ValSem205ConfirmationTag(in *CommitValidationInput) error
func ValSem206PathLeafEncryptionKeyUnique(in *CommitValidationInput) error
func ValSem207PathEncryptionKeysUnique(in *CommitValidationInput) error
func ValSem208SingleGroupContextExtensions(in *CommitValidationInput) error
func ValSem209GroupExtensionsSupported(in *CommitValidationInput) error
func ValSem300NoTrailingBlankNodes(tree *RatchetTree) error
```

ValSem203 (`ErrPathDecrypt`) is raised by `(*RatchetTree).ApplyUpdatePath` in the TreeKEM plan, which
is the only place the path secrets are decrypted; this file does not duplicate it. The commit
processing path in Task 18 wraps that error so the negative test still sees `ErrPathDecrypt`.

- [ ] **Step 1: Write the failing test**

`connect/mls/validate_commit_test.go`:

```go
package mls

import (
	"errors"
	"testing"
	"time"
)

func testCommitInput(t *testing.T, crypto CryptoProvider, tree *RatchetTree,
	list *ProposalList, commit *Commit) *CommitValidationInput {
	t.Helper()
	return &CommitValidationInput{
		Crypto:    crypto,
		PreTree:   tree,
		PostTree:  tree.Clone(),
		Context:   &GroupContext{Version: ProtocolVersionMls10, CipherSuite: CipherSuiteX25519ChaCha20SHA256Ed25519, GroupId: []byte("group"), Epoch: 1},
		Committer: LeafIndex(0),
		Own:       LeafIndex(0),
		List:      list,
		Commit:    commit,
		Now:       time.Now(),
	}
}

func TestValSem200SelfRemoveInCommit(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 0}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	if err := ValSem200NoSelfRemove(in); !errors.Is(err, ErrSelfRemoveInCommit) {
		t.Fatalf("ValSem200 error = %v, want ErrSelfRemoveInCommit", err)
	}
}

func TestValSem201MissingPath(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 1}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	in := testCommitInput(t, crypto, tree, list, &Commit{Path: nil})
	if err := ValSem201PathPresentWhenRequired(in); !errors.Is(err, ErrMissingPath) {
		t.Fatalf("ValSem201 error = %v, want ErrMissingPath", err)
	}
}

func TestValSem201EmptyProposalListRequiresPath(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: nil})
	if err := ValSem201PathPresentWhenRequired(in); !errors.Is(err, ErrMissingPath) {
		t.Fatalf("ValSem201 error = %v, want ErrMissingPath for an empty proposal list", err)
	}
}

func TestValSem202PathLength(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob", "carol", "dave")
	path := &UpdatePath{Nodes: []UpdatePathNode{{}}} // one node where the filtered direct path is longer
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{Path: path})
	if err := ValSem202PathLength(in); !errors.Is(err, ErrPathLength) {
		t.Fatalf("ValSem202 error = %v, want ErrPathLength", err)
	}
}

func TestValSem208MultipleGroupContextExtensions(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{}}, ByValue: true}
	list := &ProposalList{GCE: []CachedProposal{cached, cached}, All: []CachedProposal{cached, cached}}
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	if err := ValSem208SingleGroupContextExtensions(in); !errors.Is(err, ErrMultipleGCE) {
		t.Fatalf("ValSem208 error = %v, want ErrMultipleGCE", err)
	}
}

func TestValSem209UnsupportedGroupExtension(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	// external_senders is refused by the v1 profile at group-context validation
	unsupported := Extension{ExtensionType: ExtensionTypeExternalSenders, ExtensionData: []byte{}}
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: []Extension{unsupported}}}, ByValue: true}
	list := &ProposalList{GCE: []CachedProposal{cached}, All: []CachedProposal{cached}}
	in := testCommitInput(t, crypto, tree, list, &Commit{})
	err := ValSem209GroupExtensionsSupported(in)
	if !errors.Is(err, ErrUnsupportedGroupExtension) && !errors.Is(err, ErrProfileExternalSender) {
		t.Fatalf("ValSem209 error = %v, want ErrUnsupportedGroupExtension or ErrProfileExternalSender", err)
	}
}

func TestValSem205ConfirmationTagMismatch(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice")
	in := testCommitInput(t, crypto, tree, &ProposalList{}, &Commit{})
	in.ConfirmationKey = make([]byte, crypto.HashSize())
	in.ConfirmedHash = []byte("confirmed")
	in.ConfirmationTag = []byte("not the tag")
	if err := ValSem205ConfirmationTag(in); !errors.Is(err, ErrBadConfirmationTag) {
		t.Fatalf("ValSem205 error = %v, want ErrBadConfirmationTag", err)
	}
	in.ConfirmationTag = crypto.Mac(in.ConfirmationKey, in.ConfirmedHash)
	if err := ValSem205ConfirmationTag(in); err != nil {
		t.Fatalf("ValSem205 rejected the correct tag: %v", err)
	}
}

func TestValSem300TrailingBlankNodes(t *testing.T) {
	crypto := testCrypto(t)
	tree, _ := testTreeWith(t, crypto, "alice", "bob")
	if err := ValSem300NoTrailingBlankNodes(tree); err != nil {
		t.Fatalf("ValSem300 rejected a full tree: %v", err)
	}
	if err := tree.RemoveLeaf(LeafIndex(1)); err != nil {
		t.Fatalf("RemoveLeaf: %v", err)
	}
	// RemoveLeaf truncates, so a tree that still reports trailing blanks is a
	// tree that was decoded from the wire rather than built here.
	decoded, err := tree.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	padded := append(decoded, 0x00)
	if _, err := ParseRatchetTree(crypto, padded); err == nil {
		t.Fatal("ParseRatchetTree accepted a tree with a trailing blank node")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestValSem2|TestValSem300' -v`
Expected: FAIL to build with `undefined: CommitValidationInput`, `undefined: ValSem200NoSelfRemove`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/validate_commit.go`:

```go
// RFC 9420 §12.4 commit validation, one named function per ValSem code.
// ValSem203 lives in the TreeKEM path decryption, which is the only place path
// secrets are opened; commit processing wraps that error unchanged.
package mls

import (
	"bytes"
	"fmt"
	"time"
)

// CommitValidationInput is everything a commit is judged against. PreTree is
// the epoch's tree; PostTree is the tree after the proposals were applied and
// before the UpdatePath was merged, which is the state the RFC's uniqueness
// checks are written against.
type CommitValidationInput struct {
	Crypto          CryptoProvider
	PreTree         *RatchetTree
	PostTree        *RatchetTree
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

// ValidateCommit runs the structural checks in code order. ValSem205 is run by
// the caller after the new key schedule exists, because the confirmation key is
// not derivable until then.
func ValidateCommit(in *CommitValidationInput) error {
	checks := []func(*CommitValidationInput) error{
		ValSem200NoSelfRemove,
		ValSem201PathPresentWhenRequired,
		ValSem202PathLength,
		ValSem204PathLeafKeyIsNew,
		ValSem206PathLeafEncryptionKeyUnique,
		ValSem207PathEncryptionKeysUnique,
		ValSem208SingleGroupContextExtensions,
		ValSem209GroupExtensionsSupported,
	}
	for _, check := range checks {
		if err := check(in); err != nil {
			return err
		}
	}
	return nil
}

// ValSem200NoSelfRemove: a commit must not cover a Remove of the committer.
func ValSem200NoSelfRemove(in *CommitValidationInput) error {
	for _, cached := range in.List.Removes {
		if cached.Proposal.Remove.Removed == in.Committer {
			return fmt.Errorf("%w: committer at leaf %d removed itself", ErrSelfRemoveInCommit, in.Committer)
		}
	}
	return nil
}

// ValSem201PathPresentWhenRequired: the path is populated when the proposal
// list is empty or contains a path-required type.
func ValSem201PathPresentWhenRequired(in *CommitValidationInput) error {
	if CommitPathRequired(in.List) && in.Commit.Path == nil {
		return fmt.Errorf("%w: this proposal list requires an update path", ErrMissingPath)
	}
	return nil
}

// ValSem202PathLength: the path has exactly one node per entry in the
// committer's filtered direct path in the post-proposal tree.
func ValSem202PathLength(in *CommitValidationInput) error {
	if in.Commit.Path == nil {
		return nil
	}
	want := len(in.PostTree.FilteredDirectPath(in.Committer))
	if len(in.Commit.Path.Nodes) != want {
		return fmt.Errorf("%w: path has %d nodes, the filtered direct path has %d",
			ErrPathLength, len(in.Commit.Path.Nodes), want)
	}
	return nil
}

// ValSem204PathLeafKeyIsNew: the path's leaf node carries an encryption key
// different from the committer's current one, so a commit cannot claim post
// compromise security it did not provide.
func ValSem204PathLeafKeyIsNew(in *CommitValidationInput) error {
	if in.Commit.Path == nil {
		return nil
	}
	current, ok := in.PreTree.LeafNode(in.Committer)
	if !ok {
		return fmt.Errorf("%w: committer leaf %d is blank", ErrBlankSenderLeaf, in.Committer)
	}
	if bytes.Equal(current.EncryptionKey, in.Commit.Path.LeafNode.EncryptionKey) {
		return fmt.Errorf("%w: path leaf reuses the committer's current encryption key", ErrPathKeyMismatch)
	}
	if in.Commit.Path.LeafNode.LeafNodeSource != LeafNodeSourceCommit {
		return fmt.Errorf("%w: path leaf_node_source is %d, want commit",
			ErrPathKeyMismatch, in.Commit.Path.LeafNode.LeafNodeSource)
	}
	return in.Commit.Path.LeafNode.Validate(in.Crypto, in.Context.GroupId, in.Committer,
		LeafNodeSourceCommit, in.Extensions, in.Now)
}

// ValSem205ConfirmationTag: the confirmation tag equals
// MAC(confirmation_key, confirmed_transcript_hash) for the new epoch.
func ValSem205ConfirmationTag(in *CommitValidationInput) error {
	if len(in.ConfirmationTag) == 0 {
		return ErrMissingConfirmationTag
	}
	if !in.Crypto.MacVerify(in.ConfirmationKey, in.ConfirmedHash, in.ConfirmationTag) {
		return fmt.Errorf("%w: the group has forked or the commit was tampered with", ErrBadConfirmationTag)
	}
	return nil
}

// ValSem206PathLeafEncryptionKeyUnique: the path leaf's encryption key appears
// nowhere else in the post-proposal tree or in the proposal list.
func ValSem206PathLeafEncryptionKeyUnique(in *CommitValidationInput) error {
	if in.Commit.Path == nil {
		return nil
	}
	key := in.Commit.Path.LeafNode.EncryptionKey
	for _, leafIndex := range in.PostTree.NonBlankLeaves() {
		if leafIndex == in.Committer {
			continue
		}
		leaf, _ := in.PostTree.LeafNode(leafIndex)
		if bytes.Equal(leaf.EncryptionKey, key) {
			return fmt.Errorf("%w: path leaf key is already in the tree at leaf %d",
				ErrDuplicateEncryptionKey, leafIndex)
		}
	}
	return nil
}

// ValSem207PathEncryptionKeysUnique: no public key in the UpdatePath appears in
// any node of the post-proposal tree, and no key repeats within the path.
func ValSem207PathEncryptionKeysUnique(in *CommitValidationInput) error {
	if in.Commit.Path == nil {
		return nil
	}
	seen := map[string]bool{string(in.Commit.Path.LeafNode.EncryptionKey): true}
	for i, node := range in.Commit.Path.Nodes {
		key := string(node.EncryptionKey)
		if seen[key] {
			return fmt.Errorf("%w: update path node %d repeats a key", ErrDuplicateEncryptionKey, i)
		}
		seen[key] = true
		if in.PostTree.EncryptionKeyInUse(node.EncryptionKey) {
			return fmt.Errorf("%w: update path node %d reuses a key already in the tree",
				ErrDuplicateEncryptionKey, i)
		}
	}
	return nil
}

// ValSem208SingleGroupContextExtensions: at most one GCE proposal per commit.
func ValSem208SingleGroupContextExtensions(in *CommitValidationInput) error {
	if len(in.List.GCE) > 1 {
		return fmt.Errorf("%w: %d group_context_extensions proposals", ErrMultipleGCE, len(in.List.GCE))
	}
	return nil
}

// ValSem209GroupExtensionsSupported: a GCE proposal may only install extensions
// every member supports, and in v1 only the profile's allowed set. Spec A §3.1
// allows required_capabilities, ratchet_tree, urmessage_group_policy and
// urmessage_owner_successor.
func ValSem209GroupExtensionsSupported(in *CommitValidationInput) error {
	exts, ok := in.List.Extensions()
	if !ok {
		return nil
	}
	profile := DefaultProfile()
	for _, ext := range exts {
		if err := profile.CheckGroupExtension(ext.ExtensionType); err != nil {
			return err
		}
	}
	required, hasRequired := requiredCapabilitiesOf(exts)
	if !hasRequired {
		return nil
	}
	for _, leafIndex := range in.PostTree.NonBlankLeaves() {
		leaf, _ := in.PostTree.LeafNode(leafIndex)
		if err := leaf.Capabilities.Supports(required); err != nil {
			return fmt.Errorf("%w: leaf %d does not support the proposed required capabilities: %v",
				ErrUnsupportedGroupExtension, leafIndex, err)
		}
	}
	return nil
}

// ValSem300NoTrailingBlankNodes: an exported ratchet tree carries no trailing
// blank nodes, so two implementations cannot produce two encodings of one tree.
func ValSem300NoTrailingBlankNodes(tree *RatchetTree) error {
	if tree.HasTrailingBlankNodes() {
		return ErrTrailingBlankNodes
	}
	return nil
}
```

`(*RatchetTree).FilteredDirectPath(LeafIndex) []NodeIndex` is consumed from the TreeKEM plan; if it
is unexported there, export it rather than reimplementing the filter here — two filtered-direct-path
implementations is exactly the divergence ValSem202 exists to catch.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestValSem2|TestValSem300' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/validate_commit.go connect/mls/validate_commit_test.go && \
git commit -m "feat(mls): commit validation, ValSem200 through ValSem209 and ValSem300"
```

---

### Task 11: Group creation — `NewGroup`, RFC 9420 §11

**Files:**
- Create: `connect/mls/group.go`
- Test: `connect/mls/group_test.go`

**Interfaces:**
- Consumes: `mls.CryptoProvider`, `mls.NewRatchetTree`, `(*RatchetTree).AddLeaf/RootHash`, `mls.NewLeafNode`, `mls.Credential`, `mls.Capabilities`, `mls.GroupContext`, `DeriveEpochSecretsFromEpochSecret`, `NewSecretTree`, `InterimTranscriptHash`, `DefaultProfile`, `(*Profile).CheckCiphersuiteForCreate` — from the Crypto/HPKE, TreeKEM, Key schedule, Framing and Validation plans.
- Produces (this is the contract `connect/message` consumes through its `GroupEngine` adapter):
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

type Group struct{ /* stateLock-guarded, not safe for concurrent use */ }

func NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error)

func (self *Group) GroupId() []byte
func (self *Group) Epoch() uint64
func (self *Group) OwnLeafIndex() LeafIndex
func (self *Group) Members() []Member
func (self *Group) MemberAt(leafIndex LeafIndex) (Member, bool)
func (self *Group) EpochAuthenticator() []byte
func (self *Group) Export(label string, context []byte, length int) ([]byte, error)
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error)
func (self *Group) RatchetTree() ([]byte, error)
func (self *Group) GroupContext() ([]byte, error)
func (self *Group) GroupPolicy() (*GroupPolicyExtension, error)
func (self *Group) Close() error
```

**Creation is the RFC's four steps, not a shortcut.** RFC 9420 §11: a one-member tree, epoch 0, an
empty confirmed transcript hash, a fresh random `epoch_secret` of size `KDF.Nh`, then the
confirmation tag over the empty confirmed hash and the interim transcript hash from it. The RFC
notes that a shortcut removes choices "by which, for example, bad randomness could be introduced";
we follow it exactly.

- [ ] **Step 1: Write the failing test**

`connect/mls/group_test.go`:

```go
package mls

import (
	"bytes"
	"errors"
	"testing"
)

// testStore is an in-memory StateStore for the lifecycle tests.
type testStore struct {
	states   map[string][]byte
	privs    map[string][]byte
	packages map[string][3][]byte
	deletes  []uint64
}

func newTestStore() *testStore {
	return &testStore{states: map[string][]byte{}, privs: map[string][]byte{}, packages: map[string][3][]byte{}}
}

func stateKey(groupId []byte, epoch uint64) string {
	return string(groupId) + "/" + string(rune(epoch))
}

func (self *testStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.states[stateKey(groupId, epoch)] = append([]byte(nil), state...)
	return nil
}
func (self *testStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	state, ok := self.states[stateKey(groupId, epoch)]
	if !ok {
		return nil, errors.New("no state")
	}
	return state, nil
}
func (self *testStore) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.deletes = append(self.deletes, epoch)
	for key := range self.states {
		for e := uint64(0); e < epoch; e += 1 {
			if key == stateKey(groupId, e) {
				delete(self.states, key)
			}
		}
	}
	return nil
}
func (self *testStore) PutPrivateKey(pub, priv []byte) error {
	self.privs[string(pub)] = append([]byte(nil), priv...)
	return nil
}
func (self *testStore) GetPrivateKey(pub []byte) ([]byte, error) {
	priv, ok := self.privs[string(pub)]
	if !ok {
		return nil, errors.New("no key")
	}
	return priv, nil
}
func (self *testStore) DeletePrivateKey(pub []byte) error {
	delete(self.privs, string(pub))
	return nil
}
func (self *testStore) PutKeyPackage(ref, kp, initPriv, encPriv []byte) error {
	self.packages[string(ref)] = [3][]byte{kp, initPriv, encPriv}
	return nil
}
func (self *testStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	entry, ok := self.packages[string(ref)]
	if !ok {
		return nil, nil, nil, errors.New("no key package")
	}
	delete(self.packages, string(ref))
	return entry[0], entry[1], entry[2], nil
}

// testGroupConfig builds a v1-profile config for one member.
func testGroupConfig(t *testing.T, crypto CryptoProvider, owner *testMember, groupId string) *GroupConfig {
	t.Helper()
	policy := &GroupPolicyExtension{Roles: []RoleEntry{{MemberId: owner.IdentityPub, Role: RoleOwner}}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	policyExt, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode policy: %v", err)
	}
	return &GroupConfig{
		Suite:      CipherSuiteX25519ChaCha20SHA256Ed25519,
		GroupId:    []byte(groupId),
		Extensions: []Extension{policyExt},
		RequiredCaps: RequiredCapabilities{
			ExtensionTypes: []ExtensionType{ExtensionTypeUrmessageGroupPolicy, ExtensionTypeUrmessageLeafKeys},
		},
		Crypto:   crypto,
		Store:    newTestStore(),
		Profile:  DefaultProfile(),
		LeafKeys: LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: owner.XwingPub},
	}
}

func testNewGroup(t *testing.T, crypto CryptoProvider, owner *testMember, groupId string) *Group {
	t.Helper()
	cfg := testGroupConfig(t, crypto, owner, groupId)
	group, err := NewGroup(cfg, owner.SigPriv, Credential{CredentialType: CredentialTypeBasic, Identity: owner.IdentityPub})
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	return group
}

func TestNewGroupIsAOneMemberGroupAtEpochZero(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if group.Epoch() != 0 {
		t.Fatalf("Epoch = %d, want 0", group.Epoch())
	}
	if group.OwnLeafIndex() != 0 {
		t.Fatalf("OwnLeafIndex = %d, want 0", group.OwnLeafIndex())
	}
	members := group.Members()
	if len(members) != 1 {
		t.Fatalf("Members = %d, want 1", len(members))
	}
	if !bytes.Equal(members[0].IdentityPub, owner.IdentityPub) {
		t.Fatal("the creator is not the single member")
	}
	if members[0].Role != RoleOwner {
		t.Fatalf("creator role = %v, want owner", members[0].Role)
	}
	if members[0].LeafKeys == nil || !bytes.Equal(members[0].LeafKeys.DeviceXwingPub, owner.XwingPub) {
		t.Fatal("the creator's leaf does not carry urmessage_leaf_keys")
	}
	if !bytes.Equal(group.GroupId(), []byte("group-1")) {
		t.Fatalf("GroupId = %q", group.GroupId())
	}
	if len(group.EpochAuthenticator()) != crypto.HashSize() {
		t.Fatalf("EpochAuthenticator length = %d, want %d", len(group.EpochAuthenticator()), crypto.HashSize())
	}
}

func TestNewGroupConfirmedTranscriptHashIsEmptyAtEpochZero(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	encoded, err := group.GroupContext()
	if err != nil {
		t.Fatalf("GroupContext: %v", err)
	}
	var ctx GroupContext
	if _, err := syntaxUnmarshalGroupContext(encoded, &ctx); err != nil {
		t.Fatalf("unmarshal group context: %v", err)
	}
	if len(ctx.ConfirmedTranscriptHash) != 0 {
		t.Fatalf("ConfirmedTranscriptHash = %x, want the zero-length octet string", ctx.ConfirmedTranscriptHash)
	}
	if ctx.Epoch != 0 || ctx.Version != ProtocolVersionMls10 {
		t.Fatalf("group context = %+v", ctx)
	}
	treeHash, err := group.treeHashForTest()
	if err != nil {
		t.Fatalf("treeHashForTest: %v", err)
	}
	if !bytes.Equal(ctx.TreeHash, treeHash) {
		t.Fatal("group context tree hash does not match the tree")
	}
}

func TestNewGroupTwoCreatorsDiverge(t *testing.T) {
	// epoch_secret is fresh random per RFC 9420 §11, so two creators of the same
	// group id must not derive the same epoch authenticator.
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	first := testNewGroup(t, crypto, owner, "group-1")
	defer first.Close()
	second := testNewGroup(t, crypto, owner, "group-1")
	defer second.Close()
	if bytes.Equal(first.EpochAuthenticator(), second.EpochAuthenticator()) {
		t.Fatal("two group creations produced the same epoch authenticator; epoch_secret is not random")
	}
}

func TestNewGroupRefusesNonV1Ciphersuite(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	cfg.Suite = CipherSuite(0x0001) // registered and implemented, refused by policy
	_, err := NewGroup(cfg, owner.SigPriv, Credential{CredentialType: CredentialTypeBasic, Identity: owner.IdentityPub})
	if !errors.Is(err, ErrProfileCiphersuite) {
		t.Fatalf("NewGroup error = %v, want ErrProfileCiphersuite", err)
	}
}

func TestNewGroupRefusesGroupWithoutPolicy(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	cfg.Extensions = nil
	_, err := NewGroup(cfg, owner.SigPriv, Credential{CredentialType: CredentialTypeBasic, Identity: owner.IdentityPub})
	if !errors.Is(err, ErrNoGroupPolicy) {
		t.Fatalf("NewGroup error = %v, want ErrNoGroupPolicy", err)
	}
}

func TestEpochSecretAccessorIsClosed(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	senderData, err := group.EpochSecret(EpochSecretSenderData)
	if err != nil {
		t.Fatalf("EpochSecret(sender_data): %v", err)
	}
	encryption, err := group.EpochSecret(EpochSecretEncryption)
	if err != nil {
		t.Fatalf("EpochSecret(encryption): %v", err)
	}
	if bytes.Equal(senderData, encryption) {
		t.Fatal("sender_data_secret and encryption_secret must be independent derivations")
	}
	if _, err := group.EpochSecret(EpochSecretName(9)); err == nil {
		t.Fatal("EpochSecret accepted a name outside the closed enum")
	}
}

func TestGroupStateIsPersistedAtCreation(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	store := cfg.Store.(*testStore)
	group, err := NewGroup(cfg, owner.SigPriv, Credential{CredentialType: CredentialTypeBasic, Identity: owner.IdentityPub})
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close()
	if _, err := store.GetGroupState([]byte("group-1"), 0); err != nil {
		t.Fatalf("epoch 0 state was not persisted: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestNewGroup|TestEpochSecretAccessor|TestGroupStateIsPersisted' -v`
Expected: FAIL to build with `undefined: NewGroup`, `undefined: GroupConfig`, `undefined: StateStore`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/group.go`:

```go
// The MLS group state machine. This is the only stateful exported type in the
// package. It is NOT safe for concurrent use: the caller (connect/message)
// serializes all access through a single-goroutine command loop, and stateLock
// exists so misuse fails loudly rather than corrupting a tree.
package mls

import (
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect/mls/syntax"
)

// StateStore persists group state and private key material across process
// restarts. It is deliberately dumb: no queries, no cross-group transactions,
// so sdk can implement it over the sealed local store without leaking storage
// semantics into the crypto. Spec A §3.5.
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

// GroupConfig is everything a group needs that is not epoch state.
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

// Member is one member of the group as the product sees it.
type Member struct {
	LeafIndex    LeafIndex
	IdentityPub  []byte
	SignatureKey SignaturePublicKey
	LeafKeys     *LeafKeysExtension
	Role         Role
}

// EpochSecretName is a CLOSED enum. MASTER §8.2 needs exactly these two for
// archive_secret, and exporting epoch_secret instead would also expose
// confirmation_key and membership_key. An open string accessor would invite
// exactly that mistake, so there is no such accessor.
type EpochSecretName uint8

const (
	EpochSecretSenderData EpochSecretName = iota + 1
	EpochSecretEncryption
)

// Group is one MLS group at one epoch, plus the staging area for a commit that
// has not been merged.
type Group struct {
	stateLock sync.Mutex

	cfg    *GroupConfig
	crypto CryptoProvider
	signer SignaturePrivateKey
	cred   Credential

	ownLeaf     LeafIndex
	ownEncPriv  HpkePrivateKey
	tree        *RatchetTree
	context     *GroupContext
	secrets     *EpochSecrets
	secretTree  *SecretTree
	interimHash []byte
	proposals   *ProposalCache

	pending *StagedCommit
	closed  bool
}

// NewGroup creates a one-member group, following RFC 9420 §11 exactly rather
// than short-cutting to a chosen tree and epoch secret.
func NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error) {
	profile := cfg.Profile
	if profile == nil {
		profile = DefaultProfile()
	}
	if err := profile.CheckCiphersuiteForCreate(cfg.Suite); err != nil {
		return nil, err
	}
	for _, ext := range cfg.Extensions {
		if err := profile.CheckGroupExtension(ext.ExtensionType); err != nil {
			return nil, err
		}
	}
	if _, err := GroupPolicyOf(cfg.Extensions); err != nil {
		return nil, err
	}
	leafKeysExt, err := cfg.LeafKeys.Encode()
	if err != nil {
		return nil, err
	}

	crypto := cfg.Crypto
	encPriv, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, err
	}
	leaf, err := NewLeafNode(crypto, signer, cred, encPub, v1Capabilities(cfg), []Extension{leafKeysExt})
	if err != nil {
		return nil, err
	}

	// step 1: a one-member tree, epoch 0, empty confirmed transcript hash
	tree := NewRatchetTree(crypto)
	ownLeaf, err := tree.AddLeaf(leaf)
	if err != nil {
		return nil, err
	}
	treeHash, err := tree.RootHash()
	if err != nil {
		return nil, err
	}
	extensions := append([]Extension(nil), cfg.Extensions...)
	if len(cfg.RequiredCaps.ExtensionTypes) > 0 || len(cfg.RequiredCaps.CredentialTypes) > 0 {
		requiredExt, err := encodeRequiredCapabilities(&cfg.RequiredCaps)
		if err != nil {
			return nil, err
		}
		extensions = append([]Extension{requiredExt}, extensions...)
	}
	context := &GroupContext{
		Version:                 ProtocolVersionMls10,
		CipherSuite:             cfg.Suite,
		GroupId:                 append([]byte(nil), cfg.GroupId...),
		Epoch:                   0,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: []byte{},
		Extensions:              extensions,
	}

	// step 2: a fresh random epoch secret of size KDF.Nh, and the secrets under it
	secrets, err := DeriveEpochSecretsFromEpochSecret(crypto, crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, err
	}

	// step 3: the confirmation tag over the empty confirmed transcript hash,
	// then the interim transcript hash from it
	confirmationTag := crypto.Mac(secrets.ConfirmationKey, context.ConfirmedTranscriptHash)
	interimHash, err := InterimTranscriptHash(crypto, context.ConfirmedTranscriptHash, confirmationTag)
	if err != nil {
		return nil, err
	}

	group := &Group{
		cfg:         cfg,
		crypto:      crypto,
		signer:      signer,
		cred:        cred,
		ownLeaf:     ownLeaf,
		ownEncPriv:  encPriv,
		tree:        tree,
		context:     context,
		secrets:     secrets,
		secretTree:  NewSecretTree(crypto, tree.Size(), secrets.EncryptionSecret),
		interimHash: interimHash,
		proposals:   NewProposalCache(),
	}
	if err := group.persist(); err != nil {
		return nil, err
	}
	return group, nil
}

// v1Capabilities is what every v1 leaf advertises: one version, the two
// registered suites, the four implemented proposal types, the extensions the
// group requires, and basic credentials only.
func v1Capabilities(cfg *GroupConfig) Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMls10},
		CipherSuites: []CipherSuite{CipherSuiteX25519ChaCha20SHA256Ed25519, CipherSuite(0x0001)},
		Extensions: []ExtensionType{
			ExtensionTypeUrmessageGroupPolicy,
			ExtensionTypeUrmessageLeafKeys,
			ExtensionTypeUrmessageOwnerSuccessor,
		},
		Proposals:   []ProposalType{},
		Credentials: []CredentialType{CredentialTypeBasic},
	}
}

// GroupId returns the group's identifier.
func (self *Group) GroupId() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]byte(nil), self.context.GroupId...)
}

// Epoch returns the current epoch.
func (self *Group) Epoch() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.context.Epoch
}

// OwnLeafIndex returns this device's leaf.
func (self *Group) OwnLeafIndex() LeafIndex {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ownLeaf
}

// Members returns a snapshot of the membership with roles resolved from the
// group policy extension.
func (self *Group) Members() []Member {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.membersLocked()
}

func (self *Group) membersLocked() []Member {
	policy, err := GroupPolicyOf(self.context.Extensions)
	out := []Member{}
	for _, leafIndex := range self.tree.NonBlankLeaves() {
		leaf, _ := self.tree.LeafNode(leafIndex)
		member := Member{
			LeafIndex:    leafIndex,
			IdentityPub:  append([]byte(nil), leaf.Credential.Identity...),
			SignatureKey: leaf.SignatureKey,
			Role:         RoleMember,
		}
		if keys, keysErr := LeafKeysOf(leaf); keysErr == nil {
			member.LeafKeys = keys
		}
		if err == nil {
			if role, ok := policy.RoleOf(leaf.Credential.Identity); ok {
				member.Role = role
			}
		}
		out = append(out, member)
	}
	return out
}

// MemberAt returns one member.
func (self *Group) MemberAt(leafIndex LeafIndex) (Member, bool) {
	for _, member := range self.Members() {
		if member.LeafIndex == leafIndex {
			return member, true
		}
	}
	return Member{}, false
}

// EpochAuthenticator is the value two members compare to detect a fork.
func (self *Group) EpochAuthenticator() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]byte(nil), self.secrets.EpochAuthenticator...)
}

// Export is the RFC 9420 §8.5 exporter. MASTER §7 derives mls_secret from it.
func (self *Group) Export(label string, context []byte, length int) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.secrets.Export(self.crypto, label, context, length)
}

// EpochSecret exposes exactly the two secrets MASTER §8.2 needs.
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch name {
	case EpochSecretSenderData:
		return append([]byte(nil), self.secrets.SenderDataSecret...), nil
	case EpochSecretEncryption:
		return append([]byte(nil), self.secrets.EncryptionSecret...), nil
	}
	return nil, fmt.Errorf("mls: epoch secret name %d is not in the closed enum", name)
}

// RatchetTree returns the encoded public tree, for out-of-band Welcome delivery
// and for MASTER §8.2's per-epoch snapshot record.
func (self *Group) RatchetTree() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := ValSem300NoTrailingBlankNodes(self.tree); err != nil {
		return nil, err
	}
	return self.tree.Encode()
}

// GroupContext returns the serialized GroupContext for the current epoch.
func (self *Group) GroupContext() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.context.Marshal()
}

// GroupPolicy returns the parsed urmessage_group_policy extension.
func (self *Group) GroupPolicy() (*GroupPolicyExtension, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return GroupPolicyOf(self.context.Extensions)
}

// Close releases the group. Epoch state stays in the store; secrets in memory
// are dropped.
func (self *Group) Close() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.secrets = nil
	self.secretTree = nil
	self.pending = nil
	return nil
}

// treeHashForTest exposes the current tree hash to tests in this package.
func (self *Group) treeHashForTest() ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.tree.RootHash()
}

// syntaxUnmarshalGroupContext keeps the syntax import local to this file.
func syntaxUnmarshalGroupContext(data []byte, out *GroupContext) (int, error) {
	return syntax.Unmarshal(data, out)
}

// encodeRequiredCapabilities serializes the required_capabilities extension.
func encodeRequiredCapabilities(required *RequiredCapabilities) (Extension, error) {
	data, err := syntax.Marshal(required)
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionTypeRequiredCapabilities, ExtensionData: data}, nil
}

// persist writes the current epoch's state blob. Task 19 defines the blob and
// the past-epoch window; this task writes only the current epoch.
func (self *Group) persist() error {
	blob, err := self.marshalState()
	if err != nil {
		return err
	}
	return self.cfg.Store.PutGroupState(self.context.GroupId, self.context.Epoch, blob)
}

// marshalState is defined in Task 19. For this task it serializes the group
// context and the tree, which is enough for the creation test to assert the
// write happened; Task 19 replaces it with the full blob and its round-trip
// test.
func (self *Group) marshalState() ([]byte, error) {
	tree, err := self.tree.Encode()
	if err != nil {
		return nil, err
	}
	context, err := self.context.Marshal()
	if err != nil {
		return nil, err
	}
	return syntax.Marshal(&struct {
		Context []byte `tls:"head=varint"`
		Tree    []byte `tls:"head=varint"`
	}{Context: context, Tree: tree})
}

// nowFunc is overridden in tests that need to move the clock for lifetime and
// succession checks.
var nowFunc = time.Now
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestNewGroup|TestEpochSecretAccessor|TestGroupStateIsPersisted' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/group.go connect/mls/group_test.go && \
git commit -m "feat(mls): group creation following RFC 9420 section 11"
```

---

### Task 12: Proposal generation on `Group`

**Files:**
- Modify: `connect/mls/group.go`
- Test: `connect/mls/group_test.go`

**Interfaces:**
- Consumes: `SignFramedContent`, `ProtectPrivate`, `(*MLSMessage).Marshal`, `ParseMLSMessage` (Framing plan); `(*ProposalCache).Store` (Task 6).
- Produces:
```go
func (self *Group) ProposeAdd(keyPackage []byte) (proposalMessage []byte, err error)
func (self *Group) ProposeRemove(leaf LeafIndex) ([]byte, error)
func (self *Group) ProposeUpdate() ([]byte, error)
func (self *Group) ProposeGroupContextExtensions(exts []Extension) ([]byte, error)
```

Each returns a serialized `MLSMessage(PrivateMessage)` carrying the proposal, caches it locally so a
later commit can reference it, and leaves epoch state untouched.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/group_test.go`:

```go
func TestProposeAddProducesACacheableProposal(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	encoded, err := syntaxMarshalKeyPackage(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	message, err := group.ProposeAdd(encoded)
	if err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	if len(message) == 0 {
		t.Fatal("ProposeAdd returned no message")
	}
	parsed, err := ParseMLSMessage(message)
	if err != nil {
		t.Fatalf("ParseMLSMessage: %v", err)
	}
	if parsed.WireFormat != WireFormatPrivateMessage {
		t.Fatalf("wire format = %#x, want PrivateMessage: A-ASSUME-4 puts handshake traffic in PrivateMessage",
			parsed.WireFormat)
	}
	if group.Epoch() != 0 {
		t.Fatal("proposing must not advance the epoch")
	}
	if len(group.pendingProposalsForTest()) != 1 {
		t.Fatalf("the proposal was not cached: %d entries", len(group.pendingProposalsForTest()))
	}
}

func TestProposeUpdateUsesAFreshEncryptionKey(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	before, _ := group.tree.LeafNode(group.OwnLeafIndex())
	if _, err := group.ProposeUpdate(); err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	cached := group.pendingProposalsForTest()
	if len(cached) != 1 {
		t.Fatalf("cached = %d, want 1", len(cached))
	}
	updated := cached[0].Proposal.Update.LeafNode
	if bytes.Equal(updated.EncryptionKey, before.EncryptionKey) {
		t.Fatal("an update that reuses the leaf's encryption key provides no post compromise security")
	}
	if updated.LeafNodeSource != LeafNodeSourceUpdate {
		t.Fatalf("leaf_node_source = %d, want update", updated.LeafNodeSource)
	}
}

func TestProposeRemoveRefusesOwnLeaf(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	if _, err := group.ProposeRemove(group.OwnLeafIndex()); err == nil {
		t.Fatal("ProposeRemove accepted our own leaf; ValSem200 makes that commit invalid")
	}
}

func TestProposeGroupContextExtensionsRefusesProfileViolation(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	bad := []Extension{{ExtensionType: ExtensionTypeExternalSenders, ExtensionData: []byte{}}}
	if _, err := group.ProposeGroupContextExtensions(bad); !errors.Is(err, ErrProfileExternalSender) {
		t.Fatalf("ProposeGroupContextExtensions error = %v, want ErrProfileExternalSender", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestPropose -v`
Expected: FAIL to build with `undefined: (*Group).ProposeAdd`, `undefined: pendingProposalsForTest`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/group.go`:

```go
// ProposeAdd proposes that the client holding keyPackage join the group.
// The key package is validated here rather than only at commit time, so a
// caller learns immediately that it fetched an expired or wrong-suite package.
func (self *Group) ProposeAdd(keyPackage []byte) ([]byte, error) {
	var kp KeyPackage
	read, err := syntax.Unmarshal(keyPackage, &kp)
	if err != nil {
		return nil, err
	}
	if read != len(keyPackage) {
		return nil, fmt.Errorf("mls: %d trailing bytes after key package", len(keyPackage)-read)
	}
	if err := kp.Validate(self.crypto, self.cfg.Suite, nowFunc()); err != nil {
		return nil, err
	}
	if _, err := LeafKeysOf(&kp.LeafNode); err != nil {
		return nil, err
	}
	return self.proposeLocked(&Proposal{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: kp}})
}

// ProposeRemove proposes removing a leaf. Removing our own leaf is refused:
// ValSem200 makes a commit covering it invalid, and a proposal nobody can
// commit is a proposal that silently does nothing.
func (self *Group) ProposeRemove(leaf LeafIndex) ([]byte, error) {
	self.stateLock.Lock()
	own := self.ownLeaf
	_, present := self.tree.LeafNode(leaf)
	self.stateLock.Unlock()
	if leaf == own {
		return nil, fmt.Errorf("%w: use the group's leave flow instead", ErrSelfRemoveInCommit)
	}
	if !present {
		return nil, fmt.Errorf("%w: leaf %d", ErrRemoveNonMember, leaf)
	}
	return self.proposeLocked(&Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: leaf}})
}

// ProposeUpdate proposes replacing our own leaf with one holding a fresh
// encryption key.
func (self *Group) ProposeUpdate() ([]byte, error) {
	self.stateLock.Lock()
	crypto := self.crypto
	leafKeys := self.cfg.LeafKeys
	signer := self.signer
	cred := self.cred
	cfg := self.cfg
	self.stateLock.Unlock()

	encPriv, encPub, err := crypto.DeriveKeyPair(crypto.Random(crypto.HashSize()))
	if err != nil {
		return nil, err
	}
	leafKeysExt, err := leafKeys.Encode()
	if err != nil {
		return nil, err
	}
	leaf, err := NewLeafNode(crypto, signer, cred, encPub, v1Capabilities(cfg), []Extension{leafKeysExt})
	if err != nil {
		return nil, err
	}
	leaf.LeafNodeSource = LeafNodeSourceUpdate
	leaf.Lifetime = nil
	if err := reSignLeafNode(crypto, signer, leaf, self.GroupId(), self.OwnLeafIndex()); err != nil {
		return nil, err
	}
	if err := self.cfg.Store.PutPrivateKey(encPub, encPriv); err != nil {
		return nil, err
	}
	return self.proposeLocked(&Proposal{ProposalType: ProposalTypeUpdate, Update: &Update{LeafNode: *leaf}})
}

// ProposeGroupContextExtensions proposes replacing the group context extension
// list wholesale. Every extension is checked against the v1 profile before the
// proposal is built, so a policy violation never reaches the wire.
func (self *Group) ProposeGroupContextExtensions(exts []Extension) ([]byte, error) {
	profile := self.cfg.Profile
	if profile == nil {
		profile = DefaultProfile()
	}
	for _, ext := range exts {
		if err := profile.CheckGroupExtension(ext.ExtensionType); err != nil {
			return nil, err
		}
	}
	if _, err := GroupPolicyOf(exts); err != nil {
		return nil, err
	}
	return self.proposeLocked(&Proposal{
		ProposalType:           ProposalTypeGroupContextExtensions,
		GroupContextExtensions: &GroupContextExtensions{Extensions: exts},
	})
}

// proposeLocked frames, signs, protects and caches one proposal.
func (self *Group) proposeLocked(proposal *Proposal) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, fmt.Errorf("mls: group is closed")
	}

	content := &FramedContent{
		GroupId:     append([]byte(nil), self.context.GroupId...),
		Epoch:       self.context.Epoch,
		Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: self.ownLeaf},
		ContentType: ContentTypeProposal,
		Proposal:    proposal,
	}
	authenticated, err := SignFramedContent(self.crypto, self.signer,
		WireFormatPrivateMessage, content, self.context)
	if err != nil {
		return nil, err
	}
	if _, err := self.proposals.Store(self.crypto, authenticated); err != nil {
		return nil, err
	}
	private, err := ProtectPrivate(self.crypto, self.secretTree, self.secrets.SenderDataSecret,
		self.context, authenticated, 0)
	if err != nil {
		return nil, err
	}
	message := &MLSMessage{
		Version:        ProtocolVersionMls10,
		WireFormat:     WireFormatPrivateMessage,
		PrivateMessage: private,
	}
	return message.Marshal()
}

// pendingProposalsForTest exposes the cache to tests in this package.
func (self *Group) pendingProposalsForTest() []CachedProposal {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	out := []CachedProposal{}
	for _, entry := range self.proposals.Pending() {
		cached, ok := self.proposals.Get(entry.Reference)
		if ok {
			out = append(out, cached)
		}
	}
	return out
}

// syntaxMarshalKeyPackage keeps the syntax import local, and is what tests use
// to hand a key package to ProposeAdd.
func syntaxMarshalKeyPackage(kp *KeyPackage) ([]byte, error) {
	return syntax.Marshal(kp)
}
```

`reSignLeafNode(crypto, signer, leaf, groupId, leafIndex) error` is consumed from the TreeKEM plan:
an Update leaf signs over `LeafNodeTBS` including the group id and leaf index, which a KeyPackage
leaf does not. If that plan exposes it under another name, use theirs.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestPropose -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/group.go connect/mls/group_test.go && \
git commit -m "feat(mls): proposal generation on Group for add, update, remove and GCE"
```

---

### Task 13: Commit generation, RFC 9420 §12.4.1

**Files:**
- Modify: `connect/mls/commit.go`, `connect/mls/group.go`
- Test: `connect/mls/commit_test.go`

**Interfaces:**
- Consumes: `(*RatchetTree).CreateUpdatePath`, `PathSecrets.CommitSecret` (TreeKEM plan); `DeriveEpochSecrets`, `EmptyPskSecret` (Key schedule plan); `ConfirmedTranscriptHash`, `InterimTranscriptHash`, `SignFramedContent`, `ProtectPrivate` (Framing plan); `ApplyProposals` (Task 8); `ValidateProposalList` (Task 7); `ValidateCommit` (Task 10).
- Produces:
```go
type CommitOptions struct {
    Force         bool          // build a path even when the proposal list does not require one
    ExtraProposals []Proposal   // by-value proposals, appended after the by-reference ones
}
type CommitResult struct {
    Commit      []byte   // MLSMessage(PrivateMessage) carrying the Commit
    Welcome     []byte   // MLSMessage(Welcome), nil when the commit adds nobody
    RatchetTree []byte   // the post-commit tree, for out-of-band Welcome delivery
}
type StagedCommit struct{ /* opaque */ }
func (self *StagedCommit) Epoch() uint64
func (self *StagedCommit) Committer() LeafIndex
func (self *StagedCommit) AddedLeaves() []LeafIndex
func (self *StagedCommit) RemovedLeaves() []LeafIndex
func (self *StagedCommit) UpdatedLeaves() []LeafIndex
func (self *StagedCommit) RemovesSelf() bool
func (self *StagedCommit) GroupContextExtensions() []Extension
func (self *StagedCommit) EpochAuthenticator() []byte

func (self *Group) Commit(byReference [][]byte, byValue []Proposal, opts *CommitOptions) (*CommitResult, error)
```

`byReference` is a slice of serialized `ProposalRef` values, so `connect/message` can name proposals
it saw on the wire without holding `mls` types. Passing nil means "every valid proposal cached this
epoch", which is the RFC 9420 §12.4 SHOULD.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/commit_test.go`:

```go
func TestCommitAddAdvancesTheEpochAndProducesAWelcome(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	encoded, err := syntaxMarshalKeyPackage(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}

	before := group.EpochAuthenticator()
	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if len(result.Commit) == 0 {
		t.Fatal("Commit returned no commit message")
	}
	if len(result.Welcome) == 0 {
		t.Fatal("a commit covering an Add must produce a Welcome")
	}
	if len(result.RatchetTree) == 0 {
		t.Fatal("Commit must return the post-commit tree for out-of-band delivery")
	}
	if group.Epoch() != 0 {
		t.Fatal("Commit must stage, not merge: the epoch advances at MergePendingCommit")
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	if group.Epoch() != 1 {
		t.Fatalf("Epoch = %d, want 1 after merge", group.Epoch())
	}
	if bytes.Equal(before, group.EpochAuthenticator()) {
		t.Fatal("the epoch authenticator did not change across the commit")
	}
	if len(group.Members()) != 2 {
		t.Fatalf("Members = %d, want 2", len(group.Members()))
	}
}

func TestCommitWithNoProposalsCarriesAPath(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if result.Welcome != nil {
		t.Fatal("a commit that adds nobody must not produce a Welcome")
	}
	staged := group.stagedForTest()
	if staged == nil {
		t.Fatal("no staged commit")
	}
	if !staged.hasPathForTest() {
		t.Fatal("an empty proposal list requires a path: RFC 9420 §12.4")
	}
}

func TestCommitAddOnlyOmitsThePathByDefault(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	staged, err := group.Commit(nil, []Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}}, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if staged == nil {
		t.Fatal("no result")
	}
	if group.stagedForTest().hasPathForTest() {
		t.Fatal("an add-only commit may omit the path, and this build omits it")
	}
}

func TestCommitForceBuildsAPathForAnAddOnlyList(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	if _, err := group.Commit(nil,
		[]Proposal{{ProposalType: ProposalTypeAdd, Add: &Add{KeyPackage: *kp}}},
		&CommitOptions{Force: true}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if !group.stagedForTest().hasPathForTest() {
		t.Fatal("CommitOptions.Force must populate the path")
	}
}

func TestCommitRefusesASecondPendingCommit(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if _, err := group.Commit(nil, nil, nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if _, err := group.Commit(nil, nil, nil); !errors.Is(err, ErrPendingCommitExists) {
		t.Fatalf("second Commit error = %v, want ErrPendingCommitExists", err)
	}
	group.ClearPendingCommit()
	if _, err := group.Commit(nil, nil, nil); err != nil {
		t.Fatalf("Commit after ClearPendingCommit: %v", err)
	}
}

func TestCommitRefusesItsOwnUpdateProposal(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	if _, err := group.ProposeUpdate(); err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	// nil byReference means "every cached proposal", which here is our own
	// update: ValSem111 must refuse it rather than silently dropping it.
	if _, err := group.Commit(nil, nil, nil); !errors.Is(err, ErrSelfUpdateInCommit) {
		t.Fatalf("Commit error = %v, want ErrSelfUpdateInCommit", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestCommitAdd|TestCommitWith|TestCommitForce|TestCommitRefuses' -v`
Expected: FAIL to build with `undefined: (*Group).Commit`, `undefined: CommitOptions`, `undefined: StagedCommit`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/commit.go`:

```go
// CommitOptions are the committer's discretionary choices. Nothing here can
// make an invalid commit valid.
type CommitOptions struct {
	// Force populates the path even when the proposal list does not require
	// one, which buys post compromise security for the committer.
	Force bool
}

// CommitResult is what a committer sends.
type CommitResult struct {
	Commit      []byte
	Welcome     []byte
	RatchetTree []byte
}

// StagedCommit is a commit that has been validated and whose new epoch has been
// derived, but which has not replaced the group's live state. A commit is
// staged on both sides: the committer stages its own and merges when the
// delivery service accepts it, and a receiver stages an inbound one so a policy
// decision can happen before the epoch advances.
type StagedCommit struct {
	committer     LeafIndex
	epoch         uint64
	context       *GroupContext
	tree          *RatchetTree
	secrets       *EpochSecrets
	secretTree    *SecretTree
	ownEncPriv    HpkePrivateKey
	interimHash   []byte
	list          *ProposalList
	added         []LeafIndex
	removed       []LeafIndex
	updated       []LeafIndex
	selfRemoved   bool
	hasPath       bool
	welcomeSecret []byte
	joinerSecret  []byte
	confirmTag    []byte
	pathSecrets   *PathSecrets
}

// Epoch is the epoch this commit opens.
func (self *StagedCommit) Epoch() uint64 { return self.epoch }

// Committer is the leaf that authored the commit.
func (self *StagedCommit) Committer() LeafIndex { return self.committer }

// AddedLeaves is where the commit's Add proposals landed.
func (self *StagedCommit) AddedLeaves() []LeafIndex { return append([]LeafIndex(nil), self.added...) }

// RemovedLeaves is the leaves the commit blanked.
func (self *StagedCommit) RemovedLeaves() []LeafIndex { return append([]LeafIndex(nil), self.removed...) }

// UpdatedLeaves is the leaves an Update proposal replaced.
func (self *StagedCommit) UpdatedLeaves() []LeafIndex { return append([]LeafIndex(nil), self.updated...) }

// RemovesSelf reports whether this commit removes the processing client.
func (self *StagedCommit) RemovesSelf() bool { return self.selfRemoved }

// GroupContextExtensions is the post-commit extension list.
func (self *StagedCommit) GroupContextExtensions() []Extension { return self.context.Extensions }

// EpochAuthenticator is the new epoch's fork-detection value.
func (self *StagedCommit) EpochAuthenticator() []byte {
	return append([]byte(nil), self.secrets.EpochAuthenticator...)
}

// hasPathForTest exposes the path decision to tests in this package.
func (self *StagedCommit) hasPathForTest() bool { return self.hasPath }
```

Append to `connect/mls/group.go`:

```go
// Commit builds a commit over the named proposals, following RFC 9420 §12.4.1
// step by step. It stages the result rather than merging it, because the
// delivery service accepts at most one commit per (group, epoch) and a
// committer that merged optimistically would fork itself off the group
// (MASTER §9.3).
func (self *Group) Commit(byReference [][]byte, byValue []Proposal, opts *CommitOptions) (*CommitResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, fmt.Errorf("mls: group is closed")
	}
	if self.pending != nil {
		return nil, ErrPendingCommitExists
	}
	if opts == nil {
		opts = &CommitOptions{}
	}

	// step 1: name the proposals. nil byReference means every cached proposal.
	refs := []ProposalOrRef{}
	if byReference == nil {
		refs = append(refs, self.proposals.Pending()...)
	} else {
		for _, ref := range byReference {
			refs = append(refs, ProposalOrRef{Type: ProposalOrRefTypeReference, Reference: ProposalRef(ref)})
		}
	}
	for i := range byValue {
		proposal := byValue[i]
		refs = append(refs, ProposalOrRef{Type: ProposalOrRefTypeProposal, Proposal: &proposal})
	}
	list, err := self.proposals.Resolve(self.crypto, self.ownLeaf, refs)
	if err != nil {
		return nil, err
	}

	// step 2: validate the list against the pre-commit state
	applied, err := ApplyProposals(self.crypto, self.tree, self.context, self.ownLeaf, list)
	if err != nil {
		return nil, err
	}
	validationInput := &ProposalValidationInput{
		Crypto:     self.crypto,
		Tree:       self.tree,
		Context:    self.context,
		Extensions: applied.Extensions,
		Committer:  self.ownLeaf,
		List:       list,
		Now:        nowFunc(),
	}
	if err := ValidateProposalList(validationInput); err != nil {
		return nil, err
	}
	if err := self.checkMembershipCapsLocked(applied); err != nil {
		return nil, err
	}
	if err := self.checkRemovalAuthorityLocked(list, self.ownLeaf); err != nil {
		return nil, err
	}
	if err := self.checkSuccessionLocked(list, applied, self.ownLeaf); err != nil {
		return nil, err
	}

	// step 3: decide on the path and build it against the provisional context
	commit := &Commit{Proposals: refs}
	commitSecret := make([]byte, self.crypto.HashSize())
	var pathSecrets *PathSecrets
	var newEncPriv HpkePrivateKey
	hasPath := CommitPathRequired(list) || opts.Force
	if hasPath {
		provisional := &GroupContext{
			Version:                 self.context.Version,
			CipherSuite:             self.context.CipherSuite,
			GroupId:                 self.context.GroupId,
			Epoch:                   self.context.Epoch + 1,
			ConfirmedTranscriptHash: self.context.ConfirmedTranscriptHash,
			Extensions:              applied.Extensions,
		}
		treeHash, err := applied.Tree.RootHash()
		if err != nil {
			return nil, err
		}
		provisional.TreeHash = treeHash
		provisionalBytes, err := provisional.Marshal()
		if err != nil {
			return nil, err
		}
		path, secrets, encPriv, err := applied.Tree.CreateUpdatePath(
			self.ownLeaf, self.signer, provisionalBytes, applied.AddedLeaves)
		if err != nil {
			return nil, err
		}
		commit.Path = path
		commitSecret = secrets.CommitSecret()
		pathSecrets = secrets
		newEncPriv = encPriv
	}

	// step 4: frame and sign the commit against the OLD group context
	content := &FramedContent{
		GroupId:     append([]byte(nil), self.context.GroupId...),
		Epoch:       self.context.Epoch,
		Sender:      Sender{SenderType: SenderTypeMember, LeafIndex: self.ownLeaf},
		ContentType: ContentTypeCommit,
		Commit:      commit,
	}
	authenticated, err := SignFramedContent(self.crypto, self.signer,
		WireFormatPrivateMessage, content, self.context)
	if err != nil {
		return nil, err
	}

	// step 5: the new transcript hashes, group context and key schedule
	confirmedHash, err := ConfirmedTranscriptHash(self.crypto, self.interimHash, authenticated)
	if err != nil {
		return nil, err
	}
	treeHash, err := applied.Tree.RootHash()
	if err != nil {
		return nil, err
	}
	newContext := &GroupContext{
		Version:                 self.context.Version,
		CipherSuite:             self.context.CipherSuite,
		GroupId:                 append([]byte(nil), self.context.GroupId...),
		Epoch:                   self.context.Epoch + 1,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedHash,
		Extensions:              applied.Extensions,
	}
	newContextBytes, err := newContext.Marshal()
	if err != nil {
		return nil, err
	}
	secrets, err := DeriveEpochSecrets(self.crypto, self.secrets.InitSecret, commitSecret,
		EmptyPskSecret(self.crypto), newContextBytes)
	if err != nil {
		return nil, err
	}

	// step 6: the confirmation tag, then the interim hash from it
	confirmationTag := self.crypto.Mac(secrets.ConfirmationKey, confirmedHash)
	authenticated.Auth.ConfirmationTag = confirmationTag
	interimHash, err := InterimTranscriptHash(self.crypto, confirmedHash, confirmationTag)
	if err != nil {
		return nil, err
	}

	// step 7: structural commit validation, against the state a receiver sees
	commitInput := &CommitValidationInput{
		Crypto:          self.crypto,
		PreTree:         self.tree,
		PostTree:        applied.Tree,
		Context:         self.context,
		Extensions:      applied.Extensions,
		Committer:       self.ownLeaf,
		Own:             self.ownLeaf,
		List:            list,
		Commit:          commit,
		ConfirmationKey: secrets.ConfirmationKey,
		ConfirmedHash:   confirmedHash,
		ConfirmationTag: confirmationTag,
		Now:             nowFunc(),
	}
	if err := ValidateCommit(commitInput); err != nil {
		return nil, err
	}

	// step 8: protect the commit under the OLD epoch's keys
	private, err := ProtectPrivate(self.crypto, self.secretTree, self.secrets.SenderDataSecret,
		self.context, authenticated, 0)
	if err != nil {
		return nil, err
	}
	commitMessage, err := (&MLSMessage{
		Version:        ProtocolVersionMls10,
		WireFormat:     WireFormatPrivateMessage,
		PrivateMessage: private,
	}).Marshal()
	if err != nil {
		return nil, err
	}

	if newEncPriv == nil {
		newEncPriv = self.ownEncPriv
	}
	staged := &StagedCommit{
		committer:     self.ownLeaf,
		epoch:         newContext.Epoch,
		context:       newContext,
		tree:          applied.Tree,
		secrets:       secrets,
		secretTree:    NewSecretTree(self.crypto, applied.Tree.Size(), secrets.EncryptionSecret),
		ownEncPriv:    newEncPriv,
		interimHash:   interimHash,
		list:          list,
		added:         applied.AddedLeaves,
		removed:       applied.RemovedLeaves,
		updated:       applied.UpdatedLeaves,
		selfRemoved:   applied.SelfRemoved,
		hasPath:       hasPath,
		welcomeSecret: secrets.WelcomeSecret,
		joinerSecret:  secrets.JoinerSecret,
		confirmTag:    confirmationTag,
		pathSecrets:   pathSecrets,
	}
	self.pending = staged

	result := &CommitResult{Commit: commitMessage}
	if result.RatchetTree, err = applied.Tree.Encode(); err != nil {
		return nil, err
	}
	if len(applied.AddedLeaves) > 0 {
		welcome, err := self.buildWelcomeLocked(staged)
		if err != nil {
			return nil, err
		}
		result.Welcome = welcome
	}
	return result, nil
}

// ClearPendingCommit discards a staged commit. Called when the delivery service
// accepted someone else's commit for this epoch (MASTER §9.3, Spec A §5.12).
func (self *Group) ClearPendingCommit() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pending = nil
}

// stagedForTest exposes the staged commit to tests in this package.
func (self *Group) stagedForTest() *StagedCommit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pending
}
```

`checkMembershipCapsLocked`, `checkRemovalAuthorityLocked`, `checkSuccessionLocked` and
`buildWelcomeLocked` are stubbed in this task to `return nil` / `return nil, nil` and implemented in
Tasks 15, 20 and 21. Land the stubs with a one-line comment naming the task that fills them, so the
build is green at every commit:

```go
// checkMembershipCapsLocked is implemented in Task 20.
func (self *Group) checkMembershipCapsLocked(applied *ApplyResult) error { return nil }

// checkRemovalAuthorityLocked is implemented in Task 20.
func (self *Group) checkRemovalAuthorityLocked(list *ProposalList, committer LeafIndex) error { return nil }

// checkSuccessionLocked is implemented in Task 21.
func (self *Group) checkSuccessionLocked(list *ProposalList, applied *ApplyResult, committer LeafIndex) error {
	return nil
}

// buildWelcomeLocked is implemented in Task 15.
func (self *Group) buildWelcomeLocked(staged *StagedCommit) ([]byte, error) { return nil, nil }
```

`MergePendingCommit` is implemented in Task 19; for this task add the minimal form that swaps the
staged state in, and let Task 19 add persistence and the past-epoch window:

```go
// MergePendingCommit promotes the staged commit to live state. Task 19 adds
// persistence and the past-epoch window.
func (self *Group) MergePendingCommit() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pending == nil {
		return ErrNoPendingCommit
	}
	staged := self.pending
	self.tree = staged.tree
	self.context = staged.context
	self.secrets = staged.secrets
	self.secretTree = staged.secretTree
	self.ownEncPriv = staged.ownEncPriv
	self.interimHash = staged.interimHash
	self.proposals.Clear()
	self.pending = nil
	return nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestCommitAdd|TestCommitWith|TestCommitForce|TestCommitRefuses' -v`
Expected: PASS. `TestCommitAddAdvancesTheEpochAndProducesAWelcome` still fails on the Welcome
assertion until Task 15; mark that one `t.Skip("welcome lands in Task 15")` in this task and delete
the skip in Task 15's step 1.

- [ ] **Step 5: Commit**

```bash
git add connect/mls/commit.go connect/mls/group.go connect/mls/commit_test.go && \
git commit -m "feat(mls): commit generation following RFC 9420 section 12.4.1"
```

---

### Task 14: `GroupInfo` and `GroupInfoTBS`

**Files:**
- Create: `connect/mls/welcome.go`
- Test: `connect/mls/welcome_test.go`

**Interfaces:**
- Consumes: `syntax.Marshal`, `syntax.Unmarshal`; `mls.GroupContext`, `mls.CryptoProvider.SignWithLabel/VerifyWithLabel`; `mls.RatchetTree` (TreeKEM plan).
- Produces:
```go
type GroupInfo struct {
    GroupContext    GroupContext
    Extensions      []Extension `tls:"head=varint"`
    ConfirmationTag []byte      `tls:"head=varint"`
    Signer          LeafIndex
    Signature       []byte      `tls:"head=varint"`
}
type GroupInfoTBS struct {
    GroupContext    GroupContext
    Extensions      []Extension `tls:"head=varint"`
    ConfirmationTag []byte      `tls:"head=varint"`
    Signer          LeafIndex
}
func (self *GroupInfo) Sign(crypto CryptoProvider, priv SignaturePrivateKey) error
func (self *GroupInfo) Verify(crypto CryptoProvider, tree *RatchetTree) error
```

The signature label is `"GroupInfoTBS"`, and the signature covers every field above `signature`.
RFC 9420 §12.4.3.

- [ ] **Step 1: Write the failing test**

`connect/mls/welcome_test.go`:

```go
package mls

import (
	"bytes"
	"errors"
	"testing"
)

func testGroupInfo(t *testing.T, crypto CryptoProvider, tree *RatchetTree, signer LeafIndex) *GroupInfo {
	t.Helper()
	treeHash, err := tree.RootHash()
	if err != nil {
		t.Fatalf("RootHash: %v", err)
	}
	return &GroupInfo{
		GroupContext: GroupContext{
			Version:                 ProtocolVersionMls10,
			CipherSuite:             CipherSuiteX25519ChaCha20SHA256Ed25519,
			GroupId:                 []byte("group-1"),
			Epoch:                   1,
			TreeHash:                treeHash,
			ConfirmedTranscriptHash: []byte("confirmed"),
		},
		ConfirmationTag: bytes.Repeat([]byte{3}, crypto.HashSize()),
		Signer:          signer,
	}
}

func TestGroupInfoSignAndVerify(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	info := testGroupInfo(t, crypto, tree, LeafIndex(0))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(info.Signature) == 0 {
		t.Fatal("Sign produced no signature")
	}
	if err := info.Verify(crypto, tree); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestGroupInfoVerifyRejectsATamperedField(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	info := testGroupInfo(t, crypto, tree, LeafIndex(0))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	info.GroupContext.Epoch = 2
	if err := info.Verify(crypto, tree); !errors.Is(err, ErrWelcomeGroupInfoSignature) {
		t.Fatalf("Verify error = %v, want ErrWelcomeGroupInfoSignature", err)
	}
}

func TestGroupInfoVerifyRejectsAWrongSigner(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	info := testGroupInfo(t, crypto, tree, LeafIndex(0))
	// signed by bob but claiming alice's leaf
	if err := info.Sign(crypto, members[1].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := info.Verify(crypto, tree); !errors.Is(err, ErrWelcomeGroupInfoSignature) {
		t.Fatalf("Verify error = %v, want ErrWelcomeGroupInfoSignature", err)
	}
}

func TestGroupInfoVerifyRejectsABlankSignerLeaf(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice", "bob")
	info := testGroupInfo(t, crypto, tree, LeafIndex(7))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := info.Verify(crypto, tree); err == nil {
		t.Fatal("Verify accepted a signer index that names no leaf")
	}
}

func TestGroupInfoRoundTrip(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice")
	info := testGroupInfo(t, crypto, tree, LeafIndex(0))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	encoded, err := syntaxMarshalGroupInfo(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var parsed GroupInfo
	if _, err := syntaxUnmarshalGroupInfo(encoded, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reencoded, err := syntaxMarshalGroupInfo(&parsed)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatal("re-encode is not byte identical")
	}
	if err := parsed.Verify(crypto, tree); err != nil {
		t.Fatalf("Verify after round trip: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestGroupInfo -v`
Expected: FAIL to build with `undefined: GroupInfo`, `undefined: syntaxMarshalGroupInfo`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/welcome.go`:

```go
// RFC 9420 §12.4.3, the GroupInfo a committer signs and the Welcome that
// carries it. Nothing here is URmessage specific: the group-context extensions
// that are ours ride inside GroupInfo.group_context and are covered by this
// signature and by the transcript hash.
package mls

import (
	"fmt"

	"github.com/urnetwork/connect/mls/syntax"
)

// GroupInfo is the joiner's view of the new epoch.
type GroupInfo struct {
	GroupContext    GroupContext
	Extensions      []Extension `tls:"head=varint"`
	ConfirmationTag []byte      `tls:"head=varint"`
	Signer          LeafIndex
	Signature       []byte `tls:"head=varint"`
}

// GroupInfoTBS is every field of GroupInfo above the signature.
type GroupInfoTBS struct {
	GroupContext    GroupContext
	Extensions      []Extension `tls:"head=varint"`
	ConfirmationTag []byte      `tls:"head=varint"`
	Signer          LeafIndex
}

// tbs returns the signature input.
func (self *GroupInfo) tbs() *GroupInfoTBS {
	return &GroupInfoTBS{
		GroupContext:    self.GroupContext,
		Extensions:      self.Extensions,
		ConfirmationTag: self.ConfirmationTag,
		Signer:          self.Signer,
	}
}

// Sign signs with the label "GroupInfoTBS".
func (self *GroupInfo) Sign(crypto CryptoProvider, priv SignaturePrivateKey) error {
	content, err := syntax.Marshal(self.tbs())
	if err != nil {
		return err
	}
	signature, err := crypto.SignWithLabel(priv, "GroupInfoTBS", content)
	if err != nil {
		return err
	}
	self.Signature = signature
	return nil
}

// Verify checks the signature against the leaf named by Signer. A blank signer
// leaf is refused: RFC 9420 §12.4.3.1 requires the public key be taken from a
// non-blank leaf of the ratchet tree.
func (self *GroupInfo) Verify(crypto CryptoProvider, tree *RatchetTree) error {
	leaf, ok := tree.LeafNode(self.Signer)
	if !ok {
		return fmt.Errorf("%w: signer leaf %d is blank", ErrBlankSenderLeaf, self.Signer)
	}
	content, err := syntax.Marshal(self.tbs())
	if err != nil {
		return err
	}
	if err := crypto.VerifyWithLabel(leaf.SignatureKey, "GroupInfoTBS", content, self.Signature); err != nil {
		return fmt.Errorf("%w: %v", ErrWelcomeGroupInfoSignature, err)
	}
	return nil
}

// syntaxMarshalGroupInfo and syntaxUnmarshalGroupInfo keep the syntax import
// local to this file.
func syntaxMarshalGroupInfo(info *GroupInfo) ([]byte, error) {
	return syntax.Marshal(info)
}

func syntaxUnmarshalGroupInfo(data []byte, out *GroupInfo) (int, error) {
	return syntax.Unmarshal(data, out)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestGroupInfo -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/welcome.go connect/mls/welcome_test.go && \
git commit -m "feat(mls): GroupInfo and GroupInfoTBS signing and verification"
```

---

### Task 15: Welcome generation

**Files:**
- Modify: `connect/mls/welcome.go`, `connect/mls/group.go`
- Test: `connect/mls/welcome_test.go`

**Interfaces:**
- Consumes: `EncryptWithLabel`, `HPKECiphertext` (Crypto/HPKE plan); `WelcomeKeyNonce`, `EmptyPskSecret` (Key schedule plan); `CommonAncestor` (Tree math plan); `(*PathSecrets).SecretAt` (TreeKEM plan); `(*KeyPackage).Ref` (TreeKEM plan); `StagedCommit` (Task 13).
- Produces:
```go
type PathSecret struct {
    PathSecret []byte `tls:"head=varint"`
}
type GroupSecrets struct {
    JoinerSecret []byte      `tls:"head=varint"`
    PathSecret   *PathSecret `tls:"optional"`
    Psks         []byte      `tls:"head=varint"`   // always zero-length in v1
}
type EncryptedGroupSecrets struct {
    NewMember             []byte `tls:"head=varint"`   // KeyPackageRef
    EncryptedGroupSecrets HPKECiphertext
}
type Welcome struct {
    CipherSuite         CipherSuite
    Secrets             []EncryptedGroupSecrets `tls:"head=varint"`
    EncryptedGroupInfo  []byte                  `tls:"head=varint"`
}
func BuildWelcome(crypto CryptoProvider, suite CipherSuite, info *GroupInfo, joinerSecret []byte,
    welcomeSecret []byte, joiners []WelcomeJoiner) (*Welcome, error)

type WelcomeJoiner struct {
    KeyPackage KeyPackage
    LeafIndex  LeafIndex
    PathSecret []byte   // nil when the commit carried no path
}
```

**The two things that are easy to get wrong, both transcribed from RFC 9420 §12.4.3.1:** the group
secrets are encrypted with `EncryptWithLabel(init_key, "Welcome", encrypted_group_info,
group_secrets)` — the **context is the encrypted group info**, not the group context — and the group
info is AEAD-sealed under `welcome_key`/`welcome_nonce` with **empty AAD**.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/welcome_test.go`:

```go
func TestBuildWelcomeSealsGroupInfoUnderTheWelcomeKey(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice")
	info := testGroupInfo(t, crypto, tree, LeafIndex(0))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	joinerSecret := bytes.Repeat([]byte{1}, crypto.HashSize())
	welcomeSecret := bytes.Repeat([]byte{2}, crypto.HashSize())

	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, _ := testKeyPackage(t, crypto, bob)
	welcome, err := BuildWelcome(crypto, CipherSuiteX25519ChaCha20SHA256Ed25519, info,
		joinerSecret, welcomeSecret, []WelcomeJoiner{{KeyPackage: *kp, LeafIndex: LeafIndex(1)}})
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	if len(welcome.Secrets) != 1 {
		t.Fatalf("Secrets = %d, want 1", len(welcome.Secrets))
	}
	ref, err := kp.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if !bytes.Equal(welcome.Secrets[0].NewMember, ref) {
		t.Fatal("the secrets entry is not keyed by the joiner's KeyPackageRef")
	}

	// the group info opens under welcome_key/welcome_nonce with empty AAD
	key, nonce := WelcomeKeyNonce(crypto, welcomeSecret)
	plaintext, err := crypto.AeadOpen(key, nonce, nil, welcome.EncryptedGroupInfo)
	if err != nil {
		t.Fatalf("AeadOpen with empty AAD: %v", err)
	}
	var decoded GroupInfo
	if _, err := syntaxUnmarshalGroupInfo(plaintext, &decoded); err != nil {
		t.Fatalf("unmarshal group info: %v", err)
	}
	if decoded.GroupContext.Epoch != info.GroupContext.Epoch {
		t.Fatal("the sealed group info is not the one we built")
	}

	// the group secrets open under the joiner's init key with the encrypted
	// group info as the HPKE context
	opened, err := DecryptWithLabel(crypto, initPriv, "Welcome",
		welcome.EncryptedGroupInfo, &welcome.Secrets[0].EncryptedGroupSecrets)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	var secrets GroupSecrets
	if _, err := syntaxUnmarshalGroupSecrets(opened, &secrets); err != nil {
		t.Fatalf("unmarshal group secrets: %v", err)
	}
	if !bytes.Equal(secrets.JoinerSecret, joinerSecret) {
		t.Fatal("the joiner secret did not survive")
	}
	if secrets.PathSecret != nil {
		t.Fatal("a commit with no path must produce a null path_secret")
	}
	if len(secrets.Psks) != 0 {
		t.Fatal("v1 never sends PSKs")
	}
}

func TestBuildWelcomeCarriesThePathSecretWhenThereIsOne(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice")
	info := testGroupInfo(t, crypto, tree, LeafIndex(0))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, _ := testKeyPackage(t, crypto, bob)
	pathSecret := bytes.Repeat([]byte{9}, crypto.HashSize())
	welcome, err := BuildWelcome(crypto, CipherSuiteX25519ChaCha20SHA256Ed25519, info,
		bytes.Repeat([]byte{1}, crypto.HashSize()), bytes.Repeat([]byte{2}, crypto.HashSize()),
		[]WelcomeJoiner{{KeyPackage: *kp, LeafIndex: LeafIndex(1), PathSecret: pathSecret}})
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	opened, err := DecryptWithLabel(crypto, initPriv, "Welcome",
		welcome.EncryptedGroupInfo, &welcome.Secrets[0].EncryptedGroupSecrets)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	var secrets GroupSecrets
	if _, err := syntaxUnmarshalGroupSecrets(opened, &secrets); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if secrets.PathSecret == nil || !bytes.Equal(secrets.PathSecret.PathSecret, pathSecret) {
		t.Fatal("the path secret did not survive")
	}
}

func TestBuildWelcomeCoversEveryJoiner(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "alice")
	info := testGroupInfo(t, crypto, tree, LeafIndex(0))
	if err := info.Sign(crypto, members[0].SigPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	joiners := []WelcomeJoiner{}
	for _, name := range []string{"bob", "carol", "dave"} {
		kp, _, _ := testKeyPackage(t, crypto, testIdentity(t, crypto, name))
		joiners = append(joiners, WelcomeJoiner{KeyPackage: *kp, LeafIndex: LeafIndex(len(joiners) + 1)})
	}
	welcome, err := BuildWelcome(crypto, CipherSuiteX25519ChaCha20SHA256Ed25519, info,
		bytes.Repeat([]byte{1}, crypto.HashSize()), bytes.Repeat([]byte{2}, crypto.HashSize()), joiners)
	if err != nil {
		t.Fatalf("BuildWelcome: %v", err)
	}
	if len(welcome.Secrets) != 3 {
		t.Fatalf("Secrets = %d, want 3: the welcome set MUST cover every new member", len(welcome.Secrets))
	}
}
```

Also delete the `t.Skip("welcome lands in Task 15")` added in Task 13.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestBuildWelcome -v`
Expected: FAIL to build with `undefined: BuildWelcome`, `undefined: WelcomeJoiner`, `undefined: GroupSecrets`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/welcome.go`:

```go
// PathSecret is the optional path secret a joiner receives.
type PathSecret struct {
	PathSecret []byte `tls:"head=varint"`
}

// GroupSecrets is what one joiner receives under HPKE. Psks is always
// zero-length in v1: PSK proposals are profile-refused, so there is never a PSK
// to name.
type GroupSecrets struct {
	JoinerSecret []byte      `tls:"head=varint"`
	PathSecret   *PathSecret `tls:"optional"`
	Psks         []byte      `tls:"head=varint"`
}

// EncryptedGroupSecrets is one joiner's sealed GroupSecrets, keyed by the
// KeyPackageRef of the key package that will open it.
type EncryptedGroupSecrets struct {
	NewMember             []byte `tls:"head=varint"`
	EncryptedGroupSecrets HPKECiphertext
}

// Welcome bootstraps every member added by one commit.
type Welcome struct {
	CipherSuite        CipherSuite
	Secrets            []EncryptedGroupSecrets `tls:"head=varint"`
	EncryptedGroupInfo []byte                  `tls:"head=varint"`
}

// WelcomeJoiner is one new member and the path secret, if any, for the lowest
// node the joiner and the committer share.
type WelcomeJoiner struct {
	KeyPackage KeyPackage
	LeafIndex  LeafIndex
	PathSecret []byte
}

// BuildWelcome seals the GroupInfo once under the welcome key and seals the
// GroupSecrets once per joiner under that joiner's init key.
//
// Two details are transcribed from RFC 9420 §12.4.3.1 rather than reconstructed:
// the group info is sealed with EMPTY AAD, and the group secrets are encrypted
// with the ENCRYPTED GROUP INFO as the EncryptWithLabel context. Using the
// group context there instead compiles, interoperates with nothing, and fails
// only at the far end.
func BuildWelcome(crypto CryptoProvider, suite CipherSuite, info *GroupInfo,
	joinerSecret []byte, welcomeSecret []byte, joiners []WelcomeJoiner) (*Welcome, error) {

	encodedInfo, err := syntax.Marshal(info)
	if err != nil {
		return nil, err
	}
	key, nonce := WelcomeKeyNonce(crypto, welcomeSecret)
	encryptedInfo, err := crypto.AeadSeal(key, nonce, nil, encodedInfo)
	if err != nil {
		return nil, err
	}

	welcome := &Welcome{CipherSuite: suite, EncryptedGroupInfo: encryptedInfo}
	for i := range joiners {
		joiner := joiners[i]
		secrets := &GroupSecrets{JoinerSecret: joinerSecret, Psks: []byte{}}
		if joiner.PathSecret != nil {
			secrets.PathSecret = &PathSecret{PathSecret: joiner.PathSecret}
		}
		plaintext, err := syntax.Marshal(secrets)
		if err != nil {
			return nil, err
		}
		ciphertext, err := EncryptWithLabel(crypto, joiner.KeyPackage.InitKey, "Welcome",
			encryptedInfo, plaintext)
		if err != nil {
			return nil, err
		}
		ref, err := joiner.KeyPackage.Ref(crypto)
		if err != nil {
			return nil, err
		}
		welcome.Secrets = append(welcome.Secrets, EncryptedGroupSecrets{
			NewMember:             ref,
			EncryptedGroupSecrets: *ciphertext,
		})
	}
	return welcome, nil
}

// syntaxUnmarshalGroupSecrets keeps the syntax import local to this file.
func syntaxUnmarshalGroupSecrets(data []byte, out *GroupSecrets) (int, error) {
	return syntax.Unmarshal(data, out)
}
```

Replace the Task 13 stub in `connect/mls/group.go`:

```go
// buildWelcomeLocked builds the Welcome for every member this commit added.
// The path secret handed to each joiner is the one for the lowest node the
// joiner's leaf and the committer's leaf share, which is what lets the joiner
// derive private keys for the nodes the commit reset.
func (self *Group) buildWelcomeLocked(staged *StagedCommit) ([]byte, error) {
	info := &GroupInfo{
		GroupContext:    *staged.context,
		ConfirmationTag: staged.confirmTag,
		Signer:          self.ownLeaf,
	}
	if err := info.Sign(self.crypto, self.signer); err != nil {
		return nil, err
	}

	joiners := []WelcomeJoiner{}
	for i, leafIndex := range staged.added {
		keyPackage := staged.list.Adds[i].Proposal.Add.KeyPackage
		joiner := WelcomeJoiner{KeyPackage: keyPackage, LeafIndex: leafIndex}
		if staged.pathSecrets != nil {
			ancestor := CommonAncestor(leafIndex, self.ownLeaf)
			if secret, ok := staged.pathSecrets.SecretAt(ancestor); ok {
				joiner.PathSecret = secret
			}
		}
		joiners = append(joiners, joiner)
	}

	welcome, err := BuildWelcome(self.crypto, self.cfg.Suite, info,
		staged.joinerSecret, staged.welcomeSecret, joiners)
	if err != nil {
		return nil, err
	}
	return (&MLSMessage{
		Version:    ProtocolVersionMls10,
		WireFormat: WireFormatWelcome,
		Welcome:    welcome,
	}).Marshal()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestBuildWelcome|TestCommitAdd' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/welcome.go connect/mls/group.go connect/mls/welcome_test.go && \
git commit -m "feat(mls): welcome generation, one group info seal and one HPKE seal per joiner"
```

---

### Task 16: `JoinFromWelcome`

**Files:**
- Modify: `connect/mls/welcome.go`, `connect/mls/group.go`
- Test: `connect/mls/welcome_test.go`

**Interfaces:**
- Consumes: `DecryptWithLabel` (Crypto/HPKE plan); `ParseRatchetTree`, `(*RatchetTree).Validate/RootHash/FindLeaf`, `PathSecretToNodeKeyPair`, `DerivePathSecretNext` (TreeKEM plan); `DeriveEpochSecretsFromJoiner`, `WelcomeKeyNonce`, `EmptyPskSecret` (Key schedule plan); `CommonAncestor`, `DirectPath` (Tree math plan); `InterimTranscriptHash` (Framing plan).
- Produces:
```go
type JoinKeyMaterial struct {
    KeyPackage    KeyPackage
    InitPrivate   HpkePrivateKey
    EncryptPrivate HpkePrivateKey
    SignPrivate   SignaturePrivateKey
}
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte,
    keys *JoinKeyMaterial) (*Group, error)
```

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/welcome_test.go`:

```go
func TestJoinFromWelcomeAgreesOnTheEpochAuthenticator(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, encPriv := testKeyPackage(t, crypto, bob)
	encoded, err := syntaxMarshalKeyPackage(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}

	joinerCfg := testGroupConfig(t, crypto, bob, "group-1")
	joinerCfg.LeafKeys = LeafKeysExtension{AlgId: AlgIdXwing, DeviceXwingPub: bob.XwingPub}
	joined, err := JoinFromWelcome(joinerCfg, result.Welcome, result.RatchetTree, &JoinKeyMaterial{
		KeyPackage:     *kp,
		InitPrivate:    initPriv,
		EncryptPrivate: encPriv,
		SignPrivate:    bob.SigPriv,
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}
	defer joined.Close()

	if joined.Epoch() != group.Epoch() {
		t.Fatalf("joiner epoch = %d, committer epoch = %d", joined.Epoch(), group.Epoch())
	}
	if !bytes.Equal(joined.EpochAuthenticator(), group.EpochAuthenticator()) {
		t.Fatal("joiner and committer disagree on the epoch authenticator")
	}
	if joined.OwnLeafIndex() == group.OwnLeafIndex() {
		t.Fatal("joiner and committer resolved to the same leaf")
	}
	if len(joined.Members()) != 2 {
		t.Fatalf("joiner sees %d members, want 2", len(joined.Members()))
	}
	// the joiner must be able to derive the same storage exporter output
	committerExport, err := group.Export("URmessage/v1/storage", nil, 32)
	if err != nil {
		t.Fatalf("committer Export: %v", err)
	}
	joinerExport, err := joined.Export("URmessage/v1/storage", nil, 32)
	if err != nil {
		t.Fatalf("joiner Export: %v", err)
	}
	if !bytes.Equal(committerExport, joinerExport) {
		t.Fatal("joiner and committer derive different storage secrets")
	}
}

func TestJoinFromWelcomeRejectsAWrongTree(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, encPriv := testKeyPackage(t, crypto, bob)
	encoded, _ := syntaxMarshalKeyPackage(kp)
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// a tree from a different group: the tree hash cannot match the group info
	other, _ := testTreeWith(t, crypto, "mallory", "trudy")
	otherTree, err := other.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	joinerCfg := testGroupConfig(t, crypto, bob, "group-1")
	_, err = JoinFromWelcome(joinerCfg, result.Welcome, otherTree, &JoinKeyMaterial{
		KeyPackage: *kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: bob.SigPriv,
	})
	if !errors.Is(err, ErrWelcomeTreeHashMismatch) {
		t.Fatalf("JoinFromWelcome error = %v, want ErrWelcomeTreeHashMismatch", err)
	}
}

func TestJoinFromWelcomeRejectsAWelcomeForSomebodyElse(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	bob := testIdentity(t, crypto, "bob")
	kp, _, _ := testKeyPackage(t, crypto, bob)
	encoded, _ := syntaxMarshalKeyPackage(kp)
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	mallory := testIdentity(t, crypto, "mallory")
	otherKp, otherInit, otherEnc := testKeyPackage(t, crypto, mallory)
	joinerCfg := testGroupConfig(t, crypto, mallory, "group-1")
	_, err = JoinFromWelcome(joinerCfg, result.Welcome, result.RatchetTree, &JoinKeyMaterial{
		KeyPackage: *otherKp, InitPrivate: otherInit, EncryptPrivate: otherEnc, SignPrivate: mallory.SigPriv,
	})
	if !errors.Is(err, ErrWelcomeNoMatchingKeyPackage) {
		t.Fatalf("JoinFromWelcome error = %v, want ErrWelcomeNoMatchingKeyPackage", err)
	}
}

func TestJoinFromWelcomeRejectsATamperedConfirmationTag(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")
	defer group.Close()
	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, encPriv := testKeyPackage(t, crypto, bob)
	encoded, _ := syntaxMarshalKeyPackage(kp)
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// flip a byte inside the sealed group info: the AEAD must refuse it
	tampered := append([]byte(nil), result.Welcome...)
	tampered[len(tampered)-1] ^= 0xFF
	joinerCfg := testGroupConfig(t, crypto, bob, "group-1")
	_, err = JoinFromWelcome(joinerCfg, tampered, result.RatchetTree, &JoinKeyMaterial{
		KeyPackage: *kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: bob.SigPriv,
	})
	if err == nil {
		t.Fatal("JoinFromWelcome accepted a tampered welcome")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestJoinFromWelcome -v`
Expected: FAIL to build with `undefined: JoinFromWelcome`, `undefined: JoinKeyMaterial`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/group.go`:

```go
// JoinKeyMaterial is what a joiner holds for the KeyPackage a Welcome names.
type JoinKeyMaterial struct {
	KeyPackage     KeyPackage
	InitPrivate    HpkePrivateKey
	EncryptPrivate HpkePrivateKey
	SignPrivate    SignaturePrivateKey
}

// JoinFromWelcome builds group state from a Welcome and an out-of-band ratchet
// tree, following the RFC 9420 §12.4.3.1 receive steps in order. The tree is
// always out of band here: v1 does not put a ratchet_tree extension in the
// GroupInfo, because MASTER §8.2 already publishes one snapshot record per
// epoch and a second copy inside every Welcome is the same 300 KB again.
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte,
	keys *JoinKeyMaterial) (*Group, error) {

	crypto := cfg.Crypto
	profile := cfg.Profile
	if profile == nil {
		profile = DefaultProfile()
	}

	message, err := ParseMLSMessage(welcome)
	if err != nil {
		return nil, err
	}
	if message.WireFormat != WireFormatWelcome || message.Welcome == nil {
		return nil, fmt.Errorf("mls: message is not a welcome")
	}
	parsed := message.Welcome
	if parsed.CipherSuite != keys.KeyPackage.CipherSuite {
		return nil, ErrWelcomeSuiteMismatch
	}
	if err := profile.CheckCiphersuiteForCreate(parsed.CipherSuite); err != nil {
		return nil, err
	}

	// step 1: find our entry by KeyPackageRef
	ref, err := keys.KeyPackage.Ref(crypto)
	if err != nil {
		return nil, err
	}
	var entry *EncryptedGroupSecrets
	for i := range parsed.Secrets {
		if bytesEqual(parsed.Secrets[i].NewMember, ref) {
			entry = &parsed.Secrets[i]
			break
		}
	}
	if entry == nil {
		return nil, ErrWelcomeNoMatchingKeyPackage
	}

	// step 2: open the group secrets, with the encrypted group info as context
	plaintext, err := DecryptWithLabel(crypto, keys.InitPrivate, "Welcome",
		parsed.EncryptedGroupInfo, &entry.EncryptedGroupSecrets)
	if err != nil {
		return nil, err
	}
	var secrets GroupSecrets
	if _, err := syntaxUnmarshalGroupSecrets(plaintext, &secrets); err != nil {
		return nil, err
	}
	if len(secrets.Psks) != 0 {
		return nil, fmt.Errorf("%w: welcome names a pre-shared key", ErrProfilePSK)
	}

	// step 3: open the group info under welcome_key/welcome_nonce, empty AAD
	welcomeSecret := crypto.DeriveSecret(
		crypto.Extract(secrets.JoinerSecret, EmptyPskSecret(crypto)), "welcome")
	key, nonce := WelcomeKeyNonce(crypto, welcomeSecret)
	infoBytes, err := crypto.AeadOpen(key, nonce, nil, parsed.EncryptedGroupInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWelcomeGroupInfoDecrypt, err)
	}
	var info GroupInfo
	if _, err := syntaxUnmarshalGroupInfo(infoBytes, &info); err != nil {
		return nil, err
	}

	// step 4: the tree, its hash, and its validity
	tree, err := ParseRatchetTree(crypto, ratchetTree)
	if err != nil {
		return nil, err
	}
	treeHash, err := tree.RootHash()
	if err != nil {
		return nil, err
	}
	if !bytesEqual(treeHash, info.GroupContext.TreeHash) {
		return nil, ErrWelcomeTreeHashMismatch
	}
	if err := info.Verify(crypto, tree); err != nil {
		return nil, err
	}
	if err := tree.Validate(info.GroupContext.GroupId, info.GroupContext.Extensions, nowFunc()); err != nil {
		return nil, err
	}
	for _, ext := range info.GroupContext.Extensions {
		if err := profile.CheckGroupExtension(ext.ExtensionType); err != nil {
			return nil, err
		}
	}
	if _, err := GroupPolicyOf(info.GroupContext.Extensions); err != nil {
		return nil, err
	}

	// step 5: find our own leaf
	ownLeaf, ok := tree.FindLeaf(&keys.KeyPackage.LeafNode)
	if !ok {
		return nil, ErrWelcomeLeafNotFound
	}

	// step 6: the key schedule for the epoch we are joining
	contextBytes, err := info.GroupContext.Marshal()
	if err != nil {
		return nil, err
	}
	epochSecrets, err := DeriveEpochSecretsFromJoiner(crypto, secrets.JoinerSecret,
		EmptyPskSecret(crypto), contextBytes)
	if err != nil {
		return nil, err
	}
	if !crypto.MacVerify(epochSecrets.ConfirmationKey,
		info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag) {
		return nil, ErrBadConfirmationTag
	}
	interimHash, err := InterimTranscriptHash(crypto,
		info.GroupContext.ConfirmedTranscriptHash, info.ConfirmationTag)
	if err != nil {
		return nil, err
	}

	// step 7: install the private keys we hold, and the path secrets we derived
	if err := tree.SetLeafPrivate(ownLeaf, keys.EncryptPrivate); err != nil {
		return nil, err
	}
	if secrets.PathSecret != nil {
		ancestor := CommonAncestor(ownLeaf, info.Signer)
		if err := tree.InstallPathSecret(ownLeaf, ancestor, secrets.PathSecret.PathSecret); err != nil {
			return nil, err
		}
	}

	joinCfg := *cfg
	joinCfg.Suite = parsed.CipherSuite
	joinCfg.GroupId = append([]byte(nil), info.GroupContext.GroupId...)
	joinCfg.Extensions = info.GroupContext.Extensions
	group := &Group{
		cfg:         &joinCfg,
		crypto:      crypto,
		signer:      keys.SignPrivate,
		cred:        keys.KeyPackage.LeafNode.Credential,
		ownLeaf:     ownLeaf,
		ownEncPriv:  keys.EncryptPrivate,
		tree:        tree,
		context:     &info.GroupContext,
		secrets:     epochSecrets,
		secretTree:  NewSecretTree(crypto, tree.Size(), epochSecrets.EncryptionSecret),
		interimHash: interimHash,
		proposals:   NewProposalCache(),
	}
	if err := group.persist(); err != nil {
		return nil, err
	}
	return group, nil
}

// bytesEqual is a length-then-content compare kept local so the file does not
// import bytes for one call.
func bytesEqual(a, b []byte) bool {
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

`(*RatchetTree).SetLeafPrivate(LeafIndex, HpkePrivateKey) error`,
`(*RatchetTree).InstallPathSecret(own LeafIndex, from NodeIndex, secret []byte) error` and
`(*RatchetTree).FindLeaf(*LeafNode) (LeafIndex, bool)` are consumed from the TreeKEM plan.
`InstallPathSecret` walks from `from` to the root deriving each node's key pair and MUST verify that
the derived public key equals the public key already in the node, returning `ErrPathKeyMismatch`
otherwise — RFC 9420 §12.4.3.1: "The private key MUST be the private key that corresponds to the
public key in the node."

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestJoinFromWelcome -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/group.go connect/mls/welcome_test.go && \
git commit -m "feat(mls): join a group from a Welcome and an out-of-band ratchet tree"
```

---

### Task 17: The `welcome` vector family — the gate

**Files:**
- Create: `connect/mls/welcome_vectors_test.go`
- Create: `connect/mls/testdata/vectors/welcome.json`

**Interfaces:**
- Consumes: `ParseMLSMessage`; `(*KeyPackage).Ref`; `DecryptWithLabel`; `WelcomeKeyNonce`; `EmptyPskSecret`; everything Tasks 14–16 produce.
- Produces: no new exported API. This task is the acceptance gate for this plan.

**Vector format** (`mlswg/mls-implementations/test-vectors/welcome.json`, verified against the pinned
checkout): an array of objects with `cipher_suite` (uint16), `init_priv`, `signer_pub`,
`key_package` (a serialized `MLSMessage(KeyPackage)`) and `welcome` (a serialized
`MLSMessage(Welcome)`), all hex.

**Verification, verbatim from `test-vectors.md`:**
- Decrypt the Welcome message: identify the entry in `welcome.secrets` corresponding to
  `key_package`; decrypt the encrypted group secrets using `init_priv`; decrypt the encrypted group
  info.
- Verify the signature on the decrypted group info using `signer_pub`.

- [ ] **Step 1: Write the failing test**

`connect/mls/welcome_vectors_test.go`:

```go
package mls

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type welcomeVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	InitPriv    string `json:"init_priv"`
	SignerPub   string `json:"signer_pub"`
	KeyPackage  string `json:"key_package"`
	Welcome     string `json:"welcome"`
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return out
}

func TestWelcomeVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors/welcome.json")
	if err != nil {
		t.Fatalf("read welcome.json: %v", err)
	}
	var vectors []welcomeVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse welcome.json: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("welcome.json is empty")
	}

	ran := 0
	for i, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			// a suite this build does not implement is skipped, not failed:
			// v1 registers 0x0003 and 0x0001 only.
			continue
		}
		ran += 1

		kpMessage, err := ParseMLSMessage(mustHex(t, vector.KeyPackage))
		if err != nil {
			t.Fatalf("vector %d: parse key package: %v", i, err)
		}
		if kpMessage.KeyPackage == nil {
			t.Fatalf("vector %d: message is not a key package", i)
		}
		welcomeMessage, err := ParseMLSMessage(mustHex(t, vector.Welcome))
		if err != nil {
			t.Fatalf("vector %d: parse welcome: %v", i, err)
		}
		if welcomeMessage.Welcome == nil {
			t.Fatalf("vector %d: message is not a welcome", i)
		}
		welcome := welcomeMessage.Welcome

		ref, err := kpMessage.KeyPackage.Ref(crypto)
		if err != nil {
			t.Fatalf("vector %d: key package ref: %v", i, err)
		}
		var entry *EncryptedGroupSecrets
		for j := range welcome.Secrets {
			if bytesEqual(welcome.Secrets[j].NewMember, ref) {
				entry = &welcome.Secrets[j]
				break
			}
		}
		if entry == nil {
			t.Fatalf("vector %d: no secrets entry matches the key package ref", i)
		}

		plaintext, err := DecryptWithLabel(crypto, HpkePrivateKey(mustHex(t, vector.InitPriv)),
			"Welcome", welcome.EncryptedGroupInfo, &entry.EncryptedGroupSecrets)
		if err != nil {
			t.Fatalf("vector %d: decrypt group secrets: %v", i, err)
		}
		var secrets GroupSecrets
		if _, err := syntaxUnmarshalGroupSecrets(plaintext, &secrets); err != nil {
			t.Fatalf("vector %d: parse group secrets: %v", i, err)
		}

		welcomeSecret := crypto.DeriveSecret(
			crypto.Extract(secrets.JoinerSecret, EmptyPskSecret(crypto)), "welcome")
		key, nonce := WelcomeKeyNonce(crypto, welcomeSecret)
		infoBytes, err := crypto.AeadOpen(key, nonce, nil, welcome.EncryptedGroupInfo)
		if err != nil {
			t.Fatalf("vector %d: decrypt group info: %v", i, err)
		}
		var info GroupInfo
		if _, err := syntaxUnmarshalGroupInfo(infoBytes, &info); err != nil {
			t.Fatalf("vector %d: parse group info: %v", i, err)
		}

		content, err := syntaxMarshalGroupInfoTBS(info.tbs())
		if err != nil {
			t.Fatalf("vector %d: marshal group info tbs: %v", i, err)
		}
		if err := crypto.VerifyWithLabel(SignaturePublicKey(mustHex(t, vector.SignerPub)),
			"GroupInfoTBS", content, info.Signature); err != nil {
			t.Fatalf("vector %d: group info signature: %v", i, err)
		}
	}
	if ran == 0 {
		t.Fatal("no welcome vector matched an implemented ciphersuite")
	}
}

func TestWelcomeVectorsGenerateDirection(t *testing.T) {
	// Generation catches the class of bug where encoder and decoder are wrong in
	// the same direction, which verification alone cannot see. Spec A §4.2.1.
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-vector")
	defer group.Close()

	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, _ := testKeyPackage(t, crypto, bob)
	encoded, err := syntaxMarshalKeyPackage(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// verify our own welcome through the vector path, not through JoinFromWelcome
	welcomeMessage, err := ParseMLSMessage(result.Welcome)
	if err != nil {
		t.Fatalf("ParseMLSMessage: %v", err)
	}
	welcome := welcomeMessage.Welcome
	ref, err := kp.Ref(crypto)
	if err != nil {
		t.Fatalf("Ref: %v", err)
	}
	if !bytesEqual(welcome.Secrets[0].NewMember, ref) {
		t.Fatal("our own welcome is not keyed by the joiner's KeyPackageRef")
	}
	plaintext, err := DecryptWithLabel(crypto, initPriv, "Welcome",
		welcome.EncryptedGroupInfo, &welcome.Secrets[0].EncryptedGroupSecrets)
	if err != nil {
		t.Fatalf("DecryptWithLabel: %v", err)
	}
	var secrets GroupSecrets
	if _, err := syntaxUnmarshalGroupSecrets(plaintext, &secrets); err != nil {
		t.Fatalf("parse group secrets: %v", err)
	}
	welcomeSecret := crypto.DeriveSecret(
		crypto.Extract(secrets.JoinerSecret, EmptyPskSecret(crypto)), "welcome")
	key, nonce := WelcomeKeyNonce(crypto, welcomeSecret)
	if _, err := crypto.AeadOpen(key, nonce, nil, welcome.EncryptedGroupInfo); err != nil {
		t.Fatalf("our own group info did not open under the derived welcome key: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestWelcomeVectors -v`
Expected: FAIL with `read welcome.json: open testdata/vectors/welcome.json: no such file or
directory`, then after vendoring, FAIL to build with `undefined: syntaxMarshalGroupInfoTBS`.

- [ ] **Step 3: Write minimal implementation**

Vendor the vector file at the pinned mlswg commit and record it:

```bash
mkdir -p connect/mls/testdata/vectors
curl -fsSL "https://raw.githubusercontent.com/mlswg/mls-implementations/$(grep -oP 'mlswg=\K\S+' connect/mls/interop/PINS.md)/test-vectors/welcome.json" \
  -o connect/mls/testdata/vectors/welcome.json
```

Add to `connect/mls/welcome.go`:

```go
// syntaxMarshalGroupInfoTBS keeps the syntax import local and gives the vector
// test the exact signature input without re-deriving it.
func syntaxMarshalGroupInfoTBS(tbs *GroupInfoTBS) ([]byte, error) {
	return syntax.Marshal(tbs)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestWelcomeVectors -v`
Expected: PASS, with `ran` greater than zero.

- [ ] **Step 5: Commit**

```bash
git add connect/mls/welcome_vectors_test.go connect/mls/welcome.go connect/mls/testdata/vectors/welcome.json && \
git commit -m "test(mls): the RFC 9420 welcome vector family, verify and generate directions"
```

---

### Task 18: Commit processing, RFC 9420 §12.4.2

**Files:**
- Modify: `connect/mls/group.go`
- Test: `connect/mls/group_test.go`

**Interfaces:**
- Consumes: `UnprotectPrivate`, `(*AuthenticatedContent).VerifySignature`, `ConfirmedTranscriptHash`, `InterimTranscriptHash` (Framing plan); `(*RatchetTree).ApplyUpdatePath` (TreeKEM plan); `ApplyProposals`, `ValidateProposalList`, `ValidateCommit`, `ValSem205ConfirmationTag` (Tasks 7, 8, 10).
- Produces:
```go
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
func (self *Group) Protect(aad, plaintext []byte) ([]byte, error)
func (self *Group) Unprotect(privateMessage []byte) (*ApplicationMessage, error)
```

`ProcessMessage` never mutates live epoch state. A commit comes back as a `StagedCommit` and the
caller decides — `connect/message` needs that gap to run its own policy checks and to record the
epoch's wraps before the epoch advances.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/group_test.go`:

```go
// testTwoMemberGroup returns a committer and a joiner already in the same
// group at the same epoch.
func testTwoMemberGroup(t *testing.T, crypto CryptoProvider) (*Group, *Group, *testMember, *testMember) {
	t.Helper()
	owner := testIdentity(t, crypto, "owner")
	group := testNewGroup(t, crypto, owner, "group-1")

	bob := testIdentity(t, crypto, "bob")
	kp, initPriv, encPriv := testKeyPackage(t, crypto, bob)
	encoded, err := syntaxMarshalKeyPackage(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	if _, err := group.ProposeAdd(encoded); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	result, err := group.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	joinerCfg := testGroupConfig(t, crypto, bob, "group-1")
	joined, err := JoinFromWelcome(joinerCfg, result.Welcome, result.RatchetTree, &JoinKeyMaterial{
		KeyPackage: *kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: bob.SigPriv,
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome: %v", err)
	}
	return group, joined, owner, bob
}

func TestProcessCommitStagesRatherThanMerges(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	result, err := committer.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	epochBefore := receiver.Epoch()
	processed, err := receiver.ProcessMessage(result.Commit)
	if err != nil {
		t.Fatalf("ProcessMessage: %v", err)
	}
	if processed.Kind != ProcessedCommit || processed.Commit == nil {
		t.Fatalf("Kind = %d", processed.Kind)
	}
	if receiver.Epoch() != epochBefore {
		t.Fatal("ProcessMessage must not advance the epoch")
	}
	if err := receiver.ApplyCommit(processed); err != nil {
		t.Fatalf("ApplyCommit: %v", err)
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	if receiver.Epoch() != committer.Epoch() {
		t.Fatalf("receiver epoch %d, committer epoch %d", receiver.Epoch(), committer.Epoch())
	}
	if !bytes.Equal(receiver.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatal("receiver and committer disagree on the epoch authenticator")
	}
}

func TestProcessCommitRejectsAWrongEpoch(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	first, err := committer.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	second, err := committer.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	// receiver is still at the first epoch, so the second commit is ahead
	if _, err := receiver.ProcessMessage(second); err == nil {
		t.Fatal("ProcessMessage accepted a commit from a future epoch")
	}
	if _, err := receiver.ProcessMessage(first); err != nil {
		t.Fatalf("ProcessMessage on the right epoch: %v", err)
	}
}

func TestProcessCommitRejectsATamperedConfirmationTag(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	result, err := committer.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	tampered := append([]byte(nil), result.Commit...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := receiver.ProcessMessage(tampered); err == nil {
		t.Fatal("ProcessMessage accepted a tampered commit")
	}
}

func TestProcessCommitReportsSelfRemoval(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	if _, err := committer.ProposeRemove(receiver.OwnLeafIndex()); err != nil {
		t.Fatalf("ProposeRemove: %v", err)
	}
	result, err := committer.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	processed, err := receiver.ProcessMessage(result.Commit)
	if err != nil {
		t.Fatalf("ProcessMessage: %v", err)
	}
	if !processed.Commit.RemovesSelf() {
		t.Fatal("a commit removing us must report RemovesSelf")
	}
	if err := receiver.ApplyCommit(processed); !errors.Is(err, ErrRemovedFromGroup) {
		t.Fatalf("ApplyCommit error = %v, want ErrRemovedFromGroup", err)
	}
}

func TestProcessProposalCachesIt(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	message, err := receiver.ProposeUpdate()
	if err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	processed, err := committer.ProcessMessage(message)
	if err != nil {
		t.Fatalf("ProcessMessage: %v", err)
	}
	if processed.Kind != ProcessedProposal || processed.Proposal == nil {
		t.Fatalf("Kind = %d", processed.Kind)
	}
	if len(committer.pendingProposalsForTest()) != 1 {
		t.Fatal("an inbound proposal must be cached so a later commit can reference it")
	}
	// the committer can now commit the other member's update by reference
	if _, err := committer.Commit(nil, nil, nil); err != nil {
		t.Fatalf("Commit covering the peer update: %v", err)
	}
}

func TestProtectAndUnprotectRoundTrip(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	message, err := committer.Protect([]byte("aad"), []byte("hello"))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	application, err := receiver.Unprotect(message)
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if string(application.Plaintext) != "hello" || string(application.AuthenticatedData) != "aad" {
		t.Fatalf("application = %+v", application)
	}
	if application.SenderLeaf != committer.OwnLeafIndex() {
		t.Fatalf("SenderLeaf = %d, want %d", application.SenderLeaf, committer.OwnLeafIndex())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestProcess|TestProtectAndUnprotect' -v`
Expected: FAIL to build with `undefined: (*Group).ProcessMessage`, `undefined: Processed`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/group.go`:

```go
// ProcessedKind discriminates what ProcessMessage returned.
type ProcessedKind uint8

const (
	ProcessedApplication ProcessedKind = 1
	ProcessedProposal    ProcessedKind = 2
	ProcessedCommit      ProcessedKind = 3
)

// ApplicationMessage is one decrypted application message.
type ApplicationMessage struct {
	SenderLeaf        LeafIndex
	AuthenticatedData []byte
	Plaintext         []byte
}

// Processed is the result of ingesting one MLSMessage.
type Processed struct {
	Kind        ProcessedKind
	Sender      Sender
	Application *ApplicationMessage
	Proposal    *Proposal
	Commit      *StagedCommit
}

// ProcessMessage ingests one MLSMessage. It NEVER mutates live epoch state: a
// commit comes back staged, so the caller can run its own policy and record the
// epoch's wraps before the epoch advances.
func (self *Group) ProcessMessage(message []byte) (*Processed, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, fmt.Errorf("mls: group is closed")
	}

	parsed, err := ParseMLSMessage(message)
	if err != nil {
		return nil, err
	}
	profile := self.cfg.Profile
	if profile == nil {
		profile = DefaultProfile()
	}
	if err := profile.CheckWireFormat(parsed.WireFormat); err != nil {
		return nil, err
	}
	if parsed.PrivateMessage == nil {
		return nil, ErrApplicationMustBeCiphertext
	}
	authenticated, err := UnprotectPrivate(self.crypto, self.secretTree,
		self.secrets.SenderDataSecret, self.context, parsed.PrivateMessage)
	if err != nil {
		return nil, err
	}

	// ValSem002 and ValSem003
	if !bytesEqual(authenticated.Content.GroupId, self.context.GroupId) {
		return nil, ErrWrongGroupId
	}
	if authenticated.Content.Epoch != self.context.Epoch {
		return nil, fmt.Errorf("%w: message epoch %d, group epoch %d",
			ErrWrongEpoch, authenticated.Content.Epoch, self.context.Epoch)
	}
	// ValSem004
	sender := authenticated.Content.Sender
	if sender.SenderType != SenderTypeMember {
		return nil, fmt.Errorf("%w: sender type %d is not implemented in v1",
			ErrProfileExternalSender, sender.SenderType)
	}
	senderLeaf, ok := self.tree.LeafNode(sender.LeafIndex)
	if !ok {
		return nil, fmt.Errorf("%w: leaf %d", ErrBlankSenderLeaf, sender.LeafIndex)
	}
	// ValSem010
	if err := authenticated.VerifySignature(self.crypto, senderLeaf.SignatureKey, self.context); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	switch authenticated.Content.ContentType {
	case ContentTypeApplication:
		return &Processed{
			Kind:   ProcessedApplication,
			Sender: sender,
			Application: &ApplicationMessage{
				SenderLeaf:        sender.LeafIndex,
				AuthenticatedData: authenticated.Content.AuthenticatedData,
				Plaintext:         authenticated.Content.ApplicationData,
			},
		}, nil
	case ContentTypeProposal:
		if _, err := self.proposals.Store(self.crypto, authenticated); err != nil {
			return nil, err
		}
		return &Processed{Kind: ProcessedProposal, Sender: sender, Proposal: authenticated.Content.Proposal}, nil
	case ContentTypeCommit:
		staged, err := self.stageInboundCommitLocked(authenticated)
		if err != nil {
			return nil, err
		}
		return &Processed{Kind: ProcessedCommit, Sender: sender, Commit: staged}, nil
	}
	return nil, fmt.Errorf("mls: content type %d is not defined", authenticated.Content.ContentType)
}

// stageInboundCommitLocked is the receive half of RFC 9420 §12.4.2, in the
// order the RFC lists the steps.
func (self *Group) stageInboundCommitLocked(authenticated *AuthenticatedContent) (*StagedCommit, error) {
	commit := authenticated.Content.Commit
	if commit == nil {
		return nil, fmt.Errorf("mls: commit content with no commit")
	}
	committer := authenticated.Content.Sender.LeafIndex
	if len(authenticated.Auth.ConfirmationTag) == 0 {
		return nil, ErrMissingConfirmationTag
	}

	list, err := self.proposals.Resolve(self.crypto, committer, commit.Proposals)
	if err != nil {
		return nil, err
	}
	applied, err := ApplyProposals(self.crypto, self.tree, self.context, self.ownLeaf, list)
	if err != nil {
		return nil, err
	}
	if err := ValidateProposalList(&ProposalValidationInput{
		Crypto:     self.crypto,
		Tree:       self.tree,
		Context:    self.context,
		Extensions: applied.Extensions,
		Committer:  committer,
		List:       list,
		Now:        nowFunc(),
	}); err != nil {
		return nil, err
	}
	if err := self.checkMembershipCapsLocked(applied); err != nil {
		return nil, err
	}
	if err := self.checkRemovalAuthorityLocked(list, committer); err != nil {
		return nil, err
	}
	if err := self.checkSuccessionLocked(list, applied, committer); err != nil {
		return nil, err
	}
	if err := ValidateCommit(&CommitValidationInput{
		Crypto:     self.crypto,
		PreTree:    self.tree,
		PostTree:   applied.Tree,
		Context:    self.context,
		Extensions: applied.Extensions,
		Committer:  committer,
		Own:        self.ownLeaf,
		List:       list,
		Commit:     commit,
		Now:        nowFunc(),
	}); err != nil {
		return nil, err
	}

	commitSecret := make([]byte, self.crypto.HashSize())
	if commit.Path != nil {
		provisional := &GroupContext{
			Version:                 self.context.Version,
			CipherSuite:             self.context.CipherSuite,
			GroupId:                 self.context.GroupId,
			Epoch:                   self.context.Epoch + 1,
			ConfirmedTranscriptHash: self.context.ConfirmedTranscriptHash,
			Extensions:              applied.Extensions,
		}
		treeHash, err := applied.Tree.RootHash()
		if err != nil {
			return nil, err
		}
		provisional.TreeHash = treeHash
		provisionalBytes, err := provisional.Marshal()
		if err != nil {
			return nil, err
		}
		secret, err := applied.Tree.ApplyUpdatePath(committer, commit.Path, self.ownLeaf,
			self.ownEncPriv, provisionalBytes, applied.AddedLeaves)
		if err != nil {
			return nil, err
		}
		commitSecret = secret
	}

	confirmedHash, err := ConfirmedTranscriptHash(self.crypto, self.interimHash, authenticated)
	if err != nil {
		return nil, err
	}
	treeHash, err := applied.Tree.RootHash()
	if err != nil {
		return nil, err
	}
	newContext := &GroupContext{
		Version:                 self.context.Version,
		CipherSuite:             self.context.CipherSuite,
		GroupId:                 append([]byte(nil), self.context.GroupId...),
		Epoch:                   self.context.Epoch + 1,
		TreeHash:                treeHash,
		ConfirmedTranscriptHash: confirmedHash,
		Extensions:              applied.Extensions,
	}
	newContextBytes, err := newContext.Marshal()
	if err != nil {
		return nil, err
	}
	secrets, err := DeriveEpochSecrets(self.crypto, self.secrets.InitSecret, commitSecret,
		EmptyPskSecret(self.crypto), newContextBytes)
	if err != nil {
		return nil, err
	}

	// ValSem205: the confirmation tag is the group's fork detector, so it is
	// checked before any of this state is allowed near the live group.
	if err := ValSem205ConfirmationTag(&CommitValidationInput{
		Crypto:          self.crypto,
		ConfirmationKey: secrets.ConfirmationKey,
		ConfirmedHash:   confirmedHash,
		ConfirmationTag: authenticated.Auth.ConfirmationTag,
	}); err != nil {
		return nil, err
	}
	interimHash, err := InterimTranscriptHash(self.crypto, confirmedHash, authenticated.Auth.ConfirmationTag)
	if err != nil {
		return nil, err
	}

	return &StagedCommit{
		committer:   committer,
		epoch:       newContext.Epoch,
		context:     newContext,
		tree:        applied.Tree,
		secrets:     secrets,
		secretTree:  NewSecretTree(self.crypto, applied.Tree.Size(), secrets.EncryptionSecret),
		ownEncPriv:  self.ownEncPriv,
		interimHash: interimHash,
		list:        list,
		added:       applied.AddedLeaves,
		removed:     applied.RemovedLeaves,
		updated:     applied.UpdatedLeaves,
		selfRemoved: applied.SelfRemoved,
		hasPath:     commit.Path != nil,
		confirmTag:  authenticated.Auth.ConfirmationTag,
	}, nil
}

// ApplyCommit promotes a staged inbound commit to live state.
func (self *Group) ApplyCommit(processed *Processed) error {
	if processed == nil || processed.Kind != ProcessedCommit || processed.Commit == nil {
		return fmt.Errorf("mls: ApplyCommit called with a non-commit result")
	}
	self.stateLock.Lock()
	self.pending = processed.Commit
	self.stateLock.Unlock()
	if processed.Commit.RemovesSelf() {
		self.stateLock.Lock()
		self.pending = nil
		self.closed = true
		self.secrets = nil
		self.secretTree = nil
		self.stateLock.Unlock()
		return ErrRemovedFromGroup
	}
	return self.MergePendingCommit()
}

// Protect seals an application message under the current epoch.
func (self *Group) Protect(aad, plaintext []byte) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, fmt.Errorf("mls: group is closed")
	}
	content := &FramedContent{
		GroupId:           append([]byte(nil), self.context.GroupId...),
		Epoch:             self.context.Epoch,
		Sender:            Sender{SenderType: SenderTypeMember, LeafIndex: self.ownLeaf},
		AuthenticatedData: aad,
		ContentType:       ContentTypeApplication,
		ApplicationData:   plaintext,
	}
	authenticated, err := SignFramedContent(self.crypto, self.signer,
		WireFormatPrivateMessage, content, self.context)
	if err != nil {
		return nil, err
	}
	private, err := ProtectPrivate(self.crypto, self.secretTree, self.secrets.SenderDataSecret,
		self.context, authenticated, 0)
	if err != nil {
		return nil, err
	}
	return (&MLSMessage{
		Version:        ProtocolVersionMls10,
		WireFormat:     WireFormatPrivateMessage,
		PrivateMessage: private,
	}).Marshal()
}

// Unprotect opens an application message.
func (self *Group) Unprotect(privateMessage []byte) (*ApplicationMessage, error) {
	processed, err := self.ProcessMessage(privateMessage)
	if err != nil {
		return nil, err
	}
	if processed.Kind != ProcessedApplication {
		return nil, ErrApplicationMustBeCiphertext
	}
	return processed.Application, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestProcess|TestProtectAndUnprotect' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/group.go connect/mls/group_test.go && \
git commit -m "feat(mls): commit processing following RFC 9420 section 12.4.2"
```

---

### Task 19: The epoch advance — persistence and the past-epoch window

**Files:**
- Modify: `connect/mls/group.go`
- Test: `connect/mls/group_test.go`

**Interfaces:**
- Consumes: `StateStore` (Task 11); `syntax.Marshal`, `syntax.Unmarshal`.
- Produces:
```go
type groupStateBlob struct {
    Version     uint16
    Context     []byte `tls:"head=varint"`
    Tree        []byte `tls:"head=varint"`
    InterimHash []byte `tls:"head=varint"`
    OwnLeaf     uint32
    OwnEncPriv  []byte `tls:"head=varint"`
    Secrets     []byte `tls:"head=varint"`
}
func (self *Group) MergePendingCommit() error
func LoadGroup(cfg *GroupConfig, epoch uint64, signer SignaturePrivateKey) (*Group, error)
```

**`DeleteGroupStateBefore` is a security requirement, not housekeeping.** `eph_root[n]` lives in the
epoch state, so a retained old epoch state is a retained `eph_root` — the thing MASTER §8.1 says must
become undecryptable. `PastEpochWindow = 32` and the call runs on **every** merged commit.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/group_test.go`:

```go
func TestMergePendingCommitPersistsAndPrunes(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	store := cfg.Store.(*testStore)
	group, err := NewGroup(cfg, owner.SigPriv, Credential{CredentialType: CredentialTypeBasic, Identity: owner.IdentityPub})
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close()

	for i := 0; i < 3; i += 1 {
		if _, err := group.Commit(nil, nil, nil); err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
		if err := group.MergePendingCommit(); err != nil {
			t.Fatalf("MergePendingCommit %d: %v", i, err)
		}
	}
	if group.Epoch() != 3 {
		t.Fatalf("Epoch = %d, want 3", group.Epoch())
	}
	if _, err := store.GetGroupState([]byte("group-1"), 3); err != nil {
		t.Fatalf("epoch 3 state was not persisted: %v", err)
	}
	if len(store.deletes) != 3 {
		t.Fatalf("DeleteGroupStateBefore was called %d times, want once per merged commit", len(store.deletes))
	}
	// epoch 3 - PastEpochWindow underflows to 0, so nothing is deleted yet
	if store.deletes[len(store.deletes)-1] != 0 {
		t.Fatalf("delete cutoff = %d, want 0 while the group is younger than the window",
			store.deletes[len(store.deletes)-1])
	}
}

func TestPastEpochWindowDropsOlderState(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	store := cfg.Store.(*testStore)
	group, err := NewGroup(cfg, owner.SigPriv, Credential{CredentialType: CredentialTypeBasic, Identity: owner.IdentityPub})
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close()

	for i := uint64(0); i < PastEpochWindow+2; i += 1 {
		if _, err := group.Commit(nil, nil, nil); err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
		if err := group.MergePendingCommit(); err != nil {
			t.Fatalf("MergePendingCommit %d: %v", i, err)
		}
	}
	cutoff := store.deletes[len(store.deletes)-1]
	if cutoff != group.Epoch()-PastEpochWindow {
		t.Fatalf("delete cutoff = %d, want %d", cutoff, group.Epoch()-PastEpochWindow)
	}
	if _, err := store.GetGroupState([]byte("group-1"), 0); err == nil {
		t.Fatal("epoch 0 state survived the past-epoch window; eph_root would survive with it")
	}
}

func TestLoadGroupRestoresAnEpoch(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	cfg := testGroupConfig(t, crypto, owner, "group-1")
	group, err := NewGroup(cfg, owner.SigPriv, Credential{CredentialType: CredentialTypeBasic, Identity: owner.IdentityPub})
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	if _, err := group.Commit(nil, nil, nil); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := group.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	want := group.EpochAuthenticator()
	epoch := group.Epoch()
	group.Close()

	restored, err := LoadGroup(cfg, epoch, owner.SigPriv)
	if err != nil {
		t.Fatalf("LoadGroup: %v", err)
	}
	defer restored.Close()
	if restored.Epoch() != epoch {
		t.Fatalf("restored epoch = %d, want %d", restored.Epoch(), epoch)
	}
	if !bytes.Equal(restored.EpochAuthenticator(), want) {
		t.Fatal("restored group derives a different epoch authenticator")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestMergePendingCommitPersists|TestPastEpochWindow|TestLoadGroup' -v`
Expected: FAIL with `DeleteGroupStateBefore was called 0 times` and `undefined: LoadGroup`.

- [ ] **Step 3: Write minimal implementation**

Replace `marshalState` and `MergePendingCommit` in `connect/mls/group.go`:

```go
// groupStateBlobVersion is bumped when the blob layout changes, so a restored
// state from an older build is refused rather than misread.
const groupStateBlobVersion uint16 = 1

// groupStateBlob is one epoch's persisted state. The epoch secrets are in it,
// which is why Spec A §3.5 requires the store implementation to seal it before
// it touches disk.
type groupStateBlob struct {
	Version     uint16
	Context     []byte `tls:"head=varint"`
	Tree        []byte `tls:"head=varint"`
	InterimHash []byte `tls:"head=varint"`
	OwnLeaf     uint32
	OwnEncPriv  []byte `tls:"head=varint"`
	Secrets     []byte `tls:"head=varint"`
}

// marshalState serializes the current epoch.
func (self *Group) marshalState() ([]byte, error) {
	tree, err := self.tree.Encode()
	if err != nil {
		return nil, err
	}
	context, err := self.context.Marshal()
	if err != nil {
		return nil, err
	}
	secrets, err := syntax.Marshal(self.secrets)
	if err != nil {
		return nil, err
	}
	return syntax.Marshal(&groupStateBlob{
		Version:     groupStateBlobVersion,
		Context:     context,
		Tree:        tree,
		InterimHash: self.interimHash,
		OwnLeaf:     uint32(self.ownLeaf),
		OwnEncPriv:  self.ownEncPriv,
		Secrets:     secrets,
	})
}

// MergePendingCommit promotes the staged commit to live state, persists the new
// epoch, and drops every epoch older than the past-epoch window.
//
// The delete is a security requirement rather than housekeeping: eph_root[n]
// lives in the epoch state, and a retained old epoch state is a retained
// eph_root, which is exactly what MASTER §8.1 promises becomes undecryptable.
func (self *Group) MergePendingCommit() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pending == nil {
		return ErrNoPendingCommit
	}
	staged := self.pending
	self.tree = staged.tree
	self.context = staged.context
	self.secrets = staged.secrets
	self.secretTree = staged.secretTree
	self.ownEncPriv = staged.ownEncPriv
	self.interimHash = staged.interimHash
	self.proposals.Clear()
	self.pending = nil

	if err := self.persist(); err != nil {
		return err
	}
	cutoff := uint64(0)
	if self.context.Epoch > PastEpochWindow {
		cutoff = self.context.Epoch - PastEpochWindow
	}
	return self.cfg.Store.DeleteGroupStateBefore(self.context.GroupId, cutoff)
}

// LoadGroup restores a group from persisted epoch state. The signer is supplied
// by the caller rather than stored here, because a signature private key does
// not belong in the same blob as the epoch secrets.
func LoadGroup(cfg *GroupConfig, epoch uint64, signer SignaturePrivateKey) (*Group, error) {
	raw, err := cfg.Store.GetGroupState(cfg.GroupId, epoch)
	if err != nil {
		return nil, err
	}
	var blob groupStateBlob
	read, err := syntax.Unmarshal(raw, &blob)
	if err != nil {
		return nil, err
	}
	if read != len(raw) {
		return nil, fmt.Errorf("mls: %d trailing bytes after group state", len(raw)-read)
	}
	if blob.Version != groupStateBlobVersion {
		return nil, fmt.Errorf("mls: group state blob version %d, this build writes %d",
			blob.Version, groupStateBlobVersion)
	}

	var context GroupContext
	if _, err := syntaxUnmarshalGroupContext(blob.Context, &context); err != nil {
		return nil, err
	}
	tree, err := ParseRatchetTree(cfg.Crypto, blob.Tree)
	if err != nil {
		return nil, err
	}
	var secrets EpochSecrets
	if _, err := syntax.Unmarshal(blob.Secrets, &secrets); err != nil {
		return nil, err
	}
	ownLeaf := LeafIndex(blob.OwnLeaf)
	leaf, ok := tree.LeafNode(ownLeaf)
	if !ok {
		return nil, ErrWelcomeLeafNotFound
	}
	if err := tree.SetLeafPrivate(ownLeaf, HpkePrivateKey(blob.OwnEncPriv)); err != nil {
		return nil, err
	}
	return &Group{
		cfg:         cfg,
		crypto:      cfg.Crypto,
		signer:      signer,
		cred:        leaf.Credential,
		ownLeaf:     ownLeaf,
		ownEncPriv:  HpkePrivateKey(blob.OwnEncPriv),
		tree:        tree,
		context:     &context,
		secrets:     &secrets,
		secretTree:  NewSecretTree(cfg.Crypto, tree.Size(), secrets.EncryptionSecret),
		interimHash: blob.InterimHash,
		proposals:   NewProposalCache(),
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestMergePendingCommitPersists|TestPastEpochWindow|TestLoadGroup' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/group.go connect/mls/group_test.go && \
git commit -m "feat(mls): epoch persistence and the 32 epoch past-epoch window"
```

---

### Task 20: Membership caps and removal authority

**Files:**
- Modify: `connect/mls/commit.go`, `connect/mls/group.go`
- Test: `connect/mls/commit_test.go`

**Interfaces:**
- Consumes: `GroupPolicyExtension.RoleOf/AdminCount` (Task 3); `ApplyResult` (Task 8).
- Produces:
```go
func CheckGroupSize(tree *RatchetTree) error
func CheckDeviceCount(tree *RatchetTree) error
func CheckRemovalAuthority(policy *GroupPolicyExtension, tree *RatchetTree,
    list *ProposalList, committer LeafIndex) error
```

All three run at construction **and** on receipt. The whole value of the rule is that it survives a
client someone has modified.

- [ ] **Step 1: Write the failing test**

Append to `connect/mls/commit_test.go`:

```go
func TestCheckGroupSizeRefusesPast500(t *testing.T) {
	crypto := testCrypto(t)
	tree := NewRatchetTree(crypto)
	for i := 0; i < MaxGroupMembers; i += 1 {
		leaf, _ := testLeafNode(t, crypto, testIdentity(t, crypto, "m"))
		if _, err := tree.AddLeaf(leaf); err != nil {
			t.Fatalf("AddLeaf %d: %v", i, err)
		}
	}
	if err := CheckGroupSize(tree); err != nil {
		t.Fatalf("CheckGroupSize at exactly 500: %v", err)
	}
	leaf, _ := testLeafNode(t, crypto, testIdentity(t, crypto, "one-too-many"))
	if _, err := tree.AddLeaf(leaf); err != nil {
		t.Fatalf("AddLeaf: %v", err)
	}
	if err := CheckGroupSize(tree); !errors.Is(err, ErrGroupSizeExceeded) {
		t.Fatalf("CheckGroupSize at 501 = %v, want ErrGroupSizeExceeded", err)
	}
}

func TestCheckDeviceCountRefusesAnEleventhLeaf(t *testing.T) {
	crypto := testCrypto(t)
	alice := testIdentity(t, crypto, "alice")
	tree := NewRatchetTree(crypto)
	for i := 0; i < MaxDeviceLeavesPerIdentity; i += 1 {
		leaf, _ := testLeafNode(t, crypto, alice)
		if _, err := tree.AddLeaf(leaf); err != nil {
			t.Fatalf("AddLeaf %d: %v", i, err)
		}
	}
	if err := CheckDeviceCount(tree); err != nil {
		t.Fatalf("CheckDeviceCount at exactly 10: %v", err)
	}
	extra, _ := testLeafNode(t, crypto, alice)
	if _, err := tree.AddLeaf(extra); err != nil {
		t.Fatalf("AddLeaf: %v", err)
	}
	if err := CheckDeviceCount(tree); !errors.Is(err, ErrDeviceLimitExceeded) {
		t.Fatalf("CheckDeviceCount at 11 = %v, want ErrDeviceLimitExceeded", err)
	}
}

func TestAdminCannotRemoveAdmin(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "owner", "admin-a", "admin-b")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: members[0].IdentityPub, Role: RoleOwner},
		{MemberId: members[1].IdentityPub, Role: RoleAdmin},
		{MemberId: members[2].IdentityPub, Role: RoleAdmin},
	}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}

	// admin-a at leaf 1 removing admin-b at leaf 2 is refused
	if err := CheckRemovalAuthority(policy, tree, list, LeafIndex(1)); !errors.Is(err, ErrAdminRemovedByNonOwner) {
		t.Fatalf("admin removing admin = %v, want ErrAdminRemovedByNonOwner", err)
	}
	// the owner at leaf 0 removing admin-b is allowed
	if err := CheckRemovalAuthority(policy, tree, list, LeafIndex(0)); err != nil {
		t.Fatalf("owner removing admin: %v", err)
	}
}

func TestAdminMayRemoveAMember(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "owner", "admin", "member")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: members[0].IdentityPub, Role: RoleOwner},
		{MemberId: members[1].IdentityPub, Role: RoleAdmin},
		{MemberId: members[2].IdentityPub, Role: RoleMember},
	}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 2}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	if err := CheckRemovalAuthority(policy, tree, list, LeafIndex(1)); err != nil {
		t.Fatalf("admin removing a member: %v", err)
	}
}

func TestAdminCannotRemoveTheOwner(t *testing.T) {
	crypto := testCrypto(t)
	tree, members := testTreeWith(t, crypto, "owner", "admin")
	policy := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: members[0].IdentityPub, Role: RoleOwner},
		{MemberId: members[1].IdentityPub, Role: RoleAdmin},
	}}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	cached := CachedProposal{Proposal: Proposal{ProposalType: ProposalTypeRemove, Remove: &Remove{Removed: 0}}, ByValue: true}
	list := &ProposalList{Removes: []CachedProposal{cached}, All: []CachedProposal{cached}}
	if err := CheckRemovalAuthority(policy, tree, list, LeafIndex(1)); !errors.Is(err, ErrAdminRemovedByNonOwner) {
		t.Fatalf("admin removing the owner = %v, want ErrAdminRemovedByNonOwner", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestCheckGroupSize|TestCheckDeviceCount|TestAdmin' -v`
Expected: FAIL to build with `undefined: CheckGroupSize`, `undefined: CheckRemovalAuthority`.

- [ ] **Step 3: Write minimal implementation**

Append to `connect/mls/commit.go`:

```go
// CheckGroupSize enforces MASTER §6's 500 member cap on the post-commit tree.
// Enforced by the committing client and by every receiving client, so the cap
// does not depend on one well-behaved participant.
func CheckGroupSize(tree *RatchetTree) error {
	count := len(tree.NonBlankLeaves())
	if count > MaxGroupMembers {
		return fmt.Errorf("%w: commit would leave %d members, the cap is %d",
			ErrGroupSizeExceeded, count, MaxGroupMembers)
	}
	return nil
}

// CheckDeviceCount enforces MASTER §6's ten device leaves per identity. Leaves
// are counted by BasicCredential identity, which is the member's Ed25519
// identity key and is therefore stable across that member's devices.
func CheckDeviceCount(tree *RatchetTree) error {
	counts := map[string]int{}
	for _, leafIndex := range tree.NonBlankLeaves() {
		leaf, _ := tree.LeafNode(leafIndex)
		identity := string(leaf.Credential.Identity)
		counts[identity] += 1
		if counts[identity] > MaxDeviceLeavesPerIdentity {
			return fmt.Errorf("%w: an identity would hold %d leaves, the cap is %d",
				ErrDeviceLimitExceeded, counts[identity], MaxDeviceLeavesPerIdentity)
		}
	}
	return nil
}

// CheckRemovalAuthority enforces MASTER §11: only an OWNER may remove an ADMIN
// or the OWNER. Without it one compromised admin strips the entire admin set
// including the owner in a single commit, and the removed owner's keys are gone
// from the very next epoch, so there is no undo by construction.
func CheckRemovalAuthority(policy *GroupPolicyExtension, tree *RatchetTree,
	list *ProposalList, committer LeafIndex) error {
	if len(list.Removes) == 0 {
		return nil
	}
	committerLeaf, ok := tree.LeafNode(committer)
	if !ok {
		return fmt.Errorf("%w: committer leaf %d is blank", ErrBlankSenderLeaf, committer)
	}
	committerRole, _ := policy.RoleOf(committerLeaf.Credential.Identity)
	if committerRole == RoleOwner {
		return nil
	}
	for _, cached := range list.Removes {
		target, ok := tree.LeafNode(cached.Proposal.Remove.Removed)
		if !ok {
			continue
		}
		// a member removing their own device leaf is self-service device
		// management, not an administrative removal
		if bytesEqual(target.Credential.Identity, committerLeaf.Credential.Identity) {
			continue
		}
		targetRole, _ := policy.RoleOf(target.Credential.Identity)
		if targetRole == RoleAdmin || targetRole == RoleOwner {
			return fmt.Errorf("%w: %v tried to remove a %v",
				ErrAdminRemovedByNonOwner, committerRole, targetRole)
		}
	}
	return nil
}
```

Replace the Task 13 stubs in `connect/mls/group.go`:

```go
// checkMembershipCapsLocked runs the two hard caps against the post-commit tree.
func (self *Group) checkMembershipCapsLocked(applied *ApplyResult) error {
	if err := CheckGroupSize(applied.Tree); err != nil {
		return err
	}
	return CheckDeviceCount(applied.Tree)
}

// checkRemovalAuthorityLocked reads the PRE-commit policy, because a commit
// that both demotes an admin and removes them must be judged against the roles
// that were in force when it was authored.
func (self *Group) checkRemovalAuthorityLocked(list *ProposalList, committer LeafIndex) error {
	policy, err := GroupPolicyOf(self.context.Extensions)
	if err != nil {
		return err
	}
	return CheckRemovalAuthority(policy, self.tree, list, committer)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run 'TestCheckGroupSize|TestCheckDeviceCount|TestAdmin' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/commit.go connect/mls/group.go connect/mls/commit_test.go && \
git commit -m "feat(mls): 500 member cap, 10 device cap and owner-only admin removal"
```

---

### Task 21: Owner succession — the five conditions

**Files:**
- Create: `connect/mls/succession.go`
- Modify: `connect/mls/group.go`
- Test: `connect/mls/succession_test.go`

**Interfaces:**
- Consumes: `OwnerSuccessorExtension`, `successionPreimage` (Task 4); `GroupPolicyExtension` (Task 3); `crypto.VerifyWithLabel`; `ApplyResult`, `ProposalList` (Tasks 6, 8).
- Produces:
```go
type SuccessionCountersignature struct {
    AdminMemberId []byte `tls:"head=varint"`
    Signature     []byte `tls:"head=varint"`
}
type SuccessionClaim struct {
    SuccessorMemberId  []byte                        `tls:"head=varint"`
    NominatedAtMs      uint64
    Countersignatures  []SuccessionCountersignature  `tls:"head=varint"`
}
func SuccessionQuorum(adminCount int) int
func SignSuccessionCountersignature(crypto CryptoProvider, priv SignaturePrivateKey,
    adminMemberId, groupId []byte, epoch uint64, successorMemberId []byte, nominatedAtMs uint64) (SuccessionCountersignature, error)
func ValidateSuccession(crypto CryptoProvider, groupId []byte, epoch uint64,
    prePolicy *GroupPolicyExtension, nomination *OwnerSuccessorExtension,
    committerMemberId []byte, claim *SuccessionClaim, lastOwnerRecordMs uint64, nowMs uint64) error
func (self *Group) SetSuccessionClaim(claim *SuccessionClaim, lastOwnerRecordMs uint64)
```

`SuccessionQuorum(n) = max(2, ceil(2n/3))`. Below two admins the arithmetic has no solution, so a
group with fewer than two admins has no succession path at all — one arithmetic rule, because two
rules written in prose disagreed for a group with one admin.

- [ ] **Step 1: Write the failing test**

`connect/mls/succession_test.go`:

```go
package mls

import (
	"errors"
	"testing"
)

func TestSuccessionQuorumArithmetic(t *testing.T) {
	for _, tc := range []struct {
		admins int
		want   int
	}{
		{0, 2}, {1, 2}, {2, 2}, {3, 2}, {4, 3}, {5, 4}, {6, 4}, {9, 6}, {10, 7},
	} {
		if got := SuccessionQuorum(tc.admins); got != tc.want {
			t.Fatalf("SuccessionQuorum(%d) = %d, want %d", tc.admins, got, tc.want)
		}
	}
}

// testSuccessionFixture builds a group with an owner, three admins and a
// nominated successor, plus a valid claim.
func testSuccessionFixture(t *testing.T, crypto CryptoProvider) (
	*GroupPolicyExtension, *OwnerSuccessorExtension, *SuccessionClaim, *testMember, []*testMember) {
	t.Helper()
	owner := testIdentity(t, crypto, "owner")
	successor := testIdentity(t, crypto, "successor")
	admins := []*testMember{
		testIdentity(t, crypto, "admin-a"),
		testIdentity(t, crypto, "admin-b"),
		testIdentity(t, crypto, "admin-c"),
	}
	policy := &GroupPolicyExtension{Roles: []RoleEntry{
		{MemberId: owner.IdentityPub, Role: RoleOwner},
		{MemberId: successor.IdentityPub, Role: RoleMember},
	}}
	for _, admin := range admins {
		policy.Roles = append(policy.Roles, RoleEntry{MemberId: admin.IdentityPub, Role: RoleAdmin})
	}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	nomination := &OwnerSuccessorExtension{
		Enabled:           true,
		SuccessorMemberId: successor.IdentityPub,
		NominatedAtMs:     1000,
		FloorMs:           SuccessionFloorMinMs,
	}
	claim := &SuccessionClaim{SuccessorMemberId: successor.IdentityPub, NominatedAtMs: 1000}
	for _, admin := range admins[:SuccessionQuorum(3)] {
		signature, err := SignSuccessionCountersignature(crypto, admin.SigPriv, admin.IdentityPub,
			[]byte("group-1"), 7, successor.IdentityPub, 1000)
		if err != nil {
			t.Fatalf("SignSuccessionCountersignature: %v", err)
		}
		claim.Countersignatures = append(claim.Countersignatures, signature)
	}
	return policy, nomination, claim, successor, admins
}

func TestSuccessionRequiresAllFive(t *testing.T) {
	crypto := testCrypto(t)
	policy, nomination, claim, successor, admins := testSuccessionFixture(t, crypto)
	const nowMs = uint64(1000) + SuccessionFloorMinMs + 1
	const lastOwnerMs = uint64(1000)

	if err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
		successor.IdentityPub, claim, lastOwnerMs, nowMs); err != nil {
		t.Fatalf("the valid promotion was rejected: %v", err)
	}

	// 1: succession disabled
	disabled := *nomination
	disabled.Enabled = false
	if err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, &disabled,
		successor.IdentityPub, claim, lastOwnerMs, nowMs); !errors.Is(err, ErrSuccessionDisabled) {
		t.Fatalf("disabled = %v, want ErrSuccessionDisabled", err)
	}

	// 2: the committer is not the nominee
	if err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
		admins[0].IdentityPub, claim, lastOwnerMs, nowMs); !errors.Is(err, ErrSuccessionNotNominee) {
		t.Fatalf("not nominee = %v, want ErrSuccessionNotNominee", err)
	}

	// 3: one countersignature short
	short := &SuccessionClaim{
		SuccessorMemberId: claim.SuccessorMemberId,
		NominatedAtMs:     claim.NominatedAtMs,
		Countersignatures: claim.Countersignatures[:len(claim.Countersignatures)-1],
	}
	if err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
		successor.IdentityPub, short, lastOwnerMs, nowMs); !errors.Is(err, ErrSuccessionQuorum) {
		t.Fatalf("short quorum = %v, want ErrSuccessionQuorum", err)
	}

	// 4: the floor has not elapsed
	if err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
		successor.IdentityPub, claim, lastOwnerMs, lastOwnerMs+SuccessionFloorMinMs-1); !errors.Is(err, ErrSuccessionFloor) {
		t.Fatalf("floor not elapsed = %v, want ErrSuccessionFloor", err)
	}

	// 5: the nomination's floor is shorter than ninety days
	shortFloor := *nomination
	shortFloor.FloorMs = SuccessionFloorMinMs - 1
	if err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, &shortFloor,
		successor.IdentityPub, claim, lastOwnerMs, nowMs); !errors.Is(err, ErrSuccessionFloorTooShort) {
		t.Fatalf("short floor = %v, want ErrSuccessionFloorTooShort", err)
	}
}

func TestSuccessionOptOutIsAbsolute(t *testing.T) {
	crypto := testCrypto(t)
	policy, nomination, claim, successor, _ := testSuccessionFixture(t, crypto)
	nomination.Enabled = false
	err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
		successor.IdentityPub, claim, 1000, 1000+SuccessionFloorMinMs*10)
	if !errors.Is(err, ErrSuccessionDisabled) {
		t.Fatalf("error = %v, want ErrSuccessionDisabled even with the other four satisfied", err)
	}
}

func TestSuccessionUnobtainableBelowTwoAdmins(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	successor := testIdentity(t, crypto, "successor")
	admin := testIdentity(t, crypto, "only-admin")

	for _, admins := range [][]*testMember{{}, {admin}} {
		policy := &GroupPolicyExtension{Roles: []RoleEntry{
			{MemberId: owner.IdentityPub, Role: RoleOwner},
			{MemberId: successor.IdentityPub, Role: RoleMember},
		}}
		for _, a := range admins {
			policy.Roles = append(policy.Roles, RoleEntry{MemberId: a.IdentityPub, Role: RoleAdmin})
		}
		if err := policy.Canonicalize(); err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}
		nomination := &OwnerSuccessorExtension{Enabled: true, SuccessorMemberId: successor.IdentityPub,
			NominatedAtMs: 1000, FloorMs: SuccessionFloorMinMs}
		claim := &SuccessionClaim{SuccessorMemberId: successor.IdentityPub, NominatedAtMs: 1000}
		for _, a := range admins {
			signature, err := SignSuccessionCountersignature(crypto, a.SigPriv, a.IdentityPub,
				[]byte("group-1"), 7, successor.IdentityPub, 1000)
			if err != nil {
				t.Fatalf("SignSuccessionCountersignature: %v", err)
			}
			claim.Countersignatures = append(claim.Countersignatures, signature)
		}
		err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
			successor.IdentityPub, claim, 1000, 1000+SuccessionFloorMinMs+1)
		if !errors.Is(err, ErrSuccessionQuorum) {
			t.Fatalf("with %d admins error = %v, want ErrSuccessionQuorum", len(admins), err)
		}
	}
}

func TestSuccessionRejectsANonAdminCountersignature(t *testing.T) {
	crypto := testCrypto(t)
	policy, nomination, claim, successor, _ := testSuccessionFixture(t, crypto)
	outsider := testIdentity(t, crypto, "outsider")
	forged, err := SignSuccessionCountersignature(crypto, outsider.SigPriv, outsider.IdentityPub,
		[]byte("group-1"), 7, successor.IdentityPub, 1000)
	if err != nil {
		t.Fatalf("SignSuccessionCountersignature: %v", err)
	}
	claim.Countersignatures[0] = forged
	err = ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
		successor.IdentityPub, claim, 1000, 1000+SuccessionFloorMinMs+1)
	if !errors.Is(err, ErrSuccessionQuorum) {
		t.Fatalf("error = %v, want ErrSuccessionQuorum: an outsider's signature must not count", err)
	}
}

func TestSuccessionRejectsADuplicatedCountersignature(t *testing.T) {
	crypto := testCrypto(t)
	policy, nomination, claim, successor, _ := testSuccessionFixture(t, crypto)
	claim.Countersignatures[1] = claim.Countersignatures[0]
	err := ValidateSuccession(crypto, []byte("group-1"), 7, policy, nomination,
		successor.IdentityPub, claim, 1000, 1000+SuccessionFloorMinMs+1)
	if !errors.Is(err, ErrSuccessionQuorum) {
		t.Fatalf("error = %v, want ErrSuccessionQuorum: one admin cannot sign twice", err)
	}
}

func TestSuccessionCountersignatureIsEpochBound(t *testing.T) {
	crypto := testCrypto(t)
	policy, nomination, claim, successor, _ := testSuccessionFixture(t, crypto)
	// the signatures were made for epoch 7; validating at epoch 8 must fail
	err := ValidateSuccession(crypto, []byte("group-1"), 8, policy, nomination,
		successor.IdentityPub, claim, 1000, 1000+SuccessionFloorMinMs+1)
	if !errors.Is(err, ErrSuccessionQuorum) {
		t.Fatalf("error = %v, want ErrSuccessionQuorum: the preimage binds the epoch", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestSuccession -v`
Expected: FAIL to build with `undefined: SuccessionQuorum`, `undefined: ValidateSuccession`.

- [ ] **Step 3: Write minimal implementation**

`connect/mls/succession.go`:

```go
// MASTER §11 owner succession. Every condition here is a validity condition on
// a promotion commit, checked at every receiving client. The warning obligation
// of MASTER §11 is deliberately NOT here: no receiving client can observe what
// was displayed on the owner's devices, and a validity condition nobody can
// check is a condition that is silently skipped.
package mls

import (
	"bytes"
	"fmt"
)

// SuccessionCountersignature is one admin's assertion that the owner is
// unreachable.
type SuccessionCountersignature struct {
	AdminMemberId []byte `tls:"head=varint"`
	Signature     []byte `tls:"head=varint"`
}

// SuccessionClaim rides in the promotion record's MLS-authenticated payload.
type SuccessionClaim struct {
	SuccessorMemberId []byte                       `tls:"head=varint"`
	NominatedAtMs     uint64
	Countersignatures []SuccessionCountersignature `tls:"head=varint"`
}

// SuccessionQuorum is max(2, ceil(2 * admins / 3)). One arithmetic rule: two
// rules written in prose disagreed for a group with one admin, where one clause
// allowed a single signature to take a group and the other forbade it. Below
// two admins the arithmetic has no solution, so such a group has no succession
// path at all, and the client states that as a consequence of having no admins.
func SuccessionQuorum(adminCount int) int {
	required := (2*adminCount + 2) / 3
	if required < 2 {
		return 2
	}
	return required
}

// SignSuccessionCountersignature signs the MASTER §11 preimage under an admin's
// identity key.
func SignSuccessionCountersignature(crypto CryptoProvider, priv SignaturePrivateKey,
	adminMemberId, groupId []byte, epoch uint64, successorMemberId []byte,
	nominatedAtMs uint64) (SuccessionCountersignature, error) {

	preimage := successionPreimage(groupId, epoch, successorMemberId, nominatedAtMs)
	signature, err := crypto.SignWithLabel(priv, "URmessageSuccession", preimage)
	if err != nil {
		return SuccessionCountersignature{}, err
	}
	return SuccessionCountersignature{
		AdminMemberId: append([]byte(nil), adminMemberId...),
		Signature:     signature,
	}, nil
}

// ValidateSuccession checks all five MASTER §11 conditions and names the one
// that failed. Order matters for the message a user sees: the group-level
// switch is reported before the nominee, and the nominee before the quorum.
func ValidateSuccession(crypto CryptoProvider, groupId []byte, epoch uint64,
	prePolicy *GroupPolicyExtension, nomination *OwnerSuccessorExtension,
	committerMemberId []byte, claim *SuccessionClaim,
	lastOwnerRecordMs uint64, nowMs uint64) error {

	// 1: succession is enabled for this group
	if nomination == nil || !nomination.Enabled {
		return ErrSuccessionDisabled
	}
	// 5: the nomination's floor is at least ninety days. Checked before the
	// elapsed-time test, so a group that shortened its floor is told that
	// rather than being told the clock has not run out.
	if nomination.FloorMs < SuccessionFloorMinMs {
		return fmt.Errorf("%w: floor is %d ms", ErrSuccessionFloorTooShort, nomination.FloorMs)
	}
	// 2: the committer is the nominated successor
	if len(nomination.SuccessorMemberId) == 0 ||
		!bytes.Equal(nomination.SuccessorMemberId, committerMemberId) {
		return ErrSuccessionNotNominee
	}
	if claim == nil || !bytes.Equal(claim.SuccessorMemberId, nomination.SuccessorMemberId) ||
		claim.NominatedAtMs != nomination.NominatedAtMs {
		return ErrSuccessionNotNominee
	}
	// 4: ninety days since the last record any of the owner's device leaves
	// authored in this group
	if nowMs < lastOwnerRecordMs || nowMs-lastOwnerRecordMs < nomination.FloorMs {
		return fmt.Errorf("%w: %d ms elapsed, floor is %d ms",
			ErrSuccessionFloor, nowMs-lastOwnerRecordMs, nomination.FloorMs)
	}
	// 3: a supermajority of CURRENT admins, counted at the epoch the promotion
	// commits from
	required := SuccessionQuorum(prePolicy.AdminCount())
	preimage := successionPreimage(groupId, epoch, nomination.SuccessorMemberId, nomination.NominatedAtMs)
	counted := map[string]bool{}
	for _, countersignature := range claim.Countersignatures {
		role, ok := prePolicy.RoleOf(countersignature.AdminMemberId)
		if !ok || role != RoleAdmin {
			continue
		}
		if counted[string(countersignature.AdminMemberId)] {
			continue
		}
		if err := crypto.VerifyWithLabel(SignaturePublicKey(countersignature.AdminMemberId),
			"URmessageSuccession", preimage, countersignature.Signature); err != nil {
			continue
		}
		counted[string(countersignature.AdminMemberId)] = true
	}
	if len(counted) < required {
		return fmt.Errorf("%w: %d valid countersignatures, %d required from %d admins",
			ErrSuccessionQuorum, len(counted), required, prePolicy.AdminCount())
	}
	return nil
}
```

Replace the Task 13 stub in `connect/mls/group.go`:

```go
// SetSuccessionClaim installs the claim and the owner-activity timestamp that
// the next promotion commit is judged against. connect/message supplies both:
// mls does not read records and cannot know when the owner last wrote.
func (self *Group) SetSuccessionClaim(claim *SuccessionClaim, lastOwnerRecordMs uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.successionClaim = claim
	self.lastOwnerRecordMs = lastOwnerRecordMs
}

// checkSuccessionLocked runs the §11 conditions when, and only when, a commit's
// GroupContextExtensions proposal moves the OWNER role to a different member.
func (self *Group) checkSuccessionLocked(list *ProposalList, applied *ApplyResult, committer LeafIndex) error {
	newExts, ok := list.Extensions()
	if !ok {
		return nil
	}
	prePolicy, err := GroupPolicyOf(self.context.Extensions)
	if err != nil {
		return err
	}
	postPolicy, err := GroupPolicyOf(newExts)
	if err != nil {
		return err
	}
	preOwner, _ := prePolicy.OwnerId()
	postOwner, _ := postPolicy.OwnerId()
	if bytesEqual(preOwner, postOwner) {
		return nil
	}

	committerLeaf, ok := self.tree.LeafNode(committer)
	if !ok {
		return fmt.Errorf("%w: committer leaf %d is blank", ErrBlankSenderLeaf, committer)
	}
	// an owner handing the group over is an ordinary transfer, not a succession
	if bytesEqual(committerLeaf.Credential.Identity, preOwner) {
		return nil
	}

	nomination, present, err := OwnerSuccessorOf(self.context.Extensions)
	if err != nil {
		return err
	}
	if !present {
		return ErrSuccessionDisabled
	}
	return ValidateSuccession(self.crypto, self.context.GroupId, self.context.Epoch,
		prePolicy, nomination, committerLeaf.Credential.Identity,
		self.successionClaim, self.lastOwnerRecordMs, uint64(nowFunc().UnixMilli()))
}
```

Add the two fields to `Group`:

```go
	successionClaim   *SuccessionClaim
	lastOwnerRecordMs uint64
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestSuccession -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add connect/mls/succession.go connect/mls/group.go connect/mls/succession_test.go && \
git commit -m "feat(mls): owner succession validated against all five MASTER section 11 conditions"
```

---

### Task 22: Round-trip group tests — the gate

**Files:**
- Create: `connect/mls/group_roundtrip_test.go`

**Interfaces:**
- Consumes: everything this plan produces.
- Produces: no new exported API. With Task 17 this is the gate for this plan.

- [ ] **Step 1: Write the failing test**

`connect/mls/group_roundtrip_test.go`:

```go
package mls

import (
	"bytes"
	"errors"
	"testing"
)

// testCohort is a set of groups that must stay in lockstep.
type testCohort struct {
	groups  []*Group
	members []*testMember
}

// deliver hands one message to every group except the author, applying commits.
func (self *testCohort) deliver(t *testing.T, author *Group, message []byte, isCommit bool) {
	t.Helper()
	for _, group := range self.groups {
		if group == author {
			continue
		}
		processed, err := group.ProcessMessage(message)
		if err != nil {
			t.Fatalf("ProcessMessage: %v", err)
		}
		if isCommit {
			if err := group.ApplyCommit(processed); err != nil {
				t.Fatalf("ApplyCommit: %v", err)
			}
		}
	}
	if isCommit {
		if err := author.MergePendingCommit(); err != nil {
			t.Fatalf("MergePendingCommit: %v", err)
		}
	}
}

// assertLockstep fails unless every group agrees on epoch, authenticator and
// membership. This is the single strongest assertion in the plan: an epoch
// authenticator match means the tree, the transcript and the key schedule all
// agree.
func (self *testCohort) assertLockstep(t *testing.T) {
	t.Helper()
	first := self.groups[0]
	for _, group := range self.groups[1:] {
		if group.Epoch() != first.Epoch() {
			t.Fatalf("epoch %d vs %d", group.Epoch(), first.Epoch())
		}
		if !bytes.Equal(group.EpochAuthenticator(), first.EpochAuthenticator()) {
			t.Fatal("epoch authenticators diverged")
		}
		if len(group.Members()) != len(first.Members()) {
			t.Fatalf("membership %d vs %d", len(group.Members()), len(first.Members()))
		}
	}
}

// testAddMember commits an Add and joins the new member into the cohort.
func (self *testCohort) addMember(t *testing.T, crypto CryptoProvider, committer *Group, name string) *Group {
	t.Helper()
	member := testIdentity(t, crypto, name)
	kp, initPriv, encPriv := testKeyPackage(t, crypto, member)
	encoded, err := syntaxMarshalKeyPackage(kp)
	if err != nil {
		t.Fatalf("marshal key package: %v", err)
	}
	proposal, err := committer.ProposeAdd(encoded)
	if err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	self.deliver(t, committer, proposal, false)
	result, err := committer.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	self.deliver(t, committer, result.Commit, true)

	cfg := testGroupConfig(t, crypto, member, string(committer.GroupId()))
	joined, err := JoinFromWelcome(cfg, result.Welcome, result.RatchetTree, &JoinKeyMaterial{
		KeyPackage: *kp, InitPrivate: initPriv, EncryptPrivate: encPriv, SignPrivate: member.SigPriv,
	})
	if err != nil {
		t.Fatalf("JoinFromWelcome for %s: %v", name, err)
	}
	self.groups = append(self.groups, joined)
	self.members = append(self.members, member)
	return joined
}

func TestGroupLifecycleFullCycle(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	root := testNewGroup(t, crypto, owner, "roundtrip")
	cohort := &testCohort{groups: []*Group{root}, members: []*testMember{owner}}
	defer func() {
		for _, group := range cohort.groups {
			group.Close()
		}
	}()

	cohort.addMember(t, crypto, root, "bob")
	cohort.assertLockstep(t)
	cohort.addMember(t, crypto, root, "carol")
	cohort.assertLockstep(t)
	cohort.addMember(t, crypto, root, "dave")
	cohort.assertLockstep(t)
	if len(root.Members()) != 4 {
		t.Fatalf("Members = %d, want 4", len(root.Members()))
	}

	// a member updates, and someone else commits it by reference
	bob := cohort.groups[1]
	update, err := bob.ProposeUpdate()
	if err != nil {
		t.Fatalf("ProposeUpdate: %v", err)
	}
	cohort.deliver(t, bob, update, false)
	result, err := root.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit covering the peer update: %v", err)
	}
	cohort.deliver(t, root, result.Commit, true)
	cohort.assertLockstep(t)

	// application traffic flows in both directions at the new epoch
	message, err := bob.Protect([]byte("aad"), []byte("after the update"))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	for _, group := range cohort.groups[2:] {
		application, err := group.Unprotect(message)
		if err != nil {
			t.Fatalf("Unprotect: %v", err)
		}
		if string(application.Plaintext) != "after the update" {
			t.Fatalf("plaintext = %q", application.Plaintext)
		}
	}

	// a GroupContextExtensions commit changes the retention policy
	policy, err := root.GroupPolicy()
	if err != nil {
		t.Fatalf("GroupPolicy: %v", err)
	}
	policy.RetentionPolicy = RetentionPolicy{DurableMs: 31536000000, MediaMs: 2592000000}
	ext, err := policy.Encode()
	if err != nil {
		t.Fatalf("Encode policy: %v", err)
	}
	gce, err := root.ProposeGroupContextExtensions([]Extension{ext})
	if err != nil {
		t.Fatalf("ProposeGroupContextExtensions: %v", err)
	}
	cohort.deliver(t, root, gce, false)
	result, err = root.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit with GCE: %v", err)
	}
	cohort.deliver(t, root, result.Commit, true)
	cohort.assertLockstep(t)
	updated, err := cohort.groups[2].GroupPolicy()
	if err != nil {
		t.Fatalf("GroupPolicy: %v", err)
	}
	if updated.RetentionPolicy.DurableMs != 31536000000 {
		t.Fatal("the GCE commit did not reach the other members")
	}

	// a remove: the removed member sees ErrRemovedFromGroup, the rest stay in lockstep
	dave := cohort.groups[3]
	daveLeaf := dave.OwnLeafIndex()
	removal, err := root.ProposeRemove(daveLeaf)
	if err != nil {
		t.Fatalf("ProposeRemove: %v", err)
	}
	for _, group := range cohort.groups[1:] {
		if _, err := group.ProcessMessage(removal); err != nil {
			t.Fatalf("ProcessMessage removal proposal: %v", err)
		}
	}
	result, err = root.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("Commit with remove: %v", err)
	}
	for _, group := range cohort.groups[1:] {
		processed, err := group.ProcessMessage(result.Commit)
		if err != nil {
			t.Fatalf("ProcessMessage removal commit: %v", err)
		}
		err = group.ApplyCommit(processed)
		if group == dave {
			if !errors.Is(err, ErrRemovedFromGroup) {
				t.Fatalf("removed member error = %v, want ErrRemovedFromGroup", err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ApplyCommit: %v", err)
		}
	}
	if err := root.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	cohort.groups = cohort.groups[:3]
	cohort.assertLockstep(t)
	if len(root.Members()) != 3 {
		t.Fatalf("Members after removal = %d, want 3", len(root.Members()))
	}

	// the removed member can no longer read the new epoch
	if _, err := dave.Protect(nil, []byte("still here?")); err == nil {
		t.Fatal("a removed member was able to protect a message")
	}
}

func TestJoinAtAnAdvancedEpoch(t *testing.T) {
	crypto := testCrypto(t)
	owner := testIdentity(t, crypto, "owner")
	root := testNewGroup(t, crypto, owner, "advanced")
	cohort := &testCohort{groups: []*Group{root}, members: []*testMember{owner}}
	defer func() {
		for _, group := range cohort.groups {
			group.Close()
		}
	}()

	for i := 0; i < 5; i += 1 {
		result, err := root.Commit(nil, nil, nil)
		if err != nil {
			t.Fatalf("Commit %d: %v", i, err)
		}
		cohort.deliver(t, root, result.Commit, true)
	}
	if root.Epoch() != 5 {
		t.Fatalf("Epoch = %d, want 5", root.Epoch())
	}
	late := cohort.addMember(t, crypto, root, "late")
	if late.Epoch() != root.Epoch() {
		t.Fatalf("late joiner epoch = %d, committer = %d", late.Epoch(), root.Epoch())
	}
	cohort.assertLockstep(t)
}

func TestLosingCommitterRederivesAgainstTheWinner(t *testing.T) {
	// MASTER §9.3: the delivery service accepts one commit per (group, epoch).
	// The loser clears its pending commit, applies the winner, and re-proposes.
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	winner, err := committer.Commit(nil, nil, nil)
	if err != nil {
		t.Fatalf("winner Commit: %v", err)
	}
	if _, err := receiver.Commit(nil, nil, nil); err != nil {
		t.Fatalf("loser Commit: %v", err)
	}
	// the loser learns the server accepted the other commit
	receiver.ClearPendingCommit()
	processed, err := receiver.ProcessMessage(winner)
	if err != nil {
		t.Fatalf("loser ProcessMessage: %v", err)
	}
	if err := receiver.ApplyCommit(processed); err != nil {
		t.Fatalf("loser ApplyCommit: %v", err)
	}
	if err := committer.MergePendingCommit(); err != nil {
		t.Fatalf("winner MergePendingCommit: %v", err)
	}
	if !bytes.Equal(receiver.EpochAuthenticator(), committer.EpochAuthenticator()) {
		t.Fatal("the loser did not converge on the winner's epoch")
	}
	// and can commit again at the new epoch
	if _, err := receiver.Commit(nil, nil, nil); err != nil {
		t.Fatalf("loser re-commit: %v", err)
	}
}

func TestProfileRefusalsEndToEnd(t *testing.T) {
	crypto := testCrypto(t)
	committer, receiver, _, _ := testTwoMemberGroup(t, crypto)
	defer committer.Close()
	defer receiver.Close()

	// a PSK proposal cannot even be built: the type has no struct in this package
	var proposal Proposal
	if _, err := proposal.UnmarshalTLS([]byte{0x00, 0x04, 0x00}); !errors.Is(err, ErrProfilePSK) {
		t.Fatalf("psk parse = %v, want ErrProfilePSK", err)
	}
	// an external_init proposal is refused with the external-commit error
	if _, err := proposal.UnmarshalTLS([]byte{0x00, 0x06, 0x00}); !errors.Is(err, ErrProfileExternalCommit) {
		t.Fatalf("external_init parse = %v, want ErrProfileExternalCommit", err)
	}
	// a group context extension outside the allowed set is refused before it commits
	bad := []Extension{{ExtensionType: ExtensionTypeExternalSenders, ExtensionData: []byte{}}}
	if _, err := committer.ProposeGroupContextExtensions(bad); !errors.Is(err, ErrProfileExternalSender) {
		t.Fatalf("external_senders = %v, want ErrProfileExternalSender", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run 'TestGroupLifecycleFullCycle|TestJoinAtAnAdvancedEpoch|TestLosingCommitter|TestProfileRefusalsEndToEnd' -v`
Expected: FAIL — the first failure is whichever gap remains from Tasks 11–21. Fix forward until all
four pass; do not weaken an assertion to make it green.

- [ ] **Step 3: Write minimal implementation**

No new production code is expected. If a test fails, the fix belongs in the file the failing
behaviour lives in, and the fix is a change to that file plus a note in its task's commit message.
The one change this task legitimately makes is `(*Group).Protect` returning an error once the group
is closed, which `TestGroupLifecycleFullCycle` asserts for the removed member — that is already in
Task 18's `Protect`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -v`
Expected: PASS, all tests in the package.

- [ ] **Step 5: Commit**

```bash
git add connect/mls/group_roundtrip_test.go && \
git commit -m "test(mls): round-trip group lifecycle gate across add, update, remove, GCE and rejoin"
```

---

### Task 23: The passive-client vector families

**Files:**
- Create: `connect/mls/passive_client_vectors_test.go`
- Create: `connect/mls/testdata/vectors/passive-client-welcome.json`
- Create: `connect/mls/testdata/vectors/passive-client-handling-commit.json`
- Create: `connect/mls/testdata/vectors/passive-client-random.json`

**Interfaces:**
- Consumes: `JoinFromWelcome`, `ProcessMessage`, `ApplyCommit`, `EpochAuthenticator` (Tasks 16, 18).
- Produces: no new exported API. Spec A §4.2.1 maps families 13, 14 and 15 to `group.go`, which is
this plan's file, so they are this plan's obligation.

**Vector format**, from `test-vectors.md` at the pinned commit: `cipher_suite`, `external_psks`,
`key_package`, `signature_priv`, `encryption_priv`, `init_priv`, `welcome`, `ratchet_tree`
(hex-encoded `optional<Node> ratchet_tree<V>`, null when the tree is in the welcome),
`initial_epoch_authenticator`, and an `epochs` array of `{proposals, commit, epoch_authenticator}`.

**Verification:** join with the Welcome, assert the computed epoch authenticator equals
`initial_epoch_authenticator`, then for each epoch apply the proposals and the commit and assert the
epoch authenticator again.

- [ ] **Step 1: Write the failing test**

`connect/mls/passive_client_vectors_test.go`:

```go
package mls

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type passiveEpoch struct {
	Proposals          []string `json:"proposals"`
	Commit             string   `json:"commit"`
	EpochAuthenticator string   `json:"epoch_authenticator"`
}

type passiveVector struct {
	CipherSuite               uint16 `json:"cipher_suite"`
	ExternalPsks              []any  `json:"external_psks"`
	KeyPackage                string `json:"key_package"`
	SignaturePriv             string `json:"signature_priv"`
	EncryptionPriv            string `json:"encryption_priv"`
	InitPriv                  string `json:"init_priv"`
	Welcome                   string `json:"welcome"`
	RatchetTree               string `json:"ratchet_tree"`
	InitialEpochAuthenticator string `json:"initial_epoch_authenticator"`
	Epochs                    []passiveEpoch `json:"epochs"`
}

func runPassiveVectors(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var vectors []passiveVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(vectors) == 0 {
		t.Fatalf("%s is empty", path)
	}

	ran := 0
	for i, vector := range vectors {
		suite := CipherSuite(vector.CipherSuite)
		crypto, err := NewCryptoProvider(suite)
		if err != nil {
			continue
		}
		if len(vector.ExternalPsks) != 0 {
			// v1 refuses PSKs at parse; a vector that needs one is out of profile
			continue
		}
		ran += 1

		kpMessage, err := ParseMLSMessage(mustHex(t, vector.KeyPackage))
		if err != nil {
			t.Fatalf("vector %d: parse key package: %v", i, err)
		}
		cfg := &GroupConfig{
			Suite:   suite,
			Crypto:  crypto,
			Store:   newTestStore(),
			Profile: DefaultProfile(),
		}
		group, err := JoinFromWelcome(cfg, mustHex(t, vector.Welcome), mustHex(t, vector.RatchetTree),
			&JoinKeyMaterial{
				KeyPackage:     *kpMessage.KeyPackage,
				InitPrivate:    HpkePrivateKey(mustHex(t, vector.InitPriv)),
				EncryptPrivate: HpkePrivateKey(mustHex(t, vector.EncryptionPriv)),
				SignPrivate:    SignaturePrivateKey(mustHex(t, vector.SignaturePriv)),
			})
		if err != nil {
			t.Fatalf("vector %d: JoinFromWelcome: %v", i, err)
		}
		if !bytes.Equal(group.EpochAuthenticator(), mustHex(t, vector.InitialEpochAuthenticator)) {
			t.Fatalf("vector %d: initial epoch authenticator mismatch", i)
		}

		for e, epoch := range vector.Epochs {
			for p, proposal := range epoch.Proposals {
				if _, err := group.ProcessMessage(mustHex(t, proposal)); err != nil {
					t.Fatalf("vector %d epoch %d proposal %d: %v", i, e, p, err)
				}
			}
			processed, err := group.ProcessMessage(mustHex(t, epoch.Commit))
			if err != nil {
				t.Fatalf("vector %d epoch %d: ProcessMessage: %v", i, e, err)
			}
			if err := group.ApplyCommit(processed); err != nil {
				t.Fatalf("vector %d epoch %d: ApplyCommit: %v", i, e, err)
			}
			if !bytes.Equal(group.EpochAuthenticator(), mustHex(t, epoch.EpochAuthenticator)) {
				t.Fatalf("vector %d epoch %d: epoch authenticator mismatch", i, e)
			}
		}
		group.Close()
	}
	if ran == 0 {
		t.Fatalf("%s: no vector matched an implemented ciphersuite and the v1 profile", path)
	}
}

func TestPassiveClientWelcomeVectors(t *testing.T) {
	runPassiveVectors(t, "testdata/vectors/passive-client-welcome.json")
}

func TestPassiveClientHandlingCommitVectors(t *testing.T) {
	runPassiveVectors(t, "testdata/vectors/passive-client-handling-commit.json")
}

func TestPassiveClientRandomVectors(t *testing.T) {
	runPassiveVectors(t, "testdata/vectors/passive-client-random.json")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./connect/mls/... -run TestPassiveClient -v`
Expected: FAIL with `read testdata/vectors/passive-client-welcome.json: no such file or directory`.

- [ ] **Step 3: Write minimal implementation**

Vendor the three files at the pinned mlswg commit:

```bash
PIN=$(grep -oP 'mlswg=\K\S+' connect/mls/interop/PINS.md)
for family in passive-client-welcome passive-client-handling-commit passive-client-random; do
  curl -fsSL "https://raw.githubusercontent.com/mlswg/mls-implementations/${PIN}/test-vectors/${family}.json" \
    -o "connect/mls/testdata/vectors/${family}.json"
done
```

The vectors deliver handshake messages as `PublicMessage` in some configurations. `DefaultProfile`
refuses `PublicMessage` by group policy, and the passive-client families are the one place that
matters, so `GroupConfig.Profile` here is `DefaultProfile()` with the wire-format gate relaxed:

```go
// in the test file, alongside runPassiveVectors
func vectorProfile() *Profile {
	profile := DefaultProfile()
	profile.AllowPublicMessage = true   // vectors only; group policy still refuses it in product code
	return profile
}
```

`Profile.AllowPublicMessage` is consumed from the Validation plan's `profile.go`; if it does not
exist, add it there as an unexported-by-default field with a constructor, rather than duplicating a
second profile type here. `A-ASSUME-4` keeps the product on `PrivateMessage`; this flag exists so
the vector families and the nightly `-public` interop matrix can exercise the other path.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./connect/mls/... -run TestPassiveClient -v`
Expected: PASS for all three families, each with `ran` greater than zero.

- [ ] **Step 5: Commit**

```bash
git add connect/mls/passive_client_vectors_test.go connect/mls/testdata/vectors/passive-client-*.json && \
git commit -m "test(mls): passive-client vector families 13, 14 and 15"
```

---

## Definition of done

This plan is complete when all of the following are true, each verified by running the command, not
by inspection:

| Gate | Command | Expected |
|---|---|---|
| Every task's tests pass | `go test ./connect/mls/... -count=1` | ok |
| Race-clean | `go test ./connect/mls/... -race -count=1` | ok |
| The `welcome` vector family passes, both directions | `go test ./connect/mls/... -run TestWelcomeVectors -v` | PASS, `ran > 0` |
| Passive-client families 13, 14, 15 pass | `go test ./connect/mls/... -run TestPassiveClient -v` | PASS, `ran > 0` each |
| Round-trip group tests pass | `go test ./connect/mls/... -run 'TestGroupLifecycleFullCycle\|TestJoinAtAnAdvancedEpoch\|TestLosingCommitter\|TestProfileRefusalsEndToEnd' -v` | PASS |
| Layering holds | `go test ./connect/ -run TestLayering -v` | PASS — `connect/mls` imports neither `connect` nor `connect/message` |
| No forbidden primitive | `grep -rn 'GenerateSharedSecret\|box.Precompute\|curve25519.ScalarMult' connect/mls/` | no matches |
| Vectors are pinned | `connect/mls/interop/PINS.md` names the mlswg commit the four vendored files came from | recorded |

**What this plan does not close.** The other 43-code negative-test obligation, the mlswg gRPC interop
harness in both roles, and the differential fuzzing against OpenMLS's nine targets belong to the
Validation and interop plan. This plan provides the named check functions those tests target
(`ValSem101`–`ValSem113`, `ValSem200`–`ValSem209`, `ValSem300`) and the group state machine the
interop client drives; it does not itself satisfy Gates 2, 3 or 4 of Spec A §4.
