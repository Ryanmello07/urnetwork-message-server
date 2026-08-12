# URmessage Spec A â€” Protocol, SDK and Connect

**Component:** `connect/mls`, `connect/message`, `sdk` client core, `URmessageSdk.dll`
**Branch:** `beta/message` on `Ryanmello07/urnetwork-connect` and `Ryanmello07/urnetwork-sdk`
**Date:** 2026-08-12
**Revision:** A-1 (first issue)
**Status:** Design, pending owner review
**Normative parent:** `docs/specs/2026-08-12-urmessage-protocol-design.md` (revision 5), hereafter **MASTER**
**Ledger:** `SPEC-LEDGER.md`
**Siblings:** Spec B (message server), Spec C (Windows messaging client)

This document is the implementation contract for everything below the client UI: the MLS
implementation, the storage/record layer, the client core in `sdk`, and the C ABI that Spec C calls.
It does not restate MASTER. Where a construction is defined in MASTER, this document cites the
section and specifies the **Go types, package boundaries, and test obligations** for it.

---

## 0. Planning ledger

### 0.1 Current state

| Item | State |
|---|---|
| MASTER protocol design | Revision 5, awaiting owner review |
| This spec | Revision A-1, first issue |
| Code | None. `beta/message` branches not yet cut. |
| Go toolchain | 1.26.5, verified on the build host (`go version` â†’ `go1.26.5`) |
| `crypto/mlkem` | Verified present: `NewDecapsulationKey768(seed)` takes a **64-byte** `d â€– z` seed |
| `crypto/sha3` | Verified present: `SumSHAKE256(data, length)`, `Sum256` â€” X-Wing is stdlib-only |
| `crypto/hkdf` | Verified present: `Extract[H](h, secret, salt)` â€” **note the argument order**, see Â§5.9 |
| `golang.org/x/sys/windows` | Already pinned at v0.46.0 in `sdk`; exposes `CryptProtectData`/`CryptUnprotectData`. DPAPI needs **no new dependency**. |
| MLS reference corpus | `mls_measure/` holds pinned OpenMLS 0.9.0-rc.1, mlspp, the mlswg `mls-implementations` harness, and a Go implementation used only as a shape reference |

### 0.2 Decisions specific to this component, and why

| # | Decision | Reasoning |
|---|---|---|
| A1 | MLS lives in `connect/mls/`, storage in `connect/message/`, client core in `sdk` | Follows MASTER Â§14 slices. `connect` is the cross-platform layer that already builds everywhere gomobile goes; `sdk` is the product surface. |
| A2 | `connect` (the parent package) **never** imports `connect/mls` or `connect/message` | `connect/CODESTYLE.md` "Package layering": a package must never import its own subpackages. `connect/message` may import `connect` and its peer `connect/mls`; the reverse is forbidden. This is enforced by a CI test (Â§11.4). |
| A3 | The narrow swappable interface is declared **at each consumer**, not in a shared interface package | Go satisfies interfaces structurally, so one engine implementation satisfies both `message.GroupEngine` and `sdk.MlsEngine` with no import edge between them. A shared `mlsiface` package would be a child both parents import â€” exactly the inversion A2 forbids. The **swap point** (which implementation is constructed) is in `sdk`, which is where the product decides. |
| A4 | X-Wing, HPKE, and the MLS ciphersuite are implemented on Go stdlib primitives only â€” no third-party crypto | Verified feasible: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, `chacha20poly1305` from the already-pinned `golang.org/x/crypto`. Zero new crypto dependency, zero Rust or C in CI, and `sdk` stays gomobile-buildable. |
| A5 | The TLS presentation-language codec is written once in `connect/mls/syntax` and used by `connect/message` too | MLS signs over serialized forms, so encode/decode must be byte-exact and round-trip stable. One codec, one fuzz corpus, one class of bug. |
| A6 | The OpenMLS differential oracle runs **out of process**, over a stdio/gRPC boundary, only in CI | Keeps "read-only oracle, never a dependency" literal: OpenMLS is never in `go.mod`, never linked, never present in a shipped artifact. Its `StorageProvider<const VERSION: u16>` cannot cross a C ABI anyway (measurement pass). |
| A7 | `URmessageSdk.dll` is a **new** cgo `c-shared` module at `sdk/cgo-message/`, with its own generator and its own `urmsg_` symbol prefix | The existing `sdk/cgo` generator walks the whole `github.com/urnetwork/sdk` surface and emits 10,444 lines of `urnet_*` exports. Reusing it would put the VPN surface in the messaging DLL and vice versa, and any messaging-driven generator change would perturb `URnetworkSdk.dll`'s ABI baseline. Separate module, separate baseline, separate symbol namespace, **zero** risk to VPN builds. |
| A8 | Local message store is SQLite via `modernc.org/sqlite` (pure Go, no cgo) behind a 14-method `sdk.MessageStore` interface | The store needs indexed pagination, per-group cursors, and text search. Hand-rolling that is a large, bug-dense surface. `modernc.org/sqlite` is pure Go and gomobile-buildable. **Marked as an assumption to confirm â€” see Â§0.5 A-ASSUME-1.** The interface is deliberately narrow so replacing it is a contained job. |
| A9 | Record ciphertext is stored **as ciphertext** in the local DB; only key material is DPAPI-sealed | No SQLCipher, no encrypted-DB dependency. The DB holds what the server holds plus decrypted-for-display text; the display cache is sealed as one blob per group per Â§8.3. |
| A10 | Transport uses the existing `connect.Client` addressed send/receive path with two new `MessageType` frame codes (29, 30) | `connect/transfer.go` already provides `Send`/`SendWithTimeout`/`AddReceiveCallback`. We add framing, not a transport. Confirmed no store-and-forward exists in `connect` â€” durability is the message server's job (Spec B). |
| A11 | Every exported ABI function is panic-guarded and every handle is registry-allocated with non-reusable ids | Copied deliberately from the proven `sdk/cgo/handles.go` design: a panic unwinding into C aborts the host process, and a reused handle id resolves a stale pointer to a live object. |

### 0.3 Interfaces to the other two components

| Direction | Contract | Detail |
|---|---|---|
| A â†’ B | Record wire format, `write_auth`, wrap indexing, commit-agreement semantics | Â§12.1 |
| B â†’ A | Server-advertised limits, fetch attestation, epoch verification state | Â§12.1 |
| A â†’ C | `URmessageSdk.dll` C ABI: handles, callbacks, memory ownership | Â§9, Â§12.2 |
| C â†’ A | Storage root path, DPAPI entropy, foreground/background lifecycle, WNS token | Â§12.2 |
| A â†” B | Both depend on `connect/message` for the record codec; the server imports it via `replace ../` | Â§2.4 |

### 0.4 Open items

1. **Retention floor negotiation** (MASTER open item 1) â€” the client-side behaviour is unimplemented until the owner rules. Placeholder: `RetentionPolicyConflict` event, refuse to commit.
2. **Push** (MASTER open item 2) â€” no push wake-up path exists. `sdk` exposes `SetPushToken` as a no-op stub so Spec C can wire WNS without an ABI break later.
3. **`OWNER_SUCCESSOR_SET` placement** (MASTER open item 4) â€” this spec assumes group-context extension and reserves extension type `0xF003`.
4. **Skipped-key window size** â€” Â§5.5 proposes 1024 per (sender, class). Needs a memory budget from Spec C before it is fixed.
5. **Errata against MASTER** â€” Â§5.10 records three concrete problems found while specifying the Go types. Two of them (E1, E2) are blocking for slice 2.

### 0.5 Assumptions to confirm

| Id | Assumption | Blast radius if wrong |
|---|---|---|
| A-ASSUME-1 | `modernc.org/sqlite` is acceptable in `sdk` despite being ~6 MB of transpiled C-as-Go, and builds under gomobile for `android/arm` (32-bit) | Contained: `sdk.MessageStore` is 14 methods. Fallback is a segment-log + index store, roughly 3 engineer-weeks. |
| A-ASSUME-2 | The Windows messaging app ships `URmessageSdk.dll` **and** `URnetworkSdk.dll` when both apps are installed, with no attempt to share a Go runtime between them | Two Go runtimes in one process is supported but doubles resident memory. If unacceptable, the two DLLs must merge, which is an ABI redesign. |
| A-ASSUME-3 | `X-Wing` is pinned at `draft-connolly-cfrg-xwing-kem-06` semantics (32-byte seed, SHAKE-256 expansion, SHA3-256 combiner) | MASTER Â§5.2 says the recovery key is a **96-byte** derivation, which is the *expanded* form of the -02 draft. See erratum E3 (Â§5.10). |
| A-ASSUME-4 | v1 groups use `PrivateMessage` wire format for **all** handshake messages (no `PublicMessage` on the wire) | Simplifies the profile and removes the membership-tag path from production. `PublicMessage` is still implemented because the interop harness and ValSem007/008 require it; it is refused by policy at the group config. |
| A-ASSUME-5 | The message server is trusted to be the single Delivery Service, so `connect/message` implements no client-side commit-conflict resolution beyond re-derive-and-retry | MASTER Â§9.3. If multi-server lands in V2 this becomes a real distributed-consensus problem. |

### 0.6 Edit log

Append-only. Newest last. One entry per commit that changes this spec. Every change follows
`SPEC-LEDGER.md` Â§6: edit â†’ subagent diff review â†’ fix â†’ commit with ledger entry â†’ append here.

<!-- entries begin -->

---

## 1. Scope

**In scope for this spec:** the RFC 9420 implementation; the storage record layer; the post-quantum
wrap composition; the client core (group state machine, local store, key-transparency client, device
provisioning); the `sdk` API surface; the `URmessageSdk.dll` C ABI; local persistence and sealing;
the test strategy and CI gates for all of the above.

**Out of scope:** anything the message server does (Spec B); anything WinUI 3, XAML, packaging, or
installer (Spec C); the operator's discovery directory and KT log server side (MASTER Â§14 slice 9).

**Cross-platform obligation.** Everything in `connect/mls`, `connect/message`, and `sdk` MUST build
for `windows/{amd64,arm64}`, `linux/{amd64,arm64}`, `darwin/arm64`, `android/{arm64,arm,amd64}`, and
`ios/arm64` from the first commit. No cgo outside `sdk/cgo-message/`. No build tags on the crypto.
The gomobile `bind` validation in `sdk/build/Makefile` is a CI gate (Â§11.5), so a type that gomobile
cannot export is a build break, not a warning.

---

## 2. Branch, repository and module layout

### 2.1 Branches

| Repo | Branch | Base | Parallel to |
|---|---|---|---|
| `Ryanmello07/urnetwork-connect` | `beta/message` | `origin/main` | `beta/algorithm-dpi`, `beta/custom-server` |
| `Ryanmello07/urnetwork-sdk` | `beta/message` | `origin/main` | same |
| `Ryanmello07/urnetwork-message-server` | `main` | â€” | Spec B |
| `Ryanmello07/urnetwork-windows-message` | `main` | â€” | Spec C |

`beta/message` is long-lived. Feature branches target it and are cherry-picked to `-upstream`
branches per the `urnetwork-upstream-pr` workflow only when a change is genuinely generic (for
example a codec fix in `connect/mls/syntax` is not; a `connect` bug found while building on it is).

**MLS and the message layer are NOT proposed upstream in v1.** They are a product, not a transport
improvement. Sending 25k lines of new crypto to `urnetwork/connect` is not a reviewable PR.

### 2.2 Package tree

```
connect/                                   (existing; never imports its own children)
  protocol/frame.proto                     + MessageType 29, 30  (Â§10.1)
  mls/                                     RFC 9420. peer-importable, imports only stdlib + x/crypto
    syntax/                                TLS presentation language codec (Â§5.8)
      decode.go  encode.go  varint.go  optional.go  vector.go
    suite.go                               ciphersuite registry; v1 = 0x0003 only
    crypto.go                              CryptoProvider: KDF, AEAD, sig, hash
    hpke.go                                RFC 9180 DHKEM(X25519,HKDF-SHA256) + ChaCha20Poly1305
    tree_math.go                           Â§4 node/leaf index arithmetic
    tree.go  tree_hash.go  tree_sync.go    ratchet tree, parent hashes, tree validation
    treekem.go                             UpdatePath encrypt/decrypt, path secrets
    leaf_node.go  key_package.go           Â§7.2 / Â§10, with urmessage_leaf_keys (Â§3.4)
    credential.go                          BasicCredential only
    framing.go                             FramedContent, AuthenticatedContent, Public/PrivateMessage
    secret_tree.go                         Â§9 sender ratchets, generation windows
    key_schedule.go                        Â§8 epoch secrets, exporter, PSK secret
    transcript.go                          confirmed/interim transcript hashes
    proposal.go  commit.go                 proposal list validation, commit application
    group.go                               the state machine; the only stateful exported type
    validation.go                          every ValSem check, one named func per code
    errors.go                              typed errors, one per ValSem code
    profile.go                             the v1 profile gate (Â§3.1)
    interop/                               child of mls; may import mls. NOT built into any product
      proto/                               vendored mlswg mls_client.proto + generated .pb.go
      client/main.go                       our gRPC MLSClient server
      oracle/main.go                       stdio decode-oracle client for differential fuzz
    testdata/
      vectors/                             the 16 mlswg vector families, pinned by commit
      corpus/                              seed corpus for the 9 fuzz targets
  message/                                 storage layer. imports connect and connect/mls (peers)
    record.go                              Record, RecordHeader, retention classes
    codec.go                               record wire encode/decode (uses mls/syntax)
    keyschedule.go                         storage_root, class keys, record_key ratchet
    ratchet.go                             sender ratchet + skipped-key window
    xwing.go                               X-Wing KEM (Â§5.4)
    wrap.go                                epoch wraps: device leaves, recovery targets, snapshot
    writeauth.go                           write_auth MAC (Â§5.7)
    handle.go                              sender_handle, recovery_handle, wrap_target_handle
    pad.go                                 size buckets, COVER records
    engine.go                              the GroupEngine interface (Â§6) + the connect/mls adapter
    tombstone.go                           TOMBSTONE construction and verification
    eph.go                                 eph_root, buckets, window expiry
    errors.go
sdk/                                       (existing)
  message.go                               MessageClient â€” the product surface (Â§7)
  message_group.go  message_device.go  message_verify.go  message_attachment.go
  message_events.go                        listener interfaces and event structs
  message_store.go                         MessageStore interface (Â§8.1)
  message_store_sqlite.go                  the v1 implementation
  message_seal.go                          Sealer interface + portable fallback
  message_seal_windows.go                  DPAPI (build tag windows)
  message_mls.go                           MlsEngine interface + the swap point (Â§6)
  message_kt.go                            key-transparency client, pinning, TOFU (Â§7.6)
  message_sync.go                          server sync loop, fetch attestations, backfill
  message_transport.go                     connect.Client binding (Â§10)
  cgo-message/                             NEW module: URmessageSdk.dll (Â§9)
    go.mod                                 module github.com/urnetwork/sdk/cgo-message
    gen/gen.go                             generator, seeded from sdk/cgo/gen
    exports_gen.go  exports_manual.go  exports_core.go
    callbacks.h  callbacks.c
    handles.go  cstrings.go
    include/urmessage_sdk.h  .hpp  .def
    smoke/  Makefile
```

### 2.3 Layering rules (enforced in CI)

```
sdk  â”€â”€importsâ”€â”€â–¶  connect/message  â”€â”€importsâ”€â”€â–¶  connect/mls  â”€â”€importsâ”€â”€â–¶  connect/mls/syntax
 â”‚                        â”‚
 â””â”€â”€importsâ”€â”€â–¶  connect â—€â”€â”˜
```

Forbidden edges, each asserted by a test in `connect/layering_test.go` and `sdk/layering_test.go`
that walks `go list -deps`:

- `connect` â†’ `connect/mls` or `connect/message` (A2)
- `connect/mls` â†’ `connect` or `connect/message` (MLS must be a self-contained crypto library, so it
  can be audited and fuzzed without the transport)
- `connect/mls/syntax` â†’ anything but stdlib
- `connect/message` â†’ `sdk`

### 2.4 Modules and dependency policy

`connect/mls/interop` is a **separate Go module** (`connect/mls/interop/go.mod`) so that gRPC,
protobuf, and the mlswg proto never enter `connect`'s dependency graph and therefore never enter
`sdk`, the DLL, or the mobile AARs. It is built only by the CI interop job.

New dependencies permitted in `connect` on `beta/message`: **none.**
New dependencies permitted in `sdk` on `beta/message`: `modernc.org/sqlite` only (A-ASSUME-1).

`server/go.mod` (Spec B) already imports `connect` and `sdk` via local `replace ../` directives.
Spec B consumes `connect/message` through that same replace. That means **the record codec has
exactly one implementation, shared by client and server** â€” the server cannot drift from the client's
notion of what a record is, because it is the same Go code.

---

## 3. `connect/mls` â€” the RFC 9420 implementation

### 3.1 The v1 profile

The profile is a hard gate, not a default. `mls.Profile` is checked at group creation, at every
message ingest, and at every commit construction. Anything outside it is a typed error, never a
silent skip.

| Dimension | v1 value | Enforcement point |
|---|---|---|
| Protocol version | `mls10` (0x0001) only | `profile.go:checkVersion` |
| Ciphersuite | `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003) only | `suite.go` registry has one entry |
| Credential type | `BasicCredential` (0x0001) only | `credential.go:Parse` |
| Wire format, handshake | `PrivateMessage` on the wire; `PublicMessage` implemented and tested but refused by group policy (A-ASSUME-4) | `group.go:policyCheck` |
| Wire format, application | `PrivateMessage` (ValSem005 makes this mandatory anyway) | `framing.go` |
| Proposal types | `add`, `update`, `remove`, `group_context_extensions` | `profile.go:allowedProposals` |
| External commits | **not implemented** | `commit.go` rejects `ExternalInit` at parse |
| External senders | **not implemented** | `profile.go`; extension `external_senders` refused |
| PSKs (external, resumption, branch) | **not implemented** | `proposal.go` rejects `psk` at parse |
| ReInit / branch / subgroup | **not implemented** | rejected at parse |
| Extensions, group context | `required_capabilities` (0x0003), `ratchet_tree` (0x0002), `urmessage_group_policy` (0xF001) | `profile.go:allowedGroupExtensions` |
| Extensions, leaf node | `urmessage_leaf_keys` (0xF002) | `leaf_node.go` |
| Extensions, reserved unimplemented | `urmessage_owner_successor` (0xF003) | reserved, parse-refused in v1 |
| Lifetime enforcement on KeyPackages | yes, Â±1h clock skew tolerance | `key_package.go:Validate` |
| Max group size | no hard cap; design target 500 (MASTER P4). A soft warning fires above 1000 leaves | `group.go` |
| Delivery service | ours, strongly consistent (MASTER Â§9.3) | `connect/message` |

### 3.2 Deliberately not implemented, and what happens instead

| RFC 9420 feature | v1 | Behaviour on receipt |
|---|---|---|
| External commits (Â§12.4.3.2) | no | `ErrProfileExternalCommit`, message dropped, warning logged, sender not trusted further this epoch |
| External senders extension (Â§12.1.8.1) | no | `ErrProfileExternalSender` at group-context validation; commit refused |
| PreSharedKey proposals (Â§12.1.5) | no | `ErrProfilePSK` at proposal parse |
| ReInit (Â§12.1.6) | no | `ErrProfileReInit` |
| Branching / subgroups (Â§11.2) | no | `ErrProfileBranch` |
| `x509` credentials (Â§5.3.2) | no | `ErrProfileCredentialType` |
| Ciphersuites other than 0x0003 | no | `ErrProfileCiphersuite` |
| `application_id` leaf extension | no | ignored if not in `required_capabilities`; refused if required |
| GREASE values (Â§13.2) | **parsed and ignored**, never generated | must not error â€” interop harness sends them |

**Every one of these still needs a negative test.** Narrowing the profile does not remove the
obligation to test ValSem240â€“246 and ValSem401â€“403; it changes the expected outcome from "the RFC's
specific check fires" to "the profile gate rejects the whole message before the check is reached."
Both are asserted, and the test asserts *which* error surfaced, so a future accidental implementation
of external commits turns the test red rather than green. See Â§4.3.

### 3.3 Core Go types

`connect/mls` follows `connect/CODESTYLE.md`: `self` receivers, `stateLock` for guarded state, usage+type
naming, explicit struct field names, doc comment on every file/type/func, no name repetition in comments.

```go
// suite.go
type CipherSuite uint16

const CipherSuiteX25519ChaCha20SHA256Ed25519 CipherSuite = 0x0003

// crypto.go
// the whole cryptographic surface of the implementation, in one interface, so an
// audit has one file to read and a test can substitute a deterministic instance.
type CryptoProvider interface {
    Suite() CipherSuite
    HashSize() int                                       // KDF.Nh â€” 32
    KeySize() int                                        // AEAD.Nk â€” 32
    NonceSize() int                                      // AEAD.Nn â€” 12
    Hash(data []byte) []byte
    Mac(key, data []byte) []byte                         // HMAC-SHA256
    MacVerify(key, data, tag []byte) bool                // constant time
    Extract(salt, ikm []byte) []byte                     // ARGUMENT ORDER IS (salt, ikm) â€” Â§5.9
    Expand(prk []byte, info []byte, length int) []byte   // ExpandWithLabel callers use DeriveSecret
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

// group.go
// the MLS group state machine. NOT safe for concurrent use â€” the caller
// (connect/message) serializes all access per group.
type Group struct {
    stateLock sync.Mutex
    ...
}

type GroupConfig struct {
    Suite            CipherSuite
    GroupId          []byte
    Extensions       []Extension            // group context extensions
    RequiredCaps     RequiredCapabilities
    Crypto           CryptoProvider
    Store            StateStore
    Profile          Profile
    LeafKeys         LeafKeysExtension      // urmessage_leaf_keys for our own leaf
}

func NewGroup(cfg *GroupConfig, signer SignaturePrivateKey, cred Credential) (*Group, error)
func JoinFromWelcome(cfg *GroupConfig, welcome []byte, ratchetTree []byte,
    keys *JoinKeyMaterial) (*Group, error)

func (self *Group) GroupId() []byte
func (self *Group) Epoch() uint64
func (self *Group) OwnLeafIndex() LeafIndex
func (self *Group) Members() []Member
func (self *Group) EpochAuthenticator() []byte
func (self *Group) Export(label string, context []byte, length int) ([]byte, error)
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error)   // Â§3.4
func (self *Group) RatchetTree() ([]byte, error)
func (self *Group) GroupContext() ([]byte, error)

func (self *Group) ProposeAdd(keyPackage []byte) (proposalMessage []byte, err error)
func (self *Group) ProposeRemove(leaf LeafIndex) ([]byte, error)
func (self *Group) ProposeUpdate() ([]byte, error)
func (self *Group) ProposeGroupContextExtensions(exts []Extension) ([]byte, error)

func (self *Group) Commit(byReference [][]byte, byValue []Proposal, opts *CommitOptions) (*CommitResult, error)
func (self *Group) MergePendingCommit() error
func (self *Group) ClearPendingCommit()

func (self *Group) ProcessMessage(message []byte) (*Processed, error)
func (self *Group) ApplyCommit(processed *Processed) error

func (self *Group) Protect(aad, plaintext []byte) (privateMessage []byte, err error)
func (self *Group) Unprotect(privateMessage []byte) (*ApplicationMessage, error)

type CommitResult struct {
    Commit      []byte     // MLSMessage(PrivateMessage) carrying the Commit
    Welcome     []byte     // MLSMessage(Welcome), nil when no Add
    RatchetTree []byte     // the post-commit tree, for out-of-band Welcome delivery
}

type Processed struct {
    Kind        ProcessedKind   // Application | Proposal | Commit
    Sender      Sender
    Application *ApplicationMessage
    Proposal    *Proposal
    Commit      *StagedCommit
}
```

`EpochSecretName` is a **closed** enum, deliberately. MASTER Â§8.2 needs exactly
`sender_data_secret` and `encryption_secret` for `archive_secret`, and MASTER's revision-3 correction
records that exporting `epoch_secret` instead would also expose `confirmation_key` and
`membership_key`. Making the accessor an open string invites exactly that mistake.

```go
type EpochSecretName uint8

const (
    EpochSecretSenderData EpochSecretName = iota + 1  // sender_data_secret
    EpochSecretEncryption                             // encryption_secret
)
// epoch_secret, confirmation_key, membership_key, init_secret, resumption_psk
// are intentionally NOT reachable through this API. connect/message must not
// be able to ask for them. See MASTER Â§8.2.
```

### 3.4 Leaf and group extensions

```go
// leaf_node.go
// urmessage_leaf_keys, extension type 0xF002. MASTER Â§5.3.
// carried in the LeafNode so it is covered by the leaf signature and the tree
// hash, validated by RFC 9420 Â§7.3, and removed by Remove with the rest of the leaf.
type LeafKeysExtension struct {
    AlgId          uint16   // 0x0014 = X-Wing (X25519 + ML-KEM-768)
    DeviceXwingPub []byte   // 1216 bytes for alg 0x0014
}

// urmessage_group_policy, extension type 0xF001. MASTER Â§6.
// group context, so it is covered by the transcript hash and no server can alter it.
type GroupPolicyExtension struct {
    Roles                []RoleEntry     // sorted by MemberId, canonical
    RetentionPolicy      RetentionPolicy
    DisappearingBuckets  []uint8
    ServerId             []byte          // v1: always the one server. V2 field, retained.
}
```

`RequiredCapabilities` for a v1 group is fixed:
`extension_types = [0xF001, 0xF002]`, `proposal_types = []`, `credential_types = [basic]`.
This means a client that does not understand `urmessage_leaf_keys` cannot be added â€” which is exactly
right, since a member with no X-Wing key cannot receive the epoch wrap and would silently lose
history at the next commit.

### 3.5 The state store

MLS state must survive process restart, and the epoch secrets in it are the crown jewels. The
interface is deliberately dumb â€” no queries, no transactions across groups â€” so `sdk` can implement
it over the sealed local store (Â§8) without leaking storage semantics into the crypto.

```go
// group.go
type StateStore interface {
    // group state, one blob per (groupId, epoch). the implementation retains a
    // bounded window of past epochs for out-of-order receipt and drops the rest.
    PutGroupState(groupId []byte, epoch uint64, state []byte) error
    GetGroupState(groupId []byte, epoch uint64) ([]byte, error)
    DeleteGroupStateBefore(groupId []byte, epoch uint64) error

    // our own private key material, keyed by public key. these MUST be sealed
    // by the implementation before they touch disk.
    PutPrivateKey(pub []byte, priv []byte) error
    GetPrivateKey(pub []byte) ([]byte, error)
    DeletePrivateKey(pub []byte) error

    // pending key packages awaiting a Welcome
    PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error
    TakeKeyPackage(ref []byte) (kp, initPriv, encPriv []byte, err error)
}
```

**Deletion is a security requirement, not housekeeping.** `DeleteGroupStateBefore` is what makes
MASTER Â§8.1's disappearing-message guarantee real: `eph_root[n]` lives in the epoch state, and a
retained old epoch state is a retained `eph_root`. The store implementation MUST overwrite before
unlinking where the platform allows it, and MUST NOT rely on SQLite `DELETE` alone (which leaves the
page contents in the freelist). See Â§8.4.

### 3.6 Concurrency contract

Per `CODESTYLE.md`, a type's methods are unsafe for concurrent use unless documented otherwise.

| Type | Contract |
|---|---|
| `mls.Group` | Not safe for concurrent use. Guarded by an internal `stateLock` only to make misuse fail loudly rather than corrupt; callers must still serialize. |
| `mls.CryptoProvider` | Safe for concurrent use. Stateless. |
| `message.GroupSession` | Safe for concurrent use. Owns exactly one `mls.Group` and serializes access through a single-goroutine command loop (`run()`, started by the constructor, per CODESTYLE goroutine lifecycle). |
| `sdk.MessageClient` | Safe for concurrent use. |

The command-loop shape matters: MLS commit construction, message ingest, and epoch rotation all
mutate the same tree, and a lock around each public method would not prevent an interleaving where
two goroutines both build a commit for epoch *n*. One goroutine per group, commands on a channel.

---

## 4. MLS acceptance criteria

MASTER Â§6 and Â§14 state the acceptance criterion as "the IETF test vectors pass." **A measurement
pass established that this is inadequate** and the criteria below supersede it. The evidence, not
restated here: the 16 vector families are ~6,158 lines against 40,181 lines of behavioural tests in
OpenMLS (~13% of the corpus); they test **none** of the 43 ValSem validation codes; and six 2026
OpenMLS defects each passed 100% of the vectors.

The revised criteria are six gates. **All six must be green before any non-beta user.** Gates 1â€“5
must be green before slice 5 (the first testable build).

### 4.1 Gate 1 â€” the narrow profile is implemented and enforced

Â§3.1 and Â§3.2. Verified by `profile_test.go`, which asserts for each row of Â§3.2 that the named
error surfaces, and by `TestProfileIsClosed`, which asserts the allowed-set tables contain exactly
the documented values (so adding a proposal type without updating this spec breaks the build).

### 4.2 Gate 2 â€” vectors plus the mlswg gRPC interop harness, both roles, every commit

#### 4.2.1 Vector families

All 16, pinned from `mlswg/mls-implementations` at a recorded commit, vendored into
`connect/mls/testdata/vectors/`.

| # | Family | File | Our package under test |
|---|---|---|---|
| 1 | Tree math | `tree-math.json` | `tree_math.go` |
| 2 | Crypto basics | `crypto-basics.json` | `crypto.go` |
| 3 | Secret tree | `secret-tree.json` | `secret_tree.go` |
| 4 | Message protection | `message-protection.json` | `framing.go` |
| 5 | Key schedule | `key-schedule.json` | `key_schedule.go` |
| 6 | Pre-shared keys | `psk_secret.json` | `key_schedule.go` (computation only; PSK proposals are profile-refused) |
| 7 | Transcript hashes | `transcript-hashes.json` | `transcript.go` |
| 8 | Welcome | `welcome.json` | `key_package.go`, `key_schedule.go` |
| 9 | Tree operations | `tree-operations.json` | `tree.go` |
| 10 | Tree validation | `tree-validation.json` | `tree_sync.go` |
| 11 | TreeKEM | `treekem.json` | `treekem.go` |
| 12 | Messages | `messages.json` | `syntax/`, all message types |
| 13 | Passive client, welcome | `passive-client-welcome.json` | `group.go` |
| 14 | Passive client, handling commit | `passive-client-handling-commit.json` | `group.go` |
| 15 | Passive client, random | `passive-client-random.json` | `group.go` |
| 16 | Vector deserialization | `deserialization.json` | `syntax/varint.go` |

Each family gets **both** directions where the vector format supports it: *verify* a supplied vector,
and *generate* a fresh vector then verify our own output with an independent code path. Generation
catches the class of bug where encoder and decoder are wrong in the same direction â€” which
verification alone cannot see, because the vector never round-trips through our encoder.

Family 6 is retained even though PSK proposals are profile-refused: `psk_secret` is computed in the
key schedule on every epoch (as the empty-PSK case), and getting the empty case wrong silently
diverges every epoch secret.

#### 4.2.2 The interop harness

The harness is the mlswg `mls-implementations` gRPC framework: each MLS client is a gRPC **server**
implementing `MLSClient`; a Go **test runner** drives them and assigns actors (`alice`, `bob`,
`charlieâ€¦`) to clients. The service has 30 RPCs across group creation, joining, proposals, commits,
external joins, reinit, branching, and free.

**Our client:** `connect/mls/interop/client`, a `package main` gRPC server implementing `MLSClient`
over `mls.Group`. It sits in a separate module (Â§2.4) so gRPC never reaches the product.

RPC implementation policy:

| RPC group | Our client |
|---|---|
| `Name`, `SupportedCiphersuites` | implemented; reports `0x0003` only |
| `CreateGroup`, `CreateKeyPackage`, `JoinGroup` | implemented |
| `GroupInfo`, `StateAuth`, `Export`, `Protect`, `Unprotect` | implemented |
| `AddProposal`, `UpdateProposal`, `RemoveProposal`, `GroupContextExtensionsProposal` | implemented |
| `Commit`, `HandleCommit`, `HandlePendingCommit` | implemented |
| `Free` | implemented; must actually release, and the harness job asserts zero leaked states at exit |
| `ExternalJoin`, `NewMemberAddProposal`, `CreateExternalSigner`, `AddExternalSigner`, `ExternalSignerProposal` | return `UNIMPLEMENTED` with a stable message |
| `StorePSK`, `ExternalPSKProposal`, `ResumptionPSKProposal` | return `UNIMPLEMENTED` |
| `ReInit*`, `CreateBranch`, `HandleBranch` | return `UNIMPLEMENTED` |

**Peers:** OpenMLS (`interop_client`), mlspp, mls-rs. All three pinned by container image digest,
prebuilt and pushed to GHCR by a weekly job that opens a digest-bump PR. CI never compiles Rust or
C++ on a per-commit path.

#### 4.2.3 Both roles â€” the part that is usually skipped

The test runner assigns actors to clients in the order the `-client host:port` flags are given.
Running with our client first exercises us as **committer/creator**; running with our client last
exercises us as **receiver/joiner**. A harness run that only does one of these tests half the
implementation, and the receiver half is where the validation logic lives.

The CI job runs, for each peer P in {openmls, mlspp, mls-rs} and each config C:

```
run 1:  test-runner -config C -client ours:50051 -client P:50052 -private
run 2:  test-runner -config C -client P:50052     -client ours:50051 -private
run 3:  test-runner -config C -client ours:50051 -client P:50052 -client openmls:50053 -private
```

Run 3 is the three-party case, which is the only one that exercises a commit we neither authored nor
are the sole recipient of.

`-private` is used because A-ASSUME-4 puts all handshake traffic in `PrivateMessage`. A separate
nightly matrix adds `-public` to keep the `PublicMessage` path (and ValSem007/008) honest.

| Config | Runs in per-commit CI | Expected |
|---|---|---|
| `welcome_join.json` | yes | pass |
| `commit.json` | yes | pass |
| `application.json` | yes | pass |
| `branch.json` | yes | **documented failure** â€” asserted against `profile-reject.json` |
| `external_join.json` | yes | **documented failure** â€” asserted |
| `external_proposals.json` | yes | **documented failure** â€” asserted |
| `reinit.json` | yes | **documented failure** â€” asserted |
| `deep_random.json` | nightly, with a logged seed | pass |

The "documented failure" mechanism is the important one. `connect/mls/interop/profile-reject.json`
lists, per config, exactly which scenario ids must fail and with what gRPC status and message. The CI
step asserts the observed failure set **equals** the expected set. A scenario that starts passing â€”
because someone implemented external commits without updating the profile â€” is a CI failure, not a
silent capability expansion.

#### 4.2.4 CI wiring, concretely

`.github/workflows/mls-interop.yml` on `connect`, triggered on every push to `beta/message` and
every PR targeting it:

```yaml
jobs:
  mls-interop:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    services: {}                       # compose is driven explicitly, not via services:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.26.5' }
      # our client, built from the branch under test
      - run: go build -o /tmp/urmessage-mls-client ./client
        working-directory: mls/interop
      # peers, pinned by digest â€” no source builds on the commit path
      - run: docker compose -f mls/interop/docker-compose.yml up -d --wait
      - run: /tmp/urmessage-mls-client -port 50051 &
      # the runner is vendored at the same pinned mlswg commit as the vectors
      - run: go run ./test-runner ...   # one invocation per row of the Â§4.2.3 matrix
        working-directory: mls/interop
      - name: assert documented failures
        run: go run ./cmd/assert-profile-rejects -expect profile-reject.json -got runner-output.json
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: interop-transcripts
          path: |
            mls/interop/out/*.json
            mls/interop/out/wiredump/*.bin
```

Our client writes every byte it sends and receives to `out/wiredump/`, so a failure produces the
exact bytes that diverged rather than a gRPC status code. This has to be built in from the start â€”
retrofitting it after the first cross-implementation failure is how a week gets lost.

The pinned mlswg commit is recorded in `connect/mls/interop/PINS.md` alongside the three peer image
digests, and bumping any of them is a PR that must show a green matrix.

### 4.3 Gate 3 â€” explicit negative tests for all 43 ValSem codes

One test function per code, named `TestValSemNNN_<slug>`, in `connect/mls/validation_test.go` (split
by category into `validation_framing_test.go`, `_proposal_`, `_commit_`, `_external_`, `_psk_`). Each
constructs a group in a valid state, mutates exactly one thing, and asserts the specific typed error.

Per `CODESTYLE.md` Â§Tests these are top-level functions, not `t.Run` subtests.

**Framing (RFC 9420 Â§6)**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem002 | Group id matches | error `ErrWrongGroupId` |
| ValSem003 | Epoch matches | `ErrWrongEpoch` |
| ValSem004 | Sender Member points to a non-blank leaf | `ErrBlankSenderLeaf` |
| ValSem005 | Application messages must be `PrivateMessage` | `ErrApplicationMustBeCiphertext` |
| ValSem006 | Ciphertext decryption must succeed | `ErrDecryptFailed` |
| ValSem007 | Membership tag present | `ErrMissingMembershipTag` (PublicMessage path only) |
| ValSem008 | Membership tag verifies | `ErrBadMembershipTag` |
| ValSem009 | Confirmation tag present | `ErrMissingConfirmationTag` |
| ValSem010 | Signature verifies | `ErrBadSignature` |
| ValSem011 | `PrivateMessageContent` padding is all-zero | `ErrNonZeroPadding` |

**Proposals covered by a commit (Â§12.1, Â§12.2)**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem101 | Add: signature key unique among proposals and members | `ErrDuplicateSignatureKey` |
| ValSem102 | Add: init key unique among proposals | `ErrDuplicateInitKey` |
| ValSem103 | Add: encryption key unique among proposals and members | `ErrDuplicateEncryptionKey` |
| ValSem104 | Add: init key â‰  encryption key | `ErrInitEqualsEncryptionKey` |
| ValSem105 | Add: ciphersuite and version match the group | `ErrSuiteMismatch` |
| ValSem106 | Add: required capabilities satisfied | `ErrMissingRequiredCapability` |
| ValSem107 | Remove: removed member unique among proposals | `ErrDuplicateRemove` |
| ValSem108 | Remove: removed member exists | `ErrRemoveNonMember` |
| ValSem109 | Update: required capabilities | `ErrMissingRequiredCapability` |
| ValSem110 | Update: encryption key unique among proposals and members | `ErrDuplicateEncryptionKey` |
| ValSem111 | Committer must not include its own Update proposals | `ErrSelfUpdateInCommit` |
| ValSem112 | Standalone Update sender must be type `member` | `ErrUpdateSenderNotMember` |
| ValSem113 | Proposal type supported by all members | `ErrUnsupportedProposalType` |

**Commits (Â§12.4)**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem200 | Commit must not cover an inline self-Remove | `ErrSelfRemoveInCommit` |
| ValSem201 | Path present when a proposal requires one | `ErrMissingPath` |
| ValSem202 | Path is the right length | `ErrPathLength` |
| ValSem203 | Path secrets decrypt correctly | `ErrPathDecrypt` |
| ValSem204 | Path public keys verified and match the direct-path private keys | `ErrPathKeyMismatch` |
| ValSem205 | Confirmation tag verifies | `ErrBadConfirmationTag` |
| ValSem206 | Path leaf-node encryption key unique among proposals and members | `ErrDuplicateEncryptionKey` |
| ValSem207 | Path encryption keys unique among proposals and members | `ErrDuplicateEncryptionKey` |
| ValSem208 | At most one `GroupContextExtensions` proposal per commit | `ErrMultipleGCE` |
| ValSem209 | GCE may only contain extensions all members support | `ErrUnsupportedGroupExtension` |

ValSem208 and ValSem209 are **untested in OpenMLS** (its own validation doc shows no test file for
either). We test them. This is one of the places where "differential against OpenMLS" is not
sufficient and the spec text is the authority.

**External commits (Â§12.4.3.2) â€” profile-refused in v1**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem240 | External commit covers â‰¥1 inline `ExternalInit` | `ErrProfileExternalCommit` at parse |
| ValSem241 | External commit covers â‰¤1 inline `ExternalInit` | `ErrProfileExternalCommit` |
| ValSem242 | External commit only covers allowlisted inline proposals | `ErrProfileExternalCommit` |
| ValSem244 | External commit includes no by-reference proposals | `ErrProfileExternalCommit` |
| ValSem245 | External commit contains a path | `ErrProfileExternalCommit` |
| ValSem246 | External commit signature verified with the path KeyPackage credential | `ErrProfileExternalCommit` |

Each of these six tests asserts the profile error **and** carries a commented-out assertion of the
RFC error, so that implementing external commits in V2 is a mechanical swap with the test already
written. (There is no ValSem243; the mlswg numbering skips it. ValSem247 is folded into ValSem010.)

**Ratchet tree (Â§12.4.3.1)**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem300 | Exported ratchet trees have no trailing blank nodes | `ErrTrailingBlankNodes` |

**PSK (Â§8.4) â€” profile-refused in v1**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem401 | `PreSharedKeyID` nonce has length `KDF.Nh` | `ErrProfilePSK` at parse |
| ValSem402 | PSK is Resumption(Application) or External | `ErrProfilePSK` |
| ValSem403 | No duplicate `PreSharedKeyID` in a proposal list | `ErrProfilePSK` |

ValSem403 is **untested in OpenMLS** (tracked as openmls#1335). We test it.

**ValSem400** â€” the RFC's SHOULD that an application bound the number of past epochs for which
`resumption_psk` is stored â€” is **not implemented in OpenMLS at all** (tracked as openmls#1122). We
implement it as a hard bound: `StateStore.DeleteGroupStateBefore` is called on every merged commit
with `epoch - PastEpochWindow`, `PastEpochWindow = 8`, and `TestValSem400_PastEpochBound` asserts
that state older than the window is gone from the store. This is not optional politeness â€” it is the
same deletion that makes MASTER Â§8.1's ephemeral guarantee true.

**Errata**

| Erratum | Subject | Test |
|---|---|---|
| RFC 9420 errata 8745 | Correction to the specified validation/derivation text as published in the RFC errata list | `TestErrata8745`, asserting the corrected behaviour and asserting the *pre*-erratum behaviour is rejected |
| RFC 9420 errata 8815 | As above | `TestErrata8815`, same shape |

Both tests are written against the errata text as published on the RFC Editor errata page at the
commit recorded in `connect/mls/ERRATA.md`, which quotes each erratum in full so the test is
reviewable without network access. **Action for the implementer:** transcribe both errata verbatim
into `ERRATA.md` as the first task of slice 1, and have the diff review verify the transcription
against the RFC Editor page. Do not paraphrase them from memory.

### 4.4 Gate 4 â€” differential fuzzing against OpenMLS's 9 targets

OpenMLS ships nine fuzz targets:

| Target | Our Go target |
|---|---|
| `extension_decode.rs` | `FuzzExtensionDecode` |
| `extension_decode_bytes.rs` | `FuzzExtensionDecodeBytes` |
| `key_package_decode.rs` | `FuzzKeyPackageDecode` |
| `key_package_decode_bytes.rs` | `FuzzKeyPackageDecodeBytes` |
| `mls_message_decode.rs` | `FuzzMlsMessageDecode` |
| `mls_message_decode_bytes.rs` | `FuzzMlsMessageDecodeBytes` |
| `proposal_decode.rs` | `FuzzProposalDecode` |
| `proposal_decode_bytes.rs` | `FuzzProposalDecodeBytes` |
| `welcome_decode.rs` | `FuzzWelcomeDecode` |

(The `_bytes` variants take an arbitrary byte string; the plain variants take a structured input the
fuzzer mutates. Go's native fuzzer only does the byte-string form, so the structured variants are
implemented as byte-string targets seeded from a structured generator in `syntax/fuzzgen_test.go`.)

Each Go target asserts three properties:

1. **No panic, no OOM, no unbounded allocation.** A length prefix must never be used to size an
   allocation before the remaining input is checked. `syntax` has a hard `MaxVectorLength` and a
   reader that cannot over-allocate.
2. **Round-trip stability.** If decode succeeds, `encode(decode(x))` must equal the canonical
   re-serialization, and `decode(encode(decode(x)))` must equal `decode(x)`. MLS signs over
   serialized forms, so a decoder that accepts two encodings of the same object is a signature-bypass
   primitive.
3. **Differential agreement with OpenMLS** on accept/reject and, on accept, on the canonical
   re-serialization bytes.

**How the oracle runs without becoming a dependency.** `connect/mls/interop/oracle` is a tiny Go
program that speaks a length-prefixed stdio protocol to a Rust binary built in CI from the pinned
OpenMLS checkout (`mls_measure/openmls`). The Rust side is 200 lines: read frame, attempt decode,
reply `{accept: bool, reserialized: bytes, error: string}`. The Go fuzz target talks to it over a
pipe. Nothing is linked; OpenMLS never appears in any `go.mod`; the oracle binary never ships.

Because a subprocess round-trip is slow, the differential property runs in a **nightly** long fuzz
job (4 hours per target, corpus persisted as a CI cache) while properties 1 and 2 run on every commit
for 60 seconds per target. Any differential disagreement is a P0 and opens an issue automatically
with the reproducing input attached.

Seed corpus: the 16 vector families, every wire dump the interop job produced (harvested nightly),
and OpenMLS's own checked-in corpora, all under `connect/mls/testdata/corpus/`.

### 4.5 Gate 5 â€” MLS sits behind a narrow swappable interface

Â§6. Verified by `TestEngineSwappable`, which builds the entire `connect/message` and `sdk` test suite
against a second `GroupEngine` implementation â€” a deterministic in-memory fake that is not MLS at all
â€” and asserts every test still passes. If a test needs a real MLS behaviour that the interface does
not expose, the interface has leaked and the test fails to compile, which is the signal we want.

### 4.6 Gate 6 â€” funded external audit before any non-beta user

Scope: `connect/mls` and `connect/message` in full, `sdk/message_*.go`, `sdk/cgo-message`, and the
key schedule end to end. The audit brief includes this document, MASTER, and the ValSem coverage
report. Not schedulable until gates 1â€“5 are green, because an auditor should not spend budget
finding what a test suite finds.

### 4.7 Release gating

| Gate | Blocks slice 5 (first testable build) | Blocks beta | Blocks GA |
|---|---|---|---|
| 1 profile | yes | yes | yes |
| 2 vectors + interop | yes | yes | yes |
| 3 ValSem 43 + errata | yes | yes | yes |
| 4 fuzz (properties 1â€“2) | yes | yes | yes |
| 4 fuzz (differential, nightly clean for 14 days) | no | yes | yes |
| 5 swappable interface | yes | yes | yes |
| 6 external audit | no | no | **yes** |

---

## 5. `connect/message` â€” the storage layer

MASTER Â§8 defines the record, its AADs, and the key schedule. This section defines the Go types, the
package API, and the invariants the code must carry.

### 5.1 Record types

```go
// record.go
type RetentionClass uint8

const (
    RetentionPermanent RetentionClass = 0
    RetentionDurable   RetentionClass = 1
    RetentionMedia     RetentionClass = 2
    RetentionEph       RetentionClass = 3   // low nibble of the wire byte carries the bucket
)

type SizeBucket uint8

const (
    SizeBucket256  SizeBucket = 0
    SizeBucket1K   SizeBucket = 1
    SizeBucket4K   SizeBucket = 2
    SizeBucket16K  SizeBucket = 3
    SizeBucket64K  SizeBucket = 4
    SizeBucketBlob SizeBucket = 5
)

// the authenticated header. every field here is covered by AAD_head and by
// write_auth (MASTER I6, I8). RecordId is NOT in either â€” it is server-assigned
// after acceptance and is pagination only.
type RecordHeader struct {
    GroupId        [32]byte
    SenderHandle   [16]byte
    Epoch          uint64
    StreamIndex    uint64
    IsCommit       bool
    RetentionClass RetentionClass
    EphBucket      uint8         // meaningful only when RetentionClass == RetentionEph
    SizeBucket     SizeBucket
    ExpireAt       uint64        // unix ms, advisory. keys are authoritative.
    BodyHash       [32]byte      // H(CtBody). RETAINED after CtBody is erased.
}

type Record struct {
    RecordId  []byte        // server-assigned, may be nil on construction
    Header    RecordHeader
    CtHead    []byte        // AEAD, always retained
    CtBody    []byte        // AEAD, erasable; nil once pruned
    WriteAuth [32]byte      // computed last
}
```

`EphBucket` is split out of `RetentionClass` in Go and rejoined on the wire, because a single `u8`
whose meaning depends on its own high bits is exactly the kind of field that gets compared with `==`
somewhere and silently treats `EPH(bucket 1)` as a different class from `EPH(bucket 0)`.

### 5.2 Construction order is a type, not a convention

MASTER Â§8 gives the construction order: encrypt body â†’ hash body â†’ encrypt head â†’ compute
`write_auth`. Every dependency is acyclic, and getting it wrong produces a circular AAD that
*appears* to work until two implementations disagree.

The API makes the order unrepresentable-otherwise:

```go
// codec.go
type recordBuilder struct{ ... }   // unexported; no way to construct a Record by hand

// the only way to build a record. the steps happen inside, in order.
func (self *GroupSession) SealRecord(
    class RetentionClass, ephBucket uint8, isCommit bool,
    headPlain []byte, bodyPlain []byte, expireAt uint64,
) (*Record, error)

// the only way to consume one.
func (self *GroupSession) OpenRecord(record *Record) (headPlain, bodyPlain []byte, err error)
```

`Record` has no exported constructor and its fields are set only by `codec.go` and by the decoder.
Spec B's server-side code never seals or opens; it uses `message.ParseRecord`, `message.EncodeRecord`,
and `message.VerifyWriteAuth`, which are the only exported functions it needs (Â§12.1).

### 5.3 Key schedule

```go
// keyschedule.go

// storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n])   MASTER Â§7
//
// mls_secret[n] = MLS-Exporter("URmessage/v1/storage", "", 32)   RFC 9420 Â§8.5
//
// NOTE the argument order. crypto/hkdf.Extract takes (secret, salt) â€” ikm FIRST.
// This wrapper takes (salt, ikm), matching the spec text. Never call
// crypto/hkdf.Extract directly anywhere in this package. See Â§5.9.
func StorageRoot(mlsSecret, pqSecret []byte) []byte

type ClassKeys struct {
    Perm    []byte   // HKDF-Expand(storage_root, "perm/v1", 32)
    Durable []byte   // "durable/v1"
    Media   []byte   // "media/v1"
    // Eph is NOT here. eph_root is 32 B fresh CSPRNG at commit, never derived
    // from storage_root. MASTER I4. Putting it in this struct would make the
    // wrong thing the easy thing.
}

func DeriveClassKeys(storageRoot []byte) *ClassKeys
func NewEphRoot(rand io.Reader) ([]byte, error)          // CSPRNG only; no seed parameter, ever
func EphKey(ephRoot []byte, bucket uint8, window uint64) []byte

// record_key[0]   = HKDF-Expand(class_key, "sender/v1" â€– LP(leaf_index), 32)
// record_key[i+1] = HKDF-Expand(record_key[i], "ratchet/v1", 32)
func RecordKeyZero(classKey []byte, leaf uint32) []byte
func RecordKeyNext(recordKey []byte) []byte

// key_head â€– nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)
// key_body â€– nonce_body = HKDF-Expand(record_key[i], "rec/v1/body", 56)
func RecordAeadHead(recordKey []byte) (key, nonce []byte)
func RecordAeadBody(recordKey []byte) (key, nonce []byte)

// group_handle_key = HKDF-Expand(storage_root[0], "gh/v1", 32)  â€” FIXED at group
// creation, so sender_handle survives epoch changes. MASTER Â§8.
func GroupHandleKey(storageRootEpoch0 []byte) []byte
func SenderHandle(groupHandleKey []byte, leaf uint32) [16]byte
```

`NewEphRoot` takes an `io.Reader` and nothing else â€” no group, no epoch, no storage root. There is
deliberately no function in this package that produces an `eph_root` from any durable input. MASTER
Â§8.1 calls this out as the most easily broken property in the design: a derivation would compile, pass
every test that does not specifically look for it, and silently make every expired message
recoverable forever. The type signature is the defence. `TestEphRootHasNoDurableInput` additionally
asserts by reflection that no exported function in the package returns eph key material from
arguments that include a `storageRoot`.

### 5.4 X-Wing

`draft-connolly-cfrg-xwing-kem`, implemented exactly, on Go stdlib. No third-party dependency, and
the ordering of combiner inputs and the domain-separation label are transcribed from the draft, not
reconstructed.

```go
// xwing.go
const (
    XwingSeedSize       = 32     // dk, the storable private key
    XwingExpandedSize   = 96     // SHAKE256(seed, 96): [0:64] = ML-KEM dâ€–z, [64:96] = X25519 sk
    XwingPublicKeySize  = 1216   // pk_M (1184) â€– pk_X (32)
    XwingCiphertextSize = 1120   // ct_M (1088) â€– ct_X (32)
    XwingSharedSize     = 32
)

type XwingPrivateKey struct{ ... }   // holds the 32-byte seed and the expanded halves
type XwingPublicKey struct{ ... }

func XwingKeyGenFromSeed(seed []byte) (*XwingPrivateKey, error)   // seed must be 32 B
func XwingGenerateKey(rand io.Reader) (*XwingPrivateKey, error)
func (self *XwingPrivateKey) Public() *XwingPublicKey
func (self *XwingPublicKey) Bytes() []byte
func ParseXwingPublicKey(b []byte) (*XwingPublicKey, error)

func XwingEncapsulate(rand io.Reader, pub *XwingPublicKey) (ct, ss []byte, err error)
func XwingDecapsulate(priv *XwingPrivateKey, ct []byte) (ss []byte, err error)
```

Stdlib mapping, verified against the pinned toolchain:

| X-Wing step | Go |
|---|---|
| Expand `dk` | `sha3.SumSHAKE256(seed, 96)` |
| ML-KEM key from `expanded[0:64]` | `mlkem.NewDecapsulationKey768(expanded[0:64])` â€” documented as taking a 64-byte `d â€– z` seed |
| X25519 scalar from `expanded[64:96]` | `ecdh.X25519().NewPrivateKey(expanded[64:96])` |
| ML-KEM encaps/decaps | `EncapsulationKey768.Encapsulate()`, `DecapsulationKey768.Decapsulate(ct)` |
| X25519 DH | `PrivateKey.ECDH(pub)` â€” **error is a hard failure**, never ignored |
| Combiner | `sha3.Sum256(XWingLabel â€– ss_M â€– ss_X â€– ct_X â€– pk_X)` |

Mandatory tests before any use (MASTER Â§7.2): the draft's own KAT vectors, both directions; a
negative test that a low-order X25519 point produces an error rather than a zero shared secret; and a
test that a truncated or over-long ciphertext is rejected by length before any arithmetic.

**`sdk.GenerateSharedSecret` (`sdk/sdk.go:804-817`), `box.Precompute`, and `curve25519.ScalarMult`
MUST NOT be referenced anywhere in `connect/mls`, `connect/message`, or `sdk/message_*.go`.** A CI
grep gate asserts this (Â§11.4). The existing function length-checks only, reaches deprecated
`ScalarMult` through `box.Precompute`, and returns an all-zero secret on a low-order point.

### 5.5 The sender ratchet and the skipped-key window

```go
// ratchet.go
// a real forward ratchet: the sender overwrites record_key[i] after use.
// receivers keep a bounded window of skipped keys for out-of-order receipt.
type SenderRatchet struct {
    stateLock sync.Mutex
    ...
}

func NewSenderRatchet(classKey []byte, leaf uint32) *SenderRatchet
func (self *SenderRatchet) Next() (index uint64, recordKey []byte)     // advances and zeroes
type ReceiverRatchet struct{ ... }
func (self *ReceiverRatchet) KeyFor(index uint64) ([]byte, error)      // fills and prunes the window
```

Window size: **1024 keys per (sender_handle, retention class)**, ~32 KB each, capped at 64 senders
tracked per group before the oldest is evicted. For a 500-member group with two devices each this is
a worst case of ~2 MB per group, which is why the cap on tracked senders exists. Needs a Spec C memory
budget to finalize (open item 4).

Beyond the window, a record is undecryptable and surfaces as `MessageGap` in the UI â€” not as an
error. This is a deliberate, visible failure: silently skipping is how a message loss becomes
invisible.

**Zeroization.** `Next()` overwrites the previous key with zeros before returning. Go gives no
guarantee this survives the optimizer, so `zeroize()` uses a `//go:noinline` helper writing through
a `unsafe.Pointer`-derived slice, and `TestRatchetZeroizes` inspects the backing array after the
call. This is best-effort and documented as such; a Go program cannot promise a secret is gone from
RAM. It is still worth doing, because the common case â€” a key still sitting in a live struct field â€”
is entirely preventable.

### 5.6 `stream_index` is write-once, and durably so

MASTER Â§8: a device MUST durably record "index k consumed" **before** encrypting, and MUST NEVER
encrypt a second record at a consumed index. Nonce reuse under a repeated `record_key` is a total
break of both AEADs for that record.

```go
// ratchet.go
// the reservation MUST be durable before the key is produced. this is the
// caller's obligation and the constructor takes the sink to make it explicit.
type StreamIndexReserver interface {
    // returns only after the reservation is durable (fsync'd or equivalent).
    Reserve(groupId []byte, class RetentionClass, index uint64) error
    HighWater(groupId []byte, class RetentionClass) (uint64, error)
}
```

`SealRecord` calls `Reserve` and refuses to proceed on error. On startup, `HighWater` is read and the
ratchet resumes at `highWater + 1`, never at a recomputed value. A crash between reserve and send
burns an index, which is fine: the server enforces monotonicity, not contiguity, so a gap does not
brick the stream.

`TestStreamIndexNeverReused` runs 10,000 seal operations with an injected crash after `Reserve` and
before the AEAD, restarts the session from the persisted state, and asserts no `(class, index)` pair
is ever produced twice.

### 5.7 `write_auth`

```go
// writeauth.go
func WriteKey(storageRoot []byte) []byte    // HKDF-Expand(storage_root[n], "write/v1", 32)

// MAC(write_key, "URmessage/v1/write" â€– LP(server_nonce) â€– LP(group_id)
//     â€– LP(sender_handle) â€– u64(epoch) â€– u64(stream_index) â€– u8(is_commit)
//     â€– u8(retention_class) â€– u8(size_bucket) â€– u64(expire_at)
//     â€– LP(H(ct_head)) â€– LP(body_hash))
func ComputeWriteAuth(writeKey []byte, serverNonce []byte, header *RecordHeader, ctHead []byte) [32]byte
func VerifyWriteAuth(writeKey []byte, serverNonce []byte, record *Record) bool   // constant time
```

`VerifyWriteAuth` is exported specifically for Spec B. It is the **only** authentication the server
performs, and per MASTER I5 it is access control, never authenticity â€” a forged record fails MLS
verification at every client no matter what the server accepts.

`serverNonce` comes from the connection challenge and prevents cross-connection replay. Its lifetime
and rotation are Spec B's to define; this layer takes it as an opaque byte string and refuses to
compute with an empty one.

### 5.8 The codec

`connect/mls/syntax` implements the TLS presentation language of RFC 8446 Â§3 as MLS uses it: fixed
integers, `opaque V<..>` with the MLS variable-length prefix, `optional<T>`, and vectors.

Rules, each with a fuzz property behind it (Â§4.4):

1. **Canonical encoding only.** The variable-length integer prefix has exactly one valid encoding per
   length; a non-minimal prefix is a decode error. (`deserialization.json` is precisely this test.)
2. **No allocation before validation.** A length prefix is checked against the remaining input before
   any `make`. `MaxVectorLength` caps at 1 MiB for anything but the ratchet tree, which caps at 16 MiB.
3. **Full consumption.** Top-level decode fails if bytes remain.
4. **Round-trip byte-exact.** `encode(decode(x)) == x` for every accepted `x`, asserted in the fuzzer.

`connect/message` uses the same codec for records, so there is one length-prefix implementation in the
system and one place for a length-prefix bug to be.

### 5.9 Implementation guardrails

These are the specific ways this code will be got wrong. Each has a mechanical defence.

| # | Hazard | Defence |
|---|---|---|
| G1 | **`crypto/hkdf.Extract(h, secret, salt)` takes ikm first, salt second.** MASTER writes `HKDF-Extract(salt = mls_secret, ikm = pq_secret)`. Swapping them compiles, returns 32 bytes, and passes every test that does not compare against an independent implementation. | `message.StorageRoot(mlsSecret, pqSecret)` is the only call site. A lint gate forbids `hkdf.Extract` anywhere else in `connect/message` and `connect/mls`. `TestStorageRootKAT` pins the output against a hand-computed vector recorded in the test file with its derivation shown. |
| G2 | `eph_root` derived from anything durable | Â§5.3: no such function exists; reflection test |
| G3 | X25519 error ignored | All `ECDH` calls return through a helper that converts error to `ErrInvalidPoint`; grep gate forbids `_ =` on an `ECDH` result |
| G4 | `body_hash` placed in `AAD_body` (circular) | `AAD_body` is built by a function that does not take a hash argument |
| G5 | AEAD nonce reuse | Â§5.6 durable reservation + `TestStreamIndexNeverReused` |
| G6 | `epoch_secret` exported instead of the two named secrets | Â§3.3: `EpochSecretName` is a closed two-value enum |
| G7 | Signature/MAC mismatch logged and continued | `errors.go` types are all fatal-by-construction; no verification helper returns `bool` except `VerifyWriteAuth`, whose one caller is asserted to `return` on false |
| G8 | Non-constant-time comparison of a tag | Every tag comparison goes through `crypto/subtle.ConstantTimeCompare`; grep gate forbids `bytes.Equal` in `validation.go`, `writeauth.go`, `framing.go` |
| G9 | ML-KEM seed length confusion (32 vs 64) | `XwingKeyGenFromSeed` takes exactly 32 and expands; `mlkem.NewDecapsulationKey768` is called with exactly `expanded[0:64]`; both lengths asserted with a compile-time-adjacent `const` check and a unit test |

### 5.10 Errata against MASTER found while specifying this layer

These are proposed corrections to MASTER, not decisions taken unilaterally. **E1 and E2 are blocking
for slice 2** â€” the layer cannot be built correctly without a ruling.

**E1 (blocking) â€” a seed-only restorer cannot derive `storage_root[n]`, so it cannot decrypt anything.**

MASTER Â§8.2 gives the recovery target `pq_secret[n]` and `archive_secret[n]`.
`storage_root[n] = HKDF-Extract(mls_secret[n], pq_secret[n])` requires `mls_secret[n]`, which is
`MLS-Exporter(...)` and therefore requires live MLS epoch state. A seed-only restorer (MASTER Â§5.4)
has no MLS state by definition. It can therefore derive no class key, no `record_key`, and cannot
open `ct_head` or `ct_body` â€” even though `archive_secret` would let it open the MLS `PrivateMessage`
inside. Seed-only restore does not work as specified.

*Proposed fix:* the **recovery** wrap carries `storage_root[n]` (32 B) in place of `pq_secret[n]`.
The device wrap is unchanged and still carries `pq_secret[n]`.

*Why this does not weaken the PQ property:* the PQ protection exists against an adversary who
harvested the classical MLS handshake and later gains a quantum computer. That adversary derives
`mls_secret[n]` from the harvested handshake regardless, so for them `pq_secret` and `storage_root`
are equivalent â€” both are protected solely by X-Wing, which is what MASTER Â§7 intends. Against a
classical adversary, the only way to read the recovery wrap is to hold the recovery X-Wing private
key, which is derived from `recovery_root`, which is derived from the seed â€” and a seed holder
already reads everything (MASTER Â§13). No adversary class gains anything.

**E2 (blocking) â€” the per-epoch ratchet-tree snapshot must not be duplicated per recovery target.**

MASTER Â§8.2 says the recovery wrap "also carries a snapshot of the epoch's ratchet-tree public state
and GroupContext." For the 500-member design target with two devices each, the tree snapshot is
roughly 300 KB. Carried inside each of 500 member wraps, a single commit would emit ~150 MB. It also
duplicates the same public data 500 times.

*Proposed fix:* the snapshot is one `PERMANENT`-class record per epoch, encrypted under
`K_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 32)`. The recovery wrap carries secrets
only. With E1 applied, `storage_root[n]` is in the recovery wrap, so the restorer can open the
snapshot record. Sizing after both fixes, for 500 members Ã— 2 devices:

| Item | Per unit | Count | Total |
|---|---|---|---|
| Device wrap (X-Wing ct 1120 + AEAD over `pq_secret â€– eph_root` = 80 + framing 10) | 1,210 B | 1,000 | 1.21 MB |
| Recovery wrap (1120 + AEAD over `storage_root â€– archive_secret` = 112 + framing 10) | 1,242 B | 500 | 0.62 MB |
| Epoch snapshot | ~300 KB | 1 | 0.30 MB |
| **Per commit** | | | **~2.1 MB** |

That is a real number Spec B must plan for, and it is why Â§12.1 requires the server to index wraps by
target so a joining device fetches ~1.2 KB rather than 2.1 MB.

**E3 (non-blocking, needs confirmation) â€” the recovery X-Wing key derivation length.**

MASTER Â§5.2 derives `rk_xwing = XWing.KeyGen(HKDF-Expand(recovery_root, "rk/v1" â€– LP(g), 96))` with
a **96-byte** input. In the current X-Wing draft the private key is a **32-byte** seed that the
algorithm itself expands to 96 bytes with SHAKE-256. The 96-byte figure matches the *expanded* form of
an earlier draft. Deriving 96 bytes and using them directly as the expanded key is not X-Wing, does
not match the draft's test vectors, and forfeits the security proof that MASTER Â§7 gives as the entire
reason for choosing it.

*Proposed fix:* `HKDF-Expand(recovery_root, "rk/v1" â€– LP(g), 32)` â†’ 32-byte X-Wing seed â†’ expand per
draft. Recorded as A-ASSUME-3.

---

## 6. The narrow swappable interface

Gate 5 (Â§4.5). The interface is declared at each consumer (A3); Go's structural typing makes the
`connect/mls` adapter satisfy both without an import edge.

```go
// connect/message/engine.go
//
// the entire MLS surface connect/message is allowed to see. adding a method
// here is a design decision, not a convenience â€” everything added is something
// a replacement implementation must provide.
type GroupEngine interface {
    Suite() uint16
    NewKeyPackage() (keyPackage []byte, err error)
    CreateGroup(groupId []byte, policy []byte, leafKeys []byte) (GroupHandle, error)
    JoinFromWelcome(welcome, ratchetTree []byte) (GroupHandle, error)
}

type GroupHandle interface {
    GroupId() []byte
    Epoch() uint64
    OwnLeafIndex() uint32
    MemberCount() int
    MemberAt(i int) (leafIndex uint32, identityPub []byte, leafKeys []byte, err error)

    // the two named secrets of MASTER Â§8.2, and the exporter. nothing else.
    Export(label string, context []byte, length int) ([]byte, error)
    SenderDataSecret() ([]byte, error)
    EncryptionSecret() ([]byte, error)
    EpochAuthenticator() []byte
    RatchetTreeSnapshot() ([]byte, error)
    GroupContextBytes() ([]byte, error)

    ProposeAdd(keyPackage []byte) ([]byte, error)
    ProposeRemove(leafIndex uint32) ([]byte, error)
    ProposeUpdate() ([]byte, error)
    ProposeGroupPolicy(policy []byte) ([]byte, error)

    Commit(byReference [][]byte) (commit, welcome, ratchetTree []byte, err error)
    MergePendingCommit() error
    ClearPendingCommit()

    Process(message []byte) (*EngineProcessed, error)
    ApplyCommit(processed *EngineProcessed) error

    Protect(aad, plaintext []byte) ([]byte, error)
    Unprotect(message []byte) (aad, plaintext []byte, senderLeaf uint32, err error)

    Close() error
}

type EngineProcessed struct {
    Kind       uint8    // 1 application, 2 proposal, 3 commit
    SenderLeaf uint32
    Aad        []byte
    Plaintext  []byte
    Raw        []byte   // opaque to connect/message; handed back to ApplyCommit
    stagedRef  any      // engine-private; connect/message never inspects it
}
```

Note what is **not** on this interface: no tree, no node, no secret tree, no HPKE, no
`epoch_secret`, no `confirmation_key`, no `membership_key`, no ciphersuite internals. `EngineProcessed.Raw`
and `stagedRef` are deliberately opaque so a staged commit can be carried across a policy decision
without `connect/message` being able to read or forge it.

**The swap point** lives in `sdk`, where the product decides:

```go
// sdk/message_mls.go
type MlsEngineFactory interface {
    NewEngine(store MlsStateStore, signer *MessageIdentity) (message.GroupEngine, error)
}

// the v1 factory. replacing it is a one-line change and TestEngineSwappable
// proves the rest of the system does not care.
func NewConnectMlsEngineFactory() MlsEngineFactory
```

---

## 7. The `sdk` API surface

`sdk` is the product surface. It must satisfy gomobile's type restrictions (Â§7.8) because the same
package builds the Android AAR and the Apple framework, and the cgo generator's ABI baseline
(Â§9) is derived from it.

### 7.1 Object model

| Type | Kind | Notes |
|---|---|---|
| `MessageClient` | behavioural handle | the root. one per device per account. safe for concurrent use. |
| `MessageGroup` | value struct | snapshot; not live. re-fetch or listen for changes. |
| `MessageEntry` | value struct | one rendered message, its state, its attachments |
| `MessageDevice` | value struct | one of your own device leaves |
| `MessageMember` | value struct | one member of a group |
| `MessagePin` | value struct | a TOFU pin on a contact's identity key |
| `MessageSendTicket` | behavioural handle | in-flight send; cancellable |
| `Sub` | behavioural handle | existing sdk type; returned by every `Add*Listener` |
| `*List` types | value struct | gomobile cannot export `[]T`; the existing sdk `*List` pattern applies |

### 7.2 Lifecycle and identity

```go
func NewMessageClient(device Device, settings *MessageClientSettings) (*MessageClient, error)
func (self *MessageClient) Close()

type MessageClientSettings struct {
    StorageDir      string   // Spec C supplies; sealed material lives under here
    MessageServerId string   // v1: the one server's client id
    EnableCover     bool     // MASTER T7 â€” off by default
    MediaCacheBytes int64
}

// identity â€” MASTER Â§5.1. the phrase is generated on-device and NEVER transmitted.
func GenerateMessageSeedphrase() (string, error)               // BIP39 24 words
func ValidateMessageSeedphrase(phrase string) error
func (self *MessageClient) HasIdentity() bool
func (self *MessageClient) CreateIdentity(phrase string) error // first run
func (self *MessageClient) RestoreIdentity(phrase string, callback RestoreCallback) *MessageSendTicket
func (self *MessageClient) IdentityFingerprint() string        // for display; 12 groups of 5 digits
func (self *MessageClient) IdentityPublicKey() []byte

// the local-only start; does not touch the network. the URnetwork account and
// its ByJwt come from the existing Device (MASTER Â§4.4).
func (self *MessageClient) Start() error
func (self *MessageClient) SyncState() *SyncState
func (self *MessageClient) AddSyncListener(listener SyncListener) *Sub
```

`CreateIdentity` never returns the phrase and never accepts a phrase it generated itself â€” Spec C
calls `GenerateMessageSeedphrase`, displays it, requires confirmation, then calls `CreateIdentity`.
The seedphrase is never written to the local store; only the derived `master_key` children are, and
they are sealed (Â§8).

### 7.3 Groups

```go
func (self *MessageClient) CreateGroup(name string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) CreateDirect(principal string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) Groups() *MessageGroupList
func (self *MessageClient) Group(groupId string) *MessageGroup            // nil if unknown
func (self *MessageClient) Members(groupId string) *MessageMemberList
func (self *MessageClient) InviteMember(groupId string, principal string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) RemoveMember(groupId string, memberId string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) SetMemberRole(groupId string, memberId string, role string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) LeaveGroup(groupId string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) SetGroupPolicy(groupId string, policy *MessageGroupPolicy, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) PendingInvites() *MessageInviteList
func (self *MessageClient) AcceptInvite(inviteId string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) DeclineInvite(inviteId string) error
func (self *MessageClient) AddGroupListener(listener GroupListener) *Sub

type MessageGroupPolicy struct {
    RetentionDurableMs   int64
    RetentionMediaMs     int64    // default 1 month; server cap applies
    DisappearingBucket   int32    // 0 = off; 1=1h 2=8h 3=1d 4=1w 5=4w
    ReadReceipts         bool     // default true
    TypingIndicators     bool     // default true
}
```

`CreateDirect` is not a different code path â€” MASTER P2, a DM is a two-member group. It exists only
so the UI can express intent and the client can render it as a conversation. `MessageGroup.IsDirect`
is `MemberCount() == 2 && CreatedAsDirect`.

Role strings are `"owner"`, `"admin"`, `"member"`, `"observer"` (MASTER Â§11). Strings rather than an
int enum because gomobile enums are ints in Java/Swift with no name, and a mis-set role is a
security-relevant bug.

### 7.4 Messaging

```go
func (self *MessageClient) SendText(groupId string, text string, replyToId string,
    callback SendCallback) *MessageSendTicket
func (self *MessageClient) SendAttachment(groupId string, filePath string, mimeType string,
    caption string, callback SendCallback) *MessageSendTicket
func (self *MessageClient) React(groupId string, targetId string, emoji string,
    callback SendCallback) *MessageSendTicket
func (self *MessageClient) Unreact(groupId string, targetId string, emoji string,
    callback SendCallback) *MessageSendTicket

// delete-for-everyone. a TOMBSTONE, MLS-authenticated from the original sender.
// MASTER Â§12.1: a deletion cannot be forged.
func (self *MessageClient) DeleteForEveryone(groupId string, messageId string,
    callback SendCallback) *MessageSendTicket
// local-only removal. does not affect anyone else and says so in the UI copy.
func (self *MessageClient) DeleteLocal(groupId string, messageId string) error

func (self *MessageClient) MarkRead(groupId string, throughMessageId string) error
func (self *MessageClient) SetTyping(groupId string, typing bool)

// history comes from the local store, synchronously. the sync loop backfills.
func (self *MessageClient) History(groupId string, beforeMessageId string, limit int32) *MessageEntryList
func (self *MessageClient) Entry(groupId string, messageId string) *MessageEntry
func (self *MessageClient) Search(query string, limit int32) *MessageEntryList
func (self *MessageClient) RequestBackfill(groupId string, beforeMessageId string, callback SyncCallback) *MessageSendTicket

func (self *MessageClient) AddMessageListener(groupId string, listener MessageListener) *Sub
func (self *MessageClient) DownloadAttachment(groupId string, messageId string, attachmentId string,
    destPath string, callback DownloadCallback) *MessageSendTicket

type MessageEntry struct {
    MessageId    string
    GroupId      string
    SenderId     string     // stable per group; maps to a MessageMember
    SentAtMs     int64
    ReceivedAtMs int64
    Kind         string     // "text" | "attachment" | "reaction" | "tombstone" | "system" | "gap"
    Text         string
    ReplyToId    string
    State        string     // "pending" | "sent" | "delivered" | "read" | "failed" | "expired"
    ExpiresAtMs  int64      // 0 when not disappearing
    Edited       bool       // reserved; always false in v1
    Attachments  *MessageAttachmentList
    Reactions    *MessageReactionList
    ReadBy       *MessageReceiptList
}
```

`Kind == "gap"` is a first-class entry type: an undecryptable or missing record renders as a visible
gap with the reason (`"expired"`, `"out_of_window"`, `"not_a_member_yet"`, `"withheld"`). A messenger
that silently drops what it cannot read is a messenger that cannot be trusted to have shown you
everything.

`MessageSendTicket` has `Cancel()` and `Await()`; `Await` is not exposed over the ABI (Â§9.5).

### 7.5 Devices â€” MASTER Â§5.4, Â§11

```go
func (self *MessageClient) Devices() *MessageDeviceList
func (self *MessageClient) ThisDeviceId() string
// existing device: produce the QR payload and the short authentication string
func (self *MessageClient) BeginDeviceLink(callback DeviceLinkCallback) *MessageDeviceLinkSession
// new device: consume the QR payload
func (self *MessageClient) JoinDeviceLink(offerPayload string, callback DeviceLinkCallback) *MessageDeviceLinkSession

type MessageDeviceLinkSession struct{ ... }   // behavioural handle
func (self *MessageDeviceLinkSession) SessionId() string
func (self *MessageDeviceLinkSession) OfferPayload() string       // QR content, existing side
func (self *MessageDeviceLinkSession) AuthString() string         // both sides display; user compares
func (self *MessageDeviceLinkSession) Confirm(matches bool) error // both sides
func (self *MessageDeviceLinkSession) Cancel()

// self-service revocation. MASTER Â§11: a member may add or remove THEIR OWN
// device leaves and commit that change, without an admin.
func (self *MessageClient) RemoveDevice(deviceId string, callback GroupCallback) *MessageSendTicket
```

The provisioning bundle carries the group list and **durable-class** archive material only.
Ephemeral-class material is never included (MASTER I4). `TestProvisioningBundleHasNoEphemeral`
asserts by construction: the bundle builder takes a `DurableArchive` type that has no field capable
of holding an `eph_root`.

### 7.6 Verification â€” MASTER Â§10, SSH-style TOFU

```go
func (self *MessageClient) SafetyNumber(principal string) (string, error)
func (self *MessageClient) Pins() *MessagePinList
func (self *MessageClient) PinFor(principal string) *MessagePin
// the SSH changed-host-key moment. blocking in the UI; this is the "I accept" call.
func (self *MessageClient) AcceptKeyChange(principal string, newKeyFingerprint string) error
func (self *MessageClient) MarkVerified(principal string, viaSafetyNumber bool) error
func (self *MessageClient) AddKeyChangeListener(listener KeyChangeListener) *Sub

type MessagePin struct {
    Principal        string
    KeyFingerprint   string
    FirstSeenMs      int64
    LastConfirmedMs  int64
    Verified         bool     // set only by MarkVerified; NO badge is rendered from this in v1
    ChangePending    bool     // true while a KeyChangeWarning is unacknowledged
}

type KeyChangeWarning struct {
    Principal          string
    OldKeyFingerprint  string
    NewKeyFingerprint  string
    ChangedAtMs        int64
    EvidenceClass      string   // "kt_inclusion" | "operator_assertion" | "unsigned"
    SharedGroupIds     *StringList
}
```

`EvidenceClass` carries MASTER Â§5.5's requirement that an operator-driven identity reset be visible
as such. `"operator_assertion"` means the operator asserted the new key and no prior key signed it â€”
which is precisely the shape of the key-substitution attack, and the UI must say so.

There is **no verified badge in v1** (MASTER I4/Â§10.2). `MessagePin.Verified` exists for a future
release and for the "you verified this on 3 March" line in a contact detail sheet; Spec C must not
render it as a badge in a message list. Stated here because it is the kind of decision that gets
quietly reversed by a UI ticket.

Key-transparency: every resolution requires an inclusion proof; signed tree heads are gossiped over
two paths (message server and peer clients). `sdk/message_kt.go` refuses a resolution with no proof
and surfaces `KtProofMissing`, which is a hard failure, not a warning.

### 7.7 Listeners

One-method interfaces, matching the existing sdk convention, so the cgo generator maps each to a
single C function pointer.

```go
type SyncListener      interface { SyncStateChanged(state *SyncState) }
type GroupListener     interface { GroupChanged(event *GroupEvent) }
type MessageListener   interface { MessageChanged(event *MessageEvent) }
type KeyChangeListener interface { KeyChanged(warning *KeyChangeWarning) }
type SendCallback      interface { SendResult(result *SendResult, err error) }
type GroupCallback     interface { GroupResult(result *GroupResult, err error) }
type RestoreCallback   interface { RestoreProgress(progress *RestoreProgress, err error) }
type DownloadCallback  interface { DownloadProgress(progress *DownloadProgress, err error) }
type DeviceLinkCallback interface { DeviceLinkChanged(state *DeviceLinkState, err error) }
type SyncCallback      interface { SyncResult(result *SyncResult, err error) }
```

### 7.8 gomobile constraints

The exported `sdk` surface must obey gomobile's type rules, and the `build/Makefile` bind validation
is a CI gate. In practice:

- Exported functions and methods may use `bool`, `int`, `int8/16/32/64`, `float32/64`, `string`,
  `[]byte`, and named types defined in `sdk`.
- **No maps, no slices of anything but `byte`.** Hence `*MessageEntryList` etc., following the
  existing sdk `*List` pattern.
- **No generics** in exported signatures.
- Multiple returns only as `(T, error)`.
- Struct fields must themselves be exportable types.
- `time.Time` does not cross; use `int64` unix milliseconds, named `...Ms`.

The cgo generator additionally maps `sdk.Id` to a UUID string and value structs to JSON, so a struct
that cannot marshal to JSON cannot cross the ABI. `TestMessageSurfaceIsExportable` runs the same walk
the generator does and fails on the first unmappable type, so the break shows up in `go test` rather
than in a gomobile build on someone else's machine.

---

## 8. Local persistence and sealing

### 8.1 What is stored

| Data | Store | Sealed | Deleted when |
|---|---|---|---|
| `master_key` children (`identity` priv, `recovery_root`) | keyfile | **yes** | identity reset |
| `device_sig` (Ed25519 leaf key), `device_xwing` (X-Wing seed) | keyfile | **yes** | device removed from all groups |
| MLS group state per (group, epoch) | SQLite `mls_state` | **yes**, per-row blob | `DeleteGroupStateBefore`, epoch window 8 |
| MLS private keys by public key | SQLite `mls_private` | **yes**, per-row | key superseded or leaf removed |
| Pending KeyPackages + their private halves | SQLite `mls_keypackage` | **yes** | Welcome consumed, or 30-day lifetime expiry |
| `eph_root[n]` | SQLite `eph_root`, inside the epoch state row | **yes** | window closes, or epoch falls out of the window |
| Record ciphertext (as received) | SQLite `record` | no â€” it is already ciphertext | retention class + `expire_at` |
| Decrypted display cache (text, sender, timestamps) | SQLite `entry` | **yes**, one blob per group | group left, message deleted, disappearing timer |
| Attachment blobs | files under `StorageDir/media/` | file body encrypted under the message's class key | MEDIA retention, 1 month default |
| TOFU pins, KT tree heads | SQLite `pin`, `kt_head` | no (public data), but integrity-MAC'd | never |
| `stream_index` high-water marks | SQLite `stream`, `PRAGMA synchronous=FULL` on that table's writes | no | never |
| Fetch attestations covering the high-water range | SQLite `attestation` | no | superseded by a wider covering attestation |
| Server-advertised limits, `server_nonce` | memory only | â€” | reconnect |

Path layout under `MessageClientSettings.StorageDir`:

```
StorageDir/
  urmessage.db            SQLite
  urmessage.db-wal        WAL
  keys.sealed             DPAPI blob: master children + device keys
  entropy.bin             32 B random, created on first run, 0600 / owner-only ACL
  media/<groupId>/<blobId>
```

### 8.2 The store interface

```go
// sdk/message_store.go
type MessageStore interface {
    Open(dir string, sealer Sealer) error
    Close() error

    PutRecords(groupId []byte, records [][]byte) error
    RecordsAfter(groupId []byte, afterRecordId []byte, limit int) ([][]byte, error)
    DeleteRecords(groupId []byte, recordIds [][]byte) error

    PutEntries(groupId []byte, entries []StoredEntry) error
    EntriesBefore(groupId []byte, beforeId string, limit int) ([]StoredEntry, error)
    EntryById(groupId []byte, id string) (StoredEntry, error)
    SearchEntries(query string, limit int) ([]StoredEntry, error)
    DeleteEntries(groupId []byte, ids []string) error
    ExpireEntriesBefore(nowMs int64) (int, error)

    ReserveStreamIndex(groupId []byte, class uint8, index uint64) error
    StreamHighWater(groupId []byte, class uint8) (uint64, error)

    Vacuum() error
}
```

Fourteen methods. That bound is the point (A8): if `modernc.org/sqlite` has to go, this is what has to
be reimplemented.

### 8.3 Sealing

```go
// sdk/message_seal.go
type Sealer interface {
    Seal(context string, plaintext []byte) ([]byte, error)
    Unseal(context string, sealed []byte) ([]byte, error)
    Description() string    // shown in the security settings screen, verbatim
}
```

**Windows (`message_seal_windows.go`, build tag `windows`):** DPAPI via
`golang.org/x/sys/windows.CryptProtectData` / `CryptUnprotectData` â€” already in `sdk`'s pinned
dependency set, no new module.

| Parameter | Value |
|---|---|
| Scope | **User** (no `CRYPTPROTECT_LOCAL_MACHINE`) â€” a machine-scope blob is readable by every account on the box |
| Flags | `CRYPTPROTECT_UI_FORBIDDEN` â€” the DLL may be called from a background thread and must never raise UI |
| Optional entropy | the 32 bytes in `entropy.bin`, mixed with a per-context label so a blob sealed for `"mls_state"` cannot be unsealed as `"keys"` |
| `promptStruct` | nil |
| Description | `"URmessage local key material"` |

`Description()` returns
`"Protected by Windows DPAPI for your user account. This protects your messages from other accounts on this PC and from someone reading the disk. It does not protect against software running as you."`
Spec C renders that string verbatim. It is a factual limit of DPAPI and MASTER Â§13's honesty standard
applies to it.

**Other platforms:** `message_seal_portable.go` derives a key from a platform keystore where one
exists (macOS Keychain via `security`, Linux via the Secret Service where present) and otherwise
falls back to a 0600 keyfile with a loud `Description()` saying the material is protected by file
permissions only. Mobile lands with the platform keystores in slice 7+.

The entropy file is created with an explicit owner-only DACL on Windows (not just `0600` semantics,
which Go maps loosely on NTFS). `TestEntropyFileAcl` asserts the DACL on Windows CI.

### 8.4 Deletion actually deleting

Three mechanisms, because SQLite `DELETE` alone leaves page contents in the freelist and the WAL:

1. `PRAGMA secure_delete = ON` at open â€” overwrite deleted content with zeros.
2. `PRAGMA auto_vacuum = FULL` plus an explicit `Vacuum()` after any bulk expiry, so freed pages are
   released rather than retained.
3. `PRAGMA journal_size_limit` bounded and a WAL checkpoint (`TRUNCATE`) after every expiry pass, so
   the WAL does not retain the deleted rows.

`TestExpiredMessageIsUnrecoverable` is the end-to-end proof of MASTER Â§12.1's second guarantee: send
an ephemeral message, advance the clock past its window, close the client, then open the raw DB file
and the raw record store and assert the plaintext, the entry blob, and the `eph_root` are all absent
â€” and assert that a **freshly provisioned** device and a **seedphrase-only** restore both fail to
decrypt it. That single test is the difference between the feature working and the feature being a
UI label.

---

## 9. `URmessageSdk.dll` â€” the cgo export surface

### 9.1 Why it is separate

`sdk/cgo` generates 10,444 lines of `urnet_*` exports by walking the whole `github.com/urnetwork/sdk`
surface, and it carries an ABI baseline test (`sdk/cgo/gen/abi_baseline_test.go`) that fails on any
symbol change. Adding a messaging surface there would (a) put every VPN export in the messaging DLL,
(b) put every messaging export in `URnetworkSdk.dll`, and (c) make any messaging-driven generator
change perturb the VPN ABI baseline â€” a shipped, signed, in-production artifact.

`sdk/cgo-message` is a new module with its own generator, its own `urmsg_` prefix, its own baseline,
and its own `.def`. **VPN builds are untouched.** The two DLLs may both be loaded in one process
(A-ASSUME-2); each has its own Go runtime, and no handle, pointer, or string crosses between them.

### 9.2 Generation

The generator is seeded from `sdk/cgo/gen/gen.go` and keeps its proven mapping model:

- Behavioural objects cross as opaque `uint64_t` handles, released with `urmsg_release`.
- Data structs, lists and maps cross as JSON strings.
- `sdk.Id` crosses as a UUID string; times as `int64` unix milliseconds (0 = none).
- One-method listener interfaces cross as a C function pointer plus `void* user_data`.
- `[]byte` parameters cross as `(const uint8_t*, int32_t)`.
- `[]byte` **results** use the buffer-out pattern (`out`, `inout_len`), hand-written in
  `exports_manual.go`.

Differences from `sdk/cgo/gen`:

| | `sdk/cgo` | `sdk/cgo-message` |
|---|---|---|
| Root walked | whole `sdk` package | only types reachable from `MessageClient` (an explicit allowlist in `gen.go`) |
| Symbol prefix | `urnet_` | `urmsg_` |
| Behavioural types | 30+ view controllers, devices, tunnels | `MessageClient`, `MessageSendTicket`, `MessageDeviceLinkSession`, `Sub` |
| Header | `include/urnetwork_sdk.h` | `include/urmessage_sdk.h` |
| Module def | `urnetwork_sdk.def` | `urmessage_sdk.def` |
| Baseline test | `sdk/cgo/gen/abi_baseline_test.go` | `sdk/cgo-message/gen/abi_baseline_test.go`, independent |

`make generate` regenerates `exports_gen.go`, `callbacks.h/.c`, `include/`, and
`coverage_report.txt`. The coverage report lists every exported symbol and every skipped one with a
reason; a skip with no reason is a generator error.

### 9.3 The C ABI

Core, hand-written in `exports_core.go`:

```c
const char*  urmsg_version(void);
void         urmsg_free_string(char* p);
bool         urmsg_release(uint64_t handle);
int64_t      urmsg_live_handle_count(void);
```

Session lifecycle:

```c
uint64_t urmsg_client_open(const char* settings_json, uint64_t urnet_device_handle, char** out_error);
void     urmsg_client_close(uint64_t client);

bool     urmsg_generate_seedphrase(char** out_phrase, char** out_error);
bool     urmsg_client_create_identity(uint64_t client, const char* phrase, char** out_error);
bool     urmsg_client_has_identity(uint64_t client);
bool     urmsg_client_identity_fingerprint(uint64_t client, char** out_fingerprint);
bool     urmsg_client_start(uint64_t client, char** out_error);
```

`urnet_device_handle` is the one place the two DLLs meet, and they meet **by value, not by pointer**.
Spec C passes the `uint64_t` handle it got from `URnetworkSdk.dll`. `URmessageSdk.dll` cannot resolve
that handle â€” it is an id in the other DLL's registry. So the actual contract is:

> **The messaging DLL does not share objects with the VPN DLL.** `urmsg_client_open` takes a
> `settings_json` that includes the ByJwt, the network space host, and the client id as **strings**,
> obtained by Spec C from `URnetworkSdk.dll` through its normal getters. The messaging DLL constructs
> its own `connect.Client`.

The `uint64_t urnet_device_handle` parameter above is therefore **removed** from the final signature.
It is written here and struck out because "just pass the device handle across" is the first thing
someone will try, and it produces a handle-registry lookup failure at best and a cross-runtime
pointer dereference at worst. Final signature:

```c
uint64_t urmsg_client_open(const char* settings_json, char** out_error);
```

Groups, messaging, devices, verification: one export per Â§7 method, generated. Illustrative:

```c
uint64_t urmsg_client_send_text(uint64_t client, const char* group_id, const char* text,
                                const char* reply_to_id,
                                urmsg_send_cb cb, void* user_data);
char*    urmsg_client_history(uint64_t client, const char* group_id,
                              const char* before_message_id, int32_t limit);   /* json */
uint64_t urmsg_client_add_message_listener(uint64_t client, const char* group_id,
                                           urmsg_message_changed_cb cb, void* user_data);
bool     urmsg_client_identity_public_key(uint64_t client, uint8_t* out, int32_t* inout_len);
```

### 9.4 Memory ownership â€” the whole table, because this is where cgo bugs live

| Crossing | Allocated by | Freed by | Rule |
|---|---|---|---|
| `char*` **returned** by any `urmsg_*` | Go, via `C.CString` (malloc) | **C caller**, via `urmsg_free_string` | Never `free()` it with the CRT directly â€” the DLL and the app may link different CRTs. `urmsg_free_string` frees in the DLL's heap. |
| `char** out_error` | Go, on error only | C caller, via `urmsg_free_string`, **only if non-NULL after the call** | Every fallible export sets `*out_error` to NULL on success. C code must initialize it to NULL and check. |
| `const char*` **passed in** | C caller | C caller | Go copies with `C.GoString` before returning. The DLL never retains the pointer. |
| `const uint8_t*, int32_t` **passed in** | C caller | C caller | Go copies with `C.GoBytes`. Valid only for the duration of the call. |
| `uint8_t* out, int32_t* inout_len` | **C caller** | C caller | Buffer-out pattern: `*inout_len` is always set to the needed size; the copy happens and `true` is returned only when `out != NULL` and the passed capacity suffices. Call twice: once with `out = NULL` to size, once to fill. |
| `uint64_t` handle | Go registry | C caller, via `urmsg_release` (or `urmsg_client_close` for the client) | Ids are **never reused**, so a stale handle can never resolve to a new object â€” it resolves to nothing and the call returns false. |
| `void* user_data` on a listener | C caller | C caller, **after** the `Sub` handle is released and `urmsg_release` has returned | See Â§9.5. This is the ordering that gets got wrong. |
| Bytes handed to a **callback** | Go | nobody â€” borrowed | Valid only for the duration of the callback. C must copy to retain. Mirrors `connect`'s message-pool borrow rule. |
| Go pointers into C | never | â€” | No Go pointer is ever stored in C memory. C function pointers and `void*` stored in Go structs are fine and are what the generated `cAdapter*` types do. |

### 9.5 The callback contract

Generated shape, matching the proven `sdk/cgo` pattern: a `cAdapterXxx` Go struct holding the C
function pointer and `user_data`, plus a `callbacks.c` shim (`urmsg_invoke_xxx`) so cgo can call
through a C function pointer at all.

```go
type cAdapterMessageChanged struct {
    cbMessageChanged C.urmsg_message_changed_cb
    userData         unsafe.Pointer
}

func (self *cAdapterMessageChanged) MessageChanged(event *sdk.MessageEvent) {
    defer cgoGuard("urmsg_message_changed_cb")
    event_ := cJson(event, "urmsg_message_changed_cb")
    C.urmsg_invoke_message_changed(self.cbMessageChanged, self.userData, event_)
    if event_ != nil {
        cStringFree(event_)
    }
}
```

Rules, each of which corresponds to a real failure mode:

1. **Every exported function begins `defer cgoGuard(name)`.** A panic unwinding into C aborts the
   host process with no stack. The guard logs and returns the zero value. `TestEveryExportIsGuarded`
   parses `exports_*.go` and fails if any `//export` function's first statement is not the guard.
2. **Callbacks arrive on an arbitrary Go goroutine, never the UI thread.** Spec C must marshal to the
   dispatcher queue itself. Documented in the header, in the `.hpp` wrapper, and in Spec C Â§.
3. **Callbacks may arrive re-entrantly with respect to the call that registered them.**
   `urmsg_client_add_message_listener` may fire before it returns. The C++ wrapper must not hold a
   lock across registration.
4. **Unregister is synchronous and final.** `urmsg_release(sub)` does not return until no callback is
   executing and none will start. It is implemented with a per-`Sub` `sync.WaitGroup` plus a
   `closed` flag checked inside the adapter under the same lock that `release` takes. Without this,
   `user_data` can be freed while a callback is mid-flight â€” the single most common crash in this
   class of binding.
5. **`user_data` lifetime is: allocate before register, free after `urmsg_release` returns.**
   Stated in the header next to every `_cb` typedef, because rule 4 is worthless if the caller frees
   early.
6. **No callback may re-enter the DLL synchronously on the same goroutine.** A callback that calls
   `urmsg_client_send_text` from inside `MessageChanged` deadlocks against the group command loop.
   The adapter therefore dispatches every listener callback from a dedicated per-`Sub` goroutine with
   a bounded queue (256 events); overflow drops the oldest and sets a `dropped` counter carried in
   the next event. Documented; asserted by `TestCallbackReentrancy`.
7. **Errors are strings, not codes.** `char** out_error` carries `err.Error()`. There is no numeric
   error enum across the ABI, because the set is open and a stale numeric mapping is worse than a
   string. Programmatic cases (key change, gap, retention conflict) come through **events**, which
   are JSON with a stable `kind` field.

### 9.6 Build matrix

| Target | CC | Output |
|---|---|---|
| `windows/amd64` | `x86_64-w64-mingw32-gcc` | `URmessageSdk.dll` + `.h` + `.hpp` + `.def` |
| `windows/arm64` | `aarch64-w64-mingw32-clang` (llvm-mingw) | same |
| `linux/amd64` | `zig cc -target x86_64-linux-gnu.2.35` | `libURmessageSdk.so` |
| `linux/arm64` | `zig cc -target aarch64-linux-gnu.2.35` | same |
| host (dev) | system clang | `libURmessageSdk.dylib`, used by the smoke tests |

Flags mirror `sdk/cgo/Makefile`: `-trimpath -buildmode=c-shared`, `-ldflags "-s -w -X
github.com/urnetwork/sdk.Version=$WARP_VERSION -buildid="`, `GOEXPERIMENT=greenteagc`. The generated
`URmessageSdk.h` from `go build` is deleted; the hand-generated `include/urmessage_sdk.h` ships.

Two smoke tests, both CI gates: `smoke/smoke.cpp` against the raw C ABI, and `smoke/smoke_hpp.cpp`
against the C++ wrapper. Both assert `urmsg_live_handle_count() == 0` at exit, which catches leaked
handles â€” the failure mode that otherwise shows up as a slow memory climb in production.

---

## 10. Binding to `connect`

### 10.1 Frames

Two new `MessageType` values in `connect/protocol/frame.proto`, continuing from 28:

| Value | Name | `Frame.message_bytes` |
|---|---|---|
| 29 | `MessageEnvelope` | marshaled `MessageEnvelope` â€” a clientâ†”message-server request or response |
| 30 | `MessageStreamAck` | marshaled `MessageStreamAck` â€” flow control for large backfills |

```proto
message MessageEnvelope {
    uint64 request_id   = 1;   // client-assigned; correlates response to request
    uint32 op           = 2;   // MessageOp
    bytes  payload      = 3;   // op-specific, encoded by connect/message
    bytes  server_nonce = 4;   // echoed by the client on writes; Â§5.7
}
```

`MessageOp` and the payload encodings are **Spec B's** to define. This spec fixes only the envelope
and the fact that it rides the existing addressed `Send`/`AddReceiveCallback` path, so message
traffic gets the same contract, relay, and per-peer hybrid transit encryption
(`transfer_encrypt.go:378` leads with `tls.X25519MLKEM768`) as everything else.

Older clients ignore unknown message types, so adding 29 and 30 is not a compatibility break.

### 10.2 What `connect` gives us and what it does not

| Need | `connect` | Us |
|---|---|---|
| Addressed client-to-client delivery | `Client.Send`, `SendWithTimeout`, `SendMultiHop`, `AddReceiveCallback` | â€” |
| Reliable ordered delivery within a session | yes, the sequence machinery | â€” |
| Per-peer transit encryption, hybrid PQ | yes | â€” |
| Contracts and billing | `ContractManager.CreateContract`, needs a `ByJwt` | supply the ByJwt from the existing account |
| **Store and forward** | **no â€” verified absent in `transfer.go`** | the message server (Spec B) |
| Push wake-up | no | open item 2 |
| Long-lived provider-terminated contract per (device, message server) | shaping only | MASTER Â§9.6; we request this shape |

### 10.3 Transport identity is not messaging authorization

`server/connect/transport.go:471-501` authenticates a session with `ParseByJwtForAudience` +
`ValidateByJwtState` + a network-membership lookup. There is no challenge-response; `ByJwt` is a pure
bearer token and every check reads a database the operator owns. MASTER Â§4.3.

`sdk/message_transport.go` therefore treats a live `connect` session as evidence of **transport
authorization only**. Every group write carries `write_auth` (Â§5.7), and every message's authenticity
is MLS's (MASTER I5). A code review rule: no function in `sdk/message_*.go` may branch on ByJwt
contents for anything but transport setup and billing display.

---

## 11. Testing strategy and CI gates

### 11.1 Test layers

| Layer | Where | What |
|---|---|---|
| Unit | alongside each file | tree math, codec, key schedule, X-Wing, ratchet |
| KAT / vectors | `connect/mls/*_kat_test.go` | the 16 families (Â§4.2.1), X-Wing draft vectors, our own pinned `StorageRoot` vector |
| Negative | `connect/mls/validation_*_test.go` | the 43 ValSem codes + 2 errata (Â§4.3) |
| Property / fuzz | `connect/mls/*_fuzz_test.go`, `connect/message/*_fuzz_test.go` | the 9 targets (Â§4.4) plus a record-codec target |
| Interop | `connect/mls/interop` | the mlswg harness (Â§4.2.2â€“4.2.4) |
| Integration, in-process | `connect/message/*_integration_test.go` | 3, 10, 50, 500-member groups with a fake delivery service; commit races; out-of-order receipt |
| Integration, cross-repo | `sdk/message_e2e_test.go` | two `MessageClient`s against a real message server binary from Spec B, over a loopback `connect` |
| ABI | `sdk/cgo-message/gen/abi_baseline_test.go`, `smoke/` | symbol stability; handle-leak zero at exit |
| Layering | `connect/layering_test.go`, `sdk/layering_test.go` | the forbidden import edges of Â§2.3 |
| Lint gates | `scripts/check-forbidden.sh` | the grep gates of Â§5.9 |

### 11.2 Tests that exist because a specific property would otherwise silently break

| Test | Property it protects |
|---|---|
| `TestEphRootHasNoDurableInput` | MASTER I4 / Â§8.1 â€” the disappearing guarantee |
| `TestExpiredMessageIsUnrecoverable` | end-to-end version of the same, across server, new device, and seed holder (Â§8.4) |
| `TestStreamIndexNeverReused` | MASTER I7 â€” no nonce reuse, across simulated crashes (Â§5.6) |
| `TestStorageRootKAT` | G1 â€” the `hkdf.Extract` argument order |
| `TestEpochSecretsAreClosed` | MASTER Â§8.2 â€” only the two named secrets are reachable |
| `TestProvisioningBundleHasNoEphemeral` | MASTER I4 |
| `TestEngineSwappable` | Gate 5 â€” the interface has not leaked |
| `TestProfileIsClosed` | Â§3.1 â€” no silent capability expansion |
| `TestValSem400_PastEpochBound` | bounded past-epoch retention, which OpenMLS does not implement |
| `TestEveryExportIsGuarded` | no panic unwinds into C |
| `TestCallbackReentrancy` | Â§9.5 rules 4 and 6 |
| `TestNoForbiddenCrypto` | `GenerateSharedSecret`, `box.Precompute`, `curve25519.ScalarMult` absent |
| `TestEntropyFileAcl` | owner-only DACL on Windows |

### 11.3 Running the suites

`connect` and `sdk` both ship `test.sh`, both zsh, both `-timeout 0 -race`, and `connect/test.sh`
runs timing-sensitive groups first in their own process. Follow the `urnetwork-workspace` skill:
`go test ./...` naively will hang or fail in ways that look like real bugs and are not.

`connect/mls` and `connect/message` have **no timing-sensitive tests** and must keep it that way â€” a
crypto suite that flakes is a crypto suite people start re-running instead of reading. A test that
needs a clock takes an injected `nowMs func() int64`.

The 500-member integration tests are slow (~4 minutes with `-race`). They run in a `-tags large`
build so `./test.sh` stays usable, and unconditionally in CI.

### 11.4 CI jobs

| Job | Repo | Trigger | Blocking |
|---|---|---|---|
| `unit` (`./test.sh`, race) | connect, sdk | every push/PR | yes |
| `vectors` | connect | every push/PR | yes |
| `valsem` | connect | every push/PR | yes |
| `layering` | connect, sdk | every push/PR | yes |
| `forbidden-crypto` | connect, sdk | every push/PR | yes |
| `fuzz-short` (60 s Ã— 10 targets, properties 1â€“2) | connect | every push/PR | yes |
| `mls-interop` (Â§4.2.4) | connect | every push/PR | yes |
| `gomobile-validate` (bind for android+ios, types only) | sdk | every push/PR | yes |
| `abi-baseline` + `smoke` + `smoke_hpp` | sdk | every push/PR | yes |
| `build-matrix` (5 targets, Â§9.6) | sdk | every push/PR | yes |
| `large` (500-member integration) | connect | every push/PR | yes |
| `e2e` (against Spec B's server binary) | sdk | every push/PR | yes |
| `fuzz-long` (4 h Ã— 10, differential vs OpenMLS) | connect | nightly | no (P0 issue on failure) |
| `interop-random` (`deep_random.json`, logged seed) | connect | nightly | no (P0 issue) |
| `interop-public` (`-public` matrix) | connect | nightly | no |
| `peer-image-bump` | connect | weekly | opens a PR |

### 11.5 The gomobile gate

`sdk`'s `build/Makefile` runs `gomobile bind` with a validation step listing expected skips. Messaging
types must produce **no new expected skips**. A type that gomobile cannot export is a design error in
the `sdk` surface, caught at PR time, not at release time when the Android client is being started.

---

## 12. Interfaces OUT

### 12.1 To the message server (Spec B)

**What Spec B imports from us.** `github.com/urnetwork/connect/message`, via the existing
`replace ../` in `server/go.mod`. The exported surface the server may use â€” and **only** this
surface, asserted by a test in Spec B's repo:

```go
func ParseRecord(b []byte) (*Record, error)
func EncodeRecord(r *Record) ([]byte, error)
func VerifyWriteAuth(writeKey []byte, serverNonce []byte, record *Record) bool
func RecordSizeBucketBytes(b SizeBucket) int
func ClassIsPrunable(c RetentionClass) bool
type Record, RecordHeader, RetentionClass, SizeBucket
```

The server gets **no** decryption function, no key-schedule function, and no MLS type. If Spec B ever
needs one, that is a design discussion, not a patch.

**What we require of the server.**

| # | Requirement | Source |
|---|---|---|
| S1 | Accept a record only if `VerifyWriteAuth` passes against the epoch's published verification state | MASTER Â§9.2 |
| S2 | Enforce **monotonic**, not contiguous, `stream_index` per `(group_id, sender_handle, retention_class)` | MASTER Â§8; a refused write must not brick the stream |
| S3 | Accept at most one `is_commit = 1` per `(group_id, epoch)`, first valid wins, never replaced; return the accepted commit to any later submitter | MASTER Â§9.3 |
| S4 | Reject records whose `epoch` is not the current accepted epoch | MASTER Â§9.3 |
| S5 | **Index epoch wrap records by an opaque target handle** so a device or restorer fetches its own wrap in O(1). Device wraps are indexed by `wrap_target_handle` (16 B, derived from `group_handle_key`); recovery wraps by `recovery_handle` (16 B, derived from `recovery_root` alone, so a seed-only restorer can ask for them). Without this a 500-member group makes every join a 2.1 MB download (Â§5.10 E2). | this spec |
| S6 | A commit's record set may reach ~2.1 MB for a 500-member group. The per-record size cap must not reject a legitimate commit; wraps are separate records, so cap them individually, not as a group. | Â§5.10 E2 |
| S7 | Serve `FETCH_ATTESTATION{group_id, requested_range, record_ids_returned[], server_time, server_id, sig}` on every history fetch, signed by the server's long-term Ed25519 key | MASTER Â§9.4 |
| S8 | Advertise: max attachment bytes (default 100 MB), minimum retention it honours per class, max records per fetch, and the `server_nonce` lifetime | MASTER Â§12.2 |
| S9 | Supply a `server_nonce` bound to the connection, rotated at a published interval | MASTER Â§9.2 |
| S10 | Prune by retention class and `expire_at`; retain `ct_head` and `body_hash` when `ct_body` is erased | MASTER Â§8, Â§12.2 |
| S11 | Never create, store, or transmit logs of client commands, transport connections, or a history of deleted records in production | MASTER Â§9.7 â€” an acceptance criterion, not a policy page |
| S12 | Never decrypt; never be consulted on group admission; never satisfy an MLS validity condition | MASTER I1, Â§4.2 |

**What we give the server.** For each epoch, the committer publishes verification state in the commit
record's cleartext: `H(write_key[n])`-derived material sufficient to verify `write_auth` for epoch *n*
without learning `write_key`. The exact construction is `connect/message`'s and is specified in
`writeauth.go`; Spec B calls `VerifyWriteAuth` and does not implement it.

### 12.2 To the Windows messaging client (Spec C)

**What Spec C gets:** `URmessageSdk.dll`, `urmessage_sdk.h`, `urmessage_sdk.hpp` (C++/WinRT-friendly
wrapper over the C ABI, using `nlohmann/json` exactly as the VPN client's wrapper does), and
`urmessage_sdk.def`.

**What Spec C must supply.**

| # | Obligation |
|---|---|
| C1 | A writable per-user directory as `MessageClientSettings.StorageDir`. Not `%PROGRAMDATA%` â€” DPAPI is user-scoped and a shared directory defeats it. |
| C2 | The ByJwt, network space host, and client id as strings in `settings_json`. **Not** a handle from `URnetworkSdk.dll` (Â§9.3). |
| C3 | Marshal every callback to the UI dispatcher. Callbacks arrive on Go goroutines. |
| C4 | Free every returned `char*` with `urmsg_free_string`; never with the CRT `free`. |
| C5 | Free `void* user_data` only after `urmsg_release(sub)` has returned. |
| C6 | Call `urmsg_client_close` before process exit, and assert `urmsg_live_handle_count() == 0` in debug builds. |
| C7 | Render `Sealer.Description()` verbatim in the security screen. |
| C8 | Render the required UI language of MASTER Â§12.4 verbatim for disappearing, delete-for-everyone, and the durable default. Never say "gone forever" for the durable class. |
| C9 | Render `Kind == "gap"` entries visibly, with the reason. Do not hide them. |
| C10 | Treat `KeyChangeWarning` as **blocking** â€” the SSH changed-host-key shape (MASTER Â§10.2). No verified badge (Â§7.6). |
| C11 | Never persist the seedphrase. Display once, confirm, discard. |
| C12 | No administrator tunnel, no privileged service, no WFP, no wintun, no LocalSystem, no mTLS loopback RPC. This app forwards message traffic only. |

**What Spec C must not assume.** That `URmessageSdk.dll` and `URnetworkSdk.dll` share anything. They
share the file system directory layout and nothing else â€” no handles, no pointers, no strings, no Go
runtime.

### 12.3 To the operator (`/server`, MASTER slice 9)

Out of scope for all three specs, listed so it is not lost: a discovery directory mapping
`principal â†’ identity master key`, published to an append-only key-transparency log over a Merkle
prefix tree, serving inclusion proofs and signed tree heads (MASTER Â§10.1). `sdk/message_kt.go` is
written against this and fails closed until it exists; in slices 1â€“8 it runs against a local test
log, and `MessagePin.EvidenceClass` reports `"unsigned"`, which the UI must show.

---

## 13. Slice sequencing for this spec

Refines MASTER Â§14 for the A-component only.

| # | Slice | Contents | Done when |
|---|---|---|---|
| A1 | `connect/mls/syntax` | codec, varint, vectors, optional | family 16 passes; fuzz properties 1â€“2 clean for 60 s Ã— 3 targets |
| A2 | `connect/mls` crypto + tree | `crypto.go`, `hpke.go`, `tree_math.go`, `tree.go`, `tree_hash.go` | families 1, 2, 9, 10 pass |
| A3 | `connect/mls` schedule + framing | `key_schedule.go`, `secret_tree.go`, `framing.go`, `transcript.go` | families 3, 4, 5, 6, 7 pass |
| A4 | `connect/mls` group | `treekem.go`, `proposal.go`, `commit.go`, `group.go`, `validation.go`, `profile.go` | families 8, 11, 12, 13, 14, 15 pass; **Gate 1 and Gate 3 green** |
| A5 | `connect/mls/interop` | our gRPC client, vendored proto, CI job | **Gate 2 green**, both roles, three peers |
| A6 | `connect/message` | records, key schedule, X-Wing, ratchet, wraps, `write_auth`, tombstones, padding, COVER | wire format frozen; E1â€“E3 resolved; `TestStreamIndexNeverReused` and `TestEphRootHasNoDurableInput` green |
| A7 | `sdk` client core | `MessageClient`, store, sealer, KT client, sync loop, transport binding | two clients exchange a message against Spec B's server in `e2e` |
| A8 | `sdk/cgo-message` | generator, exports, header, `.hpp`, smoke tests, build matrix | Spec C can build against the header; handle count zero at exit |
| A9 | Disappearing, multi-device, attachments | `eph.go`, provisioning, blob handling | `TestExpiredMessageIsUnrecoverable` green |
| A10 | Fuzz hardening + audit prep | differential oracle, 14 clean nightlies, audit brief | **Gate 4 green**; Gate 6 scheduled |

A1â€“A5 are the schedule risk, and they are first because each has an objective completion test.
A1â€“A8 produce something two people can text on.

---

## 14. Open items (consolidated)

| # | Item | Owner | Blocks |
|---|---|---|---|
| 1 | E1 â€” recovery wrap must carry `storage_root[n]`, not `pq_secret[n]` (Â§5.10) | MASTER owner | slice A6 |
| 2 | E2 â€” epoch snapshot must be one record, not per-target (Â§5.10) | MASTER owner | slice A6 |
| 3 | E3 â€” X-Wing recovery key derivation is 32 bytes, not 96 (Â§5.10) | MASTER owner | slice A6 |
| 4 | A-ASSUME-1 â€” `modernc.org/sqlite` in `sdk` | project owner | slice A7 |
| 5 | A-ASSUME-2 â€” two Go runtimes in one Windows process | Spec C + project owner | slice A8 |
| 6 | A-ASSUME-4 â€” `PrivateMessage`-only handshake policy | project owner | slice A4 |
| 7 | Skipped-key window size and per-group memory budget (Â§5.5) | Spec C | slice A6 |
| 8 | Retention floor negotiation behaviour (MASTER open item 1) | MASTER owner | slice A7 |
| 9 | Push transport / WNS wake-up (MASTER open item 2) | Spec B + Spec C | post-A8 |
| 10 | `OWNER_SUCCESSOR_SET` extension placement (MASTER open item 4) | MASTER owner | V2 |
| 11 | Transcribe RFC 9420 errata 8745 and 8815 verbatim into `connect/mls/ERRATA.md` (Â§4.3) | implementer | slice A4 |
| 12 | `MessageOp` codes and envelope payload encodings | Spec B | slice A7 |
