# URmessage Spec A — Protocol, SDK and Connect

**Component:** `connect/mls`, `connect/message`, `sdk` client core, `URmessageSdk.dll`
**Branch:** `beta/message` on `Ryanmello07/urnetwork-connect` and `Ryanmello07/urnetwork-sdk`
**Date:** 2026-08-12
**Revision:** A-3 (R5 convergence pass: `blob_id` in the header and both preimages; `req_auth` re-keyed to a group-lifetime `read_key`; the SDK surface Spec C calls fully declared)
**Status:** Design, pending owner review
**Normative parent:** `docs/specs/2026-08-12-urmessage-protocol-design.md` (revision 6), hereafter **MASTER**
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
| MASTER protocol design | Revision 6, awaiting owner review |
| This spec | Revision A-3, R5 convergence pass applied |
| Code | None. `beta/message` branches not yet cut. |
| Go toolchain | 1.26.5, verified on the build host (`go version` → `go1.26.5`) |
| `crypto/mlkem` | Verified present: `NewDecapsulationKey768(seed)` takes a **64-byte** `d ‖ z` seed |
| `crypto/sha3` | Verified present: `SumSHAKE256(data, length)`, `Sum256` — X-Wing is stdlib-only |
| `crypto/hkdf` | Verified present: `Extract[H](h, secret, salt)` — **note the argument order**, see §5.9 |
| `golang.org/x/sys/windows` | Already pinned at v0.46.0 in `sdk`; exposes `CryptProtectData`/`CryptUnprotectData`. DPAPI needs **no new dependency**. |
| MLS reference corpus | `mls_measure/` holds pinned OpenMLS 0.9.0-rc.1, mlspp, the mlswg `mls-implementations` harness, and a Go implementation used only as a shape reference |

### 0.2 Decisions specific to this component, and why

| # | Decision | Reasoning |
|---|---|---|
| A1 | MLS lives in `connect/mls/`, storage in `connect/message/`, client core in `sdk` | Follows MASTER §14 slices. `connect` is the cross-platform layer that already builds everywhere gomobile goes; `sdk` is the product surface. |
| A2 | `connect` (the parent package) **never** imports `connect/mls` or `connect/message` | `connect/CODESTYLE.md` "Package layering": a package must never import its own subpackages. `connect/message` may import `connect` and its peer `connect/mls`; the reverse is forbidden. This is enforced by a CI test (§11.4). |
| A3 | The narrow swappable interface is declared **at each consumer**, not in a shared interface package | Go satisfies interfaces structurally, so one engine implementation satisfies both `message.GroupEngine` and `sdk.MlsEngine` with no import edge between them. A shared `mlsiface` package would be a child both parents import — exactly the inversion A2 forbids. The **swap point** (which implementation is constructed) is in `sdk`, which is where the product decides. |
| A4 | X-Wing, HPKE, and the MLS ciphersuite are implemented on Go stdlib primitives only — no third-party crypto | Verified feasible: `crypto/mlkem`, `crypto/ecdh`, `crypto/hkdf`, `crypto/sha3`, `chacha20poly1305` from the already-pinned `golang.org/x/crypto`. Zero new crypto dependency, zero Rust or C in CI, and `sdk` stays gomobile-buildable. |
| A5 | The TLS presentation-language codec is written once in `connect/mls/syntax` and used by `connect/message` too | MLS signs over serialized forms, so encode/decode must be byte-exact and round-trip stable. One codec, one fuzz corpus, one class of bug. |
| A6 | The OpenMLS differential oracle runs **out of process**, over a stdio/gRPC boundary, only in CI | Keeps "read-only oracle, never a dependency" literal: OpenMLS is never in `go.mod`, never linked, never present in a shipped artifact. Its `StorageProvider<const VERSION: u16>` cannot cross a C ABI anyway (measurement pass). |
| A7 | `URmessageSdk.dll` is a **new** cgo `c-shared` module at `sdk/cgo-message/`, with its own generator and its own `urmsg_` symbol prefix | The existing `sdk/cgo` generator walks the whole `github.com/urnetwork/sdk` surface and emits 10,444 lines of `urnet_*` exports. Reusing it would put the VPN surface in the messaging DLL and vice versa, and any messaging-driven generator change would perturb `URnetworkSdk.dll`'s ABI baseline. Separate module, separate baseline, separate symbol namespace, **zero** risk to VPN builds. |
| A8 | Local message store is SQLite via `modernc.org/sqlite` (pure Go, no cgo) behind a 14-method `sdk.MessageStore` interface | The store needs indexed pagination, per-group cursors, and text search. Hand-rolling that is a large, bug-dense surface. `modernc.org/sqlite` is pure Go and gomobile-buildable. **Marked as an assumption to confirm — see §0.5 A-ASSUME-1.** The interface is deliberately narrow so replacing it is a contained job. |
| A9 | Record ciphertext is stored **as ciphertext** in the local DB; only key material is DPAPI-sealed | No SQLCipher, no encrypted-DB dependency. The DB holds what the server holds plus decrypted-for-display text; the display cache is sealed as one blob per group per §8.3. |
| A10 | Transport uses the existing `connect.Client` addressed send/receive path with four new `MessageType` frame codes in the reserved 1000-1099 block (§10.1) | `connect/transfer.go` already provides `Send`/`SendWithTimeout`/`AddReceiveCallback`. We add framing, not a transport. Confirmed no store-and-forward exists in `connect` — durability is the message server's job (Spec B). |
| A11 | Every exported ABI function is panic-guarded and every handle is registry-allocated with non-reusable ids | Copied deliberately from the proven `sdk/cgo/handles.go` design: a panic unwinding into C aborts the host process, and a reused handle id resolves a stale pointer to a live object. |
| A12 | `URmessage.exe` loads **`URmessageSdk.dll` only**. `URnetworkSdk.dll` is never loaded into the messaging process. `URmessageSdk.dll` therefore also exports the URnetwork account surface the messaging client needs, under the `urmsg_auth_*` prefix. | Two Go runtimes in one process means two `DLL_PROCESS_ATTACH` error-mode mutations, two signal-handler installations and two `SetUnhandledExceptionFilter` chains in the process that owns the UI (§14.1 trap 4 in Spec C is about exactly one of them), plus doubled resident memory — for the sole purpose of moving three strings across a DLL boundary. One runtime removes the problem instead of documenting it. VPN builds remain untouched: `URnetworkSdk.dll` is not modified. |

### 0.3 Interfaces to the other two components

| Direction | Contract | Detail |
|---|---|---|
| A → B | Record wire format, `write_auth`, wrap indexing, commit-agreement semantics | §12.1 |
| B → A | Server-advertised limits, fetch attestation, epoch verification state | §12.1 |
| A → C | `URmessageSdk.dll` C ABI: handles, callbacks, memory ownership | §9, §12.2 |
| C → A | Storage root path, network space host, message server client id, foreground/background lifecycle, WNS channel URI. **Not** a ByJwt at construction and **not** a handle from another DLL — A owns login (A12). | §12.2 |
| A ↔ B | Both depend on `connect/message` for the record codec; the server imports it via `replace ../` and on `connect/protocol/message.proto`, which A owns and B's arms populate (§10.1). | §2.4 |

### 0.4 Open items

Open items are consolidated in §14, with stable numbers. There is no second list.

### 0.5 Assumptions to confirm

| Id | Assumption | Blast radius if wrong |
|---|---|---|
| A-ASSUME-1 | `modernc.org/sqlite` is acceptable in `sdk` despite being ~6 MB of transpiled C-as-Go, and builds under gomobile for `android/arm` (32-bit) | Contained: `sdk.MessageStore` is 14 methods. Fallback is a segment-log + index store, roughly 3 engineer-weeks. |
| A-ASSUME-3 | **CONFIRMED, not an assumption.** X-Wing is pinned at `draft-connolly-cfrg-xwing-kem-06` semantics: a **32-byte** seed, expanded internally to 96 bytes with SHAKE-256, SHA3-256 combiner. | MASTER §5.2 already derives a 32-byte seed. There is nothing to rule on. |
| A-ASSUME-4 | v1 groups use `PrivateMessage` wire format for **all** handshake messages (no `PublicMessage` on the wire) | Simplifies the profile and removes the membership-tag path from production. `PublicMessage` is still implemented because the interop harness and ValSem007/008 require it; it is refused by policy at the group config. |
| A-ASSUME-5 | The message server is trusted to be the single Delivery Service, so `connect/message` implements no client-side commit-conflict resolution beyond re-derive-and-retry | MASTER §9.3. If multi-server lands in V2 this becomes a real distributed-consensus problem. |

### 0.6 Edit log

Append-only. Newest last. One entry per commit that changes this spec. Every change follows
`SPEC-LEDGER.md` §6: edit → subagent diff review → fix → commit with ledger entry → append here.

<!-- entries begin -->

| Date | Revision | Change |
|---|---|---|
| 2026-08-12 | A-2 | R4 review pass. File re-encoded from double-encoded UTF-8 to clean UTF-8, no BOM, LF. Wire binding adopted from Spec B and `MessageEnvelope`/`MessageOp`/`MessageStreamAck` deleted. `server_attachment` adopted, §5.11 added. `H(write_key)` language struck; the server holds `write_key`. Retention-class wire byte fixed to `0x10 \| bucket`. `stream_index` scoped to `(group_id, sender_handle)`. `record_id` made a 1-based `uint64`. `req_auth` added for reads; Ed25519 recovery proof. Epoch publication sequence and wrap indexing. `expire_at` fixed to milliseconds, may only shorten. Fetch attestation covers `class_mask`/`heads_only`. `server_nonce` per connection, never rotated. One exported-surface table. Evidence classes closed, `self_signed_rotation` reserved. `"delivered"` deleted. `RevealSeedphrase` added. One Go runtime, decision A12. `CanSend`/health/`SyncState` vocabularies added. Key-change scope split DM/group. Retention negotiation ruled warn-and-proceed. Interfaces-out table added. Event drop counter and sequence. §5.12 (losing committer) and §5.13 (blobs) added. |
| 2026-08-12 | A-3 | R5 convergence pass. `blob_id` added to `RecordHeader` and to both preimages. `req_auth` re-keyed from the epoch `write_key` to a group-lifetime `read_key`, carried in `EpochAttachment` and delivered to joiners in the `Welcome`; `WrapFetch` added to the authorized-read set with op byte 19. `MessageInvite`, `MessageReaction`, `MessageReceipt` and `MessageHistoryGrant` defined. `Retry`, `SetDisappearing`, `SetGroupMuted`, `SetGroupNotificationMode`, `GrantHistory` and `HistoryGrants` added. `MessageRetentionApplied` moved to seconds to match the wire. `write_auth` declared zero on read. MIME authority ruled to `connect/message`. Epoch-bundle sizing recomputed against the padded ladder. Interfaces-out rows A-11 and A-12 added. Open-item numbering unified on §14. All internal edit-plan labels replaced with real section references. |

---

## 1. Scope

**In scope for this spec:** the RFC 9420 implementation; the storage record layer; the post-quantum
wrap composition; the client core (group state machine, local store, key-transparency client, device
provisioning); the `sdk` API surface; the `URmessageSdk.dll` C ABI; local persistence and sealing;
the test strategy and CI gates for all of the above.

**Out of scope:** anything the message server does (Spec B); anything WinUI 3, XAML, packaging, or
installer (Spec C); the operator's discovery directory and KT log server side (MASTER §14 slice 9).

**Cross-platform obligation.** Everything in `connect/mls`, `connect/message`, and `sdk` MUST build
for `windows/{amd64,arm64}`, `linux/{amd64,arm64}`, `darwin/arm64`, `android/{arm64,arm,amd64}`, and
`ios/arm64` from the first commit. No cgo outside `sdk/cgo-message/`. No build tags on the crypto.
The gomobile `bind` validation in `sdk/build/Makefile` is a CI gate (§11.5), so a type that gomobile
cannot export is a build break, not a warning.

---

## 2. Branch, repository and module layout

### 2.1 Branches

| Repo | Branch | Base | Parallel to |
|---|---|---|---|
| `Ryanmello07/urnetwork-connect` | `beta/message` | `origin/main` | `beta/algorithm-dpi`, `beta/custom-server` |
| `Ryanmello07/urnetwork-sdk` | `beta/message` | `origin/main` | same |
| `Ryanmello07/urnetwork-message-server` | `main` | — | Spec B |
| `Ryanmello07/urnetwork-windows-message` | `main` | — | Spec C |

`beta/message` is long-lived. Feature branches target it and are cherry-picked to `-upstream`
branches per the `urnetwork-upstream-pr` workflow only when a change is genuinely generic (for
example a codec fix in `connect/mls/syntax` is not; a `connect` bug found while building on it is).

**MLS and the message layer are NOT proposed upstream in v1.** They are a product, not a transport
improvement. Sending 25k lines of new crypto to `urnetwork/connect` is not a reviewable PR.

### 2.2 Package tree

```
connect/                                   (existing; never imports its own children)
  protocol/frame.proto                     + MessageType 1000-1003  (§10.1)
  protocol/message.proto                   URmessage control plane; A owns the file,
                                           B owns the oneof arms  (§10.1)
  mls/                                     RFC 9420. peer-importable, imports only stdlib + x/crypto
    syntax/                                TLS presentation language codec (§5.8)
      decode.go  encode.go  varint.go  optional.go  vector.go
    suite.go                               ciphersuite registry; v1 = 0x0003 only
    crypto.go                              CryptoProvider: KDF, AEAD, sig, hash
    hpke.go                                RFC 9180 DHKEM(X25519,HKDF-SHA256) + ChaCha20Poly1305
    tree_math.go                           §4 node/leaf index arithmetic
    tree.go  tree_hash.go  tree_sync.go    ratchet tree, parent hashes, tree validation
    treekem.go                             UpdatePath encrypt/decrypt, path secrets
    leaf_node.go  key_package.go           §7.2 / §10, with urmessage_leaf_keys (§3.4)
    credential.go                          BasicCredential only
    framing.go                             FramedContent, AuthenticatedContent, Public/PrivateMessage
    secret_tree.go                         §9 sender ratchets, generation windows
    key_schedule.go                        §8 epoch secrets, exporter, PSK secret
    transcript.go                          confirmed/interim transcript hashes
    proposal.go  commit.go                 proposal list validation, commit application
    group.go                               the state machine; the only stateful exported type
    validation.go                          every ValSem check, one named func per code
    errors.go                              typed errors, one per ValSem code
    profile.go                             the v1 profile gate (§3.1)
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
    xwing.go                               X-Wing KEM (§5.4)
    wrap.go                                epoch wraps: device leaves, recovery targets, snapshot
    writeauth.go                           write_auth and req_auth MACs (§5.7)
    recovery.go                            Ed25519 recovery proof (§5.7)
    attachment.go                          server_attachment encoding (§5.11)
    handle.go                              sender_handle, recovery_handle, wrap_target_handle
    pad.go                                 size buckets, COVER records
    engine.go                              the GroupEngine interface (§6) + the connect/mls adapter
    tombstone.go                           TOMBSTONE construction and verification
    eph.go                                 eph_root, buckets, window expiry
    errors.go
sdk/                                       (existing)
  message.go                               MessageClient — the product surface (§7)
  message_group.go  message_device.go  message_verify.go  message_attachment.go
  message_events.go                        listener interfaces and event structs
  message_store.go                         MessageStore interface (§8.1)
  message_store_sqlite.go                  the v1 implementation
  message_seal.go                          Sealer interface + portable fallback
  message_seal_windows.go                  DPAPI (build tag windows)
  message_mls.go                           MlsEngine interface + the swap point (§6)
  message_kt.go                            key-transparency client, pinning, TOFU (§7.6)
  message_sync.go                          server sync loop, fetch attestations, backfill
  message_transport.go                     connect.Client binding (§10)
  cgo-message/                             NEW module: URmessageSdk.dll (§9)
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
sdk  ──imports──▶  connect/message  ──imports──▶  connect/mls  ──imports──▶  connect/mls/syntax
 │                        │
 └──imports──▶  connect ◀─┘
```

Forbidden edges, each asserted by a test in `connect/layering_test.go` and `sdk/layering_test.go`
that walks `go list -deps`:

- `connect` → `connect/mls` or `connect/message` (A2)
- `connect/mls` → `connect` or `connect/message` (MLS must be a self-contained crypto library, so it
  can be audited and fuzzed without the transport)
- `connect/mls/syntax` → anything but stdlib
- `connect/message` → `sdk`

### 2.4 Modules and dependency policy

`connect/mls/interop` is a **separate Go module** (`connect/mls/interop/go.mod`) so that gRPC,
protobuf, and the mlswg proto never enter `connect`'s dependency graph and therefore never enter
`sdk`, the DLL, or the mobile AARs. It is built only by the CI interop job.

New dependencies permitted in `connect` on `beta/message`: **none.**
New dependencies permitted in `sdk` on `beta/message`: `modernc.org/sqlite` only (A-ASSUME-1).

`server/go.mod` (Spec B) already imports `connect` and `sdk` via local `replace ../` directives.
Spec B consumes `connect/message` through that same replace. The record codec has exactly one
implementation, shared by client and server, and the wire message is shaped to make that literally
true rather than merely intended:

On **submit**, the server calls `message.ParseRecord(record_bytes)`, verifies every projection field
equals the parsed value, verifies `write_auth`, and stores the record **decomposed** into columns.
On **read**, the server rebuilds `record_bytes` by calling `message.EncodeRecord` over the stored
columns — with `ct_body` nil when the body has been erased or when `heads_only` is set — and sets
`record_id`. There is exactly one encoder and one parser in the system, and the server links the same
Go code the client does.

`write_auth` is **zero on read**. It is a MAC over the submitting connection's `server_nonce`, which
is scoped to that connection and meaningless to anyone else, so there is nothing to reconstruct and
nobody who could verify it. `EncodeRecord` accepts a zero `WriteAuth` and `ParseRecord` never rejects
one. A client MUST NOT verify `write_auth` on a fetched record: record authenticity is MLS's, per
MASTER I5, and a client that treated a server-rebuilt MAC as evidence would be trusting the server
to vouch for content.

---

## 3. `connect/mls` — the RFC 9420 implementation

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
| Lifetime enforcement on KeyPackages | yes, ±1h clock skew tolerance | `key_package.go:Validate` |
| Max group size | no hard cap; design target 500 (ledger P4). A soft warning fires above 1000 leaves | `group.go` |
| Delivery service | ours, strongly consistent (MASTER §9.3) | `connect/message` |

### 3.2 Deliberately not implemented, and what happens instead

| RFC 9420 feature | v1 | Behaviour on receipt |
|---|---|---|
| External commits (§12.4.3.2) | no | `ErrProfileExternalCommit`, message dropped, warning logged, sender not trusted further this epoch |
| External senders extension (§12.1.8.1) | no | `ErrProfileExternalSender` at group-context validation; commit refused |
| PreSharedKey proposals (§12.1.5) | no | `ErrProfilePSK` at proposal parse |
| ReInit (§12.1.6) | no | `ErrProfileReInit` |
| Branching / subgroups (§11.2) | no | `ErrProfileBranch` |
| `x509` credentials (§5.3.2) | no | `ErrProfileCredentialType` |
| Ciphersuites other than 0x0003 | no | `ErrProfileCiphersuite` |
| `application_id` leaf extension | no | ignored if not in `required_capabilities`; refused if required |
| GREASE values (§13.2) | **parsed and ignored**, never generated | must not error — interop harness sends them |

**Every one of these still needs a negative test.** Narrowing the profile does not remove the
obligation to test ValSem240–246 and ValSem401–403; it changes the expected outcome from "the RFC's
specific check fires" to "the profile gate rejects the whole message before the check is reached."
Both are asserted, and the test asserts *which* error surfaced, so a future accidental implementation
of external commits turns the test red rather than green. See §4.3.

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
    HashSize() int                                       // KDF.Nh — 32
    KeySize() int                                        // AEAD.Nk — 32
    NonceSize() int                                      // AEAD.Nn — 12
    Hash(data []byte) []byte
    Mac(key, data []byte) []byte                         // HMAC-SHA256
    MacVerify(key, data, tag []byte) bool                // constant time
    Extract(salt, ikm []byte) []byte                     // ARGUMENT ORDER IS (salt, ikm) — §5.9
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
// the MLS group state machine. NOT safe for concurrent use — the caller
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
func (self *Group) EpochSecret(name EpochSecretName) ([]byte, error)   // §3.4
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

`EpochSecretName` is a **closed** enum, deliberately. MASTER §8.2 needs exactly
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
// be able to ask for them. See MASTER §8.2.
```

### 3.4 Leaf and group extensions

```go
// leaf_node.go
// urmessage_leaf_keys, extension type 0xF002. MASTER §5.3.
// carried in the LeafNode so it is covered by the leaf signature and the tree
// hash, validated by RFC 9420 §7.3, and removed by Remove with the rest of the leaf.
type LeafKeysExtension struct {
    AlgId          uint16   // 0x0014 = X-Wing (X25519 + ML-KEM-768)
    DeviceXwingPub []byte   // 1216 bytes for alg 0x0014
}

// urmessage_group_policy, extension type 0xF001. MASTER §6.
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
This means a client that does not understand `urmessage_leaf_keys` cannot be added — which is exactly
right, since a member with no X-Wing key cannot receive the epoch wrap and would silently lose
history at the next commit.

### 3.5 The state store

MLS state must survive process restart, and the epoch secrets in it are the crown jewels. The
interface is deliberately dumb — no queries, no transactions across groups — so `sdk` can implement
it over the sealed local store (§8) without leaking storage semantics into the crypto.

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
MASTER §8.1's disappearing-message guarantee real: `eph_root[n]` lives in the epoch state, and a
retained old epoch state is a retained `eph_root`. The store implementation MUST overwrite before
unlinking where the platform allows it, and MUST NOT rely on SQLite `DELETE` alone (which leaves the
page contents in the freelist). See §8.4.

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

MASTER §6 and §14 state the acceptance criterion as "the IETF test vectors pass." **A measurement
pass established that this is inadequate** and the criteria below supersede it. The evidence, not
restated here: the 16 vector families are ~6,158 lines against 40,181 lines of behavioural tests in
OpenMLS (~13% of the corpus); they test **none** of the 43 ValSem validation codes; and six 2026
OpenMLS defects each passed 100% of the vectors.

The revised criteria are six gates. **All six must be green before any non-beta user.** Gates 1–5
must be green before slice 5 (the first testable build).

### 4.1 Gate 1 — the narrow profile is implemented and enforced

§3.1 and §3.2. Verified by `profile_test.go`, which asserts for each row of §3.2 that the named
error surfaces, and by `TestProfileIsClosed`, which asserts the allowed-set tables contain exactly
the documented values (so adding a proposal type without updating this spec breaks the build).

### 4.2 Gate 2 — vectors plus the mlswg gRPC interop harness, both roles, every commit

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
catches the class of bug where encoder and decoder are wrong in the same direction — which
verification alone cannot see, because the vector never round-trips through our encoder.

Family 6 is retained even though PSK proposals are profile-refused: `psk_secret` is computed in the
key schedule on every epoch (as the empty-PSK case), and getting the empty case wrong silently
diverges every epoch secret.

#### 4.2.2 The interop harness

The harness is the mlswg `mls-implementations` gRPC framework: each MLS client is a gRPC **server**
implementing `MLSClient`; a Go **test runner** drives them and assigns actors (`alice`, `bob`,
`charlie…`) to clients. The service has 30 RPCs across group creation, joining, proposals, commits,
external joins, reinit, branching, and free.

**Our client:** `connect/mls/interop/client`, a `package main` gRPC server implementing `MLSClient`
over `mls.Group`. It sits in a separate module (§2.4) so gRPC never reaches the product.

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

#### 4.2.3 Both roles — the part that is usually skipped

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
| `branch.json` | yes | **documented failure** — asserted against `profile-reject.json` |
| `external_join.json` | yes | **documented failure** — asserted |
| `external_proposals.json` | yes | **documented failure** — asserted |
| `reinit.json` | yes | **documented failure** — asserted |
| `deep_random.json` | nightly, with a logged seed | pass |

The "documented failure" mechanism is the important one. `connect/mls/interop/profile-reject.json`
lists, per config, exactly which scenario ids must fail and with what gRPC status and message. The CI
step asserts the observed failure set **equals** the expected set. A scenario that starts passing —
because someone implemented external commits without updating the profile — is a CI failure, not a
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
      # peers, pinned by digest — no source builds on the commit path
      - run: docker compose -f mls/interop/docker-compose.yml up -d --wait
      - run: /tmp/urmessage-mls-client -port 50051 &
      # the runner is vendored at the same pinned mlswg commit as the vectors
      - run: go run ./test-runner ...   # one invocation per row of the §4.2.3 matrix
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
exact bytes that diverged rather than a gRPC status code. This has to be built in from the start —
retrofitting it after the first cross-implementation failure is how a week gets lost.

The pinned mlswg commit is recorded in `connect/mls/interop/PINS.md` alongside the three peer image
digests, and bumping any of them is a PR that must show a green matrix.

### 4.3 Gate 3 — explicit negative tests for all 43 ValSem codes

One test function per code, named `TestValSemNNN_<slug>`, in `connect/mls/validation_test.go` (split
by category into `validation_framing_test.go`, `_proposal_`, `_commit_`, `_external_`, `_psk_`). Each
constructs a group in a valid state, mutates exactly one thing, and asserts the specific typed error.

Per `CODESTYLE.md` §Tests these are top-level functions, not `t.Run` subtests.

**Framing (RFC 9420 §6)**

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

**Proposals covered by a commit (§12.1, §12.2)**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem101 | Add: signature key unique among proposals and members | `ErrDuplicateSignatureKey` |
| ValSem102 | Add: init key unique among proposals | `ErrDuplicateInitKey` |
| ValSem103 | Add: encryption key unique among proposals and members | `ErrDuplicateEncryptionKey` |
| ValSem104 | Add: init key ≠ encryption key | `ErrInitEqualsEncryptionKey` |
| ValSem105 | Add: ciphersuite and version match the group | `ErrSuiteMismatch` |
| ValSem106 | Add: required capabilities satisfied | `ErrMissingRequiredCapability` |
| ValSem107 | Remove: removed member unique among proposals | `ErrDuplicateRemove` |
| ValSem108 | Remove: removed member exists | `ErrRemoveNonMember` |
| ValSem109 | Update: required capabilities | `ErrMissingRequiredCapability` |
| ValSem110 | Update: encryption key unique among proposals and members | `ErrDuplicateEncryptionKey` |
| ValSem111 | Committer must not include its own Update proposals | `ErrSelfUpdateInCommit` |
| ValSem112 | Standalone Update sender must be type `member` | `ErrUpdateSenderNotMember` |
| ValSem113 | Proposal type supported by all members | `ErrUnsupportedProposalType` |

**Commits (§12.4)**

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

**External commits (§12.4.3.2) — profile-refused in v1**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem240 | External commit covers ≥1 inline `ExternalInit` | `ErrProfileExternalCommit` at parse |
| ValSem241 | External commit covers ≤1 inline `ExternalInit` | `ErrProfileExternalCommit` |
| ValSem242 | External commit only covers allowlisted inline proposals | `ErrProfileExternalCommit` |
| ValSem244 | External commit includes no by-reference proposals | `ErrProfileExternalCommit` |
| ValSem245 | External commit contains a path | `ErrProfileExternalCommit` |
| ValSem246 | External commit signature verified with the path KeyPackage credential | `ErrProfileExternalCommit` |

Each of these six tests asserts the profile error **and** carries a commented-out assertion of the
RFC error, so that implementing external commits in V2 is a mechanical swap with the test already
written. (There is no ValSem243; the mlswg numbering skips it. ValSem247 is folded into ValSem010.)

**Ratchet tree (§12.4.3.1)**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem300 | Exported ratchet trees have no trailing blank nodes | `ErrTrailingBlankNodes` |

**PSK (§8.4) — profile-refused in v1**

| Code | Check | v1 expectation |
|---|---|---|
| ValSem401 | `PreSharedKeyID` nonce has length `KDF.Nh` | `ErrProfilePSK` at parse |
| ValSem402 | PSK is Resumption(Application) or External | `ErrProfilePSK` |
| ValSem403 | No duplicate `PreSharedKeyID` in a proposal list | `ErrProfilePSK` |

ValSem403 is **untested in OpenMLS** (tracked as openmls#1335). We test it.

**ValSem400** — the RFC's SHOULD that an application bound the number of past epochs for which
`resumption_psk` is stored — is **not implemented in OpenMLS at all** (tracked as openmls#1122). We
implement it as a hard bound: `StateStore.DeleteGroupStateBefore` is called on every merged commit
with `epoch - PastEpochWindow`, `PastEpochWindow = 8`, and `TestValSem400_PastEpochBound` asserts
that state older than the window is gone from the store. This is not optional politeness — it is the
same deletion that makes MASTER §8.1's ephemeral guarantee true.

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

### 4.4 Gate 4 — differential fuzzing against OpenMLS's 9 targets

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

### 4.5 Gate 5 — MLS sits behind a narrow swappable interface

§6. Verified by `TestEngineSwappable`, which builds the entire `connect/message` and `sdk` test suite
against a second `GroupEngine` implementation — a deterministic in-memory fake that is not MLS at all
— and asserts every test still passes. If a test needs a real MLS behaviour that the interface does
not expose, the interface has leaked and the test fails to compile, which is the signal we want.

### 4.6 Gate 6 — funded external audit before any non-beta user

Scope: `connect/mls` and `connect/message` in full, `sdk/message_*.go`, `sdk/cgo-message`, and the
key schedule end to end. The audit brief includes this document, MASTER, and the ValSem coverage
report. Not schedulable until gates 1–5 are green, because an auditor should not spend budget
finding what a test suite finds.

### 4.7 Release gating

| Gate | Blocks slice 5 (first testable build) | Blocks beta | Blocks GA |
|---|---|---|---|
| 1 profile | yes | yes | yes |
| 2 vectors + interop | yes | yes | yes |
| 3 ValSem 43 + errata | yes | yes | yes |
| 4 fuzz (properties 1–2) | yes | yes | yes |
| 4 fuzz (differential, nightly clean for 14 days) | no | yes | yes |
| 5 swappable interface | yes | yes | yes |
| 6 external audit | no | no | **yes** |

---

## 5. `connect/message` — the storage layer

MASTER §8 defines the record, its AADs, and the key schedule. This section defines the Go types, the
package API, and the invariants the code must carry.

### 5.1 Record types

```go
// record.go
type RetentionClass uint8

const (
    RetentionPermanent RetentionClass = 0
    RetentionDurable   RetentionClass = 1
    RetentionMedia     RetentionClass = 2
    RetentionEph       RetentionClass = 3   // Go-side tag only; see the wire table below
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
// write_auth (MASTER I6, I8). RecordId is in NEITHER — it is server-assigned
// after acceptance and is pagination only.
type RecordHeader struct {
    GroupId          [32]byte
    SenderHandle     [16]byte
    Epoch            uint64
    StreamIndex      uint64
    IsCommit         bool
    RetentionClass   RetentionClass
    EphBucket        uint8     // meaningful only when RetentionClass == RetentionEph
    SizeBucket       SizeBucket
    ExpireAt         uint64    // unix MILLISECONDS, 0 = unset. May only shorten retention.
    BodyHash         [32]byte  // H(CtBody). RETAINED after CtBody is erased.
    BlobId           []byte    // exactly 32 bytes iff SizeBucket == SizeBucketBlob, else nil.
                               // Covered by AAD_head and by write_auth like every other header
                               // field. Derived from the record's key material (§5.13), never
                               // from content.
    ServerAttachment []byte    // nil/empty for ordinary records. §5.11.
}

type Record struct {
    RecordId  uint64        // server-assigned, 1-based, 0 = unassigned
    Header    RecordHeader
    CtHead    []byte        // AEAD, always retained
    CtBody    []byte        // AEAD, erasable; nil once pruned
    WriteAuth [32]byte      // computed last
}
```

The codec encodes `BlobId` as a length prefix in both `AAD_head` and the `write_auth` preimage, and
that prefix is **zero-length** whenever `SizeBucket != SizeBucketBlob`. There is no conditional in
the preimage builder and no special case for ordinary records; `ParseRecord` rejects a record whose
`BlobId` presence disagrees with its `SizeBucket`.

**The wire byte.** `RetentionClass` above is a Go-side tag. The wire encoding is fixed by MASTER §8 and
is restated here character-for-character because Spec B §3.1 restates the same table and a divergence
makes every EPH record fail both AEAD and MAC:

```
retention_class wire byte:

  0x00  PERMANENT
  0x01  DURABLE
  0x02  MEDIA
  0x10 | bucket   EPH(bucket), bucket in 0..5  →  0x10, 0x11, 0x12, 0x13, 0x14, 0x15
                                                  (decimal 16, 17, 18, 19, 20, 21)

No other value is legal. RetentionClassOf() and RetentionClassWire() in connect/message are the ONLY
places the class and the bucket are joined or split.

eph bucket → seconds:  [0] transient (never persisted), [1] 3600, [2] 28800,
                       [3] 86400, [4] 604800, [5] 2419200

size_bucket:  0 = 256 B, 1 = 1024 B, 2 = 4096 B, 3 = 16384 B, 4 = 65536 B, 5 = blob-ref
              octet_length(ct_body) MUST equal size_bucket_bytes[b] + 16 exactly (the AEAD tag),
              for b in 0..4. For b = 5, ct_body is absent and blob_id is present.
```

`EphBucket` is split out of `RetentionClass` in Go and rejoined on the wire, because a single `u8`
whose meaning depends on its own high bits is exactly the kind of field that gets compared with `==`
somewhere and silently treats `EPH(bucket 1)` as a different class from `EPH(bucket 0)`.

`RetentionClassOf` and `RetentionClassWire` are the **only** two functions in the system that join or
split the class and the bucket. A grep gate forbids `class<<4`, `class|bucket`, `16+bucket` and
`class*16` anywhere else in `connect/` and `sdk/`.

**`record_id`.**

`record_id` is a **per-group, gapless, monotonically allocated `uint64`**, server-assigned after
acceptance. It is **1-based**: `message_group.next_record_id` starts at 1 and `record_id = 0` is never
assigned, so `since_record_id = 0` is the well-defined "from the beginning" cursor for an exclusive lower
bound. It is used for pagination and for hole detection only. It is **never authenticated**: it appears in
neither `AAD_head`, nor `AAD_body`, nor the `write_auth` preimage, nor the `req_auth` preimage. It is
ignored on submit and populated on read.

**Size-bucket byte lengths, including the AEAD tag.** Spec B indexes and `CHECK`s on the right-hand
column; it is published here so the two never diverge (§12.1 A-3).

| `size_bucket` | body bytes | `octet_length(ct_body)` (body + 16-byte AEAD tag) |
|---|---|---|
| 0 | 256 | 272 |
| 1 | 1024 | 1040 |
| 2 | 4096 | 4112 |
| 3 | 16384 | 16400 |
| 4 | 65536 | 65552 |
| 5 | blob-ref | `ct_body` absent; `blob_id` present |

### 5.2 Construction order is a type, not a convention

MASTER §8 gives the construction order: build `server_attachment` → encrypt `ct_body` → compute
`body_hash` → encrypt `ct_head` → compute `write_auth`. Every dependency is acyclic, and getting it
wrong produces a circular AAD that *appears* to work until two implementations disagree.

The API makes the order unrepresentable-otherwise:

```go
// codec.go
type recordBuilder struct{ ... }   // unexported; no way to construct a Record by hand

// the only way to build a record. the steps happen inside, in order.
// serverAttachment is nil for an ordinary record and MUST then encode zero-length (§5.11).
func (self *GroupSession) SealRecord(
    class RetentionClass, ephBucket uint8, isCommit bool,
    headPlain []byte, bodyPlain []byte, expireAt uint64,
    serverAttachment *ServerAttachment,
) (*Record, error)

// the only way to consume one.
func (self *GroupSession) OpenRecord(record *Record) (headPlain, bodyPlain []byte, err error)
```

`Record` has no exported constructor and its fields are set only by `codec.go` and by the decoder.
Spec B's server-side code never seals or opens; it uses `message.ParseRecord`, `message.EncodeRecord`,
and `message.VerifyWriteAuth`, which are the only exported functions it needs (§12.1).

### 5.3 Key schedule

```go
// keyschedule.go

// storage_root[n] = HKDF-Extract(salt = mls_secret[n], ikm = pq_secret[n])   MASTER §7
//
// mls_secret[n] = MLS-Exporter("URmessage/v1/storage", "", 32)   RFC 9420 §8.5
//
// NOTE the argument order. crypto/hkdf.Extract takes (secret, salt) — ikm FIRST.
// This wrapper takes (salt, ikm), matching the spec text. Never call
// crypto/hkdf.Extract directly anywhere in this package. See §5.9.
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

// record_key[0]   = HKDF-Expand(class_key, "sender/v1" ‖ LP(leaf_index), 32)
// record_key[i+1] = HKDF-Expand(record_key[i], "ratchet/v1", 32)
func RecordKeyZero(classKey []byte, leaf uint32) []byte
func RecordKeyNext(recordKey []byte) []byte

// key_head ‖ nonce_head = HKDF-Expand(record_key[i], "rec/v1/head", 56)
// key_body ‖ nonce_body = HKDF-Expand(record_key[i], "rec/v1/body", 56)
func RecordAeadHead(recordKey []byte) (key, nonce []byte)
func RecordAeadBody(recordKey []byte) (key, nonce []byte)

// group_handle_key = HKDF-Expand(storage_root[0], "gh/v1", 32)  — FIXED at group
// creation, so sender_handle survives epoch changes. MASTER §8.
func GroupHandleKey(storageRootEpoch0 []byte) []byte
func SenderHandle(groupHandleKey []byte, leaf uint32) [16]byte
```

`NewEphRoot` takes an `io.Reader` and nothing else — no group, no epoch, no storage root. There is
deliberately no function in this package that produces an `eph_root` from any durable input. MASTER
§8.1 calls this out as the most easily broken property in the design: a derivation would compile, pass
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
    XwingExpandedSize   = 96     // SHAKE256(seed, 96): [0:64] = ML-KEM d‖z, [64:96] = X25519 sk
    XwingPublicKeySize  = 1216   // pk_M (1184) ‖ pk_X (32)
    XwingCiphertextSize = 1120   // ct_M (1088) ‖ ct_X (32)
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
| ML-KEM key from `expanded[0:64]` | `mlkem.NewDecapsulationKey768(expanded[0:64])` — documented as taking a 64-byte `d ‖ z` seed |
| X25519 scalar from `expanded[64:96]` | `ecdh.X25519().NewPrivateKey(expanded[64:96])` |
| ML-KEM encaps/decaps | `EncapsulationKey768.Encapsulate()`, `DecapsulationKey768.Decapsulate(ct)` |
| X25519 DH | `PrivateKey.ECDH(pub)` — **error is a hard failure**, never ignored |
| Combiner | `sha3.Sum256(XWingLabel ‖ ss_M ‖ ss_X ‖ ct_X ‖ pk_X)` |

Mandatory tests before any use (MASTER §7.2): the draft's own KAT vectors, both directions; a
negative test that a low-order X25519 point produces an error rather than a zero shared secret; and a
test that a truncated or over-long ciphertext is rejected by length before any arithmetic.

**`sdk.GenerateSharedSecret` (`sdk/sdk.go:804-817`), `box.Precompute`, and `curve25519.ScalarMult`
MUST NOT be referenced anywhere in `connect/mls`, `connect/message`, or `sdk/message_*.go`.** A CI
grep gate asserts this (§11.4). The existing function length-checks only, reaches deprecated
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
budget to finalize (§14 open item 7).

Beyond the window, a record is undecryptable and surfaces as a `Kind == "gap"` entry with
`GapReason == "out_of_window"` (§7.4) — not as an error. This is a deliberate, visible failure:
silently skipping is how a message loss becomes invisible.

**Zeroization.** `Next()` overwrites the previous key with zeros before returning. Go gives no
guarantee this survives the optimizer, so `zeroize()` uses a `//go:noinline` helper writing through
a `unsafe.Pointer`-derived slice, and `TestRatchetZeroizes` inspects the backing array after the
call. This is best-effort and documented as such; a Go program cannot promise a secret is gone from
RAM. It is still worth doing, because the common case — a key still sitting in a live struct field —
is entirely preventable.

### 5.6 `stream_index` is write-once, and durably so

`stream_index` is a single `u64` counter per `(group_id, sender_handle)`, write-once, assigned locally.
A device MUST durably record "index *k* consumed" **before** encrypting, and MUST NEVER encrypt a second
record at a consumed index. The server enforces **monotonicity, not contiguity**, so a refused write, a
crash between reserve and send, or a lost commit leaves a legal gap.

`EPH(bucket 0)` transients **do** consume an index locally (so the counter is never rewound) and are
**never** checked server-side, because the record is never stored and `message_sender.last_stream_index`
is not advanced for them.

Nonce reuse under a repeated `record_key` is a total break of both AEADs for that record, which is why
the reservation is durable rather than best-effort.

```go
// ratchet.go
// the reservation MUST be durable before the key is produced. this is the
// caller's obligation and the constructor takes the sink to make it explicit.
type StreamIndexReserver interface {
    // returns only after the reservation is durable (fsync'd or equivalent).
    Reserve(groupId []byte, index uint64) error
    HighWater(groupId []byte) (uint64, error)
}
```

`SealRecord` calls `Reserve` and refuses to proceed on error. On startup, `HighWater` is read and the
ratchet resumes at `highWater + 1`, never at a recomputed value. A crash between reserve and send
burns an index, which is fine: the server enforces monotonicity, not contiguity, so a gap does not
brick the stream.

`TestStreamIndexNeverReused` runs 10,000 seal operations with an injected crash after `Reserve` and
before the AEAD, restarts the session from the persisted state, and asserts no `index` is ever
produced twice.

### 5.7 `write_auth`, `req_auth` and the recovery proof

```go
// writeauth.go
func WriteKey(storageRoot []byte) []byte    // HKDF-Expand(storage_root[n], "write/v1", 32)

// MAC(write_key, "URmessage/v1/write" ‖ LP(server_nonce) ‖ LP(group_id)
//     ‖ LP(sender_handle) ‖ u64(epoch) ‖ u64(stream_index) ‖ u8(is_commit)
//     ‖ u8(retention_class) ‖ u8(size_bucket) ‖ u64(expire_at)
//     ‖ LP(H(ct_head)) ‖ LP(body_hash) ‖ LP(blob_id) ‖ LP(H(server_attachment)))
func WriteAuthPreimage(serverNonce []byte, h *RecordHeader, ctHead []byte,
                       serverAttachment []byte) []byte
func ComputeWriteAuth(writeKey []byte, serverNonce []byte, h *RecordHeader,
                      ctHead []byte, serverAttachment []byte) [32]byte
func VerifyWriteAuth(writeKey []byte, serverNonce []byte, record *Record) bool   // constant time

// read_key = HKDF-Expand(storage_root[0], "read/v1", 32). Fixed at group creation,
// never rotated, and delivered to a joining member in its Welcome alongside
// group_handle_key. Deriving it from the CURRENT epoch's storage_root would lock out
// every client that was offline across a commit — see the read-authorization
// discussion below.
func ReadKey(storageRootZero []byte) []byte

// MAC(read_key, "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op) ‖ LP(request_bytes))
func RequestAuthPreimage(serverNonce []byte, op uint8, requestBytes []byte) []byte
func ComputeRequestAuth(readKey []byte, serverNonce []byte, op uint8,
                        requestBytes []byte) [32]byte
func VerifyRequestAuth(readKey []byte, serverNonce []byte, op uint8,
                       requestBytes []byte, auth []byte) bool                     // constant time

// recovery.go — MASTER §5.2, §9.2. Ed25519, NOT a MAC: the server holds only the
// public half, so a symmetric construction would be unverifiable by construction.
func RecoveryProof(recoveryRoot []byte, serverNonce []byte,
                   recoveryHandle []byte) ([]byte, error)
func VerifyRecoveryProof(recoveryVerifyPub []byte, serverNonce []byte,
                         recoveryHandle []byte, sig []byte) bool
```

`VerifyWriteAuth` is exported specifically for Spec B. It is the **only** authentication the server
performs on the write path, and per MASTER I5 it is access control, never authenticity — a forged
record fails MLS verification at every client no matter what the server accepts.

**Read authorization.** Reads are authorized under the group's lifetime `read_key` and a domain label
distinct from `write_auth`'s:

```
req_auth = MAC(read_key, "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op)
                         ‖ LP(canonical_request_bytes))

  read_key                = HKDF-Expand(storage_root[0], "read/v1", 32), fixed at group
                            creation and never rotated.
  op                      = the field number of the selected `oneof body` arm in
                            MessageServerRequest, as a u8.
  canonical_request_bytes = the deterministically-marshaled request body message
                            (protobuf deterministic marshal, fields ascending) with its
                            own `req_auth` field set to zero length.

Required on, with their op bytes:  FetchRequest (13), SubscribeRequest (14),
                                   GroupStatusRequest (16), BlobGrantRequest (17),
                                   WrapFetchRequest (19).

NOT used on: HelloRequest (names no group, and is where server_nonce is issued),
             CreateGroupRequest (the group does not exist yet; the initial commit is
               self-certified against bootstrap_write_key — Spec B §6.1),
             UnsubscribeRequest (cancels only the caller's own subscription),
             SubmitRequest (every record in it carries its own write_auth),
             RecoveryFetchRequest (asymmetric Ed25519 proof, below).

Verified on the server with Spec B §5.1 checks 1, 2, 4, 5 and the group read-key lookup,
and then this MAC, returning Spec B's deliberately non-specific REASON_REJECTED on
failure. No transaction is opened and no row is allocated on the read path.
```

`read_key` is deliberately not the epoch's `write_key`. The server keeps only the current epoch's
write key and one 60-second predecessor, so a client that was offline across one commit holds a key
the server cannot resolve — and every route out of that condition (`GroupStatus` to learn the epoch,
`Fetch` to obtain the commits, `WrapFetch` to obtain its own wrap) is itself a read. `connect/message`
therefore takes a `read_key` on every request-auth call and has no code path that MACs a request
under a `write_key`; `TestReadAuthNeverUsesWriteKey` asserts it by walking the call graph of
`ComputeRequestAuth`.

A group's `read_key` reaches the server inside `EpochAttachment.read_key` on every commit, identical
in every epoch, and reaches a joining member in the `Welcome` alongside `group_handle_key` (MASTER
§8). A member that holds neither cannot read at all — including the read that would fetch the commit
that admitted it, which is why both travel out of band with the join.

**The recovery proof.** A seed-only restorer holds no group key at all — neither `write_key` nor
`read_key` — so `RecoveryFetch` is authorized asymmetrically:

```
recovery_root      = HKDF-Expand(master_key, "recovery/v1", 32)              (unchanged)
recovery_handle    = HKDF-Expand(recovery_root, "idx/v1", 16)                (unchanged)
recovery_sig_seed  = HKDF-Expand(recovery_root, "idxsig/v1", 32)             (NEW)
recovery_sig_sk    = Ed25519 private key from recovery_sig_seed
recovery_verify_pub= Ed25519 public key of recovery_sig_sk                   (32 B)

recovery_proof = Ed25519(recovery_sig_sk,
                   "URmessage/v1/recovery" ‖ LP(server_nonce) ‖ LP(recovery_handle))

The archive record's server_attachment RecoveryTag (§5.11, kind 0x0002) carries
{recovery_handle, recovery_verify_pub, alg_id} and is covered by write_auth, so the
public half arrives authenticated as a member of the group.

The server stores the public half on first sight and REFUSES any later differing
recovery_verify_pub for the same recovery_handle (trust-on-first-use, the same shape as
the client's server-key pin). RecoveryFetchRequest.proof is verified against it.
```

**The nonce.**

`server_nonce` is 32 bytes, issued by the message server at session start in `HelloResponse`, scoped to
**that connection**, valid for the life of that connection, and never rotated. It prevents
cross-connection replay. It is **not** carried in requests — the server knows its own connection's nonce
and looks it up from the connection, never from the request.

**Outbox rule (normative, client side).** On reconnect, every queued record MUST be re-MAC'd against the
new connection's nonce before submission. On `REASON_EPOCH_STALE`, a queued record MUST be discarded and
re-sealed at the new epoch, consuming a **fresh** `stream_index`.

This layer takes the nonce as an opaque byte string and refuses to compute with an empty one.

### 5.8 The codec

`connect/mls/syntax` implements the TLS presentation language of RFC 8446 §3 as MLS uses it: fixed
integers, `opaque V<..>` with the MLS variable-length prefix, `optional<T>`, and vectors.

Rules, each with a fuzz property behind it (§4.4):

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
| G2 | `eph_root` derived from anything durable | §5.3: no such function exists; reflection test |
| G3 | X25519 error ignored | All `ECDH` calls return through a helper that converts error to `ErrInvalidPoint`; grep gate forbids `_ =` on an `ECDH` result |
| G4 | `body_hash` placed in `AAD_body` (circular) | `AAD_body` is built by a function that does not take a hash argument |
| G5 | AEAD nonce reuse | §5.6 durable reservation + `TestStreamIndexNeverReused` |
| G6 | `epoch_secret` exported instead of the two named secrets | §3.3: `EpochSecretName` is a closed two-value enum |
| G7 | Signature/MAC mismatch logged and continued | `errors.go` types are all fatal-by-construction; the only verification helpers returning `bool` are `VerifyWriteAuth`, `VerifyRequestAuth` and `VerifyRecoveryProof`, and each caller is asserted to `return` on false |
| G8 | Non-constant-time comparison of a tag | Every tag comparison goes through `crypto/subtle.ConstantTimeCompare`; grep gate forbids `bytes.Equal` in `validation.go`, `writeauth.go`, `framing.go` |
| G9 | ML-KEM seed length confusion (32 vs 64) | `XwingKeyGenFromSeed` takes exactly 32 and expands; `mlkem.NewDecapsulationKey768` is called with exactly `expanded[0:64]`; both lengths asserted with a compile-time-adjacent `const` check and a unit test |
| G10 | `pq_secret[n+1]` carried across a lost commit | The provisional epoch state is a value that `ClearPendingCommit` destroys; there is no path that reads it afterwards. `TestLostCommitResamplesPqSecret` |
| G11 | `stream_index` reused after a lost commit | Extend `TestStreamIndexNeverReused` with an injected commit loss between reserve and re-seal |

### 5.10 Corrections adopted in MASTER

Three problems were found while specifying this layer. **All three are applied in MASTER**; they are
recorded here only so a reader of this document does not implement the pre-correction variant. No
ruling is outstanding and nothing blocks slice A6.

| # | Correction | Where it now lives in MASTER |
|---|---|---|
| E1 | The **recovery** wrap carries `storage_root[n]` and `archive_secret[n]`, not `pq_secret[n]`. A seed-only restorer has no MLS state and therefore no `mls_secret[n]`, so a wrap carrying `pq_secret` would open nothing. The **device** wrap is unchanged and still carries `pq_secret[n]` and `eph_root[n]`. | §8.2, table and the "Why the recovery wrap carries `storage_root[n]`" paragraph |
| E2 | The per-epoch ratchet-tree snapshot is **one `PERMANENT`-class record per epoch** under `K_snapshot[n] = HKDF-Expand(storage_root[n], "snap/v1", 32)`, not a copy inside every wrap. | §8.2, "The epoch snapshot is a record, not part of the wrap" |
| E3 | The recovery X-Wing key is derived from a **32-byte** seed, expanded internally with SHAKE-256 per draft-06. A 96-byte HKDF output used directly is not X-Wing and forfeits the security proof. | §5.2 |

Sizing after all three, for 500 members × 2 devices, is MASTER §8.2's sizing paragraph: every wrap
pads to `size_bucket 2` (a `ct_body` of exactly 4,112 bytes), so a device wrap and a recovery wrap are
each about 4.6 KB on the wire — device wraps 4.6 MB, recovery wraps 2.3 MB, snapshot 0.30 MB on the
bulk plane, **≈ 6.9 MB per commit** and ~55 round trips at `max_submit_bytes = 131072`.

### 5.11 The server attachment

`connect/message/attachment.go` owns this encoding. Spec B consumes it and never reimplements it
(B §12.1 A-2). MASTER §8.3 carries the same block.

`LP(x)` = 32-bit big-endian length prefix then `x`; `u8/u16/u32/u64` big-endian fixed width.

```
server_attachment := u16(kind) ‖ LP(body)

  kind 0x0000  NONE            body is zero-length. Ordinary records carry a ZERO-LENGTH
                               server_attachment (the whole field is empty), NOT kind 0x0000.
  kind 0x0001  EpochAttachment carried by, and only by, a record with is_commit = 1
  kind 0x0002  RecoveryTag     carried by RECOVERY_PUB records and by recovery wrap records
  kind 0x0003  WrapTag         carried by per-device epoch wrap records and by the epoch snapshot
  kind 0x0004  EpochComplete   carried by the wrap-set-complete marker record

EpochAttachment {
    u64  epoch                  // the epoch this attachment OPENS. MUST equal current_epoch + 1
    u16  alg_id                 // 0x0031 (HKDF-SHA-256) in v1
    LP   write_key              // exactly 32 bytes: write_key[epoch]
    LP   read_key               // exactly 32 bytes: read_key = HKDF-Expand(storage_root[0],
                                //   "read/v1", 32). Identical in every epoch of this group;
                                //   the server refuses a commit that changes it (§5.7)
    u32  media_ttl_seconds
    u32  durable_ttl_seconds    // 0 = indefinite
    LP   group_context_hash     // exactly 32 bytes
    u32  expected_wrap_count    // device wraps + recovery wraps + 1 snapshot, for the epoch it opens
}

RecoveryTag {
    LP   recovery_handle        // exactly 16 bytes
    LP   recovery_verify_pub    // exactly 32 bytes, Ed25519
    u16  alg_id                 // 0x0001 (Ed25519)
}

WrapTag {
    LP   wrap_target_handle     // exactly 16 bytes
    u64  epoch                  // the epoch whose wrap or snapshot this record carries
}

EpochComplete {
    u64  epoch
    u32  wrap_count             // MUST equal that epoch's EpochAttachment.expected_wrap_count
}

wrap_target_handle = HKDF-Expand(group_handle_key, "wt/v1" ‖ u64(epoch) ‖ u32(leaf_index), 16)
                     // every member can compute it for every leaf; the server cannot invert it.
                     // The epoch snapshot record uses leaf_index = 0xFFFFFFFF.
```

**Epoch publication sequence.** A commit is submitted at `epoch == current_epoch = n`, MAC'd under
`write_key[n]`, and carries an `EpochAttachment` for epoch `n+1`.

1. The server accepts at most one commit per `(group_id, epoch)`. On acceptance it sets
   `current_epoch := n+1` and installs `write_key[n+1]` from the attachment, in the same transaction.
2. The committer then submits, **as ordinary records at epoch `n+1`, MAC'd under `write_key[n+1]`**: one
   device wrap per active device leaf (`WrapTag`, indexed by `wrap_target_handle`), one recovery wrap per
   member (`RecoveryTag`, indexed by `recovery_handle`), and the ratchet-tree snapshot (one
   `PERMANENT`-class record, `WrapTag` with `leaf_index = 0xFFFFFFFF`).
3. The committer closes the fan-out with one `EpochComplete` marker record whose `wrap_count` MUST equal
   the attachment's `expected_wrap_count`. Until that marker is accepted, the group is
   **readable-but-not-writable**: the server returns `REASON_EPOCH_INCOMPLETE` to any non-wrap submit
   at epoch `n+1`.
4. A member or device that finds no wrap for its target at epoch `n+1` after the marker has landed
   surfaces a `gap` entry with reason `no_wrap`. It never fails silently.
5. If the committer dies mid-fan-out, the marker never lands, the group stays non-writable, and any
   member may re-publish the missing wraps for epoch `n+1` (they are all derivable from the epoch state
   every member holds) and submit the marker.

**Sizing at the 500-member × 2-device design target.** Wraps pad to the ladder like everything else:
a device wrap (~1,210 B) and a recovery wrap (~1,242 B) both land in `size_bucket 2`, a `ct_body` of
exactly 4,112 bytes, about 4.6 KB on the wire each. One commit + 1,000 device wraps + 500 recovery
wraps + 1 snapshot + 1 marker ≈ 1,503 records ≈ **6.9 MB**, plus a ~300 KB snapshot object. Per-record
size caps apply to individual wrap records, never to the commit as a whole. `max_records_per_submit`
is 256 and `max_submit_bytes` is 131072; the byte cap binds first at about 28 wraps per submission,
so a wrap-only batch takes **~55 round trips**.

The snapshot exceeds the 64 KiB inline ceiling and is therefore written by `wrap.go` as a **blob-ref
record** (`size_bucket = 5`) of class `PERMANENT`. The server MUST offer a non-expiring object rung
for it — see Spec B §8.3 — and MUST NOT place it on any TTL ladder. `BlobGrantRequest.retention_class`
MAY therefore be `PERMANENT`, `DURABLE`, `MEDIA`, or the parent's `EPH` class; the server binds a
blob only to a record of the *same* class, so omitting `DURABLE` would make a durable attachment
unrepresentable.

The Go surface:

```go
// attachment.go
type ServerAttachmentKind uint16

const (
    AttachmentNone     ServerAttachmentKind = 0x0000
    AttachmentEpoch    ServerAttachmentKind = 0x0001
    AttachmentRecovery ServerAttachmentKind = 0x0002
    AttachmentWrap     ServerAttachmentKind = 0x0003
    AttachmentComplete ServerAttachmentKind = 0x0004
)

type ServerAttachment struct {
    Kind     ServerAttachmentKind
    Epoch    *EpochAttachment
    Recovery *RecoveryTag
    Wrap     *WrapTag
    Complete *EpochComplete
}

func ParseServerAttachment(b []byte) (*ServerAttachment, error)   // empty input -> AttachmentNone
func EncodeServerAttachment(a *ServerAttachment) ([]byte, error)  // AttachmentNone -> zero-length

// handle.go
func WrapTargetHandle(groupHandleKey []byte, epoch uint64, leafIndex uint32) [16]byte
```

**Test obligation.** `TestServerAttachmentRoundTripsAgainstVectors`, driven by the shared interop
vector file (§12.1 A-8), asserting that a zero-length attachment and an `AttachmentNone` attachment
encode identically (both zero-length) so `H(server_attachment)` cannot differ between client and
server for an ordinary record.

### 5.12 The losing committer (normative)

Spec B binds this contract to **any rejection of a commit submission**, not only to
`REASON_COMMIT_LOST`. `connect/message` implements it; A-ASSUME-5's "re-derive-and-retry" is not
sufficient description.

```
On any rejection of a commit submission, the committer MUST, in order:

1. Discard its provisional epoch-(n+1) state entirely — TreeKEM path secrets, storage_root[n+1],
   write_key[n+1], eph_root[n+1], and every X-Wing wrap it built.
2. MUST NOT reuse the pq_secret[n+1] it sampled. It was encapsulated to a ratchet tree that no
   longer exists; carrying it into the real epoch n+1 binds one PQ secret across two distinct
   epochs and breaks MASTER §7's per-epoch independence. Sample a fresh one.
3. Apply the winning commit from SubmitResult.winning_commit, verifying it through MLS exactly as
   if it had arrived by fetch. Server delivery grants it nothing.
4. Recompute which of its own proposals remain unapplied. The winner may already have included
   some; blindly re-proposing produces duplicates a correct implementation then rejects.
5. Re-propose only the remainder, and retry the commit at epoch n+1.
6. Discard and re-encrypt any records it optimistically produced at epoch n+1. Their stream_index
   values were already consumed and MUST NOT be reused; the stream acquires a legal gap.
7. Back off: full jitter, base 250 ms, cap 8 s, maximum 5 attempts, then surface a failure.
```

### 5.13 Blobs

`blob_id` is 32 bytes derived from the record's key material —
`blob_id = HKDF-Expand(record_key[i], "blob/v1", 32)` — so it is unlinkable across groups and is
**never** a hash of the plaintext or of the ciphertext (a content-derived id makes the object store a
confirmation oracle).

Object length is padded by the client to a multiple of **262144 bytes (256 KiB)** before upload. Bounded
overhead, removes fine-grained size fingerprinting. This closes Spec B open item 4.

MIME type is determined by the client from the file's content sniff plus extension and is carried
**inside** the encrypted body, never on the wire; the bulk plane always sees
`application/octet-stream`.

The `mimeType` argument of `SendAttachment` (§7.4) is a **hint** from the caller's file picker.
`connect/message` sniffs the content itself and uses its own result whenever the two disagree; an
empty hint is legal and means "sniff it". One layer decides, and it is this one, because the value
travels inside the encrypted body that this layer builds.

---

## 6. The narrow swappable interface

Gate 5 (§4.5). The interface is declared at each consumer (A3); Go's structural typing makes the
`connect/mls` adapter satisfy both without an import edge.

```go
// connect/message/engine.go
//
// the entire MLS surface connect/message is allowed to see. adding a method
// here is a design decision, not a convenience — everything added is something
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

    // the two named secrets of MASTER §8.2, and the exporter. nothing else.
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

`sdk` is the product surface. It must satisfy gomobile's type restrictions (§7.8) because the same
package builds the Android AAR and the Apple framework, and the cgo generator's ABI baseline
(§9) is derived from it.

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
func NewMessageClient(settings *MessageClientSettings) (*MessageClient, error)
func (self *MessageClient) Close()

type MessageClientSettings struct {
    StorageDir       string   // Spec C supplies; sealed material lives under here
    NetworkSpaceHost string   // the URnetwork network space, e.g. "ur.network"
    MessageServerId  string   // v1: the one server's URnetwork client id
    EnableCover      bool     // MASTER §9.5 — off by default
    MediaCacheBytes  int64
}

// ── account (A12: this DLL owns login; there is no second Go runtime) ──────
func (self *MessageClient) SetByJwt(jwt string) error   // hot-swappable. Does NOT disturb the
                                                        // local store, MLS state, the outbox,
                                                        // or any Sub. Used for token refresh.
func (self *MessageClient) ByJwtState() string          // "valid" | "expired" | "absent"

// ── identity — MASTER §5.1. the phrase is generated on-device, NEVER transmitted ──
func GenerateMessageSeedphrase() (string, error)               // BIP39 24 words
func ValidateMessageSeedphrase(phrase string) error
func (self *MessageClient) HasIdentity() bool
func (self *MessageClient) CreateIdentity(phrase string) error // first run
func (self *MessageClient) RestoreIdentity(phrase string, callback RestoreCallback) *MessageSendTicket
func (self *MessageClient) RevealSeedphrase() (string, error)  // §7.2.1
func (self *MessageClient) RemoveIdentity() error              // destructive; see §7.2.1
func (self *MessageClient) MarkPhraseConfirmed() error
func (self *MessageClient) PhraseConfirmedAtMs() int64         // 0 = never confirmed
func (self *MessageClient) IdentitySafetyDigits() string       // 12 groups of 5 digits (safety number format)
func (self *MessageClient) IdentityShortFingerprint() string   // 8 hex, for the Settings row
func (self *MessageClient) IdentityPublicKey() []byte

// ── live settings (were construction-only; C exposes them as switches) ─────
func (self *MessageClient) SetCoverTraffic(enabled bool) error   // takes effect on the next
                                                                 // scheduling window; the schedule
                                                                 // stays independent of real
                                                                 // sending (MASTER §9.5)
func (self *MessageClient) SetMediaCacheBytes(n int64) error
func (self *MessageClient) SetUserPreference(key string, value string) error
func (self *MessageClient) UserPreference(key string) string
// user-preference keys, closed: "read_receipts", "typing_indicators",
// "disappearing_default_bucket". Backed by the sealed local store, NOT prefs.json.
// COMPOSITION RULE: a receipt or typing indicator is emitted only if the user
// preference AND the group policy allow it. See §7.3.

// ── server ────────────────────────────────────────────────────────────────
func (self *MessageClient) ServerInfo() *MessageServerInfo
func (self *MessageClient) AcceptServerKey(fingerprint string) error

// ── lifecycle ─────────────────────────────────────────────────────────────
func (self *MessageClient) Start() error
func (self *MessageClient) SyncState() *SyncState
func (self *MessageClient) AddSyncListener(listener SyncListener) *Sub
func (self *MessageClient) Health() *MessageHealthEvent
func (self *MessageClient) AddHealthListener(listener HealthListener) *Sub

// ── push (§14 open item 9; slice A11). No-op stubs until the channel registry
// exists on the server, so wiring WNS later is not an ABI break. ────────────
func (self *MessageClient) RegisterPushChannel(uri string) error
func (self *MessageClient) UnregisterPushChannel() error
```

**The `settings_json` schema.** `MessageClientSettings` and the JSON `urmsg_client_open` takes are the
same shape:

```jsonc
// urmsg_client_open(settings_json, out_error). All keys required unless marked optional.
{
  "storage_dir":        "string",   // absolute path, per-user, writable. NOT %PROGRAMDATA%.
  "network_space_host": "string",   // e.g. "ur.network"; the URnetwork network space
  "message_server_id":  "string",   // the one server's URnetwork client id (UUID string),
                                    // from the build-time constant kMessageServerClientId
                                    // or, when set, from the operator discovery response
  "enable_cover":       false,      // optional, default false  (MASTER §9.5)
  "media_cache_bytes":  1073741824  // optional, default 1 GiB
}
```

```go
type MessageClientSettings struct {
    StorageDir       string
    NetworkSpaceHost string
    MessageServerId  string   // v1: the one server's URnetwork client id
    EnableCover      bool     // MASTER §9.5 — off by default
    MediaCacheBytes  int64
}
```

The ByJwt is **not** a construction-time value. It is established by the `urmsg_auth_*` login surface
and refreshed with `SetByJwt` (§9.3).

**The state C renders.** Every state Spec C renders is an explicit enumerable value from this layer.
`SyncState` is the input to C's health evaluator, so C's transition table is testable against a fake
rather than against the network:

```go
// sdk/message_events.go
type SyncState struct {
    Transport                string   // "down" | "connecting" | "up"
    MachineOnline            bool
    LastRecordReceivedMs     int64    // 0 = never; drives C §9.2's carrying veto
    ConsecutiveFetchFailures int32
    ConsecutiveSendFailures  int32
    LastAttemptMs            int64
    LastSuccessMs            int64
    ServerPinState           string   // "unpinned" | "pinned" | "changed_unaccepted"
    StoreState               string   // "ok" | "unseal_failed" | "corrupt" | "disk_full"
                                      //      | "locked_by_another_process"
    TokenState               string   // "valid" | "expired" | "absent"
    BlockedReason            string   // a vocabulary-3 Reason, or "none"
    EvaluatedAtMs            int64
    Dropped                  int64    // events dropped for this Sub since the last delivery
}
// SyncStateChanged fires on every transition of any field.
```

**The three closed vocabularies**, owned by this document and cited everywhere else:

```go
// ── 1. Sendability. CanSend(groupId) -> MessageSendability.Reason ──────────
//   "ok"
//   "offline"                 no network on the machine
//   "server_unreachable"      §9.4's reachability rule has fired
//   "key_change_unresolved"   a DM peer's key changed and is unaccepted
//   "not_a_member"            removed from the group
//   "observer"                role is OBSERVER
//   "no_leaf_after_restore"   seed-only restore; no MLS leaf in this group
//   "fork_detected"           transcript hash divergence in this group
//   "phrase_not_confirmed"    PhraseConfirmedAtMs() == 0 and C-1's gate applies
//   "store_unavailable"       the local store could not be opened
//   "group_closed"            the server has closed the group
//   "epoch_incomplete"        the epoch's wrap set has not landed yet (§5.11, epoch
//                             publication step 3)

// ── 2. Send failure. SendStateChanged / MessageEntry.Reason ────────────────
//   every value of vocabulary 1, plus:
//   "too_large"               exceeds ServerInfo().MaxBlobBytes
//   "blob_incomplete"         the blob was not fully uploaded before bind
//   "rate_limited"            carries RetryAfterMs in ReasonDetail
//   "oversize"                the record or request exceeded an advertised cap
//   "quota_exceeded"
//   "internal"
// NOT a value: "commit_lost" (A retries internally and never surfaces it — MASTER §9.3),
//              "retention_refused" (deleted; retention is warn-and-proceed — MASTER §15 item 1).

// ── 3. Health. MessageHealthEvent.State ───────────────────────────────────
//   "no_account" | "offline" | "connecting" | "reachable" | "degraded"
//   | "server_unreachable" | "blocked" | "store_unavailable"
// MessageHealthEvent.Reason, closed:
//   "none" | "token_expired" | "key_change_unresolved" | "server_key_change_unresolved"
//   | "fork_detected" | "unseal_failed" | "corrupt" | "disk_full"
//   | "locked_by_another_process"
```

Token expiry maps to health `no_account` with reason `token_expired`; no ninth state is added.

```go
type MessageSendability struct {
    Allowed      bool
    Reason       string   // vocabulary 1
    ReasonDetail string   // free text for display only; never parsed
}

func (self *MessageClient) CanSend(groupId string) *MessageSendability
// GroupListener additionally delivers SendabilityChanged(groupId string, s *MessageSendability)

type MessageServerInfo struct {
    Host                  string
    ServerIdHex           string
    ClientId              string
    SigningKeyFingerprint string
    PinState              string   // "unpinned" | "pinned" | "changed_unaccepted"
    PinnedAtMs            int64
    MaxBlobBytes          int64
    MediaTtlMaxMs         int64
    MediaTtlDefaultMs     int64
    DurableRetentionMinMs int64
    MaxRecordsPerFetch    int32
    MaxRecordsPerSubmit   int32
    MaxSubmitBytes        int32
    MaxRequestBytes       int32    // post-reassembly control-plane cap; exceeding it aborts
                                   // the request server-side
    MaxResponseBytes      int32
    BlobChunkBytes        int32
    BlobPadMultiple       int32
    AttestationSupported  bool
    CapabilityVersion     int64
    Advertised            bool     // false before the first HelloResponse of this install.
                                   // Spec C renders "not known yet", NEVER a fabricated default.
}

type MessageHealthEvent struct {
    State   string   // vocabulary 3
    Reason  string   // vocabulary 3 reasons
    Detail  string   // display only; never parsed
    Seq     int64
    Dropped int64
}
type HealthListener interface { HealthChanged(event *MessageHealthEvent) }
```

`MessageServerInfo`'s `MediaTtlMaxMs`, `MediaTtlDefaultMs` and `DurableRetentionMinMs` are
milliseconds because every other duration on this API surface is milliseconds; `sdk` converts them
from the server's seconds once, on receipt of `Capabilities`. `MessageRetentionApplied` does **not**
convert — it is a mirror of a wire message and stays in seconds.

#### 7.2.1 Seedphrase custody

```go
// sdk/message.go
// Reconstructs the 24-word BIP39 mnemonic from the sealed entropy. The entropy is
// stored in keys.sealed under DPAPI context "seed_entropy" for the life of the install
// and is deleted only by RemoveIdentity(). The words themselves are NEVER persisted.
// Spec C gates this behind its Windows Hello check and holds the string only for the
// life of the screen.
func (self *MessageClient) RevealSeedphrase() (string, error)
```

```c
bool urmsg_client_reveal_seedphrase(uint64_t client, char** out_phrase, char** out_error);
```

**Correction.** An earlier revision of this section said `CreateIdentity` *"never returns the phrase and
never accepts a phrase it generated itself"*, immediately before describing the flow in which Spec C
passes back exactly the phrase `GenerateMessageSeedphrase` produced. The second clause was wrong and is
deleted. The contract is: `GenerateMessageSeedphrase` is a free function; Spec C displays the words,
requires confirmation, then calls `CreateIdentity(phrase)`; `CreateIdentity` derives `master_key`, seals
the **256-bit BIP39 entropy** under DPAPI context `"seed_entropy"` alongside the derived children, and
discards the words. `RevealSeedphrase()` reconstructs the words from that entropy. `RemoveIdentity()`
deletes the entropy, the derived children, and the whole local store; after it, the words are the only
way back.

### 7.3 Groups

```go
func (self *MessageClient) CreateGroup(name string, callback GroupCallback) *MessageSendTicket
// one MLS commit covering N Add proposals plus the policy, so "created" is atomic.
// Replaces the CreateGroup + N×InviteMember + SetGroupPolicy sequence, each of which
// was its own commit and its own (group_id, epoch) race.
func (self *MessageClient) CreateGroupWithMembers(name string, principals *StringList,
    policy *MessageGroupPolicy, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) CreateDirect(principal string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) Groups() *MessageGroupList
func (self *MessageClient) Group(groupId string) *MessageGroup            // nil if unknown
func (self *MessageClient) Members(groupId string) *MessageMemberList
func (self *MessageClient) InviteMember(groupId string, principal string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) RemoveMember(groupId string, memberId string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) SetMemberRole(groupId string, memberId string, role string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) LeaveGroup(groupId string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) SetGroupPolicy(groupId string, policy *MessageGroupPolicy, callback GroupCallback) *MessageSendTicket

// the single-field forms of SetGroupPolicy, because Spec C's disappearing sheet and its
// Ctrl+Shift+D chord set one field and must not have to read-modify-write a whole policy.
// Both are ADMIN/OWNER-only group state and both commit (MASTER §11).
func (self *MessageClient) SetDisappearing(groupId string, bucket int32,
    callback GroupCallback) *MessageSendTicket

// personal, not group state: these write the local store and commit nothing.
func (self *MessageClient) SetGroupMuted(groupId string, muted bool) error
func (self *MessageClient) SetGroupNotificationMode(groupId string, mode string) error
// mode is CLOSED: "default" | "name_and_message" | "name_only" | "nothing".
// "default" means "follow the global notification setting" and is the initial value.

// MASTER §11: owner-only, non-erasable. A grant is a group record, so it is a commit and
// returns a ticket. Calling it as anyone but OWNER fails with a GroupResult reason.
func (self *MessageClient) GrantHistory(groupId string, memberId string, fromEpoch int64,
    callback GroupCallback) *MessageSendTicket
func (self *MessageClient) HistoryGrants(groupId string) *MessageHistoryGrantList

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
// NAMESPACE NOTE: this field and the wire EPH class number are DIFFERENT NAMESPACES.
// On the wire, EPH(bucket 0) is the transient class carrying receipts and typing and is
// never persisted. Here, 0 means "disappearing is off". SetDisappearing(gid, 0) turns
// disappearing OFF; it never sends a receipt-class record. Spec C's open item C-8 is
// closed by citing this line.
//
// LAYERING: these three fields are the GROUP policy, settable by ADMIN/OWNER only
// (MASTER §11). The USER's own preferences are SetUserPreference/UserPreference (§7.2).
// A receipt or typing indicator is emitted only if BOTH allow it. Spec C's Settings
// toggles write the user preference; the group sheet writes the policy.
```

**Retention negotiation is warn-and-proceed, in both directions** (MASTER §15 item 1). The server
clamps a policy longer than `media_ttl_max_seconds` **down**, floors a policy shorter than
`durable_retention_min_seconds` **up**, accepts the commit either way, and reports what it applied.
`GroupEvent` (§7.7) therefore carries `RetentionApplied *MessageRetentionApplied` with
`{MediaTtlSeconds, DurableTtlSeconds, MediaClampedDown, DurableFlooredUp,
RequestedMediaTtlSeconds, RequestedDurableTtlSeconds}`. The group's transcript-covered policy is
unchanged; the client renders a one-time in-group notice naming the **effective** value, never the
requested one. There is no `RetentionPolicyConflict` event and no refuse-to-commit path.

`CreateDirect` is not a different code path — ledger P2 — a DM is a two-member group (MASTER §6). It
exists only so the UI can express intent and the client can render it as a conversation. `MessageGroup.IsDirect`
is `MemberCount() == 2 && CreatedAsDirect`.

Role strings are `"owner"`, `"admin"`, `"member"`, `"observer"` (MASTER §11). Strings rather than an
int enum because gomobile enums are ints in Java/Swift with no name, and a mis-set role is a
security-relevant bug.

### 7.4 Messaging

```go
func (self *MessageClient) SendText(groupId string, text string, replyToId string,
    callback SendCallback) *MessageSendTicket
func (self *MessageClient) SendAttachment(groupId string, filePath string, mimeType string,
    caption string, callback UploadCallback) *MessageSendTicket
func (self *MessageClient) ResumeAttachment(groupId string, messageId string,
    callback UploadCallback) *MessageSendTicket

// re-send a message that reached State == "failed". The entry keeps its MessageId and
// returns to "pending"; a fresh stream_index is consumed (§5.12 step 6). Calling it on
// an entry in any other state returns a ticket that completes with an error.
func (self *MessageClient) Retry(groupId string, messageId string,
    callback SendCallback) *MessageSendTicket

func (self *MessageClient) React(groupId string, targetId string, emoji string,
    callback SendCallback) *MessageSendTicket
func (self *MessageClient) Unreact(groupId string, targetId string, emoji string,
    callback SendCallback) *MessageSendTicket

func (self *MessageClient) DeleteForEveryone(groupId string, messageId string,
    callback SendCallback) *MessageSendTicket
func (self *MessageClient) DeleteLocal(groupId string, messageId string) error

func (self *MessageClient) MarkRead(groupId string, throughMessageId string) error
func (self *MessageClient) SetTyping(groupId string, typing bool)

// can this device send to this group right now, and if not, why. CLOSED reason set.
func (self *MessageClient) CanSend(groupId string) *MessageSendability

// history comes from the local store, synchronously; the sync loop backfills.
// Spec C MUST call History off the UI thread (Spec C §5.1).
func (self *MessageClient) History(groupId string, beforeMessageId string, limit int32) *MessageEntryList
func (self *MessageClient) HistoryState(groupId string) *MessageHistoryState
func (self *MessageClient) Entry(groupId string, messageId string) *MessageEntry
func (self *MessageClient) EntryDetail(groupId string, messageId string) *MessageEntryDetail
func (self *MessageClient) Search(groupId string, query string, limit int32) *MessageSearchResultList
func (self *MessageClient) RequestBackfill(groupId string, beforeMessageId string,
    callback SyncCallback) *MessageSendTicket

// groupId == "" subscribes to ALL groups. The client holds exactly one all-groups Sub
// plus at most one per open conversation.
func (self *MessageClient) AddMessageListener(groupId string, listener MessageListener) *Sub
// client-wide, independent of any open conversation. Fires for EVERY expiring record
// from the expiry sweep, so an Action Center toast can be revoked when its key dies.
func (self *MessageClient) AddRecordLifecycleListener(listener RecordLifecycleListener) *Sub

func (self *MessageClient) DownloadAttachment(groupId string, messageId string, attachmentId string,
    destPath string, callback DownloadCallback) *MessageSendTicket

type MessageEntry struct {
    MessageId        string
    GroupId          string
    SenderId         string   // stable per group; maps to a MessageMember
    SenderLeafIndex  int32
    SenderRoleAtSend string   // "owner"|"admin"|"member"|"observer", READ FROM THE
                              // TRANSCRIPT-COVERED GROUP-CONTEXT EXTENSION OF THE SENDING
                              // EPOCH — never from current membership
    Epoch            int64
    SentAtMs         int64
    ReceivedAtMs     int64
    Kind             string   // "text"|"attachment"|"reaction"|"tombstone"|"system"|"gap"
    GapReason        string   // set iff Kind == "gap"; see below
    Text             string
    ReplyToId        string
    State            string   // "pending"|"sent"|"read"|"failed"|"expired"
    Reason           string   // set iff State == "failed"; §7.2 vocabulary 2
    ReasonDetail     string
    ExpiresAtMs      int64    // 0 when not disappearing
    RetentionClass   string   // "permanent"|"durable"|"media"|"eph"
    EphBucket        int32
    SizeBucket       int32
    Edited           bool     // reserved; always false in v1
    Attachments      *MessageAttachmentList
    Reactions        *MessageReactionList
    ReadBy           *MessageReceiptList
    Seq              int64
    Dropped          int64
}

type MessageEntryDetail struct {
    Entry            *MessageEntry
    TranscriptEpoch  int64
    ServerRecordId   int64
    AttestationState string   // "covered" | "uncovered" | "gap_recorded"
}

type MessageHistoryState struct {
    HasMoreLocal   bool     // more rows in the local store below the current window
    HasMoreRemote  bool     // the sync loop believes the server has older records
    OldestLocalMs  int64
    JoinedAtEpoch  int64
}

type MessageAttachment struct {
    AttachmentId string
    FileName     string
    MimeType     string
    Bytes        int64
    Caption      string
    State        string   // CLOSED: "available" | "not_downloaded" | "downloading"
                          //       | "pruned" | "expired" | "failed"
    LocalPath    string   // set iff State == "available"
}

type MessageSearchResult struct {
    GroupId      string
    MessageId    string
    SentAtMs     int64
    Snippet      string
    MatchOffset  int32
    MatchLength  int32
}

type UploadProgress struct {
    GroupId    string
    MessageId  string
    BytesSent  int64
    BytesTotal int64
    Resumed    bool
}
type UploadCallback interface { UploadProgress(progress *UploadProgress, err error) }

type RecordLifecycleEvent struct {
    Kind      string   // "expired" | "tombstoned" | "read_elsewhere"
    GroupId   string
    MessageId string
    Seq       int64
    Dropped   int64
}
type RecordLifecycleListener interface { RecordLifecycle(event *RecordLifecycleEvent) }
```

`DeleteForEveryone` writes a TOMBSTONE, MLS-authenticated from the original sender — MASTER §12.1: a
deletion cannot be forged. `DeleteLocal` is local-only, does not affect anyone else, and says so in
the UI copy.

`Kind == "gap"` is a first-class entry type: an undecryptable or missing record renders as a visible gap
with its reason. `GapReason` is a **closed set**: `"expired"`, `"out_of_window"`, `"not_a_member_yet"`,
`"withheld"`, `"no_wrap"`. Attachment outcomes are **not** gap reasons — a pruned or failed attachment is
an `AttachmentState`, so the client can tell "kept for a month and then pruned" from "the download
failed", which are different sentences to a user. A messenger that silently drops what it cannot read is
a messenger that cannot be trusted to have shown you everything.

```
MessageEntry.State is a CLOSED set:  "pending" | "sent" | "read" | "failed" | "expired"

  pending  in the local outbox; not yet accepted by the message server
  sent     accepted by the message server
  read     a read receipt was received (only when both sides have receipts on)
  failed   terminal; carries a Reason from the closed send-failure vocabulary
  expired  the disappearing timer elapsed and the key is gone

There is NO "delivered" state. URmessage does not claim delivery: the server does not know which
member a sender_handle belongs to (MASTER §9.5) and MUST NOT record which client fetched which
range (MASTER §9.7, Spec B §11.1). Per-member delivery is a V2 item gated on a client-emitted
delivery receipt.
```

**Event delivery.**

1. Every event payload A delivers carries `Dropped int64` (events discarded from this `Sub`'s bounded
   256-event queue since the last successful delivery) and `Seq int64` (a per-`Sub` monotonic sequence
   number). Both appear on **every** event struct, not only listener events.
2. On any event with `Dropped > 0`, the client MUST treat its view of that group as **stale**: discard
   the in-memory window, re-read via `History()`, and re-evaluate unread. It MUST NOT merge a post-drop
   event into the existing list.
3. `AddMessageListener("" , listener)` subscribes to **all** groups. The client holds exactly one
   all-groups `Sub` plus at most one per open conversation.
4. `AddRecordLifecycleListener(listener) *Sub` is **client-wide** and delivers
   `RecordLifecycleEvent{Kind, GroupId, MessageId, Seq, Dropped}` with
   `Kind ∈ {"expired", "tombstoned", "read_elsewhere"}`. A raises it for **every** expiring record from
   the expiry sweep, regardless of whether any group listener is attached — this is what makes toast
   revocation possible for a conversation the user never opened this session.
5. A single UI-side event applier keyed by `(groupId, messageId)`, idempotent, tolerating out-of-order
   arrival, using `Seq` to detect reordering rather than assuming it away.

**Ephemeral containment (requirement on this layer).** No `DURABLE`-class artefact may contain `EPH`
plaintext. Concretely: the search index **excludes `EPH` records entirely**; `Search` never returns a
snippet from an ephemeral record; a reply to an ephemeral message stores `ReplyToId` only and never a
copy of the quoted text; `EntryDetail` on an expired record returns metadata with `Text == ""`. Asserted
by extending `TestExpiredMessageIsUnrecoverable` to the search index and the reply path.

`MessageSendTicket` has `Cancel()` and `Await()`; `Await` is not exposed over the ABI (§9.5).

### 7.5 Devices — MASTER §5.4, §11

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

// v1 is desktop-to-desktop with no camera on either end, so the TYPED path is primary
// and the QR is the convenience. Both sides still compare the SAS.
func (self *MessageDeviceLinkSession) PairingCode() string
// 8 groups of 4 uppercase Crockford base32 characters = 160 bits of rendezvous entropy.
// Lifetime 10 minutes. The rendezvous is rate-limited to 5 attempts per code and 20 per
// client_id per hour; 5 failures burn the code. A short code is an online-guessing
// surface and these three numbers are what make it not one.
func (self *MessageClient) JoinDeviceLinkWithCode(code string,
    callback DeviceLinkCallback) *MessageDeviceLinkSession

// self-service revocation. MASTER §11: a member may add or remove THEIR OWN
// device leaves and commit that change, without an admin.
//
// per-group progress, because a Remove is one MLS Remove + one Commit in EVERY group the
// user belongs to and can partially succeed. The device is not revoked anywhere until
// its group's commit is accepted.
func (self *MessageClient) RemoveDevice(deviceId string, callback DeviceRemovalCallback) *MessageSendTicket

type DeviceRemovalProgress struct {
    DeviceId       string
    GroupId        string
    GroupName      string
    State          string   // "waiting" | "committing" | "done" | "failed"
    Reason         string   // §7.2 vocabulary 2 when State == "failed"
    GroupsDone     int32
    GroupsTotal    int32
}
type DeviceRemovalCallback interface {
    DeviceRemovalChanged(progress *DeviceRemovalProgress, err error)
}
```

`DeviceLinkState`'s fields are defined in §7.7.

The provisioning bundle carries the group list and **durable-class** archive material only.
Ephemeral-class material is never included (MASTER I4). `TestProvisioningBundleHasNoEphemeral`
asserts by construction: the bundle builder takes a `DurableArchive` type that has no field capable
of holding an `eph_root`.

### 7.6 Verification — MASTER §10, SSH-style TOFU

```go
func (self *MessageClient) SafetyNumber(principal string) (string, error)  // 12 groups of 5 digits
func (self *MessageClient) Pins() *MessagePinList
func (self *MessageClient) PinFor(principal string) *MessagePin
// the SSH changed-host-key moment. Blocking in the UI; this is the "I accept" call.
// newKeyFingerprint MUST match the fingerprint the user was shown; if the key changed
// again between the modal opening and the click, this returns an error and the UI
// re-opens the modal with the new evidence rather than accepting a key nobody saw.
func (self *MessageClient) AcceptKeyChange(principal string, newKeyFingerprint string) error
func (self *MessageClient) MarkVerified(principal string, viaSafetyNumber bool) error
func (self *MessageClient) AddKeyChangeListener(listener KeyChangeListener) *Sub

// ── directory (MASTER §10.1; the operator side is slice 9) ─────────────────
func (self *MessageClient) LookupPrincipal(query string,
    callback DirectoryCallback) *MessageSendTicket

// ── integrity ──────────────────────────────────────────────────────────────
func (self *MessageClient) AddIntegrityListener(listener IntegrityListener) *Sub
func (self *MessageClient) ResyncGroup(groupId string, callback SyncCallback) *MessageSendTicket

type MessagePin struct {
    Principal        string
    KeyFingerprint   string
    FirstSeenMs      int64
    LastConfirmedMs  int64
    EvidenceClass    string
    SignedByOldKey   bool
    Verified         bool     // set only by MarkVerified; NO badge is rendered from this in v1
    ChangePending    bool     // true while a KeyChangeWarning is unacknowledged
}

type KeyChangeWarning struct {
    Kind               string   // "key_changed" | "member_added_with_changed_key"
    Principal          string
    GroupId            string   // set iff Kind == "member_added_with_changed_key"
    OldKeyFingerprint  string
    NewKeyFingerprint  string
    FirstSeenMs        int64    // when the OLD key was first pinned — from MessagePin.FirstSeenMs,
                                // joined here so Spec C never has to fetch two objects for one modal
    ChangedAtMs        int64
    EvidenceClass      string
    SignedByOldKey     bool
    SharedGroupIds     *StringList
    Seq                int64
    Dropped            int64
}

type MessageDirectoryResult struct {
    Principal              string
    DisplayName            string
    IdentityKeyFingerprint string
    ProofState             string   // CLOSED: "included" | "proof_missing" | "log_unavailable"
}
type DirectoryCallback interface {
    DirectoryResult(results *MessageDirectoryResultList, err error)
}
// Resolution WITHOUT an inclusion proof fails closed: a result with ProofState other than
// "included" MUST NOT be used to start a conversation. Before slice 9 every lookup returns
// "log_unavailable" and Spec C renders that state explicitly.

type IntegrityEvent struct {
    Kind                string   // CLOSED: "fork" | "attestation_gap" | "server_key_change"
    GroupId             string
    Epoch               int64
    OursHex             string   // fork: our confirmed_transcript_hash
    TheirsHex           string   // fork: the peer's
    MessageId           string   // attestation_gap
    AttestationServerTimeMs int64
    CoveredSinceRecordId    int64
    CoveredUntilRecordId    int64
    ServerHost          string   // server_key_change
    OldKeyFingerprint   string
    NewKeyFingerprint   string
    FirstSeenMs         int64
    ChangedAtMs         int64
    Seq                 int64
    Dropped             int64
}
type IntegrityListener interface { IntegrityChanged(event *IntegrityEvent) }
```

```go
// KeyChangeWarning.EvidenceClass and MessagePin.EvidenceClass. CLOSED SET.
//   "kt_inclusion"        the KT log shows the new key included, with a valid inclusion proof
//   "operator_assertion"  the operator asserted the new key; no prior key signed it
//   "operator_reset"      the operator asserted it as part of a MASTER §5.5 identity reset
//   "kt_unavailable"      no KT log was reachable; the change is unattested (pre-slice-9 default)
//   "unknown"             none of the above could be established
// RESERVED, never emitted in v1: "self_signed_rotation" (V2; requires a rotation record
//   signed by the pinned key, which v1's seed-derived identity makes unnecessary).
```

**Where a key change blocks, and where it does not:**

**In a DM with the changed contact:** blocking modal, outbound sending to that conversation disabled until
resolved.

**In a group containing them:** a permanent, non-dismissible in-thread record plus a non-blocking bar.
**Sending stays enabled**, because the changed key is not in the group's ratchet tree and cannot read
anything sent there.

**New blocking condition:** an `Add` committing a member whose identity key differs from a pin the user
holds. This is blocking for that group, with its own permanent record, and its own copy:
*"Bo was added to this group with a different safety number than the one you have seen."*

There is **no verified badge in v1** (MASTER §10.2, ledger I4). `MessagePin.Verified` exists for a future
release and for the "you verified this on 3 March" line in a contact detail sheet; Spec C must not
render it as a badge in a message list. Stated here because it is the kind of decision that gets
quietly reversed by a UI ticket.

Key-transparency: every resolution requires an inclusion proof; signed tree heads are gossiped over
two paths (message server and peer clients). `sdk/message_kt.go` refuses a resolution with no proof
and surfaces `KtProofMissing`, which is a hard failure, not a warning. Until slice 9 exists,
`EvidenceClass` reports `"kt_unavailable"` — **not** `"unsigned"`, which is not a member of the closed
set — and Spec C renders that row explicitly.

**Server key changes.** When a server key change is accepted via `AcceptServerKey`, A MUST discard
every retained `FetchAttestation` signed under the old key rather than silently trusting it, and MUST
report the invalidated `(since, until)` range on the `server_key_change` `IntegrityEvent` so Spec C can
name it in the modal.

### 7.7 Listeners

One-method interfaces, matching the existing sdk convention, so the cgo generator maps each to a
single C function pointer.

Every payload type reachable from `MessageClient` has its fields defined here; a callback payload
that is named but not defined is what makes Spec C unbuildable.

```go
type SyncListener          interface { SyncStateChanged(state *SyncState) }
type HealthListener        interface { HealthChanged(event *MessageHealthEvent) }
type GroupListener         interface { GroupChanged(event *GroupEvent) }
type MessageListener       interface { MessageChanged(event *MessageEvent) }
type KeyChangeListener     interface { KeyChanged(warning *KeyChangeWarning) }
type IntegrityListener     interface { IntegrityChanged(event *IntegrityEvent) }
type RecordLifecycleListener interface { RecordLifecycle(event *RecordLifecycleEvent) }
type SendCallback          interface { SendResult(result *SendResult, err error) }
type UploadCallback        interface { UploadProgress(progress *UploadProgress, err error) }
type GroupCallback         interface { GroupResult(result *GroupResult, err error) }
type RestoreCallback       interface { RestoreProgress(progress *RestoreProgress, err error) }
type DownloadCallback      interface { DownloadProgress(progress *DownloadProgress, err error) }
type DeviceLinkCallback    interface { DeviceLinkChanged(state *DeviceLinkState, err error) }
type DeviceRemovalCallback interface { DeviceRemovalChanged(progress *DeviceRemovalProgress, err error) }
type SyncCallback          interface { SyncResult(result *SyncResult, err error) }
type DirectoryCallback     interface { DirectoryResult(results *MessageDirectoryResultList, err error) }

type MessageEvent struct {
    Kind      string   // CLOSED: "appended" | "state_changed" | "reactions_changed"
                       //       | "read_changed" | "typing_changed" | "removed" | "gap"
    GroupId   string
    Entries   *MessageEntryList   // "appended"
    MessageId string              // "state_changed" | "removed" | "gap"
    State     string
    Reason    string
    TypingIds *StringList         // "typing_changed"
    Seq       int64
    Dropped   int64
}

type GroupEvent struct {
    Kind             string   // CLOSED: "created" | "changed" | "members_changed"
                              //       | "policy_changed" | "sendability_changed"
                              //       | "invited" | "left" | "removed" | "closed"
                              //       | "history_granted"
    GroupId          string
    Group            *MessageGroup
    Sendability      *MessageSendability
    RetentionApplied *MessageRetentionApplied
    Seq              int64
    Dropped          int64
}

// Seconds, not milliseconds: this struct is a field-for-field mirror of the message
// server's RetentionApplied, and every retention value in the system is seconds
// (EpochAttachment.media_ttl_seconds / durable_ttl_seconds, media_ttl_max_seconds,
// durable_retention_min_seconds). The two differ only in Go casing. DurableTtlSeconds
// == 0 means INDEFINITE, never "zero seconds", and DurableFlooredUp is then false.
type MessageRetentionApplied struct {
    MediaTtlSeconds            int64
    DurableTtlSeconds          int64
    MediaClampedDown           bool
    DurableFlooredUp           bool
    RequestedMediaTtlSeconds   int64
    RequestedDurableTtlSeconds int64
}

type MessageGroup struct {
    GroupId            string
    Name               string
    IsDirect           bool
    MemberCount        int32
    PreviewText        string   // "" for an EPH conversation — the list must not cache it
    PreviewClass       string   // "text"|"attachment"|"system"|"eph"|"none"
    PreviewSenderId    string
    LastActivityMs     int64
    UnreadCount        int32
    Muted              bool
    DisappearingBucket int32
    RetentionDurableMs int64    // effective policy, as applied by the server
    RetentionMediaMs   int64
    ReadReceipts       bool
    TypingIndicators   bool
    NotificationMode   string   // "default" | "name_and_message" | "name_only" | "nothing"
    MyRole             string
    Closed             bool
}

type MessageMember struct {
    MemberId          string
    Principal         string
    DisplayName       string
    IdentityPublicKey []byte   // Spec C §11.5 derives the identicon from THIS
    KeyFingerprint    string
    Role              string
    DeviceCount       int32
    LeafIndex         int32
    Pinned            bool
    ChangePending     bool
}

type MessageInvite struct {
    InviteId              string
    GroupId               string
    GroupName             string
    InviterMemberId       string
    InviterPrincipal      string
    InviterDisplayName    string
    InviterKeyFingerprint string
    MemberCount           int32
    CreatedAtMs           int64
    ExpiresAtMs           int64    // 0 = no expiry
    State                 string   // CLOSED: "pending" | "accepting" | "accepted"
                                   //       | "declined" | "expired"
}

type MessageReaction struct {
    Emoji     string        // one member of the v1 set; see Spec C §5.2a
    Count     int32
    MemberIds *StringList   // who reacted, in first-seen order
    MineSet   bool          // this device's own account is among them
}

type MessageReceipt struct {
    MemberId string
    ReadAtMs int64
}

type MessageHistoryGrant struct {
    GrantId               string
    GranteeMemberId       string
    GranteePrincipal      string
    GranteeDisplayName    string
    GrantedByMemberId     string
    GrantedByDisplayName  string
    FromEpoch             int64
    FromMs                int64
    GrantedAtMs           int64
}

type MessageDevice struct {
    DeviceId    string
    Name        string
    AddedAtMs   int64
    LastSeenMs  int64
    IsThisDevice bool
    LeafIndex   int32
}

type DeviceLinkState struct {
    SessionId  string
    Role       string   // "existing" | "new"
    State      string   // CLOSED: "waiting" | "code_shown" | "peer_joined" | "sas_compare"
                        //       | "approved" | "refused" | "timed_out" | "failed"
    PairingCode string
    AuthString string
    Reason     string
}

type SyncResult   struct { GroupId string; RecordsFetched int32; Complete bool; Reason string }
type SendResult   struct { GroupId string; MessageId string; State string; Reason string }
type GroupResult  struct { GroupId string; Kind string; Reason string
                           PartialInvites *StringList /* principals whose invite failed */ }
type RestoreProgress struct { Phase string; GroupId string; GroupName string
                              MessagesDone int64; MessagesTotal int64
                              GroupsDone int32; GroupsTotal int32
                              Outcome string /* "full"|"partial"|"nothing_found"|"read_only" */
                              Reason string }
type DownloadProgress struct { GroupId string; MessageId string; AttachmentId string
                               BytesReceived int64; BytesTotal int64; LocalPath string }
```

`MessageInvite`, `MessageReaction`, `MessageReceipt` and `MessageHistoryGrant` each get a `*List`
wrapper per the §7.1 pattern: `MessageInviteList`, `MessageReactionList`, `MessageReceiptList`,
`MessageHistoryGrantList`.

There is no `GroupDetails(groupId)` call. `Group(groupId)` already returns the snapshot and now
carries every field a details screen renders; a second accessor returning the same data under
another name is the kind of drift this pass exists to remove.

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
| **BIP39 entropy (256 bits)** | keyfile | **yes**, DPAPI context `"seed_entropy"` | `RemoveIdentity()` |
| `master_key` children (`identity` priv, `recovery_root`, `recovery_sig_seed`) | keyfile | **yes** | identity reset |
| **`phrase_confirmed_at` (unix ms)** | keyfile | **yes** | `RemoveIdentity()` |
| `device_sig` (Ed25519 leaf key), `device_xwing` (X-Wing seed) | keyfile | **yes** | device removed from all groups |
| MLS group state per (group, epoch) | SQLite `mls_state` | **yes**, per-row blob | `DeleteGroupStateBefore`, epoch window 8 |
| MLS private keys by public key | SQLite `mls_private` | **yes**, per-row | key superseded or leaf removed |
| Pending KeyPackages + their private halves | SQLite `mls_keypackage` | **yes** | Welcome consumed, or 30-day lifetime expiry |
| `eph_root[n]` | SQLite `eph_root`, inside the epoch state row | **yes** | window closes, or epoch falls out of the window |
| Record ciphertext (as received) | SQLite `record` | no — it is already ciphertext | retention class + `expire_at` |
| Decrypted display cache (text, sender, timestamps) | SQLite `entry` | **yes**, one blob per group | group left, message deleted, disappearing timer |
| Attachment blobs | files under `StorageDir/media/` | file body encrypted under the message's class key | MEDIA retention, 1 month default |
| TOFU pins, KT tree heads | SQLite `pin`, `kt_head` | no (public data), but integrity-MAC'd | never |
| `stream_index` high-water marks | SQLite `stream`, `PRAGMA synchronous=FULL` on that table's writes | no | never |
| Fetch attestations covering the high-water range | SQLite `attestation` | no | superseded by a wider covering attestation |
| **Server-advertised limits, pin state, `capability_version`** | SQLite `server_info` | no (public data), integrity-MAC'd | never; refreshed on `CapabilityChange` |
| `server_nonce` | memory only | — | reconnect |

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
    RecordsAfter(groupId []byte, afterRecordId uint64, limit int) ([][]byte, error)
    DeleteRecords(groupId []byte, recordIds []uint64) error

    PutEntries(groupId []byte, entries []StoredEntry) error
    EntriesBefore(groupId []byte, beforeId string, limit int) ([]StoredEntry, error)
    EntryById(groupId []byte, id string) (StoredEntry, error)
    SearchEntries(groupId []byte, query string, limit int) ([]StoredEntry, error)  // nil groupId = all
    DeleteEntries(groupId []byte, ids []string) error
    ExpireEntriesBefore(nowMs int64) (int, error)

    ReserveStreamIndex(groupId []byte, index uint64) error
    StreamHighWater(groupId []byte) (uint64, error)

    Vacuum() error
}
```

Fourteen methods. That bound is the point (A8): if `modernc.org/sqlite` has to go, this is what has to
be reimplemented.

**Store-open failure is an explicit value, never an empty result.** `Open` returns a typed error whose
reason is one of `unseal_failed`, `corrupt`, `disk_full`, `locked_by_another_process`; the client enters
health state `store_unavailable` with that reason. `Groups()` and `History()` MUST NOT return
empty in this condition — Spec C would then render "No conversations yet" to a user whose entire history
is intact on the server.

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
`golang.org/x/sys/windows.CryptProtectData` / `CryptUnprotectData` — already in `sdk`'s pinned
dependency set, no new module.

| Parameter | Value |
|---|---|
| Scope | **User** (no `CRYPTPROTECT_LOCAL_MACHINE`) — a machine-scope blob is readable by every account on the box |
| Flags | `CRYPTPROTECT_UI_FORBIDDEN` — the DLL may be called from a background thread and must never raise UI |
| Optional entropy | the 32 bytes in `entropy.bin`, mixed with a per-context label so a blob sealed for `"mls_state"` cannot be unsealed as `"keys"` |
| `promptStruct` | nil |
| Description | `"URmessage local key material"` |

`Description()` returns
`"Protected by Windows DPAPI for your user account. This protects your messages from other accounts on this PC and from someone reading the disk. It does not protect against software running as you."`
Spec C renders that string verbatim. It is a factual limit of DPAPI and MASTER §13's honesty standard
applies to it.

**Other platforms:** `message_seal_portable.go` derives a key from a platform keystore where one
exists (macOS Keychain via `security`, Linux via the Secret Service where present) and otherwise
falls back to a 0600 keyfile with a loud `Description()` saying the material is protected by file
permissions only. Mobile lands with the platform keystores in slice 7+.

The entropy file is created with an explicit owner-only DACL on Windows (not just `0600` semantics,
which Go maps loosely on NTFS). `TestEntropyFileAcl` asserts the DACL on Windows CI.

### 8.4 Deletion actually deleting

Three mechanisms, because SQLite `DELETE` alone leaves page contents in the freelist and the WAL:

1. `PRAGMA secure_delete = ON` at open — overwrite deleted content with zeros.
2. `PRAGMA auto_vacuum = FULL` plus an explicit `Vacuum()` after any bulk expiry, so freed pages are
   released rather than retained.
3. `PRAGMA journal_size_limit` bounded and a WAL checkpoint (`TRUNCATE`) after every expiry pass, so
   the WAL does not retain the deleted rows.

`TestExpiredMessageIsUnrecoverable` is the end-to-end proof of MASTER §12.1's second guarantee: send
an ephemeral message, advance the clock past its window, close the client, then open the raw DB file
and the raw record store and assert the plaintext, the entry blob, and the `eph_root` are all absent
— and assert that a **freshly provisioned** device and a **seedphrase-only** restore both fail to
decrypt it. That single test is the difference between the feature working and the feature being a
UI label.

---

## 9. `URmessageSdk.dll` — the cgo export surface

### 9.1 Why it is separate

`sdk/cgo` generates 10,444 lines of `urnet_*` exports by walking the whole `github.com/urnetwork/sdk`
surface, and it carries an ABI baseline test (`sdk/cgo/gen/abi_baseline_test.go`) that fails on any
symbol change. Adding a messaging surface there would (a) put every VPN export in the messaging DLL,
(b) put every messaging export in `URnetworkSdk.dll`, and (c) make any messaging-driven generator
change perturb the VPN ABI baseline — a shipped, signed, in-production artifact.

`sdk/cgo-message` is a new module with its own generator, its own `urmsg_` prefix, its own baseline,
and its own `.def`. **VPN builds are untouched.** Per decision A12 the two DLLs are never loaded into
the same process: `URmessage.exe` loads `URmessageSdk.dll` only, so there is exactly one Go runtime in
the messaging process, and `URmessageSdk.dll` exports the URnetwork account surface itself under the
`urmsg_auth_*` prefix.

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

Session lifecycle, account and identity:

```c
/* session lifecycle */
uint64_t urmsg_client_open(const char* settings_json, char** out_error);
void     urmsg_client_close(uint64_t client);

/* account — this DLL owns login (decision A12). URnetworkSdk.dll is NOT loaded. */
uint64_t urmsg_auth_login_begin(uint64_t client, const char* request_json,
                                urmsg_auth_cb cb, void* user_data);
bool     urmsg_client_set_by_jwt(uint64_t client, const char* jwt, char** out_error);
bool     urmsg_client_by_jwt_state(uint64_t client, char** out_state);

/* identity */
bool     urmsg_generate_seedphrase(char** out_phrase, char** out_error);
bool     urmsg_client_create_identity(uint64_t client, const char* phrase, char** out_error);
bool     urmsg_client_reveal_seedphrase(uint64_t client, char** out_phrase, char** out_error);
bool     urmsg_client_remove_identity(uint64_t client, char** out_error);
bool     urmsg_client_mark_phrase_confirmed(uint64_t client, char** out_error);
int64_t  urmsg_client_phrase_confirmed_at_ms(uint64_t client);
bool     urmsg_client_has_identity(uint64_t client);
bool     urmsg_client_identity_safety_digits(uint64_t client, char** out_digits);
bool     urmsg_client_identity_short_fingerprint(uint64_t client, char** out_fp);
bool     urmsg_client_start(uint64_t client, char** out_error);
```

**The `settings_json` schema.**

```jsonc
// urmsg_client_open(settings_json, out_error). All keys required unless marked optional.
{
  "storage_dir":        "string",   // absolute path, per-user, writable. NOT %PROGRAMDATA%.
  "network_space_host": "string",   // e.g. "ur.network"; the URnetwork network space
  "message_server_id":  "string",   // the one server's URnetwork client id (UUID string),
                                    // from the build-time constant kMessageServerClientId
                                    // or, when set, from the operator discovery response
  "enable_cover":       false,      // optional, default false  (MASTER §9.5)
  "media_cache_bytes":  1073741824  // optional, default 1 GiB
}
```

**Why there is no `urnet_device_handle` parameter.** An earlier revision took one, then struck it,
because a handle is an id in the *other* DLL's registry and resolving it cross-runtime is a lookup
failure at best. Decision A12 removes the question entirely: there is no other DLL in the process. The
messaging DLL constructs its own `connect.Client` and owns its own account session.

Groups, messaging, devices, verification: one export per §7 method, generated. Illustrative:

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

### 9.4 Memory ownership — the whole table, because this is where cgo bugs live

| Crossing | Allocated by | Freed by | Rule |
|---|---|---|---|
| `char*` **returned** by any `urmsg_*` | Go, via `C.CString` (malloc) | **C caller**, via `urmsg_free_string` | Never `free()` it with the CRT directly — the DLL and the app may link different CRTs. `urmsg_free_string` frees in the DLL's heap. |
| `char** out_error` | Go, on error only | C caller, via `urmsg_free_string`, **only if non-NULL after the call** | Every fallible export sets `*out_error` to NULL on success. C code must initialize it to NULL and check. |
| `const char*` **passed in** | C caller | C caller | Go copies with `C.GoString` before returning. The DLL never retains the pointer. |
| `const uint8_t*, int32_t` **passed in** | C caller | C caller | Go copies with `C.GoBytes`. Valid only for the duration of the call. |
| `uint8_t* out, int32_t* inout_len` | **C caller** | C caller | Buffer-out pattern: `*inout_len` is always set to the needed size; the copy happens and `true` is returned only when `out != NULL` and the passed capacity suffices. Call twice: once with `out = NULL` to size, once to fill. |
| `uint64_t` handle | Go registry | C caller, via `urmsg_release` (or `urmsg_client_close` for the client) | Ids are **never reused**, so a stale handle can never resolve to a new object — it resolves to nothing and the call returns false. |
| `void* user_data` on a listener | C caller | C caller, **after** the `Sub` handle is released and `urmsg_release` has returned | See §9.5. This is the ordering that gets got wrong. |
| Bytes handed to a **callback** | Go | nobody — borrowed | Valid only for the duration of the callback. C must copy to retain. Mirrors `connect`'s message-pool borrow rule. |
| Go pointers into C | never | — | No Go pointer is ever stored in C memory. C function pointers and `void*` stored in Go structs are fine and are what the generated `cAdapter*` types do. |

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
   dispatcher queue itself. Documented in the header, in the `.hpp` wrapper, and in Spec C §.
3. **Callbacks may arrive re-entrantly with respect to the call that registered them.**
   `urmsg_client_add_message_listener` may fire before it returns. The C++ wrapper must not hold a
   lock across registration.
4. **Unregister is synchronous and final.** `urmsg_release(sub)` does not return until no callback is
   executing and none will start. It is implemented with a per-`Sub` `sync.WaitGroup` plus a
   `closed` flag checked inside the adapter under the same lock that `release` takes. Without this,
   `user_data` can be freed while a callback is mid-flight — the single most common crash in this
   class of binding.
5. **`user_data` lifetime is: allocate before register, free after `urmsg_release` returns.**
   Stated in the header next to every `_cb` typedef, because rule 4 is worthless if the caller frees
   early.
6. **No callback may re-enter the DLL synchronously on the same goroutine.** A callback that calls
   `urmsg_client_send_text` from inside `MessageChanged` deadlocks against the group command loop.
   The adapter therefore dispatches every listener callback from a dedicated per-`Sub` goroutine with
   a bounded queue (256 events); overflow drops the oldest and increments a `Dropped` counter. The
   counter appears on **every** event payload, not only the next one after an overflow, alongside a
   per-`Sub` monotonic `Seq`. Documented; asserted by `TestCallbackReentrancy`.
7. **Errors are strings, not codes.** `char** out_error` carries `err.Error()`. There is no numeric
   error enum across the ABI, because the set is open and a stale numeric mapping is worse than a
   string. Programmatic cases (key change, gap, retention applied) come through **events**, which
   are JSON with a stable `kind` field.

   **Reason strings are not `out_error` strings.** `char** out_error` carries `err.Error()` — open,
   human-readable, never parsed. Separately, `MessageSendability.Reason`, `MessageEntry.Reason`,
   `MessageHealthEvent.State`/`.Reason`, `MessageEntry.GapReason`, `MessageAttachment.State`,
   `KeyChangeWarning.EvidenceClass`, `IntegrityEvent.Kind`, `MessageDirectoryResult.ProofState` and
   `DeviceLinkState.State` are **closed, versioned vocabularies** carried in JSON events with a stable
   `kind` field. Spec C switches on those; it never parses `out_error`. A new value in any of these
   vocabularies is a spec change in this document and a `TestVocabulariesAreClosed` failure, not a silent
   addition.

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
handles — the failure mode that otherwise shows up as a slow memory climb in production.

---

## 10. Binding to `connect`

### 10.1 Frames

Four new `MessageType` values in `connect/protocol/frame.proto`, in a reserved high block so parallel
beta branches (`beta/algorithm-dpi`, `beta/custom-server`) do not collide on the shared file:

```proto
    // ── URmessage (beta/message). Block 1000-1099 reserved so parallel beta
    // branches do not collide. Every operation lives in a oneof inside
    // MessageServerRequest/Response/Push, NOT as its own MessageType.
    MessageServerRequest  = 1000;
    MessageServerResponse = 1001;
    MessageServerPush     = 1002;
    MessageServerFragment = 1003;
```

Spec A owns the file `connect/protocol/message.proto` and its codegen (it is generated by the existing
`connect/protocol/Makefile` and linked by both the client and the server). Spec B owns the set of `oneof`
arms and their semantics. A change to the file is an A commit; a change to an arm's meaning is a B
decision recorded in `SPEC-LEDGER.md`.

There is no `MessageEnvelope`, no `MessageOp` and no `MessageStreamAck`. An earlier revision of this
document proposed them; Spec B's binding supersedes them, flow control is B's `Backpressure` push, and
the `server_nonce` is a property of the connection rather than a field of the request (§5.7).

Everything rides the existing addressed `Send` / `AddReceiveCallback` path, so message traffic gets the
same contract, relay and per-peer hybrid transit encryption (`transfer_encrypt.go:378` leads with
`tls.X25519MLKEM768`) as everything else. Older clients ignore unknown message types, so this is not a
compatibility break.

### 10.2 What `connect` gives us and what it does not

| Need | `connect` | Us |
|---|---|---|
| Addressed client-to-client delivery | `Client.Send`, `SendWithTimeout`, `SendMultiHop`, `AddReceiveCallback` | — |
| Reliable ordered delivery within a session | yes, the sequence machinery | — |
| Per-peer transit encryption, hybrid PQ | yes | — |
| Contracts and billing | `ContractManager.CreateContract`, needs a `ByJwt` | supply the ByJwt from the existing account |
| **Store and forward** | **no — verified absent in `transfer.go`** | the message server (Spec B) |
| Push wake-up | no | §14 open item 9 |
| Long-lived provider-terminated contract per (device, message server) | shaping only | MASTER §9.6; we request this shape |

### 10.3 Transport identity is not messaging authorization

`server/connect/transport.go:471-501` authenticates a session with `ParseByJwtForAudience` +
`ValidateByJwtState` + a network-membership lookup. There is no challenge-response; `ByJwt` is a pure
bearer token and every check reads a database the operator owns. MASTER §4.3.

`sdk/message_transport.go` therefore treats a live `connect` session as evidence of **transport
authorization only**. Every group write carries `write_auth` (§5.7), and every message's authenticity
is MLS's (MASTER I5). A code review rule: no function in `sdk/message_*.go` may branch on ByJwt
contents for anything but transport setup and billing display.

---

## 11. Testing strategy and CI gates

### 11.1 Test layers

| Layer | Where | What |
|---|---|---|
| Unit | alongside each file | tree math, codec, key schedule, X-Wing, ratchet |
| KAT / vectors | `connect/mls/*_kat_test.go` | the 16 families (§4.2.1), X-Wing draft vectors, our own pinned `StorageRoot` vector |
| Negative | `connect/mls/validation_*_test.go` | the 43 ValSem codes + 2 errata (§4.3) |
| Property / fuzz | `connect/mls/*_fuzz_test.go`, `connect/message/*_fuzz_test.go` | the 9 targets (§4.4) plus a record-codec target |
| Interop | `connect/mls/interop` | the mlswg harness (§4.2.2–4.2.4) |
| Interop vectors | `connect/message/vectors_test.go` | `testdata/message-server-vectors.json`, shared with the message-server repo |
| Integration, in-process | `connect/message/*_integration_test.go` | 3, 10, 50, 500-member groups with a fake delivery service; commit races; out-of-order receipt |
| Integration, cross-repo | `sdk/message_e2e_test.go` | two `MessageClient`s against a real message server binary from Spec B, over a loopback `connect` |
| ABI | `sdk/cgo-message/gen/abi_baseline_test.go`, `smoke/` | symbol stability; handle-leak zero at exit |
| Layering | `connect/layering_test.go`, `sdk/layering_test.go` | the forbidden import edges of §2.3 |
| Lint gates | `scripts/check-forbidden.sh` | the grep gates of §5.9 |

### 11.2 Tests that exist because a specific property would otherwise silently break

| Test | Property it protects |
|---|---|
| `TestEphRootHasNoDurableInput` | MASTER I4 / §8.1 — the disappearing guarantee |
| `TestExpiredMessageIsUnrecoverable` | end-to-end version of the same, across server, new device, and seed holder (§8.4) |
| `TestStreamIndexNeverReused` | MASTER I7 — no nonce reuse, across simulated crashes (§5.6) |
| `TestStorageRootKAT` | G1 — the `hkdf.Extract` argument order |
| `TestEpochSecretsAreClosed` | MASTER §8.2 — only the two named secrets are reachable |
| `TestProvisioningBundleHasNoEphemeral` | MASTER I4 |
| `TestEngineSwappable` | Gate 5 — the interface has not leaked |
| `TestProfileIsClosed` | §3.1 — no silent capability expansion |
| `TestValSem400_PastEpochBound` | bounded past-epoch retention, which OpenMLS does not implement |
| `TestEveryExportIsGuarded` | no panic unwinds into C |
| `TestCallbackReentrancy` | §9.5 rules 4 and 6 |
| `TestNoForbiddenCrypto` | `GenerateSharedSecret`, `box.Precompute`, `curve25519.ScalarMult` absent |
| `TestEntropyFileAcl` | owner-only DACL on Windows |
| `TestServerAttachmentRoundTripsAgainstVectors` | §5.11 — a zero-length attachment and `AttachmentNone` encode identically, so `H(server_attachment)` cannot differ between client and server |
| `TestLostCommitResamplesPqSecret` | §5.12 / G10 — MASTER §7's per-epoch PQ independence across a lost commit |
| `TestVocabulariesAreClosed` | §9.5 rule 7 — no silent addition to a closed reason vocabulary |
| `TestReadAuthNeverUsesWriteKey` | §5.7 — `req_auth` is MAC'd under `read_key`; no call path reaches `ComputeRequestAuth` with an epoch key |
| `TestBlobIdIsInBothPreimages` | §5.1 — a record with `size_bucket = 5` whose `blob_id` is altered fails both AEAD open and `VerifyWriteAuth`; a record with any other bucket encodes a zero-length `blob_id` prefix |

### 11.3 Running the suites

`connect` and `sdk` both ship `test.sh`, both zsh, both `-timeout 0 -race`, and `connect/test.sh`
runs timing-sensitive groups first in their own process. Follow the `urnetwork-workspace` skill:
`go test ./...` naively will hang or fail in ways that look like real bugs and are not.

`connect/mls` and `connect/message` have **no timing-sensitive tests** and must keep it that way — a
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
| `fuzz-short` (60 s × 10 targets, properties 1–2) | connect | every push/PR | yes |
| `mls-interop` (§4.2.4) | connect | every push/PR | yes |
| `message-server-vectors` | connect | every push/PR | yes |
| `gomobile-validate` (bind for android+ios, types only) | sdk | every push/PR | yes |
| `abi-baseline` + `smoke` + `smoke_hpp` | sdk | every push/PR | yes |
| `build-matrix` (5 targets, §9.6) | sdk | every push/PR | yes |
| `large` (500-member integration) | connect | every push/PR | yes |
| `e2e` (against Spec B's server binary) | sdk | every push/PR | yes |
| `fuzz-long` (4 h × 10, differential vs OpenMLS) | connect | nightly | no (P0 issue on failure) |
| `interop-random` (`deep_random.json`, logged seed) | connect | nightly | no (P0 issue) |
| `interop-public` (`-public` matrix) | connect | nightly | no |
| `peer-image-bump` | connect | weekly | opens a PR |
| `encoding-guard` | connect, sdk | every push/PR | yes |

`encoding-guard` fails the build on any occurrence, in `docs/**/*.md`, of the four byte runs that
double-encoded UTF-8 produces — the sequences U+00E2 U+20AC, U+00C2 U+00A7, U+00C3 U+00A2 and
U+00C3 U+201A — and asserts that `.gitattributes` contains the line
`*.md text working-tree-encoding=UTF-8 eol=lf`. The check is written against codepoints, never
against literal corrupted text, so the check's own source file does not trip it. Creating
`.gitattributes` and the job file is repo work, not a change to this document; the requirement lives
here.

### 11.5 The gomobile gate

`sdk`'s `build/Makefile` runs `gomobile bind` with a validation step listing expected skips. Messaging
types must produce **no new expected skips**. A type that gomobile cannot export is a design error in
the `sdk` surface, caught at PR time, not at release time when the Android client is being started.

---

## 12. Interfaces OUT

### 12.1 To the message server (Spec B)

**What Spec B imports from us.** `github.com/urnetwork/connect/message`, via the existing
`replace ../` in `server/go.mod`. This table is the single published version of that surface and is
restated character-for-character in Spec B §12.1 (A-1):

```go
// ── records ────────────────────────────────────────────────────────────────
func ParseRecord(b []byte) (*Record, error)
func EncodeRecord(r *Record) ([]byte, error)
func ParseRecordHeader(b []byte) (*RecordHeader, error)

// ── authenticators ─────────────────────────────────────────────────────────
func WriteAuthPreimage(serverNonce []byte, h *RecordHeader, ctHead []byte,
                       serverAttachment []byte) []byte
func ComputeWriteAuth(writeKey []byte, serverNonce []byte, h *RecordHeader,
                      ctHead []byte, serverAttachment []byte) [32]byte
func VerifyWriteAuth(writeKey []byte, serverNonce []byte, r *Record) bool           // constant time

func RequestAuthPreimage(serverNonce []byte, op uint8, requestBytes []byte) []byte
func ComputeRequestAuth(readKey []byte, serverNonce []byte, op uint8,
                        requestBytes []byte) [32]byte
func VerifyRequestAuth(readKey []byte, serverNonce []byte, op uint8,
                       requestBytes []byte, auth []byte) bool                        // constant time

func RecoveryProof(recoveryRoot []byte, serverNonce []byte,
                   recoveryHandle []byte) ([]byte, error)                            // Ed25519 sig
func VerifyRecoveryProof(recoveryVerifyPub []byte, serverNonce []byte,
                         recoveryHandle []byte, sig []byte) bool

// ── ladders ────────────────────────────────────────────────────────────────
func SizeBucketBytes(b SizeBucket) int          // body bytes EXCLUDING the 16-byte AEAD tag
func SizeBucketCtBodyBytes(b SizeBucket) int    // = SizeBucketBytes(b) + 16
func EphBucketSeconds(bucket uint8) int
func RetentionClassOf(wire byte) (RetentionClass, uint8, error)   // -> class, ephBucket
func RetentionClassWire(c RetentionClass, ephBucket uint8) byte
func ClassIsPrunable(c RetentionClass) bool

// ── server attachment ──────────────────────────────────────────────────────
func ParseServerAttachment(b []byte) (*ServerAttachment, error)
func EncodeServerAttachment(a *ServerAttachment) ([]byte, error)

// ── exported types ─────────────────────────────────────────────────────────
type Record, RecordHeader, RetentionClass, SizeBucket,
     ServerAttachment, EpochAttachment, RecoveryTag, WrapTag, EpochComplete
```

The server may use **only** this surface. It gets no decryption function, no key-schedule function, and no
MLS type. A test in the message-server repo asserts the allowlist. If Spec B ever needs more, that is a
design discussion, not a patch.

**What we require of the server.**

| # | Requirement | Source |
|---|---|---|
| S1 | Accept a record only if `VerifyWriteAuth` passes under `write_key[n]`, installed from the commit's `EpochAttachment.write_key` and held wrapped under a vault KEK | MASTER §9.2 |
| S2 | Enforce **monotonic**, not contiguous, `stream_index` per `(group_id, sender_handle)` — **not** per class | MASTER §8; a refused write must not brick the stream |
| S3 | Accept at most one `is_commit = 1` per `(group_id, epoch)`, first valid wins, never replaced; return the accepted commit to any later submitter | MASTER §9.3 |
| S4 | Reject records whose `epoch` is not the current accepted epoch | MASTER §9.3 |
| S5 | Index epoch wrap records by target: device wraps and the epoch snapshot by `wrap_target_handle` (16 B, from `WrapTag`), recovery wraps by `recovery_handle` (16 B, from `RecoveryTag`), both delivered inside the authenticated `server_attachment`. Serve a wrap by target in O(1). | §5.11, MASTER §8.2 |
| S6 | A commit's epoch bundle reaches ~6.9 MB at 500 members, every wrap padded to `size_bucket 2`. Per-record size caps apply to individual wrap records, never to the bundle. Honour the epoch-publication sequence of §5.11, including the `EpochComplete` marker. | §5.11 |
| S7 | Serve a `FetchAttestation` on every history fetch, with the field list and signing preimage of MASTER §9.4 — including `class_mask` and `heads_only` inside the signature | MASTER §9.4 |
| S8 | Advertise, as data the client can read before it acts: max blob bytes, media TTL cap and default, durable retention minimum, max records per fetch and submit, max submit bytes, max request bytes, max response bytes, blob chunk bytes, blob pad multiple, attestation support, and a monotonic `capability_version` | MASTER §12.2 |
| S9 | Supply a 32-byte `server_nonce` in `HelloResponse`, bound to the connection and valid for its life. **No rotation.** The nonce is not carried in requests. | MASTER §9.2 |
| S10 | Prune by retention class **and** `expire_at`, where `expire_at` may only shorten retention, never extend it; retain `ct_head` and `body_hash` when `ct_body` is erased | MASTER §8, §9.1, §12.2 |
| S11 | Never create, store, or transmit logs of client commands, transport connections, or a history of deleted records in production | MASTER §9.7 — an acceptance criterion, not a policy page |
| S12 | Never decrypt; never be consulted on group admission; never satisfy an MLS validity condition | MASTER I1, §4.2 |
| S13 | **Authorize reads.** `Fetch`, `Subscribe`, `GroupStatus`, `BlobGrant` and `WrapFetch` MUST carry and verify `req_auth` under the group's `read_key`, installed from `EpochAttachment.read_key` and identical in every epoch (§5.7). An unauthenticated read is a full metadata dump and a group-existence oracle. `RecoveryFetch` uses the Ed25519 recovery proof instead. | MASTER §9.1, §9.2 |
| S14 | Serve a wrap by target in O(1) from an authenticated `WrapFetch`, and return a defined refusal when the named target has no wrap at that epoch | §5.11, MASTER §8.2 |

**What we give the server.**

The server holds `write_key[n]` itself. It is delivered to the server by the committer inside the commit
record's `server_attachment` (`EpochAttachment.write_key`), over the connect session's own hybrid-PQ
encryption, and is stored wrapped under a vault KEK. Four consequences, all accepted:

1. A server holding `write_key` **can forge `write_auth`**. This changes nothing: the server is the party
   enforcing `write_auth`, so it could equally accept an unauthenticated record, and any record it injects
   fails MLS verification at every client (**I5**).
2. `write_key` is a label-separated HKDF child of `storage_root[n]`, so holding it yields neither
   `storage_root[n]` nor the sibling class keys `K_perm` / `K_durable` / `K_media` / `eph_root`. It MUST
   NOT be reused for any second purpose beyond `write_auth`.
3. The server retains the **current** epoch's key plus **one** briefly-retired predecessor (60 s), and
   nothing older.
4. `read_key` is a separate label-separated child of `storage_root[0]`, delivered in the same
   attachment, stored the same way, and **never** discarded while the group exists. It is what makes
   an offline member's catch-up possible; see §5.7.

An asymmetric per-epoch write proof (Ed25519 derived from `storage_root`, server holds only the public
half) removes the forgery capability at the cost of one signature per record. It is the right long-term
shape and is a **V2** item, not v1 text.

**Interfaces out → to Spec B.** The rows A-1…A-12 below are what Spec B's own interfaces-in table
consumes, with owners and slices:

| # | We supply | Where | Slice |
|---|---|---|---|
| A-1 | `connect/message`'s exported surface, exactly the block above | §12.1 | A6 |
| A-2 | The `server_attachment` encoding: `EpochAttachment`, `RecoveryTag`, `WrapTag`, `EpochComplete`, and the amended `write_auth` / `AAD_head` preimages | §5.11, §5.7 | A6 |
| A-3 | Size-bucket byte lengths **including the 16-byte AEAD tag**, as a table | §5.1 | A6 |
| A-4 | The eph-bucket → seconds table, bucket 0 defined as transient and never persisted | §5.1 | A6 |
| A-5 | `connect/protocol/message.proto` and its codegen | §10.1 | A7 |
| A-6 | The losing-committer contract, implemented in `sdk` — especially "never reuse `pq_secret[n+1]`" and "never reuse a consumed `stream_index`" | §5.12 | A7 |
| A-7 | Blob padding ladder (256 KiB multiple) and `blob_id` derivation from the record's key material | §5.13 | A9 |
| A-8 | The shared interop vector file `testdata/message-server-vectors.json` — records with epoch keys, nonces, expected verdicts, a commit-race scenario, a non-zero `expire_at` record, a `size_bucket = 5` record with a `blob_id`, one authenticated request per `req_auth` op byte (13, 14, 16, 17, 19) including a `WrapFetch`, a per-class stream-index collision case, and a `since_record_id = 0` fetch case. **A blocking CI job in both repos.** | §11.1, §11.4 | A6 |
| A-9 | A measurement of the platform transport's production `FramerSettings.MaxMessageLen` | §10.2 | A7, named owner required |
| A-10 | `ComputeRequestAuth` / `VerifyRequestAuth` and `RecoveryProof` / `VerifyRecoveryProof` | §5.7 | A6 |
| A-11 | `expire_at` as unix milliseconds, u64, big-endian, 0 = unset, on the wire and in both preimages; `connect/message` is the only producer of the preimage on both sides | §5.1, §5.7 | A6 |
| A-12 | `read_key` and its delivery: `EpochAttachment.read_key`, identical in every epoch, and `ComputeRequestAuth` / `VerifyRequestAuth` taking it rather than an epoch key | §5.7, §5.11 | A6 |

### 12.2 To the Windows messaging client (Spec C)

**What Spec C gets:** `URmessageSdk.dll`, `urmessage_sdk.h`, `urmessage_sdk.hpp` (C++/WinRT-friendly
wrapper over the C ABI, using `nlohmann/json` exactly as the VPN client's wrapper does), and
`urmessage_sdk.def`.

**What Spec C must supply.**

| # | Obligation |
|---|---|
| C1 | A writable per-user directory as `MessageClientSettings.StorageDir`. Not `%PROGRAMDATA%` — DPAPI is user-scoped and a shared directory defeats it. |
| C2 | Supply `settings_json` per the §9.3 schema: `storage_dir`, `network_space_host`, `message_server_id`. **No ByJwt at construction** and **no handle from another DLL** — this DLL owns login (A12). |
| C3 | Marshal every callback to the UI dispatcher. Callbacks arrive on Go goroutines. |
| C4 | Free every returned `char*` with `urmsg_free_string`; never with the CRT `free`. |
| C5 | Free `void* user_data` only after `urmsg_release(sub)` has returned. |
| C6 | Call `urmsg_client_close` before process exit, and assert `urmsg_live_handle_count() == 0` in debug builds. |
| C7 | Render `Sealer.Description()` verbatim in the security screen. |
| C8 | Render the required UI language of MASTER §12.4 verbatim for disappearing, delete-for-everyone, and the durable default. Never say "gone forever" for the durable class. |
| C9 | Render `Kind == "gap"` entries visibly, with the reason. Do not hide them. |
| C10 | Treat `KeyChangeWarning` as **blocking** — the SSH changed-host-key shape (MASTER §10.2). No verified badge (§7.6). |
| C11 | Never persist the seedphrase **words**. A persists the 256-bit entropy in the sealed keyfile and returns the words only through `RevealSeedphrase()`. C holds them for the life of the §6.2 protected screen and writes them to no file, no `prefs.json`, no clipboard history, and no log. |
| C12 | No administrator tunnel, no privileged service, no WFP, no wintun, no LocalSystem, no mTLS loopback RPC. This app forwards message traffic only. |
| C13 | Render `Sealer.Description()` verbatim in a Security screen. It is lint-checked like the MASTER §12.4 strings. |
| C14 | On any event with `Dropped > 0`, discard the in-memory window for that group and re-read via `History()`. Never merge a post-drop event. |
| C15 | Render every closed vocabulary of §9.5 rule 7 by switching on the value. Never parse `out_error`, and never invent a value the vocabulary does not contain. |

**What Spec C must not assume.** That `URnetworkSdk.dll` is present at all. Per decision A12 it is
never loaded into the messaging process: `URmessage.exe` loads `URmessageSdk.dll` only, and the
URnetwork account surface the client needs is exported from that DLL under the `urmsg_auth_*` prefix.

### 12.3 To the operator (`/server`, MASTER slice 9)

Out of scope for all three specs, listed so it is not lost: a discovery directory mapping
`principal → identity master key`, published to an append-only key-transparency log over a Merkle
prefix tree, serving inclusion proofs and signed tree heads (MASTER §10.1). `sdk/message_kt.go` is
written against this and fails closed until it exists; in slices 1–8 it runs against a local test
log, and `MessagePin.EvidenceClass` reports `"kt_unavailable"`, which the UI must show as its own row
(Spec C §7.3).

---

## 13. Slice sequencing for this spec

Refines MASTER §14 for the A-component only.

| # | Slice | Contents | Done when |
|---|---|---|---|
| A1 | `connect/mls/syntax` | codec, varint, vectors, optional | family 16 passes; fuzz properties 1–2 clean for 60 s × 3 targets |
| A2 | `connect/mls` crypto + tree | `crypto.go`, `hpke.go`, `tree_math.go`, `tree.go`, `tree_hash.go` | families 1, 2, 9, 10 pass |
| A3 | `connect/mls` schedule + framing | `key_schedule.go`, `secret_tree.go`, `framing.go`, `transcript.go` | families 3, 4, 5, 6, 7 pass |
| A4 | `connect/mls` group | `treekem.go`, `proposal.go`, `commit.go`, `group.go`, `validation.go`, `profile.go` | families 8, 11, 12, 13, 14, 15 pass; **Gate 1 and Gate 3 green** |
| A5 | `connect/mls/interop` | our gRPC client, vendored proto, CI job | **Gate 2 green**, both roles, three peers |
| A6 | `connect/message` | records, key schedule, X-Wing, ratchet, wraps, `write_auth`, `req_auth`, recovery proof, `server_attachment`, tombstones, padding, COVER | wire format frozen; X-Wing draft KAT vectors pass both directions; the recovery wrap carries `storage_root ‖ archive_secret`; the shared interop vector file is committed and green in **both** repos; `TestStreamIndexNeverReused` and `TestEphRootHasNoDurableInput` green |
| A7 | `sdk` client core | `MessageClient`, store, sealer, KT client, sync loop, transport binding, `connect/protocol/message.proto` | two clients exchange a message against Spec B's server in `e2e` |
| A8 | `sdk/cgo-message` | generator, exports, header, `.hpp`, smoke tests, build matrix, the `urmsg_auth_*` account surface | Spec C can build against the header; handle count zero at exit; §7 defines the fields of every type reachable from `MessageClient`; the `urmsg_auth_*` surface builds and the smoke test logs in |
| A9 | Disappearing, multi-device, attachments | `eph.go`, provisioning, blob handling | `TestExpiredMessageIsUnrecoverable` green |
| A10 | Fuzz hardening + audit prep | differential oracle, 14 clean nightlies, audit brief | **Gate 4 green**; Gate 6 scheduled |
| A11 | Push channel | `RegisterPushChannel` / `UnregisterPushChannel` in §7.2, server-side channel registry (Spec B), WNS renderer (Spec C §10.2) | a raw WNS wake delivers a toast for a record received while the app was closed |

A1–A5 are the schedule risk, and they are first because each has an objective completion test.
A1–A8 produce something two people can text on.

---

## 14. Open items (consolidated)

Item numbers are stable; items 1, 2, 3, 5, 8 and 12 are closed and are not renumbered.

| # | Item | Owner | Blocks |
|---|---|---|---|
| 4 | A-ASSUME-1 — `modernc.org/sqlite` in `sdk` | project owner | slice A7 |
| 6 | A-ASSUME-4 — `PrivateMessage`-only handshake policy | project owner | slice A4 |
| 7 | Skipped-key window size and per-group memory budget (§5.5) | Spec C | slice A6 |
| 8 | **RULED — warn and proceed both directions (MASTER §15 item 1). Closed.** | — | — |
| 9 | Push transport / WNS wake-up (MASTER open item 2). A exposes `RegisterPushChannel(uri string) error` and `UnregisterPushChannel() error` in §7.2 as no-op stubs, so wiring WNS later is not an ABI break; owned jointly with Spec C's C-6 and scheduled as slice A11 (§13). The Azure AD application registration WNS needs still has no named owner. | Spec A + Spec B + Spec C | post-A8 |
| 10 | `OWNER_SUCCESSOR_SET` extension placement (MASTER open item 4) | MASTER owner | V2 |
| 11 | Transcribe RFC 9420 errata 8745 and 8815 verbatim into `connect/mls/ERRATA.md` (§4.3) | implementer | slice A4 |
