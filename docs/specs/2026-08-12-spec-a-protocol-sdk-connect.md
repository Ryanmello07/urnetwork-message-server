# URmessage Spec A — Protocol, SDK and Connect

**Component:** `connect/mls`, `connect/message`, `sdk` client core, `URmessageSdk.dll`
**Branch:** `beta/message` on `Ryanmello07/urnetwork-connect` and `Ryanmello07/urnetwork-sdk`
**Date:** 2026-08-12
**Revision:** A-6 (the contact card gets the transport it was specified without: §5.14 owns the card encoding, the seedphrase-derived capability generations, the sealed 5238-byte deposit and the five rendezvous signature preimages, and S18 and A-18 require the server to carry it; the card's `State`, `Generation` and expiry become part of the SDK contract and the card is per identity rather than per device; auto-accept degrades to manual review under load; `succession_floor_too_short` and `card_not_live` join `GroupResult.Reason`; §5.7's recovery pin is scoped per group; §7.3b is scheduled in slice A7)
**Status:** Design, owner rulings applied
**Normative parent:** `docs/specs/2026-08-12-urmessage-protocol-design.md` (revision 9), hereafter **MASTER**
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
| MASTER protocol design | Revision 9, owner rulings applied |
| This spec | Revision A-6, owner rulings applied |
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
| A8 | Local message store is SQLite via `modernc.org/sqlite` (pure Go, no cgo) behind a 14-method `sdk.MessageStore` interface | The store needs indexed pagination, per-group cursors, and text search. Hand-rolling that is a large, bug-dense surface. `modernc.org/sqlite` is pure Go and gomobile-buildable. Accepted for v1. The interface is deliberately narrow so replacing it is a contained job. |
| A9 | Record ciphertext is stored **as ciphertext** in the local DB. Everything decrypted for display is encrypted **per row** under one `local_store_key`, with a plaintext metadata index — group id, timestamps, sender handle, message id, state — left indexable | No SQLCipher and no encrypted-DB dependency, and the SQLite dependency A8 takes still earns itself. A single sealed blob per group would have meant unsealing and re-serialising a group's entire history to append one message, and no index at all — which is the opposite of the reason for taking a database. Per-row AEAD keeps the query surface A8 exists for while leaving no plaintext body at rest. §8.3a specifies it. |
| A10 | Transport uses the existing `connect.Client` addressed send/receive path with four new `MessageType` frame codes in the reserved 1000-1099 block (§10.1) | `connect/transfer.go` already provides `Send`/`SendWithTimeout`/`AddReceiveCallback`. We add framing, not a transport. Confirmed no store-and-forward exists in `connect` — durability is the message server's job (Spec B). |
| A11 | Every exported ABI function is panic-guarded and every handle is registry-allocated with non-reusable ids | Copied deliberately from the proven `sdk/cgo/handles.go` design: a panic unwinding into C aborts the host process, and a reused handle id resolves a stale pointer to a live object. |
| A12 | `URmessage.exe` loads **`URmessageSdk.dll` only**. `URnetworkSdk.dll` is never loaded into the messaging process. `URmessageSdk.dll` therefore also exports the URnetwork account surface the messaging client needs, under the `urmsg_auth_*` prefix. | Two Go runtimes in one process means two `DLL_PROCESS_ATTACH` error-mode mutations, two signal-handler installations and two `SetUnhandledExceptionFilter` chains in the process that owns the UI (§14.1 trap 4 in Spec C is about exactly one of them), plus doubled resident memory — for the sole purpose of moving three strings across a DLL boundary. One runtime removes the problem instead of documenting it. VPN builds remain untouched: `URnetworkSdk.dll` is not modified. |
| A13 | No operator host is a compile-time constant anywhere in this component. `NetworkSpaceHost` is configuration with a runtime setter, and `MessageServerInfo.OperatorHost` names the message server's operator rather than "the" operator | MASTER §4.1 records that more than one operator exists and that two run today, and MASTER §2 makes a build that compiles one operator's host in as its only source a defect. The two hosts are independent: the client's operator carries this device's traffic, the message server's operator carries the server's, and a check written as though one operator sees the whole system is wrong. A CI grep asserts that no operator hostname literal appears outside the default-value declaration, mirroring the same gate on the server side (Spec B) |

### 0.3 Interfaces to the other two components

| Direction | Contract | Detail |
|---|---|---|
| A → B | Record wire format, `write_auth`, wrap indexing, commit-agreement semantics | §12.1 |
| B → A | Server-advertised limits, fetch attestation, epoch verification state | §12.1 |
| A → C | `URmessageSdk.dll` C ABI: handles, callbacks, memory ownership | §9, §12.2 |
| C → A | Storage root path, the network space host as configuration rather than a compile-time constant (A13), message server client id, foreground/background lifecycle, WNS channel URI. **Not** a ByJwt at construction and **not** a handle from another DLL — A owns login (A12). | §12.2 |
| A ↔ B | Both depend on `connect/message` for the record codec; the server imports it via `replace ../` and on `connect/protocol/message.proto`, which A owns and B's arms populate (§10.1). | §2.4 |

### 0.4 Open items

Open items are consolidated in §14, with stable numbers. There is no second list.

### 0.5 Assumptions to confirm

| Id | Assumption | Blast radius if wrong |
|---|---|---|
| A-ASSUME-1 | **CONFIRMED, not an assumption.** `modernc.org/sqlite` is accepted for the local store in `sdk`, behind the 14-method `sdk.MessageStore` interface. The gomobile `android/arm` build remains a CI gate (§11.4), not an open question. | — |
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
| 2026-08-12 | A-4 | Owner rulings applied. `modernc.org/sqlite` accepted and A-ASSUME-1 closed. Decision A9 replaced by per-row AEAD over a plaintext metadata index (§8.3a), with an optional PIN wrap and idle auto-lock (§8.6). `read_key` re-keyed from a group lifetime value to a per-epoch key with a 90-day server window and a `read_epoch` request field (§5.7, §5.11, §12.1). Delivery receipts added: `MessageEntry.State` gains `delivered`, `DeliveredTo`, a user preference, and an `EPH(0)` receipt record (§7.4). A second ciphersuite registered (§3.1). Extension `0xF003` accepted and owner succession specified (§3.4, §7.3a). Group size capped at 500 and devices at 10, both client-enforced (§3.1). `PastEpochWindow` raised to 32 (§4.3). Invite links, join requests, ownership transfer, balance-code redemption, directory listing, diagnostics and fork auto-resync added to the `sdk` surface (§7.3, §7.3a, §7.6, §7.9). Server key custody moved to a hardcoded fleet root with signed-silent rotation; `AcceptServerKey` deleted (§7.6). Delete-for-everyone bounded to 24 hours. Attachment auto-download restricted to known senders. Slices resequenced: A9 disappearing and multi-device, A10 attachments, A11 fuzz and audit prep, A12 push. |
| 2026-08-12 | A-5 | Operator plurality reached every operator-facing value and every key-transparency artefact: `NetworkSpaceHost` became configuration with `NetworkSpaceHost()` / `SetNetworkSpaceHost()` and decision A13; `MessageServerInfo` gained `OperatorHost`, `KtGossipUsable`, `HostingJurisdiction` and `ReadKeyWindowMs`; `MessagePin`, `KeyChangeWarning` and `MessageDirectoryResult` each carry the operator they came from; `pin` and `kt_head` are keyed by operator (§8.1); §7.6a and §12.3 state that each operator runs its own directory and its own log. Directory lookups render `kt_unavailable` and proceed until the log is live: `ProofState` now separates a failed proof (fails closed) from an unreachable log (proceeds), §7.6b written, §12.3's fail-closed sentence struck. Contact cards added as §7.3b with rotation, the `out_of_band` evidence class, two `GroupResult.Reason` values and one security-log kind. The reaction body widened to arbitrary emoji against a pinned Unicode version (§5.1, §7.4a), `MessageReaction` split into `Emoji` and `EmojiRaw`, and `"malformed"` added to `GapReason`. Read receipts and typing indicators made reciprocal in the user-preference block (§7.2); delivery receipts explicitly not. Succession quorum restated as `max(2, ceil(2 × admins / 3))` and the owner warning removed from the validity table as a client obligation; admin removal given an enforcement point, a typed error and a profile row (§3.1, §3.4). Text retention split into two wire sentinels (§5.11) with `MessageRetentionApplied` gaining `DurableClampedDown` and `DurableDefaulted`. `MessageProtocolLimits` and `MessageBalance.FreeAllowanceBytesPerDay` added so the client renders no literal. The write-key custody block returned to three consequences with the read key stated outside it (§12.1). S17, A-16 and A-17 added; §14's preamble corrected; §4.6 and slice A11 separated the audit decision from its scheduling. |
| 2026-08-12 | A-6 | The contact card got its transport. §5.14 added: `card_root` and the numbered capability generations, the 131-byte card encoding, the 5238-byte deposit sealed under X-Wing to the card's KEM key, and the five `server_nonce`-bound Ed25519 preimages (`register_auth`, `open_auth`, `deposit_auth`, `collect_auth`, `retire_auth`), with the client-side `request_sig` obligation and the rotation ordering. §12.1 gained the nine rendezvous functions and two types on the A-1 surface, requirement S18, interface row A-18 (and the A-1…A-17 range became A-1…A-18), and rendezvous cases on the A-8 vector file. §7.3b: `MessageContactCard` gained `Generation`, `State` and `ExpiresAtMs` and `TokenId` was defined; the card was stated to be per identity and not per device; redemption was rewritten onto the rendezvous with `StartDirectFromCard` returning a ticket rather than a conversation; the rate-limit paragraph took its values from `ServerInfo()` and merged retired with unknown; auto-accept now degrades to manual review after three requests in an hour, adding `"held_for_review"` to `MessageContactRequest.State` and `RefusedSinceLastCollect` to the struct; `MessageContactCard` lost its `*List`. `MessageServerInfo` gained `RendezvousTtlSeconds`, `RendezvousDepositTtlSeconds` and `RendezvousMailboxDepth`. §7.5's provisioning bundle carries the current generation number. `GroupResult.Reason` gained `"succession_floor_too_short"` and `"card_not_live"`. §5.7's recovery trust-on-first-use scoped per group. §7.2's duplicate `MessageClientSettings` deleted. §13 scheduled §7.3b in A7 and added the card encoding and preimages to A6. |
| 2026-08-25 | A-7 | Implementation feedback, four defects found by transcribing this spec into `connect/protocol/message.proto`. **§10.1's four `MessageType` value names were uncompilable**: proto3 scopes an enum value name to the enum's parent scope, so `MessageServerRequest` collided with Spec B's `message MessageServerRequest` in the same package and `protoc` refused the pair. Resolved on the enum side — the message names are the `oneof` arm types the §5.7 op byte is defined over — following `MessageType`'s existing `IpIpPing` convention; the four numbers are unchanged. Recorded here because the old spelling now produces a compile error rather than a silent break. Spec B revision 7 of the same date records all four, including this one. Two knock-on corrections on this side: §7.2 vocabulary 2 said `"rate_limited"` carries `RetryAfterMs` **in `ReasonDetail`**, which cannot work because `ReasonDetail` is free text declared never to be parsed — so Spec C §9's `{RetryAfterMs}` interpolation had nothing to read. `RetryAfterMs` is now a typed `int64` on both `MessageSendability` and `MessageEntry` (`int64` because gomobile does not bind unsigned types). And the claim that a response field is never a MAC input, written while resolving Spec B's §4.5 gap, is **false** — `FetchAttestation` signs nine `FetchResponse` fields — and is corrected there rather than left to be generalised. |
| 2026-08-25 | A-8 | Implementation feedback from the record codec, both amendments in §12.1. **`RetentionClassWire` returns `(byte, error)`, not `byte`.** It is one of the two functions that cross between the retention class as Go carries it and the byte the wire carries it in, and it has two things to refuse — a non-eph class arriving with an eph bucket, and an eph bucket past 5. A function that cannot refuse has to **normalise**, and both normalisations store a record as though the caller's belief about it had been right: dropping the bucket silently reclassifies, truncating it manufactures `0x16`, a byte every reader refuses. MASTER §8 gives no Go signature, so this settles the arity. It is an arity change, so Spec B's server does not compile against the old spelling; Spec B §12.1 is amended identically as B-8. **The nine `Err*` sentinels are published on the A-1 surface.** §5.9 guardrail 7 already required every failure in `connect/message` to be a typed error; a typed error the server cannot name is one it can only match on message text, and §5.1 check 3 acts on two of them directly. The allowlist test in the message-server repo covers nine names and no more. |
| 2026-08-25 | A-9 | Implementation feedback from the two record AAD preimages; one amendment, in §12.1, and it changes no signature. **The refusals block is an allowlist of what the server may reach, not an inventory of what `connect/message` exports.** A-8's "nine names, no more, and a tenth is a design discussion" reads as a rule about the count; the rule is reachability. §12.1 was never the package's export set — the package also exports the sealing side, `AADBody`, `AADHead` and `BodyBinding`, which build MASTER §8's two record AEAD preimages and are deliberately on no line of §12.1 because the server never decrypts — so the message-server allowlist test asserts the names in the block rather than what the package declares. A sentinel a published function can return is owed a line in the same commit that makes it reachable; one only an unpublished function can return is not, and publishing it would widen the server's allowlist with a name no server can use. `ErrRecordHeaderNil` and `ErrServerAttachmentMismatch` are the first two of that kind: both are `AADHead`'s, and both stay off the surface until something on it can return them. |
| 2026-08-26 | A-10 | Implementation feedback from `connect/message/attachment.go`, the codec Spec B §5.1 check 3 calls on every submit. Four amendments, none of which changes a wire byte. **§12.1 gains the six sentinels `ParseServerAttachment` can return**, under A-9's rule that a sentinel a published function can return is owed a line in the same commit that makes it reachable. **§12.1 gains `ServerAttachmentKind` and its five constants**: without them a server held to the published surface can tell an `EpochAttachment` from a `RecoveryTag` only by testing four body pointers for nil, never by the discriminator §5.11 defines, while check 3 requires exactly that discrimination. **§5.11 gains Go field types for `EpochAttachment`, `RecoveryTag`, `WrapTag` and `EpochComplete`** — it previously declared `ServerAttachment`'s and none of theirs, so a second implementation could reasonably read the wire table's "exactly 32 bytes" as `[32]byte`, at which point check 3's `write_key` exactly 32 bytes' is a question it can neither ask nor fail. **Kind `0x0000` on parse is RULED: a parser MUST refuse an encoded one.** The table forbade emitting it and said nothing about receiving it; accepting it would give one logical attachment two encodings with two different `H(server_attachment)`, which sits inside `AAD_head` and the `write_auth` preimage, so two peers choosing differently would disagree on the AEAD of every ordinary record with neither side's tests failing. |
| 2026-08-26 | A-11 | Implementation feedback from `peer/`, the connect frame transport. **§5.7 said `server_nonce` is "scoped to that connection" while the transport supplies no connection identity**, verified in `connect`'s source rather than inferred: the receive callback gets `{SourceId, StreamId}` with `StreamId` always zero, `connect.Peer` is built from the contract rather than the session, a `ReceiveSequence`'s per-session id never reaches a callback, and `EncryptionModeOff` means a deployment may have no sessions at all — so the whole arriving identity is the `client_id`, which survives a reconnect. A connection is now defined as **one `Hello` epoch of a `client_id`**, and **the residual is stated rather than argued away**: a client that reconnects without saying `Hello` keeps its nonce and the server cannot tell, so cross-connection replay resistance rests on the client outbox rule rather than on the transport, and that rule is therefore normative for the guarantee. The §6.1 step (0) idempotency claim and stream-index monotonicity already refuse a replay without depending on the nonce, which bounds the residual without removing it. Removing it needs `connect` to expose a session identity at the receive callback — a change to a repository this work does not own, and therefore an owner decision. |

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
| Ciphersuite | Groups are created and accepted at `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (0x0003). `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) is **registered and implemented** but refused at group creation by policy | `suite.go` registry has **two** entries; `group.go:policyCheck` pins group creation to 0x0003 |
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
| Extensions, group context | `urmessage_owner_successor` (0xF003) — **accepted and validated in v1** | `profile.go:allowedGroupExtensions`, validated per §3.4 |
| Lifetime enforcement on KeyPackages | yes, ±1h clock skew tolerance | `key_package.go:Validate` |
| Max group size | **500 members, hard.** A commit whose resulting membership exceeds it is refused at construction and rejected on receipt | `commit.go:checkGroupSize`, `ErrGroupSizeExceeded` |
| Max devices per identity | **10 leaves per identity in one group**, hard, same enforcement on both sides | `commit.go:checkDeviceCount`, `ErrDeviceLimitExceeded` |
| Removal authority | **Only an OWNER may remove an ADMIN or the OWNER**, hard, enforced at construction and on receipt | `commit.go:checkRemovalAuthority`, `ErrAdminRemovedByNonOwner` |
| Delivery service | ours, strongly consistent (MASTER §9.3) | `connect/message` |

**Why a second ciphersuite is registered before anything needs it.** A registry with one entry and a
registry that is a hardcoded constant are indistinguishable by test, and the difference only shows up
when a second suite is added — which the post-quantum MLS ciphersuites make a near certainty, since
they are still an Internet-Draft (MASTER §7). Registering 0x0001 now costs an AES-GCM binding on
stdlib primitives and a second pass through the vector families; discovering later that the suite id
was assumed constant in eleven places costs a release. 0x0001 is implemented, vector-tested and
refused by group policy, so no group on the wire changes.

`ReInit` stays unimplemented. Registering a suite and migrating a live group to it are different
problems, and only the first is in v1.

### 3.2 Deliberately not implemented, and what happens instead

| RFC 9420 feature | v1 | Behaviour on receipt |
|---|---|---|
| External commits (§12.4.3.2) | no | `ErrProfileExternalCommit`, message dropped, warning logged, sender not trusted further this epoch |
| External senders extension (§12.1.8.1) | no | `ErrProfileExternalSender` at group-context validation; commit refused |
| PreSharedKey proposals (§12.1.5) | no | `ErrProfilePSK` at proposal parse |
| ReInit (§12.1.6) | no | `ErrProfileReInit` |
| Branching / subgroups (§11.2) | no | `ErrProfileBranch` |
| `x509` credentials (§5.3.2) | no | `ErrProfileCredentialType` |
| Creating or joining a group at any suite but 0x0003 | no | `ErrProfileCiphersuite`. 0x0001 is implemented and vector-tested but refused here by policy (§3.1) |
| `application_id` leaf extension | no | ignored if not in `required_capabilities`; refused if required |
| GREASE values (§13.2) | **parsed and ignored**, never generated | must not error — interop harness sends them |

**Every one of these still needs a negative test.** Narrowing the profile does not remove the
obligation to test ValSem240–246 and ValSem401–403; it changes the expected outcome from "the RFC's
specific check fires" to "the profile gate rejects the whole message before the check is reached."
Both are asserted, and the test asserts *which* error surfaced, so a future accidental implementation
of external commits turns the test red rather than green. See §4.3.

Note what is **not** on this list: the owner-succession group-context extension `0xF003` is
implemented and validated in v1 (§3.4). An earlier revision of this document parse-refused it while
MASTER §11 specified the mechanism, which meant shipping succession later would have required
updating the entire fleet before the first group could use it.

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

// urmessage_owner_successor, extension type 0xF003. MASTER §11.
// group context, so the nomination is covered by the transcript hash and no
// server can alter it, add one, or remove one.
type OwnerSuccessorExtension struct {
    Enabled            bool     // false disables succession for this group entirely
    SuccessorMemberId  []byte   // empty when no successor is nominated
    NominatedAtMs      uint64
    FloorMs            uint64   // 7776000000 (90 days) in v1; smaller values are refused
}
```

`RequiredCapabilities` for a v1 group is fixed:
`extension_types = [0xF001, 0xF002]`, `proposal_types = []`, `credential_types = [basic]`.
This means a client that does not understand `urmessage_leaf_keys` cannot be added — which is exactly
right, since a member with no X-Wing key cannot receive the epoch wrap and would silently lose
history at the next commit. `urmessage_owner_successor` is deliberately **not** in
`required_capabilities`: it is accepted and validated by every v1 client, and requiring it would
exclude a member for a governance feature its group may never enable.

**Owner succession, validated at every client.** `commit.go` validates a commit that promotes the
nominated successor to OWNER against every condition MASTER §11 makes a validity condition, and
rejects it with a typed error naming the one that failed. MASTER §11's warning obligation is
deliberately not in this table: no receiving client can observe what was displayed on the owner's
devices, so it is a client obligation there and not a condition here.

| Condition | Error on failure |
|---|---|
| `Enabled` is true in the epoch being committed from | `ErrSuccessionDisabled` |
| The committer is the nominated `SuccessorMemberId` | `ErrSuccessionNotNominee` |
| Countersignatures from at least `max(2, ceil(2 * admins / 3))` current admins, counted at the epoch the promotion commits from | `ErrSuccessionQuorum` |
| `now - lastOwnerRecordMs >= FloorMs`, where `lastOwnerRecordMs` is the most recent record authored by any of the owner's device leaves that this client has accepted | `ErrSuccessionFloor` |
| `FloorMs >= 7776000000` | `ErrSuccessionFloorTooShort` |

The countersignatures ride in the promotion record's MLS-authenticated payload, each an Ed25519
signature by an admin's `identity` key over
`"URmessage/v1/succession" ‖ LP(group_id) ‖ u64(epoch) ‖ LP(successor_member_id) ‖ u64(nominated_at_ms)`.
Validation is client-side at every member, because the message server holds no identity keys and by
MASTER I5 never verifies authorship.

`TestSuccessionRequiresAllFive` constructs a valid promotion and then breaks exactly one condition at
a time, asserting the specific error each time. `TestSuccessionOptOutIsAbsolute` asserts a promotion
in a group with `Enabled == false` fails even when the other four conditions hold.
`TestSuccessionUnobtainableBelowTwoAdmins` asserts that in a group with one admin and in a group with
none, no set of countersignatures satisfies the quorum, so the promotion is rejected with
`ErrSuccessionQuorum` — the arithmetic has no solution below two admins, and a group in that shape
has no succession path at all.

**Removal authority, validated at every client.** `commit.go` reads the pre-commit
`GroupPolicyExtension.Roles` and rejects a commit that contains a `Remove` of a leaf whose role in
that extension is ADMIN or OWNER when the member who proposed or committed it does not hold OWNER,
with `ErrAdminRemovedByNonOwner`. The check runs on receipt as well as at construction, because the
whole value of the rule is that it survives a client someone has modified: one compromised admin
could otherwise strip the entire admin set including the owner in a single commit, and the removed
owner's keys are gone from the very next epoch, so there is no undo by construction (MASTER §11).
`TestAdminCannotRemoveAdmin` asserts the construction refusal and the receipt rejection separately.

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
implement it as a hard bound: `StateStore.DeleteGroupStateBefore` is called on every merged commit with
`epoch - PastEpochWindow`, **`PastEpochWindow = 32`**, and `TestValSem400_PastEpochBound` asserts
that state older than the window is gone from the store. This is not optional politeness — it is the
same deletion that makes MASTER §8.1's ephemeral guarantee true.

**Why 32 and not 8.** The window is a product promise about how long a user may close their laptop,
and eight epochs is not one: an active group with ordinary membership churn and self-service device
management can burn eight epochs in a single day, so a machine closed over a weekend came back to
permanent, unfillable holes in its history. Nobody chose that behaviour — it fell out of a memory
budget. Thirty-two costs more stored epoch state per group (the dominant term is the per-epoch
ratchet-tree state, so the increase is bounded and measurable) and slightly weakens the deletion
guarantee, because `eph_root` for an epoch survives until that epoch leaves the window. Both costs
are accepted; the ephemeral guarantee is unaffected, because `eph_root` is time-sliced and its
window closes on the timer regardless of which epochs are retained (§5.3).

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

### 4.6 Gate 6 — the external audit decision, taken at slice 5

Scope: `connect/mls` and `connect/message` in full, `sdk/message_*.go`, `sdk/cgo-message`, and the
key schedule end to end. The audit brief includes this document, MASTER, and the ValSem coverage
report. The decision is taken at MASTER §14 slice 5; the audit is not *schedulable* until gates 1–5
are green, because an auditor should not spend budget finding what a test suite finds. The decision
and the scheduling are two different moments and this document keeps them apart.

**Whether to commission this audit is decided when slice 5 exists**, so a firm can quote against
working code rather than a design. If the answer is yes, it blocks general availability exactly as
written above. The risk of deciding late is worth restating rather than filing: audit firms book
months out, so a "yes" at slice 5 puts the lead time on the critical path to general availability
instead of running alongside the build. MASTER §15 item 7 carries the same ruling.

### 4.7 Release gating

| Gate | Blocks slice 5 (first testable build) | Blocks beta | Blocks GA |
|---|---|---|---|
| 1 profile | yes | yes | yes |
| 2 vectors + interop | yes | yes | yes |
| 3 ValSem 43 + errata | yes | yes | yes |
| 4 fuzz (properties 1–2) | yes | yes | yes |
| 4 fuzz (differential, nightly clean for 14 days) | no | yes | yes |
| 5 swappable interface | yes | yes | yes |
| 6 external audit — decision taken at slice 5 | no | no | **yes, if commissioned** |

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

**Record bodies with a fixed shape.** Most application records carry an opaque body inside `ct_body`
and this layer never looks at it. The reaction is the exception, because its body is validated on
both sides:

```
REACTION { u8 op, LP(target_message_id), LP(emoji_utf8) }
  op        0x01 = add, 0x02 = remove
  emoji_utf8  1..64 bytes, valid UTF-8, exactly one extended grapheme cluster, and every
              codepoint drawn from the emoji set of the pinned Unicode version (§7.4a).
              Validated on send AND on receipt; a record failing validation renders as a
              gap with reason "malformed" rather than as a reaction.
```

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

// read_key[n] = HKDF-Expand(storage_root[n], "read/v1", 32), one per epoch.
// Every member derives it from epoch state it already holds; a joining member
// receives its joining epoch's key in the Welcome alongside group_handle_key.
// The server installs each epoch's key from that epoch's EpochAttachment and
// RETAINS it for the window it advertises as read_key_window_seconds — 90 days
// on a stock server, surfaced as MessageServerInfo.ReadKeyWindowMs — which is
// what lets an offline member catch up and what makes a removed member's
// metadata access expire. MASTER §9.2.
func ReadKey(storageRootEpoch []byte) []byte

// MAC(read_key, "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op) ‖ LP(request_bytes))
// The epoch whose read key computed the MAC travels in the request's read_epoch
// field, which is inside canonical_request_bytes and therefore inside the MAC.
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

**Read authorization.** Reads are authorized under the epoch's `read_key` and a domain label
distinct from `write_auth`'s:

```
req_auth = MAC(read_key[e], "URmessage/v1/req" ‖ LP(server_nonce) ‖ u8(op)
                            ‖ LP(canonical_request_bytes))

  read_key[e]             = HKDF-Expand(storage_root[e], "read/v1", 32).
  e                       = the request's read_epoch field. The client uses the newest
                            epoch whose state it holds. It is a field of the request
                            body, so it is inside canonical_request_bytes and inside
                            the MAC: the server selects a key by an authenticated value.
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

Verified on the server with Spec B §5.1 checks 1, 2, 4, 5 and the read-key lookup for
(group_id, read_epoch), and then this MAC, returning Spec B's deliberately non-specific
REASON_REJECTED on failure. No transaction is opened and no row is allocated on the
read path.
```

`read_key` is deliberately not the epoch's `write_key`. The server keeps only the current epoch's
write key and one 60-second predecessor, so a client that was offline across one commit holds a key
the server cannot resolve — and every route out of that condition (`GroupStatus` to learn the epoch,
`Fetch` to obtain the commits, `WrapFetch` to obtain its own wrap) is itself a read. `connect/message`
therefore takes a `read_key` on every request-auth call and has no code path that MACs a request
under a `write_key`; `TestReadAuthNeverUsesWriteKey` asserts it by walking the call graph of
`ComputeRequestAuth`.

**The read-key window, and what the client does at its edge.** The server retains each installed read
key for the window it advertises as `read_key_window_seconds` — 90 days on a stock server, and the
value the client reads from `MessageServerInfo.ReadKeyWindowMs` rather than hardcoding. A client
always authenticates under the newest epoch it holds, so the window binds only when the client has
been away longer than that. `sdk` detects that
condition explicitly rather than retrying a refusal: when every read under every epoch key the
client holds is refused and the connection is otherwise healthy, `MessageClient` reports sendability
reason `read_authorization_expired` (§7.2 vocabulary 1) and health reason
`read_authorization_expired` (§7.2 vocabulary 3), and the two recoveries that still work are named
in the payload — link from another signed-in device (§7.5) or restore from the seedphrase, which is
authorized by the Ed25519 recovery proof below and never by a read key.
`TestReadKeyWindowSurfacesExplicitly` asserts the client never reports a generic failure for this
condition.

A group's read key for epoch *n* reaches the server inside `EpochAttachment.read_key` on the commit
that opens epoch *n*, and reaches a joining member in the `Welcome` alongside `group_handle_key`
(MASTER §8). Every later epoch's key is derived locally from that epoch's `storage_root`.

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
```

The server stores the public half on first sight and REFUSES any later differing
`recovery_verify_pub` for the same `recovery_handle` **within that group** (trust-on-first-use, the
same shape as the client's server-key pin, kept per group so one bad first write cannot deny restore
everywhere — Spec B §5.4). `RecoveryFetchRequest.proof` is verified against **each candidate
group's** stored key, and a group whose row was poisoned drops out of the result while every other
group still restores.

**The nonce.**

`server_nonce` is 32 bytes, issued by the message server at session start in `HelloResponse`, scoped to
**that connection**, valid for the life of that connection, and never rotated. It prevents
cross-connection replay. It is **not** carried in requests — the server knows its own connection's nonce
and looks it up from the connection, never from the request.

**What "that connection" means, RULED 2026-08-26 — and the residual is stated rather than assumed
away.** The paragraph above was written as though the transport supplies a connection identity.
**It does not.** `connect`'s receive callback is handed `path.SourceMask()`, which is
`{SourceId, StreamId}` with `StreamId` always zero because a frame whose path `IsStream()` is dropped
before the callback; `connect.Peer` is `{ProvideMode, Roles, Principal}`, built from the active
contract rather than from the session; a `ReceiveSequence` does hold a per-session `sequenceId` and it
never reaches a callback; and `EncryptionModeOff` is a supported setting, so a deployment may have no
sessions at all. **The whole of the arriving identity is the `client_id`, and a `client_id` survives a
reconnect unchanged.** That was verified in the source, not inferred.

So a connection is defined here as **one `Hello` epoch of a `client_id`**: every `Hello` mints a fresh
nonce and destroys the previous one outright, with no history and no grace window, so a record sealed
against the old connection stops verifying the instant a new one is issued.

**The residual, named because it is the difference between what this section promises and what it
delivers:** a client that reconnects *without* saying `Hello` keeps its nonce, and the server cannot
tell. Cross-connection replay resistance therefore rests on **the client protocol** — the outbox rule
below — and not on the transport. The outbox rule is consequently **normative for this guarantee**,
not merely for correctness, and that is why it is stated as a MUST.

Two things bound the residual rather than removing it. A replayed record is already refused by the
§6.1 step (0) idempotency claim and by stream-index monotonicity, so the nonce is defence in depth
over a check that does not depend on it. And a server SHOULD bound connection lifetime with an idle
sweep. **Neither is the guarantee.** Removing the residual needs `connect` to expose a session
identity at the receive callback, which is a change to a repository this work does not own and is
therefore an owner decision rather than a spec edit.

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
                               RULED 2026-08-26: a parser MUST REFUSE an encoded kind 0x0000
                               (ErrServerAttachmentNoneEncoded), rather than accepting it as
                               an absent attachment. Both readings were available and only
                               one is safe: accepting it would give one logical attachment
                               TWO encodings — the empty field, and two octets of zero — with
                               two different H(server_attachment), and H(server_attachment) is
                               inside both AAD_head and the write_auth preimage. Two peers that
                               chose differently would disagree on the AEAD of every ordinary
                               record, and neither side's tests would fail. 0x0000 therefore
                               stays in this table as a RESERVED code that no conforming
                               implementation ever emits and none ever accepts; it is here so
                               the numbering is stable and so this paragraph has somewhere to
                               live.
  kind 0x0001  EpochAttachment carried by, and only by, a record with is_commit = 1
  kind 0x0002  RecoveryTag     carried by RECOVERY_PUB records and by recovery wrap records
  kind 0x0003  WrapTag         carried by per-device epoch wrap records and by the epoch snapshot
  kind 0x0004  EpochComplete   carried by the wrap-set-complete marker record

EpochAttachment {
    u64  epoch                  // the epoch this attachment OPENS. MUST equal current_epoch + 1
    u16  alg_id                 // 0x0031 (HKDF-SHA-256) in v1
    LP   write_key              // exactly 32 bytes: write_key[epoch]
    LP   read_key               // exactly 32 bytes: read_key[epoch] = HKDF-Expand(
                                //   storage_root[epoch], "read/v1", 32), for the epoch this
                                //   attachment OPENS. Different in every epoch; the server
                                //   installs it against that epoch and retains it 90 days (§5.7)
    u32  media_ttl_seconds
    u32  durable_ttl_seconds    // 0 = the group set nothing; the server applies its own advertised
                                //     text default (MASTER §8.3, Spec B §7.3)
                                // 0xFFFFFFFF = the group asked for indefinite retention. On a server
                                //     advertising a text cap this is clamped DOWN to the cap and
                                //     reported through RetentionApplied.durable_clamped_down. It is
                                //     never refused — Spec B §7.3 case 3 forbids refusal in all cases.
                                // any other value = seconds, floored up to the server's minimum and
                                //     clamped down to its cap
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

// The four bodies. Added 2026-08-26: this block previously declared ServerAttachment's
// field types and none of theirs, leaving only the wire table's "exactly 32 bytes"
// annotations to imply a Go type. A second implementation reading this surface could
// reasonably choose [32]byte for write_key, at which point §5.1 check 3's "write_key
// exactly 32 bytes" becomes a question that implementation cannot fail and cannot even
// ask. Slices, matching the record codec's own rule that a variable-length wire field
// is LP(x) and reaches Go as a slice whose length is then checked.
type EpochAttachment struct {
    Epoch                uint64   // the epoch this attachment OPENS
    AlgId                uint16
    WriteKey             []byte   // exactly 32; the server holds it (§5.3)
    ReadKey              []byte   // exactly 32; different in EVERY epoch, so never
                                  // compared against a previously installed one
    MediaTtlSeconds      uint32
    DurableTtlSeconds    uint32   // both sentinels legal here; resolved at §6.1 step (6)
    GroupContextHash     []byte   // exactly 32
    ExpectedWrapCount    uint32   // > 0
}

type RecoveryTag struct {
    RecoveryHandle     []byte   // exactly 16
    RecoveryVerifyPub  []byte   // exactly 32, Ed25519
    AlgId              uint16
}

type WrapTag struct {
    WrapTargetHandle []byte   // exactly 16
    Epoch            uint64
}

type EpochComplete struct {
    Epoch     uint64
    WrapCount uint32   // must match the epoch's EpochAttachment.ExpectedWrapCount
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

**Auto-download is a client policy and is not a property of the blob.** `connect/message` neither
knows nor cares which senders a user trusts; the decision is made in `sdk` before a
`BlobGrantRequest` is issued (§7.4). This layer's only obligation is that a record whose body was
never downloaded is still a complete, verifiable record: `ct_head`, `body_hash` and `blob_id` are
retained and checked exactly as for a downloaded one, so a held attachment is a deliberate
non-fetch rather than a partial parse.

### 5.14 Contact cards and the rendezvous

`connect/message` owns the card encoding, the rendezvous derivations, the five signature preimages
and the sealed deposit, because the message server links the verifiers and two implementations of a
preimage diverge (§12.1 A-1). The mechanism is MASTER §9.8 and the wire messages are Spec B §4.3.11.

**Derivations.** A card is a numbered capability generation of the identity:

```
card_root            = HKDF-Expand(master_key, "card/v1", 32)              MASTER §5.2
card_seed[k]         = HKDF-Expand(card_root, "cardgen/v1" ‖ u32(k), 32)
token[k]             = HKDF-Expand(card_seed[k], "token/v1", 16)
card_xwing[k]        = XWing.KeyGen(HKDF-Expand(card_seed[k], "cardkem/v1", 32))
collect_sig_seed[k]  = HKDF-Expand(card_seed[k], "colsig/v1", 32)   → Ed25519 collect_sig_sk
rendezvous_id[k]     = H("URmessage/v1/rendezvous" ‖ token[k])                        [32 B]
deposit_sig_seed[k]  = HKDF-Expand(HKDF-Extract("URmessage/v1/rendezvous", token[k]),
                                   "depsig/v1", 32)                → Ed25519 deposit_sig_sk
```

**The card.** `u8 version = 0x01 ‖ u16 alg_id ‖ LP(identity_pub) ‖ LP(token) ‖ LP(display_name) ‖
u32 checksum`, where `display_name` is at most 64 UTF-8 bytes and `checksum` is the first four
bytes of `H("URmessage/v1/card" ‖ every byte above)`. 131 bytes at a full-length name; the
`urmessage://` form and the QR payload are the same bytes, base64url. The card carries no
encryption key deliberately — the card's KEM public half is fetched from the rendezvous by a holder
that has already proved possession of the token — because a card that carried an X-Wing public key
would be 1.3 KB and a QR nobody can print.

**The sealed deposit**, exactly 5238 bytes:

```
CONTACT_REQUEST, padded to exactly 4096 bytes as u16(body_len) ‖ body ‖ zeros:
  u16  alg_id
  LP   identity_pub          // 32 B Ed25519, the requester's master identity
  LP   key_package           // the MLS KeyPackage the card's owner will Add
  LP   display_name          // UTF-8, at most 64 bytes
  u64  requested_at_ms
  LP   request_sig           // Ed25519 under identity_pub over
                             //   "URmessage/v1/rzvrequest" ‖ LP(rendezvous_id)
                             //   ‖ LP(H(key_package)) ‖ LP(display_name) ‖ u64(requested_at_ms)

(ct_xwing, ss) = XWing.Encapsulate(card_xwing_pub)
deposit_key    = HKDF-Expand(ss, "URmessage/v1/rzvdeposit" ‖ LP(rendezvous_id), 32)
deposit_ct     = u16(alg_id) ‖ LP(ct_xwing) ‖ AEAD(deposit_key, nonce = 0,
                   aad = "URmessage/v1/aad/rzv" ‖ LP(rendezvous_id), padded_body)
                 // 2 + 1124 + 4112 = 5238 bytes, an equality the server asserts
```

Every encapsulation yields a fresh `deposit_key`, so the zero nonce uses no key twice (**I7**).

**The five preimages**, each binding the connection's `server_nonce` so a captured frame does not
replay onto another connection:

```
register_auth = Ed25519(collect_sig_sk, "URmessage/v1/rzvregister" ‖ LP(server_nonce)
                  ‖ LP(rendezvous_id) ‖ LP(deposit_verify_pub) ‖ LP(collect_verify_pub)
                  ‖ LP(card_xwing_pub) ‖ u16(alg_id))
open_auth     = Ed25519(deposit_sig_sk, "URmessage/v1/rzvopen" ‖ LP(server_nonce)
                  ‖ LP(rendezvous_id))
deposit_auth  = Ed25519(deposit_sig_sk, "URmessage/v1/rzvdeposit" ‖ LP(server_nonce)
                  ‖ LP(rendezvous_id) ‖ LP(H(deposit_ct)))
collect_auth  = Ed25519(collect_sig_sk, "URmessage/v1/rzvcollect" ‖ LP(server_nonce)
                  ‖ LP(rendezvous_id) ‖ u64(since_deposit_id) ‖ u64(ack_through_deposit_id)
                  ‖ u32(limit) ‖ u8(subscribe))
retire_auth   = Ed25519(collect_sig_sk, "URmessage/v1/rzvretire" ‖ LP(server_nonce)
                  ‖ LP(rendezvous_id))
```

**What the client MUST verify and the server never can.** A collected deposit is opened, its
`request_sig` verified under the `identity_pub` inside it, and the request refused without a word to
the user if it does not verify. `SafetyDigits` are computed from that same `identity_pub`, so the
digits the owner reads back over a phone call are the digits of the key that signed the request. The
server holds no identity keys and by **I5** never verifies authorship; a `deposit_auth` that
verifies proves possession of the card and nothing else.

**Client obligations on rotation.** `RotateContactCard` registers generation *k+1*, collects
everything outstanding at *k*, retires *k*, and only then persists *k+1* as current. An interrupted
rotation leaves both generations live and is resumed rather than restarted. A device that has been
offline across a rotation discovers the current generation by opening forward from the last one it
knows, bounded to sixteen probes, after which it reports the card as unavailable on this device
rather than handing out a dead link.

Tests: `TestRendezvousIdIsTokenDerived`, `TestDepositIsExactly5238Bytes`,
`TestDepositSigProvesOnlyTokenPossession`, `TestCollectKeyIsNotDerivableFromToken`,
`TestCardGenerationsAreUnlinkable`, `TestRotateCollectsBeforeRetiring`.

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
    NetworkSpaceHost string   // the URnetwork network space this client's account is on, e.g.
                              // "ur.network". This names the client's OWN operator. It is a
                              // configured value with a build-time default, never a compile-time
                              // constant — see the operator note below.
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

// ── local store lock (§8.6). Optional, and a real second factor: the PIN
// wraps the store key, so the key cannot be unsealed without it. ──────────
func (self *MessageClient) HasPin() bool
func (self *MessageClient) SetPin(pin string) error          // "" clears it; requires Unlock first
func (self *MessageClient) ChangePin(oldPin, newPin string) error
func (self *MessageClient) Unlock(pin string) error          // wrong PIN returns a typed error
func (self *MessageClient) Lock() error                      // immediate, manual
func (self *MessageClient) IsLocked() bool
func (self *MessageClient) AutoLockMinutes() int32           // 0 = never; default 15
func (self *MessageClient) SetAutoLockMinutes(n int32) error

// ── live settings (were construction-only; C exposes them as switches) ─────
func (self *MessageClient) SetCoverTraffic(enabled bool) error   // takes effect on the next
                                                                 // scheduling window; the schedule
                                                                 // stays independent of real
                                                                 // sending (MASTER §9.5)
func (self *MessageClient) SetMediaCacheBytes(n int64) error
func (self *MessageClient) SetUserPreference(key string, value string) error
func (self *MessageClient) UserPreference(key string) string
// user-preference keys, closed: "read_receipts", "delivery_receipts",
// "typing_indicators", "disappearing_default_bucket", "attachment_auto_download",
// "notification_mode", "contact_card_auto_accept". Backed by the sealed local store,
// NOT prefs.json.
//
// COMPOSITION: a receipt or typing indicator is emitted only if the user preference AND
// the group policy allow it. The group half is MessageGroupPolicy (§7.3).
//
// RECIPROCITY, for "read_receipts" and "typing_indicators" only: turning yours off also
// hides everyone else's from you. With "read_receipts" false, this client emits none AND
// drops inbound read receipts before they reach the store — MessageEntry.ReadBy stays
// empty, no "read_changed" event is delivered, and an outgoing message's State stops at
// "delivered" and never reaches "read". With "typing_indicators" false, this client emits
// none AND delivers no "typing_changed" event. The rule is enforced here rather than in a
// UI, so a client that forgot it cannot leak what the setting is supposed to withhold.
//
// Without reciprocity the setting is a one-way observation tool: the most privacy-conscious
// person in a conversation would be the one who learns the most about everyone else, which
// is the opposite of what someone reaching for the switch is asking for. Signal, WhatsApp
// and iMessage all resolve it the same way.
//
// "delivery_receipts" is NOT reciprocal. Turning it off stops this device emitting a
// receipt when it decrypts; it does not hide anyone else's, because a delivery receipt is
// a statement about a device being online rather than about a person having read something,
// and the two are not the same disclosure.
//
// "attachment_auto_download" is CLOSED: "known_contacts" (default) | "always" | "never".
// "contact_card_auto_accept" is CLOSED: "true" (default) | "false" — §7.3b. The SDK
// suspends automatic acceptance for the remainder of the hour once more than three
// requests arrive at one card within an hour, whatever this preference says, and
// reports the suspension on MessageContactRequest.State.

// ── directory listing (MASTER §10.1). OFF by default; this is the only call
// that creates a link between this messaging identity and the URnetwork
// account paying for the traffic. ─────────────────────────────────────────
func (self *MessageClient) DirectoryListed() bool
func (self *MessageClient) SetDirectoryListed(listed bool, callback SendCallback) *MessageSendTicket

// ── diagnostics (MASTER §9.7). Opt-in, bounded, and the only condition under
// which the message server retains anything per-identity about this client. ─
func (self *MessageClient) StartDiagnosticSession(minutes int32) (sessionId string, err error)
func (self *MessageClient) StopDiagnosticSession() error
func (self *MessageClient) DiagnosticSessionEndsAtMs() int64   // 0 = no session

// ── server ────────────────────────────────────────────────────────────────
func (self *MessageClient) ServerInfo() *MessageServerInfo

// the client's own operator, readable and settable at runtime. The value supplied at
// construction is a default, not a fixed property of the build: a build that can only
// ever reach one operator cannot be pointed at a second one without shipping a new binary.
// Changing it closes the session, re-resolves the message server, and re-opens; it does
// not touch the local store, the MLS state or any pin.
func (self *MessageClient) NetworkSpaceHost() string
func (self *MessageClient) SetNetworkSpaceHost(host string) error

// ── lifecycle ─────────────────────────────────────────────────────────────
func (self *MessageClient) Start() error
func (self *MessageClient) SyncState() *SyncState
func (self *MessageClient) AddSyncListener(listener SyncListener) *Sub
func (self *MessageClient) Health() *MessageHealthEvent
func (self *MessageClient) AddHealthListener(listener HealthListener) *Sub

// ── push (§14 open item 9; slice A12). No-op stubs until the channel registry
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
  "network_space_host": "string",   // e.g. "ur.network"; the operator this client's own
                                    // account is on, from the host application's per-user
                                    // configuration, with a build-time value used only
                                    // when nothing is configured. Never a compile-time
                                    // constant as its only source.
  "message_server_id":  "string",   // the one server's URnetwork client id (UUID string),
                                    // from the build-time constant kMessageServerClientId
                                    // or, when set, from the operator discovery response
  "enable_cover":       false,      // optional, default false  (MASTER §9.5)
  "media_cache_bytes":  1073741824  // optional, default 1 GiB
}
```

**`network_space_host` is configuration.** The host supplied here is the operator this client's own
account is on, and it is read from the calling application's per-user configuration with a build-time
value used only when nothing is configured. Nothing in this component may treat it as fixed at
compile time. MASTER §2 makes a build that compiles one operator's host in as its only source a
defect, and the reason is in MASTER §4.1: more than one operator exists, two run today, and a client,
a message server and a contact may each be on a different one.

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
    ServerKeyState           string   // CLOSED: "root_verified" | "untrusted" (§7.6). There is
                                      // no "changed_unaccepted": a key either chains to the
                                      // fleet root or the session is refused.
    StoreState               string   // "ok" | "locked" | "unseal_failed" | "corrupt"
                                      //      | "disk_full" | "locked_by_another_process"
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
//   "phrase_not_confirmed"    PhraseConfirmedAtMs() == 0 and C-1's gate applies
//   "store_unavailable"       the local store could not be opened
//   "group_closed"            the server has closed the group
//   "epoch_incomplete"        the epoch's wrap set has not landed yet (§5.11, epoch
//                             publication step 3)
//   "locked"                  the local store is PIN-locked (§8.6)
//   "read_authorization_expired" away longer than the server's advertised read-key
//                             window (ServerInfo().ReadKeyWindowMs, 90 days on a stock
//                             server); relink a device or restore from the phrase (§5.7)
//   "out_of_credit"           the URnetwork account has no data allowance left (§7.9)
//   "fork_unresolved"         automatic resynchronisation of this group failed (§7.6)
//   (there is no "fork_detected" value. A transcript-hash divergence triggers an
//    automatic resync first and only surfaces as "fork_unresolved" if that fails — §7.6.)

// ── 2. Send failure. SendStateChanged / MessageEntry.Reason ────────────────
//   every value of vocabulary 1, plus:
//   "too_large"               exceeds ServerInfo().MaxBlobBytes
//   "blob_incomplete"         the blob was not fully uploaded before bind
//   "rate_limited"            carries RetryAfterMs, a TYPED field on both
//                             MessageSendability and MessageEntry. Corrected 2026-08-25:
//                             an earlier revision said "in ReasonDetail", which cannot
//                             work — ReasonDetail is free text that is explicitly never
//                             parsed, so Spec C §9's `{RetryAfterMs}` interpolation had
//                             nothing to read. Sourced from
//                             MessageServerResponse.retry_after_ms (Spec B §4.5).
//   "oversize"                the record or request exceeded an advertised cap
//   "quota_exceeded"
//   "internal"
//   "delete_window_expired"   a retraction was requested more than 24 hours after sending
// NOT a value: "commit_lost" (A retries internally and never surfaces it — MASTER §9.3),
//              "retention_refused" (deleted; retention is warn-and-proceed — MASTER §15 item 1).

// ── 3. Health. MessageHealthEvent.State ───────────────────────────────────
//   "no_account" | "offline" | "connecting" | "reachable" | "degraded"
//   | "server_unreachable" | "blocked" | "store_unavailable" | "locked"
//   | "out_of_credit"
// MessageHealthEvent.Reason, closed:
//   "none" | "token_expired" | "key_change_unresolved" | "pin_required"
//   | "read_authorization_expired" | "out_of_credit" | "server_key_untrusted"
//   | "fork_unresolved" | "unseal_failed" | "corrupt" | "disk_full"
//   | "locked_by_another_process"
// The Reason set LOSES "server_key_change_unresolved", which no longer exists: a server
// key that does not chain to the pinned fleet root is refused outright and reported as
// "server_key_untrusted"; one that does chain is applied silently (§7.6). It also loses
// "fork_detected", for the reason vocabulary 1 gives.
```

Token expiry maps to health `no_account` with reason `token_expired`; it adds no state of its own.
Vocabulary 3 is **ten** states. `locked` and `out_of_credit` are the two that are neither a transport
condition nor a store failure, and both are evaluated before the transport states because a locked
store or an exhausted allowance makes every other state meaningless.

```go
type MessageSendability struct {
    Allowed      bool
    Reason       string   // vocabulary 1
    ReasonDetail string   // free text for display only; never parsed
    RetryAfterMs int64    // > 0 only when Reason is "rate_limited"; 0 otherwise.
                          // The server's own backoff from MessageServerResponse.retry_after_ms
                          // (Spec B §4.5), carried as a number because Spec C §9 renders it.
                          // int64 rather than the wire's uint32 because gomobile does not
                          // bind unsigned types (§9).
}

func (self *MessageClient) CanSend(groupId string) *MessageSendability
// GroupListener additionally delivers SendabilityChanged(groupId string, s *MessageSendability)

type MessageServerInfo struct {
    Host                  string
    ServerIdHex           string
    ClientId              string
    OperatorHost          string   // the operator THIS SERVER holds its account on, from the
                                   // server's advertised capabilities. It names this server's
                                   // operator and never "the" operator: the client's own
                                   // operator is NetworkSpaceHost() and need not be the same one.
    KtGossipUsable        bool     // true iff OperatorHost equals NetworkSpaceHost(). When false,
                                   // this server's gossiped tree heads are about a different
                                   // operator's log and are not a second path for this client
                                   // (§7.6).
    HostingJurisdiction   string   // where this server is hosted, as the operator of the server
                                   // published it. Empty until Advertised is true.
    SigningKeyFingerprint string
    KeyState              string   // CLOSED: "root_verified" | "untrusted" (§7.6)
    KeyVerifiedAtMs       int64
    MaxBlobBytes          int64    // the file size limit
    MediaTtlMaxMs         int64    // the media and file window
    MediaTtlDefaultMs     int64
    DurableTtlMaxMs       int64    // the text storage cap; 0 = the server sets no maximum
    DurableTtlDefaultMs   int64    // what a group gets if it sets nothing; 1 year by default
    DurableRetentionMinMs int64
    ReadKeyWindowMs       int64    // how long this server keeps each epoch's read key. 90 days on
                                   // a stock server; the client names this number rather than
                                   // hardcoding it (§5.7).
    GroupDurableOverride  bool     // false = groups may not raise text retention on this server
    MaxRecordsPerFetch    int32
    MaxRecordsPerSubmit   int32
    MaxSubmitBytes        int32
    MaxRequestBytes       int32    // post-reassembly control-plane cap; exceeding it aborts
                                   // the request server-side
    MaxResponseBytes      int32
    BlobChunkBytes        int32
    BlobPadMultiple       int32
    RendezvousTtlSeconds       int64  // how long a card's registration lives without a collect
    RendezvousDepositTtlSeconds int64 // how long one uncollected contact request lives
    RendezvousMailboxDepth     int32  // uncollected requests one card may hold (§7.3b, §5.14).
                                      // Spec C formats all three; it renders no literal for them.
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

`MessageServerInfo`'s `MediaTtlMaxMs`, `MediaTtlDefaultMs`, `DurableTtlMaxMs`, `DurableTtlDefaultMs`
and `DurableRetentionMinMs` are milliseconds because every other duration on this API surface is
milliseconds; `sdk` converts them from the server's seconds once, on receipt of `Capabilities`.
`MaxBlobBytes`, `MediaTtlMaxMs` and `DurableTtlMaxMs` are the **three limits every message server
advertises** — file size, media and file window, text storage cap (MASTER §12.2) — and every group
operates inside all three. `MessageRetentionApplied` does **not**
convert — it is a mirror of a wire message and stays in seconds.

`OperatorHost`, `HostingJurisdiction` and `ReadKeyWindowMs` render as "not known yet" while
`Advertised` is false, exactly as the three limits do. A fabricated default for any of them would be
a claim about where a user's ciphertext sits and how long they may be away, made before the server
has said anything.

```go
// The caps this component enforces on both sides of a commit, exposed so a UI can state
// them before a user hits them rather than reporting a refusal afterwards. These are
// protocol constants enforced by connect/mls (§3.1), NOT server-advertised values —
// MessageServerInfo carries what the server advertises, and these two are not that.
type MessageProtocolLimits struct {
    MaxGroupMembers           int32   // 500
    MaxDevicesPerIdentity     int32   // 10
    DeleteForEveryoneWindowMs int64   // 86400000
}

func MessageProtocolLimitsValues() *MessageProtocolLimits
```

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

// MASTER §11: an OWNER may not leave until ownership has moved. LeaveGroup called
// by an OWNER fails with GroupResult reason "owner_must_transfer" and commits
// nothing; TransferOwnership is the way out, and the two are separate calls so the
// UI can offer the transfer rather than reporting a dead end.
func (self *MessageClient) TransferOwnership(groupId string, memberId string,
    callback GroupCallback) *MessageSendTicket

// MASTER §11 succession. Nominating, clearing and disabling are OWNER-only and all
// commit, because the nomination lives in the transcript-covered group context.
func (self *MessageClient) NominateSuccessor(groupId string, memberId string,
    callback GroupCallback) *MessageSendTicket
func (self *MessageClient) ClearSuccessor(groupId string, callback GroupCallback) *MessageSendTicket
func (self *MessageClient) SetSuccessionEnabled(groupId string, enabled bool,
    callback GroupCallback) *MessageSendTicket
func (self *MessageClient) Succession(groupId string) *MessageSuccessionState

// countersign that this group's owner is unreachable, and claim a nomination.
// Both fail with a GroupResult reason naming the unmet condition rather than a
// generic error, because five conditions can each block a promotion (§3.4).
func (self *MessageClient) CountersignSuccession(groupId string,
    callback GroupCallback) *MessageSendTicket
func (self *MessageClient) ClaimSuccession(groupId string,
    callback GroupCallback) *MessageSendTicket

type MessageSuccessionState struct {
    Enabled                bool
    SuccessorMemberId      string
    SuccessorDisplayName   string
    NominatedAtMs          int64
    FloorMs                int64    // 90 days
    OwnerLastActiveMs      int64
    EligibleAtMs           int64    // OwnerLastActiveMs + FloorMs
    CountersignsHeld       int32
    CountersignsRequired   int32
    IAmTheSuccessor        bool
    IAmTheOwner            bool
    OwnerWarningStage      int32    // 0 none, then 30, 60, 75, 85 days elapsed
}

type MessageGroupPolicy struct {
    RetentionDurableMs   int64    // 0 = unset; the server applies its advertised text default
                                  // (one year on a stock server). -1 = ask for indefinite, which a
                                  // server advertising a text cap stores as that cap. Any other
                                  // value is milliseconds. The server's cap, minimum and override
                                  // rule all apply (MessageServerInfo, §7.2)
    RetentionMediaMs     int64    // default 1 month; the server's media window applies
    DisappearingBucket   int32    // 0 = off; 1=1h 2=8h 3=1d 4=1w 5=4w
    ReadReceipts         bool     // default true
    DeliveryReceipts     bool     // default true; the group half of the §7.4 composition rule
    TypingIndicators     bool     // default true
}
// NAMESPACE NOTE: this field and the wire EPH class number are DIFFERENT NAMESPACES.
// On the wire, EPH(bucket 0) is the transient class carrying receipts and typing and is
// never persisted. Here, 0 means "disappearing is off". SetDisappearing(gid, 0) turns
// disappearing OFF; it never sends a receipt-class record. Spec C's open item C-8 is
// closed by citing this line.
//
// LAYERING: the receipt, typing and disappearing fields are the GROUP policy, settable by ADMIN/OWNER only
// (MASTER §11). The USER's own preferences are SetUserPreference/UserPreference (§7.2).
// A receipt or typing indicator is emitted only if BOTH allow it. Spec C's Settings
// toggles write the user preference; the group sheet writes the policy.
```

**Removal authority is client-enforced, because the server cannot enforce it.** `RemoveMember`
fails with `GroupResult` reason `"admin_removal_is_owner_only"` when the caller is an ADMIN and the
target is an ADMIN or the OWNER, and `connect/mls` rejects such a commit on receipt (§3.4). MASTER
§11 states the rule and the reason: one compromised admin could otherwise strip the whole admin set
including the owner in a single commit, and the removed owner's keys are gone from the next epoch,
so there is no recovery by construction.

**A DM's policy is jointly controlled.** In a group where `IsDirect` is true, both members may call
`SetGroupPolicy` and `SetDisappearing`. A change that **shortens** retention or the disappearing
timer commits immediately. A change that **lengthens** either does not commit: it is recorded as a
pending request, announced in the thread, and takes effect only when the other member sets the same
value, expiring after seven days. `GroupEvent` carries it as
`PendingPolicy *MessagePendingPolicy{RequestedByMemberId, RetentionDurableMs, RetentionMediaMs,
DisappearingBucket, RequestedAtMs, ExpiresAtMs}`, and `SetGroupPolicy` returns `GroupResult` reason
`"awaiting_other_party"` so the caller can say so rather than showing a failure. This keeps a DM a
two-member group with no second code path while removing the surprise that whoever opened the chat
silently controls how long the other person's messages survive.

**Disappearing timers are forward-only.** `SetDisappearing` applies to messages sent after the
commit that carries it; messages already sent keep the class they were sealed under. This is forced
by the cryptography rather than chosen: a durable message is encrypted under the durable class key
and re-classing it after the fact would be a promise about client cooperation, not a guarantee. The
UI states it at the moment of the change (Spec C §8.3).

**Retention negotiation is warn-and-proceed, in both directions** (MASTER §15 item 1). The server
clamps a policy longer than `media_ttl_max_seconds` or `durable_ttl_max_seconds` **down**, floors a
policy shorter than `durable_retention_min_seconds` **up**, accepts the commit either way, and
reports what it applied. `GroupEvent` (§7.7) therefore carries
`RetentionApplied *MessageRetentionApplied` with `{MediaTtlSeconds, DurableTtlSeconds,
MediaClampedDown, DurableFlooredUp, RequestedMediaTtlSeconds, RequestedDurableTtlSeconds,
DurableClampedDown, DurableDefaulted}`. The
group's transcript-covered policy is unchanged, so a move to a server with different limits restores
the original intent; the client renders a one-time in-group notice naming the **effective** value,
never the requested one. There is no `RetentionPolicyConflict` event and no refuse-to-commit path.

**Text retention defaults to one year, and a group may raise it only where the server allows.** A
policy that sets no `RetentionDurableMs` sends the unset sentinel, and the **server** applies its own
advertised text default — one year on a stock server — rather than the client volunteering a number
(§5.11). `MessageServerInfo.DurableTtlDefaultMs` is what that default will be, so the UI can state it
before the commit; `MessageRetentionApplied.DurableDefaulted` is how the client learns it was
applied. When `MessageServerInfo.GroupDurableOverride` is false,
`SetGroupPolicy` refuses a `RetentionDurableMs` above that default before it commits, with
`GroupResult` reason `"durable_override_not_permitted"`, and Spec C states the server's fixed period
in place of the control (Spec C §8.4). "Forever" is not a default anyone chose; it is what happens
when nobody sets a number.

`CreateDirect` is not a different code path — ledger P2 — a DM is a two-member group (MASTER §6). It
exists only so the UI can express intent and the client can render it as a conversation. `MessageGroup.IsDirect`
is `MemberCount() == 2 && CreatedAsDirect`.

Role strings are `"owner"`, `"admin"`, `"member"`, `"observer"` (MASTER §11). Strings rather than an
int enum because gomobile enums are ints in Java/Swift with no name, and a mis-set role is a
security-relevant bug.

### 7.3a Invite links and join requests

An invite link is **an invitation a member has already made**, not a public door. This is what
reconciles links with the v1 profile: external commits are not implemented and are parse-refused
(§3.1), so nothing arriving over a link can join a group by itself. Every join is still an `Add`
proposed by a current member and a `Welcome` produced by a commit.

Two kinds, and the default is the narrow one:

- **One-time link (default).** A member creates it for one person. It carries a rendezvous id and a
  one-time capability. Redeeming it produces a join request that is already attributed to the
  inviting member, so accepting it needs no further approval: the client that created the link
  commits the `Add` as soon as the redeemer presents a key package.
- **Reusable published address.** A group may publish a durable address that means *requests land
  here for a member to approve*. Redeeming it produces a **join request** that any ADMIN or the
  OWNER accepts or declines. It never admits anyone by itself. **Revoking a published address
  disturbs no existing member**: it invalidates the address for future requests and commits
  nothing to the group's membership.

```go
func (self *MessageClient) CreateInviteLink(groupId string, reusable bool,
    expiresInMs int64, callback InviteLinkCallback) *MessageSendTicket
func (self *MessageClient) InviteLinks(groupId string) *MessageInviteLinkList
func (self *MessageClient) RevokeInviteLink(groupId string, linkId string) error

// the redeeming side. The URL is opaque to the caller and is parsed here, so a
// malformed or expired link is a typed error rather than a request nobody answers.
func (self *MessageClient) RedeemInviteLink(url string,
    callback GroupCallback) *MessageSendTicket

// the approving side, for reusable addresses.
func (self *MessageClient) JoinRequests(groupId string) *MessageJoinRequestList
func (self *MessageClient) AcceptJoinRequest(groupId string, requestId string,
    callback GroupCallback) *MessageSendTicket
func (self *MessageClient) DeclineJoinRequest(groupId string, requestId string) error
func (self *MessageClient) AddJoinRequestListener(listener JoinRequestListener) *Sub

type MessageInviteLink struct {
    LinkId            string
    GroupId           string
    Url               string   // the urmessage:// form Spec C renders and shares
    Reusable          bool
    CreatedByMemberId string
    CreatedAtMs       int64
    ExpiresAtMs       int64    // 0 = no expiry; one-time links default to 7 days
    Redeemed          bool     // one-time links only
    Revoked           bool
}

type MessageJoinRequest struct {
    RequestId        string
    GroupId          string
    Principal        string
    DisplayName      string
    KeyFingerprint   string
    ViaLinkId        string
    RequestedAtMs    int64
    State            string   // CLOSED: "pending" | "accepting" | "accepted" | "declined" | "expired"
}

type InviteLinkCallback interface { InviteLinkCreated(link *MessageInviteLink, err error) }
type JoinRequestListener interface { JoinRequestChanged(request *MessageJoinRequest) }
```

`MessageInviteLink` and `MessageJoinRequest` each get a `*List` wrapper per the §7.1 pattern.

**What the link contains, and what it does not.** It carries the group id, the rendezvous id, the
inviting member's identity fingerprint, and the capability. It carries **no group key**: a link that
could decrypt anything would make the link the membership secret, which is the property invite-only
exists to avoid. A redeemer learns the group exists and who invited them, and nothing else until a
`Welcome` arrives.

**Rate limits.** Redemption of a reusable address is rate-limited per redeeming client and per
address; a burned one-time link is refused with a typed error rather than silently producing a
request that no one will approve.

An invite link needs someone already inside the group. Two people who have never met and are not in a
group together cannot reach each other with one, which is why §7.3b exists.

### 7.3b Contact cards

An invite link needs someone already inside a group, and a directory lookup needs the other person to
have turned listing on. Two people who have neither cannot reach each other at all, which makes the
product unusable exactly at first contact — and unusable for anyone who never wants to be listed. A
**contact card** closes that: a QR code and a copyable `urmessage://` link that its owner hands to
someone directly, out of band, and that opens a direct conversation with no directory involved and no
transparency log required.

```go
// this identity's current card. Cheap, local, no network.
func (self *MessageClient) ContactCard() *MessageContactCard

// mint a new capability and retire the current one. Existing conversations are untouched;
// only the ability of a NEW holder to open one is withdrawn. Commits nothing to any group.
func (self *MessageClient) RotateContactCard(callback SendCallback) *MessageSendTicket

// the receiving side. The URL is opaque to the caller and is parsed here, so a malformed,
// retired or unsupported card is a typed error rather than a request nobody answers.
// AddContactByCard pins the key without opening a conversation; StartDirectFromCard pins
// it and asks the card's owner for a two-member group.
func (self *MessageClient) AddContactByCard(url string) (*MessagePin, error)
func (self *MessageClient) StartDirectFromCard(url string,
    callback GroupCallback) *MessageSendTicket

// the card owner's side: requests that arrived through a card.
func (self *MessageClient) ContactRequests() *MessageContactRequestList
func (self *MessageClient) AcceptContactRequest(requestId string,
    callback GroupCallback) *MessageSendTicket
func (self *MessageClient) DeclineContactRequest(requestId string) error
func (self *MessageClient) AddContactRequestListener(listener ContactRequestListener) *Sub

type MessageContactCard struct {
    Url                    string   // the urmessage:// form; what a user copies
    QrPayload              string   // the same bytes, for a QR renderer
    DisplayName            string
    IdentityKeyFingerprint string
    SafetyDigits           string   // the same 12 groups of 5 that SafetyNumber() renders,
                                    // so a recipient can read them back over a phone call
    TokenId                string   // Crockford base32 of the first 8 bytes of rendezvous_id.
                                    // A display and log handle for "which card"; never an
                                    // authenticator, and it identifies the capability, not
                                    // the identity
    Generation             int32    // the capability generation k of §5.14; 0 is the first
    State                  string   // CLOSED: "registering" | "live" | "expired" | "retired"
                                    //       | "unavailable"
    CreatedAtMs            int64
    RotatedAtMs            int64    // 0 until the first rotation
    ExpiresAtMs            int64    // when the registration lapses if no device collects
}

type MessageContactRequest struct {
    RequestId      string
    Principal      string   // empty unless the requester's directory listing is on
    DisplayName    string
    KeyFingerprint string
    SafetyDigits   string
    ViaTokenId     string
    RequestedAtMs  int64
    RefusedSinceLastCollect int32   // requests the server refused at this card since the last
                                    // collection. A property of the card, so it carries the same
                                    // value on every request in one collection (§7.3b)
    State          string   // CLOSED: "pending" | "accepting" | "accepted" | "declined"
                            //       | "expired" | "token_retired" | "held_for_review"
}

type ContactRequestListener interface { ContactRequestChanged(request *MessageContactRequest) }
```

`"held_for_review"` is the state a request takes when automatic acceptance is suspended by the rate
fallback below: the request is intact and waiting for the owner, and it is not `"pending"`, because
the owner needs to know the difference between a request that is waiting for a tap by preference and
one that is waiting because the card is under load.

`ContactCard()` is local and does not block on the network, but the card it returns is not usable
until its registration has reached the server, so `State` is part of the contract rather than a
detail: `"registering"` until the rendezvous exists, `"live"` once it does, `"expired"` when the
registration lapsed because no device of this identity collected inside the server's advertised
window, `"retired"` for a generation that has been rotated away, and `"unavailable"` on a device
that has been offline across more rotations than it can probe forward through. A client MUST NOT
present a link or a QR for a card that is not `"live"`, because a card that cannot receive is worse
than no card: the person it was handed to gets a refusal and no explanation.

`MessageContactRequest` gets a `*List` wrapper per the §7.1 pattern. `MessageContactCard` does not:
this identity has exactly one current card, and `ContactCard()` returns it directly.

**The card is per identity, not per device.** `card_root` derives from the master key (§5.14), so
every device of an identity computes the same generation, the same token and the same
`rendezvous_id`: `ContactCard()` returns the same `Url`, `QrPayload` and `TokenId` on the laptop and
on the desktop, and `RotateContactCard` on either retires the identity's card everywhere. A device
that is offline at the moment of rotation still shows the stale card until it next syncs, and that
stale card is **inert** rather than live — the rendezvous it addresses has been retired, so a
redemption of it is refused. A newly linked device receives the current generation number in the
device-link payload (§7.5) and derives the rest; the payload never carries the token itself, because
the generation number plus the seed is smaller and is all that is needed.

**What the card contains.** A version byte, an algorithm id, the owner's Ed25519 identity public
key, a 16-byte capability token, a display name of at most 64 UTF-8 bytes, and a checksum over all
of it — 131 bytes, encoded identically in the `urmessage://` link and in the QR (§5.14). It carries
**no group key**, no device key, **no encryption key** and **no URnetwork principal** — handing
someone a way to message you should not also hand them the name of the account that pays for your
traffic, and the two are unlinked by design (MASTER §4.2). A holder who also knows the principal
learns nothing new; a holder who does not, does not learn it here.

**What redeeming one does.** The redeemer pins the identity key immediately and locally, with
`MessagePin.EvidenceClass == "out_of_band"` — the key came from the person, not from a directory or a
log, and that is a stronger provenance than either, not a weaker one. It then opens the **contact
rendezvous** the token addresses (MASTER §9.8, Spec B §4.3.11), seals a contact request carrying its
key package and a signature under its own `identity` key to the card's KEM key, and deposits it.
Nothing has happened in any group at that point and the redeemer has no conversation yet:
`StartDirectFromCard` returns a ticket that completes when the deposit is accepted, and the
conversation appears only when the card owner's client collects the request, verifies the inner
signature, creates the two-member group and issues the `Welcome`. No external commit is involved and
none is possible: the v1 profile parse-refuses them (§3.1), so a card can never admit anyone by
itself. Whether the owner's client commits immediately or waits for a tap is the
`"contact_card_auto_accept"` user preference, defaulting to immediate, because a token the owner
handed out is already the owner's decision.

**The card is a capability, and capabilities have to be revocable.** Anyone who obtains the link —
forwarded, screenshotted, scraped from a slide — can open a conversation with the owner until the
token is retired. `RotateContactCard` mints a fresh token and retires the current one: a redemption
of the old link fails with `GroupResult` reason `"card_retired"`, and **every conversation already
started stays exactly as it was**, because the token authorises first contact and nothing else. A
user who rotates loses the printed cards and the old screenshots, never a friend — and, unless the
client collects first, any request deposited at the old rendezvous and not yet collected, which is
why `RotateContactCard` collects everything outstanding before it retires (§5.14, MASTER §11). The
rotation is written to the local security log as
`MessageSecurityLogEntry{Kind: "contact_card_rotated"}`, so "when did I last change this" has an
answer.

**Rate limits, and what happens when they bind.** The server limits deposits per rendezvous and per
depositing client, and bounds each rendezvous to sixteen uncollected requests; the values are
advertised in `Capabilities` and reach this surface through `ServerInfo()`, never as literals (Spec
B §4.3.11, §4.7). A refusal for depth or rate is `GroupResult` reason `"card_rate_limited"`. A
retired card, and a token the server has never seen, both return `"card_retired"` — the same answer,
deliberately, because "this link is no longer live" is true of both and distinguishing them would
let a party test guessed tokens. A card that has taken an unusual number of requests in a short
window surfaces that fact to its owner rather than only throttling in silence: `ContactRequests()`
carries the count the server refused since the last collection, and the SDK falls back to manual
review for the remainder of the hour once more than three requests arrive at one card within an
hour, regardless of the `"contact_card_auto_accept"` preference, so a firehose cannot turn itself
into groups while the owner is asleep.

`"card_retired"`, `"card_rate_limited"` and `"card_not_live"` are members of `GroupResult.Reason`'s
closed set (§7.7), and `"contact_card_rotated"` of `MessageSecurityLogEntry.Kind`'s (§7.6).

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
    State            string   // "pending"|"sent"|"delivered"|"read"|"failed"|"expired"
    Reason           string   // set iff State == "failed"; §7.2 vocabulary 2
    ReasonDetail     string
    RetryAfterMs     int64    // > 0 only when Reason == "rate_limited"; 0 otherwise. Same
                              // source and same reason for the width as
                              // MessageSendability.RetryAfterMs.
    ExpiresAtMs      int64    // 0 when not disappearing
    RetentionClass   string   // "permanent"|"durable"|"media"|"eph"
    EphBucket        int32
    SizeBucket       int32
    Edited           bool     // reserved; always false in v1
    Attachments      *MessageAttachmentList
    Reactions        *MessageReactionList
    DeliveredTo      *MessageReceiptList   // MemberId + the earliest receipt time
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
    AutoDownloadHeld bool // true when the body was NOT fetched because the sender is not
                          // yet a known contact or the group is newly joined (§7.4).
                          // State is "not_downloaded".
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

`DeleteForEveryone` is bounded to **24 hours from `SentAtMs`**. Outside the window the call fails
with send-failure reason `delete_window_expired` and writes no record, and a `TOMBSTONE` naming a
record older than 24 hours is ignored on receipt rather than applied — otherwise the bound would be
a client-side courtesy that any modified client could ignore. Inside the window the entry becomes
`Kind == "tombstone"` and stays visible as a placeholder; it is never removed from the timeline.

**Attachments auto-download from known senders only.** `sdk` fetches an attachment body without
being asked when **both** hold: the sender's principal already has a `MessagePin` (§7.6), and this
device has been a member of the group for at least 24 hours. Otherwise the entry arrives with
`MessageAttachment.State == "not_downloaded"` and `AutoDownloadHeld == true`, and the body is
fetched when the user asks for it. The `"attachment_auto_download"` preference (§7.2) can widen this
to `"always"` or narrow it to `"never"`; `"known_contacts"` is the default. This closes
unsolicited-attachment decoder exposure — the case where an unknown party's first contact is bytes
your image decoder parses — without making image-heavy groups feel broken, since every group you
have been in for a day behaves normally.

**Ordering is the server's; the timestamp is the sender's.** `History`, `Entry` and every
`MessageEvent` order messages by the server-assigned `record_id`, which is per-group, gapless and
agreed by every client, and which no client can manipulate. `MessageEntry.SentAtMs` is
sender-claimed and is **rendered as the label** — it is what a user reads next to a message — and it
**never determines order**. A message whose claimed timestamp precedes the one above it is displayed
where the server put it, with its own claimed time. `TestOrderIsServerOrder` asserts that a record
with a `sent_at` far in the past or the future lands in `record_id` position.

`Kind == "gap"` is a first-class entry type: an undecryptable or missing record renders as a visible gap
with its reason. `GapReason` is a **closed set**: `"expired"`, `"out_of_window"`, `"not_a_member_yet"`,
`"withheld"`, `"no_wrap"`, `"malformed"`. `"malformed"` is a record that arrived and failed
validation — the reaction-body rule of §7.4a is the first producer of it. Attachment outcomes are
**not** gap reasons — a pruned or failed attachment is
an `AttachmentState`, so the client can tell "kept for a month and then pruned" from "the download
failed", which are different sentences to a user. A messenger that silently drops what it cannot read is
a messenger that cannot be trusted to have shown you everything.

```
MessageEntry.State is a CLOSED set:
  "pending" | "sent" | "delivered" | "read" | "failed" | "expired"

  pending    in the local outbox; not yet accepted by the message server
  sent       accepted by the message server
  delivered  at least one device of at least one other member emitted a delivery
             receipt for it — a statement by a device that decrypted the record,
             never an inference by the server, which cannot make one (MASTER §9.5)
  read       a read receipt was received (only when both sides have receipts on)
  failed     terminal; carries a Reason from the closed send-failure vocabulary
  expired    the disappearing timer elapsed and the key is gone

The state is monotonic in that order for a given message, and a receipt that would
move it backwards is applied to the per-member list and ignored for the state.
```

**The delivery receipt is a record, not a server signal.** When a device successfully opens a
record's body it emits one `EPH(bucket 0)` receipt naming the record and nothing else, under the
same batching and the same never-persisted handling as read receipts and typing indicators (MASTER
§12.2). It is emitted only if the emitting user's `"delivery_receipts"` preference and the group
policy's `DeliveryReceipts` both allow it, exactly as for read receipts (§7.3). `MessageEntry`
therefore carries both lists:

```go
    DeliveredTo      *MessageReceiptList   // MemberId + the earliest receipt time
    ReadBy           *MessageReceiptList
```

The cost is real and is disclosed rather than buried: a receipt emitted on decryption tells the
message server when a device of that group was online and processing, which read receipts alone did
not. MASTER §9.5 and §13 state it.

#### 7.4a Reactions

**A reaction carries any emoji, and the field is a string on the wire.** `React(groupId, targetId,
emoji, cb)` takes whatever the user picked. The record body is `REACTION { u8 op,
LP(target_message_id), LP(emoji_utf8) }` (§5.1), and `connect/message` validates `emoji_utf8` on
**both** send and receipt against one pinned Unicode version:

- valid UTF-8, 1 to 64 bytes;
- exactly **one extended grapheme cluster**, so a joined sequence is one reaction and can never
  become several;
- every codepoint drawn from the emoji properties of the pinned Unicode version, plus zero-width
  joiner, the two variation selectors, regional indicators, tag characters and the skin-tone
  modifiers.

A call whose emoji fails validation returns the error to the `SendCallback` and emits no record; it
is a call error, not a send state, and adds no value to the closed send-failure vocabulary. A
**received** record that fails validation renders as a gap with reason `"malformed"` rather than as a
reaction — a record that cannot be shown is shown as unshowable, never silently dropped.

**Grouping and display are two different strings.** `MessageReaction.Emoji` is the grouping key:
Normalisation Form C with skin-tone modifiers and variation selectors removed.
`MessageReaction.EmojiRaw` is exactly what a reactor sent. Counts group on the key, so a thumbs-up
with a skin tone and one without are the same pill; display uses whichever raw form the client
prefers, and a client that renders the key is also correct. Skin tone is removed rather than
preserved because a reaction is a one-tap gesture and a tone attached to it carries a signal the
reactor did not choose to send.

**The Unicode version is pinned and stated.** `connect/message` vendors the emoji property tables for
one named Unicode version, and both the sender's validation and the receiver's use the same tables.
Without that, a sender on a newer version emits something a receiver refuses, and the reaction
disappears with no explanation on either side. Updating the version is a deliberate change with its
own test vectors, not a dependency bump.

`TestReactionGroupingKey` asserts the skin-tone and variation-selector folds and asserts that a
joined sequence survives as one cluster. `TestReactionRejectsNonEmoji` asserts that text, an empty
string, two clusters and an over-length string are all refused on send **and** on receipt, because a
rule enforced only on the sending side is a rule a modified client ignores.

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

// v1 multi-device is desktop-to-desktop. Neither machine has a camera, so the
// primary path is a SHORT typed code plus a numeric comparison, and the QR is a
// convenience for a machine that can read one.
func (self *MessageDeviceLinkSession) PairingCode() string
// 2 groups of 4 uppercase Crockford base32 characters = 40 bits of rendezvous
// entropy, e.g. "K7QM-3XB9". Lifetime 10 minutes. Rate-limited to 5 attempts per
// code and 20 per client_id per hour; 3 failures burn the code permanently.
// 40 bits with 3 attempts in 10 minutes is not an online-guessing surface, and a
// 32-character code that a user retypes across a room is a code that gets
// mistyped, abandoned, or photographed.
func (self *MessageDeviceLinkSession) SasDigits() string
// 6 decimal digits, shown on BOTH machines and compared by the user out loud or
// by eye. This is the authentication; the pairing code is only the rendezvous.
// Confirm(false) on either side aborts and burns the code.
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

An identity may hold at most **ten device leaves** (MASTER §11). `BeginDeviceLink` fails with a
typed error naming the cap when the identity already holds ten, and the UI states the limit before
the user starts (Spec C §12.5) rather than after they have typed a code on a second machine.

The provisioning bundle carries the group list and **durable-class** archive material only.
Ephemeral-class material is never included (MASTER I4). `TestProvisioningBundleHasNoEphemeral`
asserts by construction: the bundle builder takes a `DurableArchive` type that has no field capable
of holding an `eph_root`.

The bundle also carries the identity's **current contact-card generation number** (§5.14), so a
newly linked device shows the same card as every other device of the identity rather than minting
one of its own. It carries the number and not the token: the token derives from the seed and the
generation, and shipping the smaller value is what keeps a linked device from holding a capability
it could not have re-derived anyway.

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
    OperatorHost     string   // the operator whose directory and log this evidence came from.
                              // Evidence from one operator is never compared with evidence from
                              // another; a head from operator A says nothing about operator B.
                              // Empty for a key that came from a contact card (§7.3b), which
                              // came from no operator at all.
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
    OperatorHost       string
    Seq                int64
    Dropped            int64
}

type MessageDirectoryResult struct {
    Principal              string
    DisplayName            string
    IdentityKeyFingerprint string
    ProofState             string   // CLOSED: "included" | "proof_missing" | "log_unavailable"
    OperatorHost           string
}
type DirectoryCallback interface {
    DirectoryResult(results *MessageDirectoryResultList, err error)
}
// ProofState decides what a resolution may be used for, and the three values are three
// different situations rather than three degrees of the same one:
//
//   "included"        the log answered and the inclusion proof verifies. The resulting pin
//                     carries EvidenceClass "kt_inclusion".
//   "proof_missing"   the log answered and the proof did not verify. FAIL CLOSED: this result
//                     MUST NOT be used to start a conversation, pin a key, or add a member.
//                     This is the event key transparency exists to catch, and it is the only
//                     resolution outcome that fails closed.
//   "log_unavailable" no log was reachable at all. The result MAY be used. The resulting pin
//                     carries EvidenceClass "kt_unavailable", and every surface that shows the
//                     contact renders that state explicitly rather than showing nothing —
//                     Spec C §7.3's evidence rows, the contact sheet, and the key-change sheet.
//
// Before the transparency log and its four client endpoints are live, every lookup returns
// "log_unavailable" and the product is usable in that state; MASTER §15 item 6 makes the live
// log a general-availability gate rather than a beta gate, and applies the same treatment to
// lookups that it applies to key changes. From the release in which the log is live,
// "log_unavailable" is treated as "proof_missing" and fails closed, because at that point an
// unreachable log is a fact about an attack or an outage rather than about the schedule.

type IntegrityEvent struct {
    Kind                string   // CLOSED: "fork_resyncing" | "fork_unresolved"
                                 //       | "attestation_gap" | "server_key_rotated"
                                 //       | "server_key_untrusted"
    GroupId             string
    Epoch               int64
    OursHex             string   // fork: our confirmed_transcript_hash
    TheirsHex           string   // fork: the peer's
    MessageId           string   // attestation_gap
    AttestationServerTimeMs int64
    CoveredSinceRecordId    int64
    CoveredUntilRecordId    int64
    ServerHost          string   // server_key_rotated | server_key_untrusted
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
//   "kt_unavailable"      no KT log was reachable; the key or the change rests on no
//                         transparency evidence. This is the state every lookup and every key
//                         change is in until the log is live (§7.6b), and the permanent, correct
//                         state of an identity that has never listed itself
//   "out_of_band"         the key came from a contact card the identity's owner handed over
//                         directly (§7.3b). Stronger provenance than any directory answer, not
//                         weaker, and rendered as such
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

**Server keys chain to a root compiled into this DLL.** `sdk` carries a hardcoded Ed25519 **fleet
root public key** and verifies the message server's key against it on the **first** fetch, which is
the only unauthenticated moment in the design and the only one that cannot be closed after
installs have shipped. The server presents its current signing key with a signature by the root over
`"URmessage/v1/serverkeyroot" ‖ LP(server_id) ‖ LP(key_pub) ‖ u64(not_before_ms) ‖ u64(not_after_ms)`,
and successors chained by the outgoing key exactly as Spec B §4.3.1 specifies.

- A key that **chains** — to the root, or to a key that chains to the root — is accepted
  **silently**. No modal, no prompt, no user decision. `sdk` appends one entry to an inspectable
  security log and raises `IntegrityEvent{Kind: "server_key_rotated"}`.
- A key that **does not chain** is refused. The session is not established, no data is fetched,
  `MessageServerInfo.KeyState` is `"untrusted"`, and health reports `server_key_untrusted`. **There
  is no call that accepts it**, deliberately: an accept affordance on this screen is a button that
  gets clicked, and with a root pin there is no legitimate case in which it would be correct to
  click it.

There is no `AcceptServerKey` call on this surface, and there must never be one: trust-on-first-use
for the **server** key is replaced by the root pin. Trust-on-first-use for **contacts** is unchanged
and is what the rest of this section is about.

```go
// the inspectable log Spec C §12.6 renders. Append-only, local, bounded to 500
// entries, and never contains message content.
func (self *MessageClient) SecurityLog() *MessageSecurityLogEntryList

type MessageSecurityLogEntry struct {
    AtMs           int64
    Kind           string   // CLOSED: "server_key_rotated" | "server_key_untrusted"
                            //       | "key_change_accepted" | "identity_removed"
                            //       | "pin_set" | "pin_cleared" | "diagnostic_session"
                            //       | "device_added" | "device_removed"
                            //       | "contact_card_rotated"
    Subject        string   // a principal, a server host, or a device name
    Detail         string   // display only; never parsed
}
```

When a rotation is applied, `sdk` discards every retained `FetchAttestation` signed under the
outgoing key rather than silently trusting it, and reports the invalidated
`(CoveredSinceRecordId, CoveredUntilRecordId)` range on the `server_key_rotated` `IntegrityEvent` so
Spec C can name it in the security log entry.

**Fork detection resyncs before it stops anything.** A `confirmed_transcript_hash` divergence is a
security signal and also the signal a bad server deploy produces, and the two are
indistinguishable at the moment of detection. `sdk` therefore attempts an automatic
`ResyncGroup` first — re-fetching the group's records and rebuilding epoch state from the snapshot
— and raises `IntegrityEvent{Kind: "fork_resyncing"}` while it does. Sending in that group continues
during the attempt.

Only if the resync fails does the client raise `IntegrityEvent{Kind: "fork_unresolved"}`, disable
sending with `CanSend` reason `fork_unresolved`, and surface the hard stop. The security property is
unchanged — a genuine fork still stops sending, because a genuine fork does not resolve on a refetch
— while the blast radius of one bad deploy is no longer "nobody in this group can send until every
member individually clicks a button". Backoff is full jitter, base 2 s, cap 60 s, three attempts.

**Directory listing is off until asked for.** `LookupPrincipal` resolves only identities that have
opted in, and `SetDirectoryListed` (§7.2) is the only call that publishes one. An identity that has
never called it has no directory entry and no key-transparency leaf, so `MessagePin.EvidenceClass`
for that identity is `"kt_unavailable"` — which is a true statement rather than a degradation, and
Spec C renders it as its own row (Spec C §7.3).

#### 7.6a Key transparency is scoped to an operator

**Every key-transparency artefact is scoped to the operator it came from.** More than one operator
exists, each runs its own directory and its own log, and divergence between two operators' logs is
the normal case and means nothing. `MessagePin`, `KeyChangeWarning` and `MessageDirectoryResult`
therefore each carry the resolving operator's host; `kt_head` is keyed by `(operator_host,
kt_epoch)` and `pin` by `(principal, operator_host)` (§8.1); and `sdk/message_kt.go` compares a
gossiped signed tree head only against a head from **the same** operator's log. Comparing across two
would raise the blocking equivocation warning of MASTER §10.2 on an entirely healthy system, which is
the worst possible failure mode for a warning whose value depends on never crying wolf.

The message server's gossip counts as a second path only when the server's operator is this client's
operator. `MessageServerInfo.OperatorHost` names the server's; `NetworkSpaceHost()` names this
client's; `MessageServerInfo.KtGossipUsable` is the comparison, computed once by this layer so no
caller has to remember to make it. When it is false, this client has one path — the operator itself —
until it obtains a second from peer clients, and it does not upgrade an evidence class on the
strength of a head from a log its resolutions did not come from. The server-side half of this rule is
Spec B §9.5.

#### 7.6b What a resolution means before the log is live

**A resolution with no reachable log proceeds, and says so.** `sdk/message_kt.go` distinguishes three
outcomes and treats only one of them as an attack. A resolution answered **with** an inclusion proof
that verifies produces evidence class `"kt_inclusion"`. A resolution answered with a proof that does
**not** verify is a hard failure — `KtProofMissing`, no pin, no conversation, nothing started —
because the log spoke and the proof was wrong, and that is precisely the event this machinery exists
to catch. A resolution made when **no log is reachable at all** proceeds, and produces evidence class
`"kt_unavailable"`, which every surface renders explicitly rather than silently: it is a true
statement about what is known, not a degradation to be hidden.

Before the transparency log, its four client endpoints and its monitor role are live, every lookup
lands in the third case and the product works in that state. MASTER §15 item 6 makes the live log a
general-availability gate rather than a beta gate, and applies to lookups exactly what it applies to
key changes; a lookup that failed closed before the log existed would leave a beta with no way to
start any conversation at all. From the release in which the log is live, an unreachable log is a
fact about an outage or an attack rather than about the schedule, and this layer treats it as the
second case.

An identity that has never turned directory listing on has no directory entry and no log leaf, so
`"kt_unavailable"` is its permanent and correct state; a key obtained from a contact card carries
`"out_of_band"` instead, because it came from the person rather than from any log (§7.3b). Spec C
§7.3 renders each of these as its own row.

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
type InviteLinkCallback    interface { InviteLinkCreated(link *MessageInviteLink, err error) }
type JoinRequestListener   interface { JoinRequestChanged(request *MessageJoinRequest) }
type ContactRequestListener interface { ContactRequestChanged(request *MessageContactRequest) }
type BalanceListener       interface { BalanceChanged(balance *MessageBalance) }
type BalanceRedeemCallback interface { BalanceRedeemed(result *BalanceRedeemResult, err error) }

type MessageEvent struct {
    Kind      string   // CLOSED: "appended" | "state_changed" | "reactions_changed"
                       //       | "delivered_changed" | "read_changed" | "typing_changed"
                       //       | "removed" | "gap"
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
                              //       | "policy_changed" | "policy_pending"
                              //       | "sendability_changed" | "invited" | "left"
                              //       | "removed" | "closed" | "history_granted"
                              //       | "ownership_changed" | "succession_changed"
                              //       | "join_request_changed"
    GroupId          string
    Group            *MessageGroup
    Sendability      *MessageSendability
    RetentionApplied *MessageRetentionApplied
    PendingPolicy    *MessagePendingPolicy   // "policy_pending"; §7.3's joint DM control
    Succession       *MessageSuccessionState // "succession_changed" | "ownership_changed"
    Seq              int64
    Dropped          int64
}

// a DM policy change that LENGTHENS retention or the disappearing timer. It commits
// nothing until the other member sets the same value, and expires after seven days.
// §7.3.
type MessagePendingPolicy struct {
    RequestedByMemberId string
    RetentionDurableMs  int64
    RetentionMediaMs    int64
    DisappearingBucket  int32
    RequestedAtMs       int64
    ExpiresAtMs         int64
}

// Seconds, not milliseconds: this struct is a field-for-field mirror of the message
// server's RetentionApplied, and every retention value in the system is seconds
// (EpochAttachment.media_ttl_seconds / durable_ttl_seconds, media_ttl_max_seconds,
// durable_retention_min_seconds). The two differ only in Go casing.
//
// DurableTtlSeconds is what the server actually stored. 4294967295 means indefinite; 0
// never appears in an applied value, because "unset" is a request and not an outcome.
// DurableDefaulted is true when the group sent nothing and the server supplied its own
// default, which is the case the in-group notice must name differently from a clamp —
// "this group keeps messages for a year because that is this server's default" and "this
// group asked for longer and got a year" are different sentences.
type MessageRetentionApplied struct {
    MediaTtlSeconds            int64
    DurableTtlSeconds          int64
    MediaClampedDown           bool
    DurableFlooredUp           bool
    RequestedMediaTtlSeconds   int64
    RequestedDurableTtlSeconds int64
    DurableClampedDown         bool
    DurableDefaulted           bool
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
    DeliveryReceipts   bool
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
    Emoji     string        // the grouping key: NFC, skin-tone modifiers removed, variation
                            // selectors removed. Two reactions group together iff their grouping
                            // keys are byte-identical (§7.4).
    EmojiRaw  string        // exactly what a reactor sent, for display. Never used for grouping.
    Count     int32
    MemberIds *StringList   // who reacted, in first-seen order
    MineSet   bool          // this device's own account is among them
}

// used by both MessageEntry.DeliveredTo and MessageEntry.ReadBy. In DeliveredTo,
// ReadAtMs carries the earliest delivery receipt seen from that member's devices.
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
    SasDigits  string   // the 6 digits both machines show and the user compares (§7.5)
    AuthString string   // the same authentication value in its long form, for display
    Reason     string
}

type SyncResult   struct { GroupId string; RecordsFetched int32; Complete bool; Reason string }
type SendResult   struct { GroupId string; MessageId string; State string; Reason string }
type GroupResult  struct { GroupId string; Kind string; Reason string
                           PartialInvites *StringList /* principals whose invite failed */ }
// GroupResult.Reason is CLOSED and is its own vocabulary, separate from §7.2's three:
//   "ok" | "not_permitted" | "owner_must_transfer" | "admin_removal_is_owner_only"
//   | "awaiting_other_party" | "durable_override_not_permitted" | "group_size_exceeded"
//   | "device_limit_exceeded" | "succession_disabled" | "succession_not_nominee"
//   | "succession_quorum" | "succession_floor" | "succession_floor_too_short"
//   | "link_expired" | "link_revoked" | "link_already_redeemed"
//   | "card_retired" | "card_rate_limited" | "card_not_live"
//   | "rate_limited" | "offline" | "internal"
type RestoreProgress struct { Phase string; GroupId string; GroupName string
                              MessagesDone int64; MessagesTotal int64
                              GroupsDone int32; GroupsTotal int32
                              Outcome string /* "full"|"partial"|"nothing_found"|"read_only" */
                              Reason string }
type DownloadProgress struct { GroupId string; MessageId string; AttachmentId string
                               BytesReceived int64; BytesTotal int64; LocalPath string }
```

`"succession_floor_too_short"` maps from `ErrSuccessionFloorTooShort`, which §3.4 defines and which
previously fell through to `"internal"` — the exact outcome §7.3 promises will not happen; extend
`TestSuccessionRequiresAllFive` to assert each of the five typed errors surfaces as its own reason.
`"card_not_live"` is returned by `StartDirectFromCard` when the *local* card is not `"live"`, which
is a different failure from the remote card being retired.

`MessageInvite`, `MessageReaction`, `MessageReceipt`, `MessageHistoryGrant`, `MessageInviteLink`,
`MessageJoinRequest`, `MessageContactRequest` and `MessageSecurityLogEntry` each get a `*List` wrapper
per the §7.1 pattern: `MessageInviteList`, `MessageReactionList`, `MessageReceiptList`,
`MessageHistoryGrantList`, `MessageInviteLinkList`, `MessageJoinRequestList`,
`MessageContactRequestList`, `MessageSecurityLogEntryList`.

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

### 7.9 Data allowance and balance codes

Messaging consumes the user's own URnetwork data allowance on their own operator (MASTER §4.5).
This DLL already owns the account session (decision A12), so it owns the balance surface too; there
is no second runtime to ask.

```go
func (self *MessageClient) Balance() *MessageBalance
func (self *MessageClient) AddBalanceListener(listener BalanceListener) *Sub

// Redeem a balance code issued by an operator. Wraps the operator's existing
// balance-code redemption endpoint through the account session this DLL holds;
// no new server-side mechanism is required for it.
func (self *MessageClient) RedeemBalanceCode(code string,
    callback BalanceRedeemCallback) *MessageSendTicket

type MessageBalance struct {
    State            string   // CLOSED: "ok" | "low" | "exhausted" | "unknown"
    AvailableBytes   int64    // -1 when unknown
    PeriodEndsAtMs   int64    // when the current free allowance refreshes; 0 if not applicable
    CheckedAtMs      int64
    FreeAllowanceBytesPerDay int64   // the operator's free daily allowance for this account;
                                     // -1 when unknown. An operator sets this and may change it,
                                     // so a client that renders it as a literal is stating an
                                     // operator's pricing decision as a product fact.
}

type BalanceRedeemResult struct {
    Ok             bool
    GrantedBytes   int64
    Reason         string   // CLOSED: "ok" | "invalid_code" | "already_redeemed"
                            //       | "expired" | "rate_limited" | "offline" | "internal"
    Detail         string   // display only; never parsed
}

type BalanceListener       interface { BalanceChanged(balance *MessageBalance) }
type BalanceRedeemCallback interface { BalanceRedeemed(result *BalanceRedeemResult, err error) }
```

```c
uint64_t urmsg_client_redeem_balance_code(uint64_t client, const char* code,
                                          urmsg_balance_redeem_cb cb, void* user_data);
char*    urmsg_client_balance(uint64_t client);   /* json */
```

**`State == "exhausted"` is a first-class condition, not a transport failure.** `CanSend` returns
reason `out_of_credit`, health reports state `out_of_credit`, and the client tells the user where to
add credit — the URnetwork website, app or VPN client. **URmessage contains no purchase flow and
sets no price**; operators price data, and this product only spends and redeems. `"unknown"` is what
the client reports before it has ever reached the account API, and it is never rendered as a number.

`"invalid_code"` and `"already_redeemed"` are deliberately distinguishable to the user, because the
two have different remedies and a beta tester retyping a code needs to know which one they hit.
Redemption is rate-limited at the operator; `"rate_limited"` carries a retry hint in `Detail`.

---

## 8. Local persistence and sealing

### 8.1 What is stored

| Data | Store | Sealed | Deleted when |
|---|---|---|---|
| **BIP39 entropy (256 bits)** | keyfile | **yes**, DPAPI context `"seed_entropy"`, and additionally under the PIN wrap when one is set | `RemoveIdentity()` |
| `master_key` children (`identity` priv, `recovery_root`, `recovery_sig_seed`) | keyfile | **yes** | identity reset |
| **`phrase_confirmed_at` (unix ms)** | keyfile | **yes** | `RemoveIdentity()` |
| `device_sig` (Ed25519 leaf key), `device_xwing` (X-Wing seed) | keyfile | **yes** | device removed from all groups |
| MLS group state per (group, epoch) | SQLite `mls_state` | **yes**, per-row blob | `DeleteGroupStateBefore`, epoch window **32** |
| MLS private keys by public key | SQLite `mls_private` | **yes**, per-row | key superseded or leaf removed |
| Pending KeyPackages + their private halves | SQLite `mls_keypackage` | **yes** | Welcome consumed, or 30-day lifetime expiry |
| `eph_root[n]` | SQLite `eph_root`, inside the epoch state row | **yes** | window closes, or epoch falls out of the window |
| Record ciphertext (as received) | SQLite `record` | no — it is already ciphertext | retention class + `expire_at` |
| Decrypted display bodies | SQLite `entry.body_sealed` | **yes**, **per row** under `local_store_key` | group left, message deleted, disappearing timer |
| Display metadata index (group id, message id, `record_id`, sender handle, timestamps, state, class) | SQLite `entry`, plaintext columns | no — deliberately, §8.3a | with the row |
| **`local_store_key` (32 B)** | keyfile | **yes**, DPAPI, and additionally under the PIN wrap when one is set (§8.6) | `RemoveIdentity()` |
| **PIN verifier and Argon2id parameters** | keyfile | **yes** | PIN cleared, or `RemoveIdentity()` |
| Retained read keys per (group, epoch) | SQLite `read_key` | **yes**, per-row | group left, or the epoch ages out of the client's own retention |
| Attachment blobs | files under `StorageDir/media/` | file body encrypted under the message's class key | MEDIA retention, 1 month default |
| TOFU pins, keyed by `(principal, operator_host)` | SQLite `pin` | no (public data), but integrity-MAC'd | never |
| KT signed tree heads, keyed by `(operator_host, kt_epoch)` | SQLite `kt_head` | no (public data), but integrity-MAC'd | never |
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

### 8.3a How the local store is encrypted

One key, per-row encryption, and an index that stays queryable.

```
local_store_key   32 B, CSPRNG at first run, sealed by the Sealer (§8.3) and, once a
                  PIN exists, wrapped under it as well (§8.6). Never derived from the
                  seedphrase: it protects a cache, not history, and a device that loses
                  it re-derives every row from the record store.

per row:  key ‖ nonce = HKDF-Expand(local_store_key, "entry/v1" ‖ LP(group_id)
                                    ‖ LP(message_id), 44)
          body_sealed  = XChaCha20-Poly1305(key, nonce, aad = the row's plaintext
                         index columns, plaintext = the decrypted body, sender display
                         name, caption and attachment filenames)
```

**What stays plaintext, and why that is the point.** `group_id`, `message_id`, `record_id`,
`sender_handle`, `sent_at`, `received_at`, `state`, `retention_class`, `eph_bucket` and
`expires_at`. Those are the columns every query in the product filters and orders on — the
conversation list, pagination, unread counts, the expiry sweep — and they are exactly what the
message server already holds for the same records. Sealing them would buy nothing against an
adversary who has the disk and the server's view, and would cost the reason for taking a database at
all.

**Search decrypts a bounded window.** `SearchEntries` walks candidate rows in `record_id` order,
decrypting at most 2,000 bodies at a time into memory that is zeroed after the pass, and stops at the
caller's limit. There is no plaintext full-text index on disk, and `EPH`-class rows are excluded from
the walk entirely (§7.4). This is slower than an FTS index over plaintext and is the deliberate
trade: a searchable plaintext index is a second copy of every message that survives the row it came
from.

**This replaces the sealed-blob-per-group cache.** A single blob per group would have required
unsealing, appending to and resealing an entire group's history to store one message, would have
supported no index, and would have made the SQLite dependency of decision A8 unjustifiable —
A8 exists for indexed pagination, per-group cursors and search, none of which a blob provides.

`TestNoPlaintextBodyAtRest` writes a known phrase through `PutEntries`, closes the client, and greps
the raw database file, the WAL and the journal for it. `TestIndexColumnsAreQueryable` asserts the
conversation-list and pagination queries execute without decrypting a single body.

**An expired ephemeral row keeps no sender.** On expiry the entry row's `sender_handle` column is
overwritten with sixteen zero bytes in the same statement that clears `body_sealed`, matching what
the message server does to its own copy of that column (Spec B §7.2). The row keeps `record_id`, its
timestamps and its class, so the placeholder still renders in order and the gapless id sequence is
intact. Keeping the row is justified by the gap-detection argument; keeping the sender in it is not,
and would leave a permanent, plaintext, per-sender, timestamped trail on the client as the residue of
the one feature whose entire purpose is to leave none.

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
decrypt it, and that the expired row's `sender_handle` is sixteen zero bytes in the raw database file
and in the WAL (§8.3a). That single test is the difference between the feature working and the
feature being a UI label.

### 8.6 The PIN, and what it actually protects

A PIN is **optional** and, when set, is a genuine second factor rather than a screen the UI puts in
front of data it has already unsealed.

- **No PIN.** `local_store_key`, the seed entropy and the device keys are sealed by the platform
  Sealer alone — DPAPI on Windows, user-scoped. Anyone who can run code as this Windows user can
  unseal them, which `Sealer.Description()` says in as many words.
- **PIN set.** The same material is additionally wrapped under a key derived from the PIN:
  `pin_key = Argon2id(pin, salt = 16 B random, time = 3, memory = 64 MiB, parallelism = 4, 32 B)`,
  and the sealed blob is `Seal(Wrap(pin_key, material))`. The platform seal still applies, so both
  are required. **Without the PIN the store key cannot be unwrapped**, by this process or any other.

```
Locked state:      local_store_key is not in memory. Groups(), History(), Search() and
                   every send path fail with CanSend reason "locked" and health state
                   "locked" with reason "pin_required". The connect session and the
                   outbox are NOT torn down: records still arrive and are stored as the
                   ciphertext the server sent, and are decrypted for display on unlock.
Auto-lock:         after AutoLockMinutes of no call from the host application.
                   DEFAULT 15. 0 disables it. Manual Lock() is always available.
Wrong PIN:         typed error, exponential delay after 5 consecutive failures
                   (1 s, 2 s, 4 s … capped at 60 s). There is no lockout that destroys
                   data: the PIN protects a cache and a seed the user may still hold on
                   paper, and a device-wiping counter would destroy more than it defends.
Forgetting it:     local history is lost and the store is re-created empty. The
                   seedphrase still restores from the server (§7.2 RestoreIdentity).
                   The client states this before the PIN is set, not after.
```

`TestPinIsNotAUiGate` asserts that with a PIN set and the client locked, the raw keyfile yields no
usable `local_store_key` under the platform Sealer alone — that is, that unsealing without the PIN
produces wrapped bytes and not a key.

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

/* account — this DLL owns signup as well as login (decision A12). */
uint64_t urmsg_auth_signup_begin(uint64_t client, const char* request_json,
                                 urmsg_auth_cb cb, void* user_data);
uint64_t urmsg_auth_verify_begin(uint64_t client, const char* request_json,
                                 urmsg_auth_cb cb, void* user_data);
uint64_t urmsg_auth_password_reset_begin(uint64_t client, const char* request_json,
                                         urmsg_auth_cb cb, void* user_data);

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
  "network_space_host": "string",   // e.g. "ur.network"; the operator this client's own
                                    // account is on, from the host application's per-user
                                    // configuration, with a build-time value used only
                                    // when nothing is configured. Never a compile-time
                                    // constant as its only source.
  "message_server_id":  "string",   // the one server's URnetwork client id (UUID string),
                                    // from the build-time constant kMessageServerClientId
                                    // or, when set, from the operator discovery response
  "enable_cover":       false,      // optional, default false  (MASTER §9.5)
  "media_cache_bytes":  1073741824  // optional, default 1 GiB
}
```

A user with no URnetwork account creates one **inside URmessage**: signup, email or SSO
verification, and password reset are all exported here, because this DLL already owns the account
session and there is no second runtime to hand the flow to. The client never sends the user to a
browser or to the VPN app to get an account.

**One trap, and it is the kind that ships.** The URnetwork account has a seedphrase of its own, and
so does the messaging identity. Both appear during onboarding, minutes apart, and they are
completely different secrets: one is a login credential the operator receives on every use, the
other is a master key that never leaves the device (MASTER §5.1). The two flows must never share a
screen, a string, or a phrase-entry control, and each must name which phrase it means in its own
title. Spec C §6.1 carries the user-facing form of this warning.

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
   `KeyChangeWarning.EvidenceClass`, `IntegrityEvent.Kind`, `MessageDirectoryResult.ProofState`,
   `DeviceLinkState.State`, `MessageServerInfo.KeyState`, `SyncState.ServerKeyState`,
   `MessageSecurityLogEntry.Kind`, `MessageJoinRequest.State`, `MessageBalance.State`,
   `BalanceRedeemResult.Reason` and `GroupResult.Reason` are **closed, versioned vocabularies**
   carried in JSON events with a stable
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
    MessageMessageServerRequest  = 1000;
    MessageMessageServerResponse = 1001;
    MessageMessageServerPush     = 1002;
    MessageMessageServerFragment = 1003;
```

**On the spelling, corrected 2026-08-25 during implementation.** Earlier revisions of this document
named these four values `MessageServerRequest`, `MessageServerResponse`, `MessageServerPush` and
`MessageServerFragment` — the same names as the four *messages* of Spec B §4.3 and §4.6, in the same
`package bringyour`. **That pair cannot be compiled.** proto3 scopes an enum *value* name to the
enum's **parent** scope, not to the enum, so `MessageServerRequest` as a value of `MessageType` claims
the qualified name `bringyour.MessageServerRequest` — which `message MessageServerRequest` already
holds. `protoc` refuses it outright:

```
<file>: "bringyour.MessageServerRequest" is already defined in file "<other>".
<file>: Note that enum values use C++ scoping rules, meaning that enum values are siblings
        of their type, not children of it. Therefore, "MessageServerRequest" must be unique
        within "bringyour", not just within "MessageType".
```

protoc's second line is the one that actually explains the rule, which is why it is quoted rather than
elided. The pair fails the same way whether the two declarations are in one file or two.

The collision is resolved on the **enum** side because the message names are the normative half: they
are the `oneof` arm types that Spec B §4.3.8's op byte — and therefore the `req_auth` MAC of §5.7 — is
defined over, and they appear across all three specs. The convention is the one `MessageType` already
uses for exactly this collision with `ip.proto`: repeat the domain prefix, as in
`IpIpPacketToProvider` for `message IpPacketToProvider` and `IpIpPing` for `message IpPing`.

**The four numbers are unchanged and are the wire code points.** Only the Go-visible spellings differ,
and a spelling copied from an older revision of this text is now a compile error rather than a silent
break.

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
| `TestReadAuthNeverUsesWriteKey` | §5.7 — `req_auth` is MAC'd under a `read_key`; no call path reaches `ComputeRequestAuth` with an epoch write key |
| `TestBlobIdIsInBothPreimages` | §5.1 — a record with `size_bucket = 5` whose `blob_id` is altered fails both AEAD open and `VerifyWriteAuth`; a record with any other bucket encodes a zero-length `blob_id` prefix |
| `TestNoPlaintextBodyAtRest` | §8.3a — per-row encryption; no body, name or filename in the raw database file |
| `TestPinIsNotAUiGate` | §8.6 — the PIN wraps the store key rather than gating a screen |
| `TestReadKeyWindowSurfacesExplicitly` | §5.7 — a client past the 90-day read window reports a named reason, never a generic failure |
| `TestReadAuthNamesItsEpoch` | §5.7 — `read_epoch` is inside `canonical_request_bytes` and therefore inside the MAC |
| `TestSuiteRegistryIsNotASingleton` | §3.1 — both registered ciphersuites pass the vector families and group creation still refuses 0x0001 |
| `TestSuccessionRequiresAllFive` | §3.4 — each of the five succession conditions, broken one at a time |
| `TestSuccessionOptOutIsAbsolute` | §3.4 — succession disabled defeats a valid quorum |
| `TestAdminCannotRemoveAdmin` | §7.3 — a non-owner commit removing an ADMIN is rejected on receipt, not merely refused at construction |
| `TestGroupAndDeviceCapsAreEnforcedOnReceipt` | §3.1 — a commit past 500 members or 11 device leaves is rejected by a receiving client |
| `TestDeleteWindowIsEnforcedOnReceipt` | §7.4 — a `TOMBSTONE` naming a record older than 24 hours is ignored, not applied |
| `TestDeliveryReceiptIsEphemeral` | §7.4 — a delivery receipt is `EPH(bucket 0)`, is never persisted, and is not emitted when either the user preference or the group policy forbids it |
| `TestOrderIsServerOrder` | §7.4 — a record with an implausible `sent_at` lands in `record_id` position |
| `TestForkResyncsBeforeStopping` | §7.6 — a recoverable divergence never disables sending; an unrecoverable one always does |
| `TestAutoDownloadHoldsUnknownSenders` | §7.4 — a first-time sender's attachment is held; a known contact's is fetched |

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
func RetentionClassWire(c RetentionClass, ephBucket uint8) (byte, error)  // refuses, see below
func ClassIsPrunable(c RetentionClass) bool

// ── server attachment ──────────────────────────────────────────────────────
func ParseServerAttachment(b []byte) (*ServerAttachment, error)
func EncodeServerAttachment(a *ServerAttachment) ([]byte, error)

// ── contact rendezvous (§5.14) ─────────────────────────────────────────────
func RendezvousId(token []byte) [32]byte
func DepositVerifyKey(token []byte) ([]byte, error)                            // Ed25519 public
func RendezvousRegisterPreimage(serverNonce []byte, r *RendezvousRegistration) []byte
func VerifyRendezvousRegister(r *RendezvousRegistration, serverNonce []byte, sig []byte) bool
func VerifyRendezvousOpen(depositVerifyPub []byte, serverNonce []byte,
                          rendezvousId []byte, sig []byte) bool
func VerifyRendezvousDeposit(depositVerifyPub []byte, serverNonce []byte,
                             rendezvousId []byte, depositCt []byte, sig []byte) bool
func VerifyRendezvousCollect(collectVerifyPub []byte, serverNonce []byte,
                             c *RendezvousCollectParams, sig []byte) bool
func VerifyRendezvousRetire(collectVerifyPub []byte, serverNonce []byte,
                            rendezvousId []byte, sig []byte) bool
func RendezvousDepositBytes() int                                              // 5238, exactly

// ── exported types ─────────────────────────────────────────────────────────
type Record, RecordHeader, RetentionClass, SizeBucket,
     ServerAttachment, EpochAttachment, RecoveryTag, WrapTag, EpochComplete,
     ServerAttachmentKind,
     RendezvousRegistration, RendezvousCollectParams

// and the discriminator's five values. Added 2026-08-26: without them a server held to
// this surface can tell an EpochAttachment from a RecoveryTag only by testing the four
// body pointers for nil, never by the discriminator §5.11 itself defines — and §5.1
// check 3 requires exactly that discrimination on every submit.
const AttachmentNone, AttachmentEpoch, AttachmentRecovery,
      AttachmentWrap, AttachmentComplete ServerAttachmentKind

// ── refusals ───────────────────────────────────────────────────────────────
// Sentinels, wrapped with %w at each site that has a value worth naming, so
// errors.Is holds for the server while the message still carries the byte or
// the length that was refused. Every one is fatal by construction: §5.9
// guardrail 7 says no path in connect/message reports one and carries on.
var ErrRetentionClassUnknown  error   // a wire byte, or a class tag, off the table
var ErrEphBucketOutOfRange    error   // an eph bucket past 5
var ErrEphBucketOnNonEphClass error   // a non-eph class carrying a bucket
var ErrRecordNil              error   // EncodeRecord(nil)
var ErrRecordFormatVersion    error   // a leading version byte this build does not read
var ErrIsCommitNotBoolean     error   // an is_commit byte that is neither 0 nor 1
var ErrSizeBucketOutOfRange   error   // a size bucket past the top of the ladder
var ErrBlobIdPresence         error   // blob_id presence disagrees with size_bucket
var ErrCtBodyLength           error   // ct_body neither absent nor its rung's length

// ParseServerAttachment's, added 2026-08-26 under A-9's rule: a sentinel a published
// function can return is owed a line in the same commit that makes it reachable, and
// §5.1 check 3 calls ParseServerAttachment on every submit.
var ErrServerAttachmentKindUnknown error // a kind byte §5.11 does not define
var ErrServerAttachmentBody        error // the kind and the body carried disagree, or
                                         // more than one body is carried
var ErrServerAttachmentNoneEncoded error // an encoded kind 0x0000 arrived; an absent
                                         // attachment is the EMPTY FIELD, never a kind
var ErrServerAttachmentFieldLength error // a field is not the exact width §5.11 gives it
var ErrServerAttachmentAlgId       error // an alg_id the kind does not name
var ErrExpectedWrapCountZero       error // an EpochAttachment expecting no wraps at all
```

The server gets verifiers and no signers, and no function that opens a deposit — a sealing or
opening function on this surface would be a decryption capability in the process that holds the
mailbox.

The server may use **only** this surface. It gets no decryption function, no key-schedule function, and no
MLS type. A test in the message-server repo asserts the allowlist. If Spec B ever needs more, that is a
design discussion, not a patch.

**Two amendments from the implementation (A-8, 2026-08-25).** Both are in the block above and both
are restated in Spec B §12.1, which is the same list.

`RetentionClassWire` returns `(byte, error)` and not `byte`. It is one of the two functions in the
system that cross between the retention class as Go carries it and the single byte the wire carries
it in (§5.1), and it has two things to refuse: a non-eph class that arrives carrying an eph bucket,
and an eph bucket past 5. A function that cannot refuse has to **normalise** instead — drop the
bucket, or truncate it — and both normalisations store a record as though the caller's belief about
it had been right. Dropping a bucket silently reclassifies the record; manufacturing `0x16` puts a
byte on the wire that every reader refuses, the sender's own other devices included. MASTER §8 gives
no Go signature, so it does not settle this; the arity is settled here. The error is returned
alongside a value that is **not** a legal wire byte, so a caller that ignores it writes a record the
split refuses rather than the `PERMANENT` record a returned `0x00` would have produced quietly.

The nine `Err*` sentinels are **on** this surface and always were in substance: §5.9 guardrail 7 requires
every failure in `connect/message` to be a typed error, and a typed error a caller cannot name is one the
caller can only match on message text. The server acts on several of them directly — a submit refused for
`ErrCtBodyLength` is a client that did not pad to its rung, and a fetch that will not re-encode for
`ErrBlobIdPresence` is a corrupted stored row — so they are published rather than left implicit. The
allowlist test in the message-server repo covers them: these nine, which are the names a function on
this surface can return.

**Amendment A-9, 2026-08-25 — what the refusals block is a list of.** A-8 published the nine and added
that "a tenth is a design discussion like any other addition here", which reads as a rule about the
count. It is not one, and taken as one it gets the next sentinel wrong in whichever direction the
reader leans: publish an unreachable name and the server's allowlist grows a name no server can use;
leave a reachable one unpublished and §5.9 guardrail 7 is back to being matched on message text. The
rule is reachability, and it follows from what this block has always been.

This block is the allowlist of what the message server may **reach**, and not an inventory of what
`connect/message` exports. It never could have been one: the package necessarily exports the sealing
side as well — `AADBody`, `AADHead` and `BodyBinding` build the two record AEAD preimages of MASTER
§8, and they appear on no line above because the server never decrypts and a preimage builder in the
process that holds the mailbox is half of a capability it must not have. `AADBody`'s signature is
itself guardrail G4 of §5.9. So the test in the message-server repo asserts the names in this block,
which is what the server may use, and says nothing about what the package declares.

The refusals follow the same rule. A sentinel a function **on this surface** can return is part of the
surface and is owed a line here in the same commit that makes it reachable, because a typed error the
server cannot name is one it can only match on message text. A sentinel only an unpublished function
can return is not, and adding it would widen the server's allowlist with a name no server can reach.
`ErrRecordHeaderNil` and `ErrServerAttachmentMismatch` are the first two of that kind: both are
`AADHead`'s refusals, `AADHead` is on no line above, and neither is therefore on this surface. If
either ever becomes reachable from a published function it stops being of that kind, and the
amendment that publishes it lands with the change that made it reachable.

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
| S8 | Advertise, as data the client can read before it acts: **the file size limit** (max blob bytes), **the media and file window** (media TTL cap and default), **the text storage cap and minimum** (durable TTL maximum, default and minimum) and whether groups may override the text default; plus max records per fetch and submit, max submit bytes, max request bytes, max response bytes, blob chunk bytes, blob pad multiple, attestation support, and a monotonic `capability_version` | MASTER §12.2 |
| S9 | Supply a 32-byte `server_nonce` in `HelloResponse`, bound to the connection and valid for its life. **No rotation.** The nonce is not carried in requests. | MASTER §9.2 |
| S10 | Prune by retention class **and** `expire_at`, where `expire_at` may only shorten retention, never extend it; retain `ct_head` and `body_hash` when `ct_body` is erased | MASTER §8, §9.1, §12.2 |
| S11 | Record nothing per identity: no `group_id`, `sender_handle`, `record_id`, `client_id`, address or authenticator in any log, metric label, trace or database log. Aggregate counters and error classes only. The single exception is a **client-initiated diagnostic session**, bounded and opt-in, retained separately and surfaced back to the user who started it | MASTER §9.7 — an acceptance criterion, not a policy page |
| S12 | Never decrypt; never be consulted on group admission; never satisfy an MLS validity condition | MASTER I1, §4.2 |
| S13 | **Authorize reads.** `Fetch`, `Subscribe`, `GroupStatus`, `BlobGrant` and `WrapFetch` MUST carry and verify `req_auth` under the read key of the epoch named by the request's `read_epoch` field (§5.7). Install each epoch's `read_key` from that epoch's `EpochAttachment`, retain it **90 days from installation**, and refuse a request naming an epoch whose key has aged out. An unauthenticated read is a full metadata dump and a group-existence oracle. `RecoveryFetch` uses the Ed25519 recovery proof instead. | MASTER §9.1, §9.2 |
| S14 | Serve a wrap by target in O(1) from an authenticated `WrapFetch`, and return a defined refusal when the named target has no wrap at that epoch | §5.11, MASTER §8.2 |
| S15 | Present a signing key chained to the hardcoded fleet root, and chain every rotation by the outgoing key. A key that does not chain MUST be refused by the client, so the server must never present one | MASTER §9.4, §12.1 A-13 |
| S16 | Keep the row of an expired ephemeral record so `record_id` stays gapless, and **zero its `sender_handle`** when the body is erased | MASTER §12.2, Spec B §7.2 |
| S17 | Advertise the operator this server holds its account on, its hosting jurisdiction, and the length of its read-key retention window, as fields a client can read before it acts | MASTER §4.1, §9.2, Spec B §7.3, §10.4 |
| S18 | **Carry the contact rendezvous.** Register, open, deposit, collect and retire a group-less mailbox keyed on `rendezvous_id`, verifying one Ed25519 signature per operation over a preimage covering every value acted on: `register_auth` against the key the registration carries and pins, `open_auth` and `deposit_auth` against the pinned `deposit_verify_pub`, `collect_auth` and `retire_auth` against the pinned `collect_verify_pub`. Assert `deposit_ct` is exactly `rendezvous_deposit_bytes`. Bound each rendezvous to `rendezvous_mailbox_depth` uncollected deposits and each deposit to `rendezvous_deposit_ttl_seconds`. Return the same `REASON_CARD_RETIRED` for a retired and for an unknown id. Store no depositor identifier on the deposit row. | MASTER §9.8, §9.5; §5.14 |

**What we give the server.**

The server holds `write_key[n]` itself. It is delivered to the server by the committer inside the commit
record's `server_attachment` (`EpochAttachment.write_key`), over the connect session's own hybrid-PQ
encryption, and is stored wrapped under a vault KEK. Three consequences, all accepted:

1. A server holding `write_key` **can forge `write_auth`**. This changes nothing: the server is the party
   enforcing `write_auth`, so it could equally accept an unauthenticated record, and any record it injects
   fails MLS verification at every client (**I5**).
2. `write_key` is a label-separated HKDF child of `storage_root[n]`, so holding it yields neither
   `storage_root[n]` nor the sibling class keys `K_perm` / `K_durable` / `K_media` / `eph_root`. It MUST
   NOT be reused for any second purpose beyond `write_auth`.
3. The server retains the **current** epoch's key plus **one** briefly-retired predecessor (60 s), and
   nothing older.

**And the read key, which is not part of that block.** `read_key[n]` is a separate label-separated
child of **each epoch's** `storage_root[n]`, delivered in that epoch's attachment, stored the same
way, and retained for the window the server advertises as `read_key_window_seconds` — ninety days on
a stock server — rather than for sixty seconds. That window is what makes an offline member's
catch-up possible and what makes a removed member's metadata access expire; see §5.7. It is written
outside the quoted block deliberately: the three consequences above are reproduced byte-identically
in MASTER §9.2 and Spec B §5.3, and a fourth item here would make that claim false.

An asymmetric per-epoch write proof (Ed25519 derived from `storage_root`, server holds only the public
half) removes the forgery capability at the cost of one signature per record. It is the right long-term
shape and is a **V2** item, not v1 text.

**Interfaces out → to Spec B.** The rows A-1…A-18 below are what Spec B's own interfaces-in table
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
| A-8 | The shared interop vector file `testdata/message-server-vectors.json` — records with epoch keys, nonces, expected verdicts, a commit-race scenario, a non-zero `expire_at` record, a `size_bucket = 5` record with a `blob_id`, one authenticated request per `req_auth` op byte (13, 14, 16, 17, 19) including a `WrapFetch`, each naming its `read_epoch`, plus one request naming an epoch whose read key has aged out, a per-class stream-index collision case, and a `since_record_id = 0` fetch case; plus one rendezvous registration, one open, one deposit at the exact length, one collect with an acknowledgement and one retirement, each with its expected verdict, plus a deposit one byte short and a collect signed under the deposit key. **A blocking CI job in both repos.** | §11.1, §11.4 | A6 |
| A-9 | A measurement of the platform transport's production `FramerSettings.MaxMessageLen` | §10.2 | A7, named owner required |
| A-10 | `ComputeRequestAuth` / `VerifyRequestAuth` and `RecoveryProof` / `VerifyRecoveryProof` | §5.7 | A6 |
| A-11 | `expire_at` as unix milliseconds, u64, big-endian, 0 = unset, on the wire and in both preimages; `connect/message` is the only producer of the preimage on both sides | §5.1, §5.7 | A6 |
| A-12 | `read_key[n]` and its delivery: `EpochAttachment.read_key`, one per epoch, and `ComputeRequestAuth` / `VerifyRequestAuth` taking a read key rather than an epoch write key | §5.7, §5.11 | A6 |
| A-13 | The fleet-root verification preimage `"URmessage/v1/serverkeyroot" ‖ LP(server_id) ‖ LP(key_pub) ‖ u64(not_before_ms) ‖ u64(not_after_ms)`, and the rule that a non-chaining key is refused with no accept path | §7.6 | A7 |
| A-14 | `read_epoch` as a field of every authorized read request, inside `canonical_request_bytes`; `ReadKey` taking an epoch's `storage_root` | §5.7 | A6 |
| A-15 | The delivery-receipt record: `EPH(bucket 0)`, never persisted, fanned out on the transient channel exactly as read receipts are | §7.4 | A6 |
| A-16 | The reaction body encoding: `LP(emoji_utf8)`, one extended grapheme cluster, validated against a pinned Unicode version on both sides | §5.1, §7.4a | A6 |
| A-17 | The two-sentinel `durable_ttl_seconds` encoding, and the rule that the server applies its own advertised default on the unset sentinel | §5.11 | A6 |
| A-18 | The contact-card encoding, the rendezvous derivations, the sealed deposit at its exact length, and the five rendezvous signature preimages with their verifiers | §5.14 | A6 |

### 12.2 To the Windows messaging client (Spec C)

**What Spec C gets:** `URmessageSdk.dll`, `urmessage_sdk.h`, `urmessage_sdk.hpp` (C++/WinRT-friendly
wrapper over the C ABI, using `nlohmann/json` exactly as the VPN client's wrapper does), and
`urmessage_sdk.def`.

**What Spec C must supply.**

| # | Obligation |
|---|---|
| C1 | A writable per-user directory as `MessageClientSettings.StorageDir`. Not `%PROGRAMDATA%` — DPAPI is user-scoped and a shared directory defeats it. |
| C2 | Supply `settings_json` per the §9.3 schema: `storage_dir`, `network_space_host`, `message_server_id`. `network_space_host` comes from per-user configuration with a build-time default, never from a compiled-in constant as its only source (§7.2, decision A13). **No ByJwt at construction** and **no handle from another DLL** — this DLL owns login (A12). |
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
| C16 | Render the PIN as what it is: an optional second factor whose loss costs local history and whose absence is not a security failure. Never claim it protects anything when it is unset (§8.6) |
| C17 | Never present an accept affordance for a message-server key that does not chain to the fleet root. There is no call for it and there must be no button (§7.6) |
| C18 | Render the three server-advertised limits — file size, media window, text storage cap — from `ServerInfo()`, never as literals |
| C19 | Render the security log verbatim from `SecurityLog()`, oldest to newest, with no editorial summary layer |
| C20 | Start and stop diagnostic sessions only on explicit user action, and show when one is running and when it ends |

**What Spec C must not assume.** That `URnetworkSdk.dll` is present at all. Per decision A12 it is
never loaded into the messaging process: `URmessage.exe` loads `URmessageSdk.dll` only, and the
URnetwork account surface the client needs is exported from that DLL under the `urmsg_auth_*` prefix.

### 12.3 To the operator (`/server`, MASTER slice 9)

Out of scope for all three specs, listed so it is not lost: **each operator's own** discovery
directory mapping `principal → identity master key`, published to **that operator's own** append-only
key-transparency log over a Merkle prefix tree, serving inclusion proofs and signed tree heads
(MASTER §10.1). There is more than one operator and there is therefore more than one log. A client
verifies against the log of the operator it resolved a principal from and never treats one operator's
signed tree head as evidence about another's, which is why every artefact in §7.6 carries the
operator it came from.

`sdk/message_kt.go` is written against this. Until it exists it runs against a local test log, every
lookup returns `"log_unavailable"` and proceeds (§7.6b), and `MessagePin.EvidenceClass` reports
`"kt_unavailable"`, which the UI must show as its own row (Spec C §7.3).

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
| A6 | `connect/message` | records, key schedule, X-Wing, ratchet, wraps, `write_auth`, `req_auth` with `read_epoch`, recovery proof, `server_attachment`, tombstones, padding, COVER, **and the delivery-receipt record**, **the reaction body as a length-prefixed UTF-8 string**, **the two-sentinel `durable_ttl_seconds` encoding**, and **the contact-card encoding and the rendezvous preimages of §5.14** — all use existing classes and existing transport paths, so none is a format break, but all must land before the format freezes here rather than with the client work that renders them | wire format frozen; X-Wing draft KAT vectors pass both directions; the recovery wrap carries `storage_root ‖ archive_secret`; the shared interop vector file is committed and green in **both** repos; the rendezvous interop vectors are green in both repos; `TestStreamIndexNeverReused` and `TestEphRootHasNoDurableInput` green |
| A7 | `sdk` client core | `MessageClient`, store, sealer, KT client, sync loop, transport binding, `connect/protocol/message.proto` | two clients exchange a message against Spec B's server in `e2e` |
| A8 | `sdk/cgo-message` | generator, exports, header, `.hpp`, smoke tests, build matrix, the `urmsg_auth_*` account surface | Spec C can build against the header; handle count zero at exit; §7 defines the fields of every type reachable from `MessageClient`; the `urmsg_auth_*` surface builds and the smoke test logs in |
| A9 | Disappearing messages and multi-device | `eph.go`, provisioning with the short code and numeric comparison, device management, revocation, the PIN and auto-lock (§8.6) | `TestExpiredMessageIsUnrecoverable` green; a second machine pairs and sends; **this is the slice the public beta ships from** |
| A10 | Attachments | Blob handling, `MEDIA` class, thumbnails, resumable upload, auto-download policy | an image sends, resumes across a disconnect, and is held for an unknown sender |
| A11 | Fuzz hardening + audit prep | differential oracle, 14 clean nightlies, audit brief | **Gate 4 green**; the audit brief and the ValSem coverage report are complete, so that an audit commissioned by the decision taken at MASTER §14 slice 5 (§4.6, MASTER §15 item 7) can be scoped against working code |
| A12 | Push channel | `RegisterPushChannel` / `UnregisterPushChannel` in §7.2, server-side channel registry (Spec B), WNS renderer (Spec C §10.2) | a raw WNS wake delivers a toast for a record received while the app was closed |

A1–A5 are the schedule risk, and they are first because each has an objective completion test.
**A1–A8 produce an internal-only build** — two people can text on it, and it is text-only,
single-device and unnotified, which is a demo rather than a beta. **A9 is what ships publicly**,
because multi-device is the thing this product has that the obvious alternative does not, and
attachments in A10 are table stakes nobody switches for.

Invite links and join requests (§7.3a), **contact cards and their rotation (§7.3b)**, ownership
transfer and succession (§7.3), and balance-code redemption (§7.9) land in **A7** with the rest of
the client core: each is an `sdk`-level flow over mechanisms A6 already froze, and all four are
needed for the first group a stranger joins. A7 is done for the card when a card minted on one
client opens a two-member group on another with `EvidenceClass == "out_of_band"`, and a rotated
card's old link is refused with `card_retired` while the conversation it already opened is
untouched.

---

## 14. Open items (consolidated)

Item numbers are stable. Items 4, 8 and 10 are closed and their closing rulings are retained in the
table below. Items 1, 2, 3, 5 and 12 were closed in revision A-2 and their text is in the edit log
rather than here, which is why they do not appear as rows.

| # | Item | Owner | Blocks |
|---|---|---|---|
| 4 | **RULED — `modernc.org/sqlite` accepted (§0.2 A8, §0.5). Closed.** | — | — |
| 6 | A-ASSUME-4 — `PrivateMessage`-only handshake policy | project owner | slice A4 |
| 7 | Skipped-key window size and per-group memory budget (§5.5) | Spec C | slice A6 |
| 8 | **RULED — warn and proceed both directions (MASTER §15 item 1). Closed.** | — | — |
| 9 | Push transport / WNS wake-up (MASTER open item 2). A exposes `RegisterPushChannel(uri string) error` and `UnregisterPushChannel() error` in §7.2 as no-op stubs, so wiring WNS later is not an ABI break; owned jointly with Spec C's C-6 and scheduled as slice A12 (§13). The Azure AD application registration WNS needs still has no named owner. | Spec A + Spec B + Spec C | post-A8 |
| 10 | **RULED — the successor nomination is a group-context extension (`0xF003`), accepted and validated in v1 (§3.4). Closed.** | — | — |
| 11 | Transcribe RFC 9420 errata 8745 and 8815 verbatim into `connect/mls/ERRATA.md` (§4.3) | implementer | slice A4 |
| 13 | External cryptographic audit — the **decision** is scheduled for slice 5 (§4.6, MASTER §15 item 7), not deferred indefinitely. Owner action, not engineering work. | project owner | GA, if commissioned |
