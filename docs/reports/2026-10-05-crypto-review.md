# Two AI reviews of URmessage's cryptography, checked against the code and against their sources

**2026-10-05.** This report is the evidence behind ledger item 280. Two external AI models reviewed
URmessage's encryption and methodology from a short summary of the stack, not from the specs. The
owner pasted both reviews and asked whether to improve the protocol on their strength or to accept
the downsides. This report checks:
- each claim the reviews make about our design, against the code;
- each claim they make about the world, against its primary source.

It ends with the verdict the owner adopted.

**Pinned at:**
- connect `8cc3b556` (`beta/message`). Its `mls`, `messagegroup`, `message` and `protocol` trees are
  unchanged at `e449f7d8`.
- sdk `c71bb73b` (`beta/message`). Its `urmessage` tree is unchanged at `d20d82c1`.
- message-server `81cf1f4` (`main`), and message-windows `0b08178`.

Paths are given as `repository:file:line`. MASTER is
`docs/specs/2026-08-12-urmessage-protocol-design.md` in this repository, and Spec A, B and C are the
`spec-a`, `spec-b` and `spec-c` files beside it.

**How each claim was established:**
- **measured:** reproduced by running something, with the query given;
- **read:** read in source at a named line;
- **inferred:** follows from what was read, and was not run.

---

## Summary

- **The reviews were right that our post-quantum protection does not heal, and that several
  protections exist only on paper.**
- **One review was wrong about where the post-quantum layer sits.** It placed it at bootstrap and
  transport only. In fact every MLS commit draws a fresh secret, seals it with X-Wing to each member
  device, and keys the stored messages from it. The weak points are elsewhere:
  - the epoch a join opens, whose secret is pasted in the clear;
  - the device X-Wing key, which never changes;
  - verification: no key can be checked today.
- **The fix they recommended is a moving target.** It is X-Wing inside MLS's own key exchange, as
  a ciphersuite.
  - The draft one review cites is dead, and the codepoint it names is one implementation's own.
  - The successor draft is in last call without codepoints.
  - The KEM codepoint it would use, 0x647a, carries two incompatible key derivations today, and two
    versions of OpenMLS already disagree on it. Neither review saw this. We reproduced the split;
    which side each OpenMLS takes was read from source (section 4).
- **The verdict:**
  - **adopt five changes:** seal the join secret, safety numbers and TOFU, healing, the missing
    state-machine tests, and the quick fixes;
  - **defer** a post-quantum MLS ciphersuite until it is an RFC;
  - **accept** no deniability and classical authentication.

  The external audit comes after the alpha.

---

## 1. What the two reviews said

Neither saw the specs. Each worked from a short description of the stack. From what both repeat
back, it named MLS (RFC 9420) on suites 0x0003 and 0x0001, X-Wing wrapping device keys, TLS 1.3 with
X25519MLKEM768, and an in-house Go implementation checked against test vectors and OpenMLS.

**Review A** placed us ahead of the Signal family on the group protocol and one step behind Signal
and iMessage on post-quantum ratcheting.
- It read our PQ layer as covering bootstrap and transport, with MLS epochs healing classically.
- It recommended an X-Wing MLS ciphersuite, citing draft-mahy-mls-xwing and OpenMLS's suite 0x004D.
- It recommended differential state-machine fuzzing against OpenMLS, since vectors check the
  cryptography and not the state machine.
- It recommended byte-exact codec discipline at the protobuf boundary.
- It recommended an external audit, and pinning the X-Wing draft in the docs.
- It said the X-Wing HPKE id was still IANA-pending.
- It said gorilla/websocket has a rocky maintenance history.
- It said the server can swap key packages without key transparency.
- It said MLS gives no deniability.

**Review B** called the design standards-first, and set out three levels of post-quantum maturity:
- a PQ handshake;
- a PQ ratchet;
- hybrid wrapping of static device keys.

It asked whether our X-Wing encapsulation is re-run per epoch or applied once to static keys. It
recommended publishing the PQ story honestly either way, and pointing at formal analysis: a Tamarin
or ProVerif model.

Each review compared us with other messengers. Those claims are checked in section 4.

---

## 2. What we build

Read at the pins above, unless marked.

| Layer | As built | Where |
|---|---|---|
| MLS suite | One suite, 0x0003: X25519, ChaCha20-Poly1305, SHA-256, Ed25519. 0x0001 is implemented and refused at group creation. | `sdk:urmessage/device.go:41`; `connect:mls/group.go:396-401` |
| MLS's HPKE: Welcome, update path, init keys | X25519 only | `connect:mls/hpke.go:214`, `:271` |
| Authentication | Ed25519 signatures on handshake and application messages | `connect:mls/framing_protect.go:78` |
| The PQ storage layer | Each commit draws a fresh `pq_secret` and seals it with X-Wing to each remaining device's static X-Wing key, as a permanent record. `storage_root` = HKDF-Extract(salt = the MLS exporter, ikm = `pq_secret`), and every record key derives from it. | `sdk:urmessage/group.go:2037-2079`; `sdk:urmessage/pqepoch.go:1556`; `connect:messagegroup/keyschedule.go:104`, `:131` |
| The join | The invite carries the joiner's `pq_secret` in the clear, beside an X25519 Welcome. | `sdk:urmessage/invite.go:45-51`, `:88`; `sdk:urmessage/pqepoch.go:1383` |
| The device's X-Wing key | Minted once and published in leaf extension 0xF002. An MLS update re-encodes the same key. | `sdk:urmessage/device.go:513-555`; `connect:mls/group.go:1800-1803`; `connect:mls/extension.go:87` |
| Self-update | Nothing sends one. | ledger item 266 |
| Keys at rest | On disk in the clear, protected by file permissions alone. On Windows, where the alpha runs, that is only the ACL of the directory the caller chose. | `sdk:urmessage/statestore_durable.go:29-50`; ledger item 229 |
| The transport to the message server | On the direct and URnetwork routes: TLS 1.3 only, with X25519MLKEM768 only. The client pins the server's key, so authentication is classical. The platform route stays on for older builds. | `message-server:endpoint/endpoint.go:184-194`; `sdk:message_route.go:332-349`; ledger item 268 |
| Key transparency, TOFU, safety numbers | Specified in full, and none built. The sdk has no safety-number API. | `message-server:kt/doc.go:5` ("This package holds no code yet"); MASTER §10; Spec A §7.6 |
| Vector families | 16 pinned. 7 have no runner in connect's registry: 2, 8, 9, 13, 14, 15 and 16, among them tree operations, the Welcome and the three passive-client families. 16's runner exists in `mls/syntax` and is not installed, 2's constructions are checked in `crypto_labels_test.go`, and the label, key-schedule, Welcome and framing tests read parts of 8 and 14. | `connect:mls/vectors_test.go:110`; `connect:mls/syntax/vectors_test.go:22`; `connect:mls/crypto_labels_test.go:1382` |
| ValSem negative tests | 29 `TestValSem` tests. No test names ValSem240 to 246, six codes, since there is no 243. Each needs a new_member_commit sender, which connect refuses earlier, with `errProcessSenderType`, and tests. Spec A expects `ErrProfileExternalCommit` for them. | measured, by query (below); `connect:mls/commit_process_test.go:871-877`; Spec A :884-889 |
| OpenMLS oracle and interop peers | Specified. Their image digests are placeholders, and nothing has run. | `connect:mls/interop/PINS.md:21-23` |
| `req_auth` | An HMAC over a label, the connection nonce, the op and a deterministic protobuf marshal of the request. connect pins the framing and the tag over raw octets. Nothing pins the marshal's bytes. | `sdk:urmessage/record.go:246`, `:269`; `message-server:api/fetch.go:250`; `connect:message/writeauth_test.go:457`, `:509` |
| The X-Wing pin | The code pins draft-10's vectors, byte-identical since -05, with the label last in the combiner. Spec A says -06, with the label first. MASTER names no version. | `connect:messagegroup/xwing.go:92`; `connect:mls/interop/PINS.md:83`; Spec A :72, :1687; MASTER :884 |
| Dependency monitoring | None: no Dependabot or Renovate configuration that applies, and no govulncheck. connect's `sctp/renovate.json` is a vendored copy of pion's, which Renovate does not read from a subdirectory. | measured, by query (below) |

**The queries behind the absences:**
- **ValSem240 to 246.** `git grep -E 'ValSem24[0-6]' 8cc3b556` in connect returns nothing.
  - The control, in the same tree: `func TestValSem` finds 29 tests, and `ValSem2[0-9]{2}` finds
    ValSem200 to 209.
  - The query finds names, not behaviour. No test names ValSem400 either, yet
    `TestPastEpochWindowDropsOlderState` tests its bound.
- **Dependency monitoring.** In each repository's `.github`, no file names dependabot or renovate,
  and no workflow names govulncheck.
  - The control: the same search finds `actions/setup-go` in 3, 2 and 1 workflow files of connect,
    sdk and message-server.
  - Repository-wide, the only such files are in connect's vendored `sctp/`: `sctp/renovate.json`
    and `sctp/.github/workflows/renovate-go-sum-fix.yaml`, pion's. Neither Renovate nor GitHub
    Actions reads them from a subdirectory. No file anywhere names govulncheck.
- **A KAT for `req_auth`'s marshal.** Seven test files in each Go repository name the MAC, its
  field or the deterministic marshal. In them, the probe looks for any quoted hex string of 16 or
  more digits, any `[]byte{0x…}` literal and any `hex.` call.
  - `connect:message/writeauth_test.go` pins the framing and the tag, over raw request octets.
  - Every other hit, in all three repositories, is a fill pattern. None pins a request's marshal.
  - The control: the same probe finds 35 hex strings in that connect file.

---

## 3. The reviews' claims about our design, checked

| What a review said or asked | What is true here |
|---|---|
| PQ covers bootstrap and transport only, and epochs heal classically (A). Is X-Wing re-run per epoch, or applied once to static keys (B)? | Per commit, but to static keys. Each commit draws a fresh secret and seals it with X-Wing to each device's static key, as a permanent record. So a passive recorder with a future quantum computer is defeated for every epoch a commit opens, but not for the epoch a join opens, and nothing heals after a compromise, PQ or classical. |
| Close the gap with an X-Wing MLS ciphersuite (A); ride X-Wing in the update path (B) | Deferred, under locked decision C6. The suite A names is dead or non-standard (section 4). After the join seal and healing below, what such a suite adds is narrow: post-quantum protection inside MLS itself. S3's red team states what healing against a quantum adversary means while MLS stays classical. |
| The server can swap key packages without key transparency (A) | Partly. The server and the operator never carry key packages: join codes and invites are pasted between people. Whoever controls that paste channel can swap them, and no safety number, TOFU check or transparency log exists to catch it. All three are specified. |
| The vectors validate the cryptography, not the state machine. Differential state-machine fuzzing against OpenMLS is the most valuable addition (A). | Right. Seven of sixteen vector families have no runner in connect's registry, including the three passive-client families, though two of the seven are partly checked elsewhere (section 2). No test names ValSem240 to 246. The OpenMLS oracle and the interop peers are specified and have never run. |
| Keep the codec byte-exact at the protobuf boundary (A) | Mostly so already: MLS bytes never travel as protobuf fields, and the record crosses as opaque `record_bytes`. The exception is `req_auth`, whose MAC covers a deterministic protobuf marshal that no test pins to known bytes. Protobuf does not promise that output across languages. |
| Pin the X-Wing draft version, and say so (A) | The code is pinned (draft-10's vectors). Our specs disagree with it, and with each other. |
| MLS gives no deniability; be deliberate about it (A) | Deliberate. It is a permanent non-goal (MASTER :554-555), and the owner's recorded ruling (ledger item 232). |
| An external audit before shipping (A) | Ruled on 2026-10-05: the audit comes after the alpha. |
| Point at formal analysis (B) | None exists, and none is in the adopted program. |
| gorilla/websocket has a rocky history; pin it (A) | It is pinned at v1.5.3. It parses unauthenticated input on the message server's public :443, and nothing watches its advisories. S0.3 will add govulncheck and Dependabot. |
| Publish the PQ story, and label it honestly (B) | Adopted. MASTER §13 says "Post-quantum protection for stored messages" with neither the join epoch nor the static key as a caveat, and S0.3 will correct it. |

---

## 4. The reviews' claims about the world, checked

The fact-check checked each row against its primary source: the IANA registries, the IETF drafts on
the datatracker, OpenMLS's repository and changelog, and the vendors' own posts. The dates are as of
2026-10-04. For this report, the rows that bear on our own choices were checked again: the IANA
entry, draft-ietf-mls-pq-ciphersuites-06's suite table, OpenMLS's measurements, and the derivation
split below.

| Claim | Verdict | What the sources say |
|---|---|---|
| X-Wing is draft-11, not an RFC | true | draft-connolly-cfrg-xwing-kem-11 (2026-09-23) is on the Independent Submission stream, not in the RFC Editor's queue. Its IETF-track twin is MLKEM768-X25519, in draft-irtf-cfrg-concrete-hybrid-kems-04 and draft-ietf-hpke-pq-05. |
| X-Wing's test vectors changed between drafts | true, and settled | They changed at -01, -03 and -05, and are byte-identical from -05 (2024-10-20) to -11. |
| X-Wing's HPKE KEM id is IANA-pending | false | IANA's HPKE registry lists 0x647A, X-Wing, citing draft -06. It was added late in 2024. |
| draft-mahy-mls-xwing is the escape hatch | outdated | It stopped at -00 (2024-03-04) and expired on 2024-09-05. Its line continued as draft-ietf-mls-pq-ciphersuites. |
| That draft registers 0x004D | false | IANA's MLS registry holds only RFC 9420's 0x0001 to 0x0007. draft-ietf-mls-pq-ciphersuites-06, in working-group last call, lists TBD1 to TBD11, and its list was reshuffled at -01, -02 and -05. None is an X-Wing suite with ChaCha20-Poly1305, SHA-256 and Ed25519, so there is no standard twin of our 0x0003. Its security section claims post-quantum confidentiality only. |
| OpenMLS has an experimental X-Wing suite, 0x004D | true, with caveats | Added in OpenMLS 0.6.0, as MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519. Since 0.9.0 it sits behind a draft feature with provisional values, and it has never been stable. OpenMLS's own post: "There is no IANA code-point for this ciphersuite yet, such that interoperability may not be guaranteed." |
| XMTP wraps key packages with X-Wing | false as stated | XMTP wraps Welcomes with X-Wing HPKE, to a PQ key its KeyPackage carries, and its group suite stays 0x0003 (XMTP, 2025-07-10). The OpenMLS post the review cites does not mention XMTP. |
| OpenMLS sits on formally verified libcrux | partly | libcrux's ML-KEM is verified. Its X-Wing combiner crate is described as pre-verification, and hpke-rs is not verified. |
| PQXDH upgrades only the handshake, with no PQ forward secrecy (B) | true, except the last part | PQXDH gives the handshake PQ forward secrecy. What it does not give is PQ post-compromise security. |
| Signal's SPQR, a PQ ratchet rolling out since October 2025 | true, and 1:1 only | Announced 2025-10-02. libsignal's sender-key code has no SPQR and no KEM, so Signal's groups have no PQ ratchet. |
| iMessage PQ3 rekeys periodically | true | Kyber-1024 with P-256, and a PQ rekey about every 50 messages, at least weekly. A Tamarin analysis was published (USENIX Security 2025). |
| RCS chose MLS partly for PQ | partly | GSMA RCC.16 v3.0 §1.1 says MLS "supports post-quantum encryption". No PQ suite is mandated, and whether RCS's MLS uses one could not be verified. |
| Apple's E2EE RCS beta, May 2026 | true | Apple Newsroom, 2026-05-11 (iOS 26.5). It mentions neither MLS nor PQ. |
| Matrix is mid-migration to MLS | true; the source cited is stale | MSC4244 and MSC4256 are open. arewemlsyet.com was last updated 2025-06-20. |
| Wire's MLS reached general availability in April 2025 | true | 2025-04-24. |
| WhatsApp has no PQ for chats, and PQ only for backups | none found; unverifiable | No primary source supports either PQ claim. The Meta address cited returns 404. Meta's hybrid ML-KEM document is for Messenger's Labyrinth storage. |
| WhatsApp's AKD, and IETF key transparency | true | AKD dates from 2023-04-13. keytrans-architecture-09 is at the IESG, and RFC 9750 recommends key transparency for the authentication service. |
| gorilla/websocket was archived, then revived | true | Archived 2022-12-09, revived 2023-07-15. The last release is v1.5.3 (2024-06-14), and the last commit is 2025-03-19. |
| MLS has no cryptographic deniability | mostly true | RFC 9750 §8.2.3. No deniable MLS construction was found, and Signal's groups sign too. |
| An X-Wing MLS suite gives PQ post-compromise security per epoch | true by design, unproven | Each Welcome and update path becomes PQ-confidential, against a passive quantum attacker only. Authentication stays classical, and healing still needs commits with a path. In OpenMLS's measurements it costs about eight times the bytes and twice the compute: a KeyPackage of 2,669 bytes against 299, a Welcome of 5,457 against 716, and a self-update of 3,954 against 495. |

### The split neither review saw: one codepoint, two key derivations

**The two definitions** (read):
- X-Wing draft-11 §5.6 defines `DeriveKeyPair(ikm)` as `GenerateKeyPairDerand(SHAKE256(ikm, 32))`.
- draft-ietf-hpke-pq-05 uses `SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)`, which is
  SHAKE256 over `ikm || "HPKE-v1" || "KEM" || I2OSP(0x647a, 2) || I2OSP(13, 2) || "DeriveKeyPair" ||
  I2OSP(32, 2)`. It asks IANA to "replace the entry for the value 0x647a".

Both name the same codepoint, and they derive different keys from the same input key material. Any
protocol that derives keys this way, as MLS does for every tree node, gets different keys depending
on which definition an implementation follows.

**How it was reproduced** (measured). A 110-line Python script recomputes only the X25519 half of
each public key, because no ML-KEM arithmetic is needed to tell the two derivations apart.
- From a candidate seed it takes SHAKE256(seed, 96), bytes 64 to 96, as the X25519 scalar.
- It multiplies the base point by that scalar, and compares the result with the last 32 bytes of the
  published 1,216-byte public key.
- **The control** is X-Wing draft-11's own Appendix C vectors, seed to public key, run through the
  same code. All three match, so the harness reads and computes correctly.
- **The test** runs both candidate seeds, A = SHAKE256(ikm, 32) and B = LabeledDerive, over the
  `ikmR` of draft-ietf-hpke-pq-05's two MLKEM768-X25519 vectors.

Its output:

```
CONTROL X-Wing -11 Appendix C: 3 vectors match, 0 mismatch
A.5.  MLKEM768-X25519, HKDF-SHA256, ChaCha20Poly1305: len(ikmR)=32 len(pkRm)=1216
   A  plain SHAKE256(ikm,32)  [X-Wing -11 s5.6] matches pkRm: False
   B  LabeledDerive            [hpke-pq-05 s4]   matches pkRm: True
A.12.  MLKEM768-X25519, SHAKE256, ChaCha20Poly1305: len(ikmR)=32 len(pkRm)=1216
   A  plain SHAKE256(ikm,32)  [X-Wing -11 s5.6] matches pkRm: False
   B  LabeledDerive            [hpke-pq-05 s4]   matches pkRm: True
```

So draft-ietf-hpke-pq-05's own vectors follow LabeledDerive, while the IANA entry still cites the
X-Wing draft, whose rule is the unlabeled one.

**Which side implementations take** (read):
- **OpenMLS 0.9.0** (2026-08-25) uses hpke-rs 0.7.0 from crates.io. Its X-Wing key derivation is
  `shake256::<32>(ikm)`: the unlabeled form. OpenMLS asks for hpke-rs `0.7`, so this holds while
  0.7.0 is the newest 0.7.x release, as it is today. A later 0.7.x with the labeled form would
  change what a fresh resolve of 0.9.0 gets.
- **OpenMLS main** has taken hpke-rs from a git revision of the libcrux repository since commit
  `ff94cdc2b036` (2026-09-10). There, the derivation goes through `pq_derive_keypair_seed`: the
  labeled form. OpenMLS's own `Cargo.toml` says why: "The next hpke-rs release (with the
  draft-ietf-hpke-pq derivation) is not out yet; use the git version until it is." Every
  `Cargo.lock` from the 0.9.0 release preparation to the commit before that one names crates.io's
  hpke-rs 0.7.0.
- **Go's standard library** `crypto/hpke` (Go 1.26 and later) uses LabeledDerive.

**The consequence** (inferred, not run): OpenMLS 0.9.0 and OpenMLS main should not interoperate on
any X-Wing suite. Our own X-Wing use is unaffected today. It runs outside HPKE, with its own key
derivation and a private algorithm identifier, and it is pinned to draft-10's vectors. But any
cross-check involving X-Wing in HPKE must be run against OpenMLS main, never 0.9.0.

---

## 5. The verdict

| | What | Why |
|---|---|---|
| **Adopt, 1** | Seal the joiner's `pq_secret` to the X-Wing key its KeyPackage already carries, instead of pasting it in the clear | A recorder of both pasted codes, with a future quantum computer, can read the epoch a join opens. For a two-person chat that never commits again, that is the whole chat. |
| **Adopt, 2** | Safety numbers and TOFU key-change warnings, as already specified | Joins are unauthenticated: whoever controls the paste channel can substitute keys unseen. This is the largest practical gap, larger than PQ. |
| **Adopt, 3** | Self-updates on a cadence, rotating the device X-Wing key in each, and keys encrypted at rest | Today a copied device state keeps decrypting until that device is removed. |
| **Adopt, 4** | The missing vector families and ValSem tests, an OpenMLS-main interop and state-machine cross-check, and a `req_auth` known-answer test | The reviewers' strongest methodology point. Today the vectors check the cryptography, not the state machine. |
| **Adopt, 5** | Correct the X-Wing pin in the docs, correct MASTER's PQ overclaims, publish an honest PQ statement, add govulncheck and Dependabot | Cheap honesty and hygiene |
| **Defer** | A post-quantum MLS ciphersuite | C6 keeps v1's MLS suite classical, and MASTER §7 (:1098) adopts a PQ suite once draft-ietf-mls-pq-ciphersuites is an RFC; at -06 it has no codepoints. After 1 and 3, what such a suite adds is narrow: post-quantum protection inside MLS itself. S3's red team states what healing against a quantum adversary means while MLS stays classical. When it comes, Go's `crypto/hpke` is a test oracle. |
| **Accept** | No deniability, and classical (Ed25519) authentication | No deniability: the owner's ruling (ledger item 232), and a permanent non-goal (MASTER :554). Classical authentication: C6's classical suite. Deniability is absent MLS-wide, and Signal's groups sign too. |

The owner adopted all five, in the order the lead recommends: "All of the above in best recommended
order." The program runs the quick fixes and the state-machine vectors first, as foundations
(section 7). The owner also asked for simulation tests and a test-backed report at each major
success. On the external audit, the owner ruled:
"Audit comes after the alpha is out. It’s planned in our wider scope so don’t worry and move
forward, we plan to use some of the best auditors".

---

## 6. What is post-quantum today, and what is not

This is the honest state as of 2026-10-05. The public statement the program publishes will replace
it.
- **Stored messages:** protected against an attacker who records them now and decrypts later with a
  quantum computer, for every epoch that a commit opens. This assumes the code is right, and it has
  not been audited.
- **The epoch a join opens:** not protected that way. The joiner's secret is pasted in the clear,
  beside a classical Welcome.
- **After a device is compromised:** nothing heals, classically or post-quantum. The device's X-Wing
  key never changes, and the copied state keeps decrypting until that device is removed.
- **The connection to the message server,** on the direct and URnetwork routes: a post-quantum
  hybrid key exchange (X25519MLKEM768). The server is authenticated by a pinned classical key.
- **Authentication everywhere:** classical: Ed25519 in MLS, and a pinned P-256 key on the
  transport. No key can be verified yet.

---

## 7. What happens next

The program, in order, is `docs/plans/2026-10-05-hardening-program.md`:
- **S0, foundations:** the rulings, an adversary simulation harness that runs red on today's gaps,
  the quick fixes, and the state-machine vectors.
- **S1** seals the join secret.
- **S2** builds safety numbers and TOFU.
- **S3** heals.
- **S4** cross-checks against OpenMLS main.
- **S5** ships to the alpha.

S1, S2 and S3 each get an adversarial red team before any spec edit. Each track's
simulation must fail on today's tree and pass after its change, and each major success is reported
to the owner with its tests. Ledger item 280 records the rulings.
