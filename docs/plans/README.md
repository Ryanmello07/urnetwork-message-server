# Implementation plans

One plan per slice from §14 of the protocol design. Each plan is written before its code and
reviewed before it is executed.

Slices, in order:

| # | Slice | Gate |
|---|---|---|
| 1 | `connect/mls/` — RFC 9420 | **The IETF test vectors pass**, cross-checked against OpenMLS |
| 2 | `connect/message/` — storage records, retention classes, ratchet, PQ composition, `write_auth`, padding, `COVER` | Freezes the wire format |
| 3 | `message-server` — store, ordering, single-commit agreement, `write_auth` verification, retention, fetch attestation | The §9.7 logging prohibition is an acceptance criterion |
| 4 | Client core in `sdk` — group state, local store, KT client, provisioning | |
| 5 | `message-windows` — text, groups, TOFU warnings, reactions, receipts | **First testable build** |
| 6 | Disappearing messages — `eph_root`, buckets, tombstones | |
| 7 | Multi-device — provisioning UI, device management, revocation | |
| 8 | Attachments — blob store, `MEDIA` class, thumbnails, resumable upload | |
| 9 | `/server` operator — discovery directory, KT log | |

Slice 1 is the schedule risk and is first because it has an objective completion test. Slices 1–5
produce something two people can text on.
