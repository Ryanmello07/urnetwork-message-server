# URnetwork route, 2026-10-04: why the beta's exits ignore the per-peer handshake

This report is the evidence behind ledger item 279, which records the owner's two rulings. Times are UTC. Client ids are shortened.

## Summary

- **The regression.** The merged URmessage client requires a per-peer session with each exit, and almost no exit on the beta answers one (ledger 278).
- **The mechanism, measured on exits of our own.** connect's default per-peer mode is Off, and an exit in that mode drops every ClientHello. One added setting, `EncryptionModeOpportunistic`, makes the same provider answer.
- **The fleet, measured on the operator's database.**
  - 245 of the 246 connected public providers name one third-party program, `v3.23.0-fix.28.0`,
    in their client descriptions, all in one network.
  - None of the 72 of them that we reached answered.
  - The one exit that answered runs a connect-era CLI.
- **The client half, committed.** On the fork's `main` (sdk `c71bb73b`), and proposed upstream as
  urnetwork/sdk#156, URmessage's route asks each exit for a session in OPPORTUNISTIC mode. No
  released build carries it yet: the alpha still ships the pre-merge SDK, which asks for no
  session, and upstream's `main` requires one until #156 merges.
  - On today's fleet its first Hello is answered on attempt 1, as the alpha's is.
  - With an exit that answers, it seals once the session is usable, 0.55 to 0.62 s after the ClientHello.
  - A 1 s establish hold in connect, to seal from the first byte, is in progress.

## 1. The experiment: three providers of our own

The owner asked whether the providers run old code, and proposed the test: run a node of our own, note its client id, and connect to it directly. Each run pinned the client's window to one exit, by client id.

**The client was the same in every run.**
- It was `livepeer`, built from the forks' sdk `22629e9a` and connect `8cc3b556`, plus an 18-line experiment patch.
  - 15 lines are the pin: `URMESSAGE_EXIT_CLIENT_ID` becomes `ProviderSpec{ClientId}`, which skips find-providers2.
  - The other 3 print the Hello's timing.
- The `PostQuantumEncryption` profile, which requires a session, was unchanged.
- It ran as a test user, with route `urnetwork` and the endpoint `wss://74.50.11.53/urmessage/v1` with its pin, from a fresh state directory each time.

**The providers** ran on our VPS, under a new seedphrase account. Its secrets stay on the VPS.

| Run | Provider | Per-peer handshake | First URmessage Hello | Traffic to the exit |
|---|---|---|---|---|
| pinA-1 | **A**: urfoundation/sn `9356e1d4` (`./cli/miner`) on sdk `22629e9a` and connect `8cc3b556`; client `01a10822-…` | completed: 1 ClientHello, 1 complete, identity verified | attempt 1, 1.456 s | 15 sealed writes, 0 plaintext application writes |
| pinA-2 | A, same process | completed | attempt 1, 1.388 s | 15 sealed, 0 plaintext |
| pinB-1 | **B**: our build of the operator's untracked `provider/main.go` at its connect `647bdae0`, with `golang.org/x/term v0.45.0` added to go.mod; client `01a10829-…` | **never**: 14 ClientHellos, 0 answered; 13 cancelled at exactly 5.00 s, 1 still open at exit | **never**: 3 attempts × 60 s, then FAIL after 190 s | 0 application writes; 28 plaintext handshake frames |
| pinBprime-1 | **B′**: B plus a 9-line env gate that sets `Mode = EncryptionModeOpportunistic`; client `01a1082e-…` | completed | attempt 1, 1.444 s | 15 sealed, 0 plaintext |

**The public windows**, by the VPS's clock:
- A: 18:19:24 to 18:21:06;
- B: 18:24:31 to 18:28:39;
- B′: 18:30:22 to 18:31:32.

No other sender's traffic reached any of them. Every sender was one of our own windows, or the platform.

**Why B's result counts:**
- **The hellos were delivered and ignored, not lost.** B logged a receipt for all 14 of the client's window ids: `[r]head 1 (TransferEncryptedControl)`.
  - The VPS's clock ran 4.71 to 5.19 s ahead of the client's. A's and B′'s handshakes bound
    that offset.
  - Corrected for it, each hello reached B within 0.55 s of leaving the client.
- **B logged no `[tls]` line and never wrote `.provider.cert`.**
  - Its server TLS configuration is built only when the mode is not Off.
  - The same extraction kept 58 `[tls]` lines for A and 27 for B′.
  - B's receipts are themselves V(1) lines, so the absence is not a logging level.
- **The 5.00 s is the client's, not the exit's.** Each cancel came when the window's evaluation failed with "encryption required: session not established with peer". Any exit that does not answer produces it.
- **The counting script reproduces ledger 278's published figures on 278's runs.**
  - On its two merged runs: 130 ClientHellos, 2 complete and 123 cancelled.
  - On its two OPPORTUNISTIC runs: its write table.

## 2. The mechanism

- **connect's default is Off.** `DefaultEncryptionSettings().Mode` is `EncryptionModeOff` at `647bdae0` and at `8cc3b556`. In that mode `DeliverEncryptedControl` returns at once (`647bdae0` `transfer_encrypt.go:3610-3612`).
- **The sdk's provider path turns sessions on.** It has since `8a91a91c` (2026-07-22), as
  `Encrypt = true`, and has set `EncryptionModeOpportunistic` since `e7680ba6` (2026-08-09). At
  `22629e9a` the line is `device_local_provider.go:207`. sn's provider uses that path.
- **The connect-era CLI never turns sessions on.**
  - That holds for the operator's copy, and for the last committed one, `ecd2b90f`. Upstream deleted the CLI the same day, in `3b6b151e`.
  - Before 2026-08-09 the switch was `EncryptionSettings.Encrypt`, default false. `Mode` first appears in connect `d2553e06`.
  - No version of `provider/main.go` in connect's history sets either one.
- **The handshake's messages did not change** between `647bdae0` and `8cc3b556`, and B′ completes the handshake with the merged client. The other wire changes between those two connects only add things.

## 3. The fleet

These are read-only queries on the operator's database. q8 ran at 20:46 UTC.

```sql
-- q8: connected public providers (provide_mode 3), by the program their client description names
with p as (
  select distinct nc.client_id, coalesce(nc.description,'') as d, nc.network_id
  from provide_key pk
  join network_client nc on nc.client_id = pk.client_id
  join network_client_connection ncc on ncc.client_id = nc.client_id and ncc.connected
  where pk.provide_mode = 3
)
select case when d ~ '\[[^]]+\]$' then substring(d from '\[([^]]+)\]$')
            when d like 'provider %' then 'connect-era CLI'
            when d = '' then '(empty)' else '(other)' end as program_version,
       count(*) as connected_public_providers, count(distinct network_id) as networks
from p group by 1 order by 2 desc;
```

| Program, from the client description | Connected public providers | Networks |
|---|---|---|
| `v3.23.0-fix.28.0` (descriptions read `<host> [v3.23.0-fix.28.0]`) | 245 | 1 |
| connect-era CLI (description `provider linux`, client created 2026-09-07) | 1 | 1 |

**q7 looks up ledger 278's exits the same way.**
- It takes the 73 exits that 278's four runs sent a ClientHello to, from their `[tls]` lines that
  read `client c=… <id> outbox batch 0: <n> bytes (record type 0x16)` and
  `… <id> handshake complete`. Their `opened session for peer <id> as client` lines give the
  same 73.
- 72 run `v3.23.0-fix.28.0`, and none of them answered.
- The one that answered is the connect-era CLI.
- The ids are a third party's clients, so they are not printed.

**What follows:**
- **By its client descriptions, the silent fleet is one third-party provider program, under one
  network.** It is not the connect-era CLI. Its source is not in any repository we have.
- **Why it drops the ClientHello is inferred, not seen.** connect's Off default fits.
- **The fix for such a program**, which the owner relays to its operator:
  - wherever it builds its connect client settings, set `EncryptionSettings.Mode = EncryptionModeOpportunistic` (connect `d2553e06` or later);
  - or, if it uses the sdk's provider, update the sdk to `e7680ba6` or later.
  - It is backward-compatible: clients that ask for no session keep working as before.
- **The fleet's one connect-era CLI answers**, although no CLI source we hold turns sessions on. So it runs a build we do not hold.
- **The VPN works on this fleet** because by default it asks for no session. A silent exit carries
  its traffic unsealed.

## 4. The client half: OPPORTUNISTIC

**What was committed.**
- sdk `c71bb73b` is on the fork's `main`. Upstream, it is urnetwork/sdk#156: `98e444e1`, which is
  upstream's `main` plus one commit. Its `go test` passed (run `37234810669`).
- No released build carries it yet: the alpha ships the pre-merge SDK (`alpha/premerge`), and
  upstream's `main` carries REQUIRED until #156 merges.
- It sets the window clients' per-peer mode to `EncryptionModeOpportunistic`.
- It turns `PostQuantumEncryption` from true to false, because connect reads it as REQUIRED. It
  keeps `AllowDirect` false.

**Measured on the beta, 2026-10-04:**

| Runs | Exit | First URmessage Hello | Per-peer sessions | Plaintext application writes before the cipher was usable | Sealed writes |
|---|---|---|---|---|---|
| opp-a1, opp-a2 | unpinned: the fleet | attempt 1, after 2.007 s and 2.463 s | 12 ClientHellos each, none answered | all of them: 136 and 211 | 0 |
| opp-b1 | exit A (sn's provider) | attempt 1, after 1.234 s | 1, identity verified | 6 | 8 |
| pinA-opp-1, pinA-opp-2 | `urn-exit-a` | attempt 1, after 1.212 s and 1.212 s | 1 each, identity verified | 6 and 6 | 9 and 8 |
| pinB-opp-1, pinB-opp-2 | `urn-exit-b` | attempt 1, after 1.209 s and 1.293 s | 1 each, identity verified | 6 and 3 | 9 and 12 |

- **The pre-session window** runs from the ClientHello until the cipher is usable. It lasted 0.549 to 0.621 s.
  - By size, the writes in it were the TCP open to the endpoint: 3 or 4 writes of 95 to 178 bytes.
  - In 4 windows of 5 they also carried its TLS ClientHello, in writes of 1,200 and 574 bytes.
  - REQUIRED holds these writes: A's and B′'s REQUIRED runs sent 0 of them.
- **How the writes are counted.** An application write is a `write plaintext` line with `forceUnwrapped=false` to a non-zero destination. They are counted per window client, before that window's `cipher is now usable`.
- **The live probe.** On the VPS, `liveprobe -route urnetwork` reported "13 STEPS, 1668 ASSERTIONS, ALL HELD" in 2 runs.

**What OPPORTUNISTIC gives up, against REQUIRED.** It defeats a relay that reads, not one that interferes, and the app cannot tell which it met.
- **With an exit that never answers**, the relay reads every packet's headers, as with mode Off.
- **With an exit that answers**, the relay reads the packets sent before the session is usable, as measured above.
- **Only REQUIRED does these things:**
  - holds application writes until the session is up (`SendSequence.Pack`);
  - holds the cipher for the signed key-history check (`keyHistoryRequiredWithLock`), which was
    narrow in this tunnel even under REQUIRED: it sets no `PeerClientKeyPinStore` and no
    `TrustedClientKeySigners`, so an operator could downgrade it by withholding the history;
  - drops plaintext from a sealed exit (`ReceiveSequence.receiveHead`);
  - refuses the downgrade that a forged nack forces (`handleUnknownWrapNack`).
- **Content stays protected in every mode:** TLS to the server's pinned key, and MLS.

**In progress: a 1 s establish hold in connect** (`EncryptionSettings.OpportunisticEstablishHold`, zero by default).
- An OPPORTUNISTIC window holds its writes up to 1 s for the exit's session, so an exit that answers is sealed from the first byte.
- It cannot stop a relay that drops the handshake.

## 5. The provider patch, and our test exits

**The patch** makes B′'s change without the env gate. It is to the connect-era CLI's `provider/main.go`: the operator's copy, sha256 `7b4bd794…`.
- It compiles for linux/amd64 against `647bdae0` only with `golang.org/x/term v0.45.0` added to go.mod and go.sum. Those lines ship with it.
- The fleet's one CLI exit already answers. So the patch serves our own test exit, and any CLI exit someone starts.

**Our test exits** run on the VPS for the test period, with the owner's approval.
- `urn-exit-a` runs sn's provider. Its client is `01a10822-…`, stable across restarts.
- `urn-exit-b` runs the patched CLI, with a new client id on each start.
- Both are public. Each is capped at `MemoryMax=700M` and `CPUQuota=60%`.
- While they run, other beta users can egress through the VPS.
- A third, `urn-exit-a2`, ran sn with a fresh auth-client credential. sn's custody check refused it, and it was removed.

## 6. Operator findings: a report, not a fix

1. **The provider source on the operator is not in git.**
   - `provider/main.go` is untracked in the operator's connect checkout.
   - The operator's connect `647bdae0` and its parent `8f07a862` are on neither the fork nor upstream.
   - The fork's `beta/merge-main-2026-07-25` is at `3648dd7b`, an ancestor of both. So the operator is two unpushed merge commits (2026-09-15) ahead.
2. **That source does not build at its own checkout.**
   - It imports `golang.org/x/term`, which `647bdae0`'s go.mod does not require. x/term left
     connect's go.mod in `2ce0a49a` (2026-07-15), eleven days after upstream deleted the CLI in
     `3b6b151e`.
   - So whatever the operator deployed was not built from this tree as it stands.
3. **Today's sn provider cannot create a client on this operator.**
   - It speaks only `POST /network/register-client-v1`, which server `3eaa31e7` lacks.
   - Adopting the account's original credential works.
   - sn's custody check refuses a fresh auth-client credential.
   - So a fresh install of today's provider cannot join this beta.
4. **Seedphrase account creation is rate-limited per address.** Ledger item 264 recorded a sixth account refused. This run's account was created at the first attempt.
5. **Today's provider also starts an extender role.**
   - On the VPS it bound UDP 443 and 4053.
   - Its TCP 443 and UDP 53 binds failed. TCP 443 is the message server's own, so the message server was untouched.
   - `urn-exit-a` runs this role on the message-server box, and sn `9356e1d4` has no flag to
     disable it. The lead's ruling, in ledger 279: it stays for the test period, and is revisited
     if it adds load or if the message server ever listens on UDP 443.

## 7. Evidence and cleanup

- **The working files are in the lead's session scratch directory, not in this repository.** They are:
  - the run logs and the address-stripped provider extracts;
  - the scripts and the queries;
  - the diffs and the patch.
- **Why they stay out:** the client logs carry network addresses, and one query lists a third party's client ids.
- **The queries behind the counts** are printed here and in ledger 278's query table. The CLI
  exit's description and creation date come from two more read-only queries, which print only
  buckets.
- **The raw provider logs** held address lines. They were shredded on the VPS once the extracts were taken, and a stale log watcher from an earlier session was killed.
- **Nothing remains of the A/B runs:** no unit, and no process. The two test exits in section 5 are separate units.
- `urmessage` and `postgresql` were active at every check, and `/readyz` reported ready.
