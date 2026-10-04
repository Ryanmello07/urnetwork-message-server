# Running the message server

What to install, what to configure, how to start it, how to tell it is healthy, and how to make it
refuse so you know the refusal works.

This is written against the build at which it was added. Every claim in it was run on a real
PostgreSQL 17.6 — except the ones marked **NOT VERIFIED HERE**, which need a URnetwork operator
account and are marked rather than assumed.

---

## Read this first: the message plane is not a listener

**This process binds exactly one socket, and that socket is the health port.**

Clients do not connect to the message server over TCP. They reach it over `connect`, the URnetwork
mesh transport, which works one way only: the server runs a `connect.Client` that **dials out** to
its operator's platform at `wss://connect.<operator_host>`, and the platform routes client frames
to that client's `client_id`. Spec B §9.1 says it in those words — *"Each instance runs a
`connect.Client` against the platform transport exactly as any client does."*

The consequences for a deployment are all of the following, and none of them is optional:

- **There is no port to open in the firewall for message traffic.** Outbound 443 to the operator is
  what this process needs.
- **There is no TLS certificate to obtain for the message plane.** The platform connection is
  `wss://` to the operator's own certificate.
- **You cannot run this server without a URnetwork operator account.** It needs a `network_client`
  credential on the operator named in `operator_host`. An admin **of that operator** creates the
  network once and one `network_client` per ordinal (§9.1). Nothing in this repository can create
  one, and neither can `connect`: minting a client credential
  (`BringYourApi.AuthNetworkClient`) authenticates with a *user* credential that an operator
  issues.

Without that credential the process still starts, still serves both health endpoints, and refuses
readiness on `ordinal_credential` while logging one line saying no message traffic will be served.
It does **not** stand up a client that silently receives nothing.

---

## What to install

| | |
|---|---|
| **PostgreSQL 17** | A cluster **separate from the operator's** — decision B10, and §9.2 makes it enforceable rather than advisory: the operator must not be given read access to this database. **The cluster's `timezone` must be `UTC`** (§3.1). It is a READINESS precondition and not a startup check — deliberately, because the case that produces a non-UTC cluster is a failover to a replica configured in another zone, which happens to a process that is already running — so a wrong zone makes `/readyz` refuse on `clock_utc` while the process runs and says why. The host clock must also agree with the cluster's, which is the separate `clock_skew` precondition. An earlier revision of this document said the process "refuses to start otherwise"; it does not, and never did. |
| **The two binaries** | `message-server` and `messagectl`, built static — see *Building* below. |
| **Nothing else** | No Redis, no object store, no Prometheus. This build opens none of them; see *What this build does not do*. |

## Building

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=$(git describe --always)" \
  -o message-server ./cmd/message-server
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o messagectl ./cmd/messagectl
```

`CGO_ENABLED=0` is not incidental: it is part of the configuration `release-platforms.txt` names and
that `deps_test.go` measures the dependency closure against, and it is what makes the binary static
and copyable to a bare box. `linux/amd64` and `linux/arm64` are the two released platforms.

The `-ldflags` stamp is what the process prints as its version. Without it the binary honestly
prints `dev`.

---

## Configuring

The process reads a **resource directory** — `URMESSAGE_RESOURCE_DIR`, default `.` — holding the
§10.2 resources, each a flat `key: value` file. Every value can also come from the environment, and
**the environment wins**, so secrets need never be written to disk.

The file format is a flat mapping and nothing else. Indentation, sequences, quotes that do not
close, duplicate keys and any key `message.yml` has no setting for are all **errors that name the
line number** — never lines that are silently skipped. A `#` is a comment only in the first column,
so a `#` inside a Postgres password is part of the password.

### `message.yml` — the advertised configuration (§10.2)

```yaml
# the operator this server holds its account on. A bare host name, not a URL.
operator_host: ur.network
# advertised to every client in Capabilities (§4.3.1). /readyz refuses until it is set.
hosting_jurisdiction: US

# every value below has a §10.2 default and can be omitted
read_key_window_seconds: 7776000
durable_ttl_default_seconds: 31536000
durable_ttl_max_seconds: 0
rendezvous_ttl_seconds: 7776000
rendezvous_deposit_ttl_seconds: 604800
rendezvous_mailbox_depth: 16
card_tombstone_seconds: 7776000
diagnostic_session_max_minutes: 60
```

Each key is overridable as `URMESSAGE_` + the key in upper case, e.g.
`URMESSAGE_HOSTING_JURISDICTION=DE`.

Only two of these ten do anything in this build: `durable_ttl_default_seconds` and
`durable_ttl_max_seconds` reach §7.3's clamp in the store. The other eight are loaded, printed, and
consumed by nothing — `/readyz` prints that list under `not-built`, so you can see it rather than
discover it.

### `pg.yml` — the database (vault; secret)

```yaml
dsn: postgres://urmessage:PASSWORD@127.0.0.1:5432/urmessage?pool_max_conns=16
```

Or `URMESSAGE_PG_DSN`. There is no separate `db.yml`: pgxpool reads `pool_max_conns`,
`pool_min_conns`, `pool_max_conn_lifetime`, `pool_max_conn_idle_time` and `pool_health_check_period`
out of the DSN itself, which is the one place the sizing can come from.

### `message_fleet.yml` — fleet-wide (vault; the KEK is secret)

```yaml
# §5.5's key-encryption key, 32 octets, hex. Losing it is unrecoverable and fleet-wide.
write_key_kek: 0000000000000000000000000000000000000000000000000000000000000000
write_key_kek_id: 1
# §4.3.1's server_id, 16 octets, hex, stable per fleet. Not a secret.
server_id: 00000000000000000000000000000000
```

Or `URMESSAGE_WRITE_KEY_KEK`, `URMESSAGE_WRITE_KEY_KEK_ID`, `URMESSAGE_SERVER_ID`.

Generate them with `openssl rand -hex 32` and `openssl rand -hex 16`. **Back the KEK up before the
first group is created.** §5.5 makes its loss unrecoverable: every epoch key in the database is
wrapped under it, and there is no second copy anywhere.

> `server_id` is read from `message_fleet.yml` because §9.1 makes it fleet-wide rather than
> per-ordinal, and §10.1's own rule — *"every advertised value that has no honest default present"* —
> is what makes an unset one a readiness refusal. **§10.2's contents list for `message_fleet.yml`
> does not name it.** That is a spec gap, filed in the ledger, not a decision this build took
> quietly.

### `message_server.yml` — this ordinal's identity (vault; secret)

```yaml
0.by_jwt: eyJhbGciOi...
1.by_jwt: eyJhbGciOi...
```

Or `URMESSAGE_BY_JWT` — **for a single instance only**. Which entry is selected comes from
`MESSAGE_SERVER_ORDINAL` (default `0`), per §9.1.

> **`URMESSAGE_BY_JWT` is one value for the whole process, and the environment beats the file for
> *every* ordinal.** One Kubernetes Secret or one shared systemd `EnvironmentFile` across a
> StatefulSet therefore gives every replica the same credential and so the same `client_id`, which
> §9.1 forbids — it requires one `network_client` **per ordinal**. The process cannot see its
> siblings, so it cannot refuse; it prints a `WARNING` line on every start and in `--print-config`
> whenever the credential came from that variable. At N ≥ 2, put the credentials in
> `message_server.yml`, keyed by ordinal.

Every resource line says **which source won**: `present (file)` or `present (environment)`.

The `client_id` is read out of the credential and never configured beside it. You may write
`0.client_id: <uuid>` as documentation; if you do, it is **checked** against the id inside the
credential and a disagreement is a startup failure — the platform routes to the id it
authenticated, and an id in a file that disagrees is an address clients reach and nothing answers.

---

## Starting it

### 1. Check the configuration without opening anything

```bash
URMESSAGE_RESOURCE_DIR=/etc/urmessage ./message-server --print-config
```

Reads every resource, opens no socket and no database, and prints what it would run on. Secrets are
printed as `present (file)`, `present (environment)` or `ABSENT`, and never as values. This is the
first thing to run on a new box, and it **works before `pg.yml` exists**: a missing DSN prints as
`ABSENT` with a `this configuration WILL NOT START` line under it, and the command still exits 0.
Every other resource is read and reported, so the answer is whole rather than truncated at the
first thing that is missing.

### 2. Migrate

```bash
URMESSAGE_RESOURCE_DIR=/etc/urmessage ./messagectl migrate
```

§10.3 is normative that migrations are run by a dedicated job or by this command, **never by N
replicas racing at startup**. The server therefore has no migration path at all: it reads whether
the list has run and refuses readiness until it has. The command takes
`pg_advisory_lock(0x75726d7367)` for the whole run, is idempotent against a database already at
head, and works against a completely empty one.

```bash
./messagectl status     # exit 0 at head, exit 2 with the missing version named
```

It prints §3.1's two clock answers on separate lines, because they are two faults with two
repairs — a `postgresql.conf` and an NTP daemon:

```
timezone:   UTC
clock skew: within 30s
migrations: at head, 11 applied
```

An earlier build printed one line, `clock: UTC`, and printed it against a cluster configured
`America/Phoenix`: it asked the question through the pool, and every pooled connection pins
`timezone = UTC` in its startup packet, so the comparison ran against the value it was checking
for. If your `timezone:` line reads `NOT UTC`, the cluster is what is wrong, not the host.

**The exit code is about migrations only** — 0 at head, 2 behind — so a cluster in the wrong zone
exits 0 here while `/readyz` refuses on `clock_utc`. If you gate a deploy on this command, read the
`timezone:` line as well as the status.

### 3. Run

```bash
URMESSAGE_RESOURCE_DIR=/etc/urmessage \
URMESSAGE_HEALTH_ADDRESS=127.0.0.1:9099 \
MESSAGE_SERVER_ORDINAL=0 \
  ./message-server
```

It logs one structured line per resource and per §10.2 value, then either `attached to the operator
platform` with the two service URLs, or a warning in capitals that no message traffic will be
served. It runs until SIGINT or SIGTERM.

Health endpoints bind `127.0.0.1:9099` by default. §10.1 puts them on a **private** port; the
loopback default is deliberate, so that a missing firewall rule is not the only thing keeping them
off the public interface.

---

## Telling whether it is healthy

```bash
curl -s -o /dev/null -w '%{http_code}\n' localhost:9099/healthz   # 200 while the process runs
curl -s localhost:9099/readyz
```

`/healthz` is *is this process alive*, and answers 200 even when nothing else works — a supervisor
that restarted a replica because its database was down would get a second replica whose database is
down.

`/readyz` is *should traffic come here*. 200 and the body `ready`, or 503 and one
`not-ready <name>: <why>` line per unmet precondition. Neither endpoint returns any identifier: the
names and the reasons are constants in the binary, and no configured value is ever printed.

The preconditions, which are §10.1's list plus the two §9.1 adds:

| Name | Met when |
|---|---|
| `database_reachable` | the pool answers |
| `clock_utc` | the cluster's own `timezone` renders every month of this year as UTC does. Read on a connection that does **not** send the `timezone` parameter, because every pooled connection pins it to `UTC` and the cluster's own value cannot be seen through the pool |
| `clock_skew` | the database's wall clock and this host's agree to within 30 s. §7.1 stamps `prune_after` from the host's clock and §7.4 sweeps against the database's |
| `migrations_at_head` | `messagectl migrate` has run this binary's whole list |
| `kek_loaded` | `message_fleet.yml` supplied a 32-octet `write_key_kek` |
| `server_id_set` | `message_fleet.yml` supplied a 16-octet `server_id` |
| `ordinal_credential` | `message_server.yml` has an entry for `MESSAGE_SERVER_ORDINAL` |
| `connect_client_attached` | the platform transport holds a connection with routes registered |
| `operator_host` | `message.yml` set it |
| `hosting_jurisdiction` | `message.yml` set it |

Below those, the body prints one `not-built` line per gap in this build. Those lines are printed on
the **ready** answer too: a server that is ready and serves no rendezvous arm is still a server you
need to know serves no rendezvous arm.

### Watching it refuse

Each of these produces a specific refusal, and each is worth doing once so you know the probe works:

```bash
export URMESSAGE_RESOURCE_DIR=/etc/urmessage

# an empty database: migrations_at_head, and database_reachable NOT named
createdb urmessage           # and do not run `messagectl migrate` yet
./message-server & sleep 1
curl -s localhost:9099/readyz | grep -E 'migrations_at_head|database_reachable'
kill %1

# a jurisdiction nobody set: hosting_jurisdiction
URMESSAGE_HOSTING_JURISDICTION= ./message-server & sleep 1
curl -s localhost:9099/readyz | grep hosting_jurisdiction
kill %1

# an ordinal with no entry: ordinal_credential, and connect_client_attached behind it
MESSAGE_SERVER_ORDINAL=99 ./message-server & sleep 1
curl -s localhost:9099/readyz
kill %1

# a cluster that is not UTC: clock_utc, and clock_skew NOT named
#   (`options` is what a postgresql.conf would have done; the pool's own timezone=UTC does not
#    hide it, which is the whole point of the check)
URMESSAGE_PG_DSN="$(cat /etc/urmessage/pg.yml | sed 's/^dsn: //')&options=-c%20timezone%3DAmerica/Phoenix"   ./message-server & sleep 1
curl -s localhost:9099/readyz | grep -E 'clock_utc|clock_skew'
kill %1

# a database that is not there at all: database_reachable, and /healthz still 200
URMESSAGE_PG_DSN='postgres://nobody@127.0.0.1:1/nothing' ./message-server & sleep 1
curl -s localhost:9099/readyz | grep database_reachable
curl -s -o /dev/null -w '%{http_code}
' localhost:9099/healthz    # 200
kill %1
```

The last one is the one worth doing deliberately: `/healthz` answering 200 while `/readyz` refuses
is what stops a supervisor from restart-looping the whole fleet through a database outage.

A misspelled key is a **startup failure** naming the key, not a silent default:

```bash
echo 'hosting_juristiction: DE' >> /etc/urmessage/message.yml
./message-server --print-config
# message-server: .../message.yml: no §10.2 setting has this name...: hosting_juristiction
```

### Shutting it down

SIGTERM or SIGINT. Readiness goes false first, so a load balancer stops sending here before
anything is torn down; then the frame dispatcher closes and waits for every in-flight request; then
the connect client; then the pool; then the health listener, which keeps answering `not ready` for
as long as the teardown takes. A second signal is not swallowed.

---

## What this build does not do

Every one of these is printed by `/readyz` under `not-built`, and by `--print-config`. They are
listed here so a deployment plan is made with them in view rather than around them.

> That claim of completeness was false once, and it is worth knowing how. §5.1 check 5's
> known-group filter was a per-process `map[string]bool` wired at `cmd/message-server/server.go`,
> populated only by a `CreateGroup` that committed on that process and never read back from
> Postgres. **Every group created before a restart became permanently `REASON_REJECTED`** — which
> §4.5 makes indistinguishable from a bad MAC — while `/readyz` went on answering `ready`. It was
> on no `not-built` list and in no version of this document, and the list said it was complete.
> Each entry below is now emitted by the collaborator that has the hole rather than typed into a
> list beside it.

- **§5.1's cuckoo filter, its Redis-published add, and its 60-second refresh.** Check 5 itself
  **is** run, and it reads the truth: a filter miss does one indexed `message_group` lookup and
  caches the hit, so a restarted replica, a second replica and a replica that has never seen a
  group all answer the same thing. What is absent is the machinery §5.1 describes for answering
  that question without the read. The price is one indexed row read per **distinct unknown**
  `group_id` — an attacker holding no `write_key` can force that read, and §4.7's per-`client_id`
  limits that would bound it are check 4, which is also not built. The refresh is absent because a
  read-through filter has nothing for it to back up: a negative is never stored, so it cannot go
  stale. The positive cache is never evicted, so it holds roughly a hundred bytes per distinct
  group served since the process started, and only a restart empties it.
- **§2.3's drain.** SIGTERM does not send `Drain{reconnect_after_ms}` to attached clients, because
  `peer` has no push path of any kind. At N ≥ 2 a rolling deploy therefore migrates the whole
  attached population at once. **Run one replica until this lands.**
- **§2.4's Redis.** Not opened. Subscribe fan-out, presence and the distributed token buckets are
  absent, so a second replica shares nothing but Postgres.
- **§8's blob plane.** No object store, no `blobd`, no grant tokens.
- **§7.4's sweep.** Nothing prunes. `read_key_window_seconds`, `card_tombstone_seconds` and the TTLs
  are loaded and no job reads them; records accumulate.
- **§4.3.1's `ServerKey` chain.** `HelloResponse` carries no signing key, because §9.1 decision B13
  keeps every signing key off every replica and there is no signing sidecar here. No
  `FetchAttestation` is signed.
- **§4.3.11's rendezvous**, **§4.3.5's subscribe**, **§9.3's discovery publication**, **§9.4's KT
  gossip.** Absent.
- **§10.2's reload.** `message.yml` is read once at startup and is not watched. There is no
  `capability_version` and no `CapabilityChange`, so changing an advertised value **does** require a
  restart — which is exactly what §10.2 says it must not.
- **TLS termination, systemd units, metrics, backups.** Out of this build's scope by decision;
  §10.4's backup requirements in particular are not optional before real users and are not
  addressed here.

---

## The order to bring a new deployment up in

§9.1's bootstrapping order, made concrete:

1. An admin of the operator in `operator_host` creates the network and one `network_client` per
   ordinal. **This is the step that cannot be done from this repository.**
2. Write the credential into `message_server.yml` (or `URMESSAGE_BY_JWT`).
3. Generate and back up `write_key_kek`; generate `server_id`. Both into `message_fleet.yml`.
4. Create the database and role; write `pg.yml`.
5. `messagectl migrate`.
6. Start `message-server`. `/readyz` should answer 200 within a few seconds of the platform dial
   completing. **NOT VERIFIED HERE:** steps 1 and 6's platform attachment have not been exercised
   against a live operator from this repository — no account was available.
