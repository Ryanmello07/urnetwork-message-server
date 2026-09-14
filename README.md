# message-server

Message server for **URmessage** — private messaging built on the URnetwork mesh.

The message server stores encrypted records, orders them, serves history, and prunes by retention
policy. It never decrypts anything, and it is not the authority on group membership: that lives in
the MLS (RFC 9420) group state held by clients.

## Status

Early development, and the process runs. It loads
[spec B §10.2](docs/specs/2026-08-12-spec-b-message-server-operator.md)'s configuration, opens the
message-server Postgres cluster, asserts §3.1's clock and §10.3's migrations, builds the store, the
§5.1 pipeline and §4.2's frame dispatch on top of them, attaches a URnetwork client to its
operator's platform, serves §10.1's `/healthz` and `/readyz` on a private port, and shuts down in
§2.3's order. A first start against an empty database is a tested path.

**It binds exactly one socket, and that socket is the health port.** The message plane is not a
listener and cannot be: clients reach this server over `connect`, which dials the operator's
platform and receives the frames the platform routes to this replica's `client_id`. That means a
running message server needs a `network_client` credential on that operator, created by an admin of
it — §9.1 — and nothing in this repository or in `connect` can mint one. Without it the process
starts, serves both health endpoints, and refuses readiness on `ordinal_credential` rather than
standing up a client that silently receives nothing.

To deploy one, read
[docs/ops/2026-09-14-running-the-message-server.md](docs/ops/2026-09-14-running-the-message-server.md).
It also lists, in one place, everything this build does not do.

## Layout

Every directory of §2.1 exists, and each one that has no code yet carries a `doc.go` saying what it
will hold and what it may import. The stubs are not decoration — a gate whose root directory is
missing either fails outright or, worse, reports clean having read nothing.

| Package | What it will hold |
|---|---|
| `cmd/message-server` | process entrypoint |
| `cmd/messagectl` | ops CLI: migrate, sweep-now, capability dump, key rotate |
| `peer` | connect client wiring, frame dispatch, fragmentation (§4.6) |
| `api` | request handlers, one file per operation (§4.3), `write_auth` verification (§5.1) |
| `store` | pgx queries and migrations — the only package that writes SQL |
| `blobd` | HTTP bulk plane, grant verification (§8) |
| `sweep` | retention sweep, blob GC, orphan reaper (§7.4) |
| `kt` | key-transparency gossip client, read-only (§9.4) |
| `redact` | unprintable identifier types (decision B11, §11.2) |
| `metrics` | Prometheus collectors (§11.3) |

## Building

The URnetwork Go repositories are built from the working tree, sibling-checked-out, the way the rest
of the workspace is wired. This module's `go.mod` replaces two of them with `../`, so the checkout
must look like this:

```
<workspace>/
  connect/          github.com/urnetwork/connect     (branch beta/message)
  glog/             github.com/urnetwork/glog
  message-server/   this repository
```

`glog` is replaced even though nothing here names it: `connect` requires `github.com/urnetwork/glog
v0.0.0`, a version no proxy serves, and a `replace` in a dependency's `go.mod` is ignored — only the
main module's replaces apply. Without that line `connect` is unbuildable from here.

Neither module is *required* yet, because nothing in this module imports either one. The `require`
lands with the first import.

```bash
go build ./...
go vet ./...
go test -count=1 -run '.' -timeout 30m ./...
go run ./cmd/message-server --print-config   # reads every resource, opens nothing, prints it

# the release configuration, which is what CI builds and what deps_test.go measures against
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/message-server
```

Go 1.26.5. Measured 2026-09-14 with PostgreSQL 17.6 running:

```
go test ./... -count=1 -timeout 45m -json | grep -c '"Action":"pass".*"Test":'   ->  583
                                             grep -c '"Action":"fail".*"Test":'  ->    0
                                             grep -c '"Action":"skip".*"Test":'  ->    0
```

**Zero skips is the number that matters.** Without `URMESSAGE_TEST_DSN` the pgx store contract and
the server's start-up tests skip loudly, `store/coverage_test.go` prints a PARTIAL RUN banner, and
the total drops by well over a hundred — a green line that executed §6.1's transaction against
PostgreSQL exactly zero times. Set the variable to a DSN the suite may create and drop schemas in,
and set `URMESSAGE_REQUIRE_CONTRACT_COVERAGE=1` so that a run which somehow did not is a failure
rather than a banner.

`-race` is clean over every package, with `CGO_ENABLED=1` and a C compiler on `PATH`.

## The dependency gate

`deps_test.go` at the root of the module is spec B §2.2 as a test. It runs `go list -deps`, over the
packages this module builds and again over their tests, and holds the result to the whole of what
§2.2 allows — not to a list of what §2.2 bans. A dependency nobody wrote down fails it, which is the
direction the shell one-liner in §2.2 does not check at all.

It has a positive control, so a broken matcher cannot report the module clean, and it **fails rather
than skips** when `go list` cannot run: a gate that skips is a gate that is off, and it prints the
same green line as a gate that passed.

The first package here that parses a record will fail this gate, and that failure is correct. §2.2
allows `connect/message`; `connect/message` imports `connect/mls/syntax`; §5.3 and §13 item 8 ban
`connect/mls` and assert it with a `grep` that also matches its child. The two cannot both hold as
written, and the resolution belongs in the spec rather than in a quiet edit to the allow list. The
test's comment says so at the point where somebody will be tempted.

## Postgres

`.github/workflows/gates.yml` runs a `postgres:17` service and sets `URMESSAGE_TEST_DSN` and
`URMESSAGE_REQUIRE_CONTRACT_COVERAGE`, so the pgx half of the store contract RUNS in CI and a job
that somehow did not run it fails rather than passing with a banner. The store has a memory
implementation and a pgx one held to one contract ([`store/contract.go`](store/contract.go)), and
`store/migrations.go` is the append-only list of §10.3.

Migrations are run by [`cmd/messagectl`](cmd/messagectl) and never by a replica at startup, which is
normative in §10.3. The server reads whether the list has run and refuses readiness until it has.

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).
