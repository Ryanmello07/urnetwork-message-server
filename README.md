# message-server

Message server for **URmessage** — private messaging built on the URnetwork mesh.

The message server stores encrypted records, orders them, serves history, and prunes by retention
policy. It never decrypts anything, and it is not the authority on group membership: that lives in
the MLS (RFC 9420) group state held by clients.

## Status

Early development. The module is a skeleton: the package layout of
[spec B §2.1](docs/specs/2026-08-12-spec-b-message-server-operator.md), an entrypoint that prints
what it is and what it would run on, and the dependency gate of §2.2. Nothing stores a record yet,
and nothing listens on anything.

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
go test -count=1 -run '.' -timeout 5m ./...
go run ./cmd/message-server        # prints its version and configuration, then exits
```

Go 1.26.5. There is no `go.sum` because there is no dependency outside the standard library yet.

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

There is none on a developer box, and none in this repository's CI at the time of writing. The store
therefore gets a memory implementation first (the next task), against the same interface the pgx one
will satisfy. Anything that can only be tested against a live database — the commit race of §13
item 2, the migration-on-populated-database of item 11 — is a CI concern, and is not claimed to pass
here until it has actually run somewhere.

## License

Mozilla Public License 2.0 — see [LICENSE](LICENSE).
