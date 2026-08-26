// The only package in this module that writes SQL. Every query of spec B §3, the ordered
// migration list and the `migration_audit` table of §10.3 in migrations.go, and the
// single-commit transaction of §6.1.
//
// This package holds no code yet — the next task builds it, against the memory
// implementation first, because there is no Postgres on a developer box and a store whose
// only implementation needs one is a store nobody can test before CI.
//
// May import: jackc/pgx/v5, this module's redact and metrics, and github.com/urnetwork/server
// (root package only) for the vault and config resource loading of §10.2. Never
// github.com/urnetwork/server/model: that package is the operator's account identity layer,
// and a store that can reach it will eventually join against it. Every identifier crossing
// this boundary is one of the opaque types in redact, and it is unwrapped here explicitly —
// §11.2 gives the pgx encoding path that makes a named []byte type write the literal bytes
// `<redacted>` into a primary key.
package store
