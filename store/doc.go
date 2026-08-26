// The only package in this module that writes SQL. Every query of spec B §3, the ordered
// migration list and the `migration_audit` table of §10.3 in migrations.go, and the
// single-commit transaction of §6.1.
//
// # The interface, and why it is a deviation
//
// §2.1 says this package is "pgx queries", one implementation and no seam. It has one now:
// [Store] is an interface, [NewMemoryStore] is an implementation of it that holds everything
// in memory, and the pgx implementation lands behind the same interface. The reason is
// operational rather than architectural. There is no Postgres and no Docker on a developer
// box here, so a pgx-only store is a store nobody can execute a single assertion against
// before CI, and the first message could not travel until a database existed somewhere. A
// seam that lets the transaction of §6.1 be written, run and mutated today is worth more than
// the one implementation §2.1 assumed.
//
// What does not change: this package remains the only one that will write SQL. The interface
// is a boundary inside the package, not an invitation to put queries anywhere else.
//
// # The hazard the deviation creates, and what is done about it
//
// A memory implementation can hand out semantics Postgres will not. A map lookup is atomic in
// ways `SELECT … FOR UPDATE` is not; a Go mutex serialises what a READ COMMITTED transaction
// interleaves. An implementation that quietly provides more than the database does makes the
// contract pass here and the deployment fail there, and it fails there in the one place §6.1
// says the order is the entire point.
//
// Two things answer it. The behavioural tests are a contract suite — [RunContract] — which
// belongs to the interface rather than to either implementation, and which the pgx
// implementation runs unchanged; a test that can only pass against a map does not belong in
// it. And the memory implementation models the two mechanisms §6.1 actually names, rather
// than substituting Go's: a per-group lock that is the row lock of step (1) and is taken for
// nothing wider, and a per-group visibility lock that makes a transaction's writes appear
// together, which is what READ COMMITTED gives a concurrent reader. memory.go says where each
// one stands in for what.
//
// # What the contract demands of a second implementation
//
// Two of its gates derive a class rather than checking a list, and both of them will have
// something to say to the pgx store on its first run.
//
// Every [protocol.Reason] the implementation under test can name owes a scenario. The class is
// walked from the AST — the reasons named by the functions reachable from the methods of the
// concrete type RunContract was handed — so it is per implementation and not per directory: a
// refusal only the pgx store can give, such as §6.4's REASON_RATE_LIMITED on `lock_timeout`,
// belongs to the pgx run and is invisible to the memory one. It is not enough to answer the
// refusal; there has to be a scenario, because the scenario is what asserts that the refusal
// allocated nothing.
//
// Every error sentinel declared beside [Store] owes one too. That class is the interface's
// rather than either implementation's, and it is read out of this package's own source, so a
// sentinel added tomorrow fails the next run by name.
//
// May import: jackc/pgx/v5, this module's redact and metrics, and github.com/urnetwork/server
// (root package only) for the vault and config resource loading of §10.2. Never
// github.com/urnetwork/server/model: that package is the operator's account identity layer,
// and a store that can reach it will eventually join against it. Every identifier crossing
// this boundary is one of the opaque types in redact, and it is unwrapped here explicitly —
// §11.2 gives the pgx encoding path that makes a named []byte type write the literal bytes
// `<redacted>` into a primary key. Until redact holds those types the identifiers here are
// plain []byte, and the swap is a change to this package's signatures and to nothing else.
//
//urmsg:mayimport redact metrics
package store
