// A client of this server for this repository's own tests: the smallest thing that can say the
// four operations of §4.3 over a [connect.Client] and correlate what comes back.
//
// # This is a harness, and it is not a product client
//
// Spec A §7's `MessageClient` in the sdk is the product surface — the thing a phone runs, with
// the MLS key schedule under it, an outbox, a cache, a reconnect policy and a user to answer to.
// None of that is here and none of it is coming here. What this package is for is that a server
// integration test needs the *other end of the wire* to exist in the same process: something
// that puts a §4.2 frame on a connect route, waits for the frame that answers it, and can be
// asked afterwards how many frames that took. A test written against the api layer directly
// proves that a record survives a function call; the value of this package is that it does not
// let a test do that.
//
// Three things follow from being a harness rather than a client, and each is a deliberate
// absence:
//
//   - **It does not encrypt.** `ct_head` and `ct_body` are opaque octets the caller hands in and
//     the caller gets back. The MLS key schedule that produces real content keys is plan p4 and
//     is absent, not stubbed — there is no cipher here, no test key schedule, and no name
//     suggesting this path is confidential. What it is is authenticated, addressed and durable
//     transport for opaque bytes, which is the whole of the claim.
//   - **It holds no keys of its own.** The epoch write key and read key are arguments. A harness
//     that derived them would be deriving them from a schedule that does not exist.
//   - **It does not import testing.** Every refusal is an error or a [protocol.Reason] returned
//     to the caller. A harness that could call t.Fatalf would be a harness that ends a test from
//     a goroutine it does not own, which is the one thing the concurrency tests below cannot
//     have.
//
// What it does implement, and each of them because the wire requires it of any client: §4.3.1's
// Hello and the `server_nonce` every later authenticator is computed against, spec A §5.2's
// sealing order and §5.4's `write_auth`, §4.3.8's `req_auth` over the canonical request bytes,
// §4.6's fragmentation in both directions, and the `request_id` correlation that is the only
// thing a client can correlate two concurrent requests by.
//
// Nothing this module builds imports this package outside a test binary, and that is a gate
// rather than a convention — TestTheHarnessIsReachedOnlyFromTests in deps_test.go derives it
// from the module's own import graph.
//
// May import: github.com/urnetwork/connect and its protocol and message packages, and this
// module's store for the identifier widths, blobd for §8.3's content hash, and peer for §4.6's
// part size. The last three are all "the one place this number is written" rather than
// convenience: a client that carried its own copy of the sender-handle width, of SHA-256 over a
// body, or of §4.6's 2048 would be a second implementation that agrees until one of them is
// edited, which is the failure §12.1 A-1 is written against.
//
//urmsg:mayimport store blobd peer
package harness
