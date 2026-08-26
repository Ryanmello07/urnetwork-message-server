// The connect client wiring: the instance's own URnetwork session, the frame dispatch that
// turns a `MessageMessageServerRequest` into a call on api, and the fragmentation of spec B
// §4.6 that a request or a response too large for one frame is carried in.
//
// This is the outermost layer of a network service. Everything that arrives here was chosen by
// whoever addressed the frame, so every path through this package answers a refusal or drops
// the frame; none of them panics, and none of them lets a client choose a value the checks of
// §5.1 are computed over. The two front checks §5.1 numbers 1 and 2 live here, and check 4
// stays exactly as absent as it was — [api.ChecksNotImplemented] still owns it and still says
// so out loud.
//
// It also owns the one thing connect does not give us: a *connection*. See [Connections] for
// what was looked for in connect, what is actually there, and why a connection here is one
// Hello epoch of a client_id.
//
// May import: github.com/urnetwork/connect and github.com/urnetwork/connect/protocol for the
// session and the frame types, github.com/urnetwork/glog, this module's api, redact and
// metrics. Never github.com/urnetwork/server/session — the frame's `client_id` is the whole
// of the identity this process is entitled to, and §5.2 is the argument for why.
//
//urmsg:mayimport api redact metrics
package peer
