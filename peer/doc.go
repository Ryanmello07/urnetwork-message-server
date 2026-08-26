// The connect client wiring: the instance's own URnetwork session, the frame dispatch that
// turns a `MessageMessageServerRequest` into a call on api, and the fragmentation of spec B
// §4.6 that a response too large for one frame is carried in.
//
// This package holds no code yet. It is here as a directory because the dependency gate at
// the root of the module walks what `go list` reports for `./...`, and a package that does
// not exist is one the gate cannot read — spec B §2.1 fixes the layout, so the layout is
// created before the code that fills it rather than as a side effect of the first commit
// that needs it.
//
// May import: github.com/urnetwork/connect and github.com/urnetwork/connect/protocol for the
// session and the frame types, github.com/urnetwork/glog, this module's api, redact and
// metrics. Never github.com/urnetwork/server/session — the frame's `client_id` is the whole
// of the identity this process is entitled to, and §5.2 is the argument for why.
package peer
