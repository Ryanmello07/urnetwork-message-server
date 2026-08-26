// The request handlers of spec B §4.3, one file per operation, and the `write_auth` and
// `req_auth` verification of §5.1 that every one of them runs first.
//
// This package holds no code yet; §2.1 fixes the layout and the layout is created before the
// code that fills it, so that the dependency gate at the root of the module reads a tree that
// matches the spec rather than a tree that matches whatever landed first.
//
// May import: github.com/urnetwork/connect/message for the record parser and the four
// preimages a record is authenticated by — this module never re-derives what that package
// already computes — plus this module's store, blobd, redact and metrics. Never
// github.com/urnetwork/connect/mls: §5.3 is normative that this binary links no MLS
// implementation, and the moment one is in the process "just validate the commit" is a
// one-line change.
package api
