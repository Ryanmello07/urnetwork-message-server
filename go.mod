module github.com/urnetwork/message-server

go 1.26.5

// The siblings are checked out beside this repository and built from the working tree, the
// way every other urnetwork go module in this workspace is wired. connect is required as of
// the first import of it: store names the Reason codes of spec B §4.5, whose generated Go
// lives in connect/protocol, so that the refusal vocabulary the API layer hands to clients and
// the one the store answers with are one enum rather than two that have to be translated.
//
// google.golang.org/protobuf arrived with connect as an indirect dependency and is now a direct
// one. api names it: §4.3.8's `canonical_request_bytes` is a deterministic marshal, §4.3.8's `op`
// is a field number read out of the compiled descriptor rather than written down, and §5.1
// check 3 compares the request's projection with the parse as one message rather than as a list
// of fields to forget one from. §2.2 does not print it and deps_test.go writes it down with the
// reason: §2.2 allows connect/protocol, connect/protocol is protoc-gen-go output, and allowing
// generated code while refusing the runtime it was generated against allows a package that
// cannot be built.
//
// glog is replaced even though this module never names it, because connect requires
// github.com/urnetwork/glog v0.0.0 — a version no proxy serves — and a replace in a
// dependency's go.mod is ignored. Only the main module's replaces apply, so connect is
// unbuildable from here without this line.
replace github.com/urnetwork/connect => ../connect

replace github.com/urnetwork/glog => ../glog

require (
	github.com/urnetwork/connect v0.0.0
	google.golang.org/protobuf v1.36.11
)
