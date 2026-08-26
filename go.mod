module github.com/urnetwork/message-server

go 1.26.5

// The siblings are checked out beside this repository and built from the working tree, the
// way every other urnetwork go module in this workspace is wired. connect is required as of
// the first import of it: store names the Reason codes of spec B §4.5, whose generated Go
// lives in connect/protocol, so that the refusal vocabulary the API layer hands to clients and
// the one the store answers with are one enum rather than two that have to be translated.
//
// google.golang.org/protobuf comes with it and is indirect. Nothing in this module names it;
// connect/protocol is generated code and does not compile without the runtime it is generated
// against, which is why §2.2's allow list gains it in deps_test.go rather than here.
//
// glog is replaced even though this module never names it, because connect requires
// github.com/urnetwork/glog v0.0.0 — a version no proxy serves — and a replace in a
// dependency's go.mod is ignored. Only the main module's replaces apply, so connect is
// unbuildable from here without this line.
replace github.com/urnetwork/connect => ../connect

replace github.com/urnetwork/glog => ../glog

require github.com/urnetwork/connect v0.0.0

require google.golang.org/protobuf v1.36.11 // indirect
