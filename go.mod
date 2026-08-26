module github.com/urnetwork/message-server

go 1.26.5

// The siblings are checked out beside this repository and built from the working tree, the
// way every other urnetwork go module in this workspace is wired. Neither is required yet,
// because nothing in this module imports either one: a require for a module no package
// imports is the first step toward a dependency rule that describes nothing, and deps_test.go
// is the second half of that argument. The require lands with the first import.
//
// glog is replaced even though this module never names it, because connect requires
// github.com/urnetwork/glog v0.0.0 — a version no proxy serves — and a replace in a
// dependency's go.mod is ignored. Only the main module's replaces apply, so connect is
// unbuildable from here without this line.
replace github.com/urnetwork/connect => ../connect

replace github.com/urnetwork/glog => ../glog
