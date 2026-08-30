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

require (
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/pion/datachannel v1.6.2 // indirect
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/ice/v4 v4.4.1 // indirect
	github.com/pion/interceptor v0.1.47 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.17 // indirect
	github.com/pion/rtp v1.10.5 // indirect
	github.com/pion/sctp v1.11.1 // indirect
	github.com/pion/sdp/v3 v3.0.19 // indirect
	github.com/pion/srtp/v3 v3.0.13 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v4 v4.1.0 // indirect
	github.com/pion/turn/v5 v5.0.12 // indirect
	github.com/pion/webrtc/v4 v4.2.18 // indirect
	github.com/quic-go/quic-go v0.61.0 // indirect
	github.com/urnetwork/glog v0.0.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20260727155853-b88d891fe743 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260805230438-8eba670122c5 // indirect
	src.agwa.name/tlshacks v0.0.4 // indirect
)
