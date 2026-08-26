package peer

import (
	"context"
	"slices"

	"github.com/urnetwork/connect/protocol"
	"google.golang.org/protobuf/proto"
)

// §4.3.1: capability advertisement, and the issuance of this connection's `server_nonce`.
//
// Hello is the only operation that carries no authenticator of any kind — spec A §5.7 lists it
// first under "NOT used on", because it "names no group, and is where server_nonce is issued".
// What bounds it is that it costs one CSPRNG read and one map write, touches no group state, and
// reads no database: an unauthenticated party who can address a frame here can make this server
// mint nonces for its own client_id and nothing else.
//
// It opens a connection, which ends the previous one for this client_id. That is the whole of
// the nonce rotation this design has, and [Connections] is where the argument for it is written.
func (self *Peer) hello(ctx context.Context, arrived *inbound, request *protocol.HelloRequest) (protocol.Reason, *protocol.HelloResponse, error) {
	// §4.3.1 negotiates before it issues. A client that does not name the version this server
	// speaks gets no nonce and no connection: issuing one would leave a connection open under a
	// protocol neither side agreed on, and the client cannot use it for anything anyway.
	//
	// An empty list is refused with the same code. `supported_versions` is repeated and the
	// client fills it; a Hello that names nothing has not negotiated, and treating "said
	// nothing" as "said whatever this server speaks" is how a version gate stops being one.
	if !slices.Contains(request.GetSupportedVersions(), self.protocolVersion) {
		return protocol.Reason_REASON_UNSUPPORTED_VERSION, nil, nil
	}

	connection, err := self.connections.Open(arrived.clientId)
	if err != nil {
		// the only way here is a CSPRNG that would not fill 32 bytes. Answering REASON_OK with a
		// short nonce would be answering with a nonce an attacker can enumerate
		return protocol.Reason_REASON_INTERNAL, nil, err
	}
	arrived.connection = connection

	// the advertisement is cloned on the way out. Capabilities is one value held for the life of
	// the process, and a response that aliased it would put every client's copy one marshaling
	// bug away from the server's own limits
	capabilities, _ := proto.Clone(self.capabilities).(*protocol.Capabilities)
	return protocol.Reason_REASON_OK, &protocol.HelloResponse{
		ProtocolVersion: self.protocolVersion,
		ServerId:        append([]byte(nil), self.serverId...),
		ServerTimeMs:    uint64(self.now().UnixMilli()),
		ServerNonce:     connection.ServerNonce(),
		Capabilities:    capabilities,
		// ServerKeys and KtGossip are absent, and [unsignedHello] declares why: §9.1 decision
		// B13 keeps every signing key off every replica, so there is nothing here to sign a key
		// chain with and nothing that observed an operator STH. `client_epoch_hint` is read by
		// nothing: §4.3.1 calls it an opaque cache pre-warm, and this build has no cache to warm
	}, nil
}
