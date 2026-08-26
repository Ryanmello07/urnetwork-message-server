package peer

import (
	"context"
	"errors"
	"slices"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
)

var (
	ErrNoConnections    = errors.New("peer: §5.1 check 2 resolves a connection, so the checks and the peer have to share one registry to resolve it from")
	ErrNoRequestBytes   = errors.New("peer: §5.1 check 1 is a bound, and a bound of zero or less refuses every request this server could ever be sent")
	ErrCheckedElsewhere = errors.New("peer: the handler's front checks read a different connection registry than the peer that dispatches into it, so check 2 would answer about connections that are not the ones requests arrive on")
	ErrNoChecks         = errors.New("peer: §5.1 checks 1 and 2 have an owner or they are skipped silently, and the handler this peer dispatches into was built around the same one")
)

// §5.1's checks 1 and 2, as this build performs them.
//
// It is a separate type from [Peer] because api.New requires an [api.FrontChecks] before there is
// a handler, and [Peer] requires the handler. The two therefore share one of these, and
// [New] refuses a wiring where they do not: see [ErrCheckedElsewhere].
type Checks struct {
	// Check 4 is not overridden anywhere below, so it is exactly as absent as it was, answered
	// by the type api.go named for what it does not do. Embedding rather than reimplementing
	// means the day a Redis limiter lands, it lands in one place.
	api.ChecksNotImplemented

	connections     *Connections
	maxRequestBytes int
}

var _ api.FrontChecks = (*Checks)(nil)

// The checks of §5.1 this type actually performs, as opposed to the ones it declares unrun.
//
// One entry, and check 2 is deliberately not on it. Check 2 has two halves: "the connection is
// authenticated at the connect layer (`ByJwt` validated by the platform)", which decision B1
// forbids this process from verifying and which §5.1 itself calls a named dependency on the
// operator transport, and "the server knows its own connection's nonce and looks it up from the
// connection, never from the request", which this package does perform and which
// [Checks.ConnectionAuthenticated] refuses on. Listing 2 as performed would delete the standing
// declaration of the half nobody here can do, and §5.1's own paragraph is emphatic that it is a
// dependency rather than an assumption. So the half that runs runs, the entry that says what
// does not run stays, and [amendedNotBuilt] rewrites that entry to say which half is which.
var performedChecks = []int{1}

// §5.1 check 1: the frame decoded and reassembly stayed inside `max_request_bytes` (§4.6).
//
// The decode already happened — a request that did not decode never reached a handler, and never
// will, because there is nothing to dispatch. What is left for check 1 to decide is the bound,
// and it decides it here, on every request, from what the frame layer measured.
//
// A request that reached the pipeline carrying no measurement is answered REASON_INTERNAL rather
// than REASON_OK. That case cannot arise from anything a client sends: it means this package
// stopped putting the measurement in the context, and a check that cannot see its own input must
// not report a pass. "Not called" and "called and passed" being the same green test is the whole
// reason [api.FrontChecks] is an interface, and answering OK on a missing input would put that
// failure right back.
func (self *Checks) FrameWithinLimits(ctx context.Context, conn *api.Connection) protocol.Reason {
	arrived, found := inboundOf(ctx)
	if !found {
		return protocol.Reason_REASON_INTERNAL
	}
	return withinLimits(arrived.bytes, self.maxRequestBytes)
}

// §5.1 check 2, the half of it that is this process's.
//
// Three things are refused, and none of them is a claim about `ByJwt`:
//
//  1. a request that arrived on no connection at all — a client that submits before it says
//     Hello has no nonce, and §4.3.1 is where a nonce comes from;
//  2. a request whose connection has since been replaced — a re-Hello ends the previous
//     connection, and an in-flight request from it was authenticated against a nonce that no
//     longer exists anywhere in this process;
//  3. a request whose handler was handed a `server_nonce` that is not that connection's own.
//
// The third is the one worth having and the one that is not a tautology. Everything else in this
// package builds an [api.Connection] through [Connection.ApiConnection], which reads the
// connection's own nonce field; a dispatcher that started sourcing the nonce from anywhere the
// client can influence — a request field, a cache keyed on something the client chose — would
// fail here rather than verifying MACs against a value an attacker picked.
//
// REASON_REJECTED on all three, which is §5.1's own answer for check 2 and §4.5's non-specific
// refusal: whether a connection exists for a client_id is not a fact this server owes anyone.
func (self *Checks) ConnectionAuthenticated(ctx context.Context, conn *api.Connection) protocol.Reason {
	arrived, found := inboundOf(ctx)
	if !found || arrived.connection == nil || conn == nil {
		return protocol.Reason_REASON_REJECTED
	}
	if !self.connections.IsLive(arrived.connection) {
		return protocol.Reason_REASON_REJECTED
	}
	if !arrived.connection.Holds(conn.ServerNonce) {
		return protocol.Reason_REASON_REJECTED
	}
	return protocol.Reason_REASON_OK
}

// What §5.1 says this build still does not do.
//
// Derived from [api.ChecksNotImplemented]'s own list rather than retyped: every entry it carries
// is dropped if this type performs that check, amended if this type performs part of it, and
// otherwise passed through untouched. A fourth front check added to api tomorrow arrives here
// declared, which is the direction that cannot understate the gap.
func (self *Checks) NotBuilt() []api.NotBuilt {
	notBuilt := []api.NotBuilt{}
	for _, entry := range self.ChecksNotImplemented.NotBuilt() {
		if slices.Contains(performedChecks, entry.Check) {
			continue
		}
		notBuilt = append(notBuilt, amendedNotBuilt(entry))
	}
	return notBuilt
}

// Check 2's declaration, rewritten to say which half of it this package performs.
//
// api's text is written for a build with no transport at all, where the whole of check 2 is
// missing. Here the nonce half runs and the `ByJwt` half cannot, and an entry that said only
// "not run" would be read by §10.1's readiness endpoint as more missing than there is — while an
// entry that said "run" would delete decision B1's named dependency from the one list an
// operator reads. Every other entry passes through unchanged.
func amendedNotBuilt(entry api.NotBuilt) api.NotBuilt {
	if entry.Check != 2 {
		return entry
	}
	entry.What = "the connect layer's ByJwt authentication of source.SourceId. peer performs check 2's other half — a request is served only on a connection this server opened, and the server_nonce a handler verifies against is that connection's own and never the request's — but whether the platform authenticated source.SourceId is decision B1's named dependency and cannot be checked in this process"
	entry.Owner = "the operator transport, through connect"
	return entry
}

// What the frame layer measured about the request now being served, and the connection it
// arrived on.
//
// It travels in the context because [api.FrontChecks] is handed a connection and nothing else,
// and check 1 is a fact about a frame. It is request-scoped by construction — one value per
// dispatched request, never stored, never shared — which is what a context value is for.
type inbound struct {
	// The platform-authenticated `source.SourceId` of §5.1 check 2, as connect handed it to the
	// receive callback. It is the only identity an arriving frame has — see [Connections].
	clientId connect.Id

	connection *Connection

	// The reassembled request's byte count: check 1's input, and §4.6's cap is over the
	// reassembly rather than over any one frame.
	bytes int

	// How many frames carried it. One for an unfragmented request.
	fragments int
}

type inboundKey struct{}

func withInbound(ctx context.Context, arrived *inbound) context.Context {
	return context.WithValue(ctx, inboundKey{}, arrived)
}

func inboundOf(ctx context.Context) (*inbound, bool) {
	arrived, found := ctx.Value(inboundKey{}).(*inbound)
	return arrived, found && arrived != nil
}

func NewChecks(connections *Connections, maxRequestBytes int) (*Checks, error) {
	if connections == nil {
		return nil, ErrNoConnections
	}
	if maxRequestBytes <= 0 {
		return nil, ErrNoRequestBytes
	}
	return &Checks{connections: connections, maxRequestBytes: maxRequestBytes}, nil
}
