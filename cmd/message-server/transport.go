package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// How this process obtains the `*connect.Client` that [peer.Config] requires, and what it
// connects that client to.
//
// # The answer, which is not "it listens"
//
// The message server binds no socket for message traffic and cannot. `connect` has no inbound
// listener for client frames: the only two ways a `connect.Client` ever receives one are an
// in-process `connect.Route` — which is what `stack_test.go` wires between two clients in one
// test binary — and a [connect.PlatformTransport], which DIALS OUT to the operator's platform at
// `wss://connect.<operator_host>` and receives frames the platform routes to this client_id.
// There is no third, and this is the measurement rather than an impression. At `connect` 27c50c2,
//
//	grep -rlnE 'net\.Listen|websocket\.Upgrader|http\.Server\{' --include=*.go . | grep -v _test
//
// returns five files and not one of them accepts a peer: egress.go:40 is a comment about a
// net.Dialer Control callback; ip_mux_upgrade.go:337 is the provider-side DNS/TCP listener inside
// the IP mux; transport.go:1423 is a local UDP socket for QUIC's own client side; tun.go:965 is
// gonet.ListenTCP inside the userspace netstack; and extender/extender.go is the extender, a
// separate relay program that is not the client transport.
//
// So §9.1's sentence is literal: *"Each instance runs a `connect.Client` against the platform
// transport exactly as any client does."* The message server is a client of the URnetwork mesh in
// exactly the way a VPN provider is. A client finds it by `message_server_id` — §9.3's discovery
// answers that id — and the platform routes to it. Spec A §9.3's `network_space_host` and
// `message_server_id` are the CLIENT's two settings for this, and they are the mirror of the two
// values here: this server's `operator_host` is the host a client's `network_space_host` must
// resolve the fleet through, and this replica's `client_id` is the `message_server_id` a client
// addresses.
//
// # What that requires, and what nothing in this repository can produce
//
// A `connect.Client` on the platform transport needs a `ByJwt` for a `network_client` on that
// operator. §9.1 says where it comes from: *"An admin **of that operator** creates the network
// once and one `network_client` per **ordinal**"*, and the credential is the per-ordinal entry in
// `message_server.yml`. That is an operator-admin action against a running URnetwork operator,
// and neither this module nor `connect` can perform it: `connect.BringYourApi.AuthNetworkClient`
// mints a client credential, but it authenticates with a USER credential that this process is
// never given and that §9.2 is explicit an operator issues.
//
// This is the finding, and it is the whole of it. Everything else in the startup path — config,
// pool, migrations, store, api, peer, health, shutdown — runs against an empty database on a bare
// box. The transport does not, and it does not for a reason no amount of code here changes.
//
// # What this build does about it
//
// Builds the whole path and refuses loudly when the credential is absent. There is no fallback
// client and no loopback mode: a `connect.Client` with no transport receives nothing, forever,
// while `peer` runs eight workers and a sweep loop behind it and every counter reads zero — which
// is indistinguishable at a glance from a server nobody has messaged yet. So without a credential
// this process constructs no client and no peer at all, `/readyz` refuses on
// `ordinal_credential`, and the startup log says in one line that no message traffic will be
// served.

// The platform this replica attaches to, and the client it attaches with.
type attachment struct {
	client    *connect.Client
	transport *connect.PlatformTransport
	strategy  *connect.ClientStrategy
	cancel    context.CancelFunc

	platformUrl string
	apiUrl      string
}

var errNoCredential = errors.New("this ordinal has no transport credential, so there is no URnetwork client to receive frames on (§9.1)")

// §9.3's two service URLs for an operator host.
//
// `https://api.<host>` and `wss://connect.<host>`, which is what `sdk`'s `ServiceUrl` produces for
// the `main` environment and is the shape every URnetwork client uses. It is derived here rather
// than imported because §2.2 forbids this module from importing `sdk` at all — the derivation is
// two `fmt.Sprintf`s and the alternative is a forbidden dependency.
//
// A non-`main` environment — `sdk` spells those `<env>-api.<host>` — is not expressible, because
// §10.2's `message.yml` has one host key and no environment key. That is a gap and not a choice;
// see the ledger.
func serviceUrls(operatorHost string) (apiUrl string, platformUrl string, err error) {
	host := strings.TrimSpace(operatorHost)
	if host == "" {
		return "", "", errNoOperatorHost
	}
	if strings.ContainsAny(host, "/:? ") {
		return "", "", fmt.Errorf("%w: operator_host is a bare host name such as `ur.network`, not a URL", errBadOperatorHost)
	}
	return "https://api." + host, "wss://connect." + host, nil
}

var (
	errNoOperatorHost  = errors.New("operator_host is unset, and it is the host every service URL is derived from (§9.1)")
	errBadOperatorHost = errors.New("operator_host is not a bare host name")
)

// Stand up this replica's URnetwork client and attach it to the operator's platform.
//
// Construction does not block on the network and must not: [connect.NewPlatformTransport] starts
// a run loop that dials, backs off and re-dials for the life of the context, so a platform that
// is unreachable at startup is a replica that comes up, refuses readiness on
// `connect_client_attached`, and attaches when the platform returns. A startup that waited would
// instead crash-loop through a transient outage.
func attachToPlatform(ctx context.Context, deploy deployment, loaded configuration) (*attachment, error) {
	if deploy.byJwt == "" {
		return nil, errNoCredential
	}
	apiUrl, platformUrl, err := serviceUrls(loaded.operatorHost)
	if err != nil {
		return nil, err
	}

	attached, cancel := context.WithCancel(ctx)
	strategy := connect.NewClientStrategyWithDefaults(attached)
	// the out-of-band control plane: §9.1's contracts are provider-terminated and long-lived per
	// (device, message server), and this is the path that creates and closes them. It is the API
	// form and not connect.NewNoContractClientOob, which is what the in-process fixture uses and
	// which would make this replica serve every client for free and account for nothing
	oob := connect.NewApiOutOfBandControl(attached, strategy, deploy.byJwt, apiUrl)

	settings := connect.DefaultClientSettings()
	client := connect.NewClient(attached, deploy.clientId, oob, settings)

	transportSettings := connect.DefaultPlatformTransportSettings()
	transport := connect.NewPlatformTransport(
		client.Ctx(),
		strategy,
		client.RouteManager(),
		platformUrl,
		&connect.ClientAuth{
			ByJwt:      deploy.byJwt,
			InstanceId: connect.NewId(),
			AppVersion: version,
		},
		transportSettings,
	)

	// WITHOUT THIS THE PLATFORM DELIVERS NOTHING AND THE PROCESS LOOKS HEALTHY.
	//
	// Measured on the first real deployment: the client attached, `/readyz` answered `ready`,
	// the probe's Hello was sent, and the server's log recorded no incoming frame at all --
	// only its pool statistics. A `connect.Client` accepts a peer's frames only for a provide
	// mode its contract manager has enabled, and this process enabled none.
	//
	// `Public` rather than `Network`: §9.1 gives this replica its own account on the operator,
	// and every USER holds their own separate account, so a client reaching this server is
	// never on its network. `Network` would accept only frames from the server's own network,
	// which contains nothing but the server.
	//
	// `Stream` comes with it because a request is only half of §4.3: the response is this
	// process SENDING to a client it did not contract with, and that is return traffic.
	client.ContractManager().SetProvideModesWithReturnTraffic(map[protocol.ProvideMode]bool{
		protocol.ProvideMode_Public: true,
	})

	return &attachment{
		client:      client,
		transport:   transport,
		strategy:    strategy,
		cancel:      cancel,
		platformUrl: platformUrl,
		apiUrl:      apiUrl,
	}, nil
}

// Whether the platform transport currently holds a connection with routes registered.
//
// This is §10.1's "connect client attached", and it is the transport's own counter rather than
// anything this file tracks: `registeredCount` is incremented when a connection registers routes
// on the route manager and decremented when it stops, so it answers "can a frame reach this
// replica right now" and not "did a dial once succeed".
func (self *attachment) attached() bool {
	return self != nil && self.transport != nil && self.transport.IsConnected()
}

// Close the transport and the client, in that order.
func (self *attachment) Close() {
	if self == nil {
		return
	}
	if self.transport != nil {
		self.transport.Close()
	}
	if self.client != nil {
		self.client.Close()
	}
	if self.cancel != nil {
		self.cancel()
	}
}
