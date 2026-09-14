package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/peer"
	"github.com/urnetwork/message-server/store"
)

// The process of spec B §2.3, assembled.
//
// Startup order is the whole of this file and it is not arbitrary: everything that can fail
// without a database fails before the pool is opened, everything the pool needs is asserted
// before the store is built on it, and the connect client — the one collaborator that reaches the
// public internet — is attached last, after there is something behind it to serve with.
type server struct {
	config configuration
	deploy deployment
	log    *slog.Logger

	pool     *pgxpool.Pool
	records  *store.PgxStore
	handler  *api.Handler
	dispatch *peer.Peer

	// §4.2's connection table and §5.1's front checks, which [peer.New] is given and which the
	// handler above was built against. Kept because they are this process's, and because a
	// replica with no credential builds no peer — so these are the only handles to them.
	connections *peer.Connections
	checks      *peer.Checks

	attachment *attachment

	// Where "is the transport carrying traffic right now" is read from.
	//
	// A seam, for the same reason peer's clock and ticker are seams: the only production answer
	// is [connect.PlatformTransport]'s own registration count, and the only way to make that
	// answer true is to dial the operator's platform. A readiness set whose one transport
	// precondition can never be observed met in a test is a precondition nothing exercises.
	attached func() bool

	// The slack [store.CheckClockSkew] is given, as a field rather than the constant, so that the
	// clock_skew precondition can be observed REFUSING. Its failure is the one a test cannot
	// arrange by withholding configuration: it needs a database whose wall clock disagrees with
	// this process, and the only way to have one without moving a machine's clock is to narrow
	// the tolerance. Zero takes [clockSlack].
	//
	// clock_utc needs no such device. Its failure IS arrangeable — a DSN that asks for a session
	// zone that is not UTC produces exactly the cluster §3.1 forbids — which is the difference
	// between a check that can be observed doing its job and the one this replaced.
	clockSlack time.Duration

	ready    *readiness
	health   *http.Server
	listener net.Listener

	closed chan struct{}
}

// How long a shutdown is allowed to take before this process stops waiting and exits anyway.
//
// §10.1 sets `terminationGracePeriodSeconds = 90` "matched to the 60 s drain window (§2.3)". This
// is not that window — §2.3's drain is not built, and [configurationNotWired] says so — it is the
// bound on the teardown itself, kept well inside 90 s so that a replica stuck on a wedged
// database is killed by this rather than by SIGKILL with no log line.
const shutdownTimeout = 20 * time.Second

// §4.3.1's version. "URmessage/v1" is the domain-separation prefix of every preimage in spec A
// §5.7 and spec B §4.3.1, so the wire protocol this build speaks is version 1.
const protocolVersion = 1

// §3.1's skew assertion, with the slack store.CheckClockSkew takes.
const clockSlack = 30 * time.Second

var (
	errNoKek      = errors.New("no write_key_kek is configured, so §5.5 has nothing to wrap an epoch key under")
	errNoServerId = errors.New("no server_id is configured, and §4.3.1 advertises one in every HelloResponse")
)

// Build every collaborator this process serves with, in dependency order.
//
// A failure here is a failure to start. What is NOT a failure to start is a collaborator that is
// merely absent — no credential, no KEK, migrations behind — because §10.1's readiness endpoint
// exists so that a replica can come up, say what it is missing, and be looked at. The line
// between the two is: this process cannot serve without a database, and it can run without
// anything else for long enough to tell somebody why.
func newServer(ctx context.Context, deploy deployment, loaded configuration, log *slog.Logger) (*server, error) {
	self := &server{
		config: loaded,
		deploy: deploy,
		log:    log,
		closed: make(chan struct{}),
	}

	pool, err := store.NewPgxPool(ctx, deploy.dsn)
	if err != nil {
		// pgxpool.ParseConfig puts the DSN in its error and the DSN carries a password
		return nil, errors.New("the pg.yml DSN did not parse, or a pool could not be created from it")
	}
	self.pool = pool

	// §5.5's KEK ring. Absent is survivable-to-start and refused at readiness: a replica with no
	// KEK can answer Hello and Fetch on a group whose keys were wrapped by another, and cannot
	// open an epoch — so it must not take traffic, and it must be able to say so.
	var keys *store.KekRing
	if deploy.kek != nil {
		keys, err = store.NewKekRing(deploy.kekId, deploy.kek)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("%s: write_key_kek: %w", fleetResource, err)
		}
	}

	self.clockSlack = clockSlack
	self.records = store.NewPgxStore(pool, limitsOf(loaded), keys)

	connections, err := peer.NewConnections(rand.Reader, time.Now, time.Hour)
	if err != nil {
		pool.Close()
		return nil, err
	}
	checks, err := peer.NewChecks(connections, peer.DefaultMaxRequestBytes)
	if err != nil {
		pool.Close()
		return nil, err
	}
	// The process's own §4.2 collaborators, kept as fields rather than dropped as locals.
	//
	// peer.New takes both, and when there is no credential there is no peer.New call to take them
	// — so without these the connection table and the front checks THIS handler was built with
	// would be unreachable from outside [newServer], and a test could only reach the wiring below
	// by building a copy of it. A copy is exactly what the restart defect hid behind: everything
	// downstream of this file was correct, and the one line that named the filter was not.
	self.connections = connections
	self.checks = checks

	// §5.1 check 5's filter, read from where the truth is.
	//
	// It is [api.NewStoreKnownGroups] and not [api.NewMemoryKnownGroups], and the difference is
	// the difference between a replica that can be restarted and one that cannot. The memory
	// filter's only writer is a CreateGroup that committed in this process, so a restart empties
	// it: every group made before the restart is answered REASON_REJECTED, §4.5 makes that
	// indistinguishable from a bad MAC, and — because the rows are all still in Postgres and the
	// pool still answers — every precondition below is met and `/readyz` answers `ready` the
	// whole time. This process has a store; the filter reads it.
	//
	// What the substitution costs is declared by [api.NewStoreKnownGroups]'s own NotBuilt entry,
	// which reaches §10.1's endpoint through [server.notBuilt]. That entry is as much the point
	// as the wiring is: the per-process map was on no NotBuilt list and in no ops document, and a
	// list that claims to be complete and is not is worse than no list.
	self.handler, err = api.New(api.Config{
		Store:       self.records,
		KnownGroups: api.NewStoreKnownGroups(self.records),
		Front:       checks,
	})
	if err != nil {
		pool.Close()
		return nil, err
	}

	// The connect client, and the one place this process reaches the public internet. Absent
	// unless every input an attachment needs is present, and absent means absent — see
	// transport.go for why there is no client-with-no-transport fallback.
	if canAttach(deploy, loaded) {
		self.attachment, err = attachToPlatform(ctx, deploy, loaded)
		if err != nil {
			pool.Close()
			return nil, err
		}
		self.dispatch, err = peer.New(peer.Config{
			Client:          self.attachment.client,
			Handler:         self.handler,
			Connections:     connections,
			Checks:          checks,
			Capabilities:    self.capabilities(),
			ServerId:        self.deploy.serverId,
			ProtocolVersion: protocolVersion,
		})
		if err != nil {
			self.attachment.Close()
			pool.Close()
			return nil, err
		}
	}

	self.attached = self.attachment.attached
	self.ready = &readiness{
		preconditions: self.preconditions(),
		notBuilt:      self.notBuilt(),
	}
	return self, nil
}

// The three inputs an attachment needs, all of which /readyz refuses on individually.
//
// It is a function over the two configurations rather than a method, so that the gate in
// [newServer] and the reason [attachToPlatform] would refuse cannot drift apart: what is
// checked here is exactly what that function checks, and a deployment missing any of them
// produces no client and a named refusal instead of a startup failure. §10.1's endpoint is the
// design for this — a replica comes up, says what it is missing, and is looked at.
func canAttach(deploy deployment, loaded configuration) bool {
	if deploy.byJwt == "" || len(deploy.serverId) != serverIdBytes {
		return false
	}
	_, _, err := serviceUrls(loaded.operatorHost)
	return err == nil
}

// §4.3.1's advertisement, from §10.2's values, §7.3's limits and `connect/message`'s ladders.
//
// Every §10.2 value that §4.3.1 has a field for is carried here, and that is the whole point of
// loading a configuration rather than printing one: `operator_host`, `hosting_jurisdiction` and
// `read_key_window_seconds` are advertised values with no other consumer in this build, so a
// `message.yml` that reached the printed configuration and not this struct would be a
// configuration surface that changes nothing a client can see.
//
// The two byte budgets come from `peer`'s own constants because peer.New refuses a wiring where
// the number advertised and the number §5.1 check 1 enforces differ, and §10.2's `message.yml`
// has no key for either — so a value here would be a third number to disagree with the other two.
// That is ledger item 197 and not a decision taken here. The retention limits are read off the
// same [store.Limits] the store was built with, rather than out of the configuration a second
// time, so what is advertised and what §7.3 clamps against are one value.
//
// `capability_version` is deliberately zero: §10.2 makes it monotonic and bumped on every reload
// of `message.yml`, this build does not watch the file, and a 1 here would advertise a version
// that never changes as though it did. `attestation_supported` is left false because §9.1 keeps
// every signing key off every replica and this build has no sidecar to reach.
func (self *server) capabilities() *protocol.Capabilities {
	limits := limitsOf(self.config)
	return &protocol.Capabilities{
		MaxRequestBytes:            peer.DefaultMaxRequestBytes,
		MaxResponseBytes:           peer.DefaultMaxResponseBytes,
		MaxRecordsPerSubmit:        api.DefaultMaxRecordsPerSubmit,
		MaxRecordsPerFetch:         api.DefaultMaxRecordsPerFetch,
		MediaTtlDefaultSeconds:     limits.MediaTtlDefaultSeconds,
		MediaTtlMaxSeconds:         limits.MediaTtlMaxSeconds,
		DurableRetentionMinSeconds: limits.DurableRetentionMinSeconds,
		DurableTtlDefaultSeconds:   limits.DurableTtlDefaultSeconds,
		DurableTtlMaxSeconds:       limits.DurableTtlMaxSeconds,
		OperatorHost:               self.config.operatorHost,
		HostingJurisdiction:        self.config.hostingJurisdiction,
		ReadKeyWindowSeconds:       uint32(self.config.readKeyWindowSeconds),
		EphBucketSeconds:           ephBucketLadder(),
		SizeBucketBytes:            sizeBucketLadder(),
	}
}

// §4.3.1's `size_bucket_bytes`, walked out of `connect/message` rather than written down here.
//
// Neither ladder exports a length. Both accessors answer a NEGATIVE for a rung that is not on the
// ladder, which IS the boundary, so walking until the answer goes negative derives the ladder from
// the package that owns it — and a rung added to `connect/message` tomorrow arrives here
// advertised instead of being a fifth copy of a list that is now wrong.
//
// The alternative, a literal `[]uint32{256, 1024, 4096, 16384, 65536}`, is a second copy of a
// ladder §5.1 check 3 enforces as an EQUALITY. The two would agree on the day they were written
// and the disagreement would surface as one size of record being refused.
func sizeBucketLadder() []uint32 {
	var ladder []uint32
	for bucket := 0; bucket <= 255; bucket++ {
		bytes := message.SizeBucketBytes(message.SizeBucket(bucket))
		if bytes < 0 {
			return ladder
		}
		ladder = append(ladder, uint32(bytes))
	}
	return ladder
}

// §4.3.1's `eph_bucket_seconds`, walked the same way.
//
// Bucket 0's answer is ZERO and not negative — the transient rung is never persisted, so nought
// seconds is its true window — which is why the walk stops on a negative and not on a zero. That
// distinction was ruled 2026-09-13 (m1 open item M1-27); before it, bucket 0 and a bucket that is
// no bucket both answered -1, and this function would have advertised an empty ladder.
func ephBucketLadder() []uint32 {
	var ladder []uint32
	for bucket := 0; bucket <= 255; bucket++ {
		seconds := message.EphBucketSeconds(uint8(bucket))
		if seconds < 0 {
			return ladder
		}
		ladder = append(ladder, uint32(seconds))
	}
	return ladder
}

// §10.1's readiness set, in the order §10.1 states it, plus the two §9.1 adds.
func (self *server) preconditions() []precondition {
	return []precondition{
		{
			name:          "database_reachable",
			needsDatabase: true,
			why:           "the message-server Postgres cluster did not answer; check pg.yml's DSN and the cluster (§2.3, decision B10)",
			met: func(ctx context.Context) error {
				return self.pool.Ping(ctx)
			},
		},
		{
			name:          "migrations_at_head",
			needsDatabase: true,
			why:           "run `messagectl migrate` against this database; §10.3 forbids a replica migrating at startup, so this refuses until the job has run",
			met: func(ctx context.Context) error {
				head, missing, err := store.MigrationsAtHead(ctx, self.pool)
				if err != nil {
					return err
				}
				if !head {
					return fmt.Errorf("migration %d of %d has not run", missing, store.MigrationCount())
				}
				return nil
			},
		},
		{
			// §3.1, and §13 item 21: "/readyz fails on a cluster whose timezone is not UTC."
			//
			// It is a readiness precondition and NOT a startup check, which is what those two
			// sentences say and is also the stronger placement. Retention is split across two
			// clocks -- §7.1 computes prune_after in Go, §7.4 sweeps with `WHERE prune_after <=
			// now()` in the database -- so a non-UTC cluster prunes media up to fourteen hours
			// early, fleet-wide and silently, and early pruning destroys user data. A check that
			// ran once at startup could not see the case that actually produces it: a failover to
			// a streaming replica configured in another zone, which happens to a process that is
			// already running.
			//
			// It asks the DSN and not the pool, and [store.CheckClusterTimezone] is where that is
			// argued: every pooled connection has `timezone = UTC` in its startup packet, so the
			// pool is the one place in this process from which the cluster's own zone cannot be
			// seen. Under the old wiring this precondition was met on every run of a suite whose
			// cluster is `America/Phoenix` -- it was not lenient, it was blind.
			name:          "clock_utc",
			needsDatabase: true,
			why:           "the cluster's own timezone is not UTC; §3.1 makes `timezone = UTC` normative on the primary, every replica and every restore target, and §7.4 prunes against it",
			met: func(ctx context.Context) error {
				return store.CheckClusterTimezone(ctx, self.deploy.dsn)
			},
		},
		{
			// The other half of §3.1, which the check above cannot see and which the check above
			// used to be mistaken for: the two machines agree about the instant.
			//
			// A cluster correctly set to UTC whose host clock has drifted prunes early by the
			// drift, for the same reason and with the same consequence -- §7.1 reads Go's clock
			// and §7.4 reads the database's. It is a separate precondition and not a second
			// clause inside clock_utc because they fail for different reasons and send an
			// operator to different places: one is a postgresql.conf, the other is NTP.
			name:          "clock_skew",
			needsDatabase: true,
			why:           "the database's wall clock and this process's disagree by more than the allowed slack; §7.1 computes prune_after from this process's clock and §7.4 sweeps against the database's",
			met: func(ctx context.Context) error {
				return store.CheckClockSkew(ctx, self.pool, self.clockSlack)
			},
		},
		{
			name: "kek_loaded",
			why:  "message_fleet.yml has no write_key_kek; §5.5 cannot wrap an epoch key without one and no group could be created",
			met: func(ctx context.Context) error {
				if self.deploy.kek == nil {
					return errNoKek
				}
				return nil
			},
		},
		{
			name: "server_id_set",
			why:  "message_fleet.yml has no server_id; §4.3.1 advertises 16 octets stable per fleet, and a fleet that advertised zeroes would be indistinguishable from any other",
			met: func(ctx context.Context) error {
				if len(self.deploy.serverId) != serverIdBytes {
					return errNoServerId
				}
				return nil
			},
		},
		{
			name: "ordinal_credential",
			why:  "message_server.yml has no entry for this ordinal; §9.1 requires one network_client per ordinal, created by an admin of the operator named in operator_host",
			met: func(ctx context.Context) error {
				if self.deploy.byJwt == "" {
					return errNoOrdinalEntry
				}
				return nil
			},
		},
		{
			name: "connect_client_attached",
			why:  "no connection to the operator's platform holds a route; this server receives frames only over connect and binds no socket of its own for them (§9.1)",
			met: func(ctx context.Context) error {
				if self.attached == nil || !self.attached() {
					return errNotAttached
				}
				return nil
			},
		},
		{
			name: "operator_host",
			why:  "message.yml's operator_host is unset, or is not a bare host name such as `ur.network`; §9.1 makes it the operator this server holds its account on and both service URLs are derived from it",
			met: func(ctx context.Context) error {
				// the same derivation the attachment uses, rather than a non-empty test beside
				// it: `https://ur.network` is non-empty and produces `wss://connect.https://ur.network`,
				// which fails to dial with a message about a URL nobody typed
				_, _, err := serviceUrls(self.config.operatorHost)
				return err
			},
		},
		{
			name: "hosting_jurisdiction",
			why:  "message.yml's hosting_jurisdiction is unset; §4.3.1 advertises it to every client and §10.1 refuses readiness rather than advertise nothing",
			met: func(ctx context.Context) error {
				if self.config.hostingJurisdiction == "" {
					return errNoHostingJurisdiction
				}
				return nil
			},
		},
	}
}

var (
	errNotAttached           = errors.New("the platform transport holds no connection")
	errNoHostingJurisdiction = errors.New("hosting_jurisdiction is unset")
)

// Everything this build does not do, from every layer that knows it: the two configuration lists
// here, and whatever `api` and `peer` declare about themselves.
func (self *server) notBuilt() []api.NotBuilt {
	list := append([]api.NotBuilt{}, configurationNotWired...)
	list = append(list, deploymentNotWired...)
	if self.dispatch != nil {
		list = append(list, self.dispatch.NotBuilt()...)
	} else if self.handler != nil {
		list = append(list, self.handler.NotBuilt()...)
	}
	return list
}

// Bind §10.1's private port and serve the health endpoints.
//
// Bound before Serve and returned as an error, so a port that is taken is a startup failure with
// a message rather than a goroutine that dies into a log nobody reads.
func (self *server) listen() error {
	listener, err := net.Listen("tcp", self.deploy.healthAddress)
	if err != nil {
		return self.bindFailure(err)
	}
	self.listener = listener
	self.health = &http.Server{
		Handler:           healthMux(self.ready),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		defer close(self.closed)
		if err := self.health.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			self.log.Error("the health listener stopped", "error", err.Error())
		}
	}()
	return nil
}

// A failed bind, with the value §11.1 forbids taken out of it.
//
// [server.announce] omits the bind address deliberately — §11.1's MUST-NOT list says "any IP
// address", without qualifying whose, and `health.go` pays a real diagnostic cost for reading it
// that literally — and then the bind FAILURE printed it, two functions away:
//
//	message-server: §10.1's private health port: listen tcp 127.0.0.1:443: bind: Only one usage
//	of each socket address ... is normally permitted.
//
// The harm was small, which is exactly why it is worth fixing rather than arguing about: it is the
// process's own loopback address echoed back to the operator who typed it. But the rule was read
// literally enough elsewhere to cost an operator their `database_reachable` diagnosis, and a rule
// that holds in the function that pays for it and not in the function beside it is not a rule.
// This picks the literal reading, everywhere.
//
// The guarantee is derived rather than curated: the message that comes back is checked against the
// configured address and replaced wholesale if it names any part of it, so a Go release that
// reworded a bind error cannot reopen this. `*net.OpError`'s own Error() is "listen tcp <address>:
// <cause>" — the operation, the address, then the cause — so the cause alone is what is kept, and
// §11.1's MAY list permits exactly that: "error classes without identifiers".
func (self *server) bindFailure(err error) error {
	var opError *net.OpError
	if errors.As(err, &opError) && opError.Err != nil {
		err = opError.Err
	}
	if namesTheAddress(err.Error(), self.deploy.healthAddress) {
		return fmt.Errorf("%w (%s); §11.1 forbids logging the address, so it is not repeated here",
			errNotBound, healthAddressVariable)
	}
	return err
}

var errNotBound = errors.New("the configured address could not be bound")

// Whether a message contains any part of an address §11.1 forbids printing.
//
// Host and port are checked separately as well as together, because the two appear apart: a
// malformed address reaches `*net.AddrError`, whose message is "address <what was typed>: missing
// port in address". An address that will not split is treated as named rather than as safe — the
// direction that cannot understate is the only one worth defaulting to here.
func namesTheAddress(message string, address string) bool {
	if address == "" {
		return false
	}
	if strings.Contains(message, address) {
		return true
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return true
	}
	return (host != "" && strings.Contains(message, host)) || (port != "" && strings.Contains(message, port))
}

// The address §10.1's endpoints are actually on. Not the configured one: a configured port of 0
// is how a test binds without picking a number, and the two differ exactly then.
func (self *server) healthAddress() string {
	if self.listener == nil {
		return ""
	}
	return self.listener.Addr().String()
}

// §2.3's shutdown: stop taking traffic, stop dispatching, close the client, close the pool.
//
// The order is what makes it graceful. Readiness goes false FIRST, so a load balancer scraping
// /readyz stops sending here before anything is torn down. Then the peer closes, which
// unsubscribes the receive callback — no further frame can be enqueued — and waits for every
// worker to finish the request it is on, which is §2.3's "drain in-flight transactions". Only
// then is the connect client closed, because a worker still sending a response needs it. The pool
// is last, because a transaction in flight needs a connection, and the health listener is last of
// all, so the endpoint keeps answering "not ready" for as long as this takes.
//
// What is NOT here is §2.3's `Drain{reconnect_after_ms}` to every attached client. `peer` has no
// push path — there is no `MessageServerPush` anywhere in this module — so this build cannot send
// one, and [configurationNotWired] declares that rather than this comment being the only place it
// is written down.
func (self *server) Close() {
	self.ready.draining.Store(true)

	if self.dispatch != nil {
		self.dispatch.Close()
	}
	if self.attachment != nil {
		self.attachment.Close()
	}
	if self.pool != nil {
		self.pool.Close()
	}
	if self.health != nil {
		bounded, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := self.health.Shutdown(bounded); err != nil {
			self.health.Close()
		}
		<-self.closed
	}
}

// What this process logs about itself at startup: what it is, what it read, what it will run on,
// and — in one sentence an operator cannot miss — whether it will serve any message traffic at
// all.
//
// Nothing here prints a secret. [deployment.lines] prints presence and never a value, and every
// §10.2 value printed is one §4.3.1 advertises to every client.
func (self *server) announce(ctx context.Context) {
	// The bind address is NOT logged, and that is §11.1 taken literally rather than argued with:
	// its MUST-NOT list says "any IP address", without qualifying whose, and this one is the
	// process's own rather than a client's. The rule is not carved an exception here — an operator
	// configured the address and does not need it read back. §11.1's MAY list is what the rest of
	// this function prints: process lifecycle events, and the NAMES of what was read.
	self.log.Info("message-server starting",
		"version", version,
		"ordinal", self.deploy.ordinal)
	self.log.Info("readiness preconditions", "names", strings.Join(self.ready.names(), " "))
	for _, line := range self.deploy.lines() {
		self.log.Info("resource", "line", line)
	}
	for _, line := range self.config.lines() {
		self.log.Info("configuration", "line", line)
	}
	if self.attachment == nil {
		self.log.Warn("NO MESSAGE TRAFFIC WILL BE SERVED: this process has no URnetwork client. " +
			"It receives frames only over connect, which dials the operator's platform and is not a socket it can bind (§9.1). " +
			"Set message_server.yml's <ordinal>.by_jwt and message_fleet.yml's server_id, then restart.")
	} else {
		// NOT "attached". Reaching here means a connect.Client was CONSTRUCTED and a
		// platform transport started; the dial is asynchronous and its outcome is not
		// known at announce time. Saying "attached" here contradicted /readyz, which
		// answers `not-ready connect_client_attached` for the whole time a dial to an
		// unresolvable host is failing -- so the log asserted success while the probe
		// asserted the opposite, and the log is the thing an operator reads first.
		self.log.Info("URnetwork client constructed, dialling the operator platform",
			"platform_url", self.attachment.platformUrl,
			"api_url", self.attachment.apiUrl,
			"attached", "unknown here -- /readyz connect_client_attached is the authority")
	}
	if failed := self.ready.unmet(ctx); 0 < len(failed) {
		self.log.Warn("not ready", "preconditions", summarise(failed))
	} else {
		self.log.Info("ready")
	}
	for _, item := range self.notBuilt() {
		self.log.Warn("not built", "what", item.String())
	}
}
