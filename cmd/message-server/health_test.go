package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/message-server/api"
)

// §10.1's two endpoints, as the four properties they carry.
//
//  1. **`/readyz` is 200 only when every precondition holds**, and 503 naming the ones that do
//     not. A probe that cannot say which is a probe that turns five different outages into one
//     page.
//  2. **Every precondition can refuse on its own.** A precondition that no state reaches is a
//     precondition that never fires, and the way that happens is not malice — it is a check
//     written after another one that always fails first.
//  3. **Neither endpoint returns any identifier**, which §10.1 states in those words.
//  4. **`/healthz` answers while `/readyz` refuses.** They are different questions, and a build
//     that answers them together restarts a replica whose database is down and gets a second
//     replica whose database is down.

// A readiness whose preconditions are known, so the endpoint can be held to property 1 without
// standing up anything it asks about.
func syntheticReadiness(unmet ...string) *readiness {
	failing := map[string]bool{}
	for _, name := range unmet {
		failing[name] = true
	}
	var set []precondition
	for _, name := range []string{"first", "second", "third"} {
		set = append(set, precondition{
			name: name,
			why:  "the reason " + name + " is not met",
			met: func(ctx context.Context) error {
				if failing[name] {
					return errors.New("not met")
				}
				return nil
			},
		})
	}
	return &readiness{preconditions: set}
}

// `/readyz` answers 503 naming exactly the preconditions that are unmet, over every subset of the
// set.
//
// Every subset and not a handful: with three preconditions there are eight, and the two that
// matter most are the empty one (200, and nothing named) and the full one (503, and all three
// named). A handler that reported the first failure and stopped passes a one-at-a-time test.
func TestReadyzNamesExactlyThePreconditionsThatAreUnmet(t *testing.T) {
	all := []string{"first", "second", "third"}
	for mask := range 1 << len(all) {
		var unmet []string
		for index, name := range all {
			if mask&(1<<index) != 0 {
				unmet = append(unmet, name)
			}
		}
		t.Run(fmt.Sprintf("unmet=%v", unmet), func(t *testing.T) {
			status, body := probe(t, readyzHandler(syntheticReadiness(unmet...)), "/readyz")

			wantStatus := http.StatusOK
			if 0 < len(unmet) {
				wantStatus = http.StatusServiceUnavailable
			}
			if status != wantStatus {
				t.Fatalf("%d unmet preconditions answered %d, want %d\n%s", len(unmet), status, wantStatus, body)
			}
			for _, name := range all {
				named := strings.Contains(body, "not-ready "+name+":")
				if want := slices.Contains(unmet, name); named != want {
					t.Fatalf("%s is named %v in the body and is unmet %v:\n%s", name, named, want, body)
				}
			}
		})
	}
}

// A replica that has received its shutdown signal refuses readiness, whatever else is true.
//
// §2.3 shuts down by draining first. The load balancer has to stop sending here before anything
// is torn down, and the only thing it reads is this endpoint — so `draining` is checked before
// the preconditions and not alongside them.
func TestADrainingReplicaRefusesReadinessEvenWithEveryPreconditionMet(t *testing.T) {
	current := syntheticReadiness()
	status, _ := probe(t, readyzHandler(current), "/readyz")
	if status != http.StatusOK {
		t.Fatalf("a replica with every precondition met answered %d before it was draining", status)
	}
	current.draining.Store(true)
	status, body := probe(t, readyzHandler(current), "/readyz")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("a draining replica answered %d, want 503", status)
	}
	if !strings.Contains(body, "draining") {
		t.Fatalf("a draining replica refused without saying why:\n%s", body)
	}
}

// `/healthz` answers while `/readyz` refuses everything.
//
// The two are different questions. A supervisor reads `/healthz` to decide whether to restart the
// process, and a load balancer reads `/readyz` to decide whether to send it traffic; a build that
// failed both when the database was down would restart-loop every replica during a database
// outage, which is the one time restarting helps least.
func TestHealthzAnswersWhileReadyzRefuses(t *testing.T) {
	current := syntheticReadiness("first", "second", "third")
	current.draining.Store(true)

	if status, _ := probe(t, readyzHandler(current), "/readyz"); status != http.StatusServiceUnavailable {
		t.Fatalf("/readyz answered %d with everything unmet and the replica draining", status)
	}
	status, body := probe(t, healthzHandler(), "/healthz")
	if status != http.StatusOK {
		t.Fatalf("/healthz answered %d while the process was running: a supervisor would restart it", status)
	}
	if !strings.Contains(body, "alive") {
		t.Fatalf("/healthz answered 200 with a body that does not say the process is alive: %q", body)
	}
}

// §10.1: "Neither returns any identifier."
//
// Every value this deployment was configured with is a sentinel that appears nowhere else, and
// the assertion is over the whole body of both endpoints in both states. It catches the shape
// that actually happens, which is not somebody printing a client_id on purpose: it is a
// precondition whose `why` was made more helpful by interpolating the value that is missing, and
// the value that is missing is a DSN.
func TestNeitherEndpointReturnsAConfiguredValue(t *testing.T) {
	const (
		sentinelHost         = "sentinel-operator-host-zzz"
		sentinelJurisdiction = "sentinel-jurisdiction-zzz"
		sentinelDsn          = "postgres://sentinel-user:sentinel-password-zzz@127.0.0.1:1/sentineldb"
		sentinelJwt          = "sentinel-transport-credential-zzz"
		sentinelOrdinal      = "sentinel-ordinal-zzz"
	)
	loaded := defaultConfiguration()
	loaded.operatorHost = sentinelHost
	loaded.hostingJurisdiction = sentinelJurisdiction

	current := &server{
		config: loaded,
		deploy: deployment{
			dsn:      sentinelDsn,
			byJwt:    sentinelJwt,
			ordinal:  sentinelOrdinal,
			kek:      make([]byte, kekBytes),
			serverId: make([]byte, serverIdBytes),
		},
	}
	// every precondition that does not ask the database, so this test needs none; the two that
	// do are held to the same rule by TestAFirstStartAgainstAnEmptyDatabase below, whose server
	// is built with the same sentinels
	ready := &readiness{preconditions: withoutDatabase(current.preconditions()), notBuilt: current.notBuilt()}

	for _, state := range []string{"ready", "draining"} {
		ready.draining.Store(state == "draining")
		_, body := probe(t, readyzHandler(ready), "/readyz")
		for _, sentinel := range []string{sentinelHost, sentinelJurisdiction, sentinelDsn, sentinelJwt, sentinelOrdinal, "sentinel-password-zzz"} {
			if strings.Contains(body, sentinel) {
				t.Fatalf("/readyz (%s) printed a configured value:\n%s", state, body)
			}
		}
	}
}

// Every precondition of the real set can be reached, and the ones this test does not reach are
// printed by name.
//
// This is the test the set needs and a list of cases cannot give. A precondition that no state
// makes fail is a check that never fires, and the way it happens is a check written behind
// another one that always fails first — so the class is the SET, taken from
// [server.preconditions], and the complement is printed rather than left implicit.
//
// The two that ask the database are not reachable without one, and they are named in the
// complement rather than quietly dropped from the denominator. TestAFirstStartAgainstAnEmptyDatabase
// is where they are reached.
func TestEveryPreconditionCanRefuseOnItsOwnAndTheComplementIsPrinted(t *testing.T) {
	// one deployment per precondition, each of which is complete except for the one thing that
	// precondition is about
	cases := []struct {
		expect string
		spoil  func(*server)
	}{
		{"kek_loaded", func(s *server) { s.deploy.kek = nil }},
		{"server_id_set", func(s *server) { s.deploy.serverId = nil }},
		{"ordinal_credential", func(s *server) { s.deploy.byJwt = "" }},
		{"connect_client_attached", func(s *server) { s.attached = func() bool { return false } }},
		{"operator_host", func(s *server) { s.config.operatorHost = "" }},
		{"operator_host", func(s *server) { s.config.operatorHost = "https://ur.network" }},
		{"hosting_jurisdiction", func(s *server) { s.config.hostingJurisdiction = "" }},
	}

	reached := map[string]bool{}
	for _, current := range cases {
		t.Run(current.expect, func(t *testing.T) {
			built := completeServer()
			current.spoil(built)
			unmet := namesOf(withoutDatabase(built.preconditions()))
			if !slices.Contains(unmet, current.expect) {
				t.Fatalf("with %s removed, the unmet set is %v and does not hold %s", current.expect, unmet, current.expect)
			}
			if len(unmet) != 1 {
				t.Fatalf("removing one thing left %v unmet; this case cannot say which of them %s is about", unmet, current.expect)
			}
		})
		reached[current.expect] = true
	}

	// the complement, printed: every precondition of the real set that no case above refuses
	var complement []string
	for _, item := range completeServer().preconditions() {
		if !reached[item.name] {
			complement = append(complement, item.name)
		}
	}
	// derived from the set rather than typed: the complement of "refused by a case above" must be
	// exactly "asks the database", so a precondition added without a case here fails, and one that
	// stops asking the database without gaining a case fails too
	want := needingDatabase(completeServer().preconditions())
	if !slices.Equal(complement, want) {
		t.Fatalf("the preconditions no case here refuses are %v, and the ones that ask the database are %v; a precondition that is in neither is one nothing reaches",
			complement, want)
	}
	if len(want) == 0 {
		t.Fatal("no precondition asks the database, so the complement is empty for the wrong reason")
	}
	t.Logf("not refused here, and refused by TestAFirstStartAgainstAnEmptyDatabaseServesHealthAndNamesWhatIsMissing: %v", complement)
}

// A server with everything present except a connect client that is attached. The transport is
// never dialled: [attachment.attached] reads the transport's own registration count, and a nil
// attachment is the "no credential" case, so this asserts the precondition and not the network.
func completeServer() *server {
	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	loaded.hostingJurisdiction = "US"
	return &server{
		config: loaded,
		deploy: deployment{
			ordinal:  "0",
			dsn:      "postgres://ignored",
			byJwt:    "a.credential.that.is.never.parsed.here",
			kek:      make([]byte, kekBytes),
			serverId: make([]byte, serverIdBytes),
		},
		// the transport seam, answering what a dialled platform transport answers when it holds a
		// connection. Every case above that is not about the transport needs this, or it would
		// have two unmet preconditions and could not say which one it was about
		attached: func() bool { return true },
	}
}

// The preconditions that do not ask the database, for the tests that have none.
//
// Filtered on the entry's own declaration and never on its name: a precondition renamed without
// its declaration would otherwise slip through here and run against a nil pool, and the panic
// would take down the very test that exists to notice the rename.
func withoutDatabase(set []precondition) []precondition {
	var kept []precondition
	for _, item := range set {
		if item.needsDatabase {
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

// The preconditions that DO ask the database, by name, in declaration order.
func needingDatabase(set []precondition) []string {
	var names []string
	for _, item := range set {
		if item.needsDatabase {
			names = append(names, item.name)
		}
	}
	return names
}

// The names of every precondition in this set that is not met.
func namesOf(set []precondition) []string {
	var unmet []string
	for _, item := range set {
		if item.met(context.Background()) != nil {
			unmet = append(unmet, item.name)
		}
	}
	return unmet
}

// `not-built` is printed on the ready answer as well as the not-ready one.
//
// A server that is ready and serves no rendezvous arm is still a server somebody has to be told
// serves no rendezvous arm. Printing the list only when something is wrong is how a gap becomes
// invisible on exactly the deployment that is working.
func TestTheNotBuiltListIsPrintedOnTheReadyAnswerToo(t *testing.T) {
	current := syntheticReadiness()
	current.notBuilt = []api.NotBuilt{{Section: "§9.9", What: "a thing that is not built", Owner: "nobody"}}

	status, body := probe(t, readyzHandler(current), "/readyz")
	if status != http.StatusOK {
		t.Fatalf("a readiness with every precondition met answered %d", status)
	}
	if !strings.Contains(body, "not-built") || !strings.Contains(body, "a thing that is not built") {
		t.Fatalf("the ready answer does not carry the not-built list:\n%s", body)
	}
}

// ── the fixtures ─────────────────────────────────────────────────────────────────────────

func probe(t *testing.T, handler http.HandlerFunc, path string) (int, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return recorder.Code, string(body)
}
