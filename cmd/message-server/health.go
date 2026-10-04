package main

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/urnetwork/message-server/api"
)

// §10.1's two health endpoints, on §10.1's private port.
//
// > Health endpoints on a private port: `/healthz` (process alive) and `/readyz` (database
// > reachable, KEK loaded, connect client attached, migrations at head, and every advertised
// > value that has no honest default present — `operator_host` and `hosting_jurisdiction` both
// > non-empty, §4.3.1). Neither returns any identifier.
//
// The two are different questions and this build answers them differently, which is the whole
// reason there are two: `/healthz` is "is this process running", and a process that is running
// and cannot serve a single request must still answer it, or a supervisor restarts a replica
// whose problem is that its database is down and gets a second replica whose database is down.
// `/readyz` is "should traffic come here", and everything below is a reason it should not.
//
// **Neither returns any identifier**, and that is enforced rather than intended: a precondition
// prints its `name` and its `why`, both of which are constants in this file, and never the error
// its check returned.
//
// **The error its check returned goes nowhere at all, and that is a cost this build pays on
// purpose.** The obvious improvement — log it, so an operator debugging `database_reachable` can
// see what pgx actually said — is the one §11.1 forbids: its MUST-NOT list names "any IP
// address" without qualification, and a pgx dial failure carries the host and port it dialled.
// §11.1's MAY list permits "error *classes* without identifiers", so a classification could be
// logged; none is invented here, and the honest statement of what an operator gets is the
// precondition NAME and its `why`. TestNeitherEndpointReturnsAConfiguredValue holds the endpoint
// to the first half; the second half is a gap, stated rather than papered over with a parameter
// nothing ever writes to.

// One thing that must be true before traffic should arrive.
type precondition struct {
	// A stable, identifier-free name. It is what an operator greps for and what a runbook cites,
	// so it is a constant here and never derived from a value.
	name string
	// What is missing and what to do about it, in the operator's words. Also a constant.
	why string
	// Whether this precondition asks the database. Declared rather than inferred from the name,
	// because the tests that run without one have to know which entries they may evaluate -- and a
	// test that decided that by matching names lets a renamed entry through to a nil pool, where
	// it panics and takes the whole binary down with it, including the test that would have caught
	// the rename.
	needsDatabase bool

	// nil when the precondition is met. The error is never written to the response; see above.
	met func(ctx context.Context) error
}

// How long the readiness probe will wait on the collaborators it asks. §10.1's endpoint is
// scraped on an interval; one that can block forever on a wedged database is one that stops
// answering exactly when an operator most needs the answer.
const readinessTimeout = 2 * time.Second

// §10.1's readiness, plus §2.3's drain.
type readiness struct {
	preconditions []precondition
	// Set at the first signal and never cleared. §2.3 drains and then exits; a replica that
	// became ready again after announcing it was going away is a replica a load balancer sends
	// traffic to on its way out.
	draining atomic.Bool
	// Everything this build does not do that an operator would otherwise have to discover.
	// Printed on both the ready and the not-ready answer, because a server that is ready and
	// serves no rendezvous arm is still a server somebody needs to know serves no rendezvous arm.
	notBuilt []api.NotBuilt
}

// Every precondition that is not met, in the order they are declared.
func (self *readiness) unmet(ctx context.Context) []precondition {
	var failed []precondition
	for _, current := range self.preconditions {
		bounded, cancel := context.WithTimeout(ctx, readinessTimeout)
		err := current.met(bounded)
		cancel()
		if err != nil {
			failed = append(failed, current)
		}
	}
	return failed
}

// §10.1's `/healthz`: this process is alive. It asks nothing of anything else, deliberately.
func healthzHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		fmt.Fprint(writer, "alive\n")
	}
}

// §10.1's `/readyz`: 200 when every precondition holds, 503 with the names of the ones that do
// not.
//
// The failing names are in the body because the alternative is an operator with a red probe and
// no way to tell "the database is down" from "nobody set hosting_jurisdiction". They are names
// and static sentences, and nothing read out of the configuration.
func readyzHandler(current *readiness) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")

		if current.draining.Load() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(writer, "not ready\nnot-ready draining: this replica received a shutdown signal and is closing (§2.3)\n")
			return
		}

		failed := current.unmet(request.Context())
		if 0 < len(failed) {
			writer.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(writer, "not ready\n")
			for _, item := range failed {
				fmt.Fprintf(writer, "not-ready %s: %s\n", item.name, item.why)
			}
		} else {
			writer.WriteHeader(http.StatusOK)
			fmt.Fprint(writer, "ready\n")
		}
		for _, item := range current.notBuilt {
			fmt.Fprintf(writer, "not-built %s\n", item.String())
		}
	}
}

// The readiness endpoints on their own mux. Nothing else is served here: §10.1 puts /metrics on
// this port too, and this build exports no metric, so registering a path that answered an empty
// scrape would be worse than the 404 it answers instead.
func healthMux(current *readiness) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/healthz", healthzHandler())
	mux.Handle("/readyz", readyzHandler(current))
	return mux
}

// The names of every precondition, sorted. Printed by [server.announce] so an operator can see
// the whole set at startup, without having to make the endpoint fail one at a time.
func (self *readiness) names() []string {
	names := make([]string, 0, len(self.preconditions))
	for _, item := range self.preconditions {
		names = append(names, item.name)
	}
	sort.Strings(names)
	return names
}

// A one-line summary of what is not ready, for the log. Names only.
func summarise(failed []precondition) string {
	names := make([]string, 0, len(failed))
	for _, item := range failed {
		names = append(names, item.name)
	}
	return strings.Join(names, " ")
}
