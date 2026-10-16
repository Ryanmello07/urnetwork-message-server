package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/store"
)

// THIS BUILD SERVES NO KIND-4 ARM, AND ITS READINESS SAYS WHY (§4.3.11; LRI R70 and its addendum),
// asked of the wiring [newServer] does and of nothing built beside it. The store newServer opens is
// the handler's link box store, and the floor is the configured `reject_floor_ms`. The library this
// build pins publishes no rendezvous verifier, so at every floor the handler serves none of the five
// arms, Capabilities 26 and 29 leave kind 4 out, and the not-built list names the verifiers; at the
// default floor of zero it names the floor too. It never says the link box store is missing, since
// newServer wires it, and the control shows the search below would find that line if it were there.
func TestThisBuildServesNoKindFourArmAndItsReadinessSaysWhy(t *testing.T) {
	dsn := freshSchemaDsn(t)
	const (
		verifiers = "publishes none of the five rendezvous verifiers"
		floor     = "reject_floor_ms is zero"
		unwired   = "no link box store is configured"
	)
	says := func(lines []api.NotBuilt, what string) bool {
		return slices.ContainsFunc(lines, func(line api.NotBuilt) bool { return strings.Contains(line.What, what) })
	}

	// THE CONTROL for the one absence asserted below: a handler built with no link box store says
	// so in these words, so a list without them is a measurement and not a line since reworded
	memory := store.NewMemoryStore(store.DefaultLimits())
	unwiredHandler, err := api.New(api.Config{
		Store:       memory,
		KnownGroups: api.NewMemoryKnownGroups(),
		Front:       api.ChecksNotImplemented{},
		RejectFloor: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	if !says(unwiredHandler.NotBuilt(), unwired) {
		t.Fatalf("the control, a handler with no link box store, does not say %q: %v", unwired, unwiredHandler.NotBuilt())
	}

	for name, current := range map[string]struct {
		floorMs int64
		says    []string
		silent  []string
	}{
		"at the default floor of zero": {0, []string{verifiers, floor}, []string{unwired}},
		"at a floor of 25 ms":          {25, []string{verifiers}, []string{unwired, floor}},
	} {
		t.Run(name, func(t *testing.T) {
			loaded := defaultConfiguration()
			loaded.operatorHost = "ur.network"
			loaded.hostingJurisdiction = "US"
			loaded.rejectFloorMs = current.floorMs
			built, err := newServer(context.Background(), deployment{
				ordinal:       "0",
				healthAddress: "127.0.0.1:0",
				dsn:           dsn,
				kek:           make([]byte, kekBytes),
				serverId:      make([]byte, serverIdBytes),
			}, loaded, discardLog())
			if err != nil {
				t.Fatalf("newServer: %v", err)
			}
			defer built.Close()
			if built.handler == nil {
				t.Fatal("newServer built no handler, so nothing below would be asked of one")
			}

			if built.handler.RendezvousServed() {
				t.Fatal("the handler newServer built says it serves the rendezvous arms, and this build pins no verifier for them")
			}
			advertised := built.capabilities()
			if advertised.GetRendezvousKinds() != 0 || len(advertised.GetRendezvousDepositSizes()) != 0 {
				t.Fatalf("Capabilities advertises rendezvous kinds %b and deposit sizes %v from a server that serves no kind-4 arm",
					advertised.GetRendezvousKinds(), advertised.GetRendezvousDepositSizes())
			}
			lines := built.notBuilt()
			for _, what := range current.says {
				if !says(lines, what) {
					t.Fatalf("the not-built list does not say %q:\n%v", what, lines)
				}
			}
			for _, what := range current.silent {
				if says(lines, what) {
					t.Fatalf("the not-built list says %q of a server newServer wired:\n%v", what, lines)
				}
			}
		})
	}
}
