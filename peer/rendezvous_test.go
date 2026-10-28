package peer

import (
	"slices"
	"strings"
	"testing"

	messageprotocol "github.com/urnetwork/message/protocol"
)

// §4.3.11's five arms are routed only when the handler serves them (LRI R70's addendum), and that
// is the one difference serving makes: the derived list of unserved arms drops by exactly those
// five, printed with what stays unserved either way. The round trip is the same request over the
// frame path to both peers: REASON_INTERNAL from the one that does not serve the arms, as Spec B
// §4.3.11 says such a server answers, and the handler's own answer from the one that does.
func TestTheFiveRendezvousArmsAreRoutedOnlyWhenTheHandlerServesThem(t *testing.T) {
	unserved := newFixture(t)
	servingHandler := &recordingHandler{rendezvousServed: true}
	served := newFixtureWith(t, Config{Handler: servingHandler})

	unservedNames := func(current *fixture) []string {
		names := []string{}
		for _, entry := range current.peer.unservedArms() {
			name, _, found := strings.Cut(strings.TrimPrefix(entry.What, "the "), " arm of MessageServerRequest.body")
			if !found {
				t.Fatalf("an unserved arm is declared as %q, which does not open by naming its arm", entry.What)
			}
			names = append(names, name)
		}
		slices.Sort(names)
		return names
	}
	before, after := unservedNames(unserved), unservedNames(served)
	dropped := []string{}
	for _, name := range before {
		if !slices.Contains(after, name) {
			dropped = append(dropped, name)
		}
	}
	for _, name := range after {
		if !slices.Contains(before, name) {
			t.Fatalf("the %s arm is unserved only when the handler serves the rendezvous arms", name)
		}
	}
	want := []string{"rendezvous_collect", "rendezvous_deposit", "rendezvous_open", "rendezvous_register", "rendezvous_retire"}
	t.Logf("not serving: %d unserved arms; serving: %d; the five serving removes: %v", len(before), len(after), dropped)
	t.Logf("unserved either way (the complement): %v", after)
	if !slices.Equal(dropped, want) {
		t.Fatalf("serving the rendezvous arms took %v off the unserved list, want exactly %v", dropped, want)
	}
	if len(served.peer.routes)-len(unserved.peer.routes) != len(want) {
		t.Fatalf("the serving peer routes %d arms and the other %d, want five more", len(served.peer.routes), len(unserved.peer.routes))
	}

	for name, current := range map[string]struct {
		fixture *fixture
		want    messageprotocol.Reason
	}{
		"a peer whose handler does not serve them": {unserved, messageprotocol.Reason_REASON_INTERNAL},
		"a peer whose handler serves them":         {served, messageprotocol.Reason_REASON_OK},
	} {
		current.fixture.hello(t)
		response := current.fixture.call(t, &messageprotocol.RendezvousOpenRequest{RendezvousId: make([]byte, 32)})
		if response.GetReason() != current.want {
			t.Fatalf("an Open sent to %s was answered %v, want %v", name, response.GetReason(), current.want)
		}
	}
	reached := false
	for _, call := range servingHandler.recorded() {
		if call.arm == "rendezvous_open" {
			reached = true
		}
	}
	if !reached {
		t.Fatal("the serving peer answered the Open without reaching its handler's RendezvousOpen")
	}
}
