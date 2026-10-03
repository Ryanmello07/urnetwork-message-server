package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// SPEC B REVISION 23: a message server can be configured NOT to attach to the operator's platform,
// and is then reached only at its own endpoint. Three properties:
//
//  1. An endpoint-only replica is asked nothing about the platform, and IS asked whether its
//     endpoint is serving, because the endpoint is then the only carrier it has. Held BOTH WAYS:
//     the set an attaching replica is asked and the endpoint-only set differ in exactly the names
//     printed, each on the side its mode puts it.
//  2. Endpoint-only with no endpoint is a startup failure, refused before the pool opens.
//  3. The setting takes "on" or "off" and nothing else, and it is on unless somebody says off.

func preconditionNames(set []precondition) []string {
	var names []string
	for _, item := range set {
		names = append(names, item.name)
	}
	return names
}

// The names in `from` that are not in `other`, in `from`'s order.
func namesMissingFrom(from []string, other []string) []string {
	var missing []string
	for _, name := range from {
		if !slices.Contains(other, name) {
			missing = append(missing, name)
		}
	}
	return missing
}

func TestAnEndpointOnlyReplicaIsAskedNothingAboutThePlatform(t *testing.T) {
	attaching := completeServer()
	endpointOnly := completeServer()
	endpointOnly.config.platformAttachment = "off"
	// the two things an endpoint-only replica does not have, TAKEN AWAY, so that asking it about
	// either would refuse and the test could see it asked
	endpointOnly.deploy.byJwt = ""
	endpointOnly.attached = func() bool { return false }

	on := preconditionNames(attaching.preconditions())
	off := preconditionNames(endpointOnly.preconditions())
	notAsked := namesMissingFrom(on, off)
	onlyAsked := namesMissingFrom(off, on)
	// THE COMPLEMENT, printed both ways before it is asserted
	t.Logf("an endpoint-only replica is not asked %v and is asked %v", notAsked, onlyAsked)

	if want := []string{"ordinal_credential", "connect_client_attached"}; !slices.Equal(notAsked, want) {
		t.Fatalf("an endpoint-only replica is spared %v; it must be spared exactly %v, the platform's own", notAsked, want)
	}
	if want := []string{"endpoint_listening"}; !slices.Equal(onlyAsked, want) {
		t.Fatalf("an endpoint-only replica is additionally asked %v; it must be asked exactly %v, its only carrier", onlyAsked, want)
	}
	for name := range platformOnlyPreconditions {
		if !slices.Contains(on, name) {
			t.Fatalf("platformOnlyPreconditions names %q, which no attaching replica is asked: a name that drifted from its precondition", name)
		}
	}

	// it refuses on the endpoint, and on nothing about the platform although it has no credential
	// and no attached transport
	if unmet := namesOf(withoutDatabase(endpointOnly.preconditions())); !slices.Equal(unmet, []string{"endpoint_listening"}) {
		t.Fatalf("an endpoint-only replica whose endpoint is not serving is unmet on %v; want exactly endpoint_listening", unmet)
	}
	endpointOnly.endpointServing.Store(true)
	if unmet := namesOf(withoutDatabase(endpointOnly.preconditions())); len(unmet) != 0 {
		t.Fatalf("an endpoint-only replica whose endpoint IS serving is still unmet on %v", unmet)
	}

	// and the CONTROL: the same two absences on an ATTACHING replica refuse it, by name
	attaching.deploy.byJwt = ""
	attaching.attached = func() bool { return false }
	unmet := namesOf(withoutDatabase(attaching.preconditions()))
	if !slices.Contains(unmet, "ordinal_credential") || !slices.Contains(unmet, "connect_client_attached") {
		t.Fatalf("an attaching replica with no credential and no transport is unmet on %v; the absences above were not tested by anything", unmet)
	}
}

func TestEndpointOnlyWithNoEndpointIsRefusedBeforeAnythingOpens(t *testing.T) {
	loaded := defaultConfiguration()
	loaded.platformAttachment = "off"
	loaded.endpointListenAddress = ""
	// a DSN that would fail to parse: reaching the pool would be a different error, so this one
	// is only the refusal if it comes first
	_, err := newServer(t.Context(), deployment{ordinal: "0", dsn: "not a dsn"}, loaded, discardLog())
	if !errors.Is(err, errNoCarrier) {
		t.Fatalf("platform_attachment off with no endpoint started with %v; it would receive nothing", err)
	}
}

func TestPlatformAttachmentTakesOnOrOffAndNothingElse(t *testing.T) {
	if got := defaultConfiguration().platformAttachment; got != "on" {
		t.Fatalf("platform_attachment defaults to %q; a server must attach unless somebody says otherwise", got)
	}
	for _, value := range []string{"on", "off"} {
		file := writeResource(t, messageResource, "platform_attachment: "+value+"\n")
		loaded, err := loadConfiguration(file, noEnvironment)
		if err != nil {
			t.Fatalf("platform_attachment %q was refused: %v", value, err)
		}
		if loaded.platformAttachment != value || loaded.attachesToPlatform() != (value == "on") {
			t.Fatalf("platform_attachment %q loaded as %q (attaches %v)", value, loaded.platformAttachment, loaded.attachesToPlatform())
		}
	}
	for _, value := range []string{"false", "no", "0", "OFF", "detached"} {
		file := writeResource(t, messageResource, "platform_attachment: "+value+"\n")
		_, err := loadConfiguration(file, noEnvironment)
		if !errors.Is(err, errNotAChoice) {
			t.Fatalf("platform_attachment %q loaded with %v; a spelling of off that is read as on attaches anyway", value, err)
		}
		if !strings.Contains(err.Error(), "on, off") {
			t.Fatalf("the refusal of %q does not say what the setting takes: %v", value, err)
		}
	}
}

func TestOffMeansNoSessionEvenWithEveryInputPresent(t *testing.T) {
	deploy := deployment{ordinal: "0", byJwt: "a.credential.that.is.never.parsed.here", serverId: make([]byte, serverIdBytes)}
	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	// THE CONTROL: every input an attachment needs is present, so the setting alone decides
	if !canAttach(deploy, loaded) {
		t.Fatal("canAttach refused a complete deployment; the two cases below would prove nothing")
	}
	if !wantsAttachment(deploy, loaded) {
		t.Fatal("platform_attachment on, with every input present, does not attach")
	}
	loaded.platformAttachment = "off"
	if wantsAttachment(deploy, loaded) {
		t.Fatal("platform_attachment off still dials the platform because a credential is on the box; off must mean no session")
	}
}
