package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// The transport, as the two things about it that are checkable without an operator account.
//
// Everything else about it is not: whether a platform dial succeeds, whether the credential is
// accepted, whether a client's frames arrive. Those need a `network_client` on a running
// URnetwork operator, which §9.1 has an admin of that operator create and which nothing in this
// repository can produce — so they are stated as a finding in transport.go and are NOT asserted
// here by a test that would pass against a server that never dialled anything.

// The two service URLs are derived from `operator_host`, and only from it.
//
// They are the mirror of spec A §9.3's client settings: a client's `network_space_host` and this
// server's `operator_host` have to resolve to the same platform, or the client dials one place
// and the server is attached to another. Deriving them in two places that can disagree is how
// that happens, so this asserts the shape rather than trusting it.
func TestTheServiceUrlsAreDerivedFromOperatorHost(t *testing.T) {
	apiUrl, platformUrl, err := serviceUrls("ur.network")
	if err != nil {
		t.Fatalf("serviceUrls: %v", err)
	}
	if apiUrl != "https://api.ur.network" {
		t.Fatalf("the api URL is %q, want https://api.ur.network — the shape every URnetwork client uses", apiUrl)
	}
	if platformUrl != "wss://connect.ur.network" {
		t.Fatalf("the platform URL is %q, want wss://connect.ur.network", platformUrl)
	}

	// a different host gives different URLs, so the two above are not constants with a host
	// pasted next to them
	otherApi, otherPlatform, err := serviceUrls("example.test")
	if err != nil {
		t.Fatalf("serviceUrls: %v", err)
	}
	if otherApi == apiUrl || otherPlatform == platformUrl {
		t.Fatal("two different operator hosts produced the same service URLs")
	}
}

// `operator_host` is a bare host name, and anything else is refused rather than concatenated.
//
// An operator who writes `https://ur.network` produces `wss://connect.https://ur.network`, which
// fails to dial with a message about a URL nobody typed. Refusing it at the point it is read is
// the difference between a startup error naming the key and an hour in a transport log.
func TestOperatorHostIsRefusedWhenItIsNotABareHostName(t *testing.T) {
	for _, bad := range []string{"", "https://ur.network", "ur.network/path", "ur.network:443", "ur network"} {
		if _, _, err := serviceUrls(bad); err == nil {
			t.Fatalf("operator_host %q was accepted; it would be concatenated into a URL that cannot be dialled", bad)
		}
	}
	if _, _, err := serviceUrls("ur.network"); err != nil {
		t.Fatalf("a bare host name was refused: %v", err)
	}
}

// With no credential, nothing is constructed and nothing is dialled.
//
// This is the property transport.go argues at length: a `connect.Client` with no transport
// receives nothing, forever, while `peer` runs eight workers and a sweep loop behind it and every
// counter reads zero — which looks exactly like a server nobody has messaged yet. So the absence
// is an absence, and `/readyz` is where it is reported.
func TestWithNoCredentialNoClientIsConstructed(t *testing.T) {
	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"

	attached, err := attachToPlatform(context.Background(), deployment{ordinal: "0"}, loaded)
	if !errors.Is(err, errNoCredential) {
		t.Fatalf("attachToPlatform with no credential answered %v, want %v", err, errNoCredential)
	}
	if attached != nil {
		t.Fatal("attachToPlatform refused and returned an attachment anyway")
	}
	// and the nil attachment answers the readiness question, rather than panicking on it
	if attached.attached() {
		t.Fatal("a nil attachment reports itself attached")
	}
}

// An attachment is not built when `operator_host` is unset, even with a credential present.
//
// The two are one requirement: the credential says who this replica is and `operator_host` says
// which platform to present it to. A build that dialled with one and not the other would dial
// nothing and report a credential problem.
func TestACredentialWithNoOperatorHostDoesNotAttach(t *testing.T) {
	credential, identity := unsignedCredential(t)
	_, err := attachToPlatform(context.Background(), deployment{
		ordinal:  "0",
		byJwt:    credential,
		clientId: identity,
	}, defaultConfiguration())
	if !errors.Is(err, errNoOperatorHost) {
		t.Fatalf("attachToPlatform with a credential and no operator_host answered %v, want %v", err, errNoOperatorHost)
	}
}

// A logger that writes nowhere, for the tests that build a server.
func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
