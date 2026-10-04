package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// §11.1, at the one place in this module that writes a log line.
//
// > **MUST NOT appear in any log line, metric label, trace span, error string, panic message, core
// > dump, database log, object-store access log, or Redis slowlog:** `group_id` · `sender_handle` ·
// > … · `client_id` · `network_id` · **any IP address** · **any `ByJwt`** · … · any KEK · …
//
// §11.2 ranks the enforcement in descending order of reliability and puts *structural* first —
// `redact`'s opaque types, which hold no code yet — then a compile-time analyser, then a logging
// wrapper with no `log.Any`. None of the three exists. This is the fourth-best thing and it is what
// there is: the startup announcement is the only log this process writes before it is serving, it
// writes every one of its inputs' *names*, and this asserts that it writes none of their values.
//
// The list below is the subset of §11.1's that this process actually holds: a `ByJwt`, a KEK, the
// DSN's password, the `client_id` inside the credential, and an IP address. `group_id`,
// `sender_handle`, `record_id` and the rest never reach this file — `peer` and `api` hold those, and
// §11.1's structural enforcement for them is `redact`, which is item 28's work and is not this.
func TestTheStartupAnnouncementPrintsNoValueSpecB111Forbids(t *testing.T) {
	credential, identity := unsignedCredential(t)
	const (
		sentinelKekHex = "5e27e1e15e27e1e15e27e1e15e27e1e15e27e1e15e27e1e15e27e1e15e27e1e1"
		sentinelDsn    = "postgres://sentinel-user:sentinel-password-zzz@10.11.12.13:5432/sentineldb"
		sentinelHost   = "sentinel-operator-host-zzz.example"
	)

	loaded := defaultConfiguration()
	loaded.operatorHost = sentinelHost
	loaded.hostingJurisdiction = "US"

	written := &bytes.Buffer{}
	current := &server{
		config: loaded,
		deploy: deployment{
			resourceDir:   "/etc/urmessage",
			ordinal:       "0",
			healthAddress: "10.11.12.13:9099",
			dsn:           sentinelDsn,
			kek:           mustHex(t, sentinelKekHex),
			kekId:         7,
			serverId:      make([]byte, serverIdBytes),
			byJwt:         credential,
			clientId:      identity,
		},
		log:      slog.New(slog.NewTextHandler(written, &slog.HandlerOptions{Level: slog.LevelDebug})),
		attached: func() bool { return false },
	}
	current.ready = &readiness{
		preconditions: withoutDatabase(current.preconditions()),
		notBuilt:      current.notBuilt(),
	}
	current.announce(context.Background())

	log := written.String()
	if log == "" {
		t.Fatal("the startup announcement wrote nothing, so this test asserts nothing about it")
	}
	// the control: it did announce, and it did say the one thing an operator must not miss
	if !strings.Contains(log, "NO MESSAGE TRAFFIC WILL BE SERVED") {
		t.Fatalf("a server with no connect client did not say so in its startup log:\n%s", log)
	}

	for _, forbidden := range []struct {
		what  string
		value string
	}{
		{"any ByJwt", credential},
		{"a client_id", identity.String()},
		{"any KEK", sentinelKekHex},
		{"the DSN, which carries a password", sentinelDsn},
		{"a password", "sentinel-password-zzz"},
		{"any IP address", "10.11.12.13"},
	} {
		if strings.Contains(log, forbidden.value) {
			t.Fatalf("§11.1 forbids %s in any log line, and the startup announcement printed one:\n%s",
				forbidden.what, log)
		}
	}

	// and the names ARE there: §11.1's MAY list is "process lifecycle events", and a log that
	// redacted the resource names along with the values would tell an operator nothing at all
	for _, name := range []string{messageResource, pgResource, fleetResource, messageServerResource} {
		if !strings.Contains(log, name) {
			t.Fatalf("the startup log does not name %s, so an operator cannot tell which resource was read:\n%s", name, log)
		}
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := fixedHex(value, kekBytes, "a test KEK")
	if err != nil {
		t.Fatalf("decoding the test KEK: %v", err)
	}
	return decoded
}
