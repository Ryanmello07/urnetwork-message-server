package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
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

// THE SWEEP'S LOG LINES JOIN THE GATE (LRI R75, D1; Spec B §11.1: "any IP address"). The server's
// own sweep job, built by newServer over a pool whose database cannot be reached, is ticked once
// through newServer's seam. Its failure line, in the log newServer was handed, carries the error's
// class, `connect`, and the pass's totals, and carries nothing of the database: not the DSN's user,
// password or database, and no address. The line's text used to be pgx's, which names the user, the
// database, and the address and host it dialled. The control is the same search over a line planted
// in the same capture, which finds what it planted.
func TestTheSweepsFailureLineNamesNothingOfTheDatabase(t *testing.T) {
	const dsn = "postgres://planted-user:planted-password@127.0.0.1:1/planted-db?sslmode=disable&connect_timeout=2"
	written := &bytes.Buffer{}
	var mutex sync.Mutex
	writer := lockedWriter{buffer: written, mutex: &mutex}
	log := slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	read := func() string {
		mutex.Lock()
		defer mutex.Unlock()
		return written.String()
	}

	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	loaded.hostingJurisdiction = "US"
	ticks := make(chan time.Time)
	built, err := buildServer(context.Background(), deployment{
		ordinal:       "0",
		healthAddress: "127.0.0.1:0",
		dsn:           dsn,
		kek:           make([]byte, kekBytes),
		serverId:      make([]byte, serverIdBytes),
	}, loaded, log, serverSeams{sweepTicks: func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	defer built.Close()
	select {
	case ticks <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("the server's sweep job took no tick: newServer did not start it")
	}

	const failed = `msg="the link box sweep failed"`
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(read(), failed) {
		if time.Now().After(deadline) {
			t.Fatalf("the sweep logged no failure in 30 s over an unreachable database:\n%s", read())
		}
		time.Sleep(10 * time.Millisecond)
	}
	line := ""
	for _, candidate := range strings.Split(read(), "\n") {
		if strings.Contains(candidate, failed) {
			line = candidate
		}
	}
	if !strings.Contains(line, "class=connect ") || !strings.Contains(line, "batches=0 boxes=0 deposits=0") {
		t.Fatalf("the sweep's failure line carries no class=connect and totals: %s", line)
	}
	needles := []string{"planted-user", "planted-password", "planted-db"}
	search := func(haystack string) []string {
		found := []string{}
		for _, needle := range needles {
			if strings.Contains(haystack, needle) {
				found = append(found, needle)
			}
		}
		return found
	}
	if found := search(read()); len(found) != 0 {
		t.Fatalf("a log line names %v:\n%s", found, read())
	}
	// no address in the failure line: the dialled one, or any other
	if strings.Contains(line, "127.0.0.1") || strings.Contains(line, "dial") {
		t.Fatalf("the sweep's failure line names the address it dialled: %s", line)
	}
	t.Logf("%s", line)

	// THE CONTROL: the same search finds each value in a line that plants it
	for _, needle := range needles {
		if found := search("level=WARN msg=control value=" + needle); len(found) != 1 || found[0] != needle {
			t.Fatalf("the control planted %s and the search found %v", needle, found)
		}
	}
}
