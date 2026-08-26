// The message server process entrypoint of spec B §2.1.
//
// This build is a skeleton and says so on every run: it prints what version it is and what
// configuration it would run under, and then it exits. It opens no socket, binds no port,
// loads no vault resource and dials nothing — there is no store behind it yet, and a
// skeleton that listens is one somebody deploys.
//
// The configuration printed here is the shape of spec B §10.2 with that section's defaults,
// not a file that was read. Two of the values have no honest default and print as unset:
// §10.1 has /readyz refuse readiness until `operator_host` and `hosting_jurisdiction` are
// both non-empty, because §4.3.1 advertises them to clients and an advertised jurisdiction
// nobody set is worse than no answer at all.
//
// Nothing here prints a secret, and nothing here can: the vault resources of §10.2 are named
// in the output and read by neither this file nor anything it calls.
//
// May import: any package of this module. An entrypoint that cannot import a package cannot
// start it, so the layering the other packages declare stops here — what this file may reach
// outside the module is still spec B §2.2's list and nothing wider.
//
//urmsg:mayimport *
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

// stamped at link time with -ldflags "-X main.version=...". `dev` is the honest answer for a
// build nobody stamped, and it is the one an unstamped release binary will print in front of
// an operator, so it is a word rather than an empty string.
var version = "dev"

// The §10.2 `message.yml` values this process runs on, with that section's defaults. This is
// config, never a constant in code: §10.2 is normative that changing an advertised value must
// not require a release, so the defaults live in one struct that a loader can overwrite whole.
type configuration struct {
	operatorHost                string
	hostingJurisdiction         string
	readKeyWindowSeconds        int64
	durableTtlDefaultSeconds    int64
	durableTtlMaxSeconds        int64
	rendezvousTtlSeconds        int64
	rendezvousDepositTtlSeconds int64
	rendezvousMailboxDepth      int64
	cardTombstoneSeconds        int64
	diagnosticSessionMaxMinutes int64
}

// The defaults of spec B §10.2, verbatim.
func defaultConfiguration() configuration {
	return configuration{
		operatorHost:                "",
		hostingJurisdiction:         "",
		readKeyWindowSeconds:        7776000,
		durableTtlDefaultSeconds:    31536000,
		durableTtlMaxSeconds:        0,
		rendezvousTtlSeconds:        7776000,
		rendezvousDepositTtlSeconds: 604800,
		rendezvousMailboxDepth:      16,
		cardTombstoneSeconds:        7776000,
		diagnosticSessionMaxMinutes: 60,
	}
}

// One printed configuration line: what it is called in `message.yml`, what this process would
// run on, and what a reader needs to know about that value beyond its number.
type setting struct {
	name  string
	value string
	note  string
}

func (self configuration) settings() []setting {
	return []setting{
		{"operator_host", self.operatorHost, "unset — /readyz refuses readiness until it is configured (§10.1)"},
		{"hosting_jurisdiction", self.hostingJurisdiction, "unset — advertised to clients in Capabilities (§4.3.1)"},
		{"read_key_window_seconds", fmt.Sprint(self.readKeyWindowSeconds), "90 days; a write key is still retired after 60 s (§5.3)"},
		{"durable_ttl_default_seconds", fmt.Sprint(self.durableTtlDefaultSeconds), "1 year, the DURABLE default when a group asks for none (§7.3)"},
		{"durable_ttl_max_seconds", fmt.Sprint(self.durableTtlMaxSeconds), "0 means no fleet cap, and stores NULL rather than a clamp (§7.3)"},
		{"rendezvous_ttl_seconds", fmt.Sprint(self.rendezvousTtlSeconds), "§4.3.7"},
		{"rendezvous_deposit_ttl_seconds", fmt.Sprint(self.rendezvousDepositTtlSeconds), "7 days (§4.3.7)"},
		{"rendezvous_mailbox_depth", fmt.Sprint(self.rendezvousMailboxDepth), "the 17th uncollected deposit is refused (§13.38)"},
		{"card_tombstone_seconds", fmt.Sprint(self.cardTombstoneSeconds), "a retired id answers identically until the sweep reclaims it (§13.39)"},
		{"diagnostic_session_max_minutes", fmt.Sprint(self.diagnosticSessionMaxMinutes), "the one bounded exception to §11.1 (§11.5)"},
	}
}

// The §10.2 vault and config resources, named so an operator can see what this process will
// ask for. None of them is read here.
var resources = []struct {
	name string
	kind string
	what string
}{
	{"pg.yml", "vault", "postgres connection, message-server cluster (decision B10: not the operator's)"},
	{"db.yml", "config", "pool sizing"},
	{"redis.yml", "vault + config", "redis connection and pool (§2.4)"},
	{"minio.yml", "vault", "object store endpoint, credentials, prefix (§8.3)"},
	{"message_server.yml", "vault", "this ordinal's client_id and transport credential (§9.1)"},
	{"message_fleet.yml", "vault", "write_key_kek, grant_kek, channel_key, signing sidecar, fleet root public key (§9.1)"},
	{"message.yml", "config", "the values above; watched and reloaded, bumping capability_version (§10.2)"},
}

func main() {
	out := os.Stdout

	fmt.Fprintf(out, "message-server %s\n", version)
	fmt.Fprintf(out, "  go          %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	for _, line := range buildLines() {
		fmt.Fprintf(out, "  %s\n", line)
	}

	fmt.Fprintf(out, "\nconfiguration (spec B §10.2 defaults; no resource was read)\n")
	for _, resource := range resources {
		fmt.Fprintf(out, "  %-20s %-14s %s\n", resource.name, resource.kind, resource.what)
	}
	fmt.Fprintf(out, "\n")
	for _, item := range defaultConfiguration().settings() {
		value := item.value
		if value == "" {
			value = "(unset)"
		}
		fmt.Fprintf(out, "  %-32s %-12s %s\n", item.name, value, item.note)
	}

	fmt.Fprintf(out, "\nthis build is a skeleton: it binds no port, reads no vault resource, and connects to nothing.\n")
}

// What the toolchain stamped into this binary about where it came from. Read rather than
// asked for, so a binary built outside the release path still says which revision it is —
// and says plainly when it does not know, rather than printing a blank line.
func buildLines() []string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return []string{"build       no build information in this binary"}
	}
	revision, modified, stamped := "", "", false
	for _, stamp := range info.Settings {
		switch stamp.Key {
		case "vcs.revision":
			revision, stamped = stamp.Value, true
		case "vcs.modified":
			if stamp.Value == "true" {
				modified = " (working tree modified)"
			}
		}
	}
	if !stamped {
		return []string{fmt.Sprintf("module      %s", info.Main.Path), "revision    not stamped"}
	}
	return []string{
		fmt.Sprintf("module      %s", info.Main.Path),
		fmt.Sprintf("revision    %s%s", revision, modified),
	}
}
