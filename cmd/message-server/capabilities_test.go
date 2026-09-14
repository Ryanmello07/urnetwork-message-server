package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
)

// §4.3.1's advertisement, as the property §10.2 makes it: **a value an operator sets in
// `message.yml` is a value a client is told.**
//
// This is the half of "configuration, loaded rather than printed" that a printed configuration
// cannot give. `operator_host`, `hosting_jurisdiction` and `read_key_window_seconds` have no other
// consumer in this build at all — nothing enforces them, nothing prunes on them — so if they do
// not reach `Capabilities` they reach nobody, and the configuration surface is decoration.

// Every §10.2 setting that §4.3.1 has a field for carries its configured value into the
// advertisement, and the settings §4.3.1 has no field for are PRINTED rather than left implicit.
//
// The complement is the point of the second half. A table of six advertised settings is a table
// that silently stops covering a seventh; a table that also names the four it does not cover, and
// fails when the two sets do not partition `settings()`, cannot.
func TestEverySpecB102SettingSpecB431AdvertisesReachesTheAdvertisement(t *testing.T) {
	advertised := map[string]struct {
		configure func(*configuration)
		read      func(*protocol.Capabilities) uint64
		want      uint64
	}{
		"read_key_window_seconds": {
			func(c *configuration) { c.readKeyWindowSeconds = 4242 },
			func(c *protocol.Capabilities) uint64 { return uint64(c.GetReadKeyWindowSeconds()) },
			4242,
		},
		"durable_ttl_default_seconds": {
			func(c *configuration) { c.durableTtlDefaultSeconds = 5353 },
			func(c *protocol.Capabilities) uint64 { return uint64(c.GetDurableTtlDefaultSeconds()) },
			5353,
		},
		"durable_ttl_max_seconds": {
			func(c *configuration) { c.durableTtlMaxSeconds = 6464 },
			func(c *protocol.Capabilities) uint64 { return uint64(c.GetDurableTtlMaxSeconds()) },
			6464,
		},
	}
	// the two string-valued ones, which the shape above cannot carry
	advertisedText := map[string]struct {
		configure func(*configuration)
		read      func(*protocol.Capabilities) string
		want      string
	}{
		"operator_host": {
			func(c *configuration) { c.operatorHost = "advertised.example" },
			func(c *protocol.Capabilities) string { return c.GetOperatorHost() },
			"advertised.example",
		},
		"hosting_jurisdiction": {
			func(c *configuration) { c.hostingJurisdiction = "advertised-jurisdiction" },
			func(c *protocol.Capabilities) string { return c.GetHostingJurisdiction() },
			"advertised-jurisdiction",
		},
	}

	// §4.3.1 has no field for these, and each is a gap this build declares rather than a value it
	// forgot. `rendezvous_*` and `card_tombstone_seconds` are server-side limits §4.3.11 answers
	// with reason codes rather than advertising; `diagnostic_session_max_minutes` is §11.5's own.
	unadvertised := []string{
		"rendezvous_ttl_seconds",
		"rendezvous_deposit_ttl_seconds",
		"rendezvous_mailbox_depth",
		"card_tombstone_seconds",
		"diagnostic_session_max_minutes",
	}

	for _, item := range settings() {
		_, carried := advertised[item.name]
		_, carriedText := advertisedText[item.name]
		if carried || carriedText {
			continue
		}
		if !slices.Contains(unadvertised, item.name) {
			t.Fatalf("§10.2's %s is in neither table: this test does not say whether §4.3.1 advertises it, and a setting nobody can observe is a setting that may reach nothing at all",
				item.name)
		}
	}
	for _, name := range unadvertised {
		if !slices.ContainsFunc(settings(), func(item setting) bool { return item.name == name }) {
			t.Fatalf("%s is named as unadvertised and is not a §10.2 setting any more", name)
		}
	}
	t.Logf("§10.2 settings §4.3.1 does not advertise: %s", strings.Join(unadvertised, " "))

	for name, current := range advertised {
		t.Run(name, func(t *testing.T) {
			loaded := defaultConfiguration()
			current.configure(&loaded)
			built := (&server{config: loaded}).capabilities()
			if got := current.read(built); got != current.want {
				t.Fatalf("%s was configured %d and Capabilities advertises %d", name, current.want, got)
			}
		})
	}
	for name, current := range advertisedText {
		t.Run(name, func(t *testing.T) {
			loaded := defaultConfiguration()
			current.configure(&loaded)
			built := (&server{config: loaded}).capabilities()
			if got := current.read(built); got != current.want {
				t.Fatalf("%s was configured %q and Capabilities advertises %q", name, current.want, got)
			}
		})
	}
}

// The two ladders §4.3.1 advertises are `connect/message`'s own, walked rather than copied.
//
// A literal here would be a second copy of a ladder §5.1 check 3 enforces as an EQUALITY: the two
// would agree the day they were written, and the disagreement would surface as one size of record
// being refused for no reason a client could see.
func TestTheAdvertisedLaddersAreConnectMessagesOwn(t *testing.T) {
	sizes := sizeBucketLadder()
	if len(sizes) == 0 {
		t.Fatal("the size ladder is empty, so §4.3.1 advertises no rung and a client cannot pick one")
	}
	for bucket, advertised := range sizes {
		if want := message.SizeBucketBytes(message.SizeBucket(bucket)); int(advertised) != want {
			t.Fatalf("size bucket %d is advertised as %d and connect/message answers %d", bucket, advertised, want)
		}
	}
	// and it stopped at the ladder's end rather than before it
	if message.SizeBucketBytes(message.SizeBucket(len(sizes))) >= 0 {
		t.Fatalf("the size ladder was cut at %d rungs and connect/message still answers for rung %d", len(sizes), len(sizes))
	}

	windows := ephBucketLadder()
	if len(windows) == 0 {
		t.Fatal("the eph ladder is empty")
	}
	// bucket 0's window is ZERO and not absent: the transient rung is never persisted, so nought
	// seconds is its true window. A walk that stopped on a falsy answer rather than on a negative
	// one would advertise an empty ladder, and before m1's M1-27 ruling it would have been right to
	if windows[0] != 0 {
		t.Fatalf("eph bucket 0 is advertised as %d; §7.6's transient rung is never persisted and its window is 0", windows[0])
	}
	if len(windows) < 2 {
		t.Fatal("the eph ladder holds only the transient rung, so the walk stopped on bucket 0's zero rather than on a negative")
	}
	for bucket, advertised := range windows {
		if want := message.EphBucketSeconds(uint8(bucket)); int(advertised) != want {
			t.Fatalf("eph bucket %d is advertised as %d and connect/message answers %d", bucket, advertised, want)
		}
	}
	if message.EphBucketSeconds(uint8(len(windows))) >= 0 {
		t.Fatalf("the eph ladder was cut at %d rungs and connect/message still answers for rung %d", len(windows), len(windows))
	}
}

// `capability_version` is zero, and that is §10.2 being told the truth.
//
// §10.2 makes it monotonic and bumped on every reload of `message.yml`. This build does not watch
// the file, so there is nothing to bump; a 1 here would advertise a version that never changes as
// though it did, and §10.2's fleet-convergence rule — an instance whose version is lower than the
// stored one refuses readiness — would then be comparing two constants.
func TestCapabilityVersionIsZeroWhileNothingReloads(t *testing.T) {
	built := (&server{config: defaultConfiguration()}).capabilities()
	if built.GetCapabilityVersion() != 0 {
		t.Fatalf("capability_version is advertised as %d and nothing in this build reloads message.yml or bumps it",
			built.GetCapabilityVersion())
	}
	if built.GetAttestationSupported() {
		t.Fatal("attestation_supported is advertised true and §9.1 keeps every signing key off every replica; there is no sidecar here to sign a FetchAttestation")
	}
}
