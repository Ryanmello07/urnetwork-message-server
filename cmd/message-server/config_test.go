package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// §10.2's `message.yml`, as the property it has to hold: **a value written in the file is the
// value this process runs on, and a value nobody can write is not a setting.**
//
// Both halves are needed and the second is the one that rots. A settings table that only PRINTS
// is a table the loader drifts from — add a field to [configuration], add it to the print list,
// forget the loader, and the value loads as its default, prints as its default, and reads
// correctly on every run and in every screenshot. Nothing but a class derived from the struct
// itself catches that, which is what the first test below is.

// Every field of [configuration] is written by exactly one setting, and every setting writes
// exactly one field.
//
// Derived from the struct rather than from a list: the class is `reflect.TypeOf(configuration{})`
// and the count comes from the type, so a field added tomorrow is a failure here on the day it is
// added rather than a value an operator cannot set.
//
// It is written as "which fields moved" rather than as a pointer comparison on purpose. What it
// asserts is the behaviour — this setting's `read` changed this field and no other — and a
// setting that wrote two fields, or wrote the wrong one, fails it. A pointer comparison would
// assert only that the entry POINTS at a field, which a `read` that ignores its own field
// accessor would pass.
func TestEverySettableFieldOfTheConfigurationIsWrittenByExactlyOneSetting(t *testing.T) {
	shape := reflect.TypeOf(configuration{})
	written := map[int]string{}

	for _, item := range settings() {
		var target configuration
		// a value that is non-zero in either shape, so "did this field move" is the same
		// question for a string field and for an int64 one
		if err := item.read(&target, "1"); err != nil {
			t.Fatalf("%s: read of the value 1: %v", item.name, err)
		}
		var moved []int
		mirror := reflect.ValueOf(&target).Elem()
		for index := range shape.NumField() {
			if !mirror.Field(index).IsZero() {
				moved = append(moved, index)
			}
		}
		if len(moved) != 1 {
			var names []string
			for _, index := range moved {
				names = append(names, shape.Field(index).Name)
			}
			t.Fatalf("%s wrote %d fields of the configuration (%s); a setting reads one §10.2 key and writes the one field it is the setting for",
				item.name, len(moved), strings.Join(names, ", "))
		}
		if previous, taken := written[moved[0]]; taken {
			t.Fatalf("%s and %s both write configuration.%s, so one of them is a §10.2 key that silently overwrites the other",
				previous, item.name, shape.Field(moved[0]).Name)
		}
		written[moved[0]] = item.name
	}

	for index := range shape.NumField() {
		if _, covered := written[index]; !covered {
			t.Fatalf("configuration.%s is written by no setting, so §10.2 gives no key for it: this process runs on its default, prints its default, and an operator cannot change it. %d of %d fields are covered",
				shape.Field(index).Name, len(written), shape.NumField())
		}
	}
}

// A value written in `message.yml` is the value this process runs on, for every §10.2 key.
//
// The loop is over `settings()` and not over a list typed here, for the same reason as above: a
// key added to §10.2 without a loader entry is caught by the test above, and a key with an entry
// that does not read the file is caught by this one.
func TestAValueInMessageYmlIsTheValueTheProcessRunsOn(t *testing.T) {
	for _, item := range settings() {
		t.Run(item.name, func(t *testing.T) {
			base := defaultConfiguration()
			written := distinctFrom(item.print(&base))

			file := writeResource(t, messageResource, fmt.Sprintf("%s: %s\n", item.name, written))
			loaded, err := loadConfiguration(file, noEnvironment)
			if err != nil {
				t.Fatalf("loadConfiguration: %v", err)
			}
			if got := item.print(&loaded); got != written {
				t.Fatalf("%s was written %q in message.yml and this process would run on %q", item.name, written, got)
			}
			// and nothing else moved: a loader that assigned to the wrong field would pass the
			// line above only if it also read it back from the wrong field, which the test above
			// rules out, but a loader that reset a SECOND key to its zero would pass both
			for _, other := range settings() {
				if other.name == item.name {
					continue
				}
				if got, want := other.print(&loaded), other.print(&base); got != want {
					t.Fatalf("writing %s changed %s from %q to %q", item.name, other.name, want, got)
				}
			}
		})
	}
}

// The environment overrides the file, for every §10.2 key.
//
// §10.1 deploys this in a container: the file is baked into an image or a ConfigMap and the
// environment is the one thing an operator can change for one instance without rebuilding either.
// A loader with the precedence the other way round is a loader whose override silently does
// nothing.
func TestTheEnvironmentOverridesMessageYml(t *testing.T) {
	for _, item := range settings() {
		t.Run(item.name, func(t *testing.T) {
			base := defaultConfiguration()
			inFile := distinctFrom(item.print(&base))
			inEnvironment := distinctFrom(inFile)

			file := writeResource(t, messageResource, fmt.Sprintf("%s: %s\n", item.name, inFile))
			variable := environmentNameOf(item.name)
			loaded, err := loadConfiguration(file, func(name string) (string, bool) {
				if name == variable {
					return inEnvironment, true
				}
				return "", false
			})
			if err != nil {
				t.Fatalf("loadConfiguration: %v", err)
			}
			if got := item.print(&loaded); got != inEnvironment {
				t.Fatalf("%s is %q in message.yml and %q in %s, and this process would run on %q",
					item.name, inFile, inEnvironment, variable, got)
			}
		})
	}
}

// A key `message.yml` holds that no §10.2 setting claims is an error.
//
// It is the operator's typo, and it is the one config failure that has no other symptom: the
// value they meant to set is not set, the server runs on a default, and the file loaded without
// complaint. §10.1 exists because of exactly this class — "an advertised jurisdiction nobody set
// is worse than no answer at all" — and a `hosting_juristiction:` that loads silently is that
// sentence with the operator believing they have answered.
func TestAKeyNoSettingClaimsIsRefusedRatherThanIgnored(t *testing.T) {
	file := writeResource(t, messageResource, "hosting_juristiction: DE\noperator_host: ur.network\n")
	loaded, err := loadConfiguration(file, noEnvironment)
	if !errors.Is(err, errUnknownSetting) {
		t.Fatalf("a misspelled key loaded with %v; the process would run with hosting_jurisdiction unset and nothing would say so", err)
	}
	if !strings.Contains(err.Error(), "hosting_juristiction") {
		t.Fatalf("the refusal does not name the key that was not read: %v", err)
	}
	// and the correctly spelled key beside it is not what made it fail
	_ = loaded
}

// Every §10.2 value that is a count or a duration refuses what is not one.
//
// Negative is refused as well as non-numeric, and it is the half worth having: §7.1's prune
// arithmetic is `stored_at + ttl`, and a negative TTL is a prune time in the past — a
// configuration that deletes every record the sweep touches, with no parse error anywhere.
func TestANumberSettingRefusesWhatIsNotANonNegativeNumber(t *testing.T) {
	for _, item := range settings() {
		base := defaultConfiguration()
		// the text settings take any string by construction; the class here is the settings
		// whose printed default is a number, derived rather than listed
		if item.read(&base, "not a number") == nil {
			continue
		}
		t.Run(item.name, func(t *testing.T) {
			for _, bad := range []string{"not a number", "-1", "1.5", "", "0x10"} {
				var target configuration
				if err := item.read(&target, bad); err == nil {
					t.Fatalf("%s accepted %q", item.name, bad)
				}
			}
			var target configuration
			if err := item.read(&target, "0"); err != nil {
				t.Fatalf("%s refused 0, which is §10.2's own value for durable_ttl_max_seconds: %v", item.name, err)
			}
		})
	}
}

// §10.2's defaults are the numbers §10.2 prints, and an absent file changes none of them.
//
// The point is the second half. A loader given no file at all must produce the same configuration
// as a loader given an empty one, or "the resource is not mounted" and "the resource is mounted
// and empty" are two different servers.
func TestAnAbsentMessageYmlIsTheSameAsAnEmptyOne(t *testing.T) {
	absent, _, err := readResource(filepath.Join(t.TempDir(), messageResource))
	if err != nil {
		t.Fatalf("readResource on a file that does not exist: %v", err)
	}
	fromAbsent, err := loadConfiguration(absent, noEnvironment)
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	fromEmpty, err := loadConfiguration(writeResource(t, messageResource, ""), noEnvironment)
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	if fromAbsent != fromEmpty || fromAbsent != defaultConfiguration() {
		t.Fatalf("absent, empty and default are three different configurations:\n absent %+v\n empty  %+v\n spec   %+v",
			fromAbsent, fromEmpty, defaultConfiguration())
	}
}

// §7.3's limits carry §10.2's two durable values into the store.
//
// The clamp of §6.1 step (6) is evaluated against [store.Limits], so a `durable_ttl_max_seconds`
// that reached the printed configuration and not the store is a fleet cap an operator set and the
// database ignored — visible only as a retention a group ends up with months later.
func TestTheDurableLimitsReachTheStore(t *testing.T) {
	loaded := defaultConfiguration()
	loaded.durableTtlDefaultSeconds = 4242
	loaded.durableTtlMaxSeconds = 8484

	limits := limitsOf(loaded)
	if limits.DurableTtlDefaultSeconds != 4242 {
		t.Fatalf("durable_ttl_default_seconds reached the store as %d, want 4242", limits.DurableTtlDefaultSeconds)
	}
	if limits.DurableTtlMaxSeconds != 8484 {
		t.Fatalf("durable_ttl_max_seconds reached the store as %d, want 8484", limits.DurableTtlMaxSeconds)
	}
}

// ── the fixtures ─────────────────────────────────────────────────────────────────────────

// A resource file in a directory of this test's own, read back through the real reader.
func writeResource(t *testing.T, name string, contents string) *resource {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	file, present, err := readResource(path)
	if err != nil {
		t.Fatalf("readResource(%s): %v", name, err)
	}
	if !present {
		t.Fatalf("%s was written and readResource says it is not there", name)
	}
	return file
}

// A value that is not the one given, in whichever shape the one given is.
//
// A test that wrote a value equal to the default would assert nothing: the loader could ignore
// the file entirely and still print the number the test expects.
func distinctFrom(value string) string {
	if value == "" {
		return "a-value-no-default-has"
	}
	if _, err := fmt.Sscanf(value, "%d", new(int64)); err == nil {
		var number int64
		fmt.Sscanf(value, "%d", &number)
		return fmt.Sprint(number + 7)
	}
	return value + "-changed"
}

// An environment that holds nothing, for the tests that are about the file.
func noEnvironment(string) (string, bool) { return "", false }
