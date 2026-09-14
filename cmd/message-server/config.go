package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/store"
)

// The §10.2 `message.yml` values this process runs on, with that section's defaults.
//
// This is config, never a constant in code: §10.2 is normative that changing an advertised value
// must not require a release, so the defaults live in one struct that [loadConfiguration]
// overwrites whole.
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

// One `message.yml` value: its §10.2 name, how it is read out of the file, and how it is printed
// back.
//
// The read and the print are both here on purpose. A settings table that only prints is a table
// a loader can drift from — a field added to [configuration] and to the print list and not to
// the loader loads as its default, prints as its default, and looks correct on every run.
// TestEverySettableFieldOfTheConfigurationIsWrittenByExactlyOneSetting derives its class from
// [configuration]'s own fields, so a field with no entry here fails rather than becoming a value
// nobody can set — and it asserts the BEHAVIOUR, which field of the struct this entry's `read`
// actually moves, rather than a pointer the entry merely carries.
type setting struct {
	name  string
	note  string
	read  func(target *configuration, value string) error
	print func(source *configuration) string
}

// A §10.2 key whose value is a string.
func textSetting(name string, note string, field func(*configuration) *string) setting {
	return setting{
		name: name,
		note: note,
		read: func(target *configuration, value string) error {
			*field(target) = value
			return nil
		},
		print: func(source *configuration) string { return *field(source) },
	}
}

// A §10.2 key whose value is a count or a duration in seconds. Negative is refused rather than
// stored: no §10.2 value has a meaning below zero, and a negative TTL reaches §7.1's arithmetic
// as a prune time in the past.
func numberSetting(name string, note string, field func(*configuration) *int64) setting {
	return setting{
		name: name,
		note: note,
		read: func(target *configuration, value string) error {
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return errNotAnInteger
			}
			if parsed < 0 {
				return errNegative
			}
			*field(target) = parsed
			return nil
		},
		print: func(source *configuration) string { return strconv.FormatInt(*field(source), 10) },
	}
}

var (
	errNotAnInteger = errors.New("not an integer")
	errNegative     = errors.New("negative, and no §10.2 value is")
)

// Every §10.2 key, in the order §10.2 lists them.
func settings() []setting {
	return []setting{
		textSetting("operator_host",
			"the operator this server holds its account on (§9.1); /readyz refuses until it is set (§10.1)",
			func(c *configuration) *string { return &c.operatorHost }),
		textSetting("hosting_jurisdiction",
			"advertised to clients in Capabilities (§4.3.1); /readyz refuses until it is set (§10.1)",
			func(c *configuration) *string { return &c.hostingJurisdiction }),
		numberSetting("read_key_window_seconds",
			"90 days; a write key is still retired after 60 s (§5.3)",
			func(c *configuration) *int64 { return &c.readKeyWindowSeconds }),
		numberSetting("durable_ttl_default_seconds",
			"1 year, the DURABLE default when a group asks for none (§7.3)",
			func(c *configuration) *int64 { return &c.durableTtlDefaultSeconds }),
		numberSetting("durable_ttl_max_seconds",
			"0 means no fleet cap, and stores NULL rather than a clamp (§7.3)",
			func(c *configuration) *int64 { return &c.durableTtlMaxSeconds }),
		numberSetting("rendezvous_ttl_seconds",
			"§4.3.7",
			func(c *configuration) *int64 { return &c.rendezvousTtlSeconds }),
		numberSetting("rendezvous_deposit_ttl_seconds",
			"7 days (§4.3.7)",
			func(c *configuration) *int64 { return &c.rendezvousDepositTtlSeconds }),
		numberSetting("rendezvous_mailbox_depth",
			"the 17th uncollected deposit is refused (§13.38)",
			func(c *configuration) *int64 { return &c.rendezvousMailboxDepth }),
		numberSetting("card_tombstone_seconds",
			"a retired id answers identically until the sweep reclaims it (§13.39)",
			func(c *configuration) *int64 { return &c.cardTombstoneSeconds }),
		numberSetting("diagnostic_session_max_minutes",
			"the one bounded exception to §11.1 (§11.5)",
			func(c *configuration) *int64 { return &c.diagnosticSessionMaxMinutes }),
	}
}

// The environment variable one `message.yml` key is overridden by.
//
// Environment beats file, because §10.1 deploys this in a container: the file is baked into an
// image or a ConfigMap, and the environment is what an operator can change for one instance
// without rebuilding either.
func environmentNameOf(key string) string {
	return "URMESSAGE_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(key))
}

// A key in `message.yml` that no §10.2 setting claims. It is an error and not a warning: the
// value an operator meant to set is not set, the server runs on a default, and the only evidence
// either way is a line in a file that loaded without complaint.
var errUnknownSetting = errors.New("no §10.2 setting has this name; a misspelled key would otherwise load as a default")

// §10.2's `message.yml`, read from a file and then from the environment.
//
// `lookupEnvironment` is a parameter so that a test can run the whole loader without writing to
// the process environment, which no test running in parallel with another may do.
func loadConfiguration(file *resource, lookupEnvironment func(string) (string, bool)) (configuration, error) {
	loaded := defaultConfiguration()
	known := map[string]bool{}
	for _, item := range settings() {
		known[item.name] = true
		if value, found := file.lookup(item.name); found {
			if err := item.read(&loaded, value); err != nil {
				return loaded, fmt.Errorf("%s: %s is %w", file.path, item.name, err)
			}
		}
		if value, found := lookupEnvironment(environmentNameOf(item.name)); found {
			if err := item.read(&loaded, value); err != nil {
				return loaded, fmt.Errorf("%s: %s is %w", environmentNameOf(item.name), item.name, err)
			}
		}
	}
	if unknown := file.unread(known); 0 < len(unknown) {
		return loaded, fmt.Errorf("%s: %w: %s", file.path, errUnknownSetting, strings.Join(unknown, ", "))
	}
	return loaded, nil
}

// What this process prints about its own configuration, one line per §10.2 key.
func (self configuration) lines() []string {
	var printed []string
	for _, item := range settings() {
		value := item.print(&self)
		if value == "" {
			value = "(unset)"
		}
		printed = append(printed, fmt.Sprintf("%-32s %-12s %s", item.name, value, item.note))
	}
	return printed
}

// §7.3's limits, from §10.2's values.
//
// Two of the five come from `message.yml`, because §10.2 names those two and no others. The media
// pair and the durable floor keep [store.DefaultLimits]'s §7.3 numbers, and that is a gap rather
// than a decision — see [configurationNotWired], which says so where an operator reads it.
func limitsOf(loaded configuration) store.Limits {
	limits := store.DefaultLimits()
	limits.DurableTtlDefaultSeconds = uint32(loaded.durableTtlDefaultSeconds)
	limits.DurableTtlMaxSeconds = uint32(loaded.durableTtlMaxSeconds)
	return limits
}

// The §10.2 values this build loads, prints, and then does nothing with, because the machinery
// that would read them is not built.
//
// Every one of these is a number an operator can set and watch have no effect. Saying so is the
// difference between a configuration surface and a configuration surface that lies: §10.1's
// readiness endpoint prints this list, so "I set it and nothing happened" is answered by the
// server rather than by a bisect.
var configurationNotWired = []api.NotBuilt{
	{Section: "§5.3", What: "read_key_window_seconds is loaded and ADVERTISED in Capabilities, and nothing retires a key on it: there is no sweep, so the number a client is told is a promise this build does not keep", Owner: "sweep"},
	{Section: "§4.3.7", What: "rendezvous_ttl_seconds, rendezvous_deposit_ttl_seconds and rendezvous_mailbox_depth are loaded and no rendezvous arm is served", Owner: "api"},
	{Section: "§13.39", What: "card_tombstone_seconds is loaded and nothing tombstones a retired id", Owner: "sweep"},
	{Section: "§11.5", What: "diagnostic_session_max_minutes is loaded and no diagnostic session can be opened", Owner: "api"},
	{Section: "§7.3", What: "the media TTL pair and durable_retention_min_seconds are not §10.2 keys, so the media clamp runs on store.DefaultLimits and cannot be configured", Owner: "store"},
	{Section: "§10.2", What: "group_durable_override is a §10.2 key with no stated default and no consumer here; it is neither loaded nor advertised, so groups cannot raise text retention and are not told why", Owner: "store"},
	{Section: "§10.2", What: "message.yml is read once at startup and is not watched; there is no capability_version and no CapabilityChange, so changing an advertised value does require a restart", Owner: "cmd/message-server"},
	{Section: "§2.3", What: "SIGTERM closes the peer without sending Drain{reconnect_after_ms}; peer has no push path at all, so a rolling deploy reconnects the whole attached population at once", Owner: "peer"},
	{Section: "§2.4", What: "there is no Redis, so subscribe fan-out, presence and the distributed token buckets are absent and a second replica shares nothing but Postgres", Owner: "peer"},
}
