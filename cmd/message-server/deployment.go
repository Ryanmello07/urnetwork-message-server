package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/message-server/api"
)

// The §10.2 resources this process reads, and the two §9.1 values that come from the
// environment rather than from a file.
//
// Everything here is deployment: where the database is, which KEK wraps an epoch key, which
// ordinal this replica is and what credential that ordinal holds. None of it is advertised to a
// client and three of the fields are secrets, so nothing in this file has a String method and
// nothing in this process prints one — see [deployment.lines], which prints only whether a value
// is present.
type deployment struct {
	// where the §10.2 resources are read from, and which ordinal's entry is selected (§9.1)
	resourceDir string
	ordinal     string

	// §10.1's private port. Health endpoints only: "Prometheus scrapes /metrics on a private
	// port, never on the public interface", and this process serves no /metrics at all.
	healthAddress string

	// pg.yml (vault): the message-server cluster, which decision B10 makes a different cluster
	// from the operator's. Secret — it carries a password.
	dsn string

	// message_fleet.yml (vault): §5.5's key-encryption key and the id it is stored under.
	// Secret.
	kekId uint8
	kek   []byte

	// message_fleet.yml: §4.3.1's `server_id`, 16 octets, stable per fleet. NOT a secret — it is
	// advertised in every HelloResponse — and it is here rather than in `message.yml` because
	// §9.1 is explicit that it is fleet-wide and not per-ordinal.
	serverId []byte

	// message_server.yml (vault): this ordinal's transport credential. Secret. `clientId` is
	// read out of the credential rather than configured beside it, so the two cannot disagree.
	byJwt    string
	clientId connect.Id
}

// §10.2's resource names, which are also the file names.
const (
	messageResource       = "message.yml"
	pgResource            = "pg.yml"
	fleetResource         = "message_fleet.yml"
	messageServerResource = "message_server.yml"
)

const (
	// §4.3.1: "16 B, stable per fleet".
	serverIdBytes = 16
	// §5.5 wraps under AES-256-GCM, so the KEK is 32 octets. store.KekRing refuses any other
	// length; this refuses it a second time with the resource named, because "invalid key size
	// 31" from crypto/aes does not tell an operator which file to open.
	kekBytes = 32
)

var (
	errResourceMissing = errors.New("a required §10.2 resource is not present")
	errNotHex          = errors.New("is not hexadecimal")
	errWrongLength     = errors.New("is the wrong length")
	errNoOrdinalEntry  = errors.New("message_server.yml has no entry for this ordinal (§9.1); /readyz will refuse")
	errJwtNoClientId   = errors.New("the transport credential carries no client_id claim, so this replica has no identity to route to")
)

// §9.1: "The process reads MESSAGE_SERVER_ORDINAL from the environment and selects that keyed
// entry from message_server.yml."
const ordinalVariable = "MESSAGE_SERVER_ORDINAL"

// The default ordinal. §9.1 deploys a StatefulSet, whose first pod is ordinal 0, and a single
// instance is ordinal 0 as well — so a deployment that sets nothing is the one-replica case
// rather than a startup failure.
const defaultOrdinal = "0"

// §10.1 puts the health endpoints "on a private port". Loopback rather than every interface,
// because the §10.1 sentence that follows is about what must never reach the public one, and a
// default that binds 0.0.0.0 makes an operator's firewall the only thing holding that.
const defaultHealthAddress = "127.0.0.1:9099"

// Where the §10.2 resources live. A directory rather than seven paths, because §10.2's names are
// fixed and an operator who can override each one individually is an operator who can silently
// load six of seven.
const resourceDirVariable = "URMESSAGE_RESOURCE_DIR"

// The environment names for the values that live in a vault resource. Each is here so that a
// deployment can hold a secret in the environment — which is what a Kubernetes Secret and a
// systemd `EnvironmentFile` both produce — without writing a file into the image.
const (
	dsnVariable           = "URMESSAGE_PG_DSN"
	kekVariable           = "URMESSAGE_WRITE_KEY_KEK"
	kekIdVariable         = "URMESSAGE_WRITE_KEY_KEK_ID"
	serverIdVariable      = "URMESSAGE_SERVER_ID"
	byJwtVariable         = "URMESSAGE_BY_JWT"
	healthAddressVariable = "URMESSAGE_HEALTH_ADDRESS"
)

// Read §10.2's resources and §9.1's environment.
//
// The DSN is the one hard requirement: §2.3 makes Postgres authoritative and there is nothing for
// this process to serve without it, so its absence is a startup failure rather than a readiness
// refusal. Everything else that is missing is a readiness refusal, because §10.1's endpoint
// exists precisely so that a replica can come up, say what it is missing, and be looked at.
func loadDeployment(lookupEnvironment func(string) (string, bool)) (deployment, *resource, error) {
	loaded := deployment{
		resourceDir:   ".",
		ordinal:       defaultOrdinal,
		healthAddress: defaultHealthAddress,
	}
	if value, found := lookupEnvironment(resourceDirVariable); found && value != "" {
		loaded.resourceDir = value
	}
	if value, found := lookupEnvironment(ordinalVariable); found && value != "" {
		loaded.ordinal = value
	}
	if value, found := lookupEnvironment(healthAddressVariable); found && value != "" {
		loaded.healthAddress = value
	}
	if !simpleKey(loaded.ordinal) {
		return loaded, nil, fmt.Errorf("%s: an ordinal is a key in %s and holds only a-z 0-9 . _ -", ordinalVariable, messageServerResource)
	}

	message, _, err := readResource(filepath.Join(loaded.resourceDir, messageResource))
	if err != nil {
		return loaded, nil, err
	}

	postgres, _, err := readResource(filepath.Join(loaded.resourceDir, pgResource))
	if err != nil {
		return loaded, message, err
	}
	loaded.dsn = pick(postgres, "dsn", lookupEnvironment, dsnVariable)
	if loaded.dsn == "" {
		return loaded, message, fmt.Errorf("%w: %s has no `dsn` and %s is unset; §2.3 makes Postgres authoritative and there is nothing to serve without it",
			errResourceMissing, filepath.Join(loaded.resourceDir, pgResource), dsnVariable)
	}

	fleet, _, err := readResource(filepath.Join(loaded.resourceDir, fleetResource))
	if err != nil {
		return loaded, message, err
	}
	if value := pick(fleet, "write_key_kek", lookupEnvironment, kekVariable); value != "" {
		loaded.kek, err = fixedHex(value, kekBytes, "write_key_kek")
		if err != nil {
			return loaded, message, err
		}
	}
	if value := pick(fleet, "write_key_kek_id", lookupEnvironment, kekIdVariable); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return loaded, message, fmt.Errorf("%s: write_key_kek_id is not an integer in 0..255", fleetResource)
		}
		loaded.kekId = uint8(parsed)
	}
	if value := pick(fleet, "server_id", lookupEnvironment, serverIdVariable); value != "" {
		loaded.serverId, err = fixedHex(value, serverIdBytes, "server_id")
		if err != nil {
			return loaded, message, err
		}
	}

	credentials, _, err := readResource(filepath.Join(loaded.resourceDir, messageServerResource))
	if err != nil {
		return loaded, message, err
	}
	loaded.byJwt = pick(credentials, loaded.ordinal+".by_jwt", lookupEnvironment, byJwtVariable)
	if loaded.byJwt != "" {
		parsed, err := connect.ParseByJwtUnverified(loaded.byJwt)
		if err != nil {
			// the credential is NOT in this message and must never be
			return loaded, message, fmt.Errorf("the transport credential for ordinal %s does not parse as a JWT", loaded.ordinal)
		}
		// ParseByJwtUnverified drops a claim it cannot parse instead of failing, so an absent or
		// malformed client_id arrives here as the zero Id — which connect would then use as this
		// replica's address, and every client's frames would route to whatever else holds it
		if parsed.ClientId == (connect.Id{}) {
			return loaded, message, fmt.Errorf("ordinal %s: %w", loaded.ordinal, errJwtNoClientId)
		}
		loaded.clientId = parsed.ClientId
		// §9.1 keys the entry by ordinal; a `client_id` written beside the credential is checked
		// against the one inside it rather than believed, because the credential is what the
		// platform authenticates and the file is what an operator edits
		if declared, found := credentials.lookup(loaded.ordinal + ".client_id"); found && declared != "" {
			if !strings.EqualFold(declared, parsed.ClientId.String()) {
				return loaded, message, fmt.Errorf("ordinal %s: the client_id written in %s is not the client_id inside the credential",
					loaded.ordinal, messageServerResource)
			}
		}
	}
	return loaded, message, nil
}

// One value, from the environment if it is there and from the resource file otherwise.
func pick(file *resource, key string, lookupEnvironment func(string) (string, bool), variable string) string {
	if value, found := lookupEnvironment(variable); found && value != "" {
		return value
	}
	value, _ := file.lookup(key)
	return value
}

// An exact-width hexadecimal value. The value is never in the error: two of the three callers
// are secrets.
func fixedHex(value string, width int, name string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, fmt.Errorf("%s %w", name, errNotHex)
	}
	if len(decoded) != width {
		return nil, fmt.Errorf("%s %w: %d octets, want %d", name, errWrongLength, len(decoded), width)
	}
	return decoded, nil
}

// What this process prints about its deployment: which resource holds what, and whether this
// deployment supplied it. Never a value — three of these are secrets and the fourth is a DSN
// that carries one.
func (self deployment) lines() []string {
	present := func(supplied bool) string {
		if supplied {
			return "present"
		}
		return "ABSENT"
	}
	return []string{
		fmt.Sprintf("%-22s %-14s %s", "resource directory", "", self.resourceDir),
		fmt.Sprintf("%-22s %-14s ordinal %s (%s)", messageServerResource, present(self.byJwt != ""), self.ordinal, ordinalVariable),
		fmt.Sprintf("%-22s %-14s %s", pgResource, present(self.dsn != ""), "postgres connection, message-server cluster (decision B10: not the operator's)"),
		fmt.Sprintf("%-22s %-14s %s", fleetResource, present(self.kek != nil), "write_key_kek (§5.5)"),
		fmt.Sprintf("%-22s %-14s %s", fleetResource, present(self.serverId != nil), "server_id, 16 octets, stable per fleet (§4.3.1)"),
		fmt.Sprintf("%-22s %-14s %s", messageResource, "", "the §10.2 values below"),
	}
}

// The §10.2 resources this build does not read at all, and what is missing because it does not.
//
// Naming them is the point. Four of the seven resources §10.2 lists are absent from this process,
// and the machinery behind three of them is absent too — so an operator who writes `redis.yml`
// and restarts should be told that nothing opened it, rather than discovering it when a second
// replica turns out to share no state with the first.
var deploymentNotWired = []api.NotBuilt{
	{Section: "§10.2", What: "db.yml is not read; pgxpool takes its sizing from the DSN's own pool_* keys, which is the one place it can come from", Owner: "cmd/message-server"},
	{Section: "§2.4", What: "redis.yml is not read and no Redis is opened", Owner: "peer"},
	{Section: "§8.3", What: "minio.yml is not read and no object store is opened; there is no blob plane", Owner: "blobd"},
	{Section: "§9.1", What: "message_fleet.yml's grant_kek, channel_key, signing-sidecar endpoint and fleet root public key are not read; a HelloResponse therefore carries no ServerKey and this fleet signs no FetchAttestation", Owner: "cmd/message-server"},
}

// The process environment, as [loadDeployment] and [loadConfiguration] take it.
func osEnvironment(name string) (string, bool) {
	return os.LookupEnv(name)
}
