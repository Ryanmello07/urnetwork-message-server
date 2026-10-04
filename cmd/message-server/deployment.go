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

	// WHICH of §10.2's two sources supplied each value above that has two.
	//
	// It is recorded because the printed line used to name the file for a value the environment
	// supplied, and that is not a cosmetic error. §9.1 requires one `network_client` per ordinal;
	// `URMESSAGE_BY_JWT` is one variable for the whole process and [pick] prefers the environment
	// for EVERY ordinal, so a single Kubernetes Secret or a shared systemd EnvironmentFile gives
	// all N replicas the same `client_id` — and the one line an operator would use to notice said
	// `message_server.yml present ordinal 99` for an ordinal that file has no entry for.
	dsnSource      source
	kekSource      source
	serverIdSource source
	byJwtSource    source
}

// Where a §10.2 value came from. Every one of them can come from a file or from the environment,
// and "the environment wins" is the documented rule — so the question an operator debugging a
// deployment has is not what the value is but which of the two won, which is the question nothing
// here could answer.
type source uint8

const (
	sourceAbsent source = iota
	sourceFile
	sourceEnvironment
)

func (self source) String() string {
	switch self {
	case sourceFile:
		return "present (file)"
	case sourceEnvironment:
		return "present (environment)"
	default:
		return "ABSENT"
	}
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
	errJwtClaimType    = errors.New("a claim in the transport credential is not the type connect's parser asserts it to be (network_name, user_id, network_id and client_id are read as strings); the credential is not printed here, and the claim that is wrong is in whoever minted it")
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
	loaded.dsn, loaded.dsnSource = pick(postgres, "dsn", lookupEnvironment, dsnVariable)

	// §2.3 makes Postgres authoritative, so a deployment with no DSN cannot serve — but the
	// refusal is HELD to the end of this function rather than returned here, and that is F4.
	//
	// `--print-config` is documented as "the one mode an operator does first on a new box —
	// confirm the process can see its configuration, BEFORE it has a database to point at", and it
	// could not run on a box in that state: `run` called this function first and a missing DSN was
	// a hard return. Returning here also truncates the answer — `message_fleet.yml` and
	// `message_server.yml` are read below — so an early return would have made --print-config
	// print ABSENT for three resources it had not looked at, which is a worse answer than an
	// error. The error is built now, while the path that produced it is in hand, and returned at
	// the bottom with everything else loaded.
	var missingDsn error
	if loaded.dsn == "" {
		missingDsn = fmt.Errorf("%w: %s has no `dsn` and %s is unset; §2.3 makes Postgres authoritative and there is nothing to serve without it",
			errResourceMissing, filepath.Join(loaded.resourceDir, pgResource), dsnVariable)
	}

	fleet, _, err := readResource(filepath.Join(loaded.resourceDir, fleetResource))
	if err != nil {
		return loaded, message, err
	}
	if value, from := pick(fleet, "write_key_kek", lookupEnvironment, kekVariable); value != "" {
		loaded.kek, err = fixedHex(value, kekBytes, "write_key_kek")
		if err != nil {
			return loaded, message, err
		}
		loaded.kekSource = from
	}
	if value, _ := pick(fleet, "write_key_kek_id", lookupEnvironment, kekIdVariable); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 8)
		if err != nil {
			return loaded, message, fmt.Errorf("%s: write_key_kek_id is not an integer in 0..255", fleetResource)
		}
		loaded.kekId = uint8(parsed)
	}
	if value, from := pick(fleet, "server_id", lookupEnvironment, serverIdVariable); value != "" {
		loaded.serverId, err = fixedHex(value, serverIdBytes, "server_id")
		if err != nil {
			return loaded, message, err
		}
		loaded.serverIdSource = from
	}

	credentials, _, err := readResource(filepath.Join(loaded.resourceDir, messageServerResource))
	if err != nil {
		return loaded, message, err
	}
	loaded.byJwt, loaded.byJwtSource = pick(credentials, loaded.ordinal+".by_jwt", lookupEnvironment, byJwtVariable)
	if loaded.byJwt != "" {
		parsed, err := parseCredential(loaded.byJwt)
		if err != nil {
			if errors.Is(err, errJwtClaimType) {
				// a named startup failure, in the same shape as the guard below it, and carrying
				// no part of the credential
				return loaded, message, fmt.Errorf("ordinal %s: %w", loaded.ordinal, err)
			}
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
	return loaded, message, missingDsn
}

// [connect.ParseByJwtUnverified], with the panic it can take turned into a named refusal.
//
// `connect/jwt.go:31` reads `claims["network_name"].(string)` with no comma-ok, so a credential
// whose `network_name` claim is a number — or a bool, or an object — takes the process down with
// `panic: interface conversion: interface {} is float64, not string`. The same shape applies to
// `user_id`, `network_id` and `client_id`, which are asserted to string before ParseId sees them.
// That fires inside `--print-config`, which the ops document calls the first thing to run on a new
// box: a mistyped config file kills the process with a stack trace instead of a sentence.
//
// **`connect` is read-only from this repository, so the defence is here and the repair is
// reported.** This is deliberately the same shape as [errJwtNoClientId], the guard immediately
// below its call site, which covers the sibling defect in the same forty lines — a claim
// ParseByJwtUnverified silently drops rather than one it asserts. Two defects, one function, one
// style of refusal.
//
// The recovered value is never put in the error. A type-assertion panic carries no secret today,
// but a panic from a future claim reader could carry a fragment of the credential, and the rule
// this file keeps is that no error it returns contains any part of one.
func parseCredential(byJwt string) (parsed *connect.ByJwt, err error) {
	defer func() {
		if recover() != nil {
			parsed, err = nil, errJwtClaimType
		}
	}()
	return connect.ParseByJwtUnverified(byJwt)
}

// One value, from the environment if it is there and from the resource file otherwise, and which
// of the two it was.
//
// The second return is not optional at any call site. A value whose source is not recorded is a
// value [deployment.lines] has to guess about, and the guess it used to make — "it is in the file
// this key belongs to" — is wrong exactly when it matters most, because the environment is where a
// fleet-wide secret comes from.
func pick(file *resource, key string, lookupEnvironment func(string) (string, bool), variable string) (string, source) {
	if value, found := lookupEnvironment(variable); found && value != "" {
		return value, sourceEnvironment
	}
	value, _ := file.lookup(key)
	if value == "" {
		return "", sourceAbsent
	}
	return value, sourceFile
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
	lines := []string{
		fmt.Sprintf("%-22s %-22s %s", "resource directory", "", self.resourceDir),
		fmt.Sprintf("%-22s %-22s ordinal %s (%s)", messageServerResource, self.byJwtSource, self.ordinal, ordinalVariable),
		fmt.Sprintf("%-22s %-22s %s", pgResource, self.dsnSource, "postgres connection, message-server cluster (decision B10: not the operator's)"),
		fmt.Sprintf("%-22s %-22s %s", fleetResource, self.kekSource, "write_key_kek (§5.5)"),
		fmt.Sprintf("%-22s %-22s %s", fleetResource, self.serverIdSource, "server_id, 16 octets, stable per fleet (§4.3.1)"),
		fmt.Sprintf("%-22s %-22s %s", messageResource, "", "the §10.2 values below"),
	}
	if warning := self.ordinalCredentialWarning(); warning != "" {
		lines = append(lines, warning)
	}
	return lines
}

// §9.1's one-credential-per-ordinal rule, when the deployment has quietly defeated it.
//
// `URMESSAGE_BY_JWT` is ONE variable for the whole process and [pick] prefers the environment for
// EVERY ordinal, so the same Kubernetes Secret or systemd EnvironmentFile mounted across a
// StatefulSet gives every replica the same credential and therefore the same `client_id`. §9.1
// requires one `network_client` per ordinal. Nothing refused, nothing warned, and the one printed
// line said `message_server.yml present ordinal 99` — naming the file, for an ordinal that file
// has no entry for at all.
//
// It is a warning and not a refusal, and the line is where it is: the ops document offers
// `URMESSAGE_BY_JWT` as the single-instance way to hold the credential, which is legitimate, and a
// single process cannot see how many siblings share its environment. What it CAN see is that the
// credential it is about to use came from a variable that is fleet-wide by nature, and it can say
// so on every start and in `--print-config`.
func (self deployment) ordinalCredentialWarning() string {
	if self.byJwtSource != sourceEnvironment {
		return ""
	}
	return fmt.Sprintf("%-22s %-22s this ordinal's credential came from %s, which is ONE value for the whole process: §9.1 requires one network_client per ordinal, and N replicas sharing this variable share a client_id",
		messageServerResource, "WARNING", byJwtVariable)
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
