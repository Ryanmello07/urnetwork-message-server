package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
)

// §10.2's vault resources and §9.1's ordinal selection, as the properties they carry.
//
//  1. **The DSN is the one hard requirement.** §2.3 makes Postgres authoritative; a process that
//     started without one would come up, refuse readiness, and be a container an operator has to
//     exec into to find out it was never pointed at a database.
//  2. **This replica's `client_id` is read out of its credential, never configured beside it.**
//     The platform authenticates the credential and routes to the id inside it; an id written in
//     a file that disagrees is an id clients address and nothing answers on.
//  3. **A secret is never in an error.** Two of the four values here are secrets and the third
//     carries one.

// §9.1: "The process reads MESSAGE_SERVER_ORDINAL from the environment and selects that keyed
// entry from message_server.yml."
//
// Two ordinals in one file, and each selects its own. A loader that read the first entry, or the
// last, passes a fixture with one ordinal in it — which is the fixture somebody writes.
func TestTheOrdinalSelectsItsOwnEntryFromMessageServerYml(t *testing.T) {
	zero, zeroId := unsignedCredential(t)
	one, oneId := unsignedCredential(t)
	directory := resourceDirectory(t, map[string]string{
		pgResource:            "dsn: postgres://x/y\n",
		messageServerResource: "0.by_jwt: " + zero + "\n1.by_jwt: " + one + "\n",
	})

	for _, current := range []struct {
		ordinal string
		want    connect.Id
	}{{"0", zeroId}, {"1", oneId}} {
		t.Run("ordinal "+current.ordinal, func(t *testing.T) {
			loaded, _, err := loadDeployment(environment(map[string]string{
				resourceDirVariable: directory,
				ordinalVariable:     current.ordinal,
			}))
			if err != nil {
				t.Fatalf("loadDeployment: %v", err)
			}
			if loaded.clientId != current.want {
				t.Fatalf("ordinal %s selected client_id %v, want the one in its own entry (%v)",
					current.ordinal, loaded.clientId, current.want)
			}
		})
	}

	// an ordinal with no entry is not a startup failure — §9.1 says "/readyz fails if the ordinal
	// has no credential", which is a refusal and not a crash
	loaded, _, err := loadDeployment(environment(map[string]string{
		resourceDirVariable: directory,
		ordinalVariable:     "7",
	}))
	if err != nil {
		t.Fatalf("an ordinal with no entry failed startup: %v; §9.1 makes it a readiness refusal", err)
	}
	if loaded.byJwt != "" {
		t.Fatal("an ordinal with no entry picked up somebody else's credential")
	}
}

// This replica's `client_id` comes out of the credential, and a `client_id` written beside it is
// checked rather than believed.
//
// The platform routes to the id inside the credential it authenticated. An id in a file that
// disagrees is the id §9.3's discovery would publish and clients would address, answered by
// nothing — and the symptom is every client timing out against a replica whose own logs say it is
// connected.
func TestTheClientIdComesOutOfTheCredentialAndADisagreeingOneIsRefused(t *testing.T) {
	credential, identity := unsignedCredential(t)

	agreeing := resourceDirectory(t, map[string]string{
		pgResource:            "dsn: postgres://x/y\n",
		messageServerResource: "0.by_jwt: " + credential + "\n0.client_id: " + identity.String() + "\n",
	})
	loaded, _, err := loadDeployment(environment(map[string]string{resourceDirVariable: agreeing}))
	if err != nil {
		t.Fatalf("a client_id that agrees with the credential was refused: %v", err)
	}
	if loaded.clientId != identity {
		t.Fatalf("client_id loaded as %v, want %v", loaded.clientId, identity)
	}

	other := connect.NewId()
	disagreeing := resourceDirectory(t, map[string]string{
		pgResource:            "dsn: postgres://x/y\n",
		messageServerResource: "0.by_jwt: " + credential + "\n0.client_id: " + other.String() + "\n",
	})
	if _, _, err := loadDeployment(environment(map[string]string{resourceDirVariable: disagreeing})); err == nil {
		t.Fatal("a client_id written beside the credential that is not the one inside it was accepted")
	}
}

// A credential with no `client_id` claim is refused.
//
// [connect.ParseByJwtUnverified] does not fail on a claim it cannot read — it leaves the field at
// its zero — so a credential with no `client_id` arrives as `Id{}`, sixteen zero bytes, which
// `connect` would then use as this replica's address. Every frame for the all-zero id would route
// to whatever else in the network holds it.
func TestACredentialWithNoClientIdIsRefused(t *testing.T) {
	blank := jwtWithClaims(t, map[string]any{"network_name": "urmessage"})
	directory := resourceDirectory(t, map[string]string{
		pgResource:            "dsn: postgres://x/y\n",
		messageServerResource: "0.by_jwt: " + blank + "\n",
	})
	_, _, err := loadDeployment(environment(map[string]string{resourceDirVariable: directory}))
	if !errors.Is(err, errJwtNoClientId) {
		t.Fatalf("a credential carrying no client_id was answered %v, want %v; it would otherwise be this replica's address, and it is sixteen zero bytes",
			err, errJwtNoClientId)
	}
}

// No DSN is a startup failure, not a readiness refusal.
//
// §2.3 makes Postgres authoritative and there is nothing at all for this process to serve without
// it. A replica that came up anyway would be a container whose only symptom is a red probe.
func TestNoDsnIsAStartupFailure(t *testing.T) {
	directory := resourceDirectory(t, map[string]string{messageResource: "operator_host: ur.network\n"})
	_, _, err := loadDeployment(environment(map[string]string{resourceDirVariable: directory}))
	if !errors.Is(err, errResourceMissing) {
		t.Fatalf("a deployment with no DSN started, and answered %v", err)
	}
}

// Every secret this loader reads stays out of every error it returns.
//
// The class is the three secrets, and each is made to fail in the way that produces an error: a
// DSN that does not parse, a KEK that is the wrong length, a credential that is not a JWT.
func TestNoSecretReachesAnError(t *testing.T) {
	const (
		secretDsn = "postgres://u:secret-password-zzz@h/db"
		secretKek = "abcdef-not-hex-secret-zzz"
		secretJwt = "not.a.jwt-secret-zzz"
	)
	for _, current := range []struct {
		what   string
		files  map[string]string
		secret string
	}{
		{"a KEK that is not hexadecimal", map[string]string{
			pgResource:    "dsn: postgres://x/y\n",
			fleetResource: "write_key_kek: " + secretKek + "\n",
		}, secretKek},
		{"a KEK of the wrong length", map[string]string{
			pgResource:    "dsn: postgres://x/y\n",
			fleetResource: "write_key_kek: " + hex.EncodeToString([]byte("short")) + "\n",
		}, hex.EncodeToString([]byte("short"))},
		{"a credential that is not a JWT", map[string]string{
			pgResource:            "dsn: postgres://x/y\n",
			messageServerResource: "0.by_jwt: " + secretJwt + "\n",
		}, secretJwt},
		{"a DSN that does not parse", map[string]string{
			pgResource: "dsn: " + secretDsn + "\n",
		}, "secret-password-zzz"},
	} {
		t.Run(current.what, func(t *testing.T) {
			directory := resourceDirectory(t, current.files)
			_, _, err := loadDeployment(environment(map[string]string{resourceDirVariable: directory}))
			if err == nil {
				// the DSN case loads here and fails in newServer; its refusal is asserted by
				// TestADsnThatDoesNotParseIsRefusedWithoutBeingPrinted
				return
			}
			if strings.Contains(err.Error(), current.secret) {
				t.Fatalf("%s put the value in the error, and an operator pastes a startup error into a ticket: %v", current.what, err)
			}
		})
	}
}

// A DSN that does not parse is refused, and pgx's own message — which quotes the DSN — is not
// what the operator is shown.
func TestADsnThatDoesNotParseIsRefusedWithoutBeingPrinted(t *testing.T) {
	const secret = "secret-password-zzz"
	_, err := newServer(t.Context(), deployment{
		ordinal: "0",
		dsn:     "this is not a DSN at all " + secret,
	}, defaultConfiguration(), discardLog())
	if err == nil {
		t.Fatal("a DSN that does not parse produced a running server")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the refusal printed the DSN, which carries a password: %v", err)
	}
}

// `server_id` and the KEK are exact-width, and a value of the wrong width is refused where it is
// read rather than by whatever consumes it.
//
// §4.3.1 puts `server_id` in every HelloResponse; a short one is advertised to every client and
// pinned. The KEK's own refusal comes from crypto/aes and says "invalid key size 31", which does
// not tell an operator which file to open.
func TestAnExactWidthValueOfTheWrongWidthIsRefused(t *testing.T) {
	for _, current := range []struct {
		key     string
		correct int
	}{{"server_id", serverIdBytes}, {"write_key_kek", kekBytes}} {
		t.Run(current.key, func(t *testing.T) {
			for _, width := range []int{current.correct - 1, current.correct + 1} {
				directory := resourceDirectory(t, map[string]string{
					pgResource:    "dsn: postgres://x/y\n",
					fleetResource: current.key + ": " + hex.EncodeToString(make([]byte, width)) + "\n",
				})
				_, _, err := loadDeployment(environment(map[string]string{resourceDirVariable: directory}))
				if !errors.Is(err, errWrongLength) {
					t.Fatalf("%s at %d octets was answered %v, want %v", current.key, width, err, errWrongLength)
				}
			}
			directory := resourceDirectory(t, map[string]string{
				pgResource:    "dsn: postgres://x/y\n",
				fleetResource: current.key + ": " + hex.EncodeToString(make([]byte, current.correct)) + "\n",
			})
			if _, _, err := loadDeployment(environment(map[string]string{resourceDirVariable: directory})); err != nil {
				t.Fatalf("%s at its own width was refused: %v", current.key, err)
			}
		})
	}
}

// ── the fixtures ─────────────────────────────────────────────────────────────────────────

// A directory holding the named §10.2 resources.
func resourceDirectory(t *testing.T, files map[string]string) string {
	t.Helper()
	directory := t.TempDir()
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	return directory
}

// An environment that holds exactly these names.
func environment(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, found := values[name]
		return value, found
	}
}

// A transport credential carrying a `client_id`, and the id inside it.
//
// Unsigned, because [connect.ParseByJwtUnverified] is what reads it and it parses without
// verifying — which is the whole of what this process does with the credential. Signing it would
// assert something about a key nothing here holds.
func unsignedCredential(t *testing.T) (string, connect.Id) {
	t.Helper()
	identity := connect.NewId()
	return jwtWithClaims(t, map[string]any{
		"client_id":    identity.String(),
		"network_name": "urmessage",
	}), identity
}

func jwtWithClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encoding a JWT segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	header := encode(map[string]any{"alg": "HS256", "typ": "JWT"})
	return header + "." + encode(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
}
