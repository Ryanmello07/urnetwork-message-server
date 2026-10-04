package peer

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/api"
)

// ── the coverage of §5.1's front checks ──────────────────────────────────────────────────

// Every check §5.1 puts in front of the pipeline is performed here or declared unbuilt, and none
// is both.
//
// Both ends are derived. The set of front checks is [api.ChecksNotImplemented]'s own list, which
// is the type that owns them when nobody performs any; a fourth front check added to api arrives
// in that list and has to be accounted for here. The numbers are checked against §5.1's table in
// the spec document, so a number this package claims that §5.1 does not have is a failure rather
// than a line nobody reads.
func TestEveryFrontCheckOfSpecB51IsPerformedOrDeclared(t *testing.T) {
	specified := checkNumbersOfSpecB51(t)
	t.Logf("§5.1 numbers %d checks: %v", len(specified), specified)

	front := []int{}
	for _, entry := range (api.ChecksNotImplemented{}).NotBuilt() {
		front = append(front, entry.Check)
	}
	slices.Sort(front)
	if len(front) == 0 {
		t.Fatal("api.ChecksNotImplemented declares no check at all, so this gate has no class to work from")
	}
	t.Logf("§5.1 puts %v in front of the pipeline; this build performs %v", front, performedChecks)

	checks, err := NewChecks(newTestConnections(t), DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	declared := []int{}
	for _, entry := range checks.NotBuilt() {
		declared = append(declared, entry.Check)
	}
	slices.Sort(declared)

	for _, number := range front {
		performed := slices.Contains(performedChecks, number)
		named := slices.Contains(declared, number)
		switch {
		case performed && named:
			t.Fatalf("§5.1 check %d is both performed and declared unrun, so one of the two is a lie", number)
		case !performed && !named:
			t.Fatalf("§5.1 check %d is neither performed (%v) nor declared unrun (%v); a skipped check that looks like a passed check is how a pipeline ships with a hole",
				number, performedChecks, declared)
		}
	}
	for _, number := range append(append([]int{}, performedChecks...), declared...) {
		if !slices.Contains(specified, number) {
			t.Fatalf("this package claims a check %d that §5.1 does not number: %v", number, specified)
		}
		if !slices.Contains(front, number) {
			t.Fatalf("this package claims check %d, which §5.1 does not put in front of the pipeline: %v", number, front)
		}
	}
}

// Check 2's declaration still names the dependency decision B1 makes unverifiable here.
//
// peer performs half of check 2, and the risk in performing half of something is that the other
// half is tidied away with the entry that described it. §5.1's own paragraph calls the `ByJwt`
// half "an explicit, named dependency on the operator transport, with an owner on the operator
// side — not an assumption", and this is the one list §10.1's readiness endpoint reads.
func TestCheckTwosDeclarationStillNamesTheByJwtDependency(t *testing.T) {
	checks, err := NewChecks(newTestConnections(t), DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	for _, entry := range checks.NotBuilt() {
		if entry.Check != 2 {
			continue
		}
		for _, wanted := range []string{"ByJwt", "source.SourceId", "B1"} {
			if !strings.Contains(entry.What, wanted) {
				t.Fatalf("§5.1 check 2's declaration does not name %q: %s", wanted, entry.What)
			}
		}
		if !strings.Contains(entry.What, "server_nonce") {
			t.Fatalf("§5.1 check 2's declaration does not say which half this package does perform: %s", entry.What)
		}
		return
	}
	t.Fatalf("§5.1 check 2 is not declared at all: %v", checks.NotBuilt())
}

// ── the checks themselves ────────────────────────────────────────────────────────────────

// Check 1 answers REASON_INTERNAL, never REASON_OK, when it cannot see what it is checking.
//
// This is the anti-tautology in [api.FrontChecks]'s own words: "not called" and "called and
// passed" are the same green test. A check 1 that answered REASON_OK on a request carrying no
// measurement would pass every test in this repository on a build that had stopped measuring.
func TestCheckOneFailsClosedWhenItCannotSeeItsInput(t *testing.T) {
	checks, err := NewChecks(newTestConnections(t), DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	if reason := checks.FrameWithinLimits(context.Background(), &api.Connection{}); reason != protocol.Reason_REASON_INTERNAL {
		t.Fatalf("check 1 with no measurement in the context answered %v, want REASON_INTERNAL", reason)
	}
	ctx := withInbound(context.Background(), &inbound{bytes: 10})
	if reason := checks.FrameWithinLimits(ctx, &api.Connection{}); reason != protocol.Reason_REASON_OK {
		t.Fatalf("check 1 on a ten byte request against a %d byte cap answered %v", DefaultMaxRequestBytes, reason)
	}
}

// Check 2 refuses a nonce that is not the connection's own.
//
// The dispatcher builds every [api.Connection] out of [Connection.ApiConnection], so this cannot
// be reached by anything a client sends today. That is exactly why it is here: it is what makes a
// dispatcher that started sourcing the nonce from somewhere the client can influence fail a test
// instead of verifying MACs against a value an attacker picked.
func TestCheckTwoRefusesANonceThatIsNotTheConnectionsOwn(t *testing.T) {
	connections := newTestConnections(t)
	checks, err := NewChecks(connections, DefaultMaxRequestBytes)
	if err != nil {
		t.Fatalf("NewChecks: %v", err)
	}
	clientId := connect.NewId()
	connection, err := connections.Open(clientId)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx := withInbound(context.Background(), &inbound{clientId: clientId, connection: connection, bytes: 10})

	if reason := checks.ConnectionAuthenticated(ctx, connection.ApiConnection()); reason != protocol.Reason_REASON_OK {
		t.Fatalf("check 2 refused the connection's own nonce: %v", reason)
	}
	for _, wrong := range [][]byte{
		nil,
		{},
		bytes.Repeat([]byte{0}, ServerNonceBytes),
		flippedLastByte(connection.ServerNonce()),
		append(connection.ServerNonce(), 0x00),
	} {
		if reason := checks.ConnectionAuthenticated(ctx, &api.Connection{ServerNonce: wrong, ClientId: clientId.Bytes()}); reason != protocol.Reason_REASON_REJECTED {
			t.Fatalf("check 2 answered %v for a %d byte nonce that is not this connection's", reason, len(wrong))
		}
	}

	// and a request that reached the pipeline on no connection at all
	if reason := checks.ConnectionAuthenticated(context.Background(), connection.ApiConnection()); reason != protocol.Reason_REASON_REJECTED {
		t.Fatalf("check 2 with no connection in the context answered %v, want REASON_REJECTED", reason)
	}
}

func newTestConnections(t *testing.T) *Connections {
	t.Helper()
	connections, err := NewConnections(rand.Reader, time.Now, 0)
	if err != nil {
		t.Fatalf("NewConnections: %v", err)
	}
	return connections
}

// ── §5.1's table, read out of the spec ───────────────────────────────────────────────────

// The check numbers §5.1's own table carries.
//
// The same parse api's checks_test.go makes, and it is here rather than shared because a test
// file is not an importable package. What it must not become is a list: the numbers come out of
// the document, so a tenth check added to §5.1 is a number this package neither performs nor
// declares, and this fails instead of staying green on a table it never read.
func checkNumbersOfSpecB51(t *testing.T) []int {
	t.Helper()
	name, document := specBDocument(t)
	lines := strings.Split(document, "\n")

	heading := -1
	for number, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "### 5.1 ") {
			if heading != -1 {
				t.Fatalf("%s carries two §5.1 headings and this gate would have to choose between them", name)
			}
			heading = number
		}
	}
	if heading == -1 {
		t.Fatalf("%s carries no '### 5.1 ' heading, so §5.1's table has moved or been reworded and this gate would have read nothing", name)
	}

	numbers := []int{}
	started := false
	for number := heading + 1; number < len(lines); number++ {
		line := strings.TrimSpace(lines[number])
		if strings.HasPrefix(line, "#") {
			break
		}
		if !strings.HasPrefix(line, "|") {
			if started {
				break
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		value, err := strconv.Atoi(strings.TrimSpace(cells[0]))
		if err != nil {
			continue
		}
		started = true
		numbers = append(numbers, value)
	}
	if len(numbers) < 9 {
		t.Fatalf("%s: §5.1's table was read as having %d numbered checks, and it has nine", name, len(numbers))
	}
	return numbers
}

// Spec B, read from the repository it is committed in.
func specBDocument(t *testing.T) (string, string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join("..", "docs", "specs", "*spec-b-message-server-operator.md"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("looking for spec B under docs/specs: %d matches, %v", len(matches), err)
	}
	text, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("reading %s: %v", matches[0], err)
	}
	// carriage returns first: this repository is developed where core.autocrlf is true at system
	// scope, and a parser anchored on "\n" reads a CRLF document as one malformed line — which is
	// a gate reporting a clean run having read nothing
	return matches[0], strings.ReplaceAll(string(text), "\r\n", "\n")
}

// The connection's own nonce with its last byte changed.
//
// Flipped, not overwritten with a constant. This list is of nonces that are *not* this
// connection's, and setting the last byte to zero produces this connection's own nonce whenever
// the CSPRNG's last byte was already zero — which is one run in every 256, and is what a
// once-in-a-while red suite on this test turned out to be.
func flippedLastByte(nonce []byte) []byte {
	changed := append([]byte(nil), nonce...)
	changed[len(changed)-1] ^= 0xFF
	return changed
}
