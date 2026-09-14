package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
)

// The shared known-answer table for MASTER §8's sender formula, and what it is FOR.
//
// MASTER §8's window formula exists at more than one site, and the duplication is forced by the
// dependency rule rather than chosen: Spec B §2.2 allows this module `connect/message` and
// `connect/protocol` and nothing else, so [EphWindowAt] here cannot link
// `connect/messagegroup.EphWindowAt`, which is the same function for the shipped sender. A test
// that called both and compared them is the test this repository may not write. Ledger item 193
// files that, and its *Blocks* line used to say the copies "agree today, by inspection" — which
// was false when it was written. They disagreed on 9 of 32 probed `(bucket, sent_at_ms)` pairs,
// because this copy collapsed `seconds <= 0` and answered window 0 for a bucket that names no
// rung, where the shipped sender refuses.
//
// WHAT CROSSES A FORBIDDEN IMPORT IS A VALUE. `testdata/eph-window-kat.txt` at the root of this
// module is one table of answers, computed from §8's sentence rather than from either
// implementation, and each copy of the formula is driven over it in its own repository. This
// file is msgrepo's half and it binds msgrepo's two copies. `connect` owes the other half, and
// NOTHING HERE CAN MAKE CONNECT'S HALF RED — that boundary is the honest limit of this gate and
// is stated in ledger item 193 beside what is owed.
const ephKatPath = "../testdata/eph-window-kat.txt"

// The table's digest over its CANONICAL bytes — CRLF folded to LF before hashing.
//
// Not over the raw bytes. `.gitattributes` pins `*.txt` to `eol=lf` in THIS repository, but the
// point of this table is that another repository carries it too, and connect's checkout rules
// are not this repository's to set. A digest that changed with the checkout would be a digest
// that says "the table drifted" on a clean clone, and the response to that is always to delete
// the assertion.
//
// MEASURED, not typed from memory: sha256 of testdata/eph-window-kat.txt with \r\n -> \n.
const ephKatDigest = "f6ef2ae645294a085ae88705209b756578f403029dcd0e0f5b2ef726e897712a"

// The refusal names the table uses. They name the SENTINEL and not the message text, because
// the two repositories prefix their messages differently on purpose ("harness: …" against
// "messagegroup: …") and a table that compared prose would be a table that cannot be shared.
const (
	katOffLadder = "ERR_EPH_BUCKET_OFF_LADDER"
	katSentAt    = "ERR_EPH_WINDOW_SENT_AT"
)

type ephKatRow struct {
	line     int
	bucket   uint8
	sentAtMs int64
	// Exactly one of these is set: a window, or the name of a refusal.
	window uint64
	refuse string
}

func (self ephKatRow) answer() string {
	if self.refuse != "" {
		return self.refuse
	}
	return strconv.FormatUint(self.window, 10)
}

func (self ephKatRow) String() string {
	return fmt.Sprintf("(bucket %d, sent_at_ms %d) -> %s [%s:%d]", self.bucket, self.sentAtMs, self.answer(), ephKatPath, self.line)
}

// readEphKat parses the table, and fatals rather than skipping on every way it can fail to read
// one. A missing or unparseable table must end the run: a gate whose input vanished reports the
// same clean pass as a gate whose property holds, and that is the failure mode this repository
// has already paid for once.
func readEphKat(t *testing.T) []ephKatRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(ephKatPath))
	if err != nil {
		t.Fatalf("the shared known-answer table could not be read, so this gate has no input at all: %v", err)
	}
	canonical := strings.ReplaceAll(string(raw), "\r\n", "\n")

	sum := sha256.Sum256([]byte(canonical))
	if measured := hex.EncodeToString(sum[:]); measured != ephKatDigest {
		t.Fatalf("the shared known-answer table's digest is %s and this file pins %s; the table is one half of a pair the dependency rule will not let a test compare, so an edit to it here is an edit connect cannot see. If the change is deliberate, make it in BOTH repositories and republish the digest in ledger item 193",
			measured, ephKatDigest)
	}

	rows := []ephKatRow{}
	for index, text := range strings.Split(canonical, "\n") {
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 3 {
			t.Fatalf("%s:%d has %d fields and every row of this table has three: %q", ephKatPath, index+1, len(fields), trimmed)
		}
		bucket, err := strconv.ParseUint(fields[0], 10, 8)
		if err != nil {
			t.Fatalf("%s:%d does not name a bucket byte: %v", ephKatPath, index+1, err)
		}
		sentAtMs, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("%s:%d does not name a sent_at_ms reading: %v", ephKatPath, index+1, err)
		}
		row := ephKatRow{line: index + 1, bucket: uint8(bucket), sentAtMs: sentAtMs}
		switch fields[2] {
		case katOffLadder, katSentAt:
			row.refuse = fields[2]
		default:
			window, err := strconv.ParseUint(fields[2], 10, 64)
			if err != nil {
				t.Fatalf("%s:%d's answer is neither a window nor one of %q / %q: %v", ephKatPath, index+1, katOffLadder, katSentAt, err)
			}
			row.window = window
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		t.Fatalf("%s parsed to no rows at all, so this gate read nothing", ephKatPath)
	}
	return rows
}

// katAnswerOf names what [EphWindowAt] answered, in the table's own vocabulary.
func katAnswerOf(window uint64, err error) string {
	switch {
	case errors.Is(err, ErrEphBucketOffLadder):
		return katOffLadder
	case errors.Is(err, ErrEphWindowSentAt):
		return katSentAt
	case err != nil:
		return "unclassified refusal: " + err.Error()
	}
	return strconv.FormatUint(window, 10)
}

// Every row of the shared table is the answer this copy of MASTER §8's formula gives.
//
// The mutation this is written against is the one that actually shipped: collapsing `seconds < 0`
// and `seconds == 0` into one `seconds <= 0` branch, or testing the clock reading before the
// ladder. Either puts rows of this table red — the count is in the ledger's edit log beside the
// command that measured it, not asserted here, because a test that asserted how many of its own
// rows a mutant breaks would be a test asserting a property of the mutant.
func TestTheSenderFormulaAnswersTheSharedKAT(t *testing.T) {
	rows := readEphKat(t)
	for _, row := range rows {
		measured := katAnswerOf(EphWindowAt(row.bucket, row.sentAtMs))
		if measured != row.answer() {
			t.Errorf("%s, and this copy answered %s", row, measured)
		}
	}
	t.Logf("%d rows of %s answered by harness.EphWindowAt", len(rows), ephKatPath)
}

// The table is a SAMPLE of a domain it cannot enumerate, so here is what it leaves out, named
// and asserted rather than left for a reader to worry about.
//
// The class is every bucket byte a uint8 can hold: 256 members, derived from the width and not
// typed. The ladder has rungs for some of them, and [message.EphBucketSeconds] is the one place
// that says which — so the partition is read off the ladder, and a rung added upstream moves it
// here without an edit.
//
// WHAT THIS ASSERTS, in order: the table names every bucket that HAS a rung, because a rung the
// table never exercises is a divisor nothing pins; the complement — the off-ladder bytes the
// table does NOT name — is non-empty, is exactly 256 minus the rungs minus the off-ladder bytes
// the table does name, and every one of its members is refused with the same sentinel the named
// ones are, at both signs of the reading, which is where the ORDER of the two guards shows. The
// complement is printed with its members, because a complement whose size is asserted and whose
// membership is never shown is the shape that hid a five-of-seventeen in this corpus already.
func TestTheKatsComplementOverTheBucketClassIsNamedAndRefused(t *testing.T) {
	rows := readEphKat(t)

	rungs := []uint8{}
	offLadder := []uint8{}
	for candidate := 0; candidate < 256; candidate++ {
		bucket := uint8(candidate)
		if 0 <= message.EphBucketSeconds(bucket) {
			rungs = append(rungs, bucket)
			continue
		}
		offLadder = append(offLadder, bucket)
	}
	if len(rungs) == 0 || len(offLadder) == 0 {
		t.Fatalf("the eph ladder partitions no bucket byte at all (%d rungs, %d off the ladder), so this gate read nothing", len(rungs), len(offLadder))
	}
	if total := len(rungs) + len(offLadder); total != 256 {
		t.Fatalf("the partition covers %d of the 256 bucket bytes a uint8 holds", total)
	}

	named := []uint8{}
	for _, row := range rows {
		if !slices.Contains(named, row.bucket) {
			named = append(named, row.bucket)
		}
	}
	slices.Sort(named)

	// Half one: every rung is exercised.
	missingRungs := []uint8{}
	for _, rung := range rungs {
		if !slices.Contains(named, rung) {
			missingRungs = append(missingRungs, rung)
		}
	}
	if 0 < len(missingRungs) {
		t.Errorf("%s exercises %d of the ladder's %d rungs and names none of %v; every rung's divisor has to be pinned by a value or it is pinned by nothing",
			ephKatPath, len(rungs)-len(missingRungs), len(rungs), missingRungs)
	}

	// Half two: the complement, named, counted, asserted, and failing closed when empty.
	namedOffLadder := []uint8{}
	complement := []uint8{}
	for _, bucket := range offLadder {
		if slices.Contains(named, bucket) {
			namedOffLadder = append(namedOffLadder, bucket)
			continue
		}
		complement = append(complement, bucket)
	}
	if len(complement) == 0 {
		t.Fatalf("the table names every one of the %d off-ladder bucket bytes, so this gate's complement is empty and it asserts nothing; if the table really did grow to cover all 256, delete this half rather than leave it green over nothing", len(offLadder))
	}
	if want := 256 - len(rungs) - len(namedOffLadder); len(complement) != want {
		t.Errorf("the complement holds %d bucket bytes and the arithmetic says %d (256 - %d rungs - %d named off-ladder)", len(complement), want, len(rungs), len(namedOffLadder))
	}
	t.Logf("%s names %d of the %d off-ladder bucket bytes (%v); the COMPLEMENT is the remaining %d: %v",
		ephKatPath, len(namedOffLadder), len(offLadder), namedOffLadder, len(complement), complement)

	for _, bucket := range complement {
		for _, sentAtMs := range []int64{-1, 0, 1767225600000} {
			if measured := katAnswerOf(EphWindowAt(bucket, sentAtMs)); measured != katOffLadder {
				t.Errorf("bucket %d is in the table's complement and names no rung, and (bucket %d, sent_at_ms %d) answered %s rather than %s",
					bucket, bucket, sentAtMs, measured, katOffLadder)
			}
		}
	}
}
