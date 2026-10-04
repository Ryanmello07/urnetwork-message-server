package api

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The THIRD copy of MASTER §8's sender formula, held to the same table as the other two.
//
// Ledger item 193 names three sites for one formula and calls this one "deliberate and not part
// of the question" — the fixture writes the arithmetic out because a check whose two sides come
// from one function is a check that cannot fail. That reason is sound and this file does not
// touch it. What item 193's *Blocks* line then said was that all three copies AGREE, which was
// false: this copy and `harness`'s both collapsed `seconds <= 0`, so both answered window 0 for
// a bucket that names no rung where `connect/messagegroup.EphWindowAt` refuses.
//
// Being deliberate is not the same as being unchecked. The fixture keeps its own arithmetic and
// is driven over the shared answers, which is what this file does.
//
// WHY THE READER IS HERE AGAIN AND NOT IMPORTED. `harness` has one, but `api` may not import
// `harness`: api/doc.go's `//urmsg:mayimport store blobd redact metrics` says so, and
// TestNothingThisPackageCanReachHoldsASecondImplementation measures it — "3 packages of this
// module are reachable from api: [api blobd store]". What is duplicated is a reader for three
// whitespace-separated columns. What is NOT duplicated is the table, which is the thing whose
// drift item 193 is about.
const apiEphKatPath = "../testdata/eph-window-kat.txt"

// The table's shape, pinned here by NUMBER rather than by digest, and the reason is a gate in
// this very package.
//
// `harness/ephkat_test.go` pins the table with a SHA-256 over its canonical bytes, and this file
// cannot: §12.1 A-1 says api uses connect/message's published surface and nothing else, and two
// gates here enforce it over the derived class {crypto/hkdf, crypto/hmac, crypto/sha256,
// crypto/subtle, connect/mls/syntax}. A first draft of this file imported crypto/sha256 for the
// digest and BOTH gates went red on it — correctly. An exemption would have been the laundering
// TestNothingThisPackageCanReachHoldsASecondImplementation's own failure message warns about.
//
// So the cryptographic pin lives in one package and this one pins the table's SHAPE: how many
// rows it has and how many of them take each refusal. That is weaker than a digest and is
// enough for what it has to catch here — a table quietly shrunk to the rows this copy happens to
// pass, which is the way a known-answer table stops being one. A silent EDIT to a row's answer
// is caught in `harness` by the digest, and on the other side of the wire by whatever connect
// pins; see ledger item 193 for what connect owes.
//
// MEASURED at the table's current contents, not carried forward: 57 rows, of which 12 answer
// ERR_EPH_BUCKET_OFF_LADDER and 5 answer ERR_EPH_WINDOW_SENT_AT.
const (
	apiEphKatRows      = 57
	apiEphKatOffLadder = 12
	apiEphKatSentAt    = 5

	katOffLadder = "ERR_EPH_BUCKET_OFF_LADDER"
	katSentAt    = "ERR_EPH_WINDOW_SENT_AT"
)

// Every row of the shared known-answer table is the answer the fixture's copy gives.
//
// Fatals rather than skips on a table it cannot read: a gate whose input vanished reports the
// same clean pass as a gate whose property holds.
func TestTheFixturesCopyOfTheSenderFormulaAnswersTheSharedKAT(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(apiEphKatPath))
	if err != nil {
		t.Fatalf("the shared known-answer table could not be read, so this gate has no input at all: %v", err)
	}
	canonical := strings.ReplaceAll(string(raw), "\r\n", "\n")

	rows := 0
	refusals := map[string]int{}
	for index, text := range strings.Split(canonical, "\n") {
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 3 {
			t.Fatalf("%s:%d has %d fields and every row of this table has three: %q", apiEphKatPath, index+1, len(fields), trimmed)
		}
		bucket, err := strconv.ParseUint(fields[0], 10, 8)
		if err != nil {
			t.Fatalf("%s:%d does not name a bucket byte: %v", apiEphKatPath, index+1, err)
		}
		sentAtMs, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("%s:%d does not name a sent_at_ms reading: %v", apiEphKatPath, index+1, err)
		}
		rows++

		window, refused := ephWindowAnswer(uint8(bucket), sentAtMs)
		measured := refused
		if refused == "" {
			measured = strconv.FormatUint(window, 10)
		} else {
			refusals[refused]++
		}
		if measured != fields[2] {
			t.Errorf("%s:%d says (bucket %d, sent_at_ms %d) -> %s, and the fixture's copy answered %s",
				apiEphKatPath, index+1, bucket, sentAtMs, fields[2], measured)
		}
	}

	// The shape, asserted rather than logged. Each of these is a way the table stops being a
	// known-answer table without any row of it ever disagreeing with this copy.
	if rows != apiEphKatRows {
		t.Errorf("%s holds %d rows and this file pins %d; if the table grew or shrank on purpose, re-measure the three counts here and republish the digest in harness/ephkat_test.go and in ledger item 193",
			apiEphKatPath, rows, apiEphKatRows)
	}
	if refusals[katOffLadder] != apiEphKatOffLadder {
		t.Errorf("%d rows of %s answer %s and this file pins %d; the off-ladder rows are the ones that pin the ORDER of the two guards, which is what drifted",
			refusals[katOffLadder], apiEphKatPath, katOffLadder, apiEphKatOffLadder)
	}
	if refusals[katSentAt] != apiEphKatSentAt {
		t.Errorf("%d rows of %s answer %s and this file pins %d", refusals[katSentAt], apiEphKatPath, katSentAt, apiEphKatSentAt)
	}
	t.Logf("%d rows of %s answered by the fixture's copy; %d reached %s and %d reached %s",
		rows, apiEphKatPath, refusals[katOffLadder], katOffLadder, refusals[katSentAt], katSentAt)
}
