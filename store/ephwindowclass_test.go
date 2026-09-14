package store

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// §3.2's class half of the `eph_window` CHECK, stated over every retention-class byte there is.
//
// WHY THIS TEST EXISTS, which is a measurement and not a preference. Until 2026-09-13 this
// predicate lived inline in [validateRecord] and **could not be killed by any mutation of it**.
// `validateRecord` returns [ErrTransientRecord] for `RetentionClass == ClassEphBase` several lines
// above the window block, and `ClassEphBase` is the ONLY class the `<` / `<=` distinction changes,
// so widening it to `ClassEphBase <=` left the entire repository green — including the pgx
// contract against a real PostgreSQL. The ledger had published that mutant as *"killed at the API
// layer and at the DDL"*. It was killed at neither; what is killed there are two DIFFERENT mutants
// (`api/submit.go`'s, by a panic, and migration 010's, by a named row). This is the assertion that
// kills the mutant itself.
//
// WHAT IT ASSERTS, and both halves are derived rather than typed. The class is every byte a
// `uint8` holds, 256 of them, from the width. The predicate partitions them, and BOTH SIDES are
// named: the allowed side must be exactly `ClassEphBase+1 .. ClassEphMax`, which is 17..21 and is
// what migration 010's `17 <= retention_class AND retention_class <= 21` says in SQL; the refused
// side — the COMPLEMENT — is asserted member for member against the set derived from those two
// constants, printed in full, counted, and failing closed if it is ever empty.
//
// THE MEMBER THAT MATTERS IS 16. MASTER §8's presence rule is phrased on the CLASSES and §3.2's
// CHECK on the WIRE BYTES, and the two agree only because `EPH(0)` is `0x10` = 16, one below the
// range, in the must-be-zero half with `PERMANENT`, `DURABLE` and `MEDIA`. That reading has been
// published inverted in this corpus once already (ledger item 189), so `ClassEphBase` is asserted
// to be in the complement by name, not left to be inferred from a count.
func TestTheEphWindowClassPredicateIsExactlyTheWireRange17To21(t *testing.T) {
	allowed := []uint8{}
	refused := []uint8{}
	for candidate := 0; candidate < 256; candidate++ {
		class := uint8(candidate)
		if ephWindowClassAllows(class) {
			allowed = append(allowed, class)
			continue
		}
		refused = append(refused, class)
	}
	if total := len(allowed) + len(refused); total != 256 {
		t.Fatalf("the predicate answered for %d of the 256 class bytes a uint8 holds", total)
	}

	// The allowed side, derived from the two constants the DDL is written from.
	wantAllowed := []uint8{}
	for class := ClassEphBase + 1; class <= ClassEphMax; class++ {
		wantAllowed = append(wantAllowed, class)
	}
	if len(wantAllowed) == 0 {
		t.Fatalf("ClassEphBase is %d and ClassEphMax is %d, so the windowed range is empty and this gate derived nothing", ClassEphBase, ClassEphMax)
	}
	if !slices.Equal(allowed, wantAllowed) {
		t.Errorf("§3.2's CHECK admits a window on exactly the wire bytes 17..21; this predicate admits %v and the range is %v", allowed, wantAllowed)
	}

	// The complement, named member for member rather than counted.
	wantRefused := []uint8{}
	for candidate := 0; candidate < 256; candidate++ {
		class := uint8(candidate)
		if !slices.Contains(wantAllowed, class) {
			wantRefused = append(wantRefused, class)
		}
	}
	if len(wantRefused) == 0 {
		t.Fatalf("every one of the 256 class bytes is in the windowed range, so this gate's complement is empty and it asserts nothing")
	}
	if want := 256 - len(wantAllowed); len(wantRefused) != want {
		t.Fatalf("the derived complement holds %d class bytes and the arithmetic says %d", len(wantRefused), want)
	}
	if !slices.Equal(refused, wantRefused) {
		t.Errorf("the complement of §3.2's CHECK is %d class bytes and this predicate refuses %d; the symmetric difference is %v",
			len(wantRefused), len(refused), symmetricDifference(refused, wantRefused))
	}

	// The member the whole arithmetic turns on, asserted by name and not left to the count.
	if slices.Contains(allowed, ClassEphBase) {
		t.Errorf("EPH(0) is ClassEphBase = 0x%02X = %d, which is OUTSIDE 17..21, and MASTER §8's presence rule puts it in the must-be-zero half with PERMANENT, DURABLE and MEDIA; this predicate admits a window on it",
			ClassEphBase, ClassEphBase)
	}
	for _, class := range []uint8{ClassPermanent, ClassDurable, ClassMedia, ClassEphBase, ClassEphMax + 1, 0xFF} {
		if ephWindowClassAllows(class) != slices.Contains(wantAllowed, class) {
			t.Errorf("class byte 0x%02X is on the wrong side of §3.2's CHECK", class)
		}
	}

	t.Logf("§3.2's CHECK admits %d class bytes %v; the COMPLEMENT is the other %d, and every one of them is refused: %s",
		len(allowed), allowed, len(refused), nameBytes(refused))
}

func symmetricDifference(left, right []uint8) []uint8 {
	out := []uint8{}
	for _, value := range left {
		if !slices.Contains(right, value) {
			out = append(out, value)
		}
	}
	for _, value := range right {
		if !slices.Contains(left, value) {
			out = append(out, value)
		}
	}
	return out
}

// nameBytes prints a set of class bytes as contiguous runs, so a 251-member complement is readable
// as what it is rather than as a wall of integers. It names every member: a run is its endpoints.
func nameBytes(values []uint8) string {
	if len(values) == 0 {
		return "(empty)"
	}
	runs := []string{}
	start, previous := values[0], values[0]
	flush := func() {
		if start == previous {
			runs = append(runs, fmt.Sprintf("%d", start))
			return
		}
		runs = append(runs, fmt.Sprintf("%d-%d", start, previous))
	}
	for _, value := range values[1:] {
		if value == previous+1 {
			previous = value
			continue
		}
		flush()
		start, previous = value, value
	}
	flush()
	return strings.Join(runs, ", ")
}
