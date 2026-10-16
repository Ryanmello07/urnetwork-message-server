package store

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message/protocol"
)

// §4.3.11's kind 4, the link box, at the STORE boundary: the five arms' storage halves and the
// live-box counter, held against both implementations by [RunContract].
//
// WHAT THIS FILE DOES NOT TEST, and it is the larger half of the arms. It does not verify a
// signature: `register_auth`, `open_auth`, `deposit_auth`, `collect_auth` and `retire_auth` are the
// api layer's, checked against the keys [LinkBoxes.LinkBox] reads before any method here is
// called. It does not pad a refusal to the reject floor, and it does not enforce the cap on live
// boxes, which the api layer reads through [LinkBoxes.LiveLinkBoxes]. Those are the identity
// plan's Task 19 (Spec B §13's tests 45 to 51). What IS this package's is what the rows hold and
// what each arm answers once its signature has passed: Task 18's three properties, and the
// answers Task 19's handlers are built over.

// The link boxes of the store the contract was handed. Both implementations keep them and
// RunContract holds each to them, so a Store that keeps none fails here by name: skipping it would
// be a narrowing that no line of the run prints.
func linkBoxesOf(t *testing.T, store Store) LinkBoxes {
	t.Helper()
	boxes, keeps := store.(LinkBoxes)
	if !keeps {
		t.Fatalf("%T is a Store and keeps no link boxes; RunContract holds every implementation to §4.3.11's kind 4 as well", store)
	}
	return boxes
}

// Every scenario's clock starts here: on the microsecond and in UTC, as a `timestamp` holds a time,
// so that a time a store hands back can be compared with the one it was handed.
var linkBoxEpoch = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// Spec B §10.2's `link_box_ttl_seconds` default, 600 seconds.
const linkBoxTtl = 600 * time.Second

func linkBoxAt(seconds int) time.Time {
	return linkBoxEpoch.Add(time.Duration(seconds) * time.Second)
}

// A registration whose four values are distinct from every other seed's.
func linkBoxRegistration(seed byte) *LinkBoxRegistration {
	return &LinkBoxRegistration{
		RendezvousId:     testBytes(RendezvousIdBytes, seed),
		DepositVerifyPub: testBytes(VerifyPubBytes, seed+1),
		CollectVerifyPub: testBytes(VerifyPubBytes, seed+2),
		PublicCt:         testBytes(LinkCardBytes, seed+3),
	}
}

// A deposit and its hash. The store does not hash a deposit, and is not asked to check one; the
// hash is the SHA-256 of the octets anyway, so that a fixture is what a caller would hand over.
func linkBoxDeposit(seed byte) ([]byte, []byte) {
	depositCt := testBytes(LinkDepositBytes, seed)
	depositHash := sha256.Sum256(depositCt)
	return depositCt, depositHash[:]
}

func registerLinkBox(t *testing.T, boxes LinkBoxes, seen *recorder, registration *LinkBoxRegistration, now time.Time) *LinkBoxRegistered {
	t.Helper()
	registered, err := boxes.RegisterLinkBox(context.Background(), registration, now, linkBoxTtl)
	if err != nil {
		t.Fatalf("RegisterLinkBox: %v", err)
	}
	seen.observe(registered.Reason)
	return registered
}

func depositLinkBox(t *testing.T, boxes LinkBoxes, seen *recorder, rendezvousId []byte, seed byte, now time.Time) *LinkBoxDeposited {
	t.Helper()
	depositCt, depositHash := linkBoxDeposit(seed)
	deposited, err := boxes.DepositLinkBox(context.Background(), rendezvousId, depositCt, depositHash, now)
	if err != nil {
		t.Fatalf("DepositLinkBox: %v", err)
	}
	seen.observe(deposited.Reason)
	return deposited
}

func collectLinkBox(t *testing.T, boxes LinkBoxes, seen *recorder, request *LinkBoxCollectRequest, now time.Time) *LinkBoxCollected {
	t.Helper()
	collected, err := boxes.CollectLinkBox(context.Background(), request, now)
	if err != nil {
		t.Fatalf("CollectLinkBox: %v", err)
	}
	seen.observe(collected.Reason)
	return collected
}

func retireLinkBox(t *testing.T, boxes LinkBoxes, seen *recorder, rendezvousId []byte, now time.Time) *LinkBoxRetired {
	t.Helper()
	retired, err := boxes.RetireLinkBox(context.Background(), rendezvousId, now)
	if err != nil {
		t.Fatalf("RetireLinkBox: %v", err)
	}
	seen.observe(retired.Reason)
	return retired
}

func lookUpLinkBox(t *testing.T, boxes LinkBoxes, rendezvousId []byte) *LinkBox {
	t.Helper()
	box, err := boxes.LinkBox(context.Background(), rendezvousId)
	if err != nil {
		t.Fatalf("LinkBox: %v", err)
	}
	return box
}

func liveLinkBoxes(t *testing.T, boxes LinkBoxes, now time.Time) uint64 {
	t.Helper()
	count, err := boxes.LiveLinkBoxes(context.Background(), now)
	if err != nil {
		t.Fatalf("LiveLinkBoxes: %v", err)
	}
	return count
}

// The deposit ids a collect returned, in order.
func depositIdsOf(collected *LinkBoxCollected) []uint64 {
	ids := []uint64{}
	for _, deposit := range collected.Deposits {
		ids = append(ids, deposit.DepositId)
	}
	return ids
}

// ── Register's one rule ──────────────────────────────────────────────────────────────────────

func contractLinkBoxRegister(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	boxes := linkBoxesOf(t, newStore(DefaultLimits()))
	registration := linkBoxRegistration(0x40)

	first := registerLinkBox(t, boxes, seen, registration, linkBoxEpoch)
	want := &LinkBoxRegistered{Reason: protocol.Reason_REASON_OK, ExpireTime: linkBoxAt(600)}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("a first registration answered %+v, want %+v: the box lives 600 seconds from its registration and holds no deposit yet", first, want)
	}
	stored := lookUpLinkBox(t, boxes, registration.RendezvousId)
	wantStored := &LinkBox{
		RendezvousId:     registration.RendezvousId,
		DepositVerifyPub: registration.DepositVerifyPub,
		CollectVerifyPub: registration.CollectVerifyPub,
		PublicCt:         registration.PublicCt,
		RegisterTime:     linkBoxEpoch,
		ExpireTime:       linkBoxAt(600),
		ReclaimAfter:     linkBoxAt(600),
	}
	if !reflect.DeepEqual(stored, wantStored) {
		t.Fatalf("the row read back as %s, want %s: 013's columns as Register wrote them, with reclaim_after at the expiry",
			describeLinkBox(stored), describeLinkBox(wantStored))
	}

	// the same three values again, while the box is live, is the client's own retry. It answers
	// REASON_OK with the box's FIXED expiry: a link box is not kept alive, so a retry five minutes
	// on must not move it, and must change nothing else either
	again := registerLinkBox(t, boxes, seen, linkBoxRegistration(0x40), linkBoxAt(300))
	if !reflect.DeepEqual(again, want) {
		t.Fatalf("the same registration five minutes on answered %+v, want %+v: the expiry is fixed at the first registration", again, want)
	}
	if after := lookUpLinkBox(t, boxes, registration.RendezvousId); !reflect.DeepEqual(after, stored) {
		t.Fatalf("a repeated registration changed the row from %s to %s", describeLinkBox(stored), describeLinkBox(after))
	}

	// any other row at the id is REJECTED, whichever of the three values differs, and the answer
	// carries nothing beside the reason
	refused := &LinkBoxRegistered{Reason: protocol.Reason_REASON_REJECTED}
	others := map[string]func(*LinkBoxRegistration){
		"another collect key": func(other *LinkBoxRegistration) { other.CollectVerifyPub = testBytes(VerifyPubBytes, 0x77) },
		"another deposit key": func(other *LinkBoxRegistration) { other.DepositVerifyPub = testBytes(VerifyPubBytes, 0x78) },
		"another card":        func(other *LinkBoxRegistration) { other.PublicCt = testBytes(LinkCardBytes, 0x79) },
	}
	for name, change := range others {
		other := linkBoxRegistration(0x40)
		change(other)
		answer := registerLinkBox(t, boxes, seen, other, linkBoxAt(60))
		if !reflect.DeepEqual(answer, refused) {
			t.Fatalf("a registration with %s at a live box's id answered %+v, want %+v", name, answer, refused)
		}
		if after := lookUpLinkBox(t, boxes, registration.RendezvousId); !reflect.DeepEqual(after, stored) {
			t.Fatalf("a refused registration with %s changed the row to %s; a live box keeps the key and the card it was registered with",
				name, describeLinkBox(after))
		}
	}

	// past its expiry, the same three values are refused too, at the expiry itself and after it:
	// the row stands until the sweep reclaims it, and Register is the one arm that sees it
	for _, at := range []int{600, 601} {
		if answer := registerLinkBox(t, boxes, seen, linkBoxRegistration(0x40), linkBoxAt(at)); !reflect.DeepEqual(answer, refused) {
			t.Fatalf("the same registration %d seconds on, at or past the box's expiry, answered %+v, want %+v", at, answer, refused)
		}
	}

	// and a retired box's id, by the same three values
	retiring := linkBoxRegistration(0x50)
	registerLinkBox(t, boxes, seen, retiring, linkBoxEpoch)
	if retired := retireLinkBox(t, boxes, seen, retiring.RendezvousId, linkBoxAt(10)); retired.Reason != protocol.Reason_REASON_OK {
		t.Fatalf("Retire of a live box answered %v", retired.Reason)
	}
	if answer := registerLinkBox(t, boxes, seen, linkBoxRegistration(0x50), linkBoxAt(20)); !reflect.DeepEqual(answer, refused) {
		t.Fatalf("the same registration at a retired box's id answered %+v, want %+v; a tombstone holds its id", answer, refused)
	}
}

// ── Deposit: two over a box's life ───────────────────────────────────────────────────────────

func contractLinkBoxDeposits(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	boxes := linkBoxesOf(t, newStore(DefaultLimits()))
	registration := linkBoxRegistration(0x10)
	registerLinkBox(t, boxes, seen, registration, linkBoxEpoch)
	id := registration.RendezvousId

	for index, want := range []*LinkBoxDeposited{
		{Reason: protocol.Reason_REASON_OK, DepositId: 1},
		{Reason: protocol.Reason_REASON_OK, DepositId: 2},
		// the third, of different octets: two over the box's life, and nothing beside the reason
		{Reason: protocol.Reason_REASON_CARD_RATE_LIMITED},
	} {
		if got := depositLinkBox(t, boxes, seen, id, byte(0x61+index), linkBoxAt(10+index)); !reflect.DeepEqual(got, want) {
			t.Fatalf("deposit %d answered %+v, want %+v", index+1, got, want)
		}
	}
	box := lookUpLinkBox(t, boxes, id)
	if box.DepositsTaken != 2 || box.DepositCount != 2 || box.RefusedCount != 1 {
		t.Fatalf("after two deposits and a refused third the box reads taken %d, waiting %d, refused %d; want 2, 2 and 1",
			box.DepositsTaken, box.DepositCount, box.RefusedCount)
	}

	// a replay of the first deposit's octets is that deposit, even though the box takes no more
	replay := depositLinkBox(t, boxes, seen, id, 0x61, linkBoxAt(20))
	if want := (&LinkBoxDeposited{Reason: protocol.Reason_REASON_OK, DepositId: 1}); !reflect.DeepEqual(replay, want) {
		t.Fatalf("a replay of deposit 1's octets answered %+v, want %+v", replay, want)
	}
	if after := lookUpLinkBox(t, boxes, id); !reflect.DeepEqual(after, box) {
		t.Fatalf("a replay changed the box from %s to %s", describeLinkBox(box), describeLinkBox(after))
	}

	// a collect answers the refusal and zeroes it, and once both deposits are acknowledged the box
	// still takes no third: two over its LIFE, not two waiting
	collected := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id, AckThroughDepositId: 2}, linkBoxAt(30))
	if collected.Reason != protocol.Reason_REASON_OK || collected.RefusedCount != 1 || collected.PendingCount != 0 || len(collected.Deposits) != 0 {
		t.Fatalf("a collect acknowledging both deposits answered %+v; want REASON_OK, refused 1, none pending and none returned", collected)
	}
	if after := lookUpLinkBox(t, boxes, id); after.RefusedCount != 0 || after.DepositCount != 0 || after.DepositsTaken != 2 {
		t.Fatalf("after the collect the box reads taken %d, waiting %d, refused %d; want 2, 0 and 0",
			after.DepositsTaken, after.DepositCount, after.RefusedCount)
	}
	if third := depositLinkBox(t, boxes, seen, id, 0x63, linkBoxAt(40)); third.Reason != protocol.Reason_REASON_CARD_RATE_LIMITED {
		t.Fatalf("a third deposit into an emptied box answered %v, want REASON_CARD_RATE_LIMITED: a box takes two deposits over its life, not two waiting",
			third.Reason)
	}
	if after := lookUpLinkBox(t, boxes, id); after.RefusedCount != 1 {
		t.Fatalf("the refused third deposit left refused_count at %d, want 1", after.RefusedCount)
	}
}

// ── Property 3: collect, retire and replay ───────────────────────────────────────────────────

// The identity plan's Task 18, Property 3 (Spec B §13's test 44): a collect deletes exactly through
// its acknowledgement; a retire deletes every deposit and keeps a tombstone; a deposit retried with
// the same octets is one deposit. TestCollectDeletesThroughItsAcknowledgementAndRetireKeepsATombstone
// runs this against both implementations by that name, and RunContract runs it again inside the
// contract, where the refusal and sentinel gates count what it produced.
func contractLinkBoxCollectAndRetire(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	boxes := linkBoxesOf(t, newStore(DefaultLimits()))
	registration := linkBoxRegistration(0x20)
	registerLinkBox(t, boxes, seen, registration, linkBoxEpoch)
	id := registration.RendezvousId
	first, _ := linkBoxDeposit(0x21)
	second, _ := linkBoxDeposit(0x22)
	depositLinkBox(t, boxes, seen, id, 0x21, linkBoxAt(10))
	depositLinkBox(t, boxes, seen, id, 0x22, linkBoxAt(20))

	// both come back, in order, with their octets and their times, and nothing is deleted
	all := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id}, linkBoxAt(30))
	want := &LinkBoxCollected{
		Reason: protocol.Reason_REASON_OK,
		Deposits: []*LinkBoxDeposit{
			{DepositId: 1, DepositCt: first, CreateTime: linkBoxAt(10)},
			{DepositId: 2, DepositCt: second, CreateTime: linkBoxAt(20)},
		},
		PendingCount: 2,
		ExpireTime:   linkBoxAt(600),
		Complete:     true,
	}
	if !reflect.DeepEqual(all, want) {
		t.Fatalf("a collect with no acknowledgement answered %s, want %s", describeCollected(all), describeCollected(want))
	}

	// the limit narrows what comes back and says so, and deletes nothing
	limited := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id, Limit: 1}, linkBoxAt(31))
	if !slices.Equal(depositIdsOf(limited), []uint64{1}) || limited.Complete || limited.PendingCount != 2 {
		t.Fatalf("a collect limited to one answered deposits %v, complete %v, pending %d; want [1], false and 2",
			depositIdsOf(limited), limited.Complete, limited.PendingCount)
	}

	// THE ACKNOWLEDGEMENT DELETES EXACTLY THROUGH ITSELF. Acknowledging 1 deletes deposit 1 and
	// keeps deposit 2, and a second collect with no acknowledgement is the proof: deposit 2 is
	// still there to be returned. A store that deleted what it returned, or through the next id,
	// returns nothing here
	acknowledged := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id, AckThroughDepositId: 1}, linkBoxAt(40))
	if !slices.Equal(depositIdsOf(acknowledged), []uint64{2}) || acknowledged.PendingCount != 1 {
		t.Fatalf("a collect acknowledging deposit 1 answered deposits %v with %d pending; want [2] and 1",
			depositIdsOf(acknowledged), acknowledged.PendingCount)
	}
	kept := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id}, linkBoxAt(41))
	if !slices.Equal(depositIdsOf(kept), []uint64{2}) || kept.PendingCount != 1 {
		t.Fatalf("after acknowledging deposit 1, a collect answered deposits %v with %d pending; want [2] and 1: an acknowledgement deletes through itself and not past it",
			depositIdsOf(kept), kept.PendingCount)
	}

	// the same octets again are the deposit already standing, and one deposit
	replay := depositLinkBox(t, boxes, seen, id, 0x22, linkBoxAt(50))
	if want := (&LinkBoxDeposited{Reason: protocol.Reason_REASON_OK, DepositId: 2}); !reflect.DeepEqual(replay, want) {
		t.Fatalf("a deposit retried with the same octets answered %+v, want %+v", replay, want)
	}
	if once := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id}, linkBoxAt(51)); !slices.Equal(depositIdsOf(once), []uint64{2}) || once.PendingCount != 1 {
		t.Fatalf("after a retried deposit a collect answered deposits %v with %d pending; want [2] and 1: a retry is one deposit",
			depositIdsOf(once), once.PendingCount)
	}

	// RETIRE DELETES EVERY DEPOSIT AND KEEPS A TOMBSTONE
	retired := retireLinkBox(t, boxes, seen, id, linkBoxAt(60))
	if want := (&LinkBoxRetired{Reason: protocol.Reason_REASON_OK, DiscardedDeposits: 1}); !reflect.DeepEqual(retired, want) {
		t.Fatalf("Retire answered %+v, want %+v", retired, want)
	}
	tombstone := lookUpLinkBox(t, boxes, id)
	if tombstone.RetiredTime == nil || !tombstone.RetiredTime.Equal(linkBoxAt(60)) {
		t.Fatalf("the retired box reads retired_time %v, want %v", tombstone.RetiredTime, linkBoxAt(60))
	}
	if tombstone.DepositCount != 0 || !tombstone.ReclaimAfter.Equal(linkBoxAt(600)) {
		t.Fatalf("the tombstone reads %d waiting and reclaim_after %v; want 0, and the box's expiry %v",
			tombstone.DepositCount, tombstone.ReclaimAfter, linkBoxAt(600))
	}
	for name, answer := range map[string]protocol.Reason{
		"Collect": collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id}, linkBoxAt(61)).Reason,
		"Deposit": depositLinkBox(t, boxes, seen, id, 0x23, linkBoxAt(62)).Reason,
		"Retire":  retireLinkBox(t, boxes, seen, id, linkBoxAt(63)).Reason,
	} {
		if answer != protocol.Reason_REASON_CARD_RETIRED {
			t.Fatalf("%s on a retired box answered %v, want REASON_CARD_RETIRED", name, answer)
		}
	}
	if after := lookUpLinkBox(t, boxes, id); !reflect.DeepEqual(after, tombstone) {
		t.Fatalf("the arms answered a retired box and changed its tombstone from %s to %s", describeLinkBox(tombstone), describeLinkBox(after))
	}
}

// ── one answer for a box no arm may use ──────────────────────────────────────────────────────

// Spec B §4.3.11: on Deposit, Collect and Retire, an unknown id, a retired box and a box past its
// expiry answer alike. The api layer adds the fourth case, a signature that does not verify, and
// the padding; what the store owes is that its own three answers are the same value, field for
// field, and that none of them changes a row.
func contractLinkBoxOneAnswer(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	boxes := linkBoxesOf(t, newStore(DefaultLimits()))

	unknown := testBytes(RendezvousIdBytes, 0x90)
	retired := linkBoxRegistration(0xA0)
	registerLinkBox(t, boxes, seen, retired, linkBoxEpoch)
	retireLinkBox(t, boxes, seen, retired.RendezvousId, linkBoxAt(5))
	expired := linkBoxRegistration(0xB0)
	registerLinkBox(t, boxes, seen, expired, linkBoxEpoch)
	depositLinkBox(t, boxes, seen, expired.RendezvousId, 0xB8, linkBoxAt(5))

	// at the expiry itself the box is no longer live, and one microsecond before it, it is
	if box := lookUpLinkBox(t, boxes, expired.RendezvousId); box.Live(linkBoxAt(600)) || !box.Live(linkBoxAt(600).Add(-time.Microsecond)) {
		t.Fatalf("Live answered %v at the expiry and %v a microsecond before it; want false and true",
			box.Live(linkBoxAt(600)), box.Live(linkBoxAt(600).Add(-time.Microsecond)))
	}
	if box := lookUpLinkBox(t, boxes, retired.RendezvousId); box.Live(linkBoxAt(6)) {
		t.Fatal("a retired box reads as live")
	}
	if _, err := boxes.LinkBox(ctx, unknown); err == nil {
		t.Fatal("LinkBox answered a row for an id nothing registered")
	} else {
		wantError(t, seen, err, ErrLinkBoxUnknown)
	}

	before := lookUpLinkBox(t, boxes, expired.RendezvousId)
	now := linkBoxAt(600)
	ids := map[string][]byte{"an unknown id": unknown, "a retired box": retired.RendezvousId, "a box past its expiry": expired.RendezvousId}
	arms := map[string]func([]byte) any{
		"Deposit": func(id []byte) any { return depositLinkBox(t, boxes, seen, id, 0x99, now) },
		"Collect": func(id []byte) any {
			return collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id, AckThroughDepositId: 9}, now)
		},
		"Retire": func(id []byte) any { return retireLinkBox(t, boxes, seen, id, now) },
	}
	wants := map[string]any{
		"Deposit": &LinkBoxDeposited{Reason: protocol.Reason_REASON_CARD_RETIRED},
		"Collect": &LinkBoxCollected{Reason: protocol.Reason_REASON_CARD_RETIRED},
		"Retire":  &LinkBoxRetired{Reason: protocol.Reason_REASON_CARD_RETIRED},
	}
	for arm, call := range arms {
		for which, id := range ids {
			if got := call(id); !reflect.DeepEqual(got, wants[arm]) {
				t.Fatalf("%s on %s answered %+v, want %+v: the store's three cases are one answer, field for field", arm, which, got, wants[arm])
			}
		}
	}
	if after := lookUpLinkBox(t, boxes, expired.RendezvousId); !reflect.DeepEqual(after, before) {
		t.Fatalf("the arms answered a box past its expiry and changed it from %s to %s; its deposit must stand until the sweep",
			describeLinkBox(before), describeLinkBox(after))
	}
}

// ── Q20, the live boxes ──────────────────────────────────────────────────────────────────────

func contractLinkBoxLiveCount(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	boxes := linkBoxesOf(t, newStore(DefaultLimits()))
	if count := liveLinkBoxes(t, boxes, linkBoxEpoch); count != 0 {
		t.Fatalf("an empty store counts %d live boxes", count)
	}
	for _, seed := range []byte{0x11, 0x21, 0x31} {
		registerLinkBox(t, boxes, seen, linkBoxRegistration(seed), linkBoxEpoch)
	}
	registerLinkBox(t, boxes, seen, linkBoxRegistration(0x41), linkBoxAt(300))
	retireLinkBox(t, boxes, seen, linkBoxRegistration(0x21).RendezvousId, linkBoxAt(10))
	// a refused registration adds no box
	other := linkBoxRegistration(0x11)
	other.CollectVerifyPub = testBytes(VerifyPubBytes, 0x5F)
	registerLinkBox(t, boxes, seen, other, linkBoxAt(10))

	for _, at := range []struct {
		seconds int
		want    uint64
		why     string
	}{
		{10, 3, "three registered at 0 and one at 300, less the one retired at 10"},
		{599, 3, "the same, a second before the first three expire"},
		{600, 1, "the first three expire at 600, retired or not; the fourth lives to 900"},
		{900, 0, "the fourth expires at 900"},
	} {
		if count := liveLinkBoxes(t, boxes, linkBoxAt(at.seconds)); count != at.want {
			t.Fatalf("at %d seconds the store counts %d live boxes, want %d: %s", at.seconds, count, at.want, at.why)
		}
	}
}

// ── the boundary ─────────────────────────────────────────────────────────────────────────────

// Values cross this boundary by copy, in both directions, as records do ([contractDefensiveCopy]).
func contractLinkBoxDefensiveCopy(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	boxes := linkBoxesOf(t, newStore(DefaultLimits()))
	registration := linkBoxRegistration(0x60)
	id := slices.Clone(registration.RendezvousId)
	registerLinkBox(t, boxes, seen, registration, linkBoxEpoch)
	stored := lookUpLinkBox(t, boxes, id)

	// the caller's slices, overwritten after the call
	for _, value := range [][]byte{registration.RendezvousId, registration.DepositVerifyPub, registration.CollectVerifyPub, registration.PublicCt} {
		clear(value)
	}
	// and the slices a lookup handed out
	for _, value := range [][]byte{stored.RendezvousId, stored.DepositVerifyPub, stored.CollectVerifyPub, stored.PublicCt} {
		clear(value)
	}
	if again := lookUpLinkBox(t, boxes, id); !slices.Equal(again.PublicCt, linkBoxRegistration(0x60).PublicCt) ||
		!slices.Equal(again.CollectVerifyPub, linkBoxRegistration(0x60).CollectVerifyPub) {
		t.Fatal("overwriting a registration's slices, or a lookup's, after the call reached the stored box")
	}

	depositCt, depositHash := linkBoxDeposit(0x68)
	if _, err := boxes.DepositLinkBox(ctx, id, depositCt, depositHash, linkBoxAt(10)); err != nil {
		t.Fatalf("DepositLinkBox: %v", err)
	}
	clear(depositCt)
	clear(depositHash)
	collected := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id}, linkBoxAt(20))
	original, _ := linkBoxDeposit(0x68)
	if len(collected.Deposits) != 1 || !slices.Equal(collected.Deposits[0].DepositCt, original) {
		t.Fatal("overwriting a deposit's octets after the call reached the stored deposit")
	}
	clear(collected.Deposits[0].DepositCt)
	if again := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: id}, linkBoxAt(21)); !slices.Equal(again.Deposits[0].DepositCt, original) {
		t.Fatal("overwriting a collected deposit's octets reached the stored deposit")
	}
	// and the replay is still found by its hash, which the caller's overwrite did not reach
	if replay := depositLinkBox(t, boxes, seen, id, 0x68, linkBoxAt(30)); replay.DepositId != 1 {
		t.Fatalf("a replay after the caller overwrote its own hash answered deposit %d, want 1", replay.DepositId)
	}
}

// ── the racy cases, run concurrently and for real ─────────────────────────────────────────────

func contractLinkBoxConcurrency(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()
	boxes := linkBoxesOf(t, newStore(DefaultLimits()))

	// one registration wins an id, whatever the order, and the others are refused
	contested := linkBoxRegistration(0x70)
	const contenders = 4
	answers := make([]*LinkBoxRegistered, contenders)
	var group sync.WaitGroup
	for index := range contenders {
		group.Add(1)
		go func() {
			defer group.Done()
			mine := linkBoxRegistration(0x70)
			mine.CollectVerifyPub = testBytes(VerifyPubBytes, byte(0xC0+index))
			answer, err := boxes.RegisterLinkBox(ctx, mine, linkBoxEpoch, linkBoxTtl)
			if err != nil {
				t.Errorf("RegisterLinkBox: %v", err)
				return
			}
			answers[index] = answer
		}()
	}
	group.Wait()
	winners := 0
	winner := -1
	for index, answer := range answers {
		if answer == nil {
			t.FailNow()
		}
		seen.observe(answer.Reason)
		if answer.Reason == protocol.Reason_REASON_OK {
			winners++
			winner = index
		}
	}
	if winners != 1 {
		t.Fatalf("%d of %d concurrent registrations at one id under different keys answered REASON_OK, want exactly one", winners, contenders)
	}
	if box := lookUpLinkBox(t, boxes, contested.RendezvousId); !slices.Equal(box.CollectVerifyPub, testBytes(VerifyPubBytes, byte(0xC0+winner))) {
		t.Fatal("the box holds a key other than the one its winning registration carried")
	}

	// the same octets deposited at once are one deposit
	same := linkBoxRegistration(0x74)
	registerLinkBox(t, boxes, seen, same, linkBoxEpoch)
	const depositors = 8
	ids := make([]uint64, depositors)
	for index := range depositors {
		group.Add(1)
		go func() {
			defer group.Done()
			depositCt, depositHash := linkBoxDeposit(0x75)
			deposited, err := boxes.DepositLinkBox(ctx, same.RendezvousId, depositCt, depositHash, linkBoxAt(10))
			if err != nil {
				t.Errorf("DepositLinkBox: %v", err)
				return
			}
			seen.observe(deposited.Reason)
			ids[index] = deposited.DepositId
		}()
	}
	group.Wait()
	for _, id := range ids {
		if id != 1 {
			t.Fatalf("concurrent deposits of the same octets answered ids %v, want every one 1", ids)
		}
	}
	if collected := collectLinkBox(t, boxes, seen, &LinkBoxCollectRequest{RendezvousId: same.RendezvousId}, linkBoxAt(20)); !slices.Equal(depositIdsOf(collected), []uint64{1}) {
		t.Fatalf("after concurrent deposits of the same octets the box holds deposits %v, want [1]", depositIdsOf(collected))
	}

	// three different deposits at once: two are taken, with ids 1 and 2, and the third refused
	full := linkBoxRegistration(0x7A)
	registerLinkBox(t, boxes, seen, full, linkBoxEpoch)
	results := make([]*LinkBoxDeposited, 3)
	for index := range 3 {
		group.Add(1)
		go func() {
			defer group.Done()
			depositCt, depositHash := linkBoxDeposit(byte(0xD0 + index))
			deposited, err := boxes.DepositLinkBox(ctx, full.RendezvousId, depositCt, depositHash, linkBoxAt(10))
			if err != nil {
				t.Errorf("DepositLinkBox: %v", err)
				return
			}
			results[index] = deposited
		}()
	}
	group.Wait()
	taken := []uint64{}
	limited := 0
	for _, result := range results {
		if result == nil {
			t.FailNow()
		}
		seen.observe(result.Reason)
		switch result.Reason {
		case protocol.Reason_REASON_OK:
			taken = append(taken, result.DepositId)
		case protocol.Reason_REASON_CARD_RATE_LIMITED:
			limited++
		}
	}
	slices.Sort(taken)
	if !slices.Equal(taken, []uint64{1, 2}) || limited != 1 {
		t.Fatalf("three concurrent deposits took ids %v and refused %d; want [1 2] and one refused", taken, limited)
	}
}

// ── the caller's errors ──────────────────────────────────────────────────────────────────────

// The link box's shapes, each damaged by one octet, and the TTL. [contractCallerErrors] runs these
// and counts them as scenarios for [assertEveryDeclaredShapeIsDamaged]. Each asserts that the
// refused call stored nothing, and each builds one store: a pgx store is a schema and every
// migration, and a refusal leaves nothing behind for the next case on the same store to meet.
func linkBoxShapeScenarios(newStore func(Limits) Store, seen *recorder) map[string]func(*testing.T) {
	ctx := context.Background()
	registerRefused := func(t *testing.T, boxes LinkBoxes, damage func(*LinkBoxRegistration), ttl time.Duration, want error) {
		t.Helper()
		registration := linkBoxRegistration(0x30)
		damage(registration)
		registered, err := boxes.RegisterLinkBox(ctx, registration, linkBoxEpoch, ttl)
		wantError(t, seen, err, want)
		if registered != nil {
			t.Fatal("RegisterLinkBox answered an error and a result")
		}
		if count := liveLinkBoxes(t, boxes, linkBoxEpoch); count != 0 {
			t.Fatalf("a refused registration left %d live boxes", count)
		}
	}
	depositRefused := func(t *testing.T, boxes LinkBoxes, depositCt []byte, depositHash []byte, want error) {
		t.Helper()
		registration := linkBoxRegistration(0x30)
		registerLinkBox(t, boxes, seen, registration, linkBoxEpoch)
		deposited, err := boxes.DepositLinkBox(ctx, registration.RendezvousId, depositCt, depositHash, linkBoxAt(10))
		wantError(t, seen, err, want)
		if deposited != nil {
			t.Fatal("DepositLinkBox answered an error and a result")
		}
		if box := lookUpLinkBox(t, boxes, registration.RendezvousId); box.DepositsTaken != 0 || box.RefusedCount != 0 {
			t.Fatalf("a refused deposit left the box reading taken %d and refused %d", box.DepositsTaken, box.RefusedCount)
		}
	}
	return map[string]func(*testing.T){
		"ARendezvousIdOfTheWrongLength": func(t *testing.T) {
			boxes := linkBoxesOf(t, newStore(DefaultLimits()))
			registerRefused(t, boxes, func(r *LinkBoxRegistration) { r.RendezvousId = testBytes(RendezvousIdBytes-1, 0x30) }, linkBoxTtl, ErrIdentifierShape)
			_, err := boxes.LinkBox(ctx, testBytes(RendezvousIdBytes+1, 0x30))
			wantError(t, seen, err, ErrIdentifierShape)
			_, err = boxes.CollectLinkBox(ctx, &LinkBoxCollectRequest{RendezvousId: testBytes(RendezvousIdBytes-1, 0x30)}, linkBoxEpoch)
			wantError(t, seen, err, ErrIdentifierShape)
			_, err = boxes.RetireLinkBox(ctx, nil, linkBoxEpoch)
			wantError(t, seen, err, ErrIdentifierShape)
			depositCt, depositHash := linkBoxDeposit(0x30)
			_, err = boxes.DepositLinkBox(ctx, testBytes(RendezvousIdBytes-1, 0x30), depositCt, depositHash, linkBoxEpoch)
			wantError(t, seen, err, ErrIdentifierShape)
			_, err = boxes.CollectLinkBox(ctx, nil, linkBoxEpoch)
			wantError(t, seen, err, ErrIdentifierShape)
		},
		"ALinkBoxKeyOfTheWrongLength": func(t *testing.T) {
			boxes := linkBoxesOf(t, newStore(DefaultLimits()))
			registerRefused(t, boxes, func(r *LinkBoxRegistration) { r.CollectVerifyPub = testBytes(VerifyPubBytes-1, 0x32) }, linkBoxTtl, ErrIdentifierShape)
			registerRefused(t, boxes, func(r *LinkBoxRegistration) { r.DepositVerifyPub = testBytes(VerifyPubBytes+1, 0x31) }, linkBoxTtl, ErrIdentifierShape)
		},
		"ALinkCardOfTheWrongLength": func(t *testing.T) {
			boxes := linkBoxesOf(t, newStore(DefaultLimits()))
			registerRefused(t, boxes, func(r *LinkBoxRegistration) { r.PublicCt = testBytes(LinkCardBytes-1, 0x33) }, linkBoxTtl, ErrLinkBoxShape)
			registerRefused(t, boxes, func(r *LinkBoxRegistration) { r.PublicCt = testBytes(LinkCardBytes+1, 0x33) }, linkBoxTtl, ErrLinkBoxShape)
		},
		"ALinkDepositOfTheWrongLength": func(t *testing.T) {
			boxes := linkBoxesOf(t, newStore(DefaultLimits()))
			_, depositHash := linkBoxDeposit(0x34)
			depositRefused(t, boxes, testBytes(LinkDepositBytes-1, 0x34), depositHash, ErrLinkBoxShape)
			depositRefused(t, boxes, testBytes(LinkDepositBytes+1, 0x34), depositHash, ErrLinkBoxShape)
		},
		"ADepositHashOfTheWrongLength": func(t *testing.T) {
			boxes := linkBoxesOf(t, newStore(DefaultLimits()))
			depositCt, _ := linkBoxDeposit(0x35)
			depositRefused(t, boxes, depositCt, testBytes(DepositHashBytes-1, 0x35), ErrIdentifierShape)
		},
		"ALinkBoxTtlThatIsNotPositive": func(t *testing.T) {
			boxes := linkBoxesOf(t, newStore(DefaultLimits()))
			registerRefused(t, boxes, func(*LinkBoxRegistration) {}, 0, ErrLinkBoxTtl)
			registerRefused(t, boxes, func(*LinkBoxRegistration) {}, -time.Second, ErrLinkBoxTtl)
		},
	}
}

// ── rendering, for the failure messages ──────────────────────────────────────────────────────

// A box, with every byte column shortened to its first octets: enough to tell two seeds apart.
func describeLinkBox(box *LinkBox) string {
	if box == nil {
		return "no box"
	}
	retired := "not retired"
	if box.RetiredTime != nil {
		retired = "retired " + box.RetiredTime.Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("{id %.4x, deposit key %.4x, collect key %.4x, card %.4x (%d octets), waiting %d, taken %d, refused %d, registered %s, expires %s, %s, reclaimed after %s}",
		box.RendezvousId, box.DepositVerifyPub, box.CollectVerifyPub, box.PublicCt, len(box.PublicCt),
		box.DepositCount, box.DepositsTaken, box.RefusedCount, box.RegisterTime.Format(time.RFC3339Nano),
		box.ExpireTime.Format(time.RFC3339Nano), retired, box.ReclaimAfter.Format(time.RFC3339Nano))
}

func describeCollected(collected *LinkBoxCollected) string {
	deposits := []string{}
	for _, deposit := range collected.Deposits {
		deposits = append(deposits, fmt.Sprintf("%d:%.4x@%s", deposit.DepositId, deposit.DepositCt, deposit.CreateTime.Format(time.RFC3339Nano)))
	}
	return fmt.Sprintf("{%v, deposits %v, pending %d, refused %d, expires %s, complete %v}",
		collected.Reason, deposits, collected.PendingCount, collected.RefusedCount,
		collected.ExpireTime.Format(time.RFC3339Nano), collected.Complete)
}
