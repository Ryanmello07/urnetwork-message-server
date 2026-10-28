package api

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/protocol"
)

// §4.5's floor, as the slice review of Tasks 18 to 20 left it (LRI R75): where the envelope starts
// (T4), a pad that holds none of its caller's goroutines (T3), a floor that is never negative (T8),
// and an overrun that is named while nothing counts it (S-5).

// A clock that moves only when something moves it: a test, or a store read below.
type steppedClock struct {
	mutex sync.Mutex
	at    time.Time
}

func newSteppedClock() *steppedClock {
	return &steppedClock{at: time.Unix(1767225600, 0).UTC()}
}

func (self *steppedClock) now() time.Time {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.at
}

func (self *steppedClock) advance(by time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.at = self.at.Add(by)
}

// LinkBoxes whose Q17 takes `by` on the clock: the time a read of a box that exists costs, made a
// number a test can hold an envelope to.
type advancingLinkBoxes struct {
	store.LinkBoxes
	clock *steppedClock
	by    time.Duration
}

func (self *advancingLinkBoxes) LinkBox(ctx context.Context, rendezvousId []byte) (*store.LinkBox, error) {
	self.clock.advance(self.by)
	return self.LinkBoxes.LinkBox(ctx, rendezvousId)
}

// A store whose epoch key read takes `by` on the clock, for the submit path's merged refusals.
type advancingStore struct {
	store.Store
	clock *steppedClock
	by    time.Duration
}

func (self *advancingStore) EpochKeys(ctx context.Context, groupId []byte, epoch uint64) (*store.EpochKeys, error) {
	self.clock.advance(self.by)
	return self.Store.EpochKeys(ctx, groupId, epoch)
}

// The time a store read takes in the tests below.
const storeRead = 3 * time.Millisecond

// EVERY REFUSAL ON THE FOUR ARMS ENDS ITS ENVELOPE AT THE FLOOR, TIMED FROM THE ARM'S OWN START (LRI
// R75, T4; §4.5; §4.3.11's one answer "padded to §4.5's reject floor"). The clock moves by a read's
// time inside Q17, so an arm that read the box pads the floor less that read, and its whole answer
// takes the floor exactly. An unknown id, a retired box, a box past its expiry, and a live box asked
// with a signature that does not verify, on each of Open, Deposit, Collect and Retire, each pad the
// floor less one read. An arm that timed its envelope from after the read, STARTED-LATE, pads the
// whole floor there, so that a box that exists answers a read later than one that does not: the
// existence signal §13's test 46 forbids. The control is check 3's refusal, made before any read,
// which pads the floor itself.
func TestEveryRefusalOnTheFourArmsEndsItsEnvelopeAtTheFloor(t *testing.T) {
	ctx := context.Background()
	clock := newSteppedClock()
	fixture := newRendezvousFixture(t, func(config *Config) {
		config.Now = clock.now
		config.LinkBoxes = &advancingLinkBoxes{LinkBoxes: config.LinkBoxes, clock: clock, by: storeRead}
	})
	register := func(seed byte, at time.Time) *protocol.RendezvousRegisterRequest {
		t.Helper()
		request := linkRegister(seed)
		registered, err := fixture.boxes.RegisterLinkBox(ctx, &store.LinkBoxRegistration{
			RendezvousId:     request.GetRendezvousId(),
			DepositVerifyPub: request.GetDepositVerifyPub(),
			CollectVerifyPub: request.GetCollectVerifyPub(),
			PublicCt:         request.GetPublicCt(),
		}, at, DefaultLinkBoxTtl, DefaultLinkBoxLiveCap)
		if err != nil || registered.Reason != protocol.Reason_REASON_OK {
			t.Fatalf("RegisterLinkBox: %+v (%v)", registered, err)
		}
		return request
	}
	live := register(0x10, clock.now())
	retired := register(0x20, clock.now())
	if answer, err := fixture.boxes.RetireLinkBox(ctx, retired.GetRendezvousId(), retired.GetCollectVerifyPub(), clock.now()); err != nil || answer.Reason != protocol.Reason_REASON_OK {
		t.Fatalf("RetireLinkBox: %+v (%v)", answer, err)
	}
	expired := register(0x30, clock.now().Add(-2*DefaultLinkBoxTtl))
	unknown := linkRegister(0x40)
	// a signature of the right length that no key made
	forged := linkBytes(64, 0x55)

	arms := map[string]func(id []byte) protocol.Reason{
		"Open": func(id []byte) protocol.Reason {
			reason, _, _ := fixture.handler.RendezvousOpen(ctx, fixture.conn, &protocol.RendezvousOpenRequest{RendezvousId: id, OpenAuth: forged})
			return reason
		},
		"Deposit": func(id []byte) protocol.Reason {
			reason, _, _ := fixture.handler.RendezvousDeposit(ctx, fixture.conn, &protocol.RendezvousDepositRequest{
				RendezvousId: id, DepositCt: linkBytes(store.LinkDepositBytes, 0x56), DepositAuth: forged})
			return reason
		},
		"Collect": func(id []byte) protocol.Reason {
			reason, _, _ := fixture.handler.RendezvousCollect(ctx, fixture.conn, &protocol.RendezvousCollectRequest{
				RendezvousId: id, AckThroughDepositId: 9, Subscribe: true, CollectAuth: forged})
			return reason
		},
		"Retire": func(id []byte) protocol.Reason {
			reason, _, _ := fixture.handler.RendezvousRetire(ctx, fixture.conn, &protocol.RendezvousRetireRequest{RendezvousId: id, RetireAuth: forged})
			return reason
		},
	}
	padded := func(call func() protocol.Reason) (protocol.Reason, time.Duration, []time.Duration) {
		fixture.mutex.Lock()
		fixture.sleeps = nil
		fixture.mutex.Unlock()
		before := clock.now()
		reason := call()
		took := clock.now().Sub(before)
		fixture.mutex.Lock()
		defer fixture.mutex.Unlock()
		return reason, took, append([]time.Duration{}, fixture.sleeps...)
	}

	for name, box := range map[string]*protocol.RendezvousRegisterRequest{
		"an unknown id":                     unknown,
		"a retired box":                     retired,
		"a box past its expiry":             expired,
		"a live box and a forged signature": live,
	} {
		for arm, call := range arms {
			reason, took, pads := padded(func() protocol.Reason { return call(box.GetRendezvousId()) })
			if reason != protocol.Reason_REASON_CARD_RETIRED {
				t.Fatalf("%s on %s answered %v, want REASON_CARD_RETIRED", arm, name, reason)
			}
			if took != storeRead {
				t.Fatalf("%s on %s moved the clock %v, want one Q17 read, %v: the case measures nothing else", arm, name, took, storeRead)
			}
			if want := []time.Duration{rendezvousFloor - storeRead}; !slices.Equal(pads, want) {
				t.Fatalf("%s on %s padded %v, want %v: the arm read for %v and its envelope, timed from its start, ends at the floor %v",
					arm, name, pads, want, storeRead, rendezvousFloor)
			}
		}
	}

	// THE CONTROL: check 3's refusal comes before any read, and pads the whole floor
	reason, took, pads := padded(func() protocol.Reason { return arms["Open"](linkBytes(store.RendezvousIdBytes-1, 0x41)) })
	if reason != protocol.Reason_REASON_REJECTED || took != 0 || !slices.Equal(pads, []time.Duration{rendezvousFloor}) {
		t.Fatalf("the control, Open with an id one octet short, answered %v after %v and padded %v; want REASON_REJECTED, no read, and the whole floor",
			reason, took, pads)
	}
}

// THE SUBMIT PATH'S MERGED REFUSALS END THEIR ENVELOPE AT THE FLOOR TOO (LRI R75, T4, for api's merge
// test). TestTheThreeCausesOfRejectedAreIndistinguishableInTheResponse holds the three causes to one
// pad on a clock that never moves, so that where an envelope starts is never seen there. Here the
// epoch key read takes a read's time: an unknown group is refused by the filter before it and pads
// the whole floor, while an unknown epoch key and a write_auth that does not verify are refused after
// it and pad the floor less the read. Each answer, its own time and its pad, takes the floor exactly.
func TestTheMergedRefusalsOfSubmitEndTheirEnvelopeAtTheFloor(t *testing.T) {
	clock := newSteppedClock()
	const floor = 25 * time.Millisecond
	fixture := newFixtureWith(t, Config{
		Store:       &advancingStore{Store: store.NewMemoryStore(store.DefaultLimits()), clock: clock, by: storeRead},
		RejectFloor: floor,
		Now:         clock.now,
	})
	fixture.createOpenGroup(t)

	elsewhere := groupId(0x99)
	unknownGroup := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 30, groupId: elsewhere,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})
	unknownEpoch := fixture.seal(t, sealed{
		sender: senderA, epoch: 9, streamIndex: 31,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(9),
	})
	forged := fixture.seal(t, sealed{
		sender: senderA, epoch: 1, streamIndex: 32,
		class: message.RetentionDurable, bucket: message.SizeBucket256,
		head: []byte("a head"), body: []byte("a body"), writeKey: fixture.writeKey(1),
	})
	forged.RecordBytes[len(forged.RecordBytes)-1] ^= 0x01

	read := map[string]bool{}
	for _, refusal := range []struct {
		name    string
		groupId []byte
		record  *protocol.Record
	}{
		{"an unknown group", elsewhere, unknownGroup},
		{"an unknown epoch key", fixture.groupId, unknownEpoch},
		{"a write_auth that did not verify", fixture.groupId, forged},
	} {
		fixture.sleeps = nil
		before := clock.now()
		reason, response, err := fixture.handler.Submit(context.Background(), fixture.conn, &protocol.SubmitRequest{
			GroupId: refusal.groupId,
			Records: []*protocol.Record{refusal.record},
		})
		took := clock.now().Sub(before)
		if err != nil || reason != protocol.Reason_REASON_OK || response.GetResults()[0].GetReason() != protocol.Reason_REASON_REJECTED {
			t.Fatalf("%s was answered %v, %v (%v), want the merged REASON_REJECTED", refusal.name, reason, response, err)
		}
		if want := []time.Duration{floor - took}; !slices.Equal(fixture.sleeps, want) {
			t.Fatalf("%s took %v on the clock and padded %v, want %v: its envelope, timed from the arm's start, ends at the floor",
				refusal.name, took, fixture.sleeps, want)
		}
		read[refusal.name] = took != 0
	}
	// the measurement's own control: the read was taken on the paths that read, and not on the one that does not
	if want := map[string]bool{"an unknown group": false, "an unknown epoch key": true, "a write_auth that did not verify": true}; !maps.Equal(read, want) {
		t.Fatalf("the epoch key read moved the clock on %v, want %v, so the envelopes above were not measured across a read", read, want)
	}
}

// A PADDED REFUSAL IS DEFERRED TO A CALLER THAT CAN ANSWER LATER, AND HOLDS NONE OF ITS GOROUTINES (LRI
// R75, T3). Handed a Deferral in its context, a handler that refuses sleeps nothing, returns at once,
// and leaves in the Deferral the rest of the floor its answer must still wait; the peer sends that
// answer from a timer off its worker pool (cmd/message-server's TestAPaddedRefusalHoldsNoWorker holds
// that half). The control is the same refusal with no Deferral, which sleeps the same rest, so that no
// caller is answered before the floor. Both are measured across a Q17 read, so the rest is the floor
// less the read on both; and an answer that is not padded, a request the arm serves, defers nothing.
func TestAPaddedRefusalIsDeferredToACallerThatCanAnswerLater(t *testing.T) {
	clock := newSteppedClock()
	fixture := newRendezvousFixture(t, func(config *Config) {
		config.Now = clock.now
		config.LinkBoxes = &advancingLinkBoxes{LinkBoxes: config.LinkBoxes, clock: clock, by: storeRead}
	})
	open := &protocol.RendezvousOpenRequest{RendezvousId: linkRegister(0xD0).GetRendezvousId()}

	deferral := &Deferral{}
	reason, response, err := fixture.handler.RendezvousOpen(WithDeferral(context.Background(), deferral), fixture.conn, open)
	if err != nil || reason != protocol.Reason_REASON_CARD_RETIRED || response != nil {
		t.Fatalf("Open on an unknown id answered %v (%v), want REASON_CARD_RETIRED and no body", reason, err)
	}
	fixture.mutex.Lock()
	slept := append([]time.Duration{}, fixture.sleeps...)
	fixture.sleeps = nil
	fixture.mutex.Unlock()
	if len(slept) != 0 {
		t.Fatalf("a refusal handed a Deferral slept %v on its caller's goroutine, want nothing", slept)
	}
	if remaining, deferred := deferral.Remaining(); !deferred || remaining != rendezvousFloor-storeRead {
		t.Fatalf("a refusal handed a Deferral deferred %v (%v), want %v: the floor less the read", remaining, deferred, rendezvousFloor-storeRead)
	}

	// THE CONTROL: no Deferral, and the same rest is slept
	reason, _, _ = fixture.handler.RendezvousOpen(context.Background(), fixture.conn, open)
	fixture.mutex.Lock()
	slept = append([]time.Duration{}, fixture.sleeps...)
	fixture.mutex.Unlock()
	if reason != protocol.Reason_REASON_CARD_RETIRED || !slices.Equal(slept, []time.Duration{rendezvousFloor - storeRead}) {
		t.Fatalf("the control, the same refusal with no Deferral, answered %v and slept %v, want %v", reason, slept, rendezvousFloor-storeRead)
	}

	// and what is served defers nothing: a fresh box's own registration is answered at once
	served := &Deferral{}
	reason, _, err = fixture.handler.RendezvousRegister(WithDeferral(context.Background(), served), fixture.conn, linkRegister(0xE0))
	if err != nil {
		t.Fatalf("RendezvousRegister: %v", err)
	}
	// unsigned, so refused at check 7 and padded: a Register that is served needs a signature, which
	// this package cannot make; what is held here is that a refusal deferred, and the Unsubscribe
	// below, which is never padded, did not
	if remaining, deferred := served.Remaining(); reason != protocol.Reason_REASON_REJECTED || !deferred || remaining != rendezvousFloor {
		t.Fatalf("an unsigned registration answered %v and deferred %v (%v), want REASON_REJECTED and the whole floor", reason, remaining, deferred)
	}
	unpadded := &Deferral{}
	if reason, err := fixture.handler.Unsubscribe(WithDeferral(context.Background(), unpadded), fixture.conn, &protocol.UnsubscribeRequest{All: true}); err != nil {
		t.Fatalf("Unsubscribe: %v (%v)", reason, err)
	}
	if remaining, deferred := unpadded.Remaining(); deferred {
		t.Fatalf("Unsubscribe, which pads nothing, deferred %v", remaining)
	}
}

// A NEGATIVE REJECT FLOOR IS REFUSED, AND SERVES NOTHING HOWEVER A HANDLER CAME BY ONE (LRI R75, T8).
// §4.5's floor is a length of time. [New] refuses a negative one, and the three predicates that read
// the floor, whether kind 4 is served, whether the envelope is named unbuilt, and whether the pad
// pads, each take a negative floor as the zero it is not above: the arms are unserved, the envelope is
// named as missing, and nothing is slept. The control is the fixture's own floor of 25 ms.
func TestANegativeRejectFloorIsRefusedAndServesNothing(t *testing.T) {
	memory := store.NewMemoryStore(store.DefaultLimits())
	if _, err := New(Config{
		Store:       memory,
		KnownGroups: NewMemoryKnownGroups(),
		Front:       ChecksNotImplemented{},
		LinkBoxes:   memory,
		RejectFloor: -time.Millisecond,
	}); !errors.Is(err, ErrNegativeRejectFloor) {
		t.Fatalf("New with a reject floor of -1 ms answered %v, want ErrNegativeRejectFloor", err)
	}

	control := newRendezvousFixture(t, nil)
	if !control.handler.RendezvousServed() || slices.Contains(control.handler.NotBuilt(), unpaddedRejectPath) {
		t.Fatal("the control, a handler at a floor of 25 ms, does not serve kind 4, or names its envelope unbuilt")
	}

	negative := newRendezvousFixture(t, nil)
	negative.handler.rejectFloor = -time.Millisecond
	if negative.handler.RendezvousServed() || negative.handler.RendezvousKinds() != 0 {
		t.Fatal("a handler whose reject floor is negative serves the kind-4 arms, with no envelope to pad them to")
	}
	lines := negative.handler.NotBuilt()
	if !slices.Contains(lines, unpaddedRejectPath) || !slices.Contains(lines, rendezvousWithoutFloor) {
		t.Fatalf("a handler whose reject floor is negative does not name the missing envelope and floor: %v", lines)
	}
	negative.handler.pad(context.Background(), time.Now())
	negative.mutex.Lock()
	defer negative.mutex.Unlock()
	if len(negative.sleeps) != 0 {
		t.Fatalf("a pad at a negative floor slept %v", negative.sleeps)
	}
}

// A PAD OVERRUN IS NAMED WHILE NOTHING COUNTS IT (LRI R75, S-5). A refusal whose own path outlasts
// the floor is answered when its path ends, and the floor then no longer hides that path's time;
// §4.3.11 asks the floor to be at least the slowest refusal path as measured, and nothing in this
// build counts or reports an overrun, since the metrics package has no code. So a handler with a
// floor names the gap among what it has not built, and one with no floor does not, since its
// envelope is named missing already.
func TestAPadOverrunIsNamedAmongWhatIsNotBuiltWhileTheFloorIsSet(t *testing.T) {
	names := func(lines []NotBuilt) bool {
		return slices.ContainsFunc(lines, func(line NotBuilt) bool {
			return strings.Contains(line.What, "outlasts the reject floor")
		})
	}
	if lines := newRendezvousFixture(t, nil).handler.NotBuilt(); !names(lines) {
		t.Fatalf("a handler at a floor of 25 ms does not name the uncounted pad overrun: %v", lines)
	}
	if lines := newRendezvousFixture(t, func(config *Config) { config.RejectFloor = 0 }).handler.NotBuilt(); names(lines) || !slices.Contains(lines, unpaddedRejectPath) {
		t.Fatalf("a handler with no floor names a pad overrun, or does not name its missing envelope: %v", lines)
	}
}
