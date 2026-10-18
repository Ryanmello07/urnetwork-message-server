package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/message-server/api"
	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/message/protocol"
)

// KIND 4 IS SERVED ABOVE A ZERO FLOOR, AND THE READINESS SAYS WHY WHEN IT IS NOT (§4.3.11; LRI R70
// and its addendum), asked of the wiring [newServer] does and of nothing built beside it. The store
// newServer opens is the handler's link box store, and the floor is the configured `reject_floor_ms`.
// At the default of zero the handler serves none of the five arms, Capabilities 26 and 29 leave kind
// 4 out, and the not-built list names the floor; at 25 ms it serves them, advertises kind 4 and its
// one deposit size, and names neither. It never says the link box store is missing, since newServer
// wires it, and the control shows the search below would find that line if it were there.
//
// THE TWO LINK BOX KEYS REACH THE HANDLER (LRI R75, T6). At 25 ms the server is loaded with
// link_box_ttl_seconds 120 and link_box_live_cap 1, neither of them its default, and a box is
// registered through the handler newServer built, over the peer, signed: its expiry is 120 seconds
// from its registration, and a second box is refused at the cap of one. UNWIRED-KEYS, the two keys
// left unwired, so that the handler ran on 600 and 10,000, is killed here.
func TestKindFourIsServedAboveAZeroFloorAndTheReadinessSaysWhyNot(t *testing.T) {
	dsn := freshSchemaDsn(t)
	const (
		floor   = "reject_floor_ms is zero"
		unwired = "no link box store is configured"
	)
	says := func(lines []api.NotBuilt, what string) bool {
		return slices.ContainsFunc(lines, func(line api.NotBuilt) bool { return strings.Contains(line.What, what) })
	}

	// THE CONTROLS for the absences asserted below. A handler built with no link box store says so in
	// these words, so a list without them is a measurement and not a line since reworded; and the
	// floor line is held to its words by the case at a floor of zero, which must say it
	memory := store.NewMemoryStore(store.DefaultLimits())
	unwiredHandler, err := api.New(api.Config{
		Store:       memory,
		KnownGroups: api.NewMemoryKnownGroups(),
		Front:       api.ChecksNotImplemented{},
		RejectFloor: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	if !says(unwiredHandler.NotBuilt(), unwired) {
		t.Fatalf("the control, a handler with no link box store, does not say %q: %v", unwired, unwiredHandler.NotBuilt())
	}

	for name, current := range map[string]struct {
		floorMs int64
		served  bool
		says    []string
		silent  []string
	}{
		"at the default floor of zero":                       {0, false, []string{floor}, []string{unwired}},
		"at a floor of 25 ms, a TTL of 120 s and a cap of 1": {25, true, nil, []string{unwired, floor}},
	} {
		t.Run(name, func(t *testing.T) {
			loaded := defaultConfiguration()
			loaded.operatorHost = "ur.network"
			loaded.hostingJurisdiction = "US"
			loaded.rejectFloorMs = current.floorMs
			loaded.linkBoxTtlSeconds = 120
			loaded.linkBoxLiveCap = 1
			built, err := newServer(context.Background(), deployment{
				ordinal:       "0",
				healthAddress: "127.0.0.1:0",
				dsn:           dsn,
				kek:           make([]byte, kekBytes),
				serverId:      make([]byte, serverIdBytes),
			}, loaded, discardLog())
			if err != nil {
				t.Fatalf("newServer: %v", err)
			}
			defer built.Close()
			if built.handler == nil {
				t.Fatal("newServer built no handler, so nothing below would be asked of one")
			}

			if served := built.handler.RendezvousServed(); served != current.served {
				t.Fatalf("the handler newServer built serves the rendezvous arms: %v, want %v", served, current.served)
			}
			advertised := built.capabilities()
			kinds, sizes := advertised.GetRendezvousKinds(), advertised.GetRendezvousDepositSizes()
			if current.served && (kinds != 1<<store.LinkBoxKind || !slices.Equal(sizes, []uint32{store.LinkDepositBytes})) {
				t.Fatalf("a server that serves kind 4 advertises rendezvous kinds %b and deposit sizes %v, want 10000 and [%d]", kinds, sizes, store.LinkDepositBytes)
			}
			if !current.served && (kinds != 0 || len(sizes) != 0) {
				t.Fatalf("Capabilities advertises rendezvous kinds %b and deposit sizes %v from a server that serves no kind-4 arm", kinds, sizes)
			}
			lines := built.notBuilt()
			for _, what := range current.says {
				if !says(lines, what) {
					t.Fatalf("the not-built list does not say %q:\n%v", what, lines)
				}
			}
			for _, what := range current.silent {
				if says(lines, what) {
					t.Fatalf("the not-built list says %q of a server newServer wired:\n%v", what, lines)
				}
			}
			if current.served {
				registerThroughTheWiring(t, built)
			}
		})
	}
}

// A box registered over the peer, through the handler newServer built, which runs on a TTL of 120
// seconds and a cap of one live box: its expiry is the TTL's, and a second box is refused at the cap.
func registerThroughTheWiring(t *testing.T, built *server) {
	t.Helper()
	// the schema the test's server opened is fresh, and the link box's tables are 013's and 014's
	if err := store.Migrate(context.Background(), built.pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	current := newStackWith(t, built.records, built)
	current.hello(t)
	register := func(seed byte) *protocol.MessageServerResponse {
		t.Helper()
		box := newLinkBox(seed)
		request := &protocol.RendezvousRegisterRequest{
			RendezvousId:     box.id,
			DepositVerifyPub: publicOf(box.deposit),
			CollectVerifyPub: publicOf(box.collect),
			AlgId:            store.LinkBoxAlgId,
			Kind:             store.LinkBoxKind,
			PublicCt:         box.card,
		}
		signRegister(request, box.collect, current.client.Nonce())
		response, err := current.client.Call(current.ctx, request)
		if err != nil {
			t.Fatalf("Register over the peer: %v", err)
		}
		return response
	}
	before := time.Now()
	first := register(0x10)
	after := time.Now()
	expire := first.GetRendezvousRegister().GetExpireTimeMs()
	low, high := uint64(before.Add(120*time.Second).UnixMilli()), uint64(after.Add(120*time.Second).UnixMilli())
	if first.GetReason() != protocol.Reason_REASON_OK || expire < low-1 || high < expire {
		t.Fatalf("a box registered through the wiring answered %v with expiry %d, want REASON_OK and %d to %d: link_box_ttl_seconds is 120",
			first.GetReason(), expire, low, high)
	}
	if second := register(0x20); second.GetReason() != protocol.Reason_REASON_CARD_RATE_LIMITED {
		t.Fatalf("a second box through the wiring answered %v, want REASON_CARD_RATE_LIMITED: link_box_live_cap is 1", second.GetReason())
	}
}

// THE SERVER SWEEPS EXPIRED LINK BOXES FROM ITS OWN STORE, ON ITS OWN TICKS, AND CLOSES THE JOB
// BEFORE THE POOL (§7.4; the identity plan's Task 20; LRI R75, D2 and T9), on the wiring newServer
// does, with only the ticks put in place of the clock, through newServer's seam.
//   - A TICK RECLAIMS. The job newServer started takes a tick, and its pass deletes a box past its
//     expiry from the PgxStore the server opened, with no call of Pass; the control is a live box,
//     which stands. The mutant that removes newServer's Start is killed here: its job takes no tick.
//   - CLOSE STOPS THE JOB, AND THEN THE POOL. A pass is held in flight, its first statement waiting
//     on a lock the test holds, and Close is called. Closing the job first cancels the statement and
//     Close returns; closing the pool first waits on the connection the pass holds, and Close does
//     not return while the lock is held. A tick after Close is not taken.
func TestTheServerSweepsExpiredLinkBoxesOnItsOwnTicksAndClosesTheJobFirst(t *testing.T) {
	dsn := freshSchemaDsn(t)
	ctx := context.Background()
	migration, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatalf("a pool for the migration job: %v", err)
	}
	err = store.Migrate(ctx, migration)
	migration.Close()
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	loaded := defaultConfiguration()
	loaded.operatorHost = "ur.network"
	loaded.hostingJurisdiction = "US"
	ticks := make(chan time.Time)
	built, err := buildServer(ctx, deployment{
		ordinal:       "0",
		healthAddress: "127.0.0.1:0",
		dsn:           dsn,
		kek:           make([]byte, kekBytes),
		serverId:      make([]byte, serverIdBytes),
	}, loaded, discardLog(), serverSeams{sweepTicks: func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			built.Close()
		}
	}()
	tick := func(what string) {
		t.Helper()
		select {
		case ticks <- time.Now():
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the server's sweep job took no tick in 5 s: newServer did not start it", what)
		}
	}

	register := func(seed byte, at time.Time) []byte {
		id := bytes.Repeat([]byte{seed}, store.RendezvousIdBytes)
		registered, err := built.records.RegisterLinkBox(ctx, &store.LinkBoxRegistration{
			RendezvousId:     id,
			DepositVerifyPub: bytes.Repeat([]byte{seed + 1}, store.VerifyPubBytes),
			CollectVerifyPub: bytes.Repeat([]byte{seed + 2}, store.VerifyPubBytes),
			PublicCt:         bytes.Repeat([]byte{seed + 3}, store.LinkCardBytes),
		}, at, api.DefaultLinkBoxTtl, api.DefaultLinkBoxLiveCap)
		if err != nil || registered.Reason != protocol.Reason_REASON_OK {
			t.Fatalf("RegisterLinkBox: %v (%v)", registered, err)
		}
		return id
	}
	now := time.Now()
	expired := register(0x10, now.Add(-2*api.DefaultLinkBoxTtl))
	live := register(0x20, now)

	// A TICK RECLAIMS, with no call of Pass
	tick("the first tick")
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := built.records.LinkBox(ctx, expired)
		if errors.Is(err, store.ErrLinkBoxUnknown) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("10 s after a tick the expired box is still in the server's store: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := built.records.LinkBox(ctx, live); err != nil {
		t.Fatalf("the control, a live box, did not survive the tick's pass: %v", err)
	}

	// CLOSE STOPS THE JOB, AND THEN THE POOL. The test's own connection holds 014's table, so that
	// the next pass's first statement waits on it
	holderPool, err := store.NewPgxPool(ctx, dsn)
	if err != nil {
		t.Fatalf("a pool for the lock: %v", err)
	}
	defer holderPool.Close()
	holder, err := holderPool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			holder.Rollback(context.Background())
		}
	}
	defer release()
	if _, err := holder.Exec(ctx, `LOCK TABLE message_rendezvous_deposit IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("LOCK TABLE: %v", err)
	}
	tick("the second tick")
	waiting := func() int {
		var count int
		if err := holderPool.QueryRow(ctx, `SELECT count(*) FROM pg_locks
			 WHERE NOT granted AND relation = 'message_rendezvous_deposit'::regclass`).Scan(&count); err != nil {
			t.Fatalf("reading pg_locks: %v", err)
		}
		return count
	}
	deadline = time.Now().Add(10 * time.Second)
	for waiting() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("10 s after the second tick no pass waits on the held table, so Close below would not be closing a pass in flight")
		}
		time.Sleep(20 * time.Millisecond)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		built.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		release()
		<-done
		closed = true
		t.Fatal("Close did not return in 5 s while a pass waited on a lock: the pool is closed before the job, or the job is not closed, and the pool waits on the pass's connection")
	}
	closed = true
	release()
	select {
	case ticks <- time.Now():
		t.Fatal("a tick after Close was taken: the job still runs")
	case <-time.After(200 * time.Millisecond):
	}
}
