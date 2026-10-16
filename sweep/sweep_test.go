package sweep

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/message-server/store"
)

// A sweeper that answers from a script, and records what it was asked.
type scriptedSweeper struct {
	mutex  sync.Mutex
	script []*store.LinkBoxesSwept
	err    error
	asked  []store.LinkBoxSweepBounds
	at     []time.Time
	called chan struct{}
}

func (self *scriptedSweeper) SweepLinkBoxes(ctx context.Context, now time.Time, bounds store.LinkBoxSweepBounds) (*store.LinkBoxesSwept, error) {
	self.mutex.Lock()
	defer func() {
		self.mutex.Unlock()
		if self.called != nil {
			select {
			case self.called <- struct{}{}:
			default:
			}
		}
	}()
	self.asked = append(self.asked, bounds)
	self.at = append(self.at, now)
	if self.err != nil {
		return nil, self.err
	}
	if len(self.script) == 0 {
		return &store.LinkBoxesSwept{}, nil
	}
	next := self.script[0]
	self.script = self.script[1:]
	return next, nil
}

func (self *scriptedSweeper) calls() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return len(self.asked)
}

// A job over `sweeper` with its pauses recorded and its clock moved by the test.
type jobFixture struct {
	job     *Job
	mutex   sync.Mutex
	pauses  []time.Duration
	clock   time.Time
	ticks   chan time.Time
	stopped bool
}

func newJobFixture(t *testing.T, sweeper store.LinkBoxSweeper, configure func(*Config)) *jobFixture {
	t.Helper()
	fixture := &jobFixture{clock: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC), ticks: make(chan time.Time)}
	config := Config{
		LinkBoxes: sweeper,
		Now:       fixture.now,
		Sleep:     fixture.sleep,
		Ticks: func(every time.Duration) (<-chan time.Time, func()) {
			return fixture.ticks, func() {
				fixture.mutex.Lock()
				defer fixture.mutex.Unlock()
				fixture.stopped = true
			}
		},
	}
	if configure != nil {
		configure(&config)
	}
	job, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(job.Close)
	fixture.job = job
	return fixture
}

func (self *jobFixture) now() time.Time {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.clock
}

func (self *jobFixture) advance(by time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.clock = self.clock.Add(by)
}

func (self *jobFixture) sleep(pause time.Duration) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.pauses = append(self.pauses, pause)
}

func (self *jobFixture) slept() []time.Duration {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]time.Duration(nil), self.pauses...)
}

// A JOB WITH NOTHING CONFIGURED RUNS §7.4's CADENCE AND BOUNDS: every five minutes, Q19's LIMITs of
// 1000 deposits and 500 boxes, at most 50 batches or 20 seconds a pass, 100 ms between batches.
// And a job with no store to sweep is refused rather than built to do nothing.
func TestAJobWithNothingConfiguredRunsSection74sCadenceAndBounds(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNoLinkBoxes) {
		t.Fatalf("New with no store answered %v, want %v", err, ErrNoLinkBoxes)
	}
	job, err := New(Config{LinkBoxes: &scriptedSweeper{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer job.Close()
	if job.every != 5*time.Minute || job.maxBatches != 50 || job.budget != 20*time.Second || job.pause != 100*time.Millisecond {
		t.Fatalf("a job with nothing configured runs every %v, %d batches, %v a pass, %v between: want 5m, 50, 20s, 100ms",
			job.every, job.maxBatches, job.budget, job.pause)
	}
	if job.bounds != (store.LinkBoxSweepBounds{Deposits: 1000, Boxes: 500}) {
		t.Fatalf("a job with nothing configured is bounded at %+v, want Q19's 1000 deposits and 500 boxes", job.bounds)
	}
}

// A PASS RUNS BATCHES UNTIL ONE REACHES NEITHER BOUND. A batch that deleted as many deposits as its
// bound, or as many boxes, may have left more, so another follows it, after a pause; a batch short
// of both ends the pass. The totals are the batches' sums, and every batch asks at the job's clock
// under the job's bounds.
func TestAPassRunsBatchesUntilOneReachesNeitherBound(t *testing.T) {
	bounds := store.LinkBoxSweepBounds{Deposits: 3, Boxes: 2}
	sweeper := &scriptedSweeper{script: []*store.LinkBoxesSwept{
		{Deposits: 3, Boxes: 0}, // full on deposits
		{Deposits: 1, Boxes: 2}, // full on boxes
		{Deposits: 2, Boxes: 1}, // full on neither: the last
		{Deposits: 3, Boxes: 2}, // never asked for
	}}
	fixture := newJobFixture(t, sweeper, func(config *Config) { config.Bounds = bounds })
	totals, err := fixture.job.Pass(context.Background())
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	want := Totals{Batches: 3, Deposits: 6, Boxes: 3}
	if totals != want || sweeper.calls() != 3 {
		t.Fatalf("a pass over full, full, then short batches answered %+v after %d batches, want %+v after 3", totals, sweeper.calls(), want)
	}
	if pauses := fixture.slept(); len(pauses) != 2 || pauses[0] != DefaultPause || pauses[1] != DefaultPause {
		t.Fatalf("three batches were separated by pauses %v, want two of %v", pauses, DefaultPause)
	}
	for index, asked := range sweeper.asked {
		if asked != bounds || !sweeper.at[index].Equal(fixture.now()) {
			t.Fatalf("batch %d asked under %+v at %v, want %+v at the job's clock %v", index+1, asked, sweeper.at[index], bounds, fixture.now())
		}
	}
}

// A PASS STOPS AT ITS BATCH LIMIT AND AT ITS BUDGET, whichever comes first, even while every batch
// is full: the rest waits for the next tick.
func TestAPassStopsAtItsBatchLimitAndAtItsBudget(t *testing.T) {
	full := func(count int) []*store.LinkBoxesSwept {
		script := []*store.LinkBoxesSwept{}
		for range count {
			script = append(script, &store.LinkBoxesSwept{Deposits: 1000, Boxes: 500})
		}
		return script
	}
	limited := &scriptedSweeper{script: full(80)}
	fixture := newJobFixture(t, limited, nil)
	if totals, err := fixture.job.Pass(context.Background()); err != nil || totals.Batches != DefaultMaxBatches || limited.calls() != DefaultMaxBatches {
		t.Fatalf("a pass over full batches ran %d (%+v, %v), want %d", limited.calls(), totals, err, DefaultMaxBatches)
	}

	budgeted := &scriptedSweeper{script: full(80)}
	var clocked *jobFixture
	clocked = newJobFixture(t, budgeted, func(config *Config) {
		config.Sleep = func(pause time.Duration) { clocked.advance(7 * time.Second) }
	})
	// batches at 0 s, 7 s and 14 s; at 21 s the budget of 20 s is spent
	if totals, err := clocked.job.Pass(context.Background()); err != nil || totals.Batches != 3 {
		t.Fatalf("a pass whose pauses took 7 s each ran %d batches (%v), want 3 inside a budget of %v", totals.Batches, err, DefaultBudget)
	}
}

// A PASS THAT FINDS THE LOCK HELD STOPS THERE, and one whose batch fails stops and answers the
// error, which the next tick retries.
func TestAPassStopsWhenTheLockIsHeldOrABatchFails(t *testing.T) {
	held := &scriptedSweeper{script: []*store.LinkBoxesSwept{{Skipped: true}, {Deposits: 1}}}
	if totals, err := newJobFixture(t, held, nil).job.Pass(context.Background()); err != nil || !totals.Skipped || totals.Batches != 0 || held.calls() != 1 {
		t.Fatalf("a pass that found the lock held answered %+v (%v) after %d calls, want Skipped after one", totals, err, held.calls())
	}
	failing := &scriptedSweeper{err: errors.New("sweep_test: the batch failed")}
	if _, err := newJobFixture(t, failing, nil).job.Pass(context.Background()); err == nil || failing.calls() != 1 {
		t.Fatalf("a pass whose batch failed answered %v after %d calls, want the error after one", err, failing.calls())
	}
}

// THE JOB RUNS A PASS ON EVERY TICK, AND CLOSE STOPS IT: the ticks stop, the goroutine ends, and a
// tick sent after Close is never taken. Close is safe twice, and on a job never started.
func TestTheJobPassesOnEveryTickAndCloseStopsIt(t *testing.T) {
	sweeper := &scriptedSweeper{called: make(chan struct{}, 4)}
	fixture := newJobFixture(t, sweeper, nil)
	fixture.job.Start()
	fixture.job.Start()
	for tick := 1; tick <= 2; tick++ {
		fixture.ticks <- fixture.now()
		select {
		case <-sweeper.called:
		case <-time.After(5 * time.Second):
			t.Fatalf("tick %d ran no pass", tick)
		}
	}
	fixture.job.Close()
	fixture.job.Close()
	select {
	case fixture.ticks <- fixture.now():
		t.Fatal("a tick sent after Close was taken")
	case <-time.After(100 * time.Millisecond):
	}
	fixture.mutex.Lock()
	stopped := fixture.stopped
	fixture.mutex.Unlock()
	if !stopped || sweeper.calls() != 2 {
		t.Fatalf("after Close the ticks were stopped %v and %d passes ran, want stopped and 2", stopped, sweeper.calls())
	}

	never, err := New(Config{LinkBoxes: &scriptedSweeper{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	never.Close()
	never.Start()
	never.Close()
}

// THE JOB RECLAIMS AN EXPIRED BOX FROM A REAL STORE, AND NOTHING LIVE (§7.4, §4.3.11): a pass at
// the expiry of one box deletes it and its deposit, and leaves a box still live, with its deposit,
// standing. The memory store is the one this package can build; the PgxStore is held to the same
// by store.RunContract and by cmd/message-server's test of the wiring.
func TestTheJobReclaimsAnExpiredBoxAndNothingLive(t *testing.T) {
	ctx := context.Background()
	boxes := store.NewMemoryStore(store.DefaultLimits())
	registered := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	register := func(seed byte, at time.Time) []byte {
		id := bytesOf(store.RendezvousIdBytes, seed)
		answered, err := boxes.RegisterLinkBox(ctx, &store.LinkBoxRegistration{
			RendezvousId:     id,
			DepositVerifyPub: bytesOf(store.VerifyPubBytes, seed+1),
			CollectVerifyPub: bytesOf(store.VerifyPubBytes, seed+2),
			PublicCt:         bytesOf(store.LinkCardBytes, seed+3),
		}, at, 600*time.Second)
		if err != nil {
			t.Fatalf("RegisterLinkBox: %v", err)
		}
		if _, err := boxes.DepositLinkBox(ctx, id, bytesOf(store.LinkDepositBytes, seed+4), at); err != nil || answered == nil {
			t.Fatalf("DepositLinkBox: %v", err)
		}
		return id
	}
	expiring := register(0x10, registered)
	live := register(0x20, registered.Add(time.Minute))

	fixture := newJobFixture(t, boxes, nil)
	fixture.advance(600 * time.Second)
	totals, err := fixture.job.Pass(ctx)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if totals != (Totals{Batches: 1, Deposits: 1, Boxes: 1}) {
		t.Fatalf("a pass at one box's expiry answered %+v, want one batch, one deposit and one box", totals)
	}
	if _, err := boxes.LinkBox(ctx, expiring); !errors.Is(err, store.ErrLinkBoxUnknown) {
		t.Fatalf("the expired box was not reclaimed: %v", err)
	}
	if box, err := boxes.LinkBox(ctx, live); err != nil || box.DepositCount != 1 {
		t.Fatalf("the live box, or its deposit, did not survive the pass: %+v, %v", box, err)
	}
}

func bytesOf(length int, seed byte) []byte {
	value := make([]byte, length)
	for index := range value {
		value[index] = seed + byte(index)
	}
	return value
}
