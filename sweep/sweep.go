package sweep

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/urnetwork/message-server/store"
)

// §7.4's five-minute loop, as far as this build has one: the reclaim of §4.3.11's rendezvous
// state, the identity plan's Task 20. Each pass runs Q19 in batches, each batch one call of
// [store.LinkBoxSweeper.SweepLinkBoxes] under Q19's bounds, until a batch reaches neither bound,
// the lock is found held, or the pass has run its batches or spent its budget.
//
// IT DECIDES NOTHING AN ARM ANSWERS. Every arm answers a box past its expiry as an unknown one
// whether or not this has run (§4.3.11), because every arm reads the expiry and none reads this.
// What a pass changes is the space the rows take, and Register, the one arm the sweep's timing
// reaches: an id whose row a pass deleted can be registered again.

// §7.4's cadence and its bounds on a pass: "max 50 batches or 20 s wall clock, whichever first",
// with "100 ms sleep" between batches. Q19's own LIMITs are [store.DefaultLinkBoxSweepBounds].
const (
	DefaultEvery      = 5 * time.Minute
	DefaultMaxBatches = 50
	DefaultBudget     = 20 * time.Second
	DefaultPause      = 100 * time.Millisecond
)

var ErrNoLinkBoxes = errors.New("sweep: no link box store to sweep")

type Config struct {
	// The store whose rendezvous state a pass reclaims. Required.
	LinkBoxes store.LinkBoxSweeper

	// Zero takes each default above, and [store.DefaultLinkBoxSweepBounds].
	Every      time.Duration
	Bounds     store.LinkBoxSweepBounds
	MaxBatches int
	Budget     time.Duration
	Pause      time.Duration

	// Seams, so that a test moves the clock, counts the pauses and sends the ticks. Nil takes
	// time.Now, time.Sleep and a [time.Ticker] at Every.
	Now   func() time.Time
	Sleep func(time.Duration)
	Ticks func(every time.Duration) (ticks <-chan time.Time, stop func())

	// Where a pass is reported, in counts and nothing else (§11.1). Nil discards.
	Log *slog.Logger
}

// What one pass did, summed over its batches.
type Totals struct {
	Batches  int
	Deposits uint64
	Boxes    uint64
	// Another sweeper held the lock, and the pass stopped there.
	Skipped bool
}

// Job runs a pass on every tick, from [Job.Start] until [Job.Close].
type Job struct {
	linkBoxes  store.LinkBoxSweeper
	every      time.Duration
	bounds     store.LinkBoxSweepBounds
	maxBatches int
	budget     time.Duration
	pause      time.Duration
	now        func() time.Time
	sleep      func(time.Duration)
	ticks      func(time.Duration) (<-chan time.Time, func())
	log        *slog.Logger

	// ends a pass in flight at its next batch when the job is closed
	context context.Context
	cancel  context.CancelFunc

	startOnce sync.Once
	closeOnce sync.Once
	stop      chan struct{}
	done      chan struct{}
}

func New(config Config) (*Job, error) {
	if config.LinkBoxes == nil {
		return nil, ErrNoLinkBoxes
	}
	job := &Job{
		linkBoxes:  config.LinkBoxes,
		every:      config.Every,
		bounds:     config.Bounds,
		maxBatches: config.MaxBatches,
		budget:     config.Budget,
		pause:      config.Pause,
		now:        config.Now,
		sleep:      config.Sleep,
		ticks:      config.Ticks,
		log:        config.Log,
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	job.context, job.cancel = context.WithCancel(context.Background())
	if job.every <= 0 {
		job.every = DefaultEvery
	}
	if job.bounds.Deposits == 0 {
		job.bounds.Deposits = store.DefaultLinkBoxSweepBounds.Deposits
	}
	if job.bounds.Boxes == 0 {
		job.bounds.Boxes = store.DefaultLinkBoxSweepBounds.Boxes
	}
	if job.maxBatches <= 0 {
		job.maxBatches = DefaultMaxBatches
	}
	if job.budget <= 0 {
		job.budget = DefaultBudget
	}
	if job.pause <= 0 {
		job.pause = DefaultPause
	}
	if job.now == nil {
		job.now = time.Now
	}
	if job.sleep == nil {
		job.sleep = time.Sleep
	}
	if job.ticks == nil {
		job.ticks = func(every time.Duration) (<-chan time.Time, func()) {
			ticker := time.NewTicker(every)
			return ticker.C, ticker.Stop
		}
	}
	if job.log == nil {
		job.log = slog.New(slog.DiscardHandler)
	}
	return job, nil
}

// Start runs a pass on every tick, on a goroutine of its own, until [Job.Close]. A second Start,
// or a Start after Close, starts nothing.
func (self *Job) Start() {
	self.startOnce.Do(func() {
		ticks, stopTicks := self.ticks(self.every)
		go func() {
			defer close(self.done)
			defer stopTicks()
			for {
				select {
				case <-self.stop:
					return
				case <-ticks:
					self.Pass(self.context)
				}
			}
		}()
	})
}

// Close stops the ticks, ends a pass in flight at its next batch, and waits for it. It is safe to
// call more than once, and on a job that was never started.
func (self *Job) Close() {
	self.closeOnce.Do(func() {
		close(self.stop)
		self.cancel()
		// a job never started has no goroutine to wait for; this also makes a later Start a no-op
		self.startOnce.Do(func() { close(self.done) })
		<-self.done
	})
}

// Pass is one tick's work: batches until one reaches neither of Q19's bounds, the lock is found
// held, the pass has run its batches or spent its budget, or ctx ends. Each batch is one
// transaction, and a pause separates two. An error ends the pass and is returned, and the next
// tick tries again.
func (self *Job) Pass(ctx context.Context) (Totals, error) {
	totals := Totals{}
	started := self.now()
	for totals.Batches < self.maxBatches {
		if totals.Batches != 0 {
			self.sleep(self.pause)
			// no batch starts once the pass has spent its budget
			if self.budget <= self.now().Sub(started) {
				break
			}
		}
		if err := ctx.Err(); err != nil {
			return totals, err
		}
		swept, err := self.linkBoxes.SweepLinkBoxes(ctx, self.now(), self.bounds)
		if err != nil {
			self.log.Warn("the link box sweep failed", "batches", totals.Batches, "error", err.Error())
			return totals, err
		}
		if swept.Skipped {
			totals.Skipped = true
			self.log.Debug("the link box sweep skipped this tick: another sweeper holds the lock")
			return totals, nil
		}
		totals.Batches += 1
		totals.Deposits += uint64(swept.Deposits)
		totals.Boxes += uint64(swept.Boxes)
		if swept.Deposits < self.bounds.Deposits && swept.Boxes < self.bounds.Boxes {
			break
		}
	}
	if totals.Deposits != 0 || totals.Boxes != 0 {
		self.log.Info("the link box sweep reclaimed expired rendezvous state",
			"boxes", totals.Boxes, "deposits", totals.Deposits, "batches", totals.Batches)
	}
	return totals, nil
}
