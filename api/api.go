package api

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The refusals this package can only answer with an error, because no client could have caused
// them: a handler built without the collaborators §5.1 needs, or a request that arrived on no
// connection at all. A client's answer is always a [protocol.Reason], never one of these.
var (
	ErrNoStore       = errors.New("api: a handler is built around a store, and §6.1 has nowhere to run without one")
	ErrNoKnownGroups = errors.New("api: §5.1 check 5 is a filter this handler was not given, and a missing filter is a database read per unknown group")
	ErrNoFrontChecks = errors.New("api: §5.1 checks 1, 2 and 4 have an owner or they are skipped silently; pass ChecksNotImplemented to say so out loud")
	ErrNoConnection  = errors.New("api: §5.1 check 2 reads the server_nonce from the connection and never from the request, so there has to be a connection")
	ErrNoOpForBody   = errors.New("api: the request body is not an arm of MessageServerRequest.body, so §4.3.8 gives it no op byte")
)

// §5.1 check 3's head cap, which the spec names and never gives a number to (see the note in
// [Config.MaxCtHeadBytes]). It is the top of the inline body ladder, read from the ladder
// rather than typed, so a rung added above 64 KiB moves this bound with it instead of leaving
// a head cap below a body size the same server accepts.
var DefaultMaxCtHeadBytes = message.SizeBucketBytes(message.SizeBucket64K)

// §4.3.1's advertised batch limits, at their documented defaults.
const (
	DefaultMaxRecordsPerSubmit = 256
	DefaultMaxRecordsPerFetch  = 512
)

// What the connect layer knows about the connection a request arrived on.
//
// The `server_nonce` is here and not in any request message, which is §5.1 check 2 stated as a
// data shape rather than as a rule to remember: "the server knows its own connection's nonce
// and looks it up from the connection, never from the request". A nonce a request could carry
// is a nonce an attacker chooses, and both authenticators of §5.4 are computed over it.
type Connection struct {
	ServerNonce []byte

	// The platform-authenticated `source.SourceId` of §5.1 check 2, which every §4.7 rate limit
	// and every §8.2 grant binding rests on. This package never validates it — decision B1 puts
	// the code that could in server/model, which §2.2 forbids — it is handed the result.
	ClientId []byte
}

// §5.1 check 5's known-group filter: every `group_id` that exists, in memory, answered without
// a database read.
//
// It is an interface because the deployed one is not this process's own map. §5.1 describes a
// cuckoo filter fed by an add published over Redis from the CreateGroup transaction's
// after-commit hook, with a 60-second full refresh as a backstop, and the shape that matters to
// a caller is which direction it may be wrong in: a false positive costs one wasted epoch-key
// lookup, and a false negative is a member told REASON_REJECTED for a group that exists — which
// §4.5 makes indistinguishable from a bad MAC, so the client can render nothing diagnosable and
// the operator sees nothing. Insert before responding, refresh as a backstop, never the reverse.
type KnownGroups interface {
	Contains(groupId []byte) bool
	Insert(groupId []byte)
}

// The single-process filter: every group this instance has created or been told about.
//
// It has no false positives, which the cuckoo filter of §5.1 does, so a handler under this one
// never pays the epoch-key lookup a filter hit can be wrong about. That is the direction that
// costs nothing to be wrong in, and the one nothing here may rely on: no code in this package
// may read "the filter said yes" as "the group exists".
type memoryKnownGroups struct {
	mutex sync.RWMutex
	ids   map[string]bool
}

func NewMemoryKnownGroups() KnownGroups {
	return &memoryKnownGroups{ids: map[string]bool{}}
}

func (self *memoryKnownGroups) Contains(groupId []byte) bool {
	self.mutex.RLock()
	defer self.mutex.RUnlock()
	return self.ids[string(groupId)]
}

func (self *memoryKnownGroups) Insert(groupId []byte) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.ids[string(groupId)] = true
}

// One §5.1 check, or one capability behind §6.1, that this build does not perform.
//
// It is a value rather than a comment because a skipped check that looks like a passed check is
// how a pipeline ships with a hole. [Handler.NotBuilt] answers the whole list, §10.1's readiness
// endpoint has something to refuse on, and TestEveryCheckOfSpecB51IsRunOrDeclared reads §5.1's
// own table and fails if a number is neither run nor named here.
type NotBuilt struct {
	// The §5.1 check number, or 0 for something that is not one of the nine.
	Check int
	// The section that specifies it, and what is missing, in the operator's words.
	Section string
	What    string
	// The package that will hold it. Named so the gap has an address rather than a shrug.
	Owner string
}

func (self NotBuilt) String() string {
	if self.Check == 0 {
		return fmt.Sprintf("%s (%s) is not built; it belongs to %s", self.What, self.Section, self.Owner)
	}
	return fmt.Sprintf("§5.1 check %d, %s (%s), is not run; it belongs to %s", self.Check, self.What, self.Section, self.Owner)
}

// §5.1 checks 1, 2 and 4, which belong to the transport and the rate limiter.
//
// They are an interface with one implementation rather than three calls this package does not
// make, because "not called" and "called and passed" are the same green test. A handler cannot
// be built without something in this slot, and the only thing there is to put in it is
// [ChecksNotImplemented], whose name is the whole point.
type FrontChecks interface {
	// Check 1: the frame decoded and fragment reassembly stayed inside `max_request_bytes`
	// (§4.6). REASON_OVERSIZE on failure, and the reassembly buffer is freed immediately.
	FrameWithinLimits(ctx context.Context, conn *Connection) protocol.Reason

	// Check 2: the connection is authenticated at the connect layer. §5.1 states this as a
	// dependency on the operator transport rather than as an assumption, because decision B1
	// forbids importing the package that could verify it here.
	ConnectionAuthenticated(ctx context.Context, conn *Connection) protocol.Reason

	// Check 4: §4.7's rate limits and §9.6's quarantine, per op byte.
	WithinRateLimits(ctx context.Context, conn *Connection, op uint8) protocol.Reason

	// What this implementation does not actually check.
	NotBuilt() []NotBuilt
}

// The only implementation of [FrontChecks] there is: it answers REASON_OK to all three and says
// so in [ChecksNotImplemented.NotBuilt].
//
// peer/ (checks 1 and 2) and the Redis rate limiter (check 4) do not exist yet. This type is
// what keeps that fact in the process rather than in a commit message: it is named for what it
// does not do, a handler prints its list at startup, and the coverage gate fails the day
// somebody deletes an entry without writing the check.
type ChecksNotImplemented struct{}

var _ FrontChecks = ChecksNotImplemented{}

func (ChecksNotImplemented) FrameWithinLimits(ctx context.Context, conn *Connection) protocol.Reason {
	return protocol.Reason_REASON_OK
}

func (ChecksNotImplemented) ConnectionAuthenticated(ctx context.Context, conn *Connection) protocol.Reason {
	return protocol.Reason_REASON_OK
}

func (ChecksNotImplemented) WithinRateLimits(ctx context.Context, conn *Connection, op uint8) protocol.Reason {
	return protocol.Reason_REASON_OK
}

func (ChecksNotImplemented) NotBuilt() []NotBuilt {
	return []NotBuilt{
		{
			Check:   1,
			Section: "§4.6, §5.1",
			What:    "frame decode and fragment reassembly inside max_request_bytes",
			Owner:   "peer",
		},
		{
			Check:   2,
			Section: "§5.1, §4.3 master",
			What:    "the connect layer's ByJwt authentication of source.SourceId",
			Owner:   "peer, over the operator transport",
		},
		{
			Check:   4,
			Section: "§4.7, §9.6",
			What:    "rate limits and the quarantine check",
			Owner:   "a Redis-backed limiter this module does not have",
		},
	}
}

// A handler's collaborators. Everything whose zero value would be a silent hole is refused by
// [New] rather than defaulted.
type Config struct {
	Store       store.Store
	KnownGroups KnownGroups
	Front       FrontChecks

	// §5.1 check 3's "`ct_head` ≤ head cap". The spec names the cap in check 3 and never gives
	// it a number — it is in no Capabilities field, no DDL CHECK and no other section — so this
	// is a configured bound and [DefaultMaxCtHeadBytes] says where its default comes from. Zero
	// takes that default.
	MaxCtHeadBytes int

	// §4.3.1's `max_records_per_submit` and `max_records_per_fetch`. Zero takes the defaults.
	MaxRecordsPerSubmit int
	MaxRecordsPerFetch  int

	// §4.5's fixed latency floor on the reject path, which is the third of the three things a
	// merged REASON_REJECTED has to keep identical — the same code, the same response size, and
	// the same timing envelope. Zero pads nothing, which is honest about a floor nobody
	// configured rather than a floor of zero pretending to be one.
	RejectFloor time.Duration

	// Injectable so that the pad is observable without a test that sleeps. Both default to the
	// real clock and the real sleep.
	Now   func() time.Time
	Sleep func(time.Duration)
}

// The request handlers of §4.3, with the check order of §5.1 in front of them.
type Handler struct {
	store       store.Store
	knownGroups KnownGroups
	front       FrontChecks

	maxCtHeadBytes      int
	maxRecordsPerSubmit int
	maxRecordsPerFetch  int

	rejectFloor time.Duration
	now         func() time.Time
	sleep       func(time.Duration)
}

func New(config Config) (*Handler, error) {
	if config.Store == nil {
		return nil, ErrNoStore
	}
	if config.KnownGroups == nil {
		return nil, ErrNoKnownGroups
	}
	if config.Front == nil {
		return nil, ErrNoFrontChecks
	}
	handler := &Handler{
		store:               config.Store,
		knownGroups:         config.KnownGroups,
		front:               config.Front,
		maxCtHeadBytes:      config.MaxCtHeadBytes,
		maxRecordsPerSubmit: config.MaxRecordsPerSubmit,
		maxRecordsPerFetch:  config.MaxRecordsPerFetch,
		rejectFloor:         config.RejectFloor,
		now:                 config.Now,
		sleep:               config.Sleep,
	}
	if handler.maxCtHeadBytes == 0 {
		handler.maxCtHeadBytes = DefaultMaxCtHeadBytes
	}
	if handler.maxRecordsPerSubmit == 0 {
		handler.maxRecordsPerSubmit = DefaultMaxRecordsPerSubmit
	}
	if handler.maxRecordsPerFetch == 0 {
		handler.maxRecordsPerFetch = DefaultMaxRecordsPerFetch
	}
	if handler.now == nil {
		handler.now = time.Now
	}
	if handler.sleep == nil {
		handler.sleep = func(remaining time.Duration) {
			if 0 < remaining {
				time.Sleep(remaining)
			}
		}
	}
	return handler, nil
}

// Everything §5.1 or §6.1 specifies that this build does not perform: the front checks' three,
// and the two record kinds whose acceptance would rest on machinery that is absent.
//
// §10.1's readiness endpoint is the intended reader. A list that is empty in production and
// non-empty here is the difference between a server that passes eight checks and a server that
// passes eight checks and knows which one it did not.
func (self *Handler) NotBuilt() []NotBuilt {
	notBuilt := append([]NotBuilt{}, self.front.NotBuilt()...)
	notBuilt = append(notBuilt, unbuiltCapabilities...)
	if self.rejectFloor == 0 {
		notBuilt = append(notBuilt, unpaddedRejectPath)
	}
	return notBuilt
}

// §4.5's timing envelope, when nobody configured a floor for it.
//
// The other three bounds this package takes from [Config] have defaults, and this one deliberately
// does not: §4.5 requires the envelope and no section of the spec gives it a number, so a default
// here would be an invented latency published as though the spec had named it. What a missing
// number must not be is silent. Two of §4.5's three properties — the same code and the same
// response size — are properties of what this package builds and hold in every deployment; the
// third is a property of when it answers, and a build with no floor loses it while still passing
// every test that asserts the other two. §10.1's readiness endpoint is the intended reader, and
// the asymmetry with the three defaulted bounds is the whole reason this is a value rather than a
// sentence in [Config.RejectFloor]'s comment.
var unpaddedRejectPath = NotBuilt{
	Section: "§4.5",
	What:    "the reject path's fixed latency floor: Config.RejectFloor is zero, so every refusal answers as fast as its own path allows and the timing envelope of a merged REASON_REJECTED is not held",
	Owner:   "the operator's configuration",
}

// What this layer refuses, or omits, rather than half-serving.
//
// None of the three is a check of §5.1 — each is a capability behind §6.1 or §4.3.4 that the
// module does not have — so each carries Check 0 and the check-coverage gate holds them to
// nothing. They are on the same list because a reader asking "what does this build not do"
// wants one list.
var unbuiltCapabilities = []NotBuilt{
	{
		Section: "§7.6, §4.3.3",
		What:    "the EPH(0) transient channel: a transient is never persisted, and there is nothing here to fan one out to",
		Owner:   "peer, over Redis",
	},
	{
		Section: "§8.3",
		What:    "blob binding: a size_bucket 5 record binds against message_blob's content_hash, and there is no blob store and no blob table",
		Owner:   "blobd and store",
	},
	{
		Section: "§4.3.4, §9.4",
		What:    "FetchAttestation: an Ed25519 signature by the fleet key over nine response fields, and this process holds no fleet key",
		Owner:   "the key custody of §9.1, through kt",
	},
}

// §4.3.8's `op`: the field number of the selected `oneof body` arm of MessageServerRequest.
//
// It is read out of the compiled descriptor rather than written down. The number is a MAC input
// — it is `u8(op)` inside the req_auth preimage — so a constant here that disagreed with the arm
// would produce a REASON_REJECTED on exactly one operation, for exactly one implementation,
// which §4.5 deliberately refuses to explain to the client. Reading the descriptor makes the
// server's op and the wire's arm the same fact rather than two that agree today.
func opOf(body proto.Message) (uint8, error) {
	if body == nil {
		return 0, ErrNoOpForBody
	}
	want := body.ProtoReflect().Descriptor().FullName()
	fields := (&protocol.MessageServerRequest{}).ProtoReflect().Descriptor().Fields()
	for index := 0; index < fields.Len(); index++ {
		field := fields.Get(index)
		if field.Kind() != protoreflect.MessageKind || field.ContainingOneof() == nil {
			continue
		}
		if field.Message().FullName() != want {
			continue
		}
		if field.Number() < 0 || 255 < field.Number() {
			return 0, fmt.Errorf("%w: %s is arm %d, which is not a u8", ErrNoOpForBody, want, field.Number())
		}
		return uint8(field.Number()), nil
	}
	return 0, fmt.Errorf("%w: %s", ErrNoOpForBody, want)
}

// §4.5's third property of a merged refusal: the same timing envelope.
//
// The code and the response size are properties of what this package builds, and are asserted
// directly. The envelope is a property of when it answers, and without this an unknown group is
// one filter probe away from its rejection while a bad MAC is a database read and an HMAC away
// — a difference an attacker measures rather than reads.
//
// The sleep is injectable so that a test can observe that every refusing path pads, and pads to
// the same floor, without measuring wall clock and flaking.
func (self *Handler) pad(started time.Time) {
	if self.rejectFloor == 0 {
		return
	}
	self.sleep(self.rejectFloor - self.now().Sub(started))
}
