package peer

import (
	"container/list"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// §4.6's own numbers, as constants rather than as literals in the middle of a branch.
const (
	// "The sender chooses `part` size as min(peer_advertised_frame_budget, 2048) bytes and MUST
	// NOT exceed the negotiated budget." The 2048 is the ceiling of that min, so it is a bound no
	// configuration reaches past rather than a default a configuration replaces — see [partSize].
	// connect advertises no per-peer frame budget to a caller, so with nothing to be the smaller
	// of, the ceiling is also the whole of the default.
	MaxFragmentPartBytes     = 2048
	DefaultFragmentPartBytes = MaxFragmentPartBytes

	// "Reassembly state is per (source client_id, request_id), expires after 30 s, and is capped
	// at 16 concurrent in-flight reassemblies per client."
	DefaultReassemblyIdle        = 30 * time.Second
	DefaultReassembliesPerClient = 16

	// The reassemblies this server holds at once, across every client that has one open.
	//
	// §4.6 bounds one client and names nothing above it, and above it is where a bound has to
	// be. Reassembly is keyed on the `source.SourceId` connect hands the receive callback; §5.1
	// check 2 resolves a connection one stage later, inside the api pipeline; so a client_id
	// that has never said Hello opens buffers here. Sixteen per client multiplied by as many
	// client_ids as an attacker cares to name is not a bound at all — ten thousand of them is
	// ten thousand times sixteen times `max_request_bytes`, which is the memory-exhaustion
	// vector §4.6 is written against, reached around its per-client cap rather than through it.
	//
	// A count rather than a byte budget, because §4.6's own bound is a count and the two have to
	// be comparable; the byte budget it implies is this count times `max_request_bytes`, which
	// at §4.6's own working assumption is 1024 x 131072 = 128 MiB. Spec B gives no number here,
	// so this one is declared by [Peer.NotBuilt] as a bound of this build's own choosing rather
	// than presented as §4.6's — see [globalReassemblyBound].
	DefaultMaxReassemblies = 1024

	// §4.6: "the working assumption is max_request_bytes = 131072 with fragmentation on", and
	// §4.3.1's `max_response_bytes` default is 1048576. Both are advertised in Capabilities and
	// both are enforced here, from the same field — see [Config.Capabilities].
	DefaultMaxRequestBytes  = 131072
	DefaultMaxResponseBytes = 1048576
)

// §5.1 check 1's bound, decided in one function.
//
// Two call sites need this answer and they must not be two answers. The reassembler applies it
// as a memory bound — §4.6 requires the buffer freed the moment it would be exceeded, which
// cannot wait for a pipeline stage — and [Checks.FrameWithinLimits] applies it as check 1's
// refusal on every request, fragmented or not. A second copy of `max < bytes` in either place is
// a build whose advertised cap and enforced cap differ by whichever one somebody edited.
//
// The comparison is `max < bytes`, and both of its neighbours are wrong in a way no size far
// from the bound can see. `max <= bytes` refuses a request of exactly the number §4.3.1
// advertises, which is the size a client that reads Capabilities cuts its largest request to;
// anything looser serves a request past the number this server told every client it enforces.
// Each is one character, which is why the boundary is asserted at the number rather than near it
// — see TestCheckOnesBoundIsExactlyTheNumberCapabilitiesAdvertises.
func withinLimits(bytes int, max int) protocol.Reason {
	if max < bytes {
		return protocol.Reason_REASON_OVERSIZE
	}
	return protocol.Reason_REASON_OK
}

// §4.6's `part` size, decided in one function: min(peer_advertised_frame_budget, 2048).
//
// A budget of zero or less names no negotiation at all — and connect advertises none — so it
// takes the ceiling. A budget above the ceiling is clamped rather than honoured, because §4.6's
// rule is a MUST NOT: a build that could configure its way past it would put fragments on the
// wire at a size a conforming receiver is entitled to refuse, chosen by whoever wrote the yml.
//
// Idempotent, which is what makes it safe to apply where the peer is built and again where the
// frames are cut: two call sites of one rule rather than two expressions of it, which is the
// arrangement that survives one of them being edited.
func partSize(budget int) int {
	if budget <= 0 || MaxFragmentPartBytes < budget {
		return MaxFragmentPartBytes
	}
	return budget
}

// ── §4.6's aborts, as a table rather than as a chain of ifs ──────────────────────────────

// One of §4.6's abort conditions.
//
// They are values because the *class* of them is what a test has to be right about, and a class
// typed out by hand has understated itself every time it has been tried on this project. The
// four conditions listed beside this code were five conditions' worth of enforcement, and the
// one the list left out — a `count` that changes mid-reassembly — could be deleted with the
// whole suite green. TestEveryWaySpecB46AbortsAReassembly now iterates this table, fails while
// any rule in it has no case of its own, and proves each case belongs to its own rule by taking
// that rule away and watching the refusal it claims disappear.
//
// Order matters only for the one abort §4.6 names a code for. Several rules can fire on one
// fragment and the first of them decides, so `max_request_bytes` is asked last: everything above
// it answers §4.5's non-specific REASON_REJECTED, and a fragment that is both out of order and
// oversize is out of order first.
type abortRule struct {
	name string

	// The refusal this rule decides, or REASON_OK when this fragment is not its business.
	refuses func(state fragmentState) protocol.Reason
}

// What one abort rule decides on: the arriving fragment, whatever is already buffered under its
// key, and the bounds this reassembler holds.
//
// A value rather than the reassembler itself, so that a rule cannot reach past what it is
// deciding about — and so that a test can build the state a rule fires on without having to
// build the history that would produce it.
type fragmentState struct {
	fragment *protocol.MessageServerFragment

	// nil when nothing is open for this (client_id, request_id) yet: this fragment would open it.
	current *partial

	openForClient int
	open          int

	perClient       int
	maxReassemblies int
	maxRequestBytes int
}

// The index this reassembly will accept. A reassembly that does not exist yet accepts index 0,
// which is what makes "a first fragment must be index 0" the same rule as "in order" rather than
// a second rule beside it.
func (self fragmentState) next() uint32 {
	if self.current == nil {
		return 0
	}
	return self.current.next
}

func (self fragmentState) buffered() int {
	if self.current == nil {
		return 0
	}
	return len(self.current.bytes)
}

// Whether this fragment would open a reassembly rather than continue one.
func (self fragmentState) opening() bool {
	return self.current == nil
}

// Every way §4.6 aborts a reassembly, in the order they are asked.
var reassemblyAborts = []abortRule{
	{
		// a `count` of zero is the degenerate case of this rather than a rule beside it: it
		// names no fragments at all, and no index is below zero of them
		name: "an index that is not below the fragment count",
		refuses: func(state fragmentState) protocol.Reason {
			if state.fragment.GetCount() <= state.fragment.GetIndex() {
				return protocol.Reason_REASON_REJECTED
			}
			return protocol.Reason_REASON_OK
		},
	},
	{
		// §4.6: "out-of-order `index` aborts the request rather than buffering holes". Asked
		// before the buffer exists, this is also "a first fragment that is not index 0 is a
		// request whose beginning is not coming"
		name: "an index that is not the one this reassembly is waiting for",
		refuses: func(state fragmentState) protocol.Reason {
			if state.fragment.GetIndex() != state.next() {
				return protocol.Reason_REASON_REJECTED
			}
			return protocol.Reason_REASON_OK
		},
	},
	{
		// the count is fixed by the fragment that opened the reassembly. A sender that changes
		// it mid-request is describing two different requests under one request_id, and this
		// buffer completes on the number it was opened with
		name: "a fragment count that changed mid-reassembly",
		refuses: func(state fragmentState) protocol.Reason {
			if state.opening() {
				return protocol.Reason_REASON_OK
			}
			if state.fragment.GetCount() != state.current.count {
				return protocol.Reason_REASON_REJECTED
			}
			return protocol.Reason_REASON_OK
		},
	},
	{
		// §4.6's sixteen concurrent reassemblies per client. §4.6 names no reason code for it,
		// and §4.5's REASON_REJECTED is the non-specific refusal every unnamed one falls back
		// to: REASON_RATE_LIMITED would be a claim that this build has the limiter of §4.7, and
		// §5.1 check 4 is still absent
		name: "§4.6's concurrent reassemblies for one client",
		refuses: func(state fragmentState) protocol.Reason {
			if state.opening() && state.perClient <= state.openForClient {
				return protocol.Reason_REASON_REJECTED
			}
			return protocol.Reason_REASON_OK
		},
	},
	{
		// and the bound above that one, which §4.6 does not give and which the per-client cap
		// multiplies by every client_id an attacker cares to name without it — see
		// [DefaultMaxReassemblies]. Zero or less is no global bound at all, which is what the
		// client side of a test reassembles under
		name: "the reassemblies this server holds for every client at once",
		refuses: func(state fragmentState) protocol.Reason {
			if state.opening() && 0 < state.maxReassemblies && state.maxReassemblies <= state.open {
				return protocol.Reason_REASON_REJECTED
			}
			return protocol.Reason_REASON_OK
		},
	},
	{
		// §5.1 check 1's `max_request_bytes`, over the reassembled request rather than over any
		// one frame, and asked last because it is the one abort §4.6 names a code for
		name: "§5.1 check 1's max_request_bytes over the whole reassembly",
		refuses: func(state fragmentState) protocol.Reason {
			return withinLimits(state.buffered()+len(state.fragment.GetPart()), state.maxRequestBytes)
		},
	},
}

// §4.6's inbound reassembly: the fragments of one request, per (source client_id, request_id).
type reassembly struct {
	now func() time.Time

	maxRequestBytes int
	perClient       int
	maxReassemblies int
	idle            time.Duration

	// [reassemblyAborts], as a field, so that a test can take one rule away and watch what stops
	// being refused. Every production reassembler holds the package table.
	aborts []abortRule

	mutex    sync.Mutex
	inFlight map[reassemblyKey]*partial
	counts   map[connect.Id]int

	// The open reassemblies in the order they began, which is the order they expire in — see
	// [reassembly.expire].
	order *list.List

	// How many buffers the expiry has had to look at, over the life of this reassembler. See
	// [reassembly.expiryReads].
	examined uint64
}

type reassemblyKey struct {
	clientId  connect.Id
	requestId uint64
}

// One request being assembled. `next` is the index this buffer will accept and nothing else:
// §4.6 is explicit that "out-of-order `index` aborts the request rather than buffering holes",
// so there is no place here to put a hole in.
type partial struct {
	count   uint32
	next    uint32
	bytes   []byte
	started time.Time

	// Where this reassembly sits in [reassembly.order], so that dropping it is a removal rather
	// than a search for it.
	element *list.Element
}

func newReassembly(now func() time.Time, maxRequestBytes int, perClient int, maxReassemblies int, idle time.Duration) *reassembly {
	return &reassembly{
		now:             now,
		maxRequestBytes: maxRequestBytes,
		perClient:       perClient,
		maxReassemblies: maxReassemblies,
		idle:            idle,
		aborts:          reassemblyAborts,
		inFlight:        map[reassemblyKey]*partial{},
		counts:          map[connect.Id]int{},
		order:           list.New(),
	}
}

// One fragment, applied.
//
// Answers the assembled request bytes, whether the request is now complete, and a refusal reason
// on any of [reassemblyAborts]. Every abort frees the buffer before returning, which is §4.6's
// "frees the buffer immediately" — an unbounded reassembly buffer is the memory-exhaustion
// vector the rule exists for, and a buffer freed one stage later is a buffer an attacker gets to
// hold open by never sending the last fragment.
//
// Every rule is asked before anything is created, so a refusal on the fragment that would have
// opened a reassembly allocates nothing at all: a cap applied after the allocation is a cap on
// nothing that matters.
//
// Completion is its own return value and not a nil check on the bytes, because a request can be
// zero bytes long: `proto.Marshal(&MessageServerRequest{})` is zero bytes, and nothing stops a
// client fragmenting one. Signalled by a nil slice, that reassembly *completed* — its state
// freed and its per-client count decremented — while answering the sentinel that means "more
// fragments are expected", so the caller returned without sending anything and without counting
// a drop: a well-formed frame carrying a request_id that was received, never served and never
// answered. The unfragmented path decodes those same zero bytes and answers REASON_REJECTED,
// and §4.6 is not a second opinion about what an empty request means.
func (self *reassembly) accept(clientId connect.Id, fragment *protocol.MessageServerFragment) ([]byte, bool, protocol.Reason) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.expire()

	key := reassemblyKey{clientId: clientId, requestId: fragment.GetRequestId()}
	current := self.inFlight[key]
	state := fragmentState{
		fragment:        fragment,
		current:         current,
		openForClient:   self.counts[clientId],
		open:            len(self.inFlight),
		perClient:       self.perClient,
		maxReassemblies: self.maxReassemblies,
		maxRequestBytes: self.maxRequestBytes,
	}
	for _, rule := range self.aborts {
		reason := rule.refuses(state)
		if reason == protocol.Reason_REASON_OK {
			continue
		}
		// whatever this key holds goes now — and a key that holds nothing is a drop of nothing,
		// which is every rule that fires on the fragment that would have opened one
		self.drop(key)
		return nil, false, reason
	}

	if current == nil {
		current = &partial{count: fragment.GetCount(), started: self.now()}
		self.inFlight[key] = current
		current.element = self.order.PushBack(key)
		self.counts[clientId]++
	}
	current.bytes = append(current.bytes, fragment.GetPart()...)
	current.next++
	if current.next < current.count {
		return nil, false, protocol.Reason_REASON_OK
	}
	assembled := current.bytes
	self.drop(key)
	return assembled, true, protocol.Reason_REASON_OK
}

// Everything past §4.6's 30 seconds, dropped, and how many went.
//
// Called under the caller's lock on every accept, so a client that opens fifteen reassemblies and
// walks away has them collected by its own sixteenth attempt rather than holding its own cap. That
// bounds a busy server and it does not bound a quiet one: nothing arrives to sweep, and every
// buffer of every client that went silent is held for as long as the silence lasts. §4.6's thirty
// seconds is a bound on an attacker rather than a courtesy, so [Peer.sweepLoop] applies it on a
// clock of this process's own as well.
//
// The bound is on when the reassembly *began* and is not refreshed by a fragment, which is what
// "reassembly state expires after 30 s" says: a sender that drips one byte every twenty seconds
// would otherwise hold a buffer open for as long as it liked.
//
// That is also what lets this cost what it drops rather than what is open. Reassemblies expire in
// the order they began, [reassembly.order] is kept in that order, and the first entry inside the
// bound ends the walk. The alternative — the whole map scanned on every arriving fragment — is
// linear in what is open and so quadratic in an attacker's total work, with the mutex every
// client's fragments queue behind held for all of it: the enforcement of a DoS control paying the
// attacker's costs for him.
func (self *reassembly) expire() int {
	if self.idle == 0 {
		return 0
	}
	dropped := 0
	deadline := self.now().Add(-self.idle)
	for element := self.order.Front(); element != nil; element = self.order.Front() {
		key, _ := element.Value.(reassemblyKey)
		self.examined++
		current, found := self.inFlight[key]
		if !found {
			// nothing holds this key any more, so this entry is stale and goes with it.
			// Unreachable while [reassembly.drop] is the only removal — and a break here would
			// leave the walk stopping on it forever
			self.order.Remove(element)
			continue
		}
		if !current.started.Before(deadline) {
			break
		}
		self.drop(key)
		dropped++
	}
	return dropped
}

// §4.6's thirty seconds, applied with no fragment to hang them on. See [expire] for why the
// expiry inside [reassembly.accept] is not the whole of the bound, and [Peer.sweepLoop] for what
// runs this.
func (self *reassembly) sweep() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.expire()
}

// One reassembly's state, released: the buffer, its place in the expiry order, and the per-client
// slot it was counted against.
//
// The client_id is read off the key rather than taken as a second argument. The two must name
// the same client — the count that gates §4.6's per-client cap is the count of exactly these
// entries — and an argument that can disagree with the key is an argument that eventually does:
// a drop that decremented the wrong client would leave one client capped against buffers it does
// not hold and another holding buffers nothing counts.
func (self *reassembly) drop(key reassemblyKey) {
	current, found := self.inFlight[key]
	if !found {
		return
	}
	delete(self.inFlight, key)
	if current.element != nil {
		self.order.Remove(current.element)
		current.element = nil
	}
	if self.counts[key.clientId] <= 1 {
		delete(self.counts, key.clientId)
		return
	}
	self.counts[key.clientId]--
}

// What §4.6's reassembler is holding at this instant.
//
// It exists because "the buffer was freed" is not observable from a refusal. A receiver that
// answers REASON_OVERSIZE and keeps the bytes and one that frees them answer a client
// identically, and the difference between the two is precisely the memory-exhaustion vector the
// rule is written against — so the freeing is asserted here rather than inferred from the code
// that is supposed to do it.
//
// Three numbers rather than one, because §4.6 bounds three things: how many reassemblies are open,
// how many clients hold one, and how many bytes are buffered under them. An accounting that
// dropped a buffer and kept its per-client slot would leak the cap while every byte count stayed
// honest, and one that did the reverse would leak the memory.
type held struct {
	reassemblies int
	clients      int
	bytes        int
}

func (self *reassembly) holding() held {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	holding := held{reassemblies: len(self.inFlight), clients: len(self.counts)}
	for _, buffered := range self.inFlight {
		holding.bytes += len(buffered.bytes)
	}
	return holding
}

// How many buffers §4.6's expiry has had to look at, over the life of this reassembler.
//
// It is here for the reason [reassembly.holding] is: the cost of the enforcement is not
// observable from its answer. An expiry that scans every open reassembly on every arriving
// fragment refuses exactly what one that walks only the expired ones refuses, and the difference
// is that the first is linear in what is open — so ten thousand reassemblies, which anyone may
// open, make every other client's fragment cost ten thousand comparisons with the reassembler's
// mutex held. Counted rather than timed, because what is claimed is a complexity and not a
// duration, and a duration asserted on a shared machine is a flake.
func (self *reassembly) expiryReads() uint64 {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.examined
}

// The frames one response travels in: one response frame, or §4.6's fragments of it.
//
// `Frame.raw` is false on every one of them, which §4.2 states for the whole of this binding —
// a raw frame carries bytes that are not a protobuf, and every frame here is one.
//
// §4.6's part size is applied here rather than trusted from the caller. [New] applies it too, and
// [partSize] is idempotent so the second application changes nothing; what it buys is that this
// function cannot be handed a part size at all — a zero would be a division by zero on the
// fragment count, and anything past the ceiling would be a MUST NOT on the wire.
func responseFrames(response *protocol.MessageServerResponse, partBytes int) ([]*protocol.Frame, error) {
	partBytes = partSize(partBytes)
	body, err := connect.ProtoMarshal(response)
	if err != nil {
		return nil, err
	}
	if len(body) <= partBytes {
		return []*protocol.Frame{{
			MessageType:  protocol.MessageType_MessageMessageServerResponse,
			MessageBytes: body,
		}}, nil
	}

	count := (len(body) + partBytes - 1) / partBytes
	frames := make([]*protocol.Frame, 0, count)
	for index := 0; index < count; index++ {
		end := min((index+1)*partBytes, len(body))
		fragment, err := connect.ProtoMarshal(&protocol.MessageServerFragment{
			RequestId: response.GetRequestId(),
			Index:     uint32(index),
			Count:     uint32(count),
			Part:      body[index*partBytes : end],
		})
		if err != nil {
			// free what was built before giving up, so a marshal failure halfway through a
			// large response does not leak the pool buffers of the fragments before it
			returnFrames(frames)
			connect.MessagePoolReturn(body)
			return nil, err
		}
		frames = append(frames, &protocol.Frame{
			MessageType:  protocol.MessageType_MessageMessageServerFragment,
			MessageBytes: fragment,
		})
	}
	// the whole response now lives in the fragments, so the buffer it was marshaled into goes
	// back to the pool rather than to the collector
	connect.MessagePoolReturn(body)
	return frames, nil
}

// Give a frame's bytes back to the pool. MessagePoolReturn drops anything that did not come
// from one, so this is safe on a frame built any other way.
func returnFrames(frames []*protocol.Frame) {
	for _, frame := range frames {
		connect.MessagePoolReturn(frame.MessageBytes)
	}
}
