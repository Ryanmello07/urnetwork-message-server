package peer

import (
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

// §4.6's inbound reassembly: the fragments of one request, per (source client_id, request_id).
type reassembly struct {
	now func() time.Time

	maxRequestBytes int
	perClient       int
	idle            time.Duration

	mutex    sync.Mutex
	inFlight map[reassemblyKey]*partial
	counts   map[connect.Id]int
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
}

func newReassembly(now func() time.Time, maxRequestBytes int, perClient int, idle time.Duration) *reassembly {
	return &reassembly{
		now:             now,
		maxRequestBytes: maxRequestBytes,
		perClient:       perClient,
		idle:            idle,
		inFlight:        map[reassemblyKey]*partial{},
		counts:          map[connect.Id]int{},
	}
}

// One fragment, applied.
//
// Answers the assembled request bytes, whether the request is now complete, and a refusal reason
// on any of §4.6's four abort conditions. Every abort frees the buffer before returning, which is
// §4.6's "frees the buffer immediately" — an unbounded reassembly buffer is the memory-exhaustion
// vector the rule exists for, and a buffer freed one stage later is a buffer an attacker gets to
// hold open by never sending the last fragment.
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
	current, found := self.inFlight[key]
	if !found {
		// a count of zero names no fragments at all, and an index past the count names a
		// fragment of a request with fewer of them than the sender just claimed
		if fragment.GetCount() == 0 || fragment.GetCount() <= fragment.GetIndex() {
			return nil, false, protocol.Reason_REASON_REJECTED
		}
		// §4.6 delivers fragments in order, so a first fragment that is not index 0 is a request
		// whose beginning is not coming
		if fragment.GetIndex() != 0 {
			return nil, false, protocol.Reason_REASON_REJECTED
		}
		// §4.6 names no reason code for the per-client cap, and §4.5's REASON_REJECTED is the
		// non-specific refusal every unnamed one falls back to. REASON_RATE_LIMITED would be a
		// claim that this build has the limiter of §4.7, and §5.1 check 4 is still absent
		if self.perClient <= self.counts[clientId] {
			return nil, false, protocol.Reason_REASON_REJECTED
		}
		current = &partial{count: fragment.GetCount(), started: self.now()}
		self.inFlight[key] = current
		self.counts[clientId]++
	}

	if fragment.GetCount() != current.count || fragment.GetIndex() != current.next {
		self.drop(key)
		return nil, false, protocol.Reason_REASON_REJECTED
	}
	if reason := withinLimits(len(current.bytes)+len(fragment.GetPart()), self.maxRequestBytes); reason != protocol.Reason_REASON_OK {
		self.drop(key)
		return nil, false, reason
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
func (self *reassembly) expire() int {
	if self.idle == 0 {
		return 0
	}
	dropped := 0
	deadline := self.now().Add(-self.idle)
	for key, current := range self.inFlight {
		if current.started.Before(deadline) {
			self.drop(key)
			dropped++
		}
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

// One reassembly's state, released: the buffer and the per-client slot it was counted against.
//
// The client_id is read off the key rather than taken as a second argument. The two must name
// the same client — the count that gates §4.6's per-client cap is the count of exactly these
// entries — and an argument that can disagree with the key is an argument that eventually does:
// a drop that decremented the wrong client would leave one client capped against buffers it does
// not hold and another holding buffers nothing counts.
func (self *reassembly) drop(key reassemblyKey) {
	if _, found := self.inFlight[key]; !found {
		return
	}
	delete(self.inFlight, key)
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
