package peer

import (
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// §4.6's own numbers, as constants rather than as literals in the middle of a branch.
const (
	// "The sender chooses `part` size as min(peer_advertised_frame_budget, 2048) bytes." connect
	// advertises no per-peer frame budget to a caller, so 2048 is the whole of the minimum.
	DefaultFragmentPartBytes = 2048

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
		self.drop(key, clientId)
		return nil, false, protocol.Reason_REASON_REJECTED
	}
	if reason := withinLimits(len(current.bytes)+len(fragment.GetPart()), self.maxRequestBytes); reason != protocol.Reason_REASON_OK {
		self.drop(key, clientId)
		return nil, false, reason
	}

	current.bytes = append(current.bytes, fragment.GetPart()...)
	current.next++
	if current.next < current.count {
		return nil, false, protocol.Reason_REASON_OK
	}
	assembled := current.bytes
	self.drop(key, clientId)
	return assembled, true, protocol.Reason_REASON_OK
}

// Everything past §4.6's 30 seconds, dropped. Called under the lock on every accept, which is
// what makes the expiry real without a goroutine: a client that opens fifteen reassemblies and
// walks away has them collected by the sixteenth attempt rather than holding the cap forever.
func (self *reassembly) expire() {
	if self.idle == 0 {
		return
	}
	deadline := self.now().Add(-self.idle)
	for key, current := range self.inFlight {
		if current.started.Before(deadline) {
			self.drop(key, key.clientId)
		}
	}
}

func (self *reassembly) drop(key reassemblyKey, clientId connect.Id) {
	if _, found := self.inFlight[key]; !found {
		return
	}
	delete(self.inFlight, key)
	if self.counts[clientId] <= 1 {
		delete(self.counts, clientId)
		return
	}
	self.counts[clientId]--
}

func (self *reassembly) inFlightCount() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return len(self.inFlight)
}

// The frames one response travels in: one response frame, or §4.6's fragments of it.
//
// `Frame.raw` is false on every one of them, which §4.2 states for the whole of this binding —
// a raw frame carries bytes that are not a protobuf, and every frame here is one.
func responseFrames(response *protocol.MessageServerResponse, partBytes int) ([]*protocol.Frame, error) {
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
