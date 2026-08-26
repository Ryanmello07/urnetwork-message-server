package peer

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/message-server/api"
)

// §4.3.1's `server_nonce` is 32 bytes, and spec A §5.7 names the width in the same sentence
// that names the guarantee. There is no ladder to read it from, so it is a constant here, and
// [Connections.Open] refuses a source that cannot fill it rather than issuing a short one.
const ServerNonceBytes = 32

var (
	ErrNoRandom   = errors.New("peer: a connection's server_nonce is 32 bytes of CSPRNG, and there is nothing here to read them from")
	ErrShortNonce = errors.New("peer: the random source answered fewer bytes than a server_nonce is wide, and a short nonce is a nonce an attacker can enumerate")
)

// What connect actually gives the message server, and why a connection here is one Hello epoch.
//
// Spec A §5.7 and spec B §5.1 check 2 both require a nonce "scoped to that connection, valid
// for the life of that connection, and never rotated", looked up "from the connection, never
// from the request". connect has no such object to hand, and this is what was looked for:
//
//   - The receive callback's whole signature is
//     `func(source TransferPath, frames []*protocol.Frame, peer Peer)` (transfer.go:152).
//     `source` is `path.SourceMask()` (transfer.go:1520), which is `{SourceId, StreamId}`, and
//     `StreamId` is always zero here because a frame whose path `IsStream()` is dropped before
//     that line (transfer.go:1512). So the whole of the arriving identity is `SourceId`: the
//     client_id, which survives a disconnect and a reconnect unchanged.
//   - `connect.Peer` is `{ProvideMode, Roles, Principal}` (transfer.go:140) — the source's
//     identity from the active contract, not from the session.
//   - A ReceiveSequence does carry a per-session `sequenceId` (transfer.go:2629), and the
//     client will not hand it to a callback: it appears only as an *argument* to
//     `ReceiveQueueSize(source, sequenceId)`, which is a caller telling connect which sequence
//     it means, not connect telling a caller which one a frame came from.
//   - `EncryptionSessionManager` has a per-peer session lifecycle and an event stream
//     (`AddEncryptionEventCallback`), but `EncryptionEvent` is `{PeerId, Type, Reason}` with no
//     session identifier and no closed event, its sessions are keyed by `(peerId, role,
//     companion)` rather than by connection, and `EncryptionModeOff` is a supported setting, so
//     a deployment may have no sessions at all.
//
// So connect distinguishes one session of a client_id from the next nowhere this server can
// read. Keying the nonce by client_id alone is therefore exactly the failure the design has to
// avoid: a reconnecting client would keep the nonce it had, and cross-connection replay
// resistance is the entire reason the nonce exists.
//
// What is left is the one in-band event that marks the start of a client's session, and §4.3.1
// already puts the nonce there: **Hello**. A connection is one Hello epoch of a client_id. Every
// Hello mints a fresh nonce and *destroys* the previous one for that client_id — no history, no
// grace window, no second nonce that still verifies — so a record sealed against the old nonce
// stops verifying the instant the new one is issued. Spec A §5.7's outbox rule is the client
// half of the same statement: "On reconnect, every queued record MUST be re-MAC'd against the
// new connection's nonce."
//
// What this cannot do is notice a reconnect the client does not announce. That gap is the
// platform's rather than this file's, it is written down here beside the code that would close
// it if connect ever grew a session identity, and the idle bound is what limits how long a
// nonce outlives a session the client ended without saying so.
//
// That bound is enforced on the request path and on the Hello path, by [Connections.expired],
// and by nothing else — there is no sweeper goroutine here to start and therefore none to
// forget to start. [Connections.Lookup] applies it to the one entry it resolves, so a nonce
// stops verifying at the bound rather than at whenever something else happened to run; and
// [Connections.Open] sweeps the whole map, so the map holds only client_ids that have said
// Hello or carried a frame inside the bound. This is [reassembly.expire]'s arrangement for the
// same reason: an expiry whose only trigger is a goroutine somebody has to remember to start
// is an expiry that a build silently ships without.
type Connections struct {
	random io.Reader
	now    func() time.Time

	// A connection with no traffic for this long is closed and its nonce destroyed. Zero
	// disables it, which is what [Peer.NotBuilt] declares: without an idle bound the live map
	// holds one entry per client_id that ever said Hello and never grows back down, and that
	// is a memory bound anyone who can address a frame gets to choose.
	//
	// Read in exactly one place, [Connections.expired]. Three methods bound themselves by it
	// and a fourth copy of `seen.Before(now.Add(-idle))` in any of them would be a build that
	// enforces the bound where somebody last edited and not where they did not.
	idle time.Duration

	mutex sync.Mutex
	live  map[connect.Id]*Connection
}

// One connection: one Hello epoch of one client_id.
//
// Immutable except for `seen`, which is the idle sweep's input. The nonce in particular is
// written once by [Connections.Open] and never again, which is §5.7's "never rotated" as a data
// shape rather than as a rule to remember — there is no method here that could rotate it.
type Connection struct {
	clientId connect.Id
	nonce    []byte

	// How many Hellos this client_id has said, this one included. It is on no wire and in no
	// preimage. It exists so that "the same client_id, a later connection" is a thing this
	// server can say — in a log line, and in a test that has to tell two connections of one
	// client apart when every byte connect handed it is identical.
	generation uint64

	mutex sync.Mutex

	// When this connection last carried a frame: the idle sweep's only input. When it was
	// opened is deliberately not kept — nothing would read it, and the sweep is about silence
	// rather than about age.
	seen time.Time
}

func NewConnections(random io.Reader, now func() time.Time, idle time.Duration) (*Connections, error) {
	if random == nil {
		return nil, ErrNoRandom
	}
	if now == nil {
		now = time.Now
	}
	return &Connections{
		random: random,
		now:    now,
		idle:   idle,
		live:   map[connect.Id]*Connection{},
	}, nil
}

// §4.3.1's nonce issuance: a fresh connection for this client_id, and the end of the previous
// one.
//
// The replacement is unconditional and the old value is kept nowhere. A grace window in which
// the previous nonce still verified would be a window in which a record sealed against the old
// connection replays onto the new one, which is the one thing the nonce is for.
func (self *Connections) Open(clientId connect.Id) (*Connection, error) {
	nonce := make([]byte, ServerNonceBytes)
	// io.ReadFull rather than Read: a source that answers short is a source that would issue a
	// nonce with a run of zeros on the end, and an error is the only honest answer to that
	if _, err := io.ReadFull(self.random, nonce); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrShortNonce, err)
	}

	self.mutex.Lock()
	defer self.mutex.Unlock()
	// before the sweep, so that a client whose previous connection has just been swept is still
	// on its second epoch rather than back on its first. The generation is on no wire and in no
	// preimage, and the one thing it is for is telling two connections of one client_id apart
	generation := uint64(1)
	if previous, found := self.live[clientId]; found {
		generation = previous.generation + 1
	}
	// every Hello sweeps, which is the whole of what bounds the live map. A Hello is the only
	// thing that can add an entry, so sweeping here means the map holds only what has been
	// heard from inside the bound plus the one being added — a bound rather than a hope that
	// something calls Sweep
	self.sweep()
	current := &Connection{
		clientId:   clientId,
		nonce:      nonce,
		generation: generation,
		seen:       self.now(),
	}
	self.live[clientId] = current
	return current, nil
}

// The connection a frame from this client_id arrived on, or nothing.
//
// This is §5.1 check 2's "the server knows its own connection's nonce and looks it up from the
// connection": the only argument is the platform-authenticated `source.SourceId`, and there is
// no overload of this that takes a request.
//
// The idle bound decides here as well as in the sweep, and this is where it becomes a bound
// rather than a setting. A connection past it resolves to nothing, so its nonce stops verifying
// at the bound itself rather than whenever the next Hello happens to sweep — the difference
// between the two is the window in which a record sealed against a session the client ended
// without saying so still verifies, and that window is the reason the bound exists.
//
// The expired entry is deleted rather than only refused: leaving it would leave the map holding
// something nothing can resolve, and would let a later frame inside a fresh bound resurrect a
// nonce that has already been declared gone.
func (self *Connections) Lookup(clientId connect.Id) (*Connection, bool) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	current, found := self.live[clientId]
	if !found {
		return nil, false
	}
	now := self.now()
	if self.expired(current, now) {
		delete(self.live, clientId)
		return nil, false
	}
	current.touch(now)
	return current, true
}

// Whether this connection is still the live one for its client_id.
//
// A request in flight across a re-Hello is a request whose connection has been replaced, and it
// must not be served: it was authenticated against a nonce that no longer exists. Pointer
// identity is the comparison, because two connections of one client_id differ in nothing else
// the platform gave us.
func (self *Connections) IsLive(current *Connection) bool {
	if current == nil {
		return false
	}
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.live[current.clientId] != current {
		return false
	}
	// and the bound again, so that "live" is one predicate rather than two that agree until an
	// idle connection is asked about through this door instead of through Lookup
	return !self.expired(current, self.now())
}

// Close every connection idle longer than the configured bound, and answer how many went.
//
// Zero disables it entirely, and [Peer.NotBuilt] says so: with no bound the live map has no
// upper limit at all, and a nonce outlives a session whose client stopped talking without
// saying so for as long as the process runs.
//
// Exported because an operator loop or a drain may want to run it early, but nothing in this
// module depends on anything calling it: [Connections.Open] runs the same pass on every Hello
// and [Connections.Lookup] applies the same bound to the entry it resolves, so the bound holds
// in a build where this method is never called at all. It used to be the other way round, and
// what that cost was that configuring the bound removed [unsweptConnections] from the list of
// what this build does not do without creating the bound it declared missing.
func (self *Connections) Sweep() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.sweep()
}

// The sweep itself, under the caller's lock, so that [Connections.Open] can run it in the same
// critical section it replaces a connection in.
func (self *Connections) sweep() int {
	if self.idle == 0 {
		return 0
	}
	now := self.now()
	closed := 0
	for clientId, current := range self.live {
		if self.expired(current, now) {
			delete(self.live, clientId)
			closed++
		}
	}
	return closed
}

// Whether this connection has been silent for longer than the idle bound.
//
// The only expression of the bound in this package. The sweep, the lookup and the liveness
// predicate all ask here, so there is no arrangement of edits in which one of them enforces a
// bound the others do not — a connection that is expired to the sweep and live to a lookup
// would be a nonce that verifies for as long as nothing sweeps.
//
// A zero bound is no bound, and answers false rather than "everything is expired": zero is what
// [Peer.NotBuilt] declares through [unsweptConnections], and a declaration of a missing bound
// has to describe a build that actually has no bound.
//
// Takes `now` rather than reading the clock, because the sweep asks about every connection in
// one pass and a clock read per entry would make the deadline drift down the map.
func (self *Connections) expired(current *Connection, now time.Time) bool {
	if self.idle == 0 {
		return false
	}
	return current.lastSeen().Before(now.Add(-self.idle))
}

func (self *Connections) Count() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return len(self.live)
}

func (self *Connection) ClientId() connect.Id {
	return self.clientId
}

// The connection's own nonce, copied.
//
// A copy because the value travels into a handler and into a MAC preimage, and the one thing
// that must not happen to a nonce valid for the life of a connection is that something down the
// call path writes through the slice. The cost is 32 bytes per request; the alternative is a
// mutable shared secret.
func (self *Connection) ServerNonce() []byte {
	return append([]byte(nil), self.nonce...)
}

func (self *Connection) Generation() uint64 {
	return self.generation
}

// Whether a nonce that reached a handler is this connection's own.
//
// Constant time not because the nonce is a secret from this client — the server handed it to
// them in HelloResponse — but because it is a secret from everybody else, and a comparison that
// short-circuits on the first differing byte has a duration that is a hint. Not offering the
// hint costs nothing.
func (self *Connection) Holds(nonce []byte) bool {
	return subtle.ConstantTimeCompare(self.nonce, nonce) == 1
}

// What the api layer is told about the connection: §5.1 check 2's two values, and nothing else.
//
// Built here rather than by the dispatcher, so that there is exactly one expression in this
// module from which a `ServerNonce` reaches a handler and it reads a field of a connection. A
// dispatcher that took the nonce from anywhere else — a request field, a cache keyed by
// something the client chose — would have to stop calling this.
func (self *Connection) ApiConnection() *api.Connection {
	return &api.Connection{
		ServerNonce: self.ServerNonce(),
		ClientId:    self.clientId.Bytes(),
	}
}

func (self *Connection) touch(now time.Time) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.seen = now
}

func (self *Connection) lastSeen() time.Time {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.seen
}
