// Package endpoint is the message server's own door: a TLS listener an app reaches like any
// internet host, carrying the same §4.2 frames the platform path carries.
//
// WHY IT EXISTS. The platform-attached path (cmd/message-server/transport.go) makes this server a
// connect client of the operator, so the operator holds every frame in the clear unless both ends
// run per-peer encryption, and it is the only party that can deliver to this server at all
// (ledger 266, 267). This endpoint is the other shape the owner asked for: the server is an
// ordinary host, and the app reaches it through a URnetwork exit provider over its own TLS
// session, or directly when the app's routing setting says so. The operator then relays nothing
// it can read, and an exit provider sees an IP address, a port and TLS records.
//
// WHAT CROSSES. One WebSocket binary message is one marshaled [protocol.Frame], exactly the unit
// connect hands `peer` today, so fragmentation (§4.6), Hello and request correlation are the
// code that already runs and nothing here re-decides them. Each accepted connection is given a
// fresh [connect.Id], which is the `source.SourceId` peer keys a connection on; it is minted
// here, it identifies one TLS session and nothing else, and it is never a client_id the
// operator knows.
//
// WHAT IT AUTHENTICATES. The server, by key: the app pins the SHA-256 of this certificate's
// SubjectPublicKeyInfo ([PinOf]), so no CA, no domain name and no operator stands between the
// app and the key it expects. It authenticates no client, which is unchanged from the platform
// path: §10.3 keeps transport identity out of messaging authorization, and write_auth/req_auth
// are what admit a request to a group.
//
// WHAT IT DOES NOT LOG. Nothing identifying: no remote address, no connection id. §11.1 forbids
// identifiers in every sink, and a server reached through an exit would otherwise be keeping a
// list of exit addresses. [Endpoint.Stats] is counters only.
//
// It imports nothing of this module: it carries frames and knows no request.
//
//urmsg:mayimport
package endpoint

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// The one path this endpoint answers. Anything else is a 404, so a scanner that finds port 443
// open learns nothing more than that an HTTPS server is there.
const DefaultPath = "/urmessage/v1"

const (
	// The largest WebSocket message read. A frame is at most a §4.6 part plus its envelope,
	// which is kilobytes; a megabyte bounds a hostile sender without coming near a real one.
	DefaultMaxMessageBytes = int64(1 << 20)
	// Concurrent connections. Past it a new connection is refused before the upgrade.
	DefaultMaxConnections = 4096
	// How often a ping goes out; a connection that answers nothing for three of these is closed.
	DefaultPingInterval = 25 * time.Second
	// The TLS and WebSocket handshakes together.
	DefaultHandshakeTimeout = 30 * time.Second
	// A send whose caller gave no bound.
	DefaultWriteTimeout = 30 * time.Second
	// How long a closed connection's id is still recognised as this endpoint's. A response to a
	// connection that has just gone must be refused here rather than handed to the platform
	// client, which would treat the id as a client_id and try to reach it.
	retiredIdRetention = 10 * time.Minute
)

var (
	ErrNoCertificate = errors.New("endpoint: no TLS certificate, and the app pins this server by its key")
	ErrClosed        = errors.New("endpoint: closed")
)

type Config struct {
	// The server's certificate and private key. Self-signed is the expected shape: the app pins
	// the key, so the issuer is never consulted.
	Certificate tls.Certificate

	// Zero values take the defaults above.
	Path             string
	MaxMessageBytes  int64
	MaxConnections   int
	PingInterval     time.Duration
	HandshakeTimeout time.Duration
}

// Counters, and only counters. See the package comment for why there is no list.
type Stats struct {
	Accepted      uint64
	Refused       uint64
	Open          uint64
	Closed        uint64
	FramesIn      uint64
	FramesOut     uint64
	FramesDropped uint64
}

type Endpoint struct {
	config    Config
	pin       []byte
	tlsConfig *tls.Config
	upgrader  websocket.Upgrader
	server    *http.Server

	ctx    context.Context
	cancel context.CancelFunc

	mutex        sync.Mutex
	conns        map[connect.Id]*conn
	retired      map[connect.Id]time.Time
	callbacks    map[uint64]connect.ReceiveFunction
	nextCallback uint64
	closed       bool

	accepted      atomic.Uint64
	refused       atomic.Uint64
	closedCount   atomic.Uint64
	framesIn      atomic.Uint64
	framesOut     atomic.Uint64
	framesDropped atomic.Uint64
}

type conn struct {
	id         connect.Id
	ws         *websocket.Conn
	writeMutex sync.Mutex
	done       chan struct{}
	closeOnce  sync.Once
}

func (self *conn) close() {
	self.closeOnce.Do(func() {
		close(self.done)
		self.ws.Close()
	})
}

// PinOf is the SHA-256 of the leaf certificate's SubjectPublicKeyInfo: what an app pins.
func PinOf(certificate tls.Certificate) ([]byte, error) {
	if len(certificate.Certificate) == 0 {
		return nil, ErrNoCertificate
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("endpoint: the certificate does not parse: %w", err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return pin[:], nil
}

func New(ctx context.Context, config Config) (*Endpoint, error) {
	pin, err := PinOf(config.Certificate)
	if err != nil {
		return nil, err
	}
	if config.Path == "" {
		config.Path = DefaultPath
	}
	if config.MaxMessageBytes <= 0 {
		config.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = DefaultMaxConnections
	}
	if config.PingInterval <= 0 {
		config.PingInterval = DefaultPingInterval
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = DefaultHandshakeTimeout
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &Endpoint{
		config: config,
		pin:    pin,
		// TLS 1.3 only, and the key exchange PINNED to X25519MLKEM768 rather than left to the
		// library's default (spec B §4.1, Revision 23): the write keys a committer delivers travel
		// inside this session, and MASTER §9.2 promises them a post-quantum hybrid transit. A client
		// that offers only a classical group is refused at the handshake. http/1.1 only, because the
		// upgrade below is an HTTP/1.1 upgrade.
		tlsConfig: &tls.Config{
			Certificates:     []tls.Certificate{config.Certificate},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
			NextProtos:       []string{"http/1.1"},
		},
		ctx:       cancelCtx,
		cancel:    cancel,
		conns:     map[connect.Id]*conn{},
		retired:   map[connect.Id]time.Time{},
		callbacks: map[uint64]connect.ReceiveFunction{},
	}
	self.upgrader = websocket.Upgrader{
		HandshakeTimeout: config.HandshakeTimeout,
		ReadBufferSize:   16 * 1024,
		WriteBufferSize:  16 * 1024,
		// no browser is a client of this endpoint, so there is no origin to defend
		CheckOrigin: func(*http.Request) bool { return true },
	}
	mux := http.NewServeMux()
	mux.HandleFunc(config.Path, self.serveWebSocket)
	self.server = &http.Server{
		Handler:           mux,
		TLSConfig:         self.tlsConfig,
		ReadHeaderTimeout: config.HandshakeTimeout,
		// http.Server logs TLS handshake failures with the remote address; that is an
		// identifier, so the log goes nowhere
		ErrorLog: newDiscardLogger(),
		BaseContext: func(net.Listener) context.Context {
			return cancelCtx
		},
	}
	return self, nil
}

// Ctx ends when the endpoint is closed.
func (self *Endpoint) Ctx() context.Context {
	return self.ctx
}

func newDiscardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

// Pin is this endpoint's [PinOf], for the operator to hand to apps.
func (self *Endpoint) Pin() []byte {
	return append([]byte(nil), self.pin...)
}

// Serve accepts TLS connections on a plain listener until [Endpoint.Close]. It returns nil when
// closed, and the listener's error otherwise.
func (self *Endpoint) Serve(listener net.Listener) error {
	err := self.server.Serve(tls.NewListener(listener, self.tlsConfig))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (self *Endpoint) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != self.config.Path {
		http.NotFound(w, r)
		return
	}
	if !websocket.IsWebSocketUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	self.mutex.Lock()
	full := self.closed || self.config.MaxConnections <= len(self.conns)
	self.mutex.Unlock()
	if full {
		self.refused.Add(1)
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	ws, err := self.upgrader.Upgrade(w, r, nil)
	if err != nil {
		self.refused.Add(1)
		return
	}
	c := &conn{
		id:   connect.NewId(),
		ws:   ws,
		done: make(chan struct{}),
	}
	self.mutex.Lock()
	if self.closed {
		self.mutex.Unlock()
		ws.Close()
		return
	}
	self.conns[c.id] = c
	self.mutex.Unlock()
	self.accepted.Add(1)

	defer func() {
		c.close()
		self.mutex.Lock()
		delete(self.conns, c.id)
		now := time.Now()
		self.retired[c.id] = now
		for id, at := range self.retired {
			if retiredIdRetention < now.Sub(at) {
				delete(self.retired, id)
			}
		}
		self.mutex.Unlock()
		self.closedCount.Add(1)
	}()

	go self.pingLoop(c)
	self.readLoop(c)
}

func (self *Endpoint) pingLoop(c *conn) {
	ticker := time.NewTicker(self.config.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-self.ctx.Done():
			c.close()
			return
		case <-ticker.C:
			// WriteControl is safe beside the one writer and the one reader
			if err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(self.config.PingInterval)); err != nil {
				c.close()
				return
			}
		}
	}
}

func (self *Endpoint) readLoop(c *conn) {
	c.ws.SetReadLimit(self.config.MaxMessageBytes)
	idle := 3 * self.config.PingInterval
	c.ws.SetReadDeadline(time.Now().Add(idle))
	c.ws.SetPongHandler(func(string) error {
		return c.ws.SetReadDeadline(time.Now().Add(idle))
	})
	source := connect.TransferPath{SourceId: c.id}
	for {
		kind, data, err := c.ws.ReadMessage()
		if err != nil {
			return
		}
		c.ws.SetReadDeadline(time.Now().Add(idle))
		if kind != websocket.BinaryMessage {
			self.framesDropped.Add(1)
			continue
		}
		frame := &protocol.Frame{}
		if err := proto.Unmarshal(data, frame); err != nil {
			self.framesDropped.Add(1)
			continue
		}
		self.framesIn.Add(1)
		for _, callback := range self.callbackList() {
			callback(source, []*protocol.Frame{frame}, connect.Peer{})
		}
	}
}

func (self *Endpoint) callbackList() []connect.ReceiveFunction {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	callbacks := make([]connect.ReceiveFunction, 0, len(self.callbacks))
	for _, callback := range self.callbacks {
		callbacks = append(callbacks, callback)
	}
	return callbacks
}

// AddReceiveCallback is one half of peer.FrameClient.
func (self *Endpoint) AddReceiveCallback(receiveCallback connect.ReceiveFunction) func() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	id := self.nextCallback
	self.nextCallback += 1
	self.callbacks[id] = receiveCallback
	return func() {
		self.mutex.Lock()
		defer self.mutex.Unlock()
		delete(self.callbacks, id)
	}
}

// SendWithTimeout is the other half, with connect's ownership rule: false means the frame was
// not taken, its bytes are still the caller's and no ack will fire; true means the frame is on
// the wire, its bytes have gone back to the pool and the ack has fired.
func (self *Endpoint) SendWithTimeout(
	frame *protocol.Frame,
	destination connect.TransferPath,
	ackCallback connect.AckFunction,
	timeout time.Duration,
	opts ...any,
) bool {
	self.mutex.Lock()
	c := self.conns[destination.DestinationId]
	self.mutex.Unlock()
	if c == nil {
		return false
	}
	data, err := proto.Marshal(frame)
	if err != nil {
		return false
	}
	if timeout < 0 {
		timeout = DefaultWriteTimeout
	}
	c.writeMutex.Lock()
	c.ws.SetWriteDeadline(time.Now().Add(timeout))
	err = c.ws.WriteMessage(websocket.BinaryMessage, data)
	c.writeMutex.Unlock()
	if err != nil {
		c.close()
		return false
	}
	self.framesOut.Add(1)
	connect.MessagePoolReturn(frame.MessageBytes)
	if ackCallback != nil {
		ackCallback(nil)
	}
	return true
}

// Owns reports whether an id was minted here, open or recently closed.
func (self *Endpoint) Owns(id connect.Id) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if _, ok := self.conns[id]; ok {
		return true
	}
	_, ok := self.retired[id]
	return ok
}

func (self *Endpoint) Stats() Stats {
	self.mutex.Lock()
	open := uint64(len(self.conns))
	self.mutex.Unlock()
	return Stats{
		Accepted:      self.accepted.Load(),
		Refused:       self.refused.Load(),
		Open:          open,
		Closed:        self.closedCount.Load(),
		FramesIn:      self.framesIn.Load(),
		FramesOut:     self.framesOut.Load(),
		FramesDropped: self.framesDropped.Load(),
	}
}

func (self *Endpoint) Close() error {
	self.mutex.Lock()
	if self.closed {
		self.mutex.Unlock()
		return nil
	}
	self.closed = true
	conns := make([]*conn, 0, len(self.conns))
	for _, c := range self.conns {
		conns = append(conns, c)
	}
	self.mutex.Unlock()
	self.cancel()
	for _, c := range conns {
		c.close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return self.server.Shutdown(ctx)
}

// ── joining it to the platform path ────────────────────────────────────────────────────────

// FrameClient is peer.FrameClient's method set, restated so this package does not import peer.
type FrameClient interface {
	Ctx() context.Context
	AddReceiveCallback(receiveCallback connect.ReceiveFunction) func()
	SendWithTimeout(
		frame *protocol.Frame,
		destination connect.TransferPath,
		ackCallback connect.AckFunction,
		timeout time.Duration,
		opts ...any,
	) bool
}

var _ FrameClient = (*Endpoint)(nil)

// Joined is the one FrameClient a peer is given when a replica takes frames from both carriers.
// Either may be nil. A send goes to the endpoint when the endpoint minted the destination, and to
// the platform client otherwise.
type Joined struct {
	endpoint *Endpoint
	platform FrameClient
}

var _ FrameClient = (*Joined)(nil)

func Join(endpoint *Endpoint, platform FrameClient) *Joined {
	return &Joined{endpoint: endpoint, platform: platform}
}

// Ctx is the endpoint's when there is one: a peer serving both carriers lives as long as the
// listener, not as long as the operator connection, which can come and go.
func (self *Joined) Ctx() context.Context {
	if self.endpoint != nil {
		return self.endpoint.Ctx()
	}
	return self.platform.Ctx()
}

func (self *Joined) AddReceiveCallback(receiveCallback connect.ReceiveFunction) func() {
	var unsubscribes []func()
	if self.endpoint != nil {
		unsubscribes = append(unsubscribes, self.endpoint.AddReceiveCallback(receiveCallback))
	}
	if self.platform != nil {
		unsubscribes = append(unsubscribes, self.platform.AddReceiveCallback(receiveCallback))
	}
	return func() {
		for _, unsubscribe := range unsubscribes {
			unsubscribe()
		}
	}
}

func (self *Joined) SendWithTimeout(
	frame *protocol.Frame,
	destination connect.TransferPath,
	ackCallback connect.AckFunction,
	timeout time.Duration,
	opts ...any,
) bool {
	if self.endpoint != nil && self.endpoint.Owns(destination.DestinationId) {
		return self.endpoint.SendWithTimeout(frame, destination, ackCallback, timeout, opts...)
	}
	if self.platform != nil {
		return self.platform.SendWithTimeout(frame, destination, ackCallback, timeout, opts...)
	}
	return false
}
