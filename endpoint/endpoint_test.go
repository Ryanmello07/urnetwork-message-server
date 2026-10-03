package endpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// THE JOIN'S ONE RULE, MEASURED: a response goes back the way its request came, and a response to
// an endpoint connection that has CLOSED is refused here rather than handed to the operator
// client, which would read the id as a client_id and go looking for it.

type recordingPlatform struct {
	mutex sync.Mutex
	sent  []connect.Id
	ctx   context.Context
}

func (self *recordingPlatform) Ctx() context.Context { return self.ctx }

func (self *recordingPlatform) AddReceiveCallback(connect.ReceiveFunction) func() { return func() {} }

func (self *recordingPlatform) SendWithTimeout(frame *protocol.Frame, destination connect.TransferPath,
	ack connect.AckFunction, timeout time.Duration, opts ...any) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.sent = append(self.sent, destination.DestinationId)
	return true
}

func (self *recordingPlatform) sends() []connect.Id {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]connect.Id(nil), self.sent...)
}

func TestAResponseGoesBackTheWayItsRequestCameAndNeverToTheOperatorOnceItsConnectionCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served, err := New(ctx, Config{Certificate: testCertificate(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer served.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go served.Serve(listener)

	platform := &recordingPlatform{ctx: ctx}
	joined := Join(served, platform)
	sources := make(chan connect.Id, 4)
	joined.AddReceiveCallback(func(source connect.TransferPath, frames []*protocol.Frame, _ connect.Peer) {
		sources <- source.SourceId
	})

	// one app: a frame up, so the endpoint mints its connection id
	dialer := &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}}
	ws, _, err := dialer.Dial("wss://"+listener.Addr().String()+DefaultPath, nil)
	if err != nil {
		t.Fatalf("dialling the endpoint: %v", err)
	}
	up, _ := proto.Marshal(&protocol.Frame{MessageType: protocol.MessageType_MessageMessageServerRequest, MessageBytes: []byte("request")})
	if err := ws.WriteMessage(websocket.BinaryMessage, up); err != nil {
		t.Fatalf("writing a frame: %v", err)
	}
	var source connect.Id
	select {
	case source = <-sources:
	case <-time.After(5 * time.Second):
		t.Fatal("the endpoint delivered no frame to the joined callback")
	}
	if !served.Owns(source) {
		t.Fatal("the endpoint does not own the id it minted for a connection it holds")
	}

	// the response goes down the same connection, and the operator client is not asked
	down := &protocol.Frame{MessageType: protocol.MessageType_MessageMessageServerResponse, MessageBytes: []byte("response")}
	if !joined.SendWithTimeout(down, connect.DestinationId(source), nil, time.Second) {
		t.Fatal("a response to an open endpoint connection was refused")
	}
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	got := &protocol.Frame{}
	if err := proto.Unmarshal(data, got); err != nil || string(got.GetMessageBytes()) != "response" {
		t.Fatalf("the app read %q, %v", got.GetMessageBytes(), err)
	}

	// the connection closes; a late response to it is REFUSED, and still not the operator's
	ws.Close()
	deadline := time.Now().Add(5 * time.Second)
	for served.Stats().Closed == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the endpoint never noticed the connection close")
		}
		time.Sleep(10 * time.Millisecond)
	}
	late := &protocol.Frame{MessageType: protocol.MessageType_MessageMessageServerResponse, MessageBytes: []byte("late")}
	if joined.SendWithTimeout(late, connect.DestinationId(source), nil, time.Second) {
		t.Fatal("a response to a closed endpoint connection was reported sent")
	}
	if !served.Owns(source) {
		t.Fatal("a just-closed connection's id is no longer recognised, so its responses would go to the operator")
	}

	// the control: an id the endpoint never minted IS the operator's
	stranger := connect.NewId()
	if !joined.SendWithTimeout(late, connect.DestinationId(stranger), nil, time.Second) {
		t.Fatal("a send to an operator client_id was refused")
	}
	sends := platform.sends()
	if len(sends) != 1 || sends[0] != stranger {
		t.Fatalf("the operator client was asked to send to %v; only the stranger %s should reach it", sends, stranger)
	}
}

func TestAPinIsTheHashOfTheKeyAndNotOfTheCertificate(t *testing.T) {
	certificate := testCertificate(t)
	pin, err := PinOf(certificate)
	if err != nil || len(pin) != 32 {
		t.Fatalf("PinOf: %x, %v", pin, err)
	}
	// re-sign the SAME key into a second certificate: a new serial, a new validity, the same pin
	leaf, _ := x509.ParseCertificate(certificate.Certificate[0])
	key := certificate.PrivateKey.(*ecdsa.PrivateKey)
	template := *leaf
	template.SerialNumber = big.NewInt(2)
	template.NotAfter = time.Now().Add(48 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("re-signing: %v", err)
	}
	again, err := PinOf(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	if err != nil || string(again) != string(pin) {
		t.Fatalf("a renewed certificate over the same key pins %x and the original %x", again, pin)
	}
	if _, err := PinOf(tls.Certificate{}); err == nil {
		t.Fatal("PinOf answered a pin for no certificate")
	}
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "urmessage-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// THE KEY EXCHANGE IS PINNED, not left to the library's default (spec B §4.1, Revision 23): a
// default Go client negotiates X25519MLKEM768, and a client offering only classical X25519 is
// refused at the handshake. The second half is the one a default would not show.
func TestTheEndpointTakesOnlyTheHybridKeyExchange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served, err := New(ctx, Config{Certificate: testCertificate(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer served.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go served.Serve(listener)

	dial := func(curves []tls.CurveID) (*tls.Conn, error) {
		return tls.Dial("tcp", listener.Addr().String(), &tls.Config{
			// the identity is not what this test is about; the pin test above holds it
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   curves,
			NextProtos:         []string{"http/1.1"},
		})
	}
	hybrid, err := dial(nil)
	if err != nil {
		t.Fatalf("a default client could not complete a handshake: %v", err)
	}
	state := hybrid.ConnectionState()
	hybrid.Close()
	if state.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("a default client negotiated %v; the endpoint must negotiate X25519MLKEM768", state.CurveID)
	}
	if classical, err := dial([]tls.CurveID{tls.X25519}); err == nil {
		classical.Close()
		t.Fatal("a client offering only X25519 completed a handshake: the hybrid key exchange is a default here, not a pin")
	}
}
