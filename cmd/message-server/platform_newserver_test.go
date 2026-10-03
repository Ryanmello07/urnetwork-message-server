package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A self-signed endpoint certificate and key in a fresh resource directory, for the tests that
// drive newServer itself with an endpoint configured.
func endpointResources(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "k.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// "OFF ATTACHES NOTHING", HELD AT newServer ITSELF and not only at the helper it calls: the diff
// review of spec B Revision 23 put back the pre-revision call site (`if canAttach(...)`), left the
// helper alone, and every test passed. This one drives newServer with every input an attachment
// needs present, in both modes. It needs no database: pgxpool connects lazily, so a parseable DSN
// to a closed port opens nothing. Written by that review, kept as it was.
func TestOffConstructsNoAttachmentAtNewServerItself(t *testing.T) {
	dir := endpointResources(t)
	loaded := defaultConfiguration()
	loaded.operatorHost = "invalid" // a bare host: canAttach is true, and nothing real is dialled
	loaded.hostingJurisdiction = "US"
	loaded.endpointListenAddress = "127.0.0.1:0"
	loaded.endpointCertificateFile = "c.pem"
	loaded.endpointPrivateKeyFile = "k.pem"
	deploy := deployment{resourceDir: dir, ordinal: "0", dsn: "postgres://u:p@127.0.0.1:1/none?connect_timeout=1",
		byJwt: "a.credential.that.is.never.parsed.here", serverId: make([]byte, serverIdBytes)}
	if !canAttach(deploy, loaded) {
		t.Fatal("control: canAttach refused; the case below would prove nothing")
	}

	for _, mode := range []string{"on", "off"} {
		loaded.platformAttachment = mode
		current, err := newServer(t.Context(), deploy, loaded, discardLog())
		if err != nil {
			t.Fatalf("%s: newServer: %v", mode, err)
		}
		attached := current.attachment != nil
		names := current.ready.names()
		current.Close()
		t.Logf("%s: attachment constructed=%v endpoint=%v readiness=%v", mode, attached, current.endpoint != nil, names)
		if mode == "on" && !attached {
			t.Fatal("control: on, with every input present, constructed no attachment")
		}
		if mode == "off" && attached {
			t.Fatal("off constructed an attachment because a credential is on the box")
		}
		if mode == "off" && (slices.Contains(names, "connect_client_attached") || !slices.Contains(names, "endpoint_listening")) {
			t.Fatalf("off readiness set is %v", names)
		}
	}
}

// The endpoint's bind failure never prints the address it was given (§11.1: no IP address in any
// log line). A *net.AddrError's text IS the address, so unwrapping net.OpError is not enough.
func TestTheEndpointsBindFailureNamesNoAddress(t *testing.T) {
	dir := endpointResources(t)
	for _, address := range []string{"203.0.113.5", "203.0.113.5:99999"} {
		loaded := defaultConfiguration()
		loaded.endpointListenAddress = address
		loaded.endpointCertificateFile = "c.pem"
		loaded.endpointPrivateKeyFile = "k.pem"
		_, _, err := openEndpoint(t.Context(), deployment{resourceDir: dir}, loaded)
		if err == nil {
			t.Fatalf("%q bound", address)
		}
		if strings.Contains(err.Error(), "203.0.113.5") || strings.Contains(err.Error(), "99999") {
			t.Fatalf("the bind failure for an endpoint address printed it: %v", err)
		}
		if !errors.Is(err, errEndpointBindNamesAddress) {
			t.Logf("%q failed without naming the address, by another road: %v", address, err)
		}
	}
}
