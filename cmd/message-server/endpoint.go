package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path/filepath"

	"github.com/urnetwork/message-server/endpoint"
	"github.com/urnetwork/message-server/peer"
)

// THE SERVER'S OWN DOOR, AS THIS PROCESS OPENS IT (ledger 268).
//
// msgrepo/endpoint is the listener; this file is the three things only the process knows: where
// the certificate is, where to listen, and how the endpoint and the operator client are joined
// in front of one peer. Nothing here logs an address: not the bind address, which §11.1's
// "any IP address" covers whoever's it is, and not a client's, which the endpoint never records.

// openEndpoint loads the certificate and binds the listener; [server.serveEndpoint] starts
// accepting once a peer exists to dispatch to.
func openEndpoint(ctx context.Context, deploy deployment, loaded configuration) (*endpoint.Endpoint, net.Listener, error) {
	resolve := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(deploy.resourceDir, path)
	}
	if loaded.endpointCertificateFile == "" || loaded.endpointPrivateKeyFile == "" {
		return nil, nil, errEndpointNoCertificate
	}
	// the error names a file or a PEM fault, never key material
	certificate, err := tls.LoadX509KeyPair(
		resolve(loaded.endpointCertificateFile),
		resolve(loaded.endpointPrivateKeyFile),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("endpoint: the TLS certificate and key did not load: %w", err)
	}
	served, err := endpoint.New(ctx, endpoint.Config{Certificate: certificate})
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("tcp", loaded.endpointListenAddress)
	if err != nil {
		served.Close()
		// net.OpError's text carries the address; its cause does not
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Err != nil {
			err = opErr.Err
		}
		return nil, nil, fmt.Errorf("endpoint: endpoint_listen_address could not be bound: %w", err)
	}
	return served, listener, nil
}

var errEndpointNoCertificate = errors.New("endpoint: endpoint_listen_address is set and endpoint_tls_certificate_file or endpoint_tls_private_key_file is not; apps pin the server by this key")

// carrier is the one peer.FrameClient behind which this process serves, or nil when it has none.
func (self *server) carrier() peer.FrameClient {
	switch {
	case self.endpoint != nil && self.attachment != nil:
		return endpoint.Join(self.endpoint, self.attachment.client)
	case self.endpoint != nil:
		return endpoint.Join(self.endpoint, nil)
	case self.attachment != nil:
		return self.attachment.client
	}
	return nil
}

func (self *server) serveEndpoint() {
	self.endpointServing.Store(true)
	err := self.endpoint.Serve(self.endpointListener)
	self.endpointServing.Store(false)
	if err != nil {
		// the listener's error text names the bind address, so only that it stopped is logged
		self.log.Error("the endpoint stopped accepting connections")
	}
}

func (self *server) closeEndpoint() {
	if self.endpoint != nil {
		self.endpoint.Close()
	}
	if self.endpointListener != nil {
		self.endpointListener.Close()
	}
}
