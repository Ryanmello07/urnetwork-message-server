// The HTTP bulk plane of spec B §8: upload, download, and the grant verification of §8.2
// that stands in front of both. Blob bytes never cross the connect session, and they never
// cross Redis.
//
// This package holds no code yet; §2.1 fixes the layout.
//
// May import: minio/minio-go/v7 for the object store, net/http for the bulk plane it serves,
// this module's store, redact and metrics. It is the one package in this module that is
// expected to bind a listener, and §10.1 puts it on a private port beside /healthz, /readyz
// and /metrics, never on the public interface.
//
//urmsg:mayimport store redact metrics
package blobd
