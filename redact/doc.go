// The unprintable identifier types of decision B11: GroupId, SenderHandle, BlobId,
// RecoveryHandle, ClientId, RendezvousId and DepositId, each an opaque struct over an
// unexported []byte whose String, Format, LogValue, MarshalJSON and MarshalText all answer
// `<redacted>`, and whose bytes are reachable only through an explicit Unwrap.
//
// This package holds no code yet; §2.1 fixes the layout.
//
// May import: the standard library, and nothing else. Every other package in this module
// imports it, so an import here is an import everywhere, and the structural half of §11.1 —
// that an accidental %v cannot leak because there is nothing to print — is only as strong as
// this package's own import list.
//
//urmsg:mayimport
package redact
