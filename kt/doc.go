// The key-transparency gossip client of spec B §9.4 and §9.5: read-only, against the
// operator's STH and proof endpoints, in a different repository under a different deploy
// cadence.
//
// This package holds no code yet; §2.1 fixes the layout.
//
// May import: net/http for the operator's endpoints and this module's metrics. It reads the
// operator over its public API and never over its database — §10.3's cross-repo release order
// puts the operator schema ahead of this client, and this client MUST tolerate the schema's
// absence by disabling itself rather than by failing /readyz, or the wrong deploy order pages
// on a metric indistinguishable from "not deployed yet".
package kt
