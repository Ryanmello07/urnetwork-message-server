// The Prometheus collectors of spec B §11.3. Aggregate only: counters and histograms with no
// identifier labels, which is what §11.1 permits and the whole of it.
//
// This package holds no code yet; §2.1 fixes the layout.
//
// May import: prometheus/client_golang, and the standard library. Never this module's redact:
// the point of a label type that cannot be printed is lost the moment a collector can accept
// one, and a metric label is a sink §11.1 names explicitly alongside logs and traces.
package metrics
