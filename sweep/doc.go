// The retention sweep of spec B §7.4, the blob GC of §8.3, and the orphan reaper — behind a
// Postgres advisory lock, because §2.2 costs this module github.com/urnetwork/server/task and
// N replicas each running their own sweeper is the same table twice.
//
// This package holds no code yet; §2.1 fixes the layout.
//
// May import: this module's store and metrics. It never reads a record body and it never
// learns what class a record is from anything but the single byte §7.2 sweeps on, so it needs
// neither connect/message nor a decryption capability it must not have.
//
//urmsg:mayimport store metrics
package sweep
