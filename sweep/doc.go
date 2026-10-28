// The retention sweep of spec B §7.4, the blob GC of §8.3, and the orphan reaper — behind a
// Postgres advisory lock, because §2.2 costs this module github.com/urnetwork/server/task and
// N replicas each running their own sweeper is the same table twice.
//
// What it holds is the part of §7.4's five-minute loop that the identity plan's Task 20 built:
// the reclaim of §4.3.11's link boxes (sweep.go). The record sweep, the blob GC and the orphan
// reaper are not built; §2.1 fixes the layout they take.
//
// May import: this module's store and metrics. It never reads a record body and it never
// learns what class a record is from anything but the single byte §7.2 sweeps on, so it needs
// neither the record layer nor a decryption capability it must not have.
//
//urmsg:mayimport store metrics
package sweep
