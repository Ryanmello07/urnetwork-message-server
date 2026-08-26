package blobd

import "crypto/sha256"

// ContentHash is §8.3's `content_hash`: SHA-256 over a body's ciphertext, taken whole.
//
// It is one function because §5.1 check 8 is one comparison asked in two places. For an inline
// body the api layer takes this hash of `ct_body` and compares it with the record's
// authenticated `body_hash`; for a blob-backed body §8.3 step 4 takes the same hash over the
// assembled object as it streams and §8.3's bind check compares it with the same `body_hash`.
// Two implementations of that hash would agree until one of them was changed, and the symptom
// would be a record whose body every recipient refuses on one path and accepts on the other.
//
// It is here rather than in api for a second reason, and it is the one that decides the
// placement. The api package may not compute a MAC, build a preimage, or parse a record — §5.1
// check 7 and §12.1 A-2 both say the server never reimplements what connect/message already
// computes — and api/second_implementation_test.go holds that as a gate with no exemption in
// it: not one call into a MAC, a hash or the presentation-language codec, anywhere in the
// package. A carve-out for "the one legitimate hash" would be a name on a list, which is the
// shape of gate this project has been walked past twelve times. So the legitimate hash lives
// in the package §8.3 gives it and api asks for it.
func ContentHash(body []byte) [32]byte {
	return sha256.Sum256(body)
}
