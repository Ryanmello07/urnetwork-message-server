// The positive control for the gate in api/second_implementation_test.go.
//
// It is the second implementation §12.1 A-1 and §5.1 check 7 are written against, in the shape
// it actually arrives in: not somebody deciding to reimplement the record layer, but three
// small helpers that each look reasonable on their own — a preimage assembled inline because
// the builder took an argument that was inconvenient, a MAC taken because comparing tags here
// saved a call, and a body hash because it was one line.
//
// It lives under testdata, so the go tool never builds it and it is never linked into anything.
// The gate parses it. If the gate reports nothing here, the gate is measuring nothing, and the
// clean report it gives the real package means nothing either.
package secondimplementation

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/urnetwork/connect/mls/syntax"
)

// A preimage built here rather than by connect/message's builder: the same fields, the same
// order, agreeing with the real one today and diverging on the first edit to either.
func writeAuthPreimage(serverNonce []byte, groupId []byte, senderHandle []byte, epoch uint64, ctHead []byte) []byte {
	writer := syntax.NewWriter()
	writer.WriteRaw([]byte("URmessage/v1/write"))
	writer.WriteOpaqueLP(serverNonce)
	writer.WriteOpaqueLP(groupId)
	writer.WriteOpaqueLP(senderHandle)
	writer.WriteUint64(epoch)
	headHash := sha256.Sum256(ctHead)
	writer.WriteOpaqueLP(headHash[:])
	preimage, _ := writer.Bytes()
	return preimage
}

// A MAC taken in the server, over the preimage above.
func computeWriteAuth(writeKey []byte, preimage []byte) []byte {
	mac := hmac.New(sha256.New, writeKey)
	mac.Write(preimage)
	return mac.Sum(nil)
}

// And the comparison, in the server, in variable time for good measure.
func verifyWriteAuth(writeKey []byte, preimage []byte, tag []byte) bool {
	return hmac.Equal(computeWriteAuth(writeKey, preimage), tag)
}

// The record parsed here instead of by ParseRecord: a header read field by field out of the
// same presentation language, which is the third of the three things the gate names.
func parseRecordHeader(recordBytes []byte) (uint64, uint64, error) {
	reader := syntax.NewReader(recordBytes)
	epoch, err := reader.ReadUint64()
	if err != nil {
		return 0, 0, err
	}
	streamIndex, err := reader.ReadUint64()
	if err != nil {
		return 0, 0, err
	}
	return epoch, streamIndex, nil
}
