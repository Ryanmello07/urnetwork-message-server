package api

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message-server/store"
)

// §5.1 check 3's `0x0005` arm: the two doors an attachment can come through, the alignment rule
// §4.3.3 gives the delivery beside it, and the digest comparison that binds the two together.
//
// ── WHY THERE ARE TWO DOORS AND NOT A WIDER ONE ────────────────────────────────────────────
//
// `message.ParseServerAttachment` serves the five kinds Spec A §5.11 defines and refuses kind
// `0x0005` BY NAME with `ErrServerAttachmentKindNotServed`. That refusal is not an obstacle to
// route around; it is the interlock ruling 27 bought. A server built from a `connect/message`
// that has not been widened cannot be talked into installing an epoch whose keys it was never
// handed, whatever a client sends it. `message.ParseEpochDigestAttachment` is the sixth kind's
// own door, and this server opens it DELIBERATELY, once, here — which is what makes "this build
// accepts `0x0005`" one decision in one place rather than a flag whose effect is spread over a
// parse, a gate and an install.
//
// Both doors run the same codec, the same body table and the same well-formedness check inside
// `connect/message`, so nothing here re-derives a field width, an `alg_id` or
// `expected_wrap_count > 0` — Spec B §12.1 A-2.
//
// ── WHAT THIS FILE DOES NOT DO ─────────────────────────────────────────────────────────────
//
// It does not compute `H(epoch_keys)`. `message.CheckEpochKeysDigest` does, and A-1 is the
// reason: two independent implementations of a preimage diverge, and when they do the symptom
// is "some clients cannot commit", intermittently, with a byte-order difference nobody can see
// behind it. It also does not choose which epoch goes into that preimage — the checker reads it
// out of the attachment's own body and refuses to take one as a parameter, because THREE epochs
// are live at this call site (the record header's, the attachment's, and this server's own
// `current_epoch + 1`) and a wrong choice among them type checks.

// The named refusals of the alignment rule Spec B §4.3.3 and §4.3.2 give `epoch_keys`.
//
// They are ERRORS AND NOT `protocol.Reason`s, and the distinction is the whole reason this file
// has sentinels at all. §4.5 merges every client-caused refusal into `REASON_REJECTED`, so the
// wire cannot tell these five apart and MUST NOT — a client that could distinguish "your keys
// are missing" from "your keys do not match the digest" holds an oracle over a value the MAC
// covers. What needs to tell them apart is this server's own tests and its operator log: a gate
// whose four clauses all answer one opaque code is a gate three of whose clauses can be deleted
// with every test still green, which is exactly the shape ledger item 249 records being defeated
// three times in `connect`.
var (
	// §4.3.3: "EMPTY, OR EXACTLY AS LONG AS `records`". The refusal exists so that a short list
	// is refused rather than indexed: a delivery list one shorter than `records` silently
	// re-aims every later entry at the wrong record, and what it re-aims is a key.
	ErrEpochKeysLength = errors.New("api: epoch_keys is neither empty nor exactly as long as records")

	// §4.3.3: an entry sitting opposite a record with `is_commit = 0`. Decided on a value check
	// 3 has already verified against `ParseRecord(record_bytes)`.
	ErrEpochKeysOnNonCommit = errors.New("api: an epoch key delivery sits opposite a record with is_commit = 0")

	// §4.3.3 and §4.3.2: a kind `0x0005` commit with no delivery. It is an epoch this server
	// would install without having been handed what opens it.
	ErrEpochKeysMissing = errors.New("api: a kind 0x0005 commit arrived with no epoch key delivery")

	// §5.4's acceptance window, read the other way: a kind `0x0001` commit WITH a delivery. Its
	// keys are in the attachment, so a delivery beside it is a field this server would not read
	// and that can disagree with the one the write_auth MAC covers.
	ErrEpochKeysUnwanted = errors.New("api: a kind 0x0001 commit arrived with an epoch key delivery beside it")

	// A delivery whose keys are not exactly 32 octets each. It is refused HERE rather than left
	// to `message.EpochKeysDigest`'s own width check so that a client bug and a digest mismatch
	// are different lines in an operator's log; the checker refuses it too, and that is the
	// belt this braces.
	ErrEpochKeyWidth = errors.New("api: an epoch key delivery carries a key that is not exactly 32 octets")

	// A present-but-zero delivery, which proto3 cannot tell from an absent one on a repeated
	// entry. It is two EMPTY KEYS and never an absence, and it is named separately from
	// [ErrEpochKeyWidth] because the two say different things about the client that sent it.
	ErrEpochKeysEmptyEntry = errors.New("api: an epoch key delivery carries two empty keys, which is not an absence")
)

// The one attachment parse this package makes, over both of §5.11's doors.
//
// It answers a `message.ServerAttachment` in both cases so that everything downstream — the
// `iff is_commit` clause, `projectionOf`, `attachmentOf` — keeps asking one value what kind it
// is. The digest door hands back a bare body, so the discriminator is put back on here and in
// exactly one place; a caller that had to remember to do it is a caller that can forget.
//
// THE FALL-THROUGH IS ON THE SENTINEL AND NEVER ON "the first door said no". `ParseServerAttachment`
// refuses a malformed attachment, an undefined kind and an encoded `0x0000` with three other
// sentinels, and a fall-through on any error would hand those octets to the second door and
// report whatever it said about them. Only `ErrServerAttachmentKindNotServed` means "these ARE
// an attachment, of a kind this door does not serve".
func parseServerAttachment(bs []byte) (*message.ServerAttachment, error) {
	attachment, err := message.ParseServerAttachment(bs)
	if err == nil {
		return attachment, nil
	}
	if !errors.Is(err, message.ErrServerAttachmentKindNotServed) {
		return nil, err
	}
	digest, digestErr := message.ParseEpochDigestAttachment(bs)
	if digestErr != nil {
		// the kind is one §5.11's door does not serve and is not the digest kind either, which
		// is a seventh kind this build has not been taught. The FIRST door's refusal is
		// returned, because that is the one that names the door the record was submitted to
		return nil, err
	}
	return &message.ServerAttachment{Kind: message.AttachmentEpochDigest, EpochDigest: digest}, nil
}

// Whether an attachment kind is an EPOCH attachment for §5.1 check 3's `iff is_commit`.
//
// IT IS A DISJUNCTION AND IT HAS TO BE. `(kind == message.AttachmentEpoch) != is_commit` looks
// like an iff and stops being one the moment a second epoch kind exists: a kind `0x0005`
// attachment on a NON-commit record gives `false != false`, which PASSES — so the clause that
// exists to keep an epoch attachment off an ordinary record admits the newer of the two epoch
// attachments on every ordinary record. `connect/message`'s own file comment names this server's
// three copies of the clause as the defect; this is the api layer's, and `store.isEpochAttachmentKind`
// is the other two.
func isEpochAttachmentKind(kind message.ServerAttachmentKind) bool {
	switch kind {
	case message.AttachmentEpoch, message.AttachmentEpochDigest:
		return true
	default:
		return false
	}
}

// The epoch an attachment OPENS, from whichever of the two epoch kinds carries it, and whether
// it is an epoch attachment at all.
//
// One call rather than a kind test followed by a field read, because the two have to agree: a
// caller that tested the kind and then reached for `.Epoch.Epoch` would panic on the other kind,
// and one that tested for nil instead would read a zero as an epoch. The `ok` is false for every
// kind that is not an epoch attachment and for a tag whose body is missing.
func opensEpochOf(attachment *message.ServerAttachment) (uint64, bool) {
	if attachment == nil {
		return 0, false
	}
	switch attachment.Kind {
	case message.AttachmentEpoch:
		if attachment.Epoch == nil {
			return 0, false
		}
		return attachment.Epoch.Epoch, true
	case message.AttachmentEpochDigest:
		if attachment.EpochDigest == nil {
			return 0, false
		}
		return attachment.EpochDigest.Epoch, true
	default:
		return 0, false
	}
}

// §4.3.3's alignment rule over one submission, answering the ONE delivery §4.3.3 admits.
//
// It returns the delivery the batch's single commit needs — or nil, when the batch has no commit
// or its commit is kind `0x0001` — together with the index a refusal belongs to, or a named
// error. The index is [wholeSubmission] for the length clause, because a list of the wrong
// length is the submission's fault and not the third record's.
//
// WHAT IT ADMITS, ENUMERATED, because it admits exactly two lengths and not a general batch.
// §4.3.3 makes a batch containing a commit exactly one record, so `epoch_keys` is EMPTY when
// `records` carries no commit or carries one `0x0001` commit, and holds EXACTLY ONE ENTRY when
// `records` is a single `0x0005` commit. There is no third length. For a mixed batch the field
// is not under-specified, it is UNSATISFIABLE — which is stated in Spec B §4.3.3 rather than
// discovered here.
//
// THE INDEXING IS THE POINT. Every read of `deliveries` below is guarded by the length clause
// having already run, so this function answers a named refusal where a naive `deliveries[index]`
// answers a panic — and a panic in the submit pipeline is a 500 to a party holding no key, for
// a request it shaped.
func epochKeyAlignment(records []*recordPass, deliveries []*protocol.EpochKeyDelivery) (*protocol.EpochKeyDelivery, int, error) {
	// (1) the length clause, first, because every clause after it indexes.
	if len(deliveries) != 0 && len(deliveries) != len(records) {
		return nil, wholeSubmission, fmt.Errorf("%w: %d entries against %d records",
			ErrEpochKeysLength, len(deliveries), len(records))
	}

	var wanted *protocol.EpochKeyDelivery
	wantedIndex := wholeSubmission
	for index, record := range records {
		var delivery *protocol.EpochKeyDelivery
		if index < len(deliveries) {
			delivery = deliveries[index]
		}
		isCommit := record.parsed.Header.IsCommit
		digestKind := record.attachment != nil && record.attachment.Kind == message.AttachmentEpochDigest

		// (2) an entry opposite a non-commit. Checked before the commit arms so that a batch of
		// ordinary records carrying a full-length delivery list is refused for what it is.
		if delivery != nil && !isCommit {
			return nil, index, ErrEpochKeysOnNonCommit
		}
		if !isCommit {
			continue
		}
		// (3) the two kind-keyed arms of §5.4's acceptance window.
		if digestKind && delivery == nil {
			return nil, index, ErrEpochKeysMissing
		}
		if !digestKind && delivery != nil {
			return nil, index, ErrEpochKeysUnwanted
		}
		if delivery == nil {
			continue
		}
		// (4) the widths, and the zero entry a repeated proto3 field cannot spell an absence
		// with. Empty-and-empty is reported as its own thing: "your client sent two empty keys"
		// and "your client sent a 31-octet key" are different bugs.
		if len(delivery.GetWriteKey()) == 0 && len(delivery.GetReadKey()) == 0 {
			return nil, index, ErrEpochKeysEmptyEntry
		}
		if len(delivery.GetWriteKey()) != store.EpochKeyBytes || len(delivery.GetReadKey()) != store.EpochKeyBytes {
			return nil, index, fmt.Errorf("%w: write_key %d, read_key %d",
				ErrEpochKeyWidth, len(delivery.GetWriteKey()), len(delivery.GetReadKey()))
		}
		wanted, wantedIndex = delivery, index
	}
	return wanted, wantedIndex, nil
}

// §5.1 check 3's digest clause: are these the two keys this attachment's digest is over?
//
// It is `message.CheckEpochKeysDigest` and a group id, and it is deliberately nothing else. The
// epoch is the attachment's own — the checker refuses to take one — and the comparison is
// constant time inside it. What this function adds is the ONE thing `connect/message` cannot
// have: the `group_id` the request named and this server verified the record's header against
// three clauses earlier in check 3 (`staticShape` refuses a record whose header names another
// group), at the `[32]byte` width the preimage frames.
//
// I6 IS SATISFIED BY EQUALITY WITH THE ACCEPTANCE PATH AND NOT BY A NEW AUTHENTICATOR.
// `LP(H(server_attachment))` is already inside the `write_auth` preimage check 7 verifies, so
// the MAC covers the attachment, the attachment covers the digest, and the digest covers the
// keys. Altering either key fails this comparison; altering the digest fails check 7.
func checkEpochKeysDigest(groupId []byte, attachment *message.ServerAttachment, delivery *protocol.EpochKeyDelivery) error {
	if len(groupId) != store.GroupIdBytes {
		// unreachable from Submit and CreateGroup, both of which refuse a group id of another
		// width before anything reads it. It is here because the conversion below is a
		// fixed-width copy and a short group id would be silently zero-padded into a different
		// group's preimage
		return store.ErrIdentifierShape
	}
	if attachment == nil || attachment.EpochDigest == nil {
		return fmt.Errorf("%w: no epoch digest attachment to compare against", ErrEpochKeysMissing)
	}
	if delivery == nil {
		return ErrEpochKeysMissing
	}
	group := [store.GroupIdBytes]byte(groupId)
	return message.CheckEpochKeysDigest(group, attachment.EpochDigest, delivery.GetWriteKey(), delivery.GetReadKey())
}

// The delivery this layer hands the store, which is the wire type crossing one package boundary
// and nothing more.
//
// It is a conversion and not a copy of a rule: the store's own [store.EpochKeyDelivery] is
// singular because §4.3.3 admits one, and the reduction from the aligned list to that one value
// happened in [epochKeyAlignment] above, under this layer's named refusals. A store handed this
// cannot be handed a misaligned one.
func deliveryOf(delivery *protocol.EpochKeyDelivery) *store.EpochKeyDelivery {
	if delivery == nil {
		return nil
	}
	return &store.EpochKeyDelivery{
		WriteKey: bytes.Clone(delivery.GetWriteKey()),
		ReadKey:  bytes.Clone(delivery.GetReadKey()),
	}
}
