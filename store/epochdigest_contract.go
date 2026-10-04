package store

import (
	"context"
	"slices"
	"testing"

	"github.com/urnetwork/connect/protocol"
)

// Ruling 27's sixth attachment kind, at the STORE boundary: the epoch a `0x0005` commit opens is
// installed from the REQUEST's delivery, the `0x0001` path is untouched, and neither key ever
// reaches a column of `message_record`.
//
// WHAT THIS FILE DOES NOT TEST, and it is the larger half. It does not check the digest. Spec B
// §5.1 check 3 makes that comparison in the api layer through `message.CheckEpochKeysDigest`,
// which is the layer that holds the request the keys arrived on and the `group_id` it verified,
// and this package is forbidden an opinion about that preimage (§12.1 A-1, A-2). It does not
// check the alignment of §4.3.3's repeated `epoch_keys` against `records` either: the api layer
// reduces that list to the one delivery §4.3.3 admits, under named refusals, before this
// package is handed anything — which is why [SubmitRequest.EpochKeys] is singular and why
// misalignment is not representable here rather than re-checked here.
//
// What IS this package's is the half the api layer cannot do: where the two keys come from when
// the epoch is opened, and what is left behind in the row.
func contractEpochDigest(t *testing.T, newStore func(Limits) Store, seen *recorder) {
	t.Parallel()
	ctx := context.Background()

	// ── THE PROPERTY, and its inline control ───────────────────────────────────────────────
	//
	// A `0x0005` commit opens its epoch with the REQUEST's two keys. The control in the same
	// subtest is the `0x0001` commit of the same seed, which opens its epoch with its
	// ATTACHMENT's two keys — and the two pairs are different bytes by construction
	// ([digestKeys] is seed+4/seed+5 and [commitRecord] is seed/seed+1), so an implementation
	// that took the wrong source is a mismatch and never an equality that happened to hold.
	t.Run("AKind0x0005CommitOpensItsEpochWithTheRequestsKeysAndNotTheRecords", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))

		keys := digestKeys(0x41)
		commit := digestCommitRecord(testHandle(0x31), 1, 0, 2, 0x41)
		accepted := submitWithKeys(t, store, seen, group, keys, commit)
		wantReason(t, accepted[0], protocol.Reason_REASON_OK)

		opened, err := store.EpochKeys(ctx, group, 2)
		if err != nil {
			t.Fatalf("no keys installed for the epoch a kind 0x0005 commit opened: %v", err)
		}
		if !slices.Equal(opened.WriteKey, keys.WriteKey) {
			t.Errorf("epoch 2 holds write key %x and the REQUEST delivered %x; under ruling 27 the attachment carries no key at all, so a store that reached for the record installed a nil and this group can never be written to again",
				opened.WriteKey, keys.WriteKey)
		}
		if !slices.Equal(opened.ReadKey, keys.ReadKey) {
			t.Errorf("epoch 2 holds read key %x and the REQUEST delivered %x", opened.ReadKey, keys.ReadKey)
		}
		// the two keys are not the same key: §5.3 makes them two keys with two lifetimes, and
		// a store that installed the write key twice passes every assertion above that is not
		// this one
		if slices.Equal(opened.WriteKey, opened.ReadKey) {
			t.Errorf("epoch 2 holds one key in both columns (%x); the delivery carried two", opened.WriteKey)
		}

		// THE CONTROL, in the same subtest: the same scenario under kind 0x0001, whose keys
		// come from the attachment. Without it, a store that installed nothing at all and a
		// store that installed the right thing are told apart only by the equality above —
		// and an EpochKeys that errored would have failed the fatal, not the equality
		controlStore, controlGroup := openGroup(t, newStore(DefaultLimits()))
		control := commitRecord(testHandle(0x31), 1, 0, 2, 0x41)
		controlAccepted := submit(t, controlStore, seen, controlGroup, control)
		wantReason(t, controlAccepted[0], protocol.Reason_REASON_OK)
		controlOpened, err := controlStore.EpochKeys(ctx, controlGroup, 2)
		if err != nil {
			t.Fatalf("the kind 0x0001 control installed no keys: %v", err)
		}
		if !slices.Equal(controlOpened.WriteKey, control.Attachment.Epoch.WriteKey) {
			t.Errorf("the kind 0x0001 control holds write key %x and its attachment carried %x; the control is what says this scenario can tell an installed key from an absent one",
				controlOpened.WriteKey, control.Attachment.Epoch.WriteKey)
		}
		// and the two arms really are distinguishable: the control's installed key is NOT the
		// delivery's, so "the request's keys" and "the record's keys" are two answers here
		if slices.Equal(controlOpened.WriteKey, keys.WriteKey) {
			t.Fatal("the kind 0x0001 attachment's write key and the kind 0x0005 delivery's are the same bytes, so this whole scenario cannot tell the two sources apart")
		}
	})

	// The epoch's POLICY still comes from the attachment under both kinds. Ruling 27 took two
	// fields out of the attachment and nothing else, and a store that read the policy from the
	// wrong place under the new kind would set a group's retention from a zero value.
	t.Run("EverythingButTheKeysStillComesFromTheAttachment", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))

		commit := digestCommitRecord(testHandle(0x31), 1, 0, 2, 0x41)
		digest := commit.Attachment.EpochDigest
		wantReason(t, submitWithKeys(t, store, seen, group, digestKeys(0x41), commit)[0], protocol.Reason_REASON_OK)

		opened, err := store.EpochKeys(ctx, group, 2)
		if err != nil {
			t.Fatalf("EpochKeys: %v", err)
		}
		if opened.AlgId != digest.AlgId {
			t.Errorf("epoch 2 holds alg_id %d and the digest attachment carried %d", opened.AlgId, digest.AlgId)
		}
		state := stateOf(t, store, group)
		if !slices.Equal(state.GroupContextHash, digest.GroupContextHash) {
			t.Errorf("the group holds group_context_hash %x and the digest attachment carried %x", state.GroupContextHash, digest.GroupContextHash)
		}
		if state.MediaTtlSeconds != digest.MediaTtlSeconds {
			t.Errorf("the group holds media_ttl_seconds %d and the digest attachment carried %d", state.MediaTtlSeconds, digest.MediaTtlSeconds)
		}
	})

	// The two shapes [openingOf] refuses, which are §5.4's acceptance window read into this
	// package: a `0x0005` commit with no delivery would install a nil key, and a `0x0001`
	// commit WITH one carries a value this package would not read.
	t.Run("TheDeliveryIsRequiredUnderOneKindAndRefusedUnderTheOther", func(t *testing.T) {
		t.Parallel()

		missing, missingGroup := openGroup(t, newStore(DefaultLimits()))
		refused := submitWithKeys(t, missing, seen, missingGroup, nil,
			digestCommitRecord(testHandle(0x31), 1, 0, 2, 0x41))
		wantReason(t, refused[0], protocol.Reason_REASON_REJECTED)
		if _, err := missing.EpochKeys(context.Background(), missingGroup, 2); err == nil {
			t.Fatal("a kind 0x0005 commit with no delivery was refused and epoch 2 exists anyway; the refusal is what stops an epoch opening with a nil write key")
		}

		unwanted, unwantedGroup := openGroup(t, newStore(DefaultLimits()))
		wantReason(t, submitWithKeys(t, unwanted, seen, unwantedGroup, digestKeys(0x41),
			commitRecord(testHandle(0x31), 1, 0, 2, 0x41))[0], protocol.Reason_REASON_REJECTED)

		// THE CONTROL: each arm's own well-formed submission is accepted by the same store, so
		// neither refusal above is a store that refuses commits
		okDigest, okDigestGroup := openGroup(t, newStore(DefaultLimits()))
		wantReason(t, submitWithKeys(t, okDigest, seen, okDigestGroup, digestKeys(0x41),
			digestCommitRecord(testHandle(0x31), 1, 0, 2, 0x41))[0], protocol.Reason_REASON_OK)
		okEpoch, okEpochGroup := openGroup(t, newStore(DefaultLimits()))
		wantReason(t, submit(t, okEpoch, seen, okEpochGroup,
			commitRecord(testHandle(0x31), 1, 0, 2, 0x41))[0], protocol.Reason_REASON_OK)
	})

	// §5.1 check 3's `iff is_commit`, in this package's two copies of it, over the kind the
	// disjunction was written for. A kind 0x0005 attachment on an ORDINARY record is the shape
	// `is_commit != (kind == AttachmentEpoch)` admits — `false != false` passes — so this is
	// the scenario that catches a store whose clause was never widened.
	t.Run("AKind0x0005AttachmentOnANonCommitRecordIsRefused", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))

		ordinary := ordinaryRecord(testHandle(0x31), 1, 0, 0x41)
		ordinary.Attachment = digestCommitRecord(testHandle(0x31), 1, 0, 2, 0x41).Attachment
		wantReason(t, submitWithKeys(t, store, seen, group, nil, ordinary)[0], protocol.Reason_REASON_REJECTED)

		// and the other direction of the same iff, which is the half that was already held:
		// a commit with NO attachment at all
		bare := digestCommitRecord(testHandle(0x31), 1, 1, 2, 0x41)
		bare.Attachment = nil
		wantReason(t, submitWithKeys(t, store, seen, group, digestKeys(0x41), bare)[0], protocol.Reason_REASON_REJECTED)

		// THE CONTROL: the same ordinary record with no attachment is accepted, so the refusal
		// above is about the attachment and not about the record
		wantReason(t, submit(t, store, seen, group, ordinaryRecord(testHandle(0x31), 1, 2, 0x41))[0], protocol.Reason_REASON_OK)
	})

	// Item 244's property, at the layer that owns the row: NOTHING the store hands back for a
	// `0x0005` commit contains either key. The api layer holds the same property over the
	// SERVED BYTES; this is the half that says the row itself never had them.
	t.Run("NoServedValueOfAKind0x0005CommitCarriesEitherKey", func(t *testing.T) {
		t.Parallel()
		store, group := openGroup(t, newStore(DefaultLimits()))

		keys := digestKeys(0x41)
		wantReason(t, submitWithKeys(t, store, seen, group, keys,
			digestCommitRecord(testHandle(0x31), 1, 0, 2, 0x41))[0], protocol.Reason_REASON_OK)

		result, err := store.Fetch(ctx, &FetchRequest{GroupId: group, Limit: 100, ReadEpoch: 2})
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		found := 0
		for _, record := range result.Records {
			// the founding commit at epoch 0 is openGroup's and is kind 0x0001; the subject
			// here is the commit this scenario submitted, at epoch 1
			if !record.IsCommit || record.Epoch != 1 {
				continue
			}
			found++
			if record.Attachment == nil || record.Attachment.Kind != AttachmentEpochDigest {
				t.Fatalf("the served commit came back as attachment kind %v, and this scenario is about kind 0x0005", attachmentKindOf(record))
			}
			// the digest survived the round trip, which is what says the projection did not
			// silently drop the one field the sixth kind adds
			if !slices.Equal(record.Attachment.EpochDigest.EpochKeysDigest, testBytes(32, 0x41+3)) {
				t.Errorf("the served commit's epoch_keys_digest is %x and it was submitted as %x", record.Attachment.EpochDigest.EpochKeysDigest, testBytes(32, 0x41+3))
			}
			// and NEITHER KEY is anywhere in the served row
			if where := keyMaterialIn(record, keys); len(where) != 0 {
				t.Errorf("a served kind 0x0005 commit carries one of the two epoch keys, in %v; ledger item 244 is that the served commit hands a removed member the next epoch's keys, and ruling 27 is the amendment that takes them out", where)
			}
		}
		if found != 1 {
			t.Fatalf("the fetch returned %d commits and this scenario needs exactly the one it submitted; a zero here would make the property above hold over nothing", found)
		}

		// THE POSITIVE CONTROL, IN THE SAME SUBTEST, because "no bytes matched" proves nothing
		// unless the same search FINDS them when they are there. Under kind 0x0001 the served
		// commit carries both keys in its attachment, and `containsKeyMaterial` says so.
		controlStore, controlGroup := openGroup(t, newStore(DefaultLimits()))
		control := commitRecord(testHandle(0x31), 1, 0, 2, 0x41)
		wantReason(t, submit(t, controlStore, seen, controlGroup, control)[0], protocol.Reason_REASON_OK)
		controlResult, err := controlStore.Fetch(ctx, &FetchRequest{GroupId: controlGroup, Limit: 100, ReadEpoch: 2})
		if err != nil {
			t.Fatalf("Fetch (control): %v", err)
		}
		controlKeys := &EpochKeyDelivery{
			WriteKey: control.Attachment.Epoch.WriteKey,
			ReadKey:  control.Attachment.Epoch.ReadKey,
		}
		matched := false
		for _, record := range controlResult.Records {
			if !record.IsCommit || record.Epoch != 1 {
				continue
			}
			// it has to be found IN THE ATTACHMENT and not merely somewhere. A fixture whose
			// ct_body happens to contain the key would satisfy "the search found something"
			// while proving nothing about the serve path item 244 is about
			if slices.Contains(keyMaterialIn(record, controlKeys), "Attachment.Epoch.WriteKey") {
				matched = true
			}
		}
		if !matched {
			t.Fatal("the kind 0x0001 control's served commit does NOT carry its write key in its own attachment under this search, so the search is not one that would find a key under kind 0x0005 either and the property above is vacuous")
		}
	})
}

// Where a served record carries either of two keys, named per field.
//
// It answers the field NAMES rather than a bool, and that is what makes the positive control in
// the scenario above non-vacuous: "the search found the key somewhere" is satisfied by a fixture
// whose `ct_body` happens to contain it, and what the control has to say is that the search
// finds a key IN THE ATTACHMENT, which is where ledger item 244's leak was.
//
// It is written over every place a KEY could be rather than over the one place it was, because
// what item 244 is about is a serve path that forgot: a store that moved the value into
// `ServerAttachment`, into `CtHead` or into the digest field would pass a search that looked
// only where the old one was.
func keyMaterialIn(record *Record, keys *EpochKeyDelivery) []string {
	named := map[string][]byte{
		"ServerAttachment": record.ServerAttachment,
		"CtHead":           record.CtHead,
		"CtBody":           record.CtBody,
		"BodyHash":         record.BodyHash,
		"BlobId":           record.BlobId,
	}
	if record.Attachment != nil {
		if epoch := record.Attachment.Epoch; epoch != nil {
			named["Attachment.Epoch.WriteKey"] = epoch.WriteKey
			named["Attachment.Epoch.ReadKey"] = epoch.ReadKey
			named["Attachment.Epoch.GroupContextHash"] = epoch.GroupContextHash
		}
		if digest := record.Attachment.EpochDigest; digest != nil {
			named["Attachment.EpochDigest.EpochKeysDigest"] = digest.EpochKeysDigest
			named["Attachment.EpochDigest.GroupContextHash"] = digest.GroupContextHash
		}
		if wrap := record.Attachment.Wrap; wrap != nil {
			named["Attachment.Wrap.TargetHandle"] = wrap.TargetHandle
		}
		if recovery := record.Attachment.Recovery; recovery != nil {
			named["Attachment.Recovery.Handle"] = recovery.Handle
			named["Attachment.Recovery.VerifyPub"] = recovery.VerifyPub
		}
	}
	found := []string{}
	for name, field := range named {
		for _, key := range [][]byte{keys.WriteKey, keys.ReadKey} {
			if len(key) != 0 && containsBytes(field, key) {
				found = append(found, name)
				break
			}
		}
	}
	slices.Sort(found)
	return found
}

// A substring search rather than an equality, so that a key CONCATENATED into a wider field —
// which is exactly how `server_attachment` carries one under kind 0x0001 on the wire — is found.
func containsBytes(haystack []byte, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for start := 0; start+len(needle) <= len(haystack); start++ {
		if slices.Equal(haystack[start:start+len(needle)], needle) {
			return true
		}
	}
	return false
}
