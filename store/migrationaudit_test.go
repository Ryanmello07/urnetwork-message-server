package store

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// THE MIGRATION AUDIT (the identity plan's Task 18, Property 2; Spec B §13's test 43): no landed
// migration is edited, renamed or moved, and 013 and 014 come after every one of them.
//
// [Migrate]'s `migration_audit` holds a NAME to its version, and that catches a rename, a move or a
// deletion on the next run against a database that ran the list. It does not catch an edit: a
// landed migration whose SQL changed under the same name and position is skipped by every database
// that ran it and applied by every database that did not, and the two schemas silently differ.
// That is the edit this test is for. It holds each landed migration to the SHA-256 of its SQL, by
// position, so the edit fails here, on the commit that makes it, against no database at all.
//
// WHICH ARE LANDED. The thirteen below are this repository's `main` when 013 and 014 were
// appended, and a migration joins this table in the commit after the one that lands it on `main`,
// with the digest of its SQL as it landed. The ones appended since, which have not landed, are
// named in [appendedMigrations], in order: their SQL may still change before they land, and naming
// them is what makes a migration added to the list without a decision fail here.
var landedMigrations = []struct {
	name   string
	sha256 string
}{
	{"001 message_group", "da5e64148d4feb856edd005dca7f7df98e5067a64fd3ba460bd2fbad492994af"},
	{"002 message_epoch", "2dfaade8328d631248ddab708285587b475c8da1a2e9934376bc359088638175"},
	{"003 message_record", "e08b2daa7ec2750393ac018a64c0e3e3849eefd9bf9cc473575714bf117c9e23"},
	{"003b message_stream_claim", "bf2b88eefee0775edad2e0d939fcc73d9c5de0e0a2dfcb11b8171945d72f6e56"},
	{"004 message_record indexes", "3680aefa94a0f48baccfa518e5284a69ebd8b6881c3ca6c46e65531b6c6d7fc8"},
	{"004b message_commit", "eaee661cce08c53aa91f85b11764517cae43c2862146044c631e19b7c5de1c22"},
	{"005 message_sender", "08de5cce638edeb42bc71bc9fcd4e0be8a1fa4606696615f4fa6f442083957f2"},
	{"005b message_epoch expected_wrap_count", "325ef8a07a6d3361b25b5a4532aa796c7f5123726c5707a4eef1d570c21a71c6"},
	{"005c message_record attachment projection", "c0ed2ab6c776dfe4ef7bb3a7ebcfc054c599207e987af35af8939e0dd08f734f"},
	{"009 message_recovery", "b92d3aefab3af366d9daac01781912c0cc21d603e069665f859150ff805f4e5f"},
	{"010 message_record eph_window", "c80399d307f9abf812fcd55231d07383562f582234e7d7147c2a5b79a8c51b3c"},
	{"011 message_record epoch ceiling", "e881bd1d2fb1155166db36bedea44bc0e0ef4a927e5a07d1bdc8a658237870f1"},
	{"012 message_record epoch digest", "8787760d2a19efad7824a04bfe767420877993c12b4e3c9cf5800bd9c4e3da9f"},
}

// Appended after every landed migration and not landed yet: §4.3.11's two tables, as §3.2's
// revision 25 has them (ledger item 301).
var appendedMigrations = []string{
	"013 message_rendezvous",
	"014 message_rendezvous_deposit",
}

func TestNoLandedMigrationIsEditedRenamedOrMoved(t *testing.T) {
	list := migrationAuditList(migrations)
	for index, landed := range landedMigrations {
		t.Logf("landed %2d: %-45s %s", index+1, landed.name, landed.sha256)
	}
	t.Logf("appended since: %v", appendedMigrations)
	if findings := migrationAuditFindings(list); len(findings) != 0 {
		t.Fatalf("the migration list departs from what landed:\n  %s", strings.Join(findings, "\n  "))
	}

	// THE CONTROL, in the same run, one case per way the property can fail. Each is the real list
	// with one change, and each must be reported, naming the migration it is about
	for _, control := range []struct {
		what  string
		names string
		edit  func([]auditedMigration) []auditedMigration
	}{
		{"one octet of a landed migration's SQL changed", "011 message_record epoch ceiling", func(list []auditedMigration) []auditedMigration {
			list[11].sql = list[11].sql + " "
			return list
		}},
		{"a landed migration renamed", "004b message_commit", func(list []auditedMigration) []auditedMigration {
			list[5].name = "004b the commit table"
			return list
		}},
		{"two landed migrations swapped", "002 message_epoch", func(list []auditedMigration) []auditedMigration {
			list[1], list[2] = list[2], list[1]
			return list
		}},
		{"a landed migration removed", "012 message_record epoch digest", func(list []auditedMigration) []auditedMigration {
			return slices.Delete(list, 12, 13)
		}},
		{"a migration appended without being named", "015 unnamed", func(list []auditedMigration) []auditedMigration {
			return append(list, auditedMigration{name: "015 unnamed", sql: "SELECT 1;"})
		}},
	} {
		findings := migrationAuditFindings(control.edit(slices.Clone(list)))
		if len(findings) == 0 || !strings.Contains(strings.Join(findings, "\n"), control.names) {
			t.Fatalf("the audit, shown the list with %s, reported %v; it must name %q, or it cannot tell the property from its failure",
				control.what, findings, control.names)
		}
	}
}

type auditedMigration struct {
	name string
	sql  string
}

func migrationAuditList(list []migration) []auditedMigration {
	audited := []auditedMigration{}
	for _, current := range list {
		audited = append(audited, auditedMigration{name: current.name, sql: current.sql})
	}
	return audited
}

func migrationAuditFindings(list []auditedMigration) []string {
	findings := []string{}
	for index, landed := range landedMigrations {
		version := index + 1
		if index >= len(list) {
			findings = append(findings, fmt.Sprintf("version %d, %q, has landed and the list no longer holds it", version, landed.name))
			continue
		}
		current := list[index]
		if current.name != landed.name {
			findings = append(findings, fmt.Sprintf("version %d landed as %q and the list holds %q there", version, landed.name, current.name))
			continue
		}
		digest := sha256.Sum256([]byte(current.sql))
		if got := hex.EncodeToString(digest[:]); got != landed.sha256 {
			findings = append(findings, fmt.Sprintf("version %d, %q, has landed and its SQL is not what landed: SHA-256 %s, want %s", version, landed.name, got, landed.sha256))
		}
	}
	for offset, name := range appendedMigrations {
		index := len(landedMigrations) + offset
		if index >= len(list) || list[index].name != name {
			findings = append(findings, fmt.Sprintf("version %d should be %q, appended after every landed migration", index+1, name))
		}
	}
	for index := len(landedMigrations) + len(appendedMigrations); index < len(list); index++ {
		findings = append(findings, fmt.Sprintf("version %d, %q, is in the list and neither landed nor named as appended", index+1, list[index].name))
	}
	return findings
}
