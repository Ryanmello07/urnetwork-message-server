package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The §10.2 resource reader, as the two properties it exists for.
//
//  1. **A line this reader does not understand is an error, never a line it skips.** Four of the
//     seven resources §10.2 names are vault resources; the values in them are a DSN, a KEK and a
//     transport credential, and the one in `message.yml` that matters most is a value §10.1
//     refuses readiness over. A reader that silently drops what it cannot parse turns every one
//     of those into a server running on a default with nothing anywhere saying so.
//
//  2. **Nothing it refuses is echoed.** The line number is in the message and the line never is.
//     A parse error that prints the line it failed on is how `pg.yml`'s password and
//     `message_server.yml`'s credential reach a log — and a parse error is exactly the moment an
//     operator copies the whole message into a ticket.

// Every shape this reader will not guess at is refused, and none of them prints the line.
//
// The secret is in every fixture on purpose. A reader that echoed the failing line would pass a
// test that only checked for an error.
func TestALineThisReaderCannotParseIsRefusedAndNeverEchoed(t *testing.T) {
	const secret = "sup3rsecret-not-in-any-message"
	for _, badly := range []struct {
		what     string
		contents string
	}{
		{"an indented line, which is a nested mapping", "outer:\n  dsn: " + secret + "\n"},
		{"a sequence item", "- " + secret + "\n"},
		{"a line with no colon at all", secret + "\n"},
		{"a value that opens a quote it does not close", `dsn: "` + secret + "\n"},
		{"a key that is not a key", "a key with spaces: " + secret + "\n"},
		{"the same key twice", "dsn: first\ndsn: " + secret + "\n"},
	} {
		t.Run(badly.what, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), pgResource)
			if err := os.WriteFile(path, []byte(badly.contents), 0o600); err != nil {
				t.Fatalf("writing the fixture: %v", err)
			}
			_, _, err := readResource(path)
			if err == nil {
				t.Fatalf("%s loaded without complaint; whatever an operator meant to set is not set and nothing says so", badly.what)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the refusal printed the line it failed on, and this file's line holds a credential: %v", err)
			}
		})
	}
}

// A duplicate key is refused rather than resolved.
//
// Last-wins and first-wins are both defensible and both wrong here: an operator who edits the
// value at the top of a file and gets the one at the bottom has a server running on something
// they cannot see.
func TestAKeyWrittenTwiceIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), messageResource)
	if err := os.WriteFile(path, []byte("operator_host: one\noperator_host: two\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	if _, _, err := readResource(path); !errors.Is(err, errResourceDuplicate) {
		t.Fatalf("a key written twice was answered %v, want %v", err, errResourceDuplicate)
	}
}

// A key written with an empty value is not the same as a key nobody wrote.
//
// §10.1 turns on exactly this difference. `hosting_jurisdiction:` written empty is an operator
// who has been asked and has not answered, and `hosting_jurisdiction` absent is an operator who
// has not been asked — and while both refuse readiness today, a loader that cannot tell them
// apart cannot ever be made to.
func TestAKeyWrittenEmptyIsDistinguishableFromAKeyNobodyWrote(t *testing.T) {
	path := filepath.Join(t.TempDir(), messageResource)
	if err := os.WriteFile(path, []byte("operator_host:\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	file, _, err := readResource(path)
	if err != nil {
		t.Fatalf("readResource: %v", err)
	}
	value, found := file.lookup("operator_host")
	if !found {
		t.Fatal("a key written with an empty value reads as a key nobody wrote")
	}
	if value != "" {
		t.Fatalf("a key written with an empty value reads as %q", value)
	}
	if _, found := file.lookup("hosting_jurisdiction"); found {
		t.Fatal("a key nobody wrote reads as written")
	}
}

// A `#` is a comment in the first column and nowhere else.
//
// The reason is a value, not a preference: a Postgres password may contain `#`, and a reader that
// treated a trailing `#` as a comment would truncate the credential and hand pgx a password that
// is almost right — which fails authentication, in a message that says nothing about a comment.
func TestAHashInsideAValueIsPartOfTheValue(t *testing.T) {
	const dsn = "postgres://postgres:pa#ssword@127.0.0.1:5432/urmessage"
	path := filepath.Join(t.TempDir(), pgResource)
	if err := os.WriteFile(path, []byte("# the message-server cluster (decision B10)\ndsn: "+dsn+"\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	file, _, err := readResource(path)
	if err != nil {
		t.Fatalf("readResource: %v", err)
	}
	if value, _ := file.lookup("dsn"); value != dsn {
		t.Fatalf("the DSN read back as %q; a `#` in the password was treated as a comment", value)
	}
}

// An absent file is absent, and every key in it reads as unset.
//
// Which of §10.2's seven resources are required is the caller's question and differs per
// resource, so the reader reports the absence rather than deciding it.
func TestAnAbsentResourceIsReportedAsAbsentRatherThanAsAnError(t *testing.T) {
	file, present, err := readResource(filepath.Join(t.TempDir(), "message_fleet.yml"))
	if err != nil {
		t.Fatalf("readResource on a file that does not exist: %v", err)
	}
	if present {
		t.Fatal("a file that does not exist was reported as present")
	}
	if _, found := file.lookup("write_key_kek"); found {
		t.Fatal("a key in a file that does not exist reads as set")
	}
}

// One layer of quotes comes off, and a value that contains its own quote is refused rather than
// half-read.
//
// No escape processing at all is the honest limit, and the refusal is what makes it honest: a
// reader that stripped the outer quotes and left an inner one is a reader that silently corrupts
// a credential.
func TestOneLayerOfQuotesComesOffAndAnInnerQuoteIsRefused(t *testing.T) {
	for _, current := range []struct {
		what     string
		written  string
		want     string
		refusing bool
	}{
		{"double quotes", `dsn: "postgres://x"`, "postgres://x", false},
		{"single quotes", `dsn: 'postgres://x'`, "postgres://x", false},
		{"no quotes", `dsn: postgres://x`, "postgres://x", false},
		{"a value holding its own quote", `dsn: "postgres://a"b"`, "", true},
	} {
		t.Run(current.what, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), pgResource)
			if err := os.WriteFile(path, []byte(current.written+"\n"), 0o600); err != nil {
				t.Fatalf("writing the fixture: %v", err)
			}
			file, _, err := readResource(path)
			if current.refusing {
				if err == nil {
					t.Fatalf("%s loaded, and there is no reading of it this reader can be sure of", current.what)
				}
				return
			}
			if err != nil {
				t.Fatalf("readResource: %v", err)
			}
			if value, _ := file.lookup("dsn"); value != current.want {
				t.Fatalf("%s read back as %q, want %q", current.what, value, current.want)
			}
		})
	}
}
