package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

// A §10.2 resource file, read.
//
// §10.2 names seven resources and says they "follow `server.Vault.RequireSimpleResource` /
// `server.Config.RequireSimpleResource` naming so ops and ansible keep the same shape". Every
// value §10.2 lists for them is a scalar: a host, a duration in seconds, a count, a DSN, a
// credential. So what this reads is a flat mapping of scalars and nothing else, and everything
// else in YAML — nesting, sequences, anchors, block scalars, multiple documents — is an error
// naming the line rather than a construct silently dropped.
//
// Refusing is the whole point. A loader that skips what it does not understand turns an
// operator's mistake into a server running on a default: a `hosting_jurisdiction` typed one
// indent too far is not an empty file, it is a file whose most important value is missing while
// the rest of it loaded, and §10.1 exists because "an advertised jurisdiction nobody set is
// worse than no answer at all".
//
// Why not a YAML library: spec B §2.2's allow list is normative and closed, and no YAML module
// is on it. deps_test.go enforces the list in the direction that matters — everything not
// written down fails — so adding one is a spec amendment and not a dependency bump. This is a
// hundred lines against that, and it is honest about which hundred: see [errResourceSyntax].

// A line this reader will not guess at. The line NUMBER is in the message and the line CONTENT
// never is: these files hold `pg.yml`'s DSN and `message_server.yml`'s transport credential, and
// a parse error that echoes the line it failed on is how a credential reaches a log.
var errResourceSyntax = errors.New("resource: not a flat `key: value` mapping")

// A key that appears twice. The second one silently winning is the shape where an operator edits
// the value at the top of the file and the server runs on the one at the bottom.
var errResourceDuplicate = errors.New("resource: a key appears twice")

// What one `*.yml` of §10.2 holds: its keys, in file order, and their values.
type resource struct {
	path   string
	values map[string]string
	order  []string
}

// Read one resource file. A file that does not exist is not an error here — which of the seven
// are required is the caller's question, and §10.2's answer differs per resource — so the
// absence is reported as such and every key reads as unset.
func readResource(path string) (*resource, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return &resource{path: path, values: map[string]string{}}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()

	current := &resource{path: path, values: map[string]string{}}
	scanner := bufio.NewScanner(file)
	for number := 1; scanner.Scan(); number++ {
		line := scanner.Text()
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "" {
			continue
		}
		// a comment is a `#` in the FIRST column, and nowhere else. A trailing `#` is not a
		// comment because a DSN's password may contain one, and a reader that stripped it would
		// truncate a credential into a connection that fails with the wrong error
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, " ") || strings.HasPrefix(trimmed, "\t") {
			return nil, true, fmt.Errorf("%s line %d: %w (this line is indented, and nested mappings are not read)", path, number, errResourceSyntax)
		}
		if strings.HasPrefix(trimmed, "-") {
			return nil, true, fmt.Errorf("%s line %d: %w (this line is a sequence item, and sequences are not read)", path, number, errResourceSyntax)
		}
		name, value, found := strings.Cut(trimmed, ":")
		if !found {
			return nil, true, fmt.Errorf("%s line %d: %w (no `:` on this line)", path, number, errResourceSyntax)
		}
		name = strings.TrimSpace(name)
		if name == "" || !simpleKey(name) {
			return nil, true, fmt.Errorf("%s line %d: %w (the key is empty or holds a character outside a-z 0-9 . _ -)", path, number, errResourceSyntax)
		}
		value = strings.TrimSpace(value)
		if unquoted, ok := unquote(value); ok {
			value = unquoted
		} else if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, "'") {
			return nil, true, fmt.Errorf("%s line %d: %w (the value opens a quote it does not close; no escape sequence is read, so a value containing its own quote character must be written unquoted)", path, number, errResourceSyntax)
		}
		if _, taken := current.values[name]; taken {
			return nil, true, fmt.Errorf("%s line %d: %w: %q", path, number, errResourceDuplicate, name)
		}
		current.values[name] = value
		current.order = append(current.order, name)
	}
	if err := scanner.Err(); err != nil {
		return nil, true, err
	}
	return current, true, nil
}

// A key is a name an operator can type and this reader can be sure of. Deliberately narrow:
// anything wider is a key that differs from another by something invisible.
func simpleKey(name string) bool {
	for _, character := range name {
		switch {
		case 'a' <= character && character <= 'z':
		case '0' <= character && character <= '9':
		case character == '.' || character == '_' || character == '-':
		default:
			return false
		}
	}
	return true
}

// One layer of matching quotes, stripped. No escape processing at all, which is the honest
// limit and is stated in the syntax error above rather than left to be discovered.
func unquote(value string) (string, bool) {
	if len(value) < 2 {
		return value, false
	}
	first, last := value[0], value[len(value)-1]
	if first != last {
		return value, false
	}
	if first != '"' && first != '\'' {
		return value, false
	}
	inner := value[1 : len(value)-1]
	if strings.ContainsRune(inner, rune(first)) {
		return value, false
	}
	return inner, true
}

// The value under this key, and whether it was set at all. An empty value that WAS written is
// distinguishable from a key nobody wrote, because §10.1 turns on exactly that difference.
func (self *resource) lookup(name string) (string, bool) {
	value, found := self.values[name]
	return value, found
}

// Every key this file held that the caller never asked for.
//
// A misspelled key in a config file is the failure this catches, and it is the one an operator
// hits: `operator_hosts:`, `hosting_juristiction:`, a key from an older revision of §10.2. Left
// unchecked it is a file that loads, a server that runs on a default, and nothing anywhere that
// says so.
func (self *resource) unread(known map[string]bool) []string {
	var unknown []string
	for _, name := range self.order {
		if !known[name] {
			unknown = append(unknown, name)
		}
	}
	return unknown
}
