// The edit-log gate: the rule each spec document states about its OWN log, checked against
// this repository's history rather than against the reviewer who reads the document after.
//
// Spec B's log says it in four sentences: "Append-only. Newest last. One entry per commit that
// changes this spec. Follow the ledger §6 change process: edit, subagent diff review, fix,
// commit with the ledger entry, append here." Spec A §0.6 and Spec C §0.6 say the same thing in
// their own words, and SPEC-LEDGER.md §7 says it one level up — "one entry per commit that
// changes a spec or plan".
//
// # Why this is a test and not a step in the change process
//
// It was a step in the change process, and it was skipped. Measured over the whole history at
// the commit that adds this file:
//
//	Spec B    23 commits touch it,  3 added no entry — 3bc0603 (it created the document),
//	                                                   21f22c7, 5210f09
//	Spec A    36 commits touch it,  8 added no entry — 3bc0603, 10f0a39, 28c04b2, 4eddba1,
//	                                                   368ef8d, a401b9b, 21f22c7, 5210f09
//	Spec C     9 commits touch it,  4 added no entry — 3bc0603, d2e7a51, 368ef8d, 21f22c7
//
// The two most recent spec commits on this project — 21f22c7 and 5210f09, which between them
// carried ruling 27, the largest amendment these documents have taken — appended nothing to any
// of the three logs. Spec B's log ended at Revision 21 of 2026-09-13; Spec A's table ended at
// A-27 of 2026-09-15 with its last SIX commits adding no row at all. Both commits wrote a long
// SPEC-LEDGER entry instead, which is a different artefact from the per-document log the
// document's own process names, and a reader of either document could not see the amendment.
//
// This project's own rule for that situation is written down and is the reason this file
// exists: a gate bypassed twice is not tracking the property, and the repair is a mechanical
// check rather than a louder reminder.
//
// # Why the check is per commit, and not "the newest date in the log is not older than the
// newest commit"
//
// That was the first proposal and it is weaker in three ways that are measurable here, not
// arguable:
//
//  1. It cannot be written for Spec C. Its log is `| Rev | Change |` — the entries carry a
//     revision NUMBER and no date field at all. Written the obvious way, over any date found in
//     an entry, it reads 2026-08-12 out of a FILENAME quoted in row 2 and reports the log as
//     stale forever, no matter how many rows are appended. Measured: mutant M6 of this commit.
//  2. It is blind at day resolution, which is the resolution this project actually commits at.
//     21f22c7 and 5210f09 landed on the same day, and three passes of 2026-09-22 are in this
//     history already. Backfilling one entry dated 2026-09-22 would make every later commit of
//     that day pass a date check having appended nothing.
//  3. It says nothing about WHICH commit an entry belongs to, so it cannot tell a log that is
//     current from a log that took one entry and skipped five.
//
// The property the documents state is per commit, so the check is per commit: for every commit
// that changed the document, the same commit added a line to that document's own log region.
//
// # The region is the mechanism, and it is load-bearing
//
// An added line counts only if its line number in the file AS OF THAT COMMIT falls inside the
// document's edit-log section. Matching the entry pattern anywhere in the diff is not the same
// check and does not give the same answer: 3bc0603 added THIRTY-TWO lines matching Spec C's
// entry pattern `| <n> | ...` and NONE of them is an edit-log row — they are §14.2's per-datum
// table and four others like it. Unscoped, that commit reads as the best-documented commit in
// the history. Scoped, it correctly reads as the commit that created the document with an empty
// log, which is what the log itself says: its first entry is numbered 2.
// TestTheEditLogGateStillDetectsWhatPaidAndWhatDidNot holds that difference as an assertion, so
// the scoping cannot be removed and leave a green suite behind.
//
// # Both directions, or it is not a narrowing
//
// Every commit that this gate does not hold to the rule is named in editLogDispositions with a
// kind, and each kind carries its own assertion:
//
//   - backfilledInTheLog — the document's log region must CITE that commit's short hash today.
//     The entry that pays a debt has to name what it is paying, or the claim is unauditable.
//   - createdTheDocument — the commit must be the FIRST commit that touched the document, and
//     the document's log must begin at entry 2, which is what makes the creating commit
//     revision 1 rather than a skipped one.
//   - debtRecordedNotPaid — the commit must be an ancestor of editLogGateBaseline. This kind
//     records a debt that predates the gate and CANNOT excuse new work: a commit landed after
//     the baseline can never take it.
//
// And the reverse direction is a refusal too. A disposition row whose commit did not touch that
// document, or did touch it and paid, or is not in the history at all, fails the gate. A map
// that grows a row nothing needs is how a narrowing stops tracking what it narrows.
//
// # How to run it
//
//	go test ./ -run TestTheEditLogGate
//
// Every test in this file carries that prefix and
// TestTheEditLogGateRunsUnderTheInvocationThisFileDocuments derives the test set off this
// file's own source, so a check added tomorrow is run by the command that is already written
// down. planlint_test.go shipped five checks that this rule would have caught being unrunnable
// for a month; the rule is copied from there on purpose.
//
// # What it costs and what it cannot see
//
// It runs git once per commit per document plus one blob read each — about 180 invocations over
// this history, a few seconds. It reads structure, never meaning: it cannot tell a truthful
// entry from a lie, and an entry that says "typo fix" over a commit that rewrote §5 satisfies
// it completely. That half stays the author's and the diff review's.
package messageserver

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ── the invocation, held to this file's source rather than to the comment above ──────────

const editLogRunPrefix = "TestTheEditLogGate"

const editLogGateSource = "editlog_test.go"

// ── the corpus, and the rule each document states ────────────────────────────────────────

type editLogRule int

const (
	// The document carries its own log and every commit that changes the document appends to
	// it. Specs A, B and C.
	ruleOwnEntryPerCommit editLogRule = iota

	// The document is the log FOR the others: every commit that changes a spec or a plan
	// appends an entry here. SPEC-LEDGER.md §7.
	ruleEntryWhenASpecChanges

	// The document carries no per-commit log and is not held to one. The reason is stated and
	// the absence is asserted, because "it has no log" is exactly the sentence a document
	// acquires by losing one.
	ruleNoLogOfItsOwn
)

type editLogDocument struct {
	path string
	rule editLogRule

	// The heading line that opens the log region, verbatim. Its level (the count of leading
	// '#') closes the region at the next heading of that level or higher.
	heading string

	// One entry, matched against a single line inside the region. The first capture group, when
	// numbered is true, is the entry's number.
	entry    *regexp.Regexp
	numbered bool

	why string
}

func editLogCorpus() []editLogDocument {
	return []editLogDocument{
		{
			path:     "docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md",
			rule:     ruleOwnEntryPerCommit,
			heading:  "### 0.6 Edit log",
			entry:    regexp.MustCompile(`^\| \d{4}-\d{2}-\d{2} \| A-(\d+) \|`),
			numbered: true,
			why:      "§0.6: \"Append-only. Newest last. One entry per commit that changes this spec.\"",
		},
		{
			path:     "docs/specs/2026-08-12-spec-b-message-server-operator.md",
			rule:     ruleOwnEntryPerCommit,
			heading:  "### Edit log",
			entry:    regexp.MustCompile(`^\*\*Revision (\d+)`),
			numbered: true,
			why:      "\"Append-only. Newest last. One entry per commit that changes this spec.\"",
		},
		{
			path:     "docs/specs/2026-08-12-spec-c-windows-client-ui.md",
			rule:     ruleOwnEntryPerCommit,
			heading:  "### 0.6 Edit log",
			entry:    regexp.MustCompile(`^\| (\d+) \| `),
			numbered: true,
			why:      "§0.6: \"Append-only. Newest last. One entry per commit that changes this spec.\"",
		},
		{
			path:    "SPEC-LEDGER.md",
			rule:    ruleEntryWhenASpecChanges,
			heading: "## 7. Edit log",
			entry:   regexp.MustCompile(`^### \d{4}-\d{2}-\d{2}`),
			why:     "§7: \"Append-only. Newest last. One entry per commit that changes a spec or plan.\"",
		},
		{
			path: "docs/specs/2026-08-12-urmessage-protocol-design.md",
			rule: ruleNoLogOfItsOwn,
			why: "MASTER's §0 is \"Revision history and what it cost\" — a narrative of what each " +
				"REVISION cost, written in paragraphs and carrying no per-commit rule. It is not an " +
				"append-only log and this gate does not invent one for it.",
		},
		{
			path: "docs/specs/2026-08-13-windows-client-scaffold-brief.md",
			rule: ruleNoLogOfItsOwn,
			why: "A brief handed to the client scaffold, not a normative document: it states no " +
				"edit-log rule and nothing cites it as one.",
		},
	}
}

// Every other document this repository writes specs against lives under docs/plans/. They hold
// no log of their own — the ledger's §7 is the log for a plan change — and that narrowing is
// asserted by TestTheEditLogGateCoversEveryDocumentInTheCorpus rather than assumed here.
const editLogPlanGlob = "docs/plans/*.md"

const editLogSpecGlob = "docs/specs/*.md"

// A heading that opens a per-commit log, in the loosest form this project has ever written one.
// It is what the ruleNoLogOfItsOwn rows are asserted against, with the documents that DO carry a
// log as the positive control in the same query.
var editLogHeadingPattern = regexp.MustCompile(`(?mi)^#{2,4} +([\d.]+ +)?edit log *$`)

// ── the dispositions ─────────────────────────────────────────────────────────────────────

type editLogDispositionKind int

const (
	// The document's log region cites this commit's short hash today. Asserted against the
	// document, not against this comment.
	backfilledInTheLog editLogDispositionKind = iota

	// This commit created the document. Asserted: it is the first commit that touched the path,
	// and the log's first entry is numbered 2 — so the creating commit is revision 1 and not a
	// skipped one.
	createdTheDocument

	// A debt that predates this gate, recorded and not paid. Asserted: the commit is an
	// ancestor of editLogGateBaseline, so no commit landed after the baseline can ever take
	// this kind.
	debtRecordedNotPaid
)

func (self editLogDispositionKind) String() string {
	switch self {
	case backfilledInTheLog:
		return "backfilledInTheLog"
	case createdTheDocument:
		return "createdTheDocument"
	case debtRecordedNotPaid:
		return "debtRecordedNotPaid"
	}
	return fmt.Sprintf("editLogDispositionKind(%d)", int(self))
}

type editLogDisposition struct {
	doc    string
	commit string
	kind   editLogDispositionKind
	why    string
}

// The commit this gate's own repair was written on top of. It is the ONLY thing
// debtRecordedNotPaid is measured against: a commit that is not an ancestor of this one cannot
// carry that kind, so the historical debt below can never grow by one more skipped commit.
const editLogGateBaseline = "41d8207"

func editLogDispositions() []editLogDisposition {
	const (
		specA  = "docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md"
		specB  = "docs/specs/2026-08-12-spec-b-message-server-operator.md"
		specC  = "docs/specs/2026-08-12-spec-c-windows-client-ui.md"
		ledger = "SPEC-LEDGER.md"
	)
	return []editLogDisposition{
		{specA, "3bc0603", createdTheDocument, "the commit that added specs A, B and C; §0.6 begins at A-2"},
		{specB, "3bc0603", createdTheDocument, "the same commit; the log begins at Revision 2"},
		{specC, "3bc0603", createdTheDocument, "the same commit; §0.6 begins at Rev 2"},

		{specA, "10f0a39", backfilledInTheLog, "paid by A-28"},
		{specA, "28c04b2", backfilledInTheLog, "paid by A-28"},
		{specA, "4eddba1", backfilledInTheLog, "paid by A-28"},
		{specA, "368ef8d", backfilledInTheLog, "paid by A-28"},
		{specA, "a401b9b", backfilledInTheLog, "paid by A-28"},
		{specA, "21f22c7", backfilledInTheLog, "paid by A-28"},
		{specA, "5210f09", backfilledInTheLog, "paid by A-28"},

		{specB, "21f22c7", backfilledInTheLog, "paid by Revision 22"},
		{specB, "5210f09", backfilledInTheLog, "paid by Revision 22"},

		{specC, "d2e7a51", backfilledInTheLog, "paid by Rev 7"},
		{specC, "368ef8d", backfilledInTheLog, "paid by Rev 7"},
		{specC, "21f22c7", backfilledInTheLog, "paid by Rev 7"},
	}
}

// The ledger's own arm, which is the same rule one level up and has a longer debt.
//
// §7 says one entry per commit that changes a spec or a plan. Twenty-one commits of this
// history changed one and appended no §7 entry — every one of them before the baseline, most of
// them in the first three days of the repository, and four of them (10f0a39, 368ef8d, a401b9b
// and d89e528) recent commits that DID write ledger prose, into §5's open items rather than into
// §7's log. The set is closed and asserted exactly: a commit that is delinquent and not listed
// here fails the gate, and a hash listed here that turns out to have paid, or to be a descendant
// of the baseline, fails it too.
//
// It is a list and not a count because a count is satisfied by any twenty-one commits.
func editLogLedgerDebt() []string {
	return []string{
		"24df8be", "0e349ba", "e424ce0", "ad355c6", "2891f19", "e2e2e5a", "5ed3e02",
		"636779d", "cfe47b8", "c76d7db", "43f6de0", "3d6c09b", "74f83d7", "9a03a12",
		"7964c38", "d89e528", "f971f29", "10f0a39", "05b3288", "368ef8d", "a401b9b",
	}
}

// ── git, which this gate reads and never writes ──────────────────────────────────────────

// The git command, found rather than assumed, and FATAL when it is missing. A gate that skips
// is a gate that is off and reports the same green run as a gate that passed — deps_test.go
// makes the same argument about the go command and this file takes it verbatim.
func gitCommand(t *testing.T) string {
	t.Helper()
	found, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("no git command on PATH (%v); this gate reads the history and does not skip", err)
	}
	return found
}

func gitTry(t *testing.T, arguments ...string) (string, error) {
	t.Helper()
	command := exec.Command(gitCommand(t), arguments...)
	stdout := &strings.Builder{}
	stderr := &strings.Builder{}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w\n%s", strings.Join(arguments, " "), err, stderr.String())
	}
	return strings.ReplaceAll(stdout.String(), "\r", ""), nil
}

func gitOutput(t *testing.T, arguments ...string) string {
	t.Helper()
	out, err := gitTry(t, arguments...)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out
}

func gitLines(t *testing.T, arguments ...string) []string {
	t.Helper()
	out := []string{}
	for _, line := range strings.Split(gitOutput(t, arguments...), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// The history has to be all of it. A shallow clone answers a truncated commit list to every
// question this file asks and each answer looks like a clean repository: no commit touched the
// document, so no commit skipped its entry. .github/workflows/gates.yml checks out with
// fetch-depth: 0 for this reason, and this is the assertion that says so out loud.
func requireWholeHistory(t *testing.T) {
	t.Helper()
	if _, err := gitTry(t, "rev-parse", "--git-dir"); err != nil {
		t.Fatalf("this is not a git working tree, so the edit-log gate can read nothing: %v", err)
	}
	if strings.TrimSpace(gitOutput(t, "rev-parse", "--is-shallow-repository")) == "true" {
		t.Fatal("the repository is a SHALLOW clone: every history question below would be answered " +
			"off a truncated log and would pass having read almost nothing. Fetch the whole history " +
			"(fetch-depth: 0 in CI, git fetch --unshallow by hand).")
	}
	if _, err := gitTry(t, "rev-parse", "--verify", editLogGateBaseline+"^{commit}"); err != nil {
		t.Fatalf("the baseline %s is not in this history (%v); debtRecordedNotPaid is measured "+
			"against it and cannot be measured here", editLogGateBaseline, err)
	}
}

func shortHash(t *testing.T, revision string) string {
	t.Helper()
	out, err := gitTry(t, "rev-parse", "--short=7", revision+"^{commit}")
	if err != nil {
		t.Fatalf("%s is not a commit in this history: %v", revision, err)
	}
	return strings.TrimSpace(out)
}

// Every commit that changed one of these paths, oldest first, with its parents. Merge commits
// are refused rather than skipped: `git show` prints no diff for a merge by default, so a gate
// that met one would read nothing and say so in the shape of a pass. This history holds none.
func commitsTouching(t *testing.T, paths ...string) []string {
	t.Helper()
	arguments := append([]string{"log", "--reverse", "--format=%h %p", "--"}, paths...)
	commits := []string{}
	for _, line := range gitLines(t, arguments...) {
		fields := strings.Fields(line)
		if len(fields) > 2 {
			t.Fatalf("commit %s is a MERGE (parents %v) and `git show` prints no diff for one by "+
				"default; this gate would read nothing from it. Teach it -m before merging.",
				fields[0], fields[1:])
		}
		commits = append(commits, fields[0])
	}
	return commits
}

func fileAt(t *testing.T, sha string, path string) string {
	t.Helper()
	out, err := gitTry(t, "show", sha+":"+path)
	if err != nil {
		return ""
	}
	return out
}

// ── the log region, and what an entry in it is ───────────────────────────────────────────

// The 1-based, inclusive line range of the document's log section. It ends at the next heading
// of the same level or higher, which is what makes "inside the log" a property of the document's
// structure rather than of a line count somebody has to keep up to date.
func editLogRegion(document editLogDocument, content string) (int, int, bool) {
	if content == "" {
		return 0, 0, false
	}
	level := len(document.heading) - len(strings.TrimLeft(document.heading, "#"))
	lines := strings.Split(strings.ReplaceAll(content, "\r", ""), "\n")
	start := 0
	for index, line := range lines {
		if strings.TrimRight(line, " ") == document.heading {
			start = index + 2 // the heading itself is not part of the region
			break
		}
	}
	if start == 0 {
		return 0, 0, false
	}
	for index := start - 1; index < len(lines); index++ {
		line := lines[index]
		if !strings.HasPrefix(line, "#") {
			continue
		}
		hashes := len(line) - len(strings.TrimLeft(line, "#"))
		if hashes <= level && strings.HasPrefix(strings.TrimLeft(line, "#"), " ") {
			return start, index, true // the heading line's index is the last line before it
		}
	}
	return start, len(lines), true
}

// The entry lines the document's log carries today, in order.
func editLogEntries(t *testing.T, document editLogDocument, content string) []string {
	t.Helper()
	start, end, found := editLogRegion(document, content)
	if !found {
		t.Fatalf("%s: the heading %q is not in the document, so its log region cannot be located",
			document.path, document.heading)
	}
	lines := strings.Split(strings.ReplaceAll(content, "\r", ""), "\n")
	entries := []string{}
	for index := start - 1; index < end && index < len(lines); index++ {
		if document.entry.MatchString(lines[index]) {
			entries = append(entries, lines[index])
		}
	}
	return entries
}

// The number of log entries a commit APPENDED to a document: added lines whose position in the
// file as of that commit falls inside that commit's own log region.
//
// scoped=false answers the same question with the region dropped — the weaker check this gate
// deliberately is not — and exists so the difference between the two can be asserted rather than
// described. See TestTheEditLogGateStillDetectsWhatPaidAndWhatDidNot.
func editLogEntriesAdded(t *testing.T, document editLogDocument, sha string, scoped bool) int {
	t.Helper()
	start, end, found := editLogRegion(document, fileAt(t, sha, document.path))
	if !found && scoped {
		// The document had no log section at that commit, so no line of that commit can have
		// landed in one. It is delinquent and needs a disposition like any other.
		return 0
	}
	diff := gitOutput(t, "show", "--no-color", "--format=", "--unified=0", "--no-renames", sha, "--", document.path)
	count := 0
	line := 0
	for _, text := range strings.Split(diff, "\n") {
		switch {
		case strings.HasPrefix(text, "@@"):
			line = hunkStart(t, sha, text)
		case strings.HasPrefix(text, "+++"), strings.HasPrefix(text, "---"):
		case strings.HasPrefix(text, "+"):
			if document.entry.MatchString(text[1:]) && (!scoped || (line >= start && line <= end)) {
				count++
			}
			line++
		case strings.HasPrefix(text, "-"):
		default:
			if line > 0 {
				line++
			}
		}
	}
	return count
}

var hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

func hunkStart(t *testing.T, sha string, header string) int {
	t.Helper()
	match := hunkHeader.FindStringSubmatch(header)
	if match == nil {
		t.Fatalf("%s: unreadable hunk header %q; the gate would mis-place every added line after it", sha, header)
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("%s: unreadable hunk header %q: %v", sha, header, err)
	}
	return value
}

func readDocument(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return strings.ReplaceAll(string(raw), "\r", "")
}

// The guard against the failure this whole file is about: a check whose class is empty has read
// nothing, and its clean run means nothing.
func editLogMustHaveRead(t *testing.T, subject string, count int) {
	t.Helper()
	if count == 0 {
		t.Fatalf("%s read NOTHING, so a clean run of it would report clean over an empty class", subject)
	}
	t.Logf("%s: %d read", subject, count)
}

// ── check 1: every document in the corpus has a disposition, and it is the right one ─────

func TestTheEditLogGateCoversEveryDocumentInTheCorpus(t *testing.T) {
	corpus := editLogCorpus()

	byPath := map[string]editLogDocument{}
	for _, document := range corpus {
		if _, duplicate := byPath[document.path]; duplicate {
			t.Fatalf("%s is in the corpus table twice", document.path)
		}
		byPath[document.path] = document
		if document.path != "SPEC-LEDGER.md" && !strings.HasPrefix(document.path, "docs/specs/") {
			t.Errorf("%s is neither SPEC-LEDGER.md nor a document under docs/specs/", document.path)
		}
		if _, err := os.Stat(document.path); err != nil {
			t.Errorf("the corpus table names %s, which is not in the tree: %v", document.path, err)
		}
	}

	// Direction 2: every document under docs/specs/ is in the table. A spec document that
	// arrives without a row is a document this gate silently does not hold.
	onDisk, err := filepath.Glob(editLogSpecGlob)
	if err != nil {
		t.Fatalf("globbing %s: %v", editLogSpecGlob, err)
	}
	editLogMustHaveRead(t, "documents under "+editLogSpecGlob, len(onDisk))
	for _, path := range onDisk {
		path = filepath.ToSlash(path)
		if _, held := byPath[path]; !held {
			t.Errorf("%s is under docs/specs/ and has NO row in the corpus table: it states an "+
				"edit-log rule that nothing checks, or it states none and nothing says so", path)
		}
	}

	// Each row's own claim, asserted against the document.
	withLog, withoutLog := 0, 0
	for _, document := range corpus {
		content := readDocument(t, document.path)
		switch document.rule {
		case ruleNoLogOfItsOwn:
			withoutLog++
			if match := editLogHeadingPattern.FindString(content); match != "" {
				t.Errorf("%s is dispositioned %q but carries the heading %q: it HAS a log and this "+
					"gate is not holding it to one", document.path, document.why, strings.TrimSpace(match))
			}
		default:
			withLog++
			if document.heading == "" {
				t.Errorf("%s carries a log rule and no heading to locate it by", document.path)
				continue
			}
			// The positive control for the absence query above, in the same query: the documents
			// that DO have a log match the same pattern.
			if !editLogHeadingPattern.MatchString(content) {
				t.Errorf("%s carries a log rule but the heading pattern matches nothing in it, so "+
					"the absence answered for the ruleNoLogOfItsOwn documents is not evidence of "+
					"anything", document.path)
			}
			if strings.Count(content, "\n"+document.heading+"\n") != 1 {
				t.Errorf("%s: the heading %q appears %d times; the region this gate reads is the one "+
					"between a heading and the next, and two of them make it ambiguous",
					document.path, document.heading, strings.Count(content, "\n"+document.heading+"\n"))
				continue
			}
			entries := editLogEntries(t, document, content)
			if len(entries) == 0 {
				t.Errorf("%s: the log region holds no line matching %v, so every 'this commit added "+
					"no entry' below would be an artefact of the pattern", document.path, document.entry)
				continue
			}
			t.Logf("%s: %d entries, newest %q", document.path, len(entries),
				trimForLog(entries[len(entries)-1]))
		}
	}
	editLogMustHaveRead(t, "documents holding a log", withLog)
	editLogMustHaveRead(t, "documents dispositioned as holding none", withoutLog)

	// The plans hold no log of their own — asserted, with the specs that do as the control in
	// the same query rather than in a sentence.
	plans, err := filepath.Glob(editLogPlanGlob)
	if err != nil {
		t.Fatalf("globbing %s: %v", editLogPlanGlob, err)
	}
	editLogMustHaveRead(t, "plans under "+editLogPlanGlob, len(plans))
	for _, path := range plans {
		if match := editLogHeadingPattern.FindString(readDocument(t, path)); match != "" {
			t.Errorf("%s carries %q: a plan with its own log, which this gate holds nobody to. "+
				"Give it a corpus row or take the heading out", filepath.ToSlash(path), strings.TrimSpace(match))
		}
	}
}

func trimForLog(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 96 {
		return text[:96] + "…"
	}
	return text
}

// ── check 2: every commit that changed a document appended to that document's log ────────

func TestTheEditLogGateHoldsEveryCommitToTheDocumentsOwnLog(t *testing.T) {
	requireWholeHistory(t)

	// The map, keyed and validated once, so both directions are answered off the same table.
	type key struct{ doc, commit string }
	dispositions := map[key]editLogDisposition{}
	for _, disposition := range editLogDispositions() {
		resolved := shortHash(t, disposition.commit)
		if resolved != disposition.commit {
			t.Errorf("disposition %s/%s: this history abbreviates that commit as %s; the table and "+
				"the log citation have to name the same string",
				disposition.doc, disposition.commit, resolved)
		}
		if strings.TrimSpace(disposition.why) == "" {
			t.Errorf("disposition %s/%s carries no reason", disposition.doc, disposition.commit)
		}
		entry := key{disposition.doc, disposition.commit}
		if _, duplicate := dispositions[entry]; duplicate {
			t.Errorf("disposition %s/%s appears twice", disposition.doc, disposition.commit)
		}
		dispositions[entry] = disposition
	}

	used := map[key]bool{}
	read, delinquent := 0, 0
	for _, document := range editLogCorpus() {
		if document.rule != ruleOwnEntryPerCommit {
			continue
		}
		content := readDocument(t, document.path)
		region := strings.Join(editLogEntriesRegionText(t, document, content), "\n")
		entries := editLogEntries(t, document, content)
		commits := commitsTouching(t, document.path)
		editLogMustHaveRead(t, "commits touching "+document.path, len(commits))
		read += len(commits)

		for _, commit := range commits {
			if editLogEntriesAdded(t, document, commit, true) > 0 {
				if disposition, listed := dispositions[key{document.path, commit}]; listed {
					used[key{document.path, commit}] = true
					t.Errorf("%s: commit %s APPENDED an entry and is dispositioned %q anyway. A row "+
						"nothing needs is how a narrowing stops tracking what it narrows",
						document.path, commit, disposition.why)
				}
				continue
			}
			delinquent++
			disposition, listed := dispositions[key{document.path, commit}]
			if !listed {
				t.Errorf("%s: commit %s changed the document and appended NO entry to its log. "+
					"The document's own rule is %s. Append the entry, or add the commit to "+
					"editLogDispositions with the kind that says why it owes none",
					document.path, commit, document.why)
				continue
			}
			used[key{document.path, commit}] = true

			switch disposition.kind {
			case backfilledInTheLog:
				if !strings.Contains(region, commit) {
					t.Errorf("%s: commit %s is dispositioned %s (%q) and the log region does not "+
						"CITE it. The entry that pays a debt names what it pays, or the claim "+
						"cannot be audited from the document", document.path, commit, disposition.kind, disposition.why)
				}
			case createdTheDocument:
				if first := commits[0]; commit != first {
					t.Errorf("%s: commit %s is dispositioned %s but the first commit to touch the "+
						"document is %s", document.path, commit, disposition.kind, first)
				}
				if !document.numbered {
					t.Errorf("%s: %s needs the log's entries to be numbered and this document's "+
						"are not", document.path, disposition.kind)
					break
				}
				number := document.entry.FindStringSubmatch(entries[0])
				if number == nil || number[1] != "2" {
					t.Errorf("%s: commit %s is dispositioned %s, which claims the creating commit "+
						"is revision 1 — but the log's first entry is %q and not entry 2",
						document.path, commit, disposition.kind, trimForLog(entries[0]))
				}
			case debtRecordedNotPaid:
				requireAncestorOfBaseline(t, document.path, commit)
			default:
				t.Errorf("%s: commit %s carries an unknown disposition kind %v", document.path, commit, disposition.kind)
			}
		}
	}

	// Direction 2, the rest of it: a row for a commit that never touched that document at all.
	for entry, disposition := range dispositions {
		if !used[entry] {
			t.Errorf("disposition %s/%s (%s, %q) was never needed: that commit does not appear in "+
				"the history of that document", disposition.doc, disposition.commit, disposition.kind, disposition.why)
		}
	}

	editLogMustHaveRead(t, "document commits held to the rule", read)
	editLogMustHaveRead(t, "commits that appended nothing and are dispositioned", delinquent)
}

// The text of the log region as it stands in the working tree, which is what a backfill
// citation is asserted against.
func editLogEntriesRegionText(t *testing.T, document editLogDocument, content string) []string {
	t.Helper()
	start, end, found := editLogRegion(document, content)
	if !found {
		t.Fatalf("%s: no log region", document.path)
	}
	lines := strings.Split(content, "\n")
	if end > len(lines) {
		end = len(lines)
	}
	return lines[start-1 : end]
}

func requireAncestorOfBaseline(t *testing.T, subject string, commit string) {
	t.Helper()
	command := exec.Command(gitCommand(t), "merge-base", "--is-ancestor", commit, editLogGateBaseline)
	if err := command.Run(); err != nil {
		t.Errorf("%s: commit %s is dispositioned debtRecordedNotPaid, which only the history BEFORE "+
			"the baseline %s may take, and it is not an ancestor of it (%v). A debt this gate was "+
			"written to stop cannot be filed as a debt it inherited", subject, commit, editLogGateBaseline, err)
	}
}

// ── check 3: every commit that changed a spec appended to the ledger's own log ───────────

func TestTheEditLogGateHoldsEverySpecCommitToALedgerEntry(t *testing.T) {
	requireWholeHistory(t)

	var ledger editLogDocument
	triggers := []string{editLogPlanGlob}
	for _, document := range editLogCorpus() {
		switch document.rule {
		case ruleEntryWhenASpecChanges:
			if ledger.path != "" {
				t.Fatalf("two documents claim to be the log for the others: %s and %s", ledger.path, document.path)
			}
			ledger = document
		case ruleOwnEntryPerCommit:
			triggers = append(triggers, document.path)
		}
	}
	if ledger.path == "" {
		t.Fatal("no document in the corpus carries the rule that every spec commit appends to it")
	}

	debt := map[string]bool{}
	for _, commit := range editLogLedgerDebt() {
		if resolved := shortHash(t, commit); resolved != commit {
			t.Errorf("the recorded ledger debt names %s; this history abbreviates it as %s", commit, resolved)
		}
		if debt[commit] {
			t.Errorf("the recorded ledger debt names %s twice", commit)
		}
		debt[commit] = true
	}

	paid := map[string]bool{}
	commits := commitsTouching(t, triggers...)
	editLogMustHaveRead(t, "commits that changed a spec or a plan", len(commits))
	delinquent := 0
	for _, commit := range commits {
		if editLogEntriesAdded(t, ledger, commit, true) > 0 {
			if debt[commit] {
				t.Errorf("%s: commit %s appended a §7 entry and is recorded as debt anyway", ledger.path, commit)
			}
			paid[commit] = true
			continue
		}
		delinquent++
		if !debt[commit] {
			t.Errorf("%s: commit %s changed a spec or a plan and appended NO entry to §7. The "+
				"ledger's own rule is %s", ledger.path, commit, ledger.why)
			continue
		}
		requireAncestorOfBaseline(t, ledger.path, commit)
	}
	for commit := range debt {
		if !paid[commit] && !containsCommit(commits, commit) {
			t.Errorf("the recorded ledger debt names %s, which did not change a spec or a plan at "+
				"all: a row nothing needs", commit)
		}
	}
	editLogMustHaveRead(t, "spec-or-plan commits that appended no §7 entry", delinquent)
	t.Logf("%s: %d of %d spec-or-plan commits appended an entry; %d are recorded debt, all before %s",
		ledger.path, len(paid), len(commits), delinquent, editLogGateBaseline)
}

func containsCommit(commits []string, wanted string) bool {
	for _, commit := range commits {
		if commit == wanted {
			return true
		}
	}
	return false
}

// ── check 4: the arm that fires BEFORE the commit exists ─────────────────────────────────

// The landed arms above can only find a skipped entry after it has been pushed. This one runs
// against the working tree, so it goes red while the edit is still in the author's hands, which
// is the half that would have caught 21f22c7 and 5210f09 on the day. A gate is judged by what it
// catches and WHEN; early and partial beats late and complete.
func TestTheEditLogGateHoldsAPendingEditToItsEntry(t *testing.T) {
	requireWholeHistory(t)

	var ledger editLogDocument
	for _, document := range editLogCorpus() {
		if document.rule == ruleEntryWhenASpecChanges {
			ledger = document
		}
	}

	pending := []string{}
	for _, document := range editLogCorpus() {
		if document.rule != ruleOwnEntryPerCommit {
			continue
		}
		diff := gitOutput(t, "diff", "--no-color", "--unified=0", "HEAD", "--", document.path)
		if strings.TrimSpace(diff) == "" {
			continue
		}
		pending = append(pending, document.path)
		if pendingEntriesAdded(t, document, diff) == 0 {
			t.Errorf("%s has UNCOMMITTED changes and the working tree adds no entry to its log. "+
				"%s Append it before the commit, not after the review", document.path, document.why)
		}
	}
	if len(pending) == 0 {
		t.Log("no uncommitted change to a document that carries a log; this arm is the one that " +
			"fires during an edit and there is none in this tree")
		return
	}
	t.Logf("pending edits: %v", pending)

	diff := gitOutput(t, "diff", "--no-color", "--unified=0", "HEAD", "--", ledger.path)
	if pendingEntriesAdded(t, ledger, diff) == 0 {
		t.Errorf("%v changed in the working tree and %s gains no §7 entry. %s",
			pending, ledger.path, ledger.why)
	}
}

// The same region rule as the landed arm, against the working tree's own copy of the document.
func pendingEntriesAdded(t *testing.T, document editLogDocument, diff string) int {
	t.Helper()
	start, end, found := editLogRegion(document, readDocument(t, document.path))
	if !found {
		t.Fatalf("%s: no log region in the working tree", document.path)
	}
	count := 0
	line := 0
	for _, text := range strings.Split(strings.ReplaceAll(diff, "\r", ""), "\n") {
		switch {
		case strings.HasPrefix(text, "@@"):
			line = hunkStart(t, "working tree", text)
		case strings.HasPrefix(text, "+++"), strings.HasPrefix(text, "---"):
		case strings.HasPrefix(text, "+"):
			if line >= start && line <= end && document.entry.MatchString(text[1:]) {
				count++
			}
			line++
		case strings.HasPrefix(text, "-"):
		default:
			if line > 0 {
				line++
			}
		}
	}
	return count
}

// ── check 5: the detector itself, held to commits whose answer is known ──────────────────

// The permanent positive control. Every "this commit appended nothing" above is an ABSENCE, and
// an absence is worth what the query that produced it is worth: a pattern that stopped matching
// would turn this whole file into a gate that reports clean having read nothing — which is the
// failure mode the repository's .gitattributes, deps_test.go and planlint_test.go each carry
// their own paragraph about.
//
// So the detector is pinned against commits whose answer is known by hand, in both directions,
// and the last row pins the MECHANISM rather than the pattern: 3bc0603 added 32 lines matching
// Spec C's entry pattern and not one of them is an edit-log row. Scoped it reads 0. Unscoped it
// reads 32. Take the region out and this assertion fails before the disposition table does.
func TestTheEditLogGateStillDetectsWhatPaidAndWhatDidNot(t *testing.T) {
	requireWholeHistory(t)

	corpus := map[string]editLogDocument{}
	for _, document := range editLogCorpus() {
		corpus[document.path] = document
	}
	const (
		specA  = "docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md"
		specB  = "docs/specs/2026-08-12-spec-b-message-server-operator.md"
		specC  = "docs/specs/2026-08-12-spec-c-windows-client-ui.md"
		ledger = "SPEC-LEDGER.md"
	)
	for _, control := range []struct {
		doc    string
		commit string
		paid   bool
		what   string
	}{
		{specB, "d2e7a51", true, "added Revision 21 to Spec B's log"},
		{specB, "5210f09", false, "carried ruling 27 into Spec B §5.4 and appended nothing"},
		{specA, "4b465ae", true, "added row A-27 to Spec A §0.6"},
		{specA, "a401b9b", false, "rewrote Spec A's GroupHandle block and appended no row"},
		{specC, "ad355c6", true, "added Rev 6 to Spec C §0.6"},
		{specC, "21f22c7", false, "amended Spec C §9.6's comparison tuple and appended no row"},
		{ledger, "5210f09", true, "appended a §7 entry"},
		{ledger, "368ef8d", false, "changed Spec A and Spec C and appended no §7 entry"},
	} {
		document, held := corpus[control.doc]
		if !held {
			t.Fatalf("the control names %s, which is not in the corpus table", control.doc)
		}
		added := editLogEntriesAdded(t, document, control.commit, true)
		if (added > 0) != control.paid {
			t.Errorf("control %s/%s (%s): the detector answers %d entries added, expected %s",
				control.doc, control.commit, control.what, added,
				map[bool]string{true: "at least one", false: "none"}[control.paid])
		}
	}

	// The mechanism, not the pattern.
	scoped := editLogEntriesAdded(t, corpus[specC], "3bc0603", true)
	unscoped := editLogEntriesAdded(t, corpus[specC], "3bc0603", false)
	if scoped != 0 {
		t.Errorf("3bc0603 created Spec C with an empty log and the scoped detector reads %d entries", scoped)
	}
	if unscoped < 20 {
		t.Errorf("3bc0603 adds %d lines matching Spec C's entry pattern outside the log region; this "+
			"control asserts that dropping the region scoping CHANGES the answer, and at %d it no "+
			"longer does", unscoped, unscoped)
	}
	t.Logf("region scoping is load-bearing: 3bc0603 reads %d entries scoped and %d unscoped", scoped, unscoped)
}

// ── check 6: the invocation ──────────────────────────────────────────────────────────────

func TestTheEditLogGateRunsUnderTheInvocationThisFileDocuments(t *testing.T) {
	source := readDocument(t, editLogGateSource)
	declared := regexp.MustCompile(`(?m)^func (Test\w+)\(`).FindAllStringSubmatch(source, -1)
	editLogMustHaveRead(t, "tests declared in "+editLogGateSource, len(declared))
	for _, match := range declared {
		if !strings.HasPrefix(match[1], editLogRunPrefix) {
			t.Errorf("%s does not begin with %q, so `go test ./ -run %s` — the command this file "+
				"documents and the ledger prints — does not run it",
				match[1], editLogRunPrefix, editLogRunPrefix)
		}
	}
}
