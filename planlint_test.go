// The plan linter: the four defect classes this project has actually shipped in its plans,
// checked over docs/plans/*.md by the test suite rather than by the review after.
//
// Why this is a test and not a review checklist. Thirteen documents, 61,000 lines, and every
// one of them written to the same rigid shape — Files, Interfaces (Consumes/Produces),
// Properties, Mutations. Four defect classes have recurred across them, and every time the
// finding came from a human reading the document after it landed:
//
//  1. a property with no mutation that would make it fail — the test that cannot fail, one
//     layer up. Roughly thirty of those shipped in p1-p8 as plan-supplied tests, and four
//     unsatisfiable properties shipped in s1;
//  2. a property deriving a class that has no member at its own task, which either fatals on
//     arrival (this tree's gates fatal on an empty derived class rather than reporting clean
//     over one) or passes vacuously. Four instances in m1 before the 2026-09-05 repair, a
//     fifth introduced by that repair, and two of the three relocations it made never landed
//     at their destinations;
//  3. a cross-reference that does not resolve — a Task, an M1-n item, a ledger item or another
//     plan that is not there;
//  4. a Consumes entry naming something no earlier task Produces and no external leg supplies.
//     Two plans here dispatched tasks that could not compile for exactly this reason.
//
// The 2026-09-05 repair is the argument for the file. It swept m1 for class 2, introduced a
// fifth instance of class 2 in the very task it rewrote, and left two of its own relocations
// unlanded — because the sweep was prose and the check came afterwards from someone else. A
// sweep that cannot check its own output ships its own defect class.
//
// # What this linter cannot see, and which half is still the author's
//
// It reads structure and resolves names. It decides nothing about meaning. Specifically:
//
//   - It cannot decide whether a derived class is SEMANTICALLY DECIDABLE. "every package-level
//     function returning a 32-octet secret" and "every function returning a pq_secret" are the
//     same sentence to this file; neither is readable off a Go signature when the functions
//     return []byte, and the linter cannot tell you that. It checks only that a class-deriving
//     property states its membership somewhere, and that any relocation the membership forces
//     actually landed.
//   - It cannot tell a true claim from a false one. "stagedRef being unexported confines every
//     GroupEngine implementation to package connect/message" is false as a matter of Go
//     semantics, in six places, and every one of those six resolves, counts and
//     cross-references perfectly.
//   - It cannot decide that a stated mutation would actually refute the property beside it. It
//     checks that mutations exist, and — where a document links them to properties by name, as
//     s1 does and m1 does not — that every property is named by one.
//   - It does not resolve spec section or spec line references (§5.6, "spec line 1233"). Those
//     have drifted on this project too; they are a fifth check and not this file's.
//   - It reads the documents, never the tree. "That class is empty at this task's commit" is
//     taken as the author's own measurement; the linter checks that a measurement was stated
//     and that the relocation it triggers landed, not that the number is right.
//
// # Reporting versus fatal
//
// A check that would fail widely on plans already committed lands REPORTING: it prints every
// finding and does not fail the suite. Each such check states, in the constant that sets its
// severity, exactly what turns it fatal. No check is weakened to make an old plan pass — the
// severity moves, the derived class does not.
//
// Every check fatals if its derived class is empty across the whole corpus. A gate reporting
// the clean run of a complete gate having read nothing is this project's most expensive
// failure mode; this file refuses to be an instance of it.
//
// This file imports nothing of this module and reads only its documents, so it adds no edge the
// dependency gate in deps_test.go has to account for. It carries no //urmsg:mayimport directive
// of its own: doc.go's is the root package's one directive and this file is part of that package.
package messageserver

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// ── the corpus, and how a plan is taken apart ───────────────────────────────────────────────

// Where the plans live. A glob rather than a list: a plan added tomorrow is linted tomorrow,
// which is the whole difference between this file and a review checklist.
const planGlob = "docs/plans/*.md"

// The ledger the plans cite by item number.
const ledgerPath = "SPEC-LEDGER.md"

// One plan document, split into lines with the line endings normalised. Normalised because
// core.autocrlf is true at system scope on the Windows boxes this repository is developed on,
// and a matcher that does not strip the carriage return matches nothing at all — which is how
// 84 source anchors on this project passed vacuously.
type planDocument struct {
	name         string // base file name, for messages
	token        string // the short plan token derived from the file name: p1..p8, s1, m1
	lines        []string
	tasks        []*planTask
	definedItems map[string]int // the ids this document DEFINES: M1-43, S1-9, O-5
}

// One task. The id is the heading's own: 9 and 9a are different tasks and the difference is
// load-bearing, because that is where m1's relocations were supposed to land.
type planTask struct {
	doc        *planDocument
	id         string
	title      string
	level      int
	ordinal    int
	start, end int // 1-based line numbers, inclusive
	properties []*planProperty
	mutations  []*planMutation
	consumes   []string
	produces   []string
	declares   []string
	body       string
}

// One stated property, and the lines it owns.
type planProperty struct {
	task       *planTask
	number     int
	start, end int
	text       string
}

// One stated mutation. refutes holds the property numbers the mutation's own text names, where
// the document states them — s1 writes "Property 1 must fail" and m1 writes nothing.
type planMutation struct {
	task    *planTask
	line    int
	text    string
	refutes []int
}

var (
	taskHeadingRe  = regexp.MustCompile(`^(#{2,6})[ \t]+Task[ \t]+([0-9]+)([a-z]?)\b[ \t]*(.*)$`)
	headingRe      = regexp.MustCompile(`^(#{1,6})[ \t]+`)
	propertyStart  = regexp.MustCompile(`\*\*Property[ \t]+([0-9]+)`)
	stepLineRe     = regexp.MustCompile(`^[ \t]*-[ \t]*\[[ xX]\][ \t]*\*\*Steps?\b`)
	numberedItemRe = regexp.MustCompile(`^[ \t]*([0-9]+)\.[ \t]+(\S.*)$`)
	consumesRe     = regexp.MustCompile(`^[ \t]*-[ \t]*Consumes\b[^:]*:?[ \t]*(.*)$`)
	producesRe     = regexp.MustCompile(`^[ \t]*-[ \t]*Produces\b[^:]*:?[ \t]*(.*)$`)
	planTokenRe    = regexp.MustCompile(`-((?:p|s|m)[0-9]+)-`)
	refutesRe      = regexp.MustCompile(`\bProperty[ \t]+([0-9]+)`)
	goTestFuncRe   = regexp.MustCompile(`\bfunc[ \t]+Test[A-Z]`)
	itemDefRe      = regexp.MustCompile(`\*\*((?:[A-Za-z]+[0-9]*-[0-9]+[a-z]?)|(?:O-[0-9]+))[ \t]*[—–-]`)
	itemRowDefRe   = regexp.MustCompile(`^\|[ \t]*((?:[A-Za-z]+[0-9]*-[0-9]+[a-z]?)|(?:O-[0-9]+))[ \t]*\|`)
	goFuncDeclRe   = regexp.MustCompile(`^func[ \t]+(?:\([^)]*\)[ \t]*)?([A-Za-z_]\w*)`)
	goTypeDeclRe   = regexp.MustCompile(`^(type|const|var)[ \t]+([A-Za-z_]\w*)`)
	backtickRe     = regexp.MustCompile("`([^`]+)`")
	identifierRe   = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]{2,}`)
)

// Reading the corpus. It is the input to every check below, so a failure here is a hard stop
// rather than a skipped check.
func readPlanCorpus(t *testing.T) []*planDocument {
	t.Helper()
	paths, err := filepath.Glob(planGlob)
	if err != nil {
		t.Fatalf("globbing %s: %v", planGlob, err)
	}
	if len(paths) == 0 {
		t.Fatalf("%s matched no document, so every check below would report clean having read nothing", planGlob)
	}
	slices.Sort(paths)
	docs := make([]*planDocument, 0, len(paths))
	for _, path := range paths {
		text, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		docs = append(docs, newPlanDocument(filepath.Base(path), string(text)))
	}
	return docs
}

// One document from its own text. The control fixture is built through this same constructor,
// so the fixture is read by the derivation the corpus is read by and not by a second one.
func newPlanDocument(name string, text string) *planDocument {
	doc := &planDocument{
		name:         name,
		lines:        strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"),
		definedItems: map[string]int{},
	}
	if match := planTokenRe.FindStringSubmatch(doc.name); match != nil {
		doc.token = match[1]
	}
	parseTasks(doc)
	parseDefinedItems(doc)
	return doc
}

// The tasks of one document, and the line range each owns. A task ends at the next heading of
// the same depth or shallower, which is the document's own outline saying where it ends.
func parseTasks(doc *planDocument) {
	for index, line := range doc.lines {
		match := taskHeadingRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		doc.tasks = append(doc.tasks, &planTask{
			doc:     doc,
			id:      match[2] + match[3],
			title:   strings.TrimSpace(strings.TrimLeft(match[4], ": \t")),
			level:   len(match[1]),
			ordinal: len(doc.tasks),
			start:   index + 1,
		})
	}
	for _, task := range doc.tasks {
		task.end = len(doc.lines)
		for line := task.start; line < len(doc.lines); line++ {
			match := headingRe.FindStringSubmatch(doc.lines[line])
			if match != nil && len(match[1]) <= task.level {
				task.end = line
				break
			}
		}
		task.body = strings.Join(doc.lines[task.start-1:min(task.end, len(doc.lines))], "\n")
		parseProperties(task)
		parseMutations(task)
		parseInterfaces(task)
	}
}

// The properties one task states. A property owns the lines from its own bold headline to the
// next property, the next step line, or the end of the task — whichever comes first.
func parseProperties(task *planTask) {
	starts, numbers := []int{}, []int{}
	for line := task.start; line <= task.end && line <= len(task.doc.lines); line++ {
		match := propertyStart.FindStringSubmatch(task.doc.lines[line-1])
		if match == nil {
			continue
		}
		number, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		// A property number already stated in this task is a back-reference, not a second
		// statement of it.
		if slices.Contains(numbers, number) {
			continue
		}
		starts, numbers = append(starts, line), append(numbers, number)
	}
	for i, start := range starts {
		end := task.end
		if i+1 < len(starts) {
			end = starts[i+1] - 1
		}
		for line := start + 1; line <= end && line <= len(task.doc.lines); line++ {
			if stepLineRe.MatchString(task.doc.lines[line-1]) {
				end = line - 1
				break
			}
		}
		task.properties = append(task.properties, &planProperty{
			task:   task,
			number: numbers[i],
			start:  start,
			end:    end,
			text:   strings.Join(task.doc.lines[start-1:min(end, len(task.doc.lines))], "\n"),
		})
	}
}

// The mutations one task states. Two shapes, both in use: a numbered list under a mutation
// step, and — where a task's steps are collapsed — a semicolon-separated clause list after
// "with mutations including:". Both are read off the document; neither is a list kept here.
func parseMutations(task *planTask) {
	for line := task.start; line <= task.end && line <= len(task.doc.lines); line++ {
		text := task.doc.lines[line-1]
		if !stepLineRe.MatchString(text) || !strings.Contains(strings.ToLower(text), "mutation") {
			continue
		}
		blockEnd := task.end
		for scan := line + 1; scan <= task.end && scan <= len(task.doc.lines); scan++ {
			if stepLineRe.MatchString(task.doc.lines[scan-1]) {
				blockEnd = scan - 1
				break
			}
		}
		found := false
		for scan := line; scan <= blockEnd && scan <= len(task.doc.lines); scan++ {
			match := numberedItemRe.FindStringSubmatch(task.doc.lines[scan-1])
			if match == nil {
				continue
			}
			found = true
			body := match[2]
			for follow := scan + 1; follow <= blockEnd && follow <= len(task.doc.lines); follow++ {
				next := task.doc.lines[follow-1]
				if strings.TrimSpace(next) == "" || numberedItemRe.MatchString(next) || stepLineRe.MatchString(next) {
					break
				}
				body += " " + strings.TrimSpace(next)
			}
			task.mutations = append(task.mutations, newMutation(task, scan, body))
		}
		if found {
			continue
		}
		whole := strings.Join(task.doc.lines[line-1:min(blockEnd, len(task.doc.lines))], " ")
		lowered := strings.ToLower(whole)
		index := strings.Index(lowered, "mutations including:")
		if index < 0 {
			continue
		}
		for _, clause := range strings.Split(whole[index+len("mutations including:"):], ";") {
			clause = strings.TrimSpace(strings.Trim(strings.TrimSpace(clause), ".)"))
			if clause == "" {
				continue
			}
			task.mutations = append(task.mutations, newMutation(task, line, clause))
		}
	}
}

func newMutation(task *planTask, line int, body string) *planMutation {
	mutation := &planMutation{task: task, line: line, text: body}
	for _, match := range refutesRe.FindAllStringSubmatch(body, -1) {
		number, err := strconv.Atoi(match[1])
		if err == nil && !slices.Contains(mutation.refutes, number) {
			mutation.refutes = append(mutation.refutes, number)
		}
	}
	return mutation
}

// The Consumes and Produces entries of one task, as whole clauses. Entries are read as text
// because the documents write them as text; the checks below extract what they can decide from
// them rather than pretending the clause is a grammar.
func parseInterfaces(task *planTask) {
	collect := func(re *regexp.Regexp) (clauses []string, raw []string) {
		clauses, raw = []string{}, []string{}
		for line := task.start; line <= task.end && line <= len(task.doc.lines); line++ {
			match := re.FindStringSubmatch(task.doc.lines[line-1])
			if match == nil {
				continue
			}
			body, inFence := match[1], false
			raw = append(raw, match[1])
			for follow := line + 1; follow <= task.end && follow <= len(task.doc.lines); follow++ {
				next := task.doc.lines[follow-1]
				if strings.HasPrefix(strings.TrimSpace(next), "```") {
					inFence = !inFence
					continue
				}
				if !inFence {
					trimmed := strings.TrimSpace(next)
					if trimmed == "" || strings.HasPrefix(trimmed, "- ") || stepLineRe.MatchString(next) || headingRe.MatchString(next) {
						break
					}
				}
				body += " " + strings.TrimSpace(next)
				raw = append(raw, next)
			}
			clauses = append(clauses, body)
		}
		return clauses, raw
	}
	task.consumes, _ = collect(consumesRe)
	var producesRaw []string
	task.produces, producesRaw = collect(producesRe)
	task.declares = declaredNames(producesRaw)
}

// The names a Produces block DECLARES, as opposed to the names it mentions. A declaration is a
// Go declaration line inside the block's fence, or a bare backticked identifier in its prose —
// the two shapes the plans use. Parameter names, result types and prose are deliberately not
// declarations: check 4 asks whether a consumed name was produced, and a producer set that
// swallowed "error" and "[]byte" would answer yes to everything.
func declaredNames(lines []string) []string {
	out := []string{}
	add := func(name string) {
		if name == "" || slices.Contains(out, name) {
			return
		}
		out = append(out, name)
	}
	for _, line := range lines {
		text := strings.TrimSpace(line)
		if match := goFuncDeclRe.FindStringSubmatch(text); match != nil {
			add(match[1])
			continue
		}
		if match := goTypeDeclRe.FindStringSubmatch(text); match != nil {
			add(match[2])
			continue
		}
		for _, span := range backtickRe.FindAllStringSubmatch(text, -1) {
			for _, token := range identifierRe.FindAllString(span[1], -1) {
				add(token)
			}
		}
	}
	return out
}

// The item ids one document defines. Two shapes, both in the corpus: bold-and-dash in a prose
// section — "**M1-43 —", "**O-5 —", "**S1-9 —" — and a leading table cell, which is how the
// interface registry writes its ten reconciliation decisions. Reading only the first shape is
// how a check that resolves references convicts a document for citing what it defines.
func parseDefinedItems(doc *planDocument) {
	define := func(id string, line int) {
		id = strings.ToUpper(id)
		if _, seen := doc.definedItems[id]; !seen {
			doc.definedItems[id] = line
		}
	}
	for index, line := range doc.lines {
		for _, match := range itemDefRe.FindAllStringSubmatch(line, -1) {
			define(match[1], index+1)
		}
		if match := itemRowDefRe.FindStringSubmatch(line); match != nil {
			define(match[1], index+1)
		}
	}
}

// ── findings, and the two severities ────────────────────────────────────────────────────────

type finding struct {
	doc  string
	line int
	what string
}

func (self finding) String() string {
	return fmt.Sprintf("%s:%d: %s", self.doc, self.line, self.what)
}

// A check lands reporting when it would fail widely on plans already committed. whenFatal is
// not a promise to a future reader that something will happen; it is the condition, written
// down, under which the severity constant beside the check changes.
func report(t *testing.T, subject string, findings []finding, fatal bool, whenFatal string) {
	t.Helper()
	slices.SortFunc(findings, func(a, b finding) int {
		if a.doc != b.doc {
			return strings.Compare(a.doc, b.doc)
		}
		return a.line - b.line
	})
	if len(findings) == 0 {
		t.Logf("%s: no findings", subject)
		return
	}
	lines := make([]string, 0, len(findings))
	for _, item := range findings {
		lines = append(lines, "  "+item.String())
	}
	body := fmt.Sprintf("%s: %d finding(s)\n%s", subject, len(findings), strings.Join(lines, "\n"))
	if fatal {
		t.Errorf("%s", body)
		return
	}
	t.Logf("%s\n  REPORTING, not failing. Turns fatal when: %s", body, whenFatal)
}

// The guard against the failure mode this file exists to prevent. A check whose derived class
// is empty across the whole corpus has read nothing, and a clean run of it means nothing.
func mustHaveRead(t *testing.T, subject string, count int) {
	t.Helper()
	if count == 0 {
		t.Fatalf("%s derived an empty class over the whole corpus, so a clean run of it would report clean having read nothing", subject)
	}
}

func allTasks(docs []*planDocument) []*planTask {
	out := []*planTask{}
	for _, doc := range docs {
		out = append(out, doc.tasks...)
	}
	return out
}

// ── check 1: a property with no mutation that would make it fail ─────────────────────────────

// The severities of check 1, and what moves them.
//
// 1a is fatal everywhere: a task that states properties and no mutation set at all has stated
// properties nothing would refute, which is R1's whole subject one layer up. It had a member in
// this corpus — m1 Task 16, four properties and no mutation step — and it is fatal rather than
// reporting because one finding in one plan is not "widely".
//
// 1b is decidable only inside the convention that makes it decidable, and the convention is
// derived rather than assumed: a document links mutations to properties when at least half of
// its mutations name the property they refute ("Property 1 must fail", which is how s1 writes
// every one of them and how m1 writes none). Inside such a document, a property no mutation
// names is a property that document itself claims to have covered and did not. It REPORTS
// today for one reason and one only: seven such properties sit in s1, a landed plan this pass
// is not authorised to edit, and a check that fails the suite on another plan's defect stops
// the suite rather than the defect. It turns fatal the day s1's seven are closed — the class is
// not narrowed to get there, and the seven are named in the output so they cannot be lost.
//
// 1c reports, one line per document, that a document states no linkage at all. That is not a
// defect in a document written to m1's convention; it is the statement of which half of check 1
// no machine can do for that document. It turns fatal when m1's mutation sets are written in
// s1's shape.
const (
	check1aFatal = true
	check1bFatal = false
	check1cFatal = false
)

// The share of a document's mutations that must name a property before the document counts as
// having the linkage convention. A half rather than one: m1 has exactly one mutation naming a
// property out of 107, and reading that as a convention would convict every property in the
// task it sits in.
const linkageConventionShare = 2

func TestEveryStatedPropertyHasAStatedMutation(t *testing.T) {
	docs := readPlanCorpus(t)
	properties := 0
	for _, task := range allTasks(docs) {
		properties += len(task.properties)
	}
	mustHaveRead(t, "the property class", properties)

	noMutations, unlinked, unstated := []finding{}, []finding{}, []finding{}
	for _, doc := range docs {
		linking := documentLinksMutationsToProperties(doc)
		stated := false
		for _, task := range doc.tasks {
			if len(task.properties) == 0 {
				continue
			}
			stated = true
			if len(task.mutations) == 0 {
				numbers := []string{}
				for _, property := range task.properties {
					numbers = append(numbers, strconv.Itoa(property.number))
				}
				noMutations = append(noMutations, finding{doc.name, task.start,
					fmt.Sprintf("Task %s states %d properties (%s) and no mutation at all, so nothing stated would make any of them fail",
						task.id, len(task.properties), strings.Join(numbers, ", "))})
				continue
			}
			if !linking {
				continue
			}
			named := []int{}
			for _, mutation := range task.mutations {
				named = append(named, mutation.refutes...)
			}
			for _, property := range task.properties {
				if slices.Contains(named, property.number) {
					continue
				}
				unlinked = append(unlinked, finding{doc.name, property.start,
					fmt.Sprintf("Task %s Property %d is named by no mutation, in a document whose mutations name the property each refutes",
						task.id, property.number)})
			}
		}
		if stated && !linking {
			unstated = append(unstated, finding{doc.name, 1,
				"this document states properties and mutations and links none of them, so which property each mutation refutes is stated nowhere a machine can read; check 1b cannot run here and that half stays the author's"})
		}
	}
	report(t, "check 1a — a task states properties and no mutation", noMutations, check1aFatal, "never; it is fatal")
	report(t, "check 1b — a property no mutation names, in a document that links mutations to properties", unlinked, check1bFatal,
		"s1's seven unlinked properties are closed by s1's own owner; the check is fatal-ready and only another plan's findings keep it reporting")
	report(t, "check 1c — a document that links no mutation to any property", unstated, check1cFatal,
		"m1's mutation sets are rewritten in s1's shape, naming the property each mutation refutes")
}

// Whether a document writes the linkage down. Derived from the document's own mutations, so a
// plan that adopts the convention is held to it the day it adopts it.
func documentLinksMutationsToProperties(doc *planDocument) bool {
	total, linked := 0, 0
	for _, task := range doc.tasks {
		for _, mutation := range task.mutations {
			total++
			if len(mutation.refutes) > 0 {
				linked++
			}
		}
	}
	return total > 0 && linked*linkageConventionShare >= total
}

// The same defect one layer up, and the one this project actually paid for: a task that hands
// the implementer a finished test and states no mutation that would make it fail. Roughly thirty
// of those shipped in p1-p8.
//
// Reporting for a document that states no properties at all, because p1-p8 are written to a
// five-step shape that has no mutation step and re-cutting them is not this file's business.
// Fatal for a document that DOES state properties, because that document has adopted the shape
// and a task inside it that supplies a test instead is a regression against its own convention.
// The severity is derived from the document, not written down per plan.
func TestNoTaskSuppliesATestWithNoMutationThatWouldRefuteIt(t *testing.T) {
	docs := readPlanCorpus(t)
	supplied, fatalFindings, reportedFindings := 0, []finding{}, []finding{}
	for _, doc := range docs {
		documentStatesProperties := false
		for _, task := range doc.tasks {
			if len(task.properties) > 0 {
				documentStatesProperties = true
				break
			}
		}
		for _, task := range doc.tasks {
			if !goTestInAFence(task) {
				continue
			}
			supplied++
			if len(task.mutations) > 0 {
				continue
			}
			item := finding{doc.name, task.start,
				fmt.Sprintf("Task %s supplies a Go test and states no mutation that would make it fail", task.id)}
			if documentStatesProperties {
				fatalFindings = append(fatalFindings, item)
				continue
			}
			reportedFindings = append(reportedFindings, item)
		}
	}
	mustHaveRead(t, "the plan-supplied-test class", supplied)
	report(t, "check 1d — a plan-supplied test with no mutation set, in a plan that states properties", fatalFindings, true, "never; it is fatal")
	report(t, "check 1d — a plan-supplied test with no mutation set, in a plan that states no properties", reportedFindings, false,
		"p1-p8 are re-cut to the property-and-mutation shape; until then their five-step tasks have no mutation step by construction and failing on them would be failing on style")
}

// A task supplies a test when a fenced Go block inside it declares one.
func goTestInAFence(task *planTask) bool {
	inFence := false
	for line := task.start; line <= task.end && line <= len(task.doc.lines); line++ {
		text := task.doc.lines[line-1]
		if strings.HasPrefix(strings.TrimSpace(text), "```") {
			inFence = !inFence
			continue
		}
		if inFence && goTestFuncRe.MatchString(text) {
			return true
		}
	}
	return false
}

// ── check 2: a property deriving a class that is empty at its own task ───────────────────────

var (
	// A property derives a class when it says so. Every phrasing below is the corpus's own:
	// "The scope question (R3a): derive the class of ...", "derived off the tree", "over the
	// class every function whose name begins with Verify", "a derived-class gate".
	derivesClassRe = regexp.MustCompile(`(?i)\bclass\b`)
	derivationRe   = regexp.MustCompile(`(?i)(deriv|off the tree|syntax tree|scope question|read off the)`)
	// A membership claim: the class, a copula, and a count. The copula is what separates "the
	// class is two members" from "a gate that fatals on an empty class" — the second is a
	// statement about the gate's behaviour and says nothing about how many members this class
	// has, and reading it as a count is how a property with no membership at all passes.
	membershipClaimRe = regexp.MustCompile(`(?i)\b(?:that|this|the|its|whose)?[ ]*(?:derived[ ]+)?class[ ]+(?:now[ ]+|today[ ]+|first[ ]+)?(?:is|has|holds|contains|was|had)[ ]+(?:\*\*)?(?:exactly[ ]+|only[ ]+|about[ ]+|at[ ]+least[ ]+)?(?:\*\*)?(empty|none|no[ ]+members?|zero|a[ ]+members?|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|[0-9]+)\b`)
	emptyCountRe      = regexp.MustCompile(`(?i)^(empty|none|no[ ]+members?|zero|0)$`)
	// Where a relocated half is sent. The verb is required: a property that merely mentions
	// another task is not relocating anything to it, and m1 Task 9 Property 2 mentions three.
	relocationVerbRe = regexp.MustCompile(`(?i)\b(moves? to|moved to|belongs (?:in|to)|lands? (?:in|at)|deferred to|is held by|is[ ]+(?:\*\*)?Task)`)
	taskRefRe        = regexp.MustCompile(`\bTasks?[ ]+(?:\*\*)?([0-9]+[a-z]?)`)
	propertyRefRe    = regexp.MustCompile(`\bTask[ ]+(?:\*\*)?([0-9]+[a-z]?)(?:\*\*)?(?:'s|’s)?[ ,]+(?:\*\*)?Propert(?:y|ies)[ ]+([0-9]+)`)
	itsPropertyRe    = regexp.MustCompile(`(?i)\bits[ ]+Property[ ]+([0-9]+)`)
	sentenceSplitRe  = regexp.MustCompile(`[.;:!?]`)
)

// The severities of check 2.
//
// 2a reports. Its class is every property that says it derives a class, and its finding is that
// the property never says how many members the class has. It fires on properties that are
// correct as well as on the defect, because "the class is the method set read off engine.go" is
// a complete derivation with the count stated in the task's Produces block instead. It turns
// fatal when every class-deriving property in m1 and s1 carries its own count sentence — which
// is a rewrite of both documents, not a fix to one.
//
// 2b is fatal. Its class is every property that states its class is EMPTY at its own task, and
// its finding is that the relocation such a property owes did not land. This is the check that
// the 2026-09-05 repair needed and did not have: it made three relocations and two of them never
// arrived. The reciprocal reference it requires is the repair's own instruction — "note it in
// both tasks so it is not dropped between them", and "cross-reference both ways so neither is
// dropped" — so this is the plan's rule read back to it, not a rule invented here.
const (
	check2aFatal = false
	check2bFatal = true
)

func TestEveryClassDerivingPropertyStatesItsMembership(t *testing.T) {
	docs := readPlanCorpus(t)
	derived := []*planProperty{}
	for _, task := range allTasks(docs) {
		for _, property := range task.properties {
			if derivesClassRe.MatchString(property.text) && derivationRe.MatchString(property.text) {
				derived = append(derived, property)
			}
		}
	}
	mustHaveRead(t, "the class-deriving property class", len(derived))

	unstated, unlanded := []finding{}, []finding{}
	for _, property := range derived {
		task := property.task
		counts := membershipCounts(property.text)
		if len(counts) == 0 {
			unstated = append(unstated, finding{task.doc.name, property.start,
				fmt.Sprintf("Task %s Property %d derives a class and never says how many members it has at this task, so a reader cannot tell a gate that fatals on arrival from one that passes vacuously",
					task.id, property.number)})
			continue
		}
		empty := false
		for _, count := range counts {
			if emptyCountRe.MatchString(strings.TrimSpace(count)) {
				empty = true
			}
		}
		if !empty {
			continue
		}
		// An empty class at this task owes a relocation, and the relocation owes a reciprocal.
		destinations := relocationTargets(property)
		if len(destinations) == 0 {
			unlanded = append(unlanded, finding{task.doc.name, property.start,
				fmt.Sprintf("Task %s Property %d states its derived class is empty at this task and names no later task where the class first has a member",
					task.id, property.number)})
			continue
		}
		for _, destination := range destinations {
			target := taskByID(task.doc, destination.task)
			if target == nil {
				unlanded = append(unlanded, finding{task.doc.name, property.start,
					fmt.Sprintf("Task %s Property %d relocates its empty-class half to Task %s, which this document does not declare",
						task.id, property.number, destination.task)})
				continue
			}
			if destination.property != 0 {
				landed := propertyByNumber(target, destination.property)
				if landed == nil {
					unlanded = append(unlanded, finding{task.doc.name, property.start,
						fmt.Sprintf("Task %s Property %d relocates its empty-class half to Task %s Property %d, which Task %s does not state",
							task.id, property.number, destination.task, destination.property, destination.task)})
					continue
				}
				if !reciprocates(landed.text, task.id, property.number) {
					unlanded = append(unlanded, finding{task.doc.name, landed.start,
						fmt.Sprintf("Task %s Property %d is where Task %s Property %d relocated its empty-class half, and it does not name Task %s Property %d back, so what landed here cannot be checked against what left there",
							destination.task, destination.property, task.id, property.number, task.id, property.number)})
				}
				continue
			}
			if !reciprocates(target.body, task.id, property.number) {
				unlanded = append(unlanded, finding{task.doc.name, target.start,
					fmt.Sprintf("Task %s is where Task %s Property %d relocated its empty-class half, and it does not name Task %s Property %d anywhere, so the half that left there did not land here",
						destination.task, task.id, property.number, task.id, property.number)})
			}
		}
	}
	report(t, "check 2a — a class-deriving property that never states its membership", unstated, check2aFatal,
		"every class-deriving property in m1 and s1 carries its own count sentence; today several state the count in the task's Produces block instead, which is correct and which this check cannot see")
	report(t, "check 2b — an empty derived class whose relocation did not land", unlanded, check2bFatal, "never; it is fatal")
}

// The counts a property states about its class. "That class is empty at this task's commit"
// gives "empty"; "Today the class is two members" gives "two"; "a gate that fatals on an empty
// class" gives nothing, because it is a claim about the gate and not about this class.
func membershipCounts(text string) []string {
	out := []string{}
	for _, match := range membershipClaimRe.FindAllStringSubmatch(flatten(text), -1) {
		out = append(out, match[1])
	}
	return out
}

type relocation struct {
	task     string
	property int
}

// Where a property says its empty half goes. Only sentences carrying a relocation verb are
// read — "the never-inspected half moves to Task 9a", "the call-site gate is Task 11
// Property 7's" — because a property that merely mentions another task is not sending anything
// there, and the empty-class properties in this corpus mention two or three each. Inside such a
// sentence, "Task N Property M" is the precise destination and "Task N ... its Property M" is
// the same thing said in two clauses; a bare "Task N" is the loose form and is taken as the
// destination task with no property.
func relocationTargets(property *planProperty) []relocation {
	out := []relocation{}
	seen := map[relocation]bool{}
	add := func(item relocation) {
		if item.task == property.task.id || seen[item] {
			return
		}
		seen[item] = true
		out = append(out, item)
	}
	for _, sentence := range sentenceSplitRe.Split(flatten(property.text), -1) {
		if !relocationVerbRe.MatchString(sentence) {
			continue
		}
		precise := propertyRefRe.FindAllStringSubmatch(sentence, -1)
		for _, match := range precise {
			if number, err := strconv.Atoi(match[2]); err == nil {
				add(relocation{task: match[1], property: number})
			}
		}
		if len(precise) > 0 {
			continue
		}
		tasks := taskRefRe.FindAllStringSubmatch(sentence, -1)
		loose := itsPropertyRe.FindStringSubmatch(sentence)
		for _, match := range tasks {
			item := relocation{task: match[1]}
			if loose != nil && len(tasks) == 1 {
				if number, err := strconv.Atoi(loose[1]); err == nil {
					item.property = number
				}
			}
			add(item)
		}
	}
	return out
}

// The reciprocal a relocation owes: the destination names the source task AND the source
// property. Naming the source task alone is not it — m1 Task 15 names Task 13 in passing while
// holding none of what Task 13 relocated to it, which is the exact miss this check is for. The
// text is flattened first, because "Task 11\n  Property 7's" is one reference over two lines
// and the reciprocal is as likely to be wrapped as the reference that owes it.
func reciprocates(text string, sourceTask string, sourceProperty int) bool {
	pattern := regexp.MustCompile(`\bTask[ ]+(?:\*\*)?` + regexp.QuoteMeta(sourceTask) +
		`(?:\*\*)?(?:'s|’s)?[ ,]+(?:\*\*)?Propert(?:y|ies)[ ]+` + strconv.Itoa(sourceProperty) + `\b`)
	return pattern.MatchString(flatten(text))
}

func taskByID(doc *planDocument, id string) *planTask {
	for _, task := range doc.tasks {
		if task.id == id {
			return task
		}
	}
	return nil
}

func propertyByNumber(task *planTask, number int) *planProperty {
	for _, property := range task.properties {
		if property.number == number {
			return property
		}
	}
	return nil
}

// ── check 3: every cross-reference resolves ─────────────────────────────────────────────────

var (
	// "Task 9", "Task 9a", "Tasks 19-20", "Tasks 7-13, 15, 16, 18, 19 and 22".
	taskListRe = regexp.MustCompile(`\bTasks?[ \t]+((?:[0-9]+[a-z]?)(?:[ \t]*(?:,|and|or|to|through|[–—-])[ \t]*(?:[0-9]+[a-z]?))*)`)
	taskNumRe  = regexp.MustCompile(`[0-9]+[a-z]?`)
	// The plan token that qualifies a task reference to another document: "p7 Tasks 7-13",
	// "s1's Task 16", "m1 Task 13". Read backwards from the reference with the markup stripped.
	qualifierRe = regexp.MustCompile(`\b((?:p|s|m)[0-9]+)(?:'s|’s)?[ \t]*$`)
	// An open-item id as the plans write it: M1-43, S1-9, O-5.
	itemRefRe = regexp.MustCompile(`\b((?:[A-Z][0-9]+-[0-9]+[a-z]?)|(?:O-[0-9]+))\b`)
	// A ledger citation: "ledger 21", "Ledger 25", "ledger item 47", "ledger items 44 and 44a",
	// "ledger open item 7".
	ledgerRefRe = regexp.MustCompile(`(?i)\bledger[ \t]+(?:open[ \t]+)?(?:items?[ \t]+)?((?:[0-9]+[a-z]?)(?:[ \t]*(?:,|and)[ \t]*(?:[0-9]+[a-z]?))*)`)
	// A plan named by its token in running prose: "p8's plan", "s5 produces", "m1".
	planRefRe = regexp.MustCompile(`\b((?:p|s|m)[0-9]+)\b`)
	// The ledger's own open items, as an ordered list under its open-items heading.
	ledgerItemRe = regexp.MustCompile(`^([0-9]+[a-z]?)\.[ \t]+`)
)

// The severities of check 3.
//
// 3a reports, and it reports because of three findings in documents this pass may not edit, all
// three of them real:
//
//   - p8 line 883 says `Profile` "is produced here (`profile.go`, Task 2a)" and p8's own heading
//     for `profile.go` is Task 3a. p8 declares no Task 2a;
//   - m1 line 43 and s1 line 43 both say "p6 Task 23's five plan tests", and p6 declares twenty
//     tasks. SPEC-LEDGER.md line 1988 says it too, so the number is wrong in three documents
//     and this file cannot tell which task was meant;
//   - the interface registry cites other plans' tasks with the plan token further from the
//     reference than a qualifier can be read off ("p7's call sites in Tasks 12, 13 and 18").
//
// It turns fatal when those are closed. The class is not narrowed to get there, and every
// finding is printed on every run so none of them is lost.
//
// 3b is fatal. An M1-n/S1-n/O-n reference that resolves to no item is a dangling name with no
// reading under which it is correct.
//
// 3c reports. Its class is every plan token a document names — p1..p8, s1, m1, and s2..s10,
// which the plans cite constantly as owners of work nobody has written yet. A reference to a
// plan that does not exist is load-bearing information ("no written plan owns this leg") rather
// than a defect, and failing on it would make the suite red for a fact the plans state on
// purpose. It turns fatal when every plan token cited across the corpus has a document — which
// is s2 through s10 being written, and is the same day S1-9 and M1-42 close.
//
// 3d is fatal. A ledger citation names an item number in a document this repository owns, and
// the ledger is right here.
const (
	check3aFatal = false
	check3bFatal = true
	check3cFatal = false
	check3dFatal = true
)

func TestEveryCrossReferenceResolves(t *testing.T) {
	docs := readPlanCorpus(t)
	byToken := map[string]*planDocument{}
	for _, doc := range docs {
		if doc.token != "" {
			byToken[doc.token] = doc
		}
	}
	ledger := readLedgerItems(t)

	tasks, items, plans, ledgerRefs := 0, 0, 0, 0
	danglingTasks, danglingItems, danglingPlans, danglingLedger := []finding{}, []finding{}, []finding{}, []finding{}

	for _, doc := range docs {
		for index, line := range doc.lines {
			number := index + 1
			flat := flatten(line)

			for _, match := range taskListRe.FindAllStringSubmatchIndex(flat, -1) {
				prefix := stripMarkup(flat[:match[0]])
				target := doc
				qualifier := qualifierRe.FindStringSubmatch(prefix)
				if qualifier != nil {
					named, known := byToken[qualifier[1]]
					if !known {
						continue // the plan itself is missing; 3c owns that finding
					}
					target = named
				}
				// A document that declares no task of its own has no local task namespace, so an
				// unqualified reference in it is a reference into somebody else's numbering and
				// this file cannot say whose. The interface registry is the whole of that case.
				if target == doc && len(doc.tasks) == 0 {
					continue
				}
				for _, id := range taskNumRe.FindAllString(flat[match[2]:match[3]], -1) {
					tasks++
					if taskByID(target, id) != nil {
						continue
					}
					where := "this document"
					if target != doc {
						where = target.name
					}
					danglingTasks = append(danglingTasks, finding{doc.name, number,
						fmt.Sprintf("names Task %s, which %s does not declare", id, where)})
				}
			}

			for _, match := range itemRefRe.FindAllStringSubmatch(flat, -1) {
				id := strings.ToUpper(match[1])
				items++
				if _, defined := doc.definedItems[id]; defined {
					continue
				}
				if definedSomewhere(docs, id) {
					continue
				}
				danglingItems = append(danglingItems, finding{doc.name, number,
					fmt.Sprintf("names open item %s, which no plan in this corpus defines", id)})
			}

			for _, match := range planRefRe.FindAllStringSubmatch(flat, -1) {
				plans++
				if _, known := byToken[match[1]]; known {
					continue
				}
				danglingPlans = append(danglingPlans, finding{doc.name, number,
					fmt.Sprintf("names plan %s, for which %s holds no document", match[1], planGlob)})
			}

			for _, match := range ledgerRefRe.FindAllStringSubmatchIndex(flat, -1) {
				// "argued in ledger 2026-09-04" cites an edit-log entry by date, not an item by
				// number. A citation whose digits run straight into a hyphen is a date, and RE2
				// has no lookahead to say so inside the pattern.
				if match[3] < len(flat) && flat[match[3]] == '-' {
					continue
				}
				for _, id := range taskNumRe.FindAllString(flat[match[2]:match[3]], -1) {
					ledgerRefs++
					if ledger[id] {
						continue
					}
					danglingLedger = append(danglingLedger, finding{doc.name, number,
						fmt.Sprintf("cites ledger item %s, which %s does not carry", id, ledgerPath)})
				}
			}
		}
	}

	mustHaveRead(t, "the task-reference class", tasks)
	mustHaveRead(t, "the open-item-reference class", items)
	mustHaveRead(t, "the plan-reference class", plans)
	mustHaveRead(t, "the ledger-reference class", ledgerRefs)

	report(t, "check 3a — a Task reference that resolves to no task", danglingTasks, check3aFatal,
		"p8 line 883's \"Task 2a\" becomes Task 3a (the heading p8 gives profile.go), the registry's \"p1 Task 17b\" is reconciled with p1's numbering, and the \"p6 Task 23\" that m1, s1 and SPEC-LEDGER.md all cite is corrected against p6's twenty tasks; none of the three is this file's to decide and all three are printed above")
	report(t, "check 3b — an open-item reference that resolves to no item", danglingItems, check3bFatal, "never; it is fatal")
	report(t, "check 3c — a reference to a plan that has no document", collapse(danglingPlans), check3cFatal,
		"every plan token the corpus cites has a document in "+planGlob+"; today s2 through s10 are cited as owners of unwritten work, which the plans say on purpose")
	report(t, "check 3d — a ledger citation that resolves to no ledger item", danglingLedger, check3dFatal, "never; it is fatal")
}

// The ledger's open-item numbers, read out of its own ordered list rather than counted.
func readLedgerItems(t *testing.T) map[string]bool {
	t.Helper()
	text, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("reading %s: %v", ledgerPath, err)
	}
	items := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(string(text), "\r\n", "\n"), "\n") {
		if match := ledgerItemRe.FindStringSubmatch(line); match != nil {
			items[match[1]] = true
		}
	}
	if len(items) == 0 {
		t.Fatalf("%s carries no numbered item, so check 3d would report clean having read nothing", ledgerPath)
	}
	return items
}

func definedSomewhere(docs []*planDocument, id string) bool {
	for _, doc := range docs {
		if _, defined := doc.definedItems[id]; defined {
			return true
		}
	}
	return false
}

// ── check 4: every Consumes entry names something produced or enumerated ────────────────────

// The severities of check 4.
//
// 4a is fatal. A Consumes entry naming "Task 31" in a document whose tasks stop at 24 is a
// dispatch instruction that cannot be followed, and it is the shape that put two tasks on this
// project in front of an implementer who could not compile them.
//
// 4b reports. Its class is every qualified name a Consumes entry spells — GroupHandle.Method,
// Writer.WriteRaw — whose owning type this plan produces; its finding is that no Produces block
// of the plan declares the member. It fires on m1 Task 16's GroupEngine.JoinFromWelcome, which
// is the third instance of the class the brief names, and it fires on the p-plans wherever a
// method is consumed off a type whose Produces block lists the type and not its method set. It
// turns fatal when every Produces block that declares a type also declares the members other
// tasks consume off it — which is a rewrite of p1-p8's Produces blocks, not a fix to one.
const (
	check4aFatal = true
	check4bFatal = false
)

var qualifiedNameRe = regexp.MustCompile(`\b([A-Z][A-Za-z0-9_]*)\.([A-Z][A-Za-z0-9_]*)\b`)

func TestEveryConsumedNameIsProducedOrExternal(t *testing.T) {
	docs := readPlanCorpus(t)
	entries, qualified := 0, 0
	unresolvableTasks, unproducedMembers := []finding{}, []finding{}

	for _, doc := range docs {
		producedTypes := map[string]bool{}
		declared := map[string]bool{}
		for _, task := range doc.tasks {
			for _, name := range task.declares {
				declared[name] = true
				producedTypes[name] = true
			}
		}
		for _, task := range doc.tasks {
			for _, clause := range task.consumes {
				entries++
				flat := flatten(clause)
				for _, match := range taskListRe.FindAllStringSubmatchIndex(flat, -1) {
					prefix := stripMarkup(flat[:match[0]])
					target := doc
					if qualifier := qualifierRe.FindStringSubmatch(prefix); qualifier != nil {
						named := documentWithToken(docs, qualifier[1])
						if named == nil {
							continue
						}
						target = named
					}
					for _, id := range taskNumRe.FindAllString(flat[match[2]:match[3]], -1) {
						if taskByID(target, id) != nil {
							continue
						}
						where := "this document"
						if target != doc {
							where = target.name
						}
						unresolvableTasks = append(unresolvableTasks, finding{doc.name, task.start,
							fmt.Sprintf("Task %s consumes from Task %s, which %s does not declare", task.id, id, where)})
					}
				}
				for _, span := range backtickRe.FindAllStringSubmatch(flat, -1) {
					for _, match := range qualifiedNameRe.FindAllStringSubmatch(span[1], -1) {
						if !producedTypes[match[1]] {
							continue
						}
						qualified++
						if declared[match[2]] {
							continue
						}
						unproducedMembers = append(unproducedMembers, finding{doc.name, task.start,
							fmt.Sprintf("Task %s consumes %s.%s off a type this plan produces, and no Produces block in this plan declares %s",
								task.id, match[1], match[2], match[2])})
					}
				}
			}
		}
	}

	mustHaveRead(t, "the Consumes-entry class", entries)
	mustHaveRead(t, "the qualified-consumed-name class", qualified)
	report(t, "check 4a — a Consumes entry naming a task that does not exist", unresolvableTasks, check4aFatal, "never; it is fatal")
	report(t, "check 4b — a consumed member of a produced type that no Produces block declares", collapse(unproducedMembers), check4bFatal,
		"every Produces block that declares a type also declares the members other tasks consume off it; today p1-p8 declare the type and leave the method set to the registry")
}

func documentWithToken(docs []*planDocument, token string) *planDocument {
	for _, doc := range docs {
		if doc.token == token {
			return doc
		}
	}
	return nil
}

// ── shared text handling ────────────────────────────────────────────────────────────────────

// One line of text out of a document's wrapped prose. Every matcher in this file runs over the
// flattened form, because the plans wrap at 98 columns and a reference is as likely to straddle
// a newline as not — "Task 11\n  Property 7's" is one reference and two lines, and a matcher
// keyed to spaces reads it as neither.
func flatten(text string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(text, "\n", " ")), " ")
}

// Markup removed, so a qualifier can be read off the words before a reference. "**p7 Tasks" and
// "`connect/mls` **p7 Tasks" both have p7 immediately before the reference; only one of them
// does without this.
func stripMarkup(text string) string {
	return strings.NewReplacer("*", "", "`", "", "_", "", "[", "", "]", "").Replace(text)
}

// Findings collapsed to one line per document, for a reporting check whose class is large. The
// count and every task named stay in the output — this shortens the report, it does not narrow
// the class.
func collapse(findings []finding) []finding {
	order := []string{}
	byDoc := map[string][]finding{}
	for _, item := range findings {
		if _, seen := byDoc[item.doc]; !seen {
			order = append(order, item.doc)
		}
		byDoc[item.doc] = append(byDoc[item.doc], item)
	}
	if len(findings) <= 12 {
		return findings
	}
	out := []finding{}
	for _, name := range order {
		group := byDoc[name]
		seen := []string{}
		for _, item := range group {
			if !slices.Contains(seen, item.what) {
				seen = append(seen, item.what)
			}
		}
		shown := seen
		if len(shown) > 4 {
			shown = append(append([]string{}, seen[:4]...), fmt.Sprintf("and %d more", len(seen)-4))
		}
		out = append(out, finding{name, group[0].line,
			fmt.Sprintf("%d finding(s): %s", len(group), strings.Join(shown, "; "))})
	}
	return out
}

// ── the control fixture ─────────────────────────────────────────────────────────────────────

// The linter checked against a plan carrying every defect it exists to find.
//
// Why a control at all, and why this shape. Three of the four checks above land REPORTING
// today, because three landed plans carry findings this pass may not edit. A reporting check
// that silently stopped deriving anything would look exactly like a reporting check with
// nothing to report — which is the failure mode the whole file is written against, one level
// further in. So the derivations are run over a document built here, carrying each defect on
// purpose, and every one must come back. This is the shape the tree already uses:
// TestHkdfConfinementFlagsTheControlFixture in connect/mls/crypto_forbidden_test.go builds one
// nested control twin per allow-list entry and requires each to be reported.
//
// The fixture is read through newPlanDocument, the same constructor readPlanCorpus uses, so
// what is exercised is the derivation the corpus is read by and not a second one written to
// agree with it.
//
// Every defect below is one this project actually shipped, reintroduced deliberately:
//
//   - Task 1 states two properties and no mutation (check 1a) — m1 Task 16's shape;
//   - Task 1 Property 2 derives a class and never states its membership (check 2a) — m1
//     Task 7 Property 1's shape before this repair;
//   - Task 2 Property 1 states its class is empty here and relocates to a task that never
//     names it back (check 2b) — m1 Task 13 Property 4 and Task 9 Property 2's shape;
//   - Task 2 Property 2 states its class is empty and relocates nowhere at all (check 2b);
//   - Task 3 names Task 99 and open item M9-77 (checks 3a, 3b), and cites ledger item 9999
//     (check 3d);
//   - Task 3 consumes from Task 88 (check 4a).
//
// The fixture also carries the CORRECT forms beside the defects — Task 2 Property 3 relocates
// to Task 3 Property 1, which names it back — so a check that fired on everything would fail
// this test too.
func TestThePlanLinterFlagsTheControlFixture(t *testing.T) {
	doc := newPlanDocument("2026-01-01-slice0-x9-control-fixture.md", controlFixture)
	if len(doc.tasks) != 3 {
		t.Fatalf("the control fixture parsed to %d tasks, want 3; the fixture and the parser have drifted and every assertion below would be meaningless", len(doc.tasks))
	}
	corpus := []*planDocument{doc}

	t.Run("check1a_a_task_states_properties_and_no_mutation", func(t *testing.T) {
		task := mustTask(t, doc, "1")
		if len(task.properties) == 0 || len(task.mutations) != 0 {
			t.Fatalf("fixture Task 1 parsed to %d properties and %d mutations, want properties and no mutation", len(task.properties), len(task.mutations))
		}
	})

	t.Run("check2a_a_class_deriving_property_states_no_membership", func(t *testing.T) {
		property := mustProperty(t, doc, "1", 2)
		if !derivesClassRe.MatchString(property.text) || !derivationRe.MatchString(property.text) {
			t.Fatal("fixture Task 1 Property 2 is no longer read as deriving a class, so check 2a's class no longer holds it")
		}
		if counts := membershipCounts(property.text); len(counts) != 0 {
			t.Fatalf("fixture Task 1 Property 2 states no membership and the linter read %v out of it", counts)
		}
	})

	t.Run("check2b_an_empty_class_whose_relocation_did_not_land", func(t *testing.T) {
		property := mustProperty(t, doc, "2", 1)
		counts := membershipCounts(property.text)
		if len(counts) == 0 || !emptyCountRe.MatchString(strings.TrimSpace(counts[0])) {
			t.Fatalf("fixture Task 2 Property 1 says its class is empty here and the linter read %v", counts)
		}
		targets := relocationTargets(property)
		if len(targets) != 1 || targets[0].task != "3" || targets[0].property != 2 {
			t.Fatalf("fixture Task 2 Property 1 relocates to Task 3 Property 2 and the linter read %+v", targets)
		}
		landed := mustProperty(t, doc, "3", 2)
		if reciprocates(landed.text, "2", 1) {
			t.Fatal("fixture Task 3 Property 2 does not name Task 2 Property 1 back and the linter says it does")
		}
	})

	t.Run("check2b_an_empty_class_that_relocates_nowhere", func(t *testing.T) {
		property := mustProperty(t, doc, "2", 2)
		if targets := relocationTargets(property); len(targets) != 0 {
			t.Fatalf("fixture Task 2 Property 2 names no destination and the linter read %+v", targets)
		}
	})

	t.Run("check2b_a_relocation_that_did_land_is_not_a_finding", func(t *testing.T) {
		property := mustProperty(t, doc, "2", 3)
		targets := relocationTargets(property)
		if len(targets) != 1 || targets[0].task != "3" || targets[0].property != 1 {
			t.Fatalf("fixture Task 2 Property 3 relocates to Task 3 Property 1 and the linter read %+v", targets)
		}
		landed := mustProperty(t, doc, "3", 1)
		if !reciprocates(landed.text, "2", 3) {
			t.Fatal("fixture Task 3 Property 1 names Task 2 Property 3 back and the linter does not see it; a check that reports the correct form as a defect is a check nobody will keep")
		}
	})

	t.Run("check3a_a_task_reference_that_resolves_to_nothing", func(t *testing.T) {
		if taskByID(doc, "99") != nil {
			t.Fatal("the fixture declares a Task 99, which it must not")
		}
		if !mentionsTask(mustTask(t, doc, "3").body, "99") {
			t.Fatal("fixture Task 3 names Task 99 and the reference extractor does not find it")
		}
	})

	t.Run("check3b_an_item_reference_that_resolves_to_nothing", func(t *testing.T) {
		if _, defined := doc.definedItems["M9-77"]; defined {
			t.Fatal("the fixture defines M9-77, which it must not")
		}
		if _, defined := doc.definedItems["M9-1"]; !defined {
			t.Fatal("the fixture defines M9-1 and the item-definition parser does not see it, so check 3b would convict a document for citing what it defines")
		}
	})

	t.Run("check3d_a_ledger_citation_that_resolves_to_nothing_and_a_date_that_is_not_one", func(t *testing.T) {
		body := flatten(mustTask(t, doc, "3").body)
		cited := []string{}
		for _, match := range ledgerRefRe.FindAllStringSubmatchIndex(body, -1) {
			if match[3] < len(body) && body[match[3]] == '-' {
				continue
			}
			cited = append(cited, taskNumRe.FindAllString(body[match[2]:match[3]], -1)...)
		}
		if !slices.Contains(cited, "9999") {
			t.Fatalf("fixture Task 3 cites ledger item 9999 and the linter read %v", cited)
		}
		if slices.Contains(cited, "2026") {
			t.Fatalf("fixture Task 3's \"ledger 2026-01-01\" is an edit-log date and the linter read it as item 2026, out of %v", cited)
		}
	})

	t.Run("check4a_a_consumes_entry_naming_a_task_that_does_not_exist", func(t *testing.T) {
		task := mustTask(t, doc, "3")
		if len(task.consumes) == 0 {
			t.Fatal("fixture Task 3 states a Consumes entry and the interface parser found none")
		}
		if taskByID(doc, "88") != nil {
			t.Fatal("the fixture declares a Task 88, which it must not")
		}
		if !mentionsTask(strings.Join(task.consumes, " "), "88") {
			t.Fatalf("fixture Task 3 consumes from Task 88 and the linter read %q", task.consumes)
		}
	})

	// And the whole of it end to end: the checks above are run over the fixture as the corpus,
	// and the findings they produce are the ones the fixture plants. This is the assertion that
	// survives a refactor of any single helper.
	t.Run("every_check_reports_the_fixture", func(t *testing.T) {
		if got := len(fixtureFindings(corpus)); got < 6 {
			t.Fatalf("the fixture plants six defects and the linter returned %d findings over it", got)
		}
	})
}

func mustTask(t *testing.T, doc *planDocument, id string) *planTask {
	t.Helper()
	task := taskByID(doc, id)
	if task == nil {
		t.Fatalf("the control fixture declares no Task %s", id)
	}
	return task
}

func mustProperty(t *testing.T, doc *planDocument, id string, number int) *planProperty {
	t.Helper()
	property := propertyByNumber(mustTask(t, doc, id), number)
	if property == nil {
		t.Fatalf("the control fixture declares no Task %s Property %d", id, number)
	}
	return property
}

func mentionsTask(text string, id string) bool {
	for _, match := range taskListRe.FindAllStringSubmatch(flatten(text), -1) {
		if slices.Contains(taskNumRe.FindAllString(match[1], -1), id) {
			return true
		}
	}
	return false
}

// The findings the four derivations produce over a corpus, without the severities. Used by the
// control fixture to assert the derivations still see what the fixture plants.
func fixtureFindings(docs []*planDocument) []finding {
	out := []finding{}
	for _, doc := range docs {
		for _, task := range doc.tasks {
			if len(task.properties) > 0 && len(task.mutations) == 0 {
				out = append(out, finding{doc.name, task.start, "task states properties and no mutation"})
			}
			for _, property := range task.properties {
				if !derivesClassRe.MatchString(property.text) || !derivationRe.MatchString(property.text) {
					continue
				}
				counts := membershipCounts(property.text)
				if len(counts) == 0 {
					out = append(out, finding{doc.name, property.start, "class derived, membership never stated"})
					continue
				}
				empty := false
				for _, count := range counts {
					if emptyCountRe.MatchString(strings.TrimSpace(count)) {
						empty = true
					}
				}
				if !empty {
					continue
				}
				targets := relocationTargets(property)
				if len(targets) == 0 {
					out = append(out, finding{doc.name, property.start, "empty class, no relocation"})
					continue
				}
				for _, target := range targets {
					landing := taskByID(doc, target.task)
					if landing == nil {
						out = append(out, finding{doc.name, property.start, "relocation to a task that does not exist"})
						continue
					}
					text := landing.body
					if target.property != 0 {
						if landed := propertyByNumber(landing, target.property); landed != nil {
							text = landed.text
						}
					}
					if !reciprocates(text, task.id, property.number) {
						out = append(out, finding{doc.name, property.start, "relocation that did not land"})
					}
				}
			}
			for _, clause := range task.consumes {
				for _, match := range taskListRe.FindAllStringSubmatch(flatten(clause), -1) {
					for _, id := range taskNumRe.FindAllString(match[1], -1) {
						if taskByID(doc, id) == nil {
							out = append(out, finding{doc.name, task.start, "consumes from a task that does not exist"})
						}
					}
				}
			}
		}
		for index, line := range doc.lines {
			flat := flatten(line)
			for _, match := range taskListRe.FindAllStringSubmatchIndex(flat, -1) {
				if qualifierRe.MatchString(stripMarkup(flat[:match[0]])) || len(doc.tasks) == 0 {
					continue
				}
				for _, id := range taskNumRe.FindAllString(flat[match[2]:match[3]], -1) {
					if taskByID(doc, id) == nil {
						out = append(out, finding{doc.name, index + 1, "names a task that does not exist"})
					}
				}
			}
			for _, match := range itemRefRe.FindAllStringSubmatch(flat, -1) {
				if _, defined := doc.definedItems[strings.ToUpper(match[1])]; !defined {
					out = append(out, finding{doc.name, index + 1, "names an item no plan defines"})
				}
			}
		}
	}
	return out
}

// The control document. Written to this corpus's own shape — Files, Interfaces, Properties,
// Mutations — and carrying one instance of each defect class beside one instance of the correct
// form. It uses no plan token and no code spans, so nothing here can be confused for a
// reference into a real plan.
const controlFixture = `
# [Control fixture] Implementation Plan

**Goal:** carry one instance of every defect the plan linter exists to find, so that a check
which quietly stopped deriving anything is distinguishable from a check with nothing to report.

## Task 1: A task that states properties and states no mutation

**Files:**
- Create: one file

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the value is the one the spec names.** Assert it.

  **Property 2 — nothing outside the allowed set reaches the sink.** The scope question: derive
  the class of production functions that reach the sink, off the syntax tree, and assert each is
  allowed. This property never says how many members that class has, which is the whole defect.

- [ ] **Step 6: Commit**

---

## Task 2: Empty derived classes, one relocated badly, one not relocated, one relocated well

**Files:**
- Modify: one file

**Interfaces:**
- Consumes: Task 1.
- Produces: nothing.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the readers of the staged value never inspect it.** The scope question: derive
  the class of functions that read the staged value. That class is empty at this task's commit,
  and the half that needs a member moves to Task 3 Property 2, where the class first has a
  member.

  **Property 2 — every call site passes the pinned identifier.** Derive the class of call sites
  off the syntax tree. That class is empty at this task's commit, and this property names no
  later place at all, which is the second defect.

  **Property 3 — the sink is reached before the key exists.** Derive the class of paths into the
  sink. That class is empty at this task's commit, and the half that needs a member moves to
  Task 3 Property 1.

- [ ] **Step 5: Mutation-test.**
  1. Drop the call.
  2. Ignore the error.
- [ ] **Step 6: Commit**

---

## Task 3: The landing sites, and four references that resolve to nothing

**Files:**
- Modify: one file

**Interfaces:**
- Consumes: Task 88's sink; Task 2's staged value.
- Produces: nothing.

**M9-1 — the fixture's one defined item.** It exists so that a check refusing an undefined item
is not a check refusing every item. This task also cites M9-77, which nothing defines, and
Task 99, which nothing declares. Its argument was recorded in ledger 2026-01-01, and the number
it should have cited is ledger item 9999.

- [ ] **Step 1: Derive the property and write the failing test**

  **Property 1 — the paths into the sink all pass the reservation.** This is the derived-class
  half of Task 2 Property 3, landing here because this is the commit where the class first has a
  member. The class has three members.

  **Property 2 — the staged value is carried opaquely.** Derive the class of writers of the
  staged value; the class has one member. Something was relocated here and this property does not
  say what, which is the first defect.

- [ ] **Step 5: Mutation-test.**
  1. Carry the staged value in the wrong field.
- [ ] **Step 6: Commit**
`
