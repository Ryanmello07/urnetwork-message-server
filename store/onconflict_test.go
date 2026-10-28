package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// EVERY INSERT INTO A LINK BOX TABLE CARRIES THE ON CONFLICT §4.3.11 PRINTS (LRI R75, S-4; Spec B
// §11.2 item 4: "Every INSERT in store/ MUST use ON CONFLICT"). 013's rows go in with
// `ON CONFLICT (rendezvous_id)`, and 014's with `ON CONFLICT (rendezvous_id, deposit_hash)`, which is
// §4.3.11's Deposit: "Insert with ON CONFLICT (rendezvous_id, deposit_hash) DO NOTHING and return the
// existing deposit_id on conflict". Without it, the box's row lock is all that stands between a
// replay and a unique_violation, which answers the replay REASON_INTERNAL and, §11.2 says, carries
// the key into the DETAIL of any database log not set to terse.
//
// It is read out of this package's own source: every string literal in a function that holds an
// `INSERT INTO`, by the table it names.
//
// THE NARROWING, PRINTED AND HELD BOTH WAYS. §11.2 item 4 is about every INSERT in store/, and the
// INSERTs into the tables before 013 that carry no ON CONFLICT are older than this gate and are not
// the slice review's to change. They are printed, and held to [insertsWithoutOnConflict] in both
// directions: a new INSERT without one fails here by its function and its table, and so does a
// listed one that has gained one, which leaves its row stale.
var insertsWithoutOnConflict = map[string]string{
	"CreateGroup message_epoch":        "a new group's epochs, in the transaction whose group row went in with ON CONFLICT (group_id) DO NOTHING and was this request's",
	"CreateGroup message_stream_claim": "a new group's founding claim, in the same transaction",
	"CreateGroup message_commit":       "a new group's founding commit, in the same transaction",
	"CreateGroup message_sender":       "a new group's founding sender, in the same transaction",
	"openEpoch message_epoch":          "an epoch opened under the group's row lock, §6.1 step (1), after the epoch gate",
	"Migrate migration_audit":          "the migration runner's own record, in the migration's transaction under its lock",
}

// The ON CONFLICT target each link box table's inserts must name.
var linkBoxConflictTargets = map[string]string{
	"message_rendezvous":         "(rendezvous_id)",
	"message_rendezvous_deposit": "(rendezvous_id, deposit_hash)",
}

var (
	insertIntoPattern = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+([a-z_0-9]+)`)
	onConflictPattern = regexp.MustCompile(`(?is)\bON\s+CONFLICT\s*(\([^)]*\))`)
)

// One INSERT this package makes: the function it is in, the table it names, and the ON CONFLICT
// target it carries, or none.
type insertStatement struct {
	function string
	table    string
	conflict string
	at       string
}

// Every INSERT in a set of string literals, by function.
func insertsIn(files *token.FileSet, parsed []*ast.File) []insertStatement {
	found := []insertStatement{}
	for _, file := range parsed {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				text, err := strconv.Unquote(literal.Value)
				if err != nil {
					return true
				}
				found = append(found, insertsInText(function.Name.Name, text, files.Position(literal.Pos()).String())...)
				return true
			})
		}
	}
	return found
}

func insertsInText(function string, text string, at string) []insertStatement {
	found := []insertStatement{}
	for _, match := range insertIntoPattern.FindAllStringSubmatch(text, -1) {
		statement := insertStatement{function: function, table: match[1], at: at}
		if conflict := onConflictPattern.FindStringSubmatch(text); conflict != nil {
			statement.conflict = strings.Join(strings.Fields(conflict[1]), " ")
		}
		found = append(found, statement)
	}
	return found
}

func TestEveryInsertIntoALinkBoxTableCarriesItsOnConflict(t *testing.T) {
	files := token.NewFileSet()
	packages, err := parser.ParseDir(files, ".", func(info fs.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parsing this package: %v", err)
	}
	parsed := []*ast.File{}
	for _, file := range packages["store"].Files {
		parsed = append(parsed, file)
	}
	inserts := insertsIn(files, parsed)

	linkBoxInserts := map[string]int{}
	without := []string{}
	for _, insert := range inserts {
		if want, ours := linkBoxConflictTargets[insert.table]; ours {
			linkBoxInserts[insert.table]++
			if insert.conflict != want {
				t.Fatalf("%s inserts into %s at %s with ON CONFLICT %q, want ON CONFLICT %s (§4.3.11; §11.2 item 4)",
					insert.function, insert.table, insert.at, insert.conflict, want)
			}
			continue
		}
		if insert.conflict == "" {
			without = append(without, insert.function+" "+insert.table)
		}
	}
	for table := range linkBoxConflictTargets {
		if linkBoxInserts[table] == 0 {
			t.Fatalf("no INSERT INTO %s was found in this package, so the gate above held nothing of it", table)
		}
	}
	t.Logf("the link box inserts, by table: %v", linkBoxInserts)

	// the complement: every other INSERT with no ON CONFLICT, printed and held to the list both ways
	slices.Sort(without)
	t.Logf("the INSERTs outside the link box tables that carry no ON CONFLICT: %v", without)
	for _, key := range without {
		if _, listed := insertsWithoutOnConflict[key]; !listed {
			t.Fatalf("%s carries no ON CONFLICT and insertsWithoutOnConflict does not list it: §11.2 item 4 says every INSERT in store/ uses one", key)
		}
	}
	for key, why := range insertsWithoutOnConflict {
		if !slices.Contains(without, key) {
			t.Fatalf("insertsWithoutOnConflict lists %s (%s), and no such INSERT without an ON CONFLICT is in this package: the row is stale", key, why)
		}
	}

	// THE CONTROL: the same reading, shown a deposit insert with its ON CONFLICT and without it
	with := insertsInText("DepositLinkBox", "INSERT INTO message_rendezvous_deposit (rendezvous_id) VALUES ($1)\n ON CONFLICT (rendezvous_id,\n deposit_hash) DO NOTHING", "control")
	bare := insertsInText("DepositLinkBox", "INSERT INTO message_rendezvous_deposit (rendezvous_id) VALUES ($1)", "control")
	if len(with) != 1 || with[0].conflict != linkBoxConflictTargets["message_rendezvous_deposit"] || len(bare) != 1 || bare[0].conflict != "" {
		t.Fatalf("the control: the reading found %+v in an insert with its ON CONFLICT and %+v in one without, so it cannot tell them apart", with, bare)
	}
}
