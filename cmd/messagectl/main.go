// The ops CLI of spec B §2.1: migrate, sweep-now, capability dump, key rotate.
//
// None of the four is implemented yet, and this build says so per subcommand rather than
// printing a usage banner that reads like a working tool. The one that matters first is
// `migrate`: §10.3 is normative that migrations are run by a dedicated job or by this
// command holding `pg_advisory_lock`, never by N replicas racing at startup, so the command
// exists in the layout before the store does — otherwise the first person who needs a
// migration runs it from a replica.
package main

import (
	"fmt"
	"os"
)

// The subcommands §2.1 names, with the section each will be built against.
var subcommands = []struct {
	name string
	what string
}{
	{"migrate", "apply the ordered migration list under pg_advisory_lock (§10.3)"},
	{"sweep-now", "run the retention sweep once, --until-clean after a restore (§10.4 trap 1)"},
	{"capabilities", "dump the Capabilities this fleet advertises, and its capability_version (§10.2)"},
	{"rotate", "rotate a KEK or the fleet transport credential (§5.5, §10.5)"},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stdout, "messagectl <subcommand>\n\n")
		for _, subcommand := range subcommands {
			fmt.Fprintf(os.Stdout, "  %-14s %s\n", subcommand.name, subcommand.what)
		}
		fmt.Fprintf(os.Stdout, "\nnone of these is implemented in this build.\n")
		return
	}
	fmt.Fprintf(os.Stderr, "messagectl: %s is not implemented in this build\n", os.Args[1])
	os.Exit(1)
}
