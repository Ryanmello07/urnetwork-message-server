// The message server process entrypoint of spec B §2.1.
//
// This build runs. It loads §10.2's `message.yml` and the vault resources beside it, opens the
// message-server Postgres cluster of decision B10, asserts §3.1's clock and §10.3's migrations,
// builds the store, the §5.1 pipeline and §4.2's frame dispatch on top of them, attaches a
// URnetwork client to the operator's platform, serves §10.1's `/healthz` and `/readyz` on a
// private port, and shuts down in §2.3's order.
//
// It binds exactly one socket, and that socket is the health port. **The message plane is not a
// listener and cannot be**: a client reaches this server over `connect`, which dials the
// operator's platform at `wss://connect.<operator_host>` and receives frames the platform routes
// to this replica's `client_id`. transport.go is where that is argued from `connect`'s own code,
// and it is also where the one thing this repository cannot produce is named — the per-ordinal
// `network_client` credential of §9.1, which an admin of that operator creates.
//
// Without that credential this process still starts, still serves both health endpoints, and
// refuses readiness on `ordinal_credential` while saying in one log line that it will serve no
// message traffic. It does not stand up a client that receives nothing: see transport.go.
//
// Nothing here prints a secret and nothing it calls does. The three secrets — `pg.yml`'s DSN,
// `message_fleet.yml`'s KEK and `message_server.yml`'s transport credential — are reported as
// present or ABSENT and never as a value, the resource reader's parse errors carry a line number
// and never a line, and a DSN that fails to parse is reported without pgx's own message, which
// quotes it.
//
// May import: any package of this module. An entrypoint that cannot import a package cannot
// start it, so the layering the other packages declare stops here — what this file may reach
// outside the module is still spec B §2.2's list and nothing wider.
//
//urmsg:mayimport *
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
)

// stamped at link time with -ldflags "-X main.version=...". `dev` is the honest answer for a
// build nobody stamped, and it is the one an unstamped release binary will print in front of
// an operator, so it is a word rather than an empty string.
var version = "dev"

func main() {
	printOnly := flag.Bool("print-config", false,
		"print what this process would run on and exit, reading every resource but opening nothing")
	flag.Parse()

	if err := run(*printOnly); err != nil {
		fmt.Fprintf(os.Stderr, "message-server: %v\n", err)
		os.Exit(1)
	}
}

// Load, start, serve until a signal, then shut down.
//
// The signal context is established BEFORE anything is opened. A SIGTERM that arrives during a
// slow startup — a database that takes twenty seconds to answer, on a node that is being drained
// — then cancels the startup instead of being delivered to a process that has not installed a
// handler yet, which is the default disposition and is an immediate exit with a half-open pool.
func run(printOnly bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	deploy, message, err := loadDeployment(osEnvironment)
	if err != nil {
		return err
	}
	loaded, err := loadConfiguration(message, osEnvironment)
	if err != nil {
		return err
	}

	if printOnly {
		printConfiguration(deploy, loaded)
		return nil
	}

	// The collaborators' own lifetime, which is deliberately NOT the signal's.
	//
	// §2.3 shuts down by draining in-flight transactions AFTER the signal arrives. A pool and a
	// connect client whose context died with the signal have nothing left to drain on: the
	// teardown would be reading from collaborators it had already cancelled, and the 60 s window
	// §2.3 specifies would be 60 s of failed queries. [server.Close] ends these; the signal ends
	// the wait below.
	lifetime, endLifetime := context.WithCancel(context.Background())
	defer endLifetime()

	current, err := newServer(lifetime, deploy, loaded, log)
	if err != nil {
		return err
	}
	defer current.Close()

	// a signal that arrived while the pool was opening is a shutdown and not a start: bind
	// nothing, announce nothing, and let the deferred Close run
	if ctx.Err() != nil {
		log.Info("shutting down", "reason", "signal during startup")
		return nil
	}

	if err := current.listen(); err != nil {
		return fmt.Errorf("§10.1's private health port: %w", err)
	}
	current.announce(ctx)

	<-ctx.Done()
	// the signal has been received; stop catching it, so a second one kills a process that is
	// stuck in teardown rather than being swallowed by the same handler
	stop()
	log.Info("shutting down", "reason", "signal")
	return nil
}

// `--print-config`: every resource read and nothing opened.
//
// It is the one mode that survives from the build before this one, and it survives because it is
// the thing an operator does first on a new box — confirm the process can see its configuration,
// before it has a database to point at.
func printConfiguration(deploy deployment, loaded configuration) {
	out := os.Stdout
	fmt.Fprintf(out, "message-server %s\n", version)
	fmt.Fprintf(out, "  go          %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	for _, line := range buildLines() {
		fmt.Fprintf(out, "  %s\n", line)
	}

	fmt.Fprintf(out, "\nresources (spec B §10.2; values are never printed, only whether they were supplied)\n")
	for _, line := range deploy.lines() {
		fmt.Fprintf(out, "  %s\n", line)
	}

	fmt.Fprintf(out, "\nconfiguration (spec B §10.2)\n")
	for _, line := range loaded.lines() {
		fmt.Fprintf(out, "  %s\n", line)
	}

	fmt.Fprintf(out, "\nnot built\n")
	for _, item := range configurationNotWired {
		fmt.Fprintf(out, "  %s\n", item.String())
	}
	for _, item := range deploymentNotWired {
		fmt.Fprintf(out, "  %s\n", item.String())
	}
}

// What the toolchain stamped into this binary about where it came from. Read rather than
// asked for, so a binary built outside the release path still says which revision it is —
// and says plainly when it does not know, rather than printing a blank line.
func buildLines() []string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return []string{"build       no build information in this binary"}
	}
	revision, modified, stamped := "", "", false
	for _, stamp := range info.Settings {
		switch stamp.Key {
		case "vcs.revision":
			revision, stamped = stamp.Value, true
		case "vcs.modified":
			if stamp.Value == "true" {
				modified = " (working tree modified)"
			}
		}
	}
	if !stamped {
		return []string{fmt.Sprintf("module      %s", info.Main.Path), "revision    not stamped"}
	}
	return []string{
		fmt.Sprintf("module      %s", info.Main.Path),
		fmt.Sprintf("revision    %s%s", revision, modified),
	}
}
