package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// AN ERROR'S CLASS NAMES NOTHING OF THE ERROR (LRI R75, D1; Spec B §11.1's "error classes without
// identifiers"). Each kind of failure answers its class, wrapped or not: a server error its SQLSTATE,
// and "server" when its code is not one; a failure to connect that carries no server error
// "connect"; an ended context "canceled"; anything else "other". No class carries any of the error's
// own text, which is planted here in every field it could come from; sweep's and
// cmd/message-server's tests hold the log lines built from it, a real failure to connect among them.
// A connection the server refused carries the server's error inside pgconn's ConnectError, and
// answers its SQLSTATE (LRI R80). This table cannot build one: the error a ConnectError wraps is
// pgconn's own to set.
func TestAnErrorClassNamesNothingOfTheError(t *testing.T) {
	const planted = "planted-10.11.12.13-planted-user"
	for _, current := range []struct {
		name string
		err  error
		want string
	}{
		{"no error", nil, ""},
		{"a server error", &pgconn.PgError{Code: "40P01", Message: planted, Detail: planted}, "40P01"},
		{"a server error, wrapped", fmt.Errorf("a batch: %w", &pgconn.PgError{Code: "57014", Message: planted}), "57014"},
		{"a server error whose code is not a SQLSTATE", &pgconn.PgError{Code: planted}, "server"},
		{"a server error whose code has a lower-case letter", &pgconn.PgError{Code: "40p01"}, "server"},
		{"a failure to connect", &pgconn.ConnectError{Config: &pgconn.Config{Host: planted, User: planted, Database: planted}}, "connect"},
		{"a failure to connect, wrapped", fmt.Errorf("Begin: %w", &pgconn.ConnectError{Config: &pgconn.Config{Host: planted}}), "connect"},
		{"a cancel", context.Canceled, "canceled"},
		{"a deadline, wrapped", fmt.Errorf("a batch: %w", context.DeadlineExceeded), "canceled"},
		{"anything else", errors.New(planted), "other"},
	} {
		got := ErrorClass(current.err)
		if got != current.want {
			t.Fatalf("%s: ErrorClass answered %q, want %q", current.name, got, current.want)
		}
		if strings.Contains(got, "planted") {
			t.Fatalf("%s: ErrorClass answered %q, which carries the error's own text", current.name, got)
		}
	}
}
