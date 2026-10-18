package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// What kind of failure an error this package answered is, in words that name nothing: Spec B §11.1's
// "error classes without identifiers", which is what a log line may carry where it may not carry
// "any IP address" (LRI R75, D1).
//
// It exists because the text of a pgx error can carry what §11.1 forbids. A failure to connect names
// the user and the database it connected as, and the address and the host it dialled (pgconn's
// ConnectError, and the per-dial error inside it), and a server error's message can name a value. A
// caller that logs a failure logs this instead, and never the text:
//   - a server error, by its SQLSTATE, the five characters PostgreSQL defines for it (40P01 a
//     deadlock, 57014 a statement canceled, 08006 a connection lost), and "server" for one that is
//     not five such characters;
//   - "connect", for a failure to connect;
//   - "canceled", for a context that ended, by a cancel or a deadline;
//   - "other", for anything else, whose text is not looked at.
func ErrorClass(err error) string {
	var server *pgconn.PgError
	var connect *pgconn.ConnectError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &server):
		if isSqlState(server.Code) {
			return server.Code
		}
		return "server"
	case errors.As(err, &connect):
		return "connect"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	}
	return "other"
}

// A SQLSTATE: five characters, each a digit or an upper-case letter.
func isSqlState(code string) bool {
	if len(code) != 5 {
		return false
	}
	for _, character := range code {
		if !('0' <= character && character <= '9') && !('A' <= character && character <= 'Z') {
			return false
		}
	}
	return true
}
