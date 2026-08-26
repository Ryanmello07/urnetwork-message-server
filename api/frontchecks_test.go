package api

import (
	"context"
	"go/ast"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect/protocol"
)

// ── §5.1 checks 1, 2 and 4 ───────────────────────────────────────────────────────────────

// [FrontChecks] exists because "not called" and "called and passed" are the same green test —
// api.go says so in as many words. Until this file there was no refusing implementation of it
// anywhere in the package, only [ChecksNotImplemented], which answers REASON_OK to all three: a
// handler that returned REASON_OK before calling any of them was indistinguishable from one that
// called all three and passed, which is the exact failure the interface was introduced to make
// impossible.

// A front check's refusal is the operation's answer, on every operation, for every check.
//
// The class of operations is derived from the handler's own method set rather than named here.
// §5.1 puts checks 1, 2 and 4 "in front of the whole pipeline", so a request handler added later
// that skipped them would be a new hole in the same place, and a list of three method names in a
// test is a list that would not have the fourth on it.
func TestEveryOperationRunsSpecB51sFrontChecksAndAnswersTheirRefusal(t *testing.T) {
	checks := frontChecksInSpecOrder(t)
	t.Logf("§5.1's front checks, in the order api.go documents them: %v", checks)
	reasons := refusalReasonsOtherThanTheHandlersOwn(t, len(checks))

	for position, check := range checks {
		t.Run(check.method, func(t *testing.T) {
			front := &recordingFrontChecks{refuseAt: check.method, reason: reasons[position]}
			counted := &countingStore{}
			fixture := newFixtureWith(t, Config{Store: counted, Front: front, RejectFloor: 25 * time.Millisecond})
			counted.Store = fixture.store

			for _, operation := range requestHandlersOf(t, fixture.handler) {
				front.called = nil
				fixture.sleeps = nil
				counted.reset()

				reason, body, err := operation.call(t, fixture.conn)
				if err != nil {
					t.Fatalf("%s: %v", operation.name, err)
				}
				if reason != reasons[position] {
					t.Fatalf("%s was answered %v by a front check that refused with %v; §5.1 check %d's refusal is the operation's answer",
						operation.name, reason, reasons[position], check.number)
				}
				if body {
					t.Fatalf("%s answered a body after §5.1 check %d refused it; the refusal has only the envelope to travel on",
						operation.name, check.number)
				}
				if !slices.Equal(front.called, methodNames(checks[:position+1])) {
					t.Fatalf("%s called %v; §5.1 check %d refused, so the checks before it run and the checks after it do not: want %v",
						operation.name, front.called, check.number, methodNames(checks[:position+1]))
				}
				if counted.reads() != 0 {
					t.Fatalf("%s reached the store %d times after a front check refused it: %s", operation.name, counted.reads(), counted)
				}
				if len(fixture.sleeps) != 1 {
					t.Fatalf("%s padded %d times after a front check refused it, want exactly one pad to §4.5's floor",
						operation.name, len(fixture.sleeps))
				}
			}
		})
	}
}

// When nothing refuses, every front check still runs, in §5.1's order, on every operation.
//
// The half above cannot see this: a handler that ran only check 1 would answer check 1's refusal
// correctly and skip the other two forever.
func TestEveryOperationRunsEveryFrontCheckWhenNoneRefuses(t *testing.T) {
	checks := frontChecksInSpecOrder(t)
	front := &recordingFrontChecks{}
	fixture := newFixtureWith(t, Config{Front: front})

	for _, operation := range requestHandlersOf(t, fixture.handler) {
		front.called = nil
		if _, _, err := operation.call(t, fixture.conn); err != nil {
			t.Fatalf("%s: %v", operation.name, err)
		}
		if !slices.Equal(front.called, methodNames(checks)) {
			t.Fatalf("%s called %v, want every front check in §5.1's order: %v", operation.name, front.called, methodNames(checks))
		}
	}
}

// The set of front checks is the interface's, and their numbers are §5.1's own.
//
// Both halves are derived, and each catches something the other cannot. The set comes from the
// [FrontChecks] method set, so a fourth check added to the interface and called by nobody fails
// the two tests above rather than passing them silently. The numbers come from §5.1's table
// minus the checks the pipeline runs, so a check that moved from the front to the pipeline — or
// the other way — makes this fail instead of leaving two lists that disagree.
func TestTheFrontChecksAreExactlyTheChecksSpecB51DoesNotPutInThePipeline(t *testing.T) {
	checks := frontChecksInSpecOrder(t)

	declared := reflect.TypeOf((*FrontChecks)(nil)).Elem()
	methods := []string{}
	for index := 0; index < declared.NumMethod(); index++ {
		name := declared.Method(index).Name
		if name == "NotBuilt" {
			// the interface's report of itself, and not one of §5.1's checks
			continue
		}
		methods = append(methods, name)
	}
	documented := append([]string{}, methodNames(checks)...)
	slices.Sort(methods)
	slices.Sort(documented)
	if !slices.Equal(methods, documented) {
		t.Fatalf("FrontChecks declares %v and api.go documents a §5.1 check number for %v; a method with no number is a check nothing in this file would call",
			methods, documented)
	}

	handler := newFixture(t).handler
	run := []int{}
	for _, stage := range handler.submitStages() {
		run = append(run, stage.number)
	}
	want := []int{}
	for _, number := range checkNumbersOfSpecB51(t) {
		if !slices.Contains(run, number) {
			want = append(want, number)
		}
	}
	found := []int{}
	for _, check := range checks {
		found = append(found, check.number)
	}
	if !slices.Equal(found, want) {
		t.Fatalf("api.go documents the front checks as §5.1 checks %v, and §5.1's table minus the checks the pipeline runs is %v", found, want)
	}
}

// ── the doubles ──────────────────────────────────────────────────────────────────────────

// A [FrontChecks] that records what it was asked and refuses at one named method.
//
// The recording is the point. §5.1's order is normative for denial of service on the front three
// exactly as it is inside the pipeline — check 1 frees the reassembly buffer before check 2 does
// any work — so "all three ran" is not enough and neither is "the right one refused".
type recordingFrontChecks struct {
	called   []string
	refuseAt string
	reason   protocol.Reason
}

var _ FrontChecks = &recordingFrontChecks{}

func (self *recordingFrontChecks) answer(method string) protocol.Reason {
	self.called = append(self.called, method)
	if method == self.refuseAt {
		return self.reason
	}
	return protocol.Reason_REASON_OK
}

func (self *recordingFrontChecks) FrameWithinLimits(ctx context.Context, conn *Connection) protocol.Reason {
	return self.answer("FrameWithinLimits")
}

func (self *recordingFrontChecks) ConnectionAuthenticated(ctx context.Context, conn *Connection) protocol.Reason {
	return self.answer("ConnectionAuthenticated")
}

func (self *recordingFrontChecks) WithinRateLimits(ctx context.Context, conn *Connection, op uint8) protocol.Reason {
	return self.answer("WithinRateLimits")
}

func (self *recordingFrontChecks) NotBuilt() []NotBuilt {
	return ChecksNotImplemented{}.NotBuilt()
}

// ── the derivations ──────────────────────────────────────────────────────────────────────

// One of §5.1's front checks: the interface method that runs it and the number §5.1 gives it.
type frontCheck struct {
	method string
	number int
}

func (self frontCheck) String() string {
	return "check " + strconv.Itoa(self.number) + " (" + self.method + ")"
}

func methodNames(checks []frontCheck) []string {
	names := []string{}
	for _, check := range checks {
		names = append(names, check.method)
	}
	return names
}

// The [FrontChecks] methods in the order §5.1 numbers them, read out of api.go's own doc
// comments rather than written down here.
//
// Each method's document opens "Check N:", which is where the mapping from a method to a §5.1
// number actually lives; a copy of it in this file would be the second list to keep in step, and
// the whole shape of failure this project keeps walking into is a second list that agrees today.
func frontChecksInSpecOrder(t *testing.T) []frontCheck {
	t.Helper()
	_, files := parseGoDir(t, ".", false)
	found := []frontCheck{}
	for _, file := range files {
		ast.Inspect(file, func(node ast.Node) bool {
			declared, isType := node.(*ast.TypeSpec)
			if !isType || declared.Name.Name != "FrontChecks" {
				return true
			}
			interfaceType, isInterface := declared.Type.(*ast.InterfaceType)
			if !isInterface {
				t.Fatalf("FrontChecks is not an interface, so this gate cannot read its methods")
			}
			for _, method := range interfaceType.Methods.List {
				if method.Doc == nil || len(method.Names) != 1 {
					continue
				}
				number, documented := checkNumberOf(method.Doc.Text())
				if !documented {
					continue
				}
				found = append(found, frontCheck{method: method.Names[0].Name, number: number})
			}
			return false
		})
	}
	if len(found) == 0 {
		t.Fatal("no method of FrontChecks opens its document with a §5.1 check number, so this gate read nothing and every assertion under it would be vacuous")
	}
	for index := 1; index < len(found); index++ {
		if found[index].number <= found[index-1].number {
			t.Fatalf("FrontChecks declares %v after %v; §5.1's order is normative and this gate reads the declaration order as the call order",
				found[index], found[index-1])
		}
	}
	return found
}

// The number in a "Check N: ..." document, if it opens with one.
func checkNumberOf(document string) (int, bool) {
	rest, opens := strings.CutPrefix(strings.TrimSpace(document), "Check ")
	if !opens {
		return 0, false
	}
	digits, _, split := strings.Cut(rest, ":")
	if !split {
		return 0, false
	}
	number, err := strconv.Atoi(strings.TrimSpace(digits))
	if err != nil {
		return 0, false
	}
	return number, true
}

// One of this handler's request handlers, ready to be called with an empty request of its own
// arm's type.
type requestHandler struct {
	name string
	call func(t *testing.T, conn *Connection) (protocol.Reason, bool, error)
}

// Every operation [Handler] serves, derived from its method set.
//
// The shape is the derivation: a §4.3 operation takes a context, the connection §5.1 check 2
// reads its nonce from, and a request, and answers a [protocol.Reason], a body and an error.
// Nothing else on the type has that shape. A list of names here would be a list that a fifth
// operation is added without, which is how the front checks came to be unobserved on three
// operations at once.
func requestHandlersOf(t *testing.T, handler *Handler) []requestHandler {
	t.Helper()
	handlerType := reflect.TypeOf(handler)
	handlerValue := reflect.ValueOf(handler)
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	connectionType := reflect.TypeOf((*Connection)(nil))
	reasonType := reflect.TypeOf(protocol.Reason(0))
	errorType := reflect.TypeOf((*error)(nil)).Elem()

	found := []requestHandler{}
	for index := 0; index < handlerType.NumMethod(); index++ {
		method := handlerType.Method(index)
		signature := method.Type
		if signature.NumIn() != 4 || signature.NumOut() != 3 {
			continue
		}
		if signature.In(1) != contextType || signature.In(2) != connectionType {
			continue
		}
		if signature.In(3).Kind() != reflect.Pointer || signature.In(3).Elem().Kind() != reflect.Struct {
			continue
		}
		if signature.Out(0) != reasonType || signature.Out(2) != errorType {
			continue
		}
		call := handlerValue.Method(index)
		requestType := signature.In(3)
		name := method.Name
		found = append(found, requestHandler{
			name: name,
			call: func(t *testing.T, conn *Connection) (protocol.Reason, bool, error) {
				t.Helper()
				// an empty request of the operation's own arm: non-nil, so the nil-request answer
				// in front of the front checks is not what this measures
				answers := call.Call([]reflect.Value{
					reflect.ValueOf(context.Background()),
					reflect.ValueOf(conn),
					reflect.New(requestType.Elem()),
				})
				err, _ := answers[2].Interface().(error)
				return answers[0].Interface().(protocol.Reason), !answers[1].IsNil(), err
			},
		})
	}
	if len(found) < 3 {
		t.Fatalf("this gate found %d request handlers on *Handler, and §4.3 gives it at least Submit, CreateGroup and Fetch; the derivation has stopped matching", len(found))
	}
	return found
}

// Distinct refusals no operation of this package produces on its own.
//
// They come out of the compiled enum rather than being chosen here, minus the three an empty
// request can be answered with by the pipeline itself: a test double that refused with
// REASON_REJECTED would pass on a handler that never called it.
func refusalReasonsOtherThanTheHandlersOwn(t *testing.T, count int) []protocol.Reason {
	t.Helper()
	own := []protocol.Reason{
		protocol.Reason_REASON_OK,
		protocol.Reason_REASON_REJECTED,
		protocol.Reason_REASON_INTERNAL,
	}
	values := protocol.Reason(0).Descriptor().Values()
	found := []protocol.Reason{}
	for index := 0; index < values.Len() && len(found) < count; index++ {
		reason := protocol.Reason(values.Get(index).Number())
		if slices.Contains(own, reason) {
			continue
		}
		found = append(found, reason)
	}
	if len(found) != count {
		t.Fatalf("protocol.Reason carries %d refusals this package does not produce itself and this test needs %d", len(found), count)
	}
	return found
}
