package peer

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// One peer for the whole fuzz process.
//
// Built once and shared, because a fuzz target that stood up a pair of connect clients per input
// would spend its whole budget on wiring. It has a connect client with no route attached: nothing
// below reaches the send path, and the dispatch, the reassembly and the descriptor walks are what
// the inbound surface actually is.
var fuzzPeer = sync.OnceValue(func() *Peer {
	client := connect.NewClient(context.Background(), connect.NewId(), connect.NewNoContractClientOob(), connect.DefaultClientSettings())
	connections, err := NewConnections(rand.Reader, time.Now, 0)
	if err != nil {
		panic(err)
	}
	checks, err := NewChecks(connections, DefaultMaxRequestBytes)
	if err != nil {
		panic(err)
	}
	handler := &recordingHandler{front: checks}
	served, err := New(Config{
		Client:          client,
		Handler:         handler,
		Connections:     connections,
		Checks:          checks,
		Capabilities:    &protocol.Capabilities{},
		ProtocolVersion: fixtureProtocolVersion,
		ServerId:        make([]byte, 16),
	})
	if err != nil {
		panic(err)
	}
	return served
})

// The seed corpus: one well-formed request per served arm, one per arm nothing serves, and the
// shapes a decoder is most often walked into.
func seedInbound(f *testing.F) {
	f.Helper()
	bodies := []proto.Message{
		&protocol.HelloRequest{SupportedVersions: []uint32{fixtureProtocolVersion}},
		&protocol.SubmitRequest{GroupId: make([]byte, 32)},
		&protocol.FetchRequest{GroupId: make([]byte, 32), ReadEpoch: 3},
		&protocol.CreateGroupRequest{GroupId: make([]byte, 32)},
		&protocol.SubscribeRequest{},
		&protocol.RendezvousDepositRequest{},
	}
	for index, body := range bodies {
		request := &protocol.MessageServerRequest{RequestId: uint64(index + 1), ProtocolVersion: fixtureProtocolVersion}
		if err := setRequestBody(request, body); err != nil {
			f.Fatalf("setRequestBody: %v", err)
		}
		encoded, err := proto.Marshal(request)
		if err != nil {
			f.Fatalf("Marshal: %v", err)
		}
		f.Add(encoded, false, false)
		f.Add(encoded, true, false)
	}
	// a request with no body at all, an empty frame, a truncated one, and bytes that are not a
	// protobuf in any reading
	empty, _ := proto.Marshal(&protocol.MessageServerRequest{RequestId: 7})
	f.Add(empty, false, false)
	f.Add([]byte{}, false, false)
	f.Add([]byte{0x08}, false, false)
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, false, false)
	f.Add([]byte{0x08, 0x01, 0x52, 0x02, 0x08, 0x01}, true, false)
	f.Add([]byte{0x08, 0x01, 0x10, 0x00, 0x18, 0x02, 0x22, 0x01, 0x41}, true, false)
	f.Add([]byte{0x01, 0x02, 0x03}, false, true)
}

// Nothing an attacker can put in a frame reaches a panic, and every request that decodes is
// answered under its own `request_id`.
//
// This is the outermost layer of a network service and every byte here was chosen by whoever
// addressed the frame, so a panic on any of them is an availability bug reachable by anybody who
// can address one. The two properties are asserted together because the interesting failures are
// in the second: a dispatcher that returned nil for an arm it did not recognise, or that answered
// under a request_id it invented, would not panic and would still be broken.
//
// `raw` and `fragmented` are fuzzed alongside the bytes so that all three inbound shapes of §4.2
// and §4.6 are reached: a request frame, a request frame marked raw when §4.2 says this binding
// never marks one, and a fragment frame.
func FuzzTheInboundFrameSurfaceRefusesRatherThanPanics(f *testing.F) {
	seedInbound(f)
	served := fuzzPeer()
	clientId := connect.NewId()

	f.Fuzz(func(t *testing.T, body []byte, fragmented bool, raw bool) {
		frame := &protocol.Frame{MessageBytes: body, Raw: raw}

		if fragmented {
			frame.MessageType = protocol.MessageType_MessageMessageServerFragment
			fragment, decoded := decodeFragment(frame)
			if !decoded {
				return
			}
			assembled, reason := served.reassembly.accept(clientId, fragment)
			if reason != protocol.Reason_REASON_OK && assembled != nil {
				t.Fatalf("a refused fragment answered %v and handed back %d bytes to dispatch anyway", reason, len(assembled))
			}
			if served.maxRequestBytes < len(assembled) {
				t.Fatalf("reassembly answered %d bytes against a %d byte cap", len(assembled), served.maxRequestBytes)
			}
			return
		}

		frame.MessageType = protocol.MessageType_MessageMessageServerRequest
		arrived, request, decoded := decodeRequest(clientId, frame)
		if !decoded {
			// a frame that does not decode is dropped rather than answered, because a response
			// has to carry a request_id and there is not one to carry
			return
		}
		response := served.answer(context.Background(), arrived, request)
		if response == nil {
			t.Fatal("a request that decoded was answered with no response at all")
		}
		if response.GetRequestId() != request.GetRequestId() {
			t.Fatalf("a request with request_id %d was answered under %d", request.GetRequestId(), response.GetRequestId())
		}
		if response.GetReason() == protocol.Reason_REASON_OK && request.ProtoReflect().WhichOneof(bodyOneofOf(request.ProtoReflect().Descriptor())) == nil {
			t.Fatal("a request with no body at all was answered REASON_OK")
		}
	})
}

// A zero value of a generated message, found by name in the registry protoc-gen-go registered it
// in. Not dynamicpb: the oneof arms of the generated MessageServerResponse hold generated
// messages, and a dynamic one placed in one of them is a panic rather than a test.
func newMessageOf(t *testing.T, name protoreflect.FullName) proto.Message {
	t.Helper()
	found, err := protoregistry.GlobalTypes.FindMessageByName(name)
	if err != nil {
		t.Fatalf("the registry has no %s: %v", name, err)
	}
	return found.New().Interface()
}

// Placing a handler's answer in the response oneof never panics and never lands in another arm.
//
// [setResponseBody] is reached with whatever a handler returns, and it finds the arm by matching
// the body's own message name against the descriptor. What must not happen is that a message
// which is not an arm of the response oneof is quietly dropped into one — an answer in the wrong
// arm is a response the client parses as another operation's.
func FuzzTheResponseArmIsTheOneThatHoldsTheBodysType(f *testing.F) {
	f.Add(uint64(1), 0)
	f.Add(uint64(0), 3)
	f.Add(^uint64(0), 7)

	arms := bodyArmsOf((&protocol.MessageServerResponse{}).ProtoReflect().Descriptor())
	f.Fuzz(func(t *testing.T, requestId uint64, which int) {
		response := &protocol.MessageServerResponse{RequestId: requestId}
		if which < 0 {
			which = -which
		}
		// half the inputs get a message that is an arm of the response oneof, and half get one
		// that is an arm of the *request* oneof and therefore of no response arm at all
		requestArms := bodyArmsOf((&protocol.MessageServerRequest{}).ProtoReflect().Descriptor())
		var body proto.Message
		wanted := true
		if which%2 == 0 {
			body = newMessageOf(t, arms[(which/2)%len(arms)].Message().FullName())
		} else {
			body = newMessageOf(t, requestArms[(which/2)%len(requestArms)].Message().FullName())
			// a handful of §4.3's messages are named identically on both sides, and those do
			// have a response arm; whether this one does is read from the descriptor rather
			// than guessed
			wanted = false
			for _, arm := range arms {
				if arm.Message().FullName() == body.ProtoReflect().Descriptor().FullName() {
					wanted = true
				}
			}
		}

		err := setResponseBody(response, body)
		if wanted != (err == nil) {
			t.Fatalf("setResponseBody(%s) answered err %v, and the response oneof %s an arm for it",
				body.ProtoReflect().Descriptor().FullName(), err, map[bool]string{true: "has", false: "has not"}[wanted])
		}
		if response.GetRequestId() != requestId {
			t.Fatalf("placing a body changed the request_id from %d to %d", requestId, response.GetRequestId())
		}
		if err != nil {
			return
		}
		field := response.ProtoReflect().WhichOneof(bodyOneofOf(response.ProtoReflect().Descriptor()))
		if field == nil {
			t.Fatal("setResponseBody answered no error and set no arm")
		}
		if field.Message().FullName() != body.ProtoReflect().Descriptor().FullName() {
			t.Fatalf("a %s was placed in the %s arm", body.ProtoReflect().Descriptor().FullName(), field.Message().FullName())
		}
	})
}
