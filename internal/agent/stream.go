package agent

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/sanabriadiosnel86-dotcom/aegis-ebpf/internal/events"
)

// subscriberBuffer bounds how many events a slow subscriber may fall behind
// before the hub drops it, so that one stalled client cannot hold memory.
const subscriberBuffer = 256

// hub fans out ingested events to the WebSocket subscribers of /v1/stream.
type hub struct {
	subscribe   chan chan events.AuditEvent
	unsubscribe chan chan events.AuditEvent
	incoming    chan events.AuditEvent
}

func newHub() *hub {
	h := &hub{
		subscribe:   make(chan chan events.AuditEvent),
		unsubscribe: make(chan chan events.AuditEvent),
		incoming:    make(chan events.AuditEvent, subscriberBuffer),
	}
	go h.run()
	return h
}

// run owns the subscriber set, so the hub needs no mutex.
func (h *hub) run() {
	subscribers := make(map[chan events.AuditEvent]struct{})
	for {
		select {
		case ch := <-h.subscribe:
			subscribers[ch] = struct{}{}
		case ch := <-h.unsubscribe:
			if _, ok := subscribers[ch]; ok {
				delete(subscribers, ch)
				close(ch)
			}
		case ev := <-h.incoming:
			for ch := range subscribers {
				// Never block on a slow subscriber: drop the event for it.
				select {
				case ch <- ev:
				default:
				}
			}
		}
	}
}

// publish hands an event to the hub. It never blocks: when the hub is busy,
// the event is dropped from the live stream (it is still stored and queryable).
func (h *hub) publish(ev events.AuditEvent) {
	select {
	case h.incoming <- ev:
	default:
	}
}

func (h *hub) add() chan events.AuditEvent {
	ch := make(chan events.AuditEvent, subscriberBuffer)
	h.subscribe <- ch
	return ch
}

func (h *hub) remove(ch chan events.AuditEvent) { h.unsubscribe <- ch }

// streamEvents upgrades the request to a WebSocket and streams every event
// ingested from then on, as JSON messages. It is not part of the OpenAPI
// contract, which describes only the request/response endpoints.
func (a *Agent) streamEvents(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The dashboard is served from a different origin in development.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return // Accept already wrote the error response
	}
	defer conn.CloseNow()

	ch := a.stream.add()
	defer a.stream.remove(ch)
	a.log.Debug("stream subscriber connected", "remote", r.RemoteAddr)

	ctx := conn.CloseRead(r.Context()) // watch for the client closing
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return // dropped by the hub
			}
			writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := wsjson.Write(writeCtx, conn, ev)
			cancel()
			if err != nil {
				return
			}
		case <-ping.C:
			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}
