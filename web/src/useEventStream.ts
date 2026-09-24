import { useEffect, useRef, useState } from "react";
import type { AuditEvent } from "./types";

export type ConnectionState = "connecting" | "open" | "closed";

// streamURL is the agent's /v1/stream WebSocket, on the same origin as the
// page (the agent serves the dashboard; Vite proxies it in development).
function streamURL(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/v1/stream`;
}

// useEventStream keeps a live WebSocket to the agent and calls onEvent for
// every audit event. It reconnects automatically with a capped backoff.
export function useEventStream(onEvent: (ev: AuditEvent) => void): ConnectionState {
  const [state, setState] = useState<ConnectionState>("connecting");
  // Keep the latest callback without reconnecting when it changes.
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let backoff = 500;
    let closed = false;

    const connect = () => {
      setState("connecting");
      socket = new WebSocket(streamURL());

      socket.onopen = () => {
        backoff = 500;
        setState("open");
      };
      socket.onmessage = (msg) => {
        try {
          handler.current(JSON.parse(msg.data) as AuditEvent);
        } catch {
          // Ignore malformed frames rather than break the stream.
        }
      };
      socket.onclose = () => {
        setState("closed");
        if (!closed) {
          reconnectTimer = window.setTimeout(connect, backoff);
          backoff = Math.min(backoff * 2, 10_000);
        }
      };
      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      closed = true;
      window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, []);

  return state;
}
