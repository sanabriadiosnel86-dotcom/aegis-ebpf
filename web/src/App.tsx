import { useCallback, useMemo, useRef, useState } from "react";
import { SEVERITIES, type AuditEvent, type Severity } from "./types";
import { useEventStream, type ConnectionState } from "./useEventStream";
import { SeverityCounters } from "./components/SeverityCounters";
import { EventFeed } from "./components/EventFeed";
import { Graph } from "./components/Graph";

const FEED_LIMIT = 300; // events kept in the feed
const GRAPH_WINDOW = 60; // most recent events fed to the graph

function emptyCounts(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

export default function App() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [counts, setCounts] = useState<Record<Severity, number>>(emptyCounts);
  const total = useRef(0);
  const [totalSeen, setTotalSeen] = useState(0);

  const onEvent = useCallback((ev: AuditEvent) => {
    setEvents((prev) => {
      const next = [ev, ...prev];
      return next.length > FEED_LIMIT ? next.slice(0, FEED_LIMIT) : next;
    });
    setCounts((prev) => {
      const sev = SEVERITIES.includes(ev.severity) ? ev.severity : "info";
      return { ...prev, [sev]: prev[sev] + 1 };
    });
    total.current += 1;
    setTotalSeen(total.current);
  }, []);

  const connection = useEventStream(onEvent);
  const graphEvents = useMemo(() => events.slice(0, GRAPH_WINDOW), [events]);

  return (
    <div className="flex h-full flex-col">
      <Header connection={connection} />
      <main className="flex flex-1 flex-col gap-4 overflow-hidden p-4">
        <SeverityCounters counts={counts} total={totalSeen} />
        <div className="grid flex-1 grid-cols-1 gap-4 overflow-hidden lg:grid-cols-2">
          <Panel title="Live audit feed" subtitle={`${events.length} shown`}>
            <EventFeed events={events} />
          </Panel>
          <Panel title="Process graph" subtitle={`last ${graphEvents.length} events`}>
            <Graph events={graphEvents} />
          </Panel>
        </div>
      </main>
    </div>
  );
}

function Header({ connection }: { connection: ConnectionState }) {
  return (
    <header className="flex items-center gap-3 border-b border-slate-800 bg-slate-900/60 px-4 py-3">
      <div className="flex items-center gap-2">
        <ShieldIcon />
        <div>
          <h1 className="font-semibold tracking-tight text-slate-100">Aegis-eBPF</h1>
          <p className="text-xs text-slate-500">Runtime audit console</p>
        </div>
      </div>
      <div className="ml-auto">
        <ConnectionBadge connection={connection} />
      </div>
    </header>
  );
}

function ConnectionBadge({ connection }: { connection: ConnectionState }) {
  const map = {
    open: { label: "Live", dot: "bg-emerald-400", text: "text-emerald-300" },
    connecting: { label: "Connecting", dot: "bg-amber-400 animate-pulse", text: "text-amber-300" },
    closed: { label: "Disconnected", dot: "bg-rose-500", text: "text-rose-300" },
  }[connection];
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-1 text-xs ${map.text}`}
    >
      <span className={`h-2 w-2 rounded-full ${map.dot}`} />
      {map.label}
    </span>
  );
}

function Panel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="flex min-h-0 flex-col rounded-xl border border-slate-800 bg-slate-900/40">
      <div className="flex items-baseline justify-between border-b border-slate-800 px-4 py-2">
        <h2 className="text-sm font-medium text-slate-200">{title}</h2>
        {subtitle && <span className="font-mono text-xs text-slate-500">{subtitle}</span>}
      </div>
      <div className="min-h-0 flex-1">{children}</div>
    </section>
  );
}

function ShieldIcon() {
  return (
    <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3Z"
        stroke="#38bdf8"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path d="m9 12 2 2 4-4" stroke="#38bdf8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
