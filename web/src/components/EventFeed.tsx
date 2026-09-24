import { memo } from "react";
import { type AuditEvent, podLabel, summarizeData } from "../types";
import { severityStyle } from "../severity";

interface Props {
  events: AuditEvent[];
}

// EventFeed lists the most recent events, newest first.
export const EventFeed = memo(function EventFeed({ events }: Props) {
  if (events.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-slate-500">
        Waiting for audit events…
      </div>
    );
  }
  return (
    <ul className="scroll-slim h-full divide-y divide-slate-800/70 overflow-y-auto">
      {events.map((ev) => (
        <EventRow key={ev.id} ev={ev} />
      ))}
    </ul>
  );
});

function EventRow({ ev }: { ev: AuditEvent }) {
  const style = severityStyle(ev.severity);
  const time = ev.time.slice(11, 23); // HH:MM:SS.mmm
  return (
    <li className="animate-fade-in px-3 py-2 hover:bg-slate-800/30">
      <div className="flex items-center gap-2 text-xs">
        <span className={`rounded px-1.5 py-0.5 font-medium uppercase ${style.badge}`}>
          {ev.severity}
        </span>
        <span className="font-mono text-slate-300">{ev.kind}</span>
        <span className="ml-auto font-mono text-slate-500">{time}</span>
      </div>
      <div className="mt-1 truncate font-mono text-sm text-slate-200" title={summarizeData(ev)}>
        {summarizeData(ev)}
      </div>
      <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
        <span className="text-slate-400">{ev.process.comm}</span>
        <span>pid {ev.process.pid}</span>
        <span>·</span>
        <span className="truncate">{podLabel(ev)}</span>
        <span className="ml-auto">{ev.node}</span>
      </div>
    </li>
  );
}
