import { SEVERITIES, type Severity } from "../types";
import { severityStyle } from "../severity";

interface Props {
  counts: Record<Severity, number>;
  total: number;
}

// SeverityCounters shows one tile per severity with a running count.
export function SeverityCounters({ counts, total }: Props) {
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
      <Tile label="Total" value={total} dot="bg-slate-400" text="text-slate-200" />
      {SEVERITIES.map((sev) => {
        const style = severityStyle(sev);
        return (
          <Tile
            key={sev}
            label={sev}
            value={counts[sev] ?? 0}
            dot={style.dot}
            text={style.text}
          />
        );
      })}
    </div>
  );
}

function Tile({
  label,
  value,
  dot,
  text,
}: {
  label: string;
  value: number;
  dot: string;
  text: string;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2">
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${dot}`} />
        <span className="text-xs uppercase tracking-wide text-slate-400">{label}</span>
      </div>
      <div className={`mt-1 font-mono text-2xl tabular-nums ${text}`}>
        {value.toLocaleString()}
      </div>
    </div>
  );
}
