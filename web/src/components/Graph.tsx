import { useMemo } from "react";
import { type AuditEvent, type Severity, podLabel } from "../types";
import { severityStyle } from "../severity";

interface Props {
  events: AuditEvent[];
}

// The graph relates the three things every event ties together: the pod it
// happened in, the process that caused it, and the syscall the probe saw.
// Nodes are laid out in three columns and linked pod → process → syscall.

const COLUMN_CAP = 9; // nodes kept per column, most recent first
const WIDTH = 760;
const COLUMN_X = { pod: 130, proc: 380, sys: 630 };
const TOP = 34;
const ROW = 40;

type Column = "pod" | "proc" | "sys";

interface Node {
  id: string;
  label: string;
  column: Column;
  severity: Severity;
  x: number;
  y: number;
}

interface Link {
  from: string;
  to: string;
  severity: Severity;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  const order: Severity[] = ["info", "low", "medium", "high", "critical"];
  return order.indexOf(a) >= order.indexOf(b) ? a : b;
}

function buildGraph(events: AuditEvent[]) {
  const nodes = new Map<string, Node>();
  const links = new Map<string, Link>();

  const touchNode = (id: string, label: string, column: Column, severity: Severity) => {
    const existing = nodes.get(id);
    if (existing) {
      existing.severity = maxSeverity(existing.severity, severity);
    } else {
      nodes.set(id, { id, label, column, severity, x: 0, y: 0 });
    }
  };
  const touchLink = (from: string, to: string, severity: Severity) => {
    const key = `${from}\u0000${to}`;
    const existing = links.get(key);
    if (existing) {
      existing.severity = maxSeverity(existing.severity, severity);
    } else {
      links.set(key, { from, to, severity });
    }
  };

  // Events arrive newest-first; the first COLUMN_CAP distinct nodes per
  // column are the freshest.
  for (const ev of events) {
    const podId = `pod:${podLabel(ev)}`;
    const procId = `proc:${ev.node}:${ev.process.pid}`;
    const sysId = `sys:${ev.kind}`;
    touchNode(podId, podLabel(ev), "pod", ev.severity);
    touchNode(procId, `${ev.process.comm}·${ev.process.pid}`, "proc", ev.severity);
    touchNode(sysId, ev.kind, "sys", ev.severity);
    touchLink(podId, procId, ev.severity);
    touchLink(procId, sysId, ev.severity);
  }

  // Keep only the first COLUMN_CAP nodes of each column (insertion order is
  // recency order), and drop links to dropped nodes.
  const byColumn: Record<Column, Node[]> = { pod: [], proc: [], sys: [] };
  for (const node of nodes.values()) {
    if (byColumn[node.column].length < COLUMN_CAP) {
      byColumn[node.column].push(node);
    } else {
      nodes.delete(node.id);
    }
  }

  const layoutColumn = (column: Column) => {
    const list = byColumn[column];
    list.forEach((node, i) => {
      node.x = COLUMN_X[column];
      node.y = TOP + i * ROW;
    });
  };
  layoutColumn("pod");
  layoutColumn("proc");
  layoutColumn("sys");

  const keptLinks = [...links.values()].filter((l) => nodes.has(l.from) && nodes.has(l.to));
  const height = TOP + Math.max(byColumn.pod.length, byColumn.proc.length, byColumn.sys.length, 1) * ROW;
  return { nodes: [...nodes.values()], links: keptLinks, height };
}

export function Graph({ events }: Props) {
  const { nodes, links, height } = useMemo(() => buildGraph(events), [events]);
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  if (events.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-slate-500">
        The process graph appears as events arrive.
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto">
      <svg
        viewBox={`0 0 ${WIDTH} ${Math.max(height, 120)}`}
        className="h-full w-full"
        preserveAspectRatio="xMidYMin meet"
      >
        <ColumnHeaders />
        {links.map((link) => {
          const a = nodeById.get(link.from)!;
          const b = nodeById.get(link.to)!;
          const midX = (a.x + b.x) / 2;
          return (
            <path
              key={`${link.from}-${link.to}`}
              d={`M ${a.x + 60} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${b.x - 60} ${b.y}`}
              fill="none"
              stroke={severityStyle(link.severity).hex}
              strokeWidth={1.2}
              strokeOpacity={0.5}
            />
          );
        })}
        {nodes.map((node) => (
          <GraphNode key={node.id} node={node} />
        ))}
      </svg>
    </div>
  );
}

function GraphNode({ node }: { node: Node }) {
  const style = severityStyle(node.severity);
  return (
    <g>
      <rect
        x={node.x - 60}
        y={node.y - 12}
        width={120}
        height={24}
        rx={6}
        fill="#0f172a"
        stroke={style.hex}
        strokeOpacity={0.7}
      />
      <circle cx={node.x - 48} cy={node.y} r={3} fill={style.hex} />
      <text
        x={node.x - 40}
        y={node.y + 4}
        fill="#cbd5e1"
        fontSize={11}
        fontFamily="ui-monospace, monospace"
      >
        {truncate(node.label, 15)}
      </text>
    </g>
  );
}

function ColumnHeaders() {
  const headers: [Column, string][] = [
    ["pod", "Pods"],
    ["proc", "Processes"],
    ["sys", "Syscalls"],
  ];
  return (
    <g>
      {headers.map(([col, label]) => (
        <text
          key={col}
          x={COLUMN_X[col]}
          y={16}
          textAnchor="middle"
          fill="#64748b"
          fontSize={11}
          fontFamily="ui-monospace, monospace"
          className="uppercase"
        >
          {label}
        </text>
      ))}
    </g>
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
