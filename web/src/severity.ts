import type { Severity } from "./types";

// Colors for each severity, as Tailwind classes and a raw hex for SVG.
interface Style {
  dot: string;
  text: string;
  badge: string;
  ring: string;
  hex: string;
}

const STYLES: Record<Severity, Style> = {
  info: {
    dot: "bg-sky-400",
    text: "text-sky-400",
    badge: "bg-sky-500/10 text-sky-300 ring-1 ring-inset ring-sky-500/30",
    ring: "ring-sky-500/40",
    hex: "#38bdf8",
  },
  low: {
    dot: "bg-emerald-400",
    text: "text-emerald-400",
    badge: "bg-emerald-500/10 text-emerald-300 ring-1 ring-inset ring-emerald-500/30",
    ring: "ring-emerald-500/40",
    hex: "#34d399",
  },
  medium: {
    dot: "bg-amber-400",
    text: "text-amber-400",
    badge: "bg-amber-500/10 text-amber-300 ring-1 ring-inset ring-amber-500/30",
    ring: "ring-amber-500/40",
    hex: "#fbbf24",
  },
  high: {
    dot: "bg-orange-400",
    text: "text-orange-400",
    badge: "bg-orange-500/10 text-orange-300 ring-1 ring-inset ring-orange-500/30",
    ring: "ring-orange-500/40",
    hex: "#fb923c",
  },
  critical: {
    dot: "bg-rose-500",
    text: "text-rose-400",
    badge: "bg-rose-500/10 text-rose-300 ring-1 ring-inset ring-rose-500/40",
    ring: "ring-rose-500/50",
    hex: "#f43f5e",
  },
};

export function severityStyle(sev: Severity): Style {
  return STYLES[sev] ?? STYLES.info;
}
