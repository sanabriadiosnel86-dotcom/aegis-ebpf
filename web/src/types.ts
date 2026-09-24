// AuditEvent mirrors the JSON the agent streams on /v1/stream, which is the
// AuditEvent schema of api/openapi.yaml.

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const KINDS = [
  "process_exec",
  "file_open",
  "privilege_escalation",
  "network_connect",
  "ptrace",
] as const;
export type Kind = (typeof KINDS)[number];

export interface Process {
  pid: number;
  ppid?: number;
  uid: number;
  gid: number;
  comm: string;
  cgroup_id?: number;
}

export interface Pod {
  name?: string;
  namespace?: string;
  uid?: string;
}

export interface Container {
  id: string;
  runtime?: string;
  name?: string;
  pod?: Pod;
}

export interface AuditEvent {
  id: string;
  kind: Kind | string;
  time: string;
  node: string;
  severity: Severity;
  process: Process;
  container?: Container;
  data: Record<string, unknown>;
}

// summarizeData renders the kind-specific payload as a short, readable line.
export function summarizeData(ev: AuditEvent): string {
  const d = ev.data ?? {};
  switch (ev.kind) {
    case "process_exec": {
      const argv = (d.argv as string[]) ?? [];
      const line = argv.length > 0 ? argv.join(" ") : String(d.filename ?? "");
      return d.argv_truncated ? `${line} …` : line;
    }
    case "file_open":
      return `${d.path} [${((d.flags as string[]) ?? []).join(", ")}]`;
    case "privilege_escalation":
      return `${d.syscall}: uid ${d.old_uid} → ${d.new_uid}`;
    case "network_connect":
      return `→ ${d.address}:${d.port} (${d.family})`;
    case "ptrace":
      return `${d.request} pid ${d.target_pid} @ ${d.addr}`;
    default:
      return JSON.stringify(d);
  }
}

// podLabel is the "namespace/pod" of an event, or its container id, or "host".
export function podLabel(ev: AuditEvent): string {
  const pod = ev.container?.pod;
  if (pod?.name) {
    return pod.namespace ? `${pod.namespace}/${pod.name}` : pod.name;
  }
  if (ev.container?.id) {
    return `container ${ev.container.id.slice(0, 12)}`;
  }
  return "host";
}
