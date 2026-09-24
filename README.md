# aegis-ebpf

Autonomous Cloud-Native Runtime Security &amp; Self-Healing.

Aegis-eBPF watches what containers do from inside the Linux kernel and turns
dangerous behavior into concrete fixes for the Kubernetes workloads that
caused it: when a container writes to `/etc`, the answer is a patch that mounts
its root filesystem read-only.

```mermaid
flowchart LR
    subgraph kernel[Linux kernel]
        tp[tracepoints<br/>exec · open · setuid] --> rb[(ring buffer)]
    end
    subgraph probe[aegis-probe · Rust + Aya]
        rb --> conv[decode + enrich<br/>from /proc]
    end
    subgraph agent[aegis-agent · Go]
        api[HTTP API] --> rules[rules]
        rules --> rem[(remediations)]
        rem --> fixer[syntactic fixer]
    end
    conv -- "POST /v1/events" --> api
    fixer -- "patched YAML +<br/>JSON Patch" --> user([GitOps / kubectl])
```

## Components

| Path | Language | Role |
| --- | --- | --- |
| [`crates/aegis-probe-ebpf`](crates/aegis-probe-ebpf) | Rust (`no_std`, [Aya](https://aya-rs.dev)) | Passive eBPF programs attached to kernel tracepoints. They write audit records in place into a `BPF_MAP_TYPE_RINGBUF`. |
| [`crates/aegis-probe-common`](crates/aegis-probe-common) | Rust (`no_std`) | `#[repr(C)]` records shared by the kernel and user-space sides. |
| [`crates/aegis-probe`](crates/aegis-probe) | Rust (Aya, Tokio) | Loads and attaches the programs, decodes the records into `AuditEvent`s, resolves the container of each process from `/proc`, and sends them to the agent in batches. |
| [`cmd/aegis-agent`](cmd/aegis-agent) | Go | The control plane: ingests events, classifies them and keeps remediations ([`internal/agent`](internal/agent)). |
| [`internal/fixer`](internal/fixer) | Go | The syntactic engine: rules that map events to hardening plans, and the engine that applies those plans to manifests. |
| [`internal/events`](internal/events) | Go | The `AuditEvent` type, its payloads and their validation. |
| [`api/openapi.yaml`](api/openapi.yaml) | OpenAPI 3.0 | Contract of the events and of the agent API. |

## Audit events and detections

The probe is strictly passive: its eBPF programs only read syscall
arguments and write to the probe's own maps. They never write process
memory, block or alter a syscall, or signal a process.

| Event (`kind`) | Kernel hook | What it records | Rule | Fix proposed for the container |
| --- | --- | --- | --- | --- |
| `process_exec` | `syscalls:sys_enter_execve` | Program path and its first 16 arguments | AEG-001 · root process in a container (medium) | `securityContext.runAsNonRoot: true` |
| `privilege_escalation` | `syscalls:sys_{enter,exit}_set{,re,res}uid` | Syscall and the UIDs before and after | AEG-002 · real UID changed to 0 (critical) | `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]` |
| `file_open` | `syscalls:sys_enter_{openat,openat2,open,creat}` | Path and flags of opens with write intent | AEG-003 · write under `/etc`, `/usr`, `/bin`… (high) | `readOnlyRootFilesystem: true` |
| `network_connect` | `syscalls:sys_enter_connect` | Destination IPv4 or IPv6 address and port | — (audit only) | — |
| `ptrace` | `syscalls:sys_enter_ptrace` | Request, target PID and address | — (audit only) | — |

Only processes that run in a container are reported by default: the probe
recognizes the cgroups of Docker, containerd, CRI-O and Podman, and the pod
UID under Kubernetes. The probe does not audit its own activity. Each rule
opens one remediation per container; later matches increase its
`occurrences`.

## The syntactic fixer

A plan is a list of operations whose paths are relative to the pod spec, so
the same plan fixes a Pod, a Deployment or a CronJob:

```json
{"op": "set", "path": "containers[name=web].securityContext.allowPrivilegeEscalation", "value": false}
{"op": "add", "path": "containers[*].securityContext.capabilities.drop", "value": "ALL"}
```

The engine parses these paths (`segment[selector].segment…`, where a selector
is `*`, an index or `field=value`) and edits the YAML syntax tree of the
manifest rather than re-serializing Go structs:

- comments, key order and quoting survive; the indentation and list style of
  each edited document are detected and kept;
- documents that do not change, such as a `Service` next to the `Deployment`,
  are copied byte for byte;
- every edit is also returned as an RFC 6902 JSON Patch, ready for
  `kubectl patch --type=json`;
- applying a plan twice changes nothing.

## Build

Everything builds in Docker; the host needs Docker Engine 23 or later.

```sh
make            # compile both binaries into ./bin and build both images
make test       # gofmt, go vet, Go tests, rustfmt, clippy, Rust tests, OpenAPI lint
make help       # every target
```

| Target | Result |
| --- | --- |
| `make build` | `bin/aegis-agent` and `bin/aegis-probe` |
| `make images` | `ghcr.io/sanabriadiosnel86-dotcom/aegis-{agent,probe}:<version>` |
| `make test-go` | Go checks, including contract tests that validate every API exchange against `api/openapi.yaml` |
| `make test-rust` | Rust checks |
| `make lint-api` | Redocly lint of the OpenAPI specification |

Set `VERSION`, `REGISTRY` or `BUILD_FLAGS` (e.g. `BUILD_FLAGS=--platform=linux/arm64`)
to override the defaults.

## Run

`make up` starts the agent and the probe on the local Docker host with
[`deploy/compose.yaml`](deploy/compose.yaml). The probe runs privileged in the
PID namespace of the host; it needs Linux 5.8 or later and tracefs mounted on
the host's `/sys/kernel/tracing`, which it reads through a read-only mount.
Where tracefs is missing, `aegis-probe --mount-tracefs` mounts it; the probe
never does so on its own. Then:

```sh
docker run --rm alpine sh -c 'echo pwned > /etc/motd'

curl -s 'http://127.0.0.1:8080/v1/events?min_severity=high'
curl -s  http://127.0.0.1:8080/v1/remediations

# Render a remediation against the manifest of the workload.
curl -s -X POST http://127.0.0.1:8080/v1/remediations/<id>/patch \
  -H 'Content-Type: application/yaml' --data-binary @deployment.yaml
```

`aegis-probe --agent-url -` prints the events as JSON lines instead of sending
them, which helps when working on the probe; `aegis-probe --help` lists its
other options.

## Develop without Docker

- Go 1.26 or later: `go test ./...`
- Rust stable, plus a nightly toolchain with `rust-src` and
  [`bpf-linker`](https://github.com/aya-rs/bpf-linker), which compile the eBPF
  programs: `cargo test`, then `sudo ./target/debug/aegis-probe`.
  Formatting uses nightly rustfmt: `cargo +nightly fmt`.

## Current limits

- The API has no authentication yet: keep the agent on loopback or on a
  network that only the probe reaches.
- Events and remediations live in memory, bounded, and are lost on restart.
- The container of a process is read from `/proc` when its event arrives, so
  events of very short-lived processes may lose it.
- Pod names and container names are not resolved yet; without the container
  name, plans target every container of the pod.
- `process_exec` is recorded when `execve(2)` enters the kernel: attempts that
  fail, such as a program looked up along `PATH`, are recorded too, and
  `process.comm` names the calling process. Arguments are captured up to 16,
  of up to 127 bytes each; `argv_truncated` flags longer command lines.
- The `target_pid` of a `ptrace` event is in the caller's PID namespace, so
  inside a container it differs from the node-level `process.pid`.

## License

MIT. The eBPF programs in `crates/aegis-probe-ebpf` are dual-licensed MIT or
GPL-2.0, as the kernel only lets GPL-compatible programs use helpers such as
`bpf_probe_read_user_str`.
