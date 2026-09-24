//! aegis-probe loads the eBPF programs of Aegis-eBPF, attaches them to their
//! tracepoints and forwards their audit events to aegis-agent.
//!
//! The probe is read-only: it observes syscalls and never alters the audited
//! system. The one exception, mounting tracefs when the host has not, only
//! happens with `--mount-tracefs`.

use std::{
    ffi::CString,
    io::Write as _,
    path::{Path, PathBuf},
    time::Duration,
};

use aegis_probe::event::{self, AuditEvent, Converter, Record};
use anyhow::{Context as _, anyhow};
use aya::{
    Ebpf,
    maps::{MapData, RingBuf},
    programs::TracePoint,
};
use clap::Parser;
use log::{debug, info, warn};
use serde::Serialize;
use tokio::{
    io::unix::AsyncFd,
    signal::unix::{SignalKind, signal},
    sync::mpsc,
    time::{Instant, timeout_at},
};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// Events endpoint of aegis-agent; "-" prints the events to stdout as
    /// JSON lines instead.
    #[arg(
        long,
        env = "AEGIS_AGENT_URL",
        default_value = "http://127.0.0.1:8080/v1/events"
    )]
    agent_url: String,
    /// Node name reported in every event [default: the hostname].
    #[arg(long, env = "NODE_NAME")]
    node_name: Option<String>,
    /// Also report processes that do not run in a container.
    #[arg(long)]
    all_processes: bool,
    /// Maximum number of events per request to the agent.
    #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u16).range(1..=1000))]
    batch_size: u16,
    /// Maximum time an event waits for its batch to fill up.
    #[arg(long, default_value = "500ms", value_parser = humantime::parse_duration)]
    flush_interval: Duration,
    /// Where the procfs of the host is mounted.
    #[arg(long, default_value = "/proc")]
    proc_root: PathBuf,
    /// Mount tracefs on /sys/kernel/tracing when it is missing. Off by
    /// default, so that the probe changes nothing on the host.
    #[arg(long)]
    mount_tracefs: bool,
}

/// Tracepoints of each eBPF program.
const PROGRAMS: [(&str, &[(&str, &str)]); 9] = [
    ("aegis_execve", &[("syscalls", "sys_enter_execve")]),
    ("aegis_connect", &[("syscalls", "sys_enter_connect")]),
    ("aegis_ptrace", &[("syscalls", "sys_enter_ptrace")]),
    ("aegis_openat", &[("syscalls", "sys_enter_openat")]),
    ("aegis_openat2", &[("syscalls", "sys_enter_openat2")]),
    ("aegis_open", &[("syscalls", "sys_enter_open")]),
    ("aegis_creat", &[("syscalls", "sys_enter_creat")]),
    (
        "aegis_setuid_enter",
        &[
            ("syscalls", "sys_enter_setuid"),
            ("syscalls", "sys_enter_setreuid"),
            ("syscalls", "sys_enter_setresuid"),
        ],
    ),
    (
        "aegis_setuid_exit",
        &[
            ("syscalls", "sys_exit_setuid"),
            ("syscalls", "sys_exit_setreuid"),
            ("syscalls", "sys_exit_setresuid"),
        ],
    ),
];

/// Tracepoints that some kernels lack: aarch64 has neither open(2) nor
/// creat(2), and openat2(2) appeared in Linux 5.6.
const OPTIONAL_TRACEPOINTS: [&str; 3] = ["sys_enter_open", "sys_enter_creat", "sys_enter_openat2"];

/// Capacity of the queue between the ring buffer reader and the forwarder.
const QUEUE_LEN: usize = 8192;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let node = match opt.node_name {
        Some(name) => name,
        None => std::fs::read_to_string("/proc/sys/kernel/hostname")
            .context("reading the hostname; set --node-name")?
            .trim()
            .to_owned(),
    };
    if node.is_empty() || node.chars().count() > 253 {
        return Err(anyhow!("the node name must have 1 to 253 characters"));
    }
    let sink = Sink::new(&opt.agent_url)?;

    bump_memlock_rlimit();
    ensure_tracefs(opt.mount_tracefs)?;
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aegis-probe"
    )))
    .context("loading the eBPF programs")?;
    for (name, tracepoints) in PROGRAMS {
        attach(&mut ebpf, name, tracepoints)?;
    }
    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("map EVENTS not found")?)?;
    let converter = Converter::new(
        node.clone(),
        event::boot_time().context("reading CLOCK_BOOTTIME")?,
        opt.proc_root,
        !opt.all_processes,
    );

    let (tx, rx) = mpsc::channel(QUEUE_LEN);
    let mut reader = tokio::spawn(read_events(ring, converter, tx));
    let forwarder = tokio::spawn(forward(rx, sink, opt.batch_size.into(), opt.flush_interval));
    info!(
        "aegis-probe {} watching node {node}; sending events to {}",
        env!("CARGO_PKG_VERSION"),
        opt.agent_url
    );

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
        res = &mut reader => return res?.context("reading the ring buffer"),
    }
    info!("shutting down");
    // Stopping the reader closes the queue: the forwarder sends the events
    // left in it, then returns.
    reader.abort();
    drop(ebpf);
    if tokio::time::timeout(Duration::from_secs(5), forwarder)
        .await
        .is_err()
    {
        warn!("gave up sending the last events");
    }
    Ok(())
}

fn attach(ebpf: &mut Ebpf, name: &str, tracepoints: &[(&str, &str)]) -> anyhow::Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(name)
        .with_context(|| format!("program {name} not found"))?
        .try_into()?;
    program.load().with_context(|| format!("loading {name}"))?;
    for (category, tracepoint) in tracepoints {
        match program.attach(category, tracepoint) {
            Ok(_) => {}
            Err(err) if OPTIONAL_TRACEPOINTS.contains(tracepoint) => {
                info!("skipping {category}/{tracepoint}, which this kernel lacks: {err}");
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("attaching {name} to {category}/{tracepoint}"));
            }
        }
    }
    Ok(())
}

/// Reads the ring buffer until the programs are detached, and queues the
/// events for the forwarder. Drops events when the queue is full rather than
/// stall the ring buffer.
async fn read_events(
    ring: RingBuf<MapData>,
    converter: Converter,
    tx: mpsc::Sender<AuditEvent>,
) -> anyhow::Result<()> {
    let mut ring = AsyncFd::new(ring)?;
    let mut dropped = 0u64;
    loop {
        let mut guard = ring.readable_mut().await?;
        let ring = guard.get_inner_mut();
        while let Some(item) = ring.next() {
            let Some(event) = Record::parse(&item).and_then(|r| converter.convert(&r)) else {
                continue;
            };
            if tx.try_send(event).is_err() {
                dropped += 1;
                if dropped.is_power_of_two() {
                    warn!("dropped {dropped} events so far: the agent does not keep up");
                }
            }
        }
        guard.clear_ready();
    }
}

/// Sends the queued events in batches of at most `batch_size`, waiting at
/// most `flush_interval` for a batch to fill up.
async fn forward(
    mut rx: mpsc::Receiver<AuditEvent>,
    sink: Sink,
    batch_size: usize,
    flush_interval: Duration,
) {
    let mut batch = Vec::with_capacity(batch_size);
    while rx.recv_many(&mut batch, batch_size).await > 0 {
        let deadline = Instant::now() + flush_interval;
        while batch.len() < batch_size {
            let room = batch_size - batch.len();
            match timeout_at(deadline, rx.recv_many(&mut batch, room)).await {
                Ok(n) if n > 0 => {}
                _ => break,
            }
        }
        sink.send(&batch).await;
        batch.clear();
    }
}

/// Destination of the events.
enum Sink {
    Stdout,
    Agent {
        client: reqwest::Client,
        url: reqwest::Url,
    },
}

#[derive(Serialize)]
struct Batch<'a> {
    events: &'a [AuditEvent],
}

impl Sink {
    fn new(url: &str) -> anyhow::Result<Self> {
        if url == "-" {
            return Ok(Self::Stdout);
        }
        let url = reqwest::Url::parse(url).with_context(|| format!("invalid --agent-url {url}"))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self::Agent { client, url })
    }

    /// Sends a batch. The agent rejects invalid batches as a whole; failed
    /// batches are logged and dropped.
    async fn send(&self, events: &[AuditEvent]) {
        match self {
            Self::Stdout => {
                let mut out = std::io::stdout().lock();
                for event in events {
                    let _ = serde_json::to_writer(&mut out, event);
                    let _ = out.write_all(b"\n");
                }
                let _ = out.flush();
            }
            Self::Agent { client, url } => {
                match client
                    .post(url.clone())
                    .json(&Batch { events })
                    .send()
                    .await
                {
                    Ok(res) if res.status().is_success() => debug!("sent {} events", events.len()),
                    Ok(res) => {
                        let status = res.status();
                        let body = res.text().await.unwrap_or_default();
                        warn!(
                            "the agent rejected {} events with {status}: {body}",
                            events.len()
                        );
                    }
                    Err(err) => warn!("sending {} events to the agent: {err}", events.len()),
                }
            }
        }
    }
}

/// Lifts the locked memory limit, which bounds eBPF maps on kernels older
/// than 5.11 (see https://lwn.net/Articles/837122/).
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: rlim is a valid rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        debug!(
            "removing the limit on locked memory failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Makes sure tracefs, which attaching tracepoints needs, is available.
/// Containers get a fresh /sys without it. Only with `mount` does the probe
/// mount it; otherwise it just checks, and changes nothing on the host.
fn ensure_tracefs(mount: bool) -> anyhow::Result<()> {
    const TRACEFS: &str = "/sys/kernel/tracing";
    if Path::new(TRACEFS).join("events").exists()
        || Path::new("/sys/kernel/debug/tracing/events").exists()
    {
        return Ok(());
    }
    if !mount {
        return Err(anyhow!(
            "tracefs is not mounted on {TRACEFS}: mount it \
             (mount -t tracefs nodev {TRACEFS}) or pass --mount-tracefs"
        ));
    }
    let (source, target) = (
        CString::new("tracefs").unwrap(),
        CString::new(TRACEFS).unwrap(),
    );
    // SAFETY: the arguments are valid NUL-terminated strings.
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            source.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mounting tracefs on {TRACEFS}"));
    }
    info!("mounted tracefs on {TRACEFS}");
    Ok(())
}
