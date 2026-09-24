//! Conversion of the records written by the eBPF programs into the events of
//! api/openapi.yaml.

use std::{
    ffi::CStr,
    fs,
    mem::size_of,
    path::PathBuf,
    ptr,
    time::{Duration, SystemTime},
};

use aegis_probe_common::{self as raw, kind, open_flags::*};
use serde::Serialize;

use crate::container::{self, Container};

/// An event as the agent ingests it: the `Event` schema of api/openapi.yaml,
/// without the `id` and `severity` that the agent assigns.
#[derive(Debug, Serialize)]
pub struct Event {
    pub kind: &'static str,
    /// RFC 3339 timestamp, with nanoseconds.
    pub time: String,
    pub node: String,
    pub process: Process,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
    pub data: Data,
}

#[derive(Debug, Serialize)]
pub struct Process {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub uid: u32,
    pub gid: u32,
    pub comm: String,
    pub cgroup_id: u64,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Data {
    ProcessExec {
        filename: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        argv: Vec<String>,
    },
    FileOpen {
        path: String,
        flags: Vec<&'static str>,
    },
    PrivilegeEscalation {
        syscall: &'static str,
        old_uid: u32,
        new_uid: u32,
    },
}

/// A record of the `EVENTS` ring buffer.
#[derive(Clone, Copy, Debug)]
pub enum Record {
    ProcessExec(raw::ProcessExec),
    FileOpen(raw::FileOpen),
    PrivilegeEscalation(raw::PrivilegeEscalation),
}

/// Marks the records that are valid for any bit pattern.
///
/// # Safety
///
/// Implementors must only hold integers and arrays of integers.
unsafe trait Plain: Copy {}
unsafe impl Plain for raw::EventHeader {}
unsafe impl Plain for raw::ProcessExec {}
unsafe impl Plain for raw::FileOpen {}
unsafe impl Plain for raw::PrivilegeEscalation {}

fn read<T: Plain>(bytes: &[u8]) -> Option<T> {
    // SAFETY: the length is checked and any bit pattern is a valid T.
    (bytes.len() >= size_of::<T>())
        .then(|| unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

impl Record {
    /// Decodes a record of the ring buffer; None if it is truncated or of an
    /// unknown kind.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        match read::<raw::EventHeader>(bytes)?.kind {
            kind::PROCESS_EXEC => read(bytes).map(Self::ProcessExec),
            kind::FILE_OPEN => read(bytes).map(Self::FileOpen),
            kind::PRIVILEGE_ESCALATION => read(bytes).map(Self::PrivilegeEscalation),
            _ => None,
        }
    }

    fn header(&self) -> &raw::EventHeader {
        match self {
            Self::ProcessExec(r) => &r.header,
            Self::FileOpen(r) => &r.header,
            Self::PrivilegeEscalation(r) => &r.header,
        }
    }
}

/// Turns records into events, enriched from `/proc`.
pub struct Converter {
    node: String,
    /// Wall-clock time of the boot, to convert `CLOCK_BOOTTIME` timestamps.
    boot_time: SystemTime,
    proc_root: PathBuf,
    containers_only: bool,
}

impl Converter {
    /// Returns a converter that stamps events with `node`, reads process
    /// details under `proc_root` and, when `containers_only`, drops the
    /// events of processes that run outside containers.
    pub fn new(
        node: String,
        boot_time: SystemTime,
        proc_root: PathBuf,
        containers_only: bool,
    ) -> Self {
        Self {
            node,
            boot_time,
            proc_root,
            containers_only,
        }
    }

    /// Converts a record, or returns None when the event must be dropped.
    pub fn convert(&self, record: &Record) -> Option<Event> {
        let header = record.header();
        let proc_dir = self.proc_root.join(header.pid.to_string());
        // Short-lived processes may be gone already: enrichment is best effort.
        let container = fs::read_to_string(proc_dir.join("cgroup"))
            .ok()
            .and_then(|c| container::from_proc_cgroup(&c));
        if self.containers_only && container.is_none() {
            return None;
        }
        let (kind, data) = match record {
            Record::ProcessExec(r) => {
                let argv = fs::read(proc_dir.join("cmdline"))
                    .map(|b| parse_cmdline(&b))
                    .unwrap_or_default();
                let filename = c_string(&r.filename);
                ("process_exec", Data::ProcessExec { filename, argv })
            }
            Record::FileOpen(r) => (
                "file_open",
                Data::FileOpen {
                    path: c_string(&r.path),
                    flags: flag_names(r.flags),
                },
            ),
            Record::PrivilegeEscalation(r) => (
                "privilege_escalation",
                Data::PrivilegeEscalation {
                    syscall: syscall_name(r.syscall_nr)?,
                    old_uid: r.old_uid,
                    new_uid: r.new_uid,
                },
            ),
        };
        // The kernel reports empty strings when it cannot read a path.
        if matches!(&data, Data::ProcessExec { filename: p, .. } | Data::FileOpen { path: p, .. } if p.is_empty())
        {
            return None;
        }
        let time = self.boot_time + Duration::from_nanos(header.boot_ns);
        Some(Event {
            kind,
            time: humantime::format_rfc3339_nanos(time).to_string(),
            node: self.node.clone(),
            process: Process {
                pid: header.pid,
                ppid: fs::read_to_string(proc_dir.join("stat"))
                    .ok()
                    .and_then(|s| parse_ppid(&s)),
                uid: header.uid,
                gid: header.gid,
                comm: c_string(&header.comm),
                cgroup_id: header.cgroup_id,
            },
            container,
            data,
        })
    }
}

/// Returns the wall-clock time at which the system booted, which converts
/// `CLOCK_BOOTTIME` timestamps into wall-clock ones.
pub fn boot_time() -> std::io::Result<SystemTime> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let now = SystemTime::now();
    // SAFETY: ts is a valid timespec to write to.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let uptime = Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
    Ok(now - uptime)
}

fn c_string(bytes: &[u8]) -> String {
    CStr::from_bytes_until_nul(bytes)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

/// Splits `/proc/<pid>/cmdline` into arguments, keeping at most the 256 that
/// api/openapi.yaml allows.
fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    bytes
        .strip_suffix(b"\0")
        .unwrap_or(bytes)
        .split(|&b| b == 0)
        .take(256)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

/// Extracts the parent PID from `/proc/<pid>/stat`. The command name, in
/// parentheses, may contain spaces and parentheses itself.
fn parse_ppid(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn flag_names(flags: u32) -> Vec<&'static str> {
    let mut names = vec![match flags & O_ACCMODE {
        O_WRONLY => "O_WRONLY",
        O_RDWR => "O_RDWR",
        _ => "O_RDONLY",
    }];
    for (flag, name) in [
        (O_CREAT, "O_CREAT"),
        (O_TRUNC, "O_TRUNC"),
        (O_APPEND, "O_APPEND"),
    ] {
        if flags & flag != 0 {
            names.push(name);
        }
    }
    names
}

fn syscall_name(nr: u32) -> Option<&'static str> {
    match i64::from(nr) {
        libc::SYS_setuid => Some("setuid"),
        libc::SYS_setreuid => Some("setreuid"),
        libc::SYS_setresuid => Some("setresuid"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        mem::size_of,
        process,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::*;

    const CONTAINER_ID: &str = "2d1f6c4a9e8b7d0c3f5a6b1e4d7c0a9f8e2b5d6c1a4f7e0b3d9c2a5f8e1b4d7c";

    fn header(kind: u32, pid: u32) -> raw::EventHeader {
        let mut comm = [0; raw::TASK_COMM_LEN];
        comm[..2].copy_from_slice(b"sh");
        raw::EventHeader {
            kind,
            pid,
            uid: 0,
            gid: 0,
            cgroup_id: 7,
            boot_ns: 1_500_000_000,
            comm,
        }
    }

    fn path(s: &str) -> [u8; raw::MAX_PATH_LEN] {
        let mut buf = [0; raw::MAX_PATH_LEN];
        buf[..s.len()].copy_from_slice(s.as_bytes());
        buf
    }

    fn bytes_of<T: Plain>(v: &T) -> Vec<u8> {
        // SAFETY: T is plain old data without padding bytes.
        unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }.to_vec()
    }

    /// Creates a fake /proc holding one process.
    fn fake_proc(pid: u32, cgroup: &str) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "aegis-probe-test-{}-{}",
            process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup"), cgroup).unwrap();
        fs::write(
            dir.join("stat"),
            format!("{pid} (my (odd) comm) S 4100 {pid} {pid} 0"),
        )
        .unwrap();
        fs::write(dir.join("cmdline"), b"sh\0-c\0id\0").unwrap();
        root
    }

    #[test]
    fn parses_records() {
        let exec = raw::ProcessExec {
            header: header(kind::PROCESS_EXEC, 42),
            filename: path("/bin/sh"),
        };
        let bytes = bytes_of(&exec);
        assert!(
            matches!(Record::parse(&bytes), Some(Record::ProcessExec(r)) if r.header.pid == 42)
        );
        assert!(
            Record::parse(&bytes[..size_of::<raw::EventHeader>()]).is_none(),
            "truncated record"
        );
        let mut unknown = exec;
        unknown.header.kind = 99;
        assert!(Record::parse(&bytes_of(&unknown)).is_none(), "unknown kind");
    }

    #[test]
    fn converts_container_events() {
        let proc_root = fake_proc(
            42,
            &format!("0::/system.slice/docker-{CONTAINER_ID}.scope\n"),
        );
        let boot = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let converter = Converter::new("worker-1".into(), boot, proc_root.clone(), true);

        let exec = Record::ProcessExec(raw::ProcessExec {
            header: header(kind::PROCESS_EXEC, 42),
            filename: path("/bin/sh"),
        });
        let ev = serde_json::to_value(converter.convert(&exec).unwrap()).unwrap();
        assert_eq!(
            ev,
            serde_json::json!({
                "kind": "process_exec",
                "time": "2026-09-21T14:13:21.500000000Z",
                "node": "worker-1",
                "process": {"pid": 42, "ppid": 4100, "uid": 0, "gid": 0, "comm": "sh", "cgroup_id": 7},
                "container": {"id": CONTAINER_ID, "runtime": "docker"},
                "data": {"filename": "/bin/sh", "argv": ["sh", "-c", "id"]},
            })
        );

        let open = Record::FileOpen(raw::FileOpen {
            header: header(kind::FILE_OPEN, 42),
            flags: O_WRONLY | O_CREAT | O_TRUNC | 0o2000000, // | O_CLOEXEC
            _pad: 0,
            path: path("/etc/passwd"),
        });
        let ev = serde_json::to_value(converter.convert(&open).unwrap()).unwrap();
        assert_eq!(
            ev["data"],
            serde_json::json!({"path": "/etc/passwd", "flags": ["O_WRONLY", "O_CREAT", "O_TRUNC"]})
        );

        let escalation = Record::PrivilegeEscalation(raw::PrivilegeEscalation {
            header: header(kind::PRIVILEGE_ESCALATION, 42),
            syscall_nr: libc::SYS_setresuid as u32,
            old_uid: 1000,
            new_uid: 0,
            _pad: 0,
        });
        let ev = serde_json::to_value(converter.convert(&escalation).unwrap()).unwrap();
        assert_eq!(
            ev["data"],
            serde_json::json!({"syscall": "setresuid", "old_uid": 1000, "new_uid": 0})
        );
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn filters_host_processes() {
        let proc_root = fake_proc(7, "0::/user.slice/session-2.scope\n");
        let record = Record::ProcessExec(raw::ProcessExec {
            header: header(kind::PROCESS_EXEC, 7),
            filename: path("/usr/bin/id"),
        });
        let boot = SystemTime::UNIX_EPOCH;
        let containers_only = Converter::new("n".into(), boot, proc_root.clone(), true);
        assert!(containers_only.convert(&record).is_none());
        let everything = Converter::new("n".into(), boot, proc_root.clone(), false);
        let ev = everything.convert(&record).unwrap();
        assert!(ev.container.is_none());
        // Processes that already exited are converted without enrichment.
        let gone = Record::ProcessExec(raw::ProcessExec {
            header: header(kind::PROCESS_EXEC, 8),
            filename: path("/usr/bin/id"),
        });
        let ev = everything.convert(&gone).unwrap();
        assert!(ev.process.ppid.is_none() && ev.container.is_none());
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn parses_proc_files() {
        assert_eq!(parse_ppid("42 (a) b) S 7 42 42"), Some(7));
        assert_eq!(parse_ppid("garbage"), None);
        assert_eq!(parse_cmdline(b"sh\0-c\0\0x\0"), ["sh", "-c", "", "x"]);
        assert!(parse_cmdline(b"").is_empty());
        assert_eq!(parse_cmdline(&b"a\0".repeat(300)).len(), 256);
    }
}
