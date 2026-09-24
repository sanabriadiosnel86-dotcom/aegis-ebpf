//! Conversion of the records written by the eBPF programs into the audit
//! events of api/openapi.yaml.

use std::{
    ffi::CStr,
    fs,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    ptr,
    time::{Duration, SystemTime},
};

use aegis_probe_common::{self as raw, address_family::*, kind, open_flags::*};
use serde::Serialize;

use crate::container::{self, Container};

/// An audit event as the agent ingests it: the `AuditEvent` schema of
/// api/openapi.yaml, without the `id` and `severity` that the agent assigns.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
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
        /// Set when the command line had more arguments than were captured.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        argv_truncated: bool,
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
    NetworkConnect {
        family: &'static str,
        address: String,
        port: u16,
        fd: i32,
    },
    Ptrace {
        request: &'static str,
        request_code: i64,
        /// The `pid` argument as the caller passed it, in the caller's PID
        /// namespace: inside a container it differs from `process.pid`.
        target_pid: i32,
        /// Address argument, as a hexadecimal string.
        addr: String,
    },
}

/// A record of the `EVENTS` ring buffer.
#[derive(Clone, Debug)]
pub enum Record {
    // The records that carry path or argument buffers are boxed: they are
    // several times larger than the others.
    ProcessExec(Box<raw::ProcessExec>),
    FileOpen(Box<raw::FileOpen>),
    PrivilegeEscalation(raw::PrivilegeEscalation),
    NetworkConnect(raw::NetworkConnect),
    Ptrace(raw::Ptrace),
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
unsafe impl Plain for raw::NetworkConnect {}
unsafe impl Plain for raw::Ptrace {}

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
            kind::PROCESS_EXEC => read(bytes).map(|r| Self::ProcessExec(Box::new(r))),
            kind::FILE_OPEN => read(bytes).map(|r| Self::FileOpen(Box::new(r))),
            kind::PRIVILEGE_ESCALATION => read(bytes).map(Self::PrivilegeEscalation),
            kind::NETWORK_CONNECT => read(bytes).map(Self::NetworkConnect),
            kind::PTRACE => read(bytes).map(Self::Ptrace),
            _ => None,
        }
    }

    fn header(&self) -> &raw::EventHeader {
        match self {
            Self::ProcessExec(r) => &r.header,
            Self::FileOpen(r) => &r.header,
            Self::PrivilegeEscalation(r) => &r.header,
            Self::NetworkConnect(r) => &r.header,
            Self::Ptrace(r) => &r.header,
        }
    }
}

/// Turns records into audit events, enriched from `/proc`.
pub struct Converter {
    node: String,
    /// Wall-clock time of the boot, to convert `CLOCK_BOOTTIME` timestamps.
    boot_time: SystemTime,
    proc_root: PathBuf,
    containers_only: bool,
    /// PID of this probe, whose own activity (such as its connections to the
    /// agent) is not audited: reporting it would feed back into itself.
    own_pid: u32,
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
            own_pid: std::process::id(),
        }
    }

    /// Converts a record, or returns None when the event must be dropped.
    pub fn convert(&self, record: &Record) -> Option<AuditEvent> {
        let header = record.header();
        if header.pid == self.own_pid {
            return None;
        }
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
                let filename = c_string(&r.filename);
                // The kernel reports an empty path when it cannot read it.
                if filename.is_empty() {
                    return None;
                }
                (
                    "process_exec",
                    Data::ProcessExec {
                        filename,
                        argv: parse_args(&r.args, r.argc),
                        argv_truncated: r.argv_truncated != 0,
                    },
                )
            }
            Record::FileOpen(r) => {
                let path = c_string(&r.path);
                if path.is_empty() {
                    return None;
                }
                (
                    "file_open",
                    Data::FileOpen {
                        path,
                        flags: flag_names(r.flags),
                    },
                )
            }
            Record::PrivilegeEscalation(r) => (
                "privilege_escalation",
                Data::PrivilegeEscalation {
                    syscall: syscall_name(r.syscall_nr)?,
                    old_uid: r.old_uid,
                    new_uid: r.new_uid,
                },
            ),
            Record::NetworkConnect(r) => {
                let (family, address) = format_address(r.family, &r.addr)?;
                (
                    "network_connect",
                    Data::NetworkConnect {
                        family,
                        address,
                        port: r.port,
                        fd: r.fd,
                    },
                )
            }
            Record::Ptrace(r) => (
                "ptrace",
                Data::Ptrace {
                    request: ptrace_request_name(r.request),
                    request_code: r.request,
                    target_pid: r.target_pid,
                    addr: format!("{:#x}", r.addr),
                },
            ),
        };
        let time = self.boot_time + Duration::from_nanos(header.boot_ns);
        Some(AuditEvent {
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

/// Decodes the arguments the eBPF program stored, one NUL-terminated string
/// per slot. `argc` comes from the kernel but is bounded all the same.
fn parse_args(slots: &[[u8; raw::ARG_LEN]; raw::MAX_ARGV], argc: u32) -> Vec<String> {
    let argc = (argc as usize).min(raw::MAX_ARGV);
    slots[..argc].iter().map(|slot| c_string(slot)).collect()
}

/// Formats a connection address; None for families the probe does not report.
fn format_address(family: u16, addr: &[u8; raw::ADDR_LEN]) -> Option<(&'static str, String)> {
    match family {
        AF_INET => {
            let v4 = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            Some(("ipv4", v4.to_string()))
        }
        AF_INET6 => Some(("ipv6", Ipv6Addr::from(*addr).to_string())),
        _ => None,
    }
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

/// Names a `ptrace(2)` request. Unknown requests keep their code in
/// `request_code`.
fn ptrace_request_name(request: i64) -> &'static str {
    match request {
        1 => "PTRACE_PEEKTEXT",
        2 => "PTRACE_PEEKDATA",
        3 => "PTRACE_PEEKUSER",
        4 => "PTRACE_POKETEXT",
        5 => "PTRACE_POKEDATA",
        6 => "PTRACE_POKEUSER",
        7 => "PTRACE_CONT",
        8 => "PTRACE_KILL",
        9 => "PTRACE_SINGLESTEP",
        #[cfg(target_arch = "x86_64")]
        12 => "PTRACE_GETREGS",
        #[cfg(target_arch = "x86_64")]
        13 => "PTRACE_SETREGS",
        16 => "PTRACE_ATTACH",
        17 => "PTRACE_DETACH",
        24 => "PTRACE_SYSCALL",
        0x4200 => "PTRACE_SETOPTIONS",
        0x4201 => "PTRACE_GETEVENTMSG",
        0x4202 => "PTRACE_GETSIGINFO",
        0x4203 => "PTRACE_SETSIGINFO",
        0x4204 => "PTRACE_GETREGSET",
        0x4205 => "PTRACE_SETREGSET",
        0x4206 => "PTRACE_SEIZE",
        0x4207 => "PTRACE_INTERRUPT",
        0x4208 => "PTRACE_LISTEN",
        _ => "PTRACE_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        mem::size_of,
        process,
        sync::atomic::{AtomicU32, Ordering},
    };

    use serde_json::json;

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

    /// Lays `args` out in the argv slots the eBPF program fills.
    fn argv(args: &[&str]) -> ([[u8; raw::ARG_LEN]; raw::MAX_ARGV], u32) {
        let mut slots = [[0; raw::ARG_LEN]; raw::MAX_ARGV];
        for (slot, arg) in slots.iter_mut().zip(args) {
            slot[..arg.len()].copy_from_slice(arg.as_bytes());
        }
        (slots, args.len() as u32)
    }

    fn exec(pid: u32, filename: &str, args: &[&str]) -> raw::ProcessExec {
        let (args, argc) = argv(args);
        raw::ProcessExec {
            header: header(kind::PROCESS_EXEC, pid),
            filename: path(filename),
            args,
            argc,
            argv_truncated: 0,
        }
    }

    fn connect(family: u16, addr: [u8; raw::ADDR_LEN], port: u16) -> raw::NetworkConnect {
        raw::NetworkConnect {
            header: header(kind::NETWORK_CONNECT, 42),
            fd: 3,
            family,
            port,
            addr,
        }
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
        root
    }

    fn container_converter() -> (Converter, PathBuf) {
        let proc_root = fake_proc(
            42,
            &format!("0::/system.slice/docker-{CONTAINER_ID}.scope\n"),
        );
        let boot = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let converter = Converter::new("worker-1".into(), boot, proc_root.clone(), true);
        (converter, proc_root)
    }

    #[test]
    fn parses_every_record_kind() {
        let records: [Vec<u8>; 5] = [
            bytes_of(&exec(42, "/bin/sh", &["sh"])),
            bytes_of(&raw::FileOpen {
                header: header(kind::FILE_OPEN, 42),
                flags: O_WRONLY,
                _pad: 0,
                path: path("/etc/passwd"),
            }),
            bytes_of(&raw::PrivilegeEscalation {
                header: header(kind::PRIVILEGE_ESCALATION, 42),
                syscall_nr: libc::SYS_setuid as u32,
                old_uid: 1000,
                new_uid: 0,
                _pad: 0,
            }),
            bytes_of(&connect(AF_INET, [0; raw::ADDR_LEN], 443)),
            bytes_of(&raw::Ptrace {
                header: header(kind::PTRACE, 42),
                request: 16,
                target_pid: 7,
                _pad: 0,
                addr: 0,
            }),
        ];
        for bytes in &records {
            let record = Record::parse(bytes).expect("a known, complete record");
            assert_eq!(record.header().pid, 42);
            assert!(
                Record::parse(&bytes[..size_of::<raw::EventHeader>()]).is_none(),
                "a truncated record is rejected"
            );
        }
        let mut unknown = exec(42, "/bin/sh", &[]);
        unknown.header.kind = 99;
        assert!(Record::parse(&bytes_of(&unknown)).is_none(), "unknown kind");
    }

    #[test]
    fn serializes_process_exec() {
        let (converter, proc_root) = container_converter();
        let record = Record::ProcessExec(Box::new(exec(
            42,
            "/usr/bin/curl",
            &["curl", "-s", "example.com"],
        )));
        let ev = serde_json::to_value(converter.convert(&record).unwrap()).unwrap();
        assert_eq!(
            ev,
            json!({
                "kind": "process_exec",
                "time": "2026-09-21T14:13:21.500000000Z",
                "node": "worker-1",
                "process": {"pid": 42, "ppid": 4100, "uid": 0, "gid": 0, "comm": "sh", "cgroup_id": 7},
                "container": {"id": CONTAINER_ID, "runtime": "docker"},
                "data": {"filename": "/usr/bin/curl", "argv": ["curl", "-s", "example.com"]},
            })
        );

        // A command line longer than the captured slots is flagged.
        let mut long = exec(42, "/bin/echo", &["echo"; raw::MAX_ARGV]);
        long.argv_truncated = 1;
        let ev = serde_json::to_value(
            converter
                .convert(&Record::ProcessExec(Box::new(long)))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ev["data"]["argv"].as_array().unwrap().len(), raw::MAX_ARGV);
        assert_eq!(ev["data"]["argv_truncated"], json!(true));

        // An unreadable path yields no event.
        let empty = Record::ProcessExec(Box::new(exec(42, "", &[])));
        assert!(converter.convert(&empty).is_none());
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn serializes_network_connect() {
        let (converter, proc_root) = container_converter();
        let mut v4 = [0; raw::ADDR_LEN];
        v4[..4].copy_from_slice(&[10, 0, 0, 7]);
        let ev = serde_json::to_value(
            converter
                .convert(&Record::NetworkConnect(connect(AF_INET, v4, 443)))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ev["kind"], json!("network_connect"));
        assert_eq!(
            ev["data"],
            json!({"family": "ipv4", "address": "10.0.0.7", "port": 443, "fd": 3})
        );

        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        let ev = serde_json::to_value(
            converter
                .convert(&Record::NetworkConnect(connect(AF_INET6, v6, 8443)))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            ev["data"],
            json!({"family": "ipv6", "address": "2001:db8::1", "port": 8443, "fd": 3})
        );

        // Families other than IPv4 and IPv6 are not reported.
        assert!(
            converter
                .convert(&Record::NetworkConnect(connect(1, v4, 0)))
                .is_none()
        );
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn serializes_ptrace() {
        let (converter, proc_root) = container_converter();
        let record = Record::Ptrace(raw::Ptrace {
            header: header(kind::PTRACE, 42),
            request: 4, // PTRACE_POKETEXT
            target_pid: 1234,
            _pad: 0,
            addr: 0x7ffd_1000,
        });
        let ev = serde_json::to_value(converter.convert(&record).unwrap()).unwrap();
        assert_eq!(ev["kind"], json!("ptrace"));
        assert_eq!(
            ev["data"],
            json!({
                "request": "PTRACE_POKETEXT",
                "request_code": 4,
                "target_pid": 1234,
                "addr": "0x7ffd1000",
            })
        );
        assert_eq!(ptrace_request_name(0x4206), "PTRACE_SEIZE");
        assert_eq!(ptrace_request_name(0x7777), "PTRACE_UNKNOWN");
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn serializes_file_and_privilege_events() {
        let (converter, proc_root) = container_converter();
        let open = Record::FileOpen(Box::new(raw::FileOpen {
            header: header(kind::FILE_OPEN, 42),
            flags: O_WRONLY | O_CREAT | O_TRUNC | 0o2000000, // | O_CLOEXEC
            _pad: 0,
            path: path("/etc/passwd"),
        }));
        let ev = serde_json::to_value(converter.convert(&open).unwrap()).unwrap();
        assert_eq!(
            ev["data"],
            json!({"path": "/etc/passwd", "flags": ["O_WRONLY", "O_CREAT", "O_TRUNC"]})
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
            json!({"syscall": "setresuid", "old_uid": 1000, "new_uid": 0})
        );
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn filters_host_processes() {
        let proc_root = fake_proc(7, "0::/user.slice/session-2.scope\n");
        let record = Record::ProcessExec(Box::new(exec(7, "/usr/bin/id", &["id"])));
        let boot = SystemTime::UNIX_EPOCH;
        let containers_only = Converter::new("n".into(), boot, proc_root.clone(), true);
        assert!(containers_only.convert(&record).is_none());
        let everything = Converter::new("n".into(), boot, proc_root.clone(), false);
        let ev = everything.convert(&record).unwrap();
        assert!(ev.container.is_none());
        // Processes that already exited are converted without enrichment.
        let gone = Record::ProcessExec(Box::new(exec(8, "/usr/bin/id", &["id"])));
        let ev = everything.convert(&gone).unwrap();
        assert!(ev.process.ppid.is_none() && ev.container.is_none());
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn ignores_its_own_activity() {
        let proc_root = fake_proc(42, "0::/\n");
        let converter =
            Converter::new("n".into(), SystemTime::UNIX_EPOCH, proc_root.clone(), false);
        let mut own = connect(AF_INET, [0; raw::ADDR_LEN], 8080);
        own.header.pid = process::id();
        assert!(converter.convert(&Record::NetworkConnect(own)).is_none());
        let other = connect(AF_INET, [0; raw::ADDR_LEN], 8080);
        assert!(converter.convert(&Record::NetworkConnect(other)).is_some());
        fs::remove_dir_all(proc_root).unwrap();
    }

    #[test]
    fn parses_helpers() {
        assert_eq!(parse_ppid("42 (a) b) S 7 42 42"), Some(7));
        assert_eq!(parse_ppid("garbage"), None);
        let (slots, _) = argv(&["a", "", "c"]);
        assert_eq!(parse_args(&slots, 3), ["a", "", "c"]);
        // A corrupt argc cannot read past the slots.
        assert_eq!(parse_args(&slots, 1000).len(), raw::MAX_ARGV);
    }
}
