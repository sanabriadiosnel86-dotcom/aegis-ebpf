//! eBPF programs of the Aegis-eBPF probe: read-only audit telemetry.
//!
//! Every program is strictly passive. It is attached to a tracepoint, reads
//! the syscall arguments with `bpf_probe_read_*`, and writes only to this
//! probe's own maps. None of them writes user memory, blocks or alters a
//! syscall, or signals a process: the audited system behaves exactly as it
//! would without the probe.
//!
//! Each program reports its records to user space through `EVENTS`, a
//! `BPF_MAP_TYPE_RINGBUF`, as the structs of `aegis_probe_common`. Records are
//! written in place, in memory reserved in the ring buffer: they never touch
//! the 512-byte eBPF stack.
//!
//! The field offsets below come from
//! `/sys/kernel/tracing/events/<category>/<name>/format`. Tracepoints are a
//! stable kernel interface, so they do not need BTF relocations.
#![no_std]
#![no_main]

use aegis_probe_common::{
    ADDR_LEN, ARG_LEN, EventHeader, FileOpen, MAX_ARGV, MAX_PATH_LEN, NetworkConnect,
    PrivilegeEscalation, ProcessExec, Ptrace, TASK_COMM_LEN,
    address_family::{AF_INET, AF_INET6},
    kind,
    open_flags::{O_CREAT, O_TRUNC, O_WRONLY, is_write_intent},
};
use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user,
        generated::{
            bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_ktime_get_boot_ns,
            bpf_probe_read_user_str,
        },
    },
    macros::{map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::TracePointContext,
};

/// Audit records for user space: a 1 MiB `BPF_MAP_TYPE_RINGBUF`, shared by
/// every CPU so that records keep their order.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

/// Real UID of the tasks inside a setuid-family syscall, by pid_tgid. Tasks
/// killed during the syscall never reach its exit; the LRU policy evicts
/// their entries.
#[map]
static SETUID_CALLS: LruHashMap<u64, u32> = LruHashMap::with_max_entries(16384, 0);

/// syscalls/sys_enter_execve: `const char *filename`.
const EXECVE_FILENAME: usize = 16;
/// syscalls/sys_enter_execve: `const char *const *argv`.
const EXECVE_ARGV: usize = 24;
/// syscalls/sys_enter_openat and sys_enter_openat2: `const char *filename`.
const OPENAT_FILENAME: usize = 24;
/// syscalls/sys_enter_openat: `int flags`, in an 8-byte slot.
const OPENAT_FLAGS: usize = 32;
/// syscalls/sys_enter_openat2: `struct open_how *how`, whose first member is
/// `__u64 flags`.
const OPENAT2_HOW: usize = 32;
/// syscalls/sys_enter_open and sys_enter_creat: `const char *filename`.
const OPEN_FILENAME: usize = 16;
/// syscalls/sys_enter_open: `int flags`, in an 8-byte slot.
const OPEN_FLAGS: usize = 24;
/// syscalls/sys_enter_connect: `int fd`, in an 8-byte slot.
const CONNECT_FD: usize = 16;
/// syscalls/sys_enter_connect: `struct sockaddr *uservaddr`.
const CONNECT_ADDR: usize = 24;
/// syscalls/sys_enter_ptrace: `long request`.
const PTRACE_REQUEST: usize = 16;
/// syscalls/sys_enter_ptrace: `long pid`, the target process.
const PTRACE_PID: usize = 24;
/// syscalls/sys_enter_ptrace: `unsigned long addr`.
const PTRACE_ADDR: usize = 32;
/// syscalls/sys_exit_*: `int __syscall_nr`.
const EXIT_SYSCALL_NR: usize = 8;
/// syscalls/sys_exit_*: `long ret`.
const EXIT_RET: usize = 16;

/// `ptrace(2)` request that makes the caller a tracee; it never touches
/// another process, so it is not reported.
const PTRACE_TRACEME: i64 = 0;
/// Offset of `sin_port`/`sin6_port` in `sockaddr_in`/`sockaddr_in6`.
const SOCKADDR_PORT: usize = 2;
/// Offset of `sin_addr` in `sockaddr_in`.
const SOCKADDR_IN_ADDR: usize = 4;
/// Offset of `sin6_addr` in `sockaddr_in6`.
const SOCKADDR_IN6_ADDR: usize = 8;

/// Attached to syscalls/sys_enter_execve: a process is about to run a new
/// program. Captures the program path and its arguments.
#[tracepoint]
pub fn aegis_execve(ctx: TracePointContext) -> u32 {
    let filename = unsafe { ctx.read_at::<*const u8>(EXECVE_FILENAME) };
    let argv = unsafe { ctx.read_at::<*const *const u8>(EXECVE_ARGV) };
    let (Ok(filename), Ok(argv)) = (filename, argv) else {
        return 0;
    };
    let Some(mut entry) = EVENTS.reserve::<ProcessExec>(0) else {
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).header, kind::PROCESS_EXEC);
        bpf_probe_read_user_str(
            (&raw mut (*ev).filename).cast(),
            MAX_PATH_LEN as u32,
            filename.cast(),
        );
        let (argc, truncated) = read_argv(argv, (&raw mut (*ev).args).cast());
        (*ev).argc = argc;
        (*ev).argv_truncated = truncated;
    }
    entry.submit(0);
    0
}

/// Reads up to [`MAX_ARGV`] arguments from the user-space `argv` array into
/// `slots` (the first element of `ProcessExec::args`), NUL-terminating each.
/// Returns the number of arguments stored and whether the command line held
/// more.
#[inline(always)]
unsafe fn read_argv(argv: *const *const u8, slots: *mut [u8; ARG_LEN]) -> (u32, u32) {
    let mut argc: u32 = 0;
    for i in 0..MAX_ARGV {
        // Mask the index so the verifier can prove the store is in bounds.
        let slot = unsafe { slots.add(i & (MAX_ARGV - 1)) };
        let Ok(argp) = (unsafe { bpf_probe_read_user::<*const u8>(argv.add(i)) }) else {
            break;
        };
        if argp.is_null() {
            break;
        }
        unsafe {
            (*slot)[0] = 0; // empty string if the read below fails
            bpf_probe_read_user_str(slot.cast(), ARG_LEN as u32, argp.cast());
        }
        argc += 1;
    }
    let mut truncated = 0;
    if argc == MAX_ARGV as u32
        && let Ok(argp) = (unsafe { bpf_probe_read_user::<*const u8>(argv.add(MAX_ARGV)) })
        && !argp.is_null()
    {
        truncated = 1;
    }
    (argc, truncated)
}

/// Attached to syscalls/sys_enter_connect: an outbound connection to an IPv4
/// or IPv6 address.
#[tracepoint]
pub fn aegis_connect(ctx: TracePointContext) -> u32 {
    let fd = unsafe { ctx.read_at::<u64>(CONNECT_FD) };
    let uservaddr = unsafe { ctx.read_at::<*const u8>(CONNECT_ADDR) };
    let (Ok(fd), Ok(uservaddr)) = (fd, uservaddr) else {
        return 0;
    };
    if uservaddr.is_null() {
        return 0;
    }
    let Ok(family) = (unsafe { bpf_probe_read_user::<u16>(uservaddr.cast()) }) else {
        return 0;
    };
    if family != AF_INET && family != AF_INET6 {
        return 0;
    }
    let Ok(be_port) = (unsafe { bpf_probe_read_user::<u16>(uservaddr.add(SOCKADDR_PORT).cast()) })
    else {
        return 0;
    };
    let Some(mut entry) = EVENTS.reserve::<NetworkConnect>(0) else {
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).header, kind::NETWORK_CONNECT);
        (*ev).fd = fd as i32;
        (*ev).family = family;
        (*ev).port = u16::from_be(be_port);
        (*ev).addr = [0u8; ADDR_LEN];
        if family == AF_INET {
            if let Ok(v4) = bpf_probe_read_user::<[u8; 4]>(uservaddr.add(SOCKADDR_IN_ADDR).cast()) {
                (*ev).addr[0] = v4[0];
                (*ev).addr[1] = v4[1];
                (*ev).addr[2] = v4[2];
                (*ev).addr[3] = v4[3];
            }
        } else if let Ok(v6) =
            bpf_probe_read_user::<[u8; ADDR_LEN]>(uservaddr.add(SOCKADDR_IN6_ADDR).cast())
        {
            (*ev).addr = v6;
        }
    }
    entry.submit(0);
    0
}

/// Attached to syscalls/sys_enter_ptrace: a process is inspecting or altering
/// another process, a common step of code injection.
#[tracepoint]
pub fn aegis_ptrace(ctx: TracePointContext) -> u32 {
    let Ok(request) = (unsafe { ctx.read_at::<i64>(PTRACE_REQUEST) }) else {
        return 0;
    };
    if request == PTRACE_TRACEME {
        return 0;
    }
    let target = unsafe { ctx.read_at::<i64>(PTRACE_PID) }.unwrap_or(0);
    let addr = unsafe { ctx.read_at::<u64>(PTRACE_ADDR) }.unwrap_or(0);
    let Some(mut entry) = EVENTS.reserve::<Ptrace>(0) else {
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).header, kind::PTRACE);
        (*ev).request = request;
        (*ev).target_pid = target as i32;
        (*ev)._pad = 0;
        (*ev).addr = addr;
    }
    entry.submit(0);
    0
}

/// Attached to syscalls/sys_enter_openat.
#[tracepoint]
pub fn aegis_openat(ctx: TracePointContext) -> u32 {
    let filename = unsafe { ctx.read_at::<*const u8>(OPENAT_FILENAME) };
    let flags = unsafe { ctx.read_at::<u64>(OPENAT_FLAGS) };
    match (filename, flags) {
        (Ok(filename), Ok(flags)) => report_open(filename, flags as u32),
        _ => 0,
    }
}

/// Attached to syscalls/sys_enter_openat2.
#[tracepoint]
pub fn aegis_openat2(ctx: TracePointContext) -> u32 {
    let filename = unsafe { ctx.read_at::<*const u8>(OPENAT_FILENAME) };
    let how = unsafe { ctx.read_at::<*const u64>(OPENAT2_HOW) };
    match (
        filename,
        how.and_then(|how| unsafe { bpf_probe_read_user(how) }),
    ) {
        (Ok(filename), Ok(flags)) => report_open(filename, flags as u32),
        _ => 0,
    }
}

/// Attached to syscalls/sys_enter_open, which x86_64 keeps and musl libc
/// still uses.
#[tracepoint]
pub fn aegis_open(ctx: TracePointContext) -> u32 {
    let filename = unsafe { ctx.read_at::<*const u8>(OPEN_FILENAME) };
    let flags = unsafe { ctx.read_at::<u64>(OPEN_FLAGS) };
    match (filename, flags) {
        (Ok(filename), Ok(flags)) => report_open(filename, flags as u32),
        _ => 0,
    }
}

/// Attached to syscalls/sys_enter_creat, on the architectures that have it.
#[tracepoint]
pub fn aegis_creat(ctx: TracePointContext) -> u32 {
    let Ok(filename) = (unsafe { ctx.read_at::<*const u8>(OPEN_FILENAME) }) else {
        return 0;
    };
    report_open(filename, O_WRONLY | O_CREAT | O_TRUNC)
}

/// Reports an open of the user-space path `filename` with `flags`, if they
/// express write intent.
#[inline(always)]
fn report_open(filename: *const u8, flags: u32) -> u32 {
    if !is_write_intent(flags) {
        return 0;
    }
    let Some(mut entry) = EVENTS.reserve::<FileOpen>(0) else {
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).header, kind::FILE_OPEN);
        (*ev).flags = flags;
        (*ev)._pad = 0;
        bpf_probe_read_user_str(
            (&raw mut (*ev).path).cast(),
            MAX_PATH_LEN as u32,
            filename.cast(),
        );
    }
    entry.submit(0);
    0
}

/// Attached to syscalls/sys_enter_{setuid,setreuid,setresuid}: remembers the
/// real UID of non-root callers until the syscall returns.
#[tracepoint]
pub fn aegis_setuid_enter(_ctx: TracePointContext) -> u32 {
    let uid = bpf_get_current_uid_gid() as u32;
    if uid != 0 {
        let _ = SETUID_CALLS.insert(bpf_get_current_pid_tgid(), uid, 0);
    }
    0
}

/// Attached to syscalls/sys_exit_{setuid,setreuid,setresuid}: reports the
/// calls that succeeded in making a non-root task root.
#[tracepoint]
pub fn aegis_setuid_exit(ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(old_uid) = (unsafe { SETUID_CALLS.get(pid_tgid) }).copied() else {
        return 0;
    };
    let _ = SETUID_CALLS.remove(pid_tgid);
    let new_uid = bpf_get_current_uid_gid() as u32;
    let ret = unsafe { ctx.read_at::<i64>(EXIT_RET) }.unwrap_or(-1);
    if ret != 0 || new_uid != 0 {
        return 0;
    }
    let Ok(syscall_nr) = (unsafe { ctx.read_at::<i32>(EXIT_SYSCALL_NR) }) else {
        return 0;
    };
    let Some(mut entry) = EVENTS.reserve::<PrivilegeEscalation>(0) else {
        return 0;
    };
    let ev = entry.as_mut_ptr();
    unsafe {
        fill_header(&raw mut (*ev).header, kind::PRIVILEGE_ESCALATION);
        (*ev).syscall_nr = syscall_nr as u32;
        (*ev).old_uid = old_uid;
        (*ev).new_uid = new_uid;
        (*ev)._pad = 0;
    }
    entry.submit(0);
    0
}

/// Fills the header of an event reserved in `EVENTS` with the identity of
/// the current task.
#[inline(always)]
unsafe fn fill_header(h: *mut EventHeader, kind: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    unsafe {
        (*h).kind = kind;
        (*h).pid = (pid_tgid >> 32) as u32;
        (*h).uid = uid_gid as u32;
        (*h).gid = (uid_gid >> 32) as u32;
        (*h).cgroup_id = bpf_get_current_cgroup_id();
        (*h).boot_ns = bpf_ktime_get_boot_ns();
        bpf_get_current_comm((&raw mut (*h).comm).cast(), TASK_COMM_LEN as u32);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The kernel only lets programs with a GPL-compatible license call helpers
/// such as bpf_probe_read_user_str.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
