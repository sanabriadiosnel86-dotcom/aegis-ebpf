//! Types shared by the eBPF programs of Aegis-eBPF and the user-space probe.
//!
//! The kernel side writes one of the `#[repr(C)]` structs below per event to
//! the `EVENTS` ring buffer. Every struct starts with an [`EventHeader`] whose
//! `kind` tells which one it is.
#![cfg_attr(not(test), no_std)]

/// Size of the task name (`task_struct::comm`), NUL terminator included.
pub const TASK_COMM_LEN: usize = 16;

/// Bytes captured from a path, NUL terminator included. Longer paths are
/// truncated.
pub const MAX_PATH_LEN: usize = 512;

/// Bytes captured from a single command-line argument, NUL terminator
/// included. Longer arguments are truncated.
pub const ARG_LEN: usize = 128;

/// Number of command-line arguments captured from an `execve(2)`. It is a
/// power of two so the eBPF program can index the buffer with a masked,
/// verifier-friendly offset.
pub const MAX_ARGV: usize = 16;

/// Bytes of an IP address: 4 for IPv4 (in the first four), 16 for IPv6.
pub const ADDR_LEN: usize = 16;

/// Values of [`EventHeader::kind`].
pub mod kind {
    /// [`ProcessExec`](super::ProcessExec).
    pub const PROCESS_EXEC: u32 = 1;
    /// [`FileOpen`](super::FileOpen).
    pub const FILE_OPEN: u32 = 2;
    /// [`PrivilegeEscalation`](super::PrivilegeEscalation).
    pub const PRIVILEGE_ESCALATION: u32 = 3;
    /// [`NetworkConnect`](super::NetworkConnect).
    pub const NETWORK_CONNECT: u32 = 4;
    /// [`Ptrace`](super::Ptrace).
    pub const PTRACE: u32 = 5;
}

/// `open(2)` flags. Their values are the same on x86_64 and aarch64.
pub mod open_flags {
    pub const O_ACCMODE: u32 = 0o3;
    pub const O_RDONLY: u32 = 0o0;
    pub const O_WRONLY: u32 = 0o1;
    pub const O_RDWR: u32 = 0o2;
    pub const O_CREAT: u32 = 0o100;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;

    /// Reports whether `flags` open a file with the intent to modify it.
    pub const fn is_write_intent(flags: u32) -> bool {
        flags & O_ACCMODE != O_RDONLY || flags & (O_CREAT | O_TRUNC) != 0
    }
}

/// Socket address families, as `sa_family_t` reports them.
pub mod address_family {
    pub const AF_INET: u16 = 2;
    pub const AF_INET6: u16 = 10;
}

/// Fields shared by every event.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    /// One of the constants of [`kind`].
    pub kind: u32,
    /// Thread-group ID of the task, i.e. its user-space PID.
    pub pid: u32,
    /// Real user ID of the task.
    pub uid: u32,
    /// Real group ID of the task.
    pub gid: u32,
    /// ID of the task's cgroup in the unified (v2) hierarchy.
    pub cgroup_id: u64,
    /// `CLOCK_BOOTTIME` timestamp of the event, in nanoseconds.
    pub boot_ns: u64,
    /// NUL-terminated task name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// A process asked to replace its image with `execve(2)`.
///
/// The event is reported at syscall entry, so `header.comm` is the name of
/// the calling process (for example a shell), while `filename` is the program
/// it is about to run.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessExec {
    pub header: EventHeader,
    /// NUL-terminated path of the new image.
    pub filename: [u8; MAX_PATH_LEN],
    /// The first [`MAX_ARGV`] arguments, each a NUL-terminated string in its
    /// own slot. Unused slots begin with a NUL.
    pub args: [[u8; ARG_LEN]; MAX_ARGV],
    /// Number of arguments stored in `args`.
    pub argc: u32,
    /// Non-zero when the command line had more than [`MAX_ARGV`] arguments.
    pub argv_truncated: u32,
}

/// A file was opened with write intent.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileOpen {
    pub header: EventHeader,
    /// Flags passed to `openat(2)`.
    pub flags: u32,
    pub _pad: u32,
    /// NUL-terminated path passed to `openat(2)`.
    pub path: [u8; MAX_PATH_LEN],
}

/// A `setuid(2)`-family call changed the real UID of a process to root.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrivilegeEscalation {
    pub header: EventHeader,
    /// Architecture-specific number of the syscall.
    pub syscall_nr: u32,
    /// Real UID before the call.
    pub old_uid: u32,
    /// Real UID after the call.
    pub new_uid: u32,
    pub _pad: u32,
}

/// A process started an outbound connection with `connect(2)` to an IPv4 or
/// IPv6 address.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NetworkConnect {
    pub header: EventHeader,
    /// The socket's file descriptor.
    pub fd: i32,
    /// Address family: [`address_family::AF_INET`] or `AF_INET6`.
    pub family: u16,
    /// Destination port, in host byte order.
    pub port: u16,
    /// Destination address in network byte order: IPv4 in the first four
    /// bytes, IPv6 in all sixteen.
    pub addr: [u8; ADDR_LEN],
}

/// A process called `ptrace(2)`, which can read or write another process's
/// memory and registers, a common step of code injection.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Ptrace {
    pub header: EventHeader,
    /// The `request` argument, i.e. the ptrace operation.
    pub request: i64,
    /// The `pid` argument: the process the caller wants to manipulate.
    pub target_pid: i32,
    pub _pad: u32,
    /// The `addr` argument, the target address of a peek or poke.
    pub addr: u64,
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::{open_flags::*, *};

    #[test]
    fn layouts_fit_the_ring_buffer() {
        // The kernel reserves ring buffer records on 8-byte boundaries, so
        // every record must have an alignment of at most 8.
        assert_eq!(size_of::<EventHeader>(), 48);
        for (size, align) in [
            (size_of::<ProcessExec>(), align_of::<ProcessExec>()),
            (size_of::<FileOpen>(), align_of::<FileOpen>()),
            (
                size_of::<PrivilegeEscalation>(),
                align_of::<PrivilegeEscalation>(),
            ),
            (size_of::<NetworkConnect>(), align_of::<NetworkConnect>()),
            (size_of::<Ptrace>(), align_of::<Ptrace>()),
        ] {
            assert_eq!(size % 8, 0, "size {size} is not a multiple of 8");
            assert!(align <= 8, "alignment {align} exceeds 8");
        }
    }

    #[test]
    fn write_intent() {
        assert!(!is_write_intent(O_RDONLY));
        assert!(!is_write_intent(O_RDONLY | 0o2000000)); // O_CLOEXEC
        assert!(is_write_intent(O_WRONLY));
        assert!(is_write_intent(O_RDWR));
        assert!(is_write_intent(O_RDONLY | O_CREAT));
        assert!(is_write_intent(O_RDONLY | O_TRUNC));
        assert!(is_write_intent(O_WRONLY | O_APPEND));
    }
}
