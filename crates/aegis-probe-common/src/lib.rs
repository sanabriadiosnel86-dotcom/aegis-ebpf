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

/// Values of [`EventHeader::kind`].
pub mod kind {
    /// [`ProcessExec`](super::ProcessExec).
    pub const PROCESS_EXEC: u32 = 1;
    /// [`FileOpen`](super::FileOpen).
    pub const FILE_OPEN: u32 = 2;
    /// [`PrivilegeEscalation`](super::PrivilegeEscalation).
    pub const PRIVILEGE_ESCALATION: u32 = 3;
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

/// A process replaced its image with `execve(2)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessExec {
    pub header: EventHeader,
    /// NUL-terminated path of the new image.
    pub filename: [u8; MAX_PATH_LEN],
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

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::{open_flags::*, *};

    #[test]
    fn layouts_fit_the_ring_buffer() {
        // The kernel reserves ring buffer records on 8-byte boundaries.
        assert_eq!(size_of::<EventHeader>(), 48);
        for (size, align) in [
            (size_of::<ProcessExec>(), align_of::<ProcessExec>()),
            (size_of::<FileOpen>(), align_of::<FileOpen>()),
            (
                size_of::<PrivilegeEscalation>(),
                align_of::<PrivilegeEscalation>(),
            ),
        ] {
            assert_eq!(size % 8, 0);
            assert!(align <= 8);
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
