//! Kernel ABI constants and structures for `seccomp(SECCOMP_SET_MODE_FILTER)`
//! and the `SECCOMP_IOCTL_NOTIF_*` family.
//!
//! These mirror `<linux/seccomp.h>` and `<linux/sched.h>`. They are
//! `pub(super)` so every notifier submodule can see them — keeping ABI
//! constants in one place avoids drift between (for example) the BPF
//! filter builder and the supervisor's ioctl wrapper.

/// `seccomp(SECCOMP_SET_MODE_FILTER, flags, args)` syscall operation.
pub(super) const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

/// Flag: return a notification fd from `seccomp()`.
pub(super) const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;

/// `SECCOMP_RET_USER_NOTIF` — suspend syscall and notify supervisor.
pub(super) const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

// ioctl numbers for the seccomp notification fd. Architecture-independent
// on Linux.
//
//   _IOWR('!', 0, seccomp_notif)        sizeof=80 → 0xC0502100
//   _IOWR('!', 1, seccomp_notif_resp)   sizeof=24 → 0xC0182101
//   _IOW ('!', 2, u64)                   sizeof=8  → 0x40082102
pub(super) const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
pub(super) const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;
pub(super) const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

// Clone flag constants used by clone()/clone3() filtering.
pub(super) const CLONE_NEWNS: u64 = 0x0002_0000;
pub(super) const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub(super) const CLONE_NEWUTS: u64 = 0x0400_0000;
pub(super) const CLONE_NEWIPC: u64 = 0x0800_0000;
pub(super) const CLONE_NEWUSER: u64 = 0x1000_0000;
pub(super) const CLONE_NEWPID: u64 = 0x2000_0000;
pub(super) const CLONE_NEWNET: u64 = 0x4000_0000;
pub(super) const CLONE_NEWTIME: u64 = 0x0000_0080;

/// All namespace-creating flags that sandboxed processes must not use.
pub(super) const NS_FLAGS_MASK: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWTIME;

// Socket domain/type constants used by socket() filtering.
pub(super) const AF_INET: u64 = libc::AF_INET as u64;
pub(super) const AF_INET6: u64 = libc::AF_INET6 as u64;
pub(super) const AF_UNIX: u64 = libc::AF_UNIX as u64;
pub(super) const AF_NETLINK: u64 = libc::AF_NETLINK as u64;
pub(super) const SOCK_RAW: u64 = libc::SOCK_RAW as u64;

/// Mask out `SOCK_NONBLOCK` / `SOCK_CLOEXEC` from the type argument.
pub(super) const SOCK_TYPE_MASK: u64 = 0x0F;

/// Mirrors `struct seccomp_notif` from `<linux/seccomp.h>`.
///
/// What we receive from `SECCOMP_IOCTL_NOTIF_RECV`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(super) struct SeccompNotif {
    pub(super) id: u64,
    pub(super) pid: u32,
    pub(super) flags: u32,
    pub(super) data: SeccompData,
}

/// Mirrors `struct seccomp_data` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(super) struct SeccompData {
    pub(super) nr: i32,
    pub(super) arch: u32,
    pub(super) instruction_pointer: u64,
    pub(super) args: [u64; 6],
}

/// Mirrors `struct seccomp_notif_resp` from `<linux/seccomp.h>`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(super) struct SeccompNotifResp {
    pub(super) id: u64,
    pub(super) val: i64,
    pub(super) error: i32,
    pub(super) flags: u32,
}

/// Flag for `seccomp_notif_resp.flags`: allow the syscall to proceed.
pub(super) const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// Ensure structs match kernel expectations.
const _: () = {
    assert!(std::mem::size_of::<SeccompNotif>() == 80);
    assert!(std::mem::size_of::<SeccompNotifResp>() == 24);
};
