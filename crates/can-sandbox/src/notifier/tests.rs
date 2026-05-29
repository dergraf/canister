//! Tests for the notifier subsystem: the static BPF prelude (verified by
//! running the real emitted program through a BPF interpreter) and the exec
//! path allow-list. The egress (connect/sendto/sendmsg) and socket/clone
//! tests were removed when those checks left the supervisor — egress is now
//! enforced by the network topology and the register gates by static BPF.

#![allow(clippy::field_reassign_with_default)]

use std::path::{Path, PathBuf};

use super::abi::{
    AF_INET, AF_INET6, AF_NETLINK, AF_UNIX, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET,
    CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS, SOCK_RAW, SeccompData,
};
use super::eval_proc::is_exec_path_allowed;
use super::filter::{FilterPolicy, build_notifier_filter};
use super::policy::NotifierPolicy;

// -----------------------------------------------------------------
// is_exec_path_allowed — exec policy checks
// -----------------------------------------------------------------

fn exec_policy(paths: &[&str], prefixes: &[&str]) -> NotifierPolicy {
    let mut p = NotifierPolicy::default();
    for s in paths {
        p.allowed_exec_paths.insert(PathBuf::from(s));
    }
    for s in prefixes {
        p.allowed_exec_prefixes.push(PathBuf::from(s));
    }
    p
}

#[test]
fn exec_exact_match_allowed() {
    let p = exec_policy(&["/usr/bin/python3.12"], &[]);
    assert!(is_exec_path_allowed(Path::new("/usr/bin/python3.12"), &p));
}

#[test]
fn exec_exact_no_match_denied() {
    let p = exec_policy(&["/usr/bin/python3.12"], &[]);
    assert!(!is_exec_path_allowed(Path::new("/usr/bin/python3.11"), &p));
    assert!(!is_exec_path_allowed(Path::new("/bin/python3.12"), &p));
}

#[test]
fn exec_empty_policy_denies_everything() {
    let p = exec_policy(&[], &[]);
    assert!(!is_exec_path_allowed(Path::new("/usr/bin/sh"), &p));
    assert!(!is_exec_path_allowed(Path::new("/bin/echo"), &p));
}

#[test]
fn exec_prefix_match_with_boundary_allowed() {
    let p = exec_policy(&[], &["/nix/store"]);
    assert!(is_exec_path_allowed(
        Path::new("/nix/store/abc-foo/bin/mix"),
        &p,
    ));
    assert!(is_exec_path_allowed(Path::new("/nix/store/x/y"), &p));
}

#[test]
fn exec_prefix_match_requires_boundary_not_partial() {
    // Critical: prefix "/nix/store" must NOT match "/nix/storage" —
    // the next char after the prefix MUST be '/'. Anything else
    // (including end-of-string) is a partial directory name match
    // and a known sandbox-escape pattern.
    let p = exec_policy(&[], &["/nix/store"]);
    assert!(!is_exec_path_allowed(Path::new("/nix/storage/x"), &p));
    assert!(!is_exec_path_allowed(Path::new("/nix/storex"), &p));
    // Exactly the prefix itself with no trailing slash is also NOT
    // a match — would need to be an exec path which by definition
    // has a binary name component after the directory.
    assert!(!is_exec_path_allowed(Path::new("/nix/store"), &p));
}

#[test]
fn exec_prefix_does_not_subsume_unrelated_paths() {
    let p = exec_policy(&[], &["/nix/store"]);
    assert!(!is_exec_path_allowed(Path::new("/usr/bin/sh"), &p));
    assert!(!is_exec_path_allowed(Path::new("/home/user/bin"), &p));
}

#[test]
fn exec_exact_path_and_prefix_can_coexist() {
    let p = exec_policy(&["/usr/bin/python3.12"], &["/home/user/.local/bin"]);
    assert!(is_exec_path_allowed(Path::new("/usr/bin/python3.12"), &p,));
    assert!(is_exec_path_allowed(
        Path::new("/home/user/.local/bin/myscript"),
        &p,
    ));
    assert!(!is_exec_path_allowed(Path::new("/etc/shadow"), &p));
}

#[test]
fn exec_multiple_prefixes_short_circuit_correctly() {
    let p = exec_policy(&[], &["/a", "/b", "/c/d"]);
    assert!(is_exec_path_allowed(Path::new("/a/x"), &p));
    assert!(is_exec_path_allowed(Path::new("/b/y"), &p));
    assert!(is_exec_path_allowed(Path::new("/c/d/z"), &p));
    // /c alone doesn't match — only /c/d
    assert!(!is_exec_path_allowed(Path::new("/c/x"), &p));
}

#[test]
fn exec_root_prefix_allows_everything_under_root() {
    // Edge case: a prefix of "/" matches everything because every
    // absolute path starts with "/" and has a '/' as the next char.
    // This is intentional — a recipe authoring "/*" essentially
    // disables exec filtering. Documented behaviour; pin it here.
    let p = exec_policy(&[], &[""]);
    assert!(is_exec_path_allowed(Path::new("/anything"), &p));
    assert!(is_exec_path_allowed(Path::new("/etc/shadow"), &p));
}

/// Test-local classic-BPF interpreter (see `notifier::bpf`).
fn interpret(prog: &[libc::sock_filter], data: &SeccompData) -> u32 {
    // Serialise seccomp_data to the byte layout BPF_ABS loads index into.
    let mut bytes = [0u8; 64];
    bytes[0..4].copy_from_slice(&data.nr.to_ne_bytes());
    bytes[4..8].copy_from_slice(&data.arch.to_ne_bytes());
    bytes[8..16].copy_from_slice(&data.instruction_pointer.to_ne_bytes());
    for (n, arg) in data.args.iter().enumerate() {
        let off = 16 + n * 8;
        bytes[off..off + 8].copy_from_slice(&arg.to_ne_bytes());
    }

    let mut acc: u32 = 0;
    let mut pc: usize = 0;
    // Bound iterations defensively; preludes are tiny and loop-free.
    for _ in 0..10_000 {
        let insn = &prog[pc];
        let class = (insn.code as u32) & 0x07;
        match class {
            x if x == libc::BPF_LD => {
                let off = insn.k as usize;
                acc = u32::from_ne_bytes([
                    bytes[off],
                    bytes[off + 1],
                    bytes[off + 2],
                    bytes[off + 3],
                ]);
                pc += 1;
            }
            x if x == libc::BPF_ALU => {
                // Only AND|K is emitted.
                acc &= insn.k;
                pc += 1;
            }
            x if x == libc::BPF_JMP => {
                let op = (insn.code as u32) & 0xf0;
                if op == libc::BPF_JA {
                    pc += 1 + insn.k as usize;
                } else {
                    let taken = match op {
                        o if o == libc::BPF_JEQ => acc == insn.k,
                        o if o == libc::BPF_JSET => (acc & insn.k) != 0,
                        _ => unreachable!("unexpected JMP op {op:#x}"),
                    };
                    let off = if taken { insn.jt } else { insn.jf } as usize;
                    pc += 1 + off;
                }
            }
            x if x == libc::BPF_RET => return insn.k,
            other => unreachable!("unexpected BPF class {other:#x}"),
        }
    }
    panic!("BPF interpreter did not terminate (no RET reached)");
}

// -----------------------------------------------------------------
// Notifier prelude — register-decidable gates, verified by running the
// real emitted BPF program through an interpreter (notifier::bpf). This
// proves the *installed* program reaches the right verdict, not just
// that some Rust helper does.
// -----------------------------------------------------------------

const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_USER_NOTIF: u32 = 0x7fc0_0000;

#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xC000_00B7;

fn errno(e: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | (e as u32)
}

fn seccomp_data(nr: i64, args: [u64; 6]) -> SeccompData {
    SeccompData {
        nr: nr as i32,
        arch: NATIVE_ARCH,
        instruction_pointer: 0,
        args,
    }
}

fn run(nr: i64, args: [u64; 6]) -> u32 {
    run_with(&FilterPolicy::default(), nr, args)
}

fn run_with(policy: &FilterPolicy, nr: i64, args: [u64; 6]) -> u32 {
    let prog = build_notifier_filter(policy).expect("prelude builds");
    interpret(&prog, &seccomp_data(nr, args))
}

// --- clone: namespace flags denied from registers ---

#[test]
fn prelude_clone_no_flags_allowed() {
    assert_eq!(run(libc::SYS_clone, [0, 0, 0, 0, 0, 0]), RET_ALLOW);
}

#[test]
fn prelude_clone_thread_flags_allowed() {
    // CLONE_VM|FS|FILES|SIGHAND|THREAD — pthread_create, no NS bits.
    let flags = 0x100 | 0x200 | 0x400 | 0x800 | 0x0001_0000;
    assert_eq!(run(libc::SYS_clone, [flags, 0, 0, 0, 0, 0]), RET_ALLOW);
}

#[test]
fn prelude_clone_ns_flags_denied() {
    for flag in [
        CLONE_NEWUSER,
        CLONE_NEWNS,
        CLONE_NEWPID,
        CLONE_NEWNET,
        CLONE_NEWIPC,
        CLONE_NEWUTS,
        CLONE_NEWCGROUP,
        CLONE_NEWTIME,
    ] {
        assert_eq!(
            run(libc::SYS_clone, [flag, 0, 0, 0, 0, 0]),
            errno(libc::EPERM),
            "clone flag {flag:#x} must be denied",
        );
    }
}

#[test]
fn prelude_clone_ns_mixed_with_thread_flags_denied() {
    let flags = 0x100 | 0x0001_0000 | CLONE_NEWUSER;
    assert_eq!(
        run(libc::SYS_clone, [flags, 0, 0, 0, 0, 0]),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_clone3_returns_enosys() {
    // Flags live behind args[0] (a pointer) — BPF can't read them, so
    // clone3 is forced to ENOSYS regardless of args, making libc retry
    // clone() (which IS register-filtered above).
    assert_eq!(
        run(libc::SYS_clone3, [0xdead_beef, 88, 0, 0, 0, 0]),
        errno(libc::ENOSYS)
    );
}

// --- socket: domain/type/protocol gates from registers ---

#[test]
fn prelude_socket_inet_tcp_allowed() {
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_INET, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
        ),
        RET_ALLOW
    );
}

#[test]
fn prelude_socket_inet_udp_allowed() {
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_INET, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]
        ),
        RET_ALLOW
    );
}

#[test]
fn prelude_socket_inet6_tcp_allowed() {
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_INET6, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
        ),
        RET_ALLOW
    );
}

#[test]
fn prelude_socket_type_flags_are_masked() {
    // SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK is a stream socket, not
    // SOCK_RAW — the type-mask must ignore the high flag bits.
    let sock_type =
        libc::SOCK_STREAM as u64 | libc::SOCK_CLOEXEC as u64 | libc::SOCK_NONBLOCK as u64;
    assert_eq!(
        run(libc::SYS_socket, [AF_INET, sock_type, 0, 0, 0, 0]),
        RET_ALLOW
    );
}

#[test]
fn prelude_socket_inet_raw_denied() {
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_INET, SOCK_RAW, libc::IPPROTO_ICMP as u64, 0, 0, 0]
        ),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_socket_inet6_raw_denied() {
    assert_eq!(
        run(libc::SYS_socket, [AF_INET6, SOCK_RAW, 0, 0, 0, 0]),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_socket_packet_denied() {
    const AF_PACKET: u64 = 17;
    assert_eq!(
        run(libc::SYS_socket, [AF_PACKET, SOCK_RAW, 0, 0, 0, 0]),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_socket_netlink_route_allowed() {
    assert_eq!(
        run(libc::SYS_socket, [AF_NETLINK, SOCK_RAW, 0, 0, 0, 0]),
        RET_ALLOW
    );
}

#[test]
fn prelude_socket_netlink_audit_denied() {
    const NETLINK_AUDIT: u64 = 9;
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_NETLINK, SOCK_RAW, NETLINK_AUDIT, 0, 0, 0]
        ),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_socket_netlink_kobject_uevent_denied() {
    const NETLINK_KOBJECT_UEVENT: u64 = 15;
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT, 0, 0, 0]
        ),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_socket_unknown_domain_denied() {
    const AF_BLUETOOTH: u64 = 31;
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_BLUETOOTH, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
        ),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_socket_af_unix_allowed_by_default() {
    assert_eq!(
        run(
            libc::SYS_socket,
            [AF_UNIX, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
        ),
        RET_ALLOW
    );
}

#[test]
fn prelude_socket_af_unix_denied_when_policy_disallows() {
    let policy = FilterPolicy {
        allow_af_unix: false,
        allow_af_inet: true,
    };
    assert_eq!(
        run_with(
            &policy,
            libc::SYS_socket,
            [AF_UNIX, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
        ),
        errno(libc::EPERM)
    );
}

#[test]
fn prelude_socket_af_inet_denied_when_policy_disallows() {
    let policy = FilterPolicy {
        allow_af_unix: true,
        allow_af_inet: false,
    };
    assert_eq!(
        run_with(
            &policy,
            libc::SYS_socket,
            [AF_INET, libc::SOCK_STREAM as u64, 0, 0, 0, 0]
        ),
        errno(libc::EACCES)
    );
}

// --- execveat: AT_EMPTY_PATH denied; path arm still supervised ---

#[test]
fn prelude_execveat_empty_path_denied() {
    let flags = libc::AT_EMPTY_PATH as u64;
    assert_eq!(
        run(libc::SYS_execveat, [3, 0x1000, 0, 0, flags, 0]),
        errno(libc::EACCES)
    );
}

#[test]
fn prelude_execveat_without_empty_path_supervised() {
    assert_eq!(
        run(libc::SYS_execveat, [3, 0x1000, 0, 0, 0, 0]),
        RET_USER_NOTIF
    );
}

// --- routing of the remaining memory-dependent syscalls ---

#[test]
fn prelude_execve_routed_to_supervisor() {
    // execve is the only memory-dependent syscall still supervised (the
    // path allow-list). execveat-without-AT_EMPTY_PATH is covered above.
    assert_eq!(run(libc::SYS_execve, [0; 6]), RET_USER_NOTIF);
}

#[test]
fn prelude_egress_syscalls_not_notified() {
    // connect/sendto/sendmsg are no longer supervised — egress is enforced
    // by the network topology, so the prelude defers them to the main
    // filter (ALLOW here).
    for nr in [libc::SYS_connect, libc::SYS_sendto, libc::SYS_sendmsg] {
        assert_eq!(
            run(nr, [0; 6]),
            RET_ALLOW,
            "syscall {nr} must not be notified"
        );
    }
}

#[test]
fn prelude_unrelated_syscall_allowed() {
    // Not one of ours → defer to the main filter (ALLOW here).
    assert_eq!(run(libc::SYS_read, [0; 6]), RET_ALLOW);
}

#[test]
fn prelude_foreign_arch_defers_to_main_filter() {
    // A would-be SOCK_RAW on a foreign arch must NOT be ERRNO'd here;
    // arch mismatch returns ALLOW so the main filter's arch-kill applies.
    let prog = build_notifier_filter(&FilterPolicy::default()).expect("builds");
    let mut data = seccomp_data(libc::SYS_socket, [AF_INET, SOCK_RAW, 0, 0, 0, 0]);
    data.arch = 0xdead_beef;
    assert_eq!(interpret(&prog, &data), RET_ALLOW);
}

#[test]
fn prelude_builds_within_jump_range() {
    // The assembler errors rather than emitting wrong offsets; this just
    // pins that the real program assembles for both AF policy settings.
    for allow_af_unix in [true, false] {
        for allow_af_inet in [true, false] {
            let policy = FilterPolicy {
                allow_af_unix,
                allow_af_inet,
            };
            assert!(build_notifier_filter(&policy).is_ok());
        }
    }
}
