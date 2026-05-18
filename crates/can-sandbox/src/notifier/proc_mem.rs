//! Reading the worker's memory via `/proc/<pid>/mem` and
//! `process_vm_readv(2)`.
//!
//! The supervisor (PID 1 in the sandbox's user/PID namespace) needs to
//! read syscall argument buffers (sockaddrs, pathnames, clone3 args)
//! that the worker passed by pointer. Two mechanisms are used:
//!
//! - `/proc/<pid>/mem` — works in steady state. Returns EIO on some
//!   kernels (e.g. Ubuntu noble cloud kernels) when the worker is paused
//!   mid-`execve()` — the mm is transiently between programs.
//! - `process_vm_readv(2)` — goes through a different kernel path with
//!   no per-fd mm-access check at open time. Frequently succeeds in
//!   the brief window where `/proc/mem` returns EIO.
//!
//! `read_proc_string_with_retry` tries both and backs off on failure.
//! Used only for execve/execveat where mid-exec races happen; the
//! syscall-arg readers for connect/sendto/clone3 use the simpler
//! `read_proc_mem` path.

use std::io::Read;

use super::error::NotifierError;

/// Maximum bytes we'll read from a target process's memory in a single
/// call. Largest legitimate read is a pathname (`PATH_MAX = 4096`).
pub(super) const MAX_PROC_MEM_READ: usize = 4096;

/// Boundary above which userspace addresses are invalid on x86_64.
/// Kernel virtual addresses start at `0xffff_8000_0000_0000`.
const KERNEL_ADDR_BOUNDARY: u64 = 0xffff_8000_0000_0000;

/// Read `len` bytes from `offset` in a child process's memory via
/// `/proc/<pid>/mem`.
///
/// Opens `/proc/<pid>/mem` for the specific PID on each call. Works
/// because the supervisor runs as PID 1 in the same user namespace and
/// PID namespace as the sandboxed processes, with its own procfs mount.
/// As an ancestor process, Yama `ptrace_scope=1` is satisfied
/// automatically.
pub(super) fn read_proc_mem(pid: u32, offset: u64, len: usize) -> Result<Vec<u8>, NotifierError> {
    if pid == 0 {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pid is 0",
        )));
    }
    if len == 0 || len > MAX_PROC_MEM_READ {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("read length {len} out of bounds (max {MAX_PROC_MEM_READ})"),
        )));
    }
    if offset >= KERNEL_ADDR_BOUNDARY {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("address {offset:#x} is in kernel space"),
        )));
    }
    if offset
        .checked_add(len as u64)
        .is_none_or(|end| end > KERNEL_ADDR_BOUNDARY)
    {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("read at {offset:#x}+{len} would cross kernel boundary"),
        )));
    }

    let mem_path = format!("/proc/{pid}/mem");
    let mut file = match std::fs::File::open(&mem_path) {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(pid, path = %mem_path, error = %e, "failed to open proc mem");
            return Err(NotifierError::ProcMem(e));
        }
    };

    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(NotifierError::ProcMem)?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).map_err(NotifierError::ProcMem)?;
    Ok(buf)
}

/// Read a NUL-terminated string from a child process's memory.
fn read_proc_string(pid: u32, addr: u64, max_len: usize) -> Result<String, NotifierError> {
    let buf = read_proc_mem(pid, addr, max_len)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Read a NUL-terminated string from a child process's memory, with a
/// `process_vm_readv` fallback and a backoff retry on failure. Used by
/// the execve/execveat evaluators where mid-exec races mean
/// `/proc/<pid>/mem` may return EIO.
pub(super) fn read_proc_string_with_retry(
    pid: u32,
    addr: u64,
    max_len: usize,
) -> Result<String, NotifierError> {
    // Fast path 1: try process_vm_readv. Works on most kernels.
    if let Ok(s) = read_proc_string_vm(pid, addr, max_len) {
        return Ok(s);
    }
    // Fast path 2: try /proc/<pid>/mem once without sleeping.
    if let Ok(s) = read_proc_string(pid, addr, max_len) {
        return Ok(s);
    }

    // Slow path: backoff loop alternating both mechanisms.
    const RETRIES: u32 = 12;
    const SLEEP: std::time::Duration = std::time::Duration::from_millis(10);

    let mut last_err = None;
    for _ in 0..RETRIES {
        std::thread::sleep(SLEEP);
        if let Ok(s) = read_proc_string_vm(pid, addr, max_len) {
            return Ok(s);
        }
        match read_proc_string(pid, addr, max_len) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    // SAFETY-UNWRAP: loop runs at least once, every Err branch sets
    // last_err.
    Err(last_err.expect("loop runs at least once"))
}

/// Read a string from another process's memory via `process_vm_readv(2)`.
///
/// The kernel performs the mm-access check at call time rather than at
/// open time, which means it can succeed during the brief window where
/// `/proc/mem` returns EIO mid-execve.
fn read_proc_string_vm(pid: u32, addr: u64, max_len: usize) -> Result<String, NotifierError> {
    if pid == 0 {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pid is 0",
        )));
    }
    if max_len == 0 || max_len > MAX_PROC_MEM_READ {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("max_len {max_len} out of bounds"),
        )));
    }
    if addr >= KERNEL_ADDR_BOUNDARY
        || addr
            .checked_add(max_len as u64)
            .is_none_or(|end| end > KERNEL_ADDR_BOUNDARY)
    {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "address in kernel space",
        )));
    }

    let mut buf = vec![0u8; max_len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: max_len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: max_len,
    };
    // SAFETY: valid iovecs sized to `max_len`; the kernel writes at
    // most that many bytes into `buf` and returns the count.
    let n = unsafe { libc::process_vm_readv(pid as i32, &local_iov, 1, &remote_iov, 1, 0) };
    if n < 0 {
        return Err(NotifierError::ProcMem(std::io::Error::last_os_error()));
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}
