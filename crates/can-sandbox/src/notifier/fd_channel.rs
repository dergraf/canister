//! Fd passing between worker and supervisor via pipe + `pidfd_getfd()`.
//!
//! The worker's seccomp notifier filter intercepts `sendmsg`, so we
//! cannot use SCM_RIGHTS to pass the notifier fd from worker to
//! supervisor — doing so would deadlock (the supervisor would need the
//! notifier fd to process the very `sendmsg` notification that's trying
//! to send it).
//!
//! Instead, the worker writes the raw fd number over a pipe using
//! `write()` (not intercepted), and the supervisor uses `pidfd_open()` +
//! `pidfd_getfd()` (Linux 5.6+) to duplicate the fd from the worker's
//! fd table.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::error::NotifierError;

/// Create a pipe for passing the notifier fd number from worker to
/// supervisor. Returns `(read_end, write_end)`.
pub fn create_fd_channel() -> Result<(OwnedFd, OwnedFd), NotifierError> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(NotifierError::SocketPair(std::io::Error::last_os_error()));
    }
    let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read_end, write_end))
}

/// Send the notifier fd number to the supervisor via a pipe.
///
/// The worker writes its raw fd number (as a little-endian i32) using
/// `write()`, which is NOT intercepted by the seccomp notifier filter.
pub fn send_fd(pipe_write: &OwnedFd, fd_to_send: &OwnedFd) -> Result<(), NotifierError> {
    let fd_num = fd_to_send.as_raw_fd();
    let bytes = fd_num.to_le_bytes();
    let ret = unsafe {
        libc::write(
            pipe_write.as_raw_fd(),
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
        )
    };
    if ret < 0 {
        return Err(NotifierError::SendFd(std::io::Error::last_os_error()));
    }
    if (ret as usize) != bytes.len() {
        return Err(NotifierError::SendFd(std::io::Error::other(
            "short write on fd channel pipe",
        )));
    }
    tracing::debug!(fd = fd_num, "sent notifier fd number via pipe");
    Ok(())
}

/// Receive the notifier fd from the worker via pipe + `pidfd_getfd()`.
///
/// Reads the raw fd number from the pipe, then uses `pidfd_open()` +
/// `pidfd_getfd()` to duplicate the fd from the worker's fd table into
/// the supervisor's. Avoids `sendmsg`/SCM_RIGHTS which would be
/// intercepted by the seccomp notifier filter.
pub fn recv_fd(pipe_read: &OwnedFd, worker_pid: i32) -> Result<OwnedFd, NotifierError> {
    let mut buf = [0u8; 4];
    let ret = unsafe {
        libc::read(
            pipe_read.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if ret < 0 {
        return Err(NotifierError::RecvFd(std::io::Error::last_os_error()));
    }
    if (ret as usize) != buf.len() {
        return Err(NotifierError::RecvFd(std::io::Error::other(format!(
            "short read on fd channel pipe ({ret} bytes)",
        ))));
    }
    let target_fd = i32::from_le_bytes(buf);
    tracing::debug!(
        target_fd,
        worker_pid,
        "received notifier fd number, using pidfd_getfd to duplicate"
    );

    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, worker_pid, 0i32) };
    if pidfd < 0 {
        return Err(NotifierError::RecvFd(std::io::Error::other(format!(
            "pidfd_open({worker_pid}) failed: {}",
            std::io::Error::last_os_error()
        ))));
    }
    let pidfd = pidfd as i32;

    let new_fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_fd, 0u32) };
    // Close the pidfd immediately — we only needed it for getfd.
    unsafe { libc::close(pidfd) };

    if new_fd < 0 {
        return Err(NotifierError::RecvFd(std::io::Error::other(format!(
            "pidfd_getfd(pidfd, {target_fd}) failed: {}",
            std::io::Error::last_os_error()
        ))));
    }

    let owned = unsafe { OwnedFd::from_raw_fd(new_fd as i32) };
    tracing::debug!(
        notifier_fd = owned.as_raw_fd(),
        "obtained notifier fd via pidfd_getfd"
    );
    Ok(owned)
}
