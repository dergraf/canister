use crate::seccomp::SeccompError;

/// Errors from the notifier subsystem.
#[derive(Debug, thiserror::Error)]
pub enum NotifierError {
    #[error("seccomp() syscall failed: {0}")]
    SeccompSyscall(std::io::Error),

    #[error("failed to create unix socket pair: {0}")]
    SocketPair(std::io::Error),

    #[error("failed to send notifier fd via SCM_RIGHTS: {0}")]
    SendFd(std::io::Error),

    #[error("failed to receive notifier fd via SCM_RIGHTS: {0}")]
    RecvFd(std::io::Error),

    #[error("SECCOMP_IOCTL_NOTIF_RECV failed: {0}")]
    NotifRecv(std::io::Error),

    #[error("SECCOMP_IOCTL_NOTIF_SEND failed: {0}")]
    NotifSend(std::io::Error),

    #[error("notifier not supported (requires Linux 5.9+)")]
    NotSupported,

    #[error("failed to read process memory: {0}")]
    ProcMem(std::io::Error),

    #[error("seccomp filter error: {0}")]
    Filter(#[from] SeccompError),
}
