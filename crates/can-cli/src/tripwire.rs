//! Filesystem tripwires (ADR-0019).
//!
//! For each `[filesystem] decoy` path, an empty decoy file is created in a
//! private host directory and bind-mounted read-only at that path inside
//! the sandbox (`can_sandbox::overlay`). inotify watches the host file:
//! the watch is on the inode, so an access through the bind mount in the
//! sandbox's namespace is seen here, outside the sandbox, where the
//! workload cannot switch it off. Each access becomes an `fs_access`
//! event, coalesced per path and operation over one-second windows.

use std::collections::HashMap;
use std::fs::{DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use can_events::schema::{FsAccess, FsMechanism, FsOperation};
use can_policy::config::DecoyMount;
use nix::errno::Errno;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, InotifyEvent, WatchDescriptor};

/// How long repeated accesses to one path are coalesced into one event.
const WINDOW: Duration = Duration::from_secs(1);

/// How often the watcher looks for events and closes windows.
const TICK: Duration = Duration::from_millis(50);

/// Armed tripwires: the decoys to mount, and the watcher reporting on them.
pub struct Tripwires {
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
}

impl Tripwires {
    /// Create the decoys for `paths`, start watching them and return the
    /// mounts for the sandbox. `sink` receives every event, on the
    /// watcher's thread. `None` when there is nothing to watch.
    pub fn arm(
        paths: &[PathBuf],
        sink: impl Fn(FsAccess) + Send + 'static,
    ) -> Result<Option<(Self, Vec<DecoyMount>)>> {
        if paths.is_empty() {
            return Ok(None);
        }

        // Unique per run, so a directory left by a crashed run is never reused.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("can-decoys-{}-{nanos}", std::process::id()));
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating the decoy directory {}", dir.display()))?;

        // Close-on-exec: the descriptor must not reach the workload.
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
            .context("starting inotify for the decoys")?;

        let mut mounts = Vec::with_capacity(paths.len());
        let mut watched = HashMap::new();
        for (index, target) in paths.iter().enumerate() {
            let source = dir.join(index.to_string());
            File::create(&source)
                .with_context(|| format!("creating the decoy for {}", target.display()))?;
            let watch = inotify
                .add_watch(&source, watch_flags())
                .with_context(|| format!("watching the decoy for {}", target.display()))?;
            watched.insert(watch, target.display().to_string());
            mounts.push(DecoyMount {
                source,
                target: target.clone(),
            });
        }

        let stop = Arc::new(AtomicBool::new(false));
        let watcher = {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("can-tripwires".to_string())
                .spawn(move || watch(&inotify, &watched, &stop, &sink))
                .context("starting the decoy watcher")?
        };

        Ok(Some((
            Self {
                dir,
                stop,
                watcher: Some(watcher),
            },
            mounts,
        )))
    }

    /// Stop watching, report what is still pending and remove the decoys.
    /// Call before `run_end`, so every access precedes it in the stream.
    pub fn disarm(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let panicked = self
            .watcher
            .take()
            .is_some_and(|watcher| watcher.join().is_err());
        if panicked {
            tracing::warn!("decoy watcher panicked; some accesses may be unreported");
        }
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            tracing::warn!(dir = %self.dir.display(), error = %e, "could not remove the decoys");
        }
    }
}

impl Drop for Tripwires {
    fn drop(&mut self) {
        if self.watcher.is_some() {
            self.shutdown();
        }
    }
}

fn watch_flags() -> AddWatchFlags {
    AddWatchFlags::IN_OPEN
        | AddWatchFlags::IN_ACCESS
        | AddWatchFlags::IN_MODIFY
        | AddWatchFlags::IN_CLOSE_WRITE
}

/// The watcher loop: read whatever inotify has, close expired windows,
/// and on stop drain both.
fn watch(
    inotify: &Inotify,
    watched: &HashMap<WatchDescriptor, String>,
    stop: &AtomicBool,
    sink: &dyn Fn(FsAccess),
) {
    let mut coalescer = Coalescer::default();
    loop {
        let stopping = stop.load(Ordering::SeqCst);
        loop {
            match inotify.read_events() {
                Ok(events) => {
                    for event in events {
                        record(&mut coalescer, watched, &event, Instant::now(), sink);
                    }
                }
                Err(Errno::EAGAIN) => break,
                Err(e) => {
                    tracing::warn!(error = %e, "reading decoy events failed; tripwires stop");
                    coalescer.flush_all().into_iter().for_each(sink);
                    return;
                }
            }
        }
        if stopping {
            coalescer.flush_all().into_iter().for_each(sink);
            return;
        }
        coalescer
            .flush_expired(Instant::now())
            .into_iter()
            .for_each(sink);
        std::thread::sleep(TICK);
    }
}

fn record(
    coalescer: &mut Coalescer,
    watched: &HashMap<WatchDescriptor, String>,
    event: &InotifyEvent,
    now: Instant,
    sink: &dyn Fn(FsAccess),
) {
    let (Some(path), Some(operation)) = (watched.get(&event.wd), operation(event.mask)) else {
        return;
    };
    if let Some(first) = coalescer.observe(path, operation, now) {
        sink(first);
    }
}

fn operation(mask: AddWatchFlags) -> Option<FsOperation> {
    if mask.intersects(AddWatchFlags::IN_MODIFY | AddWatchFlags::IN_CLOSE_WRITE) {
        Some(FsOperation::Write)
    } else if mask.contains(AddWatchFlags::IN_ACCESS) {
        Some(FsOperation::Read)
    } else if mask.contains(AddWatchFlags::IN_OPEN) {
        Some(FsOperation::Open)
    } else {
        None
    }
}

/// Per path and operation: the first occurrence is reported at once,
/// later ones in the same window are counted and reported when it closes.
#[derive(Default)]
struct Coalescer {
    windows: HashMap<(String, FsOperation), Window>,
}

struct Window {
    opened: Instant,
    pending: u64,
}

impl Coalescer {
    /// Record one access; returns the event to emit now, if any.
    fn observe(&mut self, path: &str, operation: FsOperation, now: Instant) -> Option<FsAccess> {
        let key = (path.to_string(), operation);
        match self.windows.get_mut(&key) {
            Some(window) if now.duration_since(window.opened) < WINDOW => {
                window.pending += 1;
                None
            }
            _ => {
                self.windows.insert(
                    key,
                    Window {
                        opened: now,
                        pending: 0,
                    },
                );
                Some(access(path, operation, 1))
            }
        }
    }

    /// Close every window older than `WINDOW`, reporting what it counted.
    fn flush_expired(&mut self, now: Instant) -> Vec<FsAccess> {
        let expired: Vec<_> = self
            .windows
            .iter()
            .filter(|(_, w)| now.duration_since(w.opened) >= WINDOW)
            .map(|(key, _)| key.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|key| {
                let window = self.windows.remove(&key)?;
                (window.pending > 0).then(|| access(&key.0, key.1, window.pending))
            })
            .collect()
    }

    /// Report everything still counted, whatever the window's age.
    fn flush_all(&mut self) -> Vec<FsAccess> {
        let mut events: Vec<_> = self
            .windows
            .drain()
            .filter(|(_, w)| w.pending > 0)
            .map(|((path, operation), w)| access(&path, operation, w.pending))
            .collect();
        events.sort_by(|a, b| a.path.cmp(&b.path));
        events
    }
}

fn access(path: &str, operation: FsOperation, count: u64) -> FsAccess {
    FsAccess {
        path: path.to_string(),
        operation,
        mechanism: FsMechanism::Decoy,
        count,
        pid: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::Mutex;

    #[test]
    fn the_first_access_is_reported_at_once_and_repeats_are_counted() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();

        let first = c.observe("/home/dev/.ssh/id_ed25519", FsOperation::Open, t0);
        assert_eq!(first.map(|a| a.count), Some(1));

        for i in 1..=4 {
            let at = t0 + Duration::from_millis(100 * i);
            assert!(
                c.observe("/home/dev/.ssh/id_ed25519", FsOperation::Open, at)
                    .is_none()
            );
        }
        assert!(c.flush_expired(t0 + Duration::from_millis(900)).is_empty());

        let closed = c.flush_expired(t0 + WINDOW);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].count, 4);
    }

    #[test]
    fn a_new_window_reports_its_first_access_at_once_again() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();
        c.observe("/p", FsOperation::Read, t0);
        assert!(
            c.flush_expired(t0 + WINDOW).is_empty(),
            "nothing pending, nothing to say"
        );
        assert!(
            c.observe("/p", FsOperation::Read, t0 + WINDOW * 2)
                .is_some()
        );
    }

    #[test]
    fn paths_and_operations_are_counted_apart() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();
        assert!(c.observe("/a", FsOperation::Open, t0).is_some());
        assert!(c.observe("/a", FsOperation::Read, t0).is_some());
        assert!(c.observe("/b", FsOperation::Open, t0).is_some());
    }

    #[test]
    fn stopping_reports_what_is_still_pending() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();
        c.observe("/a", FsOperation::Open, t0);
        c.observe("/a", FsOperation::Open, t0);
        c.observe("/b", FsOperation::Open, t0);
        let pending = c.flush_all();
        assert_eq!(pending.len(), 1);
        assert_eq!((pending[0].path.as_str(), pending[0].count), ("/a", 1));
    }

    #[test]
    fn inotify_masks_map_to_operations() {
        assert_eq!(operation(AddWatchFlags::IN_OPEN), Some(FsOperation::Open));
        assert_eq!(operation(AddWatchFlags::IN_ACCESS), Some(FsOperation::Read));
        assert_eq!(
            operation(AddWatchFlags::IN_MODIFY),
            Some(FsOperation::Write)
        );
        assert_eq!(operation(AddWatchFlags::IN_CLOSE_NOWRITE), None);
    }

    #[test]
    fn nothing_to_watch_starts_nothing() {
        assert!(Tripwires::arm(&[], |_| {}).unwrap().is_none());
    }

    #[test]
    fn opening_a_decoy_is_reported_and_disarming_removes_it() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = {
            let seen = Arc::clone(&seen);
            move |a: FsAccess| seen.lock().unwrap().push(a)
        };
        let target = PathBuf::from("/home/dev/.aws/credentials");
        let (tripwires, mounts) = Tripwires::arm(std::slice::from_ref(&target), sink)
            .unwrap()
            .unwrap();

        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].target, target);
        let mode = std::fs::metadata(mounts[0].source.parent().unwrap()).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o700
        );

        let mut contents = String::new();
        File::open(&mounts[0].source)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let source = mounts[0].source.clone();
        tripwires.disarm();

        let seen = seen.lock().unwrap();
        assert!(
            seen.iter()
                .any(|a| a.path == "/home/dev/.aws/credentials" && a.operation == FsOperation::Open),
            "{seen:?}"
        );
        assert!(!source.exists(), "the decoys are removed");
    }
}
