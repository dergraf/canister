//! The configured part of the sandbox's filesystem, as data (ADR-0032).
//!
//! [`plan`] decides, from the filesystem config, the working directory and
//! what exists on the host, which configured entries are mounted, how, and
//! in what order; `overlay` applies the plan. The planner touches nothing
//! but the [`HostProbe`] it is given, so its rules are tested without a
//! mount namespace. Checks that need the sandbox being built (does a
//! masked path or a decoy target exist inside the new root, is a denied
//! path a symlink there) stay in the executor.

use std::path::{Path, PathBuf};

use can_policy::config::{DecoyMount, FilesystemConfig, WorkdirAccess};

use crate::overlay::{
    DecoyPlacement, decoy_placement, denied_within_mounts, workdir_writable, writable_within,
};

/// What the planner may ask about the host.
pub(crate) trait HostProbe {
    fn exists(&self, path: &Path) -> bool;
    fn is_dir(&self, path: &Path) -> bool;
}

/// The host's real filesystem.
pub(crate) struct RealHost;

impl HostProbe for RealHost {
    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn is_dir(&self, path: &Path) -> bool {
        path.is_dir()
    }
}

/// How a configured path is mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Read,
    Write,
}

/// Why a configured path is not mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SkipReason {
    Missing,
    Denied,
}

/// How the working directory is mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkdirMount {
    /// Bound writable.
    Writable,
    /// Bound read-only (ADR-0024).
    ReadOnly,
    /// An empty tmpfs that only the entries listed inside it are mounted
    /// into, sealed read-only after them (ADR-0032).
    Listed,
}

/// One step of the configured filesystem, in the order it is applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// Bind a host path into the sandbox at the same path.
    Bind {
        source: PathBuf,
        access: Access,
        is_dir: bool,
        noexec: bool,
    },
    /// A configured path that is not mounted, and why.
    Skipped {
        path: PathBuf,
        access: Access,
        reason: SkipReason,
    },
    /// The sandbox's own `/tmp`.
    Tmp { noexec: bool },
    /// The working directory, at its own path.
    Workdir {
        cwd: PathBuf,
        mount: WorkdirMount,
        noexec: bool,
    },
    /// Make a listed working directory read-only, once the entries inside
    /// it are mounted.
    SealWorkdir { cwd: PathBuf },
    /// Hide a denied path that lies inside a mounted one.
    Hide { path: PathBuf },
    /// Mask a path with an empty file or directory, if it exists.
    Mask { path: PathBuf },
    /// Place a decoy, if nothing real is there and the placement allows.
    Decoy {
        decoy: DecoyMount,
        placement: DecoyPlacement,
    },
}

/// The configured mounts, in order.
pub(crate) type MountPlan = Vec<Step>;

/// Plan the configured mounts. `noexec` applies to every writable mount
/// (a restricted exec policy).
pub(crate) fn plan(
    config: &FilesystemConfig,
    host_cwd: Option<&Path>,
    noexec: bool,
    host: &dyn HostProbe,
) -> MountPlan {
    let mut steps = Vec::new();
    let workdir = host_cwd.map(|cwd| (cwd, workdir_mount(config, cwd)));

    // A listed working directory is an empty tmpfs; an entry inside it
    // mounted before it would be hidden, so it is mounted after it.
    let listed_inside = |source: &Path| matches!(workdir, Some((cwd, WorkdirMount::Listed)) if source.starts_with(cwd));
    let (reads_inside, reads): (Vec<_>, Vec<_>) =
        config.read.iter().partition(|source| listed_inside(source));
    let (writes_inside, writes): (Vec<_>, Vec<_>) = config
        .write
        .iter()
        .partition(|source| listed_inside(source));

    for source in reads {
        steps.push(bind(config, source, Access::Read, noexec, host));
    }
    for source in writes {
        steps.push(bind(config, source, Access::Write, noexec, host));
    }

    steps.push(Step::Tmp { noexec });

    if let Some((cwd, mount)) = workdir {
        steps.push(Step::Workdir {
            cwd: cwd.to_path_buf(),
            mount,
            noexec,
        });
        match mount {
            WorkdirMount::Writable => {}
            // Mounted before a read-only working directory, these would be
            // hidden by it, so they are mounted again on top (ADR-0024).
            WorkdirMount::ReadOnly => {
                for source in writable_within(config, cwd) {
                    steps.push(bind(config, &source, Access::Write, noexec, host));
                }
            }
            WorkdirMount::Listed => {
                for source in reads_inside {
                    steps.push(bind(config, source, Access::Read, noexec, host));
                }
                for source in writes_inside {
                    steps.push(bind(config, source, Access::Write, noexec, host));
                }
                steps.push(Step::SealWorkdir {
                    cwd: cwd.to_path_buf(),
                });
            }
        }
    }

    for path in denied_within_mounts(config, host_cwd) {
        steps.push(Step::Hide { path });
    }

    for path in &config.mask {
        steps.push(Step::Mask { path: path.clone() });
    }

    // After every real mount, so a real grant always wins (ADR-0019).
    for decoy in &config.decoys {
        steps.push(Step::Decoy {
            decoy: decoy.clone(),
            placement: decoy_placement(&decoy.target, config, host_cwd),
        });
    }

    steps
}

/// A `write` entry covering the working directory makes it writable
/// whatever `workdir` says (ADR-0024); otherwise `workdir` decides.
fn workdir_mount(config: &FilesystemConfig, cwd: &Path) -> WorkdirMount {
    if workdir_writable(config, cwd) {
        WorkdirMount::Writable
    } else if config.workdir() == WorkdirAccess::Listed {
        WorkdirMount::Listed
    } else {
        WorkdirMount::ReadOnly
    }
}

fn bind(
    config: &FilesystemConfig,
    source: &Path,
    access: Access,
    noexec: bool,
    host: &dyn HostProbe,
) -> Step {
    let skipped = |reason| Step::Skipped {
        path: source.to_path_buf(),
        access,
        reason,
    };

    if !host.exists(source) {
        skipped(SkipReason::Missing)
    } else if config.deny.iter().any(|d| source.starts_with(d)) {
        skipped(SkipReason::Denied)
    } else {
        Step::Bind {
            source: source.to_path_buf(),
            access,
            is_dir: host.is_dir(source),
            noexec: noexec && access == Access::Write,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A host that has exactly the paths given, each a directory or not.
    struct FakeHost(BTreeMap<PathBuf, bool>);

    impl FakeHost {
        fn with(paths: &[(&str, bool)]) -> Self {
            Self(
                paths
                    .iter()
                    .map(|(p, dir)| (PathBuf::from(p), *dir))
                    .collect(),
            )
        }
    }

    impl HostProbe for FakeHost {
        fn exists(&self, path: &Path) -> bool {
            self.0.contains_key(path)
        }

        fn is_dir(&self, path: &Path) -> bool {
            self.0.get(path).copied().unwrap_or(false)
        }
    }

    fn paths(list: &[&str]) -> Vec<PathBuf> {
        list.iter().map(PathBuf::from).collect()
    }

    fn config(read: &[&str], write: &[&str], deny: &[&str]) -> FilesystemConfig {
        FilesystemConfig {
            read: paths(read),
            write: paths(write),
            deny: paths(deny),
            ..FilesystemConfig::default()
        }
    }

    fn bind_of(source: &str, access: Access, is_dir: bool, noexec: bool) -> Step {
        Step::Bind {
            source: source.into(),
            access,
            is_dir,
            noexec,
        }
    }

    #[test]
    fn reads_then_writes_then_tmp_then_the_working_directory() {
        let host = FakeHost::with(&[("/usr", true), ("/data", true), ("/etc/hosts", false)]);
        let plan = plan(
            &config(&["/usr", "/etc/hosts"], &["/data"], &[]),
            Some(Path::new("/work")),
            false,
            &host,
        );

        assert_eq!(
            plan,
            vec![
                bind_of("/usr", Access::Read, true, false),
                bind_of("/etc/hosts", Access::Read, false, false),
                bind_of("/data", Access::Write, true, false),
                Step::Tmp { noexec: false },
                Step::Workdir {
                    cwd: "/work".into(),
                    mount: WorkdirMount::Writable,
                    noexec: false
                },
            ]
        );
    }

    #[test]
    fn a_missing_or_denied_entry_is_skipped_with_its_reason() {
        let host = FakeHost::with(&[("/home/u", true), ("/home/u/.ssh", true)]);
        let plan = plan(
            &config(
                &["/opt/gone", "/home/u/.ssh"],
                &["/home/u/.ssh"],
                &["/home/u/.ssh"],
            ),
            None,
            false,
            &host,
        );

        assert_eq!(
            plan[..3],
            [
                Step::Skipped {
                    path: "/opt/gone".into(),
                    access: Access::Read,
                    reason: SkipReason::Missing
                },
                Step::Skipped {
                    path: "/home/u/.ssh".into(),
                    access: Access::Read,
                    reason: SkipReason::Denied
                },
                Step::Skipped {
                    path: "/home/u/.ssh".into(),
                    access: Access::Write,
                    reason: SkipReason::Denied
                },
            ]
        );
    }

    #[test]
    fn noexec_applies_to_writable_mounts_only() {
        let host = FakeHost::with(&[("/usr", true), ("/data", true)]);
        let plan = plan(&config(&["/usr"], &["/data"], &[]), None, true, &host);

        assert_eq!(plan[0], bind_of("/usr", Access::Read, true, false));
        assert_eq!(plan[1], bind_of("/data", Access::Write, true, true));
        assert_eq!(plan[2], Step::Tmp { noexec: true });
    }

    #[test]
    fn writes_inside_a_read_only_working_directory_are_mounted_again_after_it() {
        let host = FakeHost::with(&[("/work/notes", true), ("/work/out", true)]);
        let config = FilesystemConfig {
            workdir: Some(can_policy::config::WorkdirAccess::Read),
            ..config(&[], &["/work/notes", "/work/out"], &[])
        };
        let plan = plan(&config, Some(Path::new("/work")), false, &host);

        let workdir = plan
            .iter()
            .position(|s| {
                matches!(
                    s,
                    Step::Workdir {
                        mount: WorkdirMount::ReadOnly,
                        ..
                    }
                )
            })
            .expect("a read-only working directory");
        assert_eq!(
            plan[workdir + 1..workdir + 3],
            [
                bind_of("/work/notes", Access::Write, true, false),
                bind_of("/work/out", Access::Write, true, false),
            ]
        );
    }

    #[test]
    fn a_writable_working_directory_mounts_nothing_again() {
        let host = FakeHost::with(&[("/work/notes", true)]);
        let plan = plan(
            &config(&[], &["/work/notes"], &[]),
            Some(Path::new("/work")),
            false,
            &host,
        );
        assert_eq!(
            plan.last(),
            Some(&Step::Workdir {
                cwd: "/work".into(),
                mount: WorkdirMount::Writable,
                noexec: false
            })
        );
    }

    fn listed(read: &[&str], write: &[&str]) -> FilesystemConfig {
        FilesystemConfig {
            workdir: Some(WorkdirAccess::Listed),
            ..config(read, write, &[])
        }
    }

    #[test]
    fn a_listed_working_directory_mounts_its_entries_after_it_then_seals_it() {
        let host = FakeHost::with(&[
            ("/usr", true),
            ("/work/src", true),
            ("/work/README.md", false),
            ("/work/notes", true),
            ("/data", true),
        ]);
        let plan = plan(
            &listed(
                &["/usr", "/work/src", "/work/README.md"],
                &["/work/notes", "/data"],
            ),
            Some(Path::new("/work")),
            false,
            &host,
        );

        assert_eq!(
            plan,
            vec![
                bind_of("/usr", Access::Read, true, false),
                bind_of("/data", Access::Write, true, false),
                Step::Tmp { noexec: false },
                Step::Workdir {
                    cwd: "/work".into(),
                    mount: WorkdirMount::Listed,
                    noexec: false
                },
                bind_of("/work/src", Access::Read, true, false),
                bind_of("/work/README.md", Access::Read, false, false),
                bind_of("/work/notes", Access::Write, true, false),
                Step::SealWorkdir {
                    cwd: "/work".into()
                },
            ]
        );
    }

    #[test]
    fn a_listed_entry_that_is_missing_or_denied_is_skipped_inside_it() {
        let host = FakeHost::with(&[("/work/.env", false)]);
        let config = FilesystemConfig {
            deny: paths(&["/work/.env"]),
            ..listed(&["/work/gone", "/work/.env"], &[])
        };
        let plan = plan(&config, Some(Path::new("/work")), false, &host);

        assert!(matches!(
            plan[2..4],
            [
                Step::Skipped {
                    reason: SkipReason::Missing,
                    ..
                },
                Step::Skipped {
                    reason: SkipReason::Denied,
                    ..
                }
            ]
        ));
        assert_eq!(
            plan[4],
            Step::SealWorkdir {
                cwd: "/work".into()
            }
        );
    }

    #[test]
    fn a_write_entry_covering_a_listed_working_directory_makes_it_writable() {
        let host = FakeHost::with(&[("/work", true)]);
        let plan = plan(
            &listed(&[], &["/work"]),
            Some(Path::new("/work")),
            false,
            &host,
        );

        assert!(plan.contains(&Step::Workdir {
            cwd: "/work".into(),
            mount: WorkdirMount::Writable,
            noexec: false
        }));
        assert!(!plan.iter().any(|s| matches!(s, Step::SealWorkdir { .. })));
    }

    #[test]
    fn an_entry_outside_a_listed_working_directory_keeps_its_place() {
        let host = FakeHost::with(&[("/workspace", true)]);
        let plan = plan(
            &listed(&["/workspace"], &[]),
            Some(Path::new("/work")),
            false,
            &host,
        );
        assert_eq!(plan[0], bind_of("/workspace", Access::Read, true, false));
    }

    #[test]
    fn hides_then_masks_then_decoys_come_last_in_that_order() {
        let host = FakeHost::with(&[("/home/u", true)]);
        let decoy = DecoyMount {
            source: "/run/decoys/aws".into(),
            target: "/root/.aws/credentials".into(),
        };
        let config = FilesystemConfig {
            mask: paths(&["/work/canister.toml"]),
            decoys: vec![decoy.clone()],
            ..config(&["/home/u"], &[], &["/home/u/.ssh"])
        };
        let plan = plan(&config, Some(Path::new("/work")), false, &host);

        assert_eq!(
            plan[plan.len() - 3..],
            [
                Step::Hide {
                    path: "/home/u/.ssh".into()
                },
                Step::Mask {
                    path: "/work/canister.toml".into()
                },
                Step::Decoy {
                    decoy,
                    placement: DecoyPlacement::Place
                },
            ]
        );
    }

    #[test]
    fn a_decoy_under_a_writable_mount_is_planned_as_not_placed() {
        let host = FakeHost::with(&[]);
        let decoy = DecoyMount {
            source: "/run/decoys/env".into(),
            target: "/work/.env".into(),
        };
        let config = FilesystemConfig {
            decoys: vec![decoy],
            ..config(&[], &[], &[])
        };
        let plan = plan(&config, Some(Path::new("/work")), false, &host);

        assert!(matches!(
            plan.last(),
            Some(Step::Decoy {
                placement: DecoyPlacement::UnderWritable,
                ..
            })
        ));
    }

    #[test]
    fn without_a_working_directory_there_is_no_workdir_step() {
        let plan = plan(&config(&[], &[], &[]), None, false, &FakeHost::with(&[]));
        assert_eq!(plan, vec![Step::Tmp { noexec: false }]);
    }
}
