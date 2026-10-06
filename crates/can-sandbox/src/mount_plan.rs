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

use can_policy::config::{DecoyMount, FilesystemConfig};

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
    /// The working directory, bound at its own path.
    Workdir {
        cwd: PathBuf,
        writable: bool,
        noexec: bool,
    },
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

    for source in &config.read {
        steps.push(bind(config, source, Access::Read, noexec, host));
    }
    for source in &config.write {
        steps.push(bind(config, source, Access::Write, noexec, host));
    }

    steps.push(Step::Tmp { noexec });

    if let Some(cwd) = host_cwd {
        let writable = workdir_writable(config, cwd);
        steps.push(Step::Workdir {
            cwd: cwd.to_path_buf(),
            writable,
            noexec,
        });
        // Mounted before a read-only working directory, these would be
        // hidden by it, so they are mounted again on top (ADR-0024).
        if !writable {
            for source in writable_within(config, cwd) {
                steps.push(bind(config, &source, Access::Write, noexec, host));
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
                    writable: true,
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
                        writable: false,
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
                writable: true,
                noexec: false
            })
        );
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
